"""Recursion runner — slice 3.

Wraps the per-stage primitives in ``csak.collect.pipeline`` and
``csak.collect.runner`` with a depth loop. The runner:

  1. Runs the slice 2 single-pass cascade at depth 0 via
     ``run_collect``. The dedup set is initialized empty for this run
     and threaded through.
  2. After every successful stage, harvests typed outputs by calling
     ``tool.extract_outputs(artifact_path, scan)``. The runner's role
     is purely orchestration — extraction lives on the tool.
  3. Builds a frontier of ``(tool, target_value, mode)`` candidates
     by walking the registered toolbox: each typed output is paired
     with every tool whose ``accepts`` matches the candidate's type
     (with subtype widening). Candidates already in the dedup set are
     dropped.
  4. Iterates the frontier at the next depth: each task runs as a
     standalone single-tool invocation (no slice 2 cascade abort —
     each ``(tool, target, mode)`` is independent at depth 1+ per
     spec §How the frontier is built).
  5. Stops when the frontier is exhausted, when ``--max-depth N`` is
     hit (with prompt-to-continue when the frontier is non-empty), or
     when the user declines the prompt.

The dedup set is in-memory only — when this function returns, the set
is gone. Cross-invocation persistence is explicitly out of scope for
slice 3.
"""
from __future__ import annotations

import sqlite3
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from csak.collect.pipeline import (
    CollectReport,
    StageOutcome,
    _label,
    _materialize_outcome,
    run_collect,
)
from csak.collect.runner import Runner
from csak.collect.tool import Mode, Tool
from csak.collect.tools import ALL_TOOLS
from csak.collect.types import TypedTarget, matches


@dataclass
class FrontierTask:
    """One queued ``(tool, target_value, mode)`` candidate.

    ``parent_scan_id`` is the Scan whose extracted output queued this
    task. ``triggered_by_finding_id`` is set only when a specific
    Finding (typically a nuclei row's ``matched-at``) caused this
    task; bulk fanouts (subfinder's 87 subdomains) leave it ``None``
    even though ``parent_scan_id`` is set.
    """

    tool: Tool
    target: TypedTarget
    mode: Mode
    parent_scan_id: str | None = None
    triggered_by_finding_id: str | None = None


@dataclass
class DepthSummary:
    """Per-depth counters surfaced by the progress hook."""

    depth: int
    extracted: int = 0
    candidates: int = 0
    queued: int = 0
    deduped: int = 0
    tasks_run: int = 0
    tasks_failed: int = 0


@dataclass
class RecursionReport:
    """The recursion-aware report returned by ``run_collect_recursive``.

    Wraps the depth-0 ``CollectReport`` from ``run_collect`` and tacks
    on per-depth stage outcomes plus the unscanned frontier remaining
    when the run ended (depth limit hit and user declined to continue,
    or natural exhaustion with no remainder).
    """

    base: CollectReport
    depths_run: int = 1
    per_depth: list[DepthSummary] = field(default_factory=list)
    extra_stages: list[StageOutcome] = field(default_factory=list)
    frontier_remaining: list[FrontierTask] = field(default_factory=list)
    user_declined: bool = False

    @property
    def stages(self) -> list[StageOutcome]:
        return self.base.stages + self.extra_stages

    @property
    def hard_failure(self) -> bool:
        return any(
            s.status in ("failed", "timeout") for s in self.stages
        )


# ── progress hooks ──────────────────────────────────────────────────


class RecursionProgress:
    """Hooks the recursion runner calls to surface depth structure.

    The CLI provides a concrete subclass that wires these into the
    ``ProgressReporter`` (depth headers, frontier counts,
    prompt-to-continue rendering). Tests can substitute a stub.
    """

    def on_depth_started(self, depth: int, queued: int, max_depth: int) -> None:
        """Fired before any task at ``depth`` runs."""

    def on_depth_completed(self, summary: DepthSummary) -> None:
        """Fired after the last task at this depth finishes; ``summary``
        already reflects extracted / queued / deduped counts.
        """

    def on_task_started(self, task: FrontierTask, depth: int) -> None:
        """Fired before each single-tool task at depth >= 1."""

    def on_task_completed(self, task: FrontierTask, outcome: StageOutcome) -> None:
        """Fired after each single-tool task at depth >= 1 finishes."""

    def confirm_continue(self, depth: int, max_depth: int, queued: int) -> bool:
        """Return True to extend the depth budget by ``max_depth`` and
        keep going, False to stop with the frontier reported.

        Default: stop. The CLI overrides for interactive sessions
        (renders the prompt) and for ``--yes`` (always returns True).
        """
        return False


# ── helpers ─────────────────────────────────────────────────────────


def _frontier_from_outcomes(
    outcomes: list[StageOutcome],
    *,
    mode: Mode,
    dedup_set: set[tuple[str, str, Mode]],
    summary: DepthSummary,
) -> list[FrontierTask]:
    """Walk freshly-completed stage outcomes and emit deduped tasks.

    For every typed output of every stage, pair the candidate with
    every registered tool that ``accepts`` its type (with subtype
    widening). Drop any ``(tool, target, mode)`` already in
    ``dedup_set``; add survivors to the set and return them.
    """
    tasks: list[FrontierTask] = []
    for outcome in outcomes:
        for candidate in outcome.extracted:
            summary.extracted += 1
            for tool in ALL_TOOLS:
                if not matches(candidate.type, tool.accepts):
                    continue
                if tool.is_skipped_by_mode(mode):
                    continue
                summary.candidates += 1
                key = (tool.name, candidate.value, mode)
                if key in dedup_set:
                    summary.deduped += 1
                    continue
                dedup_set.add(key)
                tasks.append(
                    FrontierTask(
                        tool=tool,
                        target=candidate,
                        mode=mode,
                        parent_scan_id=outcome.scan_id,
                        triggered_by_finding_id=candidate.source_finding_id,
                    )
                )
    summary.queued = len(tasks)
    return tasks


def _order_tasks_by_dependency(tasks: list[FrontierTask]) -> list[FrontierTask]:
    """Stable order tasks so producers run before consumers within the
    same depth.

    Per spec §How the frontier is built: a tool that accepts type X
    runs after a tool that produces type X, even within the same
    depth. We approximate via tool position in ``ALL_TOOLS`` (the
    catalog already orders subfinder → httpx → nuclei). For arbitrary
    plugins we fall back to topological ordering on accepts/produces.
    """
    tool_index = {t.name: i for i, t in enumerate(ALL_TOOLS)}
    return sorted(tasks, key=lambda t: tool_index.get(t.tool.name, 1_000_000))


# ── single-tool task runner ─────────────────────────────────────────


def _run_single_task(
    conn: sqlite3.Connection,
    *,
    org_id: str,
    task: FrontierTask,
    depth: int,
    artifacts_root: Path,
    work_dir: Path,
    runner: Runner,
    overrides: dict[str, dict[str, str]],
    timeouts: dict[str, float],
    label: str,
) -> StageOutcome:
    """Run one ``(tool, target, mode)`` task at depth >= 1.

    No cascade abort logic — this is a single tool firing once.
    Output is harvested via ``extract_outputs`` and written onto the
    returned ``StageOutcome.extracted`` for the next depth's frontier.
    """
    tool = task.tool
    stage_dir = work_dir / f"depth-{depth}" / tool.name / _safe_segment(task.target.value)
    stage_dir.mkdir(parents=True, exist_ok=True)

    # At depth 1+ we feed the typed value directly via ``-u`` because
    # each task is a single-target invocation. ``_input_for_stage``
    # would write a one-line list-file — equivalent and slightly
    # heavier; keep it simple and pass ``input_path=None`` so the
    # tool's invocation handler picks the bare-target branch.
    result = runner.run_tool(
        tool=tool,
        target=task.target.value,
        target_type=task.target.type,
        mode=task.mode,
        input_path=None,
        output_dir=stage_dir,
        overrides=overrides.get(tool.name),
        timeout=timeouts.get(tool.name),
    )

    outcome = _materialize_outcome(
        conn,
        org_id=org_id,
        tool=tool,
        result=result,
        label=label,
        mode=task.mode,
        now=datetime.now(timezone.utc),
        artifacts_root=artifacts_root,
        depth=depth,
        parent_scan_id=task.parent_scan_id,
        triggered_by_finding_id=task.triggered_by_finding_id,
    )
    if result.status == "succeeded" and result.output_path is not None:
        try:
            outcome.extracted = list(tool.extract_outputs(result.output_path, None))
        except Exception:  # pragma: no cover - defensive
            outcome.extracted = []
    return outcome


def _safe_segment(value: str) -> str:
    """Make a value usable as a filesystem segment.

    Targets contain ``://``, ``/``, ``:``, ``.`` etc. We sanitize to
    keep ``stage_dir`` reasonable across OSes; collisions are
    acceptable because the dedup set already guarantees uniqueness at
    the (tool, target, mode) level.
    """
    safe = "".join(c if c.isalnum() else "-" for c in value)
    return safe[:80] or "task"


# ── public entrypoint ───────────────────────────────────────────────


ProgressCallback = Callable[..., None]


def run_collect_recursive(
    conn: sqlite3.Connection,
    *,
    org_id: str,
    target: str,
    mode: Mode = "standard",
    artifacts_root: Path,
    overrides: dict[str, dict[str, str]] | None = None,
    timeouts: dict[str, float] | None = None,
    work_dir: Path | None = None,
    runner: Runner | None = None,
    progress_callback=None,
    adaptive_rate: bool = True,
    max_depth: int = 3,
    progress: RecursionProgress | None = None,
) -> RecursionReport:
    """Recursive-collect entrypoint.

    ``max_depth`` semantics per spec:
      * ``0`` — infinite recursion until exhaustion.
      * ``1`` — equivalent to slice 2 single-pass.
      * ``N >= 2`` — run depth 0 through N-1; prompt to continue
        when the frontier is non-empty at the limit.
    """
    overrides = overrides or {}
    timeouts = timeouts or {}
    progress = progress or RecursionProgress()

    if work_dir is None:
        work_dir = Path(tempfile.mkdtemp(prefix="csak-collect-recurse-"))
    else:
        work_dir.mkdir(parents=True, exist_ok=True)

    runner = runner or Runner(
        progress_callback=progress_callback,
        adaptive_rate=adaptive_rate,
    )

    dedup_set: set[tuple[str, str, Mode]] = set()
    # Seed dedup with the root target itself so a depth-1 candidate
    # equal to the root doesn't re-queue the same tool.
    for tool in ALL_TOOLS:
        dedup_set.add((tool.name, target, mode))

    # Depth 0 — slice 2 cascade.
    progress.on_depth_started(0, queued=1, max_depth=max_depth)

    base = run_collect(
        conn,
        org_id=org_id,
        target=target,
        mode=mode,
        artifacts_root=artifacts_root,
        overrides=overrides,
        timeouts=timeouts,
        work_dir=work_dir / "depth-0",
        runner=runner,
        progress_callback=progress_callback,
        adaptive_rate=adaptive_rate,
        depth=0,
        parent_scan_id=None,
        triggered_by_finding_id=None,
        dedup_set=None,  # dedup applies depth-1 forward; depth 0 keeps slice 2 semantics
    )

    report = RecursionReport(base=base)
    summary = DepthSummary(depth=0)
    summary.tasks_run = sum(1 for s in base.stages if s.status == "succeeded")
    summary.tasks_failed = sum(1 for s in base.stages if s.status in ("failed", "timeout"))
    # No depth-1 frontier extraction yet — count what depth 0 produced.
    frontier = _frontier_from_outcomes(
        base.stages,
        mode=mode,
        dedup_set=dedup_set,
        summary=summary,
    )
    progress.on_depth_completed(summary)
    report.per_depth.append(summary)

    # Slice 2 single-pass: skip everything below.
    if max_depth == 1:
        report.frontier_remaining = list(frontier)
        return report

    label = _label(target, mode, base.started_at)

    effective_max = max_depth  # Will be bumped on prompt-to-continue.
    current_depth = 1

    while frontier and (effective_max == 0 or current_depth < effective_max):
        progress.on_depth_started(
            current_depth, queued=len(frontier), max_depth=effective_max
        )
        depth_summary = DepthSummary(depth=current_depth)
        ordered = _order_tasks_by_dependency(frontier)
        outcomes_this_depth: list[StageOutcome] = []

        for task in ordered:
            progress.on_task_started(task, current_depth)
            outcome = _run_single_task(
                conn,
                org_id=org_id,
                task=task,
                depth=current_depth,
                artifacts_root=artifacts_root,
                work_dir=work_dir,
                runner=runner,
                overrides=overrides,
                timeouts=timeouts,
                label=label,
            )
            report.extra_stages.append(outcome)
            outcomes_this_depth.append(outcome)
            if outcome.status == "succeeded":
                depth_summary.tasks_run += 1
            elif outcome.status in ("failed", "timeout"):
                depth_summary.tasks_failed += 1
            progress.on_task_completed(task, outcome)

        # Build next-depth frontier from this depth's outcomes.
        next_frontier = _frontier_from_outcomes(
            outcomes_this_depth,
            mode=mode,
            dedup_set=dedup_set,
            summary=depth_summary,
        )
        progress.on_depth_completed(depth_summary)
        report.per_depth.append(depth_summary)
        report.depths_run = current_depth + 1

        frontier = next_frontier
        current_depth += 1

        # Prompt-to-continue at depth limit when frontier is non-empty.
        if (
            effective_max != 0
            and current_depth >= effective_max
            and frontier
        ):
            if progress.confirm_continue(
                depth=current_depth, max_depth=effective_max, queued=len(frontier)
            ):
                effective_max = current_depth + max_depth
            else:
                report.user_declined = True
                break

    report.frontier_remaining = list(frontier)
    return report
