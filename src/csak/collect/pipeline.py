"""Collect orchestrator — wire detect → route → run → ingest.

One ``run_collect`` call drives one depth-0 cascade:

  * Resolves the target type via ``classify`` (the runtime registry
    seam introduced in slice 3 — the slice 2 ``detect.py`` is gone).
  * Resolves the running tool set via ``router.route``.
  * Records a ``status=skipped`` Scan for each tool that didn't apply.
  * For each running tool: invokes the runner, on success feeds the
    Artifact through the slice 1 ingest pipeline, on failure / timeout
    records a ``status=failed`` Scan with notes carrying the reason.
  * Decides whether the next stage can still run when its upstream
    failed — per spec: subfinder failure → httpx still tries with the
    bare target; httpx failure → nuclei aborts.
  * Inter-stage chaining uses each tool's ``extract_outputs`` to
    classify outputs and the type-aware matcher to decide what feeds
    the next stage. The slice 2 ``_prepare_input_for_next_stage`` /
    ``_extract_field_to_list`` helpers are gone — their job is now
    done by per-tool ``extract_outputs`` plus a single dispatcher
    here.

The pipeline never *raises* on stage failure — failures are recorded
and surfaced via the returned ``CollectReport``. The caller (CLI or
recursion runner) chooses the exit code based on the report.

Slice 3: ``run_collect`` accepts optional ``depth`` /
``parent_scan_id`` / ``triggered_by_finding_id`` / ``dedup_set``
parameters. The non-recursive caller (slice 2 single-pass) leaves
them at their defaults and gets bit-for-bit slice 2 behavior. The
recursion runner (``csak.collect.recursion``) passes lineage and a
shared dedup set so frontier targets aren't re-queued across depths.
"""
from __future__ import annotations

import sqlite3
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from csak.collect.router import Routed, route
from csak.collect.runner import (
    RunEvent,
    Runner,
    RunResult,
    make_input_file_for,
)
from csak.collect.tool import Mode, TargetType, Tool
from csak.collect.tools import ALL_TOOLS  # noqa: F401  (importing triggers tool registration)
from csak.collect.types import (
    InvalidTargetError,
    TypedTarget,
    classify,
    matches,
)
from csak.ingest.pipeline import IngestReport, ingest_path
from csak.storage import repository as repo
from csak.storage.models import Scan


@dataclass
class StageOutcome:
    """One stage's contribution to the collect report.

    ``run_result`` is None for stages that didn't run (skipped). ``ingest``
    is None for stages that ran but didn't produce a usable Artifact.
    """

    tool: str
    status: str  # "succeeded" | "failed" | "skipped" | "timeout"
    scan_id: str | None = None
    artifact_id: str | None = None
    output_path: Path | None = None
    output_line_count: int = 0
    elapsed: float = 0.0
    new_findings: int = 0
    reoccurrences: int = 0
    notes: str = ""
    error: str | None = None
    # Slice 3: typed values harvested from this stage's artifact, used
    # by the recursion runner to build the next-depth frontier.
    extracted: list[TypedTarget] = field(default_factory=list)
    depth: int = 0


@dataclass
class CollectReport:
    target: str
    target_type: TargetType
    mode: Mode
    started_at: datetime
    completed_at: datetime
    stages: list[StageOutcome] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)

    @property
    def total_new_findings(self) -> int:
        return sum(s.new_findings for s in self.stages)

    @property
    def total_reoccurrences(self) -> int:
        return sum(s.reoccurrences for s in self.stages)

    @property
    def hard_failure(self) -> bool:
        """True if any stage that *should* have run failed.

        Used by the CLI to pick a non-zero exit code per spec §Exit
        codes. Skips don't count as failures.
        """
        return any(s.status in ("failed", "timeout") for s in self.stages)


ProgressCallback = Callable[[RunEvent], None]


def _label(target: str, mode: Mode, started: datetime) -> str:
    """Per spec §Storage: a single ``csak collect`` run produces multiple
    Scans, all sharing a label like
    ``"csak collect 2026-04-24T08-30-00 — acmecorp.com standard mode"``.
    """
    ts = started.strftime("%Y-%m-%dT%H-%M-%S")
    return f"csak collect {ts} — {target} {mode} mode"


def run_collect(
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
    progress_callback: ProgressCallback | None = None,
    adaptive_rate: bool = True,
    depth: int = 0,
    parent_scan_id: str | None = None,
    triggered_by_finding_id: str | None = None,
    dedup_set: set[tuple[str, str, Mode]] | None = None,
) -> CollectReport:
    """Top-level collect entrypoint for a single depth-N cascade.

    For slice 2 callers (no ``--recurse``): ``depth=0``,
    ``parent_scan_id=None``, ``dedup_set=None`` → bit-for-bit slice 2
    behavior. The slice 3 recursion runner threads its dedup set and
    lineage through this same function for the depth-0 root pass and
    then drives subsequent depths via single-tool calls (see
    ``csak.collect.recursion``).
    """
    overrides = overrides or {}
    timeouts = timeouts or {}
    started_at = datetime.now(timezone.utc)

    try:
        typed = classify(target)
        target_type: TargetType = typed.type
    except InvalidTargetError:
        return CollectReport(
            target=target,
            target_type="invalid",
            mode=mode,
            started_at=started_at,
            completed_at=started_at,
            stages=[],
            skipped={},
        )

    routed: Routed = route(target_type, mode)

    # Synthesize Scan rows for each skipped tool. Spec §Pipeline shape
    # says these have ``status=skipped`` and zero findings.
    label = _label(target, mode, started_at)
    for tool_name, reason in routed.skipped.items():
        _record_skipped_scan(
            conn,
            org_id=org_id,
            tool_name=tool_name,
            reason=reason,
            label=label,
            now=started_at,
            depth=depth,
            parent_scan_id=parent_scan_id,
            triggered_by_finding_id=triggered_by_finding_id,
        )

    runner = runner or Runner(
        progress_callback=progress_callback,
        adaptive_rate=adaptive_rate,
    )

    if work_dir is None:
        work_dir = Path(tempfile.mkdtemp(prefix="csak-collect-"))
    else:
        work_dir.mkdir(parents=True, exist_ok=True)

    report = CollectReport(
        target=target,
        target_type=target_type,
        mode=mode,
        started_at=started_at,
        completed_at=started_at,
        skipped=dict(routed.skipped),
    )

    # The ``upstream_typed`` carries this stage's extracted candidates
    # forward; the next stage filters by its ``accepts`` and writes a
    # list-file for ``-l`` consumption. Empty at depth 0 root: each
    # tool either gets the prior stage's typed outputs or falls back
    # to the bare target.
    upstream_typed: list[TypedTarget] = []
    upstream_input: Path | None = None

    for tool in routed.tools:
        # Pre-flight: is this (tool, target, mode) already in the
        # within-invocation dedup set? At depth 0 the dedup set is
        # typically empty so this is a no-op for non-recursive calls.
        if dedup_set is not None:
            key = (tool.name, target, mode)
            if key in dedup_set:
                outcome = StageOutcome(
                    tool=tool.name,
                    status="skipped",
                    notes=f"dedup: ({tool.name}, {target}, {mode}) already run",
                    depth=depth,
                )
                report.stages.append(outcome)
                continue
            dedup_set.add(key)

        # Build the input file for this stage from upstream typed
        # values it accepts. Falls back to None (the tool runs against
        # the bare target via ``-u``) when nothing upstream applies.
        stage_input = _input_for_stage(
            tool=tool,
            upstream=upstream_typed,
            existing_path=upstream_input,
            work_dir=work_dir,
        )

        stage_dir = work_dir / tool.name
        result = runner.run_tool(
            tool=tool,
            target=target,
            target_type=target_type,
            mode=mode,
            input_path=stage_input,
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
            mode=mode,
            now=datetime.now(timezone.utc),
            artifacts_root=artifacts_root,
            depth=depth,
            parent_scan_id=parent_scan_id,
            triggered_by_finding_id=triggered_by_finding_id,
        )
        report.stages.append(outcome)

        # Decide whether to feed downstream.
        if result.status == "succeeded" and result.output_path is not None:
            outcome.extracted = _safe_extract_outputs(tool, result.output_path, outcome)
            if outcome.extracted:
                upstream_typed = outcome.extracted
                upstream_input = None  # ``_input_for_stage`` will rebuild as needed
            else:
                # Zero typed output: subfinder's contract is "fall back
                # to the bare target" (spec §Pipeline shape). httpx
                # zero output → nothing for nuclei (handled below).
                upstream_typed = []
                upstream_input = None
        elif tool.name == "subfinder":
            # Subfinder failure → keep upstream None so httpx falls
            # back to the bare target (spec §Pipeline shape).
            upstream_typed = []
            upstream_input = None
        elif tool.name == "httpx":
            # httpx failure → nuclei has no live host list. Spec
            # says: pipeline aborts (depth 0 only — at depth 1+ each
            # task is independent and runs through the recursion
            # driver, not this loop).
            _abort_remaining(
                conn,
                org_id=org_id,
                report=report,
                remaining=routed.tools[routed.tools.index(tool) + 1:],
                label=label,
                reason="upstream httpx failed; no live hosts to scan",
                now=datetime.now(timezone.utc),
                depth=depth,
                parent_scan_id=parent_scan_id,
                triggered_by_finding_id=triggered_by_finding_id,
            )
            break

    report.completed_at = datetime.now(timezone.utc)
    return report


def _safe_extract_outputs(
    tool: Tool, output_path: Path, outcome: StageOutcome
) -> list[TypedTarget]:
    """Wrap ``tool.extract_outputs`` so a buggy plugin doesn't kill the run."""
    scan = None  # repository lookup is overkill here — the artifact path is
                  # what extract_outputs actually needs; ``scan`` is advisory.
    try:
        return list(tool.extract_outputs(output_path, scan))
    except Exception as exc:  # pragma: no cover - defensive
        outcome.notes = (
            outcome.notes + ("; " if outcome.notes else "")
            + f"extract_outputs failed: {exc}"
        )
        return []


def _input_for_stage(
    *,
    tool: Tool,
    upstream: list[TypedTarget],
    existing_path: Path | None,
    work_dir: Path,
) -> Path | None:
    """Build the ``-l`` input file for this stage from upstream candidates.

    Filters ``upstream`` to candidates whose type widens to one of the
    tool's ``accepts``. Writes a deduped, newline-separated value list
    to a per-tool path under ``work_dir``. Returns ``None`` when there
    is nothing to write — the runner falls back to ``-u <target>``.
    """
    if not upstream:
        return existing_path
    accepted = [t for t in upstream if matches(t.type, tool.accepts)]
    if not accepted:
        return existing_path
    seen: set[str] = set()
    lines: list[str] = []
    for t in accepted:
        if t.value in seen:
            continue
        seen.add(t.value)
        lines.append(t.value)
    if not lines:
        return existing_path
    dest = work_dir / f"{tool.name}-input.txt"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return dest


def _materialize_outcome(
    conn: sqlite3.Connection,
    *,
    org_id: str,
    tool: Tool,
    result: RunResult,
    label: str,
    mode: Mode,
    now: datetime,
    artifacts_root: Path,
    depth: int,
    parent_scan_id: str | None,
    triggered_by_finding_id: str | None,
) -> StageOutcome:
    """Turn a RunResult into either an ingest-driven Scan + Findings
    or a synthesized failed-stage Scan.
    """
    if result.status == "succeeded" and result.output_path is not None:
        try:
            ingest_report = ingest_path(
                conn,
                org_id=org_id,
                source_tool=tool.name,
                path=result.output_path,
                artifacts_root=artifacts_root,
                label=label,
            )
        except Exception as e:
            # Ingest failure is reported on the StageOutcome but
            # doesn't abort the pipeline — the artifact bytes are
            # still on disk for manual inspection.
            return StageOutcome(
                tool=tool.name,
                status="failed",
                output_path=result.output_path,
                output_line_count=result.output_line_count,
                elapsed=result.elapsed,
                error=f"ingest failed: {e}",
                notes=f"via csak collect mode={mode}; ingest error: {e}",
                depth=depth,
                scan_id=_record_failed_scan(
                    conn,
                    org_id=org_id,
                    tool_name=tool.name,
                    reason=f"ingest failed: {e}",
                    label=label,
                    now=now,
                    depth=depth,
                    parent_scan_id=parent_scan_id,
                    triggered_by_finding_id=triggered_by_finding_id,
                ),
            )

        # Tag the Scan with collect provenance per spec §Storage:
        # ``Scan.notes`` carries "via csak collect" so reports can
        # cite the methodology correctly.
        notes = f"via csak collect mode={mode}"
        if depth > 0:
            notes += f"; depth={depth}"
        if result.output_line_count == 0:
            notes += "; zero rows produced"
        if result.adjusted_rate is not None:
            notes += f"; rate adjusted to {result.adjusted_rate} req/s"
        _set_scan_notes(conn, ingest_report.scan_id, notes)
        # Slice 3: stamp lineage onto the Scan row created by ingest.
        if depth > 0 or parent_scan_id is not None or triggered_by_finding_id is not None:
            repo.update_scan_lineage(
                conn,
                ingest_report.scan_id,
                parent_scan_id=parent_scan_id,
                depth=depth,
                triggered_by_finding_id=triggered_by_finding_id,
            )
            conn.commit()

        return StageOutcome(
            tool=tool.name,
            status="succeeded",
            scan_id=ingest_report.scan_id,
            artifact_id=ingest_report.artifact_id,
            output_path=result.output_path,
            output_line_count=result.output_line_count,
            elapsed=result.elapsed,
            new_findings=ingest_report.new_findings,
            reoccurrences=ingest_report.reoccurrences,
            notes=notes,
            depth=depth,
        )

    # Failed or timeout — record a Scan row with the reason in notes.
    reason = result.error or f"{tool.name} {result.status}"
    notes = f"via csak collect mode={mode}; status={result.status}: {reason}"
    if depth > 0:
        notes += f"; depth={depth}"
    scan_id = _record_failed_scan(
        conn,
        org_id=org_id,
        tool_name=tool.name,
        reason=notes,
        label=label,
        now=now,
        depth=depth,
        parent_scan_id=parent_scan_id,
        triggered_by_finding_id=triggered_by_finding_id,
    )
    return StageOutcome(
        tool=tool.name,
        status=result.status,
        scan_id=scan_id,
        output_path=result.output_path,
        output_line_count=result.output_line_count,
        elapsed=result.elapsed,
        notes=notes,
        error=result.error,
        depth=depth,
    )


def _record_skipped_scan(
    conn: sqlite3.Connection,
    *,
    org_id: str,
    tool_name: str,
    reason: str,
    label: str,
    now: datetime,
    depth: int = 0,
    parent_scan_id: str | None = None,
    triggered_by_finding_id: str | None = None,
) -> str:
    notes = f"skipped: {reason}"
    scan = Scan(
        id=repo.new_id(),
        org_id=org_id,
        source_tool=tool_name,
        label=label,
        scan_started_at=now,
        scan_completed_at=now,
        timestamp_source="fallback-ingested",
        artifact_ids=[],
        target_ids=[],
        ingested_at=now,
        notes=notes,
        parent_scan_id=parent_scan_id,
        depth=depth,
        triggered_by_finding_id=triggered_by_finding_id,
    )
    repo.insert_scan(conn, scan)
    conn.commit()
    return scan.id


def _record_failed_scan(
    conn: sqlite3.Connection,
    *,
    org_id: str,
    tool_name: str,
    reason: str,
    label: str,
    now: datetime,
    depth: int = 0,
    parent_scan_id: str | None = None,
    triggered_by_finding_id: str | None = None,
) -> str:
    scan = Scan(
        id=repo.new_id(),
        org_id=org_id,
        source_tool=tool_name,
        label=label,
        scan_started_at=now,
        scan_completed_at=now,
        timestamp_source="fallback-ingested",
        artifact_ids=[],
        target_ids=[],
        ingested_at=now,
        notes=reason,
        parent_scan_id=parent_scan_id,
        depth=depth,
        triggered_by_finding_id=triggered_by_finding_id,
    )
    repo.insert_scan(conn, scan)
    conn.commit()
    return scan.id


def _abort_remaining(
    conn: sqlite3.Connection,
    *,
    org_id: str,
    report: CollectReport,
    remaining: list[Tool],
    label: str,
    reason: str,
    now: datetime,
    depth: int,
    parent_scan_id: str | None,
    triggered_by_finding_id: str | None,
) -> None:
    """Record skipped Scans for the tools we never got to."""
    for tool in remaining:
        scan_id = _record_skipped_scan(
            conn,
            org_id=org_id,
            tool_name=tool.name,
            reason=reason,
            label=label,
            now=now,
            depth=depth,
            parent_scan_id=parent_scan_id,
            triggered_by_finding_id=triggered_by_finding_id,
        )
        report.stages.append(
            StageOutcome(
                tool=tool.name,
                status="skipped",
                scan_id=scan_id,
                notes=f"skipped: {reason}",
                depth=depth,
            )
        )
        report.skipped[tool.name] = reason


def _set_scan_notes(conn: sqlite3.Connection, scan_id: str, notes: str) -> None:
    """Update an existing Scan row's notes column.

    Slice 1's repository didn't expose a notes setter — we add the
    SQL inline here rather than reach across modules.
    """
    conn.execute(
        "UPDATE scans SET notes = ? WHERE id = ?",
        (notes, scan_id),
    )
    conn.commit()
