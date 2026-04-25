"""Collect orchestrator — wire detect → route → run → ingest.

One ``run_collect`` call drives the whole collect pipeline for a
single ``csak collect`` invocation:

  * Resolves the target type via ``detect.detect_target_type``.
  * Resolves the running tool set via ``router.route``.
  * Records a ``status=skipped`` Scan for each tool that didn't apply.
  * For each running tool: invokes the runner, on success feeds the
    Artifact through the slice 1 ingest pipeline, on failure / timeout
    records a ``status=failed`` Scan with notes carrying the reason.
  * Decides whether the next stage can still run when its upstream
    failed — per spec: subfinder failure → httpx still tries with the
    bare target; httpx failure → nuclei aborts.

The pipeline never *raises* on stage failure — failures are recorded
and surfaced via the returned ``CollectReport``. The caller (CLI)
chooses the exit code based on the report.
"""
from __future__ import annotations

import json
import sqlite3
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from csak.collect.detect import detect_target_type
from csak.collect.router import Routed, route
from csak.collect.runner import (
    RunEvent,
    Runner,
    RunResult,
    make_input_file_for,
)
from csak.collect.tool import Mode, TargetType, Tool
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
) -> CollectReport:
    """Top-level collect entrypoint.

    ``overrides``: mapping of tool name → dict of override key → value
    (e.g. ``{"nuclei": {"templates": "/path"}}``).

    ``timeouts``: mapping of tool name → timeout seconds.

    ``work_dir`` is where each stage's output file is written before
    being copied into the artifact store. Created under ``tempfile``
    if not given.
    """
    overrides = overrides or {}
    timeouts = timeouts or {}
    started_at = datetime.now(timezone.utc)
    target_type = detect_target_type(target)

    if target_type == "invalid":
        return CollectReport(
            target=target,
            target_type=target_type,
            mode=mode,
            started_at=started_at,
            completed_at=started_at,
            stages=[],
            skipped={},
        )

    routed: Routed = route(target_type, mode)

    # Synthesize Scan rows for each skipped tool. Spec §Pipeline shape
    # says these have `status=skipped` and zero findings.
    for tool_name, reason in routed.skipped.items():
        scan_id = _record_skipped_scan(
            conn,
            org_id=org_id,
            tool_name=tool_name,
            reason=reason,
            label=_label(target, mode, started_at),
            now=started_at,
        )
        # Don't surface skipped tools as full StageOutcomes — they go
        # in the ``skipped`` dict so the CLI can render them
        # separately. But we DO record them in the stages list so
        # ``csak scan list`` and reports see them.

    label = _label(target, mode, started_at)

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

    upstream_input: Path | None = None

    for tool in routed.tools:
        stage_dir = work_dir / tool.name
        result = runner.run_tool(
            tool=tool,
            target=target,
            target_type=target_type,
            mode=mode,
            input_path=upstream_input,
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
        )
        report.stages.append(outcome)

        # Decide whether to feed downstream.
        if result.status == "succeeded" and result.output_line_count > 0:
            upstream_input = _prepare_input_for_next_stage(
                tool=tool,
                output_path=result.output_path,
                work_dir=work_dir,
            )
        elif result.status == "succeeded" and result.output_line_count == 0:
            # Zero output: subfinder's contract is "fall back to the
            # bare target" (spec §Pipeline shape). httpx zero output
            # → nothing for nuclei (handled below). For now keep
            # whatever upstream we had; if upstream is None the next
            # stage will fall back to the raw target via -u.
            pass
        elif tool.name == "subfinder":
            # Subfinder failure → keep upstream None so httpx falls
            # back to the bare target (spec §Pipeline shape).
            upstream_input = None
        elif tool.name == "httpx":
            # httpx failure → nuclei has no live host list. Spec
            # says: pipeline aborts.
            _abort_remaining(
                conn,
                org_id=org_id,
                report=report,
                remaining=routed.tools[routed.tools.index(tool) + 1:],
                label=label,
                reason="upstream httpx failed; no live hosts to scan",
                now=datetime.now(timezone.utc),
            )
            break

    report.completed_at = datetime.now(timezone.utc)
    return report


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
                scan_id=_record_failed_scan(
                    conn,
                    org_id=org_id,
                    tool_name=tool.name,
                    reason=f"ingest failed: {e}",
                    label=label,
                    now=now,
                ),
            )

        # Tag the Scan with collect provenance per spec §Storage:
        # ``Scan.notes`` carries "via csak collect" so reports can
        # cite the methodology correctly.
        notes = f"via csak collect mode={mode}"
        if result.output_line_count == 0:
            notes += "; zero rows produced"
        if result.adjusted_rate is not None:
            notes += f"; rate adjusted to {result.adjusted_rate} req/s"
        _set_scan_notes(conn, ingest_report.scan_id, notes)

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
        )

    # Failed or timeout — record a Scan row with the reason in notes.
    reason = result.error or f"{tool.name} {result.status}"
    notes = f"via csak collect mode={mode}; status={result.status}: {reason}"
    scan_id = _record_failed_scan(
        conn,
        org_id=org_id,
        tool_name=tool.name,
        reason=notes,
        label=label,
        now=now,
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
    )


def _prepare_input_for_next_stage(
    *, tool: Tool, output_path: Path | None, work_dir: Path
) -> Path | None:
    """Convert this stage's tool output into a plain host/URL list the
    next stage can consume.

    Subfinder JSONL → host list (one host per line).
    httpx JSONL → URL list (one URL per line).
    Nuclei is the last stage so its output never feeds downstream.
    """
    if output_path is None or not output_path.exists():
        return None
    if tool.name == "subfinder":
        return _extract_field_to_list(
            output_path,
            field="host",
            dest=work_dir / "subfinder-hosts.txt",
        )
    if tool.name == "httpx":
        return _extract_field_to_list(
            output_path,
            field="url",
            dest=work_dir / "httpx-urls.txt",
            fallback="host",
        )
    return None


def _extract_field_to_list(
    path: Path,
    *,
    field: str,
    dest: Path,
    fallback: str | None = None,
) -> Path | None:
    """Read a JSONL file, extract one field per row, write a newline-
    separated list. Returns the dest path if any rows were extracted,
    None if the result would be empty (caller falls back to bare
    target).
    """
    out_lines: list[str] = []
    seen: set[str] = set()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError:
            continue
        value = row.get(field)
        if not value and fallback:
            value = row.get(fallback)
        if not value:
            continue
        s = str(value)
        if s in seen:
            continue
        seen.add(s)
        out_lines.append(s)

    if not out_lines:
        return None

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    return dest


def _record_skipped_scan(
    conn: sqlite3.Connection,
    *,
    org_id: str,
    tool_name: str,
    reason: str,
    label: str,
    now: datetime,
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
        )
        report.stages.append(
            StageOutcome(
                tool=tool.name,
                status="skipped",
                scan_id=scan_id,
                notes=f"skipped: {reason}",
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
