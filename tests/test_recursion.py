"""Slice 3 recursion runner integration tests.

Uses a stubbed ``Runner`` that writes canned JSONL outputs per tool
invocation, so the depth iteration and dedup logic gets exercised
without spawning real subprocesses. The slice 1 ingest pipeline runs
for real — Findings actually land in SQLite — so each test can also
assert on lineage columns.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import pytest

from csak.collect.recursion import (
    DepthSummary,
    FrontierTask,
    RecursionProgress,
    run_collect_recursive,
)
from csak.collect.runner import RunResult
from csak.collect.tool import Tool
from csak.storage import repository as repo


@dataclass
class CannedStage:
    """One canned response for a (tool_name) lookup. ``rows`` is the
    JSONL the stub Runner writes to ``output_filename``.
    """

    rows_for: Callable[[str], list[dict]]
    status: str = "succeeded"


class StubRunner:
    """Runs no subprocess; writes ``stage.rows_for(target)`` as JSONL."""

    def __init__(self, stages: dict[str, CannedStage]) -> None:
        self.stages = stages
        self.calls: list[dict] = []

    def run_tool(
        self,
        *,
        tool: Tool,
        target: str,
        target_type: str,
        mode: str,
        input_path: Path | None,
        output_dir: Path,
        overrides: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> RunResult:
        self.calls.append({
            "tool": tool.name,
            "target": target,
            "target_type": target_type,
            "input_path": str(input_path) if input_path else None,
        })
        cfg = self.stages.get(tool.name)
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / tool.output_filename
        if cfg is None or cfg.status != "succeeded":
            output_file.write_text("", encoding="utf-8")
            return RunResult(
                tool=tool.name,
                status=cfg.status if cfg else "failed",
                output_path=output_file,
                output_line_count=0,
                exit_code=1,
                elapsed=0.01,
                error=None if cfg else "no stage canned",
            )
        rows = cfg.rows_for(target)
        text = "\n".join(json.dumps(r) for r in rows) + ("\n" if rows else "")
        output_file.write_text(text, encoding="utf-8")
        return RunResult(
            tool=tool.name,
            status="succeeded",
            output_path=output_file,
            output_line_count=len(rows),
            exit_code=0,
            elapsed=0.01,
        )


def test_max_depth_one_is_single_pass(db, tmp_path: Path, artifacts_dir: Path) -> None:
    """``--max-depth 1`` is equivalent to slice 2 single-pass."""
    org = repo.create_org(db, name="acme", slug="acme")

    runner = StubRunner({
        "subfinder": CannedStage(rows_for=lambda t: [
            {"host": "api.acme.com", "input": "acme.com"},
        ]),
        "httpx": CannedStage(rows_for=lambda t: [
            {"url": "https://api.acme.com", "host": "api.acme.com", "status_code": 200},
        ]),
        "nuclei": CannedStage(rows_for=lambda t: []),
    })

    report = run_collect_recursive(
        db,
        org_id=org.id,
        target="acme.com",
        mode="standard",
        artifacts_root=artifacts_dir,
        runner=runner,
        work_dir=tmp_path / "work",
        max_depth=1,
    )

    # Only the depth-0 cascade ran.
    tools_called = [c["tool"] for c in runner.calls]
    assert tools_called == ["subfinder", "httpx", "nuclei"]
    # No depth-1 stages on the report.
    assert report.depths_run == 1
    assert all(s.depth == 0 for s in report.stages)


def test_recursion_runs_depth_one_after_extracting(
    db, tmp_path: Path, artifacts_dir: Path
) -> None:
    """A nuclei finding whose matched-at URL is new should drive a
    depth-1 nuclei run on that URL.
    """
    org = repo.create_org(db, name="acme", slug="acme")

    runner = StubRunner({
        "subfinder": CannedStage(rows_for=lambda t: [
            {"host": "api.acme.com", "input": "acme.com"},
        ]),
        "httpx": CannedStage(rows_for=lambda t: [
            {"url": "https://api.acme.com", "host": "api.acme.com", "status_code": 200},
        ]),
        "nuclei": CannedStage(rows_for=lambda t: (
            # Only the depth-0 nuclei finds new URLs; depth-1 is empty
            # so the run terminates by exhaustion at depth 2.
            [
                {
                    "template-id": "exposed",
                    "matched-at": "https://api.acme.com/admin",
                    "info": {"name": "exposed admin", "severity": "low"},
                },
            ]
            if t == "https://api.acme.com" else []
        )),
    })

    report = run_collect_recursive(
        db,
        org_id=org.id,
        target="acme.com",
        mode="standard",
        artifacts_root=artifacts_dir,
        runner=runner,
        work_dir=tmp_path / "work",
        max_depth=3,
    )

    # Exactly one depth-1 nuclei task on the new URL.
    depth_one_calls = [
        c for c in runner.calls
        if c["tool"] == "nuclei" and c["target"] == "https://api.acme.com/admin"
    ]
    assert len(depth_one_calls) == 1
    assert report.depths_run >= 2


def test_dedup_prevents_re_queueing_root_target(
    db, tmp_path: Path, artifacts_dir: Path
) -> None:
    """A nuclei finding that points at the root target should NOT be
    re-queued. The seed dedup includes the root for every tool.
    """
    org = repo.create_org(db, name="acme", slug="acme")

    runner = StubRunner({
        "subfinder": CannedStage(rows_for=lambda t: []),
        "httpx": CannedStage(rows_for=lambda t: [
            {"url": "https://acme.com", "host": "acme.com", "status_code": 200},
        ]),
        # Points right back at the root URL.
        "nuclei": CannedStage(rows_for=lambda t: [
            {"template-id": "x", "matched-at": "acme.com"},
        ]),
    })

    report = run_collect_recursive(
        db,
        org_id=org.id,
        target="acme.com",
        mode="standard",
        artifacts_root=artifacts_dir,
        runner=runner,
        work_dir=tmp_path / "work",
        max_depth=3,
    )

    # nuclei against acme.com only runs once (depth 0). No depth-1
    # repeat.
    nuclei_calls = [c for c in runner.calls if c["tool"] == "nuclei" and c["target"] == "acme.com"]
    assert len(nuclei_calls) == 1


def test_lineage_columns_persisted_for_recursion_scans(
    db, tmp_path: Path, artifacts_dir: Path
) -> None:
    org = repo.create_org(db, name="acme", slug="acme")

    runner = StubRunner({
        "subfinder": CannedStage(rows_for=lambda t: [
            {"host": "api.acme.com", "input": "acme.com"},
        ]),
        "httpx": CannedStage(rows_for=lambda t: [
            {"url": "https://api.acme.com", "host": "api.acme.com", "status_code": 200},
        ]),
        "nuclei": CannedStage(rows_for=lambda t: (
            [{"template-id": "x", "matched-at": "https://api.acme.com/admin"}]
            if t == "https://api.acme.com" else []
        )),
    })

    run_collect_recursive(
        db,
        org_id=org.id,
        target="acme.com",
        mode="standard",
        artifacts_root=artifacts_dir,
        runner=runner,
        work_dir=tmp_path / "work",
        max_depth=3,
    )

    scans = repo.list_scans(db, org.id)
    # Depth-0 scans have depth=0 and parent_scan_id=None.
    depth_0 = [s for s in scans if s.depth == 0]
    assert depth_0  # at least one
    for s in depth_0:
        assert s.parent_scan_id is None

    # At least one depth-1 scan exists with a parent set.
    depth_1 = [s for s in scans if s.depth == 1]
    assert depth_1
    for s in depth_1:
        assert s.parent_scan_id is not None


def test_recursion_progress_hooks_fire_per_depth(
    db, tmp_path: Path, artifacts_dir: Path
) -> None:
    org = repo.create_org(db, name="acme", slug="acme")
    runner = StubRunner({
        "subfinder": CannedStage(rows_for=lambda t: []),
        "httpx": CannedStage(rows_for=lambda t: [
            {"url": "https://acme.com", "host": "acme.com", "status_code": 200},
        ]),
        "nuclei": CannedStage(rows_for=lambda t: []),
    })

    starts: list[int] = []
    summaries: list[DepthSummary] = []

    class CapturingProgress(RecursionProgress):
        def on_depth_started(self, depth, queued, max_depth):
            starts.append(depth)

        def on_depth_completed(self, summary):
            summaries.append(summary)

    run_collect_recursive(
        db,
        org_id=org.id,
        target="acme.com",
        mode="standard",
        artifacts_root=artifacts_dir,
        runner=runner,
        work_dir=tmp_path / "work",
        max_depth=2,
        progress=CapturingProgress(),
    )

    assert starts[0] == 0
    assert all(isinstance(s, DepthSummary) for s in summaries)
