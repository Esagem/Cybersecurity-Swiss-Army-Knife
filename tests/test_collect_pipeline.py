"""Collect pipeline integration tests.

The pipeline is exercised end-to-end with a fake Runner that writes
a predetermined output file per tool. The slice 1 ingest pipeline
runs for real — Findings actually land in SQLite — so we verify
the full data path: target detection, routing, runner, ingest, scan
recording.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from csak.collect.pipeline import CollectReport, run_collect
from csak.collect.runner import RunResult
from csak.collect.tools import ALL_TOOLS
from csak.collect.tool import Tool
from csak.storage import repository as repo


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


@dataclass
class FakeStage:
    """How the FakeRunner should behave for one tool name."""

    status: str = "succeeded"
    rows: list[dict] | None = None
    error: str | None = None


class FakeRunner:
    """Stand-in for ``csak.collect.runner.Runner``.

    Keys: tool name → FakeStage describing how it behaves. The runner
    writes the row list as JSONL to the expected output_dir, then
    returns a RunResult mirroring real Runner output.
    """

    def __init__(self, stages: dict[str, FakeStage]) -> None:
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
        self.calls.append(
            {
                "tool": tool.name,
                "target": target,
                "target_type": target_type,
                "mode": mode,
                "input_path": input_path,
                "overrides": overrides,
            }
        )
        cfg = self.stages.get(tool.name, FakeStage())
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / tool.output_filename

        if cfg.status == "succeeded":
            content = "\n".join(json.dumps(r) for r in (cfg.rows or [])) + (
                "\n" if cfg.rows else ""
            )
            output_file.write_text(content, encoding="utf-8")
            line_count = len(cfg.rows or [])
            return RunResult(
                tool=tool.name,
                status="succeeded",
                output_path=output_file,
                output_line_count=line_count,
                exit_code=0,
                elapsed=0.1,
            )

        # Failed / timeout — no usable output.
        return RunResult(
            tool=tool.name,
            status=cfg.status,
            output_path=output_file,
            output_line_count=0,
            exit_code=1,
            elapsed=0.1,
            error=cfg.error or f"{tool.name} {cfg.status}",
        )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_pipeline_domain_runs_full_chain(
    db, tmp_path: Path, artifacts_dir: Path
) -> None:
    org = repo.create_org(db, name="acme", slug="acme")

    fake = FakeRunner(
        {
            "subfinder": FakeStage(
                rows=[
                    {"host": "api.acme.com", "input": "acme.com"},
                    {"host": "dev.acme.com", "input": "acme.com"},
                ]
            ),
            "httpx": FakeStage(
                rows=[
                    {
                        "url": "https://api.acme.com",
                        "host": "api.acme.com",
                        "status_code": 200,
                    },
                    {
                        "url": "https://dev.acme.com",
                        "host": "dev.acme.com",
                        "status_code": 500,
                    },
                ]
            ),
            "nuclei": FakeStage(
                rows=[
                    {
                        "template-id": "CVE-2024-1234",
                        "info": {"name": "Test CVE", "severity": "high"},
                        "host": "https://api.acme.com",
                        "matched-at": "https://api.acme.com/vuln",
                    }
                ]
            ),
        }
    )

    report: CollectReport = run_collect(
        db,
        org_id=org.id,
        target="acme.com",
        mode="standard",
        artifacts_root=artifacts_dir,
        runner=fake,
        work_dir=tmp_path / "work",
    )

    assert report.target_type == "domain"
    assert [s.tool for s in report.stages] == ["subfinder", "httpx", "nuclei"]
    assert all(s.status == "succeeded" for s in report.stages)
    assert report.skipped == {}
    assert report.hard_failure is False

    # httpx and nuclei produced findings; subfinder records identifiers.
    assert report.total_new_findings >= 1
    # Tool order respected: subfinder ran with no input, httpx got
    # subfinder's output, nuclei got httpx's output.
    assert fake.calls[0]["tool"] == "subfinder"
    assert fake.calls[0]["input_path"] is None
    assert fake.calls[1]["tool"] == "httpx"
    assert fake.calls[1]["input_path"] is not None
    assert fake.calls[2]["tool"] == "nuclei"
    assert fake.calls[2]["input_path"] is not None

    # All scans persisted with collect provenance in notes.
    scans = repo.list_scans(db, org.id)
    assert len(scans) == 3
    for s in scans:
        assert "via csak collect" in s.notes


def test_pipeline_subdomain_skips_subfinder(
    db, tmp_path: Path, artifacts_dir: Path
) -> None:
    org = repo.create_org(db, name="acme", slug="acme")
    fake = FakeRunner(
        {
            "httpx": FakeStage(
                rows=[
                    {
                        "url": "https://api.acme.com",
                        "host": "api.acme.com",
                        "status_code": 200,
                    }
                ]
            ),
            "nuclei": FakeStage(rows=[]),
        }
    )

    report = run_collect(
        db,
        org_id=org.id,
        target="api.acme.com",
        mode="standard",
        artifacts_root=artifacts_dir,
        runner=fake,
        work_dir=tmp_path / "work",
    )

    assert report.target_type == "subdomain"
    assert "subfinder" in report.skipped
    # Only httpx + nuclei ran.
    assert [c["tool"] for c in fake.calls] == ["httpx", "nuclei"]
    # The skipped subfinder still produced a Scan row.
    scans_by_tool = {s.source_tool: s for s in repo.list_scans(db, org.id)}
    assert "subfinder" in scans_by_tool
    assert "skipped" in scans_by_tool["subfinder"].notes


def test_pipeline_url_only_runs_nuclei(
    db, tmp_path: Path, artifacts_dir: Path
) -> None:
    org = repo.create_org(db, name="acme", slug="acme")
    fake = FakeRunner({"nuclei": FakeStage(rows=[])})

    report = run_collect(
        db,
        org_id=org.id,
        target="https://api.acme.com/v2/users",
        mode="standard",
        artifacts_root=artifacts_dir,
        runner=fake,
        work_dir=tmp_path / "work",
    )
    assert report.target_type == "url"
    assert [c["tool"] for c in fake.calls] == ["nuclei"]
    assert "subfinder" in report.skipped
    assert "httpx" in report.skipped


def test_pipeline_quick_mode_skips_nuclei(
    db, tmp_path: Path, artifacts_dir: Path
) -> None:
    org = repo.create_org(db, name="acme", slug="acme")
    fake = FakeRunner(
        {
            "subfinder": FakeStage(rows=[{"host": "x.acme.com", "input": "acme.com"}]),
            "httpx": FakeStage(rows=[]),
        }
    )

    report = run_collect(
        db,
        org_id=org.id,
        target="acme.com",
        mode="quick",
        artifacts_root=artifacts_dir,
        runner=fake,
        work_dir=tmp_path / "work",
    )
    assert "nuclei" in report.skipped
    assert [c["tool"] for c in fake.calls] == ["subfinder", "httpx"]


def test_pipeline_subfinder_failure_still_runs_httpx(
    db, tmp_path: Path, artifacts_dir: Path
) -> None:
    """Per spec §Pipeline shape: subfinder failure → httpx tries with the
    bare target.
    """
    org = repo.create_org(db, name="acme", slug="acme")
    fake = FakeRunner(
        {
            "subfinder": FakeStage(status="failed", error="boom"),
            "httpx": FakeStage(
                rows=[{"url": "https://acme.com", "host": "acme.com", "status_code": 200}]
            ),
            "nuclei": FakeStage(rows=[]),
        }
    )

    report = run_collect(
        db,
        org_id=org.id,
        target="acme.com",
        mode="standard",
        artifacts_root=artifacts_dir,
        runner=fake,
        work_dir=tmp_path / "work",
    )

    statuses = {s.tool: s.status for s in report.stages}
    assert statuses["subfinder"] == "failed"
    assert statuses["httpx"] == "succeeded"
    assert statuses["nuclei"] == "succeeded"
    assert report.hard_failure is True
    # httpx ran with no upstream input (used the bare target).
    httpx_call = next(c for c in fake.calls if c["tool"] == "httpx")
    assert httpx_call["input_path"] is None


def test_pipeline_httpx_failure_aborts_nuclei(
    db, tmp_path: Path, artifacts_dir: Path
) -> None:
    """Per spec §Pipeline shape: httpx failure → nuclei has nothing to
    scan, pipeline aborts.
    """
    org = repo.create_org(db, name="acme", slug="acme")
    fake = FakeRunner(
        {
            "subfinder": FakeStage(rows=[{"host": "x.acme.com", "input": "acme.com"}]),
            "httpx": FakeStage(status="failed", error="connection error"),
        }
    )

    report = run_collect(
        db,
        org_id=org.id,
        target="acme.com",
        mode="standard",
        artifacts_root=artifacts_dir,
        runner=fake,
        work_dir=tmp_path / "work",
    )
    statuses = {s.tool: s.status for s in report.stages}
    assert statuses["httpx"] == "failed"
    # Nuclei is recorded as skipped, not run.
    assert statuses["nuclei"] == "skipped"
    # Nuclei was NOT actually invoked.
    assert all(c["tool"] != "nuclei" for c in fake.calls)


def test_pipeline_invalid_target_returns_empty_report(
    db, tmp_path: Path, artifacts_dir: Path
) -> None:
    org = repo.create_org(db, name="acme", slug="acme")
    fake = FakeRunner({})
    report = run_collect(
        db,
        org_id=org.id,
        target="not-a-host",
        mode="standard",
        artifacts_root=artifacts_dir,
        runner=fake,
        work_dir=tmp_path / "work",
    )
    assert report.target_type == "invalid"
    assert report.stages == []
    assert fake.calls == []


def test_pipeline_zero_finding_nuclei_is_not_a_failure(
    db, tmp_path: Path, artifacts_dir: Path
) -> None:
    """Zero-finding is a valid outcome per spec — recorded as Scan with
    0 Findings, not a failure.
    """
    org = repo.create_org(db, name="acme", slug="acme")
    fake = FakeRunner(
        {
            "subfinder": FakeStage(rows=[{"host": "x.acme.com", "input": "acme.com"}]),
            "httpx": FakeStage(
                rows=[{"url": "https://x.acme.com", "host": "x.acme.com", "status_code": 200}]
            ),
            "nuclei": FakeStage(rows=[]),
        }
    )

    report = run_collect(
        db,
        org_id=org.id,
        target="acme.com",
        mode="standard",
        artifacts_root=artifacts_dir,
        runner=fake,
        work_dir=tmp_path / "work",
    )
    statuses = {s.tool: s.status for s in report.stages}
    assert statuses["nuclei"] == "succeeded"
    nuclei_stage = next(s for s in report.stages if s.tool == "nuclei")
    assert nuclei_stage.new_findings == 0
    assert "zero rows" in nuclei_stage.notes
    assert report.hard_failure is False


def test_pipeline_passes_overrides_through(
    db, tmp_path: Path, artifacts_dir: Path
) -> None:
    org = repo.create_org(db, name="acme", slug="acme")
    fake = FakeRunner(
        {
            "subfinder": FakeStage(rows=[]),
            "httpx": FakeStage(rows=[]),
            "nuclei": FakeStage(rows=[]),
        }
    )
    run_collect(
        db,
        org_id=org.id,
        target="acme.com",
        mode="standard",
        artifacts_root=artifacts_dir,
        runner=fake,
        work_dir=tmp_path / "work",
        overrides={"nuclei": {"templates": "/my/templates"}},
    )
    nuclei_call = next(c for c in fake.calls if c["tool"] == "nuclei")
    assert nuclei_call["overrides"] == {"templates": "/my/templates"}
