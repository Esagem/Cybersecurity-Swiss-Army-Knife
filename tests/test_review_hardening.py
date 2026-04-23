"""Coverage gaps surfaced during the slice-1 review.

Each test here targets a specific behavior from the spec that didn't
have a direct assertion in the earlier suites: multi-org isolation,
cross-run dedup advancing last_seen, the spec's "no overwriting"
guarantee under back-to-back invocations, tool-default confidence
applying correctly, re-occurrences not recomputing priority, and
error paths in the CLI.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from csak.cli.main import main
from csak.ingest.pipeline import ingest_path
from csak.query.context import build_context
from csak.query.finders import parse_period
from csak.render import docx_renderer as dx
from csak.render import json_renderer as jr
from csak.render import markdown as md_renderer
from csak.storage import repository as repo
from csak.storage.models import Target


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _cli(runner, db_path, artifacts, reports, args):
    return runner.invoke(
        main,
        [
            "--db", str(db_path),
            "--artifacts-dir", str(artifacts),
            "--reports-dir", str(reports),
            *args,
        ],
    )


@pytest.fixture
def cli_env(tmp_path: Path):
    db = tmp_path / "csak.db"
    artifacts = tmp_path / "artifacts"
    reports = tmp_path / "reports"
    artifacts.mkdir()
    reports.mkdir()
    runner = CliRunner()

    def invoke(args):
        return _cli(runner, db, artifacts, reports, args)

    return invoke, tmp_path, db, artifacts, reports


def _nuclei_line(severity="high", matched_at="https://api.acme.com", ts="2026-04-20T10:00:00Z"):
    return json.dumps({
        "template-id": "cve-x",
        "info": {"name": "Bad lib", "severity": severity},
        "matched-at": matched_at,
        "host": matched_at.split("//", 1)[-1],
        "timestamp": ts,
    })


# ---------------------------------------------------------------------------
# Multi-org isolation
# ---------------------------------------------------------------------------


def test_findings_and_targets_are_isolated_across_orgs(
    db, tmp_path: Path, artifacts_dir: Path
) -> None:
    org_a = repo.create_org(db, name="A", slug="orga")
    org_b = repo.create_org(db, name="B", slug="orgb")
    p = tmp_path / "n.jsonl"
    p.write_text(_nuclei_line() + "\n", encoding="utf-8")

    ingest_path(db, org_id=org_a.id, source_tool="nuclei",
                path=p, artifacts_root=artifacts_dir)
    ingest_path(db, org_id=org_b.id, source_tool="nuclei",
                path=p, artifacts_root=artifacts_dir)

    a_findings = repo.list_findings_for_org(db, org_a.id)
    b_findings = repo.list_findings_for_org(db, org_b.id)
    assert len(a_findings) == 1 and len(b_findings) == 1
    assert a_findings[0].id != b_findings[0].id
    assert a_findings[0].target_id != b_findings[0].target_id

    # Same content across orgs still stores two Artifact rows (the
    # unique constraint is (org_id, hash), not hash alone).
    a_art = repo.get_artifact_by_hash(
        db, org_id=org_a.id, hash_=a_findings[0].source_artifact_id  # noqa
    )  # may be None since we look up by finding's artifact_id
    _ = a_art
    # Direct scan of artifacts by org:
    rows_a = db.execute("SELECT id FROM artifacts WHERE org_id = ?", (org_a.id,)).fetchall()
    rows_b = db.execute("SELECT id FROM artifacts WHERE org_id = ?", (org_b.id,)).fetchall()
    assert len(rows_a) == 1 and len(rows_b) == 1


# ---------------------------------------------------------------------------
# Cross-run dedup + re-occurrence semantics
# ---------------------------------------------------------------------------


def test_reoccurrence_advances_last_seen_and_preserves_priority(
    db, tmp_path: Path, artifacts_dir: Path
) -> None:
    org = repo.create_org(db, name="acme", slug="acme")

    # Run 1: April 20.
    p1 = tmp_path / "run1.jsonl"
    p1.write_text(_nuclei_line(ts="2026-04-20T10:00:00Z") + "\n", encoding="utf-8")
    ingest_path(db, org_id=org.id, source_tool="nuclei",
                path=p1, artifacts_root=artifacts_dir)

    findings_after_run1 = repo.list_findings_for_org(db, org.id)
    assert len(findings_after_run1) == 1
    f1 = findings_after_run1[0]
    original_priority = f1.priority
    original_first_seen = f1.first_seen

    # Run 2: same finding, April 25. Different file bytes (ts differs).
    p2 = tmp_path / "run2.jsonl"
    p2.write_text(_nuclei_line(ts="2026-04-25T09:00:00Z") + "\n", encoding="utf-8")
    report = ingest_path(db, org_id=org.id, source_tool="nuclei",
                         path=p2, artifacts_root=artifacts_dir)

    assert report.new_findings == 0
    assert report.reoccurrences == 1

    findings_after_run2 = repo.list_findings_for_org(db, org.id)
    assert len(findings_after_run2) == 1
    f2 = findings_after_run2[0]
    # Priority must NOT be recomputed on re-occurrence (spec rule).
    assert f2.priority == original_priority
    # last_seen advanced; first_seen preserved.
    assert f2.last_seen > original_first_seen
    assert f2.first_seen == original_first_seen

    # Both scans recorded in the junction table.
    scans = repo.scans_for_finding(db, f2.id)
    assert len(scans) == 2


def test_same_bytes_reingest_still_records_new_scan(
    db, tmp_path: Path, artifacts_dir: Path
) -> None:
    """Bytes-level dedup is only a no-op at the Artifact layer — a
    fresh Scan row is still created per the spec."""
    org = repo.create_org(db, name="acme", slug="acme")
    p = tmp_path / "n.jsonl"
    p.write_text(_nuclei_line() + "\n", encoding="utf-8")

    ingest_path(db, org_id=org.id, source_tool="nuclei",
                path=p, artifacts_root=artifacts_dir)
    ingest_path(db, org_id=org.id, source_tool="nuclei",
                path=p, artifacts_root=artifacts_dir)

    # One Artifact row (hash dedup), two Scan rows.
    artifacts_count = db.execute(
        "SELECT COUNT(*) FROM artifacts WHERE org_id = ?", (org.id,)
    ).fetchone()[0]
    scans_count = db.execute(
        "SELECT COUNT(*) FROM scans WHERE org_id = ?", (org.id,)
    ).fetchone()[0]
    assert artifacts_count == 1
    assert scans_count == 2


# ---------------------------------------------------------------------------
# Same-second report generate — no overwriting
# ---------------------------------------------------------------------------


def test_back_to_back_report_generate_does_not_overwrite(cli_env) -> None:
    invoke, tmp_path, _, _, reports = cli_env
    invoke(["org", "create", "acme"])
    p = tmp_path / "n.jsonl"
    p.write_text(_nuclei_line() + "\n", encoding="utf-8")
    invoke(["ingest", "--org", "acme", "--tool", "nuclei", str(p)])

    # Two invocations as fast as Python can dispatch them.
    for _ in range(2):
        r = invoke([
            "report", "generate",
            "--org", "acme", "--period", "2026-04",
            "--kind", "internal-review", "--format", "markdown",
        ])
        assert r.exit_code == 0

    files = list((reports / "acme" / "2026-04").glob("*.md"))
    assert len(files) == 2
    # And their names differ (millisecond precision in the prefix).
    assert files[0].name != files[1].name


# ---------------------------------------------------------------------------
# Tool-default confidence applies when the tool doesn't report confidence
# ---------------------------------------------------------------------------


def test_tool_default_confidence_applies(db, tmp_path: Path, artifacts_dir: Path) -> None:
    org = repo.create_org(db, name="acme", slug="acme")
    p = tmp_path / "n.jsonl"
    p.write_text(_nuclei_line() + "\n", encoding="utf-8")
    ingest_path(db, org_id=org.id, source_tool="nuclei",
                path=p, artifacts_root=artifacts_dir)

    f = repo.list_findings_for_org(db, org.id)[0]
    # Nuclei default confidence is "high" per scoring.DEFAULT_CONFIDENCE.
    assert f.confidence == "high"

    # Nessus default confidence is "medium".
    nessus = tmp_path / "scan.nessus"
    nessus.write_text("""<?xml version="1.0" ?>
<NessusClientData_v2>
  <Report name="r">
    <ReportHost name="h">
      <HostProperties>
        <tag name="HOST_START">Tue Apr 21 14:30:22 2026</tag>
      </HostProperties>
      <ReportItem pluginID="1" port="80" severity="3" pluginName="x"/>
    </ReportHost>
  </Report>
</NessusClientData_v2>
""", encoding="utf-8")
    ingest_path(db, org_id=org.id, source_tool="nessus",
                path=nessus, artifacts_root=artifacts_dir)
    nessus_f = [
        fr for fr in repo.list_findings_for_org(db, org.id)
        if fr.source_tool == "nessus"
    ][0]
    assert nessus_f.confidence == "medium"


# ---------------------------------------------------------------------------
# Multi-target same-template produces separate Findings (per spec)
# ---------------------------------------------------------------------------


def test_same_template_on_three_targets_produces_three_findings(
    db, tmp_path: Path, artifacts_dir: Path
) -> None:
    org = repo.create_org(db, name="acme", slug="acme")
    p = tmp_path / "n.jsonl"
    p.write_text(
        _nuclei_line(matched_at="https://api.acme.com", ts="2026-04-20T10:00:00Z") + "\n"
        + _nuclei_line(matched_at="https://www.acme.com", ts="2026-04-20T10:01:00Z") + "\n"
        + _nuclei_line(matched_at="https://dev.acme.com", ts="2026-04-20T10:02:00Z") + "\n",
        encoding="utf-8",
    )
    ingest_path(db, org_id=org.id, source_tool="nuclei",
                path=p, artifacts_root=artifacts_dir)

    findings = repo.list_findings_for_org(db, org.id)
    assert len(findings) == 3
    # Three distinct targets.
    target_ids = {f.target_id for f in findings}
    assert len(target_ids) == 3


# ---------------------------------------------------------------------------
# CLI error paths
# ---------------------------------------------------------------------------


def test_ingest_with_unknown_org_errors(cli_env) -> None:
    invoke, tmp_path, _, _, _ = cli_env
    p = tmp_path / "n.jsonl"
    p.write_text(_nuclei_line() + "\n", encoding="utf-8")
    r = invoke(["ingest", "--org", "ghost", "--tool", "nuclei", str(p)])
    assert r.exit_code != 0
    assert "unknown org" in r.output


def test_report_generate_with_unknown_org_errors(cli_env) -> None:
    invoke, _, _, _, _ = cli_env
    r = invoke([
        "report", "generate", "--org", "ghost",
        "--period", "2026-04", "--kind", "internal-review",
    ])
    assert r.exit_code != 0
    assert "unknown org" in r.output


def test_report_generate_with_unknown_format_errors(cli_env) -> None:
    invoke, _, _, _, _ = cli_env
    invoke(["org", "create", "acme"])
    r = invoke([
        "report", "generate", "--org", "acme",
        "--period", "2026-04", "--kind", "internal-review",
        "--format", "pdf,markdown",
    ])
    assert r.exit_code != 0
    assert "unknown format" in r.output
    assert "pdf" in r.output


def test_findings_update_rejects_probability_out_of_range(cli_env) -> None:
    invoke, tmp_path, db_path, _, _ = cli_env
    invoke(["org", "create", "acme"])
    p = tmp_path / "n.jsonl"
    p.write_text(_nuclei_line() + "\n", encoding="utf-8")
    invoke(["ingest", "--org", "acme", "--tool", "nuclei", str(p)])

    conn = sqlite3.connect(str(db_path))
    fid = conn.execute("SELECT id FROM findings").fetchone()[0]
    conn.close()

    r = invoke(["findings", "update", fid, "--probability-real", "1.5"])
    assert r.exit_code != 0
    assert "probability-real" in r.output


def test_findings_show_returns_detail(cli_env) -> None:
    invoke, tmp_path, db_path, _, _ = cli_env
    invoke(["org", "create", "acme"])
    p = tmp_path / "n.jsonl"
    p.write_text(_nuclei_line() + "\n", encoding="utf-8")
    invoke(["ingest", "--org", "acme", "--tool", "nuclei", str(p)])

    conn = sqlite3.connect(str(db_path))
    fid = conn.execute("SELECT id FROM findings").fetchone()[0]
    conn.close()

    r = invoke(["findings", "show", fid])
    assert r.exit_code == 0, r.output
    assert fid in r.output
    assert "priority:" in r.output
    assert "severity_w" in r.output


def test_findings_update_status_does_not_change_value_but_commits(cli_env) -> None:
    invoke, tmp_path, db_path, _, _ = cli_env
    invoke(["org", "create", "acme"])
    p = tmp_path / "n.jsonl"
    p.write_text(_nuclei_line() + "\n", encoding="utf-8")
    invoke(["ingest", "--org", "acme", "--tool", "nuclei", str(p)])

    conn = sqlite3.connect(str(db_path))
    fid, old_priority = conn.execute("SELECT id, priority FROM findings").fetchone()
    conn.close()

    r = invoke(["findings", "update", fid, "--status", "accepted-risk"])
    assert r.exit_code == 0

    conn = sqlite3.connect(str(db_path))
    new_status, new_priority = conn.execute(
        "SELECT status, priority FROM findings WHERE id = ?", (fid,)
    ).fetchone()
    conn.close()
    assert new_status == "accepted-risk"
    # Status alone doesn't change priority value (formula doesn't include status).
    assert new_priority == pytest.approx(old_priority)


# ---------------------------------------------------------------------------
# Empty / sparse inputs
# ---------------------------------------------------------------------------


def test_empty_nuclei_file_ingests_as_empty_scan(
    db, tmp_path: Path, artifacts_dir: Path
) -> None:
    org = repo.create_org(db, name="acme", slug="acme")
    p = tmp_path / "empty.jsonl"
    p.write_text("", encoding="utf-8")
    report = ingest_path(db, org_id=org.id, source_tool="nuclei",
                         path=p, artifacts_root=artifacts_dir)
    assert report.new_findings == 0
    assert len(repo.list_scans(db, org.id)) == 1


def test_zeek_directory_with_only_non_zeek_files_ingests_empty_scan(
    db, tmp_path: Path, artifacts_dir: Path
) -> None:
    capture = tmp_path / "cap"
    capture.mkdir()
    (capture / "README.txt").write_text("hi", encoding="utf-8")
    (capture / "other.csv").write_text("x,y\n1,2", encoding="utf-8")
    org = repo.create_org(db, name="acme", slug="acme")
    report = ingest_path(db, org_id=org.id, source_tool="zeek",
                         path=capture, artifacts_root=artifacts_dir)
    assert report.new_findings == 0


def test_period_with_no_data_produces_valid_empty_reports(cli_env) -> None:
    invoke, tmp_path, _, _, reports = cli_env
    invoke(["org", "create", "acme"])
    p = tmp_path / "n.jsonl"
    p.write_text(_nuclei_line(ts="2026-04-20T10:00:00Z") + "\n", encoding="utf-8")
    invoke(["ingest", "--org", "acme", "--tool", "nuclei", str(p)])

    # March 2026 has no data; report should still write all three formats.
    r = invoke([
        "report", "generate", "--org", "acme",
        "--period", "2026-03", "--kind", "internal-review",
        "--format", "markdown,docx,json",
    ])
    assert r.exit_code == 0, r.output

    out_dir = reports / "acme" / "2026-03"
    files = {p.suffix for p in out_dir.iterdir()}
    assert files == {".md", ".docx", ".json"}

    # Markdown says so explicitly.
    md = next(out_dir.glob("*.md")).read_text(encoding="utf-8")
    assert "no findings in this period" in md

    # JSON has total_findings=0 and no methodology entries.
    doc = json.loads(next(out_dir.glob("*.json")).read_text(encoding="utf-8"))
    assert doc["summary"]["total_findings"] == 0
    assert doc["methodology"] == []


# ---------------------------------------------------------------------------
# JSON schema self-describing round-trip
# ---------------------------------------------------------------------------


def test_json_export_round_trips_all_finding_raw_fields(
    db, tmp_path: Path, artifacts_dir: Path
) -> None:
    org = repo.create_org(db, name="acme", slug="acme")
    p = tmp_path / "n.jsonl"
    # Include a nested list and a None in the raw record to confirm
    # the JSON serialization doesn't drop or coerce those.
    rec = {
        "template-id": "t1",
        "info": {
            "name": "Name",
            "severity": "high",
            "tags": ["cve", "rce"],
            "reference": None,
        },
        "matched-at": "https://acme.com",
        "host": "acme.com",
        "timestamp": "2026-04-20T10:00:00Z",
    }
    p.write_text(json.dumps(rec) + "\n", encoding="utf-8")
    ingest_path(db, org_id=org.id, source_tool="nuclei",
                path=p, artifacts_root=artifacts_dir)

    ctx = build_context(db, org=org, period=parse_period("2026-04"),
                        kind="internal-review")
    doc = jr.serialize(ctx)
    raw = doc["findings"][0]["raw"]
    assert raw["template-id"] == "t1"
    assert raw["info"]["tags"] == ["cve", "rce"]
    assert raw["info"]["reference"] is None


# ---------------------------------------------------------------------------
# Soft-delete sanity: deleted_at respected in queries
# ---------------------------------------------------------------------------


def test_soft_deleted_org_hidden_from_lookup(db) -> None:
    org = repo.create_org(db, name="acme", slug="acme")
    db.execute(
        "UPDATE orgs SET deleted_at = ? WHERE id = ?",
        (datetime.now(timezone.utc).isoformat(), org.id),
    )
    db.commit()
    assert repo.get_org_by_slug(db, "acme") is None
    assert repo.get_org(db, org.id) is None
    assert [o.id for o in repo.list_orgs(db)] == []


def test_soft_deleted_finding_excluded_from_listings(
    db, tmp_path: Path, artifacts_dir: Path
) -> None:
    org = repo.create_org(db, name="acme", slug="acme")
    p = tmp_path / "n.jsonl"
    p.write_text(_nuclei_line() + "\n", encoding="utf-8")
    ingest_path(db, org_id=org.id, source_tool="nuclei",
                path=p, artifacts_root=artifacts_dir)

    fid = repo.list_findings_for_org(db, org.id)[0].id
    db.execute(
        "UPDATE findings SET deleted_at = ? WHERE id = ?",
        (datetime.now(timezone.utc).isoformat(), fid),
    )
    db.commit()
    assert repo.list_findings_for_org(db, org.id) == []
    assert repo.get_finding(db, fid) is None


# ---------------------------------------------------------------------------
# Subfinder without "input" field falls back to naive parent resolution
# ---------------------------------------------------------------------------


def test_subfinder_without_input_falls_back_to_host_parent(
    db, tmp_path: Path, artifacts_dir: Path
) -> None:
    org = repo.create_org(db, name="acme", slug="acme")
    p = tmp_path / "s.jsonl"
    p.write_text(json.dumps({"host": "api.acme.com"}) + "\n", encoding="utf-8")
    ingest_path(db, org_id=org.id, source_tool="subfinder",
                path=p, artifacts_root=artifacts_dir)

    # A top-level Target "acme.com" (the fallback parent) now exists
    # with "api.acme.com" in its identifiers.
    parent = repo.get_target_by_name(db, org_id=org.id, name="acme.com")
    assert parent is not None
    assert "api.acme.com" in parent.identifiers
