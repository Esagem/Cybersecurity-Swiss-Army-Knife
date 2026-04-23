"""End-to-end: the slice-1 exit-criteria walkthrough.

Set up an Org, ingest a mixed-tool run (Nessus + Nuclei + Zeek),
generate internal-review and fit-bundle reports in markdown, docx,
and JSON, and verify the output layout + no-overwriting rule.
"""
from __future__ import annotations

import json
import time
import zipfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from csak.cli.main import main


NESSUS_XML = """<?xml version="1.0" ?>
<NessusClientData_v2>
  <Policy><policyName>Scan</policyName></Policy>
  <Report name="April">
    <ReportHost name="10.0.0.10">
      <HostProperties>
        <tag name="host-ip">10.0.0.10</tag>
        <tag name="HOST_START">Tue Apr 21 14:30:22 2026</tag>
        <tag name="HOST_END">Tue Apr 21 14:45:10 2026</tag>
      </HostProperties>
      <ReportItem pluginID="51192" port="443" protocol="tcp" severity="4" pluginName="SSL expired">
        <description>expired</description><solution>renew</solution>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""

NUCLEI_JSONL = (
    '{"template-id":"cve-2024-9999","info":{"name":"Bad lib","severity":"high"},'
    '"matched-at":"https://api.acme.com","host":"api.acme.com",'
    '"timestamp":"2026-04-20T10:00:00Z"}\n'
)

ZEEK_NOTICE = """\
#separator \\x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	notice
#fields	ts	uid	note	msg	src	dst
#types	time	string	string	string	addr	addr
1776781822.0	abc123	Scan::Port_Scan	Port scan	1.2.3.4	10.0.0.10
"""


def _cli(runner: CliRunner, db_path: Path, artifacts: Path, reports: Path, args: list[str]):
    return runner.invoke(
        main,
        [
            "--db", str(db_path),
            "--artifacts-dir", str(artifacts),
            "--reports-dir", str(reports),
            *args,
        ],
    )


def test_mixed_tool_report_end_to_end(tmp_path: Path) -> None:
    db = tmp_path / "csak.db"
    artifacts = tmp_path / "artifacts"
    reports = tmp_path / "reports"
    artifacts.mkdir()
    reports.mkdir()
    runner = CliRunner()

    # 1. Create org.
    r = _cli(runner, db, artifacts, reports, ["org", "create", "acmecorp"])
    assert r.exit_code == 0, r.output

    # 2. Ingest three tools: Nessus, Nuclei, and a Zeek folder.
    nessus = tmp_path / "scan.nessus"
    nessus.write_text(NESSUS_XML, encoding="utf-8")
    nuclei = tmp_path / "nuclei.jsonl"
    nuclei.write_text(NUCLEI_JSONL, encoding="utf-8")
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "notice.log").write_text(ZEEK_NOTICE, encoding="utf-8")

    for tool, path in [("nessus", nessus), ("nuclei", nuclei), ("zeek", zeek_dir)]:
        r = _cli(runner, db, artifacts, reports, [
            "ingest", "--org", "acmecorp", "--tool", tool, str(path)
        ])
        assert r.exit_code == 0, r.output

    # 3. Generate internal-review in all three formats.
    r = _cli(runner, db, artifacts, reports, [
        "report", "generate",
        "--org", "acmecorp",
        "--period", "2026-04",
        "--kind", "internal-review",
        "--format", "markdown,docx,json",
    ])
    assert r.exit_code == 0, r.output

    period_dir = reports / "acmecorp" / "2026-04"
    assert period_dir.is_dir()
    review_files = list(period_dir.iterdir())
    # One .md, one .docx, one .json, all with matching timestamp prefixes.
    exts = sorted(p.suffix for p in review_files)
    assert exts == [".docx", ".json", ".md"]
    stamps = {p.name.split("_internal-review")[0] for p in review_files}
    assert len(stamps) == 1

    # 4. JSON output is a well-formed CSAK report export.
    json_path = next(p for p in review_files if p.suffix == ".json")
    doc = json.loads(json_path.read_text(encoding="utf-8"))
    assert doc["schema"]["name"] == "csak.report"
    assert doc["report"]["kind"] == "internal-review"
    assert doc["summary"]["total_findings"] >= 3
    # Every finding carries source_tool — that's the spec's
    # "source-tool attribution on every finding" self-describing rule.
    assert all("source_tool" in f for f in doc["findings"])
    # Methodology has entries for all three ingested scans.
    tools = sorted({m["source_tool"] for m in doc["methodology"]})
    assert tools == ["nessus", "nuclei", "zeek"]

    # 5. Markdown output has cross-tool content.
    md_path = next(p for p in review_files if p.suffix == ".md")
    md_text = md_path.read_text(encoding="utf-8")
    assert "Internal Review" in md_text
    assert "Bad lib" in md_text
    assert "SSL expired" in md_text
    assert "Port_Scan" in md_text or "Port scan" in md_text

    # 6. Second invocation writes fresh timestamped files; prior ones
    # are preserved. No overwriting.
    time.sleep(1.1)  # ensure second-granularity timestamp differs
    r2 = _cli(runner, db, artifacts, reports, [
        "report", "generate",
        "--org", "acmecorp",
        "--period", "2026-04",
        "--kind", "internal-review",
        "--format", "markdown",
    ])
    assert r2.exit_code == 0, r2.output

    period_files = sorted(period_dir.iterdir())
    md_files = [p for p in period_files if p.suffix == ".md"]
    assert len(md_files) == 2

    # 7. Fit-bundle with markdown + json.
    r3 = _cli(runner, db, artifacts, reports, [
        "report", "generate",
        "--org", "acmecorp",
        "--period", "2026-04",
        "--kind", "fit-bundle",
        "--format", "markdown,json",
    ])
    assert r3.exit_code == 0, r3.output

    # Bundle has a per-ticket directory, a zip, and a json file.
    fit_files = list(period_dir.iterdir())
    has_zip = any(p.suffix == ".zip" and "_fit.zip" in p.name for p in fit_files)
    has_fit_json = any(p.name.endswith("_fit.json") for p in fit_files)
    has_fit_dir = any(p.is_dir() and p.name.endswith("_fit") for p in fit_files)
    assert has_zip
    assert has_fit_json
    assert has_fit_dir

    bundle_dir = next(p for p in fit_files if p.is_dir() and p.name.endswith("_fit"))
    tickets = list(bundle_dir.glob("FIT-*.md"))
    assert len(tickets) >= 3  # 3 findings → 3 tickets (no shared dedup keys)

    # The zip contains the same tickets.
    zip_path = next(p for p in fit_files if p.suffix == ".zip")
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = zf.namelist()
        assert any(n.startswith("FIT-001") for n in names)


def test_fallback_ingested_label_surfaces_in_report(tmp_path: Path) -> None:
    """Subfinder has no run-level timestamps → fallback-ingested.
    The internal-review report must flag that explicitly per the spec.
    """
    db = tmp_path / "c.db"
    artifacts = tmp_path / "a"
    reports = tmp_path / "r"
    artifacts.mkdir()
    reports.mkdir()
    runner = CliRunner()

    _cli(runner, db, artifacts, reports, ["org", "create", "acme"])
    subs = tmp_path / "s.jsonl"
    subs.write_text(
        json.dumps({"host": "api.acme.com", "input": "acme.com"}) + "\n",
        encoding="utf-8",
    )
    _cli(runner, db, artifacts, reports, [
        "ingest", "--org", "acme", "--tool", "subfinder", str(subs)
    ])

    r = _cli(runner, db, artifacts, reports, [
        "report", "generate",
        "--org", "acme",
        "--period", "all",
        "--kind", "internal-review",
        "--format", "markdown,json",
    ])
    assert r.exit_code == 0, r.output

    md_path = next(p for p in (reports / "acme" / "all").iterdir() if p.suffix == ".md")
    md_text = md_path.read_text(encoding="utf-8")
    # The methodology section flags fallback-ingested scans.
    assert "fallback-ingested" in md_text
    assert "approximation" in md_text

    json_path = next(p for p in (reports / "acme" / "all").iterdir() if p.suffix == ".json")
    doc = json.loads(json_path.read_text(encoding="utf-8"))
    assert any(
        m["timestamp_source"] == "fallback-ingested"
        and m["timestamp_disclaimer"] is not None
        for m in doc["methodology"]
    )
