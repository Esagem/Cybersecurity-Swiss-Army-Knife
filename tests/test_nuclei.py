import json
from pathlib import Path

from csak.ingest.nuclei import parse
from csak.ingest.pipeline import ingest_path
from csak.storage import repository as repo


NUCLEI_JSONL = """\
{"template-id":"ssl-dns-names","info":{"name":"SSL DNS Names","severity":"info"},"matched-at":"https://acme.com","host":"acme.com","timestamp":"2026-04-20T10:00:00.123Z"}
{"template-id":"cve-2024-12345","info":{"name":"Bad Lib","severity":"high"},"matched-at":"https://api.acme.com/app","host":"api.acme.com","timestamp":"2026-04-20T10:05:00.000Z"}
"""


def _write_jsonl(tmp_path: Path) -> Path:
    p = tmp_path / "nuclei.jsonl"
    p.write_text(NUCLEI_JSONL, encoding="utf-8")
    return p


def test_parse_extracts_findings_and_timestamps(tmp_path: Path) -> None:
    p = _write_jsonl(tmp_path)
    result = parse(p)
    assert len(result.findings) == 2
    assert result.scan.timestamp_source == "extracted"
    assert result.scan.scan_started_at < result.scan.scan_completed_at


def test_json_array_format_is_also_accepted(tmp_path: Path) -> None:
    p = tmp_path / "nuclei-array.json"
    arr = [json.loads(line) for line in NUCLEI_JSONL.strip().splitlines()]
    p.write_text(json.dumps(arr), encoding="utf-8")
    result = parse(p)
    assert len(result.findings) == 2


def test_pipeline_ingest_writes_findings(db, tmp_path: Path, artifacts_dir: Path) -> None:
    org = repo.create_org(db, name="acme", slug="acme")
    p = _write_jsonl(tmp_path)
    report = ingest_path(
        db,
        org_id=org.id,
        source_tool="nuclei",
        path=p,
        artifacts_root=artifacts_dir,
    )
    assert report.new_findings == 2
    assert report.reoccurrences == 0

    # Re-ingest same bytes — Artifact dedup is a no-op at the artifact
    # layer, but the Scan is still created and every finding gets a
    # re-occurrence row (not a new Finding).
    report2 = ingest_path(
        db,
        org_id=org.id,
        source_tool="nuclei",
        path=p,
        artifacts_root=artifacts_dir,
    )
    assert report2.new_findings == 0
    assert report2.reoccurrences == 2


def test_priority_is_stored_and_descends_by_severity(
    db, tmp_path: Path, artifacts_dir: Path
) -> None:
    org = repo.create_org(db, name="acme", slug="acme")
    ingest_path(
        db,
        org_id=org.id,
        source_tool="nuclei",
        path=_write_jsonl(tmp_path),
        artifacts_root=artifacts_dir,
    )
    findings = repo.list_findings_for_org(db, org.id)
    assert len(findings) == 2
    # high-severity finding sorts first
    assert findings[0].severity == "high"
    assert findings[1].severity == "info"
    assert findings[0].priority > findings[1].priority
