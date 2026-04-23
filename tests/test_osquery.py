import json
from pathlib import Path

from csak.ingest.osquery import parse
from csak.ingest.pipeline import ingest_path
from csak.storage import repository as repo


def test_parse_wrapped_results(tmp_path: Path) -> None:
    payload = {
        "name": "listening_ports",
        "columns": ["port", "address"],
        "rows": [
            {"port": "22", "address": "0.0.0.0", "hostname": "host-a"},
            {"port": "8080", "address": "0.0.0.0", "hostname": "host-a"},
        ],
    }
    p = tmp_path / "osq.json"
    p.write_text(json.dumps(payload), encoding="utf-8")

    result = parse(p)
    assert len(result.findings) == 2
    # listening_ports rows map to "info" severity via the ruleset.
    assert all(f.raw_severity == "info" for f in result.findings)


def test_parse_pack_output(tmp_path: Path) -> None:
    payload = {
        "suid_bin": {
            "columns": ["path"],
            "rows": [{"path": "/usr/bin/sudo", "hostname": "host-b"}],
        }
    }
    p = tmp_path / "pack.json"
    p.write_text(json.dumps(payload), encoding="utf-8")

    result = parse(p)
    assert len(result.findings) == 1
    assert result.findings[0].raw_severity == "medium"


def test_pipeline_dedup_by_row_hash(db, tmp_path: Path, artifacts_dir: Path) -> None:
    org = repo.create_org(db, name="acme", slug="acme")
    payload = {
        "name": "listening_ports",
        "columns": ["port", "address"],
        "rows": [{"port": "22", "address": "0.0.0.0", "hostname": "host-a"}],
    }
    p = tmp_path / "osq.json"
    p.write_text(json.dumps(payload), encoding="utf-8")

    r1 = ingest_path(
        db, org_id=org.id, source_tool="osquery",
        path=p, artifacts_root=artifacts_dir,
    )
    assert r1.new_findings == 1

    # Re-ingest same content → re-occurrence, not a new Finding row.
    r2 = ingest_path(
        db, org_id=org.id, source_tool="osquery",
        path=p, artifacts_root=artifacts_dir,
    )
    assert r2.new_findings == 0
    assert r2.reoccurrences == 1
