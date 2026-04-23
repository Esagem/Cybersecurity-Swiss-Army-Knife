import json
from pathlib import Path

from csak.ingest.pipeline import ingest_path
from csak.ingest.probe import parse_httpx, parse_subfinder
from csak.storage import repository as repo
from csak.storage.models import Target


def _write_jsonl(tmp_path: Path, name: str, rows: list[dict]) -> Path:
    p = tmp_path / name
    p.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    return p


def test_subfinder_records_discovered_identifiers(
    db, tmp_path: Path, artifacts_dir: Path
) -> None:
    org = repo.create_org(db, name="acme", slug="acme")
    # Parent domain exists already — subfinder hits should land in its
    # identifiers list, not as findings.
    parent = repo.insert_target(
        db,
        Target(
            id=repo.new_id(),
            org_id=org.id,
            name="acmecorp.com",
            type="domain",
            identifiers=["acmecorp.com"],
        ),
    )
    db.commit()

    p = _write_jsonl(
        tmp_path,
        "subs.jsonl",
        [
            {"host": "api.acmecorp.com", "input": "acmecorp.com"},
            {"host": "dev.acmecorp.com", "input": "acmecorp.com"},
        ],
    )
    report = ingest_path(
        db, org_id=org.id, source_tool="subfinder",
        path=p, artifacts_root=artifacts_dir,
    )
    assert report.new_findings == 0

    refreshed = repo.get_target(db, parent.id)
    assert "api.acmecorp.com" in refreshed.identifiers
    assert "dev.acmecorp.com" in refreshed.identifiers


def test_httpx_produces_findings_and_severities(
    db, tmp_path: Path, artifacts_dir: Path
) -> None:
    rows = [
        {"url": "https://acme.com/", "host": "acme.com", "status_code": 200, "title": "Home"},
        {"url": "https://acme.com/oops", "host": "acme.com", "status_code": 500},
        {"url": "https://acme.com/missing", "host": "acme.com", "status_code": 404},
    ]
    p = _write_jsonl(tmp_path, "httpx.jsonl", rows)

    res = parse_httpx(p)
    sevs = [f.raw_severity for f in res.findings]
    assert sevs == ["info", "medium", "low"]

    org = repo.create_org(db, name="acme", slug="acme")
    report = ingest_path(
        db, org_id=org.id, source_tool="httpx",
        path=p, artifacts_root=artifacts_dir,
    )
    assert report.new_findings == 3


def test_subfinder_parse_function_returns_discovered_map(tmp_path: Path) -> None:
    p = _write_jsonl(
        tmp_path, "s.jsonl",
        [{"host": "x.acme.com", "input": "acme.com"}],
    )
    res = parse_subfinder(p)
    assert res.discovered_identifiers == {"acme.com": ["x.acme.com"]}
