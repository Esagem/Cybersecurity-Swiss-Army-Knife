from datetime import datetime, timezone
from pathlib import Path

import pytest

from csak.ingest.pipeline import ingest_path
from csak.query.finders import (
    findings_active_in_period,
    parse_period,
    scans_contributing_to_period,
)
from csak.storage import repository as repo


def test_parse_period_month() -> None:
    p = parse_period("2026-04")
    assert p.label == "2026-04"
    assert p.start == datetime(2026, 4, 1, tzinfo=timezone.utc)
    assert p.end == datetime(2026, 5, 1, tzinfo=timezone.utc)


def test_parse_period_day() -> None:
    p = parse_period("2026-04-15")
    assert p.start == datetime(2026, 4, 15, tzinfo=timezone.utc)
    assert p.end == datetime(2026, 4, 16, tzinfo=timezone.utc)


def test_parse_period_december_wraps_to_next_year() -> None:
    p = parse_period("2026-12")
    assert p.end == datetime(2027, 1, 1, tzinfo=timezone.utc)


def test_findings_in_period_includes_overlap(db, tmp_path: Path, artifacts_dir: Path) -> None:
    org = repo.create_org(db, name="acme", slug="acme")
    # Ingest a Nuclei file timestamped April 20, 2026.
    jsonl = tmp_path / "n.jsonl"
    jsonl.write_text(
        '{"template-id":"t1","info":{"name":"x","severity":"high"},'
        '"matched-at":"https://acme.com","host":"acme.com",'
        '"timestamp":"2026-04-20T10:00:00Z"}\n',
        encoding="utf-8",
    )
    ingest_path(
        db, org_id=org.id, source_tool="nuclei",
        path=jsonl, artifacts_root=artifacts_dir,
    )

    april = parse_period("2026-04")
    findings = findings_active_in_period(db, org, april)
    assert len(findings) == 1

    march = parse_period("2026-03")
    assert findings_active_in_period(db, org, march) == []


def test_scans_contributing_to_period(db, tmp_path: Path, artifacts_dir: Path) -> None:
    org = repo.create_org(db, name="acme", slug="acme")
    jsonl = tmp_path / "n.jsonl"
    jsonl.write_text(
        '{"template-id":"t1","info":{"name":"x","severity":"high"},'
        '"matched-at":"https://acme.com","host":"acme.com",'
        '"timestamp":"2026-04-20T10:00:00Z"}\n',
        encoding="utf-8",
    )
    ingest_path(
        db, org_id=org.id, source_tool="nuclei",
        path=jsonl, artifacts_root=artifacts_dir,
    )

    april = parse_period("2026-04")
    assert len(scans_contributing_to_period(db, org, april)) == 1
