import json
from pathlib import Path

from csak.ingest.pipeline import ingest_path
from csak.query.context import build_context, JSON_SCHEMA_VERSION
from csak.query.finders import parse_period
from csak.render import json_renderer as jr
from csak.storage import repository as repo


NUCLEI = """\
{"template-id":"cve-x","info":{"name":"Bad lib","severity":"high"},"matched-at":"https://api.acme.com","host":"api.acme.com","timestamp":"2026-04-20T10:00:00Z"}
{"template-id":"banner","info":{"name":"Banner","severity":"info"},"matched-at":"https://acme.com","host":"acme.com","timestamp":"2026-04-20T10:02:00Z"}
"""


def _seed(db, tmp_path, artifacts_dir):
    org = repo.create_org(db, name="Acme Corp", slug="acme")
    p = tmp_path / "n.jsonl"
    p.write_text(NUCLEI, encoding="utf-8")
    ingest_path(
        db, org_id=org.id, source_tool="nuclei",
        path=p, artifacts_root=artifacts_dir,
    )
    return org


def test_json_has_schema_version_and_core_sections(
    db, tmp_path: Path, artifacts_dir: Path
) -> None:
    org = _seed(db, tmp_path, artifacts_dir)
    ctx = build_context(db, org=org, period=parse_period("2026-04"), kind="internal-review")
    doc = jr.serialize(ctx)

    assert doc["schema"]["version"] == JSON_SCHEMA_VERSION
    assert doc["schema"]["name"] == "csak.report"
    assert "csak_version" in doc["schema"]

    assert doc["report"]["kind"] == "internal-review"
    assert doc["report"]["org"]["slug"] == "acme"
    assert doc["report"]["period"]["label"] == "2026-04"

    assert doc["summary"]["total_findings"] == 2
    assert doc["summary"]["by_severity"]["high"] == 1
    assert doc["summary"]["by_severity"]["info"] == 1

    assert len(doc["findings"]) == 2
    # Per-finding self-attribution: source_tool and priority components.
    first = doc["findings"][0]
    assert first["source_tool"] == "nuclei"
    assert set(first["priority_components"]) == {
        "severity_weight", "confidence_weight", "target_weight"
    }
    # probability_real was removed in schema v2; it must not appear on the finding.
    assert "probability_real" not in first
    # Each finding cites the scans it was seen in.
    assert "seen_in_scans" in first
    assert first["seen_in_scans"][0]["source_tool"] == "nuclei"


def test_json_fit_bundle_includes_tickets(db, tmp_path: Path, artifacts_dir: Path) -> None:
    org = _seed(db, tmp_path, artifacts_dir)
    ctx = build_context(db, org=org, period=parse_period("2026-04"), kind="fit-bundle")
    doc = jr.serialize(ctx)
    assert len(doc["tickets"]) == 2
    assert doc["tickets"][0]["ticket_id"] == "FIT-001"
    assert "affected_assets" in doc["tickets"][0]
    # Ticket points at its underlying finding ids for traceability.
    assert len(doc["tickets"][0]["finding_ids"]) >= 1


def test_json_is_parseable_roundtrip(
    db, tmp_path: Path, artifacts_dir: Path, reports_dir: Path
) -> None:
    org = _seed(db, tmp_path, artifacts_dir)
    ctx = build_context(db, org=org, period=parse_period("2026-04"), kind="internal-review")
    out = jr.write_report(ctx, reports_dir / "r.json")
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["schema"]["name"] == "csak.report"
