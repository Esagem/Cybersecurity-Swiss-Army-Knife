from pathlib import Path

from csak.ingest.pipeline import ingest_path
from csak.query.context import build_context
from csak.query.finders import parse_period
from csak.render import markdown as md
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


def test_internal_review_renders(db, tmp_path: Path, artifacts_dir: Path) -> None:
    org = _seed(db, tmp_path, artifacts_dir)
    ctx = build_context(db, org=org, period=parse_period("2026-04"), kind="internal-review")
    out = md.render_internal_review(ctx)
    assert "Internal Review — Acme Corp" in out
    assert "Bad lib" in out
    assert "Banner" in out
    # Priority formula appears in the finding card
    assert "Priority:" in out
    # Severity breakdown table has entries
    assert "| high | 1 |" in out
    assert "| info | 1 |" in out


def test_fit_bundle_renders_tickets(db, tmp_path: Path, artifacts_dir: Path) -> None:
    org = _seed(db, tmp_path, artifacts_dir)
    ctx = build_context(db, org=org, period=parse_period("2026-04"), kind="fit-bundle")
    out = md.render_fit_bundle(ctx)
    assert "Fix-it Ticket Bundle" in out
    assert "FIT-001" in out
    # Tickets carry impact/remediation/validation sections.
    assert "**Impact**" in out
    assert "**Remediation**" in out
    assert "**Validation**" in out


def test_write_report_and_bundle_produce_files(
    db, tmp_path: Path, artifacts_dir: Path, reports_dir: Path
) -> None:
    org = _seed(db, tmp_path, artifacts_dir)
    ctx = build_context(db, org=org, period=parse_period("2026-04"), kind="internal-review")
    out = md.write_report(ctx, reports_dir / "review.md")
    assert out.exists()

    ctx_fit = build_context(db, org=org, period=parse_period("2026-04"), kind="fit-bundle")
    bundle_dir = reports_dir / "fit"
    written = md.write_ticket_bundle(ctx_fit, bundle_dir)
    assert len(written) == 2
    assert all(p.exists() for p in written)
    assert all(p.suffix == ".md" for p in written)


def test_empty_window_produces_valid_empty_report(
    db, tmp_path: Path, artifacts_dir: Path
) -> None:
    org = _seed(db, tmp_path, artifacts_dir)
    # March is outside the ingest window — no findings.
    ctx = build_context(db, org=org, period=parse_period("2026-03"), kind="internal-review")
    out = md.render_internal_review(ctx)
    assert "no findings in this period" in out
