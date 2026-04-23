import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from csak.cli.main import main


@pytest.fixture
def db_path(tmp_path: Path) -> str:
    return str(tmp_path / "csak.db")


@pytest.fixture
def artifacts_path(tmp_path: Path) -> str:
    d = tmp_path / "artifacts"
    d.mkdir()
    return str(d)


def _cli(db_path: str, artifacts_path: str, args: list[str]):
    runner = CliRunner()
    return runner.invoke(
        main,
        ["--db", db_path, "--artifacts-dir", artifacts_path, *args],
    )


def _seed_nuclei(tmp_path: Path) -> Path:
    p = tmp_path / "n.jsonl"
    p.write_text(
        '{"template-id":"cve-x","info":{"name":"Bad lib","severity":"high"},'
        '"matched-at":"https://api.acme.com","host":"api.acme.com",'
        '"timestamp":"2026-04-15T10:00:00Z"}\n',
        encoding="utf-8",
    )
    return p


def test_end_to_end_ingest_list_update_flow(
    tmp_path: Path, db_path: str, artifacts_path: str
) -> None:
    r = _cli(db_path, artifacts_path, ["org", "create", "acme"])
    assert r.exit_code == 0, r.output

    p = _seed_nuclei(tmp_path)
    r = _cli(db_path, artifacts_path, ["ingest", "--org", "acme", "--tool", "nuclei", str(p)])
    assert r.exit_code == 0, r.output
    assert "1 new" in r.output

    # `findings list` shows our finding with "high" severity.
    r = _cli(db_path, artifacts_path, ["findings", "list", "--org", "acme"])
    assert r.exit_code == 0, r.output
    assert "high" in r.output
    assert "Bad lib" in r.output

    # Extract finding id from `findings list` — it isn't printed there,
    # so query the DB directly to get the id.
    import sqlite3

    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT id, status FROM findings").fetchone()
    finding_id, old_status = row
    conn.close()

    # Update: mark as accepted-risk.
    r = _cli(
        db_path, artifacts_path,
        ["findings", "update", finding_id, "--status", "accepted-risk"],
    )
    assert r.exit_code == 0, r.output

    conn = sqlite3.connect(db_path)
    new_status = conn.execute(
        "SELECT status FROM findings WHERE id = ?", (finding_id,)
    ).fetchone()[0]
    conn.close()
    assert old_status == "active"
    assert new_status == "accepted-risk"


def test_target_weight_update_recomputes_finding_priorities(
    tmp_path: Path, db_path: str, artifacts_path: str
) -> None:
    _cli(db_path, artifacts_path, ["org", "create", "acme"])
    p = _seed_nuclei(tmp_path)
    _cli(db_path, artifacts_path, ["ingest", "--org", "acme", "--tool", "nuclei", str(p)])

    import sqlite3

    conn = sqlite3.connect(db_path)
    target_id = conn.execute(
        "SELECT id FROM targets WHERE name = 'https://api.acme.com'"
    ).fetchone()[0]
    old_priority = conn.execute("SELECT priority FROM findings").fetchone()[0]
    conn.close()

    r = _cli(
        db_path, artifacts_path,
        ["target", "update", target_id, "--weight", "2.0"],
    )
    assert r.exit_code == 0, r.output

    conn = sqlite3.connect(db_path)
    new_priority = conn.execute("SELECT priority FROM findings").fetchone()[0]
    conn.close()
    assert new_priority == pytest.approx(old_priority * 2.0)


def test_scan_list_shows_ingested_scans(
    tmp_path: Path, db_path: str, artifacts_path: str
) -> None:
    _cli(db_path, artifacts_path, ["org", "create", "acme"])
    p = _seed_nuclei(tmp_path)
    _cli(db_path, artifacts_path, ["ingest", "--org", "acme", "--tool", "nuclei", str(p)])

    r = _cli(db_path, artifacts_path, ["scan", "list", "--org", "acme"])
    assert r.exit_code == 0, r.output
    assert "nuclei" in r.output
    assert "extracted" in r.output
