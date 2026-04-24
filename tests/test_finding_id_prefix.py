"""`findings list` must surface a usable ID handle, and `findings show`
/ `findings update` must accept it — otherwise mutating a finding you
spotted via `list` requires dropping into sqlite3.

Coverage:
  * `findings list` shows an ID column whose values appear verbatim in
    the beginning of each finding's full UUID.
  * `findings show <prefix>` resolves to the right row.
  * `findings update <prefix>` mutates the right row.
  * Ambiguous prefix errors cleanly (and suggests being more specific).
  * Unknown prefix errors cleanly.
  * A full UUID still works (backwards-compatible).
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from click.testing import CliRunner

from csak.cli.findings import SHORT_ID_WIDTH
from csak.cli.main import main
from csak.storage import repository as repo
from csak.storage.db import connect


def _cli(runner, db_path, artifacts, args):
    return runner.invoke(
        main,
        ["--db", str(db_path), "--artifacts-dir", str(artifacts), *args],
    )


def _nuclei(ts="2026-04-20T10:00:00Z", matched_at="https://acme.com") -> str:
    return json.dumps({
        "template-id": "t1",
        "info": {"name": "Bad lib", "severity": "high"},
        "matched-at": matched_at,
        "host": matched_at.split("//", 1)[-1],
        "timestamp": ts,
    })


@pytest.fixture
def seeded_env(tmp_path: Path):
    db = tmp_path / "csak.db"
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    runner = CliRunner()

    _cli(runner, db, artifacts, ["org", "create", "acme"])
    p = tmp_path / "n.jsonl"
    p.write_text(_nuclei() + "\n", encoding="utf-8")
    _cli(runner, db, artifacts, ["ingest", "--org", "acme", "--tool", "nuclei", str(p)])

    def invoke(args):
        return _cli(runner, db, artifacts, args)

    return invoke, db


def test_findings_list_includes_id_column(seeded_env) -> None:
    invoke, db = seeded_env
    r = invoke(["findings", "list", "--org", "acme"])
    assert r.exit_code == 0, r.output

    # Header has ID first.
    lines = r.output.splitlines()
    assert lines[0].startswith("ID"), f"header was: {lines[0]!r}"

    # The first printed short id is the 8-char prefix of the full UUID.
    conn = sqlite3.connect(str(db))
    full_id = conn.execute("SELECT id FROM findings").fetchone()[0]
    conn.close()
    short_id = full_id[:SHORT_ID_WIDTH]
    assert short_id in r.output


def test_findings_show_accepts_short_prefix(seeded_env) -> None:
    invoke, db = seeded_env
    conn = sqlite3.connect(str(db))
    full_id = conn.execute("SELECT id FROM findings").fetchone()[0]
    conn.close()

    r = invoke(["findings", "show", full_id[:SHORT_ID_WIDTH]])
    assert r.exit_code == 0, r.output
    assert f"id:               {full_id}" in r.output


def test_findings_update_accepts_short_prefix(seeded_env) -> None:
    invoke, db = seeded_env
    conn = sqlite3.connect(str(db))
    full_id = conn.execute("SELECT id FROM findings").fetchone()[0]
    conn.close()

    r = invoke([
        "findings", "update", full_id[:SHORT_ID_WIDTH],
        "--status", "accepted-risk",
    ])
    assert r.exit_code == 0, r.output

    conn = sqlite3.connect(str(db))
    status = conn.execute(
        "SELECT status FROM findings WHERE id = ?", (full_id,)
    ).fetchone()[0]
    conn.close()
    assert status == "accepted-risk"


def test_findings_show_accepts_full_uuid_too(seeded_env) -> None:
    invoke, db = seeded_env
    conn = sqlite3.connect(str(db))
    full_id = conn.execute("SELECT id FROM findings").fetchone()[0]
    conn.close()

    r = invoke(["findings", "show", full_id])
    assert r.exit_code == 0, r.output
    assert full_id in r.output


def test_unknown_prefix_errors_cleanly(seeded_env) -> None:
    invoke, _ = seeded_env
    r = invoke(["findings", "show", "deadbeef"])
    assert r.exit_code != 0
    assert "no finding matches id prefix" in r.output


def test_ambiguous_prefix_errors_with_count(tmp_path: Path) -> None:
    """A real-world UUID collision at 8 chars is astronomically unlikely.
    Force the situation by writing two findings with hand-crafted IDs
    that share a prefix, then verify the resolver raises cleanly."""
    db_path = tmp_path / "csak.db"
    conn = connect(db_path)
    org = repo.create_org(conn, name="acme", slug="acme")

    from datetime import datetime, timezone

    from csak.storage.models import Artifact, Finding, Target

    t = repo.insert_target(conn, Target(
        id=repo.new_id(), org_id=org.id, name="x", type="domain",
        identifiers=["x"],
    ))
    art = repo.insert_artifact(conn, Artifact(
        id=repo.new_id(), org_id=org.id, source_tool="nuclei",
        received_at=datetime.now(timezone.utc), path="/dev/null", hash="h",
    ))

    def mk(id_str: str, dedup: str) -> None:
        repo.insert_finding(conn, Finding(
            id=id_str,
            org_id=org.id,
            target_id=t.id,
            source_tool="nuclei",
            source_artifact_id=art.id,
            dedup_key=dedup,
            title="x",
            severity="high",
            confidence="high",
            priority=0.75,
            severity_weight=0.75,
            confidence_weight=1.0,
            raw={},
            normalized={},
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        ))

    mk("abcd1234-0000-0000-0000-000000000001", "d1")
    mk("abcd1234-0000-0000-0000-000000000002", "d2")
    conn.commit()

    with pytest.raises(repo.AmbiguousPrefix) as exc:
        repo.resolve_finding_id(conn, "abcd1234")
    assert "matches 2 findings" in str(exc.value)
    conn.close()


def test_cli_reports_ambiguous_prefix_as_error(tmp_path: Path) -> None:
    """Same scenario but through the CLI — the analyst sees a clean
    'ambiguous' error rather than a traceback."""
    db_path = tmp_path / "csak.db"
    conn = connect(db_path)
    org = repo.create_org(conn, name="acme", slug="acme")

    from datetime import datetime, timezone

    from csak.storage.models import Artifact, Finding, Target

    t = repo.insert_target(conn, Target(
        id=repo.new_id(), org_id=org.id, name="x", type="domain",
        identifiers=["x"],
    ))
    art = repo.insert_artifact(conn, Artifact(
        id=repo.new_id(), org_id=org.id, source_tool="nuclei",
        received_at=datetime.now(timezone.utc), path="/dev/null", hash="h",
    ))
    for i in range(1, 3):
        repo.insert_finding(conn, Finding(
            id=f"abcd1234-0000-0000-0000-00000000000{i}",
            org_id=org.id, target_id=t.id, source_tool="nuclei",
            source_artifact_id=art.id, dedup_key=f"d{i}", title="x",
            severity="high", confidence="high",
            priority=0.75, severity_weight=0.75, confidence_weight=1.0,
            raw={}, normalized={},
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        ))
    conn.commit()
    conn.close()

    runner = CliRunner()
    r = runner.invoke(main, [
        "--db", str(db_path), "findings", "show", "abcd1234",
    ])
    assert r.exit_code != 0
    assert "ambiguous" in r.output
    assert "matches 2" in r.output
