"""Slice 3 schema migration tests.

Verifies that an existing slice 1/2 database (SCHEMA_VERSION=1, no
slice 3 columns on ``scans``) is migrated in place when CSAK opens
it under slice 3, and that the migration is idempotent across
re-opens. Old rows must keep their data and gain ``depth=0``,
``parent_scan_id=NULL``, ``triggered_by_finding_id=NULL`` defaults.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from csak.storage.db import connect


# A standalone copy of the slice 2 schema — no slice 3 columns.
# Reproduced verbatim because the live ``schema.py`` has already
# moved to slice 3 and we want to start the test from genuine
# slice 2 state.
_SLICE2_STATEMENTS = (
    "CREATE TABLE schema_version (version INTEGER PRIMARY KEY)",
    """
    CREATE TABLE orgs (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, slug TEXT NOT NULL UNIQUE,
        notes TEXT NOT NULL DEFAULT '', created TEXT NOT NULL,
        updated TEXT NOT NULL, deleted_at TEXT
    )
    """,
    """
    CREATE TABLE targets (
        id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES orgs(id),
        name TEXT NOT NULL, type TEXT NOT NULL,
        identifiers_json TEXT NOT NULL DEFAULT '[]',
        parent_target_id TEXT REFERENCES targets(id),
        target_weight REAL NOT NULL DEFAULT 1.0,
        first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, deleted_at TEXT
    )
    """,
    """
    CREATE TABLE artifacts (
        id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES orgs(id),
        source_tool TEXT NOT NULL, received_at TEXT NOT NULL,
        path TEXT NOT NULL, hash TEXT NOT NULL, period_hint TEXT,
        UNIQUE(org_id, hash)
    )
    """,
    """
    CREATE TABLE scans (
        id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES orgs(id),
        source_tool TEXT NOT NULL, label TEXT NOT NULL,
        scan_started_at TEXT NOT NULL, scan_completed_at TEXT NOT NULL,
        timestamp_source TEXT NOT NULL,
        artifact_ids_json TEXT NOT NULL DEFAULT '[]',
        target_ids_json TEXT NOT NULL DEFAULT '[]',
        ingested_at TEXT NOT NULL, notes TEXT NOT NULL DEFAULT ''
    )
    """,
    """
    CREATE TABLE findings (
        id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES orgs(id),
        target_id TEXT NOT NULL REFERENCES targets(id),
        source_tool TEXT NOT NULL,
        source_artifact_id TEXT NOT NULL REFERENCES artifacts(id),
        dedup_key TEXT NOT NULL, title TEXT NOT NULL, severity TEXT,
        confidence TEXT NOT NULL, priority REAL NOT NULL,
        severity_weight REAL NOT NULL, confidence_weight REAL NOT NULL,
        raw_json TEXT NOT NULL, normalized_json TEXT NOT NULL,
        first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active',
        tags_json TEXT NOT NULL DEFAULT '[]', deleted_at TEXT,
        UNIQUE(org_id, source_tool, dedup_key)
    )
    """,
    """
    CREATE TABLE finding_scan_occurrences (
        finding_id TEXT NOT NULL REFERENCES findings(id),
        scan_id TEXT NOT NULL REFERENCES scans(id),
        seen_at TEXT NOT NULL, PRIMARY KEY(finding_id, scan_id)
    )
    """,
)


def _make_slice2_db(path: Path) -> None:
    conn = sqlite3.connect(str(path))
    for stmt in _SLICE2_STATEMENTS:
        conn.execute(stmt)
    conn.execute("INSERT INTO schema_version(version) VALUES (1)")

    # Insert one fully-populated scan row using the slice 2 column set.
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO orgs(id, name, slug, notes, created, updated) "
        "VALUES ('o1', 'acme', 'acme', '', ?, ?)",
        (now, now),
    )
    conn.execute(
        "INSERT INTO scans(id, org_id, source_tool, label, "
        "scan_started_at, scan_completed_at, timestamp_source, "
        "artifact_ids_json, target_ids_json, ingested_at, notes) "
        "VALUES ('s1','o1','nuclei','test',?,?, 'extracted','[]','[]',?,'')",
        (now, now, now),
    )
    conn.commit()
    conn.close()


def test_migration_adds_slice3_columns_in_place(tmp_path: Path) -> None:
    db_path = tmp_path / "csak.db"
    _make_slice2_db(db_path)

    # Re-open via slice 3 connector — should migrate.
    conn = connect(db_path)
    try:
        version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
        assert version == 2

        cols = {r[1] for r in conn.execute("PRAGMA table_info(scans)").fetchall()}
        assert "parent_scan_id" in cols
        assert "depth" in cols
        assert "triggered_by_finding_id" in cols

        # Old row preserved, new columns defaulted.
        row = conn.execute(
            "SELECT depth, parent_scan_id, triggered_by_finding_id "
            "FROM scans WHERE id = 's1'"
        ).fetchone()
        assert row[0] == 0
        assert row[1] is None
        assert row[2] is None
    finally:
        conn.close()


def test_migration_is_idempotent(tmp_path: Path) -> None:
    db_path = tmp_path / "csak.db"
    _make_slice2_db(db_path)
    # First open — applies the migration.
    connect(db_path).close()
    # Second open — should be a no-op (no error from re-running ALTER).
    conn = connect(db_path)
    try:
        version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
        assert version == 2
    finally:
        conn.close()


def test_fresh_db_starts_at_version_2(tmp_path: Path) -> None:
    db_path = tmp_path / "fresh.db"
    conn = connect(db_path)
    try:
        version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
        assert version == 2
    finally:
        conn.close()
