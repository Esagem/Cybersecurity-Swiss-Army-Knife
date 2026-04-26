"""Connection factory for the CSAK SQLite database."""
from __future__ import annotations

import sqlite3
from pathlib import Path

from .schema import MIGRATIONS, SCHEMA_STATEMENTS, SCHEMA_VERSION


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Open a connection and ensure the schema is initialized.

    Foreign keys are off by default in SQLite; we turn them on for
    every connection so the junction tables can rely on referential
    integrity at insert time.
    """
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    _init_schema(conn)
    return conn


def _init_schema(conn: sqlite3.Connection) -> None:
    for stmt in SCHEMA_STATEMENTS:
        conn.execute(stmt)
    row = conn.execute("SELECT version FROM schema_version").fetchone()
    if row is None:
        # Fresh database: the CREATE TABLE statements above already
        # reflect the current schema, so we simply record the version.
        conn.execute("INSERT INTO schema_version(version) VALUES (?)", (SCHEMA_VERSION,))
    else:
        current = int(row["version"])
        while current < SCHEMA_VERSION:
            for stmt in MIGRATIONS.get(current, ()):
                conn.execute(stmt)
            current += 1
        if current != int(row["version"]):
            conn.execute("UPDATE schema_version SET version = ?", (current,))
    conn.commit()
