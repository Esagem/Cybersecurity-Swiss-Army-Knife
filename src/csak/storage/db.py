"""Connection factory for the CSAK SQLite database."""
from __future__ import annotations

import sqlite3
from pathlib import Path

from .schema import SCHEMA_STATEMENTS, SCHEMA_VERSION


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
        conn.execute("INSERT INTO schema_version(version) VALUES (?)", (SCHEMA_VERSION,))
    conn.commit()
