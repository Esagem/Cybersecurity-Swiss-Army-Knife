"""SQLite schema for CSAK entities.

The shape of these tables mirrors the slice-1 data model exactly —
Org → Target → Scan → Finding, plus an immutable Artifact layer and a
FindingScanOccurrence junction that records every scan a finding has
appeared in.

Slice 3 adds three nullable columns to ``scans`` (``parent_scan_id``,
``depth``, ``triggered_by_finding_id``) for recursion lineage. Existing
slice 1/2 databases are migrated in place by ``MIGRATIONS`` below; the
CREATE TABLE statement reflects the slice 3 shape so fresh installs
get the new columns directly.
"""
from __future__ import annotations

SCHEMA_VERSION = 2

# Each statement is run in order on a fresh database.
SCHEMA_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS schema_version (
        version INTEGER PRIMARY KEY
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS orgs (
        id          TEXT PRIMARY KEY,
        name        TEXT NOT NULL,
        slug        TEXT NOT NULL UNIQUE,
        notes       TEXT NOT NULL DEFAULT '',
        created     TEXT NOT NULL,
        updated     TEXT NOT NULL,
        deleted_at  TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS targets (
        id                TEXT PRIMARY KEY,
        org_id            TEXT NOT NULL REFERENCES orgs(id),
        name              TEXT NOT NULL,
        type              TEXT NOT NULL,
        identifiers_json  TEXT NOT NULL DEFAULT '[]',
        parent_target_id  TEXT REFERENCES targets(id),
        target_weight     REAL NOT NULL DEFAULT 1.0,
        first_seen        TEXT NOT NULL,
        last_seen         TEXT NOT NULL,
        deleted_at        TEXT
    )
    """,
    # A target's (org_id, name) should be unique among active rows so
    # the promotion logic can look a target up by (org, identifier string).
    """
    CREATE UNIQUE INDEX IF NOT EXISTS idx_targets_org_name_active
    ON targets(org_id, name) WHERE deleted_at IS NULL
    """,
    """
    CREATE TABLE IF NOT EXISTS artifacts (
        id            TEXT PRIMARY KEY,
        org_id        TEXT NOT NULL REFERENCES orgs(id),
        source_tool   TEXT NOT NULL,
        received_at   TEXT NOT NULL,
        path          TEXT NOT NULL,
        hash          TEXT NOT NULL,
        period_hint   TEXT,
        UNIQUE(org_id, hash)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS scans (
        id                       TEXT PRIMARY KEY,
        org_id                   TEXT NOT NULL REFERENCES orgs(id),
        source_tool              TEXT NOT NULL,
        label                    TEXT NOT NULL,
        scan_started_at          TEXT NOT NULL,
        scan_completed_at        TEXT NOT NULL,
        timestamp_source         TEXT NOT NULL,
        artifact_ids_json        TEXT NOT NULL DEFAULT '[]',
        target_ids_json          TEXT NOT NULL DEFAULT '[]',
        ingested_at              TEXT NOT NULL,
        notes                    TEXT NOT NULL DEFAULT '',
        parent_scan_id           TEXT REFERENCES scans(id),
        depth                    INTEGER NOT NULL DEFAULT 0,
        triggered_by_finding_id  TEXT REFERENCES findings(id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS findings (
        id                  TEXT PRIMARY KEY,
        org_id              TEXT NOT NULL REFERENCES orgs(id),
        target_id           TEXT NOT NULL REFERENCES targets(id),
        source_tool         TEXT NOT NULL,
        source_artifact_id  TEXT NOT NULL REFERENCES artifacts(id),
        dedup_key           TEXT NOT NULL,
        title               TEXT NOT NULL,
        severity            TEXT,
        confidence          TEXT NOT NULL,
        priority            REAL NOT NULL,
        severity_weight     REAL NOT NULL,
        confidence_weight   REAL NOT NULL,
        raw_json            TEXT NOT NULL,
        normalized_json     TEXT NOT NULL,
        first_seen          TEXT NOT NULL,
        last_seen           TEXT NOT NULL,
        status              TEXT NOT NULL DEFAULT 'active',
        tags_json           TEXT NOT NULL DEFAULT '[]',
        deleted_at          TEXT,
        UNIQUE(org_id, source_tool, dedup_key)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_findings_org_active
    ON findings(org_id, status) WHERE deleted_at IS NULL
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_findings_target
    ON findings(target_id) WHERE deleted_at IS NULL
    """,
    """
    CREATE TABLE IF NOT EXISTS finding_scan_occurrences (
        finding_id  TEXT NOT NULL REFERENCES findings(id),
        scan_id     TEXT NOT NULL REFERENCES scans(id),
        seen_at     TEXT NOT NULL,
        PRIMARY KEY(finding_id, scan_id)
    )
    """,
)


# In-place migrations from version N to N+1. Each entry's statements
# run only once when an existing database is opened at the older
# version. The connector applies them in ascending order until the
# database matches ``SCHEMA_VERSION``.
MIGRATIONS: dict[int, tuple[str, ...]] = {
    1: (
        # Slice 3: Scan lineage columns. CREATE TABLE IF NOT EXISTS won't
        # add columns to an existing table; ALTER TABLE handles slice 1/2
        # databases that pre-date these columns.
        "ALTER TABLE scans ADD COLUMN parent_scan_id TEXT REFERENCES scans(id)",
        "ALTER TABLE scans ADD COLUMN depth INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE scans ADD COLUMN triggered_by_finding_id TEXT REFERENCES findings(id)",
    ),
}
