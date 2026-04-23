"""CRUD helpers over the CSAK SQLite schema.

Higher-level operations (target promotion, dedup, scan linkage) live
in the ingest module. This file deliberately does one thing: move
rows between Python dataclasses and SQLite.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Iterable

from .models import (
    Artifact,
    Finding,
    FindingScanOccurrence,
    Org,
    Scan,
    Target,
)


def new_id() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _parse_iso(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value)


# ---------------------------------------------------------------------------
# Org
# ---------------------------------------------------------------------------


def create_org(conn: sqlite3.Connection, *, name: str, slug: str, notes: str = "") -> Org:
    now = _now()
    org = Org(
        id=new_id(),
        name=name,
        slug=slug,
        notes=notes,
        created=now,
        updated=now,
    )
    conn.execute(
        "INSERT INTO orgs(id, name, slug, notes, created, updated) VALUES (?, ?, ?, ?, ?, ?)",
        (org.id, org.name, org.slug, org.notes, _iso(org.created), _iso(org.updated)),
    )
    conn.commit()
    return org


def get_org_by_slug(conn: sqlite3.Connection, slug: str) -> Org | None:
    row = conn.execute(
        "SELECT * FROM orgs WHERE slug = ? AND deleted_at IS NULL", (slug,)
    ).fetchone()
    return _row_to_org(row) if row else None


def get_org(conn: sqlite3.Connection, org_id: str) -> Org | None:
    row = conn.execute(
        "SELECT * FROM orgs WHERE id = ? AND deleted_at IS NULL", (org_id,)
    ).fetchone()
    return _row_to_org(row) if row else None


def list_orgs(conn: sqlite3.Connection) -> list[Org]:
    rows = conn.execute(
        "SELECT * FROM orgs WHERE deleted_at IS NULL ORDER BY name"
    ).fetchall()
    return [_row_to_org(r) for r in rows]


def _row_to_org(row: sqlite3.Row) -> Org:
    return Org(
        id=row["id"],
        name=row["name"],
        slug=row["slug"],
        notes=row["notes"],
        created=_parse_iso(row["created"]),
        updated=_parse_iso(row["updated"]),
        deleted_at=_parse_iso(row["deleted_at"]),
    )


# ---------------------------------------------------------------------------
# Target
# ---------------------------------------------------------------------------


def insert_target(conn: sqlite3.Connection, target: Target) -> Target:
    if target.first_seen is None:
        target.first_seen = _now()
    if target.last_seen is None:
        target.last_seen = target.first_seen
    conn.execute(
        """
        INSERT INTO targets(id, org_id, name, type, identifiers_json,
                            parent_target_id, target_weight,
                            first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            target.id,
            target.org_id,
            target.name,
            target.type,
            json.dumps(target.identifiers),
            target.parent_target_id,
            target.target_weight,
            _iso(target.first_seen),
            _iso(target.last_seen),
        ),
    )
    return target


def get_target_by_name(
    conn: sqlite3.Connection, *, org_id: str, name: str
) -> Target | None:
    row = conn.execute(
        "SELECT * FROM targets WHERE org_id = ? AND name = ? AND deleted_at IS NULL",
        (org_id, name),
    ).fetchone()
    return _row_to_target(row) if row else None


def get_target(conn: sqlite3.Connection, target_id: str) -> Target | None:
    row = conn.execute(
        "SELECT * FROM targets WHERE id = ? AND deleted_at IS NULL", (target_id,)
    ).fetchone()
    return _row_to_target(row) if row else None


def list_targets(conn: sqlite3.Connection, org_id: str) -> list[Target]:
    rows = conn.execute(
        "SELECT * FROM targets WHERE org_id = ? AND deleted_at IS NULL ORDER BY name",
        (org_id,),
    ).fetchall()
    return [_row_to_target(r) for r in rows]


def find_target_containing_identifier(
    conn: sqlite3.Connection, *, org_id: str, identifier: str
) -> Target | None:
    """Return any Target in this Org whose identifiers list contains
    `identifier`, or None. Used by the promotion logic.

    identifiers_json is a JSON array of strings; we use SQLite's JSON1
    extension (which is bundled with modern SQLite) for the search.
    """
    try:
        row = conn.execute(
            """
            SELECT * FROM targets
            WHERE org_id = ?
              AND deleted_at IS NULL
              AND EXISTS (
                  SELECT 1 FROM json_each(targets.identifiers_json)
                  WHERE json_each.value = ?
              )
            LIMIT 1
            """,
            (org_id, identifier),
        ).fetchone()
    except sqlite3.OperationalError:
        # JSON1 not available — fall back to Python-side scan.
        for t in list_targets(conn, org_id):
            if identifier in t.identifiers:
                return t
        return None
    return _row_to_target(row) if row else None


def add_identifier(conn: sqlite3.Connection, target: Target, identifier: str) -> None:
    if identifier in target.identifiers:
        return
    target.identifiers.append(identifier)
    conn.execute(
        "UPDATE targets SET identifiers_json = ?, last_seen = ? WHERE id = ?",
        (json.dumps(target.identifiers), _iso(_now()), target.id),
    )


def update_target_weight(
    conn: sqlite3.Connection, target_id: str, weight: float
) -> Target | None:
    conn.execute(
        "UPDATE targets SET target_weight = ?, last_seen = ? WHERE id = ?",
        (weight, _iso(_now()), target_id),
    )
    conn.commit()
    return get_target(conn, target_id)


def touch_target(conn: sqlite3.Connection, target_id: str, when: datetime) -> None:
    conn.execute(
        "UPDATE targets SET last_seen = ? WHERE id = ?",
        (_iso(when), target_id),
    )


def _row_to_target(row: sqlite3.Row) -> Target:
    return Target(
        id=row["id"],
        org_id=row["org_id"],
        name=row["name"],
        type=row["type"],
        identifiers=json.loads(row["identifiers_json"]),
        parent_target_id=row["parent_target_id"],
        target_weight=row["target_weight"],
        first_seen=_parse_iso(row["first_seen"]),
        last_seen=_parse_iso(row["last_seen"]),
        deleted_at=_parse_iso(row["deleted_at"]),
    )


# ---------------------------------------------------------------------------
# Artifact
# ---------------------------------------------------------------------------


def insert_artifact(conn: sqlite3.Connection, artifact: Artifact) -> Artifact:
    conn.execute(
        """
        INSERT INTO artifacts(id, org_id, source_tool, received_at,
                              path, hash, period_hint)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            artifact.id,
            artifact.org_id,
            artifact.source_tool,
            _iso(artifact.received_at),
            artifact.path,
            artifact.hash,
            artifact.period_hint,
        ),
    )
    return artifact


def get_artifact_by_hash(
    conn: sqlite3.Connection, *, org_id: str, hash_: str
) -> Artifact | None:
    row = conn.execute(
        "SELECT * FROM artifacts WHERE org_id = ? AND hash = ?",
        (org_id, hash_),
    ).fetchone()
    return _row_to_artifact(row) if row else None


def get_artifact(conn: sqlite3.Connection, artifact_id: str) -> Artifact | None:
    row = conn.execute(
        "SELECT * FROM artifacts WHERE id = ?", (artifact_id,)
    ).fetchone()
    return _row_to_artifact(row) if row else None


def _row_to_artifact(row: sqlite3.Row) -> Artifact:
    return Artifact(
        id=row["id"],
        org_id=row["org_id"],
        source_tool=row["source_tool"],
        received_at=_parse_iso(row["received_at"]),
        path=row["path"],
        hash=row["hash"],
        period_hint=row["period_hint"],
    )


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------


def insert_scan(conn: sqlite3.Connection, scan: Scan) -> Scan:
    if scan.ingested_at is None:
        scan.ingested_at = _now()
    conn.execute(
        """
        INSERT INTO scans(id, org_id, source_tool, label,
                          scan_started_at, scan_completed_at, timestamp_source,
                          artifact_ids_json, target_ids_json, ingested_at, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan.id,
            scan.org_id,
            scan.source_tool,
            scan.label,
            _iso(scan.scan_started_at),
            _iso(scan.scan_completed_at),
            scan.timestamp_source,
            json.dumps(scan.artifact_ids),
            json.dumps(scan.target_ids),
            _iso(scan.ingested_at),
            scan.notes,
        ),
    )
    return scan


def update_scan_targets(conn: sqlite3.Connection, scan_id: str, target_ids: list[str]) -> None:
    conn.execute(
        "UPDATE scans SET target_ids_json = ? WHERE id = ?",
        (json.dumps(target_ids), scan_id),
    )


def get_scan(conn: sqlite3.Connection, scan_id: str) -> Scan | None:
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return _row_to_scan(row) if row else None


def list_scans(conn: sqlite3.Connection, org_id: str) -> list[Scan]:
    rows = conn.execute(
        "SELECT * FROM scans WHERE org_id = ? ORDER BY scan_started_at",
        (org_id,),
    ).fetchall()
    return [_row_to_scan(r) for r in rows]


def _row_to_scan(row: sqlite3.Row) -> Scan:
    return Scan(
        id=row["id"],
        org_id=row["org_id"],
        source_tool=row["source_tool"],
        label=row["label"],
        scan_started_at=_parse_iso(row["scan_started_at"]),
        scan_completed_at=_parse_iso(row["scan_completed_at"]),
        timestamp_source=row["timestamp_source"],
        artifact_ids=json.loads(row["artifact_ids_json"]),
        target_ids=json.loads(row["target_ids_json"]),
        ingested_at=_parse_iso(row["ingested_at"]),
        notes=row["notes"],
    )


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


def insert_finding(conn: sqlite3.Connection, finding: Finding) -> Finding:
    conn.execute(
        """
        INSERT INTO findings(
            id, org_id, target_id, source_tool, source_artifact_id, dedup_key,
            title, severity, confidence, priority,
            severity_weight, confidence_weight, raw_json, normalized_json,
            first_seen, last_seen, status, tags_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            finding.id,
            finding.org_id,
            finding.target_id,
            finding.source_tool,
            finding.source_artifact_id,
            finding.dedup_key,
            finding.title,
            finding.severity,
            finding.confidence,
            finding.priority,
            finding.severity_weight,
            finding.confidence_weight,
            json.dumps(finding.raw),
            json.dumps(finding.normalized),
            _iso(finding.first_seen),
            _iso(finding.last_seen),
            finding.status,
            json.dumps(finding.tags),
        ),
    )
    return finding


def get_finding(conn: sqlite3.Connection, finding_id: str) -> Finding | None:
    row = conn.execute(
        "SELECT * FROM findings WHERE id = ? AND deleted_at IS NULL", (finding_id,)
    ).fetchone()
    return _row_to_finding(row) if row else None


def get_finding_by_dedup(
    conn: sqlite3.Connection, *, org_id: str, source_tool: str, dedup_key: str
) -> Finding | None:
    row = conn.execute(
        """
        SELECT * FROM findings
        WHERE org_id = ? AND source_tool = ? AND dedup_key = ?
          AND deleted_at IS NULL
        """,
        (org_id, source_tool, dedup_key),
    ).fetchone()
    return _row_to_finding(row) if row else None


def update_finding_last_seen(
    conn: sqlite3.Connection, finding_id: str, last_seen: datetime
) -> None:
    conn.execute(
        "UPDATE findings SET last_seen = ? WHERE id = ?",
        (_iso(last_seen), finding_id),
    )


def update_finding_priority(
    conn: sqlite3.Connection,
    finding_id: str,
    *,
    priority: float,
    status: str | None = None,
    tags: list[str] | None = None,
) -> None:
    """Apply an analyst mutation and its recomputed priority.

    `status`/`tags` are optional so the caller can update just the
    priority (e.g. after a target weight changes).
    """
    fields: list[str] = ["priority = ?"]
    params: list = [priority]
    if status is not None:
        fields.append("status = ?")
        params.append(status)
    if tags is not None:
        fields.append("tags_json = ?")
        params.append(json.dumps(tags))
    params.append(finding_id)
    conn.execute(
        f"UPDATE findings SET {', '.join(fields)} WHERE id = ?",
        tuple(params),
    )


def list_findings_for_org(
    conn: sqlite3.Connection,
    org_id: str,
    *,
    status: str | None = None,
    severity: str | None = None,
) -> list[Finding]:
    clauses = ["org_id = ?", "deleted_at IS NULL"]
    params: list = [org_id]
    if status:
        clauses.append("status = ?")
        params.append(status)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    sql = f"SELECT * FROM findings WHERE {' AND '.join(clauses)} ORDER BY priority DESC"
    rows = conn.execute(sql, tuple(params)).fetchall()
    return [_row_to_finding(r) for r in rows]


def list_findings_for_target(
    conn: sqlite3.Connection, target_id: str
) -> list[Finding]:
    rows = conn.execute(
        "SELECT * FROM findings WHERE target_id = ? AND deleted_at IS NULL ORDER BY priority DESC",
        (target_id,),
    ).fetchall()
    return [_row_to_finding(r) for r in rows]


def _row_to_finding(row: sqlite3.Row) -> Finding:
    return Finding(
        id=row["id"],
        org_id=row["org_id"],
        target_id=row["target_id"],
        source_tool=row["source_tool"],
        source_artifact_id=row["source_artifact_id"],
        dedup_key=row["dedup_key"],
        title=row["title"],
        severity=row["severity"],
        confidence=row["confidence"],
        priority=row["priority"],
        severity_weight=row["severity_weight"],
        confidence_weight=row["confidence_weight"],
        raw=json.loads(row["raw_json"]),
        normalized=json.loads(row["normalized_json"]),
        first_seen=_parse_iso(row["first_seen"]),
        last_seen=_parse_iso(row["last_seen"]),
        status=row["status"],
        tags=json.loads(row["tags_json"]),
        deleted_at=_parse_iso(row["deleted_at"]),
    )


# ---------------------------------------------------------------------------
# FindingScanOccurrence
# ---------------------------------------------------------------------------


def record_occurrence(
    conn: sqlite3.Connection,
    *,
    finding_id: str,
    scan_id: str,
    seen_at: datetime,
) -> None:
    conn.execute(
        """
        INSERT OR IGNORE INTO finding_scan_occurrences(finding_id, scan_id, seen_at)
        VALUES (?, ?, ?)
        """,
        (finding_id, scan_id, _iso(seen_at)),
    )


def occurrences_for_finding(
    conn: sqlite3.Connection, finding_id: str
) -> list[FindingScanOccurrence]:
    rows = conn.execute(
        "SELECT finding_id, scan_id, seen_at FROM finding_scan_occurrences WHERE finding_id = ? ORDER BY seen_at",
        (finding_id,),
    ).fetchall()
    return [
        FindingScanOccurrence(
            finding_id=r["finding_id"],
            scan_id=r["scan_id"],
            seen_at=_parse_iso(r["seen_at"]),
        )
        for r in rows
    ]


def scans_for_finding(conn: sqlite3.Connection, finding_id: str) -> list[Scan]:
    rows = conn.execute(
        """
        SELECT s.* FROM scans s
        JOIN finding_scan_occurrences o ON o.scan_id = s.id
        WHERE o.finding_id = ?
        ORDER BY s.scan_started_at
        """,
        (finding_id,),
    ).fetchall()
    return [_row_to_scan(r) for r in rows]


def findings_for_scan(conn: sqlite3.Connection, scan_id: str) -> list[Finding]:
    rows = conn.execute(
        """
        SELECT f.* FROM findings f
        JOIN finding_scan_occurrences o ON o.finding_id = f.id
        WHERE o.scan_id = ? AND f.deleted_at IS NULL
        ORDER BY f.priority DESC
        """,
        (scan_id,),
    ).fetchall()
    return [_row_to_finding(r) for r in rows]
