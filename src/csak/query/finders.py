"""Finder queries for slice-1 reads.

This module is the single source of truth for "which findings are
active during a given period" — the rule report generation and the
``csak findings list`` command both need.

Period semantics (from the spec):

    A finding is active during [a, b] if
        first_seen <= b AND last_seen >= a

That is, a finding belongs to the window if any of its occurrences
fell inside the window. Windows are half-open at the implementation
level: ``[start, end)``.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from csak.storage import repository as repo
from csak.storage.models import Finding, Org, Scan, Target


@dataclass
class Period:
    label: str          # human-facing label ("2026-04", "today", "q1-review")
    start: datetime     # inclusive
    end: datetime       # exclusive


def parse_period(value: str, *, now: datetime | None = None) -> Period:
    """Understand a handful of common period shapes.

    Supported forms:
      * ``YYYY-MM`` — a calendar month.
      * ``YYYY-MM-DD`` — a single day.
      * ``today`` — from midnight UTC today to midnight UTC tomorrow.
      * ``all`` — the inclusive-of-everything window.
      * anything else — treated as an opaque label, meaning no window
        filter is applied (the analyst named their own period).
    """
    now = now or datetime.now(timezone.utc)

    if value == "today":
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=1)
        return Period(label="today", start=start, end=end)

    if value == "all":
        # End far enough in the future that nothing sorts past it.
        start = datetime(1970, 1, 1, tzinfo=timezone.utc)
        end = datetime(9999, 1, 1, tzinfo=timezone.utc)
        return Period(label="all", start=start, end=end)

    # YYYY-MM
    if len(value) == 7 and value[4] == "-":
        year, month = int(value[:4]), int(value[5:])
        start = datetime(year, month, 1, tzinfo=timezone.utc)
        if month == 12:
            end = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
        else:
            end = datetime(year, month + 1, 1, tzinfo=timezone.utc)
        return Period(label=value, start=start, end=end)

    # YYYY-MM-DD
    if len(value) == 10 and value[4] == "-" and value[7] == "-":
        d = datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
        return Period(label=value, start=d, end=d + timedelta(days=1))

    # Opaque label — no window filter.
    return Period(
        label=value,
        start=datetime(1970, 1, 1, tzinfo=timezone.utc),
        end=datetime(9999, 1, 1, tzinfo=timezone.utc),
    )


# ---------------------------------------------------------------------------
# Reads used by both report generation and `csak findings list`.
# ---------------------------------------------------------------------------


def findings_active_in_period(
    conn: sqlite3.Connection,
    org: Org,
    period: Period,
    *,
    include_statuses: tuple[str, ...] = ("active", "accepted-risk"),
) -> list[Finding]:
    placeholders = ",".join("?" * len(include_statuses))
    rows = conn.execute(
        f"""
        SELECT * FROM findings
        WHERE org_id = ?
          AND deleted_at IS NULL
          AND status IN ({placeholders})
          AND first_seen < ?
          AND last_seen >= ?
        ORDER BY priority DESC
        """,
        (
            org.id,
            *include_statuses,
            _iso(period.end),
            _iso(period.start),
        ),
    ).fetchall()
    return [repo._row_to_finding(r) for r in rows]


def scans_contributing_to_period(
    conn: sqlite3.Connection, org: Org, period: Period
) -> list[Scan]:
    """Scans that overlap the window. Reports cite these as methodology."""
    rows = conn.execute(
        """
        SELECT * FROM scans
        WHERE org_id = ?
          AND scan_started_at < ?
          AND scan_completed_at >= ?
        ORDER BY scan_started_at
        """,
        (org.id, _iso(period.end), _iso(period.start)),
    ).fetchall()
    return [repo._row_to_scan(r) for r in rows]


def targets_for_findings(
    conn: sqlite3.Connection, findings: list[Finding]
) -> dict[str, Target]:
    out: dict[str, Target] = {}
    for f in findings:
        if f.target_id in out:
            continue
        t = repo.get_target(conn, f.target_id)
        if t is not None:
            out[t.id] = t
    return out


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()
