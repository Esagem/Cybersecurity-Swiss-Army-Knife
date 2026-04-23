"""Target promotion logic.

When a parser emits a finding keyed to a specific identifier (a host,
a URL, a subdomain), the storage layer needs to decide which Target
the finding attaches to. The rule from the spec:

1. If a Target with ``name == identifier`` already exists, use it.
2. If the identifier is present in some parent Target's identifiers
   list AND the parser is asking to attach a finding, promote it to
   its own child Target under that parent.
3. Otherwise create a new top-level Target.

``parent_hint`` lets the caller bias the promotion toward a specific
parent when the string match alone is ambiguous (e.g. a fresh ingest
where the parent hasn't been seen before).
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from csak.storage import repository as repo
from csak.storage.models import Target


def resolve_target(
    conn: sqlite3.Connection,
    *,
    org_id: str,
    identifier: str,
    target_type: str,
    parent_hint: str | None = None,
    promote: bool = True,
    now: datetime | None = None,
) -> Target:
    now = now or datetime.now(timezone.utc)

    # 1. Already a Target by name.
    existing = repo.get_target_by_name(conn, org_id=org_id, name=identifier)
    if existing is not None:
        repo.touch_target(conn, existing.id, now)
        return existing

    # 2. Named inside some parent's identifiers list.
    parent = repo.find_target_containing_identifier(
        conn, org_id=org_id, identifier=identifier
    )
    if parent is not None and promote:
        child = repo.insert_target(
            conn,
            Target(
                id=repo.new_id(),
                org_id=org_id,
                name=identifier,
                type=target_type,
                identifiers=[identifier],
                parent_target_id=parent.id,
                first_seen=now,
                last_seen=now,
            ),
        )
        return child

    # 3. Brand new top-level Target. Optionally nest under a hinted parent.
    parent_id: str | None = None
    if parent_hint:
        hinted = repo.get_target_by_name(conn, org_id=org_id, name=parent_hint)
        if hinted is not None:
            parent_id = hinted.id

    created = repo.insert_target(
        conn,
        Target(
            id=repo.new_id(),
            org_id=org_id,
            name=identifier,
            type=target_type,
            identifiers=[identifier],
            parent_target_id=parent_id,
            first_seen=now,
            last_seen=now,
        ),
    )
    return created


def record_identifier_only(
    conn: sqlite3.Connection,
    *,
    org_id: str,
    parent_target: Target,
    identifier: str,
) -> None:
    """Add ``identifier`` to ``parent_target.identifiers`` without
    creating a child Target.

    Used when a discovery tool (subfinder) surfaces a new subdomain
    but no vuln scanner has hit it yet — it lives as a string until
    something makes it worth promoting.
    """
    repo.add_identifier(conn, parent_target, identifier)
