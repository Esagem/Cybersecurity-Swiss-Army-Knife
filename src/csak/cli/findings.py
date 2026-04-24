from __future__ import annotations

import sqlite3

import click

from csak.ingest.scoring import compute_priority
from csak.storage import repository as repo
from csak.storage.db import connect


# Short ID width used both in the `findings list` output and as the
# suggested copy length. 8 hex chars = 4 billion combinations, which
# is plenty for the scale of a single CSAK database.
SHORT_ID_WIDTH = 8


def _resolve(conn: sqlite3.Connection, finding_id: str) -> str:
    """Resolve a user-supplied finding id or prefix to a full ID.

    Converts repository errors into Click errors so the user sees a
    clean message instead of a Python traceback.
    """
    try:
        return repo.resolve_finding_id(conn, finding_id)
    except repo.AmbiguousPrefix as e:
        raise click.ClickException(str(e))
    except LookupError as e:
        raise click.ClickException(str(e))


@click.group()
def findings() -> None:
    """Inspect and update findings."""


@findings.command("list")
@click.option("--org", required=True, help="Org slug.")
@click.option(
    "--status",
    type=click.Choice(
        ["active", "suppressed", "accepted-risk", "false-positive", "fixed"],
        case_sensitive=False,
    ),
)
@click.option(
    "--severity",
    type=click.Choice(["critical", "high", "medium", "low", "info"], case_sensitive=False),
)
@click.pass_context
def list_cmd(ctx: click.Context, org: str, status: str | None, severity: str | None) -> None:
    """List findings for an org, optionally filtered."""
    conn = connect(ctx.obj["db_path"])
    try:
        org_row = repo.get_org_by_slug(conn, org)
        if org_row is None:
            raise click.ClickException(f"unknown org slug: {org!r}")
        rows = repo.list_findings_for_org(
            conn, org_row.id, status=status, severity=severity
        )
        if not rows:
            click.echo("(no findings)")
            return
        click.echo(
            f"{'ID':<{SHORT_ID_WIDTH}}  "
            f"{'PRIORITY':>8}  {'SEVERITY':<8}  {'TOOL':<10}  "
            f"{'TARGET':<30}  TITLE"
        )
        for f in rows:
            target = repo.get_target(conn, f.target_id)
            target_name = target.name if target else "?"
            click.echo(
                f"{f.id[:SHORT_ID_WIDTH]:<{SHORT_ID_WIDTH}}  "
                f"{f.priority:>8.3f}  "
                f"{(f.severity or '—'):<8}  "
                f"{f.source_tool:<10}  "
                f"{target_name[:30]:<30}  "
                f"{f.title}"
            )
    finally:
        conn.close()


@findings.command("show")
@click.argument("finding_id")
@click.pass_context
def show(ctx: click.Context, finding_id: str) -> None:
    """Show a single finding's details.

    FINDING_ID may be a full UUID or an unambiguous id prefix (at least
    the 8 characters shown by ``findings list``).
    """
    conn = connect(ctx.obj["db_path"])
    try:
        full_id = _resolve(conn, finding_id)
        f = repo.get_finding(conn, full_id)
        if f is None:
            raise click.ClickException(f"finding {finding_id} not found")
        target = repo.get_target(conn, f.target_id)
        scans = repo.scans_for_finding(conn, f.id)
        click.echo(f"id:               {f.id}")
        click.echo(f"title:            {f.title}")
        click.echo(f"tool:             {f.source_tool}")
        click.echo(f"target:           {target.name if target else f.target_id}")
        click.echo(f"severity:         {f.severity or '— (needs analyst review)'}")
        click.echo(f"confidence:       {f.confidence}")
        click.echo(f"priority:         {f.priority:.4f}")
        click.echo(f"  severity_w:     {f.severity_weight}")
        click.echo(f"  confidence_w:   {f.confidence_weight}")
        if target is not None:
            click.echo(f"  target_weight:  {target.target_weight}")
        click.echo(f"status:           {f.status}")
        click.echo(f"first_seen:       {f.first_seen}")
        click.echo(f"last_seen:        {f.last_seen}")
        click.echo(f"scans ({len(scans)}):")
        for s in scans:
            click.echo(f"  - {s.id}  {s.label}  [{s.timestamp_source}]")
    finally:
        conn.close()


@findings.command("update")
@click.argument("finding_id")
@click.option(
    "--status",
    type=click.Choice(
        ["active", "suppressed", "accepted-risk", "false-positive", "fixed"],
        case_sensitive=False,
    ),
)
@click.option("--tag", "tags", multiple=True, help="Replace tags (may be given multiple times).")
@click.pass_context
def update(
    ctx: click.Context,
    finding_id: str,
    status: str | None,
    tags: tuple[str, ...],
) -> None:
    """Mutate a finding. Triggers a priority recompute.

    FINDING_ID may be a full UUID or an unambiguous id prefix (at least
    the 8 characters shown by ``findings list``).
    """
    conn = connect(ctx.obj["db_path"])
    try:
        full_id = _resolve(conn, finding_id)
        f = repo.get_finding(conn, full_id)
        if f is None:
            raise click.ClickException(f"finding {finding_id} not found")

        if status is None and not tags:
            raise click.ClickException("nothing to update (pass --status or --tag)")

        if status is not None:
            f.status = status
        if tags:
            f.tags = list(tags)

        target = repo.get_target(conn, f.target_id)
        target_weight = target.target_weight if target else 1.0

        score = compute_priority(
            severity=f.severity,
            confidence=f.confidence,
            target_weight=target_weight,
        )
        repo.update_finding_priority(
            conn,
            f.id,
            priority=score.priority,
            status=f.status,
            tags=f.tags,
        )
        conn.commit()
        click.echo(
            f"Updated {f.id}: priority={score.priority:.4f} status={f.status}"
        )
    finally:
        conn.close()
