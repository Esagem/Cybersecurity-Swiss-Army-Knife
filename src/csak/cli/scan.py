from __future__ import annotations

import click

from csak.storage import repository as repo
from csak.storage.db import connect


@click.group()
def scan() -> None:
    """Inspect scan history."""


@scan.command("list")
@click.option("--org", required=True)
@click.pass_context
def list_cmd(ctx: click.Context, org: str) -> None:
    conn = connect(ctx.obj["db_path"])
    try:
        org_row = repo.get_org_by_slug(conn, org)
        if org_row is None:
            raise click.ClickException(f"unknown org slug: {org!r}")
        scans = repo.list_scans(conn, org_row.id)
        if not scans:
            click.echo("(no scans)")
            return
        click.echo(
            f"{'TOOL':<10}  {'STARTED':<30}  {'TS-SRC':<18}  LABEL"
        )
        for s in scans:
            click.echo(
                f"{s.source_tool:<10}  "
                f"{str(s.scan_started_at):<30}  "
                f"{s.timestamp_source:<18}  "
                f"{s.label}"
            )
    finally:
        conn.close()
