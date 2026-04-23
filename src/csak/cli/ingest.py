from __future__ import annotations

from pathlib import Path

import click

from csak.ingest.pipeline import ingest_path
from csak.storage import repository as repo
from csak.storage.db import connect


TOOL_CHOICES = ["nuclei", "nessus", "zeek", "osquery", "subfinder", "httpx"]


@click.command("ingest")
@click.option("--org", required=True, help="Org slug.")
@click.option(
    "--tool",
    required=True,
    type=click.Choice(TOOL_CHOICES, case_sensitive=False),
    help="Source tool that produced the file.",
)
@click.option("--label", help="Human-readable scan label; defaults to a tool-derived one.")
@click.option("--period-hint", help="Optional period (e.g. '2026-04') for the Artifact.")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.pass_context
def ingest(
    ctx: click.Context,
    org: str,
    tool: str,
    path: Path,
    label: str | None,
    period_hint: str | None,
) -> None:
    """Ingest a tool-output file or directory into CSAK."""
    conn = connect(ctx.obj["db_path"])
    try:
        found = repo.get_org_by_slug(conn, org)
        if found is None:
            raise click.ClickException(f"unknown org slug: {org!r}")

        report = ingest_path(
            conn,
            org_id=found.id,
            source_tool=tool.lower(),
            path=path,
            artifacts_root=Path(ctx.obj["artifacts_dir"]),
            label=label,
            period_hint=period_hint,
        )
        click.echo(
            f"Ingested scan {report.scan_id}: "
            f"{report.new_findings} new, {report.reoccurrences} re-occurrences, "
            f"{len(report.target_ids)} targets touched"
        )
    finally:
        conn.close()
