from __future__ import annotations

import click

from csak.ingest.scoring import compute_priority
from csak.storage import repository as repo
from csak.storage.db import connect


@click.group()
def target() -> None:
    """Inspect and update targets."""


@target.command("list")
@click.option("--org", required=True)
@click.pass_context
def list_cmd(ctx: click.Context, org: str) -> None:
    conn = connect(ctx.obj["db_path"])
    try:
        org_row = repo.get_org_by_slug(conn, org)
        if org_row is None:
            raise click.ClickException(f"unknown org slug: {org!r}")
        rows = repo.list_targets(conn, org_row.id)
        if not rows:
            click.echo("(no targets)")
            return
        click.echo(f"{'WEIGHT':>6}  {'TYPE':<10}  {'NAME':<30}  PARENT  ID")
        for t in rows:
            click.echo(
                f"{t.target_weight:>6.2f}  "
                f"{t.type:<10}  "
                f"{t.name[:30]:<30}  "
                f"{(t.parent_target_id or '—')[:8]:<8}  "
                f"{t.id}"
            )
    finally:
        conn.close()


@target.command("update")
@click.argument("target_id")
@click.option("--weight", type=float, help="New target_weight.")
@click.pass_context
def update(ctx: click.Context, target_id: str, weight: float | None) -> None:
    """Change a target's weight. Triggers a priority recompute for every
    finding attached to that target (per the spec's mutation rules).
    """
    if weight is None:
        raise click.ClickException("nothing to update (pass --weight)")
    conn = connect(ctx.obj["db_path"])
    try:
        t = repo.get_target(conn, target_id)
        if t is None:
            raise click.ClickException(f"target {target_id} not found")

        repo.update_target_weight(conn, target_id, weight)

        # Recompute priority for every finding on this target.
        findings = repo.list_findings_for_target(conn, target_id)
        for f in findings:
            score = compute_priority(
                severity=f.severity,
                confidence=f.confidence,
                target_weight=weight,
                probability_real=f.probability_real,
            )
            repo.update_finding_priority(conn, f.id, priority=score.priority)
        conn.commit()
        click.echo(
            f"Updated {t.name}: weight={weight} "
            f"(recomputed {len(findings)} findings)"
        )
    finally:
        conn.close()
