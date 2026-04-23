from __future__ import annotations

import re

import click

from csak.storage import repository as repo
from csak.storage.db import connect


_SLUG_RE = re.compile(r"[^a-z0-9._-]+")


def _slugify(name: str) -> str:
    s = name.strip().lower()
    s = _SLUG_RE.sub("-", s)
    return s.strip("-") or name


@click.group()
def org() -> None:
    """Manage organizations (clients)."""


@org.command("create")
@click.argument("name")
@click.option("--slug", help="File-safe slug. Defaults to a slugified version of NAME.")
@click.option("--notes", default="", help="Freeform context.")
@click.pass_context
def create(ctx: click.Context, name: str, slug: str | None, notes: str) -> None:
    """Create a new organization."""
    conn = connect(ctx.obj["db_path"])
    try:
        final_slug = slug or _slugify(name)
        existing = repo.get_org_by_slug(conn, final_slug)
        if existing is not None:
            raise click.ClickException(
                f"org with slug {final_slug!r} already exists (id={existing.id})"
            )
        created = repo.create_org(conn, name=name, slug=final_slug, notes=notes)
        click.echo(f"Created org {created.slug}  id={created.id}")
    finally:
        conn.close()


@org.command("list")
@click.pass_context
def list_cmd(ctx: click.Context) -> None:
    """List all organizations."""
    conn = connect(ctx.obj["db_path"])
    try:
        orgs = repo.list_orgs(conn)
        if not orgs:
            click.echo("(no orgs)")
            return
        for o in orgs:
            click.echo(f"{o.slug:20}  {o.name:30}  {o.id}")
    finally:
        conn.close()
