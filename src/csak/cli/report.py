from __future__ import annotations

import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import click

from csak.query.context import build_context, REPORT_KINDS
from csak.query.finders import parse_period
from csak.render import docx_renderer, json_renderer
from csak.render import markdown as md_renderer
from csak.storage import repository as repo
from csak.storage.db import connect


FORMATS = ("markdown", "docx", "json")


def _period_slug(label: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", label).strip("-") or "period"


def _timestamp_prefix(now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    # ISO-8601 with filesystem-safe colon replacement (second granularity).
    return now.strftime("%Y-%m-%dT%H-%M-%S")


@click.group()
def report() -> None:
    """Generate reports."""


@report.command("generate")
@click.option("--org", required=True)
@click.option("--period", "period_label", required=True, help="e.g. 2026-04, today, q1-review")
@click.option(
    "--kind",
    required=True,
    type=click.Choice(list(REPORT_KINDS), case_sensitive=False),
)
@click.option(
    "--format",
    "formats",
    default="markdown",
    help="Comma-separated list: markdown, docx, json. Defaults to markdown.",
)
@click.pass_context
def generate(
    ctx: click.Context,
    org: str,
    period_label: str,
    kind: str,
    formats: str,
) -> None:
    """Generate a report.

    Writes timestamped files under reports/<org>/<period>/. Every
    invocation produces a new set of files; previous reports are
    preserved.
    """
    # Parse formats.
    requested = [f.strip().lower() for f in formats.split(",") if f.strip()]
    for f in requested:
        if f not in FORMATS:
            raise click.ClickException(
                f"unknown format {f!r}; valid: {', '.join(FORMATS)}"
            )

    conn = connect(ctx.obj["db_path"])
    try:
        org_row = repo.get_org_by_slug(conn, org)
        if org_row is None:
            raise click.ClickException(f"unknown org slug: {org!r}")

        period = parse_period(period_label)
        rep_ctx = build_context(conn, org=org_row, period=period, kind=kind)

        reports_root = Path(ctx.obj["reports_dir"])
        out_dir = reports_root / org_row.slug / _period_slug(period.label)
        out_dir.mkdir(parents=True, exist_ok=True)

        stamp = _timestamp_prefix(rep_ctx.generated_at)
        written: list[Path] = []

        for fmt in requested:
            written.extend(
                _render_one(
                    rep_ctx,
                    fmt,
                    out_dir=out_dir,
                    stamp=stamp,
                    kind=kind,
                )
            )

        click.echo(f"Generated {len(written)} file(s) under {out_dir}:")
        for p in written:
            click.echo(f"  {p}")
    finally:
        conn.close()


def _render_one(
    rep_ctx,
    fmt: str,
    *,
    out_dir: Path,
    stamp: str,
    kind: str,
) -> list[Path]:
    if kind == "internal-review":
        return _render_internal_review(rep_ctx, fmt, out_dir=out_dir, stamp=stamp)
    if kind == "fit-bundle":
        return _render_fit_bundle(rep_ctx, fmt, out_dir=out_dir, stamp=stamp)
    raise ValueError(f"unknown kind: {kind}")


def _render_internal_review(rep_ctx, fmt: str, *, out_dir: Path, stamp: str) -> list[Path]:
    if fmt == "markdown":
        out = out_dir / f"{stamp}_internal-review.md"
        return [md_renderer.write_report(rep_ctx, out)]
    if fmt == "docx":
        out = out_dir / f"{stamp}_internal-review.docx"
        return [docx_renderer.write_report(rep_ctx, out)]
    if fmt == "json":
        out = out_dir / f"{stamp}_internal-review.json"
        return [json_renderer.write_report(rep_ctx, out)]
    raise ValueError(fmt)


def _render_fit_bundle(rep_ctx, fmt: str, *, out_dir: Path, stamp: str) -> list[Path]:
    """Fit bundle rendering:

    * markdown → directory of per-ticket .md files + a zip of that
      directory.
    * docx → directory of per-ticket .docx files + a zip of that
      directory.
    * json → single JSON export file of the full report context
      (ticket layer plus findings plus methodology), at the
      period-directory level.
    """
    if fmt == "json":
        out = out_dir / f"{stamp}_fit.json"
        return [json_renderer.write_report(rep_ctx, out)]

    bundle_dir = out_dir / f"{stamp}_fit"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    written_files: list[Path] = []

    if fmt == "markdown":
        for ticket in rep_ctx.tickets:
            out = bundle_dir / f"{ticket.ticket_id}-{ticket.slug}.md"
            out.write_text(md_renderer.render_ticket(ticket), encoding="utf-8")
            written_files.append(out)
    elif fmt == "docx":
        for ticket in rep_ctx.tickets:
            out = bundle_dir / f"{ticket.ticket_id}-{ticket.slug}.docx"
            docx_renderer.write_ticket(ticket, out)
            written_files.append(out)
    else:
        raise ValueError(fmt)

    # Zip the bundle for easy sharing.
    zip_path = out_dir / f"{stamp}_fit.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p in written_files:
            zf.write(p, arcname=p.relative_to(bundle_dir).as_posix())

    return written_files + [zip_path]
