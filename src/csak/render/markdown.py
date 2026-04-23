"""Markdown renderer — Jinja2 over the shared report context."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Iterable

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from csak.query.context import ReportContext, TicketGroup


TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates" / "markdown"


def _make_env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=False,
        trim_blocks=False,
        lstrip_blocks=False,
        undefined=StrictUndefined,
        keep_trailing_newline=True,
    )
    env.filters["isodate"] = _isodate
    env.filters["isodatetime"] = _isodatetime
    return env


def _isodate(value: datetime) -> str:
    return value.date().isoformat()


def _isodatetime(value: datetime) -> str:
    # Second-granularity, UTC, readable.
    return value.strftime("%Y-%m-%d %H:%M:%S UTC")


def render_internal_review(ctx: ReportContext) -> str:
    env = _make_env()
    template = env.get_template("internal-review.md.j2")
    return template.render(
        org=ctx.org,
        period=ctx.period,
        generated_at=ctx.generated_at,
        csak_version=ctx.csak_version,
        findings=ctx.findings,
        findings_by_severity=ctx.findings_by_severity,
        methodology=ctx.methodology,
        targets_by_name=ctx.findings_by_target,
    )


def render_fit_bundle(ctx: ReportContext) -> str:
    env = _make_env()
    template = env.get_template("fit-bundle.md.j2")
    return template.render(
        org=ctx.org,
        period=ctx.period,
        generated_at=ctx.generated_at,
        tickets=ctx.tickets,
    )


def render_ticket(ticket: TicketGroup) -> str:
    env = _make_env()
    template = env.get_template("ticket.md.j2")
    return template.render(ticket=ticket)


def write_report(ctx: ReportContext, out_path: Path) -> Path:
    """Render ctx.kind to markdown and write it to ``out_path``."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if ctx.kind == "internal-review":
        out_path.write_text(render_internal_review(ctx), encoding="utf-8")
    elif ctx.kind == "fit-bundle":
        out_path.write_text(render_fit_bundle(ctx), encoding="utf-8")
    else:
        raise ValueError(f"unknown report kind: {ctx.kind}")
    return out_path


def write_ticket_bundle(ctx: ReportContext, bundle_dir: Path) -> list[Path]:
    """Write one markdown file per ticket under ``bundle_dir``."""
    bundle_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for ticket in ctx.tickets:
        path = bundle_dir / f"{ticket.ticket_id}-{ticket.slug}.md"
        path.write_text(render_ticket(ticket), encoding="utf-8")
        written.append(path)
    return written
