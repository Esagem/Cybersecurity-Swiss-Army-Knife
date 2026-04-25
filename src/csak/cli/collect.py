"""``csak collect`` CLI command.

Thin click handler — the heavy lifting is in
``csak.collect.pipeline.run_collect``. This file's responsibilities:

  * Parse flags, including per-tool overrides and timeouts.
  * Resolve the org slug to an org id.
  * Wire a ``ProgressReporter`` to the runner so the analyst gets
    live output per spec §Output format.
  * Print the final summary.
  * Exit non-zero on hard failure per spec §Exit codes.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import click

from csak.collect.detect import detect_target_type
from csak.collect.pipeline import CollectReport, run_collect
from csak.collect.runner import RunEvent
from csak.collect.tool import VALID_MODES
from csak.storage import repository as repo
from csak.storage.db import connect


# Per-tool override flags. Keep these in one place so the help text
# stays maintainable. Each entry maps the click flag name → (tool name,
# override key).
_OVERRIDE_FLAGS: list[tuple[str, str, str, str]] = [
    # (click flag, tool, override key, help text)
    ("subfinder-rate-limit", "subfinder", "rate_limit", "Subfinder -rl override."),
    ("httpx-rate-limit", "httpx", "rate_limit", "httpx -rl override."),
    ("httpx-threads", "httpx", "threads", "httpx -t override."),
    ("nuclei-rate-limit", "nuclei", "rate_limit", "Nuclei -rl override."),
    ("nuclei-templates", "nuclei", "templates", "Path or list passed to nuclei -t."),
    ("nuclei-tags", "nuclei", "tags", "Nuclei -tags override."),
    ("nuclei-severity", "nuclei", "severity", "Nuclei -severity override."),
    ("nuclei-concurrency", "nuclei", "concurrency", "Nuclei -c override."),
]


@click.command("collect")
@click.option("--org", required=True, help="Org slug.")
@click.option("--target", required=True, help="Domain, subdomain, IP, CIDR, or URL.")
@click.option(
    "--mode",
    type=click.Choice(list(VALID_MODES), case_sensitive=False),
    default="standard",
    show_default=True,
    help="Scan intensity.",
)
@click.option("--timeout-subfinder", type=float, default=60.0, show_default=True)
@click.option("--timeout-httpx", type=float, default=300.0, show_default=True)
@click.option("--timeout-nuclei", type=float, default=1800.0, show_default=True)
@click.option(
    "--no-adaptive-rate",
    "adaptive_rate",
    flag_value=False,
    default=True,
    help="Disable the adaptive rate limiter (power-user / fixed-rate mode).",
)
@click.option("--verbose/--no-verbose", default=False, help="Stream raw tool stderr.")
@click.option("--quiet/--no-quiet", default=False, help="Suppress live progress.")
@click.option("--yes", is_flag=True, default=False, help="Skip interactive prompts.")
# Build the per-tool override flags dynamically.
@click.option("--subfinder-rate-limit", default=None, help=_OVERRIDE_FLAGS[0][3])
@click.option("--httpx-rate-limit", default=None, help=_OVERRIDE_FLAGS[1][3])
@click.option("--httpx-threads", default=None, help=_OVERRIDE_FLAGS[2][3])
@click.option("--nuclei-rate-limit", default=None, help=_OVERRIDE_FLAGS[3][3])
@click.option("--nuclei-templates", default=None, help=_OVERRIDE_FLAGS[4][3])
@click.option("--nuclei-tags", default=None, help=_OVERRIDE_FLAGS[5][3])
@click.option("--nuclei-severity", default=None, help=_OVERRIDE_FLAGS[6][3])
@click.option("--nuclei-concurrency", default=None, help=_OVERRIDE_FLAGS[7][3])
@click.pass_context
def collect(
    ctx: click.Context,
    org: str,
    target: str,
    mode: str,
    timeout_subfinder: float,
    timeout_httpx: float,
    timeout_nuclei: float,
    adaptive_rate: bool,
    verbose: bool,
    quiet: bool,
    yes: bool,
    subfinder_rate_limit: str | None,
    httpx_rate_limit: str | None,
    httpx_threads: str | None,
    nuclei_rate_limit: str | None,
    nuclei_templates: str | None,
    nuclei_tags: str | None,
    nuclei_severity: str | None,
    nuclei_concurrency: str | None,
) -> None:
    """Run the collect pipeline against TARGET."""
    target_type = detect_target_type(target)
    if target_type == "invalid":
        raise click.ClickException(
            f"target {target!r} is not a valid domain, subdomain, IP, CIDR, or URL"
        )

    overrides = _collect_overrides(
        subfinder_rate_limit=subfinder_rate_limit,
        httpx_rate_limit=httpx_rate_limit,
        httpx_threads=httpx_threads,
        nuclei_rate_limit=nuclei_rate_limit,
        nuclei_templates=nuclei_templates,
        nuclei_tags=nuclei_tags,
        nuclei_severity=nuclei_severity,
        nuclei_concurrency=nuclei_concurrency,
    )

    timeouts = {
        "subfinder": timeout_subfinder,
        "httpx": timeout_httpx,
        "nuclei": timeout_nuclei,
    }

    conn = connect(ctx.obj["db_path"])
    try:
        org_row = repo.get_org_by_slug(conn, org)
        if org_row is None:
            raise click.ClickException(f"unknown org slug: {org!r}")

        reporter = ProgressReporter(verbose=verbose, quiet=quiet)
        reporter.print_header(target=target, target_type=target_type, mode=mode)

        wall_start = time.monotonic()
        report = run_collect(
            conn,
            org_id=org_row.id,
            target=target,
            mode=mode,  # type: ignore[arg-type]
            artifacts_root=Path(ctx.obj["artifacts_dir"]),
            overrides=overrides,
            timeouts=timeouts,
            progress_callback=reporter.handle_event,
            adaptive_rate=adaptive_rate,
        )
        wall_elapsed = time.monotonic() - wall_start

        reporter.print_summary(report=report, wall_elapsed=wall_elapsed)

        if report.hard_failure:
            sys.exit(2)
    finally:
        conn.close()


def _collect_overrides(**flags: str | None) -> dict[str, dict[str, str]]:
    """Translate the click flag values into the
    ``{tool: {key: value}}`` shape ``run_collect`` expects.
    """
    out: dict[str, dict[str, str]] = {}
    mapping = {
        "subfinder_rate_limit": ("subfinder", "rate_limit"),
        "httpx_rate_limit": ("httpx", "rate_limit"),
        "httpx_threads": ("httpx", "threads"),
        "nuclei_rate_limit": ("nuclei", "rate_limit"),
        "nuclei_templates": ("nuclei", "templates"),
        "nuclei_tags": ("nuclei", "tags"),
        "nuclei_severity": ("nuclei", "severity"),
        "nuclei_concurrency": ("nuclei", "concurrency"),
    }
    for click_key, (tool, override_key) in mapping.items():
        value = flags.get(click_key)
        if value is None:
            continue
        out.setdefault(tool, {})[override_key] = str(value)
    return out


class ProgressReporter:
    """Renders ``RunEvent``s to the terminal per spec §Output format.

    Slice 2's reporter is intentionally a simple line-stream — full
    in-place progress bars with ANSI cursor controls are not worth
    the cross-platform complexity at this scope. Tests don't depend
    on the exact characters rendered; the CLI smoke tests only verify
    that the summary lines appear.
    """

    def __init__(self, *, verbose: bool, quiet: bool) -> None:
        self.verbose = verbose
        self.quiet = quiet

    def print_header(self, *, target: str, target_type: str, mode: str) -> None:
        if self.quiet:
            return
        click.echo(f"[csak] Identified target {target} as type={target_type}")
        click.echo(f"[csak] Mode: {mode}")

    def handle_event(self, event: RunEvent) -> None:
        if self.quiet and event.kind not in ("rate_adjusted", "failed", "timeout"):
            return

        prefix = f"[{event.tool}]"
        if event.kind == "started":
            click.echo(f"{prefix} starting")
        elif event.kind == "progress":
            if self.verbose and event.progress is not None:
                p = event.progress
                parts: list[str] = []
                if p.percent is not None:
                    parts.append(f"{p.percent}%")
                if p.count is not None and p.total is not None:
                    parts.append(f"{p.count}/{p.total}")
                elif p.count is not None:
                    parts.append(f"count={p.count}")
                if p.rps is not None:
                    parts.append(f"rps={p.rps}")
                if p.errors is not None:
                    parts.append(f"errors={p.errors}")
                click.echo(f"{prefix} progress {' '.join(parts)} elapsed={event.elapsed:.0f}s")
        elif event.kind == "rate_signal":
            if self.verbose:
                click.echo(f"{prefix} rate signal: {event.message}")
        elif event.kind == "rate_adjusted":
            click.echo(f"{prefix} {event.message}")
        elif event.kind == "completed":
            click.echo(
                f"{prefix} done elapsed={event.elapsed:.0f}s {event.message or ''}"
            )
        elif event.kind == "failed":
            click.echo(
                f"{prefix} FAILED elapsed={event.elapsed:.0f}s "
                f"reason={event.message or 'unknown'}",
                err=True,
            )
        elif event.kind == "timeout":
            click.echo(
                f"{prefix} TIMEOUT elapsed={event.elapsed:.0f}s "
                f"reason={event.message or 'timeout exceeded'}",
                err=True,
            )

    def print_summary(self, *, report: CollectReport, wall_elapsed: float) -> None:
        click.echo("")
        click.echo(
            f"[csak] Collect complete for {report.target} (mode={report.mode})"
        )
        click.echo(f"[csak] Total elapsed: {wall_elapsed:.1f}s")
        if report.stages:
            click.echo("[csak] Stages:")
            for s in report.stages:
                line = (
                    f"  - {s.tool:<10} status={s.status:<10} "
                    f"rows={s.output_line_count:<5} new={s.new_findings} "
                    f"reoccur={s.reoccurrences}"
                )
                if s.error:
                    line += f" error={s.error!r}"
                click.echo(line)
        if report.skipped:
            click.echo("[csak] Skipped:")
            for tool, reason in report.skipped.items():
                click.echo(f"  - {tool:<10} {reason}")
        click.echo(
            f"[csak] Findings: {report.total_new_findings} new, "
            f"{report.total_reoccurrences} re-occurrences"
        )
        click.echo(
            f"[csak] Run `csak findings list --org {_org_slug_hint(report)}` to review"
        )


def _org_slug_hint(report: CollectReport) -> str:
    """We don't have the slug in the report — render a placeholder."""
    return "<org>"
