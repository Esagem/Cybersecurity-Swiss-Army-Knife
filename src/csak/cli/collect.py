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

from csak.collect.pipeline import CollectReport, run_collect
from csak.collect.recursion import (
    DepthSummary,
    FrontierTask,
    RecursionProgress,
    RecursionReport,
    run_collect_recursive,
)
from csak.collect.plugins import load_plugins
from csak.collect.runner import RunEvent
from csak.collect.tool import VALID_MODES
from csak.collect.tools import ALL_TOOLS
from csak.collect.types import (
    InvalidTargetError,
    classify,
    validate_registry,
    validate_tool_accepts_produces,
)
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
    ("httpx-ports", "httpx", "ports", "httpx -ports override (comma-separated)."),
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
@click.option(
    "--recurse",
    is_flag=True,
    default=False,
    help="Enable recursive collect: harvest typed outputs and feed downstream tools.",
)
@click.option(
    "--max-depth",
    type=int,
    default=3,
    show_default=True,
    help="Recursion depth ceiling. 0 = infinite, 1 = no recursion. Ignored without --recurse.",
)
@click.option(
    "--no-plugins",
    is_flag=True,
    default=False,
    help="Skip loading plugins from ~/.csak/tools/.",
)
# Build the per-tool override flags dynamically.
@click.option("--subfinder-rate-limit", default=None, help=_OVERRIDE_FLAGS[0][3])
@click.option("--httpx-rate-limit", default=None, help=_OVERRIDE_FLAGS[1][3])
@click.option("--httpx-threads", default=None, help=_OVERRIDE_FLAGS[2][3])
@click.option("--httpx-ports", default=None, help=_OVERRIDE_FLAGS[3][3])
@click.option("--nuclei-rate-limit", default=None, help=_OVERRIDE_FLAGS[4][3])
@click.option("--nuclei-templates", default=None, help=_OVERRIDE_FLAGS[5][3])
@click.option("--nuclei-tags", default=None, help=_OVERRIDE_FLAGS[6][3])
@click.option("--nuclei-severity", default=None, help=_OVERRIDE_FLAGS[7][3])
@click.option("--nuclei-concurrency", default=None, help=_OVERRIDE_FLAGS[8][3])
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
    recurse: bool,
    max_depth: int,
    no_plugins: bool,
    subfinder_rate_limit: str | None,
    httpx_rate_limit: str | None,
    httpx_threads: str | None,
    httpx_ports: str | None,
    nuclei_rate_limit: str | None,
    nuclei_templates: str | None,
    nuclei_tags: str | None,
    nuclei_severity: str | None,
    nuclei_concurrency: str | None,
) -> None:
    """Run the collect pipeline against TARGET."""
    if not no_plugins:
        plugin_load = load_plugins()
        for warning in plugin_load.warnings:
            click.echo(f"[csak] plugin warning: {warning}", err=True)

    # Slice 3: validate the type registry + tool accepts/produces
    # references before any tool runs. Per spec §Type registry
    # validation, failures stop the run with the offending plugin
    # named.
    registry_errors = list(validate_registry())
    for tool in ALL_TOOLS:
        registry_errors.extend(
            validate_tool_accepts_produces(tool.name, tool.accepts, tool.produces)
        )
    if registry_errors:
        for err in registry_errors:
            click.echo(f"[csak] registry error: {err}", err=True)
        raise click.ClickException(
            "type registry has errors; fix the offending plugin(s) and re-run "
            "(see `csak doctor`)"
        )

    try:
        typed = classify(target)
    except InvalidTargetError:
        raise click.ClickException(
            f"target {target!r} is not a valid domain, subdomain, host, "
            f"network_block, URL, or service identifier"
        )
    target_type = typed.type

    overrides = _collect_overrides(
        subfinder_rate_limit=subfinder_rate_limit,
        httpx_rate_limit=httpx_rate_limit,
        httpx_threads=httpx_threads,
        httpx_ports=httpx_ports,
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
        reporter.print_header(
            target=target,
            target_type=target_type,
            mode=mode,
            recurse=recurse,
            max_depth=max_depth,
        )

        wall_start = time.monotonic()
        if recurse:
            recursion_progress = ReporterRecursionProgress(reporter, yes=yes)
            recursion_report = run_collect_recursive(
                conn,
                org_id=org_row.id,
                target=target,
                mode=mode,  # type: ignore[arg-type]
                artifacts_root=Path(ctx.obj["artifacts_dir"]),
                overrides=overrides,
                timeouts=timeouts,
                progress_callback=reporter.handle_event,
                adaptive_rate=adaptive_rate,
                max_depth=max_depth,
                progress=recursion_progress,
            )
            wall_elapsed = time.monotonic() - wall_start
            reporter.print_recursion_summary(
                report=recursion_report, wall_elapsed=wall_elapsed
            )
            hard_failure = recursion_report.hard_failure
        else:
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
            hard_failure = report.hard_failure

        if hard_failure:
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
        "httpx_ports": ("httpx", "ports"),
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


_BAR_WIDTH = 20
_BAR_FILL = "█"
_BAR_EMPTY = "░"


def _format_eta(elapsed: float, percent: int | None) -> str:
    """Linear-extrapolation ETA. Returns ``"?"`` if we don't have enough
    info, else a string like ``"27s"`` / ``"4m12s"``."""
    if percent is None or percent <= 0 or percent >= 100:
        return "0s" if percent == 100 else "?"
    remaining = elapsed * (100 - percent) / percent
    if remaining < 60:
        return f"{remaining:.0f}s"
    return f"{int(remaining // 60)}m{int(remaining % 60):02d}s"


def _format_elapsed(elapsed: float) -> str:
    if elapsed < 60:
        return f"{elapsed:.0f}s"
    return f"{int(elapsed // 60)}m{int(elapsed % 60):02d}s"


class ProgressReporter:
    """Renders ``RunEvent``s per spec §Output format.

    Default mode (stdout is a tty): live in-place progress bars with
    %, elapsed, ETA, running counts. ``\\r`` updates the active stage's
    line in place; on completion the line is finalised and the next
    stage starts on a new line. Rate-limit adjustments print on their
    own line and the active bar resumes underneath.

    Non-tty / ``--quiet`` / ``--verbose``: fall back to plain text per
    event so output is grep-friendly and pipe-safe. Verbose adds
    progress lines as they arrive.
    """

    def __init__(self, *, verbose: bool, quiet: bool) -> None:
        self.verbose = verbose
        self.quiet = quiet
        # Live bars need ANSI cursor control; only viable on a real tty.
        # Pipes, CI, redirects → plain-text fallback.
        self._render_bars = (
            not quiet
            and not verbose
            and bool(getattr(sys.stdout, "isatty", lambda: False)())
        )
        self._bar_active = False  # an in-place bar is currently drawn
        self._last_progress: RunEvent | None = None  # for redraw after rate-adjust

    # ── header / summary ────────────────────────────────────────────

    def print_header(
        self,
        *,
        target: str,
        target_type: str,
        mode: str,
        recurse: bool = False,
        max_depth: int | None = None,
    ) -> None:
        if self.quiet:
            return
        click.echo(f"[csak] Identified target {target} as type={target_type}")
        click.echo(f"[csak] Mode: {mode}")
        if recurse:
            depth_label = "infinite" if max_depth == 0 else str(max_depth)
            click.echo(
                f"[csak] Recursion: enabled, max-depth={depth_label}, dedup=on"
            )

    # ── slice 3: depth-aware hooks ─────────────────────────────────

    def print_depth_header(self, *, depth: int, queued: int, max_depth: int) -> None:
        if self.quiet:
            return
        self._finalise_bar()
        if depth == 0:
            label = f"Depth 0 (root) - {queued} candidate"
        else:
            remaining = (
                "infinite"
                if max_depth == 0
                else f"{max(0, max_depth - depth)}"
            )
            label = f"Depth {depth} (depth budget remaining: {remaining}) - {queued} queued"
        click.echo(f"[csak] {label}")

    def print_depth_summary(self, summary) -> None:
        if self.quiet:
            return
        self._finalise_bar()
        click.echo(
            f"[csak] Depth {summary.depth} complete. "
            f"Frontier: {summary.extracted} typed targets extracted, "
            f"{summary.queued} queued for depth {summary.depth + 1} "
            f"({summary.deduped} deduped/dropped)"
        )

    def print_recursion_summary(
        self, *, report, wall_elapsed: float
    ) -> None:
        click.echo("")
        base = report.base
        click.echo(
            f"[csak] Collect complete for {base.target} (mode={base.mode}, "
            f"recurse=on, depths={report.depths_run})"
        )
        click.echo(f"[csak] Total elapsed: {wall_elapsed:.1f}s")
        # Per-depth task counts.
        per_tool: dict[str, int] = {}
        for s in report.stages:
            if s.status not in ("succeeded", "failed", "timeout"):
                continue
            per_tool[s.tool] = per_tool.get(s.tool, 0) + 1
        if per_tool:
            click.echo(
                "[csak] Scans created: "
                + ", ".join(f"{name} x{count}" for name, count in per_tool.items())
            )
        click.echo(
            f"[csak] Findings: {sum(s.new_findings for s in report.stages)} new, "
            f"{sum(s.reoccurrences for s in report.stages)} re-occurrences"
        )
        if report.frontier_remaining:
            click.echo(
                f"[csak] Frontier remaining: {len(report.frontier_remaining)} "
                f"unscanned candidates"
                + (" (user declined to continue)" if report.user_declined else "")
            )
        click.echo(
            f"[csak] Run `csak findings list --org {_org_slug_hint(base)}` to review"
        )

    # ── event handler ──────────────────────────────────────────────

    def handle_event(self, event: RunEvent) -> None:
        if self.quiet and event.kind not in ("rate_adjusted", "failed", "timeout"):
            return

        if event.kind == "started":
            self._on_started(event)
        elif event.kind == "progress":
            self._on_progress(event)
        elif event.kind == "rate_signal":
            if self.verbose:
                self._line(f"[{event.tool}] rate signal: {event.message}")
        elif event.kind == "rate_adjusted":
            self._on_rate_adjusted(event)
        elif event.kind == "completed":
            self._on_completed(event)
        elif event.kind == "failed":
            self._on_failed(event, kind="failed")
        elif event.kind == "timeout":
            self._on_failed(event, kind="timeout")

    # ── per-event renderers ────────────────────────────────────────

    def _on_started(self, event: RunEvent) -> None:
        prefix = f"[{event.tool}]"
        if self._render_bars:
            self._draw_bar_line(event.tool, percent=None, elapsed=0.0,
                                progress=None, status="starting…")
        else:
            self._line(f"{prefix} starting")

    def _on_progress(self, event: RunEvent) -> None:
        self._last_progress = event
        if self._render_bars:
            p = event.progress
            self._draw_bar_line(
                event.tool,
                percent=p.percent if p else None,
                elapsed=event.elapsed,
                progress=p,
            )
        elif self.verbose and event.progress is not None:
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
            self._line(
                f"[{event.tool}] progress {' '.join(parts)} "
                f"elapsed={_format_elapsed(event.elapsed)}"
            )

    def _on_rate_adjusted(self, event: RunEvent) -> None:
        # Spec: rate-limit messages print on their own line, then the
        # bar resumes drawing underneath.
        self._finalise_bar()
        self._line(f"[{event.tool}] {event.message}")
        # Re-draw the active bar from the last known progress so it
        # doesn't disappear.
        if self._render_bars and self._last_progress is not None:
            p = self._last_progress.progress
            self._draw_bar_line(
                self._last_progress.tool,
                percent=p.percent if p else None,
                elapsed=self._last_progress.elapsed,
                progress=p,
            )

    def _on_completed(self, event: RunEvent) -> None:
        self._finalise_bar()
        msg = event.message or ""
        self._line(
            f"[{event.tool}] ✓ done   elapsed={_format_elapsed(event.elapsed)}  {msg}"
        )
        self._last_progress = None

    def _on_failed(self, event: RunEvent, *, kind: str) -> None:
        self._finalise_bar()
        marker = "✗ FAILED" if kind == "failed" else "✗ TIMEOUT"
        self._line(
            f"[{event.tool}] {marker} elapsed={_format_elapsed(event.elapsed)}  "
            f"reason={event.message or kind}",
            err=True,
        )
        self._last_progress = None

    # ── ANSI bar primitives ────────────────────────────────────────

    def _draw_bar_line(
        self,
        tool: str,
        *,
        percent: int | None,
        elapsed: float,
        progress,
        status: str | None = None,
    ) -> None:
        """Draw / overwrite the active stage's progress bar in place."""
        if percent is not None:
            filled = max(0, min(_BAR_WIDTH, int(_BAR_WIDTH * percent / 100)))
            bar = _BAR_FILL * filled + _BAR_EMPTY * (_BAR_WIDTH - filled)
            head = f"{bar} {percent:3d}%"
            eta = _format_eta(elapsed, percent)
        else:
            # Streaming mode (e.g. subfinder): no percent, just running counts.
            spinner = "·" * _BAR_WIDTH
            head = f"{spinner}  ?? "
            eta = "?"

        counts = ""
        if progress is not None:
            if progress.count is not None and progress.total is not None:
                counts = f"  {progress.count}/{progress.total}"
            elif progress.count is not None:
                counts = f"  count={progress.count}"
            if progress.rps is not None:
                counts += f"  rps={progress.rps}"
            if progress.errors is not None and progress.errors > 0:
                counts += f"  errors={progress.errors}"

        if status:
            line = f"[{tool:<10}] {head}  {status}"
        else:
            line = (
                f"[{tool:<10}] {head}  "
                f"elapsed={_format_elapsed(elapsed)}  eta={eta}{counts}"
            )

        # \r returns cursor to start of line; pad to clear stale chars.
        sys.stdout.write("\r" + line + " " * 4)
        sys.stdout.flush()
        self._bar_active = True

    def _finalise_bar(self) -> None:
        """Move the cursor off the in-place bar so the next ``echo``
        starts on a fresh line, leaving the bar's last state visible."""
        if self._bar_active:
            sys.stdout.write("\r" + " " * 100 + "\r")  # erase the bar line
            sys.stdout.flush()
            self._bar_active = False

    def _line(self, text: str, *, err: bool = False) -> None:
        """Print a fresh line, finalising any active bar first."""
        self._finalise_bar()
        click.echo(text, err=err)

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


class ReporterRecursionProgress(RecursionProgress):
    """Bridge ``RecursionProgress`` callbacks into the ProgressReporter.

    Renders depth headers, frontier summaries, and the prompt-to-continue
    via ``click.confirm``. Honours the slice 2 ``--yes`` flag so
    non-interactive usage extends the depth budget without prompting.
    """

    def __init__(self, reporter: "ProgressReporter", *, yes: bool) -> None:
        self._reporter = reporter
        self._yes = yes

    def on_depth_started(self, depth: int, queued: int, max_depth: int) -> None:
        self._reporter.print_depth_header(
            depth=depth, queued=queued, max_depth=max_depth
        )

    def on_depth_completed(self, summary: DepthSummary) -> None:
        self._reporter.print_depth_summary(summary)

    def confirm_continue(
        self, depth: int, max_depth: int, queued: int
    ) -> bool:
        # Spec: ``--yes`` bypasses the prompt and extends the depth
        # budget by another ``max_depth``. Default response is Y when
        # the analyst hits Enter.
        self._reporter._finalise_bar()
        click.echo(
            f"[csak] Depth budget hit (max-depth={max_depth}). "
            f"Frontier remaining: {queued} unscanned candidates."
        )
        if self._yes:
            click.echo(f"[csak] --yes set; continuing for another {max_depth} depths.")
            return True
        try:
            return click.confirm(
                f"[csak] Continue with another {max_depth} depths?",
                default=True,
            )
        except (click.exceptions.Abort, EOFError):
            return False
