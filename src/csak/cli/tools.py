"""``csak tools list`` and ``csak tools show <tool>`` — slice 3.

Read-only views over the runtime tool registry. Both commands trigger
plugin discovery (so plugin tools appear in the listing) and then
walk ``ALL_TOOLS`` to render. No side effects beyond the import-time
plugin loading — discovery is required to know what's installed; we
never run a tool here.
"""
from __future__ import annotations

import click

from csak.collect.plugins import load_plugins
from csak.collect.tool import VALID_MODES, Tool
from csak.collect.tools import ALL_TOOLS, get_tool
from csak.collect.types import matches


@click.group()
def tools() -> None:
    """Inspect the registered collect tool catalog."""


@tools.command("list")
@click.option(
    "--no-plugins",
    is_flag=True,
    default=False,
    help="Skip loading plugins from ~/.csak/tools/ before listing.",
)
def list_cmd(no_plugins: bool) -> None:
    """List every registered tool, what it accepts/produces, and its source."""
    if not no_plugins:
        result = load_plugins()
        for warn in result.warnings:
            click.echo(f"[csak] plugin warning: {warn}", err=True)

    builtins = [t for t in ALL_TOOLS if t.origin == "builtin"]
    plugins = [t for t in ALL_TOOLS if t.origin == "plugin"]

    if builtins:
        click.echo("Built-in tools:")
        for t in sorted(builtins, key=lambda x: x.name):
            click.echo(f"  {t.name:<12} {_io_summary(t)}")
    if plugins:
        click.echo("")
        click.echo("Plugin tools (~/.csak/tools/):")
        for t in sorted(plugins, key=lambda x: x.name):
            line = f"  {t.name:<12} {_io_summary(t)}"
            if t.source_path:
                line += f"   {t.source_path}"
            click.echo(line)
    if not builtins and not plugins:
        click.echo("(no tools registered)")
        return
    click.echo("")
    click.echo("Run 'csak tools show <name>' for catalog details.")


@tools.command("show")
@click.argument("tool_name")
@click.option(
    "--no-plugins",
    is_flag=True,
    default=False,
    help="Skip loading plugins before lookup.",
)
def show(tool_name: str, no_plugins: bool) -> None:
    """Show one tool's catalog metadata + recursion graph."""
    if not no_plugins:
        result = load_plugins()
        for warn in result.warnings:
            click.echo(f"[csak] plugin warning: {warn}", err=True)

    tool = get_tool(tool_name)
    if tool is None:
        raise click.ClickException(
            f"unknown tool {tool_name!r}; run `csak tools list` to see registered tools"
        )

    click.echo(f"{tool.name}  ({tool.origin})")
    click.echo(f"  binary:           {tool.binary}")
    if tool.minimum_version:
        click.echo(f"  minimum version:  {tool.minimum_version}")
    if tool.install_command:
        click.echo(f"  install:          {tool.install_command}")
    if tool.source_path:
        click.echo(f"  source:           {tool.source_path}")
    click.echo("")
    click.echo("  Accepts:")
    if tool.accepts:
        for t in tool.accepts:
            widens = _widening_subtypes(t)
            note = f"   (matches: {', '.join(widens)})" if widens else ""
            click.echo(f"    {t}{note}")
    else:
        click.echo("    (none)")
    click.echo("")
    click.echo("  Produces:")
    if tool.produces:
        for t in tool.produces:
            click.echo(f"    {t}")
    else:
        click.echo("    (none)")
    click.echo("")
    click.echo("  Modes:")
    for mode in VALID_MODES:
        if tool.is_skipped_by_mode(mode):
            click.echo(f"    {mode:<9} (skipped)")
        else:
            click.echo(f"    {mode}")
    if tool.rate_limit is not None:
        click.echo("")
        click.echo("  Rate limiting:")
        click.echo(f"    starting rate:  {tool.rate_limit.start_rps} req/s")
        click.echo(f"    floor:          {tool.rate_limit.floor_rps} req/s")
        click.echo(f"    ceiling:        {tool.rate_limit.ceiling_rps} req/s")

    upstream, downstream = _recursion_graph_for(tool)
    click.echo("")
    click.echo("  Recursion graph (when --recurse):")
    if upstream:
        click.echo("    upstream (tools that produce types this accepts):")
        for u in upstream:
            click.echo(f"      {u}")
    else:
        click.echo("    upstream: (none)")
    if downstream:
        click.echo("    downstream (tools that accept types this produces):")
        for d in downstream:
            click.echo(f"      {d}")
    else:
        click.echo("    downstream: (none)")


def _io_summary(tool: Tool) -> str:
    accepts = ", ".join(tool.accepts) if tool.accepts else "—"
    produces = ", ".join(tool.produces) if tool.produces else "—"
    return f"{accepts} → {produces}"


def _widening_subtypes(type_name: str) -> list[str]:
    """Return the registered types that widen to ``type_name`` via
    parent links. Used only for the "matches: ..." annotation.
    """
    from csak.collect.types import _TYPES

    out: list[str] = []
    for name, t in _TYPES.items():
        if name == type_name:
            continue
        if matches(name, [type_name]):
            out.append(name)
    return sorted(out)


def _recursion_graph_for(tool: Tool) -> tuple[list[str], list[str]]:
    """Compute the live upstream/downstream for ``tool``.

    Upstream: tools whose ``produces`` overlaps ``tool.accepts``
    (with subtype widening — a tool that produces ``subdomain`` is
    upstream of a tool that accepts ``host``).

    Downstream: tools whose ``accepts`` overlaps ``tool.produces``
    (subtype-aware in the same direction).
    """
    upstream: list[str] = []
    downstream: list[str] = []
    for other in ALL_TOOLS:
        if other.name == tool.name:
            continue
        if any(matches(p, tool.accepts) for p in other.produces):
            upstream.append(
                f"{other.name}  (produces: {', '.join(other.produces) or '—'})"
            )
        if any(matches(p, other.accepts) for p in tool.produces):
            downstream.append(
                f"{other.name}  (accepts: {', '.join(other.accepts) or '—'})"
            )
    return upstream, downstream
