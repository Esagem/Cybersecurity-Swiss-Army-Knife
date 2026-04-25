"""``csak doctor`` — check external tool dependencies and (with
permission) install or upgrade them.

The catalog modules (``csak.collect.tools.*``) declare each tool's
binary, minimum version, and install command. Doctor reads the catalog,
checks the binary, parses the version, compares to the minimum, and
either reports OK or offers to run the install command.

Per spec §`csak doctor`:
  * Three statuses: ✓ present and compatible, ⚠ present but outdated,
    ✗ missing.
  * Auto-install via ``go install`` is gated behind a permission
    prompt.
  * ``--yes`` skips the prompt for scripting / CI.
"""
from __future__ import annotations

import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass

import click

from csak.collect.tool import Tool
from csak.collect.tools import ALL_TOOLS


@dataclass
class ToolStatus:
    tool: Tool
    state: str   # "ok" | "outdated" | "missing"
    found_version: str | None
    error: str | None = None

    @property
    def is_actionable(self) -> bool:
        return self.state in ("missing", "outdated")


def check_tool(tool: Tool) -> ToolStatus:
    """Return the diagnostic status of one tool."""
    binary_path = shutil.which(tool.binary)
    if binary_path is None:
        return ToolStatus(tool=tool, state="missing", found_version=None)

    try:
        result = subprocess.run(
            [binary_path, *tool.version_args],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return ToolStatus(
            tool=tool, state="missing", found_version=None, error=str(e)
        )

    # ProjectDiscovery tools print to stderr typically. Combine both
    # streams to be robust.
    output = (result.stdout or "") + "\n" + (result.stderr or "")
    version = tool.parse_version(output)
    if version is None:
        return ToolStatus(
            tool=tool,
            state="missing",
            found_version=None,
            error="unable to parse version output",
        )

    if _version_lt(version, tool.minimum_version):
        return ToolStatus(tool=tool, state="outdated", found_version=version)

    return ToolStatus(tool=tool, state="ok", found_version=version)


def install_tool(tool: Tool) -> tuple[bool, str]:
    """Run the catalog's install command. Returns (ok, captured_output)."""
    cmd = shlex.split(tool.install_command)
    if not cmd:
        return False, "install command is empty"
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except FileNotFoundError as e:
        return False, f"failed to launch installer: {e}"
    except subprocess.TimeoutExpired:
        return False, "install timed out after 10 minutes"

    output = (result.stdout or "") + (result.stderr or "")
    return result.returncode == 0, output


@click.command("doctor")
@click.option("--yes", is_flag=True, default=False, help="Skip the install prompt.")
def doctor(yes: bool) -> None:
    """Check that external tool binaries are present and compatible."""
    click.echo("Checking external tool dependencies...\n")

    statuses: list[ToolStatus] = [check_tool(t) for t in ALL_TOOLS]
    for st in statuses:
        click.echo(_format_status_line(st))

    actionable = [s for s in statuses if s.is_actionable]
    if not actionable:
        click.echo("\nAll tools present and compatible. CSAK collect is ready.")
        return

    click.echo("\nThe following actions can be taken:")
    for s in actionable:
        verb = "install" if s.state == "missing" else "upgrade"
        click.echo(f"  - {verb} {s.tool.name}    via: {s.tool.install_command}")

    if not yes:
        if not click.confirm("\nProceed?", default=False):
            click.echo(
                "\nNo changes made. Run the install commands manually, "
                "then re-run `csak doctor`."
            )
            sys.exit(1)

    click.echo("")
    all_succeeded = True
    for s in actionable:
        click.echo(f"  installing {s.tool.name}...")
        ok, output = install_tool(s.tool)
        if not ok:
            all_succeeded = False
            click.echo(f"  ✗ failed: {output.strip().splitlines()[-1] if output else 'unknown error'}", err=True)
        else:
            # Re-check.
            new_status = check_tool(s.tool)
            if new_status.state == "ok":
                click.echo(f"  ✓ installed {s.tool.name} {new_status.found_version or ''}")
            else:
                all_succeeded = False
                click.echo(
                    f"  ⚠ install ran but {s.tool.name} still {new_status.state}",
                    err=True,
                )

    if all_succeeded:
        click.echo("\nAll tools present and compatible. CSAK collect is ready.")
    else:
        sys.exit(1)


def _format_status_line(status: ToolStatus) -> str:
    name = status.tool.name
    if status.state == "ok":
        return f"  [ok]   {name:<12} v{status.found_version} (>= {status.tool.minimum_version})"
    if status.state == "outdated":
        return (
            f"  [warn] {name:<12} v{status.found_version} "
            f"(< {status.tool.minimum_version}, recommended upgrade)"
        )
    return f"  [miss] {name:<12} not found on PATH"


def _version_lt(found: str, minimum: str) -> bool:
    """Compare two semver-ish strings. Returns True iff ``found`` <
    ``minimum``. Tolerates extra suffixes (e.g. ``2.6.4-dev``) by
    only comparing the leading dot-separated integers.
    """
    return _parse_version_tuple(found) < _parse_version_tuple(minimum)


def _parse_version_tuple(s: str) -> tuple[int, ...]:
    s = s.lstrip("vV")
    parts: list[int] = []
    for chunk in s.split("."):
        digits = ""
        for ch in chunk:
            if ch.isdigit():
                digits += ch
            else:
                break
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts)
