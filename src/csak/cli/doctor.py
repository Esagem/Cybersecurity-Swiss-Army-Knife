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

from csak.cli.path_setup import (
    PathStatus,
    add_directory_to_user_path,
    check_path_status,
    is_directory_persisted_on_user_path,
)
from csak.collect.plugins import default_plugin_dir, load_plugins
from csak.collect.tool import Tool
from csak.collect.tools import ALL_TOOLS
from csak.collect.types import (
    types_in_registry,
    validate_registry,
    validate_tool_accepts_produces,
)


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


GO_INSTALL_URL = "https://go.dev/dl/"


# Known winget HRESULT codes that surface in stderr when an install
# fails. The hints are remediation steps the user can run themselves —
# none requires admin. Keep the keys lowercase so we can match
# case-insensitively against captured output.
_WINGET_ERROR_HINTS: dict[str, str] = {
    "0x80072f19": (
        "winget can't authenticate to its package source. Try "
        "`winget source reset --force` (no admin needed) and re-run "
        "`csak doctor`."
    ),
    "0x80072efd": (
        "no network connection — check internet/VPN/proxy and re-run "
        "`csak doctor`."
    ),
    "0x8a15000f": (
        "the winget package source is stale. Run `winget source update` "
        "and re-run `csak doctor`."
    ),
    "0x8a150019": (
        "winget couldn't find an applicable source. Run "
        "`winget source reset --force` and re-run `csak doctor`."
    ),
}


def _winget_error_hint(message: str) -> str | None:
    """If ``message`` contains a known winget HRESULT, return a one-line
    remediation hint. Otherwise return ``None``."""
    lowered = message.lower()
    for code, hint in _WINGET_ERROR_HINTS.items():
        if code in lowered:
            return hint
    return None


def _go_bin_dir() -> str | None:
    """Return the directory where ``go install`` deposits binaries.

    Respects ``GOBIN`` if set, else ``GOPATH/bin``, else the default
    ``~/go/bin``. Asks the live ``go`` binary so we honour any user
    overrides instead of guessing. Returns ``None`` if ``go`` isn't on
    PATH or ``go env`` can't be queried.
    """
    import os

    go = shutil.which("go")
    if go is None:
        return None

    def _go_env(key: str) -> str:
        try:
            r = subprocess.run(
                [go, "env", key], capture_output=True, text=True, timeout=10
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return ""
        return r.stdout.strip() if r.returncode == 0 else ""

    gobin = _go_env("GOBIN")
    if gobin:
        return gobin
    gopath = _go_env("GOPATH")
    if gopath:
        # GOPATH may be a list (separator: os.pathsep). The first entry
        # is where `go install` writes by default.
        first = gopath.split(os.pathsep)[0]
        return os.path.join(first, "bin")
    return os.path.expanduser("~/go/bin")


def _go_installer_command() -> list[str] | None:
    """Return the package-manager argv that installs Go on this platform,
    or ``None`` if no supported installer is available.

    We cap the matrix at the platforms with a single canonical, scriptable
    package manager: ``winget`` on Windows, ``brew`` on macOS. Linux is
    intentionally left out — distros diverge enough that picking one would
    surprise users. Doctor falls back to printing the Go download URL on
    unsupported platforms.
    """
    if sys.platform == "win32" and shutil.which("winget"):
        return [
            "winget",
            "install",
            "-e",
            "--id",
            "GoLang.Go",
            "--accept-source-agreements",
            "--accept-package-agreements",
        ]
    if sys.platform == "darwin" and shutil.which("brew"):
        return ["brew", "install", "go"]
    return None


def _go_installer_label() -> str:
    if sys.platform == "win32":
        return "winget (winget install -e --id GoLang.Go)"
    if sys.platform == "darwin":
        return "Homebrew (brew install go)"
    return "your package manager"


# Phrases winget/brew print when ``install`` is run on a package
# that's already present and up-to-date. Both tools exit non-zero in
# this case, but the user's intent ("Go is now installed") is satisfied
# — so we treat these as success and still extend the live PATH so a
# stale shell can pick up the existing install.
_ALREADY_INSTALLED_SIGNALS: tuple[str, ...] = (
    "no newer package versions are available",  # winget install
    "no applicable update found",                # winget upgrade
    "installed package is current",              # winget
    "already installed",                         # brew
    "is already installed",                      # brew variant
)


def _output_says_already_installed(output: str) -> bool:
    lowered = output.lower()
    return any(sig in lowered for sig in _ALREADY_INSTALLED_SIGNALS)


def _locate_existing_go() -> str | None:
    """Check canonical install locations for an existing Go install.

    A "stale" shell — one launched before Go was installed system-wide
    — won't have Go on PATH but the binary is still on disk at a
    well-known location. Detecting that directly takes microseconds;
    asking winget the same question takes 10-30 seconds because it has
    to refresh sources. Returns the directory containing ``go`` /
    ``go.exe``, or ``None`` if no canonical install is found.
    """
    import os

    candidates: list[str] = []
    if sys.platform == "win32":
        candidates.extend([
            r"C:\Program Files\Go\bin",
            r"C:\Program Files (x86)\Go\bin",
        ])
    elif sys.platform == "darwin":
        candidates.extend([
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "/opt/local/bin",
        ])

    exe = "go.exe" if sys.platform == "win32" else "go"
    for d in candidates:
        if os.path.isfile(os.path.join(d, exe)):
            return d
    return None


def install_go() -> tuple[bool, str]:
    """Run the platform's Go installer. Returns ``(ok, message)``.

    Fast path: if Go is already installed at a canonical location,
    skip the (slow) package-manager invocation and just extend the
    live PATH — covers the very common case of a stale shell that
    started before Go was installed.

    Slow path: invoke ``winget install`` / ``brew install``. Even if
    the package manager exits non-zero with a "no newer version"
    message we treat that as success and still extend the live PATH.
    """
    existing = _locate_existing_go()
    if existing is not None:
        _extend_live_path_for_go()
        return True, (
            f"Go already installed at {existing} — extended this shell's "
            "PATH so the install is visible without restarting"
        )

    cmd = _go_installer_command()
    if cmd is None:
        return False, (
            f"automatic Go install isn't supported here; "
            f"download Go from {GO_INSTALL_URL}"
        )
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except FileNotFoundError as e:
        return False, f"failed to launch installer: {e}"
    except subprocess.TimeoutExpired:
        return False, "Go install timed out after 10 minutes"

    output = (result.stdout or "") + (result.stderr or "")
    already_installed = _output_says_already_installed(output)

    if result.returncode != 0 and not already_installed:
        last = output.strip().splitlines()[-1] if output.strip() else "unknown error"
        return False, f"installer failed: {last}"

    _extend_live_path_for_go()
    if already_installed:
        return True, (
            "Go was already installed — extended this shell's PATH so "
            "the install is visible without restarting the terminal"
        )
    return True, "Go installed (a new terminal may be needed for permanent PATH)"


def _extend_live_path_for_go() -> None:
    """Prepend canonical Go bin and user GOBIN to this process's PATH."""
    import os

    candidates: list[str] = []
    if sys.platform == "win32":
        candidates.append(r"C:\Program Files\Go\bin")
    elif sys.platform == "darwin":
        candidates.extend(["/opt/homebrew/bin", "/usr/local/bin"])
    candidates.append(os.path.expanduser("~/go/bin"))

    current_parts = os.environ.get("PATH", "").split(os.pathsep)
    current_norm = {os.path.normcase(os.path.normpath(p)) for p in current_parts if p}
    for d in candidates:
        if os.path.normcase(os.path.normpath(d)) not in current_norm:
            os.environ["PATH"] = d + os.pathsep + os.environ.get("PATH", "")


def _prompt_tool_strategy(default: str = "n") -> str:
    """Ask ``[a]ll / [n]one / [s]ome`` and return ``"all"``, ``"none"``, or ``"some"``."""
    answer = click.prompt(
        "Install tools? [a]ll / [n]one / [s]ome",
        type=click.Choice(["a", "n", "s"], case_sensitive=False),
        default=default,
        show_choices=False,
    ).lower()
    return {"a": "all", "n": "none", "s": "some"}[answer]


@click.command("doctor")
@click.option(
    "--yes",
    is_flag=True,
    default=False,
    help="Approve every offered action without prompting (Go, PATH, all tools).",
)
@click.option(
    "--no-go",
    is_flag=True,
    default=False,
    help="Do not offer to install Go even if it is missing.",
)
@click.option(
    "--no-path",
    is_flag=True,
    default=False,
    help="Do not offer or apply the User PATH update.",
)
@click.option(
    "--no-tools",
    is_flag=True,
    default=False,
    help="Do not offer or apply external-tool installs.",
)
def doctor(yes: bool, no_go: bool, no_path: bool, no_tools: bool) -> None:
    """Check csak's environment and offer per-action fixes in order:

    \b
      1. Install Go if missing (winget on Windows, brew on macOS).
      2. Add csak's Scripts directory to your User PATH.
      3. Install/upgrade subfinder, httpx, nuclei — choose [a]ll,
         [n]one, or [s]ome to pick per-tool.

    Use ``--yes`` to approve every offered action without prompting,
    or ``--no-go`` / ``--no-path`` / ``--no-tools`` to suppress a
    category entirely.
    """
    click.echo("Checking csak environment...\n")

    # Slice 3: import plugins before doing tool checks so plugin-loaded
    # tools appear in the per-tool list and any plugin-introduced types
    # participate in the registry validation below.
    plugin_report = load_plugins()
    plugin_warnings: list[str] = list(plugin_report.warnings)

    path_status = check_path_status()
    click.echo(_format_path_status_line(path_status))
    statuses: list[ToolStatus] = [check_tool(t) for t in ALL_TOOLS]
    for st in statuses:
        click.echo(_format_status_line(st))

    # Slice 3: plugin and type-registry validation. Failures are
    # blocking ("collect won't run reliably"); warnings are advisory.
    plugin_dir = plugin_report.plugin_dir
    click.echo("")
    click.echo(f"Checking plugin tools ({plugin_dir})...")
    plugin_tools = [t for t in ALL_TOOLS if t.origin == "plugin"]
    if not plugin_dir.exists():
        click.echo("  (plugin directory does not exist — no plugins loaded)")
    elif not plugin_tools and not plugin_warnings:
        click.echo("  (no plugins loaded)")
    else:
        for t in plugin_tools:
            click.echo(f"  [ok]   {t.name:<12} loaded from {t.source_path}")
        for w in plugin_warnings:
            click.echo(f"  [warn] {w}")

    click.echo("")
    click.echo("Checking type registry...")
    type_count = len(types_in_registry())
    plugin_type_count = max(0, type_count - 7)
    click.echo(
        f"  [ok]   {type_count} registered types "
        f"({type_count - plugin_type_count} built-in, {plugin_type_count} plugin)"
    )
    registry_errors: list[str] = list(validate_registry())
    for tool in ALL_TOOLS:
        registry_errors.extend(
            validate_tool_accepts_produces(tool.name, tool.accepts, tool.produces)
        )
    for err in registry_errors:
        click.echo(f"  [fail] {err}", err=True)

    click.echo("")
    click.echo("Checking recursion graph...")
    orphan_warnings = _check_recursion_graph()
    if orphan_warnings:
        for w in orphan_warnings:
            click.echo(f"  [warn] {w}")
    else:
        click.echo("  [ok]   no orphan tools")

    if registry_errors:
        click.echo("")
        click.echo(
            f"Type registry has {len(registry_errors)} error(s); collect will "
            "refuse to run until they are fixed.",
            err=True,
        )

    path_actionable = (
        path_status.state == "needs_add"
        and path_status.directory is not None
        and not no_path
    )
    actionable_tools = (
        [] if no_tools else [s for s in statuses if s.is_actionable]
    )
    go_missing = bool(actionable_tools) and shutil.which("go") is None
    go_installer = _go_installer_command() if go_missing and not no_go else None

    if not path_actionable and not actionable_tools:
        if registry_errors:
            sys.exit(1)
        click.echo("\nAll tools present and compatible. CSAK collect is ready.")
        return

    click.echo("")
    all_succeeded = True
    go_unresolved = False

    # ── Step 1: Go ───────────────────────────────────────────────────────
    if go_missing:
        if go_installer is not None:
            click.echo(
                f"Go is required to install subfinder/httpx/nuclei but is "
                f"not on PATH.\nWe can install it via {_go_installer_label()}.\n"
            )
            if yes or click.confirm("Install Go now?", default=False):
                click.echo("  installing Go...")
                ok, msg = install_go()
                if ok:
                    click.echo(f"  ✓ {msg}")
                    if shutil.which("go") is None:
                        click.echo(
                            "  ⚠ Go installer ran but `go` isn't visible in this "
                            "shell yet. Restart the terminal and re-run "
                            "`csak doctor` to install the tools.",
                            err=True,
                        )
                        actionable_tools = []
                        go_unresolved = True
                else:
                    all_succeeded = False
                    go_unresolved = True
                    actionable_tools = []
                    click.echo(f"  ✗ {msg}", err=True)
                    hint = _winget_error_hint(msg)
                    if hint:
                        click.echo(f"  Hint: {hint}", err=True)
                    click.echo(
                        f"  Manual install: download Go from {GO_INSTALL_URL} "
                        "and re-run `csak doctor`.",
                        err=True,
                    )
            else:
                click.echo("  ⤳ skipped Go install")
                go_unresolved = True
                actionable_tools = []
        else:
            click.echo(
                f"Go is required to install subfinder/httpx/nuclei but is "
                f"not on PATH.\nInstall Go (>= 1.21) from {GO_INSTALL_URL} "
                "and re-run `csak doctor`."
            )
            go_unresolved = True
            actionable_tools = []

    # ── Step 2: PATH ─────────────────────────────────────────────────────
    if path_actionable:
        assert path_status.directory is not None
        if go_missing:
            click.echo("")
        if yes or click.confirm(
            f"Add {path_status.directory} to User PATH?", default=False
        ):
            click.echo(f"  adding {path_status.directory} to User PATH...")
            ok, msg = add_directory_to_user_path(path_status.directory)
            if ok:
                click.echo(f"  ✓ {msg}")
            else:
                all_succeeded = False
                click.echo(f"  ✗ {msg}", err=True)
        else:
            click.echo("  ⤳ skipped PATH update")

    # ── Step 3: Tools (all/none/some) ────────────────────────────────────
    if actionable_tools:
        click.echo("\nThe following tools can be installed or upgraded:")
        for s in actionable_tools:
            verb = "install" if s.state == "missing" else "upgrade"
            click.echo(f"  - {verb} {s.tool.name}    via: {s.tool.install_command}")
        click.echo("")

        if yes:
            strategy = "all"
        else:
            strategy = _prompt_tool_strategy(default="n")

        any_tool_installed = False
        if strategy == "none":
            for s in actionable_tools:
                click.echo(f"  ⤳ skipped {s.tool.name}")
        else:
            for s in actionable_tools:
                if strategy == "some":
                    if not click.confirm(
                        f"  Install {s.tool.name} via "
                        f"`{s.tool.install_command}`?",
                        default=False,
                    ):
                        click.echo(f"  ⤳ skipped {s.tool.name}")
                        continue
                if _apply_tool_install(s):
                    any_tool_installed = True
                else:
                    all_succeeded = False

        # ── Step 4: GOBIN on User PATH ───────────────────────────────────
        # `go install` drops binaries in $GOBIN (or $GOPATH/bin), which
        # isn't on the default User PATH. Without this fix, csak collect
        # in a *new* shell won't find subfinder/httpx/nuclei.
        if any_tool_installed and not no_path:
            go_bin = _go_bin_dir()
            # Use the persisted-only check: install_go() may have just
            # added go_bin to the live PATH, but we want to know if
            # *future* shells will see it.
            if go_bin and is_directory_persisted_on_user_path(go_bin):
                click.echo(
                    f"\n  [ok]   {go_bin} already on User PATH — fresh "
                    "shells will find the tools"
                )
            elif go_bin:
                click.echo("")
                if yes or click.confirm(
                    f"Add {go_bin} to User PATH so `csak collect` finds "
                    "the tools after a shell restart?",
                    default=True,
                ):
                    click.echo(f"  adding {go_bin} to User PATH...")
                    ok, msg = add_directory_to_user_path(go_bin)
                    if ok:
                        click.echo(f"  ✓ {msg}")
                    else:
                        all_succeeded = False
                        click.echo(f"  ✗ {msg}", err=True)
                else:
                    click.echo(f"  ⤳ skipped — add {go_bin} to PATH yourself "
                               "or csak collect won't find the tools.")

    if all_succeeded and not go_unresolved and not registry_errors:
        click.echo("\nAll selected actions completed. CSAK collect is ready.")
    else:
        sys.exit(1)


def _apply_tool_install(status: ToolStatus) -> bool:
    """Run install + re-check for one tool. Returns True on success."""
    verb = "install" if status.state == "missing" else "upgrade"
    click.echo(f"  {verb}ing {status.tool.name}...")
    ok, output = install_tool(status.tool)
    if not ok:
        last = output.strip().splitlines()[-1] if output else "unknown error"
        click.echo(f"  ✗ failed: {last}", err=True)
        return False
    new_status = check_tool(status.tool)
    if new_status.state == "ok":
        click.echo(
            f"  ✓ installed {status.tool.name} "
            f"{new_status.found_version or ''}"
        )
        return True
    click.echo(
        f"  ⚠ install ran but {status.tool.name} still {new_status.state}",
        err=True,
    )
    return False


def _check_recursion_graph() -> list[str]:
    """Return advisory warnings for the recursion graph.

    Currently surfaces orphan output types — types a tool produces
    that no registered tool (including the tool itself, since same-
    tool recursion against a different target is valid) accepts. Per
    spec these are warnings, not errors: an analyst may have a tool
    whose output they consume manually.
    """
    from csak.collect.types import matches as types_match

    warnings: list[str] = []
    for tool in ALL_TOOLS:
        for produces_type in tool.produces:
            consumed = any(
                types_match(produces_type, other.accepts) for other in ALL_TOOLS
            )
            if not consumed:
                warnings.append(
                    f"tool {tool.name!r} produces {produces_type!r} which no "
                    "registered tool accepts (orphan output type)"
                )
    return warnings


def _format_path_status_line(status: PathStatus) -> str:
    if status.state == "ok":
        return f"  [ok]   csak script dir on PATH ({status.directory})"
    if status.state == "needs_add":
        return f"  [warn] csak script dir not on User PATH ({status.directory})"
    return f"  [warn] csak script dir not located ({status.message})"


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
