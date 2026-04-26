"""Tests for the ``csak doctor`` checker.

The check_tool path uses ``shutil.which`` and ``subprocess.run``. Both
are monkeypatched here so the test never depends on whether
subfinder/httpx/nuclei are actually installed on the test host.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass

import click
import pytest
from click.testing import CliRunner

from csak.cli import doctor as doctor_mod
from csak.cli.doctor import (
    _go_bin_dir,
    _locate_existing_go,
    _parse_version_tuple,
    _prompt_tool_strategy,
    _version_lt,
    _winget_error_hint,
    check_tool,
    doctor,
    install_go,
    install_tool,
)
from csak.cli.path_setup import PathStatus
from csak.collect.tools.subfinder import SUBFINDER


@pytest.fixture(autouse=True)
def _stub_path_check(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default: PATH is fine. Tests that care override this."""
    monkeypatch.setattr(
        doctor_mod,
        "check_path_status",
        lambda: PathStatus(state="ok", directory="/usr/local/bin", message="ok"),
    )


@pytest.fixture(autouse=True)
def _stub_locate_existing_go(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default: pretend Go isn't at a canonical path. Tests that
    exercise the fast path override this."""
    monkeypatch.setattr(doctor_mod, "_locate_existing_go", lambda: None)


@dataclass
class FakeCompleted:
    returncode: int
    stdout: str = ""
    stderr: str = ""


def test_check_tool_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor_mod.shutil, "which", lambda b: None)
    status = check_tool(SUBFINDER)
    assert status.state == "missing"
    assert status.found_version is None


def test_check_tool_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor_mod.shutil, "which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr(
        doctor_mod.subprocess,
        "run",
        lambda *a, **k: FakeCompleted(
            returncode=0,
            stderr="Current Version: v2.6.4",
        ),
    )
    status = check_tool(SUBFINDER)
    assert status.state == "ok"
    assert status.found_version == "2.6.4"


def test_check_tool_outdated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor_mod.shutil, "which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr(
        doctor_mod.subprocess,
        "run",
        lambda *a, **k: FakeCompleted(
            returncode=0,
            stderr="Current Version: v2.5.9",
        ),
    )
    status = check_tool(SUBFINDER)
    assert status.state == "outdated"
    assert status.found_version == "2.5.9"


def test_check_tool_handles_unparseable_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(doctor_mod.shutil, "which", lambda b: "/usr/bin/x")
    monkeypatch.setattr(
        doctor_mod.subprocess,
        "run",
        lambda *a, **k: FakeCompleted(returncode=0, stderr="garbage no version"),
    )
    status = check_tool(SUBFINDER)
    assert status.state == "missing"


def test_check_tool_handles_subprocess_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(doctor_mod.shutil, "which", lambda b: "/usr/bin/x")

    def bad_run(*a, **k):
        raise subprocess.TimeoutExpired(cmd="x", timeout=5)

    monkeypatch.setattr(doctor_mod.subprocess, "run", bad_run)
    status = check_tool(SUBFINDER)
    assert status.state == "missing"


def test_install_tool_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        doctor_mod.subprocess,
        "run",
        lambda *a, **k: FakeCompleted(returncode=0, stdout="installed ok"),
    )
    ok, output = install_tool(SUBFINDER)
    assert ok
    assert "installed ok" in output


def test_install_tool_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        doctor_mod.subprocess,
        "run",
        lambda *a, **k: FakeCompleted(returncode=1, stderr="boom"),
    )
    ok, output = install_tool(SUBFINDER)
    assert not ok
    assert "boom" in output


def test_install_go_unsupported_platform_returns_hint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(doctor_mod, "_go_installer_command", lambda: None)
    ok, msg = install_go()
    assert not ok
    assert "https://go.dev/dl/" in msg


def test_install_go_runs_command_and_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[list[str]] = []

    monkeypatch.setattr(
        doctor_mod, "_go_installer_command", lambda: ["winget", "install", "go"]
    )

    def fake_run(cmd, *a, **k):
        captured.append(list(cmd))
        return FakeCompleted(returncode=0, stdout="installed")

    monkeypatch.setattr(doctor_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(doctor_mod, "_extend_live_path_for_go", lambda: None)

    ok, msg = install_go()
    assert ok
    assert captured == [["winget", "install", "go"]]
    assert "Go installed" in msg


def test_install_go_failure_surfaces_last_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        doctor_mod, "_go_installer_command", lambda: ["winget", "install", "go"]
    )
    monkeypatch.setattr(
        doctor_mod.subprocess,
        "run",
        lambda *a, **k: FakeCompleted(returncode=1, stderr="boom: package missing"),
    )

    ok, msg = install_go()
    assert not ok
    assert "boom: package missing" in msg


def test_install_go_treats_winget_already_installed_as_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """winget exits non-zero with 'no newer package versions are available'
    when the package is already installed. That's a success from the user's
    point of view — Go is present — so install_go() should return ok and
    extend the live PATH."""
    extend_calls: list[bool] = []
    monkeypatch.setattr(
        doctor_mod, "_go_installer_command", lambda: ["winget", "install", "go"]
    )
    monkeypatch.setattr(
        doctor_mod, "_extend_live_path_for_go",
        lambda: extend_calls.append(True),
    )
    monkeypatch.setattr(
        doctor_mod.subprocess,
        "run",
        lambda *a, **k: FakeCompleted(
            returncode=1,
            stderr="No newer package versions are available from the configured sources.",
        ),
    )

    ok, msg = install_go()
    assert ok
    assert extend_calls == [True]
    assert "already installed" in msg


def test_install_go_fast_path_when_canonical_install_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If Go is found at a canonical location, install_go returns success
    without invoking the package manager — saves the slow winget/brew run."""
    extend_calls: list[bool] = []
    subprocess_calls: list[object] = []

    monkeypatch.setattr(
        doctor_mod, "_locate_existing_go", lambda: r"C:\Program Files\Go\bin"
    )
    monkeypatch.setattr(
        doctor_mod, "_extend_live_path_for_go",
        lambda: extend_calls.append(True),
    )
    monkeypatch.setattr(
        doctor_mod.subprocess,
        "run",
        lambda *a, **k: subprocess_calls.append((a, k)),
    )

    ok, msg = install_go()
    assert ok
    assert subprocess_calls == []     # no winget invocation at all
    assert extend_calls == [True]     # but live PATH was extended
    assert "already installed" in msg
    assert r"C:\Program Files\Go\bin" in msg


def test_locate_existing_go_returns_none_when_no_canonical_install(
    monkeypatch: pytest.MonkeyPatch, tmp_path,
) -> None:
    """Disable the autouse stub and exercise the real function.
    With no canonical Go install, the function should return None."""
    monkeypatch.undo()  # drop autouse stubs so real function runs
    # Force the candidate paths to point at an empty tmp dir.
    monkeypatch.setattr(doctor_mod.sys, "platform", "linux")  # unsupported → []
    assert _locate_existing_go() is None


def test_install_go_treats_brew_already_installed_as_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        doctor_mod, "_go_installer_command", lambda: ["brew", "install", "go"]
    )
    monkeypatch.setattr(doctor_mod, "_extend_live_path_for_go", lambda: None)
    monkeypatch.setattr(
        doctor_mod.subprocess,
        "run",
        lambda *a, **k: FakeCompleted(
            returncode=1,
            stderr="Warning: go 1.22 is already installed and up-to-date.",
        ),
    )

    ok, _ = install_go()
    assert ok


def test_winget_error_hint_recognises_known_codes() -> None:
    msg = "installer failed: 0x80072f19 : unknown error"
    hint = _winget_error_hint(msg)
    assert hint is not None
    assert "winget source reset" in hint


def test_winget_error_hint_is_case_insensitive() -> None:
    assert _winget_error_hint("FAILED 0x80072F19") is not None


def test_winget_error_hint_returns_none_for_unknown() -> None:
    assert _winget_error_hint("some other error 0xdeadbeef") is None
    assert _winget_error_hint("") is None


def test_go_bin_dir_returns_none_without_go(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(doctor_mod.shutil, "which", lambda b: None)
    assert _go_bin_dir() is None


def test_go_bin_dir_prefers_gobin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor_mod.shutil, "which", lambda b: "/usr/bin/go")

    def fake_run(cmd, *a, **k):
        # Order: GOBIN first, then GOPATH if GOBIN is empty.
        if cmd[-1] == "GOBIN":
            return FakeCompleted(returncode=0, stdout="/custom/gobin\n")
        return FakeCompleted(returncode=0, stdout="/should/not/be/used\n")

    monkeypatch.setattr(doctor_mod.subprocess, "run", fake_run)
    assert _go_bin_dir() == "/custom/gobin"


def test_go_bin_dir_falls_back_to_gopath_bin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor_mod.shutil, "which", lambda b: "/usr/bin/go")

    def fake_run(cmd, *a, **k):
        if cmd[-1] == "GOBIN":
            return FakeCompleted(returncode=0, stdout="\n")
        if cmd[-1] == "GOPATH":
            return FakeCompleted(returncode=0, stdout="/home/u/go\n")
        return FakeCompleted(returncode=1, stdout="")

    monkeypatch.setattr(doctor_mod.subprocess, "run", fake_run)
    result = _go_bin_dir()
    # Use os.path.join semantics for the expected slash style.
    import os as _os
    assert result == _os.path.join("/home/u/go", "bin")


def test_go_bin_dir_handles_multi_entry_gopath(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If GOPATH is a list, `go install` writes to the first entry's bin."""
    import os as _os

    monkeypatch.setattr(doctor_mod.shutil, "which", lambda b: "/usr/bin/go")
    multi = f"/first/path{_os.pathsep}/second/path"

    def fake_run(cmd, *a, **k):
        if cmd[-1] == "GOBIN":
            return FakeCompleted(returncode=0, stdout="\n")
        return FakeCompleted(returncode=0, stdout=multi + "\n")

    monkeypatch.setattr(doctor_mod.subprocess, "run", fake_run)
    assert _go_bin_dir() == _os.path.join("/first/path", "bin")


def test_doctor_offers_gobin_path_after_tool_installs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When tools install successfully and GOBIN isn't on PATH, doctor
    asks to add it (defaulting to yes) so a fresh shell finds the tools."""
    add_calls: list[str] = []
    state = {"installed": False}

    def fake_which(binary: str):
        if binary == "go":
            return "/usr/bin/go"
        if state["installed"]:
            return f"/usr/bin/{binary}"
        return None

    def fake_run(cmd, *a, **k):
        # `go env` queries.
        if isinstance(cmd, list) and cmd[:2] == ["/usr/bin/go", "env"]:
            return FakeCompleted(
                returncode=0,
                stdout="" if cmd[-1] == "GOBIN" else "/home/u/go\n",
            )
        # `go install ...` triggers tool install.
        if isinstance(cmd, list) and cmd and cmd[0] == "go":
            state["installed"] = True
            return FakeCompleted(returncode=0, stdout="ok")
        # Tool version probes.
        return FakeCompleted(returncode=0, stderr="Current Version: v9.9.9")

    monkeypatch.setattr(doctor_mod.shutil, "which", fake_which)
    monkeypatch.setattr(doctor_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(
        doctor_mod, "is_directory_persisted_on_user_path", lambda d: False
    )
    monkeypatch.setattr(
        doctor_mod, "add_directory_to_user_path",
        lambda d: (add_calls.append(d), (True, "ok"))[1],
    )

    result = CliRunner().invoke(doctor, ["--yes"])
    assert result.exit_code == 0
    import os as _os
    expected = _os.path.join("/home/u/go", "bin")
    assert add_calls == [expected]


def test_doctor_skips_gobin_path_when_already_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    add_calls: list[str] = []
    state = {"installed": False}

    def fake_which(binary: str):
        if binary == "go":
            return "/usr/bin/go"
        if state["installed"]:
            return f"/usr/bin/{binary}"
        return None

    def fake_run(cmd, *a, **k):
        if isinstance(cmd, list) and cmd[:2] == ["/usr/bin/go", "env"]:
            return FakeCompleted(
                returncode=0,
                stdout="" if cmd[-1] == "GOBIN" else "/home/u/go\n",
            )
        if isinstance(cmd, list) and cmd and cmd[0] == "go":
            state["installed"] = True
            return FakeCompleted(returncode=0, stdout="ok")
        return FakeCompleted(returncode=0, stderr="Current Version: v9.9.9")

    monkeypatch.setattr(doctor_mod.shutil, "which", fake_which)
    monkeypatch.setattr(doctor_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(
        doctor_mod, "is_directory_persisted_on_user_path", lambda d: True
    )
    monkeypatch.setattr(
        doctor_mod, "add_directory_to_user_path",
        lambda d: (add_calls.append(d), (True, "ok"))[1],
    )

    result = CliRunner().invoke(doctor, ["--yes"])
    assert result.exit_code == 0
    assert add_calls == []   # GOBIN already on PATH; no add attempted
    assert "already on User PATH" in result.output  # explicit confirmation


def test_doctor_no_path_flag_suppresses_gobin_prompt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    add_calls: list[str] = []
    state = {"installed": False}

    def fake_which(binary: str):
        if binary == "go":
            return "/usr/bin/go"
        if state["installed"]:
            return f"/usr/bin/{binary}"
        return None

    def fake_run(cmd, *a, **k):
        if isinstance(cmd, list) and cmd[:2] == ["/usr/bin/go", "env"]:
            return FakeCompleted(returncode=0, stdout="/home/u/go\n")
        if isinstance(cmd, list) and cmd and cmd[0] == "go":
            state["installed"] = True
            return FakeCompleted(returncode=0, stdout="ok")
        return FakeCompleted(returncode=0, stderr="Current Version: v9.9.9")

    monkeypatch.setattr(doctor_mod.shutil, "which", fake_which)
    monkeypatch.setattr(doctor_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(
        doctor_mod, "is_directory_persisted_on_user_path", lambda d: False
    )
    monkeypatch.setattr(
        doctor_mod, "add_directory_to_user_path",
        lambda d: (add_calls.append(d), (True, "ok"))[1],
    )

    result = CliRunner().invoke(doctor, ["--yes", "--no-path"])
    assert result.exit_code == 0
    # csak Scripts dir update suppressed by --no-path; same for GOBIN.
    assert add_calls == []


def test_doctor_go_failure_surfaces_hint_and_manual_link(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the package-manager Go install fails with a known winget
    error, doctor prints the remediation hint AND the manual download
    URL so the user always has a clear next step."""
    monkeypatch.setattr(
        doctor_mod, "_go_installer_command", lambda: ["winget", "install", "go"]
    )
    monkeypatch.setattr(
        doctor_mod,
        "install_go",
        lambda: (False, "installer failed: 0x80072f19 : unknown error"),
    )
    monkeypatch.setattr(doctor_mod.shutil, "which", lambda b: None)
    monkeypatch.setattr(
        doctor_mod.subprocess,
        "run",
        lambda *a, **k: FakeCompleted(returncode=0, stderr=""),
    )

    result = CliRunner().invoke(doctor, ["--yes"])
    assert result.exit_code == 1
    combined = result.output + (result.stderr_bytes or b"").decode(errors="replace")
    assert "0x80072f19" in combined
    assert "winget source reset" in combined
    assert "https://go.dev/dl/" in combined


def test_prompt_tool_strategy_maps_short_letters() -> None:
    from click.testing import CliRunner

    @click.command()
    def cmd() -> None:
        click.echo(_prompt_tool_strategy())

    runner = CliRunner()
    assert "all" in runner.invoke(cmd, input="a\n").output
    assert "none" in runner.invoke(cmd, input="n\n").output
    assert "some" in runner.invoke(cmd, input="s\n").output


def test_install_tool_launch_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def bad_run(*a, **k):
        raise FileNotFoundError("go: command not found")

    monkeypatch.setattr(doctor_mod.subprocess, "run", bad_run)
    ok, output = install_tool(SUBFINDER)
    assert not ok
    assert "go: command not found" in output


def test_version_compare_lt() -> None:
    assert _version_lt("2.5.9", "2.6.0") is True
    assert _version_lt("2.6.0", "2.6.0") is False
    assert _version_lt("3.0.0", "2.6.0") is False
    # Trailing suffix tolerated.
    assert _version_lt("2.6.4-dev", "2.6.0") is False


def test_parse_version_tuple_handles_short_versions() -> None:
    assert _parse_version_tuple("2.6") == (2, 6)
    assert _parse_version_tuple("v2.6.4") == (2, 6, 4)
    assert _parse_version_tuple("not-a-version") == ()


# ---------------------------------------------------------------------------
# CLI integration — the doctor command itself.
# ---------------------------------------------------------------------------


def test_doctor_cli_all_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor_mod.shutil, "which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr(
        doctor_mod.subprocess,
        "run",
        lambda *a, **k: FakeCompleted(returncode=0, stderr="Current Version: v9.9.9"),
    )
    result = CliRunner().invoke(doctor, [])
    assert result.exit_code == 0
    assert "All tools present and compatible" in result.output


def test_doctor_cli_skips_tool_installs_when_go_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(doctor_mod.shutil, "which", lambda b: None)
    result = CliRunner().invoke(doctor, [])
    assert result.exit_code == 1
    assert "not found on PATH" in result.output
    assert "Go is required" in result.output
    assert "https://go.dev/dl/" in result.output


def test_doctor_cli_yes_runs_install(monkeypatch: pytest.MonkeyPatch) -> None:
    # Before install: tool binaries missing on PATH; after install: present.
    # Go must be present for installs to be offered at all.
    state = {"installed": False}

    def fake_which(binary: str):
        if binary == "go":
            return "/usr/bin/go"
        if state["installed"]:
            return f"/usr/bin/{binary}"
        return None

    def fake_run(cmd, *a, **k):
        if isinstance(cmd, list) and cmd and cmd[0] == "go":
            state["installed"] = True
            return FakeCompleted(returncode=0, stdout="ok")
        return FakeCompleted(returncode=0, stderr="Current Version: v9.9.9")

    monkeypatch.setattr(doctor_mod.shutil, "which", fake_which)
    monkeypatch.setattr(doctor_mod.subprocess, "run", fake_run)

    result = CliRunner().invoke(doctor, ["--yes"])
    assert result.exit_code == 0
    assert "installing" in result.output


# ---------------------------------------------------------------------------
# PATH-setup integration with doctor.
# ---------------------------------------------------------------------------


def test_doctor_lists_path_action_when_script_dir_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        doctor_mod,
        "check_path_status",
        lambda: PathStatus(
            state="needs_add",
            directory=r"C:\Users\u\AppData\Roaming\Python\Python314\Scripts",
            message="not on User PATH",
        ),
    )
    monkeypatch.setattr(doctor_mod.shutil, "which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr(
        doctor_mod.subprocess,
        "run",
        lambda *a, **k: FakeCompleted(returncode=0, stderr="Current Version: v9.9.9"),
    )

    # Decline the path-update prompt: skipping is intentional, exit 0.
    result = CliRunner().invoke(doctor, [], input="n\n")
    assert result.exit_code == 0
    assert "not on User PATH" in result.output
    assert "Add C:\\Users\\u\\AppData\\Roaming\\Python\\Python314\\Scripts" in result.output
    assert "skipped PATH update" in result.output


def test_doctor_yes_applies_path_fix(monkeypatch: pytest.MonkeyPatch) -> None:
    target_dir = r"C:\Users\u\AppData\Roaming\Python\Python314\Scripts"
    calls: list[str] = []

    monkeypatch.setattr(
        doctor_mod,
        "check_path_status",
        lambda: PathStatus(state="needs_add", directory=target_dir, message="x"),
    )

    def fake_add(d: str) -> tuple[bool, str]:
        calls.append(d)
        return True, f"added {d} to User PATH"

    monkeypatch.setattr(doctor_mod, "add_directory_to_user_path", fake_add)
    monkeypatch.setattr(doctor_mod.shutil, "which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr(
        doctor_mod.subprocess,
        "run",
        lambda *a, **k: FakeCompleted(returncode=0, stderr="Current Version: v9.9.9"),
    )

    result = CliRunner().invoke(doctor, ["--yes"])
    assert result.exit_code == 0
    assert calls == [target_dir]
    assert f"added {target_dir} to User PATH" in result.output


def test_doctor_path_fix_failure_exits_nonzero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        doctor_mod,
        "check_path_status",
        lambda: PathStatus(state="needs_add", directory="/some/dir", message="x"),
    )
    monkeypatch.setattr(
        doctor_mod,
        "add_directory_to_user_path",
        lambda d: (False, "registry write denied"),
    )
    monkeypatch.setattr(doctor_mod.shutil, "which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr(
        doctor_mod.subprocess,
        "run",
        lambda *a, **k: FakeCompleted(returncode=0, stderr="Current Version: v9.9.9"),
    )

    result = CliRunner().invoke(doctor, ["--yes"])
    assert result.exit_code == 1
    assert "registry write denied" in result.output


def test_doctor_strategy_some_picks_individual_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Decline PATH, choose [s]ome, then install each tool individually."""
    target_dir = r"C:\scripts"
    path_calls: list[str] = []
    install_calls: list[str] = []

    monkeypatch.setattr(
        doctor_mod,
        "check_path_status",
        lambda: PathStatus(state="needs_add", directory=target_dir, message="x"),
    )
    monkeypatch.setattr(
        doctor_mod, "add_directory_to_user_path", lambda d: (path_calls.append(d), (True, "ok"))[1]
    )

    state = {"installed": False}

    def fake_which(binary: str):
        if binary == "go":
            return "/usr/bin/go"
        if state["installed"]:
            return f"/usr/bin/{binary}"
        return None

    def fake_run(cmd, *a, **k):
        if isinstance(cmd, list) and cmd and cmd[0] == "go":
            state["installed"] = True
            install_calls.append(cmd[-1])
            return FakeCompleted(returncode=0, stdout="ok")
        return FakeCompleted(returncode=0, stderr="Current Version: v9.9.9")

    monkeypatch.setattr(doctor_mod.shutil, "which", fake_which)
    monkeypatch.setattr(doctor_mod.subprocess, "run", fake_run)

    # PATH=no, strategy=some, subfinder=yes, httpx=yes, nuclei=yes.
    result = CliRunner().invoke(doctor, [], input="n\ns\ny\ny\ny\n")
    assert result.exit_code == 0
    assert path_calls == []
    assert len(install_calls) == 3
    assert "skipped PATH update" in result.output


def test_doctor_strategy_all_installs_every_tool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`a` at the strategy prompt installs every tool without per-tool prompts."""
    install_calls: list[list[str]] = []
    state = {"installed": False}

    def fake_which(binary: str):
        if binary == "go":
            return "/usr/bin/go"
        if state["installed"]:
            return f"/usr/bin/{binary}"
        return None

    def fake_run(cmd, *a, **k):
        if isinstance(cmd, list) and cmd and cmd[0] == "go":
            state["installed"] = True
            install_calls.append(list(cmd))
            return FakeCompleted(returncode=0, stdout="ok")
        return FakeCompleted(returncode=0, stderr="Current Version: v9.9.9")

    monkeypatch.setattr(doctor_mod.shutil, "which", fake_which)
    monkeypatch.setattr(doctor_mod.subprocess, "run", fake_run)

    result = CliRunner().invoke(doctor, [], input="a\n")
    assert result.exit_code == 0
    assert len(install_calls) == 3   # one per tool, no per-tool prompts


def test_doctor_strategy_none_skips_every_tool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_calls: list[list[str]] = []

    def fake_which(binary: str):
        if binary == "go":
            return "/usr/bin/go"
        return None

    def fake_run(cmd, *a, **k):
        if isinstance(cmd, list) and cmd and cmd[0] == "go":
            install_calls.append(list(cmd))
            return FakeCompleted(returncode=0, stdout="ok")
        return FakeCompleted(returncode=0, stderr="")

    monkeypatch.setattr(doctor_mod.shutil, "which", fake_which)
    monkeypatch.setattr(doctor_mod.subprocess, "run", fake_run)

    # PATH stub returns ok via the autouse fixture, so only the
    # strategy prompt fires.
    result = CliRunner().invoke(doctor, [], input="n\n")
    assert result.exit_code == 0
    assert install_calls == []
    assert result.output.count("skipped") == 3


def test_doctor_offers_go_install_when_supported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If Go is missing AND the platform installer is available, doctor
    prompts to install Go before the tools step."""
    install_go_calls: list[bool] = []
    state = {"go_installed": False}

    def fake_which(binary: str):
        if binary == "go" and state["go_installed"]:
            return "/usr/bin/go"
        if binary == "go":
            return None
        return None

    def fake_install_go() -> tuple[bool, str]:
        install_go_calls.append(True)
        state["go_installed"] = True
        return True, "Go installed"

    monkeypatch.setattr(
        doctor_mod, "_go_installer_command", lambda: ["winget", "install", "go"]
    )
    monkeypatch.setattr(doctor_mod, "install_go", fake_install_go)
    monkeypatch.setattr(doctor_mod.shutil, "which", fake_which)
    monkeypatch.setattr(
        doctor_mod.subprocess,
        "run",
        lambda *a, **k: FakeCompleted(returncode=0, stderr=""),
    )

    # Decline Go install (and there are no other actionable items because
    # tools all "missing" + go_unresolved skips them).
    result = CliRunner().invoke(doctor, [], input="n\n")
    assert result.exit_code == 1
    assert install_go_calls == []
    assert "skipped Go install" in result.output


def test_doctor_yes_runs_go_install_then_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_go_calls: list[bool] = []
    install_tool_calls: list[list[str]] = []
    state = {"go_installed": False, "tools_installed": False}

    def fake_which(binary: str):
        if binary == "go":
            return "/usr/bin/go" if state["go_installed"] else None
        if state["tools_installed"]:
            return f"/usr/bin/{binary}"
        return None

    def fake_install_go() -> tuple[bool, str]:
        install_go_calls.append(True)
        state["go_installed"] = True
        return True, "Go installed"

    def fake_run(cmd, *a, **k):
        if isinstance(cmd, list) and cmd and cmd[0] == "go":
            state["tools_installed"] = True
            install_tool_calls.append(list(cmd))
            return FakeCompleted(returncode=0, stdout="ok")
        return FakeCompleted(returncode=0, stderr="Current Version: v9.9.9")

    monkeypatch.setattr(
        doctor_mod, "_go_installer_command", lambda: ["winget", "install", "go"]
    )
    monkeypatch.setattr(doctor_mod, "install_go", fake_install_go)
    monkeypatch.setattr(doctor_mod.shutil, "which", fake_which)
    monkeypatch.setattr(doctor_mod.subprocess, "run", fake_run)

    result = CliRunner().invoke(doctor, ["--yes"])
    assert result.exit_code == 0
    assert install_go_calls == [True]
    assert len(install_tool_calls) == 3


def test_doctor_no_go_flag_skips_go_offer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``--no-go`` keeps the Go-missing message but doesn't prompt."""
    install_go_calls: list[bool] = []

    monkeypatch.setattr(
        doctor_mod, "_go_installer_command", lambda: ["winget", "install", "go"]
    )
    monkeypatch.setattr(
        doctor_mod, "install_go", lambda: (install_go_calls.append(True), (True, "x"))[1]
    )
    monkeypatch.setattr(doctor_mod.shutil, "which", lambda b: None)
    monkeypatch.setattr(
        doctor_mod.subprocess,
        "run",
        lambda *a, **k: FakeCompleted(returncode=0, stderr=""),
    )

    result = CliRunner().invoke(doctor, ["--no-go"])
    assert result.exit_code == 1
    assert install_go_calls == []
    assert "https://go.dev/dl/" in result.output


def test_doctor_no_path_flag_suppresses_path_prompt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        doctor_mod,
        "check_path_status",
        lambda: PathStatus(state="needs_add", directory=r"C:\scripts", message="x"),
    )
    add_called: list[str] = []
    monkeypatch.setattr(
        doctor_mod, "add_directory_to_user_path", lambda d: (add_called.append(d), (True, "ok"))[1]
    )
    monkeypatch.setattr(doctor_mod.shutil, "which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr(
        doctor_mod.subprocess,
        "run",
        lambda *a, **k: FakeCompleted(returncode=0, stderr="Current Version: v9.9.9"),
    )

    result = CliRunner().invoke(doctor, ["--no-path", "--yes"])
    assert result.exit_code == 0
    assert add_called == []
    assert "Add C:\\scripts to User PATH" not in result.output


def test_doctor_no_tools_flag_suppresses_tool_prompts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(doctor_mod.shutil, "which", lambda b: None)
    install_attempts: list[object] = []

    def fake_run(cmd, *a, **k):
        if isinstance(cmd, list) and cmd and cmd[0] == "go":
            install_attempts.append(cmd)
        return FakeCompleted(returncode=0, stdout="")

    monkeypatch.setattr(doctor_mod.subprocess, "run", fake_run)

    result = CliRunner().invoke(doctor, ["--no-tools"])
    # Path is "ok" via the autouse stub, tools suppressed → nothing actionable.
    assert result.exit_code == 0
    assert install_attempts == []
    assert "All tools present and compatible" in result.output
