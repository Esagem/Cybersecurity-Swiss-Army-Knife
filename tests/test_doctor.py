"""Tests for the ``csak doctor`` checker.

The check_tool path uses ``shutil.which`` and ``subprocess.run``. Both
are monkeypatched here so the test never depends on whether
subfinder/httpx/nuclei are actually installed on the test host.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass

import pytest
from click.testing import CliRunner

from csak.cli import doctor as doctor_mod
from csak.cli.doctor import (
    _parse_version_tuple,
    _version_lt,
    check_tool,
    doctor,
    install_tool,
)
from csak.collect.tools.subfinder import SUBFINDER


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


def test_doctor_cli_lists_missing_and_aborts_without_yes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(doctor_mod.shutil, "which", lambda b: None)
    result = CliRunner().invoke(doctor, [], input="n\n")
    assert result.exit_code == 1
    assert "not found on PATH" in result.output


def test_doctor_cli_yes_runs_install(monkeypatch: pytest.MonkeyPatch) -> None:
    # First subprocess.run call (for check_tool) returns missing-version
    # output — but actually the missing case comes from `shutil.which`
    # returning None. So we control behavior via which() flipping after
    # install: before install → None; after install → "/path".
    state = {"installed": False}

    def fake_which(binary: str):
        if state["installed"]:
            return f"/usr/bin/{binary}"
        return None

    def fake_run(cmd, *a, **k):
        # Two kinds of calls:
        #   * the install command (`go install ...@latest`)
        #   * the post-install version check
        if isinstance(cmd, list) and cmd and cmd[0] == "go":
            state["installed"] = True
            return FakeCompleted(returncode=0, stdout="ok")
        return FakeCompleted(returncode=0, stderr="Current Version: v9.9.9")

    monkeypatch.setattr(doctor_mod.shutil, "which", fake_which)
    monkeypatch.setattr(doctor_mod.subprocess, "run", fake_run)

    result = CliRunner().invoke(doctor, ["--yes"])
    assert result.exit_code == 0
    assert "installing" in result.output
