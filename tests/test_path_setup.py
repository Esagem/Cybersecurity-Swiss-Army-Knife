"""Tests for the PATH-setup helpers used by ``csak doctor``.

These exercise the OS-agnostic logic (locate, normalize, decide
whether persisted PATH already contains the directory) without
touching the real Windows registry or the user's environment.
"""
from __future__ import annotations

import os
import sysconfig
from pathlib import Path

import pytest

from csak.cli import path_setup as ps


def test_split_path_string_filters_empty_and_whitespace_only() -> None:
    sample = f"a{os.pathsep}{os.pathsep}b{os.pathsep} {os.pathsep}c"
    assert ps._split_path_string(sample) == ["a", "b", "c"]


def test_normalize_collapses_case_and_separators() -> None:
    a = ps._normalize(r"C:\Foo\Bar")
    b = ps._normalize("C:/Foo/Bar/")
    if os.name == "nt":
        assert a == b
    else:
        # POSIX is case-sensitive; the helper still strips trailing
        # separators and whitespace.
        assert ps._normalize("/foo/bar/") == ps._normalize("/foo/bar")


def test_find_script_directory_uses_which_when_available(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    fake_exe = tmp_path / ("csak.exe" if os.name == "nt" else "csak")
    fake_exe.write_text("")
    monkeypatch.setattr(ps.shutil, "which", lambda name: str(fake_exe))

    result = ps.find_script_directory()
    assert result == str(tmp_path.resolve())


def test_find_script_directory_falls_back_to_sysconfig(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setattr(ps.shutil, "which", lambda name: None)
    exe_name = "csak.exe" if os.name == "nt" else "csak"
    (tmp_path / exe_name).write_text("")

    def fake_get_path(key: str, scheme: str | None = None) -> str:
        assert key == "scripts"
        return str(tmp_path)

    monkeypatch.setattr(sysconfig, "get_path", fake_get_path)
    monkeypatch.setattr(sysconfig, "get_default_scheme", lambda: "posix_prefix")

    result = ps.find_script_directory()
    assert result == str(tmp_path.resolve())


def test_find_script_directory_returns_none_when_not_installed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setattr(ps.shutil, "which", lambda name: None)
    monkeypatch.setattr(sysconfig, "get_path", lambda *a, **k: str(tmp_path))
    monkeypatch.setattr(sysconfig, "get_default_scheme", lambda: "posix_prefix")
    assert ps.find_script_directory() is None


def test_is_directory_on_user_path_yes_via_environ(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = "/some/scripts/dir"
    monkeypatch.setenv("PATH", f"/usr/bin{os.pathsep}{target}{os.pathsep}/bin")
    monkeypatch.setattr(ps, "_read_windows_user_path", lambda: [])
    assert ps.is_directory_on_user_path(target)


def test_is_directory_on_user_path_no(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setattr(ps, "_read_windows_user_path", lambda: [])
    assert not ps.is_directory_on_user_path("/some/scripts/dir")


def test_is_directory_on_user_path_yes_via_windows_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = r"C:\Tools\Scripts"
    monkeypatch.setenv("PATH", "")
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(ps, "_read_windows_user_path", lambda: [target])
    assert ps.is_directory_on_user_path(target)


def test_is_directory_persisted_on_user_path_ignores_live_path_mutations_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A directory that is on the live ``os.environ['PATH']`` but
    NOT in the registry should not count as persisted."""
    target = r"C:\Users\u\go\bin"
    monkeypatch.setenv("PATH", target)            # live PATH only
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(ps, "_read_windows_user_path", lambda: [])  # registry empty
    assert ps.is_directory_on_user_path(target)               # live counts → True
    assert not ps.is_directory_persisted_on_user_path(target) # registry empty → False


def test_is_directory_persisted_on_user_path_yes_when_in_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = r"C:\Users\u\go\bin"
    monkeypatch.setenv("PATH", "")
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(ps, "_read_windows_user_path", lambda: [target])
    assert ps.is_directory_persisted_on_user_path(target)


def test_is_directory_persisted_on_user_path_uses_original_path_on_posix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On POSIX we fall back to the PATH at module import time so we're
    not fooled by ``os.environ['PATH']`` mutations made during the run."""
    monkeypatch.setattr(os, "name", "posix")
    original = os.pathsep.join(["/usr/bin", "/usr/local/bin"])
    mutated = os.pathsep.join(["/home/u/go/bin", "/usr/bin"])
    monkeypatch.setattr(ps, "_ORIGINAL_PATH_AT_IMPORT", original)
    monkeypatch.setenv("PATH", mutated)  # mutated mid-run

    assert ps.is_directory_persisted_on_user_path("/usr/local/bin")
    assert not ps.is_directory_persisted_on_user_path("/home/u/go/bin")


def test_check_path_status_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ps, "find_script_directory", lambda: "/foo/bin")
    monkeypatch.setattr(ps, "is_directory_on_user_path", lambda d: True)
    status = ps.check_path_status()
    assert status.state == "ok"
    assert status.directory == "/foo/bin"


def test_check_path_status_needs_add(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ps, "find_script_directory", lambda: "/foo/bin")
    monkeypatch.setattr(ps, "is_directory_on_user_path", lambda d: False)
    status = ps.check_path_status()
    assert status.state == "needs_add"
    assert status.directory == "/foo/bin"


def test_check_path_status_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ps, "find_script_directory", lambda: None)
    status = ps.check_path_status()
    assert status.state == "unknown"
    assert status.directory is None


@pytest.mark.skipif(os.name == "nt", reason="POSIX-only message")
def test_add_directory_to_user_path_posix_returns_hint() -> None:
    ok, msg = ps.add_directory_to_user_path("/some/dir")
    assert ok is False
    assert "shell rc" in msg
    assert "/some/dir" in msg
