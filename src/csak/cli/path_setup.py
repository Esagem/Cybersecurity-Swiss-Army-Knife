"""Detect whether the directory holding the ``csak`` console
script is on the user's PATH and, with permission, persist it.

A fresh ``pip install --user`` on Windows places ``csak.exe`` in
``%APPDATA%\\Python\\PythonNN\\Scripts`` — a directory that isn't
on the default User PATH, so ``csak`` is not callable as a bare
command afterwards. ``csak doctor`` uses this module to detect
the gap and (with consent) append the directory to the persisted
User PATH via the Windows registry.

On non-Windows platforms shell-rc files are too varied to edit
safely, so we return a copy-pasteable hint instead.
"""
from __future__ import annotations

import os
import shutil
import sysconfig
from dataclasses import dataclass
from pathlib import Path

SCRIPT_NAME = "csak"

# PATH as it was when this module was first imported. Used by
# ``is_directory_persisted_on_user_path`` on non-Windows to answer
# "would this directory be on PATH in a fresh shell?" without being
# fooled by mutations the same Python process makes via
# ``os.environ['PATH'] = …`` (e.g. doctor's _extend_live_path_for_go).
_ORIGINAL_PATH_AT_IMPORT: str = os.environ.get("PATH", "")


@dataclass
class PathStatus:
    state: str  # "ok" | "needs_add" | "unknown"
    directory: str | None
    message: str


def find_script_directory() -> str | None:
    """Return the directory containing the ``csak`` console script.

    Tries the live PATH first, then falls back to ``sysconfig`` so
    we can locate the script even when it isn't on PATH (the case
    we're trying to fix). Returns ``None`` if no copy is found.
    """
    found = shutil.which(SCRIPT_NAME)
    if found:
        return str(Path(found).resolve().parent)

    exe_name = f"{SCRIPT_NAME}.exe" if os.name == "nt" else SCRIPT_NAME
    for scheme in _candidate_schemes():
        try:
            scripts_dir = sysconfig.get_path("scripts", scheme)
        except KeyError:
            continue
        if not scripts_dir:
            continue
        if (Path(scripts_dir) / exe_name).is_file():
            return str(Path(scripts_dir).resolve())
    return None


def _candidate_schemes() -> list[str]:
    schemes = [sysconfig.get_default_scheme()]
    user_scheme = f"{os.name}_user"
    if user_scheme not in schemes:
        schemes.append(user_scheme)
    return schemes


def is_directory_on_user_path(directory: str) -> bool:
    """Whether ``directory`` is on the user's PATH (persisted or live).

    On Windows we read ``HKCU\\Environment\\Path`` directly so we
    see the persisted value, not just the current process's env
    (which may have been launched before a recent change).
    """
    target = _normalize(directory)
    candidates: list[str] = []
    if os.name == "nt":
        candidates.extend(_read_windows_user_path())
    candidates.extend(_split_path_string(os.environ.get("PATH", "")))
    return any(_normalize(p) == target for p in candidates)


def is_directory_persisted_on_user_path(directory: str) -> bool:
    """Whether ``directory`` will be on PATH in a *fresh* shell.

    Unlike :func:`is_directory_on_user_path` this ignores in-process
    mutations to ``os.environ['PATH']``. On Windows we read only the
    registry; on POSIX we consult the PATH that was present when this
    module was first imported (a best-effort proxy for what shell rc
    files contributed). Use this for "do we need to persist it?"
    decisions where a transient live-PATH entry would mislead.
    """
    target = _normalize(directory)
    if os.name == "nt":
        candidates = _read_windows_user_path()
    else:
        candidates = _split_path_string(_ORIGINAL_PATH_AT_IMPORT)
    return any(_normalize(p) == target for p in candidates)


def add_directory_to_user_path(directory: str) -> tuple[bool, str]:
    """Persist ``directory`` onto the user's PATH. ``(ok, message)``.

    Windows: append to ``HKCU\\Environment\\Path`` and broadcast
    ``WM_SETTINGCHANGE`` so newly spawned shells inherit it. The
    caller's current shell will not see the new PATH until restarted.

    Non-Windows: return ``(False, hint)`` — the right rc file
    (``.bashrc``, ``.zshrc``, ``.profile``, …) depends on shell and
    login type, so we don't auto-edit.
    """
    if os.name == "nt":
        return _add_to_windows_user_path(directory)
    line = f'export PATH="$PATH:{directory}"'
    return False, (
        "automatic PATH edit is only supported on Windows; "
        f"add this line to your shell rc file (e.g. ~/.bashrc):\n    {line}"
    )


def check_path_status() -> PathStatus:
    """High-level summary of where csak's script dir is and whether it's reachable."""
    directory = find_script_directory()
    if directory is None:
        return PathStatus(
            state="unknown",
            directory=None,
            message=f"could not locate the {SCRIPT_NAME} script directory",
        )
    if is_directory_on_user_path(directory):
        return PathStatus(
            state="ok",
            directory=directory,
            message=f"{SCRIPT_NAME} script directory on PATH: {directory}",
        )
    return PathStatus(
        state="needs_add",
        directory=directory,
        message=f"{SCRIPT_NAME} script directory not on User PATH: {directory}",
    )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _normalize(p: str) -> str:
    return os.path.normcase(os.path.normpath(p.strip()))


def _split_path_string(value: str) -> list[str]:
    return [part for part in value.split(os.pathsep) if part.strip()]


def _read_windows_user_path() -> list[str]:
    try:
        import winreg  # type: ignore[import-not-found]
    except ImportError:
        return []
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
            value, _ = winreg.QueryValueEx(key, "Path")
    except (FileNotFoundError, OSError):
        return []
    return _split_path_string(str(value))


def _add_to_windows_user_path(directory: str) -> tuple[bool, str]:
    try:
        import winreg  # type: ignore[import-not-found]
    except ImportError:
        return False, "winreg unavailable on this platform"

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            "Environment",
            0,
            winreg.KEY_READ | winreg.KEY_WRITE,
        ) as key:
            try:
                current, kind = winreg.QueryValueEx(key, "Path")
            except FileNotFoundError:
                current, kind = "", winreg.REG_EXPAND_SZ
            current_str = str(current) if current else ""
            # User PATH is conventionally REG_EXPAND_SZ; preserve a
            # pre-existing string type, otherwise default to expand.
            if kind not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
                kind = winreg.REG_EXPAND_SZ

            target = _normalize(directory)
            if any(_normalize(p) == target for p in _split_path_string(current_str)):
                return True, f"{directory} was already on User PATH"

            new_value = (
                current_str + os.pathsep + directory if current_str else directory
            )
            winreg.SetValueEx(key, "Path", 0, kind, new_value)
    except OSError as e:
        return False, f"failed to update User PATH in registry: {e}"

    _broadcast_environment_change()
    return True, (
        f"added {directory} to User PATH "
        "(open a new terminal for the change to take effect)"
    )


def _broadcast_environment_change() -> None:
    """Notify other processes that the environment changed. Best-effort."""
    try:
        import ctypes

        HWND_BROADCAST = 0xFFFF
        WM_SETTINGCHANGE = 0x001A
        SMTO_ABORTIFHUNG = 0x0002

        result = ctypes.c_long()
        ctypes.windll.user32.SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            "Environment",
            SMTO_ABORTIFHUNG,
            5000,
            ctypes.byref(result),
        )
    except Exception:
        pass
