"""One-shot setup: install csak in editable mode, then run ``csak doctor``.

Why this exists: PEP 517 wheel installs don't run a post-install
hook, so we can't make ``pip install`` itself add csak's Scripts
directory to the user's PATH or install the external tool
binaries. Running this script is the supported "one command"
that does both — pip install first, then ``csak doctor``, which
prompts for Go install, PATH update, and each tool.

Usage::

    python bootstrap.py
"""
from __future__ import annotations

import itertools
import shutil as _shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

# Force UTF-8 so success/skip glyphs round-trip through pipes on Windows.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass

REPO_ROOT = Path(__file__).resolve().parent
SPINNER_FRAMES = ("|", "/", "-", "\\")


def _term_width() -> int:
    try:
        return _shutil.get_terminal_size((80, 20)).columns
    except OSError:
        return 80


def _run_with_spinner(cmd: list[str], cwd: str) -> tuple[int, list[str]]:
    """Run ``cmd``, streaming its latest stdout line as a spinner status.

    Returns ``(returncode, captured_lines)``. Caller decides what to
    do with the captured output — typically: silent on success, dump
    on failure.
    """
    process = subprocess.Popen(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        encoding="utf-8",
        errors="replace",
    )
    captured: list[str] = []
    state = {"latest": "starting…"}
    stop = threading.Event()

    def spin() -> None:
        max_msg = max(20, _term_width() - 6)
        for ch in itertools.cycle(SPINNER_FRAMES):
            if stop.is_set():
                break
            msg = state["latest"]
            if len(msg) > max_msg:
                msg = msg[: max_msg - 1] + "…"
            sys.stdout.write(f"\r  {ch} {msg.ljust(max_msg)}")
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write("\r" + " " * (max_msg + 6) + "\r")
        sys.stdout.flush()

    spinner_thread = threading.Thread(target=spin, daemon=True)
    spinner_thread.start()
    try:
        assert process.stdout is not None
        for raw in process.stdout:
            line = raw.rstrip()
            captured.append(line)
            if line.strip():
                state["latest"] = line.strip()
    finally:
        rc = process.wait()
        stop.set()
        spinner_thread.join()

    return rc, captured


def main() -> int:
    print(f"Step 1/2: installing csak from {REPO_ROOT} (editable mode)...")
    rc, lines = _run_with_spinner(
        [sys.executable, "-m", "pip", "install", "-e", ".[dev]"],
        cwd=str(REPO_ROOT),
    )
    if rc != 0:
        # Failure path: surface the full pip output so the user can see
        # what went wrong.
        for line in lines:
            print(line)
        print("\npip install failed; aborting bootstrap.", file=sys.stderr)
        return rc

    summary = next(
        (ln for ln in reversed(lines) if ln.startswith("Successfully installed")),
        "csak installed",
    )
    print(f"  ✓ {summary}")

    print(
        "\nStep 2/2: running csak doctor — you'll be prompted for Go "
        "install, PATH update, and each tool.\n"
    )
    return subprocess.call([sys.executable, "-m", "csak", "doctor"])


if __name__ == "__main__":
    raise SystemExit(main())
