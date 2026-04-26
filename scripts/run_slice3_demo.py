"""End-to-end slice 3 demo: spin up the recursive test target, run
``csak collect --recurse``, and surface what makes slice 3 interesting.

What you see:

  1. ``csak doctor`` output — slice 3 sections (plugin tools, type
     registry, recursion graph orphan check).
  2. ``csak tools list`` and ``csak tools show linkfinder`` — the live
     toolbox including the plugin we just loaded.
  3. ``csak collect --recurse --max-depth=3 --target 127.0.0.1:8080``
     — depth-aware live output, frontier counts, prompt-to-continue.
  4. ``csak scan list`` — depth column populated for recursion-spawned
     scans; ``parent_scan_id`` and ``triggered_by_finding_id`` visible.

The demo runs everything in a fresh tmp directory so it never
clobbers an existing CSAK database. Pass ``--keep`` to leave the
artefacts on disk for inspection.

Bound to 127.0.0.1 only.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from tempfile import mkdtemp


REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_DIR = REPO_ROOT / "scripts" / "csak_plugins"


def _section(title: str) -> None:
    bar = "=" * len(title)
    print(f"\n\n{bar}\n{title}\n{bar}")


def _run(argv: list[str], env: dict[str, str], *, check: bool = False) -> int:
    """Run a subprocess and tee its output to this terminal."""
    print(f"\n$ {' '.join(argv)}")
    r = subprocess.run(argv, env=env)
    if check and r.returncode != 0:
        print(f"  (exit {r.returncode})")
    return r.returncode


def _start_target(ports: list[int]) -> subprocess.Popen:
    """Launch the test target as a child process so we can clean it up."""
    target_script = REPO_ROOT / "scripts" / "test_target_recurse.py"
    proc = subprocess.Popen(
        [sys.executable, str(target_script), "--ports", ",".join(map(str, ports))],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # Give the threads a moment to bind their listeners.
    time.sleep(0.5)
    return proc


def _wait_for(host: str, port: int, attempts: int = 20) -> bool:
    import socket

    for _ in range(attempts):
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--max-depth", type=int, default=3,
                    help="Recursion depth ceiling for the collect run.")
    ap.add_argument("--mode", default="standard",
                    choices=("quick", "standard", "deep"))
    ap.add_argument("--keep", action="store_true",
                    help="Leave the demo db / artifacts on disk after the run.")
    ap.add_argument("--no-target", action="store_true",
                    help="Skip starting the test target (you've started it yourself).")
    ap.add_argument("--port", type=int, default=8080,
                    help="App port the test target binds (also passed to --target).")
    ap.add_argument(
        "--target",
        default=None,
        help="Override the --target passed to csak collect. Defaults to "
             "http://127.0.0.1:<port>/ so the URL form works on any port.",
    )
    args = ap.parse_args()

    workdir = Path(mkdtemp(prefix="csak-slice3-demo-"))
    db = workdir / "csak.db"
    artifacts = workdir / "artifacts"

    env = os.environ.copy()
    env["CSAK_PLUGIN_DIR"] = str(PLUGIN_DIR)
    # Editable installs put csak on PYTHONPATH; respect what's there
    # so a worktree without ``pip install -e`` still works.
    src = REPO_ROOT / "src"
    if src.exists():
        existing = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = (
            f"{src}{os.pathsep}{existing}" if existing else str(src)
        )

    csak_argv = [
        sys.executable, "-m", "csak",
        "--db", str(db),
        "--artifacts-dir", str(artifacts),
    ]

    target_proc: subprocess.Popen | None = None
    try:
        if not args.no_target:
            _section("Starting test target on 127.0.0.1")
            target_proc = _start_target([args.port, args.port + 1, 8443])
            if not _wait_for("127.0.0.1", args.port):
                print(f"  ERROR: nothing listening on 127.0.0.1:{args.port}")
                return
            print(f"  app listening on http://127.0.0.1:{args.port}")
            print(f"  admin listening on http://127.0.0.1:{args.port + 1}")
            print(f"  api listening on http://127.0.0.1:8443")

        _section("csak doctor — slice 3 sections")
        _run(csak_argv + ["doctor", "--no-go", "--no-tools", "--no-path"], env)

        _section("csak tools list — built-ins + plugins")
        _run(csak_argv + ["tools", "list"], env)

        _section("csak tools show linkfinder — recursion graph")
        _run(csak_argv + ["tools", "show", "linkfinder"], env)

        _section("csak tools show httpx — upstream now includes plugins")
        _run(csak_argv + ["tools", "show", "httpx"], env)

        _section("Setup: create demo org")
        _run(csak_argv + ["org", "create", "demo", "--slug", "demo"], env)

        target = args.target or f"http://127.0.0.1:{args.port}/"
        _section(
            f"csak collect --recurse --max-depth={args.max_depth} "
            f"--target {target}"
        )
        _run(csak_argv + [
            "collect",
            "--org", "demo",
            "--target", target,
            "--mode", args.mode,
            "--recurse",
            "--max-depth", str(args.max_depth),
            "--yes",
        ], env)

        _section("csak scan list — depth column populated")
        # ``scan list`` doesn't yet print the depth column in slice 3
        # (the slice 2 listing is unchanged). Read the rows directly
        # so the demo highlights the new lineage state.
        _run(
            [sys.executable, "-c", _SCAN_LINEAGE_SNIPPET, str(db)],
            env,
        )

        _section("csak findings list — surfaced findings")
        _run(csak_argv + ["findings", "list", "--org", "demo"], env)

    finally:
        if target_proc is not None:
            target_proc.terminate()
            try:
                target_proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                target_proc.kill()
        if not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)
        else:
            print(f"\n  workdir kept at {workdir}")


# Inline script the demo runs to dump the new Scan lineage columns.
# Lives as a string so the demo can be a single self-contained file.
_SCAN_LINEAGE_SNIPPET = """
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
db.row_factory = sqlite3.Row
print(f"  {'TOOL':<10}  {'DEPTH':<5}  {'PARENT':<10}  {'TRIGGER':<10}  STATUS  NOTES")
for r in db.execute(
    "SELECT source_tool, depth, parent_scan_id, triggered_by_finding_id, notes "
    "FROM scans ORDER BY scan_started_at"
).fetchall():
    parent = (r['parent_scan_id'] or '-')[:8]
    trig = (r['triggered_by_finding_id'] or '-')[:8]
    status = 'skip' if 'skipped' in r['notes'] else (
        'fail' if 'status=failed' in r['notes'] or 'status=timeout' in r['notes']
        else 'run'
    )
    notes = r['notes'][:60].replace(chr(10), ' ')
    print(f"  {r['source_tool']:<10}  {r['depth']:<5}  {parent:<10}  {trig:<10}  {status:<6}  {notes}")
"""


if __name__ == "__main__":
    main()
