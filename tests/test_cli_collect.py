"""Smoke tests for ``csak collect`` and ``csak doctor`` CLI dispatch.

Heavy integration is in test_collect_pipeline.py; these tests just
verify the CLI dispatches correctly for the rejection paths.
"""
from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from csak.cli.main import main
from csak.storage import repository as repo
from csak.storage.db import connect


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    p = tmp_path / "csak.db"
    conn = connect(p)
    repo.create_org(conn, name="acme", slug="acme")
    conn.close()
    return p


def test_collect_rejects_invalid_target(tmp_path: Path, db_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--db",
            str(db_path),
            "--artifacts-dir",
            str(tmp_path / "artifacts"),
            "collect",
            "--org",
            "acme",
            "--target",
            "not-a-host",
        ],
    )
    assert result.exit_code != 0
    assert "not a valid" in result.output


def test_collect_rejects_unknown_org(tmp_path: Path, db_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--db",
            str(db_path),
            "--artifacts-dir",
            str(tmp_path / "artifacts"),
            "collect",
            "--org",
            "nope",
            "--target",
            "acme.com",
        ],
    )
    assert result.exit_code != 0
    assert "unknown org" in result.output


def test_collect_help_lists_overrides() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["collect", "--help"])
    assert result.exit_code == 0
    assert "--nuclei-templates" in result.output
    assert "--mode" in result.output


def test_doctor_help() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["doctor", "--help"])
    assert result.exit_code == 0
    output = result.output.lower()
    assert "--no-path" in output
    assert "--no-tools" in output


# ---------------------------------------------------------------------------
# Progress reporter — spec §Output format
# ---------------------------------------------------------------------------


def test_progress_reporter_eta_format() -> None:
    """ETA = elapsed × (100 - pct) / pct, formatted like ``27s`` / ``4m12s``."""
    from csak.cli.collect import _format_eta

    assert _format_eta(elapsed=10.0, percent=50) == "10s"
    assert _format_eta(elapsed=60.0, percent=20) == "4m00s"
    assert _format_eta(elapsed=10.0, percent=0) == "?"
    assert _format_eta(elapsed=10.0, percent=None) == "?"
    assert _format_eta(elapsed=10.0, percent=100) == "0s"


def test_progress_reporter_elapsed_format() -> None:
    from csak.cli.collect import _format_elapsed

    assert _format_elapsed(0.0) == "0s"
    assert _format_elapsed(7.4) == "7s"
    assert _format_elapsed(63.0) == "1m03s"
    assert _format_elapsed(245.0) == "4m05s"


def test_progress_reporter_falls_back_to_text_when_not_a_tty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When stdout isn't a tty (CI / pipe / harness), the reporter
    must NOT emit ANSI cursor controls — pipes mangle them. It should
    fall back to plain per-event text output."""
    from csak.cli.collect import ProgressReporter
    from csak.collect.runner import RunEvent
    from csak.collect.tool import ProgressUpdate
    import io

    monkeypatch.setattr("sys.stdout", io.StringIO())
    # io.StringIO has isatty() returning False, so the reporter
    # picks the plain-text path.
    reporter = ProgressReporter(verbose=False, quiet=False)
    assert reporter._render_bars is False  # plain-text path active

    reporter.handle_event(RunEvent(kind="started", tool="httpx", elapsed=0.0))
    reporter.handle_event(RunEvent(
        kind="completed", tool="httpx", elapsed=12.5, message="34 rows",
    ))
    out = sys.stdout.getvalue()  # type: ignore[attr-defined]
    # No ANSI escape characters in non-tty mode.
    assert "\x1b[" not in out
    assert "\r" not in out
    assert "starting" in out
    assert "done" in out
    assert "12s" in out


def test_progress_reporter_quiet_suppresses_progress() -> None:
    """``--quiet`` mode shows only failure / timeout / rate adjustments —
    not normal progress, completion or starts."""
    from csak.cli.collect import ProgressReporter
    from csak.collect.runner import RunEvent
    import io
    import sys

    buf = io.StringIO()
    saved = sys.stdout
    sys.stdout = buf
    try:
        reporter = ProgressReporter(verbose=False, quiet=True)
        reporter.handle_event(RunEvent(kind="started", tool="httpx", elapsed=0.0))
        reporter.handle_event(RunEvent(kind="completed", tool="httpx",
                                        elapsed=12.5, message="34 rows"))
        out = buf.getvalue()
    finally:
        sys.stdout = saved
    # Nothing leaks for routine progress events under --quiet.
    assert "starting" not in out
    assert "done" not in out
