"""Smoke tests for ``csak collect`` and ``csak doctor`` CLI dispatch.

Heavy integration is in test_collect_pipeline.py; these tests just
verify the CLI dispatches correctly for the rejection paths.
"""
from __future__ import annotations

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
    assert "external tool" in result.output.lower()
