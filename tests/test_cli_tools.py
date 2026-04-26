"""Smoke tests for ``csak tools list`` and ``csak tools show``."""
from __future__ import annotations

import pytest
from click.testing import CliRunner

from csak.cli.tools import tools as tools_group


def test_tools_list_shows_builtins() -> None:
    runner = CliRunner()
    result = runner.invoke(tools_group, ["list", "--no-plugins"])
    assert result.exit_code == 0, result.output
    assert "Built-in tools:" in result.output
    assert "subfinder" in result.output
    assert "httpx" in result.output
    assert "nuclei" in result.output


def test_tools_show_httpx_documents_accepts_and_produces() -> None:
    runner = CliRunner()
    result = runner.invoke(tools_group, ["show", "httpx", "--no-plugins"])
    assert result.exit_code == 0, result.output
    # httpx accepts host (widening covers domain/subdomain) and
    # network_block — the spec was reconciled to omit url.
    assert "host" in result.output
    assert "network_block" in result.output
    assert "url" in result.output  # appears under produces and matches list
    # Recursion graph section present.
    assert "Recursion graph" in result.output


def test_tools_show_unknown_tool_errors() -> None:
    runner = CliRunner()
    result = runner.invoke(tools_group, ["show", "nonexistent", "--no-plugins"])
    assert result.exit_code != 0
    assert "unknown tool" in result.output.lower()


def test_tools_show_subfinder_strict_accepts_domain() -> None:
    runner = CliRunner()
    result = runner.invoke(tools_group, ["show", "subfinder", "--no-plugins"])
    assert result.exit_code == 0, result.output
    # subfinder strictly accepts ``domain`` — its widening notation
    # should NOT include subdomain (subdomain widens to host, not the
    # other way).
    accepts_section = result.output.split("Accepts:")[1].split("Produces:")[0]
    assert "domain" in accepts_section
