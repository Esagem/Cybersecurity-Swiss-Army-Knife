"""Slice 3 plugin discovery tests.

A real plugin file is dropped into a tmp directory, ``CSAK_PLUGIN_DIR``
is pointed at it, and ``load_plugins`` is invoked. We assert on the
runtime registry state — both for the success path and for fail-soft
handling of a broken plugin.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from csak.collect.plugins import load_plugins
from csak.collect.tools import ALL_TOOLS, get_tool, reset_tools_for_tests


@pytest.fixture
def plugin_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    d = tmp_path / "plugins"
    d.mkdir()
    monkeypatch.setenv("CSAK_PLUGIN_DIR", str(d))
    return d


@pytest.fixture(autouse=True)
def restore_tools(monkeypatch: pytest.MonkeyPatch):
    """Snapshot/restore the tool registry around each test so we don't
    leak plugin tools into other test files.
    """
    snapshot = list(ALL_TOOLS)
    yield
    reset_tools_for_tests()
    for t in snapshot:
        from csak.collect.tools import register_tool
        register_tool(t, origin=t.origin, source_path=t.source_path)


def test_load_plugin_registers_tool(plugin_dir: Path) -> None:
    plugin_path = plugin_dir / "fakeplug.py"
    plugin_path.write_text(
        "from csak.collect.tool import Tool\n"
        "from csak.collect.tools import register_tool\n"
        "class FakeTool(Tool):\n"
        "    name = 'fakeplug'\n"
        "    binary = 'fakeplug'\n"
        "    accepts = ['url']\n"
        "    produces = []\n"
        "register_tool(FakeTool(), origin='plugin', source_path=__file__)\n",
        encoding="utf-8",
    )

    report = load_plugins(plugin_dir)

    assert report.warnings == []
    tool = get_tool("fakeplug")
    assert tool is not None
    assert tool.origin == "plugin"
    assert tool.accepts == ["url"]


def test_csak_tools_hook_registers_each(plugin_dir: Path) -> None:
    """Plugins that prefer ``CSAK_TOOLS = [...]`` get auto-registered."""
    plugin_path = plugin_dir / "viahook.py"
    plugin_path.write_text(
        "from csak.collect.tool import Tool\n"
        "class A(Tool):\n"
        "    name = 'plug_a'\n"
        "    binary = 'plug_a'\n"
        "    accepts = []\n"
        "    produces = []\n"
        "class B(Tool):\n"
        "    name = 'plug_b'\n"
        "    binary = 'plug_b'\n"
        "    accepts = []\n"
        "    produces = []\n"
        "CSAK_TOOLS = [A(), B()]\n",
        encoding="utf-8",
    )

    load_plugins(plugin_dir)

    assert get_tool("plug_a") is not None
    assert get_tool("plug_b") is not None
    assert get_tool("plug_a").origin == "plugin"


def test_broken_plugin_is_warned_not_raised(plugin_dir: Path) -> None:
    """A plugin with a syntax error must not take CSAK down."""
    (plugin_dir / "broken.py").write_text(
        "this is not valid python ::: !!\n",
        encoding="utf-8",
    )
    (plugin_dir / "good.py").write_text(
        "from csak.collect.tool import Tool\n"
        "from csak.collect.tools import register_tool\n"
        "class GoodTool(Tool):\n"
        "    name = 'goodplug'\n"
        "    binary = 'goodplug'\n"
        "    accepts = []\n"
        "    produces = []\n"
        "register_tool(GoodTool(), origin='plugin', source_path=__file__)\n",
        encoding="utf-8",
    )

    report = load_plugins(plugin_dir)

    assert any("broken.py" in w for w in report.warnings)
    # The good plugin still loaded.
    assert get_tool("goodplug") is not None


def test_underscore_prefixed_files_skipped(plugin_dir: Path) -> None:
    (plugin_dir / "_helper.py").write_text(
        "raise RuntimeError('should not import')\n",
        encoding="utf-8",
    )
    report = load_plugins(plugin_dir)
    assert report.warnings == []
    assert report.loaded == []


def test_missing_plugin_dir_is_silent(tmp_path: Path) -> None:
    """No plugin dir = no plugins, no warnings."""
    missing = tmp_path / "does-not-exist"
    report = load_plugins(missing)
    assert report.warnings == []
    assert report.loaded == []


def test_collect_refuses_when_plugin_has_unknown_type(
    plugin_dir: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Per spec §Type registry validation: ``csak collect`` exits with
    a clear error if a plugin's accepts/produces references unknown
    types. The validation runs before any tool executes.
    """
    from click.testing import CliRunner

    from csak.cli.collect import collect as collect_cmd
    from csak.storage.db import connect
    from csak.storage import repository as repo

    (plugin_dir / "bad.py").write_text(
        "from csak.collect.tool import Tool\n"
        "from csak.collect.tools import register_tool\n"
        "class Bad(Tool):\n"
        "    name = 'badtool'\n"
        "    binary = 'badtool'\n"
        "    accepts = ['nonexistent_type']\n"
        "    produces = []\n"
        "register_tool(Bad(), origin='plugin', source_path=__file__)\n",
        encoding="utf-8",
    )

    db_path = tmp_path / "csak.db"
    artifacts = tmp_path / "art"
    artifacts.mkdir()
    conn = connect(db_path)
    repo.create_org(conn, name="acme", slug="acme")
    conn.close()

    runner = CliRunner()
    result = runner.invoke(
        collect_cmd,
        ["--org", "acme", "--target", "acme.com"],
        obj={"db_path": str(db_path), "artifacts_dir": str(artifacts),
             "reports_dir": str(tmp_path / "rpts")},
    )
    assert result.exit_code != 0
    assert "registry error" in result.output.lower()
    assert "nonexistent_type" in result.output
