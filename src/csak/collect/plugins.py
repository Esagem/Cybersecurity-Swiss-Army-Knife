"""Plugin discovery — slice 3.

Imports every ``*.py`` file in the analyst's plugin directory (default
``~/.csak/tools/``) at startup. Each plugin is a Python module that
calls ``register_type`` and/or ``register_tool`` to extend the
toolbox. There is no metadata format and no entry-point convention —
the file's import-time side effects ARE the registration.

Slice 3 takes the "trust the analyst's plugin choice" posture
explicitly: plugins run as full Python under the analyst's user
permissions, no sandbox. ``csak doctor`` validates plugin discovery
and reports collisions / cycles / missing references; one broken
plugin shouldn't take CSAK down, so loading is fail-soft — the failure
is recorded as a warning and the run continues with the remaining
tools.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import traceback
from dataclasses import dataclass, field
from pathlib import Path

from csak.collect.tools import register_tool


def default_plugin_dir() -> Path:
    """The convention is ``~/.csak/tools/``. Override via the
    ``CSAK_PLUGIN_DIR`` environment variable for testing or for a
    multi-user shared install.
    """
    env = os.environ.get("CSAK_PLUGIN_DIR")
    if env:
        return Path(env)
    return Path.home() / ".csak" / "tools"


@dataclass
class PluginLoadReport:
    """Outcome of one ``load_plugins`` call.

    ``loaded`` is the list of (module_name, source_path) pairs that
    imported successfully. ``warnings`` is human-readable strings,
    typically "couldn't import X: <error>"; the CLI prints them.
    """

    plugin_dir: Path
    loaded: list[tuple[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def load_plugins(plugin_dir: Path | None = None) -> PluginLoadReport:
    """Import every ``*.py`` in ``plugin_dir`` and run its top level.

    Returns a report describing what loaded and what failed. Plugin
    files are imported in lexical order so the registration order is
    stable across runs.
    """
    plugin_dir = plugin_dir or default_plugin_dir()
    report = PluginLoadReport(plugin_dir=plugin_dir)
    if not plugin_dir.exists():
        return report
    if not plugin_dir.is_dir():
        report.warnings.append(
            f"plugin path {plugin_dir} exists but is not a directory; skipped"
        )
        return report

    for path in sorted(plugin_dir.glob("*.py")):
        if path.name.startswith("_"):
            continue
        module_name = f"csak_plugin_{path.stem}"
        try:
            _import_plugin(module_name, path)
        except Exception as e:  # pragma: no cover - exercised via tests
            report.warnings.append(
                f"plugin {path.name!r} failed to load: {e}"
            )
            # Drop a partially-loaded module out of sys.modules so a
            # subsequent ``csak doctor`` call gets a fresh import.
            sys.modules.pop(module_name, None)
            continue
        report.loaded.append((module_name, str(path)))

    return report


def _import_plugin(module_name: str, path: Path) -> None:
    """Spec-compliant import of a single plugin file.

    The module is registered in ``sys.modules`` so any relative
    ``from csak.collect.plugins import ...`` inside the plugin works
    (rare, but cheap to support).

    A plugin that defines ``CSAK_TOOLS`` at module level — a list of
    Tool instances — gets each one registered automatically. Plugins
    that prefer to call ``register_tool`` directly do so in their
    module body and we skip the hook.
    """
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not build importer spec for {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)  # type: ignore[union-attr]
    except Exception:
        # Re-raise with a tidied traceback for the warning string.
        raise RuntimeError(traceback.format_exc(limit=3).strip().splitlines()[-1])

    # Optional convenience hook: ``CSAK_TOOLS`` at module level.
    tools = getattr(module, "CSAK_TOOLS", None)
    if tools:
        for tool in tools:
            register_tool(tool, origin="plugin", source_path=str(path))
