"""Per-tool catalog modules.

Each module under here defines exactly one ``Tool`` subclass and an
instance singleton. The list ``ALL_TOOLS`` is the canonical ordered
set used by the router and the doctor command — built-ins are
registered at import; plugin tools join the same list at startup via
``csak.collect.plugins`` calling ``register_tool``.

Order matters within the slice 2 cascade: subfinder → httpx → nuclei.
Plugins append after the built-ins; the router decides what runs based
on each tool's ``accepts`` declaration, so order only matters when the
recursion graph is symmetric and we need a stable tie-breaker.
"""
from __future__ import annotations

from csak.collect.tool import Tool


# Runtime tool registry. Mutated by ``register_tool`` (called both for
# built-ins below and plugins discovered later); ordering follows
# registration order so the slice 2 cascade still runs in the canonical
# subfinder → httpx → nuclei order.
ALL_TOOLS: list[Tool] = []
_BY_NAME: dict[str, Tool] = {}


def register_tool(tool: Tool, *, origin: str = "builtin", source_path: str | None = None) -> None:
    """Add a tool instance to the runtime registry.

    Plugins call this from their import-time setup; built-ins are
    registered below as a side effect of importing this module.
    Re-registering a name replaces the previous entry — useful for
    reloading a plugin during development; the built-ins always
    register first so a plugin can intentionally shadow one (the
    ``csak doctor`` plugin-collision check surfaces this so the
    analyst sees what's loaded).
    """
    tool.origin = origin
    tool.source_path = source_path
    if tool.name in _BY_NAME:
        # Replace in place to preserve registration order.
        existing = _BY_NAME[tool.name]
        idx = ALL_TOOLS.index(existing)
        ALL_TOOLS[idx] = tool
    else:
        ALL_TOOLS.append(tool)
    _BY_NAME[tool.name] = tool


def get_tool(name: str) -> Tool | None:
    return _BY_NAME.get(name)


def reset_tools_for_tests() -> None:
    """Clear the tool registry. **Tests only.**"""
    ALL_TOOLS.clear()
    _BY_NAME.clear()


# Importing each catalog module creates the singleton; ``register_tool``
# attaches it to ``ALL_TOOLS``. Keep the import order — it dictates the
# slice 2 cascade subfinder → httpx → nuclei.
from csak.collect.tools.subfinder import SUBFINDER  # noqa: E402
from csak.collect.tools.httpx import HTTPX  # noqa: E402
from csak.collect.tools.nuclei import NUCLEI  # noqa: E402

if not ALL_TOOLS:
    register_tool(SUBFINDER, origin="builtin")
    register_tool(HTTPX, origin="builtin")
    register_tool(NUCLEI, origin="builtin")
