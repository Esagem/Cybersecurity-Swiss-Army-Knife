"""Tool routing — given a target type and mode, return the ordered
list of tools that will run, plus reasons for any tools that were
skipped.

The routing rules live in two places:

  * Each ``Tool`` declares ``accepts: list[str]`` — the registered
    type names it consumes. Slice 3's matcher walks the candidate
    type's parent chain so a tool that ``accepts: ["host"]`` matches
    a domain or subdomain candidate via subtype widening.
  * The mode imposes one extra rule: ``quick`` skips Nuclei entirely
    even when it would otherwise apply.

The order in which applicable tools run is fixed by the catalog
ordering (subfinder → httpx → nuclei for the built-ins) — the runtime
tool registry preserves registration order, so plugins running last
is intentional.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from csak.collect.tool import Mode, TargetType, Tool
from csak.collect.tools import ALL_TOOLS
from csak.collect.types import matches


@dataclass
class Routed:
    """Outcome of a routing decision.

    ``tools`` is the ordered list of tools that will run. ``skipped``
    maps tool name → human-readable skip reason for tools that did
    NOT run. The pipeline turns each skip into a ``status=skipped``
    Scan with the reason in ``Scan.notes``.
    """

    tools: list[Tool] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)


def route(target_type: TargetType, mode: Mode) -> Routed:
    """Return the routing decision for ``(target_type, mode)``.

    Skipped tools are recorded with a reason so the live output and
    the Scan notes can explain *why* each was skipped. The reasons
    here are user-facing strings.
    """
    if target_type == "invalid":
        # Defense in depth — the CLI rejects invalid targets before
        # calling route(), but we still produce a coherent result.
        return Routed(
            tools=[],
            skipped={t.name: "target type invalid" for t in ALL_TOOLS},
        )

    result = Routed()
    for tool in ALL_TOOLS:
        if not matches(target_type, tool.accepts):
            result.skipped[tool.name] = _skip_reason_for_type(tool, target_type)
            continue
        if tool.is_skipped_by_mode(mode):
            result.skipped[tool.name] = f"mode={mode} skips {tool.name}"
            continue
        result.tools.append(tool)
    return result


def _skip_reason_for_type(tool: Tool, target_type: TargetType) -> str:
    """Phrase the skip reason in user-facing terms.

    Two slice 2 reasons survive verbatim because they appear in
    documentation and tests:
      * subfinder: "no subdomain enumeration for IP/CIDR/URL targets".
      * httpx for url: "URL is already a known endpoint; httpx step
        skipped".
    Other skips fall back to a generic message that names the tool and
    type for diagnostic value.
    """
    if tool.name == "subfinder":
        return "no subdomain enumeration for IP/CIDR/URL targets"
    if tool.name == "httpx" and target_type == "url":
        return "URL is already a known endpoint; httpx step skipped"
    return f"{tool.name} does not apply to target type {target_type}"
