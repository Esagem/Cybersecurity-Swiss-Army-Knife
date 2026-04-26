"""Declarative-only plugin: introduces a new target type + a stub tool.

Demonstrates two things:
  1. Plugins can register *new* target types via the same
     ``register_type`` entry point built-ins use. The new type gets
     a parent (``network_block``) so the matcher widens to it.
  2. Tools that ``accepts`` / ``produces`` the new type appear in
     ``csak tools list`` and the recursion graph from ``csak tools
     show <name>`` (and ``show httpx``) updates automatically.

This plugin does NOT actually run ``asnmap`` — it raises in
``invocation`` so an accidental ``csak collect --target AS15169``
will fail loudly rather than do nothing. Wire ``invocation`` to the
real binary if you have ``asnmap`` installed.
"""
from __future__ import annotations

from csak.collect.tool import Mode, RateLimitDefaults, Tool
from csak.collect.tools import register_tool
from csak.collect.types import TargetType, get_type, register_type


# Idempotent type registration — repeated imports (``csak doctor``,
# ``csak collect``, ``csak tools list`` all trigger plugin load) must
# not re-register and crash with a collision error.
if get_type("asn") is None:
    register_type(TargetType(
        name="asn",
        # ``network_block`` already covers ASNs in the built-in
        # ``classify``; declaring ``parents=["network_block"]`` here
        # makes the matcher widen ASN candidates back to any tool that
        # ``accepts: ["network_block"]`` (httpx, nuclei).
        parents=["network_block"],
        recognizes=lambda v: (
            len(v) > 2 and v[:2].lower() == "as" and v[2:].isdigit()
        ),
        parse=lambda v: {"asn": "AS" + v[2:]},
    ))


class AsnmapDemoTool(Tool):
    name = "asnmap_demo"
    binary = "asnmap"
    minimum_version = "0.0.4"
    install_command = (
        "go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
    )
    output_filename = "asnmap.txt"
    rate_limit = RateLimitDefaults(
        start_rps=0, floor_rps=1, ceiling_rps=50, flag_name="-rl",
    )

    accepts = ["asn"]
    produces = ["network_block"]

    def invocation(self, *, target, target_type, mode, input_file, output_file, overrides=None):
        # Stub. Replace with real asnmap argv (e.g. ``-a target -silent``)
        # and remove the raise.
        raise RuntimeError(
            "asnmap_demo is a declarative stub — install asnmap and "
            "wire the invocation in scripts/csak_plugins/asnmap_demo.py"
        )


register_tool(AsnmapDemoTool(), origin="plugin", source_path=__file__)
