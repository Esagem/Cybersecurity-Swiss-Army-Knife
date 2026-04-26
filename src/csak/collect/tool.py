"""Shared types and the ``Tool`` base class for the slice 2/3 catalog.

Each orchestrated tool lives in ``csak/collect/tools/<tool>.py`` and
subclasses ``Tool``. The interface is small enough to fit in one screen
and rich enough to express target-type routing, mode-dependent
invocation, progress parsing, rate-limit signal detection, and
recursion-graph declarations (``accepts``/``produces``/
``extract_outputs``).

Slice 3 changes (additive):
  * ``accepts: list[str]`` — registered type names this tool consumes.
  * ``produces: list[str]`` — registered type names this tool emits.
  * ``extract_outputs(artifact_path, scan)`` — harvest typed values
    from this tool's artifact for the next recursion depth.
  * ``applies_to`` becomes a thin wrapper over the type matcher; the
    router consults ``accepts`` directly. The wrapper is preserved for
    backward compatibility with external callers (``csak doctor``,
    legacy tests).

See ``cyber-wiki/wiki/specs/slice-3.md §Tool catalog`` for the design.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, TYPE_CHECKING


# Slice 3 dropped the slice 2 ``Literal`` alias for ``TargetType`` —
# the runtime registry is the source of truth for type names. We keep
# ``TargetType`` as a plain ``str`` alias so existing slice 2 type
# annotations still compile without a runtime cost.
TargetType = str
Mode = Literal["quick", "standard", "deep"]

# Slice 2 valid types kept for the small number of call sites that
# enumerate them (notably ``csak doctor`` and a couple of help texts).
# Slice 3 routing reads ``accepts``/``produces`` from each tool, not
# this list; callers that need a type list should consult
# ``csak.collect.types.types_in_registry()``.
VALID_TARGET_TYPES: tuple[str, ...] = (
    "domain",
    "subdomain",
    "host",
    "network_block",
    "url",
    "service",
    "finding_ref",
)
VALID_MODES: tuple[Mode, ...] = ("quick", "standard", "deep")


if TYPE_CHECKING:
    from csak.collect.types import TypedTarget
    from csak.storage.models import Scan


@dataclass
class ProgressUpdate:
    """A snapshot of a stage's progress, emitted by ``parse_progress``.

    All fields are optional — a tool that only knows the running count
    populates ``count`` and leaves the rest ``None``. The runner /
    progress reporter renders whatever is available.
    """

    count: int | None = None       # things found so far (subdomains, hosts, findings)
    total: int | None = None       # total expected, if known
    percent: int | None = None     # 0..100, if the tool exposes it
    rps: int | None = None         # requests per second, if known
    errors: int | None = None      # cumulative error count, if known
    message: str | None = None     # free-form note for the live output


@dataclass
class RateLimitDefaults:
    """Per-tool rate-limit policy. All requests/second.

    The runner starts at ``start_rps`` and halves on signal; never below
    ``floor_rps`` and never above ``ceiling_rps``. ``flag_name`` is the
    CLI flag the tool exposes for setting the global rate.
    """

    start_rps: int
    floor_rps: int
    ceiling_rps: int
    flag_name: str  # e.g. "-rl"


class Tool:
    """Base class implemented by ``csak/collect/tools/<tool>.py``.

    Subclasses set the class-level metadata (``name``, ``binary``,
    ``minimum_version``, ``install_command``, ``rate_limit``,
    ``accepts``, ``produces``) and override ``invocation``,
    ``parse_progress``, ``detect_rate_limit_signal``, and
    ``extract_outputs``.
    """

    # Class metadata — every subclass overrides these.
    name: str = ""                 # "subfinder"
    binary: str = ""               # "subfinder"
    minimum_version: str = ""      # "2.6.0"
    install_command: str = ""      # "go install -v ...@latest"
    output_filename: str = ""      # e.g. "subdomains.jsonl"
    rate_limit: RateLimitDefaults | None = None
    version_args: tuple[str, ...] = ("-version",)

    # Override flag prefixes the CLI converts into raw tool flags.
    # Example: SubfinderTool.override_flags = {"rate_limit": "-rl"}
    # turns ``--subfinder-rate-limit 30`` into ``-rl 30``.
    override_flags: dict[str, str] = {}

    # ── slice 3: recursion graph declarations ──────────────────────

    # Registered type names this tool consumes. The router matches
    # candidates against this list with subtype widening (a candidate
    # of type ``domain`` matches ``accepts: ["host"]`` because
    # ``domain`` declares ``parents: [host]``).
    accepts: list[str] = []

    # Registered type names this tool emits. Used to compute the
    # recursion graph for ``csak tools show``; ``extract_outputs``
    # actually returns the typed values at runtime.
    produces: list[str] = []

    # Origin metadata — set by ``register_tool``. ``"builtin"`` for
    # tools shipped with CSAK; ``"plugin"`` for tools loaded from
    # ``~/.csak/tools/``. Plugin tools also set ``source_path``.
    origin: str = "builtin"
    source_path: str | None = None

    def applies_to(self, target_type: TargetType) -> bool:
        """Backward-compatible wrapper: ``True`` iff a candidate of this
        type would be routed to this tool.

        Slice 2 had a per-tool override; slice 3 derives it from
        ``accepts`` plus the subtype matcher. Kept available for
        external callers (``csak doctor`` and legacy tests) that ask
        the legacy question. The router uses
        ``csak.collect.types.matches`` directly per spec.
        """
        from csak.collect.types import matches

        return matches(target_type, self.accepts)

    def invocation(
        self,
        *,
        target: str,
        target_type: TargetType,
        mode: Mode,
        input_file: str | None,
        output_file: str,
        overrides: dict[str, str] | None = None,
    ) -> list[str]:  # pragma: no cover - abstract
        """Build the argv list for this tool, given the active mode.

        Returns the argv WITHOUT the binary name — the runner prepends
        ``self.binary``. ``input_file`` is the previous stage's
        Artifact path (None for the first applicable stage).
        """
        raise NotImplementedError

    def parse_progress(self, line: str) -> ProgressUpdate | None:
        """Parse a single stderr line into a ProgressUpdate, or None.

        Default: no progress signal exposed. Subfinder uses this default;
        httpx and nuclei override.
        """
        return None

    def detect_rate_limit_signal(self, line: str) -> bool:
        """Return True if this stderr line indicates target rate-limiting.

        Default: never. Subfinder uses this default; httpx and nuclei
        override with tool-specific patterns.
        """
        return False

    def is_skipped_by_mode(self, mode: Mode) -> bool:
        """``quick`` mode skips Nuclei entirely per spec §Modes. Other
        tools never get skipped purely by mode.
        """
        return False

    def parse_version(self, version_output: str) -> str | None:
        """Extract a semver-ish version string from the tool's
        ``-version`` output.

        ProjectDiscovery tools print ``Current Version: vX.Y.Z`` to
        stderr. The default impl finds the first ``vN.N.N`` token.
        """
        import re

        match = re.search(r"v?(\d+\.\d+\.\d+)", version_output)
        return match.group(1) if match else None

    # ── slice 3: recursion harvest ─────────────────────────────────

    def extract_outputs(
        self, artifact_path: Path, scan: "Scan"
    ) -> list["TypedTarget"]:
        """Harvest typed values from this tool's artifact.

        The recursion runner calls this after every successful stage;
        each returned ``TypedTarget`` is a candidate for the next
        depth's frontier (subject to the ``(tool, target, mode)``
        dedup set). Invalid strings — anything ``classify`` can't
        match — should be silently dropped: artifacts legitimately
        contain non-typed strings (response bodies, error messages,
        free-form text fields).

        Default: return ``[]``. A tool that produces nothing the rest
        of the catalog can use is fine — it just doesn't drive
        recursion forward. ``produces`` should be empty for such
        tools so the recursion graph reflects reality.
        """
        return []
