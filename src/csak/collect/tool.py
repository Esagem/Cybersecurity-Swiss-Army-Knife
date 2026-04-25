"""Shared types and the ``Tool`` base class for the slice 2 catalog.

Each orchestrated tool lives in ``csak/collect/tools/<tool>.py`` and
subclasses ``Tool``. The interface is small enough to fit in one screen
and rich enough to express target-type routing, mode-dependent
invocation, progress parsing, and rate-limit signal detection.

See ``cyber-wiki/wiki/specs/slice-2.md §Tool catalog`` for the design
rationale and ``cyber-wiki/wiki/research/slice-2-tool-output-reference.md``
for verified per-tool flag and stderr details.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


TargetType = Literal["domain", "subdomain", "ip", "cidr", "url", "invalid"]
Mode = Literal["quick", "standard", "deep"]

VALID_TARGET_TYPES: tuple[TargetType, ...] = (
    "domain",
    "subdomain",
    "ip",
    "cidr",
    "url",
)
VALID_MODES: tuple[Mode, ...] = ("quick", "standard", "deep")


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
    ``minimum_version``, ``install_command``, ``rate_limit``) and
    override ``applies_to``, ``invocation``, ``parse_progress``, and
    ``detect_rate_limit_signal``.
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

    def applies_to(self, target_type: TargetType) -> bool:  # pragma: no cover - abstract
        raise NotImplementedError

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
