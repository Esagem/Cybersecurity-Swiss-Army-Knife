"""Nuclei catalog module.

Tool flags and output format documented at
``cyber-wiki/wiki/research/slice-2-tool-output-reference.md``.

Nuclei is the active web vuln scanner. Slice 1's nuclei parser handles
its JSONL findings. Slice 2 adds invocation recipes per mode,
``-stats`` progress parsing, and the heuristic rate-limit signal
detector — there is no clean "429 detected" stderr event from nuclei,
so we watch for repeated ``[WRN] context deadline exceeded`` /
``connection refused`` lines plus error-count spikes in ``-stats``.

``quick`` mode skips Nuclei entirely per spec §Modes — that's
expressed via ``is_skipped_by_mode``, not by an empty invocation.
"""
from __future__ import annotations

import re

from csak.collect.tool import (
    Mode,
    ProgressUpdate,
    RateLimitDefaults,
    TargetType,
    Tool,
)


INVOCATIONS: dict[Mode, list[str] | None] = {
    # Quick mode skips nuclei — see Tool.is_skipped_by_mode below.
    "quick": None,
    "standard": [
        # source: reconFTW v4.0 modules/vulns.sh (default scan recipe)
        "-silent", "-nc", "-jsonl", "-duc", "-stats", "-si", "5",
        "-severity", "low,medium,high,critical",
        "-rl", "150",       # adaptive limiter scales this
        "-c", "25",
        "-bs", "25",
    ],
    "deep": [
        # source: reconFTW v4.0 modules/vulns.sh (deep scan recipe)
        "-silent", "-nc", "-jsonl", "-duc", "-stats", "-si", "5",
        "-severity", "info,low,medium,high,critical",
        "-irr",
        "-rl", "150",
        "-c", "50",
        "-bs", "25",
        "-tags", "cve,oast,exposure,misconfiguration,tech",
    ],
}


# Format from real run output (verified):
#   [INF] Stats: requests=1234, errors=23, RPS=45, percent=15
# Older versions vary in exact field names but the key=value style and
# the ``Stats:`` token are stable.
_STATS_RE = re.compile(
    r"Stats:.*?requests\s*=\s*(?P<count>\d+)"
    r".*?errors\s*=\s*(?P<errors>\d+)"
    r"(?:.*?RPS\s*=\s*(?P<rps>\d+))?"
    r"(?:.*?percent\s*=\s*(?P<pct>\d+))?",
    re.IGNORECASE,
)

# Rate-limit signals in [WRN] lines, per the spec wiki.
_RL_PATTERNS: tuple[str, ...] = (
    "context deadline exceeded",
    "connection refused",
    "connection reset",
)


class NucleiTool(Tool):
    name = "nuclei"
    binary = "nuclei"
    minimum_version = "3.0.0"
    install_command = (
        "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    )
    output_filename = "findings.jsonl"
    rate_limit = RateLimitDefaults(
        start_rps=150,
        floor_rps=5,
        ceiling_rps=300,
        flag_name="-rl",
    )
    override_flags = {
        "rate_limit": "-rl",
        "templates": "-t",
        "tags": "-tags",
        "severity": "-severity",
        "concurrency": "-c",
    }

    def applies_to(self, target_type: TargetType) -> bool:
        # Nuclei applies to every valid target type.
        return target_type in ("domain", "subdomain", "ip", "cidr", "url")

    def is_skipped_by_mode(self, mode: Mode) -> bool:
        # Per spec §Modes — quick mode skips nuclei entirely.
        return mode == "quick"

    def invocation(
        self,
        *,
        target: str,
        target_type: TargetType,
        mode: Mode,
        input_file: str | None,
        output_file: str,
        overrides: dict[str, str] | None = None,
    ) -> list[str]:
        recipe = INVOCATIONS[mode]
        if recipe is None:
            raise ValueError(f"nuclei has no invocation for mode={mode}")
        argv = list(recipe)
        if input_file is not None:
            argv.extend(["-l", input_file])
        else:
            argv.extend(["-u", target])
        argv.extend(["-o", output_file])

        self._last_errors = 0

        for key, value in (overrides or {}).items():
            flag = self.override_flags.get(key)
            if flag is None:
                continue
            argv.extend([flag, value])
        return argv

    def parse_progress(self, line: str) -> ProgressUpdate | None:
        match = _STATS_RE.search(line)
        if match is None:
            return None
        return ProgressUpdate(
            count=int(match.group("count")),
            errors=int(match.group("errors")),
            rps=int(match.group("rps")) if match.group("rps") else None,
            percent=int(match.group("pct")) if match.group("pct") else None,
        )

    def detect_rate_limit_signal(self, line: str) -> bool:
        if "[WRN]" in line or "[ERR]" in line:
            for pat in _RL_PATTERNS:
                if pat in line:
                    return True
        # Stats-line heuristic: errors rose by 20+ since last interval.
        match = _STATS_RE.search(line)
        if match is None:
            return False
        errors = int(match.group("errors"))
        last = getattr(self, "_last_errors", 0)
        rose = errors - last
        self._last_errors = errors
        return rose >= 20


NUCLEI = NucleiTool()
