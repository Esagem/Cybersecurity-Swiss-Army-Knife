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

Slice 3 recursion graph: nuclei accepts ``host`` (widening picks up
``domain``/``subdomain``), ``url`` (URLs flow directly to nuclei without
a httpx hop), and ``network_block`` (slice 2 parity). It produces
``url`` (from a finding's ``matched-at``/``extracted-results``) and
``finding_ref`` (forward-compat for tools that take findings as input;
slice 3 has none, but the type is registered).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from csak.collect.tool import (
    Mode,
    ProgressUpdate,
    RateLimitDefaults,
    TargetType,
    Tool,
)
from csak.collect.types import InvalidTargetError, TypedTarget, classify


INVOCATIONS: dict[Mode, list[str] | None] = {
    # Quick mode skips nuclei entirely per spec §Modes. quick exists
    # for "tell me what's there" reconnaissance (subfinder + httpx
    # surface discovery), not for "find vulnerabilities" — that's
    # standard's job. See ``is_skipped_by_mode`` below.
    "quick": None,
    "standard": [
        # source: reconFTW v4.0 modules/vulns.sh (default scan recipe)
        # NOTE: ``info`` IS included. Many real-world risks (EOL
        # software fingerprints, generic env-file disclosure, missing
        # security headers, basic auth detection) are tagged ``info``
        # by nuclei but are genuinely actionable. Filtering them out
        # in standard mode caused silent gaps — see the integration
        # harness baseline (heavy target). The triage UI / scoring
        # layer is the right place to demote noise, not the scanner.
        "-silent", "-nc", "-jsonl", "-duc", "-stats", "-si", "5",
        "-severity", "info,low,medium,high,critical",
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


# Two stats formats observed in the wild:
#
#   v2 / older nuclei:
#     [INF] Stats: requests=1234, errors=23, RPS=45, percent=15
#
#   v3+ nuclei (the current default with ``-stats -si N``):
#     {"duration":"0:00:05","errors":"49","hosts":"1","matched":"0",
#      "percent":"3","requests":"532","rps":"101","templates":"6537",
#      "total":"14894","startedAt":"2026-04-25T16:42:19Z"}
#
# We parse both. The JSON form is preferred (it has ``total`` and
# ``hosts`` too); the regex is the fallback.
_STATS_RE = re.compile(
    r"Stats:.*?requests\s*=\s*(?P<count>\d+)"
    r".*?errors\s*=\s*(?P<errors>\d+)"
    r"(?:.*?RPS\s*=\s*(?P<rps>\d+))?"
    r"(?:.*?percent\s*=\s*(?P<pct>\d+))?",
    re.IGNORECASE,
)


def _parse_stats(line: str) -> dict[str, int | None] | None:
    """Return ``{count, total, percent, rps, errors}`` if ``line`` is
    a nuclei stats line, else ``None``.

    Handles both the legacy ``Stats: requests=…`` regex format and the
    JSON-per-tick format nuclei v3+ emits with ``-stats -si N``.
    """
    stripped = line.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict) and "requests" in data:
            return {
                "count": _opt_int(data.get("requests")),
                "total": _opt_int(data.get("total")),
                "percent": _opt_int(data.get("percent")),
                "rps": _opt_int(data.get("rps")),
                "errors": _opt_int(data.get("errors")) or 0,
            }

    match = _STATS_RE.search(line)
    if match:
        return {
            "count": int(match.group("count")),
            "total": None,
            "percent": int(match.group("pct")) if match.group("pct") else None,
            "rps": int(match.group("rps")) if match.group("rps") else None,
            "errors": int(match.group("errors")),
        }
    return None


def _opt_int(value: object) -> int | None:
    """nuclei's JSON output stringifies numbers — coerce defensively."""
    if value is None:
        return None
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


# Rate-limit indicators per spec §Adaptive rate limiting. Strings are
# matched case-insensitively against [WRN]/[ERR] stderr lines.
#
# We previously also matched ``context deadline exceeded`` /
# ``connection refused`` / ``connection reset``, but those fire on
# *any* failed connection — including nuclei probing closed ports on
# a small target. The spec-defined indicators (429/503/rate-limit/
# too-many-requests/retry-after) are specific to actual throttling
# and don't false-positive on inapplicable templates. Genuine slow
# rate-limits where the target only emits timeouts (no HTTP status)
# are not detected at the nuclei layer; httpx's earlier stage catches
# 429/503 from response codes and the current_rate carry-forward
# propagates the lowered rate to nuclei.
_RL_PATTERNS: tuple[str, ...] = (
    "429",
    "503",
    "rate limit",
    "too many requests",
    "retry-after",
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

    # Slice 3 recursion graph. Nuclei takes hosts (widening covers
    # domain and subdomain), URLs (URL-typed candidates skip httpx
    # and feed nuclei directly), and CIDRs (slice 2 parity — nuclei
    # itself iterates the network when given ``-u <cidr>``).
    accepts = ["host", "url", "network_block"]
    produces = ["url", "finding_ref"]

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
        stats = _parse_stats(line)
        if stats is None:
            return None
        return ProgressUpdate(
            count=stats["count"],
            total=stats["total"],
            percent=stats["percent"],
            rps=stats["rps"],
            errors=stats["errors"],
        )

    def detect_rate_limit_signal(self, line: str) -> bool:
        """Per spec §Adaptive rate limiting — only the explicit
        rate-limit indicators count: 429, 503, "rate limit",
        "too many requests", "retry-after". Generic network failures
        (connection refused, context deadline exceeded) are not signals
        because they false-positive on small targets where most
        templates probe services that don't exist."""
        if "[WRN]" not in line and "[ERR]" not in line:
            return False
        lowered = line.lower()
        return any(pat in lowered for pat in _RL_PATTERNS)

    def extract_outputs(self, artifact_path, scan):
        """Harvest typed values from nuclei's JSONL findings file.

        Two sources per finding:
          * ``matched-at`` — the URL or host the template fired on.
          * ``extracted-results`` — strings extracted by the template
            (often URLs or hostnames).

        We classify each via the registry and silently drop strings
        that aren't typed values (free-form template output, response
        bodies, etc).
        """
        out: list[TypedTarget] = []
        if artifact_path is None:
            return out
        path = Path(artifact_path)
        if not path.exists():
            return out
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            return out
        for raw in text.splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                finding = json.loads(raw)
            except json.JSONDecodeError:
                continue
            matched = finding.get("matched-at") or finding.get("host")
            if matched:
                try:
                    out.append(classify(str(matched)))
                except InvalidTargetError:
                    pass
            for value in finding.get("extracted-results") or []:
                try:
                    out.append(classify(str(value)))
                except InvalidTargetError:
                    continue
        return out


NUCLEI = NucleiTool()
