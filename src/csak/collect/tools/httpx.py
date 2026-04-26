"""httpx catalog module.

Tool flags and output format documented at
``cyber-wiki/wiki/research/slice-2-tool-output-reference.md``.

httpx is the live-host filter — it reads a list of hosts/URLs and
emits structured JSON per probed endpoint. The slice 1 probe parser
handles its output; slice 2 adds invocation, progress parsing
(via ``-stats``), and rate-limit signal detection.

Progress signal format from ``-stats -si 5``::

    [INF] Stats: 234/500 (46%) | RPS: 45 | Errors: 12 | Duration: 5s

Rate-limit signal: there is no clean structured event. We watch for
errors-count climbing fast (the heuristic per spec) plus stray ``429``
or ``503`` strings if any leak through ``-silent``.

Slice 3 recursion graph: httpx accepts ``host`` (widening picks up
``domain`` and ``subdomain``) and ``network_block`` (so the slice 2
behaviour where httpx expands a CIDR target survives) and produces
``url``. URL-typed candidates from the recursion frontier skip httpx
deliberately — they're already known endpoints; nuclei consumes them
directly.
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


# Default port set passed to httpx. httpx itself probes only 80/443
# unless a port list is given; that misses dev servers, internal admin
# UIs, and most enterprise web apps. We expand to the high-signal
# OWASP-recommended port set per mode:
#
#   quick    — 5 most common HTTP(S) ports
#   standard — adds the next tier of common dev/admin/proxy ports
#   deep     — full coverage of common alternate-port HTTP services
#
# Source: ProjectDiscovery's "common ports" reference + OWASP testing
# guide §4.2.1.
DEFAULT_PORTS: dict[Mode, str] = {
    "quick":    "80,443,8080,8443,8000",
    "standard": "80,443,8080,8443,8000,8008,8081,8088,8888,3000,5000,9000,9090",
    "deep":     "80,443,8080,8443,8000,8001,8008,8009,8081,8082,8088,8089,8090,8443,8888,9000,9001,9080,9090,9091,9443,3000,3001,4000,5000,5080,5601,6000,7000,7001,7070,7080,8118,9200,9300",
}


INVOCATIONS: dict[Mode, list[str]] = {
    "quick": [
        # source: reconFTW v4.0 modules/web.sh (lightweight probe recipe)
        "-silent", "-nc", "-j", "-duc", "-stats", "-si", "5",
        "-sc", "-title", "-server", "-ip",
    ],
    "standard": [
        # source: reconFTW v4.0 modules/web.sh (default probe recipe)
        "-silent", "-nc", "-j", "-duc", "-stats", "-si", "5",
        "-sc", "-cl", "-ct", "-title", "-server", "-td", "-ip", "-cname",
    ],
    "deep": [
        # source: reconFTW v4.0 modules/web.sh (deep probe recipe)
        "-silent", "-nc", "-j", "-duc", "-stats", "-si", "5",
        "-sc", "-cl", "-ct", "-title", "-server", "-td", "-ip", "-cname",
        "-favicon", "-jarm", "-tls-grab", "-fep",
    ],
}


# Two stats line formats observed in current httpx (v1.6+):
#
#   [0:00:01] | RPS: 20 | Requests: 26 | Hosts: 12/12 (100%)
#
# Older builds also emit a ``Stats:`` legacy form. We accept both.
# ``Hosts: N/M (P%)`` doubles as count/total/percent — there is no
# separate ``Errors:`` field in the new format, so we default errors
# to 0 (the rate-limiter falls back to its [WRN] / [ERR] heuristic).
_STATS_RE_NEW = re.compile(
    r"\[\d+:\d+:\d+\]"
    r".*?RPS:\s*(?P<rps>\d+)"
    r".*?Requests:\s*(?P<requests>\d+)"
    r".*?Hosts:\s*(?P<count>\d+)\s*/\s*(?P<total>\d+)\s*\((?P<pct>\d+)%\)",
    re.IGNORECASE,
)
_STATS_RE_LEGACY = re.compile(
    r"Stats:\s*(?P<count>\d+)\s*/\s*(?P<total>\d+)"
    r".*?\((?P<pct>\d+)%\)"
    r".*?RPS:\s*(?P<rps>\d+)"
    r".*?Errors:\s*(?P<errors>\d+)",
    re.IGNORECASE,
)


def _parse_stats(line: str) -> dict[str, int | None] | None:
    """Return ``{count, total, percent, rps, errors}`` if ``line`` is
    an httpx stats line, else ``None``."""
    match = _STATS_RE_NEW.search(line)
    if match:
        return {
            "count": int(match.group("count")),
            "total": int(match.group("total")),
            "percent": int(match.group("pct")),
            "rps": int(match.group("rps")),
            "errors": 0,
        }
    match = _STATS_RE_LEGACY.search(line)
    if match:
        return {
            "count": int(match.group("count")),
            "total": int(match.group("total")),
            "percent": int(match.group("pct")),
            "rps": int(match.group("rps")),
            "errors": int(match.group("errors")),
        }
    return None


class HttpxTool(Tool):
    name = "httpx"
    binary = "httpx"
    minimum_version = "1.4.0"
    install_command = (
        "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    )
    output_filename = "live-hosts.jsonl"
    rate_limit = RateLimitDefaults(
        start_rps=150,
        floor_rps=5,
        ceiling_rps=300,
        flag_name="-rl",
    )
    override_flags = {
        "rate_limit": "-rl",
        "threads": "-t",
        "timeout": "-timeout",
        "ports": "-ports",
    }

    # Slice 3 recursion graph. ``host`` widens to ``domain`` and
    # ``subdomain`` via the matcher; ``network_block`` is included so
    # CIDR / ASN targets continue to flow through httpx (httpx itself
    # handles CIDR expansion via ``-u <cidr>``). ``url`` is deliberately
    # absent: a URL is already a known endpoint; the slice 2 router
    # records "URL is already a known endpoint; httpx step skipped"
    # for url-typed targets and slice 3 inherits this.
    accepts = ["host", "network_block"]
    produces = ["url"]

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
        argv = list(INVOCATIONS[mode])
        # If we have a previous stage's artifact, use it as the input
        # list. Otherwise we feed the raw target directly via stdin
        # (handled at the runner level by writing a one-line input
        # file with the target).
        if input_file is not None:
            argv.extend(["-l", input_file])
        else:
            argv.extend(["-u", target])
        argv.extend(["-o", output_file])

        # Apply mode's default port set, unless the caller is going to
        # override via ``--httpx-ports``. Adding it here (rather than
        # in the static INVOCATIONS recipe) keeps overrides idempotent.
        overrides = overrides or {}
        if "ports" not in overrides:
            argv.extend(["-ports", DEFAULT_PORTS[mode]])

        # Track previous stage's error count so we can detect rapid
        # rises. Stored on the instance for the duration of one run;
        # the pipeline resets it before each invocation.
        self._last_errors = 0

        for key, value in overrides.items():
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
        rate-limit responses count. The stats-error heuristic was
        removed because httpx's new stats line has no errors counter
        and the count anyway double-counts inapplicable-template
        connection failures (false positive on small targets)."""
        return "429" in line or "503" in line

    def extract_outputs(self, artifact_path, scan):
        """Classify each responding host's URL from httpx's JSONL output.

        We only emit candidates for rows where ``status_code`` is
        present (i.e. the host actually responded). Status, tech, and
        title travel as advisory metadata so a downstream tool that
        cares can use them without changing its declared accepts.
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
                row = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not row.get("status_code"):
                continue
            url = row.get("url") or row.get("host")
            if not url:
                continue
            try:
                t = classify(str(url))
            except InvalidTargetError:
                continue
            t.metadata["status"] = row.get("status_code")
            tech = row.get("tech") or row.get("technologies") or []
            if tech:
                t.metadata["tech"] = list(tech) if isinstance(tech, (list, tuple)) else [tech]
            title = row.get("title")
            if title:
                t.metadata["title"] = str(title)
            out.append(t)
        return out


HTTPX = HttpxTool()
