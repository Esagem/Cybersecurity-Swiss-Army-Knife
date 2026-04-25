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


# Compiled once at import. The format is documented in the wiki — the
# only stable parts are the ``Stats:`` token, ``N/M``, ``(P%)``,
# ``RPS: N``, and ``Errors: N``.
_STATS_RE = re.compile(
    r"Stats:\s*(?P<count>\d+)\s*/\s*(?P<total>\d+)"
    r".*?\((?P<pct>\d+)%\)"
    r".*?RPS:\s*(?P<rps>\d+)"
    r".*?Errors:\s*(?P<errors>\d+)",
    re.IGNORECASE,
)


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
    }

    def applies_to(self, target_type: TargetType) -> bool:
        # Per spec routing matrix: httpx applies to everything except
        # url targets (we already know URLs are "interesting").
        return target_type in ("domain", "subdomain", "ip", "cidr")

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

        # Track previous stage's error count so we can detect rapid
        # rises. Stored on the instance for the duration of one run;
        # the pipeline resets it before each invocation.
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
            total=int(match.group("total")),
            percent=int(match.group("pct")),
            rps=int(match.group("rps")),
            errors=int(match.group("errors")),
            message=None,
        )

    def detect_rate_limit_signal(self, line: str) -> bool:
        # Strong signals: literal 429 or 503 in any line (rare under
        # -silent but happens in newer versions).
        if "429" in line or "503" in line:
            return True
        # Heuristic: the errors-count in -stats jumped sharply.
        match = _STATS_RE.search(line)
        if match is None:
            return False
        errors = int(match.group("errors"))
        last = getattr(self, "_last_errors", 0)
        rose = errors - last
        self._last_errors = errors
        # Threshold per spec wiki: errors rising by ~10+ between
        # 5-second intervals is the canonical heuristic.
        return rose >= 10


HTTPX = HttpxTool()
