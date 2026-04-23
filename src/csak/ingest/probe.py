"""Subfinder + httpx parsers (ProjectDiscovery tooling).

Both tools emit JSONL when invoked with ``-oJ``/``-json``. One JSON
object per line.

Subfinder rows typically look like::

    {"host": "api.acmecorp.com", "input": "acmecorp.com", "source": "crtsh"}

Each subfinder hit is recorded as a **discovered identifier** on the
parent domain rather than a Finding in its own right — that matches
the spec's rule that "a subdomain with no finding stays a string in
the parent's identifiers list." If the analyst wants to force a
promotion, they can give the subdomain a target-weight override.

httpx rows have more context::

    {"url": "https://api.acmecorp.com/health",
     "status_code": 200,
     "host": "api.acmecorp.com",
     "title": "Healthcheck",
     "tech": ["nginx", "python"]}

Each httpx hit IS a Finding — the live-host confirmation plus its
surface data (status/tech) is worth tracking so that reports can say
"these URLs were reachable during the window."
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from csak.ingest.parser import ParsedScan, ParseResult, ProtoFinding
from csak.ingest.pipeline import register_parser


def parse_subfinder(path: Path) -> ParseResult:
    rows = list(_load_jsonl(path))
    now = datetime.now(timezone.utc)

    discovered: dict[str, list[str]] = {}
    for row in rows:
        host = row.get("host")
        parent = row.get("input") or _parent_of(host) if host else None
        if host and parent:
            discovered.setdefault(str(parent), []).append(str(host))

    scan = ParsedScan(
        source_tool="subfinder",
        label=f"subfinder discovery {now.date().isoformat()}",
        scan_started_at=now,
        scan_completed_at=now,
        timestamp_source="fallback-ingested",
    )
    return ParseResult(scan=scan, discovered_identifiers=discovered)


def parse_httpx(path: Path) -> ParseResult:
    rows = list(_load_jsonl(path))
    findings: list[ProtoFinding] = []
    timestamps: list[datetime] = []

    for row in rows:
        url = row.get("url") or row.get("input")
        if not url:
            continue
        status = row.get("status_code") or row.get("status-code")
        title = (
            f"HTTP {status} — {row.get('title') or row.get('host') or url}"
            if status is not None
            else f"live host: {row.get('host') or url}"
        )
        # httpx signals "live host reachable." Severity is informational
        # by default — it becomes medium if the status is 4xx/5xx hinting
        # at misconfigured endpoints, or high if it's clearly a critical
        # response. We keep the ruleset simple.
        severity = _httpx_severity(status)
        host = row.get("host") or _host_of(str(url))

        normalized = {"url": str(url), "host": host, "status": status}
        findings.append(
            ProtoFinding(
                target_identifier=str(url),
                target_type="url",
                raw_severity=severity,
                raw_confidence=None,
                title=title,
                raw=row,
                normalized=normalized,
            )
        )
        ts = _parse_ts(row.get("timestamp"))
        if ts is not None:
            timestamps.append(ts)

    if timestamps:
        scan_started = min(timestamps)
        scan_completed = max(timestamps)
        timestamp_source = "extracted"
    else:
        scan_started = scan_completed = datetime.now(timezone.utc)
        timestamp_source = "fallback-ingested"

    scan = ParsedScan(
        source_tool="httpx",
        label=f"httpx probe {scan_started.date().isoformat()}",
        scan_started_at=scan_started,
        scan_completed_at=scan_completed,
        timestamp_source=timestamp_source,
    )
    return ParseResult(scan=scan, findings=findings)


def _httpx_severity(status: int | str | None) -> str:
    if status is None:
        return "info"
    try:
        code = int(status)
    except (TypeError, ValueError):
        return "info"
    if 500 <= code < 600:
        return "medium"
    if 400 <= code < 500:
        return "low"
    return "info"


def _parent_of(host: str | None) -> str | None:
    if not host:
        return None
    # crude: treat "a.b.c.d" as a subdomain of "b.c.d" for 3+ label hosts;
    # otherwise return the host itself so grouping is still stable.
    parts = host.split(".")
    if len(parts) >= 3:
        return ".".join(parts[-2:])
    return host


def _host_of(url: str) -> str:
    from urllib.parse import urlparse

    try:
        return urlparse(url).hostname or url
    except Exception:
        return url


def _parse_ts(raw) -> datetime | None:
    if not raw:
        return None
    try:
        s = str(raw)
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except Exception:
        return None


def _load_jsonl(path: Path) -> Iterable[dict]:
    text = path.read_text(encoding="utf-8")
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        yield json.loads(line)


register_parser("subfinder", parse_subfinder)
register_parser("httpx", parse_httpx)
