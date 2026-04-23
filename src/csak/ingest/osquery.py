"""osquery parser.

osquery emits JSON when invoked with ``--json``. Two shapes are common:

  * A single JSON array of result rows from ``osqueryi`` or a pack run.
  * A wrapper object with ``{"name": <query>, "columns": [...], "rows": [...]}``.
  * A list of such wrapper objects (pack-style output).

We accept all three.

osquery has no native severity — it just returns query rows. CSAK
assigns severity via a small ruleset keyed on the query name. Anything
we don't recognise stays ``None`` ("needs analyst review").
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from csak.ingest.parser import ParsedScan, ParseResult, ProtoFinding
from csak.ingest.pipeline import register_parser


# Query-name → CSAK severity. Conservative defaults; the analyst can
# override individual findings via status or tags.
QUERY_SEVERITY: dict[str, str] = {
    "listening_ports": "info",
    "processes": "info",
    "users": "info",
    "shell_history": "info",
    "logged_in_users": "info",
    # A few classic "interesting" ones from the osquery pack library.
    "startup_items": "medium",
    "suid_bin": "medium",
    "kernel_modules": "medium",
    "crontab": "medium",
    "launchd": "medium",
    "rpm_packages": "info",
    "deb_packages": "info",
}


def parse(path: Path) -> ParseResult:
    raw = json.loads(path.read_text(encoding="utf-8"))
    findings: list[ProtoFinding] = []
    host_hint = _detect_host(raw)

    for query_name, row in _iter_rows(raw):
        findings.append(_row_to_proto(query_name, row, host_hint=host_hint))

    now = datetime.now(timezone.utc)
    scan = ParsedScan(
        source_tool="osquery",
        label=f"osquery {now.date().isoformat()}",
        scan_started_at=now,
        scan_completed_at=now,
        timestamp_source="fallback-ingested",
    )
    return ParseResult(scan=scan, findings=findings)


def _detect_host(raw: Any) -> str:
    if isinstance(raw, dict):
        return str(raw.get("hostname") or raw.get("host") or "unknown-host")
    if isinstance(raw, list) and raw:
        first = raw[0]
        if isinstance(first, dict):
            return str(first.get("hostname") or first.get("host") or "unknown-host")
    return "unknown-host"


def _iter_rows(raw: Any):
    """Yield (query_name, row_dict) for every row in the file."""
    if isinstance(raw, list):
        # A bare list of rows (no query-name wrapper). Try to use
        # per-row "name" if present; otherwise mark as "adhoc".
        for row in raw:
            if isinstance(row, dict) and "name" in row and "columns" in row:
                yield from _wrapper_rows(row)
            elif isinstance(row, dict) and "columns" in row and isinstance(row["columns"], dict):
                # Individual streamed result with embedded columns.
                yield str(row.get("name") or "adhoc"), dict(row["columns"])
            elif isinstance(row, dict):
                yield str(row.pop("_query", "adhoc") if "_query" in row else "adhoc"), row
        return
    if isinstance(raw, dict):
        if "rows" in raw and "name" in raw:
            yield from _wrapper_rows(raw)
            return
        # Pack-style: key → {columns, rows}.
        for key, payload in raw.items():
            if isinstance(payload, dict) and "rows" in payload:
                for r in payload["rows"]:
                    yield key, dict(r)
            elif isinstance(payload, list):
                for r in payload:
                    if isinstance(r, dict):
                        yield key, dict(r)


def _wrapper_rows(wrapper: dict[str, Any]):
    name = str(wrapper.get("name", "adhoc"))
    for r in wrapper.get("rows", []):
        if isinstance(r, dict):
            yield name, dict(r)


def _row_to_proto(query_name: str, row: dict, *, host_hint: str) -> ProtoFinding:
    host = (
        row.get("hostname")
        or row.get("host")
        or row.get("host_identifier")
        or host_hint
    )
    severity = QUERY_SEVERITY.get(query_name)
    title = f"osquery/{query_name}"

    normalized = {
        "query_name": query_name,
        "row": row,
        "host": host,
    }

    return ProtoFinding(
        target_identifier=str(host),
        target_type="host",
        raw_severity=severity,
        raw_confidence=None,
        title=title,
        raw={"query_name": query_name, "row": row},
        normalized=normalized,
    )


register_parser("osquery", parse)
