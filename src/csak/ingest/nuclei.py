"""Nuclei parser.

Nuclei emits either:
  * JSONL — one JSON object per finding, newline-delimited (`-jsonl`).
  * JSON array — a single JSON array when invoked with `-json-export`.

We detect which by peeking the first non-whitespace character.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from csak.ingest.parser import ParsedScan, ParseResult, ProtoFinding
from csak.ingest.pipeline import register_parser


def parse(path: Path) -> ParseResult:
    records = list(_load(path))
    timestamps = [
        _parse_ts(r.get("timestamp")) for r in records if r.get("timestamp")
    ]
    timestamps = [t for t in timestamps if t is not None]
    ingested_at = datetime.now(timezone.utc)
    if timestamps:
        scan_started = min(timestamps)
        scan_completed = max(timestamps)
        timestamp_source = "extracted"
    else:
        scan_started = scan_completed = ingested_at
        timestamp_source = "fallback-ingested"

    findings: list[ProtoFinding] = []
    for rec in records:
        findings.append(_record_to_proto(rec))

    scan = ParsedScan(
        source_tool="nuclei",
        label=f"nuclei sweep {scan_started.date().isoformat()}",
        scan_started_at=scan_started,
        scan_completed_at=scan_completed,
        timestamp_source=timestamp_source,
    )
    return ParseResult(scan=scan, findings=findings)


def _load(path: Path) -> Iterable[dict[str, Any]]:
    text = path.read_text(encoding="utf-8").lstrip()
    if not text:
        return []
    if text[0] == "[":
        return json.loads(text)
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _parse_ts(raw: Any) -> datetime | None:
    if not raw:
        return None
    try:
        # Nuclei emits ISO-8601 with offset, sometimes with nanoseconds.
        s = str(raw)
        # Trim sub-second precision beyond microseconds (Python's
        # fromisoformat accepts up to 6 digits).
        if "." in s:
            base, rest = s.split(".", 1)
            # rest may end with "Z" or +hh:mm.
            tz_mark = ""
            for marker in ("Z", "+", "-"):
                idx = rest.find(marker, 1)
                if idx != -1:
                    tz_mark = rest[idx:]
                    rest = rest[:idx]
                    break
            rest = rest[:6].ljust(6, "0")
            s = f"{base}.{rest}{tz_mark}"
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except Exception:
        return None


def _record_to_proto(rec: dict[str, Any]) -> ProtoFinding:
    info = rec.get("info") or {}
    template_id = rec.get("template-id") or rec.get("templateID") or ""
    matched_at = rec.get("matched-at") or rec.get("matched_at") or rec.get("host") or ""
    severity = info.get("severity") if isinstance(info, dict) else None
    title = info.get("name") if isinstance(info, dict) else None
    if not title:
        title = template_id or "nuclei finding"

    target_identifier = matched_at or rec.get("host") or ""
    target_type = "url" if "://" in target_identifier else "domain"

    normalized = {
        "template-id": template_id,
        "matched-at": matched_at,
        "name": info.get("name") if isinstance(info, dict) else None,
        "tags": info.get("tags") if isinstance(info, dict) else None,
        "host": rec.get("host"),
    }

    return ProtoFinding(
        target_identifier=target_identifier,
        target_type=target_type,
        raw_severity=severity,
        raw_confidence=None,
        title=str(title),
        raw=rec,
        normalized=normalized,
        observed_at=_parse_ts(rec.get("timestamp")),
    )


register_parser("nuclei", parse)
