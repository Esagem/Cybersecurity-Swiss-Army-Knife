"""Zeek parser — folder-aware.

Zeek produces many log files per capture window: ``conn.log``,
``dns.log``, ``http.log``, ``notice.log``, etc. — one per protocol,
sometimes rotated hourly.

The parser accepts either:
  * A single file → treat it as one log.
  * A directory → glob for every Zeek log under it and process them
    as one Scan. Non-Zeek files are skipped with a stderr warning.

Zeek logs come in two flavours:
  * TSV with a ``#fields`` / ``#types`` header.
  * JSON — one JSON object per line.

We surface **only events that warrant findings** as ProtoFindings:
  * notice.log → a ProtoFinding per row (Zeek's own "something weird"
    channel, with a rich ``note`` field like ``Scan::Port_Scan``).
The rest of the logs are preserved as raw Artifacts but don't become
Findings; surfacing them as findings would drown the table in
routine traffic events. That's consistent with the spec's stance
that CSAK is not a SIEM.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from csak.ingest.parser import ParsedScan, ParseResult, ProtoFinding
from csak.ingest.pipeline import register_parser


# Zeek default log files by stem. The list is a signal for filtering
# "is this a Zeek log?" when scanning a directory — a file whose stem
# isn't in this set is skipped with a warning rather than errored.
ZEEK_LOG_STEMS = {
    "conn",
    "dns",
    "http",
    "ssl",
    "x509",
    "files",
    "ftp",
    "smtp",
    "ssh",
    "notice",
    "weird",
    "dhcp",
    "dpd",
    "software",
    "stats",
    "loaded_scripts",
    "packet_filter",
    "reporter",
}


def parse(path: Path) -> ParseResult:
    if path.is_dir():
        log_files = _zeek_logs_in(path)
    else:
        log_files = [path]

    if not log_files:
        now = datetime.now(timezone.utc)
        return ParseResult(
            scan=ParsedScan(
                source_tool="zeek",
                label=f"zeek (empty) {now.date().isoformat()}",
                scan_started_at=now,
                scan_completed_at=now,
                timestamp_source="fallback-ingested",
                notes="no Zeek logs found",
            )
        )

    all_timestamps: list[datetime] = []
    findings: list[ProtoFinding] = []

    for log_path in log_files:
        log_type = log_path.name.split(".", 1)[0]  # "notice.log" -> "notice"
        rows = list(_read_zeek_log(log_path))
        for row in rows:
            ts = _row_timestamp(row)
            if ts is not None:
                all_timestamps.append(ts)
            if log_type == "notice":
                findings.append(_notice_to_proto(row, source_path=log_path))

    if all_timestamps:
        scan_started = min(all_timestamps)
        scan_completed = max(all_timestamps)
        timestamp_source = "extracted"
    else:
        scan_started = scan_completed = datetime.now(timezone.utc)
        timestamp_source = "fallback-ingested"

    scan = ParsedScan(
        source_tool="zeek",
        label=f"zeek capture {scan_started.date().isoformat()}",
        scan_started_at=scan_started,
        scan_completed_at=scan_completed,
        timestamp_source=timestamp_source,
    )
    return ParseResult(scan=scan, findings=findings)


def _zeek_logs_in(directory: Path) -> list[Path]:
    logs: list[Path] = []
    for entry in sorted(directory.iterdir()):
        if not entry.is_file():
            continue
        stem = entry.name.split(".", 1)[0]
        if stem in ZEEK_LOG_STEMS and (
            entry.suffix == ".log"
            or entry.suffix == ".json"
            or entry.name.endswith(".log.gz")
        ):
            logs.append(entry)
        else:
            print(
                f"[csak zeek] skipping non-Zeek file: {entry.name}",
                file=sys.stderr,
            )
    return logs


def _read_zeek_log(path: Path) -> Iterable[dict[str, Any]]:
    # Gzipped logs are supported to cover rotated archives.
    if path.name.endswith(".gz"):
        import gzip

        opener = lambda p: gzip.open(p, "rt", encoding="utf-8", errors="replace")
    else:
        opener = lambda p: open(p, "r", encoding="utf-8", errors="replace")

    with opener(path) as f:
        first = f.readline()
        if not first:
            return
        if first.lstrip().startswith("{"):
            # JSON mode.
            yield json.loads(first)
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)
            return

        # TSV with header.
        fields: list[str] | None = None
        separator = "\t"
        set_separator = ","
        empty_field = "(empty)"
        unset_field = "-"
        # First line was consumed; re-open to iterate cleanly.
        f.seek(0)
        for raw in f:
            raw = raw.rstrip("\n")
            if raw.startswith("#"):
                if raw.startswith("#separator"):
                    sep_raw = raw.split(" ", 1)[1].strip()
                    if sep_raw.startswith("\\x"):
                        separator = chr(int(sep_raw[2:], 16))
                elif raw.startswith("#set_separator"):
                    set_separator = raw.split(separator, 1)[1]
                elif raw.startswith("#empty_field"):
                    empty_field = raw.split(separator, 1)[1]
                elif raw.startswith("#unset_field"):
                    unset_field = raw.split(separator, 1)[1]
                elif raw.startswith("#fields"):
                    fields = raw.split(separator)[1:]
                continue
            if not raw or fields is None:
                continue
            values = raw.split(separator)
            row: dict[str, Any] = {}
            for name, val in zip(fields, values):
                if val == unset_field:
                    row[name] = None
                elif val == empty_field:
                    row[name] = ""
                elif set_separator in val and name.endswith("s"):
                    row[name] = val.split(set_separator)
                else:
                    row[name] = val
            yield row


def _row_timestamp(row: dict[str, Any]) -> datetime | None:
    ts = row.get("ts")
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc)
    except (TypeError, ValueError):
        return None


def _notice_to_proto(row: dict[str, Any], *, source_path: Path) -> ProtoFinding:
    note = row.get("note") or ""
    src = row.get("src") or ""
    dst = row.get("dst") or ""
    msg = row.get("msg") or note or "Zeek notice"
    # Severity isn't in the log itself; Zeek notices default to medium
    # — they're "something noteworthy happened." Scoring will apply
    # the tool-default confidence on top.
    target_identifier = dst or src or "unknown"

    normalized = {
        "log_type": "notice",
        "note": note,
        "src": src,
        "dst": dst,
        "msg": msg,
    }

    return ProtoFinding(
        target_identifier=target_identifier,
        target_type="ip",
        raw_severity="medium",
        raw_confidence=None,
        title=f"Zeek notice: {note}" if note else str(msg),
        raw=row,
        normalized=normalized,
        observed_at=_row_timestamp(row),
    )


register_parser("zeek", parse)
