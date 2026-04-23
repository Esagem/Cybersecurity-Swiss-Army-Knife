"""Parser interface and common data carriers.

A parser is any callable with the ``parse(path) -> ParseResult``
shape. Parsers are pure functions of their input bytes — they do
not touch the database. The orchestrator in ``ingest/pipeline.py``
takes their output and performs target resolution, scoring, dedup,
and storage.

This keeps parsers testable from a single source file without a
SQLite fixture, and makes it trivial to add a new tool later: a new
file under ``ingest/<tool>/``, a parser function, a scoring entry,
and a dedup rule.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Protocol


@dataclass
class ProtoFinding:
    """A finding as it comes out of a parser — unscored, no Target
    resolved, no dedup key yet. The orchestrator fills in those fields
    and writes the Finding row.
    """

    # Identifier string (host, URL, subdomain, IP, etc.) that this
    # finding attaches to. The orchestrator runs this through target
    # resolution to pick / promote / create the Target row.
    target_identifier: str
    target_type: str  # domain | subdomain | ip | host | url | service | person

    # Raw tool-severity string (or tool-reported number), pre-mapping.
    # The orchestrator converts this with scoring.map_severity.
    raw_severity: str | int | None

    # Tool-reported confidence if any, otherwise None and the
    # tool default kicks in.
    raw_confidence: str | None

    title: str
    raw: dict  # the tool's original row, preserved
    normalized: dict  # CSAK's internal shape (feeds into dedup key)
    observed_at: datetime | None = None  # per-row timestamp if the tool supplies one


@dataclass
class ParsedScan:
    """Metadata about one tool execution's output, as the parser sees it."""

    source_tool: str
    label: str
    scan_started_at: datetime
    scan_completed_at: datetime
    timestamp_source: str  # "extracted" | "fallback-ingested"
    notes: str = ""


@dataclass
class ParseResult:
    scan: ParsedScan
    findings: list[ProtoFinding] = field(default_factory=list)
    # Discovery-only identifiers: things a tool surfaced that aren't
    # findings (e.g. subfinder listing subdomains with no vuln attached).
    # Key = parent-target identifier, value = list of discovered children.
    discovered_identifiers: dict[str, list[str]] = field(default_factory=dict)


class Parser(Protocol):
    def __call__(self, path: Path) -> ParseResult: ...


ParserFn = Callable[[Path], ParseResult]
