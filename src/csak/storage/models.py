"""Dataclass representations of the storage entities.

These are plain data carriers used between modules. They do not know
how to load or save themselves — `repository.py` does that.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

# Keep the two textual enums as string constants. sqlite has no native
# enum type and cross-module imports of `str` literals keep the parsers
# from dragging in a heavier library.

SEVERITY_VALUES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
CONFIDENCE_VALUES: tuple[str, ...] = ("high", "medium", "low")
STATUS_VALUES: tuple[str, ...] = (
    "active",
    "suppressed",
    "accepted-risk",
    "false-positive",
    "fixed",
)
TIMESTAMP_SOURCE_VALUES: tuple[str, ...] = ("extracted", "fallback-ingested")


@dataclass
class Org:
    id: str
    name: str
    slug: str
    notes: str = ""
    created: datetime | None = None
    updated: datetime | None = None
    deleted_at: datetime | None = None


@dataclass
class Target:
    id: str
    org_id: str
    name: str
    type: str
    identifiers: list[str] = field(default_factory=list)
    parent_target_id: str | None = None
    target_weight: float = 1.0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    deleted_at: datetime | None = None


@dataclass
class Artifact:
    id: str
    org_id: str
    source_tool: str
    received_at: datetime
    path: str
    hash: str
    period_hint: str | None = None


@dataclass
class Scan:
    id: str
    org_id: str
    source_tool: str
    label: str
    scan_started_at: datetime
    scan_completed_at: datetime
    timestamp_source: str  # extracted | fallback-ingested
    artifact_ids: list[str] = field(default_factory=list)
    target_ids: list[str] = field(default_factory=list)
    ingested_at: datetime | None = None
    notes: str = ""


@dataclass
class Finding:
    id: str
    org_id: str
    target_id: str
    source_tool: str
    source_artifact_id: str
    dedup_key: str
    title: str
    severity: str | None
    confidence: str
    priority: float
    severity_weight: float
    confidence_weight: float
    raw: dict  # JSON-compatible
    normalized: dict  # JSON-compatible
    first_seen: datetime
    last_seen: datetime
    status: str = "active"
    tags: list[str] = field(default_factory=list)
    deleted_at: datetime | None = None


@dataclass
class FindingScanOccurrence:
    finding_id: str
    scan_id: str
    seen_at: datetime
