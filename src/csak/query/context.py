"""Report context builder.

Every renderer (markdown, docx, JSON) consumes the same
``ReportContext`` object. That's what keeps the three formats
aligned: same section order, same content, same source.

The context is built from one read transaction against SQLite and
holds plain dataclasses with no DB handles. Renderers are pure
functions of the context — they do not reach back to the database.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable

from csak import __version__
from csak.query.finders import (
    Period,
    findings_active_in_period,
    scans_contributing_to_period,
    targets_for_findings,
)
from csak.storage import repository as repo
from csak.storage.models import Finding, Org, Scan, Target


# Bump whenever the JSON schema changes shape in a breaking way.
# v2: removed `probability_real` from findings and from priority_components.
JSON_SCHEMA_VERSION = 2


REPORT_KINDS = ("internal-review", "fit-bundle")


@dataclass
class FindingView:
    """One finding as it appears in a report context.

    ``scans`` is the subset of methodology scans in which this finding
    was seen. That lets the renderer cite specific scan labels per
    finding.
    """

    finding: Finding
    target: Target
    scans: list[Scan]


@dataclass
class MethodologyScan:
    """A scan that contributed data to this report."""

    scan: Scan
    finding_count: int  # how many of this report's findings came from it
    timestamp_disclaimer: str | None  # non-None for fallback-ingested


@dataclass
class TicketGroup:
    """One fix-it ticket covering N Findings that share a dedup-key.

    The spec's rule: "multi-target findings sharing a dedup-key collapse
    into a single ticket listing all affected assets."
    """

    ticket_id: str  # e.g. "FIT-001"
    title: str
    severity: str | None
    priority: float  # max of the underlying findings' priorities
    findings: list[FindingView]
    affected_assets: list[str]
    slug: str
    impact: str
    remediation: str
    validation: str


@dataclass
class ReportContext:
    kind: str  # "internal-review" | "fit-bundle"
    org: Org
    period: Period
    generated_at: datetime

    # Full finding set, priority-descending.
    findings: list[FindingView]

    # Grouping views — both are populated regardless of kind; the
    # renderer picks which to walk based on the template.
    findings_by_severity: dict[str, list[FindingView]]
    findings_by_target: dict[str, list[FindingView]]

    # Methodology: which scans contributed.
    methodology: list[MethodologyScan]

    # Fix-it bundle view.
    tickets: list[TicketGroup]

    # For the JSON export's self-describing shape.
    schema_version: int = JSON_SCHEMA_VERSION
    csak_version: str = __version__


# ---------------------------------------------------------------------------


_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", None)


def build_context(
    conn: sqlite3.Connection,
    *,
    org: Org,
    period: Period,
    kind: str,
) -> ReportContext:
    if kind not in REPORT_KINDS:
        raise ValueError(f"unknown report kind {kind!r}; known: {REPORT_KINDS}")

    findings = findings_active_in_period(conn, org, period)
    contributing_scans = scans_contributing_to_period(conn, org, period)
    target_map = targets_for_findings(conn, findings)

    # Build per-finding views with their scan occurrences.
    scan_by_id = {s.id: s for s in contributing_scans}
    views: list[FindingView] = []
    for f in findings:
        scans = [
            scan_by_id[s.id]
            for s in repo.scans_for_finding(conn, f.id)
            if s.id in scan_by_id
        ]
        target = target_map.get(f.target_id)
        if target is None:
            target = repo.get_target(conn, f.target_id)
            if target is None:
                # This shouldn't happen with referential integrity, but
                # if the analyst softly deleted the target we skip the
                # finding rather than failing the whole report.
                continue
            target_map[target.id] = target
        views.append(FindingView(finding=f, target=target, scans=scans))

    # Counts per contributing scan.
    per_scan_count: dict[str, int] = {}
    for v in views:
        for s in v.scans:
            per_scan_count[s.id] = per_scan_count.get(s.id, 0) + 1

    methodology = [
        MethodologyScan(
            scan=s,
            finding_count=per_scan_count.get(s.id, 0),
            timestamp_disclaimer=(
                f"scan window is an approximation "
                f"(tool did not provide timestamps; ingested {s.ingested_at})"
                if s.timestamp_source == "fallback-ingested"
                else None
            ),
        )
        for s in contributing_scans
    ]

    by_severity = _group_by_severity(views)
    by_target = _group_by_target(views)
    tickets = _build_tickets(views)

    return ReportContext(
        kind=kind,
        org=org,
        period=period,
        generated_at=datetime.now(timezone.utc),
        findings=views,
        findings_by_severity=by_severity,
        findings_by_target=by_target,
        methodology=methodology,
        tickets=tickets,
    )


def _group_by_severity(views: Iterable[FindingView]) -> dict[str, list[FindingView]]:
    out: dict[str, list[FindingView]] = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "info": [],
        "unscored": [],
    }
    for v in views:
        key = v.finding.severity or "unscored"
        out.setdefault(key, []).append(v)
    # Sort each bucket by priority descending.
    for k in out:
        out[k].sort(key=lambda v: v.finding.priority, reverse=True)
    return out


def _group_by_target(views: Iterable[FindingView]) -> dict[str, list[FindingView]]:
    out: dict[str, list[FindingView]] = {}
    for v in views:
        out.setdefault(v.target.name, []).append(v)
    for k in out:
        out[k].sort(key=lambda v: v.finding.priority, reverse=True)
    return out


# ---------------------------------------------------------------------------
# Ticket grouping
# ---------------------------------------------------------------------------


def _build_tickets(views: list[FindingView]) -> list[TicketGroup]:
    """Collapse findings that share ``(source_tool, dedup_key)`` into
    one ticket. Slice-1 spec: "multi-target findings sharing a
    dedup-key collapse into a single ticket listing all affected
    assets."

    Most real dedup keys are host-specific, so most tickets end up
    wrapping a single finding — but when they don't, the collapse
    matters. We use the same-tool-same-dedup-key rule.
    """
    by_key: dict[tuple[str, str], list[FindingView]] = {}
    for v in views:
        key = (v.finding.source_tool, v.finding.dedup_key)
        by_key.setdefault(key, []).append(v)

    # Order tickets by the highest-priority finding they contain.
    ordered_keys = sorted(
        by_key.keys(),
        key=lambda k: max(v.finding.priority for v in by_key[k]),
        reverse=True,
    )

    tickets: list[TicketGroup] = []
    for idx, key in enumerate(ordered_keys, start=1):
        group = by_key[key]
        leader = max(group, key=lambda v: v.finding.priority)
        affected = sorted({v.target.name for v in group})
        tickets.append(
            TicketGroup(
                ticket_id=f"FIT-{idx:03d}",
                title=leader.finding.title,
                severity=leader.finding.severity,
                priority=leader.finding.priority,
                findings=sorted(
                    group, key=lambda v: v.finding.priority, reverse=True
                ),
                affected_assets=affected,
                slug=_slugify(leader.finding.title),
                impact=_default_impact(leader.finding),
                remediation=_default_remediation(leader.finding),
                validation=_default_validation(leader.finding),
            )
        )
    return tickets


def _slugify(s: str) -> str:
    import re

    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return (s or "finding")[:60]


def _default_impact(f: Finding) -> str:
    sev = f.severity or "unscored"
    return (
        f"A {sev}-severity finding was identified by {f.source_tool} against the "
        f"listed asset(s). Review and remediate per the steps below."
    )


def _default_remediation(f: Finding) -> str:
    # Pull through whatever the tool said about solution/remediation
    # if it survived normalization; otherwise a generic pointer.
    for key in ("solution", "remediation", "fix"):
        val = f.raw.get(key) if isinstance(f.raw, dict) else None
        if val:
            return str(val)
    return (
        f"Investigate using the details in the finding body. "
        f"For {f.source_tool} findings, refer to the tool's documentation "
        f"for template-specific remediation guidance."
    )


def _default_validation(f: Finding) -> str:
    return (
        f"Re-run {f.source_tool} against the affected asset(s); the finding "
        f"should no longer appear in the output."
    )
