"""JSON renderer — a stable, versioned, self-describing serialization
of the report context.

Design goal from the spec: this is the interface for a future LLM
layer. Every field that appears in markdown or docx appears here,
plus machine-friendly metadata (schema version, generation timestamp,
source-tool attributions per finding).

Breaking changes to this shape must bump ``JSON_SCHEMA_VERSION`` in
``csak.query.context`` and be documented in the project changelog.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from csak.query.context import FindingView, MethodologyScan, ReportContext, TicketGroup


def serialize(ctx: ReportContext) -> dict:
    return {
        "schema": {
            "name": "csak.report",
            "version": ctx.schema_version,
            "csak_version": ctx.csak_version,
        },
        "report": {
            "kind": ctx.kind,
            "generated_at": _dt(ctx.generated_at),
            "org": {
                "id": ctx.org.id,
                "name": ctx.org.name,
                "slug": ctx.org.slug,
                "notes": ctx.org.notes,
            },
            "period": {
                "label": ctx.period.label,
                "start": _dt(ctx.period.start),
                "end": _dt(ctx.period.end),
            },
        },
        "summary": {
            "total_findings": len(ctx.findings),
            "by_severity": {
                sev: len(items) for sev, items in ctx.findings_by_severity.items()
            },
            "targets_touched": len(ctx.findings_by_target),
            "scans_contributing": len(ctx.methodology),
        },
        "methodology": [_scan(m) for m in ctx.methodology],
        "findings": [_finding(v) for v in ctx.findings],
        "tickets": [_ticket(t) for t in ctx.tickets],
    }


def _dt(d: datetime) -> str:
    return d.isoformat()


def _scan(m: MethodologyScan) -> dict:
    return {
        "id": m.scan.id,
        "source_tool": m.scan.source_tool,
        "label": m.scan.label,
        "started_at": _dt(m.scan.scan_started_at),
        "completed_at": _dt(m.scan.scan_completed_at),
        "timestamp_source": m.scan.timestamp_source,
        "finding_count": m.finding_count,
        "timestamp_disclaimer": m.timestamp_disclaimer,
        "artifact_ids": list(m.scan.artifact_ids),
    }


def _finding(v: FindingView) -> dict:
    f = v.finding
    return {
        "id": f.id,
        "title": f.title,
        "source_tool": f.source_tool,
        "source_artifact_id": f.source_artifact_id,
        "dedup_key": f.dedup_key,
        "target": {
            "id": v.target.id,
            "name": v.target.name,
            "type": v.target.type,
            "weight": v.target.target_weight,
            "parent_target_id": v.target.parent_target_id,
        },
        "severity": f.severity,
        "confidence": f.confidence,
        "priority": f.priority,
        "priority_components": {
            "severity_weight": f.severity_weight,
            "confidence_weight": f.confidence_weight,
            "target_weight": v.target.target_weight,
        },
        "status": f.status,
        "tags": list(f.tags),
        "first_seen": _dt(f.first_seen),
        "last_seen": _dt(f.last_seen),
        "seen_in_scans": [
            {
                "scan_id": s.id,
                "label": s.label,
                "source_tool": s.source_tool,
            }
            for s in v.scans
        ],
        "raw": f.raw,
        "normalized": f.normalized,
    }


def _ticket(t: TicketGroup) -> dict:
    return {
        "ticket_id": t.ticket_id,
        "title": t.title,
        "severity": t.severity,
        "priority": t.priority,
        "affected_assets": list(t.affected_assets),
        "slug": t.slug,
        "finding_ids": [v.finding.id for v in t.findings],
        "impact": t.impact,
        "remediation": t.remediation,
        "validation": t.validation,
    }


def write_report(ctx: ReportContext, out_path: Path, *, indent: int = 2) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(serialize(ctx), indent=indent, ensure_ascii=False),
        encoding="utf-8",
    )
    return out_path
