"""Nessus parser.

Nessus Essentials emits a ``.nessus`` XML file that contains one
``<ReportHost>`` per host, each with ``<ReportItem>`` children for
every plugin that fired.

We pull out:
  * ``scan_started_at`` / ``scan_completed_at`` from the
    ``HOST_START`` / ``HOST_END`` host properties (the earliest
    start and latest end across all hosts).
  * One ProtoFinding per ReportItem. Nessus severities 0-4 map onto
    info/low/medium/high/critical.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from xml.etree import ElementTree as ET

from csak.ingest.parser import ParsedScan, ParseResult, ProtoFinding
from csak.ingest.pipeline import register_parser


def parse(path: Path) -> ParseResult:
    tree = ET.parse(path)
    root = tree.getroot()

    scan_started: datetime | None = None
    scan_completed: datetime | None = None
    findings: list[ProtoFinding] = []

    for host in root.iter("ReportHost"):
        host_name = host.get("name", "")
        props = _host_properties(host)
        host_ip = props.get("host-ip", host_name)
        start = _parse_nessus_date(props.get("HOST_START"))
        end = _parse_nessus_date(props.get("HOST_END"))
        if start is not None:
            scan_started = start if scan_started is None else min(scan_started, start)
        if end is not None:
            scan_completed = end if scan_completed is None else max(scan_completed, end)

        for item in host.findall("ReportItem"):
            findings.append(_item_to_proto(item, host_name=host_name, host_ip=host_ip))

    ingested_at = datetime.now(timezone.utc)
    if scan_started is None:
        scan_started = ingested_at
        timestamp_source = "fallback-ingested"
    else:
        timestamp_source = "extracted"
    if scan_completed is None:
        scan_completed = scan_started

    scan = ParsedScan(
        source_tool="nessus",
        label=_scan_label(root, scan_started),
        scan_started_at=scan_started,
        scan_completed_at=scan_completed,
        timestamp_source=timestamp_source,
    )
    return ParseResult(scan=scan, findings=findings)


def _host_properties(host: ET.Element) -> dict[str, str]:
    props: dict[str, str] = {}
    hp = host.find("HostProperties")
    if hp is None:
        return props
    for tag in hp.findall("tag"):
        name = tag.get("name")
        if name and tag.text:
            props[name] = tag.text
    return props


def _parse_nessus_date(value: str | None) -> datetime | None:
    if not value:
        return None
    # HOST_START / HOST_END are like "Tue Apr 21 14:30:22 2026".
    for fmt in ("%a %b %d %H:%M:%S %Y", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _scan_label(root: ET.Element, started: datetime) -> str:
    policy = root.find(".//Policy/policyName")
    name = policy.text if policy is not None and policy.text else "Nessus scan"
    return f"{name} {started.date().isoformat()}"


def _item_to_proto(
    item: ET.Element, *, host_name: str, host_ip: str
) -> ProtoFinding:
    plugin_id = item.get("pluginID", "")
    port = item.get("port", "")
    severity = item.get("severity", "0")
    plugin_name = item.get("pluginName", "") or f"plugin {plugin_id}"

    description = _child_text(item, "description")
    solution = _child_text(item, "solution")

    raw = {
        "plugin_id": plugin_id,
        "plugin_name": plugin_name,
        "severity": severity,
        "host": host_name,
        "host_ip": host_ip,
        "port": port,
        "protocol": item.get("protocol", ""),
        "svc_name": item.get("svc_name", ""),
        "description": description,
        "solution": solution,
    }

    normalized = {
        "plugin_id": plugin_id,
        "host": host_name or host_ip,
        "port": port,
        "title": plugin_name,
    }

    return ProtoFinding(
        target_identifier=host_name or host_ip,
        target_type="host",
        raw_severity=severity,
        raw_confidence=None,
        title=plugin_name,
        raw=raw,
        normalized=normalized,
    )


def _child_text(elem: ET.Element, tag: str) -> str:
    child = elem.find(tag)
    return (child.text or "").strip() if child is not None else ""


register_parser("nessus", parse)
