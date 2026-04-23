"""Deterministic scoring at ingest time.

`priority = severity_weight * confidence_weight * target_weight`

Severity comes from the tool (mapped via a per-tool table); confidence
either comes from the tool or defaults to a tool-specific constant that
reflects how much we trust that tool's raw output. Target weight lives
on the Target row and is analyst-editable.

These tables are intentionally small and explicit. They can be moved
to on-disk config later; slice 1 keeps them inline so the score path
is auditable at a single source.
"""
from __future__ import annotations

from dataclasses import dataclass

SEVERITY_WEIGHTS: dict[str | None, float] = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.5,
    "low": 0.25,
    "info": 0.05,
    None: 0.4,  # "needs analyst review" — surface above info, below medium.
}

CONFIDENCE_WEIGHTS: dict[str, float] = {
    "high": 1.0,
    "medium": 0.7,
    "low": 0.4,
}

# Per-tool mappings for raw severity strings or numbers onto the CSAK
# 5-point scale. Unknown values fall back to None ("needs analyst
# review"); the reader flags that explicitly in the reports.

NUCLEI_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "unknown": None,  # type: ignore[dict-item]
}

NESSUS_SEVERITY_MAP: dict[str, str | None] = {
    # Nessus plugin severity: 0=info, 1=low, 2=medium, 3=high, 4=critical.
    "0": "info",
    "1": "low",
    "2": "medium",
    "3": "high",
    "4": "critical",
    # Some plugins report "None" textually.
    "none": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

# Tools that don't self-report confidence get a default based on how
# much the tool tends to produce false positives or noise. The numbers
# are deliberate — Nuclei's high-signal templates are trusted more than
# Nessus's broad plugin set; osquery is ground truth.
DEFAULT_CONFIDENCE: dict[str, str] = {
    "nuclei": "high",
    "nessus": "medium",
    "zeek": "medium",
    "osquery": "high",
    "subfinder": "high",
    "httpx": "high",
    "manual": "medium",
}


@dataclass
class Score:
    severity: str | None
    confidence: str
    severity_weight: float
    confidence_weight: float
    priority: float


def compute_priority(
    *,
    severity: str | None,
    confidence: str,
    target_weight: float,
) -> Score:
    sw = SEVERITY_WEIGHTS.get(severity, SEVERITY_WEIGHTS[None])
    cw = CONFIDENCE_WEIGHTS.get(confidence, CONFIDENCE_WEIGHTS["medium"])
    priority = sw * cw * target_weight
    return Score(
        severity=severity,
        confidence=confidence,
        severity_weight=sw,
        confidence_weight=cw,
        priority=priority,
    )


def map_severity(source_tool: str, raw: str | int | None) -> str | None:
    if raw is None:
        return None
    s = str(raw).strip().lower()
    if source_tool == "nuclei":
        return NUCLEI_SEVERITY_MAP.get(s)
    if source_tool == "nessus":
        return NESSUS_SEVERITY_MAP.get(s)
    # Tools without a self-reported severity scale (zeek, osquery,
    # subfinder, httpx) apply their own ruleset in the parser and hand
    # us the CSAK severity string directly. We accept it if it's valid.
    if s in {"critical", "high", "medium", "low", "info"}:
        return s
    return None
