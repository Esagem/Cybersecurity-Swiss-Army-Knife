import pytest

from csak.ingest.scoring import (
    CONFIDENCE_WEIGHTS,
    SEVERITY_WEIGHTS,
    compute_priority,
    map_severity,
)


def test_priority_is_product_of_all_axes() -> None:
    s = compute_priority(
        severity="high",
        confidence="medium",
        target_weight=1.5,
    )
    expected = SEVERITY_WEIGHTS["high"] * CONFIDENCE_WEIGHTS["medium"] * 1.5
    assert s.priority == pytest.approx(expected)
    assert s.severity_weight == SEVERITY_WEIGHTS["high"]
    assert s.confidence_weight == CONFIDENCE_WEIGHTS["medium"]


def test_unknown_severity_surfaces_between_info_and_medium() -> None:
    s = compute_priority(severity=None, confidence="high", target_weight=1.0)
    # Null severity sits above info but below medium so "needs review"
    # items are visible in a priority-sorted list.
    info_score = compute_priority(
        severity="info", confidence="high", target_weight=1.0
    ).priority
    medium_score = compute_priority(
        severity="medium", confidence="high", target_weight=1.0
    ).priority
    assert info_score < s.priority < medium_score


def test_target_weight_scales_priority_linearly() -> None:
    base = compute_priority(
        severity="high", confidence="high", target_weight=1.0
    ).priority
    doubled = compute_priority(
        severity="high", confidence="high", target_weight=2.0
    ).priority
    assert doubled == pytest.approx(base * 2.0)


def test_map_severity_nuclei_and_nessus() -> None:
    assert map_severity("nuclei", "Critical") == "critical"
    assert map_severity("nuclei", "informational") == "info"
    assert map_severity("nessus", "4") == "critical"
    assert map_severity("nessus", "0") == "info"
    # Unknown values fall through to None.
    assert map_severity("nuclei", "weirdval") is None
