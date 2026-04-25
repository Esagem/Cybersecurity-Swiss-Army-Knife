from __future__ import annotations

import pytest

from csak.collect.router import route


@pytest.mark.parametrize(
    "target_type,mode,expected_tools,expected_skipped",
    [
        # Domain → full pipeline in standard.
        ("domain", "standard", ["subfinder", "httpx", "nuclei"], []),
        # Domain in deep mode runs everything.
        ("domain", "deep", ["subfinder", "httpx", "nuclei"], []),
        # Quick mode skips nuclei everywhere.
        ("domain", "quick", ["subfinder", "httpx"], ["nuclei"]),
        ("subdomain", "quick", ["httpx"], ["subfinder", "nuclei"]),
        # Subdomain → skip subfinder.
        ("subdomain", "standard", ["httpx", "nuclei"], ["subfinder"]),
        # IP → skip subfinder.
        ("ip", "standard", ["httpx", "nuclei"], ["subfinder"]),
        # CIDR → skip subfinder.
        ("cidr", "standard", ["httpx", "nuclei"], ["subfinder"]),
        # URL → skip subfinder + httpx; nuclei alone.
        ("url", "standard", ["nuclei"], ["subfinder", "httpx"]),
        # URL + quick → nothing applies.
        ("url", "quick", [], ["subfinder", "httpx", "nuclei"]),
    ],
)
def test_routing_matrix(
    target_type: str,
    mode: str,
    expected_tools: list[str],
    expected_skipped: list[str],
) -> None:
    routed = route(target_type, mode)  # type: ignore[arg-type]
    assert [t.name for t in routed.tools] == expected_tools
    assert sorted(routed.skipped.keys()) == sorted(expected_skipped)


def test_invalid_target_skips_everything() -> None:
    routed = route("invalid", "standard")  # type: ignore[arg-type]
    assert routed.tools == []
    assert sorted(routed.skipped.keys()) == ["httpx", "nuclei", "subfinder"]


def test_skip_reasons_are_human_readable() -> None:
    routed = route("ip", "standard")  # type: ignore[arg-type]
    assert "subdomain" in routed.skipped["subfinder"].lower()


def test_quick_mode_reason_mentions_mode() -> None:
    routed = route("domain", "quick")  # type: ignore[arg-type]
    assert "quick" in routed.skipped["nuclei"]
