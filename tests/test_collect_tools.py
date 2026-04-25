"""Per-tool catalog module tests.

Each catalog module is a small data class plus four pure methods —
applies_to, invocation, parse_progress, detect_rate_limit_signal.
These tests cover the bits that aren't otherwise tested via the
integration tests.
"""
from __future__ import annotations

from csak.collect.tools.httpx import HTTPX
from csak.collect.tools.nuclei import NUCLEI
from csak.collect.tools.subfinder import SUBFINDER


# ---------------------------------------------------------------------------
# Subfinder
# ---------------------------------------------------------------------------


def test_subfinder_only_applies_to_apex_domains() -> None:
    assert SUBFINDER.applies_to("domain") is True
    assert SUBFINDER.applies_to("subdomain") is False
    assert SUBFINDER.applies_to("ip") is False
    assert SUBFINDER.applies_to("cidr") is False
    assert SUBFINDER.applies_to("url") is False


def test_subfinder_invocation_includes_target_and_output() -> None:
    argv = SUBFINDER.invocation(
        target="acme.com",
        target_type="domain",
        mode="standard",
        input_file=None,
        output_file="/tmp/out.jsonl",
    )
    assert "-d" in argv
    assert argv[argv.index("-d") + 1] == "acme.com"
    assert "-o" in argv
    assert argv[argv.index("-o") + 1] == "/tmp/out.jsonl"
    # Mode-specific flags.
    assert "-all" in argv
    assert "-silent" in argv
    assert "-duc" in argv


def test_subfinder_quick_mode_drops_all_flag() -> None:
    argv = SUBFINDER.invocation(
        target="acme.com",
        target_type="domain",
        mode="quick",
        input_file=None,
        output_file="/tmp/out.jsonl",
    )
    assert "-all" not in argv


def test_subfinder_deep_mode_includes_recursive() -> None:
    argv = SUBFINDER.invocation(
        target="acme.com",
        target_type="domain",
        mode="deep",
        input_file=None,
        output_file="/tmp/out.jsonl",
    )
    assert "-recursive" in argv


def test_subfinder_progress_and_rate_limit_are_no_op() -> None:
    assert SUBFINDER.parse_progress("anything") is None
    assert SUBFINDER.detect_rate_limit_signal("anything") is False
    assert SUBFINDER.is_skipped_by_mode("quick") is False


def test_subfinder_overrides_pass_through() -> None:
    argv = SUBFINDER.invocation(
        target="acme.com",
        target_type="domain",
        mode="standard",
        input_file=None,
        output_file="/tmp/out",
        overrides={"rate_limit": "30"},
    )
    assert "-rl" in argv
    assert argv[argv.index("-rl") + 1] == "30"


# ---------------------------------------------------------------------------
# httpx
# ---------------------------------------------------------------------------


def test_httpx_applies_to_everything_but_url() -> None:
    assert HTTPX.applies_to("domain") is True
    assert HTTPX.applies_to("subdomain") is True
    assert HTTPX.applies_to("ip") is True
    assert HTTPX.applies_to("cidr") is True
    assert HTTPX.applies_to("url") is False


def test_httpx_uses_l_when_input_file_present() -> None:
    argv = HTTPX.invocation(
        target="acme.com",
        target_type="domain",
        mode="standard",
        input_file="/tmp/subs.txt",
        output_file="/tmp/out.jsonl",
    )
    assert "-l" in argv
    assert argv[argv.index("-l") + 1] == "/tmp/subs.txt"
    assert "-u" not in argv


def test_httpx_uses_u_when_no_input_file() -> None:
    argv = HTTPX.invocation(
        target="10.0.0.1",
        target_type="ip",
        mode="standard",
        input_file=None,
        output_file="/tmp/out.jsonl",
    )
    assert "-u" in argv
    assert argv[argv.index("-u") + 1] == "10.0.0.1"


def test_httpx_parse_progress_extracts_stats() -> None:
    line = "[INF] Stats: 234/500 (46%) | RPS: 45 | Errors: 12 | Duration: 5s"
    p = HTTPX.parse_progress(line)
    assert p is not None
    assert p.count == 234
    assert p.total == 500
    assert p.percent == 46
    assert p.rps == 45
    assert p.errors == 12


def test_httpx_parse_progress_returns_none_for_unrelated_lines() -> None:
    assert HTTPX.parse_progress("[WRN] some random message") is None


def test_httpx_rate_limit_detected_for_429_or_503() -> None:
    HTTPX._last_errors = 0
    assert HTTPX.detect_rate_limit_signal("[INF] http response: 429") is True
    assert HTTPX.detect_rate_limit_signal("[INF] http response: 503") is True


def test_httpx_rate_limit_detects_error_spike() -> None:
    HTTPX._last_errors = 5
    line = "[INF] Stats: 100/200 (50%) | RPS: 30 | Errors: 50 | Duration: 5s"
    assert HTTPX.detect_rate_limit_signal(line) is True
    # Subsequent quiet stats line should not re-trigger.
    quiet = "[INF] Stats: 150/200 (75%) | RPS: 30 | Errors: 51 | Duration: 10s"
    assert HTTPX.detect_rate_limit_signal(quiet) is False


# ---------------------------------------------------------------------------
# Nuclei
# ---------------------------------------------------------------------------


def test_nuclei_applies_to_every_valid_type() -> None:
    for t in ("domain", "subdomain", "ip", "cidr", "url"):
        assert NUCLEI.applies_to(t) is True  # type: ignore[arg-type]
    assert NUCLEI.applies_to("invalid") is False  # type: ignore[arg-type]


def test_nuclei_skipped_in_quick_mode() -> None:
    assert NUCLEI.is_skipped_by_mode("quick") is True
    assert NUCLEI.is_skipped_by_mode("standard") is False
    assert NUCLEI.is_skipped_by_mode("deep") is False


def test_nuclei_quick_mode_invocation_raises() -> None:
    import pytest

    with pytest.raises(ValueError):
        NUCLEI.invocation(
            target="acme.com",
            target_type="domain",
            mode="quick",
            input_file=None,
            output_file="/tmp/out",
        )


def test_nuclei_invocation_severity_per_mode() -> None:
    standard = NUCLEI.invocation(
        target="acme.com",
        target_type="domain",
        mode="standard",
        input_file="/tmp/in",
        output_file="/tmp/out",
    )
    assert "low,medium,high,critical" in standard
    assert "info,low,medium,high,critical" not in standard

    deep = NUCLEI.invocation(
        target="acme.com",
        target_type="domain",
        mode="deep",
        input_file="/tmp/in",
        output_file="/tmp/out",
    )
    assert "info,low,medium,high,critical" in deep
    assert "-irr" in deep


def test_nuclei_template_override() -> None:
    argv = NUCLEI.invocation(
        target="acme.com",
        target_type="domain",
        mode="standard",
        input_file="/tmp/in",
        output_file="/tmp/out",
        overrides={"templates": "/home/eli/templates"},
    )
    assert "-t" in argv
    assert argv[argv.index("-t") + 1] == "/home/eli/templates"


def test_nuclei_rate_limit_signal_from_warnings() -> None:
    assert (
        NUCLEI.detect_rate_limit_signal(
            "[WRN] [cve-test] Could not execute request for: context deadline exceeded"
        )
        is True
    )
    assert (
        NUCLEI.detect_rate_limit_signal(
            "[WRN] [cve-test] connection refused"
        )
        is True
    )
    # Unrelated warning does not trigger.
    assert (
        NUCLEI.detect_rate_limit_signal("[WRN] unrelated warning") is False
    )


def test_nuclei_rate_limit_signal_from_stats_spike() -> None:
    NUCLEI._last_errors = 0
    line = "[INF] Stats: requests=500, errors=30, RPS=40, percent=20"
    assert NUCLEI.detect_rate_limit_signal(line) is True
    follow = "[INF] Stats: requests=600, errors=31, RPS=40, percent=25"
    assert NUCLEI.detect_rate_limit_signal(follow) is False


def test_nuclei_progress_parsing() -> None:
    line = "[INF] Stats: requests=1234, errors=23, RPS=45, percent=15"
    p = NUCLEI.parse_progress(line)
    assert p is not None
    assert p.count == 1234
    assert p.errors == 23
    assert p.rps == 45
    assert p.percent == 15
