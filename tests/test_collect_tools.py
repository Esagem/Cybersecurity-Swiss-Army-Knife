"""Per-tool catalog module tests.

Each catalog module is a small data class plus four pure methods —
applies_to, invocation, parse_progress, detect_rate_limit_signal.
These tests cover the bits that aren't otherwise tested via the
integration tests.
"""
from __future__ import annotations

import pytest

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


def test_httpx_includes_default_port_set_per_mode() -> None:
    """Bare-host targets should probe more than 80/443 — common dev,
    admin, and HTTP-alt ports must be in the default set."""
    from csak.collect.tools.httpx import DEFAULT_PORTS

    for mode in ("quick", "standard", "deep"):
        argv = HTTPX.invocation(
            target="10.0.0.1",
            target_type="ip",
            mode=mode,  # type: ignore[arg-type]
            input_file=None,
            output_file="/tmp/out.jsonl",
        )
        assert "-ports" in argv
        ports = argv[argv.index("-ports") + 1]
        assert ports == DEFAULT_PORTS[mode]
        # Sanity: every mode covers the most common HTTP(S) + 8080/8443.
        for p in ("80", "443", "8080", "8443"):
            assert p in ports.split(","), f"port {p} missing from {mode} default"


def test_httpx_user_supplied_ports_override_replaces_default() -> None:
    """Passing --httpx-ports should replace the mode default, not duplicate -ports."""
    argv = HTTPX.invocation(
        target="10.0.0.1",
        target_type="ip",
        mode="standard",
        input_file=None,
        output_file="/tmp/out.jsonl",
        overrides={"ports": "9999"},
    )
    # -ports appears exactly once and carries the user-supplied value.
    assert argv.count("-ports") == 1
    assert argv[argv.index("-ports") + 1] == "9999"


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


def test_httpx_parse_progress_handles_current_v1_6_format() -> None:
    """Current httpx (v1.6+) emits stats in a new shape with no
    ``Stats:`` token and no ``Errors:`` field. Verified by capturing
    ``httpx -silent -stats -si 1`` against a multi-host input."""
    line = "[0:00:05] | RPS: 12 | Requests: 87 | Hosts: 34/50 (68%)"
    p = HTTPX.parse_progress(line)
    assert p is not None
    assert p.count == 34
    assert p.total == 50
    assert p.percent == 68
    assert p.rps == 12
    assert p.errors == 0  # new format has no errors counter


def test_httpx_rate_limit_detected_for_429_or_503() -> None:
    HTTPX._last_errors = 0
    assert HTTPX.detect_rate_limit_signal("[INF] http response: 429") is True
    assert HTTPX.detect_rate_limit_signal("[INF] http response: 503") is True


def test_httpx_rate_limit_does_not_fire_on_error_spike_stats() -> None:
    """The error-spike heuristic was removed — it generated false
    positives on small targets where most templates probe non-existent
    services. Only explicit 429/503 should trigger."""
    HTTPX._last_errors = 5
    line = "[INF] Stats: 100/200 (50%) | RPS: 30 | Errors: 50 | Duration: 5s"
    assert HTTPX.detect_rate_limit_signal(line) is False


# ---------------------------------------------------------------------------
# Nuclei
# ---------------------------------------------------------------------------


def test_nuclei_applies_to_every_valid_type() -> None:
    for t in ("domain", "subdomain", "ip", "cidr", "url"):
        assert NUCLEI.applies_to(t) is True  # type: ignore[arg-type]
    assert NUCLEI.applies_to("invalid") is False  # type: ignore[arg-type]


def test_nuclei_skipped_in_quick_mode() -> None:
    """Per spec §Modes — quick mode skips nuclei entirely. Quick is
    'tell me what's there' reconnaissance (subfinder + httpx surface
    discovery), not 'find vulnerabilities' — that's standard's job."""
    assert NUCLEI.is_skipped_by_mode("quick") is True
    assert NUCLEI.is_skipped_by_mode("standard") is False
    assert NUCLEI.is_skipped_by_mode("deep") is False


def test_nuclei_quick_mode_invocation_raises() -> None:
    """Calling .invocation(mode='quick') should fail — quick should
    never reach the runner because the router filters nuclei out via
    is_skipped_by_mode. If it does, that's a routing bug worth catching."""
    with pytest.raises(ValueError):
        NUCLEI.invocation(
            target="acme.com",
            target_type="domain",
            mode="quick",
            input_file=None,
            output_file="/tmp/out",
        )


def test_nuclei_invocation_severity_per_mode() -> None:
    """Standard now includes ``info`` so real-world risks tagged ``info``
    by nuclei (EOL software, missing security headers, generic env-file
    disclosure) reach csak's triage layer instead of being silently
    dropped at the scanner. Discovered via the integration harness
    baseline against the heavy target."""
    standard = NUCLEI.invocation(
        target="acme.com",
        target_type="domain",
        mode="standard",
        input_file="/tmp/in",
        output_file="/tmp/out",
    )
    assert "info,low,medium,high,critical" in standard

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
    """Per spec §Adaptive rate limiting — only explicit rate-limit
    indicators (429/503/rate-limit/too-many-requests/retry-after)
    in [WRN]/[ERR] lines count as signals."""
    assert NUCLEI.detect_rate_limit_signal(
        "[WRN] [cve-test] got HTTP 429 Too Many Requests from target"
    ) is True
    assert NUCLEI.detect_rate_limit_signal(
        "[WRN] [tpl] response: 503 Service Unavailable"
    ) is True
    assert NUCLEI.detect_rate_limit_signal(
        "[WRN] [tpl] rate limit exceeded; backing off"
    ) is True
    assert NUCLEI.detect_rate_limit_signal(
        "[ERR] retry-after: 30s from upstream"
    ) is True


def test_nuclei_generic_network_failures_are_not_rate_limit_signals() -> None:
    """Connection refused / context deadline exceeded fire on closed
    ports against small targets — not rate limiting. Treating them as
    rate-limit signals causes false-positive throttling that slows
    every scan against a host that doesn't run every probed service."""
    assert NUCLEI.detect_rate_limit_signal(
        "[WRN] [cve-test] Could not execute request for: context deadline exceeded"
    ) is False
    assert NUCLEI.detect_rate_limit_signal(
        "[WRN] [cve-test] connection refused"
    ) is False
    assert NUCLEI.detect_rate_limit_signal(
        "[WRN] [cve-test] connection reset by peer"
    ) is False
    # Unrelated warning still doesn't trigger.
    assert NUCLEI.detect_rate_limit_signal("[WRN] unrelated warning") is False


def test_nuclei_rate_limit_does_not_fire_on_stats_error_spike() -> None:
    """Removed heuristic regression test: a rising errors counter in
    stats lines (legacy or JSON) must NOT trigger rate halving on its
    own. nuclei against a small target inflates error counts whenever
    templates probe services the host doesn't run — that's not rate
    limiting, just inapplicable templates. Only the [WRN]/[ERR]
    pattern matchers and 429/503 (per spec) should signal."""
    NUCLEI._last_errors = 0
    legacy = "[INF] Stats: requests=500, errors=30, RPS=40, percent=20"
    assert NUCLEI.detect_rate_limit_signal(legacy) is False

    json_line = '{"requests":"500","errors":"30","percent":"20","rps":"40"}'
    NUCLEI._last_errors = 0
    assert NUCLEI.detect_rate_limit_signal(json_line) is False


def test_nuclei_progress_parsing() -> None:
    line = "[INF] Stats: requests=1234, errors=23, RPS=45, percent=15"
    p = NUCLEI.parse_progress(line)
    assert p is not None
    assert p.count == 1234
    assert p.errors == 23
    assert p.rps == 45
    assert p.percent == 15


def test_nuclei_progress_parsing_handles_v3_json_format() -> None:
    """nuclei v3+ emits stats as JSON to stderr instead of the old
    ``Stats: requests=… errors=… …`` key=value format. Verified by
    capturing real nuclei v3.8 output. Without this parser the live
    progress bar stays stuck at 'starting…' for the entire run."""
    line = (
        '{"duration":"0:00:05","errors":"49","hosts":"1","matched":"0",'
        '"percent":"3","requests":"532","rps":"101",'
        '"templates":"6537","total":"14894",'
        '"startedAt":"2026-04-25T16:42:19.0919857-05:00"}'
    )
    p = NUCLEI.parse_progress(line)
    assert p is not None
    assert p.count == 532
    assert p.total == 14894
    assert p.percent == 3
    assert p.rps == 101
    assert p.errors == 49


def test_nuclei_progress_parsing_skips_non_stats_json() -> None:
    """Some other JSON line (e.g. a finding) must not trick the parser."""
    finding = '{"template":"some-template","host":"127.0.0.1","matched-at":"http://x"}'
    assert NUCLEI.parse_progress(finding) is None
