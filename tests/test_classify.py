"""Replaces the slice 2 ``test_detect.py``.

Slice 3 substitutes the ``detect_target_type(target) -> str`` shim
with a runtime type registry. The behavior tested here is the same
classification rules as slice 2, just expressed against ``classify``
and with the renamed types (``ip`` → ``host``, ``cidr`` →
``network_block``). Invalid targets now raise ``InvalidTargetError``
rather than returning the literal ``"invalid"``.
"""
from __future__ import annotations

import pytest

from csak.collect.types import InvalidTargetError, classify


@pytest.mark.parametrize(
    "target,expected",
    [
        # Apex domains.
        ("acmecorp.com", "domain"),
        ("ACMECORP.COM", "domain"),  # case-insensitive
        ("example.io", "domain"),
        ("acme.co.uk", "domain"),       # multi-label suffix → 3-label apex
        ("acme.com.au", "domain"),
        # Subdomains.
        ("api.acmecorp.com", "subdomain"),
        ("a.b.acmecorp.com", "subdomain"),
        ("www.acme.co.uk", "subdomain"),  # 4 labels with multi-label suffix
        # IPs (slice 3: ``host``).
        ("10.0.0.42", "host"),
        ("192.168.1.1", "host"),
        ("2001:db8::1", "host"),
        ("::1", "host"),
        # CIDR (slice 3: ``network_block``).
        ("10.0.0.0/24", "network_block"),
        ("10.0.0.42/24", "network_block"),
        ("2001:db8::/64", "network_block"),
        ("AS15169", "network_block"),     # ASN
        # URL.
        ("https://api.acmecorp.com/v2/users", "url"),
        ("http://10.0.0.1:8080/admin", "url"),
        # Service.
        ("10.0.0.42:8080/tcp", "service"),
        ("[2001:db8::1]:443/tcp", "service"),
        # finding_ref.
        ("550e8400-e29b-41d4-a716-446655440000", "finding_ref"),
    ],
)
def test_classify_returns_expected_type(target: str, expected: str) -> None:
    assert classify(target).type == expected


@pytest.mark.parametrize(
    "target",
    [
        "",
        "   ",
        "not-a-host",     # single label
        "ftp://nope.com", # non-http(s) scheme
        "https://",       # scheme but no host
        "a..b.com",       # empty label
        "-bad.com",       # leading hyphen
        "bad-.com",       # trailing hyphen
    ],
)
def test_classify_invalid_raises(target: str) -> None:
    with pytest.raises(InvalidTargetError):
        classify(target)


def test_classify_long_label_invalid() -> None:
    long_label = "a" * 64
    with pytest.raises(InvalidTargetError):
        classify(f"{long_label}.com")


def test_classify_value_is_stripped() -> None:
    """Whitespace at the edges shouldn't break classification."""
    t = classify("  acme.com\n")
    assert t.type == "domain"
    assert t.value == "acme.com"


def test_classify_parsed_for_url_carries_components() -> None:
    t = classify("https://api.acme.com:8443/foo?x=1")
    assert t.type == "url"
    assert t.parsed["scheme"] == "https"
    assert t.parsed["host"] == "api.acme.com"
    assert t.parsed["port"] == 8443
    assert t.parsed["path"] == "/foo"
