from __future__ import annotations

import pytest

from csak.collect.detect import detect_target_type


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
        # IPs.
        ("10.0.0.42", "ip"),
        ("192.168.1.1", "ip"),
        ("2001:db8::1", "ip"),
        ("::1", "ip"),
        # CIDR.
        ("10.0.0.0/24", "cidr"),
        ("10.0.0.42/24", "cidr"),     # host bits set, strict=False
        ("2001:db8::/64", "cidr"),
        # URL.
        ("https://api.acmecorp.com/v2/users", "url"),
        ("http://10.0.0.1:8080/admin", "url"),
        # Invalid.
        ("", "invalid"),
        ("   ", "invalid"),
        ("not-a-host", "invalid"),     # single label
        ("ftp://nope.com", "invalid"), # non-http(s) scheme
        ("https://", "invalid"),       # scheme but no host
        ("acme.com/", "invalid"),       # trailing slash without scheme treated as cidr-like; we expect invalid
        ("a..b.com", "invalid"),       # empty label
        ("-bad.com", "invalid"),       # leading hyphen
        ("bad-.com", "invalid"),       # trailing hyphen
    ],
)
def test_detect_target_type(target: str, expected: str) -> None:
    assert detect_target_type(target) == expected


def test_detect_handles_none_like_inputs() -> None:
    # We accept str only; defensive against weird call sites.
    assert detect_target_type("") == "invalid"


def test_long_label_rejected() -> None:
    long_label = "a" * 64
    assert detect_target_type(f"{long_label}.com") == "invalid"
