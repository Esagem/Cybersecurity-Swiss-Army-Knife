"""Target type detection.

Slice 2 spec §Target type detection and tool routing defines the rules.
This module implements them. One function: ``detect_target_type``.

The detection has to work without internet lookups. We don't depend on
``tldextract`` — bringing in the full PSL is heavy for the value.
Instead we use a small curated set of common multi-label public
suffixes (``co.uk``, ``com.au``, etc.). The handful we miss falls back
to "subdomain" when the host has 3+ labels, which is the right answer
for the *vast* majority of real targets even when our suffix table is
incomplete (a real apex like ``example.co.uk`` would land as subdomain
of the (non-existent) parent ``co.uk`` — slightly wrong category, but
the tool routing matrix gives the same tools either way for
``domain`` and ``subdomain`` — see Note below).

Note on the domain/subdomain distinction: per the routing matrix in
the spec, the ONLY routing difference is that Subfinder runs for
domains and not for subdomains. False classification of an apex as
subdomain just skips Subfinder; the analyst can re-run with the
correct apex if they want subdomain enumeration. The cost of being
wrong is small.
"""
from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from csak.collect.tool import TargetType


# Curated common multi-label public suffixes. Not exhaustive; covers
# the ones a slice 2 user is most likely to hit. Add as needed; the
# wrong-answer cost is small (see module docstring).
_MULTI_LABEL_SUFFIXES: frozenset[str] = frozenset(
    {
        "co.uk", "ac.uk", "gov.uk", "org.uk", "net.uk", "ltd.uk", "plc.uk",
        "co.jp", "ne.jp", "ac.jp", "go.jp", "or.jp",
        "co.kr", "or.kr", "ne.kr",
        "co.za", "org.za", "gov.za", "ac.za",
        "co.nz", "org.nz", "net.nz", "ac.nz", "govt.nz",
        "co.in", "net.in", "org.in", "gov.in", "ac.in", "edu.in",
        "co.id", "ac.id", "or.id", "go.id",
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
        "com.br", "net.br", "org.br", "gov.br", "edu.br",
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
        "com.hk", "net.hk", "org.hk", "gov.hk", "edu.hk",
        "com.tw", "net.tw", "org.tw", "gov.tw", "edu.tw",
        "com.mx", "com.tr", "com.sg", "com.ar", "com.ph", "com.my", "com.pe",
        "com.ve", "com.uy", "com.ec", "com.co", "com.do", "com.ng",
    }
)


def detect_target_type(target: str) -> TargetType:
    """Classify ``target`` per the slice 2 detection rules.

    Returns one of ``"domain"``, ``"subdomain"``, ``"ip"``, ``"cidr"``,
    ``"url"``, or ``"invalid"``.
    """
    if not target or not isinstance(target, str):
        return "invalid"

    raw = target.strip()
    if not raw:
        return "invalid"

    # 1. URL — anything with a scheme is treated as a URL even if the
    # host part might also parse as something else.
    if "://" in raw:
        try:
            parsed = urlparse(raw)
        except ValueError:
            return "invalid"
        if parsed.scheme in ("http", "https") and parsed.hostname:
            return "url"
        return "invalid"

    # 2. CIDR — must contain a slash AND parse as a network. We accept
    # both v4 and v6, and we accept host bits being set (``strict=False``)
    # so the user can paste ``10.0.0.42/24`` and have CSAK do the right
    # thing.
    if "/" in raw:
        try:
            ipaddress.ip_network(raw, strict=False)
            return "cidr"
        except (ValueError, TypeError):
            return "invalid"

    # 3. Bare IP.
    try:
        ipaddress.ip_address(raw)
        return "ip"
    except ValueError:
        pass

    # 4. Hostname — domain vs subdomain based on label count and the
    # multi-label suffix table.
    if not _is_plausible_hostname(raw):
        return "invalid"
    return _classify_hostname(raw.lower())


def _is_plausible_hostname(host: str) -> bool:
    """Cheap hostname validity check.

    Real validation is RFC 1035; we only need to reject obvious
    garbage so callers get an early "invalid" instead of a runtime
    failure when the tool tries to resolve.
    """
    if len(host) > 253:
        return False
    if "." not in host:
        # Single-label "host" — too ambiguous to classify.
        return False
    for label in host.split("."):
        if not label:
            return False
        if len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        for ch in label:
            if not (ch.isalnum() or ch == "-"):
                return False
    return True


def _classify_hostname(host: str) -> TargetType:
    parts = host.split(".")
    n = len(parts)

    if n == 2:
        # acme.com — apex by definition.
        return "domain"

    # 3+ labels: check for multi-label suffix.
    last_two = ".".join(parts[-2:])
    if last_two in _MULTI_LABEL_SUFFIXES:
        # acme.co.uk → apex. www.acme.co.uk → subdomain.
        return "domain" if n == 3 else "subdomain"

    # Otherwise 3+ labels with a single-label TLD = subdomain.
    return "subdomain"
