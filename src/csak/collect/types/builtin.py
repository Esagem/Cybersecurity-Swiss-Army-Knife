"""The seven core target types slice 3 ships with.

Imported as a side effect of importing ``csak.collect.types`` — see the
package ``__init__`` for the wiring.

    network_block       parents: []           CIDR or ASN string
    host                parents: []           bare IP (or other "probeable")
    domain              parents: [host]       registrable apex hostname
    subdomain           parents: [host]       non-apex hostname
    url                 parents: []           scheme://host[/path]
    service             parents: []           host:port/proto
    finding_ref         parents: []           UUID-shaped Finding ID

Recognizer order is decided at classify time by the leaves-first walk
in ``classify``, so the order of registration in this file is purely
cosmetic (built-ins listed root-first to match the spec's table).
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from csak.collect.types import TargetType, register_type


# ── multi-label public-suffix table (carried forward from slice 2) ──
#
# Curated common multi-label public suffixes. Not exhaustive; covers
# the ones a real CSAK user is most likely to hit. Add as needed; the
# wrong-answer cost is small (an apex misclassified as subdomain skips
# subfinder, which the analyst can re-run with the correct apex).
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


def _is_plausible_hostname(host: str) -> bool:
    if len(host) > 253 or "." not in host:
        return False
    # Reject anything that parses as an IP address — those classify
    # as ``host``, not ``domain``/``subdomain``.
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    for label in host.split("."):
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        for ch in label:
            if not (ch.isalnum() or ch == "-"):
                return False
    # Last label must contain at least one alpha character — a TLD
    # cannot be purely numeric. Catches edge cases like ``1.2.3.4``
    # that pass ``ip_address`` only on Python's IPv4-strict parser.
    last = host.rsplit(".", 1)[-1]
    if not any(ch.isalpha() for ch in last):
        return False
    return True


# ── network_block ──────────────────────────────────────────────────


def _recognizes_network_block(value: str) -> bool:
    raw = value.strip()
    # ASN — case-insensitive ``AS<digits>``.
    if len(raw) > 2 and raw[:2].lower() == "as" and raw[2:].isdigit():
        return True
    # CIDR — must contain a slash and parse as a network. Reject
    # service strings that happen to contain a slash (host:port/proto).
    if "/" in raw and not _looks_like_service(raw):
        try:
            ipaddress.ip_network(raw, strict=False)
            return True
        except (ValueError, TypeError):
            return False
    return False


def _parse_network_block(value: str) -> dict:
    raw = value.strip()
    if raw[:2].lower() == "as" and raw[2:].isdigit():
        return {"asn": "AS" + raw[2:], "kind": "asn"}
    try:
        net = ipaddress.ip_network(raw, strict=False)
        return {"cidr": str(net), "version": net.version, "kind": "cidr"}
    except (ValueError, TypeError):
        return {}


# ── host ────────────────────────────────────────────────────────────


def _recognizes_host(value: str) -> bool:
    """Bare IP only at this layer.

    Hostnames classify as ``domain`` or ``subdomain`` (which inherit
    from ``host``). The matcher widens via the parent chain, so a tool
    that ``accepts: ["host"]`` still routes domain and subdomain
    candidates through correctly.
    """
    raw = value.strip()
    if "/" in raw or "://" in raw:
        return False
    try:
        ipaddress.ip_address(raw)
        return True
    except ValueError:
        return False


def _parse_host(value: str) -> dict:
    raw = value.strip()
    try:
        addr = ipaddress.ip_address(raw)
        return {"address": str(addr), "version": addr.version, "kind": "ip"}
    except ValueError:
        return {"hostname": raw.lower(), "kind": "hostname"}


# ── domain / subdomain ──────────────────────────────────────────────


def _hostname_label_count(value: str) -> int:
    return len(value.strip().lower().split("."))


def _is_apex(host: str) -> bool:
    parts = host.split(".")
    if len(parts) == 2:
        return True
    if len(parts) == 3:
        last_two = ".".join(parts[-2:])
        if last_two in _MULTI_LABEL_SUFFIXES:
            return True
    return False


def _recognizes_domain(value: str) -> bool:
    raw = value.strip().lower()
    if "://" in raw or "/" in raw or ":" in raw:
        return False
    if not _is_plausible_hostname(raw):
        return False
    return _is_apex(raw)


def _recognizes_subdomain(value: str) -> bool:
    raw = value.strip().lower()
    if "://" in raw or "/" in raw or ":" in raw:
        return False
    if not _is_plausible_hostname(raw):
        return False
    if _is_apex(raw):
        return False
    return _hostname_label_count(raw) >= 3


def _parse_hostname(value: str) -> dict:
    raw = value.strip().lower()
    parts = raw.split(".")
    return {
        "hostname": raw,
        "labels": parts,
        "label_count": len(parts),
        "tld": parts[-1] if parts else "",
    }


# ── url ─────────────────────────────────────────────────────────────


def _recognizes_url(value: str) -> bool:
    raw = value.strip()
    if "://" not in raw:
        return False
    try:
        parsed = urlparse(raw)
    except ValueError:
        return False
    return parsed.scheme in ("http", "https") and bool(parsed.hostname)


def _parse_url(value: str) -> dict:
    parsed = urlparse(value.strip())
    return {
        "scheme": parsed.scheme,
        "host": parsed.hostname,
        "port": parsed.port,
        "path": parsed.path or "/",
        "query": parsed.query,
    }


# ── service ─────────────────────────────────────────────────────────

_SERVICE_RE = re.compile(
    r"^(?P<host>\[[^\]]+\]|[^:\s]+):(?P<port>\d{1,5})/(?P<proto>tcp|udp|sctp)$",
    re.IGNORECASE,
)


def _looks_like_service(value: str) -> bool:
    """Cheap pre-check used by ``network_block`` to avoid false-CIDR matches."""
    return bool(_SERVICE_RE.match(value.strip()))


def _recognizes_service(value: str) -> bool:
    raw = value.strip()
    if "://" in raw:
        return False
    m = _SERVICE_RE.match(raw)
    if m is None:
        return False
    port = int(m.group("port"))
    return 0 < port < 65536


def _parse_service(value: str) -> dict:
    m = _SERVICE_RE.match(value.strip())
    if m is None:  # pragma: no cover - guarded by recognizer
        return {}
    host = m.group("host")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return {
        "host": host,
        "port": int(m.group("port")),
        "proto": m.group("proto").lower(),
    }


# ── finding_ref ─────────────────────────────────────────────────────

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _recognizes_finding_ref(value: str) -> bool:
    return bool(_UUID_RE.match(value.strip()))


def _parse_finding_ref(value: str) -> dict:
    return {"finding_id": value.strip().lower()}


# ── registration ────────────────────────────────────────────────────


def _register_builtins() -> None:
    register_type(TargetType(
        name="network_block",
        parents=[],
        recognizes=_recognizes_network_block,
        parse=_parse_network_block,
    ))
    register_type(TargetType(
        name="host",
        parents=[],
        recognizes=_recognizes_host,
        parse=_parse_host,
    ))
    register_type(TargetType(
        name="domain",
        parents=["host"],
        recognizes=_recognizes_domain,
        parse=_parse_hostname,
    ))
    register_type(TargetType(
        name="subdomain",
        parents=["host"],
        recognizes=_recognizes_subdomain,
        parse=_parse_hostname,
    ))
    register_type(TargetType(
        name="url",
        parents=[],
        recognizes=_recognizes_url,
        parse=_parse_url,
    ))
    register_type(TargetType(
        name="service",
        parents=[],
        recognizes=_recognizes_service,
        parse=_parse_service,
    ))
    register_type(TargetType(
        name="finding_ref",
        parents=[],
        recognizes=_recognizes_finding_ref,
        parse=_parse_finding_ref,
    ))


# Idempotent registration: if this module is re-imported (or
# ``reset_registry_for_tests`` was called), put the builtins back.
from csak.collect.types import _TYPES  # noqa: E402

if "host" not in _TYPES:
    _register_builtins()
