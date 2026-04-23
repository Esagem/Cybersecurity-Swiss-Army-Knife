"""Tool-specific dedup keys.

Each parser emits a proto-finding with a ``normalized`` dict; these
helpers convert that into the stable key used to dedup findings for
(org_id, source_tool, dedup_key).

The keys here match the slice-1 spec:

- Nuclei: template-id + matched-at
- Nessus: plugin_id + host + port
- Zeek: event type-specific; for notice.log it's note + src + dst
- osquery: query name + row hash
- Subfinder: subdomain
- httpx: URL
"""
from __future__ import annotations

import hashlib
import json


def nuclei_key(normalized: dict) -> str:
    template_id = normalized.get("template-id") or normalized.get("template_id") or ""
    matched_at = normalized.get("matched-at") or normalized.get("matched_at") or ""
    return f"{template_id}|{matched_at}"


def nessus_key(normalized: dict) -> str:
    plugin_id = normalized.get("plugin_id", "")
    host = normalized.get("host", "")
    port = normalized.get("port", "")
    return f"{plugin_id}|{host}|{port}"


def zeek_key(normalized: dict) -> str:
    log_type = normalized.get("log_type", "")
    if log_type == "notice":
        note = normalized.get("note", "")
        src = normalized.get("src", "")
        dst = normalized.get("dst", "")
        return f"notice|{note}|{src}|{dst}"
    # Other Zeek log types: conservative fallback on event-type + a
    # stable hash of the normalized row so each distinct event still
    # dedupes cleanly within its own log.
    h = hashlib.sha256(
        json.dumps(normalized, sort_keys=True).encode("utf-8")
    ).hexdigest()[:16]
    return f"{log_type}|{h}"


def osquery_key(normalized: dict) -> str:
    query_name = normalized.get("query_name", "")
    row = normalized.get("row", {})
    row_hash = hashlib.sha256(
        json.dumps(row, sort_keys=True).encode("utf-8")
    ).hexdigest()[:16]
    return f"{query_name}|{row_hash}"


def subfinder_key(normalized: dict) -> str:
    return normalized.get("host", "")


def httpx_key(normalized: dict) -> str:
    return normalized.get("url", "")


_DISPATCH = {
    "nuclei": nuclei_key,
    "nessus": nessus_key,
    "zeek": zeek_key,
    "osquery": osquery_key,
    "subfinder": subfinder_key,
    "httpx": httpx_key,
}


def key_for(source_tool: str, normalized: dict) -> str:
    try:
        return _DISPATCH[source_tool](normalized)
    except KeyError as e:
        raise ValueError(f"no dedup rule for source_tool={source_tool!r}") from e
