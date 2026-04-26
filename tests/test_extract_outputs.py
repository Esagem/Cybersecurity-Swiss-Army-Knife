"""Slice 3 ``Tool.extract_outputs`` per built-in tool.

Each tool reads its own JSONL artifact format; we feed each a small
fixture and assert on the typed values it harvests. Invalid strings
in the artifact must be silently dropped — recursion's correctness
depends on it.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from csak.collect.tools import HTTPX, NUCLEI, SUBFINDER


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n",
        encoding="utf-8",
    )


def test_subfinder_extract_classifies_each_host(tmp_path: Path) -> None:
    artifact = tmp_path / "subdomains.jsonl"
    _write_jsonl(artifact, [
        {"host": "api.acme.com", "input": "acme.com"},
        {"host": "dev.acme.com", "input": "acme.com"},
        {"host": "not a hostname"},  # silently dropped
    ])
    extracted = SUBFINDER.extract_outputs(artifact, scan=None)
    types = {t.type for t in extracted}
    values = {t.value for t in extracted}
    assert "subdomain" in types
    assert "api.acme.com" in values
    assert "dev.acme.com" in values
    # "not a hostname" was rejected by classify and silently dropped.
    assert all(t.value != "not a hostname" for t in extracted)


def test_httpx_extract_only_responding_rows(tmp_path: Path) -> None:
    artifact = tmp_path / "live-hosts.jsonl"
    _write_jsonl(artifact, [
        {
            "url": "https://api.acme.com",
            "host": "api.acme.com",
            "status_code": 200,
            "tech": ["nginx"],
            "title": "Login",
        },
        {
            "url": "https://dead.acme.com",
            "host": "dead.acme.com",
            # No status_code — host didn't respond. Drop it.
        },
    ])
    extracted = HTTPX.extract_outputs(artifact, scan=None)
    assert len(extracted) == 1
    target = extracted[0]
    assert target.type == "url"
    assert target.value == "https://api.acme.com"
    assert target.metadata["status"] == 200
    assert target.metadata["tech"] == ["nginx"]
    assert target.metadata["title"] == "Login"


def test_nuclei_extract_pulls_matched_at_and_extracted(tmp_path: Path) -> None:
    artifact = tmp_path / "findings.jsonl"
    _write_jsonl(artifact, [
        {
            "template-id": "exposed-config",
            "matched-at": "https://api.acme.com/.env",
            "extracted-results": ["https://api.acme.com/admin"],
        },
        {
            "template-id": "tech",
            "matched-at": "api.acme.com",  # bare host, classifies as subdomain
        },
        {
            "template-id": "no-match-field",
            "extracted-results": ["not a typed value"],
        },
    ])
    extracted = NUCLEI.extract_outputs(artifact, scan=None)
    values = [t.value for t in extracted]
    assert "https://api.acme.com/.env" in values
    assert "https://api.acme.com/admin" in values
    assert "api.acme.com" in values
    # Free-form string was dropped.
    assert "not a typed value" not in values


def test_extract_outputs_missing_artifact_returns_empty(tmp_path: Path) -> None:
    """Defensive: a stage whose artifact never landed (failed run)
    should not crash the recursion runner.
    """
    missing = tmp_path / "does-not-exist.jsonl"
    assert SUBFINDER.extract_outputs(missing, scan=None) == []
    assert HTTPX.extract_outputs(missing, scan=None) == []
    assert NUCLEI.extract_outputs(missing, scan=None) == []
