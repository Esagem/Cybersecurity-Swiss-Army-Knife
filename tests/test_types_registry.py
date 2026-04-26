"""Slice 3 type-registry mechanics.

Covers ``matches`` (subtype widening), ``register_type`` collision
behavior, and ``validate_registry`` failure modes that ``csak doctor``
surfaces. Classification per-input lives in test_classify.py.
"""
from __future__ import annotations

import pytest

from csak.collect.types import (
    InvalidTargetError,
    TargetType,
    TypeRegistrationError,
    classify,
    get_type,
    matches,
    register_type,
    types_in_registry,
    validate_registry,
    validate_tool_accepts_produces,
)


def test_matches_exact() -> None:
    assert matches("domain", ["domain"]) is True
    assert matches("domain", ["host"]) is True  # widening
    assert matches("subdomain", ["host"]) is True
    assert matches("host", ["domain"]) is False


def test_matches_url_does_not_widen_to_host() -> None:
    """URL is not a subtype of host. Routing must not feed URLs to
    tools that ``accepts: ["host"]`` only — that's a load-bearing
    invariant for httpx.
    """
    assert matches("url", ["host"]) is False


def test_matches_unknown_type_returns_false() -> None:
    assert matches("never_registered", ["host"]) is False


def test_register_type_rejects_duplicate() -> None:
    with pytest.raises(TypeRegistrationError):
        register_type(TargetType(
            name="host",
            parents=[],
            recognizes=lambda _: False,
            parse=lambda _: {},
        ))


def test_validate_registry_clean_for_builtins() -> None:
    assert validate_registry() == []


def test_validate_tool_accepts_produces_flags_unknown_types() -> None:
    errors = validate_tool_accepts_produces(
        "fancy",
        accepts=["host", "pcap"],
        produces=["nope"],
    )
    assert any("pcap" in e for e in errors)
    assert any("nope" in e for e in errors)


def test_get_type_returns_none_for_unregistered() -> None:
    assert get_type("never_registered") is None


def test_types_in_registry_includes_builtins() -> None:
    names = set(types_in_registry())
    assert {"network_block", "host", "domain", "subdomain", "url",
            "service", "finding_ref"} <= names


def test_classify_returns_typed_target_object() -> None:
    """Sanity: ``classify`` produces a ``TypedTarget`` whose value is
    the stripped input and whose ``parsed`` carries components the
    type's ``parse`` extracted.
    """
    t = classify("api.acme.com")
    assert t.type == "subdomain"
    assert t.value == "api.acme.com"
    assert t.parsed["label_count"] == 3
