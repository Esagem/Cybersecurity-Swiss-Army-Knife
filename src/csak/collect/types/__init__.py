"""Runtime type registry for slice 3.

The registry holds named target types — each with a recognizer (string
→ bool) and a parser (string → component dict). Built-ins register at
import; plugins register their own types via the same entry point.

Public surface, all importable from ``csak.collect.types``:

    TargetType            dataclass — one row in the registry
    TypedTarget           dataclass — a value classified as a type
    InvalidTargetError    raised by classify() when no type matches
    register_type(t)      add a TargetType to the registry
    classify(value)       string → TypedTarget (most-specific match)
    matches(t, accepts)   subtype-aware membership test
    validate_registry()   list[str] of validation errors (empty if OK)
    types_in_registry()   list of registered type names
    get_type(name)        TargetType lookup, or None

The shape is deliberately small: ``classify`` is the single seam for
type detection (used by the CLI on ``--target`` and by every tool's
``extract_outputs``); ``matches`` is the single seam for routing
("does this candidate fit this tool's accepts list, accounting for
subtypes").

See ``cyber-wiki/wiki/specs/slice-3.md §Type system`` for the design
discussion.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


class InvalidTargetError(ValueError):
    """``classify`` could not match the value against any registered type.

    Caught by the CLI at ``--target`` resolution to print a clear
    error; caught silently by tool ``extract_outputs`` implementations
    so non-typed strings in artifacts (response bodies, error text,
    free-form fields) don't take the run down.
    """


class TypeRegistrationError(ValueError):
    """Plugin or built-in tried to register an invalid TargetType.

    The constructor of ``register_type`` raises this for collisions
    against an existing name. ``validate_registry`` checks the broader
    invariants (parent cycles, undefined references) and surfaces them
    as a list of messages, not exceptions, so callers can present them
    all at once.
    """


@dataclass
class TargetType:
    """A registry entry."""

    name: str
    parents: list[str]
    recognizes: Callable[[str], bool]
    parse: Callable[[str], dict]


@dataclass
class TypedTarget:
    """A string value classified as one of the registered types."""

    type: str
    value: str
    metadata: dict = field(default_factory=dict)
    source_finding_id: str | None = None
    parsed: dict = field(default_factory=dict)


# ── runtime registry ────────────────────────────────────────────────

_TYPES: dict[str, TargetType] = {}
_REGISTRATION_ORDER: list[str] = []


def register_type(t: TargetType) -> None:
    """Add ``t`` to the registry. Raises on name collision.

    Plugins and built-ins both use this entry point; there is no
    distinction between them in the runtime registry.
    """
    if not isinstance(t, TargetType):
        raise TypeRegistrationError(
            f"register_type expects a TargetType, got {type(t).__name__}"
        )
    if t.name in _TYPES:
        raise TypeRegistrationError(
            f"type {t.name!r} is already registered; pick a unique name"
        )
    _TYPES[t.name] = t
    _REGISTRATION_ORDER.append(t.name)


def get_type(name: str) -> TargetType | None:
    return _TYPES.get(name)


def types_in_registry() -> list[str]:
    """Return type names in registration order. Used by ``csak doctor``
    and ``csak tools show`` for stable output.
    """
    return list(_REGISTRATION_ORDER)


def reset_registry_for_tests() -> None:
    """Clear the registry. **Tests only** — production code never needs
    to call this.
    """
    _TYPES.clear()
    _REGISTRATION_ORDER.clear()


# ── classification ─────────────────────────────────────────────────


def classify(value: str) -> TypedTarget:
    """Walk types from leaves to roots; return the most-specific match.

    A leaf is a type with parents (e.g. ``subdomain`` whose parent is
    ``host``). When ``api.acme.com`` matches both ``subdomain`` and
    ``host``, we want ``subdomain`` — so leaves are checked first.

    Raises ``InvalidTargetError`` when no type matches; the caller
    decides whether that's user-facing (CLI ``--target`` errors out)
    or silent (a tool's ``extract_outputs`` skips a string that isn't a
    typed value, e.g. a response body).
    """
    if not isinstance(value, str):
        raise InvalidTargetError(
            f"classify expects a string, got {type(value).__name__}"
        )
    raw = value.strip()
    if not raw:
        raise InvalidTargetError("empty target")

    for name in _ordered_leaves_first():
        t = _TYPES[name]
        try:
            if t.recognizes(raw):
                parsed = t.parse(raw) if t.parse is not None else {}
                return TypedTarget(type=name, value=raw, parsed=parsed)
        except Exception:
            # A buggy recognizer must not take the whole classifier
            # down. Skip it; validation will catch broken plugins.
            continue
    raise InvalidTargetError(f"target {value!r} does not match any registered type")


def matches(candidate_type: str, accepts: list[str]) -> bool:
    """``True`` iff ``candidate_type`` or any ancestor is in ``accepts``.

    A tool that wants strict matching declares only the leaf type it
    accepts (e.g. subfinder accepts ``["domain"]`` and won't widen to
    ``subdomain``). A tool that wants any kind of host declares the
    base (httpx accepts ``["host"]`` and matches both ``domain`` and
    ``subdomain`` via subtype widening).
    """
    if candidate_type in accepts:
        return True
    t = _TYPES.get(candidate_type)
    if t is None:
        return False
    for parent in t.parents:
        if matches(parent, accepts):
            return True
    return False


def _ordered_leaves_first() -> list[str]:
    """Sort registered types so deeper-in-the-hierarchy names come first.

    Ties broken by registration order — stable across Python runs as
    long as plugins import in the same order.
    """

    def depth(name: str, _seen: set[str] | None = None) -> int:
        seen = _seen or set()
        if name in seen:
            return 0  # cycle — handled by validation
        seen = seen | {name}
        t = _TYPES.get(name)
        if t is None or not t.parents:
            return 0
        return 1 + max((depth(p, seen) for p in t.parents), default=0)

    return sorted(_REGISTRATION_ORDER, key=lambda n: (-depth(n), _REGISTRATION_ORDER.index(n)))


# ── validation ─────────────────────────────────────────────────────


def validate_registry() -> list[str]:
    """Return human-readable validation messages. Empty list = OK.

    Checks per spec §Type registry validation:
    * No duplicate names. (``register_type`` raises eagerly, so this
      check only ever fires if someone bypassed the entry point.)
    * No cycles in the parent chain.
    * All ``parents`` references resolve to registered types.
    """
    errors: list[str] = []

    seen_names: set[str] = set()
    for name in _REGISTRATION_ORDER:
        if name in seen_names:
            errors.append(f"duplicate registration of type {name!r}")
        seen_names.add(name)

    for name, t in _TYPES.items():
        for p in t.parents:
            if p not in _TYPES:
                errors.append(
                    f"type {name!r} declares unknown parent {p!r} — "
                    f"register the parent type or fix the spelling"
                )

    for name in _TYPES:
        if _has_cycle(name):
            errors.append(
                f"type {name!r} participates in a parent-chain cycle"
            )

    return errors


def _has_cycle(start: str) -> bool:
    seen: set[str] = set()
    stack = [start]
    while stack:
        cur = stack.pop()
        if cur in seen:
            return True
        seen.add(cur)
        t = _TYPES.get(cur)
        if t is None:
            continue
        for p in t.parents:
            if p == start:
                return True
            stack.append(p)
    return False


def validate_tool_accepts_produces(
    tool_name: str, accepts: list[str], produces: list[str]
) -> list[str]:
    """Validate that a tool's accepts/produces references resolve.

    Used by ``csak doctor`` after plugin discovery to catch a plugin
    that says ``accepts: ["pcap"]`` when no ``pcap`` type is registered.
    Returns an empty list when everything resolves.
    """
    errors: list[str] = []
    for t in accepts:
        if t not in _TYPES:
            errors.append(
                f"tool {tool_name!r} accepts unknown type {t!r}"
            )
    for t in produces:
        if t not in _TYPES:
            errors.append(
                f"tool {tool_name!r} produces unknown type {t!r}"
            )
    return errors


# Pull in the seven core types as a side effect of importing this
# package, mirroring how ``csak/collect/__init__.py`` triggers tool
# registration. Plugins register additional types (and tools) as part
# of their import in ``csak.collect.plugins``.
from csak.collect.types import builtin as _builtin  # noqa: E402, F401
