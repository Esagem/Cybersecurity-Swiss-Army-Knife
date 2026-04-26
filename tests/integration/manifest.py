"""Ground-truth schema for csak integration tests.

A test target declares an ``Expectation`` per intentionally-introduced
exposure. After running ``csak collect``, the harness checks whether
each expectation was satisfied by **any** finding in the database.

Each expectation supplies one or more *matchers* — substrings the
harness searches for in the finding's title, target URL, or
template-id metadata. An expectation is satisfied when at least one
matcher hits at least one finding.

When an expectation is currently unsatisfiable (e.g. no upstream
nuclei template covers the case, or csak doesn't run a tool that
would catch it), mark it ``known_gap=True`` with a short rationale.
The harness still reports the miss but doesn't fail CI on it — so
the gap stays visible without being noisy.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Severity = Literal["info", "low", "medium", "high", "critical"]


@dataclass(frozen=True)
class Expectation:
    """One thing the test target intentionally exposes that csak
    *should* surface as a finding."""

    description: str
    """Human-readable summary, e.g. ``\".env file leaks AWS keys\"``."""

    vuln_class: str
    """Free-form taxonomy bucket — ``\"secret-leak\"``, ``\"version-disclosure\"``,
    ``\"open-redirect\"``, etc. Used for grouping in the report."""

    expected_severity: Severity
    """The minimum severity the matched finding should carry. ``low``
    matches low/medium/high/critical."""

    title_contains: tuple[str, ...] = ()
    """Substrings any of which must appear (case-insensitively) in
    the finding's title for a match. At least one of ``title_contains``,
    ``target_path_contains``, or ``template_id_contains`` is required."""

    target_path_contains: tuple[str, ...] = ()
    """Substrings any of which must appear in the finding's target
    URL/path."""

    template_id_contains: tuple[str, ...] = ()
    """Substrings any of which must appear in the nuclei template id
    (when stored in evidence/metadata)."""

    known_gap: bool = False
    """Set True when this expectation can't currently be satisfied —
    e.g. the upstream tool has no template, or csak doesn't run the
    tool that would catch it. Counted in the report but doesn't fail
    the assertion."""

    known_gap_reason: str | None = None
    """One-line explanation of *why* it's a known gap so future
    maintainers can revisit (e.g. ``\"nuclei lacks a template for
    cookie security flags; needs a custom check\"``)."""


@dataclass(frozen=True)
class TargetSpec:
    """A spawnable test target with its full ground-truth manifest."""

    name: str
    """Stable identifier for the target, e.g. ``\"heavy\"``."""

    description: str

    expectations: tuple[Expectation, ...]
    """All things the harness expects csak to find. Order doesn't
    matter; each is matched independently."""

    # The launcher: a callable that returns ``(stop_fn, target_arg)``.
    # ``stop_fn()`` shuts the target down. ``target_arg`` is what the
    # harness passes to ``csak collect --target``.
    launcher: object = field(default=None)


# The harness's coverage report shape.
@dataclass(frozen=True)
class ExpectationOutcome:
    expectation: Expectation
    matched_findings: tuple[str, ...]   # finding IDs that satisfied this
    matched: bool
    severity_warnings: tuple[str, ...] = ()  # one note per matched finding whose severity was below expected


@dataclass(frozen=True)
class CoverageReport:
    target_name: str
    findings_total: int
    expectations_total: int
    hits: tuple[ExpectationOutcome, ...]
    misses: tuple[ExpectationOutcome, ...]            # not satisfied AND not known_gap
    known_gaps: tuple[ExpectationOutcome, ...]        # not satisfied BUT known_gap
    unexpected_findings: tuple[str, ...]              # findings IDs that no expectation claimed

    @property
    def coverage_pct(self) -> float:
        """Fraction of *enforceable* expectations that were satisfied,
        ignoring known gaps."""
        enforceable = len(self.hits) + len(self.misses)
        if enforceable == 0:
            return 1.0
        return len(self.hits) / enforceable
