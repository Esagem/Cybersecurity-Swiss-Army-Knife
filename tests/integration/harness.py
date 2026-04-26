"""Coverage harness: launch a test target, run csak collect, diff
findings against the target's ground-truth manifest, print a report.

Usage::

    python -m tests.integration.harness heavy
    python -m tests.integration.harness heavy --mode deep
    python -m tests.integration.harness heavy --mode deep --csak-quiet

Exit codes:
    0 — every enforceable expectation was satisfied (known gaps allowed)
    1 — at least one enforceable expectation missed
    2 — fixture / setup error

The harness operates entirely on a temporary csak DB so it doesn't
pollute the user's local data. Each invocation is a clean slate.
"""
from __future__ import annotations

import argparse
import sqlite3
import subprocess
import sys
import tempfile
import time

# Force UTF-8 so the report's ✓/✗/· glyphs round-trip on Windows pipes.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass
from dataclasses import dataclass
from pathlib import Path

from csak.storage import db as csak_db
from csak.storage import repository as csak_repo
from csak.storage.models import Finding

from tests.integration.manifest import (
    CoverageReport,
    Expectation,
    ExpectationOutcome,
    TargetSpec,
)
from tests.integration.targets.heavy import HEAVY_TARGET

REGISTRY: dict[str, TargetSpec] = {
    HEAVY_TARGET.name: HEAVY_TARGET,
}

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# ---------------------------------------------------------------------------
# Matching: does any finding satisfy this expectation?
# ---------------------------------------------------------------------------


def _finding_haystack(f: Finding) -> tuple[str, str, str]:
    """Return (title, target_url, template_id) lowercased, ready for substring matching.
    All three may be empty strings if the finding doesn't carry that field."""
    title = (f.title or "").lower()
    norm = f.normalized or {}
    raw = f.raw or {}
    target_url = (
        norm.get("matched-at") or norm.get("matched_at") or norm.get("url")
        or norm.get("host") or ""
    ).lower()
    template_id = (
        norm.get("template-id") or norm.get("template_id")
        or raw.get("template-id") or raw.get("template_id") or ""
    ).lower()
    return title, target_url, template_id


def _expectation_matches(expect: Expectation, f: Finding) -> bool:
    """A finding satisfies an expectation when it matches *every*
    declared matcher category (title / path / template). Severity is
    NOT a gate — it's a quality signal surfaced separately. Otherwise
    a real csak hit at lower-than-expected severity would look like
    a miss, and we'd never see severity-downgrade regressions
    independently of detection regressions.
    """
    title, target_url, template_id = _finding_haystack(f)

    title_ok = (
        not expect.title_contains
        or any(kw.lower() in title for kw in expect.title_contains)
    )
    path_ok = (
        not expect.target_path_contains
        or any(kw.lower() in target_url for kw in expect.target_path_contains)
    )
    template_ok = (
        not expect.template_id_contains
        or any(kw.lower() in template_id for kw in expect.template_id_contains)
    )

    matchers = (
        bool(expect.title_contains),
        bool(expect.target_path_contains),
        bool(expect.template_id_contains),
    )
    if not any(matchers):
        raise ValueError(
            f"Expectation {expect.description!r} declares no matchers; "
            "give it at least one of title_contains / target_path_contains / template_id_contains."
        )

    return (
        (not expect.title_contains or title_ok)
        and (not expect.target_path_contains or path_ok)
        and (not expect.template_id_contains or template_ok)
    )


def _severity_mismatch(expect: Expectation, f: Finding) -> str | None:
    """Return a human-readable note if the finding's severity is below
    the expectation's expected_severity, else None."""
    sev_rank = _SEVERITY_RANK.get((f.severity or "info").lower(), 0)
    expected_rank = _SEVERITY_RANK.get(expect.expected_severity, 0)
    if sev_rank < expected_rank:
        return (
            f"severity downgrade: expected ≥ {expect.expected_severity} "
            f"but got {f.severity}"
        )
    return None


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


@dataclass
class HarnessConfig:
    target_name: str
    mode: str = "standard"
    csak_quiet: bool = False
    timeout_seconds: float = 600.0


def run(cfg: HarnessConfig) -> tuple[CoverageReport, list[Finding]]:
    spec = REGISTRY.get(cfg.target_name)
    if spec is None:
        raise SystemExit(f"unknown target {cfg.target_name!r}; "
                         f"available: {sorted(REGISTRY)}")

    if spec.launcher is None:
        raise SystemExit(f"target {cfg.target_name!r} has no launcher")

    workdir = Path(tempfile.mkdtemp(prefix=f"csak-coverage-{cfg.target_name}-"))
    db_path = workdir / "csak.db"
    artifacts_dir = workdir / "artifacts"
    artifacts_dir.mkdir()

    print(f"[harness] target = {spec.name}  mode = {cfg.mode}")
    print(f"[harness] tmpdir = {workdir}")
    print(f"[harness] launching target...")

    stop_target, target_arg = spec.launcher()  # type: ignore[misc]
    try:
        # Initialise a fresh csak DB.
        conn = csak_db.connect(str(db_path))
        try:
            org = csak_repo.create_org(conn, name="harness", slug="harness")
        finally:
            conn.close()

        print(f"[harness] running csak collect against {target_arg}...")
        t0 = time.monotonic()
        # ``--no-adaptive-rate`` makes the run deterministic. The
        # adaptive limiter halves nuclei's rate every time it sees
        # repeated errors, and a tiny test target generates plenty
        # (probing port 443 when nothing's listening, etc.) — that
        # rate halving was causing flaky .env / DS_Store detection
        # across runs.
        result = subprocess.run(
            [
                sys.executable, "-m", "csak",
                "--db", str(db_path),
                "--artifacts-dir", str(artifacts_dir),
                "collect",
                "--org", "harness",
                "--target", target_arg,
                "--mode", cfg.mode,
                "--no-adaptive-rate",
                "--quiet" if cfg.csak_quiet else "--no-quiet",
            ],
            capture_output=True,
            text=True,
            timeout=cfg.timeout_seconds,
        )
        elapsed = time.monotonic() - t0
        print(f"[harness] csak collect exit={result.returncode} "
              f"elapsed={elapsed:.1f}s")
        if result.returncode != 0:
            print("[harness] csak collect failed; stderr:")
            print(result.stderr)
            print("[harness] stdout:")
            print(result.stdout)
            raise SystemExit(2)
        if not cfg.csak_quiet:
            # Pass through csak's own progress so the run is debuggable.
            sys.stdout.write(result.stdout)

        # Read findings back.
        conn = csak_db.connect(str(db_path))
        try:
            findings = csak_repo.list_findings_for_org(conn, org.id)
        finally:
            conn.close()

        print(f"[harness] csak produced {len(findings)} findings.")

        return _diff(spec, findings), findings
    finally:
        stop_target()


def _diff(spec: TargetSpec, findings: list[Finding]) -> CoverageReport:
    findings_by_id = {f.id: f for f in findings}
    matched_ids: set[str] = set()
    hits: list[ExpectationOutcome] = []
    misses: list[ExpectationOutcome] = []
    known_gaps: list[ExpectationOutcome] = []

    for expect in spec.expectations:
        sat: list[str] = []
        warns: list[str] = []
        for f in findings:
            try:
                if _expectation_matches(expect, f):
                    sat.append(f.id)
                    note = _severity_mismatch(expect, f)
                    if note:
                        warns.append(f"{f.id[:8]}: {note}")
            except ValueError as e:
                # Surface schema bugs immediately.
                raise SystemExit(f"manifest error: {e}")
        outcome = ExpectationOutcome(
            expectation=expect,
            matched_findings=tuple(sat),
            matched=bool(sat),
            severity_warnings=tuple(warns),
        )
        if sat:
            hits.append(outcome)
            matched_ids.update(sat)
        elif expect.known_gap:
            known_gaps.append(outcome)
        else:
            misses.append(outcome)

    unexpected = tuple(
        fid for fid in findings_by_id if fid not in matched_ids
    )
    return CoverageReport(
        target_name=spec.name,
        findings_total=len(findings),
        expectations_total=len(spec.expectations),
        hits=tuple(hits),
        misses=tuple(misses),
        known_gaps=tuple(known_gaps),
        unexpected_findings=unexpected,
    )


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def _print_report(report: CoverageReport, findings: list[Finding] | None = None) -> None:
    print()
    print("=" * 78)
    print(f"COVERAGE REPORT — target={report.target_name}  "
          f"findings={report.findings_total}  "
          f"expectations={report.expectations_total}")
    print(f"  enforceable coverage: {report.coverage_pct:.0%} "
          f"({len(report.hits)}/{len(report.hits) + len(report.misses)})")
    print(f"  known-gap expectations:  {len(report.known_gaps)}")
    print(f"  unexpected findings:     {len(report.unexpected_findings)}")
    print("=" * 78)

    if report.hits:
        print(f"\n[hit] {len(report.hits)} expectation(s) satisfied:")
        for o in report.hits:
            print(f"  ✓ [{o.expectation.vuln_class:<26}] {o.expectation.description}")
            for fid in o.matched_findings:
                print(f"      via finding {fid[:8]}")
            for warn in o.severity_warnings:
                print(f"      ⚠ {warn}")

    if report.misses:
        print(f"\n[MISS] {len(report.misses)} enforceable expectation(s) not satisfied:")
        for o in report.misses:
            print(f"  ✗ [{o.expectation.vuln_class:<26}] {o.expectation.description}")
            print(f"      expected severity ≥ {o.expectation.expected_severity}")
            if o.expectation.title_contains:
                print(f"      title would contain: {o.expectation.title_contains}")
            if o.expectation.target_path_contains:
                print(f"      target would contain: {o.expectation.target_path_contains}")

    if report.known_gaps:
        print(f"\n[gap] {len(report.known_gaps)} known-gap expectation(s) "
              "(not failing CI):")
        for o in report.known_gaps:
            print(f"  · [{o.expectation.vuln_class:<26}] {o.expectation.description}")
            if o.expectation.known_gap_reason:
                print(f"      reason: {o.expectation.known_gap_reason}")

    if report.unexpected_findings:
        print(f"\n[unexpected] {len(report.unexpected_findings)} finding(s) "
              "with no claiming expectation:")
        if findings is not None:
            id_to_finding = {f.id: f for f in findings}
            for fid in report.unexpected_findings:
                f = id_to_finding.get(fid)
                if f is None:
                    continue
                print(f"  ? {fid[:8]} sev={f.severity} title={f.title!r}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=sorted(REGISTRY))
    parser.add_argument("--mode", choices=["quick", "standard", "deep"],
                        default="standard")
    parser.add_argument("--csak-quiet", action="store_true",
                        help="Suppress csak's own progress output.")
    parser.add_argument("--timeout", type=float, default=600.0,
                        help="Hard timeout for the csak subprocess.")
    args = parser.parse_args()

    cfg = HarnessConfig(
        target_name=args.target,
        mode=args.mode,
        csak_quiet=args.csak_quiet,
        timeout_seconds=args.timeout,
    )
    report, findings = run(cfg)
    _print_report(report, findings=findings)

    if report.misses:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
