"""Ingest orchestration.

One invocation of ``ingest_file`` or ``ingest_path``:

1. Hashes the input, creates or finds the Artifact (dedup at bytes level).
2. Invokes the registered parser for the tool, producing a ParseResult.
3. Opens a Scan row. Every proto-finding resolves to a Target (with
   promotion as needed), gets scored, and either creates a new Finding
   row or records a FindingScanOccurrence on the existing dedup-matched
   row.
4. Returns an IngestReport summarising what happened.

The orchestrator never mutates scoring or dedup rules directly — those
are imported from the scoring and dedup modules respectively.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from csak.ingest import dedup, scoring, targets
from csak.ingest.parser import ParseResult
from csak.storage import artifacts as art_store
from csak.storage import repository as repo
from csak.storage.models import Artifact, Finding, Scan


ParserFn = Callable[[Path], ParseResult]


@dataclass
class IngestReport:
    scan_id: str
    artifact_id: str
    new_findings: int = 0
    reoccurrences: int = 0
    skipped_no_target_change: int = 0
    target_ids: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# Parsers are registered lazily by ``csak.ingest.register_parser`` so
# that importing this module doesn't pull in every tool-specific
# parser. The register_* functions below are populated at package
# import time by the individual parser modules.
_PARSERS: dict[str, ParserFn] = {}


def register_parser(source_tool: str, fn: ParserFn) -> None:
    _PARSERS[source_tool] = fn


def get_parser(source_tool: str) -> ParserFn:
    try:
        return _PARSERS[source_tool]
    except KeyError as e:
        raise ValueError(
            f"no parser registered for tool {source_tool!r}; "
            f"known: {sorted(_PARSERS)}"
        ) from e


def ingest_path(
    conn: sqlite3.Connection,
    *,
    org_id: str,
    source_tool: str,
    path: Path,
    artifacts_root: Path,
    label: str | None = None,
    period_hint: str | None = None,
) -> IngestReport:
    """Top-level entry point. Accepts a file OR a directory — the parser
    decides whether the path is sensible for its tool.
    """
    parser = get_parser(source_tool)
    return _ingest(
        conn,
        org_id=org_id,
        source_tool=source_tool,
        path=path,
        parser=parser,
        artifacts_root=artifacts_root,
        label=label,
        period_hint=period_hint,
    )


def _ingest(
    conn: sqlite3.Connection,
    *,
    org_id: str,
    source_tool: str,
    path: Path,
    parser: ParserFn,
    artifacts_root: Path,
    label: str | None,
    period_hint: str | None,
) -> IngestReport:
    now = datetime.now(timezone.utc)

    # 1. Hash + Artifact. For directory inputs (Zeek), hash the
    # directory as a whole by hashing a stable ordering of its member
    # hashes — keeps dedup working when someone re-ingests the same
    # captured window.
    if path.is_dir():
        hash_ = _hash_directory(path)
        stored_path = _store_directory_manifest(artifacts_root, path, hash_)
    else:
        hash_, stored_path = art_store.store_file(artifacts_root, path)

    artifact = repo.get_artifact_by_hash(conn, org_id=org_id, hash_=hash_)
    if artifact is None:
        artifact = Artifact(
            id=repo.new_id(),
            org_id=org_id,
            source_tool=source_tool,
            received_at=now,
            path=str(stored_path),
            hash=hash_,
            period_hint=period_hint,
        )
        repo.insert_artifact(conn, artifact)

    # 2. Parse.
    parsed = parser(path)

    # 3. Scan row.
    scan = Scan(
        id=repo.new_id(),
        org_id=org_id,
        source_tool=source_tool,
        label=label or parsed.scan.label,
        scan_started_at=parsed.scan.scan_started_at,
        scan_completed_at=parsed.scan.scan_completed_at,
        timestamp_source=parsed.scan.timestamp_source,
        artifact_ids=[artifact.id],
        target_ids=[],
        ingested_at=now,
        notes=parsed.scan.notes,
    )
    repo.insert_scan(conn, scan)

    report = IngestReport(scan_id=scan.id, artifact_id=artifact.id)

    # 4. Discovered identifiers (no finding) — just appended onto a
    #    parent target's identifiers list.
    for parent_id_str, children in parsed.discovered_identifiers.items():
        parent = repo.get_target_by_name(conn, org_id=org_id, name=parent_id_str)
        if parent is None:
            # Parent hasn't been seen — create a bare domain target so
            # the discoveries have somewhere to live.
            parent = targets.resolve_target(
                conn,
                org_id=org_id,
                identifier=parent_id_str,
                target_type="domain",
                now=now,
            )
        for child in children:
            # If child is already a promoted Target, skip.
            if repo.get_target_by_name(conn, org_id=org_id, name=child):
                continue
            targets.record_identifier_only(
                conn,
                org_id=org_id,
                parent_target=parent,
                identifier=child,
            )

    # 5. Findings.
    touched_target_ids: set[str] = set()
    for pf in parsed.findings:
        # Target.
        target = targets.resolve_target(
            conn,
            org_id=org_id,
            identifier=pf.target_identifier,
            target_type=pf.target_type,
            now=pf.observed_at or now,
        )
        touched_target_ids.add(target.id)

        # Severity + confidence.
        severity = scoring.map_severity(source_tool, pf.raw_severity)
        confidence = pf.raw_confidence or scoring.DEFAULT_CONFIDENCE.get(
            source_tool, "medium"
        )

        # Dedup key.
        key = dedup.key_for(source_tool, pf.normalized)

        existing = repo.get_finding_by_dedup(
            conn, org_id=org_id, source_tool=source_tool, dedup_key=key
        )
        seen_at = pf.observed_at or now

        if existing is not None:
            # Re-occurrence — advance last_seen and add a junction row.
            # Crucially: priority is NOT recomputed.
            repo.update_finding_last_seen(conn, existing.id, seen_at)
            repo.record_occurrence(
                conn, finding_id=existing.id, scan_id=scan.id, seen_at=seen_at
            )
            report.reoccurrences += 1
            continue

        # New finding — compute priority once, write the row.
        score = scoring.compute_priority(
            severity=severity,
            confidence=confidence,
            target_weight=target.target_weight,
        )

        finding = Finding(
            id=repo.new_id(),
            org_id=org_id,
            target_id=target.id,
            source_tool=source_tool,
            source_artifact_id=artifact.id,
            dedup_key=key,
            title=pf.title,
            severity=severity,
            confidence=confidence,
            priority=score.priority,
            severity_weight=score.severity_weight,
            confidence_weight=score.confidence_weight,
            raw=pf.raw,
            normalized=pf.normalized,
            first_seen=seen_at,
            last_seen=seen_at,
            status="active",
        )
        repo.insert_finding(conn, finding)
        repo.record_occurrence(
            conn, finding_id=finding.id, scan_id=scan.id, seen_at=seen_at
        )
        report.new_findings += 1

    # 6. Finalize Scan target list.
    repo.update_scan_targets(conn, scan.id, sorted(touched_target_ids))
    report.target_ids = sorted(touched_target_ids)
    conn.commit()
    return report


def _hash_directory(path: Path) -> str:
    """Hash a directory by concatenating (name, file-hash) for every
    regular file inside it, sorted by name. Stable under re-runs.
    """
    import hashlib

    h = hashlib.sha256()
    files = sorted(p for p in path.rglob("*") if p.is_file())
    for f in files:
        rel = f.relative_to(path).as_posix()
        h.update(rel.encode("utf-8"))
        h.update(b":")
        h.update(art_store.hash_file(f).encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()


def _store_directory_manifest(artifacts_root: Path, path: Path, hash_: str) -> Path:
    """Store a manifest of the directory's contents so the Artifact
    row has something deterministic on disk to point at. The individual
    files are also copied into the content-addressed store so the raw
    bytes are preserved independently.
    """
    lines = []
    for f in sorted(p for p in path.rglob("*") if p.is_file()):
        rel = f.relative_to(path).as_posix()
        fh, _ = art_store.store_file(artifacts_root, f)
        lines.append(f"{fh}  {rel}")
    manifest = "\n".join(lines).encode("utf-8")
    manifest_hash = art_store.hash_bytes(manifest)
    # Save the manifest under a path derived from the directory hash so
    # the Artifact.path is stable across re-ingests.
    dest = art_store.store_path(artifacts_root, hash_).with_suffix(".manifest")
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        dest.write_bytes(manifest)
    _ = manifest_hash  # kept for future integrity checks
    return dest
