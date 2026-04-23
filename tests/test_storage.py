from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from csak.storage import artifacts, repository as repo
from csak.storage.models import Finding, Scan, Target


def test_create_and_fetch_org(db) -> None:
    org = repo.create_org(db, name="acmecorp", slug="acmecorp")
    fetched = repo.get_org_by_slug(db, "acmecorp")
    assert fetched is not None
    assert fetched.id == org.id
    assert fetched.name == "acmecorp"


def test_insert_target_and_lookup_by_identifier(db) -> None:
    org = repo.create_org(db, name="acme", slug="acme")
    t = repo.insert_target(
        db,
        Target(
            id=repo.new_id(),
            org_id=org.id,
            name="acmecorp.com",
            type="domain",
            identifiers=["acmecorp.com", "api.acmecorp.com"],
        ),
    )
    db.commit()

    found = repo.find_target_containing_identifier(
        db, org_id=org.id, identifier="api.acmecorp.com"
    )
    assert found is not None and found.id == t.id

    miss = repo.find_target_containing_identifier(
        db, org_id=org.id, identifier="nope.example.com"
    )
    assert miss is None


def test_artifact_dedup_by_hash(db, tmp_path: Path, artifacts_dir: Path) -> None:
    org = repo.create_org(db, name="acme", slug="acme")
    source = tmp_path / "scan.nessus"
    source.write_bytes(b"<NessusClientData/>")
    hash_, stored = artifacts.store_file(artifacts_dir, source)
    assert stored.exists()

    # Store again — file already there, same hash, same on-disk path.
    hash2, stored2 = artifacts.store_file(artifacts_dir, source)
    assert hash2 == hash_
    assert stored2 == stored

    from csak.storage.models import Artifact as ArtifactModel

    art = repo.insert_artifact(
        db,
        ArtifactModel(
            id=repo.new_id(),
            org_id=org.id,
            source_tool="nessus",
            received_at=datetime.now(timezone.utc),
            path=str(stored),
            hash=hash_,
        ),
    )
    db.commit()
    found = repo.get_artifact_by_hash(db, org_id=org.id, hash_=hash_)
    assert found is not None and found.id == art.id


def test_finding_dedup_key_unique(db) -> None:
    org = repo.create_org(db, name="acme", slug="acme")
    target = repo.insert_target(
        db,
        Target(
            id=repo.new_id(),
            org_id=org.id,
            name="acmecorp.com",
            type="domain",
            identifiers=["acmecorp.com"],
        ),
    )
    from csak.storage.models import Artifact as ArtifactModel

    art = repo.insert_artifact(
        db,
        ArtifactModel(
            id=repo.new_id(),
            org_id=org.id,
            source_tool="nuclei",
            received_at=datetime.now(timezone.utc),
            path="/dev/null",
            hash="deadbeef",
        ),
    )
    db.commit()

    now = datetime.now(timezone.utc)
    f = Finding(
        id=repo.new_id(),
        org_id=org.id,
        target_id=target.id,
        source_tool="nuclei",
        source_artifact_id=art.id,
        dedup_key="ssl-dns-names:https://acmecorp.com",
        title="SSL DNS names exposed",
        severity="info",
        confidence="high",
        priority=0.1,
        severity_weight=0.1,
        confidence_weight=1.0,
        raw={"template-id": "ssl-dns-names"},
        normalized={"title": "SSL DNS names exposed"},
        first_seen=now,
        last_seen=now,
    )
    repo.insert_finding(db, f)
    db.commit()

    fetched = repo.get_finding_by_dedup(
        db,
        org_id=org.id,
        source_tool="nuclei",
        dedup_key="ssl-dns-names:https://acmecorp.com",
    )
    assert fetched is not None and fetched.id == f.id


def test_scan_and_occurrences(db) -> None:
    org = repo.create_org(db, name="acme", slug="acme")
    now = datetime.now(timezone.utc)
    scan = Scan(
        id=repo.new_id(),
        org_id=org.id,
        source_tool="nuclei",
        label="nuclei sweep",
        scan_started_at=now,
        scan_completed_at=now,
        timestamp_source="extracted",
        artifact_ids=["art-1"],
        target_ids=["target-1"],
    )
    repo.insert_scan(db, scan)
    db.commit()

    # list_scans returns it.
    scans = repo.list_scans(db, org.id)
    assert len(scans) == 1
    assert scans[0].id == scan.id
