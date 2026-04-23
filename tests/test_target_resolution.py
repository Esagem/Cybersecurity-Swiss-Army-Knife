from csak.ingest.targets import resolve_target
from csak.storage import repository as repo
from csak.storage.models import Target


def test_resolve_returns_existing_target_by_name(db) -> None:
    org = repo.create_org(db, name="acme", slug="acme")
    t = repo.insert_target(
        db,
        Target(
            id=repo.new_id(),
            org_id=org.id,
            name="acmecorp.com",
            type="domain",
            identifiers=["acmecorp.com"],
        ),
    )
    db.commit()

    found = resolve_target(
        db, org_id=org.id, identifier="acmecorp.com", target_type="domain"
    )
    assert found.id == t.id


def test_resolve_promotes_subdomain_in_parent_identifiers(db) -> None:
    org = repo.create_org(db, name="acme", slug="acme")
    parent = repo.insert_target(
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

    child = resolve_target(
        db,
        org_id=org.id,
        identifier="api.acmecorp.com",
        target_type="subdomain",
    )
    assert child.id != parent.id
    assert child.parent_target_id == parent.id
    assert child.name == "api.acmecorp.com"


def test_resolve_creates_new_target_when_identifier_is_novel(db) -> None:
    org = repo.create_org(db, name="acme", slug="acme")
    db.commit()

    t = resolve_target(
        db, org_id=org.id, identifier="10.0.0.1", target_type="ip"
    )
    assert t.name == "10.0.0.1"
    assert t.parent_target_id is None


def test_resolve_without_promotion_does_not_create_child(db) -> None:
    org = repo.create_org(db, name="acme", slug="acme")
    parent = repo.insert_target(
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

    # With promote=False, resolve creates a fresh top-level target
    # rather than promoting. This path isn't exercised by slice 1
    # ingestors, but protects the interface for future callers.
    t = resolve_target(
        db,
        org_id=org.id,
        identifier="new.example.com",
        target_type="subdomain",
        promote=False,
    )
    assert t.parent_target_id is None
    assert t.name == "new.example.com"
    assert t.id != parent.id
