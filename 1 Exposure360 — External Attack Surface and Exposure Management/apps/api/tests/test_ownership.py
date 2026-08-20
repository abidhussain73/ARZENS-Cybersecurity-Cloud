from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from exposure360_api.db import Base
from exposure360_api.models import (
    Asset,
    AuditEvent,
    Evidence,
    Membership,
    Organization,
    User,
)
from exposure360_api.ownership import OwnershipError, OwnershipService
from exposure360_api.security import OrganizationContext, Principal


@pytest.fixture
def database_session() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection: object, _: object) -> None:
        connection.execute("PRAGMA foreign_keys=ON")  # type: ignore[union-attr]

    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _asset(session: Session, slug: str) -> tuple[Asset, User, Membership]:
    user = User(id=uuid4(), oidc_subject=f"owner-{slug}")
    organization = Organization(id=uuid4(), name=slug, slug=slug)
    membership = Membership(
        id=uuid4(),
        organization_id=organization.id,
        user_id=user.id,
        role="admin",
    )
    session.add_all([user, organization])
    session.flush()
    session.add(membership)
    session.commit()
    observed_at = datetime(2026, 1, 15, tzinfo=UTC)
    asset = Asset(
        id=uuid4(),
        organization_id=organization.id,
        asset_type="DOMAIN",
        canonical_key=f"domain:{slug}.example.com",
        display_name=f"{slug}.example.com",
        first_seen=observed_at,
        last_seen=observed_at,
    )
    session.add(asset)
    session.commit()
    return asset, user, membership


def test_manual_precedence_conflict_and_expired_claims(database_session: Session) -> None:
    now = datetime(2026, 1, 20, tzinfo=UTC)
    asset, _, _ = _asset(database_session, "ownership-resolution")
    service = OwnershipService(clock=lambda: now)
    source = service.record_claim(
        database_session,
        asset=asset,
        owner_type="TEAM",
        owner_reference="engineering",
        owner_display_name="Engineering",
        claim_type="SOURCE_ASSERTED",
        confidence=0.95,
        source_type="CMDB",
        valid_from=now - timedelta(days=1),
    )
    manual = service.record_claim(
        database_session,
        asset=asset,
        owner_type="TEAM",
        owner_reference="security",
        owner_display_name="Security",
        claim_type="MANUAL",
        confidence=1.0,
        source_type="MANUAL",
        valid_from=now,
    )
    resolution = service.resolve(database_session, asset)
    assert resolution.ownership is not None
    assert resolution.ownership.id == manual.id
    assert source.is_primary is False

    service.record_claim(
        database_session,
        asset=asset,
        owner_type="TEAM",
        owner_reference="operations",
        owner_display_name="Operations",
        claim_type="MANUAL",
        confidence=0.98,
        source_type="MANUAL",
        valid_from=now,
    )
    conflict = service.resolve(database_session, asset)
    assert conflict.conflict is True
    assert conflict.conflict_code == "OWNERSHIP_CONFLICT"


def test_source_claim_is_idempotent_and_evidence_link_is_organization_safe(
    database_session: Session,
) -> None:
    now = datetime(2026, 1, 20, tzinfo=UTC)
    asset, _, _ = _asset(database_session, "ownership-evidence")
    other_asset, _, _ = _asset(database_session, "ownership-other")
    service = OwnershipService(clock=lambda: now)
    first = service.record_claim(
        database_session,
        asset=asset,
        owner_type="SERVICE",
        owner_reference="service-a",
        owner_display_name=None,
        claim_type="SOURCE_ASSERTED",
        confidence=0.8,
        source_type="AUTHORITATIVE_SOURCE",
        valid_from=now,
    )
    replay = service.record_claim(
        database_session,
        asset=asset,
        owner_type="SERVICE",
        owner_reference="service-a",
        owner_display_name=None,
        claim_type="SOURCE_ASSERTED",
        confidence=0.8,
        source_type="AUTHORITATIVE_SOURCE",
        valid_from=now,
    )
    evidence = Evidence(
        id=uuid4(),
        organization_id=asset.organization_id,
        asset_id=asset.id,
        evidence_type="METADATA",
        object_store_bucket="metadata-only",
        object_store_key=None,
        sha256="a" * 64,
        size_bytes=1,
        media_type="application/json",
        encoding="utf-8",
        collected_at=now,
        stored_at=now,
        retention_class="STANDARD",
        sensitivity_class="INTERNAL_METADATA",
        collector_name="fixture",
        collector_version="1.0.0",
        metadata_json={},
        idempotency_key="b" * 64,
    )
    database_session.add(evidence)
    database_session.flush()
    assert first.id == replay.id
    assert (
        service.link_evidence(
            database_session,
            ownership=first,
            evidence=evidence,
            relationship_type="SUPPORTS",
        ).ownership_id
        == first.id
    )
    foreign_evidence = Evidence(
        id=uuid4(),
        organization_id=other_asset.organization_id,
        asset_id=other_asset.id,
        evidence_type="METADATA",
        object_store_bucket="metadata-only",
        object_store_key=None,
        sha256="c" * 64,
        size_bytes=1,
        media_type="application/json",
        encoding="utf-8",
        collected_at=now,
        stored_at=now,
        retention_class="STANDARD",
        sensitivity_class="INTERNAL_METADATA",
        collector_name="fixture",
        collector_version="1.0.0",
        metadata_json={},
        idempotency_key="d" * 64,
    )
    database_session.add(foreign_evidence)
    database_session.flush()
    with pytest.raises(OwnershipError, match="another organization"):
        service.link_evidence(
            database_session,
            ownership=first,
            evidence=foreign_evidence,
            relationship_type="SUPPORTS",
        )


def test_manual_override_requires_role_and_writes_audit_event(database_session: Session) -> None:
    now = datetime(2026, 1, 20, tzinfo=UTC)
    asset, user, membership = _asset(database_session, "ownership-manual")
    service = OwnershipService(clock=lambda: now)
    viewer_context = OrganizationContext(
        asset.organization_id,
        Membership(
            id=uuid4(),
            organization_id=asset.organization_id,
            user_id=user.id,
            role="viewer",
        ),
    )
    with pytest.raises(HTTPException, match="Insufficient"):
        service.assign_manual(
            database_session,
            context=viewer_context,
            principal=Principal(user),
            asset=asset,
            owner_type="TEAM",
            owner_reference="security",
            owner_display_name="Security",
            reason="approved inventory owner",
            correlation_id="ownership-test",
        )
    claim = service.assign_manual(
        database_session,
        context=OrganizationContext(asset.organization_id, membership),
        principal=Principal(user),
        asset=asset,
        owner_type="TEAM",
        owner_reference="security",
        owner_display_name="Security",
        reason="approved inventory owner",
        correlation_id="ownership-test",
    )
    database_session.commit()
    assert claim.claim_type == "MANUAL"
    assert (
        database_session.scalar(
            select(func.count(AuditEvent.id)).where(
                AuditEvent.action == "asset.ownership_manual_assigned"
            )
        )
        == 1
    )
