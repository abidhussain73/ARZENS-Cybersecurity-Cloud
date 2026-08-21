from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from exposure360_api.db import Base
from exposure360_api.models import Asset, ExternalContextEntity, Organization, Relationship
from exposure360_api.relationships import (
    ASSET,
    CONTEXT,
    REGISTRY_VERSION,
    RELATIONSHIP_TYPES,
    ExternalContextRepository,
    GraphNodeReference,
    RelationshipError,
    RelationshipInput,
    RelationshipRepository,
)

NOW = datetime(2026, 8, 21, tzinfo=UTC)


@pytest.fixture
def session() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection: object, _: object) -> None:
        connection.execute("PRAGMA foreign_keys=ON")  # type: ignore[union-attr]

    Base.metadata.create_all(engine)
    instance = sessionmaker(bind=engine, expire_on_commit=False)()
    try:
        yield instance
    finally:
        instance.close()
        engine.dispose()


def _organization(session: Session, name: str) -> Organization:
    organization = Organization(id=uuid4(), name=name, slug=f"{name}-{uuid4()}")
    session.add(organization)
    session.flush()
    return organization


def _asset(session: Session, organization_id: UUID, key: str) -> Asset:
    asset = Asset(
        id=uuid4(),
        organization_id=organization_id,
        asset_type="SERVICE",
        canonical_key=key,
        display_name=key,
        first_seen=NOW,
        last_seen=NOW,
    )
    session.add(asset)
    session.flush()
    return asset


def _context(
    session: Session, organization_id: UUID, context_type: str, canonical_key: str
) -> ExternalContextEntity:
    return ExternalContextRepository(session).upsert(
        organization_id,
        context_type=context_type,
        canonical_key=canonical_key,
        display_name=canonical_key,
        source_namespace="fixture-context",
        confidence=0.8,
        observed_at=NOW,
    )


def _input(
    relationship_type: str,
    source: GraphNodeReference,
    target: GraphNodeReference,
    *,
    observed_at: datetime = NOW,
    valid_from: datetime = NOW,
) -> RelationshipInput:
    return RelationshipInput(
        relationship_type=relationship_type,
        source=source,
        target=target,
        confidence=0.8,
        observed_at=observed_at,
        valid_from=valid_from,
        source_system="fixture-context",
    )


def test_relationship_endpoint_patterns_are_accepted(session: Session) -> None:
    organization = _organization(session, "endpoint-patterns")
    domain = _asset(session, organization.id, "domain:fixture.example")
    ip = _asset(session, organization.id, "ip:203.0.113.10")
    application = _context(
        session, organization.id, "APPLICATION", "application:fixture:endpoint-patterns"
    )
    data = _context(session, organization.id, "DATA", "data:fixture:endpoint-patterns")
    repository = RelationshipRepository(session)

    asset_to_asset = repository.upsert_relationship(
        organization.id,
        _input(
            "RESOLVES_TO",
            GraphNodeReference(ASSET, domain.id),
            GraphNodeReference(ASSET, ip.id),
        ),
    )
    asset_to_context = repository.upsert_relationship(
        organization.id,
        _input(
            "ASSET_HOSTS_APPLICATION",
            GraphNodeReference(ASSET, domain.id),
            GraphNodeReference(CONTEXT, application.id),
        ),
    )
    context_to_context = repository.upsert_relationship(
        organization.id,
        _input(
            "APPLICATION_USES_DATA",
            GraphNodeReference(CONTEXT, application.id),
            GraphNodeReference(CONTEXT, data.id),
        ),
    )

    assert [asset_to_asset.relationship_type, asset_to_context.relationship_type] == [
        "RESOLVES_TO",
        "ASSET_HOSTS_APPLICATION",
    ]
    assert context_to_context.relationship_type == "APPLICATION_USES_DATA"


def test_database_rejects_invalid_endpoint_xor(session: Session) -> None:
    organization = _organization(session, "endpoint-xor")
    asset = _asset(session, organization.id, "service:endpoint-xor")
    application = _context(
        session, organization.id, "APPLICATION", "application:fixture:endpoint-xor"
    )
    target = _asset(session, organization.id, "ip:203.0.113.12")
    relationship = Relationship(
        id=uuid4(),
        organization_id=organization.id,
        relationship_type="RESOLVES_TO",
        source_asset_id=asset.id,
        source_context_entity_id=application.id,
        target_asset_id=target.id,
        target_context_entity_id=None,
        canonical_key="b" * 64,
        confidence=0.8,
        confidence_model_version="relationship-confidence-v1",
        registry_version="relationship-type-registry-v1",
        first_seen=NOW,
        last_seen=NOW,
        valid_from=NOW,
        valid_to=None,
        state="ACTIVE",
        source_system="fixture",
        source_record_key=None,
        metadata_json={},
    )
    session.add(relationship)
    with pytest.raises(IntegrityError):
        session.flush()


def test_repository_rejects_invalid_type_kind_and_cross_org_endpoints(session: Session) -> None:
    organization = _organization(session, "relationship-guard")
    foreign = _organization(session, "relationship-foreign")
    asset = _asset(session, organization.id, "service:relationship-guard")
    foreign_asset = _asset(session, foreign.id, "service:relationship-foreign")
    application = _context(
        session, organization.id, "APPLICATION", "application:fixture:relationship-guard"
    )
    repository = RelationshipRepository(session)

    cases = (
        _input(
            "NOT_ALLOWED", GraphNodeReference(ASSET, asset.id), GraphNodeReference(ASSET, asset.id)
        ),
        _input(
            "RESOLVES_TO",
            GraphNodeReference(CONTEXT, application.id),
            GraphNodeReference(ASSET, asset.id),
        ),
        _input(
            "RESOLVES_TO",
            GraphNodeReference(ASSET, asset.id),
            GraphNodeReference(ASSET, foreign_asset.id),
        ),
    )
    for item in cases:
        with pytest.raises(RelationshipError):
            repository.upsert_relationship(organization.id, item)


def test_repeated_upsert_retains_history_and_advances_last_seen(session: Session) -> None:
    organization = _organization(session, "relationship-time")
    domain = _asset(session, organization.id, "domain:relationship-time")
    ip = _asset(session, organization.id, "ip:203.0.113.11")
    repository = RelationshipRepository(session)
    first = repository.upsert_relationship(
        organization.id,
        _input(
            "RESOLVES_TO",
            GraphNodeReference(ASSET, domain.id),
            GraphNodeReference(ASSET, ip.id),
        ),
    )
    repeated = repository.upsert_relationship(
        organization.id,
        _input(
            "RESOLVES_TO",
            GraphNodeReference(ASSET, domain.id),
            GraphNodeReference(ASSET, ip.id),
            observed_at=NOW + timedelta(hours=2),
        ),
    )

    assert repeated.id == first.id
    assert repeated.first_seen == NOW
    assert repeated.last_seen == NOW + timedelta(hours=2)
    assert session.scalar(select(func.count()).select_from(Relationship)) == 1


def test_end_relationship_and_active_at_apply_temporal_boundary(session: Session) -> None:
    organization = _organization(session, "relationship-temporal-filter")
    domain = _asset(session, organization.id, "domain:relationship-temporal-filter")
    ip = _asset(session, organization.id, "ip:203.0.113.13")
    repository = RelationshipRepository(session)
    relationship = repository.upsert_relationship(
        organization.id,
        _input(
            "RESOLVES_TO",
            GraphNodeReference(ASSET, domain.id),
            GraphNodeReference(ASSET, ip.id),
        ),
    )
    ended = repository.end_relationship(organization.id, relationship.id, NOW + timedelta(days=1))

    assert ended.state == "ENDED"
    assert ended.valid_to == NOW + timedelta(days=1)
    assert repository.get_active_at(organization.id, NOW + timedelta(hours=12)) == [ended]
    assert repository.get_active_at(organization.id, NOW + timedelta(days=1)) == []


def test_provenance_is_retained_idempotently_and_registry_version_is_stable(
    session: Session,
) -> None:
    organization = _organization(session, "relationship-provenance")
    asset = _asset(session, organization.id, "service:relationship-provenance")
    application = _context(
        session, organization.id, "APPLICATION", "application:fixture:relationship-provenance"
    )
    repository = RelationshipRepository(session)
    relationship = repository.upsert_relationship(
        organization.id,
        _input(
            "ASSET_HOSTS_APPLICATION",
            GraphNodeReference(ASSET, asset.id),
            GraphNodeReference(CONTEXT, application.id),
        ),
    )
    first = repository.link_provenance(
        organization.id, relationship.id, source_context_record_hash="c" * 64
    )
    repeated = repository.link_provenance(
        organization.id, relationship.id, source_context_record_hash="c" * 64
    )

    assert first.id == repeated.id
    assert first.source_context_record_hash == "c" * 64
    assert relationship.registry_version == REGISTRY_VERSION == "relationship-type-registry-v1"
    assert len(RELATIONSHIP_TYPES) == 20
