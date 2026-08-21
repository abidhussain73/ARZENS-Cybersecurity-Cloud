from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from exposure360_api.db import Base
from exposure360_api.external_context_import import (
    ExternalContextBatch,
    ExternalContextEntityContract,
    ExternalContextImportService,
    FixtureExternalContextAdapter,
)
from exposure360_api.models import (
    Asset,
    ExternalContextEntity,
    Organization,
    Relationship,
    RelationshipEvidenceLink,
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


def _asset(session: Session, organization_id: object, key: str) -> Asset:
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


def _fixture_batch() -> ExternalContextBatch:
    return ExternalContextBatch.model_validate(
        {
            "source_namespace": "fixture-context",
            "adapter_version": "fixture-external-context-v1",
            "source_snapshot_id": "synthetic-context-001",
            "source_observed_at": NOW,
            "retrieved_at": NOW,
            "entities": [
                {
                    "context_type": "IDENTITY",
                    "source_native_id": "alice-fixture",
                    "canonical_key": "identity:fixture:alice",
                    "display_name": "Alice Fixture",
                    "confidence": 0.8,
                    "metadata": {"identity_kind": "user"},
                },
                {
                    "context_type": "CLOUD_RESOURCE",
                    "source_native_id": "lb-001",
                    "canonical_key": "cloud:fixture:load-balancer:lb-001",
                    "display_name": "Fixture load balancer",
                    "confidence": 0.9,
                    "metadata": {},
                },
                {
                    "context_type": "APPLICATION",
                    "source_native_id": "customer-portal",
                    "canonical_key": "application:fixture:customer-portal",
                    "display_name": "Customer portal",
                    "confidence": 0.8,
                    "metadata": {},
                },
                {
                    "context_type": "DATA",
                    "source_native_id": "customer-records",
                    "canonical_key": "data:fixture:customer-records",
                    "display_name": "Customer records metadata",
                    "confidence": 0.7,
                    "metadata": {"classification": "restricted"},
                },
                {
                    "context_type": "VULNERABILITY",
                    "source_native_id": "CVE-2099-6001",
                    "canonical_key": "vulnerability:CVE-2099-6001",
                    "display_name": "Synthetic CVE-2099-6001",
                    "confidence": 0.75,
                    "metadata": {"severity_hint": "HIGH"},
                },
            ],
            "relationships": [
                {
                    "relationship_type": "ASSET_HOSTS_APPLICATION",
                    "source_ref": {"kind": "EXPOSURE_ASSET", "canonical_key": "service:fixture"},
                    "target_ref": {
                        "kind": "EXTERNAL_CONTEXT",
                        "canonical_key": "application:fixture:customer-portal",
                    },
                    "observed_at": NOW,
                    "confidence": 0.8,
                },
                {
                    "relationship_type": "APPLICATION_EXPOSED_BY_SERVICE",
                    "source_ref": {
                        "kind": "EXTERNAL_CONTEXT",
                        "canonical_key": "application:fixture:customer-portal",
                    },
                    "target_ref": {"kind": "EXPOSURE_ASSET", "canonical_key": "service:fixture"},
                    "observed_at": NOW,
                    "confidence": 0.8,
                },
                {
                    "relationship_type": "APPLICATION_USES_DATA",
                    "source_ref": {
                        "kind": "EXTERNAL_CONTEXT",
                        "canonical_key": "application:fixture:customer-portal",
                    },
                    "target_ref": {
                        "kind": "EXTERNAL_CONTEXT",
                        "canonical_key": "data:fixture:customer-records",
                    },
                    "observed_at": NOW,
                    "confidence": 0.7,
                },
                {
                    "relationship_type": "IDENTITY_CAN_ACCESS_APPLICATION",
                    "source_ref": {
                        "kind": "EXTERNAL_CONTEXT",
                        "canonical_key": "identity:fixture:alice",
                    },
                    "target_ref": {
                        "kind": "EXTERNAL_CONTEXT",
                        "canonical_key": "application:fixture:customer-portal",
                    },
                    "observed_at": NOW,
                    "confidence": 0.8,
                },
                {
                    "relationship_type": "CLOUD_RESOURCE_EXPOSES_ASSET",
                    "source_ref": {
                        "kind": "EXTERNAL_CONTEXT",
                        "canonical_key": "cloud:fixture:load-balancer:lb-001",
                    },
                    "target_ref": {
                        "kind": "EXPOSURE_ASSET",
                        "canonical_key": "domain:fixture.example",
                    },
                    "observed_at": NOW,
                    "confidence": 0.9,
                },
                {
                    "relationship_type": "SERVICE_HAS_VULNERABILITY",
                    "source_ref": {"kind": "EXPOSURE_ASSET", "canonical_key": "service:fixture"},
                    "target_ref": {
                        "kind": "EXTERNAL_CONTEXT",
                        "canonical_key": "vulnerability:CVE-2099-6001",
                    },
                    "observed_at": NOW,
                    "confidence": 0.75,
                },
            ],
        }
    )


def test_synthetic_context_import_is_idempotent_tenant_bound_and_provenanced(
    session: Session,
) -> None:
    organization = _organization(session, "import-primary")
    foreign = _organization(session, "import-foreign")
    _asset(session, organization.id, "service:fixture")
    _asset(session, organization.id, "domain:fixture.example")
    _asset(session, foreign.id, "service:fixture")
    batch = _fixture_batch()
    service = ExternalContextImportService(session, FixtureExternalContextAdapter())

    assert service.import_batch(organization.id, batch) == 6
    assert service.import_batch(organization.id, batch) == 6
    assert (
        session.scalar(
            select(func.count())
            .select_from(ExternalContextEntity)
            .where(ExternalContextEntity.organization_id == organization.id)
        )
        == 5
    )
    assert (
        session.scalar(
            select(func.count())
            .select_from(Relationship)
            .where(Relationship.organization_id == organization.id)
        )
        == 6
    )
    assert (
        session.scalar(
            select(func.count())
            .select_from(Relationship)
            .where(Relationship.organization_id == foreign.id)
        )
        == 0
    )
    imported_types = set(
        session.scalars(
            select(ExternalContextEntity.context_type).where(
                ExternalContextEntity.organization_id == organization.id
            )
        )
    )
    imported_relationships = set(
        session.scalars(
            select(Relationship.relationship_type).where(
                Relationship.organization_id == organization.id
            )
        )
    )
    assert imported_types == {
        "IDENTITY",
        "CLOUD_RESOURCE",
        "APPLICATION",
        "DATA",
        "VULNERABILITY",
    }
    assert {
        "ASSET_HOSTS_APPLICATION",
        "APPLICATION_EXPOSED_BY_SERVICE",
        "APPLICATION_USES_DATA",
        "IDENTITY_CAN_ACCESS_APPLICATION",
        "CLOUD_RESOURCE_EXPOSES_ASSET",
        "SERVICE_HAS_VULNERABILITY",
    } <= imported_relationships
    evidence_links = session.scalars(
        select(RelationshipEvidenceLink).where(
            RelationshipEvidenceLink.organization_id == organization.id
        )
    ).all()
    assert len(evidence_links) == 6
    assert all(
        item.source_context_record_hash == batch.source_snapshot_hash for item in evidence_links
    )


def test_import_contract_rejects_unknown_context_and_unknown_relationship_type(
    session: Session,
) -> None:
    with pytest.raises(ValidationError):
        ExternalContextEntityContract(
            context_type="HUMAN",
            canonical_key="human:fixture:one",
            display_name="Not allowed",
            confidence=0.5,
        )

    organization = _organization(session, "import-invalid-relationship")
    _asset(session, organization.id, "service:fixture")
    batch = _fixture_batch().model_copy(
        update={
            "relationships": [
                _fixture_batch().relationships[0].model_copy(update={"relationship_type": "CUSTOM"})
            ]
        }
    )
    with pytest.raises(ValueError, match="unsupported relationship type"):
        ExternalContextImportService(session, FixtureExternalContextAdapter()).import_batch(
            organization.id, batch
        )


def test_synthetic_source_hash_is_stable_for_the_same_normalized_batch() -> None:
    assert _fixture_batch().source_snapshot_hash == _fixture_batch().source_snapshot_hash
