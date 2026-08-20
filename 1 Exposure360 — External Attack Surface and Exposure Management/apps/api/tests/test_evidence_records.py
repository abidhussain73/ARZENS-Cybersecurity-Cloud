from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from exposure360_api.db import Base
from exposure360_api.evidence_records import (
    EvidenceRecordError,
    EvidenceRecordService,
    canonical_json_bytes,
    sha256_hex,
)
from exposure360_api.models import Asset, CanonicalObservation, Organization


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


def _asset(session: Session, slug: str) -> Asset:
    organization = Organization(id=uuid4(), name=slug, slug=slug)
    session.add(organization)
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
    return asset


def test_observation_replay_is_idempotent_and_temporal_facts_remain_distinct(
    database_session: Session,
) -> None:
    asset = _asset(database_session, "evidence-observation")
    service = EvidenceRecordService(clock=lambda: datetime(2026, 1, 16, tzinfo=UTC))
    observed_at = datetime(2026, 1, 15, tzinfo=UTC)
    kwargs = {
        "organization_id": asset.organization_id,
        "asset": asset,
        "observation_type": "HTTP_RESPONSE",
        "source_type": "COLLECTOR",
        "source_key": "fixture-http",
        "source_record_key": "response-1",
        "source_version": "1.0.0",
        "observed_at": observed_at,
        "collected_at": observed_at,
        "payload": {"status_code": 200, "set-cookie": "must-not-persist"},
    }
    first = service.record_observation(database_session, **kwargs)
    replay = service.record_observation(database_session, **kwargs)
    later = service.record_observation(
        database_session,
        **{**kwargs, "observed_at": observed_at + timedelta(minutes=1)},
    )
    database_session.commit()

    assert first.created is True
    assert replay.created is False
    assert first.observation.id == replay.observation.id
    assert later.observation.id != first.observation.id
    assert "set-cookie" not in first.observation.normalized_payload_json
    assert database_session.scalar(select(func.count(CanonicalObservation.id))) == 2


def test_canonical_json_hash_evidence_provenance_and_immutability(
    database_session: Session,
) -> None:
    asset = _asset(database_session, "evidence-metadata")
    service = EvidenceRecordService(clock=lambda: datetime(2026, 1, 16, tzinfo=UTC))
    collected_at = datetime(2026, 1, 15, tzinfo=UTC)
    assert canonical_json_bytes({"b": 2, "a": 1}) == canonical_json_bytes({"a": 1, "b": 2})
    result = service.record_metadata_evidence(
        database_session,
        organization_id=asset.organization_id,
        asset=asset,
        observation=None,
        evidence_type="HTTP_METADATA",
        metadata={"status_code": 200, "cookie": "must-not-persist"},
        source_observed_at=collected_at - timedelta(minutes=1),
        collected_at=collected_at,
        collector_name="fixture-http",
        collector_version="1.0.0",
    )
    database_session.commit()
    evidence = result.evidence

    assert evidence.sha256 == sha256_hex(canonical_json_bytes({"status_code": 200}))
    assert evidence.collector_version == "1.0.0"
    assert evidence.source_observed_at == collected_at - timedelta(minutes=1)
    evidence.sha256 = "0" * 64
    with pytest.raises(ValueError, match="immutable"):
        database_session.commit()


def test_cross_organization_evidence_link_is_rejected(database_session: Session) -> None:
    asset_a = _asset(database_session, "evidence-a")
    asset_b = _asset(database_session, "evidence-b")
    service = EvidenceRecordService()
    observed_at = datetime(2026, 1, 15, tzinfo=UTC)
    with pytest.raises(EvidenceRecordError, match="organization"):
        service.record_observation(
            database_session,
            organization_id=asset_a.organization_id,
            asset=asset_b,
            observation_type="DNS_A",
            source_type="FIXTURE",
            source_key="fixture",
            source_record_key="record",
            source_version="1.0.0",
            observed_at=observed_at,
            collected_at=observed_at,
            payload={"address": "192.0.2.20"},
        )
