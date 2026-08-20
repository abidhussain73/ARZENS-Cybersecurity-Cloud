from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from exposure360_api.asset_lifecycle import AssetLifecycleError, AssetLifecycleService
from exposure360_api.db import Base
from exposure360_api.models import Asset, AssetFreshnessPolicy, Organization


@pytest.fixture
def database_session() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _asset(session: Session, observed_at: datetime) -> Asset:
    organization = Organization(
        id=uuid4(),
        name="Lifecycle Org",
        slug=f"lifecycle-{uuid4().hex[:8]}",
    )
    session.add(organization)
    session.commit()
    asset = Asset(
        id=uuid4(),
        organization_id=organization.id,
        asset_type="DOMAIN",
        canonical_key=f"domain:{uuid4().hex}.example.com",
        display_name="lifecycle.example.com",
        lifecycle_state="ACTIVE",
        first_seen=observed_at,
        last_seen=observed_at,
    )
    session.add(asset)
    session.commit()
    return asset


def test_lifecycle_is_monotonic_for_repeated_and_out_of_order_observations(
    database_session: Session,
) -> None:
    now = datetime(2026, 1, 20, tzinfo=UTC)
    asset = _asset(database_session, now)
    service = AssetLifecycleService(clock=lambda: now)

    service.apply_observation(
        database_session,
        asset=asset,
        observed_at=now,
        directly_confirmed=True,
    )
    service.apply_observation(
        database_session,
        asset=asset,
        observed_at=now - timedelta(days=10),
        directly_confirmed=False,
    )
    service.apply_observation(
        database_session,
        asset=asset,
        observed_at=now - timedelta(days=5),
        directly_confirmed=False,
    )

    assert asset.first_seen == now - timedelta(days=10)
    assert asset.last_seen == now
    assert asset.last_confirmed_at == now
    assert asset.lifecycle_state == "ACTIVE"


def test_lifecycle_stale_retired_and_reobservation_policy(database_session: Session) -> None:
    now = datetime(2026, 1, 20, tzinfo=UTC)
    asset = _asset(database_session, now - timedelta(days=3))
    database_session.add(
        AssetFreshnessPolicy(
            id=uuid4(),
            organization_id=asset.organization_id,
            asset_type="DOMAIN",
            policy_version="test-v1",
            stale_after_seconds=24 * 60 * 60,
            is_active=True,
        )
    )
    database_session.commit()
    service = AssetLifecycleService(clock=lambda: now)

    assert service.refresh_state(database_session, asset) == "STALE"
    service.retire(asset)
    result = service.apply_observation(
        database_session,
        asset=asset,
        observed_at=now,
        directly_confirmed=True,
    )

    assert result.lifecycle_state == "RETIRED"
    assert result.reactivation_review_required is True
    assert asset.lifecycle_state == "RETIRED"


def test_lifecycle_rejects_implausible_future_timestamp(database_session: Session) -> None:
    now = datetime(2026, 1, 20, tzinfo=UTC)
    asset = _asset(database_session, now)
    service = AssetLifecycleService(clock=lambda: now)

    with pytest.raises(AssetLifecycleError, match="future"):
        service.apply_observation(
            database_session,
            asset=asset,
            observed_at=now + timedelta(days=2),
            directly_confirmed=False,
        )
