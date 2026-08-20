from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from exposure360_api.canonical_promotion import (
    CanonicalAssetKeyFactory,
    CanonicalAssetPromoter,
    CanonicalPromotionError,
)
from exposure360_api.db import Base
from exposure360_api.models import Asset, EndpointAsset, Organization, ServiceAsset


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


def _organization(session: Session, slug: str) -> Organization:
    organization = Organization(id=uuid4(), name=slug, slug=slug)
    session.add(organization)
    session.commit()
    return organization


def test_canonical_key_factory_normalizes_domain_ip_and_asn() -> None:
    assert CanonicalAssetKeyFactory.domain("WWW.Example.COM.").canonical_key == (
        "domain:www.example.com"
    )
    assert CanonicalAssetKeyFactory.domain("bücher.example").canonical_key == (
        "domain:xn--bcher-kva.example"
    )
    assert CanonicalAssetKeyFactory.ip("2001:0db8:0:0:0:0:0:1").canonical_key == "ip:2001:db8::1"
    assert CanonicalAssetKeyFactory.asn("64500").canonical_key == "asn:AS64500"
    assert CanonicalAssetKeyFactory.endpoint("2001:db8::1", "TCP", 443).canonical_key == (
        "endpoint:tcp:[2001:db8::1]:443"
    )


def test_same_domain_in_different_organizations_is_not_merged(database_session: Session) -> None:
    promoter = CanonicalAssetPromoter()
    observed_at = datetime(2026, 1, 15, tzinfo=UTC)
    organization_a = _organization(database_session, "promotion-a")
    organization_b = _organization(database_session, "promotion-b")

    asset_a = promoter.promote_domain(
        database_session,
        organization_id=organization_a.id,
        raw_value="WWW.Example.COM.",
        observed_at=observed_at,
        source="fixture",
    )
    asset_b = promoter.promote_domain(
        database_session,
        organization_id=organization_b.id,
        raw_value="www.example.com",
        observed_at=observed_at,
        source="fixture",
    )
    database_session.commit()

    assert asset_a.id != asset_b.id
    assert asset_a.canonical_key == asset_b.canonical_key


def test_repeated_ip_and_endpoint_promotion_is_idempotent_and_temporal(
    database_session: Session,
) -> None:
    promoter = CanonicalAssetPromoter()
    organization = _organization(database_session, "promotion-temporal")
    later = datetime(2026, 1, 20, tzinfo=UTC)
    earlier = later - timedelta(days=10)

    first_ip = promoter.promote_ip(
        database_session,
        organization_id=organization.id,
        raw_value="192.0.2.20",
        observed_at=later,
        source="fixture",
    )
    second_ip = promoter.promote_ip(
        database_session,
        organization_id=organization.id,
        raw_value="192.0.2.20",
        observed_at=earlier,
        source="fixture",
    )
    first_endpoint = promoter.promote_endpoint(
        database_session,
        organization_id=organization.id,
        raw_ip="192.0.2.20",
        port=443,
        observed_at=later,
        source="tcp-fixture",
    )
    second_endpoint = promoter.promote_endpoint(
        database_session,
        organization_id=organization.id,
        raw_ip="192.0.2.20",
        port=443,
        observed_at=later,
        source="tcp-fixture",
    )
    database_session.commit()

    refreshed_ip = database_session.get(Asset, first_ip.id)
    assert refreshed_ip is not None
    assert first_ip.id == second_ip.id
    assert refreshed_ip.first_seen == earlier
    assert refreshed_ip.last_seen == later
    assert first_endpoint.id == second_endpoint.id
    assert database_session.scalar(select(func.count(EndpointAsset.asset_id))) == 1


def test_authority_specific_services_are_not_overmerged(database_session: Session) -> None:
    promoter = CanonicalAssetPromoter()
    organization = _organization(database_session, "promotion-services")
    observed_at = datetime(2026, 1, 15, tzinfo=UTC)
    endpoint = promoter.promote_endpoint(
        database_session,
        organization_id=organization.id,
        raw_ip="192.0.2.21",
        port=443,
        observed_at=observed_at,
        source="tcp-fixture",
    )
    www = promoter.promote_domain(
        database_session,
        organization_id=organization.id,
        raw_value="www.example.com",
        observed_at=observed_at,
        source="fixture",
    )
    api = promoter.promote_domain(
        database_session,
        organization_id=organization.id,
        raw_value="api.example.com",
        observed_at=observed_at,
        source="fixture",
    )
    first_service = promoter.promote_service(
        database_session,
        endpoint=endpoint,
        application_protocol="HTTPS",
        authority_domain=www,
        observed_at=observed_at,
    )
    second_service = promoter.promote_service(
        database_session,
        endpoint=endpoint,
        application_protocol="HTTPS",
        authority_domain=api,
        observed_at=observed_at,
    )
    database_session.commit()

    assert first_service.id != second_service.id
    assert database_session.scalar(select(func.count(ServiceAsset.asset_id))) == 2


def test_invalid_endpoint_and_service_identity_are_rejected() -> None:
    with pytest.raises(CanonicalPromotionError, match="port"):
        CanonicalAssetKeyFactory.endpoint("192.0.2.20", "TCP", 0)
    endpoint_key = CanonicalAssetKeyFactory.endpoint("192.0.2.20", "TCP", 443)
    with pytest.raises(CanonicalPromotionError, match="application protocol"):
        CanonicalAssetKeyFactory.service(endpoint_key, "FTP", None)
