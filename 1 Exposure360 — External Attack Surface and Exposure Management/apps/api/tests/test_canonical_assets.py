from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from exposure360_api.canonical_assets import (
    CanonicalAssetRepository,
    CanonicalAssetValidationError,
)
from exposure360_api.db import Base
from exposure360_api.models import (
    AsnAsset,
    Asset,
    DomainAsset,
    EndpointAsset,
    IpAsset,
    Organization,
    ServiceAsset,
)


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


def _asset(organization_id: UUID, asset_type: str, canonical_key: str) -> Asset:
    observed_at = datetime(2026, 1, 15, tzinfo=UTC)
    return Asset(
        id=uuid4(),
        organization_id=organization_id,
        asset_type=asset_type,
        canonical_key=canonical_key,
        display_name=canonical_key,
        first_seen=observed_at,
        last_seen=observed_at,
    )


def test_each_canonical_asset_subtype_can_be_created(database_session: Session) -> None:
    organization = Organization(id=uuid4(), name="Canonical Org", slug="canonical-org")
    database_session.add(organization)
    database_session.commit()
    domain = _asset(organization.id, "DOMAIN", "domain:www.example.com")
    ip = _asset(organization.id, "IP", "ip:192.0.2.20")
    asn = _asset(organization.id, "ASN", "asn:AS64500")
    endpoint = _asset(organization.id, "ENDPOINT", "endpoint:tcp:192.0.2.20:443")
    service = _asset(
        organization.id,
        "SERVICE",
        "service:tcp:192.0.2.20:443:https:www.example.com",
    )
    database_session.add_all([domain, ip, asn, endpoint, service])
    database_session.flush()
    database_session.add_all(
        [
            DomainAsset(
                asset_id=domain.id,
                organization_id=organization.id,
                fqdn_ascii="www.example.com",
                fqdn_unicode=None,
                registrable_domain="example.com",
            ),
            IpAsset(
                asset_id=ip.id,
                organization_id=organization.id,
                address="192.0.2.20",
                ip_version=4,
                is_global=False,
                address_class="DOCUMENTATION",
            ),
            AsnAsset(
                asset_id=asn.id,
                organization_id=organization.id,
                asn_number=64500,
                canonical_asn="AS64500",
                name_hint=None,
            ),
            EndpointAsset(
                asset_id=endpoint.id,
                organization_id=organization.id,
                ip_asset_id=ip.id,
                transport_protocol="TCP",
                port=443,
            ),
        ]
    )
    CanonicalAssetRepository(database_session).add_service(
        ServiceAsset(
            asset_id=service.id,
            organization_id=organization.id,
            endpoint_asset_id=endpoint.id,
            service_kind="HTTPS",
            application_protocol="HTTPS",
            authority_domain_asset_id=domain.id,
            service_key="tcp:192.0.2.20:443:https:www.example.com",
        )
    )
    database_session.commit()

    assert database_session.scalar(select(Asset).where(Asset.organization_id == organization.id))
    assert database_session.get(ServiceAsset, service.id) is not None


def test_duplicate_canonical_key_is_rejected_within_an_organization(
    database_session: Session,
) -> None:
    organization = Organization(id=uuid4(), name="Duplicate Org", slug="duplicate-org")
    database_session.add(organization)
    database_session.commit()
    database_session.add_all(
        [
            _asset(organization.id, "DOMAIN", "domain:www.example.com"),
            _asset(organization.id, "DOMAIN", "domain:www.example.com"),
        ]
    )

    with pytest.raises(IntegrityError):
        database_session.commit()


def test_cross_organization_endpoint_reference_is_rejected(database_session: Session) -> None:
    organization_a = Organization(id=uuid4(), name="Canonical A", slug="canonical-a")
    organization_b = Organization(id=uuid4(), name="Canonical B", slug="canonical-b")
    database_session.add_all([organization_a, organization_b])
    database_session.commit()
    endpoint = _asset(organization_a.id, "ENDPOINT", "endpoint:tcp:192.0.2.21:443")
    foreign_ip = _asset(organization_b.id, "IP", "ip:192.0.2.21")
    database_session.add_all([endpoint, foreign_ip])
    database_session.flush()
    database_session.add(
        EndpointAsset(
            asset_id=endpoint.id,
            organization_id=organization_a.id,
            ip_asset_id=foreign_ip.id,
            transport_protocol="TCP",
            port=443,
        )
    )

    with pytest.raises(IntegrityError):
        database_session.commit()


def test_invalid_endpoint_port_is_rejected(database_session: Session) -> None:
    organization = Organization(id=uuid4(), name="Port Org", slug="port-org")
    database_session.add(organization)
    database_session.commit()
    ip = _asset(organization.id, "IP", "ip:192.0.2.22")
    endpoint = _asset(organization.id, "ENDPOINT", "endpoint:tcp:192.0.2.22:0")
    database_session.add_all([ip, endpoint])
    database_session.flush()
    database_session.add(
        EndpointAsset(
            asset_id=endpoint.id,
            organization_id=organization.id,
            ip_asset_id=ip.id,
            transport_protocol="TCP",
            port=0,
        )
    )

    with pytest.raises(IntegrityError):
        database_session.commit()


def test_service_with_non_endpoint_parent_is_rejected(database_session: Session) -> None:
    organization = Organization(id=uuid4(), name="Service Org", slug="service-org")
    database_session.add(organization)
    database_session.commit()
    domain = _asset(organization.id, "DOMAIN", "domain:service.example.com")
    service = _asset(organization.id, "SERVICE", "service:invalid")
    database_session.add_all([domain, service])
    database_session.flush()

    with pytest.raises(CanonicalAssetValidationError, match="endpoint asset"):
        CanonicalAssetRepository(database_session).add_service(
            ServiceAsset(
                asset_id=service.id,
                organization_id=organization.id,
                endpoint_asset_id=domain.id,
                service_kind="HTTPS",
                application_protocol="HTTPS",
                authority_domain_asset_id=None,
                service_key="invalid",
            )
        )
