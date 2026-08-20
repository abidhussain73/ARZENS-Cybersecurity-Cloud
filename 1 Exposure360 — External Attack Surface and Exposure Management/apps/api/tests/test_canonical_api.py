import uuid
from collections.abc import Generator
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from exposure360_api.auth import current_principal
from exposure360_api.db import Base, get_session
from exposure360_api.main import app
from exposure360_api.models import (
    Asset,
    AssetOwnership,
    CanonicalObservation,
    DomainAsset,
    EndpointAsset,
    Evidence,
    IpAsset,
    Membership,
    Organization,
    ServiceAsset,
    TechnologyFingerprint,
    User,
)
from exposure360_api.security import Principal


@pytest.fixture
def database_session() -> Generator[Session, None, None]:
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


@pytest.fixture
def api_client(
    database_session: Session,
) -> Generator[tuple[TestClient, dict[str, uuid.UUID]], None, None]:
    now = datetime(2026, 1, 20, tzinfo=UTC)
    user = User(id=uuid.uuid4(), oidc_subject="canonical-api-user")
    organization_a = Organization(id=uuid.uuid4(), name="Canonical A", slug="canonical-a")
    organization_b = Organization(id=uuid.uuid4(), name="Canonical B", slug="canonical-b")
    database_session.add_all([user, organization_a, organization_b])
    database_session.flush()
    database_session.add_all(
        [
            Membership(
                id=uuid.uuid4(),
                organization_id=organization_a.id,
                user_id=user.id,
                role="viewer",
            ),
            Membership(
                id=uuid.uuid4(),
                organization_id=organization_b.id,
                user_id=user.id,
                role="viewer",
            ),
        ]
    )
    domain = Asset(
        id=uuid.uuid4(),
        organization_id=organization_a.id,
        asset_type="DOMAIN",
        canonical_key="domain:www.example.test",
        display_name="www.example.test",
        lifecycle_state="ACTIVE",
        first_seen=now,
        last_seen=now,
    )
    ip = Asset(
        id=uuid.uuid4(),
        organization_id=organization_a.id,
        asset_type="IP",
        canonical_key="ip:192.0.2.20",
        display_name="192.0.2.20",
        lifecycle_state="ACTIVE",
        first_seen=now,
        last_seen=now,
    )
    endpoint = Asset(
        id=uuid.uuid4(),
        organization_id=organization_a.id,
        asset_type="ENDPOINT",
        canonical_key="endpoint:tcp:192.0.2.20:443",
        display_name="192.0.2.20:443/tcp",
        lifecycle_state="STALE",
        first_seen=now,
        last_seen=now,
    )
    service = Asset(
        id=uuid.uuid4(),
        organization_id=organization_a.id,
        asset_type="SERVICE",
        canonical_key="service:tcp:192.0.2.20:443:https:www.example.test",
        display_name="https://www.example.test",
        lifecycle_state="ACTIVE",
        first_seen=now,
        last_seen=now,
    )
    database_session.add_all([domain, ip, endpoint, service])
    database_session.flush()
    database_session.add_all(
        [
            DomainAsset(
                asset_id=domain.id,
                organization_id=organization_a.id,
                fqdn_ascii="www.example.test",
                fqdn_unicode=None,
                registrable_domain="example.test",
            ),
            IpAsset(
                asset_id=ip.id,
                organization_id=organization_a.id,
                address="192.0.2.20",
                ip_version=4,
                is_global=False,
                address_class="DOCUMENTATION",
            ),
            EndpointAsset(
                asset_id=endpoint.id,
                organization_id=organization_a.id,
                ip_asset_id=ip.id,
                transport_protocol="TCP",
                port=443,
            ),
            ServiceAsset(
                asset_id=service.id,
                organization_id=organization_a.id,
                endpoint_asset_id=endpoint.id,
                service_kind="HTTPS",
                application_protocol="HTTPS",
                authority_domain_asset_id=domain.id,
                service_key="tcp:192.0.2.20:443:https:www.example.test",
            ),
        ]
    )
    observation = CanonicalObservation(
        id=uuid.uuid4(),
        organization_id=organization_a.id,
        asset_id=domain.id,
        observation_type="DNS_A",
        source_type="FIXTURE",
        source_key="fixture-dns",
        source_record_key="dns-record-1",
        observed_at=now,
        collected_at=now,
        normalized_payload_json={"answers": [{"address": "192.0.2.20"}]},
        normalized_payload_hash="a" * 64,
        idempotency_key="b" * 64,
    )
    database_session.add(observation)
    database_session.flush()
    database_session.add_all(
        [
            Evidence(
                id=uuid.uuid4(),
                organization_id=organization_a.id,
                observation_id=observation.id,
                asset_id=domain.id,
                evidence_type="DNS_METADATA",
                object_store_bucket="metadata-only",
                object_store_key=None,
                sha256="c" * 64,
                size_bytes=10,
                media_type="application/json",
                encoding="utf-8",
                collected_at=now,
                stored_at=now,
                retention_class="STANDARD",
                sensitivity_class="INTERNAL_METADATA",
                collector_name="fixture",
                collector_version="1.0.0",
                metadata_json={"no": "raw bytes"},
                idempotency_key="d" * 64,
            ),
            AssetOwnership(
                id=uuid.uuid4(),
                organization_id=organization_a.id,
                asset_id=domain.id,
                owner_type="TEAM",
                owner_reference="security",
                owner_display_name="Security",
                claim_type="MANUAL",
                confidence=1.0,
                source_type="MANUAL",
                claim_key="e" * 64,
                is_primary=True,
                valid_from=now,
            ),
            TechnologyFingerprint(
                id=uuid.uuid4(),
                organization_id=organization_a.id,
                asset_id=domain.id,
                technology_vendor="Fixture",
                technology_product="FixtureWeb",
                technology_category="web_server",
                version_value="1.2.3",
                version_confidence=0.8,
                confidence=0.8,
                confidence_model_version="phase4-fingerprint-v1",
                rule_id="tech.fixture-web",
                rule_version=1,
                rule_hash="f" * 64,
                ruleset_hash="1" * 64,
                fingerprint_key="2" * 64,
                evidence_fields_json=["http.headers.server"],
                first_seen=now,
                last_seen=now,
            ),
        ]
    )
    database_session.commit()

    def session_override() -> Generator[Session, None, None]:
        yield database_session

    app.dependency_overrides[get_session] = session_override
    app.dependency_overrides[current_principal] = lambda: Principal(user=user)
    client = TestClient(app)
    try:
        yield (
            client,
            {
                "org_a": organization_a.id,
                "org_b": organization_b.id,
                "domain": domain.id,
                "ip": ip.id,
                "endpoint": endpoint.id,
                "service": service.id,
            },
        )
    finally:
        app.dependency_overrides.clear()


def _headers(organization_id: uuid.UUID) -> dict[str, str]:
    return {
        "X-Organization-ID": str(organization_id),
        "X-Correlation-ID": "canonical-api-test",
    }


def test_list_filters_search_pagination_and_detail_summaries(
    api_client: tuple[TestClient, dict[str, uuid.UUID]],
) -> None:
    client, identifiers = api_client
    headers = _headers(identifiers["org_a"])
    listing = client.get("/api/v1/assets", headers=headers)
    assert listing.status_code == 200
    assert listing.json()["page"]["total"] == 4
    domain_item = next(
        item for item in listing.json()["items"] if item["id"] == str(identifiers["domain"])
    )
    assert domain_item["top_technologies"]
    filtered = client.get("/api/v1/assets?asset_type=DOMAIN", headers=headers)
    assert filtered.status_code == 200
    assert [item["asset_type"] for item in filtered.json()["items"]] == ["DOMAIN"]
    searched = client.get("/api/v1/assets?search=domain%3Awww.example", headers=headers)
    assert searched.status_code == 200
    assert searched.json()["page"]["total"] == 1
    paged = client.get("/api/v1/assets?offset=1&limit=1", headers=headers)
    assert paged.status_code == 200
    assert len(paged.json()["items"]) == 1
    detail = client.get(f"/api/v1/assets/{identifiers['domain']}", headers=headers)
    assert detail.status_code == 200
    payload = detail.json()
    assert payload["primary_owner"]["owner_reference"] == "security"
    assert payload["technology_fingerprints"][0]["product"] == "FixtureWeb"
    assert "object_store_key" not in payload
    assert "metadata_json" not in payload


def test_observations_evidence_timeline_and_direct_relationships(
    api_client: tuple[TestClient, dict[str, uuid.UUID]],
) -> None:
    client, identifiers = api_client
    headers = _headers(identifiers["org_a"])
    observation = client.get(
        f"/api/v1/assets/{identifiers['domain']}/observations", headers=headers
    )
    assert observation.status_code == 200
    assert observation.json()["items"][0]["observation_type"] == "DNS_A"
    evidence = client.get(f"/api/v1/assets/{identifiers['domain']}/evidence", headers=headers)
    assert evidence.status_code == 200
    assert "object_store_key" not in evidence.json()[0]
    assert "metadata_json" not in evidence.json()[0]
    timeline = client.get(f"/api/v1/assets/{identifiers['domain']}/timeline", headers=headers)
    assert timeline.status_code == 200
    assert {item["event_type"] for item in timeline.json()} >= {
        "ASSET_FIRST_SEEN",
        "OBSERVATION",
        "OWNERSHIP_CLAIM",
        "FINGERPRINT_FIRST_SEEN",
    }
    domain_relations = client.get(
        f"/api/v1/assets/{identifiers['domain']}/relationships",
        headers=headers,
    )
    assert domain_relations.json()[0]["relationship_type"] == "RESOLVES_TO"
    assert domain_relations.json()[0]["target_asset_id"] == str(identifiers["ip"])
    ip_relations = client.get(f"/api/v1/assets/{identifiers['ip']}/relationships", headers=headers)
    assert ip_relations.json()[0]["relationship_type"] == "HAS_ENDPOINT"
    endpoint_relations = client.get(
        f"/api/v1/assets/{identifiers['endpoint']}/relationships",
        headers=headers,
    )
    assert {item["relationship_type"] for item in endpoint_relations.json()} == {
        "ON_IP",
        "EXPOSES_SERVICE",
    }
    service_relations = client.get(
        f"/api/v1/assets/{identifiers['service']}/relationships",
        headers=headers,
    )
    assert {item["relationship_type"] for item in service_relations.json()} == {
        "ON_ENDPOINT",
        "SERVED_FOR",
    }


def test_cross_org_isolation_ownership_and_openapi_scope(
    api_client: tuple[TestClient, dict[str, uuid.UUID]],
) -> None:
    client, identifiers = api_client
    empty = client.get("/api/v1/assets", headers=_headers(identifiers["org_b"]))
    assert empty.status_code == 200
    assert empty.json()["items"] == []
    denied = client.get(
        f"/api/v1/assets/{identifiers['domain']}",
        headers=_headers(identifiers["org_b"]),
    )
    assert denied.status_code == 404
    ownership = client.get(
        f"/api/v1/assets/{identifiers['domain']}/ownership",
        headers=_headers(identifiers["org_a"]),
    )
    assert ownership.status_code == 200
    assert ownership.json()["primary"]["owner_reference"] == "security"
    openapi = client.get("/api/v1/openapi.json")
    assert openapi.status_code == 200
    paths = openapi.json()["paths"]
    assert "/api/v1/assets/{asset_id}/relationships" in paths
    assert not any("graph" in path for path in paths)
