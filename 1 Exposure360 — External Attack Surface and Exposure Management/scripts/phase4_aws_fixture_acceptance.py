"""Self-cleaning live-schema acceptance for Exposure360 Phase 4.

This script creates a disposable organization and canonical fixture facts, validates
the registered API with FastAPI's in-process client, then deletes every fixture row.
It performs no DNS, TCP, TLS, HTTP collection, or other active network work.
"""

import uuid
from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy import delete

from exposure360_api.auth import current_principal
from exposure360_api.db import SessionLocal, get_session
from exposure360_api.main import app
from exposure360_api.models import (
    Asset,
    AssetIdentifier,
    AssetOwnership,
    AuditEvent,
    CanonicalObservation,
    DomainAsset,
    EndpointAsset,
    Evidence,
    FingerprintEvidenceLink,
    IpAsset,
    Membership,
    Organization,
    OwnershipEvidenceLink,
    ServiceAsset,
    TechnologyFingerprint,
    User,
)
from exposure360_api.security import Principal


def main() -> None:
    session = SessionLocal()
    fixture_id = uuid.uuid4()
    now = datetime(2026, 8, 20, tzinfo=UTC)
    user = User(id=uuid.uuid4(), oidc_subject=f"phase4-fixture-{fixture_id}")
    organization = Organization(
        id=uuid.uuid4(),
        name=f"Phase 4 Fixture {fixture_id}",
        slug=f"phase4-fixture-{fixture_id.hex[:20]}",
    )
    try:
        session.add_all([user, organization])
        session.flush()
        session.add(
            Membership(
                id=uuid.uuid4(),
                organization_id=organization.id,
                user_id=user.id,
                role="admin",
            )
        )
        domain = Asset(
            id=uuid.uuid4(),
            organization_id=organization.id,
            asset_type="DOMAIN",
            canonical_key=f"domain:fixture-{fixture_id.hex[:12]}.example.test",
            display_name=f"fixture-{fixture_id.hex[:12]}.example.test",
            lifecycle_state="ACTIVE",
            first_seen=now,
            last_seen=now,
        )
        ip = Asset(
            id=uuid.uuid4(),
            organization_id=organization.id,
            asset_type="IP",
            canonical_key="ip:192.0.2.77",
            display_name="192.0.2.77",
            lifecycle_state="ACTIVE",
            first_seen=now,
            last_seen=now,
        )
        session.add_all([domain, ip])
        session.flush()
        session.add_all(
            [
                DomainAsset(
                    asset_id=domain.id,
                    organization_id=organization.id,
                    fqdn_ascii=domain.display_name,
                    fqdn_unicode=None,
                    registrable_domain="example.test",
                ),
                IpAsset(
                    asset_id=ip.id,
                    organization_id=organization.id,
                    address="192.0.2.77",
                    ip_version=4,
                    is_global=False,
                    address_class="DOCUMENTATION",
                ),
            ]
        )
        observation = CanonicalObservation(
            id=uuid.uuid4(),
            organization_id=organization.id,
            asset_id=domain.id,
            observation_type="DNS_A",
            source_type="FIXTURE",
            source_key="phase4-aws-fixture",
            source_record_key=str(fixture_id),
            observed_at=now,
            collected_at=now,
            normalized_payload_json={"answers": [{"address": "192.0.2.77"}]},
            normalized_payload_hash="a" * 64,
            idempotency_key="b" * 64,
        )
        evidence = Evidence(
            id=uuid.uuid4(),
            organization_id=organization.id,
            observation_id=observation.id,
            asset_id=domain.id,
            evidence_type="DNS_METADATA",
            object_store_bucket="metadata-only",
            object_store_key=None,
            sha256="c" * 64,
            size_bytes=19,
            media_type="application/json",
            encoding="utf-8",
            collected_at=now,
            stored_at=now,
            retention_class="STANDARD",
            sensitivity_class="INTERNAL_METADATA",
            collector_name="phase4-fixture",
            collector_version="1.0.0",
            metadata_json={"fixture": True},
            idempotency_key="d" * 64,
        )
        ownership = AssetOwnership(
            id=uuid.uuid4(),
            organization_id=organization.id,
            asset_id=domain.id,
            owner_type="TEAM",
            owner_reference="fixture-security",
            owner_display_name="Fixture Security",
            claim_type="MANUAL",
            confidence=1.0,
            source_type="MANUAL",
            claim_key="e" * 64,
            is_primary=True,
            valid_from=now,
        )
        session.add_all([observation, evidence, ownership])
        session.commit()

        def session_override():
            yield session

        app.dependency_overrides[get_session] = session_override
        app.dependency_overrides[current_principal] = lambda: Principal(user=user)
        client = TestClient(app)
        headers = {
            "X-Organization-ID": str(organization.id),
            "X-Correlation-ID": f"phase4-aws-{fixture_id}",
        }
        routes = [
            ("/api/v1/assets?asset_type=DOMAIN", "list"),
            (f"/api/v1/assets/{domain.id}", "detail"),
            (f"/api/v1/assets/{domain.id}/observations", "observations"),
            (f"/api/v1/assets/{domain.id}/evidence", "evidence"),
            (f"/api/v1/assets/{domain.id}/ownership", "ownership"),
            (f"/api/v1/assets/{domain.id}/relationships", "relationships"),
        ]
        outcomes: dict[str, int] = {}
        for path, name in routes:
            response = client.get(path, headers=headers)
            outcomes[name] = response.status_code
            assert response.status_code == 200, f"{name} route returned {response.status_code}"
            if name == "evidence":
                assert "object_store_key" not in response.json()[0]
        relationships = client.get(routes[-1][0], headers=headers).json()
        assert relationships[0]["relationship_type"] == "RESOLVES_TO"
        assert relationships[0]["target_asset_id"] == str(ip.id)
        print({"phase4_fixture": "PASS", "routes": outcomes, "alembic_expected_head": "0010"})
    finally:
        app.dependency_overrides.clear()
        _cleanup(session, organization.id, user.id)
        session.close()


def _cleanup(session, organization_id: uuid.UUID, user_id: uuid.UUID) -> None:
    session.rollback()
    organization_models = [
        FingerprintEvidenceLink,
        OwnershipEvidenceLink,
        TechnologyFingerprint,
        AssetOwnership,
        Evidence,
        CanonicalObservation,
        AssetIdentifier,
        ServiceAsset,
        EndpointAsset,
        DomainAsset,
        IpAsset,
        Asset,
        AuditEvent,
        Membership,
    ]
    for model in organization_models:
        session.execute(delete(model).where(model.organization_id == organization_id))
    session.execute(delete(Organization).where(Organization.id == organization_id))
    session.execute(delete(User).where(User.id == user_id))
    session.commit()


if __name__ == "__main__":
    main()
