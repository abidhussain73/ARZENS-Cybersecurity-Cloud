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
    Evidence,
    Finding,
    FindingEvaluationEvent,
    FindingEvidenceLink,
    FindingStateEvent,
    Membership,
    Organization,
    User,
)
from exposure360_api.security import Principal

NOW = datetime(2026, 8, 20, 1, 30, tzinfo=UTC)


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
    user = User(id=uuid.uuid4(), oidc_subject="finding-api-user", display_name="Admin")
    organization_a = Organization(id=uuid.uuid4(), name="Finding A", slug="finding-api-a")
    organization_b = Organization(id=uuid.uuid4(), name="Finding B", slug="finding-api-b")
    database_session.add_all([user, organization_a, organization_b])
    database_session.flush()
    database_session.add_all(
        [
            Membership(
                id=uuid.uuid4(),
                organization_id=organization_a.id,
                user_id=user.id,
                role="admin",
            ),
            Membership(
                id=uuid.uuid4(),
                organization_id=organization_b.id,
                user_id=user.id,
                role="viewer",
            ),
        ]
    )
    asset_a = Asset(
        id=uuid.uuid4(),
        organization_id=organization_a.id,
        asset_type="DOMAIN",
        canonical_key="domain:www.example.test",
        display_name="www.example.test",
        first_seen=NOW,
        last_seen=NOW,
    )
    asset_b = Asset(
        id=uuid.uuid4(),
        organization_id=organization_b.id,
        asset_type="DOMAIN",
        canonical_key="domain:foreign.example.test",
        display_name="foreign.example.test",
        first_seen=NOW,
        last_seen=NOW,
    )
    database_session.add_all([asset_a, asset_b])
    database_session.flush()
    evidence = Evidence(
        id=uuid.uuid4(),
        organization_id=organization_a.id,
        observation_id=None,
        asset_id=asset_a.id,
        evidence_type="HTTP_RESPONSE",
        object_store_bucket="fixture-metadata",
        object_store_key=None,
        sha256="a" * 64,
        size_bytes=16,
        media_type="application/json",
        encoding="utf-8",
        source_observed_at=NOW,
        collected_at=NOW,
        stored_at=NOW,
        retention_class="STANDARD",
        sensitivity_class="INTERNAL_METADATA",
        collector_name="fixture",
        collector_version="1",
        metadata_json={},
        idempotency_key="b" * 64,
    )
    finding = Finding(
        id=uuid.uuid4(),
        organization_id=organization_a.id,
        asset_id=asset_a.id,
        service_asset_id=None,
        rule_id="exposure.http.missing_hsts",
        rule_version=1,
        rule_hash="c" * 64,
        fingerprint="d" * 64,
        title="Missing HSTS",
        description="Fixture metadata demonstrates an absent HSTS header.",
        category="HTTP_SECURITY_HEADER",
        rule_severity="MEDIUM",
        confidence=0.9,
        state="OPEN",
        first_seen=NOW,
        last_seen=NOW,
        opened_at=NOW,
    )
    database_session.add_all([evidence, finding])
    database_session.flush()
    database_session.add_all(
        [
            FindingEvidenceLink(
                id=uuid.uuid4(),
                organization_id=organization_a.id,
                finding_id=finding.id,
                evidence_id=evidence.id,
                observation_id=None,
                rule_id=finding.rule_id,
                rule_version=1,
                link_key="e" * 64,
            ),
            FindingEvaluationEvent(
                id=uuid.uuid4(),
                organization_id=organization_a.id,
                finding_id=finding.id,
                evaluation_run_id=None,
                rule_version=1,
                matched=True,
                confidence=0.9,
                evidence_set_hash="f" * 64,
                evaluated_at=NOW,
            ),
            FindingStateEvent(
                id=uuid.uuid4(),
                organization_id=organization_a.id,
                finding_id=finding.id,
                from_state=None,
                to_state="OPEN",
                actor_user_id=user.id,
                reason="fixture created",
                correlation_id="finding-api-fixture",
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
                "finding": finding.id,
            },
        )
    finally:
        app.dependency_overrides.clear()


def _headers(organization_id: uuid.UUID) -> dict[str, str]:
    return {"X-Organization-ID": str(organization_id), "X-Correlation-ID": "finding-api-test"}


def test_findings_list_detail_evidence_history_filters_and_transitions(
    api_client: tuple[TestClient, dict[str, uuid.UUID]],
) -> None:
    client, identifiers = api_client
    headers = _headers(identifiers["org_a"])
    listing = client.get("/api/v1/findings?state=OPEN&confidence_min=0.8", headers=headers)
    assert listing.status_code == 200
    assert listing.json()["page"]["total"] == 1
    finding_id = identifiers["finding"]
    detail = client.get(f"/api/v1/findings/{finding_id}", headers=headers)
    assert detail.status_code == 200
    assert detail.json()["rule_id"] == "exposure.http.missing_hsts"
    assert detail.json()["asset"]["display_name"] == "www.example.test"
    evidence = client.get(f"/api/v1/findings/{finding_id}/evidence", headers=headers)
    assert evidence.status_code == 200
    assert evidence.json()[0]["sha256"] == "a" * 64
    assert "object_store_key" not in evidence.json()[0]
    history = client.get(f"/api/v1/findings/{finding_id}/history?limit=1", headers=headers)
    assert history.status_code == 200
    assert history.json()["page"]["total"] == 2
    acknowledged = client.post(
        f"/api/v1/findings/{finding_id}/acknowledge", json={}, headers=headers
    )
    assert acknowledged.status_code == 200
    assert acknowledged.json()["state"] == "ACKNOWLEDGED"
    invalid_close = client.post(f"/api/v1/findings/{finding_id}/close", json={}, headers=headers)
    assert invalid_close.status_code == 409
    assert invalid_close.json()["detail"]["code"] == "INVALID_FINDING_TRANSITION"
    exception = client.post(
        f"/api/v1/findings/{finding_id}/exception",
        json={"reason": "planned maintenance", "expires_at": "2026-08-21T00:00:00Z"},
        headers=headers,
    )
    assert exception.status_code == 200
    assert exception.json()["state"] == "EXCEPTION"
    assert exception.json()["exception"]["reason"] == "planned maintenance"


def test_findings_cross_organization_denial_and_openapi(
    api_client: tuple[TestClient, dict[str, uuid.UUID]],
) -> None:
    client, identifiers = api_client
    foreign_headers = _headers(identifiers["org_b"])
    listing = client.get("/api/v1/findings", headers=foreign_headers)
    assert listing.status_code == 200
    assert listing.json()["items"] == []
    denied = client.get(f"/api/v1/findings/{identifiers['finding']}", headers=foreign_headers)
    assert denied.status_code == 404
    assert denied.json()["detail"]["code"] == "FINDING_NOT_FOUND"
    openapi = client.get("/api/v1/openapi.json")
    assert openapi.status_code == 200
    paths = openapi.json()["paths"]
    assert "/api/v1/findings/{finding_id}/evidence" in paths
    assert not any("risk" in path for path in paths)
