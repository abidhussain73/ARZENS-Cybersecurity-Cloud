import uuid
from collections.abc import Generator
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from exposure360_api.auth import current_principal
from exposure360_api.db import Base, get_session
from exposure360_api.main import app
from exposure360_api.models import (
    ApprovedChange,
    Asset,
    ChangeEvent,
    Membership,
    Organization,
    User,
)
from exposure360_api.security import Principal

NOW = datetime(2026, 8, 20, 1, 30, tzinfo=UTC)


@pytest.fixture
def api_client() -> Generator[tuple[TestClient, dict[str, uuid.UUID]], None, None]:
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
    user = User(id=uuid.uuid4(), oidc_subject="change-api-user", display_name="Admin")
    organization_a = Organization(id=uuid.uuid4(), name="Change A", slug="change-api-a")
    organization_b = Organization(id=uuid.uuid4(), name="Change B", slug="change-api-b")
    session.add_all([user, organization_a, organization_b])
    session.flush()
    session.add_all(
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
        asset_type="SERVICE",
        canonical_key="service:fixture",
        display_name="fixture service",
        first_seen=NOW,
        last_seen=NOW,
    )
    asset_b = Asset(
        id=uuid.uuid4(),
        organization_id=organization_b.id,
        asset_type="SERVICE",
        canonical_key="service:foreign",
        display_name="foreign service",
        first_seen=NOW,
        last_seen=NOW,
    )
    session.add_all([asset_a, asset_b])
    session.flush()
    approval = ApprovedChange(
        id=uuid.uuid4(),
        organization_id=organization_a.id,
        name="Certificate rotation",
        description="Fixture expected certificate rotation",
        asset_id=asset_a.id,
        allowed_change_types_json=["CERTIFICATE"],
        component_selector_json={"component_key": "certificate"},
        starts_at=NOW - timedelta(hours=1),
        ends_at=NOW + timedelta(hours=1),
        reason="Authorized maintenance",
        ticket_reference="CHG-1",
        approved_by_user_id=user.id,
        created_by_user_id=user.id,
        status="ACTIVE",
    )
    session.add(approval)
    session.flush()
    change = ChangeEvent(
        id=uuid.uuid4(),
        organization_id=organization_a.id,
        asset_id=asset_a.id,
        change_type="CERTIFICATE",
        fingerprint="a" * 64,
        from_snapshot_id=None,
        to_snapshot_id=None,
        summary="CERTIFICATE: certificate",
        details_json={"component_key": "certificate", "old": "old", "new": "new"},
        first_seen=NOW,
        last_seen=NOW,
        state="EXPECTED",
        significance_score=55,
        significance_model_version="change-significance-v1",
        significance_factors_json=[{"factor": "CERTIFICATE_CHANGE", "points": 55}],
        approved_change_id=approval.id,
    )
    session.add(change)
    session.commit()

    def session_override() -> Generator[Session, None, None]:
        yield session

    app.dependency_overrides[get_session] = session_override
    app.dependency_overrides[current_principal] = lambda: Principal(user=user)
    client = TestClient(app)
    try:
        yield client, {"org_a": organization_a.id, "org_b": organization_b.id, "change": change.id}
    finally:
        app.dependency_overrides.clear()
        session.close()
        engine.dispose()


def _headers(organization_id: uuid.UUID) -> dict[str, str]:
    return {"X-Organization-ID": str(organization_id), "X-Correlation-ID": "change-api-test"}


def test_changes_list_detail_expected_and_approved_change_crud(
    api_client: tuple[TestClient, dict[str, uuid.UUID]],
) -> None:
    client, identifiers = api_client
    headers = _headers(identifiers["org_a"])
    listing = client.get(
        "/api/v1/changes?expected=true&significance_min=50&limit=1",
        headers=headers,
    )
    assert listing.status_code == 200
    assert listing.json()["items"][0]["state"] == "EXPECTED"
    detail = client.get(f"/api/v1/changes/{identifiers['change']}", headers=headers)
    assert detail.status_code == 200
    assert detail.json()["significance_factors"][0]["factor"] == "CERTIFICATE_CHANGE"
    assert detail.json()["approved_change"]["name"] == "Certificate rotation"
    created = client.post(
        "/api/v1/approved-changes",
        json={
            "name": "Service maintenance",
            "description": "Fixture service maintenance",
            "asset_id": detail.json()["asset_id"],
            "allowed_change_types": ["SERVICE"],
            "starts_at": "2026-08-20T02:00:00Z",
            "ends_at": "2026-08-20T03:00:00Z",
            "reason": "Approved fixture maintenance",
        },
        headers=headers,
    )
    assert created.status_code == 201
    approval_id = created.json()["id"]
    listed = client.get("/api/v1/approved-changes?limit=1", headers=headers)
    assert listed.status_code == 200
    assert listed.json()["page"]["total"] == 2
    fetched = client.get(f"/api/v1/approved-changes/{approval_id}", headers=headers)
    assert fetched.status_code == 200
    disabled = client.post(f"/api/v1/approved-changes/{approval_id}/disable", headers=headers)
    assert disabled.status_code == 200
    assert disabled.json()["status"] == "DISABLED"


def test_changes_cross_org_denial_and_approved_change_rbac(
    api_client: tuple[TestClient, dict[str, uuid.UUID]],
) -> None:
    client, identifiers = api_client
    foreign_headers = _headers(identifiers["org_b"])
    assert client.get("/api/v1/changes", headers=foreign_headers).json()["items"] == []
    denied = client.get(f"/api/v1/changes/{identifiers['change']}", headers=foreign_headers)
    assert denied.status_code == 404
    assert denied.json()["detail"]["code"] == "CHANGE_NOT_FOUND"
    rbac = client.post(
        "/api/v1/approved-changes",
        json={
            "name": "Viewer attempt",
            "description": "Should be denied",
            "asset_id": str(uuid.uuid4()),
            "allowed_change_types": ["SERVICE"],
            "starts_at": "2026-08-20T02:00:00Z",
            "ends_at": "2026-08-20T03:00:00Z",
            "reason": "No permission",
        },
        headers=foreign_headers,
    )
    assert rbac.status_code == 403
    openapi = client.get("/api/v1/openapi.json")
    assert "/api/v1/changes/{change_id}" in openapi.json()["paths"]
    assert "/api/v1/approved-changes/{approval_id}/disable" in openapi.json()["paths"]
