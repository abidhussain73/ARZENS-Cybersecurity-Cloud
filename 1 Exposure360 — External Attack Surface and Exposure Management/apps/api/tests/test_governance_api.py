import uuid
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from exposure360_api.auth import current_principal
from exposure360_api.db import Base, get_session
from exposure360_api.main import app
from exposure360_api.models import AuditEvent, Membership, Organization, User
from exposure360_api.security import Principal


@pytest.fixture
def database_session() -> Generator[Session, None, None]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    local_session = sessionmaker(bind=engine, expire_on_commit=False)
    session = local_session()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture
def api_client(
    database_session: Session,
) -> Generator[tuple[TestClient, dict[str, uuid.UUID]], None, None]:
    user = User(id=uuid.uuid4(), oidc_subject="phase-two-admin", email="admin@example.test")
    organization_a = Organization(id=uuid.uuid4(), name="Org A", slug="org-a")
    organization_b = Organization(id=uuid.uuid4(), name="Org B", slug="org-b")
    database_session.add_all(
        [
            user,
            organization_a,
            organization_b,
            Membership(
                id=uuid.uuid4(),
                organization_id=organization_a.id,
                user_id=user.id,
                role="admin",
                is_active=True,
            ),
            Membership(
                id=uuid.uuid4(),
                organization_id=organization_b.id,
                user_id=user.id,
                role="admin",
                is_active=True,
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
        yield client, {"org_a": organization_a.id, "org_b": organization_b.id}
    finally:
        app.dependency_overrides.clear()


def _headers(organization_id: uuid.UUID) -> dict[str, str]:
    return {"X-Organization-ID": str(organization_id), "X-Correlation-ID": "phase-two-api-test"}


def test_scope_lifecycle_is_audited_and_approved_versions_are_immutable(
    api_client: tuple[TestClient, dict[str, uuid.UUID]], database_session: Session
) -> None:
    client, ids = api_client
    headers = _headers(ids["org_a"])

    created = client.post(
        "/api/v1/scopes",
        headers=headers,
        json={"name": "Documentation targets", "description": "Reserved test scope"},
    )
    assert created.status_code == 201
    version = created.json()
    scope_id = version["scope_id"]
    version_id = version["id"]

    seed = client.post(
        f"/api/v1/scopes/{scope_id}/versions/{version_id}/seeds",
        headers=headers,
        json={
            "target_type": "DOMAIN",
            "raw_value": "Example.COM.",
            "match_mode": "DOMAIN_AND_SUBDOMAINS",
        },
    )
    assert seed.status_code == 201
    assert seed.json()["canonical_value"] == "example.com"

    exclusion = client.post(
        f"/api/v1/scopes/{scope_id}/versions/{version_id}/exclusions",
        headers=headers,
        json={
            "target_type": "DOMAIN",
            "raw_value": "hidden.example.com",
            "match_mode": "EXACT",
            "reason": "Reserved excluded documentation host",
        },
    )
    assert exclusion.status_code == 201

    policy = client.put(
        f"/api/v1/scopes/{scope_id}/versions/{version_id}/policy",
        headers=headers,
        json={
            "allowed_protocols": ["HTTPS"],
            "max_requests_per_second": 1,
            "max_concurrent_targets": 1,
            "max_concurrent_requests": 1,
            "schedule_timezone": "UTC",
            "schedule_windows": [],
            "active_scanning_enabled": False,
        },
    )
    assert policy.status_code == 200
    assert policy.json()["active_scanning_enabled"] is False

    validation = client.post(
        f"/api/v1/scopes/{scope_id}/versions/{version_id}/validate", headers=headers
    )
    assert validation.status_code == 200
    assert validation.json()["approvable"] is True
    assert validation.json()["content_hash"]

    submitted = client.post(
        f"/api/v1/scopes/{scope_id}/versions/{version_id}/submit", headers=headers
    )
    assert submitted.status_code == 200
    assert submitted.json()["state"] == "SUBMITTED"

    immutable_add = client.post(
        f"/api/v1/scopes/{scope_id}/versions/{version_id}/seeds",
        headers=headers,
        json={"target_type": "DOMAIN", "raw_value": "www.example.com"},
    )
    assert immutable_add.status_code == 409
    assert immutable_add.json()["detail"]["error"]["code"] == "SCOPE_VERSION_IMMUTABLE"

    approval = client.post(
        f"/api/v1/scopes/{scope_id}/versions/{version_id}/approve",
        headers=headers,
        json={"decision_reason": "Governance review complete"},
    )
    assert approval.status_code == 200
    assert approval.json()["decision"] == "APPROVED"

    stopped = client.post(
        f"/api/v1/scopes/{scope_id}/emergency-stop",
        headers=headers,
        json={"reason": "Acceptance control verification"},
    )
    assert stopped.status_code == 200
    assert stopped.json()["active"] is True
    assert stopped.json()["level"] == "SCOPE"

    resumed = client.post(f"/api/v1/scopes/{scope_id}/resume", headers=headers)
    assert resumed.status_code == 200
    assert resumed.json()["active"] is False

    actions = database_session.scalars(
        select(AuditEvent.action)
        .where(AuditEvent.organization_id == ids["org_a"])
        .order_by(AuditEvent.created_at)
    ).all()
    assert {
        "scope.create",
        "scope.version.create",
        "scope.version.update",
        "scope.version.submit",
        "scope.approval.approve",
        "scope.emergency_stop",
        "scope.resume",
    }.issubset(set(actions))
    assert all(
        event.correlation_id == "phase-two-api-test"
        for event in database_session.scalars(select(AuditEvent)).all()
    )


def test_cross_organization_scope_access_is_forbidden(
    api_client: tuple[TestClient, dict[str, uuid.UUID]],
) -> None:
    client, ids = api_client
    created = client.post(
        "/api/v1/scopes", headers=_headers(ids["org_a"]), json={"name": "Organization A scope"}
    )
    assert created.status_code == 201
    scope_id = created.json()["scope_id"]

    response = client.get(f"/api/v1/scopes/{scope_id}", headers=_headers(ids["org_b"]))

    assert response.status_code == 403
    assert response.json()["detail"]["error"]["code"] == "FORBIDDEN"


def test_rejection_and_organization_stop_lifecycle_actions_are_audited(
    api_client: tuple[TestClient, dict[str, uuid.UUID]], database_session: Session
) -> None:
    client, ids = api_client
    headers = _headers(ids["org_a"])
    created = client.post("/api/v1/scopes", headers=headers, json={"name": "Audit action coverage"})
    assert created.status_code == 201
    scope_id = created.json()["scope_id"]
    version_id = created.json()["id"]
    assert (
        client.post(
            f"/api/v1/scopes/{scope_id}/versions/{version_id}/seeds",
            headers=headers,
            json={"target_type": "DOMAIN", "raw_value": "example.com"},
        ).status_code
        == 201
    )
    assert (
        client.put(
            f"/api/v1/scopes/{scope_id}/versions/{version_id}/policy",
            headers=headers,
            json={
                "allowed_protocols": ["HTTPS"],
                "max_requests_per_second": 1,
                "max_concurrent_targets": 1,
                "max_concurrent_requests": 1,
                "schedule_timezone": "UTC",
                "schedule_windows": [],
                "active_scanning_enabled": False,
            },
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/api/v1/scopes/{scope_id}/versions/{version_id}/submit", headers=headers
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/api/v1/scopes/{scope_id}/versions/{version_id}/reject",
            headers=headers,
            json={"decision_reason": "Deterministic audit rejection"},
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/api/v1/organizations/{ids['org_a']}/emergency-stop",
            headers=headers,
            json={"reason": "Deterministic organization stop"},
        ).status_code
        == 200
    )
    assert (
        client.post(f"/api/v1/organizations/{ids['org_a']}/resume", headers=headers).status_code
        == 200
    )

    events = database_session.scalars(
        select(AuditEvent)
        .where(AuditEvent.organization_id == ids["org_a"])
        .order_by(AuditEvent.created_at)
    ).all()
    actions = {event.action for event in events}
    assert {
        "scope.approval.reject",
        "organization.emergency_stop",
        "organization.resume",
    }.issubset(actions)
    assert all(event.correlation_id == "phase-two-api-test" for event in events)
