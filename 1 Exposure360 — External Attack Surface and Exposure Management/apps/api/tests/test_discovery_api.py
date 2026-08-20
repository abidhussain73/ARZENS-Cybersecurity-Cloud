import uuid
from collections.abc import Generator
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from exposure360_api.auth import current_principal
from exposure360_api.db import Base, get_session
from exposure360_api.main import app
from exposure360_api.models import (
    AuditEvent,
    DeadLetterItem,
    Membership,
    Organization,
    ScanPolicy,
    Scope,
    ScopeApproval,
    ScopeSeed,
    ScopeVersion,
    User,
)
from exposure360_api.scope_approval import ScopeApprovalService
from exposure360_api.security import Principal


@pytest.fixture
def database_session() -> Generator[Session, None, None]:
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


@pytest.fixture
def api_client(
    database_session: Session,
) -> Generator[tuple[TestClient, dict[str, uuid.UUID]], None, None]:
    user = User(id=uuid.uuid4(), oidc_subject="discovery-api-admin", email="admin@example.test")
    organization_a = Organization(id=uuid.uuid4(), name="Discovery A", slug="discovery-a")
    organization_b = Organization(id=uuid.uuid4(), name="Discovery B", slug="discovery-b")
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
        yield client, {"user": user.id, "org_a": organization_a.id, "org_b": organization_b.id}
    finally:
        app.dependency_overrides.clear()


def _headers(organization_id: uuid.UUID) -> dict[str, str]:
    return {
        "X-Organization-ID": str(organization_id),
        "X-Correlation-ID": "discovery-api-contract-test",
    }


def _approved_scope(
    session: Session,
    *,
    organization_id: uuid.UUID,
    user_id: uuid.UUID,
    approved: bool = True,
) -> tuple[Scope, ScopeVersion]:
    scope = Scope(
        id=uuid.uuid4(),
        organization_id=organization_id,
        name=f"Scope-{uuid.uuid4().hex[:8]}",
        status="ACTIVE",
        created_by_user_id=user_id,
    )
    version = ScopeVersion(
        id=uuid.uuid4(),
        organization_id=organization_id,
        scope_id=scope.id,
        version_number=1,
        state="APPROVED" if approved else "DRAFT",
        created_by_user_id=user_id,
        content_hash="",
    )
    session.add_all(
        [
            scope,
            version,
            ScopeSeed(
                id=uuid.uuid4(),
                organization_id=organization_id,
                scope_version_id=version.id,
                seed_type="DOMAIN",
                raw_value="example.com",
                canonical_value="example.com",
                match_mode="DOMAIN_AND_SUBDOMAINS",
            ),
            ScanPolicy(
                id=uuid.uuid4(),
                organization_id=organization_id,
                scope_version_id=version.id,
                allowed_protocols=["HTTPS"],
                max_requests_per_second=1.0,
                max_concurrent_targets=1,
                max_concurrent_requests=1,
                schedule_timezone="UTC",
                schedule_windows=[],
                connect_timeout_seconds=5,
                request_timeout_seconds=5,
                active_scanning_enabled=False,
            ),
        ]
    )
    session.flush()
    content_hash = ScopeApprovalService.content_hash(session, version)
    version.content_hash = content_hash
    if approved:
        approval_time = datetime.now(UTC)
        session.add(
            ScopeApproval(
                id=uuid.uuid4(),
                organization_id=organization_id,
                scope_id=scope.id,
                scope_version_id=version.id,
                approved_by_user_id=user_id,
                decision="APPROVED",
                approved_at=approval_time - timedelta(minutes=1),
                expires_at=approval_time + timedelta(days=1),
                content_hash=content_hash,
            )
        )
    session.commit()
    return scope, version


def test_discovery_api_create_list_detail_cancel_and_audit(
    api_client: tuple[TestClient, dict[str, uuid.UUID]],
    database_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, ids = api_client
    scope, version = _approved_scope(
        database_session,
        organization_id=ids["org_a"],
        user_id=ids["user"],
    )
    enqueued: list[dict[str, str]] = []

    def enqueue(_: object, **kwargs: str) -> None:
        enqueued.append(kwargs)

    monkeypatch.setattr("exposure360_api.discovery_api.enqueue_discovery_job", enqueue)
    created = client.post(
        "/api/v1/discovery/jobs",
        headers=_headers(ids["org_a"]),
        json={"scope_id": str(scope.id), "scope_version_id": str(version.id)},
    )

    assert created.status_code == 202
    payload = created.json()
    job_id = payload["id"]
    assert payload["state"] == "QUEUED"
    assert payload["known_total"] is None
    assert payload["indeterminate"] is True
    assert payload["links"]["cancel"].endswith(f"/jobs/{job_id}/cancel")
    assert enqueued == [
        {
            "organization_id": str(ids["org_a"]),
            "job_id": job_id,
            "correlation_id": "discovery-api-contract-test",
        }
    ]
    listed = client.get("/api/v1/discovery/jobs", headers=_headers(ids["org_a"]))
    detail = client.get(f"/api/v1/discovery/jobs/{job_id}", headers=_headers(ids["org_a"]))
    stages = client.get(f"/api/v1/discovery/jobs/{job_id}/stages", headers=_headers(ids["org_a"]))
    events = client.get(f"/api/v1/discovery/jobs/{job_id}/events", headers=_headers(ids["org_a"]))
    assert listed.json()[0]["id"] == job_id
    assert detail.status_code == 200
    assert len(stages.json()) == 8
    assert events.json()[0]["event_type"] == "job.created"

    cancelled = client.post(
        f"/api/v1/discovery/jobs/{job_id}/cancel",
        headers=_headers(ids["org_a"]),
    )
    assert cancelled.status_code == 202
    assert cancelled.json()["state"] == "CANCELLING"
    actions = set(
        database_session.scalars(
            select(AuditEvent.action).where(AuditEvent.organization_id == ids["org_a"])
        )
    )
    assert {"discovery.job.create", "discovery.job.cancel"}.issubset(actions)


def test_discovery_api_rejects_unapproved_and_cross_organization_scope(
    api_client: tuple[TestClient, dict[str, uuid.UUID]],
    database_session: Session,
) -> None:
    client, ids = api_client
    unapproved_scope, unapproved_version = _approved_scope(
        database_session,
        organization_id=ids["org_a"],
        user_id=ids["user"],
        approved=False,
    )
    rejected = client.post(
        "/api/v1/discovery/jobs",
        headers=_headers(ids["org_a"]),
        json={"scope_id": str(unapproved_scope.id), "scope_version_id": str(unapproved_version.id)},
    )
    assert rejected.status_code == 409
    assert rejected.json()["detail"]["error"]["code"] == "APPROVAL_REQUIRED"

    foreign_scope, foreign_version = _approved_scope(
        database_session,
        organization_id=ids["org_b"],
        user_id=ids["user"],
    )
    forbidden = client.post(
        "/api/v1/discovery/jobs",
        headers=_headers(ids["org_a"]),
        json={"scope_id": str(foreign_scope.id), "scope_version_id": str(foreign_version.id)},
    )
    assert forbidden.status_code == 403
    assert forbidden.json()["detail"]["error"]["code"] == "FORBIDDEN"


def test_discovery_api_scopes_dead_letters_and_cross_organization_job_reads(
    api_client: tuple[TestClient, dict[str, uuid.UUID]],
    database_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, ids = api_client
    scope, version = _approved_scope(
        database_session,
        organization_id=ids["org_a"],
        user_id=ids["user"],
    )
    monkeypatch.setattr(
        "exposure360_api.discovery_api.enqueue_discovery_job",
        lambda *_args, **_kwargs: None,
    )
    created = client.post(
        "/api/v1/discovery/jobs",
        headers=_headers(ids["org_a"]),
        json={"scope_id": str(scope.id), "scope_version_id": str(version.id)},
    )
    assert created.status_code == 202
    job_id = uuid.UUID(created.json()["id"])
    database_session.add(
        DeadLetterItem(
            id=uuid.uuid4(),
            organization_id=ids["org_a"],
            discovery_job_id=job_id,
            candidate_id=None,
            stage="HTTP_METADATA",
            operation_key="http:api-fixture",
            attempts=3,
            last_error_class="TRANSIENT_TIMEOUT",
            last_error_safe_message="fixture timeout",
            state="OPEN",
            first_failed_at=datetime(2026, 8, 19, tzinfo=UTC),
            last_failed_at=datetime(2026, 8, 19, tzinfo=UTC) + timedelta(seconds=3),
        )
    )
    database_session.commit()

    dead_letters = client.get(
        f"/api/v1/discovery/jobs/{job_id}/dead-letters",
        headers=_headers(ids["org_a"]),
    )
    assert dead_letters.status_code == 200
    assert dead_letters.json()[0]["safe_message"] == "fixture timeout"
    forbidden = client.get(f"/api/v1/discovery/jobs/{job_id}", headers=_headers(ids["org_b"]))
    assert forbidden.status_code == 403
