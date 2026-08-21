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
    Asset,
    Finding,
    Membership,
    Organization,
    RemediationTask,
    RiskAssessment,
    User,
)
from exposure360_api.security import Principal

NOW = datetime(2026, 8, 21, 12, tzinfo=UTC)


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
    user = User(id=uuid.uuid4(), oidc_subject="phase7-api-user", display_name="Phase 7 Admin")
    organization_a = Organization(id=uuid.uuid4(), name="Phase7 A", slug="phase7-api-a")
    organization_b = Organization(id=uuid.uuid4(), name="Phase7 B", slug="phase7-api-b")
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
    primary_finding_id = uuid.uuid4()
    foreign_finding_id = uuid.uuid4()
    primary_asset = Asset(
        id=uuid.uuid4(),
        organization_id=organization_a.id,
        asset_type="SERVICE",
        canonical_key="service:phase7-primary",
        display_name="Phase 7 primary service",
        first_seen=NOW,
        last_seen=NOW,
    )
    foreign_asset = Asset(
        id=uuid.uuid4(),
        organization_id=organization_b.id,
        asset_type="SERVICE",
        canonical_key="service:phase7-foreign",
        display_name="Phase 7 foreign service",
        first_seen=NOW,
        last_seen=NOW,
    )
    primary_finding = Finding(
        id=primary_finding_id,
        organization_id=organization_a.id,
        asset_id=primary_asset.id,
        service_asset_id=None,
        rule_id="phase7-api-fixture",
        rule_version=1,
        rule_hash="c" * 64,
        fingerprint="d" * 64,
        title="Phase 7 API primary finding",
        description="Fixture-only finding for Phase 7 API contracts.",
        category="EXPOSURE",
        rule_severity="HIGH",
        confidence=0.9,
        state="OPEN",
        first_seen=NOW,
        last_seen=NOW,
        opened_at=NOW,
    )
    foreign_finding = Finding(
        id=foreign_finding_id,
        organization_id=organization_b.id,
        asset_id=foreign_asset.id,
        service_asset_id=None,
        rule_id="phase7-api-fixture",
        rule_version=1,
        rule_hash="e" * 64,
        fingerprint="f" * 64,
        title="Phase 7 API foreign finding",
        description="Foreign fixture-only finding for Phase 7 API contracts.",
        category="EXPOSURE",
        rule_severity="MEDIUM",
        confidence=0.8,
        state="OPEN",
        first_seen=NOW,
        last_seen=NOW,
        opened_at=NOW,
    )
    risk = RiskAssessment(
        id=uuid.uuid4(),
        organization_id=organization_a.id,
        finding_id=primary_finding_id,
        asset_id=primary_asset.id,
        service_asset_id=None,
        model_version="contextual-risk-v1",
        registry_hash="a" * 64,
        raw_score=72.5,
        adjusted_score=61.2,
        factor_coverage=0.8,
        confidence=0.76,
        risk_band="HIGH",
        evaluated_at=NOW,
        explanation_json={"fixture": True},
    )
    foreign_risk = RiskAssessment(
        id=uuid.uuid4(),
        organization_id=organization_b.id,
        finding_id=foreign_finding_id,
        asset_id=foreign_asset.id,
        service_asset_id=None,
        model_version="contextual-risk-v1",
        registry_hash="b" * 64,
        raw_score=30,
        adjusted_score=30,
        factor_coverage=1,
        confidence=1,
        risk_band="MODERATE",
        evaluated_at=NOW - timedelta(minutes=1),
        explanation_json={"fixture": "foreign"},
    )
    task = RemediationTask(
        id=uuid.uuid4(),
        organization_id=organization_a.id,
        finding_id=primary_finding_id,
        asset_id=risk.asset_id,
        source_path_key=None,
        source_relationship_id=None,
        title="Review HSTS remediation",
        description="Track approved remediation only.",
        state="IN_PROGRESS",
        priority="P2",
        owner_user_id=None,
        opened_at=NOW,
        due_at=NOW + timedelta(days=3),
    )
    database_session.add_all(
        [primary_asset, foreign_asset, primary_finding, foreign_finding, risk, foreign_risk, task]
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
                "risk": risk.id,
                "finding": primary_finding_id,
                "task": task.id,
            },
        )
    finally:
        app.dependency_overrides.clear()


def _headers(organization_id: uuid.UUID) -> dict[str, str]:
    return {"X-Organization-ID": str(organization_id), "X-Correlation-ID": "phase7-api-test"}


def test_phase7_risk_endpoints_are_bounded_and_labeled(
    api_client: tuple[TestClient, dict[str, uuid.UUID]],
) -> None:
    client, identifiers = api_client
    headers = _headers(identifiers["org_a"])

    listing = client.get("/api/v1/risks?limit=1", headers=headers)
    assert listing.status_code == 200
    assert listing.json()["page"] == {"offset": 0, "limit": 1, "total": 1}
    assert listing.json()["items"][0]["raw_contextual_risk_score"] == 72.5
    assert listing.json()["items"][0]["adjusted_contextual_risk_score"] == 61.2

    detail = client.get(f"/api/v1/risks/{identifiers['risk']}", headers=headers)
    assert detail.status_code == 200
    assert detail.json()["risk_band"] == "HIGH"

    latest = client.get(f"/api/v1/findings/{identifiers['finding']}/risk", headers=headers)
    assert latest.status_code == 200
    assert latest.json()["model_version"] == "contextual-risk-v1"


def test_phase7_risk_and_task_endpoints_are_organization_scoped_and_in_openapi(
    api_client: tuple[TestClient, dict[str, uuid.UUID]],
) -> None:
    client, identifiers = api_client
    foreign_headers = _headers(identifiers["org_b"])

    risk_list = client.get("/api/v1/risks", headers=foreign_headers)
    assert risk_list.status_code == 200
    assert len(risk_list.json()["items"]) == 1

    denied_risk = client.get(f"/api/v1/risks/{identifiers['risk']}", headers=foreign_headers)
    assert denied_risk.status_code == 404
    assert denied_risk.json()["detail"] == "RISK_NOT_FOUND"

    remediation = client.get("/api/v1/remediation/tasks?state=IN_PROGRESS", headers=foreign_headers)
    assert remediation.status_code == 200
    assert remediation.json()["items"] == []

    openapi = client.get("/api/v1/openapi.json")
    assert openapi.status_code == 200
    paths = openapi.json()["paths"]
    assert "/api/v1/risks" in paths
    assert "/api/v1/remediation/tasks" in paths


def test_phase7_remediation_task_detail_is_organization_scoped(
    api_client: tuple[TestClient, dict[str, uuid.UUID]],
) -> None:
    client, identifiers = api_client
    own_headers = _headers(identifiers["org_a"])
    foreign_headers = _headers(identifiers["org_b"])

    detail = client.get(f"/api/v1/remediation/tasks/{identifiers['task']}", headers=own_headers)
    assert detail.status_code == 200
    assert detail.json()["task"]["state"] == "IN_PROGRESS"
    assert detail.json()["sla"] is None
    assert detail.json()["history"] == []
    assert detail.json()["verification_runs"] == []
    assert detail.json()["closure_decisions"] == []

    denied = client.get(f"/api/v1/remediation/tasks/{identifiers['task']}", headers=foreign_headers)
    assert denied.status_code == 404
    assert denied.json()["detail"] == "REMEDIATION_TASK_NOT_FOUND"
