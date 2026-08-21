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
    RiskFactorResult,
    SlaPolicy,
    User,
    VerifiedControlEvidence,
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
    factor = RiskFactorResult(
        id=uuid.uuid4(),
        organization_id=organization_a.id,
        risk_assessment_id=risk.id,
        factor_key="FINDING_SEVERITY",
        availability="AVAILABLE",
        raw_value_json={"severity": "HIGH"},
        normalized_value=0.75,
        configured_weight=0.3,
        effective_weight=0.3,
        contribution=22.5,
        factor_confidence=1,
        evidence_reference_json={"finding_id": str(primary_finding_id)},
        reason_code=None,
    )
    stale_control = VerifiedControlEvidence(
        id=uuid.uuid4(),
        organization_id=organization_a.id,
        asset_id=primary_asset.id,
        service_asset_id=None,
        finding_id=primary_finding_id,
        relationship_id=None,
        control_type="NETWORK_RESTRICTION",
        control_key="fixture-stale-allowlist",
        verification_state="STALE",
        effectiveness=0.8,
        confidence=0.9,
        verified_at=NOW - timedelta(days=31),
        expires_at=NOW - timedelta(days=1),
        freshness_window_seconds=86_400,
        source_type="fixture",
        source_reference="fixture://stale-control",
        metadata_json={"fixture": True},
    )
    policy = SlaPolicy(
        id=uuid.uuid4(),
        organization_id=organization_a.id,
        policy_key="fixture-high-risk",
        version=1,
        priority="P2",
        acknowledge_within_seconds=None,
        start_within_seconds=None,
        resolve_within_seconds=259_200,
        verify_within_seconds=86_400,
        active=True,
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
        state="OPEN",
        priority="P2",
        owner_user_id=None,
        opened_at=NOW,
        due_at=NOW + timedelta(days=3),
    )
    database_session.add_all(
        [
            primary_asset,
            foreign_asset,
            primary_finding,
            foreign_finding,
            risk,
            foreign_risk,
            factor,
            stale_control,
            policy,
            task,
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
                "asset": primary_asset.id,
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
    assert detail.json()["factors"][0]["key"] == "FINDING_SEVERITY"
    assert detail.json()["verified_controls"][0]["state"] == "STALE"
    assert detail.json()["verified_controls"][0]["reduction_applied"] == 0

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
    assert detail.json()["task"]["state"] == "OPEN"
    assert detail.json()["sla"] is None
    assert detail.json()["history"] == []
    assert detail.json()["verification_runs"] == []
    assert detail.json()["closure_decisions"] == []

    denied = client.get(f"/api/v1/remediation/tasks/{identifiers['task']}", headers=foreign_headers)
    assert denied.status_code == 404
    assert denied.json()["detail"] == "REMEDIATION_TASK_NOT_FOUND"


def test_phase7_remediation_actions_use_named_state_machine_endpoints(
    api_client: tuple[TestClient, dict[str, uuid.UUID]],
) -> None:
    client, identifiers = api_client
    own_headers = _headers(identifiers["org_a"])
    foreign_headers = _headers(identifiers["org_b"])
    task_id = identifiers["task"]

    planned = client.post(
        f"/api/v1/remediation/tasks/{task_id}/plan",
        json={"reason": "Owner plan recorded."},
        headers=own_headers,
    )
    assert planned.status_code == 200
    assert planned.json()["state"] == "PLANNED"

    started = client.post(
        f"/api/v1/remediation/tasks/{task_id}/start",
        json={},
        headers=own_headers,
    )
    assert started.status_code == 200
    assert started.json()["state"] == "IN_PROGRESS"

    unsupported = client.post(
        f"/api/v1/remediation/tasks/{task_id}/close",
        json={},
        headers=own_headers,
    )
    assert unsupported.status_code == 404
    assert unsupported.json()["detail"] == "REMEDIATION_ACTION_NOT_FOUND"

    viewer = client.post(
        f"/api/v1/remediation/tasks/{task_id}/block",
        json={},
        headers=foreign_headers,
    )
    assert viewer.status_code == 403


def test_phase7_remediation_task_create_derives_priority_and_versioned_sla(
    api_client: tuple[TestClient, dict[str, uuid.UUID]],
) -> None:
    client, identifiers = api_client
    headers = _headers(identifiers["org_a"])
    created = client.post(
        "/api/v1/remediation/tasks",
        json={
            "finding_id": str(identifiers["finding"]),
            "title": "Create task from HIGH contextual risk",
            "description": "The deadline must come from the versioned P2 fixture policy.",
        },
        headers=headers,
    )
    assert created.status_code == 200
    assert created.json()["state"] == "OPEN"
    assert created.json()["priority"] == "P2"
    assert created.json()["due_at"] is not None


def test_phase7_exception_request_list_approval_and_rbac(
    api_client: tuple[TestClient, dict[str, uuid.UUID]],
) -> None:
    client, identifiers = api_client
    own_headers = _headers(identifiers["org_a"])
    foreign_headers = _headers(identifiers["org_b"])
    request = client.post(
        "/api/v1/exceptions",
        json={
            "finding_id": str(identifiers["finding"]),
            "remediation_task_id": str(identifiers["task"]),
            "rationale": "Documented maintenance window requires temporary governance review.",
            "expires_at": "2026-09-01T12:00:00Z",
        },
        headers=own_headers,
    )
    assert request.status_code == 200
    assert request.json()["state"] == "REQUESTED"
    exception_id = request.json()["id"]

    listing = client.get("/api/v1/exceptions?state=REQUESTED&limit=1", headers=own_headers)
    assert listing.status_code == 200
    assert listing.json()["page"]["total"] == 1
    assert listing.json()["items"][0]["id"] == exception_id

    approved = client.post(f"/api/v1/exceptions/{exception_id}/approve", headers=own_headers)
    assert approved.status_code == 200
    assert approved.json()["state"] == "APPROVED"

    revoked = client.post(f"/api/v1/exceptions/{exception_id}/revoke", headers=own_headers)
    assert revoked.status_code == 200
    assert revoked.json()["state"] == "REVOKED"
    assert revoked.json()["revoked_at"] is not None

    denied = client.post(f"/api/v1/exceptions/{exception_id}/reject", headers=foreign_headers)
    assert denied.status_code == 403


def test_phase7_attack_path_analysis_and_simulation_are_bounded_and_analytical(
    api_client: tuple[TestClient, dict[str, uuid.UUID]],
) -> None:
    client, identifiers = api_client
    headers = _headers(identifiers["org_a"])
    payload = {
        "start_asset_id": str(identifiers["asset"]),
        "profile": "exposure-to-data-v1",
        "max_hops": 2,
        "max_paths": 10,
        "min_edge_confidence": 0.5,
    }

    analysis = client.post("/api/v1/attack-paths/analyze", json=payload, headers=headers)
    assert analysis.status_code == 200
    assert analysis.json()["analytical_only"] is True
    assert analysis.json()["exploitability_verified"] is False
    assert analysis.json()["analysis_completeness"] == "COMPLETE"
    assert analysis.json()["paths"] == []

    candidates = client.post(
        "/api/v1/attack-paths/path-breaking-candidates",
        json=payload,
        headers=headers,
    )
    assert candidates.status_code == 200
    assert candidates.json()["simulation_only"] is True
    assert candidates.json()["source_system_mutation"] is False
    assert candidates.json()["candidates"] == []

    listing = client.get(
        f"/api/v1/attack-paths?start_asset_id={identifiers['asset']}&limit=10",
        headers=headers,
    )
    assert listing.status_code == 200
    assert listing.json()["analytical_only"] is True
    assert listing.json()["exploitability_verified"] is False
    assert listing.json()["items"] == []


def test_phase7_retest_requires_real_scope_guard_approval_and_keeps_runs_scoped(
    api_client: tuple[TestClient, dict[str, uuid.UUID]],
) -> None:
    client, identifiers = api_client
    own_headers = _headers(identifiers["org_a"])
    foreign_headers = _headers(identifiers["org_b"])
    task_id = identifiers["task"]
    denied = client.post(
        f"/api/v1/remediation/tasks/{task_id}/retest",
        json={
            "scope_id": str(uuid.uuid4()),
            "scope_version_id": str(uuid.uuid4()),
            "approval_id": str(uuid.uuid4()),
            "target": "fixture.example.test",
            "idempotency_key": "scope-guard-denied-retest",
        },
        headers=own_headers,
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["code"] == "SCOPE_GUARD_DENIED"

    listing = client.get(
        f"/api/v1/remediation/tasks/{task_id}/verification-runs",
        headers=own_headers,
    )
    assert listing.status_code == 200
    assert listing.json()["items"] == []

    foreign = client.get(
        f"/api/v1/remediation/tasks/{task_id}/verification-runs",
        headers=foreign_headers,
    )
    assert foreign.status_code == 404
    assert foreign.json()["detail"] == "REMEDIATION_TASK_NOT_FOUND"
