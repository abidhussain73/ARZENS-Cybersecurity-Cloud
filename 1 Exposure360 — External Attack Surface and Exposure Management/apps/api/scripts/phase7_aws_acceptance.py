from __future__ import annotations

import os
import sys
import uuid
from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy import delete, select

from exposure360_api.db import SessionLocal
from exposure360_api.models import (
    Asset,
    AuditEvent,
    Finding,
    FindingStateEvent,
    Membership,
    Organization,
    RemediationTask,
    RemediationTaskEvent,
    RiskAcceptanceException,
    RiskAssessment,
    RiskFactorResult,
    SlaInstance,
    SlaPolicy,
    User,
    VerifiedControlEvidence,
)


def _status(response: httpx.Response, expected: int) -> dict[str, object]:
    if response.status_code != expected:
        raise RuntimeError(f"expected HTTP {expected}, got {response.status_code}: {response.text}")
    return response.json()


def _token(username: str, password: str) -> str:
    response = httpx.post(
        "http://identity:8080/realms/exposure360/protocol/openid-connect/token",
        data={
            "client_id": "exposure360-web",
            "grant_type": "password",
            "username": username,
            "password": password,
        },
        timeout=15,
    )
    return str(_status(response, 200)["access_token"])


def _cleanup(organization_id: uuid.UUID) -> None:
    with SessionLocal() as session:
        task_ids = select(RemediationTask.id).where(
            RemediationTask.organization_id == organization_id
        )
        risk_ids = select(RiskAssessment.id).where(
            RiskAssessment.organization_id == organization_id
        )
        session.execute(
            delete(RiskAcceptanceException).where(
                RiskAcceptanceException.organization_id == organization_id
            )
        )
        session.execute(delete(SlaInstance).where(SlaInstance.organization_id == organization_id))
        session.execute(
            delete(RemediationTaskEvent).where(
                RemediationTaskEvent.organization_id == organization_id
            )
        )
        session.execute(delete(RemediationTask).where(RemediationTask.id.in_(task_ids)))
        session.execute(
            delete(VerifiedControlEvidence).where(
                VerifiedControlEvidence.organization_id == organization_id
            )
        )
        session.execute(
            delete(RiskFactorResult).where(RiskFactorResult.risk_assessment_id.in_(risk_ids))
        )
        session.execute(
            delete(RiskAssessment).where(RiskAssessment.organization_id == organization_id)
        )
        session.execute(
            delete(FindingStateEvent).where(FindingStateEvent.organization_id == organization_id)
        )
        session.execute(delete(Finding).where(Finding.organization_id == organization_id))
        session.execute(delete(SlaPolicy).where(SlaPolicy.organization_id == organization_id))
        session.execute(delete(Asset).where(Asset.organization_id == organization_id))
        session.execute(delete(AuditEvent).where(AuditEvent.organization_id == organization_id))
        session.execute(delete(Membership).where(Membership.organization_id == organization_id))
        session.execute(delete(Organization).where(Organization.id == organization_id))
        session.commit()


def main() -> int:
    username = os.environ.get("PHASE7_ACCEPTANCE_USERNAME")
    password = os.environ.get("PHASE7_ACCEPTANCE_PASSWORD")
    if not username or not password:
        raise RuntimeError("PHASE7_ACCEPTANCE_USERNAME and PHASE7_ACCEPTANCE_PASSWORD are required")

    token = _token(username, password)
    headers = {"Authorization": f"Bearer {token}", "Host": "localhost"}
    organization_id = uuid.uuid4()
    now = datetime.now(UTC)
    fixture_key = f"phase7-acceptance-{organization_id.hex}"
    try:
        with httpx.Client(base_url="http://api:8000", timeout=20) as client:
            me = _status(client.get("/api/v1/me", headers=headers), 200)
            user_id = uuid.UUID(str(me["id"]))

            with SessionLocal() as session:
                user = session.scalar(select(User).where(User.id == user_id))
                if user is None:
                    raise RuntimeError("authenticated API user was not persisted")
                asset = Asset(
                    id=uuid.uuid4(),
                    organization_id=organization_id,
                    asset_type="DOMAIN",
                    canonical_key=f"domain:{fixture_key}.example.test",
                    display_name=f"{fixture_key}.example.test",
                    lifecycle_state="ACTIVE",
                    first_seen=now,
                    last_seen=now,
                    last_confirmed_at=now,
                    created_from_discovery_job_id=None,
                )
                finding = Finding(
                    id=uuid.uuid4(),
                    organization_id=organization_id,
                    asset_id=asset.id,
                    service_asset_id=None,
                    rule_id="phase7-aws-fixture",
                    rule_version=1,
                    rule_hash="a" * 64,
                    fingerprint=(uuid.uuid4().hex + uuid.uuid4().hex),
                    title="Phase 7 AWS fixture finding",
                    description=(
                        "Self-cleaning fixture only; no active collection or source-system change."
                    ),
                    category="EXPOSURE",
                    rule_severity="HIGH",
                    confidence=0.9,
                    state="OPEN",
                    first_seen=now,
                    last_seen=now,
                    opened_at=now,
                    acknowledged_at=None,
                    in_progress_at=None,
                    resolved_pending_verification_at=None,
                    closed_at=None,
                    exception_at=None,
                    assigned_to_user_id=None,
                    assigned_owner_reference=None,
                    exception_reason=None,
                    exception_expires_at=None,
                )
                assessment = RiskAssessment(
                    id=uuid.uuid4(),
                    organization_id=organization_id,
                    finding_id=finding.id,
                    asset_id=asset.id,
                    service_asset_id=None,
                    model_version="contextual-risk-v1",
                    registry_hash="b" * 64,
                    raw_score=82.0,
                    adjusted_score=82.0,
                    factor_coverage=1.0,
                    confidence=0.9,
                    risk_band="CRITICAL_PRIORITY",
                    evaluated_at=now,
                    explanation_json={"fixture": True},
                )
                factor = RiskFactorResult(
                    id=uuid.uuid4(),
                    organization_id=organization_id,
                    risk_assessment_id=assessment.id,
                    factor_key="FINDING_SEVERITY",
                    availability="AVAILABLE",
                    raw_value_json={"fixture": "HIGH"},
                    normalized_value=0.82,
                    configured_weight=0.30,
                    effective_weight=0.30,
                    contribution=24.6,
                    factor_confidence=0.9,
                    evidence_reference_json={"fixture": fixture_key},
                    reason_code=None,
                )
                stale_control = VerifiedControlEvidence(
                    id=uuid.uuid4(),
                    organization_id=organization_id,
                    asset_id=asset.id,
                    service_asset_id=None,
                    finding_id=finding.id,
                    relationship_id=None,
                    control_type="WAF",
                    control_key=f"fixture-control-{organization_id.hex}",
                    verification_state="STALE",
                    effectiveness=1.0,
                    confidence=1.0,
                    verified_at=now - timedelta(days=2),
                    expires_at=now - timedelta(days=1),
                    freshness_window_seconds=60,
                    source_type="FIXTURE",
                    source_reference=f"fixture:{fixture_key}",
                    metadata_json={"fixture": True},
                )
                policy = SlaPolicy(
                    id=uuid.uuid4(),
                    organization_id=organization_id,
                    policy_key=f"fixture-sla-{organization_id.hex}",
                    version=1,
                    priority="P1",
                    acknowledge_within_seconds=3600,
                    start_within_seconds=7200,
                    resolve_within_seconds=86400,
                    verify_within_seconds=86400,
                    active=True,
                )
                session.add(
                    Organization(
                        id=organization_id,
                        name="Phase 7 AWS Fixture",
                        slug=fixture_key,
                    )
                )
                session.flush()
                session.add_all(
                    [
                        Membership(
                            id=uuid.uuid4(),
                            organization_id=organization_id,
                            user_id=user.id,
                            role="admin",
                            is_active=True,
                        ),
                        asset,
                        finding,
                        assessment,
                        factor,
                        stale_control,
                        policy,
                    ]
                )
                session.commit()

            scoped_headers = headers | {"X-Organization-ID": str(organization_id)}
            risks = _status(client.get("/api/v1/risks?limit=10", headers=scoped_headers), 200)
            if len(risks["items"]) != 1:
                raise RuntimeError("fixture risk list did not remain organization-scoped")
            risk_detail = _status(
                client.get(f"/api/v1/findings/{finding.id}/risk", headers=scoped_headers),
                200,
            )
            if risk_detail["verified_controls"][0]["reduction_applied"] != 0:
                raise RuntimeError("stale verified control applied a risk reduction")
            task = _status(
                client.post(
                    "/api/v1/remediation/tasks",
                    headers=scoped_headers,
                    json={"finding_id": str(finding.id), "title": "AWS fixture remediation"},
                ),
                200,
            )
            task_id = uuid.UUID(str(task["id"]))
            _status(
                client.post(
                    f"/api/v1/remediation/tasks/{task_id}/plan",
                    headers=scoped_headers,
                    json={"reason": "Fixture-only AWS acceptance transition"},
                ),
                200,
            )
            _status(
                client.get(f"/api/v1/remediation/tasks/{task_id}", headers=scoped_headers),
                200,
            )
            _status(
                client.get(f"/api/v1/remediation/tasks/{task_id}/sla", headers=scoped_headers),
                200,
            )
            exception = _status(
                client.post(
                    "/api/v1/exceptions",
                    headers=scoped_headers,
                    json={
                        "finding_id": str(finding.id),
                        "remediation_task_id": str(task_id),
                        "rationale": "Fixture-only acceptance exception",
                        "expires_at": (now + timedelta(days=1)).isoformat(),
                    },
                ),
                200,
            )
            _status(
                client.post(
                    f"/api/v1/exceptions/{exception['id']}/approve",
                    headers=scoped_headers,
                ),
                200,
            )
            denial = client.post(
                f"/api/v1/remediation/tasks/{task_id}/retest",
                headers=scoped_headers,
                json={
                    "scope_id": str(uuid.uuid4()),
                    "scope_version_id": str(uuid.uuid4()),
                    "approval_id": str(uuid.uuid4()),
                    "target": "fixture.example.test",
                    "idempotency_key": str(uuid.uuid4()),
                },
            )
            if (
                denial.status_code != 403
                or denial.json().get("detail", {}).get("code") != "SCOPE_GUARD_DENIED"
            ):
                raise RuntimeError("ScopeGuard did not deny the out-of-scope retest fixture")
            _status(
                client.get(
                    f"/api/v1/remediation/tasks/{task_id}/verification-runs",
                    headers=scoped_headers,
                ),
                200,
            )
            paths = _status(
                client.get(
                    f"/api/v1/attack-paths?start_asset_id={asset.id}&limit=10",
                    headers=scoped_headers,
                ),
                200,
            )
            if (
                paths["analytical_only"] is not True
                or paths["exploitability_verified"] is not False
            ):
                raise RuntimeError("attack-path safety flags were not preserved")
        print("phase7_aws_acceptance=passed fixture_only=true source_system_mutation=false")
        return 0
    finally:
        _cleanup(organization_id)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"phase7_aws_acceptance=failed error={exc}", file=sys.stderr)
        raise
