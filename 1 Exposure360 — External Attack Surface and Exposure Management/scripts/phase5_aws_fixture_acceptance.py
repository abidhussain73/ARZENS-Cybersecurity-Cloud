"""Self-cleaning deployed-schema acceptance for Exposure360 Phase 5.

The fixture creates only local database metadata. It performs no DNS, TCP, TLS,
HTTP, credential, exploit, or other active network collection.
"""

import sys
import uuid
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "apps" / "api"))

from exposure360_api.auth import current_principal
from exposure360_api.db import SessionLocal, get_session
from exposure360_api.evaluation_scheduler import EvaluationRunRepository
from exposure360_api.main import app
from exposure360_api.models import (
    ApprovedChange,
    Asset,
    AssetSnapshot,
    AuditEvent,
    ChangeEvent,
    EvaluationRun,
    Finding,
    FindingEvaluationEvent,
    FindingEvidenceLink,
    FindingStateEvent,
    Membership,
    Organization,
    User,
)
from exposure360_api.scheduled_evaluations import ScheduledEvaluationService
from exposure360_api.security import Principal


def main() -> None:
    session = SessionLocal()
    fixture_id = uuid.uuid4()
    now = datetime(2026, 8, 20, 2, 0, tzinfo=UTC)
    user = User(id=uuid.uuid4(), oidc_subject=f"phase5-fixture-{fixture_id}")
    organization = Organization(
        id=uuid.uuid4(),
        name=f"Phase 5 Fixture {fixture_id}",
        slug=f"phase5-fixture-{fixture_id.hex[:20]}",
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
        asset = Asset(
            id=uuid.uuid4(),
            organization_id=organization.id,
            asset_type="DOMAIN",
            canonical_key=f"domain:phase5-{fixture_id.hex[:12]}.example.test",
            display_name=f"phase5-{fixture_id.hex[:12]}.example.test",
            lifecycle_state="ACTIVE",
            first_seen=now,
            last_seen=now,
        )
        session.add(asset)
        session.flush()
        finding = Finding(
            id=uuid.uuid4(),
            organization_id=organization.id,
            asset_id=asset.id,
            service_asset_id=None,
            rule_id="fixture.phase5.missing_hsts",
            rule_version=1,
            rule_hash="a" * 64,
            fingerprint="b" * 64,
            title="Fixture missing HSTS",
            description="Metadata-only fixture finding",
            category="HTTP_SECURITY_HEADER",
            rule_severity="MEDIUM",
            confidence=0.9,
            state="OPEN",
            first_seen=now,
            last_seen=now,
            opened_at=now,
        )
        change = ChangeEvent(
            id=uuid.uuid4(),
            organization_id=organization.id,
            asset_id=asset.id,
            change_type="OWNERSHIP",
            fingerprint="c" * 64,
            from_snapshot_id=None,
            to_snapshot_id=None,
            summary="OWNERSHIP: ownership",
            details_json={"component_key": "ownership", "old": None, "new": {"primary": "team"}},
            first_seen=now,
            last_seen=now,
            state="EXPECTED",
            significance_score=45,
            significance_model_version="change-significance-v1",
            significance_factors_json=[{"factor": "OWNERSHIP_CHANGE", "points": 45}],
        )
        approval = ApprovedChange(
            id=uuid.uuid4(),
            organization_id=organization.id,
            name="Fixture ownership handoff",
            description="Phase 5 acceptance fixture",
            asset_id=asset.id,
            allowed_change_types_json=["OWNERSHIP"],
            component_selector_json={"component_key": "ownership"},
            starts_at=now - timedelta(minutes=1),
            ends_at=now + timedelta(days=1),
            reason="Fixture approved change",
            ticket_reference="FIXTURE-5",
            approved_by_user_id=user.id,
            created_by_user_id=user.id,
            status="ACTIVE",
        )
        change.approved_change_id = approval.id
        expiring = Finding(
            id=uuid.uuid4(),
            organization_id=organization.id,
            asset_id=asset.id,
            service_asset_id=None,
            rule_id="fixture.phase5.expiry",
            rule_version=1,
            rule_hash="d" * 64,
            fingerprint="e" * 64,
            title="Fixture expired exception",
            description="Metadata-only fixture exception",
            category="FIXTURE",
            rule_severity="LOW",
            confidence=0.5,
            state="EXCEPTION",
            first_seen=now,
            last_seen=now,
            opened_at=now,
            exception_reason="Fixture expiry",
            exception_expires_at=now,
        )
        session.add_all([finding, approval, change, expiring])
        session.commit()

        def session_override() -> Generator[Session, None, None]:
            yield session

        app.dependency_overrides[get_session] = session_override
        app.dependency_overrides[current_principal] = lambda: Principal(user=user)
        client = TestClient(app)
        headers = {
            "X-Organization-ID": str(organization.id),
            "X-Correlation-ID": f"phase5-aws-{fixture_id}",
        }
        routes = {
            "findings": "/api/v1/findings?state=OPEN",
            "finding_detail": f"/api/v1/findings/{finding.id}",
            "finding_evidence": f"/api/v1/findings/{finding.id}/evidence",
            "finding_history": f"/api/v1/findings/{finding.id}/history",
            "changes": "/api/v1/changes?change_type=OWNERSHIP",
            "change_detail": f"/api/v1/changes/{change.id}",
            "approved_changes": "/api/v1/approved-changes",
        }
        outcomes: dict[str, int] = {}
        for name, path in routes.items():
            response = client.get(path, headers=headers)
            outcomes[name] = response.status_code
            assert response.status_code == 200, f"{name} route returned {response.status_code}"
        assert client.get(routes["change_detail"], headers=headers).json()["state"] == "EXPECTED"

        repository = EvaluationRunRepository(session)
        execution = repository.start_or_skip(
            organization.id,
            "EXCEPTION_EXPIRY",
            f"phase5-aws-schedule-{fixture_id}",
            started_at=now + timedelta(minutes=1),
        )
        assert execution.run is not None and not execution.skipped_for_overlap
        metrics = ScheduledEvaluationService(session).execute(
            execution.run, now=now + timedelta(minutes=1)
        )
        repository.finish(execution.run, metrics, finished_at=now + timedelta(minutes=1))
        session.commit()
        assert metrics.findings_updated == 1
        assert expiring.state == "OPEN"
        assert (
            session.scalar(
                select(AuditEvent).where(
                    AuditEvent.organization_id == organization.id,
                    AuditEvent.action == "finding.exception_expired",
                )
            )
            is not None
        )
        print(
            {
                "phase5_fixture": "PASS",
                "routes": outcomes,
                "scheduled_exception_expiry": "PASS",
                "alembic_expected_head": "0017",
            }
        )
    finally:
        app.dependency_overrides.clear()
        _cleanup(session, organization.id, user.id)
        session.close()


def _cleanup(session: Session, organization_id: uuid.UUID, user_id: uuid.UUID) -> None:
    session.rollback()
    session.execute(
        delete(FindingEvidenceLink).where(FindingEvidenceLink.organization_id == organization_id)
    )
    session.execute(
        delete(FindingEvaluationEvent).where(
            FindingEvaluationEvent.organization_id == organization_id
        )
    )
    session.execute(
        delete(FindingStateEvent).where(FindingStateEvent.organization_id == organization_id)
    )
    session.execute(delete(Finding).where(Finding.organization_id == organization_id))
    session.execute(delete(ChangeEvent).where(ChangeEvent.organization_id == organization_id))
    session.execute(delete(ApprovedChange).where(ApprovedChange.organization_id == organization_id))
    session.execute(delete(AssetSnapshot).where(AssetSnapshot.organization_id == organization_id))
    session.execute(delete(EvaluationRun).where(EvaluationRun.organization_id == organization_id))
    session.execute(delete(AuditEvent).where(AuditEvent.organization_id == organization_id))
    session.execute(delete(Asset).where(Asset.organization_id == organization_id))
    session.execute(delete(Membership).where(Membership.organization_id == organization_id))
    session.execute(delete(Organization).where(Organization.id == organization_id))
    session.execute(delete(User).where(User.id == user_id))
    session.commit()


if __name__ == "__main__":
    main()
