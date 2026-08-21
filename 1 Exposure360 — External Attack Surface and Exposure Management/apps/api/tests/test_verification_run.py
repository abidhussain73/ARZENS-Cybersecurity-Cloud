from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from exposure360_api.db import Base
from exposure360_api.models import Asset, Finding, Organization, RemediationTask
from exposure360_api.verification_run import (
    VerificationResult,
    VerificationRunError,
    VerificationRunService,
)

NOW = datetime(2026, 8, 21, 12, tzinfo=UTC)


@pytest.fixture
def session() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection: object, _: object) -> None:
        connection.execute("PRAGMA foreign_keys=ON")  # type: ignore[union-attr]

    Base.metadata.create_all(engine)
    instance = sessionmaker(bind=engine, expire_on_commit=False)()
    try:
        yield instance
    finally:
        instance.close()
        engine.dispose()


def _pending_task(session: Session, organization_id: UUID) -> RemediationTask:
    asset = Asset(
        id=uuid4(),
        organization_id=organization_id,
        asset_type="SERVICE",
        canonical_key=f"service:{uuid4()}",
        display_name="Local HSTS fixture",
        first_seen=NOW,
        last_seen=NOW,
    )
    finding = Finding(
        id=uuid4(),
        organization_id=organization_id,
        asset_id=asset.id,
        service_asset_id=None,
        rule_id="missing-hsts",
        rule_version=1,
        rule_hash="c" * 64,
        fingerprint=uuid4().hex + uuid4().hex,
        title="HSTS fixture",
        description="Local fixture only.",
        category="EXPOSURE",
        rule_severity="HIGH",
        confidence=0.9,
        state="RESOLVED_PENDING_VERIFICATION",
        first_seen=NOW,
        last_seen=NOW,
        opened_at=NOW,
    )
    task = RemediationTask(
        id=uuid4(),
        organization_id=organization_id,
        finding_id=finding.id,
        asset_id=asset.id,
        source_path_key=None,
        source_relationship_id=None,
        title="Retest local HSTS fixture",
        description=None,
        state="RESOLVED_PENDING_VERIFICATION",
        priority="P2",
        owner_user_id=None,
        opened_at=NOW,
        due_at=NOW + timedelta(days=3),
    )
    session.add_all((asset, finding, task))
    session.flush()
    return task


def _request(service: VerificationRunService, organization_id: UUID, task_id: UUID, key: str):
    return service.request(
        organization_id,
        task_id,
        key,
        NOW,
        scope_approval_valid=True,
        emergency_stop=False,
    )


def test_current_condition_absent_closes_and_decision_is_immutable(session: Session) -> None:
    organization = Organization(id=uuid4(), name="HSTS", slug=f"hsts-{uuid4()}")
    session.add(organization)
    session.flush()
    task = _pending_task(session, organization.id)
    service = VerificationRunService(session)
    run = _request(service, organization.id, task.id, "hsts-fixed")
    completion = service.complete(
        organization.id,
        run.id,
        NOW + timedelta(minutes=1),
        result=VerificationResult.CONDITION_ABSENT,
        evidence_collected_at=NOW + timedelta(seconds=1),
        evidence_integrity_valid=True,
        collection_complete=True,
        scope_approval_valid=True,
        correct_target=True,
    )
    session.commit()

    assert completion.closure.decision.value == "ALLOW_CLOSE"
    assert task.state == "CLOSED"
    with pytest.raises(ValueError):
        completion.closure_record.decision = "INCONCLUSIVE"
        session.flush()


def test_present_or_stale_degraded_evidence_does_not_close(session: Session) -> None:
    organization = Organization(id=uuid4(), name="Negative", slug=f"negative-{uuid4()}")
    session.add(organization)
    session.flush()
    service = VerificationRunService(session)
    present_task = _pending_task(session, organization.id)
    present = _request(service, organization.id, present_task.id, "condition-present")
    denied = service.complete(
        organization.id,
        present.id,
        NOW,
        result=VerificationResult.CONDITION_PRESENT,
        evidence_collected_at=NOW,
        evidence_integrity_valid=True,
        collection_complete=True,
        scope_approval_valid=True,
        correct_target=True,
    )
    stale_task = _pending_task(session, organization.id)
    stale = _request(service, organization.id, stale_task.id, "stale-degraded")
    inconclusive = service.complete(
        organization.id,
        stale.id,
        NOW,
        result=VerificationResult.CONDITION_ABSENT,
        evidence_collected_at=NOW - timedelta(seconds=1),
        evidence_integrity_valid=False,
        collection_complete=False,
        scope_approval_valid=True,
        correct_target=False,
    )

    assert denied.closure.decision.value == "DENY_CLOSE"
    assert present_task.state == "IN_PROGRESS"
    assert inconclusive.closure.decision.value == "INCONCLUSIVE"
    assert stale_task.state == "RESOLVED_PENDING_VERIFICATION"


def test_idempotency_active_control_emergency_stop_and_tenant_scope(session: Session) -> None:
    organization_a = Organization(id=uuid4(), name="Retest A", slug=f"retest-a-{uuid4()}")
    organization_b = Organization(id=uuid4(), name="Retest B", slug=f"retest-b-{uuid4()}")
    session.add_all((organization_a, organization_b))
    session.flush()
    task = _pending_task(session, organization_a.id)
    service = VerificationRunService(session)
    first = _request(service, organization_a.id, task.id, "same-key")
    duplicate = _request(service, organization_a.id, task.id, "same-key")

    assert duplicate.id == first.id
    with pytest.raises(VerificationRunError):
        _request(service, organization_a.id, task.id, "different-key")
    with pytest.raises(VerificationRunError):
        _request(service, organization_b.id, task.id, "foreign")
    with pytest.raises(VerificationRunError):
        service.request(
            organization_a.id,
            task.id,
            "invalid-scope",
            NOW,
            scope_approval_valid=False,
            emergency_stop=False,
        )

    stop_task = _pending_task(session, organization_a.id)
    stopped = service.request(
        organization_a.id,
        stop_task.id,
        "emergency-stop",
        NOW,
        scope_approval_valid=True,
        emergency_stop=True,
    )
    assert stopped.state == "CANCELLED"
    assert stopped.result == "INCONCLUSIVE"
