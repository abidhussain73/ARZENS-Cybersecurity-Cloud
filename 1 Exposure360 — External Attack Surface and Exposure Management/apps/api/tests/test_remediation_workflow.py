from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from exposure360_api.db import Base
from exposure360_api.models import (
    Asset,
    Finding,
    Organization,
    RemediationTask,
    RemediationTaskEvent,
    RiskAcceptanceException,
    SlaInstance,
    SlaPolicy,
)
from exposure360_api.remediation import RemediationState, RemediationTransitionError
from exposure360_api.remediation_workflow import (
    RemediationWorkflowError,
    RemediationWorkflowService,
    SlaClock,
    SlaTerms,
)

NOW = datetime(2026, 8, 21, 12, tzinfo=UTC)


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


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


def _finding(session: Session, organization_id: UUID, key: str) -> Finding:
    asset = Asset(
        id=uuid4(),
        organization_id=organization_id,
        asset_type="SERVICE",
        canonical_key=f"service:{key}",
        display_name=key,
        first_seen=NOW,
        last_seen=NOW,
    )
    finding = Finding(
        id=uuid4(),
        organization_id=organization_id,
        asset_id=asset.id,
        service_asset_id=None,
        rule_id="phase-seven-remediation-fixture",
        rule_version=1,
        rule_hash="b" * 64,
        fingerprint=uuid4().hex + uuid4().hex,
        title="Fixture remediation finding",
        description="Fixture-only finding for remediation workflow acceptance.",
        category="EXPOSURE",
        rule_severity="HIGH",
        confidence=0.9,
        state="OPEN",
        first_seen=NOW,
        last_seen=NOW,
        opened_at=NOW,
    )
    session.add_all((asset, finding))
    session.flush()
    return finding


def _policy(session: Session, organization_id: UUID, priority: str = "P2") -> SlaPolicy:
    policy = SlaPolicy(
        id=uuid4(),
        organization_id=organization_id,
        policy_key="simple-calendar-v1",
        version=1,
        priority=priority,
        acknowledge_within_seconds=None,
        start_within_seconds=None,
        resolve_within_seconds=72 * 60 * 60,
        verify_within_seconds=None,
        active=True,
    )
    session.add(policy)
    session.flush()
    return policy


def _workflow_task(
    session: Session,
    organization_id: UUID,
    *,
    risk_band: str = "HIGH",
) -> RemediationTask:
    finding = _finding(session, organization_id, str(uuid4()))
    policy = _policy(session, organization_id)
    return RemediationWorkflowService(session).create_task(
        organization_id,
        finding.id,
        policy,
        NOW,
        title="Review approved remediation configuration",
        description="Track approved work only; do not execute source-system changes.",
        risk_band=risk_band,
    )


def _task(due_at: datetime, state: str = "IN_PROGRESS") -> RemediationTask:
    return RemediationTask(
        id=uuid4(),
        organization_id=uuid4(),
        finding_id=uuid4(),
        asset_id=None,
        source_path_key=None,
        source_relationship_id=None,
        title="Fixture remediation",
        description=None,
        state=state,
        priority="P1",
        owner_user_id=None,
        opened_at=NOW,
        due_at=due_at,
    )


def test_sla_uses_utc_elapsed_time_and_exact_boundary_is_not_overdue() -> None:
    due_at = SlaClock.due_at(NOW, SlaTerms("P1", 24 * 60 * 60))
    task = _task(due_at)

    assert due_at == NOW + timedelta(days=1)
    assert SlaClock.overdue(task, due_at - timedelta(seconds=1)) is False
    assert SlaClock.overdue(task, due_at) is False
    assert SlaClock.overdue(task, due_at + timedelta(seconds=1)) is True


def test_terminal_tasks_are_not_overdue() -> None:
    due_at = NOW - timedelta(seconds=1)

    assert SlaClock.overdue(_task(due_at, "CLOSED"), NOW) is False
    assert SlaClock.overdue(_task(due_at, "CANCELLED"), NOW) is False


def test_task_creation_derives_priority_persists_policy_and_records_state_history(
    session: Session,
) -> None:
    organization = Organization(id=uuid4(), name="Workflow", slug=f"workflow-{uuid4()}")
    session.add(organization)
    session.flush()
    task = _workflow_task(session, organization.id)
    workflow = RemediationWorkflowService(session)
    workflow.transition(organization.id, task.id, RemediationState.IN_PROGRESS, NOW)
    workflow.transition(
        organization.id,
        task.id,
        RemediationState.RESOLVED_PENDING_VERIFICATION,
        NOW + timedelta(hours=1),
    )
    session.commit()

    instance = session.scalar(
        select(SlaInstance).where(
            SlaInstance.organization_id == organization.id,
            SlaInstance.remediation_task_id == task.id,
        )
    )
    events = session.scalars(
        select(RemediationTaskEvent)
        .where(RemediationTaskEvent.remediation_task_id == task.id)
        .order_by(RemediationTaskEvent.occurred_at)
    ).all()

    assert task.priority == "P2"
    assert task.due_at == NOW + timedelta(hours=72)
    assert task.state == RemediationState.RESOLVED_PENDING_VERIFICATION.value
    assert instance is not None
    assert instance.policy_version == 1
    assert _as_utc(instance.final_due_at) == _as_utc(task.due_at)
    assert [(item.from_state, item.to_state) for item in events] == [
        (None, "OPEN"),
        ("OPEN", "IN_PROGRESS"),
        ("IN_PROGRESS", "RESOLVED_PENDING_VERIFICATION"),
    ]


def test_generic_workflow_cannot_verify_or_close_without_verification_service(
    session: Session,
) -> None:
    organization = Organization(id=uuid4(), name="No bypass", slug=f"no-bypass-{uuid4()}")
    session.add(organization)
    session.flush()
    task = _workflow_task(session, organization.id)
    workflow = RemediationWorkflowService(session)
    workflow.transition(organization.id, task.id, RemediationState.IN_PROGRESS, NOW)

    with pytest.raises(RemediationTransitionError):
        workflow.transition(organization.id, task.id, RemediationState.CLOSED, NOW)
    with pytest.raises(RemediationTransitionError):
        workflow.transition(organization.id, task.id, RemediationState.VERIFIED, NOW)


def test_exception_lifecycle_expiry_preserves_finding_and_sla_pause_resume_extension_audit(
    session: Session,
) -> None:
    organization = Organization(id=uuid4(), name="Exception", slug=f"exception-{uuid4()}")
    session.add(organization)
    session.flush()
    task = _workflow_task(session, organization.id)
    workflow = RemediationWorkflowService(session)
    exception = RiskAcceptanceException(
        id=uuid4(),
        organization_id=organization.id,
        finding_id=task.finding_id,
        remediation_task_id=task.id,
        state="REQUESTED",
        requested_by_user_id=uuid4(),
        requested_at=NOW,
        rationale="Approved temporary operational exception fixture.",
        approved_by_user_id=None,
        approved_at=None,
        expires_at=NOW + timedelta(hours=1),
        revoked_at=None,
    )
    workflow.request_exception(exception)
    workflow.approve_exception(organization.id, exception.id, uuid4(), NOW)
    workflow.pause_sla(organization.id, task.id, NOW + timedelta(hours=1))
    resumed = workflow.resume_sla(organization.id, task.id, NOW + timedelta(hours=3))
    workflow.extend_sla(
        organization.id,
        task.id,
        3600,
        NOW + timedelta(hours=3),
        actor_user_id=uuid4(),
        reason="Approved maintenance window extension",
    )
    expired = workflow.expire_exceptions(organization.id, NOW + timedelta(hours=4))
    session.commit()

    extension_event = session.scalar(
        select(RemediationTaskEvent).where(
            RemediationTaskEvent.remediation_task_id == task.id,
            RemediationTaskEvent.event_type == "sla_extension",
        )
    )

    assert exception.state == "EXPIRED"
    assert [item.id for item in expired] == [exception.id]
    assert resumed.paused_duration_seconds == 7200
    assert _as_utc(task.due_at) == NOW + timedelta(hours=75)
    assert extension_event is not None
    assert extension_event.metadata_json == {"extension_seconds": 3600}
    assert session.get(Finding, task.finding_id) is not None


def test_exception_rejection_and_cross_organization_task_and_exception_denial(
    session: Session,
) -> None:
    organization_a = Organization(id=uuid4(), name="Workflow A", slug=f"workflow-a-{uuid4()}")
    organization_b = Organization(id=uuid4(), name="Workflow B", slug=f"workflow-b-{uuid4()}")
    session.add_all((organization_a, organization_b))
    session.flush()
    task = _workflow_task(session, organization_a.id)
    workflow = RemediationWorkflowService(session)
    exception = RiskAcceptanceException(
        id=uuid4(),
        organization_id=organization_a.id,
        finding_id=task.finding_id,
        remediation_task_id=task.id,
        state="REQUESTED",
        requested_by_user_id=uuid4(),
        requested_at=NOW,
        rationale="Fixture rejection lifecycle.",
        approved_by_user_id=None,
        approved_at=None,
        expires_at=NOW + timedelta(days=1),
        revoked_at=None,
    )
    workflow.request_exception(exception)
    rejected = workflow.reject_exception(organization_a.id, exception.id)

    with pytest.raises(RemediationWorkflowError):
        workflow.transition(organization_b.id, task.id, RemediationState.IN_PROGRESS, NOW)
    with pytest.raises(RemediationWorkflowError):
        workflow.approve_exception(organization_b.id, exception.id, uuid4(), NOW)

    assert rejected.state == "REJECTED"
