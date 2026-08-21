"""Governed Phase 7 remediation workflow services using UTC elapsed-time SLA semantics."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import (
    Finding,
    RemediationTask,
    RemediationTaskEvent,
    RiskAcceptanceException,
    SlaInstance,
    SlaPolicy,
)
from .remediation import RemediationState, validate_transition


class RemediationWorkflowError(ValueError):
    """Raised for tenant-isolation, state-machine, or SLA policy violations."""


@dataclass(frozen=True)
class SlaTerms:
    priority: str
    resolve_within_seconds: int
    verify_within_seconds: int = 0


class SlaClock:
    """Simple Calendar v1: all due dates are UTC elapsed durations, without holiday logic."""

    @staticmethod
    def due_at(opened_at: datetime, terms: SlaTerms) -> datetime:
        return _utc(opened_at) + timedelta(seconds=terms.resolve_within_seconds)

    @staticmethod
    def overdue(task: RemediationTask, now: datetime) -> bool:
        return task.state not in {"CLOSED", "CANCELLED"} and _utc(now) > _utc(task.due_at)


class RemediationWorkflowService:
    def __init__(self, session: Session):
        self._session = session

    def create_task(
        self,
        organization_id: uuid.UUID,
        finding_id: uuid.UUID,
        policy: SlaPolicy,
        opened_at: datetime,
        *,
        title: str,
        description: str | None = None,
        risk_band: str,
        actor_user_id: uuid.UUID | None = None,
    ) -> RemediationTask:
        finding = self._session.scalar(
            select(Finding).where(
                Finding.id == finding_id,
                Finding.organization_id == organization_id,
            )
        )
        if finding is None:
            raise RemediationWorkflowError("finding not found in organization")
        if policy.organization_id not in {None, organization_id}:
            raise RemediationWorkflowError("SLA policy not available in organization")
        priority = priority_for_risk_band(risk_band)
        if policy.priority != priority:
            raise RemediationWorkflowError("SLA policy priority does not match risk band")
        when = _utc(opened_at)
        due_at = SlaClock.due_at(
            when,
            SlaTerms(
                priority=policy.priority,
                resolve_within_seconds=policy.resolve_within_seconds,
                verify_within_seconds=policy.verify_within_seconds or 0,
            ),
        )
        task = RemediationTask(
            id=uuid.uuid4(),
            organization_id=organization_id,
            finding_id=finding.id,
            asset_id=finding.asset_id,
            source_path_key=None,
            source_relationship_id=None,
            title=title,
            description=description,
            state=RemediationState.OPEN.value,
            priority=priority,
            owner_user_id=None,
            opened_at=when,
            due_at=due_at,
        )
        self._session.add(task)
        self._session.flush()
        self._session.add(
            SlaInstance(
                id=uuid.uuid4(),
                organization_id=organization_id,
                remediation_task_id=task.id,
                policy_id=policy.id,
                policy_version=policy.version,
                started_at=when,
                resolve_due_at=due_at,
                verify_due_at=None,
                final_due_at=due_at,
                paused_at=None,
                paused_duration_seconds=0,
                state="ACTIVE",
            )
        )
        self._event(task, None, RemediationState.OPEN.value, actor_user_id, "task_created", when)
        return task

    def transition(
        self,
        organization_id: uuid.UUID,
        task_id: uuid.UUID,
        target: RemediationState,
        occurred_at: datetime,
        *,
        actor_user_id: uuid.UUID | None = None,
        reason: str | None = None,
    ) -> RemediationTask:
        task = self._task(organization_id, task_id)
        current = RemediationState(task.state)
        validate_transition(current, target)
        when = _utc(occurred_at)
        task.state = target.value
        if target is RemediationState.RESOLVED_PENDING_VERIFICATION:
            task.resolved_pending_at = when
        elif target is RemediationState.CLOSED:
            task.closed_at = when
        self._event(task, current.value, target.value, actor_user_id, reason, when)
        return task

    def request_exception(self, exception: RiskAcceptanceException) -> RiskAcceptanceException:
        if exception.state != "REQUESTED":
            raise RemediationWorkflowError("new exceptions must begin in REQUESTED state")
        self._session.add(exception)
        return exception

    def approve_exception(
        self,
        organization_id: uuid.UUID,
        exception_id: uuid.UUID,
        approver_user_id: uuid.UUID,
        approved_at: datetime,
    ) -> RiskAcceptanceException:
        exception = self._session.scalar(
            select(RiskAcceptanceException).where(
                RiskAcceptanceException.id == exception_id,
                RiskAcceptanceException.organization_id == organization_id,
            )
        )
        if exception is None:
            raise RemediationWorkflowError("exception not found in organization")
        if exception.state != "REQUESTED":
            raise RemediationWorkflowError("exception is not awaiting approval")
        exception.state = "APPROVED"
        exception.approved_by_user_id = approver_user_id
        exception.approved_at = _utc(approved_at)
        return exception

    def reject_exception(
        self,
        organization_id: uuid.UUID,
        exception_id: uuid.UUID,
    ) -> RiskAcceptanceException:
        exception = self._exception(organization_id, exception_id)
        if exception.state != "REQUESTED":
            raise RemediationWorkflowError("exception is not awaiting approval")
        exception.state = "REJECTED"
        return exception

    def expire_exceptions(
        self, organization_id: uuid.UUID, now: datetime
    ) -> list[RiskAcceptanceException]:
        when = _utc(now)
        expired = list(
            self._session.scalars(
                select(RiskAcceptanceException).where(
                    RiskAcceptanceException.organization_id == organization_id,
                    RiskAcceptanceException.state == "APPROVED",
                    RiskAcceptanceException.expires_at <= when,
                )
            )
        )
        for exception in expired:
            exception.state = "EXPIRED"
        return expired

    def pause_sla(
        self, organization_id: uuid.UUID, task_id: uuid.UUID, paused_at: datetime
    ) -> SlaInstance:
        instance = self._sla_instance(organization_id, task_id)
        if instance.paused_at is not None:
            raise RemediationWorkflowError("SLA is already paused")
        instance.paused_at = _utc(paused_at)
        instance.state = "PAUSED"
        return instance

    def resume_sla(
        self, organization_id: uuid.UUID, task_id: uuid.UUID, resumed_at: datetime
    ) -> SlaInstance:
        instance = self._sla_instance(organization_id, task_id)
        if instance.paused_at is None:
            raise RemediationWorkflowError("SLA is not paused")
        duration = max(0, int((_utc(resumed_at) - _utc(instance.paused_at)).total_seconds()))
        instance.paused_duration_seconds += duration
        instance.final_due_at += timedelta(seconds=duration)
        if instance.resolve_due_at is not None:
            instance.resolve_due_at += timedelta(seconds=duration)
        task = self._task(organization_id, task_id)
        task.due_at = instance.final_due_at
        instance.paused_at = None
        instance.state = "ACTIVE"
        return instance

    def extend_sla(
        self,
        organization_id: uuid.UUID,
        task_id: uuid.UUID,
        extension_seconds: int,
        occurred_at: datetime,
        *,
        actor_user_id: uuid.UUID | None = None,
        reason: str,
    ) -> SlaInstance:
        if extension_seconds <= 0:
            raise RemediationWorkflowError("SLA extension must be positive")
        if not reason:
            raise RemediationWorkflowError("SLA extension requires a reason")
        task = self._task(organization_id, task_id)
        instance = self._sla_instance(organization_id, task_id)
        extension = timedelta(seconds=extension_seconds)
        instance.final_due_at += extension
        if instance.resolve_due_at is not None:
            instance.resolve_due_at += extension
        task.due_at = instance.final_due_at
        self._event(
            task,
            task.state,
            task.state,
            actor_user_id,
            reason,
            _utc(occurred_at),
            event_type="sla_extension",
            metadata={"extension_seconds": extension_seconds},
        )
        return instance

    def _task(self, organization_id: uuid.UUID, task_id: uuid.UUID) -> RemediationTask:
        task = self._session.scalar(
            select(RemediationTask).where(
                RemediationTask.id == task_id, RemediationTask.organization_id == organization_id
            )
        )
        if task is None:
            raise RemediationWorkflowError("remediation task not found in organization")
        return task

    def _sla_instance(self, organization_id: uuid.UUID, task_id: uuid.UUID) -> SlaInstance:
        instance = self._session.scalar(
            select(SlaInstance).where(
                SlaInstance.remediation_task_id == task_id,
                SlaInstance.organization_id == organization_id,
            )
        )
        if instance is None:
            raise RemediationWorkflowError("SLA instance not found in organization")
        return instance

    def _exception(
        self, organization_id: uuid.UUID, exception_id: uuid.UUID
    ) -> RiskAcceptanceException:
        exception = self._session.scalar(
            select(RiskAcceptanceException).where(
                RiskAcceptanceException.id == exception_id,
                RiskAcceptanceException.organization_id == organization_id,
            )
        )
        if exception is None:
            raise RemediationWorkflowError("exception not found in organization")
        return exception

    def _event(
        self,
        task: RemediationTask,
        from_state: str | None,
        to_state: str,
        actor_user_id: uuid.UUID | None,
        reason: str | None,
        occurred_at: datetime,
        *,
        event_type: str = "state_transition",
        metadata: dict[str, object] | None = None,
    ) -> None:
        self._session.add(
            RemediationTaskEvent(
                organization_id=task.organization_id,
                remediation_task_id=task.id,
                event_type=event_type,
                from_state=from_state,
                to_state=to_state,
                actor_user_id=actor_user_id,
                reason=reason,
                metadata_json=metadata or {},
                occurred_at=occurred_at,
            )
        )


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def priority_for_risk_band(risk_band: str) -> str:
    priority_by_band = {
        "CRITICAL_PRIORITY": "P1",
        "HIGH": "P2",
        "ELEVATED": "P3",
        "MODERATE": "P4",
        "LOW": "P4",
    }
    try:
        return priority_by_band[risk_band]
    except KeyError as error:
        raise RemediationWorkflowError("unknown risk band") from error
