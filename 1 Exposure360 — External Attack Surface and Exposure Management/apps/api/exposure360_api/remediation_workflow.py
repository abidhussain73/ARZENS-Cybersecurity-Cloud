"""Governed Phase 7 remediation workflow services using UTC elapsed-time SLA semantics."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import RemediationTask, RemediationTaskEvent, RiskAcceptanceException, SlaInstance
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
        instance.paused_at = None
        instance.state = "ACTIVE"
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

    def _event(
        self,
        task: RemediationTask,
        from_state: str,
        to_state: str,
        actor_user_id: uuid.UUID | None,
        reason: str | None,
        occurred_at: datetime,
    ) -> None:
        self._session.add(
            RemediationTaskEvent(
                organization_id=task.organization_id,
                remediation_task_id=task.id,
                event_type="state_transition",
                from_state=from_state,
                to_state=to_state,
                actor_user_id=actor_user_id,
                reason=reason,
                occurred_at=occurred_at,
            )
        )


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
