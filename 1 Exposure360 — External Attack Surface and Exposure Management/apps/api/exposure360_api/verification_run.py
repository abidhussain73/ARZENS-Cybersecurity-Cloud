"""Phase 7 safe retest orchestration; collection happens through existing approved controls."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import select
from sqlalchemy.orm import Session

from .closure_gate import ClosureGateInput, ClosureGateResult, FindingClosureGate
from .models import (
    ClosureDecisionRecord,
    Finding,
    RemediationTask,
    RemediationTaskEvent,
    VerificationRun,
)
from .remediation import RemediationState, verification_transition


class VerificationRunState(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    PARTIAL = "PARTIAL"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class VerificationResult(StrEnum):
    CONDITION_PRESENT = "CONDITION_PRESENT"
    CONDITION_ABSENT = "CONDITION_ABSENT"
    INCONCLUSIVE = "INCONCLUSIVE"


class VerificationRunError(ValueError):
    """Raised when verification is unauthorized, duplicated, active, or tenant-mismatched."""


@dataclass(frozen=True)
class VerificationCompletion:
    run: VerificationRun
    closure: ClosureGateResult
    closure_record: ClosureDecisionRecord


class VerificationRunService:
    def __init__(self, session: Session):
        self._session = session
        self._gate = FindingClosureGate()

    def request(
        self,
        organization_id: uuid.UUID,
        task_id: uuid.UUID,
        idempotency_key: str,
        requested_at: datetime,
        *,
        scope_approval_valid: bool,
        emergency_stop: bool,
        actor_user_id: uuid.UUID | None = None,
        correlation_id: str = "verification-fixture",
    ) -> VerificationRun:
        task, finding = self._task_and_finding(organization_id, task_id)
        existing = self._session.scalar(
            select(VerificationRun).where(
                VerificationRun.organization_id == organization_id,
                VerificationRun.idempotency_key == idempotency_key,
            )
        )
        if existing is not None:
            return existing
        if not scope_approval_valid:
            raise VerificationRunError("verification requires valid scope approval")
        active = self._session.scalar(
            select(VerificationRun).where(
                VerificationRun.organization_id == organization_id,
                VerificationRun.remediation_task_id == task.id,
                VerificationRun.state.in_(("QUEUED", "RUNNING")),
            )
        )
        if active is not None:
            raise VerificationRunError("verification already active for remediation task")
        now = _utc(requested_at)
        run = VerificationRun(
            id=uuid.uuid4(),
            organization_id=organization_id,
            finding_id=finding.id,
            remediation_task_id=task.id,
            idempotency_key=idempotency_key,
            state=(
                VerificationRunState.CANCELLED if emergency_stop else VerificationRunState.QUEUED
            ).value,
            requested_by_user_id=actor_user_id,
            requested_at=now,
            started_at=None,
            finished_at=now if emergency_stop else None,
            rule_id=finding.rule_id,
            rule_version=finding.rule_version,
            result=(VerificationResult.INCONCLUSIVE if emergency_stop else None),
            evidence_collected_at=None,
            evidence_integrity_valid=False,
            collection_complete=False,
            scope_approval_valid=True,
            correct_target=False,
            metadata_json={"emergency_stop": emergency_stop},
            correlation_id=correlation_id,
        )
        self._session.add(run)
        return run

    def complete(
        self,
        organization_id: uuid.UUID,
        run_id: uuid.UUID,
        completed_at: datetime,
        *,
        result: VerificationResult,
        evidence_collected_at: datetime | None,
        evidence_integrity_valid: bool,
        collection_complete: bool,
        scope_approval_valid: bool,
        correct_target: bool,
        contradictory_current_evidence: bool = False,
        actor_or_system: str = "verification-service",
    ) -> VerificationCompletion:
        run = self._run(organization_id, run_id)
        if run.state == VerificationRunState.CANCELLED.value:
            raise VerificationRunError("cancelled verification cannot complete")
        if run.state not in {VerificationRunState.QUEUED.value, VerificationRunState.RUNNING.value}:
            raise VerificationRunError("verification is not active")
        task, finding = self._task_and_finding(organization_id, run.remediation_task_id)
        when = _utc(completed_at)
        run.state = VerificationRunState.COMPLETED.value
        run.result = result.value
        run.started_at = run.started_at or run.requested_at
        run.finished_at = when
        run.evidence_collected_at = evidence_collected_at
        run.evidence_integrity_valid = evidence_integrity_valid
        run.collection_complete = collection_complete
        run.scope_approval_valid = scope_approval_valid
        run.correct_target = correct_target
        evidence_current = (
            evidence_collected_at is not None and _utc(evidence_collected_at) >= run.started_at
        )
        closure = self._gate.evaluate(
            ClosureGateInput(
                finding_state=finding.state,
                remediation_state=task.state,
                verification_state=run.state,
                verification_result=result.value,
                evidence_current=evidence_current,
                evidence_integrity_valid=evidence_integrity_valid,
                collection_complete=collection_complete,
                scope_approval_valid=scope_approval_valid,
                rule_verification_valid=correct_target,
                contradictory_current_evidence=contradictory_current_evidence,
            )
        )
        record = ClosureDecisionRecord(
            id=uuid.uuid4(),
            organization_id=organization_id,
            finding_id=finding.id,
            remediation_task_id=task.id,
            verification_run_id=run.id,
            decision=closure.decision.value,
            reason_codes=list(closure.reason_codes),
            evidence_ids=[],
            observation_ids=[],
            rule_id=run.rule_id,
            rule_version=run.rule_version,
            decided_at=when,
            actor_or_system=actor_or_system,
        )
        self._session.add(record)
        if closure.decision.value == "ALLOW_CLOSE":
            task.state = verification_transition(RemediationState(task.state)).value
            task.verified_at = when
            finding.state = "CLOSED"
            task.state = RemediationState.CLOSED.value
            task.closed_at = when
            self._event(task, "RESOLVED_PENDING_VERIFICATION", "VERIFIED", when)
            self._event(task, "VERIFIED", "CLOSED", when)
        elif result is VerificationResult.CONDITION_PRESENT:
            task.state = RemediationState.IN_PROGRESS.value
            self._event(task, "RESOLVED_PENDING_VERIFICATION", "IN_PROGRESS", when)
        return VerificationCompletion(run, closure, record)

    def _task_and_finding(
        self, organization_id: uuid.UUID, task_id: uuid.UUID
    ) -> tuple[RemediationTask, Finding]:
        task = self._session.scalar(
            select(RemediationTask).where(
                RemediationTask.id == task_id,
                RemediationTask.organization_id == organization_id,
            )
        )
        if task is None:
            raise VerificationRunError("remediation task not found in organization")
        finding = self._session.scalar(
            select(Finding).where(
                Finding.id == task.finding_id,
                Finding.organization_id == organization_id,
            )
        )
        if finding is None:
            raise VerificationRunError("finding not found in organization")
        return task, finding

    def _run(self, organization_id: uuid.UUID, run_id: uuid.UUID) -> VerificationRun:
        run = self._session.scalar(
            select(VerificationRun).where(
                VerificationRun.id == run_id,
                VerificationRun.organization_id == organization_id,
            )
        )
        if run is None:
            raise VerificationRunError("verification run not found in organization")
        return run

    def _event(self, task: RemediationTask, from_state: str, to_state: str, when: datetime) -> None:
        self._session.add(
            RemediationTaskEvent(
                id=uuid.uuid4(),
                organization_id=task.organization_id,
                remediation_task_id=task.id,
                event_type="verification_state_transition",
                from_state=from_state,
                to_state=to_state,
                actor_user_id=None,
                reason="verification_completion",
                metadata_json={},
                occurred_at=when,
            )
        )


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
