"""Organization-scoped Phase 7 contextual-risk and remediation read APIs."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .auth import current_principal
from .db import get_session
from .models import (
    ClosureDecisionRecord,
    RemediationTask,
    RemediationTaskEvent,
    RiskAcceptanceException,
    RiskAssessment,
    RiskFactorResult,
    SlaInstance,
    VerificationRun,
    VerifiedControlEvidence,
)
from .remediation import RemediationState
from .remediation_workflow import RemediationWorkflowError, RemediationWorkflowService
from .security import (
    OrganizationContext,
    Principal,
    organization_header,
    require_org_context,
    require_role,
)

router = APIRouter(prefix="/api/v1", tags=["phase-7"])


class RemediationTransitionRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=2048)


class ExceptionRequest(BaseModel):
    finding_id: uuid.UUID
    remediation_task_id: uuid.UUID | None = None
    rationale: str = Field(min_length=1, max_length=4096)
    expires_at: datetime


def _context(
    session: Session,
    principal: Principal,
    organization_id: str | None,
) -> OrganizationContext:
    return require_org_context(session, principal, organization_id)


@router.get("/risks")
def list_risks(
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
    offset: int = Query(default=0, ge=0, le=100_000),
    limit: int = Query(default=50, ge=1, le=100),
) -> dict[str, object]:
    context = _context(session, principal, organization_id)
    filters = [RiskAssessment.organization_id == context.organization_id]
    rows = list(
        session.scalars(
            select(RiskAssessment)
            .where(*filters)
            .order_by(RiskAssessment.evaluated_at.desc(), RiskAssessment.id.asc())
            .offset(offset)
            .limit(limit)
        )
    )
    total = session.scalar(select(func.count(RiskAssessment.id)).where(*filters)) or 0
    return {
        "items": [_risk(item) for item in rows],
        "page": {"offset": offset, "limit": limit, "total": total},
    }


@router.get("/risks/{risk_assessment_id}")
def get_risk(
    risk_assessment_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> dict[str, object]:
    context = _context(session, principal, organization_id)
    item = session.scalar(
        select(RiskAssessment).where(
            RiskAssessment.id == risk_assessment_id,
            RiskAssessment.organization_id == context.organization_id,
        )
    )
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="RISK_NOT_FOUND")
    return _risk_detail(session, context, item)


@router.get("/findings/{finding_id}/risk")
def latest_finding_risk(
    finding_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> dict[str, object]:
    context = _context(session, principal, organization_id)
    item = session.scalar(
        select(RiskAssessment)
        .where(
            RiskAssessment.finding_id == finding_id,
            RiskAssessment.organization_id == context.organization_id,
        )
        .order_by(RiskAssessment.evaluated_at.desc())
    )
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="RISK_NOT_FOUND")
    return _risk_detail(session, context, item)


@router.get("/remediation/tasks")
def list_remediation_tasks(
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
    state: str | None = Query(default=None, max_length=40),
    offset: int = Query(default=0, ge=0, le=100_000),
    limit: int = Query(default=50, ge=1, le=100),
) -> dict[str, object]:
    context = _context(session, principal, organization_id)
    filters = [RemediationTask.organization_id == context.organization_id]
    if state:
        filters.append(RemediationTask.state == state)
    rows = list(
        session.scalars(
            select(RemediationTask)
            .where(*filters)
            .order_by(RemediationTask.due_at.asc(), RemediationTask.id.asc())
            .offset(offset)
            .limit(limit)
        )
    )
    total = session.scalar(select(func.count(RemediationTask.id)).where(*filters)) or 0
    return {
        "items": [_task(item) for item in rows],
        "page": {"offset": offset, "limit": limit, "total": total},
    }


@router.get("/remediation/tasks/{task_id}")
def get_remediation_task(
    task_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> dict[str, object]:
    context = _context(session, principal, organization_id)
    task = session.scalar(
        select(RemediationTask).where(
            RemediationTask.id == task_id,
            RemediationTask.organization_id == context.organization_id,
        )
    )
    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="REMEDIATION_TASK_NOT_FOUND",
        )
    events = list(
        session.scalars(
            select(RemediationTaskEvent)
            .where(
                RemediationTaskEvent.organization_id == context.organization_id,
                RemediationTaskEvent.remediation_task_id == task.id,
            )
            .order_by(RemediationTaskEvent.occurred_at.asc(), RemediationTaskEvent.id.asc())
        )
    )
    exceptions = list(
        session.scalars(
            select(RiskAcceptanceException).where(
                RiskAcceptanceException.organization_id == context.organization_id,
                RiskAcceptanceException.remediation_task_id == task.id,
            )
        )
    )
    sla = session.scalar(
        select(SlaInstance).where(
            SlaInstance.organization_id == context.organization_id,
            SlaInstance.remediation_task_id == task.id,
        )
    )
    verification_runs = list(
        session.scalars(
            select(VerificationRun)
            .where(
                VerificationRun.organization_id == context.organization_id,
                VerificationRun.remediation_task_id == task.id,
            )
            .order_by(VerificationRun.requested_at.desc(), VerificationRun.id.asc())
        )
    )
    decisions = list(
        session.scalars(
            select(ClosureDecisionRecord).where(
                ClosureDecisionRecord.organization_id == context.organization_id,
                ClosureDecisionRecord.remediation_task_id == task.id,
            )
        )
    )
    return {
        "task": _task(task),
        "sla": _sla(sla),
        "exceptions": [_exception(item) for item in exceptions],
        "verification_runs": [_verification(item) for item in verification_runs],
        "closure_decisions": [_closure(item) for item in decisions],
        "history": [_event(item) for item in events],
    }


@router.post("/remediation/tasks/{task_id}/{action}")
def transition_remediation_task(
    task_id: uuid.UUID,
    action: str,
    payload: RemediationTransitionRequest,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> dict[str, object]:
    context = _context(session, principal, organization_id)
    require_role(context, "analyst", "admin", "owner")
    targets = {
        "plan": RemediationState.PLANNED,
        "start": RemediationState.IN_PROGRESS,
        "block": RemediationState.BLOCKED,
        "resolve-pending-verification": RemediationState.RESOLVED_PENDING_VERIFICATION,
        "cancel": RemediationState.CANCELLED,
    }
    target = targets.get(action)
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="REMEDIATION_ACTION_NOT_FOUND",
        )
    try:
        task = RemediationWorkflowService(session).transition(
            context.organization_id,
            task_id,
            target,
            datetime.now(UTC),
            actor_user_id=principal.user.id,
            reason=payload.reason,
        )
        session.commit()
    except RemediationWorkflowError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "INVALID_REMEDIATION_TRANSITION", "message": str(exc)},
        ) from exc
    return _task(task)


@router.get("/exceptions")
def list_exceptions(
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
    state: str | None = Query(default=None, max_length=16),
    offset: int = Query(default=0, ge=0, le=100_000),
    limit: int = Query(default=50, ge=1, le=100),
) -> dict[str, object]:
    context = _context(session, principal, organization_id)
    filters = [RiskAcceptanceException.organization_id == context.organization_id]
    if state:
        filters.append(RiskAcceptanceException.state == state)
    rows = list(
        session.scalars(
            select(RiskAcceptanceException)
            .where(*filters)
            .order_by(RiskAcceptanceException.requested_at.desc(), RiskAcceptanceException.id.asc())
            .offset(offset)
            .limit(limit)
        )
    )
    total = session.scalar(select(func.count(RiskAcceptanceException.id)).where(*filters)) or 0
    return {
        "items": [_exception(item) for item in rows],
        "page": {"offset": offset, "limit": limit, "total": total},
    }


@router.post("/exceptions")
def request_exception(
    payload: ExceptionRequest,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> dict[str, object]:
    context = _context(session, principal, organization_id)
    require_role(context, "analyst", "admin", "owner")
    now = datetime.now(UTC)
    exception = RiskAcceptanceException(
        id=uuid.uuid4(),
        organization_id=context.organization_id,
        finding_id=payload.finding_id,
        remediation_task_id=payload.remediation_task_id,
        state="REQUESTED",
        requested_by_user_id=principal.user.id,
        requested_at=now,
        rationale=payload.rationale,
        approved_by_user_id=None,
        approved_at=None,
        expires_at=payload.expires_at,
        revoked_at=None,
    )
    try:
        RemediationWorkflowService(session).request_exception(exception)
        session.commit()
    except RemediationWorkflowError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "INVALID_EXCEPTION_TRANSITION", "message": str(exc)},
        ) from exc
    return _exception(exception)


@router.post("/exceptions/{exception_id}/approve")
def approve_exception(
    exception_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> dict[str, object]:
    context = _context(session, principal, organization_id)
    require_role(context, "reviewer", "admin", "owner")
    try:
        exception = RemediationWorkflowService(session).approve_exception(
            context.organization_id,
            exception_id,
            principal.user.id,
            datetime.now(UTC),
        )
        session.commit()
    except RemediationWorkflowError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "INVALID_EXCEPTION_TRANSITION", "message": str(exc)},
        ) from exc
    return _exception(exception)


@router.post("/exceptions/{exception_id}/reject")
def reject_exception(
    exception_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> dict[str, object]:
    context = _context(session, principal, organization_id)
    require_role(context, "reviewer", "admin", "owner")
    try:
        exception = RemediationWorkflowService(session).reject_exception(
            context.organization_id,
            exception_id,
        )
        session.commit()
    except RemediationWorkflowError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "INVALID_EXCEPTION_TRANSITION", "message": str(exc)},
        ) from exc
    return _exception(exception)


def _risk(item: RiskAssessment) -> dict[str, object]:
    return {
        "id": str(item.id),
        "finding_id": str(item.finding_id),
        "raw_contextual_risk_score": item.raw_score,
        "adjusted_contextual_risk_score": item.adjusted_score,
        "risk_band": item.risk_band,
        "risk_confidence": item.confidence,
        "factor_coverage": item.factor_coverage,
        "model_version": item.model_version,
        "registry_hash": item.registry_hash,
        "evaluated_at": item.evaluated_at,
    }


def _risk_detail(
    session: Session,
    context: OrganizationContext,
    item: RiskAssessment,
) -> dict[str, object]:
    factors = list(
        session.scalars(
            select(RiskFactorResult)
            .where(
                RiskFactorResult.organization_id == context.organization_id,
                RiskFactorResult.risk_assessment_id == item.id,
            )
            .order_by(RiskFactorResult.factor_key.asc())
        )
    )
    controls = list(
        session.scalars(
            select(VerifiedControlEvidence)
            .where(
                VerifiedControlEvidence.organization_id == context.organization_id,
                VerifiedControlEvidence.finding_id == item.finding_id,
            )
            .order_by(VerifiedControlEvidence.verified_at.desc(), VerifiedControlEvidence.id.asc())
        )
    )
    detail = _risk(item)
    detail["factors"] = [_factor(factor) for factor in factors]
    detail["verified_controls"] = [_control(control) for control in controls]
    return detail


def _task(item: RemediationTask) -> dict[str, object]:
    return {
        "id": str(item.id),
        "finding_id": str(item.finding_id),
        "state": item.state,
        "priority": item.priority,
        "due_at": item.due_at,
        "opened_at": item.opened_at,
    }


def _factor(item: RiskFactorResult) -> dict[str, object]:
    return {
        "key": item.factor_key,
        "availability": item.availability,
        "raw_value": item.raw_value_json,
        "normalized_value": item.normalized_value,
        "configured_weight": item.configured_weight,
        "effective_weight": item.effective_weight,
        "contribution": item.contribution,
        "confidence": item.factor_confidence,
        "evidence_reference": item.evidence_reference_json,
        "reason_code": item.reason_code,
    }


def _control(item: VerifiedControlEvidence) -> dict[str, object]:
    state = item.verification_state
    return {
        "id": str(item.id),
        "control_type": item.control_type,
        "control_key": item.control_key,
        "state": state,
        "freshness": "STALE" if state == "STALE" else state,
        "verified_at": item.verified_at,
        "expires_at": item.expires_at,
        "effectiveness": item.effectiveness,
        "confidence": item.confidence,
        "reduction_applied": 0 if state in {"STALE", "INVALID", "REVOKED"} else None,
        "source_reference": item.source_reference,
    }


def _event(item: RemediationTaskEvent) -> dict[str, object]:
    return {
        "id": str(item.id),
        "event_type": item.event_type,
        "from_state": item.from_state,
        "to_state": item.to_state,
        "reason": item.reason,
        "metadata": item.metadata_json,
        "occurred_at": item.occurred_at,
    }


def _exception(item: RiskAcceptanceException) -> dict[str, object]:
    return {
        "id": str(item.id),
        "state": item.state,
        "rationale": item.rationale,
        "requested_at": item.requested_at,
        "approved_at": item.approved_at,
        "expires_at": item.expires_at,
        "revoked_at": item.revoked_at,
    }


def _sla(item: SlaInstance | None) -> dict[str, object] | None:
    if item is None:
        return None
    return {
        "policy_version": item.policy_version,
        "state": item.state,
        "started_at": item.started_at,
        "resolve_due_at": item.resolve_due_at,
        "verify_due_at": item.verify_due_at,
        "final_due_at": item.final_due_at,
        "paused_at": item.paused_at,
        "paused_duration_seconds": item.paused_duration_seconds,
    }


def _verification(item: VerificationRun) -> dict[str, object]:
    return {
        "id": str(item.id),
        "state": item.state,
        "result": item.result,
        "requested_at": item.requested_at,
        "started_at": item.started_at,
        "finished_at": item.finished_at,
        "evidence_integrity_valid": item.evidence_integrity_valid,
        "collection_complete": item.collection_complete,
        "correct_target": item.correct_target,
    }


def _closure(item: ClosureDecisionRecord) -> dict[str, object]:
    return {
        "id": str(item.id),
        "decision": item.decision,
        "reason_codes": item.reason_codes,
        "decided_at": item.decided_at,
        "rule_id": item.rule_id,
        "rule_version": item.rule_version,
    }
