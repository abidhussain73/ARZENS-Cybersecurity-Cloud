"""Organization-scoped Phase 7 contextual-risk and remediation read APIs."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, cast

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .attack_path_analysis import AttackPathScorer
from .auth import current_principal
from .db import get_session
from .findings import FindingService, FindingStateError
from .graph_traversal import (
    GRAPH_MAX_HOPS,
    GRAPH_MAX_PATHS,
    TRAVERSAL_PROFILES,
    GraphPath,
    GraphTraversalService,
    TraversalProfile,
    TraversalResult,
)
from .models import (
    ClosureDecisionRecord,
    Finding,
    RemediationTask,
    RemediationTaskEvent,
    RiskAcceptanceException,
    RiskAssessment,
    RiskFactorResult,
    SlaInstance,
    SlaPolicy,
    VerificationRun,
    VerifiedControlEvidence,
)
from .path_breaking import PathBreakingSimulator
from .relationships import ASSET, GraphNodeReference, RelationshipError
from .remediation import RemediationState, RemediationTransitionError
from .remediation_workflow import (
    RemediationWorkflowError,
    RemediationWorkflowService,
    priority_for_risk_band,
)
from .scope_guard import OperationContext, ScopeAuthorizationRequest, ScopeGuard
from .security import (
    OrganizationContext,
    Principal,
    organization_header,
    require_org_context,
    require_role,
)
from .verification_run import VerificationRunError, VerificationRunService

router = APIRouter(prefix="/api/v1", tags=["phase-7"])


class RemediationTransitionRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=2048)


class RemediationTaskCreateRequest(BaseModel):
    finding_id: uuid.UUID
    title: str = Field(min_length=1, max_length=1024)
    description: str | None = Field(default=None, max_length=8192)


class ExceptionRequest(BaseModel):
    finding_id: uuid.UUID
    remediation_task_id: uuid.UUID | None = None
    rationale: str = Field(min_length=1, max_length=4096)
    expires_at: datetime


class AttackPathAnalysisRequest(BaseModel):
    start_asset_id: uuid.UUID
    profile: str = Field(default="exposure-to-data-v1", max_length=64)
    max_hops: int | None = Field(default=None, ge=1, le=GRAPH_MAX_HOPS)
    max_paths: int = Field(default=100, ge=1, le=GRAPH_MAX_PATHS)
    min_edge_confidence: float = Field(default=0, ge=0, le=1)
    effective_at: datetime | None = None


class RetestRequest(BaseModel):
    scope_id: uuid.UUID
    scope_version_id: uuid.UUID
    approval_id: uuid.UUID
    target: str = Field(min_length=1, max_length=512)
    protocol: str = Field(default="HTTPS", max_length=16)
    idempotency_key: str = Field(min_length=1, max_length=128)


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


@router.post("/remediation/tasks")
def create_remediation_task(
    payload: RemediationTaskCreateRequest,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> dict[str, object]:
    context = _context(session, principal, organization_id)
    require_role(context, "analyst", "admin", "owner")
    risk = session.scalar(
        select(RiskAssessment)
        .where(
            RiskAssessment.organization_id == context.organization_id,
            RiskAssessment.finding_id == payload.finding_id,
        )
        .order_by(RiskAssessment.evaluated_at.desc(), RiskAssessment.id.asc())
    )
    if risk is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="RISK_NOT_FOUND")
    policy = session.scalar(
        select(SlaPolicy)
        .where(
            SlaPolicy.active.is_(True),
            SlaPolicy.organization_id.in_((None, context.organization_id)),
            SlaPolicy.priority == priority_for_risk_band(risk.risk_band),
        )
        .order_by(SlaPolicy.organization_id.desc(), SlaPolicy.version.desc(), SlaPolicy.id.asc())
    )
    if policy is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="SLA_POLICY_NOT_FOUND")
    try:
        task = RemediationWorkflowService(session).create_task(
            context.organization_id,
            payload.finding_id,
            policy,
            datetime.now(UTC),
            title=payload.title,
            description=payload.description,
            risk_band=risk.risk_band,
            actor_user_id=principal.user.id,
        )
        session.commit()
    except RemediationWorkflowError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "REMEDIATION_TASK_CREATE_DENIED", "message": str(exc)},
        ) from exc
    return _task(task)


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


@router.post("/remediation/tasks/{task_id}/retest")
def request_retest_priority(
    task_id: uuid.UUID,
    payload: RetestRequest,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> dict[str, object]:
    return request_retest(task_id, payload, session, principal, organization_id)


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
        finding_target = {
            RemediationState.IN_PROGRESS: "IN_PROGRESS",
            RemediationState.RESOLVED_PENDING_VERIFICATION: "RESOLVED_PENDING_VERIFICATION",
        }.get(target)
        finding = None
        if finding_target is not None:
            finding = session.scalar(
                select(Finding).where(
                    Finding.id == task.finding_id,
                    Finding.organization_id == context.organization_id,
                )
            )
        if finding is not None and finding_target is not None and finding.state != finding_target:
            FindingService(session).transition(
                context,
                principal,
                finding.id,
                finding_target,
                payload.reason or f"remediation-task-{action}",
                reason=payload.reason,
            )
        session.commit()
    except (FindingStateError, RemediationTransitionError, RemediationWorkflowError) as exc:
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


@router.post("/exceptions/{exception_id}/revoke")
def revoke_exception(
    exception_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> dict[str, object]:
    context = _context(session, principal, organization_id)
    require_role(context, "admin", "owner")
    try:
        exception = RemediationWorkflowService(session).revoke_exception(
            context.organization_id,
            exception_id,
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


@router.get("/attack-paths")
def list_attack_paths(
    start_asset_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
    profile: str = Query(default="exposure-to-data-v1", max_length=64),
    min_score: int = Query(default=0, ge=0, le=100),
    min_confidence: float = Query(default=0, ge=0, le=1),
    max_hops: int | None = Query(default=None, ge=1, le=GRAPH_MAX_HOPS),
    limit: int = Query(default=50, ge=1, le=100),
    effective_at: datetime | None = None,
) -> dict[str, object]:
    context = _context(session, principal, organization_id)
    result, selected_profile = _analyze(
        session,
        context,
        AttackPathAnalysisRequest(
            start_asset_id=start_asset_id,
            profile=profile,
            max_hops=max_hops,
            max_paths=limit,
            min_edge_confidence=min_confidence,
            effective_at=effective_at,
        ),
    )
    paths = [_path(session, context, item) for item in result.paths]
    filtered = [
        item
        for item in paths
        if cast(int, item["attack_path_score"]) >= min_score
        and cast(float, item["path_confidence"]) >= min_confidence
    ]
    return {
        "items": filtered,
        "page": {"offset": 0, "limit": limit, "total": len(filtered)},
        "profile": selected_profile.profile_id,
        "analytical_only": True,
        "exploitability_verified": False,
        "analysis_completeness": "TRUNCATED" if result.truncated else "COMPLETE",
        "warnings": list(result.warnings),
    }


@router.post("/attack-paths/analyze")
def analyze_attack_paths(
    payload: AttackPathAnalysisRequest,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> dict[str, object]:
    context = _context(session, principal, organization_id)
    result, profile = _analyze(session, context, payload)
    scorer = AttackPathScorer(session)
    start = GraphNodeReference(ASSET, payload.start_asset_id)
    blast_radius = scorer.blast_radius(
        context.organization_id,
        start_node=start,
        profile=profile,
        max_hops=payload.max_hops or profile.max_hops_default,
        result=result,
    )
    return {
        "analytical_only": True,
        "exploitability_verified": False,
        "profile": profile.profile_id,
        "effective_at": payload.effective_at,
        "analysis_completeness": "TRUNCATED" if result.truncated else "COMPLETE",
        "warnings": list(result.warnings),
        "blast_radius": {
            "unique_nodes": blast_radius.unique_nodes,
            "applications": blast_radius.applications,
            "identities": blast_radius.identities,
            "data_entities": blast_radius.data_entities,
            "vulnerabilities": blast_radius.vulnerabilities,
            "cloud_resources": blast_radius.cloud_resources,
            "paths": blast_radius.paths,
            "truncated": blast_radius.truncated,
        },
        "paths": [_path(session, context, item) for item in result.paths],
    }


@router.post("/attack-paths/path-breaking-candidates")
def path_breaking_candidates(
    payload: AttackPathAnalysisRequest,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> dict[str, object]:
    context = _context(session, principal, organization_id)
    result, profile = _analyze(session, context, payload)
    candidates = PathBreakingSimulator().evaluate_candidates(result, profile=profile)
    return {
        "analytical_only": True,
        "exploitability_verified": False,
        "simulation_only": True,
        "source_system_mutation": False,
        "profile": profile.profile_id,
        "candidates": [
            {
                "candidate_type": item.candidate_type,
                "relationship_id": item.relationship_id,
                "baseline_paths": item.baseline_paths,
                "remaining_paths": item.remaining_paths,
                "paths_broken": item.paths_broken,
                "reduction_percent": item.reduction_percent,
                "affected_destinations": item.affected_destinations,
                "simulation_confidence": item.simulation_confidence,
                "suggested_change_text": item.suggested_change_text,
            }
            for item in candidates
        ],
    }


def request_retest(
    task_id: uuid.UUID,
    payload: RetestRequest,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> dict[str, object]:
    context = _context(session, principal, organization_id)
    require_role(context, "analyst", "admin", "owner")
    authorization = ScopeGuard(session).authorize(
        ScopeAuthorizationRequest(
            principal=principal,
            organization_id=context.organization_id,
            scope_id=payload.scope_id,
            scope_version_id=payload.scope_version_id,
            approval_id=payload.approval_id,
            target=payload.target,
            operation=OperationContext(
                protocol=payload.protocol,
                correlation_id=payload.idempotency_key,
            ),
            now=datetime.now(UTC),
        )
    )
    if not authorization.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "SCOPE_GUARD_DENIED", "reason": authorization.reason_code},
        )
    try:
        run = VerificationRunService(session).request(
            context.organization_id,
            task_id,
            payload.idempotency_key,
            datetime.now(UTC),
            scope_approval_valid=True,
            emergency_stop=False,
            actor_user_id=principal.user.id,
            correlation_id=payload.idempotency_key,
        )
        session.commit()
    except VerificationRunError as exc:
        session.rollback()
        message = str(exc)
        code = (
            "VERIFICATION_ALREADY_ACTIVE"
            if "already active" in message
            else "VERIFICATION_NOT_FOUND"
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": code, "message": message},
        ) from exc
    return _verification(run)


@router.get("/remediation/tasks/{task_id}/verification-runs")
def list_verification_runs(
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
    runs = list(
        session.scalars(
            select(VerificationRun)
            .where(
                VerificationRun.organization_id == context.organization_id,
                VerificationRun.remediation_task_id == task.id,
            )
            .order_by(VerificationRun.requested_at.desc(), VerificationRun.id.asc())
        )
    )
    return {"items": [_verification(run) for run in runs]}


@router.get("/remediation/tasks/{task_id}/sla")
def get_task_sla(
    task_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> dict[str, object]:
    context = _context(session, principal, organization_id)
    sla = session.scalar(
        select(SlaInstance).where(
            SlaInstance.organization_id == context.organization_id,
            SlaInstance.remediation_task_id == task_id,
        )
    )
    if sla is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SLA_NOT_FOUND")
    serialized = _sla(sla)
    assert serialized is not None
    return serialized


@router.get("/verification-runs/{verification_run_id}")
def get_verification_run(
    verification_run_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> dict[str, object]:
    context = _context(session, principal, organization_id)
    run = session.scalar(
        select(VerificationRun).where(
            VerificationRun.id == verification_run_id,
            VerificationRun.organization_id == context.organization_id,
        )
    )
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="VERIFICATION_NOT_FOUND")
    closure = session.scalar(
        select(ClosureDecisionRecord).where(
            ClosureDecisionRecord.organization_id == context.organization_id,
            ClosureDecisionRecord.verification_run_id == run.id,
        )
    )
    detail = _verification(run)
    detail["closure_decision"] = _closure(closure) if closure is not None else None
    return detail


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


def _analyze(
    session: Session,
    context: OrganizationContext,
    payload: AttackPathAnalysisRequest,
) -> tuple[TraversalResult, TraversalProfile]:
    profile = TRAVERSAL_PROFILES.get(payload.profile)
    if profile is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="INVALID_TRAVERSAL_PROFILE",
        )
    try:
        result = GraphTraversalService(session).traverse(
            context.organization_id,
            start_nodes=(GraphNodeReference(ASSET, payload.start_asset_id),),
            profile=profile,
            max_hops=payload.max_hops,
            max_paths=payload.max_paths,
            min_edge_confidence=payload.min_edge_confidence,
            effective_at=payload.effective_at,
        )
    except RelationshipError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "INVALID_ATTACK_PATH_REQUEST", "message": str(exc)},
        ) from exc
    return result, profile


def _path(session: Session, context: OrganizationContext, item: GraphPath) -> dict[str, object]:
    scorer = AttackPathScorer(session)
    score = scorer.score_path(context.organization_id, item)
    confidence = scorer.path_confidence(item)
    return {
        "path_key": item.path_key,
        "hop_count": item.hop_count,
        "nodes": [{"kind": node.kind, "id": str(node.node_id)} for node in item.nodes],
        "relationships": [
            {
                "id": edge.relationship_id,
                "relationship_type": edge.relationship_type,
                "confidence": edge.confidence,
            }
            for edge in item.edges
        ],
        "attack_path_score": score.score,
        "attack_path_score_model_version": score.model_version,
        "score_factors": [
            {"factor": factor.factor, "points": factor.points} for factor in score.factors
        ],
        "path_confidence": confidence.combined_confidence,
        "low_confidence_relationship_ids": list(confidence.low_confidence_edges),
        "analytical_only": True,
        "exploitability_verified": False,
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
        "started_at": _utc_value(item.started_at),
        "resolve_due_at": _utc_value(item.resolve_due_at),
        "verify_due_at": _utc_value(item.verify_due_at),
        "final_due_at": _utc_value(item.final_due_at),
        "paused_at": _utc_value(item.paused_at),
        "paused_duration_seconds": item.paused_duration_seconds,
    }


def _utc_value(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


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
