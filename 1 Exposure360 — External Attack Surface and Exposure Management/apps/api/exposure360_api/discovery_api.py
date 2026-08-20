"""Organization-isolated asynchronous discovery-job API for Phase 3."""

import uuid
from datetime import datetime
from typing import NoReturn

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from .audit import write_audit_event
from .auth import current_principal
from .config import get_settings
from .db import get_session
from .discovery_orchestration import DiscoveryJobService, DiscoveryJobStateError
from .jobs import enqueue_discovery_job, get_celery_client
from .models import (
    DeadLetterItem,
    DiscoveryJob,
    DiscoveryJobEvent,
    DiscoveryJobStage,
    Scope,
    ScopeApproval,
    ScopeVersion,
)
from .recovery_controls import DiscoveryRecoveryService
from .security import (
    OrganizationContext,
    Principal,
    organization_header,
    require_org_context,
    require_role,
)

router = APIRouter(prefix="/api/v1/discovery", tags=["discovery"])


class DiscoveryJobCreateRequest(BaseModel):
    scope_id: uuid.UUID
    scope_version_id: uuid.UUID


class DiscoveryJobResponse(BaseModel):
    id: uuid.UUID
    state: str
    scope_id: uuid.UUID
    scope_version_id: uuid.UUID
    approval_id: uuid.UUID
    current_stage: str | None = None
    counts: dict[str, int]
    known_total: int | None = None
    indeterminate: bool
    degraded_sources: list[dict[str, object]]
    created_at: datetime | None = None
    started_at: datetime | None = None
    updated_at: datetime | None = None
    finished_at: datetime | None = None
    links: dict[str, str]


class DiscoveryStageResponse(BaseModel):
    stage: str
    state: str
    processed: int
    succeeded: int
    failed: int
    skipped: int
    queued: int
    known_total: int | None = None
    indeterminate: bool
    last_error_code: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None


class DiscoveryEventResponse(BaseModel):
    id: uuid.UUID
    event_type: str
    stage: str | None = None
    details: dict[str, object]
    correlation_id: str | None = None
    created_at: datetime | None = None


class DeadLetterResponse(BaseModel):
    id: uuid.UUID
    candidate_id: uuid.UUID | None = None
    stage: str
    operation_key: str
    attempts: int
    error_class: str
    safe_message: str
    state: str
    first_failed_at: datetime
    last_failed_at: datetime


def _error(status_code: int, code: str, message: str) -> NoReturn:
    raise HTTPException(
        status_code=status_code,
        detail={"error": {"code": code, "message": message}},
    )


def _context(
    session: Session,
    principal: Principal,
    organization_id: str | None,
) -> OrganizationContext:
    return require_org_context(session, principal, organization_id)


def _scope(session: Session, context: OrganizationContext, scope_id: uuid.UUID) -> Scope:
    scope = session.scalar(
        select(Scope).where(
            Scope.id == scope_id,
            Scope.organization_id == context.organization_id,
        )
    )
    if scope is None:
        cross_organization = session.scalar(
            select(Scope.id)
            .where(Scope.id == scope_id, Scope.organization_id != context.organization_id)
            .limit(1)
        )
        if cross_organization is not None:
            _error(status.HTTP_403_FORBIDDEN, "FORBIDDEN", "Scope belongs to another organization")
        _error(status.HTTP_404_NOT_FOUND, "SCOPE_NOT_FOUND", "Scope not found")
    return scope


def _job(session: Session, context: OrganizationContext, job_id: uuid.UUID) -> DiscoveryJob:
    job = session.scalar(
        select(DiscoveryJob).where(
            DiscoveryJob.id == job_id,
            DiscoveryJob.organization_id == context.organization_id,
        )
    )
    if job is None:
        cross_organization = session.scalar(
            select(DiscoveryJob.id)
            .where(
                DiscoveryJob.id == job_id,
                DiscoveryJob.organization_id != context.organization_id,
            )
            .limit(1)
        )
        if cross_organization is not None:
            _error(
                status.HTTP_403_FORBIDDEN,
                "FORBIDDEN",
                "Discovery job belongs to another organization",
            )
        _error(status.HTTP_404_NOT_FOUND, "DISCOVERY_JOB_NOT_FOUND", "Discovery job not found")
    return job


def _audit(
    session: Session,
    context: OrganizationContext,
    principal: Principal,
    request: Request,
    *,
    action: str,
    job: DiscoveryJob,
) -> None:
    write_audit_event(
        session,
        context,
        principal,
        action=action,
        resource_type="discovery_job",
        resource_id=str(job.id),
        correlation_id=request.state.correlation_id,
        result="success",
        metadata={
            "scope_version_id": str(job.scope_version_id),
            "approval_id": str(job.scope_approval_id),
            "job_id": str(job.id),
        },
    )


def _job_response(job: DiscoveryJob) -> DiscoveryJobResponse:
    return DiscoveryJobResponse(
        id=job.id,
        state=job.state,
        scope_id=job.scope_id,
        scope_version_id=job.scope_version_id,
        approval_id=job.scope_approval_id,
        current_stage=job.current_stage,
        counts={
            "processed": job.progress_completed,
            "succeeded": job.progress_completed - job.progress_failed - job.progress_skipped,
            "failed": job.progress_failed,
            "skipped": job.progress_skipped,
            "queued": job.progress_queued,
        },
        known_total=job.progress_total,
        indeterminate=job.progress_indeterminate,
        degraded_sources=job.degraded_sources_json,
        created_at=job.created_at,
        started_at=job.started_at,
        updated_at=job.updated_at,
        finished_at=job.finished_at,
        links={
            "self": f"/api/v1/discovery/jobs/{job.id}",
            "cancel": f"/api/v1/discovery/jobs/{job.id}/cancel",
        },
    )


@router.post("/jobs", response_model=DiscoveryJobResponse, status_code=status.HTTP_202_ACCEPTED)
def create_discovery_job(
    body: DiscoveryJobCreateRequest,
    request: Request,
    organization_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> DiscoveryJobResponse:
    context = _context(session, principal, organization_id)
    require_role(context, "analyst", "admin", "owner")
    scope = _scope(session, context, body.scope_id)
    version = session.scalar(
        select(ScopeVersion).where(
            ScopeVersion.id == body.scope_version_id,
            ScopeVersion.scope_id == scope.id,
            ScopeVersion.organization_id == context.organization_id,
        )
    )
    if version is None:
        _error(status.HTTP_404_NOT_FOUND, "SCOPE_VERSION_NOT_FOUND", "Scope version not found")
    approval = session.scalar(
        select(ScopeApproval)
        .where(
            ScopeApproval.organization_id == context.organization_id,
            ScopeApproval.scope_id == scope.id,
            ScopeApproval.scope_version_id == version.id,
            ScopeApproval.decision == "APPROVED",
        )
        .order_by(ScopeApproval.approved_at.desc())
    )
    if approval is None:
        _error(
            status.HTTP_409_CONFLICT,
            "APPROVAL_REQUIRED",
            "Scope version has no active approval",
        )
    try:
        job = DiscoveryJobService().create_job(
            session,
            organization_id=context.organization_id,
            scope_id=scope.id,
            scope_version_id=version.id,
            approval_id=approval.id,
            requested_by_user_id=principal.user.id,
            correlation_id=request.state.correlation_id,
        )
    except DiscoveryJobStateError as error:
        _error(status.HTTP_409_CONFLICT, "DISCOVERY_NOT_RUNNABLE", str(error))
    _audit(session, context, principal, request, action="discovery.job.create", job=job)
    session.commit()
    session.refresh(job)
    enqueue_discovery_job(
        get_celery_client(get_settings()),
        organization_id=str(context.organization_id),
        job_id=str(job.id),
        correlation_id=request.state.correlation_id,
    )
    return _job_response(job)


@router.get("/jobs", response_model=list[DiscoveryJobResponse])
def list_discovery_jobs(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    organization_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> list[DiscoveryJobResponse]:
    context = _context(session, principal, organization_id)
    require_role(context, "viewer", "analyst", "reviewer", "admin", "owner")
    jobs = session.scalars(
        select(DiscoveryJob)
        .where(DiscoveryJob.organization_id == context.organization_id)
        .order_by(DiscoveryJob.created_at.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return [_job_response(job) for job in jobs]


@router.get("/jobs/{job_id}", response_model=DiscoveryJobResponse)
def get_discovery_job(
    job_id: uuid.UUID,
    organization_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> DiscoveryJobResponse:
    context = _context(session, principal, organization_id)
    require_role(context, "viewer", "analyst", "reviewer", "admin", "owner")
    return _job_response(_job(session, context, job_id))


@router.post(
    "/jobs/{job_id}/cancel",
    response_model=DiscoveryJobResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def cancel_discovery_job(
    job_id: uuid.UUID,
    request: Request,
    organization_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> DiscoveryJobResponse:
    context = _context(session, principal, organization_id)
    require_role(context, "admin", "owner")
    job = _job(session, context, job_id)
    DiscoveryRecoveryService.request_cancellation(
        session,
        organization_id=context.organization_id,
        job_id=job.id,
        correlation_id=request.state.correlation_id,
    )
    _audit(session, context, principal, request, action="discovery.job.cancel", job=job)
    session.commit()
    session.refresh(job)
    return _job_response(job)


@router.get("/jobs/{job_id}/stages", response_model=list[DiscoveryStageResponse])
def list_discovery_stages(
    job_id: uuid.UUID,
    organization_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> list[DiscoveryStageResponse]:
    context = _context(session, principal, organization_id)
    require_role(context, "viewer", "analyst", "reviewer", "admin", "owner")
    job = _job(session, context, job_id)
    stages = session.scalars(
        select(DiscoveryJobStage)
        .where(DiscoveryJobStage.discovery_job_id == job.id)
        .order_by(DiscoveryJobStage.id)
    ).all()
    return [
        DiscoveryStageResponse(
            stage=stage.stage,
            state=stage.state,
            processed=stage.processed_count,
            succeeded=stage.succeeded_count,
            failed=stage.failed_count,
            skipped=stage.skipped_count,
            queued=stage.queued_count,
            known_total=stage.known_total,
            indeterminate=stage.progress_indeterminate,
            last_error_code=stage.last_error_code,
            started_at=stage.started_at,
            finished_at=stage.finished_at,
        )
        for stage in stages
    ]


@router.get("/jobs/{job_id}/events", response_model=list[DiscoveryEventResponse])
def list_discovery_events(
    job_id: uuid.UUID,
    organization_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> list[DiscoveryEventResponse]:
    context = _context(session, principal, organization_id)
    require_role(context, "viewer", "analyst", "reviewer", "admin", "owner")
    job = _job(session, context, job_id)
    events = session.scalars(
        select(DiscoveryJobEvent)
        .where(DiscoveryJobEvent.discovery_job_id == job.id)
        .order_by(DiscoveryJobEvent.created_at)
    ).all()
    return [
        DiscoveryEventResponse(
            id=event.id,
            event_type=event.event_type,
            stage=event.stage,
            details=event.details_json,
            correlation_id=event.correlation_id,
            created_at=event.created_at,
        )
        for event in events
    ]


@router.get("/jobs/{job_id}/dead-letters", response_model=list[DeadLetterResponse])
def list_dead_letters(
    job_id: uuid.UUID,
    organization_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> list[DeadLetterResponse]:
    context = _context(session, principal, organization_id)
    require_role(context, "viewer", "analyst", "reviewer", "admin", "owner")
    job = _job(session, context, job_id)
    items = session.scalars(
        select(DeadLetterItem)
        .where(DeadLetterItem.discovery_job_id == job.id)
        .order_by(DeadLetterItem.first_failed_at.desc())
    ).all()
    return [
        DeadLetterResponse(
            id=item.id,
            candidate_id=item.candidate_id,
            stage=item.stage,
            operation_key=item.operation_key,
            attempts=item.attempts,
            error_class=item.last_error_class,
            safe_message=item.last_error_safe_message,
            state=item.state,
            first_failed_at=item.first_failed_at,
            last_failed_at=item.last_failed_at,
        )
        for item in items
    ]
