import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .auth import current_principal
from .db import get_session
from .findings import FindingService, FindingStateError
from .models import (
    Asset,
    Evidence,
    Finding,
    FindingEvaluationEvent,
    FindingEvidenceLink,
    FindingStateEvent,
)
from .security import (
    OrganizationContext,
    Principal,
    organization_header,
    require_org_context,
    require_role,
)

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])
_MEMBER_ROLES = ("viewer", "reviewer", "analyst", "admin", "owner")


class PageResponse(BaseModel):
    offset: int
    limit: int
    total: int


class FindingSummary(BaseModel):
    id: uuid.UUID
    asset_id: uuid.UUID
    asset_display_name: str
    rule_id: str
    rule_version: int
    title: str
    category: str
    severity: str
    confidence: float
    state: str
    first_seen: datetime
    last_seen: datetime


class FindingListResponse(BaseModel):
    items: list[FindingSummary]
    page: PageResponse


class FindingDetailResponse(FindingSummary):
    description: str
    service_asset_id: uuid.UUID | None
    rule_hash: str
    asset: dict[str, object]
    service_asset: dict[str, object] | None
    evidence_links: list[dict[str, object]]
    evaluation_history: list[dict[str, object]]
    state_history: list[dict[str, object]]
    exception: dict[str, object] | None


class FindingEvidenceResponse(BaseModel):
    id: uuid.UUID
    evidence_id: uuid.UUID
    observation_id: uuid.UUID | None
    evidence_type: str
    sha256: str
    size_bytes: int
    media_type: str
    collected_at: datetime
    stored_at: datetime


class FindingHistoryResponse(BaseModel):
    items: list[dict[str, object]]
    page: PageResponse


class TransitionRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=2000)
    expires_at: datetime | None = None
    verification_reference: str | None = Field(default=None, max_length=512)


@router.get("", response_model=FindingListResponse)
def list_findings(
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
    state: str | None = Query(default=None, max_length=32),
    severity: str | None = Query(default=None, max_length=16),
    category: str | None = Query(default=None, max_length=128),
    rule_id: str | None = Query(default=None, max_length=255),
    asset_id: uuid.UUID | None = None,
    owner: str | None = Query(default=None, max_length=512),
    confidence_min: float | None = Query(default=None, ge=0, le=1),
    confidence_max: float | None = Query(default=None, ge=0, le=1),
    first_seen_from: datetime | None = None,
    last_seen_to: datetime | None = None,
    search: str | None = Query(default=None, max_length=255),
    offset: int = Query(default=0, ge=0, le=100_000),
    limit: int = Query(default=50, ge=1, le=100),
) -> FindingListResponse:
    context = _access_context(session, principal, organization_id)
    filters = [Finding.organization_id == context.organization_id]
    if state:
        filters.append(Finding.state == state)
    if severity:
        filters.append(Finding.rule_severity == severity)
    if category:
        filters.append(Finding.category == category)
    if rule_id:
        filters.append(Finding.rule_id == rule_id)
    if asset_id:
        filters.append(Finding.asset_id == asset_id)
    if owner:
        filters.append(Finding.assigned_owner_reference == owner)
    if confidence_min is not None:
        filters.append(Finding.confidence >= confidence_min)
    if confidence_max is not None:
        filters.append(Finding.confidence <= confidence_max)
    if first_seen_from:
        filters.append(Finding.first_seen >= first_seen_from)
    if last_seen_to:
        filters.append(Finding.last_seen <= last_seen_to)
    if search:
        pattern = f"%{search.strip()}%"
        filters.append(or_(Finding.title.ilike(pattern), Finding.description.ilike(pattern)))
    rows = list(
        session.execute(
            select(Finding, Asset)
            .join(Asset, Asset.id == Finding.asset_id)
            .where(*filters)
            .order_by(Finding.last_seen.desc(), Finding.id.asc())
            .offset(offset)
            .limit(limit)
        )
    )
    total = session.scalar(select(func.count(Finding.id)).where(*filters)) or 0
    return FindingListResponse(
        items=[_summary(finding, asset) for finding, asset in rows],
        page=PageResponse(offset=offset, limit=limit, total=total),
    )


@router.get("/{finding_id}", response_model=FindingDetailResponse)
def get_finding(
    finding_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> FindingDetailResponse:
    context = _access_context(session, principal, organization_id)
    finding = _finding(session, context, finding_id)
    asset = _asset(session, context, finding.asset_id)
    service_asset = (
        _asset(session, context, finding.service_asset_id)
        if finding.service_asset_id is not None
        else None
    )
    links = list(
        session.scalars(
            select(FindingEvidenceLink).where(
                FindingEvidenceLink.organization_id == context.organization_id,
                FindingEvidenceLink.finding_id == finding.id,
            )
        )
    )
    evaluations = list(
        session.scalars(
            select(FindingEvaluationEvent)
            .where(
                FindingEvaluationEvent.organization_id == context.organization_id,
                FindingEvaluationEvent.finding_id == finding.id,
            )
            .order_by(FindingEvaluationEvent.evaluated_at.desc(), FindingEvaluationEvent.id.asc())
        )
    )
    state_history = list(
        session.scalars(
            select(FindingStateEvent)
            .where(
                FindingStateEvent.organization_id == context.organization_id,
                FindingStateEvent.finding_id == finding.id,
            )
            .order_by(FindingStateEvent.created_at.desc(), FindingStateEvent.id.asc())
        )
    )
    summary = _summary(finding, asset)
    exception: dict[str, object] | None = None
    if finding.state == "EXCEPTION" or finding.exception_reason:
        exception = {
            "reason": finding.exception_reason,
            "expires_at": finding.exception_expires_at,
            "created_at": finding.exception_at,
        }
    return FindingDetailResponse(
        **summary.model_dump(),
        description=finding.description,
        service_asset_id=finding.service_asset_id,
        rule_hash=finding.rule_hash,
        asset=_asset_summary(asset),
        service_asset=_asset_summary(service_asset) if service_asset else None,
        evidence_links=[_link_summary(item) for item in links],
        evaluation_history=[_evaluation_summary(item) for item in evaluations],
        state_history=[_state_summary(item) for item in state_history],
        exception=exception,
    )


@router.get("/{finding_id}/evidence", response_model=list[FindingEvidenceResponse])
def list_finding_evidence(
    finding_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> list[FindingEvidenceResponse]:
    context = _access_context(session, principal, organization_id)
    _finding(session, context, finding_id)
    rows = list(
        session.execute(
            select(FindingEvidenceLink, Evidence)
            .join(Evidence, Evidence.id == FindingEvidenceLink.evidence_id)
            .where(
                FindingEvidenceLink.organization_id == context.organization_id,
                FindingEvidenceLink.finding_id == finding_id,
                Evidence.organization_id == context.organization_id,
            )
            .order_by(FindingEvidenceLink.linked_at.desc(), FindingEvidenceLink.id.asc())
        )
    )
    return [
        FindingEvidenceResponse(
            id=link.id,
            evidence_id=evidence.id,
            observation_id=link.observation_id,
            evidence_type=evidence.evidence_type,
            sha256=evidence.sha256,
            size_bytes=evidence.size_bytes,
            media_type=evidence.media_type,
            collected_at=evidence.collected_at,
            stored_at=evidence.stored_at,
        )
        for link, evidence in rows
    ]


@router.get("/{finding_id}/history", response_model=FindingHistoryResponse)
def get_finding_history(
    finding_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
    offset: int = Query(default=0, ge=0, le=100_000),
    limit: int = Query(default=50, ge=1, le=100),
) -> FindingHistoryResponse:
    context = _access_context(session, principal, organization_id)
    _finding(session, context, finding_id)
    items = [
        _evaluation_summary(item)
        for item in session.scalars(
            select(FindingEvaluationEvent).where(
                FindingEvaluationEvent.organization_id == context.organization_id,
                FindingEvaluationEvent.finding_id == finding_id,
            )
        )
    ] + [
        _state_summary(item)
        for item in session.scalars(
            select(FindingStateEvent).where(
                FindingStateEvent.organization_id == context.organization_id,
                FindingStateEvent.finding_id == finding_id,
            )
        )
    ]
    ordered = sorted(items, key=lambda item: (item["occurred_at"], str(item["id"])), reverse=True)
    return FindingHistoryResponse(
        items=ordered[offset : offset + limit],
        page=PageResponse(offset=offset, limit=limit, total=len(ordered)),
    )


@router.post("/{finding_id}/acknowledge", response_model=FindingDetailResponse)
def acknowledge_finding(
    finding_id: uuid.UUID,
    payload: TransitionRequest,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> FindingDetailResponse:
    return _transition(
        "ACKNOWLEDGED", finding_id, payload, request, session, principal, organization_id
    )


@router.post("/{finding_id}/start", response_model=FindingDetailResponse)
def start_finding(
    finding_id: uuid.UUID,
    payload: TransitionRequest,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> FindingDetailResponse:
    return _transition(
        "IN_PROGRESS", finding_id, payload, request, session, principal, organization_id
    )


@router.post("/{finding_id}/resolve-pending-verification", response_model=FindingDetailResponse)
def resolve_pending_verification(
    finding_id: uuid.UUID,
    payload: TransitionRequest,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> FindingDetailResponse:
    return _transition(
        "RESOLVED_PENDING_VERIFICATION",
        finding_id,
        payload,
        request,
        session,
        principal,
        organization_id,
    )


@router.post("/{finding_id}/exception", response_model=FindingDetailResponse)
def except_finding(
    finding_id: uuid.UUID,
    payload: TransitionRequest,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> FindingDetailResponse:
    return _transition(
        "EXCEPTION", finding_id, payload, request, session, principal, organization_id
    )


@router.post("/{finding_id}/close", response_model=FindingDetailResponse)
def close_finding(
    finding_id: uuid.UUID,
    payload: TransitionRequest,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> FindingDetailResponse:
    return _transition("CLOSED", finding_id, payload, request, session, principal, organization_id)


@router.post("/{finding_id}/reopen", response_model=FindingDetailResponse)
def reopen_finding(
    finding_id: uuid.UUID,
    payload: TransitionRequest,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> FindingDetailResponse:
    return _transition("OPEN", finding_id, payload, request, session, principal, organization_id)


def _transition(
    target_state: str,
    finding_id: uuid.UUID,
    payload: TransitionRequest,
    request: Request,
    session: Session,
    principal: Principal,
    organization_id: str | None,
) -> FindingDetailResponse:
    context = _access_context(session, principal, organization_id)
    try:
        FindingService(session).transition(
            context,
            principal,
            finding_id,
            target_state,
            request.state.correlation_id,
            reason=payload.reason,
            exception_expires_at=payload.expires_at,
            verification_reference=payload.verification_reference,
        )
        session.commit()
    except FindingStateError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "INVALID_FINDING_TRANSITION", "message": str(exc)},
        ) from exc
    return get_finding(finding_id, session, principal, organization_id)


def _access_context(
    session: Session, principal: Principal, organization_id: str | None
) -> OrganizationContext:
    context = require_org_context(session, principal, organization_id)
    require_role(context, *_MEMBER_ROLES)
    return context


def _finding(session: Session, context: OrganizationContext, finding_id: uuid.UUID) -> Finding:
    finding = session.scalar(
        select(Finding).where(
            Finding.id == finding_id,
            Finding.organization_id == context.organization_id,
        )
    )
    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "FINDING_NOT_FOUND", "message": "Finding was not found"},
        )
    return finding


def _asset(session: Session, context: OrganizationContext, asset_id: uuid.UUID) -> Asset:
    asset = session.scalar(
        select(Asset).where(Asset.id == asset_id, Asset.organization_id == context.organization_id)
    )
    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "FINDING_NOT_FOUND", "message": "Finding asset was not found"},
        )
    return asset


def _summary(finding: Finding, asset: Asset) -> FindingSummary:
    return FindingSummary(
        id=finding.id,
        asset_id=finding.asset_id,
        asset_display_name=asset.display_name,
        rule_id=finding.rule_id,
        rule_version=finding.rule_version,
        title=finding.title,
        category=finding.category,
        severity=finding.rule_severity,
        confidence=finding.confidence,
        state=finding.state,
        first_seen=finding.first_seen,
        last_seen=finding.last_seen,
    )


def _asset_summary(asset: Asset) -> dict[str, object]:
    return {
        "id": asset.id,
        "asset_type": asset.asset_type,
        "canonical_key": asset.canonical_key,
        "display_name": asset.display_name,
        "lifecycle_state": asset.lifecycle_state,
    }


def _link_summary(link: FindingEvidenceLink) -> dict[str, object]:
    return {
        "id": link.id,
        "evidence_id": link.evidence_id,
        "observation_id": link.observation_id,
        "rule_id": link.rule_id,
        "rule_version": link.rule_version,
        "linked_at": link.linked_at,
    }


def _evaluation_summary(item: FindingEvaluationEvent) -> dict[str, object]:
    return {
        "id": item.id,
        "event_type": "EVALUATION",
        "occurred_at": item.evaluated_at,
        "matched": item.matched,
        "confidence": item.confidence,
        "rule_version": item.rule_version,
    }


def _state_summary(item: FindingStateEvent) -> dict[str, object]:
    return {
        "id": item.id,
        "event_type": "STATE_TRANSITION",
        "occurred_at": item.created_at,
        "from_state": item.from_state,
        "to_state": item.to_state,
        "reason": item.reason,
    }
