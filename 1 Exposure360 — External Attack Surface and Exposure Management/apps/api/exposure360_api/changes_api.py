import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .approved_changes import ApprovedChangeError, ApprovedChangeService
from .auth import current_principal
from .db import get_session
from .models import ApprovedChange, Asset, ChangeEvent
from .security import (
    OrganizationContext,
    Principal,
    organization_header,
    require_org_context,
    require_role,
)

router = APIRouter(tags=["changes"])
_MEMBER_ROLES = ("viewer", "reviewer", "analyst", "admin", "owner")


class PageResponse(BaseModel):
    offset: int
    limit: int
    total: int


class ChangeSummary(BaseModel):
    id: uuid.UUID
    asset_id: uuid.UUID
    asset_display_name: str
    change_type: str
    summary: str
    state: str
    significance_score: int | None
    significance_model_version: str | None
    approved_change_id: uuid.UUID | None
    first_seen: datetime
    last_seen: datetime


class ChangeListResponse(BaseModel):
    items: list[ChangeSummary]
    page: PageResponse


class ChangeDetailResponse(ChangeSummary):
    from_snapshot_id: uuid.UUID | None
    to_snapshot_id: uuid.UUID | None
    details: dict[str, object]
    significance_factors: list[dict[str, object]]
    approved_change: dict[str, object] | None


class ApprovedChangeRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1)
    asset_id: uuid.UUID
    allowed_change_types: list[str] = Field(min_length=1, max_length=6)
    component_selector: dict[str, object] | None = None
    starts_at: datetime
    ends_at: datetime
    reason: str = Field(min_length=1)
    ticket_reference: str | None = Field(default=None, max_length=255)
    approved_by_user_id: uuid.UUID | None = None


class ApprovedChangeResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    asset_id: uuid.UUID | None
    allowed_change_types: list[str]
    component_selector: dict[str, object] | None
    starts_at: datetime
    ends_at: datetime
    reason: str
    ticket_reference: str | None
    approved_by_user_id: uuid.UUID
    created_by_user_id: uuid.UUID
    status: str


class ApprovedChangeListResponse(BaseModel):
    items: list[ApprovedChangeResponse]
    page: PageResponse


@router.get("/api/v1/changes", response_model=ChangeListResponse)
def list_changes(
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
    change_type: str | None = Query(default=None, max_length=16),
    asset_id: uuid.UUID | None = None,
    state: str | None = Query(default=None, max_length=16),
    expected: bool | None = None,
    significance_min: int | None = Query(default=None, ge=0, le=100),
    significance_max: int | None = Query(default=None, ge=0, le=100),
    detected_from: datetime | None = None,
    detected_to: datetime | None = None,
    offset: int = Query(default=0, ge=0, le=100_000),
    limit: int = Query(default=50, ge=1, le=100),
) -> ChangeListResponse:
    context = _access_context(session, principal, organization_id)
    filters = [ChangeEvent.organization_id == context.organization_id]
    if change_type:
        filters.append(ChangeEvent.change_type == change_type)
    if asset_id:
        filters.append(ChangeEvent.asset_id == asset_id)
    if state:
        filters.append(ChangeEvent.state == state)
    if expected is not None:
        expected_filter = ChangeEvent.state == "EXPECTED"
        filters.append(expected_filter if expected else ~expected_filter)
    if significance_min is not None:
        filters.append(ChangeEvent.significance_score >= significance_min)
    if significance_max is not None:
        filters.append(ChangeEvent.significance_score <= significance_max)
    if detected_from:
        filters.append(ChangeEvent.last_seen >= detected_from)
    if detected_to:
        filters.append(ChangeEvent.last_seen <= detected_to)
    rows = list(
        session.execute(
            select(ChangeEvent, Asset)
            .join(Asset, Asset.id == ChangeEvent.asset_id)
            .where(*filters)
            .order_by(
                ChangeEvent.significance_score.desc(),
                ChangeEvent.last_seen.desc(),
                ChangeEvent.id.asc(),
            )
            .offset(offset)
            .limit(limit)
        )
    )
    total = session.scalar(select(func.count(ChangeEvent.id)).where(*filters)) or 0
    return ChangeListResponse(
        items=[_change_summary(event, asset) for event, asset in rows],
        page=PageResponse(offset=offset, limit=limit, total=total),
    )


@router.get("/api/v1/changes/{change_id}", response_model=ChangeDetailResponse)
def get_change(
    change_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> ChangeDetailResponse:
    context = _access_context(session, principal, organization_id)
    change = _change(session, context, change_id)
    asset = _asset(session, context, change.asset_id)
    approval = None
    if change.approved_change_id:
        approval = session.scalar(
            select(ApprovedChange).where(
                ApprovedChange.id == change.approved_change_id,
                ApprovedChange.organization_id == context.organization_id,
            )
        )
    summary = _change_summary(change, asset)
    return ChangeDetailResponse(
        **summary.model_dump(),
        from_snapshot_id=change.from_snapshot_id,
        to_snapshot_id=change.to_snapshot_id,
        details=change.details_json,
        significance_factors=change.significance_factors_json,
        approved_change=_approval_detail(approval) if approval else None,
    )


@router.get("/api/v1/approved-changes", response_model=ApprovedChangeListResponse)
def list_approved_changes(
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
    offset: int = Query(default=0, ge=0, le=100_000),
    limit: int = Query(default=50, ge=1, le=100),
) -> ApprovedChangeListResponse:
    context = _access_context(session, principal, organization_id)
    filters = [ApprovedChange.organization_id == context.organization_id]
    approvals = list(
        session.scalars(
            select(ApprovedChange)
            .where(*filters)
            .order_by(ApprovedChange.starts_at.desc(), ApprovedChange.id.asc())
            .offset(offset)
            .limit(limit)
        )
    )
    total = session.scalar(select(func.count(ApprovedChange.id)).where(*filters)) or 0
    return ApprovedChangeListResponse(
        items=[_approval_response(item) for item in approvals],
        page=PageResponse(offset=offset, limit=limit, total=total),
    )


@router.post("/api/v1/approved-changes", response_model=ApprovedChangeResponse, status_code=201)
def create_approved_change(
    payload: ApprovedChangeRequest,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> ApprovedChangeResponse:
    context = _access_context(session, principal, organization_id)
    try:
        approval = ApprovedChangeService(session).create(
            context,
            principal,
            name=payload.name,
            description=payload.description,
            asset_id=payload.asset_id,
            allowed_change_types=tuple(payload.allowed_change_types),
            starts_at=payload.starts_at,
            ends_at=payload.ends_at,
            reason=payload.reason,
            ticket_reference=payload.ticket_reference,
            component_selector=payload.component_selector,
            approved_by_user_id=payload.approved_by_user_id,
            correlation_id=request.state.correlation_id,
        )
        session.commit()
    except ApprovedChangeError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "APPROVED_CHANGE_SELECTOR_INVALID", "message": str(exc)},
        ) from exc
    return _approval_response(approval)


@router.get("/api/v1/approved-changes/{approval_id}", response_model=ApprovedChangeResponse)
def get_approved_change(
    approval_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> ApprovedChangeResponse:
    context = _access_context(session, principal, organization_id)
    return _approval_response(_approval(session, context, approval_id))


@router.post(
    "/api/v1/approved-changes/{approval_id}/disable",
    response_model=ApprovedChangeResponse,
)
def disable_approved_change(
    approval_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> ApprovedChangeResponse:
    context = _access_context(session, principal, organization_id)
    try:
        approval = ApprovedChangeService(session).disable(
            context,
            principal,
            approval_id,
            request.state.correlation_id,
        )
        session.commit()
    except ApprovedChangeError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "APPROVED_CHANGE_NOT_FOUND", "message": str(exc)},
        ) from exc
    return _approval_response(approval)


def _access_context(
    session: Session, principal: Principal, organization_id: str | None
) -> OrganizationContext:
    context = require_org_context(session, principal, organization_id)
    require_role(context, *_MEMBER_ROLES)
    return context


def _change(session: Session, context: OrganizationContext, change_id: uuid.UUID) -> ChangeEvent:
    change = session.scalar(
        select(ChangeEvent).where(
            ChangeEvent.id == change_id,
            ChangeEvent.organization_id == context.organization_id,
        )
    )
    if change is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "CHANGE_NOT_FOUND", "message": "Change was not found"},
        )
    return change


def _approval(
    session: Session, context: OrganizationContext, approval_id: uuid.UUID
) -> ApprovedChange:
    approval = session.scalar(
        select(ApprovedChange).where(
            ApprovedChange.id == approval_id,
            ApprovedChange.organization_id == context.organization_id,
        )
    )
    if approval is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "APPROVED_CHANGE_NOT_FOUND",
                "message": "Approved change was not found",
            },
        )
    return approval


def _asset(session: Session, context: OrganizationContext, asset_id: uuid.UUID) -> Asset:
    asset = session.scalar(
        select(Asset).where(Asset.id == asset_id, Asset.organization_id == context.organization_id)
    )
    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "CHANGE_NOT_FOUND", "message": "Change asset was not found"},
        )
    return asset


def _change_summary(change: ChangeEvent, asset: Asset) -> ChangeSummary:
    return ChangeSummary(
        id=change.id,
        asset_id=change.asset_id,
        asset_display_name=asset.display_name,
        change_type=change.change_type,
        summary=change.summary,
        state=change.state,
        significance_score=change.significance_score,
        significance_model_version=change.significance_model_version,
        approved_change_id=change.approved_change_id,
        first_seen=change.first_seen,
        last_seen=change.last_seen,
    )


def _approval_response(approval: ApprovedChange) -> ApprovedChangeResponse:
    return ApprovedChangeResponse(
        id=approval.id,
        name=approval.name,
        description=approval.description,
        asset_id=approval.asset_id,
        allowed_change_types=approval.allowed_change_types_json,
        component_selector=approval.component_selector_json,
        starts_at=approval.starts_at,
        ends_at=approval.ends_at,
        reason=approval.reason,
        ticket_reference=approval.ticket_reference,
        approved_by_user_id=approval.approved_by_user_id,
        created_by_user_id=approval.created_by_user_id,
        status=approval.status,
    )


def _approval_detail(approval: ApprovedChange) -> dict[str, object]:
    return {
        "id": approval.id,
        "name": approval.name,
        "reason": approval.reason,
        "starts_at": approval.starts_at,
        "ends_at": approval.ends_at,
        "approved_by_user_id": approval.approved_by_user_id,
        "status": approval.status,
    }
