import uuid
from datetime import UTC, datetime
from typing import Literal, NoReturn, cast

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .audit import write_audit_event
from .auth import current_principal
from .config import get_settings
from .db import get_session
from .emergency_stop import EmergencyStopService
from .models import ScanPolicy, Scope, ScopeApproval, ScopeExclusion, ScopeSeed, ScopeVersion
from .scan_policy import PolicyValidationError, ScanPolicySnapshot, validate_policy
from .scope_approval import ScopeApprovalService, ScopeStateError
from .scope_governance import (
    ConflictFinding,
    MatchMode,
    ScopeConflictAnalyzer,
    ScopeTargetNormalizer,
    ScopeValidationError,
    TargetRule,
    TargetType,
)
from .security import (
    OrganizationContext,
    Principal,
    organization_header,
    require_org_context,
    require_role,
)

router = APIRouter(prefix="/api/v1", tags=["scope-governance"])

TargetTypeValue = Literal["DOMAIN", "CIDR", "IP", "ASN"]
MatchModeValue = Literal["EXACT", "DOMAIN_AND_SUBDOMAINS"]


class ScopeCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=10_000)


class ScopeUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=10_000)


class ScopeVersionCreateRequest(BaseModel):
    change_summary: str | None = Field(default=None, max_length=10_000)
    clone_from_version_id: uuid.UUID | None = None


class TargetCreateRequest(BaseModel):
    target_type: TargetTypeValue
    raw_value: str = Field(min_length=1, max_length=320)
    match_mode: MatchModeValue = "EXACT"
    reason: str | None = Field(default=None, max_length=10_000)


class ScheduleWindowRequest(BaseModel):
    days: list[Literal["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"]]
    start: str
    end: str


class PolicyUpsertRequest(BaseModel):
    allowed_protocols: list[Literal["DNS", "TCP", "TLS", "HTTP", "HTTPS"]]
    max_requests_per_second: float = Field(gt=0)
    max_concurrent_targets: int = Field(ge=1)
    max_concurrent_requests: int = Field(ge=1)
    schedule_timezone: str = Field(default="UTC", min_length=1, max_length=64)
    schedule_windows: list[ScheduleWindowRequest] = Field(default_factory=list)
    connect_timeout_seconds: int = Field(default=10, ge=1, le=300)
    request_timeout_seconds: int = Field(default=30, ge=1, le=600)
    active_scanning_enabled: bool = False


class ApprovalRequest(BaseModel):
    decision_reason: str | None = Field(default=None, max_length=10_000)
    expires_at: datetime | None = None


class StopRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=10_000)


class FindingResponse(BaseModel):
    severity: Literal["ERROR", "WARNING", "INFO"]
    code: str
    message: str


class TargetResponse(BaseModel):
    id: uuid.UUID
    target_type: TargetTypeValue
    raw_value: str
    canonical_value: str
    match_mode: MatchModeValue
    warning: str | None = None
    reason: str | None = None
    created_at: datetime | None = None


class PolicyResponse(BaseModel):
    id: uuid.UUID
    allowed_protocols: list[str]
    max_requests_per_second: float
    max_concurrent_targets: int
    max_concurrent_requests: int
    schedule_timezone: str
    schedule_windows: list[dict[str, object]]
    connect_timeout_seconds: int
    request_timeout_seconds: int
    active_scanning_enabled: bool
    updated_at: datetime | None = None


class ApprovalResponse(BaseModel):
    id: uuid.UUID
    decision: Literal["APPROVED", "REJECTED"]
    decision_reason: str | None = None
    approved_by_user_id: uuid.UUID
    approved_at: datetime | None = None
    expires_at: datetime | None = None
    content_hash: str


class ScopeResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    description: str | None = None
    status: Literal["ACTIVE", "DISABLED", "ARCHIVED"]
    created_by_user_id: uuid.UUID
    created_at: datetime | None = None
    updated_at: datetime | None = None
    disabled_at: datetime | None = None
    disabled_by_user_id: uuid.UUID | None = None


class ScopeVersionResponse(BaseModel):
    id: uuid.UUID
    scope_id: uuid.UUID
    organization_id: uuid.UUID
    version_number: int
    state: Literal["DRAFT", "SUBMITTED", "APPROVED", "REJECTED", "SUPERSEDED"]
    change_summary: str | None = None
    created_by_user_id: uuid.UUID
    supersedes_version_id: uuid.UUID | None = None
    content_hash: str | None = None
    created_at: datetime | None = None
    seeds: list[TargetResponse] = Field(default_factory=list)
    exclusions: list[TargetResponse] = Field(default_factory=list)
    policy: PolicyResponse | None = None
    approvals: list[ApprovalResponse] = Field(default_factory=list)


class ValidationResponse(BaseModel):
    approvable: bool
    errors: list[FindingResponse]
    warnings: list[FindingResponse]
    content_hash: str | None = None


class StopResponse(BaseModel):
    active: bool
    level: Literal["ORGANIZATION", "SCOPE"] | None
    stop_generation: int


def _error(status_code: int, code: str, message: str) -> NoReturn:
    raise HTTPException(
        status_code=status_code, detail={"error": {"code": code, "message": message}}
    )


def _context(
    session: Session, principal: Principal, organization_id: str | None
) -> OrganizationContext:
    return require_org_context(session, principal, organization_id)


def _parse_uuid(value: str, resource: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError:
        _error(status.HTTP_404_NOT_FOUND, "SCOPE_NOT_FOUND", f"{resource} not found")
    raise AssertionError("unreachable")


def _scope(session: Session, context: OrganizationContext, scope_id: str) -> Scope:
    parsed = _parse_uuid(scope_id, "Scope")
    scope = session.scalar(
        select(Scope).where(Scope.id == parsed, Scope.organization_id == context.organization_id)
    )
    if scope is None:
        exists_in_another_organization = session.scalar(
            select(Scope.id)
            .where(Scope.id == parsed, Scope.organization_id != context.organization_id)
            .limit(1)
        )
        if exists_in_another_organization is not None:
            _error(status.HTTP_403_FORBIDDEN, "FORBIDDEN", "Scope belongs to another organization")
        _error(status.HTTP_404_NOT_FOUND, "SCOPE_NOT_FOUND", "Scope not found")
    return scope


def _version(
    session: Session, context: OrganizationContext, scope: Scope, version_id: str
) -> ScopeVersion:
    parsed = _parse_uuid(version_id, "Scope version")
    version = session.scalar(
        select(ScopeVersion).where(
            ScopeVersion.id == parsed,
            ScopeVersion.scope_id == scope.id,
            ScopeVersion.organization_id == context.organization_id,
        )
    )
    if version is None:
        _error(status.HTTP_404_NOT_FOUND, "SCOPE_NOT_FOUND", "Scope version not found")
    return version


def _require_draft(version: ScopeVersion) -> None:
    try:
        ScopeApprovalService.ensure_draft(version)
    except ScopeStateError as exc:
        _error(status.HTTP_409_CONFLICT, "SCOPE_VERSION_IMMUTABLE", str(exc))


def _audit(
    session: Session,
    context: OrganizationContext,
    principal: Principal,
    request: Request,
    *,
    action: str,
    resource_type: str,
    resource_id: uuid.UUID | str | None,
    metadata: dict[str, object] | None = None,
) -> None:
    write_audit_event(
        session,
        context,
        principal,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        correlation_id=request.state.correlation_id,
        result="success",
        metadata=metadata,
    )


def _scope_response(scope: Scope) -> ScopeResponse:
    return ScopeResponse(
        id=scope.id,
        organization_id=scope.organization_id,
        name=scope.name,
        description=scope.description,
        status=cast(Literal["ACTIVE", "DISABLED", "ARCHIVED"], scope.status),
        created_by_user_id=scope.created_by_user_id,
        created_at=scope.created_at,
        updated_at=scope.updated_at,
        disabled_at=scope.disabled_at,
        disabled_by_user_id=scope.disabled_by_user_id,
    )


def _seed_response(seed: ScopeSeed) -> TargetResponse:
    warning = (
        None if seed.raw_value == seed.canonical_value else f"Normalized to {seed.canonical_value}"
    )
    return TargetResponse(
        id=seed.id,
        target_type=cast(TargetTypeValue, seed.seed_type),
        raw_value=seed.raw_value,
        canonical_value=seed.canonical_value,
        match_mode=cast(MatchModeValue, seed.match_mode),
        warning=warning,
        created_at=seed.created_at,
    )


def _exclusion_response(exclusion: ScopeExclusion) -> TargetResponse:
    warning = (
        None
        if exclusion.raw_value == exclusion.canonical_value
        else f"Normalized to {exclusion.canonical_value}"
    )
    return TargetResponse(
        id=exclusion.id,
        target_type=cast(TargetTypeValue, exclusion.exclusion_type),
        raw_value=exclusion.raw_value,
        canonical_value=exclusion.canonical_value,
        match_mode=cast(MatchModeValue, exclusion.match_mode),
        warning=warning,
        reason=exclusion.reason,
        created_at=exclusion.created_at,
    )


def _policy_response(policy: ScanPolicy) -> PolicyResponse:
    return PolicyResponse(
        id=policy.id,
        allowed_protocols=policy.allowed_protocols,
        max_requests_per_second=policy.max_requests_per_second,
        max_concurrent_targets=policy.max_concurrent_targets,
        max_concurrent_requests=policy.max_concurrent_requests,
        schedule_timezone=policy.schedule_timezone,
        schedule_windows=policy.schedule_windows,
        connect_timeout_seconds=policy.connect_timeout_seconds,
        request_timeout_seconds=policy.request_timeout_seconds,
        active_scanning_enabled=policy.active_scanning_enabled,
        updated_at=policy.updated_at,
    )


def _approval_response(approval: ScopeApproval) -> ApprovalResponse:
    return ApprovalResponse(
        id=approval.id,
        decision=cast(Literal["APPROVED", "REJECTED"], approval.decision),
        decision_reason=approval.decision_reason,
        approved_by_user_id=approval.approved_by_user_id,
        approved_at=approval.approved_at,
        expires_at=approval.expires_at,
        content_hash=approval.content_hash,
    )


def _version_response(session: Session, version: ScopeVersion) -> ScopeVersionResponse:
    seeds = session.scalars(
        select(ScopeSeed).where(
            ScopeSeed.scope_version_id == version.id,
            ScopeSeed.organization_id == version.organization_id,
        )
    ).all()
    exclusions = session.scalars(
        select(ScopeExclusion).where(
            ScopeExclusion.scope_version_id == version.id,
            ScopeExclusion.organization_id == version.organization_id,
        )
    ).all()
    policy = session.scalar(
        select(ScanPolicy).where(
            ScanPolicy.scope_version_id == version.id,
            ScanPolicy.organization_id == version.organization_id,
        )
    )
    approvals = session.scalars(
        select(ScopeApproval)
        .where(
            ScopeApproval.scope_version_id == version.id,
            ScopeApproval.organization_id == version.organization_id,
        )
        .order_by(ScopeApproval.approved_at.desc())
    ).all()
    return ScopeVersionResponse(
        id=version.id,
        scope_id=version.scope_id,
        organization_id=version.organization_id,
        version_number=version.version_number,
        state=cast(
            Literal["DRAFT", "SUBMITTED", "APPROVED", "REJECTED", "SUPERSEDED"], version.state
        ),
        change_summary=version.change_summary,
        created_by_user_id=version.created_by_user_id,
        supersedes_version_id=version.supersedes_version_id,
        content_hash=version.content_hash,
        created_at=version.created_at,
        seeds=[_seed_response(seed) for seed in seeds],
        exclusions=[_exclusion_response(exclusion) for exclusion in exclusions],
        policy=_policy_response(policy) if policy is not None else None,
        approvals=[_approval_response(approval) for approval in approvals],
    )


def _copy_version_contents(session: Session, source: ScopeVersion, target: ScopeVersion) -> None:
    for seed in session.scalars(
        select(ScopeSeed).where(
            ScopeSeed.scope_version_id == source.id,
            ScopeSeed.organization_id == source.organization_id,
        )
    ):
        session.add(
            ScopeSeed(
                scope_version_id=target.id,
                organization_id=target.organization_id,
                seed_type=seed.seed_type,
                raw_value=seed.raw_value,
                canonical_value=seed.canonical_value,
                match_mode=seed.match_mode,
                metadata_json=seed.metadata_json,
            )
        )
    for exclusion in session.scalars(
        select(ScopeExclusion).where(
            ScopeExclusion.scope_version_id == source.id,
            ScopeExclusion.organization_id == source.organization_id,
        )
    ):
        session.add(
            ScopeExclusion(
                scope_version_id=target.id,
                organization_id=target.organization_id,
                exclusion_type=exclusion.exclusion_type,
                raw_value=exclusion.raw_value,
                canonical_value=exclusion.canonical_value,
                match_mode=exclusion.match_mode,
                reason=exclusion.reason,
            )
        )
    policy = session.scalar(
        select(ScanPolicy).where(
            ScanPolicy.scope_version_id == source.id,
            ScanPolicy.organization_id == source.organization_id,
        )
    )
    if policy is not None:
        session.add(
            ScanPolicy(
                scope_version_id=target.id,
                organization_id=target.organization_id,
                allowed_protocols=policy.allowed_protocols,
                max_requests_per_second=policy.max_requests_per_second,
                max_concurrent_targets=policy.max_concurrent_targets,
                max_concurrent_requests=policy.max_concurrent_requests,
                schedule_timezone=policy.schedule_timezone,
                schedule_windows=policy.schedule_windows,
                connect_timeout_seconds=policy.connect_timeout_seconds,
                request_timeout_seconds=policy.request_timeout_seconds,
                active_scanning_enabled=False,
            )
        )


@router.get("/scopes", response_model=list[ScopeResponse])
def list_scopes(
    organization_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> list[ScopeResponse]:
    context = _context(session, principal, organization_id)
    scopes = session.scalars(
        select(Scope)
        .where(Scope.organization_id == context.organization_id)
        .order_by(Scope.created_at.desc())
    ).all()
    return [_scope_response(scope) for scope in scopes]


@router.post("/scopes", response_model=ScopeVersionResponse, status_code=status.HTTP_201_CREATED)
def create_scope(
    body: ScopeCreateRequest,
    request: Request,
    organization_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> ScopeVersionResponse:
    context = _context(session, principal, organization_id)
    require_role(context, "analyst", "reviewer", "admin", "owner")
    scope = Scope(
        organization_id=context.organization_id,
        name=body.name,
        description=body.description,
        created_by_user_id=principal.user.id,
    )
    session.add(scope)
    session.flush()
    version = ScopeVersion(
        scope_id=scope.id,
        organization_id=context.organization_id,
        version_number=1,
        state="DRAFT",
        change_summary="Initial draft",
        created_by_user_id=principal.user.id,
    )
    session.add(version)
    _audit(
        session,
        context,
        principal,
        request,
        action="scope.create",
        resource_type="scope",
        resource_id=scope.id,
    )
    _audit(
        session,
        context,
        principal,
        request,
        action="scope.version.create",
        resource_type="scope_version",
        resource_id=version.id,
        metadata={"version_number": 1},
    )
    session.commit()
    session.refresh(version)
    return _version_response(session, version)


@router.get("/scopes/{scope_id}", response_model=ScopeResponse)
def get_scope(
    scope_id: str,
    organization_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> ScopeResponse:
    return _scope_response(_scope(session, _context(session, principal, organization_id), scope_id))


@router.patch("/scopes/{scope_id}", response_model=ScopeResponse)
def update_scope(
    scope_id: str,
    body: ScopeUpdateRequest,
    request: Request,
    organization_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> ScopeResponse:
    context = _context(session, principal, organization_id)
    require_role(context, "analyst", "reviewer", "admin", "owner")
    scope = _scope(session, context, scope_id)
    if body.name is not None:
        scope.name = body.name
    if body.description is not None:
        scope.description = body.description
    _audit(
        session,
        context,
        principal,
        request,
        action="scope.update",
        resource_type="scope",
        resource_id=scope.id,
    )
    session.commit()
    session.refresh(scope)
    return _scope_response(scope)


@router.get("/scopes/{scope_id}/versions", response_model=list[ScopeVersionResponse])
def list_versions(
    scope_id: str,
    organization_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> list[ScopeVersionResponse]:
    context = _context(session, principal, organization_id)
    scope = _scope(session, context, scope_id)
    versions = session.scalars(
        select(ScopeVersion)
        .where(
            ScopeVersion.scope_id == scope.id,
            ScopeVersion.organization_id == context.organization_id,
        )
        .order_by(ScopeVersion.version_number.desc())
    ).all()
    return [_version_response(session, version) for version in versions]


@router.post(
    "/scopes/{scope_id}/versions",
    response_model=ScopeVersionResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_version(
    scope_id: str,
    body: ScopeVersionCreateRequest,
    request: Request,
    organization_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> ScopeVersionResponse:
    context = _context(session, principal, organization_id)
    require_role(context, "analyst", "reviewer", "admin", "owner")
    scope = _scope(session, context, scope_id)
    latest_number = session.scalar(
        select(func.max(ScopeVersion.version_number)).where(
            ScopeVersion.scope_id == scope.id,
            ScopeVersion.organization_id == context.organization_id,
        )
    )
    source: ScopeVersion | None = None
    if body.clone_from_version_id is not None:
        source = _version(session, context, scope, str(body.clone_from_version_id))
    version = ScopeVersion(
        scope_id=scope.id,
        organization_id=context.organization_id,
        version_number=(latest_number or 0) + 1,
        state="DRAFT",
        change_summary=body.change_summary,
        created_by_user_id=principal.user.id,
        supersedes_version_id=source.id if source is not None else None,
    )
    session.add(version)
    session.flush()
    if source is not None:
        _copy_version_contents(session, source, version)
    _audit(
        session,
        context,
        principal,
        request,
        action="scope.version.create",
        resource_type="scope_version",
        resource_id=version.id,
        metadata={
            "version_number": version.version_number,
            "cloned_from": str(source.id) if source else None,
        },
    )
    session.commit()
    session.refresh(version)
    return _version_response(session, version)


@router.get("/scopes/{scope_id}/versions/{version_id}", response_model=ScopeVersionResponse)
def get_version(
    scope_id: str,
    version_id: str,
    organization_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> ScopeVersionResponse:
    context = _context(session, principal, organization_id)
    return _version_response(
        session, _version(session, context, _scope(session, context, scope_id), version_id)
    )


def _normalized_rule(body: TargetCreateRequest) -> tuple[TargetType, str, MatchMode]:
    try:
        normalized = ScopeTargetNormalizer.normalize_target(
            cast(TargetType, body.target_type), body.raw_value
        )
    except ScopeValidationError as exc:
        _error(status.HTTP_422_UNPROCESSABLE_ENTITY, "INVALID_SEED", str(exc))
    return (
        cast(TargetType, body.target_type),
        normalized.canonical_value,
        cast(MatchMode, body.match_mode),
    )


@router.post(
    "/scopes/{scope_id}/versions/{version_id}/seeds",
    response_model=TargetResponse,
    status_code=status.HTTP_201_CREATED,
)
def add_seed(
    scope_id: str,
    version_id: str,
    body: TargetCreateRequest,
    request: Request,
    organization_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> TargetResponse:
    context = _context(session, principal, organization_id)
    require_role(context, "analyst", "reviewer", "admin", "owner")
    version = _version(session, context, _scope(session, context, scope_id), version_id)
    _require_draft(version)
    target_type, canonical_value, match_mode = _normalized_rule(body)
    seed = ScopeSeed(
        scope_version_id=version.id,
        organization_id=context.organization_id,
        seed_type=target_type,
        raw_value=body.raw_value,
        canonical_value=canonical_value,
        match_mode=match_mode,
    )
    session.add(seed)
    _audit(
        session,
        context,
        principal,
        request,
        action="scope.version.update",
        resource_type="scope_seed",
        resource_id=seed.id,
        metadata={"scope_version_id": str(version.id), "operation": "seed.add"},
    )
    session.commit()
    session.refresh(seed)
    return _seed_response(seed)


@router.delete(
    "/scopes/{scope_id}/versions/{version_id}/seeds/{seed_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_seed(
    scope_id: str,
    version_id: str,
    seed_id: str,
    request: Request,
    organization_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> None:
    context = _context(session, principal, organization_id)
    require_role(context, "analyst", "reviewer", "admin", "owner")
    version = _version(session, context, _scope(session, context, scope_id), version_id)
    _require_draft(version)
    seed = session.scalar(
        select(ScopeSeed).where(
            ScopeSeed.id == _parse_uuid(seed_id, "Seed"),
            ScopeSeed.scope_version_id == version.id,
            ScopeSeed.organization_id == context.organization_id,
        )
    )
    if seed is None:
        _error(status.HTTP_404_NOT_FOUND, "SCOPE_NOT_FOUND", "Seed not found")
    session.delete(seed)
    _audit(
        session,
        context,
        principal,
        request,
        action="scope.version.update",
        resource_type="scope_seed",
        resource_id=seed.id,
        metadata={"scope_version_id": str(version.id), "operation": "seed.delete"},
    )
    session.commit()


@router.post(
    "/scopes/{scope_id}/versions/{version_id}/exclusions",
    response_model=TargetResponse,
    status_code=status.HTTP_201_CREATED,
)
def add_exclusion(
    scope_id: str,
    version_id: str,
    body: TargetCreateRequest,
    request: Request,
    organization_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> TargetResponse:
    if body.reason is None:
        _error(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "INVALID_EXCLUSION",
            "Exclusion reason is required",
        )
    context = _context(session, principal, organization_id)
    require_role(context, "analyst", "reviewer", "admin", "owner")
    version = _version(session, context, _scope(session, context, scope_id), version_id)
    _require_draft(version)
    try:
        normalized = ScopeTargetNormalizer.normalize_target(
            cast(TargetType, body.target_type), body.raw_value
        )
    except ScopeValidationError as exc:
        _error(status.HTTP_422_UNPROCESSABLE_ENTITY, "INVALID_EXCLUSION", str(exc))
    exclusion = ScopeExclusion(
        scope_version_id=version.id,
        organization_id=context.organization_id,
        exclusion_type=body.target_type,
        raw_value=body.raw_value,
        canonical_value=normalized.canonical_value,
        match_mode=body.match_mode,
        reason=body.reason,
    )
    session.add(exclusion)
    _audit(
        session,
        context,
        principal,
        request,
        action="scope.version.update",
        resource_type="scope_exclusion",
        resource_id=exclusion.id,
        metadata={"scope_version_id": str(version.id), "operation": "exclusion.add"},
    )
    session.commit()
    session.refresh(exclusion)
    return _exclusion_response(exclusion)


@router.delete(
    "/scopes/{scope_id}/versions/{version_id}/exclusions/{exclusion_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_exclusion(
    scope_id: str,
    version_id: str,
    exclusion_id: str,
    request: Request,
    organization_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> None:
    context = _context(session, principal, organization_id)
    require_role(context, "analyst", "reviewer", "admin", "owner")
    version = _version(session, context, _scope(session, context, scope_id), version_id)
    _require_draft(version)
    exclusion = session.scalar(
        select(ScopeExclusion).where(
            ScopeExclusion.id == _parse_uuid(exclusion_id, "Exclusion"),
            ScopeExclusion.scope_version_id == version.id,
            ScopeExclusion.organization_id == context.organization_id,
        )
    )
    if exclusion is None:
        _error(status.HTTP_404_NOT_FOUND, "SCOPE_NOT_FOUND", "Exclusion not found")
    session.delete(exclusion)
    _audit(
        session,
        context,
        principal,
        request,
        action="scope.version.update",
        resource_type="scope_exclusion",
        resource_id=exclusion.id,
        metadata={"scope_version_id": str(version.id), "operation": "exclusion.delete"},
    )
    session.commit()


@router.put("/scopes/{scope_id}/versions/{version_id}/policy", response_model=PolicyResponse)
def put_policy(
    scope_id: str,
    version_id: str,
    body: PolicyUpsertRequest,
    request: Request,
    organization_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> PolicyResponse:
    if body.active_scanning_enabled:
        _error(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "POLICY_INVALID",
            "Active network scanning is outside the Phase 2 boundary",
        )
    context = _context(session, principal, organization_id)
    require_role(context, "analyst", "reviewer", "admin", "owner")
    version = _version(session, context, _scope(session, context, scope_id), version_id)
    _require_draft(version)
    snapshot = ScanPolicySnapshot(
        allowed_protocols=tuple(body.allowed_protocols),
        max_requests_per_second=body.max_requests_per_second,
        max_concurrent_targets=body.max_concurrent_targets,
        max_concurrent_requests=body.max_concurrent_requests,
        schedule_timezone=body.schedule_timezone,
        schedule_windows=tuple(window.model_dump() for window in body.schedule_windows),
        policy_hash="pending",
    )
    try:
        validate_policy(snapshot, get_settings())
    except PolicyValidationError as exc:
        _error(status.HTTP_422_UNPROCESSABLE_ENTITY, "POLICY_INVALID", str(exc))
    policy = session.scalar(
        select(ScanPolicy).where(
            ScanPolicy.scope_version_id == version.id,
            ScanPolicy.organization_id == context.organization_id,
        )
    )
    if policy is None:
        policy = ScanPolicy(scope_version_id=version.id, organization_id=context.organization_id)
        session.add(policy)
    policy.allowed_protocols = list(body.allowed_protocols)
    policy.max_requests_per_second = body.max_requests_per_second
    policy.max_concurrent_targets = body.max_concurrent_targets
    policy.max_concurrent_requests = body.max_concurrent_requests
    policy.schedule_timezone = body.schedule_timezone
    policy.schedule_windows = [window.model_dump() for window in body.schedule_windows]
    policy.connect_timeout_seconds = body.connect_timeout_seconds
    policy.request_timeout_seconds = body.request_timeout_seconds
    policy.active_scanning_enabled = False
    _audit(
        session,
        context,
        principal,
        request,
        action="scope.version.update",
        resource_type="scan_policy",
        resource_id=policy.id,
        metadata={"scope_version_id": str(version.id), "operation": "policy.upsert"},
    )
    session.commit()
    session.refresh(policy)
    return _policy_response(policy)


def _rules(session: Session, version: ScopeVersion) -> tuple[list[TargetRule], list[TargetRule]]:
    seeds = session.scalars(
        select(ScopeSeed).where(
            ScopeSeed.scope_version_id == version.id,
            ScopeSeed.organization_id == version.organization_id,
        )
    ).all()
    exclusions = session.scalars(
        select(ScopeExclusion).where(
            ScopeExclusion.scope_version_id == version.id,
            ScopeExclusion.organization_id == version.organization_id,
        )
    ).all()
    return (
        [
            TargetRule(
                target_type=cast(TargetType, seed.seed_type),
                canonical_value=seed.canonical_value,
                match_mode=cast(MatchMode, seed.match_mode),
            )
            for seed in seeds
        ],
        [
            TargetRule(
                target_type=cast(TargetType, exclusion.exclusion_type),
                canonical_value=exclusion.canonical_value,
                match_mode=cast(MatchMode, exclusion.match_mode),
            )
            for exclusion in exclusions
        ],
    )


def _finding_response(finding: ConflictFinding) -> FindingResponse:
    return FindingResponse(severity=finding.severity, code=finding.code, message=finding.message)


@router.post("/scopes/{scope_id}/versions/{version_id}/validate", response_model=ValidationResponse)
def validate_version(
    scope_id: str,
    version_id: str,
    organization_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> ValidationResponse:
    context = _context(session, principal, organization_id)
    version = _version(session, context, _scope(session, context, scope_id), version_id)
    seeds, exclusions = _rules(session, version)
    report = ScopeConflictAnalyzer.analyze(seeds, exclusions)
    try:
        content_hash = ScopeApprovalService.content_hash(session, version)
    except ScopeStateError:
        content_hash = None
    return ValidationResponse(
        approvable=report.is_approvable and bool(seeds) and content_hash is not None,
        errors=[_finding_response(finding) for finding in report.errors],
        warnings=[_finding_response(finding) for finding in report.warnings],
        content_hash=content_hash,
    )


@router.post("/scopes/{scope_id}/versions/{version_id}/submit", response_model=ScopeVersionResponse)
def submit_version(
    scope_id: str,
    version_id: str,
    request: Request,
    organization_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> ScopeVersionResponse:
    context = _context(session, principal, organization_id)
    require_role(context, "analyst", "reviewer", "admin", "owner")
    version = _version(session, context, _scope(session, context, scope_id), version_id)
    policy = session.scalar(
        select(ScanPolicy).where(
            ScanPolicy.scope_version_id == version.id,
            ScanPolicy.organization_id == context.organization_id,
        )
    )
    if policy is None:
        _error(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "POLICY_INVALID",
            "Scope version requires a policy",
        )
    try:
        validate_policy(
            ScanPolicySnapshot(
                allowed_protocols=tuple(policy.allowed_protocols),
                max_requests_per_second=policy.max_requests_per_second,
                max_concurrent_targets=policy.max_concurrent_targets,
                max_concurrent_requests=policy.max_concurrent_requests,
                schedule_timezone=policy.schedule_timezone,
                schedule_windows=tuple(policy.schedule_windows),
                policy_hash="pending",
            ),
            get_settings(),
        )
        ScopeApprovalService.submit(session, version)
    except PolicyValidationError as exc:
        _error(status.HTTP_422_UNPROCESSABLE_ENTITY, "POLICY_INVALID", str(exc))
    except ScopeStateError as exc:
        code = "SCOPE_VERSION_IMMUTABLE" if version.state != "DRAFT" else "SCOPE_CONFLICT"
        _error(status.HTTP_409_CONFLICT, code, str(exc))
    _audit(
        session,
        context,
        principal,
        request,
        action="scope.version.submit",
        resource_type="scope_version",
        resource_id=version.id,
        metadata={"content_hash": version.content_hash},
    )
    session.commit()
    session.refresh(version)
    return _version_response(session, version)


@router.post("/scopes/{scope_id}/versions/{version_id}/approve", response_model=ApprovalResponse)
def approve_version(
    scope_id: str,
    version_id: str,
    body: ApprovalRequest,
    request: Request,
    organization_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> ApprovalResponse:
    context = _context(session, principal, organization_id)
    require_role(context, "admin", "owner")
    scope = _scope(session, context, scope_id)
    version = _version(session, context, scope, version_id)
    try:
        approval = ScopeApprovalService.approve(
            session,
            organization_id=context.organization_id,
            scope_id=scope.id,
            version_id=version.id,
            approver_id=principal.user.id,
            reason=body.decision_reason,
            expires_at=body.expires_at,
        )
    except ScopeStateError as exc:
        _error(status.HTTP_409_CONFLICT, "APPROVAL_REQUIRED", str(exc))
    _audit(
        session,
        context,
        principal,
        request,
        action="scope.approval.approve",
        resource_type="scope_approval",
        resource_id=approval.id,
        metadata={"scope_version_id": str(version.id), "content_hash": approval.content_hash},
    )
    session.commit()
    session.refresh(approval)
    return _approval_response(approval)


@router.post("/scopes/{scope_id}/versions/{version_id}/reject", response_model=ApprovalResponse)
def reject_version(
    scope_id: str,
    version_id: str,
    body: ApprovalRequest,
    request: Request,
    organization_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> ApprovalResponse:
    context = _context(session, principal, organization_id)
    require_role(context, "admin", "owner")
    scope = _scope(session, context, scope_id)
    version = _version(session, context, scope, version_id)
    if version.state != "SUBMITTED":
        _error(
            status.HTTP_409_CONFLICT,
            "APPROVAL_REQUIRED",
            "Only submitted scope versions can be rejected",
        )
    if version.content_hash is None:
        _error(
            status.HTTP_409_CONFLICT, "APPROVAL_REQUIRED", "Submitted version has no content hash"
        )
    version.state = "REJECTED"
    approval = ScopeApproval(
        organization_id=context.organization_id,
        scope_id=scope.id,
        scope_version_id=version.id,
        approved_by_user_id=principal.user.id,
        decision="REJECTED",
        decision_reason=body.decision_reason,
        content_hash=version.content_hash,
    )
    session.add(approval)
    session.flush()
    _audit(
        session,
        context,
        principal,
        request,
        action="scope.approval.reject",
        resource_type="scope_approval",
        resource_id=approval.id,
        metadata={"scope_version_id": str(version.id), "content_hash": approval.content_hash},
    )
    session.commit()
    session.refresh(approval)
    return _approval_response(approval)


@router.post("/scopes/{scope_id}/disable", response_model=ScopeResponse)
def disable_scope(
    scope_id: str,
    request: Request,
    organization_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> ScopeResponse:
    context = _context(session, principal, organization_id)
    require_role(context, "admin", "owner")
    scope = _scope(session, context, scope_id)
    scope.status = "DISABLED"
    scope.disabled_at = datetime.now(UTC)
    scope.disabled_by_user_id = principal.user.id
    _audit(
        session,
        context,
        principal,
        request,
        action="scope.disable",
        resource_type="scope",
        resource_id=scope.id,
    )
    session.commit()
    session.refresh(scope)
    return _scope_response(scope)


@router.post("/scopes/{scope_id}/enable", response_model=ScopeResponse)
def enable_scope(
    scope_id: str,
    request: Request,
    organization_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> ScopeResponse:
    context = _context(session, principal, organization_id)
    require_role(context, "admin", "owner")
    scope = _scope(session, context, scope_id)
    scope.status = "ACTIVE"
    scope.disabled_at = None
    scope.disabled_by_user_id = None
    _audit(
        session,
        context,
        principal,
        request,
        action="scope.enable",
        resource_type="scope",
        resource_id=scope.id,
    )
    session.commit()
    session.refresh(scope)
    return _scope_response(scope)


def _stop_response(
    session: Session, context: OrganizationContext, scope_id: uuid.UUID
) -> StopResponse:
    stop_status = EmergencyStopService.status(
        session, organization_id=context.organization_id, scope_id=scope_id
    )
    return StopResponse(
        active=stop_status.active,
        level=cast(Literal["ORGANIZATION", "SCOPE"] | None, stop_status.level),
        stop_generation=stop_status.generation,
    )


@router.post("/scopes/{scope_id}/emergency-stop", response_model=StopResponse)
def stop_scope(
    scope_id: str,
    body: StopRequest,
    request: Request,
    organization_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> StopResponse:
    context = _context(session, principal, organization_id)
    require_role(context, "admin", "owner")
    scope = _scope(session, context, scope_id)
    state = EmergencyStopService.set_stop(
        session,
        organization_id=context.organization_id,
        scope_id=scope.id,
        actor_id=principal.user.id,
        reason=body.reason,
    )
    _audit(
        session,
        context,
        principal,
        request,
        action="scope.emergency_stop",
        resource_type="scope",
        resource_id=scope.id,
        metadata={"generation": state.stop_generation},
    )
    session.commit()
    return _stop_response(session, context, scope.id)


@router.post("/scopes/{scope_id}/resume", response_model=StopResponse)
def resume_scope(
    scope_id: str,
    request: Request,
    organization_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> StopResponse:
    context = _context(session, principal, organization_id)
    require_role(context, "admin", "owner")
    scope = _scope(session, context, scope_id)
    try:
        EmergencyStopService.resume(
            session,
            organization_id=context.organization_id,
            scope_id=scope.id,
            actor_id=principal.user.id,
        )
    except ValueError as exc:
        _error(status.HTTP_409_CONFLICT, "EMERGENCY_STOP_ACTIVE", str(exc))
    _audit(
        session,
        context,
        principal,
        request,
        action="scope.resume",
        resource_type="scope",
        resource_id=scope.id,
    )
    session.commit()
    return _stop_response(session, context, scope.id)


def _organization_scope_id(session: Session, context: OrganizationContext) -> uuid.UUID:
    scope = session.scalar(
        select(Scope.id)
        .where(Scope.organization_id == context.organization_id)
        .order_by(Scope.created_at.asc())
        .limit(1)
    )
    return scope or uuid.UUID(int=0)


@router.post("/organizations/{organization_id}/emergency-stop", response_model=StopResponse)
def stop_organization(
    organization_id: str,
    body: StopRequest,
    request: Request,
    context_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> StopResponse:
    context = _context(session, principal, context_id)
    if str(context.organization_id) != organization_id:
        _error(
            status.HTTP_403_FORBIDDEN, "FORBIDDEN", "Organization context does not match resource"
        )
    require_role(context, "admin", "owner")
    state = EmergencyStopService.set_stop(
        session,
        organization_id=context.organization_id,
        scope_id=None,
        actor_id=principal.user.id,
        reason=body.reason,
    )
    _audit(
        session,
        context,
        principal,
        request,
        action="organization.emergency_stop",
        resource_type="organization",
        resource_id=context.organization_id,
        metadata={"generation": state.stop_generation},
    )
    session.commit()
    return _stop_response(session, context, _organization_scope_id(session, context))


@router.post("/organizations/{organization_id}/resume", response_model=StopResponse)
def resume_organization(
    organization_id: str,
    request: Request,
    context_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> StopResponse:
    context = _context(session, principal, context_id)
    if str(context.organization_id) != organization_id:
        _error(
            status.HTTP_403_FORBIDDEN, "FORBIDDEN", "Organization context does not match resource"
        )
    require_role(context, "admin", "owner")
    try:
        EmergencyStopService.resume(
            session,
            organization_id=context.organization_id,
            scope_id=None,
            actor_id=principal.user.id,
        )
    except ValueError as exc:
        _error(status.HTTP_409_CONFLICT, "EMERGENCY_STOP_ACTIVE", str(exc))
    _audit(
        session,
        context,
        principal,
        request,
        action="organization.resume",
        resource_type="organization",
        resource_id=context.organization_id,
    )
    session.commit()
    return _stop_response(session, context, _organization_scope_id(session, context))
