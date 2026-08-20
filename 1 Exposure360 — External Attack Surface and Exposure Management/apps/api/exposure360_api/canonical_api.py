import ipaddress
import uuid
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import Annotated, Literal, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .audit import write_audit_event
from .auth import current_principal
from .db import get_session
from .models import (
    AsnAsset,
    Asset,
    AssetIdentifier,
    AssetOwnership,
    CanonicalObservation,
    DomainAsset,
    EndpointAsset,
    Evidence,
    IpAsset,
    ServiceAsset,
    TechnologyFingerprint,
)
from .security import (
    OrganizationContext,
    Principal,
    organization_header,
    require_org_context,
    require_role,
)

router = APIRouter(prefix="/api/v1/assets", tags=["canonical-assets"])
_AssetType = Literal["DOMAIN", "IP", "ASN", "ENDPOINT", "SERVICE"]
_LifecycleState = Literal["ACTIVE", "STALE", "RETIRED"]
_MEMBER_ROLES = ("viewer", "reviewer", "analyst", "admin", "owner")


class PageResponse(BaseModel):
    offset: int
    limit: int
    total: int


class OwnerSummary(BaseModel):
    id: uuid.UUID
    owner_type: str
    owner_reference: str
    owner_display_name: str | None
    claim_type: str
    confidence: float


class TechnologySummary(BaseModel):
    id: uuid.UUID
    product: str
    category: str
    version_value: str | None
    confidence: float
    rule_id: str
    rule_version: int


class AssetSummary(BaseModel):
    id: uuid.UUID
    asset_type: _AssetType
    canonical_key: str
    display_name: str
    lifecycle_state: _LifecycleState
    first_seen: datetime
    last_seen: datetime
    primary_owner: OwnerSummary | None
    top_technologies: list[TechnologySummary]


class AssetListResponse(BaseModel):
    items: list[AssetSummary]
    page: PageResponse


class AssetDetailResponse(AssetSummary):
    subtype: dict[str, object] | None
    identifiers: list[dict[str, object]]
    ownership_claims: list[OwnerSummary]
    technology_fingerprints: list[TechnologySummary]
    observation_count: int
    evidence_count: int


class ObservationResponse(BaseModel):
    id: uuid.UUID
    observation_type: str
    source_type: str
    source_key: str
    observed_at: datetime
    collected_at: datetime
    confidence: float | None
    state: str
    payload_hash: str


class ObservationListResponse(BaseModel):
    items: list[ObservationResponse]
    page: PageResponse


class EvidenceMetadataResponse(BaseModel):
    id: uuid.UUID
    observation_id: uuid.UUID | None
    evidence_type: str
    sha256: str
    size_bytes: int
    media_type: str
    collected_at: datetime
    stored_at: datetime
    sensitivity_class: str
    collector_name: str
    collector_version: str


class OwnershipResponse(BaseModel):
    primary: OwnerSummary | None
    claims: list[OwnerSummary]


class TimelineItem(BaseModel):
    event_type: str
    occurred_at: datetime
    resource_id: uuid.UUID | None
    summary: str


class RelationshipResponse(BaseModel):
    relationship_type: str
    target_asset_id: uuid.UUID
    source_observation_id: uuid.UUID | None
    observed_at: datetime | None


@router.get("", response_model=AssetListResponse)
def list_assets(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
    asset_type: _AssetType | None = None,
    lifecycle_state: _LifecycleState | None = None,
    search: str | None = Query(default=None, max_length=255),
    owner: str | None = Query(default=None, max_length=255),
    technology: str | None = Query(default=None, max_length=255),
    first_seen_from: datetime | None = None,
    last_seen_to: datetime | None = None,
    offset: int = Query(default=0, ge=0, le=100_000),
    limit: int = Query(default=50, ge=1, le=100),
) -> AssetListResponse:
    context = _access_context(session, principal, organization_id)
    filters = [Asset.organization_id == context.organization_id]
    if asset_type is not None:
        filters.append(Asset.asset_type == asset_type)
    if lifecycle_state is not None:
        filters.append(Asset.lifecycle_state == lifecycle_state)
    if search:
        pattern = f"%{search.strip()}%"
        filters.append(or_(Asset.display_name.ilike(pattern), Asset.canonical_key.ilike(pattern)))
    if owner:
        filters.append(
            Asset.id.in_(
                select(AssetOwnership.asset_id).where(
                    AssetOwnership.organization_id == context.organization_id,
                    AssetOwnership.owner_reference == owner,
                )
            )
        )
    if technology:
        filters.append(
            Asset.id.in_(
                select(TechnologyFingerprint.asset_id).where(
                    TechnologyFingerprint.organization_id == context.organization_id,
                    TechnologyFingerprint.technology_product.ilike(f"%{technology.strip()}%"),
                )
            )
        )
    if first_seen_from is not None:
        filters.append(Asset.first_seen >= first_seen_from)
    if last_seen_to is not None:
        filters.append(Asset.last_seen <= last_seen_to)
    assets = list(
        session.scalars(
            select(Asset)
            .where(*filters)
            .order_by(Asset.last_seen.desc(), Asset.id.asc())
            .offset(offset)
            .limit(limit)
        )
    )
    total = session.scalar(select(func.count(Asset.id)).where(*filters)) or 0
    owners, technologies = _list_summaries(session, context, [asset.id for asset in assets])
    _audit(session, context, principal, request, "asset.list")
    return AssetListResponse(
        items=[
            _asset_summary(asset, owners.get(asset.id), technologies.get(asset.id, []))
            for asset in assets
        ],
        page=PageResponse(offset=offset, limit=limit, total=total),
    )


@router.get("/{asset_id}", response_model=AssetDetailResponse)
def get_asset_detail(
    asset_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> AssetDetailResponse:
    context = _access_context(session, principal, organization_id)
    asset = _asset_for_context(session, context, asset_id)
    owners, technologies = _list_summaries(session, context, [asset.id])
    claims = list(
        session.scalars(
            select(AssetOwnership)
            .where(
                AssetOwnership.organization_id == context.organization_id,
                AssetOwnership.asset_id == asset.id,
            )
            .order_by(AssetOwnership.is_primary.desc(), AssetOwnership.confidence.desc())
        )
    )
    identifiers = list(
        session.scalars(
            select(AssetIdentifier)
            .where(
                AssetIdentifier.organization_id == context.organization_id,
                AssetIdentifier.asset_id == asset.id,
            )
            .order_by(AssetIdentifier.is_primary.desc(), AssetIdentifier.canonical_value.asc())
        )
    )
    observations = (
        session.scalar(
            select(func.count(CanonicalObservation.id)).where(
                CanonicalObservation.organization_id == context.organization_id,
                CanonicalObservation.asset_id == asset.id,
            )
        )
        or 0
    )
    evidence = (
        session.scalar(
            select(func.count(Evidence.id)).where(
                Evidence.organization_id == context.organization_id,
                Evidence.asset_id == asset.id,
            )
        )
        or 0
    )
    _audit(session, context, principal, request, "asset.detail", asset.id)
    summary = _asset_summary(asset, owners.get(asset.id), technologies.get(asset.id, []))
    return AssetDetailResponse(
        **summary.model_dump(),
        subtype=_subtype_data(session, context, asset),
        identifiers=[
            {
                "id": identifier.id,
                "identifier_type": identifier.identifier_type,
                "canonical_value": identifier.canonical_value,
                "is_primary": identifier.is_primary,
                "source": identifier.source,
                "first_seen": identifier.first_seen,
                "last_seen": identifier.last_seen,
            }
            for identifier in identifiers
        ],
        ownership_claims=[_owner_summary(claim) for claim in claims],
        technology_fingerprints=technologies.get(asset.id, []),
        observation_count=observations,
        evidence_count=evidence,
    )


@router.get("/{asset_id}/observations", response_model=ObservationListResponse)
def list_asset_observations(
    asset_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
    observation_type: str | None = Query(default=None, max_length=32),
    source_type: str | None = Query(default=None, max_length=64),
    observed_from: datetime | None = None,
    observed_to: datetime | None = None,
    offset: int = Query(default=0, ge=0, le=100_000),
    limit: int = Query(default=50, ge=1, le=100),
) -> ObservationListResponse:
    context = _access_context(session, principal, organization_id)
    _asset_for_context(session, context, asset_id)
    filters = [
        CanonicalObservation.organization_id == context.organization_id,
        CanonicalObservation.asset_id == asset_id,
    ]
    if observation_type is not None:
        filters.append(CanonicalObservation.observation_type == observation_type)
    if source_type is not None:
        filters.append(CanonicalObservation.source_type == source_type)
    if observed_from is not None:
        filters.append(CanonicalObservation.observed_at >= observed_from)
    if observed_to is not None:
        filters.append(CanonicalObservation.observed_at <= observed_to)
    observations = list(
        session.scalars(
            select(CanonicalObservation)
            .where(*filters)
            .order_by(CanonicalObservation.observed_at.desc(), CanonicalObservation.id.asc())
            .offset(offset)
            .limit(limit)
        )
    )
    total = session.scalar(select(func.count(CanonicalObservation.id)).where(*filters)) or 0
    _audit(session, context, principal, request, "asset.observations", asset_id)
    return ObservationListResponse(
        items=[_observation_response(item) for item in observations],
        page=PageResponse(offset=offset, limit=limit, total=total),
    )


@router.get("/{asset_id}/evidence", response_model=list[EvidenceMetadataResponse])
def list_asset_evidence(
    asset_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> list[EvidenceMetadataResponse]:
    context = _access_context(session, principal, organization_id)
    _asset_for_context(session, context, asset_id)
    evidence = list(
        session.scalars(
            select(Evidence)
            .where(
                Evidence.organization_id == context.organization_id, Evidence.asset_id == asset_id
            )
            .order_by(Evidence.collected_at.desc(), Evidence.id.asc())
        )
    )
    _audit(session, context, principal, request, "asset.evidence", asset_id)
    return [
        EvidenceMetadataResponse(
            id=item.id,
            observation_id=item.observation_id,
            evidence_type=item.evidence_type,
            sha256=item.sha256,
            size_bytes=item.size_bytes,
            media_type=item.media_type,
            collected_at=item.collected_at,
            stored_at=item.stored_at,
            sensitivity_class=item.sensitivity_class,
            collector_name=item.collector_name,
            collector_version=item.collector_version,
        )
        for item in evidence
    ]


@router.get("/{asset_id}/ownership", response_model=OwnershipResponse)
def get_asset_ownership(
    asset_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> OwnershipResponse:
    context = _access_context(session, principal, organization_id)
    _asset_for_context(session, context, asset_id)
    claims = list(
        session.scalars(
            select(AssetOwnership)
            .where(
                AssetOwnership.organization_id == context.organization_id,
                AssetOwnership.asset_id == asset_id,
            )
            .order_by(AssetOwnership.is_primary.desc(), AssetOwnership.confidence.desc())
        )
    )
    owner = next((claim for claim in claims if claim.is_primary), None)
    _audit(session, context, principal, request, "asset.ownership", asset_id)
    return OwnershipResponse(
        primary=_owner_summary(owner) if owner is not None else None,
        claims=[_owner_summary(claim) for claim in claims],
    )


@router.get("/{asset_id}/timeline", response_model=list[TimelineItem])
def get_asset_timeline(
    asset_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> list[TimelineItem]:
    context = _access_context(session, principal, organization_id)
    asset = _asset_for_context(session, context, asset_id)
    events: list[TimelineItem] = [
        TimelineItem(
            event_type="ASSET_FIRST_SEEN",
            occurred_at=_as_utc(asset.first_seen),
            resource_id=asset.id,
            summary="Canonical asset first observed",
        )
    ]
    for observation in session.scalars(
        select(CanonicalObservation)
        .where(
            CanonicalObservation.organization_id == context.organization_id,
            CanonicalObservation.asset_id == asset.id,
        )
        .order_by(CanonicalObservation.observed_at.asc())
    ):
        events.append(
            TimelineItem(
                event_type="OBSERVATION",
                occurred_at=_as_utc(observation.observed_at),
                resource_id=observation.id,
                summary=observation.observation_type,
            )
        )
    for claim in session.scalars(
        select(AssetOwnership).where(
            AssetOwnership.organization_id == context.organization_id,
            AssetOwnership.asset_id == asset.id,
        )
    ):
        events.append(
            TimelineItem(
                event_type="OWNERSHIP_CLAIM",
                occurred_at=_as_utc(claim.valid_from),
                resource_id=claim.id,
                summary=claim.claim_type,
            )
        )
    for fingerprint in session.scalars(
        select(TechnologyFingerprint).where(
            TechnologyFingerprint.organization_id == context.organization_id,
            TechnologyFingerprint.asset_id == asset.id,
        )
    ):
        events.append(
            TimelineItem(
                event_type="FINGERPRINT_FIRST_SEEN",
                occurred_at=_as_utc(fingerprint.first_seen),
                resource_id=fingerprint.id,
                summary=fingerprint.technology_product,
            )
        )
    _audit(session, context, principal, request, "asset.timeline", asset.id)
    return sorted(events, key=lambda event: (event.occurred_at, str(event.resource_id)))


@router.get("/{asset_id}/relationships", response_model=list[RelationshipResponse])
def get_asset_relationships(
    asset_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> list[RelationshipResponse]:
    context = _access_context(session, principal, organization_id)
    asset = _asset_for_context(session, context, asset_id)
    relationships = _direct_relationships(session, context, asset)
    _audit(session, context, principal, request, "asset.relationships", asset.id)
    return relationships


def _access_context(
    session: Session,
    principal: Principal,
    organization_id: str | None,
) -> OrganizationContext:
    context = require_org_context(session, principal, organization_id)
    require_role(context, *_MEMBER_ROLES)
    return context


def _asset_for_context(
    session: Session, context: OrganizationContext, asset_id: uuid.UUID
) -> Asset:
    asset = session.scalar(
        select(Asset).where(Asset.id == asset_id, Asset.organization_id == context.organization_id)
    )
    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "ASSET_NOT_FOUND", "message": "Asset was not found"},
        )
    return asset


def _list_summaries(
    session: Session,
    context: OrganizationContext,
    asset_ids: list[uuid.UUID],
) -> tuple[dict[uuid.UUID, OwnerSummary], dict[uuid.UUID, list[TechnologySummary]]]:
    if not asset_ids:
        return {}, {}
    claims = session.scalars(
        select(AssetOwnership).where(
            AssetOwnership.organization_id == context.organization_id,
            AssetOwnership.asset_id.in_(asset_ids),
            AssetOwnership.is_primary.is_(True),
        )
    )
    owners = {claim.asset_id: _owner_summary(claim) for claim in claims}
    technologies: dict[uuid.UUID, list[TechnologySummary]] = {
        asset_id: [] for asset_id in asset_ids
    }
    for fingerprint in session.scalars(
        select(TechnologyFingerprint)
        .where(
            TechnologyFingerprint.organization_id == context.organization_id,
            TechnologyFingerprint.asset_id.in_(asset_ids),
        )
        .order_by(TechnologyFingerprint.confidence.desc(), TechnologyFingerprint.id.asc())
    ):
        technologies[fingerprint.asset_id].append(_technology_summary(fingerprint))
    return owners, technologies


def _asset_summary(
    asset: Asset,
    owner: OwnerSummary | None,
    technologies: list[TechnologySummary],
) -> AssetSummary:
    return AssetSummary(
        id=asset.id,
        asset_type=cast(_AssetType, asset.asset_type),
        canonical_key=asset.canonical_key,
        display_name=asset.display_name,
        lifecycle_state=cast(_LifecycleState, asset.lifecycle_state),
        first_seen=asset.first_seen,
        last_seen=asset.last_seen,
        primary_owner=owner,
        top_technologies=technologies[:5],
    )


def _owner_summary(claim: AssetOwnership) -> OwnerSummary:
    return OwnerSummary(
        id=claim.id,
        owner_type=claim.owner_type,
        owner_reference=claim.owner_reference,
        owner_display_name=claim.owner_display_name,
        claim_type=claim.claim_type,
        confidence=claim.confidence,
    )


def _technology_summary(fingerprint: TechnologyFingerprint) -> TechnologySummary:
    return TechnologySummary(
        id=fingerprint.id,
        product=fingerprint.technology_product,
        category=fingerprint.technology_category,
        version_value=fingerprint.version_value,
        confidence=fingerprint.confidence,
        rule_id=fingerprint.rule_id,
        rule_version=fingerprint.rule_version,
    )


def _observation_response(observation: CanonicalObservation) -> ObservationResponse:
    return ObservationResponse(
        id=observation.id,
        observation_type=observation.observation_type,
        source_type=observation.source_type,
        source_key=observation.source_key,
        observed_at=observation.observed_at,
        collected_at=observation.collected_at,
        confidence=observation.confidence,
        state=observation.state,
        payload_hash=observation.normalized_payload_hash,
    )


def _subtype_data(
    session: Session,
    context: OrganizationContext,
    asset: Asset,
) -> dict[str, object] | None:
    subtype: DomainAsset | IpAsset | AsnAsset | EndpointAsset | ServiceAsset | None
    if asset.asset_type == "DOMAIN":
        subtype = session.scalar(
            select(DomainAsset).where(
                DomainAsset.asset_id == asset.id,
                DomainAsset.organization_id == context.organization_id,
            )
        )
    elif asset.asset_type == "IP":
        subtype = session.scalar(
            select(IpAsset).where(
                IpAsset.asset_id == asset.id,
                IpAsset.organization_id == context.organization_id,
            )
        )
    elif asset.asset_type == "ASN":
        subtype = session.scalar(
            select(AsnAsset).where(
                AsnAsset.asset_id == asset.id,
                AsnAsset.organization_id == context.organization_id,
            )
        )
    elif asset.asset_type == "ENDPOINT":
        subtype = session.scalar(
            select(EndpointAsset).where(
                EndpointAsset.asset_id == asset.id,
                EndpointAsset.organization_id == context.organization_id,
            )
        )
    elif asset.asset_type == "SERVICE":
        subtype = session.scalar(
            select(ServiceAsset).where(
                ServiceAsset.asset_id == asset.id,
                ServiceAsset.organization_id == context.organization_id,
            )
        )
    else:
        return None
    if subtype is None:
        return None
    return {
        column.name: getattr(subtype, column.name)
        for column in subtype.__table__.columns
        if column.name not in {"organization_id"}
    }


def _direct_relationships(
    session: Session,
    context: OrganizationContext,
    asset: Asset,
) -> list[RelationshipResponse]:
    if asset.asset_type == "DOMAIN":
        return _domain_relationships(session, context, asset)
    if asset.asset_type == "IP":
        endpoints = session.scalars(
            select(EndpointAsset).where(
                EndpointAsset.organization_id == context.organization_id,
                EndpointAsset.ip_asset_id == asset.id,
            )
        )
        return [
            RelationshipResponse(
                relationship_type="HAS_ENDPOINT",
                target_asset_id=item.asset_id,
                source_observation_id=None,
                observed_at=None,
            )
            for item in endpoints
        ]
    if asset.asset_type == "ENDPOINT":
        endpoint = session.scalar(
            select(EndpointAsset).where(
                EndpointAsset.organization_id == context.organization_id,
                EndpointAsset.asset_id == asset.id,
            )
        )
        if endpoint is None:
            return []
        services = session.scalars(
            select(ServiceAsset).where(
                ServiceAsset.organization_id == context.organization_id,
                ServiceAsset.endpoint_asset_id == asset.id,
            )
        )
        return [
            RelationshipResponse(
                relationship_type="ON_IP",
                target_asset_id=endpoint.ip_asset_id,
                source_observation_id=None,
                observed_at=None,
            ),
            *[
                RelationshipResponse(
                    relationship_type="EXPOSES_SERVICE",
                    target_asset_id=service.asset_id,
                    source_observation_id=None,
                    observed_at=None,
                )
                for service in services
            ],
        ]
    if asset.asset_type == "SERVICE":
        service = session.scalar(
            select(ServiceAsset).where(
                ServiceAsset.organization_id == context.organization_id,
                ServiceAsset.asset_id == asset.id,
            )
        )
        if service is None:
            return []
        relationships = [
            RelationshipResponse(
                relationship_type="ON_ENDPOINT",
                target_asset_id=service.endpoint_asset_id,
                source_observation_id=None,
                observed_at=None,
            )
        ]
        if service.authority_domain_asset_id is not None:
            relationships.append(
                RelationshipResponse(
                    relationship_type="SERVED_FOR",
                    target_asset_id=service.authority_domain_asset_id,
                    source_observation_id=None,
                    observed_at=None,
                )
            )
        return relationships
    return []


def _domain_relationships(
    session: Session,
    context: OrganizationContext,
    asset: Asset,
) -> list[RelationshipResponse]:
    observations = session.scalars(
        select(CanonicalObservation)
        .where(
            CanonicalObservation.organization_id == context.organization_id,
            CanonicalObservation.asset_id == asset.id,
            CanonicalObservation.observation_type.in_(["DNS_A", "DNS_AAAA"]),
        )
        .order_by(CanonicalObservation.observed_at.desc(), CanonicalObservation.id.asc())
    )
    results: dict[uuid.UUID, RelationshipResponse] = {}
    for observation in observations:
        for address in _ip_values(observation.normalized_payload_json):
            ip_asset_id = session.scalar(
                select(IpAsset.asset_id).where(
                    IpAsset.organization_id == context.organization_id,
                    IpAsset.address == address,
                )
            )
            if ip_asset_id is not None and ip_asset_id not in results:
                results[ip_asset_id] = RelationshipResponse(
                    relationship_type="RESOLVES_TO",
                    target_asset_id=ip_asset_id,
                    source_observation_id=observation.id,
                    observed_at=observation.observed_at,
                )
    return list(results.values())


def _ip_values(value: object) -> Iterable[str]:
    if isinstance(value, Mapping):
        for child in value.values():
            yield from _ip_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _ip_values(child)
    elif isinstance(value, str):
        try:
            yield str(ipaddress.ip_address(value))
        except ValueError:
            return


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _audit(
    session: Session,
    context: OrganizationContext,
    principal: Principal,
    request: Request,
    action: str,
    resource_id: uuid.UUID | None = None,
) -> None:
    write_audit_event(
        session,
        context,
        principal,
        action=action,
        resource_type="asset",
        resource_id=str(resource_id) if resource_id is not None else None,
        correlation_id=request.state.correlation_id,
        result="SUCCESS",
    )
    session.commit()
