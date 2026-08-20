import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from .audit import write_audit_event
from .auth import current_principal
from .config import get_settings
from .db import get_session
from .evidence_store import EvidenceObjectStore, get_evidence_store, safe_download_filename
from .models import Evidence
from .security import (
    OrganizationContext,
    Principal,
    organization_header,
    require_org_context,
    require_role,
)

router = APIRouter(prefix="/api/v1/evidence", tags=["evidence"])


class EvidenceMetadataResponse(BaseModel):
    id: uuid.UUID
    asset_id: uuid.UUID
    observation_id: uuid.UUID | None
    evidence_type: str
    sha256: str
    size_bytes: int
    media_type: str
    encoding: str | None
    source_observed_at: str | None
    collected_at: str
    stored_at: str
    retention_class: str
    sensitivity_class: str
    collector_name: str
    collector_version: str


class EvidenceDownloadResponse(BaseModel):
    method: str
    url: str
    expires_at: str
    filename: str


@router.get("/{evidence_id}", response_model=EvidenceMetadataResponse)
def get_evidence_metadata(
    evidence_id: uuid.UUID,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
) -> EvidenceMetadataResponse:
    context = require_org_context(session, principal, organization_id)
    require_role(context, "viewer", "reviewer", "analyst", "admin", "owner")
    evidence = _evidence_for_context(session, context, evidence_id)
    return _metadata_response(evidence)


@router.post("/{evidence_id}/download", response_model=EvidenceDownloadResponse)
def authorize_evidence_download(
    evidence_id: uuid.UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Principal, Depends(current_principal)],
    organization_id: Annotated[str | None, Depends(organization_header)],
    store: Annotated[EvidenceObjectStore, Depends(get_evidence_store)],
) -> EvidenceDownloadResponse:
    context = require_org_context(session, principal, organization_id)
    require_role(context, "viewer", "reviewer", "analyst", "admin", "owner")
    evidence = _evidence_for_context(session, context, evidence_id)
    if evidence.object_store_key is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "OBJECT_MISSING", "message": "Evidence has no stored object"},
        )
    if store.head(bucket=evidence.object_store_bucket, key=evidence.object_store_key) is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "OBJECT_MISSING", "message": "Evidence object is missing"},
        )
    filename = safe_download_filename(f"evidence-{evidence.id}-{evidence.evidence_type}.bin")
    reference = store.create_download_reference(
        bucket=evidence.object_store_bucket,
        key=evidence.object_store_key,
        filename=filename,
        ttl_seconds=get_settings().evidence_signed_url_ttl_seconds,
    )
    write_audit_event(
        session,
        context,
        principal,
        action="evidence.download_authorized",
        resource_type="evidence",
        resource_id=str(evidence.id),
        correlation_id=request.state.correlation_id,
        result="SUCCESS",
        metadata={"method": "presigned_url"},
    )
    session.commit()
    return EvidenceDownloadResponse(
        method="presigned_url",
        url=reference.url,
        expires_at=reference.expires_at.isoformat(),
        filename=filename,
    )


def _evidence_for_context(
    session: Session,
    context: OrganizationContext,
    evidence_id: uuid.UUID,
) -> Evidence:
    evidence = session.scalar(
        select(Evidence).where(
            Evidence.id == evidence_id,
            Evidence.organization_id == context.organization_id,
        )
    )
    if evidence is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "EVIDENCE_NOT_FOUND", "message": "Evidence was not found"},
        )
    return evidence


def _metadata_response(evidence: Evidence) -> EvidenceMetadataResponse:
    return EvidenceMetadataResponse(
        id=evidence.id,
        asset_id=evidence.asset_id,
        observation_id=evidence.observation_id,
        evidence_type=evidence.evidence_type,
        sha256=evidence.sha256,
        size_bytes=evidence.size_bytes,
        media_type=evidence.media_type,
        encoding=evidence.encoding,
        source_observed_at=(
            evidence.source_observed_at.isoformat()
            if evidence.source_observed_at is not None
            else None
        ),
        collected_at=evidence.collected_at.isoformat(),
        stored_at=evidence.stored_at.isoformat(),
        retention_class=evidence.retention_class,
        sensitivity_class=evidence.sensitivity_class,
        collector_name=evidence.collector_name,
        collector_version=evidence.collector_version,
    )
