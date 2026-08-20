import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .audit import write_audit_event
from .models import Asset, AssetOwnership, Evidence, OwnershipEvidenceLink
from .security import OrganizationContext, Principal, require_role

_CLAIM_PRECEDENCE = {"MANUAL": 3, "SOURCE_ASSERTED": 2, "INFERRED": 1}
_SOURCE_PRECEDENCE = {"MANUAL": 3, "CMDB": 2, "AUTHORITATIVE_SOURCE": 2, "INFERENCE": 1}


class OwnershipError(ValueError):
    """Raised when an ownership claim, link, or organization scope is invalid."""


@dataclass(frozen=True)
class OwnershipResolution:
    ownership: AssetOwnership | None
    conflict: bool
    conflict_code: str | None


class OwnershipService:
    """Preserves competing ownership claims and chooses a primary result deterministically."""

    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))

    def record_claim(
        self,
        session: Session,
        *,
        asset: Asset,
        owner_type: str,
        owner_reference: str,
        owner_display_name: str | None,
        claim_type: str,
        confidence: float,
        source_type: str,
        valid_from: datetime,
        valid_to: datetime | None = None,
        reason: str | None = None,
        created_by_user_id: UUID | None = None,
    ) -> AssetOwnership:
        if not 0 <= confidence <= 1:
            raise OwnershipError("ownership confidence must be between zero and one")
        effective_from = self._require_aware_utc(valid_from)
        effective_to = None if valid_to is None else self._require_aware_utc(valid_to)
        if effective_to is not None and effective_to <= effective_from:
            raise OwnershipError("ownership valid_to must be after valid_from")
        claim_key = self._claim_key(
            asset.id,
            owner_type,
            owner_reference,
            claim_type,
            source_type,
            effective_from,
        )
        existing = session.scalar(
            select(AssetOwnership).where(
                AssetOwnership.organization_id == asset.organization_id,
                AssetOwnership.asset_id == asset.id,
                AssetOwnership.claim_key == claim_key,
            )
        )
        if existing is not None:
            return existing
        claim = AssetOwnership(
            organization_id=asset.organization_id,
            asset_id=asset.id,
            owner_type=owner_type,
            owner_reference=owner_reference,
            owner_display_name=owner_display_name,
            claim_type=claim_type,
            confidence=confidence,
            source_type=source_type,
            claim_key=claim_key,
            valid_from=effective_from,
            valid_to=effective_to,
            reason=reason,
            created_by_user_id=created_by_user_id,
        )
        try:
            with session.begin_nested():
                session.add(claim)
                session.flush()
        except IntegrityError:
            existing = session.scalar(
                select(AssetOwnership).where(
                    AssetOwnership.organization_id == asset.organization_id,
                    AssetOwnership.asset_id == asset.id,
                    AssetOwnership.claim_key == claim_key,
                )
            )
            if existing is None:
                raise
            return existing
        return claim

    def link_evidence(
        self,
        session: Session,
        *,
        ownership: AssetOwnership,
        evidence: Evidence,
        relationship_type: str,
    ) -> OwnershipEvidenceLink:
        if ownership.organization_id != evidence.organization_id:
            raise OwnershipError("ownership evidence belongs to another organization")
        if ownership.asset_id != evidence.asset_id:
            raise OwnershipError("ownership evidence must reference the same asset")
        existing = session.scalar(
            select(OwnershipEvidenceLink).where(
                OwnershipEvidenceLink.ownership_id == ownership.id,
                OwnershipEvidenceLink.evidence_id == evidence.id,
                OwnershipEvidenceLink.relationship_type == relationship_type,
            )
        )
        if existing is not None:
            return existing
        link = OwnershipEvidenceLink(
            organization_id=ownership.organization_id,
            ownership_id=ownership.id,
            evidence_id=evidence.id,
            observation_id=evidence.observation_id,
            relationship_type=relationship_type,
        )
        session.add(link)
        return link

    def resolve(self, session: Session, asset: Asset) -> OwnershipResolution:
        now = self._require_aware_utc(self._clock())
        claims = list(
            session.scalars(
                select(AssetOwnership).where(
                    AssetOwnership.organization_id == asset.organization_id,
                    AssetOwnership.asset_id == asset.id,
                    AssetOwnership.valid_from <= now,
                    (AssetOwnership.valid_to.is_(None)) | (AssetOwnership.valid_to > now),
                )
            )
        )
        for claim in claims:
            claim.is_primary = False
        ordered = sorted(claims, key=self._sort_key, reverse=True)
        if not ordered:
            return OwnershipResolution(None, False, None)
        winner = ordered[0]
        if len(ordered) > 1 and self._is_conflict(winner, ordered[1]):
            return OwnershipResolution(None, True, "OWNERSHIP_CONFLICT")
        winner.is_primary = True
        return OwnershipResolution(winner, False, None)

    def assign_manual(
        self,
        session: Session,
        *,
        context: OrganizationContext,
        principal: Principal,
        asset: Asset,
        owner_type: str,
        owner_reference: str,
        owner_display_name: str | None,
        reason: str,
        correlation_id: str,
    ) -> AssetOwnership:
        require_role(context, "admin", "owner")
        if asset.organization_id != context.organization_id:
            raise OwnershipError("asset does not belong to the organization")
        claim = self.record_claim(
            session,
            asset=asset,
            owner_type=owner_type,
            owner_reference=owner_reference,
            owner_display_name=owner_display_name,
            claim_type="MANUAL",
            confidence=1.0,
            source_type="MANUAL",
            valid_from=self._require_aware_utc(self._clock()),
            reason=reason,
            created_by_user_id=principal.user.id,
        )
        self.resolve(session, asset)
        write_audit_event(
            session,
            context,
            principal,
            action="asset.ownership_manual_assigned",
            resource_type="asset_ownership",
            resource_id=str(claim.id),
            correlation_id=correlation_id,
            result="SUCCESS",
            metadata={"asset_id": str(asset.id), "owner_type": owner_type},
        )
        return claim

    @staticmethod
    def _sort_key(claim: AssetOwnership) -> tuple[int, float, int, datetime, str]:
        return (
            _CLAIM_PRECEDENCE[claim.claim_type],
            claim.confidence,
            _SOURCE_PRECEDENCE.get(claim.source_type, 0),
            OwnershipService._database_utc(claim.valid_from),
            str(claim.id),
        )

    @staticmethod
    def _is_conflict(first: AssetOwnership, second: AssetOwnership) -> bool:
        return (
            first.owner_reference != second.owner_reference
            and first.claim_type == second.claim_type
            and abs(first.confidence - second.confidence) <= 0.05
        )

    @staticmethod
    def _claim_key(*parts: object) -> str:
        serialized = [
            part.isoformat() if isinstance(part, datetime) else str(part) for part in parts
        ]
        encoded = json.dumps(
            serialized,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _require_aware_utc(value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise OwnershipError("ownership timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @staticmethod
    def _database_utc(value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
