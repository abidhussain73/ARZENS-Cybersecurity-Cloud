import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .models import Asset, CanonicalObservation, Evidence

_SENSITIVE_HEADER_NAMES = {"authorization", "cookie", "set-cookie"}


class EvidenceRecordError(ValueError):
    """Raised when evidence or observation provenance is invalid."""


@dataclass(frozen=True)
class ObservationRecordResult:
    observation: CanonicalObservation
    created: bool


@dataclass(frozen=True)
class EvidenceRecordResult:
    evidence: Evidence
    created: bool


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class EvidenceRecordService:
    """Creates safe, idempotent, immutable canonical fact records."""

    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))

    def record_observation(
        self,
        session: Session,
        *,
        organization_id: UUID,
        asset: Asset,
        observation_type: str,
        source_type: str,
        source_key: str,
        source_record_key: str | None,
        source_version: str | None,
        observed_at: datetime,
        collected_at: datetime,
        payload: dict[str, object],
        confidence: float | None = None,
    ) -> ObservationRecordResult:
        self._require_same_organization(organization_id, asset.organization_id, "asset")
        observed = self._require_aware(observed_at, "observed_at")
        collected = self._require_aware(collected_at, "collected_at")
        normalized_payload = self._sanitize(payload)
        payload_hash = sha256_hex(canonical_json_bytes(normalized_payload))
        record_key = source_record_key or ""
        idempotency_key = self._idempotency_hash(
            organization_id,
            asset.id,
            observation_type,
            source_key,
            record_key,
            observed,
            payload_hash,
        )
        existing = session.scalar(
            select(CanonicalObservation).where(
                CanonicalObservation.organization_id == organization_id,
                CanonicalObservation.idempotency_key == idempotency_key,
            )
        )
        if existing is not None:
            return ObservationRecordResult(existing, False)
        observation = CanonicalObservation(
            organization_id=organization_id,
            asset_id=asset.id,
            observation_type=observation_type,
            source_type=source_type,
            source_key=source_key,
            source_record_key=record_key,
            source_version=source_version,
            observed_at=observed,
            collected_at=collected,
            normalized_payload_json=normalized_payload,
            normalized_payload_hash=payload_hash,
            idempotency_key=idempotency_key,
            confidence=confidence,
        )
        try:
            with session.begin_nested():
                session.add(observation)
                session.flush()
        except IntegrityError:
            existing = session.scalar(
                select(CanonicalObservation).where(
                    CanonicalObservation.organization_id == organization_id,
                    CanonicalObservation.idempotency_key == idempotency_key,
                )
            )
            if existing is None:
                raise
            return ObservationRecordResult(existing, False)
        return ObservationRecordResult(observation, True)

    def record_metadata_evidence(
        self,
        session: Session,
        *,
        organization_id: UUID,
        asset: Asset,
        observation: CanonicalObservation | None,
        evidence_type: str,
        metadata: dict[str, object],
        source_observed_at: datetime | None,
        collected_at: datetime,
        collector_name: str,
        collector_version: str,
        sensitivity_class: str = "INTERNAL_METADATA",
    ) -> EvidenceRecordResult:
        self._require_same_organization(organization_id, asset.organization_id, "asset")
        if observation is not None:
            self._require_same_organization(
                organization_id,
                observation.organization_id,
                "observation",
            )
            if observation.asset_id != asset.id:
                raise EvidenceRecordError("evidence observation must reference the same asset")
        source_observed = (
            None
            if source_observed_at is None
            else self._require_aware(source_observed_at, "source_observed_at")
        )
        collected = self._require_aware(collected_at, "collected_at")
        safe_metadata = self._sanitize(metadata)
        encoded = canonical_json_bytes(safe_metadata)
        digest = sha256_hex(encoded)
        idempotency_key = self._idempotency_hash(
            organization_id,
            asset.id,
            evidence_type,
            collector_name,
            collector_version,
            collected,
            digest,
        )
        existing = session.scalar(
            select(Evidence).where(
                Evidence.organization_id == organization_id,
                Evidence.idempotency_key == idempotency_key,
            )
        )
        if existing is not None:
            return EvidenceRecordResult(existing, False)
        evidence = Evidence(
            organization_id=organization_id,
            observation_id=None if observation is None else observation.id,
            asset_id=asset.id,
            evidence_type=evidence_type,
            object_store_bucket="metadata-only",
            object_store_key=None,
            sha256=digest,
            size_bytes=len(encoded),
            media_type="application/json",
            encoding="utf-8",
            source_observed_at=source_observed,
            collected_at=collected,
            stored_at=self._as_utc(self._clock()),
            retention_class="STANDARD",
            sensitivity_class=sensitivity_class,
            collector_name=collector_name,
            collector_version=collector_version,
            metadata_json=safe_metadata,
            idempotency_key=idempotency_key,
        )
        try:
            with session.begin_nested():
                session.add(evidence)
                session.flush()
        except IntegrityError:
            existing = session.scalar(
                select(Evidence).where(
                    Evidence.organization_id == organization_id,
                    Evidence.idempotency_key == idempotency_key,
                )
            )
            if existing is None:
                raise
            return EvidenceRecordResult(existing, False)
        return EvidenceRecordResult(evidence, True)

    @staticmethod
    def _sanitize(value: object) -> dict[str, object]:
        sanitized = EvidenceRecordService._sanitize_value(value)
        if not isinstance(sanitized, dict):
            raise EvidenceRecordError("evidence payload must remain an object")
        return sanitized

    @staticmethod
    def _sanitize_value(value: object) -> object:
        if isinstance(value, dict):
            return {
                str(key): EvidenceRecordService._sanitize_value(item)
                for key, item in value.items()
                if str(key).lower() not in _SENSITIVE_HEADER_NAMES
            }
        if isinstance(value, list):
            return [EvidenceRecordService._sanitize_value(item) for item in value]
        if isinstance(value, str | int | float | bool) or value is None:
            return value
        raise EvidenceRecordError("evidence payload contains unsupported value type")

    @staticmethod
    def _idempotency_hash(*parts: object) -> str:
        normalized = [
            part.isoformat() if isinstance(part, datetime) else str(part) for part in parts
        ]
        return sha256_hex(canonical_json_bytes(normalized))

    @staticmethod
    def _require_same_organization(expected: UUID, actual: UUID, field_name: str) -> None:
        if expected != actual:
            raise EvidenceRecordError(f"{field_name} does not belong to the organization")

    @staticmethod
    def _require_aware(value: datetime, name: str) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise EvidenceRecordError(f"{name} must be timezone-aware")
        return EvidenceRecordService._as_utc(value)

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        return value.astimezone(UTC)
