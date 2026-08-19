"""Centralized candidate staging reconciliation and confidence computation."""

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .discovery_contracts import CandidateAssetContract
from .models import CandidateAsset, CandidateObservation, DiscoverySource

CONFIDENCE_MODEL_VERSION = "candidate-confidence-v1"
_EVIDENCE_WEIGHTS = {
    "passive_dns": 0.60,
    "certificate_metadata": 0.65,
    "dns_validation": 0.90,
    "tcp_reachability": 0.70,
}
_CONFIDENCE_CAP = 0.99


@dataclass(frozen=True)
class CandidateIngestionResult:
    candidate_id: UUID
    observation_created: bool
    confidence_score: float
    confidence_factors: tuple[dict[str, object], ...]


class CandidateReconciliationService:
    """Persist contracts safely; adapters never write staging ORM rows directly."""

    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))

    def ingest(
        self,
        session: Session,
        *,
        source: DiscoverySource,
        contracts: Iterable[CandidateAssetContract],
        payload_hash: str,
    ) -> list[CandidateIngestionResult]:
        results: list[CandidateIngestionResult] = []
        for contract in contracts:
            if contract.organization_id != source.organization_id:
                raise ValueError(
                    "Candidate contract organization does not match source organization"
                )
            candidate = self._get_or_create_candidate(session, contract)
            observation_created = self._get_or_create_observation(
                session,
                candidate=candidate,
                source=source,
                contract=contract,
                payload_hash=payload_hash,
            )
            factors, score = self._recompute_confidence(session, candidate)
            results.append(
                CandidateIngestionResult(
                    candidate_id=candidate.id,
                    observation_created=observation_created,
                    confidence_score=score,
                    confidence_factors=factors,
                )
            )
        return results

    def _get_or_create_candidate(
        self,
        session: Session,
        contract: CandidateAssetContract,
    ) -> CandidateAsset:
        candidate = session.scalar(
            select(CandidateAsset).where(
                CandidateAsset.organization_id == contract.organization_id,
                CandidateAsset.scope_version_id == contract.scope_version_id,
                CandidateAsset.candidate_type == contract.candidate_type.value,
                CandidateAsset.canonical_value == contract.canonical_value,
            )
        )
        if candidate is not None:
            candidate.last_discovered_at = max(
                self._as_utc(candidate.last_discovered_at), contract.observed_at
            )
            return candidate

        candidate = CandidateAsset(
            organization_id=contract.organization_id,
            scope_id=contract.scope_id,
            scope_version_id=contract.scope_version_id,
            scope_approval_id=contract.scope_approval_id,
            candidate_type=contract.candidate_type.value,
            raw_value=contract.raw_value,
            canonical_value=contract.canonical_value,
            first_discovered_at=contract.observed_at,
            last_discovered_at=contract.observed_at,
            confidence_model_version=CONFIDENCE_MODEL_VERSION,
            metadata_json={},
        )
        try:
            with session.begin_nested():
                session.add(candidate)
                session.flush()
        except IntegrityError:
            candidate = session.scalar(
                select(CandidateAsset).where(
                    CandidateAsset.organization_id == contract.organization_id,
                    CandidateAsset.scope_version_id == contract.scope_version_id,
                    CandidateAsset.candidate_type == contract.candidate_type.value,
                    CandidateAsset.canonical_value == contract.canonical_value,
                )
            )
            if candidate is None:
                raise
        return candidate

    def _get_or_create_observation(
        self,
        session: Session,
        *,
        candidate: CandidateAsset,
        source: DiscoverySource,
        contract: CandidateAssetContract,
        payload_hash: str,
    ) -> bool:
        record_key = contract.source_record_key or contract.canonical_value
        existing = session.scalar(
            select(CandidateObservation).where(
                CandidateObservation.candidate_id == candidate.id,
                CandidateObservation.source_id == source.id,
                CandidateObservation.source_record_key == record_key,
                CandidateObservation.payload_hash == payload_hash,
                CandidateObservation.observed_at == contract.observed_at,
            )
        )
        if existing is not None:
            return False
        observation = CandidateObservation(
            organization_id=contract.organization_id,
            candidate_id=candidate.id,
            source_id=source.id,
            source_record_key=record_key,
            observed_at=contract.observed_at,
            collected_at=self._clock(),
            payload_hash=payload_hash,
            normalized_metadata_json=contract.metadata,
        )
        try:
            with session.begin_nested():
                session.add(observation)
                session.flush()
        except IntegrityError:
            existing = session.scalar(
                select(CandidateObservation).where(
                    CandidateObservation.candidate_id == candidate.id,
                    CandidateObservation.source_id == source.id,
                    CandidateObservation.source_record_key == record_key,
                    CandidateObservation.payload_hash == payload_hash,
                    CandidateObservation.observed_at == contract.observed_at,
                )
            )
            if existing is None:
                raise
            return False
        return True

    def _recompute_confidence(
        self,
        session: Session,
        candidate: CandidateAsset,
    ) -> tuple[tuple[dict[str, object], ...], float]:
        observations = list(
            session.scalars(
                select(CandidateObservation).where(
                    CandidateObservation.candidate_id == candidate.id
                )
            )
        )
        category_weights: dict[str, float] = {}
        for observation in observations:
            category = observation.normalized_metadata_json.get("evidence_category")
            if not isinstance(category, str):
                continue
            weight = _EVIDENCE_WEIGHTS.get(category)
            if weight is not None:
                category_weights[category] = max(category_weights.get(category, 0.0), weight)
        factors = tuple(
            {"source": category, "weight": weight}
            for category, weight in sorted(category_weights.items())
        )
        score = min(
            _CONFIDENCE_CAP,
            1 - self._multiplicative_remainder(tuple(category_weights.values())),
        )
        candidate.confidence_model_version = CONFIDENCE_MODEL_VERSION
        candidate.confidence_score = score
        candidate.confidence_factors_json = list(factors)
        session.flush()
        return factors, score

    @staticmethod
    def _multiplicative_remainder(weights: tuple[float, ...]) -> float:
        remainder = 1.0
        for weight in weights:
            remainder *= 1 - weight
        return remainder

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
