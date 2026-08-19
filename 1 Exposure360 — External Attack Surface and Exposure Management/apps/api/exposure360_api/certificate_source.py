"""Recorded certificate metadata import for passive Phase 3 candidate staging."""

from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID

from pydantic import Field, field_validator

from .discovery_contracts import (
    CandidateAssetContract,
    CandidateType,
    DiscoveryCheckpointContract,
    DiscoveryContractModel,
    DiscoverySourceContract,
    DiscoverySourceType,
    DiscoveryStageName,
    SourceBatch,
    SourceHealthState,
    SourceRecordContract,
)
from .discovery_sources import (
    AdapterCapabilities,
    NormalizedSourceRecord,
    ScopeSourceContext,
    parse_utc_timestamp,
    payload_hash,
)
from .scope_governance import ScopeTargetNormalizer, ScopeValidationError


class CertificateMetadataRecord(DiscoveryContractModel):
    source_record_id: str = Field(min_length=1, max_length=512)
    subject_cn: str | None = Field(default=None, max_length=253)
    dns_names: list[str] = Field(default_factory=list, max_length=100)
    issuer: str | None = Field(default=None, max_length=512)
    serial: str | None = Field(default=None, max_length=512)
    fingerprint_sha256: str | None = Field(default=None, max_length=128)
    not_before: datetime
    not_after: datetime
    observed_at: datetime
    source: str = Field(min_length=1, max_length=128)
    payload_hash: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")

    @field_validator("not_before", "not_after", "observed_at")
    @classmethod
    def require_timezone_aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Certificate timestamps must be timezone-aware")
        return value


class RecordedCertificateMetadataAdapter:
    source_key = "fixture-certificate-metadata"
    adapter_version = "1.0.0"
    source_type = DiscoverySourceType.CERTIFICATE_METADATA_IMPORT

    def __init__(
        self,
        records: list[dict[str, object]],
        *,
        page_size: int = 2,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if page_size < 1 or page_size > 1000:
            raise ValueError("page_size must be between 1 and 1000")
        self._records = records
        self._page_size = page_size
        self._clock = clock or (lambda: datetime.now(UTC))

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(
            candidate_types=(CandidateType.DOMAIN,),
            supports_checkpoint=True,
            supports_recorded_fixture=True,
        )

    def health(self) -> SourceHealthState:
        return SourceHealthState.HEALTHY

    def describe(self, organization_id: UUID) -> DiscoverySourceContract:
        return DiscoverySourceContract(
            organization_id=organization_id,
            source_key=self.source_key,
            source_type=self.source_type,
            display_name="Recorded Certificate Metadata",
            adapter_version=self.adapter_version,
        )

    def collect(
        self,
        context: ScopeSourceContext,
        checkpoint: DiscoveryCheckpointContract | None,
    ) -> SourceBatch:
        del context
        start = self._checkpoint_index(checkpoint)
        end = min(start + self._page_size, len(self._records))
        source_records = [
            self._source_record(index, payload)
            for index, payload in enumerate(self._records[start:end], start)
        ]
        next_checkpoint = None
        if end < len(self._records):
            next_checkpoint = DiscoveryCheckpointContract(
                source_key=self.source_key,
                adapter_version=self.adapter_version,
                stage=DiscoveryStageName.CERTIFICATE_IMPORT,
                token={"record_index": end},
            )
        return SourceBatch(
            records=source_records,
            next_checkpoint=next_checkpoint,
            retrieved_at=self._clock(),
        )

    def normalize(
        self,
        context: ScopeSourceContext,
        record: SourceRecordContract,
    ) -> NormalizedSourceRecord:
        certificate_payload = dict(record.attributes)
        certificate_payload.pop("certificate_id", None)
        certificate_payload.update(
            {
                "source_record_id": record.source_record_key,
                "payload_hash": record.payload_hash,
                "source": self.source_key,
            }
        )
        try:
            certificate = CertificateMetadataRecord.model_validate(certificate_payload)
        except ValueError:
            return NormalizedSourceRecord((), ("MALFORMED_CERTIFICATE_METADATA",))

        candidates: list[CandidateAssetContract] = []
        warnings: list[str] = []
        names = [*certificate.dns_names]
        if certificate.subject_cn and certificate.subject_cn not in names:
            names.append(certificate.subject_cn)
        for raw_name in names:
            candidate_raw_name = raw_name
            wildcard = raw_name.startswith("*.")
            if wildcard:
                candidate_raw_name = raw_name[2:]
            try:
                normalized = ScopeTargetNormalizer.normalize_domain(candidate_raw_name)
            except ScopeValidationError:
                warnings.append("INVALID_CERTIFICATE_DNS_NAME")
                continue
            if not context.allows_domain(normalized.canonical_value):
                warnings.append("OUT_OF_SCOPE_CERTIFICATE_DNS_NAME")
                continue
            metadata: dict[str, object] = {
                "evidence_category": "certificate_metadata",
                "certificate_record_id": certificate.source_record_id,
                "issuer": certificate.issuer,
                "not_before": certificate.not_before.isoformat(),
                "not_after": certificate.not_after.isoformat(),
                "wildcard_hint": wildcard,
            }
            candidates.append(
                CandidateAssetContract(
                    organization_id=context.organization_id,
                    scope_id=context.scope_id,
                    scope_version_id=context.scope_version_id,
                    scope_approval_id=context.scope_approval_id,
                    candidate_type=CandidateType.DOMAIN,
                    raw_value=candidate_raw_name,
                    canonical_value=normalized.canonical_value,
                    source_key=self.source_key,
                    source_record_key=certificate.source_record_id,
                    observed_at=certificate.observed_at,
                    confidence_hint=0.65,
                    metadata=metadata,
                )
            )
        return NormalizedSourceRecord(tuple(candidates), tuple(sorted(set(warnings))))

    def _checkpoint_index(self, checkpoint: DiscoveryCheckpointContract | None) -> int:
        if checkpoint is None:
            return 0
        if (
            checkpoint.source_key != self.source_key
            or checkpoint.stage is not DiscoveryStageName.CERTIFICATE_IMPORT
        ):
            raise ValueError("Checkpoint does not belong to recorded certificate metadata source")
        value = checkpoint.token.get("record_index")
        if not isinstance(value, int) or value < 0 or value > len(self._records):
            raise ValueError("Checkpoint record_index is invalid")
        return value

    def _source_record(self, index: int, record: dict[str, object]) -> SourceRecordContract:
        observed_at = parse_utc_timestamp(record.get("observed_at"))
        record_key = record.get("certificate_id")
        if not isinstance(record_key, str) or not record_key:
            record_key = f"certificate-{index}"
        return SourceRecordContract(
            source_record_key=record_key,
            payload_hash=payload_hash(record),
            observed_at=observed_at,
            attributes=dict(record),
        )
