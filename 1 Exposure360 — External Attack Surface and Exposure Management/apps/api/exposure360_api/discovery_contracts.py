"""Versioned contracts shared by Phase 3 discovery adapters and services."""

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CandidateType(StrEnum):
    DOMAIN = "DOMAIN"
    IP = "IP"
    ENDPOINT_HINT = "ENDPOINT_HINT"


class DiscoverySourceType(StrEnum):
    RECORDED_PASSIVE_DNS = "RECORDED_PASSIVE_DNS"
    CERTIFICATE_METADATA_IMPORT = "CERTIFICATE_METADATA_IMPORT"
    PASSIVE_DNS_PROVIDER = "PASSIVE_DNS_PROVIDER"


class SourceHealthState(StrEnum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"
    MISCONFIGURED = "MISCONFIGURED"


class SourceErrorClass(StrEnum):
    TRANSIENT = "TRANSIENT"
    RATE_LIMITED = "RATE_LIMITED"
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    INVALID_RESPONSE = "INVALID_RESPONSE"
    PERMANENT = "PERMANENT"
    PARTIAL = "PARTIAL"


class DiscoveryStageName(StrEnum):
    PASSIVE_SOURCE = "PASSIVE_SOURCE"
    CERTIFICATE_IMPORT = "CERTIFICATE_IMPORT"
    CANDIDATE_RECONCILIATION = "CANDIDATE_RECONCILIATION"
    DNS_VALIDATE = "DNS_VALIDATE"
    TCP_VALIDATE = "TCP_VALIDATE"
    TLS_METADATA = "TLS_METADATA"
    HTTP_METADATA = "HTTP_METADATA"
    FINALIZE = "FINALIZE"


class CollectionResultCode(StrEnum):
    SUCCESS = "SUCCESS"
    NOT_PRESENT = "NOT_PRESENT"
    DENIED = "DENIED"
    TIMEOUT = "TIMEOUT"
    TRANSIENT_ERROR = "TRANSIENT_ERROR"
    PERMANENT_ERROR = "PERMANENT_ERROR"
    PARTIAL = "PARTIAL"
    CANCELLED = "CANCELLED"


class DiscoveryContractModel(BaseModel):
    """Forbid unclassified provider payload fields from crossing the domain boundary."""

    model_config = ConfigDict(extra="forbid")


class DiscoverySourceContract(DiscoveryContractModel):
    source_contract_version: str = Field(default="discovery-source-v1", min_length=1, max_length=64)
    organization_id: UUID
    source_key: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    source_type: DiscoverySourceType
    display_name: str = Field(min_length=1, max_length=255)
    adapter_version: str = Field(min_length=1, max_length=64)
    enabled: bool = True
    configuration_reference: str | None = Field(default=None, max_length=255)


class CandidateAssetContract(DiscoveryContractModel):
    candidate_contract_version: str = Field(default="candidate-v1", min_length=1, max_length=64)
    organization_id: UUID
    scope_id: UUID
    scope_version_id: UUID
    scope_approval_id: UUID
    candidate_type: CandidateType
    raw_value: str = Field(min_length=1, max_length=2048)
    canonical_value: str = Field(min_length=1, max_length=2048)
    source_key: str = Field(min_length=1, max_length=128)
    source_record_key: str | None = Field(default=None, max_length=512)
    observed_at: datetime
    confidence_hint: float | None = Field(default=None, ge=0, le=1)
    metadata: dict[str, object] = Field(default_factory=dict)

    @field_validator("observed_at")
    @classmethod
    def require_timezone_aware_observed_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must be timezone-aware")
        return value


class SourceRecordContract(DiscoveryContractModel):
    source_record_key: str = Field(min_length=1, max_length=512)
    payload_hash: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    observed_at: datetime
    attributes: dict[str, object] = Field(default_factory=dict)

    @field_validator("observed_at")
    @classmethod
    def require_timezone_aware_observed_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must be timezone-aware")
        return value


class DiscoveryCheckpointContract(DiscoveryContractModel):
    checkpoint_schema_version: str = Field(default="checkpoint-v1", min_length=1, max_length=64)
    source_key: str = Field(min_length=1, max_length=128)
    adapter_version: str = Field(min_length=1, max_length=64)
    stage: DiscoveryStageName
    token: dict[str, object] = Field(default_factory=dict)


class SourceBatch(DiscoveryContractModel):
    records: list[SourceRecordContract] = Field(default_factory=list, max_length=1000)
    next_checkpoint: DiscoveryCheckpointContract | None = None
    source_observed_at: datetime | None = None
    retrieved_at: datetime
    partial: bool = False
    warnings: list[str] = Field(default_factory=list, max_length=100)
    rate_limit_state: dict[str, object] = Field(default_factory=dict)

    @field_validator("source_observed_at", "retrieved_at")
    @classmethod
    def require_timezone_aware_timestamps(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return value
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("batch timestamps must be timezone-aware")
        return value


class SourceErrorContract(DiscoveryContractModel):
    error_class: SourceErrorClass
    reason_code: str = Field(min_length=1, max_length=128)
    safe_message: str = Field(min_length=1, max_length=512)
    retry_after_seconds: int | None = Field(default=None, ge=0, le=3600)
