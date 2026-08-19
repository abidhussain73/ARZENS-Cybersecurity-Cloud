"""Provider-neutral, fixture-backed passive discovery source contracts."""

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID

from .discovery_contracts import (
    CandidateAssetContract,
    CandidateType,
    DiscoveryCheckpointContract,
    DiscoverySourceContract,
    DiscoverySourceType,
    DiscoveryStageName,
    SourceBatch,
    SourceHealthState,
    SourceRecordContract,
)
from .scope_governance import (
    ScopeTargetNormalizer,
    ScopeValidationError,
    TargetRule,
    target_matches,
)


def payload_hash(payload: dict[str, object]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def parse_utc_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("Source timestamp must be an ISO-8601 string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Source timestamp must include an offset")
    return parsed.astimezone(UTC)


@dataclass(frozen=True)
class ScopeSourceContext:
    organization_id: UUID
    scope_id: UUID
    scope_version_id: UUID
    scope_approval_id: UUID
    included_rules: tuple[TargetRule, ...]
    exclusion_rules: tuple[TargetRule, ...]

    def allows_domain(self, canonical_value: str) -> bool:
        is_included = any(
            target_matches(rule, "DOMAIN", canonical_value) for rule in self.included_rules
        )
        is_excluded = any(
            target_matches(rule, "DOMAIN", canonical_value) for rule in self.exclusion_rules
        )
        return is_included and not is_excluded


@dataclass(frozen=True)
class AdapterCapabilities:
    candidate_types: tuple[CandidateType, ...]
    supports_checkpoint: bool
    supports_recorded_fixture: bool


@dataclass(frozen=True)
class NormalizedSourceRecord:
    candidates: tuple[CandidateAssetContract, ...]
    warnings: tuple[str, ...]


class DiscoverySourceAdapter(Protocol):
    source_key: str
    adapter_version: str
    source_type: DiscoverySourceType

    def capabilities(self) -> AdapterCapabilities: ...

    def health(self) -> SourceHealthState: ...

    def describe(self, organization_id: UUID) -> DiscoverySourceContract: ...

    def collect(
        self,
        context: ScopeSourceContext,
        checkpoint: DiscoveryCheckpointContract | None,
    ) -> SourceBatch: ...

    def normalize(
        self,
        context: ScopeSourceContext,
        record: SourceRecordContract,
    ) -> NormalizedSourceRecord: ...


class RecordedPassiveDnsAdapter:
    """Deterministic passive-DNS adapter used by CI and offline acceptance."""

    source_key = "fixture-passive-dns"
    adapter_version = "1.0.0"
    source_type = DiscoverySourceType.RECORDED_PASSIVE_DNS

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
            candidate_types=(CandidateType.DOMAIN, CandidateType.IP),
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
            display_name="Recorded Passive DNS",
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
                stage=DiscoveryStageName.PASSIVE_SOURCE,
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
        rrname = record.attributes.get("rrname")
        rrtype = record.attributes.get("rrtype")
        rdata = record.attributes.get("rdata")
        if not isinstance(rrname, str) or not isinstance(rrtype, str) or not isinstance(rdata, str):
            return NormalizedSourceRecord((), ("MALFORMED_PASSIVE_DNS_RECORD",))
        if rrtype not in {"A", "AAAA"}:
            return NormalizedSourceRecord((), ("UNSUPPORTED_PASSIVE_RRTYPE",))
        try:
            domain = ScopeTargetNormalizer.normalize_domain(rrname)
            address = ScopeTargetNormalizer.normalize_ip(rdata)
        except ScopeValidationError:
            return NormalizedSourceRecord((), ("INVALID_PASSIVE_DNS_TARGET",))
        if not context.allows_domain(domain.canonical_value):
            return NormalizedSourceRecord((), ("OUT_OF_SCOPE_PASSIVE_DNS_RECORD",))

        domain_candidate = CandidateAssetContract(
            organization_id=context.organization_id,
            scope_id=context.scope_id,
            scope_version_id=context.scope_version_id,
            scope_approval_id=context.scope_approval_id,
            candidate_type=CandidateType.DOMAIN,
            raw_value=rrname,
            canonical_value=domain.canonical_value,
            source_key=self.source_key,
            source_record_key=record.source_record_key,
            observed_at=record.observed_at,
            confidence_hint=0.60,
            metadata={"evidence_category": "passive_dns", "rrtype": rrtype},
        )
        ip_candidate = CandidateAssetContract(
            organization_id=context.organization_id,
            scope_id=context.scope_id,
            scope_version_id=context.scope_version_id,
            scope_approval_id=context.scope_approval_id,
            candidate_type=CandidateType.IP,
            raw_value=rdata,
            canonical_value=address.canonical_value,
            source_key=self.source_key,
            source_record_key=record.source_record_key,
            observed_at=record.observed_at,
            confidence_hint=0.60,
            metadata={
                "evidence_category": "passive_dns",
                "relationship_hint": "resolves_to",
                "derived_from_canonical": domain.canonical_value,
                "rrtype": rrtype,
            },
        )
        return NormalizedSourceRecord((domain_candidate, ip_candidate), ())

    def _checkpoint_index(self, checkpoint: DiscoveryCheckpointContract | None) -> int:
        if checkpoint is None:
            return 0
        if (
            checkpoint.source_key != self.source_key
            or checkpoint.stage is not DiscoveryStageName.PASSIVE_SOURCE
        ):
            raise ValueError("Checkpoint does not belong to recorded passive DNS source")
        value = checkpoint.token.get("record_index")
        if not isinstance(value, int) or value < 0 or value > len(self._records):
            raise ValueError("Checkpoint record_index is invalid")
        return value

    def _source_record(self, index: int, record: dict[str, object]) -> SourceRecordContract:
        observed_at = parse_utc_timestamp(record.get("last_seen"))
        return SourceRecordContract(
            source_record_key=str(record.get("id", f"passive-{index}")),
            payload_hash=payload_hash(record),
            observed_at=observed_at,
            attributes=dict(record),
        )
