"""Guard-first, bounded DNS validation for Phase 3 discovery staging."""

import hashlib
import ipaddress
import json
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol

from sqlalchemy.orm import Session

from .candidate_reconciliation import CandidateReconciliationService
from .discovery_contracts import CandidateAssetContract, CandidateType, DiscoveryStageName
from .models import CandidateAsset, CollectionAttempt, DiscoveryJob, DiscoverySource
from .scope_guard import OperationContext, ScopeAuthorizationRequest, ScopeDecision, ScopeGuard
from .security import Principal

DnsResultCode = Literal[
    "SUCCESS",
    "NXDOMAIN",
    "NOANSWER",
    "SERVFAIL",
    "TIMEOUT",
    "DENIED",
    "TRANSIENT_ERROR",
    "PERMANENT_ERROR",
]


@dataclass(frozen=True)
class DnsAnswer:
    address: str
    record_type: Literal["A", "AAAA"]
    ttl: int | None


@dataclass(frozen=True)
class DnsResolution:
    result: DnsResultCode
    answers: tuple[DnsAnswer, ...] = ()
    reason_code: str | None = None


class DnsResolver(Protocol):
    """Injected resolver boundary; tests must use deterministic fixture implementations."""

    def resolve_a(self, name: str) -> DnsResolution: ...

    def resolve_aaaa(self, name: str) -> DnsResolution: ...


class FixtureDnsResolver:
    """Recorded resolver with call accounting; it performs no network I/O."""

    def __init__(self, responses: Mapping[tuple[str, str], DnsResolution]) -> None:
        self._responses = dict(responses)
        self.calls: list[tuple[str, str]] = []

    def resolve_a(self, name: str) -> DnsResolution:
        return self._resolve(name, "A")

    def resolve_aaaa(self, name: str) -> DnsResolution:
        return self._resolve(name, "AAAA")

    def _resolve(self, name: str, record_type: str) -> DnsResolution:
        self.calls.append((name, record_type))
        return self._responses.get(
            (name, record_type),
            DnsResolution(result="NOANSWER", reason_code="FIXTURE_NO_ANSWER"),
        )


def fixture_resolver_for_reference(reference: str | None) -> FixtureDnsResolver | None:
    """Return only a versioned offline resolver fixture explicitly selected by source config."""

    if reference != "fixture:dns-validation-v1":
        return None
    return FixtureDnsResolver(
        {
            ("www.example.com", "A"): DnsResolution(
                result="SUCCESS",
                answers=(DnsAnswer("192.0.2.20", "A", 300),),
            ),
            ("www.example.com", "AAAA"): DnsResolution(result="NOANSWER"),
            ("api.example.com", "A"): DnsResolution(
                result="SUCCESS",
                answers=(DnsAnswer("192.0.2.21", "A", 300),),
            ),
            ("api.example.com", "AAAA"): DnsResolution(result="NOANSWER"),
        }
    )


@dataclass(frozen=True)
class DnsValidationOutcome:
    decision: ScopeDecision
    result: DnsResultCode
    addresses: tuple[DnsAnswer, ...]
    active_validation_eligible_addresses: tuple[str, ...]
    attempt_id: uuid.UUID


def is_active_validation_safe_address(address: str) -> bool:
    """Allow global unicast only; private, special, and documentation ranges are denied."""

    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    cgnat = ipaddress.ip_network("100.64.0.0/10")
    return parsed.is_global and parsed not in cgnat


class DnsValidationWorker:
    """Resolve an already-staged domain only after fresh ScopeGuard authorization."""

    def __init__(
        self,
        *,
        resolver: DnsResolver,
        reconciler: CandidateReconciliationService | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._resolver = resolver
        self._reconciler = reconciler or CandidateReconciliationService(clock=clock)
        self._clock = clock or (lambda: datetime.now(UTC))

    def validate(
        self,
        session: Session,
        *,
        job: DiscoveryJob,
        candidate: CandidateAsset,
        source: DiscoverySource,
        principal: Principal,
        correlation_id: str,
        now: datetime | None = None,
    ) -> DnsValidationOutcome:
        if candidate.candidate_type != CandidateType.DOMAIN.value:
            raise ValueError("DNS validation accepts DOMAIN candidates only")
        started_at = self._clock()
        authorization = ScopeAuthorizationRequest(
            principal=principal,
            organization_id=job.organization_id,
            scope_id=job.scope_id,
            scope_version_id=job.scope_version_id,
            approval_id=job.scope_approval_id,
            target=candidate.canonical_value,
            operation=OperationContext(protocol="DNS", correlation_id=correlation_id),
            now=now or started_at,
        )
        decision = ScopeGuard(session).authorize(authorization)
        if not decision.allowed:
            attempt = self._record_attempt(
                session,
                job=job,
                candidate=candidate,
                decision=decision,
                result="DENIED",
                reason_code=decision.reason_code,
                started_at=started_at,
                metadata={"scope_decision": decision.reason_code},
                correlation_id=correlation_id,
            )
            candidate.state = "DENIED"
            session.flush()
            return DnsValidationOutcome(decision, "DENIED", (), (), attempt.id)

        resolutions = (
            self._resolver.resolve_a(candidate.canonical_value),
            self._resolver.resolve_aaaa(candidate.canonical_value),
        )
        result, answers = self._combine(resolutions)
        resolved_at = self._clock()
        safe_addresses = tuple(
            answer.address
            for answer in answers
            if is_active_validation_safe_address(answer.address)
        )
        metadata: dict[str, object] = {
            "scope_decision": decision.reason_code,
            "resolved_at": resolved_at.isoformat(),
            "answers": [
                {
                    "address": answer.address,
                    "record_type": answer.record_type,
                    "ttl": answer.ttl,
                    "active_validation_eligible": answer.address in safe_addresses,
                }
                for answer in answers
            ],
        }
        attempt = self._record_attempt(
            session,
            job=job,
            candidate=candidate,
            decision=decision,
            result=result,
            reason_code=None,
            started_at=started_at,
            metadata=metadata,
            correlation_id=correlation_id,
        )
        if result == "SUCCESS":
            candidate.state = "VALIDATED"
            self._persist_dns_provenance(
                session,
                job=job,
                candidate=candidate,
                source=source,
                principal=principal,
                answers=answers,
                observed_at=resolved_at,
            )
        elif result in {"NXDOMAIN", "NOANSWER"}:
            candidate.state = "UNRESOLVED"
        session.flush()
        return DnsValidationOutcome(decision, result, answers, safe_addresses, attempt.id)

    def _persist_dns_provenance(
        self,
        session: Session,
        *,
        job: DiscoveryJob,
        candidate: CandidateAsset,
        source: DiscoverySource,
        principal: Principal,
        answers: tuple[DnsAnswer, ...],
        observed_at: datetime,
    ) -> None:
        answer_metadata: list[dict[str, object]] = [
            {"address": answer.address, "record_type": answer.record_type, "ttl": answer.ttl}
            for answer in answers
        ]
        payload_hash = self._payload_hash(candidate.canonical_value, answer_metadata)
        contracts = [
            CandidateAssetContract(
                organization_id=job.organization_id,
                scope_id=job.scope_id,
                scope_version_id=job.scope_version_id,
                scope_approval_id=job.scope_approval_id,
                candidate_type=CandidateType.DOMAIN,
                raw_value=candidate.raw_value,
                canonical_value=candidate.canonical_value,
                source_key=source.source_key,
                source_record_key=f"dns:{candidate.id}",
                observed_at=observed_at,
                metadata={"evidence_category": "dns_validation", "answers": answer_metadata},
            )
        ]
        for answer in answers:
            ip_authorization = ScopeAuthorizationRequest(
                principal=principal,
                organization_id=job.organization_id,
                scope_id=job.scope_id,
                scope_version_id=job.scope_version_id,
                approval_id=job.scope_approval_id,
                target=answer.address,
                operation=OperationContext(protocol="DNS", correlation_id="dns-ip-hint"),
                now=observed_at,
            )
            if ScopeGuard(session).authorize(ip_authorization).allowed:
                contracts.append(
                    CandidateAssetContract(
                        organization_id=job.organization_id,
                        scope_id=job.scope_id,
                        scope_version_id=job.scope_version_id,
                        scope_approval_id=job.scope_approval_id,
                        candidate_type=CandidateType.IP,
                        raw_value=answer.address,
                        canonical_value=answer.address,
                        source_key=source.source_key,
                        source_record_key=f"dns:{candidate.id}:{answer.address}",
                        observed_at=observed_at,
                        metadata={
                            "evidence_category": "dns_validation",
                            "hostname": candidate.canonical_value,
                            "ttl": answer.ttl,
                        },
                    )
                )
        self._reconciler.ingest(
            session,
            source=source,
            contracts=contracts,
            payload_hash=payload_hash,
        )

    @staticmethod
    def _combine(
        resolutions: tuple[DnsResolution, DnsResolution],
    ) -> tuple[DnsResultCode, tuple[DnsAnswer, ...]]:
        answers = tuple(answer for resolution in resolutions for answer in resolution.answers)
        if answers:
            return "SUCCESS", answers
        results = {resolution.result for resolution in resolutions}
        if "TIMEOUT" in results:
            return "TIMEOUT", ()
        if "SERVFAIL" in results or "TRANSIENT_ERROR" in results:
            return "TRANSIENT_ERROR", ()
        if "NXDOMAIN" in results:
            return "NXDOMAIN", ()
        if "NOANSWER" in results:
            return "NOANSWER", ()
        return "PERMANENT_ERROR", ()

    def _record_attempt(
        self,
        session: Session,
        *,
        job: DiscoveryJob,
        candidate: CandidateAsset,
        decision: ScopeDecision,
        result: DnsResultCode,
        reason_code: str | None,
        started_at: datetime,
        metadata: dict[str, object],
        correlation_id: str,
    ) -> CollectionAttempt:
        finished_at = self._clock()
        attempt = CollectionAttempt(
            organization_id=job.organization_id,
            discovery_job_id=job.id,
            candidate_id=candidate.id,
            stage=DiscoveryStageName.DNS_VALIDATE.value,
            protocol="DNS",
            target_host=candidate.canonical_value,
            target_port=None,
            scope_decision="ALLOWED" if decision.allowed else "DENIED",
            result=result,
            reason_code=reason_code,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=max(0, int((finished_at - started_at).total_seconds() * 1000)),
            metadata_json=metadata,
            correlation_id=correlation_id,
        )
        session.add(attempt)
        session.flush()
        return attempt

    @staticmethod
    def _payload_hash(hostname: str, answers: list[dict[str, object]]) -> str:
        payload = json.dumps({"hostname": hostname, "answers": answers}, sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
