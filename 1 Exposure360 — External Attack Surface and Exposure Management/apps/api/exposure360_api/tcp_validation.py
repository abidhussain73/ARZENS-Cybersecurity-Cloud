"""Guard-first, allowlisted TCP connectivity validation for Phase 3 staging."""

import socket
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol

from sqlalchemy.orm import Session

from .discovery_contracts import DiscoveryStageName
from .dns_validation import is_active_validation_safe_address
from .models import CandidateAsset, CollectionAttempt, DiscoveryJob
from .scope_guard import OperationContext, ScopeAuthorizationRequest, ScopeDecision, ScopeGuard
from .security import Principal

TcpResultCode = Literal[
    "SUCCESS",
    "CONNECTION_REFUSED",
    "TIMEOUT",
    "TRANSIENT_ERROR",
    "DENIED",
]

_ALLOWED_PORTS = {
    "HTTP": frozenset({80, 8080}),
    "HTTPS": frozenset({443, 8443}),
    "TLS": frozenset({443, 8443}),
}


@dataclass(frozen=True)
class ResolvedAddress:
    hostname: str
    address: str
    resolved_at: datetime
    ttl_seconds: int | None
    scope_decision: str


@dataclass(frozen=True)
class TcpConnectResult:
    result: TcpResultCode
    reason_code: str | None = None


class TcpConnector(Protocol):
    def connect(self, *, address: str, port: int, timeout_seconds: float) -> TcpConnectResult: ...


class SocketTcpConnector:
    """Production connector using one timeout-bounded standard socket connect and no payload."""

    def connect(self, *, address: str, port: int, timeout_seconds: float) -> TcpConnectResult:
        try:
            with socket.create_connection((address, port), timeout=timeout_seconds):
                return TcpConnectResult(result="SUCCESS")
        except TimeoutError:
            return TcpConnectResult(result="TIMEOUT", reason_code="CONNECT_TIMEOUT")
        except ConnectionRefusedError:
            return TcpConnectResult(result="CONNECTION_REFUSED", reason_code="CONNECTION_REFUSED")
        except OSError:
            return TcpConnectResult(result="TRANSIENT_ERROR", reason_code="CONNECT_OS_ERROR")


class FixtureTcpConnector:
    """Call-accounting mock transport. It never opens a real socket."""

    def __init__(self, responses: Mapping[tuple[str, int], TcpConnectResult]) -> None:
        self._responses = dict(responses)
        self.calls: list[tuple[str, int, float]] = []

    def connect(self, *, address: str, port: int, timeout_seconds: float) -> TcpConnectResult:
        self.calls.append((address, port, timeout_seconds))
        return self._responses.get(
            (address, port),
            TcpConnectResult(result="CONNECTION_REFUSED", reason_code="FIXTURE_REFUSED"),
        )


def fixture_connector_for_reference(reference: str | None) -> FixtureTcpConnector | None:
    """Return an offline connector only when an explicit protected fixture is selected."""

    if reference != "fixture:tcp-validation-v1":
        return None
    return FixtureTcpConnector({("8.8.8.8", 443): TcpConnectResult(result="SUCCESS")})


@dataclass(frozen=True)
class TcpValidationOutcome:
    decision: ScopeDecision
    result: TcpResultCode
    attempt_id: uuid.UUID


class TcpValidationWorker:
    """Perform one allowlisted TCP check against an already resolved, re-authorized address."""

    def __init__(
        self,
        *,
        connector: TcpConnector,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._connector = connector
        self._clock = clock or (lambda: datetime.now(UTC))

    def validate(
        self,
        session: Session,
        *,
        job: DiscoveryJob,
        candidate: CandidateAsset,
        principal: Principal,
        resolved: ResolvedAddress,
        protocol: str,
        port: int,
        timeout_seconds: float,
        correlation_id: str,
        requests_in_current_second: float = 0,
        concurrent_targets: int = 0,
        concurrent_requests: int = 0,
        now: datetime | None = None,
    ) -> TcpValidationOutcome:
        started_at = self._clock()
        decision = self._authorize(
            session,
            job=job,
            principal=principal,
            target=resolved.address,
            protocol=protocol,
            correlation_id=correlation_id,
            requests_in_current_second=requests_in_current_second,
            concurrent_targets=concurrent_targets,
            concurrent_requests=concurrent_requests,
            now=now or started_at,
        )
        if not decision.allowed:
            return self._deny(
                session,
                job=job,
                candidate=candidate,
                decision=decision,
                protocol=protocol,
                port=port,
                started_at=started_at,
                correlation_id=correlation_id,
            )
        if port not in _ALLOWED_PORTS.get(protocol, frozenset()):
            return self._deny(
                session,
                job=job,
                candidate=candidate,
                decision=decision,
                protocol=protocol,
                port=port,
                started_at=started_at,
                correlation_id=correlation_id,
                reason_code="PORT_NOT_ALLOWED",
            )
        if resolved.scope_decision != "ALLOWED":
            return self._deny(
                session,
                job=job,
                candidate=candidate,
                decision=decision,
                protocol=protocol,
                port=port,
                started_at=started_at,
                correlation_id=correlation_id,
                reason_code="DNS_SCOPE_DECISION_DENIED",
            )
        if not is_active_validation_safe_address(resolved.address):
            return self._deny(
                session,
                job=job,
                candidate=candidate,
                decision=decision,
                protocol=protocol,
                port=port,
                started_at=started_at,
                correlation_id=correlation_id,
                reason_code="SPECIAL_ADDRESS_DENIED",
            )
        result = self._connector.connect(
            address=resolved.address,
            port=port,
            timeout_seconds=timeout_seconds,
        )
        attempt = self._record_attempt(
            session,
            job=job,
            candidate=candidate,
            decision=decision,
            result=result.result,
            reason_code=result.reason_code,
            protocol=protocol,
            port=port,
            started_at=started_at,
            metadata={
                "hostname": resolved.hostname,
                "resolved_at": resolved.resolved_at.isoformat(),
                "ttl_seconds": resolved.ttl_seconds,
            },
            correlation_id=correlation_id,
        )
        session.flush()
        return TcpValidationOutcome(decision, result.result, attempt.id)

    def _authorize(
        self,
        session: Session,
        *,
        job: DiscoveryJob,
        principal: Principal,
        target: str,
        protocol: str,
        correlation_id: str,
        requests_in_current_second: float,
        concurrent_targets: int,
        concurrent_requests: int,
        now: datetime,
    ) -> ScopeDecision:
        return ScopeGuard(session).authorize(
            ScopeAuthorizationRequest(
                principal=principal,
                organization_id=job.organization_id,
                scope_id=job.scope_id,
                scope_version_id=job.scope_version_id,
                approval_id=job.scope_approval_id,
                target=target,
                operation=OperationContext(
                    protocol=protocol,
                    correlation_id=correlation_id,
                    requests_in_current_second=requests_in_current_second,
                    concurrent_targets=concurrent_targets,
                    concurrent_requests=concurrent_requests,
                ),
                now=now,
            )
        )

    def _deny(
        self,
        session: Session,
        *,
        job: DiscoveryJob,
        candidate: CandidateAsset,
        decision: ScopeDecision,
        protocol: str,
        port: int,
        started_at: datetime,
        correlation_id: str,
        reason_code: str | None = None,
    ) -> TcpValidationOutcome:
        attempt = self._record_attempt(
            session,
            job=job,
            candidate=candidate,
            decision=decision,
            result="DENIED",
            reason_code=reason_code or decision.reason_code,
            protocol=protocol,
            port=port,
            started_at=started_at,
            metadata={},
            correlation_id=correlation_id,
        )
        session.flush()
        return TcpValidationOutcome(decision, "DENIED", attempt.id)

    def _record_attempt(
        self,
        session: Session,
        *,
        job: DiscoveryJob,
        candidate: CandidateAsset,
        decision: ScopeDecision,
        result: TcpResultCode,
        reason_code: str | None,
        protocol: str,
        port: int,
        started_at: datetime,
        metadata: dict[str, object],
        correlation_id: str,
    ) -> CollectionAttempt:
        finished_at = self._clock()
        attempt = CollectionAttempt(
            organization_id=job.organization_id,
            discovery_job_id=job.id,
            candidate_id=candidate.id,
            stage=DiscoveryStageName.TCP_VALIDATE.value,
            protocol=protocol,
            target_host=candidate.canonical_value,
            target_port=port,
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
