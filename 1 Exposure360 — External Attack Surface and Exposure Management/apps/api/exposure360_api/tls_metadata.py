"""Guard-first TLS metadata collection for Phase 3 staging."""

import hashlib
import socket
import ssl
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

TlsResultCode = Literal[
    "SUCCESS",
    "HANDSHAKE_FAILED",
    "TIMEOUT",
    "CERTIFICATE_UNAVAILABLE",
    "DENIED",
    "TRANSIENT_ERROR",
]

_TLS_PORTS = frozenset({443, 8443})


@dataclass(frozen=True)
class TlsHandshakeResult:
    result: TlsResultCode
    metadata: dict[str, object]
    reason_code: str | None = None


class TlsConnector(Protocol):
    def handshake(
        self,
        *,
        address: str,
        port: int,
        server_hostname: str,
        timeout_seconds: float,
    ) -> TlsHandshakeResult: ...


class SocketTlsConnector:
    """Standard metadata-only TLS handshake with no credentials or application payload."""

    def handshake(
        self,
        *,
        address: str,
        port: int,
        server_hostname: str,
        timeout_seconds: float,
    ) -> TlsHandshakeResult:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((address, port), timeout=timeout_seconds) as raw_socket:
                with context.wrap_socket(raw_socket, server_hostname=server_hostname) as tls_socket:
                    certificate = tls_socket.getpeercert(binary_form=True)
                    if certificate is None:
                        return TlsHandshakeResult(
                            result="CERTIFICATE_UNAVAILABLE",
                            metadata={"certificate_validation": "NOT_VERIFIED"},
                        )
                    cipher = tls_socket.cipher()
                    return TlsHandshakeResult(
                        result="SUCCESS",
                        metadata={
                            "tls_version": tls_socket.version(),
                            "cipher": cipher[0] if cipher is not None else None,
                            "alpn": tls_socket.selected_alpn_protocol(),
                            "leaf_fingerprint_sha256": hashlib.sha256(certificate).hexdigest(),
                            "certificate_chain_length": 1,
                            "certificate_validation": "NOT_VERIFIED",
                        },
                    )
        except TimeoutError:
            return TlsHandshakeResult(result="TIMEOUT", metadata={}, reason_code="TLS_TIMEOUT")
        except ssl.SSLError:
            return TlsHandshakeResult(
                result="HANDSHAKE_FAILED", metadata={}, reason_code="TLS_HANDSHAKE_FAILED"
            )
        except OSError:
            return TlsHandshakeResult(
                result="TRANSIENT_ERROR", metadata={}, reason_code="TLS_OS_ERROR"
            )


class FixtureTlsConnector:
    """Deterministic no-network TLS transport with call accounting for acceptance tests."""

    def __init__(self, responses: Mapping[tuple[str, int], TlsHandshakeResult]) -> None:
        self._responses = dict(responses)
        self.calls: list[tuple[str, int, str, float]] = []

    def handshake(
        self,
        *,
        address: str,
        port: int,
        server_hostname: str,
        timeout_seconds: float,
    ) -> TlsHandshakeResult:
        self.calls.append((address, port, server_hostname, timeout_seconds))
        return self._responses.get(
            (address, port),
            TlsHandshakeResult(
                result="HANDSHAKE_FAILED",
                metadata={},
                reason_code="FIXTURE_FAILED",
            ),
        )


def fixture_connector_for_reference(reference: str | None) -> FixtureTlsConnector | None:
    """Return deterministic metadata only for the explicit Phase 3 TLS fixture reference."""

    if reference != "fixture:tls-metadata-v1":
        return None
    return FixtureTlsConnector(
        {
            ("8.8.8.8", 443): TlsHandshakeResult(
                result="SUCCESS",
                metadata={
                    "tls_version": "TLSv1.3",
                    "cipher": "TLS_AES_256_GCM_SHA384",
                    "alpn": "h2",
                    "leaf_fingerprint_sha256": "a" * 64,
                    "certificate_chain_length": 1,
                    "certificate_validation": "NOT_VERIFIED",
                },
            )
        }
    )


@dataclass(frozen=True)
class TlsValidationOutcome:
    decision: ScopeDecision
    result: TlsResultCode
    attempt_id: uuid.UUID


class TlsMetadataCollector:
    """Collect one negotiated TLS metadata record only after a fresh ScopeGuard decision."""

    def __init__(
        self,
        *,
        connector: TlsConnector,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._connector = connector
        self._clock = clock or (lambda: datetime.now(UTC))

    def collect(
        self,
        session: Session,
        *,
        job: DiscoveryJob,
        candidate: CandidateAsset,
        principal: Principal,
        hostname: str,
        address: str,
        port: int,
        timeout_seconds: float,
        correlation_id: str,
        attempt_number: int = 1,
        now: datetime | None = None,
    ) -> TlsValidationOutcome:
        started_at = self._clock()
        decision = ScopeGuard(session).authorize(
            ScopeAuthorizationRequest(
                principal=principal,
                organization_id=job.organization_id,
                scope_id=job.scope_id,
                scope_version_id=job.scope_version_id,
                approval_id=job.scope_approval_id,
                target=address,
                operation=OperationContext(protocol="TLS", correlation_id=correlation_id),
                now=now or started_at,
            )
        )
        reason = None
        if not decision.allowed:
            reason = decision.reason_code
        elif port not in _TLS_PORTS:
            reason = "PORT_NOT_ALLOWED"
        elif not is_active_validation_safe_address(address):
            reason = "SPECIAL_ADDRESS_DENIED"
        if reason is not None:
            attempt = self._record(
                session,
                job=job,
                candidate=candidate,
                decision=decision,
                result="DENIED",
                reason_code=reason,
                hostname=hostname,
                port=port,
                started_at=started_at,
                metadata={},
                correlation_id=correlation_id,
                attempt_number=attempt_number,
            )
            return TlsValidationOutcome(decision, "DENIED", attempt.id)
        handshake = self._connector.handshake(
            address=address,
            port=port,
            server_hostname=hostname,
            timeout_seconds=timeout_seconds,
        )
        attempt = self._record(
            session,
            job=job,
            candidate=candidate,
            decision=decision,
            result=handshake.result,
            reason_code=handshake.reason_code,
            hostname=hostname,
            port=port,
            started_at=started_at,
            metadata=handshake.metadata,
            correlation_id=correlation_id,
            attempt_number=attempt_number,
        )
        return TlsValidationOutcome(decision, handshake.result, attempt.id)

    def _record(
        self,
        session: Session,
        *,
        job: DiscoveryJob,
        candidate: CandidateAsset,
        decision: ScopeDecision,
        result: TlsResultCode,
        reason_code: str | None,
        hostname: str,
        port: int,
        started_at: datetime,
        metadata: dict[str, object],
        correlation_id: str,
        attempt_number: int,
    ) -> CollectionAttempt:
        finished_at = self._clock()
        attempt = CollectionAttempt(
            organization_id=job.organization_id,
            discovery_job_id=job.id,
            candidate_id=candidate.id,
            stage=DiscoveryStageName.TLS_METADATA.value,
            protocol="TLS",
            target_host=hostname,
            target_port=port,
            attempt_number=attempt_number,
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
