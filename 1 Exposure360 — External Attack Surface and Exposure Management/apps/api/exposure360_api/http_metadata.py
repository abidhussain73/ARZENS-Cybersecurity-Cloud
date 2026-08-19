"""Fixture-first bounded HTTP metadata collection for Phase 3."""

import hashlib
import ipaddress
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal
from urllib.parse import urljoin, urlsplit

from sqlalchemy.orm import Session

from .discovery_contracts import DiscoveryStageName
from .models import CandidateAsset, CollectionAttempt, DiscoveryJob
from .scope_guard import OperationContext, ScopeAuthorizationRequest, ScopeDecision, ScopeGuard
from .security import Principal

SAFE_USER_AGENT = "Exposure360/0.1 (+authorized-security-assessment)"
SAFE_RESPONSE_HEADERS = frozenset(
    {
        "content-type",
        "content-length",
        "server",
        "location",
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
    }
)

HttpResult = Literal["SUCCESS", "REDIRECT_DENIED", "TOO_MANY_REDIRECTS", "DENIED", "TIMEOUT"]


@dataclass(frozen=True)
class HttpFixtureResponse:
    status_code: int
    headers: Mapping[str, str]
    body_chunks: Sequence[bytes] = ()
    timeout: bool = False


class FixtureHttpTransport:
    """No-network transport with explicit method/URL/header call accounting."""

    def __init__(self, responses: Mapping[tuple[str, str], HttpFixtureResponse]) -> None:
        self._responses = dict(responses)
        self.calls: list[tuple[str, str, Mapping[str, str]]] = []

    def request(self, *, method: str, url: str, headers: Mapping[str, str]) -> HttpFixtureResponse:
        self.calls.append((method, url, headers))
        return self._responses[(method, url)]


def fixture_transport_for_reference(reference: str | None) -> FixtureHttpTransport | None:
    """Resolve only the explicit Phase 3 no-network HTTP fixture transport."""

    if reference != "fixture:http-metadata-v1":
        return None
    return FixtureHttpTransport(
        {
            ("HEAD", "https://www.example.com/"): HttpFixtureResponse(
                status_code=200,
                headers={"Content-Type": "text/html", "Server": "fixture-http"},
            )
        }
    )


def validate_http_url(url: str) -> str | None:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    return url


def _safe_http_target(hostname: str) -> bool:
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return True
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def safe_response_headers(headers: Mapping[str, str]) -> dict[str, str | bool]:
    lowered = {key.lower(): value for key, value in headers.items()}
    result: dict[str, str | bool] = {
        key: value for key, value in lowered.items() if key in SAFE_RESPONSE_HEADERS
    }
    if "set-cookie" in lowered:
        result["set_cookie_present"] = True
    return result


def collect_fixture_http_metadata(
    transport: FixtureHttpTransport,
    *,
    start_url: str,
    max_response_bytes: int = 65536,
    max_redirects: int = 3,
    reauthorize_redirect: Callable[[str], bool],
) -> tuple[HttpResult, dict[str, object]]:
    """Collect bounded fixture metadata; each redirect must be re-authorized before request."""

    current_url = validate_http_url(start_url)
    if current_url is None:
        return "DENIED", {"reason_code": "INVALID_URL"}
    redirects: list[str] = []
    for _ in range(max_redirects + 1):
        response = transport.request(
            method="HEAD",
            url=current_url,
            headers={"User-Agent": SAFE_USER_AGENT, "Accept": "*/*"},
        )
        if response.status_code in {405, 501}:
            response = transport.request(
                method="GET",
                url=current_url,
                headers={
                    "User-Agent": SAFE_USER_AGENT,
                    "Accept": "*/*",
                    "Range": f"bytes=0-{max_response_bytes - 1}",
                },
            )
        if response.timeout:
            return "TIMEOUT", {"final_url": current_url, "redirect_chain": redirects}
        location = response.headers.get("Location") or response.headers.get("location")
        if response.status_code in {301, 302, 303, 307, 308} and location is not None:
            if len(redirects) >= max_redirects:
                return "TOO_MANY_REDIRECTS", {"final_url": current_url, "redirect_chain": redirects}
            next_url = validate_http_url(urljoin(current_url, location))
            if next_url is None or not reauthorize_redirect(next_url):
                return "REDIRECT_DENIED", {"final_url": current_url, "redirect_chain": redirects}
            redirects.append(next_url)
            current_url = next_url
            continue
        chunks = response.body_chunks
        bytes_sampled = b"".join(chunks)[:max_response_bytes]
        truncated = sum(len(chunk) for chunk in chunks) > len(bytes_sampled)
        return "SUCCESS", {
            "status_code": response.status_code,
            "final_url": current_url,
            "redirect_chain": redirects,
            "headers": safe_response_headers(response.headers),
            "bytes_sampled": len(bytes_sampled),
            "body_truncated": truncated,
            "sample_sha256": hashlib.sha256(bytes_sampled).hexdigest(),
        }
    return "TOO_MANY_REDIRECTS", {"final_url": current_url, "redirect_chain": redirects}


@dataclass(frozen=True)
class HttpMetadataOutcome:
    decision: ScopeDecision | None
    result: HttpResult
    attempt_id: uuid.UUID


class HttpMetadataCollector:
    """Collect bounded HTTP metadata after fresh scope authorization for every URL hop."""

    def __init__(
        self,
        *,
        transport: FixtureHttpTransport,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or (lambda: datetime.now(UTC))

    def collect(
        self,
        session: Session,
        *,
        job: DiscoveryJob,
        candidate: CandidateAsset,
        principal: Principal,
        start_url: str,
        correlation_id: str,
        max_response_bytes: int = 65536,
        max_redirects: int = 3,
        attempt_number: int = 1,
        now: datetime | None = None,
    ) -> HttpMetadataOutcome:
        started_at = self._clock()
        authorization_time = now or started_at
        last_decision: ScopeDecision | None = None

        def authorize_url(url: str) -> bool:
            nonlocal last_decision
            normalized = validate_http_url(url)
            if normalized is None:
                return False
            parsed = urlsplit(normalized)
            hostname = parsed.hostname
            if hostname is None:
                return False
            protocol = "HTTPS" if parsed.scheme == "https" else "HTTP"
            last_decision = ScopeGuard(session).authorize(
                ScopeAuthorizationRequest(
                    principal=principal,
                    organization_id=job.organization_id,
                    scope_id=job.scope_id,
                    scope_version_id=job.scope_version_id,
                    approval_id=job.scope_approval_id,
                    target=hostname,
                    operation=OperationContext(protocol=protocol, correlation_id=correlation_id),
                    now=authorization_time,
                )
            )
            return last_decision.allowed and _safe_http_target(hostname)

        initial_url = validate_http_url(start_url)
        if initial_url is None or not authorize_url(initial_url):
            initial_reason = (
                last_decision.reason_code if last_decision is not None else "INVALID_URL"
            )
            return self._record(
                session,
                job=job,
                candidate=candidate,
                decision=last_decision,
                result="DENIED",
                reason_code=initial_reason,
                target_url=start_url,
                started_at=started_at,
                metadata={},
                correlation_id=correlation_id,
                attempt_number=attempt_number,
            )
        result, metadata = collect_fixture_http_metadata(
            self._transport,
            start_url=initial_url,
            max_response_bytes=max_response_bytes,
            max_redirects=max_redirects,
            reauthorize_redirect=authorize_url,
        )
        reason: str | None = None
        if result == "REDIRECT_DENIED":
            reason = last_decision.reason_code if last_decision is not None else "REDIRECT_INVALID"
        return self._record(
            session,
            job=job,
            candidate=candidate,
            decision=last_decision,
            result=result,
            reason_code=reason,
            target_url=initial_url,
            started_at=started_at,
            metadata=metadata,
            correlation_id=correlation_id,
            attempt_number=attempt_number,
        )

    def _record(
        self,
        session: Session,
        *,
        job: DiscoveryJob,
        candidate: CandidateAsset,
        decision: ScopeDecision | None,
        result: HttpResult,
        reason_code: str | None,
        target_url: str,
        started_at: datetime,
        metadata: dict[str, object],
        correlation_id: str,
        attempt_number: int,
    ) -> HttpMetadataOutcome:
        finished_at = self._clock()
        parsed = urlsplit(target_url)
        attempt = CollectionAttempt(
            organization_id=job.organization_id,
            discovery_job_id=job.id,
            candidate_id=candidate.id,
            stage=DiscoveryStageName.HTTP_METADATA.value,
            protocol="HTTPS" if parsed.scheme == "https" else "HTTP",
            target_host=parsed.hostname or "",
            target_port=parsed.port,
            attempt_number=attempt_number,
            scope_decision="ALLOWED" if decision is not None and decision.allowed else "DENIED",
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
        return HttpMetadataOutcome(decision=decision, result=result, attempt_id=attempt.id)
