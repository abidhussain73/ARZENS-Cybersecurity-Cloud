import socket
import ssl
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from exposure360_api.db import Base
from exposure360_api.discovery_orchestration import DiscoveryJobService
from exposure360_api.dns_validation import (
    DnsAnswer,
    DnsResolution,
    DnsValidationWorker,
    FixtureDnsResolver,
    is_active_validation_safe_address,
)
from exposure360_api.emergency_stop import EmergencyStopService
from exposure360_api.http_metadata import (
    FixtureHttpTransport,
    HttpFixtureResponse,
    HttpMetadataCollector,
)
from exposure360_api.models import (
    CandidateAsset,
    CandidateObservation,
    CollectionAttempt,
    DiscoveryJob,
    DiscoverySource,
    Membership,
    Organization,
    ScanPolicy,
    Scope,
    ScopeApproval,
    ScopeExclusion,
    ScopeSeed,
    ScopeVersion,
    User,
)
from exposure360_api.scope_approval import ScopeApprovalService
from exposure360_api.security import Principal
from exposure360_api.tcp_validation import (
    FixtureTcpConnector,
    ResolvedAddress,
    SocketTcpConnector,
    TcpConnectResult,
    TcpValidationWorker,
)
from exposure360_api.tls_metadata import (
    FixtureTlsConnector,
    SocketTlsConnector,
    TlsHandshakeResult,
    TlsMetadataCollector,
)

NOW = datetime(2026, 8, 17, 2, tzinfo=UTC)


@pytest.fixture
def database_session() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _context(session: Session) -> dict[str, object]:
    user = User(id=uuid4(), oidc_subject=f"dns-validator-{uuid4()}")
    organization = Organization(id=uuid4(), name="DNS validation", slug=f"dns-{uuid4().hex[:8]}")
    session.add_all(
        [
            user,
            organization,
            Membership(id=uuid4(), organization_id=organization.id, user_id=user.id, role="admin"),
        ]
    )
    session.flush()
    scope = Scope(
        id=uuid4(),
        organization_id=organization.id,
        name="Documentation scope",
        status="ACTIVE",
        created_by_user_id=user.id,
    )
    version = ScopeVersion(
        id=uuid4(),
        organization_id=organization.id,
        scope_id=scope.id,
        version_number=1,
        state="APPROVED",
        created_by_user_id=user.id,
        content_hash="",
    )
    session.add_all(
        [
            scope,
            version,
            ScopeSeed(
                id=uuid4(),
                organization_id=organization.id,
                scope_version_id=version.id,
                seed_type="DOMAIN",
                raw_value="example.com",
                canonical_value="example.com",
                match_mode="DOMAIN_AND_SUBDOMAINS",
            ),
            ScopeSeed(
                id=uuid4(),
                organization_id=organization.id,
                scope_version_id=version.id,
                seed_type="CIDR",
                raw_value="192.0.2.0/24",
                canonical_value="192.0.2.0/24",
                match_mode="EXACT",
            ),
            ScopeExclusion(
                id=uuid4(),
                organization_id=organization.id,
                scope_version_id=version.id,
                exclusion_type="DOMAIN",
                raw_value="blocked.example.com",
                canonical_value="blocked.example.com",
                match_mode="DOMAIN_AND_SUBDOMAINS",
                reason="DNS test exclusion",
            ),
            ScopeExclusion(
                id=uuid4(),
                organization_id=organization.id,
                scope_version_id=version.id,
                exclusion_type="CIDR",
                raw_value="192.0.2.64/26",
                canonical_value="192.0.2.64/26",
                match_mode="EXACT",
                reason="TCP test exclusion",
            ),
            ScanPolicy(
                id=uuid4(),
                organization_id=organization.id,
                scope_version_id=version.id,
                allowed_protocols=["DNS"],
                max_requests_per_second=10.0,
                max_concurrent_targets=5,
                max_concurrent_requests=5,
                schedule_timezone="UTC",
                schedule_windows=[],
                connect_timeout_seconds=5,
                request_timeout_seconds=5,
                active_scanning_enabled=False,
            ),
            DiscoverySource(
                id=uuid4(),
                organization_id=organization.id,
                source_key="fixture-dns-validation",
                source_type="RECORDED_PASSIVE_DNS",
                display_name="Fixture DNS validation",
                adapter_version="1.0.0",
            ),
        ]
    )
    session.flush()
    content_hash = ScopeApprovalService.content_hash(session, version)
    version.content_hash = content_hash
    approval = ScopeApproval(
        id=uuid4(),
        organization_id=organization.id,
        scope_id=scope.id,
        scope_version_id=version.id,
        approved_by_user_id=user.id,
        decision="APPROVED",
        approved_at=NOW,
        expires_at=NOW + timedelta(days=1),
        content_hash=content_hash,
    )
    session.add(approval)
    session.commit()
    job = DiscoveryJobService(clock=lambda: NOW).create_job(
        session,
        organization_id=organization.id,
        scope_id=scope.id,
        scope_version_id=version.id,
        approval_id=approval.id,
        requested_by_user_id=user.id,
        correlation_id="dns-validation-test",
    )
    session.commit()
    return {
        "user": user,
        "organization_id": organization.id,
        "scope": scope,
        "version": version,
        "approval": approval,
        "policy": session.scalar(select(ScanPolicy)),
        "source": session.scalar(select(DiscoverySource)),
        "job": job,
    }


def _candidate(session: Session, context: dict[str, object], hostname: str) -> CandidateAsset:
    job = context["job"]
    assert isinstance(job, DiscoveryJob)
    candidate = CandidateAsset(
        id=uuid4(),
        organization_id=job.organization_id,
        scope_id=job.scope_id,
        scope_version_id=job.scope_version_id,
        scope_approval_id=job.scope_approval_id,
        candidate_type="DOMAIN",
        raw_value=hostname,
        canonical_value=hostname,
        first_discovered_at=NOW,
        last_discovered_at=NOW,
        confidence_score=0.0,
        confidence_model_version="candidate-confidence-v1",
        confidence_factors_json=[],
        state="DISCOVERED",
        metadata_json={},
    )
    session.add(candidate)
    session.commit()
    return candidate


def _ip_candidate(session: Session, context: dict[str, object], address: str) -> CandidateAsset:
    job = context["job"]
    assert isinstance(job, DiscoveryJob)
    candidate = CandidateAsset(
        id=uuid4(),
        organization_id=job.organization_id,
        scope_id=job.scope_id,
        scope_version_id=job.scope_version_id,
        scope_approval_id=job.scope_approval_id,
        candidate_type="IP",
        raw_value=address,
        canonical_value=address,
        first_discovered_at=NOW,
        last_discovered_at=NOW,
        confidence_score=0.0,
        confidence_model_version="candidate-confidence-v1",
        confidence_factors_json=[],
        state="DISCOVERED",
        metadata_json={},
    )
    session.add(candidate)
    session.commit()
    return candidate


def _refresh_approval_hash(session: Session, context: dict[str, object]) -> None:
    version = context["version"]
    approval = context["approval"]
    assert isinstance(version, ScopeVersion)
    assert isinstance(approval, ScopeApproval)
    content_hash = ScopeApprovalService.content_hash(session, version)
    version.content_hash = content_hash
    approval.content_hash = content_hash
    session.commit()


def _allow_global_tcp_fixture(session: Session, context: dict[str, object]) -> None:
    version = context["version"]
    policy = context["policy"]
    organization_id = context["organization_id"]
    assert isinstance(version, ScopeVersion)
    assert isinstance(policy, ScanPolicy)
    assert isinstance(organization_id, UUID)
    session.add(
        ScopeSeed(
            id=uuid4(),
            organization_id=organization_id,
            scope_version_id=version.id,
            seed_type="CIDR",
            raw_value="8.8.8.8/32",
            canonical_value="8.8.8.8/32",
            match_mode="EXACT",
        )
    )
    policy.allowed_protocols = ["HTTPS"]
    session.flush()
    _refresh_approval_hash(session, context)


def _validate(
    session: Session,
    context: dict[str, object],
    candidate: CandidateAsset,
    resolver: FixtureDnsResolver,
    *,
    now: datetime = NOW,
) -> object:
    user = context["user"]
    source = context["source"]
    job = context["job"]
    assert isinstance(user, User)
    assert isinstance(source, DiscoverySource)
    assert isinstance(job, DiscoveryJob)
    return DnsValidationWorker(resolver=resolver, clock=lambda: NOW).validate(
        session,
        job=job,
        candidate=candidate,
        source=source,
        principal=Principal(user=user),
        correlation_id="dns-validation-test",
        now=now,
    )


def _validate_tcp(
    session: Session,
    context: dict[str, object],
    candidate: CandidateAsset,
    connector: FixtureTcpConnector,
    *,
    protocol: str = "HTTPS",
    port: int = 443,
    concurrent_requests: int = 0,
) -> object:
    user = context["user"]
    job = context["job"]
    assert isinstance(user, User)
    assert isinstance(job, DiscoveryJob)
    return TcpValidationWorker(connector=connector, clock=lambda: NOW).validate(
        session,
        job=job,
        candidate=candidate,
        principal=Principal(user=user),
        resolved=ResolvedAddress(
            hostname="www.example.com",
            address=candidate.canonical_value,
            resolved_at=NOW,
            ttl_seconds=300,
            scope_decision="ALLOWED",
        ),
        protocol=protocol,
        port=port,
        timeout_seconds=3.0,
        correlation_id="tcp-validation-test",
        concurrent_requests=concurrent_requests,
        now=NOW,
    )


def _validate_tls(
    session: Session,
    context: dict[str, object],
    candidate: CandidateAsset,
    connector: FixtureTlsConnector,
    *,
    port: int = 443,
    now: datetime = NOW,
) -> object:
    user = context["user"]
    job = context["job"]
    assert isinstance(user, User)
    assert isinstance(job, DiscoveryJob)
    return TlsMetadataCollector(connector=connector, clock=lambda: NOW).collect(
        session,
        job=job,
        candidate=candidate,
        principal=Principal(user=user),
        hostname="www.example.com",
        address=candidate.canonical_value,
        port=port,
        timeout_seconds=3.0,
        correlation_id="tls-metadata-test",
        now=now,
    )


def test_approved_domain_uses_fixture_resolver_and_persists_rebinding_metadata(
    database_session: Session,
) -> None:
    context = _context(database_session)
    candidate = _candidate(database_session, context, "www.example.com")
    resolver = FixtureDnsResolver(
        {
            ("www.example.com", "A"): DnsResolution(
                result="SUCCESS",
                answers=(DnsAnswer("192.0.2.20", "A", 300),),
            ),
            ("www.example.com", "AAAA"): DnsResolution(result="NOANSWER"),
        }
    )

    outcome = _validate(database_session, context, candidate, resolver)

    assert resolver.calls == [("www.example.com", "A"), ("www.example.com", "AAAA")]
    assert outcome.result == "SUCCESS"
    assert outcome.active_validation_eligible_addresses == ()
    attempt = database_session.get(CollectionAttempt, outcome.attempt_id)
    assert attempt is not None
    assert attempt.result == "SUCCESS"
    assert attempt.metadata_json["scope_decision"] == "ALLOWED"
    assert attempt.metadata_json["resolved_at"] == NOW.isoformat()
    assert database_session.scalar(select(func.count()).select_from(CandidateObservation)) == 2
    assert (
        database_session.scalar(
            select(func.count())
            .select_from(CandidateAsset)
            .where(CandidateAsset.candidate_type == "IP")
        )
        == 1
    )


@pytest.mark.parametrize(
    ("hostname", "reason"),
    [
        ("outside.example.net", "TARGET_OUT_OF_SCOPE"),
        ("blocked.example.com", "TARGET_EXCLUDED"),
    ],
)
def test_out_of_scope_or_excluded_name_never_calls_resolver(
    database_session: Session,
    hostname: str,
    reason: str,
) -> None:
    context = _context(database_session)
    candidate = _candidate(database_session, context, hostname)
    resolver = FixtureDnsResolver({})

    outcome = _validate(database_session, context, candidate, resolver)

    assert outcome.result == "DENIED"
    assert outcome.decision.reason_code == reason
    assert resolver.calls == []


def test_emergency_stop_and_protocol_policy_skip_resolver(database_session: Session) -> None:
    context = _context(database_session)
    candidate = _candidate(database_session, context, "www.example.com")
    user = context["user"]
    organization_id = context["organization_id"]
    assert isinstance(user, User)
    assert isinstance(organization_id, UUID)
    EmergencyStopService.set_stop(
        database_session,
        organization_id=organization_id,
        scope_id=None,
        actor_id=user.id,
        reason="DNS stop test",
    )
    database_session.commit()
    stopped_resolver = FixtureDnsResolver({})

    stopped = _validate(database_session, context, candidate, stopped_resolver)

    assert stopped.result == "DENIED"
    assert stopped.decision.reason_code == "ORGANIZATION_EMERGENCY_STOP"
    assert stopped_resolver.calls == []


@pytest.mark.parametrize(
    ("policy_update", "validation_time", "reason"),
    [
        ({"allowed_protocols": ["HTTPS"]}, NOW, "PROTOCOL_NOT_ALLOWED"),
        (
            {"schedule_windows": [{"days": ["MON"], "start": "01:00", "end": "05:00"}]},
            datetime(2026, 8, 17, 7, tzinfo=UTC),
            "OUTSIDE_SCHEDULE",
        ),
    ],
)
def test_policy_denial_never_calls_resolver(
    database_session: Session,
    policy_update: dict[str, object],
    validation_time: datetime,
    reason: str,
) -> None:
    context = _context(database_session)
    policy = context["policy"]
    assert isinstance(policy, ScanPolicy)
    for field, value in policy_update.items():
        setattr(policy, field, value)
    _refresh_approval_hash(database_session, context)
    candidate = _candidate(database_session, context, "www.example.com")
    resolver = FixtureDnsResolver({})

    outcome = _validate(
        database_session,
        context,
        candidate,
        resolver,
        now=validation_time,
    )

    assert outcome.result == "DENIED"
    assert outcome.decision.reason_code == reason
    assert resolver.calls == []


def test_nxdomain_and_timeout_are_bounded_non_crashing_results(database_session: Session) -> None:
    context = _context(database_session)
    nxdomain_candidate = _candidate(database_session, context, "www.example.com")
    nxdomain_resolver = FixtureDnsResolver(
        {
            ("www.example.com", "A"): DnsResolution(result="NXDOMAIN"),
            ("www.example.com", "AAAA"): DnsResolution(result="NXDOMAIN"),
        }
    )

    nxdomain = _validate(database_session, context, nxdomain_candidate, nxdomain_resolver)

    assert nxdomain.result == "NXDOMAIN"
    assert nxdomain_resolver.calls == [("www.example.com", "A"), ("www.example.com", "AAAA")]
    assert nxdomain_candidate.state == "UNRESOLVED"

    timeout_candidate = _candidate(database_session, context, "api.example.com")
    timeout_resolver = FixtureDnsResolver(
        {
            ("api.example.com", "A"): DnsResolution(result="TIMEOUT"),
            ("api.example.com", "AAAA"): DnsResolution(result="NOANSWER"),
        }
    )
    timeout = _validate(database_session, context, timeout_candidate, timeout_resolver)

    assert timeout.result == "TIMEOUT"
    assert timeout_resolver.calls == [("api.example.com", "A"), ("api.example.com", "AAAA")]


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.0.0.1", "169.254.169.254", "192.0.2.20", "::1", "fe80::1"],
)
def test_special_addresses_are_ineligible_for_downstream_active_validation(address: str) -> None:
    assert is_active_validation_safe_address(address) is False


def test_approved_allowlisted_tcp_endpoint_uses_only_fixture_connector(
    database_session: Session,
) -> None:
    context = _context(database_session)
    _allow_global_tcp_fixture(database_session, context)
    candidate = _ip_candidate(database_session, context, "8.8.8.8")
    connector = FixtureTcpConnector({("8.8.8.8", 443): TcpConnectResult(result="SUCCESS")})

    outcome = _validate_tcp(database_session, context, candidate, connector)

    assert outcome.result == "SUCCESS"
    assert connector.calls == [("8.8.8.8", 443, 3.0)]
    attempt = database_session.get(CollectionAttempt, outcome.attempt_id)
    assert attempt is not None
    assert attempt.result == "SUCCESS"
    assert attempt.metadata_json["ttl_seconds"] == 300


@pytest.mark.parametrize(
    ("protocol", "port", "reason"),
    [("HTTPS", 22, "PORT_NOT_ALLOWED"), ("SSH", 443, "PROTOCOL_NOT_ALLOWED")],
)
def test_unsupported_port_or_protocol_never_calls_connector(
    database_session: Session,
    protocol: str,
    port: int,
    reason: str,
) -> None:
    context = _context(database_session)
    _allow_global_tcp_fixture(database_session, context)
    candidate = _ip_candidate(database_session, context, "8.8.8.8")
    connector = FixtureTcpConnector({})

    outcome = _validate_tcp(
        database_session,
        context,
        candidate,
        connector,
        protocol=protocol,
        port=port,
    )

    assert outcome.result == "DENIED"
    assert outcome.decision.reason_code in {"ALLOWED", reason}
    assert connector.calls == []
    attempt = database_session.get(CollectionAttempt, outcome.attempt_id)
    assert attempt is not None
    assert attempt.reason_code == reason


@pytest.mark.parametrize(
    "address",
    ["198.51.100.9", "192.0.2.65", "192.0.2.20", "10.0.0.1", "127.0.0.1"],
)
def test_out_of_scope_or_special_address_never_calls_connector(
    database_session: Session,
    address: str,
) -> None:
    context = _context(database_session)
    _allow_global_tcp_fixture(database_session, context)
    candidate = _ip_candidate(database_session, context, address)
    connector = FixtureTcpConnector({})

    outcome = _validate_tcp(database_session, context, candidate, connector)

    assert outcome.result == "DENIED"
    assert connector.calls == []


def test_socket_connector_enforces_timeout_without_live_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def timed_out(address: tuple[str, int], timeout: float) -> object:
        captured["address"] = address
        captured["timeout"] = timeout
        raise TimeoutError

    monkeypatch.setattr(socket, "create_connection", timed_out)

    result = SocketTcpConnector().connect(address="8.8.8.8", port=443, timeout_seconds=2.5)

    assert result.result == "TIMEOUT"
    assert result.reason_code == "CONNECT_TIMEOUT"
    assert captured == {"address": ("8.8.8.8", 443), "timeout": 2.5}


def test_tls_socket_connector_collects_metadata_without_live_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    class FakeRawSocket:
        def __enter__(self) -> "FakeRawSocket":
            return self

        def __exit__(self, *_: object) -> None:
            return None

    class FakeTlsSocket:
        def __enter__(self) -> "FakeTlsSocket":
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def getpeercert(self, *, binary_form: bool) -> bytes:
            assert binary_form is True
            return b"fixture-leaf-certificate"

        def cipher(self) -> tuple[str, str, int]:
            return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

        def version(self) -> str:
            return "TLSv1.3"

        def selected_alpn_protocol(self) -> str:
            return "h2"

    class FakeContext:
        check_hostname = True
        verify_mode = ssl.CERT_REQUIRED

        def wrap_socket(self, raw_socket: FakeRawSocket, *, server_hostname: str) -> FakeTlsSocket:
            captured["raw_socket"] = raw_socket
            captured["server_hostname"] = server_hostname
            return FakeTlsSocket()

    fake_context = FakeContext()

    def create_connection(address: tuple[str, int], timeout: float) -> FakeRawSocket:
        captured["address"] = address
        captured["timeout"] = timeout
        return FakeRawSocket()

    monkeypatch.setattr(socket, "create_connection", create_connection)
    monkeypatch.setattr(ssl, "create_default_context", lambda: fake_context)

    result = SocketTlsConnector().handshake(
        address="8.8.8.8",
        port=443,
        server_hostname="www.example.com",
        timeout_seconds=2.5,
    )

    assert captured == {
        "address": ("8.8.8.8", 443),
        "timeout": 2.5,
        "raw_socket": captured["raw_socket"],
        "server_hostname": "www.example.com",
    }
    assert fake_context.check_hostname is False
    assert fake_context.verify_mode == ssl.CERT_NONE
    assert result.result == "SUCCESS"
    assert result.metadata == {
        "tls_version": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "alpn": "h2",
        "leaf_fingerprint_sha256": (
            "1dda6874127fb6185d99bdaa46b4d1d2b1a5acddd284040a1d4c01584cd8366c"
        ),
        "certificate_chain_length": 1,
        "certificate_validation": "NOT_VERIFIED",
    }


def test_emergency_stop_and_concurrency_limit_never_call_connector(
    database_session: Session,
) -> None:
    context = _context(database_session)
    _allow_global_tcp_fixture(database_session, context)
    candidate = _ip_candidate(database_session, context, "8.8.8.8")
    user = context["user"]
    organization_id = context["organization_id"]
    assert isinstance(user, User)
    assert isinstance(organization_id, UUID)
    EmergencyStopService.set_stop(
        database_session,
        organization_id=organization_id,
        scope_id=None,
        actor_id=user.id,
        reason="TCP stop test",
    )
    database_session.commit()
    stopped_connector = FixtureTcpConnector({})

    stopped = _validate_tcp(database_session, context, candidate, stopped_connector)

    assert stopped.result == "DENIED"
    assert stopped_connector.calls == []

    EmergencyStopService.resume(
        database_session,
        organization_id=organization_id,
        scope_id=None,
        actor_id=user.id,
    )
    database_session.commit()
    constrained_connector = FixtureTcpConnector({})
    constrained = _validate_tcp(
        database_session,
        context,
        candidate,
        constrained_connector,
        concurrent_requests=5,
    )

    assert constrained.result == "DENIED"
    assert constrained.decision.reason_code == "CONCURRENCY_LIMIT_EXCEEDED"
    assert constrained_connector.calls == []


@pytest.mark.parametrize("result", ["CONNECTION_REFUSED", "TIMEOUT"])
def test_refused_or_timeout_connector_results_are_bounded_non_fatal(
    database_session: Session,
    result: str,
) -> None:
    context = _context(database_session)
    _allow_global_tcp_fixture(database_session, context)
    candidate = _ip_candidate(database_session, context, "8.8.8.8")
    connector = FixtureTcpConnector(
        {("8.8.8.8", 443): TcpConnectResult(result=result, reason_code=f"FIXTURE_{result}")}
    )

    outcome = _validate_tcp(database_session, context, candidate, connector)

    assert outcome.result == result
    assert connector.calls == [("8.8.8.8", 443, 3.0)]


def test_authorized_fixture_tls_metadata_is_bounded_and_persisted(
    database_session: Session,
) -> None:
    context = _context(database_session)
    _allow_global_tcp_fixture(database_session, context)
    policy = context["policy"]
    assert isinstance(policy, ScanPolicy)
    policy.allowed_protocols = ["TLS"]
    _refresh_approval_hash(database_session, context)
    candidate = _ip_candidate(database_session, context, "8.8.8.8")
    connector = FixtureTlsConnector(
        {
            ("8.8.8.8", 443): TlsHandshakeResult(
                result="SUCCESS",
                metadata={
                    "tls_version": "TLSv1.3",
                    "cipher": "TLS_AES_256_GCM_SHA384",
                    "alpn": "h2",
                    "leaf_fingerprint_sha256": "a" * 64,
                    "certificate_chain_length": 1,
                    "subject": "CN=www.example.com",
                    "sans": ["www.example.com", "api.example.com"],
                    "not_before": "2026-01-01T00:00:00+00:00",
                    "not_after": "2027-01-01T00:00:00+00:00",
                    "certificate_validation": "NOT_VERIFIED",
                },
            )
        }
    )

    outcome = _validate_tls(database_session, context, candidate, connector)

    assert outcome.result == "SUCCESS"
    assert connector.calls == [("8.8.8.8", 443, "www.example.com", 3.0)]
    attempt = database_session.get(CollectionAttempt, outcome.attempt_id)
    assert attempt is not None
    assert attempt.metadata_json["leaf_fingerprint_sha256"] == "a" * 64
    assert attempt.metadata_json["certificate_validation"] == "NOT_VERIFIED"
    assert attempt.metadata_json["subject"] == "CN=www.example.com"
    assert attempt.metadata_json["sans"] == ["www.example.com", "api.example.com"]
    assert attempt.metadata_json["not_after"] == "2027-01-01T00:00:00+00:00"


def test_special_address_tls_denial_never_calls_handshake_connector(
    database_session: Session,
) -> None:
    context = _context(database_session)
    policy = context["policy"]
    assert isinstance(policy, ScanPolicy)
    policy.allowed_protocols = ["TLS"]
    _refresh_approval_hash(database_session, context)
    special_candidate = _ip_candidate(database_session, context, "192.0.2.20")
    connector = FixtureTlsConnector({})

    outcome = _validate_tls(database_session, context, special_candidate, connector)

    assert outcome.result == "DENIED"
    assert connector.calls == []


@pytest.mark.parametrize("address", ["198.51.100.9", "192.0.2.65"])
def test_out_of_scope_or_excluded_tls_never_calls_handshake_connector(
    database_session: Session,
    address: str,
) -> None:
    context = _context(database_session)
    policy = context["policy"]
    assert isinstance(policy, ScanPolicy)
    policy.allowed_protocols = ["TLS"]
    _refresh_approval_hash(database_session, context)
    candidate = _ip_candidate(database_session, context, address)
    connector = FixtureTlsConnector({})

    outcome = _validate_tls(database_session, context, candidate, connector)

    assert outcome.result == "DENIED"
    assert connector.calls == []


def test_policy_port_schedule_and_emergency_stop_never_call_tls_connector(
    database_session: Session,
) -> None:
    context = _context(database_session)
    _allow_global_tcp_fixture(database_session, context)
    policy = context["policy"]
    user = context["user"]
    organization_id = context["organization_id"]
    assert isinstance(policy, ScanPolicy)
    assert isinstance(user, User)
    assert isinstance(organization_id, UUID)
    candidate = _ip_candidate(database_session, context, "8.8.8.8")

    policy.allowed_protocols = ["HTTPS"]
    _refresh_approval_hash(database_session, context)
    protocol_connector = FixtureTlsConnector({})
    protocol = _validate_tls(database_session, context, candidate, protocol_connector)
    assert protocol.result == "DENIED"
    assert protocol_connector.calls == []

    policy.allowed_protocols = ["TLS"]
    _refresh_approval_hash(database_session, context)
    port_connector = FixtureTlsConnector({})
    port_denied = _validate_tls(database_session, context, candidate, port_connector, port=80)
    assert port_denied.result == "DENIED"
    assert port_connector.calls == []

    policy.schedule_windows = [{"days": ["MON"], "start": "01:00", "end": "05:00"}]
    _refresh_approval_hash(database_session, context)
    schedule_connector = FixtureTlsConnector({})
    schedule_denied = _validate_tls(
        database_session,
        context,
        candidate,
        schedule_connector,
        now=datetime(2026, 8, 17, 7, tzinfo=UTC),
    )
    assert schedule_denied.result == "DENIED"
    assert schedule_connector.calls == []

    policy.schedule_windows = []
    _refresh_approval_hash(database_session, context)
    EmergencyStopService.set_stop(
        database_session,
        organization_id=organization_id,
        scope_id=None,
        actor_id=user.id,
        reason="TLS stop test",
    )
    database_session.commit()
    stop_connector = FixtureTlsConnector({})
    stopped = _validate_tls(database_session, context, candidate, stop_connector)
    assert stopped.result == "DENIED"
    assert stop_connector.calls == []


def test_http_redirects_reauthorize_each_hop_before_fixture_transport(
    database_session: Session,
) -> None:
    context = _context(database_session)
    policy = context["policy"]
    user = context["user"]
    job = context["job"]
    assert isinstance(policy, ScanPolicy)
    assert isinstance(user, User)
    assert isinstance(job, DiscoveryJob)
    policy.allowed_protocols = ["HTTPS"]
    _refresh_approval_hash(database_session, context)
    candidate = CandidateAsset(
        id=uuid4(),
        organization_id=job.organization_id,
        scope_id=job.scope_id,
        scope_version_id=job.scope_version_id,
        scope_approval_id=job.scope_approval_id,
        candidate_type="ENDPOINT_HINT",
        raw_value="https://www.example.com/",
        canonical_value="https://www.example.com/",
        first_discovered_at=NOW,
        last_discovered_at=NOW,
        confidence_score=0.0,
        confidence_model_version="candidate-confidence-v1",
        confidence_factors_json=[],
        state="DISCOVERED",
        metadata_json={},
    )
    database_session.add(candidate)
    database_session.commit()
    transport = FixtureHttpTransport(
        {
            ("HEAD", "https://www.example.com/"): HttpFixtureResponse(
                status_code=302,
                headers={"Location": "https://api.example.com/"},
            ),
            ("HEAD", "https://api.example.com/"): HttpFixtureResponse(
                status_code=200,
                headers={"Server": "fixture-redirect"},
            ),
        }
    )

    outcome = HttpMetadataCollector(transport=transport, clock=lambda: NOW).collect(
        database_session,
        job=job,
        candidate=candidate,
        principal=Principal(user=user),
        start_url=candidate.canonical_value,
        correlation_id="http-redirect-guard",
        now=NOW,
    )

    assert outcome.result == "SUCCESS"
    assert [call[1] for call in transport.calls] == [
        "https://www.example.com/",
        "https://api.example.com/",
    ]
    attempt = database_session.get(CollectionAttempt, outcome.attempt_id)
    assert attempt is not None
    assert attempt.scope_decision == "ALLOWED"
    assert attempt.metadata_json["redirect_chain"] == ["https://api.example.com/"]


def test_http_excluded_redirect_is_denied_before_second_fixture_transport(
    database_session: Session,
) -> None:
    context = _context(database_session)
    policy = context["policy"]
    user = context["user"]
    job = context["job"]
    assert isinstance(policy, ScanPolicy)
    assert isinstance(user, User)
    assert isinstance(job, DiscoveryJob)
    policy.allowed_protocols = ["HTTPS"]
    _refresh_approval_hash(database_session, context)
    candidate = CandidateAsset(
        id=uuid4(),
        organization_id=job.organization_id,
        scope_id=job.scope_id,
        scope_version_id=job.scope_version_id,
        scope_approval_id=job.scope_approval_id,
        candidate_type="ENDPOINT_HINT",
        raw_value="https://www.example.com/",
        canonical_value="https://www.example.com/",
        first_discovered_at=NOW,
        last_discovered_at=NOW,
        confidence_score=0.0,
        confidence_model_version="candidate-confidence-v1",
        confidence_factors_json=[],
        state="DISCOVERED",
        metadata_json={},
    )
    database_session.add(candidate)
    database_session.commit()
    transport = FixtureHttpTransport(
        {
            ("HEAD", "https://www.example.com/"): HttpFixtureResponse(
                status_code=302,
                headers={"Location": "https://blocked.example.com/"},
            )
        }
    )

    outcome = HttpMetadataCollector(transport=transport, clock=lambda: NOW).collect(
        database_session,
        job=job,
        candidate=candidate,
        principal=Principal(user=user),
        start_url=candidate.canonical_value,
        correlation_id="http-redirect-exclusion",
        now=NOW,
    )

    assert outcome.result == "REDIRECT_DENIED"
    assert [call[1] for call in transport.calls] == ["https://www.example.com/"]
    attempt = database_session.get(CollectionAttempt, outcome.attempt_id)
    assert attempt is not None
    assert attempt.reason_code == "TARGET_EXCLUDED"


def test_http_out_of_scope_redirect_is_denied_before_second_fixture_transport(
    database_session: Session,
) -> None:
    context = _context(database_session)
    policy = context["policy"]
    user = context["user"]
    job = context["job"]
    assert isinstance(policy, ScanPolicy)
    assert isinstance(user, User)
    assert isinstance(job, DiscoveryJob)
    policy.allowed_protocols = ["HTTPS"]
    _refresh_approval_hash(database_session, context)
    candidate = CandidateAsset(
        id=uuid4(),
        organization_id=job.organization_id,
        scope_id=job.scope_id,
        scope_version_id=job.scope_version_id,
        scope_approval_id=job.scope_approval_id,
        candidate_type="ENDPOINT_HINT",
        raw_value="https://www.example.com/",
        canonical_value="https://www.example.com/",
        first_discovered_at=NOW,
        last_discovered_at=NOW,
        confidence_score=0.0,
        confidence_model_version="candidate-confidence-v1",
        confidence_factors_json=[],
        state="DISCOVERED",
        metadata_json={},
    )
    database_session.add(candidate)
    database_session.commit()
    transport = FixtureHttpTransport(
        {
            ("HEAD", "https://www.example.com/"): HttpFixtureResponse(
                status_code=302,
                headers={"Location": "https://outside.example.net/"},
            )
        }
    )

    outcome = HttpMetadataCollector(transport=transport, clock=lambda: NOW).collect(
        database_session,
        job=job,
        candidate=candidate,
        principal=Principal(user=user),
        start_url=candidate.canonical_value,
        correlation_id="http-redirect-out-of-scope",
        now=NOW,
    )

    assert outcome.result == "REDIRECT_DENIED"
    assert [call[1] for call in transport.calls] == ["https://www.example.com/"]
    attempt = database_session.get(CollectionAttempt, outcome.attempt_id)
    assert attempt is not None
    assert attempt.reason_code == "TARGET_OUT_OF_SCOPE"
