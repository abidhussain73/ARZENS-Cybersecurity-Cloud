import uuid
from collections.abc import Generator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from exposure360_api.db import Base
from exposure360_api.emergency_stop import EmergencyStopService
from exposure360_api.models import (
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
from exposure360_api.scope_guard import (
    GuardedNetworkClient,
    OperationContext,
    ScopeAuthorizationRequest,
    ScopeDenied,
    ScopeGuard,
)
from exposure360_api.security import Principal


@dataclass
class FakeTransport:
    calls: list[tuple[str, str]]

    def request(self, *, target: str, protocol: str) -> object:
        self.calls.append((target, protocol))
        return {"transport": "fake", "target": target, "protocol": protocol}


@dataclass
class GuardFixture:
    session: Session
    principal: Principal
    organization_id: uuid.UUID
    other_organization_id: uuid.UUID
    scope: Scope
    version: ScopeVersion
    approval: ScopeApproval


@pytest.fixture
def guard_fixture() -> Generator[GuardFixture, None, None]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    local_session = sessionmaker(bind=engine, expire_on_commit=False)
    session = local_session()
    now = datetime(2026, 8, 17, 2, tzinfo=UTC)
    user = User(id=uuid.uuid4(), oidc_subject="scope-guard-user")
    organization = Organization(id=uuid.uuid4(), name="Guard organization", slug="guard-org")
    other_organization = Organization(id=uuid.uuid4(), name="Other organization", slug="other-org")
    session.add_all(
        [
            user,
            organization,
            other_organization,
            Membership(
                id=uuid.uuid4(),
                organization_id=organization.id,
                user_id=user.id,
                role="admin",
                is_active=True,
            ),
            Membership(
                id=uuid.uuid4(),
                organization_id=other_organization.id,
                user_id=user.id,
                role="admin",
                is_active=True,
            ),
        ]
    )
    session.flush()
    scope = Scope(
        organization_id=organization.id,
        name="Reserved documentation targets",
        created_by_user_id=user.id,
    )
    session.add(scope)
    session.flush()
    version = ScopeVersion(
        scope_id=scope.id,
        organization_id=organization.id,
        version_number=1,
        state="APPROVED",
        created_by_user_id=user.id,
    )
    session.add(version)
    session.flush()
    session.add_all(
        [
            ScopeSeed(
                scope_version_id=version.id,
                organization_id=organization.id,
                seed_type="DOMAIN",
                raw_value="example.com",
                canonical_value="example.com",
                match_mode="DOMAIN_AND_SUBDOMAINS",
            ),
            ScopeSeed(
                scope_version_id=version.id,
                organization_id=organization.id,
                seed_type="CIDR",
                raw_value="192.0.2.0/24",
                canonical_value="192.0.2.0/24",
                match_mode="EXACT",
            ),
            ScopeExclusion(
                scope_version_id=version.id,
                organization_id=organization.id,
                exclusion_type="DOMAIN",
                raw_value="blocked.example.com",
                canonical_value="blocked.example.com",
                match_mode="DOMAIN_AND_SUBDOMAINS",
                reason="Blocked test host",
            ),
            ScopeExclusion(
                scope_version_id=version.id,
                organization_id=organization.id,
                exclusion_type="CIDR",
                raw_value="192.0.2.64/26",
                canonical_value="192.0.2.64/26",
                match_mode="EXACT",
                reason="Blocked test network",
            ),
            ScanPolicy(
                scope_version_id=version.id,
                organization_id=organization.id,
                allowed_protocols=["HTTPS"],
                max_requests_per_second=2,
                max_concurrent_targets=2,
                max_concurrent_requests=2,
                schedule_timezone="UTC",
                schedule_windows=[{"days": ["MON"], "start": "01:00", "end": "05:00"}],
                active_scanning_enabled=False,
            ),
        ]
    )
    session.flush()
    content_hash = ScopeApprovalService.content_hash(session, version)
    version.content_hash = content_hash
    approval = ScopeApproval(
        organization_id=organization.id,
        scope_id=scope.id,
        scope_version_id=version.id,
        approved_by_user_id=user.id,
        decision="APPROVED",
        approved_at=now,
        expires_at=now + timedelta(days=1),
        content_hash=content_hash,
    )
    session.add(approval)
    session.commit()
    try:
        yield GuardFixture(
            session=session,
            principal=Principal(user=user),
            organization_id=organization.id,
            other_organization_id=other_organization.id,
            scope=scope,
            version=version,
            approval=approval,
        )
    finally:
        session.close()
        engine.dispose()


def authorization(
    fixture: GuardFixture,
    target: str,
    **operation_overrides: object,
) -> ScopeAuthorizationRequest:
    operation_fields: dict[str, object] = {
        "protocol": "HTTPS",
        "correlation_id": "scope-guard-test",
    }
    operation_fields.update(operation_overrides)
    operation = OperationContext(**operation_fields)
    return ScopeAuthorizationRequest(
        principal=fixture.principal,
        organization_id=fixture.organization_id,
        scope_id=fixture.scope.id,
        scope_version_id=fixture.version.id,
        approval_id=fixture.approval.id,
        target=target,
        operation=operation,
        now=datetime(2026, 8, 17, 2, tzinfo=UTC),
    )


def guarded_client(fixture: GuardFixture) -> tuple[GuardedNetworkClient, FakeTransport]:
    transport = FakeTransport(calls=[])
    return GuardedNetworkClient(ScopeGuard(fixture.session), transport), transport


@pytest.mark.parametrize("target", ["example.com", "www.example.com", "192.0.2.10"])
def test_allowed_targets_invoke_only_the_fake_transport(
    guard_fixture: GuardFixture, target: str
) -> None:
    client, transport = guarded_client(guard_fixture)

    result = client.request(authorization(guard_fixture, target))

    assert result == {"transport": "fake", "target": target, "protocol": "HTTPS"}
    assert transport.calls == [(target, "HTTPS")]


@pytest.mark.parametrize(
    ("target", "reason"),
    [
        ("example.com.attacker.test", "TARGET_OUT_OF_SCOPE"),
        ("blocked.example.com", "TARGET_EXCLUDED"),
        ("child.blocked.example.com", "TARGET_EXCLUDED"),
        ("192.0.2.65", "TARGET_EXCLUDED"),
        ("198.51.100.1", "TARGET_OUT_OF_SCOPE"),
        ("AS64500", "ASN_NOT_NETWORK_EXECUTABLE"),
    ],
)
def test_disallowed_targets_are_blocked_before_transport(
    guard_fixture: GuardFixture, target: str, reason: str
) -> None:
    client, transport = guarded_client(guard_fixture)

    with pytest.raises(ScopeDenied) as error:
        client.request(authorization(guard_fixture, target))

    assert error.value.decision.reason_code == reason
    assert transport.calls == []


@pytest.mark.parametrize(
    ("prepare", "operation_overrides", "reason"),
    [
        (lambda fixture: setattr(fixture.scope, "status", "DISABLED"), {}, "SCOPE_DISABLED"),
        (
            lambda fixture: EmergencyStopService.set_stop(
                fixture.session,
                organization_id=fixture.organization_id,
                scope_id=None,
                actor_id=fixture.principal.user.id,
                reason="organization halt",
            ),
            {},
            "ORGANIZATION_EMERGENCY_STOP",
        ),
        (
            lambda fixture: EmergencyStopService.set_stop(
                fixture.session,
                organization_id=fixture.organization_id,
                scope_id=fixture.scope.id,
                actor_id=fixture.principal.user.id,
                reason="scope halt",
            ),
            {},
            "SCOPE_EMERGENCY_STOP",
        ),
        (lambda fixture: None, {"protocol": "TCP"}, "PROTOCOL_NOT_ALLOWED"),
        (lambda fixture: None, {"requests_in_current_second": 2}, "RATE_LIMIT_EXCEEDED"),
        (lambda fixture: None, {"concurrent_requests": 2}, "CONCURRENCY_LIMIT_EXCEEDED"),
    ],
)
def test_lifecycle_and_policy_denials_skip_transport(
    guard_fixture: GuardFixture,
    prepare: object,
    operation_overrides: dict[str, object],
    reason: str,
) -> None:
    action = prepare
    assert callable(action)
    action(guard_fixture)
    guard_fixture.session.commit()
    client, transport = guarded_client(guard_fixture)

    with pytest.raises(ScopeDenied) as error:
        client.request(authorization(guard_fixture, "example.com", **operation_overrides))

    assert error.value.decision.reason_code == reason
    assert transport.calls == []


def test_expired_approval_cross_org_version_hash_mismatch_and_schedule_skip_transport(
    guard_fixture: GuardFixture,
) -> None:
    client, transport = guarded_client(guard_fixture)
    guard_fixture.approval.expires_at = datetime(2026, 8, 17, 1, tzinfo=UTC)
    guard_fixture.session.commit()
    with pytest.raises(ScopeDenied) as expired:
        client.request(authorization(guard_fixture, "example.com"))
    assert expired.value.decision.reason_code == "APPROVAL_EXPIRED"
    assert transport.calls == []

    guard_fixture.approval.expires_at = datetime(2026, 8, 18, 2, tzinfo=UTC)
    cross_org = authorization(guard_fixture, "example.com")
    cross_org = ScopeAuthorizationRequest(
        **{**cross_org.__dict__, "organization_id": guard_fixture.other_organization_id}
    )
    with pytest.raises(ScopeDenied) as cross_org_error:
        client.request(cross_org)
    assert cross_org_error.value.decision.reason_code == "SCOPE_NOT_FOUND"
    assert transport.calls == []

    guard_fixture.version.content_hash = "0" * 64
    guard_fixture.session.commit()
    with pytest.raises(ScopeDenied) as mismatch:
        client.request(authorization(guard_fixture, "example.com"))
    assert mismatch.value.decision.reason_code == "APPROVAL_INVALID"
    assert transport.calls == []

    guard_fixture.version.content_hash = guard_fixture.approval.content_hash
    guard_fixture.session.commit()
    outside_schedule = authorization(guard_fixture, "example.com")
    outside_schedule = ScopeAuthorizationRequest(
        **{**outside_schedule.__dict__, "now": datetime(2026, 8, 17, 7, tzinfo=UTC)}
    )
    with pytest.raises(ScopeDenied) as schedule:
        client.request(outside_schedule)
    assert schedule.value.decision.reason_code == "OUTSIDE_SCHEDULE"
    assert transport.calls == []


def test_running_guarded_operation_observes_stop_before_its_next_request(
    guard_fixture: GuardFixture,
) -> None:
    client, transport = guarded_client(guard_fixture)
    first_request = authorization(guard_fixture, "example.com")

    client.request(first_request)
    EmergencyStopService.set_stop(
        guard_fixture.session,
        organization_id=guard_fixture.organization_id,
        scope_id=None,
        actor_id=guard_fixture.principal.user.id,
        reason="stop a running guarded operation",
    )
    guard_fixture.session.commit()

    with pytest.raises(ScopeDenied) as stopped:
        client.request(first_request)

    assert stopped.value.decision.reason_code == "ORGANIZATION_EMERGENCY_STOP"
    assert transport.calls == [("example.com", "HTTPS")]
