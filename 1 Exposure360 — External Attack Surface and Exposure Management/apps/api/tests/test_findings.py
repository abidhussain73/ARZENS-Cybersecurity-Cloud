from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from exposure360_api.db import Base
from exposure360_api.findings import FindingMatch, FindingService, FindingStateError
from exposure360_api.models import (
    Asset,
    AuditEvent,
    Evidence,
    Finding,
    FindingEvaluationEvent,
    FindingEvidenceLink,
    FindingStateEvent,
    Membership,
    Organization,
    User,
)
from exposure360_api.security import OrganizationContext, Principal


@pytest.fixture
def session() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection: object, _: object) -> None:
        connection.execute("PRAGMA foreign_keys=ON")  # type: ignore[union-attr]

    Base.metadata.create_all(engine)
    instance = sessionmaker(bind=engine, expire_on_commit=False)()
    try:
        yield instance
    finally:
        instance.close()
        engine.dispose()


def _context(session: Session, role: str = "admin") -> tuple[OrganizationContext, Principal, Asset]:
    organization = Organization(
        id=uuid4(), name=f"Finding {role}", slug=f"finding-{role}-{uuid4()}"
    )
    user = User(id=uuid4(), oidc_subject=f"finding-{role}-{uuid4()}", email=None, display_name=role)
    membership = Membership(id=uuid4(), organization_id=organization.id, user_id=user.id, role=role)
    observed_at = datetime(2026, 1, 20, tzinfo=UTC)
    asset = Asset(
        id=uuid4(),
        organization_id=organization.id,
        asset_type="SERVICE",
        canonical_key=f"service:{uuid4()}",
        display_name="fixture service",
        first_seen=observed_at,
        last_seen=observed_at,
    )
    session.add_all([organization, user])
    session.commit()
    session.add(membership)
    session.commit()
    session.add(asset)
    session.commit()
    return OrganizationContext(organization.id, membership), Principal(user), asset


def _evidence(session: Session, asset: Asset, observed_at: datetime) -> Evidence:
    evidence = Evidence(
        id=uuid4(),
        organization_id=asset.organization_id,
        observation_id=None,
        asset_id=asset.id,
        evidence_type="HTTP_RESPONSE",
        object_store_bucket="private",
        object_store_key=None,
        sha256="a" * 64,
        size_bytes=1,
        media_type="application/json",
        encoding=None,
        source_observed_at=observed_at,
        collected_at=observed_at,
        stored_at=observed_at,
        retention_class="STANDARD",
        sensitivity_class="INTERNAL_METADATA",
        collector_name="fixture",
        collector_version="1",
        metadata_json={},
        idempotency_key=str(uuid4()).replace("-", "") + "0" * 32,
    )
    session.add(evidence)
    session.flush()
    return evidence


def _viewer_in_organization(
    session: Session, organization_id: UUID
) -> tuple[OrganizationContext, Principal]:
    user = User(
        id=uuid4(), oidc_subject=f"finding-viewer-{uuid4()}", email=None, display_name="viewer"
    )
    session.add(user)
    session.commit()
    membership = Membership(
        id=uuid4(), organization_id=organization_id, user_id=user.id, role="viewer"
    )
    session.add(membership)
    session.commit()
    return OrganizationContext(organization_id, membership), Principal(user)


def _match(
    asset: Asset, observed_at: datetime, evidence_ids: tuple[UUID, ...] = ()
) -> FindingMatch:
    return FindingMatch(
        asset_id=asset.id,
        service_asset_id=None,
        rule_id="exposure.http.missing_hsts",
        rule_version=1,
        rule_hash="b" * 64,
        title="HSTS absent",
        description="Fixture metadata condition.",
        category="HTTP_SECURITY_HEADER",
        rule_severity="MEDIUM",
        confidence=0.9,
        observed_at=observed_at,
        observation_id=None,
        evidence_ids=evidence_ids,
    )


def test_state_machine_persists_events_and_audit(session: Session) -> None:
    context, principal, asset = _context(session)
    service = FindingService(session)
    finding = service.record_match(
        context.organization_id, _match(asset, datetime(2026, 1, 20, tzinfo=UTC))
    )
    service.transition(context, principal, finding.id, "ACKNOWLEDGED", "corr-1")
    service.transition(context, principal, finding.id, "IN_PROGRESS", "corr-2")
    service.transition(context, principal, finding.id, "RESOLVED_PENDING_VERIFICATION", "corr-3")
    service.transition(
        context,
        principal,
        finding.id,
        "CLOSED",
        "corr-4",
        verification_reference="fixture-evidence",
    )
    session.commit()
    assert finding.state == "CLOSED" and finding.closed_at is not None
    assert len(list(session.scalars(select(FindingStateEvent)))) == 4
    assert (
        len(
            list(
                session.scalars(
                    select(AuditEvent).where(AuditEvent.action == "finding.state_changed")
                )
            )
        )
        == 4
    )


def test_invalid_viewer_and_cross_organization_transitions_are_denied(session: Session) -> None:
    admin_context, admin, asset = _context(session, "admin")
    finding = FindingService(session).record_match(
        admin_context.organization_id, _match(asset, datetime(2026, 1, 20, tzinfo=UTC))
    )
    with pytest.raises(FindingStateError, match="invalid transition"):
        FindingService(session).transition(
            admin_context, admin, finding.id, "CLOSED", "corr", verification_reference="x"
        )
    viewer_context, viewer = _viewer_in_organization(session, admin_context.organization_id)
    with pytest.raises(Exception, match="Insufficient organization role"):
        FindingService(session).transition(
            viewer_context, viewer, finding.id, "ACKNOWLEDGED", "corr"
        )
    foreign_context, foreign_user, _ = _context(session, "viewer")
    with pytest.raises(FindingStateError, match="not found"):
        FindingService(session).transition(
            foreign_context, foreign_user, finding.id, "OPEN", "corr"
        )


def test_exception_expiry_reopens_only_the_existing_finding(session: Session) -> None:
    context, principal, asset = _context(session, "reviewer")
    service = FindingService(session)
    finding = service.record_match(
        context.organization_id, _match(asset, datetime(2026, 1, 20, tzinfo=UTC))
    )
    service.transition(
        context,
        principal,
        finding.id,
        "EXCEPTION",
        "corr-exception",
        reason="accepted temporary exception",
        exception_expires_at=datetime(2026, 1, 21, tzinfo=UTC),
    )
    reopened = service.reopen_expired_exceptions(
        context.organization_id, datetime(2026, 1, 22, tzinfo=UTC), "corr-expiry"
    )
    assert reopened == [finding] and finding.state == "OPEN"
    assert session.scalar(
        select(FindingStateEvent).where(FindingStateEvent.reason == "exception_expired")
    )


def test_repeated_evaluation_is_one_finding_with_temporal_evidence_and_recurrence_history(
    session: Session,
) -> None:
    context, principal, asset = _context(session)
    service = FindingService(session)
    later = datetime(2026, 1, 22, tzinfo=UTC)
    first = datetime(2026, 1, 20, tzinfo=UTC)
    older = datetime(2026, 1, 19, tzinfo=UTC)
    first_evidence = _evidence(session, asset, first)
    later_evidence = _evidence(session, asset, later)
    finding = service.record_match(
        context.organization_id, _match(asset, first, (first_evidence.id,))
    )
    same = service.record_match(context.organization_id, _match(asset, first, (first_evidence.id,)))
    updated = service.record_match(
        context.organization_id, _match(asset, later, (later_evidence.id,))
    )
    historical = service.record_match(
        context.organization_id, _match(asset, older, (first_evidence.id,))
    )
    assert finding.id == same.id == updated.id == historical.id
    assert finding.first_seen == older and finding.last_seen == later
    assert len(list(session.scalars(select(FindingEvidenceLink)))) == 2
    assert len(list(session.scalars(select(FindingEvaluationEvent)))) == 4
    service.transition(context, principal, finding.id, "IN_PROGRESS", "corr-in-progress")
    service.transition(
        context, principal, finding.id, "RESOLVED_PENDING_VERIFICATION", "corr-resolved"
    )
    service.transition(
        context, principal, finding.id, "CLOSED", "corr-close", verification_reference="fixture"
    )
    recurrence = service.record_match(
        context.organization_id, _match(asset, later + timedelta(days=1))
    )
    assert recurrence.state == "OPEN"
    assert session.scalar(
        select(FindingStateEvent).where(FindingStateEvent.reason == "recurrence_detected")
    )


def test_same_rule_different_asset_has_distinct_fingerprint(session: Session) -> None:
    context, _, asset = _context(session)
    other = Asset(
        id=uuid4(),
        organization_id=context.organization_id,
        asset_type="SERVICE",
        canonical_key=f"service:{uuid4()}",
        display_name="second service",
        first_seen=datetime(2026, 1, 20, tzinfo=UTC),
        last_seen=datetime(2026, 1, 20, tzinfo=UTC),
    )
    session.add(other)
    service = FindingService(session)
    one = service.record_match(
        context.organization_id, _match(asset, datetime(2026, 1, 20, tzinfo=UTC))
    )
    two = service.record_match(
        context.organization_id, _match(other, datetime(2026, 1, 20, tzinfo=UTC))
    )
    assert one.fingerprint != two.fingerprint
    assert len(list(session.scalars(select(Finding)))) == 2
