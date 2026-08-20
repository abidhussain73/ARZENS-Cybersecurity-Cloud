from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from exposure360_api import approved_changes
from exposure360_api.approved_changes import ApprovedChangeService, SignificanceScorer
from exposure360_api.db import Base
from exposure360_api.models import Asset, AuditEvent, ChangeEvent, Membership, Organization, User
from exposure360_api.security import OrganizationContext, Principal

NOW = datetime(2026, 8, 20, 1, 30, tzinfo=UTC)


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


def _context(session: Session, slug_prefix: str) -> tuple[OrganizationContext, Principal, Asset]:
    organization = Organization(id=uuid4(), name=slug_prefix, slug=f"{slug_prefix}-{uuid4()}")
    user = User(
        id=uuid4(),
        oidc_subject=f"{slug_prefix}-{uuid4()}",
        email=None,
        display_name="reviewer",
    )
    membership = Membership(
        id=uuid4(), organization_id=organization.id, user_id=user.id, role="reviewer"
    )
    asset = Asset(
        id=uuid4(),
        organization_id=organization.id,
        asset_type="SERVICE",
        canonical_key=f"service:{uuid4()}",
        display_name="fixture service",
        first_seen=NOW,
        last_seen=NOW,
    )
    session.add_all([organization, user])
    session.commit()
    session.add_all([membership, asset])
    session.commit()
    return OrganizationContext(organization.id, membership), Principal(user), asset


def _event(
    context: OrganizationContext,
    asset: Asset,
    change_type: str = "CERTIFICATE",
    details: dict[str, object] | None = None,
) -> ChangeEvent:
    return ChangeEvent(
        id=uuid4(),
        organization_id=context.organization_id,
        asset_id=asset.id,
        change_type=change_type,
        fingerprint=str(uuid4()).replace("-", "") * 2,
        from_snapshot_id=None,
        to_snapshot_id=None,
        summary=f"{change_type}: fixture",
        details_json={"component_key": "certificate"} | (details or {}),
        first_seen=NOW,
        last_seen=NOW,
        state="OBSERVED",
    )


def _approval(
    service: ApprovedChangeService,
    context: OrganizationContext,
    principal: Principal,
    asset: Asset,
    *,
    change_types: tuple[str, ...] = ("CERTIFICATE",),
    starts_at: datetime = NOW - timedelta(hours=1),
    ends_at: datetime = NOW + timedelta(hours=1),
) -> None:
    service.create(
        context,
        principal,
        name="Certificate maintenance",
        description="Fixture certificate rotation",
        asset_id=asset.id,
        allowed_change_types=change_types,
        starts_at=starts_at,
        ends_at=ends_at,
        reason="Authorized maintenance",
        correlation_id="approval-create",
    )


def test_matching_approval_suppresses_but_retains_event_and_audits(session: Session) -> None:
    context, principal, asset = _context(session, "matching")
    service = ApprovedChangeService(session)
    _approval(service, context, principal, asset)
    event_item = _event(context, asset)
    session.add(event_item)
    session.flush()

    returned = service.apply_suppression(context, principal, event_item.id, NOW, "suppression")
    session.commit()

    assert returned.state == "EXPECTED"
    assert returned.approved_change_id is not None
    assert returned.significance_score == 55
    assert session.get(ChangeEvent, event_item.id) is not None
    assert session.scalar(select(func.count(ChangeEvent.id))) == 1
    assert session.scalar(
        select(AuditEvent).where(AuditEvent.action == "change_event.suppressed_expected")
    )


@pytest.mark.parametrize(
    ("event_type", "starts_at", "ends_at"),
    [
        ("SERVICE", NOW - timedelta(hours=1), NOW + timedelta(hours=1)),
        ("CERTIFICATE", NOW + timedelta(minutes=1), NOW + timedelta(hours=1)),
        ("CERTIFICATE", NOW - timedelta(hours=2), NOW),
    ],
)
def test_wrong_type_or_time_window_does_not_suppress(
    session: Session, event_type: str, starts_at: datetime, ends_at: datetime
) -> None:
    context, principal, asset = _context(session, f"type-window-{event_type}-{starts_at.hour}")
    service = ApprovedChangeService(session)
    _approval(service, context, principal, asset, starts_at=starts_at, ends_at=ends_at)
    event_item = _event(context, asset, event_type)
    session.add(event_item)
    session.flush()

    returned = service.apply_suppression(context, principal, event_item.id, NOW, "no-suppression")

    assert returned.state == "OBSERVED"
    assert returned.approved_change_id is None
    assert returned.significance_score is not None
    assert (
        session.scalar(
            select(AuditEvent).where(AuditEvent.action == "change_event.suppressed_expected")
        )
        is None
    )


def test_wrong_asset_and_cross_organization_approval_are_not_usable(session: Session) -> None:
    context, principal, asset = _context(session, "origin")
    foreign_context, foreign_principal, foreign_asset = _context(session, "other")
    unrelated_asset = Asset(
        id=uuid4(),
        organization_id=context.organization_id,
        asset_type="SERVICE",
        canonical_key=f"service:{uuid4()}",
        display_name="unrelated fixture service",
        first_seen=NOW,
        last_seen=NOW,
    )
    session.add(unrelated_asset)
    session.flush()
    service = ApprovedChangeService(session)
    _approval(service, context, principal, unrelated_asset)
    _approval(ApprovedChangeService(session), foreign_context, foreign_principal, foreign_asset)
    event_item = _event(context, asset)
    session.add(event_item)
    session.flush()

    returned = service.apply_suppression(context, principal, event_item.id, NOW, "wrong-asset")

    assert returned.state == "OBSERVED"
    assert returned.approved_change_id is None


def test_disabled_approval_no_longer_suppresses(session: Session) -> None:
    context, principal, asset = _context(session, "disabled")
    service = ApprovedChangeService(session)
    _approval(service, context, principal, asset)
    approval = session.scalar(select(approved_changes.ApprovedChange))
    assert approval is not None
    service.disable(context, principal, approval.id, "approval-disable")
    event_item = _event(context, asset)
    session.add(event_item)
    session.flush()

    returned = service.apply_suppression(context, principal, event_item.id, NOW, "disabled-window")

    assert returned.state == "OBSERVED"
    assert (
        session.scalar(select(AuditEvent).where(AuditEvent.action == "change_approval.disable"))
        is not None
    )


def test_significance_is_deterministic_explainable_and_clamped(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    context, _, asset = _context(session, "scoring")
    event_item = _event(
        context,
        asset,
        "SERVICE",
        {"evidence_confidence": 0.9, "externally_active": True},
    )
    scorer = SignificanceScorer()

    first = scorer.score(event_item)
    second = scorer.score(event_item)

    assert first == second
    assert first.score == 92
    assert first.model_version == "change-significance-v1"
    assert {factor["factor"] for factor in first.factors} == {
        "SERVICE_CHANGE",
        "HIGH_EVIDENCE_CONFIDENCE",
        "CURRENT_EXTERNAL_SERVICE",
    }
    monkeypatch.setitem(approved_changes._BASE_WEIGHTS, "SERVICE", 200)
    clamped = scorer.score(event_item)
    assert clamped.score == 100
    assert {factor["factor"] for factor in clamped.factors} >= {"SERVICE_CHANGE", "SCORE_CLAMP"}
