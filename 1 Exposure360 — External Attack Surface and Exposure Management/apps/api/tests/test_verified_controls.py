from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from exposure360_api.db import Base
from exposure360_api.models import Organization, VerifiedControlEvidence
from exposure360_api.verified_controls import (
    MAX_GLOBAL_CONTROL_REDUCTION,
    ControlState,
    VerifiedControlInput,
    VerifiedControlReducer,
)

NOW = datetime(2026, 8, 21, tzinfo=UTC)


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


def _persisted_control(
    organization_id: UUID,
    finding_id: UUID,
    *,
    state: ControlState = ControlState.VERIFIED,
    verified_at: datetime = NOW,
    expires_at: datetime | None = None,
) -> VerifiedControlEvidence:
    return VerifiedControlEvidence(
        id=uuid4(),
        organization_id=organization_id,
        asset_id=None,
        service_asset_id=None,
        finding_id=finding_id,
        relationship_id=None,
        control_type="AUTHENTICATION_REQUIRED",
        control_key=f"control-{uuid4()}",
        verification_state=state.value,
        effectiveness=0.8,
        confidence=0.75,
        verified_at=verified_at,
        expires_at=expires_at,
        freshness_window_seconds=3600,
        source_type="FIXTURE",
        source_reference="fixture://verified-control",
        metadata_json={"integrity_valid": True},
    )


def _to_input(control: VerifiedControlEvidence) -> VerifiedControlInput:
    return VerifiedControlInput(
        control.control_key,
        str(control.finding_id),
        ControlState(control.verification_state),
        control.effectiveness,
        control.confidence,
        control.verified_at,
        control.freshness_window_seconds,
        control.expires_at,
        bool(control.metadata_json["integrity_valid"]),
    )


def _control(
    state: ControlState = ControlState.VERIFIED,
    *,
    verified_at: datetime = NOW,
    expires_at: datetime | None = None,
    integrity_valid: bool = True,
    effectiveness: float = 0.8,
    confidence: float = 0.75,
) -> VerifiedControlInput:
    return VerifiedControlInput(
        "control-1",
        "finding-1",
        state,
        effectiveness,
        confidence,
        verified_at,
        3600,
        expires_at,
        integrity_valid,
    )


def test_fresh_verified_control_reduces_score_with_global_cap() -> None:
    reducer = VerifiedControlReducer()
    current = reducer.evaluate(_control(), NOW)
    duplicated = reducer.evaluate(_control(), NOW)

    assert current.freshness == "CURRENT"
    assert current.reduction == MAX_GLOBAL_CONTROL_REDUCTION
    assert reducer.adjusted_score(100, (current, duplicated)) == 50


def test_stale_expired_invalid_and_revoked_controls_have_zero_reduction() -> None:
    reducer = VerifiedControlReducer()
    results = (
        reducer.evaluate(_control(verified_at=NOW - timedelta(hours=2)), NOW),
        reducer.evaluate(_control(expires_at=NOW), NOW),
        reducer.evaluate(_control(integrity_valid=False), NOW),
        reducer.evaluate(_control(ControlState.REVOKED), NOW),
    )

    assert [item.reduction for item in results] == [0.0, 0.0, 0.0, 0.0]
    assert [item.reason_code for item in results] == [
        "EVIDENCE_STALE",
        "CONTROL_EXPIRED",
        "EVIDENCE_INVALID",
        "NOT_VERIFIED",
    ]
    assert reducer.adjusted_score(70, results) == 70


def test_persisted_stale_control_remains_visible_but_has_zero_reduction(session: Session) -> None:
    organization = Organization(id=uuid4(), name="Control stale", slug=f"control-{uuid4()}")
    session.add(organization)
    session.flush()
    control = _persisted_control(
        organization.id,
        uuid4(),
        verified_at=NOW - timedelta(hours=2),
    )
    session.add(control)
    session.commit()

    persisted = session.scalar(
        select(VerifiedControlEvidence).where(
            VerifiedControlEvidence.id == control.id,
            VerifiedControlEvidence.organization_id == organization.id,
        )
    )

    assert persisted is not None
    result = VerifiedControlReducer().evaluate(_to_input(persisted), NOW)
    assert result.state is ControlState.STALE
    assert result.reduction == 0.0
    assert result.reason_code == "EVIDENCE_STALE"


def test_organization_scoped_control_selection_excludes_other_organization_and_revoked_is_zero(
    session: Session,
) -> None:
    organization_a = Organization(id=uuid4(), name="Control A", slug=f"control-a-{uuid4()}")
    organization_b = Organization(id=uuid4(), name="Control B", slug=f"control-b-{uuid4()}")
    finding_id = uuid4()
    session.add_all((organization_a, organization_b))
    session.flush()
    first_control = _persisted_control(organization_a.id, finding_id)
    foreign_revoked = _persisted_control(
        organization_b.id,
        finding_id,
        state=ControlState.REVOKED,
    )
    session.add_all((first_control, foreign_revoked))
    session.commit()

    applicable = session.scalars(
        select(VerifiedControlEvidence).where(
            VerifiedControlEvidence.organization_id == organization_a.id,
            VerifiedControlEvidence.finding_id == finding_id,
        )
    ).all()
    revoked_result = VerifiedControlReducer().evaluate(_to_input(foreign_revoked), NOW)

    assert [item.id for item in applicable] == [first_control.id]
    assert revoked_result.state is ControlState.REVOKED
    assert revoked_result.reduction == 0.0
    assert revoked_result.reason_code == "NOT_VERIFIED"
