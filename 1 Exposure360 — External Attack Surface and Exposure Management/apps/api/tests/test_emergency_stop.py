import uuid
from datetime import UTC, datetime
from typing import cast

import pytest
from sqlalchemy.orm import Session

from exposure360_api.emergency_stop import EmergencyStopService
from exposure360_api.models import EmergencyStopState


class ScalarCollection:
    def __init__(self, values: list[EmergencyStopState]) -> None:
        self.values = values

    def all(self) -> list[EmergencyStopState]:
        return self.values


class FakeSession:
    def __init__(self, scalar_value: EmergencyStopState | None = None) -> None:
        self.scalar_value = scalar_value
        self.added: list[EmergencyStopState] = []
        self.flushed = False
        self.status_states: list[EmergencyStopState] = []

    def scalar(self, _statement: object) -> EmergencyStopState | None:
        return self.scalar_value

    def scalars(self, _statement: object) -> ScalarCollection:
        return ScalarCollection(self.status_states)

    def add(self, entity: EmergencyStopState) -> None:
        self.added.append(entity)

    def flush(self) -> None:
        self.flushed = True


def test_organization_stop_creates_new_state() -> None:
    session = FakeSession()
    actor_id = uuid.uuid4()
    state = EmergencyStopService.set_stop(
        cast(Session, session),
        organization_id=uuid.uuid4(),
        scope_id=None,
        actor_id=actor_id,
        reason="operator requested global halt",
        now=datetime(2026, 8, 19, tzinfo=UTC),
    )

    assert state.level == "ORGANIZATION"
    assert state.is_stopped is True
    assert state.stop_generation == 1
    assert state.stopped_by_user_id == actor_id
    assert session.added == [state]
    assert session.flushed is True


def test_repeated_stop_increments_generation_for_inflight_invalidation() -> None:
    state = EmergencyStopState(
        organization_id=uuid.uuid4(),
        scope_id=uuid.uuid4(),
        level="SCOPE",
        is_stopped=False,
        stop_generation=4,
    )
    session = FakeSession(state)

    updated = EmergencyStopService.set_stop(
        cast(Session, session),
        organization_id=state.organization_id,
        scope_id=state.scope_id,
        actor_id=uuid.uuid4(),
        reason="scope halt",
    )

    assert updated.is_stopped is True
    assert updated.stop_generation == 5
    assert updated.reason == "scope halt"


def test_organization_stop_takes_precedence_over_scope_stop() -> None:
    organization_id = uuid.uuid4()
    scope_id = uuid.uuid4()
    org_state = EmergencyStopState(
        organization_id=organization_id,
        scope_id=None,
        level="ORGANIZATION",
        is_stopped=True,
        stop_generation=2,
    )
    scope_state = EmergencyStopState(
        organization_id=organization_id,
        scope_id=scope_id,
        level="SCOPE",
        is_stopped=True,
        stop_generation=9,
    )
    session = FakeSession()
    session.status_states = [scope_state, org_state]

    status = EmergencyStopService.status(
        cast(Session, session), organization_id=organization_id, scope_id=scope_id
    )

    assert status.active is True
    assert status.level == "ORGANIZATION"
    assert status.generation == 2


def test_resume_updates_existing_state_and_missing_state_is_rejected() -> None:
    state = EmergencyStopState(
        organization_id=uuid.uuid4(),
        scope_id=None,
        level="ORGANIZATION",
        is_stopped=True,
        stop_generation=1,
    )
    session = FakeSession(state)
    actor_id = uuid.uuid4()

    resumed = EmergencyStopService.resume(
        cast(Session, session),
        organization_id=state.organization_id,
        scope_id=None,
        actor_id=actor_id,
        now=datetime(2026, 8, 19, tzinfo=UTC),
    )

    assert resumed.is_stopped is False
    assert resumed.resumed_by_user_id == actor_id
    with pytest.raises(ValueError, match="does not exist"):
        EmergencyStopService.resume(
            cast(Session, FakeSession()),
            organization_id=uuid.uuid4(),
            scope_id=None,
            actor_id=actor_id,
        )
