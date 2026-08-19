import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import EmergencyStopState


@dataclass(frozen=True)
class StopStatus:
    active: bool
    generation: int
    level: str | None


class EmergencyStopService:
    @staticmethod
    def set_stop(
        session: Session,
        *,
        organization_id: uuid.UUID,
        scope_id: uuid.UUID | None,
        actor_id: uuid.UUID,
        reason: str,
        now: datetime | None = None,
    ) -> EmergencyStopState:
        now = now or datetime.now(UTC)
        level = "ORGANIZATION" if scope_id is None else "SCOPE"
        state = session.scalar(
            select(EmergencyStopState)
            .where(
                EmergencyStopState.organization_id == organization_id,
                EmergencyStopState.scope_id == scope_id,
                EmergencyStopState.level == level,
            )
            .with_for_update()
        )
        if state is None:
            state = EmergencyStopState(
                organization_id=organization_id,
                scope_id=scope_id,
                level=level,
                is_stopped=True,
                stop_generation=1,
                reason=reason,
                stopped_at=now,
                stopped_by_user_id=actor_id,
            )
            session.add(state)
        else:
            state.is_stopped = True
            state.stop_generation += 1
            state.reason = reason
            state.stopped_at = now
            state.stopped_by_user_id = actor_id
            state.resumed_at = None
            state.resumed_by_user_id = None
        session.flush()
        return state

    @staticmethod
    def resume(
        session: Session,
        *,
        organization_id: uuid.UUID,
        scope_id: uuid.UUID | None,
        actor_id: uuid.UUID,
        now: datetime | None = None,
    ) -> EmergencyStopState:
        now = now or datetime.now(UTC)
        level = "ORGANIZATION" if scope_id is None else "SCOPE"
        state = session.scalar(
            select(EmergencyStopState)
            .where(
                EmergencyStopState.organization_id == organization_id,
                EmergencyStopState.scope_id == scope_id,
                EmergencyStopState.level == level,
            )
            .with_for_update()
        )
        if state is None:
            raise ValueError("Emergency stop state does not exist")
        state.is_stopped = False
        state.resumed_at = now
        state.resumed_by_user_id = actor_id
        session.flush()
        return state

    @staticmethod
    def status(
        session: Session,
        *,
        organization_id: uuid.UUID,
        scope_id: uuid.UUID,
    ) -> StopStatus:
        states = session.scalars(
            select(EmergencyStopState).where(
                EmergencyStopState.organization_id == organization_id,
                EmergencyStopState.is_stopped.is_(True),
            )
        ).all()
        organization_stop = next((state for state in states if state.scope_id is None), None)
        if organization_stop is not None:
            return StopStatus(True, organization_stop.stop_generation, "ORGANIZATION")
        scope_stop = next((state for state in states if state.scope_id == scope_id), None)
        if scope_stop is not None:
            return StopStatus(True, scope_stop.stop_generation, "SCOPE")
        return StopStatus(False, 0, None)
