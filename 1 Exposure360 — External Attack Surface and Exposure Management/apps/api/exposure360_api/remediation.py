"""Phase 7 remediation workflow state machine; source changes are never executed here."""

from __future__ import annotations

from enum import StrEnum


class RemediationState(StrEnum):
    OPEN = "OPEN"
    PLANNED = "PLANNED"
    IN_PROGRESS = "IN_PROGRESS"
    BLOCKED = "BLOCKED"
    RESOLVED_PENDING_VERIFICATION = "RESOLVED_PENDING_VERIFICATION"
    VERIFIED = "VERIFIED"
    CLOSED = "CLOSED"
    CANCELLED = "CANCELLED"


_TRANSITIONS: dict[RemediationState, frozenset[RemediationState]] = {
    RemediationState.OPEN: frozenset(
        {
            RemediationState.PLANNED,
            RemediationState.IN_PROGRESS,
            RemediationState.BLOCKED,
            RemediationState.CANCELLED,
        }
    ),
    RemediationState.PLANNED: frozenset(
        {RemediationState.IN_PROGRESS, RemediationState.BLOCKED, RemediationState.CANCELLED}
    ),
    RemediationState.IN_PROGRESS: frozenset(
        {
            RemediationState.BLOCKED,
            RemediationState.RESOLVED_PENDING_VERIFICATION,
            RemediationState.CANCELLED,
        }
    ),
    RemediationState.BLOCKED: frozenset(
        {RemediationState.PLANNED, RemediationState.IN_PROGRESS, RemediationState.CANCELLED}
    ),
    RemediationState.RESOLVED_PENDING_VERIFICATION: frozenset(
        {RemediationState.IN_PROGRESS, RemediationState.BLOCKED}
    ),
    RemediationState.VERIFIED: frozenset({RemediationState.CLOSED}),
    RemediationState.CLOSED: frozenset({RemediationState.OPEN}),
    RemediationState.CANCELLED: frozenset({RemediationState.OPEN}),
}


class RemediationTransitionError(ValueError):
    pass


def validate_transition(current: RemediationState, target: RemediationState) -> None:
    if target not in _TRANSITIONS[current]:
        raise RemediationTransitionError(f"invalid remediation transition {current} to {target}")


def verification_transition(current: RemediationState) -> RemediationState:
    if current is not RemediationState.RESOLVED_PENDING_VERIFICATION:
        raise RemediationTransitionError(
            "verification requires resolved-pending-verification state"
        )
    return RemediationState.VERIFIED
