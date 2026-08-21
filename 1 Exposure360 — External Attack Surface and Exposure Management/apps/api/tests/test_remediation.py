import pytest

from exposure360_api.remediation import (
    RemediationState,
    RemediationTransitionError,
    validate_transition,
    verification_transition,
)


def test_remediation_state_machine_allows_reviewed_workflow() -> None:
    validate_transition(RemediationState.OPEN, RemediationState.IN_PROGRESS)
    validate_transition(
        RemediationState.IN_PROGRESS, RemediationState.RESOLVED_PENDING_VERIFICATION
    )
    assert (
        verification_transition(RemediationState.RESOLVED_PENDING_VERIFICATION)
        is RemediationState.VERIFIED
    )
    validate_transition(RemediationState.VERIFIED, RemediationState.CLOSED)


def test_remediation_state_machine_denies_direct_close_and_verification_bypass() -> None:
    with pytest.raises(RemediationTransitionError):
        validate_transition(RemediationState.IN_PROGRESS, RemediationState.CLOSED)
    with pytest.raises(RemediationTransitionError):
        validate_transition(
            RemediationState.RESOLVED_PENDING_VERIFICATION, RemediationState.VERIFIED
        )
    with pytest.raises(RemediationTransitionError):
        verification_transition(RemediationState.IN_PROGRESS)
