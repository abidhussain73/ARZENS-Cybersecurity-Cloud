from datetime import UTC, datetime, timedelta

from exposure360_api.verified_controls import (
    MAX_GLOBAL_CONTROL_REDUCTION,
    ControlState,
    VerifiedControlInput,
    VerifiedControlReducer,
)

NOW = datetime(2026, 8, 21, tzinfo=UTC)


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
