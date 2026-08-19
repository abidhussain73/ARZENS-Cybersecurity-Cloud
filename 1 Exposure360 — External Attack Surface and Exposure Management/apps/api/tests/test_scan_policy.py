from datetime import UTC, datetime

import pytest

from exposure360_api.config import Settings
from exposure360_api.scan_policy import (
    PolicyEvaluationInput,
    PolicyValidationError,
    ScanPolicyEvaluator,
    ScanPolicySnapshot,
    validate_policy,
)


def policy() -> ScanPolicySnapshot:
    return ScanPolicySnapshot(
        allowed_protocols=("DNS", "HTTPS"),
        max_requests_per_second=2,
        max_concurrent_targets=2,
        max_concurrent_requests=3,
        schedule_timezone="UTC",
        schedule_windows=({"days": ["MON"], "start": "01:00", "end": "05:00"},),
        policy_hash="policy-hash",
    )


def request(**overrides: object) -> PolicyEvaluationInput:
    fields: dict[str, object] = {
        "requested_protocol": "HTTPS",
        "now": datetime(2026, 8, 17, 2, 0, tzinfo=UTC),
        "scope_active": True,
        "approval_valid": True,
        "emergency_stop_active": False,
        "requests_in_current_second": 0,
        "concurrent_targets": 0,
        "concurrent_requests": 0,
    }
    fields.update(overrides)
    return PolicyEvaluationInput(**fields)


def test_policy_allows_authorized_request() -> None:
    decision = ScanPolicyEvaluator.evaluate(policy(), request())
    assert decision.allowed
    assert decision.reason_code == "ALLOWED"


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"requested_protocol": "SSH"}, "PROTOCOL_NOT_ALLOWED"),
        ({"now": datetime(2026, 8, 17, 7, 0, tzinfo=UTC)}, "OUTSIDE_SCHEDULE"),
        ({"requests_in_current_second": 2}, "RATE_LIMIT_EXCEEDED"),
        ({"concurrent_requests": 3}, "CONCURRENCY_LIMIT_EXCEEDED"),
        ({"emergency_stop_active": True}, "EMERGENCY_STOP_ACTIVE"),
    ],
)
def test_policy_denials_are_explicit(overrides: dict[str, object], reason: str) -> None:
    assert ScanPolicyEvaluator.evaluate(policy(), request(**overrides)).reason_code == reason


def test_policy_rejects_invalid_timezone() -> None:
    invalid = ScanPolicySnapshot(
        allowed_protocols=("HTTPS",),
        max_requests_per_second=1,
        max_concurrent_targets=1,
        max_concurrent_requests=1,
        schedule_timezone="Invalid/Timezone",
        schedule_windows=(),
        policy_hash="invalid",
    )
    with pytest.raises(PolicyValidationError):
        validate_policy(invalid, Settings())
