from dataclasses import dataclass
from datetime import UTC, datetime, time, timedelta
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .config import Settings

PolicyReason = Literal[
    "ALLOWED",
    "PROTOCOL_NOT_ALLOWED",
    "OUTSIDE_SCHEDULE",
    "RATE_LIMIT_EXCEEDED",
    "CONCURRENCY_LIMIT_EXCEEDED",
    "SCOPE_DISABLED",
    "APPROVAL_EXPIRED",
    "EMERGENCY_STOP_ACTIVE",
    "POLICY_INVALID",
]

_SUPPORTED_PROTOCOLS = frozenset({"DNS", "TCP", "TLS", "HTTP", "HTTPS"})
_DAY_NAMES = ("MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN")


class PolicyValidationError(ValueError):
    """Raised when a stored policy cannot be evaluated safely."""


@dataclass(frozen=True)
class ScanPolicySnapshot:
    allowed_protocols: tuple[str, ...]
    max_requests_per_second: float
    max_concurrent_targets: int
    max_concurrent_requests: int
    schedule_timezone: str
    schedule_windows: tuple[dict[str, object], ...]
    policy_hash: str


@dataclass(frozen=True)
class PolicyEvaluationInput:
    requested_protocol: str
    now: datetime
    scope_active: bool
    approval_valid: bool
    emergency_stop_active: bool
    requests_in_current_second: float
    concurrent_targets: int
    concurrent_requests: int


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason_code: PolicyReason
    policy_hash: str


def validate_policy(policy: ScanPolicySnapshot, settings: Settings) -> None:
    protocols = {protocol.upper() for protocol in policy.allowed_protocols}
    if not protocols or not protocols.issubset(_SUPPORTED_PROTOCOLS):
        raise PolicyValidationError("Policy has unsupported protocols")
    if not 0 < policy.max_requests_per_second <= settings.platform_max_requests_per_second:
        raise PolicyValidationError("Policy rate exceeds platform limit")
    if not 1 <= policy.max_concurrent_targets <= settings.platform_max_concurrent_targets:
        raise PolicyValidationError("Policy target concurrency exceeds platform limit")
    if not 1 <= policy.max_concurrent_requests <= settings.platform_max_concurrent_requests:
        raise PolicyValidationError("Policy request concurrency exceeds platform limit")
    try:
        ZoneInfo(policy.schedule_timezone)
    except ZoneInfoNotFoundError as exc:
        raise PolicyValidationError("Policy timezone is invalid") from exc
    for window in policy.schedule_windows:
        _parse_window(window)


def _parse_window(window: dict[str, object]) -> tuple[set[str], time, time]:
    days_raw = window.get("days")
    start_raw = window.get("start")
    end_raw = window.get("end")
    if (
        not isinstance(days_raw, list)
        or not days_raw
        or not all(isinstance(day, str) and day in _DAY_NAMES for day in days_raw)
    ):
        raise PolicyValidationError("Schedule window days are invalid")
    if not isinstance(start_raw, str) or not isinstance(end_raw, str):
        raise PolicyValidationError("Schedule window times are invalid")
    try:
        start = time.fromisoformat(start_raw)
        end = time.fromisoformat(end_raw)
    except ValueError as exc:
        raise PolicyValidationError("Schedule window times are invalid") from exc
    if start == end:
        raise PolicyValidationError("Schedule window start and end must differ")
    return set(days_raw), start, end


def _within_schedule(policy: ScanPolicySnapshot, now: datetime) -> bool:
    if not policy.schedule_windows:
        return True
    localized = now.astimezone(ZoneInfo(policy.schedule_timezone))
    local_time = localized.timetz().replace(tzinfo=None)
    today = _DAY_NAMES[localized.weekday()]
    previous_day = _DAY_NAMES[(localized - timedelta(days=1)).weekday()]
    for window in policy.schedule_windows:
        days, start, end = _parse_window(window)
        if start < end and today in days and start <= local_time < end:
            return True
        if start > end and (
            (today in days and local_time >= start) or (previous_day in days and local_time < end)
        ):
            return True
    return False


class ScanPolicyEvaluator:
    @staticmethod
    def evaluate(policy: ScanPolicySnapshot, request: PolicyEvaluationInput) -> PolicyDecision:
        if request.emergency_stop_active:
            return PolicyDecision(False, "EMERGENCY_STOP_ACTIVE", policy.policy_hash)
        if not request.scope_active:
            return PolicyDecision(False, "SCOPE_DISABLED", policy.policy_hash)
        if not request.approval_valid:
            return PolicyDecision(False, "APPROVAL_EXPIRED", policy.policy_hash)
        if request.requested_protocol.upper() not in set(policy.allowed_protocols):
            return PolicyDecision(False, "PROTOCOL_NOT_ALLOWED", policy.policy_hash)
        if not _within_schedule(policy, request.now):
            return PolicyDecision(False, "OUTSIDE_SCHEDULE", policy.policy_hash)
        if request.requests_in_current_second >= policy.max_requests_per_second:
            return PolicyDecision(False, "RATE_LIMIT_EXCEEDED", policy.policy_hash)
        if (
            request.concurrent_targets >= policy.max_concurrent_targets
            or request.concurrent_requests >= policy.max_concurrent_requests
        ):
            return PolicyDecision(False, "CONCURRENCY_LIMIT_EXCEEDED", policy.policy_hash)
        return PolicyDecision(True, "ALLOWED", policy.policy_hash)


def utc_now() -> datetime:
    return datetime.now(UTC)
