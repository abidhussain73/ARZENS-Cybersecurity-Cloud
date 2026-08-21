"""Evidence-backed Phase 7 control reduction with strict freshness handling."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

VERIFIED_CONTROL_REGISTRY_VERSION = "verified-control-registry-v1"
MAX_GLOBAL_CONTROL_REDUCTION = 0.50


class ControlState(StrEnum):
    VERIFIED = "VERIFIED"
    STALE = "STALE"
    INVALID = "INVALID"
    REVOKED = "REVOKED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class VerifiedControlInput:
    control_id: str
    target_id: str
    state: ControlState
    effectiveness: float
    confidence: float
    verified_at: datetime
    freshness_window_seconds: int
    expires_at: datetime | None
    evidence_integrity_valid: bool


@dataclass(frozen=True)
class ControlReductionResult:
    control_id: str
    state: ControlState
    freshness: str
    reduction: float
    reason_code: str | None


class VerifiedControlReducer:
    def evaluate(
        self, control: VerifiedControlInput, evaluated_at: datetime
    ) -> ControlReductionResult:
        now = self._utc(evaluated_at)
        verified_at = self._utc(control.verified_at)
        if control.state is not ControlState.VERIFIED:
            return ControlReductionResult(
                control.control_id, control.state, "NOT_CURRENT", 0.0, "NOT_VERIFIED"
            )
        if not control.evidence_integrity_valid:
            return ControlReductionResult(
                control.control_id, ControlState.INVALID, "INVALID", 0.0, "EVIDENCE_INVALID"
            )
        if control.expires_at is not None and self._utc(control.expires_at) <= now:
            return ControlReductionResult(
                control.control_id, ControlState.STALE, "EXPIRED", 0.0, "CONTROL_EXPIRED"
            )
        if verified_at + timedelta(seconds=control.freshness_window_seconds) <= now:
            return ControlReductionResult(
                control.control_id, ControlState.STALE, "STALE", 0.0, "EVIDENCE_STALE"
            )
        reduction = min(MAX_GLOBAL_CONTROL_REDUCTION, control.effectiveness * control.confidence)
        return ControlReductionResult(
            control.control_id, ControlState.VERIFIED, "CURRENT", reduction, None
        )

    @staticmethod
    def adjusted_score(raw_score: float, results: tuple[ControlReductionResult, ...]) -> float:
        reduction = min(MAX_GLOBAL_CONTROL_REDUCTION, sum(item.reduction for item in results))
        return round(max(0.0, min(100.0, raw_score * (1 - reduction))), 4)

    @staticmethod
    def _utc(value: datetime) -> datetime:
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
