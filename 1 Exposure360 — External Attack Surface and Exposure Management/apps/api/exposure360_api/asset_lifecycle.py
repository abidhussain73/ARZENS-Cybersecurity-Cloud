from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from .models import Asset, AssetFreshnessPolicy

DEFAULT_FRESHNESS_POLICY_VERSION = "phase4-default-freshness-v1"
DEFAULT_STALE_AFTER_SECONDS = {
    "DOMAIN": 30 * 24 * 60 * 60,
    "IP": 30 * 24 * 60 * 60,
    "ASN": 90 * 24 * 60 * 60,
    "ENDPOINT": 14 * 24 * 60 * 60,
    "SERVICE": 14 * 24 * 60 * 60,
}


class AssetLifecycleError(ValueError):
    """Raised when lifecycle input would corrupt temporal truth."""


@dataclass(frozen=True)
class LifecycleUpdateResult:
    lifecycle_state: str
    reactivation_review_required: bool


class AssetLifecycleService:
    """Applies canonical temporal and conservative lifecycle semantics in one place."""

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] | None = None,
        max_future_skew: timedelta = timedelta(days=1),
    ) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))
        self._max_future_skew = max_future_skew

    def apply_observation(
        self,
        session: Session,
        *,
        asset: Asset,
        observed_at: datetime,
        directly_confirmed: bool,
    ) -> LifecycleUpdateResult:
        observed = self._validate_timestamp(observed_at)
        asset.first_seen = min(self._as_utc(asset.first_seen), observed)
        asset.last_seen = max(self._as_utc(asset.last_seen), observed)
        if directly_confirmed:
            confirmed_at = asset.last_confirmed_at
            asset.last_confirmed_at = (
                observed if confirmed_at is None else max(self._as_utc(confirmed_at), observed)
            )
        if asset.lifecycle_state == "RETIRED":
            return LifecycleUpdateResult("RETIRED", True)
        asset.lifecycle_state = self._state_for(session, asset, now=self._as_utc(self._clock()))
        return LifecycleUpdateResult(asset.lifecycle_state, False)

    def retire(self, asset: Asset) -> None:
        asset.lifecycle_state = "RETIRED"

    def refresh_state(self, session: Session, asset: Asset) -> str:
        if asset.lifecycle_state != "RETIRED":
            asset.lifecycle_state = self._state_for(session, asset, now=self._as_utc(self._clock()))
        return asset.lifecycle_state

    def _state_for(self, session: Session, asset: Asset, *, now: datetime) -> str:
        stale_after = self._stale_after(session, asset.organization_id, asset.asset_type)
        return "STALE" if now - self._as_utc(asset.last_seen) > stale_after else "ACTIVE"

    def _stale_after(self, session: Session, organization_id: UUID, asset_type: str) -> timedelta:
        policy = session.scalar(
            select(AssetFreshnessPolicy)
            .where(
                AssetFreshnessPolicy.organization_id == organization_id,
                AssetFreshnessPolicy.asset_type == asset_type,
                AssetFreshnessPolicy.is_active.is_(True),
            )
            .order_by(
                desc(AssetFreshnessPolicy.created_at),
                desc(AssetFreshnessPolicy.policy_version),
            )
        )
        seconds = (
            policy.stale_after_seconds
            if policy is not None
            else DEFAULT_STALE_AFTER_SECONDS[asset_type]
        )
        return timedelta(seconds=seconds)

    def _validate_timestamp(self, value: datetime) -> datetime:
        observed = self._as_utc(value)
        if observed.year < 2000:
            raise AssetLifecycleError("observed_at is implausibly old")
        if observed > self._as_utc(self._clock()) + self._max_future_skew:
            raise AssetLifecycleError("observed_at is implausibly far in the future")
        return observed

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise AssetLifecycleError("timestamps must be timezone-aware")
        return value.astimezone(UTC)
