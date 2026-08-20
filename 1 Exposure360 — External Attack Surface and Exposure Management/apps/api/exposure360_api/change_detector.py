"""Pure typed comparisons for compatible canonical asset snapshots."""

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Asset, ChangeEvent

ChangeType = Literal["NEW", "REMOVED", "SERVICE", "CERTIFICATE", "OWNERSHIP", "FINGERPRINT"]


@dataclass(frozen=True)
class DetectedChange:
    change_type: ChangeType
    component_key: str
    old: object | None
    new: object | None


class ChangeDetector:
    def compare(
        self, previous: dict[str, object] | None, current: dict[str, object] | None
    ) -> tuple[DetectedChange, ...]:
        if previous is None and current is None:
            return ()
        if previous is None:
            assert current is not None
            asset = cast(dict[str, object], current["asset"])
            return (DetectedChange("NEW", str(asset["canonical_key"]), None, current),)
        if current is None:
            asset = cast(dict[str, object], previous["asset"])
            return (DetectedChange("REMOVED", str(asset["canonical_key"]), previous, None),)
        if previous.get("schema_version") != current.get("schema_version"):
            raise ValueError("incompatible snapshot schema versions")
        changes: list[DetectedChange] = []
        if previous.get("ownership") != current.get("ownership"):
            changes.append(
                DetectedChange(
                    "OWNERSHIP", "ownership", previous.get("ownership"), current.get("ownership")
                )
            )
        if previous.get("technologies") != current.get("technologies"):
            changes.append(
                DetectedChange(
                    "FINGERPRINT",
                    "technologies",
                    previous.get("technologies"),
                    current.get("technologies"),
                )
            )
        if previous.get("services") != current.get("services"):
            changes.append(
                DetectedChange(
                    "SERVICE", "services", previous.get("services"), current.get("services")
                )
            )
        return tuple(changes)


class ChangeEventRepository:
    def __init__(self, session: Session):
        self._session = session

    def persist(
        self,
        organization_id: uuid.UUID,
        asset_id: uuid.UUID,
        detected: DetectedChange,
        observed_at: datetime,
        *,
        from_snapshot_id: uuid.UUID | None = None,
        to_snapshot_id: uuid.UUID | None = None,
    ) -> ChangeEvent:
        asset = self._session.scalar(
            select(Asset).where(Asset.id == asset_id, Asset.organization_id == organization_id)
        )
        if asset is None:
            raise ValueError("asset not found in organization")
        details = {
            "component_key": detected.component_key,
            "old": detected.old,
            "new": detected.new,
        }
        fingerprint = _fingerprint(asset.canonical_key, detected.change_type, details)
        event = self._session.scalar(
            select(ChangeEvent).where(
                ChangeEvent.organization_id == organization_id,
                ChangeEvent.fingerprint == fingerprint,
            )
        )
        when = _utc(observed_at)
        if event is not None:
            event.first_seen = min(_utc(event.first_seen), when)
            event.last_seen = max(_utc(event.last_seen), when)
            return event
        event = ChangeEvent(
            organization_id=organization_id,
            asset_id=asset_id,
            change_type=detected.change_type,
            fingerprint=fingerprint,
            from_snapshot_id=from_snapshot_id,
            to_snapshot_id=to_snapshot_id,
            summary=f"{detected.change_type}: {detected.component_key}",
            details_json=details,
            first_seen=when,
            last_seen=when,
            state="OBSERVED",
        )
        self._session.add(event)
        return event


def _fingerprint(asset_key: str, change_type: ChangeType, details: dict[str, object]) -> str:
    material = {"asset_key": asset_key, "change_type": change_type, "details": details}
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
