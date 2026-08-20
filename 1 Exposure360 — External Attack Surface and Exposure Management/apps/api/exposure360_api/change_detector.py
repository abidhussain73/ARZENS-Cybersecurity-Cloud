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
            normalized_current = _normalize_snapshot(current)
            asset = cast(dict[str, object], normalized_current["asset"])
            return (DetectedChange("NEW", str(asset["canonical_key"]), None, normalized_current),)
        if current is None:
            normalized_previous = _normalize_snapshot(previous)
            asset = cast(dict[str, object], normalized_previous["asset"])
            return (
                DetectedChange("REMOVED", str(asset["canonical_key"]), normalized_previous, None),
            )
        normalized_previous = _normalize_snapshot(previous)
        normalized_current = _normalize_snapshot(current)
        if normalized_previous.get("schema_version") != normalized_current.get("schema_version"):
            raise ValueError("incompatible snapshot schema versions")
        changes: list[DetectedChange] = []
        if normalized_previous.get("ownership") != normalized_current.get("ownership"):
            changes.append(
                DetectedChange(
                    "OWNERSHIP",
                    "ownership",
                    normalized_previous.get("ownership"),
                    normalized_current.get("ownership"),
                )
            )
        if normalized_previous.get("technologies") != normalized_current.get("technologies"):
            changes.append(
                DetectedChange(
                    "FINGERPRINT",
                    "technologies",
                    normalized_previous.get("technologies"),
                    normalized_current.get("technologies"),
                )
            )
        old_services = normalized_previous.get("services")
        new_services = normalized_current.get("services")
        if _certificate_projections(old_services) == _certificate_projections(new_services):
            service_changed = old_services != new_services
        else:
            changes.append(DetectedChange("CERTIFICATE", "certificate", old_services, new_services))
            service_changed = _without_certificates(old_services) != _without_certificates(
                new_services
            )
        if service_changed:
            changes.append(DetectedChange("SERVICE", "services", old_services, new_services))
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


def _normalize_snapshot(snapshot: dict[str, object]) -> dict[str, object]:
    return cast(dict[str, object], _normalize_value(snapshot))


def _normalize_value(value: object) -> object:
    if isinstance(value, dict):
        return {key: _normalize_value(item) for key, item in sorted(value.items())}
    if isinstance(value, list | tuple):
        return tuple(sorted((_normalize_value(item) for item in value), key=_canonical_json))
    return value


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _certificate_projections(services: object) -> tuple[object, ...]:
    normalized = cast(tuple[object, ...], services) if isinstance(services, tuple) else ()
    projections: list[object] = []
    for service in normalized:
        if isinstance(service, dict) and "certificate_fingerprint" in service:
            projections.append(
                {
                    "endpoint": service.get("endpoint"),
                    "certificate_fingerprint": service.get("certificate_fingerprint"),
                    "certificate_issuer": service.get("certificate_issuer"),
                    "certificate_not_after": service.get("certificate_not_after"),
                }
            )
    return tuple(sorted(projections, key=_canonical_json))


def _without_certificates(services: object) -> object:
    if not isinstance(services, tuple):
        return services
    stripped: list[object] = []
    for service in services:
        if isinstance(service, dict):
            stripped.append(
                {
                    key: value
                    for key, value in service.items()
                    if key
                    not in {
                        "certificate_fingerprint",
                        "certificate_issuer",
                        "certificate_not_after",
                    }
                }
            )
        else:
            stripped.append(service)
    return tuple(sorted(stripped, key=_canonical_json))
