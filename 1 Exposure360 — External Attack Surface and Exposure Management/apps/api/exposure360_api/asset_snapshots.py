"""Versioned, deterministic canonical asset snapshot serialization."""

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final, cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Asset, AssetSnapshot

SNAPSHOT_SCHEMA_VERSION: Final[int] = 1


@dataclass(frozen=True)
class AssetSnapshotInput:
    asset_type: str
    canonical_key: str
    lifecycle_state: str
    display_last_seen: datetime | None
    ownership: dict[str, object]
    resolved_ips: tuple[str, ...]
    services: tuple[dict[str, object], ...]
    technologies: tuple[dict[str, object], ...]


@dataclass(frozen=True)
class CanonicalSnapshot:
    schema_version: int
    snapshot_json: dict[str, object]
    comparison_projection: dict[str, object]
    snapshot_hash: str


class AssetSnapshotBuilder:
    def build(self, source: AssetSnapshotInput) -> CanonicalSnapshot:
        asset = {
            "type": source.asset_type,
            "canonical_key": source.canonical_key,
            "lifecycle_state": source.lifecycle_state,
        }
        services = tuple(
            sorted(
                (_normalize_service(item) for item in source.services),
                key=_canonical_json,
            )
        )
        technologies = tuple(
            sorted(
                (_normalize_technology(item) for item in source.technologies),
                key=_canonical_json,
            )
        )
        projection: dict[str, object] = {
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "asset": asset,
            "ownership": _normalize_mapping(source.ownership),
            "relationships": {"resolved_ips": sorted(source.resolved_ips)},
            "services": list(services),
            "technologies": list(technologies),
        }
        payload = dict(projection)
        display_last_seen = (
            _utc(source.display_last_seen).isoformat() if source.display_last_seen else None
        )
        payload["display"] = {"last_seen": display_last_seen}
        return CanonicalSnapshot(
            schema_version=SNAPSHOT_SCHEMA_VERSION,
            snapshot_json=payload,
            comparison_projection=projection,
            snapshot_hash=hashlib.sha256(_canonical_json(projection).encode("utf-8")).hexdigest(),
        )


class AssetSnapshotRepository:
    def __init__(self, session: Session):
        self._session = session

    def persist(
        self,
        organization_id: uuid.UUID,
        asset_id: uuid.UUID,
        effective_at: datetime,
        snapshot: CanonicalSnapshot,
        source_evaluation_run_id: uuid.UUID | None = None,
    ) -> AssetSnapshot:
        asset = self._session.scalar(
            select(Asset).where(Asset.id == asset_id, Asset.organization_id == organization_id)
        )
        if asset is None:
            raise ValueError("asset not found in organization")
        when = _utc(effective_at)
        existing = self._session.scalar(
            select(AssetSnapshot).where(
                AssetSnapshot.asset_id == asset_id,
                AssetSnapshot.effective_at == when,
                AssetSnapshot.snapshot_hash == snapshot.snapshot_hash,
            )
        )
        if existing is not None:
            return existing
        record = AssetSnapshot(
            organization_id=organization_id,
            asset_id=asset_id,
            snapshot_schema_version=snapshot.schema_version,
            snapshot_hash=snapshot.snapshot_hash,
            effective_at=when,
            source_evaluation_run_id=source_evaluation_run_id,
            snapshot_json=snapshot.snapshot_json,
        )
        self._session.add(record)
        return record


def _normalize_service(value: dict[str, object]) -> dict[str, object]:
    return _normalize_mapping(value)


def _normalize_technology(value: dict[str, object]) -> dict[str, object]:
    return _normalize_mapping(value)


def _normalize_mapping(value: dict[str, object]) -> dict[str, object]:
    normalized = json.loads(_canonical_json(value))
    return cast(dict[str, object], normalized)


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
