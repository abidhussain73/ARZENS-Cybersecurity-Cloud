"""Provider-neutral Phase 6 external-context import contracts and normalization."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Asset
from .relationships import (
    ASSET,
    CONTEXT,
    ExternalContextRepository,
    GraphNodeReference,
    RelationshipInput,
    RelationshipRepository,
)

CONTEXT_TYPES = {"IDENTITY", "CLOUD_RESOURCE", "APPLICATION", "DATA", "VULNERABILITY"}


class ExternalContextContract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ExternalContextEntityContract(ExternalContextContract):
    context_type: str
    source_native_id: str | None = Field(default=None, max_length=512)
    canonical_key: str = Field(min_length=1, max_length=2048)
    display_name: str = Field(min_length=1, max_length=2048)
    confidence: float = Field(ge=0, le=1)
    metadata: dict[str, object] = Field(default_factory=dict)

    @field_validator("context_type")
    @classmethod
    def allow_only_bounded_context_types(cls, value: str) -> str:
        if value not in CONTEXT_TYPES:
            raise ValueError("unsupported external context type")
        return value


class ExternalNodeReference(ExternalContextContract):
    kind: str = Field(pattern=r"^(EXPOSURE_ASSET|EXTERNAL_CONTEXT)$")
    canonical_key: str = Field(min_length=1, max_length=2048)


class ExternalRelationshipContract(ExternalContextContract):
    relationship_type: str = Field(min_length=1, max_length=128)
    source_ref: ExternalNodeReference
    target_ref: ExternalNodeReference
    observed_at: datetime
    confidence: float = Field(ge=0, le=1)
    source_record_key: str | None = Field(default=None, max_length=512)
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    metadata: dict[str, object] = Field(default_factory=dict)

    @field_validator("observed_at", "valid_from", "valid_to")
    @classmethod
    def require_utc_aware_time(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("external context timestamps must be timezone-aware")
        return value


class ExternalContextBatch(ExternalContextContract):
    source_namespace: str = Field(min_length=1, max_length=128)
    adapter_version: str = Field(min_length=1, max_length=64)
    source_snapshot_id: str = Field(min_length=1, max_length=255)
    source_observed_at: datetime
    retrieved_at: datetime
    entities: list[ExternalContextEntityContract] = Field(max_length=1000)
    relationships: list[ExternalRelationshipContract] = Field(max_length=5000)
    next_checkpoint: dict[str, object] | None = None
    partial: bool = False
    warnings: list[str] = Field(default_factory=list, max_length=100)

    @field_validator("source_observed_at", "retrieved_at")
    @classmethod
    def require_aware_batch_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("batch timestamps must be timezone-aware")
        return value

    @property
    def source_snapshot_hash(self) -> str:
        material = self.model_dump(mode="json", exclude={"next_checkpoint", "warnings"})
        return hashlib.sha256(
            json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()


class ExternalContextImportAdapter(Protocol):
    source_namespace: str
    adapter_version: str

    def capabilities(self) -> set[str]: ...

    def validate(self, batch: ExternalContextBatch) -> None: ...

    def normalize_entities(
        self, batch: ExternalContextBatch
    ) -> list[ExternalContextEntityContract]: ...

    def normalize_relationships(
        self, batch: ExternalContextBatch
    ) -> list[ExternalRelationshipContract]: ...


class FixtureExternalContextAdapter:
    """Safe deterministic adapter used only with supplied synthetic acceptance fixtures."""

    source_namespace = "fixture-context"
    adapter_version = "fixture-external-context-v1"

    def capabilities(self) -> set[str]:
        return set(CONTEXT_TYPES)

    def validate(self, batch: ExternalContextBatch) -> None:
        if batch.source_namespace != self.source_namespace:
            raise ValueError("fixture adapter source namespace mismatch")

    def normalize_entities(
        self, batch: ExternalContextBatch
    ) -> list[ExternalContextEntityContract]:
        self.validate(batch)
        return sorted(batch.entities, key=lambda item: (item.context_type, item.canonical_key))

    def normalize_relationships(
        self, batch: ExternalContextBatch
    ) -> list[ExternalRelationshipContract]:
        self.validate(batch)
        return sorted(
            batch.relationships,
            key=lambda item: (
                item.relationship_type,
                item.source_ref.kind,
                item.source_ref.canonical_key,
                item.target_ref.kind,
                item.target_ref.canonical_key,
            ),
        )


class ExternalContextImportService:
    """Persists a validated batch under trusted job context, never source-supplied tenancy."""

    def __init__(self, session: Session, adapter: ExternalContextImportAdapter):
        self._session = session
        self._adapter = adapter

    def import_batch(self, organization_id: uuid.UUID, batch: ExternalContextBatch) -> int:
        self._adapter.validate(batch)
        contexts = ExternalContextRepository(self._session)
        relationships = RelationshipRepository(self._session)
        nodes: dict[tuple[str, str], GraphNodeReference] = {}
        for item in self._adapter.normalize_entities(batch):
            entity = contexts.upsert(
                organization_id,
                context_type=item.context_type,
                canonical_key=item.canonical_key,
                display_name=item.display_name,
                source_namespace=batch.source_namespace,
                source_native_id=item.source_native_id,
                confidence=item.confidence,
                observed_at=batch.source_observed_at,
                metadata=item.metadata,
            )
            nodes[("EXTERNAL_CONTEXT", item.canonical_key)] = GraphNodeReference(CONTEXT, entity.id)
        for canonical_key, asset_id in self._session.execute(
            select(Asset.canonical_key, Asset.id).where(Asset.organization_id == organization_id)
        ):
            nodes[("EXPOSURE_ASSET", canonical_key)] = GraphNodeReference(ASSET, asset_id)
        imported = 0
        for relationship_item in self._adapter.normalize_relationships(batch):
            source = nodes.get(
                (relationship_item.source_ref.kind, relationship_item.source_ref.canonical_key)
            )
            target = nodes.get(
                (relationship_item.target_ref.kind, relationship_item.target_ref.canonical_key)
            )
            if source is None or target is None:
                raise ValueError(
                    "external relationship endpoint cannot be resolved in organization"
                )
            relationship = relationships.upsert_relationship(
                organization_id,
                RelationshipInput(
                    relationship_type=relationship_item.relationship_type,
                    source=source,
                    target=target,
                    confidence=relationship_item.confidence,
                    observed_at=relationship_item.observed_at,
                    valid_from=relationship_item.valid_from or relationship_item.observed_at,
                    valid_to=relationship_item.valid_to,
                    source_system=batch.source_namespace,
                    source_record_key=relationship_item.source_record_key,
                    metadata=relationship_item.metadata,
                ),
            )
            relationships.link_provenance(
                organization_id,
                relationship.id,
                source_context_record_hash=batch.source_snapshot_hash,
            )
            imported += 1
        return imported
