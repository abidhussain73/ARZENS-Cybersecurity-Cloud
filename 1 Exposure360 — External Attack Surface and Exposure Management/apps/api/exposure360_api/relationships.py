"""Phase 6 time-aware, evidence-backed relationship persistence."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .models import (
    Asset,
    ExternalContextEntity,
    Relationship,
    RelationshipEvidenceLink,
)

REGISTRY_VERSION = "relationship-type-registry-v1"
CONFIDENCE_MODEL_VERSION = "relationship-confidence-v1"
ASSET = "ASSET"
CONTEXT = "EXTERNAL_CONTEXT"


class RelationshipError(ValueError):
    """Raised when relationship input would weaken graph safety or tenant isolation."""


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


@dataclass(frozen=True)
class RelationshipTypeDefinition:
    key: str
    source_kinds: frozenset[str]
    target_kinds: frozenset[str]
    category: str
    traversal_default: bool = True
    path_relevance: bool = True
    default_confidence_cap: float = 1.0
    breakable: bool = False


def _definition(
    key: str,
    source_kinds: set[str],
    target_kinds: set[str],
    category: str,
    *,
    breakable: bool = False,
) -> RelationshipTypeDefinition:
    return RelationshipTypeDefinition(
        key=key,
        source_kinds=frozenset(source_kinds),
        target_kinds=frozenset(target_kinds),
        category=category,
        breakable=breakable,
    )


_REGISTRY_ITEMS = (
    _definition("RESOLVES_TO", {ASSET}, {ASSET}, "TECHNICAL"),
    _definition("HAS_ENDPOINT", {ASSET}, {ASSET}, "TECHNICAL"),
    _definition("EXPOSES_SERVICE", {ASSET}, {ASSET}, "TECHNICAL", breakable=True),
    _definition("SERVED_FOR", {ASSET}, {ASSET}, "TECHNICAL"),
    _definition("IDENTITY_CAN_ACCESS_ASSET", {CONTEXT}, {ASSET}, "IDENTITY", breakable=True),
    _definition(
        "IDENTITY_CAN_ACCESS_APPLICATION", {CONTEXT}, {CONTEXT}, "IDENTITY", breakable=True
    ),
    _definition("IDENTITY_OWNS_ASSET", {CONTEXT}, {ASSET}, "IDENTITY"),
    _definition("IDENTITY_ADMINISTERS_ASSET", {CONTEXT}, {ASSET}, "IDENTITY", breakable=True),
    _definition("ASSET_BACKED_BY_CLOUD_RESOURCE", {ASSET}, {CONTEXT}, "CLOUD"),
    _definition("CLOUD_RESOURCE_EXPOSES_ASSET", {CONTEXT}, {ASSET}, "CLOUD", breakable=True),
    _definition(
        "CLOUD_RESOURCE_CONNECTED_TO_CLOUD_RESOURCE", {CONTEXT}, {CONTEXT}, "CLOUD", breakable=True
    ),
    _definition("ASSET_HOSTS_APPLICATION", {ASSET}, {CONTEXT}, "APPLICATION"),
    _definition(
        "APPLICATION_EXPOSED_BY_SERVICE", {CONTEXT}, {ASSET}, "APPLICATION", breakable=True
    ),
    _definition(
        "APPLICATION_DEPENDS_ON_APPLICATION", {CONTEXT}, {CONTEXT}, "APPLICATION", breakable=True
    ),
    _definition("APPLICATION_USES_DATA", {CONTEXT}, {CONTEXT}, "DATA", breakable=True),
    _definition("SERVICE_EXPOSES_DATA_PATH", {ASSET}, {CONTEXT}, "DATA", breakable=True),
    _definition("IDENTITY_CAN_ACCESS_DATA", {CONTEXT}, {CONTEXT}, "DATA", breakable=True),
    _definition("ASSET_HAS_VULNERABILITY", {ASSET}, {CONTEXT}, "VULNERABILITY"),
    _definition("SERVICE_HAS_VULNERABILITY", {ASSET}, {CONTEXT}, "VULNERABILITY"),
    _definition("APPLICATION_HAS_VULNERABILITY", {CONTEXT}, {CONTEXT}, "VULNERABILITY"),
)
RELATIONSHIP_TYPES = {item.key: item for item in _REGISTRY_ITEMS}


@dataclass(frozen=True)
class GraphNodeReference:
    kind: str
    node_id: uuid.UUID


@dataclass(frozen=True)
class RelationshipInput:
    relationship_type: str
    source: GraphNodeReference
    target: GraphNodeReference
    confidence: float
    observed_at: datetime
    valid_from: datetime
    source_system: str
    source_record_key: str | None = None
    valid_to: datetime | None = None
    metadata: dict[str, object] | None = None


class RelationshipIdentityService:
    @staticmethod
    def create(
        organization_id: uuid.UUID,
        relationship_type: str,
        source: GraphNodeReference,
        target: GraphNodeReference,
        source_system: str,
    ) -> str:
        material = {
            "organization_id": str(organization_id),
            "relationship_type": relationship_type,
            "source": {"kind": source.kind, "id": str(source.node_id)},
            "target": {"kind": target.kind, "id": str(target.node_id)},
            "source_system": source_system,
        }
        return hashlib.sha256(
            json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()


class ExternalContextRepository:
    def __init__(self, session: Session):
        self._session = session

    def upsert(
        self,
        organization_id: uuid.UUID,
        *,
        context_type: str,
        canonical_key: str,
        display_name: str,
        source_namespace: str,
        confidence: float,
        observed_at: datetime,
        source_native_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> ExternalContextEntity:
        allowed_context_types = {
            "IDENTITY",
            "CLOUD_RESOURCE",
            "APPLICATION",
            "DATA",
            "VULNERABILITY",
        }
        if context_type not in allowed_context_types:
            raise RelationshipError("unsupported external context type")
        if not 0 <= confidence <= 1:
            raise RelationshipError("external context confidence must be between zero and one")
        entity = self._session.scalar(
            select(ExternalContextEntity).where(
                ExternalContextEntity.organization_id == organization_id,
                ExternalContextEntity.context_type == context_type,
                ExternalContextEntity.canonical_key == canonical_key,
            )
        )
        if entity is None:
            entity = ExternalContextEntity(
                organization_id=organization_id,
                context_type=context_type,
                canonical_key=canonical_key,
                display_name=display_name,
                source_namespace=source_namespace,
                source_native_id=source_native_id,
                confidence=confidence,
                state="ACTIVE",
                first_seen=observed_at,
                last_seen=observed_at,
                metadata_json=metadata or {},
            )
            self._session.add(entity)
            self._session.flush()
            return entity
        entity.last_seen = max(_utc(entity.last_seen), _utc(observed_at))
        entity.confidence = confidence
        entity.display_name = display_name
        entity.metadata_json = metadata or {}
        return entity


class RelationshipRepository:
    def __init__(self, session: Session):
        self._session = session

    def upsert_relationship(
        self, organization_id: uuid.UUID, item: RelationshipInput
    ) -> Relationship:
        definition = RELATIONSHIP_TYPES.get(item.relationship_type)
        if definition is None:
            raise RelationshipError("unsupported relationship type")
        if (
            item.source.kind not in definition.source_kinds
            or item.target.kind not in definition.target_kinds
        ):
            raise RelationshipError("relationship endpoint kinds are not permitted by the registry")
        if not 0 <= item.confidence <= definition.default_confidence_cap:
            raise RelationshipError("relationship confidence is outside the permitted range")
        if item.valid_to is not None and item.valid_to <= item.valid_from:
            raise RelationshipError("relationship validity window is invalid")
        self._assert_node_in_organization(organization_id, item.source)
        self._assert_node_in_organization(organization_id, item.target)
        canonical_key = RelationshipIdentityService.create(
            organization_id,
            item.relationship_type,
            item.source,
            item.target,
            item.source_system,
        )
        relationship = self._session.scalar(
            select(Relationship).where(
                Relationship.organization_id == organization_id,
                Relationship.canonical_key == canonical_key,
            )
        )
        if relationship is None:
            relationship = Relationship(
                organization_id=organization_id,
                relationship_type=item.relationship_type,
                source_asset_id=item.source.node_id if item.source.kind == ASSET else None,
                source_context_entity_id=(
                    item.source.node_id if item.source.kind == CONTEXT else None
                ),
                target_asset_id=item.target.node_id if item.target.kind == ASSET else None,
                target_context_entity_id=(
                    item.target.node_id if item.target.kind == CONTEXT else None
                ),
                canonical_key=canonical_key,
                confidence=item.confidence,
                confidence_model_version=CONFIDENCE_MODEL_VERSION,
                registry_version=REGISTRY_VERSION,
                first_seen=item.observed_at,
                last_seen=item.observed_at,
                valid_from=item.valid_from,
                valid_to=item.valid_to,
                state=(
                    "ENDED"
                    if item.valid_to is not None and item.valid_to <= item.observed_at
                    else "ACTIVE"
                ),
                source_system=item.source_system,
                source_record_key=item.source_record_key,
                metadata_json=item.metadata or {},
            )
            self._session.add(relationship)
            self._session.flush()
            return relationship
        relationship.last_seen = max(_utc(relationship.last_seen), _utc(item.observed_at))
        relationship.confidence = item.confidence
        relationship.valid_to = item.valid_to
        relationship.state = (
            "ENDED" if item.valid_to is not None and item.valid_to <= item.observed_at else "ACTIVE"
        )
        relationship.metadata_json = item.metadata or {}
        return relationship

    def get_relationship(
        self, organization_id: uuid.UUID, relationship_id: uuid.UUID
    ) -> Relationship:
        relationship = self._session.scalar(
            select(Relationship).where(
                Relationship.organization_id == organization_id, Relationship.id == relationship_id
            )
        )
        if relationship is None:
            raise RelationshipError("relationship not found in organization")
        return relationship

    def list_relationships_for_node(
        self, organization_id: uuid.UUID, node: GraphNodeReference
    ) -> list[Relationship]:
        self._assert_node_in_organization(organization_id, node)
        source_column = (
            Relationship.source_asset_id
            if node.kind == ASSET
            else Relationship.source_context_entity_id
        )
        target_column = (
            Relationship.target_asset_id
            if node.kind == ASSET
            else Relationship.target_context_entity_id
        )
        return list(
            self._session.scalars(
                select(Relationship)
                .where(
                    Relationship.organization_id == organization_id,
                    or_(source_column == node.node_id, target_column == node.node_id),
                )
                .order_by(Relationship.canonical_key)
            )
        )

    def get_active_at(
        self, organization_id: uuid.UUID, effective_at: datetime
    ) -> list[Relationship]:
        return list(
            self._session.scalars(
                select(Relationship)
                .where(
                    Relationship.organization_id == organization_id,
                    Relationship.valid_from <= effective_at,
                    or_(Relationship.valid_to.is_(None), effective_at < Relationship.valid_to),
                    Relationship.state != "INVALID",
                )
                .order_by(Relationship.canonical_key)
            )
        )

    def end_relationship(
        self, organization_id: uuid.UUID, relationship_id: uuid.UUID, valid_to: datetime
    ) -> Relationship:
        relationship = self.get_relationship(organization_id, relationship_id)
        if valid_to <= relationship.valid_from:
            raise RelationshipError("relationship end must be after valid-from")
        relationship.valid_to = valid_to
        relationship.state = "ENDED"
        return relationship

    def link_provenance(
        self,
        organization_id: uuid.UUID,
        relationship_id: uuid.UUID,
        *,
        source_context_record_hash: str | None = None,
        observation_id: uuid.UUID | None = None,
        evidence_id: uuid.UUID | None = None,
    ) -> RelationshipEvidenceLink:
        self.get_relationship(organization_id, relationship_id)
        if source_context_record_hash is None and observation_id is None and evidence_id is None:
            raise RelationshipError("relationship provenance is required")
        material = {
            "relationship_id": str(relationship_id),
            "observation_id": str(observation_id) if observation_id else None,
            "evidence_id": str(evidence_id) if evidence_id else None,
            "source_context_record_hash": source_context_record_hash,
        }
        link_key = hashlib.sha256(
            json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        link = self._session.scalar(
            select(RelationshipEvidenceLink).where(
                RelationshipEvidenceLink.organization_id == organization_id,
                RelationshipEvidenceLink.link_key == link_key,
            )
        )
        if link is not None:
            return link
        link = RelationshipEvidenceLink(
            organization_id=organization_id,
            relationship_id=relationship_id,
            observation_id=observation_id,
            evidence_id=evidence_id,
            source_context_record_hash=source_context_record_hash,
            link_key=link_key,
        )
        self._session.add(link)
        self._session.flush()
        return link

    def _assert_node_in_organization(
        self, organization_id: uuid.UUID, node: GraphNodeReference
    ) -> None:
        if node.kind == ASSET:
            model: type[Asset] | type[ExternalContextEntity] = Asset
        elif node.kind == CONTEXT:
            model = ExternalContextEntity
        else:
            raise RelationshipError("unknown graph node kind")
        exists = self._session.scalar(
            select(model.id).where(
                model.id == node.node_id,
                model.organization_id == organization_id,
            )
        )
        if exists is None:
            raise RelationshipError("graph node is not available in organization")
