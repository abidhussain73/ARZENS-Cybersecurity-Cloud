"""Bounded, evidence-backed graph traversal for Phase 6 analytical context."""

from __future__ import annotations

import hashlib
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import or_, select
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from .models import Asset, ExternalContextEntity, Relationship
from .relationships import ASSET, CONTEXT, GraphNodeReference, RelationshipError

GRAPH_MAX_HOPS = 6
GRAPH_MAX_PATHS = 500
GRAPH_MAX_NODES = 5000
OUTBOUND = "OUTBOUND"
INBOUND = "INBOUND"
BOTH = "BOTH"


@dataclass(frozen=True)
class TraversalProfile:
    profile_id: str
    allowed_edges: frozenset[str]
    max_hops_default: int
    direction: str = OUTBOUND


EXPOSURE_TO_DATA = TraversalProfile(
    profile_id="exposure-to-data-v1",
    allowed_edges=frozenset(
        {
            "RESOLVES_TO",
            "HAS_ENDPOINT",
            "EXPOSES_SERVICE",
            "APPLICATION_EXPOSED_BY_SERVICE",
            "APPLICATION_USES_DATA",
        }
    ),
    max_hops_default=4,
    direction=BOTH,
)
EXPOSURE_TO_APPLICATION = TraversalProfile(
    profile_id="exposure-to-application-v1",
    allowed_edges=frozenset(
        {
            "RESOLVES_TO",
            "HAS_ENDPOINT",
            "EXPOSES_SERVICE",
            "ASSET_HOSTS_APPLICATION",
            "APPLICATION_EXPOSED_BY_SERVICE",
        }
    ),
    max_hops_default=4,
    direction=BOTH,
)
EXPOSURE_TO_IDENTITY = TraversalProfile(
    profile_id="exposure-to-identity-v1",
    allowed_edges=frozenset(
        {
            "IDENTITY_CAN_ACCESS_ASSET",
            "IDENTITY_CAN_ACCESS_APPLICATION",
            "IDENTITY_ADMINISTERS_ASSET",
            "IDENTITY_OWNS_ASSET",
        }
    ),
    max_hops_default=4,
    direction=BOTH,
)
EXPOSURE_TO_VULNERABILITY = TraversalProfile(
    profile_id="exposure-to-vulnerability-v1",
    allowed_edges=frozenset(
        {
            "ASSET_HAS_VULNERABILITY",
            "SERVICE_HAS_VULNERABILITY",
            "APPLICATION_HAS_VULNERABILITY",
        }
    ),
    max_hops_default=4,
    direction=BOTH,
)
TRAVERSAL_PROFILES = {
    item.profile_id: item
    for item in (
        EXPOSURE_TO_DATA,
        EXPOSURE_TO_APPLICATION,
        EXPOSURE_TO_IDENTITY,
        EXPOSURE_TO_VULNERABILITY,
    )
}


@dataclass(frozen=True)
class GraphEdge:
    relationship_id: str
    relationship_type: str
    confidence: float


@dataclass(frozen=True)
class GraphPath:
    nodes: tuple[GraphNodeReference, ...]
    edges: tuple[GraphEdge, ...]
    hop_count: int
    path_key: str


@dataclass(frozen=True)
class TraversalResult:
    paths: tuple[GraphPath, ...]
    visited_node_count: int
    truncated: bool
    warnings: tuple[str, ...]


class GraphTraversalService:
    """Application-level BFS that remains bounded, deterministic, and tenant-scoped."""

    def __init__(self, session: Session):
        self._session = session

    def traverse(
        self,
        organization_id: object,
        *,
        start_nodes: tuple[GraphNodeReference, ...],
        profile: TraversalProfile,
        max_hops: int | None = None,
        effective_at: datetime | None = None,
        max_paths: int = GRAPH_MAX_PATHS,
        max_nodes: int = GRAPH_MAX_NODES,
        min_edge_confidence: float = 0.0,
        direction: str | None = None,
    ) -> TraversalResult:
        if not start_nodes:
            raise RelationshipError("at least one organization-scoped start node is required")
        selected_direction = direction or profile.direction
        actual_max_hops = max_hops if max_hops is not None else profile.max_hops_default
        self._validate_limits(
            actual_max_hops,
            max_paths,
            max_nodes,
            min_edge_confidence,
            selected_direction,
        )
        for node in start_nodes:
            self._assert_node_in_organization(organization_id, node)
        query_time = self._utc(effective_at or datetime.now(UTC))
        queue: deque[GraphPath] = deque(
            GraphPath(nodes=(node,), edges=(), hop_count=0, path_key="") for node in start_nodes
        )
        paths: list[GraphPath] = []
        visited_nodes = set(start_nodes)
        warnings: list[str] = []
        truncated = False

        while queue:
            frontier_hops = queue[0].hop_count
            if frontier_hops >= actual_max_hops:
                queue.popleft()
                continue
            frontier: list[GraphPath] = []
            while queue and queue[0].hop_count == frontier_hops:
                frontier.append(queue.popleft())
            adjacency = self._fetch_adjacency(
                organization_id,
                tuple(path.nodes[-1] for path in frontier),
                profile.allowed_edges,
                query_time,
                min_edge_confidence,
                selected_direction,
            )
            stop = False
            for path in frontier:
                for relationship, next_node in adjacency.get(path.nodes[-1], ()):
                    if next_node in path.nodes:
                        continue
                    if next_node not in visited_nodes and len(visited_nodes) >= max_nodes:
                        truncated = True
                        self._add_warning(warnings, "NODE_LIMIT_REACHED")
                        stop = True
                        break
                    visited_nodes.add(next_node)
                    edge = GraphEdge(
                        relationship_id=str(relationship.id),
                        relationship_type=relationship.relationship_type,
                        confidence=relationship.confidence,
                    )
                    edges = (*path.edges, edge)
                    candidate = GraphPath(
                        nodes=(*path.nodes, next_node),
                        edges=edges,
                        hop_count=len(edges),
                        path_key=self._path_key(edges),
                    )
                    if len(paths) >= max_paths:
                        truncated = True
                        self._add_warning(warnings, "PATH_LIMIT_REACHED")
                        stop = True
                        break
                    paths.append(candidate)
                    queue.append(candidate)
                if stop:
                    break
            if stop:
                break
        return TraversalResult(
            paths=tuple(sorted(paths, key=lambda item: (item.hop_count, item.path_key))),
            visited_node_count=len(visited_nodes),
            truncated=truncated,
            warnings=tuple(warnings),
        )

    def _fetch_adjacency(
        self,
        organization_id: object,
        frontier: tuple[GraphNodeReference, ...],
        allowed_edges: frozenset[str],
        effective_at: datetime,
        min_edge_confidence: float,
        direction: str,
    ) -> dict[GraphNodeReference, tuple[tuple[Relationship, GraphNodeReference], ...]]:
        asset_ids = tuple(node.node_id for node in frontier if node.kind == ASSET)
        context_ids = tuple(node.node_id for node in frontier if node.kind == CONTEXT)
        outbound = self._endpoint_predicates(asset_ids, context_ids, outgoing=True)
        inbound = self._endpoint_predicates(asset_ids, context_ids, outgoing=False)
        predicates: tuple[ColumnElement[bool], ...] = outbound if direction == OUTBOUND else inbound
        if direction == BOTH:
            predicates = (*outbound, *inbound)
        if not predicates:
            return {}
        relationships = self._session.scalars(
            select(Relationship)
            .where(
                Relationship.organization_id == organization_id,
                Relationship.relationship_type.in_(allowed_edges),
                Relationship.valid_from <= effective_at,
                or_(Relationship.valid_to.is_(None), effective_at < Relationship.valid_to),
                Relationship.state != "INVALID",
                Relationship.confidence >= min_edge_confidence,
                or_(*predicates),
            )
            .order_by(Relationship.canonical_key)
        ).all()
        result: dict[GraphNodeReference, list[tuple[Relationship, GraphNodeReference]]] = {}
        for relationship in relationships:
            source = self._source_node(relationship)
            target = self._target_node(relationship)
            if direction in {OUTBOUND, BOTH} and source in frontier:
                result.setdefault(source, []).append((relationship, target))
            if direction in {INBOUND, BOTH} and target in frontier:
                result.setdefault(target, []).append((relationship, source))
        return {node: tuple(edges) for node, edges in result.items()}

    @staticmethod
    def _endpoint_predicates(
        asset_ids: tuple[object, ...], context_ids: tuple[object, ...], *, outgoing: bool
    ) -> tuple[ColumnElement[bool], ...]:
        asset_column = Relationship.source_asset_id if outgoing else Relationship.target_asset_id
        context_column = (
            Relationship.source_context_entity_id
            if outgoing
            else Relationship.target_context_entity_id
        )
        predicates: list[ColumnElement[bool]] = []
        if asset_ids:
            predicates.append(asset_column.in_(asset_ids))
        if context_ids:
            predicates.append(context_column.in_(context_ids))
        return tuple(predicates)

    @staticmethod
    def _source_node(relationship: Relationship) -> GraphNodeReference:
        if relationship.source_asset_id is not None:
            return GraphNodeReference(ASSET, relationship.source_asset_id)
        if relationship.source_context_entity_id is not None:
            return GraphNodeReference(CONTEXT, relationship.source_context_entity_id)
        raise RelationshipError("relationship source endpoint is missing")

    @staticmethod
    def _target_node(relationship: Relationship) -> GraphNodeReference:
        if relationship.target_asset_id is not None:
            return GraphNodeReference(ASSET, relationship.target_asset_id)
        if relationship.target_context_entity_id is not None:
            return GraphNodeReference(CONTEXT, relationship.target_context_entity_id)
        raise RelationshipError("relationship target endpoint is missing")

    def _assert_node_in_organization(
        self, organization_id: object, node: GraphNodeReference
    ) -> None:
        if node.kind == ASSET:
            model: type[Asset] | type[ExternalContextEntity] = Asset
        elif node.kind == CONTEXT:
            model = ExternalContextEntity
        else:
            raise RelationshipError("unknown graph node kind")
        if (
            self._session.scalar(
                select(model.id).where(
                    model.id == node.node_id,
                    model.organization_id == organization_id,
                )
            )
            is None
        ):
            raise RelationshipError("graph start node is not available in organization")

    @staticmethod
    def _path_key(edges: tuple[GraphEdge, ...]) -> str:
        return hashlib.sha256(
            ":".join(edge.relationship_id for edge in edges).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _utc(value: datetime) -> datetime:
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)

    @staticmethod
    def _add_warning(warnings: list[str], warning: str) -> None:
        if warning not in warnings:
            warnings.append(warning)

    @staticmethod
    def _validate_limits(
        max_hops: int,
        max_paths: int,
        max_nodes: int,
        min_edge_confidence: float,
        direction: str,
    ) -> None:
        if not 0 <= max_hops <= GRAPH_MAX_HOPS:
            raise RelationshipError("max hops exceeds the graph traversal platform ceiling")
        if not 1 <= max_paths <= GRAPH_MAX_PATHS:
            raise RelationshipError("max paths is outside the graph traversal platform ceiling")
        if not 1 <= max_nodes <= GRAPH_MAX_NODES:
            raise RelationshipError("max nodes is outside the graph traversal platform ceiling")
        if not 0 <= min_edge_confidence <= 1:
            raise RelationshipError("minimum edge confidence must be between zero and one")
        if direction not in {OUTBOUND, INBOUND, BOTH}:
            raise RelationshipError("unsupported traversal direction")
