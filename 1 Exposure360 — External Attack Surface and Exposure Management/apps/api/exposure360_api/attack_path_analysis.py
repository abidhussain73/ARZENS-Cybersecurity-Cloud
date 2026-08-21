"""Explainable Phase 6 attack-path analysis; this module does not calculate risk."""

from __future__ import annotations

import math
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from .graph_traversal import GraphPath, TraversalProfile, TraversalResult
from .models import Asset, ExternalContextEntity, Finding
from .relationships import ASSET, CONTEXT, GraphNodeReference

ATTACK_PATH_SCORE_MODEL_VERSION = "attack-path-score-v1"


@dataclass(frozen=True)
class PathScoreFactor:
    factor: str
    points: int


@dataclass(frozen=True)
class PathScoreBreakdown:
    score: int
    model_version: str
    factors: tuple[PathScoreFactor, ...]


@dataclass(frozen=True)
class PathConfidenceResult:
    combined_confidence: float
    edge_count: int
    min_edge_confidence: float
    low_confidence_edges: tuple[str, ...]


@dataclass(frozen=True)
class BlastRadiusSummary:
    start_node: GraphNodeReference
    profile: str
    max_hops: int
    unique_nodes: int
    applications: int
    identities: int
    data_entities: int
    vulnerabilities: int
    cloud_resources: int
    paths: int
    truncated: bool


class AttackPathScorer:
    """A deterministic topology score with explicit factors, never a risk score."""

    def __init__(self, session: Session):
        self._session = session

    def score_path(self, organization_id: object, path: GraphPath) -> PathScoreBreakdown:
        if not path.nodes:
            return PathScoreBreakdown(0, ATTACK_PATH_SCORE_MODEL_VERSION, ())
        factors: list[PathScoreFactor] = []
        asset_types, context_types = self._node_types(organization_id, path.nodes)
        start = path.nodes[0]
        if start.kind == ASSET and asset_types.get(start.node_id) in {
            "DOMAIN",
            "ENDPOINT",
            "SERVICE",
        }:
            factors.append(PathScoreFactor("EXTERNAL_START", 20))
        severities = self._active_finding_severities(organization_id, path.nodes)
        if "HIGH" in severities or "CRITICAL" in severities:
            factors.append(PathScoreFactor("HIGH_FINDING", 15))
        elif "MEDIUM" in severities:
            factors.append(PathScoreFactor("MEDIUM_FINDING", 8))
        if any(edge.relationship_type.endswith("HAS_VULNERABILITY") for edge in path.edges):
            factors.append(PathScoreFactor("VULNERABILITY_CONTEXT", 10))
        if any(edge.relationship_type == "IDENTITY_ADMINISTERS_ASSET" for edge in path.edges):
            factors.append(PathScoreFactor("IDENTITY_ADMIN_EDGE", 18))
        end = path.nodes[-1]
        if end.kind == CONTEXT and context_types.get(end.node_id) == "DATA":
            factors.append(PathScoreFactor("DATA_DESTINATION", 15))
        if path.hop_count > 1:
            factors.append(PathScoreFactor("PATH_LENGTH_PENALTY", -5 * (path.hop_count - 1)))
        return PathScoreBreakdown(
            score=max(0, min(100, sum(item.points for item in factors))),
            model_version=ATTACK_PATH_SCORE_MODEL_VERSION,
            factors=tuple(factors),
        )

    @staticmethod
    def path_confidence(
        path: GraphPath, *, low_confidence_below: float = 0.5
    ) -> PathConfidenceResult:
        if not 0 <= low_confidence_below <= 1:
            raise ValueError("low-confidence threshold must be between zero and one")
        confidences = tuple(edge.confidence for edge in path.edges)
        if not confidences:
            return PathConfidenceResult(0.0, 0, 0.0, ())
        combined = math.prod(confidences) ** (1 / len(confidences))
        low_edges = tuple(
            edge.relationship_id for edge in path.edges if edge.confidence < low_confidence_below
        )
        return PathConfidenceResult(
            combined_confidence=round(combined, 6),
            edge_count=len(confidences),
            min_edge_confidence=min(confidences),
            low_confidence_edges=low_edges,
        )

    def blast_radius(
        self,
        organization_id: object,
        *,
        start_node: GraphNodeReference,
        profile: TraversalProfile,
        max_hops: int,
        result: TraversalResult,
    ) -> BlastRadiusSummary:
        nodes = {node for path in result.paths for node in path.nodes}
        nodes.discard(start_node)
        _, context_types = self._node_types(organization_id, tuple(nodes))
        categories = {
            item: sum(1 for value in context_types.values() if value == item)
            for item in {
                "APPLICATION",
                "IDENTITY",
                "DATA",
                "VULNERABILITY",
                "CLOUD_RESOURCE",
            }
        }
        return BlastRadiusSummary(
            start_node=start_node,
            profile=profile.profile_id,
            max_hops=max_hops,
            unique_nodes=len(nodes),
            applications=categories["APPLICATION"],
            identities=categories["IDENTITY"],
            data_entities=categories["DATA"],
            vulnerabilities=categories["VULNERABILITY"],
            cloud_resources=categories["CLOUD_RESOURCE"],
            paths=len({path.path_key for path in result.paths}),
            truncated=result.truncated,
        )

    def _active_finding_severities(
        self, organization_id: object, nodes: tuple[GraphNodeReference, ...]
    ) -> set[str]:
        asset_ids = tuple(node.node_id for node in nodes if node.kind == ASSET)
        if not asset_ids:
            return set()
        return set(
            self._session.scalars(
                select(Finding.rule_severity).where(
                    Finding.organization_id == organization_id,
                    Finding.asset_id.in_(asset_ids),
                    Finding.state.in_(("OPEN", "ACKNOWLEDGED", "IN_PROGRESS")),
                )
            )
        )

    def _node_types(
        self, organization_id: object, nodes: tuple[GraphNodeReference, ...]
    ) -> tuple[dict[object, str], dict[object, str]]:
        asset_ids = tuple(node.node_id for node in nodes if node.kind == ASSET)
        context_ids = tuple(node.node_id for node in nodes if node.kind == CONTEXT)
        asset_types: dict[object, str] = (
            {
                identifier: asset_type
                for identifier, asset_type in self._session.execute(
                    select(Asset.id, Asset.asset_type).where(
                        Asset.organization_id == organization_id,
                        Asset.id.in_(asset_ids),
                    )
                ).tuples()
            }
            if asset_ids
            else {}
        )
        context_types: dict[object, str] = (
            {
                identifier: context_type
                for identifier, context_type in self._session.execute(
                    select(ExternalContextEntity.id, ExternalContextEntity.context_type).where(
                        ExternalContextEntity.organization_id == organization_id,
                        ExternalContextEntity.id.in_(context_ids),
                    )
                ).tuples()
            }
            if context_ids
            else {}
        )
        return asset_types, context_types
