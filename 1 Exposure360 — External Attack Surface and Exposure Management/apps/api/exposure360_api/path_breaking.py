"""Hypothetical Phase 6 path-breaking analysis; no source-system changes occur here."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .graph_traversal import GraphEdge, GraphPath, TraversalProfile, TraversalResult
from .relationships import RELATIONSHIP_TYPES

PATH_BREAK_MAX_CANDIDATES = 100


@dataclass(frozen=True)
class PathBreakingCandidate:
    candidate_type: str
    relationship_id: str
    baseline_paths: int
    remaining_paths: int
    paths_broken: int
    reduction_percent: float
    affected_destinations: int
    simulation_only: bool
    simulation_confidence: str
    suggested_change_text: str


class PathBreakingSimulator:
    """Ranks hypothetical edge removals over a bounded in-memory graph projection only."""

    def evaluate_candidates(
        self,
        baseline: TraversalResult,
        *,
        profile: TraversalProfile,
        candidate_edges: tuple[GraphEdge, ...] | None = None,
        max_candidates: int = PATH_BREAK_MAX_CANDIDATES,
    ) -> tuple[PathBreakingCandidate, ...]:
        if not 1 <= max_candidates <= PATH_BREAK_MAX_CANDIDATES:
            raise ValueError("candidate limit is outside the Phase 6 platform ceiling")
        paths = {path.path_key: path for path in baseline.paths}
        discovered_edges = {
            edge.relationship_id: edge
            for path in paths.values()
            for edge in path.edges
            if RELATIONSHIP_TYPES.get(edge.relationship_type, None)
            and RELATIONSHIP_TYPES[edge.relationship_type].breakable
        }
        selected_edges = candidate_edges or tuple(discovered_edges.values())
        candidates = [
            self._evaluate_edge(paths, edge, profile, baseline.truncated) for edge in selected_edges
        ]
        return tuple(
            sorted(
                candidates,
                key=lambda item: (-item.paths_broken, item.relationship_id, item.candidate_type),
            )[:max_candidates]
        )

    @staticmethod
    def _evaluate_edge(
        paths: Mapping[str, GraphPath],
        edge: GraphEdge,
        profile: TraversalProfile,
        baseline_truncated: bool,
    ) -> PathBreakingCandidate:
        baseline_paths = len(paths)
        remaining = [
            path
            for path in paths.values()
            if all(item.relationship_id != edge.relationship_id for item in path.edges)
        ]
        remaining_paths = len(remaining)
        paths_broken = baseline_paths - remaining_paths
        destinations = {
            path.nodes[-1]
            for path in paths.values()
            if any(item.relationship_id == edge.relationship_id for item in path.edges)
        }
        return PathBreakingCandidate(
            candidate_type=PathBreakingSimulator._candidate_type(edge.relationship_type),
            relationship_id=edge.relationship_id,
            baseline_paths=baseline_paths,
            remaining_paths=remaining_paths,
            paths_broken=paths_broken,
            reduction_percent=(
                round((paths_broken / baseline_paths) * 100, 2) if baseline_paths else 0.0
            ),
            affected_destinations=len(destinations),
            simulation_only=True,
            simulation_confidence="PARTIAL" if baseline_truncated else "FULL",
            suggested_change_text=(
                f"Simulated graph-only removal of {edge.relationship_type} "
                f"under {profile.profile_id}; "
                f"no source-system change is executed."
            ),
        )

    @staticmethod
    def _candidate_type(relationship_type: str) -> str:
        if relationship_type.startswith("IDENTITY_"):
            return "REMOVE_IDENTITY_ACCESS_EDGE"
        if relationship_type in {"EXPOSES_SERVICE", "CLOUD_RESOURCE_EXPOSES_ASSET"}:
            return "BLOCK_SERVICE_EXPOSURE_EDGE"
        return "REMOVE_RELATIONSHIP"
