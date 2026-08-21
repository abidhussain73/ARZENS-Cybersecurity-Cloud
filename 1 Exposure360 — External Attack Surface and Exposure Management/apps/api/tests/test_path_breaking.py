from uuid import uuid4

from exposure360_api.graph_traversal import GraphEdge, GraphPath, TraversalProfile, TraversalResult
from exposure360_api.path_breaking import PATH_BREAK_MAX_CANDIDATES, PathBreakingSimulator
from exposure360_api.relationships import ASSET, GraphNodeReference

PROFILE = TraversalProfile(
    profile_id="path-breaking-fixture-v1",
    allowed_edges=frozenset({"EXPOSES_SERVICE", "HAS_ENDPOINT"}),
    max_hops_default=4,
)


def _edge(identifier: str, relationship_type: str = "EXPOSES_SERVICE") -> GraphEdge:
    return GraphEdge(identifier, relationship_type, 0.9)


def _path(identifier: str, *edges: GraphEdge) -> GraphPath:
    nodes = tuple(GraphNodeReference(ASSET, uuid4()) for _ in range(len(edges) + 1))
    return GraphPath(nodes=nodes, edges=edges, hop_count=len(edges), path_key=identifier)


def test_single_and_shared_edges_reduce_paths_without_mutating_baseline() -> None:
    shared = _edge("shared")
    first = _path("first", shared, _edge("first-tail", "HAS_ENDPOINT"))
    second = _path("second", shared, _edge("second-tail", "HAS_ENDPOINT"))
    baseline = TraversalResult((first, second), 3, False, ())

    candidates = PathBreakingSimulator().evaluate_candidates(baseline, profile=PROFILE)
    shared_candidate = next(item for item in candidates if item.relationship_id == "shared")

    assert shared_candidate.paths_broken == 2
    assert shared_candidate.remaining_paths == 0
    assert shared_candidate.simulation_only is True
    assert baseline.paths == (first, second)


def test_irrelevant_edge_is_zero_reduction_and_results_are_deterministic() -> None:
    path = _path("only", _edge("relevant"))
    baseline = TraversalResult((path,), 2, False, ())
    simulator = PathBreakingSimulator()
    requested = (_edge("irrelevant"), _edge("relevant"))

    first = simulator.evaluate_candidates(baseline, profile=PROFILE, candidate_edges=requested)
    second = simulator.evaluate_candidates(baseline, profile=PROFILE, candidate_edges=requested)

    assert first == second
    assert next(item for item in first if item.relationship_id == "irrelevant").paths_broken == 0
    assert [item.paths_broken for item in first] == [1, 0]


def test_partial_and_candidate_ceiling_are_explicit() -> None:
    edges = tuple(_edge(f"edge-{index}") for index in range(PATH_BREAK_MAX_CANDIDATES + 2))
    paths = tuple(_path(f"path-{index}", edge) for index, edge in enumerate(edges))
    baseline = TraversalResult(paths, len(paths) + 1, True, ("PATH_LIMIT_REACHED",))

    candidates = PathBreakingSimulator().evaluate_candidates(baseline, profile=PROFILE)

    assert len(candidates) == PATH_BREAK_MAX_CANDIDATES
    assert all(item.simulation_confidence == "PARTIAL" for item in candidates)
    assert all("graph-only" in item.suggested_change_text for item in candidates)
