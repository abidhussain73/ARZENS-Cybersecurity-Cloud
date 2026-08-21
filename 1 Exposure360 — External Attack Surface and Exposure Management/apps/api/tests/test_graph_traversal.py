from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from exposure360_api.db import Base
from exposure360_api.graph_traversal import (
    BOTH,
    OUTBOUND,
    GraphTraversalService,
    TraversalProfile,
)
from exposure360_api.models import Asset, Organization
from exposure360_api.relationships import (
    ASSET,
    GraphNodeReference,
    RelationshipError,
    RelationshipInput,
)
from exposure360_api.relationships import (
    RelationshipRepository as RelationshipStore,
)

NOW = datetime(2026, 8, 21, tzinfo=UTC)
TECHNICAL_PROFILE = TraversalProfile(
    profile_id="technical-fixture-v1",
    allowed_edges=frozenset({"RESOLVES_TO", "HAS_ENDPOINT", "EXPOSES_SERVICE"}),
    max_hops_default=4,
    direction=OUTBOUND,
)


@pytest.fixture
def session() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection: object, _: object) -> None:
        connection.execute("PRAGMA foreign_keys=ON")  # type: ignore[union-attr]

    Base.metadata.create_all(engine)
    instance = sessionmaker(bind=engine, expire_on_commit=False)()
    try:
        yield instance
    finally:
        instance.close()
        engine.dispose()


def _organization(session: Session, name: str) -> Organization:
    organization = Organization(id=uuid4(), name=name, slug=f"{name}-{uuid4()}")
    session.add(organization)
    session.flush()
    return organization


def _asset(session: Session, organization_id: UUID, key: str) -> Asset:
    asset = Asset(
        id=uuid4(),
        organization_id=organization_id,
        asset_type="SERVICE",
        canonical_key=key,
        display_name=key,
        first_seen=NOW,
        last_seen=NOW,
    )
    session.add(asset)
    session.flush()
    return asset


def _edge(
    session: Session,
    organization_id: UUID,
    source: Asset,
    target: Asset,
    *,
    relationship_type: str = "RESOLVES_TO",
    confidence: float = 0.9,
    observed_at: datetime = NOW,
    valid_from: datetime = NOW,
    valid_to: datetime | None = None,
) -> None:
    RelationshipStore(session).upsert_relationship(
        organization_id,
        RelationshipInput(
            relationship_type=relationship_type,
            source=GraphNodeReference(ASSET, source.id),
            target=GraphNodeReference(ASSET, target.id),
            confidence=confidence,
            observed_at=observed_at,
            valid_from=valid_from,
            valid_to=valid_to,
            source_system="graph-fixture",
        ),
    )


def _traverse(
    session: Session,
    organization_id: UUID,
    start: Asset,
    **kwargs: object,
):
    return GraphTraversalService(session).traverse(
        organization_id,
        start_nodes=(GraphNodeReference(ASSET, start.id),),
        profile=TECHNICAL_PROFILE,
        **kwargs,
    )


def test_one_hop_multi_hop_and_max_hop_boundary(session: Session) -> None:
    organization = _organization(session, "traversal-depth")
    first, second, third = (
        _asset(session, organization.id, "service:depth-a"),
        _asset(session, organization.id, "service:depth-b"),
        _asset(session, organization.id, "service:depth-c"),
    )
    _edge(session, organization.id, first, second)
    _edge(session, organization.id, second, third, relationship_type="HAS_ENDPOINT")

    one_hop = _traverse(session, organization.id, first, max_hops=1, effective_at=NOW)
    full = _traverse(session, organization.id, first, max_hops=2, effective_at=NOW)

    assert [item.hop_count for item in one_hop.paths] == [1]
    assert [item.hop_count for item in full.paths] == [1, 2]


def test_allowed_edges_exclude_disallowed_relationships(session: Session) -> None:
    organization = _organization(session, "traversal-allowlist")
    first = _asset(session, organization.id, "service:allow-a")
    allowed = _asset(session, organization.id, "service:allow-b")
    disallowed = _asset(session, organization.id, "service:allow-c")
    _edge(session, organization.id, first, allowed, relationship_type="RESOLVES_TO")
    _edge(session, organization.id, first, disallowed, relationship_type="SERVED_FOR")

    result = _traverse(session, organization.id, first, effective_at=NOW)

    assert {item.nodes[-1].node_id for item in result.paths} == {allowed.id}


def test_cycle_and_self_loop_do_not_repeat_nodes(session: Session) -> None:
    organization = _organization(session, "traversal-cycle")
    first, second, third, fourth = (
        _asset(session, organization.id, "service:cycle-a"),
        _asset(session, organization.id, "service:cycle-b"),
        _asset(session, organization.id, "service:cycle-c"),
        _asset(session, organization.id, "service:cycle-d"),
    )
    _edge(session, organization.id, first, second)
    _edge(session, organization.id, second, third)
    _edge(session, organization.id, third, first)
    _edge(session, organization.id, third, fourth)
    _edge(session, organization.id, fourth, fourth)

    result = _traverse(session, organization.id, first, max_hops=6, effective_at=NOW)

    assert any(path.nodes[-1].node_id == fourth.id for path in result.paths)
    assert all(len(path.nodes) == len(set(path.nodes)) for path in result.paths)


def test_diamond_retains_two_distinct_paths_in_deterministic_order(session: Session) -> None:
    organization = _organization(session, "traversal-diamond")
    start, left, right, destination = (
        _asset(session, organization.id, "service:diamond-a"),
        _asset(session, organization.id, "service:diamond-b"),
        _asset(session, organization.id, "service:diamond-c"),
        _asset(session, organization.id, "service:diamond-d"),
    )
    _edge(session, organization.id, start, left)
    _edge(session, organization.id, start, right, relationship_type="HAS_ENDPOINT")
    _edge(session, organization.id, left, destination)
    _edge(session, organization.id, right, destination, relationship_type="HAS_ENDPOINT")

    first = _traverse(session, organization.id, start, max_hops=2, effective_at=NOW)
    second = _traverse(session, organization.id, start, max_hops=2, effective_at=NOW)
    destination_paths = [item for item in first.paths if item.nodes[-1].node_id == destination.id]

    assert len(destination_paths) == 2
    assert [item.path_key for item in first.paths] == [item.path_key for item in second.paths]
    assert [item.path_key for item in first.paths] == sorted(
        item.path_key for item in first.paths if item.hop_count == 1
    ) + sorted(item.path_key for item in first.paths if item.hop_count == 2)


def test_temporal_and_confidence_filters_apply(session: Session) -> None:
    organization = _organization(session, "traversal-temporal")
    start = _asset(session, organization.id, "service:temporal-a")
    historical = _asset(session, organization.id, "service:temporal-b")
    weak = _asset(session, organization.id, "service:temporal-c")
    _edge(
        session,
        organization.id,
        start,
        historical,
        observed_at=NOW - timedelta(days=3),
        valid_from=NOW - timedelta(days=3),
        valid_to=NOW - timedelta(days=1),
    )
    _edge(session, organization.id, start, weak, relationship_type="HAS_ENDPOINT", confidence=0.2)

    current = _traverse(session, organization.id, start, effective_at=NOW, min_edge_confidence=0.5)
    past = _traverse(
        session,
        organization.id,
        start,
        effective_at=NOW - timedelta(days=2),
        min_edge_confidence=0.5,
    )

    assert current.paths == ()
    assert [path.nodes[-1].node_id for path in past.paths] == [historical.id]


def test_path_and_node_limits_return_explicit_partial_results(session: Session) -> None:
    organization = _organization(session, "traversal-limits")
    start = _asset(session, organization.id, "service:limits-a")
    first = _asset(session, organization.id, "service:limits-b")
    second = _asset(session, organization.id, "service:limits-c")
    third = _asset(session, organization.id, "service:limits-d")
    _edge(session, organization.id, start, first)
    _edge(session, organization.id, start, second, relationship_type="HAS_ENDPOINT")
    _edge(session, organization.id, start, third, relationship_type="EXPOSES_SERVICE")

    paths_limited = _traverse(session, organization.id, start, effective_at=NOW, max_paths=1)
    nodes_limited = _traverse(session, organization.id, start, effective_at=NOW, max_nodes=2)

    assert paths_limited.truncated is True
    assert paths_limited.warnings == ("PATH_LIMIT_REACHED",)
    assert nodes_limited.truncated is True
    assert nodes_limited.warnings == ("NODE_LIMIT_REACHED",)
    assert nodes_limited.visited_node_count == 2


def test_cross_org_start_is_denied_and_both_direction_is_explicit(session: Session) -> None:
    organization = _organization(session, "traversal-owner")
    foreign = _organization(session, "traversal-foreign")
    owned = _asset(session, organization.id, "service:owned")
    foreign_asset = _asset(session, foreign.id, "service:foreign")

    with pytest.raises(RelationshipError):
        _traverse(session, organization.id, foreign_asset, effective_at=NOW)

    reverse_profile = TraversalProfile(
        profile_id="reverse-fixture-v1",
        allowed_edges=frozenset({"RESOLVES_TO"}),
        max_hops_default=1,
        direction=BOTH,
    )
    _edge(session, organization.id, owned, _asset(session, organization.id, "service:target"))
    result = GraphTraversalService(session).traverse(
        organization.id,
        start_nodes=(GraphNodeReference(ASSET, owned.id),),
        profile=reverse_profile,
        effective_at=NOW,
    )
    assert len(result.paths) == 1
