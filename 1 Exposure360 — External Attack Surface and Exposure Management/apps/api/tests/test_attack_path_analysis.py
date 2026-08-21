from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from exposure360_api.attack_path_analysis import (
    ATTACK_PATH_SCORE_MODEL_VERSION,
    AttackPathScorer,
)
from exposure360_api.db import Base
from exposure360_api.graph_traversal import (
    GraphEdge,
    GraphPath,
    TraversalProfile,
    TraversalResult,
)
from exposure360_api.models import Asset, ExternalContextEntity, Finding, Organization
from exposure360_api.relationships import (
    ASSET,
    CONTEXT,
    ExternalContextRepository,
    GraphNodeReference,
)

NOW = datetime(2026, 8, 21, tzinfo=UTC)
PROFILE = TraversalProfile(
    profile_id="analysis-fixture-v1",
    allowed_edges=frozenset({"ASSET_HOSTS_APPLICATION", "APPLICATION_USES_DATA"}),
    max_hops_default=4,
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
    item = Organization(id=uuid4(), name=name, slug=f"{name}-{uuid4()}")
    session.add(item)
    session.flush()
    return item


def _asset(session: Session, organization_id: UUID, asset_type: str, key: str) -> Asset:
    item = Asset(
        id=uuid4(),
        organization_id=organization_id,
        asset_type=asset_type,
        canonical_key=key,
        display_name=key,
        first_seen=NOW,
        last_seen=NOW,
    )
    session.add(item)
    session.flush()
    return item


def _context(
    session: Session, organization_id: UUID, context_type: str, canonical_key: str
) -> ExternalContextEntity:
    return ExternalContextRepository(session).upsert(
        organization_id,
        context_type=context_type,
        canonical_key=canonical_key,
        display_name=canonical_key,
        source_namespace="analysis-fixture",
        confidence=0.8,
        observed_at=NOW,
    )


def _path(*nodes: GraphNodeReference, edges: tuple[GraphEdge, ...]) -> GraphPath:
    return GraphPath(
        nodes=nodes,
        edges=edges,
        hop_count=len(edges),
        path_key="|".join(edge.relationship_id for edge in edges),
    )


def _finding(session: Session, organization_id: UUID, asset_id: UUID, severity: str) -> None:
    session.add(
        Finding(
            id=uuid4(),
            organization_id=organization_id,
            asset_id=asset_id,
            service_asset_id=None,
            rule_id="analysis-fixture",
            rule_version=1,
            rule_hash="a" * 64,
            fingerprint=uuid4().hex + uuid4().hex,
            title="Analysis finding",
            description="Fixture-only finding for Phase 6 topology analysis.",
            category="EXPOSURE",
            rule_severity=severity,
            confidence=0.9,
            state="OPEN",
            first_seen=NOW,
            last_seen=NOW,
            opened_at=NOW,
        )
    )
    session.flush()


def test_attack_path_score_is_deterministic_explainable_and_versioned(session: Session) -> None:
    organization = _organization(session, "analysis-score")
    service = _asset(session, organization.id, "SERVICE", "service:analysis")
    application = _context(session, organization.id, "APPLICATION", "application:analysis")
    data = _context(session, organization.id, "DATA", "data:analysis")
    _finding(session, organization.id, service.id, "HIGH")
    path = _path(
        GraphNodeReference(ASSET, service.id),
        GraphNodeReference(CONTEXT, application.id),
        GraphNodeReference(CONTEXT, data.id),
        edges=(
            GraphEdge("edge-1", "ASSET_HOSTS_APPLICATION", 0.9),
            GraphEdge("edge-2", "APPLICATION_USES_DATA", 0.9),
        ),
    )
    scorer = AttackPathScorer(session)

    first = scorer.score_path(organization.id, path)
    second = scorer.score_path(organization.id, path)

    assert first == second
    assert 0 <= first.score <= 100
    assert first.model_version == ATTACK_PATH_SCORE_MODEL_VERSION == "attack-path-score-v1"
    assert {(item.factor, item.points) for item in first.factors} == {
        ("EXTERNAL_START", 20),
        ("HIGH_FINDING", 15),
        ("DATA_DESTINATION", 15),
        ("PATH_LENGTH_PENALTY", -5),
    }


def test_vulnerability_and_path_length_factors_are_explicit_without_exploit_claims(
    session: Session,
) -> None:
    organization = _organization(session, "analysis-vulnerability")
    service = _asset(session, organization.id, "SERVICE", "service:vulnerability")
    vulnerability = _context(
        session, organization.id, "VULNERABILITY", "vulnerability:CVE-2099-6001"
    )
    path = _path(
        GraphNodeReference(ASSET, service.id),
        GraphNodeReference(CONTEXT, vulnerability.id),
        edges=(GraphEdge("edge-v", "SERVICE_HAS_VULNERABILITY", 0.6),),
    )

    breakdown = AttackPathScorer(session).score_path(organization.id, path)

    assert ("VULNERABILITY_CONTEXT", 10) in {
        (item.factor, item.points) for item in breakdown.factors
    }
    assert "RISK" not in {item.factor for item in breakdown.factors}


def test_path_confidence_is_geometric_and_weak_edges_reduce_it() -> None:
    strong = _path(
        GraphNodeReference(ASSET, uuid4()),
        GraphNodeReference(ASSET, uuid4()),
        edges=(GraphEdge("strong", "RESOLVES_TO", 0.9),),
    )
    weak = _path(
        GraphNodeReference(ASSET, uuid4()),
        GraphNodeReference(ASSET, uuid4()),
        GraphNodeReference(ASSET, uuid4()),
        edges=(
            GraphEdge("strong", "RESOLVES_TO", 0.9),
            GraphEdge("weak", "HAS_ENDPOINT", 0.2),
        ),
    )

    first = AttackPathScorer.path_confidence(strong)
    second = AttackPathScorer.path_confidence(strong)
    weak_result = AttackPathScorer.path_confidence(weak)

    assert first == second
    assert first.combined_confidence == 0.9
    assert weak_result.combined_confidence < first.combined_confidence
    assert weak_result.low_confidence_edges == ("weak",)


def test_blast_radius_counts_unique_categories_and_marks_partial(session: Session) -> None:
    organization = _organization(session, "analysis-radius")
    service = _asset(session, organization.id, "SERVICE", "service:radius")
    application = _context(session, organization.id, "APPLICATION", "application:radius")
    data = _context(session, organization.id, "DATA", "data:radius")
    identity = _context(session, organization.id, "IDENTITY", "identity:radius")
    path_one = _path(
        GraphNodeReference(ASSET, service.id),
        GraphNodeReference(CONTEXT, application.id),
        GraphNodeReference(CONTEXT, data.id),
        edges=(
            GraphEdge("radius-1", "ASSET_HOSTS_APPLICATION", 0.9),
            GraphEdge("radius-2", "APPLICATION_USES_DATA", 0.9),
        ),
    )
    path_two = _path(
        GraphNodeReference(ASSET, service.id),
        GraphNodeReference(CONTEXT, identity.id),
        edges=(GraphEdge("radius-3", "IDENTITY_CAN_ACCESS_ASSET", 0.9),),
    )
    result = TraversalResult(
        paths=(path_one, path_one, path_two),
        visited_node_count=4,
        truncated=True,
        warnings=("PATH_LIMIT_REACHED",),
    )

    radius = AttackPathScorer(session).blast_radius(
        organization.id,
        start_node=GraphNodeReference(ASSET, service.id),
        profile=PROFILE,
        max_hops=4,
        result=result,
    )

    assert radius.unique_nodes == 3
    assert (radius.applications, radius.data_entities, radius.identities) == (1, 1, 1)
    assert radius.paths == 2
    assert radius.truncated is True
