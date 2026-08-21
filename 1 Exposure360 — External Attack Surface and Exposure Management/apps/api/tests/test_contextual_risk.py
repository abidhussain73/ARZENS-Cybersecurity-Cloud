from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from exposure360_api.contextual_risk import (
    CONTEXTUAL_RISK_MODEL_VERSION,
    ContextualRiskScorer,
    FactorAvailability,
    RiskFactorInput,
)
from exposure360_api.db import Base
from exposure360_api.models import Asset, Finding, Organization, RiskAssessment, RiskFactorResult

NOW = datetime(2026, 8, 21, tzinfo=UTC)


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


def _finding(session: Session, organization_id: UUID, key: str) -> Finding:
    asset = Asset(
        id=uuid4(),
        organization_id=organization_id,
        asset_type="SERVICE",
        canonical_key=f"service:{key}",
        display_name=key,
        first_seen=NOW,
        last_seen=NOW,
    )
    finding = Finding(
        id=uuid4(),
        organization_id=organization_id,
        asset_id=asset.id,
        service_asset_id=None,
        rule_id="phase-seven-risk-fixture",
        rule_version=1,
        rule_hash="a" * 64,
        fingerprint=(uuid4().hex + uuid4().hex),
        title="Fixture contextual risk finding",
        description="Fixture-only finding for contextual-risk persistence acceptance.",
        category="EXPOSURE",
        rule_severity="HIGH",
        confidence=0.9,
        state="OPEN",
        first_seen=NOW,
        last_seen=NOW,
        opened_at=NOW,
    )
    session.add_all((asset, finding))
    session.flush()
    return finding


def _persist_result(
    session: Session, organization_id: UUID, finding: Finding, result: object
) -> RiskAssessment:
    risk_result = result
    assessment = RiskAssessment(
        id=uuid4(),
        organization_id=organization_id,
        finding_id=finding.id,
        asset_id=finding.asset_id,
        service_asset_id=None,
        model_version=risk_result.model_version,
        registry_hash=risk_result.registry_hash,
        raw_score=risk_result.raw_score,
        adjusted_score=risk_result.adjusted_score,
        factor_coverage=risk_result.factor_coverage,
        confidence=risk_result.confidence,
        risk_band=risk_result.risk_band,
        evaluated_at=NOW,
        explanation_json={"model": risk_result.model_version},
    )
    session.add(assessment)
    session.flush()
    session.add_all(
        RiskFactorResult(
            id=uuid4(),
            organization_id=organization_id,
            risk_assessment_id=assessment.id,
            factor_key=factor.key,
            availability=factor.availability.value,
            raw_value_json={"value": factor.raw_value},
            normalized_value=factor.normalized_value,
            configured_weight=factor.configured_weight,
            effective_weight=factor.effective_weight,
            contribution=factor.contribution,
            factor_confidence=factor.confidence,
            evidence_reference_json=factor.evidence_reference,
            reason_code=factor.reason_code,
        )
        for factor in risk_result.factors
    )
    session.flush()
    return assessment


def _factor(
    key: str,
    value: float | None,
    availability: FactorAvailability = FactorAvailability.AVAILABLE,
    confidence: float = 1.0,
) -> RiskFactorInput:
    return RiskFactorInput(key, availability, value, value, confidence, {"fixture": key})


def test_available_scores_are_explainable_deterministic_and_banded() -> None:
    factors = (
        _factor("FINDING_SEVERITY", 1.0),
        _factor("FINDING_CONFIDENCE", 1.0),
        _factor("EXTERNAL_SERVICE_EXPOSURE", 1.0),
        _factor("ATTACK_PATH_SCORE", 1.0),
        _factor("ATTACK_PATH_CONFIDENCE", 1.0),
        _factor("VULNERABILITY_CONTEXT", 1.0),
    )
    scorer = ContextualRiskScorer()

    first = scorer.score(factors)
    second = scorer.score(factors)

    assert first == second
    assert first.raw_score == 100
    assert first.factor_coverage == 1
    assert first.confidence == 1
    assert first.risk_band == "CRITICAL_PRIORITY"
    assert first.model_version == CONTEXTUAL_RISK_MODEL_VERSION
    assert len(first.registry_hash) == 64
    assert all(item.contribution > 0 for item in first.factors)


def test_missing_stale_and_invalid_factors_lower_coverage_not_raw_denominator() -> None:
    result = ContextualRiskScorer().score(
        (
            _factor("FINDING_SEVERITY", 0.75),
            _factor("FINDING_CONFIDENCE", 0.8),
            _factor("EXTERNAL_SERVICE_EXPOSURE", None, FactorAvailability.NOT_APPLICABLE),
            _factor("ATTACK_PATH_SCORE", None, FactorAvailability.MISSING, 0.0),
            _factor("ATTACK_PATH_CONFIDENCE", None, FactorAvailability.STALE, 0.0),
            _factor("VULNERABILITY_CONTEXT", None, FactorAvailability.INVALID, 0.0),
        )
    )

    assert result.raw_score == 76.6667
    assert result.factor_coverage == round(0.45 / 0.85, 6)
    assert result.confidence < 0.9
    explanations = {item.key: item for item in result.factors}
    assert explanations["ATTACK_PATH_SCORE"].availability is FactorAvailability.MISSING
    assert explanations["ATTACK_PATH_SCORE"].contribution == 0
    assert explanations["EXTERNAL_SERVICE_EXPOSURE"].effective_weight == 0


def test_not_applicable_is_excluded_and_low_coverage_remains_visible() -> None:
    result = ContextualRiskScorer().score(
        (
            _factor("FINDING_SEVERITY", 0.5),
            _factor("FINDING_CONFIDENCE", None, FactorAvailability.MISSING, 0),
            _factor("EXTERNAL_SERVICE_EXPOSURE", None, FactorAvailability.NOT_APPLICABLE),
        )
    )

    assert 0 <= result.raw_score <= 100
    assert result.factor_coverage < 0.5
    assert result.risk_band == "ELEVATED"


def test_assessment_and_factor_results_persist_model_registry_coverage_and_confidence(
    session: Session,
) -> None:
    organization = Organization(id=uuid4(), name="Risk persistence", slug=f"risk-{uuid4()}")
    session.add(organization)
    session.flush()
    finding = _finding(session, organization.id, "persistence")
    factors = (
        _factor("FINDING_SEVERITY", 0.75),
        _factor("FINDING_CONFIDENCE", 0.9),
        _factor("EXTERNAL_SERVICE_EXPOSURE", None, FactorAvailability.NOT_APPLICABLE),
        _factor("ATTACK_PATH_SCORE", None, FactorAvailability.MISSING, 0.0),
        _factor("ATTACK_PATH_CONFIDENCE", 0.8),
        _factor("VULNERABILITY_CONTEXT", None, FactorAvailability.STALE, 0.0),
    )
    scorer = ContextualRiskScorer()
    result = scorer.score(factors)
    assessment = _persist_result(session, organization.id, finding, result)
    session.commit()

    persisted = session.scalar(
        select(RiskAssessment).where(
            RiskAssessment.id == assessment.id,
            RiskAssessment.organization_id == organization.id,
        )
    )
    factor_rows = session.scalars(
        select(RiskFactorResult).where(
            RiskFactorResult.risk_assessment_id == assessment.id,
            RiskFactorResult.organization_id == organization.id,
        )
    ).all()

    assert persisted is not None
    assert persisted.model_version == CONTEXTUAL_RISK_MODEL_VERSION
    assert persisted.registry_hash == scorer.registry_hash()
    assert persisted.factor_coverage == result.factor_coverage
    assert persisted.confidence == result.confidence
    assert len(factor_rows) == len(result.factors)
    assert {row.factor_key for row in factor_rows} == {item.key for item in result.factors}


def test_risk_assessments_are_deterministic_and_organization_scoped(session: Session) -> None:
    first_organization = Organization(id=uuid4(), name="Risk first", slug=f"risk-a-{uuid4()}")
    second_organization = Organization(id=uuid4(), name="Risk second", slug=f"risk-b-{uuid4()}")
    session.add_all((first_organization, second_organization))
    session.flush()
    first_finding = _finding(session, first_organization.id, "first")
    second_finding = _finding(session, second_organization.id, "second")
    scorer = ContextualRiskScorer()
    factors = (_factor("FINDING_SEVERITY", 1.0), _factor("FINDING_CONFIDENCE", 0.9))
    first_result = scorer.score(factors)
    second_result = scorer.score(factors)
    first_assessment = _persist_result(session, first_organization.id, first_finding, first_result)
    _persist_result(session, second_organization.id, second_finding, second_result)
    session.commit()

    scoped_to_second = session.scalar(
        select(RiskAssessment).where(
            RiskAssessment.id == first_assessment.id,
            RiskAssessment.organization_id == second_organization.id,
        )
    )

    assert first_result == second_result
    assert scorer.registry_hash() == ContextualRiskScorer.registry_hash()
    assert scoped_to_second is None
