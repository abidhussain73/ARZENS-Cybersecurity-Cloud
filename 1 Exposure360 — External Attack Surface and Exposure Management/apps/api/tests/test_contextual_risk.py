from exposure360_api.contextual_risk import (
    CONTEXTUAL_RISK_MODEL_VERSION,
    ContextualRiskScorer,
    FactorAvailability,
    RiskFactorInput,
)


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
