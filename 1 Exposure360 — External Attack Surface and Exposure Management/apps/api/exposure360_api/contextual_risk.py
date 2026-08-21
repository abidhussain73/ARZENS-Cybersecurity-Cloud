"""Deterministic Phase 7 contextual prioritization; this is not exploit probability."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum

CONTEXTUAL_RISK_MODEL_VERSION = "contextual-risk-v1"
RISK_FACTOR_REGISTRY_VERSION = "risk-factor-registry-v1"


class FactorAvailability(StrEnum):
    AVAILABLE = "AVAILABLE"
    MISSING = "MISSING"
    STALE = "STALE"
    INVALID = "INVALID"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True)
class RiskFactorDefinition:
    key: str
    display_name: str
    category: str
    weight: float
    required: bool
    freshness_required: bool


RISK_FACTOR_REGISTRY = (
    RiskFactorDefinition("FINDING_SEVERITY", "Finding severity", "FINDING", 0.30, True, False),
    RiskFactorDefinition("FINDING_CONFIDENCE", "Finding confidence", "FINDING", 0.15, True, False),
    RiskFactorDefinition(
        "EXTERNAL_SERVICE_EXPOSURE", "External service exposure", "EXPOSURE", 0.15, False, True
    ),
    RiskFactorDefinition("ATTACK_PATH_SCORE", "Attack-Path Score", "GRAPH", 0.20, False, True),
    RiskFactorDefinition("ATTACK_PATH_CONFIDENCE", "Path confidence", "GRAPH", 0.10, False, True),
    RiskFactorDefinition(
        "VULNERABILITY_CONTEXT", "Vulnerability context", "CONTEXT", 0.10, False, True
    ),
)


@dataclass(frozen=True)
class RiskFactorInput:
    key: str
    availability: FactorAvailability
    raw_value: object | None
    normalized_value: float | None
    confidence: float
    evidence_reference: dict[str, object]
    reason_code: str | None = None


@dataclass(frozen=True)
class RiskFactorExplanation:
    key: str
    availability: FactorAvailability
    raw_value: object | None
    normalized_value: float | None
    configured_weight: float
    effective_weight: float
    contribution: float
    confidence: float
    evidence_reference: dict[str, object]
    reason_code: str | None


@dataclass(frozen=True)
class ContextualRiskResult:
    raw_score: float
    adjusted_score: float
    factor_coverage: float
    confidence: float
    risk_band: str
    model_version: str
    registry_hash: str
    factors: tuple[RiskFactorExplanation, ...]


class ContextualRiskScorer:
    def score(self, factors: tuple[RiskFactorInput, ...]) -> ContextualRiskResult:
        supplied = {item.key: item for item in factors}
        explanations: list[RiskFactorExplanation] = []
        available_weight = 0.0
        expected_weight = 0.0
        weighted_value = 0.0
        weighted_confidence = 0.0
        for definition in RISK_FACTOR_REGISTRY:
            input_value = supplied.get(definition.key)
            if input_value is None:
                input_value = RiskFactorInput(
                    definition.key,
                    FactorAvailability.MISSING,
                    None,
                    None,
                    0.0,
                    {},
                    "FACTOR_NOT_SUPPLIED",
                )
            if input_value.availability is not FactorAvailability.NOT_APPLICABLE:
                expected_weight += definition.weight
            available = input_value.availability is FactorAvailability.AVAILABLE
            effective_weight = definition.weight if available else 0.0
            contribution = effective_weight * (input_value.normalized_value or 0.0) * 100
            if available:
                available_weight += definition.weight
                weighted_value += definition.weight * (input_value.normalized_value or 0.0)
                weighted_confidence += definition.weight * input_value.confidence
            explanations.append(
                RiskFactorExplanation(
                    definition.key,
                    input_value.availability,
                    input_value.raw_value,
                    input_value.normalized_value,
                    definition.weight,
                    effective_weight,
                    contribution,
                    input_value.confidence,
                    input_value.evidence_reference,
                    input_value.reason_code,
                )
            )
        raw_score = 100 * weighted_value / available_weight if available_weight else 0.0
        coverage = available_weight / expected_weight if expected_weight else 1.0
        evidence_confidence = weighted_confidence / available_weight if available_weight else 0.0
        return ContextualRiskResult(
            raw_score=round(max(0.0, min(100.0, raw_score)), 4),
            adjusted_score=round(max(0.0, min(100.0, raw_score)), 4),
            factor_coverage=round(coverage, 6),
            confidence=round(evidence_confidence * coverage, 6),
            risk_band=self._band(raw_score),
            model_version=CONTEXTUAL_RISK_MODEL_VERSION,
            registry_hash=self.registry_hash(),
            factors=tuple(explanations),
        )

    @staticmethod
    def registry_hash() -> str:
        material = [item.__dict__ for item in RISK_FACTOR_REGISTRY]
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    @staticmethod
    def _band(score: float) -> str:
        if score < 20:
            return "LOW"
        if score < 40:
            return "MODERATE"
        if score < 60:
            return "ELEVATED"
        if score < 80:
            return "HIGH"
        return "CRITICAL_PRIORITY"
