import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import (
    Asset,
    CanonicalObservation,
    Evidence,
    FingerprintEvidenceLink,
    TechnologyFingerprint,
)
from .technology_signatures import (
    SignatureClause,
    TechnologyRuleset,
    TechnologySignature,
    safe_version_pattern,
)

CONFIDENCE_MODEL_VERSION = "phase4-fingerprint-v1"
_MAX_REGEX_INPUT_LENGTH = 4_096
_REGEX_TIMEOUT_SECONDS = 0.05


class FingerprintEvaluationError(ValueError):
    """Raised when canonical fingerprint inputs do not share an organization boundary."""


@dataclass(frozen=True)
class FingerprintEvaluationResult:
    fingerprint: TechnologyFingerprint
    created: bool
    matched_fields: tuple[str, ...]


class FingerprintEvaluator:
    """Evaluates loaded data rules against already collected canonical observation metadata."""

    def evaluate(
        self,
        session: Session,
        *,
        observation: CanonicalObservation,
        ruleset: TechnologyRuleset,
        evidence: Evidence | None = None,
        service_asset: Asset | None = None,
    ) -> list[FingerprintEvaluationResult]:
        self._validate_organization(observation, evidence, service_asset)
        fields = _flatten_observation_payload(observation.normalized_payload_json)
        observed_at = _database_utc(observation.observed_at)
        results: list[FingerprintEvaluationResult] = []
        for rule in ruleset.rules:
            matched_fields = self._matched_fields(rule, fields)
            if matched_fields is None:
                continue
            version_value = _extract_version(rule, fields)
            fingerprint_key = _fingerprint_key(
                observation.organization_id,
                observation.asset_id,
                service_asset.id if service_asset is not None else None,
                rule,
                version_value,
            )
            existing = session.scalar(
                select(TechnologyFingerprint).where(
                    TechnologyFingerprint.organization_id == observation.organization_id,
                    TechnologyFingerprint.fingerprint_key == fingerprint_key,
                )
            )
            created = existing is None
            if existing is None:
                fingerprint = TechnologyFingerprint(
                    organization_id=observation.organization_id,
                    asset_id=observation.asset_id,
                    service_asset_id=service_asset.id if service_asset is not None else None,
                    technology_vendor=rule.technology.vendor,
                    technology_product=rule.technology.product,
                    technology_category=rule.technology.category,
                    version_value=version_value,
                    version_confidence=rule.confidence if version_value is not None else None,
                    base_confidence=rule.confidence,
                    confidence=rule.confidence,
                    confidence_model_version=CONFIDENCE_MODEL_VERSION,
                    rule_id=rule.rule_id,
                    rule_version=rule.rule_version,
                    rule_hash=rule.rule_hash,
                    ruleset_hash=ruleset.ruleset_hash,
                    fingerprint_key=fingerprint_key,
                    evidence_fields_json=list(matched_fields),
                    first_seen=observed_at,
                    last_seen=observed_at,
                )
                session.add(fingerprint)
                session.flush()
            else:
                fingerprint = existing
                fingerprint.first_seen = min(_database_utc(fingerprint.first_seen), observed_at)
                fingerprint.last_seen = max(_database_utc(fingerprint.last_seen), observed_at)
                fingerprint.ruleset_hash = ruleset.ruleset_hash
                fingerprint.evidence_fields_json = list(matched_fields)
            self._link_provenance(session, fingerprint, observation, evidence)
            results.append(FingerprintEvaluationResult(fingerprint, created, matched_fields))
        self._refresh_confidence_and_conflicts(
            session,
            observation.organization_id,
            observation.asset_id,
            service_asset.id if service_asset is not None else None,
        )
        return results

    @staticmethod
    def _refresh_confidence_and_conflicts(
        session: Session,
        organization_id: UUID,
        asset_id: UUID,
        service_asset_id: UUID | None,
    ) -> None:
        fingerprints = list(
            session.scalars(
                select(TechnologyFingerprint).where(
                    TechnologyFingerprint.organization_id == organization_id,
                    TechnologyFingerprint.asset_id == asset_id,
                    TechnologyFingerprint.service_asset_id == service_asset_id,
                )
            )
        )
        by_technology: dict[tuple[str, str, str], list[TechnologyFingerprint]] = {}
        for fingerprint in fingerprints:
            technology_key = (
                fingerprint.technology_vendor or "",
                fingerprint.technology_product,
                fingerprint.technology_category,
            )
            by_technology.setdefault(technology_key, []).append(fingerprint)
        for matches in by_technology.values():
            components = _independent_confidence_components(matches)
            confidence = _combine_confidence(component["confidence"] for component in components)
            for fingerprint in matches:
                fingerprint.confidence = confidence
                fingerprint.confidence_components_json = components
                fingerprint.confidence_model_version = CONFIDENCE_MODEL_VERSION
        by_category: dict[str, list[TechnologyFingerprint]] = {}
        for fingerprint in fingerprints:
            by_category.setdefault(fingerprint.technology_category, []).append(fingerprint)
        for category_fingerprints in by_category.values():
            distinct_products = {item.technology_product for item in category_fingerprints}
            strongest = sorted(
                category_fingerprints,
                key=lambda item: (-item.confidence, item.technology_product, str(item.id)),
            )
            is_conflict = (
                len(distinct_products) > 1
                and len(strongest) > 1
                and abs(strongest[0].confidence - strongest[1].confidence) <= 0.05
            )
            for fingerprint in category_fingerprints:
                fingerprint.fingerprint_state = "CONFLICT" if is_conflict else "CONFIRMED"

    def _matched_fields(
        self,
        rule: TechnologySignature,
        fields: Mapping[str, object],
    ) -> tuple[str, ...] | None:
        available_types = {field.split(".", maxsplit=1)[0].upper() for field in fields}
        if not set(rule.applies_to).intersection(available_types):
            return None
        matched_all = [_matches(clause, fields) for clause in rule.match_all]
        matched_any = [_matches(clause, fields) for clause in rule.match_any]
        if not all(result[0] for result in matched_all):
            return None
        if matched_any and not any(result[0] for result in matched_any):
            return None
        matched_fields = [field for matched, field in [*matched_all, *matched_any] if matched]
        return tuple(sorted(set(matched_fields)))

    @staticmethod
    def _validate_organization(
        observation: CanonicalObservation,
        evidence: Evidence | None,
        service_asset: Asset | None,
    ) -> None:
        if evidence is not None and evidence.organization_id != observation.organization_id:
            raise FingerprintEvaluationError("evidence belongs to another organization")
        if evidence is not None and evidence.asset_id != observation.asset_id:
            raise FingerprintEvaluationError("evidence must reference the observation asset")
        if (
            service_asset is not None
            and service_asset.organization_id != observation.organization_id
        ):
            raise FingerprintEvaluationError("service asset belongs to another organization")

    @staticmethod
    def _link_provenance(
        session: Session,
        fingerprint: TechnologyFingerprint,
        observation: CanonicalObservation,
        evidence: Evidence | None,
    ) -> None:
        link_key = hashlib.sha256(
            json.dumps(
                [str(fingerprint.id), str(observation.id), str(evidence.id) if evidence else ""],
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest()
        existing = session.scalar(
            select(FingerprintEvidenceLink).where(
                FingerprintEvidenceLink.organization_id == observation.organization_id,
                FingerprintEvidenceLink.link_key == link_key,
            )
        )
        if existing is None:
            session.add(
                FingerprintEvidenceLink(
                    organization_id=observation.organization_id,
                    fingerprint_id=fingerprint.id,
                    observation_id=observation.id,
                    evidence_id=evidence.id if evidence is not None else None,
                    link_key=link_key,
                )
            )


def _flatten_observation_payload(payload: dict[str, object]) -> dict[str, object]:
    flattened: dict[str, object] = {}

    def visit(value: object, prefix: str) -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                if isinstance(key, str):
                    child_prefix = f"{prefix}.{key}" if prefix else key
                    visit(child, child_prefix)
        elif prefix:
            flattened[prefix] = value

    visit(payload, "")
    return flattened


def _matches(clause: SignatureClause, fields: Mapping[str, object]) -> tuple[bool, str]:
    actual = fields.get(clause.field)
    if clause.operator == "exists":
        return actual is not None, clause.field
    if actual is None:
        return False, clause.field
    values = list(_values(actual))
    expected = clause.value
    if clause.operator == "in":
        expected_values = cast(tuple[str | int, ...], expected)
        return any(value in expected_values for value in values), clause.field
    if expected is None:
        return False, clause.field
    scalar_expected = cast(str | int, expected)
    return any(_compare(value, scalar_expected, clause.operator) for value in values), clause.field


def _values(value: object) -> Iterable[str | int]:
    if isinstance(value, list | tuple):
        for item in value:
            if isinstance(item, str | int) and not isinstance(item, bool):
                yield item
    elif isinstance(value, str | int) and not isinstance(value, bool):
        yield value


def _compare(actual: str | int, expected: str | int, operator: str) -> bool:
    if operator == "equals":
        return actual == expected
    if operator == "equals_ci":
        return str(actual).casefold() == str(expected).casefold()
    if operator == "contains":
        return str(expected) in str(actual)
    if operator == "contains_ci":
        return str(expected).casefold() in str(actual).casefold()
    if operator == "starts_with":
        return str(actual).startswith(str(expected))
    if operator == "starts_with_ci":
        return str(actual).casefold().startswith(str(expected).casefold())
    if operator == "ends_with":
        return str(actual).endswith(str(expected))
    if operator == "ends_with_ci":
        return str(actual).casefold().endswith(str(expected).casefold())
    return False


def _extract_version(rule: TechnologySignature, fields: Mapping[str, object]) -> str | None:
    extraction = rule.version_extraction
    if extraction is None:
        return None
    actual = fields.get(extraction.field)
    if not isinstance(actual, str):
        return None
    try:
        match = safe_version_pattern(extraction.pattern).search(
            actual[:_MAX_REGEX_INPUT_LENGTH],
            timeout=_REGEX_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        return None
    if match is None:
        return None
    version = match.groupdict().get("version") or (match.group(1) if match.groups() else None)
    return version if version else None


def _fingerprint_key(
    organization_id: UUID,
    asset_id: UUID,
    service_asset_id: UUID | None,
    rule: TechnologySignature,
    version_value: str | None,
) -> str:
    serialized = [
        str(organization_id),
        str(asset_id),
        str(service_asset_id) if service_asset_id is not None else "",
        rule.rule_id,
        str(rule.rule_version),
        rule.rule_hash,
        version_value or "",
    ]
    return hashlib.sha256(
        json.dumps(serialized, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def _database_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _independent_confidence_components(
    fingerprints: list[TechnologyFingerprint],
) -> list[dict[str, object]]:
    strongest_by_field: dict[str, TechnologyFingerprint] = {}
    for fingerprint in fingerprints:
        for field in fingerprint.evidence_fields_json:
            current = strongest_by_field.get(field)
            if current is None or fingerprint.base_confidence > current.base_confidence:
                strongest_by_field[field] = fingerprint
    return [
        {
            "field": field,
            "confidence": fingerprint.base_confidence,
            "rule_id": fingerprint.rule_id,
            "rule_version": fingerprint.rule_version,
        }
        for field, fingerprint in sorted(strongest_by_field.items())
    ]


def _combine_confidence(confidences: Iterable[object]) -> float:
    product = 1.0
    for confidence in confidences:
        value = cast(float, confidence)
        product *= 1 - value
    return round(1 - product, 8)
