"""Safe, declarative exposure-rule loading and repository synchronization."""

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, cast

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import ExposureRuleVersion

RuleSeverity = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
ActivationState = Literal["ACTIVE", "DISABLED", "DEPRECATED"]
_SEVERITIES: Final[frozenset[str]] = frozenset({"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"})
_ACTIVATION_STATES: Final[frozenset[str]] = frozenset({"ACTIVE", "DISABLED", "DEPRECATED"})
_OPERATORS: Final[frozenset[str]] = frozenset(
    {
        "equals",
        "not_equals",
        "equals_ci",
        "contains",
        "contains_ci",
        "starts_with",
        "ends_with",
        "exists",
        "not_exists",
        "in",
        "not_in",
        "less_than",
        "less_than_or_equal",
        "greater_than",
        "greater_than_or_equal",
        "before",
        "after",
    }
)
_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "asset.asset_type",
        "asset.lifecycle_state",
        "service.application_protocol",
        "service.port",
        "service.service_kind",
        "http.status_code",
        "http.headers.server",
        "http.headers.strict_transport_security",
        "http.headers.content_security_policy",
        "http.headers.x_content_type_options",
        "tls.certificate.not_after",
        "tls.certificate.not_before",
        "tls.validation_state",
        "tls.version",
        "ownership.primary_present",
        "ownership.conflict",
        "technology.product",
        "technology.version_value",
    }
)
_ROOT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "rule_id",
        "rule_version",
        "title",
        "description",
        "category",
        "severity",
        "activation_state",
        "applies_to",
        "confidence",
        "condition",
        "evidence_fields",
        "recommendation_hint",
        "metadata",
    }
)
_MAX_CONDITION_DEPTH: Final[int] = 5


class ExposureRuleValidationError(ValueError):
    """Raised for malformed, unsafe, or internally inconsistent declarative rules."""


@dataclass(frozen=True)
class ExposureRuleClause:
    field: str
    operator: str
    value: str | int | float | bool | tuple[str | int | float | bool, ...] | None


@dataclass(frozen=True)
class ExposureCondition:
    all: tuple["ExposureCondition | ExposureRuleClause", ...] = ()
    any: tuple["ExposureCondition | ExposureRuleClause", ...] = ()
    not_: tuple["ExposureCondition | ExposureRuleClause", ...] = ()


@dataclass(frozen=True)
class ExposureRule:
    rule_id: str
    rule_version: int
    title: str
    description: str
    category: str
    severity: RuleSeverity
    activation_state: ActivationState
    asset_types: tuple[str, ...]
    observation_types: tuple[str, ...]
    base_confidence: float
    condition: ExposureCondition
    evidence_fields: tuple[str, ...]
    recommendation_hint: str | None
    tags: tuple[str, ...]
    content_hash: str


@dataclass(frozen=True)
class ExposureRuleset:
    rules: tuple[ExposureRule, ...]
    ruleset_hash: str


def default_exposure_rule_directory() -> Path:
    return Path(__file__).resolve().parents[3] / "rules" / "exposure"


class ExposureRuleLoader:
    def load(self, directory: Path) -> ExposureRuleset:
        if not directory.exists():
            raise ExposureRuleValidationError(f"rule directory does not exist: {directory}")
        rules = tuple(self._load_file(path) for path in sorted(directory.rglob("*.yaml")))
        if not rules:
            raise ExposureRuleValidationError("ruleset must contain at least one rule")
        self._validate_uniqueness(rules)
        ordered = tuple(sorted(rules, key=lambda rule: (rule.rule_id, rule.rule_version)))
        ruleset_hash = _sha256([rule.content_hash for rule in ordered])
        return ExposureRuleset(rules=ordered, ruleset_hash=ruleset_hash)

    def synchronize(self, session: Session, ruleset: ExposureRuleset) -> None:
        for rule in ruleset.rules:
            existing = session.scalar(
                select(ExposureRuleVersion).where(
                    ExposureRuleVersion.rule_id == rule.rule_id,
                    ExposureRuleVersion.rule_version == rule.rule_version,
                )
            )
            if existing is None:
                session.add(
                    ExposureRuleVersion(
                        rule_id=rule.rule_id,
                        rule_version=rule.rule_version,
                        title=rule.title,
                        category=rule.category,
                        severity=rule.severity,
                        base_confidence=rule.base_confidence,
                        content_hash=rule.content_hash,
                        activation_state=rule.activation_state,
                    )
                )
            elif existing.content_hash != rule.content_hash:
                raise ExposureRuleValidationError("released rule version content is immutable")

    def _load_file(self, path: Path) -> ExposureRule:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as error:
            raise ExposureRuleValidationError(f"invalid YAML in {path.name}") from error
        if not isinstance(raw, dict):
            raise ExposureRuleValidationError(f"rule {path.name} must be a mapping")
        unknown = set(raw).difference(_ROOT_FIELDS)
        if unknown:
            raise ExposureRuleValidationError(f"unknown rule fields: {sorted(unknown)}")
        required = {
            "schema_version",
            "rule_id",
            "rule_version",
            "title",
            "description",
            "category",
            "severity",
            "applies_to",
            "confidence",
            "condition",
            "evidence_fields",
        }
        missing = required.difference(raw)
        if missing:
            raise ExposureRuleValidationError(f"missing rule fields: {sorted(missing)}")
        if raw["schema_version"] != 1:
            raise ExposureRuleValidationError("unsupported rule schema version")
        rule_id = _string(raw["rule_id"], "rule_id")
        rule_version = _positive_int(raw["rule_version"], "rule_version")
        severity = _enum(raw["severity"], _SEVERITIES, "severity")
        activation_state = _enum(
            raw.get("activation_state", "ACTIVE"), _ACTIVATION_STATES, "activation_state"
        )
        applies_to = _mapping(raw["applies_to"], "applies_to")
        asset_types = _string_tuple(applies_to.get("asset_types"), "applies_to.asset_types")
        observation_types = _string_tuple(
            applies_to.get("observation_types"), "applies_to.observation_types"
        )
        confidence = _mapping(raw["confidence"], "confidence")
        base_confidence = _confidence(confidence.get("base"))
        condition = _condition(raw["condition"], depth=1)
        if isinstance(condition, ExposureRuleClause):
            raise ExposureRuleValidationError("top-level condition must be a logical group")
        evidence_fields = _string_tuple(raw["evidence_fields"], "evidence_fields")
        for field in evidence_fields:
            _safe_field(field)
        metadata = _mapping(raw.get("metadata", {}), "metadata")
        tags = _string_tuple(metadata.get("tags", []), "metadata.tags")
        canonical = _canonical_rule(raw)
        return ExposureRule(
            rule_id=rule_id,
            rule_version=rule_version,
            title=_string(raw["title"], "title"),
            description=_string(raw["description"], "description"),
            category=_string(raw["category"], "category"),
            severity=cast(RuleSeverity, severity),
            activation_state=cast(ActivationState, activation_state),
            asset_types=asset_types,
            observation_types=observation_types,
            base_confidence=base_confidence,
            condition=condition,
            evidence_fields=evidence_fields,
            recommendation_hint=_optional_string(
                raw.get("recommendation_hint"), "recommendation_hint"
            ),
            tags=tags,
            content_hash=_sha256(canonical),
        )

    @staticmethod
    def _validate_uniqueness(rules: tuple[ExposureRule, ...]) -> None:
        identities = [(rule.rule_id, rule.rule_version) for rule in rules]
        if len(identities) != len(set(identities)):
            raise ExposureRuleValidationError("duplicate rule_id and rule_version")
        active_ids = [rule.rule_id for rule in rules if rule.activation_state == "ACTIVE"]
        if len(active_ids) != len(set(active_ids)):
            raise ExposureRuleValidationError("two active versions for one rule_id")


def _condition(value: object, depth: int) -> ExposureCondition | ExposureRuleClause:
    if depth > _MAX_CONDITION_DEPTH:
        raise ExposureRuleValidationError("condition nesting exceeds maximum depth")
    mapping = _mapping(value, "condition")
    clause_keys = {"field", "operator", "value"}
    logical_keys = {"all", "any", "not"}
    keys = set(mapping)
    if keys.intersection(clause_keys):
        if not {"field", "operator"}.issubset(mapping):
            raise ExposureRuleValidationError("condition clause requires field and operator")
        if keys.difference(clause_keys):
            raise ExposureRuleValidationError("unknown condition clause field")
        operator = _enum(mapping["operator"], _OPERATORS, "condition.operator")
        normalized = _normalize_value(mapping.get("value"))
        if operator not in {"exists", "not_exists"} and normalized is None:
            raise ExposureRuleValidationError("condition value is required")
        return ExposureRuleClause(
            field=_safe_field(mapping["field"]), operator=operator, value=normalized
        )
    if not keys or keys.difference(logical_keys):
        raise ExposureRuleValidationError("condition requires only all, any, or not")
    return ExposureCondition(
        all=_condition_tuple(mapping["all"], depth) if "all" in mapping else (),
        any=_condition_tuple(mapping["any"], depth) if "any" in mapping else (),
        not_=_condition_tuple(mapping["not"], depth) if "not" in mapping else (),
    )


def _condition_tuple(
    value: object, depth: int
) -> tuple[ExposureCondition | ExposureRuleClause, ...]:
    if not isinstance(value, list) or not value:
        raise ExposureRuleValidationError("logical condition requires a non-empty list")
    return tuple(_condition(item, depth + 1) for item in value)


def _safe_field(value: object) -> str:
    field = _string(value, "condition.field")
    if field not in _FIELDS:
        raise ExposureRuleValidationError(f"unknown or unsafe rule field: {field}")
    return field


def _mapping(value: object, field: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ExposureRuleValidationError(f"{field} must be a mapping")
    return cast(dict[str, object], value)


def _string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ExposureRuleValidationError(f"{field} must be a non-empty string")
    return value.strip()


def _optional_string(value: object, field: str) -> str | None:
    return None if value is None else _string(value, field)


def _string_tuple(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise ExposureRuleValidationError(f"{field} must be a non-empty string list")
    return tuple(item.strip() for item in value)


def _positive_int(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ExposureRuleValidationError(f"{field} must be a positive integer")
    return value


def _confidence(value: object) -> float:
    if not isinstance(value, int | float) or isinstance(value, bool) or not 0 <= float(value) <= 1:
        raise ExposureRuleValidationError("confidence.base must be between 0 and 1")
    return float(value)


def _enum(value: object, allowed: frozenset[str], field: str) -> str:
    candidate = _string(value, field)
    if candidate not in allowed:
        raise ExposureRuleValidationError(f"invalid {field}: {candidate}")
    return candidate


def _normalize_value(
    value: object,
) -> str | int | float | bool | tuple[str | int | float | bool, ...] | None:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if (
        isinstance(value, list)
        and value
        and all(isinstance(item, str | int | float | bool) for item in value)
    ):
        return tuple(cast(str | int | float | bool, item) for item in value)
    raise ExposureRuleValidationError("condition value must be a scalar or non-empty scalar list")


def _canonical_rule(raw: dict[str, object]) -> str:
    return json.dumps(
        raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _sha256(value: object) -> str:
    material = (
        value
        if isinstance(value, str)
        else json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
