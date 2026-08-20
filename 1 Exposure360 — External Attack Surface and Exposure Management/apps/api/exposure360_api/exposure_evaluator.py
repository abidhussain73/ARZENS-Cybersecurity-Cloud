"""Pure, metadata-only evaluation for declarative exposure rules."""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from .exposure_rules import ExposureCondition, ExposureRule, ExposureRuleClause, ExposureRuleset

EvaluationState = Literal["MATCHED", "NO_MATCH", "NOT_APPLICABLE", "INSUFFICIENT_DATA"]


@dataclass(frozen=True)
class ExposureFactSet:
    asset_type: str
    observation_type: str
    values: dict[str, str | int | float | bool | datetime | None]
    observation_id: str | None
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class ExposureRuleResult:
    rule_id: str
    rule_version: int
    rule_hash: str
    state: EvaluationState
    severity: str
    confidence: float
    reason_codes: tuple[str, ...]
    evidence_ids: tuple[str, ...]


class ExposureRuleEvaluator:
    """Evaluates facts only; this module intentionally has no transport/collector imports."""

    def evaluate(
        self,
        facts: ExposureFactSet,
        ruleset: ExposureRuleset,
        evaluation_time: datetime,
    ) -> tuple[ExposureRuleResult, ...]:
        now = _utc(evaluation_time)
        return tuple(self._evaluate_rule(facts, rule, now) for rule in ruleset.rules)

    def _evaluate_rule(
        self,
        facts: ExposureFactSet,
        rule: ExposureRule,
        evaluation_time: datetime,
    ) -> ExposureRuleResult:
        if (
            facts.asset_type not in rule.asset_types
            or facts.observation_type not in rule.observation_types
        ):
            return self._result(rule, "NOT_APPLICABLE", (), facts)
        matched, incomplete, reason_codes = _matches(rule.condition, facts.values, evaluation_time)
        if incomplete:
            return self._result(rule, "INSUFFICIENT_DATA", reason_codes, facts)
        return self._result(rule, "MATCHED" if matched else "NO_MATCH", reason_codes, facts)

    @staticmethod
    def _result(
        rule: ExposureRule,
        state: EvaluationState,
        reason_codes: tuple[str, ...],
        facts: ExposureFactSet,
    ) -> ExposureRuleResult:
        return ExposureRuleResult(
            rule_id=rule.rule_id,
            rule_version=rule.rule_version,
            rule_hash=rule.content_hash,
            state=state,
            severity=rule.severity,
            confidence=rule.base_confidence if state == "MATCHED" else 0.0,
            reason_codes=reason_codes,
            evidence_ids=facts.evidence_ids if state == "MATCHED" else (),
        )


def _matches(
    condition: ExposureCondition | ExposureRuleClause,
    values: dict[str, str | int | float | bool | datetime | None],
    evaluation_time: datetime,
) -> tuple[bool, bool, tuple[str, ...]]:
    if isinstance(condition, ExposureRuleClause):
        return _clause_matches(condition, values, evaluation_time)
    results = [_matches(item, values, evaluation_time) for item in condition.all]
    any_results = [_matches(item, values, evaluation_time) for item in condition.any]
    not_results = [_matches(item, values, evaluation_time) for item in condition.not_]
    incomplete = any(result[1] for result in results + any_results + not_results)
    all_match = all(result[0] for result in results) if results else True
    any_match = any(result[0] for result in any_results) if any_results else True
    not_match = not any(result[0] for result in not_results)
    codes = tuple(code for result in results + any_results + not_results for code in result[2])
    return all_match and any_match and not_match, incomplete, codes


def _clause_matches(
    clause: ExposureRuleClause,
    values: dict[str, str | int | float | bool | datetime | None],
    evaluation_time: datetime,
) -> tuple[bool, bool, tuple[str, ...]]:
    actual = values.get(clause.field)
    code = clause.field.upper().replace(".", "_")
    if clause.operator == "exists":
        return actual is not None, False, (code,)
    if clause.operator == "not_exists":
        return actual is None, False, (code,)
    if actual is None:
        return False, True, (f"MISSING_{code}",)
    expected = evaluation_time if clause.value == "evaluation_time" else clause.value
    try:
        matched = _compare(actual, clause.operator, expected)
    except (TypeError, ValueError):
        return False, True, (f"INVALID_{code}",)
    return matched, False, (code,)


def _compare(actual: str | int | float | bool | datetime, operator: str, expected: object) -> bool:
    if operator == "equals":
        return actual == expected
    if operator == "not_equals":
        return actual != expected
    if operator == "equals_ci":
        return str(actual).casefold() == str(expected).casefold()
    if operator == "contains":
        return str(expected) in str(actual)
    if operator == "contains_ci":
        return str(expected).casefold() in str(actual).casefold()
    if operator == "starts_with":
        return str(actual).startswith(str(expected))
    if operator == "ends_with":
        return str(actual).endswith(str(expected))
    if operator == "in":
        return actual in _items(expected)
    if operator == "not_in":
        return actual not in _items(expected)
    if operator in {
        "less_than",
        "less_than_or_equal",
        "greater_than",
        "greater_than_or_equal",
    }:
        return _ordered_compare(actual, expected, operator)
    if operator == "before":
        return _as_datetime(actual) < _as_datetime(expected)
    if operator == "after":
        return _as_datetime(actual) > _as_datetime(expected)
    raise ValueError("unsupported operator")


def _items(value: object) -> tuple[object, ...]:
    return value if isinstance(value, tuple) else (value,)


def _ordered_compare(
    actual: str | int | float | bool | datetime,
    expected: object,
    operator: str,
) -> bool:
    if isinstance(actual, bool):
        raise TypeError("boolean metadata cannot use ordered comparison")
    if isinstance(actual, datetime):
        return _order(_utc(actual), _as_datetime(expected), operator)
    if isinstance(actual, str) and isinstance(expected, str):
        return _order(actual, expected, operator)
    if isinstance(actual, int | float) and isinstance(expected, int | float):
        return _order(float(actual), float(expected), operator)
    raise TypeError("ordered comparison requires compatible scalar types")


def _order(left: str | float | datetime, right: str | float | datetime, operator: str) -> bool:
    if type(left) is not type(right):
        raise TypeError("ordered comparison requires matching types")
    if operator == "less_than":
        return left < right  # type: ignore[operator]
    if operator == "less_than_or_equal":
        return left <= right  # type: ignore[operator]
    if operator == "greater_than":
        return left > right  # type: ignore[operator]
    if operator == "greater_than_or_equal":
        return left >= right  # type: ignore[operator]
    raise ValueError("unsupported ordered operator")


def _as_datetime(value: object) -> datetime:
    if isinstance(value, datetime):
        return _utc(value)
    if isinstance(value, str):
        return _utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
    raise TypeError("datetime comparison requires a datetime value")


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
