import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import regex
import yaml

_SCHEMA_VERSION = 1
_ALLOWED_TOP_LEVEL = {
    "schema_version",
    "rule_id",
    "rule_version",
    "name",
    "technology",
    "applies_to",
    "confidence",
    "match",
    "version_extraction",
}
_ALLOWED_TECHNOLOGY_FIELDS = {"vendor", "product", "category"}
_ALLOWED_MATCH_FIELDS = {
    "http.status_code",
    "http.headers.server",
    "http.headers.x-powered-by",
    "http.content_type",
    "http.html.title",
    "http.html.meta_generator",
    "tls.version",
    "tls.alpn",
    "tls.certificate.issuer",
    "tls.certificate.subject",
    "tls.certificate.san",
    "service.application_protocol",
    "service.port",
}
_ALLOWED_OPERATORS = {
    "equals",
    "equals_ci",
    "contains",
    "contains_ci",
    "starts_with",
    "starts_with_ci",
    "ends_with",
    "ends_with_ci",
    "exists",
    "in",
}
_ALLOWED_APPLIES_TO = {"HTTP", "TLS", "SERVICE"}
_MAX_PATTERN_LENGTH = 256
_MAX_REGEX_INPUT_LENGTH = 4_096
_REGEX_TIMEOUT_SECONDS = 0.05
_NESTED_QUANTIFIER = regex.compile(r"\((?:[^()]|\([^()]*\))*[+*][^()]*\)[+*{]")


class TechnologySignatureError(ValueError):
    """Raised when a technology signature is invalid or cannot be safely loaded."""


@dataclass(frozen=True)
class TechnologyDescriptor:
    vendor: str
    product: str
    category: str


@dataclass(frozen=True)
class SignatureClause:
    field: str
    operator: str
    value: str | int | tuple[str | int, ...] | None


@dataclass(frozen=True)
class VersionExtraction:
    field: str
    pattern: str


@dataclass(frozen=True)
class TechnologySignature:
    rule_id: str
    rule_version: int
    name: str
    technology: TechnologyDescriptor
    applies_to: tuple[str, ...]
    confidence: float
    match_all: tuple[SignatureClause, ...]
    match_any: tuple[SignatureClause, ...]
    version_extraction: VersionExtraction | None
    rule_hash: str


@dataclass(frozen=True)
class TechnologyRuleset:
    rules: tuple[TechnologySignature, ...]
    ruleset_hash: str


class TechnologySignatureLoader:
    """Loads a complete, safe, immutable ruleset or rejects it as a whole."""

    def load(self, directory: Path | None = None) -> TechnologyRuleset:
        source_directory = directory or default_signature_directory()
        if not source_directory.is_dir():
            raise TechnologySignatureError("technology signature directory does not exist")
        files = sorted(
            [*source_directory.rglob("*.yaml"), *source_directory.rglob("*.yml")],
            key=lambda path: path.as_posix(),
        )
        if not files:
            raise TechnologySignatureError("technology signature directory contains no YAML rules")
        seen: set[tuple[str, int]] = set()
        rules: list[TechnologySignature] = []
        for path in files:
            rule = self._load_file(path)
            identity = (rule.rule_id, rule.rule_version)
            if identity in seen:
                raise TechnologySignatureError(
                    f"duplicate technology signature identity: {rule.rule_id}@{rule.rule_version}"
                )
            seen.add(identity)
            rules.append(rule)
        ordered_rules = tuple(sorted(rules, key=lambda rule: (rule.rule_id, rule.rule_version)))
        ruleset_hash = hashlib.sha256(
            json.dumps(
                [rule.rule_hash for rule in ordered_rules],
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest()
        return TechnologyRuleset(ordered_rules, ruleset_hash)

    def _load_file(self, path: Path) -> TechnologySignature:
        try:
            loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise TechnologySignatureError(f"could not read signature {path.name}") from exc
        data = _mapping(loaded, f"signature {path.name}")
        _require_exact_keys(
            data,
            _ALLOWED_TOP_LEVEL,
            f"signature {path.name}",
            optional={"version_extraction"},
        )
        schema_version = _integer(data, "schema_version", f"signature {path.name}")
        if schema_version != _SCHEMA_VERSION:
            raise TechnologySignatureError("unsupported technology signature schema version")
        rule_id = _string(data, "rule_id", f"signature {path.name}")
        rule_version = _integer(data, "rule_version", f"signature {path.name}")
        if rule_version < 1:
            raise TechnologySignatureError("technology signature rule_version must be positive")
        name = _string(data, "name", f"signature {path.name}")
        technology_data = _mapping(data["technology"], "technology")
        _require_exact_keys(technology_data, _ALLOWED_TECHNOLOGY_FIELDS, "technology")
        technology = TechnologyDescriptor(
            vendor=_string(technology_data, "vendor", "technology"),
            product=_string(technology_data, "product", "technology"),
            category=_string(technology_data, "category", "technology"),
        )
        applies_to = _parse_applies_to(data["applies_to"])
        confidence = _confidence(data["confidence"])
        match_all, match_any = _parse_match(data["match"])
        version_extraction = _parse_version_extraction(data.get("version_extraction"))
        canonical_rule = {
            "schema_version": schema_version,
            "rule_id": rule_id,
            "rule_version": rule_version,
            "name": name,
            "technology": {
                "vendor": technology.vendor,
                "product": technology.product,
                "category": technology.category,
            },
            "applies_to": list(applies_to),
            "confidence": confidence,
            "match": {
                "all": [_clause_data(clause) for clause in match_all],
                "any": [_clause_data(clause) for clause in match_any],
            },
            "version_extraction": (
                None
                if version_extraction is None
                else {
                    "field": version_extraction.field,
                    "pattern": version_extraction.pattern,
                }
            ),
        }
        canonical_bytes = json.dumps(
            canonical_rule,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        rule_hash = hashlib.sha256(canonical_bytes).hexdigest()
        return TechnologySignature(
            rule_id=rule_id,
            rule_version=rule_version,
            name=name,
            technology=technology,
            applies_to=applies_to,
            confidence=confidence,
            match_all=match_all,
            match_any=match_any,
            version_extraction=version_extraction,
            rule_hash=rule_hash,
        )


def default_signature_directory() -> Path:
    return Path(__file__).resolve().parents[3] / "signatures" / "technology"


def safe_version_pattern(pattern: str) -> regex.Pattern[str]:
    if not pattern or len(pattern) > _MAX_PATTERN_LENGTH:
        raise TechnologySignatureError("version extraction pattern exceeds safe length")
    if "(?<=" in pattern or "(?<!" in pattern or regex.search(r"\\[1-9]", pattern):
        raise TechnologySignatureError("version extraction pattern uses an unsafe construct")
    if _NESTED_QUANTIFIER.search(pattern):
        raise TechnologySignatureError("version extraction pattern contains nested quantifiers")
    try:
        compiled = regex.compile(pattern)
        compiled.search("a" * _MAX_REGEX_INPUT_LENGTH, timeout=_REGEX_TIMEOUT_SECONDS)
    except (TimeoutError, regex.error) as exc:
        raise TechnologySignatureError("version extraction pattern is unsafe") from exc
    return compiled


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise TechnologySignatureError(f"{label} must be a mapping with string keys")
    return cast(dict[str, object], dict(value))


def _require_exact_keys(
    data: dict[str, object],
    allowed: set[str],
    label: str,
    *,
    optional: set[str] | None = None,
) -> None:
    unknown = set(data) - allowed
    missing = (allowed - (optional or set())) - set(data)
    if unknown or missing:
        raise TechnologySignatureError(f"{label} has unknown or missing fields")


def _string(data: dict[str, object], key: str, label: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise TechnologySignatureError(f"{label}.{key} must be a non-empty string")
    return value


def _integer(data: dict[str, object], key: str, label: str) -> int:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise TechnologySignatureError(f"{label}.{key} must be an integer")
    return value


def _confidence(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise TechnologySignatureError("confidence must be a number")
    confidence = float(value)
    if not 0 <= confidence <= 1:
        raise TechnologySignatureError("confidence must be between zero and one")
    return confidence


def _parse_applies_to(value: object) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, str) or not value:
        raise TechnologySignatureError("applies_to must be a non-empty list")
    applies_to = tuple(value)
    if not all(isinstance(item, str) and item in _ALLOWED_APPLIES_TO for item in applies_to):
        raise TechnologySignatureError("applies_to contains an unsupported source")
    return cast(tuple[str, ...], applies_to)


def _parse_match(value: object) -> tuple[tuple[SignatureClause, ...], tuple[SignatureClause, ...]]:
    data = _mapping(value, "match")
    if not data or set(data) - {"all", "any"}:
        raise TechnologySignatureError("match must contain only all and/or any")
    match_all = _parse_clauses(data.get("all", []), "match.all")
    match_any = _parse_clauses(data.get("any", []), "match.any")
    if not match_all and not match_any:
        raise TechnologySignatureError("match must contain at least one clause")
    return match_all, match_any


def _parse_clauses(value: object, label: str) -> tuple[SignatureClause, ...]:
    if not isinstance(value, list):
        raise TechnologySignatureError(f"{label} must be a list")
    clauses: list[SignatureClause] = []
    for index, raw_clause in enumerate(value):
        clause = _mapping(raw_clause, f"{label}[{index}]")
        required = {"field", "operator"}
        allowed = {*required, "value"}
        if set(clause) - allowed or required - set(clause):
            raise TechnologySignatureError(f"{label}[{index}] has unknown or missing fields")
        field = _string(clause, "field", f"{label}[{index}]")
        if field not in _ALLOWED_MATCH_FIELDS:
            raise TechnologySignatureError(f"unsupported signature field: {field}")
        operator = _string(clause, "operator", f"{label}[{index}]")
        if operator not in _ALLOWED_OPERATORS:
            raise TechnologySignatureError(f"unsupported signature operator: {operator}")
        raw_value = clause.get("value")
        if operator == "exists":
            if "value" in clause:
                raise TechnologySignatureError("exists operator does not accept a value")
            normalized_value: str | int | tuple[str | int, ...] | None = None
        elif operator == "in":
            if not isinstance(raw_value, list) or not raw_value:
                raise TechnologySignatureError("in operator requires a non-empty list value")
            valid_values = all(
                isinstance(item, str | int) and not isinstance(item, bool) for item in raw_value
            )
            if not valid_values:
                raise TechnologySignatureError("in values must be strings or integers")
            normalized_value = tuple(cast(list[str | int], raw_value))
        elif isinstance(raw_value, str | int) and not isinstance(raw_value, bool):
            normalized_value = raw_value
        else:
            raise TechnologySignatureError(
                f"{operator} operator requires a string or integer value"
            )
        clauses.append(SignatureClause(field, operator, normalized_value))
    return tuple(clauses)


def _parse_version_extraction(value: object) -> VersionExtraction | None:
    if value is None:
        return None
    data = _mapping(value, "version_extraction")
    _require_exact_keys(data, {"field", "pattern"}, "version_extraction")
    field = _string(data, "field", "version_extraction")
    if field not in _ALLOWED_MATCH_FIELDS:
        raise TechnologySignatureError(f"unsupported signature field: {field}")
    pattern = _string(data, "pattern", "version_extraction")
    safe_version_pattern(pattern)
    return VersionExtraction(field, pattern)


def _clause_data(clause: SignatureClause) -> dict[str, object]:
    value: object = clause.value
    if isinstance(value, tuple):
        value = list(value)
    return {"field": clause.field, "operator": clause.operator, "value": value}
