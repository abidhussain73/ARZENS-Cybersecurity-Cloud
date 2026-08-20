from pathlib import Path

import pytest

from exposure360_api.technology_signatures import (
    TechnologySignatureError,
    TechnologySignatureLoader,
)


def _rule(
    *,
    rule_id: str = "tech.fixture",
    rule_version: int = 1,
    field: str = "http.headers.server",
    operator: str = "contains_ci",
    value: str = "FixtureWeb",
    extraction: str | None = None,
) -> str:
    suffix = ""
    if extraction is not None:
        suffix = f"\nversion_extraction:\n  field: {field}\n  pattern: '{extraction}'\n"
    return f"""schema_version: 1
rule_id: {rule_id}
rule_version: {rule_version}
name: Fixture Rule
technology:
  vendor: Fixture
  product: FixtureWeb
  category: web_server
applies_to:
  - HTTP
confidence: 0.80
match:
  all:
    - field: {field}
      operator: {operator}
      value: {value}
{suffix}"""


def _write_rule(directory: Path, name: str, content: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(content, encoding="utf-8")


def test_valid_rules_load_with_stable_hashes_and_deterministic_sort(tmp_path: Path) -> None:
    _write_rule(tmp_path, "z.yaml", _rule(rule_id="tech.zeta"))
    _write_rule(tmp_path, "a.yaml", _rule(rule_id="tech.alpha"))
    loader = TechnologySignatureLoader()
    first = loader.load(tmp_path)
    second = loader.load(tmp_path)
    assert [rule.rule_id for rule in first.rules] == ["tech.alpha", "tech.zeta"]
    assert first.ruleset_hash == second.ruleset_hash
    assert first.rules[0].rule_hash == second.rules[0].rule_hash


def test_invalid_schema_unknown_field_unknown_operator_and_unsafe_regex_are_rejected(
    tmp_path: Path,
) -> None:
    _write_rule(tmp_path, "invalid-schema.yaml", "schema_version: 1\n")
    with pytest.raises(TechnologySignatureError, match="unknown or missing"):
        TechnologySignatureLoader().load(tmp_path)
    (tmp_path / "invalid-schema.yaml").unlink()
    _write_rule(tmp_path, "unknown-field.yaml", _rule(field="http.raw_body"))
    with pytest.raises(TechnologySignatureError, match="unsupported signature field"):
        TechnologySignatureLoader().load(tmp_path)
    (tmp_path / "unknown-field.yaml").unlink()
    _write_rule(tmp_path, "unknown-operator.yaml", _rule(operator="matches"))
    with pytest.raises(TechnologySignatureError, match="unsupported signature operator"):
        TechnologySignatureLoader().load(tmp_path)
    (tmp_path / "unknown-operator.yaml").unlink()
    _write_rule(tmp_path, "unsafe.yaml", _rule(extraction="(a+)+$"))
    with pytest.raises(TechnologySignatureError, match="unsafe|nested"):
        TechnologySignatureLoader().load(tmp_path)


def test_duplicate_identity_and_new_rule_version_behavior(tmp_path: Path) -> None:
    _write_rule(tmp_path, "one.yaml", _rule(rule_id="tech.fixture", rule_version=1))
    _write_rule(tmp_path, "duplicate.yaml", _rule(rule_id="tech.fixture", rule_version=1))
    with pytest.raises(TechnologySignatureError, match="duplicate"):
        TechnologySignatureLoader().load(tmp_path)
    (tmp_path / "duplicate.yaml").unlink()
    baseline = TechnologySignatureLoader().load(tmp_path)
    _write_rule(tmp_path, "new-version.yaml", _rule(rule_id="tech.fixture", rule_version=2))
    versioned = TechnologySignatureLoader().load(tmp_path)
    assert len(versioned.rules) == 2
    assert versioned.ruleset_hash != baseline.ruleset_hash
