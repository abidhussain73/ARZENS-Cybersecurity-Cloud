from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from exposure360_api.db import Base
from exposure360_api.exposure_rules import (
    ExposureRuleLoader,
    ExposureRuleValidationError,
    default_exposure_rule_directory,
)
from exposure360_api.models import ExposureRuleVersion


def _rule(
    rule_id: str = "exposure.test.rule",
    version: int = 1,
    severity: str = "LOW",
    activation: str = "ACTIVE",
    field: str = "http.headers.server",
    operator: str = "exists",
    confidence: float = 0.8,
) -> str:
    return f"""schema_version: 1
rule_id: {rule_id}
rule_version: {version}
title: Test rule
description: Synthetic metadata-only test rule.
category: TEST
severity: {severity}
activation_state: {activation}
applies_to:
  asset_types: [SERVICE]
  observation_types: [HTTP_RESPONSE]
confidence: {{base: {confidence}}}
condition:
  all:
    - field: {field}
      operator: {operator}
evidence_fields: [http.headers.server]
metadata: {{tags: [fixture]}}
"""


def _write(directory: Path, name: str, content: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(content, encoding="utf-8")


def _session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:", poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def test_default_rules_load_with_stable_rule_and_ruleset_hashes() -> None:
    loader = ExposureRuleLoader()
    first = loader.load(default_exposure_rule_directory())
    second = loader.load(default_exposure_rule_directory())
    assert len(first.rules) == 4
    assert first.ruleset_hash == second.ruleset_hash
    assert [rule.content_hash for rule in first.rules] == [
        rule.content_hash for rule in second.rules
    ]
    assert (
        "eval"
        not in Path(__file__)
        .resolve()
        .parents[1]
        .joinpath("exposure360_api/exposure_rules.py")
        .read_text()
    )
    assert (
        "exec"
        not in Path(__file__)
        .resolve()
        .parents[1]
        .joinpath("exposure360_api/exposure_rules.py")
        .read_text()
    )


@pytest.mark.parametrize(
    ("content", "error"),
    [
        (_rule().replace("rule_id: exposure.test.rule\n", ""), "missing rule fields"),
        (_rule(severity="SEVERE"), "invalid severity"),
        (_rule(confidence=1.1), "confidence.base"),
        (_rule(field="database.raw_sql"), "unknown or unsafe rule field"),
        (_rule(operator="regex"), "invalid condition.operator"),
    ],
)
def test_invalid_rule_schema_is_rejected(tmp_path: Path, content: str, error: str) -> None:
    _write(tmp_path, "invalid.yaml", content)
    with pytest.raises(ExposureRuleValidationError, match=error):
        ExposureRuleLoader().load(tmp_path)


def test_depth_duplicates_and_two_active_versions_are_rejected(tmp_path: Path) -> None:
    too_deep = (
        "  all:\n    - all:\n      - all:\n        - all:\n          - all:\n"
        "            - all:\n              - field: http.headers.server\n"
        "                operator: exists"
    )
    nested = _rule().replace(
        "  all:\n    - field: http.headers.server\n      operator: exists",
        too_deep,
    )
    _write(tmp_path, "deep.yaml", nested)
    with pytest.raises(ExposureRuleValidationError, match="nesting"):
        ExposureRuleLoader().load(tmp_path)
    (tmp_path / "deep.yaml").unlink()
    _write(tmp_path, "first.yaml", _rule())
    _write(tmp_path, "second.yaml", _rule())
    with pytest.raises(ExposureRuleValidationError, match="duplicate"):
        ExposureRuleLoader().load(tmp_path)
    for path in tmp_path.glob("*.yaml"):
        path.unlink()
    _write(tmp_path, "v1.yaml", _rule(version=1))
    _write(tmp_path, "v2.yaml", _rule(version=2))
    with pytest.raises(ExposureRuleValidationError, match="two active"):
        ExposureRuleLoader().load(tmp_path)


def test_version_change_changes_hash_and_released_repository_row_is_immutable(
    tmp_path: Path,
) -> None:
    _write(tmp_path, "rule.yaml", _rule(version=1))
    loader = ExposureRuleLoader()
    first = loader.load(tmp_path)
    session = _session()
    try:
        loader.synchronize(session, first)
        session.commit()
        persisted = session.scalar(select(ExposureRuleVersion))
        assert persisted is not None
        assert persisted.content_hash == first.rules[0].content_hash
        _write(tmp_path, "rule.yaml", _rule(version=2))
        second = loader.load(tmp_path)
        assert second.rules[0].content_hash != first.rules[0].content_hash
        loader.synchronize(session, second)
        session.commit()
        assert len(list(session.scalars(select(ExposureRuleVersion)))) == 2
        _write(tmp_path, "rule.yaml", _rule(version=1, severity="MEDIUM"))
        altered = loader.load(tmp_path)
        with pytest.raises(ExposureRuleValidationError, match="immutable"):
            loader.synchronize(session, altered)
    finally:
        session.close()
