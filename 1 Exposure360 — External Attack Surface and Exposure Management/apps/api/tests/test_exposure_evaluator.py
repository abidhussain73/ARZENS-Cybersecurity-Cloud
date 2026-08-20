from datetime import UTC, datetime
from pathlib import Path

from exposure360_api.exposure_evaluator import ExposureFactSet, ExposureRuleEvaluator
from exposure360_api.exposure_rules import ExposureRuleLoader, default_exposure_rule_directory


def _rules():
    return ExposureRuleLoader().load(default_exposure_rule_directory())


def _result(facts: ExposureFactSet, rule_id: str):
    results = ExposureRuleEvaluator().evaluate(facts, _rules(), datetime(2026, 1, 20, tzinfo=UTC))
    return next(result for result in results if result.rule_id == rule_id)


def test_missing_hsts_and_server_disclosure_use_metadata_only_fixtures() -> None:
    facts = ExposureFactSet(
        asset_type="SERVICE",
        observation_type="HTTP_RESPONSE",
        observation_id="obs-1",
        evidence_ids=("ev-1",),
        values={"service.application_protocol": "HTTPS", "http.headers.server": "FixtureWeb/1.2.3"},
    )
    hsts = _result(facts, "exposure.http.missing_hsts")
    disclosure = _result(facts, "exposure.http.server_version_disclosure")
    assert hsts.state == "MATCHED" and hsts.confidence == 0.9 and hsts.evidence_ids == ("ev-1",)
    assert disclosure.state == "MATCHED" and disclosure.severity == "LOW"


def test_present_hsts_generic_header_and_valid_certificate_are_negative() -> None:
    http = ExposureFactSet(
        asset_type="SERVICE",
        observation_type="HTTP_RESPONSE",
        observation_id="obs-1",
        evidence_ids=("ev-1",),
        values={
            "service.application_protocol": "HTTPS",
            "http.headers.strict_transport_security": "max-age=1",
            "http.headers.server": "gateway",
        },
    )
    tls = ExposureFactSet(
        asset_type="SERVICE",
        observation_type="TLS_CERTIFICATE",
        observation_id="obs-2",
        evidence_ids=("ev-2",),
        values={"tls.certificate.not_after": datetime(2026, 2, 1, tzinfo=UTC)},
    )
    assert _result(http, "exposure.http.missing_hsts").state == "NO_MATCH"
    assert _result(http, "exposure.http.server_version_disclosure").state == "NO_MATCH"
    assert _result(tls, "exposure.tls.certificate_expired").state == "NO_MATCH"


def test_expired_certificate_and_missing_owner_match_deterministically() -> None:
    tls = ExposureFactSet(
        asset_type="SERVICE",
        observation_type="TLS_CERTIFICATE",
        observation_id="obs-2",
        evidence_ids=("ev-2",),
        values={"tls.certificate.not_after": datetime(2026, 1, 19, tzinfo=UTC)},
    )
    ownership = ExposureFactSet(
        asset_type="SERVICE",
        observation_type="HTTP_RESPONSE",
        observation_id="obs-3",
        evidence_ids=("ev-3",),
        values={"asset.lifecycle_state": "ACTIVE", "ownership.primary_present": False},
    )
    assert _result(tls, "exposure.tls.certificate_expired").state == "MATCHED"
    assert _result(ownership, "exposure.ownership.missing_owner").state == "MATCHED"
    assert _result(ownership, "exposure.ownership.missing_owner") == _result(
        ownership, "exposure.ownership.missing_owner"
    )


def test_missing_required_metadata_is_insufficient_and_evaluator_has_no_network_imports() -> None:
    facts = ExposureFactSet(
        asset_type="SERVICE",
        observation_type="TLS_CERTIFICATE",
        observation_id=None,
        evidence_ids=(),
        values={},
    )
    assert _result(facts, "exposure.tls.certificate_expired").state == "INSUFFICIENT_DATA"
    source = (
        Path(__file__)
        .resolve()
        .parents[1]
        .joinpath("exposure360_api/exposure_evaluator.py")
        .read_text()
    )
    for forbidden in ("requests", "httpx", "socket", "dns", "ssl", "collector"):
        assert f"import {forbidden}" not in source
