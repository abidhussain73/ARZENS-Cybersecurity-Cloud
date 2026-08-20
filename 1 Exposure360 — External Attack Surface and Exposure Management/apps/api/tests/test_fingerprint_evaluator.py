from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from exposure360_api.db import Base
from exposure360_api.fingerprint_evaluator import (
    CONFIDENCE_MODEL_VERSION,
    FingerprintEvaluationError,
    FingerprintEvaluator,
)
from exposure360_api.models import (
    Asset,
    CanonicalObservation,
    FingerprintEvidenceLink,
    Organization,
    TechnologyFingerprint,
)
from exposure360_api.technology_signatures import (
    TechnologySignatureLoader,
    default_signature_directory,
)


@pytest.fixture
def database_session() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection: object, _: object) -> None:
        connection.execute("PRAGMA foreign_keys=ON")  # type: ignore[union-attr]

    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _asset(session: Session, slug: str) -> Asset:
    organization = Organization(id=uuid4(), name=slug, slug=slug)
    session.add(organization)
    session.flush()
    observed_at = datetime(2026, 1, 20, tzinfo=UTC)
    asset = Asset(
        id=uuid4(),
        organization_id=organization.id,
        asset_type="DOMAIN",
        canonical_key=f"domain:{slug}.example.test",
        display_name=f"{slug}.example.test",
        first_seen=observed_at,
        last_seen=observed_at,
    )
    session.add(asset)
    session.commit()
    return asset


def _observation(
    session: Session,
    asset: Asset,
    payload: dict[str, object],
    observed_at: datetime,
) -> CanonicalObservation:
    observation = CanonicalObservation(
        id=uuid4(),
        organization_id=asset.organization_id,
        asset_id=asset.id,
        observation_type="HTTP_RESPONSE",
        source_type="FIXTURE",
        source_key="fixture",
        source_record_key=str(uuid4()),
        observed_at=observed_at,
        collected_at=observed_at,
        normalized_payload_json=payload,
        normalized_payload_hash=uuid4().hex + uuid4().hex,
        idempotency_key=uuid4().hex + uuid4().hex,
    )
    session.add(observation)
    session.commit()
    return observation


def _signature(
    rule_id: str,
    product: str,
    category: str,
    field: str,
    value: str,
    confidence: float,
) -> str:
    return f"""schema_version: 1
rule_id: {rule_id}
rule_version: 1
name: {product}
technology:
  vendor: Fixture
  product: {product}
  category: {category}
applies_to:
  - HTTP
confidence: {confidence}
match:
  all:
    - field: {field}
      operator: equals
      value: {value}
"""


def test_http_tls_service_version_confidence_and_provenance(database_session: Session) -> None:
    asset = _asset(database_session, "fingerprint-fixture")
    now = datetime(2026, 1, 20, tzinfo=UTC)
    ruleset = TechnologySignatureLoader().load(default_signature_directory())
    evaluator = FingerprintEvaluator()
    http = _observation(
        database_session,
        asset,
        {"http": {"headers": {"server": "FixtureWeb/1.2.3"}}},
        now,
    )
    http_results = evaluator.evaluate(database_session, observation=http, ruleset=ruleset)
    assert len(http_results) == 1
    assert http_results[0].fingerprint.technology_product == "FixtureWeb"
    assert http_results[0].fingerprint.version_value == "1.2.3"
    assert http_results[0].fingerprint.confidence == pytest.approx(0.8)
    assert http_results[0].fingerprint.confidence_model_version == CONFIDENCE_MODEL_VERSION
    assert http_results[0].fingerprint.ruleset_hash == ruleset.ruleset_hash
    tls = _observation(database_session, asset, {"tls": {"alpn": "h2"}}, now)
    service = _observation(
        database_session,
        asset,
        {"service": {"application_protocol": "fixture-proto", "port": 443}},
        now,
    )
    tls_results = evaluator.evaluate(database_session, observation=tls, ruleset=ruleset)
    service_results = evaluator.evaluate(database_session, observation=service, ruleset=ruleset)
    assert tls_results[0].fingerprint.technology_product == "FixtureTLS"
    assert service_results[0].fingerprint.technology_product == "FixtureService"
    assert database_session.scalar(select(func.count(FingerprintEvidenceLink.id))) == 3


def test_negative_replay_later_observation_and_cross_org_isolation(
    database_session: Session,
) -> None:
    asset = _asset(database_session, "fingerprint-history")
    other_asset = _asset(database_session, "fingerprint-other")
    now = datetime(2026, 1, 20, tzinfo=UTC)
    ruleset = TechnologySignatureLoader().load(default_signature_directory())
    evaluator = FingerprintEvaluator()
    negative = _observation(
        database_session,
        asset,
        {"http": {"headers": {"server": "GenericServer"}}},
        now,
    )
    assert evaluator.evaluate(database_session, observation=negative, ruleset=ruleset) == []
    first = _observation(
        database_session,
        asset,
        {"http": {"headers": {"server": "FixtureWeb/1.2.3"}}},
        now,
    )
    first_results = evaluator.evaluate(database_session, observation=first, ruleset=ruleset)
    replay_results = evaluator.evaluate(database_session, observation=first, ruleset=ruleset)
    assert first_results[0].created is True
    assert replay_results[0].created is False
    later = _observation(
        database_session,
        asset,
        {"http": {"headers": {"server": "FixtureWeb/1.2.3"}}},
        now + timedelta(days=1),
    )
    evaluator.evaluate(database_session, observation=later, ruleset=ruleset)
    fingerprint = database_session.scalar(
        select(TechnologyFingerprint).where(
            TechnologyFingerprint.organization_id == asset.organization_id,
            TechnologyFingerprint.technology_product == "FixtureWeb",
        )
    )
    assert fingerprint is not None
    assert fingerprint.last_seen == now + timedelta(days=1)
    with pytest.raises(FingerprintEvaluationError, match="another organization"):
        evaluator.evaluate(
            database_session,
            observation=first,
            ruleset=ruleset,
            service_asset=other_asset,
        )


def test_independent_confidence_deduplicates_fields_and_surfaces_category_conflict(
    database_session: Session,
    tmp_path: Path,
) -> None:
    rules_directory = tmp_path / "technology"
    rules_directory.mkdir()
    rules = [
        _signature(
            "tech.combined.server",
            "FixtureCombined",
            "web_server",
            "http.headers.server",
            "FixtureWeb",
            0.8,
        ),
        _signature(
            "tech.combined.powered",
            "FixtureCombined",
            "web_server",
            "http.headers.x-powered-by",
            "FixtureRuntime",
            0.75,
        ),
        _signature(
            "tech.conflict.alpha",
            "FixtureAlpha",
            "framework",
            "http.headers.server",
            "FixtureWeb",
            0.8,
        ),
        _signature(
            "tech.conflict.beta",
            "FixtureBeta",
            "framework",
            "http.headers.server",
            "FixtureWeb",
            0.78,
        ),
    ]
    for index, rule in enumerate(rules):
        (rules_directory / f"rule-{index}.yaml").write_text(rule, encoding="utf-8")
    asset = _asset(database_session, "fingerprint-confidence")
    now = datetime(2026, 1, 20, tzinfo=UTC)
    observation = _observation(
        database_session,
        asset,
        {
            "http": {
                "headers": {
                    "server": "FixtureWeb",
                    "x-powered-by": "FixtureRuntime",
                }
            }
        },
        now,
    )
    evaluator = FingerprintEvaluator()
    ruleset = TechnologySignatureLoader().load(rules_directory)
    evaluator.evaluate(database_session, observation=observation, ruleset=ruleset)
    combined = database_session.scalar(
        select(TechnologyFingerprint).where(
            TechnologyFingerprint.organization_id == asset.organization_id,
            TechnologyFingerprint.technology_product == "FixtureCombined",
        )
    )
    assert combined is not None
    assert combined.confidence == pytest.approx(0.95)
    assert len(combined.confidence_components_json) == 2
    duplicate = _observation(
        database_session,
        asset,
        observation.normalized_payload_json,
        now + timedelta(hours=1),
    )
    evaluator.evaluate(database_session, observation=duplicate, ruleset=ruleset)
    database_session.refresh(combined)
    assert combined.confidence == pytest.approx(0.95)
    assert len(combined.confidence_components_json) == 2
    conflicts = list(
        database_session.scalars(
            select(TechnologyFingerprint).where(
                TechnologyFingerprint.organization_id == asset.organization_id,
                TechnologyFingerprint.technology_category == "framework",
            )
        )
    )
    assert {fingerprint.fingerprint_state for fingerprint in conflicts} == {"CONFLICT"}
