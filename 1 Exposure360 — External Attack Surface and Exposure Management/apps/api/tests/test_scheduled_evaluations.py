from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from exposure360_api.db import Base
from exposure360_api.evaluation_metrics import (
    EVALUATION_ASSETS,
    EVALUATION_RUNS,
    record,
    started_at,
)
from exposure360_api.evaluation_scheduler import (
    EvaluationMetrics,
    EvaluationRunRepository,
    EvaluationSchedulePlanner,
)
from exposure360_api.exposure_rules import (
    ExposureCondition,
    ExposureRule,
    ExposureRuleClause,
    ExposureRuleset,
)
from exposure360_api.models import (
    ApprovedChange,
    Asset,
    AssetOwnership,
    AuditEvent,
    CanonicalObservation,
    ChangeEvent,
    EvaluationRun,
    Evidence,
    Finding,
    FindingEvaluationEvent,
    Organization,
    User,
)
from exposure360_api.scheduled_evaluations import ScheduledEvaluationService

NOW = datetime(2026, 8, 20, 1, 30, tzinfo=UTC)


@pytest.fixture
def session() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection: object, _: object) -> None:
        connection.execute("PRAGMA foreign_keys=ON")  # type: ignore[union-attr]

    Base.metadata.create_all(engine)
    instance = sessionmaker(bind=engine, expire_on_commit=False)()
    try:
        yield instance
    finally:
        instance.close()
        engine.dispose()


def _organization(session: Session) -> Organization:
    organization = Organization(id=uuid4(), name="Scheduled fixture", slug=f"scheduled-{uuid4()}")
    session.add(organization)
    session.commit()
    return organization


def _asset(session: Session, organization: Organization, asset_type: str = "SERVICE") -> Asset:
    asset = Asset(
        id=uuid4(),
        organization_id=organization.id,
        asset_type=asset_type,
        canonical_key=f"{asset_type.lower()}:{uuid4()}",
        display_name="scheduled.fixture.test",
        lifecycle_state="ACTIVE",
        first_seen=NOW,
        last_seen=NOW,
    )
    session.add(asset)
    session.flush()
    return asset


def _run(
    session: Session,
    organization: Organization,
    run_type: str,
    now: datetime,
    ruleset: ExposureRuleset | None = None,
) -> EvaluationRun:
    repository = EvaluationRunRepository(session)
    execution = repository.start_or_skip(
        organization.id,
        run_type,  # type: ignore[arg-type]
        f"acceptance:{run_type}:{now.isoformat()}",
        ruleset_hash=ruleset.ruleset_hash if ruleset is not None else None,
        started_at=now,
    )
    assert execution.run is not None and not execution.skipped_for_overlap
    metrics = ScheduledEvaluationService(session).execute(execution.run, now=now, ruleset=ruleset)
    repository.finish(execution.run, metrics, finished_at=now)
    session.commit()
    return execution.run


def _missing_hsts_ruleset() -> ExposureRuleset:
    rule = ExposureRule(
        rule_id="exposure.http.missing_hsts",
        rule_version=1,
        title="Missing HSTS",
        description="HTTP metadata does not contain an HSTS header.",
        category="HTTP_SECURITY_HEADER",
        severity="MEDIUM",
        activation_state="ACTIVE",
        asset_types=("SERVICE",),
        observation_types=("HTTP_RESPONSE",),
        base_confidence=0.9,
        condition=ExposureCondition(
            all=(ExposureRuleClause("http.headers.strict_transport_security", "not_exists", None),)
        ),
        evidence_fields=("http.headers.strict_transport_security",),
        recommendation_hint=None,
        tags=(),
        content_hash="a" * 64,
    )
    return ExposureRuleset(rules=(rule,), ruleset_hash="b" * 64)


def test_scheduled_rule_evaluation_is_metadata_only_and_idempotent(session: Session) -> None:
    organization = _organization(session)
    asset = _asset(session, organization)
    observation = CanonicalObservation(
        id=uuid4(),
        organization_id=organization.id,
        asset_id=asset.id,
        observation_type="HTTP_RESPONSE",
        source_type="FIXTURE",
        source_key="scheduled-fixture",
        source_record_key="http-1",
        observed_at=NOW,
        collected_at=NOW,
        normalized_payload_json={"headers": {"server": "Fixture"}},
        normalized_payload_hash="c" * 64,
        idempotency_key="d" * 64,
        state="ACCEPTED",
    )
    evidence = Evidence(
        id=uuid4(),
        organization_id=organization.id,
        observation_id=observation.id,
        asset_id=asset.id,
        evidence_type="HTTP_RESPONSE",
        object_store_bucket="fixture-metadata",
        object_store_key=None,
        sha256="e" * 64,
        size_bytes=1,
        media_type="application/json",
        encoding="utf-8",
        source_observed_at=NOW,
        collected_at=NOW,
        stored_at=NOW,
        retention_class="STANDARD",
        sensitivity_class="INTERNAL_METADATA",
        collector_name="fixture",
        collector_version="1",
        metadata_json={},
        idempotency_key="f" * 64,
    )
    session.add_all([observation, evidence])
    session.commit()
    ruleset = _missing_hsts_ruleset()

    first = _run(session, organization, "EXPOSURE_RULE_EVALUATION", NOW, ruleset)
    second = _run(
        session,
        organization,
        "EXPOSURE_RULE_EVALUATION",
        NOW + timedelta(minutes=5),
        ruleset,
    )

    assert first.findings_created == 1
    assert second.findings_created == 0
    assert second.findings_updated == 1
    finding = session.scalar(select(Finding).where(Finding.organization_id == organization.id))
    assert finding is not None
    assert len(list(session.scalars(select(Finding)))) == 1
    assert len(list(session.scalars(select(FindingEvaluationEvent)))) == 2


def test_snapshot_change_expected_suppression_and_expiry_audit(session: Session) -> None:
    organization = _organization(session)
    asset = _asset(session, organization, "DOMAIN")
    _run(session, organization, "ASSET_SNAPSHOT_BUILD", NOW)
    user = User(id=uuid4(), oidc_subject=f"scheduled-user-{uuid4()}")
    session.add(user)
    session.flush()
    approval = ApprovedChange(
        id=uuid4(),
        organization_id=organization.id,
        name="Ownership handoff",
        description="Scheduled fixture change",
        asset_id=asset.id,
        allowed_change_types_json=["OWNERSHIP"],
        component_selector_json={"component_key": "ownership"},
        starts_at=NOW,
        ends_at=NOW + timedelta(days=1),
        reason="Approved maintenance",
        ticket_reference=None,
        approved_by_user_id=user.id,
        created_by_user_id=user.id,
        status="ACTIVE",
    )
    ownership = AssetOwnership(
        id=uuid4(),
        organization_id=organization.id,
        asset_id=asset.id,
        owner_type="TEAM",
        owner_reference="security",
        owner_display_name="Security",
        claim_type="MANUAL",
        confidence=1.0,
        source_type="MANUAL",
        claim_key="g" * 64,
        is_primary=True,
        valid_from=NOW,
    )
    session.add_all([approval, ownership])
    session.commit()
    _run(session, organization, "ASSET_SNAPSHOT_BUILD", NOW + timedelta(minutes=1))
    change_run = _run(session, organization, "CHANGE_DETECTION", NOW + timedelta(minutes=2))
    event = session.scalar(
        select(ChangeEvent).where(ChangeEvent.organization_id == organization.id)
    )

    assert change_run.changes_created == 1
    assert change_run.changes_suppressed == 1
    assert event is not None and event.state == "EXPECTED"
    assert event.approved_change_id == approval.id
    assert (
        session.scalar(
            select(AuditEvent).where(AuditEvent.action == "change_event.suppressed_expected")
        )
        is not None
    )

    finding = Finding(
        id=uuid4(),
        organization_id=organization.id,
        asset_id=asset.id,
        service_asset_id=None,
        rule_id="fixture.exception",
        rule_version=1,
        rule_hash="h" * 64,
        fingerprint="i" * 64,
        title="Expired exception fixture",
        description="Fixture",
        category="FIXTURE",
        rule_severity="LOW",
        confidence=0.5,
        state="EXCEPTION",
        first_seen=NOW,
        last_seen=NOW,
        opened_at=NOW,
        exception_reason="time bounded",
        exception_expires_at=NOW + timedelta(minutes=1),
    )
    session.add(finding)
    session.commit()
    expiry_run = _run(session, organization, "EXCEPTION_EXPIRY", NOW + timedelta(minutes=3))

    assert expiry_run.findings_updated == 1
    assert finding.state == "OPEN"
    expiry_audit = session.scalar(
        select(AuditEvent).where(AuditEvent.action == "finding.exception_expired")
    )
    assert expiry_audit is not None


def test_due_planner_overlap_and_failure_state_are_durable(session: Session) -> None:
    organization = _organization(session)
    settings = SimpleNamespace(
        exposure_evaluation_interval=60,
        snapshot_interval=60,
        change_detection_interval=60,
        exception_expiry_interval=60,
    )
    planner = EvaluationSchedulePlanner(session, settings)  # type: ignore[arg-type]
    assert len(planner.due(NOW)) == 4

    repository = EvaluationRunRepository(session)
    running = repository.start_or_skip(
        organization.id, "CHANGE_DETECTION", "overlap", started_at=NOW
    )
    assert running.run is not None
    assert (organization.id, "CHANGE_DETECTION") not in planner.due(NOW + timedelta(hours=1))
    repository.fail(running.run, "FIXTURE_FAILURE", finished_at=NOW + timedelta(minutes=1))
    session.commit()
    assert running.run.state == "FAILED"
    assert running.run.last_error_code == "FIXTURE_FAILURE"
    assert (organization.id, "CHANGE_DETECTION") in planner.due(NOW + timedelta(hours=1))


def test_evaluation_metrics_increment_with_bounded_labels(session: Session) -> None:
    organization = _organization(session)
    run = _run(session, organization, "ASSET_SNAPSHOT_BUILD", NOW)
    run_labels = EVALUATION_RUNS.labels(run_type=run.run_type, state=run.state)
    asset_labels = EVALUATION_ASSETS.labels(run_type=run.run_type)
    before_runs = run_labels._value.get()  # type: ignore[attr-defined]
    before_assets = asset_labels._value.get()  # type: ignore[attr-defined]

    record(run, EvaluationMetrics(assets_processed=2), started_at())

    assert run_labels._value.get() == before_runs + 1  # type: ignore[attr-defined]
    assert asset_labels._value.get() == before_assets + 2  # type: ignore[attr-defined]
    assert set(EVALUATION_RUNS._labelnames) == {"run_type", "state"}  # type: ignore[attr-defined]
