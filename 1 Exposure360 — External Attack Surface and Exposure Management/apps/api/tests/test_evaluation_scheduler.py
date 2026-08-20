from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from exposure360_api.db import Base
from exposure360_api.evaluation_scheduler import (
    EvaluationMetrics,
    EvaluationRunRepository,
    EvaluationScheduler,
)
from exposure360_api.models import EvaluationRun, Organization

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


def _organization(session: Session, *, active: bool = True) -> Organization:
    organization = Organization(
        id=uuid4(),
        name="Evaluation fixture",
        slug=f"evaluation-{uuid4()}",
        is_active=active,
    )
    session.add(organization)
    session.commit()
    return organization


def test_start_or_skip_prevents_same_organization_type_overlap(session: Session) -> None:
    organization = _organization(session)
    repository = EvaluationRunRepository(session)

    first = repository.start_or_skip(
        organization.id,
        "CHANGE_DETECTION",
        "first-correlation",
        started_at=NOW,
    )
    second = repository.start_or_skip(
        organization.id,
        "CHANGE_DETECTION",
        "second-correlation",
        started_at=NOW,
    )

    assert first.run is not None and not first.skipped_for_overlap
    assert second.run is not None and second.skipped_for_overlap
    assert first.run.id == second.run.id
    running = session.scalar(select(EvaluationRun).where(EvaluationRun.state == "RUNNING"))
    assert running == first.run


def test_scheduler_records_metrics_and_allows_later_terminal_runs(session: Session) -> None:
    organization = _organization(session)
    scheduler = EvaluationScheduler(session)

    completed = scheduler.run_for_organization(
        organization.id,
        "ASSET_SNAPSHOT_BUILD",
        "snapshot-correlation",
        lambda _: EvaluationMetrics(assets_processed=3, snapshots_created=3),
    )
    session.commit()
    later = scheduler.run_for_organization(
        organization.id,
        "ASSET_SNAPSHOT_BUILD",
        "snapshot-correlation-later",
        lambda _: EvaluationMetrics(assets_processed=1, snapshots_created=1, error_count=1),
    )

    assert completed.run is not None
    assert completed.run.state == "COMPLETED"
    assert completed.run.assets_processed == 3
    assert completed.run.snapshots_created == 3
    assert completed.run.finished_at is not None
    assert later.run is not None and later.run.id != completed.run.id
    assert later.run.state == "PARTIAL"
    assert later.run.error_count == 1


def test_rule_evaluation_pins_one_ruleset_hash_and_metrics(session: Session) -> None:
    organization = _organization(session)
    scheduler = EvaluationScheduler(session)
    loads = 0

    def load_ruleset_hash() -> str:
        nonlocal loads
        loads += 1
        return "a" * 64

    execution = scheduler.run_rule_evaluation(
        organization.id,
        "ruleset-correlation",
        load_ruleset_hash,
        lambda _: EvaluationMetrics(findings_matched=2, findings_created=1, findings_updated=1),
    )

    assert loads == 1
    assert execution.run is not None
    assert execution.run.ruleset_hash == "a" * 64
    assert execution.run.findings_matched == 2
    assert execution.run.snapshot_schema_version == 1
    assert execution.run.significance_model_version == "change-significance-v1"


def test_inactive_organization_does_not_create_evaluation_run(session: Session) -> None:
    organization = _organization(session, active=False)

    execution = EvaluationRunRepository(session).start_or_skip(
        organization.id,
        "EXCEPTION_EXPIRY",
        "inactive-correlation",
        started_at=NOW,
    )

    assert execution.run is None
    assert not execution.skipped_for_overlap
