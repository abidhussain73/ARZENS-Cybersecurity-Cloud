import importlib
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from exposure360_api.candidate_reconciliation import CandidateReconciliationService
from exposure360_api.db import Base
from exposure360_api.discovery_contracts import DiscoveryCheckpointContract, DiscoveryStageName
from exposure360_api.discovery_orchestration import (
    DiscoveryJobService,
    DiscoveryJobStateError,
    DiscoveryJobWorker,
    RecordedSourceStageRunner,
    WorkerInterrupted,
)
from exposure360_api.discovery_sources import RecordedPassiveDnsAdapter
from exposure360_api.emergency_stop import EmergencyStopService
from exposure360_api.http_metadata import FixtureHttpTransport, HttpFixtureResponse
from exposure360_api.models import (
    CandidateAsset,
    CandidateObservation,
    CollectionAttempt,
    DeadLetterItem,
    DiscoveryCheckpoint,
    DiscoveryJob,
    DiscoveryJobEvent,
    DiscoveryJobStage,
    DiscoverySource,
    Membership,
    Organization,
    ScanPolicy,
    Scope,
    ScopeApproval,
    ScopeSeed,
    ScopeVersion,
    User,
)
from exposure360_api.recovery_controls import DiscoveryRecoveryService
from exposure360_api.scope_approval import ScopeApprovalService
from exposure360_api.tls_metadata import FixtureTlsConnector, TlsHandshakeResult


class MutableClock:
    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


@pytest.fixture
def database_session() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _approved_context(session: Session) -> dict[str, UUID]:
    user = User(id=uuid4(), oidc_subject=f"job-worker-{uuid4()}")
    organization = Organization(id=uuid4(), name="Job Org", slug=f"job-{uuid4().hex[:8]}")
    scope = Scope(
        id=uuid4(),
        organization_id=organization.id,
        name="Documentation candidates",
        status="ACTIVE",
        created_by_user_id=user.id,
    )
    version = ScopeVersion(
        id=uuid4(),
        organization_id=organization.id,
        scope_id=scope.id,
        version_number=1,
        state="APPROVED",
        created_by_user_id=user.id,
        content_hash="",
    )
    seed = ScopeSeed(
        id=uuid4(),
        organization_id=organization.id,
        scope_version_id=version.id,
        seed_type="DOMAIN",
        raw_value="example.com",
        canonical_value="example.com",
        match_mode="DOMAIN_AND_SUBDOMAINS",
    )
    policy = ScanPolicy(
        id=uuid4(),
        organization_id=organization.id,
        scope_version_id=version.id,
        allowed_protocols=["DNS"],
        max_requests_per_second=1.0,
        max_concurrent_targets=1,
        max_concurrent_requests=1,
        schedule_timezone="UTC",
        schedule_windows=[],
        connect_timeout_seconds=5,
        request_timeout_seconds=5,
        active_scanning_enabled=False,
    )
    source = DiscoverySource(
        id=uuid4(),
        organization_id=organization.id,
        source_key="fixture-passive-dns",
        source_type="RECORDED_PASSIVE_DNS",
        display_name="Recorded Passive DNS",
        adapter_version="1.0.0",
        configuration_reference="fixture:passive-dns-v1",
    )
    membership = Membership(
        id=uuid4(),
        organization_id=organization.id,
        user_id=user.id,
        role="admin",
        is_active=True,
    )
    session.add_all([user, organization, membership, scope, version, seed, policy, source])
    session.flush()
    content_hash = ScopeApprovalService.content_hash(session, version)
    version.content_hash = content_hash
    approval = ScopeApproval(
        id=uuid4(),
        organization_id=organization.id,
        scope_id=scope.id,
        scope_version_id=version.id,
        approved_by_user_id=user.id,
        decision="APPROVED",
        content_hash=content_hash,
    )
    session.add(approval)
    session.commit()
    return {
        "user_id": user.id,
        "organization_id": organization.id,
        "scope_id": scope.id,
        "version_id": version.id,
        "approval_id": approval.id,
        "source_id": source.id,
    }


def _records() -> list[dict[str, object]]:
    return [
        {
            "id": "passive-001",
            "rrname": "www.example.com",
            "rrtype": "A",
            "rdata": "192.0.2.20",
            "first_seen": "2026-01-01T00:00:00Z",
            "last_seen": "2026-01-15T00:00:00Z",
        },
        {
            "id": "passive-002",
            "rrname": "api.example.com",
            "rrtype": "A",
            "rdata": "192.0.2.21",
            "first_seen": "2026-01-02T00:00:00Z",
            "last_seen": "2026-01-15T00:00:00Z",
        },
        {
            "id": "passive-003",
            "rrname": "outside.example.net",
            "rrtype": "A",
            "rdata": "192.0.2.30",
            "first_seen": "2026-01-03T00:00:00Z",
            "last_seen": "2026-01-15T00:00:00Z",
        },
    ]


def _create_job(
    session: Session,
    ids: dict[str, UUID],
    service: DiscoveryJobService,
) -> DiscoveryJob:
    job = service.create_job(
        session,
        organization_id=ids["organization_id"],
        scope_id=ids["scope_id"],
        scope_version_id=ids["version_id"],
        approval_id=ids["approval_id"],
        requested_by_user_id=ids["user_id"],
        correlation_id="phase-three-job-test",
    )
    session.commit()
    return job


def _worker_tasks_module() -> ModuleType:
    worker_package = str(Path(__file__).resolve().parents[2] / "worker")
    if worker_package not in sys.path:
        sys.path.insert(0, worker_package)
    return importlib.import_module("exposure360_worker.tasks")


def test_job_creation_pins_approved_scope_and_initializes_all_stages(
    database_session: Session,
) -> None:
    ids = _approved_context(database_session)
    service = DiscoveryJobService()

    job = _create_job(database_session, ids, service)
    stages = list(
        database_session.scalars(
            select(DiscoveryJobStage).where(DiscoveryJobStage.discovery_job_id == job.id)
        )
    )

    assert job.state == "QUEUED"
    assert job.scope_version_id == ids["version_id"]
    assert job.scope_approval_id == ids["approval_id"]
    assert len(stages) == 8
    assert {stage.stage for stage in stages} == {stage.value for stage in DiscoveryStageName}
    assert (
        database_session.scalar(
            select(func.count()).select_from(DiscoveryJob).where(DiscoveryJob.id == job.id)
        )
        == 1
    )


def test_job_creation_denies_disabled_scope(database_session: Session) -> None:
    ids = _approved_context(database_session)
    scope = database_session.get(Scope, ids["scope_id"])
    assert scope is not None
    scope.status = "DISABLED"
    database_session.commit()

    with pytest.raises(DiscoveryJobStateError, match="not active"):
        _create_job(database_session, ids, DiscoveryJobService())


def test_job_creation_denies_active_emergency_stop(database_session: Session) -> None:
    ids = _approved_context(database_session)
    EmergencyStopService.set_stop(
        database_session,
        organization_id=ids["organization_id"],
        scope_id=None,
        actor_id=ids["user_id"],
        reason="Phase 3 job authorization test",
    )
    database_session.commit()

    with pytest.raises(DiscoveryJobStateError, match="Emergency stop"):
        _create_job(database_session, ids, DiscoveryJobService())


def test_restart_resumes_from_durable_checkpoint_without_duplicate_candidates(
    database_session: Session,
) -> None:
    ids = _approved_context(database_session)
    clock = MutableClock(datetime(2026, 1, 15, tzinfo=UTC))
    jobs = DiscoveryJobService(clock=clock)
    job = _create_job(database_session, ids, jobs)
    source = database_session.get(DiscoverySource, ids["source_id"])
    assert source is not None
    adapter = RecordedPassiveDnsAdapter(_records(), page_size=2, clock=clock)
    runner = RecordedSourceStageRunner(
        jobs=jobs,
        reconciler=CandidateReconciliationService(clock=clock),
        clock=clock,
    )

    with pytest.raises(WorkerInterrupted):
        runner.run(
            database_session,
            organization_id=ids["organization_id"],
            job_id=job.id,
            source=source,
            adapter=adapter,
            stage=DiscoveryStageName.PASSIVE_SOURCE,
            worker_token="worker-one",
            lease_seconds=5,
            correlation_id="phase-three-job-test",
            interrupt_after_batches=1,
        )
    checkpoint = database_session.scalar(
        select(DiscoveryCheckpoint).where(
            DiscoveryCheckpoint.discovery_job_id == job.id,
            DiscoveryCheckpoint.stage == DiscoveryStageName.PASSIVE_SOURCE.value,
        )
    )
    assert checkpoint is not None
    assert checkpoint.token_json == {"record_index": 2}
    assert database_session.scalar(select(func.count()).select_from(CandidateAsset)) == 4

    clock.now += timedelta(seconds=6)
    assert runner.run(
        database_session,
        organization_id=ids["organization_id"],
        job_id=job.id,
        source=source,
        adapter=adapter,
        stage=DiscoveryStageName.PASSIVE_SOURCE,
        worker_token="worker-two",
        lease_seconds=5,
        correlation_id="phase-three-job-test",
    )
    assert not runner.run(
        database_session,
        organization_id=ids["organization_id"],
        job_id=job.id,
        source=source,
        adapter=adapter,
        stage=DiscoveryStageName.PASSIVE_SOURCE,
        worker_token="duplicate-delivery",
        lease_seconds=5,
        correlation_id="phase-three-job-test",
    )
    stage = database_session.scalar(
        select(DiscoveryJobStage).where(
            DiscoveryJobStage.discovery_job_id == job.id,
            DiscoveryJobStage.stage == DiscoveryStageName.PASSIVE_SOURCE.value,
        )
    )
    assert stage is not None
    assert stage.state == "COMPLETED"
    assert stage.processed_count == 3
    assert stage.succeeded_count == 2
    assert stage.skipped_count == 1
    assert database_session.scalar(select(func.count()).select_from(CandidateAsset)) == 4
    assert database_session.scalar(select(func.count()).select_from(CandidateObservation)) == 4


def test_finalization_requires_all_stages_to_reach_terminal_state(
    database_session: Session,
) -> None:
    ids = _approved_context(database_session)
    service = DiscoveryJobService()
    job = _create_job(database_session, ids, service)

    with pytest.raises(DiscoveryJobStateError, match="queued stages"):
        service.finalize(
            database_session,
            organization_id=ids["organization_id"],
            job_id=job.id,
        )
    for stage in database_session.scalars(
        select(DiscoveryJobStage).where(DiscoveryJobStage.discovery_job_id == job.id)
    ):
        stage.state = "SKIPPED"
    database_session.commit()

    assert (
        service.finalize(
            database_session,
            organization_id=ids["organization_id"],
            job_id=job.id,
        )
        == "COMPLETED"
    )


def test_worker_executes_configured_fixture_stage_with_durable_progress(
    database_session: Session,
) -> None:
    ids = _approved_context(database_session)
    job = _create_job(database_session, ids, DiscoveryJobService())
    bind = database_session.get_bind()
    worker = DiscoveryJobWorker(
        session_factory=sessionmaker(bind=bind, expire_on_commit=False),
        lease_seconds=5,
    )

    assert (
        worker.run(
            organization_id=ids["organization_id"],
            job_id=job.id,
            correlation_id="worker-integration-test",
            worker_token="test-celery-delivery",
        )
        == "completed"
    )
    database_session.expire_all()
    passive_stage = database_session.scalar(
        select(DiscoveryJobStage).where(
            DiscoveryJobStage.discovery_job_id == job.id,
            DiscoveryJobStage.stage == DiscoveryStageName.PASSIVE_SOURCE.value,
        )
    )
    checkpoint = database_session.scalar(
        select(DiscoveryCheckpoint).where(
            DiscoveryCheckpoint.discovery_job_id == job.id,
            DiscoveryCheckpoint.stage == DiscoveryStageName.PASSIVE_SOURCE.value,
        )
    )
    assert passive_stage is not None
    assert checkpoint is not None
    assert passive_stage.state == "COMPLETED"
    assert passive_stage.processed_count == 2
    assert checkpoint.token_json == {"completed": True, "processed": 2}
    assert {
        stage.state
        for stage in database_session.scalars(
            select(DiscoveryJobStage).where(DiscoveryJobStage.discovery_job_id == job.id)
        )
    }.issubset({"COMPLETED", "SKIPPED"})

    progress = DiscoveryJobService().progress(
        database_session,
        organization_id=ids["organization_id"],
        job_id=job.id,
    )
    completed_job = database_session.get(DiscoveryJob, job.id)
    assert completed_job is not None
    assert completed_job.state == "COMPLETED"
    assert progress.processed == 2
    assert progress.queued == 0
    assert progress.known_total is None
    assert progress.indeterminate is True


def test_celery_task_body_executes_real_worker_with_sqlite_and_redelivery(
    database_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ids = _approved_context(database_session)
    job = _create_job(database_session, ids, DiscoveryJobService())
    session_factory = sessionmaker(bind=database_session.get_bind(), expire_on_commit=False)

    class TaskSettings:
        discovery_stage_lease_seconds = 5

    from exposure360_api import config, db

    monkeypatch.setattr(db, "SessionLocal", session_factory)
    monkeypatch.setattr(config, "get_settings", lambda: TaskSettings())
    worker_tasks = _worker_tasks_module()
    task = worker_tasks.run_discovery_job

    first = task.run(str(ids["organization_id"]), str(job.id), "sqlite-task-integration")
    second = task.run(str(ids["organization_id"]), str(job.id), "sqlite-task-redelivery")

    database_session.expire_all()
    passive_stage = database_session.scalar(
        select(DiscoveryJobStage).where(
            DiscoveryJobStage.discovery_job_id == job.id,
            DiscoveryJobStage.stage == DiscoveryStageName.PASSIVE_SOURCE.value,
        )
    )
    checkpoint = database_session.scalar(
        select(DiscoveryCheckpoint).where(
            DiscoveryCheckpoint.discovery_job_id == job.id,
            DiscoveryCheckpoint.stage == DiscoveryStageName.PASSIVE_SOURCE.value,
        )
    )
    completed_job = database_session.get(DiscoveryJob, job.id)
    assert first["status"] == "completed"
    assert second["status"] == "completed"
    assert passive_stage is not None
    assert checkpoint is not None
    assert completed_job is not None
    assert passive_stage.state == "COMPLETED"
    assert checkpoint.token_json == {"completed": True, "processed": 2}
    assert completed_job.state == "COMPLETED"
    assert database_session.scalar(select(func.count()).select_from(CandidateAsset)) == 4
    assert database_session.scalar(select(func.count()).select_from(CandidateObservation)) == 4


def test_progress_snapshot_reports_known_remaining_work_truthfully(
    database_session: Session,
) -> None:
    ids = _approved_context(database_session)
    service = DiscoveryJobService()
    job = _create_job(database_session, ids, service)
    lease = service.claim_stage(
        database_session,
        organization_id=ids["organization_id"],
        job_id=job.id,
        stage=DiscoveryStageName.PASSIVE_SOURCE,
        worker_token="known-total-progress",
        lease_seconds=5,
        correlation_id="known-total-progress",
    )
    assert lease is not None
    service.save_checkpoint(
        database_session,
        lease=lease,
        checkpoint=DiscoveryCheckpointContract(
            source_key="fixture-passive-dns",
            adapter_version="1.0.0",
            stage=DiscoveryStageName.PASSIVE_SOURCE,
            token={"record_index": 2},
        ),
        processed_count=2,
        succeeded_count=2,
        failed_count=0,
        skipped_count=0,
        known_total=5,
    )
    database_session.commit()

    progress = service.progress(
        database_session,
        organization_id=ids["organization_id"],
        job_id=job.id,
    )
    stage = database_session.scalar(
        select(DiscoveryJobStage).where(
            DiscoveryJobStage.discovery_job_id == job.id,
            DiscoveryJobStage.stage == DiscoveryStageName.PASSIVE_SOURCE.value,
        )
    )
    assert stage is not None
    assert progress.processed == 2
    assert progress.succeeded == 2
    assert progress.known_total == 5
    assert progress.queued == 3
    assert progress.indeterminate is False
    assert stage.queued_count == 3
    assert stage.progress_indeterminate is False


def test_worker_runs_explicit_offline_dns_validation_stage(
    database_session: Session,
) -> None:
    ids = _approved_context(database_session)
    database_session.add(
        DiscoverySource(
            id=uuid4(),
            organization_id=ids["organization_id"],
            source_key="fixture-dns-validation",
            source_type="RECORDED_PASSIVE_DNS",
            display_name="Recorded DNS validation",
            adapter_version="1.0.0",
            configuration_reference="fixture:dns-validation-v1",
        )
    )
    database_session.commit()
    job = _create_job(database_session, ids, DiscoveryJobService())
    worker = DiscoveryJobWorker(
        session_factory=sessionmaker(bind=database_session.get_bind(), expire_on_commit=False),
        lease_seconds=5,
    )

    assert (
        worker.run(
            organization_id=ids["organization_id"],
            job_id=job.id,
            correlation_id="dns-stage-integration",
            worker_token="dns-stage-worker",
        )
        == "completed"
    )
    database_session.expire_all()
    dns_stage = database_session.scalar(
        select(DiscoveryJobStage).where(
            DiscoveryJobStage.discovery_job_id == job.id,
            DiscoveryJobStage.stage == DiscoveryStageName.DNS_VALIDATE.value,
        )
    )
    checkpoint = database_session.scalar(
        select(DiscoveryCheckpoint).where(
            DiscoveryCheckpoint.discovery_job_id == job.id,
            DiscoveryCheckpoint.stage == DiscoveryStageName.DNS_VALIDATE.value,
        )
    )
    assert dns_stage is not None
    assert checkpoint is not None
    assert dns_stage.state == "COMPLETED"
    assert dns_stage.processed_count == 2
    assert dns_stage.succeeded_count == 2
    assert checkpoint.token_json == {"completed": True, "processed": 2}
    progress = DiscoveryJobService().progress(
        database_session,
        organization_id=ids["organization_id"],
        job_id=job.id,
    )
    assert progress.known_total == 2
    assert progress.queued == 0
    assert progress.indeterminate is False


def test_worker_runs_configured_tcp_stage_with_dns_provenance_checkpoint(
    database_session: Session,
) -> None:
    ids = _approved_context(database_session)
    policy = database_session.scalar(
        select(ScanPolicy).where(
            ScanPolicy.organization_id == ids["organization_id"],
            ScanPolicy.scope_version_id == ids["version_id"],
        )
    )
    version = database_session.get(ScopeVersion, ids["version_id"])
    approval = database_session.get(ScopeApproval, ids["approval_id"])
    assert policy is not None
    assert version is not None
    assert approval is not None
    policy.allowed_protocols = ["DNS", "HTTPS"]
    content_hash = ScopeApprovalService.content_hash(database_session, version)
    version.content_hash = content_hash
    approval.content_hash = content_hash
    database_session.add_all(
        [
            DiscoverySource(
                id=uuid4(),
                organization_id=ids["organization_id"],
                source_key="fixture-dns-validation",
                source_type="RECORDED_PASSIVE_DNS",
                display_name="Recorded DNS validation",
                adapter_version="1.0.0",
                configuration_reference="fixture:dns-validation-v1",
            ),
            DiscoverySource(
                id=uuid4(),
                organization_id=ids["organization_id"],
                source_key="fixture-tcp-validation",
                source_type="RECORDED_PASSIVE_DNS",
                display_name="Recorded TCP validation",
                adapter_version="1.0.0",
                configuration_reference="fixture:tcp-validation-v1",
            ),
        ]
    )
    database_session.commit()
    job = _create_job(database_session, ids, DiscoveryJobService())
    worker = DiscoveryJobWorker(
        session_factory=sessionmaker(bind=database_session.get_bind(), expire_on_commit=False),
        lease_seconds=5,
    )

    assert (
        worker.run(
            organization_id=ids["organization_id"],
            job_id=job.id,
            correlation_id="tcp-stage-integration",
            worker_token="tcp-stage-worker",
        )
        == "completed"
    )
    database_session.expire_all()
    tcp_stage = database_session.scalar(
        select(DiscoveryJobStage).where(
            DiscoveryJobStage.discovery_job_id == job.id,
            DiscoveryJobStage.stage == DiscoveryStageName.TCP_VALIDATE.value,
        )
    )
    checkpoint = database_session.scalar(
        select(DiscoveryCheckpoint).where(
            DiscoveryCheckpoint.discovery_job_id == job.id,
            DiscoveryCheckpoint.stage == DiscoveryStageName.TCP_VALIDATE.value,
        )
    )
    assert tcp_stage is not None
    assert checkpoint is not None
    assert tcp_stage.state == "COMPLETED"
    assert tcp_stage.processed_count == 2
    assert tcp_stage.succeeded_count == 0
    assert tcp_stage.skipped_count == 2
    assert checkpoint.token_json == {"completed": True, "processed": 2}


def test_worker_runs_configured_tls_stage_with_dns_provenance_checkpoint(
    database_session: Session,
) -> None:
    ids = _approved_context(database_session)
    policy = database_session.scalar(
        select(ScanPolicy).where(
            ScanPolicy.organization_id == ids["organization_id"],
            ScanPolicy.scope_version_id == ids["version_id"],
        )
    )
    version = database_session.get(ScopeVersion, ids["version_id"])
    approval = database_session.get(ScopeApproval, ids["approval_id"])
    assert policy is not None
    assert version is not None
    assert approval is not None
    policy.allowed_protocols = ["DNS", "TLS"]
    content_hash = ScopeApprovalService.content_hash(database_session, version)
    version.content_hash = content_hash
    approval.content_hash = content_hash
    database_session.add_all(
        [
            DiscoverySource(
                id=uuid4(),
                organization_id=ids["organization_id"],
                source_key="fixture-dns-validation",
                source_type="RECORDED_PASSIVE_DNS",
                display_name="Recorded DNS validation",
                adapter_version="1.0.0",
                configuration_reference="fixture:dns-validation-v1",
            ),
            DiscoverySource(
                id=uuid4(),
                organization_id=ids["organization_id"],
                source_key="fixture-tls-metadata",
                source_type="RECORDED_PASSIVE_DNS",
                display_name="Recorded TLS metadata",
                adapter_version="1.0.0",
                configuration_reference="fixture:tls-metadata-v1",
            ),
        ]
    )
    database_session.commit()
    job = _create_job(database_session, ids, DiscoveryJobService())
    worker = DiscoveryJobWorker(
        session_factory=sessionmaker(bind=database_session.get_bind(), expire_on_commit=False),
        lease_seconds=5,
    )

    assert (
        worker.run(
            organization_id=ids["organization_id"],
            job_id=job.id,
            correlation_id="tls-stage-integration",
            worker_token="tls-stage-worker",
        )
        == "completed"
    )
    database_session.expire_all()
    stage = database_session.scalar(
        select(DiscoveryJobStage).where(
            DiscoveryJobStage.discovery_job_id == job.id,
            DiscoveryJobStage.stage == DiscoveryStageName.TLS_METADATA.value,
        )
    )
    checkpoint = database_session.scalar(
        select(DiscoveryCheckpoint).where(
            DiscoveryCheckpoint.discovery_job_id == job.id,
            DiscoveryCheckpoint.stage == DiscoveryStageName.TLS_METADATA.value,
        )
    )
    assert stage is not None
    assert checkpoint is not None
    assert stage.state == "COMPLETED"
    assert stage.processed_count == 2
    assert stage.succeeded_count == 0
    assert stage.skipped_count == 2
    assert checkpoint.token_json == {"completed": True, "processed": 2}


def test_worker_runs_guarded_http_endpoint_hint_stage(database_session: Session) -> None:
    ids = _approved_context(database_session)
    policy = database_session.scalar(
        select(ScanPolicy).where(
            ScanPolicy.organization_id == ids["organization_id"],
            ScanPolicy.scope_version_id == ids["version_id"],
        )
    )
    version = database_session.get(ScopeVersion, ids["version_id"])
    approval = database_session.get(ScopeApproval, ids["approval_id"])
    assert policy is not None
    assert version is not None
    assert approval is not None
    policy.allowed_protocols = ["DNS", "HTTPS"]
    content_hash = ScopeApprovalService.content_hash(database_session, version)
    version.content_hash = content_hash
    approval.content_hash = content_hash
    database_session.add(
        DiscoverySource(
            id=uuid4(),
            organization_id=ids["organization_id"],
            source_key="fixture-http-metadata",
            source_type="RECORDED_PASSIVE_DNS",
            display_name="Recorded HTTP metadata",
            adapter_version="1.0.0",
            configuration_reference="fixture:http-metadata-v1",
        )
    )
    database_session.commit()
    job = _create_job(database_session, ids, DiscoveryJobService())
    endpoint = CandidateAsset(
        id=uuid4(),
        organization_id=ids["organization_id"],
        scope_id=ids["scope_id"],
        scope_version_id=ids["version_id"],
        scope_approval_id=ids["approval_id"],
        candidate_type="ENDPOINT_HINT",
        raw_value="https://www.example.com/",
        canonical_value="https://www.example.com/",
        first_discovered_at=datetime(2026, 8, 19, tzinfo=UTC),
        last_discovered_at=datetime(2026, 8, 19, tzinfo=UTC),
        confidence_score=0.0,
        confidence_model_version="candidate-confidence-v1",
        confidence_factors_json=[],
        state="DISCOVERED",
        metadata_json={},
    )
    database_session.add(endpoint)
    database_session.commit()
    worker = DiscoveryJobWorker(
        session_factory=sessionmaker(bind=database_session.get_bind(), expire_on_commit=False),
        lease_seconds=5,
    )

    assert (
        worker.run(
            organization_id=ids["organization_id"],
            job_id=job.id,
            correlation_id="http-stage-integration",
            worker_token="http-stage-worker",
        )
        == "completed"
    )
    database_session.expire_all()
    stage = database_session.scalar(
        select(DiscoveryJobStage).where(
            DiscoveryJobStage.discovery_job_id == job.id,
            DiscoveryJobStage.stage == DiscoveryStageName.HTTP_METADATA.value,
        )
    )
    attempt = database_session.scalar(
        select(CollectionAttempt).where(
            CollectionAttempt.discovery_job_id == job.id,
            CollectionAttempt.stage == DiscoveryStageName.HTTP_METADATA.value,
        )
    )
    assert stage is not None
    assert attempt is not None
    assert stage.state == "COMPLETED"
    assert stage.processed_count == 1
    assert stage.succeeded_count == 1
    assert attempt.result == "SUCCESS"
    assert attempt.scope_decision == "ALLOWED"
    assert attempt.metadata_json["headers"] == {
        "content-type": "text/html",
        "server": "fixture-http",
    }


def test_cancellation_retry_and_dead_letter_controls_are_durable(
    database_session: Session,
) -> None:
    ids = _approved_context(database_session)
    job = _create_job(database_session, ids, DiscoveryJobService())

    cancelling = DiscoveryRecoveryService.request_cancellation(
        database_session,
        organization_id=ids["organization_id"],
        job_id=job.id,
        correlation_id="recovery-test",
        now=datetime(2026, 8, 19, tzinfo=UTC),
    )
    database_session.commit()
    repeated = DiscoveryRecoveryService.request_cancellation(
        database_session,
        organization_id=ids["organization_id"],
        job_id=job.id,
        correlation_id="recovery-test",
        now=datetime(2026, 8, 19, tzinfo=UTC),
    )
    item = DiscoveryRecoveryService.record_dead_letter(
        database_session,
        organization_id=ids["organization_id"],
        job_id=job.id,
        candidate_id=None,
        stage="HTTP_METADATA",
        operation_key="http:www.example.com",
        attempts=3,
        error_class="TRANSIENT",
        safe_message="fixture timeout",
        now=datetime(2026, 8, 19, tzinfo=UTC),
    )
    updated = DiscoveryRecoveryService.record_dead_letter(
        database_session,
        organization_id=ids["organization_id"],
        job_id=job.id,
        candidate_id=None,
        stage="HTTP_METADATA",
        operation_key="http:www.example.com",
        attempts=4,
        error_class="TRANSIENT",
        safe_message="fixture timeout replay",
        now=datetime(2026, 8, 19, 1, tzinfo=UTC),
    )

    assert cancelling.state == "CANCELLING"
    assert repeated.cancel_generation == 1
    assert DiscoveryRecoveryService.cancellation_requested(repeated) is True
    assert DiscoveryRecoveryService.retry_delay(1, max_attempts=3) == timedelta(seconds=1)
    assert DiscoveryRecoveryService.retry_delay(2, max_attempts=3) == timedelta(seconds=2)
    assert DiscoveryRecoveryService.retry_delay(3, max_attempts=3) is None
    assert item.id == updated.id
    assert updated.attempts == 4
    assert database_session.scalar(select(func.count()).select_from(DeadLetterItem)) == 1


def test_open_dead_letter_finalizes_job_as_degraded(database_session: Session) -> None:
    ids = _approved_context(database_session)
    service = DiscoveryJobService()
    job = _create_job(database_session, ids, service)
    for stage in database_session.scalars(
        select(DiscoveryJobStage).where(DiscoveryJobStage.discovery_job_id == job.id)
    ):
        stage.state = "COMPLETED"
    DiscoveryRecoveryService.record_dead_letter(
        database_session,
        organization_id=ids["organization_id"],
        job_id=job.id,
        candidate_id=None,
        stage="HTTP_METADATA",
        operation_key="http:fixture-timeout",
        attempts=3,
        error_class="TRANSIENT_TIMEOUT",
        safe_message="fixture timeout after bounded retries",
        now=datetime(2026, 8, 19, tzinfo=UTC),
    )
    database_session.commit()

    assert (
        service.finalize(
            database_session,
            organization_id=ids["organization_id"],
            job_id=job.id,
        )
        == "DEGRADED"
    )


def test_dead_letter_requeue_reopens_only_affected_stage_idempotently(
    database_session: Session,
) -> None:
    ids = _approved_context(database_session)
    service = DiscoveryJobService()
    job = _create_job(database_session, ids, service)
    for stage in database_session.scalars(
        select(DiscoveryJobStage).where(DiscoveryJobStage.discovery_job_id == job.id)
    ):
        stage.state = "COMPLETED"
    item = DiscoveryRecoveryService.record_dead_letter(
        database_session,
        organization_id=ids["organization_id"],
        job_id=job.id,
        candidate_id=None,
        stage="HTTP_METADATA",
        operation_key="http:requeue-fixture",
        attempts=3,
        error_class="TRANSIENT_TIMEOUT",
        safe_message="fixture timeout after bounded retries",
        now=datetime(2026, 8, 19, tzinfo=UTC),
    )
    database_session.commit()
    assert (
        service.finalize(
            database_session,
            organization_id=ids["organization_id"],
            job_id=job.id,
        )
        == "DEGRADED"
    )

    requeued = DiscoveryRecoveryService.requeue_dead_letter(
        database_session,
        organization_id=ids["organization_id"],
        job_id=job.id,
        item_id=item.id,
        correlation_id="dead-letter-requeue",
    )
    repeated = DiscoveryRecoveryService.requeue_dead_letter(
        database_session,
        organization_id=ids["organization_id"],
        job_id=job.id,
        item_id=item.id,
        correlation_id="dead-letter-requeue",
    )

    stage = database_session.scalar(
        select(DiscoveryJobStage).where(
            DiscoveryJobStage.discovery_job_id == job.id,
            DiscoveryJobStage.stage == "HTTP_METADATA",
        )
    )
    assert requeued.id == repeated.id
    assert repeated.state == "REQUEUED"
    assert stage is not None
    assert stage.state == "QUEUED"
    assert job.state == "QUEUED"
    assert (
        database_session.scalar(
            select(func.count())
            .select_from(DiscoveryJobEvent)
            .where(DiscoveryJobEvent.event_type == "DEAD_LETTER_REQUEUED")
        )
        == 1
    )


def test_http_timeout_retries_are_bounded_and_dead_letter_is_degraded(
    database_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ids = _approved_context(database_session)
    policy = database_session.scalar(
        select(ScanPolicy).where(
            ScanPolicy.organization_id == ids["organization_id"],
            ScanPolicy.scope_version_id == ids["version_id"],
        )
    )
    version = database_session.get(ScopeVersion, ids["version_id"])
    approval = database_session.get(ScopeApproval, ids["approval_id"])
    assert policy is not None
    assert version is not None
    assert approval is not None
    policy.allowed_protocols = ["DNS", "HTTPS"]
    content_hash = ScopeApprovalService.content_hash(database_session, version)
    version.content_hash = content_hash
    approval.content_hash = content_hash
    database_session.add(
        DiscoverySource(
            id=uuid4(),
            organization_id=ids["organization_id"],
            source_key="fixture-http-timeout",
            source_type="RECORDED_PASSIVE_DNS",
            display_name="Recorded HTTP timeout",
            adapter_version="1.0.0",
            configuration_reference="fixture:http-timeout-v1",
        )
    )
    database_session.commit()
    job = _create_job(database_session, ids, DiscoveryJobService())
    endpoint = CandidateAsset(
        id=uuid4(),
        organization_id=ids["organization_id"],
        scope_id=ids["scope_id"],
        scope_version_id=ids["version_id"],
        scope_approval_id=ids["approval_id"],
        candidate_type="ENDPOINT_HINT",
        raw_value="https://www.example.com/",
        canonical_value="https://www.example.com/",
        first_discovered_at=datetime(2026, 8, 19, tzinfo=UTC),
        last_discovered_at=datetime(2026, 8, 19, tzinfo=UTC),
        confidence_score=0.0,
        confidence_model_version="candidate-confidence-v1",
        confidence_factors_json=[],
        state="DISCOVERED",
        metadata_json={},
    )
    database_session.add(endpoint)
    database_session.commit()
    timeout_transport = FixtureHttpTransport(
        {
            ("HEAD", "https://www.example.com/"): HttpFixtureResponse(
                status_code=200,
                headers={},
                timeout=True,
            )
        }
    )
    monkeypatch.setattr(
        "exposure360_api.discovery_orchestration.http_fixture_transport_for_reference",
        lambda reference: timeout_transport if reference == "fixture:http-timeout-v1" else None,
    )
    worker = DiscoveryJobWorker(
        session_factory=sessionmaker(bind=database_session.get_bind(), expire_on_commit=False),
        lease_seconds=5,
        max_attempts=3,
    )

    assert (
        worker.run(
            organization_id=ids["organization_id"],
            job_id=job.id,
            correlation_id="http-timeout-recovery",
            worker_token="http-timeout-worker",
        )
        == "degraded"
    )
    database_session.expire_all()
    attempts = list(
        database_session.scalars(
            select(CollectionAttempt)
            .where(
                CollectionAttempt.discovery_job_id == job.id,
                CollectionAttempt.stage == DiscoveryStageName.HTTP_METADATA.value,
            )
            .order_by(CollectionAttempt.attempt_number)
        )
    )
    retry_events = list(
        database_session.scalars(
            select(DiscoveryJobEvent).where(
                DiscoveryJobEvent.discovery_job_id == job.id,
                DiscoveryJobEvent.event_type == "retry.scheduled",
            )
        )
    )
    dead_letter = database_session.scalar(
        select(DeadLetterItem).where(DeadLetterItem.discovery_job_id == job.id)
    )
    assert len(timeout_transport.calls) == 3
    assert [attempt.attempt_number for attempt in attempts] == [1, 2, 3]
    assert [event.details_json["delay_seconds"] for event in retry_events] == [1.0, 2.0]
    assert dead_letter is not None
    assert dead_letter.attempts == 3


def test_worker_restart_resumes_ten_unique_candidates_after_durable_checkpoint(
    database_session: Session,
) -> None:
    ids = _approved_context(database_session)
    clock = MutableClock(datetime(2026, 8, 19, tzinfo=UTC))
    jobs = DiscoveryJobService(clock=clock)
    job = _create_job(database_session, ids, jobs)
    records = [
        {
            "id": f"restart-{index}",
            "rrname": f"service-{index}.example.com",
            "rrtype": "A",
            "rdata": f"192.0.2.{index}",
            "first_seen": "2026-08-01T00:00:00Z",
            "last_seen": "2026-08-19T00:00:00Z",
        }
        for index in range(1, 6)
    ]

    def adapter_factory(source: DiscoverySource) -> RecordedPassiveDnsAdapter:
        assert source.source_key == "fixture-passive-dns"
        return RecordedPassiveDnsAdapter(records, page_size=2, clock=clock)

    interrupted_worker = DiscoveryJobWorker(
        session_factory=sessionmaker(bind=database_session.get_bind(), expire_on_commit=False),
        adapter_factory=adapter_factory,
        jobs=jobs,
        reconciler=CandidateReconciliationService(clock=clock),
        lease_seconds=5,
        interrupt_after_source_batches=1,
    )
    with pytest.raises(WorkerInterrupted):
        interrupted_worker.run(
            organization_id=ids["organization_id"],
            job_id=job.id,
            correlation_id="ten-candidate-interrupt",
            worker_token="interrupted-worker",
        )
    checkpoint = database_session.scalar(
        select(DiscoveryCheckpoint).where(
            DiscoveryCheckpoint.discovery_job_id == job.id,
            DiscoveryCheckpoint.stage == DiscoveryStageName.PASSIVE_SOURCE.value,
        )
    )
    assert checkpoint is not None
    assert checkpoint.token_json == {"record_index": 2}
    assert database_session.scalar(select(func.count()).select_from(CandidateAsset)) == 4

    clock.now += timedelta(seconds=6)
    restarted_worker = DiscoveryJobWorker(
        session_factory=sessionmaker(bind=database_session.get_bind(), expire_on_commit=False),
        adapter_factory=adapter_factory,
        jobs=jobs,
        reconciler=CandidateReconciliationService(clock=clock),
        lease_seconds=5,
    )

    assert (
        restarted_worker.run(
            organization_id=ids["organization_id"],
            job_id=job.id,
            correlation_id="ten-candidate-restart",
            worker_token="restarted-worker",
        )
        == "completed"
    )
    assert database_session.scalar(select(func.count()).select_from(CandidateAsset)) == 10
    assert (
        database_session.scalar(select(func.count(func.distinct(CandidateAsset.canonical_value))))
        == 10
    )


def test_tls_transient_failures_use_bounded_worker_retry_and_dead_letter(
    database_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ids = _approved_context(database_session)
    policy = database_session.scalar(
        select(ScanPolicy).where(
            ScanPolicy.organization_id == ids["organization_id"],
            ScanPolicy.scope_version_id == ids["version_id"],
        )
    )
    version = database_session.get(ScopeVersion, ids["version_id"])
    approval = database_session.get(ScopeApproval, ids["approval_id"])
    source = database_session.get(DiscoverySource, ids["source_id"])
    assert policy is not None
    assert version is not None
    assert approval is not None
    assert source is not None
    policy.allowed_protocols = ["DNS", "TLS"]
    database_session.add_all(
        [
            ScopeSeed(
                id=uuid4(),
                organization_id=ids["organization_id"],
                scope_version_id=ids["version_id"],
                seed_type="CIDR",
                raw_value="8.8.8.8/32",
                canonical_value="8.8.8.8/32",
                match_mode="EXACT",
            ),
            DiscoverySource(
                id=uuid4(),
                organization_id=ids["organization_id"],
                source_key="fixture-tls-timeout",
                source_type="RECORDED_PASSIVE_DNS",
                display_name="Recorded TLS timeout",
                adapter_version="1.0.0",
                configuration_reference="fixture:tls-timeout-v1",
            ),
        ]
    )
    content_hash = ScopeApprovalService.content_hash(database_session, version)
    version.content_hash = content_hash
    approval.content_hash = content_hash
    database_session.commit()
    job = _create_job(database_session, ids, DiscoveryJobService())
    candidate = CandidateAsset(
        id=uuid4(),
        organization_id=ids["organization_id"],
        scope_id=ids["scope_id"],
        scope_version_id=ids["version_id"],
        scope_approval_id=ids["approval_id"],
        candidate_type="IP",
        raw_value="8.8.8.8",
        canonical_value="8.8.8.8",
        first_discovered_at=datetime(2026, 8, 19, tzinfo=UTC),
        last_discovered_at=datetime(2026, 8, 19, tzinfo=UTC),
        confidence_score=0.0,
        confidence_model_version="candidate-confidence-v1",
        confidence_factors_json=[],
        state="DISCOVERED",
        metadata_json={},
    )
    database_session.add(candidate)
    database_session.flush()
    database_session.add_all(
        [
            CandidateObservation(
                id=uuid4(),
                organization_id=ids["organization_id"],
                candidate_id=candidate.id,
                source_id=source.id,
                source_record_key="tls-timeout-hostname",
                observed_at=datetime(2026, 8, 19, tzinfo=UTC),
                collected_at=datetime(2026, 8, 19, tzinfo=UTC),
                payload_hash="a" * 64,
                normalized_metadata_json={"hostname": "www.example.com"},
            ),
            CollectionAttempt(
                id=uuid4(),
                organization_id=ids["organization_id"],
                discovery_job_id=job.id,
                candidate_id=candidate.id,
                stage=DiscoveryStageName.TCP_VALIDATE.value,
                protocol="HTTPS",
                target_host="www.example.com",
                target_port=443,
                scope_decision="ALLOWED",
                result="SUCCESS",
                started_at=datetime(2026, 8, 19, tzinfo=UTC),
                finished_at=datetime(2026, 8, 19, tzinfo=UTC),
                duration_ms=0,
                metadata_json={},
                correlation_id="tls-timeout-recovery",
            ),
        ]
    )
    database_session.commit()
    timeout_connector = FixtureTlsConnector(
        {
            ("8.8.8.8", 443): TlsHandshakeResult(
                result="TRANSIENT_ERROR",
                metadata={},
                reason_code="FIXTURE_TLS_TIMEOUT",
            )
        }
    )
    monkeypatch.setattr(
        "exposure360_api.discovery_orchestration.tls_fixture_connector_for_reference",
        lambda reference: timeout_connector if reference == "fixture:tls-timeout-v1" else None,
    )
    worker = DiscoveryJobWorker(
        session_factory=sessionmaker(bind=database_session.get_bind(), expire_on_commit=False),
        lease_seconds=5,
        max_attempts=3,
    )

    assert (
        worker.run(
            organization_id=ids["organization_id"],
            job_id=job.id,
            correlation_id="tls-timeout-recovery",
            worker_token="tls-timeout-worker",
        )
        == "degraded"
    )
    tls_attempts = list(
        database_session.scalars(
            select(CollectionAttempt)
            .where(
                CollectionAttempt.discovery_job_id == job.id,
                CollectionAttempt.stage == DiscoveryStageName.TLS_METADATA.value,
            )
            .order_by(CollectionAttempt.attempt_number)
        )
    )
    assert len(timeout_connector.calls) == 3
    assert [attempt.attempt_number for attempt in tls_attempts] == [1, 2, 3]
    assert (
        database_session.scalar(
            select(func.count())
            .select_from(DeadLetterItem)
            .where(DeadLetterItem.stage == DiscoveryStageName.TLS_METADATA.value)
        )
        == 1
    )


def test_worker_converges_durable_cancellation_before_any_collector_call(
    database_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ids = _approved_context(database_session)
    database_session.add(
        DiscoverySource(
            id=uuid4(),
            organization_id=ids["organization_id"],
            source_key="fixture-tls-metadata",
            source_type="RECORDED_PASSIVE_DNS",
            display_name="Recorded TLS metadata",
            adapter_version="1.0.0",
            configuration_reference="fixture:tls-metadata-v1",
        )
    )
    database_session.commit()
    job = _create_job(database_session, ids, DiscoveryJobService())
    calls: list[str] = []

    def unexpected_tls_fixture(reference: str | None) -> object:
        calls.append(str(reference))
        raise AssertionError("Cancellation must prevent collector construction")

    monkeypatch.setattr(
        "exposure360_api.discovery_orchestration.tls_fixture_connector_for_reference",
        unexpected_tls_fixture,
    )
    DiscoveryRecoveryService.request_cancellation(
        database_session,
        organization_id=ids["organization_id"],
        job_id=job.id,
        correlation_id="cancel-before-collector",
        now=datetime(2026, 8, 19, tzinfo=UTC),
    )
    database_session.commit()
    worker = DiscoveryJobWorker(
        session_factory=sessionmaker(bind=database_session.get_bind(), expire_on_commit=False),
        lease_seconds=5,
    )

    assert (
        worker.run(
            organization_id=ids["organization_id"],
            job_id=job.id,
            correlation_id="cancel-before-collector",
            worker_token="cancel-worker",
        )
        == "cancelled"
    )
    database_session.expire_all()
    refreshed = database_session.get(DiscoveryJob, job.id)
    assert refreshed is not None
    assert refreshed.state == "CANCELLED"
    assert calls == []
    assert {
        stage.state
        for stage in database_session.scalars(
            select(DiscoveryJobStage).where(DiscoveryJobStage.discovery_job_id == job.id)
        )
    } == {"CANCELLED"}
