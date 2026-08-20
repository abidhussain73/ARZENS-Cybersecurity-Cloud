"""Durable Phase 3 discovery-job orchestration and resumable source-stage runner."""

import hashlib
import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from .candidate_reconciliation import CandidateReconciliationService
from .certificate_source import RecordedCertificateMetadataAdapter
from .discovery_contracts import CandidateType, DiscoveryCheckpointContract, DiscoveryStageName
from .discovery_sources import (
    DiscoverySourceAdapter,
    RecordedPassiveDnsAdapter,
    ScopeSourceContext,
)
from .dns_validation import DnsValidationWorker, fixture_resolver_for_reference
from .emergency_stop import EmergencyStopService
from .http_metadata import (
    HttpMetadataCollector,
)
from .http_metadata import (
    fixture_transport_for_reference as http_fixture_transport_for_reference,
)
from .models import (
    CandidateAsset,
    CandidateObservation,
    CollectionAttempt,
    DeadLetterItem,
    DiscoveryCheckpoint,
    DiscoveryJob,
    DiscoveryJobEvent,
    DiscoveryJobStage,
    DiscoverySource,
    ScanPolicy,
    ScopeExclusion,
    ScopeSeed,
    User,
)
from .recorded_fixture_catalog import recorded_fixture
from .recovery_controls import DiscoveryRecoveryService
from .scope_approval import ScopeApprovalService, ScopeStateError
from .scope_governance import MatchMode, TargetRule, TargetType
from .security import Principal
from .tcp_validation import (
    ResolvedAddress,
    TcpValidationWorker,
    fixture_connector_for_reference,
)
from .tls_metadata import (
    TlsMetadataCollector,
)
from .tls_metadata import (
    fixture_connector_for_reference as tls_fixture_connector_for_reference,
)

STAGE_ORDER = (
    DiscoveryStageName.PASSIVE_SOURCE,
    DiscoveryStageName.CERTIFICATE_IMPORT,
    DiscoveryStageName.CANDIDATE_RECONCILIATION,
    DiscoveryStageName.DNS_VALIDATE,
    DiscoveryStageName.TCP_VALIDATE,
    DiscoveryStageName.TLS_METADATA,
    DiscoveryStageName.HTTP_METADATA,
    DiscoveryStageName.FINALIZE,
)
_TERMINAL_JOB_STATES = {"PARTIAL", "DEGRADED", "COMPLETED", "CANCELLED", "FAILED"}
_TERMINAL_STAGE_STATES = {"COMPLETED", "PARTIAL", "SKIPPED", "FAILED", "CANCELLED"}


class DiscoveryJobStateError(ValueError):
    """Raised when a job cannot transition without weakening governance or durability."""


class WorkerInterrupted(RuntimeError):
    """Deterministic test signal raised only after a durable checkpoint commit."""


@dataclass(frozen=True)
class StageLease:
    job_id: uuid.UUID
    stage: DiscoveryStageName
    token: str
    generation: int


@dataclass(frozen=True)
class DiscoveryProgressSnapshot:
    stage: str | None
    processed: int
    succeeded: int
    failed: int
    skipped: int
    queued: int
    known_total: int | None
    indeterminate: bool


def policy_hash(policy: ScanPolicy) -> str:
    payload = {
        "allowed_protocols": sorted(policy.allowed_protocols),
        "max_requests_per_second": policy.max_requests_per_second,
        "max_concurrent_targets": policy.max_concurrent_targets,
        "max_concurrent_requests": policy.max_concurrent_requests,
        "schedule_timezone": policy.schedule_timezone,
        "schedule_windows": policy.schedule_windows,
        "connect_timeout_seconds": policy.connect_timeout_seconds,
        "request_timeout_seconds": policy.request_timeout_seconds,
        "active_scanning_enabled": policy.active_scanning_enabled,
    }
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class DiscoveryJobService:
    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))

    def create_job(
        self,
        session: Session,
        *,
        organization_id: uuid.UUID,
        scope_id: uuid.UUID,
        scope_version_id: uuid.UUID,
        approval_id: uuid.UUID,
        requested_by_user_id: uuid.UUID,
        correlation_id: str,
    ) -> DiscoveryJob:
        now = self._clock()
        try:
            envelope = ScopeApprovalService.active_envelope(
                session,
                organization_id=organization_id,
                scope_id=scope_id,
                version_id=scope_version_id,
                approval_id=approval_id,
                now=now,
            )
        except ScopeStateError as error:
            raise DiscoveryJobStateError(str(error)) from error
        stop_status = EmergencyStopService.status(
            session,
            organization_id=organization_id,
            scope_id=scope_id,
        )
        if stop_status.active:
            raise DiscoveryJobStateError("Emergency stop is active")
        policy = session.scalar(
            select(ScanPolicy).where(
                ScanPolicy.scope_version_id == scope_version_id,
                ScanPolicy.organization_id == organization_id,
            )
        )
        if policy is None:
            raise DiscoveryJobStateError("Approved scope version has no policy")
        job = DiscoveryJob(
            organization_id=organization_id,
            scope_id=scope_id,
            scope_version_id=scope_version_id,
            scope_approval_id=approval_id,
            scope_content_hash=envelope.policy_hash,
            scan_policy_hash=policy_hash(policy),
            state="QUEUED",
            requested_by_user_id=requested_by_user_id,
        )
        session.add(job)
        session.flush()
        for stage in STAGE_ORDER:
            session.add(
                DiscoveryJobStage(
                    organization_id=organization_id,
                    discovery_job_id=job.id,
                    stage=stage.value,
                    state="QUEUED",
                )
            )
        self._event(
            session,
            job=job,
            event_key="job.created",
            event_type="job.created",
            stage=None,
            correlation_id=correlation_id,
            details={"scope_version_id": str(scope_version_id), "approval_id": str(approval_id)},
        )
        session.flush()
        return job

    def claim_stage(
        self,
        session: Session,
        *,
        organization_id: uuid.UUID,
        job_id: uuid.UUID,
        stage: DiscoveryStageName,
        worker_token: str,
        lease_seconds: int,
        correlation_id: str,
    ) -> StageLease | None:
        now = self._clock()
        job = self._job_for_update(session, organization_id, job_id)
        if job.state in _TERMINAL_JOB_STATES:
            return None
        if job.cancel_requested_at is not None:
            job.state = "CANCELLING"
            return None
        stop = EmergencyStopService.status(
            session,
            organization_id=organization_id,
            scope_id=job.scope_id,
        )
        if stop.active:
            job.state = "CANCELLING"
            job.cancel_reason = f"emergency_stop:{stop.level}"
            job.cancel_requested_at = now
            job.cancel_generation = max(job.cancel_generation, stop.generation)
            return None
        stage_row = session.scalar(
            select(DiscoveryJobStage)
            .where(
                DiscoveryJobStage.organization_id == organization_id,
                DiscoveryJobStage.discovery_job_id == job_id,
                DiscoveryJobStage.stage == stage.value,
            )
            .with_for_update()
        )
        if stage_row is None:
            raise DiscoveryJobStateError("Job stage does not exist")
        if stage_row.state in _TERMINAL_STAGE_STATES:
            return None
        if stage_row.state == "RUNNING" and stage_row.lease_expires_at is not None:
            if self._as_utc(stage_row.lease_expires_at) > now:
                return None
        stage_row.state = "RUNNING"
        stage_row.execution_generation += 1
        stage_row.execution_token = worker_token
        stage_row.lease_expires_at = now + timedelta(seconds=lease_seconds)
        stage_row.started_at = stage_row.started_at or now
        job.state = "RUNNING"
        job.current_stage = stage.value
        job.started_at = job.started_at or now
        self._event(
            session,
            job=job,
            event_key=f"{stage.value.lower()}.started.{stage_row.execution_generation}",
            event_type="stage.started",
            stage=stage,
            correlation_id=correlation_id,
            details={"generation": stage_row.execution_generation},
        )
        session.flush()
        return StageLease(job.id, stage, worker_token, stage_row.execution_generation)

    def save_checkpoint(
        self,
        session: Session,
        *,
        lease: StageLease,
        checkpoint: DiscoveryCheckpointContract,
        processed_count: int,
        succeeded_count: int,
        failed_count: int,
        skipped_count: int,
        known_total: int | None,
    ) -> None:
        job = self._job_for_update(session, None, lease.job_id)
        stage = self._leased_stage_for_update(session, lease)
        existing = session.scalar(
            select(DiscoveryCheckpoint)
            .where(
                DiscoveryCheckpoint.discovery_job_id == lease.job_id,
                DiscoveryCheckpoint.stage == lease.stage.value,
            )
            .with_for_update()
        )
        if existing is None:
            existing = DiscoveryCheckpoint(
                organization_id=job.organization_id,
                discovery_job_id=job.id,
                stage=lease.stage.value,
                checkpoint_schema_version=checkpoint.checkpoint_schema_version,
                source_key=checkpoint.source_key,
                adapter_version=checkpoint.adapter_version,
                token_json=checkpoint.token,
            )
            session.add(existing)
        else:
            existing.checkpoint_schema_version = checkpoint.checkpoint_schema_version
            existing.source_key = checkpoint.source_key
            existing.adapter_version = checkpoint.adapter_version
            existing.token_json = checkpoint.token
        stage.processed_count = processed_count
        stage.succeeded_count = succeeded_count
        stage.failed_count = failed_count
        stage.skipped_count = skipped_count
        stage.known_total = known_total
        stage.queued_count = max(0, known_total - processed_count) if known_total is not None else 0
        stage.progress_indeterminate = known_total is None
        job.progress_completed = processed_count
        job.progress_failed = failed_count
        job.progress_skipped = skipped_count
        job.progress_total = known_total
        job.progress_queued = stage.queued_count
        job.progress_indeterminate = known_total is None
        job.last_checkpoint_at = self._clock()
        session.flush()

    def complete_stage(
        self,
        session: Session,
        *,
        lease: StageLease,
        state: str,
        correlation_id: str,
    ) -> None:
        if state not in _TERMINAL_STAGE_STATES:
            raise DiscoveryJobStateError("Stage completion requires a terminal stage state")
        job = self._job_for_update(session, None, lease.job_id)
        stage = self._leased_stage_for_update(session, lease)
        stage.state = state
        stage.finished_at = self._clock()
        stage.lease_expires_at = None
        self._event(
            session,
            job=job,
            event_key=f"{lease.stage.value.lower()}.completed.{lease.generation}",
            event_type="stage.completed",
            stage=lease.stage,
            correlation_id=correlation_id,
            details={"state": state},
        )
        session.flush()

    def finalize(self, session: Session, *, organization_id: uuid.UUID, job_id: uuid.UUID) -> str:
        job = self._job_for_update(session, organization_id, job_id)
        if job.state in _TERMINAL_JOB_STATES:
            return job.state
        stages = list(
            session.scalars(
                select(DiscoveryJobStage).where(
                    DiscoveryJobStage.organization_id == organization_id,
                    DiscoveryJobStage.discovery_job_id == job_id,
                )
            )
        )
        if any(stage.state == "RUNNING" for stage in stages):
            raise DiscoveryJobStateError("Cannot finalize a job with a running stage")
        if any(stage.state not in _TERMINAL_STAGE_STATES for stage in stages):
            raise DiscoveryJobStateError("Cannot finalize a job with queued stages")
        if job.cancel_requested_at is not None or any(
            stage.state == "CANCELLED" for stage in stages
        ):
            job.state = "CANCELLED"
        elif (
            session.scalar(
                select(DeadLetterItem.id).where(
                    DeadLetterItem.organization_id == organization_id,
                    DeadLetterItem.discovery_job_id == job_id,
                    DeadLetterItem.state == "OPEN",
                )
            )
            is not None
        ):
            job.state = "DEGRADED"
        elif any(stage.state == "FAILED" for stage in stages) and job.progress_completed == 0:
            job.state = "FAILED"
        elif any(stage.state in {"FAILED", "PARTIAL"} for stage in stages):
            job.state = "PARTIAL"
        else:
            job.state = "COMPLETED"
        job.finished_at = self._clock()
        session.flush()
        return job.state

    def checkpoint_for_stage(
        self,
        session: Session,
        *,
        job_id: uuid.UUID,
        stage: DiscoveryStageName,
    ) -> DiscoveryCheckpointContract | None:
        record = session.scalar(
            select(DiscoveryCheckpoint).where(
                DiscoveryCheckpoint.discovery_job_id == job_id,
                DiscoveryCheckpoint.stage == stage.value,
            )
        )
        if record is None:
            return None
        return DiscoveryCheckpointContract(
            checkpoint_schema_version=record.checkpoint_schema_version,
            source_key=record.source_key,
            adapter_version=record.adapter_version,
            stage=stage,
            token=record.token_json,
        )

    def progress(
        self,
        session: Session,
        *,
        organization_id: uuid.UUID,
        job_id: uuid.UUID,
    ) -> DiscoveryProgressSnapshot:
        job = session.scalar(
            select(DiscoveryJob).where(
                DiscoveryJob.id == job_id,
                DiscoveryJob.organization_id == organization_id,
            )
        )
        if job is None:
            raise DiscoveryJobStateError("Discovery job not found")
        return DiscoveryProgressSnapshot(
            stage=job.current_stage,
            processed=job.progress_completed,
            succeeded=job.progress_completed - job.progress_failed - job.progress_skipped,
            failed=job.progress_failed,
            skipped=job.progress_skipped,
            queued=job.progress_queued,
            known_total=job.progress_total,
            indeterminate=job.progress_indeterminate,
        )

    def _job_for_update(
        self,
        session: Session,
        organization_id: uuid.UUID | None,
        job_id: uuid.UUID,
    ) -> DiscoveryJob:
        filters = [DiscoveryJob.id == job_id]
        if organization_id is not None:
            filters.append(DiscoveryJob.organization_id == organization_id)
        job = session.scalar(select(DiscoveryJob).where(*filters).with_for_update())
        if job is None:
            raise DiscoveryJobStateError("Discovery job not found")
        return job

    def _leased_stage_for_update(self, session: Session, lease: StageLease) -> DiscoveryJobStage:
        stage = session.scalar(
            select(DiscoveryJobStage)
            .where(
                DiscoveryJobStage.discovery_job_id == lease.job_id,
                DiscoveryJobStage.stage == lease.stage.value,
            )
            .with_for_update()
        )
        if stage is None or stage.execution_token != lease.token:
            raise DiscoveryJobStateError("Stage lease is no longer held by this worker")
        if stage.execution_generation != lease.generation:
            raise DiscoveryJobStateError("Stage lease generation is stale")
        return stage

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @staticmethod
    def _event(
        session: Session,
        *,
        job: DiscoveryJob,
        event_key: str,
        event_type: str,
        stage: DiscoveryStageName | None,
        correlation_id: str,
        details: dict[str, object],
    ) -> None:
        session.add(
            DiscoveryJobEvent(
                organization_id=job.organization_id,
                discovery_job_id=job.id,
                event_key=event_key,
                event_type=event_type,
                stage=stage.value if stage is not None else None,
                details_json=details,
                correlation_id=correlation_id,
            )
        )


class RecordedSourceStageRunner:
    """Run one adapter stage in checkpointed batches; used by the Celery worker and tests."""

    def __init__(
        self,
        *,
        jobs: DiscoveryJobService,
        reconciler: CandidateReconciliationService,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._jobs = jobs
        self._reconciler = reconciler
        self._clock = clock or (lambda: datetime.now(UTC))

    def run(
        self,
        session: Session,
        *,
        organization_id: uuid.UUID,
        job_id: uuid.UUID,
        source: DiscoverySource,
        adapter: DiscoverySourceAdapter,
        stage: DiscoveryStageName,
        worker_token: str,
        lease_seconds: int,
        correlation_id: str,
        interrupt_after_batches: int | None = None,
    ) -> bool:
        if adapter.source_key != source.source_key:
            raise DiscoveryJobStateError(
                "Adapter source key does not match persisted discovery source"
            )
        lease = self._jobs.claim_stage(
            session,
            organization_id=organization_id,
            job_id=job_id,
            stage=stage,
            worker_token=worker_token,
            lease_seconds=lease_seconds,
            correlation_id=correlation_id,
        )
        if lease is None:
            return False
        session.commit()
        stage_row = session.scalar(
            select(DiscoveryJobStage).where(
                DiscoveryJobStage.discovery_job_id == job_id,
                DiscoveryJobStage.stage == stage.value,
            )
        )
        if stage_row is None:
            raise DiscoveryJobStateError("Job stage does not exist")
        processed = stage_row.processed_count
        succeeded = stage_row.succeeded_count
        failed = stage_row.failed_count
        skipped = stage_row.skipped_count
        batches = 0
        while True:
            checkpoint = self._jobs.checkpoint_for_stage(session, job_id=job_id, stage=stage)
            context = self._scope_context(session, organization_id=organization_id, job_id=job_id)
            batch = adapter.collect(context, checkpoint)
            for record in batch.records:
                normalized = adapter.normalize(context, record)
                processed += 1
                if normalized.candidates:
                    self._reconciler.ingest(
                        session,
                        source=source,
                        contracts=normalized.candidates,
                        payload_hash=record.payload_hash,
                    )
                    succeeded += 1
                elif normalized.warnings:
                    skipped += 1
                else:
                    failed += 1
            durable_checkpoint = batch.next_checkpoint or DiscoveryCheckpointContract(
                source_key=adapter.source_key,
                adapter_version=adapter.adapter_version,
                stage=stage,
                token={"completed": True, "processed": processed},
            )
            self._jobs.save_checkpoint(
                session,
                lease=lease,
                checkpoint=durable_checkpoint,
                processed_count=processed,
                succeeded_count=succeeded,
                failed_count=failed,
                skipped_count=skipped,
                known_total=None,
            )
            session.commit()
            batches += 1
            if interrupt_after_batches is not None and batches >= interrupt_after_batches:
                raise WorkerInterrupted("Interrupted after durable source checkpoint")
            if batch.next_checkpoint is None:
                self._jobs.complete_stage(
                    session,
                    lease=lease,
                    state="PARTIAL" if failed else "COMPLETED",
                    correlation_id=correlation_id,
                )
                session.commit()
                return True

    @staticmethod
    def _scope_context(
        session: Session,
        *,
        organization_id: uuid.UUID,
        job_id: uuid.UUID,
    ) -> ScopeSourceContext:
        job = session.scalar(
            select(DiscoveryJob).where(
                DiscoveryJob.id == job_id,
                DiscoveryJob.organization_id == organization_id,
            )
        )
        if job is None:
            raise DiscoveryJobStateError("Discovery job not found")
        seeds = tuple(
            TargetRule(
                cast(TargetType, seed.seed_type),
                seed.canonical_value,
                cast(MatchMode, seed.match_mode),
            )
            for seed in session.scalars(
                select(ScopeSeed).where(
                    ScopeSeed.scope_version_id == job.scope_version_id,
                    ScopeSeed.organization_id == organization_id,
                )
            )
        )
        exclusions = tuple(
            TargetRule(
                cast(TargetType, exclusion.exclusion_type),
                exclusion.canonical_value,
                cast(MatchMode, exclusion.match_mode),
            )
            for exclusion in session.scalars(
                select(ScopeExclusion).where(
                    ScopeExclusion.scope_version_id == job.scope_version_id,
                    ScopeExclusion.organization_id == organization_id,
                )
            )
        )
        return ScopeSourceContext(
            organization_id=job.organization_id,
            scope_id=job.scope_id,
            scope_version_id=job.scope_version_id,
            scope_approval_id=job.scope_approval_id,
            included_rules=seeds,
            exclusion_rules=exclusions,
        )


def adapter_for_configured_source(source: DiscoverySource) -> DiscoverySourceAdapter | None:
    """Resolve only explicit offline fixture references; live providers remain disabled."""

    if source.configuration_reference is None:
        return None
    fixture = recorded_fixture(source.configuration_reference)
    if fixture is None:
        return None
    if source.source_type == "RECORDED_PASSIVE_DNS":
        return RecordedPassiveDnsAdapter(fixture)
    if source.source_type == "CERTIFICATE_METADATA_IMPORT":
        return RecordedCertificateMetadataAdapter(fixture)
    return None


class DiscoveryJobWorker:
    """Worker-side durable driver accepting job IDs, never targets or provider credentials."""

    def __init__(
        self,
        *,
        session_factory: Callable[[], Session],
        adapter_factory: Callable[[DiscoverySource], DiscoverySourceAdapter | None] = (
            adapter_for_configured_source
        ),
        jobs: DiscoveryJobService | None = None,
        reconciler: CandidateReconciliationService | None = None,
        lease_seconds: int = 120,
        max_attempts: int = 3,
        interrupt_after_source_batches: int | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._adapter_factory = adapter_factory
        self._jobs = jobs or DiscoveryJobService()
        self._reconciler = reconciler or CandidateReconciliationService()
        self._lease_seconds = lease_seconds
        self._max_attempts = max_attempts
        self._interrupt_after_source_batches = interrupt_after_source_batches

    def run(
        self,
        *,
        organization_id: uuid.UUID,
        job_id: uuid.UUID,
        correlation_id: str,
        worker_token: str,
    ) -> str:
        with self._session_factory() as session:
            job = session.scalar(
                select(DiscoveryJob).where(
                    DiscoveryJob.id == job_id,
                    DiscoveryJob.organization_id == organization_id,
                )
            )
            if job is None:
                return "not_found"
            sources = list(
                session.scalars(
                    select(DiscoverySource).where(
                        DiscoverySource.organization_id == organization_id,
                        DiscoverySource.enabled.is_(True),
                    )
                )
            )
            runner = RecordedSourceStageRunner(jobs=self._jobs, reconciler=self._reconciler)
            executed_stages: set[DiscoveryStageName] = set()
            for source in sources:
                if self._converge_cancellation(session, job_id=job_id):
                    return "cancelled"
                if http_fixture_transport_for_reference(source.configuration_reference) is not None:
                    if self._run_configured_http_stage(
                        session,
                        job=job,
                        source=source,
                        correlation_id=correlation_id,
                        worker_token=worker_token,
                    ):
                        executed_stages.add(DiscoveryStageName.HTTP_METADATA)
                    if self._converge_cancellation(session, job_id=job_id):
                        return "cancelled"
                    continue
                if tls_fixture_connector_for_reference(source.configuration_reference) is not None:
                    if self._run_configured_tls_stage(
                        session,
                        job=job,
                        source=source,
                        correlation_id=correlation_id,
                        worker_token=worker_token,
                    ):
                        executed_stages.add(DiscoveryStageName.TLS_METADATA)
                    if self._converge_cancellation(session, job_id=job_id):
                        return "cancelled"
                    continue
                if fixture_connector_for_reference(source.configuration_reference) is not None:
                    if self._run_configured_tcp_stage(
                        session,
                        job=job,
                        source=source,
                        correlation_id=correlation_id,
                        worker_token=worker_token,
                    ):
                        executed_stages.add(DiscoveryStageName.TCP_VALIDATE)
                    if self._converge_cancellation(session, job_id=job_id):
                        return "cancelled"
                    continue
                if fixture_resolver_for_reference(source.configuration_reference) is not None:
                    if self._run_configured_dns_stage(
                        session,
                        job=job,
                        source=source,
                        correlation_id=correlation_id,
                        worker_token=worker_token,
                    ):
                        executed_stages.add(DiscoveryStageName.DNS_VALIDATE)
                    if self._converge_cancellation(session, job_id=job_id):
                        return "cancelled"
                    continue
                adapter = self._adapter_factory(source)
                stage = self._stage_for_source(source)
                if adapter is None or stage is None:
                    continue
                runner.run(
                    session,
                    organization_id=organization_id,
                    job_id=job_id,
                    source=source,
                    adapter=adapter,
                    stage=stage,
                    worker_token=f"{worker_token}:{stage.value}",
                    lease_seconds=self._lease_seconds,
                    correlation_id=correlation_id,
                    interrupt_after_batches=self._interrupt_after_source_batches,
                )
                executed_stages.add(stage)
                if self._converge_cancellation(session, job_id=job_id):
                    return "cancelled"
            self._skip_unregistered_stages(
                session,
                organization_id=organization_id,
                job_id=job_id,
                executed_stages=executed_stages,
                correlation_id=correlation_id,
            )
            status = self._jobs.finalize(session, organization_id=organization_id, job_id=job_id)
            session.commit()
            return status.lower()

    def _converge_cancellation(self, session: Session, *, job_id: uuid.UUID) -> bool:
        """Converge a durable cancellation before initiating any further stage work."""

        job = session.get(DiscoveryJob, job_id, populate_existing=True)
        if job is None or not DiscoveryRecoveryService.cancellation_requested(job):
            return False
        for stage in session.scalars(
            select(DiscoveryJobStage).where(DiscoveryJobStage.discovery_job_id == job.id)
        ):
            if stage.state not in _TERMINAL_STAGE_STATES:
                stage.state = "CANCELLED"
                stage.finished_at = self._jobs._clock()
                stage.lease_expires_at = None
        job.state = "CANCELLED"
        job.finished_at = self._jobs._clock()
        session.commit()
        return True

    def _run_configured_dns_stage(
        self,
        session: Session,
        *,
        job: DiscoveryJob,
        source: DiscoverySource,
        correlation_id: str,
        worker_token: str,
    ) -> bool:
        resolver = fixture_resolver_for_reference(source.configuration_reference)
        if resolver is None:
            return False
        lease = self._jobs.claim_stage(
            session,
            organization_id=job.organization_id,
            job_id=job.id,
            stage=DiscoveryStageName.DNS_VALIDATE,
            worker_token=f"{worker_token}:{DiscoveryStageName.DNS_VALIDATE.value}",
            lease_seconds=self._lease_seconds,
            correlation_id=correlation_id,
        )
        if lease is None:
            return True
        requester = session.get(User, job.requested_by_user_id)
        if requester is None:
            self._jobs.complete_stage(
                session,
                lease=lease,
                state="FAILED",
                correlation_id=correlation_id,
            )
            return True
        candidates = list(
            session.scalars(
                select(CandidateAsset).where(
                    CandidateAsset.organization_id == job.organization_id,
                    CandidateAsset.scope_version_id == job.scope_version_id,
                    CandidateAsset.candidate_type == CandidateType.DOMAIN.value,
                )
            )
        )
        worker = DnsValidationWorker(resolver=resolver, reconciler=self._reconciler)
        succeeded = 0
        failed = 0
        skipped = 0
        for candidate in candidates:
            outcome = worker.validate(
                session,
                job=job,
                candidate=candidate,
                source=source,
                principal=Principal(user=requester),
                correlation_id=correlation_id,
            )
            if outcome.result == "SUCCESS":
                succeeded += 1
            elif outcome.result in {"DENIED", "NXDOMAIN", "NOANSWER"}:
                skipped += 1
            else:
                failed += 1
        processed = succeeded + failed + skipped
        self._jobs.save_checkpoint(
            session,
            lease=lease,
            checkpoint=DiscoveryCheckpointContract(
                source_key=source.source_key,
                adapter_version=source.adapter_version,
                stage=DiscoveryStageName.DNS_VALIDATE,
                token={"completed": True, "processed": processed},
            ),
            processed_count=processed,
            succeeded_count=succeeded,
            failed_count=failed,
            skipped_count=skipped,
            known_total=len(candidates),
        )
        session.commit()
        self._jobs.complete_stage(
            session,
            lease=lease,
            state="PARTIAL" if failed else "COMPLETED",
            correlation_id=correlation_id,
        )
        session.commit()
        return True

    def _run_configured_http_stage(
        self,
        session: Session,
        *,
        job: DiscoveryJob,
        source: DiscoverySource,
        correlation_id: str,
        worker_token: str,
    ) -> bool:
        transport = http_fixture_transport_for_reference(source.configuration_reference)
        if transport is None:
            return False
        lease = self._jobs.claim_stage(
            session,
            organization_id=job.organization_id,
            job_id=job.id,
            stage=DiscoveryStageName.HTTP_METADATA,
            worker_token=f"{worker_token}:{DiscoveryStageName.HTTP_METADATA.value}",
            lease_seconds=self._lease_seconds,
            correlation_id=correlation_id,
        )
        if lease is None:
            return True
        requester = session.get(User, job.requested_by_user_id)
        if requester is None:
            self._jobs.complete_stage(
                session, lease=lease, state="FAILED", correlation_id=correlation_id
            )
            return True
        candidates = list(
            session.scalars(
                select(CandidateAsset).where(
                    CandidateAsset.organization_id == job.organization_id,
                    CandidateAsset.scope_version_id == job.scope_version_id,
                    CandidateAsset.candidate_type == CandidateType.ENDPOINT_HINT.value,
                )
            )
        )
        collector = HttpMetadataCollector(transport=transport)
        succeeded = failed = skipped = 0
        for candidate in candidates:
            if self._converge_cancellation(session, job_id=job.id):
                return True
            outcome = None
            for attempt_number in range(1, self._max_attempts + 1):
                if self._converge_cancellation(session, job_id=job.id):
                    return True
                outcome = collector.collect(
                    session,
                    job=job,
                    candidate=candidate,
                    principal=Principal(user=requester),
                    start_url=candidate.canonical_value,
                    correlation_id=correlation_id,
                    attempt_number=attempt_number,
                )
                retry_delay = DiscoveryRecoveryService.retry_delay(
                    attempt_number, max_attempts=self._max_attempts
                )
                if outcome.result != "TIMEOUT" or retry_delay is None:
                    break
                self._jobs._event(
                    session,
                    job=job,
                    event_key=(f"http_metadata.retry.{candidate.id}.{attempt_number}"),
                    event_type="retry.scheduled",
                    stage=DiscoveryStageName.HTTP_METADATA,
                    correlation_id=correlation_id,
                    details={
                        "attempt": attempt_number,
                        "delay_seconds": retry_delay.total_seconds(),
                    },
                )
                session.commit()
            if outcome is None:
                raise DiscoveryJobStateError("HTTP retry loop did not produce an outcome")
            if outcome.result == "TIMEOUT":
                DiscoveryRecoveryService.record_dead_letter(
                    session,
                    organization_id=job.organization_id,
                    job_id=job.id,
                    candidate_id=candidate.id,
                    stage=DiscoveryStageName.HTTP_METADATA.value,
                    operation_key=f"http:{candidate.id}",
                    attempts=self._max_attempts,
                    error_class="TRANSIENT_TIMEOUT",
                    safe_message="HTTP metadata fixture timed out after bounded retries",
                )
            if outcome.result == "SUCCESS":
                succeeded += 1
            elif outcome.result in {"DENIED", "REDIRECT_DENIED", "TOO_MANY_REDIRECTS"}:
                skipped += 1
            else:
                failed += 1
            processed = succeeded + failed + skipped
            self._jobs.save_checkpoint(
                session,
                lease=lease,
                checkpoint=DiscoveryCheckpointContract(
                    source_key=source.source_key,
                    adapter_version=source.adapter_version,
                    stage=DiscoveryStageName.HTTP_METADATA,
                    token={"completed": False, "processed": processed},
                ),
                processed_count=processed,
                succeeded_count=succeeded,
                failed_count=failed,
                skipped_count=skipped,
                known_total=len(candidates),
            )
            session.commit()
        processed = succeeded + failed + skipped
        self._jobs.save_checkpoint(
            session,
            lease=lease,
            checkpoint=DiscoveryCheckpointContract(
                source_key=source.source_key,
                adapter_version=source.adapter_version,
                stage=DiscoveryStageName.HTTP_METADATA,
                token={"completed": True, "processed": processed},
            ),
            processed_count=processed,
            succeeded_count=succeeded,
            failed_count=failed,
            skipped_count=skipped,
            known_total=len(candidates),
        )
        session.commit()
        self._jobs.complete_stage(
            session,
            lease=lease,
            state="PARTIAL" if failed else "COMPLETED",
            correlation_id=correlation_id,
        )
        session.commit()
        return True

    def _run_configured_tls_stage(
        self,
        session: Session,
        *,
        job: DiscoveryJob,
        source: DiscoverySource,
        correlation_id: str,
        worker_token: str,
    ) -> bool:
        connector = tls_fixture_connector_for_reference(source.configuration_reference)
        if connector is None:
            return False
        lease = self._jobs.claim_stage(
            session,
            organization_id=job.organization_id,
            job_id=job.id,
            stage=DiscoveryStageName.TLS_METADATA,
            worker_token=f"{worker_token}:{DiscoveryStageName.TLS_METADATA.value}",
            lease_seconds=self._lease_seconds,
            correlation_id=correlation_id,
        )
        if lease is None:
            return True
        requester = session.get(User, job.requested_by_user_id)
        if requester is None:
            self._jobs.complete_stage(
                session, lease=lease, state="FAILED", correlation_id=correlation_id
            )
            return True
        candidates = list(
            session.scalars(
                select(CandidateAsset).where(
                    CandidateAsset.organization_id == job.organization_id,
                    CandidateAsset.scope_version_id == job.scope_version_id,
                    CandidateAsset.candidate_type == CandidateType.IP.value,
                )
            )
        )
        collector = TlsMetadataCollector(connector=connector)
        succeeded = failed = skipped = 0
        for candidate in candidates:
            if self._converge_cancellation(session, job_id=job.id):
                return True
            tcp_success = session.scalar(
                select(CollectionAttempt).where(
                    CollectionAttempt.discovery_job_id == job.id,
                    CollectionAttempt.candidate_id == candidate.id,
                    CollectionAttempt.stage == DiscoveryStageName.TCP_VALIDATE.value,
                    CollectionAttempt.result == "SUCCESS",
                )
            )
            if tcp_success is None:
                skipped += 1
            else:
                observation = session.scalar(
                    select(CandidateObservation)
                    .where(CandidateObservation.candidate_id == candidate.id)
                    .order_by(CandidateObservation.observed_at.desc())
                )
                hostname = (
                    observation.normalized_metadata_json.get("hostname")
                    if observation is not None
                    else None
                )
                if not isinstance(hostname, str):
                    skipped += 1
                else:
                    outcome = None
                    for attempt_number in range(1, self._max_attempts + 1):
                        if self._converge_cancellation(session, job_id=job.id):
                            return True
                        outcome = collector.collect(
                            session,
                            job=job,
                            candidate=candidate,
                            principal=Principal(user=requester),
                            hostname=hostname,
                            address=candidate.canonical_value,
                            port=443,
                            timeout_seconds=3.0,
                            correlation_id=correlation_id,
                            attempt_number=attempt_number,
                        )
                        retry_delay = DiscoveryRecoveryService.retry_delay(
                            attempt_number, max_attempts=self._max_attempts
                        )
                        if (
                            outcome.result not in {"TIMEOUT", "TRANSIENT_ERROR"}
                            or retry_delay is None
                        ):
                            break
                        self._jobs._event(
                            session,
                            job=job,
                            event_key=(f"tls_metadata.retry.{candidate.id}.{attempt_number}"),
                            event_type="retry.scheduled",
                            stage=DiscoveryStageName.TLS_METADATA,
                            correlation_id=correlation_id,
                            details={
                                "attempt": attempt_number,
                                "delay_seconds": retry_delay.total_seconds(),
                            },
                        )
                        session.commit()
                    if outcome is None:
                        raise DiscoveryJobStateError("TLS retry loop did not produce an outcome")
                    if outcome.result in {"TIMEOUT", "TRANSIENT_ERROR"}:
                        DiscoveryRecoveryService.record_dead_letter(
                            session,
                            organization_id=job.organization_id,
                            job_id=job.id,
                            candidate_id=candidate.id,
                            stage=DiscoveryStageName.TLS_METADATA.value,
                            operation_key=f"tls:{candidate.id}",
                            attempts=self._max_attempts,
                            error_class="TRANSIENT_TLS",
                            safe_message="TLS metadata fixture failed after bounded retries",
                        )
                    if outcome.result == "SUCCESS":
                        succeeded += 1
                    elif outcome.result in {"DENIED", "CERTIFICATE_UNAVAILABLE"}:
                        skipped += 1
                    else:
                        failed += 1
            processed = succeeded + failed + skipped
            self._jobs.save_checkpoint(
                session,
                lease=lease,
                checkpoint=DiscoveryCheckpointContract(
                    source_key=source.source_key,
                    adapter_version=source.adapter_version,
                    stage=DiscoveryStageName.TLS_METADATA,
                    token={"completed": False, "processed": processed},
                ),
                processed_count=processed,
                succeeded_count=succeeded,
                failed_count=failed,
                skipped_count=skipped,
                known_total=len(candidates),
            )
            session.commit()
        processed = succeeded + failed + skipped
        self._jobs.save_checkpoint(
            session,
            lease=lease,
            checkpoint=DiscoveryCheckpointContract(
                source_key=source.source_key,
                adapter_version=source.adapter_version,
                stage=DiscoveryStageName.TLS_METADATA,
                token={"completed": True, "processed": processed},
            ),
            processed_count=processed,
            succeeded_count=succeeded,
            failed_count=failed,
            skipped_count=skipped,
            known_total=len(candidates),
        )
        session.commit()
        self._jobs.complete_stage(
            session,
            lease=lease,
            state="PARTIAL" if failed else "COMPLETED",
            correlation_id=correlation_id,
        )
        session.commit()
        return True

    def _run_configured_tcp_stage(
        self,
        session: Session,
        *,
        job: DiscoveryJob,
        source: DiscoverySource,
        correlation_id: str,
        worker_token: str,
    ) -> bool:
        connector = fixture_connector_for_reference(source.configuration_reference)
        if connector is None:
            return False
        lease = self._jobs.claim_stage(
            session,
            organization_id=job.organization_id,
            job_id=job.id,
            stage=DiscoveryStageName.TCP_VALIDATE,
            worker_token=f"{worker_token}:{DiscoveryStageName.TCP_VALIDATE.value}",
            lease_seconds=self._lease_seconds,
            correlation_id=correlation_id,
        )
        if lease is None:
            return True
        requester = session.get(User, job.requested_by_user_id)
        if requester is None:
            self._jobs.complete_stage(
                session,
                lease=lease,
                state="FAILED",
                correlation_id=correlation_id,
            )
            return True
        candidates = list(
            session.scalars(
                select(CandidateAsset).where(
                    CandidateAsset.organization_id == job.organization_id,
                    CandidateAsset.scope_version_id == job.scope_version_id,
                    CandidateAsset.candidate_type == CandidateType.IP.value,
                )
            )
        )
        worker = TcpValidationWorker(connector=connector)
        succeeded = 0
        failed = 0
        skipped = 0
        for candidate in candidates:
            observation = session.scalar(
                select(CandidateObservation)
                .where(CandidateObservation.candidate_id == candidate.id)
                .order_by(CandidateObservation.observed_at.desc())
            )
            if observation is None:
                skipped += 1
                continue
            metadata = observation.normalized_metadata_json
            hostname = metadata.get("hostname")
            ttl = metadata.get("ttl")
            if not isinstance(hostname, str) or not isinstance(ttl, int):
                skipped += 1
                continue
            outcome = worker.validate(
                session,
                job=job,
                candidate=candidate,
                principal=Principal(user=requester),
                resolved=ResolvedAddress(
                    hostname=hostname,
                    address=candidate.canonical_value,
                    resolved_at=observation.observed_at,
                    ttl_seconds=ttl,
                    scope_decision="ALLOWED",
                ),
                protocol="HTTPS",
                port=443,
                timeout_seconds=3.0,
                correlation_id=correlation_id,
            )
            if outcome.result == "SUCCESS":
                succeeded += 1
            elif outcome.result in {"DENIED", "CONNECTION_REFUSED"}:
                skipped += 1
            else:
                failed += 1
        processed = succeeded + failed + skipped
        self._jobs.save_checkpoint(
            session,
            lease=lease,
            checkpoint=DiscoveryCheckpointContract(
                source_key=source.source_key,
                adapter_version=source.adapter_version,
                stage=DiscoveryStageName.TCP_VALIDATE,
                token={"completed": True, "processed": processed},
            ),
            processed_count=processed,
            succeeded_count=succeeded,
            failed_count=failed,
            skipped_count=skipped,
            known_total=len(candidates),
        )
        session.commit()
        self._jobs.complete_stage(
            session,
            lease=lease,
            state="PARTIAL" if failed else "COMPLETED",
            correlation_id=correlation_id,
        )
        session.commit()
        return True

    def _skip_unregistered_stages(
        self,
        session: Session,
        *,
        organization_id: uuid.UUID,
        job_id: uuid.UUID,
        executed_stages: set[DiscoveryStageName],
        correlation_id: str,
    ) -> None:
        for stage in STAGE_ORDER:
            if stage in executed_stages:
                continue
            lease = self._jobs.claim_stage(
                session,
                organization_id=organization_id,
                job_id=job_id,
                stage=stage,
                worker_token=f"skip:{stage.value}",
                lease_seconds=self._lease_seconds,
                correlation_id=correlation_id,
            )
            if lease is not None:
                self._jobs.complete_stage(
                    session,
                    lease=lease,
                    state="SKIPPED",
                    correlation_id=correlation_id,
                )

    @staticmethod
    def _stage_for_source(source: DiscoverySource) -> DiscoveryStageName | None:
        mapping = {
            "RECORDED_PASSIVE_DNS": DiscoveryStageName.PASSIVE_SOURCE,
            "CERTIFICATE_METADATA_IMPORT": DiscoveryStageName.CERTIFICATE_IMPORT,
        }
        return mapping.get(source.source_type)
