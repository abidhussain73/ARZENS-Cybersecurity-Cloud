import os
import uuid

from celery import Celery
from opentelemetry import propagate

from .observability import configure_tracing, log_event, trace_id

celery = Celery(
    "exposure360_worker",
    broker=os.environ["REDIS_URL"],
    backend=os.environ["REDIS_URL"],
)
tracer = configure_tracing("exposure360-worker")


@celery.task(name="exposure360_worker.tasks.run_discovery_job")
def run_discovery_job(
    organization_id: str,
    job_id: str,
    correlation_id: str,
    trace_headers: dict[str, str] | None = None,
) -> dict[str, str | None]:
    """Load a durable job by ID; stages attach only guarded runners."""

    from exposure360_api.config import get_settings
    from exposure360_api.db import SessionLocal
    from exposure360_api.discovery_orchestration import DiscoveryJobWorker

    parent_context = propagate.extract(trace_headers or {})
    with tracer.start_as_current_span("discovery_job.worker", context=parent_context):
        settings = get_settings()
        status = DiscoveryJobWorker(
            session_factory=SessionLocal,
            lease_seconds=settings.discovery_stage_lease_seconds,
        ).run(
            organization_id=uuid.UUID(organization_id),
            job_id=uuid.UUID(job_id),
            correlation_id=correlation_id,
            worker_token=f"celery:{uuid.uuid4()}",
        )
        log_event(
            "discovery_job_executed",
            correlation_id=correlation_id,
            job_id=job_id,
            organization_id=organization_id,
            status=status,
        )
        return {"status": status, "job_id": job_id, "trace_id": trace_id()}


@celery.task(name="exposure360_worker.tasks.observability_probe")
def observability_probe(
    correlation_id: str, trace_headers: dict[str, str] | None = None
) -> dict[str, str | None]:
    parent_context = propagate.extract(trace_headers or {})
    with tracer.start_as_current_span("observability_probe.worker", context=parent_context) as span:
        current_trace_id = trace_id()
        log_event(
            "observability_probe_completed",
            correlation_id=correlation_id,
            trace_id=current_trace_id,
            span_id=f"{span.get_span_context().span_id:016x}",
        )
    return {"status": "completed", "correlation_id": correlation_id, "trace_id": current_trace_id}


@celery.task(name="exposure360_worker.tasks.run_evaluation_job")
def run_evaluation_job(
    organization_id: str,
    run_type: str,
    correlation_id: str,
    trace_headers: dict[str, str] | None = None,
) -> dict[str, str | None]:
    """Run one tenant-safe, metadata-only Phase 5 evaluation by stable identifiers."""

    from exposure360_api.db import SessionLocal
    from exposure360_api.evaluation_metrics import record, started_at
    from exposure360_api.evaluation_scheduler import EvaluationMetrics, EvaluationScheduler
    from exposure360_api.exposure_rules import (
        ExposureRuleLoader,
        default_exposure_rule_directory,
    )
    from exposure360_api.scheduled_evaluations import ScheduledEvaluationService

    parent_context = propagate.extract(trace_headers or {})
    with tracer.start_as_current_span("evaluation_run.worker", context=parent_context):
        started = started_at()
        with SessionLocal() as session:
            scheduler = EvaluationScheduler(session)
            ruleset = None
            if run_type == "EXPOSURE_RULE_EVALUATION":
                ruleset = ExposureRuleLoader().load(default_exposure_rule_directory())
                ExposureRuleLoader().synchronize(session, ruleset)
            execution = scheduler.run_for_organization(
                uuid.UUID(organization_id),
                run_type,  # type: ignore[arg-type]
                correlation_id,
                lambda run: ScheduledEvaluationService(session).execute(run, ruleset=ruleset),
                ruleset_hash=ruleset.ruleset_hash if ruleset is not None else None,
                trace_id=trace_id(),
            )
            if execution.run is not None and not execution.skipped_for_overlap:
                metrics = EvaluationMetrics(
                    assets_processed=execution.run.assets_processed,
                    findings_matched=execution.run.findings_matched,
                    findings_created=execution.run.findings_created,
                    findings_updated=execution.run.findings_updated,
                    snapshots_created=execution.run.snapshots_created,
                    changes_created=execution.run.changes_created,
                    changes_suppressed=execution.run.changes_suppressed,
                    error_count=execution.run.error_count,
                    last_error_code=execution.run.last_error_code,
                )
                record(execution.run, metrics, started)
            session.commit()
            log_event(
                "evaluation_run_executed",
                organization_id=organization_id,
                run_type=run_type,
                correlation_id=correlation_id,
                run_id=str(execution.run.id) if execution.run is not None else None,
                state=execution.run.state if execution.run is not None else "SKIPPED",
            )
            return {
                "status": execution.run.state if execution.run is not None else "skipped",
                "run_id": str(execution.run.id) if execution.run is not None else None,
                "trace_id": trace_id(),
            }


@celery.task(name="exposure360_worker.tasks.scheduler_heartbeat")
def scheduler_heartbeat(correlation_id: str = "scheduler-heartbeat") -> dict[str, str | int]:
    """Dispatch due work when invoked by a durable external scheduler, never a local timer."""

    from exposure360_api.config import get_settings
    from exposure360_api.db import SessionLocal
    from exposure360_api.evaluation_scheduler import EvaluationSchedulePlanner

    with SessionLocal() as session:
        due = EvaluationSchedulePlanner(session, get_settings()).due()
        for organization_id, run_type in due:
            celery.send_task(
                "exposure360_worker.tasks.run_evaluation_job",
                kwargs={
                    "organization_id": str(organization_id),
                    "run_type": run_type,
                    "correlation_id": f"{correlation_id}:{organization_id}:{run_type}",
                    "trace_headers": {},
                },
            )
        log_event("scheduler_heartbeat", correlation_id=correlation_id, enqueued=len(due))
        return {"status": "scheduler-heartbeat", "enqueued": len(due)}
