import os

from celery import Celery
from opentelemetry import propagate

from .observability import configure_tracing, log_event, trace_id

celery = Celery("exposure360_worker", broker=os.environ["REDIS_URL"], backend=os.environ["REDIS_URL"])
celery.conf.beat_schedule = {
    "scheduler-heartbeat": {
        "task": "exposure360_worker.tasks.scheduler_heartbeat",
        "schedule": 60.0,
    }
}
tracer = configure_tracing("exposure360-worker")

@celery.task(name="exposure360_worker.tasks.observability_probe")
def observability_probe(
    correlation_id: str, trace_headers: dict[str, str] | None = None
) -> dict[str, str | None]:
    parent_context = propagate.extract(trace_headers or {})
    with tracer.start_as_current_span(
        "observability_probe.worker", context=parent_context
    ) as span:
        current_trace_id = trace_id()
        log_event(
            "observability_probe_completed",
            correlation_id=correlation_id,
            trace_id=current_trace_id,
            span_id=f"{span.get_span_context().span_id:016x}",
        )
    return {"status": "completed", "correlation_id": correlation_id, "trace_id": current_trace_id}

@celery.task(name="exposure360_worker.tasks.scheduler_heartbeat")
def scheduler_heartbeat() -> dict[str, str]:
    log_event("scheduler_heartbeat")
    return {"status": "scheduler-heartbeat"}
