from time import perf_counter

from prometheus_client import Counter, Histogram

from .evaluation_scheduler import EvaluationMetrics
from .models import EvaluationRun

EVALUATION_RUNS = Counter(
    "exposure_evaluation_runs_total",
    "Evaluation runs by durable terminal state",
    ["run_type", "state"],
)
EVALUATION_DURATION = Histogram(
    "evaluation_duration_seconds",
    "Evaluation duration by run type",
    ["run_type"],
)
EVALUATION_ASSETS = Counter(
    "evaluation_assets_processed_total",
    "Assets processed by evaluation type",
    ["run_type"],
)
FINDINGS_CREATED = Counter(
    "findings_created_total",
    "Findings created by bounded severity",
    ["severity"],
)
FINDINGS_UPDATED = Counter(
    "findings_updated_total",
    "Findings updated by bounded lifecycle state",
    ["state"],
)
CHANGE_EVENTS = Counter(
    "change_events_total",
    "Change events by bounded type",
    ["type"],
)
CHANGE_EVENTS_SUPPRESSED = Counter(
    "change_events_suppressed_total",
    "Expected change events by bounded type",
    ["type"],
)


def started_at() -> float:
    return perf_counter()


def record(run: EvaluationRun, metrics: EvaluationMetrics, started: float) -> None:
    EVALUATION_RUNS.labels(run_type=run.run_type, state=run.state).inc()
    EVALUATION_DURATION.labels(run_type=run.run_type).observe(perf_counter() - started)
    EVALUATION_ASSETS.labels(run_type=run.run_type).inc(metrics.assets_processed)
    if metrics.findings_created:
        FINDINGS_CREATED.labels(severity="UNSPECIFIED").inc(metrics.findings_created)
    if metrics.findings_updated:
        FINDINGS_UPDATED.labels(state="OPEN").inc(metrics.findings_updated)
    if metrics.changes_created:
        CHANGE_EVENTS.labels(type="MIXED").inc(metrics.changes_created)
    if metrics.changes_suppressed:
        CHANGE_EVENTS_SUPPRESSED.labels(type="MIXED").inc(metrics.changes_suppressed)
