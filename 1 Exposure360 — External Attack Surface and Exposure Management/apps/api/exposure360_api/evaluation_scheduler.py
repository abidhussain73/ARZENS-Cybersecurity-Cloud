"""Durable, externally triggered Phase 5 evaluation scheduling primitives.

This module deliberately contains no timer. A platform-managed Heartbeat invokes a handler,
which calls ``run_for_organization`` with an explicit run type and stable correlation identifier.
"""

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final, Literal, cast

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .approved_changes import SignificanceScorer
from .asset_snapshots import SNAPSHOT_SCHEMA_VERSION
from .config import Settings
from .models import EvaluationRun, Organization

RunType = Literal[
    "EXPOSURE_RULE_EVALUATION",
    "ASSET_SNAPSHOT_BUILD",
    "CHANGE_DETECTION",
    "EXCEPTION_EXPIRY",
]
RunState = Literal["QUEUED", "RUNNING", "PARTIAL", "COMPLETED", "FAILED", "CANCELLED"]

_RUN_TYPES: Final[frozenset[str]] = frozenset(
    {"EXPOSURE_RULE_EVALUATION", "ASSET_SNAPSHOT_BUILD", "CHANGE_DETECTION", "EXCEPTION_EXPIRY"}
)


@dataclass(frozen=True)
class EvaluationMetrics:
    assets_processed: int = 0
    findings_matched: int = 0
    findings_created: int = 0
    findings_updated: int = 0
    snapshots_created: int = 0
    changes_created: int = 0
    changes_suppressed: int = 0
    error_count: int = 0
    last_error_code: str | None = None


@dataclass(frozen=True)
class EvaluationExecution:
    run: EvaluationRun | None
    skipped_for_overlap: bool


class EvaluationRunRepository:
    def __init__(self, session: Session):
        self._session = session

    def start_or_skip(
        self,
        organization_id: uuid.UUID,
        run_type: RunType,
        correlation_id: str,
        *,
        ruleset_hash: str | None = None,
        trace_id: str | None = None,
        started_at: datetime | None = None,
    ) -> EvaluationExecution:
        self._validate_run_type(run_type)
        if not self._is_active_organization(organization_id):
            return EvaluationExecution(run=None, skipped_for_overlap=False)
        current = self._running(organization_id, run_type)
        if current is not None:
            return EvaluationExecution(run=current, skipped_for_overlap=True)
        now = _utc(started_at or datetime.now(tz=UTC))
        run = EvaluationRun(
            organization_id=organization_id,
            run_type=run_type,
            state="RUNNING",
            ruleset_hash=ruleset_hash,
            snapshot_schema_version=SNAPSHOT_SCHEMA_VERSION,
            significance_model_version=SignificanceScorer.model_version,
            started_at=now,
            correlation_id=correlation_id,
            trace_id=trace_id,
        )
        try:
            with self._session.begin_nested():
                self._session.add(run)
                self._session.flush()
        except IntegrityError:
            current = self._running(organization_id, run_type)
            if current is None:
                raise
            return EvaluationExecution(run=current, skipped_for_overlap=True)
        return EvaluationExecution(run=run, skipped_for_overlap=False)

    def finish(
        self,
        run: EvaluationRun,
        metrics: EvaluationMetrics,
        state: RunState = "COMPLETED",
        *,
        finished_at: datetime | None = None,
    ) -> EvaluationRun:
        if state not in {"PARTIAL", "COMPLETED", "FAILED", "CANCELLED"}:
            raise ValueError("evaluation runs may only finish in a terminal state")
        if metrics.error_count and state == "COMPLETED":
            state = "PARTIAL"
        run.state = state
        run.finished_at = _utc(finished_at or datetime.now(tz=UTC))
        run.assets_processed = _non_negative(metrics.assets_processed)
        run.findings_matched = _non_negative(metrics.findings_matched)
        run.findings_created = _non_negative(metrics.findings_created)
        run.findings_updated = _non_negative(metrics.findings_updated)
        run.snapshots_created = _non_negative(metrics.snapshots_created)
        run.changes_created = _non_negative(metrics.changes_created)
        run.changes_suppressed = _non_negative(metrics.changes_suppressed)
        run.error_count = _non_negative(metrics.error_count)
        run.last_error_code = metrics.last_error_code
        return run

    def fail(
        self,
        run: EvaluationRun,
        error_code: str,
        *,
        finished_at: datetime | None = None,
    ) -> None:
        run.state = "FAILED"
        run.finished_at = _utc(finished_at or datetime.now(tz=UTC))
        run.error_count += 1
        run.last_error_code = error_code[:128]

    def _running(self, organization_id: uuid.UUID, run_type: RunType) -> EvaluationRun | None:
        return self._session.scalar(
            select(EvaluationRun).where(
                EvaluationRun.organization_id == organization_id,
                EvaluationRun.run_type == run_type,
                EvaluationRun.state == "RUNNING",
            )
        )

    def _is_active_organization(self, organization_id: uuid.UUID) -> bool:
        return (
            self._session.scalar(
                select(Organization.id).where(
                    Organization.id == organization_id,
                    Organization.is_active.is_(True),
                )
            )
            is not None
        )

    @staticmethod
    def _validate_run_type(run_type: str) -> None:
        if run_type not in _RUN_TYPES:
            raise ValueError("unsupported evaluation run type")


class EvaluationScheduler:
    """Entry point for Heartbeat callbacks and worker-triggered execution."""

    def __init__(self, session: Session):
        self._runs = EvaluationRunRepository(session)

    def run_for_organization(
        self,
        organization_id: uuid.UUID,
        run_type: RunType,
        correlation_id: str,
        executor: Callable[[EvaluationRun], EvaluationMetrics],
        *,
        ruleset_hash: str | None = None,
        trace_id: str | None = None,
    ) -> EvaluationExecution:
        execution = self._runs.start_or_skip(
            organization_id,
            run_type,
            correlation_id,
            ruleset_hash=ruleset_hash,
            trace_id=trace_id,
        )
        if execution.run is None or execution.skipped_for_overlap:
            return execution
        try:
            metrics = executor(execution.run)
        except Exception:
            self._runs.fail(execution.run, "EVALUATION_EXECUTION_FAILED")
            return execution
        self._runs.finish(execution.run, metrics)
        return execution

    def run_rule_evaluation(
        self,
        organization_id: uuid.UUID,
        correlation_id: str,
        ruleset_loader: Callable[[], str],
        executor: Callable[[EvaluationRun], EvaluationMetrics],
        *,
        trace_id: str | None = None,
    ) -> EvaluationExecution:
        ruleset_hash = ruleset_loader()
        return self.run_for_organization(
            organization_id,
            "EXPOSURE_RULE_EVALUATION",
            correlation_id,
            executor,
            ruleset_hash=ruleset_hash,
            trace_id=trace_id,
        )


class EvaluationSchedulePlanner:
    """Determines due tenant/type pairs; triggering remains outside this process."""

    def __init__(self, session: Session, settings: Settings):
        self._session = session
        self._intervals = {
            "EXPOSURE_RULE_EVALUATION": settings.exposure_evaluation_interval,
            "ASSET_SNAPSHOT_BUILD": settings.snapshot_interval,
            "CHANGE_DETECTION": settings.change_detection_interval,
            "EXCEPTION_EXPIRY": settings.exception_expiry_interval,
        }

    def due(self, now: datetime | None = None) -> tuple[tuple[uuid.UUID, RunType], ...]:
        when = _utc(now or datetime.now(tz=UTC))
        organizations = self._session.scalars(
            select(Organization.id)
            .where(Organization.is_active.is_(True))
            .order_by(Organization.id)
        )
        due: list[tuple[uuid.UUID, RunType]] = []
        for organization_id in organizations:
            for run_type, interval in self._intervals.items():
                typed_run_type = cast(RunType, run_type)
                if self._is_due(organization_id, typed_run_type, interval, when):
                    due.append((organization_id, typed_run_type))
        return tuple(due)

    def _is_due(
        self, organization_id: uuid.UUID, run_type: RunType, interval_seconds: int, now: datetime
    ) -> bool:
        latest = self._session.scalar(
            select(EvaluationRun)
            .where(
                EvaluationRun.organization_id == organization_id,
                EvaluationRun.run_type == run_type,
            )
            .order_by(EvaluationRun.created_at.desc(), EvaluationRun.id.desc())
        )
        if latest is None:
            return True
        if latest.state == "RUNNING":
            return False
        reference = latest.finished_at or latest.started_at or latest.created_at
        return (_utc(reference) - now).total_seconds() <= -interval_seconds


def _non_negative(value: int) -> int:
    return max(0, value)


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
