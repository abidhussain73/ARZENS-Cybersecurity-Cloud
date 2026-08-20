"""Cancellation, bounded retry, and dead-letter controls for discovery staging."""

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import DeadLetterItem, DiscoveryJob, DiscoveryJobEvent, DiscoveryJobStage


class DiscoveryRecoveryService:
    """Durable control-plane operations for at-least-once worker execution."""

    @staticmethod
    def request_cancellation(
        session: Session,
        *,
        organization_id: uuid.UUID,
        job_id: uuid.UUID,
        correlation_id: str,
        now: datetime | None = None,
    ) -> DiscoveryJob:
        job = session.scalar(
            select(DiscoveryJob).where(
                DiscoveryJob.id == job_id,
                DiscoveryJob.organization_id == organization_id,
            )
        )
        if job is None:
            raise ValueError("Discovery job not found")
        if job.state not in {
            "COMPLETED",
            "PARTIAL",
            "DEGRADED",
            "CANCELLING",
            "CANCELLED",
            "FAILED",
        }:
            timestamp = now or datetime.now(UTC)
            job.state = "CANCELLING"
            job.cancel_requested_at = timestamp
            job.cancel_reason = "Cancellation requested"
            job.cancel_generation += 1
            session.add(
                DiscoveryJobEvent(
                    organization_id=organization_id,
                    discovery_job_id=job.id,
                    event_key=f"cancel-requested:{job.id}",
                    event_type="CANCELLATION_REQUESTED",
                    details_json={"requested_at": timestamp.isoformat()},
                    correlation_id=correlation_id,
                )
            )
        session.flush()
        return job

    @staticmethod
    def cancellation_requested(job: DiscoveryJob) -> bool:
        return job.state in {"CANCELLING", "CANCELLED"}

    @staticmethod
    def retry_delay(
        attempt_number: int,
        *,
        max_attempts: int,
        base_seconds: int = 1,
    ) -> timedelta | None:
        if attempt_number < 1 or attempt_number >= max_attempts:
            return None
        return timedelta(seconds=base_seconds * (2 ** (attempt_number - 1)))

    @staticmethod
    def record_dead_letter(
        session: Session,
        *,
        organization_id: uuid.UUID,
        job_id: uuid.UUID,
        candidate_id: uuid.UUID | None,
        stage: str,
        operation_key: str,
        attempts: int,
        error_class: str,
        safe_message: str,
        now: datetime | None = None,
    ) -> DeadLetterItem:
        timestamp = now or datetime.now(UTC)
        item = session.scalar(
            select(DeadLetterItem).where(
                DeadLetterItem.discovery_job_id == job_id,
                DeadLetterItem.operation_key == operation_key,
            )
        )
        if item is None:
            item = DeadLetterItem(
                organization_id=organization_id,
                discovery_job_id=job_id,
                candidate_id=candidate_id,
                stage=stage,
                operation_key=operation_key,
                attempts=attempts,
                last_error_class=error_class,
                last_error_safe_message=safe_message[:512],
                state="OPEN",
                first_failed_at=timestamp,
                last_failed_at=timestamp,
            )
            session.add(item)
        else:
            item.attempts = attempts
            item.last_error_class = error_class
            item.last_error_safe_message = safe_message[:512]
            item.last_failed_at = timestamp
            item.state = "OPEN"
        session.flush()
        return item

    @staticmethod
    def requeue_dead_letter(
        session: Session,
        *,
        organization_id: uuid.UUID,
        job_id: uuid.UUID,
        item_id: uuid.UUID,
        correlation_id: str,
    ) -> DeadLetterItem:
        """Mark one durable failure for replay and reopen only its affected job stage."""

        item = session.scalar(
            select(DeadLetterItem).where(
                DeadLetterItem.id == item_id,
                DeadLetterItem.organization_id == organization_id,
                DeadLetterItem.discovery_job_id == job_id,
            )
        )
        if item is None:
            raise ValueError("Dead-letter item not found")
        job = session.scalar(
            select(DiscoveryJob).where(
                DiscoveryJob.id == job_id,
                DiscoveryJob.organization_id == organization_id,
            )
        )
        if job is None:
            raise ValueError("Discovery job not found")
        stage = session.scalar(
            select(DiscoveryJobStage).where(
                DiscoveryJobStage.discovery_job_id == job_id,
                DiscoveryJobStage.organization_id == organization_id,
                DiscoveryJobStage.stage == item.stage,
            )
        )
        if stage is None:
            raise ValueError("Dead-letter stage not found")
        if item.state != "REQUEUED":
            item.state = "REQUEUED"
            stage.state = "QUEUED"
            stage.finished_at = None
            stage.lease_expires_at = None
            job.state = "QUEUED"
            job.finished_at = None
            session.add(
                DiscoveryJobEvent(
                    organization_id=organization_id,
                    discovery_job_id=job.id,
                    event_key=f"dead-letter-requeued:{item.id}",
                    event_type="DEAD_LETTER_REQUEUED",
                    stage=item.stage,
                    details_json={"dead_letter_item_id": str(item.id), "stage": item.stage},
                    correlation_id=correlation_id,
                )
            )
        session.flush()
        return item
