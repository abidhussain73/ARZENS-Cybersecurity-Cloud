from celery import Celery

from .config import Settings


def get_celery_client(settings: Settings) -> Celery:
    return Celery("exposure360_api", broker=settings.redis_url, backend=settings.redis_url)


def enqueue_discovery_job(
    celery: Celery,
    *,
    organization_id: str,
    job_id: str,
    correlation_id: str,
) -> None:
    """Queue stable identifiers only."""

    celery.send_task(
        "exposure360_worker.tasks.run_discovery_job",
        kwargs={
            "organization_id": organization_id,
            "job_id": job_id,
            "correlation_id": correlation_id,
        },
    )
