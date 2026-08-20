from unittest.mock import Mock

from exposure360_api.jobs import enqueue_discovery_job


def test_enqueue_discovery_job_passes_stable_identifiers_only() -> None:
    celery = Mock()

    enqueue_discovery_job(
        celery,
        organization_id="11111111-1111-1111-1111-111111111111",
        job_id="22222222-2222-2222-2222-222222222222",
        correlation_id="phase-three-queue-test",
    )

    celery.send_task.assert_called_once_with(
        "exposure360_worker.tasks.run_discovery_job",
        kwargs={
            "organization_id": "11111111-1111-1111-1111-111111111111",
            "job_id": "22222222-2222-2222-2222-222222222222",
            "correlation_id": "phase-three-queue-test",
        },
    )
