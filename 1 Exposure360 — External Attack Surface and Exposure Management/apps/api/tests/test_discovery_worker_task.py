"""Celery-entrypoint coverage without a broker or any external transport."""

import os
import sys
from pathlib import Path
from uuid import uuid4

import pytest

os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "worker"))

from exposure360_worker import tasks  # noqa: E402


def test_celery_task_delegates_stable_identifiers_to_durable_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization_id = uuid4()
    job_id = uuid4()
    received: dict[str, object] = {}

    class FakeSettings:
        discovery_stage_lease_seconds = 17

    class FakeWorker:
        def __init__(self, *, session_factory: object, lease_seconds: int) -> None:
            received["session_factory"] = session_factory
            received["lease_seconds"] = lease_seconds

        def run(
            self,
            *,
            organization_id: object,
            job_id: object,
            correlation_id: str,
            worker_token: str,
        ) -> str:
            received.update(
                {
                    "organization_id": organization_id,
                    "job_id": job_id,
                    "correlation_id": correlation_id,
                    "worker_token": worker_token,
                }
            )
            return "completed"

    from exposure360_api import config, discovery_orchestration

    monkeypatch.setattr(config, "get_settings", lambda: FakeSettings())
    monkeypatch.setattr(discovery_orchestration, "DiscoveryJobWorker", FakeWorker)

    result = tasks.run_discovery_job.run(
        str(organization_id),
        str(job_id),
        "celery-boundary-test",
    )

    assert result["status"] == "completed"
    assert result["job_id"] == str(job_id)
    assert received["organization_id"] == organization_id
    assert received["job_id"] == job_id
    assert received["correlation_id"] == "celery-boundary-test"
    assert received["lease_seconds"] == 17
    assert isinstance(received["worker_token"], str)
    assert str(received["worker_token"]).startswith("celery:")
