"""Phase 5 scheduler dispatch tests without a broker or background timer."""

import os
import sys
from pathlib import Path
from uuid import uuid4

import pytest

os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "worker"))

from exposure360_worker import tasks  # noqa: E402


def test_external_scheduler_heartbeat_dispatches_due_stable_identifiers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization_id = uuid4()
    sent: list[tuple[str, dict[str, object]]] = []

    class FakeSession:
        def __enter__(self) -> "FakeSession":
            return self

        def __exit__(self, *args: object) -> None:
            return None

    class FakePlanner:
        def __init__(self, session: object, settings: object):
            del session, settings

        def due(self) -> tuple[tuple[object, str], ...]:
            return ((organization_id, "CHANGE_DETECTION"),)

    from exposure360_api import config, db, evaluation_scheduler

    monkeypatch.setattr(config, "get_settings", lambda: object())
    monkeypatch.setattr(db, "SessionLocal", lambda: FakeSession())
    monkeypatch.setattr(evaluation_scheduler, "EvaluationSchedulePlanner", FakePlanner)
    monkeypatch.setattr(
        tasks.celery,
        "send_task",
        lambda name, kwargs: sent.append((name, kwargs)),
    )

    result = tasks.scheduler_heartbeat.run("external-heartbeat-test")

    assert not tasks.celery.conf.beat_schedule
    assert result == {"status": "scheduler-heartbeat", "enqueued": 1}
    assert sent == [
        (
            "exposure360_worker.tasks.run_evaluation_job",
            {
                "organization_id": str(organization_id),
                "run_type": "CHANGE_DETECTION",
                "correlation_id": f"external-heartbeat-test:{organization_id}:CHANGE_DETECTION",
                "trace_headers": {},
            },
        )
    ]
