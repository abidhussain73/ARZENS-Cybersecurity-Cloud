from datetime import UTC, datetime, timedelta
from uuid import uuid4

from exposure360_api.models import RemediationTask
from exposure360_api.remediation_workflow import SlaClock, SlaTerms

NOW = datetime(2026, 8, 21, 12, tzinfo=UTC)


def _task(due_at: datetime, state: str = "IN_PROGRESS") -> RemediationTask:
    return RemediationTask(
        id=uuid4(),
        organization_id=uuid4(),
        finding_id=uuid4(),
        title="Fixture remediation",
        state=state,
        priority="P1",
        opened_at=NOW,
        due_at=due_at,
    )


def test_sla_uses_utc_elapsed_time_and_exact_boundary_is_not_overdue() -> None:
    due_at = SlaClock.due_at(NOW, SlaTerms("P1", 24 * 60 * 60))
    task = _task(due_at)

    assert due_at == NOW + timedelta(days=1)
    assert SlaClock.overdue(task, due_at - timedelta(seconds=1)) is False
    assert SlaClock.overdue(task, due_at) is False
    assert SlaClock.overdue(task, due_at + timedelta(seconds=1)) is True


def test_terminal_tasks_are_not_overdue() -> None:
    due_at = NOW - timedelta(seconds=1)

    assert SlaClock.overdue(_task(due_at, "CLOSED"), NOW) is False
    assert SlaClock.overdue(_task(due_at, "CANCELLED"), NOW) is False
