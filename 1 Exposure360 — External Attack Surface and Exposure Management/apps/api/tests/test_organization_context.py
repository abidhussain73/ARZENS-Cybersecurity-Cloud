import uuid

import pytest
from fastapi import HTTPException
from sqlalchemy.dialects import postgresql

from exposure360_api.models import Membership, User
from exposure360_api.security import Principal, require_org_context


class RecordingSession:
    def __init__(self, membership: Membership | None) -> None:
        self.membership = membership
        self.query_sql = ""

    def scalar(self, statement: object) -> Membership | None:
        self.query_sql = str(statement.compile(dialect=postgresql.dialect()))
        return self.membership


def _principal() -> Principal:
    return Principal(User(id=uuid.uuid4(), oidc_subject="alice", is_active=True))


def test_organization_context_allows_active_matching_membership() -> None:
    principal = _principal()
    organization_id = uuid.uuid4()
    membership = Membership(
        organization_id=organization_id,
        user_id=principal.user.id,
        role="analyst",
        is_active=True,
    )
    session = RecordingSession(membership)

    context = require_org_context(session, principal, str(organization_id))

    assert context.organization_id == organization_id
    assert context.membership is membership
    assert "memberships.organization_id" in session.query_sql
    assert "memberships.user_id" in session.query_sql


def test_organization_context_rejects_mismatched_organization() -> None:
    principal = _principal()
    requested_organization = uuid.uuid4()
    session = RecordingSession(None)

    with pytest.raises(HTTPException) as exception:
        require_org_context(session, principal, str(requested_organization))

    assert exception.value.status_code == 403
    assert "memberships.organization_id" in session.query_sql
    assert "memberships.user_id" in session.query_sql
