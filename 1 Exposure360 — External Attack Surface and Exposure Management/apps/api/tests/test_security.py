import uuid

import pytest
from fastapi import HTTPException

from exposure360_api.models import Membership
from exposure360_api.security import OrganizationContext, require_role


def _membership(role: str) -> Membership:
    return Membership(
        organization_id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        role=role,
        is_active=True,
    )


def test_role_policy_denies_viewer_for_admin_action() -> None:
    context = OrganizationContext(uuid.uuid4(), _membership("viewer"))
    with pytest.raises(HTTPException) as exception:
        require_role(context, "admin")
    assert exception.value.status_code == 403


def test_role_policy_accepts_admin() -> None:
    context = OrganizationContext(uuid.uuid4(), _membership("admin"))
    require_role(context, "admin")
