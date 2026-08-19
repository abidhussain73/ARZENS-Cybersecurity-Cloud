from typing import cast

import pytest

from exposure360_api.models import ScopeVersion
from exposure360_api.scope_approval import ScopeApprovalService, ScopeStateError


class DraftVersion:
    state = "DRAFT"


class ApprovedVersion:
    state = "APPROVED"


def test_only_drafts_are_editable() -> None:
    ScopeApprovalService.ensure_draft(cast(ScopeVersion, DraftVersion()))

    with pytest.raises(ScopeStateError, match="immutable"):
        ScopeApprovalService.ensure_draft(cast(ScopeVersion, ApprovedVersion()))
