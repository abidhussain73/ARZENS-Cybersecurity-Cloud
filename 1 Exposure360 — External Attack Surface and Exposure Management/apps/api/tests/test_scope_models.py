from exposure360_api.models import (
    EmergencyStopState,
    ScanPolicy,
    Scope,
    ScopeApproval,
    ScopeExclusion,
    ScopeSeed,
    ScopeVersion,
)


def test_phase_two_entities_are_organization_owned() -> None:
    for model in (
        Scope,
        ScopeVersion,
        ScopeSeed,
        ScopeExclusion,
        ScanPolicy,
        ScopeApproval,
        EmergencyStopState,
    ):
        assert "organization_id" in model.__table__.c


def test_scope_version_has_immutable_approval_constraints() -> None:
    constraint_names = {constraint.name for constraint in ScopeVersion.__table__.constraints}
    index_names = {index.name for index in ScopeVersion.__table__.indexes}

    assert "uq_scope_version_number" in constraint_names
    assert "ck_scope_version_state" in constraint_names
    assert "uq_scope_versions_one_approved" in index_names


def test_scope_targets_and_policy_have_governance_constraints() -> None:
    seed_constraints = {constraint.name for constraint in ScopeSeed.__table__.constraints}
    exclusion_constraints = {constraint.name for constraint in ScopeExclusion.__table__.constraints}
    policy_constraints = {constraint.name for constraint in ScanPolicy.__table__.constraints}
    stop_constraints = {constraint.name for constraint in EmergencyStopState.__table__.constraints}

    assert {"ck_scope_seed_type", "ck_scope_seed_match_mode"}.issubset(seed_constraints)
    assert {"ck_scope_exclusion_type", "ck_scope_exclusion_match_mode"}.issubset(
        exclusion_constraints
    )
    assert {
        "ck_policy_positive_rate",
        "ck_policy_positive_targets",
        "ck_policy_positive_requests",
    }.issubset(policy_constraints)
    assert {"ck_stop_state_level", "ck_stop_state_scope_shape"}.issubset(stop_constraints)
