from exposure360_api.closure_gate import (
    ClosureDecision,
    ClosureGateInput,
    FindingClosureGate,
)


def _input(**changes: object) -> ClosureGateInput:
    values: dict[str, object] = {
        "finding_state": "RESOLVED_PENDING_VERIFICATION",
        "remediation_state": "RESOLVED_PENDING_VERIFICATION",
        "verification_state": "COMPLETED",
        "verification_result": "CONDITION_ABSENT",
        "evidence_current": True,
        "evidence_integrity_valid": True,
        "collection_complete": True,
        "scope_approval_valid": True,
        "rule_verification_valid": True,
        "contradictory_current_evidence": False,
    }
    values.update(changes)
    return ClosureGateInput(**values)  # type: ignore[arg-type]


def test_closure_is_allowed_only_after_current_complete_evidence_proves_absence() -> None:
    result = FindingClosureGate().evaluate(_input())

    assert result.decision is ClosureDecision.ALLOW_CLOSE
    assert result.reason_codes == ()


def test_stale_degraded_tampered_or_contradictory_evidence_cannot_close() -> None:
    for changes, reason in (
        ({"evidence_current": False}, "EVIDENCE_STALE"),
        ({"collection_complete": False}, "COLLECTION_INCOMPLETE"),
        ({"evidence_integrity_valid": False}, "EVIDENCE_INTEGRITY_INVALID"),
        ({"contradictory_current_evidence": True}, "CONTRADICTORY_CURRENT_EVIDENCE"),
    ):
        result = FindingClosureGate().evaluate(_input(**changes))
        assert result.decision is ClosureDecision.INCONCLUSIVE
        assert reason in result.reason_codes


def test_condition_present_is_an_explicit_denial() -> None:
    result = FindingClosureGate().evaluate(_input(verification_result="CONDITION_PRESENT"))

    assert result.decision is ClosureDecision.DENY_CLOSE
    assert "CONDITION_PRESENT" in result.reason_codes
