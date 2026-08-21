"""Evidence-based Phase 7 closure gate; a task cannot self-certify closure."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ClosureDecision(StrEnum):
    ALLOW_CLOSE = "ALLOW_CLOSE"
    DENY_CLOSE = "DENY_CLOSE"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True)
class ClosureGateInput:
    finding_state: str
    remediation_state: str
    verification_state: str
    verification_result: str
    evidence_current: bool
    evidence_integrity_valid: bool
    collection_complete: bool
    scope_approval_valid: bool
    rule_verification_valid: bool
    contradictory_current_evidence: bool


@dataclass(frozen=True)
class ClosureGateResult:
    decision: ClosureDecision
    reason_codes: tuple[str, ...]


class FindingClosureGate:
    def evaluate(self, item: ClosureGateInput) -> ClosureGateResult:
        reasons: list[str] = []
        if item.finding_state != "RESOLVED_PENDING_VERIFICATION":
            reasons.append("FINDING_NOT_PENDING_VERIFICATION")
        if item.remediation_state != "RESOLVED_PENDING_VERIFICATION":
            reasons.append("TASK_NOT_PENDING_VERIFICATION")
        if item.verification_state != "COMPLETED":
            reasons.append("VERIFICATION_NOT_COMPLETED")
        if item.verification_result == "CONDITION_PRESENT":
            return ClosureGateResult(
                ClosureDecision.DENY_CLOSE, tuple(reasons + ["CONDITION_PRESENT"])
            )
        if item.verification_result != "CONDITION_ABSENT":
            reasons.append("VERIFICATION_INCONCLUSIVE")
        if not item.evidence_current:
            reasons.append("EVIDENCE_STALE")
        if not item.evidence_integrity_valid:
            reasons.append("EVIDENCE_INTEGRITY_INVALID")
        if not item.collection_complete:
            reasons.append("COLLECTION_INCOMPLETE")
        if not item.scope_approval_valid:
            reasons.append("SCOPE_APPROVAL_INVALID")
        if not item.rule_verification_valid:
            reasons.append("RULE_VERIFICATION_INVALID")
        if item.contradictory_current_evidence:
            reasons.append("CONTRADICTORY_CURRENT_EVIDENCE")
        if reasons:
            return ClosureGateResult(ClosureDecision.INCONCLUSIVE, tuple(reasons))
        return ClosureGateResult(ClosureDecision.ALLOW_CLOSE, ())
