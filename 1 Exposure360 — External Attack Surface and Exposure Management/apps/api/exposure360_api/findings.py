"""Evidence-backed finding lifecycle and deterministic deduplication services."""

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .audit import write_audit_event
from .models import (
    Finding,
    FindingEvaluationEvent,
    FindingEvidenceLink,
    FindingStateEvent,
)
from .security import OrganizationContext, Principal, require_role

_TRANSITIONS: dict[str, frozenset[str]] = {
    "OPEN": frozenset({"ACKNOWLEDGED", "IN_PROGRESS", "EXCEPTION"}),
    "ACKNOWLEDGED": frozenset({"OPEN", "IN_PROGRESS", "EXCEPTION"}),
    "IN_PROGRESS": frozenset({"OPEN", "RESOLVED_PENDING_VERIFICATION", "EXCEPTION"}),
    "RESOLVED_PENDING_VERIFICATION": frozenset({"OPEN", "IN_PROGRESS", "CLOSED"}),
    "EXCEPTION": frozenset({"OPEN", "IN_PROGRESS", "RESOLVED_PENDING_VERIFICATION"}),
    "CLOSED": frozenset({"OPEN"}),
}


class FindingStateError(ValueError):
    """Raised when a reviewed lifecycle transition cannot be performed."""


@dataclass(frozen=True)
class FindingMatch:
    asset_id: uuid.UUID
    service_asset_id: uuid.UUID | None
    rule_id: str
    rule_version: int
    rule_hash: str
    title: str
    description: str
    category: str
    rule_severity: str
    confidence: float
    observed_at: datetime
    component_key: str = "default"
    identity_version: int = 1
    observation_id: uuid.UUID | None = None
    evidence_ids: tuple[uuid.UUID, ...] = ()
    evaluation_run_id: uuid.UUID | None = None


class FindingFingerprintService:
    @staticmethod
    def create(organization_id: uuid.UUID, match: FindingMatch) -> str:
        material = {
            "organization_id": str(organization_id),
            "asset_id": str(match.asset_id),
            "service_asset_id": str(match.service_asset_id) if match.service_asset_id else "-",
            "rule_id": match.rule_id,
            "component_key": match.component_key,
            "identity_version": match.identity_version,
        }
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class FindingService:
    def __init__(self, session: Session):
        self._session = session

    def record_match(self, organization_id: uuid.UUID, match: FindingMatch) -> Finding:
        observed_at = _utc(match.observed_at)
        fingerprint = FindingFingerprintService.create(organization_id, match)
        finding = self._session.scalar(
            select(Finding).where(
                Finding.organization_id == organization_id,
                Finding.fingerprint == fingerprint,
            )
        )
        if finding is None:
            finding = self._create_finding(organization_id, match, fingerprint, observed_at)
        else:
            self._refresh_finding(finding, match, observed_at)
        self._link_evidence(organization_id, finding, match)
        self._add_evaluation_event(organization_id, finding, match, observed_at)
        return finding

    def transition(
        self,
        context: OrganizationContext,
        principal: Principal,
        finding_id: uuid.UUID,
        target_state: str,
        correlation_id: str,
        *,
        reason: str | None = None,
        exception_expires_at: datetime | None = None,
        verification_reference: str | None = None,
        occurred_at: datetime | None = None,
    ) -> Finding:
        finding = self._finding(context.organization_id, finding_id)
        self._authorize(context, target_state)
        if target_state not in _TRANSITIONS.get(finding.state, frozenset()):
            raise FindingStateError(f"invalid transition {finding.state} to {target_state}")
        if target_state == "CLOSED" and not verification_reference:
            raise FindingStateError("closing requires a verification reference")
        if target_state == "EXCEPTION" and not reason:
            raise FindingStateError("exception requires a reason")
        now = _utc(occurred_at or datetime.now(tz=UTC))
        previous = finding.state
        finding.state = target_state
        self._set_transition_timestamp(finding, target_state, now, reason, exception_expires_at)
        self._state_event(
            context.organization_id,
            finding,
            previous,
            target_state,
            principal.user.id,
            reason,
            correlation_id,
        )
        write_audit_event(
            self._session,
            context,
            principal,
            action="finding.state_changed",
            resource_type="finding",
            resource_id=str(finding.id),
            correlation_id=correlation_id,
            result="SUCCESS",
            metadata={"from_state": previous, "to_state": target_state, "reason": reason},
        )
        return finding

    def reopen_expired_exceptions(
        self,
        organization_id: uuid.UUID,
        now: datetime,
        correlation_id: str,
    ) -> list[Finding]:
        when = _utc(now)
        expired = list(
            self._session.scalars(
                select(Finding).where(
                    Finding.organization_id == organization_id,
                    Finding.state == "EXCEPTION",
                    Finding.exception_expires_at.is_not(None),
                    Finding.exception_expires_at <= when,
                )
            )
        )
        for finding in expired:
            finding.state = "OPEN"
            self._state_event(
                organization_id,
                finding,
                "EXCEPTION",
                "OPEN",
                None,
                "exception_expired",
                correlation_id,
            )
        return expired

    def _create_finding(
        self,
        organization_id: uuid.UUID,
        match: FindingMatch,
        fingerprint: str,
        observed_at: datetime,
    ) -> Finding:
        finding = Finding(
            organization_id=organization_id,
            asset_id=match.asset_id,
            service_asset_id=match.service_asset_id,
            rule_id=match.rule_id,
            rule_version=match.rule_version,
            rule_hash=match.rule_hash,
            fingerprint=fingerprint,
            title=match.title,
            description=match.description,
            category=match.category,
            rule_severity=match.rule_severity,
            confidence=match.confidence,
            state="OPEN",
            first_seen=observed_at,
            last_seen=observed_at,
            opened_at=observed_at,
        )
        try:
            with self._session.begin_nested():
                self._session.add(finding)
                self._session.flush()
        except IntegrityError:
            existing_finding = self._session.scalar(
                select(Finding).where(
                    Finding.organization_id == organization_id,
                    Finding.fingerprint == fingerprint,
                )
            )
            if existing_finding is None:
                raise
            finding = existing_finding
            self._refresh_finding(finding, match, observed_at)
        return finding

    def _refresh_finding(
        self, finding: Finding, match: FindingMatch, observed_at: datetime
    ) -> None:
        finding.rule_version = match.rule_version
        finding.rule_hash = match.rule_hash
        finding.title = match.title
        finding.description = match.description
        finding.category = match.category
        finding.rule_severity = match.rule_severity
        finding.confidence = match.confidence
        finding.first_seen = min(_utc(finding.first_seen), observed_at)
        finding.last_seen = max(_utc(finding.last_seen), observed_at)
        if finding.state == "CLOSED":
            finding.state = "OPEN"
            self._state_event(
                finding.organization_id,
                finding,
                "CLOSED",
                "OPEN",
                None,
                "recurrence_detected",
                "system-recurrence",
            )

    def _link_evidence(
        self, organization_id: uuid.UUID, finding: Finding, match: FindingMatch
    ) -> None:
        for evidence_id in match.evidence_ids:
            material = (
                f"{finding.id}:{evidence_id}:{match.observation_id}:"
                f"{match.rule_id}:{match.rule_version}"
            )
            link_key = hashlib.sha256(material.encode("utf-8")).hexdigest()
            existing = self._session.scalar(
                select(FindingEvidenceLink).where(
                    FindingEvidenceLink.organization_id == organization_id,
                    FindingEvidenceLink.link_key == link_key,
                )
            )
            if existing is None:
                self._session.add(
                    FindingEvidenceLink(
                        organization_id=organization_id,
                        finding_id=finding.id,
                        evidence_id=evidence_id,
                        observation_id=match.observation_id,
                        rule_id=match.rule_id,
                        rule_version=match.rule_version,
                        link_key=link_key,
                    )
                )

    def _add_evaluation_event(
        self,
        organization_id: uuid.UUID,
        finding: Finding,
        match: FindingMatch,
        observed_at: datetime,
    ) -> None:
        evidence_set = ",".join(sorted(str(item) for item in match.evidence_ids))
        self._session.add(
            FindingEvaluationEvent(
                organization_id=organization_id,
                finding_id=finding.id,
                evaluation_run_id=match.evaluation_run_id,
                rule_version=match.rule_version,
                matched=True,
                confidence=match.confidence,
                evidence_set_hash=hashlib.sha256(evidence_set.encode("utf-8")).hexdigest(),
                evaluated_at=observed_at,
            )
        )

    def _finding(self, organization_id: uuid.UUID, finding_id: uuid.UUID) -> Finding:
        finding = self._session.scalar(
            select(Finding).where(
                Finding.id == finding_id, Finding.organization_id == organization_id
            )
        )
        if finding is None:
            raise FindingStateError("finding not found in organization")
        return finding

    @staticmethod
    def _authorize(context: OrganizationContext, target_state: str) -> None:
        if target_state in {"ACKNOWLEDGED", "IN_PROGRESS", "RESOLVED_PENDING_VERIFICATION"}:
            require_role(context, "analyst", "admin", "owner")
        elif target_state == "EXCEPTION":
            require_role(context, "reviewer", "admin", "owner")
        elif target_state == "CLOSED":
            require_role(context, "admin", "owner")
        else:
            require_role(context, "analyst", "reviewer", "admin", "owner")

    @staticmethod
    def _set_transition_timestamp(
        finding: Finding,
        target_state: str,
        occurred_at: datetime,
        reason: str | None,
        exception_expires_at: datetime | None,
    ) -> None:
        if target_state == "ACKNOWLEDGED":
            finding.acknowledged_at = occurred_at
        if target_state == "IN_PROGRESS":
            finding.in_progress_at = occurred_at
        if target_state == "RESOLVED_PENDING_VERIFICATION":
            finding.resolved_pending_verification_at = occurred_at
        if target_state == "CLOSED":
            finding.closed_at = occurred_at
        if target_state == "EXCEPTION":
            finding.exception_at = occurred_at
            finding.exception_reason = reason
            finding.exception_expires_at = (
                _utc(exception_expires_at) if exception_expires_at else None
            )

    def _state_event(
        self,
        organization_id: uuid.UUID,
        finding: Finding,
        from_state: str | None,
        to_state: str,
        actor_user_id: uuid.UUID | None,
        reason: str | None,
        correlation_id: str,
    ) -> None:
        self._session.add(
            FindingStateEvent(
                organization_id=organization_id,
                finding_id=finding.id,
                from_state=from_state,
                to_state=to_state,
                actor_user_id=actor_user_id,
                reason=reason,
                correlation_id=correlation_id,
            )
        )


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
