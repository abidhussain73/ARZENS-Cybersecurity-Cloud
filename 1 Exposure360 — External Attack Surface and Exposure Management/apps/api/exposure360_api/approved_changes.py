"""Approved expected-change matching and explainable operational significance."""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final, cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from .audit import write_audit_event
from .models import ApprovedChange, Asset, ChangeEvent
from .security import OrganizationContext, Principal, require_role

_ALLOWED_CHANGE_TYPES: Final[frozenset[str]] = frozenset(
    {"NEW", "REMOVED", "SERVICE", "CERTIFICATE", "OWNERSHIP", "FINGERPRINT"}
)
_BASE_WEIGHTS: Final[dict[str, int]] = {
    "NEW": 60,
    "REMOVED": 40,
    "SERVICE": 70,
    "CERTIFICATE": 55,
    "OWNERSHIP": 45,
    "FINGERPRINT": 50,
}


class ApprovedChangeError(ValueError):
    """Raised for safe approved-change validation and tenancy failures."""


@dataclass(frozen=True)
class SignificanceResult:
    score: int
    model_version: str
    factors: tuple[dict[str, object], ...]


class SignificanceScorer:
    """Versioned deterministic review-priority scorer, not a risk scorer."""

    model_version: Final[str] = "change-significance-v1"

    def score(self, event: ChangeEvent) -> SignificanceResult:
        change_type = event.change_type
        if change_type not in _BASE_WEIGHTS:
            raise ApprovedChangeError(f"unsupported change type: {change_type}")
        factors: list[dict[str, object]] = [
            {"factor": f"{change_type}_CHANGE", "points": _BASE_WEIGHTS[change_type]}
        ]
        details = event.details_json
        if _number(details.get("evidence_confidence")) >= 0.8:
            factors.append({"factor": "HIGH_EVIDENCE_CONFIDENCE", "points": 10})
        if change_type == "SERVICE" and _externally_active(details):
            factors.append({"factor": "CURRENT_EXTERNAL_SERVICE", "points": 12})
        if change_type == "OWNERSHIP" and _ownership_conflict(details):
            factors.append({"factor": "OWNERSHIP_CONFLICT", "points": 15})
        if change_type == "CERTIFICATE" and _certificate_urgent(details):
            factors.append({"factor": "CERTIFICATE_URGENCY", "points": 15})
        if event.state == "EXPECTED":
            factors.append({"factor": "APPROVED_EXPECTED_CHANGE", "points": 0})
        unbounded = sum(cast(int, item["points"]) for item in factors)
        score = min(100, max(0, unbounded))
        if score != unbounded:
            factors.append({"factor": "SCORE_CLAMP", "points": score - unbounded})
        return SignificanceResult(score, self.model_version, tuple(factors))

    def persist(self, event: ChangeEvent) -> SignificanceResult:
        result = self.score(event)
        event.significance_score = result.score
        event.significance_model_version = result.model_version
        event.significance_factors_json = list(result.factors)
        return result


class ApprovedChangeService:
    def __init__(self, session: Session, scorer: SignificanceScorer | None = None):
        self._session = session
        self._scorer = scorer or SignificanceScorer()

    def create(
        self,
        context: OrganizationContext,
        principal: Principal,
        *,
        name: str,
        description: str,
        asset_id: uuid.UUID,
        allowed_change_types: tuple[str, ...],
        starts_at: datetime,
        ends_at: datetime,
        reason: str,
        correlation_id: str,
        approved_by_user_id: uuid.UUID | None = None,
        ticket_reference: str | None = None,
        component_selector: dict[str, object] | None = None,
        trace_id: str | None = None,
    ) -> ApprovedChange:
        require_role(context, "reviewer", "admin", "owner")
        normalized_types = self._validate_change_types(allowed_change_types)
        normalized_selector = self._validate_selector(component_selector)
        start = _utc(starts_at)
        end = _utc(ends_at)
        if start >= end:
            raise ApprovedChangeError("approved-change window must end after it starts")
        if not name.strip() or not description.strip() or not reason.strip():
            raise ApprovedChangeError("name, description, and reason are required")
        if self._asset(context.organization_id, asset_id) is None:
            raise ApprovedChangeError("asset not found in organization")
        approver = approved_by_user_id or principal.user.id
        approval = ApprovedChange(
            organization_id=context.organization_id,
            name=name.strip(),
            description=description.strip(),
            asset_id=asset_id,
            allowed_change_types_json=list(normalized_types),
            component_selector_json=normalized_selector,
            starts_at=start,
            ends_at=end,
            reason=reason.strip(),
            ticket_reference=ticket_reference.strip() if ticket_reference else None,
            approved_by_user_id=approver,
            created_by_user_id=principal.user.id,
            status="ACTIVE",
        )
        self._session.add(approval)
        self._session.flush()
        write_audit_event(
            self._session,
            context,
            principal,
            action="change_approval.create",
            resource_type="approved_change",
            resource_id=str(approval.id),
            correlation_id=correlation_id,
            trace_id=trace_id,
            result="SUCCESS",
            metadata={"asset_id": str(asset_id), "allowed_change_types": list(normalized_types)},
        )
        return approval

    def disable(
        self,
        context: OrganizationContext,
        principal: Principal,
        approval_id: uuid.UUID,
        correlation_id: str,
        *,
        trace_id: str | None = None,
    ) -> ApprovedChange:
        require_role(context, "reviewer", "admin", "owner")
        approval = self._approval(context.organization_id, approval_id)
        if approval.status != "DISABLED":
            approval.status = "DISABLED"
            write_audit_event(
                self._session,
                context,
                principal,
                action="change_approval.disable",
                resource_type="approved_change",
                resource_id=str(approval.id),
                correlation_id=correlation_id,
                trace_id=trace_id,
                result="SUCCESS",
            )
        return approval

    def apply_suppression(
        self,
        context: OrganizationContext,
        principal: Principal,
        change_event_id: uuid.UUID,
        observed_at: datetime,
        correlation_id: str,
        *,
        trace_id: str | None = None,
    ) -> ChangeEvent:
        event = self._event(context.organization_id, change_event_id)
        approval = self._match(context.organization_id, event, _utc(observed_at))
        if approval is not None and event.approved_change_id != approval.id:
            event.approved_change_id = approval.id
            event.state = "EXPECTED"
            self._scorer.persist(event)
            write_audit_event(
                self._session,
                context,
                principal,
                action="change_event.suppressed_expected",
                resource_type="change_event",
                resource_id=str(event.id),
                correlation_id=correlation_id,
                trace_id=trace_id,
                result="SUCCESS",
                metadata={"approved_change_id": str(approval.id), "change_type": event.change_type},
            )
        elif event.significance_score is None:
            self._scorer.persist(event)
        return event

    def _match(
        self, organization_id: uuid.UUID, event: ChangeEvent, observed_at: datetime
    ) -> ApprovedChange | None:
        candidates = self._session.scalars(
            select(ApprovedChange).where(
                ApprovedChange.organization_id == organization_id,
                ApprovedChange.status == "ACTIVE",
                ApprovedChange.asset_id == event.asset_id,
                ApprovedChange.starts_at <= observed_at,
                ApprovedChange.ends_at > observed_at,
            )
        )
        for approval in candidates:
            if event.change_type not in set(approval.allowed_change_types_json):
                continue
            if _selector_matches(approval.component_selector_json, event.details_json):
                return approval
        return None

    def _approval(self, organization_id: uuid.UUID, approval_id: uuid.UUID) -> ApprovedChange:
        approval = self._session.scalar(
            select(ApprovedChange).where(
                ApprovedChange.id == approval_id,
                ApprovedChange.organization_id == organization_id,
            )
        )
        if approval is None:
            raise ApprovedChangeError("approved change not found in organization")
        return approval

    def _event(self, organization_id: uuid.UUID, event_id: uuid.UUID) -> ChangeEvent:
        event = self._session.scalar(
            select(ChangeEvent).where(
                ChangeEvent.id == event_id,
                ChangeEvent.organization_id == organization_id,
            )
        )
        if event is None:
            raise ApprovedChangeError("change event not found in organization")
        return event

    def _asset(self, organization_id: uuid.UUID, asset_id: uuid.UUID) -> Asset | None:
        return self._session.scalar(
            select(Asset).where(Asset.id == asset_id, Asset.organization_id == organization_id)
        )

    @staticmethod
    def _validate_change_types(change_types: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(set(change_types)))
        if not normalized or not set(normalized).issubset(_ALLOWED_CHANGE_TYPES):
            raise ApprovedChangeError("approved change types are invalid")
        return normalized

    @staticmethod
    def _validate_selector(selector: dict[str, object] | None) -> dict[str, object] | None:
        if selector is None:
            return None
        if set(selector) != {"component_key"}:
            raise ApprovedChangeError("component selector only supports component_key")
        value = selector.get("component_key")
        if not isinstance(value, str) or not value.strip():
            raise ApprovedChangeError("component selector must contain a component_key")
        return {"component_key": value.strip()}


def _selector_matches(selector: dict[str, object] | None, details: dict[str, object]) -> bool:
    if selector is None:
        return True
    return selector["component_key"] == details.get("component_key")


def _number(value: object) -> float:
    return float(value) if isinstance(value, int | float) else 0.0


def _externally_active(details: dict[str, object]) -> bool:
    return bool(details.get("externally_active")) or _nested_flag(
        details.get("new"), "externally_active"
    )


def _ownership_conflict(details: dict[str, object]) -> bool:
    return _nested_value(details.get("new"), "state") == "CONFLICT"


def _certificate_urgent(details: dict[str, object]) -> bool:
    return _number(details.get("certificate_expires_in_days")) <= 7 and (
        "certificate_expires_in_days" in details
    )


def _nested_flag(value: object, key: str) -> bool:
    return isinstance(value, dict) and bool(value.get(key))


def _nested_value(value: object, key: str) -> object | None:
    return value.get(key) if isinstance(value, dict) else None


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
