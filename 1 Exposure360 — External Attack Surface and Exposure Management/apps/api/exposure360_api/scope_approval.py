import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import ScanPolicy, Scope, ScopeApproval, ScopeExclusion, ScopeSeed, ScopeVersion
from .scope_governance import (
    MatchMode,
    ScopeConflictAnalyzer,
    TargetRule,
    TargetType,
    calculate_content_hash,
)


class ScopeStateError(ValueError):
    """Raised when a scope lifecycle transition would weaken governance."""


@dataclass(frozen=True)
class ScopeAuthorizationEnvelope:
    organization_id: uuid.UUID
    scope_id: uuid.UUID
    scope_version_id: uuid.UUID
    approval_id: uuid.UUID
    policy_hash: str


def _seed_rules(session: Session, version: ScopeVersion) -> list[TargetRule]:
    records = session.scalars(
        select(ScopeSeed).where(
            ScopeSeed.scope_version_id == version.id,
            ScopeSeed.organization_id == version.organization_id,
        )
    ).all()
    return [
        TargetRule(
            target_type=cast(TargetType, record.seed_type),
            canonical_value=record.canonical_value,
            match_mode=cast(MatchMode, record.match_mode),
        )
        for record in records
    ]


def _exclusion_rules(session: Session, version: ScopeVersion) -> list[TargetRule]:
    records = session.scalars(
        select(ScopeExclusion).where(
            ScopeExclusion.scope_version_id == version.id,
            ScopeExclusion.organization_id == version.organization_id,
        )
    ).all()
    return [
        TargetRule(
            target_type=cast(TargetType, record.exclusion_type),
            canonical_value=record.canonical_value,
            match_mode=cast(MatchMode, record.match_mode),
        )
        for record in records
    ]


def _policy_payload(policy: ScanPolicy) -> dict[str, object]:
    return {
        "allowed_protocols": sorted(policy.allowed_protocols),
        "max_requests_per_second": policy.max_requests_per_second,
        "max_concurrent_targets": policy.max_concurrent_targets,
        "max_concurrent_requests": policy.max_concurrent_requests,
        "schedule_timezone": policy.schedule_timezone,
        "schedule_windows": policy.schedule_windows,
        "connect_timeout_seconds": policy.connect_timeout_seconds,
        "request_timeout_seconds": policy.request_timeout_seconds,
        "active_scanning_enabled": policy.active_scanning_enabled,
    }


class ScopeApprovalService:
    @staticmethod
    def ensure_draft(version: ScopeVersion) -> None:
        if version.state != "DRAFT":
            raise ScopeStateError("Scope version is immutable outside DRAFT state")

    @staticmethod
    def content_hash(session: Session, version: ScopeVersion) -> str:
        policy = session.scalar(
            select(ScanPolicy).where(
                ScanPolicy.scope_version_id == version.id,
                ScanPolicy.organization_id == version.organization_id,
            )
        )
        if policy is None:
            raise ScopeStateError("Scope version requires a scan policy")
        return calculate_content_hash(
            scope_version_id=str(version.id),
            seeds=_seed_rules(session, version),
            exclusions=_exclusion_rules(session, version),
            policy=_policy_payload(policy),
        )

    @classmethod
    def submit(cls, session: Session, version: ScopeVersion) -> str:
        cls.ensure_draft(version)
        seeds = _seed_rules(session, version)
        if not seeds:
            raise ScopeStateError("Scope version requires at least one seed")
        report = ScopeConflictAnalyzer.analyze(seeds, _exclusion_rules(session, version))
        if not report.is_approvable:
            raise ScopeStateError("Scope version has blocking conflicts")
        version.content_hash = cls.content_hash(session, version)
        version.state = "SUBMITTED"
        return version.content_hash

    @classmethod
    def approve(
        cls,
        session: Session,
        *,
        organization_id: uuid.UUID,
        scope_id: uuid.UUID,
        version_id: uuid.UUID,
        approver_id: uuid.UUID,
        reason: str | None,
        expires_at: datetime | None,
    ) -> ScopeApproval:
        version = session.scalar(
            select(ScopeVersion)
            .where(
                ScopeVersion.id == version_id,
                ScopeVersion.scope_id == scope_id,
                ScopeVersion.organization_id == organization_id,
            )
            .with_for_update()
        )
        scope = session.scalar(
            select(Scope)
            .where(Scope.id == scope_id, Scope.organization_id == organization_id)
            .with_for_update()
        )
        if scope is None or version is None:
            raise ScopeStateError("Scope or version not found")
        if scope.status != "ACTIVE":
            raise ScopeStateError("Disabled or archived scope cannot be approved")
        if version.state != "SUBMITTED":
            raise ScopeStateError("Only submitted scope versions can be approved")
        current_hash = cls.content_hash(session, version)
        if version.content_hash != current_hash:
            raise ScopeStateError("Scope version content changed after submission")
        if expires_at is not None and expires_at <= datetime.now(UTC):
            raise ScopeStateError("Approval expiry must be in the future")
        current = session.scalar(
            select(ScopeVersion)
            .where(ScopeVersion.scope_id == scope_id, ScopeVersion.state == "APPROVED")
            .with_for_update()
        )
        if current is not None:
            current.state = "SUPERSEDED"
        version.state = "APPROVED"
        approval = ScopeApproval(
            organization_id=organization_id,
            scope_id=scope_id,
            scope_version_id=version.id,
            approved_by_user_id=approver_id,
            decision="APPROVED",
            decision_reason=reason,
            expires_at=expires_at,
            content_hash=current_hash,
        )
        session.add(approval)
        session.flush()
        return approval

    @classmethod
    def active_envelope(
        cls,
        session: Session,
        *,
        organization_id: uuid.UUID,
        scope_id: uuid.UUID,
        version_id: uuid.UUID,
        approval_id: uuid.UUID,
        now: datetime | None = None,
    ) -> ScopeAuthorizationEnvelope:
        now = now or datetime.now(UTC)
        scope = session.scalar(
            select(Scope).where(Scope.id == scope_id, Scope.organization_id == organization_id)
        )
        version = session.scalar(
            select(ScopeVersion).where(
                ScopeVersion.id == version_id,
                ScopeVersion.scope_id == scope_id,
                ScopeVersion.organization_id == organization_id,
            )
        )
        approval = session.scalar(
            select(ScopeApproval).where(
                ScopeApproval.id == approval_id,
                ScopeApproval.organization_id == organization_id,
                ScopeApproval.scope_id == scope_id,
                ScopeApproval.scope_version_id == version_id,
                ScopeApproval.decision == "APPROVED",
            )
        )
        if scope is None or version is None or approval is None:
            raise ScopeStateError("Approval envelope is not authorized")
        if scope.status != "ACTIVE" or version.state != "APPROVED":
            raise ScopeStateError("Scope version is not active")
        if approval.expires_at is not None and approval.expires_at <= now:
            raise ScopeStateError("Approval has expired")
        current_hash = cls.content_hash(session, version)
        if current_hash != approval.content_hash or version.content_hash != approval.content_hash:
            raise ScopeStateError("Approved content hash does not match")
        return ScopeAuthorizationEnvelope(
            organization_id=organization_id,
            scope_id=scope_id,
            scope_version_id=version_id,
            approval_id=approval_id,
            policy_hash=approval.content_hash,
        )
