import ipaddress
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, cast

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .emergency_stop import EmergencyStopService
from .models import ScanPolicy, Scope, ScopeExclusion, ScopeSeed, ScopeVersion
from .scan_policy import PolicyEvaluationInput, ScanPolicyEvaluator, ScanPolicySnapshot
from .scope_approval import ScopeApprovalService, ScopeStateError
from .scope_governance import (
    MatchMode,
    ScopeTargetNormalizer,
    ScopeValidationError,
    TargetRule,
    TargetType,
    target_matches,
)
from .security import Principal, require_org_context

_ASN_PATTERN = re.compile(r"^(?:AS)?[0-9]+$", re.IGNORECASE)


@dataclass(frozen=True)
class OperationContext:
    protocol: str
    correlation_id: str
    requests_in_current_second: float = 0
    concurrent_targets: int = 0
    concurrent_requests: int = 0


@dataclass(frozen=True)
class ScopeAuthorizationRequest:
    principal: Principal
    organization_id: uuid.UUID
    scope_id: uuid.UUID
    scope_version_id: uuid.UUID
    approval_id: uuid.UUID
    target: str
    operation: OperationContext
    now: datetime | None = None


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason_code: str
    scope_id: uuid.UUID
    scope_version_id: uuid.UUID
    approval_id: uuid.UUID
    policy_hash: str | None
    correlation_id: str


class ScopeDenied(PermissionError):
    def __init__(self, decision: ScopeDecision) -> None:
        super().__init__(decision.reason_code)
        self.decision = decision


class NetworkTransport(Protocol):
    def request(self, *, target: str, protocol: str) -> object: ...


def _infer_target_type(target: str) -> TargetType:
    value = target.strip()
    if _ASN_PATTERN.fullmatch(value):
        return "ASN"
    if "/" in value:
        return "CIDR"
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return "DOMAIN"
    return "IP"


class ScopeGuard:
    def __init__(self, session: Session) -> None:
        self.session = session

    def _decision(
        self,
        request: ScopeAuthorizationRequest,
        *,
        allowed: bool,
        reason_code: str,
        policy_hash: str | None = None,
    ) -> ScopeDecision:
        return ScopeDecision(
            allowed=allowed,
            reason_code=reason_code,
            scope_id=request.scope_id,
            scope_version_id=request.scope_version_id,
            approval_id=request.approval_id,
            policy_hash=policy_hash,
            correlation_id=request.operation.correlation_id,
        )

    def authorize(self, request: ScopeAuthorizationRequest) -> ScopeDecision:
        """Apply the Phase 2 guard order immediately before a future connector request."""
        # 1. Authenticate the caller's organization context.
        try:
            context = require_org_context(
                self.session, request.principal, str(request.organization_id)
            )
        except HTTPException:
            return self._decision(request, allowed=False, reason_code="ORGANIZATION_CONTEXT_DENIED")

        # 2-3. Load exactly this organization's active scope.
        scope = self.session.scalar(
            select(Scope).where(
                Scope.id == request.scope_id,
                Scope.organization_id == context.organization_id,
            )
        )
        if scope is None:
            return self._decision(request, allowed=False, reason_code="SCOPE_NOT_FOUND")
        if scope.status != "ACTIVE":
            return self._decision(request, allowed=False, reason_code="SCOPE_DISABLED")

        # 4-5. Check organization and scope emergency stops on every request.
        stop_status = EmergencyStopService.status(
            self.session, organization_id=context.organization_id, scope_id=scope.id
        )
        if stop_status.active:
            code = (
                "ORGANIZATION_EMERGENCY_STOP"
                if stop_status.level == "ORGANIZATION"
                else "SCOPE_EMERGENCY_STOP"
            )
            return self._decision(request, allowed=False, reason_code=code)

        # 6. Verify exact version belongs to this scope and organization.
        version = self.session.scalar(
            select(ScopeVersion).where(
                ScopeVersion.id == request.scope_version_id,
                ScopeVersion.scope_id == scope.id,
                ScopeVersion.organization_id == context.organization_id,
            )
        )
        if version is None:
            return self._decision(request, allowed=False, reason_code="SCOPE_VERSION_NOT_FOUND")

        # 7-8. Verify immutable approval and content hash through the single authority.
        try:
            envelope = ScopeApprovalService.active_envelope(
                self.session,
                organization_id=context.organization_id,
                scope_id=scope.id,
                version_id=version.id,
                approval_id=request.approval_id,
                now=request.now or datetime.now(UTC),
            )
        except ScopeStateError as exc:
            message = str(exc).lower()
            reason = "APPROVAL_EXPIRED" if "expired" in message else "APPROVAL_INVALID"
            return self._decision(request, allowed=False, reason_code=reason)

        # 9. Normalize the requested target without resolution or probing.
        target_type = _infer_target_type(request.target)
        try:
            normalized_target = ScopeTargetNormalizer.normalize_target(target_type, request.target)
        except ScopeValidationError:
            return self._decision(
                request,
                allowed=False,
                reason_code="TARGET_INVALID",
                policy_hash=envelope.policy_hash,
            )
        if target_type == "ASN":
            return self._decision(
                request,
                allowed=False,
                reason_code="ASN_NOT_NETWORK_EXECUTABLE",
                policy_hash=envelope.policy_hash,
            )

        seeds = self.session.scalars(
            select(ScopeSeed).where(
                ScopeSeed.scope_version_id == version.id,
                ScopeSeed.organization_id == context.organization_id,
            )
        ).all()
        seed_rules = [
            TargetRule(
                target_type=cast(TargetType, seed.seed_type),
                canonical_value=seed.canonical_value,
                match_mode=cast(MatchMode, seed.match_mode),
            )
            for seed in seeds
        ]

        # 10. An exact or explicitly included target is required.
        if not any(
            target_matches(rule, normalized_target.target_type, normalized_target.raw_value)
            for rule in seed_rules
        ):
            return self._decision(
                request,
                allowed=False,
                reason_code="TARGET_OUT_OF_SCOPE",
                policy_hash=envelope.policy_hash,
            )

        exclusions = self.session.scalars(
            select(ScopeExclusion).where(
                ScopeExclusion.scope_version_id == version.id,
                ScopeExclusion.organization_id == context.organization_id,
            )
        ).all()
        exclusion_rules = [
            TargetRule(
                target_type=cast(TargetType, exclusion.exclusion_type),
                canonical_value=exclusion.canonical_value,
                match_mode=cast(MatchMode, exclusion.match_mode),
            )
            for exclusion in exclusions
        ]

        # 11. Exclusions have precedence over inclusions.
        if any(
            target_matches(rule, normalized_target.target_type, normalized_target.raw_value)
            for rule in exclusion_rules
        ):
            return self._decision(
                request,
                allowed=False,
                reason_code="TARGET_EXCLUDED",
                policy_hash=envelope.policy_hash,
            )

        policy = self.session.scalar(
            select(ScanPolicy).where(
                ScanPolicy.scope_version_id == version.id,
                ScanPolicy.organization_id == context.organization_id,
            )
        )
        if policy is None:
            return self._decision(
                request,
                allowed=False,
                reason_code="POLICY_MISSING",
                policy_hash=envelope.policy_hash,
            )

        # 12-14. Apply protocol, IANA schedule, and rate/concurrency constraints.
        policy_decision = ScanPolicyEvaluator.evaluate(
            ScanPolicySnapshot(
                allowed_protocols=tuple(policy.allowed_protocols),
                max_requests_per_second=policy.max_requests_per_second,
                max_concurrent_targets=policy.max_concurrent_targets,
                max_concurrent_requests=policy.max_concurrent_requests,
                schedule_timezone=policy.schedule_timezone,
                schedule_windows=tuple(policy.schedule_windows),
                policy_hash=envelope.policy_hash,
            ),
            PolicyEvaluationInput(
                requested_protocol=request.operation.protocol,
                now=request.now or datetime.now(UTC),
                scope_active=True,
                approval_valid=True,
                emergency_stop_active=False,
                requests_in_current_second=request.operation.requests_in_current_second,
                concurrent_targets=request.operation.concurrent_targets,
                concurrent_requests=request.operation.concurrent_requests,
            ),
        )
        if not policy_decision.allowed:
            return self._decision(
                request,
                allowed=False,
                reason_code=policy_decision.reason_code,
                policy_hash=envelope.policy_hash,
            )

        # 15. Only this explicit success state permits a guarded transport invocation.
        return self._decision(
            request,
            allowed=True,
            reason_code="ALLOWED",
            policy_hash=envelope.policy_hash,
        )


class GuardedNetworkClient:
    def __init__(self, scope_guard: ScopeGuard, transport: NetworkTransport) -> None:
        self.scope_guard = scope_guard
        self.transport = transport

    def request(self, authorization: ScopeAuthorizationRequest) -> object:
        decision = self.scope_guard.authorize(authorization)
        if not decision.allowed:
            raise ScopeDenied(decision)
        return self.transport.request(
            target=authorization.target,
            protocol=authorization.operation.protocol,
        )
