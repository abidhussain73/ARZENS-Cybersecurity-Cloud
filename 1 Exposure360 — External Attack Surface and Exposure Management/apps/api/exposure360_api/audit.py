from sqlalchemy.orm import Session

from .logging import redact
from .models import AuditEvent
from .security import OrganizationContext, Principal


def write_audit_event(
    session: Session,
    context: OrganizationContext,
    principal: Principal,
    *,
    action: str,
    resource_type: str,
    resource_id: str | None,
    correlation_id: str,
    result: str,
    trace_id: str | None = None,
    metadata: dict[str, object] | None = None,
) -> AuditEvent:
    event = AuditEvent(
        organization_id=context.organization_id,
        actor_user_id=principal.user.id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        correlation_id=correlation_id,
        trace_id=trace_id,
        result=result,
        metadata_json=redact(metadata or {}),
    )
    session.add(event)
    return event
