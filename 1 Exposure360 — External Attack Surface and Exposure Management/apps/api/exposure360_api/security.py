import uuid
from dataclasses import dataclass

from fastapi import Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Membership, User

ROLE_ORDER = {"viewer": 0, "reviewer": 1, "analyst": 2, "admin": 3, "owner": 4}


@dataclass(frozen=True)
class Principal:
    user: User


@dataclass(frozen=True)
class OrganizationContext:
    organization_id: uuid.UUID
    membership: Membership


def require_org_context(
    session: Session, principal: Principal, organization_id: str | None
) -> OrganizationContext:
    if not organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="X-Organization-ID is required"
        )
    try:
        parsed = uuid.UUID(organization_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid organization context") from exc
    membership = session.scalar(
        select(Membership).where(
            Membership.organization_id == parsed,
            Membership.user_id == principal.user.id,
            Membership.is_active.is_(True),
        )
    )
    if membership is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Organization access denied"
        )
    return OrganizationContext(parsed, membership)


def require_role(context: OrganizationContext, *roles: str) -> None:
    if context.membership.role not in roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient organization role"
        )


def organization_header(x_organization_id: str | None = Header(default=None)) -> str | None:
    return x_organization_id
