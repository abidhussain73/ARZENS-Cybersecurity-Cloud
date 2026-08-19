"""Deterministic local-only identity and organization fixtures for Phase 1 acceptance tests."""

from __future__ import annotations

import uuid

from sqlalchemy import select

from .db import SessionLocal
from .models import Membership, Organization, User

ORG_A_ID = uuid.UUID("e3601000-0000-4000-8000-000000000001")
ORG_B_ID = uuid.UUID("e3601000-0000-4000-8000-000000000002")
ALICE_SUBJECT = "e3600000-0000-4000-8000-000000000001"
BOB_SUBJECT = "e3600000-0000-4000-8000-000000000002"
COORDINATOR_SUBJECT = "e3600000-0000-4000-8000-000000000003"


def _get_or_create_user(subject: str, name: str, email: str) -> User:
    with SessionLocal() as session:
        user = session.scalar(select(User).where(User.oidc_subject == subject))
        if user is None:
            user = User(oidc_subject=subject, display_name=name, email=email, is_active=True)
            session.add(user)
            session.commit()
            session.refresh(user)
        return user


def seed_phase1_fixtures() -> None:
    """Create only the deterministic Phase 1 users, organizations, and memberships."""
    users = {
        ALICE_SUBJECT: _get_or_create_user(ALICE_SUBJECT, "Alice Local", "alice@local.invalid"),
        BOB_SUBJECT: _get_or_create_user(BOB_SUBJECT, "Bob Local", "bob@local.invalid"),
        COORDINATOR_SUBJECT: _get_or_create_user(
            COORDINATOR_SUBJECT, "Coordinator Local", "coordinator@local.invalid"
        ),
    }
    with SessionLocal() as session:
        organizations = (
            (ORG_A_ID, "ORG-A", "org-a"),
            (ORG_B_ID, "ORG-B", "org-b"),
        )
        for organization_id, name, slug in organizations:
            organization = session.get(Organization, organization_id)
            if organization is None:
                session.add(Organization(id=organization_id, name=name, slug=slug, is_active=True))
        session.flush()

        memberships = (
            (ORG_A_ID, users[ALICE_SUBJECT].id, "analyst"),
            (ORG_B_ID, users[BOB_SUBJECT].id, "analyst"),
            (ORG_A_ID, users[COORDINATOR_SUBJECT].id, "owner"),
            (ORG_B_ID, users[COORDINATOR_SUBJECT].id, "owner"),
        )
        for organization_id, user_id, role in memberships:
            membership = session.scalar(
                select(Membership).where(
                    Membership.organization_id == organization_id,
                    Membership.user_id == user_id,
                )
            )
            if membership is None:
                session.add(
                    Membership(
                        organization_id=organization_id,
                        user_id=user_id,
                        role=role,
                        is_active=True,
                    )
                )
        session.commit()


if __name__ == "__main__":
    seed_phase1_fixtures()
