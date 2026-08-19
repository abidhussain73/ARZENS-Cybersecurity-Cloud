from __future__ import annotations

from dataclasses import dataclass

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from exposure360_api import auth
from exposure360_api.models import User


@dataclass
class FakeVerifier:
    claims: dict[str, object]

    def verify(self, token: str) -> dict[str, object]:
        if token != "valid-token":
            raise auth.InvalidTokenError("token rejected")
        return self.claims


class FakeSession:
    def __init__(self, existing_user: User | None = None) -> None:
        self.existing_user = existing_user
        self.added: list[User] = []
        self.commit_count = 0

    def scalar(self, statement: object) -> User | None:
        del statement
        return self.existing_user

    def add(self, user: User) -> None:
        self.added.append(user)

    def commit(self) -> None:
        self.commit_count += 1

    def refresh(self, user: User) -> None:
        del user


def _credentials(token: str = "valid-token") -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def test_current_principal_requires_bearer_credentials() -> None:
    with pytest.raises(HTTPException) as exception:
        auth.current_principal(None, FakeSession())
    assert exception.value.status_code == 401


def test_current_principal_bootstraps_profile_from_verified_claims(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    claims = {
        "sub": "subject-alice",
        "email": "alice@local.invalid",
        "name": "Alice Local",
    }
    monkeypatch.setattr(auth, "get_oidc_verifier", lambda: FakeVerifier(claims))
    session = FakeSession()

    principal = auth.current_principal(_credentials(), session)

    assert principal.user.oidc_subject == "subject-alice"
    assert principal.user.email == "alice@local.invalid"
    assert principal.user.display_name == "Alice Local"
    assert len(session.added) == 1
    assert session.commit_count == 1


def test_current_principal_updates_existing_profile_without_duplicate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    existing = User(
        oidc_subject="subject-alice",
        email="old@local.invalid",
        display_name="Old Name",
        is_active=True,
    )
    claims = {
        "sub": "subject-alice",
        "email": "alice@local.invalid",
        "preferred_username": "alice",
    }
    monkeypatch.setattr(auth, "get_oidc_verifier", lambda: FakeVerifier(claims))
    session = FakeSession(existing)

    principal = auth.current_principal(_credentials(), session)

    assert principal.user is existing
    assert existing.email == "alice@local.invalid"
    assert existing.display_name == "alice"
    assert session.added == []
    assert session.commit_count == 1


def test_current_principal_rejects_invalid_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(auth, "get_oidc_verifier", lambda: FakeVerifier({}))
    with pytest.raises(HTTPException) as exception:
        auth.current_principal(_credentials("invalid-token"), FakeSession())
    assert exception.value.status_code == 401
