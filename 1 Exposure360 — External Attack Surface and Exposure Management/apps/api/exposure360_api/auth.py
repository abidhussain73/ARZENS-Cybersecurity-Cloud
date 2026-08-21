from __future__ import annotations

from functools import lru_cache
from typing import Any

import httpx
import jwt
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import InvalidTokenError, PyJWKClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_session
from .models import User
from .security import Principal

_bearer_scheme = HTTPBearer(auto_error=False)


class OidcVerifier:
    """Verifies bearer tokens using the configured issuer discovery document and cached JWKS."""

    def __init__(self, issuer: str, audience: str, jwks_url: str | None = None) -> None:
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        if jwks_url is None:
            discovery_url = f"{self.issuer}/.well-known/openid-configuration"
            try:
                response = httpx.get(discovery_url, timeout=5.0)
                response.raise_for_status()
                discovery: dict[str, Any] = response.json()
            except (httpx.HTTPError, ValueError) as exc:
                raise RuntimeError("OIDC discovery is unavailable") from exc

            if discovery.get("issuer") != self.issuer:
                raise RuntimeError("OIDC discovery issuer does not match configured issuer")
            jwks_uri = discovery.get("jwks_uri")
            if not isinstance(jwks_uri, str) or not jwks_uri.startswith(("http://", "https://")):
                raise RuntimeError("OIDC discovery did not provide a valid JWKS URI")
        else:
            jwks_uri = jwks_url

        # PyJWT caches signing keys and refreshes the JWKS on an unknown key ID.
        self._jwks_client = PyJWKClient(jwks_uri, cache_keys=True, lifespan=300)

    def verify(self, token: str) -> dict[str, Any]:
        signing_key = self._jwks_client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=self.audience,
            issuer=self.issuer,
            options={"require": ["exp", "iss", "aud", "sub"], "verify_nbf": True},
        )
        return dict(claims)


@lru_cache
def get_oidc_verifier() -> OidcVerifier:
    settings = get_settings()
    jwks_url = str(settings.oidc_jwks_url) if settings.oidc_jwks_url is not None else None
    return OidcVerifier(str(settings.oidc_issuer_url), settings.oidc_audience, jwks_url)


def _safe_string_claim(claims: dict[str, Any], name: str) -> str | None:
    value = claims.get(name)
    return value if isinstance(value, str) and value.strip() else None


def current_principal(
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer_scheme),
    session: Session = Depends(get_session),
) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        claims = get_oidc_verifier().verify(credentials.credentials)
    except (InvalidTokenError, RuntimeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None

    subject = _safe_string_claim(claims, "sub")
    if subject is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid access token")

    email = _safe_string_claim(claims, "email")
    display_name = _safe_string_claim(claims, "name") or _safe_string_claim(
        claims, "preferred_username"
    )
    user = session.scalar(select(User).where(User.oidc_subject == subject))
    if user is None:
        user = User(
            oidc_subject=subject,
            email=email,
            display_name=display_name,
            is_active=True,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
    else:
        if email is not None:
            user.email = email
        if display_name is not None:
            user.display_name = display_name
        if not user.is_active:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is inactive")
        session.commit()

    return Principal(user=user)
