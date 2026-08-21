from types import SimpleNamespace

from exposure360_api import auth


def test_oidc_verifier_uses_private_jwks_without_public_discovery(
    monkeypatch: object,
) -> None:
    captured: dict[str, str] = {}

    def fail_discovery(*_: object, **__: object) -> None:
        raise AssertionError(
            "public issuer discovery must not run when a private JWKS URL is configured"
        )

    def fake_jwks_client(url: str, **_: object) -> SimpleNamespace:
        captured["url"] = url
        return SimpleNamespace()

    monkeypatch.setattr(auth.httpx, "get", fail_discovery)
    monkeypatch.setattr(auth, "PyJWKClient", fake_jwks_client)

    auth.OidcVerifier(
        "https://gateway.example.test/realms/exposure360",
        "exposure360-api",
        "http://identity:8080/realms/exposure360/protocol/openid-connect/certs",
    )

    assert captured["url"].startswith("http://identity:8080/")
