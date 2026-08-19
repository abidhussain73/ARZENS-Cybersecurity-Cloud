import os

import pytest
from pydantic import ValidationError

from exposure360_api.config import Settings


def test_missing_mandatory_configuration_fails_with_clear_field_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for field_name in Settings.model_fields:
        monkeypatch.delenv(field_name.upper(), raising=False)

    with pytest.raises(ValidationError) as exception:
        Settings()

    message = str(exception.value)
    assert "app_base_url" in message
    assert "database_url" in message
    assert "oidc_issuer_url" in message


def test_test_environment_values_are_not_relied_on_by_settings_constructor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("APP_BASE_URL", "http://localhost:8080")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://test:test@localhost:5432/test")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("OBJECTSTORE_ENDPOINT", "http://localhost:9000")
    monkeypatch.setenv("OBJECTSTORE_BUCKET", "test-bucket")
    monkeypatch.setenv("OBJECTSTORE_ACCESS_KEY", "test-access")
    monkeypatch.setenv("OBJECTSTORE_SECRET_KEY", "test-secret")
    monkeypatch.setenv("OIDC_ISSUER_URL", "http://localhost:8081/realms/test")
    monkeypatch.setenv("OIDC_CLIENT_ID", "test-client")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "test-client-secret")
    monkeypatch.setenv("OIDC_AUDIENCE", "test-api")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
    monkeypatch.setenv("LOG_LEVEL", "INFO")

    settings = Settings()

    assert settings.app_env == "test"
    assert settings.oidc_audience == "test-api"
    assert os.environ["DATABASE_URL"].startswith("postgresql+")
