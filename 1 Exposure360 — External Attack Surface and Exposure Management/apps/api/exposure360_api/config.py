from collections.abc import Callable
from functools import lru_cache
from typing import Literal, cast

from pydantic import AnyHttpUrl, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    app_env: Literal["local", "test", "production"] = "local"
    app_base_url: AnyHttpUrl
    database_url: str = Field(min_length=12)
    redis_url: str = Field(min_length=12)
    objectstore_endpoint: AnyHttpUrl
    objectstore_bucket: str = Field(min_length=1)
    objectstore_access_key: str = Field(min_length=1)
    objectstore_secret_key: str = Field(min_length=1)
    oidc_issuer_url: AnyHttpUrl
    oidc_client_id: str = Field(min_length=1)
    oidc_client_secret: str = Field(min_length=1)
    oidc_audience: str = Field(min_length=1)
    otel_exporter_otlp_endpoint: AnyHttpUrl
    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    settings_factory = cast(Callable[[], Settings], Settings)
    return settings_factory()
