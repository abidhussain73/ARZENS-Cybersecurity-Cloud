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
    platform_max_requests_per_second: float = Field(default=100.0, gt=0, le=10_000)
    platform_max_concurrent_targets: int = Field(default=100, ge=1, le=10_000)
    platform_max_concurrent_requests: int = Field(default=200, ge=1, le=10_000)
    discovery_checkpoint_batch_size: int = Field(default=100, ge=1, le=1_000)
    discovery_stage_lease_seconds: int = Field(default=120, ge=1, le=3_600)
    discovery_max_attempts: int = Field(default=3, ge=1, le=10)
    evidence_max_object_bytes: int = Field(default=10_485_760, ge=1, le=1_073_741_824)
    evidence_signed_url_ttl_seconds: int = Field(default=300, ge=1, le=300)
    exposure_evaluation_interval: int = Field(default=3_600, ge=60, le=604_800)
    snapshot_interval: int = Field(default=3_600, ge=60, le=604_800)
    change_detection_interval: int = Field(default=3_600, ge=60, le=604_800)
    exception_expiry_interval: int = Field(default=3_600, ge=60, le=604_800)
    objectstore_server_side_encryption: str | None = None


@lru_cache
def get_settings() -> Settings:
    settings_factory = cast(Callable[[], Settings], Settings)
    return settings_factory()
