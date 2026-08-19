import os

_TEST_ENVIRONMENT = {
    "APP_ENV": "test",
    "APP_BASE_URL": "http://localhost:8080",
    "DATABASE_URL": "postgresql+psycopg://exposure360:local@localhost:5432/exposure360",
    "REDIS_URL": "redis://localhost:6379/0",
    "OBJECTSTORE_ENDPOINT": "http://localhost:9000",
    "OBJECTSTORE_BUCKET": "exposure360",
    "OBJECTSTORE_ACCESS_KEY": "test-access-key",
    "OBJECTSTORE_SECRET_KEY": "test-secret-key",
    "OIDC_ISSUER_URL": "http://localhost:8081/realms/exposure360",
    "OIDC_CLIENT_ID": "exposure360-web",
    "OIDC_CLIENT_SECRET": "test-client-secret",
    "OIDC_AUDIENCE": "exposure360-api",
    "OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4318",
    "LOG_LEVEL": "INFO",
}

for name, value in _TEST_ENVIRONMENT.items():
    os.environ[name] = value
