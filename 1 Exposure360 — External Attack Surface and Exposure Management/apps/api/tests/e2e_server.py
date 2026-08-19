import os
import sys
import uuid

import uvicorn
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.insert(0, "/home/ubuntu/exposure360-phase1-foundation/apps/api")

_ENVIRONMENT = {
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
    "OTEL_SDK_DISABLED": "true",
    "LOG_LEVEL": "INFO",
}
for key, value in _ENVIRONMENT.items():
    os.environ[key] = value

from exposure360_api.auth import current_principal  # noqa: E402
from exposure360_api.db import Base, get_session  # noqa: E402
from exposure360_api.main import app  # noqa: E402
from exposure360_api.models import Membership, Organization, User  # noqa: E402
from exposure360_api.security import Principal  # noqa: E402

engine = create_engine(
    "sqlite+pysqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
Base.metadata.create_all(engine)
seed_session = SessionLocal()
fixture_user = User(id=uuid.uuid4(), oidc_subject="phase-two-browser-admin")
fixture_organization = Organization(
    id=uuid.UUID("00000000-0000-4000-8000-00000000a001"),
    name="Browser acceptance organization",
    slug="browser-acceptance-org",
)
seed_session.add_all(
    [
        fixture_user,
        fixture_organization,
        Membership(
            id=uuid.uuid4(),
            organization_id=fixture_organization.id,
            user_id=fixture_user.id,
            role="admin",
            is_active=True,
        ),
    ]
)
seed_session.commit()
seed_session.close()


def session_override():
    session: Session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


app.dependency_overrides[get_session] = session_override
app.dependency_overrides[current_principal] = lambda: Principal(user=fixture_user)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8001, log_level="warning")
