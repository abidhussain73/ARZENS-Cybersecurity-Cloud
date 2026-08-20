import io
import uuid
from collections.abc import Generator
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from exposure360_api.auth import current_principal
from exposure360_api.db import Base, get_session
from exposure360_api.evidence_store import (
    EvidenceIntegrityStatus,
    EvidenceStoreError,
    MemoryEvidenceObjectStore,
    safe_download_filename,
    verify_integrity,
)
from exposure360_api.main import app
from exposure360_api.models import Asset, AuditEvent, Evidence, Membership, Organization, User
from exposure360_api.security import Principal


@pytest.fixture
def database_session() -> Generator[Session, None, None]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection: object, _: object) -> None:
        connection.execute("PRAGMA foreign_keys=ON")  # type: ignore[union-attr]

    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture
def api_client(
    database_session: Session,
) -> Generator[tuple[TestClient, dict[str, uuid.UUID], MemoryEvidenceObjectStore], None, None]:
    user = User(id=uuid.uuid4(), oidc_subject="evidence-viewer", email="viewer@example.test")
    organization_a = Organization(id=uuid.uuid4(), name="Evidence A", slug="evidence-a")
    organization_b = Organization(id=uuid.uuid4(), name="Evidence B", slug="evidence-b")
    database_session.add_all([user, organization_a, organization_b])
    database_session.flush()
    database_session.add_all(
        [
            Membership(
                id=uuid.uuid4(),
                organization_id=organization_a.id,
                user_id=user.id,
                role="viewer",
            ),
            Membership(
                id=uuid.uuid4(),
                organization_id=organization_b.id,
                user_id=user.id,
                role="viewer",
            ),
        ]
    )
    database_session.commit()
    stored_at = datetime(2026, 1, 20, tzinfo=UTC)
    asset = Asset(
        id=uuid.uuid4(),
        organization_id=organization_a.id,
        asset_type="DOMAIN",
        canonical_key="domain:evidence.example.test",
        display_name="evidence.example.test",
        first_seen=stored_at,
        last_seen=stored_at,
    )
    database_session.add(asset)
    database_session.flush()
    store = MemoryEvidenceObjectStore()
    stored = store.put_stream(
        organization_id=organization_a.id,
        evidence_id=uuid.uuid4(),
        collected_at=stored_at,
        stream=io.BytesIO(b'{"fixture":"evidence"}'),
        media_type="application/json",
    )
    evidence = Evidence(
        id=uuid.UUID(stored.key.split("/")[-2]),
        organization_id=organization_a.id,
        asset_id=asset.id,
        evidence_type="HTTP_METADATA",
        object_store_bucket=stored.bucket,
        object_store_key=stored.key,
        sha256=stored.sha256,
        size_bytes=stored.size_bytes,
        media_type=stored.media_type,
        encoding="utf-8",
        collected_at=stored_at,
        stored_at=stored_at,
        retention_class="STANDARD",
        sensitivity_class="INTERNAL_METADATA",
        collector_name="fixture",
        collector_version="1.0.0",
        metadata_json={},
        idempotency_key="e" * 64,
    )
    database_session.add(evidence)
    database_session.commit()

    def session_override() -> Generator[Session, None, None]:
        yield database_session

    from exposure360_api.evidence_store import get_evidence_store

    app.dependency_overrides[get_session] = session_override
    app.dependency_overrides[current_principal] = lambda: Principal(user=user)
    app.dependency_overrides[get_evidence_store] = lambda: store
    client = TestClient(app)
    try:
        identifiers = {
            "org_a": organization_a.id,
            "org_b": organization_b.id,
            "evidence": evidence.id,
        }
        yield client, identifiers, store
    finally:
        app.dependency_overrides.clear()


def _headers(organization_id: uuid.UUID) -> dict[str, str]:
    return {
        "X-Organization-ID": str(organization_id),
        "X-Correlation-ID": "evidence-store-test",
    }


def test_private_stream_write_hash_size_key_and_filename_safety() -> None:
    store = MemoryEvidenceObjectStore()
    organization_id = uuid.uuid4()
    evidence_id = uuid.uuid4()
    stored = store.put_stream(
        organization_id=organization_id,
        evidence_id=evidence_id,
        collected_at=datetime(2026, 1, 20, tzinfo=UTC),
        stream=io.BytesIO(b"evidence-bytes"),
        media_type="text/plain; charset=utf-8",
    )
    assert stored.size_bytes == len(b"evidence-bytes")
    assert stored.sha256 == "3c2cc14b5c5beb243cf6ce364e02599dadd6ebccbd186c230f9f2139209ab7be"
    assert stored.key.startswith(f"organizations/{organization_id}/evidence/2026/01/{evidence_id}/")
    assert ".." not in stored.key
    assert store.head(bucket=stored.bucket, key=stored.key) is not None
    filename = safe_download_filename("evil\r\nX-Test: 1/../../evidence")
    assert filename == "evilX-Test: 1_.._.._evidence"
    with pytest.raises(EvidenceStoreError, match="maximum size"):
        MemoryEvidenceObjectStore(max_object_bytes=3).put_stream(
            organization_id=organization_id,
            evidence_id=uuid.uuid4(),
            collected_at=datetime(2026, 1, 20, tzinfo=UTC),
            stream=io.BytesIO(b"four"),
            media_type=None,
        )


def test_integrity_detects_tamper_and_missing_object() -> None:
    store = MemoryEvidenceObjectStore()
    organization_id = uuid.uuid4()
    asset_id = uuid.uuid4()
    stored_at = datetime(2026, 1, 20, tzinfo=UTC)
    stored = store.put_stream(
        organization_id=organization_id,
        evidence_id=uuid.uuid4(),
        collected_at=stored_at,
        stream=io.BytesIO(b"original-object"),
        media_type=None,
    )
    evidence = Evidence(
        id=uuid.uuid4(),
        organization_id=organization_id,
        asset_id=asset_id,
        evidence_type="TEST",
        object_store_bucket=stored.bucket,
        object_store_key=stored.key,
        sha256=stored.sha256,
        size_bytes=stored.size_bytes,
        media_type=stored.media_type,
        encoding=None,
        collected_at=stored_at,
        stored_at=stored_at,
        retention_class="STANDARD",
        sensitivity_class="INTERNAL_METADATA",
        collector_name="fixture",
        collector_version="1.0.0",
        metadata_json={},
        idempotency_key="i" * 64,
    )
    assert verify_integrity(store, evidence).status == EvidenceIntegrityStatus.PASS
    store.replace_for_test(bucket=stored.bucket, key=stored.key, data=b"tampered")
    assert verify_integrity(store, evidence).status == EvidenceIntegrityStatus.HASH_MISMATCH
    store.remove_for_test(bucket=stored.bucket, key=stored.key)
    assert verify_integrity(store, evidence).status == EvidenceIntegrityStatus.OBJECT_MISSING


def test_authorized_metadata_download_cross_org_denial_and_audit(
    api_client: tuple[TestClient, dict[str, uuid.UUID], MemoryEvidenceObjectStore],
    database_session: Session,
) -> None:
    client, identifiers, store = api_client
    evidence_path = f"/api/v1/evidence/{identifiers['evidence']}"
    metadata = client.get(evidence_path, headers=_headers(identifiers["org_a"]))
    assert metadata.status_code == 200
    assert "object_store_key" not in metadata.json()
    download = client.post(f"{evidence_path}/download", headers=_headers(identifiers["org_a"]))
    assert download.status_code == 200
    assert download.json()["method"] == "presigned_url"
    assert store.download_reference_calls == 1
    assert (
        database_session.scalar(
            select(func.count(AuditEvent.id)).where(
                AuditEvent.action == "evidence.download_authorized"
            )
        )
        == 1
    )
    denied_metadata = client.get(evidence_path, headers=_headers(identifiers["org_b"]))
    denied_download = client.post(
        f"{evidence_path}/download",
        headers=_headers(identifiers["org_b"]),
    )
    assert denied_metadata.status_code == 404
    assert denied_download.status_code == 404
    assert store.download_reference_calls == 1
