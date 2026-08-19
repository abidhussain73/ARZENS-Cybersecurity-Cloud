from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from exposure360_api.candidate_reconciliation import CandidateReconciliationService
from exposure360_api.certificate_source import RecordedCertificateMetadataAdapter
from exposure360_api.db import Base
from exposure360_api.discovery_contracts import CandidateAssetContract, CandidateType
from exposure360_api.discovery_sources import ScopeSourceContext
from exposure360_api.models import (
    CandidateAsset,
    CandidateObservation,
    DiscoverySource,
    Organization,
    Scope,
    ScopeApproval,
    ScopeVersion,
    User,
)
from exposure360_api.scope_governance import TargetRule


@pytest.fixture
def database_session() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _seed_scope_context(session: Session) -> tuple[UUID, UUID, UUID, UUID, UUID]:
    user = User(id=uuid4(), oidc_subject=f"reconcile-{uuid4()}")
    organization = Organization(
        id=uuid4(), name="Candidate Org", slug=f"candidate-{uuid4().hex[:8]}"
    )
    scope = Scope(
        id=uuid4(),
        organization_id=organization.id,
        name="Candidate scope",
        status="ACTIVE",
        created_by_user_id=user.id,
    )
    version = ScopeVersion(
        id=uuid4(),
        scope_id=scope.id,
        organization_id=organization.id,
        version_number=1,
        state="APPROVED",
        created_by_user_id=user.id,
        content_hash="a" * 64,
    )
    approval = ScopeApproval(
        id=uuid4(),
        organization_id=organization.id,
        scope_id=scope.id,
        scope_version_id=version.id,
        approved_by_user_id=user.id,
        decision="APPROVED",
        content_hash="a" * 64,
    )
    source = DiscoverySource(
        id=uuid4(),
        organization_id=organization.id,
        source_key="fixture-passive-dns",
        source_type="RECORDED_PASSIVE_DNS",
        display_name="Recorded Passive DNS",
        adapter_version="1.0.0",
    )
    session.add_all([user, organization, scope, version, approval, source])
    session.commit()
    return organization.id, scope.id, version.id, approval.id, source.id


def _candidate_contract(
    organization_id: UUID,
    scope_id: UUID,
    version_id: UUID,
    approval_id: UUID,
    *,
    source_key: str,
    source_record_key: str,
    category: str,
) -> CandidateAssetContract:
    return CandidateAssetContract(
        organization_id=organization_id,
        scope_id=scope_id,
        scope_version_id=version_id,
        scope_approval_id=approval_id,
        candidate_type=CandidateType.DOMAIN,
        raw_value="WWW.Example.COM.",
        canonical_value="www.example.com",
        source_key=source_key,
        source_record_key=source_record_key,
        observed_at=datetime(2026, 1, 15, tzinfo=UTC),
        metadata={"evidence_category": category},
    )


def test_reconciliation_collapses_duplicate_candidate_and_preserves_observation(
    database_session: Session,
) -> None:
    org_id, scope_id, version_id, approval_id, source_id = _seed_scope_context(database_session)
    source = database_session.get(DiscoverySource, source_id)
    assert source is not None
    contract = _candidate_contract(
        org_id,
        scope_id,
        version_id,
        approval_id,
        source_key=source.source_key,
        source_record_key="passive-001",
        category="passive_dns",
    )
    service = CandidateReconciliationService(clock=lambda: datetime(2026, 1, 16, tzinfo=UTC))

    first = service.ingest(
        database_session, source=source, contracts=[contract], payload_hash="b" * 64
    )
    replay = service.ingest(
        database_session, source=source, contracts=[contract], payload_hash="b" * 64
    )
    database_session.commit()

    assert first[0].observation_created
    assert not replay[0].observation_created
    assert database_session.scalar(select(func.count()).select_from(CandidateAsset)) == 1
    assert database_session.scalar(select(func.count()).select_from(CandidateObservation)) == 1
    assert replay[0].confidence_score == pytest.approx(0.60)


def test_reconciliation_preserves_two_sources_and_combines_confidence_deterministically(
    database_session: Session,
) -> None:
    org_id, scope_id, version_id, approval_id, source_id = _seed_scope_context(database_session)
    source = database_session.get(DiscoverySource, source_id)
    assert source is not None
    certificate_source = DiscoverySource(
        id=uuid4(),
        organization_id=org_id,
        source_key="fixture-certificate-metadata",
        source_type="CERTIFICATE_METADATA_IMPORT",
        display_name="Recorded Certificate Metadata",
        adapter_version="1.0.0",
    )
    database_session.add(certificate_source)
    database_session.commit()
    service = CandidateReconciliationService()

    passive = _candidate_contract(
        org_id,
        scope_id,
        version_id,
        approval_id,
        source_key=source.source_key,
        source_record_key="passive-001",
        category="passive_dns",
    )
    certificate = _candidate_contract(
        org_id,
        scope_id,
        version_id,
        approval_id,
        source_key=certificate_source.source_key,
        source_record_key="certificate-001",
        category="certificate_metadata",
    )

    service.ingest(database_session, source=source, contracts=[passive], payload_hash="c" * 64)
    result = service.ingest(
        database_session,
        source=certificate_source,
        contracts=[certificate],
        payload_hash="d" * 64,
    )
    database_session.commit()

    assert database_session.scalar(select(func.count()).select_from(CandidateAsset)) == 1
    assert database_session.scalar(select(func.count()).select_from(CandidateObservation)) == 2
    assert result[0].confidence_score == pytest.approx(0.86)
    assert result[0].confidence_factors == (
        {"source": "certificate_metadata", "weight": 0.65},
        {"source": "passive_dns", "weight": 0.60},
    )


def test_certificate_adapter_output_persists_candidate_observation_provenance(
    database_session: Session,
) -> None:
    org_id, scope_id, version_id, approval_id, _ = _seed_scope_context(database_session)
    certificate_source = DiscoverySource(
        id=uuid4(),
        organization_id=org_id,
        source_key="fixture-certificate-metadata",
        source_type="CERTIFICATE_METADATA_IMPORT",
        display_name="Recorded Certificate Metadata",
        adapter_version="1.0.0",
    )
    database_session.add(certificate_source)
    database_session.commit()
    adapter = RecordedCertificateMetadataAdapter(
        [
            {
                "certificate_id": "fixture-cert-001",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2026-04-01T00:00:00Z",
                "subject_cn": "www.example.com",
                "dns_names": ["www.example.com"],
                "issuer": "Fixture CA",
                "observed_at": "2026-01-15T00:00:00Z",
            }
        ]
    )
    context = ScopeSourceContext(
        organization_id=org_id,
        scope_id=scope_id,
        scope_version_id=version_id,
        scope_approval_id=approval_id,
        included_rules=(TargetRule("DOMAIN", "example.com", "DOMAIN_AND_SUBDOMAINS"),),
        exclusion_rules=(),
    )
    batch = adapter.collect(context, None)
    normalized = adapter.normalize(context, batch.records[0])
    result = CandidateReconciliationService().ingest(
        database_session,
        source=certificate_source,
        contracts=[normalized.candidates[0]],
        payload_hash=batch.records[0].payload_hash,
    )
    database_session.commit()

    observation = database_session.scalar(
        select(CandidateObservation).where(
            CandidateObservation.candidate_id == result[0].candidate_id
        )
    )
    assert observation is not None
    assert observation.source_id == certificate_source.id
    assert observation.source_record_key == "fixture-cert-001"
    assert observation.payload_hash == batch.records[0].payload_hash
    assert observation.observed_at.replace(tzinfo=UTC) == datetime(2026, 1, 15, tzinfo=UTC)
    assert observation.normalized_metadata_json["evidence_category"] == "certificate_metadata"
    assert observation.normalized_metadata_json["issuer"] == "Fixture CA"


def test_reconciliation_identity_is_isolated_by_organization_and_scope_version(
    database_session: Session,
) -> None:
    first = _seed_scope_context(database_session)
    second = _seed_scope_context(database_session)
    first_source = database_session.get(DiscoverySource, first[4])
    second_source = database_session.get(DiscoverySource, second[4])
    assert first_source is not None
    assert second_source is not None
    service = CandidateReconciliationService()

    service.ingest(
        database_session,
        source=first_source,
        contracts=[
            _candidate_contract(
                *first[:4],
                source_key=first_source.source_key,
                source_record_key="one",
                category="passive_dns",
            )
        ],
        payload_hash="e" * 64,
    )
    service.ingest(
        database_session,
        source=second_source,
        contracts=[
            _candidate_contract(
                *second[:4],
                source_key=second_source.source_key,
                source_record_key="two",
                category="passive_dns",
            )
        ],
        payload_hash="f" * 64,
    )
    database_session.commit()

    assert database_session.scalar(select(func.count()).select_from(CandidateAsset)) == 2


def test_concurrent_candidate_identity_insert_leaves_one_authoritative_row(tmp_path: Path) -> None:
    database_path = tmp_path / "candidate-concurrency.db"
    engine = create_engine(
        f"sqlite+pysqlite:///{database_path}",
        connect_args={"check_same_thread": False, "timeout": 5},
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    try:
        org_id, scope_id, version_id, approval_id, _ = _seed_scope_context(session)
        candidate_id = uuid4()
        values = {
            "id": candidate_id,
            "organization_id": org_id,
            "scope_id": scope_id,
            "scope_version_id": version_id,
            "scope_approval_id": approval_id,
            "candidate_type": "DOMAIN",
            "raw_value": "www.example.com",
            "canonical_value": "www.example.com",
            "first_discovered_at": datetime(2026, 1, 15, tzinfo=UTC),
            "last_discovered_at": datetime(2026, 1, 15, tzinfo=UTC),
            "confidence_score": 0.0,
            "confidence_model_version": "candidate-confidence-v1",
            "confidence_factors_json": [],
            "state": "DISCOVERED",
            "metadata_json": {},
        }

        def insert_candidate() -> None:
            with engine.begin() as connection:
                connection.execute(
                    sqlite_insert(CandidateAsset)
                    .values(**values)
                    .on_conflict_do_nothing(
                        index_elements=[
                            "organization_id",
                            "scope_version_id",
                            "candidate_type",
                            "canonical_value",
                        ]
                    )
                )

        with ThreadPoolExecutor(max_workers=2) as executor:
            list(executor.map(lambda _: insert_candidate(), range(2)))

        count = session.scalar(
            select(func.count())
            .select_from(CandidateAsset)
            .where(
                CandidateAsset.organization_id == org_id,
                CandidateAsset.scope_version_id == version_id,
                CandidateAsset.canonical_value == "www.example.com",
            )
        )
        assert count == 1
    finally:
        session.close()
        engine.dispose()
