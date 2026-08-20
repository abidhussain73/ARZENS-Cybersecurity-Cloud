"""Run an isolated, fixture-only Phase 3 acceptance scenario against the configured database."""

import json
import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, sessionmaker

from exposure360_api.db import engine
from exposure360_api.discovery_contracts import DiscoveryStageName
from exposure360_api.discovery_orchestration import DiscoveryJobService, DiscoveryJobWorker
from exposure360_api.models import (
    CandidateAsset,
    DiscoveryCheckpoint,
    DiscoveryJob,
    DiscoveryJobStage,
    DiscoverySource,
    Membership,
    Organization,
    ScanPolicy,
    Scope,
    ScopeApproval,
    ScopeSeed,
    ScopeVersion,
    User,
)
from exposure360_api.scope_approval import ScopeApprovalService


def _cleanup(session: Session, organization_id: uuid.UUID, user_id: uuid.UUID) -> None:
    session.rollback()
    tables = [
        "audit_events",
        "collection_attempts",
        "candidate_observations",
        "candidate_assets",
        "discovery_checkpoints",
        "discovery_job_events",
        "dead_letter_items",
        "discovery_job_stages",
        "discovery_jobs",
        "discovery_sources",
        "emergency_stop_states",
        "scope_approvals",
        "scan_policies",
        "scope_exclusions",
        "scope_seeds",
        "scope_versions",
        "scopes",
        "memberships",
        "organizations",
    ]
    for table in tables:
        column = "id" if table == "organizations" else "organization_id"
        session.execute(
            text(f"DELETE FROM {table} WHERE {column} = :organization_id"),
            {"organization_id": organization_id},
        )
    session.execute(text("DELETE FROM users WHERE id = :user_id"), {"user_id": user_id})
    session.commit()


def main() -> None:
    token = uuid.uuid4().hex
    organization_id = uuid.uuid4()
    user_id = uuid.uuid4()
    now = datetime.now(UTC)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = session_factory()
    try:
        user = User(
            id=user_id,
            oidc_subject=f"phase3-aws-fixture-{token}",
            email=f"phase3-aws-fixture-{token}@example.test",
            display_name="Phase 3 AWS fixture",
        )
        organization = Organization(
            id=organization_id,
            name="Phase 3 AWS fixture acceptance",
            slug=f"phase3-fixture-{token[:20]}",
        )
        scope = Scope(
            id=uuid.uuid4(),
            organization_id=organization_id,
            name="Reserved documentation fixture scope",
            status="ACTIVE",
            created_by_user_id=user_id,
        )
        version = ScopeVersion(
            id=uuid.uuid4(),
            organization_id=organization_id,
            scope_id=scope.id,
            version_number=1,
            state="APPROVED",
            created_by_user_id=user_id,
            content_hash="",
        )
        session.add_all([user, organization])
        session.commit()
        session.add_all(
            [
                Membership(
                    id=uuid.uuid4(),
                    organization_id=organization_id,
                    user_id=user_id,
                    role="admin",
                    is_active=True,
                ),
                scope,
            ]
        )
        session.commit()
        session.add(version)
        session.commit()
        session.add_all(
            [
                ScopeSeed(
                    id=uuid.uuid4(),
                    organization_id=organization_id,
                    scope_version_id=version.id,
                    seed_type="DOMAIN",
                    raw_value="example.com",
                    canonical_value="example.com",
                    match_mode="DOMAIN_AND_SUBDOMAINS",
                ),
                ScanPolicy(
                    id=uuid.uuid4(),
                    organization_id=organization_id,
                    scope_version_id=version.id,
                    allowed_protocols=["DNS"],
                    max_requests_per_second=1.0,
                    max_concurrent_targets=1,
                    max_concurrent_requests=1,
                    schedule_timezone="UTC",
                    schedule_windows=[],
                    connect_timeout_seconds=1,
                    request_timeout_seconds=1,
                    active_scanning_enabled=False,
                ),
                DiscoverySource(
                    id=uuid.uuid4(),
                    organization_id=organization_id,
                    source_key="fixture-passive-dns",
                    source_type="RECORDED_PASSIVE_DNS",
                    display_name="Recorded passive DNS fixture",
                    adapter_version="1.0.0",
                    configuration_reference="fixture:passive-dns-v1",
                ),
            ]
        )
        session.commit()
        content_hash = ScopeApprovalService.content_hash(session, version)
        version.content_hash = content_hash
        approval = ScopeApproval(
            id=uuid.uuid4(),
            organization_id=organization_id,
            scope_id=scope.id,
            scope_version_id=version.id,
            approved_by_user_id=user_id,
            decision="APPROVED",
            approved_at=now,
            content_hash=content_hash,
        )
        session.add(approval)
        session.commit()

        jobs = DiscoveryJobService()
        job = jobs.create_job(
            session,
            organization_id=organization_id,
            scope_id=scope.id,
            scope_version_id=version.id,
            approval_id=approval.id,
            requested_by_user_id=user_id,
            correlation_id="phase3-aws-fixture-acceptance",
        )
        session.commit()
        result = DiscoveryJobWorker(session_factory=session_factory, lease_seconds=10).run(
            organization_id=organization_id,
            job_id=job.id,
            correlation_id="phase3-aws-fixture-acceptance",
            worker_token="phase3-aws-fixture-worker",
        )

        session.expire_all()
        accepted_job = session.get(DiscoveryJob, job.id)
        candidate_count = session.scalar(
            select(func.count())
            .select_from(CandidateAsset)
            .where(CandidateAsset.organization_id == organization_id)
        )
        source_checkpoint = session.scalar(
            select(DiscoveryCheckpoint).where(
                DiscoveryCheckpoint.discovery_job_id == job.id,
                DiscoveryCheckpoint.stage == DiscoveryStageName.PASSIVE_SOURCE.value,
            )
        )
        stages = session.scalar(
            select(func.count())
            .select_from(DiscoveryJobStage)
            .where(DiscoveryJobStage.discovery_job_id == job.id)
        )
        assert result == "completed"
        assert accepted_job is not None and accepted_job.state == "COMPLETED"
        assert candidate_count is not None and candidate_count > 0
        assert source_checkpoint is not None
        assert stages == 8
        print(
            json.dumps(
                {
                    "acceptance": "PASS",
                    "candidate_count": candidate_count,
                    "job_state": accepted_job.state,
                    "stage_count": stages,
                    "worker_result": result,
                },
                sort_keys=True,
            )
        )
    finally:
        _cleanup(session, organization_id, user_id)
        session.close()


if __name__ == "__main__":
    main()
