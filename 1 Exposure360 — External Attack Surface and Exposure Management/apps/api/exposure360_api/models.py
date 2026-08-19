import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    oidc_subject: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255))
    slug: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (
        UniqueConstraint("organization_id", "user_id", name="uq_membership_org_user"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    role: Mapped[str] = mapped_column(String(32))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True, index=True
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    action: Mapped[str] = mapped_column(String(128))
    resource_type: Mapped[str] = mapped_column(String(128))
    resource_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    correlation_id: Mapped[str] = mapped_column(String(64), index=True)
    trace_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    result: Mapped[str] = mapped_column(String(32))
    metadata_json: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Scope(Base):
    __tablename__ = "scopes"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_scope_id_org"),
        CheckConstraint("status IN ('ACTIVE', 'DISABLED', 'ARCHIVED')", name="ck_scope_status"),
        Index("ix_scopes_org_status", "organization_id", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE")
    created_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    disabled_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ScopeVersion(Base):
    __tablename__ = "scope_versions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["scope_id", "organization_id"],
            ["scopes.id", "scopes.organization_id"],
            name="fk_scope_version_scope_org",
        ),
        UniqueConstraint("id", "organization_id", name="uq_scope_version_id_org"),
        UniqueConstraint("id", "scope_id", "organization_id", name="uq_scope_version_id_scope_org"),
        UniqueConstraint("scope_id", "version_number", name="uq_scope_version_number"),
        CheckConstraint(
            "state IN ('DRAFT', 'SUBMITTED', 'APPROVED', 'REJECTED', 'SUPERSEDED')",
            name="ck_scope_version_state",
        ),
        Index("ix_scope_versions_org_state", "organization_id", "state"),
        Index(
            "uq_scope_versions_one_approved",
            "scope_id",
            unique=True,
            postgresql_where="state = 'APPROVED'",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scope_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    version_number: Mapped[int] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(16), default="DRAFT")
    change_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    supersedes_version_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scope_versions.id"), nullable=True
    )
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ScopeSeed(Base):
    __tablename__ = "scope_seeds"
    __table_args__ = (
        ForeignKeyConstraint(
            ["scope_version_id", "organization_id"],
            ["scope_versions.id", "scope_versions.organization_id"],
            name="fk_scope_seed_version_org",
        ),
        UniqueConstraint(
            "scope_version_id", "seed_type", "canonical_value", "match_mode", name="uq_scope_seed"
        ),
        CheckConstraint("seed_type IN ('DOMAIN', 'CIDR', 'IP', 'ASN')", name="ck_scope_seed_type"),
        CheckConstraint(
            "match_mode IN ('EXACT', 'DOMAIN_AND_SUBDOMAINS')", name="ck_scope_seed_match_mode"
        ),
        Index(
            "ix_scope_seeds_version_type_value",
            "scope_version_id",
            "seed_type",
            "canonical_value",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scope_version_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    seed_type: Mapped[str] = mapped_column(String(16))
    raw_value: Mapped[str] = mapped_column(Text)
    canonical_value: Mapped[str] = mapped_column(String(320))
    match_mode: Mapped[str] = mapped_column(String(32), default="EXACT")
    metadata_json: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ScopeExclusion(Base):
    __tablename__ = "scope_exclusions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["scope_version_id", "organization_id"],
            ["scope_versions.id", "scope_versions.organization_id"],
            name="fk_scope_exclusion_version_org",
        ),
        UniqueConstraint(
            "scope_version_id",
            "exclusion_type",
            "canonical_value",
            "match_mode",
            name="uq_scope_exclusion",
        ),
        CheckConstraint(
            "exclusion_type IN ('DOMAIN', 'CIDR', 'IP', 'ASN')", name="ck_scope_exclusion_type"
        ),
        CheckConstraint(
            "match_mode IN ('EXACT', 'DOMAIN_AND_SUBDOMAINS')",
            name="ck_scope_exclusion_match_mode",
        ),
        Index(
            "ix_scope_exclusions_version_type_value",
            "scope_version_id",
            "exclusion_type",
            "canonical_value",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scope_version_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    exclusion_type: Mapped[str] = mapped_column(String(16))
    raw_value: Mapped[str] = mapped_column(Text)
    canonical_value: Mapped[str] = mapped_column(String(320))
    match_mode: Mapped[str] = mapped_column(String(32), default="EXACT")
    reason: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ScanPolicy(Base):
    __tablename__ = "scan_policies"
    __table_args__ = (
        ForeignKeyConstraint(
            ["scope_version_id", "organization_id"],
            ["scope_versions.id", "scope_versions.organization_id"],
            name="fk_scan_policy_version_org",
        ),
        UniqueConstraint("scope_version_id", name="uq_scan_policy_version"),
        CheckConstraint("max_requests_per_second > 0", name="ck_policy_positive_rate"),
        CheckConstraint("max_concurrent_targets > 0", name="ck_policy_positive_targets"),
        CheckConstraint("max_concurrent_requests > 0", name="ck_policy_positive_requests"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scope_version_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    allowed_protocols: Mapped[list[str]] = mapped_column(JSON, default=list)
    max_requests_per_second: Mapped[float] = mapped_column(Float)
    max_concurrent_targets: Mapped[int] = mapped_column(Integer)
    max_concurrent_requests: Mapped[int] = mapped_column(Integer)
    schedule_timezone: Mapped[str] = mapped_column(String(64), default="UTC")
    schedule_windows: Mapped[list[dict[str, object]]] = mapped_column(JSON, default=list)
    connect_timeout_seconds: Mapped[int] = mapped_column(Integer, default=10)
    request_timeout_seconds: Mapped[int] = mapped_column(Integer, default=30)
    active_scanning_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ScopeApproval(Base):
    __tablename__ = "scope_approvals"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_scope_approval_id_org"),
        ForeignKeyConstraint(
            ["scope_version_id", "scope_id", "organization_id"],
            ["scope_versions.id", "scope_versions.scope_id", "scope_versions.organization_id"],
            name="fk_scope_approval_version_scope_org",
        ),
        CheckConstraint("decision IN ('APPROVED', 'REJECTED')", name="ck_scope_approval_decision"),
        Index("ix_scope_approvals_version_decision", "scope_version_id", "decision"),
        Index("ix_scope_approvals_expires", "expires_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    scope_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    scope_version_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    approved_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    decision: Mapped[str] = mapped_column(String(16))
    decision_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    approved_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    content_hash: Mapped[str] = mapped_column(String(64))


class EmergencyStopState(Base):
    __tablename__ = "emergency_stop_states"
    __table_args__ = (
        ForeignKeyConstraint(
            ["scope_id", "organization_id"],
            ["scopes.id", "scopes.organization_id"],
            name="fk_stop_state_scope_org",
        ),
        CheckConstraint("level IN ('ORGANIZATION', 'SCOPE')", name="ck_stop_state_level"),
        CheckConstraint(
            "(level = 'ORGANIZATION' AND scope_id IS NULL) "
            "OR (level = 'SCOPE' AND scope_id IS NOT NULL)",
            name="ck_stop_state_scope_shape",
        ),
        Index(
            "uq_org_stop_state",
            "organization_id",
            unique=True,
            postgresql_where="level = 'ORGANIZATION'",
        ),
        Index(
            "uq_scope_stop_state",
            "scope_id",
            unique=True,
            postgresql_where="level = 'SCOPE'",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    scope_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    level: Mapped[str] = mapped_column(String(16))
    is_stopped: Mapped[bool] = mapped_column(Boolean, default=False)
    stop_generation: Mapped[int] = mapped_column(Integer, default=0)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    stopped_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    resumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resumed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class DiscoverySource(Base):
    __tablename__ = "discovery_sources"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_discovery_source_id_org"),
        UniqueConstraint("organization_id", "source_key", name="uq_discovery_source_org_key"),
        CheckConstraint(
            "source_type IN ('RECORDED_PASSIVE_DNS', 'CERTIFICATE_METADATA_IMPORT', "
            "'PASSIVE_DNS_PROVIDER')",
            name="ck_discovery_source_type",
        ),
        CheckConstraint(
            "health_state IN ('HEALTHY', 'DEGRADED', 'UNAVAILABLE', 'MISCONFIGURED')",
            name="ck_discovery_source_health",
        ),
        Index("ix_discovery_sources_org_enabled", "organization_id", "enabled"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    source_key: Mapped[str] = mapped_column(String(128))
    source_type: Mapped[str] = mapped_column(String(64))
    display_name: Mapped[str] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    adapter_version: Mapped[str] = mapped_column(String(64))
    configuration_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    health_state: Mapped[str] = mapped_column(String(32), default="HEALTHY")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class DiscoveryJob(Base):
    __tablename__ = "discovery_jobs"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_discovery_job_id_org"),
        ForeignKeyConstraint(
            ["scope_version_id", "scope_id", "organization_id"],
            ["scope_versions.id", "scope_versions.scope_id", "scope_versions.organization_id"],
            name="fk_discovery_job_scope_version_org",
        ),
        ForeignKeyConstraint(
            ["scope_approval_id", "organization_id"],
            ["scope_approvals.id", "scope_approvals.organization_id"],
            name="fk_discovery_job_approval_org",
        ),
        CheckConstraint(
            "state IN ('QUEUED', 'RUNNING', 'PARTIAL', 'DEGRADED', 'COMPLETED', "
            "'CANCELLING', 'CANCELLED', 'FAILED')",
            name="ck_discovery_job_state",
        ),
        Index("ix_discovery_jobs_org_state_created", "organization_id", "state", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    scope_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    scope_version_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    scope_approval_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    scope_content_hash: Mapped[str] = mapped_column(String(64))
    scan_policy_hash: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(16), default="QUEUED")
    requested_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    cancel_requested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    cancel_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    cancel_generation: Mapped[int] = mapped_column(Integer, default=0)
    progress_total: Mapped[int | None] = mapped_column(Integer, nullable=True)
    progress_completed: Mapped[int] = mapped_column(Integer, default=0)
    progress_failed: Mapped[int] = mapped_column(Integer, default=0)
    progress_skipped: Mapped[int] = mapped_column(Integer, default=0)
    progress_queued: Mapped[int] = mapped_column(Integer, default=0)
    progress_indeterminate: Mapped[bool] = mapped_column(Boolean, default=True)
    current_stage: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_checkpoint_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_error_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    degraded_sources_json: Mapped[list[dict[str, object]]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class DiscoveryJobStage(Base):
    __tablename__ = "discovery_job_stages"
    __table_args__ = (
        ForeignKeyConstraint(
            ["discovery_job_id", "organization_id"],
            ["discovery_jobs.id", "discovery_jobs.organization_id"],
            name="fk_discovery_stage_job_org",
        ),
        UniqueConstraint("discovery_job_id", "stage", name="uq_discovery_job_stage"),
        CheckConstraint(
            "stage IN ('PASSIVE_SOURCE', 'CERTIFICATE_IMPORT', 'CANDIDATE_RECONCILIATION', "
            "'DNS_VALIDATE', 'TCP_VALIDATE', 'TLS_METADATA', 'HTTP_METADATA', 'FINALIZE')",
            name="ck_discovery_stage_name",
        ),
        CheckConstraint(
            "state IN ('QUEUED', 'RUNNING', 'COMPLETED', 'PARTIAL', 'SKIPPED', 'FAILED', "
            "'CANCELLED')",
            name="ck_discovery_stage_state",
        ),
        Index("ix_discovery_job_stages_job_state", "discovery_job_id", "state"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    discovery_job_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    stage: Mapped[str] = mapped_column(String(32))
    state: Mapped[str] = mapped_column(String(16), default="QUEUED")
    processed_count: Mapped[int] = mapped_column(Integer, default=0)
    succeeded_count: Mapped[int] = mapped_column(Integer, default=0)
    failed_count: Mapped[int] = mapped_column(Integer, default=0)
    skipped_count: Mapped[int] = mapped_column(Integer, default=0)
    queued_count: Mapped[int] = mapped_column(Integer, default=0)
    known_total: Mapped[int | None] = mapped_column(Integer, nullable=True)
    progress_indeterminate: Mapped[bool] = mapped_column(Boolean, default=True)
    last_error_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    execution_token: Mapped[str | None] = mapped_column(String(64), nullable=True)
    execution_generation: Mapped[int] = mapped_column(Integer, default=0)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class DiscoveryCheckpoint(Base):
    __tablename__ = "discovery_checkpoints"
    __table_args__ = (
        ForeignKeyConstraint(
            ["discovery_job_id", "organization_id"],
            ["discovery_jobs.id", "discovery_jobs.organization_id"],
            name="fk_discovery_checkpoint_job_org",
        ),
        UniqueConstraint("discovery_job_id", "stage", name="uq_discovery_checkpoint_stage"),
        Index("ix_discovery_checkpoints_job_stage", "discovery_job_id", "stage"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    discovery_job_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    stage: Mapped[str] = mapped_column(String(32))
    checkpoint_schema_version: Mapped[str] = mapped_column(String(64))
    source_key: Mapped[str] = mapped_column(String(128))
    adapter_version: Mapped[str] = mapped_column(String(64))
    token_json: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class CandidateAsset(Base):
    __tablename__ = "candidate_assets"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_candidate_asset_id_org"),
        ForeignKeyConstraint(
            ["scope_version_id", "scope_id", "organization_id"],
            ["scope_versions.id", "scope_versions.scope_id", "scope_versions.organization_id"],
            name="fk_candidate_scope_version_org",
        ),
        ForeignKeyConstraint(
            ["scope_approval_id", "organization_id"],
            ["scope_approvals.id", "scope_approvals.organization_id"],
            name="fk_candidate_approval_org",
        ),
        CheckConstraint(
            "candidate_type IN ('DOMAIN', 'IP', 'ENDPOINT_HINT')", name="ck_candidate_asset_type"
        ),
        CheckConstraint(
            "state IN ('DISCOVERED', 'VALIDATED', 'UNRESOLVED', 'DENIED', 'STALE')",
            name="ck_candidate_asset_state",
        ),
        UniqueConstraint(
            "organization_id",
            "scope_version_id",
            "candidate_type",
            "canonical_value",
            name="uq_candidate_asset_identity",
        ),
        Index(
            "ix_candidate_assets_org_version_type_canonical",
            "organization_id",
            "scope_version_id",
            "candidate_type",
            "canonical_value",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    scope_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    scope_version_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    scope_approval_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    candidate_type: Mapped[str] = mapped_column(String(16))
    raw_value: Mapped[str] = mapped_column(Text)
    canonical_value: Mapped[str] = mapped_column(String(2048))
    first_discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    confidence_score: Mapped[float] = mapped_column(Float, default=0.0)
    confidence_model_version: Mapped[str] = mapped_column(
        String(64), default="candidate-confidence-v1"
    )
    confidence_factors_json: Mapped[list[dict[str, object]]] = mapped_column(JSON, default=list)
    state: Mapped[str] = mapped_column(String(16), default="DISCOVERED")
    metadata_json: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class CandidateObservation(Base):
    __tablename__ = "candidate_observations"
    __table_args__ = (
        ForeignKeyConstraint(
            ["candidate_id", "organization_id"],
            ["candidate_assets.id", "candidate_assets.organization_id"],
            name="fk_candidate_observation_candidate_org",
        ),
        ForeignKeyConstraint(
            ["source_id", "organization_id"],
            ["discovery_sources.id", "discovery_sources.organization_id"],
            name="fk_candidate_observation_source_org",
        ),
        UniqueConstraint(
            "candidate_id",
            "source_id",
            "source_record_key",
            "payload_hash",
            "observed_at",
            name="uq_candidate_observation_idempotency",
        ),
        Index("ix_candidate_observations_candidate_source", "candidate_id", "source_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    candidate_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    source_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    source_record_key: Mapped[str] = mapped_column(String(512))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    payload_hash: Mapped[str] = mapped_column(String(64))
    normalized_metadata_json: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    raw_artifact_ref: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class CollectionAttempt(Base):
    __tablename__ = "collection_attempts"
    __table_args__ = (
        ForeignKeyConstraint(
            ["discovery_job_id", "organization_id"],
            ["discovery_jobs.id", "discovery_jobs.organization_id"],
            name="fk_collection_attempt_job_org",
        ),
        ForeignKeyConstraint(
            ["candidate_id", "organization_id"],
            ["candidate_assets.id", "candidate_assets.organization_id"],
            name="fk_collection_attempt_candidate_org",
        ),
        Index("ix_collection_attempts_job_stage_result", "discovery_job_id", "stage", "result"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    discovery_job_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    candidate_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True, index=True
    )
    stage: Mapped[str] = mapped_column(String(32))
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    target_host: Mapped[str] = mapped_column(String(2048))
    target_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    attempt_number: Mapped[int] = mapped_column(Integer, default=1)
    scope_decision: Mapped[str] = mapped_column(String(16))
    result: Mapped[str] = mapped_column(String(32))
    reason_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    metadata_json: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    correlation_id: Mapped[str] = mapped_column(String(64), index=True)
    trace_id: Mapped[str | None] = mapped_column(String(64), nullable=True)


class DiscoveryJobEvent(Base):
    __tablename__ = "discovery_job_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["discovery_job_id", "organization_id"],
            ["discovery_jobs.id", "discovery_jobs.organization_id"],
            name="fk_discovery_event_job_org",
        ),
        UniqueConstraint("discovery_job_id", "event_key", name="uq_discovery_event_key"),
        Index("ix_discovery_job_events_job_created", "discovery_job_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    discovery_job_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    event_key: Mapped[str] = mapped_column(String(255))
    event_type: Mapped[str] = mapped_column(String(64))
    stage: Mapped[str | None] = mapped_column(String(32), nullable=True)
    details_json: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    correlation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    trace_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DeadLetterItem(Base):
    __tablename__ = "dead_letter_items"
    __table_args__ = (
        ForeignKeyConstraint(
            ["discovery_job_id", "organization_id"],
            ["discovery_jobs.id", "discovery_jobs.organization_id"],
            name="fk_dead_letter_job_org",
        ),
        UniqueConstraint("discovery_job_id", "operation_key", name="uq_dead_letter_operation"),
        CheckConstraint(
            "state IN ('OPEN', 'REQUEUED', 'RESOLVED', 'DISMISSED')",
            name="ck_dead_letter_state",
        ),
        Index("ix_dead_letter_items_job_state", "discovery_job_id", "state"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    discovery_job_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    candidate_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True, index=True
    )
    stage: Mapped[str] = mapped_column(String(32))
    operation_key: Mapped[str] = mapped_column(String(255))
    attempts: Mapped[int] = mapped_column(Integer)
    last_error_class: Mapped[str] = mapped_column(String(64))
    last_error_safe_message: Mapped[str] = mapped_column(String(512))
    state: Mapped[str] = mapped_column(String(16), default="OPEN")
    first_failed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_failed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
