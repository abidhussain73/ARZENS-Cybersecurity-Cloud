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
    event,
    func,
    inspect,
    text,
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


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_asset_id_org"),
        UniqueConstraint("organization_id", "canonical_key", name="uq_asset_org_canonical_key"),
        ForeignKeyConstraint(
            ["created_from_discovery_job_id", "organization_id"],
            ["discovery_jobs.id", "discovery_jobs.organization_id"],
            name="fk_asset_discovery_job_org",
        ),
        CheckConstraint(
            "asset_type IN ('DOMAIN', 'IP', 'ASN', 'ENDPOINT', 'SERVICE')",
            name="ck_asset_type",
        ),
        CheckConstraint(
            "lifecycle_state IN ('ACTIVE', 'STALE', 'RETIRED')",
            name="ck_asset_lifecycle_state",
        ),
        Index("ix_assets_org_type_last_seen", "organization_id", "asset_type", "last_seen"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    asset_type: Mapped[str] = mapped_column(String(16))
    canonical_key: Mapped[str] = mapped_column(String(2048))
    display_name: Mapped[str] = mapped_column(String(2048))
    lifecycle_state: Mapped[str] = mapped_column(String(16), default="ACTIVE")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_confirmed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_from_discovery_job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class AssetIdentifier(Base):
    __tablename__ = "asset_identifiers"
    __table_args__ = (
        ForeignKeyConstraint(
            ["asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            name="fk_asset_identifier_asset_org",
        ),
        UniqueConstraint(
            "organization_id",
            "identifier_type",
            "canonical_value",
            "asset_id",
            name="uq_asset_identifier_org_type_value_asset",
        ),
        Index("ix_asset_identifiers_org_value", "organization_id", "canonical_value"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    identifier_type: Mapped[str] = mapped_column(String(32))
    raw_value: Mapped[str] = mapped_column(Text)
    canonical_value: Mapped[str] = mapped_column(String(2048))
    is_primary: Mapped[bool] = mapped_column(Boolean, default=False)
    source: Mapped[str] = mapped_column(String(128))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DomainAsset(Base):
    __tablename__ = "domain_assets"
    __table_args__ = (
        ForeignKeyConstraint(
            ["asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            name="fk_domain_asset_asset_org",
        ),
        UniqueConstraint("organization_id", "fqdn_ascii", name="uq_domain_asset_org_fqdn"),
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    fqdn_ascii: Mapped[str] = mapped_column(String(253))
    fqdn_unicode: Mapped[str | None] = mapped_column(String(253), nullable=True)
    registrable_domain: Mapped[str | None] = mapped_column(String(253), nullable=True)


class IpAsset(Base):
    __tablename__ = "ip_assets"
    __table_args__ = (
        ForeignKeyConstraint(
            ["asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            name="fk_ip_asset_asset_org",
        ),
        UniqueConstraint("organization_id", "address", name="uq_ip_asset_org_address"),
        CheckConstraint("ip_version IN (4, 6)", name="ck_ip_asset_version"),
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    address: Mapped[str] = mapped_column(String(45))
    ip_version: Mapped[int] = mapped_column(Integer)
    is_global: Mapped[bool] = mapped_column(Boolean)
    address_class: Mapped[str] = mapped_column(String(32))


class AsnAsset(Base):
    __tablename__ = "asn_assets"
    __table_args__ = (
        ForeignKeyConstraint(
            ["asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            name="fk_asn_asset_asset_org",
        ),
        UniqueConstraint("organization_id", "asn_number", name="uq_asn_asset_org_number"),
        CheckConstraint("asn_number BETWEEN 1 AND 4294967295", name="ck_asn_asset_number"),
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    asn_number: Mapped[int] = mapped_column(Integer)
    canonical_asn: Mapped[str] = mapped_column(String(16))
    name_hint: Mapped[str | None] = mapped_column(String(255), nullable=True)


class EndpointAsset(Base):
    __tablename__ = "endpoint_assets"
    __table_args__ = (
        ForeignKeyConstraint(
            ["asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            name="fk_endpoint_asset_asset_org",
        ),
        ForeignKeyConstraint(
            ["ip_asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            name="fk_endpoint_asset_ip_org",
        ),
        UniqueConstraint(
            "organization_id",
            "ip_asset_id",
            "transport_protocol",
            "port",
            name="uq_endpoint_asset_org_socket",
        ),
        CheckConstraint("transport_protocol IN ('TCP')", name="ck_endpoint_asset_transport"),
        CheckConstraint("port BETWEEN 1 AND 65535", name="ck_endpoint_asset_port"),
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    ip_asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    transport_protocol: Mapped[str] = mapped_column(String(8))
    port: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ServiceAsset(Base):
    __tablename__ = "service_assets"
    __table_args__ = (
        ForeignKeyConstraint(
            ["asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            name="fk_service_asset_asset_org",
        ),
        ForeignKeyConstraint(
            ["endpoint_asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            name="fk_service_asset_endpoint_org",
        ),
        ForeignKeyConstraint(
            ["authority_domain_asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            name="fk_service_asset_authority_org",
        ),
        UniqueConstraint("organization_id", "service_key", name="uq_service_asset_org_key"),
        CheckConstraint(
            "service_kind IN ('HTTP', 'HTTPS', 'TLS', 'UNKNOWN_TCP')",
            name="ck_service_asset_kind",
        ),
        CheckConstraint(
            "application_protocol IN ('HTTP', 'HTTPS', 'TLS', 'UNKNOWN_TCP')",
            name="ck_service_asset_protocol",
        ),
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    endpoint_asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    service_kind: Mapped[str] = mapped_column(String(16))
    application_protocol: Mapped[str] = mapped_column(String(16))
    authority_domain_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True, index=True
    )
    service_key: Mapped[str] = mapped_column(String(2048))


class AssetFreshnessPolicy(Base):
    __tablename__ = "asset_freshness_policies"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "asset_type",
            "policy_version",
            name="uq_asset_freshness_policy_org_type_version",
        ),
        CheckConstraint(
            "asset_type IN ('DOMAIN', 'IP', 'ASN', 'ENDPOINT', 'SERVICE')",
            name="ck_asset_freshness_policy_type",
        ),
        CheckConstraint("stale_after_seconds > 0", name="ck_asset_freshness_policy_seconds"),
        Index(
            "ix_asset_freshness_policy_org_type_active",
            "organization_id",
            "asset_type",
            "is_active",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    asset_type: Mapped[str] = mapped_column(String(16))
    policy_version: Mapped[str] = mapped_column(String(64))
    stale_after_seconds: Mapped[int] = mapped_column(Integer)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class CanonicalObservation(Base):
    __tablename__ = "canonical_observations"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_canonical_observation_id_org"),
        ForeignKeyConstraint(
            ["asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            name="fk_canonical_observation_asset_org",
        ),
        ForeignKeyConstraint(
            ["discovery_job_id", "organization_id"],
            ["discovery_jobs.id", "discovery_jobs.organization_id"],
            name="fk_canonical_observation_job_org",
        ),
        ForeignKeyConstraint(
            ["candidate_id", "organization_id"],
            ["candidate_assets.id", "candidate_assets.organization_id"],
            name="fk_canonical_observation_candidate_org",
        ),
        UniqueConstraint(
            "organization_id",
            "idempotency_key",
            name="uq_canonical_observation_org_idempotency",
        ),
        CheckConstraint(
            "observation_type IN ('DNS_A', 'DNS_AAAA', 'DNS_CNAME', 'TCP_REACHABILITY', "
            "'TLS_HANDSHAKE', 'TLS_CERTIFICATE', 'HTTP_RESPONSE', "
            "'PASSIVE_DNS_ASSOCIATION', 'CERTIFICATE_METADATA', 'OWNERSHIP_ASSERTION')",
            name="ck_canonical_observation_type",
        ),
        CheckConstraint(
            "state IN ('ACCEPTED', 'QUARANTINED', 'REJECTED')",
            name="ck_canonical_observation_state",
        ),
        Index("ix_canonical_observations_asset_observed", "asset_id", "observed_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    observation_type: Mapped[str] = mapped_column(String(32))
    source_type: Mapped[str] = mapped_column(String(64))
    source_key: Mapped[str] = mapped_column(String(128))
    source_record_key: Mapped[str] = mapped_column(String(512), default="")
    source_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    discovery_job_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    candidate_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    normalized_payload_json: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    normalized_payload_hash: Mapped[str] = mapped_column(String(64))
    idempotency_key: Mapped[str] = mapped_column(String(64))
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    state: Mapped[str] = mapped_column(String(16), default="ACCEPTED")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Evidence(Base):
    __tablename__ = "evidence"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_evidence_id_org"),
        ForeignKeyConstraint(
            ["asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            name="fk_evidence_asset_org",
        ),
        ForeignKeyConstraint(
            ["observation_id", "organization_id"],
            ["canonical_observations.id", "canonical_observations.organization_id"],
            name="fk_evidence_observation_org",
        ),
        UniqueConstraint("organization_id", "idempotency_key", name="uq_evidence_org_idempotency"),
        CheckConstraint(
            "sensitivity_class IN ('PUBLIC_METADATA', 'INTERNAL_METADATA', 'RESTRICTED')",
            name="ck_evidence_sensitivity",
        ),
        Index("ix_evidence_asset_created", "asset_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    observation_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    evidence_type: Mapped[str] = mapped_column(String(64))
    object_store_bucket: Mapped[str] = mapped_column(String(255))
    object_store_key: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer)
    media_type: Mapped[str] = mapped_column(String(255))
    encoding: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_observed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    stored_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    retention_class: Mapped[str] = mapped_column(String(64))
    sensitivity_class: Mapped[str] = mapped_column(String(32))
    collector_name: Mapped[str] = mapped_column(String(128))
    collector_version: Mapped[str] = mapped_column(String(64))
    metadata_json: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    idempotency_key: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AssetOwnership(Base):
    __tablename__ = "asset_ownerships"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_asset_ownership_id_org"),
        UniqueConstraint(
            "organization_id",
            "asset_id",
            "claim_key",
            name="uq_asset_ownership_org_asset_claim",
        ),
        ForeignKeyConstraint(
            ["asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            name="fk_asset_ownership_asset_org",
        ),
        CheckConstraint(
            "owner_type IN ('TEAM', 'USER', 'BUSINESS_UNIT', 'SERVICE', 'UNKNOWN')",
            name="ck_asset_ownership_owner_type",
        ),
        CheckConstraint(
            "claim_type IN ('MANUAL', 'SOURCE_ASSERTED', 'INFERRED')",
            name="ck_asset_ownership_claim_type",
        ),
        CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="ck_asset_ownership_confidence",
        ),
        Index("ix_asset_ownerships_asset_valid", "asset_id", "valid_to"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    owner_type: Mapped[str] = mapped_column(String(32))
    owner_reference: Mapped[str] = mapped_column(String(255))
    owner_display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    claim_type: Mapped[str] = mapped_column(String(32))
    confidence: Mapped[float] = mapped_column(Float)
    source_type: Mapped[str] = mapped_column(String(64))
    claim_key: Mapped[str] = mapped_column(String(64))
    is_primary: Mapped[bool] = mapped_column(Boolean, default=False)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reason: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class OwnershipEvidenceLink(Base):
    __tablename__ = "ownership_evidence_links"
    __table_args__ = (
        ForeignKeyConstraint(
            ["ownership_id", "organization_id"],
            ["asset_ownerships.id", "asset_ownerships.organization_id"],
            name="fk_ownership_evidence_link_ownership_org",
        ),
        ForeignKeyConstraint(
            ["evidence_id", "organization_id"],
            ["evidence.id", "evidence.organization_id"],
            name="fk_ownership_evidence_link_evidence_org",
        ),
        ForeignKeyConstraint(
            ["observation_id", "organization_id"],
            ["canonical_observations.id", "canonical_observations.organization_id"],
            name="fk_ownership_evidence_link_observation_org",
        ),
        UniqueConstraint(
            "ownership_id",
            "evidence_id",
            "relationship_type",
            name="uq_ownership_evidence_link",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    ownership_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    evidence_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    observation_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    relationship_type: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class TechnologyFingerprint(Base):
    __tablename__ = "technology_fingerprints"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_technology_fingerprint_id_org"),
        UniqueConstraint(
            "organization_id",
            "fingerprint_key",
            name="uq_technology_fingerprint_org_key",
        ),
        ForeignKeyConstraint(
            ["asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            name="fk_technology_fingerprint_asset_org",
        ),
        ForeignKeyConstraint(
            ["service_asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            name="fk_technology_fingerprint_service_org",
        ),
        CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="ck_technology_fingerprint_confidence",
        ),
        CheckConstraint(
            "base_confidence >= 0 AND base_confidence <= 1",
            name="ck_technology_fingerprint_base_confidence",
        ),
        CheckConstraint(
            "version_confidence IS NULL OR (version_confidence >= 0 AND version_confidence <= 1)",
            name="ck_technology_fingerprint_version_confidence",
        ),
        Index("ix_technology_fingerprints_asset_seen", "asset_id", "last_seen"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    service_asset_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    technology_vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    technology_product: Mapped[str] = mapped_column(String(255))
    technology_category: Mapped[str] = mapped_column(String(128))
    version_value: Mapped[str | None] = mapped_column(String(255), nullable=True)
    version_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    base_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    confidence: Mapped[float] = mapped_column(Float)
    confidence_model_version: Mapped[str] = mapped_column(String(64))
    rule_id: Mapped[str] = mapped_column(String(255))
    rule_version: Mapped[int] = mapped_column(Integer)
    rule_hash: Mapped[str] = mapped_column(String(64))
    ruleset_hash: Mapped[str] = mapped_column(String(64))
    fingerprint_key: Mapped[str] = mapped_column(String(64))
    evidence_fields_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    confidence_components_json: Mapped[list[dict[str, object]]] = mapped_column(JSON, default=list)
    fingerprint_state: Mapped[str] = mapped_column(String(16), default="CONFIRMED")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class FingerprintEvidenceLink(Base):
    __tablename__ = "fingerprint_evidence_links"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "link_key",
            name="uq_fingerprint_evidence_link_org_key",
        ),
        ForeignKeyConstraint(
            ["fingerprint_id", "organization_id"],
            ["technology_fingerprints.id", "technology_fingerprints.organization_id"],
            name="fk_fingerprint_evidence_link_fingerprint_org",
        ),
        ForeignKeyConstraint(
            ["observation_id", "organization_id"],
            ["canonical_observations.id", "canonical_observations.organization_id"],
            name="fk_fingerprint_evidence_link_observation_org",
        ),
        ForeignKeyConstraint(
            ["evidence_id", "organization_id"],
            ["evidence.id", "evidence.organization_id"],
            name="fk_fingerprint_evidence_link_evidence_org",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    fingerprint_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    observation_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    link_key: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ExposureRuleVersion(Base):
    __tablename__ = "exposure_rule_versions"
    __table_args__ = (
        UniqueConstraint("rule_id", "rule_version", name="uq_exposure_rule_id_version"),
        CheckConstraint(
            "severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
            name="ck_exposure_rule_severity",
        ),
        CheckConstraint(
            "activation_state IN ('ACTIVE', 'DISABLED', 'DEPRECATED')",
            name="ck_exposure_rule_activation_state",
        ),
        CheckConstraint(
            "base_confidence >= 0 AND base_confidence <= 1",
            name="ck_exposure_rule_base_confidence",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    rule_id: Mapped[str] = mapped_column(String(255))
    rule_version: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(512))
    category: Mapped[str] = mapped_column(String(128))
    severity: Mapped[str] = mapped_column(String(16))
    base_confidence: Mapped[float] = mapped_column(Float)
    content_hash: Mapped[str] = mapped_column(String(64))
    activation_state: Mapped[str] = mapped_column(String(16))
    loaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("organization_id", "fingerprint", name="uq_finding_org_fingerprint"),
        UniqueConstraint("id", "organization_id", name="uq_finding_id_org"),
        ForeignKeyConstraint(
            ["asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            name="fk_finding_asset_org",
        ),
        ForeignKeyConstraint(
            ["service_asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            name="fk_finding_service_asset_org",
        ),
        CheckConstraint(
            "state IN ('OPEN', 'ACKNOWLEDGED', 'IN_PROGRESS', "
            "'RESOLVED_PENDING_VERIFICATION', 'CLOSED', 'EXCEPTION')",
            name="ck_finding_state",
        ),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_finding_confidence"),
        Index("ix_findings_org_state_seen", "organization_id", "state", "last_seen"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    service_asset_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    rule_id: Mapped[str] = mapped_column(String(255))
    rule_version: Mapped[int] = mapped_column(Integer)
    rule_hash: Mapped[str] = mapped_column(String(64))
    fingerprint: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(128))
    rule_severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[float] = mapped_column(Float)
    state: Mapped[str] = mapped_column(String(32), default="OPEN")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    in_progress_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_pending_verification_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    exception_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    assigned_to_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    assigned_owner_reference: Mapped[str | None] = mapped_column(String(512), nullable=True)
    exception_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    exception_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class FindingEvidenceLink(Base):
    __tablename__ = "finding_evidence_links"
    __table_args__ = (
        UniqueConstraint("organization_id", "link_key", name="uq_finding_evidence_link_org_key"),
        ForeignKeyConstraint(
            ["finding_id", "organization_id"],
            ["findings.id", "findings.organization_id"],
            name="fk_finding_evidence_link_finding_org",
        ),
        ForeignKeyConstraint(
            ["evidence_id", "organization_id"],
            ["evidence.id", "evidence.organization_id"],
            name="fk_finding_evidence_link_evidence_org",
        ),
        ForeignKeyConstraint(
            ["observation_id", "organization_id"],
            ["canonical_observations.id", "canonical_observations.organization_id"],
            name="fk_finding_evidence_link_observation_org",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    finding_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    evidence_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    observation_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    rule_id: Mapped[str] = mapped_column(String(255))
    rule_version: Mapped[int] = mapped_column(Integer)
    link_key: Mapped[str] = mapped_column(String(64))
    linked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class FindingEvaluationEvent(Base):
    __tablename__ = "finding_evaluation_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["finding_id", "organization_id"],
            ["findings.id", "findings.organization_id"],
            name="fk_finding_evaluation_finding_org",
        ),
        Index("ix_finding_evaluation_events_finding_time", "finding_id", "evaluated_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    finding_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    evaluation_run_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    rule_version: Mapped[int] = mapped_column(Integer)
    matched: Mapped[bool] = mapped_column(Boolean)
    confidence: Mapped[float] = mapped_column(Float)
    evidence_set_hash: Mapped[str] = mapped_column(String(64))
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class FindingStateEvent(Base):
    __tablename__ = "finding_state_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["finding_id", "organization_id"],
            ["findings.id", "findings.organization_id"],
            name="fk_finding_state_event_finding_org",
        ),
        Index("ix_finding_state_events_finding_time", "finding_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    finding_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    from_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    to_state: Mapped[str] = mapped_column(String(32))
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    correlation_id: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AssetSnapshot(Base):
    __tablename__ = "asset_snapshots"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_asset_snapshot_id_org"),
        UniqueConstraint(
            "asset_id", "effective_at", "snapshot_hash", name="uq_asset_snapshot_identity"
        ),
        ForeignKeyConstraint(
            ["asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            name="fk_asset_snapshot_asset_org",
        ),
        Index("ix_asset_snapshots_asset_effective", "asset_id", "effective_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    snapshot_schema_version: Mapped[int] = mapped_column(Integer)
    snapshot_hash: Mapped[str] = mapped_column(String(64))
    effective_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    source_evaluation_run_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    snapshot_json: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ChangeEvent(Base):
    __tablename__ = "change_events"
    __table_args__ = (
        UniqueConstraint("organization_id", "fingerprint", name="uq_change_event_org_fingerprint"),
        ForeignKeyConstraint(
            ["asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            name="fk_change_event_asset_org",
        ),
        ForeignKeyConstraint(
            ["from_snapshot_id", "organization_id"],
            ["asset_snapshots.id", "asset_snapshots.organization_id"],
            name="fk_change_event_from_snapshot_org",
        ),
        ForeignKeyConstraint(
            ["to_snapshot_id", "organization_id"],
            ["asset_snapshots.id", "asset_snapshots.organization_id"],
            name="fk_change_event_to_snapshot_org",
        ),
        ForeignKeyConstraint(
            ["approved_change_id", "organization_id"],
            ["approved_changes.id", "approved_changes.organization_id"],
            name="fk_change_event_approved_change_org",
        ),
        CheckConstraint(
            "change_type IN ('NEW', 'REMOVED', 'SERVICE', 'CERTIFICATE', "
            "'OWNERSHIP', 'FINGERPRINT')",
            name="ck_change_event_type",
        ),
        CheckConstraint(
            "state IN ('OBSERVED', 'EXPECTED', 'REVIEWED')", name="ck_change_event_state"
        ),
        Index("ix_change_events_org_state_seen", "organization_id", "state", "last_seen"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    change_type: Mapped[str] = mapped_column(String(16))
    fingerprint: Mapped[str] = mapped_column(String(64))
    from_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    to_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    summary: Mapped[str] = mapped_column(String(1024))
    details_json: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    state: Mapped[str] = mapped_column(String(16), default="OBSERVED")
    significance_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    significance_model_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    significance_factors_json: Mapped[list[dict[str, object]]] = mapped_column(JSON, default=list)
    approved_change_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ApprovedChange(Base):
    __tablename__ = "approved_changes"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_approved_change_id_org"),
        ForeignKeyConstraint(
            ["asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            name="fk_approved_change_asset_org",
        ),
        CheckConstraint("status IN ('ACTIVE', 'DISABLED')", name="ck_approved_change_status"),
        CheckConstraint("starts_at < ends_at", name="ck_approved_change_window"),
        Index("ix_approved_changes_org_window", "organization_id", "starts_at", "ends_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    asset_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    allowed_change_types_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    component_selector_json: Mapped[dict[str, object] | None] = mapped_column(JSON, nullable=True)
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ends_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    reason: Mapped[str] = mapped_column(Text)
    ticket_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approved_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    created_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class EvaluationRun(Base):
    __tablename__ = "evaluation_runs"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_evaluation_run_id_org"),
        CheckConstraint(
            "run_type IN ('EXPOSURE_RULE_EVALUATION', 'ASSET_SNAPSHOT_BUILD', "
            "'CHANGE_DETECTION', 'EXCEPTION_EXPIRY')",
            name="ck_evaluation_run_type",
        ),
        CheckConstraint(
            "state IN ('QUEUED', 'RUNNING', 'PARTIAL', 'COMPLETED', 'FAILED', 'CANCELLED')",
            name="ck_evaluation_run_state",
        ),
        Index("ix_evaluation_runs_org_type_state", "organization_id", "run_type", "state"),
        Index(
            "uq_evaluation_runs_one_running",
            "organization_id",
            "run_type",
            unique=True,
            postgresql_where="state = 'RUNNING'",
            sqlite_where=text("state = 'RUNNING'"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    run_type: Mapped[str] = mapped_column(String(32))
    state: Mapped[str] = mapped_column(String(16), default="QUEUED")
    ruleset_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    snapshot_schema_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    significance_model_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    assets_processed: Mapped[int] = mapped_column(Integer, default=0)
    findings_matched: Mapped[int] = mapped_column(Integer, default=0)
    findings_created: Mapped[int] = mapped_column(Integer, default=0)
    findings_updated: Mapped[int] = mapped_column(Integer, default=0)
    snapshots_created: Mapped[int] = mapped_column(Integer, default=0)
    changes_created: Mapped[int] = mapped_column(Integer, default=0)
    changes_suppressed: Mapped[int] = mapped_column(Integer, default=0)
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    last_error_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    correlation_id: Mapped[str] = mapped_column(String(64), index=True)
    trace_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ExternalContextEntity(Base):
    """A bounded non-asset graph node imported from trusted structural metadata."""

    __tablename__ = "external_context_entities"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_external_context_entity_id_org"),
        UniqueConstraint(
            "organization_id",
            "context_type",
            "canonical_key",
            name="uq_external_context_entity_org_type_key",
        ),
        CheckConstraint(
            "context_type IN ('IDENTITY', 'CLOUD_RESOURCE', 'APPLICATION', 'DATA', "
            "'VULNERABILITY')",
            name="ck_external_context_entity_type",
        ),
        CheckConstraint(
            "confidence >= 0 AND confidence <= 1", name="ck_external_context_entity_confidence"
        ),
        CheckConstraint(
            "state IN ('ACTIVE', 'STALE', 'ENDED', 'INVALID')",
            name="ck_external_context_entity_state",
        ),
        Index(
            "ix_external_context_entities_org_type_seen",
            "organization_id",
            "context_type",
            "last_seen",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    context_type: Mapped[str] = mapped_column(String(32))
    canonical_key: Mapped[str] = mapped_column(String(2048))
    display_name: Mapped[str] = mapped_column(String(2048))
    source_namespace: Mapped[str] = mapped_column(String(128))
    source_native_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    confidence: Mapped[float] = mapped_column(Float)
    state: Mapped[str] = mapped_column(String(16), default="ACTIVE")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    metadata_json: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Relationship(Base):
    """Evidence-backed directional graph edge; never an assertion of exploitability."""

    __tablename__ = "relationships"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_relationship_id_org"),
        UniqueConstraint(
            "organization_id", "canonical_key", name="uq_relationship_org_canonical_key"
        ),
        ForeignKeyConstraint(
            ["source_asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            name="fk_relationship_source_asset_org",
        ),
        ForeignKeyConstraint(
            ["target_asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            name="fk_relationship_target_asset_org",
        ),
        ForeignKeyConstraint(
            ["source_context_entity_id", "organization_id"],
            ["external_context_entities.id", "external_context_entities.organization_id"],
            name="fk_relationship_source_context_org",
        ),
        ForeignKeyConstraint(
            ["target_context_entity_id", "organization_id"],
            ["external_context_entities.id", "external_context_entities.organization_id"],
            name="fk_relationship_target_context_org",
        ),
        CheckConstraint(
            "(source_asset_id IS NOT NULL AND source_context_entity_id IS NULL) OR "
            "(source_asset_id IS NULL AND source_context_entity_id IS NOT NULL)",
            name="ck_relationship_one_source_endpoint",
        ),
        CheckConstraint(
            "(target_asset_id IS NOT NULL AND target_context_entity_id IS NULL) OR "
            "(target_asset_id IS NULL AND target_context_entity_id IS NOT NULL)",
            name="ck_relationship_one_target_endpoint",
        ),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_relationship_confidence"),
        CheckConstraint(
            "valid_to IS NULL OR valid_from < valid_to", name="ck_relationship_valid_window"
        ),
        CheckConstraint(
            "state IN ('ACTIVE', 'STALE', 'ENDED', 'INVALID')", name="ck_relationship_state"
        ),
        Index(
            "ix_relationships_org_source_asset_state", "organization_id", "source_asset_id", "state"
        ),
        Index(
            "ix_relationships_org_target_asset_state", "organization_id", "target_asset_id", "state"
        ),
        Index(
            "ix_relationships_org_source_context_state",
            "organization_id",
            "source_context_entity_id",
            "state",
        ),
        Index(
            "ix_relationships_org_target_context_state",
            "organization_id",
            "target_context_entity_id",
            "state",
        ),
        Index("ix_relationships_org_type_state", "organization_id", "relationship_type", "state"),
        Index("ix_relationships_org_valid_window", "organization_id", "valid_from", "valid_to"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    relationship_type: Mapped[str] = mapped_column(String(128))
    source_asset_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    source_context_entity_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    target_asset_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    target_context_entity_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    canonical_key: Mapped[str] = mapped_column(String(64))
    confidence: Mapped[float] = mapped_column(Float)
    confidence_model_version: Mapped[str] = mapped_column(String(64))
    registry_version: Mapped[str] = mapped_column(String(64))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    state: Mapped[str] = mapped_column(String(16), default="ACTIVE")
    source_system: Mapped[str] = mapped_column(String(128))
    source_record_key: Mapped[str | None] = mapped_column(String(512), nullable=True)
    metadata_json: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class RelationshipEvidenceLink(Base):
    __tablename__ = "relationship_evidence_links"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "link_key", name="uq_relationship_evidence_link_org_key"
        ),
        ForeignKeyConstraint(
            ["relationship_id", "organization_id"],
            ["relationships.id", "relationships.organization_id"],
            name="fk_relationship_evidence_link_relationship_org",
        ),
        ForeignKeyConstraint(
            ["observation_id", "organization_id"],
            ["canonical_observations.id", "canonical_observations.organization_id"],
            name="fk_relationship_evidence_link_observation_org",
        ),
        ForeignKeyConstraint(
            ["evidence_id", "organization_id"],
            ["evidence.id", "evidence.organization_id"],
            name="fk_relationship_evidence_link_evidence_org",
        ),
        CheckConstraint(
            "observation_id IS NOT NULL OR evidence_id IS NOT NULL OR "
            "source_context_record_hash IS NOT NULL",
            name="ck_relationship_evidence_link_provenance",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    relationship_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    observation_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    source_context_record_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    link_key: Mapped[str] = mapped_column(String(64))
    linked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_risk_assessment_id_org"),
        ForeignKeyConstraint(
            ["finding_id", "organization_id"],
            ["findings.id", "findings.organization_id"],
            name="fk_risk_assessment_finding_org",
        ),
        CheckConstraint("raw_score >= 0 AND raw_score <= 100", name="ck_risk_assessment_raw_score"),
        CheckConstraint(
            "adjusted_score >= 0 AND adjusted_score <= 100",
            name="ck_risk_assessment_adjusted_score",
        ),
        CheckConstraint(
            "factor_coverage >= 0 AND factor_coverage <= 1",
            name="ck_risk_assessment_factor_coverage",
        ),
        CheckConstraint(
            "confidence >= 0 AND confidence <= 1", name="ck_risk_assessment_confidence"
        ),
        Index(
            "ix_risk_assessments_org_finding_time", "organization_id", "finding_id", "evaluated_at"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    finding_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    service_asset_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    model_version: Mapped[str] = mapped_column(String(64))
    registry_hash: Mapped[str] = mapped_column(String(64))
    raw_score: Mapped[float] = mapped_column(Float)
    adjusted_score: Mapped[float] = mapped_column(Float)
    factor_coverage: Mapped[float] = mapped_column(Float)
    confidence: Mapped[float] = mapped_column(Float)
    risk_band: Mapped[str] = mapped_column(String(32))
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    explanation_json: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class RiskFactorResult(Base):
    __tablename__ = "risk_factor_results"
    __table_args__ = (
        UniqueConstraint("risk_assessment_id", "factor_key", name="uq_risk_factor_assessment_key"),
        ForeignKeyConstraint(
            ["risk_assessment_id", "organization_id"],
            ["risk_assessments.id", "risk_assessments.organization_id"],
            name="fk_risk_factor_assessment_org",
        ),
        CheckConstraint(
            "availability IN ('AVAILABLE', 'MISSING', 'STALE', 'INVALID', 'NOT_APPLICABLE')",
            name="ck_risk_factor_availability",
        ),
        CheckConstraint(
            "normalized_value IS NULL OR (normalized_value >= 0 AND normalized_value <= 1)",
            name="ck_risk_factor_normalized_value",
        ),
        CheckConstraint(
            "factor_confidence >= 0 AND factor_confidence <= 1",
            name="ck_risk_factor_confidence",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    risk_assessment_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    factor_key: Mapped[str] = mapped_column(String(128))
    availability: Mapped[str] = mapped_column(String(32))
    raw_value_json: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    normalized_value: Mapped[float | None] = mapped_column(Float, nullable=True)
    configured_weight: Mapped[float] = mapped_column(Float)
    effective_weight: Mapped[float] = mapped_column(Float)
    contribution: Mapped[float] = mapped_column(Float)
    factor_confidence: Mapped[float] = mapped_column(Float)
    evidence_reference_json: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    reason_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class VerifiedControlEvidence(Base):
    __tablename__ = "verified_control_evidence"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_verified_control_evidence_id_org"),
        CheckConstraint(
            "verification_state IN ('VERIFIED', 'STALE', 'INVALID', 'REVOKED', 'UNKNOWN')",
            name="ck_verified_control_state",
        ),
        CheckConstraint(
            "effectiveness >= 0 AND effectiveness <= 1",
            name="ck_verified_control_effectiveness",
        ),
        CheckConstraint(
            "confidence >= 0 AND confidence <= 1", name="ck_verified_control_confidence"
        ),
        Index("ix_verified_controls_org_finding", "organization_id", "finding_id", "verified_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    asset_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    service_asset_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    finding_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    relationship_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    control_type: Mapped[str] = mapped_column(String(128))
    control_key: Mapped[str] = mapped_column(String(255))
    verification_state: Mapped[str] = mapped_column(String(16))
    effectiveness: Mapped[float] = mapped_column(Float)
    confidence: Mapped[float] = mapped_column(Float)
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    freshness_window_seconds: Mapped[int] = mapped_column(Integer)
    source_type: Mapped[str] = mapped_column(String(64))
    source_reference: Mapped[str] = mapped_column(String(512))
    metadata_json: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


@event.listens_for(Evidence, "before_update")
def _prevent_evidence_integrity_mutation(_: object, __: object, target: Evidence) -> None:
    state = inspect(target)
    immutable_fields = (
        "sha256",
        "object_store_key",
        "size_bytes",
        "source_observed_at",
        "collected_at",
        "stored_at",
    )
    if any(state.attrs[name].history.has_changes() for name in immutable_fields):
        raise ValueError("evidence integrity metadata is immutable")
