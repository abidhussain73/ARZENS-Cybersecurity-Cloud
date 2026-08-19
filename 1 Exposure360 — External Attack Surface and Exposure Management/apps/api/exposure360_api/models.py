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
