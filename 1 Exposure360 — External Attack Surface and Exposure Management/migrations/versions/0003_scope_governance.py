"""add phase two scope governance

Revision ID: 0003_scope_governance
Revises: 0002_membership_timestamps
Create Date: 2026-08-19 09:50:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0003_scope_governance"
down_revision = "0002_membership_timestamps"
branch_labels = None
depends_on = None


def upgrade() -> None:
    uuid_type = postgresql.UUID(as_uuid=True)
    op.create_table(
        "scopes",
        sa.Column("id", uuid_type, primary_key=True, nullable=False),
        sa.Column("organization_id", uuid_type, sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="ACTIVE"),
        sa.Column("created_by_user_id", uuid_type, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("disabled_by_user_id", uuid_type, sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("id", "organization_id", name="uq_scope_id_org"),
        sa.CheckConstraint("status IN ('ACTIVE', 'DISABLED', 'ARCHIVED')", name="ck_scope_status"),
    )
    op.create_index("ix_scopes_organization_id", "scopes", ["organization_id"])
    op.create_index("ix_scopes_org_status", "scopes", ["organization_id", "status"])

    op.create_table(
        "scope_versions",
        sa.Column("id", uuid_type, primary_key=True, nullable=False),
        sa.Column("scope_id", uuid_type, nullable=False),
        sa.Column("organization_id", uuid_type, nullable=False),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False, server_default="DRAFT"),
        sa.Column("change_summary", sa.Text(), nullable=True),
        sa.Column("created_by_user_id", uuid_type, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("supersedes_version_id", uuid_type, sa.ForeignKey("scope_versions.id"), nullable=True),
        sa.Column("content_hash", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(
            ["scope_id", "organization_id"],
            ["scopes.id", "scopes.organization_id"],
            name="fk_scope_version_scope_org",
        ),
        sa.UniqueConstraint("id", "organization_id", name="uq_scope_version_id_org"),
        sa.UniqueConstraint("id", "scope_id", "organization_id", name="uq_scope_version_id_scope_org"),
        sa.UniqueConstraint("scope_id", "version_number", name="uq_scope_version_number"),
        sa.CheckConstraint(
            "state IN ('DRAFT', 'SUBMITTED', 'APPROVED', 'REJECTED', 'SUPERSEDED')",
            name="ck_scope_version_state",
        ),
    )
    op.create_index("ix_scope_versions_scope_id", "scope_versions", ["scope_id"])
    op.create_index("ix_scope_versions_organization_id", "scope_versions", ["organization_id"])
    op.create_index("ix_scope_versions_org_state", "scope_versions", ["organization_id", "state"])
    op.create_index(
        "uq_scope_versions_one_approved",
        "scope_versions",
        ["scope_id"],
        unique=True,
        postgresql_where=sa.text("state = 'APPROVED'"),
    )

    for table_name, type_column, type_check, unique_name, index_name in (
        ("scope_seeds", "seed_type", "ck_scope_seed_type", "uq_scope_seed", "ix_scope_seeds_version_type_value"),
        ("scope_exclusions", "exclusion_type", "ck_scope_exclusion_type", "uq_scope_exclusion", "ix_scope_exclusions_version_type_value"),
    ):
        op.create_table(
            table_name,
            sa.Column("id", uuid_type, primary_key=True, nullable=False),
            sa.Column("scope_version_id", uuid_type, nullable=False),
            sa.Column("organization_id", uuid_type, nullable=False),
            sa.Column(type_column, sa.String(length=16), nullable=False),
            sa.Column("raw_value", sa.Text(), nullable=False),
            sa.Column("canonical_value", sa.String(length=320), nullable=False),
            sa.Column("match_mode", sa.String(length=32), nullable=False, server_default="EXACT"),
            sa.Column("metadata_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json"))
            if table_name == "scope_seeds"
            else sa.Column("reason", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.ForeignKeyConstraint(
                ["scope_version_id", "organization_id"],
                ["scope_versions.id", "scope_versions.organization_id"],
                name=f"fk_{table_name[:-1]}_version_org",
            ),
            sa.UniqueConstraint("scope_version_id", type_column, "canonical_value", "match_mode", name=unique_name),
            sa.CheckConstraint(f"{type_column} IN ('DOMAIN', 'CIDR', 'IP', 'ASN')", name=type_check),
            sa.CheckConstraint(
                "match_mode IN ('EXACT', 'DOMAIN_AND_SUBDOMAINS')",
                name=f"ck_{table_name[:-1]}_match_mode",
            ),
        )
        op.create_index(f"ix_{table_name}_scope_version_id", table_name, ["scope_version_id"])
        op.create_index(f"ix_{table_name}_organization_id", table_name, ["organization_id"])
        op.create_index(index_name, table_name, ["scope_version_id", type_column, "canonical_value"])

    op.create_table(
        "scan_policies",
        sa.Column("id", uuid_type, primary_key=True, nullable=False),
        sa.Column("scope_version_id", uuid_type, nullable=False),
        sa.Column("organization_id", uuid_type, nullable=False),
        sa.Column("allowed_protocols", sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("max_requests_per_second", sa.Float(), nullable=False),
        sa.Column("max_concurrent_targets", sa.Integer(), nullable=False),
        sa.Column("max_concurrent_requests", sa.Integer(), nullable=False),
        sa.Column("schedule_timezone", sa.String(length=64), nullable=False, server_default="UTC"),
        sa.Column("schedule_windows", sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("connect_timeout_seconds", sa.Integer(), nullable=False, server_default="10"),
        sa.Column("request_timeout_seconds", sa.Integer(), nullable=False, server_default="30"),
        sa.Column("active_scanning_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(
            ["scope_version_id", "organization_id"],
            ["scope_versions.id", "scope_versions.organization_id"],
            name="fk_scan_policy_version_org",
        ),
        sa.UniqueConstraint("scope_version_id", name="uq_scan_policy_version"),
        sa.CheckConstraint("max_requests_per_second > 0", name="ck_policy_positive_rate"),
        sa.CheckConstraint("max_concurrent_targets > 0", name="ck_policy_positive_targets"),
        sa.CheckConstraint("max_concurrent_requests > 0", name="ck_policy_positive_requests"),
    )
    op.create_index("ix_scan_policies_organization_id", "scan_policies", ["organization_id"])

    op.create_table(
        "scope_approvals",
        sa.Column("id", uuid_type, primary_key=True, nullable=False),
        sa.Column("organization_id", uuid_type, nullable=False),
        sa.Column("scope_id", uuid_type, nullable=False),
        sa.Column("scope_version_id", uuid_type, nullable=False),
        sa.Column("approved_by_user_id", uuid_type, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("decision_reason", sa.Text(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(
            ["scope_version_id", "scope_id", "organization_id"],
            ["scope_versions.id", "scope_versions.scope_id", "scope_versions.organization_id"],
            name="fk_scope_approval_version_scope_org",
        ),
        sa.CheckConstraint("decision IN ('APPROVED', 'REJECTED')", name="ck_scope_approval_decision"),
    )
    op.create_index("ix_scope_approvals_organization_id", "scope_approvals", ["organization_id"])
    op.create_index("ix_scope_approvals_scope_id", "scope_approvals", ["scope_id"])
    op.create_index("ix_scope_approvals_scope_version_id", "scope_approvals", ["scope_version_id"])
    op.create_index("ix_scope_approvals_version_decision", "scope_approvals", ["scope_version_id", "decision"])
    op.create_index("ix_scope_approvals_expires", "scope_approvals", ["expires_at"])

    op.create_table(
        "emergency_stop_states",
        sa.Column("id", uuid_type, primary_key=True, nullable=False),
        sa.Column("organization_id", uuid_type, nullable=False),
        sa.Column("scope_id", uuid_type, nullable=True),
        sa.Column("level", sa.String(length=16), nullable=False),
        sa.Column("is_stopped", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("stop_generation", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("stopped_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("stopped_by_user_id", uuid_type, sa.ForeignKey("users.id"), nullable=True),
        sa.Column("resumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resumed_by_user_id", uuid_type, sa.ForeignKey("users.id"), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(
            ["scope_id", "organization_id"],
            ["scopes.id", "scopes.organization_id"],
            name="fk_stop_state_scope_org",
        ),
        sa.CheckConstraint("level IN ('ORGANIZATION', 'SCOPE')", name="ck_stop_state_level"),
        sa.CheckConstraint(
            "(level = 'ORGANIZATION' AND scope_id IS NULL) OR (level = 'SCOPE' AND scope_id IS NOT NULL)",
            name="ck_stop_state_scope_shape",
        ),
    )
    op.create_index("ix_emergency_stop_states_organization_id", "emergency_stop_states", ["organization_id"])
    op.create_index(
        "uq_org_stop_state",
        "emergency_stop_states",
        ["organization_id"],
        unique=True,
        postgresql_where=sa.text("level = 'ORGANIZATION'"),
    )
    op.create_index(
        "uq_scope_stop_state",
        "emergency_stop_states",
        ["scope_id"],
        unique=True,
        postgresql_where=sa.text("level = 'SCOPE'"),
    )


def downgrade() -> None:
    op.drop_table("emergency_stop_states")
    op.drop_table("scope_approvals")
    op.drop_table("scan_policies")
    op.drop_table("scope_exclusions")
    op.drop_table("scope_seeds")
    op.drop_table("scope_versions")
    op.drop_table("scopes")
