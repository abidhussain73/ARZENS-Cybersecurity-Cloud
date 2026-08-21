"""Create Phase 7 remediation workflow foundation.

Revision ID: 0020_remediation_workflow
Revises: 0019_contextual_risk
"""

import sqlalchemy as sa
from alembic import op

revision = "0020_remediation_workflow"
down_revision = "0019_contextual_risk"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "remediation_tasks",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column("asset_id", sa.UUID(), nullable=True),
        sa.Column("source_path_key", sa.String(length=64), nullable=True),
        sa.Column("source_relationship_id", sa.UUID(), nullable=True),
        sa.Column("title", sa.String(length=1024), nullable=False),
        sa.Column("description", sa.String(length=8192), nullable=True),
        sa.Column("state", sa.String(length=40), nullable=False),
        sa.Column("priority", sa.String(length=4), nullable=False),
        sa.Column("owner_user_id", sa.UUID(), nullable=True),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_pending_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "priority IN ('P1', 'P2', 'P3', 'P4')", name="ck_remediation_task_priority"
        ),
        sa.CheckConstraint(
            "state IN ('OPEN', 'PLANNED', 'IN_PROGRESS', 'BLOCKED', "
            "'RESOLVED_PENDING_VERIFICATION', 'VERIFIED', 'CLOSED', 'CANCELLED')",
            name="ck_remediation_task_state",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id", "organization_id"],
            ["findings.id", "findings.organization_id"],
            name="fk_remediation_task_finding_org",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("id", "organization_id", name="uq_remediation_task_id_org"),
    )
    op.create_index(
        "ix_remediation_tasks_org_state_due",
        "remediation_tasks",
        ["organization_id", "state", "due_at"],
    )
    op.create_table(
        "remediation_task_events",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("remediation_task_id", sa.UUID(), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("from_state", sa.String(length=40), nullable=True),
        sa.Column("to_state", sa.String(length=40), nullable=True),
        sa.Column("actor_user_id", sa.UUID(), nullable=True),
        sa.Column("reason", sa.String(length=2048), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["remediation_task_id", "organization_id"],
            ["remediation_tasks.id", "remediation_tasks.organization_id"],
            name="fk_remediation_task_event_task_org",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_remediation_task_events_org_task",
        "remediation_task_events",
        ["organization_id", "remediation_task_id"],
    )
    op.create_table(
        "risk_acceptance_exceptions",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column("remediation_task_id", sa.UUID(), nullable=True),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("requested_by_user_id", sa.UUID(), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("rationale", sa.String(length=4096), nullable=False),
        sa.Column("approved_by_user_id", sa.UUID(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "state IN ('REQUESTED', 'APPROVED', 'REJECTED', 'REVOKED', 'EXPIRED')",
            name="ck_risk_exception_state",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id", "organization_id"],
            ["findings.id", "findings.organization_id"],
            name="fk_risk_exception_finding_org",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_risk_exception_org_state_expiry",
        "risk_acceptance_exceptions",
        ["organization_id", "state", "expires_at"],
    )
    op.create_table(
        "sla_policies",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=True),
        sa.Column("policy_key", sa.String(length=128), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("priority", sa.String(length=4), nullable=False),
        sa.Column("acknowledge_within_seconds", sa.Integer(), nullable=True),
        sa.Column("start_within_seconds", sa.Integer(), nullable=True),
        sa.Column("resolve_within_seconds", sa.Integer(), nullable=False),
        sa.Column("verify_within_seconds", sa.Integer(), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint("priority IN ('P1', 'P2', 'P3', 'P4')", name="ck_sla_policy_priority"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id", "policy_key", "version", name="uq_sla_policy_org_key_ver"
        ),
    )
    op.create_table(
        "sla_instances",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("remediation_task_id", sa.UUID(), nullable=False),
        sa.Column("policy_id", sa.UUID(), nullable=False),
        sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolve_due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verify_due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("final_due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("paused_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("paused_duration_seconds", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["remediation_task_id", "organization_id"],
            ["remediation_tasks.id", "remediation_tasks.organization_id"],
            name="fk_sla_instance_task_org",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("remediation_task_id", name="uq_sla_instance_task"),
    )
    op.create_index(
        "ix_sla_instances_org_state_due",
        "sla_instances",
        ["organization_id", "state", "final_due_at"],
    )


def downgrade() -> None:
    op.drop_table("sla_instances")
    op.drop_table("sla_policies")
    op.drop_table("risk_acceptance_exceptions")
    op.drop_table("remediation_task_events")
    op.drop_table("remediation_tasks")
