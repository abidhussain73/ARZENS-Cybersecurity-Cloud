"""Create Phase 7 verification runs and immutable closure decisions.

Revision ID: 0021_verification_runs
Revises: 0020a_verified_control_evidence
"""

import sqlalchemy as sa
from alembic import op

revision = "0021_verification_runs"
down_revision = "0020a_verified_control_evidence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "verification_runs",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column("remediation_task_id", sa.UUID(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("requested_by_user_id", sa.UUID(), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rule_id", sa.String(length=255), nullable=False),
        sa.Column("rule_version", sa.Integer(), nullable=False),
        sa.Column("result", sa.String(length=32), nullable=True),
        sa.Column("evidence_collected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("evidence_integrity_valid", sa.Boolean(), nullable=False),
        sa.Column("collection_complete", sa.Boolean(), nullable=False),
        sa.Column("scope_approval_valid", sa.Boolean(), nullable=False),
        sa.Column("correct_target", sa.Boolean(), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("correlation_id", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "state IN ('QUEUED', 'RUNNING', 'PARTIAL', 'COMPLETED', 'FAILED', 'CANCELLED')",
            name="ck_verification_run_state",
        ),
        sa.CheckConstraint(
            "result IS NULL OR result IN ('CONDITION_PRESENT', 'CONDITION_ABSENT', 'INCONCLUSIVE')",
            name="ck_verification_run_result",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id", "organization_id"],
            ["findings.id", "findings.organization_id"],
            name="fk_verification_run_finding_org",
        ),
        sa.ForeignKeyConstraint(
            ["remediation_task_id", "organization_id"],
            ["remediation_tasks.id", "remediation_tasks.organization_id"],
            name="fk_verification_run_task_org",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "idempotency_key",
            name="uq_verification_run_org_idempotency",
        ),
        sa.UniqueConstraint("id", "organization_id", name="uq_verification_run_id_org"),
    )
    op.create_index(
        "ix_verification_run_one_active_task",
        "verification_runs",
        ["organization_id", "remediation_task_id"],
        unique=True,
        postgresql_where=sa.text("state IN ('QUEUED', 'RUNNING')"),
        sqlite_where=sa.text("state IN ('QUEUED', 'RUNNING')"),
    )
    op.create_table(
        "closure_decisions",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column("remediation_task_id", sa.UUID(), nullable=False),
        sa.Column("verification_run_id", sa.UUID(), nullable=False),
        sa.Column("decision", sa.String(length=32), nullable=False),
        sa.Column("reason_codes", sa.JSON(), nullable=False),
        sa.Column("evidence_ids", sa.JSON(), nullable=False),
        sa.Column("observation_ids", sa.JSON(), nullable=False),
        sa.Column("rule_id", sa.String(length=255), nullable=False),
        sa.Column("rule_version", sa.Integer(), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_or_system", sa.String(length=128), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "decision IN ('ALLOW_CLOSE', 'DENY_CLOSE', 'INCONCLUSIVE')",
            name="ck_closure_decision_decision",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id", "organization_id"],
            ["findings.id", "findings.organization_id"],
            name="fk_closure_decision_finding_org",
        ),
        sa.ForeignKeyConstraint(
            ["remediation_task_id", "organization_id"],
            ["remediation_tasks.id", "remediation_tasks.organization_id"],
            name="fk_closure_decision_task_org",
        ),
        sa.ForeignKeyConstraint(
            ["verification_run_id", "organization_id"],
            ["verification_runs.id", "verification_runs.organization_id"],
            name="fk_closure_decision_run_org",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("verification_run_id", name="uq_closure_decision_verification_run"),
    )


def downgrade() -> None:
    op.drop_table("closure_decisions")
    op.drop_index("ix_verification_run_one_active_task", table_name="verification_runs")
    op.drop_table("verification_runs")
