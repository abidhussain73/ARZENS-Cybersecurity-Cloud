"""Create durable Phase 5 evaluation run records.

Revision ID: 0017_evaluation_runs
Revises: 0016_change_significance
"""

import sqlalchemy as sa
from alembic import op

revision = "0017_evaluation_runs"
down_revision = "0016_change_significance"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "evaluation_runs",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("run_type", sa.String(length=32), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("ruleset_hash", sa.String(length=64), nullable=True),
        sa.Column("snapshot_schema_version", sa.Integer(), nullable=True),
        sa.Column("significance_model_version", sa.String(length=64), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("assets_processed", sa.Integer(), nullable=False),
        sa.Column("findings_matched", sa.Integer(), nullable=False),
        sa.Column("findings_created", sa.Integer(), nullable=False),
        sa.Column("findings_updated", sa.Integer(), nullable=False),
        sa.Column("snapshots_created", sa.Integer(), nullable=False),
        sa.Column("changes_created", sa.Integer(), nullable=False),
        sa.Column("changes_suppressed", sa.Integer(), nullable=False),
        sa.Column("error_count", sa.Integer(), nullable=False),
        sa.Column("last_error_code", sa.String(length=128), nullable=True),
        sa.Column("correlation_id", sa.String(length=64), nullable=False),
        sa.Column("trace_id", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "run_type IN ('EXPOSURE_RULE_EVALUATION', 'ASSET_SNAPSHOT_BUILD', "
            "'CHANGE_DETECTION', 'EXCEPTION_EXPIRY')",
            name="ck_evaluation_run_type",
        ),
        sa.CheckConstraint(
            "state IN ('QUEUED', 'RUNNING', 'PARTIAL', 'COMPLETED', 'FAILED', 'CANCELLED')",
            name="ck_evaluation_run_state",
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("id", "organization_id", name="uq_evaluation_run_id_org"),
    )
    op.create_index(
        "ix_evaluation_runs_org_type_state",
        "evaluation_runs",
        ["organization_id", "run_type", "state"],
    )
    op.create_index(
        "uq_evaluation_runs_one_running",
        "evaluation_runs",
        ["organization_id", "run_type"],
        unique=True,
        postgresql_where=sa.text("state = 'RUNNING'"),
    )


def downgrade() -> None:
    op.drop_table("evaluation_runs")
