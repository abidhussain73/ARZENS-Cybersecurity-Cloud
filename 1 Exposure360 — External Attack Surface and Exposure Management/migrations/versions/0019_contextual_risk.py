"""Create Phase 7 contextual risk assessment history.

Revision ID: 0019_contextual_risk
Revises: 0018_relationship_graph
"""

import sqlalchemy as sa
from alembic import op

revision = "0019_contextual_risk"
down_revision = "0018_relationship_graph"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "risk_assessments",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column("asset_id", sa.UUID(), nullable=False),
        sa.Column("service_asset_id", sa.UUID(), nullable=True),
        sa.Column("model_version", sa.String(length=64), nullable=False),
        sa.Column("registry_hash", sa.String(length=64), nullable=False),
        sa.Column("raw_score", sa.Float(), nullable=False),
        sa.Column("adjusted_score", sa.Float(), nullable=False),
        sa.Column("factor_coverage", sa.Float(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("risk_band", sa.String(length=32), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("explanation_json", sa.JSON(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "raw_score >= 0 AND raw_score <= 100", name="ck_risk_assessment_raw_score"
        ),
        sa.CheckConstraint(
            "adjusted_score >= 0 AND adjusted_score <= 100",
            name="ck_risk_assessment_adjusted_score",
        ),
        sa.CheckConstraint(
            "factor_coverage >= 0 AND factor_coverage <= 1",
            name="ck_risk_assessment_factor_coverage",
        ),
        sa.CheckConstraint(
            "confidence >= 0 AND confidence <= 1", name="ck_risk_assessment_confidence"
        ),
        sa.ForeignKeyConstraint(
            ["finding_id", "organization_id"],
            ["findings.id", "findings.organization_id"],
            name="fk_risk_assessment_finding_org",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("id", "organization_id", name="uq_risk_assessment_id_org"),
    )
    op.create_index(
        "ix_risk_assessments_org_finding_time",
        "risk_assessments",
        ["organization_id", "finding_id", "evaluated_at"],
    )
    op.create_table(
        "risk_factor_results",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("risk_assessment_id", sa.UUID(), nullable=False),
        sa.Column("factor_key", sa.String(length=128), nullable=False),
        sa.Column("availability", sa.String(length=32), nullable=False),
        sa.Column("raw_value_json", sa.JSON(), nullable=False),
        sa.Column("normalized_value", sa.Float(), nullable=True),
        sa.Column("configured_weight", sa.Float(), nullable=False),
        sa.Column("effective_weight", sa.Float(), nullable=False),
        sa.Column("contribution", sa.Float(), nullable=False),
        sa.Column("factor_confidence", sa.Float(), nullable=False),
        sa.Column("evidence_reference_json", sa.JSON(), nullable=False),
        sa.Column("reason_code", sa.String(length=128), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "availability IN ('AVAILABLE', 'MISSING', 'STALE', 'INVALID', 'NOT_APPLICABLE')",
            name="ck_risk_factor_availability",
        ),
        sa.CheckConstraint(
            "normalized_value IS NULL OR (normalized_value >= 0 AND normalized_value <= 1)",
            name="ck_risk_factor_normalized_value",
        ),
        sa.CheckConstraint(
            "factor_confidence >= 0 AND factor_confidence <= 1", name="ck_risk_factor_confidence"
        ),
        sa.ForeignKeyConstraint(
            ["risk_assessment_id", "organization_id"],
            ["risk_assessments.id", "risk_assessments.organization_id"],
            name="fk_risk_factor_assessment_org",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "risk_assessment_id", "factor_key", name="uq_risk_factor_assessment_key"
        ),
    )


def downgrade() -> None:
    op.drop_table("risk_factor_results")
    op.drop_index("ix_risk_assessments_org_finding_time", table_name="risk_assessments")
    op.drop_table("risk_assessments")
