"""Create Phase 7 verified control evidence.

Revision ID: 0020a_verified_control_evidence
Revises: 0020_remediation_workflow
"""

import sqlalchemy as sa
from alembic import op

revision = "0020a_verified_control_evidence"
down_revision = "0020_remediation_workflow"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "verified_control_evidence",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("asset_id", sa.UUID(), nullable=True),
        sa.Column("service_asset_id", sa.UUID(), nullable=True),
        sa.Column("finding_id", sa.UUID(), nullable=True),
        sa.Column("relationship_id", sa.UUID(), nullable=True),
        sa.Column("control_type", sa.String(length=128), nullable=False),
        sa.Column("control_key", sa.String(length=255), nullable=False),
        sa.Column("verification_state", sa.String(length=16), nullable=False),
        sa.Column("effectiveness", sa.Float(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("freshness_window_seconds", sa.Integer(), nullable=False),
        sa.Column("source_type", sa.String(length=64), nullable=False),
        sa.Column("source_reference", sa.String(length=512), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "verification_state IN ('VERIFIED', 'STALE', 'INVALID', 'REVOKED', 'UNKNOWN')",
            name="ck_verified_control_state",
        ),
        sa.CheckConstraint(
            "effectiveness >= 0 AND effectiveness <= 1",
            name="ck_verified_control_effectiveness",
        ),
        sa.CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="ck_verified_control_confidence",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("id", "organization_id", name="uq_verified_control_evidence_id_org"),
    )
    op.create_index(
        "ix_verified_controls_org_finding",
        "verified_control_evidence",
        ["organization_id", "finding_id", "verified_at"],
    )


def downgrade() -> None:
    op.drop_table("verified_control_evidence")
