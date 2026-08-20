"""Create exposure rule version repository metadata.

Revision ID: 0011_exposure_rule_versions
Revises: 0010_fingerprint_confidence
Create Date: 2026-08-20 06:30:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "0011_exposure_rule_versions"
down_revision = "0010_fingerprint_confidence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "exposure_rule_versions",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("rule_id", sa.String(length=255), nullable=False),
        sa.Column("rule_version", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("category", sa.String(length=128), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("base_confidence", sa.Float(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("activation_state", sa.String(length=16), nullable=False),
        sa.Column(
            "loaded_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "base_confidence >= 0 AND base_confidence <= 1",
            name="ck_exposure_rule_base_confidence",
        ),
        sa.CheckConstraint(
            "severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
            name="ck_exposure_rule_severity",
        ),
        sa.CheckConstraint(
            "activation_state IN ('ACTIVE', 'DISABLED', 'DEPRECATED')",
            name="ck_exposure_rule_activation_state",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("rule_id", "rule_version", name="uq_exposure_rule_id_version"),
    )


def downgrade() -> None:
    op.drop_table("exposure_rule_versions")
