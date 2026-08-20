"""Add explainable fingerprint confidence aggregation fields.

Revision ID: 0010_fingerprint_confidence
Revises: 0009_technology_fingerprints
Create Date: 2026-08-20 06:10:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "0010_fingerprint_confidence"
down_revision = "0009_technology_fingerprints"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "technology_fingerprints",
        sa.Column("base_confidence", sa.Float(), nullable=False, server_default="0"),
    )
    op.add_column(
        "technology_fingerprints",
        sa.Column(
            "confidence_components_json",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'::json"),
        ),
    )
    op.add_column(
        "technology_fingerprints",
        sa.Column(
            "fingerprint_state",
            sa.String(length=16),
            nullable=False,
            server_default="CONFIRMED",
        ),
    )
    op.create_check_constraint(
        "ck_technology_fingerprint_base_confidence",
        "technology_fingerprints",
        "base_confidence >= 0 AND base_confidence <= 1",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_technology_fingerprint_base_confidence",
        "technology_fingerprints",
        type_="check",
    )
    op.drop_column("technology_fingerprints", "fingerprint_state")
    op.drop_column("technology_fingerprints", "confidence_components_json")
    op.drop_column("technology_fingerprints", "base_confidence")
