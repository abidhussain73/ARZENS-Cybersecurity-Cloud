"""Add explainable change significance and approved-change integrity.

Revision ID: 0016_change_significance
Revises: 0015_approved_changes
"""

import sqlalchemy as sa
from alembic import op

revision = "0016_change_significance"
down_revision = "0015_approved_changes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "change_events",
        sa.Column("significance_factors_json", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.create_foreign_key(
        "fk_change_event_approved_change_org",
        "change_events",
        "approved_changes",
        ["approved_change_id", "organization_id"],
        ["id", "organization_id"],
    )


def downgrade() -> None:
    op.drop_constraint("fk_change_event_approved_change_org", "change_events", type_="foreignkey")
    op.drop_column("change_events", "significance_factors_json")
