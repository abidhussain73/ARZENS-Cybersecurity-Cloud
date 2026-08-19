"""add membership timestamps to match the Phase 1 ORM model"""

from alembic import op
import sqlalchemy as sa

revision = "0002_membership_timestamps"
down_revision = "0001_phase1_foundation"


def upgrade() -> None:
    op.add_column(
        "memberships",
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.add_column(
        "memberships",
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_column("memberships", "updated_at")
    op.drop_column("memberships", "created_at")
