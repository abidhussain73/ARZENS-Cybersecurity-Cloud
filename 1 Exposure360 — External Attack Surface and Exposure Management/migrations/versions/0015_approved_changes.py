"""Create approved expected-change windows.

Revision ID: 0015_approved_changes
Revises: 0014_change_events
"""

import sqlalchemy as sa
from alembic import op

revision = "0015_approved_changes"
down_revision = "0014_change_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "approved_changes",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("asset_id", sa.UUID(), nullable=True),
        sa.Column("allowed_change_types_json", sa.JSON(), nullable=False),
        sa.Column("component_selector_json", sa.JSON(), nullable=True),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ends_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("ticket_reference", sa.String(length=255), nullable=True),
        sa.Column("approved_by_user_id", sa.UUID(), nullable=False),
        sa.Column("created_by_user_id", sa.UUID(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            name="fk_approved_change_asset_org",
        ),
        sa.ForeignKeyConstraint(["approved_by_user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"]),
        sa.CheckConstraint("status IN ('ACTIVE', 'DISABLED')", name="ck_approved_change_status"),
        sa.CheckConstraint("starts_at < ends_at", name="ck_approved_change_window"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("id", "organization_id", name="uq_approved_change_id_org"),
    )
    op.create_index(
        "ix_approved_changes_org_window",
        "approved_changes",
        ["organization_id", "starts_at", "ends_at"],
    )


def downgrade() -> None:
    op.drop_table("approved_changes")
