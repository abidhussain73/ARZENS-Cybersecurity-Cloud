"""Create durable canonical change events.

Revision ID: 0014_change_events
Revises: 0013_asset_snapshots
"""

import sqlalchemy as sa
from alembic import op

revision = "0014_change_events"
down_revision = "0013_asset_snapshots"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "change_events",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("asset_id", sa.UUID(), nullable=False),
        sa.Column("change_type", sa.String(length=16), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("from_snapshot_id", sa.UUID(), nullable=True),
        sa.Column("to_snapshot_id", sa.UUID(), nullable=True),
        sa.Column("summary", sa.String(length=1024), nullable=False),
        sa.Column("details_json", sa.JSON(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("significance_score", sa.Integer(), nullable=True),
        sa.Column("significance_model_version", sa.String(length=64), nullable=True),
        sa.Column("approved_change_id", sa.UUID(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            name="fk_change_event_asset_org",
        ),
        sa.ForeignKeyConstraint(
            ["from_snapshot_id", "organization_id"],
            ["asset_snapshots.id", "asset_snapshots.organization_id"],
            name="fk_change_event_from_snapshot_org",
        ),
        sa.ForeignKeyConstraint(
            ["to_snapshot_id", "organization_id"],
            ["asset_snapshots.id", "asset_snapshots.organization_id"],
            name="fk_change_event_to_snapshot_org",
        ),
        sa.CheckConstraint(
            "change_type IN ('NEW', 'REMOVED', 'SERVICE', 'CERTIFICATE', "
            "'OWNERSHIP', 'FINGERPRINT')",
            name="ck_change_event_type",
        ),
        sa.CheckConstraint(
            "state IN ('OBSERVED', 'EXPECTED', 'REVIEWED')", name="ck_change_event_state"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id", "fingerprint", name="uq_change_event_org_fingerprint"
        ),
    )
    op.create_index(
        "ix_change_events_org_state_seen",
        "change_events",
        ["organization_id", "state", "last_seen"],
    )


def downgrade() -> None:
    op.drop_table("change_events")
