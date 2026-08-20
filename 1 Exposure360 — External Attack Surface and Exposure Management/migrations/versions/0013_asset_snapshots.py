"""Create canonical asset snapshots.

Revision ID: 0013_asset_snapshots
Revises: 0012_findings
Create Date: 2026-08-20 06:40:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "0013_asset_snapshots"
down_revision = "0012_findings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "asset_snapshots",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("asset_id", sa.UUID(), nullable=False),
        sa.Column("snapshot_schema_version", sa.Integer(), nullable=False),
        sa.Column("snapshot_hash", sa.String(length=64), nullable=False),
        sa.Column("effective_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_evaluation_run_id", sa.UUID(), nullable=True),
        sa.Column("snapshot_json", sa.JSON(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            name="fk_asset_snapshot_asset_org",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "asset_id", "effective_at", "snapshot_hash", name="uq_asset_snapshot_identity"
        ),
    )
    op.create_index(
        "ix_asset_snapshots_asset_effective", "asset_snapshots", ["asset_id", "effective_at"]
    )


def downgrade() -> None:
    op.drop_table("asset_snapshots")
