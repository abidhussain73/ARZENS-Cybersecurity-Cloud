"""Create evidence-backed findings and history tables.

Revision ID: 0012_findings
Revises: 0011_exposure_rule_versions
Create Date: 2026-08-20 06:35:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "0012_findings"
down_revision = "0011_exposure_rule_versions"
branch_labels = None
depends_on = None


def _organization_reference(columns: list[str], target: str, name: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        columns, [target, target.replace(".id", ".organization_id")], name=name
    )


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("asset_id", sa.UUID(), nullable=False),
        sa.Column("service_asset_id", sa.UUID(), nullable=True),
        sa.Column("rule_id", sa.String(length=255), nullable=False),
        sa.Column("rule_version", sa.Integer(), nullable=False),
        sa.Column("rule_hash", sa.String(length=64), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("category", sa.String(length=128), nullable=False),
        sa.Column("rule_severity", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("in_progress_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_pending_verification_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("exception_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("assigned_to_user_id", sa.UUID(), nullable=True),
        sa.Column("assigned_owner_reference", sa.String(length=512), nullable=True),
        sa.Column("exception_reason", sa.Text(), nullable=True),
        sa.Column("exception_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        _organization_reference(
            ["asset_id", "organization_id"], "assets.id", "fk_finding_asset_org"
        ),
        _organization_reference(
            ["service_asset_id", "organization_id"], "assets.id", "fk_finding_service_asset_org"
        ),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_finding_confidence"),
        sa.CheckConstraint(
            "state IN ('OPEN', 'ACKNOWLEDGED', 'IN_PROGRESS', "
            "'RESOLVED_PENDING_VERIFICATION', 'CLOSED', 'EXCEPTION')",
            name="ck_finding_state",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("id", "organization_id", name="uq_finding_id_org"),
        sa.UniqueConstraint("organization_id", "fingerprint", name="uq_finding_org_fingerprint"),
    )
    op.create_index(
        "ix_findings_org_state_seen", "findings", ["organization_id", "state", "last_seen"]
    )
    op.create_table(
        "finding_evidence_links",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column("evidence_id", sa.UUID(), nullable=False),
        sa.Column("observation_id", sa.UUID(), nullable=True),
        sa.Column("rule_id", sa.String(length=255), nullable=False),
        sa.Column("rule_version", sa.Integer(), nullable=False),
        sa.Column("link_key", sa.String(length=64), nullable=False),
        sa.Column(
            "linked_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["finding_id", "organization_id"],
            ["findings.id", "findings.organization_id"],
            name="fk_finding_evidence_link_finding_org",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id", "organization_id"],
            ["evidence.id", "evidence.organization_id"],
            name="fk_finding_evidence_link_evidence_org",
        ),
        sa.ForeignKeyConstraint(
            ["observation_id", "organization_id"],
            ["canonical_observations.id", "canonical_observations.organization_id"],
            name="fk_finding_evidence_link_observation_org",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "link_key", name="uq_finding_evidence_link_org_key"),
    )
    op.create_table(
        "finding_evaluation_events",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column("evaluation_run_id", sa.UUID(), nullable=True),
        sa.Column("rule_version", sa.Integer(), nullable=False),
        sa.Column("matched", sa.Boolean(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("evidence_set_hash", sa.String(length=64), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["finding_id", "organization_id"],
            ["findings.id", "findings.organization_id"],
            name="fk_finding_evaluation_finding_org",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_finding_evaluation_events_finding_time",
        "finding_evaluation_events",
        ["finding_id", "evaluated_at"],
    )
    op.create_table(
        "finding_state_events",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column("from_state", sa.String(length=32), nullable=True),
        sa.Column("to_state", sa.String(length=32), nullable=False),
        sa.Column("actor_user_id", sa.UUID(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("correlation_id", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["finding_id", "organization_id"],
            ["findings.id", "findings.organization_id"],
            name="fk_finding_state_event_finding_org",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_finding_state_events_finding_time", "finding_state_events", ["finding_id", "created_at"]
    )


def downgrade() -> None:
    op.drop_table("finding_state_events")
    op.drop_table("finding_evaluation_events")
    op.drop_table("finding_evidence_links")
    op.drop_table("findings")
