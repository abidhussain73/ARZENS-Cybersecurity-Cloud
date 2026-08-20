"""add phase three discovery staging

Revision ID: 0004_discovery_staging
Revises: 0003_scope_governance
Create Date: 2026-08-19 13:10:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0004_discovery_staging"
down_revision = "0003_scope_governance"
branch_labels = None
depends_on = None


def upgrade() -> None:
    uuid_type = postgresql.UUID(as_uuid=True)
    op.create_unique_constraint("uq_scope_approval_id_org", "scope_approvals", ["id", "organization_id"])

    op.create_table(
        "discovery_sources",
        sa.Column("id", uuid_type, primary_key=True, nullable=False),
        sa.Column("organization_id", uuid_type, sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("source_key", sa.String(length=128), nullable=False),
        sa.Column("source_type", sa.String(length=64), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("adapter_version", sa.String(length=64), nullable=False),
        sa.Column("configuration_reference", sa.String(length=255), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("health_state", sa.String(length=32), nullable=False, server_default="HEALTHY"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("id", "organization_id", name="uq_discovery_source_id_org"),
        sa.UniqueConstraint("organization_id", "source_key", name="uq_discovery_source_org_key"),
        sa.CheckConstraint(
            "source_type IN ('RECORDED_PASSIVE_DNS', 'CERTIFICATE_METADATA_IMPORT', "
            "'PASSIVE_DNS_PROVIDER')",
            name="ck_discovery_source_type",
        ),
        sa.CheckConstraint(
            "health_state IN ('HEALTHY', 'DEGRADED', 'UNAVAILABLE', 'MISCONFIGURED')",
            name="ck_discovery_source_health",
        ),
    )
    op.create_index("ix_discovery_sources_organization_id", "discovery_sources", ["organization_id"])
    op.create_index("ix_discovery_sources_org_enabled", "discovery_sources", ["organization_id", "enabled"])

    op.create_table(
        "discovery_jobs",
        sa.Column("id", uuid_type, primary_key=True, nullable=False),
        sa.Column("organization_id", uuid_type, sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("scope_id", uuid_type, nullable=False),
        sa.Column("scope_version_id", uuid_type, nullable=False),
        sa.Column("scope_approval_id", uuid_type, nullable=False),
        sa.Column("scope_content_hash", sa.String(length=64), nullable=False),
        sa.Column("scan_policy_hash", sa.String(length=64), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False, server_default="QUEUED"),
        sa.Column("requested_by_user_id", uuid_type, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancel_reason", sa.Text(), nullable=True),
        sa.Column("cancel_generation", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("progress_total", sa.Integer(), nullable=True),
        sa.Column("progress_completed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("progress_failed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("progress_skipped", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("progress_queued", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("progress_indeterminate", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("current_stage", sa.String(length=32), nullable=True),
        sa.Column("last_checkpoint_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_code", sa.String(length=128), nullable=True),
        sa.Column("degraded_sources_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("id", "organization_id", name="uq_discovery_job_id_org"),
        sa.ForeignKeyConstraint(
            ["scope_version_id", "scope_id", "organization_id"],
            ["scope_versions.id", "scope_versions.scope_id", "scope_versions.organization_id"],
            name="fk_discovery_job_scope_version_org",
        ),
        sa.ForeignKeyConstraint(
            ["scope_approval_id", "organization_id"],
            ["scope_approvals.id", "scope_approvals.organization_id"],
            name="fk_discovery_job_approval_org",
        ),
        sa.CheckConstraint(
            "state IN ('QUEUED', 'RUNNING', 'PARTIAL', 'DEGRADED', 'COMPLETED', "
            "'CANCELLING', 'CANCELLED', 'FAILED')",
            name="ck_discovery_job_state",
        ),
    )
    op.create_index("ix_discovery_jobs_organization_id", "discovery_jobs", ["organization_id"])
    op.create_index("ix_discovery_jobs_scope_id", "discovery_jobs", ["scope_id"])
    op.create_index("ix_discovery_jobs_scope_version_id", "discovery_jobs", ["scope_version_id"])
    op.create_index("ix_discovery_jobs_scope_approval_id", "discovery_jobs", ["scope_approval_id"])
    op.create_index("ix_discovery_jobs_org_state_created", "discovery_jobs", ["organization_id", "state", "created_at"])

    op.create_table(
        "discovery_job_stages",
        sa.Column("id", uuid_type, primary_key=True, nullable=False),
        sa.Column("organization_id", uuid_type, nullable=False),
        sa.Column("discovery_job_id", uuid_type, nullable=False),
        sa.Column("stage", sa.String(length=32), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False, server_default="QUEUED"),
        sa.Column("processed_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("succeeded_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("skipped_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("queued_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("known_total", sa.Integer(), nullable=True),
        sa.Column("progress_indeterminate", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_error_code", sa.String(length=128), nullable=True),
        sa.Column("execution_token", sa.String(length=64), nullable=True),
        sa.Column("execution_generation", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(
            ["discovery_job_id", "organization_id"],
            ["discovery_jobs.id", "discovery_jobs.organization_id"],
            name="fk_discovery_stage_job_org",
        ),
        sa.UniqueConstraint("discovery_job_id", "stage", name="uq_discovery_job_stage"),
        sa.CheckConstraint(
            "stage IN ('PASSIVE_SOURCE', 'CERTIFICATE_IMPORT', 'CANDIDATE_RECONCILIATION', "
            "'DNS_VALIDATE', 'TCP_VALIDATE', 'TLS_METADATA', 'HTTP_METADATA', 'FINALIZE')",
            name="ck_discovery_stage_name",
        ),
        sa.CheckConstraint(
            "state IN ('QUEUED', 'RUNNING', 'COMPLETED', 'PARTIAL', 'SKIPPED', 'FAILED', "
            "'CANCELLED')",
            name="ck_discovery_stage_state",
        ),
    )
    op.create_index("ix_discovery_job_stages_organization_id", "discovery_job_stages", ["organization_id"])
    op.create_index("ix_discovery_job_stages_discovery_job_id", "discovery_job_stages", ["discovery_job_id"])
    op.create_index("ix_discovery_job_stages_job_state", "discovery_job_stages", ["discovery_job_id", "state"])

    op.create_table(
        "discovery_checkpoints",
        sa.Column("id", uuid_type, primary_key=True, nullable=False),
        sa.Column("organization_id", uuid_type, nullable=False),
        sa.Column("discovery_job_id", uuid_type, nullable=False),
        sa.Column("stage", sa.String(length=32), nullable=False),
        sa.Column("checkpoint_schema_version", sa.String(length=64), nullable=False),
        sa.Column("source_key", sa.String(length=128), nullable=False),
        sa.Column("adapter_version", sa.String(length=64), nullable=False),
        sa.Column("token_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(
            ["discovery_job_id", "organization_id"],
            ["discovery_jobs.id", "discovery_jobs.organization_id"],
            name="fk_discovery_checkpoint_job_org",
        ),
        sa.UniqueConstraint("discovery_job_id", "stage", name="uq_discovery_checkpoint_stage"),
    )
    op.create_index("ix_discovery_checkpoints_organization_id", "discovery_checkpoints", ["organization_id"])
    op.create_index("ix_discovery_checkpoints_discovery_job_id", "discovery_checkpoints", ["discovery_job_id"])
    op.create_index("ix_discovery_checkpoints_job_stage", "discovery_checkpoints", ["discovery_job_id", "stage"])

    op.create_table(
        "candidate_assets",
        sa.Column("id", uuid_type, primary_key=True, nullable=False),
        sa.Column("organization_id", uuid_type, sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("scope_id", uuid_type, nullable=False),
        sa.Column("scope_version_id", uuid_type, nullable=False),
        sa.Column("scope_approval_id", uuid_type, nullable=False),
        sa.Column("candidate_type", sa.String(length=16), nullable=False),
        sa.Column("raw_value", sa.Text(), nullable=False),
        sa.Column("canonical_value", sa.String(length=2048), nullable=False),
        sa.Column("first_discovered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_discovered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("confidence_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("confidence_model_version", sa.String(length=64), nullable=False, server_default="candidate-confidence-v1"),
        sa.Column("confidence_factors_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("state", sa.String(length=16), nullable=False, server_default="DISCOVERED"),
        sa.Column("metadata_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("id", "organization_id", name="uq_candidate_asset_id_org"),
        sa.UniqueConstraint(
            "organization_id",
            "scope_version_id",
            "candidate_type",
            "canonical_value",
            name="uq_candidate_asset_identity",
        ),
        sa.ForeignKeyConstraint(
            ["scope_version_id", "scope_id", "organization_id"],
            ["scope_versions.id", "scope_versions.scope_id", "scope_versions.organization_id"],
            name="fk_candidate_scope_version_org",
        ),
        sa.ForeignKeyConstraint(
            ["scope_approval_id", "organization_id"],
            ["scope_approvals.id", "scope_approvals.organization_id"],
            name="fk_candidate_approval_org",
        ),
        sa.CheckConstraint("candidate_type IN ('DOMAIN', 'IP', 'ENDPOINT_HINT')", name="ck_candidate_asset_type"),
        sa.CheckConstraint(
            "state IN ('DISCOVERED', 'VALIDATED', 'UNRESOLVED', 'DENIED', 'STALE')",
            name="ck_candidate_asset_state",
        ),
    )
    op.create_index("ix_candidate_assets_organization_id", "candidate_assets", ["organization_id"])
    op.create_index("ix_candidate_assets_scope_id", "candidate_assets", ["scope_id"])
    op.create_index("ix_candidate_assets_scope_version_id", "candidate_assets", ["scope_version_id"])
    op.create_index("ix_candidate_assets_scope_approval_id", "candidate_assets", ["scope_approval_id"])
    op.create_index(
        "ix_candidate_assets_org_version_type_canonical",
        "candidate_assets",
        ["organization_id", "scope_version_id", "candidate_type", "canonical_value"],
    )

    op.create_table(
        "candidate_observations",
        sa.Column("id", uuid_type, primary_key=True, nullable=False),
        sa.Column("organization_id", uuid_type, nullable=False),
        sa.Column("candidate_id", uuid_type, nullable=False),
        sa.Column("source_id", uuid_type, nullable=False),
        sa.Column("source_record_key", sa.String(length=512), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload_hash", sa.String(length=64), nullable=False),
        sa.Column("normalized_metadata_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("raw_artifact_ref", sa.String(length=1024), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(
            ["candidate_id", "organization_id"],
            ["candidate_assets.id", "candidate_assets.organization_id"],
            name="fk_candidate_observation_candidate_org",
        ),
        sa.ForeignKeyConstraint(
            ["source_id", "organization_id"],
            ["discovery_sources.id", "discovery_sources.organization_id"],
            name="fk_candidate_observation_source_org",
        ),
        sa.UniqueConstraint(
            "candidate_id",
            "source_id",
            "source_record_key",
            "payload_hash",
            "observed_at",
            name="uq_candidate_observation_idempotency",
        ),
    )
    op.create_index("ix_candidate_observations_organization_id", "candidate_observations", ["organization_id"])
    op.create_index("ix_candidate_observations_candidate_id", "candidate_observations", ["candidate_id"])
    op.create_index("ix_candidate_observations_source_id", "candidate_observations", ["source_id"])
    op.create_index("ix_candidate_observations_candidate_source", "candidate_observations", ["candidate_id", "source_id"])

    op.create_table(
        "collection_attempts",
        sa.Column("id", uuid_type, primary_key=True, nullable=False),
        sa.Column("organization_id", uuid_type, nullable=False),
        sa.Column("discovery_job_id", uuid_type, nullable=False),
        sa.Column("candidate_id", uuid_type, nullable=True),
        sa.Column("stage", sa.String(length=32), nullable=False),
        sa.Column("protocol", sa.String(length=16), nullable=True),
        sa.Column("target_host", sa.String(length=2048), nullable=False),
        sa.Column("target_port", sa.Integer(), nullable=True),
        sa.Column("attempt_number", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("scope_decision", sa.String(length=16), nullable=False),
        sa.Column("result", sa.String(length=32), nullable=False),
        sa.Column("reason_code", sa.String(length=128), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("correlation_id", sa.String(length=64), nullable=False),
        sa.Column("trace_id", sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(
            ["discovery_job_id", "organization_id"],
            ["discovery_jobs.id", "discovery_jobs.organization_id"],
            name="fk_collection_attempt_job_org",
        ),
        sa.ForeignKeyConstraint(
            ["candidate_id", "organization_id"],
            ["candidate_assets.id", "candidate_assets.organization_id"],
            name="fk_collection_attempt_candidate_org",
        ),
    )
    op.create_index("ix_collection_attempts_organization_id", "collection_attempts", ["organization_id"])
    op.create_index("ix_collection_attempts_discovery_job_id", "collection_attempts", ["discovery_job_id"])
    op.create_index("ix_collection_attempts_candidate_id", "collection_attempts", ["candidate_id"])
    op.create_index("ix_collection_attempts_correlation_id", "collection_attempts", ["correlation_id"])
    op.create_index("ix_collection_attempts_job_stage_result", "collection_attempts", ["discovery_job_id", "stage", "result"])

    op.create_table(
        "discovery_job_events",
        sa.Column("id", uuid_type, primary_key=True, nullable=False),
        sa.Column("organization_id", uuid_type, nullable=False),
        sa.Column("discovery_job_id", uuid_type, nullable=False),
        sa.Column("event_key", sa.String(length=255), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("stage", sa.String(length=32), nullable=True),
        sa.Column("details_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("correlation_id", sa.String(length=64), nullable=True),
        sa.Column("trace_id", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(
            ["discovery_job_id", "organization_id"],
            ["discovery_jobs.id", "discovery_jobs.organization_id"],
            name="fk_discovery_event_job_org",
        ),
        sa.UniqueConstraint("discovery_job_id", "event_key", name="uq_discovery_event_key"),
    )
    op.create_index("ix_discovery_job_events_organization_id", "discovery_job_events", ["organization_id"])
    op.create_index("ix_discovery_job_events_discovery_job_id", "discovery_job_events", ["discovery_job_id"])
    op.create_index("ix_discovery_job_events_job_created", "discovery_job_events", ["discovery_job_id", "created_at"])

    op.create_table(
        "dead_letter_items",
        sa.Column("id", uuid_type, primary_key=True, nullable=False),
        sa.Column("organization_id", uuid_type, nullable=False),
        sa.Column("discovery_job_id", uuid_type, nullable=False),
        sa.Column("candidate_id", uuid_type, nullable=True),
        sa.Column("stage", sa.String(length=32), nullable=False),
        sa.Column("operation_key", sa.String(length=255), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("last_error_class", sa.String(length=64), nullable=False),
        sa.Column("last_error_safe_message", sa.String(length=512), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False, server_default="OPEN"),
        sa.Column("first_failed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_failed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(
            ["discovery_job_id", "organization_id"],
            ["discovery_jobs.id", "discovery_jobs.organization_id"],
            name="fk_dead_letter_job_org",
        ),
        sa.UniqueConstraint("discovery_job_id", "operation_key", name="uq_dead_letter_operation"),
        sa.CheckConstraint("state IN ('OPEN', 'REQUEUED', 'RESOLVED', 'DISMISSED')", name="ck_dead_letter_state"),
    )
    op.create_index("ix_dead_letter_items_organization_id", "dead_letter_items", ["organization_id"])
    op.create_index("ix_dead_letter_items_discovery_job_id", "dead_letter_items", ["discovery_job_id"])
    op.create_index("ix_dead_letter_items_candidate_id", "dead_letter_items", ["candidate_id"])
    op.create_index("ix_dead_letter_items_job_state", "dead_letter_items", ["discovery_job_id", "state"])


def downgrade() -> None:
    op.drop_table("dead_letter_items")
    op.drop_table("discovery_job_events")
    op.drop_table("collection_attempts")
    op.drop_table("candidate_observations")
    op.drop_table("candidate_assets")
    op.drop_table("discovery_checkpoints")
    op.drop_table("discovery_job_stages")
    op.drop_table("discovery_jobs")
    op.drop_table("discovery_sources")
    op.drop_constraint("uq_scope_approval_id_org", "scope_approvals", type_="unique")
