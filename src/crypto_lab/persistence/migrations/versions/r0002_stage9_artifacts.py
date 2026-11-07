"""Stage 9 artifacts: eight tables, the deadline column, their indexes and triggers.

Revision ID: r0002_stage9_artifacts
Revises: r0001_stage8_baseline

Stage 9 plan sections 3.3, 3.4 and 6.6. ``upgrade()`` creates the eight relational
increments in dependency order -- ``candidate_artifacts``, ``artifact_refs``,
``sanitized_adapter_result_manifests``, ``run_manifests``, ``run_artifacts``,
``finalization_journal``, ``audit_events``, ``adapter_validation_results`` -- with
every CHECK, UNIQUE, primary-key and ``RESTRICT`` foreign-key constraint inline and
every plain index, adds the nullable ``engine_runs.finalization_deadline_utc``
column, then creates the Stage 9 partial indexes and triggers through the SQL
constants ``crypto_lab.persistence.schema`` exports for this revision alone
(``STAGE9_PARTIAL_INDEX_SQL``, ``STAGE9_TRIGGER_SQL``), so the metadata module and
this revision share one definition of those objects while the baseline's own
constants stay frozen. The table and index DDL below is an explicit, frozen copy of
the metadata as reviewed at this revision, in the metadata's own constraint order,
and the Stage 9 tests prove a database upgraded from ``r0001`` equals a fresh
``r0002`` render (no drift, identical ``sqlite_master`` objects). ``downgrade()``
drops the triggers, indexes and tables in reverse order and **retains** the added
column by decision (plan 2.4: no existing table is rebuilt); the retained residue is
recorded as the function's own last statement. No DDL string interpolates a value.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from crypto_lab.persistence import schema

revision = "r0002_stage9_artifacts"
down_revision = "r0001_stage8_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create the eight tables, the column, their indexes and the Stage 9 triggers."""
    op.create_table(
        "candidate_artifacts",
        sa.Column("candidate_artifact_id", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.Text(), nullable=False),
        sa.Column("owner_hash", sa.Text(), nullable=False),
        sa.Column("finalization_purpose", sa.Text(), nullable=False),
        sa.Column("source_role", sa.Text(), nullable=False),
        sa.Column("producer_kind", sa.Text(), nullable=False),
        sa.Column("artifact_kind", sa.Text(), nullable=False),
        sa.Column("staging_relative_path", sa.Text(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("adapter_declared_size", sa.Integer(), nullable=True),
        sa.Column("adapter_declared_hash", sa.Text(), nullable=True),
        sa.Column("adapter_declared_media_type", sa.Text(), nullable=True),
        sa.Column("observations_json", sa.Text(), nullable=False),
        sa.Column("observations_hash", sa.Text(), nullable=False),
        sa.Column("source_event_id", sa.Text(), nullable=True),
        sa.Column("source_adapter_manifest_id", sa.Text(), nullable=True),
        sa.Column("run_id", sa.Text(), nullable=True),
        sa.Column("invocation_id", sa.Text(), nullable=True),
        sa.Column("created_at_utc", sa.Integer(), nullable=False),
        sa.Column("updated_at_utc", sa.Integer(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("candidate_artifact_id", name="pk_candidate_artifacts"),
        sa.UniqueConstraint(
            "owner_hash",
            "finalization_purpose",
            "staging_relative_path",
            name="uq_candidate_artifacts_owner_purpose_path",
        ),
        sa.ForeignKeyConstraint(
            ["owner_hash"],
            ["artifact_owners.owner_hash"],
            name="fk_candidate_artifacts_owner",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["run_id", "invocation_id"],
            ["command_invocations.run_id", "command_invocations.invocation_id"],
            name="fk_candidate_artifacts_invocation",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.CheckConstraint(
            "length(candidate_artifact_id) = 41 AND "
            "substr(candidate_artifact_id, 1, 5) = 'cand_'",
            name="ck_candidate_artifacts_candidate_artifact_id",
        ),
        sa.CheckConstraint(
            "schema_version = '1.0.0'",
            name="ck_candidate_artifacts_schema_version",
        ),
        sa.CheckConstraint(
            "length(owner_hash) = 64 AND NOT owner_hash GLOB '*[^0-9a-f]*'",
            name="ck_candidate_artifacts_owner_hash",
        ),
        sa.CheckConstraint(
            "finalization_purpose IN ('RESULT', 'EVIDENCE')",
            name="ck_candidate_artifacts_finalization_purpose",
        ),
        sa.CheckConstraint(
            "source_role IN ('ENGINE_NATIVE_RESULT', 'NORMALIZED_RESULT', "
            "'CORE_EVIDENCE', 'ADAPTER_DESCRIPTOR_EVIDENCE', 'DATASET_INPUT', "
            "'STRATEGY_INPUT', 'EXPERIMENT_INPUT')",
            name="ck_candidate_artifacts_source_role",
        ),
        sa.CheckConstraint(
            "producer_kind IN ('ADAPTER', 'CORE')",
            name="ck_candidate_artifacts_producer_kind",
        ),
        sa.CheckConstraint(
            "length(artifact_kind) BETWEEN 1 AND 128",
            name="ck_candidate_artifacts_artifact_kind",
        ),
        sa.CheckConstraint(
            "length(staging_relative_path) BETWEEN 1 AND 512",
            name="ck_candidate_artifacts_staging_relative_path",
        ),
        sa.CheckConstraint(
            "state IN ('CANDIDATE', 'VALIDATING', 'FINALIZING', 'QUARANTINED', "
            "'CORRUPT')",
            name="ck_candidate_artifacts_state",
        ),
        sa.CheckConstraint(
            "adapter_declared_size BETWEEN 0 AND 9007199254740991",
            name="ck_candidate_artifacts_adapter_declared_size",
        ),
        sa.CheckConstraint(
            "length(adapter_declared_hash) = 64 AND NOT adapter_declared_hash GLOB "
            "'*[^0-9a-f]*'",
            name="ck_candidate_artifacts_adapter_declared_hash",
        ),
        sa.CheckConstraint(
            "length(adapter_declared_media_type) BETWEEN 3 AND 255",
            name="ck_candidate_artifacts_adapter_declared_media_type",
        ),
        sa.CheckConstraint(
            "json_valid(observations_json) AND json_type(observations_json) = "
            "'array' AND json_array_length(observations_json) <= 64",
            name="ck_candidate_artifacts_observations_json",
        ),
        sa.CheckConstraint(
            "length(observations_hash) = 64 AND NOT observations_hash GLOB "
            "'*[^0-9a-f]*'",
            name="ck_candidate_artifacts_observations_hash",
        ),
        sa.CheckConstraint(
            "length(source_event_id) = 40 AND substr(source_event_id, 1, 4) = 'evt_'",
            name="ck_candidate_artifacts_source_event_id",
        ),
        sa.CheckConstraint(
            "length(source_adapter_manifest_id) = 40 AND "
            "substr(source_adapter_manifest_id, 1, 4) = 'amf_'",
            name="ck_candidate_artifacts_source_adapter_manifest_id",
        ),
        sa.CheckConstraint(
            "length(run_id) = 40 AND substr(run_id, 1, 4) = 'run_'",
            name="ck_candidate_artifacts_run_id",
        ),
        sa.CheckConstraint(
            "length(invocation_id) = 40 AND substr(invocation_id, 1, 4) = 'inv_'",
            name="ck_candidate_artifacts_invocation_id",
        ),
        sa.CheckConstraint(
            "created_at_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_candidate_artifacts_created_at_utc",
        ),
        sa.CheckConstraint(
            "updated_at_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_candidate_artifacts_updated_at_utc",
        ),
        sa.CheckConstraint(
            "revision >= 1",
            name="ck_candidate_artifacts_revision",
        ),
        sa.CheckConstraint(
            "updated_at_utc >= created_at_utc",
            name="ck_candidate_artifacts_updated_after_created",
        ),
        sa.CheckConstraint(
            "(finalization_purpose = 'EVIDENCE' AND producer_kind = 'CORE' AND "
            "source_role = 'ADAPTER_DESCRIPTOR_EVIDENCE') OR "
            "(finalization_purpose = 'EVIDENCE' AND producer_kind = 'CORE' AND "
            "source_role = 'CORE_EVIDENCE') OR "
            "(finalization_purpose = 'EVIDENCE' AND producer_kind = 'CORE' AND "
            "source_role = 'DATASET_INPUT') OR "
            "(finalization_purpose = 'EVIDENCE' AND producer_kind = 'CORE' AND "
            "source_role = 'EXPERIMENT_INPUT') OR "
            "(finalization_purpose = 'EVIDENCE' AND producer_kind = 'CORE' AND "
            "source_role = 'STRATEGY_INPUT') OR "
            "(finalization_purpose = 'RESULT' AND producer_kind = 'ADAPTER' AND "
            "source_role = 'ENGINE_NATIVE_RESULT') OR "
            "(finalization_purpose = 'RESULT' AND producer_kind = 'CORE' AND "
            "source_role = 'NORMALIZED_RESULT')",
            name="ck_candidate_artifacts_role_table",
        ),
        sa.CheckConstraint(
            "producer_kind <> 'ADAPTER' OR (adapter_declared_size IS NOT NULL AND "
            "adapter_declared_hash IS NOT NULL AND adapter_declared_media_type IS "
            "NOT NULL AND run_id IS NOT NULL AND invocation_id IS NOT NULL)",
            name="ck_candidate_artifacts_adapter_declared_shape",
        ),
        sa.CheckConstraint(
            "producer_kind <> 'CORE' OR (adapter_declared_size IS NULL AND "
            "adapter_declared_hash IS NULL AND adapter_declared_media_type IS NULL "
            "AND source_event_id IS NULL AND source_adapter_manifest_id IS NULL)",
            name="ck_candidate_artifacts_core_declared_shape",
        ),
        sa.CheckConstraint(
            "invocation_id IS NULL OR run_id IS NOT NULL",
            name="ck_candidate_artifacts_invocation_requires_run",
        ),
    )
    op.create_index(
        "ix_candidate_artifacts_owner_purpose",
        "candidate_artifacts",
        ["owner_hash", "finalization_purpose"],
    )
    op.create_index("ix_candidate_artifacts_run_id", "candidate_artifacts", ["run_id"])
    op.create_index(
        "ix_candidate_artifacts_source_role", "candidate_artifacts", ["source_role"]
    )
    op.create_index("ix_candidate_artifacts_state", "candidate_artifacts", ["state"])
    op.create_table(
        "artifact_refs",
        sa.Column("artifact_id", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.Text(), nullable=False),
        sa.Column("owner_hash", sa.Text(), nullable=False),
        sa.Column("finalization_purpose", sa.Text(), nullable=False),
        sa.Column("source_role", sa.Text(), nullable=False),
        sa.Column("producer_kind", sa.Text(), nullable=False),
        sa.Column("artifact_kind", sa.Text(), nullable=False),
        sa.Column("finalized_relative_path", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.Text(), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("media_type", sa.Text(), nullable=False),
        sa.Column("source_candidate_artifact_id", sa.Text(), nullable=False),
        sa.Column("validation_profile", sa.Text(), nullable=False),
        sa.Column("manifest_json", sa.Text(), nullable=False),
        sa.Column("artifact_manifest_hash", sa.Text(), nullable=False),
        sa.Column("created_at_utc", sa.Integer(), nullable=False),
        sa.Column("finalized_at_utc", sa.Integer(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("artifact_id", name="pk_artifact_refs"),
        sa.UniqueConstraint(
            "source_candidate_artifact_id", name="uq_artifact_refs_source_candidate"
        ),
        sa.UniqueConstraint(
            "artifact_manifest_hash", name="uq_artifact_refs_manifest_hash"
        ),
        sa.UniqueConstraint(
            "finalized_relative_path",
            "source_candidate_artifact_id",
            name="uq_artifact_refs_path_candidate",
        ),
        sa.ForeignKeyConstraint(
            ["owner_hash"],
            ["artifact_owners.owner_hash"],
            name="fk_artifact_refs_owner",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["source_candidate_artifact_id"],
            ["candidate_artifacts.candidate_artifact_id"],
            name="fk_artifact_refs_candidate",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.CheckConstraint(
            "length(artifact_id) = 40 AND substr(artifact_id, 1, 4) = 'art_'",
            name="ck_artifact_refs_artifact_id",
        ),
        sa.CheckConstraint(
            "schema_version = '1.0.0'",
            name="ck_artifact_refs_schema_version",
        ),
        sa.CheckConstraint(
            "length(owner_hash) = 64 AND NOT owner_hash GLOB '*[^0-9a-f]*'",
            name="ck_artifact_refs_owner_hash",
        ),
        sa.CheckConstraint(
            "finalization_purpose IN ('RESULT', 'EVIDENCE')",
            name="ck_artifact_refs_finalization_purpose",
        ),
        sa.CheckConstraint(
            "source_role IN ('ENGINE_NATIVE_RESULT', 'NORMALIZED_RESULT', "
            "'CORE_EVIDENCE', 'ADAPTER_DESCRIPTOR_EVIDENCE', 'DATASET_INPUT', "
            "'STRATEGY_INPUT', 'EXPERIMENT_INPUT')",
            name="ck_artifact_refs_source_role",
        ),
        sa.CheckConstraint(
            "producer_kind IN ('ADAPTER', 'CORE')",
            name="ck_artifact_refs_producer_kind",
        ),
        sa.CheckConstraint(
            "length(artifact_kind) BETWEEN 1 AND 128",
            name="ck_artifact_refs_artifact_kind",
        ),
        sa.CheckConstraint(
            "length(finalized_relative_path) = 75 AND "
            "substr(finalized_relative_path, 1, 8) = 'objects/' AND "
            "substr(finalized_relative_path, 11, 1) = '/'",
            name="ck_artifact_refs_finalized_relative_path",
        ),
        sa.CheckConstraint(
            "length(content_hash) = 64 AND NOT content_hash GLOB '*[^0-9a-f]*'",
            name="ck_artifact_refs_content_hash",
        ),
        sa.CheckConstraint(
            "size_bytes BETWEEN 0 AND 9007199254740991",
            name="ck_artifact_refs_size_bytes",
        ),
        sa.CheckConstraint(
            "length(media_type) BETWEEN 3 AND 255",
            name="ck_artifact_refs_media_type",
        ),
        sa.CheckConstraint(
            "length(source_candidate_artifact_id) = 41 AND "
            "substr(source_candidate_artifact_id, 1, 5) = 'cand_'",
            name="ck_artifact_refs_source_candidate_artifact_id",
        ),
        sa.CheckConstraint(
            "validation_profile = 'artifact-validation/v1'",
            name="ck_artifact_refs_validation_profile",
        ),
        sa.CheckConstraint(
            "json_valid(manifest_json) AND json_type(manifest_json) = 'object'",
            name="ck_artifact_refs_manifest_json",
        ),
        sa.CheckConstraint(
            "length(artifact_manifest_hash) = 64 AND NOT artifact_manifest_hash "
            "GLOB '*[^0-9a-f]*'",
            name="ck_artifact_refs_artifact_manifest_hash",
        ),
        sa.CheckConstraint(
            "created_at_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_artifact_refs_created_at_utc",
        ),
        sa.CheckConstraint(
            "finalized_at_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_artifact_refs_finalized_at_utc",
        ),
        sa.CheckConstraint(
            "state = 'FINALIZED'",
            name="ck_artifact_refs_state",
        ),
        sa.CheckConstraint(
            "finalized_at_utc >= created_at_utc",
            name="ck_artifact_refs_finalized_after_created",
        ),
        sa.CheckConstraint(
            "substr(finalized_relative_path, 12) = content_hash AND "
            "substr(finalized_relative_path, 9, 2) = substr(content_hash, 1, 2)",
            name="ck_artifact_refs_path_addresses_hash",
        ),
        sa.CheckConstraint(
            "finalization_purpose <> 'EVIDENCE' OR (producer_kind = 'CORE' AND "
            "source_role IN ('CORE_EVIDENCE', 'ADAPTER_DESCRIPTOR_EVIDENCE', "
            "'DATASET_INPUT', 'STRATEGY_INPUT', 'EXPERIMENT_INPUT'))",
            name="ck_artifact_refs_evidence_shape",
        ),
        sa.CheckConstraint(
            "finalization_purpose <> 'RESULT' OR source_role IN "
            "('ENGINE_NATIVE_RESULT', 'NORMALIZED_RESULT')",
            name="ck_artifact_refs_result_shape",
        ),
    )
    op.create_index("ix_artifact_refs_content_hash", "artifact_refs", ["content_hash"])
    op.create_index(
        "ix_artifact_refs_owner_purpose_role",
        "artifact_refs",
        ["owner_hash", "finalization_purpose", "source_role"],
    )
    op.create_table(
        "sanitized_adapter_result_manifests",
        sa.Column("sanitized_adapter_result_manifest_hash", sa.Text(), nullable=False),
        sa.Column("run_id", sa.Text(), nullable=False),
        sa.Column("run_invocation_id", sa.Text(), nullable=False),
        sa.Column("experiment_id", sa.Text(), nullable=False),
        sa.Column("attempt_token_hash", sa.Text(), nullable=False),
        sa.Column("source_adapter_result_manifest_hash", sa.Text(), nullable=False),
        sa.Column("semantic_status", sa.Text(), nullable=False),
        sa.Column("manifest_json", sa.Text(), nullable=False),
        sa.Column("evidence_artifact_id", sa.Text(), nullable=True),
        sa.Column("recorded_at_utc", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint(
            "sanitized_adapter_result_manifest_hash",
            name="pk_sanitized_adapter_result_manifests",
        ),
        sa.UniqueConstraint(
            "run_id",
            "run_invocation_id",
            "source_adapter_result_manifest_hash",
            name="uq_sanitized_adapter_result_manifests_source",
        ),
        sa.ForeignKeyConstraint(
            ["experiment_id", "run_id"],
            ["engine_runs.experiment_id", "engine_runs.run_id"],
            name="fk_sanitized_adapter_result_manifests_run",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["run_id", "run_invocation_id"],
            ["command_invocations.run_id", "command_invocations.invocation_id"],
            name="fk_sanitized_adapter_result_manifests_invocation",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_artifact_id"],
            ["artifact_refs.artifact_id"],
            name="fk_sanitized_adapter_result_manifests_evidence",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.CheckConstraint(
            "length(sanitized_adapter_result_manifest_hash) = 64 AND NOT "
            "sanitized_adapter_result_manifest_hash GLOB '*[^0-9a-f]*'",
            name="ck_sanitized_adapter_result_manifests_"
            "sanitized_adapter_result_manifest_hash",
        ),
        sa.CheckConstraint(
            "length(run_id) = 40 AND substr(run_id, 1, 4) = 'run_'",
            name="ck_sanitized_adapter_result_manifests_run_id",
        ),
        sa.CheckConstraint(
            "length(run_invocation_id) = 40 AND substr(run_invocation_id, 1, 4) = "
            "'inv_'",
            name="ck_sanitized_adapter_result_manifests_run_invocation_id",
        ),
        sa.CheckConstraint(
            "length(experiment_id) = 40 AND substr(experiment_id, 1, 4) = 'exp_'",
            name="ck_sanitized_adapter_result_manifests_experiment_id",
        ),
        sa.CheckConstraint(
            "length(attempt_token_hash) = 64 AND NOT attempt_token_hash GLOB "
            "'*[^0-9a-f]*'",
            name="ck_sanitized_adapter_result_manifests_attempt_token_hash",
        ),
        sa.CheckConstraint(
            "length(source_adapter_result_manifest_hash) = 64 AND NOT "
            "source_adapter_result_manifest_hash GLOB '*[^0-9a-f]*'",
            name="ck_sanitized_adapter_result_manifests_"
            "source_adapter_result_manifest_hash",
        ),
        sa.CheckConstraint(
            "length(semantic_status) BETWEEN 1 AND 128",
            name="ck_sanitized_adapter_result_manifests_semantic_status",
        ),
        sa.CheckConstraint(
            "json_valid(manifest_json) AND json_type(manifest_json) = 'object' AND "
            "instr(manifest_json, '\"attempt_token\":') = 0 AND "
            "instr(manifest_json, '\"relative_path\":') = 0",
            name="ck_sanitized_adapter_result_manifests_manifest_json",
        ),
        sa.CheckConstraint(
            "length(evidence_artifact_id) = 40 AND "
            "substr(evidence_artifact_id, 1, 4) = 'art_'",
            name="ck_sanitized_adapter_result_manifests_evidence_artifact_id",
        ),
        sa.CheckConstraint(
            "recorded_at_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_sanitized_adapter_result_manifests_recorded_at_utc",
        ),
    )
    op.create_index(
        "ix_sanitized_adapter_result_manifests_semantic_status",
        "sanitized_adapter_result_manifests",
        ["semantic_status"],
    )
    op.create_table(
        "run_manifests",
        sa.Column("manifest_id", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.Text(), nullable=False),
        sa.Column("run_id", sa.Text(), nullable=False),
        sa.Column("experiment_id", sa.Text(), nullable=False),
        sa.Column("run_invocation_id", sa.Text(), nullable=False),
        sa.Column("attempt_token_hash", sa.Text(), nullable=False),
        sa.Column("sanitized_adapter_result_manifest_hash", sa.Text(), nullable=False),
        sa.Column("semantic_status", sa.Text(), nullable=False),
        sa.Column("process_exit_category", sa.Text(), nullable=False),
        sa.Column("manifest_json", sa.Text(), nullable=False),
        sa.Column("run_manifest_hash", sa.Text(), nullable=False),
        sa.Column("registered_at_utc", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("manifest_id", name="pk_run_manifests"),
        sa.UniqueConstraint("run_id", name="uq_run_manifests_run_id"),
        sa.UniqueConstraint(
            "run_manifest_hash", name="uq_run_manifests_run_manifest_hash"
        ),
        sa.ForeignKeyConstraint(
            ["experiment_id", "run_id"],
            ["engine_runs.experiment_id", "engine_runs.run_id"],
            name="fk_run_manifests_run",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["run_id", "run_invocation_id"],
            ["command_invocations.run_id", "command_invocations.invocation_id"],
            name="fk_run_manifests_invocation",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["sanitized_adapter_result_manifest_hash"],
            [
                "sanitized_adapter_result_manifests."
                "sanitized_adapter_result_manifest_hash"
            ],
            name="fk_run_manifests_sanitized_manifest",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.CheckConstraint(
            "length(manifest_id) = 40 AND substr(manifest_id, 1, 4) = 'rmf_'",
            name="ck_run_manifests_manifest_id",
        ),
        sa.CheckConstraint(
            "schema_version = '1.0.0'",
            name="ck_run_manifests_schema_version",
        ),
        sa.CheckConstraint(
            "length(run_id) = 40 AND substr(run_id, 1, 4) = 'run_'",
            name="ck_run_manifests_run_id",
        ),
        sa.CheckConstraint(
            "length(experiment_id) = 40 AND substr(experiment_id, 1, 4) = 'exp_'",
            name="ck_run_manifests_experiment_id",
        ),
        sa.CheckConstraint(
            "length(run_invocation_id) = 40 AND substr(run_invocation_id, 1, 4) = "
            "'inv_'",
            name="ck_run_manifests_run_invocation_id",
        ),
        sa.CheckConstraint(
            "length(attempt_token_hash) = 64 AND NOT attempt_token_hash GLOB "
            "'*[^0-9a-f]*'",
            name="ck_run_manifests_attempt_token_hash",
        ),
        sa.CheckConstraint(
            "length(sanitized_adapter_result_manifest_hash) = 64 AND NOT "
            "sanitized_adapter_result_manifest_hash GLOB '*[^0-9a-f]*'",
            name="ck_run_manifests_sanitized_adapter_result_manifest_hash",
        ),
        sa.CheckConstraint(
            "semantic_status IN ('SUCCEEDED', 'SUCCEEDED_WITH_WARNINGS')",
            name="ck_run_manifests_semantic_status",
        ),
        sa.CheckConstraint(
            "process_exit_category IN ('SUCCESS', 'VALIDATION_FAILURE', "
            "'NOT_APPLICABLE', 'UNAVAILABLE', 'RUNTIME_FAILURE', 'CANCELLED', "
            "'TIMED_OUT', 'PROTOCOL_VIOLATION')",
            name="ck_run_manifests_process_exit_category",
        ),
        sa.CheckConstraint(
            "json_valid(manifest_json) AND json_type(manifest_json) = 'object'",
            name="ck_run_manifests_manifest_json",
        ),
        sa.CheckConstraint(
            "length(run_manifest_hash) = 64 AND NOT run_manifest_hash GLOB "
            "'*[^0-9a-f]*'",
            name="ck_run_manifests_run_manifest_hash",
        ),
        sa.CheckConstraint(
            "registered_at_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_run_manifests_registered_at_utc",
        ),
    )
    op.create_index(
        "ix_run_manifests_experiment_id", "run_manifests", ["experiment_id"]
    )
    op.create_index(
        "ix_run_manifests_run_invocation_id", "run_manifests", ["run_invocation_id"]
    )
    op.create_table(
        "run_artifacts",
        sa.Column("run_id", sa.Text(), nullable=False),
        sa.Column("artifact_id", sa.Text(), nullable=False),
        sa.Column("link_role", sa.Text(), nullable=False),
        sa.Column("experiment_id", sa.Text(), nullable=False),
        sa.Column("run_manifest_id", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint(
            "run_id", "artifact_id", "link_role", name="pk_run_artifacts"
        ),
        sa.ForeignKeyConstraint(
            ["experiment_id", "run_id"],
            ["engine_runs.experiment_id", "engine_runs.run_id"],
            name="fk_run_artifacts_run",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["artifact_id"],
            ["artifact_refs.artifact_id"],
            name="fk_run_artifacts_artifact",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["run_manifest_id"],
            ["run_manifests.manifest_id"],
            name="fk_run_artifacts_manifest",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.CheckConstraint(
            "length(run_id) = 40 AND substr(run_id, 1, 4) = 'run_'",
            name="ck_run_artifacts_run_id",
        ),
        sa.CheckConstraint(
            "length(artifact_id) = 40 AND substr(artifact_id, 1, 4) = 'art_'",
            name="ck_run_artifacts_artifact_id",
        ),
        sa.CheckConstraint(
            "link_role IN ('RESULT_MANIFEST_MEMBER', 'RUN_EVIDENCE')",
            name="ck_run_artifacts_link_role",
        ),
        sa.CheckConstraint(
            "length(experiment_id) = 40 AND substr(experiment_id, 1, 4) = 'exp_'",
            name="ck_run_artifacts_experiment_id",
        ),
        sa.CheckConstraint(
            "length(run_manifest_id) = 40 AND substr(run_manifest_id, 1, 4) = 'rmf_'",
            name="ck_run_artifacts_run_manifest_id",
        ),
        sa.CheckConstraint(
            "(link_role = 'RESULT_MANIFEST_MEMBER') = (run_manifest_id IS NOT NULL)",
            name="ck_run_artifacts_manifest_shape",
        ),
    )
    op.create_index("ix_run_artifacts_artifact_id", "run_artifacts", ["artifact_id"])
    op.create_index("ix_run_artifacts_link_role", "run_artifacts", ["link_role"])
    op.create_index(
        "ix_run_artifacts_run_manifest_id", "run_artifacts", ["run_manifest_id"]
    )
    op.create_table(
        "finalization_journal",
        sa.Column("finalization_id", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.Text(), nullable=False),
        sa.Column("finalization_purpose", sa.Text(), nullable=False),
        sa.Column("owner_hash", sa.Text(), nullable=False),
        sa.Column("source_role", sa.Text(), nullable=False),
        sa.Column("candidate_ids_json", sa.Text(), nullable=False),
        sa.Column("candidate_set_hash", sa.Text(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("abandon_reason", sa.Text(), nullable=True),
        sa.Column("prepared_at_utc", sa.Integer(), nullable=False),
        sa.Column("finalization_deadline_utc", sa.Integer(), nullable=True),
        sa.Column("lease_expires_at_utc", sa.Integer(), nullable=False),
        sa.Column("expected_run_revision", sa.Integer(), nullable=True),
        sa.Column("expected_invocation_revision", sa.Integer(), nullable=True),
        sa.Column("run_id", sa.Text(), nullable=True),
        sa.Column("run_invocation_id", sa.Text(), nullable=True),
        sa.Column("attempt_token_hash", sa.Text(), nullable=True),
        sa.Column("source_adapter_result_manifest_hash", sa.Text(), nullable=True),
        sa.Column("sanitized_adapter_result_manifest_hash", sa.Text(), nullable=True),
        sa.Column("correlation_kind", sa.Text(), nullable=True),
        sa.Column("correlation_id", sa.Text(), nullable=True),
        sa.Column("planned_json", sa.Text(), nullable=False),
        sa.Column("observed_json", sa.Text(), nullable=False),
        sa.Column("updated_at_utc", sa.Integer(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("finalization_id", name="pk_finalization_journal"),
        sa.ForeignKeyConstraint(
            ["owner_hash"],
            ["artifact_owners.owner_hash"],
            name="fk_finalization_journal_owner",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["run_id", "run_invocation_id"],
            ["command_invocations.run_id", "command_invocations.invocation_id"],
            name="fk_finalization_journal_invocation",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.CheckConstraint(
            "length(finalization_id) = 40 AND substr(finalization_id, 1, 4) = 'fin_'",
            name="ck_finalization_journal_finalization_id",
        ),
        sa.CheckConstraint(
            "schema_version = '1.0.0'",
            name="ck_finalization_journal_schema_version",
        ),
        sa.CheckConstraint(
            "finalization_purpose IN ('RESULT', 'EVIDENCE')",
            name="ck_finalization_journal_finalization_purpose",
        ),
        sa.CheckConstraint(
            "length(owner_hash) = 64 AND NOT owner_hash GLOB '*[^0-9a-f]*'",
            name="ck_finalization_journal_owner_hash",
        ),
        sa.CheckConstraint(
            "source_role IN ('ENGINE_NATIVE_RESULT', 'NORMALIZED_RESULT', "
            "'CORE_EVIDENCE', 'ADAPTER_DESCRIPTOR_EVIDENCE', 'DATASET_INPUT', "
            "'STRATEGY_INPUT', 'EXPERIMENT_INPUT')",
            name="ck_finalization_journal_source_role",
        ),
        sa.CheckConstraint(
            "json_valid(candidate_ids_json) AND json_type(candidate_ids_json) = "
            "'array' AND json_array_length(candidate_ids_json) <= 256 AND "
            "json_array_length(candidate_ids_json) >= 1",
            name="ck_finalization_journal_candidate_ids_json",
        ),
        sa.CheckConstraint(
            "length(candidate_set_hash) = 64 AND NOT candidate_set_hash GLOB "
            "'*[^0-9a-f]*'",
            name="ck_finalization_journal_candidate_set_hash",
        ),
        sa.CheckConstraint(
            "state IN ('PREPARED', 'MOVED', 'REGISTERED', 'ABANDONED')",
            name="ck_finalization_journal_state",
        ),
        sa.CheckConstraint(
            "length(abandon_reason) BETWEEN 3 AND 128",
            name="ck_finalization_journal_abandon_reason",
        ),
        sa.CheckConstraint(
            "prepared_at_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_finalization_journal_prepared_at_utc",
        ),
        sa.CheckConstraint(
            "finalization_deadline_utc BETWEEN -62135596800000000 AND "
            "253402300799999999",
            name="ck_finalization_journal_finalization_deadline_utc",
        ),
        sa.CheckConstraint(
            "lease_expires_at_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_finalization_journal_lease_expires_at_utc",
        ),
        sa.CheckConstraint(
            "expected_run_revision >= 1",
            name="ck_finalization_journal_expected_run_revision",
        ),
        sa.CheckConstraint(
            "expected_invocation_revision >= 1",
            name="ck_finalization_journal_expected_invocation_revision",
        ),
        sa.CheckConstraint(
            "length(run_id) = 40 AND substr(run_id, 1, 4) = 'run_'",
            name="ck_finalization_journal_run_id",
        ),
        sa.CheckConstraint(
            "length(run_invocation_id) = 40 AND substr(run_invocation_id, 1, 4) = "
            "'inv_'",
            name="ck_finalization_journal_run_invocation_id",
        ),
        sa.CheckConstraint(
            "length(attempt_token_hash) = 64 AND NOT attempt_token_hash GLOB "
            "'*[^0-9a-f]*'",
            name="ck_finalization_journal_attempt_token_hash",
        ),
        sa.CheckConstraint(
            "length(source_adapter_result_manifest_hash) = 64 AND NOT "
            "source_adapter_result_manifest_hash GLOB '*[^0-9a-f]*'",
            name="ck_finalization_journal_source_adapter_result_manifest_hash",
        ),
        sa.CheckConstraint(
            "length(sanitized_adapter_result_manifest_hash) = 64 AND NOT "
            "sanitized_adapter_result_manifest_hash GLOB '*[^0-9a-f]*'",
            name="ck_finalization_journal_sanitized_adapter_result_manifest_hash",
        ),
        sa.CheckConstraint(
            "correlation_kind IN ('INVOCATION', 'DIAGNOSTIC', 'AUDIT')",
            name="ck_finalization_journal_correlation_kind",
        ),
        sa.CheckConstraint(
            "length(correlation_id) BETWEEN 1 AND 128",
            name="ck_finalization_journal_correlation_id",
        ),
        sa.CheckConstraint(
            "json_valid(planned_json) AND json_type(planned_json) = 'array' AND "
            "json_array_length(planned_json) <= 256 AND "
            "json_array_length(planned_json) >= 1",
            name="ck_finalization_journal_planned_json",
        ),
        sa.CheckConstraint(
            "json_valid(observed_json) AND json_type(observed_json) = 'array' AND "
            "json_array_length(observed_json) <= 256",
            name="ck_finalization_journal_observed_json",
        ),
        sa.CheckConstraint(
            "updated_at_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_finalization_journal_updated_at_utc",
        ),
        sa.CheckConstraint(
            "revision >= 1",
            name="ck_finalization_journal_revision",
        ),
        sa.CheckConstraint(
            "finalization_purpose <> 'RESULT' OR (finalization_deadline_utc IS NOT "
            "NULL AND expected_run_revision IS NOT NULL AND "
            "expected_invocation_revision IS NOT NULL AND run_id IS NOT NULL AND "
            "run_invocation_id IS NOT NULL AND attempt_token_hash IS NOT NULL AND "
            "source_adapter_result_manifest_hash IS NOT NULL AND "
            "sanitized_adapter_result_manifest_hash IS NOT NULL AND "
            "correlation_kind IS NULL AND correlation_id IS NULL AND source_role IN "
            "('ENGINE_NATIVE_RESULT', 'NORMALIZED_RESULT'))",
            name="ck_finalization_journal_result_shape",
        ),
        sa.CheckConstraint(
            "finalization_purpose <> 'EVIDENCE' OR (finalization_deadline_utc IS "
            "NULL AND expected_run_revision IS NULL AND "
            "expected_invocation_revision IS NULL AND run_id IS NULL AND "
            "run_invocation_id IS NULL AND attempt_token_hash IS NULL AND "
            "source_adapter_result_manifest_hash IS NULL AND "
            "sanitized_adapter_result_manifest_hash IS NULL AND "
            "correlation_kind IS NOT NULL AND correlation_id IS NOT NULL AND "
            "source_role IN ('CORE_EVIDENCE', 'ADAPTER_DESCRIPTOR_EVIDENCE', "
            "'DATASET_INPUT', 'STRATEGY_INPUT', 'EXPERIMENT_INPUT'))",
            name="ck_finalization_journal_evidence_shape",
        ),
        sa.CheckConstraint(
            "(state = 'ABANDONED') = (abandon_reason IS NOT NULL)",
            name="ck_finalization_journal_abandon_shape",
        ),
        sa.CheckConstraint(
            "finalization_deadline_utc IS NULL OR finalization_deadline_utc >= "
            "prepared_at_utc",
            name="ck_finalization_journal_deadline_after_prepared",
        ),
        sa.CheckConstraint(
            "finalization_deadline_utc IS NULL OR lease_expires_at_utc <= "
            "finalization_deadline_utc",
            name="ck_finalization_journal_lease_within_deadline",
        ),
        sa.CheckConstraint(
            "updated_at_utc >= prepared_at_utc",
            name="ck_finalization_journal_updated_after_prepared",
        ),
    )
    op.create_index(
        "ix_finalization_journal_deadline",
        "finalization_journal",
        ["finalization_deadline_utc"],
    )
    op.create_index(
        "ix_finalization_journal_owner_hash", "finalization_journal", ["owner_hash"]
    )
    op.create_index(
        "ix_finalization_journal_source_role", "finalization_journal", ["source_role"]
    )
    op.create_index(
        "ix_finalization_journal_state_lease",
        "finalization_journal",
        ["state", "lease_expires_at_utc"],
    )
    op.create_table(
        "audit_events",
        sa.Column(
            "audit_sequence",
            sa.Integer(),
            primary_key=True,
            autoincrement=True,
            nullable=False,
        ),
        sa.Column("audit_event_id", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.Text(), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("actor_kind", sa.Text(), nullable=False),
        sa.Column("actor_adapter_name", sa.Text(), nullable=True),
        sa.Column("actor_adapter_version", sa.Text(), nullable=True),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("experiment_id", sa.Text(), nullable=True),
        sa.Column("run_id", sa.Text(), nullable=True),
        sa.Column("invocation_id", sa.Text(), nullable=True),
        sa.Column("artifact_id", sa.Text(), nullable=True),
        sa.Column("timestamp_utc", sa.Integer(), nullable=False),
        sa.Column("correlation_id", sa.Text(), nullable=False),
        sa.Column("details_json", sa.Text(), nullable=False),
        sa.Column("details_hash", sa.Text(), nullable=False),
        sa.UniqueConstraint("audit_event_id", name="uq_audit_events_audit_event_id"),
        sa.CheckConstraint(
            "length(audit_event_id) = 42 AND substr(audit_event_id, 1, 6) = 'audit_'",
            name="ck_audit_events_audit_event_id",
        ),
        sa.CheckConstraint(
            "schema_version = '1.0.0'",
            name="ck_audit_events_schema_version",
        ),
        sa.CheckConstraint(
            "action IN ('ARTIFACT_CANDIDATE_REGISTERED', 'ARTIFACT_VALIDATED', "
            "'ARTIFACT_VALIDATION_FAILED', 'ARTIFACT_OWNER_PURPOSE_SELECTED', "
            "'FINALIZATION_LEASE_ACQUIRED', 'FINALIZATION_LEASE_REFUSED', "
            "'FINALIZATION_PREPARED', 'FINALIZATION_MOVED', "
            "'FINALIZATION_REGISTERED', 'FINALIZATION_REPLAYED', "
            "'FINALIZATION_ABANDONED', 'FINALIZATION_TIMED_OUT', "
            "'ARTIFACT_QUARANTINED', 'ARTIFACT_CORRUPT', "
            "'ARTIFACT_LEAKAGE_DETECTED', 'RUN_SUCCEEDED', 'RUN_FAILED', "
            "'RUN_MANIFEST_REGISTERED', 'STDERR_TRUNCATED', "
            "'STDERR_EVIDENCE_LINKED', 'RECONCILIATION_FINALIZATION_RESUMED', "
            "'RECONCILIATION_CANDIDATE_QUARANTINED', "
            "'RECONCILIATION_ORPHAN_QUARANTINED', 'RETENTION_DELETED', "
            "'QUARANTINE_OVERDUE')",
            name="ck_audit_events_action",
        ),
        sa.CheckConstraint(
            "actor_kind IN ('LOCAL_USER', 'CORE', 'ADAPTER')",
            name="ck_audit_events_actor_kind",
        ),
        sa.CheckConstraint(
            "length(actor_adapter_name) BETWEEN 1 AND 128",
            name="ck_audit_events_actor_adapter_name",
        ),
        sa.CheckConstraint(
            "length(actor_adapter_version) BETWEEN 5 AND 64",
            name="ck_audit_events_actor_adapter_version",
        ),
        sa.CheckConstraint(
            "outcome IN ('SUCCEEDED', 'REFUSED', 'FAILED')",
            name="ck_audit_events_outcome",
        ),
        sa.CheckConstraint(
            "length(experiment_id) = 40 AND substr(experiment_id, 1, 4) = 'exp_'",
            name="ck_audit_events_experiment_id",
        ),
        sa.CheckConstraint(
            "length(run_id) = 40 AND substr(run_id, 1, 4) = 'run_'",
            name="ck_audit_events_run_id",
        ),
        sa.CheckConstraint(
            "length(invocation_id) = 40 AND substr(invocation_id, 1, 4) = 'inv_'",
            name="ck_audit_events_invocation_id",
        ),
        sa.CheckConstraint(
            "length(artifact_id) = 40 AND substr(artifact_id, 1, 4) = 'art_'",
            name="ck_audit_events_artifact_id",
        ),
        sa.CheckConstraint(
            "timestamp_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_audit_events_timestamp_utc",
        ),
        sa.CheckConstraint(
            "length(correlation_id) BETWEEN 1 AND 128",
            name="ck_audit_events_correlation_id",
        ),
        sa.CheckConstraint(
            "json_valid(details_json) AND json_type(details_json) = 'object' AND "
            "length(CAST(details_json AS BLOB)) <= 16384",
            name="ck_audit_events_details_json",
        ),
        sa.CheckConstraint(
            "length(details_hash) = 64 AND NOT details_hash GLOB '*[^0-9a-f]*'",
            name="ck_audit_events_details_hash",
        ),
        sa.CheckConstraint(
            "(actor_kind = 'ADAPTER') = (actor_adapter_name IS NOT NULL) AND "
            "(actor_adapter_name IS NULL) = (actor_adapter_version IS NULL)",
            name="ck_audit_events_actor_shape",
        ),
        sa.CheckConstraint(
            "action NOT IN ('FINALIZATION_TIMED_OUT', 'RUN_SUCCEEDED', 'RUN_FAILED', "
            "'RUN_MANIFEST_REGISTERED', 'STDERR_TRUNCATED', "
            "'STDERR_EVIDENCE_LINKED') OR invocation_id IS NOT NULL",
            name="ck_audit_events_invocation_required",
        ),
        sqlite_autoincrement=True,
    )
    op.create_index("ix_audit_events_action", "audit_events", ["action"])
    op.create_index(
        "ix_audit_events_correlation_id", "audit_events", ["correlation_id"]
    )
    op.create_index("ix_audit_events_experiment_id", "audit_events", ["experiment_id"])
    op.create_index("ix_audit_events_invocation_id", "audit_events", ["invocation_id"])
    op.create_index("ix_audit_events_run_id", "audit_events", ["run_id"])
    op.create_index("ix_audit_events_timestamp_utc", "audit_events", ["timestamp_utc"])
    op.create_table(
        "adapter_validation_results",
        sa.Column("invocation_id", sa.Text(), nullable=False),
        sa.Column("run_id", sa.Text(), nullable=False),
        sa.Column("experiment_id", sa.Text(), nullable=False),
        sa.Column("validation_result_hash", sa.Text(), nullable=False),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("result_json", sa.Text(), nullable=False),
        sa.Column("evidence_artifact_id", sa.Text(), nullable=True),
        sa.Column("recorded_at_utc", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("invocation_id", name="pk_adapter_validation_results"),
        sa.UniqueConstraint(
            "validation_result_hash",
            name="uq_adapter_validation_results_validation_result_hash",
        ),
        sa.ForeignKeyConstraint(
            ["run_id", "invocation_id"],
            ["command_invocations.run_id", "command_invocations.invocation_id"],
            name="fk_adapter_validation_results_invocation",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["experiment_id", "run_id"],
            ["engine_runs.experiment_id", "engine_runs.run_id"],
            name="fk_adapter_validation_results_run",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_artifact_id"],
            ["artifact_refs.artifact_id"],
            name="fk_adapter_validation_results_evidence",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.CheckConstraint(
            "length(invocation_id) = 40 AND substr(invocation_id, 1, 4) = 'inv_'",
            name="ck_adapter_validation_results_invocation_id",
        ),
        sa.CheckConstraint(
            "length(run_id) = 40 AND substr(run_id, 1, 4) = 'run_'",
            name="ck_adapter_validation_results_run_id",
        ),
        sa.CheckConstraint(
            "length(experiment_id) = 40 AND substr(experiment_id, 1, 4) = 'exp_'",
            name="ck_adapter_validation_results_experiment_id",
        ),
        sa.CheckConstraint(
            "length(validation_result_hash) = 64 AND NOT validation_result_hash "
            "GLOB '*[^0-9a-f]*'",
            name="ck_adapter_validation_results_validation_result_hash",
        ),
        sa.CheckConstraint(
            "length(outcome) BETWEEN 1 AND 128",
            name="ck_adapter_validation_results_outcome",
        ),
        sa.CheckConstraint(
            "json_valid(result_json) AND json_type(result_json) = 'object'",
            name="ck_adapter_validation_results_result_json",
        ),
        sa.CheckConstraint(
            "length(evidence_artifact_id) = 40 AND "
            "substr(evidence_artifact_id, 1, 4) = 'art_'",
            name="ck_adapter_validation_results_evidence_artifact_id",
        ),
        sa.CheckConstraint(
            "recorded_at_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_adapter_validation_results_recorded_at_utc",
        ),
    )
    op.create_index(
        "ix_adapter_validation_results_run_outcome",
        "adapter_validation_results",
        ["run_id", "outcome"],
    )
    op.add_column(
        "engine_runs",
        sa.Column("finalization_deadline_utc", sa.Integer(), nullable=True),
    )
    for statement in schema.STAGE9_PARTIAL_INDEX_SQL:
        op.execute(sa.text(statement))
    for statement in schema.STAGE9_TRIGGER_SQL:
        op.execute(sa.text(statement))


def downgrade() -> None:
    """Drop the Stage 9 triggers, indexes and tables; retain the added column."""
    op.execute(
        sa.text("DROP TRIGGER trg_command_invocations_stderr_targets_core_evidence")
    )
    op.execute(
        sa.text("DROP TRIGGER trg_validation_result_invocation_is_validate_update")
    )
    op.execute(
        sa.text("DROP TRIGGER trg_validation_result_invocation_is_validate_insert")
    )
    op.execute(
        sa.text("DROP TRIGGER trg_sanitized_manifest_evidence_is_run_evidence_update")
    )
    op.execute(
        sa.text("DROP TRIGGER trg_sanitized_manifest_evidence_is_run_evidence_insert")
    )
    op.execute(sa.text("DROP TRIGGER trg_audit_events_append_only_delete"))
    op.execute(sa.text("DROP TRIGGER trg_audit_events_append_only_update"))
    op.execute(sa.text("DROP TRIGGER trg_finalization_journal_monotonic"))
    op.execute(sa.text("DROP TRIGGER trg_engine_runs_deadline_immutable"))
    op.execute(sa.text("DROP TRIGGER trg_engine_runs_success_requires_manifest"))
    op.execute(sa.text("DROP TRIGGER trg_run_manifests_insert_only_delete"))
    op.execute(sa.text("DROP TRIGGER trg_run_manifests_insert_only_update"))
    op.execute(sa.text("DROP TRIGGER trg_run_manifests_require_running_run"))
    op.execute(sa.text("DROP TRIGGER trg_run_artifacts_member_requires_manifest"))
    op.execute(sa.text("DROP TRIGGER trg_run_artifacts_target_run_owner"))
    op.execute(sa.text("DROP TRIGGER trg_artifact_refs_insert_only_delete"))
    op.execute(sa.text("DROP TRIGGER trg_artifact_refs_insert_only_update"))
    op.execute(sa.text("DROP TRIGGER trg_artifact_refs_match_candidate"))
    op.execute(sa.text("DROP TRIGGER trg_candidate_artifacts_terminal_frozen"))
    op.execute(sa.text("DROP TRIGGER trg_candidate_artifacts_immutable_fields"))
    op.execute(sa.text("DROP TRIGGER trg_candidate_artifacts_owner_role_combination"))
    op.drop_index("ix_engine_runs_finalization_deadline_utc", table_name="engine_runs")
    op.drop_index(
        "ix_adapter_validation_results_run_outcome",
        table_name="adapter_validation_results",
    )
    op.drop_table("adapter_validation_results")
    op.drop_index("ix_audit_events_timestamp_utc", table_name="audit_events")
    op.drop_index("ix_audit_events_run_id", table_name="audit_events")
    op.drop_index("ix_audit_events_invocation_id", table_name="audit_events")
    op.drop_index("ix_audit_events_experiment_id", table_name="audit_events")
    op.drop_index("ix_audit_events_correlation_id", table_name="audit_events")
    op.drop_index("ix_audit_events_action", table_name="audit_events")
    op.drop_table("audit_events")
    op.drop_index(
        "uq_finalization_journal_result_identity", table_name="finalization_journal"
    )
    op.drop_index(
        "uq_finalization_journal_evidence_identity", table_name="finalization_journal"
    )
    op.drop_index(
        "uq_finalization_journal_active_result_lease",
        table_name="finalization_journal",
    )
    op.drop_index(
        "ix_finalization_journal_state_lease", table_name="finalization_journal"
    )
    op.drop_index(
        "ix_finalization_journal_source_role", table_name="finalization_journal"
    )
    op.drop_index(
        "ix_finalization_journal_owner_hash", table_name="finalization_journal"
    )
    op.drop_index("ix_finalization_journal_deadline", table_name="finalization_journal")
    op.drop_table("finalization_journal")
    op.drop_index("ix_run_artifacts_run_manifest_id", table_name="run_artifacts")
    op.drop_index("ix_run_artifacts_link_role", table_name="run_artifacts")
    op.drop_index("ix_run_artifacts_artifact_id", table_name="run_artifacts")
    op.drop_table("run_artifacts")
    op.drop_index("ix_run_manifests_run_invocation_id", table_name="run_manifests")
    op.drop_index("ix_run_manifests_experiment_id", table_name="run_manifests")
    op.drop_table("run_manifests")
    op.drop_index(
        "ix_sanitized_adapter_result_manifests_semantic_status",
        table_name="sanitized_adapter_result_manifests",
    )
    op.drop_table("sanitized_adapter_result_manifests")
    op.drop_index("ix_artifact_refs_owner_purpose_role", table_name="artifact_refs")
    op.drop_index("ix_artifact_refs_content_hash", table_name="artifact_refs")
    op.drop_table("artifact_refs")
    op.drop_index("ix_candidate_artifacts_state", table_name="candidate_artifacts")
    op.drop_index(
        "ix_candidate_artifacts_source_role", table_name="candidate_artifacts"
    )
    op.drop_index("ix_candidate_artifacts_run_id", table_name="candidate_artifacts")
    op.drop_index(
        "ix_candidate_artifacts_owner_purpose", table_name="candidate_artifacts"
    )
    op.drop_table("candidate_artifacts")
    # Stage 9 plan 2.4 and 6.6: the nullable column is retained by decision rather
    # than dropped (no existing table is rebuilt); the residue is recorded here.
    op.execute("-- finalization_deadline_utc retained")
