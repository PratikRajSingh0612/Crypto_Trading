"""Stage 8 baseline: the thirteen relational tables, their indexes and triggers.

Revision ID: r0001_stage8_baseline
Revises: None (the first revision)

Plan sections 3.3, 3.4 and 6.4 (reading 18). ``upgrade()`` creates the thirteen
tables in dependency order -- ``experiments``, ``engine_slots``,
``runtime_availability_observations``, ``diagnostics``, ``diagnostic_causes``,
``strategy_versions``, ``datasets``, ``dataset_partitions``, ``engine_runs``,
``command_invocations``, ``run_events``, ``retry_decisions``, ``artifact_owners`` --
with every CHECK, UNIQUE, primary-key and ``RESTRICT`` foreign-key constraint
inline and every plain index, then the three partial unique indexes and the
triggers through the SQL constants ``crypto_lab.persistence.schema`` exports, so
the metadata module and this revision share one definition of those objects.
The table and index DDL below is an explicit, frozen copy of the metadata as
reviewed at this revision: a later change to ``schema.py`` needs a new revision,
and Task 2's tests prove a database migrated by this revision equals the
metadata (no drift, the pinned ``sqlite_master`` objects). ``downgrade()`` drops
the triggers, indexes and tables in reverse order. No DDL string interpolates a
value: every statement is a literal or one of the exported constants.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from crypto_lab.persistence import schema

revision = "r0001_stage8_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create the thirteen tables, their indexes and their triggers."""
    op.create_table(
        "experiments",
        sa.Column("experiment_id", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.Text(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("spec", sa.Text(), nullable=False),
        sa.Column("spec_hash", sa.Text(), nullable=False),
        sa.Column("strategy_version_hash", sa.Text(), nullable=False),
        sa.Column("dataset_version_hash", sa.Text(), nullable=False),
        sa.Column("slot_compatibility", sa.Text(), nullable=True),
        sa.Column("cancellation_correlation_id", sa.Text(), nullable=True),
        sa.Column("created_at_utc", sa.Integer(), nullable=False),
        sa.Column("updated_at_utc", sa.Integer(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("configuration_snapshot_schema_version", sa.Text(), nullable=True),
        sa.Column("configuration_snapshot_json", sa.Text(), nullable=True),
        sa.Column("configuration_audit_hash", sa.Text(), nullable=True),
        sa.Column("material_base_configuration_hash", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("experiment_id", name="pk_experiments"),
        sa.CheckConstraint(
            "length(experiment_id) = 40 AND substr(experiment_id, 1, 4) = 'exp_'",
            name="ck_experiments_experiment_id",
        ),
        sa.CheckConstraint(
            "schema_version = '1.0.0'",
            name="ck_experiments_schema_version",
        ),
        sa.CheckConstraint(
            "state IN ('DRAFT', 'VALIDATED', 'QUEUED', 'RUNNING', 'COMPLETED', "
            "'COMPLETED_WITH_WARNINGS', 'FAILED', 'CANCELLED')",
            name="ck_experiments_state",
        ),
        sa.CheckConstraint(
            "json_valid(spec)",
            name="ck_experiments_spec",
        ),
        sa.CheckConstraint(
            "length(spec_hash) = 64 AND NOT spec_hash GLOB '*[^0-9a-f]*'",
            name="ck_experiments_spec_hash",
        ),
        sa.CheckConstraint(
            "length(strategy_version_hash) = 64 AND NOT strategy_version_hash GLOB "
            "'*[^0-9a-f]*'",
            name="ck_experiments_strategy_version_hash",
        ),
        sa.CheckConstraint(
            "length(dataset_version_hash) = 64 AND NOT dataset_version_hash GLOB "
            "'*[^0-9a-f]*'",
            name="ck_experiments_dataset_version_hash",
        ),
        sa.CheckConstraint(
            "json_valid(slot_compatibility)",
            name="ck_experiments_slot_compatibility",
        ),
        sa.CheckConstraint(
            "length(cancellation_correlation_id) BETWEEN 1 AND 128",
            name="ck_experiments_cancellation_correlation_id",
        ),
        sa.CheckConstraint(
            "created_at_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_experiments_created_at_utc",
        ),
        sa.CheckConstraint(
            "updated_at_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_experiments_updated_at_utc",
        ),
        sa.CheckConstraint(
            "revision >= 0",
            name="ck_experiments_revision",
        ),
        sa.CheckConstraint(
            "configuration_snapshot_schema_version = '1.0.0'",
            name="ck_experiments_configuration_snapshot_schema_version",
        ),
        sa.CheckConstraint(
            "json_valid(configuration_snapshot_json) AND "
            "length(CAST(configuration_snapshot_json AS BLOB)) <= 1048576",
            name="ck_experiments_configuration_snapshot_json",
        ),
        sa.CheckConstraint(
            "length(configuration_audit_hash) = 64 AND NOT configuration_audit_hash "
            "GLOB '*[^0-9a-f]*'",
            name="ck_experiments_configuration_audit_hash",
        ),
        sa.CheckConstraint(
            "length(material_base_configuration_hash) = 64 AND NOT "
            "material_base_configuration_hash GLOB '*[^0-9a-f]*'",
            name="ck_experiments_material_base_configuration_hash",
        ),
        sa.CheckConstraint(
            "updated_at_utc >= created_at_utc",
            name="ck_experiments_updated_after_created",
        ),
        sa.CheckConstraint(
            "CASE WHEN state IN ('DRAFT', 'VALIDATED') THEN slot_compatibility IS NULL "
            "WHEN state = 'CANCELLED' THEN 1 ELSE slot_compatibility IS NOT NULL END",
            name="ck_experiments_compatibility_shape",
        ),
        sa.CheckConstraint(
            "(state = 'CANCELLED') = (cancellation_correlation_id IS NOT NULL)",
            name="ck_experiments_cancellation_shape",
        ),
        sa.CheckConstraint(
            "(configuration_snapshot_schema_version IS NULL) = "
            "(configuration_snapshot_json IS NULL) AND "
            "(configuration_snapshot_schema_version IS NULL) = "
            "(configuration_audit_hash IS NULL) AND "
            "(configuration_snapshot_schema_version IS NULL) = "
            "(material_base_configuration_hash IS NULL)",
            name="ck_experiments_snapshot_whole",
        ),
    )
    op.create_index(
        "ix_experiments_dataset_version_hash",
        "experiments",
        ["dataset_version_hash"],
    )
    op.create_index(
        "ix_experiments_state_created_at_utc",
        "experiments",
        ["state", "created_at_utc"],
    )
    op.create_index(
        "ix_experiments_strategy_version_hash",
        "experiments",
        ["strategy_version_hash"],
    )
    op.create_table(
        "engine_slots",
        sa.Column("experiment_id", sa.Text(), nullable=False),
        sa.Column("logical_slot_id", sa.Text(), nullable=False),
        sa.Column("slot_ordinal", sa.Integer(), nullable=False),
        sa.Column("adapter_name", sa.Text(), nullable=False),
        sa.Column("adapter_version", sa.Text(), nullable=False),
        sa.Column("engine_name", sa.Text(), nullable=False),
        sa.Column("engine_version", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint(
            "experiment_id",
            "logical_slot_id",
            name="pk_engine_slots",
        ),
        sa.UniqueConstraint(
            "experiment_id",
            "slot_ordinal",
            name="uq_engine_slots_experiment_ordinal",
        ),
        sa.ForeignKeyConstraint(
            ["experiment_id"],
            ["experiments.experiment_id"],
            name="fk_engine_slots_experiment",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.CheckConstraint(
            "length(logical_slot_id) = 41 AND substr(logical_slot_id, 1, 5) = 'slot_'",
            name="ck_engine_slots_logical_slot_id",
        ),
        sa.CheckConstraint(
            "slot_ordinal BETWEEN 0 AND 7",
            name="ck_engine_slots_slot_ordinal",
        ),
        sa.CheckConstraint(
            "length(adapter_name) BETWEEN 1 AND 128",
            name="ck_engine_slots_adapter_name",
        ),
        sa.CheckConstraint(
            "length(adapter_version) BETWEEN 5 AND 64",
            name="ck_engine_slots_adapter_version",
        ),
        sa.CheckConstraint(
            "length(engine_name) BETWEEN 1 AND 128",
            name="ck_engine_slots_engine_name",
        ),
        sa.CheckConstraint(
            "length(engine_version) BETWEEN 5 AND 64",
            name="ck_engine_slots_engine_version",
        ),
    )
    op.create_index(
        "ix_engine_slots_adapter_engine",
        "engine_slots",
        ["adapter_name", "adapter_version", "engine_name", "engine_version"],
    )
    op.create_table(
        "runtime_availability_observations",
        sa.Column("availability_observation_id", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.Text(), nullable=False),
        sa.Column("adapter_name", sa.Text(), nullable=False),
        sa.Column("adapter_version", sa.Text(), nullable=False),
        sa.Column("executable_path", sa.Text(), nullable=False),
        sa.Column("executable_hash", sa.Text(), nullable=False),
        sa.Column("runtime_version", sa.Text(), nullable=False),
        sa.Column("operating_system", sa.Text(), nullable=False),
        sa.Column("available", sa.Integer(), nullable=False),
        sa.Column("reason_code", sa.Text(), nullable=True),
        sa.Column("observed_at_utc", sa.Integer(), nullable=False),
        sa.Column("expires_at_utc", sa.Integer(), nullable=False),
        sa.Column("network_required", sa.Integer(), nullable=False),
        sa.Column("credentials_required", sa.Integer(), nullable=False),
        sa.Column("content_sha256", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint(
            "availability_observation_id",
            name="pk_runtime_availability_observations",
        ),
        sa.CheckConstraint(
            "length(availability_observation_id) = 42 AND "
            "substr(availability_observation_id, 1, 6) = 'avail_'",
            name="ck_runtime_availability_observations_availability_observation_id",
        ),
        sa.CheckConstraint(
            "schema_version = '1.0.0'",
            name="ck_runtime_availability_observations_schema_version",
        ),
        sa.CheckConstraint(
            "length(adapter_name) BETWEEN 1 AND 128",
            name="ck_runtime_availability_observations_adapter_name",
        ),
        sa.CheckConstraint(
            "length(adapter_version) BETWEEN 5 AND 64",
            name="ck_runtime_availability_observations_adapter_version",
        ),
        sa.CheckConstraint(
            "length(executable_path) BETWEEN 1 AND 1024",
            name="ck_runtime_availability_observations_executable_path",
        ),
        sa.CheckConstraint(
            "length(executable_hash) = 64 AND NOT executable_hash GLOB '*[^0-9a-f]*'",
            name="ck_runtime_availability_observations_executable_hash",
        ),
        sa.CheckConstraint(
            "length(runtime_version) BETWEEN 5 AND 64",
            name="ck_runtime_availability_observations_runtime_version",
        ),
        sa.CheckConstraint(
            "operating_system IN ('WINDOWS', 'LINUX', 'MACOS')",
            name="ck_runtime_availability_observations_operating_system",
        ),
        sa.CheckConstraint(
            "available IN (0, 1)",
            name="ck_runtime_availability_observations_available",
        ),
        sa.CheckConstraint(
            "length(reason_code) BETWEEN 3 AND 128",
            name="ck_runtime_availability_observations_reason_code",
        ),
        sa.CheckConstraint(
            "observed_at_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_runtime_availability_observations_observed_at_utc",
        ),
        sa.CheckConstraint(
            "expires_at_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_runtime_availability_observations_expires_at_utc",
        ),
        sa.CheckConstraint(
            "network_required IN (0, 1)",
            name="ck_runtime_availability_observations_network_required",
        ),
        sa.CheckConstraint(
            "credentials_required IN (0, 1)",
            name="ck_runtime_availability_observations_credentials_required",
        ),
        sa.CheckConstraint(
            "length(content_sha256) = 64 AND NOT content_sha256 GLOB '*[^0-9a-f]*'",
            name="ck_runtime_availability_observations_content_sha256",
        ),
        sa.CheckConstraint(
            "(available = 0) = (reason_code IS NOT NULL)",
            name="ck_runtime_availability_observations_reason_shape",
        ),
        sa.CheckConstraint(
            "expires_at_utc > observed_at_utc",
            name="ck_runtime_availability_observations_expiry_after_observation",
        ),
    )
    op.create_index(
        "ix_runtime_availability_observations_adapter_available",
        "runtime_availability_observations",
        [
            "adapter_name",
            "adapter_version",
            "available",
            "observed_at_utc",
            "expires_at_utc",
        ],
    )
    op.create_index(
        "ix_runtime_availability_observations_adapter_executable",
        "runtime_availability_observations",
        [
            "adapter_name",
            "adapter_version",
            "executable_hash",
            "availability_observation_id",
        ],
    )
    op.create_table(
        "diagnostics",
        sa.Column("diagnostic_id", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.Text(), nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("error_code", sa.Text(), nullable=False),
        sa.Column("category", sa.Text(), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("source_component", sa.Text(), nullable=False),
        sa.Column("experiment_id", sa.Text(), nullable=True),
        sa.Column("run_id", sa.Text(), nullable=True),
        sa.Column("invocation_id", sa.Text(), nullable=True),
        sa.Column("engine", sa.Text(), nullable=True),
        sa.Column("retriable", sa.Integer(), nullable=False),
        sa.Column("timestamp_utc", sa.Integer(), nullable=False),
        sa.Column("details", sa.Text(), nullable=False),
        sa.Column("causal_diagnostic_ids", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("diagnostic_id", name="pk_diagnostics"),
        sa.CheckConstraint(
            "length(diagnostic_id) = 41 AND substr(diagnostic_id, 1, 5) = 'diag_'",
            name="ck_diagnostics_diagnostic_id",
        ),
        sa.CheckConstraint(
            "schema_version = '1.0.0'",
            name="ck_diagnostics_schema_version",
        ),
        sa.CheckConstraint(
            "severity IN ('INFO', 'WARNING', 'ERROR', 'CRITICAL')",
            name="ck_diagnostics_severity",
        ),
        sa.CheckConstraint(
            "length(error_code) BETWEEN 3 AND 128",
            name="ck_diagnostics_error_code",
        ),
        sa.CheckConstraint(
            "category IN ('USER_CONFIGURATION', 'SCHEMA_VALIDATION', 'COMPATIBILITY', "
            "'ADAPTER_UNAVAILABILITY', 'ENGINE_RUNTIME', 'PROTOCOL', 'TIMEOUT', "
            "'CANCELLATION', 'ARTIFACT_CORRUPTION', 'PERSISTENCE', "
            "'INTERNAL_INVARIANT', 'SECURITY')",
            name="ck_diagnostics_category",
        ),
        sa.CheckConstraint(
            "length(message) BETWEEN 1 AND 1024",
            name="ck_diagnostics_message",
        ),
        sa.CheckConstraint(
            "length(source_component) BETWEEN 1 AND 128",
            name="ck_diagnostics_source_component",
        ),
        sa.CheckConstraint(
            "length(experiment_id) = 40 AND substr(experiment_id, 1, 4) = 'exp_'",
            name="ck_diagnostics_experiment_id",
        ),
        sa.CheckConstraint(
            "length(run_id) = 40 AND substr(run_id, 1, 4) = 'run_'",
            name="ck_diagnostics_run_id",
        ),
        sa.CheckConstraint(
            "length(invocation_id) = 40 AND substr(invocation_id, 1, 4) = 'inv_'",
            name="ck_diagnostics_invocation_id",
        ),
        sa.CheckConstraint(
            "length(engine) BETWEEN 1 AND 128",
            name="ck_diagnostics_engine",
        ),
        sa.CheckConstraint(
            "retriable IN (0, 1)",
            name="ck_diagnostics_retriable",
        ),
        sa.CheckConstraint(
            "timestamp_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_diagnostics_timestamp_utc",
        ),
        sa.CheckConstraint(
            "json_valid(details) AND json_type(details) = 'object' AND "
            "length(CAST(details AS BLOB)) <= 16384",
            name="ck_diagnostics_details",
        ),
        sa.CheckConstraint(
            "json_valid(causal_diagnostic_ids) AND json_type(causal_diagnostic_ids) = "
            "'array' AND json_array_length(causal_diagnostic_ids) <= 32",
            name="ck_diagnostics_causal_diagnostic_ids",
        ),
        sa.CheckConstraint(
            "run_id IS NULL OR experiment_id IS NOT NULL",
            name="ck_diagnostics_run_requires_experiment",
        ),
        sa.CheckConstraint(
            "category NOT IN ('ENGINE_RUNTIME', 'PROTOCOL', 'TIMEOUT', 'CANCELLATION') "
            "OR invocation_id IS NOT NULL",
            name="ck_diagnostics_command_requires_invocation",
        ),
    )
    op.create_index("ix_diagnostics_category", "diagnostics", ["category"])
    op.create_index("ix_diagnostics_error_code", "diagnostics", ["error_code"])
    op.create_index("ix_diagnostics_experiment_id", "diagnostics", ["experiment_id"])
    op.create_index("ix_diagnostics_invocation_id", "diagnostics", ["invocation_id"])
    op.create_index("ix_diagnostics_run_id", "diagnostics", ["run_id"])
    op.create_index("ix_diagnostics_severity", "diagnostics", ["severity"])
    op.create_index("ix_diagnostics_timestamp_utc", "diagnostics", ["timestamp_utc"])
    op.create_table(
        "diagnostic_causes",
        sa.Column("diagnostic_id", sa.Text(), nullable=False),
        sa.Column("causal_diagnostic_id", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint(
            "diagnostic_id",
            "causal_diagnostic_id",
            name="pk_diagnostic_causes",
        ),
        sa.ForeignKeyConstraint(
            ["diagnostic_id"],
            ["diagnostics.diagnostic_id"],
            name="fk_diagnostic_causes_diagnostic",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["causal_diagnostic_id"],
            ["diagnostics.diagnostic_id"],
            name="fk_diagnostic_causes_cause",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.CheckConstraint(
            "diagnostic_id <> causal_diagnostic_id",
            name="ck_diagnostic_causes_no_self_cause",
        ),
    )
    op.create_index(
        "ix_diagnostic_causes_causal_diagnostic_id",
        "diagnostic_causes",
        ["causal_diagnostic_id"],
    )
    op.create_table(
        "strategy_versions",
        sa.Column("content_hash", sa.Text(), nullable=False),
        sa.Column("strategy_version_id", sa.Text(), nullable=False),
        sa.Column("strategy_id", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.Text(), nullable=False),
        sa.Column("record", sa.Text(), nullable=False),
        sa.Column("hashing_profile_version", sa.Text(), nullable=False),
        sa.Column("created_at_utc", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("content_hash", name="pk_strategy_versions"),
        sa.UniqueConstraint(
            "strategy_version_id",
            name="uq_strategy_versions_strategy_version_id",
        ),
        sa.UniqueConstraint(
            "strategy_id",
            "created_at_utc",
            name="uq_strategy_versions_strategy_id_created_at_utc",
        ),
        sa.CheckConstraint(
            "length(content_hash) = 64 AND NOT content_hash GLOB '*[^0-9a-f]*'",
            name="ck_strategy_versions_content_hash",
        ),
        sa.CheckConstraint(
            "length(strategy_version_id) = 41 AND substr(strategy_version_id, 1, 5) = "
            "'strv_'",
            name="ck_strategy_versions_strategy_version_id",
        ),
        sa.CheckConstraint(
            "length(strategy_id) = 42 AND substr(strategy_id, 1, 6) = 'strat_'",
            name="ck_strategy_versions_strategy_id",
        ),
        sa.CheckConstraint(
            "schema_version = '1.0.0'",
            name="ck_strategy_versions_schema_version",
        ),
        sa.CheckConstraint(
            "json_valid(record)",
            name="ck_strategy_versions_record",
        ),
        sa.CheckConstraint(
            "hashing_profile_version = 'strategy-version/v1'",
            name="ck_strategy_versions_hashing_profile_version",
        ),
        sa.CheckConstraint(
            "created_at_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_strategy_versions_created_at_utc",
        ),
    )
    op.create_table(
        "datasets",
        sa.Column("dataset_id", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.Text(), nullable=False),
        sa.Column("record", sa.Text(), nullable=False),
        sa.Column("venue", sa.Text(), nullable=False),
        sa.Column("instrument_canonical_id", sa.Text(), nullable=False),
        sa.Column("data_type", sa.Text(), nullable=False),
        sa.Column("timeframe", sa.Text(), nullable=True),
        sa.Column("start_utc", sa.Integer(), nullable=False),
        sa.Column("end_utc", sa.Integer(), nullable=False),
        sa.Column("validation_status", sa.Text(), nullable=False),
        sa.Column("created_at_utc", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("dataset_id", name="pk_datasets"),
        sa.UniqueConstraint("content_hash", name="uq_datasets_content_hash"),
        sa.CheckConstraint(
            "length(dataset_id) = 39 AND substr(dataset_id, 1, 3) = 'ds_'",
            name="ck_datasets_dataset_id",
        ),
        sa.CheckConstraint(
            "length(content_hash) = 64 AND NOT content_hash GLOB '*[^0-9a-f]*'",
            name="ck_datasets_content_hash",
        ),
        sa.CheckConstraint(
            "schema_version = '1.0.0'",
            name="ck_datasets_schema_version",
        ),
        sa.CheckConstraint(
            "json_valid(record)",
            name="ck_datasets_record",
        ),
        sa.CheckConstraint(
            "length(venue) BETWEEN 1 AND 32",
            name="ck_datasets_venue",
        ),
        sa.CheckConstraint(
            "length(instrument_canonical_id) BETWEEN 10 AND 107",
            name="ck_datasets_instrument_canonical_id",
        ),
        sa.CheckConstraint(
            "data_type IN ('OHLCV', 'TRADES', 'QUOTES', 'ORDER_BOOK_L2')",
            name="ck_datasets_data_type",
        ),
        sa.CheckConstraint(
            "length(timeframe) BETWEEN 2 AND 16",
            name="ck_datasets_timeframe",
        ),
        sa.CheckConstraint(
            "start_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_datasets_start_utc",
        ),
        sa.CheckConstraint(
            "end_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_datasets_end_utc",
        ),
        sa.CheckConstraint(
            "validation_status IN ('VALID', 'VALID_WITH_WARNINGS', 'INVALID')",
            name="ck_datasets_validation_status",
        ),
        sa.CheckConstraint(
            "created_at_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_datasets_created_at_utc",
        ),
        sa.CheckConstraint(
            "start_utc < end_utc",
            name="ck_datasets_interval",
        ),
        sa.CheckConstraint(
            "(data_type = 'OHLCV') = (timeframe IS NOT NULL)",
            name="ck_datasets_timeframe_shape",
        ),
    )
    op.create_index(
        "ix_datasets_instrument_data_type_interval",
        "datasets",
        ["instrument_canonical_id", "data_type", "start_utc", "end_utc"],
    )
    op.create_table(
        "dataset_partitions",
        sa.Column("partition_id", sa.Text(), nullable=False),
        sa.Column("dataset_id", sa.Text(), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("record", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.Text(), nullable=False),
        sa.Column("raw_checksum", sa.Text(), nullable=False),
        sa.Column("normalized_checksum", sa.Text(), nullable=False),
        sa.Column("relative_path", sa.Text(), nullable=False),
        sa.Column("row_count", sa.Integer(), nullable=False),
        sa.Column("start_utc", sa.Integer(), nullable=False),
        sa.Column("end_utc", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("partition_id", name="pk_dataset_partitions"),
        sa.UniqueConstraint(
            "dataset_id",
            "ordinal",
            name="uq_dataset_partitions_dataset_id_ordinal",
        ),
        sa.ForeignKeyConstraint(
            ["dataset_id"],
            ["datasets.dataset_id"],
            name="fk_dataset_partitions_dataset",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.CheckConstraint(
            "length(partition_id) = 41 AND substr(partition_id, 1, 5) = 'part_'",
            name="ck_dataset_partitions_partition_id",
        ),
        sa.CheckConstraint(
            "ordinal >= 0",
            name="ck_dataset_partitions_ordinal",
        ),
        sa.CheckConstraint(
            "json_valid(record)",
            name="ck_dataset_partitions_record",
        ),
        sa.CheckConstraint(
            "length(content_hash) = 64 AND NOT content_hash GLOB '*[^0-9a-f]*'",
            name="ck_dataset_partitions_content_hash",
        ),
        sa.CheckConstraint(
            "length(raw_checksum) = 64 AND NOT raw_checksum GLOB '*[^0-9a-f]*'",
            name="ck_dataset_partitions_raw_checksum",
        ),
        sa.CheckConstraint(
            "length(normalized_checksum) = 64 AND NOT normalized_checksum GLOB "
            "'*[^0-9a-f]*'",
            name="ck_dataset_partitions_normalized_checksum",
        ),
        sa.CheckConstraint(
            "length(relative_path) BETWEEN 1 AND 1024",
            name="ck_dataset_partitions_relative_path",
        ),
        sa.CheckConstraint(
            "row_count >= 0",
            name="ck_dataset_partitions_row_count",
        ),
        sa.CheckConstraint(
            "start_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_dataset_partitions_start_utc",
        ),
        sa.CheckConstraint(
            "end_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_dataset_partitions_end_utc",
        ),
        sa.CheckConstraint(
            "start_utc < end_utc",
            name="ck_dataset_partitions_interval",
        ),
    )
    op.create_index(
        "ix_dataset_partitions_content_hash",
        "dataset_partitions",
        ["content_hash"],
    )
    op.create_index(
        "ix_dataset_partitions_normalized_checksum",
        "dataset_partitions",
        ["normalized_checksum"],
    )
    op.create_index(
        "ix_dataset_partitions_raw_checksum",
        "dataset_partitions",
        ["raw_checksum"],
    )
    op.create_table(
        "engine_runs",
        sa.Column("run_id", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.Text(), nullable=False),
        sa.Column("experiment_id", sa.Text(), nullable=False),
        sa.Column("logical_slot_id", sa.Text(), nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("attempt_token_hash", sa.Text(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("adapter_name", sa.Text(), nullable=False),
        sa.Column("adapter_version", sa.Text(), nullable=False),
        sa.Column("engine_name", sa.Text(), nullable=False),
        sa.Column("engine_version", sa.Text(), nullable=False),
        sa.Column("request_hash", sa.Text(), nullable=False),
        sa.Column("predecessor_run_id", sa.Text(), nullable=True),
        sa.Column("retry_reason", sa.Text(), nullable=True),
        sa.Column("primary_terminal_diagnostic_id", sa.Text(), nullable=True),
        sa.Column("availability_observation_id", sa.Text(), nullable=True),
        sa.Column("created_at_utc", sa.Integer(), nullable=False),
        sa.Column("updated_at_utc", sa.Integer(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("run_id", name="pk_engine_runs"),
        sa.UniqueConstraint(
            "experiment_id",
            "logical_slot_id",
            "attempt_number",
            name="uq_engine_runs_attempt",
        ),
        sa.UniqueConstraint(
            "experiment_id",
            "run_id",
            name="uq_engine_runs_experiment_run",
        ),
        sa.ForeignKeyConstraint(
            ["experiment_id"],
            ["experiments.experiment_id"],
            name="fk_engine_runs_experiment",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["experiment_id", "logical_slot_id"],
            ["engine_slots.experiment_id", "engine_slots.logical_slot_id"],
            name="fk_engine_runs_slot",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["predecessor_run_id"],
            ["engine_runs.run_id"],
            name="fk_engine_runs_predecessor",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["availability_observation_id"],
            ["runtime_availability_observations.availability_observation_id"],
            name="fk_engine_runs_observation",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.CheckConstraint(
            "length(run_id) = 40 AND substr(run_id, 1, 4) = 'run_'",
            name="ck_engine_runs_run_id",
        ),
        sa.CheckConstraint(
            "schema_version = '1.0.0'",
            name="ck_engine_runs_schema_version",
        ),
        sa.CheckConstraint(
            "length(experiment_id) = 40 AND substr(experiment_id, 1, 4) = 'exp_'",
            name="ck_engine_runs_experiment_id",
        ),
        sa.CheckConstraint(
            "length(logical_slot_id) = 41 AND substr(logical_slot_id, 1, 5) = 'slot_'",
            name="ck_engine_runs_logical_slot_id",
        ),
        sa.CheckConstraint(
            "attempt_number BETWEEN 1 AND 5",
            name="ck_engine_runs_attempt_number",
        ),
        sa.CheckConstraint(
            "length(attempt_token_hash) = 64 AND NOT attempt_token_hash GLOB "
            "'*[^0-9a-f]*'",
            name="ck_engine_runs_attempt_token_hash",
        ),
        sa.CheckConstraint(
            "state IN ('PENDING', 'VALIDATING', 'READY', 'STARTING', 'RUNNING', "
            "'SUCCEEDED', 'SUCCEEDED_WITH_WARNINGS', 'FAILED', 'CANCELLED', "
            "'TIMED_OUT', 'NOT_APPLICABLE', 'UNAVAILABLE')",
            name="ck_engine_runs_state",
        ),
        sa.CheckConstraint(
            "length(adapter_name) BETWEEN 1 AND 128",
            name="ck_engine_runs_adapter_name",
        ),
        sa.CheckConstraint(
            "length(adapter_version) BETWEEN 5 AND 64",
            name="ck_engine_runs_adapter_version",
        ),
        sa.CheckConstraint(
            "length(engine_name) BETWEEN 1 AND 128",
            name="ck_engine_runs_engine_name",
        ),
        sa.CheckConstraint(
            "length(engine_version) BETWEEN 5 AND 64",
            name="ck_engine_runs_engine_version",
        ),
        sa.CheckConstraint(
            "length(request_hash) = 64 AND NOT request_hash GLOB '*[^0-9a-f]*'",
            name="ck_engine_runs_request_hash",
        ),
        sa.CheckConstraint(
            "length(predecessor_run_id) = 40 AND substr(predecessor_run_id, 1, 4) = "
            "'run_'",
            name="ck_engine_runs_predecessor_run_id",
        ),
        sa.CheckConstraint(
            "retry_reason IN ('FAILED', 'TIMED_OUT', 'UNAVAILABLE')",
            name="ck_engine_runs_retry_reason",
        ),
        sa.CheckConstraint(
            "length(primary_terminal_diagnostic_id) = 41 AND "
            "substr(primary_terminal_diagnostic_id, 1, 5) = 'diag_'",
            name="ck_engine_runs_primary_terminal_diagnostic_id",
        ),
        sa.CheckConstraint(
            "length(availability_observation_id) = 42 AND "
            "substr(availability_observation_id, 1, 6) = 'avail_'",
            name="ck_engine_runs_availability_observation_id",
        ),
        sa.CheckConstraint(
            "created_at_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_engine_runs_created_at_utc",
        ),
        sa.CheckConstraint(
            "updated_at_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_engine_runs_updated_at_utc",
        ),
        sa.CheckConstraint(
            "revision >= 0",
            name="ck_engine_runs_revision",
        ),
        sa.CheckConstraint(
            "(attempt_number > 1) = (predecessor_run_id IS NOT NULL)",
            name="ck_engine_runs_predecessor_shape",
        ),
        sa.CheckConstraint(
            "(attempt_number > 1) = (retry_reason IS NOT NULL)",
            name="ck_engine_runs_retry_reason_shape",
        ),
        sa.CheckConstraint(
            "predecessor_run_id IS NULL OR predecessor_run_id <> run_id",
            name="ck_engine_runs_no_self_predecessor",
        ),
        sa.CheckConstraint(
            "(state IN ('FAILED', 'CANCELLED', 'TIMED_OUT', 'NOT_APPLICABLE', "
            "'UNAVAILABLE')) = (primary_terminal_diagnostic_id IS NOT NULL)",
            name="ck_engine_runs_terminal_diagnostic_shape",
        ),
        sa.CheckConstraint(
            "CASE WHEN state IN ('PENDING', 'VALIDATING') THEN "
            "availability_observation_id IS NULL WHEN state IN ('READY', 'STARTING', "
            "'RUNNING', 'SUCCEEDED', 'SUCCEEDED_WITH_WARNINGS', 'UNAVAILABLE') THEN "
            "availability_observation_id IS NOT NULL ELSE 1 END",
            name="ck_engine_runs_observation_shape",
        ),
        sa.CheckConstraint(
            "updated_at_utc >= created_at_utc",
            name="ck_engine_runs_updated_after_created",
        ),
    )
    op.create_index(
        "ix_engine_runs_availability_observation_id",
        "engine_runs",
        ["availability_observation_id"],
    )
    op.create_index(
        "ix_engine_runs_predecessor_run_id",
        "engine_runs",
        ["predecessor_run_id"],
    )
    op.create_index(
        "ix_engine_runs_primary_terminal_diagnostic_id",
        "engine_runs",
        ["primary_terminal_diagnostic_id"],
    )
    op.create_index("ix_engine_runs_state", "engine_runs", ["state"])
    op.create_table(
        "command_invocations",
        sa.Column("invocation_id", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.Text(), nullable=False),
        sa.Column("command_kind", sa.Text(), nullable=False),
        sa.Column("adapter_name", sa.Text(), nullable=False),
        sa.Column("adapter_version", sa.Text(), nullable=False),
        sa.Column("run_id", sa.Text(), nullable=True),
        sa.Column("request_hash", sa.Text(), nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("process_created", sa.Integer(), nullable=False),
        sa.Column("launch_attempted_at_utc", sa.Integer(), nullable=True),
        sa.Column("deadline_utc", sa.Integer(), nullable=True),
        sa.Column("process_started_at_utc", sa.Integer(), nullable=True),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.Column("creation_identity", sa.Text(), nullable=True),
        sa.Column("executable_path", sa.Text(), nullable=True),
        sa.Column("executable_hash", sa.Text(), nullable=True),
        sa.Column("supervisor_instance_id", sa.Text(), nullable=True),
        sa.Column("completed_at_utc", sa.Integer(), nullable=True),
        sa.Column("native_exit_value", sa.Integer(), nullable=True),
        sa.Column("process_exit_category", sa.Text(), nullable=True),
        sa.Column("cleanup_complete", sa.Integer(), nullable=False),
        sa.Column("cleanup_completed_at_utc", sa.Integer(), nullable=True),
        sa.Column("stderr_artifact_id", sa.Text(), nullable=True),
        sa.Column("primary_diagnostic_id", sa.Text(), nullable=True),
        sa.Column("diagnostic_ids", sa.Text(), nullable=False),
        sa.Column("created_at_utc", sa.Integer(), nullable=False),
        sa.Column("updated_at_utc", sa.Integer(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("invocation_id", name="pk_command_invocations"),
        sa.UniqueConstraint(
            "run_id",
            "invocation_id",
            name="uq_command_invocations_run_invocation",
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["engine_runs.run_id"],
            name="fk_command_invocations_run",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.CheckConstraint(
            "length(invocation_id) = 40 AND substr(invocation_id, 1, 4) = 'inv_'",
            name="ck_command_invocations_invocation_id",
        ),
        sa.CheckConstraint(
            "schema_version = '1.0.0'",
            name="ck_command_invocations_schema_version",
        ),
        sa.CheckConstraint(
            "command_kind IN ('DESCRIBE', 'VALIDATE', 'RUN')",
            name="ck_command_invocations_command_kind",
        ),
        sa.CheckConstraint(
            "length(adapter_name) BETWEEN 1 AND 128",
            name="ck_command_invocations_adapter_name",
        ),
        sa.CheckConstraint(
            "length(adapter_version) BETWEEN 5 AND 64",
            name="ck_command_invocations_adapter_version",
        ),
        sa.CheckConstraint(
            "length(run_id) = 40 AND substr(run_id, 1, 4) = 'run_'",
            name="ck_command_invocations_run_id",
        ),
        sa.CheckConstraint(
            "length(request_hash) = 64 AND NOT request_hash GLOB '*[^0-9a-f]*'",
            name="ck_command_invocations_request_hash",
        ),
        sa.CheckConstraint(
            "timeout_seconds BETWEEN 1 AND 604800",
            name="ck_command_invocations_timeout_seconds",
        ),
        sa.CheckConstraint(
            "state IN ('PENDING', 'STARTING', 'RUNNING', 'EXITED', 'FAILED_TO_START', "
            "'CANCELLED', 'TIMED_OUT', 'PROTOCOL_FAILED')",
            name="ck_command_invocations_state",
        ),
        sa.CheckConstraint(
            "process_created IN (0, 1)",
            name="ck_command_invocations_process_created",
        ),
        sa.CheckConstraint(
            "launch_attempted_at_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_command_invocations_launch_attempted_at_utc",
        ),
        sa.CheckConstraint(
            "deadline_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_command_invocations_deadline_utc",
        ),
        sa.CheckConstraint(
            "process_started_at_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_command_invocations_process_started_at_utc",
        ),
        sa.CheckConstraint(
            "pid BETWEEN 1 AND 4294967295",
            name="ck_command_invocations_pid",
        ),
        sa.CheckConstraint(
            "length(creation_identity) BETWEEN 1 AND 1024",
            name="ck_command_invocations_creation_identity",
        ),
        sa.CheckConstraint(
            "length(executable_path) BETWEEN 1 AND 1024",
            name="ck_command_invocations_executable_path",
        ),
        sa.CheckConstraint(
            "length(executable_hash) = 64 AND NOT executable_hash GLOB '*[^0-9a-f]*'",
            name="ck_command_invocations_executable_hash",
        ),
        sa.CheckConstraint(
            "length(supervisor_instance_id) BETWEEN 1 AND 1024",
            name="ck_command_invocations_supervisor_instance_id",
        ),
        sa.CheckConstraint(
            "completed_at_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_command_invocations_completed_at_utc",
        ),
        sa.CheckConstraint(
            "native_exit_value BETWEEN -2147483648 AND 4294967295",
            name="ck_command_invocations_native_exit_value",
        ),
        sa.CheckConstraint(
            "process_exit_category IN ('SUCCESS', 'VALIDATION_FAILURE', "
            "'NOT_APPLICABLE', 'UNAVAILABLE', 'RUNTIME_FAILURE', 'CANCELLED', "
            "'TIMED_OUT', 'PROTOCOL_VIOLATION')",
            name="ck_command_invocations_process_exit_category",
        ),
        sa.CheckConstraint(
            "cleanup_complete IN (0, 1)",
            name="ck_command_invocations_cleanup_complete",
        ),
        sa.CheckConstraint(
            "cleanup_completed_at_utc BETWEEN -62135596800000000 AND "
            "253402300799999999",
            name="ck_command_invocations_cleanup_completed_at_utc",
        ),
        sa.CheckConstraint(
            "length(stderr_artifact_id) = 40 AND substr(stderr_artifact_id, 1, 4) = "
            "'art_'",
            name="ck_command_invocations_stderr_artifact_id",
        ),
        sa.CheckConstraint(
            "length(primary_diagnostic_id) = 41 AND substr(primary_diagnostic_id, 1, "
            "5) = 'diag_'",
            name="ck_command_invocations_primary_diagnostic_id",
        ),
        sa.CheckConstraint(
            "json_valid(diagnostic_ids) AND json_type(diagnostic_ids) = 'array' AND "
            "json_array_length(diagnostic_ids) <= 64",
            name="ck_command_invocations_diagnostic_ids",
        ),
        sa.CheckConstraint(
            "created_at_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_command_invocations_created_at_utc",
        ),
        sa.CheckConstraint(
            "updated_at_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_command_invocations_updated_at_utc",
        ),
        sa.CheckConstraint(
            "revision >= 0",
            name="ck_command_invocations_revision",
        ),
        sa.CheckConstraint(
            "(command_kind = 'DESCRIBE') = (run_id IS NULL)",
            name="ck_command_invocations_describe_has_no_run",
        ),
        sa.CheckConstraint(
            "CASE command_kind WHEN 'DESCRIBE' THEN timeout_seconds BETWEEN 1 AND 300 "
            "WHEN 'VALIDATE' THEN timeout_seconds BETWEEN 1 AND 1800 ELSE "
            "timeout_seconds BETWEEN 1 AND 604800 END",
            name="ck_command_invocations_timeout_per_kind",
        ),
        sa.CheckConstraint(
            "(launch_attempted_at_utc IS NULL) = (deadline_utc IS NULL)",
            name="ck_command_invocations_launch_facts_shape",
        ),
        sa.CheckConstraint(
            "deadline_utc IS NULL OR deadline_utc = launch_attempted_at_utc + "
            "timeout_seconds * 1000000",
            name="ck_command_invocations_deadline_arithmetic",
        ),
        sa.CheckConstraint(
            "(process_started_at_utc IS NULL) = (pid IS NULL) AND "
            "(process_started_at_utc IS NULL) = (creation_identity IS NULL) AND "
            "(process_started_at_utc IS NULL) = (executable_path IS NULL) AND "
            "(process_started_at_utc IS NULL) = (executable_hash IS NULL) AND "
            "(process_started_at_utc IS NULL) = (supervisor_instance_id IS NULL)",
            name="ck_command_invocations_process_facts_shape",
        ),
        sa.CheckConstraint(
            "(process_created = 1) = (pid IS NOT NULL)",
            name="ck_command_invocations_process_created_shape",
        ),
        sa.CheckConstraint(
            "(native_exit_value IS NULL) = (process_exit_category IS NULL)",
            name="ck_command_invocations_exit_facts_shape",
        ),
        sa.CheckConstraint(
            "process_exit_category IS NULL OR process_exit_category = CASE "
            "native_exit_value WHEN 0 THEN 'SUCCESS' WHEN 10 THEN 'VALIDATION_FAILURE' "
            "WHEN 20 THEN 'NOT_APPLICABLE' WHEN 30 THEN 'UNAVAILABLE' WHEN 40 THEN "
            "'RUNTIME_FAILURE' WHEN 50 THEN 'CANCELLED' WHEN 60 THEN 'TIMED_OUT' WHEN "
            "70 THEN 'PROTOCOL_VIOLATION' ELSE 'RUNTIME_FAILURE' END",
            name="ck_command_invocations_exit_category_mapping",
        ),
        sa.CheckConstraint(
            "(cleanup_complete = 1) = (cleanup_completed_at_utc IS NOT NULL)",
            name="ck_command_invocations_cleanup_shape",
        ),
        sa.CheckConstraint(
            "(state IN ('EXITED', 'FAILED_TO_START', 'CANCELLED', 'TIMED_OUT', "
            "'PROTOCOL_FAILED')) = (completed_at_utc IS NOT NULL)",
            name="ck_command_invocations_completion_shape",
        ),
        sa.CheckConstraint(
            "state IN ('EXITED', 'FAILED_TO_START', 'CANCELLED', 'TIMED_OUT', "
            "'PROTOCOL_FAILED') OR (cleanup_complete = 0 AND primary_diagnostic_id IS "
            "NULL AND native_exit_value IS NULL AND stderr_artifact_id IS NULL)",
            name="ck_command_invocations_non_terminal_partition",
        ),
        sa.CheckConstraint(
            "CASE state WHEN 'PENDING' THEN (deadline_utc IS NULL AND process_created "
            "= 0) WHEN 'STARTING' THEN (deadline_utc IS NOT NULL AND process_created = "
            "0) WHEN 'RUNNING' THEN (deadline_utc IS NOT NULL AND process_created = 1) "
            "WHEN 'EXITED' THEN (deadline_utc IS NOT NULL AND process_created = 1 AND "
            "native_exit_value IS NOT NULL AND (native_exit_value IN (0, 10, 20, 30, "
            "40, 50, 60, 70) OR primary_diagnostic_id IS NOT NULL)) WHEN "
            "'FAILED_TO_START' THEN (deadline_utc IS NOT NULL AND process_created = 0 "
            "AND native_exit_value IS NULL AND primary_diagnostic_id IS NOT NULL) WHEN "
            "'CANCELLED' THEN (primary_diagnostic_id IS NOT NULL AND (process_created "
            "= 0 OR deadline_utc IS NOT NULL)) WHEN 'TIMED_OUT' THEN (deadline_utc IS "
            "NOT NULL AND primary_diagnostic_id IS NOT NULL) WHEN 'PROTOCOL_FAILED' "
            "THEN (deadline_utc IS NOT NULL AND process_created = 1 AND "
            "primary_diagnostic_id IS NOT NULL) ELSE 0 END",
            name="ck_command_invocations_state_row",
        ),
        sa.CheckConstraint(
            "updated_at_utc >= created_at_utc",
            name="ck_command_invocations_updated_after_created",
        ),
    )
    op.create_index(
        "ix_command_invocations_created_at_utc_invocation_id",
        "command_invocations",
        ["created_at_utc", "invocation_id"],
    )
    op.create_index(
        "ix_command_invocations_creation_identity_pid",
        "command_invocations",
        ["creation_identity", "pid"],
    )
    op.create_index(
        "ix_command_invocations_primary_diagnostic_id",
        "command_invocations",
        ["primary_diagnostic_id"],
    )
    op.create_index(
        "ix_command_invocations_reconciliation_listing",
        "command_invocations",
        ["state", "cleanup_complete", "created_at_utc", "invocation_id"],
    )
    op.create_index(
        "ix_command_invocations_run_kind_launch",
        "command_invocations",
        ["run_id", "command_kind", "launch_attempted_at_utc"],
    )
    op.create_index(
        "ix_command_invocations_state_deadline_utc",
        "command_invocations",
        ["state", "deadline_utc"],
    )
    op.create_table(
        "run_events",
        sa.Column("invocation_id", sa.Text(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("event_id", sa.Text(), nullable=False),
        sa.Column("run_id", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.Text(), nullable=False),
        sa.Column("protocol_version", sa.Text(), nullable=False),
        sa.Column("attempt_token_hash", sa.Text(), nullable=False),
        sa.Column("wire_event_hash", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.Text(), nullable=False),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("timestamp_utc", sa.Integer(), nullable=False),
        sa.Column("received_at_utc", sa.Integer(), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("invocation_id", "sequence", name="pk_run_events"),
        sa.UniqueConstraint("event_id", name="uq_run_events_event_id"),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["engine_runs.run_id"],
            name="fk_run_events_run",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["run_id", "invocation_id"],
            ["command_invocations.run_id", "command_invocations.invocation_id"],
            name="fk_run_events_invocation",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.CheckConstraint(
            "length(invocation_id) = 40 AND substr(invocation_id, 1, 4) = 'inv_'",
            name="ck_run_events_invocation_id",
        ),
        sa.CheckConstraint(
            "sequence BETWEEN 1 AND 1000000",
            name="ck_run_events_sequence",
        ),
        sa.CheckConstraint(
            "length(event_id) = 40 AND substr(event_id, 1, 4) = 'evt_'",
            name="ck_run_events_event_id",
        ),
        sa.CheckConstraint(
            "length(run_id) = 40 AND substr(run_id, 1, 4) = 'run_'",
            name="ck_run_events_run_id",
        ),
        sa.CheckConstraint(
            "schema_version = '1.0.0'",
            name="ck_run_events_schema_version",
        ),
        sa.CheckConstraint(
            "protocol_version = '1.0.0'",
            name="ck_run_events_protocol_version",
        ),
        sa.CheckConstraint(
            "length(attempt_token_hash) = 64 AND NOT attempt_token_hash GLOB "
            "'*[^0-9a-f]*'",
            name="ck_run_events_attempt_token_hash",
        ),
        sa.CheckConstraint(
            "length(wire_event_hash) = 64 AND NOT wire_event_hash GLOB '*[^0-9a-f]*'",
            name="ck_run_events_wire_event_hash",
        ),
        sa.CheckConstraint(
            "length(content_hash) = 64 AND NOT content_hash GLOB '*[^0-9a-f]*'",
            name="ck_run_events_content_hash",
        ),
        sa.CheckConstraint(
            "event_type IN ('HEARTBEAT', 'PROGRESS', 'WARNING', 'DIAGNOSTIC', "
            "'ARTIFACT_PRODUCED', 'FINAL_RESULT')",
            name="ck_run_events_event_type",
        ),
        sa.CheckConstraint(
            "timestamp_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_run_events_timestamp_utc",
        ),
        sa.CheckConstraint(
            "received_at_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_run_events_received_at_utc",
        ),
        sa.CheckConstraint(
            "json_valid(payload)",
            name="ck_run_events_payload",
        ),
    )
    op.create_index("ix_run_events_event_type", "run_events", ["event_type"])
    op.create_index("ix_run_events_run_id", "run_events", ["run_id"])
    op.create_index(
        "ix_run_events_run_id_received_at_utc",
        "run_events",
        ["run_id", "received_at_utc"],
    )
    op.create_index("ix_run_events_wire_event_hash", "run_events", ["wire_event_hash"])
    op.create_table(
        "retry_decisions",
        sa.Column("logical_slot_id", sa.Text(), nullable=False),
        sa.Column("predecessor_run_id", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.Text(), nullable=False),
        sa.Column("experiment_id", sa.Text(), nullable=False),
        sa.Column("experiment_spec_hash", sa.Text(), nullable=False),
        sa.Column("retry_policy", sa.Text(), nullable=False),
        sa.Column("created_attempt_count", sa.Integer(), nullable=False),
        sa.Column("predecessor_terminal_state", sa.Text(), nullable=False),
        sa.Column("primary_terminal_diagnostic_id", sa.Text(), nullable=False),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("denial_reason", sa.Text(), nullable=True),
        sa.Column("hard_block_error_code", sa.Text(), nullable=True),
        sa.Column("availability_observation_id", sa.Text(), nullable=True),
        sa.Column("retry_not_before_utc", sa.Integer(), nullable=True),
        sa.Column("reserved_successor_attempt_number", sa.Integer(), nullable=True),
        sa.Column("decided_at_utc", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint(
            "logical_slot_id",
            "predecessor_run_id",
            name="pk_retry_decisions",
        ),
        sa.ForeignKeyConstraint(
            ["experiment_id"],
            ["experiments.experiment_id"],
            name="fk_retry_decisions_experiment",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["experiment_id", "predecessor_run_id"],
            ["engine_runs.experiment_id", "engine_runs.run_id"],
            name="fk_retry_decisions_predecessor",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["experiment_id", "logical_slot_id"],
            ["engine_slots.experiment_id", "engine_slots.logical_slot_id"],
            name="fk_retry_decisions_slot",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["availability_observation_id"],
            ["runtime_availability_observations.availability_observation_id"],
            name="fk_retry_decisions_observation",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.CheckConstraint(
            "length(logical_slot_id) = 41 AND substr(logical_slot_id, 1, 5) = 'slot_'",
            name="ck_retry_decisions_logical_slot_id",
        ),
        sa.CheckConstraint(
            "length(predecessor_run_id) = 40 AND substr(predecessor_run_id, 1, 4) = "
            "'run_'",
            name="ck_retry_decisions_predecessor_run_id",
        ),
        sa.CheckConstraint(
            "schema_version = '1.0.0'",
            name="ck_retry_decisions_schema_version",
        ),
        sa.CheckConstraint(
            "length(experiment_id) = 40 AND substr(experiment_id, 1, 4) = 'exp_'",
            name="ck_retry_decisions_experiment_id",
        ),
        sa.CheckConstraint(
            "length(experiment_spec_hash) = 64 AND NOT experiment_spec_hash GLOB "
            "'*[^0-9a-f]*'",
            name="ck_retry_decisions_experiment_spec_hash",
        ),
        sa.CheckConstraint(
            "json_valid(retry_policy)",
            name="ck_retry_decisions_retry_policy",
        ),
        sa.CheckConstraint(
            "created_attempt_count BETWEEN 1 AND 5",
            name="ck_retry_decisions_created_attempt_count",
        ),
        sa.CheckConstraint(
            "predecessor_terminal_state IN ('FAILED', 'CANCELLED', 'TIMED_OUT', "
            "'NOT_APPLICABLE', 'UNAVAILABLE')",
            name="ck_retry_decisions_predecessor_terminal_state",
        ),
        sa.CheckConstraint(
            "length(primary_terminal_diagnostic_id) = 41 AND "
            "substr(primary_terminal_diagnostic_id, 1, 5) = 'diag_'",
            name="ck_retry_decisions_primary_terminal_diagnostic_id",
        ),
        sa.CheckConstraint(
            "outcome IN ('ALLOWED', 'DENIED')",
            name="ck_retry_decisions_outcome",
        ),
        sa.CheckConstraint(
            "denial_reason IN ('ATTEMPT_BUDGET_EXHAUSTED', "
            "'TERMINAL_STATE_NOT_RETRYABLE', 'PRIMARY_DIAGNOSTIC_NOT_RETRIABLE', "
            "'HARD_BLOCKED_OUTCOME', 'EXPERIMENT_TERMINAL', "
            "'AVAILABILITY_OBSERVATION_NOT_FRESH')",
            name="ck_retry_decisions_denial_reason",
        ),
        sa.CheckConstraint(
            "length(hard_block_error_code) BETWEEN 3 AND 128",
            name="ck_retry_decisions_hard_block_error_code",
        ),
        sa.CheckConstraint(
            "length(availability_observation_id) = 42 AND "
            "substr(availability_observation_id, 1, 6) = 'avail_'",
            name="ck_retry_decisions_availability_observation_id",
        ),
        sa.CheckConstraint(
            "retry_not_before_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_retry_decisions_retry_not_before_utc",
        ),
        sa.CheckConstraint(
            "reserved_successor_attempt_number BETWEEN 2 AND 5",
            name="ck_retry_decisions_reserved_successor_attempt_number",
        ),
        sa.CheckConstraint(
            "decided_at_utc BETWEEN -62135596800000000 AND 253402300799999999",
            name="ck_retry_decisions_decided_at_utc",
        ),
        sa.CheckConstraint(
            "(outcome = 'DENIED') = (denial_reason IS NOT NULL)",
            name="ck_retry_decisions_denial_shape",
        ),
        sa.CheckConstraint(
            "(denial_reason IS 'HARD_BLOCKED_OUTCOME') = (hard_block_error_code IS NOT "
            "NULL)",
            name="ck_retry_decisions_hard_block_shape",
        ),
        sa.CheckConstraint(
            "(outcome = 'ALLOWED') = (retry_not_before_utc IS NOT NULL)",
            name="ck_retry_decisions_not_before_shape",
        ),
        sa.CheckConstraint(
            "(outcome = 'ALLOWED') = (reserved_successor_attempt_number IS NOT NULL)",
            name="ck_retry_decisions_reservation_shape",
        ),
        sa.CheckConstraint(
            "reserved_successor_attempt_number IS NULL OR "
            "reserved_successor_attempt_number = created_attempt_count + 1",
            name="ck_retry_decisions_reservation_arithmetic",
        ),
        sa.CheckConstraint(
            "(outcome = 'ALLOWED' AND predecessor_terminal_state = 'UNAVAILABLE') = "
            "(availability_observation_id IS NOT NULL)",
            name="ck_retry_decisions_observation_shape",
        ),
    )
    op.create_index(
        "ix_retry_decisions_experiment_id",
        "retry_decisions",
        ["experiment_id"],
    )
    op.create_index(
        "ix_retry_decisions_primary_terminal_diagnostic_id",
        "retry_decisions",
        ["primary_terminal_diagnostic_id"],
    )
    op.create_table(
        "artifact_owners",
        sa.Column("owner_hash", sa.Text(), nullable=False),
        sa.Column("owner_kind", sa.Text(), nullable=False),
        sa.Column("experiment_id", sa.Text(), nullable=True),
        sa.Column("run_id", sa.Text(), nullable=True),
        sa.Column("invocation_id", sa.Text(), nullable=True),
        sa.Column("dataset_id", sa.Text(), nullable=True),
        sa.Column("strategy_version_id", sa.Text(), nullable=True),
        sa.Column("strategy_version_hash", sa.Text(), nullable=True),
        sa.Column("adapter_name", sa.Text(), nullable=True),
        sa.Column("adapter_version", sa.Text(), nullable=True),
        sa.Column("engine_name", sa.Text(), nullable=True),
        sa.Column("engine_version", sa.Text(), nullable=True),
        sa.Column("core_component", sa.Text(), nullable=True),
        sa.Column("correlation_id", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("owner_hash", name="pk_artifact_owners"),
        sa.ForeignKeyConstraint(
            ["experiment_id"],
            ["experiments.experiment_id"],
            name="fk_artifact_owners_experiment",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["experiment_id", "run_id"],
            ["engine_runs.experiment_id", "engine_runs.run_id"],
            name="fk_artifact_owners_run",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["run_id", "invocation_id"],
            ["command_invocations.run_id", "command_invocations.invocation_id"],
            name="fk_artifact_owners_invocation",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["dataset_id"],
            ["datasets.dataset_id"],
            name="fk_artifact_owners_dataset",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["strategy_version_id"],
            ["strategy_versions.strategy_version_id"],
            name="fk_artifact_owners_strategy_version",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["strategy_version_hash"],
            ["strategy_versions.content_hash"],
            name="fk_artifact_owners_strategy_hash",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.CheckConstraint(
            "length(owner_hash) = 64 AND NOT owner_hash GLOB '*[^0-9a-f]*'",
            name="ck_artifact_owners_owner_hash",
        ),
        sa.CheckConstraint(
            "owner_kind IN ('RUN', 'EXPERIMENT', 'DATASET', 'STRATEGY', 'ADAPTER', "
            "'SYSTEM')",
            name="ck_artifact_owners_owner_kind",
        ),
        sa.CheckConstraint(
            "length(experiment_id) = 40 AND substr(experiment_id, 1, 4) = 'exp_'",
            name="ck_artifact_owners_experiment_id",
        ),
        sa.CheckConstraint(
            "length(run_id) = 40 AND substr(run_id, 1, 4) = 'run_'",
            name="ck_artifact_owners_run_id",
        ),
        sa.CheckConstraint(
            "length(invocation_id) = 40 AND substr(invocation_id, 1, 4) = 'inv_'",
            name="ck_artifact_owners_invocation_id",
        ),
        sa.CheckConstraint(
            "length(dataset_id) = 39 AND substr(dataset_id, 1, 3) = 'ds_'",
            name="ck_artifact_owners_dataset_id",
        ),
        sa.CheckConstraint(
            "length(strategy_version_id) = 41 AND substr(strategy_version_id, 1, 5) = "
            "'strv_'",
            name="ck_artifact_owners_strategy_version_id",
        ),
        sa.CheckConstraint(
            "length(strategy_version_hash) = 64 AND NOT strategy_version_hash GLOB "
            "'*[^0-9a-f]*'",
            name="ck_artifact_owners_strategy_version_hash",
        ),
        sa.CheckConstraint(
            "length(adapter_name) BETWEEN 1 AND 128",
            name="ck_artifact_owners_adapter_name",
        ),
        sa.CheckConstraint(
            "length(adapter_version) BETWEEN 5 AND 64",
            name="ck_artifact_owners_adapter_version",
        ),
        sa.CheckConstraint(
            "length(engine_name) BETWEEN 1 AND 128",
            name="ck_artifact_owners_engine_name",
        ),
        sa.CheckConstraint(
            "length(engine_version) BETWEEN 5 AND 64",
            name="ck_artifact_owners_engine_version",
        ),
        sa.CheckConstraint(
            "length(core_component) BETWEEN 1 AND 128",
            name="ck_artifact_owners_core_component",
        ),
        sa.CheckConstraint(
            "length(correlation_id) BETWEEN 1 AND 128",
            name="ck_artifact_owners_correlation_id",
        ),
        sa.CheckConstraint(
            "owner_kind <> 'RUN' OR (experiment_id IS NOT NULL AND run_id IS NOT NULL "
            "AND dataset_id IS NULL AND strategy_version_id IS NULL AND "
            "strategy_version_hash IS NULL AND adapter_name IS NULL AND "
            "adapter_version IS NULL AND engine_name IS NULL AND engine_version IS "
            "NULL AND core_component IS NULL AND correlation_id IS NULL)",
            name="ck_artifact_owners_run_variant",
        ),
        sa.CheckConstraint(
            "owner_kind <> 'EXPERIMENT' OR (experiment_id IS NOT NULL AND run_id IS "
            "NULL AND invocation_id IS NULL AND dataset_id IS NULL AND "
            "strategy_version_id IS NULL AND strategy_version_hash IS NULL AND "
            "adapter_name IS NULL AND adapter_version IS NULL AND engine_name IS NULL "
            "AND engine_version IS NULL AND core_component IS NULL AND correlation_id "
            "IS NULL)",
            name="ck_artifact_owners_experiment_variant",
        ),
        sa.CheckConstraint(
            "owner_kind <> 'DATASET' OR (dataset_id IS NOT NULL AND experiment_id IS "
            "NULL AND run_id IS NULL AND invocation_id IS NULL AND strategy_version_id "
            "IS NULL AND strategy_version_hash IS NULL AND adapter_name IS NULL AND "
            "adapter_version IS NULL AND engine_name IS NULL AND engine_version IS "
            "NULL AND core_component IS NULL AND correlation_id IS NULL)",
            name="ck_artifact_owners_dataset_variant",
        ),
        sa.CheckConstraint(
            "owner_kind <> 'STRATEGY' OR ((strategy_version_id IS NOT NULL) <> "
            "(strategy_version_hash IS NOT NULL) AND experiment_id IS NULL AND run_id "
            "IS NULL AND invocation_id IS NULL AND dataset_id IS NULL AND adapter_name "
            "IS NULL AND adapter_version IS NULL AND engine_name IS NULL AND "
            "engine_version IS NULL AND core_component IS NULL AND correlation_id IS "
            "NULL)",
            name="ck_artifact_owners_strategy_variant",
        ),
        sa.CheckConstraint(
            "owner_kind <> 'ADAPTER' OR (adapter_name IS NOT NULL AND adapter_version "
            "IS NOT NULL AND (engine_name IS NULL) = (engine_version IS NULL) AND "
            "experiment_id IS NULL AND run_id IS NULL AND invocation_id IS NULL AND "
            "dataset_id IS NULL AND strategy_version_id IS NULL AND "
            "strategy_version_hash IS NULL AND core_component IS NULL AND "
            "correlation_id IS NULL)",
            name="ck_artifact_owners_adapter_variant",
        ),
        sa.CheckConstraint(
            "owner_kind <> 'SYSTEM' OR (core_component IS NOT NULL AND correlation_id "
            "IS NOT NULL AND experiment_id IS NULL AND run_id IS NULL AND "
            "invocation_id IS NULL AND dataset_id IS NULL AND strategy_version_id IS "
            "NULL AND strategy_version_hash IS NULL AND adapter_name IS NULL AND "
            "adapter_version IS NULL AND engine_name IS NULL AND engine_version IS "
            "NULL)",
            name="ck_artifact_owners_system_variant",
        ),
    )
    op.create_index(
        "ix_artifact_owners_adapter_name_adapter_version",
        "artifact_owners",
        ["adapter_name", "adapter_version"],
    )
    op.create_index("ix_artifact_owners_dataset_id", "artifact_owners", ["dataset_id"])
    op.create_index(
        "ix_artifact_owners_owner_kind_experiment_id",
        "artifact_owners",
        ["owner_kind", "experiment_id"],
    )
    op.create_index(
        "ix_artifact_owners_owner_kind_run_id",
        "artifact_owners",
        ["owner_kind", "run_id"],
    )
    op.create_index(
        "ix_artifact_owners_strategy_version_hash",
        "artifact_owners",
        ["strategy_version_hash"],
    )
    for statement in schema.PARTIAL_INDEX_SQL:
        op.execute(sa.text(statement))
    for statement in schema.TRIGGER_SQL:
        op.execute(sa.text(statement))


def downgrade() -> None:
    """Drop the triggers, indexes and tables in reverse order."""
    op.execute(sa.text("DROP TRIGGER trg_command_invocations_no_delete"))
    op.execute(sa.text("DROP TRIGGER trg_engine_runs_no_delete"))
    op.execute(sa.text("DROP TRIGGER trg_experiments_no_delete"))
    op.execute(sa.text("DROP TRIGGER trg_artifact_owners_append_only_delete"))
    op.execute(sa.text("DROP TRIGGER trg_artifact_owners_append_only_update"))
    op.execute(sa.text("DROP TRIGGER trg_dataset_partitions_append_only_delete"))
    op.execute(sa.text("DROP TRIGGER trg_dataset_partitions_append_only_update"))
    op.execute(sa.text("DROP TRIGGER trg_datasets_append_only_delete"))
    op.execute(sa.text("DROP TRIGGER trg_datasets_append_only_update"))
    op.execute(sa.text("DROP TRIGGER trg_strategy_versions_append_only_delete"))
    op.execute(sa.text("DROP TRIGGER trg_strategy_versions_append_only_update"))
    op.execute(sa.text("DROP TRIGGER trg_diagnostic_causes_append_only_delete"))
    op.execute(sa.text("DROP TRIGGER trg_diagnostic_causes_append_only_update"))
    op.execute(sa.text("DROP TRIGGER trg_diagnostics_append_only_delete"))
    op.execute(sa.text("DROP TRIGGER trg_diagnostics_append_only_update"))
    op.execute(
        sa.text("DROP TRIGGER trg_runtime_availability_observations_append_only_delete")
    )
    op.execute(
        sa.text("DROP TRIGGER trg_runtime_availability_observations_append_only_update")
    )
    op.execute(sa.text("DROP TRIGGER trg_retry_decisions_append_only_delete"))
    op.execute(sa.text("DROP TRIGGER trg_retry_decisions_append_only_update"))
    op.execute(sa.text("DROP TRIGGER trg_run_events_append_only_delete"))
    op.execute(sa.text("DROP TRIGGER trg_run_events_append_only_update"))
    op.execute(sa.text("DROP TRIGGER trg_command_invocations_terminal_immutable"))
    op.execute(sa.text("DROP TRIGGER trg_engine_runs_terminal_immutable"))
    op.execute(sa.text("DROP TRIGGER trg_experiments_snapshot_frozen"))
    op.execute(sa.text("DROP TRIGGER trg_experiments_queue_requires_snapshot"))
    op.execute(sa.text("DROP TRIGGER trg_experiments_spec_frozen"))
    op.execute(sa.text("DROP TRIGGER trg_experiments_terminal_immutable"))
    op.drop_index(
        "ix_artifact_owners_strategy_version_hash",
        table_name="artifact_owners",
    )
    op.drop_index("ix_artifact_owners_owner_kind_run_id", table_name="artifact_owners")
    op.drop_index(
        "ix_artifact_owners_owner_kind_experiment_id",
        table_name="artifact_owners",
    )
    op.drop_index("ix_artifact_owners_dataset_id", table_name="artifact_owners")
    op.drop_index(
        "ix_artifact_owners_adapter_name_adapter_version",
        table_name="artifact_owners",
    )
    op.drop_table("artifact_owners")
    op.drop_index(
        "ix_retry_decisions_primary_terminal_diagnostic_id",
        table_name="retry_decisions",
    )
    op.drop_index(
        "ix_retry_decisions_pending_not_before",
        table_name="retry_decisions",
    )
    op.drop_index("ix_retry_decisions_experiment_id", table_name="retry_decisions")
    op.drop_table("retry_decisions")
    op.drop_index("ix_run_events_wire_event_hash", table_name="run_events")
    op.drop_index("ix_run_events_run_id_received_at_utc", table_name="run_events")
    op.drop_index("ix_run_events_run_id", table_name="run_events")
    op.drop_index("ix_run_events_event_type", table_name="run_events")
    op.drop_table("run_events")
    op.drop_index("uq_command_invocations_open_kind", table_name="command_invocations")
    op.drop_index(
        "ix_command_invocations_state_deadline_utc",
        table_name="command_invocations",
    )
    op.drop_index(
        "ix_command_invocations_run_kind_launch",
        table_name="command_invocations",
    )
    op.drop_index(
        "ix_command_invocations_reconciliation_listing",
        table_name="command_invocations",
    )
    op.drop_index(
        "ix_command_invocations_primary_diagnostic_id",
        table_name="command_invocations",
    )
    op.drop_index(
        "ix_command_invocations_creation_identity_pid",
        table_name="command_invocations",
    )
    op.drop_index(
        "ix_command_invocations_created_at_utc_invocation_id",
        table_name="command_invocations",
    )
    op.drop_table("command_invocations")
    op.drop_index("uq_engine_runs_active_attempt", table_name="engine_runs")
    op.drop_index("ix_engine_runs_state", table_name="engine_runs")
    op.drop_index(
        "ix_engine_runs_primary_terminal_diagnostic_id",
        table_name="engine_runs",
    )
    op.drop_index("ix_engine_runs_predecessor_run_id", table_name="engine_runs")
    op.drop_index(
        "ix_engine_runs_availability_observation_id",
        table_name="engine_runs",
    )
    op.drop_table("engine_runs")
    op.drop_index(
        "ix_dataset_partitions_raw_checksum",
        table_name="dataset_partitions",
    )
    op.drop_index(
        "ix_dataset_partitions_normalized_checksum",
        table_name="dataset_partitions",
    )
    op.drop_index(
        "ix_dataset_partitions_content_hash",
        table_name="dataset_partitions",
    )
    op.drop_table("dataset_partitions")
    op.drop_index("ix_datasets_instrument_data_type_interval", table_name="datasets")
    op.drop_table("datasets")
    op.drop_table("strategy_versions")
    op.drop_index(
        "ix_diagnostic_causes_causal_diagnostic_id",
        table_name="diagnostic_causes",
    )
    op.drop_table("diagnostic_causes")
    op.drop_index("ix_diagnostics_timestamp_utc", table_name="diagnostics")
    op.drop_index("ix_diagnostics_severity", table_name="diagnostics")
    op.drop_index("ix_diagnostics_run_id", table_name="diagnostics")
    op.drop_index("ix_diagnostics_invocation_id", table_name="diagnostics")
    op.drop_index("ix_diagnostics_experiment_id", table_name="diagnostics")
    op.drop_index("ix_diagnostics_error_code", table_name="diagnostics")
    op.drop_index("ix_diagnostics_category", table_name="diagnostics")
    op.drop_table("diagnostics")
    op.drop_index(
        "ix_runtime_availability_observations_adapter_executable",
        table_name="runtime_availability_observations",
    )
    op.drop_index(
        "ix_runtime_availability_observations_adapter_available",
        table_name="runtime_availability_observations",
    )
    op.drop_table("runtime_availability_observations")
    op.drop_index("ix_engine_slots_adapter_engine", table_name="engine_slots")
    op.drop_table("engine_slots")
    op.drop_index("ix_experiments_strategy_version_hash", table_name="experiments")
    op.drop_index("ix_experiments_state_created_at_utc", table_name="experiments")
    op.drop_index("ix_experiments_dataset_version_hash", table_name="experiments")
    op.drop_table("experiments")
