"""The declarative metadata against the migrated database (plan 3.3, 3.4, 6.4).

Plan Task 2 Step 1: a migrated database has no metadata drift and exactly the
pinned ``sqlite_master`` objects; every table, index and trigger name of sections
3.3 and 3.4 is present (pinned here as literals, independently of the derivation
in ``schema.py``); ``engine_slots`` is keyed ``(experiment_id, logical_slot_id)``,
``engine_runs`` carries the unique triple and no unscoped
``(logical_slot_id, attempt_number)`` index exists (reading 7); every foreign key
is ``RESTRICT`` and ``PRAGMA foreign_key_check`` is empty after the upgrade; the
enum CHECKs are generated from the domain enumerations; the drift and object
checks are proven able to fail. The SHA-256 of the normalized expectation is a
literal pin so a change to either definition -- the metadata or the baseline
revision -- needs a conscious re-pin.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Final

import pytest
from sqlalchemy import CheckConstraint, text
from sqlalchemy.engine import Connection

from crypto_lab.adapters.vocabulary import ProtocolEventType
from crypto_lab.datasets import DatasetDataType, DatasetValidationStatus
from crypto_lab.domain.descriptors import OperatingSystem
from crypto_lab.domain.diagnostics import DiagnosticCategory, DiagnosticSeverity
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
    ProcessExitCategory,
    RetryTerminalState,
)
from crypto_lab.domain.retry import RetryDecisionOutcome, RetryDenialReason
from crypto_lab.persistence import schema
from crypto_lab.persistence.database import SqliteDatabase
from crypto_lab.persistence.migration_runner import metadata_drift, schema_objects
from crypto_lab.persistence.schema import (
    EXPECTED_SCHEMA_OBJECTS,
    PARTIAL_INDEX_SQL,
    TABLES_IN_DEPENDENCY_ORDER,
    TRIGGER_SQL,
    ArtifactOwnerRow,
    CommandInvocationRow,
    DatasetPartitionRow,
    DatasetRow,
    DiagnosticCauseRow,
    DiagnosticRow,
    EngineRunRow,
    EngineSlotRow,
    ExperimentRow,
    RetryDecisionRow,
    RunEventRow,
    RuntimeAvailabilityObservationRow,
    StrategyVersionRow,
    normalized_sql,
)
from persistence_support.harness import raw_connection

#: The SHA-256 of ``repr(EXPECTED_SCHEMA_OBJECTS)``; re-pinned consciously when
#: the reviewed schema changes.
_EXPECTED_OBJECTS_DIGEST: Final = (
    "814d5a92983ae31a8497666b40386695c6819908edd7d85419e255f3c0b8bc44"
)
#: Plan 6.4: the thirteen tables in dependency order.
_TABLES: Final = (
    "experiments",
    "engine_slots",
    "runtime_availability_observations",
    "diagnostics",
    "diagnostic_causes",
    "strategy_versions",
    "datasets",
    "dataset_partitions",
    "engine_runs",
    "command_invocations",
    "run_events",
    "retry_decisions",
    "artifact_owners",
)
_ROW_CLASSES: Final = (
    ExperimentRow,
    EngineSlotRow,
    RuntimeAvailabilityObservationRow,
    DiagnosticRow,
    DiagnosticCauseRow,
    StrategyVersionRow,
    DatasetRow,
    DatasetPartitionRow,
    EngineRunRow,
    CommandInvocationRow,
    RunEventRow,
    RetryDecisionRow,
    ArtifactOwnerRow,
)
#: Plan 3.3: every plain and partial index by name (literal pin).
_INDEXES: Final = frozenset(
    {
        "ix_experiments_state_created_at_utc",
        "ix_experiments_strategy_version_hash",
        "ix_experiments_dataset_version_hash",
        "ix_engine_slots_adapter_engine",
        "ix_runtime_availability_observations_adapter_executable",
        "ix_runtime_availability_observations_adapter_available",
        "ix_diagnostics_error_code",
        "ix_diagnostics_category",
        "ix_diagnostics_severity",
        "ix_diagnostics_experiment_id",
        "ix_diagnostics_run_id",
        "ix_diagnostics_invocation_id",
        "ix_diagnostics_timestamp_utc",
        "ix_diagnostic_causes_causal_diagnostic_id",
        "ix_datasets_instrument_data_type_interval",
        "ix_dataset_partitions_content_hash",
        "ix_dataset_partitions_raw_checksum",
        "ix_dataset_partitions_normalized_checksum",
        "ix_engine_runs_state",
        "ix_engine_runs_predecessor_run_id",
        "ix_engine_runs_primary_terminal_diagnostic_id",
        "ix_engine_runs_availability_observation_id",
        "uq_engine_runs_active_attempt",
        "ix_command_invocations_state_deadline_utc",
        "ix_command_invocations_run_kind_launch",
        "ix_command_invocations_creation_identity_pid",
        "ix_command_invocations_reconciliation_listing",
        "ix_command_invocations_created_at_utc_invocation_id",
        "ix_command_invocations_primary_diagnostic_id",
        "uq_command_invocations_open_kind",
        "ix_run_events_run_id_received_at_utc",
        "ix_run_events_event_type",
        "ix_run_events_wire_event_hash",
        "ix_run_events_run_id",
        "ix_retry_decisions_pending_not_before",
        "ix_retry_decisions_experiment_id",
        "ix_retry_decisions_primary_terminal_diagnostic_id",
        "ix_artifact_owners_owner_kind_experiment_id",
        "ix_artifact_owners_owner_kind_run_id",
        "ix_artifact_owners_dataset_id",
        "ix_artifact_owners_strategy_version_hash",
        "ix_artifact_owners_adapter_name_adapter_version",
    }
)
_APPEND_ONLY_TABLES: Final = (
    "run_events",
    "retry_decisions",
    "runtime_availability_observations",
    "diagnostics",
    "diagnostic_causes",
    "strategy_versions",
    "datasets",
    "dataset_partitions",
    "artifact_owners",
)
_NO_DELETE_TABLES: Final = ("experiments", "engine_runs", "command_invocations")
#: Plan 3.4: every trigger by name (literal pin; T-APPEND-ONLY is two statements
#: per table because SQLite admits one event per trigger).
_TRIGGERS: Final = frozenset(
    {
        "trg_experiments_terminal_immutable",
        "trg_experiments_spec_frozen",
        "trg_experiments_queue_requires_snapshot",
        "trg_experiments_snapshot_frozen",
        "trg_engine_runs_terminal_immutable",
        "trg_command_invocations_terminal_immutable",
        *(f"trg_{table}_append_only_update" for table in _APPEND_ONLY_TABLES),
        *(f"trg_{table}_append_only_delete" for table in _APPEND_ONLY_TABLES),
        *(f"trg_{table}_no_delete" for table in _NO_DELETE_TABLES),
    }
)
#: Plan 3.3: the foreign-key count per table (every one ``RESTRICT``).
_FOREIGN_KEY_COUNTS: Final = {
    "experiments": 0,
    "engine_slots": 1,
    "runtime_availability_observations": 0,
    "diagnostics": 0,
    "diagnostic_causes": 2,
    "strategy_versions": 0,
    "datasets": 0,
    "dataset_partitions": 1,
    "engine_runs": 4,
    "command_invocations": 1,
    "run_events": 2,
    "retry_decisions": 4,
    "artifact_owners": 6,
}


def _names(connection: Connection, kind: str) -> set[str]:
    rows = connection.execute(
        text("SELECT name FROM sqlite_master WHERE type = :kind"), {"kind": kind}
    ).scalars()
    return {str(name) for name in rows}


def _index_columns(connection: Connection, table: str) -> dict[str, list[str]]:
    columns: dict[str, list[str]] = {}
    for index in connection.execute(text(f"PRAGMA index_list({table})")).all():
        name = str(index._mapping["name"])
        info = connection.execute(text(f"PRAGMA index_info({name})")).all()
        columns[name] = [str(row._mapping["name"]) for row in info]
    return columns


def _primary_key(connection: Connection, table: str) -> list[str]:
    rows = connection.execute(text(f"PRAGMA table_info({table})")).all()
    keyed = [row for row in rows if int(row._mapping["pk"]) > 0]
    keyed.sort(key=lambda row: int(row._mapping["pk"]))
    return [str(row._mapping["name"]) for row in keyed]


def _check_text(table: str, name: str) -> str:
    for constraint in schema.metadata.tables[table].constraints:
        if isinstance(constraint, CheckConstraint) and constraint.name == name:
            return str(constraint.sqltext)
    raise AssertionError(f"{table} has no CHECK named {name}")


# --------------------------------------------------------------------------
# The pinned objects (plan 6.4; the sketch test)
# --------------------------------------------------------------------------


def test_a_migrated_database_has_no_metadata_drift_and_the_pinned_objects(
    sqlite_database: SqliteDatabase,
) -> None:
    with sqlite_database.read_only() as connection:
        assert metadata_drift(connection) == ()
        assert schema_objects(connection) == EXPECTED_SCHEMA_OBJECTS


def test_the_pinned_objects_digest_is_the_reviewed_value() -> None:
    digest = hashlib.sha256(repr(EXPECTED_SCHEMA_OBJECTS).encode("utf-8")).hexdigest()
    assert digest == _EXPECTED_OBJECTS_DIGEST, digest


def test_the_pinned_objects_name_every_plan_object_and_nothing_else() -> None:
    """The derived expectation and the literal plan pins agree: thirteen tables
    plus ``alembic_version``, every index and trigger name, nothing more."""
    tables = {row.name for row in EXPECTED_SCHEMA_OBJECTS if row.type == "table"}
    indexes = {row.name for row in EXPECTED_SCHEMA_OBJECTS if row.type == "index"}
    triggers = {row.name for row in EXPECTED_SCHEMA_OBJECTS if row.type == "trigger"}
    assert tables == {*_TABLES, "alembic_version"}
    assert indexes == _INDEXES
    assert triggers == _TRIGGERS
    assert len(EXPECTED_SCHEMA_OBJECTS) == 14 + len(_INDEXES) + len(_TRIGGERS)
    assert list(EXPECTED_SCHEMA_OBJECTS) == sorted(
        EXPECTED_SCHEMA_OBJECTS, key=lambda row: (row.type, row.table, row.name)
    )
    for row in EXPECTED_SCHEMA_OBJECTS:
        assert row.sql == normalized_sql(row.sql)
        assert row.sql.startswith(f"CREATE {row.type.upper()}") or row.sql.startswith(
            f"CREATE UNIQUE {row.type.upper()}"
        )


def test_every_table_index_and_trigger_of_the_plan_is_present(
    sqlite_database: SqliteDatabase,
) -> None:
    with sqlite_database.read_only() as connection:
        assert _names(connection, "table") == {*_TABLES, "alembic_version"}
        indexes = _names(connection, "index")
        assert {name for name in indexes if not name.startswith("sqlite_")} == _INDEXES
        assert _names(connection, "trigger") == _TRIGGERS
        assert _names(connection, "view") == set()


def test_the_row_classes_map_exactly_the_thirteen_tables() -> None:
    assert TABLES_IN_DEPENDENCY_ORDER == _TABLES
    assert set(schema.metadata.tables) == set(_TABLES)
    assert tuple(row.__tablename__ for row in _ROW_CLASSES) == _TABLES
    for row in _ROW_CLASSES:
        assert schema.metadata.tables[row.__tablename__] is row.__table__


def test_partial_indexes_and_triggers_are_created_from_the_exported_constants(
    sqlite_database: SqliteDatabase,
) -> None:
    """Plan 6.4: the revision executes the constants ``schema.py`` exports, so the
    stored SQL is their normalized text."""
    with sqlite_database.read_only() as connection:
        stored = {row.sql for row in schema_objects(connection)}
    assert len(PARTIAL_INDEX_SQL) == 3
    assert len(TRIGGER_SQL) == len(_TRIGGERS)
    for statement in (*PARTIAL_INDEX_SQL, *TRIGGER_SQL):
        assert normalized_sql(statement) in stored
    assert all(" WHERE " in statement for statement in PARTIAL_INDEX_SQL)


# --------------------------------------------------------------------------
# Keys and foreign keys (reading 7; plan 3.3)
# --------------------------------------------------------------------------


def test_engine_slots_is_keyed_by_experiment_and_slot_and_runs_carry_the_triple(
    sqlite_database: SqliteDatabase,
) -> None:
    with sqlite_database.read_only() as connection:
        assert _primary_key(connection, "engine_slots") == [
            "experiment_id",
            "logical_slot_id",
        ]
        assert _primary_key(connection, "engine_runs") == ["run_id"]
        run_indexes = _index_columns(connection, "engine_runs")
        assert ["experiment_id", "logical_slot_id", "attempt_number"] in list(
            run_indexes.values()
        )
        assert ["logical_slot_id", "attempt_number"] not in list(run_indexes.values())
        assert run_indexes["uq_engine_runs_active_attempt"] == [
            "experiment_id",
            "logical_slot_id",
        ]
        slot_indexes = _index_columns(connection, "engine_slots")
        assert ["experiment_id", "slot_ordinal"] in list(slot_indexes.values())
        assert _primary_key(connection, "retry_decisions") == [
            "logical_slot_id",
            "predecessor_run_id",
        ]
        assert _primary_key(connection, "run_events") == ["invocation_id", "sequence"]
        assert _primary_key(connection, "diagnostic_causes") == [
            "diagnostic_id",
            "causal_diagnostic_id",
        ]


def test_every_foreign_key_restricts_and_the_check_is_empty(
    sqlite_database: SqliteDatabase,
) -> None:
    with sqlite_database.read_only() as connection:
        assert connection.execute(text("PRAGMA foreign_key_check")).all() == []
        for table in _TABLES:
            rows = connection.execute(text(f"PRAGMA foreign_key_list({table})")).all()
            keys = {int(row._mapping["id"]) for row in rows}
            assert len(keys) == _FOREIGN_KEY_COUNTS[table], table
            for row in rows:
                assert row._mapping["on_update"] == "RESTRICT", (table, tuple(row))
                assert row._mapping["on_delete"] == "RESTRICT", (table, tuple(row))
        run_keys = connection.execute(
            text("PRAGMA foreign_key_list(engine_runs)")
        ).all()
        composite = [
            (str(row._mapping["table"]), str(row._mapping["from"])) for row in run_keys
        ]
        assert ("engine_slots", "experiment_id") in composite
        assert ("engine_slots", "logical_slot_id") in composite


# --------------------------------------------------------------------------
# Generated CHECK vocabularies (encoding E2; plan 3.3)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("table", "name", "members"),
    [
        ("experiments", "ck_experiments_state", ExperimentState),
        ("engine_runs", "ck_engine_runs_state", EngineRunState),
        ("engine_runs", "ck_engine_runs_retry_reason", RetryTerminalState),
        ("command_invocations", "ck_command_invocations_state", CommandInvocationState),
        ("command_invocations", "ck_command_invocations_command_kind", CommandKind),
        (
            "command_invocations",
            "ck_command_invocations_process_exit_category",
            ProcessExitCategory,
        ),
        (
            "runtime_availability_observations",
            "ck_runtime_availability_observations_operating_system",
            OperatingSystem,
        ),
        ("diagnostics", "ck_diagnostics_severity", DiagnosticSeverity),
        ("diagnostics", "ck_diagnostics_category", DiagnosticCategory),
        ("run_events", "ck_run_events_event_type", ProtocolEventType),
        ("datasets", "ck_datasets_data_type", DatasetDataType),
        ("datasets", "ck_datasets_validation_status", DatasetValidationStatus),
        ("retry_decisions", "ck_retry_decisions_outcome", RetryDecisionOutcome),
        ("retry_decisions", "ck_retry_decisions_denial_reason", RetryDenialReason),
    ],
)
def test_enum_checks_are_generated_from_the_domain_enumerations(
    table: str, name: str, members: type[StrEnum]
) -> None:
    expression = _check_text(table, name)
    for member in members:
        assert f"'{member.value}'" in expression
    assert expression.count("'") == 2 * len(list(members))


def test_the_terminal_experiment_trigger_names_exactly_the_terminal_states() -> None:
    trigger = next(
        statement
        for statement in TRIGGER_SQL
        if "trg_experiments_terminal_immutable" in statement
    )
    for member in ExperimentState:
        assert (f"'{member.value}'" in trigger) is (
            member
            in {
                ExperimentState.COMPLETED,
                ExperimentState.COMPLETED_WITH_WARNINGS,
                ExperimentState.FAILED,
                ExperimentState.CANCELLED,
            }
        )


# --------------------------------------------------------------------------
# Negative controls: the drift and object checks can fail
# --------------------------------------------------------------------------


def test_metadata_drift_names_a_dropped_index_and_an_added_column(
    sqlite_database: SqliteDatabase,
) -> None:
    connection = raw_connection(sqlite_database.path)
    try:
        connection.execute("DROP INDEX ix_diagnostics_severity")
        connection.execute("ALTER TABLE datasets ADD COLUMN probe_column INTEGER")
    finally:
        connection.close()
    with sqlite_database.read_only() as reader:
        drift = metadata_drift(reader)
    assert drift != ()
    assert any("ix_diagnostics_severity" in line for line in drift)
    assert any("probe_column" in line for line in drift)
    assert all("\n" not in line for line in drift)


def test_schema_objects_reports_a_planted_table_and_a_dropped_trigger(
    sqlite_database: SqliteDatabase,
) -> None:
    connection = raw_connection(sqlite_database.path)
    try:
        connection.execute("CREATE TABLE crash_probe (x INTEGER)")
        connection.execute("DROP TRIGGER trg_diagnostics_append_only_delete")
    finally:
        connection.close()
    with sqlite_database.read_only() as reader:
        objects = schema_objects(reader)
    assert objects != EXPECTED_SCHEMA_OBJECTS
    names = {row.name for row in objects}
    assert "crash_probe" in names
    assert "trg_diagnostics_append_only_delete" not in names


def test_normalized_sql_collapses_whitespace_only() -> None:
    assert normalized_sql("CREATE TABLE  t (\n\tx INTEGER\n)\n") == (
        "CREATE TABLE t ( x INTEGER )"
    )
    assert normalized_sql("  a   b ") == "a b"
