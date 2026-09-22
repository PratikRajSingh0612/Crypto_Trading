"""Declarative metadata of the thirteen Stage 8 tables (plan sections 3.3-3.5, 6.4).

One ``*Row`` declarative class per table of plan section 3.3, with every CHECK,
UNIQUE, primary-key and ``RESTRICT`` foreign-key constraint inline and every plain
index of that section, in the dependency order of section 6.4. The mappings are
SQLAlchemy metadata and nothing else: no canonical model is subclassed or edited,
no ORM session or identity map exists (reading 1), and the repositories of later
tasks issue Core statements against ``metadata.tables``. Column encodings follow
section 3.2 -- ``TEXT`` for identifiers, hashes, enum text, canonical decimal text
and canonical-JSON snapshots; ``INTEGER`` for booleans (``0``/``1``), bounded
integers and UTC instants as microseconds since the epoch -- and every
state-governed presence rule of the records is repeated as a CHECK over the
``NULL``-ness of the nullable columns (rule N3). Enum CHECK lists are generated
from the domain enumerations at metadata build time so they can never drift
(rule E2); the integer bounds are the records' own ``MAX_*`` constants.

Three definitions are exported for the baseline revision and the runner:
``PARTIAL_INDEX_SQL`` (the three partial unique indexes, compiled from the
``Index`` objects declared here), ``TRIGGER_SQL`` (the section 3.4 triggers; the
append-only rule is two statements per table because SQLite admits one event per
trigger) and ``EXPECTED_SCHEMA_OBJECTS``, the ``sqlite_master`` expectation a
migrated database must equal: every table (Alembic's default ``alembic_version``
included as a literal), index and trigger with its whitespace-normalized SQL,
derived from this metadata with the SQLite DDL compiler. The baseline revision
spells out its own ``op.create_table``/``op.create_index`` DDL -- a frozen copy,
so a later change here cannot silently redefine ``r0001`` -- and the Task 2
equality test is therefore a real cross-check of the two definitions; Alembic's
metadata comparison covers columns, indexes, keys and constraints it can see,
and the pinned SQL covers its SQLite blind spots (CHECK expressions, trigger
DDL, partial-index ``WHERE``). Every constraint and index carries an explicit
name (``pk_``, ``uq_``, ``fk_``, ``ck_``, ``ix_``, ``trg_``) so a refused statement
names the rule that refused it. Building the metadata performs no I/O.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum
from typing import Final, NamedTuple, get_args

from sqlalchemy import (
    CheckConstraint,
    ForeignKeyConstraint,
    Index,
    Integer,
    MetaData,
    PrimaryKeyConstraint,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects import sqlite
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.schema import CreateIndex, CreateTable

from crypto_lab.adapters.limits import MAX_SEQUENCE
from crypto_lab.adapters.vocabulary import ProtocolEventType
from crypto_lab.artifacts.ownership import (
    AdapterArtifactOwner,
    DatasetArtifactOwner,
    ExperimentArtifactOwner,
    RunArtifactOwner,
    StrategyArtifactOwner,
    SystemArtifactOwner,
)
from crypto_lab.configuration.models import MAX_CONFIGURATION_BYTES
from crypto_lab.datasets import DatasetDataType, DatasetValidationStatus
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.command_invocation import (
    MAX_DESCRIBE_TIMEOUT_SECONDS,
    MAX_DIAGNOSTIC_IDS,
    MAX_NATIVE_EXIT_VALUE,
    MAX_PID,
    MAX_RUN_TIMEOUT_SECONDS,
    MAX_VALIDATE_TIMEOUT_SECONDS,
    MIN_NATIVE_EXIT_VALUE,
    MIN_TIMEOUT_SECONDS,
)
from crypto_lab.domain.descriptors import (
    MAX_EXECUTABLE_PATH_CHARACTERS,
    OperatingSystem,
)
from crypto_lab.domain.diagnostics import (
    MAX_DETAIL_BYTES,
    DiagnosticCategory,
    DiagnosticSeverity,
)
from crypto_lab.domain.experiment import MAX_SLOT_ORDINAL
from crypto_lab.domain.lifecycle import (
    RECOGNIZED_NATIVE_EXIT_VALUES,
    TERMINAL_COMMAND_INVOCATION_STATES,
    TERMINAL_ENGINE_RUN_STATES,
    TERMINAL_EXPERIMENT_STATES,
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
    ProcessExitCategory,
    RetryTerminalState,
    process_exit_category_for,
)
from crypto_lab.domain.retry import (
    MAX_ATTEMPTS_PER_SLOT,
    RetryDecisionOutcome,
    RetryDenialReason,
)
from crypto_lab.strategy.versioning import STRATEGY_VERSION_PROFILE_VERSION

__all__ = [
    "EXPECTED_SCHEMA_OBJECTS",
    "PARTIAL_INDEX_SQL",
    "TABLES_IN_DEPENDENCY_ORDER",
    "TRIGGER_SQL",
    "ArtifactOwnerRow",
    "CommandInvocationRow",
    "DatasetPartitionRow",
    "DatasetRow",
    "DiagnosticCauseRow",
    "DiagnosticRow",
    "EngineRunRow",
    "EngineSlotRow",
    "ExperimentRow",
    "RetryDecisionRow",
    "RowBase",
    "RunEventRow",
    "RuntimeAvailabilityObservationRow",
    "SchemaObject",
    "StrategyVersionRow",
    "metadata",
    "normalized_sql",
]

#: The envelope literal every persisted record carries (spec 10.4).
_SCHEMA_VERSION: Final = "1.0.0"
#: Encoding E5: ``0001-01-01T00:00:00Z`` through ``9999-12-31T23:59:59.999999Z``
#: as microseconds since the Unix epoch, the domain's own calendar grammar.
_MIN_INSTANT_MICROS: Final = -62_135_596_800_000_000
_MAX_INSTANT_MICROS: Final = 253_402_300_799_999_999
_MICROS_PER_SECOND: Final = 1_000_000
_MAX_IDENTIFIER_TEXT: Final = 128
_MIN_SEMVER_TEXT: Final = 5
_MAX_SEMVER_TEXT: Final = 64
_MAX_BOUNDED_TEXT: Final = 1024
_MIN_ERROR_CODE_TEXT: Final = 3
_MAX_ERROR_CODE_TEXT: Final = 128
_MAX_ASSET_CODE_TEXT: Final = 32
_MIN_INSTRUMENT_TEXT: Final = 10
_MAX_INSTRUMENT_TEXT: Final = 107
_MAX_TIMEFRAME_TEXT: Final = 16
_MAX_CAUSAL_DIAGNOSTIC_IDS: Final = 32
_UUID_TEXT_LENGTH: Final = 36
#: The section 3.3.4 non-terminal partition and the section 3.3.6 restriction.
_NON_SUCCESS_TERMINAL_RUN_STATES: Final = frozenset(
    {
        EngineRunState.FAILED,
        EngineRunState.CANCELLED,
        EngineRunState.TIMED_OUT,
        EngineRunState.NOT_APPLICABLE,
        EngineRunState.UNAVAILABLE,
    }
)
_ACTIVE_RUN_STATES: Final = frozenset(
    {
        EngineRunState.PENDING,
        EngineRunState.VALIDATING,
        EngineRunState.READY,
        EngineRunState.STARTING,
        EngineRunState.RUNNING,
    }
)
_OBSERVATION_PROHIBITED_RUN_STATES: Final = frozenset(
    {EngineRunState.PENDING, EngineRunState.VALIDATING}
)
_OBSERVATION_REQUIRED_RUN_STATES: Final = frozenset(
    {
        EngineRunState.READY,
        EngineRunState.STARTING,
        EngineRunState.RUNNING,
        EngineRunState.SUCCEEDED,
        EngineRunState.SUCCEEDED_WITH_WARNINGS,
        EngineRunState.UNAVAILABLE,
    }
)
_OPEN_INVOCATION_STATES: Final = frozenset(
    {
        CommandInvocationState.PENDING,
        CommandInvocationState.STARTING,
        CommandInvocationState.RUNNING,
    }
)
_PRE_QUEUE_EXPERIMENT_STATES: Final = frozenset(
    {ExperimentState.DRAFT, ExperimentState.VALIDATED}
)
_COMMAND_DIAGNOSTIC_CATEGORIES: Final = frozenset(
    {
        DiagnosticCategory.ENGINE_RUNTIME,
        DiagnosticCategory.PROTOCOL,
        DiagnosticCategory.TIMEOUT,
        DiagnosticCategory.CANCELLATION,
    }
)


def _owner_kind(owner: type[CanonicalModel]) -> str:
    """The ``owner_kind`` literal of one ``ArtifactOwnerRef`` variant (rule E2)."""
    (kind,) = get_args(owner.model_fields["owner_kind"].annotation)
    return str(kind)


#: The six ``ArtifactOwnerRef`` variants in the plan 3.3.12 order, their kinds
#: read from the discriminator literals so the CHECK list cannot drift.
_OWNER_KINDS: Final = tuple(
    _owner_kind(owner)
    for owner in (
        RunArtifactOwner,
        ExperimentArtifactOwner,
        DatasetArtifactOwner,
        StrategyArtifactOwner,
        AdapterArtifactOwner,
        SystemArtifactOwner,
    )
)
_SNAPSHOT_COLUMNS: Final = (
    "configuration_snapshot_schema_version",
    "configuration_snapshot_json",
    "configuration_audit_hash",
    "material_base_configuration_hash",
)
_FROZEN_SPEC_COLUMNS: Final = (
    "spec",
    "spec_hash",
    "strategy_version_hash",
    "dataset_version_hash",
)
_PROCESS_COLUMNS: Final = (
    "process_started_at_utc",
    "pid",
    "creation_identity",
    "executable_path",
    "executable_hash",
    "supervisor_instance_id",
)
#: Alembic's default version table, created and maintained only by the runner
#: (plan 3.3.13, 6.4); pinned as a literal because this module imports no Alembic.
_ALEMBIC_VERSION_SQL: Final = (
    "CREATE TABLE alembic_version ( version_num VARCHAR(32) NOT NULL, "
    "CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num) )"
)
_DIALECT: Final = sqlite.dialect()

TABLES_IN_DEPENDENCY_ORDER: Final[tuple[str, ...]] = (
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


# --------------------------------------------------------------------------
# CHECK expression builders (encodings E1-E8, rule N3)
# --------------------------------------------------------------------------


def _quoted(values: Iterable[str]) -> str:
    return ", ".join(f"'{value}'" for value in values)


def _members(enumeration: type[StrEnum]) -> tuple[str, ...]:
    return tuple(member.value for member in enumeration)


def _subset(enumeration: type[StrEnum], members: frozenset[StrEnum]) -> str:
    """The members of ``enumeration`` inside ``members``, in declaration order."""
    return _quoted(member.value for member in enumeration if member in members)


def _enum(column: str, enumeration: type[StrEnum]) -> str:
    return f"{column} IN ({_quoted(_members(enumeration))})"


def _in(column: str, enumeration: type[StrEnum], members: frozenset[StrEnum]) -> str:
    return f"{column} IN ({_subset(enumeration, members)})"


def _identifier(column: str, prefix: str) -> str:
    length = len(prefix) + _UUID_TEXT_LENGTH
    return (
        f"length({column}) = {length} AND "
        f"substr({column}, 1, {len(prefix)}) = '{prefix}'"
    )


def _hash(column: str) -> str:
    return f"length({column}) = 64 AND NOT {column} GLOB '*[^0-9a-f]*'"


def _bounded_text(column: str, minimum: int, maximum: int) -> str:
    return f"length({column}) BETWEEN {minimum} AND {maximum}"


def _bounded_integer(column: str, minimum: int, maximum: int) -> str:
    return f"{column} BETWEEN {minimum} AND {maximum}"


def _instant(column: str) -> str:
    return _bounded_integer(column, _MIN_INSTANT_MICROS, _MAX_INSTANT_MICROS)


def _boolean(column: str) -> str:
    return f"{column} IN (0, 1)"


def _json(column: str) -> str:
    return f"json_valid({column})"


def _json_array(column: str, bound: int) -> str:
    return (
        f"json_valid({column}) AND json_type({column}) = 'array' "
        f"AND json_array_length({column}) <= {bound}"
    )


def _literal(column: str, value: str) -> str:
    return f"{column} = '{value}'"


def _present(column: str) -> str:
    return f"{column} IS NOT NULL"


def _absent(column: str) -> str:
    return f"{column} IS NULL"


def _same_presence(columns: Iterable[str]) -> str:
    """Every column ``NULL`` or every column present (rule N5)."""
    first, *rest = columns
    return " AND ".join(f"({_absent(first)}) = ({_absent(other)})" for other in rest)


def _check(table: str, name: str, expression: str) -> CheckConstraint:
    return CheckConstraint(expression, name=f"ck_{table}_{name}")


def _restrict(
    table: str,
    name: str,
    columns: list[str],
    referred: list[str],
) -> ForeignKeyConstraint:
    return ForeignKeyConstraint(
        columns,
        referred,
        name=f"fk_{table}_{name}",
        ondelete="RESTRICT",
        onupdate="RESTRICT",
    )


def _exit_category_case() -> str:
    """Encoding of ``process_exit_category_for`` as a ``CASE`` (section 3.3.4)."""
    branches = " ".join(
        f"WHEN {value} THEN '{process_exit_category_for(value).value}'"
        for value in sorted(RECOGNIZED_NATIVE_EXIT_VALUES)
    )
    fallback = process_exit_category_for(-1).value
    return f"CASE native_exit_value {branches} ELSE '{fallback}' END"


#: The quoted member lists several CHECKs and triggers share (section 3.3, 3.4).
_COMMAND_CATEGORY_LIST: Final = _subset(
    DiagnosticCategory, _COMMAND_DIAGNOSTIC_CATEGORIES
)
_TERMINAL_INVOCATION_LIST: Final = _subset(
    CommandInvocationState, TERMINAL_COMMAND_INVOCATION_STATES
)
_TERMINAL_EXPERIMENT_LIST: Final = _subset(ExperimentState, TERMINAL_EXPERIMENT_STATES)


def _text_column(*, nullable: bool = False) -> Mapped[str]:
    return mapped_column(Text, nullable=nullable)


def _optional_text_column() -> Mapped[str | None]:
    return mapped_column(Text, nullable=True)


def _integer_column() -> Mapped[int]:
    return mapped_column(Integer, nullable=False)


def _optional_integer_column() -> Mapped[int | None]:
    return mapped_column(Integer, nullable=True)


metadata: Final = MetaData()


class RowBase(DeclarativeBase):
    """The declarative base of every Stage 8 table; ``metadata`` is the registry."""

    metadata = metadata


# --------------------------------------------------------------------------
# 3.3.1 experiments
# --------------------------------------------------------------------------


class ExperimentRow(RowBase):
    """Plan 3.3.1: ``ExperimentRecord`` plus the four frozen-snapshot columns."""

    __tablename__ = "experiments"

    experiment_id: Mapped[str] = _text_column()
    schema_version: Mapped[str] = _text_column()
    state: Mapped[str] = _text_column()
    spec: Mapped[str] = _text_column()
    spec_hash: Mapped[str] = _text_column()
    strategy_version_hash: Mapped[str] = _text_column()
    dataset_version_hash: Mapped[str] = _text_column()
    slot_compatibility: Mapped[str | None] = _optional_text_column()
    cancellation_correlation_id: Mapped[str | None] = _optional_text_column()
    created_at_utc: Mapped[int] = _integer_column()
    updated_at_utc: Mapped[int] = _integer_column()
    revision: Mapped[int] = _integer_column()
    configuration_snapshot_schema_version: Mapped[str | None] = _optional_text_column()
    configuration_snapshot_json: Mapped[str | None] = _optional_text_column()
    configuration_audit_hash: Mapped[str | None] = _optional_text_column()
    material_base_configuration_hash: Mapped[str | None] = _optional_text_column()

    __table_args__ = (
        PrimaryKeyConstraint("experiment_id", name="pk_experiments"),
        _check("experiments", "experiment_id", _identifier("experiment_id", "exp_")),
        _check(
            "experiments",
            "schema_version",
            _literal("schema_version", _SCHEMA_VERSION),
        ),
        _check("experiments", "state", _enum("state", ExperimentState)),
        _check("experiments", "spec", _json("spec")),
        _check("experiments", "spec_hash", _hash("spec_hash")),
        _check("experiments", "strategy_version_hash", _hash("strategy_version_hash")),
        _check("experiments", "dataset_version_hash", _hash("dataset_version_hash")),
        _check("experiments", "slot_compatibility", _json("slot_compatibility")),
        _check(
            "experiments",
            "cancellation_correlation_id",
            _bounded_text("cancellation_correlation_id", 1, _MAX_IDENTIFIER_TEXT),
        ),
        _check("experiments", "created_at_utc", _instant("created_at_utc")),
        _check("experiments", "updated_at_utc", _instant("updated_at_utc")),
        _check("experiments", "revision", "revision >= 0"),
        _check(
            "experiments",
            "configuration_snapshot_schema_version",
            _literal("configuration_snapshot_schema_version", _SCHEMA_VERSION),
        ),
        _check(
            "experiments",
            "configuration_snapshot_json",
            f"{_json('configuration_snapshot_json')} AND "
            "length(CAST(configuration_snapshot_json AS BLOB)) <= "
            f"{MAX_CONFIGURATION_BYTES}",
        ),
        _check(
            "experiments",
            "configuration_audit_hash",
            _hash("configuration_audit_hash"),
        ),
        _check(
            "experiments",
            "material_base_configuration_hash",
            _hash("material_base_configuration_hash"),
        ),
        _check(
            "experiments", "updated_after_created", "updated_at_utc >= created_at_utc"
        ),
        _check(
            "experiments",
            "compatibility_shape",
            "CASE WHEN "
            f"{_in('state', ExperimentState, _PRE_QUEUE_EXPERIMENT_STATES)} "
            f"THEN {_absent('slot_compatibility')} "
            f"WHEN state = '{ExperimentState.CANCELLED.value}' THEN 1 "
            f"ELSE {_present('slot_compatibility')} END",
        ),
        _check(
            "experiments",
            "cancellation_shape",
            f"(state = '{ExperimentState.CANCELLED.value}') = "
            f"({_present('cancellation_correlation_id')})",
        ),
        _check("experiments", "snapshot_whole", _same_presence(_SNAPSHOT_COLUMNS)),
        Index("ix_experiments_state_created_at_utc", "state", "created_at_utc"),
        Index("ix_experiments_strategy_version_hash", "strategy_version_hash"),
        Index("ix_experiments_dataset_version_hash", "dataset_version_hash"),
    )


# --------------------------------------------------------------------------
# 3.3.2 engine_slots
# --------------------------------------------------------------------------


class EngineSlotRow(RowBase):
    """Plan 3.3.2: the experiment-scoped projection of the selected engine slots."""

    __tablename__ = "engine_slots"

    experiment_id: Mapped[str] = _text_column()
    logical_slot_id: Mapped[str] = _text_column()
    slot_ordinal: Mapped[int] = _integer_column()
    adapter_name: Mapped[str] = _text_column()
    adapter_version: Mapped[str] = _text_column()
    engine_name: Mapped[str] = _text_column()
    engine_version: Mapped[str] = _text_column()

    __table_args__ = (
        PrimaryKeyConstraint(
            "experiment_id", "logical_slot_id", name="pk_engine_slots"
        ),
        UniqueConstraint(
            "experiment_id", "slot_ordinal", name="uq_engine_slots_experiment_ordinal"
        ),
        _restrict(
            "engine_slots",
            "experiment",
            ["experiment_id"],
            ["experiments.experiment_id"],
        ),
        _check(
            "engine_slots", "logical_slot_id", _identifier("logical_slot_id", "slot_")
        ),
        _check(
            "engine_slots",
            "slot_ordinal",
            _bounded_integer("slot_ordinal", 0, MAX_SLOT_ORDINAL),
        ),
        _check(
            "engine_slots",
            "adapter_name",
            _bounded_text("adapter_name", 1, _MAX_IDENTIFIER_TEXT),
        ),
        _check(
            "engine_slots",
            "adapter_version",
            _bounded_text("adapter_version", _MIN_SEMVER_TEXT, _MAX_SEMVER_TEXT),
        ),
        _check(
            "engine_slots",
            "engine_name",
            _bounded_text("engine_name", 1, _MAX_IDENTIFIER_TEXT),
        ),
        _check(
            "engine_slots",
            "engine_version",
            _bounded_text("engine_version", _MIN_SEMVER_TEXT, _MAX_SEMVER_TEXT),
        ),
        Index(
            "ix_engine_slots_adapter_engine",
            "adapter_name",
            "adapter_version",
            "engine_name",
            "engine_version",
        ),
    )


# --------------------------------------------------------------------------
# 3.3.7 runtime_availability_observations
# --------------------------------------------------------------------------


class RuntimeAvailabilityObservationRow(RowBase):
    """Plan 3.3.7: ``RuntimeAvailabilityObservation`` plus ``content_sha256``."""

    __tablename__ = "runtime_availability_observations"

    availability_observation_id: Mapped[str] = _text_column()
    schema_version: Mapped[str] = _text_column()
    adapter_name: Mapped[str] = _text_column()
    adapter_version: Mapped[str] = _text_column()
    executable_path: Mapped[str] = _text_column()
    executable_hash: Mapped[str] = _text_column()
    runtime_version: Mapped[str] = _text_column()
    operating_system: Mapped[str] = _text_column()
    available: Mapped[int] = _integer_column()
    reason_code: Mapped[str | None] = _optional_text_column()
    observed_at_utc: Mapped[int] = _integer_column()
    expires_at_utc: Mapped[int] = _integer_column()
    network_required: Mapped[int] = _integer_column()
    credentials_required: Mapped[int] = _integer_column()
    content_sha256: Mapped[str] = _text_column()

    __table_args__ = (
        PrimaryKeyConstraint(
            "availability_observation_id",
            name="pk_runtime_availability_observations",
        ),
        _check(
            "runtime_availability_observations",
            "availability_observation_id",
            _identifier("availability_observation_id", "avail_"),
        ),
        _check(
            "runtime_availability_observations",
            "schema_version",
            _literal("schema_version", _SCHEMA_VERSION),
        ),
        _check(
            "runtime_availability_observations",
            "adapter_name",
            _bounded_text("adapter_name", 1, _MAX_IDENTIFIER_TEXT),
        ),
        _check(
            "runtime_availability_observations",
            "adapter_version",
            _bounded_text("adapter_version", _MIN_SEMVER_TEXT, _MAX_SEMVER_TEXT),
        ),
        _check(
            "runtime_availability_observations",
            "executable_path",
            _bounded_text("executable_path", 1, MAX_EXECUTABLE_PATH_CHARACTERS),
        ),
        _check(
            "runtime_availability_observations",
            "executable_hash",
            _hash("executable_hash"),
        ),
        _check(
            "runtime_availability_observations",
            "runtime_version",
            _bounded_text("runtime_version", _MIN_SEMVER_TEXT, _MAX_SEMVER_TEXT),
        ),
        _check(
            "runtime_availability_observations",
            "operating_system",
            _enum("operating_system", OperatingSystem),
        ),
        _check("runtime_availability_observations", "available", _boolean("available")),
        _check(
            "runtime_availability_observations",
            "reason_code",
            _bounded_text("reason_code", _MIN_ERROR_CODE_TEXT, _MAX_ERROR_CODE_TEXT),
        ),
        _check(
            "runtime_availability_observations",
            "observed_at_utc",
            _instant("observed_at_utc"),
        ),
        _check(
            "runtime_availability_observations",
            "expires_at_utc",
            _instant("expires_at_utc"),
        ),
        _check(
            "runtime_availability_observations",
            "network_required",
            _boolean("network_required"),
        ),
        _check(
            "runtime_availability_observations",
            "credentials_required",
            _boolean("credentials_required"),
        ),
        _check(
            "runtime_availability_observations",
            "content_sha256",
            _hash("content_sha256"),
        ),
        _check(
            "runtime_availability_observations",
            "reason_shape",
            f"(available = 0) = ({_present('reason_code')})",
        ),
        _check(
            "runtime_availability_observations",
            "expiry_after_observation",
            "expires_at_utc > observed_at_utc",
        ),
        Index(
            "ix_runtime_availability_observations_adapter_executable",
            "adapter_name",
            "adapter_version",
            "executable_hash",
            "availability_observation_id",
        ),
        Index(
            "ix_runtime_availability_observations_adapter_available",
            "adapter_name",
            "adapter_version",
            "available",
            "observed_at_utc",
            "expires_at_utc",
        ),
    )


# --------------------------------------------------------------------------
# 3.3.8 diagnostics and 3.3.9 diagnostic_causes
# --------------------------------------------------------------------------


class DiagnosticRow(RowBase):
    """Plan 3.3.8: the fifteen fields of ``Diagnostic``."""

    __tablename__ = "diagnostics"

    diagnostic_id: Mapped[str] = _text_column()
    schema_version: Mapped[str] = _text_column()
    severity: Mapped[str] = _text_column()
    error_code: Mapped[str] = _text_column()
    category: Mapped[str] = _text_column()
    message: Mapped[str] = _text_column()
    source_component: Mapped[str] = _text_column()
    experiment_id: Mapped[str | None] = _optional_text_column()
    run_id: Mapped[str | None] = _optional_text_column()
    invocation_id: Mapped[str | None] = _optional_text_column()
    engine: Mapped[str | None] = _optional_text_column()
    retriable: Mapped[int] = _integer_column()
    timestamp_utc: Mapped[int] = _integer_column()
    details: Mapped[str] = _text_column()
    causal_diagnostic_ids: Mapped[str] = _text_column()

    __table_args__ = (
        PrimaryKeyConstraint("diagnostic_id", name="pk_diagnostics"),
        _check("diagnostics", "diagnostic_id", _identifier("diagnostic_id", "diag_")),
        _check(
            "diagnostics", "schema_version", _literal("schema_version", _SCHEMA_VERSION)
        ),
        _check("diagnostics", "severity", _enum("severity", DiagnosticSeverity)),
        _check(
            "diagnostics",
            "error_code",
            _bounded_text("error_code", _MIN_ERROR_CODE_TEXT, _MAX_ERROR_CODE_TEXT),
        ),
        _check("diagnostics", "category", _enum("category", DiagnosticCategory)),
        _check(
            "diagnostics", "message", _bounded_text("message", 1, _MAX_BOUNDED_TEXT)
        ),
        _check(
            "diagnostics",
            "source_component",
            _bounded_text("source_component", 1, _MAX_IDENTIFIER_TEXT),
        ),
        _check("diagnostics", "experiment_id", _identifier("experiment_id", "exp_")),
        _check("diagnostics", "run_id", _identifier("run_id", "run_")),
        _check("diagnostics", "invocation_id", _identifier("invocation_id", "inv_")),
        _check(
            "diagnostics", "engine", _bounded_text("engine", 1, _MAX_IDENTIFIER_TEXT)
        ),
        _check("diagnostics", "retriable", _boolean("retriable")),
        _check("diagnostics", "timestamp_utc", _instant("timestamp_utc")),
        _check(
            "diagnostics",
            "details",
            f"{_json('details')} AND json_type(details) = 'object' "
            f"AND length(CAST(details AS BLOB)) <= {MAX_DETAIL_BYTES}",
        ),
        _check(
            "diagnostics",
            "causal_diagnostic_ids",
            _json_array("causal_diagnostic_ids", _MAX_CAUSAL_DIAGNOSTIC_IDS),
        ),
        _check(
            "diagnostics",
            "run_requires_experiment",
            f"{_absent('run_id')} OR {_present('experiment_id')}",
        ),
        _check(
            "diagnostics",
            "command_requires_invocation",
            f"category NOT IN ({_COMMAND_CATEGORY_LIST})"
            f" OR {_present('invocation_id')}",
        ),
        Index("ix_diagnostics_error_code", "error_code"),
        Index("ix_diagnostics_category", "category"),
        Index("ix_diagnostics_severity", "severity"),
        Index("ix_diagnostics_experiment_id", "experiment_id"),
        Index("ix_diagnostics_run_id", "run_id"),
        Index("ix_diagnostics_invocation_id", "invocation_id"),
        Index("ix_diagnostics_timestamp_utc", "timestamp_utc"),
    )


class DiagnosticCauseRow(RowBase):
    """Plan 3.3.9: the restricted causal-edge relation (reading 23)."""

    __tablename__ = "diagnostic_causes"

    diagnostic_id: Mapped[str] = _text_column()
    causal_diagnostic_id: Mapped[str] = _text_column()

    __table_args__ = (
        PrimaryKeyConstraint(
            "diagnostic_id", "causal_diagnostic_id", name="pk_diagnostic_causes"
        ),
        _restrict(
            "diagnostic_causes",
            "diagnostic",
            ["diagnostic_id"],
            ["diagnostics.diagnostic_id"],
        ),
        _restrict(
            "diagnostic_causes",
            "cause",
            ["causal_diagnostic_id"],
            ["diagnostics.diagnostic_id"],
        ),
        _check(
            "diagnostic_causes",
            "no_self_cause",
            "diagnostic_id <> causal_diagnostic_id",
        ),
        Index("ix_diagnostic_causes_causal_diagnostic_id", "causal_diagnostic_id"),
    )


# --------------------------------------------------------------------------
# 3.3.10 strategy_versions, 3.3.11 datasets and dataset_partitions
# --------------------------------------------------------------------------


class StrategyVersionRow(RowBase):
    """Plan 3.3.10: ``StrategyVersion`` keyed by its content hash."""

    __tablename__ = "strategy_versions"

    content_hash: Mapped[str] = _text_column()
    strategy_version_id: Mapped[str] = _text_column()
    strategy_id: Mapped[str] = _text_column()
    schema_version: Mapped[str] = _text_column()
    record: Mapped[str] = _text_column()
    hashing_profile_version: Mapped[str] = _text_column()
    created_at_utc: Mapped[int] = _integer_column()

    __table_args__ = (
        PrimaryKeyConstraint("content_hash", name="pk_strategy_versions"),
        UniqueConstraint(
            "strategy_version_id", name="uq_strategy_versions_strategy_version_id"
        ),
        UniqueConstraint(
            "strategy_id",
            "created_at_utc",
            name="uq_strategy_versions_strategy_id_created_at_utc",
        ),
        _check("strategy_versions", "content_hash", _hash("content_hash")),
        _check(
            "strategy_versions",
            "strategy_version_id",
            _identifier("strategy_version_id", "strv_"),
        ),
        _check(
            "strategy_versions", "strategy_id", _identifier("strategy_id", "strat_")
        ),
        _check(
            "strategy_versions",
            "schema_version",
            _literal("schema_version", _SCHEMA_VERSION),
        ),
        _check("strategy_versions", "record", _json("record")),
        _check(
            "strategy_versions",
            "hashing_profile_version",
            _literal("hashing_profile_version", STRATEGY_VERSION_PROFILE_VERSION),
        ),
        _check("strategy_versions", "created_at_utc", _instant("created_at_utc")),
    )


class DatasetRow(RowBase):
    """Plan 3.3.11: ``DatasetDescriptor`` with its typed index projections."""

    __tablename__ = "datasets"

    dataset_id: Mapped[str] = _text_column()
    content_hash: Mapped[str] = _text_column()
    schema_version: Mapped[str] = _text_column()
    record: Mapped[str] = _text_column()
    venue: Mapped[str] = _text_column()
    instrument_canonical_id: Mapped[str] = _text_column()
    data_type: Mapped[str] = _text_column()
    timeframe: Mapped[str | None] = _optional_text_column()
    start_utc: Mapped[int] = _integer_column()
    end_utc: Mapped[int] = _integer_column()
    validation_status: Mapped[str] = _text_column()
    created_at_utc: Mapped[int] = _integer_column()

    __table_args__ = (
        PrimaryKeyConstraint("dataset_id", name="pk_datasets"),
        UniqueConstraint("content_hash", name="uq_datasets_content_hash"),
        _check("datasets", "dataset_id", _identifier("dataset_id", "ds_")),
        _check("datasets", "content_hash", _hash("content_hash")),
        _check(
            "datasets", "schema_version", _literal("schema_version", _SCHEMA_VERSION)
        ),
        _check("datasets", "record", _json("record")),
        _check("datasets", "venue", _bounded_text("venue", 1, _MAX_ASSET_CODE_TEXT)),
        _check(
            "datasets",
            "instrument_canonical_id",
            _bounded_text(
                "instrument_canonical_id", _MIN_INSTRUMENT_TEXT, _MAX_INSTRUMENT_TEXT
            ),
        ),
        _check("datasets", "data_type", _enum("data_type", DatasetDataType)),
        _check(
            "datasets", "timeframe", _bounded_text("timeframe", 2, _MAX_TIMEFRAME_TEXT)
        ),
        _check("datasets", "start_utc", _instant("start_utc")),
        _check("datasets", "end_utc", _instant("end_utc")),
        _check(
            "datasets",
            "validation_status",
            _enum("validation_status", DatasetValidationStatus),
        ),
        _check("datasets", "created_at_utc", _instant("created_at_utc")),
        _check("datasets", "interval", "start_utc < end_utc"),
        _check(
            "datasets",
            "timeframe_shape",
            f"(data_type = '{DatasetDataType.OHLCV.value}') = "
            f"({_present('timeframe')})",
        ),
        Index(
            "ix_datasets_instrument_data_type_interval",
            "instrument_canonical_id",
            "data_type",
            "start_utc",
            "end_utc",
        ),
    )


class DatasetPartitionRow(RowBase):
    """Plan 3.3.11: ``DatasetPartition`` with its checksum projections."""

    __tablename__ = "dataset_partitions"

    partition_id: Mapped[str] = _text_column()
    dataset_id: Mapped[str] = _text_column()
    ordinal: Mapped[int] = _integer_column()
    record: Mapped[str] = _text_column()
    content_hash: Mapped[str] = _text_column()
    raw_checksum: Mapped[str] = _text_column()
    normalized_checksum: Mapped[str] = _text_column()
    relative_path: Mapped[str] = _text_column()
    row_count: Mapped[int] = _integer_column()
    start_utc: Mapped[int] = _integer_column()
    end_utc: Mapped[int] = _integer_column()

    __table_args__ = (
        PrimaryKeyConstraint("partition_id", name="pk_dataset_partitions"),
        UniqueConstraint(
            "dataset_id", "ordinal", name="uq_dataset_partitions_dataset_id_ordinal"
        ),
        _restrict(
            "dataset_partitions", "dataset", ["dataset_id"], ["datasets.dataset_id"]
        ),
        _check(
            "dataset_partitions", "partition_id", _identifier("partition_id", "part_")
        ),
        _check("dataset_partitions", "ordinal", "ordinal >= 0"),
        _check("dataset_partitions", "record", _json("record")),
        _check("dataset_partitions", "content_hash", _hash("content_hash")),
        _check("dataset_partitions", "raw_checksum", _hash("raw_checksum")),
        _check(
            "dataset_partitions", "normalized_checksum", _hash("normalized_checksum")
        ),
        _check(
            "dataset_partitions",
            "relative_path",
            _bounded_text("relative_path", 1, _MAX_BOUNDED_TEXT),
        ),
        _check("dataset_partitions", "row_count", "row_count >= 0"),
        _check("dataset_partitions", "start_utc", _instant("start_utc")),
        _check("dataset_partitions", "end_utc", _instant("end_utc")),
        _check("dataset_partitions", "interval", "start_utc < end_utc"),
        Index("ix_dataset_partitions_content_hash", "content_hash"),
        Index("ix_dataset_partitions_raw_checksum", "raw_checksum"),
        Index("ix_dataset_partitions_normalized_checksum", "normalized_checksum"),
    )


# --------------------------------------------------------------------------
# 3.3.3 engine_runs
# --------------------------------------------------------------------------


class EngineRunRow(RowBase):
    """Plan 3.3.3: ``EngineRunRecord``; ``run_id`` is the primary identity and the
    attempt triple is the port's unique key (reading 7)."""

    __tablename__ = "engine_runs"

    run_id: Mapped[str] = _text_column()
    schema_version: Mapped[str] = _text_column()
    experiment_id: Mapped[str] = _text_column()
    logical_slot_id: Mapped[str] = _text_column()
    attempt_number: Mapped[int] = _integer_column()
    attempt_token_hash: Mapped[str] = _text_column()
    state: Mapped[str] = _text_column()
    adapter_name: Mapped[str] = _text_column()
    adapter_version: Mapped[str] = _text_column()
    engine_name: Mapped[str] = _text_column()
    engine_version: Mapped[str] = _text_column()
    request_hash: Mapped[str] = _text_column()
    predecessor_run_id: Mapped[str | None] = _optional_text_column()
    retry_reason: Mapped[str | None] = _optional_text_column()
    primary_terminal_diagnostic_id: Mapped[str | None] = _optional_text_column()
    availability_observation_id: Mapped[str | None] = _optional_text_column()
    created_at_utc: Mapped[int] = _integer_column()
    updated_at_utc: Mapped[int] = _integer_column()
    revision: Mapped[int] = _integer_column()

    __table_args__ = (
        PrimaryKeyConstraint("run_id", name="pk_engine_runs"),
        UniqueConstraint(
            "experiment_id",
            "logical_slot_id",
            "attempt_number",
            name="uq_engine_runs_attempt",
        ),
        UniqueConstraint(
            "experiment_id", "run_id", name="uq_engine_runs_experiment_run"
        ),
        _restrict(
            "engine_runs",
            "experiment",
            ["experiment_id"],
            ["experiments.experiment_id"],
        ),
        _restrict(
            "engine_runs",
            "slot",
            ["experiment_id", "logical_slot_id"],
            ["engine_slots.experiment_id", "engine_slots.logical_slot_id"],
        ),
        _restrict(
            "engine_runs", "predecessor", ["predecessor_run_id"], ["engine_runs.run_id"]
        ),
        _restrict(
            "engine_runs",
            "observation",
            ["availability_observation_id"],
            ["runtime_availability_observations.availability_observation_id"],
        ),
        _check("engine_runs", "run_id", _identifier("run_id", "run_")),
        _check(
            "engine_runs", "schema_version", _literal("schema_version", _SCHEMA_VERSION)
        ),
        _check("engine_runs", "experiment_id", _identifier("experiment_id", "exp_")),
        _check(
            "engine_runs", "logical_slot_id", _identifier("logical_slot_id", "slot_")
        ),
        _check(
            "engine_runs",
            "attempt_number",
            _bounded_integer("attempt_number", 1, MAX_ATTEMPTS_PER_SLOT),
        ),
        _check("engine_runs", "attempt_token_hash", _hash("attempt_token_hash")),
        _check("engine_runs", "state", _enum("state", EngineRunState)),
        _check(
            "engine_runs",
            "adapter_name",
            _bounded_text("adapter_name", 1, _MAX_IDENTIFIER_TEXT),
        ),
        _check(
            "engine_runs",
            "adapter_version",
            _bounded_text("adapter_version", _MIN_SEMVER_TEXT, _MAX_SEMVER_TEXT),
        ),
        _check(
            "engine_runs",
            "engine_name",
            _bounded_text("engine_name", 1, _MAX_IDENTIFIER_TEXT),
        ),
        _check(
            "engine_runs",
            "engine_version",
            _bounded_text("engine_version", _MIN_SEMVER_TEXT, _MAX_SEMVER_TEXT),
        ),
        _check("engine_runs", "request_hash", _hash("request_hash")),
        _check(
            "engine_runs",
            "predecessor_run_id",
            _identifier("predecessor_run_id", "run_"),
        ),
        _check(
            "engine_runs", "retry_reason", _enum("retry_reason", RetryTerminalState)
        ),
        _check(
            "engine_runs",
            "primary_terminal_diagnostic_id",
            _identifier("primary_terminal_diagnostic_id", "diag_"),
        ),
        _check(
            "engine_runs",
            "availability_observation_id",
            _identifier("availability_observation_id", "avail_"),
        ),
        _check("engine_runs", "created_at_utc", _instant("created_at_utc")),
        _check("engine_runs", "updated_at_utc", _instant("updated_at_utc")),
        _check("engine_runs", "revision", "revision >= 0"),
        _check(
            "engine_runs",
            "predecessor_shape",
            f"(attempt_number > 1) = ({_present('predecessor_run_id')})",
        ),
        _check(
            "engine_runs",
            "retry_reason_shape",
            f"(attempt_number > 1) = ({_present('retry_reason')})",
        ),
        _check(
            "engine_runs",
            "no_self_predecessor",
            f"{_absent('predecessor_run_id')} OR predecessor_run_id <> run_id",
        ),
        _check(
            "engine_runs",
            "terminal_diagnostic_shape",
            f"({_in('state', EngineRunState, _NON_SUCCESS_TERMINAL_RUN_STATES)}) = "
            f"({_present('primary_terminal_diagnostic_id')})",
        ),
        _check(
            "engine_runs",
            "observation_shape",
            "CASE WHEN "
            f"{_in('state', EngineRunState, _OBSERVATION_PROHIBITED_RUN_STATES)} "
            f"THEN {_absent('availability_observation_id')} WHEN "
            f"{_in('state', EngineRunState, _OBSERVATION_REQUIRED_RUN_STATES)} "
            f"THEN {_present('availability_observation_id')} ELSE 1 END",
        ),
        _check(
            "engine_runs", "updated_after_created", "updated_at_utc >= created_at_utc"
        ),
        Index("ix_engine_runs_state", "state"),
        Index("ix_engine_runs_predecessor_run_id", "predecessor_run_id"),
        Index(
            "ix_engine_runs_primary_terminal_diagnostic_id",
            "primary_terminal_diagnostic_id",
        ),
        Index(
            "ix_engine_runs_availability_observation_id", "availability_observation_id"
        ),
        Index(
            "uq_engine_runs_active_attempt",
            "experiment_id",
            "logical_slot_id",
            unique=True,
            sqlite_where=text(_in("state", EngineRunState, _ACTIVE_RUN_STATES)),
        ),
    )


# --------------------------------------------------------------------------
# 3.3.4 command_invocations
# --------------------------------------------------------------------------


def _invocation_state_rows() -> str:
    """The spec 15.2 table as one ``CASE`` over ``state`` (section 3.3.4)."""
    launched = "deadline_utc IS NOT NULL"
    created = "process_created = 1"
    not_created = "process_created = 0"
    primary = "primary_diagnostic_id IS NOT NULL"
    recognized = ", ".join(
        str(value) for value in sorted(RECOGNIZED_NATIVE_EXIT_VALUES)
    )
    states = CommandInvocationState
    rows = {
        states.PENDING: f"deadline_utc IS NULL AND {not_created}",
        states.STARTING: f"{launched} AND {not_created}",
        states.RUNNING: f"{launched} AND {created}",
        states.EXITED: (
            f"{launched} AND {created} AND native_exit_value IS NOT NULL AND "
            f"(native_exit_value IN ({recognized}) OR {primary})"
        ),
        states.FAILED_TO_START: (
            f"{launched} AND {not_created} AND native_exit_value IS NULL AND {primary}"
        ),
        states.CANCELLED: f"{primary} AND ({not_created} OR {launched})",
        states.TIMED_OUT: f"{launched} AND {primary}",
        states.PROTOCOL_FAILED: f"{launched} AND {created} AND {primary}",
    }
    branches = " ".join(
        f"WHEN '{state.value}' THEN ({rows[state]})" for state in states
    )
    return f"CASE state {branches} ELSE 0 END"


class CommandInvocationRow(RowBase):
    """Plan 3.3.4: ``CommandInvocationRecord`` with ``ProcessIdentity`` flattened."""

    __tablename__ = "command_invocations"

    invocation_id: Mapped[str] = _text_column()
    schema_version: Mapped[str] = _text_column()
    command_kind: Mapped[str] = _text_column()
    adapter_name: Mapped[str] = _text_column()
    adapter_version: Mapped[str] = _text_column()
    run_id: Mapped[str | None] = _optional_text_column()
    request_hash: Mapped[str] = _text_column()
    timeout_seconds: Mapped[int] = _integer_column()
    state: Mapped[str] = _text_column()
    process_created: Mapped[int] = _integer_column()
    launch_attempted_at_utc: Mapped[int | None] = _optional_integer_column()
    deadline_utc: Mapped[int | None] = _optional_integer_column()
    process_started_at_utc: Mapped[int | None] = _optional_integer_column()
    pid: Mapped[int | None] = _optional_integer_column()
    creation_identity: Mapped[str | None] = _optional_text_column()
    executable_path: Mapped[str | None] = _optional_text_column()
    executable_hash: Mapped[str | None] = _optional_text_column()
    supervisor_instance_id: Mapped[str | None] = _optional_text_column()
    completed_at_utc: Mapped[int | None] = _optional_integer_column()
    native_exit_value: Mapped[int | None] = _optional_integer_column()
    process_exit_category: Mapped[str | None] = _optional_text_column()
    cleanup_complete: Mapped[int] = _integer_column()
    cleanup_completed_at_utc: Mapped[int | None] = _optional_integer_column()
    stderr_artifact_id: Mapped[str | None] = _optional_text_column()
    primary_diagnostic_id: Mapped[str | None] = _optional_text_column()
    diagnostic_ids: Mapped[str] = _text_column()
    created_at_utc: Mapped[int] = _integer_column()
    updated_at_utc: Mapped[int] = _integer_column()
    revision: Mapped[int] = _integer_column()

    __table_args__ = (
        PrimaryKeyConstraint("invocation_id", name="pk_command_invocations"),
        UniqueConstraint(
            "run_id", "invocation_id", name="uq_command_invocations_run_invocation"
        ),
        _restrict("command_invocations", "run", ["run_id"], ["engine_runs.run_id"]),
        _check(
            "command_invocations", "invocation_id", _identifier("invocation_id", "inv_")
        ),
        _check(
            "command_invocations",
            "schema_version",
            _literal("schema_version", _SCHEMA_VERSION),
        ),
        _check(
            "command_invocations", "command_kind", _enum("command_kind", CommandKind)
        ),
        _check(
            "command_invocations",
            "adapter_name",
            _bounded_text("adapter_name", 1, _MAX_IDENTIFIER_TEXT),
        ),
        _check(
            "command_invocations",
            "adapter_version",
            _bounded_text("adapter_version", _MIN_SEMVER_TEXT, _MAX_SEMVER_TEXT),
        ),
        _check("command_invocations", "run_id", _identifier("run_id", "run_")),
        _check("command_invocations", "request_hash", _hash("request_hash")),
        _check(
            "command_invocations",
            "timeout_seconds",
            _bounded_integer(
                "timeout_seconds", MIN_TIMEOUT_SECONDS, MAX_RUN_TIMEOUT_SECONDS
            ),
        ),
        _check("command_invocations", "state", _enum("state", CommandInvocationState)),
        _check("command_invocations", "process_created", _boolean("process_created")),
        _check(
            "command_invocations",
            "launch_attempted_at_utc",
            _instant("launch_attempted_at_utc"),
        ),
        _check("command_invocations", "deadline_utc", _instant("deadline_utc")),
        _check(
            "command_invocations",
            "process_started_at_utc",
            _instant("process_started_at_utc"),
        ),
        _check("command_invocations", "pid", _bounded_integer("pid", 1, MAX_PID)),
        _check(
            "command_invocations",
            "creation_identity",
            _bounded_text("creation_identity", 1, _MAX_BOUNDED_TEXT),
        ),
        _check(
            "command_invocations",
            "executable_path",
            _bounded_text("executable_path", 1, MAX_EXECUTABLE_PATH_CHARACTERS),
        ),
        _check("command_invocations", "executable_hash", _hash("executable_hash")),
        _check(
            "command_invocations",
            "supervisor_instance_id",
            _bounded_text("supervisor_instance_id", 1, _MAX_BOUNDED_TEXT),
        ),
        _check("command_invocations", "completed_at_utc", _instant("completed_at_utc")),
        _check(
            "command_invocations",
            "native_exit_value",
            _bounded_integer(
                "native_exit_value", MIN_NATIVE_EXIT_VALUE, MAX_NATIVE_EXIT_VALUE
            ),
        ),
        _check(
            "command_invocations",
            "process_exit_category",
            _enum("process_exit_category", ProcessExitCategory),
        ),
        _check("command_invocations", "cleanup_complete", _boolean("cleanup_complete")),
        _check(
            "command_invocations",
            "cleanup_completed_at_utc",
            _instant("cleanup_completed_at_utc"),
        ),
        _check(
            "command_invocations",
            "stderr_artifact_id",
            _identifier("stderr_artifact_id", "art_"),
        ),
        _check(
            "command_invocations",
            "primary_diagnostic_id",
            _identifier("primary_diagnostic_id", "diag_"),
        ),
        _check(
            "command_invocations",
            "diagnostic_ids",
            _json_array("diagnostic_ids", MAX_DIAGNOSTIC_IDS),
        ),
        _check("command_invocations", "created_at_utc", _instant("created_at_utc")),
        _check("command_invocations", "updated_at_utc", _instant("updated_at_utc")),
        _check("command_invocations", "revision", "revision >= 0"),
        _check(
            "command_invocations",
            "describe_has_no_run",
            f"(command_kind = '{CommandKind.DESCRIBE.value}') = ({_absent('run_id')})",
        ),
        _check(
            "command_invocations",
            "timeout_per_kind",
            f"CASE command_kind WHEN '{CommandKind.DESCRIBE.value}' THEN "
            f"timeout_seconds BETWEEN {MIN_TIMEOUT_SECONDS} AND "
            f"{MAX_DESCRIBE_TIMEOUT_SECONDS} WHEN '{CommandKind.VALIDATE.value}' THEN "
            f"timeout_seconds BETWEEN {MIN_TIMEOUT_SECONDS} AND "
            f"{MAX_VALIDATE_TIMEOUT_SECONDS} ELSE timeout_seconds BETWEEN "
            f"{MIN_TIMEOUT_SECONDS} AND {MAX_RUN_TIMEOUT_SECONDS} END",
        ),
        _check(
            "command_invocations",
            "launch_facts_shape",
            f"({_absent('launch_attempted_at_utc')}) = ({_absent('deadline_utc')})",
        ),
        _check(
            "command_invocations",
            "deadline_arithmetic",
            f"{_absent('deadline_utc')} OR deadline_utc = launch_attempted_at_utc + "
            f"timeout_seconds * {_MICROS_PER_SECOND}",
        ),
        _check(
            "command_invocations",
            "process_facts_shape",
            _same_presence(_PROCESS_COLUMNS),
        ),
        _check(
            "command_invocations",
            "process_created_shape",
            f"(process_created = 1) = ({_present('pid')})",
        ),
        _check(
            "command_invocations",
            "exit_facts_shape",
            f"({_absent('native_exit_value')}) = ({_absent('process_exit_category')})",
        ),
        _check(
            "command_invocations",
            "exit_category_mapping",
            f"{_absent('process_exit_category')} OR process_exit_category = "
            f"{_exit_category_case()}",
        ),
        _check(
            "command_invocations",
            "cleanup_shape",
            f"(cleanup_complete = 1) = ({_present('cleanup_completed_at_utc')})",
        ),
        _check(
            "command_invocations",
            "completion_shape",
            f"(state IN ({_TERMINAL_INVOCATION_LIST}))"
            f" = ({_present('completed_at_utc')})",
        ),
        _check(
            "command_invocations",
            "non_terminal_partition",
            f"state IN ({_TERMINAL_INVOCATION_LIST})"
            f" OR (cleanup_complete = 0 AND {_absent('primary_diagnostic_id')} AND "
            f"{_absent('native_exit_value')} AND {_absent('stderr_artifact_id')})",
        ),
        _check("command_invocations", "state_row", _invocation_state_rows()),
        _check(
            "command_invocations",
            "updated_after_created",
            "updated_at_utc >= created_at_utc",
        ),
        Index("ix_command_invocations_state_deadline_utc", "state", "deadline_utc"),
        Index(
            "ix_command_invocations_run_kind_launch",
            "run_id",
            "command_kind",
            "launch_attempted_at_utc",
        ),
        Index(
            "ix_command_invocations_creation_identity_pid", "creation_identity", "pid"
        ),
        Index(
            "ix_command_invocations_reconciliation_listing",
            "state",
            "cleanup_complete",
            "created_at_utc",
            "invocation_id",
        ),
        Index(
            "ix_command_invocations_created_at_utc_invocation_id",
            "created_at_utc",
            "invocation_id",
        ),
        Index("ix_command_invocations_primary_diagnostic_id", "primary_diagnostic_id"),
        Index(
            "uq_command_invocations_open_kind",
            "run_id",
            "command_kind",
            unique=True,
            sqlite_where=text(
                f"{_present('run_id')} AND "
                f"{_in('state', CommandInvocationState, _OPEN_INVOCATION_STATES)}"
            ),
        ),
    )


# --------------------------------------------------------------------------
# 3.3.5 run_events
# --------------------------------------------------------------------------


class RunEventRow(RowBase):
    """Plan 3.3.5: ``RunEvent`` keyed ``(invocation_id, sequence)``."""

    __tablename__ = "run_events"

    invocation_id: Mapped[str] = _text_column()
    sequence: Mapped[int] = _integer_column()
    event_id: Mapped[str] = _text_column()
    run_id: Mapped[str] = _text_column()
    schema_version: Mapped[str] = _text_column()
    protocol_version: Mapped[str] = _text_column()
    attempt_token_hash: Mapped[str] = _text_column()
    wire_event_hash: Mapped[str] = _text_column()
    content_hash: Mapped[str] = _text_column()
    event_type: Mapped[str] = _text_column()
    timestamp_utc: Mapped[int] = _integer_column()
    received_at_utc: Mapped[int] = _integer_column()
    payload: Mapped[str] = _text_column()

    __table_args__ = (
        PrimaryKeyConstraint("invocation_id", "sequence", name="pk_run_events"),
        UniqueConstraint("event_id", name="uq_run_events_event_id"),
        _restrict("run_events", "run", ["run_id"], ["engine_runs.run_id"]),
        _restrict(
            "run_events",
            "invocation",
            ["run_id", "invocation_id"],
            ["command_invocations.run_id", "command_invocations.invocation_id"],
        ),
        _check("run_events", "invocation_id", _identifier("invocation_id", "inv_")),
        _check("run_events", "sequence", _bounded_integer("sequence", 1, MAX_SEQUENCE)),
        _check("run_events", "event_id", _identifier("event_id", "evt_")),
        _check("run_events", "run_id", _identifier("run_id", "run_")),
        _check(
            "run_events", "schema_version", _literal("schema_version", _SCHEMA_VERSION)
        ),
        _check(
            "run_events",
            "protocol_version",
            _literal("protocol_version", _SCHEMA_VERSION),
        ),
        _check("run_events", "attempt_token_hash", _hash("attempt_token_hash")),
        _check("run_events", "wire_event_hash", _hash("wire_event_hash")),
        _check("run_events", "content_hash", _hash("content_hash")),
        _check("run_events", "event_type", _enum("event_type", ProtocolEventType)),
        _check("run_events", "timestamp_utc", _instant("timestamp_utc")),
        _check("run_events", "received_at_utc", _instant("received_at_utc")),
        _check("run_events", "payload", _json("payload")),
        Index("ix_run_events_run_id_received_at_utc", "run_id", "received_at_utc"),
        Index("ix_run_events_event_type", "event_type"),
        Index("ix_run_events_wire_event_hash", "wire_event_hash"),
        Index("ix_run_events_run_id", "run_id"),
    )


# --------------------------------------------------------------------------
# 3.3.6 retry_decisions
# --------------------------------------------------------------------------


class RetryDecisionRow(RowBase):
    """Plan 3.3.6: ``RetryDecisionRecord`` keyed by the port's pair."""

    __tablename__ = "retry_decisions"

    logical_slot_id: Mapped[str] = _text_column()
    predecessor_run_id: Mapped[str] = _text_column()
    schema_version: Mapped[str] = _text_column()
    experiment_id: Mapped[str] = _text_column()
    experiment_spec_hash: Mapped[str] = _text_column()
    retry_policy: Mapped[str] = _text_column()
    created_attempt_count: Mapped[int] = _integer_column()
    predecessor_terminal_state: Mapped[str] = _text_column()
    primary_terminal_diagnostic_id: Mapped[str] = _text_column()
    outcome: Mapped[str] = _text_column()
    denial_reason: Mapped[str | None] = _optional_text_column()
    hard_block_error_code: Mapped[str | None] = _optional_text_column()
    availability_observation_id: Mapped[str | None] = _optional_text_column()
    retry_not_before_utc: Mapped[int | None] = _optional_integer_column()
    reserved_successor_attempt_number: Mapped[int | None] = _optional_integer_column()
    decided_at_utc: Mapped[int] = _integer_column()

    __table_args__ = (
        PrimaryKeyConstraint(
            "logical_slot_id", "predecessor_run_id", name="pk_retry_decisions"
        ),
        _restrict(
            "retry_decisions",
            "experiment",
            ["experiment_id"],
            ["experiments.experiment_id"],
        ),
        _restrict(
            "retry_decisions",
            "predecessor",
            ["experiment_id", "predecessor_run_id"],
            ["engine_runs.experiment_id", "engine_runs.run_id"],
        ),
        _restrict(
            "retry_decisions",
            "slot",
            ["experiment_id", "logical_slot_id"],
            ["engine_slots.experiment_id", "engine_slots.logical_slot_id"],
        ),
        _restrict(
            "retry_decisions",
            "observation",
            ["availability_observation_id"],
            ["runtime_availability_observations.availability_observation_id"],
        ),
        _check(
            "retry_decisions",
            "logical_slot_id",
            _identifier("logical_slot_id", "slot_"),
        ),
        _check(
            "retry_decisions",
            "predecessor_run_id",
            _identifier("predecessor_run_id", "run_"),
        ),
        _check(
            "retry_decisions",
            "schema_version",
            _literal("schema_version", _SCHEMA_VERSION),
        ),
        _check(
            "retry_decisions", "experiment_id", _identifier("experiment_id", "exp_")
        ),
        _check(
            "retry_decisions", "experiment_spec_hash", _hash("experiment_spec_hash")
        ),
        _check("retry_decisions", "retry_policy", _json("retry_policy")),
        _check(
            "retry_decisions",
            "created_attempt_count",
            _bounded_integer("created_attempt_count", 1, MAX_ATTEMPTS_PER_SLOT),
        ),
        _check(
            "retry_decisions",
            "predecessor_terminal_state",
            _in(
                "predecessor_terminal_state",
                EngineRunState,
                _NON_SUCCESS_TERMINAL_RUN_STATES,
            ),
        ),
        _check(
            "retry_decisions",
            "primary_terminal_diagnostic_id",
            _identifier("primary_terminal_diagnostic_id", "diag_"),
        ),
        _check("retry_decisions", "outcome", _enum("outcome", RetryDecisionOutcome)),
        _check(
            "retry_decisions",
            "denial_reason",
            _enum("denial_reason", RetryDenialReason),
        ),
        _check(
            "retry_decisions",
            "hard_block_error_code",
            _bounded_text(
                "hard_block_error_code", _MIN_ERROR_CODE_TEXT, _MAX_ERROR_CODE_TEXT
            ),
        ),
        _check(
            "retry_decisions",
            "availability_observation_id",
            _identifier("availability_observation_id", "avail_"),
        ),
        _check(
            "retry_decisions", "retry_not_before_utc", _instant("retry_not_before_utc")
        ),
        _check(
            "retry_decisions",
            "reserved_successor_attempt_number",
            _bounded_integer(
                "reserved_successor_attempt_number", 2, MAX_ATTEMPTS_PER_SLOT
            ),
        ),
        _check("retry_decisions", "decided_at_utc", _instant("decided_at_utc")),
        _check(
            "retry_decisions",
            "denial_shape",
            f"(outcome = '{RetryDecisionOutcome.DENIED.value}') = "
            f"({_present('denial_reason')})",
        ),
        _check(
            "retry_decisions",
            "hard_block_shape",
            f"(denial_reason IS '{RetryDenialReason.HARD_BLOCKED_OUTCOME.value}') = "
            f"({_present('hard_block_error_code')})",
        ),
        _check(
            "retry_decisions",
            "not_before_shape",
            f"(outcome = '{RetryDecisionOutcome.ALLOWED.value}') = "
            f"({_present('retry_not_before_utc')})",
        ),
        _check(
            "retry_decisions",
            "reservation_shape",
            f"(outcome = '{RetryDecisionOutcome.ALLOWED.value}') = "
            f"({_present('reserved_successor_attempt_number')})",
        ),
        _check(
            "retry_decisions",
            "reservation_arithmetic",
            f"{_absent('reserved_successor_attempt_number')} OR "
            "reserved_successor_attempt_number = created_attempt_count + 1",
        ),
        _check(
            "retry_decisions",
            "observation_shape",
            f"(outcome = '{RetryDecisionOutcome.ALLOWED.value}' AND "
            f"predecessor_terminal_state = '{EngineRunState.UNAVAILABLE.value}') = "
            f"({_present('availability_observation_id')})",
        ),
        Index(
            "ix_retry_decisions_pending_not_before",
            "retry_not_before_utc",
            sqlite_where=text(f"outcome = '{RetryDecisionOutcome.ALLOWED.value}'"),
        ),
        Index("ix_retry_decisions_experiment_id", "experiment_id"),
        Index(
            "ix_retry_decisions_primary_terminal_diagnostic_id",
            "primary_terminal_diagnostic_id",
        ),
    )


# --------------------------------------------------------------------------
# 3.3.12 artifact_owners
# --------------------------------------------------------------------------


def _owner_variant(
    kind: str, required: tuple[str, ...], either: tuple[str, ...] = ()
) -> str:
    """Exactly one variant: the required columns present, the rest ``NULL``."""
    columns = (
        "experiment_id",
        "run_id",
        "invocation_id",
        "dataset_id",
        "strategy_version_id",
        "strategy_version_hash",
        "adapter_name",
        "adapter_version",
        "engine_name",
        "engine_version",
        "core_component",
        "correlation_id",
    )
    terms = [_present(column) for column in required]
    terms.extend(
        _absent(column) for column in columns if column not in required + either
    )
    return f"owner_kind <> '{kind}' OR ({' AND '.join(terms)})"


class ArtifactOwnerRow(RowBase):
    """Plan 3.3.12: ``ArtifactOwnerRef`` keyed by ``owner_hash`` (reading 8)."""

    __tablename__ = "artifact_owners"

    owner_hash: Mapped[str] = _text_column()
    owner_kind: Mapped[str] = _text_column()
    experiment_id: Mapped[str | None] = _optional_text_column()
    run_id: Mapped[str | None] = _optional_text_column()
    invocation_id: Mapped[str | None] = _optional_text_column()
    dataset_id: Mapped[str | None] = _optional_text_column()
    strategy_version_id: Mapped[str | None] = _optional_text_column()
    strategy_version_hash: Mapped[str | None] = _optional_text_column()
    adapter_name: Mapped[str | None] = _optional_text_column()
    adapter_version: Mapped[str | None] = _optional_text_column()
    engine_name: Mapped[str | None] = _optional_text_column()
    engine_version: Mapped[str | None] = _optional_text_column()
    core_component: Mapped[str | None] = _optional_text_column()
    correlation_id: Mapped[str | None] = _optional_text_column()

    __table_args__ = (
        PrimaryKeyConstraint("owner_hash", name="pk_artifact_owners"),
        _restrict(
            "artifact_owners",
            "experiment",
            ["experiment_id"],
            ["experiments.experiment_id"],
        ),
        _restrict(
            "artifact_owners",
            "run",
            ["experiment_id", "run_id"],
            ["engine_runs.experiment_id", "engine_runs.run_id"],
        ),
        _restrict(
            "artifact_owners",
            "invocation",
            ["run_id", "invocation_id"],
            ["command_invocations.run_id", "command_invocations.invocation_id"],
        ),
        _restrict(
            "artifact_owners", "dataset", ["dataset_id"], ["datasets.dataset_id"]
        ),
        _restrict(
            "artifact_owners",
            "strategy_version",
            ["strategy_version_id"],
            ["strategy_versions.strategy_version_id"],
        ),
        _restrict(
            "artifact_owners",
            "strategy_hash",
            ["strategy_version_hash"],
            ["strategy_versions.content_hash"],
        ),
        _check("artifact_owners", "owner_hash", _hash("owner_hash")),
        _check(
            "artifact_owners", "owner_kind", f"owner_kind IN ({_quoted(_OWNER_KINDS)})"
        ),
        _check(
            "artifact_owners", "experiment_id", _identifier("experiment_id", "exp_")
        ),
        _check("artifact_owners", "run_id", _identifier("run_id", "run_")),
        _check(
            "artifact_owners", "invocation_id", _identifier("invocation_id", "inv_")
        ),
        _check("artifact_owners", "dataset_id", _identifier("dataset_id", "ds_")),
        _check(
            "artifact_owners",
            "strategy_version_id",
            _identifier("strategy_version_id", "strv_"),
        ),
        _check(
            "artifact_owners", "strategy_version_hash", _hash("strategy_version_hash")
        ),
        _check(
            "artifact_owners",
            "adapter_name",
            _bounded_text("adapter_name", 1, _MAX_IDENTIFIER_TEXT),
        ),
        _check(
            "artifact_owners",
            "adapter_version",
            _bounded_text("adapter_version", _MIN_SEMVER_TEXT, _MAX_SEMVER_TEXT),
        ),
        _check(
            "artifact_owners",
            "engine_name",
            _bounded_text("engine_name", 1, _MAX_IDENTIFIER_TEXT),
        ),
        _check(
            "artifact_owners",
            "engine_version",
            _bounded_text("engine_version", _MIN_SEMVER_TEXT, _MAX_SEMVER_TEXT),
        ),
        _check(
            "artifact_owners",
            "core_component",
            _bounded_text("core_component", 1, _MAX_IDENTIFIER_TEXT),
        ),
        _check(
            "artifact_owners",
            "correlation_id",
            _bounded_text("correlation_id", 1, _MAX_IDENTIFIER_TEXT),
        ),
        _check(
            "artifact_owners",
            "run_variant",
            _owner_variant("RUN", ("experiment_id", "run_id"), ("invocation_id",)),
        ),
        _check(
            "artifact_owners",
            "experiment_variant",
            _owner_variant("EXPERIMENT", ("experiment_id",)),
        ),
        _check(
            "artifact_owners",
            "dataset_variant",
            _owner_variant("DATASET", ("dataset_id",)),
        ),
        _check(
            "artifact_owners",
            "strategy_variant",
            f"owner_kind <> 'STRATEGY' OR (({_present('strategy_version_id')}) <> "
            f"({_present('strategy_version_hash')}) AND {_absent('experiment_id')} AND "
            f"{_absent('run_id')} AND {_absent('invocation_id')} AND "
            f"{_absent('dataset_id')} AND {_absent('adapter_name')} AND "
            f"{_absent('adapter_version')} AND {_absent('engine_name')} AND "
            f"{_absent('engine_version')} AND {_absent('core_component')} AND "
            f"{_absent('correlation_id')})",
        ),
        _check(
            "artifact_owners",
            "adapter_variant",
            f"owner_kind <> 'ADAPTER' OR ({_present('adapter_name')} AND "
            f"{_present('adapter_version')} AND ({_absent('engine_name')}) = "
            f"({_absent('engine_version')}) AND {_absent('experiment_id')} AND "
            f"{_absent('run_id')} AND {_absent('invocation_id')} AND "
            f"{_absent('dataset_id')} AND {_absent('strategy_version_id')} AND "
            f"{_absent('strategy_version_hash')} AND {_absent('core_component')} AND "
            f"{_absent('correlation_id')})",
        ),
        _check(
            "artifact_owners",
            "system_variant",
            _owner_variant("SYSTEM", ("core_component", "correlation_id")),
        ),
        Index(
            "ix_artifact_owners_owner_kind_experiment_id", "owner_kind", "experiment_id"
        ),
        Index("ix_artifact_owners_owner_kind_run_id", "owner_kind", "run_id"),
        Index("ix_artifact_owners_dataset_id", "dataset_id"),
        Index("ix_artifact_owners_strategy_version_hash", "strategy_version_hash"),
        Index(
            "ix_artifact_owners_adapter_name_adapter_version",
            "adapter_name",
            "adapter_version",
        ),
    )


# --------------------------------------------------------------------------
# 3.4 triggers and the exported SQL constants
# --------------------------------------------------------------------------


def _trigger(name: str, table: str, event: str, when: str | None, message: str) -> str:
    condition = f" WHEN {when}" if when is not None else ""
    return (
        f"CREATE TRIGGER {name} {event} ON {table}{condition} "
        f"BEGIN SELECT RAISE(ABORT, '{message}'); END"
    )


def _differs(columns: Iterable[str]) -> str:
    return " OR ".join(f"NEW.{column} IS NOT OLD.{column}" for column in columns)


def _triggers() -> tuple[tuple[str, str, str], ...]:
    """``(name, table, statement)`` for every section 3.4 trigger."""
    pre_queue = _subset(ExperimentState, _PRE_QUEUE_EXPERIMENT_STATES)
    rows: list[tuple[str, str, str]] = [
        (
            "trg_experiments_terminal_immutable",
            "experiments",
            _trigger(
                "trg_experiments_terminal_immutable",
                "experiments",
                "BEFORE UPDATE",
                f"OLD.state IN ({_TERMINAL_EXPERIMENT_LIST})",
                "terminal experiment is immutable",
            ),
        ),
        (
            "trg_experiments_spec_frozen",
            "experiments",
            _trigger(
                "trg_experiments_spec_frozen",
                "experiments",
                f"BEFORE UPDATE OF {', '.join(_FROZEN_SPEC_COLUMNS)}",
                f"OLD.state NOT IN ({pre_queue}) AND "
                f"({_differs(_FROZEN_SPEC_COLUMNS)})",
                "experiment spec is frozen at QUEUED",
            ),
        ),
        (
            "trg_experiments_queue_requires_snapshot",
            "experiments",
            _trigger(
                "trg_experiments_queue_requires_snapshot",
                "experiments",
                "BEFORE UPDATE OF state",
                f"NEW.state = '{ExperimentState.QUEUED.value}' AND "
                f"OLD.state <> '{ExperimentState.QUEUED.value}' AND "
                "NEW.configuration_snapshot_json IS NULL",
                "experiment cannot be queued without a frozen configuration snapshot",
            ),
        ),
        (
            "trg_experiments_snapshot_frozen",
            "experiments",
            _trigger(
                "trg_experiments_snapshot_frozen",
                "experiments",
                f"BEFORE UPDATE OF {', '.join(_SNAPSHOT_COLUMNS)}",
                "OLD.configuration_snapshot_json IS NOT NULL AND "
                "(NEW.configuration_snapshot_json IS NULL OR "
                f"(OLD.state NOT IN ({pre_queue}) AND "
                f"({_differs(_SNAPSHOT_COLUMNS)})))",
                "configuration snapshot is frozen at QUEUED",
            ),
        ),
        (
            "trg_engine_runs_terminal_immutable",
            "engine_runs",
            _trigger(
                "trg_engine_runs_terminal_immutable",
                "engine_runs",
                "BEFORE UPDATE",
                f"OLD.state IN ({_subset(EngineRunState, TERMINAL_ENGINE_RUN_STATES)})",
                "terminal engine run is immutable",
            ),
        ),
        (
            "trg_command_invocations_terminal_immutable",
            "command_invocations",
            _trigger(
                "trg_command_invocations_terminal_immutable",
                "command_invocations",
                "BEFORE UPDATE OF state",
                "OLD.state IN "
                f"({_TERMINAL_INVOCATION_LIST})"
                " AND NEW.state <> OLD.state",
                "terminal invocation state is immutable",
            ),
        ),
    ]
    for table in (
        "run_events",
        "retry_decisions",
        "runtime_availability_observations",
        "diagnostics",
        "diagnostic_causes",
        "strategy_versions",
        "datasets",
        "dataset_partitions",
        "artifact_owners",
    ):
        for event in ("UPDATE", "DELETE"):
            name = f"trg_{table}_append_only_{event.lower()}"
            rows.append(
                (
                    name,
                    table,
                    _trigger(
                        name, table, f"BEFORE {event}", None, f"{table} is append-only"
                    ),
                )
            )
    for table in ("experiments", "engine_runs", "command_invocations"):
        name = f"trg_{table}_no_delete"
        rows.append(
            (
                name,
                table,
                _trigger(
                    name,
                    table,
                    "BEFORE DELETE",
                    None,
                    f"{table} rows are never deleted",
                ),
            )
        )
    return tuple(rows)


_TRIGGERS: Final = _triggers()

#: Plan 3.4: the trigger statements the baseline revision executes verbatim.
TRIGGER_SQL: Final[tuple[str, ...]] = tuple(statement for _, _, statement in _TRIGGERS)


def normalized_sql(statement: str) -> str:
    """Whitespace runs collapsed to one space, ends stripped: the pinned form."""
    return " ".join(statement.split())


def _partial_indexes() -> tuple[Index, ...]:
    return tuple(
        index
        for name in TABLES_IN_DEPENDENCY_ORDER
        for index in sorted(
            metadata.tables[name].indexes, key=lambda item: str(item.name)
        )
        if index.dialect_options["sqlite"]["where"] is not None
    )


def _compile_index(index: Index) -> str:
    return str(CreateIndex(index).compile(dialect=_DIALECT))


#: Plan 3.3: the three partial indexes, compiled from the ``Index`` objects above
#: so the metadata module and the baseline revision share one definition.
PARTIAL_INDEX_SQL: Final[tuple[str, ...]] = tuple(
    _compile_index(index) for index in _partial_indexes()
)


class SchemaObject(NamedTuple):
    """One ``sqlite_master`` row: type, name, owning table, normalized SQL."""

    type: str
    name: str
    table: str
    sql: str


def _expected_schema_objects() -> tuple[SchemaObject, ...]:
    rows: list[SchemaObject] = [
        SchemaObject(
            "table", "alembic_version", "alembic_version", _ALEMBIC_VERSION_SQL
        )
    ]
    for name in TABLES_IN_DEPENDENCY_ORDER:
        table = metadata.tables[name]
        rows.append(
            SchemaObject(
                "table",
                name,
                name,
                normalized_sql(str(CreateTable(table).compile(dialect=_DIALECT))),
            )
        )
        rows.extend(
            SchemaObject(
                "index", str(index.name), name, normalized_sql(_compile_index(index))
            )
            for index in table.indexes
        )
    rows.extend(
        SchemaObject("trigger", name, table, normalized_sql(statement))
        for name, table, statement in _TRIGGERS
    )
    return tuple(sorted(rows, key=lambda row: (row.type, row.table, row.name)))


#: Plan 6.4: the pinned ``sqlite_master`` expectation a migrated database equals;
#: SQLite's internal ``sqlite_autoindex_*`` rows are not listed (their UNIQUE and
#: primary-key constraints are part of the table SQL).
EXPECTED_SCHEMA_OBJECTS: Final[tuple[SchemaObject, ...]] = _expected_schema_objects()
