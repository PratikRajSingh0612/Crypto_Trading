"""SQLite test support helpers for the Stage 8 persistence suites (plan 7.1).

Task 1 creates this module with exactly five helpers -- ``raw_connection``,
``file_sha256``, ``accept_any_revision``, ``ok`` and ``code`` -- and later tasks
extend it as plan section 7.1 tabulates, each helper in the task that first needs
it. ``raw_connection`` is the independent stdlib connection the concurrency cases
use for lock holders and raw statements; it is never bound to the engine under
test. ``file_sha256`` serves the no-mutation assertions of the refused opens.
``accept_any_revision`` is the accepting ``revision_policy`` the Task 1 database
probes pass to ``SqliteDatabase.open`` (written ``_accept`` in the plan's
sketches) so an unmigrated file opens. ``ok`` and ``code`` are the two ``Result``
narrowers every later task's tests use, with the same shapes as the shared
contract module's private ``_ok`` and ``_code`` helpers, which stay private and
are not imported here. Task 2 adds ``open_test_database``: ``open_for_migration``
on ``tmp_path / "registry.sqlite3"`` followed by ``apply_migrations`` only when
the revision report is not yet ``CURRENT``, so one helper serves the first open
and every reopen of a migrated file.

Task 3 adds five helpers (plan 7.1): ``causal_edges`` reads the restricted
``diagnostic_causes`` relation through a raw connection, ordered by both columns;
``install_refusing_edge_trigger`` and ``install_refusing_partition_trigger``
install the two test-only ``BEFORE INSERT`` triggers of cases C-31 and C-29 (c)
from fixed DDL text -- the partition trigger's ``WHEN`` clause carries an integer
literal rendered from ``int(ordinal)``, never an identity or a bound parameter,
because SQLite admits no variable inside ``CREATE TRIGGER``; ``sample_strategy_version``
builds one valid ``StrategyVersion`` over a fixed ``StrategySpec`` (the committed
``sma_cross_long.valid.yaml`` document as plain data) with ``content_hash`` computed
by the versioning module's own hash function, so the record's
``validate_identity_is_recomputed`` accepts it and a second call returns an equal
record; ``sample_dataset_with_partitions`` builds one ``DatasetDescriptor`` and
exactly two ``DatasetPartition`` values at ordinals 0 and 1, identity-consistent
through ``validate_dataset_identity``, the second partition being the one C-29 (c)'s
trigger refuses. The two builders import only the committed ``strategy`` and
``datasets`` modules and the doubles' constants; nothing here imports a lifecycle
repository, ``fixtures.py`` or ``SqliteHarness`` (Task 4). The module never
imports ``subprocess`` and never launches a child.

Task 4 adds the SQLite side of the shared contract suite (plan 7.1):
``SqliteHarness`` implements ``PortHarness`` over one migrated database, tracking
every unit of work it hands out so ``close()`` can roll back a transaction a test
abandoned before disposing the engine; ``put_lifecycle_parents`` inserts, each in
its own committed transaction and only when absent, the parents the shared
fixtures reference, and is harmless for the in-memory kind; ``commit``,
``put_experiment``, ``put_run``, ``put_invocation``, ``bump``, ``bump_run`` and
``bump_invocation`` are the promoted siblings of the contract module's private
helpers, whose own names stay private and are not imported; ``sample_run_event``
builds one sanitized heartbeat with its content hash recomputed, because the
doubles offer no event builder; ``sql_identity_literal`` checks a value against
the doubles' prefixed-UUID4 grammar and single-quotes it, the only way the two
Task 4 trigger installers can name a row, since SQLite admits no bound parameter
inside ``CREATE TRIGGER``; and ``CasSubject``/``CAS_SUBJECTS`` carry the three
compare-and-swap repositories of C-30 through one parametrized case.

Task 6 adds the two units of work of plan 5.2 and 7.1. ``InterleavingUnitOfWork``
wraps a ``SqliteUnitOfWork``: ``begin()`` counts into ``begins`` and, for each
attempt number listed in ``on_attempts``, that transaction's first repository read
runs ``after_read`` once after returning its value -- the read has established the
transaction's WAL snapshot, so a winner the hook commits on its own connection is
refused at the loser's first write by the snapshot rule, never by timing (the same
shape as the doubles' ``MemberOverridingUnitOfWork`` and one-shot hooks; C-5 to C-8,
C-10 to C-13). ``CountingUnitOfWork`` wraps a unit of work so that ``begin()``
increments ``open_now`` and ``commit()``/``rollback()`` decrement it exactly once
per actual release -- an explicit rollback, the driver's ``finally``, an early
``Failure`` and an escaping exception all release once, a second call releases
nothing, and a member access counts nothing -- with ``max_open`` and ``reset_max()``
for Task 7's "no transaction across the child" assertion; it has no notion of a
child. Neither wrapper opens a connection, sleeps or reads a clock.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, Final, Protocol, cast

from sqlalchemy import Select, select
from sqlalchemy.engine import Connection

from crypto_lab.adapters.events import (
    HeartbeatPayload,
    RunEvent,
    run_event_content_hash,
)
from crypto_lab.adapters.ports import CommandInvocationRepository
from crypto_lab.adapters.vocabulary import ProtocolEventType
from crypto_lab.datasets.hashing import dataset_metadata_hash, validate_dataset_identity
from crypto_lab.datasets.models import (
    DatasetDataType,
    DatasetDescriptor,
    DatasetPartition,
    DatasetValidationStatus,
    RawSourceProvenance,
)
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.descriptors import RuntimeAvailabilityObservation
from crypto_lab.domain.diagnostics import Diagnostic
from crypto_lab.domain.engine_run import EngineRunRecord
from crypto_lab.domain.experiment import ExperimentRecord
from crypto_lab.domain.hashing import attempt_token_hash, sha256_bytes
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.ports import Clock
from crypto_lab.domain.records import InstrumentRef, MarketType
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.domain.retry import RetryDecisionRecord
from crypto_lab.experiments.ports import (
    DiagnosticReader,
    EngineRunRepository,
    ExperimentRepository,
    RetryDecisionRepository,
    RuntimeAvailabilityObservationReader,
    UnitOfWork,
)
from crypto_lab.persistence.codecs import (
    decode_command_invocation,
    decode_engine_run,
    decode_experiment,
    decode_retry_decision,
)
from crypto_lab.persistence.database import SqliteDatabase
from crypto_lab.persistence.migration_runner import (
    RevisionState,
    apply_migrations,
    check_revision,
    open_for_migration,
)
from crypto_lab.persistence.registries import SqliteDiagnosticRecorder
from crypto_lab.persistence.schema import (
    CommandInvocationRow,
    EngineRunRow,
    ExperimentRow,
    RetryDecisionRow,
)
from crypto_lab.persistence.unit_of_work import SqliteTransaction, SqliteUnitOfWork
from crypto_lab.strategy.models import StrategySpec
from crypto_lab.strategy.versioning import (
    STRATEGY_VERSION_PROFILE_VERSION,
    StrategySourceProvenance,
    StrategyVersion,
    sorted_extension_hashes,
    strategy_version_hash,
    strategy_version_identifier,
)
from doubles.experiments import (
    ATTEMPT_TOKEN,
    AVAIL_A,
    EXPERIMENT_ID,
    INSTANT,
    INVOCATION_ID,
    RUN_ID,
    UUID_A,
    UUID_B,
    UUID_E,
    FixedClock,
    sample_experiment,
    sample_invocation,
    sample_observation,
    sample_run,
)

__all__ = [
    "CAS_SUBJECTS",
    "EVENT_ID",
    "OTHER_EVENT_ID",
    "CasSubject",
    "CountingUnitOfWork",
    "InterleavingUnitOfWork",
    "SqliteHarness",
    "TransactionSource",
    "accept_any_revision",
    "bump",
    "bump_invocation",
    "bump_run",
    "causal_edges",
    "code",
    "commit",
    "file_sha256",
    "install_ignoring_update_trigger",
    "install_refusing_edge_trigger",
    "install_refusing_partition_trigger",
    "install_refusing_slot_trigger",
    "ok",
    "open_test_database",
    "put_experiment",
    "put_invocation",
    "put_lifecycle_parents",
    "put_run",
    "raw_connection",
    "sample_dataset_with_partitions",
    "sample_run_event",
    "sample_strategy_version",
    "sql_identity_literal",
]

#: Plan 7.1: the two test-only triggers, fixed DDL text (C-31, C-29 (c)).
_REFUSING_EDGE_TRIGGER: Final = (
    "CREATE TRIGGER test_refuse_edge BEFORE INSERT ON diagnostic_causes "
    "BEGIN SELECT RAISE(ABORT, 'test: edge refused'); END"
)
_REFUSING_PARTITION_TRIGGER_HEAD: Final = (
    "CREATE TRIGGER test_refuse_partition BEFORE INSERT ON dataset_partitions "
    "WHEN NEW.ordinal = "
)
_REFUSING_PARTITION_TRIGGER_TAIL: Final = (
    " BEGIN SELECT RAISE(ABORT, 'test: partition refused'); END"
)
_CAUSAL_EDGES_SQL: Final = (
    "SELECT diagnostic_id, causal_diagnostic_id FROM diagnostic_causes ORDER BY 1, 2"
)

#: The committed ``sma_cross_long.valid.yaml`` document as plain data, so the
#: fixed ``StrategySpec`` needs no file read; validated in JSON mode below.
_STRATEGY_SPEC_DOCUMENT: Final[dict[str, Any]] = {
    "schema_version": "1.0.0",
    "strategy_id": "strat_3f2504e0-4f89-41d3-9a0c-0305e82c3301",
    "display_name": "SMA Cross Long",
    "description": (
        "Enters long when a fast average crosses above a slow average and exits "
        "on the reverse cross."
    ),
    "strategy_family": "trend_following",
    "market_type": "SPOT",
    "direction": "LONG",
    "timeframe": "1h",
    "universe": {"kind": "STATIC", "instruments": ["BINANCE:BTC/USDT:SPOT"]},
    "required_capabilities": [
        {
            "schema_version": "1.0.0",
            "capability": capability,
            "required": True,
            "minimum_semantics": "capabilities/v1",
            "approximation_policy": "REJECT",
            "comparison_levels": levels,
        }
        for capability, levels in (
            ("market.spot", ["LEVEL_1", "LEVEL_2"]),
            ("direction.long", ["LEVEL_1", "LEVEL_2"]),
            ("data.ohlcv", ["LEVEL_1", "LEVEL_2"]),
            ("execution.bar_market", ["LEVEL_2"]),
            ("runtime.backtest", []),
        )
    ],
    "parameters": {
        "fast_period": {"value_type": "INTEGER", "value": 20, "minimum": 2},
        "slow_period": {"value_type": "INTEGER", "value": 50, "minimum": 3},
    },
    "features": [
        {
            "id": "fast_sma",
            "operation": "indicator.sma/v1",
            "inputs": ["bar.close"],
            "parameters": {"period": "fast_period"},
            "output_type": "DECIMAL",
            "warm_up_bars": 20,
            "missing_value_policy": "PROPAGATE_FALSE",
        },
        {
            "id": "slow_sma",
            "operation": "indicator.sma/v1",
            "inputs": ["bar.close"],
            "parameters": {"period": "slow_period"},
            "output_type": "DECIMAL",
            "warm_up_bars": 50,
            "missing_value_policy": "PROPAGATE_FALSE",
        },
    ],
    "entry_rules": [
        {
            "id": "enter_cross",
            "expression": {
                "op": "crosses_above",
                "left": {"op": "ref", "id": "fast_sma", "bars_ago": 0},
                "right": {"op": "ref", "id": "slow_sma", "bars_ago": 0},
            },
        }
    ],
    "exit_rules": [
        {
            "id": "exit_cross",
            "expression": {
                "op": "crosses_below",
                "left": {"op": "ref", "id": "fast_sma", "bars_ago": 0},
                "right": {"op": "ref", "id": "slow_sma", "bars_ago": 0},
            },
        }
    ],
    "sizing_intent": {"method": "FRACTION_OF_AVAILABLE_QUOTE", "fraction": "1"},
    "risk_assumptions": {"leverage": "1", "shorting_allowed": False},
    "warm_up_requirements": {"minimum_bars": 50},
    "comparison_requirements": {"maximum_level": "LEVEL_2"},
    "supported_approximation_policy": {"default": "REJECT"},
    "engine_extensions": [],
    "authoring_metadata": {
        "author": "local_user",
        "created_at_utc": "2026-08-10T00:00:00Z",
    },
}
_STRATEGY_SOURCE_BYTES: Final = b"schema_version: placeholder"
_STRATEGY_SOURCE_NAME: Final = "sma_cross_long.valid.yaml"

#: The dataset fixture identities and interval (the shape of
#: ``tests/unit/datasets/test_dataset_metadata_hashing.py::_models``).
DATASET_ID: Final = f"ds_{UUID_A}"
PARTITION_IDS: Final = (f"part_{UUID_A}", f"part_{UUID_B}")
_DATASET_START: Final = INSTANT - timedelta(days=2)
_DATASET_MIDDLE: Final = INSTANT - timedelta(days=1)
_DATASET_END: Final = INSTANT


def raw_connection(path: Path) -> sqlite3.Connection:
    """A stdlib connection with explicit transaction control.

    ``isolation_level=None`` disables the DBAPI's implicit ``BEGIN``, so a lock
    holder issues ``BEGIN IMMEDIATE`` itself and a raw statement autocommits.
    The caller closes it in ``finally:`` (plan 7.5).
    """
    return sqlite3.connect(path, isolation_level=None)


def file_sha256(path: Path) -> str:
    """The SHA-256 hex digest of the main database file, for C-20 and C-21."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def accept_any_revision(connection: Connection) -> Result[None]:
    """The accepting revision policy: ``Success(None)`` without reading anything."""
    del connection
    return Success[None](outcome="SUCCESS", value=None)


def ok[T](result: Success[T] | Failure) -> T:
    """Narrow a ``Result`` to its ``Success`` value, failing on a ``Failure``."""
    assert isinstance(result, Success), result
    return result.value


def code(result: object) -> str:
    """Narrow a ``Result`` to the error code of its single ``Failure`` diagnostic."""
    assert isinstance(result, Failure), result
    assert len(result.diagnostics) == 1
    return result.diagnostics[0].error_code


def open_test_database(
    tmp_path: Path, *, busy_timeout_ms: int = 100, clock: Clock
) -> SqliteDatabase:
    """The migrated test database at ``tmp_path / "registry.sqlite3"`` (plan 7.1).

    ``open_for_migration`` admits ``EMPTY``, ``BEHIND`` and ``CURRENT``;
    ``apply_migrations`` runs only when the report is not yet ``CURRENT``, so a
    current file reopens unchanged. The caller closes the database in
    ``finally:`` or through the ``sqlite_database`` fixture.
    """
    database = ok(
        open_for_migration(
            tmp_path / "registry.sqlite3", busy_timeout_ms=busy_timeout_ms, clock=clock
        )
    )
    try:
        with database.read_only() as connection:
            report = check_revision(connection)
        if report.state is not RevisionState.CURRENT:
            ok(apply_migrations(database))
    except BaseException:
        database.close()
        raise
    return database


# --------------------------------------------------------------------------
# Task 3 (plan 7.1): the causal-edge reader and the two test-only triggers
# --------------------------------------------------------------------------


def _execute_raw(database: SqliteDatabase, statement: str) -> list[tuple[Any, ...]]:
    connection = raw_connection(database.path)
    try:
        return list(connection.execute(statement).fetchall())
    finally:
        connection.close()


def causal_edges(database: SqliteDatabase) -> tuple[tuple[str, str], ...]:
    """Every ``(diagnostic_id, causal_diagnostic_id)`` row, ordered by both columns.

    Read through an independent stdlib connection, so no engine-side state can
    stand in for the durable relation (C-31, Task 7).
    """
    return tuple(
        (str(referrer), str(cause))
        for referrer, cause in _execute_raw(database, _CAUSAL_EDGES_SQL)
    )


def install_refusing_edge_trigger(database: SqliteDatabase) -> None:
    """C-31: refuse every insert into ``diagnostic_causes`` (fixed DDL text)."""
    _execute_raw(database, _REFUSING_EDGE_TRIGGER)


def install_refusing_partition_trigger(database: SqliteDatabase, ordinal: int) -> None:
    """C-29 (c): refuse the ``dataset_partitions`` insert at exactly ``ordinal``.

    The ``WHEN`` clause carries ``str(int(ordinal))`` -- an integer literal, no
    identity and no bound parameter, because SQLite admits no variable inside
    ``CREATE TRIGGER``; every data statement of the tests keeps bound parameters.
    """
    if isinstance(ordinal, bool) or not isinstance(ordinal, int):
        raise TypeError("ordinal must be a built-in integer")
    _execute_raw(
        database,
        _REFUSING_PARTITION_TRIGGER_HEAD
        + str(int(ordinal))
        + _REFUSING_PARTITION_TRIGGER_TAIL,
    )


# --------------------------------------------------------------------------
# Task 3 (plan 7.1): the two registry fixture builders
# --------------------------------------------------------------------------


def sample_strategy_version() -> StrategyVersion:
    """One valid ``StrategyVersion`` over the fixed spec at ``INSTANT`` (plan 7.1).

    ``content_hash`` is the versioning module's own ``strategy_version_hash`` and
    ``strategy_version_id`` its deterministic derivation, so the record's
    ``validate_identity_is_recomputed`` accepts it; a second call returns an
    equal record.
    """
    spec = StrategySpec.model_validate_json(
        canonical_json_bytes(_STRATEGY_SPEC_DOCUMENT)
    )
    content_hash = strategy_version_hash(spec)
    return StrategyVersion(
        schema_version="1.0.0",
        strategy_version_id=strategy_version_identifier(content_hash),
        strategy_id=spec.strategy_id,
        content_hash=content_hash,
        strategy_spec=spec,
        extension_hashes=tuple(sorted_extension_hashes(spec.engine_extensions)),
        hashing_profile_version=STRATEGY_VERSION_PROFILE_VERSION,
        created_at_utc=INSTANT,
        source_provenance=StrategySourceProvenance(
            source_name=_STRATEGY_SOURCE_NAME,
            source_bytes_sha256=sha256_bytes(_STRATEGY_SOURCE_BYTES),
            source_byte_length=len(_STRATEGY_SOURCE_BYTES),
            observed_at_utc=INSTANT,
        ),
    )


def _dataset_provenance() -> RawSourceProvenance:
    return RawSourceProvenance(
        source_name="fixture.source",
        source_version="1.0.0",
        source_record="fixture",
        source_hash="1" * 64,
    )


def _dataset_partition(
    *,
    partition_id: str,
    ordinal: int,
    start: object,
    end: object,
    raw: str,
    normalized: str,
) -> DatasetPartition:
    return DatasetPartition.model_validate(
        {
            "schema_version": "1.0.0",
            "partition_id": partition_id,
            "dataset_id": DATASET_ID,
            "ordinal": ordinal,
            "relative_path": f"ohlcv/{ordinal}.parquet",
            "content_hash": str(ordinal + 3) * 64,
            "row_count": 10 + ordinal,
            "start_utc": start,
            "end_utc": end,
            "raw_checksum": raw,
            "normalized_checksum": normalized,
            "column_schema_version": "1.0.0",
            "raw_source_provenance": (_dataset_provenance(),),
            "quality_observations": (),
        }
    )


def sample_dataset_with_partitions() -> tuple[
    DatasetDescriptor, tuple[DatasetPartition, ...]
]:
    """One ``DatasetDescriptor`` and exactly two partitions at ordinals 0 and 1.

    Identity-consistent through ``validate_dataset_identity``: the descriptor's
    ``content_hash`` is ``dataset_metadata_hash`` over the descriptor's material
    fields and the ordered partitions. The second partition (ordinal 1) is the
    one C-29 (c)'s trigger refuses.
    """
    partitions = (
        _dataset_partition(
            partition_id=PARTITION_IDS[0],
            ordinal=0,
            start=_DATASET_START,
            end=_DATASET_MIDDLE,
            raw="1" * 64,
            normalized="2" * 64,
        ),
        _dataset_partition(
            partition_id=PARTITION_IDS[1],
            ordinal=1,
            start=_DATASET_MIDDLE,
            end=_DATASET_END,
            raw="2" * 64,
            normalized="1" * 64,
        ),
    )
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "dataset_id": DATASET_ID,
        "content_hash": "0" * 64,
        "source": "fixture",
        "venue": "BINANCE",
        "instrument": InstrumentRef(
            schema_version="1.0.0",
            canonical_id="BINANCE:BTC/USDT:SPOT",
            venue="BINANCE",
            base_asset="BTC",
            quote_asset="USDT",
            market_type=MarketType.SPOT,
        ),
        "data_type": DatasetDataType.OHLCV,
        "timeframe": "1m",
        "start_utc": _DATASET_START,
        "end_utc": _DATASET_END,
        "original_timezone": "UTC",
        "normalized_to_utc": True,
        "raw_source_provenance": (_dataset_provenance(),),
        "normalization_implementation": "fixture.normalizer",
        "normalization_version": "1.0.0",
        "validation_status": DatasetValidationStatus.VALID,
        "partition_ids": PARTITION_IDS,
        "missing_intervals": (),
        "duplicate_intervals": (),
        "diagnostic_ids": (),
        "raw_checksums": tuple(item.raw_checksum for item in partitions),
        "normalized_checksums": tuple(item.normalized_checksum for item in partitions),
        "column_schema_version": "1.0.0",
        "known_limitations": (),
        "created_at_utc": INSTANT,
    }
    unhashed = DatasetDescriptor.model_validate(payload)
    payload["content_hash"] = dataset_metadata_hash(unhashed, partitions)
    descriptor = DatasetDescriptor.model_validate(payload)
    validate_dataset_identity(descriptor, partitions)
    return descriptor, partitions


# --------------------------------------------------------------------------
# Task 4 (plan 7.1): the promoted helpers, the SQLite harness, the lifecycle
# parents, the two test-only triggers and the compare-and-swap subjects
# --------------------------------------------------------------------------

_E: Final = ExperimentState
_R: Final = EngineRunState
_C: Final = CommandInvocationState

#: The two sanitized-event identities Task 4's cases use; the doubles define none.
EVENT_ID: Final = f"evt_{UUID_A}"
OTHER_EVENT_ID: Final = f"evt_{UUID_B}"
#: Plan 7.1: the doubles' prefixed UUID4 grammar, the only shape a trigger
#: installer may embed as a literal.
_IDENTITY_GRAMMAR: Final = re.compile(
    r"^[a-z]+_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
#: The three fixed ``(table, identity_column)`` pairs the ignoring trigger admits.
_UPDATE_TRIGGER_TARGETS: Final[frozenset[tuple[str, str]]] = frozenset(
    {
        ("experiments", "experiment_id"),
        ("engine_runs", "run_id"),
        ("command_invocations", "invocation_id"),
    }
)


class TransactionSource(Protocol):
    """The one member the promoted ``put_*`` helpers need of either harness kind."""

    def unit_of_work(self) -> UnitOfWork: ...


class LifecycleHarness(TransactionSource, Protocol):
    """``TransactionSource`` plus the observation seeder ``put_lifecycle_parents``
    needs, so the helper serves the in-memory and the SQLite kind alike."""

    def seed_observation(self, observation: RuntimeAvailabilityObservation) -> None: ...


def commit(unit_of_work: UnitOfWork) -> None:
    """Commit a transaction, failing the test on any refusal."""
    committed = unit_of_work.commit()
    assert isinstance(committed, Success), committed


def put_experiment(harness: TransactionSource, record: ExperimentRecord) -> None:
    """Insert one experiment in its own committed transaction."""
    transaction = harness.unit_of_work().begin()
    ok(transaction.experiments.add(record))
    commit(transaction)


def put_run(harness: TransactionSource, record: EngineRunRecord) -> None:
    """Insert one attempt in its own committed transaction."""
    transaction = harness.unit_of_work().begin()
    ok(transaction.engine_runs.add_attempt(record))
    commit(transaction)


def put_invocation(harness: TransactionSource, record: CommandInvocationRecord) -> None:
    """Insert one invocation in its own committed transaction."""
    transaction = harness.unit_of_work().begin()
    ok(transaction.command_invocations.add(record))
    commit(transaction)


def bump(record: ExperimentRecord) -> ExperimentRecord:
    """The same experiment one revision and one second later."""
    payload = record.model_dump(mode="python")
    payload["revision"] = record.revision + 1
    payload["updated_at_utc"] = record.updated_at_utc + timedelta(seconds=1)
    return ExperimentRecord.model_validate(payload)


def bump_run(record: EngineRunRecord, target: EngineRunState) -> EngineRunRecord:
    """The same attempt one revision later in ``target``."""
    payload = record.model_dump(mode="python")
    payload["state"] = target
    payload["revision"] = record.revision + 1
    payload["updated_at_utc"] = record.updated_at_utc + timedelta(seconds=1)
    if target is _R.READY:
        payload["availability_observation_id"] = AVAIL_A
    return EngineRunRecord.model_validate(payload)


def bump_invocation(
    record: CommandInvocationRecord, target: CommandInvocationState
) -> CommandInvocationRecord:
    """The same invocation one revision later in ``target``."""
    payload = record.model_dump(mode="python")
    instant = record.updated_at_utc + timedelta(seconds=1)
    payload["state"] = target
    payload["revision"] = record.revision + 1
    payload["updated_at_utc"] = instant
    if target is _C.STARTING:
        payload["launch_attempted_at_utc"] = instant
        payload["deadline_utc"] = instant + timedelta(seconds=record.timeout_seconds)
    return CommandInvocationRecord.model_validate(payload)


def sample_run_event(
    *,
    sequence: int = 1,
    event_id: str = EVENT_ID,
    invocation_id: str = INVOCATION_ID,
    run_id: str = RUN_ID,
    phase: str = "warmup",
) -> RunEvent:
    """One sanitized heartbeat with its ``RUN_EVENT_CONTENT_V1`` hash recomputed.

    ``phase`` is the one material field a caller varies to obtain a second event
    with the same key and a different ``content_hash`` (C-14); the raw attempt
    token never enters the record, only ``attempt_token_hash``.
    """
    draft = RunEvent.model_construct(
        schema_version="1.0.0",
        protocol_version="1.0.0",
        event_id=event_id,
        invocation_id=invocation_id,
        run_id=run_id,
        attempt_token_hash=attempt_token_hash(ATTEMPT_TOKEN),
        sequence=sequence,
        event_type=ProtocolEventType.HEARTBEAT,
        timestamp_utc=INSTANT + timedelta(seconds=sequence),
        payload=HeartbeatPayload(activity_counter=sequence, phase=phase),
        received_at_utc=INSTANT + timedelta(seconds=sequence, microseconds=1),
        wire_event_hash="b" * 64,
        content_hash="0" * 64,
    )
    payload = draft.model_dump(mode="python")
    payload["content_hash"] = run_event_content_hash(draft)
    return RunEvent.model_validate(payload)


class SqliteHarness:
    """``PortHarness`` over one migrated SQLite database (plan 7.1).

    Every unit of work it hands out is tracked, so ``close()`` can roll back a
    transaction a test abandoned -- a ``del``-ed one included -- before disposing
    the engine, and no lock or handle survives a test. The committed readers open
    a fresh read-only session each time, so no writer's session and no cached
    record can stand in for durable evidence.
    """

    __slots__ = ("_clock", "_units", "database")

    def __init__(self, database: SqliteDatabase) -> None:
        self.database = database
        self._clock = FixedClock(INSTANT)
        self._units: list[SqliteUnitOfWork] = []

    def unit_of_work(self) -> SqliteUnitOfWork:
        """A fresh root over the same database, tracked for teardown."""
        unit = SqliteUnitOfWork(self.database, self._clock)
        self._units.append(unit)
        return unit

    def seed_diagnostic(self, diagnostic: Diagnostic) -> None:
        """Record one diagnostic through the recorder's autonomous transaction."""
        recorder = SqliteDiagnosticRecorder(self.database, clock=self._clock)
        ok(recorder.record(diagnostic))

    def seed_observation(self, observation: RuntimeAvailabilityObservation) -> None:
        """Insert one observation through the writer in its own transaction."""
        transaction = self.unit_of_work().begin()
        ok(transaction.availability_observation_writer.add(observation))
        commit(transaction)

    def committed_experiments(self) -> tuple[ExperimentRecord, ...]:
        statement = select(ExperimentRow).order_by(ExperimentRow.experiment_id)
        return tuple(
            ok(decode_experiment(row, clock=self._clock))
            for row in self._rows(statement)
        )

    def committed_engine_runs(self) -> tuple[EngineRunRecord, ...]:
        statement = select(EngineRunRow).order_by(EngineRunRow.run_id)
        return tuple(
            ok(decode_engine_run(row, clock=self._clock))
            for row in self._rows(statement)
        )

    def committed_command_invocations(self) -> tuple[CommandInvocationRecord, ...]:
        statement = select(CommandInvocationRow).order_by(
            CommandInvocationRow.invocation_id
        )
        return tuple(
            ok(decode_command_invocation(row, clock=self._clock))
            for row in self._rows(statement)
        )

    def committed_retry_decisions(self) -> tuple[RetryDecisionRecord, ...]:
        statement = select(RetryDecisionRow).order_by(
            RetryDecisionRow.logical_slot_id, RetryDecisionRow.predecessor_run_id
        )
        return tuple(
            ok(decode_retry_decision(row, clock=self._clock))
            for row in self._rows(statement)
        )

    def open_transactions(self) -> tuple[SqliteTransaction, ...]:
        """Every transaction of every unit of work this harness handed out."""
        return tuple(
            transaction
            for unit in self._units
            for transaction in unit.open_transactions()
        )

    def close(self) -> None:
        """Roll back every surviving transaction, then dispose the engine."""
        for transaction in self.open_transactions():
            transaction.rollback()
        self._units.clear()
        self.database.close()

    def _rows(self, statement: Select[Any]) -> tuple[dict[str, object], ...]:
        with self.database.read_only() as connection:
            return tuple(
                {str(key): value for key, value in row.items()}
                for row in connection.execute(statement).mappings().all()
            )


def _absent(harness: TransactionSource, read: Callable[[UnitOfWork], object]) -> bool:
    """Is the row ``read`` names absent from committed state?"""
    transaction = harness.unit_of_work().begin()
    try:
        return isinstance(read(transaction), Failure)
    finally:
        transaction.rollback()


def put_lifecycle_parents(
    harness: LifecycleHarness,
    *,
    experiment_id: str = EXPERIMENT_ID,
    run: bool = False,
    invocation: bool = False,
    observation: bool = False,
) -> None:
    """Insert the parents the shared fixtures reference, each when absent (7.1).

    The seeded experiment is inserted directly at ``QUEUED`` through ``add``, so
    it freezes no configuration snapshot and ``consistency_report()`` counts it in
    ``queued_without_snapshot``; only Task 7's flows, which queue through
    ``queue_experiment``, assert that count. Harmless for the in-memory kind.
    """
    assert run or not invocation, "an invocation's foreign key needs its run"
    if _absent(harness, lambda opened: opened.experiments.get(experiment_id)):
        put_experiment(
            harness, sample_experiment(_E.QUEUED, experiment_id=experiment_id)
        )
    if observation and _absent(
        harness, lambda opened: opened.availability_observations.get(AVAIL_A)
    ):
        harness.seed_observation(sample_observation(AVAIL_A))
    if run and _absent(harness, lambda opened: opened.engine_runs.get(RUN_ID)):
        put_run(harness, sample_run(_R.PENDING, experiment_id=experiment_id))
    if invocation and _absent(
        harness, lambda opened: opened.command_invocations.get(INVOCATION_ID)
    ):
        put_invocation(harness, sample_invocation(_C.RUNNING))


def sql_identity_literal(identity: str) -> str:
    """The checked single-quoted literal a ``CREATE TRIGGER`` may embed (plan 7.1).

    SQLite refuses a bound parameter inside ``CREATE TRIGGER`` ("trigger cannot
    use variables"), so the two Task 4 installers compose their DDL from fixed
    text plus this literal of a fixture constant -- never from a row value and
    never as a general interpolation. Every data statement keeps its parameters.
    """
    if _IDENTITY_GRAMMAR.match(identity) is None:
        raise ValueError("identity does not match the fixture identifier grammar")
    return f"'{identity}'"


def install_refusing_slot_trigger(
    database: SqliteDatabase, logical_slot_id: str
) -> None:
    """C-29 (a), (b): refuse the ``engine_slots`` insert of exactly that slot."""
    _execute_raw(
        database,
        "CREATE TRIGGER test_refuse_slot BEFORE INSERT ON engine_slots "
        f"WHEN NEW.logical_slot_id = {sql_identity_literal(logical_slot_id)} "
        "BEGIN SELECT RAISE(ABORT, 'test: slot refused'); END",
    )


def install_ignoring_update_trigger(
    database: SqliteDatabase, table: str, identity_column: str, identity: str
) -> None:
    """C-30: make a conditional ``UPDATE`` of that row report zero affected rows.

    ``RAISE(IGNORE)`` in a ``BEFORE UPDATE`` trigger skips the row silently, which
    is the only way to reach plan 4.3.1 step f by rowcount from inside one
    connection. ``(table, identity_column)`` must be one of the three fixed pairs.
    """
    if (table, identity_column) not in _UPDATE_TRIGGER_TARGETS:
        raise ValueError("table and identity column must be a reviewed pair")
    _execute_raw(
        database,
        f"CREATE TRIGGER test_ignore_update BEFORE UPDATE ON {table} "
        f"WHEN NEW.{identity_column} = {sql_identity_literal(identity)} "
        "BEGIN SELECT RAISE(IGNORE); END",
    )


@dataclass(frozen=True, slots=True)
class CasSubject:
    """One compare-and-swap repository with its fixtures and narrowers (C-30)."""

    name: str
    member: str
    seed_parents: Callable[[SqliteHarness], None]
    record: Callable[[], Any]
    put: Callable[[SqliteHarness, Any], None]
    identity: Callable[[Any], str]
    rekey: Callable[[Any], Any]
    bump: Callable[[Any], Any]
    insert: Callable[[Any, Any], Result[None]]
    committed: Callable[[SqliteHarness], tuple[Any, ...]]


#: Plan 7.1: one subject per compare-and-swap repository, so the 4.3.1 order is
#: walked once per repository rather than written three times.
CAS_SUBJECTS: Final[tuple[CasSubject, ...]] = (
    CasSubject(
        name="experiments",
        member="experiments",
        seed_parents=lambda harness: None,
        record=lambda: sample_experiment(_E.DRAFT),
        put=put_experiment,
        identity=lambda record: str(record.experiment_id),
        rekey=lambda record: sample_experiment(_E.DRAFT, experiment_id=f"exp_{UUID_E}"),
        bump=bump,
        insert=lambda repository, record: repository.add(record),
        committed=lambda harness: harness.committed_experiments(),
    ),
    CasSubject(
        name="engine_runs",
        member="engine_runs",
        seed_parents=put_lifecycle_parents,
        record=lambda: sample_run(_R.PENDING),
        put=put_run,
        identity=lambda record: str(record.run_id),
        rekey=lambda record: sample_run(_R.PENDING, run_id=f"run_{UUID_E}"),
        bump=lambda record: bump_run(record, _R.VALIDATING),
        insert=lambda repository, record: repository.add_attempt(record),
        committed=lambda harness: harness.committed_engine_runs(),
    ),
    CasSubject(
        name="command_invocations",
        member="command_invocations",
        seed_parents=lambda harness: put_lifecycle_parents(harness, run=True),
        record=lambda: sample_invocation(_C.PENDING),
        put=put_invocation,
        identity=lambda record: str(record.invocation_id),
        rekey=lambda record: sample_invocation(
            _C.PENDING, invocation_id=f"inv_{UUID_E}"
        ),
        bump=lambda record: bump_invocation(record, _C.STARTING),
        insert=lambda repository, record: repository.add(record),
        committed=lambda harness: harness.committed_command_invocations(),
    ),
)


# --------------------------------------------------------------------------
# Task 6 (plan 5.2, 7.1): the interleaving and counting units of work
# --------------------------------------------------------------------------

#: Plan 5.2: the port methods that read. The first of them on a listed attempt
#: fires ``after_read`` once, after it returned -- the WAL snapshot now exists.
_READ_METHODS: Final[frozenset[str]] = frozenset(
    {
        "count_attempts",
        "get",
        "get_by_attempt_number",
        "get_by_predecessor",
        "get_many",
        "latest_attempt",
        "list_events",
        "list_for_adapter",
        "list_for_run",
    }
)


class _InterleavingState:
    """The ``begin()`` count and the hook, shared by a root and its transactions."""

    __slots__ = ("after_read", "begins", "on_attempts")

    def __init__(
        self, after_read: Callable[[], None], on_attempts: tuple[int, ...]
    ) -> None:
        self.after_read = after_read
        self.on_attempts = on_attempts
        self.begins = 0


class _InterleavedMember:
    """Delegates every attribute to ``target``; a method call reports its name to
    ``observe`` after returning its value."""

    def __init__(self, target: object, observe: Callable[[str], None]) -> None:
        self._target = target
        self._observe = observe

    def __getattr__(self, name: str) -> Any:
        attribute = getattr(self._target, name)
        if not callable(attribute):
            return attribute

        def call(*args: Any, **kwargs: Any) -> Any:
            value = attribute(*args, **kwargs)
            self._observe(name)
            return value

        return call


class _InterleavingTransaction:
    """One transaction of ``InterleavingUnitOfWork``: the six port members are
    proxied so the first read of a listed attempt runs the hook exactly once."""

    def __init__(
        self, inner: SqliteTransaction, state: _InterleavingState, *, armed: bool
    ) -> None:
        self._inner = inner
        self._state = state
        self._armed = armed

    def _observe(self, method: str) -> None:
        if self._armed and method in _READ_METHODS:
            self._armed = False
            self._state.after_read()

    def begin(self) -> UnitOfWork:
        """A programmer defect, exactly as on the inner transaction (reading 2)."""
        return self._inner.begin()

    def commit(self) -> Result[None]:
        return self._inner.commit()

    def rollback(self) -> None:
        self._inner.rollback()

    def _member(self, name: str) -> Any:
        return _InterleavedMember(getattr(self._inner, name), self._observe)

    @property
    def experiments(self) -> ExperimentRepository:
        return cast("ExperimentRepository", self._member("experiments"))

    @property
    def engine_runs(self) -> EngineRunRepository:
        return cast("EngineRunRepository", self._member("engine_runs"))

    @property
    def command_invocations(self) -> CommandInvocationRepository:
        return cast("CommandInvocationRepository", self._member("command_invocations"))

    @property
    def retry_decisions(self) -> RetryDecisionRepository:
        return cast("RetryDecisionRepository", self._member("retry_decisions"))

    @property
    def availability_observations(self) -> RuntimeAvailabilityObservationReader:
        return cast(
            "RuntimeAvailabilityObservationReader",
            self._member("availability_observations"),
        )

    @property
    def diagnostics(self) -> DiagnosticReader:
        return cast("DiagnosticReader", self._member("diagnostics"))


class InterleavingUnitOfWork:
    """Plan 5.2 and 7.1 (Task 6): a root whose transactions run a hook once, after
    the first repository read of each listed attempt.

    ``begin()`` counts into ``begins`` and returns a transaction over the inner
    root's; on attempt numbers in ``on_attempts`` (1-based, default the first) the
    transaction's first read method -- the read that established its WAL snapshot
    -- runs ``after_read`` once after returning its value. The callable commits the
    winner on its own connection, so the loser's first write is refused by the
    snapshot rule (``SQLITE_BUSY_SNAPSHOT``) rather than by timing.
    ``on_attempts=(1, 2)`` builds the two-interleaving half of C-13. Every other
    call delegates.
    """

    def __init__(
        self,
        inner: SqliteUnitOfWork,
        *,
        after_read: Callable[[], None],
        on_attempts: tuple[int, ...] = (1,),
    ) -> None:
        self._inner = inner
        self._state = _InterleavingState(after_read, on_attempts)

    @property
    def begins(self) -> int:
        """How many transactions ``begin()`` has opened so far."""
        return self._state.begins

    def begin(self) -> _InterleavingTransaction:
        self._state.begins += 1
        attempt = self._state.begins
        return _InterleavingTransaction(
            self._inner.begin(), self._state, armed=attempt in self._state.on_attempts
        )

    def commit(self) -> Result[None]:
        return self._inner.commit()

    def rollback(self) -> None:
        self._inner.rollback()

    @property
    def experiments(self) -> ExperimentRepository:
        return self._inner.experiments

    @property
    def engine_runs(self) -> EngineRunRepository:
        return self._inner.engine_runs

    @property
    def command_invocations(self) -> CommandInvocationRepository:
        return self._inner.command_invocations

    @property
    def retry_decisions(self) -> RetryDecisionRepository:
        return self._inner.retry_decisions

    @property
    def availability_observations(self) -> RuntimeAvailabilityObservationReader:
        return self._inner.availability_observations

    @property
    def diagnostics(self) -> DiagnosticReader:
        return self._inner.diagnostics


class _CountingState:
    """The live and maximum transaction counts shared by a root and its wrappers."""

    __slots__ = ("max_open", "open_now")

    def __init__(self) -> None:
        self.open_now = 0
        self.max_open = 0


class _CountingTransaction:
    """One transaction of ``CountingUnitOfWork``: released exactly once, whether
    by ``commit()`` (a ``Result`` or an escaping exception) or by ``rollback()``."""

    def __init__(self, inner: UnitOfWork, state: _CountingState) -> None:
        self._inner = inner
        self._state = state
        self._released = False

    def _release_once(self) -> None:
        if self._released:
            return
        self._released = True
        self._state.open_now -= 1
        assert self._state.open_now >= 0, "a transaction was released twice"

    def begin(self) -> UnitOfWork:
        """A programmer defect, exactly as on the inner transaction (reading 2)."""
        return self._inner.begin()

    def commit(self) -> Result[None]:
        try:
            return self._inner.commit()
        finally:
            self._release_once()

    def rollback(self) -> None:
        try:
            self._inner.rollback()
        finally:
            self._release_once()

    @property
    def experiments(self) -> ExperimentRepository:
        return self._inner.experiments

    @property
    def engine_runs(self) -> EngineRunRepository:
        return self._inner.engine_runs

    @property
    def command_invocations(self) -> CommandInvocationRepository:
        return self._inner.command_invocations

    @property
    def retry_decisions(self) -> RetryDecisionRepository:
        return self._inner.retry_decisions

    @property
    def availability_observations(self) -> RuntimeAvailabilityObservationReader:
        return self._inner.availability_observations

    @property
    def diagnostics(self) -> DiagnosticReader:
        return self._inner.diagnostics


class CountingUnitOfWork:
    """Plan 7.1 (Task 6): a root that counts its live transactions.

    ``begin()`` increments ``open_now`` once the inner ``begin()`` returned -- a
    transaction the inner root returns closed still holds its connection until it
    is rolled back, so it counts -- and records the maximum in ``max_open``;
    ``commit()`` and ``rollback()`` on the returned transaction decrement exactly
    once per actual release. A member access counts nothing. ``reset_max()`` sets
    the maximum back to the live count. The wrapper has no notion of a child:
    Task 7's ``SupervisedSqliteFlow`` samples ``open_now`` from its observer hooks.
    """

    def __init__(self, inner: UnitOfWork) -> None:
        self._inner = inner
        self._state = _CountingState()

    @property
    def open_now(self) -> int:
        """Transactions opened through this root and not yet released."""
        return self._state.open_now

    @property
    def max_open(self) -> int:
        """The greatest ``open_now`` since construction or the last ``reset_max()``."""
        return self._state.max_open

    def reset_max(self) -> None:
        self._state.max_open = self._state.open_now

    def begin(self) -> _CountingTransaction:
        transaction = self._inner.begin()
        self._state.open_now += 1
        self._state.max_open = max(self._state.max_open, self._state.open_now)
        return _CountingTransaction(transaction, self._state)

    def commit(self) -> Result[None]:
        return self._inner.commit()

    def rollback(self) -> None:
        self._inner.rollback()

    @property
    def experiments(self) -> ExperimentRepository:
        return self._inner.experiments

    @property
    def engine_runs(self) -> EngineRunRepository:
        return self._inner.engine_runs

    @property
    def command_invocations(self) -> CommandInvocationRepository:
        return self._inner.command_invocations

    @property
    def retry_decisions(self) -> RetryDecisionRepository:
        return self._inner.retry_decisions

    @property
    def availability_observations(self) -> RuntimeAvailabilityObservationReader:
        return self._inner.availability_observations

    @property
    def diagnostics(self) -> DiagnosticReader:
        return self._inner.diagnostics
