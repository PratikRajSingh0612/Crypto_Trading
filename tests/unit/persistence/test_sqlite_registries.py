"""The Task 3 registries over the migrated schema (plan 4.4, 4.6, 7.1; cases
C-25 (a), C-29 (c), C-31 and the registry half of C-32).

The recorder's autonomous transaction, idempotence and causal-edge derivation;
the readers' primitive rules; the availability writer; the configuration-snapshot
writer's freeze and self-checking egress; the strategy-version and dataset
repositories behind their new ports; the artifact-owner registry; the eight
counts of ``consistency_report()`` with a valid-state control and a
discriminating defect each; and the persistence of every lifecycle record
through its codec into the real schema and back through a fresh ``RowMapping``.
Every test uses the migrated ``sqlite_database`` fixture (or ``open_test_database``
for the reopen case), fresh ``read_only()`` sessions for committed visibility,
and the codecs and registries alone for ordinary writes. Raw statements enter
only where a test needs data no production path can write -- the test-only
triggers of plan 7.1, a raw ``INSERT`` whose typed columns disagree with its
``record``/``spec`` JSON, a raw ``UPDATE`` on a pre-``QUEUED`` projection column,
a raw ``DELETE`` of an ``engine_slots`` row, a raw ``DELETE`` that a trigger
refuses, and a ``PRAGMA foreign_keys=OFF`` child row -- each through
``raw_connection`` with bound parameters. No test imports ``fixtures.py``,
``SqliteHarness`` or a lifecycle repository (Task 4).
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Mapping
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Final

import pytest
from sqlalchemy import insert, select, text
from sqlalchemy.engine import Connection, RowMapping

from crypto_lab.adapters.events import (
    HeartbeatPayload,
    RunEvent,
    run_event_content_hash,
)
from crypto_lab.adapters.vocabulary import ProtocolEventType
from crypto_lab.artifacts.ownership import (
    AdapterArtifactOwner,
    ArtifactOwnerRef,
    DatasetArtifactOwner,
    ExperimentArtifactOwner,
    RunArtifactOwner,
    StrategyArtifactOwner,
    SystemArtifactOwner,
    artifact_owner_hash,
)
from crypto_lab.configuration.models import (
    ApplicationConfig,
    RetryConfig,
    SchedulerConfig,
)
from crypto_lab.configuration.snapshot import ConfigSnapshot, snapshot_configuration
from crypto_lab.datasets.hashing import dataset_metadata_hash
from crypto_lab.datasets.models import DatasetDescriptor, DatasetPartition
from crypto_lab.datasets.ports import DatasetRepository
from crypto_lab.domain.experiment import AdapterIdentity, ExperimentRecord
from crypto_lab.domain.hashing import attempt_token_hash
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.results import Failure, Success
from crypto_lab.experiments.ports import (
    DiagnosticReader,
    RuntimeAvailabilityObservationReader,
)
from crypto_lab.experiments.supervision_lifecycle import DiagnosticRecorder
from crypto_lab.persistence.codecs import (
    decode_artifact_owner,
    decode_command_invocation,
    decode_engine_run,
    decode_experiment,
    decode_retry_decision,
    decode_run_event,
    encode_artifact_owner,
    encode_command_invocation,
    encode_dataset,
    encode_dataset_partition,
    encode_diagnostic,
    encode_engine_run,
    encode_engine_slots,
    encode_experiment,
    encode_observation,
    encode_retry_decision,
    encode_run_event,
    encode_strategy_version,
)
from crypto_lab.persistence.database import ConsistencyReport, SqliteDatabase
from crypto_lab.persistence.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
    STORAGE_UNAVAILABLE,
)
from crypto_lab.persistence.registries import (
    SqliteArtifactOwnerRegistry,
    SqliteAvailabilityObservationReader,
    SqliteAvailabilityObservationWriter,
    SqliteConfigurationSnapshotWriter,
    SqliteDatasetRepository,
    SqliteDiagnosticReader,
    SqliteDiagnosticRecorder,
    SqliteStrategyVersionRepository,
)
from crypto_lab.persistence.schema import (
    EXPECTED_SCHEMA_OBJECTS,
    TABLES_IN_DEPENDENCY_ORDER,
    CommandInvocationRow,
    EngineRunRow,
    EngineSlotRow,
    ExperimentRow,
    RetryDecisionRow,
    RunEventRow,
)
from crypto_lab.strategy.models import StrategySpec
from crypto_lab.strategy.ports import StrategyVersionRepository
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
    AVAIL_B,
    DIAG_ID,
    ENGINE_BETA,
    EXECUTABLE_HASH,
    EXPERIMENT_ID,
    INSTANT,
    INVOCATION_ID,
    OTHER_DIAG_ID,
    OTHER_EXPERIMENT_ID,
    OTHER_RUN_ID,
    RUN_ID,
    SLOT_B,
    SLOT_C,
    UUID_B,
    UUID_C,
    UUID_D,
    UUID_E,
    FixedClock,
    sample_diagnostic,
    sample_experiment,
    sample_invocation,
    sample_observation,
    sample_retry_decision,
    sample_run,
    sequential_diagnostic_id,
)
from persistence_support.harness import (
    accept_any_revision,
    causal_edges,
    code,
    install_refusing_edge_trigger,
    install_refusing_partition_trigger,
    ok,
    open_test_database,
    raw_connection,
    sample_dataset_with_partitions,
    sample_strategy_version,
)

_E: Final = ExperimentState
_R: Final = EngineRunState
_C: Final = CommandInvocationState
EXP_C: Final = f"exp_{UUID_C}"
EXP_D: Final = f"exp_{UUID_D}"
#: The empty report every count-control asserts against.
_CLEAN: Final = ConsistencyReport(
    dangling_diagnostic_references=0,
    slot_identity_mismatches=0,
    spec_projection_mismatches=0,
    queued_without_snapshot=0,
    causal_edge_mismatches=0,
    unresolved_causal_references=0,
    registry_projection_mismatches=0,
    foreign_key_violations=0,
)
_SQLITE_CONSTRAINT_TRIGGER: Final = 1811
_SQLITE_CONSTRAINT_FOREIGNKEY: Final = 787
_SQLITE_CONSTRAINT_UNIQUE: Final = 2067


# --------------------------------------------------------------------------
# Module-local helpers
# --------------------------------------------------------------------------


def _clock() -> FixedClock:
    return FixedClock(INSTANT)


def _extra_identity(prefix: str, index: int) -> str:
    """A deterministic UUID4-shaped identity beyond the doubles' five constants."""
    return f"{prefix}_{index:08x}-0000-4000-8000-{index:012x}"


def _details(result: object) -> dict[str, object]:
    assert isinstance(result, Failure), result
    (diagnostic,) = result.diagnostics
    return dict(diagnostic.details)


def _message(result: object) -> str:
    assert isinstance(result, Failure), result
    (diagnostic,) = result.diagnostics
    return diagnostic.message


def _stored(row: RowMapping) -> dict[str, object]:
    """A fresh ``RowMapping`` as the codecs' ``Mapping[str, object]`` (same values)."""
    return {str(key): value for key, value in row.items()}


def _put_experiment(connection: Connection, record: ExperimentRecord) -> None:
    """Insert an experiment and its slot projection through the Task 3 codecs."""
    connection.execute(insert(ExperimentRow).values(**encode_experiment(record)))
    for slot in encode_engine_slots(record):
        connection.execute(insert(EngineSlotRow).values(**slot))


def _count(database: SqliteDatabase, table: str) -> int:
    assert table in TABLES_IN_DEPENDENCY_ORDER
    connection = raw_connection(database.path)
    try:
        # ``table`` is one of the fixed names asserted above, never a row value.
        (count,) = connection.execute(f"SELECT count(*) FROM {table}").fetchone()  # noqa: S608
        return int(count)
    finally:
        connection.close()


def _raw_insert(
    database: SqliteDatabase,
    table: str,
    values: Mapping[str, object],
    *,
    foreign_keys: bool = True,
) -> None:
    """A raw ``INSERT`` of codec-shaped values: test-only inconsistent data.

    The table is one of the fixed names and every column name is a codec key
    (asserted identifiers); the values are bound parameters.
    """
    assert table in TABLES_IN_DEPENDENCY_ORDER
    assert all(column.isidentifier() for column in values)
    columns = ", ".join(values)
    placeholders = ", ".join("?" for _ in values)
    connection = raw_connection(database.path)
    try:
        if not foreign_keys:
            connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute(
            f"INSERT INTO {table} ({columns}) VALUES ({placeholders})",  # noqa: S608
            tuple(values.values()),
        )
    finally:
        connection.close()


def _raw_execute(
    database: SqliteDatabase, statement: str, parameters: tuple[object, ...]
) -> None:
    connection = raw_connection(database.path)
    try:
        connection.execute(statement, parameters)
    finally:
        connection.close()


def _other_config() -> ApplicationConfig:
    """One bounded ``scheduler.retry`` field away from ``ApplicationConfig()``."""
    return ApplicationConfig(
        scheduler=SchedulerConfig(retry=RetryConfig(retry_delay_seconds=5))
    )


def _heartbeat_event() -> RunEvent:
    """One sanitized heartbeat for ``INVOCATION_ID`` with its hash recomputed."""
    draft = RunEvent.model_construct(
        schema_version="1.0.0",
        protocol_version="1.0.0",
        event_id=f"evt_{UUID_B}",
        invocation_id=INVOCATION_ID,
        run_id=RUN_ID,
        attempt_token_hash=attempt_token_hash(ATTEMPT_TOKEN),
        sequence=1,
        event_type=ProtocolEventType.HEARTBEAT,
        timestamp_utc=INSTANT,
        payload=HeartbeatPayload(activity_counter=1, phase="warmup"),
        received_at_utc=INSTANT + timedelta(seconds=1),
        wire_event_hash="b" * 64,
        content_hash="0" * 64,
    )
    payload = draft.model_dump(mode="python")
    payload["content_hash"] = run_event_content_hash(draft)
    return RunEvent.model_validate(payload)


def _version_over(
    spec: StrategySpec,
    *,
    created_at_utc: datetime,
    source_name: str = "sma_cross_long.valid.yaml",
) -> StrategyVersion:
    """A valid ``StrategyVersion`` over ``spec`` with the fixture's provenance bytes."""
    base = sample_strategy_version()
    content_hash = strategy_version_hash(spec)
    return StrategyVersion(
        schema_version="1.0.0",
        strategy_version_id=strategy_version_identifier(content_hash),
        strategy_id=spec.strategy_id,
        content_hash=content_hash,
        strategy_spec=spec,
        extension_hashes=tuple(sorted_extension_hashes(spec.engine_extensions)),
        hashing_profile_version=STRATEGY_VERSION_PROFILE_VERSION,
        created_at_utc=created_at_utc,
        source_provenance=StrategySourceProvenance(
            source_name=source_name,
            source_bytes_sha256=base.source_provenance.source_bytes_sha256,
            source_byte_length=base.source_provenance.source_byte_length,
            observed_at_utc=INSTANT,
        ),
    )


def _other_spec(spec: StrategySpec, label: str = "Two") -> StrategySpec:
    """The same strategy identity with one material field changed."""
    return StrategySpec.model_validate(
        {**spec.model_dump(mode="python"), "display_name": f"SMA Cross Long {label}"}
    )


def _fractional_dataset() -> tuple[DatasetDescriptor, tuple[DatasetPartition, ...]]:
    """A second identity-consistent dataset whose instants carry microseconds.

    ``created_at_utc`` (descriptor), ``start_utc`` (first partition) and
    ``end_utc`` (second partition and descriptor) all have a non-zero fraction,
    so a valid-state control over it exercises the fractional branch of the
    report's instant rendering; the content hash is recomputed over the moved
    material instants.
    """
    descriptor, partitions = sample_dataset_with_partitions()
    dataset_id = f"ds_{UUID_C}"
    end = descriptor.end_utc + timedelta(microseconds=999_999)
    moved = (
        DatasetPartition.model_validate(
            {
                **partitions[0].model_dump(mode="python"),
                "partition_id": f"part_{UUID_D}",
                "dataset_id": dataset_id,
                "start_utc": partitions[0].start_utc + timedelta(microseconds=1),
            }
        ),
        DatasetPartition.model_validate(
            {
                **partitions[1].model_dump(mode="python"),
                "partition_id": f"part_{UUID_E}",
                "dataset_id": dataset_id,
                "end_utc": end,
            }
        ),
    )
    payload: dict[str, object] = {
        **descriptor.model_dump(mode="python"),
        "dataset_id": dataset_id,
        "partition_ids": tuple(item.partition_id for item in moved),
        "end_utc": end,
        "created_at_utc": INSTANT + timedelta(microseconds=7),
    }
    unhashed = DatasetDescriptor.model_validate(payload)
    payload["content_hash"] = dataset_metadata_hash(unhashed, moved)
    return DatasetDescriptor.model_validate(payload), moved


def _rekeyed_dataset(
    descriptor: DatasetDescriptor,
    partitions: tuple[DatasetPartition, ...],
    dataset_id: str,
) -> tuple[DatasetDescriptor, tuple[DatasetPartition, ...]]:
    """The identical content under another ``dataset_id`` (same content hash)."""
    moved = tuple(
        DatasetPartition.model_validate(
            {**partition.model_dump(mode="python"), "dataset_id": dataset_id}
        )
        for partition in partitions
    )
    return (
        DatasetDescriptor.model_validate(
            {**descriptor.model_dump(mode="python"), "dataset_id": dataset_id}
        ),
        moved,
    )


# --------------------------------------------------------------------------
# The plan Task 3 Step 1 sketches
# --------------------------------------------------------------------------


def test_the_recorder_is_idempotent_and_visible_to_the_next_transaction(
    sqlite_database: SqliteDatabase,
) -> None:
    recorder = SqliteDiagnosticRecorder(sqlite_database, clock=FixedClock(INSTANT))
    diagnostic = sample_diagnostic()
    assert isinstance(recorder.record(diagnostic), Success)
    later = diagnostic.model_copy(update={"timestamp_utc": INSTANT + timedelta(1)})
    assert isinstance(recorder.record(later), Success)
    with sqlite_database.read_only() as connection:
        reader = SqliteDiagnosticReader(connection, clock=FixedClock(INSTANT))
        stored = reader.get(diagnostic.diagnostic_id)
        assert isinstance(stored, Success)
        assert stored.value == diagnostic


def test_dataset_registration_is_idempotent_on_identical_content(
    sqlite_database: SqliteDatabase,
) -> None:
    descriptor, partitions = sample_dataset_with_partitions()
    with sqlite_database.connection() as connection:
        repository = SqliteDatasetRepository(connection, clock=FixedClock(INSTANT))
        assert isinstance(repository.register(descriptor, partitions), Success)
        assert isinstance(repository.register(descriptor, partitions), Success)
        listed = repository.list_partitions(descriptor.dataset_id)
        assert isinstance(listed, Success)
        assert listed.value == partitions
        connection.commit()


def test_every_owner_variant_round_trips_and_a_two_variant_row_is_refused(
    sqlite_database: SqliteDatabase,
) -> None:
    version = sample_strategy_version()
    descriptor, partitions = sample_dataset_with_partitions()
    owners: tuple[ArtifactOwnerRef, ...] = (
        RunArtifactOwner(
            owner_kind="RUN",
            experiment_id=EXPERIMENT_ID,
            run_id=RUN_ID,
            invocation_id=INVOCATION_ID,
        ),
        RunArtifactOwner(owner_kind="RUN", experiment_id=EXPERIMENT_ID, run_id=RUN_ID),
        ExperimentArtifactOwner(owner_kind="EXPERIMENT", experiment_id=EXPERIMENT_ID),
        DatasetArtifactOwner(owner_kind="DATASET", dataset_id=descriptor.dataset_id),
        StrategyArtifactOwner(
            owner_kind="STRATEGY", strategy_version_id=version.strategy_version_id
        ),
        StrategyArtifactOwner(
            owner_kind="STRATEGY", strategy_version_hash=version.content_hash
        ),
        AdapterArtifactOwner(
            owner_kind="ADAPTER", adapter_name="adapter.alpha", adapter_version="1.0.0"
        ),
        AdapterArtifactOwner(
            owner_kind="ADAPTER",
            adapter_name="adapter.alpha",
            adapter_version="1.0.0",
            engine_name="engine.alpha",
            engine_version="2.3.4",
        ),
        SystemArtifactOwner(
            owner_kind="SYSTEM", core_component="persistence", correlation_id="corr-1"
        ),
    )
    with sqlite_database.connection() as connection:
        _put_experiment(connection, sample_experiment(_E.DRAFT))
        connection.execute(
            insert(EngineRunRow).values(**encode_engine_run(sample_run(_R.PENDING)))
        )
        connection.execute(
            insert(CommandInvocationRow).values(
                **encode_command_invocation(sample_invocation(_C.PENDING))
            )
        )
        versions = SqliteStrategyVersionRepository(connection, clock=_clock())
        assert isinstance(versions.register(version), Success)
        datasets = SqliteDatasetRepository(connection, clock=_clock())
        assert isinstance(datasets.register(descriptor, partitions), Success)
        registry = SqliteArtifactOwnerRegistry(connection, clock=_clock())
        for owner in owners:
            expected = artifact_owner_hash(owner)
            assert ok(registry.register(owner)) == expected
            assert ok(registry.register(owner)) == expected  # idempotent on owner_hash
            assert ok(registry.get(expected)) == owner
        connection.commit()
    with sqlite_database.read_only() as connection:
        registry = SqliteArtifactOwnerRegistry(connection, clock=_clock())
        for owner in owners:
            assert ok(registry.get(artifact_owner_hash(owner))) == owner
        unknown = registry.get("0" * 64)
        assert code(unknown) == INVARIANT_VIOLATION
        assert "does not exist" in _message(unknown)
    assert _count(sqlite_database, "artifact_owners") == len(owners)
    experiment_owner = encode_artifact_owner(owners[2])
    two_variant = {
        **experiment_owner,
        "owner_hash": "f" * 64,
        "dataset_id": descriptor.dataset_id,
    }
    with pytest.raises(sqlite3.IntegrityError, match="ck_artifact_owners"):
        _raw_insert(sqlite_database, "artifact_owners", two_variant)
    assert _count(sqlite_database, "artifact_owners") == len(owners)
    refused = decode_artifact_owner(two_variant, clock=_clock())
    assert code(refused) == INVARIANT_VIOLATION
    assert _details(refused)["table"] == "artifact_owners"
    assert _details(refused)["identity"] == "f" * 64


def test_causal_edges_converge_under_the_referrer_first_order(
    sqlite_database: SqliteDatabase,
) -> None:
    recorder = SqliteDiagnosticRecorder(sqlite_database, clock=FixedClock(INSTANT))
    additional = sample_diagnostic(diagnostic_id=f"diag_{UUID_B}")
    primary = sample_diagnostic(causal_diagnostic_ids=(additional.diagnostic_id,))
    assert isinstance(recorder.record(primary), Success)  # the Stage 7 order
    report = sqlite_database.consistency_report()
    assert (report.unresolved_causal_references, report.causal_edge_mismatches) == (
        1,
        0,
    )
    assert causal_edges(sqlite_database) == ()
    assert isinstance(recorder.record(additional), Success)
    edge = (primary.diagnostic_id, additional.diagnostic_id)
    assert causal_edges(sqlite_database) == (edge,)
    report = sqlite_database.consistency_report()
    assert (report.unresolved_causal_references, report.causal_edge_mismatches) == (
        0,
        0,
    )
    assert isinstance(recorder.record(additional), Success)  # replay writes no edge
    assert causal_edges(sqlite_database) == (edge,)


def test_a_refused_edge_rolls_the_diagnostic_back_with_it(
    sqlite_database: SqliteDatabase,
) -> None:
    recorder = SqliteDiagnosticRecorder(sqlite_database, clock=FixedClock(INSTANT))
    cause = sample_diagnostic(diagnostic_id=f"diag_{UUID_B}")
    assert isinstance(recorder.record(cause), Success)
    install_refusing_edge_trigger(sqlite_database)
    referrer = sample_diagnostic(causal_diagnostic_ids=(cause.diagnostic_id,))
    refused = recorder.record(referrer)
    assert isinstance(refused, Failure)
    assert refused.diagnostics[0].error_code == INVARIANT_VIOLATION
    with sqlite_database.read_only() as connection:
        reader = SqliteDiagnosticReader(connection, clock=FixedClock(INSTANT))
        assert isinstance(reader.get(referrer.diagnostic_id), Failure)  # rolled back
        assert isinstance(reader.get(cause.diagnostic_id), Success)
    assert causal_edges(sqlite_database) == ()


def test_a_frozen_snapshot_round_trips_and_a_tampered_byte_is_refused(
    sqlite_database: SqliteDatabase,
) -> None:
    snapshot = snapshot_configuration(ApplicationConfig())
    with sqlite_database.connection() as connection:
        connection.execute(
            insert(ExperimentRow).values(
                **encode_experiment(sample_experiment(_E.DRAFT))
            )
        )
        writer = SqliteConfigurationSnapshotWriter(
            connection, clock=FixedClock(INSTANT)
        )
        before = writer.get(EXPERIMENT_ID)
        assert isinstance(before, Success)
        assert not isinstance(before.value, ConfigSnapshot)  # MISSING until frozen
        assert isinstance(writer.freeze(EXPERIMENT_ID, snapshot), Success)
        assert isinstance(writer.freeze(EXPERIMENT_ID, snapshot), Success)  # idempotent
        stored = writer.get(EXPERIMENT_ID)
        assert isinstance(stored, Success)
        assert stored.value == snapshot
        # A DRAFT row is not guarded by T-EXP-SNAPSHOT-FROZEN, so the raw edit
        # lands; the validator of the rebuilt ConfigSnapshot refuses it on egress.
        connection.execute(
            text(
                "UPDATE experiments SET configuration_audit_hash = :h "
                "WHERE experiment_id = :e"
            ),
            {"h": "0" * 64, "e": EXPERIMENT_ID},
        )
        tampered = writer.get(EXPERIMENT_ID)
        assert isinstance(tampered, Failure)
        assert tampered.diagnostics[0].error_code == INVARIANT_VIOLATION
        connection.rollback()


# --------------------------------------------------------------------------
# The recorder and the readers
# --------------------------------------------------------------------------


def test_the_recorder_refuses_a_reused_identity_with_different_content(
    sqlite_database: SqliteDatabase,
) -> None:
    recorder = SqliteDiagnosticRecorder(sqlite_database, clock=_clock())
    assert isinstance(recorder, DiagnosticRecorder)
    diagnostic = sample_diagnostic()
    assert isinstance(recorder.record(diagnostic), Success)
    reused = sample_diagnostic(error_code="ENGINE.OTHER_FAILURE")
    refused = recorder.record(reused)
    assert code(refused) == INVARIANT_VIOLATION
    assert _details(refused)["table"] == "diagnostics"
    assert _details(refused)["identity"] == DIAG_ID
    with sqlite_database.read_only() as connection:
        reader = SqliteDiagnosticReader(connection, clock=_clock())
        assert isinstance(reader, DiagnosticReader)
        assert ok(reader.get(DIAG_ID)) == diagnostic
    assert _count(sqlite_database, "diagnostics") == 1


def test_the_recorder_maps_a_connection_checkout_failure_to_a_storage_failure(
    sqlite_database: SqliteDatabase,
) -> None:
    """An exhausted pool at checkout is a classified ``Failure``, never an
    exception; the recorder recovers once the pooled connection is released."""
    diagnostic = sample_diagnostic()
    opened = SqliteDatabase.open(
        sqlite_database.path,
        busy_timeout_ms=100,
        clock=_clock(),
        revision_policy=accept_any_revision,
        pool_size=1,
        max_overflow=0,
        pool_timeout_seconds=0.1,
    )
    single = ok(opened)
    try:
        recorder = SqliteDiagnosticRecorder(single, clock=_clock())
        with single.connection() as held:
            held.execute(text("SELECT 1"))
            refused = recorder.record(diagnostic)
            assert code(refused) == STORAGE_UNAVAILABLE
            assert _details(refused)["operation"] == "record"
            assert _details(refused)["table"] == "diagnostics"
        assert isinstance(recorder.record(diagnostic), Success)
    finally:
        single.close()
    with sqlite_database.read_only() as connection:
        reader = SqliteDiagnosticReader(connection, clock=_clock())
        assert ok(reader.get(DIAG_ID)) == diagnostic


def test_a_stored_row_the_record_refuses_is_the_invariant_through_every_reader(
    sqlite_database: SqliteDatabase,
) -> None:
    """A row SQL accepts but the canonical model refuses (an unsorted causal
    tuple passes the array CHECK) is INV from ``get``, ``get_many`` and the
    recorder's own read-back, naming the table, identity and column."""
    corrupt = sequential_diagnostic_id(7)
    corrupt_row = dict(encode_diagnostic(sample_diagnostic(diagnostic_id=corrupt)))
    corrupt_row["causal_diagnostic_ids"] = json.dumps([OTHER_DIAG_ID, DIAG_ID])
    _raw_insert(sqlite_database, "diagnostics", corrupt_row)
    recorder = SqliteDiagnosticRecorder(sqlite_database, clock=_clock())
    assert isinstance(recorder.record(sample_diagnostic()), Success)
    # Reading 23: the back-edge statement derives the relation from the stored
    # JSON column, so the corrupt row's citation of DIAG_ID becomes an edge when
    # DIAG_ID is recorded; the relation mirrors the column, validated or not.
    assert causal_edges(sqlite_database) == ((corrupt, DIAG_ID),)
    with sqlite_database.read_only() as connection:
        reader = SqliteDiagnosticReader(connection, clock=_clock())
        single = reader.get(corrupt)
        assert code(single) == INVARIANT_VIOLATION
        assert _details(single)["table"] == "diagnostics"
        assert _details(single)["identity"] == corrupt
        assert _details(single)["location"] == "causal_diagnostic_ids"
        many = reader.get_many((DIAG_ID, corrupt))
        assert code(many) == INVARIANT_VIOLATION
        assert _details(many)["identity"] == corrupt
    # A re-record under the corrupt identity keeps the stored row (ON CONFLICT DO
    # NOTHING), fails the read-back and rolls its transaction back: no edge.
    replay = recorder.record(sample_diagnostic(diagnostic_id=corrupt))
    assert code(replay) == INVARIANT_VIOLATION
    assert _details(replay)["location"] == "causal_diagnostic_ids"
    assert causal_edges(sqlite_database) == ((corrupt, DIAG_ID),)
    assert _count(sqlite_database, "diagnostics") == 2
    report = sqlite_database.consistency_report()
    assert (report.causal_edge_mismatches, report.unresolved_causal_references) == (
        0,
        1,
    )


_REFUSING_OBSERVATION_TRIGGER: Final = (
    "CREATE TRIGGER test_refuse_observation BEFORE INSERT ON "
    "runtime_availability_observations "
    "BEGIN SELECT RAISE(ABORT, 'test: observation refused'); END"
)


def test_observation_reads_refuse_a_corrupt_row_and_the_writer_maps_a_refused_insert(
    sqlite_database: SqliteDatabase,
) -> None:
    corrupt_row = dict(encode_observation(sample_observation(AVAIL_B)))
    corrupt_row["runtime_version"] = "not.a.semver!"  # the CHECK is length only
    _raw_insert(sqlite_database, "runtime_availability_observations", corrupt_row)
    observation = sample_observation()
    with sqlite_database.connection() as connection:
        writer = SqliteAvailabilityObservationWriter(connection, clock=_clock())
        assert isinstance(writer.add(observation), Success)
        connection.commit()
    with sqlite_database.read_only() as connection:
        reader = SqliteAvailabilityObservationReader(connection, clock=_clock())
        assert ok(reader.get(AVAIL_A)) == observation
        single = reader.get(AVAIL_B)
        assert code(single) == INVARIANT_VIOLATION
        assert _details(single)["location"] == "runtime_version"
        listed = reader.list_for_adapter("adapter.alpha", "1.0.0", EXECUTABLE_HASH)
        assert code(listed) == INVARIANT_VIOLATION
        assert _details(listed)["identity"] == AVAIL_B
    _raw_execute(sqlite_database, _REFUSING_OBSERVATION_TRIGGER, ())
    with sqlite_database.connection() as connection:
        writer = SqliteAvailabilityObservationWriter(connection, clock=_clock())
        refused = writer.add(sample_observation(f"avail_{UUID_C}"))
        assert code(refused) == INVARIANT_VIOLATION
        assert _details(refused)["operation"] == "add"
        assert _details(refused)["sqlite_errorcode"] == _SQLITE_CONSTRAINT_TRIGGER
        connection.rollback()
    assert _count(sqlite_database, "runtime_availability_observations") == 2


def test_a_reused_version_identifier_is_a_conflict_the_pre_reads_cannot_see(
    sqlite_database: SqliteDatabase,
) -> None:
    """Reading 3: a UNIQUE collision on the non-material ``strategy_version_id``
    surfaces at the insert as ``PERSISTENCE.CONCURRENCY_CONFLICT``; the
    transaction stays usable."""
    version = sample_strategy_version()
    later = _version_over(
        _other_spec(version.strategy_spec),
        created_at_utc=INSTANT + timedelta(seconds=1),
    )
    reused = StrategyVersion.model_validate(
        {
            **later.model_dump(mode="python"),
            "strategy_version_id": version.strategy_version_id,
        }
    )
    with sqlite_database.connection() as connection:
        repository = SqliteStrategyVersionRepository(connection, clock=_clock())
        assert isinstance(repository.register(version), Success)
        refused = repository.register(reused)
        assert code(refused) == CONCURRENCY_CONFLICT
        assert _details(refused)["operation"] == "register"
        assert _details(refused)["sqlite_errorcode"] == _SQLITE_CONSTRAINT_UNIQUE
        assert ok(repository.get_by_hash(version.content_hash)) == version
        connection.commit()
    assert _count(sqlite_database, "strategy_versions") == 1


def test_list_partitions_refuses_a_stored_partition_the_record_refuses(
    sqlite_database: SqliteDatabase,
) -> None:
    descriptor, partitions = sample_dataset_with_partitions()
    with sqlite_database.connection() as connection:
        repository = SqliteDatasetRepository(connection, clock=_clock())
        assert isinstance(repository.register(descriptor, partitions), Success)
        connection.commit()
    third = DatasetPartition.model_validate(
        {
            **partitions[0].model_dump(mode="python"),
            "partition_id": f"part_{UUID_C}",
            "ordinal": 2,
            "relative_path": "ohlcv/2.parquet",
        }
    )
    corrupt_row = dict(encode_dataset_partition(third))
    corrupt_row["record"] = "{}"  # json_valid, yet not a DatasetPartition
    _raw_insert(sqlite_database, "dataset_partitions", corrupt_row)
    with sqlite_database.read_only() as connection:
        repository = SqliteDatasetRepository(connection, clock=_clock())
        listed = repository.list_partitions(descriptor.dataset_id)
        assert code(listed) == INVARIANT_VIOLATION
        assert _details(listed)["table"] == "dataset_partitions"
        assert _details(listed)["identity"] == f"part_{UUID_C}"
        assert ok(repository.get_by_hash(descriptor.content_hash)) == descriptor


def test_a_recorded_diagnostic_is_durable_and_unreferenced(
    sqlite_database: SqliteDatabase,
) -> None:
    """C-25 (a): a recorded diagnostic nothing references is not dangling."""
    recorder = SqliteDiagnosticRecorder(sqlite_database, clock=_clock())
    diagnostic = sample_diagnostic()
    assert isinstance(recorder.record(diagnostic), Success)
    with sqlite_database.read_only() as connection:
        reader = SqliteDiagnosticReader(connection, clock=_clock())
        assert ok(reader.get(diagnostic.diagnostic_id)) == diagnostic
    assert sqlite_database.consistency_report().dangling_diagnostic_references == 0


def test_a_cited_cause_cannot_be_deleted(sqlite_database: SqliteDatabase) -> None:
    """C-31: T-APPEND-ONLY refuses the raw DELETE; the RESTRICT clauses are pinned."""
    recorder = SqliteDiagnosticRecorder(sqlite_database, clock=_clock())
    cause = sample_diagnostic(diagnostic_id=OTHER_DIAG_ID)
    referrer = sample_diagnostic(causal_diagnostic_ids=(OTHER_DIAG_ID,))
    assert isinstance(recorder.record(cause), Success)
    assert isinstance(recorder.record(referrer), Success)
    assert causal_edges(sqlite_database) == ((DIAG_ID, OTHER_DIAG_ID),)
    connection = raw_connection(sqlite_database.path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM diagnostics WHERE diagnostic_id = ?", (OTHER_DIAG_ID,)
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM diagnostic_causes WHERE diagnostic_id = ?", (DIAG_ID,)
            )
    finally:
        connection.close()
    assert _count(sqlite_database, "diagnostics") == 2
    assert causal_edges(sqlite_database) == ((DIAG_ID, OTHER_DIAG_ID),)
    table_sql = next(
        item.sql
        for item in EXPECTED_SCHEMA_OBJECTS
        if item.type == "table" and item.name == "diagnostic_causes"
    )
    restrict = re.findall(
        r"REFERENCES diagnostics \(diagnostic_id\) ON DELETE RESTRICT", table_sql
    )
    assert len(restrict) == 2


def test_get_many_is_sorted_unique_bounded_and_fails_on_a_missing_identity(
    sqlite_database: SqliteDatabase,
) -> None:
    recorder = SqliteDiagnosticRecorder(sqlite_database, clock=_clock())
    recorded = tuple(sequential_diagnostic_id(index) for index in range(256))
    for diagnostic_id in reversed(recorded):
        assert isinstance(
            recorder.record(sample_diagnostic(diagnostic_id=diagnostic_id)), Success
        )
    with sqlite_database.read_only() as connection:
        reader = SqliteDiagnosticReader(connection, clock=_clock())
        listed = ok(reader.get_many(tuple(reversed(recorded))))
        assert tuple(item.diagnostic_id for item in listed) == recorded
        assert len(listed) == 256
        assert ok(reader.get_many(())) == ()
        few = ok(reader.get_many((recorded[7], recorded[3])))
        assert tuple(item.diagnostic_id for item in few) == (recorded[3], recorded[7])
        duplicated = reader.get_many((recorded[3], recorded[3]))
        assert code(duplicated) == INVARIANT_VIOLATION
        assert "unique" in _message(duplicated)
        too_many = reader.get_many((*recorded, sequential_diagnostic_id(256)))
        assert code(too_many) == INVARIANT_VIOLATION
        assert "256" in _message(too_many)
        absent = sequential_diagnostic_id(999)
        missing = reader.get_many((recorded[0], absent))
        assert code(missing) == INVARIANT_VIOLATION
        assert "does not exist" in _message(missing)
        assert absent in _message(missing)
        assert _details(missing)["operation"] == "get_many"
        single = reader.get(absent)
        assert code(single) == INVARIANT_VIOLATION
        assert "does not exist" in _message(single)
    assert _count(sqlite_database, "diagnostics") == 256


def test_list_for_adapter_is_ordered_and_unbounded_over_three_hundred_rows(
    sqlite_database: SqliteDatabase,
) -> None:
    identities = [
        f"avail_{index:08x}-0000-4000-8000-000000000000" for index in range(300)
    ]
    with sqlite_database.connection() as connection:
        writer = SqliteAvailabilityObservationWriter(connection, clock=_clock())
        for offset, observation_id in enumerate(reversed(identities)):
            observation = sample_observation(
                observation_id, observed_at_utc=INSTANT + timedelta(seconds=offset)
            )
            assert isinstance(writer.add(observation), Success)
        assert isinstance(
            writer.add(sample_observation(AVAIL_B, adapter_name="adapter.beta")),
            Success,
        )
        assert isinstance(
            writer.add(sample_observation(f"avail_{UUID_C}", executable_hash="f" * 64)),
            Success,
        )
        connection.commit()
    with sqlite_database.read_only() as connection:
        reader = SqliteAvailabilityObservationReader(connection, clock=_clock())
        assert isinstance(reader, RuntimeAvailabilityObservationReader)
        listed = ok(reader.list_for_adapter("adapter.alpha", "1.0.0", EXECUTABLE_HASH))
        assert [item.availability_observation_id for item in listed] == identities
        assert len(listed) == 300
        assert (
            ok(reader.get(identities[17])).availability_observation_id
            == (identities[17])
        )
        assert (
            ok(reader.list_for_adapter("adapter.gamma", "1.0.0", EXECUTABLE_HASH)) == ()
        )
        missing = reader.get(f"avail_{UUID_D}")
        assert code(missing) == INVARIANT_VIOLATION
        assert "does not exist" in _message(missing)
    assert _count(sqlite_database, "runtime_availability_observations") == 302


def test_the_observation_writer_replays_an_identical_row_and_refuses_a_divergent_one(
    sqlite_database: SqliteDatabase,
) -> None:
    observation = sample_observation()
    with sqlite_database.connection() as connection:
        writer = SqliteAvailabilityObservationWriter(connection, clock=_clock())
        assert isinstance(writer.add(observation), Success)
        assert isinstance(writer.add(observation), Success)
        divergent = sample_observation(available=False)  # same identity, other content
        refused = writer.add(divergent)
        assert code(refused) == INVARIANT_VIOLATION
        assert _details(refused)["table"] == "runtime_availability_observations"
        assert _details(refused)["identity"] == AVAIL_A
        connection.commit()
    assert _count(sqlite_database, "runtime_availability_observations") == 1
    with sqlite_database.read_only() as connection:
        reader = SqliteAvailabilityObservationReader(connection, clock=_clock())
        assert ok(reader.get(AVAIL_A)) == observation


# --------------------------------------------------------------------------
# The configuration-snapshot writer
# --------------------------------------------------------------------------


def test_the_snapshot_writer_refuses_a_missing_experiment_and_a_frozen_queued_row(
    sqlite_database: SqliteDatabase,
) -> None:
    snapshot = snapshot_configuration(ApplicationConfig())
    other = snapshot_configuration(_other_config())
    assert other != snapshot
    with sqlite_database.connection() as connection:
        writer = SqliteConfigurationSnapshotWriter(connection, clock=_clock())
        missing = writer.freeze(EXPERIMENT_ID, snapshot)
        assert code(missing) == INVARIANT_VIOLATION
        assert "does not exist" in _message(missing)
        assert _details(missing)["operation"] == "freeze"
        absent = writer.get(EXPERIMENT_ID)
        assert code(absent) == INVARIANT_VIOLATION
        assert "does not exist" in _message(absent)
        assert _details(absent)["operation"] == "get"
        # Scaffolding: a row inserted directly at QUEUED carries no snapshot, so
        # the first freeze fills the four columns; from then on they are frozen.
        _put_experiment(connection, sample_experiment(_E.QUEUED))
        assert isinstance(writer.freeze(EXPERIMENT_ID, snapshot), Success)
        frozen = writer.freeze(EXPERIMENT_ID, other)
        assert code(frozen) == INVARIANT_VIOLATION
        assert "frozen" in _message(frozen)
        assert isinstance(writer.freeze(EXPERIMENT_ID, snapshot), Success)
        assert ok(writer.get(EXPERIMENT_ID)) == snapshot
        # A VALIDATED row admits a replacement.
        validated = sample_experiment(_E.VALIDATED, experiment_id=OTHER_EXPERIMENT_ID)
        _put_experiment(connection, validated)
        assert isinstance(writer.freeze(OTHER_EXPERIMENT_ID, snapshot), Success)
        assert isinstance(writer.freeze(OTHER_EXPERIMENT_ID, other), Success)
        assert ok(writer.get(OTHER_EXPERIMENT_ID)) == other
        # A terminal scaffolding row without a snapshot is refused at the UPDATE
        # by T-EXP-TERMINAL and surfaces as the invariant.
        _put_experiment(
            connection, sample_experiment(_E.COMPLETED, experiment_id=EXP_C)
        )
        terminal = writer.freeze(EXP_C, snapshot)
        assert code(terminal) == INVARIANT_VIOLATION
        assert _details(terminal)["sqlite_errorcode"] == _SQLITE_CONSTRAINT_TRIGGER
        assert not isinstance(ok(writer.get(EXP_C)), ConfigSnapshot)
        connection.commit()
    with sqlite_database.read_only() as connection:
        writer = SqliteConfigurationSnapshotWriter(connection, clock=_clock())
        assert ok(writer.get(EXPERIMENT_ID)) == snapshot
        assert ok(writer.get(OTHER_EXPERIMENT_ID)) == other
        assert not isinstance(ok(writer.get(EXP_C)), ConfigSnapshot)


# --------------------------------------------------------------------------
# The strategy-version and dataset repositories, the owner registry
# --------------------------------------------------------------------------


def test_strategy_versions_register_once_and_refuse_hash_or_instant_collisions(
    sqlite_database: SqliteDatabase,
) -> None:
    version = sample_strategy_version()
    assert sample_strategy_version() == version
    other_spec = _other_spec(version.strategy_spec)
    with sqlite_database.connection() as connection:
        repository = SqliteStrategyVersionRepository(connection, clock=_clock())
        assert isinstance(repository, StrategyVersionRepository)
        assert isinstance(repository.register(version), Success)
        assert isinstance(repository.register(version), Success)
        assert ok(repository.get_by_hash(version.content_hash)) == version
        renamed = _version_over(
            version.strategy_spec,
            created_at_utc=INSTANT,
            source_name="other.valid.yaml",
        )
        assert renamed.content_hash == version.content_hash
        same_hash = repository.register(renamed)
        assert code(same_hash) == INVARIANT_VIOLATION
        assert _details(same_hash)["identity"] == version.content_hash
        colliding = _version_over(other_spec, created_at_utc=INSTANT)
        assert colliding.content_hash != version.content_hash
        same_instant = repository.register(colliding)
        assert code(same_instant) == INVARIANT_VIOLATION
        assert "created_at_utc" in _message(same_instant)
        later = _version_over(other_spec, created_at_utc=INSTANT + timedelta(seconds=1))
        assert isinstance(repository.register(later), Success)
        missing = repository.get_by_hash("0" * 64)
        assert code(missing) == INVARIANT_VIOLATION
        assert "does not exist" in _message(missing)
        connection.commit()
    assert _count(sqlite_database, "strategy_versions") == 2
    with sqlite_database.read_only() as connection:
        repository = SqliteStrategyVersionRepository(connection, clock=_clock())
        assert ok(repository.get_by_hash(version.content_hash)) == version
        assert ok(repository.get_by_hash(later.content_hash)) == later


def test_dataset_registration_refuses_an_inconsistent_pair_and_a_rekeyed_descriptor(
    sqlite_database: SqliteDatabase,
) -> None:
    descriptor, partitions = sample_dataset_with_partitions()
    with sqlite_database.connection() as connection:
        repository = SqliteDatasetRepository(connection, clock=_clock())
        assert isinstance(repository, DatasetRepository)
        inconsistent = repository.register(descriptor, tuple(reversed(partitions)))
        assert code(inconsistent) == INVARIANT_VIOLATION
        assert code(repository.get_by_hash(descriptor.content_hash)) == (
            INVARIANT_VIOLATION
        )
        assert isinstance(repository.register(descriptor, partitions), Success)
        assert ok(repository.get_by_hash(descriptor.content_hash)) == descriptor
        rekeyed, moved = _rekeyed_dataset(descriptor, partitions, f"ds_{UUID_B}")
        assert rekeyed.content_hash == descriptor.content_hash
        refused = repository.register(rekeyed, moved)
        assert code(refused) == INVARIANT_VIOLATION
        assert _details(refused)["identity"] == descriptor.content_hash
        missing = repository.list_partitions(f"ds_{UUID_B}")
        assert code(missing) == INVARIANT_VIOLATION
        assert "does not exist" in _message(missing)
        assert _details(missing)["operation"] == "list_partitions"
        connection.commit()
    assert _count(sqlite_database, "datasets") == 1
    assert _count(sqlite_database, "dataset_partitions") == 2
    with sqlite_database.read_only() as connection:
        repository = SqliteDatasetRepository(connection, clock=_clock())
        assert ok(repository.get_by_hash(descriptor.content_hash)) == descriptor
        assert ok(repository.list_partitions(descriptor.dataset_id)) == partitions


def test_dataset_registration_rolls_back_to_its_savepoint(
    sqlite_database: SqliteDatabase,
) -> None:
    """C-29 (c): the refused second partition undoes the staged descriptor row."""
    install_refusing_partition_trigger(sqlite_database, 1)
    descriptor, partitions = sample_dataset_with_partitions()
    with sqlite_database.connection() as connection:
        repository = SqliteDatasetRepository(connection, clock=_clock())
        refused = repository.register(descriptor, partitions)
        assert code(refused) == INVARIANT_VIOLATION
        assert _details(refused)["table"] == "dataset_partitions"
        assert _details(refused)["sqlite_errorcode"] == _SQLITE_CONSTRAINT_TRIGGER
        staged = connection.execute(text("SELECT count(*) FROM datasets")).scalar_one()
        assert staged == 0
        assert code(repository.get_by_hash(descriptor.content_hash)) == (
            INVARIANT_VIOLATION
        )
        # The transaction stays usable and a following commit publishes nothing
        # of the failed method.
        versions = SqliteStrategyVersionRepository(connection, clock=_clock())
        assert isinstance(versions.register(sample_strategy_version()), Success)
        connection.commit()
    assert _count(sqlite_database, "datasets") == 0
    assert _count(sqlite_database, "dataset_partitions") == 0
    assert _count(sqlite_database, "strategy_versions") == 1


def test_the_owner_registry_refuses_an_unpersisted_parent(
    sqlite_database: SqliteDatabase,
) -> None:
    """C-26, owner half: a RUN owner naming a run no row holds is the invariant."""
    with sqlite_database.connection() as connection:
        registry = SqliteArtifactOwnerRegistry(connection, clock=_clock())
        orphan = RunArtifactOwner(
            owner_kind="RUN", experiment_id=EXPERIMENT_ID, run_id=RUN_ID
        )
        refused = registry.register(orphan)
        assert code(refused) == INVARIANT_VIOLATION
        assert _details(refused)["table"] == "artifact_owners"
        assert _details(refused)["sqlite_errorcode"] == _SQLITE_CONSTRAINT_FOREIGNKEY
        assert code(registry.get(artifact_owner_hash(orphan))) == INVARIANT_VIOLATION
        system = SystemArtifactOwner(
            owner_kind="SYSTEM", core_component="persistence", correlation_id="c-2"
        )
        assert ok(registry.register(system)) == artifact_owner_hash(system)
        connection.commit()
    assert _count(sqlite_database, "artifact_owners") == 1


# --------------------------------------------------------------------------
# The consistency report: eight counts, a control and a defect each
# --------------------------------------------------------------------------


def test_the_consistency_report_is_zero_on_a_migrated_empty_database(
    sqlite_database: SqliteDatabase,
) -> None:
    report = sqlite_database.consistency_report()
    assert report == _CLEAN
    assert tuple(field.name for field in fields(ConsistencyReport)) == (
        "dangling_diagnostic_references",
        "slot_identity_mismatches",
        "spec_projection_mismatches",
        "queued_without_snapshot",
        "causal_edge_mismatches",
        "unresolved_causal_references",
        "registry_projection_mismatches",
        "foreign_key_violations",
    )
    with pytest.raises(FrozenInstanceError):
        report.foreign_key_violations = 1  # type: ignore[misc]


def test_an_unrecorded_primary_terminal_diagnostic_is_a_dangling_reference(
    sqlite_database: SqliteDatabase,
) -> None:
    """The plan's case: a lawful unobserved FAILED run whose only absent parent
    is the diagnostic, so the count isolates exactly that reference."""
    with sqlite_database.connection() as connection:
        _put_experiment(connection, sample_experiment(_E.DRAFT))
        run = sample_run(_R.FAILED, observed=False)
        connection.execute(insert(EngineRunRow).values(**encode_engine_run(run)))
        connection.commit()
    report = sqlite_database.consistency_report()
    assert report.dangling_diagnostic_references == 1
    assert report == replace(_CLEAN, dangling_diagnostic_references=1)
    recorder = SqliteDiagnosticRecorder(sqlite_database, clock=_clock())
    assert isinstance(recorder.record(sample_diagnostic()), Success)
    assert sqlite_database.consistency_report() == _CLEAN


def test_every_diagnostic_reference_site_counts_toward_dangling_references(
    sqlite_database: SqliteDatabase,
) -> None:
    with sqlite_database.connection() as connection:
        _put_experiment(connection, sample_experiment(_E.DRAFT))
        run = sample_run(_R.FAILED, observed=False)
        connection.execute(insert(EngineRunRow).values(**encode_engine_run(run)))
        decision = sample_retry_decision()
        connection.execute(
            insert(RetryDecisionRow).values(**encode_retry_decision(decision))
        )
        invocation = sample_invocation(
            _C.FAILED_TO_START, primary_diagnostic_id=OTHER_DIAG_ID
        )
        connection.execute(
            insert(CommandInvocationRow).values(**encode_command_invocation(invocation))
        )
        connection.commit()
    # run primary + decision primary + invocation primary + invocation member
    assert sqlite_database.consistency_report().dangling_diagnostic_references == 4
    recorder = SqliteDiagnosticRecorder(sqlite_database, clock=_clock())
    assert isinstance(recorder.record(sample_diagnostic()), Success)
    assert sqlite_database.consistency_report().dangling_diagnostic_references == 2
    assert isinstance(
        recorder.record(sample_diagnostic(diagnostic_id=OTHER_DIAG_ID)), Success
    )
    assert sqlite_database.consistency_report().dangling_diagnostic_references == 0


def test_slot_identity_mismatches_count_runs_whose_identity_differs_from_the_slot(
    sqlite_database: SqliteDatabase,
) -> None:
    with sqlite_database.connection() as connection:
        _put_experiment(connection, sample_experiment(_E.DRAFT))
        connection.execute(
            insert(EngineRunRow).values(**encode_engine_run(sample_run(_R.PENDING)))
        )
        connection.commit()
    assert sqlite_database.consistency_report() == _CLEAN
    divergent = sample_run(
        _R.PENDING,
        run_id=OTHER_RUN_ID,
        logical_slot_id=SLOT_B,
        adapter=AdapterIdentity(adapter_name="adapter.other", adapter_version="9.9.9"),
        engine=ENGINE_BETA,
    )
    _raw_insert(sqlite_database, "engine_runs", encode_engine_run(divergent))
    report = sqlite_database.consistency_report()
    assert report.slot_identity_mismatches == 1
    assert report == replace(_CLEAN, slot_identity_mismatches=1)


def test_spec_projection_mismatches_count_each_disagreeing_experiment_once(
    sqlite_database: SqliteDatabase,
) -> None:
    with sqlite_database.connection() as connection:
        _put_experiment(connection, sample_experiment(_E.DRAFT))
        _put_experiment(
            connection, sample_experiment(_E.DRAFT, experiment_id=OTHER_EXPERIMENT_ID)
        )
        _put_experiment(connection, sample_experiment(_E.DRAFT, experiment_id=EXP_C))
        connection.commit()
    assert sqlite_database.consistency_report() == _CLEAN
    # (a) a hash projection column that disagrees with the spec (a DRAFT row is
    # not guarded by T-EXP-FROZEN, so the raw edit lands)
    _raw_execute(
        sqlite_database,
        "UPDATE experiments SET strategy_version_hash = ? WHERE experiment_id = ?",
        ("f" * 64, EXPERIMENT_ID),
    )
    assert sqlite_database.consistency_report().spec_projection_mismatches == 1
    # (b) a spec slot with no engine_slots row (the projection rewrite's delete)
    _raw_execute(
        sqlite_database,
        "DELETE FROM engine_slots WHERE experiment_id = ? AND logical_slot_id = ?",
        (OTHER_EXPERIMENT_ID, SLOT_B),
    )
    assert sqlite_database.consistency_report().spec_projection_mismatches == 2
    # (c) an engine_slots row absent from the spec
    _raw_insert(
        sqlite_database,
        "engine_slots",
        {
            "experiment_id": EXP_C,
            "logical_slot_id": SLOT_C,
            "slot_ordinal": 2,
            "adapter_name": "adapter.gamma",
            "adapter_version": "3.0.0",
            "engine_name": "engine.gamma",
            "engine_version": "1.0.0",
        },
    )
    report = sqlite_database.consistency_report()
    assert report.spec_projection_mismatches == 3
    assert report == replace(_CLEAN, spec_projection_mismatches=3)


def test_queued_without_snapshot_counts_scaffolding_at_or_after_queued(
    sqlite_database: SqliteDatabase,
) -> None:
    with sqlite_database.connection() as connection:
        _put_experiment(connection, sample_experiment(_E.DRAFT))
        _put_experiment(
            connection,
            sample_experiment(_E.VALIDATED, experiment_id=OTHER_EXPERIMENT_ID),
        )
        _put_experiment(
            connection, sample_experiment(_E.CANCELLED, experiment_id=EXP_C)
        )
        connection.commit()
    assert sqlite_database.consistency_report() == _CLEAN
    with sqlite_database.connection() as connection:
        _put_experiment(connection, sample_experiment(_E.QUEUED, experiment_id=EXP_D))
        connection.commit()
    report = sqlite_database.consistency_report()
    assert report.queued_without_snapshot == 1
    assert report == replace(_CLEAN, queued_without_snapshot=1)
    with sqlite_database.connection() as connection:
        writer = SqliteConfigurationSnapshotWriter(connection, clock=_clock())
        frozen = writer.freeze(EXP_D, snapshot_configuration(ApplicationConfig()))
        assert isinstance(frozen, Success)
        connection.commit()
    assert sqlite_database.consistency_report() == _CLEAN


def test_causal_edge_mismatches_count_both_directions_of_disagreement(
    sqlite_database: SqliteDatabase,
) -> None:
    recorder = SqliteDiagnosticRecorder(sqlite_database, clock=_clock())
    first = sample_diagnostic()
    second = sample_diagnostic(diagnostic_id=OTHER_DIAG_ID)
    assert isinstance(recorder.record(first), Success)
    assert isinstance(recorder.record(second), Success)
    assert sqlite_database.consistency_report() == _CLEAN
    # a relation row absent from the referrer's JSON
    _raw_insert(
        sqlite_database,
        "diagnostic_causes",
        {"diagnostic_id": DIAG_ID, "causal_diagnostic_id": OTHER_DIAG_ID},
    )
    assert sqlite_database.consistency_report().causal_edge_mismatches == 1
    # a JSON cause whose row exists but has no relation row
    third = sample_diagnostic(
        diagnostic_id=sequential_diagnostic_id(3), causal_diagnostic_ids=(DIAG_ID,)
    )
    _raw_insert(sqlite_database, "diagnostics", encode_diagnostic(third))
    report = sqlite_database.consistency_report()
    assert report.causal_edge_mismatches == 2
    assert report.unresolved_causal_references == 0
    assert report == replace(_CLEAN, causal_edge_mismatches=2)


def test_registry_projection_mismatches_count_every_disagreeing_typed_column(
    sqlite_database: SqliteDatabase,
) -> None:
    version = sample_strategy_version()
    descriptor, partitions = sample_dataset_with_partitions()
    # The valid-state control carries whole-second and fractional instants on
    # every registry table, so the report's SQL instant rendering is proven on
    # both branches before any defect is injected.
    fractional_version = _version_over(
        _other_spec(version.strategy_spec, "Fractional"),
        created_at_utc=INSTANT + timedelta(seconds=1, microseconds=123_456),
    )
    fractional_descriptor, fractional_partitions = _fractional_dataset()
    with sqlite_database.connection() as connection:
        versions = SqliteStrategyVersionRepository(connection, clock=_clock())
        assert isinstance(versions.register(version), Success)
        assert isinstance(versions.register(fractional_version), Success)
        datasets = SqliteDatasetRepository(connection, clock=_clock())
        assert isinstance(datasets.register(descriptor, partitions), Success)
        assert isinstance(
            datasets.register(fractional_descriptor, fractional_partitions), Success
        )
        connection.commit()
    assert sqlite_database.consistency_report() == _CLEAN
    # (a) strategy_versions: a text projection that disagrees with the record
    later = _version_over(
        _other_spec(version.strategy_spec, "Three"),
        created_at_utc=INSTANT + timedelta(seconds=3),
    )
    _raw_insert(
        sqlite_database,
        "strategy_versions",
        {**encode_strategy_version(later), "strategy_id": f"strat_{UUID_B}"},
    )
    assert sqlite_database.consistency_report().registry_projection_mismatches == 1
    # (b) strategy_versions: the instant projection alone one microsecond off the
    # record (every text projection agrees, so only the instant term can count it)
    spaced = _version_over(
        _other_spec(version.strategy_spec, "Four"),
        created_at_utc=INSTANT + timedelta(seconds=4, microseconds=5),
    )
    spaced_values = dict(encode_strategy_version(spaced))
    spaced_values["created_at_utc"] = int(str(spaced_values["created_at_utc"])) + 1
    _raw_insert(sqlite_database, "strategy_versions", spaced_values)
    assert sqlite_database.consistency_report().registry_projection_mismatches == 2
    # (c) datasets: a venue projection that disagrees with the record
    other_descriptor = DatasetDescriptor.model_validate(
        {
            **descriptor.model_dump(mode="python"),
            "dataset_id": f"ds_{UUID_B}",
            "content_hash": "8" * 64,
        }
    )
    _raw_insert(
        sqlite_database,
        "datasets",
        {**encode_dataset(other_descriptor), "venue": "OTHER"},
    )
    assert sqlite_database.consistency_report().registry_projection_mismatches == 3
    # (d) dataset_partitions: a row_count projection that disagrees with the record
    third_partition = DatasetPartition.model_validate(
        {
            **partitions[0].model_dump(mode="python"),
            "partition_id": f"part_{UUID_C}",
            "ordinal": 2,
            "relative_path": "ohlcv/2.parquet",
        }
    )
    _raw_insert(
        sqlite_database,
        "dataset_partitions",
        {**encode_dataset_partition(third_partition), "row_count": 999},
    )
    assert sqlite_database.consistency_report().registry_projection_mismatches == 4
    # (e) datasets: the start_utc projection alone one microsecond off the record
    shifted_descriptor = DatasetDescriptor.model_validate(
        {
            **descriptor.model_dump(mode="python"),
            "dataset_id": f"ds_{UUID_D}",
            "content_hash": "7" * 64,
        }
    )
    shifted_values = dict(encode_dataset(shifted_descriptor))
    shifted_values["start_utc"] = int(str(shifted_values["start_utc"])) + 1
    _raw_insert(sqlite_database, "datasets", shifted_values)
    assert sqlite_database.consistency_report().registry_projection_mismatches == 5
    # (f) dataset_partitions: the end_utc projection alone one microsecond off
    fourth_partition = DatasetPartition.model_validate(
        {
            **partitions[0].model_dump(mode="python"),
            "partition_id": _extra_identity("part", 4),
            "ordinal": 3,
            "relative_path": "ohlcv/3.parquet",
        }
    )
    fourth_values = dict(encode_dataset_partition(fourth_partition))
    fourth_values["end_utc"] = int(str(fourth_values["end_utc"])) + 1
    _raw_insert(sqlite_database, "dataset_partitions", fourth_values)
    report = sqlite_database.consistency_report()
    assert report.registry_projection_mismatches == 6
    assert report == replace(_CLEAN, registry_projection_mismatches=6)


def test_foreign_key_violations_count_the_foreign_key_check_rows(
    sqlite_database: SqliteDatabase,
) -> None:
    descriptor, partitions = sample_dataset_with_partitions()
    with sqlite_database.connection() as connection:
        datasets = SqliteDatasetRepository(connection, clock=_clock())
        assert isinstance(datasets.register(descriptor, partitions), Success)
        connection.commit()
    assert sqlite_database.consistency_report() == _CLEAN
    orphan = DatasetPartition.model_validate(
        {
            **partitions[0].model_dump(mode="python"),
            "partition_id": f"part_{UUID_C}",
            "dataset_id": f"ds_{UUID_D}",
        }
    )
    # Only a connection with the enforcement switched off can write the orphan;
    # every engine connection keeps ``foreign_keys=ON`` (plan 6.1).
    _raw_insert(
        sqlite_database,
        "dataset_partitions",
        encode_dataset_partition(orphan),
        foreign_keys=False,
    )
    report = sqlite_database.consistency_report()
    assert report.foreign_key_violations == 1
    assert report == replace(_CLEAN, foreign_key_violations=1)


# --------------------------------------------------------------------------
# Persistence of every lifecycle record and the close-and-reopen case
# --------------------------------------------------------------------------


def test_every_lifecycle_record_persists_and_decodes_from_the_migrated_schema(
    sqlite_database: SqliteDatabase,
) -> None:
    """The five Task 4 records through their Task 3 codecs into the real tables
    and back through a fresh ``RowMapping``: SQL type acceptance is not enough,
    the stored row must rebuild the canonical record."""
    experiment = sample_experiment(_E.QUEUED)
    observation = sample_observation()
    run = sample_run(_R.READY)
    invocation = sample_invocation(_C.RUNNING)
    event = _heartbeat_event()
    decision = sample_retry_decision()
    # The decision cites DIAG_ID; recording it first keeps the report's
    # dangling-reference count at zero so only the scaffolding count remains.
    recorder = SqliteDiagnosticRecorder(sqlite_database, clock=_clock())
    assert isinstance(recorder.record(sample_diagnostic()), Success)
    with sqlite_database.connection() as connection:
        _put_experiment(connection, experiment)
        writer = SqliteAvailabilityObservationWriter(connection, clock=_clock())
        assert isinstance(writer.add(observation), Success)
        connection.execute(insert(EngineRunRow).values(**encode_engine_run(run)))
        connection.execute(
            insert(CommandInvocationRow).values(**encode_command_invocation(invocation))
        )
        connection.execute(insert(RunEventRow).values(**encode_run_event(event)))
        connection.execute(
            insert(RetryDecisionRow).values(**encode_retry_decision(decision))
        )
        connection.commit()
    with sqlite_database.read_only() as connection:
        stored_experiment = connection.execute(select(ExperimentRow)).mappings().one()
        assert ok(decode_experiment(_stored(stored_experiment), clock=_clock())) == (
            experiment
        )
        stored_run = connection.execute(select(EngineRunRow)).mappings().one()
        assert ok(decode_engine_run(_stored(stored_run), clock=_clock())) == run
        stored_invocation = (
            connection.execute(select(CommandInvocationRow)).mappings().one()
        )
        decoded_invocation = decode_command_invocation(
            _stored(stored_invocation), clock=_clock()
        )
        assert ok(decoded_invocation) == (invocation)
        stored_event = connection.execute(select(RunEventRow)).mappings().one()
        assert ok(decode_run_event(_stored(stored_event), clock=_clock())) == event
        stored_decision = connection.execute(select(RetryDecisionRow)).mappings().one()
        decoded_decision = decode_retry_decision(
            _stored(stored_decision), clock=_clock()
        )
        assert ok(decoded_decision) == decision
    report = sqlite_database.consistency_report()
    # The scaffolding QUEUED row carries no snapshot; every other reference of
    # the five rows resolves, so nothing else is counted.
    assert report == replace(_CLEAN, queued_without_snapshot=1)


def test_registered_rows_survive_a_close_and_reopen(
    tmp_path: Path, fixed_clock: FixedClock
) -> None:
    """Representative durability of the Task 3 registries across a reopen; the
    whole-application recovery workflow is Task 5's."""
    version = sample_strategy_version()
    descriptor, partitions = sample_dataset_with_partitions()
    diagnostic = sample_diagnostic()
    observation = sample_observation()
    owner = SystemArtifactOwner(
        owner_kind="SYSTEM", core_component="persistence", correlation_id="reopen"
    )
    database = open_test_database(tmp_path, clock=fixed_clock)
    try:
        recorder = SqliteDiagnosticRecorder(database, clock=_clock())
        assert isinstance(recorder.record(diagnostic), Success)
        with database.connection() as connection:
            versions = SqliteStrategyVersionRepository(connection, clock=_clock())
            assert isinstance(versions.register(version), Success)
            datasets = SqliteDatasetRepository(connection, clock=_clock())
            assert isinstance(datasets.register(descriptor, partitions), Success)
            writer = SqliteAvailabilityObservationWriter(connection, clock=_clock())
            assert isinstance(writer.add(observation), Success)
            registry = SqliteArtifactOwnerRegistry(connection, clock=_clock())
            assert ok(registry.register(owner)) == artifact_owner_hash(owner)
            connection.commit()
    finally:
        database.close()
    reopened = open_test_database(tmp_path, clock=fixed_clock)
    try:
        with reopened.read_only() as connection:
            reader = SqliteDiagnosticReader(connection, clock=_clock())
            assert ok(reader.get(DIAG_ID)) == diagnostic
            versions = SqliteStrategyVersionRepository(connection, clock=_clock())
            assert ok(versions.get_by_hash(version.content_hash)) == version
            datasets = SqliteDatasetRepository(connection, clock=_clock())
            assert ok(datasets.get_by_hash(descriptor.content_hash)) == descriptor
            assert ok(datasets.list_partitions(descriptor.dataset_id)) == partitions
            observations = SqliteAvailabilityObservationReader(
                connection, clock=_clock()
            )
            assert ok(observations.get(AVAIL_A)) == observation
            registry = SqliteArtifactOwnerRegistry(connection, clock=_clock())
            assert ok(registry.get(artifact_owner_hash(owner))) == owner
        assert reopened.consistency_report() == _CLEAN
    finally:
        reopened.close()
