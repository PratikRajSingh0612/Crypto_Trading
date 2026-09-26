"""Read database failures are stable results that close the owner (plan 4.2, 6.5;
the pre-Task-7 read-failure correction).

Ten read paths through nine methods of the Task 3 registries -- the diagnostic
reader's ``get`` and ``get_many``, the availability-observation reader's ``get`` and
``list_for_adapter``, the snapshot writer's ``freeze`` (its pre-read) and ``get``,
which share one row read, ``get_by_hash`` of both registry ports,
``list_partitions`` and the artifact-owner ``get`` -- issued their statements with
no ``except DBAPIError``, so a driver error during a read left the
method as an exception instead of the classified ``Failure`` every other repository
method returns. Two transaction bindings compounded it: the observation reader's
guard never handed its results to ``TransactionScope.absorb``, and the diagnostic
reader was bound as a bare object over the connection, so neither could close the
owner on the I/O class or answer a closed transaction with its stored ``Failure``.

These tests drive the ACTUAL readers through the two low-level fault boundaries the
harness provides -- ``cursor_fault`` at the dialect's ``do_execute`` (the statement
is refused) and ``fetch_fault`` at the result's fetch (the statement ran; its rows
cannot be materialized: ``.first()``, ``.all()`` and ``scalar_one_or_none()``) --
and assert, per plan 4.2 and the recorded release ruling:

- the classified ``Failure`` through the single authority (plan 6.5): the I/O class
  is ``PERSISTENCE.WRITE_FAILED`` (the plan's row names the class, not the verb) and
  closes the transaction; ``SQLITE_BUSY`` is the conflict, ``SQLITE_CORRUPT`` and an
  uncoded error are ``STORAGE_UNAVAILABLE``, all three nonfatal;
- *logically failed* at once: the first failure stored, the transaction still
  registered and its connection still checked out, every later member call -- saved
  or fresh reference, reader or writer -- returning the SAME object with no SQL;
  *physically released* only by ``commit()`` (which publishes nothing) or
  ``rollback()``, exactly once, with the pool, the root registry and the counting
  wrapper agreeing;
- healthy reads unchanged: an existing row, a missing row (``CORE.INVARIANT_VIOLATION``
  ``does not exist``), an empty collection and ``MISSING`` are never confused with a
  storage failure, and a stored row the canonical model refuses stays the invariant
  and nonfatal;
- a standalone reader over a bare connection returns the ``Failure`` with no owner to
  close, and the caller's own context releases the connection;
- an application operation (``evaluate_retry`` through ``run_operation``) that
  consumes the diagnostic reader returns the ``Failure`` and has released its
  transaction by the time it returns.

Every fault is an injected driver fault, never a physical disk failure. Every durable
assertion is a fresh read after release. The one permitted non-zero consistency
count is ``queued_without_snapshot == 1`` for the QUEUED parent inserted through
``add`` (scaffolding, plan 4.6).
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Callable
from datetime import timedelta
from typing import Final

import pytest
from pydantic.experimental.missing_sentinel import MISSING
from sqlalchemy import insert
from sqlalchemy.engine import Connection
from sqlalchemy.pool import QueuePool

from crypto_lab.artifacts.ownership import SystemArtifactOwner, artifact_owner_hash
from crypto_lab.configuration.models import ApplicationConfig
from crypto_lab.configuration.snapshot import ConfigSnapshot, snapshot_configuration
from crypto_lab.domain.lifecycle import EngineRunState, ExperimentState
from crypto_lab.domain.results import Failure, Success
from crypto_lab.experiments.requests import RetryEvaluationRequest
from crypto_lab.experiments.retry import evaluate_retry
from crypto_lab.persistence.codecs import encode_observation
from crypto_lab.persistence.database import ConsistencyReport, SqliteDatabase
from crypto_lab.persistence.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
    STORAGE_UNAVAILABLE,
    WRITE_FAILED,
)
from crypto_lab.persistence.registries import (
    SqliteArtifactOwnerRegistry,
    SqliteAvailabilityObservationReader,
    SqliteConfigurationSnapshotWriter,
    SqliteDatasetRepository,
    SqliteDiagnosticReader,
    SqliteStrategyVersionRepository,
)
from crypto_lab.persistence.schema import RuntimeAvailabilityObservationRow
from crypto_lab.persistence.unit_of_work import SqliteTransaction
from doubles.experiments import (
    AVAIL_A,
    AVAIL_B,
    DIAG_ID,
    EXECUTABLE_HASH,
    EXPERIMENT_ID,
    INSTANT,
    OTHER_DIAG_ID,
    OTHER_EXPERIMENT_ID,
    RUN_ID,
    SLOT_A,
    FixedClock,
    sample_diagnostic,
    sample_experiment,
    sample_observation,
    sample_run,
)
from persistence_support.harness import (
    CountingUnitOfWork,
    SqliteHarness,
    code,
    commit,
    cursor_fault,
    fetch_fault,
    ok,
    put_experiment,
    put_lifecycle_parents,
    put_run,
    sample_dataset_with_partitions,
    sample_strategy_version,
    sqlite_error,
)

_E: Final = ExperimentState
_R: Final = EngineRunState
_SQLITE_BUSY: Final = 5
_SQLITE_CORRUPT: Final = 11
#: ``SQLITE_IOERR | (1 << 8)``: the extended code of a failed page read.
_SQLITE_IOERR_READ: Final = 266
_UNKNOWN_HASH: Final = "a" * 64
_UNKNOWN_DATASET: Final = "ds_" + "0" * 36
_SCAFFOLDED_PARENT: Final = ConsistencyReport(
    dangling_diagnostic_references=0,
    slot_identity_mismatches=0,
    spec_projection_mismatches=0,
    queued_without_snapshot=1,
    causal_edge_mismatches=0,
    unresolved_causal_references=0,
    registry_projection_mismatches=0,
    foreign_key_violations=0,
)
#: ``(label, statement predicate, the call, the expected failure details)``.
_Read = tuple[
    str,
    Callable[[str], bool],
    Callable[[SqliteTransaction], object],
    dict[str, object],
]
#: ``(label, statement predicate, the standalone read over a bare connection)``.
_Standalone = tuple[str, Callable[[str], bool], Callable[[Connection], object]]


def _checked_out(database: SqliteDatabase) -> int:
    """Connections the pool has lent out, not counting this probe's own."""
    with database.connection() as connection:
        pool = connection.engine.pool
        assert isinstance(pool, QueuePool)
        return pool.checkedout() - 1


def _details(result: object) -> dict[str, object]:
    assert isinstance(result, Failure), result
    (diagnostic,) = result.diagnostics
    return dict(diagnostic.details)


def _message(result: object) -> str:
    assert isinstance(result, Failure), result
    (diagnostic,) = result.diagnostics
    return diagnostic.message


def _is_missing(value: object) -> bool:
    return value is MISSING


def _clock() -> FixedClock:
    return FixedClock(INSTANT)


def _snapshot() -> ConfigSnapshot:
    return snapshot_configuration(ApplicationConfig())


def _owner() -> SystemArtifactOwner:
    return SystemArtifactOwner(
        owner_kind="SYSTEM", core_component="persistence", correlation_id="correction-c"
    )


def _from(table: str) -> Callable[[str], bool]:
    """Admits the ``SELECT`` reading ``table`` (an ``UPDATE`` has no ``FROM``)."""
    pattern = re.compile(rf"\bFROM {table}\b")
    return lambda statement: pattern.search(statement) is not None


def _io_read_refusal(table: str, operation: str, identity: str) -> dict[str, object]:
    return {
        "table": table,
        "operation": operation,
        "identity": identity,
        "sqlite_errorcode": _SQLITE_IOERR_READ,
        "sqlite_errorname": "SQLITE_IOERR_READ",
    }


def _seed(harness: SqliteHarness) -> None:
    """Commit the rows every read below can find: the QUEUED parent, the
    observation ``AVAIL_A``, two diagnostics, one strategy version, one dataset
    with its partitions and one system artifact owner."""
    put_lifecycle_parents(harness, observation=True)
    harness.seed_diagnostic(sample_diagnostic())
    harness.seed_diagnostic(sample_diagnostic(OTHER_DIAG_ID))
    transaction = harness.unit_of_work().begin()
    ok(transaction.strategy_versions.register(sample_strategy_version()))
    ok(transaction.datasets.register(*sample_dataset_with_partitions()))
    ok(transaction.artifact_owners.register(_owner()))
    commit(transaction)


_DATASET_ID: Final = sample_dataset_with_partitions()[0].dataset_id
_STRATEGY_HASH: Final = sample_strategy_version().content_hash
_DATASET_HASH: Final = sample_dataset_with_partitions()[0].content_hash
_OWNER_HASH: Final = artifact_owner_hash(_owner())

#: Every transaction-bound read path, each reached at its own statement.
_READS: tuple[_Read, ...] = (
    (
        "diagnostics.get",
        _from("diagnostics"),
        lambda transaction: transaction.diagnostics.get(DIAG_ID),
        _io_read_refusal("diagnostics", "get", DIAG_ID),
    ),
    (
        "diagnostics.get_many",
        _from("diagnostics"),
        lambda transaction: transaction.diagnostics.get_many((DIAG_ID, OTHER_DIAG_ID)),
        _io_read_refusal("diagnostics", "get_many", ""),
    ),
    (
        "availability_observations.get",
        _from("runtime_availability_observations"),
        lambda transaction: transaction.availability_observations.get(AVAIL_A),
        _io_read_refusal("runtime_availability_observations", "get", AVAIL_A),
    ),
    (
        "availability_observations.list_for_adapter",
        _from("runtime_availability_observations"),
        lambda transaction: transaction.availability_observations.list_for_adapter(
            "adapter.alpha", "1.0.0", EXECUTABLE_HASH
        ),
        _io_read_refusal(
            "runtime_availability_observations",
            "list_for_adapter",
            "adapter.alpha@1.0.0",
        ),
    ),
    (
        "configuration_snapshots.get",
        _from("experiments"),
        lambda transaction: transaction.configuration_snapshots.get(EXPERIMENT_ID),
        _io_read_refusal("experiments", "get", EXPERIMENT_ID),
    ),
    (
        # The pre-read of ``freeze`` is a read: refused before any UPDATE is issued.
        "configuration_snapshots.freeze (pre-read)",
        _from("experiments"),
        lambda transaction: transaction.configuration_snapshots.freeze(
            EXPERIMENT_ID, _snapshot()
        ),
        _io_read_refusal("experiments", "freeze", EXPERIMENT_ID),
    ),
    (
        "strategy_versions.get_by_hash",
        _from("strategy_versions"),
        lambda transaction: transaction.strategy_versions.get_by_hash(_STRATEGY_HASH),
        _io_read_refusal("strategy_versions", "get_by_hash", _STRATEGY_HASH),
    ),
    (
        "datasets.get_by_hash",
        _from("datasets"),
        lambda transaction: transaction.datasets.get_by_hash(_DATASET_HASH),
        _io_read_refusal("datasets", "get_by_hash", _DATASET_HASH),
    ),
    (
        # The descriptor probe, a ``scalar_one_or_none()`` read, is refused first.
        "datasets.list_partitions (descriptor probe)",
        _from("datasets"),
        lambda transaction: transaction.datasets.list_partitions(_DATASET_ID),
        _io_read_refusal("datasets", "list_partitions", _DATASET_ID),
    ),
    (
        # The descriptor probe (``FROM datasets``) has passed; the partition read
        # is refused, so the failure names the second table of the method.
        "datasets.list_partitions (partition read)",
        _from("dataset_partitions"),
        lambda transaction: transaction.datasets.list_partitions(_DATASET_ID),
        _io_read_refusal("dataset_partitions", "list_partitions", _DATASET_ID),
    ),
    (
        "artifact_owners.get",
        _from("artifact_owners"),
        lambda transaction: transaction.artifact_owners.get(_OWNER_HASH),
        _io_read_refusal("artifact_owners", "get", _OWNER_HASH),
    ),
)
_READ_IDS = [label for label, _, _, _ in _READS]
#: The reads whose rows are materialized after the statement executed: two
#: ``fetchone`` paths (``.first()`` and ``scalar_one_or_none()``) and three
#: ``fetchall`` paths (``.all()``).
_MATERIALIZED_LABELS: Final = frozenset(
    {
        "diagnostics.get_many",
        "availability_observations.list_for_adapter",
        "strategy_versions.get_by_hash",
        "datasets.list_partitions (descriptor probe)",
        "datasets.list_partitions (partition read)",
    }
)
_MATERIALIZED_READS = tuple(read for read in _READS if read[0] in _MATERIALIZED_LABELS)
_MATERIALIZED_IDS = [label for label, _, _, _ in _MATERIALIZED_READS]

#: The same readers constructed over a bare connection, no transaction owner.
_STANDALONE: tuple[_Standalone, ...] = (
    (
        "SqliteDiagnosticReader.get",
        _from("diagnostics"),
        lambda connection: SqliteDiagnosticReader(connection, clock=_clock()).get(
            DIAG_ID
        ),
    ),
    (
        "SqliteDiagnosticReader.get_many",
        _from("diagnostics"),
        lambda connection: SqliteDiagnosticReader(connection, clock=_clock()).get_many(
            (DIAG_ID, OTHER_DIAG_ID)
        ),
    ),
    (
        "SqliteAvailabilityObservationReader.list_for_adapter",
        _from("runtime_availability_observations"),
        lambda connection: SqliteAvailabilityObservationReader(
            connection, clock=_clock()
        ).list_for_adapter("adapter.alpha", "1.0.0", EXECUTABLE_HASH),
    ),
    (
        "SqliteConfigurationSnapshotWriter.get",
        _from("experiments"),
        lambda connection: SqliteConfigurationSnapshotWriter(
            connection, clock=_clock()
        ).get(EXPERIMENT_ID),
    ),
    (
        "SqliteStrategyVersionRepository.get_by_hash",
        _from("strategy_versions"),
        lambda connection: SqliteStrategyVersionRepository(
            connection, clock=_clock()
        ).get_by_hash(_STRATEGY_HASH),
    ),
    (
        "SqliteDatasetRepository.list_partitions",
        _from("dataset_partitions"),
        lambda connection: SqliteDatasetRepository(
            connection, clock=_clock()
        ).list_partitions(_DATASET_ID),
    ),
    (
        "SqliteArtifactOwnerRegistry.get",
        _from("artifact_owners"),
        lambda connection: SqliteArtifactOwnerRegistry(connection, clock=_clock()).get(
            _OWNER_HASH
        ),
    ),
)
_STANDALONE_IDS = [label for label, _, _ in _STANDALONE]


def _assert_logically_failed(
    harness: SqliteHarness,
    transaction: SqliteTransaction,
    refused: object,
    *,
    statements_issued: Callable[[], int],
) -> None:
    """The ruling's first half: the failure is stored and the transaction is still
    registered and still holds its connection; every member -- both readers, a
    registry read, a lifecycle read, a member write -- answers with the SAME object
    and issues no statement."""
    assert transaction.open_failure() is refused
    assert harness.open_transactions() == (transaction,)
    assert _checked_out(harness.database) == 1
    issued = statements_issued()
    assert transaction.diagnostics.get(DIAG_ID) is refused
    assert transaction.diagnostics.get_many((DIAG_ID,)) is refused
    # The gate precedes argument handling: not an empty Success, not an invariant.
    assert transaction.diagnostics.get_many(()) is refused
    assert transaction.diagnostics.get_many((DIAG_ID, DIAG_ID)) is refused
    assert transaction.availability_observations.get(AVAIL_A) is refused
    assert transaction.experiments.get(EXPERIMENT_ID) is refused
    assert transaction.configuration_snapshots.get(EXPERIMENT_ID) is refused
    assert transaction.strategy_versions.get_by_hash(_STRATEGY_HASH) is refused
    assert transaction.datasets.list_partitions(_DATASET_ID) is refused
    assert transaction.artifact_owners.get(_OWNER_HASH) is refused
    assert (
        transaction.availability_observation_writer.add(sample_observation(AVAIL_B))
        is refused
    )
    assert statements_issued() == issued


def _assert_released_once_by_commit(
    harness: SqliteHarness, transaction: SqliteTransaction, refused: object
) -> None:
    """The ruling's second half: ``commit()`` returns the stored failure, publishes
    nothing and releases; ``rollback()`` afterwards releases nothing more."""
    database = harness.database
    assert transaction.commit() is refused
    assert harness.open_transactions() == ()
    assert _checked_out(database) == 0
    transaction.rollback()
    transaction.rollback()
    assert _checked_out(database) == 0
    assert harness.open_transactions() == ()


def _assert_fresh_reads_are_healthy(harness: SqliteHarness) -> None:
    """After release: a new transaction reads every seeded row normally."""
    fresh = harness.unit_of_work().begin()
    try:
        assert ok(fresh.diagnostics.get(DIAG_ID)) == sample_diagnostic()
        assert ok(fresh.availability_observations.get(AVAIL_A)) == sample_observation(
            AVAIL_A
        )
        assert _is_missing(ok(fresh.configuration_snapshots.get(EXPERIMENT_ID)))
        assert isinstance(fresh.strategy_versions.get_by_hash(_STRATEGY_HASH), Success)
        assert isinstance(fresh.datasets.get_by_hash(_DATASET_HASH), Success)
        assert isinstance(fresh.datasets.list_partitions(_DATASET_ID), Success)
        assert isinstance(fresh.artifact_owners.get(_OWNER_HASH), Success)
    finally:
        fresh.rollback()


# --------------------------------------------------------------------------
# Execution failure, transaction-bound: the I/O class closes the owner
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "when", "attempt", "expected"), _READS, ids=_READ_IDS
)
def test_a_members_io_class_read_failure_closes_the_transaction(
    sqlite_harness: SqliteHarness,
    monkeypatch: pytest.MonkeyPatch,
    label: str,
    when: Callable[[str], bool],
    attempt: Callable[[SqliteTransaction], object],
    expected: dict[str, object],
) -> None:
    """Each read path, refused at its own statement by ``SQLITE_IOERR_READ``: the
    classified ``Failure`` with the plan 6.5 details (no SQL text, no row), the
    transaction logically failed at once -- saved references included -- and
    physically released once by ``commit()``; a fresh transaction reads normally."""
    _seed(sqlite_harness)
    database = sqlite_harness.database
    with cursor_fault(database, monkeypatch) as fault:
        transaction = sqlite_harness.unit_of_work().begin()
        saved_diagnostics = transaction.diagnostics
        saved_observations = transaction.availability_observations
        saved_experiments = transaction.experiments
        fault.arm(sqlite_error(_SQLITE_IOERR_READ, "SQLITE_IOERR_READ"), when=when)
        refused = attempt(transaction)
        assert not fault.armed, (label, fault.passed)
        assert isinstance(refused, Failure), (label, refused)
        assert code(refused) == WRITE_FAILED
        assert _details(refused) == expected
        assert "SELECT" not in _message(refused)
        # References obtained before the failure obey the failed state.
        issued = len(fault.passed)
        assert saved_diagnostics.get(DIAG_ID) is refused
        assert saved_observations.list_for_adapter("x", "1.0.0", _UNKNOWN_HASH) is (
            refused
        )
        assert saved_experiments.get(EXPERIMENT_ID) is refused
        assert attempt(transaction) is refused
        assert len(fault.passed) == issued
        _assert_logically_failed(
            sqlite_harness,
            transaction,
            refused,
            statements_issued=lambda: len(fault.passed),
        )
        _assert_released_once_by_commit(sqlite_harness, transaction, refused)
    _assert_fresh_reads_are_healthy(sqlite_harness)
    assert database.consistency_report() == _SCAFFOLDED_PARENT


# --------------------------------------------------------------------------
# Materialization failure: the statement ran, its rows cannot be fetched
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "when", "attempt", "expected"), _MATERIALIZED_READS, ids=_MATERIALIZED_IDS
)
def test_a_read_whose_rows_cannot_be_materialized_is_the_same_failure(
    sqlite_harness: SqliteHarness,
    monkeypatch: pytest.MonkeyPatch,
    label: str,
    when: Callable[[str], bool],
    attempt: Callable[[SqliteTransaction], object],
    expected: dict[str, object],
) -> None:
    """The fetch boundary: ``do_execute`` succeeded and the driver fails while the
    rows are fetched. The method returns the same classified ``Failure`` -- not a
    decoded prefix, not an empty tuple -- and the owner closes exactly as for a
    refused statement."""
    _seed(sqlite_harness)
    database = sqlite_harness.database
    with fetch_fault(monkeypatch) as fault:
        transaction = sqlite_harness.unit_of_work().begin()
        fault.arm(sqlite_error(_SQLITE_IOERR_READ, "SQLITE_IOERR_READ"), when=when)
        refused = attempt(transaction)
        assert not fault.armed, (label, fault.passed)
        assert len(fault.fired) == 1
        assert isinstance(refused, Failure), (label, refused)
        assert code(refused) == WRITE_FAILED
        assert _details(refused) == expected
        assert transaction.open_failure() is refused
        assert sqlite_harness.open_transactions() == (transaction,)
        assert _checked_out(database) == 1
        fetched = len(fault.passed)
        assert attempt(transaction) is refused
        assert transaction.experiments.get(EXPERIMENT_ID) is refused
        assert len(fault.passed) == fetched
        _assert_released_once_by_commit(sqlite_harness, transaction, refused)
    _assert_fresh_reads_are_healthy(sqlite_harness)
    assert database.consistency_report() == _SCAFFOLDED_PARENT


# --------------------------------------------------------------------------
# Standalone readers: the Failure with no owner to close
# --------------------------------------------------------------------------


@pytest.mark.parametrize(("label", "when", "read"), _STANDALONE, ids=_STANDALONE_IDS)
def test_a_standalone_reader_returns_the_failure_and_the_caller_keeps_its_connection(
    sqlite_harness: SqliteHarness,
    monkeypatch: pytest.MonkeyPatch,
    label: str,
    when: Callable[[str], bool],
    read: Callable[[Connection], object],
) -> None:
    """Constructed over a bare read-only session (plan 4.4's ``Sqlite…(connection,
    clock=…)`` shape), a refused read is the classified ``Failure`` and nothing
    else: no transaction is registered, the session stays the caller's, and the
    caller's own context releases it."""
    _seed(sqlite_harness)
    database = sqlite_harness.database
    with (
        cursor_fault(database, monkeypatch) as fault,
        database.read_only() as connection,
    ):
        fault.arm(sqlite_error(_SQLITE_IOERR_READ, "SQLITE_IOERR_READ"), when=when)
        refused = read(connection)
        assert not fault.armed, (label, fault.passed)
        assert isinstance(refused, Failure), (label, refused)
        assert code(refused) == WRITE_FAILED
        assert _details(refused)["sqlite_errorcode"] == _SQLITE_IOERR_READ
        assert sqlite_harness.open_transactions() == ()
        assert _checked_out(database) == 1
        # The injected refusal left the caller's own transaction open.
        assert connection.in_transaction()
    assert _checked_out(database) == 0
    assert database.consistency_report() == _SCAFFOLDED_PARENT


# --------------------------------------------------------------------------
# Classification controls: nonfatal codes leave the transaction usable
# --------------------------------------------------------------------------


def test_nonfatal_read_refusals_leave_the_transaction_usable(
    sqlite_harness: SqliteHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The single authority decides: ``SQLITE_BUSY`` on a read is the conflict, an
    uncoded driver error and ``SQLITE_CORRUPT`` are ``STORAGE_UNAVAILABLE``; none
    closes the transaction, the refused read succeeds when reissued, and the
    transaction writes and commits afterwards."""
    _seed(sqlite_harness)
    database = sqlite_harness.database
    with cursor_fault(database, monkeypatch) as fault:
        transaction = sqlite_harness.unit_of_work().begin()
        fault.arm(sqlite_error(_SQLITE_BUSY, "SQLITE_BUSY"), when=_from("diagnostics"))
        busy = transaction.diagnostics.get(DIAG_ID)
        assert not fault.armed
        assert code(busy) == CONCURRENCY_CONFLICT
        assert _details(busy)["sqlite_errorcode"] == _SQLITE_BUSY
        assert transaction.open_failure() is None
        assert ok(transaction.diagnostics.get(DIAG_ID)) == sample_diagnostic()
        fault.arm(
            sqlite3.OperationalError("injected driver fault without a code"),
            when=_from("strategy_versions"),
        )
        uncoded = transaction.strategy_versions.get_by_hash(_STRATEGY_HASH)
        assert not fault.armed
        assert code(uncoded) == STORAGE_UNAVAILABLE
        assert "sqlite_errorcode" not in _details(uncoded)
        assert transaction.open_failure() is None
        fault.arm(
            sqlite_error(_SQLITE_CORRUPT, "SQLITE_CORRUPT"),
            when=_from("runtime_availability_observations"),
        )
        corrupt = transaction.availability_observations.get(AVAIL_A)
        assert not fault.armed
        assert code(corrupt) == STORAGE_UNAVAILABLE
        assert _details(corrupt)["sqlite_errorcode"] == _SQLITE_CORRUPT
        assert transaction.open_failure() is None
        healthy = transaction.strategy_versions.get_by_hash(_STRATEGY_HASH)
        assert isinstance(healthy, Success)
        ok(transaction.availability_observation_writer.add(sample_observation(AVAIL_B)))
        commit(transaction)
    fresh = sqlite_harness.unit_of_work().begin()
    try:
        assert ok(fresh.availability_observations.get(AVAIL_B)) == sample_observation(
            AVAIL_B
        )
    finally:
        fresh.rollback()
    assert _checked_out(database) == 0
    assert database.consistency_report() == _SCAFFOLDED_PARENT


def test_healthy_reads_are_never_confused_with_a_storage_failure(
    sqlite_harness: SqliteHarness,
) -> None:
    """The distinct healthy answers, all with no failure stored: an existing row is
    the record; a missing identity is ``CORE.INVARIANT_VIOLATION`` ``does not exist``
    carrying no SQLite code; an unknown adapter is an empty tuple; no identifiers is
    an empty tuple; a parent without a frozen snapshot is ``MISSING``."""
    _seed(sqlite_harness)
    descriptor, partitions = sample_dataset_with_partitions()
    transaction = sqlite_harness.unit_of_work().begin()
    try:
        assert ok(transaction.diagnostics.get(DIAG_ID)) == sample_diagnostic()
        assert ok(transaction.diagnostics.get_many((OTHER_DIAG_ID, DIAG_ID))) == (
            sample_diagnostic(),
            sample_diagnostic(OTHER_DIAG_ID),
        )
        assert ok(transaction.strategy_versions.get_by_hash(_STRATEGY_HASH)) == (
            sample_strategy_version()
        )
        assert ok(transaction.datasets.get_by_hash(_DATASET_HASH)) == descriptor
        assert ok(transaction.datasets.list_partitions(_DATASET_ID)) == partitions
        assert ok(transaction.artifact_owners.get(_OWNER_HASH)) == _owner()
        for absent in (
            transaction.diagnostics.get(f"diag_{'0' * 8}-0000-4000-8000-{'0' * 12}"),
            transaction.availability_observations.get(AVAIL_B),
            transaction.strategy_versions.get_by_hash(_UNKNOWN_HASH),
            transaction.datasets.get_by_hash(_UNKNOWN_HASH),
            transaction.datasets.list_partitions(_UNKNOWN_DATASET),
            transaction.artifact_owners.get(_UNKNOWN_HASH),
            transaction.configuration_snapshots.get(OTHER_EXPERIMENT_ID),
        ):
            assert code(absent) == INVARIANT_VIOLATION
            assert _message(absent).endswith("does not exist")
            assert "sqlite_errorcode" not in _details(absent)
        unknown = transaction.availability_observations.list_for_adapter(
            "adapter.unknown", "1.0.0", EXECUTABLE_HASH
        )
        assert ok(unknown) == ()
        assert ok(transaction.diagnostics.get_many(())) == ()
        assert _is_missing(ok(transaction.configuration_snapshots.get(EXPERIMENT_ID)))
        assert transaction.open_failure() is None
    finally:
        transaction.rollback()
    assert sqlite_harness.database.consistency_report() == _SCAFFOLDED_PARENT


def test_a_stored_row_the_record_refuses_stays_the_invariant_and_nonfatal(
    sqlite_harness: SqliteHarness,
) -> None:
    """Canonical egress refusal is not relabelled: a row SQL accepts but the
    canonical model refuses (``runtime_version`` passes the length ``CHECK`` only)
    makes the read ``CORE.INVARIANT_VIOLATION`` naming the column, the transaction
    stays open, and the other reads proceed. The row is inserted directly -- the
    table is append-only, so no production path can write it. The report is
    unchanged: ``registry_projection_mismatches`` covers the two registry ports
    (plan 4.6), not the observation table."""
    _seed(sqlite_harness)
    database = sqlite_harness.database
    corrupt = dict(encode_observation(sample_observation(AVAIL_B)))
    corrupt["runtime_version"] = "not.a.semver!"
    with database.connection() as connection:
        connection.execute(insert(RuntimeAvailabilityObservationRow).values(**corrupt))
        connection.commit()
    transaction = sqlite_harness.unit_of_work().begin()
    try:
        refused = transaction.availability_observations.get(AVAIL_B)
        assert code(refused) == INVARIANT_VIOLATION
        assert _details(refused)["location"] == "runtime_version"
        assert "sqlite_errorcode" not in _details(refused)
        assert transaction.open_failure() is None
        listed = transaction.availability_observations.list_for_adapter(
            "adapter.alpha", "1.0.0", EXECUTABLE_HASH
        )
        assert code(listed) == INVARIANT_VIOLATION
        assert _details(listed)["identity"] == AVAIL_B
        assert transaction.open_failure() is None
        assert ok(transaction.availability_observations.get(AVAIL_A)) == (
            sample_observation(AVAIL_A)
        )
        assert ok(transaction.diagnostics.get(DIAG_ID)) == sample_diagnostic()
    finally:
        transaction.rollback()
    assert _checked_out(database) == 0
    assert database.consistency_report() == _SCAFFOLDED_PARENT


# --------------------------------------------------------------------------
# First-failure propagation in both orders
# --------------------------------------------------------------------------


def test_the_first_stored_failure_is_preserved_across_reads_and_writes(
    sqlite_harness: SqliteHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both orders through one owner. Write then read: a lifecycle write's I/O-class
    refusal is what both readers answer with -- the diagnostic reader answers instead
    of raising. Read then write: a fatal read's ``Failure`` is what a member write
    answers with, and a second armed fault never fires because no SQL is issued;
    ``rollback()`` is the finalizer this time."""
    _seed(sqlite_harness)
    database = sqlite_harness.database
    other = sample_experiment(_E.DRAFT, experiment_id=OTHER_EXPERIMENT_ID)
    with cursor_fault(database, monkeypatch) as fault:
        transaction = sqlite_harness.unit_of_work().begin()
        fault.arm(
            sqlite_error(_SQLITE_IOERR_READ, "SQLITE_IOERR_READ"),
            when=lambda statement: statement.startswith("INSERT"),
        )
        first = transaction.experiments.add(other)
        assert not fault.armed
        assert code(first) == WRITE_FAILED
        issued = len(fault.passed)
        assert transaction.diagnostics.get(DIAG_ID) is first
        assert transaction.diagnostics.get_many((DIAG_ID, OTHER_DIAG_ID)) is first
        assert transaction.availability_observations.get(AVAIL_A) is first
        listed = transaction.availability_observations.list_for_adapter(
            "adapter.alpha", "1.0.0", EXECUTABLE_HASH
        )
        assert listed is first
        assert len(fault.passed) == issued
        _assert_released_once_by_commit(sqlite_harness, transaction, first)
    with cursor_fault(database, monkeypatch) as fault:
        transaction = sqlite_harness.unit_of_work().begin()
        fault.arm(
            sqlite_error(_SQLITE_IOERR_READ, "SQLITE_IOERR_READ"),
            when=_from("artifact_owners"),
        )
        fatal = transaction.artifact_owners.get(_OWNER_HASH)
        assert not fault.armed
        assert code(fatal) == WRITE_FAILED
        assert transaction.open_failure() is fatal
        # A second fault stays armed: the closed transaction issues no SQL.
        fault.arm(sqlite_error(_SQLITE_IOERR_READ, "SQLITE_IOERR_READ"))
        assert transaction.strategy_versions.register(sample_strategy_version()) is (
            fatal
        )
        assert transaction.experiments.add(other) is fatal
        assert transaction.diagnostics.get(DIAG_ID) is fatal
        assert fault.armed
        assert transaction.open_failure() is fatal
        assert _checked_out(database) == 1
        transaction.rollback()
        assert sqlite_harness.open_transactions() == ()
        assert _checked_out(database) == 0
        assert fault.armed
    assert sqlite_harness.committed_experiments() == (sample_experiment(_E.QUEUED),)
    assert database.consistency_report() == _SCAFFOLDED_PARENT


# --------------------------------------------------------------------------
# The compound sequence: provisional write, fatal read, finalize, prove nothing
# --------------------------------------------------------------------------


def test_a_fatal_read_after_a_provisional_write_publishes_nothing(
    sqlite_harness: SqliteHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A valid provisional write, then the diagnostic read fails fatally. Observed
    the moment the call returned: logically failed -- closed, still registered,
    connection still checked out, the counting wrapper at one; with the fault gone,
    every permitted access answers with the stored object and no SQL; ``commit()``
    (the prescribed finalizer) publishes nothing and releases exactly once by pool,
    root registry and wrapper; a fresh connection proves the provisional row was
    never committed; a new transaction then operates."""
    _seed(sqlite_harness)
    database = sqlite_harness.database
    root = sqlite_harness.unit_of_work()
    counting = CountingUnitOfWork(root)
    provisional = sample_experiment(_E.DRAFT, experiment_id=OTHER_EXPERIMENT_ID)
    with cursor_fault(database, monkeypatch) as fault:
        transaction = counting.begin()
        (owner,) = root.open_transactions()
        ok(transaction.experiments.add(provisional))
        assert ok(transaction.experiments.get(OTHER_EXPERIMENT_ID)) == provisional
        saved_diagnostics = transaction.diagnostics
        fault.arm(
            sqlite_error(_SQLITE_IOERR_READ, "SQLITE_IOERR_READ"),
            when=_from("diagnostics"),
        )
        refused = transaction.diagnostics.get(DIAG_ID)
        assert not fault.armed
        assert code(refused) == WRITE_FAILED
        assert _details(refused) == _io_read_refusal("diagnostics", "get", DIAG_ID)
        # Logically failed, physically held (the ruling's first half).
        assert owner.open_failure() is refused
        assert root.open_transactions() == (owner,)
        assert (counting.open_now, counting.max_open) == (1, 1)
        assert _checked_out(database) == 1
        # The fault has fired and is gone; the closed state alone answers.
        issued = len(fault.passed)
        assert saved_diagnostics.get(DIAG_ID) is refused
        assert transaction.diagnostics.get(DIAG_ID) is refused
        assert transaction.availability_observations.get(AVAIL_A) is refused
        assert transaction.experiments.get(OTHER_EXPERIMENT_ID) is refused
        assert owner.configuration_snapshots.get(EXPERIMENT_ID) is refused
        assert owner.datasets.register(*sample_dataset_with_partitions()) is refused
        assert len(fault.passed) == issued
        assert (counting.open_now, counting.max_open) == (1, 1)
        # The release (the ruling's second half): every bookkeeping agrees.
        assert transaction.commit() is refused
        assert root.open_transactions() == ()
        assert (counting.open_now, _checked_out(database)) == (0, 0)
        transaction.rollback()
        assert (counting.open_now, _checked_out(database)) == (0, 0)
        assert len(fault.passed) == issued
    # A fresh connection: the provisional write never became durable.
    assert sqlite_harness.committed_experiments() == (sample_experiment(_E.QUEUED),)
    fresh = sqlite_harness.unit_of_work().begin()
    try:
        assert code(fresh.experiments.get(OTHER_EXPERIMENT_ID)) == INVARIANT_VIOLATION
        assert ok(fresh.diagnostics.get(DIAG_ID)) == sample_diagnostic()
    finally:
        fresh.rollback()
    assert database.consistency_report() == _SCAFFOLDED_PARENT
    later = sqlite_harness.unit_of_work().begin()
    ok(later.experiments.add(provisional))
    commit(later)
    assert sqlite_harness.committed_experiments() == (
        sample_experiment(_E.QUEUED),
        provisional,
    )
    assert _checked_out(database) == 0


# --------------------------------------------------------------------------
# The application boundary: the operation returns the Failure, released
# --------------------------------------------------------------------------


def test_the_retry_evaluation_returns_the_read_failure_with_its_transaction_released(
    sqlite_harness: SqliteHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``evaluate_retry`` (plan 8.4) reads the predecessor's primary diagnostic
    through ``transaction.diagnostics`` inside ``run_operation``. With that read
    refused by ``SQLITE_IOERR_READ`` the operation returns the classified
    ``Failure`` -- passed through, not relabelled as an invariant -- and by the time
    it returns the driver's ``finally`` has rolled back and released: counting
    wrapper, root registry and pool all read zero, no decision row exists and the
    experiment is unchanged. With the fault gone the same request evaluates."""
    database = sqlite_harness.database
    experiment = sample_experiment(_E.RUNNING)
    predecessor = sample_run(_R.UNAVAILABLE)
    sqlite_harness.seed_observation(sample_observation(AVAIL_A))
    sqlite_harness.seed_diagnostic(sample_diagnostic())
    put_experiment(sqlite_harness, experiment)
    put_run(sqlite_harness, predecessor)
    request = RetryEvaluationRequest(
        schema_version="1.0.0",
        experiment_id=EXPERIMENT_ID,
        logical_slot_id=SLOT_A,
        predecessor_run_id=RUN_ID,
        expected_experiment_revision=experiment.revision,
        expected_predecessor_revision=predecessor.revision,
    )
    clock = FixedClock(INSTANT + timedelta(minutes=1))
    root = sqlite_harness.unit_of_work()
    counting = CountingUnitOfWork(root)
    with cursor_fault(database, monkeypatch) as fault:
        fault.arm(
            sqlite_error(_SQLITE_IOERR_READ, "SQLITE_IOERR_READ"),
            when=_from("diagnostics"),
        )
        outcome = evaluate_retry(request, unit_of_work=counting, clock=clock)
        assert not fault.armed, fault.passed
        assert isinstance(outcome, Failure), outcome
        assert code(outcome) == WRITE_FAILED
        assert _details(outcome) == _io_read_refusal("diagnostics", "get", DIAG_ID)
        # Observed as the operation returned: the driver finalized its transaction.
        assert (counting.open_now, counting.max_open) == (0, 1)
        assert root.open_transactions() == ()
        assert _checked_out(database) == 0
    assert sqlite_harness.committed_retry_decisions() == ()
    assert sqlite_harness.committed_experiments() == (experiment,)
    decided = evaluate_retry(
        request, unit_of_work=sqlite_harness.unit_of_work(), clock=clock
    )
    assert isinstance(decided, Success), decided
    assert len(sqlite_harness.committed_retry_decisions()) == 1
    assert sqlite_harness.open_transactions() == ()
    assert _checked_out(database) == 0
