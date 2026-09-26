"""Member write failures close the owning transaction (plan 4.2; correction A).

Plan 4.2's member rule: a refusal of the I/O class (``PERSISTENCE.WRITE_FAILED``:
``SQLITE_FULL``, ``SQLITE_IOERR_*``, ``SQLITE_READONLY_*``, reading 3) closes the
transaction -- every later member call and ``commit()`` return the stored
``Failure`` and only ``rollback()`` (or that ``commit()``) releases the connection
-- because SQLite may have rolled the transaction back itself, and a later
statement would otherwise run, and commit, in autocommit mode. The four lifecycle
repositories implement the rule through ``TransactionScope.refused``; the Task 6
review found that the five persistence-owned members (``configuration_snapshots``,
``availability_observation_writer``, ``strategy_versions``, ``datasets``,
``artifact_owners``) returned their registry's ``Failure`` without storing it, so
an I/O-class refusal left the transaction open. This module is the promoted,
maintained proof of the correction: the same owner mechanism now absorbs those
members' failures.

Every fault is injected at the dialect's ``do_execute`` boundary through
``persistence_support.harness.cursor_fault`` (the technique Task 6 established),
so the ACTUAL member implementation runs, hits the error at its own statement and
returns its own ``Failure``; nothing is stubbed. Every durable assertion is a fresh
read after the transaction released. The one non-zero consistency count these
tests permit is ``queued_without_snapshot == 1`` for the ``QUEUED`` parent
``put_lifecycle_parents`` inserts directly through ``add`` (scaffolding that never
crossed the queue edge, plan 4.6); once a test freezes that parent's snapshot the
count is zero and the whole report is asserted clean.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from typing import Final

import pytest
from pydantic.experimental.missing_sentinel import MISSING
from sqlalchemy.pool import QueuePool

from crypto_lab.artifacts.ownership import SystemArtifactOwner
from crypto_lab.configuration.models import ApplicationConfig
from crypto_lab.configuration.snapshot import ConfigSnapshot, snapshot_configuration
from crypto_lab.domain.lifecycle import ExperimentState
from crypto_lab.domain.results import Failure
from crypto_lab.persistence.database import ConsistencyReport, SqliteDatabase
from crypto_lab.persistence.diagnostics import (
    INVARIANT_VIOLATION,
    STORAGE_UNAVAILABLE,
    WRITE_FAILED,
)
from crypto_lab.persistence.registries import (
    SqliteConfigurationSnapshotWriter,
    SqliteDiagnosticRecorder,
)
from crypto_lab.persistence.unit_of_work import SqliteTransaction
from doubles.experiments import (
    AVAIL_A,
    AVAIL_B,
    DIAG_ID,
    EXPERIMENT_ID,
    INSTANT,
    OTHER_DIAG_ID,
    OTHER_EXPERIMENT_ID,
    FixedClock,
    sample_diagnostic,
    sample_experiment,
    sample_observation,
)
from persistence_support.fixtures import other_config
from persistence_support.harness import (
    CountingUnitOfWork,
    SqliteHarness,
    code,
    commit,
    cursor_fault,
    ok,
    put_lifecycle_parents,
    sample_dataset_with_partitions,
    sample_strategy_version,
    sqlite_error,
)

_E: Final = ExperimentState
_SQLITE_IOERR: Final = 10
_SQLITE_FULL: Final = 13
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
#: The one permitted non-zero: the QUEUED parent inserted by ``add`` carries no
#: frozen snapshot (plan 4.6, reading 22).
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
#: ``(label, statement predicate for the member's own write, the call)``.
_MemberWrite = tuple[str, Callable[[str], bool], Callable[[SqliteTransaction], object]]


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


def _is_missing(value: object) -> bool:
    return value is MISSING


def _snapshot() -> ConfigSnapshot:
    return snapshot_configuration(ApplicationConfig())


def _owner() -> SystemArtifactOwner:
    return SystemArtifactOwner(
        owner_kind="SYSTEM", core_component="persistence", correlation_id="correction-a"
    )


def _is_update_of_experiments(statement: str) -> bool:
    return statement.startswith("UPDATE experiments")


def _is_insert(statement: str) -> bool:
    return statement.startswith("INSERT")


#: Every write method of the five members, each reached at its own statement.
_MEMBER_WRITES: tuple[_MemberWrite, ...] = (
    (
        "configuration_snapshots.freeze",
        _is_update_of_experiments,
        lambda transaction: transaction.configuration_snapshots.freeze(
            EXPERIMENT_ID, _snapshot()
        ),
    ),
    (
        "availability_observation_writer.add",
        _is_insert,
        lambda transaction: transaction.availability_observation_writer.add(
            sample_observation(AVAIL_B)
        ),
    ),
    (
        "strategy_versions.register",
        _is_insert,
        lambda transaction: transaction.strategy_versions.register(
            sample_strategy_version()
        ),
    ),
    (
        "datasets.register",
        _is_insert,
        lambda transaction: transaction.datasets.register(
            *sample_dataset_with_partitions()
        ),
    ),
    (
        # The descriptor row's INSERT has executed inside the savepoint; the
        # partition INSERT is refused, the savepoint is rolled back, the failure
        # names ``dataset_partitions`` and the transaction closes all the same.
        "datasets.register (partition insert)",
        lambda statement: statement.startswith("INSERT INTO dataset_partitions"),
        lambda transaction: transaction.datasets.register(
            *sample_dataset_with_partitions()
        ),
    ),
    (
        "artifact_owners.register",
        _is_insert,
        lambda transaction: transaction.artifact_owners.register(_owner()),
    ),
)
_MEMBER_IDS = [label for label, _, _ in _MEMBER_WRITES]


def _assert_closed_and_released_by_commit(
    harness: SqliteHarness,
    transaction: SqliteTransaction,
    refused: object,
    *,
    statements_issued: Callable[[], int],
) -> None:
    """Plan 4.2 after an I/O-class refusal: closed at once with the connection
    still owned; every later member call -- through a reference saved before the
    failure or a fresh one -- and ``commit()`` return the SAME stored ``Failure``
    without issuing a statement; ``commit()`` publishes nothing and releases;
    ``rollback()`` afterwards is a no-op."""
    database = harness.database
    assert transaction.open_failure() is refused
    assert harness.open_transactions() == (transaction,)
    assert _checked_out(database) == 1
    issued = statements_issued()
    assert transaction.experiments.get(EXPERIMENT_ID) is refused
    assert transaction.configuration_snapshots.get(EXPERIMENT_ID) is refused
    assert transaction.strategy_versions.get_by_hash("a" * 64) is refused
    assert transaction.datasets.list_partitions("ds_" + "0" * 36) is refused
    assert transaction.artifact_owners.get("a" * 64) is refused
    assert (
        transaction.availability_observation_writer.add(sample_observation(AVAIL_B))
        is refused
    )
    assert statements_issued() == issued
    assert transaction.commit() is refused
    assert harness.open_transactions() == ()
    assert _checked_out(database) == 0
    transaction.rollback()
    transaction.rollback()
    assert _checked_out(database) == 0
    assert harness.open_transactions() == ()


@pytest.mark.parametrize(("label", "when", "attempt"), _MEMBER_WRITES, ids=_MEMBER_IDS)
def test_a_members_io_class_write_failure_closes_the_transaction(
    sqlite_harness: SqliteHarness,
    monkeypatch: pytest.MonkeyPatch,
    label: str,
    when: Callable[[str], bool],
    attempt: Callable[[SqliteTransaction], object],
) -> None:
    """Each of the five members, refused at its own statement by ``SQLITE_FULL``:
    the transaction is closed exactly as a lifecycle repository closes it, saved
    references obey the closed state, and nothing of the method is durable."""
    put_lifecycle_parents(sqlite_harness, observation=True)
    database = sqlite_harness.database
    with cursor_fault(database, monkeypatch) as fault:
        transaction = sqlite_harness.unit_of_work().begin()
        saved_experiments = transaction.experiments
        saved_snapshots = transaction.configuration_snapshots
        fault.arm(sqlite_error(_SQLITE_FULL, "SQLITE_FULL"), when=when)
        refused = attempt(transaction)
        assert not fault.armed, (label, fault.passed)
        assert code(refused) == WRITE_FAILED
        assert _details(refused)["sqlite_errorcode"] == _SQLITE_FULL
        # References obtained before the failure cannot bypass the failed state.
        issued = len(fault.passed)
        assert saved_experiments.get(EXPERIMENT_ID) is refused
        assert saved_snapshots.freeze(EXPERIMENT_ID, _snapshot()) is refused
        assert attempt(transaction) is refused
        assert len(fault.passed) == issued
        _assert_closed_and_released_by_commit(
            sqlite_harness,
            transaction,
            refused,
            statements_issued=lambda: len(fault.passed),
        )
    # Nothing of the refused method survived; a new transaction reads normally.
    fresh = sqlite_harness.unit_of_work().begin()
    try:
        assert _is_missing(ok(fresh.configuration_snapshots.get(EXPERIMENT_ID)))
        assert code(fresh.availability_observations.get(AVAIL_B)) == INVARIANT_VIOLATION
        content_hash = sample_strategy_version().content_hash
        assert code(fresh.strategy_versions.get_by_hash(content_hash)) == (
            INVARIANT_VIOLATION
        )
        descriptor, _ = sample_dataset_with_partitions()
        assert code(fresh.datasets.get_by_hash(descriptor.content_hash)) == (
            INVARIANT_VIOLATION
        )
        assert code(fresh.artifact_owners.get("a" * 64)) == INVARIANT_VIOLATION
    finally:
        fresh.rollback()
    assert database.consistency_report() == _SCAFFOLDED_PARENT


def test_a_fatal_member_failure_after_a_provisional_write_publishes_nothing(
    sqlite_harness: SqliteHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The compound sequence: a valid provisional write, then a member's I/O-class
    refusal. Observed immediately after the call: closed, still registered and
    still holding its connection (plan 4.2: only the release lets go); the
    provisional row is unreadable even to its own transaction; ``commit()`` returns
    the stored failure, publishes nothing and releases once -- pool, root registry
    and the counting wrapper agree -- and an explicit ``rollback()`` releases
    nothing more."""
    put_lifecycle_parents(sqlite_harness)
    database = sqlite_harness.database
    root = sqlite_harness.unit_of_work()
    counting = CountingUnitOfWork(root)
    provisional = sample_experiment(_E.DRAFT, experiment_id=OTHER_EXPERIMENT_ID)
    with cursor_fault(database, monkeypatch) as fault:
        transaction = counting.begin()
        # The counting wrapper exposes the six port members; the five
        # persistence-owned members are reached on the owner it wraps.
        (owner,) = root.open_transactions()
        ok(transaction.experiments.add(provisional))
        assert ok(transaction.experiments.get(OTHER_EXPERIMENT_ID)) == provisional
        saved_experiments = transaction.experiments
        saved_snapshots = owner.configuration_snapshots
        saved_datasets = owner.datasets
        fault.arm(
            sqlite_error(_SQLITE_IOERR, "SQLITE_IOERR"), when=_is_update_of_experiments
        )
        refused = saved_snapshots.freeze(EXPERIMENT_ID, _snapshot())
        assert not fault.armed
        assert code(refused) == WRITE_FAILED
        assert _details(refused) == {
            "table": "experiments",
            "operation": "freeze",
            "identity": EXPERIMENT_ID,
            "sqlite_errorcode": _SQLITE_IOERR,
            "sqlite_errorname": "SQLITE_IOERR",
        }
        # Immediately after the call returned.
        assert owner.open_failure() is refused
        assert root.open_transactions() == (owner,)
        assert (counting.open_now, counting.max_open) == (1, 1)
        assert _checked_out(database) == 1
        # Saved references answer with the same object and issue no statement.
        issued = len(fault.passed)
        assert saved_experiments.get(OTHER_EXPERIMENT_ID) is refused
        assert saved_datasets.register(*sample_dataset_with_partitions()) is refused
        assert saved_snapshots.freeze(EXPERIMENT_ID, _snapshot()) is refused
        assert transaction.experiments.add(provisional) is refused
        assert len(fault.passed) == issued
        # The release: commit() publishes nothing; every bookkeeping agrees.
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
        assert _is_missing(ok(fresh.configuration_snapshots.get(EXPERIMENT_ID)))
    finally:
        fresh.rollback()
    assert database.consistency_report() == _SCAFFOLDED_PARENT
    # With the fault gone, a new transaction operates: the freeze now lands.
    later = sqlite_harness.unit_of_work().begin()
    ok(later.configuration_snapshots.freeze(EXPERIMENT_ID, _snapshot()))
    commit(later)
    reader = sqlite_harness.unit_of_work().begin()
    try:
        assert ok(reader.configuration_snapshots.get(EXPERIMENT_ID)) == _snapshot()
    finally:
        reader.rollback()
    assert database.consistency_report() == _CLEAN
    assert _checked_out(database) == 0


def test_the_lifecycle_and_member_paths_share_one_closing_rule(
    sqlite_harness: SqliteHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same owner mechanism, observed through the same assertions, for a
    lifecycle repository (``experiments.add``) and a persistence-owned member
    (``configuration_snapshots.freeze``)."""
    put_lifecycle_parents(sqlite_harness, observation=True)
    database = sqlite_harness.database
    other = sample_experiment(_E.DRAFT, experiment_id=OTHER_EXPERIMENT_ID)
    cases: tuple[
        tuple[Callable[[str], bool], Callable[[SqliteTransaction], object]], ...
    ] = (
        (_is_insert, lambda transaction: transaction.experiments.add(other)),
        (
            _is_update_of_experiments,
            lambda transaction: transaction.configuration_snapshots.freeze(
                EXPERIMENT_ID, _snapshot()
            ),
        ),
    )
    for when, attempt in cases:
        with cursor_fault(database, monkeypatch) as fault:
            transaction = sqlite_harness.unit_of_work().begin()
            fault.arm(sqlite_error(_SQLITE_IOERR, "SQLITE_IOERR"), when=when)
            refused = attempt(transaction)
            assert not fault.armed
            assert code(refused) == WRITE_FAILED
            _assert_closed_and_released_by_commit(
                sqlite_harness,
                transaction,
                refused,
                statements_issued=lambda: len(fault.passed),
            )
    assert sqlite_harness.committed_experiments() == (sample_experiment(_E.QUEUED),)
    assert database.consistency_report() == _SCAFFOLDED_PARENT


def test_nonfatal_member_refusals_leave_the_transaction_usable(
    sqlite_harness: SqliteHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Plan 4.2 unchanged for the other classes: an invariant refusal (a frozen
    snapshot re-frozen with different content) and an unclassified driver error
    (``PERSISTENCE.STORAGE_UNAVAILABLE``) abort their statement alone; the
    transaction continues, writes more and commits that later work."""
    put_lifecycle_parents(sqlite_harness)
    database = sqlite_harness.database
    first = sqlite_harness.unit_of_work().begin()
    ok(first.configuration_snapshots.freeze(EXPERIMENT_ID, _snapshot()))
    commit(first)
    transaction = sqlite_harness.unit_of_work().begin()
    invariant = transaction.configuration_snapshots.freeze(
        EXPERIMENT_ID, snapshot_configuration(other_config())
    )
    assert code(invariant) == INVARIANT_VIOLATION
    assert transaction.open_failure() is None
    with cursor_fault(database, monkeypatch) as fault:
        fault.arm(
            sqlite3.OperationalError("injected driver fault without a code"),
            when=_is_insert,
        )
        unavailable = transaction.strategy_versions.register(sample_strategy_version())
        assert not fault.armed
        assert code(unavailable) == STORAGE_UNAVAILABLE
        assert "sqlite_errorcode" not in _details(unavailable)
        assert transaction.open_failure() is None
    ok(transaction.availability_observation_writer.add(sample_observation(AVAIL_A)))
    assert ok(transaction.configuration_snapshots.get(EXPERIMENT_ID)) == _snapshot()
    commit(transaction)
    fresh = sqlite_harness.unit_of_work().begin()
    try:
        assert ok(fresh.availability_observations.get(AVAIL_A)) == sample_observation(
            AVAIL_A
        )
        content_hash = sample_strategy_version().content_hash
        assert code(fresh.strategy_versions.get_by_hash(content_hash)) == (
            INVARIANT_VIOLATION
        )
    finally:
        fresh.rollback()
    assert _checked_out(database) == 0
    assert database.consistency_report() == _CLEAN


def test_an_autonomous_diagnostic_survives_another_transactions_fatal_failure(
    sqlite_harness: SqliteHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The recorder commits in its own transaction (plan 4.4); a later fatal
    failure in a different transaction rolls back only that transaction, and the
    recorder keeps recording afterwards."""
    put_lifecycle_parents(sqlite_harness)
    database = sqlite_harness.database
    recorder = SqliteDiagnosticRecorder(database, clock=FixedClock(INSTANT))
    ok(recorder.record(sample_diagnostic(OTHER_DIAG_ID)))
    with cursor_fault(database, monkeypatch) as fault:
        transaction = sqlite_harness.unit_of_work().begin()
        fault.arm(
            sqlite_error(_SQLITE_IOERR, "SQLITE_IOERR"), when=_is_update_of_experiments
        )
        refused = transaction.configuration_snapshots.freeze(EXPERIMENT_ID, _snapshot())
        assert transaction.open_failure() is refused
        transaction.rollback()
        assert _checked_out(database) == 0
    ok(recorder.record(sample_diagnostic(DIAG_ID)))
    fresh = sqlite_harness.unit_of_work().begin()
    try:
        assert ok(fresh.diagnostics.get(OTHER_DIAG_ID)) == sample_diagnostic(
            OTHER_DIAG_ID
        )
        assert ok(fresh.diagnostics.get(DIAG_ID)) == sample_diagnostic(DIAG_ID)
    finally:
        fresh.rollback()
    assert database.consistency_report() == _SCAFFOLDED_PARENT


def test_a_standalone_registry_returns_the_failure_with_no_owner_to_close(
    sqlite_harness: SqliteHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Task 3's registries stay usable over a bare connection: constructed without a
    transaction they return the classified ``Failure`` and nothing else, and the
    connection is the caller's to roll back."""
    put_lifecycle_parents(sqlite_harness)
    database = sqlite_harness.database
    with (
        cursor_fault(database, monkeypatch) as fault,
        database.connection() as connection,
    ):
        writer = SqliteConfigurationSnapshotWriter(
            connection, clock=FixedClock(INSTANT)
        )
        fault.arm(
            sqlite_error(_SQLITE_FULL, "SQLITE_FULL"), when=_is_update_of_experiments
        )
        refused = writer.freeze(EXPERIMENT_ID, _snapshot())
        assert isinstance(refused, Failure)
        assert code(refused) == WRITE_FAILED
        assert _details(refused)["operation"] == "freeze"
        connection.rollback()
    assert _checked_out(database) == 0
    assert sqlite_harness.open_transactions() == ()
