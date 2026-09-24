"""The unit-of-work lifecycle over a real database (plan 4.2, Task 4).

The step table of plan section 4.2, case by case: what ``begin()`` returns on the
root and what it refuses on a transaction, which member access is a programmer
defect, what a commit publishes and a rollback discards, what a transaction whose
connection could never be checked out answers, and how an abandoned transaction
is reclaimed. Every case runs against the migrated file-backed database; nothing
here is satisfied by an in-memory store.
"""

from __future__ import annotations

import gc
from pathlib import Path

import pytest

from crypto_lab.adapters.ports import CommandInvocationRepository
from crypto_lab.artifacts.ownership import SystemArtifactOwner
from crypto_lab.configuration.models import ApplicationConfig
from crypto_lab.configuration.snapshot import snapshot_configuration
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.results import Success
from crypto_lab.experiments.ports import (
    DiagnosticReader,
    EngineRunRepository,
    ExperimentRepository,
    RetryDecisionRepository,
    RuntimeAvailabilityObservationReader,
    UnitOfWork,
)
from crypto_lab.persistence.database import SqliteDatabase
from crypto_lab.persistence.diagnostics import (
    INVARIANT_VIOLATION,
    STORAGE_UNAVAILABLE,
)
from crypto_lab.persistence.unit_of_work import SqliteTransaction, SqliteUnitOfWork
from doubles.experiments import (
    AVAIL_A,
    DIAG_ID,
    EXECUTABLE_HASH,
    EXPERIMENT_ID,
    INSTANT,
    INVOCATION_ID,
    RUN_ID,
    SLOT_A,
    FixedClock,
    sample_experiment,
    sample_invocation,
    sample_observation,
    sample_retry_decision,
    sample_run,
)
from persistence_support.harness import (
    SqliteHarness,
    accept_any_revision,
    bump,
    bump_invocation,
    bump_run,
    code,
    commit,
    ok,
    open_test_database,
    put_lifecycle_parents,
    sample_dataset_with_partitions,
    sample_run_event,
    sample_strategy_version,
)

_E = ExperimentState
_R = EngineRunState
_C = CommandInvocationState


def _single_connection_database(path: Path, clock: FixedClock) -> SqliteDatabase:
    """A second engine over the same migrated file whose pool holds one connection."""
    return ok(
        SqliteDatabase.open(
            path,
            busy_timeout_ms=100,
            clock=clock,
            revision_policy=accept_any_revision,
            pool_size=1,
            max_overflow=0,
            pool_timeout_seconds=0.1,
        )
    )


def test_the_root_holds_no_members_and_a_transaction_never_nests(
    sqlite_harness: SqliteHarness,
) -> None:
    root = sqlite_harness.unit_of_work()
    assert isinstance(root, UnitOfWork)
    # Reading 2: every one of the six port members is a defect on the root.
    for member in (
        "experiments",
        "engine_runs",
        "command_invocations",
        "retry_decisions",
        "availability_observations",
        "diagnostics",
    ):
        with pytest.raises(RuntimeError, match="active transaction"):
            getattr(root, member)
    with pytest.raises(RuntimeError, match="active transaction"):
        root.commit()
    # A root that never began releases nothing and never raises on rollback.
    root.rollback()
    transaction = root.begin()
    assert isinstance(transaction, UnitOfWork)
    assert isinstance(transaction, SqliteTransaction)
    with pytest.raises(RuntimeError, match="nested"):
        transaction.begin()
    transaction.rollback()


def test_a_closed_transaction_refuses_every_member_and_a_second_commit(
    sqlite_harness: SqliteHarness,
) -> None:
    transaction = sqlite_harness.unit_of_work().begin()
    commit(transaction)
    with pytest.raises(RuntimeError, match="closed"):
        transaction.commit()
    with pytest.raises(RuntimeError, match="closed"):
        _ = transaction.experiments
    with pytest.raises(RuntimeError, match="closed"):
        _ = transaction.configuration_snapshots
    # Rollback is idempotent before and after close, so a `finally` is safe.
    transaction.rollback()
    transaction.rollback()
    rolled_back = sqlite_harness.unit_of_work().begin()
    rolled_back.rollback()
    rolled_back.rollback()
    with pytest.raises(RuntimeError, match="closed"):
        rolled_back.commit()


def test_the_transaction_binds_the_six_ports_and_the_five_extra_members(
    sqlite_harness: SqliteHarness,
) -> None:
    transaction = sqlite_harness.unit_of_work().begin()
    assert isinstance(transaction.experiments, ExperimentRepository)
    assert isinstance(transaction.engine_runs, EngineRunRepository)
    assert isinstance(transaction.command_invocations, CommandInvocationRepository)
    assert isinstance(transaction.retry_decisions, RetryDecisionRepository)
    assert isinstance(
        transaction.availability_observations, RuntimeAvailabilityObservationReader
    )
    assert isinstance(transaction.diagnostics, DiagnosticReader)
    # Reading 11: the five persistence-owned members are extras on the concrete
    # transaction; the `UnitOfWork` protocol gains no member from them.
    assert code(transaction.configuration_snapshots.get(EXPERIMENT_ID)) == (
        INVARIANT_VIOLATION
    )
    assert code(transaction.strategy_versions.get_by_hash("a" * 64)) == (
        INVARIANT_VIOLATION
    )
    assert code(transaction.datasets.get_by_hash("a" * 64)) == INVARIANT_VIOLATION
    assert code(transaction.artifact_owners.get("a" * 64)) == INVARIANT_VIOLATION
    assert hasattr(transaction.availability_observation_writer, "add")
    transaction.rollback()


def test_the_extra_members_write_and_read_through_the_owning_transaction(
    sqlite_harness: SqliteHarness,
) -> None:
    """Reading 11: the five persistence-owned members run on the transaction's
    own connection and publish only when it commits."""
    put_lifecycle_parents(sqlite_harness)
    transaction = sqlite_harness.unit_of_work().begin()
    observation = sample_observation(AVAIL_A)
    ok(transaction.availability_observation_writer.add(observation))
    assert ok(transaction.availability_observations.get(AVAIL_A)) == observation
    assert ok(
        transaction.availability_observations.list_for_adapter(
            "adapter.alpha", "1.0.0", EXECUTABLE_HASH
        )
    ) == (observation,)
    version = sample_strategy_version()
    ok(transaction.strategy_versions.register(version))
    assert (
        ok(transaction.strategy_versions.get_by_hash(version.content_hash)) == version
    )
    descriptor, partitions = sample_dataset_with_partitions()
    ok(transaction.datasets.register(descriptor, partitions))
    assert ok(transaction.datasets.get_by_hash(descriptor.content_hash)) == descriptor
    assert ok(transaction.datasets.list_partitions(descriptor.dataset_id)) == partitions
    owner = SystemArtifactOwner(
        owner_kind="SYSTEM", core_component="persistence", correlation_id="task-four"
    )
    owner_hash = ok(transaction.artifact_owners.register(owner))
    assert ok(transaction.artifact_owners.get(owner_hash)) == owner
    snapshot = snapshot_configuration(ApplicationConfig())
    ok(transaction.configuration_snapshots.freeze(EXPERIMENT_ID, snapshot))
    assert ok(transaction.configuration_snapshots.get(EXPERIMENT_ID)) == snapshot
    commit(transaction)
    # A fresh unit of work sees every one of them.
    fresh = sqlite_harness.unit_of_work().begin()
    assert ok(fresh.configuration_snapshots.get(EXPERIMENT_ID)) == snapshot
    assert ok(fresh.strategy_versions.get_by_hash(version.content_hash)) == version
    assert ok(fresh.datasets.list_partitions(descriptor.dataset_id)) == partitions
    assert ok(fresh.artifact_owners.get(owner_hash)) == owner
    fresh.rollback()


def test_a_commit_publishes_and_a_rollback_discards_for_a_fresh_reader(
    sqlite_harness: SqliteHarness,
) -> None:
    stored = sample_experiment(_E.DRAFT)
    staged = sqlite_harness.unit_of_work().begin()
    ok(staged.experiments.add(stored))
    # A fresh unit of work sees nothing of an uncommitted write.
    peek = sqlite_harness.unit_of_work().begin()
    assert code(peek.experiments.get(EXPERIMENT_ID)) == INVARIANT_VIOLATION
    peek.rollback()
    commit(staged)
    fresh = sqlite_harness.unit_of_work().begin()
    assert ok(fresh.experiments.get(EXPERIMENT_ID)) == stored
    fresh.rollback()
    assert sqlite_harness.committed_experiments() == (stored,)
    discarded = sqlite_harness.unit_of_work().begin()
    ok(discarded.experiments.compare_and_swap(stored.revision, bump(stored)))
    discarded.rollback()
    assert sqlite_harness.committed_experiments() == (stored,)


def test_a_transaction_whose_connection_is_unavailable_answers_every_member(
    tmp_path: Path,
) -> None:
    """Plan 4.2: a checkout that cannot succeed leaves the transaction closed with
    ``PERSISTENCE.STORAGE_UNAVAILABLE``; every member call and ``commit()`` return
    it and only ``rollback()`` releases what was acquired."""
    clock = FixedClock(INSTANT)
    database = open_test_database(tmp_path, clock=clock)
    try:
        single = _single_connection_database(database.path, clock)
        try:
            holder = SqliteUnitOfWork(single, clock).begin()
            refused = SqliteUnitOfWork(single, clock).begin()
            # The one member this transaction cannot answer is the diagnostic
            # reader: a guarded wrapper would define both `get` and `get_many`
            # and become a sixth Stage 5 reader implementation, which plan 2.6
            # and acceptance criterion 12 pin at five. It is read-only. Checked
            # first, while the transaction is closed but not yet released, so
            # the refusal is the storage failure and not the release.
            assert refused.open_failure() is not None
            with pytest.raises(RuntimeError, match="closed"):
                _ = refused.diagnostics.get(DIAG_ID)
            for answer in (
                refused.experiments.get(EXPERIMENT_ID),
                refused.experiments.add(sample_experiment(_E.DRAFT)),
                refused.experiments.compare_and_swap(0, sample_experiment(_E.DRAFT)),
                refused.engine_runs.get(RUN_ID),
                refused.engine_runs.add_attempt(sample_run(_R.PENDING)),
                refused.engine_runs.compare_and_swap(
                    0, bump_run(sample_run(_R.PENDING), _R.VALIDATING)
                ),
                refused.engine_runs.count_attempts(EXPERIMENT_ID, SLOT_A),
                refused.engine_runs.latest_attempt(EXPERIMENT_ID, SLOT_A),
                refused.engine_runs.get_by_attempt_number(EXPERIMENT_ID, SLOT_A, 1),
                refused.engine_runs.append_event(sample_run_event(sequence=1)),
                refused.engine_runs.list_events(INVOCATION_ID),
                refused.command_invocations.get(INVOCATION_ID),
                refused.command_invocations.add(sample_invocation(_C.PENDING)),
                refused.command_invocations.compare_and_swap(
                    0, bump_invocation(sample_invocation(_C.PENDING), _C.STARTING)
                ),
                refused.command_invocations.list_for_run(RUN_ID, CommandKind.RUN),
                refused.retry_decisions.get_by_predecessor(SLOT_A, RUN_ID),
                refused.retry_decisions.insert_if_absent(sample_retry_decision()),
                refused.availability_observations.get(AVAIL_A),
                refused.availability_observations.list_for_adapter(
                    "adapter.alpha", "1.0.0", EXECUTABLE_HASH
                ),
                refused.availability_observation_writer.add(
                    sample_observation(AVAIL_A)
                ),
                refused.configuration_snapshots.get(EXPERIMENT_ID),
                refused.configuration_snapshots.freeze(
                    EXPERIMENT_ID, snapshot_configuration(ApplicationConfig())
                ),
                refused.strategy_versions.get_by_hash("a" * 64),
                refused.strategy_versions.register(sample_strategy_version()),
                refused.datasets.get_by_hash("a" * 64),
                refused.datasets.list_partitions("ds_" + "0" * 36),
                refused.datasets.register(*sample_dataset_with_partitions()),
                refused.artifact_owners.get("a" * 64),
                refused.artifact_owners.register(
                    SystemArtifactOwner(
                        owner_kind="SYSTEM",
                        core_component="persistence",
                        correlation_id="task-four",
                    )
                ),
                refused.commit(),
            ):
                assert code(answer) == STORAGE_UNAVAILABLE
            refused.rollback()
            with pytest.raises(RuntimeError, match="closed"):
                refused.commit()
            holder.rollback()
        finally:
            single.close()
    finally:
        database.close()


def test_the_harness_rolls_back_a_transaction_a_test_abandoned(
    tmp_path: Path, fixed_clock: FixedClock
) -> None:
    harness = SqliteHarness(open_test_database(tmp_path, clock=fixed_clock))
    dangling = harness.unit_of_work().begin()
    ok(dangling.experiments.add(sample_experiment(_E.DRAFT)))
    assert harness.open_transactions() == (dangling,)
    del dangling
    harness.close()
    reopened = open_test_database(tmp_path, clock=fixed_clock)
    try:
        assert SqliteHarness(reopened).committed_experiments() == ()
    finally:
        reopened.close()


def test_an_abandoned_transaction_is_reclaimed_after_a_collection(
    tmp_path: Path, fixed_clock: FixedClock
) -> None:
    """Plan 2.8: the pool's finalizer rolls an abandoned transaction back and
    returns its connection once the cyclic collector has run; no test relies on
    it, and this probe is the measurement."""
    database = open_test_database(tmp_path, clock=fixed_clock)
    try:
        single = _single_connection_database(database.path, fixed_clock)
        try:
            unit = SqliteUnitOfWork(single, fixed_clock)
            abandoned = unit.begin()
            ok(abandoned.experiments.add(sample_experiment(_E.DRAFT)))
            exhausted = SqliteUnitOfWork(single, fixed_clock).begin()
            assert code(exhausted.commit()) == STORAGE_UNAVAILABLE
            exhausted.rollback()
            del abandoned
            del unit
            del exhausted
            gc.collect()
            reclaimed = SqliteUnitOfWork(single, fixed_clock).begin()
            # The connection came back and the abandoned insert never committed.
            assert code(reclaimed.experiments.get(EXPERIMENT_ID)) == (
                INVARIANT_VIOLATION
            )
            committed = reclaimed.commit()
            assert isinstance(committed, Success)
        finally:
            single.close()
    finally:
        database.close()


def test_a_committed_transaction_returns_its_connection_for_the_next_one(
    tmp_path: Path, fixed_clock: FixedClock
) -> None:
    """Connection hygiene: a pool of one serves an unbounded run of transactions
    because each ``commit()`` and each ``rollback()`` returns its connection."""
    database = open_test_database(tmp_path, clock=fixed_clock)
    try:
        single = _single_connection_database(database.path, fixed_clock)
        try:
            root = SqliteUnitOfWork(single, fixed_clock)
            for _ in range(4):
                transaction = root.begin()
                assert code(transaction.experiments.get(EXPERIMENT_ID)) == (
                    INVARIANT_VIOLATION
                )
                commit(transaction)
            for _ in range(4):
                transaction = root.begin()
                transaction.rollback()
            assert root.open_transactions() == ()
        finally:
            single.close()
    finally:
        database.close()
