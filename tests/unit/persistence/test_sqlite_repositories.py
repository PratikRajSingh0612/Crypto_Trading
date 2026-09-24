"""The four lifecycle repositories over the migrated schema (plan 4.3, Task 4).

The compare-and-swap precedence of plan 4.3.1 walked step by step against each of
the three repositories, the experiment-scoped slot identity of reading 7, the
savepoint rule of reading 21, the queue-edge freeze of reading 22, and the
serialized-writer replacements for the two interleavings one SQLite writer makes
unconstructible: cases C-1 to C-4, C-9, C-28, C-29 (a) and (b), C-30 and the
Task 4 half of C-32. Every case runs against the file-backed migrated database
through ``sqlite_harness``; durable visibility is always read through a fresh
unit of work or the harness's own read-only session, never through the writer's.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from crypto_lab.configuration.models import ApplicationConfig
from crypto_lab.configuration.snapshot import snapshot_configuration
from crypto_lab.domain.engine_run import EngineRunRecord
from crypto_lab.domain.experiment import (
    ExperimentRecord,
    ExperimentSpec,
    experiment_spec_hash,
)
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.results import Failure, Success
from crypto_lab.persistence.codecs import encode_engine_slots
from crypto_lab.persistence.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
)
from crypto_lab.persistence.schema import EngineSlotRow
from doubles.experiments import (
    EXPERIMENT_ID,
    INSTANT,
    INVOCATION_ID,
    OTHER_EXPERIMENT_ID,
    OTHER_INVOCATION_ID,
    OTHER_RUN_ID,
    RUN_ID,
    SLOT_A,
    SLOT_B,
    SLOT_C,
    UUID_C,
    UUID_D,
    sample_experiment,
    sample_invocation,
    sample_retry_decision,
    sample_run,
)
from persistence_support.fixtures import (
    ADAPTER_GAMMA,
    ENGINE_GAMMA,
    config_backed_spec,
    other_config,
    other_slots_spec,
    other_spec,
    three_slot_experiment,
)
from persistence_support.harness import (
    CAS_SUBJECTS,
    CasSubject,
    SqliteHarness,
    bump,
    bump_run,
    code,
    commit,
    install_ignoring_update_trigger,
    install_refusing_slot_trigger,
    ok,
    put_experiment,
    put_lifecycle_parents,
    put_run,
    raw_connection,
)

_E = ExperimentState
_R = EngineRunState
_C = CommandInvocationState
_K = CommandKind


# --------------------------------------------------------------------------
# Module-local helpers (plan 7.1: named by the sketches, promoted by no task)
# --------------------------------------------------------------------------


def slot_rows(harness: SqliteHarness) -> tuple[dict[str, object], ...]:
    """Every ``engine_slots`` row, ordered by its composite primary key."""
    statement = select(EngineSlotRow).order_by(
        EngineSlotRow.experiment_id, EngineSlotRow.logical_slot_id
    )
    with harness.database.read_only() as connection:
        return tuple(
            {str(key): value for key, value in row.items()}
            for row in connection.execute(statement).mappings().all()
        )


def expected_slot_rows(*records: ExperimentRecord) -> tuple[dict[str, object], ...]:
    """The projection those experiments' specs require, in the stored order."""
    projected: list[dict[str, object]] = [
        dict(row) for record in records for row in encode_engine_slots(record)
    ]
    return tuple(
        sorted(
            projected,
            key=lambda row: (str(row["experiment_id"]), str(row["logical_slot_id"])),
        )
    )


def _with_spec(record: ExperimentRecord, spec: ExperimentSpec) -> ExperimentRecord:
    # A changed spec carries its recomputed identity through the canonical helper.
    return record.model_copy(
        update={"spec": spec, "spec_hash": experiment_spec_hash(spec)}
    )


def _clean_projection(harness: SqliteHarness) -> None:
    """The two counts the repositories govern stay zero after every write."""
    report = harness.database.consistency_report()
    assert report.slot_identity_mismatches == 0
    assert report.spec_projection_mismatches == 0


def _message(result: object) -> str:
    """The message of the single diagnostic of a ``Failure``."""
    assert isinstance(result, Failure), result
    assert len(result.diagnostics) == 1
    return result.diagnostics[0].message


def _sqlite_errorcode(result: object) -> object:
    """The SQLite result code a refused statement's diagnostic carries."""
    assert isinstance(result, Failure), result
    return result.diagnostics[0].details["sqlite_errorcode"]


def _row_count(harness: SqliteHarness, table: str) -> int:
    """A row count through an independent stdlib connection on the same file."""
    assert table in {"retry_decisions", "engine_runs", "experiments"}
    connection = raw_connection(harness.database.path)
    try:
        return int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0])  # noqa: S608
    finally:
        connection.close()


# --------------------------------------------------------------------------
# Serialized-writer replacements for the two-open-writer interleavings
# --------------------------------------------------------------------------


def test_a_refused_write_leaves_the_transaction_usable(
    sqlite_harness: SqliteHarness,
) -> None:
    stored = sample_experiment(_E.DRAFT)
    put_experiment(sqlite_harness, stored)
    loser = sqlite_harness.unit_of_work().begin()
    assert ok(loser.experiments.get(EXPERIMENT_ID)) == stored
    winner = sqlite_harness.unit_of_work().begin()
    ok(winner.experiments.compare_and_swap(stored.revision, bump(stored)))
    commit(winner)
    refused = loser.experiments.compare_and_swap(stored.revision, bump(stored))
    assert code(refused) == CONCURRENCY_CONFLICT
    # The statement was aborted, not the transaction: reads still answer from
    # the snapshot and a commit publishes nothing.
    assert ok(loser.experiments.get(EXPERIMENT_ID)) == stored
    commit(loser)
    assert sqlite_harness.committed_experiments() == (bump(stored),)


def test_concurrent_creation_of_one_identity_refuses_the_later_writer(
    sqlite_harness: SqliteHarness,
) -> None:
    first = sqlite_harness.unit_of_work().begin()
    second = sqlite_harness.unit_of_work().begin()
    ok(first.experiments.add(sample_experiment(_E.DRAFT)))
    commit(first)
    lost = second.experiments.add(sample_experiment(_E.VALIDATED))
    assert code(lost) == CONCURRENCY_CONFLICT
    commit(second)
    assert sqlite_harness.committed_experiments() == (sample_experiment(_E.DRAFT),)


def test_the_attempt_key_refuses_a_second_attempt_one_from_another_connection(
    sqlite_harness: SqliteHarness,
) -> None:
    """C-2: a loser that read the slot before the winner committed is refused by
    the snapshot rule; a loser that had not read is refused by the three-field
    unique key. Both are the same conflict, and neither row is written."""
    put_lifecycle_parents(sqlite_harness)
    first = sqlite_harness.unit_of_work().begin()
    second = sqlite_harness.unit_of_work().begin()
    assert ok(second.engine_runs.count_attempts(EXPERIMENT_ID, SLOT_A)) == 0
    ok(first.engine_runs.add_attempt(sample_run(_R.PENDING)))
    commit(first)
    lost = second.engine_runs.add_attempt(sample_run(_R.PENDING, run_id=OTHER_RUN_ID))
    assert code(lost) == CONCURRENCY_CONFLICT
    second.rollback()
    unread = sqlite_harness.unit_of_work().begin()
    late = unread.engine_runs.add_attempt(sample_run(_R.PENDING, run_id=OTHER_RUN_ID))
    assert code(late) == CONCURRENCY_CONFLICT
    unread.rollback()
    assert sqlite_harness.committed_engine_runs() == (sample_run(_R.PENDING),)


def test_the_open_invocation_index_holds_across_connections(
    sqlite_harness: SqliteHarness,
) -> None:
    """C-3: one open VALIDATE per run survives a second connection, while a
    terminal same-kind row and two DESCRIBEs are admitted."""
    put_lifecycle_parents(sqlite_harness, run=True)
    first = sqlite_harness.unit_of_work().begin()
    ok(first.command_invocations.add(sample_invocation(_C.PENDING, kind=_K.VALIDATE)))
    commit(first)
    second = sqlite_harness.unit_of_work().begin()
    lost = second.command_invocations.add(
        sample_invocation(
            _C.PENDING, kind=_K.VALIDATE, invocation_id=OTHER_INVOCATION_ID
        )
    )
    assert code(lost) == CONCURRENCY_CONFLICT
    second.rollback()
    admitted = sqlite_harness.unit_of_work().begin()
    for record in (
        sample_invocation(
            _C.EXITED, kind=_K.VALIDATE, invocation_id=OTHER_INVOCATION_ID
        ),
        sample_invocation(_C.PENDING, kind=_K.DESCRIBE, invocation_id=f"inv_{UUID_C}"),
        sample_invocation(_C.PENDING, kind=_K.DESCRIBE, invocation_id=f"inv_{UUID_D}"),
    ):
        ok(admitted.command_invocations.add(record))
    commit(admitted)
    assert len(sqlite_harness.committed_command_invocations()) == 4


def test_a_moved_row_refuses_the_stale_compare_and_swap_at_the_call(
    sqlite_harness: SqliteHarness,
) -> None:
    """C-4: the loser's pre-read still sees the stored revision from its own
    snapshot, so steps b to d pass and the conditional update is refused at
    step f by the snapshot rule -- at the call, never first at ``commit()``."""
    stored = sample_experiment(_E.DRAFT)
    put_experiment(sqlite_harness, stored)
    loser = sqlite_harness.unit_of_work().begin()
    assert ok(loser.experiments.get(EXPERIMENT_ID)) == stored
    winner = sqlite_harness.unit_of_work().begin()
    ok(winner.experiments.compare_and_swap(stored.revision, bump(stored)))
    commit(winner)
    refused = loser.experiments.compare_and_swap(stored.revision, bump(stored))
    assert code(refused) == CONCURRENCY_CONFLICT
    assert _sqlite_errorcode(refused) == 517
    loser.rollback()
    assert sqlite_harness.committed_experiments() == (bump(stored),)


# --------------------------------------------------------------------------
# The slot projection, the frozen spec and the experiment-scoped identity
# --------------------------------------------------------------------------


def test_the_slot_projection_agrees_with_the_spec_after_every_write(
    sqlite_harness: SqliteHarness,
) -> None:
    experiment = sample_experiment(_E.DRAFT)
    put_experiment(sqlite_harness, experiment)
    assert slot_rows(sqlite_harness) == expected_slot_rows(experiment)
    # other_slots_spec() changes the slot set (plan 7.1), so an untouched
    # projection would be visibly wrong; the DRAFT record carries no
    # slot_compatibility.
    replaced = bump(_with_spec(experiment, other_slots_spec()))
    transaction = sqlite_harness.unit_of_work().begin()
    ok(transaction.experiments.compare_and_swap(experiment.revision, replaced))
    commit(transaction)
    assert slot_rows(sqlite_harness) == expected_slot_rows(replaced)
    _clean_projection(sqlite_harness)


def test_a_frozen_spec_cannot_change_after_queued(
    sqlite_harness: SqliteHarness,
) -> None:
    queued = sample_experiment(_E.QUEUED)
    put_experiment(sqlite_harness, queued)
    transaction = sqlite_harness.unit_of_work().begin()
    # other_spec() changes a non-slot field (plan 7.1), so the QUEUED record's
    # slot_compatibility still validates and the repository guard is reached.
    refused = transaction.experiments.compare_and_swap(
        queued.revision, bump(_with_spec(queued, other_spec()))
    )
    assert code(refused) == INVARIANT_VIOLATION
    transaction.rollback()
    assert sqlite_harness.committed_experiments() == (queued,)
    assert slot_rows(sqlite_harness) == expected_slot_rows(queued)


def test_slot_identity_is_scoped_by_its_experiment(
    sqlite_harness: SqliteHarness,
) -> None:
    first = sample_experiment(_E.QUEUED)
    second = three_slot_experiment(_E.QUEUED, experiment_id=OTHER_EXPERIMENT_ID)
    put_experiment(sqlite_harness, first)
    put_experiment(
        sqlite_harness, second
    )  # A: SLOT_A/SLOT_B twice, SLOT_C (gamma pair) once
    # E1's first attempt is terminal, so in B only the three-field UNIQUE can
    # refuse the duplicate (the active-attempt partial index admits a new row).
    put_run(sqlite_harness, sample_run(_R.FAILED, observed=False))
    put_run(
        sqlite_harness,
        sample_run(_R.PENDING, run_id=OTHER_RUN_ID, experiment_id=OTHER_EXPERIMENT_ID),
    )  # A: same slot and attempt number under another experiment
    transaction = sqlite_harness.unit_of_work().begin()
    duplicate = transaction.engine_runs.add_attempt(
        sample_run(_R.PENDING, run_id=f"run_{UUID_C}")
    )
    assert code(duplicate) == CONCURRENCY_CONFLICT  # B: full three-field identity
    # SLOT_C exists only under OTHER_EXPERIMENT_ID (three_slot_draft, plan 7.1.1);
    # the run is shape-valid -- its adapter and engine are the slot row's -- so
    # only the composite foreign key (experiment half mismatched) can refuse it.
    foreign_slot = transaction.engine_runs.add_attempt(
        sample_run(
            _R.PENDING,
            run_id=f"run_{UUID_D}",
            logical_slot_id=SLOT_C,
            adapter=ADAPTER_GAMMA,
            engine=ENGINE_GAMMA,
        )
    )
    assert code(foreign_slot) == INVARIANT_VIOLATION  # C: composite foreign key
    control = transaction.engine_runs.add_attempt(
        sample_run(
            _R.PENDING,
            run_id=f"run_{UUID_D}",
            experiment_id=OTHER_EXPERIMENT_ID,
            logical_slot_id=SLOT_C,
            adapter=ADAPTER_GAMMA,
            engine=ENGINE_GAMMA,
        )
    )
    assert isinstance(control, Success)  # C: the same slot under its own experiment
    transaction.rollback()
    assert len(sqlite_harness.committed_engine_runs()) == 2
    assert slot_rows(sqlite_harness) == expected_slot_rows(first, second)
    _clean_projection(sqlite_harness)


# --------------------------------------------------------------------------
# C-30: the compare-and-swap precedence of plan 4.3.1, per repository
# --------------------------------------------------------------------------


@pytest.mark.parametrize("subject", CAS_SUBJECTS, ids=lambda s: s.name)
def test_compare_and_swap_refuses_missing_then_stale_then_step_in_order(
    sqlite_harness: SqliteHarness, subject: CasSubject
) -> None:
    subject.seed_parents(sqlite_harness)
    stored = subject.record()
    subject.put(sqlite_harness, stored)
    transaction = sqlite_harness.unit_of_work().begin()
    repository = getattr(transaction, subject.member)
    absent = subject.rekey(stored)
    # missing + wrong step -> conflict: step b decides before step d
    missing_row = repository.compare_and_swap(0, subject.bump(absent))
    assert code(missing_row) == CONCURRENCY_CONFLICT
    # Step b's own zero-row vocabulary, not the `get` miss (plan 4.3.1 b).
    assert "does not exist for compare-and-swap" in _message(missing_row)
    # Reading 4: a missing identity on `get` is the invariant and says so.
    absent_read = repository.get(subject.identity(absent))
    assert code(absent_read) == INVARIANT_VIOLATION
    assert "does not exist" in _message(absent_read)
    # stale + wrong step -> conflict: step c decides before step d
    stale = repository.compare_and_swap(stored.revision + 5, subject.bump(stored))
    assert code(stale) == CONCURRENCY_CONFLICT
    # matching + wrong step -> invariant, nothing written
    skipped = subject.bump(subject.bump(stored))
    assert (
        code(repository.compare_and_swap(stored.revision, skipped))
        == INVARIANT_VIOLATION
    )
    assert ok(repository.get(subject.identity(stored))) == stored
    # matching + valid step -> provisional success: this transaction sees it,
    # a fresh reader does not until commit
    swapped = ok(repository.compare_and_swap(stored.revision, subject.bump(stored)))
    assert swapped == subject.bump(stored)
    assert ok(repository.get(subject.identity(stored))) == swapped
    fresh = sqlite_harness.unit_of_work().begin()
    assert ok(getattr(fresh, subject.member).get(subject.identity(stored))) == stored
    fresh.rollback()
    transaction.rollback()
    assert subject.committed(sqlite_harness) == (stored,)


@pytest.mark.parametrize("subject", CAS_SUBJECTS, ids=lambda s: s.name)
def test_compare_and_swap_observes_this_transactions_earlier_writes(
    sqlite_harness: SqliteHarness, subject: CasSubject
) -> None:
    subject.seed_parents(sqlite_harness)
    record = subject.record()
    transaction = sqlite_harness.unit_of_work().begin()
    repository = getattr(transaction, subject.member)
    ok(subject.insert(repository, record))  # uncommitted; visible to the pre-read
    first = ok(repository.compare_and_swap(record.revision, subject.bump(record)))
    # The pre-read now sees this transaction's own swap: the same expected
    # revision is stale (step c), and nothing is written.
    again = repository.compare_and_swap(record.revision, subject.bump(record))
    assert code(again) == CONCURRENCY_CONFLICT
    second = ok(repository.compare_and_swap(first.revision, subject.bump(first)))
    assert ok(repository.get(subject.identity(record))) == second
    transaction.rollback()
    assert subject.committed(sqlite_harness) == ()


def test_a_zero_row_conditional_update_is_a_conflict_after_the_checks(
    sqlite_harness: SqliteHarness,
) -> None:
    put_lifecycle_parents(sqlite_harness, run=True)
    stored_run = sample_run(_R.PENDING)
    install_ignoring_update_trigger(
        sqlite_harness.database, "engine_runs", "run_id", RUN_ID
    )
    transaction = sqlite_harness.unit_of_work().begin()
    refused = transaction.engine_runs.compare_and_swap(
        stored_run.revision, bump_run(stored_run, _R.VALIDATING)
    )
    # Steps a-d passed (row present, revision matches, step valid); the UPDATE
    # touched no row, which is step f's conflict, not an invariant.
    assert code(refused) == CONCURRENCY_CONFLICT
    assert ok(transaction.engine_runs.get(RUN_ID)) == stored_run
    commit(transaction)
    assert sqlite_harness.committed_engine_runs() == (stored_run,)


@pytest.mark.parametrize(
    ("member", "identity_column", "identity"),
    [
        pytest.param("experiments", "experiment_id", EXPERIMENT_ID, id="experiments"),
        pytest.param(
            "command_invocations",
            "invocation_id",
            INVOCATION_ID,
            id="command_invocations",
        ),
    ],
)
def test_a_zero_row_conditional_update_is_a_conflict_for_every_repository(
    sqlite_harness: SqliteHarness,
    member: str,
    identity_column: str,
    identity: str,
) -> None:
    """The plan 4.3.1 step f rowcount branch of the other two repositories.

    The sketch above walks it for ``engine_runs``; each repository owns its own
    conditional update, so each needs the ignoring trigger pointed at its table.
    """
    subject = next(item for item in CAS_SUBJECTS if item.member == member)
    subject.seed_parents(sqlite_harness)
    stored = subject.record()
    subject.put(sqlite_harness, stored)
    install_ignoring_update_trigger(
        sqlite_harness.database, member, identity_column, identity
    )
    transaction = sqlite_harness.unit_of_work().begin()
    repository = getattr(transaction, member)
    refused = repository.compare_and_swap(stored.revision, subject.bump(stored))
    # Steps a-d' passed; the UPDATE touched no row, which is the conflict.
    assert code(refused) == CONCURRENCY_CONFLICT
    assert ok(repository.get(identity)) == stored
    commit(transaction)
    assert subject.committed(sqlite_harness) == (stored,)


# --------------------------------------------------------------------------
# C-32 (Task 4 half): the queue edge requires an agreeing frozen snapshot
# --------------------------------------------------------------------------


def test_queueing_requires_a_frozen_snapshot_that_agrees_with_the_spec(
    sqlite_harness: SqliteHarness,
) -> None:
    config = ApplicationConfig()
    validated = _with_spec(sample_experiment(_E.VALIDATED), config_backed_spec(config))
    put_experiment(sqlite_harness, validated)
    queued = _with_spec(
        sample_experiment(_E.QUEUED, revision=validated.revision + 1),
        config_backed_spec(config),
    )
    transaction = sqlite_harness.unit_of_work().begin()
    unfrozen = transaction.experiments.compare_and_swap(validated.revision, queued)
    assert code(unfrozen) == INVARIANT_VIOLATION  # step d': no frozen snapshot
    assert ok(transaction.experiments.get(EXPERIMENT_ID)) == validated
    snapshots = transaction.configuration_snapshots
    ok(snapshots.freeze(EXPERIMENT_ID, snapshot_configuration(other_config())))
    disagreeing = transaction.experiments.compare_and_swap(validated.revision, queued)
    assert code(disagreeing) == INVARIANT_VIOLATION  # step d': hash and policy differ
    ok(
        snapshots.freeze(EXPERIMENT_ID, snapshot_configuration(config))
    )  # pre-QUEUED replace
    assert (
        ok(transaction.experiments.compare_and_swap(validated.revision, queued))
        == queued
    )
    commit(transaction)
    later = sqlite_harness.unit_of_work().begin()
    assert ok(
        later.configuration_snapshots.get(EXPERIMENT_ID)
    ) == snapshot_configuration(config)
    refrozen = later.configuration_snapshots.freeze(
        EXPERIMENT_ID, snapshot_configuration(other_config())
    )
    assert code(refrozen) == INVARIANT_VIOLATION  # frozen at QUEUED
    later.rollback()
    assert sqlite_harness.committed_experiments() == (queued,)


# --------------------------------------------------------------------------
# C-29: a multi-statement method rolls back to its own savepoint
# --------------------------------------------------------------------------


def test_a_multi_statement_method_rolls_back_to_its_savepoint(
    sqlite_harness: SqliteHarness,
) -> None:
    install_refusing_slot_trigger(sqlite_harness.database, SLOT_B)
    transaction = sqlite_harness.unit_of_work().begin()
    refused = transaction.experiments.add(sample_experiment(_E.DRAFT))
    assert code(refused) == INVARIANT_VIOLATION
    # The experiment row inserted before the refused slot is gone with it.
    assert code(transaction.experiments.get(EXPERIMENT_ID)) == INVARIANT_VIOLATION
    commit(transaction)
    assert sqlite_harness.committed_experiments() == ()
    assert slot_rows(sqlite_harness) == ()


def test_a_refused_slot_reinsert_leaves_the_stored_experiment_untouched(
    sqlite_harness: SqliteHarness,
) -> None:
    """C-29 (b): the savepoint the pre-``QUEUED`` spec change enters at step e
    rolls the conditional update back with the refused reinsert."""
    stored = sample_experiment(_E.DRAFT)
    put_experiment(sqlite_harness, stored)
    before = slot_rows(sqlite_harness)
    install_refusing_slot_trigger(sqlite_harness.database, SLOT_C)
    replaced = bump(_with_spec(stored, other_slots_spec()))
    transaction = sqlite_harness.unit_of_work().begin()
    refused = transaction.experiments.compare_and_swap(stored.revision, replaced)
    assert code(refused) == INVARIANT_VIOLATION
    assert ok(transaction.experiments.get(EXPERIMENT_ID)) == stored
    commit(transaction)
    assert sqlite_harness.committed_experiments() == (stored,)
    assert slot_rows(sqlite_harness) == before
    _clean_projection(sqlite_harness)


# --------------------------------------------------------------------------
# The remaining plan 4.3 rows: reads, ordering, replay and the trigger refusals
# --------------------------------------------------------------------------


def test_the_attempt_queries_count_this_transactions_staged_rows(
    sqlite_harness: SqliteHarness,
) -> None:
    put_lifecycle_parents(sqlite_harness, observation=True)
    transaction = sqlite_harness.unit_of_work().begin()
    assert ok(transaction.engine_runs.count_attempts(EXPERIMENT_ID, SLOT_A)) == 0
    assert not isinstance(
        ok(transaction.engine_runs.latest_attempt(EXPERIMENT_ID, SLOT_A)),
        EngineRunRecord,
    )
    initial = sample_run(_R.FAILED)
    successor = sample_run(_R.PENDING, run_id=OTHER_RUN_ID, attempt_number=2)
    ok(transaction.engine_runs.add_attempt(initial))
    ok(transaction.engine_runs.add_attempt(successor))
    # Staged rows count and answer inside the transaction that wrote them.
    assert ok(transaction.engine_runs.count_attempts(EXPERIMENT_ID, SLOT_A)) == 2
    assert ok(transaction.engine_runs.latest_attempt(EXPERIMENT_ID, SLOT_A)) == (
        successor
    )
    assert (
        ok(transaction.engine_runs.get_by_attempt_number(EXPERIMENT_ID, SLOT_A, 1))
        == initial
    )
    assert not isinstance(
        ok(transaction.engine_runs.get_by_attempt_number(EXPERIMENT_ID, SLOT_A, 3)),
        EngineRunRecord,
    )
    # A fresh reader counts none of them until the commit.
    fresh = sqlite_harness.unit_of_work().begin()
    assert ok(fresh.engine_runs.count_attempts(EXPERIMENT_ID, SLOT_A)) == 0
    fresh.rollback()
    commit(transaction)
    assert len(sqlite_harness.committed_engine_runs()) == 2


def test_list_for_run_is_ordered_by_creation_then_identifier_over_permutations(
    sqlite_harness: SqliteHarness,
) -> None:
    put_lifecycle_parents(sqlite_harness, run=True)
    early = sample_invocation(
        _C.EXITED,
        invocation_id=f"inv_{UUID_C}",
        created_at_utc=INSTANT - timedelta(hours=2),
    )
    middle_low = sample_invocation(
        _C.CANCELLED,
        invocation_id=INVOCATION_ID,
        created_at_utc=INSTANT - timedelta(hours=1),
    )
    middle_high = sample_invocation(
        _C.TIMED_OUT,
        invocation_id=OTHER_INVOCATION_ID,
        created_at_utc=INSTANT - timedelta(hours=1),
    )
    latest = sample_invocation(_C.PENDING, invocation_id=f"inv_{UUID_D}")
    transaction = sqlite_harness.unit_of_work().begin()
    for record in (latest, middle_high, early, middle_low):
        ok(transaction.command_invocations.add(record))
    listed = ok(transaction.command_invocations.list_for_run(RUN_ID, _K.RUN))
    assert type(listed) is tuple
    assert listed == (early, middle_low, middle_high, latest)
    assert ok(transaction.command_invocations.list_for_run(OTHER_RUN_ID, _K.RUN)) == ()
    transaction.rollback()


def test_insert_if_absent_returns_the_stored_winner_without_writing(
    sqlite_harness: SqliteHarness,
) -> None:
    """C-9: the sequential replay returns the durable row and writes nothing."""
    put_lifecycle_parents(sqlite_harness, run=True)
    candidate = sample_retry_decision()
    first = sqlite_harness.unit_of_work().begin()
    inserted = ok(first.retry_decisions.insert_if_absent(candidate))
    assert inserted.inserted is True
    commit(first)
    second = sqlite_harness.unit_of_work().begin()
    replayed = ok(second.retry_decisions.insert_if_absent(candidate))
    assert replayed.inserted is False
    assert replayed.record == candidate
    assert ok(second.retry_decisions.get_by_predecessor(SLOT_A, RUN_ID)) == candidate
    # Reading 4: the decision reader's own miss is the invariant and says so.
    absent_decision = second.retry_decisions.get_by_predecessor(SLOT_B, OTHER_RUN_ID)
    assert code(absent_decision) == INVARIANT_VIOLATION
    assert "does not exist" in _message(absent_decision)
    commit(second)
    assert sqlite_harness.committed_retry_decisions() == (candidate,)
    assert _row_count(sqlite_harness, "retry_decisions") == 1


def test_a_terminal_run_refuses_the_repository_compare_and_swap(
    sqlite_harness: SqliteHarness,
) -> None:
    """The T-RUN-TERMINAL trigger reached through the port: an invariant at the
    conditional update, with the stored row unchanged."""
    put_lifecycle_parents(sqlite_harness, observation=True)
    terminal = sample_run(_R.FAILED)
    put_run(sqlite_harness, terminal)
    transaction = sqlite_harness.unit_of_work().begin()
    refused = transaction.engine_runs.compare_and_swap(
        terminal.revision, bump_run(terminal, _R.FAILED)
    )
    assert code(refused) == INVARIANT_VIOLATION
    assert ok(transaction.engine_runs.get(terminal.run_id)) == terminal
    commit(transaction)
    assert sqlite_harness.committed_engine_runs() == (terminal,)


def test_a_record_with_no_column_for_a_field_maps_to_an_invariant(
    sqlite_harness: SqliteHarness,
) -> None:
    """Rule N4 at the repository boundary.

    The committed ``EngineRunRecord`` validator forces
    ``finalization_deadline_utc`` absent, so no canonical input reaches this
    branch; the records below are built with ``model_construct``, which bypasses
    validation, to cover the repository's mapping of the codec's one documented
    ``ValueError``. This is a boundary case, not an end-to-end canonical one.
    """
    put_lifecycle_parents(sqlite_harness, run=True)
    stored = sample_run(_R.PENDING)
    fields = {name: getattr(stored, name) for name in EngineRunRecord.model_fields}
    fields["finalization_deadline_utc"] = stored.created_at_utc
    transaction = sqlite_harness.unit_of_work().begin()
    inserted = transaction.engine_runs.add_attempt(
        EngineRunRecord.model_construct(**{**fields, "run_id": OTHER_RUN_ID})
    )
    assert code(inserted) == INVARIANT_VIOLATION
    assert "finalization deadline" in _message(inserted)
    # Nothing of the refused attempt reached the table.
    assert code(transaction.engine_runs.get(OTHER_RUN_ID)) == INVARIANT_VIOLATION
    # In compare-and-swap the encoding happens at step e, so a missing row and a
    # stale revision still refuse as conflicts before rule N4 is reached.
    absent = EngineRunRecord.model_construct(
        **{**fields, "run_id": OTHER_RUN_ID, "revision": 1}
    )
    assert code(transaction.engine_runs.compare_and_swap(0, absent)) == (
        CONCURRENCY_CONFLICT
    )
    stale = EngineRunRecord.model_construct(**{**fields, "revision": 6})
    assert code(transaction.engine_runs.compare_and_swap(5, stale)) == (
        CONCURRENCY_CONFLICT
    )
    # At the matching revision the mapping fires, and the row is unchanged.
    bumped = EngineRunRecord.model_construct(**{**fields, "revision": 1})
    refused = transaction.engine_runs.compare_and_swap(stored.revision, bumped)
    assert code(refused) == INVARIANT_VIOLATION
    assert "finalization deadline" in _message(refused)
    assert ok(transaction.engine_runs.get(RUN_ID)) == stored
    commit(transaction)
    assert sqlite_harness.committed_engine_runs() == (stored,)
    assert _row_count(sqlite_harness, "engine_runs") == 1


def test_the_scaffolding_parent_is_the_only_queued_row_without_a_snapshot(
    sqlite_harness: SqliteHarness,
) -> None:
    """Plan 7.1: ``put_lifecycle_parents`` inserts its ``QUEUED`` parent through
    ``add``, so it is the count's only legitimate source in this task's tests."""
    assert sqlite_harness.database.consistency_report().queued_without_snapshot == 0
    put_lifecycle_parents(sqlite_harness, run=True, invocation=True)
    report = sqlite_harness.database.consistency_report()
    assert report.queued_without_snapshot == 1
    assert report.slot_identity_mismatches == 0
    assert report.spec_projection_mismatches == 0
    assert report.foreign_key_violations == 0
