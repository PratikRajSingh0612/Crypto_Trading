"""Driver races over SQLite (plan 5.1 cases C-5, C-6, C-10 to C-13; Task 6).

Every case drives a REAL application operation through ``run_operation`` over
``InterleavingUnitOfWork`` (plan 5.2, 7.1), whose hook runs the winner on a
separate ``SqliteUnitOfWork`` -- its own pooled connection -- exactly once, after
the loser's first repository read returned. That read established the loser's WAL
snapshot, so the loser's first write is refused by the snapshot rule
(``SQLITE_BUSY_SNAPSHOT``, 517) and never by a timing accident; ``begins`` pins
the reload-once driver's two attempts. No thread, no sleep, no wall clock; every
durable assertion is a fresh read after the operation returned, and the
``CountingUnitOfWork`` bookkeeping is compared with the pool's own checkout count.

Declared readings, so nothing is inferred silently:

- **C-11 as written cannot compete.** ``create_successor`` requires an ``ALLOWED``
  decision whose predecessor is the slot's latest attempt with no attempt at the
  reserved number; over that same committed state ``classify_experiment_outcome``
  row 3 (``ALLOWED_SUCCESSOR_PENDING``) returns ``NOT_YET_TERMINAL`` and
  ``aggregate_experiment`` writes nothing -- it can neither lose a swap nor commit
  a terminal state while a successor is creatable. Stage 5's race suite recorded
  the same fact (its ``no_constructible_shared_start`` case for the retry versus
  aggregation pair) and, for the successor-after-terminal-aggregation rule,
  committed the terminal
  write through the repository compare-and-swap "labelled as such". Order (a) is
  therefore the measurement over SQLite -- both actors run, the aggregation returns
  ``NOT_YET_TERMINAL`` with no write and one ``begin()``, the successor commits --
  and order (b) uses that labelled terminal write as the winner, so the plan's
  ``CORE.INVARIANT_VIOLATION`` and "no successor" outcomes are proven through the
  real ``create_successor`` rerun. One or the other, never both, in both orders.
- **C-12's mover cannot be ``transition_run`` on a read run.** Every latest attempt
  the aggregation read must be terminal for it to reach its write (row 1), and a
  terminal run accepts no transition. The row that moves without a revision move is
  the experiment row's four snapshot columns, written by the persistence-owned
  ``configuration_snapshots.freeze`` (reading 22) -- a write inside the
  aggregation's read set that never touches ``revision``. The refusal at the
  compare-and-swap, the single rerun and the recomputation are proven as the plan
  states; the companion in ``test_sqlite_retry_decisions.py`` proves a rerun that
  recomputes to a *different* outcome.
- The sketch's ``_ok``/``_code``/``_commit``/``_put_experiment``/``_bump`` shorthand
  names the promoted helpers of ``persistence_support.harness`` (plan 7.1).
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Final

import pytest
from sqlalchemy.pool import QueuePool

from crypto_lab.configuration.models import ApplicationConfig
from crypto_lab.configuration.snapshot import snapshot_configuration
from crypto_lab.domain.aggregation import (
    REASON_SLOT_FAILED,
    AggregationVerdict,
    SlotRetryStatus,
)
from crypto_lab.domain.engine_run import EngineRunRecord
from crypto_lab.domain.experiment import ExperimentRecord
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.results import Failure
from crypto_lab.domain.retry import (
    RetryDecisionOutcome,
    RetryDecisionRecord,
    RetryDenialReason,
)
from crypto_lab.experiments.aggregation import (
    aggregate_experiment,
    build_aggregation_input,
)
from crypto_lab.experiments.experiment_service import (
    LostSwap,
    Outcome,
    cancel_experiment,
    run_operation,
    transition_experiment,
)
from crypto_lab.experiments.invocation_service import begin_linked_launch
from crypto_lab.experiments.ports import UnitOfWork
from crypto_lab.experiments.requests import (
    CancelExperimentRequest,
    ExperimentAggregationRequest,
    ExperimentTransitionRequest,
    LinkedLaunchRequest,
    RetryEvaluationRequest,
    RunTransitionRequest,
    SuccessorCreationRequest,
)
from crypto_lab.experiments.retry import create_successor, evaluate_retry
from crypto_lab.experiments.run_service import transition_run
from crypto_lab.persistence.database import ConsistencyReport, SqliteDatabase
from crypto_lab.persistence.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
    persistence_failure,
)
from crypto_lab.persistence.registries import SqliteDiagnosticRecorder
from doubles.experiments import (
    ADAPTER_BETA,
    AVAIL_A,
    DIAG_ID,
    ENGINE_BETA,
    EXPERIMENT_ID,
    INSTANT,
    INVOCATION_ID,
    OTHER_RUN_ID,
    REQUEST_HASH,
    RUN_ID,
    SLOT_A,
    SLOT_B,
    FailingClock,
    FixedClock,
    SequentialIdentitySource,
    sample_diagnostic,
    sample_experiment,
    sample_invocation,
    sample_observation,
    sample_run,
    sequential_diagnostic_id,
)
from persistence_support.harness import (
    CountingUnitOfWork,
    InterleavingUnitOfWork,
    SqliteHarness,
    bump,
    code,
    commit,
    ok,
    open_test_database,
    put_experiment,
    put_invocation,
    put_lifecycle_parents,
    put_run,
    raw_connection,
)

_E: Final = ExperimentState
_R: Final = EngineRunState
_C: Final = CommandInvocationState
#: Strictly after every fixture instant (``INSTANT`` plus at most five seconds).
CLOCK_INSTANT: Final = INSTANT + timedelta(minutes=1)
#: ``sample_run(FAILED).updated_at_utc`` (``INSTANT`` + 5 s) plus the default
#: thirty-second delay: the instant the reserved successor becomes due.
DUE_INSTANT: Final = INSTANT + timedelta(seconds=35)
_REASON: Final = "TEST.TRANSITION"
_WINNER: Final = "winner"
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
#: The one permitted non-zero count: a ``RUNNING`` (or ``QUEUED``) parent inserted
#: directly through ``add`` never crossed the queue edge, so it carries no frozen
#: snapshot (plan 4.6, reading 22); every other count is zero.
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


# --------------------------------------------------------------------------
# Module-local helpers
# --------------------------------------------------------------------------


def _checked_out(database: SqliteDatabase) -> int:
    """Connections the pool has lent out, not counting this probe's own."""
    with database.connection() as connection:
        pool = connection.engine.pool
        assert isinstance(pool, QueuePool)
        return pool.checkedout() - 1


@contextmanager
def _harness_at(directory: Path) -> Iterator[SqliteHarness]:
    """A fresh migrated database in its own directory, closed on exit."""
    directory.mkdir()
    harness = SqliteHarness(open_test_database(directory, clock=FixedClock(INSTANT)))
    try:
        yield harness
    finally:
        harness.close()


def _details(result: object) -> dict[str, object]:
    assert isinstance(result, Failure), result
    (diagnostic,) = result.diagnostics
    return dict(diagnostic.details)


def _message(result: object) -> str:
    assert isinstance(result, Failure), result
    (diagnostic,) = result.diagnostics
    return diagnostic.message


def _source(result: object) -> str:
    assert isinstance(result, Failure), result
    (diagnostic,) = result.diagnostics
    return diagnostic.source_component


def _stored_experiment(harness: SqliteHarness) -> ExperimentRecord:
    (stored,) = harness.committed_experiments()
    return stored


def _row_count(harness: SqliteHarness, table: str) -> int:
    connection = raw_connection(harness.database.path)
    try:
        # A fixed table name from this module, never a caller or row value.
        statement = f"SELECT count(*) FROM {table}"  # noqa: S608
        row = connection.execute(statement).fetchone()
        return int(row[0])
    finally:
        connection.close()


def _transition_request(
    expected_revision: int = 0, target: ExperimentState = _E.VALIDATED
) -> ExperimentTransitionRequest:
    return ExperimentTransitionRequest(
        schema_version="1.0.0",
        experiment_id=EXPERIMENT_ID,
        expected_revision=expected_revision,
        target_state=target,
        reason_code=_REASON,
    )


def _cancel_request(expected_revision: int) -> CancelExperimentRequest:
    return CancelExperimentRequest(
        schema_version="1.0.0",
        experiment_id=EXPERIMENT_ID,
        expected_revision=expected_revision,
        correlation_id=_WINNER,
    )


def _successor_request(expected_revision: int) -> SuccessorCreationRequest:
    return SuccessorCreationRequest(
        schema_version="1.0.0",
        experiment_id=EXPERIMENT_ID,
        logical_slot_id=SLOT_A,
        predecessor_run_id=RUN_ID,
        expected_experiment_revision=expected_revision,
        request_hash=REQUEST_HASH,
    )


def _aggregation_request(expected_revision: int) -> ExperimentAggregationRequest:
    return ExperimentAggregationRequest(
        schema_version="1.0.0",
        experiment_id=EXPERIMENT_ID,
        expected_revision=expected_revision,
    )


def _evaluation_request(
    *, experiment_revision: int, predecessor_revision: int
) -> RetryEvaluationRequest:
    return RetryEvaluationRequest(
        schema_version="1.0.0",
        experiment_id=EXPERIMENT_ID,
        logical_slot_id=SLOT_A,
        predecessor_run_id=RUN_ID,
        expected_experiment_revision=experiment_revision,
        expected_predecessor_revision=predecessor_revision,
    )


def _terminal(stored: ExperimentRecord, state: ExperimentState) -> ExperimentRecord:
    """The record a winning terminal aggregation commits over ``stored`` (the
    Stage 5 race suite's ``_terminal`` shape)."""
    return ExperimentRecord.model_validate(
        {
            **stored.model_dump(mode="python"),
            "state": state,
            "revision": stored.revision + 1,
            "updated_at_utc": stored.updated_at_utc + timedelta(seconds=1),
        }
    )


@dataclass(frozen=True, slots=True)
class _RetryReady:
    """A ``RUNNING`` experiment whose slot A holds a due ``ALLOWED`` reservation."""

    experiment: ExperimentRecord
    predecessor: EngineRunRecord
    decision: RetryDecisionRecord


def _retry_ready(harness: SqliteHarness) -> _RetryReady:
    """RUNNING at 3 with the default policy; A FAILED attempt 1 at 5 with its primary
    recorded and its observation seeded; then the REAL ``evaluate_retry`` -> ALLOWED
    reserving attempt 2, due at ``DUE_INSTANT``, bumping the experiment to 4."""
    experiment = sample_experiment(_E.RUNNING)
    predecessor = sample_run(_R.FAILED)
    harness.seed_observation(sample_observation(AVAIL_A))
    harness.seed_diagnostic(sample_diagnostic())
    put_experiment(harness, experiment)
    put_run(harness, predecessor)
    decision = ok(
        evaluate_retry(
            _evaluation_request(
                experiment_revision=experiment.revision,
                predecessor_revision=predecessor.revision,
            ),
            unit_of_work=harness.unit_of_work(),
            clock=FixedClock(CLOCK_INSTANT),
        )
    )
    assert decision.outcome is RetryDecisionOutcome.ALLOWED
    assert decision.retry_not_before_utc == DUE_INSTANT
    assert decision.reserved_successor_attempt_number == 2
    stored = _stored_experiment(harness)
    assert stored.state is _E.RUNNING
    assert stored.revision == experiment.revision + 1
    return _RetryReady(stored, predecessor, decision)


def _create_successor_winner(harness: SqliteHarness, expected_revision: int) -> None:
    created = ok(
        create_successor(
            _successor_request(expected_revision),
            unit_of_work=harness.unit_of_work(),
            clock=FixedClock(CLOCK_INSTANT),
            identity_source=SequentialIdentitySource(_WINNER),
        )
    )
    assert created.attempt.attempt_number == 2
    assert created.experiment.revision == expected_revision + 1


def _successor_rows(harness: SqliteHarness) -> tuple[EngineRunRecord, ...]:
    return tuple(
        run for run in harness.committed_engine_runs() if run.attempt_number == 2
    )


# --------------------------------------------------------------------------
# C-5: the revision race through the driver
# --------------------------------------------------------------------------


def test_run_operation_reloads_once_after_a_lost_experiment_swap(
    sqlite_harness: SqliteHarness,
) -> None:
    stored = sample_experiment(_E.DRAFT)
    put_experiment(sqlite_harness, stored)

    def winner_commits() -> None:
        transaction = sqlite_harness.unit_of_work().begin()
        ok(transaction.experiments.compare_and_swap(0, bump(stored)))
        commit(transaction)

    interleaving = InterleavingUnitOfWork(
        sqlite_harness.unit_of_work(), after_read=winner_commits
    )
    outcome = transition_experiment(
        ExperimentTransitionRequest(
            schema_version="1.0.0",
            experiment_id=EXPERIMENT_ID,
            expected_revision=0,
            target_state=_E.VALIDATED,
            reason_code="TEST.TRANSITION",
        ),
        unit_of_work=interleaving,
        clock=FixedClock(INSTANT),
    )
    assert code(outcome) == CONCURRENCY_CONFLICT
    assert interleaving.begins == 2
    assert sqlite_harness.committed_experiments() == (bump(stored),)


def _winner_bumps(harness: SqliteHarness) -> None:
    transaction = harness.unit_of_work().begin()
    ok(transaction.experiments.compare_and_swap(0, bump(sample_experiment(_E.DRAFT))))
    commit(transaction)


def _winner_takes_the_same_edge(harness: SqliteHarness) -> None:
    ok(
        transition_experiment(
            _transition_request(),
            unit_of_work=harness.unit_of_work(),
            clock=FixedClock(INSTANT + timedelta(seconds=1)),
        )
    )


def _winner_cancels(harness: SqliteHarness) -> None:
    ok(
        cancel_experiment(
            _cancel_request(0),
            unit_of_work=harness.unit_of_work(),
            clock=FixedClock(INSTANT + timedelta(seconds=1)),
        )
    )


@pytest.mark.parametrize(
    ("winner", "expected_code", "expected_state"),
    [
        (_winner_bumps, CONCURRENCY_CONFLICT, _E.DRAFT),
        (_winner_takes_the_same_edge, CONCURRENCY_CONFLICT, _E.VALIDATED),
        (_winner_cancels, INVARIANT_VIOLATION, _E.CANCELLED),
    ],
    ids=["moved_non_terminal_row", "same_edge", "terminal_row"],
)
def test_the_rerun_of_a_lost_swap_reports_the_moved_rows_own_code(
    sqlite_harness: SqliteHarness,
    winner: Callable[[SqliteHarness], None],
    expected_code: str,
    expected_state: ExperimentState,
) -> None:
    """C-5, the three winners of plan 5.1: the rerun still carries the stale
    request, so a moved non-terminal row and the same edge are ``_stale``'s
    conflict and a now-terminal row is the invariant; exactly one write, T1's."""
    put_experiment(sqlite_harness, sample_experiment(_E.DRAFT))
    interleaving = InterleavingUnitOfWork(
        sqlite_harness.unit_of_work(), after_read=lambda: winner(sqlite_harness)
    )
    outcome = transition_experiment(
        _transition_request(), unit_of_work=interleaving, clock=FixedClock(INSTANT)
    )
    assert code(outcome) == expected_code
    assert interleaving.begins == 2
    # The public code is the operation's own (plan 9.5), never the repository's.
    assert _source(outcome) == "experiments.experiment_service"
    if expected_code == CONCURRENCY_CONFLICT:
        assert _details(outcome) == {"expected_revision": 0, "stored_revision": 1}
    else:
        assert "accepts no transition" in _message(outcome)
    stored = _stored_experiment(sqlite_harness)
    assert stored.state is expected_state
    assert stored.revision == 1


# --------------------------------------------------------------------------
# C-6: the linked pair loses atomically to a partner change
# --------------------------------------------------------------------------


def test_a_linked_launch_loses_atomically_to_a_run_cancellation(
    sqlite_harness: SqliteHarness,
) -> None:
    put_lifecycle_parents(sqlite_harness, observation=True)
    sqlite_harness.seed_diagnostic(sample_diagnostic())
    invocation = sample_invocation(_C.PENDING)
    run = sample_run(_R.READY)
    put_run(sqlite_harness, run)
    put_invocation(sqlite_harness, invocation)

    def run_is_cancelled() -> None:
        cancelled = ok(
            transition_run(
                RunTransitionRequest(
                    schema_version="1.0.0",
                    run_id=RUN_ID,
                    expected_revision=run.revision,
                    target_state=_R.CANCELLED,
                    reason_code=_REASON,
                    primary_terminal_diagnostic_id=DIAG_ID,
                ),
                unit_of_work=sqlite_harness.unit_of_work(),
                clock=FixedClock(CLOCK_INSTANT),
            )
        )
        assert cancelled.state is _R.CANCELLED

    interleaving = InterleavingUnitOfWork(
        sqlite_harness.unit_of_work(), after_read=run_is_cancelled
    )
    outcome = begin_linked_launch(
        LinkedLaunchRequest(
            schema_version="1.0.0",
            invocation_id=INVOCATION_ID,
            expected_invocation_revision=invocation.revision,
            run_id=RUN_ID,
            expected_run_revision=run.revision,
        ),
        unit_of_work=interleaving,
        clock=FixedClock(CLOCK_INSTANT),
    )
    assert code(outcome) == INVARIANT_VIOLATION
    assert "not (PENDING, CANCELLED)" in _message(outcome)
    assert interleaving.begins == 2
    # Neither row partially advanced: the invocation never left PENDING at its
    # original revision and the run carries T1's cancellation alone.
    (stored_invocation,) = sqlite_harness.committed_command_invocations()
    assert stored_invocation == invocation
    (stored_run,) = sqlite_harness.committed_engine_runs()
    assert stored_run.state is _R.CANCELLED
    assert stored_run.revision == run.revision + 1
    assert stored_run.primary_terminal_diagnostic_id == DIAG_ID
    assert sqlite_harness.database.consistency_report() == _SCAFFOLDED_PARENT


# --------------------------------------------------------------------------
# C-10: successor creation versus cancellation, both orders
# --------------------------------------------------------------------------


def test_successor_creation_and_cancellation_race_both_orders(tmp_path: Path) -> None:
    # (a) T2 create_successor; T1 cancel_experiment commits after T2's first read.
    with _harness_at(tmp_path / "cancel_wins") as harness:
        ready = _retry_ready(harness)

        def cancel_wins() -> None:
            ok(
                cancel_experiment(
                    _cancel_request(ready.experiment.revision),
                    unit_of_work=harness.unit_of_work(),
                    clock=FixedClock(CLOCK_INSTANT),
                )
            )

        interleaving = InterleavingUnitOfWork(
            harness.unit_of_work(), after_read=cancel_wins
        )
        outcome = create_successor(
            _successor_request(ready.experiment.revision),
            unit_of_work=interleaving,
            clock=FixedClock(CLOCK_INSTANT),
            identity_source=SequentialIdentitySource("loser"),
        )
        assert code(outcome) == INVARIANT_VIOLATION
        assert "a successor is created only while it is RUNNING" in _message(outcome)
        assert interleaving.begins == 2
        stored = _stored_experiment(harness)
        assert stored.state is _E.CANCELLED
        assert stored.revision == ready.experiment.revision + 1
        assert stored.cancellation_correlation_id == _WINNER
        assert harness.committed_engine_runs() == (ready.predecessor,)
        assert harness.committed_retry_decisions() == (ready.decision,)
        # A CANCELLED row lawfully carries no snapshot (reading 22), so the
        # scaffolded parent no longer counts: every one of the eight is zero.
        assert harness.database.consistency_report() == _CLEAN
    # (b) T2 cancel_experiment; T1 create_successor commits after T2's first read.
    with _harness_at(tmp_path / "successor_wins") as harness:
        ready = _retry_ready(harness)
        interleaving = InterleavingUnitOfWork(
            harness.unit_of_work(),
            after_read=lambda: _create_successor_winner(
                harness, ready.experiment.revision
            ),
        )
        refused = cancel_experiment(
            _cancel_request(ready.experiment.revision),
            unit_of_work=interleaving,
            clock=FixedClock(CLOCK_INSTANT),
        )
        assert code(refused) == CONCURRENCY_CONFLICT
        assert _source(refused) == "experiments.experiment_service"
        assert _details(refused) == {
            "expected_revision": ready.experiment.revision,
            "stored_revision": ready.experiment.revision + 1,
        }
        assert interleaving.begins == 2
        stored = _stored_experiment(harness)
        assert stored.state is _E.RUNNING
        assert stored.revision == ready.experiment.revision + 1
        assert not isinstance(stored.cancellation_correlation_id, str)
        (successor,) = _successor_rows(harness)
        assert successor.state is _R.PENDING
        assert successor.predecessor_run_id == RUN_ID
        assert successor.revision == 0
        assert len(harness.committed_engine_runs()) == 2
        assert harness.committed_retry_decisions() == (ready.decision,)
        assert harness.database.consistency_report() == _SCAFFOLDED_PARENT


# --------------------------------------------------------------------------
# C-11: successor creation versus terminal aggregation, both orders
# (declared reading, module docstring)
# --------------------------------------------------------------------------


def _resolve_slot_b(harness: SqliteHarness) -> EngineRunRecord:
    """Slot B's one attempt ends ``NOT_APPLICABLE``: terminal, mapping to no retry
    terminal state, so it needs no decision and blocks nothing."""
    resolved = sample_run(
        _R.NOT_APPLICABLE,
        run_id=OTHER_RUN_ID,
        logical_slot_id=SLOT_B,
        adapter=ADAPTER_BETA,
        engine=ENGINE_BETA,
    )
    put_run(harness, resolved)
    return resolved


def _slot_statuses(
    harness: SqliteHarness, experiment: ExperimentRecord
) -> tuple[tuple[object, SlotRetryStatus], ...]:
    transaction = harness.unit_of_work().begin()
    try:
        built = build_aggregation_input(transaction, experiment, now=CLOCK_INSTANT)
    finally:
        transaction.rollback()
    assert not isinstance(built, Failure), built
    return tuple((slot.latest_attempt_state, slot.retry_status) for slot in built.slots)


def test_successor_creation_and_aggregation_race_both_orders(tmp_path: Path) -> None:
    # (a) T2 aggregate_experiment; T1 create_successor commits after T2's first read.
    with _harness_at(tmp_path / "successor_wins") as harness:
        ready = _retry_ready(harness)
        _resolve_slot_b(harness)
        # The sole blocker of a terminal verdict is row 3 on slot A: every latest
        # attempt is terminal, slot B needs no decision, slot A's ALLOWED reservation
        # is pending. This is the state in which a successor is creatable.
        assert _slot_statuses(harness, ready.experiment) == (
            (_R.FAILED, SlotRetryStatus.ALLOWED_SUCCESSOR_PENDING),
            (_R.NOT_APPLICABLE, SlotRetryStatus.NO_DECISION_REQUIRED),
        )
        interleaving = InterleavingUnitOfWork(
            harness.unit_of_work(),
            after_read=lambda: _create_successor_winner(
                harness, ready.experiment.revision
            ),
        )
        verdict = ok(
            aggregate_experiment(
                _aggregation_request(ready.experiment.revision),
                unit_of_work=interleaving,
                clock=FixedClock(CLOCK_INSTANT),
            )
        )
        # The aggregation could not write, so nothing was lost and nothing reran.
        assert verdict.verdict is AggregationVerdict.NOT_YET_TERMINAL
        assert verdict.reason_codes == ()
        assert interleaving.begins == 1
        stored = _stored_experiment(harness)
        assert stored.state is _E.RUNNING
        assert stored.revision == ready.experiment.revision + 1
        (successor,) = _successor_rows(harness)
        assert successor.state is _R.PENDING
        # A fresh aggregation over the committed successor stays non-terminal
        # through row 1 (a PENDING current attempt): one or the other, never both.
        again = ok(
            aggregate_experiment(
                _aggregation_request(stored.revision),
                unit_of_work=harness.unit_of_work(),
                clock=FixedClock(CLOCK_INSTANT),
            )
        )
        assert again.verdict is AggregationVerdict.NOT_YET_TERMINAL
        assert _stored_experiment(harness) == stored
        assert harness.database.consistency_report() == _SCAFFOLDED_PARENT
    # (b) T2 create_successor; T1's terminal write commits after T2's first read.
    with _harness_at(tmp_path / "aggregation_wins") as harness:
        ready = _retry_ready(harness)
        _resolve_slot_b(harness)
        terminal = _terminal(ready.experiment, _E.FAILED)

        def terminal_write_wins() -> None:
            # The terminal write of a winning aggregation, committed through the
            # repository compare-and-swap and labelled as such: the real
            # aggregate_experiment cannot reach it while slot A's reservation is
            # pending (module docstring).
            transaction = harness.unit_of_work().begin()
            ok(
                transaction.experiments.compare_and_swap(
                    ready.experiment.revision, terminal
                )
            )
            commit(transaction)

        interleaving = InterleavingUnitOfWork(
            harness.unit_of_work(), after_read=terminal_write_wins
        )
        outcome = create_successor(
            _successor_request(ready.experiment.revision),
            unit_of_work=interleaving,
            clock=FixedClock(CLOCK_INSTANT),
            identity_source=SequentialIdentitySource("loser"),
        )
        assert code(outcome) == INVARIANT_VIOLATION
        assert "a successor is created only while it is RUNNING" in _message(outcome)
        assert _details(outcome) == {"experiment_state": _E.FAILED.value}
        assert interleaving.begins == 2
        assert _stored_experiment(harness) == terminal
        assert _successor_rows(harness) == ()
        assert len(harness.committed_engine_runs()) == 2
        # The terminal record replays as its verdict with no clock read and no write.
        replay = ok(
            aggregate_experiment(
                _aggregation_request(terminal.revision),
                unit_of_work=harness.unit_of_work(),
                clock=FailingClock(),
            )
        )
        assert replay.verdict is AggregationVerdict.FAILED
        assert replay.reason_codes == ()
        assert _stored_experiment(harness) == terminal
        assert harness.database.consistency_report() == _SCAFFOLDED_PARENT


# --------------------------------------------------------------------------
# C-12: read-set protection without a revision move (declared reading)
# --------------------------------------------------------------------------


def test_a_read_only_row_that_moved_refuses_the_aggregation_write(
    sqlite_harness: SqliteHarness,
) -> None:
    experiment = sample_experiment(_E.RUNNING)
    predecessor = sample_run(_R.FAILED)
    sqlite_harness.seed_observation(sample_observation(AVAIL_A))
    # A non-retriable primary: the REAL evaluate_retry denies (gate 3) and, denying,
    # bumps nothing, so slot A resolves to DENIED and the experiment stays at 3.
    sqlite_harness.seed_diagnostic(sample_diagnostic(retriable=False))
    put_experiment(sqlite_harness, experiment)
    put_run(sqlite_harness, predecessor)
    denied = ok(
        evaluate_retry(
            _evaluation_request(
                experiment_revision=experiment.revision,
                predecessor_revision=predecessor.revision,
            ),
            unit_of_work=sqlite_harness.unit_of_work(),
            clock=FixedClock(CLOCK_INSTANT),
        )
    )
    assert denied.outcome is RetryDecisionOutcome.DENIED
    assert denied.denial_reason is RetryDenialReason.PRIMARY_DIAGNOSTIC_NOT_RETRIABLE
    _resolve_slot_b(sqlite_harness)
    assert _stored_experiment(sqlite_harness) == experiment
    assert _slot_statuses(sqlite_harness, experiment) == (
        (_R.FAILED, SlotRetryStatus.DENIED),
        (_R.NOT_APPLICABLE, SlotRetryStatus.NO_DECISION_REQUIRED),
    )
    snapshot = snapshot_configuration(ApplicationConfig())
    revisions_seen_by_the_mover: list[int] = []

    def snapshot_is_frozen() -> None:
        # The mover writes the four snapshot columns of the experiment row -- a row
        # T2 read -- and never its revision (reading 22).
        transaction = sqlite_harness.unit_of_work().begin()
        ok(transaction.configuration_snapshots.freeze(EXPERIMENT_ID, snapshot))
        commit(transaction)
        fresh = _stored_experiment(sqlite_harness)
        revisions_seen_by_the_mover.append(fresh.revision)

    interleaving = InterleavingUnitOfWork(
        sqlite_harness.unit_of_work(), after_read=snapshot_is_frozen
    )
    result = ok(
        aggregate_experiment(
            _aggregation_request(experiment.revision),
            unit_of_work=interleaving,
            clock=FixedClock(CLOCK_INSTANT),
        )
    )
    # The experiment row never moved in revision, yet the first compare-and-swap
    # was refused by the snapshot rule and the rerun recomputed the same verdict.
    assert revisions_seen_by_the_mover == [experiment.revision]
    assert interleaving.begins == 2
    assert result.verdict is AggregationVerdict.FAILED
    assert result.reason_codes == (REASON_SLOT_FAILED,)
    stored = _stored_experiment(sqlite_harness)
    assert stored.state is _E.FAILED
    assert stored.revision == experiment.revision + 1
    # The record swap preserved the frozen snapshot the mover wrote (plan 4.3.1 e).
    reader = sqlite_harness.unit_of_work().begin()
    try:
        assert ok(reader.configuration_snapshots.get(EXPERIMENT_ID)) == snapshot
    finally:
        reader.rollback()
    assert sqlite_harness.database.consistency_report() == _CLEAN


# --------------------------------------------------------------------------
# C-13: the measured residual of unrelated commits
# --------------------------------------------------------------------------


class _UnrelatedRecorder:
    """Commits one new diagnostic per call from another connection: a write the
    operation never read and never writes, whose commit still invalidates the
    operation's snapshot (plan 1.4, the bounded residual)."""

    def __init__(self, database: SqliteDatabase) -> None:
        self._recorder = SqliteDiagnosticRecorder(database, clock=FixedClock(INSTANT))
        self.recorded = 0

    def __call__(self) -> None:
        self.recorded += 1
        ok(
            self._recorder.record(
                sample_diagnostic(sequential_diagnostic_id(self.recorded))
            )
        )


def test_unrelated_commits_cost_one_rerun_and_two_return_the_conflict(
    tmp_path: Path,
) -> None:
    with _harness_at(tmp_path / "one") as harness:
        put_experiment(harness, sample_experiment(_E.DRAFT))
        unrelated = _UnrelatedRecorder(harness.database)
        interleaving = InterleavingUnitOfWork(
            harness.unit_of_work(), after_read=unrelated, on_attempts=(1,)
        )
        validated = ok(
            transition_experiment(
                _transition_request(),
                unit_of_work=interleaving,
                clock=FixedClock(INSTANT),
            )
        )
        assert validated.state is _E.VALIDATED
        assert validated.revision == 1
        assert interleaving.begins == 2
        assert unrelated.recorded == 1
        assert _stored_experiment(harness) == validated
        assert _row_count(harness, "diagnostics") == 1
        assert harness.database.consistency_report() == _CLEAN
    with _harness_at(tmp_path / "two") as harness:
        stored = sample_experiment(_E.DRAFT)
        put_experiment(harness, stored)
        unrelated = _UnrelatedRecorder(harness.database)
        interleaving = InterleavingUnitOfWork(
            harness.unit_of_work(), after_read=unrelated, on_attempts=(1, 2)
        )
        outcome = transition_experiment(
            _transition_request(), unit_of_work=interleaving, clock=FixedClock(INSTANT)
        )
        # Both attempts lost to the snapshot rule: the public result is the
        # repository's conflict, carried verbatim by the driver's second loss.
        assert code(outcome) == CONCURRENCY_CONFLICT
        assert _source(outcome) == "persistence"
        details = _details(outcome)
        assert details["sqlite_errorcode"] == 517
        assert details["operation"] == "compare_and_swap"
        assert interleaving.begins == 2
        assert unrelated.recorded == 2
        assert _stored_experiment(harness) == stored
        assert _row_count(harness, "diagnostics") == 2
        # A recorded diagnostic nothing references is not dangling (C-25).
        assert harness.database.consistency_report() == _CLEAN


# --------------------------------------------------------------------------
# CountingUnitOfWork: one decrement per actual release (plan 7.1, Task 6)
# --------------------------------------------------------------------------


def _once_raises(transaction: UnitOfWork) -> Outcome[ExperimentRecord]:
    ok(transaction.experiments.get(EXPERIMENT_ID))
    raise RuntimeError("the operation body failed after a read")


def _once_loses_forever(transaction: UnitOfWork) -> Outcome[ExperimentRecord]:
    ok(transaction.experiments.get(EXPERIMENT_ID))
    return LostSwap(
        persistence_failure(
            CONCURRENCY_CONFLICT,
            message="simulated lost swap",
            clock=FixedClock(INSTANT),
        )
    )


def test_the_counting_wrapper_decrements_once_per_release_path(
    sqlite_harness: SqliteHarness,
) -> None:
    put_experiment(sqlite_harness, sample_experiment(_E.DRAFT))
    database = sqlite_harness.database
    counting = CountingUnitOfWork(sqlite_harness.unit_of_work())
    assert (counting.open_now, counting.max_open) == (0, 0)
    # A committed operation: one transaction opened and released.
    validated = ok(
        transition_experiment(
            _transition_request(), unit_of_work=counting, clock=FixedClock(INSTANT)
        )
    )
    assert validated.revision == 1
    assert (counting.open_now, counting.max_open) == (0, 1)
    assert _checked_out(database) == 0
    # An early Failure: rolled back by the driver's finally, released once.
    assert (
        code(
            transition_experiment(
                _transition_request(expected_revision=7),
                unit_of_work=counting,
                clock=FixedClock(INSTANT),
            )
        )
        == CONCURRENCY_CONFLICT
    )
    assert counting.open_now == 0
    assert _checked_out(database) == 0
    # An exception escaping the operation body: the finally releases it too.
    with pytest.raises(RuntimeError, match="failed after a read"):
        run_operation(counting, _once_raises)
    assert counting.open_now == 0
    assert _checked_out(database) == 0
    # A second loss returns the conflict after two transactions, never overlapping.
    counting.reset_max()
    assert counting.max_open == 0
    assert code(run_operation(counting, _once_loses_forever)) == CONCURRENCY_CONFLICT
    assert (counting.open_now, counting.max_open) == (0, 1)
    assert _checked_out(database) == 0
    # Explicit paths: rollback twice and commit-then-rollback each release once.
    transaction = counting.begin()
    assert (counting.open_now, _checked_out(database)) == (1, 1)
    _ = transaction.experiments  # a member access is not a release
    assert counting.open_now == 1
    transaction.rollback()
    transaction.rollback()
    assert (counting.open_now, _checked_out(database)) == (0, 0)
    transaction = counting.begin()
    commit(transaction)
    transaction.rollback()
    assert (counting.open_now, _checked_out(database)) == (0, 0)
    # Two live transactions are two, and the maximum records them.
    counting.reset_max()
    first = counting.begin()
    second = counting.begin()
    assert (counting.open_now, counting.max_open) == (2, 2)
    assert _checked_out(database) == 2
    first.rollback()
    assert (counting.open_now, counting.max_open) == (1, 2)
    second.rollback()
    assert (counting.open_now, counting.max_open) == (0, 2)
    assert _checked_out(database) == 0
    assert sqlite_harness.open_transactions() == ()


def test_the_counting_wrapper_sees_a_reload_as_two_sequential_transactions(
    sqlite_harness: SqliteHarness,
) -> None:
    """A lost swap rolls the first transaction back before the second opens, so
    the maximum stays one and the pool holds nothing afterwards."""
    stored = sample_experiment(_E.DRAFT)
    put_experiment(sqlite_harness, stored)
    interleaving = InterleavingUnitOfWork(
        sqlite_harness.unit_of_work(),
        after_read=lambda: _winner_bumps(sqlite_harness),
    )
    counting = CountingUnitOfWork(interleaving)
    outcome = transition_experiment(
        _transition_request(), unit_of_work=counting, clock=FixedClock(INSTANT)
    )
    assert code(outcome) == CONCURRENCY_CONFLICT
    assert interleaving.begins == 2
    assert (counting.open_now, counting.max_open) == (0, 1)
    assert _checked_out(sqlite_harness.database) == 0
    assert sqlite_harness.committed_experiments() == (bump(stored),)
