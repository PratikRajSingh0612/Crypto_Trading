"""Retry-decision recovery over SQLite (plan 5.1 cases C-7, C-8, C-24; Task 6).

The two concurrent-loser cases drive the REAL ``evaluate_retry`` through
``InterleavingUnitOfWork`` (plan 5.2): the hook fires after the loser's phase-1
``get_by_predecessor`` read saw the key absent -- the read that established its WAL
snapshot -- and commits the winner ``D1`` from another connection through the same
operation. The loser's first write is refused by the snapshot rule, the driver
reruns once, and phase 1 of the rerun replays ``D1`` by identity: no projection
comparison and no ``RETRY.DECISION_CONFLICT`` (reading 19), whether the loser's own
candidate was identical (C-8) or divergent because the observation it relied on
expired between the two evaluations (C-7; the expiry is a ``FixedClock`` advance).
C-24 proves the durable ``retry_not_before_utc`` across a close and reopen through
the REAL ``create_successor``; a companion proves the successor durable and its
identical replay clock-free and identity-free. The read-set companion proves a
rerun that *recomputes*: a fresh observation committed by the persistence-owned
writer between the loser's first read and its write turns its ``DENIED`` candidate
into a durable ``ALLOWED`` (plan 1.5 note 12, the C-12 measurement).

Every durable assertion is a fresh read after the operation returned; every
database is closed by the fixture's ``close()``. ``RetryFixture`` is the
module-local helper plan 7.1 names for this module.

Declared readings:

- ``RetryFixture.request`` is typed ``Any``: the two verbatim sketches read the same
  attribute as a ``RetryEvaluationRequest`` (C-7) and a ``SuccessorCreationRequest``
  (C-24). The typed twins ``evaluation_request`` and ``successor_request`` serve
  every other use in this module.
- The sketch's ``_code`` names the promoted ``code`` helper (plan 7.1).
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Final

import pytest
from sqlalchemy.pool import QueuePool

from crypto_lab.domain.engine_run import AttemptTokenMaterial, EngineRunRecord
from crypto_lab.domain.experiment import ExperimentRecord
from crypto_lab.domain.lifecycle import EngineRunState, ExperimentState
from crypto_lab.domain.results import Failure, Success
from crypto_lab.domain.retry import (
    RetryDecisionOutcome,
    RetryDecisionRecord,
    RetryDenialReason,
    evaluate_retry_gates,
    retry_decision_semantic_projection,
)
from crypto_lab.domain.time import format_utc
from crypto_lab.experiments.diagnostics import RETRY_NOT_BEFORE_NOT_REACHED
from crypto_lab.experiments.requests import (
    RetryEvaluationRequest,
    SuccessorCreationRequest,
)
from crypto_lab.experiments.retry import (
    build_retry_evaluation_snapshot,
    create_successor,
    evaluate_retry,
)
from crypto_lab.persistence.database import ConsistencyReport, SqliteDatabase
from crypto_lab.persistence.unit_of_work import SqliteUnitOfWork
from doubles.experiments import (
    AVAIL_A,
    AVAIL_B,
    EXPERIMENT_ID,
    INSTANT,
    REQUEST_HASH,
    RUN_ID,
    SLOT_A,
    CountingClock,
    FixedClock,
    SequentialIdentitySource,
    sample_diagnostic,
    sample_draft,
    sample_experiment,
    sample_observation,
    sample_retry_policy,
    sample_run,
)
from persistence_support.harness import (
    InterleavingUnitOfWork,
    SqliteHarness,
    code,
    commit,
    ok,
    open_test_database,
    put_experiment,
    put_run,
)

_E: Final = ExperimentState
_R: Final = EngineRunState
#: Strictly after every fixture instant (``INSTANT`` plus at most five seconds):
#: the base instant of every evaluation and of the reopened clock.
CLOCK_INSTANT: Final = INSTANT + timedelta(minutes=1)
#: ``sample_run(<terminal>).updated_at_utc``: the authoritative completion instant.
_COMPLETED_AT: Final = INSTANT + timedelta(seconds=5)
#: Strictly after the completion instant: the fresh observation's instant.
_FRESH_AT: Final = INSTANT + timedelta(seconds=10)
#: The fresh observation's lifetime: it is fresh at ``CLOCK_INSTANT`` (expiring at
#: ``INSTANT`` + 130 s) and expired once the clock has advanced by this plus one.
_OBSERVATION_TTL_SECONDS: Final = 120
#: The one permitted non-zero count: the ``RUNNING`` parent inserted directly
#: through ``add`` never crossed the queue edge and carries no frozen snapshot
#: (plan 4.6, reading 22); every other count is zero.
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


def _checked_out(database: SqliteDatabase) -> int:
    """Connections the pool has lent out, not counting this probe's own."""
    with database.connection() as connection:
        pool = connection.engine.pool
        assert isinstance(pool, QueuePool)
        return pool.checkedout() - 1


def _fresh_observation(ttl_seconds: int) -> Any:
    return sample_observation(
        AVAIL_B,
        observed_at_utc=_FRESH_AT,
        expires_at_utc=_FRESH_AT + timedelta(seconds=ttl_seconds),
    )


@dataclass
class RetryFixture:
    """One migrated database with a ``RUNNING`` experiment and a terminal attempt 1.

    ``seeded_unavailable`` seeds an ``UNAVAILABLE`` predecessor beside its own
    observation and, by default, one fresh observation that qualifies at
    ``CLOCK_INSTANT`` (C-7, C-8, the read-set companion). ``seeded_allowed`` seeds a
    ``FAILED`` predecessor under a policy with the given delay and commits the
    ``ALLOWED`` decision through the REAL ``evaluate_retry`` (C-24); ``reopen`` opens
    the same file again with new objects and a fresh clock at ``CLOCK_INSTANT``.
    ``close()`` rolls back every open transaction and disposes the engine.
    """

    harness: SqliteHarness
    clock: FixedClock
    identity_source: SequentialIdentitySource
    observation_ttl_seconds: int
    experiment_revision: int
    predecessor_revision: int
    successor: bool
    winners: list[RetryDecisionRecord] = field(default_factory=list)

    # -- Construction -------------------------------------------------------

    @classmethod
    def seeded_unavailable(
        cls,
        tmp_path: Path,
        *,
        observation_ttl_seconds: int = _OBSERVATION_TTL_SECONDS,
        fresh_observation: bool = True,
    ) -> RetryFixture:
        harness = SqliteHarness(open_test_database(tmp_path, clock=FixedClock(INSTANT)))
        try:
            experiment = sample_experiment(_E.RUNNING)
            predecessor = sample_run(_R.UNAVAILABLE)
            assert predecessor.availability_observation_id == AVAIL_A
            assert predecessor.updated_at_utc == _COMPLETED_AT
            harness.seed_observation(sample_observation(AVAIL_A))
            if fresh_observation:
                harness.seed_observation(_fresh_observation(observation_ttl_seconds))
            harness.seed_diagnostic(sample_diagnostic())
            put_experiment(harness, experiment)
            put_run(harness, predecessor)
        except BaseException:
            harness.close()
            raise
        return cls(
            harness=harness,
            clock=FixedClock(CLOCK_INSTANT),
            identity_source=SequentialIdentitySource("unavailable"),
            observation_ttl_seconds=observation_ttl_seconds,
            experiment_revision=experiment.revision,
            predecessor_revision=predecessor.revision,
            successor=False,
        )

    @classmethod
    def seeded_allowed(cls, tmp_path: Path, *, delay_seconds: int) -> RetryFixture:
        harness = SqliteHarness(open_test_database(tmp_path, clock=FixedClock(INSTANT)))
        try:
            policy = sample_retry_policy(retry_delay_seconds=delay_seconds)
            experiment = sample_experiment(
                _E.RUNNING, draft=sample_draft(retry_policy=policy)
            )
            predecessor = sample_run(_R.FAILED)
            assert predecessor.updated_at_utc == _COMPLETED_AT
            harness.seed_observation(sample_observation(AVAIL_A))
            harness.seed_diagnostic(sample_diagnostic())
            put_experiment(harness, experiment)
            put_run(harness, predecessor)
            fixture = cls(
                harness=harness,
                clock=FixedClock(CLOCK_INSTANT),
                identity_source=SequentialIdentitySource("allowed"),
                observation_ttl_seconds=_OBSERVATION_TTL_SECONDS,
                experiment_revision=experiment.revision,
                predecessor_revision=predecessor.revision,
                successor=False,
            )
            decision = ok(
                evaluate_retry(
                    fixture.evaluation_request,
                    unit_of_work=fixture.unit_of_work(),
                    clock=fixture.clock,
                )
            )
            assert decision.outcome is RetryDecisionOutcome.ALLOWED
            assert decision.retry_not_before_utc == _COMPLETED_AT + timedelta(
                seconds=delay_seconds
            )
        except BaseException:
            harness.close()
            raise
        fixture.experiment_revision = fixture.stored_experiment().revision
        fixture.successor = True
        return fixture

    @classmethod
    def reopen(cls, tmp_path: Path) -> RetryFixture:
        harness = SqliteHarness(open_test_database(tmp_path, clock=FixedClock(INSTANT)))
        try:
            (experiment,) = harness.committed_experiments()
            (predecessor,) = (
                run for run in harness.committed_engine_runs() if run.run_id == RUN_ID
            )
        except BaseException:
            harness.close()
            raise
        return cls(
            harness=harness,
            clock=FixedClock(CLOCK_INSTANT),
            identity_source=SequentialIdentitySource("reopened"),
            observation_ttl_seconds=_OBSERVATION_TTL_SECONDS,
            experiment_revision=experiment.revision,
            predecessor_revision=predecessor.revision,
            successor=True,
        )

    def close(self) -> None:
        self.harness.close()

    # -- Units of work ------------------------------------------------------

    @property
    def database(self) -> SqliteDatabase:
        return self.harness.database

    def unit_of_work(self) -> SqliteUnitOfWork:
        return self.harness.unit_of_work()

    def interleaving_unit_of_work(
        self, *, after_read: Callable[[], None], on_attempts: tuple[int, ...] = (1,)
    ) -> InterleavingUnitOfWork:
        return InterleavingUnitOfWork(
            self.unit_of_work(), after_read=after_read, on_attempts=on_attempts
        )

    # -- Requests -----------------------------------------------------------

    @property
    def evaluation_request(self) -> RetryEvaluationRequest:
        return RetryEvaluationRequest(
            schema_version="1.0.0",
            experiment_id=EXPERIMENT_ID,
            logical_slot_id=SLOT_A,
            predecessor_run_id=RUN_ID,
            expected_experiment_revision=self.experiment_revision,
            expected_predecessor_revision=self.predecessor_revision,
        )

    @property
    def successor_request(self) -> SuccessorCreationRequest:
        return SuccessorCreationRequest(
            schema_version="1.0.0",
            experiment_id=EXPERIMENT_ID,
            logical_slot_id=SLOT_A,
            predecessor_run_id=RUN_ID,
            expected_experiment_revision=self.experiment_revision,
            request_hash=REQUEST_HASH,
        )

    @property
    def request(self) -> Any:
        """The sketches' request: the evaluation request of an unavailable-slot
        fixture, the successor request of an allowed or reopened one."""
        if self.successor:
            return self.successor_request
        return self.evaluation_request

    # -- Winners, candidates and fresh reads --------------------------------

    def commit_fresh_winner_from_another_connection(self) -> None:
        """The REAL ``evaluate_retry`` at the base instant on a new root: ALLOWED."""
        winner = ok(
            evaluate_retry(
                self.evaluation_request,
                unit_of_work=self.unit_of_work(),
                clock=FixedClock(CLOCK_INSTANT),
            )
        )
        assert winner.outcome is RetryDecisionOutcome.ALLOWED
        self.winners.append(winner)

    def winner(self) -> RetryDecisionRecord:
        """The one durable decision, read through a fresh read-only session."""
        (stored,) = self.harness.committed_retry_decisions()
        return stored

    def candidate_at(self, instant: datetime) -> RetryDecisionRecord:
        """The candidate a phase-2 evaluation at ``instant`` would build over the
        committed rows, computed through the committed kernel over a fresh
        read transaction that is rolled back; nothing is written."""
        transaction = self.unit_of_work().begin()
        try:
            experiment = ok(transaction.experiments.get(EXPERIMENT_ID))
            predecessor = ok(transaction.engine_runs.get(RUN_ID))
            snapshot = build_retry_evaluation_snapshot(
                transaction, experiment, predecessor, now=instant
            )
        finally:
            transaction.rollback()
        assert not isinstance(snapshot, Failure), snapshot
        return evaluate_retry_gates(snapshot)

    def divergent_candidate(self) -> RetryDecisionRecord:
        """This evaluation's own candidate at the fixture's (advanced) instant."""
        return self.candidate_at(self.clock.now_utc())

    def stored_experiment(self) -> ExperimentRecord:
        (stored,) = self.harness.committed_experiments()
        return stored

    def stored_runs(self) -> tuple[EngineRunRecord, ...]:
        return self.harness.committed_engine_runs()


@pytest.fixture
def retry_fixture(tmp_path: Path) -> Iterator[RetryFixture]:
    """The unavailable-slot fixture of C-7 and C-8, closed in teardown."""
    fixture = RetryFixture.seeded_unavailable(tmp_path)
    try:
        yield fixture
    finally:
        fixture.close()


# --------------------------------------------------------------------------
# C-7 and C-8: the concurrent loser replays the durable winner by identity
# --------------------------------------------------------------------------


def test_a_divergent_concurrent_decision_replays_the_durable_winner(
    retry_fixture: RetryFixture,
) -> None:
    # The winner is committed by the hook after this evaluation's phase-1 read
    # saw the key absent; the evaluation's own candidate diverges because the
    # observation expired in between (the clock advanced before the run).
    retry_fixture.clock.advance(retry_fixture.observation_ttl_seconds + 1)
    interleaving = retry_fixture.interleaving_unit_of_work(
        after_read=retry_fixture.commit_fresh_winner_from_another_connection
    )
    outcome = evaluate_retry(
        retry_fixture.request, unit_of_work=interleaving, clock=retry_fixture.clock
    )
    assert isinstance(outcome, Success)
    winner = retry_fixture.winner()
    assert outcome.value == winner
    assert interleaving.begins == 2
    assert retry_fixture.harness.committed_retry_decisions() == (winner,)
    assert retry_decision_semantic_projection(
        winner
    ) != retry_decision_semantic_projection(retry_fixture.divergent_candidate())


def test_the_divergent_losers_candidate_was_denied_and_never_written(
    retry_fixture: RetryFixture,
) -> None:
    """C-7's companion: the loser's candidate is the gate-6 denial, the winner is
    the ALLOWED row naming the fresh observation, and only the winner's bump
    reached the experiment."""
    retry_fixture.clock.advance(retry_fixture.observation_ttl_seconds + 1)
    divergent = retry_fixture.divergent_candidate()
    assert divergent.outcome is RetryDecisionOutcome.DENIED
    assert divergent.denial_reason is (
        RetryDenialReason.AVAILABILITY_OBSERVATION_NOT_FRESH
    )
    interleaving = retry_fixture.interleaving_unit_of_work(
        after_read=retry_fixture.commit_fresh_winner_from_another_connection
    )
    outcome = ok(
        evaluate_retry(
            retry_fixture.evaluation_request,
            unit_of_work=interleaving,
            clock=retry_fixture.clock,
        )
    )
    (winner,) = retry_fixture.winners
    assert outcome == winner
    assert outcome.outcome is RetryDecisionOutcome.ALLOWED
    assert outcome.availability_observation_id == AVAIL_B
    assert outcome.decided_at_utc == CLOCK_INSTANT
    assert interleaving.begins == 2
    stored = retry_fixture.stored_experiment()
    assert stored.state is _E.RUNNING
    assert stored.revision == retry_fixture.experiment_revision + 1
    assert retry_fixture.harness.committed_retry_decisions() == (winner,)
    assert _checked_out(retry_fixture.database) == 0
    assert retry_fixture.harness.open_transactions() == ()
    assert retry_fixture.database.consistency_report() == _SCAFFOLDED_PARENT


def test_an_identical_concurrent_decision_replays_the_durable_row_once(
    retry_fixture: RetryFixture,
) -> None:
    """C-8: as C-7 with identical inputs. The loser's ALLOWED candidate swaps the
    experiment first (plan 8.4 phase 3) and that swap is what the snapshot rule
    refuses; the rerun replays the durable row after exactly two begins, and the
    projections are equal, which distinguishes this case from C-7."""
    identical = retry_fixture.candidate_at(CLOCK_INSTANT)
    assert identical.outcome is RetryDecisionOutcome.ALLOWED
    interleaving = retry_fixture.interleaving_unit_of_work(
        after_read=retry_fixture.commit_fresh_winner_from_another_connection
    )
    outcome = ok(
        evaluate_retry(
            retry_fixture.evaluation_request,
            unit_of_work=interleaving,
            clock=retry_fixture.clock,
        )
    )
    winner = retry_fixture.winner()
    assert outcome == winner
    assert interleaving.begins == 2
    assert retry_fixture.harness.committed_retry_decisions() == (winner,)
    assert retry_decision_semantic_projection(
        winner
    ) == retry_decision_semantic_projection(identical)
    # One bump, the winner's: the loser's refused swap never became durable.
    assert retry_fixture.stored_experiment().revision == (
        retry_fixture.experiment_revision + 1
    )
    assert _checked_out(retry_fixture.database) == 0


# --------------------------------------------------------------------------
# The read-set companion of C-12: a changed read set makes the rerun recompute
# --------------------------------------------------------------------------


def test_a_fresh_observation_in_the_read_set_makes_the_rerun_recompute(
    tmp_path: Path,
) -> None:
    fixture = RetryFixture.seeded_unavailable(tmp_path, fresh_observation=False)
    try:
        denied = fixture.candidate_at(CLOCK_INSTANT)
        assert denied.outcome is RetryDecisionOutcome.DENIED
        assert denied.denial_reason is (
            RetryDenialReason.AVAILABILITY_OBSERVATION_NOT_FRESH
        )
        revisions_seen_by_the_mover: list[int] = []

        def observation_lands() -> None:
            # A row enters the loser's list_for_adapter read set through the
            # persistence-owned writer; the experiment row never moves.
            transaction = fixture.unit_of_work().begin()
            ok(
                transaction.availability_observation_writer.add(
                    _fresh_observation(_OBSERVATION_TTL_SECONDS)
                )
            )
            commit(transaction)
            revisions_seen_by_the_mover.append(fixture.stored_experiment().revision)

        interleaving = fixture.interleaving_unit_of_work(after_read=observation_lands)
        outcome = ok(
            evaluate_retry(
                fixture.evaluation_request,
                unit_of_work=interleaving,
                clock=fixture.clock,
            )
        )
        assert revisions_seen_by_the_mover == [fixture.experiment_revision]
        assert interleaving.begins == 2
        # The rerun recomputed over the new observation: ALLOWED, not the DENIED
        # candidate the first attempt had built.
        assert outcome.outcome is RetryDecisionOutcome.ALLOWED
        assert outcome.availability_observation_id == AVAIL_B
        assert retry_decision_semantic_projection(
            outcome
        ) != retry_decision_semantic_projection(denied)
        assert fixture.harness.committed_retry_decisions() == (outcome,)
        assert fixture.stored_experiment().revision == fixture.experiment_revision + 1
        assert _checked_out(fixture.database) == 0
        assert fixture.database.consistency_report() == _SCAFFOLDED_PARENT
    finally:
        fixture.close()


# --------------------------------------------------------------------------
# C-24: the durable retry delay survives a reopen
# --------------------------------------------------------------------------


def test_a_durable_retry_delay_is_reused_after_reopen(tmp_path: Path) -> None:
    fixture = RetryFixture.seeded_allowed(tmp_path, delay_seconds=120)
    fixture.close()
    reopened = RetryFixture.reopen(tmp_path)
    early = create_successor(
        reopened.request,
        unit_of_work=reopened.unit_of_work(),
        clock=reopened.clock,
        identity_source=reopened.identity_source,
    )
    assert code(early) == RETRY_NOT_BEFORE_NOT_REACHED
    reopened.clock.advance(120)
    created = create_successor(
        reopened.request,
        unit_of_work=reopened.unit_of_work(),
        clock=reopened.clock,
        identity_source=reopened.identity_source,
    )
    assert isinstance(created, Success)
    assert created.value.attempt.attempt_number == 2
    reopened.close()


def test_the_reopened_successor_is_durable_and_replays_without_a_clock_or_draw(
    tmp_path: Path,
) -> None:
    """C-24's companion: the stored instant is the one refused and the one honoured;
    the successor is read back fresh; an identical replay reads no clock, draws
    no identity and writes nothing; the eight consistency counts are named."""
    fixture = RetryFixture.seeded_allowed(tmp_path, delay_seconds=120)
    decision = fixture.winner()
    not_before = _COMPLETED_AT + timedelta(seconds=120)
    assert decision.retry_not_before_utc == not_before
    fixture.close()
    reopened = RetryFixture.reopen(tmp_path)
    try:
        early = create_successor(
            reopened.successor_request,
            unit_of_work=reopened.unit_of_work(),
            clock=reopened.clock,
            identity_source=reopened.identity_source,
        )
        assert isinstance(early, Failure)
        (diagnostic,) = early.diagnostics
        assert diagnostic.error_code == RETRY_NOT_BEFORE_NOT_REACHED
        assert diagnostic.details["retry_not_before_utc"] == format_utc(not_before)
        assert diagnostic.details["now_utc"] == format_utc(CLOCK_INSTANT)
        assert len(reopened.stored_runs()) == 1
        reopened.clock.advance(120)
        assert reopened.clock.now_utc() >= not_before
        created = ok(
            create_successor(
                reopened.successor_request,
                unit_of_work=reopened.unit_of_work(),
                clock=reopened.clock,
                identity_source=reopened.identity_source,
            )
        )
        (successor,) = (run for run in reopened.stored_runs() if run.run_id != RUN_ID)
        assert successor == created.attempt
        assert successor.attempt_number == decision.reserved_successor_attempt_number
        assert successor.predecessor_run_id == RUN_ID
        assert successor.state is _R.PENDING
        assert successor.revision == 0
        stored = reopened.stored_experiment()
        assert stored.state is _E.RUNNING
        assert stored.revision == reopened.experiment_revision + 1
        # The decision row is immutable: the reopen reset nothing.
        assert reopened.winner() == decision
        # An identical replay returns the stored successor with no token, reads no
        # clock and draws no identity: a twin source drawn afterwards agrees.
        replay_clock = CountingClock(reopened.clock.now_utc())
        replay_source = SequentialIdentitySource("replay")
        replayed = ok(
            create_successor(
                reopened.successor_request,
                unit_of_work=reopened.unit_of_work(),
                clock=replay_clock,
                identity_source=replay_source,
            )
        )
        assert replayed.attempt == successor
        assert not isinstance(replayed.attempt_token, AttemptTokenMaterial)
        assert replay_clock.reads == 0
        assert (
            replay_source.new_run_id()
            == SequentialIdentitySource("replay").new_run_id()
        )
        assert len(reopened.stored_runs()) == 2
        assert reopened.stored_experiment() == stored
        assert _checked_out(reopened.database) == 0
        assert reopened.harness.open_transactions() == ()
        assert reopened.database.consistency_report() == _SCAFFOLDED_PARENT
    finally:
        reopened.close()
