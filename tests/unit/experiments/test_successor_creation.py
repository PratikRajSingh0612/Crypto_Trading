"""Stage 5 Task 7: ``create_successor`` and ``successor_is_due``.

Plan sections 3.8 (the successor's field shapes; the raw attempt token as
explicitly temporary material; a terminal record's ``updated_at_utc`` as the
instant the durable delay is measured from), 8.5 (successor creation steps 1-6:
the stored reservation, exactly one successor across restart, the
terminal-experiment rule independent of revision agreement, the durable
``retry_not_before_utc`` that restart never recomputes, the revision and
current-attempt re-check, identity drawn only after every check), 8.6 (the codes),
9.5 rows 3-4 (cancellation against successor creation in both orderings, and the
atomicity list) and 12 Task 7, read through the Task 7 service API contract: D8
(``successor_is_due`` is pure and ``>=``), D9 (``create_successor`` order S0-S6,
the lazy per-attempt clock memo, replay before the terminal rule, the loser
contracts via the reload), D10 (the reused ``AttemptCreation`` return shape) and
the adopted cross-check notes (one hook per scenario, service-only clocks, the
losing attempt's draw before its ``LostSwap``).

Every case here fails at collection until Task 7's module
``crypto_lab.experiments.retry`` exists -- that is the intended RED. Every case
drives the service through the ROOT in-memory unit of work (the service calls
``begin()`` itself), seeds rows through a transaction of its own and inspects the
backing store's committed rows, so a rejected operation is proven to write
nothing. The read-discipline clocks (``CountingClock``, ``FailingClock``) are
injected into the SERVICE only; the root keeps its default clock. Races are
simulated deterministically through the double's one-shot experiment
compare-and-swap hook -- the only hook ``create_successor`` reaches -- installed
exactly once per scenario; nothing here sleeps, starts a thread or draws a random
value.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import pytest
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.engine_run import AttemptTokenMaterial, EngineRunRecord
from crypto_lab.domain.experiment import ExperimentRecord
from crypto_lab.domain.hashing import attempt_token_hash
from crypto_lab.domain.lifecycle import (
    EngineRunState,
    ExperimentState,
    RetryTerminalState,
)
from crypto_lab.domain.ports import Clock, IdentitySource
from crypto_lab.domain.results import Failure, Success
from crypto_lab.domain.retry import (
    RetryDecisionOutcome,
    RetryDecisionRecord,
    retry_terminal_state_of,
)
from crypto_lab.domain.time import format_utc
from crypto_lab.experiments.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
    RETRY_NOT_BEFORE_NOT_REACHED,
    stage5_failure,
)
from crypto_lab.experiments.experiment_service import cancel_experiment
from crypto_lab.experiments.ports import UnitOfWork
from crypto_lab.experiments.requests import (
    CancelExperimentRequest,
    RetryEvaluationRequest,
    SuccessorCreationRequest,
)
from crypto_lab.experiments.retry import (
    create_successor,
    evaluate_retry,
    successor_is_due,
)
from crypto_lab.experiments.run_service import AttemptCreation
from doubles.experiments import (
    ADAPTER_ALPHA,
    ADAPTER_BETA,
    ENGINE_ALPHA,
    EXPERIMENT_ID,
    INSTANT,
    OTHER_DIAG_ID,
    OTHER_EXPERIMENT_ID,
    OTHER_REQUEST_HASH,
    OTHER_RUN_ID,
    REQUEST_HASH,
    RUN_ID,
    SLOT_A,
    SLOT_B,
    SLOT_C,
    THIRD_RUN_ID,
    CallRecorder,
    CountingClock,
    FailingClock,
    FixedClock,
    InMemoryBackingStore,
    InMemoryUnitOfWork,
    MemberOverridingUnitOfWork,
    RecordingUnitOfWork,
    SequentialIdentitySource,
    sample_allowed_retry_decision,
    sample_diagnostic,
    sample_experiment,
    sample_retry_decision,
    sample_run,
)

_E = ExperimentState
_R = EngineRunState

#: The fixture decision's stored ``retry_not_before_utc``: the predecessor's terminal
#: completion instant (``INSTANT`` + 5 s, plan 3.8) plus the policy delay (30 s).
DUE_INSTANT = INSTANT + timedelta(seconds=35)
#: One second before the stored instant: not yet due (specification 7.2 ``>=``).
BEFORE_INSTANT = DUE_INSTANT - timedelta(seconds=1)
#: Well past every fixture instant, for the "after the instant" cases.
LATER_INSTANT = INSTANT + timedelta(minutes=1)
#: The identity seed of the service under test when no other seed is named.
SEED = "task7"


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _missing(value: object) -> bool:
    return value is MISSING


def _code(result: object) -> str:
    assert isinstance(result, Failure)
    assert len(result.diagnostics) == 1
    return result.diagnostics[0].error_code


def _ok[T](result: Success[T] | Failure) -> T:
    assert isinstance(result, Success), result
    return result.value


def _commit(unit_of_work: InMemoryUnitOfWork) -> None:
    committed = unit_of_work.commit()
    assert isinstance(committed, Success), committed


def _seed(
    store: InMemoryBackingStore,
    *records: ExperimentRecord | EngineRunRecord | RetryDecisionRecord,
) -> None:
    """Commit the seed rows through a transaction of the test's own."""
    transaction = InMemoryUnitOfWork(store).begin()
    for record in records:
        if isinstance(record, ExperimentRecord):
            _ok(transaction.experiments.add(record))
        elif isinstance(record, EngineRunRecord):
            _ok(transaction.engine_runs.add_attempt(record))
        else:
            inserted = _ok(transaction.retry_decisions.insert_if_absent(record))
            assert inserted.inserted
    _commit(transaction)


def _by_run_id(*records: EngineRunRecord) -> tuple[EngineRunRecord, ...]:
    """The store's committed order: sorted by ``run_id``."""
    return tuple(sorted(records, key=lambda record: record.run_id))


class CountingIdentitySource(SequentialIdentitySource):
    """A ``SequentialIdentitySource`` that counts every draw, so a test can pin zero
    (plan 8.5 step 6: "replay consumes nothing")."""

    def __init__(self, seed: str = SEED) -> None:
        super().__init__(seed)
        self.draws = 0

    def new_run_id(self) -> str:
        self.draws += 1
        return super().new_run_id()

    def new_attempt_token(self) -> str:
        self.draws += 1
        return super().new_attempt_token()


@dataclass(frozen=True, slots=True)
class _Slot:
    """One seeded slot: the experiment, its terminal predecessor and the decision."""

    store: InMemoryBackingStore
    experiment: ExperimentRecord
    predecessor: EngineRunRecord
    decision: RetryDecisionRecord


def _seeded(
    *,
    experiment: ExperimentRecord | None = None,
    predecessor: EngineRunRecord | None = None,
    decision: RetryDecisionRecord | None = None,
    extra_runs: tuple[EngineRunRecord, ...] = (),
) -> _Slot:
    """Seed a RUNNING experiment at revision 3, attempt 1 of SLOT_A FAILED at
    revision 5 and the ALLOWED decision reserving attempt 2 (unless overridden)."""
    experiment = sample_experiment(_E.RUNNING) if experiment is None else experiment
    predecessor = sample_run(_R.FAILED) if predecessor is None else predecessor
    if decision is None:
        decision = sample_allowed_retry_decision(
            experiment_spec_hash=experiment.spec_hash
        )
    store = InMemoryBackingStore()
    _seed(store, experiment, predecessor, decision, *extra_runs)
    return _Slot(store, experiment, predecessor, decision)


def _assert_nothing_written(slot: _Slot, *extra_runs: EngineRunRecord) -> None:
    """Every committed row is exactly a seeded row."""
    assert slot.store.committed_experiments() == (slot.experiment,)
    assert slot.store.committed_engine_runs() == _by_run_id(
        slot.predecessor, *extra_runs
    )
    assert slot.store.committed_retry_decisions() == (slot.decision,)


def _request(
    *,
    expected_revision: int,
    request_hash: str = REQUEST_HASH,
    predecessor_run_id: str = RUN_ID,
    experiment_id: str = EXPERIMENT_ID,
) -> SuccessorCreationRequest:
    return SuccessorCreationRequest(
        schema_version="1.0.0",
        experiment_id=experiment_id,
        logical_slot_id=SLOT_A,
        predecessor_run_id=predecessor_run_id,
        expected_experiment_revision=expected_revision,
        request_hash=request_hash,
    )


def _cancel_request(
    *, expected_revision: int, correlation_id: str = "cancel-1"
) -> CancelExperimentRequest:
    return CancelExperimentRequest(
        schema_version="1.0.0",
        experiment_id=EXPERIMENT_ID,
        expected_revision=expected_revision,
        correlation_id=correlation_id,
    )


def _evaluation_request(
    *,
    predecessor: EngineRunRecord,
    expected_experiment_revision: int,
) -> RetryEvaluationRequest:
    return RetryEvaluationRequest(
        schema_version="1.0.0",
        experiment_id=EXPERIMENT_ID,
        logical_slot_id=SLOT_A,
        predecessor_run_id=predecessor.run_id,
        expected_experiment_revision=expected_experiment_revision,
        expected_predecessor_revision=predecessor.revision,
    )


def _create(
    store: InMemoryBackingStore,
    request: SuccessorCreationRequest,
    *,
    clock: Clock | None = None,
    identity_source: IdentitySource | None = None,
    seed: str = SEED,
    root: UnitOfWork | None = None,
) -> Success[AttemptCreation] | Failure:
    """Drive ``create_successor`` through a root unit of work at the due instant."""
    return create_successor(
        request,
        unit_of_work=InMemoryUnitOfWork(store) if root is None else root,
        clock=FixedClock(DUE_INSTANT) if clock is None else clock,
        identity_source=(
            SequentialIdentitySource(seed)
            if identity_source is None
            else identity_source
        ),
    )


def _created(slot: _Slot, *, seed: str = SEED) -> AttemptCreation:
    """The accepted first creation over ``slot`` at the due instant."""
    return _ok(
        _create(
            slot.store, _request(expected_revision=slot.experiment.revision), seed=seed
        )
    )


def _replaced(
    stored: ExperimentRecord, *, state: ExperimentState | None = None
) -> ExperimentRecord:
    """The record another writer commits over ``stored``: revision + 1 at the due
    instant, in ``state`` (default: the same state, a state-preserving bump)."""
    payload = stored.model_dump(mode="python")
    if state is not None:
        payload["state"] = state
    payload["updated_at_utc"] = DUE_INSTANT
    payload["revision"] = stored.revision + 1
    return ExperimentRecord.model_validate(payload)


def _rebuilt_slot_reads(
    store: InMemoryBackingStore,
) -> tuple[object, object]:
    """``get_by_attempt_number(.., 2)`` and ``latest_attempt`` via a rebuilt root."""
    reader = InMemoryUnitOfWork(store).begin()
    by_number = _ok(reader.engine_runs.get_by_attempt_number(EXPERIMENT_ID, SLOT_A, 2))
    latest = _ok(reader.engine_runs.latest_attempt(EXPERIMENT_ID, SLOT_A))
    reader.rollback()
    return by_number, latest


# --------------------------------------------------------------------------
# A. successor_is_due (contract D8; specification 7.2)
# --------------------------------------------------------------------------


def test_a_denied_decision_is_never_due() -> None:
    denied = sample_retry_decision()
    assert denied.outcome is RetryDecisionOutcome.DENIED
    assert not successor_is_due(denied, now=INSTANT)
    assert not successor_is_due(denied, now=DUE_INSTANT)
    assert not successor_is_due(denied, now=INSTANT + timedelta(days=365))


def test_an_allowed_decision_is_due_exactly_from_its_stored_instant() -> None:
    decision = sample_allowed_retry_decision()
    assert decision.retry_not_before_utc == DUE_INSTANT
    assert not successor_is_due(decision, now=BEFORE_INSTANT)
    assert successor_is_due(decision, now=DUE_INSTANT)
    assert successor_is_due(decision, now=DUE_INSTANT + timedelta(seconds=1))
    assert successor_is_due(decision, now=LATER_INSTANT)


def test_a_naive_now_is_rejected() -> None:
    decision = sample_allowed_retry_decision()
    naive = DUE_INSTANT.replace(tzinfo=None)
    with pytest.raises(ValueError, match="UTC"):
        successor_is_due(decision, now=naive)


# --------------------------------------------------------------------------
# B. Due-ness through create_successor (plan 8.5 step 4; contract D9 S4)
# --------------------------------------------------------------------------


def test_one_second_before_the_instant_is_not_before_not_reached_with_no_write() -> (
    None
):
    slot = _seeded()
    clock = CountingClock(BEFORE_INSTANT)
    identity = CountingIdentitySource()
    result = _create(
        slot.store,
        _request(expected_revision=slot.experiment.revision),
        clock=clock,
        identity_source=identity,
    )
    assert _code(result) == RETRY_NOT_BEFORE_NOT_REACHED
    assert isinstance(result, Failure)
    (diagnostic,) = result.diagnostics
    assert diagnostic.details["retry_not_before_utc"] == format_utc(
        slot.decision.retry_not_before_utc
    )
    assert diagnostic.details["now_utc"] == format_utc(BEFORE_INSTANT)
    assert diagnostic.experiment_id == EXPERIMENT_ID
    assert diagnostic.run_id == RUN_ID
    assert clock.reads == 1
    assert identity.draws == 0
    _assert_nothing_written(slot)


@pytest.mark.parametrize("seconds_after", [0, 1, 25])
def test_at_or_after_the_stored_instant_the_successor_is_created(
    seconds_after: int,
) -> None:
    slot = _seeded()
    now = DUE_INSTANT + timedelta(seconds=seconds_after)
    creation = _ok(
        _create(
            slot.store,
            _request(expected_revision=slot.experiment.revision),
            clock=FixedClock(now),
        )
    )
    assert creation.attempt.attempt_number == 2
    assert creation.attempt.created_at_utc == now
    assert isinstance(creation.attempt_token, AttemptTokenMaterial)
    assert len(slot.store.committed_engine_runs()) == 2


# --------------------------------------------------------------------------
# C. Initial insertion (plan 8.5 step 6, 3.8; contract D9 S6, D10)
# --------------------------------------------------------------------------


def test_the_successor_is_attempt_two_linked_to_the_predecessor_at_revision_zero() -> (
    None
):
    slot = _seeded()
    creation = _created(slot)
    successor = creation.attempt
    expected_identity = SequentialIdentitySource(SEED)
    assert successor.run_id == expected_identity.new_run_id()
    assert successor.run_id != RUN_ID
    assert successor.experiment_id == EXPERIMENT_ID
    assert successor.logical_slot_id == SLOT_A
    assert successor.attempt_number == 2
    assert successor.attempt_number == slot.decision.reserved_successor_attempt_number
    assert successor.predecessor_run_id == RUN_ID
    assert successor.retry_reason is RetryTerminalState.FAILED
    assert successor.retry_reason is retry_terminal_state_of(slot.predecessor.state)
    assert successor.adapter == slot.predecessor.adapter == ADAPTER_ALPHA
    assert successor.engine == slot.predecessor.engine == ENGINE_ALPHA
    assert successor.request_hash == REQUEST_HASH
    assert successor.state is _R.PENDING
    assert successor.revision == 0
    assert successor.created_at_utc == DUE_INSTANT
    assert successor.updated_at_utc == DUE_INSTANT
    assert _missing(successor.primary_terminal_diagnostic_id)
    assert _missing(successor.availability_observation_id)
    assert _missing(successor.finalization_deadline_utc)
    token = creation.attempt_token
    assert isinstance(token, AttemptTokenMaterial)
    assert token.run_id == successor.run_id
    assert token.attempt_token == expected_identity.new_attempt_token()
    assert successor.attempt_token_hash == attempt_token_hash(token.attempt_token)
    assert successor.attempt_token_hash != slot.predecessor.attempt_token_hash
    assert slot.store.committed_engine_runs() == _by_run_id(slot.predecessor, successor)


def test_the_experiment_is_bumped_in_place_and_stays_running() -> None:
    slot = _seeded()
    creation = _created(slot)
    experiment = creation.experiment
    assert experiment.revision == slot.experiment.revision + 1 == 4
    assert experiment.state is _E.RUNNING
    assert experiment.updated_at_utc == DUE_INSTANT
    assert experiment.created_at_utc == slot.experiment.created_at_utc
    assert experiment.spec == slot.experiment.spec
    assert experiment.spec_hash == slot.experiment.spec_hash
    assert experiment.slot_compatibility == slot.experiment.slot_compatibility
    assert _missing(experiment.cancellation_correlation_id)
    assert slot.store.committed_experiments() == (experiment,)


def test_the_decision_row_is_byte_identical_after_successor_creation() -> None:
    slot = _seeded()
    (before,) = slot.store.committed_retry_decisions()
    before_bytes = canonical_json_bytes(before)
    _created(slot)
    (after,) = slot.store.committed_retry_decisions()
    assert after == slot.decision
    assert canonical_json_bytes(after) == before_bytes
    assert canonical_json_bytes(after) == canonical_json_bytes(slot.decision)
    # There is no successor pointer to mutate: the successor is discovered by
    # reserved attempt number and by its own predecessor_run_id.
    assert "successor_run_id" not in RetryDecisionRecord.model_fields


def test_the_successor_is_discoverable_by_number_and_as_the_latest_attempt() -> None:
    slot = _seeded()
    successor = _created(slot).attempt
    by_number, latest = _rebuilt_slot_reads(slot.store)
    assert by_number == successor
    assert latest == successor
    assert isinstance(latest, EngineRunRecord)
    assert latest.predecessor_run_id == slot.predecessor.run_id


# --------------------------------------------------------------------------
# D. Replay and conflict (plan 8.5 steps 1-3, 5; contract D9 S0-S3, S5)
# --------------------------------------------------------------------------


def test_identical_replay_returns_the_successor_without_clock_draw_or_write() -> None:
    slot = _seeded()
    request = _request(expected_revision=slot.experiment.revision)
    first = _ok(_create(slot.store, request))
    recorder = CallRecorder()
    root = RecordingUnitOfWork(InMemoryUnitOfWork(slot.store), recorder)
    identity = CountingIdentitySource("other")
    replay = _ok(
        create_successor(
            request,
            unit_of_work=root,
            clock=FailingClock(),
            identity_source=identity,
        )
    )
    assert replay.attempt == first.attempt
    assert _missing(replay.attempt_token)
    assert replay.experiment == first.experiment
    assert replay.experiment.revision == 4
    assert identity.draws == 0
    repository_calls = recorder.repositories()
    assert ("engine_runs", "add_attempt") not in repository_calls
    assert ("experiments", "compare_and_swap") not in repository_calls
    assert ("retry_decisions", "insert_if_absent") not in repository_calls
    assert slot.store.committed_experiments() == (first.experiment,)
    assert slot.store.committed_engine_runs() == _by_run_id(
        slot.predecessor, first.attempt
    )


def test_a_divergent_duplicate_is_a_conflict_that_leaves_the_winner_untouched() -> None:
    existing = sample_run(
        _R.PENDING,
        run_id=OTHER_RUN_ID,
        attempt_number=2,
        predecessor_run_id=RUN_ID,
        request_hash=OTHER_REQUEST_HASH,
    )
    slot = _seeded(extra_runs=(existing,))
    identity = CountingIdentitySource()
    result = _create(
        slot.store,
        _request(expected_revision=slot.experiment.revision),
        identity_source=identity,
    )
    assert _code(result) == CONCURRENCY_CONFLICT
    assert identity.draws == 0
    _assert_nothing_written(slot, existing)


def test_a_missing_decision_row_is_the_repository_invariant_violation() -> None:
    store = InMemoryBackingStore()
    experiment = sample_experiment(_E.RUNNING)
    predecessor = sample_run(_R.FAILED)
    _seed(store, experiment, predecessor)
    clock = CountingClock(DUE_INSTANT)
    identity = CountingIdentitySource()
    result = _create(
        store,
        _request(expected_revision=experiment.revision),
        clock=clock,
        identity_source=identity,
    )
    assert _code(result) == INVARIANT_VIOLATION
    # A repository passthrough: the double stamps its own diagnostic, so the
    # service reads no clock and draws no identity.
    assert clock.reads == 0
    assert identity.draws == 0
    assert store.committed_experiments() == (experiment,)
    assert store.committed_engine_runs() == (predecessor,)
    assert store.committed_retry_decisions() == ()


def test_a_denied_decision_reserves_no_successor() -> None:
    slot = _seeded(decision=sample_retry_decision())
    assert slot.decision.outcome is RetryDecisionOutcome.DENIED
    result = _create(
        slot.store,
        _request(expected_revision=slot.experiment.revision),
        clock=FixedClock(LATER_INSTANT),
    )
    assert _code(result) == INVARIANT_VIOLATION
    _assert_nothing_written(slot)


def test_a_decision_keyed_to_another_experiment_is_an_invariant_violation() -> None:
    experiment = sample_experiment(_E.RUNNING)
    foreign = sample_allowed_retry_decision(
        experiment_id=OTHER_EXPERIMENT_ID, experiment_spec_hash=experiment.spec_hash
    )
    slot = _seeded(experiment=experiment, decision=foreign)
    result = _create(slot.store, _request(expected_revision=experiment.revision))
    assert _code(result) == INVARIANT_VIOLATION
    _assert_nothing_written(slot)


@pytest.mark.parametrize("state", [_E.CANCELLED, _E.COMPLETED])
def test_a_terminal_experiment_blocks_successor_creation_at_its_current_revision(
    state: ExperimentState,
) -> None:
    # Plan 8.5 step 3: independent of revision agreement and of the clock.
    slot = _seeded(experiment=sample_experiment(state))
    assert slot.experiment.revision == 4
    result = _create(
        slot.store,
        _request(expected_revision=slot.experiment.revision),
        clock=FixedClock(LATER_INSTANT),
    )
    assert _code(result) == INVARIANT_VIOLATION
    _assert_nothing_written(slot)


def test_an_existing_successor_replays_even_after_cancellation() -> None:
    # Plan 8.5 step 2 precedes step 3: the exactly-one-successor guarantee holds
    # across restart and after the experiment left RUNNING.
    cancelled = sample_experiment(_E.CANCELLED, include_compatibility=True)
    successor = sample_run(
        _R.PENDING, run_id=OTHER_RUN_ID, attempt_number=2, predecessor_run_id=RUN_ID
    )
    slot = _seeded(experiment=cancelled, extra_runs=(successor,))
    identity = CountingIdentitySource()
    creation = _ok(
        _create(
            slot.store,
            _request(expected_revision=cancelled.revision),
            clock=FailingClock(),
            identity_source=identity,
        )
    )
    assert creation.attempt == successor
    assert creation.experiment == cancelled
    assert _missing(creation.attempt_token)
    assert identity.draws == 0
    _assert_nothing_written(slot, successor)


@pytest.mark.parametrize("revision_offset", [-1, 1])
def test_a_stale_expected_experiment_revision_is_a_conflict_with_no_write(
    revision_offset: int,
) -> None:
    slot = _seeded()
    result = _create(
        slot.store,
        _request(expected_revision=slot.experiment.revision + revision_offset),
    )
    assert _code(result) == CONCURRENCY_CONFLICT
    _assert_nothing_written(slot)


def test_a_decision_whose_terminal_state_disagrees_with_the_run_is_rejected() -> None:
    # Defensive (contract D9 S5): a terminal run is immutable, so the stored
    # decision's predecessor_terminal_state can disagree only through a defect.
    experiment = sample_experiment(_E.RUNNING)
    disagreeing = sample_allowed_retry_decision(
        predecessor_terminal_state=_R.TIMED_OUT,
        experiment_spec_hash=experiment.spec_hash,
    )
    slot = _seeded(experiment=experiment, decision=disagreeing)
    assert slot.predecessor.state is _R.FAILED
    result = _create(slot.store, _request(expected_revision=experiment.revision))
    assert _code(result) == INVARIANT_VIOLATION
    _assert_nothing_written(slot)


def test_a_predecessor_whose_adapter_differs_from_the_spec_slot_is_rejected() -> None:
    slot = _seeded(predecessor=sample_run(_R.FAILED, adapter=ADAPTER_BETA))
    result = _create(slot.store, _request(expected_revision=slot.experiment.revision))
    assert _code(result) == INVARIANT_VIOLATION
    _assert_nothing_written(slot)


def test_a_predecessor_that_is_no_longer_the_latest_attempt_is_a_conflict() -> None:
    # Attempt 3 exists (linked to another predecessor) while the reserved attempt
    # 2 is absent: plan 8.5 step 5's current-attempt re-check answers.
    later = sample_run(
        _R.PENDING,
        run_id=THIRD_RUN_ID,
        attempt_number=3,
        predecessor_run_id=OTHER_RUN_ID,
    )
    slot = _seeded(extra_runs=(later,))
    result = _create(slot.store, _request(expected_revision=slot.experiment.revision))
    assert _code(result) == CONCURRENCY_CONFLICT
    _assert_nothing_written(slot, later)


# --------------------------------------------------------------------------
# E. Contention through the experiment compare-and-swap hook (plan 9.5 rows 3-4,
#    the atomicity list; contract D9 loser contracts, reload-once)
# --------------------------------------------------------------------------


def test_a_cancellation_winner_leaves_no_successor_durable() -> None:
    # Plan 9.5 row 3: insertion rolled back; the reload shows CANCELLED; 8.5 step 3.
    slot = _seeded()
    root = InMemoryUnitOfWork(slot.store)
    winners: list[ExperimentRecord] = []

    def cancel_winner(expected_revision: int, _candidate: ExperimentRecord) -> None:
        assert expected_revision == slot.experiment.revision
        winners.append(
            _ok(
                cancel_experiment(
                    _cancel_request(
                        expected_revision=expected_revision, correlation_id="winner"
                    ),
                    unit_of_work=InMemoryUnitOfWork(slot.store),
                    clock=FixedClock(DUE_INSTANT),
                )
            )
        )

    root.install_experiment_compare_and_swap_hook(cancel_winner)
    clock = CountingClock(DUE_INSTANT)
    result = _create(
        slot.store,
        _request(expected_revision=slot.experiment.revision),
        clock=clock,
        root=root,
    )
    assert _code(result) == INVARIANT_VIOLATION
    (winner,) = winners
    assert winner.state is _E.CANCELLED
    assert winner.revision == 4
    assert winner.cancellation_correlation_id == "winner"
    assert slot.store.committed_experiments() == (winner,)
    assert slot.store.committed_engine_runs() == (slot.predecessor,)
    assert slot.store.committed_retry_decisions() == (slot.decision,)
    # One clock read per attempt: the due-ness check, then the reload's diagnostic.
    assert clock.reads == 2
    assert root.hooks_installed == ()


def test_a_stale_cancellation_after_a_successor_winner_returns_the_conflict() -> None:
    # Plan 9.5 row 4: the reload shows RUNNING at N+1; 9.1 step 4 -> CONFLICT; the
    # caller may cancel again at N+1.
    slot = _seeded()
    root = InMemoryUnitOfWork(slot.store)
    winners: list[AttemptCreation] = []

    def successor_winner(_expected_revision: int, _candidate: ExperimentRecord) -> None:
        winners.append(
            _ok(
                _create(
                    slot.store,
                    _request(expected_revision=slot.experiment.revision),
                    seed="winner",
                )
            )
        )

    root.install_experiment_compare_and_swap_hook(successor_winner)
    result = cancel_experiment(
        _cancel_request(expected_revision=slot.experiment.revision),
        unit_of_work=root,
        clock=FixedClock(DUE_INSTANT),
    )
    assert _code(result) == CONCURRENCY_CONFLICT
    (winner,) = winners
    assert winner.experiment.state is _E.RUNNING
    assert winner.experiment.revision == 4
    assert slot.store.committed_experiments() == (winner.experiment,)
    assert slot.store.committed_engine_runs() == _by_run_id(
        slot.predecessor, winner.attempt
    )
    assert root.hooks_installed == ()
    cancelled = _ok(
        cancel_experiment(
            _cancel_request(expected_revision=winner.experiment.revision),
            unit_of_work=InMemoryUnitOfWork(slot.store),
            clock=FixedClock(DUE_INSTANT),
        )
    )
    assert cancelled.state is _E.CANCELLED
    assert cancelled.revision == 5
    assert slot.store.committed_experiments() == (cancelled,)


def test_an_identical_successor_winner_turns_the_loser_into_a_replay() -> None:
    slot = _seeded()
    root = InMemoryUnitOfWork(slot.store)
    winners: list[AttemptCreation] = []

    def successor_winner(_expected_revision: int, _candidate: ExperimentRecord) -> None:
        winners.append(
            _ok(
                _create(
                    slot.store,
                    _request(expected_revision=slot.experiment.revision),
                    seed="winner",
                )
            )
        )

    root.install_experiment_compare_and_swap_hook(successor_winner)
    clock = CountingClock(DUE_INSTANT)
    creation = _ok(
        _create(
            slot.store,
            _request(expected_revision=slot.experiment.revision),
            clock=clock,
            seed="loser",
            root=root,
        )
    )
    (winner,) = winners
    assert creation.attempt == winner.attempt
    assert creation.attempt.run_id == SequentialIdentitySource("winner").new_run_id()
    assert creation.attempt.run_id != SequentialIdentitySource("loser").new_run_id()
    assert _missing(creation.attempt_token)
    assert creation.experiment == winner.experiment
    assert creation.experiment.revision == 4
    assert slot.store.committed_experiments() == (winner.experiment,)
    assert slot.store.committed_engine_runs() == _by_run_id(
        slot.predecessor, winner.attempt
    )
    assert len(slot.store.committed_engine_runs()) == 2
    # The losing attempt read the clock once; the reload replayed without a read.
    assert clock.reads == 1
    assert root.hooks_installed == ()


def test_a_divergent_successor_winner_makes_the_loser_conflict() -> None:
    slot = _seeded()
    root = InMemoryUnitOfWork(slot.store)
    winners: list[AttemptCreation] = []

    def successor_winner(_expected_revision: int, _candidate: ExperimentRecord) -> None:
        winners.append(
            _ok(
                _create(
                    slot.store,
                    _request(
                        expected_revision=slot.experiment.revision,
                        request_hash=OTHER_REQUEST_HASH,
                    ),
                    seed="winner",
                )
            )
        )

    root.install_experiment_compare_and_swap_hook(successor_winner)
    result = _create(
        slot.store,
        _request(expected_revision=slot.experiment.revision),
        seed="loser",
        root=root,
    )
    assert _code(result) == CONCURRENCY_CONFLICT
    (winner,) = winners
    assert winner.attempt.request_hash == OTHER_REQUEST_HASH
    assert winner.experiment.revision == 4
    assert slot.store.committed_experiments() == (winner.experiment,)
    assert slot.store.committed_engine_runs() == _by_run_id(
        slot.predecessor, winner.attempt
    )
    assert root.hooks_installed == ()


def test_a_terminal_aggregation_winner_leaves_no_successor_durable() -> None:
    # Simulated through the experiment repository: no application sequence makes
    # aggregation write-ready while an ALLOWED retry is eligible (plan 9.5).
    slot = _seeded()
    completed = _replaced(slot.experiment, state=_E.COMPLETED)
    root = InMemoryUnitOfWork(slot.store)
    fired: list[int] = []

    def aggregation_winner(
        expected_revision: int, _candidate: ExperimentRecord
    ) -> None:
        fired.append(expected_revision)
        winner = InMemoryUnitOfWork(slot.store).begin()
        _ok(winner.experiments.compare_and_swap(expected_revision, completed))
        _commit(winner)

    root.install_experiment_compare_and_swap_hook(aggregation_winner)
    result = _create(
        slot.store, _request(expected_revision=slot.experiment.revision), root=root
    )
    assert _code(result) == INVARIANT_VIOLATION
    assert fired == [slot.experiment.revision]
    assert slot.store.committed_experiments() == (completed,)
    assert slot.store.committed_engine_runs() == (slot.predecessor,)
    assert slot.store.committed_retry_decisions() == (slot.decision,)
    assert root.hooks_installed == ()


def test_a_state_preserving_bump_by_another_writer_is_a_conflict_then_succeeds() -> (
    None
):
    slot = _seeded()
    bumped = _replaced(slot.experiment)
    assert bumped.state is _E.RUNNING
    root = InMemoryUnitOfWork(slot.store)

    def bump_winner(expected_revision: int, _candidate: ExperimentRecord) -> None:
        winner = InMemoryUnitOfWork(slot.store).begin()
        _ok(winner.experiments.compare_and_swap(expected_revision, bumped))
        _commit(winner)

    root.install_experiment_compare_and_swap_hook(bump_winner)
    result = _create(
        slot.store, _request(expected_revision=slot.experiment.revision), root=root
    )
    assert _code(result) == CONCURRENCY_CONFLICT
    assert slot.store.committed_experiments() == (bumped,)
    assert slot.store.committed_engine_runs() == (slot.predecessor,)
    assert root.hooks_installed == ()
    retried = _ok(_create(slot.store, _request(expected_revision=bumped.revision)))
    assert retried.attempt.attempt_number == 2
    assert retried.experiment.revision == 5
    assert slot.store.committed_engine_runs() == _by_run_id(
        slot.predecessor, retried.attempt
    )


def test_a_raw_winner_on_the_attempt_index_is_replayed_after_the_commit_fails() -> None:
    # "Experiment replacement staged, successor insert collides": the raw winner
    # inserts attempt 2 WITHOUT bumping the experiment while the loser's bump is
    # already staged; the loser's commit fails on the attempt index, it reloads
    # and replays the winner's row, and the staged bump never persists.
    slot = _seeded()
    raw = sample_run(
        _R.PENDING, run_id=OTHER_RUN_ID, attempt_number=2, predecessor_run_id=RUN_ID
    )
    assert raw.request_hash == REQUEST_HASH
    root = InMemoryUnitOfWork(slot.store)

    def raw_winner(_expected_revision: int, _candidate: ExperimentRecord) -> None:
        winner = InMemoryUnitOfWork(slot.store).begin()
        _ok(winner.engine_runs.add_attempt(raw))
        _commit(winner)

    root.install_experiment_compare_and_swap_hook(raw_winner)
    creation = _ok(
        _create(
            slot.store,
            _request(expected_revision=slot.experiment.revision),
            seed="loser",
            root=root,
        )
    )
    assert creation.attempt == raw
    assert _missing(creation.attempt_token)
    assert creation.experiment == slot.experiment
    assert creation.experiment.revision == 3
    assert slot.store.committed_experiments() == (slot.experiment,)
    assert slot.store.committed_engine_runs() == _by_run_id(slot.predecessor, raw)
    assert root.hooks_installed == ()


# --------------------------------------------------------------------------
# F. Exactly one successor, restart and the durable delay (plan 8.5 steps 2, 4;
#    plan 12 Task 7)
# --------------------------------------------------------------------------


def test_repeated_invocations_produce_exactly_one_successor_and_no_further_draw() -> (
    None
):
    slot = _seeded()
    request = _request(expected_revision=slot.experiment.revision)
    first = _ok(_create(slot.store, request))
    second = _ok(_create(slot.store, request))
    fresh_identity = CountingIdentitySource("fresh")
    third = _ok(
        create_successor(
            request,
            unit_of_work=InMemoryUnitOfWork(slot.store),
            clock=FixedClock(LATER_INSTANT),
            identity_source=fresh_identity,
        )
    )
    assert first.attempt == second.attempt == third.attempt
    assert third.attempt.run_id == SequentialIdentitySource(SEED).new_run_id()
    assert isinstance(first.attempt_token, AttemptTokenMaterial)
    assert _missing(second.attempt_token)
    assert _missing(third.attempt_token)
    assert fresh_identity.draws == 0
    assert first.experiment == second.experiment == third.experiment
    assert third.experiment.revision == 4
    assert slot.store.committed_engine_runs() == _by_run_id(
        slot.predecessor, first.attempt
    )
    assert slot.store.committed_experiments() == (third.experiment,)


def test_the_durable_delay_survives_a_rebuilt_service_over_the_same_store() -> None:
    slot = _seeded()
    request = _request(expected_revision=slot.experiment.revision)
    clock = FixedClock(DUE_INSTANT - timedelta(seconds=10))
    for _restart in range(2):
        result = create_successor(
            request,
            unit_of_work=InMemoryUnitOfWork(slot.store),
            clock=clock,
            identity_source=SequentialIdentitySource(SEED),
        )
        assert _code(result) == RETRY_NOT_BEFORE_NOT_REACHED
        assert isinstance(result, Failure)
        (diagnostic,) = result.diagnostics
        # The STORED instant, never recomputed or restarted.
        assert diagnostic.details["retry_not_before_utc"] == format_utc(DUE_INSTANT)
        assert slot.store.committed_retry_decisions() == (slot.decision,)
        _assert_nothing_written(slot)
    clock.advance(10)
    assert clock.now_utc() == DUE_INSTANT
    creation = _ok(
        create_successor(
            request,
            unit_of_work=InMemoryUnitOfWork(slot.store),
            clock=clock,
            identity_source=SequentialIdentitySource(SEED),
        )
    )
    assert creation.attempt.attempt_number == 2
    assert creation.attempt.created_at_utc == DUE_INSTANT
    assert slot.store.committed_retry_decisions() == (slot.decision,)


def test_evaluate_retry_then_create_successor_end_to_end_over_one_store() -> None:
    store = InMemoryBackingStore()
    experiment = sample_experiment(_E.RUNNING)
    predecessor = sample_run(_R.FAILED)
    store.seed_diagnostic(sample_diagnostic())
    _seed(store, experiment, predecessor)
    decided_at = INSTANT + timedelta(seconds=10)
    decision = _ok(
        evaluate_retry(
            _evaluation_request(
                predecessor=predecessor,
                expected_experiment_revision=experiment.revision,
            ),
            unit_of_work=InMemoryUnitOfWork(store),
            clock=FixedClock(decided_at),
        )
    )
    assert decision.outcome is RetryDecisionOutcome.ALLOWED
    assert decision.reserved_successor_attempt_number == 2
    assert decision.retry_not_before_utc == predecessor.updated_at_utc + timedelta(
        seconds=experiment.spec.retry_policy.retry_delay_seconds
    )
    assert decision.retry_not_before_utc == DUE_INSTANT
    assert decision == sample_allowed_retry_decision(
        experiment_spec_hash=experiment.spec_hash, decided_at_utc=decided_at
    )
    (evaluated,) = store.committed_experiments()
    assert evaluated.revision == 4
    assert evaluated.state is _E.RUNNING
    creation = _ok(_create(store, _request(expected_revision=evaluated.revision)))
    assert creation.attempt.attempt_number == 2
    assert creation.attempt.predecessor_run_id == RUN_ID
    assert creation.attempt.retry_reason is RetryTerminalState.FAILED
    assert creation.experiment.revision == 5
    assert store.committed_retry_decisions() == (decision,)
    assert store.committed_engine_runs() == _by_run_id(predecessor, creation.attempt)


def test_a_failed_successor_is_itself_a_predecessor_reserving_attempt_three() -> None:
    store = InMemoryBackingStore()
    experiment = sample_experiment(_E.RUNNING)
    first = sample_run(_R.FAILED)
    second = sample_run(
        _R.FAILED,
        run_id=OTHER_RUN_ID,
        attempt_number=2,
        predecessor_run_id=RUN_ID,
        primary_terminal_diagnostic_id=OTHER_DIAG_ID,
    )
    store.seed_diagnostic(sample_diagnostic(OTHER_DIAG_ID, run_id=OTHER_RUN_ID))
    _seed(store, experiment, first, second)
    decision = _ok(
        evaluate_retry(
            _evaluation_request(
                predecessor=second, expected_experiment_revision=experiment.revision
            ),
            unit_of_work=InMemoryUnitOfWork(store),
            clock=FixedClock(DUE_INSTANT),
        )
    )
    assert decision.outcome is RetryDecisionOutcome.ALLOWED
    assert decision.predecessor_run_id == OTHER_RUN_ID
    assert decision.created_attempt_count == 2
    assert decision.reserved_successor_attempt_number == 3
    assert decision.retry_not_before_utc == DUE_INSTANT
    creation = _ok(
        _create(
            store,
            _request(expected_revision=4, predecessor_run_id=OTHER_RUN_ID),
        )
    )
    successor = creation.attempt
    assert successor.attempt_number == 3
    assert successor.predecessor_run_id == OTHER_RUN_ID
    assert successor.retry_reason is RetryTerminalState.FAILED
    assert successor.run_id not in {RUN_ID, OTHER_RUN_ID}
    assert creation.experiment.revision == 5
    assert store.committed_engine_runs() == _by_run_id(first, second, successor)


# --------------------------------------------------------------------------
# G. Defensive branches of the successor read set (contract D9; reviewer note F2)
#
# Every case here begins green against the implementation (preventive): each pins
# that a defensive branch aborts or reloads without writing a successor.
# --------------------------------------------------------------------------

_STUB_SOURCE = "tests.stub"


def _stub_conflict() -> Failure:
    return stage5_failure(
        CONCURRENCY_CONFLICT,
        "simulated persistence fault",
        source_component=_STUB_SOURCE,
        timestamp_utc=INSTANT,
    )


def _conflict_answer(*_args: object, **_kwargs: object) -> Failure:
    return _stub_conflict()


def _missing_answer(*_args: object, **_kwargs: object) -> Success[object]:
    absent: Any = MISSING
    return Success(outcome="SUCCESS", value=absent)


def _overriding(
    slot: _Slot, member: str, **overrides: Callable[..., object]
) -> MemberOverridingUnitOfWork:
    return MemberOverridingUnitOfWork(InMemoryUnitOfWork(slot.store), member, overrides)


def test_a_missing_experiment_is_the_repository_invariant_violation() -> None:
    store = InMemoryBackingStore()
    predecessor = sample_run(_R.FAILED)
    decision = sample_allowed_retry_decision()
    _seed(store, predecessor, decision)
    source = CountingIdentitySource()
    result = _create(store, _request(expected_revision=3), identity_source=source)
    assert _code(result) == INVARIANT_VIOLATION
    assert source.draws == 0
    assert store.committed_engine_runs() == (predecessor,)


def test_a_missing_predecessor_is_the_repository_invariant_violation() -> None:
    store = InMemoryBackingStore()
    experiment = sample_experiment(_E.RUNNING)
    decision = sample_allowed_retry_decision(experiment_spec_hash=experiment.spec_hash)
    _seed(store, experiment, decision)
    source = CountingIdentitySource()
    result = _create(
        store, _request(expected_revision=experiment.revision), identity_source=source
    )
    assert _code(result) == INVARIANT_VIOLATION
    assert source.draws == 0
    assert store.committed_engine_runs() == ()
    assert store.committed_experiments() == (experiment,)


def test_a_predecessor_stored_on_another_slot_is_an_invariant_violation() -> None:
    slot = _seeded(predecessor=sample_run(_R.FAILED, logical_slot_id=SLOT_B))
    result = _create(slot.store, _request(expected_revision=slot.experiment.revision))
    assert _code(result) == INVARIANT_VIOLATION
    _assert_nothing_written(slot)


def test_a_predecessor_outside_the_selected_slots_is_an_invariant_violation() -> None:
    slot = _seeded(
        predecessor=sample_run(_R.FAILED, logical_slot_id=SLOT_C),
        decision=sample_allowed_retry_decision(
            logical_slot_id=SLOT_C,
            experiment_spec_hash=sample_experiment(_E.RUNNING).spec_hash,
        ),
    )
    request = SuccessorCreationRequest(
        schema_version="1.0.0",
        experiment_id=EXPERIMENT_ID,
        logical_slot_id=SLOT_C,
        predecessor_run_id=RUN_ID,
        expected_experiment_revision=slot.experiment.revision,
        request_hash=REQUEST_HASH,
    )
    result = _create(slot.store, request)
    assert _code(result) == INVARIANT_VIOLATION
    _assert_nothing_written(slot)


def test_a_latest_attempt_fault_passes_through_and_writes_nothing() -> None:
    slot = _seeded()
    result = _create(
        slot.store,
        _request(expected_revision=slot.experiment.revision),
        root=_overriding(slot, "engine_runs", latest_attempt=_conflict_answer),
    )
    assert result == _stub_conflict()
    _assert_nothing_written(slot)


def test_a_missing_latest_attempt_beside_a_stored_run_is_an_invariant_violation() -> (
    None
):
    slot = _seeded()
    result = _create(
        slot.store,
        _request(expected_revision=slot.experiment.revision),
        root=_overriding(slot, "engine_runs", latest_attempt=_missing_answer),
    )
    assert _code(result) == INVARIANT_VIOLATION
    _assert_nothing_written(slot)


def test_an_add_attempt_fault_reloads_once_and_returns_the_conflict() -> None:
    slot = _seeded()
    root = _overriding(slot, "engine_runs", add_attempt=_conflict_answer)
    source = CountingIdentitySource()
    result = _create(
        slot.store,
        _request(expected_revision=slot.experiment.revision),
        root=root,
        identity_source=source,
    )
    assert result == _stub_conflict()
    assert root.begins == 2
    # The losing attempts draw before the lost insert (declared); nothing durable.
    assert source.draws == 4
    _assert_nothing_written(slot)


def test_a_get_by_attempt_number_fault_passes_through_and_writes_nothing() -> None:
    slot = _seeded()
    source = CountingIdentitySource()
    result = _create(
        slot.store,
        _request(expected_revision=slot.experiment.revision),
        root=_overriding(slot, "engine_runs", get_by_attempt_number=_conflict_answer),
        identity_source=source,
    )
    assert result == _stub_conflict()
    assert source.draws == 0
    _assert_nothing_written(slot)
