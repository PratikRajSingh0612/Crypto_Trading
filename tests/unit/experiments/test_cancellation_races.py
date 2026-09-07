"""Stage 5 Task 8: cancellation races, the loser contracts and the successor rule.

Plan sections 9.1 (cancellation steps 1-5; the experiment revision as the single
mutual-exclusion primitive), 9.5 (the ten pairwise contention rows, each driven end
to end with the REAL operations, and the unconstructibility of the three-way race),
9.4 (the already-terminal pre-classifier path a stale aggregation lands on), Task 8
(a successor proven impossible after a cancellation or aggregation commit, at the
stale and at the fresh revision), 11 (restart over the same store) and 13.2
criterion 13, read through the Task 8 service API contract ``task8-service-api.md``:
D6 (the aggregation order the losers and winners follow), D7 (the loser's clock-read
count pins exactly one reload), D8 (no run or invocation cascade exists in Stage 5),
D11 (idempotent replay after terminalization), D17 (the ten rows and their common
assertions), D18 (successor impossible after a terminal winner) and D19 (no partial
writes).

Every case fails at collection until Task 8's module
``crypto_lab.experiments.aggregation`` exists -- that is the intended RED; the
cancellation facts of section A are therefore asserted beside an aggregation of the
cancelled record (plan 9.4: the ``CANCELLED`` verdict with no reason codes). Every
case drives the services through the ROOT in-memory unit of work (the service calls
``begin()`` itself), seeds rows through a transaction of its own and inspects the
backing store's committed rows, so a losing or rejected operation is proven to write
nothing. The read-discipline clocks (``CountingClock``, ``FailingClock``) are
injected into the SERVICE only; the root keeps its default clock. Every race is
deterministic: the loser runs through a root carrying the double's one-shot
experiment compare-and-swap hook, installed exactly once per scenario, and the
winner runs INSIDE that hook through a SEPARATE root over the same store, so it
commits between the loser's checks and the loser's swap; the hook is asserted
consumed afterwards. Nothing here sleeps, starts a thread or draws a random value.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Final

import pytest
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.domain.aggregation import (
    REASON_SLOT_UNAVAILABLE,
    AggregationVerdict,
    ExperimentAggregationResult,
)
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.compatibility import CompatibilityOutcome
from crypto_lab.domain.engine_run import EngineRunRecord
from crypto_lab.domain.experiment import ExperimentRecord
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.ports import Clock, IdentitySource
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.domain.retry import (
    RetryDecisionOutcome,
    RetryDecisionRecord,
    RetryDenialReason,
)
from crypto_lab.experiments.aggregation import (
    TERMINAL_STATE_OF_VERDICT,
    VERDICT_OF_TERMINAL_STATE,
    aggregate_experiment,
)
from crypto_lab.experiments.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
    stage5_failure,
)
from crypto_lab.experiments.experiment_service import cancel_experiment
from crypto_lab.experiments.ports import UnitOfWork
from crypto_lab.experiments.requests import (
    AttemptCreationRequest,
    CancelExperimentRequest,
    ExperimentAggregationRequest,
    RetryEvaluationRequest,
    SuccessorCreationRequest,
)
from crypto_lab.experiments.retry import create_successor, evaluate_retry
from crypto_lab.experiments.run_service import AttemptCreation, create_attempt
from doubles.experiments import (
    ADAPTER_BETA,
    AVAIL_B,
    ENGINE_BETA,
    EXPERIMENT_ID,
    INSTANT,
    OTHER_REQUEST_HASH,
    OTHER_RUN_ID,
    REQUEST_HASH,
    RUN_ID,
    SLOT_A,
    SLOT_B,
    CountingClock,
    FailingClock,
    FixedClock,
    InMemoryBackingStore,
    InMemoryUnitOfWork,
    MemberOverridingUnitOfWork,
    SequentialIdentitySource,
    sample_allowed_retry_decision,
    sample_diagnostic,
    sample_experiment,
    sample_invocation,
    sample_run,
    sample_slot_compatibility,
)

_E = ExperimentState
_R = EngineRunState

#: Strictly after every fixture instant (``INSTANT`` plus at most five seconds).
CLOCK_INSTANT: Final = INSTANT + timedelta(minutes=1)
#: The fixture ALLOWED decision's ``retry_not_before_utc``: the predecessor's
#: terminal completion instant (``INSTANT`` + 5 s) plus the 30 s policy delay.
DUE_INSTANT: Final = INSTANT + timedelta(seconds=35)
#: A later instant for replays, distinguishable from ``CLOCK_INSTANT``.
LATER_INSTANT: Final = CLOCK_INSTANT + timedelta(minutes=1)
#: The identity seed of a service under test when no other seed is named.
SEED: Final = "task8"
#: The correlation identity of every winning cancellation.
WINNER: Final = "winner"
#: Plan 9.1 step 3: the terminal states a cancellation refuses.
_OTHER_TERMINAL: Final = [_E.COMPLETED, _E.COMPLETED_WITH_WARNINGS, _E.FAILED]
#: Plan 5: every non-terminal engine-run state attempt 1 of a slot can hold.
_LIVE_RUN_STATES: Final = [_R.PENDING, _R.VALIDATING, _R.READY, _R.STARTING, _R.RUNNING]
#: The name the double reports for its installed experiment compare-and-swap hook.
_CAS_HOOK: Final[tuple[str, ...]] = ("experiment_compare_and_swap",)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _missing(value: object) -> bool:
    return value is MISSING


def _code(result: object) -> str:
    assert isinstance(result, Failure), result
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
            assert inserted.inserted, inserted
    _commit(transaction)


def _seed_invocation(
    store: InMemoryBackingStore, invocation: CommandInvocationRecord
) -> None:
    """Commit one invocation row through a transaction of the test's own."""
    transaction = InMemoryUnitOfWork(store).begin()
    _ok(transaction.command_invocations.add(invocation))
    _commit(transaction)


def _stored(
    store: InMemoryBackingStore, experiment_id: str = EXPERIMENT_ID
) -> ExperimentRecord:
    matching = [
        record
        for record in store.committed_experiments()
        if record.experiment_id == experiment_id
    ]
    assert len(matching) == 1
    return matching[0]


def _by_run_id(*records: EngineRunRecord) -> tuple[EngineRunRecord, ...]:
    """The store's committed order: sorted by ``run_id``."""
    return tuple(sorted(records, key=lambda record: record.run_id))


def _bytes(*records: object) -> tuple[bytes, ...]:
    """Canonical bytes, so "byte-identical" is a claim about the serialization."""
    return tuple(canonical_json_bytes(record) for record in records)


class CountingIdentitySource(SequentialIdentitySource):
    """A ``SequentialIdentitySource`` that counts every draw, so a test can pin zero
    (plan 8.5 step 6: identity is drawn only after every check has passed)."""

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
class _Start:
    """One shared start of plan 9.5: the store and every seeded row."""

    store: InMemoryBackingStore
    experiment: ExperimentRecord
    runs: tuple[EngineRunRecord, ...]
    decisions: tuple[RetryDecisionRecord, ...] = ()
    invocations: tuple[CommandInvocationRecord, ...] = ()

    @property
    def revision(self) -> int:
        return self.experiment.revision

    @property
    def run_a(self) -> EngineRunRecord:
        """Slot A's seeded attempt 1 (every start seeds it first)."""
        return self.runs[0]


def _assert_children_untouched(
    start: _Start,
    *winner_runs: EngineRunRecord,
    decisions: tuple[RetryDecisionRecord, ...] | None = None,
) -> None:
    """D19: every committed child row is byte-identical to a seeded row, plus
    exactly the named winner rows; the loser's attempt or decision is absent."""
    expected_runs = _by_run_id(*start.runs, *winner_runs)
    actual_runs = start.store.committed_engine_runs()
    assert actual_runs == expected_runs
    assert _bytes(*actual_runs) == _bytes(*expected_runs)
    expected_decisions = start.decisions if decisions is None else decisions
    actual_decisions = start.store.committed_retry_decisions()
    assert actual_decisions == expected_decisions
    assert _bytes(*actual_decisions) == _bytes(*expected_decisions)
    actual_invocations = start.store.committed_command_invocations()
    assert actual_invocations == start.invocations
    assert _bytes(*actual_invocations) == _bytes(*start.invocations)


def _terminal(stored: ExperimentRecord, state: ExperimentState) -> ExperimentRecord:
    """The record a raw writer commits over ``stored``: ``state`` at revision + 1
    and ``CLOCK_INSTANT``, every other field carried."""
    return ExperimentRecord.model_validate(
        {
            **stored.model_dump(mode="python"),
            "state": state,
            "revision": stored.revision + 1,
            "updated_at_utc": CLOCK_INSTANT,
        }
    )


def _stub_conflict() -> Failure:
    return stage5_failure(
        CONCURRENCY_CONFLICT,
        "simulated persistence fault",
        source_component="tests.stub",
        timestamp_utc=INSTANT,
    )


def _conflict_answer(*_args: object, **_kwargs: object) -> Failure:
    return _stub_conflict()


# --------------------------------------------------------------------------
# The shared starts (plan 9.5 column 2), seeded through a test-owned transaction
# --------------------------------------------------------------------------


def _run_b(state: EngineRunState = _R.SUCCEEDED) -> EngineRunRecord:
    """Slot B's attempt 1 on the beta adapter and engine."""
    return sample_run(
        state,
        run_id=OTHER_RUN_ID,
        logical_slot_id=SLOT_B,
        adapter=ADAPTER_BETA,
        engine=ENGINE_BETA,
        availability_observation_id=AVAIL_B,
    )


def _write_ready() -> _Start:
    """Rows 1-2: RUNNING rev 3; A and B SUCCEEDED, so aggregation is write-ready.

    9.3 row 7: S = {A, B}, N = {}, no approximation, no late member -> COMPLETED ().
    """
    store = InMemoryBackingStore()
    experiment = sample_experiment(_E.RUNNING)
    runs = (sample_run(_R.SUCCEEDED), _run_b())
    _seed(store, experiment, *runs)
    return _Start(store, experiment, runs)


def _successor_ready() -> _Start:
    """Rows 3-4: RUNNING rev 3; A FAILED (rev 5) with the ALLOWED decision reserving
    attempt 2, due at ``DUE_INSTANT``; no successor."""
    store = InMemoryBackingStore()
    experiment = sample_experiment(_E.RUNNING)
    predecessor = sample_run(_R.FAILED)
    decision = sample_allowed_retry_decision(experiment_spec_hash=experiment.spec_hash)
    assert decision.retry_not_before_utc == DUE_INSTANT
    _seed(store, experiment, predecessor, decision)
    return _Start(store, experiment, (predecessor,), (decision,))


def _attempt_ready() -> _Start:
    """Rows 5-6: RUNNING rev 3; A attempt 1 PENDING; B unattempted, SUPPORTED."""
    store = InMemoryBackingStore()
    experiment = sample_experiment(_E.RUNNING)
    pending = sample_run(_R.PENDING)
    _seed(store, experiment, pending)
    return _Start(store, experiment, (pending,))


def _unavailable_b() -> _Start:
    """Rows 7-8: RUNNING rev 3; A SUCCEEDED; B unattempted, frozen UNAVAILABLE.

    9.3 row 8: S = {A}; B is effectively UNAVAILABLE with no attempt (9.2), so row
    7's ``|S| + |N| == |slots|`` fails -> COMPLETED_WITH_WARNINGS {SLOT_UNAVAILABLE}.
    """
    store = InMemoryBackingStore()
    experiment = sample_experiment(
        _E.RUNNING,
        slot_compatibility=sample_slot_compatibility(
            outcomes={SLOT_B: CompatibilityOutcome.UNAVAILABLE}
        ),
    )
    succeeded = sample_run(_R.SUCCEEDED)
    _seed(store, experiment, succeeded)
    return _Start(store, experiment, (succeeded,))


def _retry_ready() -> _Start:
    """Rows 9-10: RUNNING rev 3; A FAILED (rev 5), its retriable primary seeded, no
    decision. ``evaluate_retry`` at (3, 5) passes every gate -- 1 < 3, FAILED listed,
    retriable, closure {(ENGINE_RUNTIME, ENGINE.RUNTIME_FAILURE)} not hard-blocking,
    RUNNING, gate 6 vacuous -> ALLOWED and a state-preserving bump to rev 4."""
    store = InMemoryBackingStore()
    experiment = sample_experiment(_E.RUNNING)
    predecessor = sample_run(_R.FAILED)
    store.seed_diagnostic(sample_diagnostic())
    _seed(store, experiment, predecessor)
    return _Start(store, experiment, (predecessor,))


# --------------------------------------------------------------------------
# The five operations, driven through a root (a hooked one or a fresh one)
# --------------------------------------------------------------------------


def _cancel(
    unit_of_work: UnitOfWork,
    *,
    expected_revision: int,
    correlation_id: str = "cancel-1",
    clock: Clock | None = None,
) -> Result[ExperimentRecord]:
    return cancel_experiment(
        CancelExperimentRequest(
            schema_version="1.0.0",
            experiment_id=EXPERIMENT_ID,
            expected_revision=expected_revision,
            correlation_id=correlation_id,
        ),
        unit_of_work=unit_of_work,
        clock=FixedClock(CLOCK_INSTANT) if clock is None else clock,
    )


def _aggregate(
    unit_of_work: UnitOfWork,
    *,
    expected_revision: int,
    clock: Clock | None = None,
) -> Result[ExperimentAggregationResult]:
    return aggregate_experiment(
        ExperimentAggregationRequest(
            schema_version="1.0.0",
            experiment_id=EXPERIMENT_ID,
            expected_revision=expected_revision,
        ),
        unit_of_work=unit_of_work,
        clock=FixedClock(CLOCK_INSTANT) if clock is None else clock,
    )


def _attempt(
    unit_of_work: UnitOfWork,
    *,
    expected_revision: int,
    seed: str,
    clock: Clock | None = None,
) -> Result[AttemptCreation]:
    """``create_attempt`` for SLOT_B, the slot every relevant start leaves empty."""
    return create_attempt(
        AttemptCreationRequest(
            schema_version="1.0.0",
            experiment_id=EXPERIMENT_ID,
            logical_slot_id=SLOT_B,
            expected_experiment_revision=expected_revision,
            request_hash=REQUEST_HASH,
        ),
        unit_of_work=unit_of_work,
        clock=FixedClock(CLOCK_INSTANT) if clock is None else clock,
        identity_source=SequentialIdentitySource(seed),
    )


def _successor(
    unit_of_work: UnitOfWork,
    *,
    expected_revision: int,
    request_hash: str = REQUEST_HASH,
    clock: Clock | None = None,
    identity_source: IdentitySource | None = None,
) -> Result[AttemptCreation]:
    """``create_successor`` of SLOT_A's predecessor, at the due instant by default."""
    return create_successor(
        SuccessorCreationRequest(
            schema_version="1.0.0",
            experiment_id=EXPERIMENT_ID,
            logical_slot_id=SLOT_A,
            predecessor_run_id=RUN_ID,
            expected_experiment_revision=expected_revision,
            request_hash=request_hash,
        ),
        unit_of_work=unit_of_work,
        clock=FixedClock(DUE_INSTANT) if clock is None else clock,
        identity_source=(
            SequentialIdentitySource(SEED)
            if identity_source is None
            else identity_source
        ),
    )


def _evaluate(
    unit_of_work: UnitOfWork,
    *,
    expected_revision: int,
    clock: Clock | None = None,
) -> Result[RetryDecisionRecord]:
    """``evaluate_retry`` of SLOT_A's FAILED predecessor at its revision 5."""
    return evaluate_retry(
        RetryEvaluationRequest(
            schema_version="1.0.0",
            experiment_id=EXPERIMENT_ID,
            logical_slot_id=SLOT_A,
            predecessor_run_id=RUN_ID,
            expected_experiment_revision=expected_revision,
            expected_predecessor_revision=5,
        ),
        unit_of_work=unit_of_work,
        clock=FixedClock(CLOCK_INSTANT) if clock is None else clock,
    )


# --------------------------------------------------------------------------
# The race driver: the loser through the hooked root, the winner inside the hook
# --------------------------------------------------------------------------


def _race[L, W](
    store: InMemoryBackingStore,
    *,
    loser: Callable[[InMemoryUnitOfWork], Result[L]],
    winner: Callable[[], W],
) -> tuple[Result[L], W, tuple[int, ...]]:
    """Run ``loser`` through a root carrying the one-shot experiment compare-and-swap
    hook; ``winner`` runs INSIDE that hook through a separate root over ``store``.

    Returns the loser's public Result, the winner's value and the expected revisions
    the hook observed -- exactly one, because the hook is removed from the root
    before it fires and the winner's own swap goes through its separate root.
    """
    root = InMemoryUnitOfWork(store)
    winners: list[W] = []
    fired: list[int] = []

    def hook(expected_revision: int, _candidate: ExperimentRecord) -> None:
        fired.append(expected_revision)
        winners.append(winner())

    root.install_experiment_compare_and_swap_hook(hook)
    result = loser(root)
    assert root.hooks_installed == ()
    (won,) = winners
    return result, won, tuple(fired)


def _cancel_winner(start: _Start) -> Callable[[], ExperimentRecord]:
    """A cancellation under ``WINNER`` committed through a separate root."""

    def winner() -> ExperimentRecord:
        return _ok(
            _cancel(
                InMemoryUnitOfWork(start.store),
                expected_revision=start.revision,
                correlation_id=WINNER,
            )
        )

    return winner


def _aggregate_winner(start: _Start) -> Callable[[], ExperimentAggregationResult]:
    """A terminal aggregation committed through a separate root."""

    def winner() -> ExperimentAggregationResult:
        return _ok(
            _aggregate(
                InMemoryUnitOfWork(start.store), expected_revision=start.revision
            )
        )

    return winner


def _attempt_winner(start: _Start) -> Callable[[], AttemptCreation]:
    """Attempt 1 of SLOT_B created through a separate root."""

    def winner() -> AttemptCreation:
        return _ok(
            _attempt(
                InMemoryUnitOfWork(start.store),
                expected_revision=start.revision,
                seed=WINNER,
            )
        )

    return winner


def _successor_winner(start: _Start) -> Callable[[], AttemptCreation]:
    """SLOT_A's reserved successor created through a separate root."""

    def winner() -> AttemptCreation:
        return _ok(
            _successor(
                InMemoryUnitOfWork(start.store),
                expected_revision=start.revision,
                identity_source=SequentialIdentitySource(WINNER),
            )
        )

    return winner


def _assert_cancelled_replay(store: InMemoryBackingStore, revision: int) -> None:
    """Plan 9.4 / D6 step 2 / D11: a CANCELLED record aggregates as the CANCELLED
    verdict with no reason codes, no clock read, no child read and no write."""
    before = _stored(store)
    assert before.state is _E.CANCELLED
    replay = _ok(
        _aggregate(
            InMemoryUnitOfWork(store), expected_revision=revision, clock=FailingClock()
        )
    )
    assert replay.verdict is AggregationVerdict.CANCELLED
    assert replay.reason_codes == ()
    assert replay.schema_version == "1.0.0"
    assert replay.experiment_id == EXPERIMENT_ID
    assert _stored(store) == before
    assert _bytes(_stored(store)) == _bytes(before)


# --------------------------------------------------------------------------
# A. Cancellation contract facts (plan 9.1, 4, 10.1 l.1269; contract D8, D19)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("state", [_E.DRAFT, _E.VALIDATED, _E.QUEUED, _E.RUNNING])
def test_cancellation_carries_the_material_and_writes_the_correlation_once(
    state: ExperimentState,
) -> None:
    # Plan 9.1 step 5 / 3.6: only state, correlation id, updated_at_utc and revision
    # move; spec, spec_hash, the frozen compatibility and created_at_utc are carried.
    store = InMemoryBackingStore()
    seed = sample_experiment(state)
    _seed(store, seed)
    assert _missing(seed.cancellation_correlation_id)
    cancelled = _ok(_cancel(InMemoryUnitOfWork(store), expected_revision=seed.revision))
    assert cancelled.state is _E.CANCELLED
    assert cancelled.experiment_id == seed.experiment_id
    assert cancelled.schema_version == seed.schema_version
    assert cancelled.spec == seed.spec
    assert cancelled.spec_hash == seed.spec_hash
    assert cancelled.slot_compatibility == seed.slot_compatibility
    assert cancelled.created_at_utc == seed.created_at_utc
    assert cancelled.revision == seed.revision + 1
    assert cancelled.updated_at_utc == CLOCK_INSTANT
    assert cancelled.updated_at_utc >= seed.updated_at_utc
    assert cancelled.cancellation_correlation_id == "cancel-1"
    assert store.committed_experiments() == (cancelled,)
    # Written once: the identical replay at a later instant rewrites nothing (the
    # Task 6 replay still reads the clock first, D7).
    clock = CountingClock(LATER_INSTANT)
    replayed = _ok(
        _cancel(
            InMemoryUnitOfWork(store),
            expected_revision=cancelled.revision,
            clock=clock,
        )
    )
    assert replayed == cancelled
    assert replayed.updated_at_utc == CLOCK_INSTANT
    assert clock.reads == 1
    assert store.committed_experiments() == (cancelled,)
    _assert_cancelled_replay(store, cancelled.revision)


@pytest.mark.parametrize("state", _OTHER_TERMINAL)
@pytest.mark.parametrize("revision_offset", [0, 1], ids=["stored", "stored_plus_one"])
def test_another_terminal_state_refuses_cancellation_regardless_of_revision(
    state: ExperimentState, revision_offset: int
) -> None:
    # Plan 9.1 step 3 precedes step 4: INVARIANT_VIOLATION whether or not the
    # revision agrees; plan 9.4: the record then aggregates as its own verdict.
    store = InMemoryBackingStore()
    seed = sample_experiment(state)
    _seed(store, seed)
    revision = seed.revision + revision_offset
    result = _cancel(InMemoryUnitOfWork(store), expected_revision=revision)
    assert _code(result) == INVARIANT_VIOLATION
    assert store.committed_experiments() == (seed,)
    replay = _ok(
        _aggregate(
            InMemoryUnitOfWork(store), expected_revision=revision, clock=FailingClock()
        )
    )
    assert replay.verdict is VERDICT_OF_TERMINAL_STATE[state]
    assert replay.reason_codes == ()
    assert store.committed_experiments() == (seed,)


@pytest.mark.parametrize("revision_offset", [0, -3, 9])
def test_a_cancelled_record_replays_on_its_correlation_identity_alone(
    revision_offset: int,
) -> None:
    # Plan 9.1 step 2: the correlation id is the replay evidence and the revision
    # is not compared; another id is CONCURRENCY_CONFLICT and rewrites nothing.
    store = InMemoryBackingStore()
    seed = sample_experiment(_E.CANCELLED, correlation_id="cancel-7")
    _seed(store, seed)
    revision = seed.revision + revision_offset
    clock = CountingClock(LATER_INSTANT)
    replayed = _ok(
        _cancel(
            InMemoryUnitOfWork(store),
            expected_revision=revision,
            correlation_id="cancel-7",
            clock=clock,
        )
    )
    assert replayed == seed
    assert _bytes(replayed) == _bytes(seed)
    assert clock.reads == 1
    other = _cancel(
        InMemoryUnitOfWork(store), expected_revision=revision, correlation_id="cancel-8"
    )
    assert _code(other) == CONCURRENCY_CONFLICT
    assert _stored(store).cancellation_correlation_id == "cancel-7"
    assert store.committed_experiments() == (seed,)
    # A pre-freeze cancellation carries no slot_compatibility; the terminal path
    # (D6 step 2) answers before build_aggregation_input would need it (D1).
    assert _missing(seed.slot_compatibility)
    _assert_cancelled_replay(store, revision)


@pytest.mark.parametrize("state", _LIVE_RUN_STATES)
def test_cancellation_cascades_to_no_run_and_no_invocation(
    state: EngineRunState,
) -> None:
    # D8 / plan 9.1, 10.1 l.1269: cancel_experiment writes the experiment only; the
    # child CANCELLED edges belong to transition_run and the coupled transition.
    store = InMemoryBackingStore()
    experiment = sample_experiment(_E.RUNNING)
    runs = (sample_run(state), _run_b())
    invocation = sample_invocation(CommandInvocationState.RUNNING)
    assert invocation.run_id == RUN_ID
    _seed(store, experiment, *runs)
    _seed_invocation(store, invocation)
    start = _Start(store, experiment, runs, invocations=(invocation,))
    cancelled = _ok(_cancel(InMemoryUnitOfWork(store), expected_revision=3))
    assert cancelled.state is _E.CANCELLED
    assert cancelled.revision == 4
    _assert_children_untouched(start)
    (stored_a,) = [run for run in store.committed_engine_runs() if run.run_id == RUN_ID]
    assert stored_a.state is state
    assert stored_a.revision == start.run_a.revision
    # Aggregation of the cancelled record likewise touches no child row (D8, D9).
    _assert_cancelled_replay(store, cancelled.revision)
    _assert_children_untouched(start)


def test_a_lost_swap_reloads_once_then_returns_the_conflict_with_no_write() -> None:
    # Plan 9.5 / 13.2 criterion 6: the lost internal swap is never the public result
    # until the single reload also loses; nothing partial survives (D19). The same
    # single-write discipline governs aggregation's terminal write (D6 step 11).
    start = _write_ready()
    root = MemberOverridingUnitOfWork(
        InMemoryUnitOfWork(start.store),
        "experiments",
        {"compare_and_swap": _conflict_answer},
    )
    cancel_clock = CountingClock(CLOCK_INSTANT)
    cancelled = _cancel(root, expected_revision=start.revision, clock=cancel_clock)
    assert cancelled == _stub_conflict()
    assert root.begins == 2
    assert cancel_clock.reads == 2
    assert start.store.committed_experiments() == (start.experiment,)
    aggregate_clock = CountingClock(CLOCK_INSTANT)
    aggregated = _aggregate(
        root, expected_revision=start.revision, clock=aggregate_clock
    )
    assert aggregated == _stub_conflict()
    assert root.begins == 4
    assert aggregate_clock.reads == 2
    assert start.store.committed_experiments() == (start.experiment,)
    assert _bytes(_stored(start.store)) == _bytes(start.experiment)
    _assert_children_untouched(start)


def test_a_rebuilt_root_replays_the_cancellation_without_moving_updated_at() -> None:
    # Plan 11: a rebuilt root over the same store observes exactly the committed
    # rows; the replay (9.1 step 2) is the stored record with its instant untouched.
    start = _write_ready()
    cancelled = _ok(_cancel(InMemoryUnitOfWork(start.store), expected_revision=3))
    assert cancelled.updated_at_utc == CLOCK_INSTANT
    rebuilt = InMemoryUnitOfWork(start.store)
    replayed = _ok(
        _cancel(
            rebuilt,
            expected_revision=cancelled.revision,
            clock=FixedClock(LATER_INSTANT),
        )
    )
    assert replayed == cancelled
    assert replayed.updated_at_utc == CLOCK_INSTANT
    assert start.store.committed_experiments() == (cancelled,)
    assert rebuilt.hooks_installed == ()
    _assert_cancelled_replay(start.store, cancelled.revision)
    _assert_children_untouched(start)


# --------------------------------------------------------------------------
# B. The ten pairwise contention rows (plan 9.5 l.1210-1219; contract D17, D7)
#
# Common assertions per row: exactly one winner committed at revision 4, the loser's
# own writes absent, every other seeded row byte-identical, the hook consumed, the
# tabulated public Result, and the loser's clock reads pinning exactly one reload.
# --------------------------------------------------------------------------


def test_row_one_a_stale_cancel_after_an_aggregation_winner_is_an_invariant() -> None:
    # 9.5 row 1: winner aggregate_experiment RUNNING -> COMPLETED (9.3 row 7: S={A,B},
    # N={}); loser cancel_experiment reloads a terminal non-cancelled record; 9.1
    # step 3 -> INVARIANT_VIOLATION; one clock read per attempt (D7: reads == 2).
    start = _write_ready()
    clock = CountingClock(CLOCK_INSTANT)

    def loser(root: InMemoryUnitOfWork) -> Result[ExperimentRecord]:
        return _cancel(root, expected_revision=start.revision, clock=clock)

    result, won, fired = _race(
        start.store, loser=loser, winner=_aggregate_winner(start)
    )
    assert _code(result) == INVARIANT_VIOLATION
    assert won.verdict is AggregationVerdict.COMPLETED
    assert won.reason_codes == ()
    stored = _stored(start.store)
    assert stored.state is _E.COMPLETED
    assert stored.state is TERMINAL_STATE_OF_VERDICT[won.verdict]
    assert stored.revision == 4
    assert stored.updated_at_utc == CLOCK_INSTANT
    assert _missing(stored.cancellation_correlation_id)
    assert stored.slot_compatibility == start.experiment.slot_compatibility
    assert fired == (start.revision,)
    assert clock.reads == 2
    _assert_children_untouched(start)


def test_row_two_a_stale_aggregation_after_a_cancel_winner_reports_cancelled() -> None:
    # 9.5 row 2: winner cancel_experiment RUNNING -> CANCELLED; loser
    # aggregate_experiment reloads CANCELLED; 9.4 / D6 step 2 -> Success CANCELLED ()
    # before the clock read, so the loser reads once in total (D7: reads == 1).
    start = _write_ready()
    clock = CountingClock(CLOCK_INSTANT)

    def loser(root: InMemoryUnitOfWork) -> Result[ExperimentAggregationResult]:
        return _aggregate(root, expected_revision=start.revision, clock=clock)

    result, won, fired = _race(start.store, loser=loser, winner=_cancel_winner(start))
    verdict = _ok(result)
    assert verdict.verdict is AggregationVerdict.CANCELLED
    assert verdict.reason_codes == ()
    assert verdict.schema_version == "1.0.0"
    assert verdict.experiment_id == EXPERIMENT_ID
    assert won.state is _E.CANCELLED
    assert won.revision == 4
    assert won.cancellation_correlation_id == WINNER
    stored = _stored(start.store)
    assert stored == won
    assert stored.slot_compatibility == start.experiment.slot_compatibility
    assert fired == (start.revision,)
    assert clock.reads == 1
    _assert_children_untouched(start)


def test_row_three_a_cancel_winner_leaves_no_successor_durable() -> None:
    # 9.5 row 3: the loser's insert and bump roll back together; its reload shows
    # CANCELLED; 8.5 step 3 -> INVARIANT_VIOLATION, clock-stamped (D7: reads == 2).
    start = _successor_ready()
    clock = CountingClock(DUE_INSTANT)
    identity = CountingIdentitySource("loser")

    def loser(root: InMemoryUnitOfWork) -> Result[AttemptCreation]:
        return _successor(
            root,
            expected_revision=start.revision,
            clock=clock,
            identity_source=identity,
        )

    result, won, fired = _race(start.store, loser=loser, winner=_cancel_winner(start))
    assert _code(result) == INVARIANT_VIOLATION
    assert won.state is _E.CANCELLED
    assert won.revision == 4
    assert won.cancellation_correlation_id == WINNER
    assert _stored(start.store) == won
    assert fired == (start.revision,)
    assert clock.reads == 2
    # The losing attempt drew its run id and token before the lost swap (Task 7's
    # declared order); the reload rejected before any draw.
    assert identity.draws == 2
    _assert_children_untouched(start)


def test_row_four_a_stale_cancel_after_a_successor_winner_is_a_conflict() -> None:
    # 9.5 row 4: winner create_successor inserts attempt 2 and bumps RUNNING 3 -> 4;
    # loser cancel_experiment reloads RUNNING at 4; 9.1 step 4 -> CONCURRENCY_CONFLICT;
    # the caller cancels again at 4 and succeeds (rev 5).
    start = _successor_ready()
    clock = CountingClock(CLOCK_INSTANT)

    def loser(root: InMemoryUnitOfWork) -> Result[ExperimentRecord]:
        return _cancel(root, expected_revision=start.revision, clock=clock)

    result, won, fired = _race(
        start.store, loser=loser, winner=_successor_winner(start)
    )
    assert _code(result) == CONCURRENCY_CONFLICT
    assert won.experiment.state is _E.RUNNING
    assert won.experiment.revision == 4
    assert won.attempt.attempt_number == 2
    assert won.attempt.predecessor_run_id == RUN_ID
    assert won.attempt.state is _R.PENDING
    stored = _stored(start.store)
    assert stored == won.experiment
    assert _missing(stored.cancellation_correlation_id)
    assert fired == (start.revision,)
    assert clock.reads == 2
    _assert_children_untouched(start, won.attempt)
    cancelled = _ok(_cancel(InMemoryUnitOfWork(start.store), expected_revision=4))
    assert cancelled.state is _E.CANCELLED
    assert cancelled.revision == 5
    assert _stored(start.store) == cancelled
    _assert_children_untouched(start, won.attempt)


def test_row_five_a_stale_cancel_after_an_attempt_winner_is_a_conflict() -> None:
    # 9.5 row 5: winner create_attempt inserts B's attempt 1 and bumps RUNNING 3 -> 4
    # (state-preserving); loser cancel_experiment reloads RUNNING at 4; 9.1 step 4 ->
    # CONCURRENCY_CONFLICT; A's PENDING attempt is untouched.
    start = _attempt_ready()
    clock = CountingClock(CLOCK_INSTANT)

    def loser(root: InMemoryUnitOfWork) -> Result[ExperimentRecord]:
        return _cancel(root, expected_revision=start.revision, clock=clock)

    result, won, fired = _race(start.store, loser=loser, winner=_attempt_winner(start))
    assert _code(result) == CONCURRENCY_CONFLICT
    assert won.experiment.state is _E.RUNNING
    assert won.experiment.revision == 4
    assert won.attempt.logical_slot_id == SLOT_B
    assert won.attempt.attempt_number == 1
    assert won.attempt.state is _R.PENDING
    assert won.attempt.adapter == ADAPTER_BETA
    assert won.attempt.engine == ENGINE_BETA
    assert _stored(start.store) == won.experiment
    assert fired == (start.revision,)
    assert clock.reads == 2
    _assert_children_untouched(start, won.attempt)


def test_row_six_a_cancel_winner_leaves_no_attempt_durable() -> None:
    # 9.5 row 6: the loser's insert and bump roll back; its reload shows CANCELLED;
    # 5 step 4 -> INVARIANT_VIOLATION (D7: reads == 2); B stays unattempted.
    start = _attempt_ready()
    clock = CountingClock(CLOCK_INSTANT)

    def loser(root: InMemoryUnitOfWork) -> Result[AttemptCreation]:
        return _attempt(
            root, expected_revision=start.revision, seed="loser", clock=clock
        )

    result, won, fired = _race(start.store, loser=loser, winner=_cancel_winner(start))
    assert _code(result) == INVARIANT_VIOLATION
    assert won.state is _E.CANCELLED
    assert won.revision == 4
    assert _stored(start.store) == won
    assert fired == (start.revision,)
    assert clock.reads == 2
    _assert_children_untouched(start)


def test_row_seven_a_stale_aggregation_after_an_attempt_winner_is_a_conflict() -> None:
    # 9.5 row 7: aggregation is write-ready (9.3 row 8: S={A}, B effectively
    # UNAVAILABLE -> CWW {SLOT_UNAVAILABLE}); winner create_attempt inserts B's
    # attempt 1 and bumps 3 -> 4; loser reloads RUNNING at 4; D6 step 5 -> CONFLICT
    # before any child read (D7: reads == 2); re-issued at 4 -> 9.3 row 1 (B PENDING)
    # NOT_YET_TERMINAL with no write.
    start = _unavailable_b()
    clock = CountingClock(CLOCK_INSTANT)

    def loser(root: InMemoryUnitOfWork) -> Result[ExperimentAggregationResult]:
        return _aggregate(root, expected_revision=start.revision, clock=clock)

    result, won, fired = _race(start.store, loser=loser, winner=_attempt_winner(start))
    assert _code(result) == CONCURRENCY_CONFLICT
    assert won.experiment.state is _E.RUNNING
    assert won.experiment.revision == 4
    assert won.attempt.logical_slot_id == SLOT_B
    assert won.attempt.state is _R.PENDING
    assert _stored(start.store) == won.experiment
    assert fired == (start.revision,)
    assert clock.reads == 2
    _assert_children_untouched(start, won.attempt)
    reissued = _ok(_aggregate(InMemoryUnitOfWork(start.store), expected_revision=4))
    assert reissued.verdict is AggregationVerdict.NOT_YET_TERMINAL
    assert reissued.reason_codes == ()
    assert _stored(start.store) == won.experiment
    _assert_children_untouched(start, won.attempt)


def test_row_eight_an_aggregation_winner_leaves_no_attempt_durable() -> None:
    # 9.5 row 8: winner aggregate_experiment RUNNING -> COMPLETED_WITH_WARNINGS (9.3
    # row 8: {SLOT_UNAVAILABLE}); loser create_attempt reloads a terminal record; 5
    # step 4 -> INVARIANT_VIOLATION (D7: reads == 2); B stays unattempted.
    start = _unavailable_b()
    clock = CountingClock(CLOCK_INSTANT)

    def loser(root: InMemoryUnitOfWork) -> Result[AttemptCreation]:
        return _attempt(
            root, expected_revision=start.revision, seed="loser", clock=clock
        )

    result, won, fired = _race(
        start.store, loser=loser, winner=_aggregate_winner(start)
    )
    assert _code(result) == INVARIANT_VIOLATION
    assert won.verdict is AggregationVerdict.COMPLETED_WITH_WARNINGS
    assert won.reason_codes == (REASON_SLOT_UNAVAILABLE,)
    stored = _stored(start.store)
    assert stored.state is _E.COMPLETED_WITH_WARNINGS
    assert stored.state is TERMINAL_STATE_OF_VERDICT[won.verdict]
    assert stored.revision == 4
    assert stored.updated_at_utc == CLOCK_INSTANT
    assert _missing(stored.cancellation_correlation_id)
    assert stored.slot_compatibility == start.experiment.slot_compatibility
    assert fired == (start.revision,)
    assert clock.reads == 2
    _assert_children_untouched(start)


def test_row_nine_a_stale_cancel_after_an_allowed_retry_winner_is_a_conflict() -> None:
    # 9.5 row 9: winner evaluate_retry inserts the ALLOWED row and bumps 3 -> 4 (8.4
    # phase 3, swap before insert); loser cancel_experiment reloads RUNNING at 4;
    # 9.1 step 4 -> CONCURRENCY_CONFLICT (D7: reads == 2).
    start = _retry_ready()
    clock = CountingClock(CLOCK_INSTANT)

    def loser(root: InMemoryUnitOfWork) -> Result[ExperimentRecord]:
        return _cancel(root, expected_revision=start.revision, clock=clock)

    def winner() -> RetryDecisionRecord:
        return _ok(
            _evaluate(InMemoryUnitOfWork(start.store), expected_revision=start.revision)
        )

    result, won, fired = _race(start.store, loser=loser, winner=winner)
    assert _code(result) == CONCURRENCY_CONFLICT
    assert won.outcome is RetryDecisionOutcome.ALLOWED
    assert won.reserved_successor_attempt_number == 2
    # Plan 8.4: the predecessor's terminal completion plus the 30 s policy delay.
    delay = timedelta(seconds=start.experiment.spec.retry_policy.retry_delay_seconds)
    assert delay == timedelta(seconds=30)
    assert won.retry_not_before_utc == start.run_a.updated_at_utc + delay
    assert won.retry_not_before_utc == DUE_INSTANT
    assert won.decided_at_utc == CLOCK_INSTANT
    stored = _stored(start.store)
    assert stored.state is _E.RUNNING
    assert stored.revision == 4
    assert stored.updated_at_utc == CLOCK_INSTANT
    assert _missing(stored.cancellation_correlation_id)
    assert fired == (start.revision,)
    assert clock.reads == 2
    _assert_children_untouched(start, decisions=(won,))


def test_row_ten_a_cancel_winner_leaves_no_decision_then_a_new_call_denies() -> None:
    # 9.5 row 10: the loser's ALLOWED swap loses (8.4 phase 3, swap before insert), so
    # insert and bump roll back together; the reload shows the revision moved; 8.3 ->
    # non-persisted CONCURRENCY_CONFLICT (D7: reads == 2). A SECOND public invocation
    # at the terminal revision fails gate 5 and persists DENIED EXPERIMENT_TERMINAL,
    # reserving nothing and writing no experiment row (plan 9.1).
    start = _retry_ready()
    clock = CountingClock(CLOCK_INSTANT)

    def loser(root: InMemoryUnitOfWork) -> Result[RetryDecisionRecord]:
        return _evaluate(root, expected_revision=start.revision, clock=clock)

    result, won, fired = _race(start.store, loser=loser, winner=_cancel_winner(start))
    assert _code(result) == CONCURRENCY_CONFLICT
    assert won.state is _E.CANCELLED
    assert won.revision == 4
    assert _stored(start.store) == won
    assert start.store.committed_retry_decisions() == ()
    assert fired == (start.revision,)
    assert clock.reads == 2
    _assert_children_untouched(start)
    denied = _ok(
        _evaluate(InMemoryUnitOfWork(start.store), expected_revision=won.revision)
    )
    assert denied.outcome is RetryDecisionOutcome.DENIED
    assert denied.denial_reason is RetryDenialReason.EXPERIMENT_TERMINAL
    assert _missing(denied.reserved_successor_attempt_number)
    assert _missing(denied.retry_not_before_utc)
    assert denied.predecessor_run_id == RUN_ID
    assert denied.logical_slot_id == SLOT_A
    assert start.store.committed_retry_decisions() == (denied,)
    assert _stored(start.store) == won
    assert _bytes(_stored(start.store)) == _bytes(won)
    assert start.store.committed_engine_runs() == start.runs


@pytest.mark.parametrize(
    ("start_of", "resolve_b"),
    [
        (_retry_ready, False),
        (_retry_ready, True),
        (_successor_ready, False),
        (_successor_ready, True),
    ],
    ids=[
        "fresh_retry_eligible",
        "fresh_retry_eligible_b_succeeded",
        "allowed_pending",
        "allowed_pending_b_succeeded",
    ],
)
def test_evaluate_retry_versus_aggregation_has_no_constructible_shared_start(
    start_of: Callable[[], _Start], resolve_b: bool
) -> None:
    # Plan 9.5 l.1200-1204 / D17: a fresh ALLOWED needs an unresolved slot, and an
    # un-created reservation keeps that slot pending, so aggregation returns
    # NOT_YET_TERMINAL with no write over every store the committed operations can
    # produce. As seeded, 9.3 row 2 fires first (B unattempted, frozen SUPPORTED);
    # with B SUCCEEDED beside it, slot A alone blocks through 9.3 row 3
    # (DECISION_UNRESOLVED without a row, ALLOWED_SUCCESSOR_PENDING with one).
    start = start_of()
    extra: tuple[EngineRunRecord, ...] = ()
    if resolve_b:
        extra = (_run_b(),)
        _seed(start.store, *extra)
    root = InMemoryUnitOfWork(start.store)

    def never(expected_revision: int, candidate: ExperimentRecord) -> None:
        raise AssertionError(f"no swap is reached: {expected_revision} {candidate!r}")

    root.install_experiment_compare_and_swap_hook(never)
    clock = CountingClock(CLOCK_INSTANT)
    verdict = _ok(_aggregate(root, expected_revision=start.revision, clock=clock))
    assert verdict.verdict is AggregationVerdict.NOT_YET_TERMINAL
    assert verdict.reason_codes == ()
    assert clock.reads == 1
    # The hook was never reached: it stays installed until the test resets it.
    assert root.hooks_installed == _CAS_HOOK
    root.reset_hooks()
    assert root.hooks_installed == ()
    assert _stored(start.store) == start.experiment
    assert _bytes(_stored(start.store)) == _bytes(start.experiment)
    _assert_children_untouched(start, *extra)


# --------------------------------------------------------------------------
# C. Successor impossible after a terminal winner (plan Task 8 l.1706-1707, 8.5
#    steps 2-3; contract D18; section 13.2 criterion 13)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("revision_offset", [0, 1], ids=["stale", "fresh"])
def test_no_successor_after_a_real_cancellation_at_the_stale_or_fresh_revision(
    revision_offset: int,
) -> None:
    # D18 / 8.5 step 3: the terminal rule is independent of revision agreement; the
    # rejection is clock-stamped, so the service clock is a FixedClock at the due
    # instant rather than FailingClock; no identity is drawn and nothing is written.
    start = _successor_ready()
    cancelled = _ok(
        _cancel(InMemoryUnitOfWork(start.store), expected_revision=start.revision)
    )
    assert cancelled.revision == 4
    revision = start.revision + revision_offset
    identity = CountingIdentitySource()
    clock = CountingClock(DUE_INSTANT)
    result = _successor(
        InMemoryUnitOfWork(start.store),
        expected_revision=revision,
        clock=clock,
        identity_source=identity,
    )
    assert _code(result) == INVARIANT_VIOLATION
    assert identity.draws == 0
    assert clock.reads == 1
    assert _stored(start.store) == cancelled
    _assert_children_untouched(start)
    _assert_cancelled_replay(start.store, revision)


@pytest.mark.parametrize("revision_offset", [0, 1], ids=["stale", "fresh"])
def test_no_successor_after_a_terminal_aggregation_at_the_stale_or_fresh_revision(
    revision_offset: int,
) -> None:
    # D18: an un-created ALLOWED reservation keeps the experiment non-write-ready
    # (9.3 row 3; the real aggregate_experiment returns NOT_YET_TERMINAL over this
    # store -- see the non-constructibility case above), so the terminal write is
    # committed here through the repository's compare-and-swap, labelled as such;
    # 8.5 step 3 then refuses the successor at both revisions.
    start = _successor_ready()
    completed = _terminal(start.experiment, _E.COMPLETED)
    writer = InMemoryUnitOfWork(start.store).begin()
    _ok(writer.experiments.compare_and_swap(start.revision, completed))
    _commit(writer)
    assert _stored(start.store) == completed
    revision = start.revision + revision_offset
    identity = CountingIdentitySource()
    clock = CountingClock(DUE_INSTANT)
    result = _successor(
        InMemoryUnitOfWork(start.store),
        expected_revision=revision,
        clock=clock,
        identity_source=identity,
    )
    assert _code(result) == INVARIANT_VIOLATION
    assert identity.draws == 0
    assert clock.reads == 1
    assert _stored(start.store) == completed
    _assert_children_untouched(start)
    # D11: the committed terminal record replays as its verdict with () -- identity
    # in verdict only, reason codes are not durable in Stage 5 -- with no write.
    replay = _ok(
        _aggregate(
            InMemoryUnitOfWork(start.store),
            expected_revision=revision,
            clock=FailingClock(),
        )
    )
    assert replay.verdict is AggregationVerdict.COMPLETED
    assert replay.reason_codes == ()
    assert _stored(start.store) == completed


def test_an_existing_successor_still_replays_after_the_cancellation() -> None:
    # Plan 8.5 step 2 precedes step 3 (Task 7 note A preserved): the exactly-one
    # successor guarantee holds after the experiment left RUNNING; identical material
    # replays clock-free with no draw, divergent material is CONCURRENCY_CONFLICT.
    start = _successor_ready()
    created = _ok(
        _successor(InMemoryUnitOfWork(start.store), expected_revision=start.revision)
    )
    assert created.attempt.attempt_number == 2
    assert created.experiment.revision == 4
    cancelled = _ok(_cancel(InMemoryUnitOfWork(start.store), expected_revision=4))
    assert cancelled.revision == 5
    identity = CountingIdentitySource()
    replayed = _ok(
        _successor(
            InMemoryUnitOfWork(start.store),
            expected_revision=cancelled.revision,
            clock=FailingClock(),
            identity_source=identity,
        )
    )
    assert replayed.attempt == created.attempt
    assert replayed.experiment == cancelled
    assert _missing(replayed.attempt_token)
    assert identity.draws == 0
    divergent = _successor(
        InMemoryUnitOfWork(start.store),
        expected_revision=cancelled.revision,
        request_hash=OTHER_REQUEST_HASH,
        identity_source=identity,
    )
    assert _code(divergent) == CONCURRENCY_CONFLICT
    assert identity.draws == 0
    assert _stored(start.store) == cancelled
    _assert_children_untouched(start, created.attempt)
    _assert_cancelled_replay(start.store, cancelled.revision)


# --------------------------------------------------------------------------
# D. Restart and rolled-back state (plan 11; contract D11, D14, D19)
# --------------------------------------------------------------------------


def test_after_row_two_a_rebuilt_root_shows_only_the_winner_and_the_seeds() -> None:
    # Plan 11: the rebuilt root observes the winner's CANCELLED record and the two
    # seeded runs; the loser wrote nothing to roll forward; the replay is CANCELLED ().
    start = _write_ready()

    def loser(root: InMemoryUnitOfWork) -> Result[ExperimentAggregationResult]:
        return _aggregate(root, expected_revision=start.revision)

    result, won, _fired = _race(start.store, loser=loser, winner=_cancel_winner(start))
    assert _ok(result).verdict is AggregationVerdict.CANCELLED
    rebuilt = InMemoryUnitOfWork(start.store)
    reader = rebuilt.begin()
    stored = _ok(reader.experiments.get(EXPERIMENT_ID))
    latest_a = _ok(reader.engine_runs.latest_attempt(EXPERIMENT_ID, SLOT_A))
    latest_b = _ok(reader.engine_runs.latest_attempt(EXPERIMENT_ID, SLOT_B))
    reader.rollback()
    assert stored == won
    assert stored.state is _E.CANCELLED
    assert stored.revision == 4
    assert (latest_a, latest_b) == start.runs
    assert rebuilt.hooks_installed == ()
    _assert_children_untouched(start)
    replay = _ok(_aggregate(rebuilt, expected_revision=4, clock=FailingClock()))
    assert replay.verdict is AggregationVerdict.CANCELLED
    assert replay.reason_codes == ()
    assert _stored(start.store) == won


def test_after_row_eight_a_rebuilt_root_replays_the_winner_verdict_only() -> None:
    # Plan 11 / D11 / D14: the rebuilt root observes the winner's terminal record and
    # no attempt for B; a repeated aggregate returns (verdict, ()) -- not the
    # terminalizing result's reason codes -- and the revision does not move.
    start = _unavailable_b()

    def loser(root: InMemoryUnitOfWork) -> Result[AttemptCreation]:
        return _attempt(root, expected_revision=start.revision, seed="loser")

    result, won, _fired = _race(
        start.store, loser=loser, winner=_aggregate_winner(start)
    )
    assert _code(result) == INVARIANT_VIOLATION
    assert won.verdict is AggregationVerdict.COMPLETED_WITH_WARNINGS
    assert won.reason_codes == (REASON_SLOT_UNAVAILABLE,)
    rebuilt = InMemoryUnitOfWork(start.store)
    reader = rebuilt.begin()
    stored = _ok(reader.experiments.get(EXPERIMENT_ID))
    latest_b = _ok(reader.engine_runs.latest_attempt(EXPERIMENT_ID, SLOT_B))
    reader.rollback()
    assert stored.state is _E.COMPLETED_WITH_WARNINGS
    assert stored.revision == 4
    assert _missing(latest_b)
    assert rebuilt.hooks_installed == ()
    _assert_children_untouched(start)
    replay = _ok(_aggregate(rebuilt, expected_revision=4, clock=FailingClock()))
    assert replay.verdict is won.verdict
    assert replay.reason_codes != won.reason_codes
    assert replay.reason_codes == ()
    assert _stored(start.store) == stored
    assert _bytes(_stored(start.store)) == _bytes(stored)


def test_after_row_four_the_successor_replays_and_cancel_bumps_once() -> None:
    # Plan 11 / D19: the winner's successor is durable across a rebuilt root; an
    # identical create_successor at 4 replays clock-free without a bump; the
    # cancellation then bumps 4 -> 5 exactly once and its own replay bumps nothing.
    start = _successor_ready()

    def loser(root: InMemoryUnitOfWork) -> Result[ExperimentRecord]:
        return _cancel(root, expected_revision=start.revision)

    result, won, _fired = _race(
        start.store, loser=loser, winner=_successor_winner(start)
    )
    assert _code(result) == CONCURRENCY_CONFLICT
    rebuilt = InMemoryUnitOfWork(start.store)
    reader = rebuilt.begin()
    latest = _ok(reader.engine_runs.latest_attempt(EXPERIMENT_ID, SLOT_A))
    reader.rollback()
    assert latest == won.attempt
    identity = CountingIdentitySource("fresh")
    replayed = _ok(
        _successor(
            rebuilt,
            expected_revision=4,
            clock=FailingClock(),
            identity_source=identity,
        )
    )
    assert replayed.attempt == won.attempt
    assert replayed.experiment == won.experiment
    assert replayed.experiment.revision == 4
    assert _missing(replayed.attempt_token)
    assert identity.draws == 0
    assert _stored(start.store) == won.experiment
    cancelled = _ok(_cancel(rebuilt, expected_revision=4))
    assert cancelled.state is _E.CANCELLED
    assert cancelled.revision == 5
    again = _ok(
        _cancel(
            InMemoryUnitOfWork(start.store),
            expected_revision=5,
            clock=FixedClock(LATER_INSTANT),
        )
    )
    assert again == cancelled
    assert _stored(start.store) == cancelled
    _assert_children_untouched(start, won.attempt)
    _assert_cancelled_replay(start.store, cancelled.revision)


# --------------------------------------------------------------------------
# E. Hook hygiene (the double's one-shot hook; contract D25)
# --------------------------------------------------------------------------


def test_a_rejection_before_the_swap_never_reaches_the_installed_hook() -> None:
    # A stale revision fails at 9.1 step 4 and at D6 step 5, before any
    # compare-and-swap: the one-shot hook stays installed until reset_hooks.
    start = _write_ready()
    root = InMemoryUnitOfWork(start.store)

    def never(expected_revision: int, candidate: ExperimentRecord) -> None:
        raise AssertionError(f"no swap is reached: {expected_revision} {candidate!r}")

    root.install_experiment_compare_and_swap_hook(never)
    stale = start.revision - 1
    assert _code(_cancel(root, expected_revision=stale)) == CONCURRENCY_CONFLICT
    assert root.hooks_installed == _CAS_HOOK
    assert _code(_aggregate(root, expected_revision=stale)) == CONCURRENCY_CONFLICT
    assert root.hooks_installed == _CAS_HOOK
    root.reset_hooks()
    assert root.hooks_installed == ()
    assert _stored(start.store) == start.experiment
    _assert_children_untouched(start)


def test_the_winner_inside_the_hook_does_not_retrigger_the_consumed_hook() -> None:
    # The hook is removed from the root BEFORE it fires; the winner's own swap runs
    # through a separate root; a later real swap through the SAME root meets no hook.
    start = _successor_ready()
    root = InMemoryUnitOfWork(start.store)
    fired: list[int] = []

    def hook(expected_revision: int, _candidate: ExperimentRecord) -> None:
        fired.append(expected_revision)
        assert root.hooks_installed == ()
        _successor_winner(start)()

    root.install_experiment_compare_and_swap_hook(hook)
    lost = _cancel(root, expected_revision=start.revision)
    assert _code(lost) == CONCURRENCY_CONFLICT
    assert fired == [start.revision]
    assert _stored(start.store).revision == 4
    cancelled = _ok(_cancel(root, expected_revision=4))
    assert cancelled.state is _E.CANCELLED
    assert cancelled.revision == 5
    assert fired == [start.revision]
    assert root.hooks_installed == ()
    _assert_cancelled_replay(start.store, cancelled.revision)
    assert len(start.store.committed_engine_runs()) == 2
