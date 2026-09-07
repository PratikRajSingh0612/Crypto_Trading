"""Stage 5 Task 6: the run service -- ``create_attempt`` and ``transition_run``.

Plan sections 3.8, 5 (the attempt creation contract, steps 1-6, and the run
table), 9.1, 9.5 rows 5-6 and 10.1 (rows ``create_attempt`` and
``transition_run``), read through the Task 6 service API contract and the
cross-check dispositions: the owned-target check precedes replay, a same-state
request at a stale revision is a concurrency conflict, every lost swap reloads
exactly once, and ``availability_observation_id`` is request-governed only on a
transition into ``READY`` or ``UNAVAILABLE`` (a restated equal value is
tolerated elsewhere, a different one is an invariant violation, an omitted one
is carried forward).

Every case drives the service through the ROOT in-memory unit of work -- the
service calls ``begin()`` itself -- seeds state through a transaction of its own
and inspects the backing store's committed rows, so a rejected operation is
proven to write nothing. Races are simulated deterministically through the
double's one-shot experiment compare-and-swap hook; nothing here sleeps, starts
a thread or draws a random value.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.compatibility import CompatibilityOutcome
from crypto_lab.domain.engine_run import (
    LINKED_ONLY_RUN_EDGES,
    NON_SUCCESS_TERMINAL_ENGINE_RUN_STATES,
    AttemptTokenMaterial,
    EngineRunRecord,
    assert_run_transition,
)
from crypto_lab.domain.experiment import ExperimentRecord
from crypto_lab.domain.hashing import attempt_token_hash
from crypto_lab.domain.lifecycle import (
    ENGINE_RUN_TRANSITIONS,
    TERMINAL_EXPERIMENT_STATES,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.results import Failure, Success
from crypto_lab.experiments.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
)
from crypto_lab.experiments.experiment_service import cancel_experiment
from crypto_lab.experiments.requests import (
    AttemptCreationRequest,
    CancelExperimentRequest,
    RunTransitionRequest,
)
from crypto_lab.experiments.run_service import (
    AttemptCreation,
    create_attempt,
    transition_run,
)
from doubles.experiments import (
    ADAPTER_ALPHA,
    ADAPTER_BETA,
    AVAIL_A,
    AVAIL_B,
    DIAG_ID,
    ENGINE_ALPHA,
    ENGINE_BETA,
    EXPERIMENT_ID,
    INSTANT,
    OTHER_REQUEST_HASH,
    OTHER_RUN_ID,
    REQUEST_HASH,
    RUN_ID,
    SLOT_A,
    SLOT_B,
    SLOT_C,
    FixedClock,
    InMemoryBackingStore,
    InMemoryUnitOfWork,
    SequentialIdentitySource,
    sample_experiment,
    sample_run,
    sample_slot_compatibility,
)

_E = ExperimentState
_R = EngineRunState

#: Strictly after every fixture instant (``INSTANT`` plus at most five seconds),
#: so an accepted write is distinguishable from the seeded record.
CLOCK_INSTANT = INSTANT + timedelta(minutes=1)
#: A shape-valid ``ErrorCode`` for the request's ``reason_code``.
REASON_CODE = "RUN.CORE_DECISION"
#: Plan section 3.8 row 14: the two targets on which the request governs the
#: availability observation.
_OBSERVATION_GOVERNING_TARGETS = frozenset({_R.READY, _R.UNAVAILABLE})
#: Plan section 5: every table edge ``transition_run`` owns, in a stable order.
_GENERIC_EDGES: list[tuple[EngineRunState, EngineRunState]] = sorted(
    ENGINE_RUN_TRANSITIONS.transitions - LINKED_ONLY_RUN_EDGES,
    key=lambda edge: (edge[0].value, edge[1].value),
)
#: Plan section 5 step 4: every experiment state other than QUEUED and RUNNING.
_INELIGIBLE_EXPERIMENT_STATES: list[ExperimentState] = [
    _E.DRAFT,
    _E.VALIDATED,
    *sorted(TERMINAL_EXPERIMENT_STATES, key=lambda state: state.value),
]


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
    store: InMemoryBackingStore, *records: ExperimentRecord | EngineRunRecord
) -> None:
    """Commit the seed rows through a transaction of the test's own."""
    transaction = InMemoryUnitOfWork(store).begin()
    for record in records:
        if isinstance(record, ExperimentRecord):
            _ok(transaction.experiments.add(record))
        else:
            _ok(transaction.engine_runs.add_attempt(record))
    _commit(transaction)


def _by_run_id(*records: EngineRunRecord) -> tuple[EngineRunRecord, ...]:
    """The store's committed order: sorted by ``run_id``."""
    return tuple(sorted(records, key=lambda record: record.run_id))


def _edge_id(edge: tuple[EngineRunState, EngineRunState]) -> str:
    return f"{edge[0].value}->{edge[1].value}"


def _attempt_request(
    slot: str = SLOT_A,
    *,
    expected_revision: int,
    request_hash: str = REQUEST_HASH,
    experiment_id: str = EXPERIMENT_ID,
) -> AttemptCreationRequest:
    return AttemptCreationRequest(
        schema_version="1.0.0",
        experiment_id=experiment_id,
        logical_slot_id=slot,
        expected_experiment_revision=expected_revision,
        request_hash=request_hash,
    )


def _run_request(
    target: EngineRunState,
    *,
    expected_revision: int,
    run_id: str = RUN_ID,
    primary: str | None = None,
    observation: str | None = None,
) -> RunTransitionRequest:
    """``None`` means the optional field is omitted from the request."""
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "run_id": run_id,
        "expected_revision": expected_revision,
        "target_state": target,
        "reason_code": REASON_CODE,
    }
    if primary is not None:
        payload["primary_terminal_diagnostic_id"] = primary
    if observation is not None:
        payload["availability_observation_id"] = observation
    return RunTransitionRequest.model_validate(payload)


def _create(
    store: InMemoryBackingStore,
    request: AttemptCreationRequest,
    *,
    clock: FixedClock | None = None,
    seed: str = "task6",
    root: InMemoryUnitOfWork | None = None,
) -> Success[AttemptCreation] | Failure:
    return create_attempt(
        request,
        unit_of_work=InMemoryUnitOfWork(store) if root is None else root,
        clock=FixedClock(CLOCK_INSTANT) if clock is None else clock,
        identity_source=SequentialIdentitySource(seed),
    )


def _transition(
    store: InMemoryBackingStore,
    request: RunTransitionRequest,
    *,
    clock: FixedClock | None = None,
) -> Success[EngineRunRecord] | Failure:
    return transition_run(
        request,
        unit_of_work=InMemoryUnitOfWork(store),
        clock=FixedClock(CLOCK_INSTANT) if clock is None else clock,
    )


def _cancelled(stored: ExperimentRecord) -> ExperimentRecord:
    """The record a winning cancellation commits over ``stored`` (plan 9.1)."""
    return ExperimentRecord.model_validate(
        {
            **stored.model_dump(mode="python"),
            "state": _E.CANCELLED,
            "cancellation_correlation_id": "cancel-1",
            "revision": stored.revision + 1,
            "updated_at_utc": stored.updated_at_utc + timedelta(seconds=1),
        }
    )


def _an_hour_later() -> FixedClock:
    clock = FixedClock(CLOCK_INSTANT)
    clock.advance(3600)
    return clock


# --------------------------------------------------------------------------
# create_attempt: the plan section 5 contract (steps 1-6)
# --------------------------------------------------------------------------


def test_attempt_creation_is_a_nested_value_object_of_three_fields() -> None:
    assert issubclass(AttemptCreation, CanonicalModel)
    assert tuple(AttemptCreation.model_fields) == (
        "experiment",
        "attempt",
        "attempt_token",
    )


def test_the_first_attempt_moves_a_queued_experiment_to_running() -> None:
    store = InMemoryBackingStore()
    stored = sample_experiment(_E.QUEUED)
    _seed(store, stored)
    clock = FixedClock(CLOCK_INSTANT)
    request = _attempt_request(expected_revision=stored.revision)
    creation = _ok(_create(store, request, clock=clock))
    expected_identity = SequentialIdentitySource("task6")
    attempt = creation.attempt
    assert attempt.run_id == expected_identity.new_run_id()
    assert attempt.experiment_id == EXPERIMENT_ID
    assert attempt.logical_slot_id == SLOT_A
    assert attempt.attempt_number == 1
    assert attempt.state is _R.PENDING
    assert attempt.revision == 0
    assert attempt.adapter == ADAPTER_ALPHA
    assert attempt.engine == ENGINE_ALPHA
    assert attempt.request_hash == REQUEST_HASH
    assert attempt.created_at_utc == clock.now_utc()
    assert attempt.updated_at_utc == clock.now_utc()
    assert _missing(attempt.predecessor_run_id)
    assert _missing(attempt.retry_reason)
    assert _missing(attempt.primary_terminal_diagnostic_id)
    assert _missing(attempt.availability_observation_id)
    assert _missing(attempt.finalization_deadline_utc)
    token = creation.attempt_token
    assert isinstance(token, AttemptTokenMaterial)
    assert token.run_id == attempt.run_id
    assert token.attempt_token == expected_identity.new_attempt_token()
    assert attempt.attempt_token_hash == attempt_token_hash(token.attempt_token)
    experiment = creation.experiment
    assert experiment.state is _E.RUNNING
    assert experiment.revision == stored.revision + 1
    assert experiment.updated_at_utc == clock.now_utc()
    assert experiment.created_at_utc == stored.created_at_utc
    assert experiment.spec == stored.spec
    assert experiment.spec_hash == stored.spec_hash
    assert experiment.slot_compatibility == stored.slot_compatibility
    assert _missing(experiment.cancellation_correlation_id)
    assert store.committed_experiments() == (experiment,)
    assert store.committed_engine_runs() == (attempt,)


def test_a_later_slot_attempt_bumps_a_running_experiment_in_place() -> None:
    store = InMemoryBackingStore()
    stored = sample_experiment(_E.RUNNING)
    first = sample_run(_R.PENDING)
    _seed(store, stored, first)
    request = _attempt_request(
        SLOT_B, expected_revision=stored.revision, request_hash=OTHER_REQUEST_HASH
    )
    creation = _ok(_create(store, request))
    attempt = creation.attempt
    assert attempt.logical_slot_id == SLOT_B
    assert attempt.attempt_number == 1
    assert attempt.state is _R.PENDING
    assert attempt.revision == 0
    assert attempt.adapter == ADAPTER_BETA
    assert attempt.engine == ENGINE_BETA
    assert attempt.request_hash == OTHER_REQUEST_HASH
    assert attempt.run_id != first.run_id
    assert isinstance(creation.attempt_token, AttemptTokenMaterial)
    assert creation.experiment.state is _E.RUNNING
    assert creation.experiment.revision == stored.revision + 1
    assert creation.experiment.updated_at_utc == CLOCK_INSTANT
    assert store.committed_experiments() == (creation.experiment,)
    assert store.committed_engine_runs() == _by_run_id(first, attempt)


def test_a_frozen_unavailable_slot_may_still_receive_attempt_one() -> None:
    # Plan 9.5 row 7: only a frozen NOT_APPLICABLE outcome bars attempt creation.
    store = InMemoryBackingStore()
    stored = sample_experiment(
        _E.QUEUED,
        slot_compatibility=sample_slot_compatibility(
            outcomes={SLOT_B: CompatibilityOutcome.UNAVAILABLE}
        ),
    )
    _seed(store, stored)
    request = _attempt_request(SLOT_B, expected_revision=stored.revision)
    creation = _ok(_create(store, request))
    assert creation.attempt.logical_slot_id == SLOT_B
    assert creation.experiment.state is _E.RUNNING
    assert len(store.committed_engine_runs()) == 1


def test_identical_replay_returns_the_stored_records_without_a_write() -> None:
    store = InMemoryBackingStore()
    stored = sample_experiment(_E.RUNNING)
    first = sample_run(_R.PENDING)
    _seed(store, stored, first)
    request = _attempt_request(expected_revision=stored.revision)
    creation = _ok(_create(store, request, clock=_an_hour_later(), seed="other"))
    assert creation.attempt == first
    assert creation.experiment == stored
    assert _missing(creation.attempt_token)
    assert store.committed_experiments() == (stored,)
    assert store.committed_engine_runs() == (first,)


def test_identical_replay_is_recognised_before_the_revision_check() -> None:
    # Contract order: step 2 (replay) precedes step 5 (expected revision).
    store = InMemoryBackingStore()
    stored = sample_experiment(_E.RUNNING)
    first = sample_run(_R.PENDING)
    _seed(store, stored, first)
    request = _attempt_request(expected_revision=stored.revision - 1)
    creation = _ok(_create(store, request))
    assert creation.attempt == first
    assert creation.experiment == stored
    assert _missing(creation.attempt_token)
    assert store.committed_experiments() == (stored,)
    assert store.committed_engine_runs() == (first,)


def test_replay_against_a_slot_whose_current_attempt_is_a_successor() -> None:
    # The replay identity is attempt 1, loaded by number when the latest is later.
    store = InMemoryBackingStore()
    stored = sample_experiment(_E.RUNNING)
    first = sample_run(_R.FAILED)
    successor = sample_run(_R.PENDING, run_id=OTHER_RUN_ID, attempt_number=2)
    _seed(store, stored, first, successor)
    creation = _ok(_create(store, _attempt_request(expected_revision=stored.revision)))
    assert creation.attempt == first
    assert creation.attempt.attempt_number == 1
    assert _missing(creation.attempt_token)
    divergent = _create(
        store,
        _attempt_request(
            expected_revision=stored.revision, request_hash=OTHER_REQUEST_HASH
        ),
    )
    assert _code(divergent) == CONCURRENCY_CONFLICT
    assert store.committed_experiments() == (stored,)
    assert store.committed_engine_runs() == _by_run_id(first, successor)


def test_a_divergent_duplicate_is_a_conflict_with_no_write() -> None:
    store = InMemoryBackingStore()
    stored = sample_experiment(_E.RUNNING)
    first = sample_run(_R.PENDING)
    _seed(store, stored, first)
    request = _attempt_request(
        expected_revision=stored.revision, request_hash=OTHER_REQUEST_HASH
    )
    assert _code(_create(store, request)) == CONCURRENCY_CONFLICT
    assert store.committed_experiments() == (stored,)
    assert store.committed_engine_runs() == (first,)


def test_a_slot_outside_the_spec_is_an_invariant_violation() -> None:
    store = InMemoryBackingStore()
    stored = sample_experiment(_E.QUEUED)
    _seed(store, stored)
    request = _attempt_request(SLOT_C, expected_revision=stored.revision)
    assert _code(_create(store, request)) == INVARIANT_VIOLATION
    assert store.committed_experiments() == (stored,)
    assert store.committed_engine_runs() == ()


def test_a_frozen_not_applicable_slot_never_receives_an_attempt() -> None:
    store = InMemoryBackingStore()
    stored = sample_experiment(
        _E.QUEUED,
        slot_compatibility=sample_slot_compatibility(
            outcomes={SLOT_B: CompatibilityOutcome.NOT_APPLICABLE}
        ),
    )
    _seed(store, stored)
    request = _attempt_request(SLOT_B, expected_revision=stored.revision)
    assert _code(_create(store, request)) == INVARIANT_VIOLATION
    assert store.committed_experiments() == (stored,)
    assert store.committed_engine_runs() == ()


def test_the_ineligible_experiment_states_complement_queued_and_running() -> None:
    assert set(_INELIGIBLE_EXPERIMENT_STATES) | {_E.QUEUED, _E.RUNNING} == set(_E)
    assert len(_INELIGIBLE_EXPERIMENT_STATES) == 6


@pytest.mark.parametrize("state", _INELIGIBLE_EXPERIMENT_STATES)
def test_an_experiment_outside_queued_and_running_refuses_attempt_creation(
    state: ExperimentState,
) -> None:
    store = InMemoryBackingStore()
    stored = sample_experiment(state)
    _seed(store, stored)
    request = _attempt_request(expected_revision=stored.revision)
    assert _code(_create(store, request)) == INVARIANT_VIOLATION
    assert store.committed_experiments() == (stored,)
    assert store.committed_engine_runs() == ()


@pytest.mark.parametrize("revision_offset", [-1, 1])
def test_a_stale_expected_experiment_revision_is_a_conflict_with_no_write(
    revision_offset: int,
) -> None:
    store = InMemoryBackingStore()
    stored = sample_experiment(_E.QUEUED)
    _seed(store, stored)
    request = _attempt_request(expected_revision=stored.revision + revision_offset)
    assert _code(_create(store, request)) == CONCURRENCY_CONFLICT
    assert store.committed_experiments() == (stored,)
    assert store.committed_engine_runs() == ()


def test_a_missing_experiment_is_an_invariant_violation() -> None:
    store = InMemoryBackingStore()
    assert _code(_create(store, _attempt_request(expected_revision=0))) == (
        INVARIANT_VIOLATION
    )
    assert store.committed_experiments() == ()
    assert store.committed_engine_runs() == ()


def test_attempt_creation_is_deterministic_for_one_seed_across_stores() -> None:
    creations: list[AttemptCreation] = []
    for _ in range(2):
        store = InMemoryBackingStore()
        stored = sample_experiment(_E.QUEUED)
        _seed(store, stored)
        request = _attempt_request(expected_revision=stored.revision)
        creations.append(_ok(_create(store, request)))
    first, second = creations
    assert first == second
    assert first.attempt == second.attempt
    assert first.experiment == second.experiment
    first_token = first.attempt_token
    second_token = second.attempt_token
    assert isinstance(first_token, AttemptTokenMaterial)
    assert isinstance(second_token, AttemptTokenMaterial)
    assert first_token.attempt_token == second_token.attempt_token
    # A different seed draws a different identity and token.
    other_store = InMemoryBackingStore()
    _seed(other_store, sample_experiment(_E.QUEUED))
    other = _ok(
        _create(other_store, _attempt_request(expected_revision=2), seed="other")
    )
    assert other.attempt.run_id != first.attempt.run_id
    assert other.attempt.attempt_token_hash != first.attempt.attempt_token_hash


# --------------------------------------------------------------------------
# create_attempt under contention (plan 9.1, 9.5 rows 5-6; reload-once)
# --------------------------------------------------------------------------


def test_a_cancellation_winner_leaves_no_attempt_durable() -> None:
    # Plan 9.5 row 6: the loser's reload shows CANCELLED; step 4 -> INVARIANT.
    store = InMemoryBackingStore()
    stored = sample_experiment(_E.RUNNING)
    first = sample_run(_R.PENDING)
    _seed(store, stored, first)
    cancelled = _cancelled(stored)
    root = InMemoryUnitOfWork(store)
    fired: list[int] = []

    def cancel_winner(expected_revision: int, _candidate: ExperimentRecord) -> None:
        fired.append(expected_revision)
        winner = InMemoryUnitOfWork(store).begin()
        _ok(winner.experiments.compare_and_swap(expected_revision, cancelled))
        _commit(winner)

    root.install_experiment_compare_and_swap_hook(cancel_winner)
    request = _attempt_request(SLOT_B, expected_revision=stored.revision)
    result = _create(store, request, root=root)
    assert _code(result) == INVARIANT_VIOLATION
    assert fired == [stored.revision]
    assert root.hooks_installed == ()
    assert store.committed_experiments() == (cancelled,)
    assert store.committed_engine_runs() == (first,)


def test_an_attempt_winner_with_the_same_hash_turns_the_loser_into_a_replay() -> None:
    store = InMemoryBackingStore()
    stored = sample_experiment(_E.QUEUED)
    _seed(store, stored)
    root = InMemoryUnitOfWork(store)
    winners: list[AttemptCreation] = []

    def attempt_winner(_expected_revision: int, _candidate: ExperimentRecord) -> None:
        request = _attempt_request(expected_revision=stored.revision)
        winners.append(_ok(_create(store, request, seed="winner")))

    root.install_experiment_compare_and_swap_hook(attempt_winner)
    request = _attempt_request(expected_revision=stored.revision)
    creation = _ok(_create(store, request, root=root, seed="loser"))
    (winner,) = winners
    assert creation.attempt == winner.attempt
    assert creation.attempt.run_id == SequentialIdentitySource("winner").new_run_id()
    assert creation.experiment == winner.experiment
    assert creation.experiment.state is _E.RUNNING
    assert creation.experiment.revision == stored.revision + 1
    assert _missing(creation.attempt_token)
    assert store.committed_experiments() == (winner.experiment,)
    assert store.committed_engine_runs() == (winner.attempt,)


def test_an_attempt_winner_with_a_different_hash_makes_the_loser_conflict() -> None:
    store = InMemoryBackingStore()
    stored = sample_experiment(_E.QUEUED)
    _seed(store, stored)
    root = InMemoryUnitOfWork(store)
    winners: list[AttemptCreation] = []

    def attempt_winner(_expected_revision: int, _candidate: ExperimentRecord) -> None:
        request = _attempt_request(
            expected_revision=stored.revision, request_hash=OTHER_REQUEST_HASH
        )
        winners.append(_ok(_create(store, request, seed="winner")))

    root.install_experiment_compare_and_swap_hook(attempt_winner)
    request = _attempt_request(expected_revision=stored.revision)
    result = _create(store, request, root=root, seed="loser")
    assert _code(result) == CONCURRENCY_CONFLICT
    (winner,) = winners
    assert winner.attempt.request_hash == OTHER_REQUEST_HASH
    assert store.committed_experiments() == (winner.experiment,)
    assert store.committed_engine_runs() == (winner.attempt,)


def test_a_stale_cancellation_after_an_attempt_winner_returns_the_conflict() -> None:
    # Plan 9.5 row 5: the reload shows RUNNING at N+1; 9.1 step 4 -> CONFLICT.
    store = InMemoryBackingStore()
    stored = sample_experiment(_E.RUNNING)
    first = sample_run(_R.PENDING)
    _seed(store, stored, first)
    root = InMemoryUnitOfWork(store)
    winners: list[AttemptCreation] = []

    def attempt_winner(_expected_revision: int, _candidate: ExperimentRecord) -> None:
        request = _attempt_request(
            SLOT_B, expected_revision=stored.revision, request_hash=OTHER_REQUEST_HASH
        )
        winners.append(_ok(_create(store, request, seed="winner")))

    root.install_experiment_compare_and_swap_hook(attempt_winner)
    result = cancel_experiment(
        CancelExperimentRequest(
            schema_version="1.0.0",
            experiment_id=EXPERIMENT_ID,
            expected_revision=stored.revision,
            correlation_id="cancel-1",
        ),
        unit_of_work=root,
        clock=FixedClock(CLOCK_INSTANT),
    )
    assert _code(result) == CONCURRENCY_CONFLICT
    (winner,) = winners
    assert winner.experiment.state is _E.RUNNING
    assert winner.experiment.revision == stored.revision + 1
    assert store.committed_experiments() == (winner.experiment,)
    assert store.committed_engine_runs() == _by_run_id(first, winner.attempt)


# --------------------------------------------------------------------------
# transition_run: the plan section 5 table, edge ownership and field shapes
# --------------------------------------------------------------------------


def test_transition_run_owns_twenty_one_of_the_twenty_three_table_edges() -> None:
    assert len(ENGINE_RUN_TRANSITIONS.transitions) == 23
    assert len(_GENERIC_EDGES) == 21
    assert LINKED_ONLY_RUN_EDGES == {
        (_R.READY, _R.STARTING),
        (_R.STARTING, _R.RUNNING),
    }


@pytest.mark.parametrize("edge", _GENERIC_EDGES, ids=_edge_id)
def test_every_generic_edge_is_accepted_with_revision_plus_one_at_the_clock(
    edge: tuple[EngineRunState, EngineRunState],
) -> None:
    current, target = edge
    store = InMemoryBackingStore()
    stored = sample_run(current)
    _seed(store, stored)
    request = _run_request(
        target,
        expected_revision=stored.revision,
        primary=DIAG_ID if target in NON_SUCCESS_TERMINAL_ENGINE_RUN_STATES else None,
        observation=AVAIL_B if target in _OBSERVATION_GOVERNING_TARGETS else None,
    )
    replacement = _ok(_transition(store, request))
    assert replacement.state is target
    assert replacement.revision == stored.revision + 1
    assert replacement.updated_at_utc == CLOCK_INSTANT
    assert replacement.created_at_utc == stored.created_at_utc
    assert replacement.run_id == stored.run_id
    assert replacement.experiment_id == stored.experiment_id
    assert replacement.logical_slot_id == stored.logical_slot_id
    assert replacement.attempt_number == stored.attempt_number
    assert replacement.attempt_token_hash == stored.attempt_token_hash
    assert replacement.adapter == stored.adapter
    assert replacement.engine == stored.engine
    assert replacement.request_hash == stored.request_hash
    if target in NON_SUCCESS_TERMINAL_ENGINE_RUN_STATES:
        assert replacement.primary_terminal_diagnostic_id == DIAG_ID
    else:
        assert _missing(replacement.primary_terminal_diagnostic_id)
    if target in _OBSERVATION_GOVERNING_TARGETS:
        assert replacement.availability_observation_id == AVAIL_B
    else:
        assert (
            replacement.availability_observation_id
            == stored.availability_observation_id
        )
    assert_run_transition(stored, replacement)
    assert store.committed_engine_runs() == (replacement,)
    # The write set is the run alone; no experiment is read or touched.
    assert store.committed_experiments() == ()


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (_R.READY, _R.STARTING),
        (_R.STARTING, _R.RUNNING),
        (_R.STARTING, _R.STARTING),
        (_R.RUNNING, _R.RUNNING),
    ],
)
def test_linked_only_targets_are_rejected_before_replay_is_considered(
    current: EngineRunState, target: EngineRunState
) -> None:
    store = InMemoryBackingStore()
    stored = sample_run(current)
    _seed(store, stored)
    request = _run_request(target, expected_revision=stored.revision)
    assert _code(_transition(store, request)) == INVARIANT_VIOLATION
    assert store.committed_engine_runs() == (stored,)


@pytest.mark.parametrize("state", [_R.VALIDATING, _R.FAILED, _R.SUCCEEDED])
def test_a_same_state_request_at_the_stored_revision_is_a_replay(
    state: EngineRunState,
) -> None:
    store = InMemoryBackingStore()
    stored = sample_run(state)
    _seed(store, stored)
    primary = DIAG_ID if state in NON_SUCCESS_TERMINAL_ENGINE_RUN_STATES else None
    request = _run_request(state, expected_revision=stored.revision, primary=primary)
    assert _ok(_transition(store, request, clock=_an_hour_later())) == stored
    assert store.committed_engine_runs() == (stored,)


@pytest.mark.parametrize("state", [_R.VALIDATING, _R.FAILED])
def test_a_same_state_request_at_a_stale_revision_is_a_conflict(
    state: EngineRunState,
) -> None:
    store = InMemoryBackingStore()
    stored = sample_run(state)
    _seed(store, stored)
    primary = DIAG_ID if state in NON_SUCCESS_TERMINAL_ENGINE_RUN_STATES else None
    request = _run_request(
        state, expected_revision=stored.revision - 1, primary=primary
    )
    assert _code(_transition(store, request)) == CONCURRENCY_CONFLICT
    assert store.committed_engine_runs() == (stored,)


@pytest.mark.parametrize("revision_offset", [0, -1, 1])
def test_a_terminal_run_refuses_another_target_regardless_of_revision(
    revision_offset: int,
) -> None:
    store = InMemoryBackingStore()
    stored = sample_run(_R.SUCCEEDED)
    _seed(store, stored)
    request = _run_request(
        _R.CANCELLED,
        expected_revision=stored.revision + revision_offset,
        primary=DIAG_ID,
    )
    assert _code(_transition(store, request)) == INVARIANT_VIOLATION
    assert store.committed_engine_runs() == (stored,)


@pytest.mark.parametrize(
    ("current", "target", "revision_offset"),
    [
        (_R.PENDING, _R.READY, 0),
        (_R.RUNNING, _R.VALIDATING, 0),
        (_R.PENDING, _R.SUCCEEDED, 0),
        (_R.VALIDATING, _R.SUCCEEDED, -1),
    ],
)
def test_a_forbidden_edge_is_an_invariant_violation_even_at_a_stale_revision(
    current: EngineRunState, target: EngineRunState, revision_offset: int
) -> None:
    store = InMemoryBackingStore()
    stored = sample_run(current)
    _seed(store, stored)
    request = _run_request(
        target,
        expected_revision=stored.revision + revision_offset,
        observation=AVAIL_B if target in _OBSERVATION_GOVERNING_TARGETS else None,
    )
    assert _code(_transition(store, request)) == INVARIANT_VIOLATION
    assert store.committed_engine_runs() == (stored,)


@pytest.mark.parametrize("revision_offset", [-1, 1])
def test_a_stale_revision_on_a_permitted_edge_is_a_conflict_with_no_write(
    revision_offset: int,
) -> None:
    store = InMemoryBackingStore()
    stored = sample_run(_R.VALIDATING)
    _seed(store, stored)
    request = _run_request(
        _R.READY,
        expected_revision=stored.revision + revision_offset,
        observation=AVAIL_B,
    )
    assert _code(_transition(store, request)) == CONCURRENCY_CONFLICT
    assert store.committed_engine_runs() == (stored,)


def test_validating_to_ready_requires_an_availability_observation() -> None:
    store = InMemoryBackingStore()
    stored = sample_run(_R.VALIDATING)
    _seed(store, stored)
    request = _run_request(_R.READY, expected_revision=stored.revision)
    assert _code(_transition(store, request)) == INVARIANT_VIOLATION
    assert store.committed_engine_runs() == (stored,)


def test_a_different_observation_on_a_non_governing_target_is_rejected() -> None:
    store = InMemoryBackingStore()
    stored = sample_run(_R.READY)
    assert stored.availability_observation_id == AVAIL_A
    _seed(store, stored)
    request = _run_request(
        _R.CANCELLED,
        expected_revision=stored.revision,
        primary=DIAG_ID,
        observation=AVAIL_B,
    )
    assert _code(_transition(store, request)) == INVARIANT_VIOLATION
    assert store.committed_engine_runs() == (stored,)


def test_an_equal_observation_restated_on_a_non_governing_target_is_kept() -> None:
    store = InMemoryBackingStore()
    stored = sample_run(_R.READY)
    _seed(store, stored)
    request = _run_request(
        _R.CANCELLED,
        expected_revision=stored.revision,
        primary=DIAG_ID,
        observation=AVAIL_A,
    )
    replacement = _ok(_transition(store, request))
    assert replacement.state is _R.CANCELLED
    assert replacement.availability_observation_id == AVAIL_A
    assert replacement.primary_terminal_diagnostic_id == DIAG_ID
    assert replacement.revision == stored.revision + 1
    assert store.committed_engine_runs() == (replacement,)


def test_an_omitted_observation_on_a_non_governing_target_is_carried() -> None:
    store = InMemoryBackingStore()
    stored = sample_run(_R.READY)
    _seed(store, stored)
    request = _run_request(
        _R.CANCELLED, expected_revision=stored.revision, primary=DIAG_ID
    )
    replacement = _ok(_transition(store, request))
    assert replacement.state is _R.CANCELLED
    assert replacement.availability_observation_id == AVAIL_A
    assert replacement.updated_at_utc == CLOCK_INSTANT
    assert store.committed_engine_runs() == (replacement,)


def test_running_to_unavailable_records_a_fresh_observation() -> None:
    store = InMemoryBackingStore()
    stored = sample_run(_R.RUNNING)
    assert stored.availability_observation_id == AVAIL_A
    _seed(store, stored)
    request = _run_request(
        _R.UNAVAILABLE,
        expected_revision=stored.revision,
        primary=DIAG_ID,
        observation=AVAIL_B,
    )
    replacement = _ok(_transition(store, request))
    assert replacement.state is _R.UNAVAILABLE
    assert replacement.availability_observation_id == AVAIL_B
    assert replacement.primary_terminal_diagnostic_id == DIAG_ID
    assert_run_transition(stored, replacement)
    assert store.committed_engine_runs() == (replacement,)


_NON_SUCCESS_TERMINAL_EDGES: list[tuple[EngineRunState, EngineRunState]] = [
    (_R.RUNNING, _R.FAILED),
    (_R.PENDING, _R.CANCELLED),
    (_R.RUNNING, _R.TIMED_OUT),
    (_R.VALIDATING, _R.NOT_APPLICABLE),
    (_R.READY, _R.UNAVAILABLE),
]


def test_the_non_success_terminal_edges_cover_exactly_the_five_states() -> None:
    assert {target for _, target in _NON_SUCCESS_TERMINAL_EDGES} == (
        NON_SUCCESS_TERMINAL_ENGINE_RUN_STATES
    )
    assert len(NON_SUCCESS_TERMINAL_ENGINE_RUN_STATES) == 5


@pytest.mark.parametrize("edge", _NON_SUCCESS_TERMINAL_EDGES, ids=_edge_id)
def test_a_non_success_terminal_target_requires_the_primary_diagnostic(
    edge: tuple[EngineRunState, EngineRunState],
) -> None:
    current, target = edge
    store = InMemoryBackingStore()
    stored = sample_run(current)
    _seed(store, stored)
    request = _run_request(
        target,
        expected_revision=stored.revision,
        observation=AVAIL_B if target in _OBSERVATION_GOVERNING_TARGETS else None,
    )
    assert _code(_transition(store, request)) == INVARIANT_VIOLATION
    assert store.committed_engine_runs() == (stored,)


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (_R.PENDING, _R.VALIDATING),
        (_R.VALIDATING, _R.READY),
        (_R.RUNNING, _R.SUCCEEDED),
    ],
)
def test_a_primary_diagnostic_on_a_non_terminal_or_success_target_is_rejected(
    current: EngineRunState, target: EngineRunState
) -> None:
    store = InMemoryBackingStore()
    stored = sample_run(current)
    _seed(store, stored)
    request = _run_request(
        target,
        expected_revision=stored.revision,
        primary=DIAG_ID,
        observation=AVAIL_B if target in _OBSERVATION_GOVERNING_TARGETS else None,
    )
    assert _code(_transition(store, request)) == INVARIANT_VIOLATION
    assert store.committed_engine_runs() == (stored,)


def test_a_missing_run_is_an_invariant_violation() -> None:
    store = InMemoryBackingStore()
    request = _run_request(_R.VALIDATING, expected_revision=0)
    assert _code(_transition(store, request)) == INVARIANT_VIOLATION
    assert store.committed_engine_runs() == ()
    other = _run_request(_R.VALIDATING, expected_revision=0, run_id=OTHER_RUN_ID)
    assert _code(_transition(store, other)) == INVARIANT_VIOLATION
    assert store.committed_engine_runs() == ()
