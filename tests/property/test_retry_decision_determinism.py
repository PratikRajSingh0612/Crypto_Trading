"""Property tests for the Task 7 retry decision and closure walk (plan 12, Task 7).

Stage 5 plan sections 8.1 (created attempts), 8.2 (the six gates, the recorded
precedence ``4, 1, 2, 3, 6, 5`` and causal-closure ownership), 8.3 (the two
preconditions) and 8.4 (the three-phase flow), read through the Task 7 service API
contract (``.superpowers/sdd/stage5/task7-service-api.md``: D1 for
``resolve_causal_closure``, D2-D7 for ``evaluate_retry``, and the D12 line that
names this module). Every case here fails at collection until Task 7's
``crypto_lab.experiments.retry`` exists; that import failure is the intended RED.

**The six-gate oracle** (plan 8.2), restated here and never re-derived from the
service. Over a generated slot history of ``n`` persisted terminal attempts whose
last attempt is the predecessor:

1. ``n < maximum_attempts_per_slot``, else ``ATTEMPT_BUDGET_EXHAUSTED``;
2. the predecessor's state maps to a ``RetryTerminalState`` that the frozen policy
   lists, else ``TERMINAL_STATE_NOT_RETRYABLE``;
3. the primary terminal diagnostic is ``retriable``, else
   ``PRIMARY_DIAGNOSTIC_NOT_RETRIABLE``;
4. no diagnostic in the causal closure has a hard-blocking category, else
   ``HARD_BLOCKED_OUTCOME`` carrying the blocker's ``error_code``;
5. the experiment is not terminal, else ``EXPERIMENT_TERMINAL``;
6. an ``UNAVAILABLE`` predecessor has a qualifying fresh availability observation,
   else ``AVAILABILITY_OBSERVATION_NOT_FRESH``.

The outcome is ``ALLOWED`` exactly when all six pass; the recorded reason is the
first failed gate in ``RETRY_DENIAL_PRECEDENCE``. ``ALLOWED`` reserves ``n + 1``,
fixes ``retry_not_before_utc = predecessor.updated_at_utc + retry_delay_seconds``
(durable facts, never the clock) and bumps the experiment revision by exactly one
with no state change; ``DENIED`` writes nothing to the experiment. The clock is
read exactly once, ``decided_at_utc`` is that instant, the committed row equals
the returned row, and a replay with a failing clock returns the identical row.

Three properties: (1) the oracle through ``evaluate_retry``; (2) for ``FAILED`` and
``TIMED_OUT`` predecessors the semantic projection and the delay are independent
of the evaluation instant while ``decided_at_utc`` follows it (D12 scopes the
``UNAVAILABLE`` case to instants before every candidate's expiry, so it is left to
property 1, whose instants all precede the fresh observation's expiry); (3)
``resolve_causal_closure`` over random DAGs equals the canonical pair set of the
nodes reachable from the primary, calls only ``get_many`` with sorted, unique,
never-repeated identifiers starting from ``(primary_id,)``, and a back edge from a
reachable node to the primary is a ``Failure`` with cause ``cycle``.

Declared test-local choices: graphs hold at most 33 nodes, so no chain breaches
D1's depth bound of 32 edges (the contract pins 33/34 nodes and 256/257 nodes in
the unit module) and the property oracle stays the reachable pair set; every
non-final attempt is ``FAILED`` with ``retry_reason`` ``FAILED``; an ``UNAVAILABLE``
history seeds the predecessor's own (unavailable) observation and a stale one that
never qualifies, so a qualifying observation exists exactly when the generator
says so; no observation is seeded for any other predecessor, so an observation
read there would surface as a repository ``Failure``. Generators draw enum
members, booleans and small integers only -- hypothesis is the single source of
randomness in ``tests/property`` -- and ``deadline=None`` because every example
builds an experiment record and drives the whole three-phase service, so
wall-clock time is work-bound rather than a signal.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Final, NamedTuple

from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.domain.diagnostics import Diagnostic, DiagnosticCategory
from crypto_lab.domain.engine_run import (
    NON_SUCCESS_TERMINAL_ENGINE_RUN_STATES,
    EngineRunRecord,
)
from crypto_lab.domain.experiment import ExperimentRecord
from crypto_lab.domain.lifecycle import (
    TERMINAL_EXPERIMENT_STATES,
    EngineRunState,
    ExperimentState,
    RetryTerminalState,
)
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.domain.retry import (
    HARD_BLOCKING_DIAGNOSTIC_CATEGORIES,
    MAX_ATTEMPTS_PER_SLOT,
    MAX_RETRY_DELAY_SECONDS,
    RETRY_DENIAL_PRECEDENCE,
    RETRY_PERMITTING_DIAGNOSTIC_CATEGORIES,
    CausalClosureEntry,
    RetryDecisionOutcome,
    RetryDecisionRecord,
    RetryDenialReason,
    RetryGate,
    RetryPolicy,
    canonical_causal_closure,
    denial_reason_for,
    retry_decision_semantic_projection,
    retry_terminal_state_of,
)
from crypto_lab.experiments.diagnostics import INVARIANT_VIOLATION
from crypto_lab.experiments.ports import DiagnosticReader
from crypto_lab.experiments.requests import RetryEvaluationRequest
from crypto_lab.experiments.retry import evaluate_retry, resolve_causal_closure
from doubles.experiments import (
    AVAIL_B,
    EXPERIMENT_ID,
    INSTANT,
    SLOT_A,
    UUID_C,
    CountingClock,
    FailingClock,
    InMemoryBackingStore,
    InMemoryUnitOfWork,
    sample_diagnostic,
    sample_draft,
    sample_experiment,
    sample_observation,
    sample_retry_policy,
    sample_run,
    sequential_diagnostic_id,
)

_E: Final = ExperimentState
_R: Final = EngineRunState
_G: Final = RetryGate
_N: Final = RetryDenialReason


def _missing(value: object) -> bool:
    return value is MISSING


def _ok[T](result: Success[T] | Failure) -> T:
    assert isinstance(result, Success), result
    return result.value


def _by_value[S: StrEnum](members: Iterable[S]) -> tuple[S, ...]:
    """A deterministic draw order: frozenset iteration varies per process."""
    return tuple(sorted(members, key=lambda member: member.value))


# --- The oracle tables (plan 8.2) --------------------------------------------------

#: Plan 8.2: the durable reason recorded when a gate is the selected failure.
_REASON_OF_GATE: Final[dict[RetryGate, RetryDenialReason]] = {
    _G.ATTEMPT_BUDGET: _N.ATTEMPT_BUDGET_EXHAUSTED,
    _G.TERMINAL_STATE: _N.TERMINAL_STATE_NOT_RETRYABLE,
    _G.PRIMARY_DIAGNOSTIC: _N.PRIMARY_DIAGNOSTIC_NOT_RETRIABLE,
    _G.HARD_BLOCK: _N.HARD_BLOCKED_OUTCOME,
    _G.EXPERIMENT_ACTIVE: _N.EXPERIMENT_TERMINAL,
    _G.AVAILABILITY_FRESHNESS: _N.AVAILABILITY_OBSERVATION_NOT_FRESH,
}
#: Plan 8.2: the fixed precedence ``4, 1, 2, 3, 6, 5`` in the gate vocabulary.
_PLAN_PRECEDENCE: Final[tuple[RetryGate, ...]] = (
    _G.HARD_BLOCK,
    _G.ATTEMPT_BUDGET,
    _G.TERMINAL_STATE,
    _G.PRIMARY_DIAGNOSTIC,
    _G.AVAILABILITY_FRESHNESS,
    _G.EXPERIMENT_ACTIVE,
)

# --- Draw vocabularies -----------------------------------------------------------

_PREDECESSOR_STATES: Final = _by_value(NON_SUCCESS_TERMINAL_ENGINE_RUN_STATES)
#: D12: the two predecessor states whose projection never reads the instant.
_CLOCK_INDEPENDENT_STATES: Final = (_R.FAILED, _R.TIMED_OUT)
#: D3 step 6: a terminal attempt exists only under RUNNING or a terminal experiment.
_EVALUABLE_EXPERIMENT_STATES: Final = (
    _E.RUNNING,
    *_by_value(TERMINAL_EXPERIMENT_STATES),
)
_HARD_BLOCKING_CATEGORIES: Final = _by_value(HARD_BLOCKING_DIAGNOSTIC_CATEGORIES)
_RETRY_PERMITTING_CATEGORIES: Final = _by_value(RETRY_PERMITTING_DIAGNOSTIC_CATEGORIES)
_BLOCKER_CODES: Final = ("CONFIG.INVALID_PARAMETER", "SECURITY.POLICY_DENIED")
#: The hard blocker's identifier, outside the ``1..5`` range of the attempt primaries.
_BLOCKER_ID: Final = sequential_diagnostic_id(0xFF)
#: A stale observation that never qualifies (observed exactly at completion).
_STALE_OBSERVATION_ID: Final = f"avail_{UUID_C}"
#: Later than every drawn evaluation instant, so freshness never expires mid-draw.
_OBSERVATION_EXPIRY: Final = INSTANT + timedelta(days=1)
_ATTEMPT_SPACING: Final = timedelta(minutes=1)
_MAX_CLOCK_OFFSET_SECONDS: Final = 3600
#: D1: a chain of 33 nodes (32 edges) is the largest that succeeds.
_MAX_GRAPH_NODES: Final = 33
_MAX_FORWARD_EDGES: Final = 3
#: Three categories (two retry-permitting, one hard-blocking) times three codes, so
#: a graph of up to 33 nodes repeats pairs and repeats codes across categories.
_CLOSURE_CATEGORIES: Final = (
    DiagnosticCategory.ADAPTER_UNAVAILABILITY,
    DiagnosticCategory.ENGINE_RUNTIME,
    DiagnosticCategory.USER_CONFIGURATION,
)
_CLOSURE_CODES: Final = (
    "ADAPTER.UNAVAILABLE",
    "CONFIG.INVALID_VALUE",
    "ENGINE.RUNTIME_FAILURE",
)
_OFFSETS = st.integers(min_value=0, max_value=_MAX_CLOCK_OFFSET_SECONDS)


# --- Generated slot histories ------------------------------------------------------


class _History(NamedTuple):
    """Every generated input of one slot history, as plain data."""

    maximum_attempts: int
    retry_states: tuple[RetryTerminalState, ...]
    delay_seconds: int
    attempt_count: int
    predecessor_state: EngineRunState
    retriable: bool
    hard_block_category: DiagnosticCategory | None
    hard_block_code: str
    primary_category: DiagnosticCategory
    experiment_state: ExperimentState
    fresh_observation: bool


@st.composite
def _histories(
    draw: st.DrawFn, *, predecessor_states: tuple[EngineRunState, ...]
) -> _History:
    retry_states = draw(
        st.lists(st.sampled_from(list(RetryTerminalState)), unique=True, max_size=3)
    )
    hard_blocked = draw(st.booleans())
    return _History(
        maximum_attempts=draw(
            st.integers(min_value=1, max_value=MAX_ATTEMPTS_PER_SLOT)
        ),
        retry_states=tuple(retry_states),
        delay_seconds=draw(st.integers(min_value=0, max_value=MAX_RETRY_DELAY_SECONDS)),
        attempt_count=draw(st.integers(min_value=1, max_value=MAX_ATTEMPTS_PER_SLOT)),
        predecessor_state=draw(st.sampled_from(predecessor_states)),
        retriable=draw(st.booleans()),
        hard_block_category=(
            draw(st.sampled_from(_HARD_BLOCKING_CATEGORIES)) if hard_blocked else None
        ),
        hard_block_code=draw(st.sampled_from(_BLOCKER_CODES)),
        primary_category=draw(st.sampled_from(_RETRY_PERMITTING_CATEGORIES)),
        experiment_state=draw(st.sampled_from(_EVALUABLE_EXPERIMENT_STATES)),
        fresh_observation=draw(st.booleans()),
    )


def _run_id(attempt_number: int) -> str:
    """A canonical ``run_`` UUID4 whose lexical order is the attempt order."""
    return f"run_{attempt_number:08x}-0000-4000-8000-000000000000"


def _policy(history: _History) -> RetryPolicy:
    return sample_retry_policy(
        maximum_attempts_per_slot=history.maximum_attempts,
        automatically_retry_terminal_states=history.retry_states,
        retry_delay_seconds=history.delay_seconds,
    )


def _experiment(history: _History) -> ExperimentRecord:
    """The experiment whose frozen policy is the generated one."""
    state = history.experiment_state
    return sample_experiment(
        state,
        draft=sample_draft(retry_policy=_policy(history)),
        include_compatibility=True if state is _E.CANCELLED else None,
    )


def _attempts(history: _History) -> tuple[EngineRunRecord, ...]:
    """``attempt_count`` chained terminal attempts; the last is the predecessor."""
    records: list[EngineRunRecord] = []
    for number in range(1, history.attempt_count + 1):
        final = number == history.attempt_count
        records.append(
            sample_run(
                history.predecessor_state if final else _R.FAILED,
                run_id=_run_id(number),
                attempt_number=number,
                predecessor_run_id=_run_id(number - 1) if number > 1 else None,
                retry_reason=RetryTerminalState.FAILED,
                primary_terminal_diagnostic_id=sequential_diagnostic_id(number),
                created_at_utc=INSTANT + _ATTEMPT_SPACING * (number - 1),
            )
        )
    return tuple(records)


def _seed_history(
    store: InMemoryBackingStore, history: _History
) -> tuple[ExperimentRecord, tuple[EngineRunRecord, ...]]:
    """Commit the rows through a transaction of the test's own; seed the reader
    tables directly on the store."""
    experiment = _experiment(history)
    attempts = _attempts(history)
    transaction = InMemoryUnitOfWork(store).begin()
    _ok(transaction.experiments.add(experiment))
    for attempt in attempts:
        _ok(transaction.engine_runs.add_attempt(attempt))
    _ok(transaction.commit())
    predecessor = attempts[-1]
    blocked = history.hard_block_category is not None
    for number, attempt in enumerate(attempts, start=1):
        final = attempt is predecessor
        store.seed_diagnostic(
            sample_diagnostic(
                sequential_diagnostic_id(number),
                category=(
                    history.primary_category
                    if final
                    else DiagnosticCategory.ENGINE_RUNTIME
                ),
                retriable=history.retriable if final else True,
                run_id=attempt.run_id,
                causal_diagnostic_ids=(_BLOCKER_ID,) if final and blocked else (),
            )
        )
    if history.hard_block_category is not None:
        store.seed_diagnostic(
            sample_diagnostic(
                _BLOCKER_ID,
                error_code=history.hard_block_code,
                category=history.hard_block_category,
                retriable=False,
                run_id=predecessor.run_id,
            )
        )
    if predecessor.state is _R.UNAVAILABLE:
        store.seed_availability_observation(sample_observation(available=False))
        store.seed_availability_observation(
            sample_observation(
                _STALE_OBSERVATION_ID,
                observed_at_utc=predecessor.updated_at_utc,
                expires_at_utc=_OBSERVATION_EXPIRY,
            )
        )
        if history.fresh_observation:
            store.seed_availability_observation(
                sample_observation(
                    AVAIL_B,
                    observed_at_utc=predecessor.updated_at_utc + timedelta(seconds=1),
                    expires_at_utc=_OBSERVATION_EXPIRY,
                )
            )
    return experiment, attempts


class _Evaluation(NamedTuple):
    """One fresh store, its seeded history and the decision the service returned."""

    store: InMemoryBackingStore
    experiment: ExperimentRecord
    attempts: tuple[EngineRunRecord, ...]
    request: RetryEvaluationRequest
    clock: CountingClock
    instant: datetime
    decision: RetryDecisionRecord

    @property
    def predecessor(self) -> EngineRunRecord:
        return self.attempts[-1]


def _evaluate(history: _History, offset_seconds: int) -> _Evaluation:
    """Seed ``history`` into a fresh store and evaluate once, with a counting clock
    at ``predecessor.updated_at_utc + offset_seconds`` and the stored revisions."""
    store = InMemoryBackingStore()
    experiment, attempts = _seed_history(store, history)
    predecessor = attempts[-1]
    request = RetryEvaluationRequest(
        schema_version="1.0.0",
        experiment_id=EXPERIMENT_ID,
        logical_slot_id=SLOT_A,
        predecessor_run_id=predecessor.run_id,
        expected_experiment_revision=experiment.revision,
        expected_predecessor_revision=predecessor.revision,
    )
    instant = predecessor.updated_at_utc + timedelta(seconds=offset_seconds)
    clock = CountingClock(instant)
    decision = _ok(
        evaluate_retry(request, unit_of_work=InMemoryUnitOfWork(store), clock=clock)
    )
    return _Evaluation(store, experiment, attempts, request, clock, instant, decision)


def _expected_failed_gates(history: _History) -> frozenset[RetryGate]:
    """Plan 8.2's six conditions over the generated history: the oracle."""
    mapped = retry_terminal_state_of(history.predecessor_state)
    failed: set[RetryGate] = set()
    if not history.attempt_count < history.maximum_attempts:
        failed.add(_G.ATTEMPT_BUDGET)
    if _missing(mapped) or mapped not in history.retry_states:
        failed.add(_G.TERMINAL_STATE)
    if not history.retriable:
        failed.add(_G.PRIMARY_DIAGNOSTIC)
    if history.hard_block_category is not None:
        failed.add(_G.HARD_BLOCK)
    if history.experiment_state in TERMINAL_EXPERIMENT_STATES:
        failed.add(_G.EXPERIMENT_ACTIVE)
    if history.predecessor_state is _R.UNAVAILABLE and not history.fresh_observation:
        failed.add(_G.AVAILABILITY_FRESHNESS)
    return frozenset(failed)


def _expected_reason(failed: frozenset[RetryGate]) -> RetryDenialReason:
    """Plan 8.2: the reason of the first failed gate in ``4, 1, 2, 3, 6, 5``."""
    for gate in RETRY_DENIAL_PRECEDENCE:
        if gate in failed:
            return _REASON_OF_GATE[gate]
    raise AssertionError("an ALLOWED decision records no denial reason")


# --- Generated causal graphs -------------------------------------------------------


class _Graph(NamedTuple):
    """A forward DAG over nodes ``0..n-1``; node 0 is the primary diagnostic."""

    edges: tuple[tuple[int, ...], ...]
    categories: tuple[DiagnosticCategory, ...]
    codes: tuple[str, ...]
    #: A node reachable from the primary, other than the primary; the cycle variant
    #: adds its back edge to node 0. ``None`` when the primary reaches nothing.
    back_edge_source: int | None


def _reachable(edges: tuple[tuple[int, ...], ...]) -> frozenset[int]:
    """Every node reachable from node 0 along ``edges`` (node 0 included)."""
    seen = {0}
    pending = [0]
    while pending:
        node = pending.pop()
        for child in edges[node]:
            if child not in seen:
                seen.add(child)
                pending.append(child)
    return frozenset(seen)


@st.composite
def _graphs(draw: st.DrawFn) -> _Graph:
    size = draw(st.integers(min_value=1, max_value=_MAX_GRAPH_NODES))
    edges: list[tuple[int, ...]] = []
    for node in range(size):
        targets: list[int] = []
        if node + 1 < size:
            targets = draw(
                st.lists(
                    st.integers(min_value=node + 1, max_value=size - 1),
                    max_size=_MAX_FORWARD_EDGES,
                    unique=True,
                )
            )
        edges.append(tuple(sorted(targets)))
    categories = draw(
        st.lists(st.sampled_from(_CLOSURE_CATEGORIES), min_size=size, max_size=size)
    )
    codes = draw(
        st.lists(st.sampled_from(_CLOSURE_CODES), min_size=size, max_size=size)
    )
    descendants = sorted(_reachable(tuple(edges)) - {0})
    source = draw(st.sampled_from(descendants)) if descendants else None
    return _Graph(tuple(edges), tuple(categories), tuple(codes), source)


def _seed_graph(store: InMemoryBackingStore, graph: _Graph, *, back_edge: bool) -> None:
    """Seed one diagnostic per node; ``back_edge`` adds ``back_edge_source -> 0``.

    Sequential identifiers sort by index, so a tuple built from ascending indexes
    is the sorted unique tuple ``Diagnostic`` requires.
    """
    for node, targets in enumerate(graph.edges):
        causes = set(targets)
        if back_edge and node == graph.back_edge_source:
            causes.add(0)
        store.seed_diagnostic(
            sample_diagnostic(
                sequential_diagnostic_id(node),
                error_code=graph.codes[node],
                category=graph.categories[node],
                causal_diagnostic_ids=tuple(
                    sequential_diagnostic_id(cause) for cause in sorted(causes)
                ),
            )
        )


def _expected_closure(graph: _Graph) -> tuple[CausalClosureEntry, ...]:
    """Plan 8.2: the whole pairs of every reachable node, deduplicated and sorted."""
    return canonical_causal_closure(
        CausalClosureEntry(
            category=graph.categories[node], error_code=graph.codes[node]
        )
        for node in sorted(_reachable(graph.edges))
    )


class _RecordingReader:
    """A ``DiagnosticReader`` that logs ``(method, identifiers)`` before delegating,
    passed DIRECTLY to the helper so the proof covers the helper alone."""

    def __init__(self, inner: DiagnosticReader) -> None:
        self._inner = inner
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    def get(self, diagnostic_id: str) -> Result[Diagnostic]:
        self.calls.append(("get", (diagnostic_id,)))
        return self._inner.get(diagnostic_id)

    def get_many(
        self, diagnostic_ids: tuple[str, ...]
    ) -> Result[tuple[Diagnostic, ...]]:
        self.calls.append(("get_many", diagnostic_ids))
        return self._inner.get_many(diagnostic_ids)


# --- The tables (preventive) -------------------------------------------------------


def test_the_oracle_tables_restate_plan_8_2_exactly() -> None:
    """Preventive: the imported precedence and the local reason table are the
    plan's, so a later edit cannot pass the properties by moving both sides."""
    assert RETRY_DENIAL_PRECEDENCE == _PLAN_PRECEDENCE
    assert set(_REASON_OF_GATE) == set(RetryGate)
    for gate, reason in _REASON_OF_GATE.items():
        assert denial_reason_for(gate) is reason
    every_category = frozenset(DiagnosticCategory)
    assert (
        HARD_BLOCKING_DIAGNOSTIC_CATEGORIES | RETRY_PERMITTING_DIAGNOSTIC_CATEGORIES
    ) == every_category
    assert (
        not HARD_BLOCKING_DIAGNOSTIC_CATEGORIES & RETRY_PERMITTING_DIAGNOSTIC_CATEGORIES
    )


# --- Property 1: the six-gate oracle through the service ---------------------------


@settings(max_examples=40, deadline=None)
@given(
    history=_histories(predecessor_states=_PREDECESSOR_STATES),
    offset_seconds=_OFFSETS,
)
def test_evaluate_retry_agrees_with_the_six_gate_oracle_and_replays_its_row(
    history: _History,
    offset_seconds: int,
) -> None:
    evaluation = _evaluate(history, offset_seconds)
    decision = evaluation.decision
    experiment = evaluation.experiment
    predecessor = evaluation.predecessor
    failed = _expected_failed_gates(history)
    # Plan 3.9 fields 2-9 and 16: identity, the durable facts and the single instant.
    assert decision.experiment_id == EXPERIMENT_ID
    assert decision.logical_slot_id == SLOT_A
    assert decision.predecessor_run_id == predecessor.run_id
    assert decision.experiment_spec_hash == experiment.spec_hash
    assert decision.retry_policy == experiment.spec.retry_policy
    assert decision.created_attempt_count == history.attempt_count
    assert decision.predecessor_terminal_state is history.predecessor_state
    assert decision.primary_terminal_diagnostic_id == sequential_diagnostic_id(
        history.attempt_count
    )
    assert decision.decided_at_utc == evaluation.instant
    assert evaluation.clock.reads == 1
    if failed:
        reason = _expected_reason(failed)
        assert decision.outcome is RetryDecisionOutcome.DENIED
        assert decision.denial_reason is reason
        if reason is _N.HARD_BLOCKED_OUTCOME:
            assert decision.hard_block_error_code == history.hard_block_code
        else:
            assert _missing(decision.hard_block_error_code)
        assert _missing(decision.retry_not_before_utc)
        assert _missing(decision.reserved_successor_attempt_number)
        assert _missing(decision.availability_observation_id)
        # Plan 9.1: a DENIED decision performs no experiment write.
        assert evaluation.store.committed_experiments() == (experiment,)
    else:
        assert decision.outcome is RetryDecisionOutcome.ALLOWED
        assert _missing(decision.denial_reason)
        assert _missing(decision.hard_block_error_code)
        assert decision.reserved_successor_attempt_number == history.attempt_count + 1
        assert decision.retry_not_before_utc == predecessor.updated_at_utc + timedelta(
            seconds=history.delay_seconds
        )
        if history.predecessor_state is _R.UNAVAILABLE:
            assert decision.availability_observation_id == AVAIL_B
        else:
            assert _missing(decision.availability_observation_id)
        # D6 step 0: revision + 1, updated_at_utc = now, state unchanged.
        bumped = ExperimentRecord.model_validate(
            {
                **experiment.model_dump(mode="python"),
                "revision": experiment.revision + 1,
                "updated_at_utc": evaluation.instant,
            }
        )
        assert evaluation.store.committed_experiments() == (bumped,)
    assert evaluation.store.committed_retry_decisions() == (decision,)
    assert evaluation.store.committed_engine_runs() == tuple(
        sorted(evaluation.attempts, key=lambda record: record.run_id)
    )
    # Plan 8.4 phase 1: the row replays with no clock read; the request's expected
    # revisions are not compared on replay (D2), so the original request serves.
    replayed = evaluate_retry(
        evaluation.request,
        unit_of_work=InMemoryUnitOfWork(evaluation.store),
        clock=FailingClock(),
    )
    assert _ok(replayed) == decision
    assert evaluation.store.committed_retry_decisions() == (decision,)


# --- Property 2: projection independence from the instant --------------------------


@settings(max_examples=40, deadline=None)
@given(
    history=_histories(predecessor_states=_CLOCK_INDEPENDENT_STATES),
    first_offset=_OFFSETS,
    second_offset=_OFFSETS,
)
def test_the_projection_and_the_delay_are_independent_of_the_clock_instant(
    history: _History,
    first_offset: int,
    second_offset: int,
) -> None:
    """Plan 3.9 and 8.4 phase 2: the same durable facts evaluated at two instants
    project identically; only ``decided_at_utc`` follows the instant."""
    first = _evaluate(history, first_offset)
    second = _evaluate(history, second_offset)
    assert retry_decision_semantic_projection(
        first.decision
    ) == retry_decision_semantic_projection(second.decision)
    assert first.decision.decided_at_utc == first.instant
    assert second.decision.decided_at_utc == second.instant
    assert (first.decision.decided_at_utc == second.decision.decided_at_utc) is (
        first_offset == second_offset
    )
    assert first.decision.retry_not_before_utc == second.decision.retry_not_before_utc
    if first.decision.outcome is RetryDecisionOutcome.ALLOWED:
        assert first.decision.retry_not_before_utc == (
            first.predecessor.updated_at_utc + timedelta(seconds=history.delay_seconds)
        )
    else:
        assert _missing(first.decision.retry_not_before_utc)


# --- Property 3: the closure walk over random DAGs ----------------------------------


@settings(max_examples=40, deadline=None)
@given(graph=_graphs())
def test_resolve_causal_closure_equals_the_reachable_pair_set_and_rejects_a_back_edge(
    graph: _Graph,
) -> None:
    primary_id = sequential_diagnostic_id(0)
    reachable = _reachable(graph.edges)
    store = InMemoryBackingStore()
    _seed_graph(store, graph, back_edge=False)
    transaction = InMemoryUnitOfWork(store).begin()
    reader = _RecordingReader(transaction.diagnostics)
    closure = _ok(resolve_causal_closure(reader, primary_id, now=INSTANT))
    transaction.rollback()
    assert closure == _expected_closure(graph)
    # D1: one get_many per level, sorted unique identifiers, level 0 is the primary,
    # a visited identifier is never fetched again, and get is never called.
    assert {method for method, _ in reader.calls} == {"get_many"}
    fetched = [identifiers for _, identifiers in reader.calls]
    assert fetched[0] == (primary_id,)
    for identifiers in fetched:
        assert identifiers == tuple(sorted(set(identifiers)))
    every = [identifier for identifiers in fetched for identifier in identifiers]
    assert len(every) == len(set(every))
    assert set(every) == {sequential_diagnostic_id(node) for node in reachable}
    if graph.back_edge_source is None:
        return
    # D1: a back edge to an ancestor is a cycle (a diamond or a cross edge is not).
    cyclic = InMemoryBackingStore()
    _seed_graph(cyclic, graph, back_edge=True)
    transaction = InMemoryUnitOfWork(cyclic).begin()
    result = resolve_causal_closure(transaction.diagnostics, primary_id, now=INSTANT)
    transaction.rollback()
    assert isinstance(result, Failure)
    assert len(result.diagnostics) == 1
    diagnostic = result.diagnostics[0]
    assert diagnostic.error_code == INVARIANT_VIOLATION
    assert diagnostic.timestamp_utc == INSTANT
    assert diagnostic.details["cause"] == "cycle"
    assert diagnostic.details["primary_terminal_diagnostic_id"] == primary_id
