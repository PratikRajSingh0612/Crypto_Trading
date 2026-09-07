"""Stage 5 Task 7: the retry decision -- ``evaluate_retry``, ``resolve_causal_closure``
and ``build_retry_evaluation_snapshot``.

Plan sections 8.1 (created attempts), 8.2 (the six gates and the single
causal-closure owner), 8.3 (preconditions), 8.4 (the three-phase flow), 8.6
(codes), 9.1 (the experiment revision as the mutual-exclusion primitive), 9.5 rows
9-10 and 12 Task 7 (the focused RED list), read through the Task 7 service API
contract (D1-D7 and its adopted cross-check notes). Declared readings exercised
here: the primary is read through ``diagnostics.get`` before the helper's
``get_many``; a helper ``Failure`` whose every diagnostic is
``CORE.INVARIANT_VIOLATION`` fail-closes to ``FAIL_CLOSED_CAUSAL_CLOSURE`` while any
other reader fault aborts unchanged; the snapshot carries gate 6's qualifying
SELECTION rather than the unbounded ``list_for_adapter`` read; the ALLOWED
compare-and-swap runs before the decision insert, so revision movement surfaces
as the reload's ``PERSISTENCE.CONCURRENCY_CONFLICT`` or a phase 1 replay and never
as ``RETRY.DECISION_CONFLICT``.

Every case drives the service through the ROOT in-memory unit of work (the service
calls ``begin()`` itself), seeds rows through a transaction of its own and reads
the backing store's committed rows back, so a "no write" assertion is a statement
about durable state. Races are simulated deterministically through the double's
two one-shot hooks -- exactly one per scenario; a winner driven through the
service via the same root consumes the other. Clock doubles are injected into the
service only; the root keeps its default clock. Nothing here sleeps, starts a
thread or draws a random value.

Every case in this module fails at collection until Task 7's
``crypto_lab.experiments.retry`` exists: that import failure is the intended RED.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta
from typing import Any, Final

import pytest
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.adapters.ports import CommandInvocationRepository
from crypto_lab.domain.descriptors import RuntimeAvailabilityObservation
from crypto_lab.domain.diagnostics import Diagnostic, DiagnosticCategory
from crypto_lab.domain.engine_run import EngineRunRecord
from crypto_lab.domain.experiment import ExperimentRecord
from crypto_lab.domain.lifecycle import (
    EngineRunState,
    ExperimentState,
    RetryTerminalState,
)
from crypto_lab.domain.ports import Clock
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.domain.retry import (
    FAIL_CLOSED_CAUSAL_CLOSURE,
    HARD_BLOCKING_DIAGNOSTIC_CATEGORIES,
    CausalClosureEntry,
    RetryDecisionOutcome,
    RetryDecisionRecord,
    RetryDenialReason,
    RetryEvaluationSnapshot,
    RetryGate,
    RetryPolicy,
    evaluate_retry_gates,
    failed_retry_gates,
    retry_decision_semantic_projection,
)
from crypto_lab.experiments.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
    RETRY_DECISION_CONFLICT,
    stage5_failure,
)
from crypto_lab.experiments.experiment_service import cancel_experiment
from crypto_lab.experiments.ports import (
    DiagnosticReader,
    EngineRunRepository,
    ExperimentRepository,
    RetryDecisionInsertOutcome,
    RetryDecisionRepository,
    RuntimeAvailabilityObservationReader,
    UnitOfWork,
)
from crypto_lab.experiments.requests import (
    CancelExperimentRequest,
    RetryEvaluationRequest,
)
from crypto_lab.experiments.retry import (
    MAX_CAUSAL_CLOSURE_DEPTH,
    MAX_CAUSAL_CLOSURE_NODES,
    build_retry_evaluation_snapshot,
    evaluate_retry,
    resolve_causal_closure,
)
from doubles.experiments import (
    AVAIL_A,
    AVAIL_B,
    DIAG_ID,
    EXECUTABLE_HASH,
    EXPERIMENT_ID,
    INSTANT,
    OTHER_DIAG_ID,
    OTHER_EXPERIMENT_ID,
    OTHER_RUN_ID,
    RUN_ID,
    SLOT_A,
    SLOT_B,
    THIRD_DIAG_ID,
    THIRD_RUN_ID,
    UUID_C,
    CountingClock,
    FailingClock,
    FixedClock,
    InMemoryBackingStore,
    InMemoryUnitOfWork,
    MemberOverridingUnitOfWork,
    RecordingUnitOfWork,
    sample_allowed_retry_decision,
    sample_diagnostic,
    sample_draft,
    sample_experiment,
    sample_observation,
    sample_retry_decision,
    sample_retry_policy,
    sample_run,
    sequential_diagnostic_id,
)

_E = ExperimentState
_R = EngineRunState
_O = RetryDecisionOutcome
_N = RetryDenialReason
_D = DiagnosticCategory

#: The service's own source component (contract: every Failure names it).
SOURCE: Final = "experiments.retry"
#: The source component of the faults this module injects through stub readers.
_STUB_SOURCE: Final = "tests.retry_decision"
#: Strictly after every fixture instant (``INSTANT`` plus at most five seconds).
CLOCK_INSTANT: Final = INSTANT + timedelta(minutes=1)
#: A winner's instant, distinguishable from the loser's.
LATER_INSTANT: Final = CLOCK_INSTANT + timedelta(minutes=1)
#: ``sample_run(<terminal>).updated_at_utc``: the authoritative completion instant.
_COMPLETED_AT: Final = INSTANT + timedelta(seconds=5)
#: Strictly after the completion instant; the default fresh-observation instant.
_FRESH_AT: Final = INSTANT + timedelta(seconds=10)
#: A third observation identity, lexicographically below ``AVAIL_A`` and ``AVAIL_B``.
AVAIL_C: Final = f"avail_{UUID_C}"
_HARD_BLOCK_CODE: Final = "CAUSE.HARD_BLOCK"
_SHARED_CODE: Final = "SHARED.CODE"
#: The primary of every sequential graph (index 0).
_ROOT_ID: Final = sequential_diagnostic_id(0)

type _Graph = Mapping[int, tuple[int, ...]]


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _missing(value: object) -> bool:
    return value is MISSING


def _code(result: object) -> str:
    assert isinstance(result, Failure), result
    assert len(result.diagnostics) == 1
    return result.diagnostics[0].error_code


def _diagnostic(result: object) -> Diagnostic:
    assert isinstance(result, Failure), result
    assert len(result.diagnostics) == 1
    return result.diagnostics[0]


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


def _policy(
    *,
    maximum_attempts: int = 3,
    states: tuple[RetryTerminalState, ...] | None = None,
) -> RetryPolicy:
    overrides: dict[str, object] = {"maximum_attempts_per_slot": maximum_attempts}
    if states is not None:
        overrides["automatically_retry_terminal_states"] = states
    return sample_retry_policy(**overrides)


def _experiment(
    state: ExperimentState = _E.RUNNING,
    *,
    policy: RetryPolicy | None = None,
    experiment_id: str = EXPERIMENT_ID,
) -> ExperimentRecord:
    draft = None if policy is None else sample_draft(retry_policy=policy)
    return sample_experiment(state, experiment_id=experiment_id, draft=draft)


def _seed_slot(
    store: InMemoryBackingStore,
    *,
    experiment: ExperimentRecord | None = None,
    predecessor: EngineRunRecord | None = None,
    primary: Diagnostic | None = None,
    seed_primary: bool = True,
) -> tuple[ExperimentRecord, EngineRunRecord]:
    """A RUNNING experiment (revision 3), a FAILED attempt 1 (revision 5) and the
    attempt's primary diagnostic, unless a case overrides one of them."""
    experiment = sample_experiment(_E.RUNNING) if experiment is None else experiment
    predecessor = sample_run(_R.FAILED) if predecessor is None else predecessor
    _seed(store, experiment, predecessor)
    if seed_primary:
        store.seed_diagnostic(sample_diagnostic() if primary is None else primary)
    return experiment, predecessor


def _stored_experiment(
    store: InMemoryBackingStore, experiment_id: str = EXPERIMENT_ID
) -> ExperimentRecord:
    matching = [
        record
        for record in store.committed_experiments()
        if record.experiment_id == experiment_id
    ]
    assert len(matching) == 1
    return matching[0]


def _terminal(stored: ExperimentRecord, state: ExperimentState) -> ExperimentRecord:
    """The record a winning terminal aggregation commits over ``stored``."""
    return ExperimentRecord.model_validate(
        {
            **stored.model_dump(mode="python"),
            "state": state,
            "revision": stored.revision + 1,
            "updated_at_utc": stored.updated_at_utc + timedelta(seconds=1),
        }
    )


def _request(
    *,
    experiment_revision: int = 3,
    predecessor_revision: int = 5,
    experiment_id: str = EXPERIMENT_ID,
    slot: str = SLOT_A,
    predecessor_run_id: str = RUN_ID,
) -> RetryEvaluationRequest:
    return RetryEvaluationRequest(
        schema_version="1.0.0",
        experiment_id=experiment_id,
        logical_slot_id=slot,
        predecessor_run_id=predecessor_run_id,
        expected_experiment_revision=experiment_revision,
        expected_predecessor_revision=predecessor_revision,
    )


def _cancel_request(revision: int, correlation_id: str) -> CancelExperimentRequest:
    return CancelExperimentRequest(
        schema_version="1.0.0",
        experiment_id=EXPERIMENT_ID,
        expected_revision=revision,
        correlation_id=correlation_id,
    )


def _evaluate(
    unit_of_work: UnitOfWork,
    request: RetryEvaluationRequest | None = None,
    *,
    clock: Clock | None = None,
) -> Success[RetryDecisionRecord] | Failure:
    return evaluate_retry(
        _request() if request is None else request,
        unit_of_work=unit_of_work,
        clock=FixedClock(CLOCK_INSTANT) if clock is None else clock,
    )


def _snapshot(
    store: InMemoryBackingStore,
    experiment: ExperimentRecord,
    predecessor: EngineRunRecord,
    *,
    now: datetime = CLOCK_INSTANT,
) -> RetryEvaluationSnapshot:
    transaction = InMemoryUnitOfWork(store).begin()
    try:
        built = build_retry_evaluation_snapshot(
            transaction, experiment, predecessor, now=now
        )
    finally:
        transaction.rollback()
    assert isinstance(built, RetryEvaluationSnapshot), built
    return built


def _reader(store: InMemoryBackingStore) -> DiagnosticReader:
    """A primitive reader over the committed diagnostics, as the service sees it."""
    return InMemoryUnitOfWork(store).begin().diagnostics


def _stub_conflict() -> Failure:
    return stage5_failure(
        CONCURRENCY_CONFLICT,
        "simulated persistence read fault",
        source_component=_STUB_SOURCE,
        timestamp_utc=INSTANT,
    )


def _assert_denied_and_durable(
    store: InMemoryBackingStore,
    decision: RetryDecisionRecord,
    experiment: ExperimentRecord,
    reason: RetryDenialReason,
) -> None:
    """A DENIED row is committed and the experiment is untouched (plan 9.1)."""
    assert decision.outcome is _O.DENIED
    assert decision.denial_reason is reason
    assert decision.decided_at_utc == CLOCK_INSTANT
    assert _missing(decision.retry_not_before_utc)
    assert _missing(decision.reserved_successor_attempt_number)
    assert _missing(decision.availability_observation_id)
    assert store.committed_retry_decisions() == (decision,)
    assert _stored_experiment(store) == experiment


def _arm_replay_guard(root: InMemoryUnitOfWork) -> None:
    """A pre-insert hook that fails the test if the insert is ever attempted."""

    def never(record: RetryDecisionRecord) -> None:
        raise AssertionError(f"insert_if_absent must not run on replay: {record!r}")

    root.install_retry_decision_insert_hook(never)


def _cancellation_winner(
    store: InMemoryBackingStore,
) -> Callable[[int, ExperimentRecord], None]:
    def hook(expected_revision: int, _candidate: ExperimentRecord) -> None:
        _ok(
            cancel_experiment(
                _cancel_request(expected_revision, "winner"),
                unit_of_work=InMemoryUnitOfWork(store),
                clock=FixedClock(INSTANT + timedelta(seconds=1)),
            )
        )

    return hook


# -- Diagnostic graphs (sequential identities sort by index) ----------------------


def _chain(nodes: int) -> dict[int, tuple[int, ...]]:
    """``nodes`` diagnostics in a line: ``nodes - 1`` edges, depth ``nodes - 1``."""
    return {
        index: ((index + 1,) if index + 1 < nodes else ()) for index in range(nodes)
    }


def _fan(nodes: int) -> dict[int, tuple[int, ...]]:
    """A two-level fan: the root, 32 children, ``nodes - 33`` grandchildren spread
    over the children (fan-out per node stays within the record's bound of 32)."""
    children: dict[int, list[int]] = {index: [] for index in range(nodes)}
    children[0] = list(range(1, 33))
    for offset, index in enumerate(range(33, nodes)):
        children[1 + offset % 32].append(index)
    return {index: tuple(sorted(kids)) for index, kids in children.items()}


def _depth_and_node_breach() -> dict[int, tuple[int, ...]]:
    """257 nodes whose depth-33 frontier is the first to breach EITHER bound.

    A chain ``0 -> 1 -> ... -> 33`` carries one node per depth; 31 extra children
    of the root sit at depth 1 and 192 grandchildren at depth 2, so exactly 256
    nodes lie at depths 0..32 and the single depth-33 node makes 257.
    """
    graph: dict[int, list[int]] = {index: [] for index in range(257)}
    for depth in range(33):
        graph[depth].append(depth + 1)
    graph[0].extend(range(34, 65))
    for offset, index in enumerate(range(65, 257)):
        graph[34 + offset % 31].append(index)
    return {index: tuple(sorted(kids)) for index, kids in graph.items()}


def _seed_graph(store: InMemoryBackingStore, graph: _Graph) -> None:
    """Seed one retriable ENGINE_RUNTIME diagnostic per node, each with a distinct
    code, whose causes are the node's children; an unseeded child is a missing
    reference."""
    for index, children in graph.items():
        store.seed_diagnostic(
            sample_diagnostic(
                sequential_diagnostic_id(index),
                error_code=f"GRAPH.NODE_{index}",
                causal_diagnostic_ids=tuple(
                    sequential_diagnostic_id(child) for child in sorted(children)
                ),
            )
        )


_CYCLE: Final[_Graph] = {0: (1,), 1: (2,), 2: (0,)}
_MISSING_REFERENCE: Final[_Graph] = {0: (1,)}
_DIAMOND: Final[_Graph] = {0: (1, 2), 1: (3,), 2: (3,), 3: ()}
#: Plan 8.2: the four degenerate closures the helper reports and the service
#: fail-closes.
_DEGENERATE_GRAPHS: Final[list[tuple[str, _Graph]]] = [
    ("cycle", _CYCLE),
    ("missing_reference", _MISSING_REFERENCE),
    ("depth_bound", _chain(34)),
    ("node_bound", _fan(257)),
]
_DEGENERATE_IDS: Final[list[str]] = [cause for cause, _ in _DEGENERATE_GRAPHS]
_HARD_BLOCKING: Final[list[DiagnosticCategory]] = sorted(
    HARD_BLOCKING_DIAGNOSTIC_CATEGORIES, key=lambda category: category.value
)
#: Plan 8.2 gate 6: one observation per disqualifying condition, each otherwise
#: qualifying against ``sample_observation()`` (``AVAIL_A``) as the predecessor's.
_DISQUALIFIED_OBSERVATIONS: Final[list[tuple[str, RuntimeAvailabilityObservation]]] = [
    (
        "adapter_name",
        sample_observation(
            AVAIL_B, adapter_name="adapter.gamma", observed_at_utc=_FRESH_AT
        ),
    ),
    (
        "adapter_version",
        sample_observation(AVAIL_B, adapter_version="1.0.1", observed_at_utc=_FRESH_AT),
    ),
    (
        "executable_hash",
        sample_observation(
            AVAIL_B, executable_hash="f" * 64, observed_at_utc=_FRESH_AT
        ),
    ),
    (
        "expired_at_the_instant",
        sample_observation(
            AVAIL_B, observed_at_utc=_FRESH_AT, expires_at_utc=CLOCK_INSTANT
        ),
    ),
    (
        "observed_at_completion",
        sample_observation(AVAIL_B, observed_at_utc=_COMPLETED_AT),
    ),
    (
        "unavailable",
        sample_observation(AVAIL_B, available=False, observed_at_utc=_FRESH_AT),
    ),
]
_DISQUALIFIED_IDS: Final[list[str]] = [label for label, _ in _DISQUALIFIED_OBSERVATIONS]


# -- Readers and units of work that record or fault ------------------------------


class _RecordingReader:
    """A ``DiagnosticReader`` that records every method name and its argument."""

    def __init__(self, inner: DiagnosticReader) -> None:
        self._inner = inner
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    def get(self, diagnostic_id: str) -> Result[Diagnostic]:
        self.calls.append(("get", (diagnostic_id,)))
        return self._inner.get(diagnostic_id)

    def get_many(
        self, diagnostic_ids: tuple[str, ...]
    ) -> Result[tuple[Diagnostic, ...]]:
        self.calls.append(("get_many", tuple(diagnostic_ids)))
        return self._inner.get_many(diagnostic_ids)


class _FaultingDiagnostics:
    """A ``DiagnosticReader`` whose ``get_many`` always returns one fixed
    ``Failure``; ``get`` delegates."""

    def __init__(self, inner: DiagnosticReader, failure: Failure) -> None:
        self._inner = inner
        self._failure = failure

    def get(self, diagnostic_id: str) -> Result[Diagnostic]:
        return self._inner.get(diagnostic_id)

    def get_many(
        self, diagnostic_ids: tuple[str, ...]
    ) -> Result[tuple[Diagnostic, ...]]:
        return self._failure


class _FaultingRetryDecisions:
    """A ``RetryDecisionRepository`` whose ``insert_if_absent`` always returns one
    fixed ``Failure``; ``get_by_predecessor`` delegates."""

    def __init__(self, inner: RetryDecisionRepository, failure: Failure) -> None:
        self._inner = inner
        self._failure = failure

    def get_by_predecessor(
        self, logical_slot_id: str, predecessor_run_id: str
    ) -> Result[RetryDecisionRecord]:
        return self._inner.get_by_predecessor(logical_slot_id, predecessor_run_id)

    def insert_if_absent(
        self, record: RetryDecisionRecord
    ) -> Result[RetryDecisionInsertOutcome]:
        return self._failure


class _Faults:
    """The faults a ``_FaultInjectingUnitOfWork`` applies, and its ``begin`` count."""

    def __init__(
        self,
        *,
        get_many: Failure | None = None,
        insert_if_absent: Failure | None = None,
    ) -> None:
        self.get_many = get_many
        self.insert_if_absent = insert_if_absent
        self.begins = 0


class _FaultInjectingUnitOfWork:
    """A ``UnitOfWork`` over an ``InMemoryUnitOfWork`` that substitutes faulting
    members for the two Stage 8 read/insert faults the double cannot produce;
    every other member, ``commit`` and ``rollback`` delegate, and ``begin()``
    returns a wrapper over the inner transaction."""

    def __init__(self, inner: InMemoryUnitOfWork, faults: _Faults) -> None:
        self._inner = inner
        self._faults = faults

    def begin(self) -> _FaultInjectingUnitOfWork:
        self._faults.begins += 1
        return _FaultInjectingUnitOfWork(self._inner.begin(), self._faults)

    def commit(self) -> Result[None]:
        return self._inner.commit()

    def rollback(self) -> None:
        self._inner.rollback()

    @property
    def experiments(self) -> ExperimentRepository:
        return self._inner.experiments

    @property
    def engine_runs(self) -> EngineRunRepository:
        return self._inner.engine_runs

    @property
    def command_invocations(self) -> CommandInvocationRepository:
        return self._inner.command_invocations

    @property
    def retry_decisions(self) -> RetryDecisionRepository:
        if self._faults.insert_if_absent is None:
            return self._inner.retry_decisions
        return _FaultingRetryDecisions(
            self._inner.retry_decisions, self._faults.insert_if_absent
        )

    @property
    def availability_observations(self) -> RuntimeAvailabilityObservationReader:
        return self._inner.availability_observations

    @property
    def diagnostics(self) -> DiagnosticReader:
        if self._faults.get_many is None:
            return self._inner.diagnostics
        return _FaultingDiagnostics(self._inner.diagnostics, self._faults.get_many)


# --------------------------------------------------------------------------
# A. resolve_causal_closure -- the single traversal owner (plan 8.2; contract D1)
# --------------------------------------------------------------------------


def test_a_primary_without_causes_yields_its_own_pair_alone() -> None:
    store = InMemoryBackingStore()
    store.seed_diagnostic(sample_diagnostic())
    closure = _ok(resolve_causal_closure(_reader(store), DIAG_ID, now=CLOCK_INSTANT))
    assert closure == (
        CausalClosureEntry(
            category=_D.ENGINE_RUNTIME, error_code="ENGINE.RUNTIME_FAILURE"
        ),
    )


def test_the_closure_is_whole_pairs_deduplicated_and_sorted_by_category_then_code() -> (
    None
):
    # The same code under two categories yields two entries; a repeated pair yields
    # one; the order is (category, error_code), not the order of discovery.
    store = InMemoryBackingStore()
    causes = tuple(sequential_diagnostic_id(index) for index in (1, 2, 3))
    store.seed_diagnostic(sample_diagnostic(causal_diagnostic_ids=causes))
    store.seed_diagnostic(
        sample_diagnostic(causes[0], error_code=_SHARED_CODE, category=_D.PERSISTENCE)
    )
    store.seed_diagnostic(
        sample_diagnostic(
            causes[1], error_code=_SHARED_CODE, category=_D.ADAPTER_UNAVAILABILITY
        )
    )
    store.seed_diagnostic(
        sample_diagnostic(causes[2], error_code=_SHARED_CODE, category=_D.PERSISTENCE)
    )
    closure = _ok(resolve_causal_closure(_reader(store), DIAG_ID, now=CLOCK_INSTANT))
    assert closure == (
        CausalClosureEntry(category=_D.ADAPTER_UNAVAILABILITY, error_code=_SHARED_CODE),
        CausalClosureEntry(
            category=_D.ENGINE_RUNTIME, error_code="ENGINE.RUNTIME_FAILURE"
        ),
        CausalClosureEntry(category=_D.PERSISTENCE, error_code=_SHARED_CODE),
    )


def test_a_diamond_is_tolerated_and_yields_the_shared_child_once() -> None:
    store = InMemoryBackingStore()
    _seed_graph(store, _DIAMOND)
    closure = _ok(resolve_causal_closure(_reader(store), _ROOT_ID, now=CLOCK_INSTANT))
    assert len(closure) == 4
    assert [entry.error_code for entry in closure].count("GRAPH.NODE_3") == 1


def test_the_helper_fetches_each_level_with_one_get_many_and_never_calls_get() -> None:
    store = InMemoryBackingStore()
    _seed_graph(store, _DIAMOND)
    reader = _RecordingReader(_reader(store))
    _ok(resolve_causal_closure(reader, _ROOT_ID, now=CLOCK_INSTANT))
    assert reader.calls == [
        ("get_many", (sequential_diagnostic_id(0),)),
        ("get_many", (sequential_diagnostic_id(1), sequential_diagnostic_id(2))),
        ("get_many", (sequential_diagnostic_id(3),)),
    ]
    assert all(method == "get_many" for method, _ in reader.calls)


def test_a_back_edge_to_an_ancestor_is_a_cycle_failure() -> None:
    store = InMemoryBackingStore()
    _seed_graph(store, _CYCLE)
    result = resolve_causal_closure(_reader(store), _ROOT_ID, now=CLOCK_INSTANT)
    assert _code(result) == INVARIANT_VIOLATION
    assert _diagnostic(result).details["cause"] == "cycle"


def test_an_unseeded_causal_reference_is_a_missing_reference_failure() -> None:
    store = InMemoryBackingStore()
    _seed_graph(store, _MISSING_REFERENCE)
    result = resolve_causal_closure(_reader(store), _ROOT_ID, now=CLOCK_INSTANT)
    assert _code(result) == INVARIANT_VIOLATION
    assert _diagnostic(result).details["cause"] == "missing_reference"


def test_the_depth_bound_admits_thirty_two_edges_and_rejects_thirty_three() -> None:
    assert MAX_CAUSAL_CLOSURE_DEPTH == 32
    within = InMemoryBackingStore()
    _seed_graph(within, _chain(33))
    closure = _ok(resolve_causal_closure(_reader(within), _ROOT_ID, now=CLOCK_INSTANT))
    assert len(closure) == 33
    beyond = InMemoryBackingStore()
    _seed_graph(beyond, _chain(34))
    result = resolve_causal_closure(_reader(beyond), _ROOT_ID, now=CLOCK_INSTANT)
    assert _code(result) == INVARIANT_VIOLATION
    assert _diagnostic(result).details["cause"] == "depth_bound"


def test_the_node_bound_admits_256_nodes_and_rejects_257() -> None:
    assert MAX_CAUSAL_CLOSURE_NODES == 256
    within = InMemoryBackingStore()
    _seed_graph(within, _fan(256))
    closure = _ok(resolve_causal_closure(_reader(within), _ROOT_ID, now=CLOCK_INSTANT))
    assert len(closure) == 256
    beyond = InMemoryBackingStore()
    _seed_graph(beyond, _fan(257))
    result = resolve_causal_closure(_reader(beyond), _ROOT_ID, now=CLOCK_INSTANT)
    assert _code(result) == INVARIANT_VIOLATION
    assert _diagnostic(result).details["cause"] == "node_bound"


def test_a_frontier_breaching_both_bounds_reports_the_depth_bound_first() -> None:
    store = InMemoryBackingStore()
    _seed_graph(store, _depth_and_node_breach())
    result = resolve_causal_closure(_reader(store), _ROOT_ID, now=CLOCK_INSTANT)
    assert _code(result) == INVARIANT_VIOLATION
    assert _diagnostic(result).details["cause"] == "depth_bound"


def test_a_reader_fault_outside_the_invariant_vocabulary_passes_through() -> None:
    # A transient PERSISTENCE.* read fault is not a degenerate closure (contract D1).
    store = InMemoryBackingStore()
    store.seed_diagnostic(sample_diagnostic())
    conflict = _stub_conflict()
    reader = _FaultingDiagnostics(_reader(store), conflict)
    result = resolve_causal_closure(reader, DIAG_ID, now=CLOCK_INSTANT)
    assert isinstance(result, Failure)
    assert result == conflict
    assert result.diagnostics == conflict.diagnostics
    assert _code(result) == CONCURRENCY_CONFLICT


def test_a_helper_failure_is_stamped_with_now_and_names_the_primary_alone() -> None:
    store = InMemoryBackingStore()
    _seed_graph(store, _CYCLE)
    reader = _reader(store)
    first = _diagnostic(resolve_causal_closure(reader, _ROOT_ID, now=CLOCK_INSTANT))
    second = _diagnostic(resolve_causal_closure(reader, _ROOT_ID, now=LATER_INSTANT))
    assert first.timestamp_utc == CLOCK_INSTANT
    assert second.timestamp_utc == LATER_INSTANT
    assert first.details == {
        "primary_terminal_diagnostic_id": _ROOT_ID,
        "cause": "cycle",
    }
    assert first.source_component == SOURCE
    assert first.category is _D.INTERNAL_INVARIANT
    assert first.retriable is False
    # The helper knows neither the run nor the experiment, and takes no clock.
    assert _missing(first.experiment_id)
    assert _missing(first.run_id)
    parameters = inspect.signature(resolve_causal_closure).parameters
    assert "clock" not in parameters
    assert parameters["now"].kind is inspect.Parameter.KEYWORD_ONLY


# --------------------------------------------------------------------------
# B. Phase 1 -- existing-row replay (plan 8.4; contract D2)
# --------------------------------------------------------------------------


def test_an_allowed_row_replays_with_no_clock_read_and_one_repository_call() -> None:
    store = InMemoryBackingStore()
    experiment, _ = _seed_slot(store)
    row = sample_allowed_retry_decision(experiment_spec_hash=experiment.spec_hash)
    _seed(store, row)
    root = InMemoryUnitOfWork(store)
    _arm_replay_guard(root)
    recording = RecordingUnitOfWork(root)
    result = evaluate_retry(_request(), unit_of_work=recording, clock=FailingClock())
    assert _ok(result) == row
    assert recording.recorder.repositories() == (
        ("retry_decisions", "get_by_predecessor"),
    )
    assert root.hooks_installed == ("retry_decision_insert",)
    assert store.committed_retry_decisions() == (row,)
    assert _stored_experiment(store) == experiment


def test_a_denied_row_replays_with_no_clock_read_and_one_repository_call() -> None:
    store = InMemoryBackingStore()
    experiment, _ = _seed_slot(store)
    row = sample_retry_decision()
    _seed(store, row)
    root = InMemoryUnitOfWork(store)
    _arm_replay_guard(root)
    recording = RecordingUnitOfWork(root)
    result = evaluate_retry(_request(), unit_of_work=recording, clock=FailingClock())
    assert _ok(result) == row
    assert recording.recorder.repositories() == (
        ("retry_decisions", "get_by_predecessor"),
    )
    assert root.hooks_installed == ("retry_decision_insert",)
    assert store.committed_retry_decisions() == (row,)
    assert _stored_experiment(store) == experiment


def test_replay_ignores_stale_expected_revisions() -> None:
    # Plan 8.4 phase 1 names identity alone; the row is complete and immutable.
    store = InMemoryBackingStore()
    experiment, _ = _seed_slot(store)
    row = sample_allowed_retry_decision(experiment_spec_hash=experiment.spec_hash)
    _seed(store, row)
    root = InMemoryUnitOfWork(store)
    _arm_replay_guard(root)
    stale = _request(experiment_revision=99, predecessor_revision=0)
    assert _ok(evaluate_retry(stale, unit_of_work=root, clock=FailingClock())) == row
    assert root.hooks_installed == ("retry_decision_insert",)
    assert store.committed_retry_decisions() == (row,)


def test_a_stored_row_keyed_to_another_experiment_is_an_invariant_violation() -> None:
    store = InMemoryBackingStore()
    experiment, _ = _seed_slot(store)
    foreign = sample_allowed_retry_decision(
        experiment_id=OTHER_EXPERIMENT_ID, experiment_spec_hash=experiment.spec_hash
    )
    _seed(store, foreign)
    clock = CountingClock(CLOCK_INSTANT)
    result = _evaluate(InMemoryUnitOfWork(store), clock=clock)
    assert _code(result) == INVARIANT_VIOLATION
    diagnostic = _diagnostic(result)
    assert diagnostic.timestamp_utc == CLOCK_INSTANT
    assert diagnostic.experiment_id == EXPERIMENT_ID
    assert diagnostic.source_component == SOURCE
    assert clock.reads == 1
    assert store.committed_retry_decisions() == (foreign,)
    assert _stored_experiment(store) == experiment


# --------------------------------------------------------------------------
# C. Phase 2 preconditions (plan 8.3; contract D3 steps 1-9)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("maximum_attempts", "outcome"),
    [(3, _O.ALLOWED), (1, _O.DENIED)],
    ids=["allowed", "denied"],
)
def test_a_fresh_evaluation_reads_the_clock_exactly_once(
    maximum_attempts: int, outcome: RetryDecisionOutcome
) -> None:
    store = InMemoryBackingStore()
    _seed_slot(
        store, experiment=_experiment(policy=_policy(maximum_attempts=maximum_attempts))
    )
    clock = CountingClock(CLOCK_INSTANT)
    decision = _ok(_evaluate(InMemoryUnitOfWork(store), clock=clock))
    assert decision.outcome is outcome
    assert decision.decided_at_utc == CLOCK_INSTANT
    assert clock.reads == 1


@pytest.mark.parametrize(
    "state", [_R.RUNNING, _R.SUCCEEDED, _R.SUCCEEDED_WITH_WARNINGS]
)
def test_an_ineligible_predecessor_is_an_invariant_violation_with_no_write(
    state: EngineRunState,
) -> None:
    store = InMemoryBackingStore()
    predecessor = sample_run(state)
    experiment, _ = _seed_slot(store, predecessor=predecessor)
    result = _evaluate(
        InMemoryUnitOfWork(store), _request(predecessor_revision=predecessor.revision)
    )
    assert _code(result) == INVARIANT_VIOLATION
    assert store.committed_retry_decisions() == ()
    assert _stored_experiment(store) == experiment


def test_a_request_slot_that_is_not_the_predecessors_is_an_invariant_violation() -> (
    None
):
    store = InMemoryBackingStore()
    experiment, _ = _seed_slot(store)
    result = _evaluate(InMemoryUnitOfWork(store), _request(slot=SLOT_B))
    assert _code(result) == INVARIANT_VIOLATION
    assert store.committed_retry_decisions() == ()
    assert _stored_experiment(store) == experiment


def test_a_request_experiment_that_does_not_own_the_predecessor_is_an_invariant() -> (
    None
):
    store = InMemoryBackingStore()
    experiment, _ = _seed_slot(store)
    other = _experiment(experiment_id=OTHER_EXPERIMENT_ID)
    _seed(store, other)
    result = _evaluate(
        InMemoryUnitOfWork(store), _request(experiment_id=OTHER_EXPERIMENT_ID)
    )
    assert _code(result) == INVARIANT_VIOLATION
    assert store.committed_retry_decisions() == ()
    assert _stored_experiment(store) == experiment
    assert _stored_experiment(store, OTHER_EXPERIMENT_ID) == other


@pytest.mark.parametrize("state", [_E.DRAFT, _E.VALIDATED, _E.QUEUED])
def test_a_terminal_attempt_under_a_pre_running_experiment_is_an_invariant(
    state: ExperimentState,
) -> None:
    store = InMemoryBackingStore()
    experiment, _ = _seed_slot(store, experiment=_experiment(state))
    result = _evaluate(
        InMemoryUnitOfWork(store), _request(experiment_revision=experiment.revision)
    )
    assert _code(result) == INVARIANT_VIOLATION
    assert store.committed_retry_decisions() == ()
    assert _stored_experiment(store) == experiment


@pytest.mark.parametrize("revision_offset", [-1, 1])
def test_a_stale_expected_experiment_revision_is_a_conflict_with_no_row(
    revision_offset: int,
) -> None:
    store = InMemoryBackingStore()
    experiment, _ = _seed_slot(store)
    result = _evaluate(
        InMemoryUnitOfWork(store),
        _request(experiment_revision=experiment.revision + revision_offset),
    )
    assert _code(result) == CONCURRENCY_CONFLICT
    assert store.committed_retry_decisions() == ()
    assert _stored_experiment(store) == experiment


@pytest.mark.parametrize("revision_offset", [-1, 1])
def test_a_stale_expected_predecessor_revision_is_a_conflict_with_no_row(
    revision_offset: int,
) -> None:
    store = InMemoryBackingStore()
    experiment, predecessor = _seed_slot(store)
    result = _evaluate(
        InMemoryUnitOfWork(store),
        _request(predecessor_revision=predecessor.revision + revision_offset),
    )
    assert _code(result) == CONCURRENCY_CONFLICT
    assert store.committed_retry_decisions() == ()
    assert _stored_experiment(store) == experiment


def test_a_predecessor_that_is_no_longer_the_latest_attempt_is_a_conflict() -> None:
    store = InMemoryBackingStore()
    experiment, _ = _seed_slot(store)
    successor = sample_run(_R.PENDING, run_id=OTHER_RUN_ID, attempt_number=2)
    assert successor.predecessor_run_id == RUN_ID
    _seed(store, successor)
    result = _evaluate(InMemoryUnitOfWork(store))
    assert _code(result) == CONCURRENCY_CONFLICT
    assert store.committed_retry_decisions() == ()
    assert _stored_experiment(store) == experiment


def test_a_missing_primary_diagnostic_aborts_before_the_closure_walk() -> None:
    # Contract D4: the primary is read through `get` BEFORE the helper runs, so no
    # `get_many` is recorded and no row is persisted.
    store = InMemoryBackingStore()
    experiment, _ = _seed_slot(store, seed_primary=False)
    recording = RecordingUnitOfWork(InMemoryUnitOfWork(store))
    result = _evaluate(recording)
    assert _code(result) == INVARIANT_VIOLATION
    assert recording.recorder.of("diagnostics") == ("get",)
    assert "get_many" not in recording.recorder.of("diagnostics")
    assert recording.recorder.of("retry_decisions") == ("get_by_predecessor",)
    assert store.committed_retry_decisions() == ()
    assert _stored_experiment(store) == experiment


# --------------------------------------------------------------------------
# D. The six gates (plan 8.1, 8.2; contract D4-D5)
# --------------------------------------------------------------------------


def test_all_six_gates_passing_allows_reserves_and_bumps_the_experiment() -> None:
    store = InMemoryBackingStore()
    experiment, predecessor = _seed_slot(store)
    policy = experiment.spec.retry_policy
    decision = _ok(_evaluate(InMemoryUnitOfWork(store)))
    assert decision.outcome is _O.ALLOWED
    assert decision.experiment_id == EXPERIMENT_ID
    assert decision.logical_slot_id == SLOT_A
    assert decision.predecessor_run_id == RUN_ID
    assert decision.experiment_spec_hash == experiment.spec_hash
    assert decision.retry_policy == policy
    assert decision.created_attempt_count == 1
    assert decision.predecessor_terminal_state is _R.FAILED
    assert decision.primary_terminal_diagnostic_id == DIAG_ID
    assert decision.reserved_successor_attempt_number == 2
    assert decision.retry_not_before_utc == predecessor.updated_at_utc + timedelta(
        seconds=policy.retry_delay_seconds
    )
    assert decision.decided_at_utc == CLOCK_INSTANT
    assert _missing(decision.denial_reason)
    assert _missing(decision.hard_block_error_code)
    assert _missing(decision.availability_observation_id)
    bumped = _stored_experiment(store)
    assert bumped.revision == experiment.revision + 1 == 4
    assert bumped.state is _E.RUNNING
    assert bumped.updated_at_utc == CLOCK_INSTANT
    assert bumped.spec == experiment.spec
    assert bumped.spec_hash == experiment.spec_hash
    assert bumped.slot_compatibility == experiment.slot_compatibility
    assert store.committed_retry_decisions() == (decision,)
    assert store.committed_engine_runs() == (predecessor,)


def test_gate_one_denies_when_the_budget_is_a_single_attempt() -> None:
    store = InMemoryBackingStore()
    experiment, _ = _seed_slot(
        store, experiment=_experiment(policy=_policy(maximum_attempts=1))
    )
    decision = _ok(_evaluate(InMemoryUnitOfWork(store)))
    _assert_denied_and_durable(store, decision, experiment, _N.ATTEMPT_BUDGET_EXHAUSTED)
    assert decision.created_attempt_count == 1
    assert _missing(decision.hard_block_error_code)


@pytest.mark.parametrize(
    ("state", "states"),
    [
        (_R.TIMED_OUT, (RetryTerminalState.FAILED,)),
        (_R.CANCELLED, None),
        (_R.NOT_APPLICABLE, None),
    ],
    ids=["timed_out_unlisted", "cancelled", "not_applicable"],
)
def test_gate_two_denies_a_terminal_state_the_policy_does_not_retry(
    state: EngineRunState, states: tuple[RetryTerminalState, ...] | None
) -> None:
    store = InMemoryBackingStore()
    experiment, _ = _seed_slot(
        store,
        experiment=_experiment(policy=_policy(states=states)),
        predecessor=sample_run(state),
    )
    decision = _ok(_evaluate(InMemoryUnitOfWork(store)))
    _assert_denied_and_durable(
        store, decision, experiment, _N.TERMINAL_STATE_NOT_RETRYABLE
    )
    assert decision.predecessor_terminal_state is state


def test_gate_three_denies_a_non_retriable_primary_diagnostic() -> None:
    store = InMemoryBackingStore()
    experiment, _ = _seed_slot(store, primary=sample_diagnostic(retriable=False))
    decision = _ok(_evaluate(InMemoryUnitOfWork(store)))
    _assert_denied_and_durable(
        store, decision, experiment, _N.PRIMARY_DIAGNOSTIC_NOT_RETRIABLE
    )


def test_gate_four_denies_a_hard_blocking_cause_under_a_retriable_primary() -> None:
    store = InMemoryBackingStore()
    experiment, _ = _seed_slot(
        store, primary=sample_diagnostic(causal_diagnostic_ids=(OTHER_DIAG_ID,))
    )
    store.seed_diagnostic(
        sample_diagnostic(
            OTHER_DIAG_ID,
            error_code="CONFIG.INVALID_VALUE",
            category=_D.USER_CONFIGURATION,
        )
    )
    decision = _ok(_evaluate(InMemoryUnitOfWork(store)))
    _assert_denied_and_durable(store, decision, experiment, _N.HARD_BLOCKED_OUTCOME)
    assert decision.hard_block_error_code == "CONFIG.INVALID_VALUE"


def test_gate_five_denies_under_a_terminal_experiment_without_rewriting_it() -> None:
    store = InMemoryBackingStore()
    experiment, _ = _seed_slot(store, experiment=_experiment(_E.COMPLETED))
    assert experiment.revision == 4
    decision = _ok(
        _evaluate(InMemoryUnitOfWork(store), _request(experiment_revision=4))
    )
    _assert_denied_and_durable(store, decision, experiment, _N.EXPERIMENT_TERMINAL)
    assert _stored_experiment(store).state is _E.COMPLETED


def test_gate_six_denies_an_unavailable_predecessor_lacking_a_fresh_observation() -> (
    None
):
    store = InMemoryBackingStore()
    experiment, _ = _seed_slot(store, predecessor=sample_run(_R.UNAVAILABLE))
    store.seed_availability_observation(sample_observation())
    decision = _ok(_evaluate(InMemoryUnitOfWork(store)))
    _assert_denied_and_durable(
        store, decision, experiment, _N.AVAILABILITY_OBSERVATION_NOT_FRESH
    )


def test_a_hard_block_outranks_an_exhausted_budget() -> None:
    # Plan 8.2 precedence 4, 1, 2, 3, 6, 5: the recorded reason is gate 4's while
    # the kernel's failed set retains both gates.
    store = InMemoryBackingStore()
    experiment, predecessor = _seed_slot(
        store,
        experiment=_experiment(policy=_policy(maximum_attempts=1)),
        primary=sample_diagnostic(causal_diagnostic_ids=(OTHER_DIAG_ID,)),
    )
    store.seed_diagnostic(
        sample_diagnostic(
            OTHER_DIAG_ID, error_code=_HARD_BLOCK_CODE, category=_D.USER_CONFIGURATION
        )
    )
    assert failed_retry_gates(_snapshot(store, experiment, predecessor)) == (
        RetryGate.ATTEMPT_BUDGET,
        RetryGate.HARD_BLOCK,
    )
    decision = _ok(_evaluate(InMemoryUnitOfWork(store)))
    _assert_denied_and_durable(store, decision, experiment, _N.HARD_BLOCKED_OUTCOME)
    assert decision.hard_block_error_code == _HARD_BLOCK_CODE


def test_an_exhausted_budget_outranks_a_terminal_experiment() -> None:
    store = InMemoryBackingStore()
    experiment, predecessor = _seed_slot(
        store, experiment=_experiment(_E.COMPLETED, policy=_policy(maximum_attempts=1))
    )
    assert failed_retry_gates(_snapshot(store, experiment, predecessor)) == (
        RetryGate.ATTEMPT_BUDGET,
        RetryGate.EXPERIMENT_ACTIVE,
    )
    decision = _ok(
        _evaluate(
            InMemoryUnitOfWork(store),
            _request(experiment_revision=experiment.revision),
        )
    )
    _assert_denied_and_durable(store, decision, experiment, _N.ATTEMPT_BUDGET_EXHAUSTED)


def test_the_budget_counts_persisted_attempts_and_never_reservations() -> None:
    # Plan 8.1: a reserved but not yet created successor is not an attempt.
    store = InMemoryBackingStore()
    experiment, _ = _seed_slot(store)
    assert experiment.spec.retry_policy.maximum_attempts_per_slot == 3
    one = _ok(_evaluate(InMemoryUnitOfWork(store)))
    assert one.outcome is _O.ALLOWED
    assert one.created_attempt_count == 1
    assert one.reserved_successor_attempt_number == 2
    assert len(store.committed_engine_runs()) == 1
    second = sample_run(
        _R.FAILED,
        run_id=OTHER_RUN_ID,
        attempt_number=2,
        predecessor_run_id=RUN_ID,
        primary_terminal_diagnostic_id=OTHER_DIAG_ID,
    )
    _seed(store, second)
    store.seed_diagnostic(sample_diagnostic(OTHER_DIAG_ID, run_id=OTHER_RUN_ID))
    two = _ok(
        _evaluate(
            InMemoryUnitOfWork(store),
            _request(experiment_revision=4, predecessor_run_id=OTHER_RUN_ID),
        )
    )
    assert two.outcome is _O.ALLOWED
    assert two.created_attempt_count == 2
    assert two.reserved_successor_attempt_number == 3
    assert len(store.committed_engine_runs()) == 2
    assert len(store.committed_retry_decisions()) == 2
    third = sample_run(
        _R.FAILED,
        run_id=THIRD_RUN_ID,
        attempt_number=3,
        predecessor_run_id=OTHER_RUN_ID,
        primary_terminal_diagnostic_id=THIRD_DIAG_ID,
    )
    _seed(store, third)
    store.seed_diagnostic(sample_diagnostic(THIRD_DIAG_ID, run_id=THIRD_RUN_ID))
    three = _ok(
        _evaluate(
            InMemoryUnitOfWork(store),
            _request(experiment_revision=5, predecessor_run_id=THIRD_RUN_ID),
        )
    )
    assert three.outcome is _O.DENIED
    assert three.denial_reason is _N.ATTEMPT_BUDGET_EXHAUSTED
    assert three.created_attempt_count == 3
    assert len(store.committed_engine_runs()) == 3
    assert len(store.committed_retry_decisions()) == 3
    assert _stored_experiment(store).revision == 5


def test_the_hard_blocking_partition_under_test_has_eight_members() -> None:
    """Preventive (begins green): the local list restates the committed partition."""
    assert len(_HARD_BLOCKING) == 8
    assert set(_HARD_BLOCKING) == HARD_BLOCKING_DIAGNOSTIC_CATEGORIES


@pytest.mark.parametrize("category", _HARD_BLOCKING, ids=lambda c: c.value)
def test_every_hard_blocking_category_denies_a_listed_retriable_predecessor(
    category: DiagnosticCategory,
) -> None:
    store = InMemoryBackingStore()
    experiment, _ = _seed_slot(
        store, primary=sample_diagnostic(causal_diagnostic_ids=(OTHER_DIAG_ID,))
    )
    store.seed_diagnostic(
        sample_diagnostic(OTHER_DIAG_ID, error_code=_HARD_BLOCK_CODE, category=category)
    )
    decision = _ok(_evaluate(InMemoryUnitOfWork(store)))
    _assert_denied_and_durable(store, decision, experiment, _N.HARD_BLOCKED_OUTCOME)
    assert decision.hard_block_error_code == _HARD_BLOCK_CODE


@pytest.mark.parametrize(("cause", "graph"), _DEGENERATE_GRAPHS, ids=_DEGENERATE_IDS)
def test_a_degenerate_closure_fail_closes_to_a_durable_hard_block(
    cause: str, graph: _Graph
) -> None:
    # Plan 8.2 / contract D5: the helper's Failure never reaches the caller.
    store = InMemoryBackingStore()
    experiment, _ = _seed_slot(
        store,
        predecessor=sample_run(_R.FAILED, primary_terminal_diagnostic_id=_ROOT_ID),
        seed_primary=False,
    )
    _seed_graph(store, graph)
    decision = _ok(_evaluate(InMemoryUnitOfWork(store)))
    _assert_denied_and_durable(store, decision, experiment, _N.HARD_BLOCKED_OUTCOME)
    assert decision.hard_block_error_code == INVARIANT_VIOLATION
    assert decision.primary_terminal_diagnostic_id == _ROOT_ID
    assert cause in _DEGENERATE_IDS


@pytest.mark.parametrize(("cause", "graph"), _DEGENERATE_GRAPHS, ids=_DEGENERATE_IDS)
def test_the_snapshot_substitutes_the_fail_closed_closure(
    cause: str, graph: _Graph
) -> None:
    store = InMemoryBackingStore()
    experiment, predecessor = _seed_slot(
        store,
        predecessor=sample_run(_R.FAILED, primary_terminal_diagnostic_id=_ROOT_ID),
        seed_primary=False,
    )
    _seed_graph(store, graph)
    snapshot = _snapshot(store, experiment, predecessor)
    assert snapshot.causal_closure == FAIL_CLOSED_CAUSAL_CLOSURE
    assert snapshot.primary_terminal_diagnostic.diagnostic_id == _ROOT_ID
    assert snapshot.candidate_availability_observations == ()
    assert _missing(snapshot.predecessor_availability_observation)
    assert cause in _DEGENERATE_IDS


def test_a_reader_fault_during_the_walk_aborts_the_evaluation_unchanged() -> None:
    store = InMemoryBackingStore()
    experiment, _ = _seed_slot(store)
    conflict = _stub_conflict()
    faulting = _FaultInjectingUnitOfWork(
        InMemoryUnitOfWork(store), _Faults(get_many=conflict)
    )
    result = _evaluate(faulting)
    assert isinstance(result, Failure)
    assert result == conflict
    assert _code(result) == CONCURRENCY_CONFLICT
    assert store.committed_retry_decisions() == ()
    assert _stored_experiment(store) == experiment


# -- Gate 6: availability identity, freshness and tie-breaking (plan 8.2) --------


def _seed_unavailable_slot(
    store: InMemoryBackingStore,
    *observations: RuntimeAvailabilityObservation,
) -> tuple[ExperimentRecord, EngineRunRecord]:
    """An UNAVAILABLE predecessor referencing ``AVAIL_A`` (seeded) plus the given
    candidate observations."""
    experiment, predecessor = _seed_slot(store, predecessor=sample_run(_R.UNAVAILABLE))
    assert predecessor.availability_observation_id == AVAIL_A
    assert predecessor.updated_at_utc == _COMPLETED_AT
    store.seed_availability_observation(sample_observation())
    for observation in observations:
        store.seed_availability_observation(observation)
    return experiment, predecessor


def test_a_fresh_observation_of_the_same_adapter_identity_allows_the_retry() -> None:
    store = InMemoryBackingStore()
    fresh = sample_observation(AVAIL_B, observed_at_utc=_FRESH_AT)
    assert fresh.expires_at_utc > CLOCK_INSTANT
    experiment, predecessor = _seed_unavailable_slot(store, fresh)
    decision = _ok(_evaluate(InMemoryUnitOfWork(store)))
    assert decision.outcome is _O.ALLOWED
    assert decision.availability_observation_id == AVAIL_B
    assert decision.predecessor_terminal_state is _R.UNAVAILABLE
    assert decision.retry_not_before_utc == predecessor.updated_at_utc + timedelta(
        seconds=experiment.spec.retry_policy.retry_delay_seconds
    )
    assert store.committed_retry_decisions() == (decision,)
    assert _stored_experiment(store).revision == experiment.revision + 1


@pytest.mark.parametrize(
    ("label", "observation"), _DISQUALIFIED_OBSERVATIONS, ids=_DISQUALIFIED_IDS
)
def test_each_disqualified_observation_denies_for_freshness(
    label: str, observation: RuntimeAvailabilityObservation
) -> None:
    store = InMemoryBackingStore()
    experiment, _ = _seed_unavailable_slot(store, observation)
    decision = _ok(_evaluate(InMemoryUnitOfWork(store)))
    _assert_denied_and_durable(
        store, decision, experiment, _N.AVAILABILITY_OBSERVATION_NOT_FRESH
    )
    assert label in _DISQUALIFIED_IDS


def test_the_predecessors_own_observation_never_qualifies_even_when_fresh() -> None:
    # Identity alone disqualifies it: observed after completion, unexpired, same
    # adapter identity, available -- and still the predecessor's.
    store = InMemoryBackingStore()
    experiment, _ = _seed_slot(store, predecessor=sample_run(_R.UNAVAILABLE))
    store.seed_availability_observation(sample_observation(observed_at_utc=_FRESH_AT))
    decision = _ok(_evaluate(InMemoryUnitOfWork(store)))
    _assert_denied_and_durable(
        store, decision, experiment, _N.AVAILABILITY_OBSERVATION_NOT_FRESH
    )


def test_the_greatest_observed_at_wins_over_a_greater_identifier() -> None:
    assert AVAIL_C < AVAIL_B
    store = InMemoryBackingStore()
    _seed_unavailable_slot(
        store,
        sample_observation(AVAIL_B, observed_at_utc=_FRESH_AT),
        sample_observation(AVAIL_C, observed_at_utc=_FRESH_AT + timedelta(seconds=10)),
    )
    decision = _ok(_evaluate(InMemoryUnitOfWork(store)))
    assert decision.outcome is _O.ALLOWED
    assert decision.availability_observation_id == AVAIL_C


def test_equal_observed_at_ties_break_to_the_lexicographically_greatest_id() -> None:
    assert AVAIL_C < AVAIL_B
    store = InMemoryBackingStore()
    _seed_unavailable_slot(
        store,
        sample_observation(AVAIL_B, observed_at_utc=_FRESH_AT),
        sample_observation(AVAIL_C, observed_at_utc=_FRESH_AT),
    )
    decision = _ok(_evaluate(InMemoryUnitOfWork(store)))
    assert decision.outcome is _O.ALLOWED
    assert decision.availability_observation_id == AVAIL_B


def test_the_snapshot_carries_the_selection_and_the_full_read_agrees() -> None:
    # Contract D4's declared reading: the snapshot holds the qualifying SELECTION,
    # and the kernel over the full sorted `list_for_adapter` read decides the same.
    store = InMemoryBackingStore()
    earlier = sample_observation(AVAIL_B, observed_at_utc=_FRESH_AT)
    later = sample_observation(
        AVAIL_C, observed_at_utc=_FRESH_AT + timedelta(seconds=10)
    )
    experiment, predecessor = _seed_unavailable_slot(store, earlier, later)
    snapshot = _snapshot(store, experiment, predecessor)
    assert snapshot.candidate_availability_observations == (later,)
    assert snapshot.predecessor_availability_observation == sample_observation()
    assert snapshot.evaluated_at_utc == CLOCK_INSTANT
    transaction = InMemoryUnitOfWork(store).begin()
    full = _ok(
        transaction.availability_observations.list_for_adapter(
            "adapter.alpha", "1.0.0", EXECUTABLE_HASH
        )
    )
    transaction.rollback()
    assert len(full) == 3
    rebuilt = RetryEvaluationSnapshot.model_validate(
        {
            **snapshot.model_dump(mode="python"),
            "candidate_availability_observations": full,
        }
    )
    from_selection = evaluate_retry_gates(snapshot)
    from_full_read = evaluate_retry_gates(rebuilt)
    assert from_full_read.outcome is from_selection.outcome is _O.ALLOWED
    assert from_full_read.availability_observation_id == AVAIL_C
    assert from_selection.availability_observation_id == AVAIL_C
    assert retry_decision_semantic_projection(
        from_full_read
    ) == retry_decision_semantic_projection(from_selection)
    decision = _ok(_evaluate(InMemoryUnitOfWork(store)))
    assert decision == from_selection


def test_an_unseeded_predecessor_observation_is_an_invariant_violation() -> None:
    store = InMemoryBackingStore()
    experiment, _ = _seed_slot(store, predecessor=sample_run(_R.UNAVAILABLE))
    result = _evaluate(InMemoryUnitOfWork(store))
    assert _code(result) == INVARIANT_VIOLATION
    assert store.committed_retry_decisions() == ()
    assert _stored_experiment(store) == experiment


# --------------------------------------------------------------------------
# E. Phase 3 -- concurrent-insert reconciliation (plan 8.4; contract D6)
# --------------------------------------------------------------------------


def test_an_identical_concurrent_winner_is_returned_with_its_own_instant() -> None:
    store = InMemoryBackingStore()
    _seed_slot(store)
    root = InMemoryUnitOfWork(store)
    winners: list[RetryDecisionRecord] = []

    def same_evaluation(_candidate: RetryDecisionRecord) -> None:
        winners.append(
            _ok(_evaluate(InMemoryUnitOfWork(store), clock=FixedClock(LATER_INSTANT)))
        )

    root.install_retry_decision_insert_hook(same_evaluation)
    result = _ok(_evaluate(root))
    (winner,) = winners
    assert result == winner
    assert result.decided_at_utc == LATER_INSTANT
    assert result.outcome is _O.ALLOWED
    assert store.committed_retry_decisions() == (winner,)
    assert _stored_experiment(store).revision == 4
    assert _stored_experiment(store).state is _E.RUNNING
    assert root.hooks_installed == ()


@pytest.mark.parametrize(
    ("created_attempt_count", "spec_hash"),
    [(2, None), (1, "b" * 64)],
    ids=["created_attempt_count", "experiment_spec_hash"],
)
def test_a_divergent_concurrent_winner_is_a_decision_conflict_with_no_bump(
    created_attempt_count: int, spec_hash: str | None
) -> None:
    # `None` keeps the experiment's own spec hash so the count is the sole divergence.
    store = InMemoryBackingStore()
    experiment, _ = _seed_slot(store)
    winner = sample_allowed_retry_decision(
        experiment_spec_hash=experiment.spec_hash if spec_hash is None else spec_hash,
        created_attempt_count=created_attempt_count,
    )
    root = InMemoryUnitOfWork(store)

    def raw_insert(_candidate: RetryDecisionRecord) -> None:
        _seed(store, winner)

    root.install_retry_decision_insert_hook(raw_insert)
    result = _evaluate(root)
    assert _code(result) == RETRY_DECISION_CONFLICT
    diagnostic = _diagnostic(result)
    assert diagnostic.details["predecessor_run_id"] == RUN_ID
    assert diagnostic.experiment_id == EXPERIMENT_ID
    assert diagnostic.timestamp_utc == CLOCK_INSTANT
    assert diagnostic.source_component == SOURCE
    assert store.committed_retry_decisions() == (winner,)
    assert _stored_experiment(store) == experiment
    assert _stored_experiment(store).revision == 3
    assert root.hooks_installed == ()


def test_a_winner_differing_only_in_decided_at_is_returned_as_the_winner() -> None:
    store = InMemoryBackingStore()
    experiment, _ = _seed_slot(store)
    winner = sample_allowed_retry_decision(
        experiment_spec_hash=experiment.spec_hash,
        decided_at_utc=INSTANT + timedelta(minutes=7),
    )
    root = InMemoryUnitOfWork(store)

    def raw_insert(_candidate: RetryDecisionRecord) -> None:
        _seed(store, winner)

    root.install_retry_decision_insert_hook(raw_insert)
    result = _ok(_evaluate(root))
    assert result == winner
    assert result.decided_at_utc == INSTANT + timedelta(minutes=7)
    assert store.committed_retry_decisions() == (winner,)
    # The projection excludes field 16 alone: the same facts at another instant.
    candidate = evaluate_retry_gates(
        _snapshot(store, experiment, sample_run(_R.FAILED))
    )
    assert candidate != winner
    assert retry_decision_semantic_projection(
        candidate
    ) == retry_decision_semantic_projection(winner)
    # A raw winner bumped nothing, so the loser's staged ALLOWED bump committed.
    assert _stored_experiment(store).revision == 4
    assert _stored_experiment(store).state is _E.RUNNING


def test_a_raw_winner_keyed_to_another_experiment_is_an_invariant_violation() -> None:
    store = InMemoryBackingStore()
    experiment, _ = _seed_slot(store)
    winner = sample_allowed_retry_decision(
        experiment_id=OTHER_EXPERIMENT_ID, experiment_spec_hash=experiment.spec_hash
    )
    root = InMemoryUnitOfWork(store)

    def raw_insert(_candidate: RetryDecisionRecord) -> None:
        _seed(store, winner)

    root.install_retry_decision_insert_hook(raw_insert)
    result = _evaluate(root)
    assert _code(result) == INVARIANT_VIOLATION
    assert store.committed_retry_decisions() == (winner,)
    assert _stored_experiment(store) == experiment


def test_an_expiry_straddling_race_conflicts_and_keeps_the_allowed_winner() -> None:
    # Contract D6 step 2 (declared): gate 6 reads the single evaluation instant, so
    # ALLOWED before `expires_at_utc` and DENIED after it legitimately diverge.
    store = InMemoryBackingStore()
    expiry = INSTANT + timedelta(minutes=2)
    straddled = sample_observation(
        AVAIL_B, observed_at_utc=_FRESH_AT, expires_at_utc=expiry
    )
    experiment, _ = _seed_unavailable_slot(store, straddled)
    root = InMemoryUnitOfWork(store)
    winners: list[RetryDecisionRecord] = []

    def earlier_evaluation(_candidate: RetryDecisionRecord) -> None:
        assert CLOCK_INSTANT < expiry
        winners.append(
            _ok(_evaluate(InMemoryUnitOfWork(store), clock=FixedClock(CLOCK_INSTANT)))
        )

    root.install_retry_decision_insert_hook(earlier_evaluation)
    after_expiry = FixedClock(INSTANT + timedelta(minutes=3))
    assert after_expiry.now_utc() > expiry
    result = _evaluate(root, clock=after_expiry)
    assert _code(result) == RETRY_DECISION_CONFLICT
    (winner,) = winners
    assert winner.outcome is _O.ALLOWED
    assert winner.availability_observation_id == AVAIL_B
    assert store.committed_retry_decisions() == (winner,)
    assert _stored_experiment(store).revision == experiment.revision + 1


def test_an_insert_failure_is_a_lost_swap_returned_after_exactly_two_attempts() -> None:
    # Contract D6 step 1: unreachable through the double; the wrapper pins it.
    store = InMemoryBackingStore()
    experiment, _ = _seed_slot(store)
    conflict = _stub_conflict()
    faults = _Faults(insert_if_absent=conflict)
    faulting = _FaultInjectingUnitOfWork(InMemoryUnitOfWork(store), faults)
    result = _evaluate(faulting)
    assert isinstance(result, Failure)
    assert result == conflict
    assert _code(result) == CONCURRENCY_CONFLICT
    assert faults.begins == 2
    assert store.committed_retry_decisions() == ()
    assert _stored_experiment(store) == experiment


# --------------------------------------------------------------------------
# F. Experiment-CAS precedence (plan 8.3, 9.5 row 10; contract D6 step 0, D7)
# --------------------------------------------------------------------------


def _second_invocation_denies_as_terminal(
    store: InMemoryBackingStore, winner: ExperimentRecord
) -> None:
    """Plan 9.5 row 10, second sentence: a NEW invocation at the terminal
    experiment's current revision persists the gate-5 denial."""
    decision = _ok(
        _evaluate(
            InMemoryUnitOfWork(store), _request(experiment_revision=winner.revision)
        )
    )
    assert decision.outcome is _O.DENIED
    assert decision.denial_reason is _N.EXPERIMENT_TERMINAL
    assert _missing(decision.reserved_successor_attempt_number)
    assert _missing(decision.retry_not_before_utc)
    assert store.committed_retry_decisions() == (decision,)
    assert _stored_experiment(store) == winner


def test_a_cancellation_winner_conflicts_first_and_denies_as_terminal_second() -> None:
    store = InMemoryBackingStore()
    experiment, _ = _seed_slot(store)
    root = InMemoryUnitOfWork(store)
    root.install_experiment_compare_and_swap_hook(_cancellation_winner(store))
    clock = CountingClock(CLOCK_INSTANT)
    first = _evaluate(root, clock=clock)
    assert _code(first) == CONCURRENCY_CONFLICT
    assert store.committed_retry_decisions() == ()
    winner = _stored_experiment(store)
    assert winner.state is _E.CANCELLED
    assert winner.revision == experiment.revision + 1 == 4
    assert winner.cancellation_correlation_id == "winner"
    assert clock.reads == 2
    assert root.hooks_installed == ()
    _second_invocation_denies_as_terminal(store, winner)


def test_an_aggregation_winner_conflicts_first_and_denies_as_terminal_second() -> None:
    # No application sequence makes aggregation write-ready while a fresh ALLOWED
    # retry is eligible (plan 9.5), so the winner is the repository's own swap.
    store = InMemoryBackingStore()
    experiment, _ = _seed_slot(store)
    completed = _terminal(experiment, _E.COMPLETED)
    root = InMemoryUnitOfWork(store)

    def aggregation_winner(expected_revision: int, _c: ExperimentRecord) -> None:
        transaction = InMemoryUnitOfWork(store).begin()
        _ok(transaction.experiments.compare_and_swap(expected_revision, completed))
        _commit(transaction)

    root.install_experiment_compare_and_swap_hook(aggregation_winner)
    clock = CountingClock(CLOCK_INSTANT)
    first = _evaluate(root, clock=clock)
    assert _code(first) == CONCURRENCY_CONFLICT
    assert store.committed_retry_decisions() == ()
    assert _stored_experiment(store) == completed
    assert completed.state is _E.COMPLETED
    assert completed.revision == 4
    assert clock.reads == 2
    assert root.hooks_installed == ()
    _second_invocation_denies_as_terminal(store, completed)


def test_a_same_predecessor_allowed_winner_at_the_swap_is_replayed_by_the_loser() -> (
    None
):
    store = InMemoryBackingStore()
    _seed_slot(store)
    root = InMemoryUnitOfWork(store)
    winners: list[RetryDecisionRecord] = []

    def allowed_winner(_expected_revision: int, _c: ExperimentRecord) -> None:
        winners.append(
            _ok(_evaluate(InMemoryUnitOfWork(store), clock=FixedClock(LATER_INSTANT)))
        )

    root.install_experiment_compare_and_swap_hook(allowed_winner)
    result = _ok(_evaluate(root))
    (winner,) = winners
    assert result == winner
    assert result.decided_at_utc == LATER_INSTANT
    assert store.committed_retry_decisions() == (winner,)
    assert _stored_experiment(store).revision == 4
    assert root.hooks_installed == ()


def test_a_denied_row_still_commits_after_a_concurrent_cancellation_and_replays() -> (
    None
):
    # Contract D6.3 (declared): a non-gate-5 denial is a durable fact of immutable
    # rows; no experiment write exists to contend on.
    store = InMemoryBackingStore()
    experiment, _ = _seed_slot(
        store, experiment=_experiment(policy=_policy(maximum_attempts=1))
    )
    root = InMemoryUnitOfWork(store)

    def cancel_meanwhile(_candidate: RetryDecisionRecord) -> None:
        _ok(
            cancel_experiment(
                _cancel_request(experiment.revision, "winner"),
                unit_of_work=InMemoryUnitOfWork(store),
                clock=FixedClock(INSTANT + timedelta(seconds=1)),
            )
        )

    root.install_retry_decision_insert_hook(cancel_meanwhile)
    decision = _ok(_evaluate(root))
    assert decision.outcome is _O.DENIED
    assert decision.denial_reason is _N.ATTEMPT_BUDGET_EXHAUSTED
    assert store.committed_retry_decisions() == (decision,)
    cancelled = _stored_experiment(store)
    assert cancelled.state is _E.CANCELLED
    assert cancelled.revision == experiment.revision + 1
    assert root.hooks_installed == ()
    replayed = _evaluate(
        InMemoryUnitOfWork(store),
        _request(experiment_revision=cancelled.revision),
        clock=FailingClock(),
    )
    assert _ok(replayed) == decision
    assert store.committed_retry_decisions() == (decision,)


# --------------------------------------------------------------------------
# G. Restart over the same store (plan 11)
# --------------------------------------------------------------------------


def test_a_rebuilt_root_replays_the_allowed_row_with_its_durable_delay() -> None:
    store = InMemoryBackingStore()
    experiment, predecessor = _seed_slot(store)
    decided = _ok(_evaluate(InMemoryUnitOfWork(store)))
    assert decided.outcome is _O.ALLOWED
    rebuilt = InMemoryUnitOfWork(store)
    _arm_replay_guard(rebuilt)
    replayed = _ok(
        evaluate_retry(
            _request(experiment_revision=4), unit_of_work=rebuilt, clock=FailingClock()
        )
    )
    assert replayed == decided
    assert replayed.retry_not_before_utc == predecessor.updated_at_utc + timedelta(
        seconds=experiment.spec.retry_policy.retry_delay_seconds
    )
    assert rebuilt.hooks_installed == ("retry_decision_insert",)
    assert store.committed_retry_decisions() == (decided,)


# --------------------------------------------------------------------------
# H. Defensive branches of the read set (contract D3/D4; reviewer notes F2 and F5)
#
# The repository-passthrough and unrepresentable-snapshot cases begin green against
# the implementation (preventive: they pin that a defensive branch aborts without a
# write). The two ``get``-fault passthrough cases are the RED for the symmetric rule
# that a reader fault outside the invariant vocabulary is never re-coded.
# --------------------------------------------------------------------------


def _overriding(
    store: InMemoryBackingStore, member: str, **overrides: Callable[..., object]
) -> MemberOverridingUnitOfWork:
    return MemberOverridingUnitOfWork(InMemoryUnitOfWork(store), member, overrides)


def _conflict_answer(*_args: object, **_kwargs: object) -> Failure:
    return _stub_conflict()


def _missing_answer(*_args: object, **_kwargs: object) -> Success[object]:
    absent: Any = MISSING
    return Success(outcome="SUCCESS", value=absent)


def _zero_answer(*_args: object, **_kwargs: object) -> Success[int]:
    return Success[int](outcome="SUCCESS", value=0)


def _assert_nothing_persisted(store: InMemoryBackingStore) -> None:
    assert store.committed_retry_decisions() == ()
    assert _stored_experiment(store).revision == 3


def test_a_count_attempts_fault_passes_through_and_persists_nothing() -> None:
    store = InMemoryBackingStore()
    _seed_slot(store)
    result = _evaluate(
        _overriding(store, "engine_runs", count_attempts=_conflict_answer)
    )
    assert result == _stub_conflict()
    _assert_nothing_persisted(store)


def test_a_zero_attempt_count_is_an_unrepresentable_snapshot_that_aborts() -> None:
    store = InMemoryBackingStore()
    _seed_slot(store)
    result = _evaluate(_overriding(store, "engine_runs", count_attempts=_zero_answer))
    assert _code(result) == INVARIANT_VIOLATION
    _assert_nothing_persisted(store)


def test_a_missing_experiment_is_the_repository_invariant_violation() -> None:
    store = InMemoryBackingStore()
    _seed(store, sample_run(_R.FAILED))
    store.seed_diagnostic(sample_diagnostic())
    result = _evaluate(InMemoryUnitOfWork(store))
    assert _code(result) == INVARIANT_VIOLATION
    assert store.committed_retry_decisions() == ()


def test_a_missing_predecessor_is_the_repository_invariant_violation() -> None:
    store = InMemoryBackingStore()
    _seed(store, sample_experiment(_E.RUNNING))
    result = _evaluate(InMemoryUnitOfWork(store))
    assert _code(result) == INVARIANT_VIOLATION
    _assert_nothing_persisted(store)


def test_a_latest_attempt_fault_passes_through_and_persists_nothing() -> None:
    store = InMemoryBackingStore()
    _seed_slot(store)
    result = _evaluate(
        _overriding(store, "engine_runs", latest_attempt=_conflict_answer)
    )
    assert result == _stub_conflict()
    _assert_nothing_persisted(store)


def test_a_missing_latest_attempt_beside_a_stored_run_is_an_invariant_violation() -> (
    None
):
    store = InMemoryBackingStore()
    _seed_slot(store)
    result = _evaluate(
        _overriding(store, "engine_runs", latest_attempt=_missing_answer)
    )
    assert _code(result) == INVARIANT_VIOLATION
    _assert_nothing_persisted(store)


def _seed_unavailable_predecessor(store: InMemoryBackingStore) -> None:
    _seed_slot(store, predecessor=sample_run(_R.UNAVAILABLE))
    store.seed_availability_observation(sample_observation())


def test_a_list_for_adapter_fault_passes_through_and_persists_nothing() -> None:
    store = InMemoryBackingStore()
    _seed_unavailable_predecessor(store)
    result = _evaluate(
        _overriding(
            store, "availability_observations", list_for_adapter=_conflict_answer
        )
    )
    assert result == _stub_conflict()
    _assert_nothing_persisted(store)


def test_a_primary_get_fault_outside_the_invariant_vocabulary_passes_through() -> None:
    store = InMemoryBackingStore()
    _seed_slot(store)
    result = _evaluate(_overriding(store, "diagnostics", get=_conflict_answer))
    assert result == _stub_conflict()
    _assert_nothing_persisted(store)


def test_an_observation_get_fault_outside_the_invariant_vocabulary_passes_through() -> (
    None
):
    store = InMemoryBackingStore()
    _seed_unavailable_predecessor(store)
    result = _evaluate(
        _overriding(store, "availability_observations", get=_conflict_answer)
    )
    assert result == _stub_conflict()
    _assert_nothing_persisted(store)
