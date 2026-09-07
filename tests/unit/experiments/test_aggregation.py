"""Stage 5 Task 8: ``build_aggregation_input`` and ``aggregate_experiment``.

Plan sections 3.10 (the aggregation records and the four required result
fields), 9.2 (selected-slot based input: the frozen compatibility entry, the
current attempt or its absence, the decision row, ``retry_status`` total over
every slot, the effective terminal state, late and approximation derivation),
9.3 (the eight-row classifier, hand-evaluated here for every expected verdict and
reason-code set), 9.4 (the aggregation transaction: the clock-free idempotent
terminal path, the ``RUNNING`` requirement, the revision check, the single
compare-and-swap and the reload-once loser), 9.5 (the two driver-level lost-swap
outcomes -- a reload onto ``RUNNING`` at ``N+1`` and onto a terminal record),
10.1 (the read set: the experiment, each slot's ``latest_attempt`` and each
decidable slot's ``get_by_predecessor``; the write set: the experiment only) and
12 Task 8, read through the Task 8 service API contract ``task8-service-api.md``
(D1-D16 and D19-D26): the ``MISSING`` ``slot_compatibility`` precondition, the
per-slot read set and its pass-through of repository faults, the retry-status
derivation that treats only an all-``CORE.INVARIANT_VIOLATION`` decision read as
absence and never probes ``get_by_attempt_number``, the constructor of every
service-built result, zero service-clock reads on the load-failure and
already-terminal paths and exactly one otherwise, the two mapping constants and
the import boundary of the new module. The pairwise races of plan 9.5 driven
with the real operations live in ``test_cancellation_races.py``.

Every case here fails at collection until Task 8's module
``crypto_lab.experiments.aggregation`` exists -- that is the intended RED. Every
case drives the service through the ROOT in-memory unit of work (the service
calls ``begin()`` itself), seeds rows through a transaction of its own and reads
the backing store's committed rows back, so a "no write" assertion is a
statement about durable state. ``build_aggregation_input`` is driven with a
transaction the test opens and rolls back. The read-discipline clocks
(``CountingClock``, ``FailingClock``) are injected into the SERVICE only; the
root keeps its default clock. Lost swaps are simulated deterministically through
the double's one-shot experiment compare-and-swap hook, installed exactly once
per scenario and asserted consumed, with the winner committed through a
separate root over the same store; nothing here sleeps, starts a thread or
draws a random value.
"""

from __future__ import annotations

import ast
import inspect
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Final

import pytest
from pydantic import ValidationError
from pydantic.experimental.missing_sentinel import MISSING

import crypto_lab.experiments as experiments_package
import crypto_lab.experiments.aggregation as aggregation_module
from crypto_lab.domain.aggregation import (
    REASON_LATE_NOT_APPLICABLE,
    REASON_NO_APPLICABLE_ENGINE,
    REASON_SLOT_CANCELLED,
    REASON_SLOT_FAILED,
    REASON_SLOT_SUCCEEDED_WITH_WARNINGS,
    REASON_SLOT_TIMED_OUT,
    REASON_SLOT_UNAVAILABLE,
    REASON_SLOT_USED_APPROXIMATION,
    AggregationVerdict,
    ExperimentAggregationInput,
    ExperimentAggregationResult,
    SlotAggregationInput,
    SlotRetryStatus,
    effective_terminal_state,
    is_late_not_applicable,
    uses_approximation,
)
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.compatibility import CompatibilityOutcome
from crypto_lab.domain.diagnostics import Diagnostic
from crypto_lab.domain.engine_run import EngineRunRecord
from crypto_lab.domain.experiment import (
    AdapterIdentity,
    EngineIdentity,
    ExperimentRecord,
    ExperimentSpecDraft,
    SelectedEngineSlot,
)
from crypto_lab.domain.lifecycle import (
    EXPERIMENT_TRANSITIONS,
    TERMINAL_EXPERIMENT_STATES,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.ports import Clock
from crypto_lab.domain.results import Failure, Success
from crypto_lab.domain.retry import (
    RetryDecisionOutcome,
    RetryDecisionRecord,
    RetryDenialReason,
)
from crypto_lab.experiments.aggregation import (
    TERMINAL_STATE_OF_VERDICT,
    VERDICT_OF_TERMINAL_STATE,
    aggregate_experiment,
    build_aggregation_input,
)
from crypto_lab.experiments.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
    stage5_failure,
)
from crypto_lab.experiments.ports import UnitOfWork
from crypto_lab.experiments.requests import ExperimentAggregationRequest
from doubles.experiments import (
    ADAPTER_BETA,
    AVAIL_A,
    AVAIL_B,
    DIAG_ID,
    ENGINE_BETA,
    EXPERIMENT_ID,
    INSTANT,
    OTHER_EXPERIMENT_ID,
    OTHER_RUN_ID,
    RUN_ID,
    SLOT_A,
    SLOT_B,
    SLOT_C,
    THIRD_RUN_ID,
    UUID_C,
    CallRecorder,
    CountingClock,
    FailingClock,
    FixedClock,
    InMemoryBackingStore,
    InMemoryUnitOfWork,
    MemberOverridingUnitOfWork,
    RecordingUnitOfWork,
    sample_allowed_retry_decision,
    sample_draft,
    sample_experiment,
    sample_retry_decision,
    sample_retry_policy,
    sample_run,
    sample_slot_compatibility,
    sample_slots,
)

_E = ExperimentState
_R = EngineRunState
_C = CompatibilityOutcome
_V = AggregationVerdict
_S = SlotRetryStatus

#: The service's own source component (contract D10: every failure it emits).
SOURCE: Final = "experiments.aggregation"
#: The double's source component (a repository failure returned unchanged).
REPOSITORY_SOURCE: Final = "doubles.experiments"
#: The source component of the faults this module injects through stub readers.
_STUB_SOURCE: Final = "tests.aggregation"
#: Strictly after every fixture instant (``INSTANT`` plus at most five seconds).
CLOCK_INSTANT: Final = INSTANT + timedelta(minutes=1)
#: ``sample_allowed_retry_decision``'s stored ``retry_not_before_utc``: the
#: predecessor's completion instant (``INSTANT`` + 5 s) plus the 30 s delay.
DUE_INSTANT: Final = INSTANT + timedelta(seconds=35)
#: The third slot's fixture material (a third distinct adapter/engine pair).
AVAIL_C: Final = f"avail_{UUID_C}"
ADAPTER_GAMMA: Final = AdapterIdentity(
    adapter_name="adapter.gamma", adapter_version="1.0.0"
)
ENGINE_GAMMA: Final = EngineIdentity(engine_name="engine.gamma", engine_version="2.3.4")
#: The name the double reports for its installed experiment compare-and-swap hook.
_CAS_HOOK: Final[tuple[str, ...]] = ("experiment_compare_and_swap",)
#: The five non-terminal engine-run states (plan 9.3 row 1).
NON_TERMINAL_RUN_STATES: Final = (
    _R.PENDING,
    _R.VALIDATING,
    _R.READY,
    _R.STARTING,
    _R.RUNNING,
)
#: The three states that map to a ``RetryTerminalState`` (plan 9.2).
RETRY_STATES: Final = (_R.FAILED, _R.TIMED_OUT, _R.UNAVAILABLE)
#: The four exported names (contract D22, plan Task 8).
EXPORTED_NAMES: Final = (
    "TERMINAL_STATE_OF_VERDICT",
    "VERDICT_OF_TERMINAL_STATE",
    "aggregate_experiment",
    "build_aggregation_input",
)


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


def _by_key(*records: RetryDecisionRecord) -> tuple[RetryDecisionRecord, ...]:
    """The store's committed order: ``(logical_slot_id, predecessor_run_id)``."""
    return tuple(
        sorted(
            records,
            key=lambda record: (record.logical_slot_id, record.predecessor_run_id),
        )
    )


# -- Fixture material -------------------------------------------------------------


def _one_slot_draft() -> ExperimentSpecDraft:
    """Contract D12: the one-slot spec is slot A alone."""
    return sample_draft(selected_engine_slots=(sample_slots()[0],))


def _three_slot_draft() -> ExperimentSpecDraft:
    third = SelectedEngineSlot(
        logical_slot_id=SLOT_C,
        slot_ordinal=2,
        adapter=ADAPTER_GAMMA,
        engine=ENGINE_GAMMA,
    )
    return sample_draft(selected_engine_slots=(*sample_slots(), third))


def _experiment(
    state: ExperimentState = _E.RUNNING,
    *,
    draft: ExperimentSpecDraft | None = None,
    outcomes: dict[str, CompatibilityOutcome] | None = None,
) -> ExperimentRecord:
    """A RUNNING experiment (revision 3) whose frozen outcomes default to
    ``SUPPORTED`` per slot, overridden by ``outcomes``."""
    return sample_experiment(
        state,
        draft=draft,
        slot_compatibility=sample_slot_compatibility(draft, outcomes=outcomes),
    )


def _run_b(state: EngineRunState, *, run_id: str = OTHER_RUN_ID) -> EngineRunRecord:
    """Attempt 1 of slot B."""
    return sample_run(
        state,
        run_id=run_id,
        logical_slot_id=SLOT_B,
        adapter=ADAPTER_BETA,
        engine=ENGINE_BETA,
        availability_observation_id=AVAIL_B,
    )


def _run_c(state: EngineRunState) -> EngineRunRecord:
    """Attempt 1 of slot C (the three-slot spec)."""
    return sample_run(
        state,
        run_id=THIRD_RUN_ID,
        logical_slot_id=SLOT_C,
        adapter=ADAPTER_GAMMA,
        engine=ENGINE_GAMMA,
        availability_observation_id=AVAIL_C,
    )


def _successor(state: EngineRunState) -> EngineRunRecord:
    """Attempt 2 of slot A, linked to attempt 1 (``RUN_ID``)."""
    return sample_run(
        state, run_id=OTHER_RUN_ID, attempt_number=2, predecessor_run_id=RUN_ID
    )


def _denied(
    state: EngineRunState,
    *,
    logical_slot_id: str = SLOT_A,
    predecessor_run_id: str = RUN_ID,
) -> RetryDecisionRecord:
    """A DENIED (``ATTEMPT_BUDGET_EXHAUSTED``) row whose
    ``predecessor_terminal_state`` is ``state`` -- ``sample_retry_decision`` is
    FAILED-only (contract D13), so the other two states are built here."""
    return RetryDecisionRecord.model_validate(
        {
            "schema_version": "1.0.0",
            "experiment_id": EXPERIMENT_ID,
            "logical_slot_id": logical_slot_id,
            "predecessor_run_id": predecessor_run_id,
            "experiment_spec_hash": "a" * 64,
            "retry_policy": sample_retry_policy(maximum_attempts_per_slot=1),
            "created_attempt_count": 1,
            "predecessor_terminal_state": state,
            "primary_terminal_diagnostic_id": DIAG_ID,
            "outcome": RetryDecisionOutcome.DENIED,
            "denial_reason": RetryDenialReason.ATTEMPT_BUDGET_EXHAUSTED,
            "decided_at_utc": INSTANT,
        }
    )


def _denied_b(state: EngineRunState) -> RetryDecisionRecord:
    """The DENIED row of slot B's attempt 1."""
    return _denied(state, logical_slot_id=SLOT_B, predecessor_run_id=OTHER_RUN_ID)


def _allowed(
    state: EngineRunState, *, experiment: ExperimentRecord
) -> RetryDecisionRecord:
    """An ALLOWED row reserving attempt 2 of slot A for a predecessor in
    ``state``; an UNAVAILABLE predecessor needs ``availability_observation_id``."""
    return sample_allowed_retry_decision(
        predecessor_terminal_state=state,
        experiment_spec_hash=experiment.spec_hash,
        availability_observation_id=AVAIL_A if state is _R.UNAVAILABLE else None,
    )


def _replaced(
    stored: ExperimentRecord, *, state: ExperimentState | None = None
) -> ExperimentRecord:
    """The record a raw winner commits over ``stored``: revision + 1 at
    ``CLOCK_INSTANT``, in ``state`` (default: a state-preserving bump)."""
    payload = stored.model_dump(mode="python")
    if state is not None:
        payload["state"] = state
    payload["revision"] = stored.revision + 1
    payload["updated_at_utc"] = CLOCK_INSTANT
    return ExperimentRecord.model_validate(payload)


def _raw_winner(
    store: InMemoryBackingStore, replacement: ExperimentRecord
) -> Callable[[int, ExperimentRecord], None]:
    """A compare-and-swap hook committing ``replacement`` through a separate root."""

    def hook(expected_revision: int, _candidate: ExperimentRecord) -> None:
        assert expected_revision == replacement.revision - 1
        winner = InMemoryUnitOfWork(store).begin()
        _ok(winner.experiments.compare_and_swap(expected_revision, replacement))
        _commit(winner)

    return hook


@dataclass(frozen=True, slots=True)
class _Seeded:
    """One seeded store: its experiment and every run and decision row committed."""

    store: InMemoryBackingStore
    experiment: ExperimentRecord
    runs: tuple[EngineRunRecord, ...]
    decisions: tuple[RetryDecisionRecord, ...]


def _seeded(
    *,
    experiment: ExperimentRecord | None = None,
    draft: ExperimentSpecDraft | None = None,
    outcomes: dict[str, CompatibilityOutcome] | None = None,
    runs: tuple[EngineRunRecord, ...] = (),
    decisions: tuple[RetryDecisionRecord, ...] = (),
) -> _Seeded:
    """Seed a RUNNING experiment (revision 3; frozen ``SUPPORTED`` unless
    ``outcomes`` overrides a slot) with ``runs`` and ``decisions``."""
    if experiment is None:
        experiment = _experiment(draft=draft, outcomes=outcomes)
    store = InMemoryBackingStore()
    _seed(store, experiment, *runs, *decisions)
    return _Seeded(store, experiment, runs, decisions)


# -- Driving the two operations -----------------------------------------------------


def _request(expected_revision: int) -> ExperimentAggregationRequest:
    return ExperimentAggregationRequest(
        schema_version="1.0.0",
        experiment_id=EXPERIMENT_ID,
        expected_revision=expected_revision,
    )


def _aggregate(
    unit_of_work: UnitOfWork,
    *,
    expected_revision: int = 3,
    clock: Clock | None = None,
) -> Success[ExperimentAggregationResult] | Failure:
    return aggregate_experiment(
        _request(expected_revision),
        unit_of_work=unit_of_work,
        clock=FixedClock(CLOCK_INSTANT) if clock is None else clock,
    )


def _aggregate_once(
    store: InMemoryBackingStore, *, expected_revision: int = 3
) -> Success[ExperimentAggregationResult] | Failure:
    """One invocation through a fresh root; exactly one service-clock read."""
    clock = CountingClock(CLOCK_INSTANT)
    result = _aggregate(
        InMemoryUnitOfWork(store), expected_revision=expected_revision, clock=clock
    )
    assert clock.reads == 1
    return result


def _build(
    root: UnitOfWork,
    experiment: ExperimentRecord,
    *,
    now: datetime = CLOCK_INSTANT,
) -> ExperimentAggregationInput | Failure:
    """Drive ``build_aggregation_input`` in a transaction the test rolls back."""
    transaction = root.begin()
    try:
        return build_aggregation_input(transaction, experiment, now=now)
    finally:
        transaction.rollback()


def _built(
    seeded: _Seeded, root: UnitOfWork | None = None
) -> ExperimentAggregationInput:
    built = _build(
        InMemoryUnitOfWork(seeded.store) if root is None else root, seeded.experiment
    )
    assert isinstance(built, ExperimentAggregationInput), built
    return built


def _slot(built: ExperimentAggregationInput, slot_id: str) -> SlotAggregationInput:
    (slot,) = [
        candidate for candidate in built.slots if candidate.logical_slot_id == slot_id
    ]
    return slot


def _recording(seeded: _Seeded) -> tuple[RecordingUnitOfWork, CallRecorder]:
    recorder = CallRecorder()
    return RecordingUnitOfWork(InMemoryUnitOfWork(seeded.store), recorder), recorder


def _stub_conflict() -> Failure:
    return stage5_failure(
        CONCURRENCY_CONFLICT,
        "simulated persistence read fault",
        source_component=_STUB_SOURCE,
        timestamp_utc=INSTANT,
    )


def _stub_invariant() -> Failure:
    return stage5_failure(
        INVARIANT_VIOLATION,
        "simulated absent row",
        source_component=_STUB_SOURCE,
        timestamp_utc=INSTANT,
    )


def _conflict_answer(*_args: object, **_kwargs: object) -> Failure:
    return _stub_conflict()


def _invariant_answer(*_args: object, **_kwargs: object) -> Failure:
    return _stub_invariant()


def _foreign_experiment_run(
    *_args: object, **_kwargs: object
) -> Success[EngineRunRecord]:
    return Success[EngineRunRecord](
        outcome="SUCCESS",
        value=sample_run(_R.SUCCEEDED, experiment_id=OTHER_EXPERIMENT_ID),
    )


def _foreign_slot_run(*_args: object, **_kwargs: object) -> Success[EngineRunRecord]:
    return Success[EngineRunRecord](
        outcome="SUCCESS", value=sample_run(_R.SUCCEEDED, logical_slot_id=SLOT_B)
    )


def _overriding(
    store: InMemoryBackingStore, member: str, **overrides: Callable[..., object]
) -> MemberOverridingUnitOfWork:
    return MemberOverridingUnitOfWork(InMemoryUnitOfWork(store), member, overrides)


# -- Shared assertions ----------------------------------------------------------------


def _result(
    verdict: AggregationVerdict, codes: tuple[str, ...] = ()
) -> ExperimentAggregationResult:
    return ExperimentAggregationResult(
        schema_version="1.0.0",
        experiment_id=EXPERIMENT_ID,
        verdict=verdict,
        reason_codes=codes,
    )


def _assert_service_stamped(result: object, *, code: str, now: datetime) -> Diagnostic:
    """Contract D10: a failure aggregation itself emits names the service and the
    single clock instant of the attempt."""
    assert _code(result) == code
    diagnostic = _diagnostic(result)
    assert diagnostic.source_component == SOURCE
    assert diagnostic.timestamp_utc == now
    assert diagnostic.experiment_id == EXPERIMENT_ID
    return diagnostic


def _assert_unchanged(
    seeded: _Seeded, experiment: ExperimentRecord | None = None
) -> None:
    """Contract D19: every committed row is exactly a seeded row (``experiment``
    names a winner's record standing in the seed's place)."""
    expected = seeded.experiment if experiment is None else experiment
    assert seeded.store.committed_experiments() == (expected,)
    assert seeded.store.committed_engine_runs() == _by_run_id(*seeded.runs)
    assert seeded.store.committed_retry_decisions() == _by_key(*seeded.decisions)
    assert seeded.store.committed_command_invocations() == ()


def _assert_not_yet_terminal(
    seeded: _Seeded, result: Success[ExperimentAggregationResult] | Failure
) -> None:
    """Contract D6 step 8, D19: the verdict alone; every seeded row untouched."""
    value = _ok(result)
    assert value == _result(_V.NOT_YET_TERMINAL)
    assert value.verdict is _V.NOT_YET_TERMINAL
    assert value.reason_codes == ()
    stored = _stored(seeded.store)
    assert stored == seeded.experiment
    assert canonical_json_bytes(stored) == canonical_json_bytes(seeded.experiment)
    assert stored.revision == seeded.experiment.revision
    _assert_unchanged(seeded)


def _assert_terminalized(
    seeded: _Seeded,
    result: Success[ExperimentAggregationResult] | Failure,
    *,
    verdict: AggregationVerdict,
    codes: tuple[str, ...],
    clock_instant: datetime = CLOCK_INSTANT,
    seed: ExperimentRecord | None = None,
) -> ExperimentRecord:
    """Contract D16, D20, D21: the terminal write over ``seed`` (default: the
    seeded experiment) and the classifier's result."""
    seed = seeded.experiment if seed is None else seed
    value = _ok(result)
    assert value == _result(verdict, codes)
    assert value.verdict is verdict
    assert value.reason_codes == codes
    assert value.reason_codes == tuple(sorted(codes))
    assert value.experiment_id == EXPERIMENT_ID
    assert value.schema_version == "1.0.0"
    stored = _stored(seeded.store)
    assert stored.state is TERMINAL_STATE_OF_VERDICT[verdict]
    assert stored.revision == seed.revision + 1
    assert stored.updated_at_utc == clock_instant
    assert stored.updated_at_utc >= seed.updated_at_utc
    assert stored.schema_version == seed.schema_version
    assert stored.experiment_id == seed.experiment_id
    assert stored.spec == seed.spec
    assert stored.spec_hash == seed.spec_hash
    assert stored.slot_compatibility == seed.slot_compatibility
    assert stored.created_at_utc == seed.created_at_utc
    assert _missing(stored.cancellation_correlation_id)
    assert all(stored.updated_at_utc >= run.updated_at_utc for run in seeded.runs)
    _assert_unchanged(seeded, stored)
    return stored


# --------------------------------------------------------------------------
# A. Surface (contract D4 mappings, D15 request, D22 exports)
# --------------------------------------------------------------------------


def test_the_request_carries_identity_and_expected_revision_only() -> None:
    assert tuple(ExperimentAggregationRequest.model_fields) == (
        "schema_version",
        "experiment_id",
        "expected_revision",
    )
    request = _request(3)
    assert request.experiment_id == EXPERIMENT_ID
    assert request.expected_revision == 3


@pytest.mark.parametrize(
    "extra",
    [
        "slots",
        "approximation_slots",
        "latest_attempt_run_id",
        "retry_status",
        "effective_terminal_state",
        "reason_codes",
        "verdict",
        "terminal_state",
        "cancellation_timestamp",
    ],
)
def test_the_request_rejects_every_derived_or_authoritative_field(extra: str) -> None:
    # Plan 3.11: no request carries an approximation flag, a retry status or an
    # authoritative terminal fact; ``extra="forbid"`` rejects each by name.
    with pytest.raises(ValidationError):
        ExperimentAggregationRequest.model_validate(
            {
                "schema_version": "1.0.0",
                "experiment_id": EXPERIMENT_ID,
                "expected_revision": 3,
                extra: "supplied",
            }
        )


def test_the_package_re_exports_the_four_names_as_the_same_objects() -> None:
    for name in EXPORTED_NAMES:
        assert name in experiments_package.__all__
        assert getattr(experiments_package, name) is getattr(aggregation_module, name)
    assert aggregation_module.aggregate_experiment is aggregate_experiment
    assert aggregation_module.build_aggregation_input is build_aggregation_input
    assert aggregation_module.TERMINAL_STATE_OF_VERDICT is TERMINAL_STATE_OF_VERDICT
    assert aggregation_module.VERDICT_OF_TERMINAL_STATE is VERDICT_OF_TERMINAL_STATE
    assert aggregation_module.SOURCE_COMPONENT == SOURCE


def test_the_verdict_to_state_mapping_holds_exactly_the_three_owned_edges() -> None:
    # Plan 4 / 9.4: aggregate_experiment owns RUNNING -> {COMPLETED, CWW, FAILED}.
    assert set(TERMINAL_STATE_OF_VERDICT) == {
        _V.COMPLETED,
        _V.COMPLETED_WITH_WARNINGS,
        _V.FAILED,
    }
    assert set(TERMINAL_STATE_OF_VERDICT.values()) == set(
        TERMINAL_EXPERIMENT_STATES - {_E.CANCELLED}
    )
    for verdict, state in TERMINAL_STATE_OF_VERDICT.items():
        assert (_E.RUNNING, state) in EXPERIMENT_TRANSITIONS.transitions
        assert verdict.value == state.value
    assert _V.NOT_YET_TERMINAL not in TERMINAL_STATE_OF_VERDICT
    assert _V.CANCELLED not in TERMINAL_STATE_OF_VERDICT


def test_the_state_to_verdict_mapping_covers_every_terminal_state_and_inverts() -> None:
    # Plan 9.4: the idempotent path reports the stored terminal state by name.
    assert set(VERDICT_OF_TERMINAL_STATE) == set(TERMINAL_EXPERIMENT_STATES)
    assert len(VERDICT_OF_TERMINAL_STATE) == 4
    for state, verdict in VERDICT_OF_TERMINAL_STATE.items():
        assert state.value == verdict.value
    for verdict, state in TERMINAL_STATE_OF_VERDICT.items():
        assert VERDICT_OF_TERMINAL_STATE[state] is verdict
    assert VERDICT_OF_TERMINAL_STATE[_E.CANCELLED] is _V.CANCELLED
    assert "NOT_YET_TERMINAL" not in {
        state.value for state in VERDICT_OF_TERMINAL_STATE
    }
    assert _V.NOT_YET_TERMINAL not in set(VERDICT_OF_TERMINAL_STATE.values())


# --------------------------------------------------------------------------
# B. build_aggregation_input (contract D1-D5, D9, D14)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("state", [_E.DRAFT, _E.VALIDATED], ids=["DRAFT", "VALIDATED"])
def test_a_record_without_frozen_slot_compatibility_is_an_invariant_violation(
    state: ExperimentState,
) -> None:
    # Contract D1: nothing to aggregate before the freeze.
    experiment = sample_experiment(state)
    assert _missing(experiment.slot_compatibility)
    seeded = _seeded(experiment=experiment)
    result = _build(InMemoryUnitOfWork(seeded.store), experiment)
    _assert_service_stamped(result, code=INVARIANT_VIOLATION, now=CLOCK_INSTANT)
    _assert_unchanged(seeded)


def test_two_unattempted_supported_slots_build_the_explicit_zero_attempt_input() -> (
    None
):
    # Plan 9.2 / 9.3 row 2 material: both slots unresolved, nothing to decide.
    seeded = _seeded()
    built = _built(seeded)
    assert built == ExperimentAggregationInput(
        schema_version="1.0.0",
        experiment_id=EXPERIMENT_ID,
        experiment_spec_hash=seeded.experiment.spec_hash,
        slots=(
            SlotAggregationInput(
                logical_slot_id=SLOT_A,
                slot_ordinal=0,
                compatibility_outcome=_C.SUPPORTED,
                approximation_ids=(),
                retry_status=_S.NO_DECISION_REQUIRED,
            ),
            SlotAggregationInput(
                logical_slot_id=SLOT_B,
                slot_ordinal=1,
                compatibility_outcome=_C.SUPPORTED,
                approximation_ids=(),
                retry_status=_S.NO_DECISION_REQUIRED,
            ),
        ),
    )
    assert tuple(slot.slot_ordinal for slot in built.slots) == (0, 1)
    assert tuple(slot.logical_slot_id for slot in built.slots) == tuple(
        slot.logical_slot_id for slot in seeded.experiment.spec.selected_engine_slots
    )
    for slot in built.slots:
        assert _missing(slot.latest_attempt_run_id)
        assert _missing(slot.latest_attempt_state)
        assert slot.retry_status is _S.NO_DECISION_REQUIRED
        assert slot.approximation_ids == ()
        assert _missing(effective_terminal_state(slot))
        assert not uses_approximation(slot)
    # Contract D26: an empty selected-slot set is unconstructible on both sides.
    with pytest.raises(ValidationError):
        sample_draft(selected_engine_slots=())
    with pytest.raises(ValidationError):
        ExperimentAggregationInput(
            schema_version="1.0.0",
            experiment_id=EXPERIMENT_ID,
            experiment_spec_hash=seeded.experiment.spec_hash,
            slots=(),
        )


@pytest.mark.parametrize(
    "slot_count", [1, 2, 3], ids=["one-slot", "two-slot", "three-slot"]
)
def test_every_selected_slot_appears_once_whether_or_not_it_has_an_attempt(
    slot_count: int,
) -> None:
    # Contract D5 / plan Task 8: the slot set equals the frozen selected-slot set.
    drafts = {1: _one_slot_draft(), 2: sample_draft(), 3: _three_slot_draft()}
    runs: tuple[EngineRunRecord, ...] = (sample_run(_R.SUCCEEDED),)
    if slot_count == 3:
        runs = (*runs, _run_c(_R.SUCCEEDED))
    seeded = _seeded(draft=drafts[slot_count], runs=runs)
    built = _built(seeded)
    spec_ids = tuple(
        slot.logical_slot_id for slot in seeded.experiment.spec.selected_engine_slots
    )
    built_ids = tuple(slot.logical_slot_id for slot in built.slots)
    assert built_ids == spec_ids
    assert len(set(built_ids)) == len(built_ids) == slot_count
    ordinals = tuple(slot.slot_ordinal for slot in built.slots)
    assert ordinals == tuple(range(slot_count))
    attempted = {run.logical_slot_id for run in runs}
    for slot in built.slots:
        if slot.logical_slot_id in attempted:
            assert slot.latest_attempt_state is _R.SUCCEEDED
        else:
            assert _missing(slot.latest_attempt_run_id)
            assert _missing(slot.latest_attempt_state)


def test_the_input_is_independent_of_run_insertion_order() -> None:
    # Contract D14: slot order is spec order, never store order.
    experiment = _experiment()
    first, second = sample_run(_R.SUCCEEDED), _run_b(_R.SUCCEEDED_WITH_WARNINGS)
    b_then_a = _seeded(experiment=experiment, runs=(second, first))
    a_then_b = _seeded(experiment=experiment, runs=(first, second))
    built_ba, built_ab = _built(b_then_a), _built(a_then_b)
    assert built_ba == built_ab
    assert canonical_json_bytes(built_ba) == canonical_json_bytes(built_ab)
    assert tuple(slot.logical_slot_id for slot in built_ba.slots) == (SLOT_A, SLOT_B)


def test_approximation_is_derived_from_the_frozen_record_alone() -> None:
    # Contract D4 / plan 9.2: approximation_ids mirror the frozen entry.
    seeded = _seeded(outcomes={SLOT_A: _C.SUPPORTED_WITH_APPROXIMATION})
    assert not _missing(seeded.experiment.slot_compatibility)
    frozen_a, frozen_b = seeded.experiment.slot_compatibility
    assert frozen_a.approximation_ids != ()
    built = _built(seeded)
    slot_a, slot_b = _slot(built, SLOT_A), _slot(built, SLOT_B)
    assert slot_a.compatibility_outcome is _C.SUPPORTED_WITH_APPROXIMATION
    assert slot_a.approximation_ids == frozen_a.approximation_ids
    assert uses_approximation(slot_a)
    assert slot_b.compatibility_outcome is _C.SUPPORTED
    assert slot_b.approximation_ids == frozen_b.approximation_ids == ()
    assert not uses_approximation(slot_b)
    # Contract D12(4): approximation alone manufactures no effective state.
    assert _missing(effective_terminal_state(slot_a))


@pytest.mark.parametrize(
    ("outcome", "effective"),
    [(_C.NOT_APPLICABLE, _R.NOT_APPLICABLE), (_C.UNAVAILABLE, _R.UNAVAILABLE)],
    ids=["NOT_APPLICABLE", "UNAVAILABLE"],
)
def test_a_zero_attempt_slot_takes_its_effective_state_from_the_frozen_outcome(
    outcome: CompatibilityOutcome, effective: EngineRunState
) -> None:
    # Plan 9.2 / contract D12(1)-(2): expected N/A is not late; UNAVAILABLE waits
    # for no decision.
    slot_a = _slot(_built(_seeded(outcomes={SLOT_A: outcome})), SLOT_A)
    assert _missing(slot_a.latest_attempt_run_id)
    assert effective_terminal_state(slot_a) is effective
    assert not is_late_not_applicable(slot_a)
    assert slot_a.retry_status is _S.NO_DECISION_REQUIRED


def test_late_not_applicable_is_derived_from_the_frozen_outcome_and_the_run() -> None:
    # Contract D20: frozen SUPPORTED + NOT_APPLICABLE attempt is late; the
    # seeded-only frozen NOT_APPLICABLE + NOT_APPLICABLE attempt is not.
    late = _slot(_built(_seeded(runs=(sample_run(_R.NOT_APPLICABLE),))), SLOT_A)
    assert late.latest_attempt_state is _R.NOT_APPLICABLE
    assert effective_terminal_state(late) is _R.NOT_APPLICABLE
    assert is_late_not_applicable(late)
    assert late.retry_status is _S.NO_DECISION_REQUIRED
    expected_seeded = _seeded(
        outcomes={SLOT_A: _C.NOT_APPLICABLE}, runs=(sample_run(_R.NOT_APPLICABLE),)
    )
    expected = _slot(_built(expected_seeded), SLOT_A)
    assert effective_terminal_state(expected) is _R.NOT_APPLICABLE
    assert not is_late_not_applicable(expected)


def test_the_latest_attempt_governs_and_the_predecessor_row_is_never_read() -> None:
    # Contract D3 / D13: the decision lookup is keyed by the LATEST run id, so a
    # SUCCEEDED successor makes the predecessor's ALLOWED row history.
    experiment = _experiment()
    seeded = _seeded(
        experiment=experiment,
        runs=(sample_run(_R.FAILED), _successor(_R.SUCCEEDED)),
        decisions=(_allowed(_R.FAILED, experiment=experiment),),
    )
    root, recorder = _recording(seeded)
    slot_a = _slot(_built(seeded, root), SLOT_A)
    assert slot_a.latest_attempt_run_id == OTHER_RUN_ID
    assert slot_a.latest_attempt_state is _R.SUCCEEDED
    assert slot_a.retry_status is _S.NO_DECISION_REQUIRED
    assert recorder.of("retry_decisions") == ()
    assert recorder.of("engine_runs") == ("latest_attempt", "latest_attempt")


_RETRY_STATUS_ROWS: Final[list[tuple[EngineRunState, SlotRetryStatus, int]]] = [
    *[(state, _S.NO_DECISION_REQUIRED, 0) for state in NON_TERMINAL_RUN_STATES],
    (_R.SUCCEEDED, _S.NO_DECISION_REQUIRED, 0),
    (_R.SUCCEEDED_WITH_WARNINGS, _S.NO_DECISION_REQUIRED, 0),
    (_R.CANCELLED, _S.NO_DECISION_REQUIRED, 0),
    (_R.NOT_APPLICABLE, _S.NO_DECISION_REQUIRED, 0),
    (_R.FAILED, _S.DECISION_UNRESOLVED, 1),
    (_R.TIMED_OUT, _S.DECISION_UNRESOLVED, 1),
    (_R.UNAVAILABLE, _S.DECISION_UNRESOLVED, 1),
]


@pytest.mark.parametrize(
    ("state", "status", "decision_reads"),
    _RETRY_STATUS_ROWS,
    ids=[row[0].value for row in _RETRY_STATUS_ROWS],
)
def test_retry_status_with_no_decision_row_follows_the_run_state(
    state: EngineRunState, status: SlotRetryStatus, decision_reads: int
) -> None:
    # Plan 9.2 / contract D3: a decision is read only for FAILED, TIMED_OUT and
    # UNAVAILABLE; every other state is NO_DECISION_REQUIRED with no read.
    assert {row[0] for row in _RETRY_STATUS_ROWS} == set(EngineRunState)
    seeded = _seeded(runs=(sample_run(state),))
    root, recorder = _recording(seeded)
    slot_a = _slot(_built(seeded, root), SLOT_A)
    assert slot_a.latest_attempt_run_id == RUN_ID
    assert slot_a.latest_attempt_state is state
    assert slot_a.retry_status is status
    assert recorder.of("retry_decisions") == ("get_by_predecessor",) * decision_reads
    assert recorder.of("engine_runs") == ("latest_attempt", "latest_attempt")


@pytest.mark.parametrize(
    "state", list(RETRY_STATES), ids=[state.value for state in RETRY_STATES]
)
def test_a_denied_row_resolves_the_slot_as_denied(state: EngineRunState) -> None:
    # Plan 9.2 / contract D13: the row's predecessor_terminal_state matches the run.
    denied = _denied(state)
    assert denied.predecessor_terminal_state is state
    if state is _R.FAILED:
        assert denied == sample_retry_decision()
    seeded = _seeded(runs=(sample_run(state),), decisions=(denied,))
    root, recorder = _recording(seeded)
    assert _slot(_built(seeded, root), SLOT_A).retry_status is _S.DENIED
    assert recorder.of("retry_decisions") == ("get_by_predecessor",)


@pytest.mark.parametrize(
    "state", list(RETRY_STATES), ids=[state.value for state in RETRY_STATES]
)
def test_an_allowed_row_without_a_successor_is_pending_with_no_further_read(
    state: EngineRunState,
) -> None:
    # Contract D3 v2: latest_attempt returning the predecessor already proves no
    # attempt bears the reserved number; get_by_attempt_number is never probed.
    experiment = _experiment()
    allowed = _allowed(state, experiment=experiment)
    assert allowed.predecessor_terminal_state is state
    assert allowed.reserved_successor_attempt_number == 2
    seeded = _seeded(
        experiment=experiment, runs=(sample_run(state),), decisions=(allowed,)
    )
    root, recorder = _recording(seeded)
    built = _built(seeded, root)
    slot_a = _slot(built, SLOT_A)
    assert slot_a.latest_attempt_run_id == RUN_ID
    assert slot_a.retry_status is _S.ALLOWED_SUCCESSOR_PENDING
    assert recorder.of("engine_runs") == ("latest_attempt",) * len(built.slots)
    assert "get_by_attempt_number" not in recorder.of("engine_runs")
    assert "count_attempts" not in recorder.of("engine_runs")
    assert recorder.of("retry_decisions") == ("get_by_predecessor",)


def test_a_decision_row_keyed_to_another_experiment_is_an_invariant_violation() -> None:
    # Contract D3: a foreign row under the slot's key is a repository defect.
    seeded = _seeded(
        runs=(sample_run(_R.FAILED),),
        decisions=(sample_retry_decision(experiment_id=OTHER_EXPERIMENT_ID),),
    )
    result = _build(InMemoryUnitOfWork(seeded.store), seeded.experiment)
    diagnostic = _assert_service_stamped(
        result, code=INVARIANT_VIOLATION, now=CLOCK_INSTANT
    )
    assert diagnostic.run_id == RUN_ID


def test_a_decision_read_fault_passes_through_as_the_same_failure_object() -> None:
    # Contract D3 v2: only an all-INVARIANT_VIOLATION read means absence.
    seeded = _seeded(runs=(sample_run(_R.FAILED), _run_b(_R.SUCCEEDED)))
    stub = _stub_conflict()

    def answer(*_args: object, **_kwargs: object) -> Failure:
        return stub

    root = _overriding(seeded.store, "retry_decisions", get_by_predecessor=answer)
    result = _build(root, seeded.experiment)
    assert result is stub
    assert _code(result) == CONCURRENCY_CONFLICT


def test_a_decision_read_answering_invariant_violation_is_an_unresolved_slot() -> None:
    # Contract D3 v2: the repository's absence vocabulary.
    seeded = _seeded(runs=(sample_run(_R.FAILED), _run_b(_R.SUCCEEDED)))
    root = _overriding(
        seeded.store, "retry_decisions", get_by_predecessor=_invariant_answer
    )
    built = _built(seeded, root)
    assert _slot(built, SLOT_A).retry_status is _S.DECISION_UNRESOLVED
    assert _slot(built, SLOT_B).retry_status is _S.NO_DECISION_REQUIRED


def test_a_decision_read_fault_aborts_aggregation_over_a_durable_denied_row() -> None:
    # Contract D3 v2 through the service: the DENIED row is not silently re-read
    # as "unresolved"; the public Result is the conflict and nothing is written.
    seeded = _seeded(
        draft=_one_slot_draft(),
        runs=(sample_run(_R.FAILED),),
        decisions=(_denied(_R.FAILED),),
    )
    root = _overriding(
        seeded.store, "retry_decisions", get_by_predecessor=_conflict_answer
    )
    clock = CountingClock(CLOCK_INSTANT)
    result = _aggregate(root, clock=clock)
    assert result == _stub_conflict()
    assert _code(result) == CONCURRENCY_CONFLICT
    assert clock.reads == 1
    assert root.begins == 1
    _assert_unchanged(seeded)


@pytest.mark.parametrize(
    "answer",
    [_foreign_experiment_run, _foreign_slot_run],
    ids=["another-experiment", "another-slot"],
)
def test_a_latest_attempt_of_another_experiment_or_slot_is_an_invariant_violation(
    answer: Callable[..., object],
) -> None:
    # Contract D2: a run whose identity differs from the query is a repository defect.
    seeded = _seeded()
    root = _overriding(seeded.store, "engine_runs", latest_attempt=answer)
    result = _build(root, seeded.experiment)
    _assert_service_stamped(result, code=INVARIANT_VIOLATION, now=CLOCK_INSTANT)


def test_a_latest_attempt_fault_passes_through_as_the_same_failure_object() -> None:
    # Contract D2: a repository Failure is returned unchanged.
    seeded = _seeded(runs=(sample_run(_R.SUCCEEDED),))
    stub = _stub_conflict()

    def answer(*_args: object, **_kwargs: object) -> Failure:
        return stub

    root = _overriding(seeded.store, "engine_runs", latest_attempt=answer)
    assert _build(root, seeded.experiment) is stub


def test_the_readers_reached_are_exactly_the_plan_read_set_in_slot_order() -> None:
    # Contract D9 / plan 10.1: latest_attempt per slot, get_by_predecessor for the
    # decidable slot, nothing else.
    experiment = _experiment()
    seeded = _seeded(
        experiment=experiment,
        runs=(sample_run(_R.FAILED),),
        decisions=(_allowed(_R.FAILED, experiment=experiment),),
    )
    root, recorder = _recording(seeded)
    built = _built(seeded, root)
    assert _slot(built, SLOT_A).retry_status is _S.ALLOWED_SUCCESSOR_PENDING
    assert _missing(_slot(built, SLOT_B).latest_attempt_run_id)
    assert recorder.repositories() == (
        ("engine_runs", "latest_attempt"),
        ("retry_decisions", "get_by_predecessor"),
        ("engine_runs", "latest_attempt"),
    )
    for forbidden in (
        "diagnostics",
        "availability_observations",
        "command_invocations",
        "experiments",
    ):
        assert recorder.of(forbidden) == ()
    methods = {method for _, method in recorder.repositories()}
    assert methods.isdisjoint({"get_by_attempt_number", "count_attempts"})


def test_zero_attempts_are_explicit_absence_never_a_placeholder() -> None:
    # Plan 9.2 / contract D12: no run id and no attempt number 0 stand in for
    # "no attempt".
    built = _built(_seeded(outcomes={SLOT_B: _C.UNAVAILABLE}))
    dumped = built.model_dump(mode="python")
    for slot, dumped_slot in zip(built.slots, dumped["slots"], strict=True):
        assert _missing(slot.latest_attempt_run_id)
        assert _missing(slot.latest_attempt_state)
        assert "latest_attempt_run_id" not in dumped_slot
        assert "latest_attempt_state" not in dumped_slot
        assert not any("attempt" in key for key in dumped_slot)
    assert b"run_" not in canonical_json_bytes(built)


def test_the_two_signatures_match_the_contract() -> None:
    build = inspect.signature(build_aggregation_input).parameters
    assert tuple(build) == ("transaction", "experiment", "now")
    assert build["transaction"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert build["experiment"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert build["now"].kind is inspect.Parameter.KEYWORD_ONLY
    aggregate = inspect.signature(aggregate_experiment).parameters
    assert tuple(aggregate) == ("request", "unit_of_work", "clock")
    assert aggregate["request"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert aggregate["unit_of_work"].kind is inspect.Parameter.KEYWORD_ONLY
    assert aggregate["clock"].kind is inspect.Parameter.KEYWORD_ONLY


# --------------------------------------------------------------------------
# C. aggregate_experiment: the idempotent terminal path (contract D6 step 2, D7,
#    D11)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("state", "include_compatibility"),
    [
        (_E.COMPLETED, None),
        (_E.COMPLETED_WITH_WARNINGS, None),
        (_E.FAILED, None),
        (_E.CANCELLED, False),
        (_E.CANCELLED, True),
    ],
    ids=[
        "COMPLETED",
        "COMPLETED_WITH_WARNINGS",
        "FAILED",
        "CANCELLED-before-freeze",
        "CANCELLED-after-freeze",
    ],
)
@pytest.mark.parametrize(
    "revision_offset", [0, -3, 9], ids=["stored", "stale", "ahead"]
)
def test_an_already_terminal_experiment_replays_its_verdict_without_a_clock_read(
    state: ExperimentState, include_compatibility: bool | None, revision_offset: int
) -> None:
    # Plan 9.4 / contract D6 step 2: verdict by state, empty codes, no clock, no
    # child read, no write; expected_revision is not compared (9.5 row 2).
    experiment = sample_experiment(state, include_compatibility=include_compatibility)
    assert experiment.revision == 4
    seeded = _seeded(experiment=experiment)
    root, recorder = _recording(seeded)
    result = _aggregate(
        root,
        expected_revision=experiment.revision + revision_offset,
        clock=FailingClock(),
    )
    assert _ok(result) == _result(VERDICT_OF_TERMINAL_STATE[state])
    assert _ok(result).verdict.value == state.value
    assert recorder.repositories() == (("experiments", "get"),)
    _assert_unchanged(seeded)


def test_a_missing_experiment_is_the_repository_invariant_violation() -> None:
    # Contract D6 step 1 / D7: the repository's failure, no service clock read.
    store = InMemoryBackingStore()
    clock = CountingClock(CLOCK_INSTANT)
    result = _aggregate(InMemoryUnitOfWork(store), clock=clock)
    assert _code(result) == INVARIANT_VIOLATION
    assert _diagnostic(result).source_component == REPOSITORY_SOURCE
    assert clock.reads == 0
    assert store.committed_experiments() == ()


def test_a_missing_experiment_returns_the_repository_failure_with_no_clock_read() -> (
    None
):
    # Contract D7 with FailingClock: a load failure never reaches the clock.
    store = InMemoryBackingStore()
    _seed(store, sample_run(_R.SUCCEEDED))
    result = _aggregate(InMemoryUnitOfWork(store), clock=FailingClock())
    assert _code(result) == INVARIANT_VIOLATION
    diagnostic = _diagnostic(result)
    assert diagnostic.source_component == REPOSITORY_SOURCE
    assert diagnostic.timestamp_utc == INSTANT
    assert store.committed_experiments() == ()
    assert store.committed_engine_runs() == (sample_run(_R.SUCCEEDED),)


# --------------------------------------------------------------------------
# D. Rejections before any child read (contract D6 steps 4-5, D7, D10, D19)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "state", [_E.DRAFT, _E.VALIDATED, _E.QUEUED], ids=["DRAFT", "VALIDATED", "QUEUED"]
)
def test_a_pre_running_experiment_is_an_invariant_violation_after_one_clock_read(
    state: ExperimentState,
) -> None:
    # Plan 9.4 / contract D6 step 4: none of these has slots to aggregate.
    seeded = _seeded(experiment=sample_experiment(state))
    root, recorder = _recording(seeded)
    clock = CountingClock(CLOCK_INSTANT)
    result = _aggregate(root, expected_revision=seeded.experiment.revision, clock=clock)
    _assert_service_stamped(result, code=INVARIANT_VIOLATION, now=CLOCK_INSTANT)
    assert clock.reads == 1
    assert recorder.repositories() == (("experiments", "get"),)
    _assert_unchanged(seeded)


@pytest.mark.parametrize("revision_offset", [-1, 1], ids=["behind", "ahead"])
def test_a_stale_expected_revision_is_a_conflict_before_any_child_read(
    revision_offset: int,
) -> None:
    # Contract D6 step 5: a write-ready store (F1 material) proves the revision
    # check fires first -- a missed check would terminalize.
    seeded = _seeded(runs=(sample_run(_R.SUCCEEDED), _run_b(_R.SUCCEEDED)))
    root, recorder = _recording(seeded)
    clock = CountingClock(CLOCK_INSTANT)
    result = _aggregate(
        root,
        expected_revision=seeded.experiment.revision + revision_offset,
        clock=clock,
    )
    _assert_service_stamped(result, code=CONCURRENCY_CONFLICT, now=CLOCK_INSTANT)
    assert clock.reads == 1
    assert recorder.repositories() == (("experiments", "get"),)
    assert recorder.of("engine_runs") == ()
    assert recorder.of("retry_decisions") == ()
    _assert_unchanged(seeded)


# --------------------------------------------------------------------------
# E. NOT_YET_TERMINAL (contract D6 step 8, D12 cases 3-4, D13 blocking statuses)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "state",
    list(NON_TERMINAL_RUN_STATES),
    ids=[state.value for state in NON_TERMINAL_RUN_STATES],
)
def test_a_non_terminal_current_attempt_blocks_with_no_write(
    state: EngineRunState,
) -> None:
    # 9.3 row 1: A non-terminal -> NOT_YET_TERMINAL, no codes, no write.
    seeded = _seeded(runs=(sample_run(state), _run_b(_R.SUCCEEDED)))
    _assert_not_yet_terminal(seeded, _aggregate_once(seeded.store))


@pytest.mark.parametrize(
    "outcome",
    [_C.SUPPORTED, _C.SUPPORTED_WITH_APPROXIMATION],
    ids=["SUPPORTED", "SUPPORTED_WITH_APPROXIMATION"],
)
def test_an_unattempted_runnable_slot_blocks_with_no_write(
    outcome: CompatibilityOutcome,
) -> None:
    # 9.3 row 2 / D12(3)-(4): A has no attempt under a runnable frozen outcome.
    seeded = _seeded(outcomes={SLOT_A: outcome}, runs=(_run_b(_R.SUCCEEDED),))
    _assert_not_yet_terminal(seeded, _aggregate_once(seeded.store))


@pytest.mark.parametrize(
    "state", list(RETRY_STATES), ids=[state.value for state in RETRY_STATES]
)
def test_an_unresolved_decision_blocks_with_no_write(state: EngineRunState) -> None:
    # 9.3 row 3: A terminal in a retry state with no decision row ->
    # DECISION_UNRESOLVED -> NOT_YET_TERMINAL.
    seeded = _seeded(runs=(sample_run(state), _run_b(_R.SUCCEEDED)))
    _assert_not_yet_terminal(seeded, _aggregate_once(seeded.store))


@pytest.mark.parametrize(
    "now",
    [DUE_INSTANT - timedelta(seconds=1), DUE_INSTANT + timedelta(days=1)],
    ids=["before-not-before", "well-after-not-before"],
)
def test_an_allowed_reservation_without_a_successor_blocks_whatever_the_instant(
    now: datetime,
) -> None:
    # 9.3 row 3 / D13: ALLOWED_SUCCESSOR_PENDING blocks; aggregation never compares
    # retry_not_before_utc with the clock -- a due reservation is not an attempt.
    experiment = _experiment()
    allowed = _allowed(_R.FAILED, experiment=experiment)
    assert allowed.retry_not_before_utc == DUE_INSTANT
    seeded = _seeded(
        experiment=experiment,
        runs=(sample_run(_R.FAILED), _run_b(_R.SUCCEEDED)),
        decisions=(allowed,),
    )
    clock = CountingClock(now)
    result = _aggregate(InMemoryUnitOfWork(seeded.store), clock=clock)
    assert clock.reads == 1
    _assert_not_yet_terminal(seeded, result)


def test_a_not_yet_terminal_result_performs_no_write_call_on_any_member() -> None:
    # Contract D8 / D9 through the service: reads only, in plan 10.1's order.
    seeded = _seeded(runs=(sample_run(_R.FAILED), _run_b(_R.SUCCEEDED)))
    root, recorder = _recording(seeded)
    _assert_not_yet_terminal(seeded, _aggregate(root))
    calls = recorder.repositories()
    assert calls == (
        ("experiments", "get"),
        ("engine_runs", "latest_attempt"),
        ("retry_decisions", "get_by_predecessor"),
        ("engine_runs", "latest_attempt"),
    )
    methods = {method for _, method in calls}
    assert methods.isdisjoint({"insert_if_absent", "add_attempt", "compare_and_swap"})


# --------------------------------------------------------------------------
# F. Terminal verdicts end to end (contract D12, D13, D16, D20, D21)
# --------------------------------------------------------------------------


def test_two_succeeded_slots_complete_cleanly() -> None:
    # 9.3 row 7: S={A,B}, N={}, no approximation, no late -> COMPLETED ().
    seeded = _seeded(runs=(sample_run(_R.SUCCEEDED), _run_b(_R.SUCCEEDED)))
    result = _aggregate_once(seeded.store)
    _assert_terminalized(seeded, result, verdict=_V.COMPLETED, codes=())


def test_an_expected_not_applicable_slot_beside_a_success_completes_cleanly() -> None:
    # 9.3 row 7 / D12(1): S={A}, N={B} (frozen N/A, zero attempts, not late),
    # |S|+|N|=2 -> COMPLETED ().
    seeded = _seeded(
        outcomes={SLOT_B: _C.NOT_APPLICABLE}, runs=(sample_run(_R.SUCCEEDED),)
    )
    result = _aggregate_once(seeded.store)
    _assert_terminalized(seeded, result, verdict=_V.COMPLETED, codes=())


def test_a_succeeded_with_warnings_slot_completes_with_its_warning() -> None:
    # 9.3 row 8: S={A,B} but B is SUCCEEDED_WITH_WARNINGS, row 7 fails ->
    # CWW {SLOT_SUCCEEDED_WITH_WARNINGS}.
    seeded = _seeded(
        runs=(sample_run(_R.SUCCEEDED), _run_b(_R.SUCCEEDED_WITH_WARNINGS))
    )
    result = _aggregate_once(seeded.store)
    _assert_terminalized(
        seeded,
        result,
        verdict=_V.COMPLETED_WITH_WARNINGS,
        codes=(REASON_SLOT_SUCCEEDED_WITH_WARNINGS,),
    )


def test_a_frozen_approximation_on_a_succeeded_slot_is_a_warning() -> None:
    # 9.3 row 8 / D20: uses_approximation(A) fails row 7 ->
    # CWW {SLOT_USED_APPROXIMATION}.
    seeded = _seeded(
        outcomes={SLOT_A: _C.SUPPORTED_WITH_APPROXIMATION},
        runs=(sample_run(_R.SUCCEEDED), _run_b(_R.SUCCEEDED)),
    )
    result = _aggregate_once(seeded.store)
    _assert_terminalized(
        seeded,
        result,
        verdict=_V.COMPLETED_WITH_WARNINGS,
        codes=(REASON_SLOT_USED_APPROXIMATION,),
    )


def test_a_late_not_applicable_slot_beside_a_success_is_a_warning() -> None:
    # 9.3 row 8 / D20: S={B}, N={A} late (frozen SUPPORTED, N/A attempt) fails
    # row 7 -> CWW {COMPAT.LATE_NOT_APPLICABLE}.
    seeded = _seeded(runs=(sample_run(_R.NOT_APPLICABLE), _run_b(_R.SUCCEEDED)))
    result = _aggregate_once(seeded.store)
    _assert_terminalized(
        seeded,
        result,
        verdict=_V.COMPLETED_WITH_WARNINGS,
        codes=(REASON_LATE_NOT_APPLICABLE,),
    )


@pytest.mark.parametrize(
    ("state", "with_row", "code"),
    [
        (_R.FAILED, True, REASON_SLOT_FAILED),
        (_R.TIMED_OUT, True, REASON_SLOT_TIMED_OUT),
        (_R.UNAVAILABLE, True, REASON_SLOT_UNAVAILABLE),
        (_R.CANCELLED, False, REASON_SLOT_CANCELLED),
    ],
    ids=["FAILED", "TIMED_OUT", "UNAVAILABLE", "CANCELLED"],
)
def test_a_denied_or_cancelled_slot_beside_a_success_is_a_warning(
    state: EngineRunState, with_row: bool, code: str
) -> None:
    # 9.3 row 8 / D13: S={B}, A effectively <state> (DENIED lets it contribute),
    # |S|+|N|=1<2 fails row 7 -> CWW {A's state code}.
    seeded = _seeded(
        runs=(sample_run(state), _run_b(_R.SUCCEEDED)),
        decisions=(_denied(state),) if with_row else (),
    )
    result = _aggregate_once(seeded.store)
    _assert_terminalized(
        seeded, result, verdict=_V.COMPLETED_WITH_WARNINGS, codes=(code,)
    )


def test_a_zero_attempt_unavailable_slot_beside_a_success_is_a_warning() -> None:
    # 9.3 row 8 / D12(2): S={A}, B effectively UNAVAILABLE (frozen, zero attempts)
    # -> CWW {SLOT_UNAVAILABLE}.
    seeded = _seeded(
        outcomes={SLOT_B: _C.UNAVAILABLE}, runs=(sample_run(_R.SUCCEEDED),)
    )
    result = _aggregate_once(seeded.store)
    _assert_terminalized(
        seeded,
        result,
        verdict=_V.COMPLETED_WITH_WARNINGS,
        codes=(REASON_SLOT_UNAVAILABLE,),
    )


def test_every_slot_expected_not_applicable_fails_with_no_applicable_engine() -> None:
    # 9.3 row 4 / D12(1): N={A,B}, none late -> FAILED {NO_APPLICABLE_ENGINE}.
    # Reachable through aggregate_experiment only from a SEEDED RUNNING record: an
    # all-N/A experiment never leaves QUEUED through create_attempt (plan 5 step 4).
    seeded = _seeded(outcomes={SLOT_A: _C.NOT_APPLICABLE, SLOT_B: _C.NOT_APPLICABLE})
    result = _aggregate_once(seeded.store)
    _assert_terminalized(
        seeded, result, verdict=_V.FAILED, codes=(REASON_NO_APPLICABLE_ENGINE,)
    )


def test_every_slot_not_applicable_with_a_late_member_adds_the_late_code() -> None:
    # 9.3 row 4 / D20: N={A late, B expected} -> FAILED
    # {COMPAT.LATE_NOT_APPLICABLE, NO_APPLICABLE_ENGINE} sorted ("C" < "E").
    seeded = _seeded(
        outcomes={SLOT_B: _C.NOT_APPLICABLE}, runs=(sample_run(_R.NOT_APPLICABLE),)
    )
    result = _aggregate_once(seeded.store)
    _assert_terminalized(
        seeded,
        result,
        verdict=_V.FAILED,
        codes=(REASON_LATE_NOT_APPLICABLE, REASON_NO_APPLICABLE_ENGINE),
    )


def test_no_success_and_two_denied_failures_fail_with_both_state_codes() -> None:
    # 9.3 row 5 / D13: S={}, A FAILED + B TIMED_OUT (both DENIED) ->
    # FAILED {SLOT_FAILED, SLOT_TIMED_OUT} sorted ("F" < "T").
    seeded = _seeded(
        runs=(sample_run(_R.FAILED), _run_b(_R.TIMED_OUT)),
        decisions=(_denied(_R.FAILED), _denied_b(_R.TIMED_OUT)),
    )
    result = _aggregate_once(seeded.store)
    _assert_terminalized(
        seeded,
        result,
        verdict=_V.FAILED,
        codes=(REASON_SLOT_FAILED, REASON_SLOT_TIMED_OUT),
    )


def test_every_slot_zero_attempt_unavailable_fails_with_one_code() -> None:
    # 9.3 row 5 / D12(2): S={}, A and B effectively UNAVAILABLE (frozen, zero
    # attempts) -> FAILED {SLOT_UNAVAILABLE} (a set: one code, not two).
    seeded = _seeded(outcomes={SLOT_A: _C.UNAVAILABLE, SLOT_B: _C.UNAVAILABLE})
    result = _aggregate_once(seeded.store)
    _assert_terminalized(
        seeded, result, verdict=_V.FAILED, codes=(REASON_SLOT_UNAVAILABLE,)
    )


def test_a_denied_failure_beside_an_expected_not_applicable_slot_fails() -> None:
    # 9.3 row 5 / D12(1), plan Task 8 l.1692-1694 (rows 2 and 5 over a zero-attempt
    # frozen NOT_APPLICABLE slot): S={}, N={B} is not every slot so row 4 does not
    # fire; A FAILED + DENIED -> FAILED {SLOT_FAILED}; the expected N/A bystander adds
    # no code and needs no synthetic run.
    seeded = _seeded(
        outcomes={SLOT_B: _C.NOT_APPLICABLE},
        runs=(sample_run(_R.FAILED),),
        decisions=(_denied(_R.FAILED),),
    )
    result = _aggregate_once(seeded.store)
    _assert_terminalized(seeded, result, verdict=_V.FAILED, codes=(REASON_SLOT_FAILED,))
    assert _missing(_slot(_built(seeded), SLOT_B).latest_attempt_run_id)


def test_row_five_carries_no_approximation_code_beside_the_failure_codes() -> None:
    # 9.3 row 5 / D16 (the Task 5 handoff pin): S={}, A FAILED + DENIED under frozen
    # SUPPORTED_WITH_APPROXIMATION, B frozen UNAVAILABLE zero attempts ->
    # FAILED {SLOT_FAILED, SLOT_UNAVAILABLE}; the approximation adds nothing.
    seeded = _seeded(
        outcomes={SLOT_A: _C.SUPPORTED_WITH_APPROXIMATION, SLOT_B: _C.UNAVAILABLE},
        runs=(sample_run(_R.FAILED),),
        decisions=(_denied(_R.FAILED),),
    )
    result = _aggregate_once(seeded.store)
    stored = _assert_terminalized(
        seeded,
        result,
        verdict=_V.FAILED,
        codes=(REASON_SLOT_FAILED, REASON_SLOT_UNAVAILABLE),
    )
    assert REASON_SLOT_USED_APPROXIMATION not in _ok(result).reason_codes
    assert stored.state is _E.FAILED


def test_no_success_and_a_cancelled_child_fails_with_slot_cancelled() -> None:
    # 9.3 row 6: S={}, N={B} (not every slot), no failure state, A CANCELLED ->
    # FAILED {SLOT_CANCELLED}.
    seeded = _seeded(
        outcomes={SLOT_B: _C.NOT_APPLICABLE}, runs=(sample_run(_R.CANCELLED),)
    )
    result = _aggregate_once(seeded.store)
    _assert_terminalized(
        seeded, result, verdict=_V.FAILED, codes=(REASON_SLOT_CANCELLED,)
    )


def test_a_succeeded_successor_supersedes_its_failed_predecessor() -> None:
    # 9.3 row 7 / D13: A's latest attempt (2) SUCCEEDED, B SUCCEEDED -> COMPLETED ();
    # the predecessor's FAILED and its ALLOWED row contribute nothing.
    experiment = _experiment()
    allowed = _allowed(_R.FAILED, experiment=experiment)
    seeded = _seeded(
        experiment=experiment,
        runs=(
            sample_run(_R.FAILED),
            _successor(_R.SUCCEEDED),
            _run_b(_R.SUCCEEDED, run_id=THIRD_RUN_ID),
        ),
        decisions=(allowed,),
    )
    before = canonical_json_bytes(seeded.store.committed_retry_decisions()[0])
    result = _aggregate_once(seeded.store)
    _assert_terminalized(seeded, result, verdict=_V.COMPLETED, codes=())
    (after,) = seeded.store.committed_retry_decisions()
    assert after == allowed
    assert canonical_json_bytes(after) == before


def test_a_single_slot_denied_failure_fails_the_experiment() -> None:
    # 9.3 row 5 / D13 (one-slot spec): S={}, A FAILED + DENIED -> FAILED {SLOT_FAILED}.
    seeded = _seeded(
        draft=_one_slot_draft(),
        runs=(sample_run(_R.FAILED),),
        decisions=(_denied(_R.FAILED),),
    )
    assert len(seeded.experiment.spec.selected_engine_slots) == 1
    result = _aggregate_once(seeded.store)
    _assert_terminalized(seeded, result, verdict=_V.FAILED, codes=(REASON_SLOT_FAILED,))


def test_one_success_beside_a_denied_failure_is_a_warning_not_a_completion() -> None:
    # 9.3 row 8 / D24 (no vote): S={A}, B FAILED + DENIED, |S|+|N|=1<2 ->
    # CWW {SLOT_FAILED}, not COMPLETED.
    seeded = _seeded(
        runs=(sample_run(_R.SUCCEEDED), _run_b(_R.FAILED)),
        decisions=(_denied_b(_R.FAILED),),
    )
    result = _aggregate_once(seeded.store)
    _assert_terminalized(
        seeded,
        result,
        verdict=_V.COMPLETED_WITH_WARNINGS,
        codes=(REASON_SLOT_FAILED,),
    )
    assert _ok(result).verdict is not _V.COMPLETED


def test_two_denied_failures_are_failed_not_averaged() -> None:
    # 9.3 row 5 / D24 (no average): S={}, A FAILED, B TIMED_OUT (both DENIED) ->
    # FAILED {SLOT_FAILED, SLOT_TIMED_OUT}; no synthetic middle verdict exists.
    seeded = _seeded(
        runs=(sample_run(_R.FAILED), _run_b(_R.TIMED_OUT)),
        decisions=(_denied(_R.FAILED), _denied_b(_R.TIMED_OUT)),
    )
    result = _aggregate_once(seeded.store)
    value = _ok(result)
    assert value.verdict is _V.FAILED
    assert value.verdict not in {_V.COMPLETED, _V.COMPLETED_WITH_WARNINGS}
    _assert_terminalized(
        seeded,
        result,
        verdict=_V.FAILED,
        codes=(REASON_SLOT_FAILED, REASON_SLOT_TIMED_OUT),
    )


def test_the_same_seed_in_reversed_store_order_yields_identical_results() -> None:
    # Contract D14: 9.3 row 5 material with two codes so sortedness is observable.
    experiment = _experiment()
    run_a, run_b = sample_run(_R.FAILED), _run_b(_R.TIMED_OUT)
    denied_a, denied_b = _denied(_R.FAILED), _denied_b(_R.TIMED_OUT)
    forward = _seeded(
        experiment=experiment, runs=(run_a, run_b), decisions=(denied_a, denied_b)
    )
    backward = _seeded(
        experiment=experiment, runs=(run_b, run_a), decisions=(denied_b, denied_a)
    )
    first = _ok(_aggregate_once(forward.store))
    second = _ok(_aggregate_once(backward.store))
    assert first == second
    assert canonical_json_bytes(first) == canonical_json_bytes(second)
    assert first.reason_codes == tuple(sorted(first.reason_codes))
    assert first.reason_codes == (REASON_SLOT_FAILED, REASON_SLOT_TIMED_OUT)
    assert _stored(forward.store) == _stored(backward.store)
    assert canonical_json_bytes(_stored(forward.store)) == canonical_json_bytes(
        _stored(backward.store)
    )
    assert _stored(forward.store).state is _E.FAILED


def test_a_clock_before_the_creation_instant_is_an_invariant_violation() -> None:
    # Contract D6 step 10: the replacement's ValidationError (updated_at_utc <
    # created_at_utc) surfaces as a Result; nothing is written.
    seeded = _seeded(runs=(sample_run(_R.SUCCEEDED), _run_b(_R.SUCCEEDED)))
    early = INSTANT - timedelta(days=1)
    clock = CountingClock(early)
    result = _aggregate(InMemoryUnitOfWork(seeded.store), clock=clock)
    _assert_service_stamped(result, code=INVARIANT_VIOLATION, now=early)
    assert clock.reads == 1
    _assert_unchanged(seeded)


# --------------------------------------------------------------------------
# G. Compare-and-swap, replay and restart (contract D6 steps 11-12, D7, D11, D19)
# --------------------------------------------------------------------------


def _completed() -> tuple[_Seeded, ExperimentRecord]:
    """F1's write: the seeded store and the committed COMPLETED record."""
    seeded = _seeded(runs=(sample_run(_R.SUCCEEDED), _run_b(_R.SUCCEEDED)))
    result = _aggregate_once(seeded.store)
    return seeded, _assert_terminalized(seeded, result, verdict=_V.COMPLETED, codes=())


def _replay(seeded: _Seeded, *, expected_revision: int) -> ExperimentAggregationResult:
    """A repeated call through a fresh root with a clock that must not be read."""
    return _ok(
        _aggregate(
            InMemoryUnitOfWork(seeded.store),
            expected_revision=expected_revision,
            clock=FailingClock(),
        )
    )


def test_a_repeated_call_at_the_new_revision_replays_without_a_clock_read() -> None:
    # Contract D11: verdict by stored state, empty codes, no double bump.
    seeded, terminal = _completed()
    assert terminal.revision == 4
    replay = _replay(seeded, expected_revision=terminal.revision)
    assert replay.verdict is _V.COMPLETED
    assert replay.reason_codes == ()
    assert replay.experiment_id == EXPERIMENT_ID
    assert replay.schema_version == "1.0.0"
    _assert_unchanged(seeded, terminal)


def test_a_repeated_call_at_the_old_revision_replays_identically() -> None:
    # Contract D6 step 2: the terminal path ignores expected_revision.
    seeded, terminal = _completed()
    replay = _replay(seeded, expected_revision=seeded.experiment.revision)
    assert replay.verdict is _V.COMPLETED
    assert replay.reason_codes == ()
    _assert_unchanged(seeded, terminal)


def test_replay_after_a_warning_verdict_reports_the_verdict_with_empty_codes() -> None:
    # Contract D11: identity in VERDICT only -- reason codes are not durable in
    # Stage 5, so the replay carries () where the terminalizing result carried one.
    seeded = _seeded(
        runs=(sample_run(_R.SUCCEEDED), _run_b(_R.SUCCEEDED_WITH_WARNINGS))
    )
    first = _ok(_aggregate_once(seeded.store))
    assert first.reason_codes == (REASON_SLOT_SUCCEEDED_WITH_WARNINGS,)
    replay = _replay(seeded, expected_revision=4)
    assert replay.verdict is _V.COMPLETED_WITH_WARNINGS
    assert replay.verdict is first.verdict
    assert replay.reason_codes == ()
    assert _stored(seeded.store).state is _E.COMPLETED_WITH_WARNINGS
    assert _stored(seeded.store).revision == 4


def test_a_rebuilt_root_over_the_same_store_observes_and_replays_the_record() -> None:
    # Contract D11 / D14 restart: the committed write survives; revision stays N+1.
    seeded, terminal = _completed()
    rebuilt = InMemoryUnitOfWork(seeded.store)
    reader = rebuilt.begin()
    loaded = _ok(reader.experiments.get(EXPERIMENT_ID))
    reader.rollback()
    assert loaded == terminal
    assert loaded.state is _E.COMPLETED
    replay = _replay(seeded, expected_revision=terminal.revision)
    assert replay.verdict is _V.COMPLETED
    assert replay.reason_codes == ()
    assert _stored(seeded.store).revision == 4
    assert rebuilt.hooks_installed == ()
    _assert_unchanged(seeded, terminal)


def test_a_lost_swap_reloading_running_at_the_next_revision_is_a_conflict() -> None:
    # Plan 9.4 / 9.5: a state-preserving bump wins; the reload lands on RUNNING at
    # N+1 -> D6 step 5 CONCURRENCY_CONFLICT after a second clock read; a re-issued
    # call at N+1 terminalizes (9.3 row 7 -> COMPLETED ()).
    seeded = _seeded(runs=(sample_run(_R.SUCCEEDED), _run_b(_R.SUCCEEDED)))
    bumped = _replaced(seeded.experiment)
    assert bumped.state is _E.RUNNING
    assert bumped.revision == 4
    root = InMemoryUnitOfWork(seeded.store)
    root.install_experiment_compare_and_swap_hook(_raw_winner(seeded.store, bumped))
    assert root.hooks_installed == _CAS_HOOK
    clock = CountingClock(CLOCK_INSTANT)
    result = _aggregate(root, clock=clock)
    _assert_service_stamped(result, code=CONCURRENCY_CONFLICT, now=CLOCK_INSTANT)
    assert clock.reads == 2
    assert root.hooks_installed == ()
    _assert_unchanged(seeded, bumped)
    second = _aggregate_once(seeded.store, expected_revision=bumped.revision)
    stored = _assert_terminalized(
        seeded, second, verdict=_V.COMPLETED, codes=(), seed=bumped
    )
    assert stored.revision == 5


def test_a_lost_swap_reloading_a_terminal_record_replays_its_verdict() -> None:
    # Plan 9.4 / 9.5 row 2 shape: a raw FAILED winner; the reload takes the terminal
    # path before the clock -> Success FAILED () after exactly one read.
    seeded = _seeded(runs=(sample_run(_R.SUCCEEDED), _run_b(_R.SUCCEEDED)))
    failed = _replaced(seeded.experiment, state=_E.FAILED)
    root = InMemoryUnitOfWork(seeded.store)
    root.install_experiment_compare_and_swap_hook(_raw_winner(seeded.store, failed))
    clock = CountingClock(CLOCK_INSTANT)
    result = _ok(_aggregate(root, clock=clock))
    assert result.verdict is _V.FAILED
    assert result.reason_codes == ()
    assert result == _result(_V.FAILED)
    assert clock.reads == 1
    assert root.hooks_installed == ()
    _assert_unchanged(seeded, failed)


def test_two_lost_swaps_return_the_conflict_after_exactly_two_transactions() -> None:
    # Contract D6 step 11: the driver reloads once; a second loss returns the
    # repository's conflict unchanged; nothing durable.
    seeded = _seeded(runs=(sample_run(_R.SUCCEEDED), _run_b(_R.SUCCEEDED)))
    root = _overriding(seeded.store, "experiments", compare_and_swap=_conflict_answer)
    clock = CountingClock(CLOCK_INSTANT)
    result = _aggregate(root, clock=clock)
    assert result == _stub_conflict()
    assert _code(result) == CONCURRENCY_CONFLICT
    assert root.begins == 2
    assert clock.reads == 2
    _assert_unchanged(seeded)


# --------------------------------------------------------------------------
# H. Boundaries (contract D23, D24)
# --------------------------------------------------------------------------

_ALLOWED_IMPORT_ROOTS: Final = frozenset(
    {"__future__", "collections", "datetime", "typing", "pydantic", "crypto_lab"}
)
_FORBIDDEN_MODULES: Final = (
    "crypto_lab.configuration",
    "crypto_lab.capabilities",
    "crypto_lab.persistence",
    "crypto_lab.cli",
    "crypto_lab.schema_registry",
    "crypto_lab.experiments.retry",
)
_GATE_NAMES: Final = frozenset(
    {"evaluate_retry", "create_successor", "evaluate_retry_gates"}
)
_DEFERRED_NAMES: Final = frozenset({"Result", "RunEvent", "AdapterResultManifest"})


def test_the_module_imports_only_the_declared_roots_and_defines_no_deferred_name() -> (
    None
):
    source = aggregation_module.__file__
    assert source is not None
    path = Path(source)
    assert path.name == "aggregation.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: list[str] = []
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "the module uses absolute imports only"
            assert node.module is not None
            modules.append(node.module)
            for alias in node.names:
                imported.add(alias.name)
                if alias.asname is not None:
                    imported.add(alias.asname)
    roots = {module.partition(".")[0] for module in modules}
    assert roots <= _ALLOWED_IMPORT_ROOTS, roots
    for module in modules:
        for forbidden in _FORBIDDEN_MODULES:
            assert module != forbidden, module
            assert not module.startswith(f"{forbidden}."), module
    # Contract D24: aggregation never re-evaluates gates or creates successors.
    assert imported.isdisjoint(_GATE_NAMES), imported & _GATE_NAMES
    defined = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
    }
    assert defined.isdisjoint(_DEFERRED_NAMES), defined & _DEFERRED_NAMES
    assert {"build_aggregation_input", "aggregate_experiment"} <= defined
