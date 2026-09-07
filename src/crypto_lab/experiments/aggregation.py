"""Terminal experiment aggregation: the authoritative input and the transaction.

Plan sections 9.2 (selected slots, effective terminal state and readiness), 9.4 (the
aggregation transaction), 9.5 rows 1-2 and 7-8 (the loser reloads once), 10.1 row
``aggregate_experiment`` (read set: the experiment with ``slot_compatibility``, each
slot's current attempt or its absence, each decision row; write set: the experiment
at the mapped terminal state, revision + 1) and 12 Task 8, under specification
section 16.3. Placement follows plan 2.3: the records, the effective-terminal-state
derivation, the reason codes and the pure classifier are Task 5's
``crypto_lab.domain.aggregation``; this module is the application operation that
reads authoritative state through the unit of work, builds the classifier's input,
invokes it once and commits the terminal transition through the experiment-revision
compare-and-swap of plan 9.1. It runs through the Task 6 reload-once driver
``run_operation``, reaches every repository through the unit of work alone, reads the
injected ``Clock`` only where declared below, and never re-evaluates a retry gate,
calls ``evaluate_retry`` or ``create_successor``, compares ``retry_not_before_utc``
with the clock, draws an identifier, averages, votes or synthesizes a verdict.

Two public operations:

1. ``build_aggregation_input`` -- plan 9.2: one ``SlotAggregationInput`` per selected
   slot, whether or not it has an attempt, from the frozen ``slot_compatibility``
   entry, the slot's current attempt and its decision row.
2. ``aggregate_experiment`` -- plan 9.4: the idempotent already-terminal path, the
   ``RUNNING`` requirement, the revision check, the classifier and the single
   compare-and-swap.

Task-local readings, declared here rather than inferred silently (each was
submitted to an adversarial cross-check before any code was written; see the Task 8
service API contract):

- **Precondition.** A record whose ``slot_compatibility`` is ``MISSING`` -- ``DRAFT``,
  ``VALIDATED``, or a ``CANCELLED`` record cancelled before the freeze -- carries no
  frozen compatibility to aggregate and is ``CORE.INVARIANT_VIOLATION``. Otherwise the
  selected slots and the frozen entries are walked together in spec order: the
  plan 3.10 requirement that the input's slot set equal the frozen selected-slot set
  (which the Task 5 kernel docstring leaves to Task 8) is discharged by
  ``ExperimentRecord``'s own alignment validator -- exactly one entry per selected
  slot, in slot order, on a frozen model -- and asserted again by the Task 8 tests.
- **Per-slot read set, equal to plan 10.1's.** Exactly one ``latest_attempt`` per
  slot; ``MISSING`` is the explicit zero-attempt answer. A run whose experiment or slot
  identity differs from the query is a repository defect
  (``CORE.INVARIANT_VIOLATION``). ``get_by_predecessor`` is read only for a slot
  whose current attempt maps to a ``RetryTerminalState`` -- ``FAILED``, ``TIMED_OUT``
  or ``UNAVAILABLE``; every other slot is ``NO_DECISION_REQUIRED`` without a decision
  read (plan 9.2). No ``get_by_attempt_number``, ``count_attempts``, diagnostic or
  observation read occurs.
- **Repository faults pass through.** A ``latest_attempt`` ``Failure`` is returned
  unchanged. A ``get_by_predecessor`` ``Failure`` whose every diagnostic is
  ``CORE.INVARIANT_VIOLATION`` is the repository's absence vocabulary and yields
  ``DECISION_UNRESOLVED``; any other ``Failure`` is a read fault and is returned
  unchanged, so a persistence fault is never re-coded into a domain fact. This is the
  convention of Task 7's ``get`` reads, which apply the same all-invariant test.
- **Retry status.** A present row keyed to another experiment is
  ``CORE.INVARIANT_VIOLATION``; ``DENIED`` resolves the slot as ``DENIED``; ``ALLOWED``
  is ``ALLOWED_SUCCESSOR_PENDING`` with no further read, because ``latest_attempt``
  returning the predecessor already establishes plan 9.2's "no attempt bears its
  reserved number": attempts are dense, a reservation is ``created_attempt_count + 1``
  and a created successor is itself the latest attempt, whose predecessor's row is
  never consulted (plan 9.2, 9.5).
- **Order of ``aggregate_experiment``** (the Task 6 check order; the clock-free replay
  path follows Task 7's phase 1): load (a missing identity is the repository's
  ``CORE.INVARIANT_VIOLATION``, passed through); an already-terminal record returns
  ``Success`` with that state's verdict and empty ``reason_codes`` -- no clock read,
  no child read, no write, and ``expected_revision`` is deliberately not compared, so
  a stale loser that reloads a cancelled record reports the ``CANCELLED`` verdict
  (plan 9.4, 9.5 row 2); then the single clock read of the attempt; ``DRAFT``,
  ``VALIDATED`` or ``QUEUED`` is ``CORE.INVARIANT_VIOLATION``; a moved
  ``expected_revision`` is ``PERSISTENCE.CONCURRENCY_CONFLICT`` before any child read
  (plan 10.1: movement in any read-set revision aborts the row; 9.5 row 7); the input;
  the classifier; ``NOT_YET_TERMINAL`` returns the result with no write; a terminal
  verdict maps through ``TERMINAL_STATE_OF_VERDICT`` and compare-and-swaps one
  replacement -- the stored record at the mapped state, ``updated_at_utc`` at the
  instant and revision + 1, every other field carried, ``cancellation_correlation_id``
  absent. A lost swap is a ``LostSwap``: the driver reloads once and re-applies the
  whole sequence, so a now-terminal record yields the idempotent verdict and a
  still-``RUNNING`` record at a newer revision yields the conflict.
- **Idempotent replay is identity in verdict only.** Reason codes are not durable in
  Stage 5 (plan 1.4), so the replay of a terminalized experiment carries the stored
  state's verdict and ``()``, not the terminalizing result's codes; specification 29.6's
  "prior identical outcome" is claimed for the verdict.
- **Clock discipline.** Zero service-clock reads on a load failure and on the
  already-terminal path; exactly one read per attempt otherwise. Every failure this
  module emits is stamped with that instant, names ``experiments.aggregation`` and
  the experiment; a repository failure keeps its own stamp.
- **The Task 5 handoff.** The classifier is consumed exactly as committed: row 5
  contributes only the codes of the slots effectively ``FAILED``, ``TIMED_OUT`` or
  ``UNAVAILABLE``, row 6 exactly ``EXPERIMENT.SLOT_CANCELLED``, row 4
  ``EXPERIMENT.NO_APPLICABLE_ENGINE`` plus the late code when any member is late, and
  row 8 the union over every slot. No second classifier and no precedence rule lives
  here.
- The two mapping constants are exported beside the plan's two produced names so a
  test and Task 9's flow can pin the verdict-to-state edges (plan 4 edge ownership:
  ``RUNNING`` to ``COMPLETED``, ``COMPLETED_WITH_WARNINGS`` or ``FAILED``) and the
  terminal-state-to-verdict replay.

Absence is ``MISSING``, never ``None`` (plan section 3.1).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Final

from pydantic import ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.domain.aggregation import (
    AggregationVerdict,
    ExperimentAggregationInput,
    ExperimentAggregationResult,
    SlotAggregationInput,
    SlotRetryStatus,
    classify_experiment_outcome,
)
from crypto_lab.domain.diagnostics import DiagnosticDetailValue
from crypto_lab.domain.engine_run import EngineRunRecord
from crypto_lab.domain.experiment import (
    ExperimentRecord,
    SelectedEngineSlot,
    SlotCompatibility,
)
from crypto_lab.domain.lifecycle import (
    TERMINAL_ENGINE_RUN_STATES,
    TERMINAL_EXPERIMENT_STATES,
    ExperimentState,
)
from crypto_lab.domain.ports import Clock
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.domain.retry import RetryDecisionOutcome, retry_terminal_state_of
from crypto_lab.experiments.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
    stage5_failure,
)
from crypto_lab.experiments.experiment_service import (
    LostSwap,
    Outcome,
    run_operation,
)
from crypto_lab.experiments.ports import UnitOfWork
from crypto_lab.experiments.requests import ExperimentAggregationRequest

SOURCE_COMPONENT: Final = "experiments.aggregation"
_E: Final = ExperimentState
_V: Final = AggregationVerdict
_S: Final = SlotRetryStatus

#: Plan 9.4: the verdict an already-terminal experiment reports idempotently.
VERDICT_OF_TERMINAL_STATE: Final[Mapping[ExperimentState, AggregationVerdict]] = {
    _E.COMPLETED: _V.COMPLETED,
    _E.COMPLETED_WITH_WARNINGS: _V.COMPLETED_WITH_WARNINGS,
    _E.FAILED: _V.FAILED,
    _E.CANCELLED: _V.CANCELLED,
}
#: Plan 4 and 9.4: the three edges ``aggregate_experiment`` owns, from ``RUNNING``.
TERMINAL_STATE_OF_VERDICT: Final[Mapping[AggregationVerdict, ExperimentState]] = {
    _V.COMPLETED: _E.COMPLETED,
    _V.COMPLETED_WITH_WARNINGS: _E.COMPLETED_WITH_WARNINGS,
    _V.FAILED: _E.FAILED,
}


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------


def _is_missing(value: object) -> bool:
    return value is MISSING


def _failure(
    code: str,
    message: str,
    *,
    now: datetime,
    experiment_id: str,
    run_id: str | MISSING = MISSING,  # type: ignore[valid-type]
    details: Mapping[str, DiagnosticDetailValue] | None = None,
) -> Failure:
    return stage5_failure(
        code,
        message,
        source_component=SOURCE_COMPONENT,
        timestamp_utc=now,
        experiment_id=experiment_id,
        run_id=run_id,
        details=details,
    )


def _all_invariant(failure: Failure) -> bool:
    """Is every diagnostic of ``failure`` the repository's absence vocabulary,
    ``CORE.INVARIANT_VIOLATION``?"""
    return all(
        diagnostic.error_code == INVARIANT_VIOLATION
        for diagnostic in failure.diagnostics
    )


def _result(
    experiment_id: str, verdict: AggregationVerdict
) -> ExperimentAggregationResult:
    """Plan 9.4: the idempotent already-terminal result -- the state's verdict and
    empty reason codes (plan 3.10 marks every field derived)."""
    return ExperimentAggregationResult(
        schema_version="1.0.0",
        experiment_id=experiment_id,
        verdict=verdict,
        reason_codes=(),
    )


# --------------------------------------------------------------------------
# build_aggregation_input (plan 9.2, 10.1 read set)
# --------------------------------------------------------------------------


def _retry_status(
    transaction: UnitOfWork,
    experiment: ExperimentRecord,
    latest: EngineRunRecord,
    *,
    now: datetime,
) -> SlotRetryStatus | Failure:
    """Plan 9.2: the retry position of the slot's current attempt.

    ``NO_DECISION_REQUIRED`` without a decision read when the attempt is non-terminal
    or its state maps to no ``RetryTerminalState``; otherwise the decision row decides:
    absent (the repository's all-invariant failure) is ``DECISION_UNRESOLVED``, any
    other read failure passes through, a row of another experiment is an invariant
    violation, ``DENIED`` is ``DENIED`` and ``ALLOWED`` is ``ALLOWED_SUCCESSOR_PENDING``
    (the predecessor is the latest attempt, so no attempt bears the reserved number).
    """
    if latest.state not in TERMINAL_ENGINE_RUN_STATES or _is_missing(
        retry_terminal_state_of(latest.state)
    ):
        return _S.NO_DECISION_REQUIRED
    loaded = transaction.retry_decisions.get_by_predecessor(
        latest.logical_slot_id, latest.run_id
    )
    if isinstance(loaded, Failure):
        if _all_invariant(loaded):
            return _S.DECISION_UNRESOLVED
        return loaded
    decision = loaded.value
    if decision.experiment_id != experiment.experiment_id:
        return _failure(
            INVARIANT_VIOLATION,
            f"the retry decision for predecessor {latest.run_id} belongs to "
            f"experiment {decision.experiment_id}, not {experiment.experiment_id}",
            now=now,
            experiment_id=experiment.experiment_id,
            run_id=latest.run_id,
            details={"stored_experiment_id": decision.experiment_id},
        )
    if decision.outcome is RetryDecisionOutcome.DENIED:
        return _S.DENIED
    return _S.ALLOWED_SUCCESSOR_PENDING


def _slot_input(
    transaction: UnitOfWork,
    experiment: ExperimentRecord,
    slot: SelectedEngineSlot,
    frozen: SlotCompatibility,
    *,
    now: datetime,
) -> SlotAggregationInput | Failure:
    """Plan 3.10 and 9.2: one selected slot from its frozen entry, its current
    attempt (or its explicit absence) and its retry status."""
    experiment_id = experiment.experiment_id
    latest = transaction.engine_runs.latest_attempt(experiment_id, slot.logical_slot_id)
    if isinstance(latest, Failure):
        return latest
    payload: dict[str, object] = {
        "logical_slot_id": slot.logical_slot_id,
        "slot_ordinal": slot.slot_ordinal,
        "compatibility_outcome": frozen.outcome,
        "approximation_ids": frozen.approximation_ids,
        "retry_status": _S.NO_DECISION_REQUIRED,
    }
    if not _is_missing(latest.value):
        run: EngineRunRecord = latest.value
        if (
            run.experiment_id != experiment_id
            or run.logical_slot_id != slot.logical_slot_id
        ):
            return _failure(
                INVARIANT_VIOLATION,
                f"the latest attempt read for slot {slot.logical_slot_id} of "
                f"experiment {experiment_id} is run {run.run_id} of experiment "
                f"{run.experiment_id} slot {run.logical_slot_id}",
                now=now,
                experiment_id=experiment_id,
                details={
                    "logical_slot_id": slot.logical_slot_id,
                    "returned_run_id": run.run_id,
                    "returned_experiment_id": run.experiment_id,
                    "returned_logical_slot_id": run.logical_slot_id,
                },
            )
        status = _retry_status(transaction, experiment, run, now=now)
        if isinstance(status, Failure):
            return status
        payload["latest_attempt_run_id"] = run.run_id
        payload["latest_attempt_state"] = run.state
        payload["retry_status"] = status
    try:
        return SlotAggregationInput.model_validate(payload)
    except ValidationError as error:  # pragma: no cover - every accepted read set
        # validates; kept so a future shape rule surfaces as a Result.
        return _failure(
            INVARIANT_VIOLATION,
            f"the authoritative reads for slot {slot.logical_slot_id} do not form a "
            f"valid slot aggregation input ({error.error_count()} error(s))",
            now=now,
            experiment_id=experiment_id,
            details={"logical_slot_id": slot.logical_slot_id},
        )


def build_aggregation_input(
    transaction: UnitOfWork,
    experiment: ExperimentRecord,
    *,
    now: datetime,
) -> ExperimentAggregationInput | Failure:
    """Plan 9.2: every selected slot's authoritative aggregation input, in slot order.

    Requires the frozen ``slot_compatibility`` (absent before the freeze:
    ``CORE.INVARIANT_VIOLATION``). For each selected slot reads its current attempt
    through ``latest_attempt`` and, only when that attempt's terminal state maps to a
    ``RetryTerminalState``, its decision row through ``get_by_predecessor``; a
    zero-attempt slot is represented with both attempt fields absent, never omitted.
    Approximation and late status are carried as the frozen outcome and the run state
    and derived by the Task 5 kernel. A repository ``Failure`` passes through
    unchanged; ``now`` stamps the failures this function emits and is read from no
    clock here.
    """
    experiment_id = experiment.experiment_id
    if _is_missing(experiment.slot_compatibility):
        return _failure(
            INVARIANT_VIOLATION,
            f"experiment {experiment_id} ({experiment.state.value}) carries no frozen "
            "slot_compatibility to aggregate",
            now=now,
            experiment_id=experiment_id,
            details={"experiment_state": experiment.state.value},
        )
    frozen_entries: tuple[SlotCompatibility, ...] = experiment.slot_compatibility
    slots: list[SlotAggregationInput] = []
    for slot, frozen in zip(
        experiment.spec.selected_engine_slots, frozen_entries, strict=True
    ):
        built = _slot_input(transaction, experiment, slot, frozen, now=now)
        if isinstance(built, Failure):
            return built
        slots.append(built)
    try:
        return ExperimentAggregationInput(
            schema_version="1.0.0",
            experiment_id=experiment_id,
            experiment_spec_hash=experiment.spec_hash,
            slots=tuple(slots),
        )
    except ValidationError as error:  # pragma: no cover - a validated spec yields
        # ordinals 0..n-1 with unique identifiers; kept so a future rule is a Result.
        return _failure(
            INVARIANT_VIOLATION,
            f"the selected slots of experiment {experiment_id} do not form a valid "
            f"aggregation input ({error.error_count()} error(s))",
            now=now,
            experiment_id=experiment_id,
        )


# --------------------------------------------------------------------------
# aggregate_experiment (plan 9.4, 9.1, 9.5, 10.1)
# --------------------------------------------------------------------------


def aggregate_experiment(
    request: ExperimentAggregationRequest,
    *,
    unit_of_work: UnitOfWork,
    clock: Clock,
) -> Result[ExperimentAggregationResult]:
    """Plan 9.4: aggregate one ``RUNNING`` experiment, or replay its terminal verdict.

    An already-terminal record returns that state's verdict with empty reason codes,
    reading no clock and writing nothing, whatever ``expected_revision`` says. A
    ``DRAFT``, ``VALIDATED`` or ``QUEUED`` record is ``CORE.INVARIANT_VIOLATION``; a
    moved ``expected_revision`` is ``PERSISTENCE.CONCURRENCY_CONFLICT`` before any child
    read. Otherwise the input is built, the pure classifier decides, a
    ``NOT_YET_TERMINAL`` verdict is returned with no write, and a terminal verdict is
    compare-and-swapped onto the experiment as the mapped state at revision + 1; a lost
    swap reloads once through the driver and re-applies this whole sequence.
    """

    def once(transaction: UnitOfWork) -> Outcome[ExperimentAggregationResult]:
        loaded = transaction.experiments.get(request.experiment_id)
        if isinstance(loaded, Failure):
            return loaded
        stored = loaded.value
        if stored.state in TERMINAL_EXPERIMENT_STATES:
            return Success[ExperimentAggregationResult](
                outcome="SUCCESS",
                value=_result(
                    stored.experiment_id, VERDICT_OF_TERMINAL_STATE[stored.state]
                ),
            )
        now = clock.now_utc()
        if stored.state is not _E.RUNNING:
            return _failure(
                INVARIANT_VIOLATION,
                f"experiment {stored.experiment_id} is {stored.state.value}; only a "
                "RUNNING experiment has slots to aggregate",
                now=now,
                experiment_id=stored.experiment_id,
                details={"experiment_state": stored.state.value},
            )
        if request.expected_revision != stored.revision:
            return _failure(
                CONCURRENCY_CONFLICT,
                f"experiment {stored.experiment_id} is at revision {stored.revision}, "
                f"not {request.expected_revision}",
                now=now,
                experiment_id=stored.experiment_id,
                details={
                    "expected_revision": request.expected_revision,
                    "stored_revision": stored.revision,
                },
            )
        aggregation = build_aggregation_input(transaction, stored, now=now)
        if isinstance(aggregation, Failure):
            return aggregation
        result = classify_experiment_outcome(aggregation)
        if result.verdict is _V.NOT_YET_TERMINAL:
            return Success[ExperimentAggregationResult](outcome="SUCCESS", value=result)
        target = TERMINAL_STATE_OF_VERDICT.get(result.verdict)
        if target is None:  # pragma: no cover - the classifier never emits CANCELLED
            # (plan 3.10); kept so a future verdict member surfaces as a Result.
            return _failure(
                INVARIANT_VIOLATION,
                f"verdict {result.verdict.value} maps to no terminal experiment state",
                now=now,
                experiment_id=stored.experiment_id,
                details={"verdict": result.verdict.value},
            )
        payload = stored.model_dump(mode="python")
        payload["state"] = target
        payload["updated_at_utc"] = now
        payload["revision"] = stored.revision + 1
        try:
            replacement = ExperimentRecord.model_validate(payload)
        except ValidationError as error:
            return _failure(
                INVARIANT_VIOLATION,
                f"RUNNING -> {target.value} produces no representable record for "
                f"experiment {stored.experiment_id} at this instant "
                f"({error.error_count()} error(s))",
                now=now,
                experiment_id=stored.experiment_id,
                details={"target_state": target.value},
            )
        swapped = transaction.experiments.compare_and_swap(stored.revision, replacement)
        if isinstance(swapped, Failure):
            return LostSwap(swapped)
        return Success[ExperimentAggregationResult](outcome="SUCCESS", value=result)

    return run_operation(unit_of_work, once)
