"""Aggregation records, the effective terminal state and the deterministic classifier.

Stage 5 plan sections 3.10, 8.6, 9.2 and 9.3, under specification section 16.3.
Placement follows plan section 2.3: the canonical records and the pure
deterministic rules live in ``domain``, while the operation that reads the
experiment, each slot's current attempt and each decision row, builds the input,
checks readiness and commits the terminal transition -- ``aggregate_experiment``
and its ``build_aggregation_input`` -- is Task 8's application service in
``experiments``, which wraps the pure kernel defined here.

Aggregation is **selected-slot based, not attempt-presence based** (plan 9.2):
``SlotAggregationInput`` represents one selected slot whether or not it has an
attempt. Only the current attempt of a slot ever contributes; predecessors are
history. The stored experiment lifecycle state is not a classifier input: Task 8
returns idempotently for an already-terminal experiment before invoking the
classifier, which is why ``AggregationVerdict.CANCELLED`` exists as a member the
pure classifier never emits (plan 3.10, 9.4).

Four kinds of rule live here.

1. **Record shape** -- ``SlotAggregationInput``, ``ExperimentAggregationInput``
   and ``ExperimentAggregationResult``: plan 3.10's fields in order. The two
   latest-attempt fields are present together or absent together;
   ``approximation_ids`` mirror the frozen ``SlotCompatibility`` rule (non-empty
   exactly under ``SUPPORTED_WITH_APPROXIMATION``, sorted, unique); slots are
   ordered by ordinal ``0..n-1`` with unique identifiers; reason codes are sorted
   and unique. Equality of the slot set with the experiment's frozen selected
   slots is Task 8's check, because it needs the experiment.
2. **Effective terminal state** -- ``effective_terminal_state``,
   ``is_late_not_applicable`` and ``uses_approximation`` (plan 9.2): the current
   attempt's state when an attempt exists and is terminal; otherwise, with no
   attempt, ``NOT_APPLICABLE`` or ``UNAVAILABLE`` from the frozen outcome, and
   unresolved (``MISSING``) when the frozen outcome is ``SUPPORTED`` or
   ``SUPPORTED_WITH_APPROXIMATION`` -- such a slot has work outstanding. A
   zero-attempt ``UNAVAILABLE`` slot has no retry decision to wait for; a refresh
   is expressed by creating an attempt, after which the attempt governs.
3. **Reason codes** -- the eight constants, ``slot_reason_code`` and
   ``slot_reason_codes`` (plan 8.6): aggregation reason codes label
   ``ExperimentAggregationResult.reason_codes`` and never inhabit a
   ``Diagnostic``, so they carry no category. ``EXPERIMENT.SLOT_TIMED_OUT`` is
   deliberately not one of the four command-specific timeout codes, and the
   cancelled row uses ``EXPERIMENT.SLOT_CANCELLED`` rather than
   ``PROCESS.CANCELLED``: an aggregation reason names which slot outcome
   contributed, not which deadline fired.
4. **The classifier** -- ``classify_experiment_outcome`` (plan 9.3): eight rows,
   evaluated top to bottom, first match wins; pure and total over the declared
   input alone. No averaging, majority voting or synthetic return exists here.

Where the plan is silent, these task-local readings are applied and declared here
rather than inferred silently:

- ``retry_status`` must be ``NO_DECISION_REQUIRED`` unless the latest attempt's
  state maps to a ``RetryTerminalState``: plan 9.2 assigns the three other
  statuses only to a slot whose terminal state "does map", so any other slot
  carrying one is an inconsistent read set.
- ``slot_reason_code`` is the closed state-row mapping of plan 8.6 over the seven
  terminal states, with ``late_not_applicable`` meaningful only for
  ``NOT_APPLICABLE``; ``slot_reason_codes`` adds the approximation condition,
  which plan 8.6 attaches "in any state".
- The rows' reason codes are read literally. Row 4 contributes
  ``EXPERIMENT.NO_APPLICABLE_ENGINE`` plus ``COMPAT.LATE_NOT_APPLICABLE`` when any
  member of ``N`` is late, and nothing else. Row 5 contributes the state code of
  each slot effectively ``FAILED``, ``TIMED_OUT`` or ``UNAVAILABLE`` and nothing
  else: a cancelled, late or approximated slot alongside them adds no code,
  because the verdict names what failed. Row 6 contributes exactly
  ``EXPERIMENT.SLOT_CANCELLED``. Row 8 contributes the union over every slot of
  its state-row code, its approximation code and its late code.
- Beyond plan 12's produced list, the helpers ``is_late_not_applicable``,
  ``uses_approximation`` and ``slot_reason_codes``, the eight reason-code constants
  and ``AGGREGATION_REASON_CODES`` are exported for Task 8's ``build_aggregation_input``
  and its tests, so the derivations are not re-expressed there.

Absence is ``MISSING``, never ``None`` (plan section 3.1).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final, Literal, Self

from pydantic import Field, field_validator, model_validator
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.compatibility import CompatibilityOutcome
from crypto_lab.domain.diagnostics import ErrorCode
from crypto_lab.domain.engine_run import SUCCESS_ENGINE_RUN_STATES
from crypto_lab.domain.experiment import (
    MAX_APPROXIMATION_IDS,
    MAX_SELECTED_ENGINE_SLOTS,
    MAX_SLOT_ORDINAL,
)
from crypto_lab.domain.identifiers import (
    ApproximationId,
    ExperimentId,
    LogicalSlotId,
    RunId,
    Sha256,
)
from crypto_lab.domain.lifecycle import TERMINAL_ENGINE_RUN_STATES, EngineRunState
from crypto_lab.domain.retry import retry_terminal_state_of

_R: Final = EngineRunState
_C: Final = CompatibilityOutcome

MAX_AGGREGATION_REASON_CODES: Final = 32

#: Plan section 8.6: the closed aggregation reason codes.
REASON_SLOT_FAILED: Final = "EXPERIMENT.SLOT_FAILED"
REASON_SLOT_TIMED_OUT: Final = "EXPERIMENT.SLOT_TIMED_OUT"
REASON_SLOT_UNAVAILABLE: Final = "EXPERIMENT.SLOT_UNAVAILABLE"
REASON_SLOT_CANCELLED: Final = "EXPERIMENT.SLOT_CANCELLED"
REASON_SLOT_SUCCEEDED_WITH_WARNINGS: Final = "EXPERIMENT.SLOT_SUCCEEDED_WITH_WARNINGS"
REASON_LATE_NOT_APPLICABLE: Final = "COMPAT.LATE_NOT_APPLICABLE"
REASON_SLOT_USED_APPROXIMATION: Final = "EXPERIMENT.SLOT_USED_APPROXIMATION"
REASON_NO_APPLICABLE_ENGINE: Final = "EXPERIMENT.NO_APPLICABLE_ENGINE"
AGGREGATION_REASON_CODES: Final[frozenset[str]] = frozenset(
    {
        REASON_SLOT_FAILED,
        REASON_SLOT_TIMED_OUT,
        REASON_SLOT_UNAVAILABLE,
        REASON_SLOT_CANCELLED,
        REASON_SLOT_SUCCEEDED_WITH_WARNINGS,
        REASON_LATE_NOT_APPLICABLE,
        REASON_SLOT_USED_APPROXIMATION,
        REASON_NO_APPLICABLE_ENGINE,
    }
)

#: Plan section 8.6: the state rows that contribute a code. ``SUCCEEDED`` and an
#: expected ``NOT_APPLICABLE`` contribute none; a late ``NOT_APPLICABLE`` is the
#: condition row handled by ``slot_reason_code``.
_STATE_REASON_CODES: Final[dict[EngineRunState, str]] = {
    _R.FAILED: REASON_SLOT_FAILED,
    _R.TIMED_OUT: REASON_SLOT_TIMED_OUT,
    _R.UNAVAILABLE: REASON_SLOT_UNAVAILABLE,
    _R.CANCELLED: REASON_SLOT_CANCELLED,
    _R.SUCCEEDED_WITH_WARNINGS: REASON_SLOT_SUCCEEDED_WITH_WARNINGS,
}
#: Plan section 9.3 row 5: the three contributing failure outcomes.
_FAILURE_STATES: Final[frozenset[EngineRunState]] = frozenset(
    {_R.FAILED, _R.TIMED_OUT, _R.UNAVAILABLE}
)
#: Plan section 9.2: the frozen outcomes under which a zero-attempt slot has work
#: outstanding.
_RUNNABLE_OUTCOMES: Final[frozenset[CompatibilityOutcome]] = frozenset(
    {_C.SUPPORTED, _C.SUPPORTED_WITH_APPROXIMATION}
)


def _is_missing(value: object) -> bool:
    return value is MISSING


class SlotRetryStatus(StrEnum):
    """Plan section 9.2: the retry position of one slot's current attempt."""

    NO_DECISION_REQUIRED = "NO_DECISION_REQUIRED"
    DECISION_UNRESOLVED = "DECISION_UNRESOLVED"
    ALLOWED_SUCCESSOR_PENDING = "ALLOWED_SUCCESSOR_PENDING"
    DENIED = "DENIED"


class AggregationVerdict(StrEnum):
    """Plan section 3.10: the classifier's verdicts plus Task 8's ``CANCELLED``."""

    NOT_YET_TERMINAL = "NOT_YET_TERMINAL"
    COMPLETED = "COMPLETED"
    COMPLETED_WITH_WARNINGS = "COMPLETED_WITH_WARNINGS"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


_BLOCKING_RETRY_STATUSES: Final[frozenset[SlotRetryStatus]] = frozenset(
    {SlotRetryStatus.DECISION_UNRESOLVED, SlotRetryStatus.ALLOWED_SUCCESSOR_PENDING}
)


class SlotAggregationInput(CanonicalModel):
    """Plan section 3.10: one selected slot, whether or not it has an attempt.

    A nested value object without an envelope ``schema_version``. The first four
    fields come from the experiment's frozen ``slot_compatibility``; the latest
    attempt and the retry status come from the run and decision repositories.
    Every field is authoritative (source **A**).
    """

    logical_slot_id: LogicalSlotId
    slot_ordinal: int = Field(ge=0, le=MAX_SLOT_ORDINAL)
    compatibility_outcome: CompatibilityOutcome
    approximation_ids: tuple[ApproximationId, ...] = Field(
        max_length=MAX_APPROXIMATION_IDS,
        json_schema_extra={"uniqueItems": True},
    )
    latest_attempt_run_id: RunId | MISSING = MISSING  # type: ignore[valid-type]
    latest_attempt_state: EngineRunState | MISSING = MISSING  # type: ignore[valid-type]
    retry_status: SlotRetryStatus

    @field_validator("approximation_ids")
    @classmethod
    def validate_approximation_ids(
        cls,
        value: tuple[ApproximationId, ...],
    ) -> tuple[ApproximationId, ...]:
        if len(set(value)) != len(value):
            raise ValueError("approximation identifiers must be unique")
        if value != tuple(sorted(value)):
            raise ValueError("approximation identifiers must be sorted")
        return value

    @model_validator(mode="after")
    def validate_slot_shape(self) -> Self:
        approximated = self.compatibility_outcome is _C.SUPPORTED_WITH_APPROXIMATION
        if approximated and not self.approximation_ids:
            raise ValueError(
                "an approximated outcome requires at least one approximation identifier"
            )
        if not approximated and self.approximation_ids:
            raise ValueError(
                "approximation identifiers are carried only by "
                "SUPPORTED_WITH_APPROXIMATION"
            )
        run_present = not _is_missing(self.latest_attempt_run_id)
        state_present = not _is_missing(self.latest_attempt_state)
        if run_present and not state_present:
            raise ValueError(
                "latest_attempt_state is required when latest_attempt_run_id is present"
            )
        if state_present and not run_present:
            raise ValueError(
                "latest_attempt_run_id is required when latest_attempt_state is present"
            )
        decidable = state_present and not _is_missing(
            retry_terminal_state_of(self.latest_attempt_state)
        )
        if (
            not decidable
            and self.retry_status is not SlotRetryStatus.NO_DECISION_REQUIRED
        ):
            raise ValueError(
                "retry_status must be NO_DECISION_REQUIRED unless the latest attempt's "
                "terminal state maps to a RetryTerminalState"
            )
        return self


class ExperimentAggregationInput(CanonicalModel):
    """Plan section 3.10: every selected slot of one experiment, in slot order."""

    schema_version: Literal["1.0.0"]
    experiment_id: ExperimentId
    experiment_spec_hash: Sha256
    slots: tuple[SlotAggregationInput, ...] = Field(
        min_length=1,
        max_length=MAX_SELECTED_ENGINE_SLOTS,
        # Distinct ordinals make every accepted member distinct.
        json_schema_extra={"uniqueItems": True},
    )

    @field_validator("slots")
    @classmethod
    def validate_slots(
        cls,
        value: tuple[SlotAggregationInput, ...],
    ) -> tuple[SlotAggregationInput, ...]:
        ordinals = tuple(slot.slot_ordinal for slot in value)
        if ordinals != tuple(range(len(value))):
            raise ValueError("slot ordinals must run 0..n-1 in ascending tuple order")
        identifiers = tuple(slot.logical_slot_id for slot in value)
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("logical_slot_id must be unique across slots")
        return value


class ExperimentAggregationResult(CanonicalModel):
    """Plan section 3.10: the verdict and the sorted unique reason codes."""

    schema_version: Literal["1.0.0"]
    experiment_id: ExperimentId
    verdict: AggregationVerdict
    reason_codes: tuple[ErrorCode, ...] = Field(
        max_length=MAX_AGGREGATION_REASON_CODES,
        json_schema_extra={"uniqueItems": True},
    )

    @field_validator("reason_codes")
    @classmethod
    def validate_reason_codes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("reason codes must be unique")
        if value != tuple(sorted(value)):
            raise ValueError("reason codes must be sorted")
        return value


# --- Effective terminal state and derived facts (plan section 9.2) -------------------


def _require_slot(slot: object) -> SlotAggregationInput:
    if type(slot) is not SlotAggregationInput:
        raise TypeError("slot must be a SlotAggregationInput")
    return slot


def effective_terminal_state(
    slot: SlotAggregationInput,
) -> EngineRunState | MISSING:  # type: ignore[valid-type]
    """Plan section 9.2: the slot's effective terminal state, or ``MISSING``.

    The current attempt's state when an attempt exists and is terminal; an
    existing non-terminal attempt is unresolved. With no attempt, the frozen
    outcome decides: ``NOT_APPLICABLE`` and ``UNAVAILABLE`` are effectively
    terminal in that state, while ``SUPPORTED`` and ``SUPPORTED_WITH_APPROXIMATION``
    have work outstanding and are unresolved.
    """
    slot = _require_slot(slot)
    if not _is_missing(slot.latest_attempt_state):
        state = slot.latest_attempt_state
        return state if state in TERMINAL_ENGINE_RUN_STATES else MISSING
    if slot.compatibility_outcome is _C.NOT_APPLICABLE:
        return _R.NOT_APPLICABLE
    if slot.compatibility_outcome is _C.UNAVAILABLE:
        return _R.UNAVAILABLE
    return MISSING


def is_late_not_applicable(slot: SlotAggregationInput) -> bool:
    """Plan section 9.2: effectively ``NOT_APPLICABLE`` although preflight was not."""
    return (
        effective_terminal_state(slot) is _R.NOT_APPLICABLE
        and slot.compatibility_outcome is not _C.NOT_APPLICABLE
    )


def uses_approximation(slot: SlotAggregationInput) -> bool:
    """Plan section 9.2: derived solely from the frozen compatibility outcome."""
    return _require_slot(slot).compatibility_outcome is _C.SUPPORTED_WITH_APPROXIMATION


# --- Reason codes (plan section 8.6) --------------------------------------------------


def slot_reason_code(
    state: EngineRunState,
    *,
    late_not_applicable: bool,
) -> ErrorCode | MISSING:  # type: ignore[valid-type]
    """Plan section 8.6: the closed state-row mapping over the seven terminal states.

    ``FAILED``, ``TIMED_OUT``, ``UNAVAILABLE``, ``CANCELLED`` and
    ``SUCCEEDED_WITH_WARNINGS`` map to their slot code; ``NOT_APPLICABLE`` maps to
    ``COMPAT.LATE_NOT_APPLICABLE`` when late and to nothing otherwise;
    ``SUCCEEDED`` maps to nothing. ``late_not_applicable`` is meaningful only for
    ``NOT_APPLICABLE`` and is a ``ValueError`` elsewhere, as is a non-terminal
    state; foreign inputs raise ``TypeError``.
    """
    if type(state) is not EngineRunState:
        raise TypeError("state must be an EngineRunState member")
    if type(late_not_applicable) is not bool:
        raise TypeError("late_not_applicable must be a bool")
    if state not in TERMINAL_ENGINE_RUN_STATES:
        raise ValueError("slot_reason_code is defined over the seven terminal states")
    if state is _R.NOT_APPLICABLE:
        return REASON_LATE_NOT_APPLICABLE if late_not_applicable else MISSING
    if late_not_applicable:
        raise ValueError("late_not_applicable applies only to NOT_APPLICABLE")
    return _STATE_REASON_CODES.get(state, MISSING)


def slot_reason_codes(slot: SlotAggregationInput) -> tuple[ErrorCode, ...]:
    """Plan section 8.6 over one slot: its state-row code plus the approximation
    condition, sorted and unique. The slot must have an effective terminal state."""
    state = effective_terminal_state(slot)
    if _is_missing(state):
        raise ValueError("the slot has no effective terminal state")
    codes: set[str] = set()
    code = slot_reason_code(state, late_not_applicable=is_late_not_applicable(slot))
    if not _is_missing(code):
        codes.add(code)
    if uses_approximation(slot):
        codes.add(REASON_SLOT_USED_APPROXIMATION)
    return tuple(sorted(codes))


# --- The classifier (plan section 9.3) ------------------------------------------------


def _result(
    aggregation: ExperimentAggregationInput,
    verdict: AggregationVerdict,
    codes: set[str],
) -> ExperimentAggregationResult:
    return ExperimentAggregationResult(
        schema_version="1.0.0",
        experiment_id=aggregation.experiment_id,
        verdict=verdict,
        reason_codes=tuple(sorted(codes)),
    )


def classify_experiment_outcome(
    aggregation: ExperimentAggregationInput,
) -> ExperimentAggregationResult:
    """Plan section 9.3: the deterministic aggregation table, first match wins.

    Let ``S`` be the slots effectively ``SUCCEEDED`` or ``SUCCEEDED_WITH_WARNINGS``
    and ``N`` those effectively ``NOT_APPLICABLE``. Rows 1-3 return
    ``NOT_YET_TERMINAL`` while any slot has a non-terminal current attempt, has no
    attempt under a runnable frozen outcome, or holds an unresolved or pending
    retry decision. Row 4: ``N`` is every slot -> ``FAILED`` with
    ``EXPERIMENT.NO_APPLICABLE_ENGINE`` plus the late code when any member is late.
    Row 5: ``S`` empty and some slot failed, timed out or was unavailable ->
    ``FAILED`` with those slots' codes. Row 6: ``S`` empty and some slot cancelled
    -> ``FAILED`` with ``EXPERIMENT.SLOT_CANCELLED``. Row 7: every member of ``S``
    is ``SUCCEEDED``, no slot used an approximation, no member of ``N`` is late and
    no other slot exists -> ``COMPLETED``. Row 8: otherwise ->
    ``COMPLETED_WITH_WARNINGS`` with every contributing slot's and condition's code.
    A ``DENIED`` decision lets its terminal predecessor contribute through rows 4-8.
    Pure and total over the declared input; never emits ``CANCELLED``.
    """
    if type(aggregation) is not ExperimentAggregationInput:
        raise TypeError("aggregation must be an ExperimentAggregationInput")
    slots = aggregation.slots
    not_yet = AggregationVerdict.NOT_YET_TERMINAL
    # Row 1: a non-terminal current attempt.
    for slot in slots:
        if (
            not _is_missing(slot.latest_attempt_state)
            and slot.latest_attempt_state not in TERMINAL_ENGINE_RUN_STATES
        ):
            return _result(aggregation, not_yet, set())
    # Row 2: no attempt under a runnable frozen outcome.
    for slot in slots:
        if (
            _is_missing(slot.latest_attempt_state)
            and slot.compatibility_outcome in _RUNNABLE_OUTCOMES
        ):
            return _result(aggregation, not_yet, set())
    # Row 3: an unresolved or pending retry decision.
    for slot in slots:
        if slot.retry_status in _BLOCKING_RETRY_STATUSES:
            return _result(aggregation, not_yet, set())
    # Every slot now has an effective terminal state.
    states = tuple((slot, effective_terminal_state(slot)) for slot in slots)
    successes = tuple(
        slot for slot, state in states if state in SUCCESS_ENGINE_RUN_STATES
    )
    not_applicable = tuple(slot for slot, state in states if state is _R.NOT_APPLICABLE)
    failed = AggregationVerdict.FAILED
    # Row 4: no applicable engine.
    if len(not_applicable) == len(slots):
        codes = {REASON_NO_APPLICABLE_ENGINE}
        if any(is_late_not_applicable(slot) for slot in not_applicable):
            codes.add(REASON_LATE_NOT_APPLICABLE)
        return _result(aggregation, failed, codes)
    # Row 5: nothing succeeded and something failed, timed out or was unavailable.
    failure_codes = {
        _STATE_REASON_CODES[state] for _, state in states if state in _FAILURE_STATES
    }
    if not successes and failure_codes:
        return _result(aggregation, failed, failure_codes)
    # Row 6: nothing succeeded and a child attempt was cancelled.
    if not successes and any(state is _R.CANCELLED for _, state in states):
        return _result(aggregation, failed, {REASON_SLOT_CANCELLED})
    # Row 7: clean completion.
    clean = (
        bool(successes)
        and all(state is _R.SUCCEEDED for slot, state in states if slot in successes)
        and not any(uses_approximation(slot) for slot in slots)
        and not any(is_late_not_applicable(slot) for slot in not_applicable)
        and len(successes) + len(not_applicable) == len(slots)
    )
    if clean:
        return _result(aggregation, AggregationVerdict.COMPLETED, set())
    # Row 8: completed with warnings.
    warning_codes: set[str] = set()
    for slot in slots:
        warning_codes.update(slot_reason_codes(slot))
    return _result(
        aggregation, AggregationVerdict.COMPLETED_WITH_WARNINGS, warning_codes
    )
