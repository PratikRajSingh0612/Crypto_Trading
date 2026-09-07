"""Stage 5 Task 5: the aggregation records, the effective-terminal-state derivation,
the closed slot reason-code mapping and the pure deterministic classifier.

Every rule below is transcribed from Stage 5 plan sections 3.10 (the aggregation
records), 8.6 (the aggregation reason codes, which never inhabit a ``Diagnostic``),
9.2 (selected slots, effective terminal state, readiness) and 9.3 (the eight-row
aggregation table, first match wins), under specification section 16.3. The
classifier is pure and total over the declared input alone: the stored experiment
state is not an input, and ``CANCELLED`` exists as a verdict member only so that
Task 8's idempotent already-terminal path can express it (plan 3.10).

The conventions of the merged tree apply: an absent state-governed field is
``MISSING``, never ``None``, and is asserted absent from **both** dump modes; a
record is never mutated through ``model_copy`` but rebuilt through
``model_validate`` so a rejection is real.
"""

from __future__ import annotations

import ast
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Final

import pytest
from pydantic import TypeAdapter, ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab import domain as domain_package
from crypto_lab.domain import aggregation as aggregation_module
from crypto_lab.domain.aggregation import (
    AGGREGATION_REASON_CODES,
    MAX_AGGREGATION_REASON_CODES,
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
    classify_experiment_outcome,
    effective_terminal_state,
    is_late_not_applicable,
    slot_reason_code,
    slot_reason_codes,
    uses_approximation,
)
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.compatibility import CompatibilityOutcome
from crypto_lab.domain.diagnostics import ErrorCode
from crypto_lab.domain.experiment import MAX_SELECTED_ENGINE_SLOTS
from crypto_lab.domain.lifecycle import (
    TERMINAL_ENGINE_RUN_STATES,
    EngineRunState,
)

_R = EngineRunState
_C = CompatibilityOutcome
_S = SlotRetryStatus
_V = AggregationVerdict

# Lowercase canonical UUID4 text: version nibble 4, variant nibble in [89ab].
_UUIDS = (
    "12345678-1234-4234-8234-123456789abc",
    "9f8e7d6c-5b4a-4321-8fed-cba987654321",
    "0a1b2c3d-4e5f-4a6b-9c7d-8e9f0a1b2c3d",
    "5e5e5e5e-1111-4222-8333-444455556666",
    "7a7a7a7a-2222-4333-9444-555566667777",
    "8b8b8b8b-3333-4444-a555-666677778888",
    "1c1c1c1c-4444-4555-b666-777788889999",
    "2d2d2d2d-5555-4666-8777-88889999aaaa",
    "3e3e3e3e-6666-4777-9888-9999aaaabbbb",
)
_SLOT_IDS = tuple(f"slot_{uuid}" for uuid in _UUIDS)
_RUN_IDS = tuple(f"run_{uuid}" for uuid in _UUIDS)
_EXPERIMENT_ID = f"exp_{_UUIDS[0]}"
_OTHER_EXPERIMENT_ID = f"exp_{_UUIDS[1]}"
# Sorted: "appx_0a..." < "appx_12...".
_APPX_LOW = f"appx_{_UUIDS[2]}"
_APPX_HIGH = f"appx_{_UUIDS[0]}"
_SPEC_HASH = "a" * 64

_SLOT_FIELDS = (
    "logical_slot_id",
    "slot_ordinal",
    "compatibility_outcome",
    "approximation_ids",
    "latest_attempt_run_id",
    "latest_attempt_state",
    "retry_status",
)
_INPUT_FIELDS = ("schema_version", "experiment_id", "experiment_spec_hash", "slots")
_RESULT_FIELDS = ("schema_version", "experiment_id", "verdict", "reason_codes")

_ALL_STATES = tuple(EngineRunState)
_NON_TERMINAL_STATES = (_R.PENDING, _R.VALIDATING, _R.READY, _R.STARTING, _R.RUNNING)
_SUCCESS_STATES = (_R.SUCCEEDED, _R.SUCCEEDED_WITH_WARNINGS)
_RETRYABLE_STATES = (_R.FAILED, _R.TIMED_OUT, _R.UNAVAILABLE)
_UNMAPPED_TERMINAL_STATES = (_R.CANCELLED, _R.NOT_APPLICABLE)
_TERMINAL_STATES = _SUCCESS_STATES + _RETRYABLE_STATES + _UNMAPPED_TERMINAL_STATES
_OUTCOMES = tuple(CompatibilityOutcome)
_RUNNABLE_OUTCOMES = (_C.SUPPORTED, _C.SUPPORTED_WITH_APPROXIMATION)
_STATE_CODE = {
    _R.FAILED: REASON_SLOT_FAILED,
    _R.TIMED_OUT: REASON_SLOT_TIMED_OUT,
    _R.UNAVAILABLE: REASON_SLOT_UNAVAILABLE,
    _R.CANCELLED: REASON_SLOT_CANCELLED,
    _R.SUCCEEDED_WITH_WARNINGS: REASON_SLOT_SUCCEEDED_WITH_WARNINGS,
}

_ABSENT: Final = object()
_ERROR_CODE: Final[TypeAdapter[str]] = TypeAdapter(ErrorCode)


# --- Fixture factories -------------------------------------------------------------


def _apply(payload: dict[str, object], overrides: dict[str, object]) -> None:
    for name, value in overrides.items():
        if value is _ABSENT:
            payload.pop(name, None)
        else:
            payload[name] = value


def _missing(value: object) -> bool:
    """Identity against the sentinel, typed over ``object`` for strict mypy."""
    return value is MISSING


def _slot(
    ordinal: int = 0,
    /,
    *,
    outcome: CompatibilityOutcome = _C.SUPPORTED,
    attempt: EngineRunState | None = None,
    retry_status: SlotRetryStatus = _S.NO_DECISION_REQUIRED,
    **overrides: object,
) -> SlotAggregationInput:
    """One selected slot; ``attempt`` adds a current attempt in that state."""
    payload: dict[str, object] = {
        "logical_slot_id": _SLOT_IDS[ordinal],
        "slot_ordinal": ordinal,
        "compatibility_outcome": outcome,
        "approximation_ids": (
            (_APPX_LOW,) if outcome is _C.SUPPORTED_WITH_APPROXIMATION else ()
        ),
        "retry_status": retry_status,
    }
    if attempt is not None:
        payload["latest_attempt_run_id"] = _RUN_IDS[ordinal]
        payload["latest_attempt_state"] = attempt
    _apply(payload, overrides)
    return SlotAggregationInput.model_validate(payload)


def _input(
    *slots: SlotAggregationInput, **overrides: object
) -> ExperimentAggregationInput:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "experiment_id": _EXPERIMENT_ID,
        "experiment_spec_hash": _SPEC_HASH,
        "slots": slots if slots else (_slot(attempt=_R.SUCCEEDED),),
    }
    _apply(payload, overrides)
    return ExperimentAggregationInput.model_validate(payload)


def _result(**overrides: object) -> ExperimentAggregationResult:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "experiment_id": _EXPERIMENT_ID,
        "verdict": _V.COMPLETED,
        "reason_codes": (),
    }
    _apply(payload, overrides)
    return ExperimentAggregationResult.model_validate(payload)


def _classify(*slots: SlotAggregationInput) -> ExperimentAggregationResult:
    return classify_experiment_outcome(_input(*slots))


def _succeeded(ordinal: int) -> SlotAggregationInput:
    return _slot(ordinal, attempt=_R.SUCCEEDED)


def _expected_not_applicable(ordinal: int) -> SlotAggregationInput:
    """Preflight predicted NOT_APPLICABLE and the slot never ran."""
    return _slot(ordinal, outcome=_C.NOT_APPLICABLE)


def _late_not_applicable(ordinal: int) -> SlotAggregationInput:
    """Preflight said SUPPORTED but the attempt discovered NOT_APPLICABLE."""
    return _slot(ordinal, attempt=_R.NOT_APPLICABLE)


def _every_instance() -> tuple[CanonicalModel, ...]:
    return (
        _slot(),
        _slot(attempt=_R.FAILED, retry_status=_S.DENIED),
        _input(),
        _result(),
    )


def _module_source(module: ModuleType) -> str:
    assert module.__file__ is not None
    return Path(module.__file__).read_text(encoding="utf-8")


# --- Shared conventions (plan section 3.1) ---------------------------------------


@pytest.mark.parametrize("instance", _every_instance(), ids=lambda m: type(m).__name__)
def test_every_aggregation_model_rejects_an_unknown_field(
    instance: CanonicalModel,
) -> None:
    payload = instance.model_dump(mode="python")
    payload["unexpected"] = "value"
    with pytest.raises(ValidationError, match="extra_forbidden"):
        type(instance).model_validate(payload)


@pytest.mark.parametrize("instance", _every_instance(), ids=lambda m: type(m).__name__)
def test_every_aggregation_model_is_frozen(instance: CanonicalModel) -> None:
    first = next(iter(type(instance).model_fields))
    with pytest.raises(ValidationError, match="frozen_instance"):
        setattr(instance, first, getattr(instance, first))


def test_every_aggregation_model_derives_from_the_canonical_base() -> None:
    """Preventive against the committed base: the configuration is inherited."""
    for model in (
        SlotAggregationInput,
        ExperimentAggregationInput,
        ExperimentAggregationResult,
    ):
        assert issubclass(model, CanonicalModel)
        assert model.model_config["extra"] == "forbid"
        assert model.model_config["frozen"] is True
        assert model.model_config["strict"] is True


def test_nested_slots_are_immutable_through_the_input() -> None:
    aggregate = _input(_slot(attempt=_R.SUCCEEDED))
    with pytest.raises(ValidationError, match="frozen_instance"):
        aggregate.slots[0].retry_status = _S.DENIED
    assert isinstance(aggregate.slots, tuple)
    assert isinstance(_result().reason_codes, tuple)


def test_strict_mode_refuses_coercion() -> None:
    cases: tuple[tuple[Callable[..., object], str, object], ...] = (
        (_slot, "slot_ordinal", "0"),
        (_slot, "slot_ordinal", True),
        (_slot, "slot_ordinal", 0.0),
        (_slot, "compatibility_outcome", "SUPPORTED"),
        (_slot, "retry_status", "DENIED"),
        (_result, "verdict", "COMPLETED"),
        (_result, "reason_codes", [REASON_SLOT_FAILED]),
    )
    for build, field, value in cases:
        with pytest.raises(ValidationError):
            build(**{field: value})


@pytest.mark.parametrize("field", ["latest_attempt_run_id", "latest_attempt_state"])
def test_absent_attempt_fields_are_omitted_from_both_dump_modes_and_null_is_rejected(
    field: str,
) -> None:
    slot = _slot()
    assert _missing(getattr(slot, field))
    assert field not in slot.model_dump(mode="json")
    assert field not in slot.model_dump(mode="python")
    payload = slot.model_dump(mode="python")
    payload[field] = None
    with pytest.raises(ValidationError):
        SlotAggregationInput.model_validate(payload)


# --- Vocabularies and reason codes (plan sections 3.10 and 8.6) ----------------------


def test_the_slot_retry_status_vocabulary_is_exactly_the_four_plan_members() -> None:
    assert [m.value for m in SlotRetryStatus] == [
        "NO_DECISION_REQUIRED",
        "DECISION_UNRESOLVED",
        "ALLOWED_SUCCESSOR_PENDING",
        "DENIED",
    ]


def test_the_verdict_vocabulary_is_exactly_the_five_plan_members() -> None:
    assert [m.value for m in AggregationVerdict] == [
        "NOT_YET_TERMINAL",
        "COMPLETED",
        "COMPLETED_WITH_WARNINGS",
        "FAILED",
        "CANCELLED",
    ]


def test_the_eight_reason_codes_are_the_plan_values_and_valid_error_codes() -> None:
    expected = {
        REASON_SLOT_FAILED: "EXPERIMENT.SLOT_FAILED",
        REASON_SLOT_TIMED_OUT: "EXPERIMENT.SLOT_TIMED_OUT",
        REASON_SLOT_UNAVAILABLE: "EXPERIMENT.SLOT_UNAVAILABLE",
        REASON_SLOT_CANCELLED: "EXPERIMENT.SLOT_CANCELLED",
        REASON_SLOT_SUCCEEDED_WITH_WARNINGS: "EXPERIMENT.SLOT_SUCCEEDED_WITH_WARNINGS",
        REASON_LATE_NOT_APPLICABLE: "COMPAT.LATE_NOT_APPLICABLE",
        REASON_SLOT_USED_APPROXIMATION: "EXPERIMENT.SLOT_USED_APPROXIMATION",
        REASON_NO_APPLICABLE_ENGINE: "EXPERIMENT.NO_APPLICABLE_ENGINE",
    }
    for constant, value in expected.items():
        assert constant == value
        assert _ERROR_CODE.validate_python(constant) == value
    assert AGGREGATION_REASON_CODES == frozenset(expected.values())
    assert len(AGGREGATION_REASON_CODES) == 8
    assert MAX_AGGREGATION_REASON_CODES == 32


def test_the_timeout_and_cancelled_codes_are_not_the_process_codes() -> None:
    """Plan 8.6: an aggregation reason names which slot outcome contributed, never
    which deadline fired or that a process was cancelled."""
    assert REASON_SLOT_TIMED_OUT not in {
        "PROCESS.DESCRIBE_TIMED_OUT",
        "PROCESS.VALIDATE_TIMED_OUT",
        "PROCESS.START_TIMED_OUT",
        "PROCESS.RUN_TIMED_OUT",
    }
    assert "PROCESS.CANCELLED" not in AGGREGATION_REASON_CODES
    assert all(
        code.startswith(("EXPERIMENT.", "COMPAT.")) for code in AGGREGATION_REASON_CODES
    )


# --- SlotAggregationInput shape (plan section 3.10) ----------------------------------


def test_the_slot_input_declares_the_seven_fields_in_order_without_envelope() -> None:
    assert tuple(SlotAggregationInput.model_fields) == _SLOT_FIELDS
    assert "schema_version" not in SlotAggregationInput.model_fields
    optional = tuple(
        name
        for name, field in SlotAggregationInput.model_fields.items()
        if not field.is_required()
    )
    assert optional == ("latest_attempt_run_id", "latest_attempt_state")
    for name in optional:
        assert SlotAggregationInput.model_fields[name].default is MISSING


def test_a_slot_with_exactly_one_latest_attempt_field_is_rejected() -> None:
    with pytest.raises(ValidationError, match="latest_attempt_state"):
        _slot(latest_attempt_run_id=_RUN_IDS[0])
    with pytest.raises(ValidationError, match="latest_attempt_run_id"):
        _slot(latest_attempt_state=_R.SUCCEEDED)
    assert _missing(_slot().latest_attempt_run_id)
    both = _slot(attempt=_R.SUCCEEDED)
    assert both.latest_attempt_run_id == _RUN_IDS[0]
    assert both.latest_attempt_state is _R.SUCCEEDED


@pytest.mark.parametrize("state", _ALL_STATES)
def test_every_engine_run_state_is_an_accepted_latest_attempt_state(
    state: EngineRunState,
) -> None:
    assert _slot(attempt=state).latest_attempt_state is state


def test_slot_ordinal_is_bounded_zero_through_seven() -> None:
    assert _slot(7).slot_ordinal == 7
    with pytest.raises(ValidationError, match="less_than_equal"):
        _slot(8)
    with pytest.raises(ValidationError, match="greater_than_equal"):
        _slot(slot_ordinal=-1)


def test_approximation_ids_are_present_exactly_under_the_approximated_outcome() -> None:
    assert _slot(outcome=_C.SUPPORTED_WITH_APPROXIMATION).approximation_ids == (
        _APPX_LOW,
    )
    with pytest.raises(ValidationError, match="approximation"):
        _slot(outcome=_C.SUPPORTED_WITH_APPROXIMATION, approximation_ids=())
    for outcome in (_C.SUPPORTED, _C.NOT_APPLICABLE, _C.UNAVAILABLE):
        with pytest.raises(ValidationError, match="approximation"):
            _slot(outcome=outcome, approximation_ids=(_APPX_LOW,))


def test_approximation_ids_are_sorted_unique_and_bounded() -> None:
    approximated = _C.SUPPORTED_WITH_APPROXIMATION
    with pytest.raises(ValidationError, match="unique"):
        _slot(outcome=approximated, approximation_ids=(_APPX_LOW, _APPX_LOW))
    with pytest.raises(ValidationError, match="sorted"):
        _slot(outcome=approximated, approximation_ids=(_APPX_HIGH, _APPX_LOW))
    accepted = _slot(outcome=approximated, approximation_ids=(_APPX_LOW, _APPX_HIGH))
    assert accepted.approximation_ids == (_APPX_LOW, _APPX_HIGH)
    with pytest.raises(ValidationError, match="appx_"):
        _slot(outcome=approximated, approximation_ids=(_SLOT_IDS[0],))


@pytest.mark.parametrize(
    "attempt",
    [None, *_NON_TERMINAL_STATES, *_SUCCESS_STATES, *_UNMAPPED_TERMINAL_STATES],
)
def test_retry_status_is_no_decision_required_unless_the_state_maps_to_a_retry_state(
    attempt: EngineRunState | None,
) -> None:
    """Plan 9.2: a decision exists only for a terminal state that maps to a
    ``RetryTerminalState``; every other slot is ``NO_DECISION_REQUIRED``."""
    assert _slot(attempt=attempt).retry_status is _S.NO_DECISION_REQUIRED
    for status in (_S.DECISION_UNRESOLVED, _S.ALLOWED_SUCCESSOR_PENDING, _S.DENIED):
        with pytest.raises(ValidationError, match="NO_DECISION_REQUIRED"):
            _slot(attempt=attempt, retry_status=status)


@pytest.mark.parametrize("attempt", _RETRYABLE_STATES)
@pytest.mark.parametrize("status", list(SlotRetryStatus))
def test_every_retry_status_is_accepted_on_a_retryable_terminal_attempt(
    attempt: EngineRunState, status: SlotRetryStatus
) -> None:
    assert _slot(attempt=attempt, retry_status=status).retry_status is status


def test_a_zero_attempt_unavailable_slot_has_no_decision_to_wait_for() -> None:
    """Plan 9.2: a refresh is expressed by creating an attempt, after which the
    attempt governs; the zero-attempt slot itself never carries a decision."""
    slot = _slot(outcome=_C.UNAVAILABLE)
    assert slot.retry_status is _S.NO_DECISION_REQUIRED
    with pytest.raises(ValidationError, match="NO_DECISION_REQUIRED"):
        _slot(outcome=_C.UNAVAILABLE, retry_status=_S.DECISION_UNRESOLVED)


def test_slot_identity_fields_are_prefixed_uuid4_identifiers() -> None:
    with pytest.raises(ValidationError, match="slot_"):
        _slot(logical_slot_id=_RUN_IDS[0])
    with pytest.raises(ValidationError, match="run_"):
        _slot(attempt=_R.SUCCEEDED, latest_attempt_run_id=_SLOT_IDS[0])


# --- ExperimentAggregationInput and Result shapes (plan section 3.10) --------------


def test_the_aggregation_input_declares_exactly_the_four_fields_in_order() -> None:
    assert tuple(ExperimentAggregationInput.model_fields) == _INPUT_FIELDS
    assert all(
        f.is_required() for f in ExperimentAggregationInput.model_fields.values()
    )


def test_the_aggregation_result_declares_exactly_the_four_fields_in_order() -> None:
    assert tuple(ExperimentAggregationResult.model_fields) == _RESULT_FIELDS
    assert all(
        f.is_required() for f in ExperimentAggregationResult.model_fields.values()
    )


def test_the_slots_are_bounded_one_through_eight() -> None:
    assert MAX_SELECTED_ENGINE_SLOTS == 8
    with pytest.raises(ValidationError, match="too_short"):
        _input(slots=())
    eight = tuple(_succeeded(ordinal) for ordinal in range(8))
    assert len(_input(*eight).slots) == 8
    with pytest.raises(ValidationError, match="too_long"):
        _input(slots=(*eight, eight[0]))


def test_the_slots_run_zero_through_n_minus_one_in_ascending_tuple_order() -> None:
    with pytest.raises(ValidationError, match="ordinal"):
        _input(_succeeded(1))
    with pytest.raises(ValidationError, match="ordinal"):
        _input(_succeeded(1), _succeeded(0))
    with pytest.raises(ValidationError, match="ordinal"):
        _input(_succeeded(0), _succeeded(2))
    with pytest.raises(ValidationError, match="ordinal"):
        _input(
            _succeeded(0), _slot(0, logical_slot_id=_SLOT_IDS[1], attempt=_R.SUCCEEDED)
        )
    assert [s.slot_ordinal for s in _input(*map(_succeeded, range(3))).slots] == [
        0,
        1,
        2,
    ]


def test_the_slot_identifiers_are_unique_across_the_input() -> None:
    duplicate = _slot(1, logical_slot_id=_SLOT_IDS[0], attempt=_R.SUCCEEDED)
    with pytest.raises(ValidationError, match="logical_slot_id"):
        _input(_succeeded(0), duplicate)


def test_the_reason_codes_are_sorted_unique_bounded_error_codes() -> None:
    with pytest.raises(ValidationError, match="unique"):
        _result(reason_codes=(REASON_SLOT_FAILED, REASON_SLOT_FAILED))
    with pytest.raises(ValidationError, match="sorted"):
        _result(reason_codes=(REASON_SLOT_TIMED_OUT, REASON_SLOT_FAILED))
    with pytest.raises(ValidationError, match="pattern"):
        _result(reason_codes=("slot failed",))
    accepted = _result(reason_codes=(REASON_SLOT_FAILED, REASON_SLOT_TIMED_OUT))
    assert accepted.reason_codes == (REASON_SLOT_FAILED, REASON_SLOT_TIMED_OUT)
    too_many = tuple(sorted(f"PROBE.CODE_{index:03d}" for index in range(33)))
    with pytest.raises(ValidationError, match="too_long"):
        _result(reason_codes=too_many)


def test_the_result_publishes_unique_items_for_its_reason_codes() -> None:
    schema = ExperimentAggregationResult.model_json_schema()
    assert schema["properties"]["reason_codes"]["uniqueItems"] is True
    assert (
        schema["properties"]["reason_codes"]["maxItems"] == MAX_AGGREGATION_REASON_CODES
    )


def test_input_and_result_identity_fields_are_validated() -> None:
    with pytest.raises(ValidationError, match="exp_"):
        _input(experiment_id=_SLOT_IDS[0])
    with pytest.raises(ValidationError, match="pattern"):
        _input(experiment_spec_hash="Z" * 64)
    with pytest.raises(ValidationError, match="exp_"):
        _result(experiment_id=_SLOT_IDS[0])


def test_every_model_round_trips_through_json_deterministically() -> None:
    for instance in _every_instance():
        again = type(instance).model_validate_json(instance.model_dump_json())
        assert again == instance
        assert canonical_json_bytes(again) == canonical_json_bytes(instance)


# --- Effective terminal state and derived facts (plan section 9.2) -------------------


@pytest.mark.parametrize("outcome", _OUTCOMES)
@pytest.mark.parametrize("attempt", [None, *_ALL_STATES])
def test_the_effective_terminal_state_over_every_outcome_and_attempt_combination(
    outcome: CompatibilityOutcome, attempt: EngineRunState | None
) -> None:
    slot = _slot(outcome=outcome, attempt=attempt)
    effective = effective_terminal_state(slot)
    if attempt is None:
        if outcome is _C.NOT_APPLICABLE:
            assert effective is _R.NOT_APPLICABLE
        elif outcome is _C.UNAVAILABLE:
            assert effective is _R.UNAVAILABLE
        else:
            assert _missing(effective)
    elif attempt in TERMINAL_ENGINE_RUN_STATES:
        assert effective is attempt
    else:
        assert _missing(effective)


def test_the_three_zero_attempt_cases_come_from_the_frozen_outcome_alone() -> None:
    assert (
        effective_terminal_state(_slot(outcome=_C.NOT_APPLICABLE)) is _R.NOT_APPLICABLE
    )
    assert effective_terminal_state(_slot(outcome=_C.UNAVAILABLE)) is _R.UNAVAILABLE
    assert _missing(effective_terminal_state(_slot(outcome=_C.SUPPORTED)))
    assert _missing(
        effective_terminal_state(_slot(outcome=_C.SUPPORTED_WITH_APPROXIMATION))
    )


def test_the_attempt_governs_once_it_exists_whatever_preflight_predicted() -> None:
    """A zero-attempt UNAVAILABLE slot refreshed by an attempt follows the attempt."""
    refreshed = _slot(outcome=_C.UNAVAILABLE, attempt=_R.SUCCEEDED)
    assert effective_terminal_state(refreshed) is _R.SUCCEEDED
    pending = _slot(outcome=_C.UNAVAILABLE, attempt=_R.PENDING)
    assert _missing(effective_terminal_state(pending))


def test_late_not_applicable_is_an_unpredicted_not_applicable_terminal() -> None:
    for outcome in (_C.SUPPORTED, _C.SUPPORTED_WITH_APPROXIMATION, _C.UNAVAILABLE):
        assert is_late_not_applicable(_slot(outcome=outcome, attempt=_R.NOT_APPLICABLE))
    assert not is_late_not_applicable(
        _slot(outcome=_C.NOT_APPLICABLE, attempt=_R.NOT_APPLICABLE)
    )
    assert not is_late_not_applicable(_slot(outcome=_C.NOT_APPLICABLE))
    for state in _ALL_STATES:
        if state is not _R.NOT_APPLICABLE:
            assert not is_late_not_applicable(_slot(attempt=state))
    assert not is_late_not_applicable(_slot())


def test_used_approximation_is_derived_solely_from_the_frozen_outcome() -> None:
    assert uses_approximation(_slot(outcome=_C.SUPPORTED_WITH_APPROXIMATION))
    assert uses_approximation(
        _slot(outcome=_C.SUPPORTED_WITH_APPROXIMATION, attempt=_R.FAILED)
    )
    for outcome in (_C.SUPPORTED, _C.NOT_APPLICABLE, _C.UNAVAILABLE):
        assert not uses_approximation(_slot(outcome=outcome))


def test_the_derivations_refuse_a_foreign_slot() -> None:
    for function in (
        effective_terminal_state,
        is_late_not_applicable,
        uses_approximation,
    ):
        with pytest.raises(TypeError, match="SlotAggregationInput"):
            function(_input())  # type: ignore[arg-type]


# --- slot_reason_code (plan section 8.6) ----------------------------------------------


@pytest.mark.parametrize("state", _TERMINAL_STATES)
def test_the_state_row_mapping_is_total_over_the_seven_terminal_states(
    state: EngineRunState,
) -> None:
    code = slot_reason_code(state, late_not_applicable=False)
    if state in _STATE_CODE:
        assert code == _STATE_CODE[state]
    else:
        assert state in (_R.SUCCEEDED, _R.NOT_APPLICABLE)
        assert _missing(code)


def test_not_applicable_contributes_the_late_code_exactly_when_late() -> None:
    assert slot_reason_code(_R.NOT_APPLICABLE, late_not_applicable=True) == (
        REASON_LATE_NOT_APPLICABLE
    )
    assert _missing(slot_reason_code(_R.NOT_APPLICABLE, late_not_applicable=False))


@pytest.mark.parametrize(
    "state", tuple(s for s in _TERMINAL_STATES if s is not _R.NOT_APPLICABLE)
)
def test_the_late_flag_is_only_meaningful_for_not_applicable(
    state: EngineRunState,
) -> None:
    with pytest.raises(ValueError, match="late_not_applicable"):
        slot_reason_code(state, late_not_applicable=True)


@pytest.mark.parametrize("state", _NON_TERMINAL_STATES)
def test_a_non_terminal_state_has_no_reason_code(state: EngineRunState) -> None:
    with pytest.raises(ValueError, match="terminal"):
        slot_reason_code(state, late_not_applicable=False)


def test_the_state_row_mapping_refuses_a_foreign_member() -> None:
    with pytest.raises(TypeError, match="EngineRunState"):
        slot_reason_code("FAILED", late_not_applicable=False)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="bool"):
        slot_reason_code(_R.NOT_APPLICABLE, late_not_applicable=1)  # type: ignore[arg-type]


def test_slot_reason_codes_add_the_approximation_condition_in_any_state() -> None:
    approximated = _C.SUPPORTED_WITH_APPROXIMATION
    assert slot_reason_codes(_slot(outcome=approximated, attempt=_R.SUCCEEDED)) == (
        REASON_SLOT_USED_APPROXIMATION,
    )
    assert slot_reason_codes(_slot(outcome=approximated, attempt=_R.FAILED)) == (
        REASON_SLOT_FAILED,
        REASON_SLOT_USED_APPROXIMATION,
    )
    assert slot_reason_codes(
        _slot(outcome=approximated, attempt=_R.NOT_APPLICABLE)
    ) == (
        REASON_LATE_NOT_APPLICABLE,
        REASON_SLOT_USED_APPROXIMATION,
    )
    assert slot_reason_codes(_succeeded(0)) == ()
    assert slot_reason_codes(_expected_not_applicable(0)) == ()
    assert slot_reason_codes(_late_not_applicable(0)) == (REASON_LATE_NOT_APPLICABLE,)
    assert slot_reason_codes(_slot(outcome=_C.UNAVAILABLE)) == (
        REASON_SLOT_UNAVAILABLE,
    )
    for state, code in _STATE_CODE.items():
        assert slot_reason_codes(_slot(attempt=state)) == (code,)


def test_slot_reason_codes_require_an_effective_terminal_state() -> None:
    with pytest.raises(ValueError, match="effective terminal state"):
        slot_reason_codes(_slot())
    with pytest.raises(ValueError, match="effective terminal state"):
        slot_reason_codes(_slot(attempt=_R.RUNNING))


# --- The classifier (plan section 9.3) ------------------------------------------------


def _codes(result: ExperimentAggregationResult) -> tuple[str, ...]:
    return result.reason_codes


# Rows 1-3: not yet terminal


@pytest.mark.parametrize("state", _NON_TERMINAL_STATES)
def test_row_one_a_non_terminal_current_attempt_blocks_aggregation(
    state: EngineRunState,
) -> None:
    result = _classify(
        _slot(0, attempt=state), _slot(1, attempt=_R.FAILED, retry_status=_S.DENIED)
    )
    assert result.verdict is _V.NOT_YET_TERMINAL
    assert _codes(result) == ()


@pytest.mark.parametrize("outcome", _RUNNABLE_OUTCOMES)
def test_row_two_a_supported_slot_without_an_attempt_blocks_aggregation(
    outcome: CompatibilityOutcome,
) -> None:
    result = _classify(_succeeded(0), _slot(1, outcome=outcome))
    assert result.verdict is _V.NOT_YET_TERMINAL
    assert _codes(result) == ()


@pytest.mark.parametrize(
    "status", [_S.DECISION_UNRESOLVED, _S.ALLOWED_SUCCESSOR_PENDING]
)
@pytest.mark.parametrize("state", _RETRYABLE_STATES)
def test_row_three_an_unresolved_or_pending_retry_blocks_aggregation(
    status: SlotRetryStatus, state: EngineRunState
) -> None:
    result = _classify(_succeeded(0), _slot(1, attempt=state, retry_status=status))
    assert result.verdict is _V.NOT_YET_TERMINAL
    assert _codes(result) == ()


@pytest.mark.parametrize("state", _RETRYABLE_STATES)
def test_a_denied_decision_lets_the_terminal_predecessor_contribute(
    state: EngineRunState,
) -> None:
    result = _classify(_succeeded(0), _slot(1, attempt=state, retry_status=_S.DENIED))
    assert result.verdict is _V.COMPLETED_WITH_WARNINGS
    assert _codes(result) == (_STATE_CODE[state],)


def test_rows_one_two_and_three_each_block_alone_and_together() -> None:
    row_one = _slot(0, attempt=_R.RUNNING)
    row_two = _slot(1, outcome=_C.SUPPORTED)
    row_three = _slot(2, attempt=_R.FAILED, retry_status=_S.DECISION_UNRESOLVED)
    for slots in (
        (row_one,),
        (_succeeded(0), _slot(1, outcome=_C.SUPPORTED)),
        (
            _succeeded(0),
            _slot(1, attempt=_R.FAILED, retry_status=_S.DECISION_UNRESOLVED),
        ),
        (row_one, row_two, row_three),
    ):
        result = _classify(*slots)
        assert result.verdict is _V.NOT_YET_TERMINAL
        assert _codes(result) == ()


def test_the_blocking_rows_outrank_every_terminal_row() -> None:
    """A single unresolved slot blocks even when every other slot would decide."""
    for terminal_others in (
        (_slot(1, attempt=_R.NOT_APPLICABLE),),  # would be row 4
        (_slot(1, attempt=_R.FAILED, retry_status=_S.DENIED),),  # would be row 5
        (_slot(1, attempt=_R.CANCELLED),),  # would be row 6
        (_succeeded(1),),  # would be row 7
        (_slot(1, attempt=_R.SUCCEEDED_WITH_WARNINGS),),  # would be row 8
    ):
        result = _classify(_slot(0, attempt=_R.STARTING), *terminal_others)
        assert result.verdict is _V.NOT_YET_TERMINAL


# Row 4: no applicable engine


def test_row_four_every_slot_not_applicable_fails_with_no_applicable_engine() -> None:
    result = _classify(_expected_not_applicable(0), _expected_not_applicable(1))
    assert result.verdict is _V.FAILED
    assert _codes(result) == (REASON_NO_APPLICABLE_ENGINE,)


def test_row_four_adds_the_late_code_when_any_member_is_late() -> None:
    result = _classify(_expected_not_applicable(0), _late_not_applicable(1))
    assert result.verdict is _V.FAILED
    assert _codes(result) == (REASON_LATE_NOT_APPLICABLE, REASON_NO_APPLICABLE_ENGINE)
    only_late = _classify(_late_not_applicable(0))
    assert _codes(only_late) == (
        REASON_LATE_NOT_APPLICABLE,
        REASON_NO_APPLICABLE_ENGINE,
    )


def test_row_four_ignores_approximation_because_no_slot_produced_a_result() -> None:
    approximated_late = _slot(
        0, outcome=_C.SUPPORTED_WITH_APPROXIMATION, attempt=_R.NOT_APPLICABLE
    )
    result = _classify(approximated_late)
    assert result.verdict is _V.FAILED
    assert _codes(result) == (REASON_LATE_NOT_APPLICABLE, REASON_NO_APPLICABLE_ENGINE)


def test_row_four_counts_late_and_expected_not_applicable_alike_as_members_of_n() -> (
    None
):
    result = _classify(_slot(0, outcome=_C.NOT_APPLICABLE, attempt=_R.NOT_APPLICABLE))
    assert result.verdict is _V.FAILED
    assert _codes(result) == (REASON_NO_APPLICABLE_ENGINE,)


# Row 5: nothing succeeded and something failed, timed out or was unavailable


@pytest.mark.parametrize("state", _RETRYABLE_STATES)
def test_row_five_no_success_and_a_contributing_slot_fails_with_its_code(
    state: EngineRunState,
) -> None:
    result = _classify(_slot(0, attempt=state, retry_status=_S.DENIED))
    assert result.verdict is _V.FAILED
    assert _codes(result) == (_STATE_CODE[state],)


def test_row_five_collects_the_code_of_each_contributing_slot_once() -> None:
    result = _classify(
        _slot(0, attempt=_R.FAILED, retry_status=_S.DENIED),
        _slot(1, attempt=_R.FAILED, retry_status=_S.DENIED),
        _slot(2, attempt=_R.TIMED_OUT, retry_status=_S.DENIED),
        _slot(3, outcome=_C.UNAVAILABLE),
    )
    assert result.verdict is _V.FAILED
    assert _codes(result) == (
        REASON_SLOT_FAILED,
        REASON_SLOT_TIMED_OUT,
        REASON_SLOT_UNAVAILABLE,
    )


def test_row_five_outranks_row_four_when_any_slot_is_not_in_n() -> None:
    result = _classify(
        _expected_not_applicable(0), _slot(1, attempt=_R.FAILED, retry_status=_S.DENIED)
    )
    assert result.verdict is _V.FAILED
    assert _codes(result) == (REASON_SLOT_FAILED,)


def test_row_five_contributes_only_the_failing_slots_codes() -> None:
    """Literal plan 9.3 row 5: a cancelled, late or approximated slot alongside the
    failing slots adds no code; the verdict names what failed."""
    result = _classify(
        _slot(
            0,
            outcome=_C.SUPPORTED_WITH_APPROXIMATION,
            attempt=_R.FAILED,
            retry_status=_S.DENIED,
        ),
        _slot(1, attempt=_R.CANCELLED),
        _late_not_applicable(2),
    )
    assert result.verdict is _V.FAILED
    assert _codes(result) == (REASON_SLOT_FAILED,)


def test_a_zero_attempt_unavailable_slot_contributes_unavailability() -> None:
    result = _classify(_slot(0, outcome=_C.UNAVAILABLE))
    assert result.verdict is _V.FAILED
    assert _codes(result) == (REASON_SLOT_UNAVAILABLE,)


# Row 6: nothing succeeded and a child was cancelled


def test_row_six_no_success_and_a_cancelled_slot_fails_with_slot_cancelled() -> None:
    result = _classify(_slot(0, attempt=_R.CANCELLED))
    assert result.verdict is _V.FAILED
    assert _codes(result) == (REASON_SLOT_CANCELLED,)


def test_row_six_contributes_exactly_slot_cancelled() -> None:
    result = _classify(
        _slot(0, outcome=_C.SUPPORTED_WITH_APPROXIMATION, attempt=_R.CANCELLED),
        _late_not_applicable(1),
        _expected_not_applicable(2),
    )
    assert result.verdict is _V.FAILED
    assert _codes(result) == (REASON_SLOT_CANCELLED,)


def test_row_five_outranks_row_six() -> None:
    result = _classify(
        _slot(0, attempt=_R.CANCELLED),
        _slot(1, attempt=_R.UNAVAILABLE, retry_status=_S.DENIED),
    )
    assert result.verdict is _V.FAILED
    assert _codes(result) == (REASON_SLOT_UNAVAILABLE,)


# Row 7: clean completion


def test_row_seven_every_applicable_slot_succeeds_cleanly() -> None:
    result = _classify(_succeeded(0), _succeeded(1))
    assert result.verdict is _V.COMPLETED
    assert _codes(result) == ()


def test_row_seven_tolerates_expected_not_applicable_slots() -> None:
    result = _classify(
        _succeeded(0),
        _expected_not_applicable(1),
        _slot(2, outcome=_C.NOT_APPLICABLE, attempt=_R.NOT_APPLICABLE),
    )
    assert result.verdict is _V.COMPLETED
    assert _codes(result) == ()


def test_the_result_carries_the_input_identity_and_envelope() -> None:
    result = _classify(_succeeded(0))
    assert result.schema_version == "1.0.0"
    assert result.experiment_id == _EXPERIMENT_ID
    other = classify_experiment_outcome(
        _input(_succeeded(0), experiment_id=_OTHER_EXPERIMENT_ID)
    )
    assert other.experiment_id == _OTHER_EXPERIMENT_ID


# Row 8: completed with warnings


def test_row_eight_a_warning_success_contributes_its_code() -> None:
    result = _classify(_succeeded(0), _slot(1, attempt=_R.SUCCEEDED_WITH_WARNINGS))
    assert result.verdict is _V.COMPLETED_WITH_WARNINGS
    assert _codes(result) == (REASON_SLOT_SUCCEEDED_WITH_WARNINGS,)
    alone = _classify(_slot(0, attempt=_R.SUCCEEDED_WITH_WARNINGS))
    assert alone.verdict is _V.COMPLETED_WITH_WARNINGS


def test_row_eight_an_approximated_success_contributes_the_approximation_code() -> None:
    result = _classify(
        _slot(0, outcome=_C.SUPPORTED_WITH_APPROXIMATION, attempt=_R.SUCCEEDED)
    )
    assert result.verdict is _V.COMPLETED_WITH_WARNINGS
    assert _codes(result) == (REASON_SLOT_USED_APPROXIMATION,)


def test_row_eight_a_late_not_applicable_slot_contributes_the_late_code() -> None:
    result = _classify(_succeeded(0), _late_not_applicable(1))
    assert result.verdict is _V.COMPLETED_WITH_WARNINGS
    assert _codes(result) == (REASON_LATE_NOT_APPLICABLE,)


@pytest.mark.parametrize("state", [*_RETRYABLE_STATES, _R.CANCELLED])
def test_row_eight_a_partial_failure_beside_a_success_is_a_warning(
    state: EngineRunState,
) -> None:
    status = _S.DENIED if state in _RETRYABLE_STATES else _S.NO_DECISION_REQUIRED
    result = _classify(_succeeded(0), _slot(1, attempt=state, retry_status=status))
    assert result.verdict is _V.COMPLETED_WITH_WARNINGS
    assert _codes(result) == (_STATE_CODE[state],)


def test_row_eight_a_zero_attempt_unavailable_slot_beside_a_success_is_a_warning() -> (
    None
):
    result = _classify(_succeeded(0), _slot(1, outcome=_C.UNAVAILABLE))
    assert result.verdict is _V.COMPLETED_WITH_WARNINGS
    assert _codes(result) == (REASON_SLOT_UNAVAILABLE,)


def test_row_eight_collects_every_contributing_slot_and_condition() -> None:
    result = _classify(
        _slot(0, outcome=_C.SUPPORTED_WITH_APPROXIMATION, attempt=_R.SUCCEEDED),
        _slot(1, attempt=_R.SUCCEEDED_WITH_WARNINGS),
        _slot(
            2,
            outcome=_C.SUPPORTED_WITH_APPROXIMATION,
            attempt=_R.FAILED,
            retry_status=_S.DENIED,
        ),
        _slot(3, attempt=_R.TIMED_OUT, retry_status=_S.DENIED),
        _slot(4, attempt=_R.CANCELLED),
        _late_not_applicable(5),
        _expected_not_applicable(6),
        _slot(7, outcome=_C.UNAVAILABLE),
    )
    assert result.verdict is _V.COMPLETED_WITH_WARNINGS
    assert _codes(result) == tuple(
        sorted(
            {
                REASON_LATE_NOT_APPLICABLE,
                REASON_SLOT_CANCELLED,
                REASON_SLOT_FAILED,
                REASON_SLOT_SUCCEEDED_WITH_WARNINGS,
                REASON_SLOT_TIMED_OUT,
                REASON_SLOT_UNAVAILABLE,
                REASON_SLOT_USED_APPROXIMATION,
            }
        )
    )
    assert REASON_NO_APPLICABLE_ENGINE not in _codes(result)


def test_rows_seven_and_eight_are_distinguished_by_each_warning_condition_alone() -> (
    None
):
    clean = (_succeeded(0), _expected_not_applicable(1))
    assert _classify(*clean).verdict is _V.COMPLETED
    for warning in (
        _slot(1, attempt=_R.SUCCEEDED_WITH_WARNINGS),
        _slot(1, outcome=_C.SUPPORTED_WITH_APPROXIMATION, attempt=_R.SUCCEEDED),
        _late_not_applicable(1),
        _slot(1, attempt=_R.FAILED, retry_status=_S.DENIED),
        _slot(1, attempt=_R.CANCELLED),
        _slot(1, outcome=_C.UNAVAILABLE),
    ):
        assert _classify(_succeeded(0), warning).verdict is _V.COMPLETED_WITH_WARNINGS


def test_rows_four_through_eight_are_ordered_by_first_match() -> None:
    """One slot set per adjacent pair, satisfying the later row's condition too."""
    # Row 4 over row 5-8 is impossible (N is every slot); row 5 over row 6:
    assert _classify(
        _slot(0, attempt=_R.CANCELLED),
        _slot(1, attempt=_R.FAILED, retry_status=_S.DENIED),
    ).reason_codes == (REASON_SLOT_FAILED,)
    # Row 6 over rows 7-8: S is empty, so no completion is possible.
    assert _classify(
        _slot(0, attempt=_R.CANCELLED), _late_not_applicable(1)
    ).verdict is (_V.FAILED)
    # Row 7 over row 8: every condition of row 7 holds, so no warning.
    assert _classify(_succeeded(0), _expected_not_applicable(1)).verdict is _V.COMPLETED
    # A success alongside a failure is row 8, never row 5.
    assert (
        _classify(
            _succeeded(0), _slot(1, attempt=_R.FAILED, retry_status=_S.DENIED)
        ).verdict
        is _V.COMPLETED_WITH_WARNINGS
    )


def test_the_classifier_never_emits_cancelled_and_never_averages() -> None:
    """Plan 3.10 and 9.3: no averaging, majority voting or synthetic return; the
    ``CANCELLED`` member exists for Task 8's already-terminal path alone."""
    verdicts = set()
    for a in (None, *_TERMINAL_STATES):
        for b in (None, *_TERMINAL_STATES):
            slots = []
            for ordinal, state in enumerate((a, b)):
                if state is None:
                    slots.append(_expected_not_applicable(ordinal))
                else:
                    status = (
                        _S.DENIED
                        if state in _RETRYABLE_STATES
                        else _S.NO_DECISION_REQUIRED
                    )
                    slots.append(_slot(ordinal, attempt=state, retry_status=status))
            verdicts.add(_classify(*slots).verdict)
    assert _V.CANCELLED not in verdicts
    assert verdicts == {_V.COMPLETED, _V.COMPLETED_WITH_WARNINGS, _V.FAILED}
    # Two successes and one failure is a warning, never two-out-of-three success.
    result = _classify(
        _succeeded(0),
        _succeeded(1),
        _slot(2, attempt=_R.FAILED, retry_status=_S.DENIED),
    )
    assert result.verdict is _V.COMPLETED_WITH_WARNINGS


def test_the_classifier_is_deterministic_and_position_independent() -> None:
    forward = _classify(
        _slot(0, attempt=_R.FAILED, retry_status=_S.DENIED), _succeeded(1)
    )
    backward = _classify(
        _succeeded(0), _slot(1, attempt=_R.FAILED, retry_status=_S.DENIED)
    )
    assert forward.verdict is backward.verdict
    assert forward.reason_codes == backward.reason_codes
    again = _classify(
        _slot(0, attempt=_R.FAILED, retry_status=_S.DENIED), _succeeded(1)
    )
    assert again == forward
    assert canonical_json_bytes(again) == canonical_json_bytes(forward)


def test_the_classifier_refuses_a_foreign_input() -> None:
    with pytest.raises(TypeError, match="ExperimentAggregationInput"):
        classify_experiment_outcome(_slot())  # type: ignore[arg-type]


# --- Package surface and purity ------------------------------------------------------


def test_the_domain_package_re_exports_every_task_five_aggregation_name() -> None:
    for name in (
        "AGGREGATION_REASON_CODES",
        "REASON_LATE_NOT_APPLICABLE",
        "REASON_NO_APPLICABLE_ENGINE",
        "REASON_SLOT_CANCELLED",
        "REASON_SLOT_FAILED",
        "REASON_SLOT_SUCCEEDED_WITH_WARNINGS",
        "REASON_SLOT_TIMED_OUT",
        "REASON_SLOT_UNAVAILABLE",
        "REASON_SLOT_USED_APPROXIMATION",
        "AggregationVerdict",
        "ExperimentAggregationInput",
        "ExperimentAggregationResult",
        "SlotAggregationInput",
        "SlotRetryStatus",
        "classify_experiment_outcome",
        "effective_terminal_state",
        "is_late_not_applicable",
        "slot_reason_code",
        "slot_reason_codes",
        "uses_approximation",
    ):
        assert name in domain_package.__all__, name
        assert getattr(domain_package, name) is getattr(aggregation_module, name), name


_AMBIENT_ROOTS = frozenset(
    {
        "os",
        "pathlib",
        "random",
        "secrets",
        "shutil",
        "signal",
        "socket",
        "subprocess",
        "sys",
        "threading",
        "time",
        "uuid",
        "datetime",
        "statistics",
        "decimal",
    }
)
_AMBIENT_CALLS = frozenset(
    {"Popen", "monotonic", "now", "now_utc", "open", "run", "system", "today", "utcnow"}
)


def test_the_module_reads_no_clock_launches_nothing_and_stays_inside_domain() -> None:
    roots: set[str] = set()
    modules: set[str] = set()
    calls: set[str] = set()
    for node in ast.walk(ast.parse(_module_source(aggregation_module))):
        if isinstance(node, ast.Import):
            roots.update(alias.name.partition(".")[0] for alias in node.names)
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            roots.add(node.module.partition(".")[0])
            modules.add(node.module)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                calls.add(node.func.attr)
            elif isinstance(node.func, ast.Name):
                calls.add(node.func.id)
    assert roots.isdisjoint(_AMBIENT_ROOTS), sorted(roots & _AMBIENT_ROOTS)
    assert calls.isdisjoint(_AMBIENT_CALLS), sorted(calls & _AMBIENT_CALLS)
    for module in modules:
        if module.startswith("crypto_lab"):
            assert module.startswith("crypto_lab.domain."), module


def test_the_module_defines_no_task_six_or_later_name() -> None:
    """No repository, unit of work, transaction, cancellation or readiness service
    lives here: the classifier is the pure kernel Task 8 wraps."""
    defined = {
        node.name
        for node in ast.walk(ast.parse(_module_source(aggregation_module)))
        if isinstance(node, ast.ClassDef | ast.FunctionDef)
    }
    for later in (
        "build_aggregation_input",
        "aggregate_experiment",
        "cancel_experiment",
        "ExperimentAggregationRequest",
        "CancelExperimentRequest",
        "ExperimentRepository",
        "EngineRunRepository",
        "RetryDecisionRepository",
        "UnitOfWork",
        "InMemoryExperimentRepository",
        "evaluate_retry",
        "create_successor",
        "RetryDecisionRecord",
        "RetryEvaluationSnapshot",
        "evaluate_retry_gates",
    ):
        assert later not in defined, later
    source = _module_source(aggregation_module)
    for forbidden in (
        "ExperimentState",
        "ExperimentRecord",
        "revision",
        "compare_and_swap",
    ):
        assert forbidden not in source, forbidden
