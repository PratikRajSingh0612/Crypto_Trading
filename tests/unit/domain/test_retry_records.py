"""Stage 5 Task 5: the hard-blocking category partition, the retry terminal-state
mapping, the causal-closure value object, the authoritative evaluation snapshot,
the six retry gates with their fixed denial precedence, the durable delay, and the
immutable ``RetryDecisionRecord`` with its semantic projection.

Every rule below is transcribed from Stage 5 plan sections 3.1 (shared model
conventions), 3.9 (the sixteen record fields, their optionality and the projection),
8.1 (created attempts), 8.2 (the six gates, the ``4, 1, 2, 3, 6, 5`` precedence, the
paired closure and gate 6's qualifying observation) and 8.4 (phase 2 candidate
construction, the durable delay and the reservation), under specification sections
7.2, 16.3, 17.2.1, 21.2 and 21.2.1. Task-local readings the module declares in its
docstring are tested here as declared and are labelled as such.

The conventions of the merged tree apply: an absent state-governed field is
``MISSING``, never ``None``, and is asserted absent from **both** dump modes; a
record is never mutated through ``model_copy`` but rebuilt through
``model_validate`` so a rejection is real. Tests that begin green against the
committed tree (the ``DiagnosticCategory`` membership and the ``CanonicalModel``
configuration) are labelled preventive.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta, timezone
from itertools import permutations, product
from pathlib import Path
from types import ModuleType
from typing import Final

import pytest
from pydantic import TypeAdapter, ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab import domain as domain_package
from crypto_lab.domain import retry as retry_module
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.descriptors import (
    OperatingSystem,
    RuntimeAvailabilityObservation,
)
from crypto_lab.domain.diagnostics import (
    Diagnostic,
    DiagnosticCategory,
    DiagnosticSeverity,
    ErrorCode,
)
from crypto_lab.domain.engine_run import (
    NON_SUCCESS_TERMINAL_ENGINE_RUN_STATES,
    SUCCESS_ENGINE_RUN_STATES,
)
from crypto_lab.domain.lifecycle import (
    TERMINAL_ENGINE_RUN_STATES,
    TERMINAL_EXPERIMENT_STATES,
    EngineRunState,
    ExperimentState,
    RetryTerminalState,
)
from crypto_lab.domain.retry import (
    FAIL_CLOSED_CAUSAL_CLOSURE,
    HARD_BLOCKING_DIAGNOSTIC_CATEGORIES,
    MAX_ATTEMPTS_PER_SLOT,
    MAX_CANDIDATE_AVAILABILITY_OBSERVATIONS,
    MAX_CAUSAL_CLOSURE_ENTRIES,
    MAX_RETRY_DELAY_SECONDS,
    RETRY_DENIAL_PRECEDENCE,
    RETRY_PERMITTING_DIAGNOSTIC_CATEGORIES,
    CausalClosureEntry,
    RetryDecisionOutcome,
    RetryDecisionRecord,
    RetryDenialReason,
    RetryEvaluationSnapshot,
    RetryGate,
    RetryPolicy,
    canonical_causal_closure,
    denial_reason_for,
    durable_retry_not_before,
    evaluate_retry_gates,
    failed_retry_gates,
    hard_block_error_code,
    recorded_denial_reason,
    retry_decision_semantic_projection,
    retry_terminal_state_of,
    select_fresh_availability_observation,
)

_R = EngineRunState
_E = ExperimentState
_T = RetryTerminalState
_D = DiagnosticCategory
_G = RetryGate
_O = RetryDecisionOutcome
_N = RetryDenialReason

# Lowercase canonical UUID4 text: version nibble 4, variant nibble in [89ab].
_UUID_A = "12345678-1234-4234-8234-123456789abc"
_UUID_B = "9f8e7d6c-5b4a-4321-8fed-cba987654321"
_UUID_C = "0a1b2c3d-4e5f-4a6b-9c7d-8e9f0a1b2c3d"
_UUID_D = "5e5e5e5e-1111-4222-8333-444455556666"
_EXPERIMENT_ID = f"exp_{_UUID_A}"
_OTHER_EXPERIMENT_ID = f"exp_{_UUID_B}"
_SLOT_ID = f"slot_{_UUID_A}"
_OTHER_SLOT_ID = f"slot_{_UUID_B}"
_PREDECESSOR_RUN_ID = f"run_{_UUID_A}"
_OTHER_RUN_ID = f"run_{_UUID_B}"
_DIAG_ID = f"diag_{_UUID_A}"
_OTHER_DIAG_ID = f"diag_{_UUID_B}"
_INVOCATION_ID = f"inv_{_UUID_A}"
# Sorted: "avail_0a..." < "avail_12..." < "avail_5e..." < "avail_9f...".
_OBS_PREDECESSOR = f"avail_{_UUID_A}"
_OBS_FRESH = f"avail_{_UUID_B}"
_OBS_FRESH_LOW = f"avail_{_UUID_C}"
_OBS_FRESH_MID = f"avail_{_UUID_D}"

_SPEC_HASH = "a" * 64
_OTHER_SPEC_HASH = "b" * 64
_EXECUTABLE_HASH = "c" * 64
_OTHER_EXECUTABLE_HASH = "d" * 64

#: The predecessor's authoritative terminal completion instant (its updated_at_utc).
_COMPLETED = datetime(2026, 9, 7, 12, 0, 0, tzinfo=UTC)
#: The single clock instant the service reads in phase 2.
_EVALUATED = _COMPLETED + timedelta(minutes=10)
_NAIVE = datetime(2026, 9, 7, 12, 0, 0)  # noqa: DTZ001 - deliberate naive probe
_OFFSET = datetime(2026, 9, 7, 13, 0, 0, tzinfo=timezone(timedelta(hours=1)))

_MAX_ATTEMPTS = 3
_DELAY = 30

_PRIMARY_CODE = "ENGINE.RUNTIME_FAILURE"
_SECURITY_CODE = "SECURITY.SENSITIVE_MATERIAL_LEAKAGE"
_ARTIFACT_CODE = "ARTIFACT.VALIDATION_FAILED"
_INVARIANT_CODE = "CORE.INVARIANT_VIOLATION"

#: Plan section 3.9, fields 1 through 16 in the reviewed order.
_RECORD_FIELDS = (
    "schema_version",
    "experiment_id",
    "logical_slot_id",
    "predecessor_run_id",
    "experiment_spec_hash",
    "retry_policy",
    "created_attempt_count",
    "predecessor_terminal_state",
    "primary_terminal_diagnostic_id",
    "outcome",
    "denial_reason",
    "hard_block_error_code",
    "availability_observation_id",
    "retry_not_before_utc",
    "reserved_successor_attempt_number",
    "decided_at_utc",
)
_OPTIONAL_RECORD_FIELDS = (
    "denial_reason",
    "hard_block_error_code",
    "availability_observation_id",
    "retry_not_before_utc",
    "reserved_successor_attempt_number",
)
_PROJECTED_FIELDS = _RECORD_FIELDS[:-1]
#: Plan section 8.2: the snapshot's authoritative inputs (task-local inventory).
_SNAPSHOT_FIELDS = (
    "schema_version",
    "experiment_id",
    "logical_slot_id",
    "predecessor_run_id",
    "experiment_spec_hash",
    "retry_policy",
    "experiment_state",
    "created_attempt_count",
    "predecessor_terminal_state",
    "predecessor_terminal_completed_at_utc",
    "primary_terminal_diagnostic",
    "causal_closure",
    "predecessor_availability_observation",
    "candidate_availability_observations",
    "evaluated_at_utc",
)
_NON_SUCCESS_TERMINAL_STATES = (
    _R.FAILED,
    _R.CANCELLED,
    _R.TIMED_OUT,
    _R.NOT_APPLICABLE,
    _R.UNAVAILABLE,
)
_SUCCESS_STATES = (_R.SUCCEEDED, _R.SUCCEEDED_WITH_WARNINGS)
_NON_TERMINAL_STATES = (_R.PENDING, _R.VALIDATING, _R.READY, _R.STARTING, _R.RUNNING)
_RETRYABLE_STATES = (_R.FAILED, _R.TIMED_OUT, _R.UNAVAILABLE)
_UNMAPPED_TERMINAL_STATES = (_R.CANCELLED, _R.NOT_APPLICABLE)
_TERMINAL_EXPERIMENT_STATES = (
    _E.COMPLETED,
    _E.COMPLETED_WITH_WARNINGS,
    _E.FAILED,
    _E.CANCELLED,
)
_PRE_RUNNING_EXPERIMENT_STATES = (_E.DRAFT, _E.VALIDATED, _E.QUEUED)
_HARD_BLOCKING = (
    _D.USER_CONFIGURATION,
    _D.SCHEMA_VALIDATION,
    _D.COMPATIBILITY,
    _D.PROTOCOL,
    _D.CANCELLATION,
    _D.ARTIFACT_CORRUPTION,
    _D.INTERNAL_INVARIANT,
    _D.SECURITY,
)
_RETRY_PERMITTING = (
    _D.ADAPTER_UNAVAILABILITY,
    _D.ENGINE_RUNTIME,
    _D.TIMEOUT,
    _D.PERSISTENCE,
)
_GATES = (
    _G.ATTEMPT_BUDGET,
    _G.TERMINAL_STATE,
    _G.PRIMARY_DIAGNOSTIC,
    _G.HARD_BLOCK,
    _G.EXPERIMENT_ACTIVE,
    _G.AVAILABILITY_FRESHNESS,
)
_PRECEDENCE = (
    _G.HARD_BLOCK,
    _G.ATTEMPT_BUDGET,
    _G.TERMINAL_STATE,
    _G.PRIMARY_DIAGNOSTIC,
    _G.AVAILABILITY_FRESHNESS,
    _G.EXPERIMENT_ACTIVE,
)
_REASON_OF = {
    _G.ATTEMPT_BUDGET: _N.ATTEMPT_BUDGET_EXHAUSTED,
    _G.TERMINAL_STATE: _N.TERMINAL_STATE_NOT_RETRYABLE,
    _G.PRIMARY_DIAGNOSTIC: _N.PRIMARY_DIAGNOSTIC_NOT_RETRIABLE,
    _G.HARD_BLOCK: _N.HARD_BLOCKED_OUTCOME,
    _G.EXPERIMENT_ACTIVE: _N.EXPERIMENT_TERMINAL,
    _G.AVAILABILITY_FRESHNESS: _N.AVAILABILITY_OBSERVATION_NOT_FRESH,
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


def _policy(**overrides: object) -> RetryPolicy:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "maximum_attempts_per_slot": _MAX_ATTEMPTS,
        "automatically_retry_terminal_states": (
            _T.FAILED,
            _T.TIMED_OUT,
            _T.UNAVAILABLE,
        ),
        "retry_delay_seconds": _DELAY,
        "require_fresh_availability_observation_for_unavailable": True,
    }
    _apply(payload, overrides)
    return RetryPolicy.model_validate(payload)


def _diagnostic(**overrides: object) -> Diagnostic:
    """The predecessor's primary terminal diagnostic: retriable engine runtime."""
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "diagnostic_id": _DIAG_ID,
        "severity": DiagnosticSeverity.ERROR,
        "error_code": _PRIMARY_CODE,
        "category": _D.ENGINE_RUNTIME,
        "message": "The engine process crashed.",
        "source_component": "experiments.run_service",
        "experiment_id": _EXPERIMENT_ID,
        "run_id": _PREDECESSOR_RUN_ID,
        "invocation_id": _INVOCATION_ID,
        "retriable": True,
        "timestamp_utc": _COMPLETED,
        "details": {},
        "causal_diagnostic_ids": (),
    }
    _apply(payload, overrides)
    return Diagnostic.model_validate(payload)


def _entry(category: DiagnosticCategory, error_code: str) -> CausalClosureEntry:
    return CausalClosureEntry.model_validate(
        {"category": category, "error_code": error_code}
    )


def _closure_of(diagnostic: Diagnostic) -> tuple[CausalClosureEntry, ...]:
    return (_entry(diagnostic.category, diagnostic.error_code),)


def _observation(**overrides: object) -> RuntimeAvailabilityObservation:
    """The observation the predecessor referenced, made before it completed."""
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "availability_observation_id": _OBS_PREDECESSOR,
        "adapter_name": "adapter.alpha",
        "adapter_version": "1.0.0",
        "executable_path": r"C:\adapters\alpha\adapter.exe",
        "executable_hash": _EXECUTABLE_HASH,
        "runtime_version": "3.12.0",
        "operating_system": OperatingSystem.WINDOWS,
        "available": True,
        "observed_at_utc": _COMPLETED - timedelta(hours=1),
        "expires_at_utc": _COMPLETED + timedelta(hours=1),
        "network_required": False,
        "credentials_required": False,
    }
    _apply(payload, overrides)
    return RuntimeAvailabilityObservation.model_validate(payload)


def _fresh(**overrides: object) -> RuntimeAvailabilityObservation:
    """A qualifying observation: same identity, later, unexpired and distinct."""
    payload: dict[str, object] = {
        "availability_observation_id": _OBS_FRESH,
        "observed_at_utc": _COMPLETED + timedelta(minutes=1),
        "expires_at_utc": _EVALUATED + timedelta(hours=1),
    }
    _apply(payload, overrides)
    return _observation(**payload)


def _sorted_observations(
    *observations: RuntimeAvailabilityObservation,
) -> tuple[RuntimeAvailabilityObservation, ...]:
    return tuple(sorted(observations, key=lambda o: o.availability_observation_id))


def _snapshot_payload(
    state: EngineRunState,
    *,
    diagnostic: Diagnostic | None = None,
) -> dict[str, object]:
    diagnostic = _diagnostic() if diagnostic is None else diagnostic
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "experiment_id": _EXPERIMENT_ID,
        "logical_slot_id": _SLOT_ID,
        "predecessor_run_id": _PREDECESSOR_RUN_ID,
        "experiment_spec_hash": _SPEC_HASH,
        "retry_policy": _policy(),
        "experiment_state": _E.RUNNING,
        "created_attempt_count": 1,
        "predecessor_terminal_state": state,
        "predecessor_terminal_completed_at_utc": _COMPLETED,
        "primary_terminal_diagnostic": diagnostic,
        "causal_closure": _closure_of(diagnostic),
        "candidate_availability_observations": (),
        "evaluated_at_utc": _EVALUATED,
    }
    if state is _R.UNAVAILABLE:
        payload["predecessor_availability_observation"] = _observation()
        payload["candidate_availability_observations"] = (_fresh(),)
    return payload


def _snapshot(
    state: EngineRunState = _R.FAILED, /, **overrides: object
) -> RetryEvaluationSnapshot:
    """A snapshot in which every gate passes; ``_ABSENT`` removes a key.

    ``diagnostic=`` replaces the primary and rebuilds the closure from it, so a
    changed category or code stays paired unless ``causal_closure`` is overridden.
    """
    diagnostic = overrides.pop("diagnostic", None)
    assert diagnostic is None or isinstance(diagnostic, Diagnostic)
    payload = _snapshot_payload(state, diagnostic=diagnostic)
    _apply(payload, overrides)
    return RetryEvaluationSnapshot.model_validate(payload)


def _decision_payload(
    outcome: RetryDecisionOutcome,
    state: EngineRunState,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "experiment_id": _EXPERIMENT_ID,
        "logical_slot_id": _SLOT_ID,
        "predecessor_run_id": _PREDECESSOR_RUN_ID,
        "experiment_spec_hash": _SPEC_HASH,
        "retry_policy": _policy(),
        "created_attempt_count": 1,
        "predecessor_terminal_state": state,
        "primary_terminal_diagnostic_id": _DIAG_ID,
        "outcome": outcome,
        "decided_at_utc": _EVALUATED,
    }
    if outcome is _O.ALLOWED:
        payload["retry_not_before_utc"] = _COMPLETED + timedelta(seconds=_DELAY)
        payload["reserved_successor_attempt_number"] = 2
        if state is _R.UNAVAILABLE:
            payload["availability_observation_id"] = _OBS_FRESH
    return payload


def _allowed(
    state: EngineRunState = _R.FAILED, /, **overrides: object
) -> RetryDecisionRecord:
    payload = _decision_payload(_O.ALLOWED, state)
    _apply(payload, overrides)
    return RetryDecisionRecord.model_validate(payload)


#: For each reason, the shape of a record whose checkable gates agree with it.
_DENIED_SHAPE: dict[RetryDenialReason, dict[str, object]] = {
    _N.ATTEMPT_BUDGET_EXHAUSTED: {"created_attempt_count": _MAX_ATTEMPTS},
    _N.TERMINAL_STATE_NOT_RETRYABLE: {"predecessor_terminal_state": _R.CANCELLED},
    _N.PRIMARY_DIAGNOSTIC_NOT_RETRIABLE: {},
    _N.HARD_BLOCKED_OUTCOME: {"hard_block_error_code": _SECURITY_CODE},
    _N.EXPERIMENT_TERMINAL: {},
    _N.AVAILABILITY_OBSERVATION_NOT_FRESH: {
        "predecessor_terminal_state": _R.UNAVAILABLE
    },
}


def _denied(
    reason: RetryDenialReason = _N.PRIMARY_DIAGNOSTIC_NOT_RETRIABLE,
    /,
    **overrides: object,
) -> RetryDecisionRecord:
    payload = _decision_payload(_O.DENIED, _R.FAILED)
    payload["denial_reason"] = reason
    _apply(payload, _DENIED_SHAPE[reason])
    _apply(payload, overrides)
    return RetryDecisionRecord.model_validate(payload)


def _rebuild[M: CanonicalModel](instance: M, **overrides: object) -> M:
    """Rebuild through validation, never through ``model_copy``."""
    payload = instance.model_dump(mode="python")
    _apply(payload, overrides)
    return type(instance).model_validate(payload)


def _every_instance() -> tuple[CanonicalModel, ...]:
    return (
        _entry(_D.ENGINE_RUNTIME, _PRIMARY_CODE),
        _snapshot(),
        _snapshot(_R.UNAVAILABLE),
        _allowed(),
        _allowed(_R.UNAVAILABLE),
        _denied(),
        _denied(_N.HARD_BLOCKED_OUTCOME),
    )


def _module_source(module: ModuleType) -> str:
    assert module.__file__ is not None
    return Path(module.__file__).read_text(encoding="utf-8")


def _gate_overrides(failing: Iterable[RetryGate]) -> dict[str, object]:
    """Snapshot overrides that make exactly ``failing`` fail, over an UNAVAILABLE
    predecessor so that every one of the six gates is independently decisive."""
    failing = frozenset(failing)
    overrides: dict[str, object] = {}
    policy: dict[str, object] = {}
    if _G.ATTEMPT_BUDGET in failing:
        overrides["created_attempt_count"] = _MAX_ATTEMPTS
    if _G.TERMINAL_STATE in failing:
        policy["automatically_retry_terminal_states"] = (_T.FAILED, _T.TIMED_OUT)
    if policy:
        overrides["retry_policy"] = _policy(**policy)
    diagnostic = _diagnostic(
        retriable=_G.PRIMARY_DIAGNOSTIC not in failing,
    )
    overrides["diagnostic"] = diagnostic
    if _G.HARD_BLOCK in failing:
        overrides["causal_closure"] = canonical_causal_closure(
            (*_closure_of(diagnostic), _entry(_D.SECURITY, _SECURITY_CODE))
        )
    if _G.EXPERIMENT_ACTIVE in failing:
        overrides["experiment_state"] = _E.CANCELLED
    if _G.AVAILABILITY_FRESHNESS in failing:
        overrides["candidate_availability_observations"] = ()
    return overrides


# --- Shared conventions (plan section 3.1) ---------------------------------------


@pytest.mark.parametrize("instance", _every_instance(), ids=lambda m: type(m).__name__)
def test_every_task_five_model_rejects_an_unknown_field(
    instance: CanonicalModel,
) -> None:
    payload = instance.model_dump(mode="python")
    payload["unexpected"] = "value"
    with pytest.raises(ValidationError, match="extra_forbidden"):
        type(instance).model_validate(payload)


@pytest.mark.parametrize("instance", _every_instance(), ids=lambda m: type(m).__name__)
def test_every_task_five_model_is_frozen(instance: CanonicalModel) -> None:
    first = next(iter(type(instance).model_fields))
    with pytest.raises(ValidationError, match="frozen_instance"):
        setattr(instance, first, getattr(instance, first))


def test_every_task_five_model_derives_from_the_canonical_base() -> None:
    """Preventive against the committed base: the configuration is inherited."""
    for model in (
        CausalClosureEntry,
        RetryEvaluationSnapshot,
        RetryDecisionRecord,
    ):
        assert issubclass(model, CanonicalModel)
        assert model.model_config["extra"] == "forbid"
        assert model.model_config["frozen"] is True
        assert model.model_config["strict"] is True
        assert model.model_config["validate_default"] is True


def test_nested_values_are_immutable_through_the_record_and_snapshot() -> None:
    record = _allowed()
    with pytest.raises(ValidationError, match="frozen_instance"):
        record.retry_policy.maximum_attempts_per_slot = 5
    snapshot = _snapshot(_R.UNAVAILABLE)
    with pytest.raises(ValidationError, match="frozen_instance"):
        snapshot.primary_terminal_diagnostic.retriable = False
    with pytest.raises(ValidationError, match="frozen_instance"):
        snapshot.causal_closure[0].error_code = _SECURITY_CODE
    assert isinstance(snapshot.causal_closure, tuple)
    assert isinstance(snapshot.candidate_availability_observations, tuple)


def test_strict_mode_refuses_coercion_for_integers_booleans_and_enums() -> None:
    for build, field, value in (
        (_allowed, "created_attempt_count", "1"),
        (_allowed, "created_attempt_count", True),
        (_snapshot, "created_attempt_count", 1.0),
        (_allowed, "outcome", "allowed"),
        (_snapshot, "predecessor_terminal_state", "failed"),
        (_denied, "denial_reason", "EXPERIMENT_TERMINAL "),
        (_snapshot, "experiment_state", "RUNNING "),
    ):
        with pytest.raises(ValidationError):
            build(**{field: value})


@pytest.mark.parametrize("field", _OPTIONAL_RECORD_FIELDS)
def test_absent_record_fields_are_omitted_from_both_dump_modes_and_null_is_rejected(
    field: str,
) -> None:
    record = _denied() if field != "denial_reason" else _allowed()
    assert _missing(getattr(record, field))
    assert field not in record.model_dump(mode="json")
    assert field not in record.model_dump(mode="python")
    payload = record.model_dump(mode="python")
    payload[field] = None
    with pytest.raises(ValidationError):
        RetryDecisionRecord.model_validate(payload)


def test_absent_snapshot_observation_is_omitted_and_null_is_rejected() -> None:
    snapshot = _snapshot()
    assert _missing(snapshot.predecessor_availability_observation)
    assert "predecessor_availability_observation" not in snapshot.model_dump(
        mode="json"
    )
    payload = snapshot.model_dump(mode="python")
    payload["predecessor_availability_observation"] = None
    with pytest.raises(ValidationError):
        RetryEvaluationSnapshot.model_validate(payload)


# --- The hard-blocking partition (plan section 8.2, specification 21.2) --------------


def test_the_two_category_sets_are_disjoint_and_partition_every_category() -> None:
    assert HARD_BLOCKING_DIAGNOSTIC_CATEGORIES.isdisjoint(
        RETRY_PERMITTING_DIAGNOSTIC_CATEGORIES
    )
    assert (
        HARD_BLOCKING_DIAGNOSTIC_CATEGORIES | RETRY_PERMITTING_DIAGNOSTIC_CATEGORIES
        == (set(DiagnosticCategory))
    )


def test_the_partition_is_exactly_the_plan_assignment() -> None:
    assert HARD_BLOCKING_DIAGNOSTIC_CATEGORIES == frozenset(_HARD_BLOCKING)
    assert RETRY_PERMITTING_DIAGNOSTIC_CATEGORIES == frozenset(_RETRY_PERMITTING)
    assert isinstance(HARD_BLOCKING_DIAGNOSTIC_CATEGORIES, frozenset)
    assert isinstance(RETRY_PERMITTING_DIAGNOSTIC_CATEGORIES, frozenset)


def test_diagnostic_category_still_has_the_twelve_merged_members() -> None:
    """Preventive: the partition's totality assertion above depends on it."""
    assert len(DiagnosticCategory) == 12


# --- retry_terminal_state_of (plan sections 3.8 row 12, 8.2 gate 2, 9.2) ------------


@pytest.mark.parametrize("state", _RETRYABLE_STATES)
def test_the_three_retryable_terminals_map_to_their_retry_terminal_state(
    state: EngineRunState,
) -> None:
    mapped = retry_terminal_state_of(state)
    assert type(mapped) is RetryTerminalState
    assert mapped.value == state.value


@pytest.mark.parametrize(
    "state", _UNMAPPED_TERMINAL_STATES + _SUCCESS_STATES + _NON_TERMINAL_STATES
)
def test_every_other_engine_run_state_maps_to_no_retry_terminal_state(
    state: EngineRunState,
) -> None:
    assert _missing(retry_terminal_state_of(state))


def test_the_mapping_is_total_over_the_twelve_states_and_refuses_a_foreign_member() -> (
    None
):
    mapped = {state: retry_terminal_state_of(state) for state in EngineRunState}
    assert len(mapped) == 12
    assert {s for s, m in mapped.items() if not _missing(m)} == set(_RETRYABLE_STATES)
    with pytest.raises(TypeError, match="EngineRunState"):
        retry_terminal_state_of("FAILED")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="EngineRunState"):
        retry_terminal_state_of(_T.FAILED)  # type: ignore[arg-type]


# --- Enumerations and precedence (plan section 8.2) ---------------------------------


def test_the_outcome_vocabulary_is_exactly_allowed_and_denied() -> None:
    assert tuple(RetryDecisionOutcome) == (_O.ALLOWED, _O.DENIED)
    assert [m.value for m in RetryDecisionOutcome] == ["ALLOWED", "DENIED"]


def test_the_denial_reason_vocabulary_is_exactly_the_six_gate_reasons() -> None:
    assert [m.value for m in RetryDenialReason] == [
        "ATTEMPT_BUDGET_EXHAUSTED",
        "TERMINAL_STATE_NOT_RETRYABLE",
        "PRIMARY_DIAGNOSTIC_NOT_RETRIABLE",
        "HARD_BLOCKED_OUTCOME",
        "EXPERIMENT_TERMINAL",
        "AVAILABILITY_OBSERVATION_NOT_FRESH",
    ]


def test_the_six_gates_are_declared_in_plan_order_and_each_maps_to_one_reason() -> None:
    assert tuple(RetryGate) == _GATES
    assert [denial_reason_for(gate) for gate in RetryGate] == [
        _REASON_OF[gate] for gate in _GATES
    ]
    assert len({denial_reason_for(gate) for gate in RetryGate}) == 6
    with pytest.raises(TypeError, match="RetryGate"):
        denial_reason_for("HARD_BLOCK")  # type: ignore[arg-type]


def test_the_denial_precedence_is_four_one_two_three_six_five() -> None:
    assert RETRY_DENIAL_PRECEDENCE == _PRECEDENCE
    assert set(RETRY_DENIAL_PRECEDENCE) == set(RetryGate)
    assert len(RETRY_DENIAL_PRECEDENCE) == 6


@pytest.mark.parametrize("failing", list(product((False, True), repeat=6)))
def test_recorded_denial_reason_follows_the_precedence_over_all_sixty_four_tuples(
    failing: tuple[bool, ...],
) -> None:
    failed = frozenset(
        gate for gate, fails in zip(_GATES, failing, strict=True) if fails
    )
    if not failed:
        with pytest.raises(ValueError, match="no failed gate"):
            recorded_denial_reason(failed)
        return
    expected = next(_REASON_OF[gate] for gate in _PRECEDENCE if gate in failed)
    assert recorded_denial_reason(failed) is expected
    # Input order is not semantic: every permutation records the same reason.
    for ordering in permutations(sorted(failed, key=_GATES.index)):
        assert recorded_denial_reason(ordering) is expected


def test_recorded_denial_reason_refuses_a_foreign_gate() -> None:
    with pytest.raises(TypeError, match="RetryGate"):
        recorded_denial_reason(("HARD_BLOCK",))  # type: ignore[arg-type]


# --- CausalClosureEntry and the closure helpers (plan section 8.2) -----------------


def test_a_closure_entry_is_exactly_a_paired_category_and_code_without_envelope() -> (
    None
):
    assert tuple(CausalClosureEntry.model_fields) == ("category", "error_code")
    assert "schema_version" not in CausalClosureEntry.model_fields
    entry = _entry(_D.SECURITY, _SECURITY_CODE)
    assert entry.category is _D.SECURITY
    assert entry.error_code == _SECURITY_CODE


def test_a_closure_entry_validates_its_category_and_code_shape() -> None:
    with pytest.raises(ValidationError, match="is_instance_of"):
        _entry("SECURITY", _SECURITY_CODE)  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="pattern"):
        _entry(_D.SECURITY, "security.leak")
    with pytest.raises(ValidationError, match="pattern"):
        _entry(_D.SECURITY, "SECURITY")


def test_canonical_causal_closure_deduplicates_and_sorts_whole_pairs() -> None:
    a = _entry(_D.ENGINE_RUNTIME, _PRIMARY_CODE)
    b = _entry(_D.SECURITY, _SECURITY_CODE)
    d = _entry(_D.ARTIFACT_CORRUPTION, _ARTIFACT_CODE)
    e = _entry(_D.ARTIFACT_CORRUPTION, "ARTIFACT.RESULT_MANIFEST_INVALID")
    # Category first, then code: "ARTIFACT.R..." sorts before "ARTIFACT.V...".
    expected = (e, d, a, b)
    for ordering in permutations((a, b, d, e)):
        assert canonical_causal_closure(ordering) == expected
    assert canonical_causal_closure((b, b, a, a, d, e, d)) == expected
    assert canonical_causal_closure(()) == ()
    assert canonical_causal_closure(iter([b, a])) == (a, b)


def test_canonical_causal_closure_keeps_pairs_whole() -> None:
    """Two entries sharing a category but not a code are distinct; two sharing a
    code but not a category are distinct too."""
    same_category = (
        _entry(_D.PROTOCOL, "PROTOCOL.MALFORMED_JSONL"),
        _entry(_D.PROTOCOL, "PROTOCOL.EVENT_TOO_LARGE"),
    )
    same_code = (
        _entry(_D.ARTIFACT_CORRUPTION, "ARTIFACT.PATH_BOUNDARY_VIOLATION"),
        _entry(_D.SECURITY, "ARTIFACT.PATH_BOUNDARY_VIOLATION"),
    )
    assert len(canonical_causal_closure(same_category)) == 2
    assert len(canonical_causal_closure(same_code)) == 2


def test_canonical_causal_closure_refuses_a_foreign_element() -> None:
    with pytest.raises(TypeError, match="CausalClosureEntry"):
        canonical_causal_closure(((_D.SECURITY, _SECURITY_CODE),))  # type: ignore[arg-type]


@pytest.mark.parametrize("category", _HARD_BLOCKING)
def test_hard_block_error_code_is_read_from_the_first_hard_blocking_entry(
    category: DiagnosticCategory,
) -> None:
    code = f"{category.name}.PROBE"
    closure = canonical_causal_closure(
        (
            _entry(_D.ENGINE_RUNTIME, _PRIMARY_CODE),
            _entry(_D.TIMEOUT, "PROCESS.RUN_TIMED_OUT"),
            _entry(category, code),
        )
    )
    assert hard_block_error_code(closure) == code


def test_hard_block_error_code_is_missing_when_no_entry_hard_blocks() -> None:
    closure = canonical_causal_closure(
        tuple(
            _entry(category, f"{category.name}.PROBE") for category in _RETRY_PERMITTING
        )
    )
    assert _missing(hard_block_error_code(closure))
    assert _missing(hard_block_error_code(()))


def test_hard_block_error_code_follows_the_sorted_closure_and_stays_paired() -> None:
    """Two hard-blocking entries: the first in ``(category, error_code)`` order wins,
    and the code comes from that same entry rather than from any other."""
    closure = canonical_causal_closure(
        (
            _entry(_D.SECURITY, "SECURITY.AAA"),
            _entry(_D.ARTIFACT_CORRUPTION, "ARTIFACT.ZZZ"),
            _entry(_D.ENGINE_RUNTIME, "ENGINE.AAA"),
        )
    )
    assert closure[0].category is _D.ARTIFACT_CORRUPTION
    assert hard_block_error_code(closure) == "ARTIFACT.ZZZ"


def test_mutation_control_independent_sorting_would_select_the_wrong_code() -> None:
    """Plan Task 5's one mutation control: a closure of
    ``(ENGINE_RUNTIME, ENGINE.RUNTIME_FAILURE)`` and
    ``(SECURITY, SECURITY.SENSITIVE_MATERIAL_LEAKAGE)`` must select the ``SECURITY``
    code. A deliberately wrong implementation that sorts categories and codes
    independently and takes the smallest code among hard-blocking material selects
    the ``ENGINE`` code, and the two must differ."""
    entries = (
        _entry(_D.ENGINE_RUNTIME, _PRIMARY_CODE),
        _entry(_D.SECURITY, _SECURITY_CODE),
    )
    closure = canonical_causal_closure(entries)
    correct = hard_block_error_code(closure)
    assert correct == _SECURITY_CODE

    categories = sorted(entry.category for entry in entries)
    codes = sorted(entry.error_code for entry in entries)
    assert any(
        category in HARD_BLOCKING_DIAGNOSTIC_CATEGORIES for category in categories
    )
    wrong = codes[0]
    assert wrong == _PRIMARY_CODE
    assert wrong != correct


def test_hard_block_error_code_refuses_an_uncanonical_closure() -> None:
    a = _entry(_D.ENGINE_RUNTIME, _PRIMARY_CODE)
    b = _entry(_D.SECURITY, _SECURITY_CODE)
    with pytest.raises(ValueError, match="canonical"):
        hard_block_error_code((b, a))
    with pytest.raises(ValueError, match="canonical"):
        hard_block_error_code((a, a))


def test_the_fail_closed_closure_is_the_single_internal_invariant_entry() -> None:
    assert FAIL_CLOSED_CAUSAL_CLOSURE == (
        _entry(_D.INTERNAL_INVARIANT, _INVARIANT_CODE),
    )
    assert isinstance(FAIL_CLOSED_CAUSAL_CLOSURE, tuple)
    assert hard_block_error_code(FAIL_CLOSED_CAUSAL_CLOSURE) == _INVARIANT_CODE


# --- RetryEvaluationSnapshot shape (plan sections 8.2 and 3.1) ---------------------


def test_the_snapshot_declares_exactly_the_declared_fields_in_order() -> None:
    assert tuple(RetryEvaluationSnapshot.model_fields) == _SNAPSHOT_FIELDS
    assert (
        RetryEvaluationSnapshot.model_fields[
            "predecessor_availability_observation"
        ].default
        is MISSING
    )
    required = {
        name
        for name, field in RetryEvaluationSnapshot.model_fields.items()
        if field.is_required()
    }
    assert required == set(_SNAPSHOT_FIELDS) - {"predecessor_availability_observation"}


def test_the_snapshot_carries_no_caller_selectable_conclusion() -> None:
    """Plan 3.11: no request or snapshot field lets a caller choose the outcome,
    denial material, the delay, a reservation or a freshness conclusion."""
    for forbidden in (
        "outcome",
        "denial_reason",
        "hard_block_error_code",
        "retry_not_before_utc",
        "reserved_successor_attempt_number",
        "availability_observation_id",
        "availability_fresh",
        "fresh",
        "hard_blocked",
        "successor_run_id",
        "expected_revision",
        "expected_experiment_revision",
        "expected_predecessor_revision",
    ):
        assert forbidden not in RetryEvaluationSnapshot.model_fields, forbidden


@pytest.mark.parametrize("state", _NON_SUCCESS_TERMINAL_STATES)
def test_every_non_success_terminal_predecessor_state_is_accepted(
    state: EngineRunState,
) -> None:
    assert _snapshot(state).predecessor_terminal_state is state


@pytest.mark.parametrize("state", _SUCCESS_STATES + _NON_TERMINAL_STATES)
def test_a_success_or_non_terminal_predecessor_state_is_rejected(
    state: EngineRunState,
) -> None:
    with pytest.raises(ValidationError, match="non-success terminal"):
        _snapshot(state)


def test_the_predecessor_state_restriction_is_the_task_four_set() -> None:
    """Preventive cross-check against the committed Task 4 constants."""
    assert (
        frozenset(_NON_SUCCESS_TERMINAL_STATES)
        == NON_SUCCESS_TERMINAL_ENGINE_RUN_STATES
    )
    assert frozenset(_SUCCESS_STATES) == SUCCESS_ENGINE_RUN_STATES
    assert NON_SUCCESS_TERMINAL_ENGINE_RUN_STATES | SUCCESS_ENGINE_RUN_STATES == (
        TERMINAL_ENGINE_RUN_STATES
    )


@pytest.mark.parametrize("count", [0, -1, MAX_ATTEMPTS_PER_SLOT + 1, True])
def test_created_attempt_count_is_bounded_one_through_five(count: object) -> None:
    with pytest.raises(ValidationError):
        _snapshot(created_attempt_count=count)


@pytest.mark.parametrize("count", range(1, MAX_ATTEMPTS_PER_SLOT + 1))
def test_every_persisted_attempt_count_in_range_is_accepted(count: int) -> None:
    assert _snapshot(created_attempt_count=count).created_attempt_count == count


@pytest.mark.parametrize("state", [_E.RUNNING, *_TERMINAL_EXPERIMENT_STATES])
def test_the_experiment_state_is_running_or_terminal(state: ExperimentState) -> None:
    assert _snapshot(experiment_state=state).experiment_state is state


@pytest.mark.parametrize("state", _PRE_RUNNING_EXPERIMENT_STATES)
def test_an_experiment_that_never_ran_cannot_have_a_terminal_attempt(
    state: ExperimentState,
) -> None:
    """Task-local reading: attempts exist only from ``RUNNING`` onward (plan 5)."""
    with pytest.raises(ValidationError, match="RUNNING or terminal"):
        _snapshot(experiment_state=state)


def test_the_terminal_experiment_states_are_the_task_one_set() -> None:
    assert frozenset(_TERMINAL_EXPERIMENT_STATES) == TERMINAL_EXPERIMENT_STATES


def test_the_primary_diagnostic_correlation_must_agree_with_the_snapshot() -> None:
    """Task-local reading: a diagnostic carrying run or experiment correlation must
    name this predecessor and this experiment; absent correlation is accepted."""
    with pytest.raises(ValidationError, match="run_id"):
        _snapshot(diagnostic=_diagnostic(run_id=_OTHER_RUN_ID))
    with pytest.raises(ValidationError, match="experiment_id"):
        _snapshot(
            diagnostic=_diagnostic(
                experiment_id=_OTHER_EXPERIMENT_ID, run_id=_PREDECESSOR_RUN_ID
            )
        )
    uncorrelated = _diagnostic(experiment_id=_ABSENT, run_id=_ABSENT)
    assert (
        _snapshot(diagnostic=uncorrelated).primary_terminal_diagnostic is uncorrelated
    )


def test_the_closure_is_canonical_bounded_and_never_empty() -> None:
    a = _entry(_D.ENGINE_RUNTIME, _PRIMARY_CODE)
    b = _entry(_D.SECURITY, _SECURITY_CODE)
    with pytest.raises(ValidationError, match="too_short"):
        _snapshot(causal_closure=())
    with pytest.raises(ValidationError, match="unique"):
        _snapshot(causal_closure=(a, a))
    with pytest.raises(ValidationError, match="sorted"):
        _snapshot(causal_closure=(b, a))
    assert _snapshot(causal_closure=(a, b)).causal_closure == (a, b)
    assert MAX_CAUSAL_CLOSURE_ENTRIES == 256
    probes = (
        _entry(_D.ENGINE_RUNTIME, f"ENGINE.PROBE_{index:03d}")
        for index in range(MAX_CAUSAL_CLOSURE_ENTRIES)
    )
    too_many = canonical_causal_closure((*probes, a))
    assert len(too_many) == MAX_CAUSAL_CLOSURE_ENTRIES + 1
    with pytest.raises(ValidationError, match="too_long"):
        _snapshot(causal_closure=too_many)


def test_the_closure_contains_the_primary_pair_unless_fail_closed() -> None:
    """Plan 8.2: the closure holds the primary terminal diagnostic and its causal
    closure; the one exception is the service's fail-closed substitution."""
    other = _entry(_D.TIMEOUT, "PROCESS.RUN_TIMED_OUT")
    with pytest.raises(ValidationError, match="primary"):
        _snapshot(causal_closure=(other,))
    snapshot = _snapshot(causal_closure=FAIL_CLOSED_CAUSAL_CLOSURE)
    assert snapshot.causal_closure == FAIL_CLOSED_CAUSAL_CLOSURE
    assert _G.HARD_BLOCK in failed_retry_gates(snapshot)


@pytest.mark.parametrize("state", _NON_SUCCESS_TERMINAL_STATES)
def test_observation_material_is_present_exactly_for_an_unavailable_predecessor(
    state: EngineRunState,
) -> None:
    unavailable = state is _R.UNAVAILABLE
    if unavailable:
        with pytest.raises(
            ValidationError, match="predecessor_availability_observation"
        ):
            _snapshot(state, predecessor_availability_observation=_ABSENT)
        # An UNAVAILABLE predecessor may have no candidate at all; gate 6 then fails.
        empty = _snapshot(state, candidate_availability_observations=())
        assert empty.candidate_availability_observations == ()
        return
    with pytest.raises(ValidationError, match="predecessor_availability_observation"):
        _snapshot(state, predecessor_availability_observation=_observation())
    with pytest.raises(ValidationError, match="candidate_availability_observations"):
        _snapshot(state, candidate_availability_observations=(_fresh(),))


def test_candidate_observations_are_unique_by_identifier_sorted_and_bounded() -> None:
    fresh = _fresh()
    with pytest.raises(ValidationError, match="unique"):
        _snapshot(_R.UNAVAILABLE, candidate_availability_observations=(fresh, fresh))
    low = _fresh(availability_observation_id=_OBS_FRESH_LOW)
    with pytest.raises(ValidationError, match="sorted"):
        _snapshot(_R.UNAVAILABLE, candidate_availability_observations=(fresh, low))
    accepted = _snapshot(
        _R.UNAVAILABLE, candidate_availability_observations=(low, fresh)
    )
    assert accepted.candidate_availability_observations == (low, fresh)
    assert MAX_CANDIDATE_AVAILABILITY_OBSERVATIONS == 256


@pytest.mark.parametrize(
    "field", ["predecessor_terminal_completed_at_utc", "evaluated_at_utc"]
)
def test_a_naive_or_offset_timestamp_is_rejected_on_every_snapshot_instant(
    field: str,
) -> None:
    with pytest.raises(ValidationError, match="UTC"):
        _snapshot(**{field: _NAIVE})
    with pytest.raises(ValidationError, match="UTC"):
        _snapshot(**{field: _OFFSET})


def test_identity_fields_are_prefixed_uuid4_identifiers_and_hashes_are_sha256() -> None:
    with pytest.raises(ValidationError, match="exp_"):
        _snapshot(experiment_id=_SLOT_ID)
    with pytest.raises(ValidationError, match="slot_"):
        _snapshot(logical_slot_id=_EXPERIMENT_ID)
    with pytest.raises(ValidationError, match="run_"):
        _snapshot(predecessor_run_id=_DIAG_ID)
    with pytest.raises(ValidationError, match="pattern"):
        _snapshot(experiment_spec_hash="A" * 64)
    with pytest.raises(ValidationError, match="run_"):
        _allowed(predecessor_run_id=_EXPERIMENT_ID)
    with pytest.raises(ValidationError, match="diag_"):
        _allowed(primary_terminal_diagnostic_id=_PREDECESSOR_RUN_ID)
    with pytest.raises(ValidationError, match="avail_"):
        _allowed(_R.UNAVAILABLE, availability_observation_id=_DIAG_ID)


# --- Gate 6: availability identity and freshness (plan section 8.2) ---------------


def _select(
    *candidates: RuntimeAvailabilityObservation,
    predecessor: RuntimeAvailabilityObservation | None = None,
    evaluated_at: datetime = _EVALUATED,
) -> object:
    return select_fresh_availability_observation(
        _observation() if predecessor is None else predecessor,
        _sorted_observations(*candidates),
        terminal_completed_at_utc=_COMPLETED,
        evaluated_at_utc=evaluated_at,
    )


def test_a_fresh_matching_distinct_unexpired_observation_qualifies() -> None:
    fresh = _fresh()
    assert _select(fresh) is fresh


def test_no_candidate_means_no_qualifying_observation() -> None:
    assert _missing(_select())


def test_the_predecessors_own_observation_never_qualifies() -> None:
    """Identity must differ even when every other condition would hold."""
    same_id = _fresh(availability_observation_id=_OBS_PREDECESSOR)
    assert _missing(_select(same_id))


@pytest.mark.parametrize(
    "override",
    [
        {"adapter_name": "adapter.beta"},
        {"adapter_version": "1.0.1"},
        {"executable_hash": _OTHER_EXECUTABLE_HASH},
    ],
    ids=["adapter_name", "adapter_version", "executable_hash"],
)
def test_an_observation_of_a_different_identity_never_qualifies(
    override: dict[str, object],
) -> None:
    assert _missing(_select(_fresh(**override)))


def test_identity_ignores_the_path_runtime_and_operating_system() -> None:
    """Plan 8.2 names adapter name, adapter version and executable hash only."""
    moved = _fresh(
        executable_path=r"D:\other\adapter.exe",
        runtime_version="3.12.1",
        operating_system=OperatingSystem.LINUX,
        network_required=True,
        credentials_required=True,
    )
    assert _select(moved) is moved


def test_an_unavailable_observation_never_qualifies() -> None:
    unavailable = _fresh(available=False, reason_code="ADAPTER.UNAVAILABLE")
    assert _missing(_select(unavailable))


@pytest.mark.parametrize(
    "observed_at",
    [
        _COMPLETED,
        _COMPLETED - timedelta(microseconds=1),
        _COMPLETED - timedelta(days=1),
    ],
    ids=["at_completion", "one_microsecond_before", "one_day_before"],
)
def test_an_observation_not_strictly_after_completion_never_qualifies(
    observed_at: datetime,
) -> None:
    stale = _fresh(
        observed_at_utc=observed_at, expires_at_utc=_EVALUATED + timedelta(1)
    )
    assert _missing(_select(stale))


def test_an_observation_one_microsecond_after_completion_qualifies() -> None:
    fresh = _fresh(observed_at_utc=_COMPLETED + timedelta(microseconds=1))
    assert _select(fresh) is fresh


@pytest.mark.parametrize(
    "expires_at",
    [_EVALUATED, _EVALUATED - timedelta(microseconds=1)],
    ids=["at_evaluation", "one_microsecond_before_evaluation"],
)
def test_an_expired_observation_never_qualifies(expires_at: datetime) -> None:
    expired = _fresh(expires_at_utc=expires_at)
    assert _missing(_select(expired))


def test_an_observation_expiring_one_microsecond_after_evaluation_qualifies() -> None:
    fresh = _fresh(expires_at_utc=_EVALUATED + timedelta(microseconds=1))
    assert _select(fresh) is fresh


def test_expiry_is_judged_against_the_supplied_instant_not_a_clock() -> None:
    fresh = _fresh()
    assert _missing(_select(fresh, evaluated_at=fresh.expires_at_utc))
    assert _select(fresh, evaluated_at=_COMPLETED + timedelta(minutes=2)) is fresh


def test_selection_prefers_the_greatest_observation_instant() -> None:
    earlier = _fresh(
        availability_observation_id=_OBS_FRESH,
        observed_at_utc=_COMPLETED + timedelta(minutes=1),
    )
    later = _fresh(
        availability_observation_id=_OBS_FRESH_LOW,
        observed_at_utc=_COMPLETED + timedelta(minutes=2),
    )
    assert _select(earlier, later) is later
    assert _select(later, earlier) is later


def test_selection_breaks_an_instant_tie_by_the_greatest_identifier() -> None:
    instant = _COMPLETED + timedelta(minutes=1)
    low = _fresh(availability_observation_id=_OBS_FRESH_LOW, observed_at_utc=instant)
    mid = _fresh(availability_observation_id=_OBS_FRESH_MID, observed_at_utc=instant)
    high = _fresh(availability_observation_id=_OBS_FRESH, observed_at_utc=instant)
    assert _OBS_FRESH_LOW < _OBS_FRESH_MID < _OBS_FRESH
    assert _select(low, mid, high) is high
    assert _select(high, low, mid) is high


def test_selection_ignores_non_qualifying_candidates_when_choosing() -> None:
    qualifying = _fresh(
        availability_observation_id=_OBS_FRESH_LOW,
        observed_at_utc=_COMPLETED + timedelta(minutes=1),
    )
    newer_but_expired = _fresh(
        availability_observation_id=_OBS_FRESH,
        observed_at_utc=_COMPLETED + timedelta(minutes=5),
        expires_at_utc=_EVALUATED - timedelta(seconds=1),
    )
    newer_but_foreign = _fresh(
        availability_observation_id=_OBS_FRESH_MID,
        observed_at_utc=_COMPLETED + timedelta(minutes=6),
        adapter_name="adapter.beta",
    )
    assert _select(qualifying, newer_but_expired, newer_but_foreign) is qualifying


def test_selection_is_deterministic_under_every_input_permutation() -> None:
    a = _fresh(availability_observation_id=_OBS_FRESH_LOW)
    b = _fresh(
        availability_observation_id=_OBS_FRESH_MID,
        observed_at_utc=_COMPLETED + timedelta(minutes=3),
    )
    c = _fresh(availability_observation_id=_OBS_FRESH)
    for ordering in permutations((a, b, c)):
        chosen = select_fresh_availability_observation(
            _observation(),
            ordering,
            terminal_completed_at_utc=_COMPLETED,
            evaluated_at_utc=_EVALUATED,
        )
        assert chosen is b


def test_selection_refuses_a_non_utc_instant() -> None:
    with pytest.raises(ValueError, match="UTC"):
        select_fresh_availability_observation(
            _observation(),
            (_fresh(),),
            terminal_completed_at_utc=_NAIVE,
            evaluated_at_utc=_EVALUATED,
        )
    with pytest.raises(ValueError, match="UTC"):
        select_fresh_availability_observation(
            _observation(),
            (_fresh(),),
            terminal_completed_at_utc=_COMPLETED,
            evaluated_at_utc=_OFFSET,
        )


def test_selection_refuses_foreign_observations() -> None:
    """Added after the implementation for the type guards (begins green)."""
    with pytest.raises(TypeError, match="RuntimeAvailabilityObservation"):
        select_fresh_availability_observation(
            _snapshot(),  # type: ignore[arg-type]
            (_fresh(),),
            terminal_completed_at_utc=_COMPLETED,
            evaluated_at_utc=_EVALUATED,
        )
    with pytest.raises(TypeError, match="RuntimeAvailabilityObservation"):
        select_fresh_availability_observation(
            _observation(),
            (_fresh(), _snapshot()),  # type: ignore[arg-type]
            terminal_completed_at_utc=_COMPLETED,
            evaluated_at_utc=_EVALUATED,
        )


# --- The six gates over a snapshot (plan section 8.2) ------------------------------


def test_every_gate_passes_for_the_baseline_snapshots() -> None:
    for state in _RETRYABLE_STATES:
        assert failed_retry_gates(_snapshot(state)) == ()
        assert evaluate_retry_gates(_snapshot(state)).outcome is _O.ALLOWED


@pytest.mark.parametrize("gate", _GATES)
def test_each_gate_fails_independently_with_its_own_reason(gate: RetryGate) -> None:
    snapshot = _snapshot(_R.UNAVAILABLE, **_gate_overrides((gate,)))
    assert failed_retry_gates(snapshot) == (gate,)
    record = evaluate_retry_gates(snapshot)
    assert record.outcome is _O.DENIED
    assert record.denial_reason is _REASON_OF[gate]


@pytest.mark.parametrize("failing", list(product((False, True), repeat=6)))
def test_all_sixty_four_gate_outcome_tuples_pin_the_outcome_and_recorded_reason(
    failing: tuple[bool, ...],
) -> None:
    failed = tuple(gate for gate, fails in zip(_GATES, failing, strict=True) if fails)
    snapshot = _snapshot(_R.UNAVAILABLE, **_gate_overrides(failed))
    assert failed_retry_gates(snapshot) == failed
    record = evaluate_retry_gates(snapshot)
    if not failed:
        assert record.outcome is _O.ALLOWED
        assert _missing(record.denial_reason)
        assert _missing(record.hard_block_error_code)
        assert record.availability_observation_id == _OBS_FRESH
        assert record.retry_not_before_utc == _COMPLETED + timedelta(seconds=_DELAY)
        assert record.reserved_successor_attempt_number == 2
        return
    assert record.outcome is _O.DENIED
    expected = next(_REASON_OF[gate] for gate in _PRECEDENCE if gate in failed)
    assert record.denial_reason is expected
    assert record.denial_reason is recorded_denial_reason(failed)
    if expected is _N.HARD_BLOCKED_OUTCOME:
        assert record.hard_block_error_code == _SECURITY_CODE
    else:
        assert _missing(record.hard_block_error_code)
    assert _missing(record.availability_observation_id)
    assert _missing(record.retry_not_before_utc)
    assert _missing(record.reserved_successor_attempt_number)


def test_the_outcome_is_order_independent_but_the_reason_is_not() -> None:
    """All six gates are ANDed; only the recorded reason depends on precedence."""
    budget_and_terminal = _snapshot(
        _R.UNAVAILABLE, **_gate_overrides((_G.ATTEMPT_BUDGET, _G.EXPERIMENT_ACTIVE))
    )
    record = evaluate_retry_gates(budget_and_terminal)
    assert record.outcome is _O.DENIED
    assert record.denial_reason is _N.ATTEMPT_BUDGET_EXHAUSTED
    fresh_and_terminal = _snapshot(
        _R.UNAVAILABLE,
        **_gate_overrides((_G.AVAILABILITY_FRESHNESS, _G.EXPERIMENT_ACTIVE)),
    )
    assert (
        evaluate_retry_gates(fresh_and_terminal).denial_reason
        is _N.AVAILABILITY_OBSERVATION_NOT_FRESH
    )


# Gate 1 -- attempt budget (plan section 8.1)


@pytest.mark.parametrize("maximum", range(1, MAX_ATTEMPTS_PER_SLOT + 1))
@pytest.mark.parametrize("count", range(1, MAX_ATTEMPTS_PER_SLOT + 1))
def test_gate_one_passes_exactly_when_the_persisted_count_is_below_the_maximum(
    count: int, maximum: int
) -> None:
    snapshot = _snapshot(
        created_attempt_count=count,
        retry_policy=_policy(maximum_attempts_per_slot=maximum),
    )
    failed = failed_retry_gates(snapshot)
    assert (_G.ATTEMPT_BUDGET in failed) == (count >= maximum)
    record = evaluate_retry_gates(snapshot)
    if count < maximum:
        assert record.outcome is _O.ALLOWED
        assert record.reserved_successor_attempt_number == count + 1
    else:
        assert record.denial_reason is _N.ATTEMPT_BUDGET_EXHAUSTED


def test_a_maximum_of_one_always_denies_because_the_initial_attempt_counts() -> None:
    """Specification 11.5 and plan 8.1: the count includes the initial attempt."""
    for state in _RETRYABLE_STATES:
        record = evaluate_retry_gates(
            _snapshot(state, retry_policy=_policy(maximum_attempts_per_slot=1))
        )
        assert record.outcome is _O.DENIED
        assert record.denial_reason is _N.ATTEMPT_BUDGET_EXHAUSTED


def test_the_count_at_maximum_minus_one_allows_and_reserves_the_maximum() -> None:
    record = evaluate_retry_gates(_snapshot(created_attempt_count=_MAX_ATTEMPTS - 1))
    assert record.outcome is _O.ALLOWED
    assert record.reserved_successor_attempt_number == _MAX_ATTEMPTS


def test_a_count_above_the_maximum_denies_on_budget() -> None:
    record = evaluate_retry_gates(
        _snapshot(
            created_attempt_count=_MAX_ATTEMPTS + 1,
            retry_policy=_policy(maximum_attempts_per_slot=_MAX_ATTEMPTS),
        )
    )
    assert record.denial_reason is _N.ATTEMPT_BUDGET_EXHAUSTED


def test_a_reservation_is_not_an_attempt() -> None:
    """The gate reads only the persisted count; the reservation is ``count + 1``
    and never feeds back into the count the record carries."""
    record = evaluate_retry_gates(_snapshot(created_attempt_count=1))
    assert record.created_attempt_count == 1
    assert record.reserved_successor_attempt_number == 2
    assert not any("reserv" in name for name in RetryEvaluationSnapshot.model_fields)


# Gate 2 -- terminal-state eligibility from the immutable policy


@pytest.mark.parametrize("state", _RETRYABLE_STATES)
@pytest.mark.parametrize(
    "listed",
    [(), (_T.FAILED,), (_T.TIMED_OUT,), (_T.UNAVAILABLE,), (_T.FAILED, _T.TIMED_OUT)],
    ids=["none", "failed", "timed_out", "unavailable", "failed_timed_out"],
)
def test_gate_two_passes_exactly_when_the_policy_lists_the_mapped_state(
    state: EngineRunState, listed: tuple[RetryTerminalState, ...]
) -> None:
    snapshot = _snapshot(
        state, retry_policy=_policy(automatically_retry_terminal_states=listed)
    )
    failed = failed_retry_gates(snapshot)
    mapped = retry_terminal_state_of(state)
    assert (_G.TERMINAL_STATE in failed) == (mapped not in listed)


@pytest.mark.parametrize("state", _UNMAPPED_TERMINAL_STATES)
def test_cancelled_and_not_applicable_fail_gate_two_under_every_policy(
    state: EngineRunState,
) -> None:
    for listed in ((), (_T.FAILED, _T.TIMED_OUT, _T.UNAVAILABLE)):
        snapshot = _snapshot(
            state, retry_policy=_policy(automatically_retry_terminal_states=listed)
        )
        assert failed_retry_gates(snapshot) == (_G.TERMINAL_STATE,)
        assert (
            evaluate_retry_gates(snapshot).denial_reason
            is _N.TERMINAL_STATE_NOT_RETRYABLE
        )


def test_a_policy_with_no_automatic_states_disables_retry_for_every_predecessor() -> (
    None
):
    disabled = _policy(automatically_retry_terminal_states=())
    for state in _NON_SUCCESS_TERMINAL_STATES:
        record = evaluate_retry_gates(_snapshot(state, retry_policy=disabled))
        assert record.outcome is _O.DENIED
        assert record.denial_reason is _N.TERMINAL_STATE_NOT_RETRYABLE


# Gate 3 -- the primary diagnostic's retriable flag


def test_gate_three_fails_exactly_when_the_primary_is_not_retriable() -> None:
    not_retriable = _snapshot(diagnostic=_diagnostic(retriable=False))
    assert failed_retry_gates(not_retriable) == (_G.PRIMARY_DIAGNOSTIC,)
    record = evaluate_retry_gates(not_retriable)
    assert record.denial_reason is _N.PRIMARY_DIAGNOSTIC_NOT_RETRIABLE
    assert record.primary_terminal_diagnostic_id == _DIAG_ID
    assert failed_retry_gates(_snapshot(diagnostic=_diagnostic(retriable=True))) == ()


# Gate 4 -- hard blockers over the paired closure


@pytest.mark.parametrize("category", _HARD_BLOCKING)
def test_a_hard_blocker_in_the_primary_denies_despite_a_listed_state_and_retriable_flag(
    category: DiagnosticCategory,
) -> None:
    code = f"{category.name}.PROBE"
    snapshot = _snapshot(
        diagnostic=_diagnostic(category=category, error_code=code, retriable=True)
    )
    assert failed_retry_gates(snapshot) == (_G.HARD_BLOCK,)
    record = evaluate_retry_gates(snapshot)
    assert record.denial_reason is _N.HARD_BLOCKED_OUTCOME
    assert record.hard_block_error_code == code


@pytest.mark.parametrize("category", _HARD_BLOCKING)
def test_a_hard_blocker_only_in_the_causal_closure_denies(
    category: DiagnosticCategory,
) -> None:
    diagnostic = _diagnostic()
    code = f"{category.name}.PROBE"
    snapshot = _snapshot(
        diagnostic=diagnostic,
        causal_closure=canonical_causal_closure(
            (*_closure_of(diagnostic), _entry(category, code))
        ),
    )
    assert snapshot.primary_terminal_diagnostic.retriable is True
    assert failed_retry_gates(snapshot) == (_G.HARD_BLOCK,)
    record = evaluate_retry_gates(snapshot)
    assert record.denial_reason is _N.HARD_BLOCKED_OUTCOME
    assert record.hard_block_error_code == code


@pytest.mark.parametrize("category", _RETRY_PERMITTING)
def test_a_retry_permitting_closure_never_fails_gate_four(
    category: DiagnosticCategory,
) -> None:
    diagnostic = _diagnostic()
    snapshot = _snapshot(
        diagnostic=diagnostic,
        causal_closure=canonical_causal_closure(
            (*_closure_of(diagnostic), _entry(category, f"{category.name}.PROBE"))
        ),
    )
    assert _G.HARD_BLOCK not in failed_retry_gates(snapshot)


def test_the_recorded_hard_block_code_is_the_first_hard_blocking_pair() -> None:
    diagnostic = _diagnostic()
    snapshot = _snapshot(
        diagnostic=diagnostic,
        causal_closure=canonical_causal_closure(
            (
                *_closure_of(diagnostic),
                _entry(_D.SECURITY, _SECURITY_CODE),
                _entry(_D.ARTIFACT_CORRUPTION, _ARTIFACT_CODE),
            )
        ),
    )
    record = evaluate_retry_gates(snapshot)
    assert record.hard_block_error_code == _ARTIFACT_CODE
    assert record.hard_block_error_code == hard_block_error_code(
        snapshot.causal_closure
    )


def test_the_fail_closed_closure_denies_durably_with_the_invariant_code() -> None:
    record = evaluate_retry_gates(_snapshot(causal_closure=FAIL_CLOSED_CAUSAL_CLOSURE))
    assert record.outcome is _O.DENIED
    assert record.denial_reason is _N.HARD_BLOCKED_OUTCOME
    assert record.hard_block_error_code == _INVARIANT_CODE


def test_a_hard_blocker_outranks_every_other_failed_gate() -> None:
    snapshot = _snapshot(_R.UNAVAILABLE, **_gate_overrides(_GATES))
    assert failed_retry_gates(snapshot) == _GATES
    record = evaluate_retry_gates(snapshot)
    assert record.denial_reason is _N.HARD_BLOCKED_OUTCOME
    assert record.hard_block_error_code == _SECURITY_CODE


# Gate 5 -- the experiment is not already terminal


@pytest.mark.parametrize("state", _TERMINAL_EXPERIMENT_STATES)
def test_gate_five_fails_for_every_terminal_experiment_state(
    state: ExperimentState,
) -> None:
    snapshot = _snapshot(experiment_state=state)
    assert failed_retry_gates(snapshot) == (_G.EXPERIMENT_ACTIVE,)
    record = evaluate_retry_gates(snapshot)
    assert record.outcome is _O.DENIED
    assert record.denial_reason is _N.EXPERIMENT_TERMINAL
    assert _missing(record.reserved_successor_attempt_number)
    assert _missing(record.retry_not_before_utc)


def test_gate_five_passes_for_a_running_experiment() -> None:
    assert _G.EXPERIMENT_ACTIVE not in failed_retry_gates(
        _snapshot(experiment_state=_E.RUNNING)
    )


def test_gate_five_is_the_lowest_precedence_reason() -> None:
    for gate in (*_GATES[:-2], _G.AVAILABILITY_FRESHNESS):
        snapshot = _snapshot(
            _R.UNAVAILABLE, **_gate_overrides((gate, _G.EXPERIMENT_ACTIVE))
        )
        assert evaluate_retry_gates(snapshot).denial_reason is _REASON_OF[gate]


# Gate 6 -- fresh availability for UNAVAILABLE only


def test_gate_six_requires_a_qualifying_observation_for_unavailable() -> None:
    absent = _snapshot(_R.UNAVAILABLE, candidate_availability_observations=())
    assert failed_retry_gates(absent) == (_G.AVAILABILITY_FRESHNESS,)
    record = evaluate_retry_gates(absent)
    assert record.denial_reason is _N.AVAILABILITY_OBSERVATION_NOT_FRESH
    assert _missing(record.availability_observation_id)


@pytest.mark.parametrize(
    "candidate",
    [
        _fresh(availability_observation_id=_OBS_PREDECESSOR),
        _fresh(adapter_name="adapter.beta"),
        _fresh(adapter_version="2.0.0"),
        _fresh(executable_hash=_OTHER_EXECUTABLE_HASH),
        _fresh(observed_at_utc=_COMPLETED),
        _fresh(expires_at_utc=_EVALUATED),
        _fresh(available=False, reason_code="ADAPTER.UNAVAILABLE"),
    ],
    ids=[
        "same_identifier",
        "wrong_adapter_name",
        "wrong_adapter_version",
        "wrong_executable_hash",
        "not_after_completion",
        "expired",
        "unavailable",
    ],
)
def test_gate_six_rejects_each_disqualified_candidate(
    candidate: RuntimeAvailabilityObservation,
) -> None:
    snapshot = _snapshot(
        _R.UNAVAILABLE, candidate_availability_observations=(candidate,)
    )
    assert failed_retry_gates(snapshot) == (_G.AVAILABILITY_FRESHNESS,)


def test_gate_six_records_the_selected_observation_on_an_allowed_decision() -> None:
    low = _fresh(
        availability_observation_id=_OBS_FRESH_LOW,
        observed_at_utc=_COMPLETED + timedelta(minutes=1),
    )
    high = _fresh(
        availability_observation_id=_OBS_FRESH,
        observed_at_utc=_COMPLETED + timedelta(minutes=2),
    )
    snapshot = _snapshot(
        _R.UNAVAILABLE,
        candidate_availability_observations=_sorted_observations(low, high),
    )
    record = evaluate_retry_gates(snapshot)
    assert record.outcome is _O.ALLOWED
    assert record.availability_observation_id == _OBS_FRESH


@pytest.mark.parametrize("state", [_R.FAILED, _R.TIMED_OUT])
def test_gate_six_passes_vacuously_and_records_no_observation_for_other_states(
    state: EngineRunState,
) -> None:
    record = evaluate_retry_gates(_snapshot(state))
    assert record.outcome is _O.ALLOWED
    assert _missing(record.availability_observation_id)


def test_gate_six_is_judged_against_the_snapshot_instant_alone() -> None:
    expiring = _fresh(expires_at_utc=_EVALUATED + timedelta(seconds=1))
    on_time = _snapshot(_R.UNAVAILABLE, candidate_availability_observations=(expiring,))
    assert failed_retry_gates(on_time) == ()
    late = _snapshot(
        _R.UNAVAILABLE,
        candidate_availability_observations=(expiring,),
        evaluated_at_utc=_EVALUATED + timedelta(seconds=1),
    )
    assert failed_retry_gates(late) == (_G.AVAILABILITY_FRESHNESS,)


# --- Phase 2 candidate construction (plan section 8.4) ------------------------------


def test_the_candidate_copies_every_authoritative_identity_from_the_snapshot() -> None:
    snapshot = _snapshot(_R.UNAVAILABLE, created_attempt_count=2)
    record = evaluate_retry_gates(snapshot)
    assert record.schema_version == "1.0.0"
    assert record.experiment_id == snapshot.experiment_id
    assert record.logical_slot_id == snapshot.logical_slot_id
    assert record.predecessor_run_id == snapshot.predecessor_run_id
    assert record.experiment_spec_hash == snapshot.experiment_spec_hash
    assert record.retry_policy == snapshot.retry_policy
    assert record.created_attempt_count == 2
    assert record.predecessor_terminal_state is _R.UNAVAILABLE
    assert (
        record.primary_terminal_diagnostic_id
        == snapshot.primary_terminal_diagnostic.diagnostic_id
    )
    assert record.decided_at_utc == snapshot.evaluated_at_utc
    assert record.reserved_successor_attempt_number == 3


def test_evaluation_is_pure_and_repeatable() -> None:
    snapshot = _snapshot(_R.UNAVAILABLE)
    first = evaluate_retry_gates(snapshot)
    second = evaluate_retry_gates(snapshot)
    assert first == second
    assert canonical_json_bytes(first) == canonical_json_bytes(second)
    assert failed_retry_gates(snapshot) == failed_retry_gates(snapshot)


def test_evaluation_refuses_a_foreign_snapshot() -> None:
    with pytest.raises(TypeError, match="RetryEvaluationSnapshot"):
        evaluate_retry_gates(_allowed())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="RetryEvaluationSnapshot"):
        failed_retry_gates({})  # type: ignore[arg-type]


# --- Durable delay (plan section 8.4, specification 7.2) ----------------------------


@pytest.mark.parametrize("delay", [0, 1, 30, MAX_RETRY_DELAY_SECONDS])
def test_the_not_before_instant_is_completion_plus_the_policy_delay(delay: int) -> None:
    record = evaluate_retry_gates(
        _snapshot(retry_policy=_policy(retry_delay_seconds=delay))
    )
    assert record.retry_not_before_utc == _COMPLETED + timedelta(seconds=delay)
    assert durable_retry_not_before(_COMPLETED, delay) == record.retry_not_before_utc


def test_a_zero_delay_makes_the_successor_eligible_at_completion_itself() -> None:
    record = evaluate_retry_gates(
        _snapshot(retry_policy=_policy(retry_delay_seconds=0))
    )
    assert record.retry_not_before_utc == _COMPLETED


def test_the_delay_never_derives_from_the_evaluation_instant() -> None:
    early = evaluate_retry_gates(_snapshot(evaluated_at_utc=_COMPLETED))
    late = evaluate_retry_gates(
        _snapshot(evaluated_at_utc=_COMPLETED + timedelta(days=3))
    )
    assert early.retry_not_before_utc == late.retry_not_before_utc
    assert early.decided_at_utc != late.decided_at_utc
    assert retry_decision_semantic_projection(early) == (
        retry_decision_semantic_projection(late)
    )


def test_the_delay_preserves_microseconds_exactly() -> None:
    completed = _COMPLETED + timedelta(microseconds=123456)
    result = durable_retry_not_before(completed, 7)
    assert result == datetime(2026, 9, 7, 12, 0, 7, 123456, tzinfo=UTC)
    assert result.microsecond == 123456
    record = evaluate_retry_gates(
        _snapshot(
            predecessor_terminal_completed_at_utc=completed,
            retry_policy=_policy(retry_delay_seconds=7),
        )
    )
    assert record.retry_not_before_utc == result


def test_the_delay_is_utc_only_and_normalizes_to_utc() -> None:
    with pytest.raises(ValueError, match="UTC"):
        durable_retry_not_before(_NAIVE, 1)
    with pytest.raises(ValueError, match="UTC"):
        durable_retry_not_before(_OFFSET, 1)
    result = durable_retry_not_before(_COMPLETED, 1)
    assert result.tzinfo is UTC


def test_the_delay_is_bounded_by_the_policy_range() -> None:
    with pytest.raises(ValueError, match="retry_delay_seconds"):
        durable_retry_not_before(_COMPLETED, -1)
    with pytest.raises(ValueError, match="retry_delay_seconds"):
        durable_retry_not_before(_COMPLETED, MAX_RETRY_DELAY_SECONDS + 1)
    with pytest.raises(TypeError, match="integer"):
        durable_retry_not_before(_COMPLETED, True)
    with pytest.raises(TypeError, match="integer"):
        durable_retry_not_before(_COMPLETED, 1.0)  # type: ignore[arg-type]


def test_an_out_of_range_instant_is_a_value_error_not_a_silent_wrap() -> None:
    last = datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=UTC)
    with pytest.raises(ValueError, match="range"):
        durable_retry_not_before(last, 1)
    assert durable_retry_not_before(last, 0) == last
    with pytest.raises(ValueError, match="range"):
        evaluate_retry_gates(
            _snapshot(
                predecessor_terminal_completed_at_utc=last,
                evaluated_at_utc=last,
                retry_policy=_policy(retry_delay_seconds=1),
            )
        )


def test_the_delay_is_deterministic_on_repeated_calculation() -> None:
    results = {durable_retry_not_before(_COMPLETED, _DELAY) for _ in range(50)}
    assert results == {_COMPLETED + timedelta(seconds=_DELAY)}


# --- RetryDecisionRecord shape (plan section 3.9) -----------------------------------


def test_the_record_declares_exactly_the_sixteen_plan_fields_in_order() -> None:
    assert tuple(RetryDecisionRecord.model_fields) == _RECORD_FIELDS


def test_exactly_the_five_outcome_governed_fields_are_optional() -> None:
    optional = tuple(
        name
        for name, field in RetryDecisionRecord.model_fields.items()
        if not field.is_required()
    )
    assert optional == _OPTIONAL_RECORD_FIELDS
    for name in optional:
        assert RetryDecisionRecord.model_fields[name].default is MISSING, name


def test_the_record_has_no_revision_operational_id_or_later_enrichment_field() -> None:
    """Plan 3.9: identity is ``(logical_slot_id, predecessor_run_id)``; there is no
    revision, no separate operational identifier, no successor pointer and no
    storage bookkeeping to enrich later."""
    for name in (
        "revision",
        "decision_id",
        "retry_decision_id",
        "successor_run_id",
        "successor_created",
        "created_at_utc",
        "updated_at_utc",
        "applied",
        "consumed",
        "audited",
    ):
        assert name not in RetryDecisionRecord.model_fields, name


@pytest.mark.parametrize("state", _NON_SUCCESS_TERMINAL_STATES)
def test_every_non_success_terminal_state_is_an_accepted_predecessor_state(
    state: EngineRunState,
) -> None:
    if state in _RETRYABLE_STATES:
        assert _allowed(state).predecessor_terminal_state is state
    reason = (
        _N.TERMINAL_STATE_NOT_RETRYABLE
        if state in _UNMAPPED_TERMINAL_STATES
        else _N.PRIMARY_DIAGNOSTIC_NOT_RETRIABLE
    )
    assert _denied(
        reason, predecessor_terminal_state=state
    ).predecessor_terminal_state is (state)


@pytest.mark.parametrize("state", _SUCCESS_STATES)
def test_the_two_success_states_are_rejected_in_field_eight(
    state: EngineRunState,
) -> None:
    with pytest.raises(ValidationError, match="non-success terminal"):
        _allowed(state)
    with pytest.raises(ValidationError, match="non-success terminal"):
        _denied(predecessor_terminal_state=state)


@pytest.mark.parametrize("state", _NON_TERMINAL_STATES)
def test_a_non_terminal_state_is_rejected_in_field_eight(state: EngineRunState) -> None:
    with pytest.raises(ValidationError, match="non-success terminal"):
        _allowed(state)


def test_field_eight_publishes_the_full_enum_and_the_runtime_narrows_it() -> None:
    """Plan 3.9's recorded residual: the schema carries every ``EngineRunState``."""
    schema = RetryDecisionRecord.model_json_schema()
    enum = schema["$defs"]["EngineRunState"]["enum"]
    assert enum == [state.value for state in EngineRunState]


def test_an_allowed_record_requires_its_delay_and_reservation() -> None:
    with pytest.raises(ValidationError, match="retry_not_before_utc"):
        _allowed(retry_not_before_utc=_ABSENT)
    with pytest.raises(ValidationError, match="reserved_successor_attempt_number"):
        _allowed(reserved_successor_attempt_number=_ABSENT)


def test_an_allowed_record_carries_no_denial_material() -> None:
    with pytest.raises(ValidationError, match="denial_reason"):
        _allowed(denial_reason=_N.EXPERIMENT_TERMINAL)
    with pytest.raises(ValidationError, match="hard_block_error_code"):
        _allowed(hard_block_error_code=_SECURITY_CODE)


@pytest.mark.parametrize("reason", list(RetryDenialReason))
def test_a_denied_record_carries_no_delay_reservation_or_observation(
    reason: RetryDenialReason,
) -> None:
    with pytest.raises(ValidationError, match="retry_not_before_utc"):
        _denied(reason, retry_not_before_utc=_COMPLETED)
    with pytest.raises(ValidationError, match="reserved_successor_attempt_number"):
        _denied(reason, reserved_successor_attempt_number=2)
    with pytest.raises(ValidationError, match="availability_observation_id"):
        _denied(reason, availability_observation_id=_OBS_FRESH)


def test_a_denied_record_requires_a_denial_reason() -> None:
    with pytest.raises(ValidationError, match="denial_reason"):
        _denied(denial_reason=_ABSENT)


def test_the_hard_block_code_is_present_exactly_under_hard_blocked_outcome() -> None:
    with pytest.raises(ValidationError, match="hard_block_error_code"):
        _denied(_N.HARD_BLOCKED_OUTCOME, hard_block_error_code=_ABSENT)
    for reason in RetryDenialReason:
        if reason is _N.HARD_BLOCKED_OUTCOME:
            continue
        with pytest.raises(ValidationError, match="hard_block_error_code"):
            _denied(reason, hard_block_error_code=_SECURITY_CODE)


def test_the_hard_block_code_is_a_strict_namespaced_error_code() -> None:
    with pytest.raises(ValidationError, match="pattern"):
        _denied(_N.HARD_BLOCKED_OUTCOME, hard_block_error_code="security")
    assert _ERROR_CODE.validate_python(_SECURITY_CODE) == _SECURITY_CODE


def test_the_observation_is_present_exactly_when_allowed_and_unavailable() -> None:
    assert _allowed(_R.UNAVAILABLE).availability_observation_id == _OBS_FRESH
    with pytest.raises(ValidationError, match="availability_observation_id"):
        _allowed(_R.UNAVAILABLE, availability_observation_id=_ABSENT)
    for state in (_R.FAILED, _R.TIMED_OUT):
        with pytest.raises(ValidationError, match="availability_observation_id"):
            _allowed(state, availability_observation_id=_OBS_FRESH)
        assert _missing(_allowed(state).availability_observation_id)


@pytest.mark.parametrize("count", range(1, MAX_ATTEMPTS_PER_SLOT))
def test_the_reservation_equals_the_count_plus_one(count: int) -> None:
    policy = _policy(maximum_attempts_per_slot=MAX_ATTEMPTS_PER_SLOT)
    record = _allowed(
        created_attempt_count=count,
        reserved_successor_attempt_number=count + 1,
        retry_policy=policy,
    )
    assert record.reserved_successor_attempt_number == count + 1
    for wrong in (count, count + 2):
        if 2 <= wrong <= MAX_ATTEMPTS_PER_SLOT:
            with pytest.raises(ValidationError, match="created_attempt_count \\+ 1"):
                _allowed(
                    created_attempt_count=count,
                    reserved_successor_attempt_number=wrong,
                    retry_policy=policy,
                )


def test_the_reservation_is_bounded_two_through_five() -> None:
    policy = _policy(maximum_attempts_per_slot=MAX_ATTEMPTS_PER_SLOT)
    with pytest.raises(ValidationError, match="greater_than_equal"):
        _allowed(reserved_successor_attempt_number=1, retry_policy=policy)
    with pytest.raises(ValidationError, match="less_than_equal"):
        _allowed(
            created_attempt_count=MAX_ATTEMPTS_PER_SLOT,
            reserved_successor_attempt_number=MAX_ATTEMPTS_PER_SLOT + 1,
            retry_policy=policy,
        )


@pytest.mark.parametrize("count", [0, -1, MAX_ATTEMPTS_PER_SLOT + 1, True])
def test_the_record_count_is_bounded_one_through_five(count: object) -> None:
    """Added after the review for the record-level bound (begins green)."""
    with pytest.raises(ValidationError):
        _allowed(created_attempt_count=count)
    with pytest.raises(ValidationError):
        _denied(_N.ATTEMPT_BUDGET_EXHAUSTED, created_attempt_count=count)


def test_an_allowed_record_at_the_attempt_ceiling_is_unrepresentable() -> None:
    """A fifth attempt can never be allowed: the reservation would be six."""
    with pytest.raises(ValidationError):
        _allowed(
            created_attempt_count=MAX_ATTEMPTS_PER_SLOT,
            reserved_successor_attempt_number=MAX_ATTEMPTS_PER_SLOT + 1,
            retry_policy=_policy(maximum_attempts_per_slot=MAX_ATTEMPTS_PER_SLOT),
        )


# Precedence-implied consistency (task-local reading D5)


def test_an_allowed_record_must_satisfy_the_checkable_gates() -> None:
    with pytest.raises(ValidationError, match="maximum_attempts_per_slot"):
        _allowed(
            created_attempt_count=_MAX_ATTEMPTS,
            reserved_successor_attempt_number=_MAX_ATTEMPTS + 1,
        )
    with pytest.raises(ValidationError, match="automatically_retry_terminal_states"):
        _allowed(
            retry_policy=_policy(automatically_retry_terminal_states=(_T.TIMED_OUT,))
        )
    for state in _UNMAPPED_TERMINAL_STATES:
        with pytest.raises(
            ValidationError, match="automatically_retry_terminal_states"
        ):
            _allowed(state)


def test_a_budget_denial_requires_the_count_to_reach_the_maximum() -> None:
    assert _denied(_N.ATTEMPT_BUDGET_EXHAUSTED).created_attempt_count == _MAX_ATTEMPTS
    with pytest.raises(ValidationError, match="ATTEMPT_BUDGET_EXHAUSTED"):
        _denied(_N.ATTEMPT_BUDGET_EXHAUSTED, created_attempt_count=1)


def test_a_terminal_state_denial_requires_an_unlisted_state_and_budget_headroom() -> (
    None
):
    with pytest.raises(ValidationError, match="TERMINAL_STATE_NOT_RETRYABLE"):
        _denied(_N.TERMINAL_STATE_NOT_RETRYABLE, predecessor_terminal_state=_R.FAILED)
    excluded = _policy(automatically_retry_terminal_states=(_T.TIMED_OUT,))
    accepted = _denied(
        _N.TERMINAL_STATE_NOT_RETRYABLE,
        predecessor_terminal_state=_R.FAILED,
        retry_policy=excluded,
    )
    assert accepted.denial_reason is _N.TERMINAL_STATE_NOT_RETRYABLE
    with pytest.raises(ValidationError, match="ATTEMPT_BUDGET_EXHAUSTED"):
        _denied(_N.TERMINAL_STATE_NOT_RETRYABLE, created_attempt_count=_MAX_ATTEMPTS)


@pytest.mark.parametrize(
    "reason",
    [
        _N.PRIMARY_DIAGNOSTIC_NOT_RETRIABLE,
        _N.EXPERIMENT_TERMINAL,
        _N.AVAILABILITY_OBSERVATION_NOT_FRESH,
    ],
)
def test_a_lower_precedence_denial_requires_the_higher_checkable_gates_to_pass(
    reason: RetryDenialReason,
) -> None:
    with pytest.raises(ValidationError, match="ATTEMPT_BUDGET_EXHAUSTED"):
        _denied(reason, created_attempt_count=_MAX_ATTEMPTS)
    with pytest.raises(ValidationError, match="TERMINAL_STATE_NOT_RETRYABLE"):
        _denied(reason, retry_policy=_policy(automatically_retry_terminal_states=()))


def test_a_freshness_denial_requires_an_unavailable_predecessor() -> None:
    assert (
        _denied(_N.AVAILABILITY_OBSERVATION_NOT_FRESH).predecessor_terminal_state
        is _R.UNAVAILABLE
    )
    for state in (_R.FAILED, _R.TIMED_OUT):
        with pytest.raises(ValidationError, match="UNAVAILABLE"):
            _denied(
                _N.AVAILABILITY_OBSERVATION_NOT_FRESH, predecessor_terminal_state=state
            )


def test_a_hard_block_denial_implies_nothing_about_the_other_gates() -> None:
    exhausted_and_unlisted = _denied(
        _N.HARD_BLOCKED_OUTCOME,
        created_attempt_count=_MAX_ATTEMPTS,
        predecessor_terminal_state=_R.CANCELLED,
    )
    assert exhausted_and_unlisted.denial_reason is _N.HARD_BLOCKED_OUTCOME


@pytest.mark.parametrize("field", ["decided_at_utc", "retry_not_before_utc"])
def test_a_naive_or_offset_timestamp_is_rejected_on_every_record_instant(
    field: str,
) -> None:
    with pytest.raises(ValidationError, match="UTC"):
        _allowed(**{field: _NAIVE})
    with pytest.raises(ValidationError, match="UTC"):
        _allowed(**{field: _OFFSET})


def test_every_record_timestamp_uses_the_forward_schema_view() -> None:
    """Plan section 2.6: every Stage 5 timestamp field uses the calendar-valid view,
    so Task 9's registration passes the merged forward-view guard unchanged."""
    for mode in ("validation", "serialization"):
        schema = RetryDecisionRecord.model_json_schema(mode=mode)
        assert "UtcDateTime" not in schema.get("$defs", {})
        assert "CalendarValidUtcDateTime" in schema["$defs"]


def test_every_generated_record_round_trips_through_json_deterministically() -> None:
    for record in (
        _allowed(),
        _allowed(_R.UNAVAILABLE),
        *map(_denied, RetryDenialReason),
    ):
        again = RetryDecisionRecord.model_validate_json(record.model_dump_json())
        assert again == record
        assert canonical_json_bytes(again) == canonical_json_bytes(record)
        assert canonical_json_bytes(_rebuild(record)) == canonical_json_bytes(record)
        dumped = record.model_dump(mode="json")
        assert dumped["decided_at_utc"] == "2026-09-07T12:10:00Z"
        assert tuple(dumped) == tuple(
            name for name in _RECORD_FIELDS if not _missing(getattr(record, name))
        )


def test_the_record_dumps_retry_policy_states_in_canonical_order() -> None:
    record = _allowed(
        retry_policy=_policy(
            automatically_retry_terminal_states=(
                _T.UNAVAILABLE,
                _T.FAILED,
                _T.TIMED_OUT,
            )
        )
    )
    assert record.retry_policy.automatically_retry_terminal_states == (
        _T.FAILED,
        _T.TIMED_OUT,
        _T.UNAVAILABLE,
    )


# --- Semantic projection (plan sections 3.9 and 8.4 phase 3) ------------------------


def test_the_projection_excludes_the_decision_instant_alone() -> None:
    record = _allowed(_R.UNAVAILABLE)
    later = _rebuild(record, decided_at_utc=_EVALUATED + timedelta(hours=1))
    assert later != record
    assert retry_decision_semantic_projection(later) == (
        retry_decision_semantic_projection(record)
    )


@pytest.mark.parametrize("field", _PROJECTED_FIELDS)
def test_the_projection_includes_each_of_the_other_fifteen_fields(field: str) -> None:
    record = _allowed(_R.UNAVAILABLE)
    denied = _denied(_N.HARD_BLOCKED_OUTCOME)
    changed: dict[str, RetryDecisionRecord] = {
        "schema_version": record,  # a Literal admits one value; asserted present below
        "experiment_id": _rebuild(record, experiment_id=_OTHER_EXPERIMENT_ID),
        "logical_slot_id": _rebuild(record, logical_slot_id=_OTHER_SLOT_ID),
        "predecessor_run_id": _rebuild(record, predecessor_run_id=_OTHER_RUN_ID),
        "experiment_spec_hash": _rebuild(record, experiment_spec_hash=_OTHER_SPEC_HASH),
        "retry_policy": _rebuild(record, retry_policy=_policy(retry_delay_seconds=31)),
        "created_attempt_count": _rebuild(
            record, created_attempt_count=2, reserved_successor_attempt_number=3
        ),
        "predecessor_terminal_state": _rebuild(
            record,
            predecessor_terminal_state=_R.FAILED,
            availability_observation_id=_ABSENT,
        ),
        "primary_terminal_diagnostic_id": _rebuild(
            record, primary_terminal_diagnostic_id=_OTHER_DIAG_ID
        ),
        "outcome": denied,
        "denial_reason": _rebuild(
            denied, denial_reason=_N.EXPERIMENT_TERMINAL, hard_block_error_code=_ABSENT
        ),
        "hard_block_error_code": _rebuild(denied, hard_block_error_code=_ARTIFACT_CODE),
        "availability_observation_id": _rebuild(
            record, availability_observation_id=_OBS_FRESH_LOW
        ),
        "retry_not_before_utc": _rebuild(
            record, retry_not_before_utc=_COMPLETED + timedelta(seconds=_DELAY + 1)
        ),
        "reserved_successor_attempt_number": _rebuild(
            record, created_attempt_count=2, reserved_successor_attempt_number=3
        ),
    }
    baseline = retry_decision_semantic_projection(record)
    if field == "schema_version":
        assert b'"schema_version":"1.0.0"' in baseline
        return
    assert retry_decision_semantic_projection(changed[field]) != baseline
    if field in ("denial_reason", "hard_block_error_code"):
        assert retry_decision_semantic_projection(changed[field]) != (
            retry_decision_semantic_projection(denied)
        )


def test_the_projection_is_canonical_json_over_the_dumped_fields_minus_instant() -> (
    None
):
    for record in (_allowed(_R.UNAVAILABLE), _denied(_N.HARD_BLOCKED_OUTCOME)):
        expected = record.model_dump(mode="python")
        del expected["decided_at_utc"]
        assert retry_decision_semantic_projection(record) == canonical_json_bytes(
            expected
        )
        assert b"decided_at_utc" not in retry_decision_semantic_projection(record)
        assert isinstance(retry_decision_semantic_projection(record), bytes)


def test_the_projection_omits_absent_fields_rather_than_writing_null() -> None:
    projection = retry_decision_semantic_projection(_allowed())
    assert b"null" not in projection
    assert b"denial_reason" not in projection
    assert b"availability_observation_id" not in projection


def test_two_evaluations_of_one_snapshot_at_different_instants_agree_semantically() -> (
    None
):
    """Plan 8.4 phase 3: a concurrent winner from the same authoritative facts has an
    equal projection; only a divergent projection is a decision conflict."""
    first = evaluate_retry_gates(_snapshot(_R.UNAVAILABLE))
    second = evaluate_retry_gates(
        _snapshot(_R.UNAVAILABLE, evaluated_at_utc=_EVALUATED + timedelta(minutes=1))
    )
    assert retry_decision_semantic_projection(first) == (
        retry_decision_semantic_projection(second)
    )
    divergent = evaluate_retry_gates(
        _snapshot(_R.UNAVAILABLE, retry_policy=_policy(retry_delay_seconds=_DELAY + 1))
    )
    assert retry_decision_semantic_projection(first) != (
        retry_decision_semantic_projection(divergent)
    )


def test_the_projection_refuses_a_foreign_record() -> None:
    with pytest.raises(TypeError, match="RetryDecisionRecord"):
        retry_decision_semantic_projection(_snapshot())  # type: ignore[arg-type]


# --- Package surface and purity ------------------------------------------------------


def test_the_domain_package_re_exports_every_task_five_retry_name() -> None:
    for name in (
        "FAIL_CLOSED_CAUSAL_CLOSURE",
        "HARD_BLOCKING_DIAGNOSTIC_CATEGORIES",
        "RETRY_DENIAL_PRECEDENCE",
        "RETRY_PERMITTING_DIAGNOSTIC_CATEGORIES",
        "CausalClosureEntry",
        "RetryDecisionOutcome",
        "RetryDecisionRecord",
        "RetryDenialReason",
        "RetryEvaluationSnapshot",
        "RetryGate",
        "canonical_causal_closure",
        "denial_reason_for",
        "durable_retry_not_before",
        "evaluate_retry_gates",
        "failed_retry_gates",
        "hard_block_error_code",
        "recorded_denial_reason",
        "retry_decision_semantic_projection",
        "retry_terminal_state_of",
        "select_fresh_availability_observation",
    ):
        assert name in domain_package.__all__, name
        assert getattr(domain_package, name) is getattr(retry_module, name), name
    assert len(set(domain_package.__all__)) == len(domain_package.__all__)


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
    }
)
_AMBIENT_CALLS = frozenset(
    {
        "Popen",
        "monotonic",
        "now",
        "now_utc",
        "open",
        "perf_counter",
        "run",
        "system",
        "today",
        "token_hex",
        "token_urlsafe",
        "utcnow",
        "uuid1",
        "uuid4",
    }
)


def test_the_module_reads_no_clock_launches_nothing_and_stays_inside_domain() -> None:
    roots: set[str] = set()
    modules: set[str] = set()
    calls: set[str] = set()
    for node in ast.walk(ast.parse(_module_source(retry_module))):
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
    source = _module_source(retry_module)
    for forbidden in ("datetime.now", "time.time", "now_utc(", "IdentitySource"):
        assert forbidden not in source, forbidden


def test_the_module_defines_no_task_six_or_later_name() -> None:
    """No repository, unit of work, double, traversal, scheduling, successor
    creation, cancellation or aggregation implementation lives here."""
    defined = {
        node.name
        for node in ast.walk(ast.parse(_module_source(retry_module)))
        if isinstance(node, ast.ClassDef | ast.FunctionDef)
    }
    for later in (
        "RetryDecisionRepository",
        "RetryDecisionInsertOutcome",
        "EngineRunRepository",
        "ExperimentRepository",
        "RuntimeAvailabilityObservationReader",
        "DiagnosticReader",
        "UnitOfWork",
        "InMemoryRetryDecisionRepository",
        "RetryEvaluationRequest",
        "SuccessorCreationRequest",
        "resolve_causal_closure",
        "evaluate_retry",
        "create_successor",
        "cancel_experiment",
        "aggregate_experiment",
        "build_aggregation_input",
        "classify_experiment_outcome",
        "SlotAggregationInput",
        "ExperimentAggregationInput",
        "ExperimentAggregationResult",
    ):
        assert later not in defined, later


def test_the_module_never_walks_causal_diagnostic_ids() -> None:
    """Closure traversal is owned by Task 7's ``resolve_causal_closure`` alone; this
    module consumes the finished closure and never reads ``causal_diagnostic_ids``."""
    source = _module_source(retry_module)
    assert "causal_diagnostic_ids" not in source
    assert "get_many" not in source
