"""Stage 5 Task 4: the engine-run record, its section 5 state-governed field shapes,
the pure transition, edge-ownership and terminal-immutability predicates, the
section 6 coupled terminal mapping and the mixed running-pair predicate.

Every rule below is transcribed from Stage 5 plan sections 3.8 (the eighteen
fields in order, their sources and their optionality), 5 (the engine-run table,
edge ownership, the immutable field list and the attempt-creation contract) and 6
(the linked operations, the mixed-pair invariant and the coupled terminal
mapping), under specification sections 11.3, 11.5, 15.2, 15.6, 16.3 and 17. The
Task 1 ``ENGINE_RUN_TRANSITIONS`` table is the sole allowed-pair authority and
nothing here re-declares an edge.

The conventions of the merged tree apply: an absent state-governed field is
``MISSING``, never ``None``, and is asserted absent from **both** dump modes; a
record is never mutated through ``model_copy`` but rebuilt through
``model_validate`` so a rejection is real. Tests that begin green against the
committed tree -- the ``EngineRunState`` membership Task 1 fixed, the table
arithmetic and the ``CanonicalModel`` configuration -- are labelled preventive.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType
from typing import Final

import pytest
from pydantic import ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab import domain as domain_package
from crypto_lab.domain import engine_run as engine_run_module
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.command_invocation import (
    CommandInvocationRecord,
    ProcessIdentity,
)
from crypto_lab.domain.diagnostics import DiagnosticCategory
from crypto_lab.domain.engine_run import (
    LINKED_ONLY_RUN_EDGES,
    NON_SUCCESS_TERMINAL_ENGINE_RUN_STATES,
    SUCCESS_ENGINE_RUN_STATES,
    AttemptTokenMaterial,
    EngineRunCheck,
    EngineRunRecord,
    EngineRunRuleViolation,
    RunEdgeOwner,
    assert_run_transition,
    assert_terminal_run_immutability,
    coupled_run_terminal_state,
    is_mixed_running_pair,
    run_edge_owner,
)
from crypto_lab.domain.experiment import AdapterIdentity, EngineIdentity
from crypto_lab.domain.hashing import attempt_token_hash
from crypto_lab.domain.lifecycle import (
    COMMAND_INVOCATION_TRANSITIONS,
    ENGINE_RUN_TRANSITIONS,
    TERMINAL_COMMAND_INVOCATION_STATES,
    TERMINAL_ENGINE_RUN_STATES,
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ProcessExitCategory,
    RetryTerminalState,
)
from crypto_lab.domain.retry import MAX_ATTEMPTS_PER_SLOT

_R = EngineRunState
_C = CommandInvocationState
_K = CommandKind
_CHECK = EngineRunCheck
_GENERIC = RunEdgeOwner.GENERIC
_LINKED = RunEdgeOwner.LINKED_LAUNCH

# Lowercase canonical UUID4 text: version nibble 4, variant nibble in [89ab].
_UUID_A = "12345678-1234-4234-8234-123456789abc"
_UUID_B = "9f8e7d6c-5b4a-4321-8fed-cba987654321"
_UUID_C = "0a1b2c3d-4e5f-4a6b-9c7d-8e9f0a1b2c3d"
_RUN_ID = f"run_{_UUID_A}"
_OTHER_RUN_ID = f"run_{_UUID_B}"
_PREDECESSOR_RUN_ID = f"run_{_UUID_C}"
_EXPERIMENT_ID = f"exp_{_UUID_A}"
_OTHER_EXPERIMENT_ID = f"exp_{_UUID_B}"
_SLOT_ID = f"slot_{_UUID_A}"
_OTHER_SLOT_ID = f"slot_{_UUID_B}"
_DIAG_ID = f"diag_{_UUID_A}"
_OTHER_DIAG_ID = f"diag_{_UUID_B}"
_OBSERVATION_ID = f"avail_{_UUID_A}"
_FRESH_OBSERVATION_ID = f"avail_{_UUID_B}"
_INVOCATION_ID = f"inv_{_UUID_A}"

_TOKEN = "A" * 32
_TOKEN_HASH = attempt_token_hash(_TOKEN)
_OTHER_TOKEN_HASH = attempt_token_hash("B" * 32)
_REQUEST_HASH = "a" * 64
_OTHER_REQUEST_HASH = "b" * 64
_EXECUTABLE_HASH = "c" * 64

_CREATED = datetime(2026, 9, 7, 12, 0, 0, tzinfo=UTC)
_LATER = _CREATED + timedelta(minutes=5)
_NAIVE = datetime(2026, 9, 7, 12, 0, 0)  # noqa: DTZ001 - deliberate naive probe
_OFFSET = datetime(2026, 9, 7, 13, 0, 0, tzinfo=timezone(timedelta(hours=1)))

_ADAPTER = AdapterIdentity(adapter_name="adapter.alpha", adapter_version="1.0.0")
_OTHER_ADAPTER = AdapterIdentity(adapter_name="adapter.beta", adapter_version="1.0.0")
_ENGINE = EngineIdentity(engine_name="engine.alpha", engine_version="2.0.0")
_OTHER_ENGINE = EngineIdentity(engine_name="engine.beta", engine_version="2.0.0")

#: Plan section 3.8, fields 1 through 18 in the reviewed order.
_RECORD_FIELDS = (
    "schema_version",
    "run_id",
    "experiment_id",
    "logical_slot_id",
    "attempt_number",
    "attempt_token_hash",
    "state",
    "adapter",
    "engine",
    "request_hash",
    "predecessor_run_id",
    "retry_reason",
    "primary_terminal_diagnostic_id",
    "availability_observation_id",
    "finalization_deadline_utc",
    "created_at_utc",
    "updated_at_utc",
    "revision",
)
_OPTIONAL_FIELDS = (
    "predecessor_run_id",
    "retry_reason",
    "primary_terminal_diagnostic_id",
    "availability_observation_id",
    "finalization_deadline_utc",
)
_ALL_STATES = tuple(EngineRunState)
_ALL_PAIRS = tuple((a, b) for a in _ALL_STATES for b in _ALL_STATES)
_NON_TERMINAL_STATES = (_R.PENDING, _R.VALIDATING, _R.READY, _R.STARTING, _R.RUNNING)
_SUCCESS_STATES = (_R.SUCCEEDED, _R.SUCCEEDED_WITH_WARNINGS)
_NON_SUCCESS_TERMINAL_STATES = (
    _R.FAILED,
    _R.CANCELLED,
    _R.TIMED_OUT,
    _R.NOT_APPLICABLE,
    _R.UNAVAILABLE,
)
_TERMINAL_STATES = _SUCCESS_STATES + _NON_SUCCESS_TERMINAL_STATES
#: Plan section 3.8 row 14 and section 5: ``availability_observation_id`` is absent
#: before ``READY``, present from ``READY`` onward and in ``UNAVAILABLE``, and
#: predecessor-dependent in the four terminals that ``VALIDATING`` reaches directly.
_OBSERVATION_PROHIBITED = (_R.PENDING, _R.VALIDATING)
_OBSERVATION_REQUIRED = (
    _R.READY,
    _R.STARTING,
    _R.RUNNING,
    _R.SUCCEEDED,
    _R.SUCCEEDED_WITH_WARNINGS,
    _R.UNAVAILABLE,
)
_OBSERVATION_OPTIONAL = (_R.FAILED, _R.CANCELLED, _R.TIMED_OUT, _R.NOT_APPLICABLE)
_LINKED_EDGES = ((_R.READY, _R.STARTING), (_R.STARTING, _R.RUNNING))
_REVISION: dict[EngineRunState, int] = {
    _R.PENDING: 0,
    _R.VALIDATING: 1,
    _R.READY: 2,
    _R.STARTING: 3,
    _R.RUNNING: 4,
    _R.SUCCEEDED: 5,
    _R.SUCCEEDED_WITH_WARNINGS: 5,
    _R.FAILED: 5,
    _R.CANCELLED: 5,
    _R.TIMED_OUT: 5,
    _R.NOT_APPLICABLE: 5,
    _R.UNAVAILABLE: 5,
}
_INVOCATION_TERMINAL_STATES = (
    _C.EXITED,
    _C.FAILED_TO_START,
    _C.CANCELLED,
    _C.TIMED_OUT,
    _C.PROTOCOL_FAILED,
)
_INVOCATION_PREDECESSORS = (_C.PENDING, _C.STARTING, _C.RUNNING)
#: Plan section 6: the run state a linked ``RUN`` invocation's own state implies
#: (parent eligibility for PENDING, ``begin_linked_launch`` for STARTING and
#: ``start_linked_run`` for RUNNING); a ``VALIDATE`` invocation's run stays
#: ``VALIDATING``. Used only to cross-check the mapping against the Task 1 table.
_RUN_STATE_FOR_RUN_INVOCATION = {
    _C.PENDING: _R.READY,
    _C.STARTING: _R.STARTING,
    _C.RUNNING: _R.RUNNING,
}

_ABSENT: Final = object()


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


def _observed_default(state: EngineRunState) -> bool:
    return state not in _OBSERVATION_PROHIBITED


def _payload(
    state: EngineRunState,
    *,
    attempt_number: int = 1,
    observed: bool | None = None,
) -> dict[str, object]:
    """A record whose state-governed fields are consistent with ``state``.

    ``observed`` fixes ``availability_observation_id`` for the four
    predecessor-dependent terminals; every other state has exactly one shape.
    """
    observed = _observed_default(state) if observed is None else observed
    revision = _REVISION[state]
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "run_id": _RUN_ID,
        "experiment_id": _EXPERIMENT_ID,
        "logical_slot_id": _SLOT_ID,
        "attempt_number": attempt_number,
        "attempt_token_hash": _TOKEN_HASH,
        "state": state,
        "adapter": _ADAPTER,
        "engine": _ENGINE,
        "request_hash": _REQUEST_HASH,
        "created_at_utc": _CREATED,
        "updated_at_utc": _CREATED + timedelta(seconds=revision),
        "revision": revision,
    }
    if attempt_number > 1:
        payload["predecessor_run_id"] = _PREDECESSOR_RUN_ID
        payload["retry_reason"] = RetryTerminalState.FAILED
    if observed:
        payload["availability_observation_id"] = _OBSERVATION_ID
    if state in _NON_SUCCESS_TERMINAL_STATES:
        payload["primary_terminal_diagnostic_id"] = _DIAG_ID
    return payload


def _record(
    state: EngineRunState = _R.PENDING, /, **overrides: object
) -> EngineRunRecord:
    """A shaped record; ``observed=`` fixes the predecessor-dependent observation
    and ``attempt_number=`` adds the successor facts; ``_ABSENT`` removes a key."""
    observed = overrides.pop("observed", None)
    assert observed is None or isinstance(observed, bool)
    attempt_number = overrides.get("attempt_number", 1)
    # A genuine successor number selects the successor shape; a probe value (a
    # string, a float, a bool) is applied raw so the record itself rejects it.
    successor = type(attempt_number) is int and attempt_number > 1
    payload = _payload(state, attempt_number=2 if successor else 1, observed=observed)
    _apply(payload, overrides)
    return EngineRunRecord.model_validate(payload)


def _successor(
    state: EngineRunState = _R.PENDING, **overrides: object
) -> EngineRunRecord:
    return _record(state, attempt_number=2, **overrides)


def _rebuild(instance: EngineRunRecord, **overrides: object) -> EngineRunRecord:
    """Rebuild through validation, never through ``model_copy``."""
    payload = instance.model_dump(mode="python")
    _apply(payload, overrides)
    return EngineRunRecord.model_validate(payload)


def _advance(
    stored: EngineRunRecord,
    target: EngineRunState,
    **overrides: object,
) -> EngineRunRecord:
    """The replacement a correct service would build for ``stored -> target``.

    Establishes ``availability_observation_id`` where the target requires it and
    drops it where the target prohibits it, adds the primary terminal diagnostic
    exactly on a non-success terminal target, carries everything else forward,
    moves ``updated_at_utc`` forward and increments ``revision``. It is shape-valid
    for every target, so a rejected pair is rejected for the pair rule alone.
    """
    payload = stored.model_dump(mode="python")
    instant = stored.updated_at_utc + timedelta(seconds=1)
    payload["state"] = target
    if target in _OBSERVATION_PROHIBITED:
        payload.pop("availability_observation_id", None)
    elif target in _OBSERVATION_REQUIRED:
        payload.setdefault("availability_observation_id", _OBSERVATION_ID)
    if target in _NON_SUCCESS_TERMINAL_STATES:
        payload["primary_terminal_diagnostic_id"] = _DIAG_ID
    else:
        payload.pop("primary_terminal_diagnostic_id", None)
    payload["updated_at_utc"] = instant
    payload["revision"] = stored.revision + 1
    _apply(payload, overrides)
    return EngineRunRecord.model_validate(payload)


def _pid_identity() -> ProcessIdentity:
    return ProcessIdentity.model_validate(
        {
            "pid": 4321,
            "creation_identity": "2026-09-07T12:00:03.1234567Z#0001",
            "executable_path": r"C:\adapters\alpha\adapter.exe",
            "executable_hash": _EXECUTABLE_HASH,
            "supervisor_instance_id": "supervisor-01",
        }
    )


def _invocation(
    state: CommandInvocationState,
    via: CommandInvocationState | None = None,
    **overrides: object,
) -> CommandInvocationRecord:
    """A shaped ``RUN``-kind invocation linked to ``_RUN_ID`` (Task 3 shape rules).

    ``via`` names the predecessor for ``CANCELLED`` and ``TIMED_OUT``; an
    ``EXITED`` record carries a captured exit ``0`` mapped to ``SUCCESS`` so the
    tests can prove that a process-level success implies nothing about the run.
    """
    if via is None:
        via = _C.RUNNING if state in (_C.CANCELLED, _C.TIMED_OUT) else None
    launch = _CREATED + timedelta(seconds=1)
    timeout = 120
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "invocation_id": _INVOCATION_ID,
        "command_kind": _K.RUN,
        "adapter_name": "adapter.alpha",
        "adapter_version": "1.0.0",
        "run_id": _RUN_ID,
        "request_hash": _REQUEST_HASH,
        "timeout_seconds": timeout,
        "state": state,
        "process_created": False,
        "cleanup_complete": False,
        "diagnostic_ids": (),
        "created_at_utc": _CREATED,
        "updated_at_utc": _CREATED,
        "revision": 0,
    }
    launched = state is not _C.PENDING and not (
        state is _C.CANCELLED and via is _C.PENDING
    )
    if launched:
        payload["deadline_utc"] = launch + timedelta(seconds=timeout)
        payload["launch_attempted_at_utc"] = launch
        payload["updated_at_utc"] = launch
        payload["revision"] = 1
    process = state in (_C.RUNNING, _C.EXITED, _C.PROTOCOL_FAILED) or (
        state in (_C.CANCELLED, _C.TIMED_OUT) and via is _C.RUNNING
    )
    if process:
        payload["process_created"] = True
        payload["process_started_at_utc"] = launch + timedelta(seconds=2)
        payload["pid_identity"] = _pid_identity()
        payload["updated_at_utc"] = launch + timedelta(seconds=2)
        payload["revision"] = 2
    if state in TERMINAL_COMMAND_INVOCATION_STATES:
        completed = launch + timedelta(seconds=10)
        payload["completed_at_utc"] = completed
        payload["updated_at_utc"] = completed
        payload["revision"] = 3
        if state is _C.EXITED:
            payload["native_exit_value"] = 0
            payload["process_exit_category"] = ProcessExitCategory.SUCCESS
        else:
            payload["primary_diagnostic_id"] = _DIAG_ID
            payload["diagnostic_ids"] = (_DIAG_ID,)
    _apply(payload, overrides)
    return CommandInvocationRecord.model_validate(payload)


def _material(**overrides: object) -> AttemptTokenMaterial:
    payload: dict[str, object] = {"run_id": _RUN_ID, "attempt_token": _TOKEN}
    _apply(payload, overrides)
    return AttemptTokenMaterial.model_validate(payload)


def _every_instance() -> tuple[CanonicalModel, ...]:
    return (_record(), _record(_R.RUNNING), _successor(_R.FAILED), _material())


def _module_source(module: ModuleType) -> str:
    assert module.__file__ is not None
    return Path(module.__file__).read_text(encoding="utf-8")


def _check_of(info: pytest.ExceptionInfo[EngineRunRuleViolation]) -> EngineRunCheck:
    return info.value.check


# --- Shared conventions (plan section 3.1) ---------------------------------------


@pytest.mark.parametrize("instance", _every_instance(), ids=lambda m: type(m).__name__)
def test_every_task_four_model_rejects_an_unknown_field(
    instance: CanonicalModel,
) -> None:
    payload = instance.model_dump(mode="python")
    assert type(instance).model_validate(payload) == instance
    payload["unexpected"] = "rejected"
    with pytest.raises(ValidationError, match="extra_forbidden"):
        type(instance).model_validate(payload)


@pytest.mark.parametrize("instance", _every_instance(), ids=lambda m: type(m).__name__)
def test_every_task_four_model_is_frozen(instance: CanonicalModel) -> None:
    """Preventive for the inherited configuration; the nested identities are
    asserted separately below because deep immutability is not inherited."""
    first = next(iter(type(instance).model_fields))
    with pytest.raises(ValidationError):
        setattr(instance, first, getattr(instance, first))


def test_every_task_four_model_derives_from_the_canonical_base() -> None:
    for model in (EngineRunRecord, AttemptTokenMaterial):
        assert issubclass(model, CanonicalModel)
        assert model.model_config["extra"] == "forbid"
        assert model.model_config["frozen"] is True
        assert model.model_config["strict"] is True


def test_nested_adapter_and_engine_identities_are_immutable_through_the_record() -> (
    None
):
    record = _record()
    with pytest.raises(ValidationError):
        record.adapter.adapter_name = "adapter.beta"
    with pytest.raises(ValidationError):
        record.engine.engine_version = "9.9.9"


def test_strict_mode_refuses_coercion_for_integers_and_booleans() -> None:
    for field, value in (
        ("attempt_number", "1"),
        ("attempt_number", True),
        ("attempt_number", 1.0),
        ("revision", "0"),
        ("revision", True),
        ("revision", 0.0),
    ):
        with pytest.raises(ValidationError):
            _record(**{field: value})


def test_the_record_declares_exactly_the_eighteen_plan_fields_in_order() -> None:
    assert tuple(EngineRunRecord.model_fields) == _RECORD_FIELDS
    assert len(_RECORD_FIELDS) == 18


def test_exactly_the_five_state_governed_fields_are_optional() -> None:
    required = tuple(
        name
        for name, field in EngineRunRecord.model_fields.items()
        if field.is_required()
    )
    assert required == tuple(f for f in _RECORD_FIELDS if f not in _OPTIONAL_FIELDS)
    assert len(required) == 13
    for name in _OPTIONAL_FIELDS:
        assert EngineRunRecord.model_fields[name].default is MISSING, name
    schema = EngineRunRecord.model_json_schema()
    assert schema["required"] == list(required)
    # Task 9 publishes field 15 as an optional property the runtime rejects.
    assert "finalization_deadline_utc" in schema["properties"]


def test_engine_run_state_holds_exactly_the_twelve_specification_members() -> None:
    """Preventive: Task 1 fixed the membership; Task 4 consumes it as closed and
    partitions it into five non-terminal, two success and five non-success terminal
    states (plan section 5)."""
    assert [m.value for m in EngineRunState] == [
        "PENDING",
        "VALIDATING",
        "READY",
        "STARTING",
        "RUNNING",
        "SUCCEEDED",
        "SUCCEEDED_WITH_WARNINGS",
        "FAILED",
        "CANCELLED",
        "TIMED_OUT",
        "NOT_APPLICABLE",
        "UNAVAILABLE",
    ]
    assert TERMINAL_ENGINE_RUN_STATES == frozenset(_TERMINAL_STATES)
    assert SUCCESS_ENGINE_RUN_STATES == frozenset(_SUCCESS_STATES)
    assert NON_SUCCESS_TERMINAL_ENGINE_RUN_STATES == frozenset(
        _NON_SUCCESS_TERMINAL_STATES
    )
    assert SUCCESS_ENGINE_RUN_STATES | NON_SUCCESS_TERMINAL_ENGINE_RUN_STATES == (
        TERMINAL_ENGINE_RUN_STATES
    )
    assert SUCCESS_ENGINE_RUN_STATES.isdisjoint(NON_SUCCESS_TERMINAL_ENGINE_RUN_STATES)
    assert frozenset(_NON_TERMINAL_STATES) | TERMINAL_ENGINE_RUN_STATES == frozenset(
        _ALL_STATES
    )
    assert len(_NON_TERMINAL_STATES) + len(_TERMINAL_STATES) == 12


@pytest.mark.parametrize("field", ["created_at_utc", "updated_at_utc"])
def test_a_naive_or_offset_timestamp_is_rejected_on_every_instant_field(
    field: str,
) -> None:
    with pytest.raises(ValidationError, match="timezone-aware UTC"):
        _record(**{field: _NAIVE})
    with pytest.raises(ValidationError, match="offset must be UTC"):
        _record(**{field: _OFFSET})
    # Field 15 is validated as an instant before the shape rule rejects its presence.
    with pytest.raises(ValidationError, match="timezone-aware UTC"):
        _record(finalization_deadline_utc=_NAIVE)


def test_every_timestamp_uses_the_forward_schema_view() -> None:
    """Plan section 2.6: every Stage 5 timestamp field uses the calendar-valid view,
    so Task 9's registration passes the merged forward-view guard unchanged."""
    for mode in ("validation", "serialization"):
        schema = EngineRunRecord.model_json_schema(mode=mode)
        assert "UtcDateTime" not in schema.get("$defs", {})
        assert "CalendarValidUtcDateTime" in schema["$defs"]


# --- Attempt token material (plan section 3.8) ------------------------------------


def test_attempt_token_material_is_exactly_run_id_and_raw_token() -> None:
    assert tuple(AttemptTokenMaterial.model_fields) == ("run_id", "attempt_token")
    assert "schema_version" not in AttemptTokenMaterial.model_fields
    material = _material()
    assert material.run_id == _RUN_ID
    assert material.attempt_token == _TOKEN
    assert attempt_token_hash(material.attempt_token) == _record().attempt_token_hash


def test_attempt_token_material_validates_the_token_shape() -> None:
    with pytest.raises(ValidationError):
        _material(attempt_token="A" * 31)
    with pytest.raises(ValidationError):
        _material(attempt_token="A" * 1025)
    with pytest.raises(ValidationError):
        _material(attempt_token="A" * 31 + "!")
    with pytest.raises(ValidationError):
        _material(run_id=_EXPERIMENT_ID)
    with pytest.raises(ValidationError):
        _material(attempt_token=_ABSENT)
    assert _material(attempt_token="a-_" * 12).attempt_token == "a-_" * 12


def test_the_raw_token_never_appears_in_the_record_or_its_repr() -> None:
    """The token is temporary sensitive correlation material: hashed into field 6,
    never a persisted field, and hidden from the material's own ``repr``. The
    dumps still carry it, because the operation's caller needs the raw value to
    build the Stage 6 request; never dumping the material is the service's rule."""
    assert "attempt_token" not in EngineRunRecord.model_fields
    assert "attempt_token" not in EngineRunRecord.model_json_schema()["properties"]
    for field in EngineRunRecord.model_fields.values():
        assert field.annotation is not AttemptTokenMaterial
    material = _material()
    assert _TOKEN not in repr(material)
    assert _TOKEN not in str(material)
    assert material.model_dump(mode="json")["attempt_token"] == _TOKEN


# --- Attempt number and predecessor rules (plan sections 3.8 and 5) ---------------


def test_attempt_number_is_bounded_one_through_five() -> None:
    assert MAX_ATTEMPTS_PER_SLOT == 5
    with pytest.raises(ValidationError):
        _record(attempt_number=0)
    with pytest.raises(ValidationError):
        _record(attempt_number=MAX_ATTEMPTS_PER_SLOT + 1)
    assert _record(attempt_number=1).attempt_number == 1
    for attempt in range(2, MAX_ATTEMPTS_PER_SLOT + 1):
        assert _record(attempt_number=attempt).attempt_number == attempt


def test_an_initial_attempt_carries_no_predecessor_and_no_retry_reason() -> None:
    record = _record()
    assert _missing(record.predecessor_run_id)
    assert _missing(record.retry_reason)
    with pytest.raises(ValidationError, match="predecessor_run_id"):
        _record(predecessor_run_id=_PREDECESSOR_RUN_ID)
    with pytest.raises(ValidationError, match="retry_reason"):
        _record(retry_reason=RetryTerminalState.FAILED)
    with pytest.raises(ValidationError):
        _record(
            predecessor_run_id=_PREDECESSOR_RUN_ID,
            retry_reason=RetryTerminalState.FAILED,
        )


@pytest.mark.parametrize("attempt", range(2, MAX_ATTEMPTS_PER_SLOT + 1))
def test_a_successor_attempt_requires_both_predecessor_and_retry_reason(
    attempt: int,
) -> None:
    record = _record(attempt_number=attempt)
    assert record.predecessor_run_id == _PREDECESSOR_RUN_ID
    assert record.retry_reason is RetryTerminalState.FAILED
    with pytest.raises(ValidationError, match="predecessor_run_id"):
        _record(attempt_number=attempt, predecessor_run_id=_ABSENT)
    with pytest.raises(ValidationError, match="retry_reason"):
        _record(attempt_number=attempt, retry_reason=_ABSENT)
    with pytest.raises(ValidationError):
        _record(
            attempt_number=attempt, predecessor_run_id=_ABSENT, retry_reason=_ABSENT
        )


def test_a_run_is_never_its_own_predecessor() -> None:
    with pytest.raises(ValidationError, match="predecessor_run_id"):
        _successor(predecessor_run_id=_RUN_ID)


@pytest.mark.parametrize("reason", list(RetryTerminalState))
def test_every_retry_terminal_state_is_an_accepted_retry_reason(
    reason: RetryTerminalState,
) -> None:
    assert _successor(retry_reason=reason).retry_reason is reason


def test_retry_reason_is_a_strict_retry_terminal_state() -> None:
    with pytest.raises(ValidationError):
        _successor(retry_reason="FAILED")
    with pytest.raises(ValidationError):
        _successor(retry_reason=_R.FAILED)
    with pytest.raises(ValidationError):
        _successor(retry_reason="CANCELLED")


def test_identity_fields_are_prefixed_uuid4_identifiers_and_hashes_are_sha256() -> None:
    for field, value in (
        ("run_id", _EXPERIMENT_ID),
        ("experiment_id", _RUN_ID),
        ("logical_slot_id", _RUN_ID),
        ("attempt_token_hash", "A" * 64),
        ("attempt_token_hash", "a" * 63),
        ("request_hash", "g" * 64),
    ):
        with pytest.raises(ValidationError):
            _record(**{field: value})
    record = _record()
    assert record.attempt_token_hash == attempt_token_hash(_TOKEN)
    assert len(record.attempt_token_hash) == 64


# --- State-governed field shapes (plan sections 3.8 and 5) ------------------------


@pytest.mark.parametrize("state", _ALL_STATES)
def test_every_state_has_a_constructible_consistent_shape(
    state: EngineRunState,
) -> None:
    record = _record(state)
    assert record.state is state
    assert _missing(record.primary_terminal_diagnostic_id) is not (
        state in NON_SUCCESS_TERMINAL_ENGINE_RUN_STATES
    )
    assert _missing(record.finalization_deadline_utc)


def test_the_observation_tables_partition_every_state() -> None:
    prohibited = set(_OBSERVATION_PROHIBITED)
    required = set(_OBSERVATION_REQUIRED)
    optional = set(_OBSERVATION_OPTIONAL)
    assert prohibited.isdisjoint(required)
    assert prohibited.isdisjoint(optional)
    assert required.isdisjoint(optional)
    assert prohibited | required | optional == set(_ALL_STATES)
    # The optional four are exactly the terminals reachable from VALIDATING that
    # are not UNAVAILABLE, which is why their observation is predecessor-dependent.
    assert optional == {
        s
        for s in ENGINE_RUN_TRANSITIONS.permitted_successors(_R.VALIDATING)
        if s in TERMINAL_ENGINE_RUN_STATES and s is not _R.UNAVAILABLE
    }


@pytest.mark.parametrize("state", _OBSERVATION_PROHIBITED)
def test_the_availability_observation_is_rejected_before_ready(
    state: EngineRunState,
) -> None:
    with pytest.raises(ValidationError, match="availability_observation_id"):
        _record(state, availability_observation_id=_OBSERVATION_ID)
    assert _missing(_record(state).availability_observation_id)


@pytest.mark.parametrize("state", _OBSERVATION_REQUIRED)
def test_the_availability_observation_is_required_from_ready_onward_and_in_unavailable(
    state: EngineRunState,
) -> None:
    with pytest.raises(ValidationError, match="availability_observation_id"):
        _record(state, availability_observation_id=_ABSENT)
    assert _record(state).availability_observation_id == _OBSERVATION_ID


@pytest.mark.parametrize("state", _OBSERVATION_OPTIONAL)
def test_the_availability_observation_follows_the_predecessor_in_the_other_terminals(
    state: EngineRunState,
) -> None:
    present = _record(state, observed=True)
    absent = _record(state, observed=False)
    assert present.availability_observation_id == _OBSERVATION_ID
    assert _missing(absent.availability_observation_id)


@pytest.mark.parametrize("state", _NON_SUCCESS_TERMINAL_STATES)
def test_the_primary_terminal_diagnostic_is_required_in_every_non_success_terminal(
    state: EngineRunState,
) -> None:
    with pytest.raises(ValidationError, match="primary_terminal_diagnostic_id"):
        _record(state, primary_terminal_diagnostic_id=_ABSENT)
    assert _record(state).primary_terminal_diagnostic_id == _DIAG_ID


@pytest.mark.parametrize("state", _NON_TERMINAL_STATES + _SUCCESS_STATES)
def test_the_primary_terminal_diagnostic_is_rejected_outside_those_five(
    state: EngineRunState,
) -> None:
    with pytest.raises(ValidationError, match="primary_terminal_diagnostic_id"):
        _record(state, primary_terminal_diagnostic_id=_DIAG_ID)
    assert _missing(_record(state).primary_terminal_diagnostic_id)


@pytest.mark.parametrize("state", _ALL_STATES)
def test_the_finalization_deadline_is_rejected_throughout_stage_five(
    state: EngineRunState,
) -> None:
    with pytest.raises(ValidationError, match="finalization_deadline_utc"):
        _record(state, finalization_deadline_utc=_LATER)
    assert _missing(_record(state).finalization_deadline_utc)


def test_updated_at_may_not_precede_created_at() -> None:
    with pytest.raises(ValidationError, match="updated_at_utc"):
        _record(updated_at_utc=_CREATED - timedelta(seconds=1))
    assert _record(updated_at_utc=_CREATED).updated_at_utc == _CREATED
    assert _record(updated_at_utc=_LATER).updated_at_utc == _LATER


def test_revision_is_a_non_negative_strict_integer() -> None:
    with pytest.raises(ValidationError):
        _record(revision=-1)
    assert _record(revision=0).revision == 0
    assert _record(revision=7).revision == 7


def test_the_record_carries_no_command_process_or_result_fact() -> None:
    """Specification 11.5: the run links to its invocations but does not duplicate
    their PID, native-exit, deadline or stderr facts; result manifests and
    artifacts are later-stage aggregates and never fields here."""
    for name in (
        "pid_identity",
        "process_created",
        "process_started_at_utc",
        "native_exit_value",
        "process_exit_category",
        "deadline_utc",
        "launch_attempted_at_utc",
        "stderr_artifact_id",
        "invocation_id",
        "run_manifest",
        "run_manifest_hash",
        "semantic_status",
        "artifact_refs",
        "result_lease",
        "attempt_token",
    ):
        assert name not in EngineRunRecord.model_fields, name


# --- Determinism and dumps (plan section 3.1) --------------------------------------


@pytest.mark.parametrize("field", _OPTIONAL_FIELDS)
def test_absent_fields_are_omitted_from_both_dump_modes_and_null_is_rejected(
    field: str,
) -> None:
    record = _record()
    assert getattr(record, field) is MISSING
    assert field not in record.model_dump(mode="json")
    assert field not in record.model_dump(mode="python")
    payload = record.model_dump(mode="python")
    payload[field] = None
    with pytest.raises(ValidationError):
        EngineRunRecord.model_validate(payload)


@pytest.mark.parametrize("state", _ALL_STATES)
@pytest.mark.parametrize("attempt", [1, 2], ids=["initial", "successor"])
def test_every_shaped_record_round_trips_through_json_deterministically(
    state: EngineRunState,
    attempt: int,
) -> None:
    record = _record(state, attempt_number=attempt)
    again = EngineRunRecord.model_validate_json(record.model_dump_json())
    assert again == record
    assert canonical_json_bytes(again) == canonical_json_bytes(record)
    assert canonical_json_bytes(_rebuild(record)) == canonical_json_bytes(record)
    dumped = record.model_dump(mode="json")
    assert tuple(dumped) == tuple(f for f in _RECORD_FIELDS if f in dumped)
    assert dumped["state"] == state.value
    assert dumped["created_at_utc"] == "2026-09-07T12:00:00Z"
    assert dumped["adapter"] == {
        "adapter_name": "adapter.alpha",
        "adapter_version": "1.0.0",
    }
    assert dumped["engine"] == {
        "engine_name": "engine.alpha",
        "engine_version": "2.0.0",
    }
    if attempt == 2:
        assert dumped["retry_reason"] == "FAILED"
        assert dumped["predecessor_run_id"] == _PREDECESSOR_RUN_ID


# --- Terminal immutability (plan section 3.8) --------------------------------------


def _terminal_mutations(state: EngineRunState) -> list[tuple[str, dict[str, object]]]:
    """Every field of a terminal record with a shape-valid alternative value."""
    # A non-success terminal moves to a success state (dropping its primary
    # diagnostic); a success state moves to FAILED (gaining one).
    other_state = _R.SUCCEEDED if state in _NON_SUCCESS_TERMINAL_STATES else _R.FAILED
    mutations: list[tuple[str, dict[str, object]]] = [
        ("experiment_id", {"experiment_id": _OTHER_EXPERIMENT_ID}),
        ("logical_slot_id", {"logical_slot_id": _OTHER_SLOT_ID}),
        (
            "attempt_number",
            {
                "attempt_number": 2,
                "predecessor_run_id": _PREDECESSOR_RUN_ID,
                "retry_reason": RetryTerminalState.FAILED,
            },
        ),
        ("attempt_token_hash", {"attempt_token_hash": _OTHER_TOKEN_HASH}),
        ("adapter", {"adapter": _OTHER_ADAPTER}),
        ("engine", {"engine": _OTHER_ENGINE}),
        ("request_hash", {"request_hash": _OTHER_REQUEST_HASH}),
        ("created_at_utc", {"created_at_utc": _CREATED - timedelta(seconds=1)}),
        ("updated_at_utc", {"updated_at_utc": _LATER}),
        ("revision", {"revision": _REVISION[state] + 1}),
    ]
    if state in _NON_SUCCESS_TERMINAL_STATES:
        mutations.append(
            (
                "primary_terminal_diagnostic_id",
                {"primary_terminal_diagnostic_id": _OTHER_DIAG_ID},
            )
        )
        mutations.append(
            (
                "state",
                {
                    "state": other_state,
                    "primary_terminal_diagnostic_id": _ABSENT,
                    "availability_observation_id": _OBSERVATION_ID,
                },
            )
        )
    else:
        mutations.append(
            (
                "state",
                {"state": other_state, "primary_terminal_diagnostic_id": _DIAG_ID},
            )
        )
    if state in _OBSERVATION_REQUIRED:
        mutations.append(
            (
                "availability_observation_id",
                {"availability_observation_id": _FRESH_OBSERVATION_ID},
            )
        )
    else:
        mutations.append(
            ("availability_observation_id", {"availability_observation_id": _ABSENT})
        )
    return mutations


@pytest.mark.parametrize("state", _TERMINAL_STATES)
def test_a_terminal_record_rejects_every_field_change_including_a_revision_bump(
    state: EngineRunState,
) -> None:
    stored = _record(state)
    for field, mutation in _terminal_mutations(state):
        replacement = _rebuild(stored, **mutation)
        assert replacement != stored, field
        with pytest.raises(EngineRunRuleViolation) as info:
            assert_terminal_run_immutability(stored, replacement)
        assert _check_of(info) is _CHECK.TERMINAL_IMMUTABLE, field
        assert field in str(info.value), field


@pytest.mark.parametrize("state", _TERMINAL_STATES)
def test_an_identical_restatement_of_a_terminal_record_is_not_a_change(
    state: EngineRunState,
) -> None:
    """Idempotent replay returns the stored record with no write (plan section 4);
    the predicate therefore accepts only a field-for-field identical restatement."""
    stored = _record(state)
    assert_terminal_run_immutability(stored, _rebuild(stored))
    assert_terminal_run_immutability(stored, stored)


@pytest.mark.parametrize("state", _NON_TERMINAL_STATES)
def test_the_terminal_predicate_guards_only_terminal_records(
    state: EngineRunState,
) -> None:
    """A non-terminal record is governed by the transition predicate instead; the
    terminal predicate holds vacuously so a service can apply it to every write."""
    stored = _record(state)
    assert_terminal_run_immutability(
        stored, _rebuild(stored, revision=stored.revision + 1)
    )


@pytest.mark.parametrize("state", _TERMINAL_STATES)
def test_a_terminal_successor_rejects_a_changed_predecessor_or_retry_reason(
    state: EngineRunState,
) -> None:
    """Strengthening: the two successor-only fields probed alone on a terminal
    successor record, so the generic field walk is proven to reach them. Begins
    green, because the walk covers every field."""
    stored = _successor(state)
    for field, value in (
        ("predecessor_run_id", _OTHER_RUN_ID),
        ("retry_reason", RetryTerminalState.TIMED_OUT),
    ):
        with pytest.raises(EngineRunRuleViolation) as info:
            assert_terminal_run_immutability(stored, _rebuild(stored, **{field: value}))
        assert _check_of(info) is _CHECK.TERMINAL_IMMUTABLE, field
        assert field in str(info.value), field


@pytest.mark.parametrize("state", _TERMINAL_STATES)
def test_an_identical_terminal_restatement_is_still_not_a_transition(
    state: EngineRunState,
) -> None:
    """The immutability predicate tolerates an identical restatement, but the
    transition predicate never accepts a terminal stored record and names the
    terminal rule, not the reflexive-edge rule, for every owner."""
    stored = _record(state)
    for owner in RunEdgeOwner:
        with pytest.raises(EngineRunRuleViolation) as info:
            assert_run_transition(stored, _rebuild(stored), owner=owner)
        assert _check_of(info) is _CHECK.TERMINAL_IMMUTABLE, owner
        with pytest.raises(EngineRunRuleViolation) as again:
            assert_run_transition(stored, stored, owner=owner)
        assert _check_of(again) is _CHECK.TERMINAL_IMMUTABLE, owner


def test_the_terminal_predicate_checks_identity_first() -> None:
    stored = _record(_R.SUCCEEDED)
    with pytest.raises(EngineRunRuleViolation) as info:
        assert_terminal_run_immutability(stored, _rebuild(stored, run_id=_OTHER_RUN_ID))
    assert _check_of(info) is _CHECK.IDENTITY


@pytest.mark.parametrize("state", _TERMINAL_STATES)
def test_a_terminal_record_accepts_no_transition_to_any_state(
    state: EngineRunState,
) -> None:
    """Retry never reopens a terminal attempt: a successor is a new record."""
    stored = _record(state)
    for target in _ALL_STATES:
        replacement = _advance(stored, target)
        for owner in RunEdgeOwner:
            with pytest.raises(EngineRunRuleViolation) as info:
                assert_run_transition(stored, replacement, owner=owner)
            assert _check_of(info) is _CHECK.TERMINAL_IMMUTABLE, (target, owner)


# --- Edge ownership and the pure transition predicate (plan section 5) -------------


def _expected_check(
    current: EngineRunState,
    target: EngineRunState,
    owner: RunEdgeOwner,
) -> EngineRunCheck | None:
    if current in TERMINAL_ENGINE_RUN_STATES:
        return _CHECK.TERMINAL_IMMUTABLE
    if not ENGINE_RUN_TRANSITIONS.is_allowed(current, target):
        return _CHECK.TRANSITION_EDGE
    linked = (current, target) in _LINKED_EDGES
    if linked is not (owner is _LINKED):
        return _CHECK.TRANSITION_EDGE_OWNERSHIP
    return None


def test_the_edge_owner_vocabulary_is_the_two_plan_authorities() -> None:
    assert [m.value for m in RunEdgeOwner] == ["GENERIC", "LINKED_LAUNCH"]
    assert LINKED_ONLY_RUN_EDGES == frozenset(_LINKED_EDGES)
    assert len(LINKED_ONLY_RUN_EDGES) == 2
    # Both remain table members: ownership is a service rule, not a table rule.
    for current, target in _LINKED_EDGES:
        assert ENGINE_RUN_TRANSITIONS.is_allowed(current, target)


@pytest.mark.parametrize(
    ("current", "target"),
    _ALL_PAIRS,
    ids=[f"{a.value}->{b.value}" for a, b in _ALL_PAIRS],
)
def test_every_table_edge_has_exactly_one_owner_and_a_non_edge_has_none(
    current: EngineRunState,
    target: EngineRunState,
) -> None:
    if not ENGINE_RUN_TRANSITIONS.is_allowed(current, target):
        with pytest.raises(ValueError, match="not a permitted engine-run edge"):
            run_edge_owner(current, target)
        return
    owner = run_edge_owner(current, target)
    assert owner is (_LINKED if (current, target) in _LINKED_EDGES else _GENERIC)


def test_the_edge_owner_predicate_refuses_a_foreign_member() -> None:
    with pytest.raises(TypeError):
        run_edge_owner("READY", _R.STARTING)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        run_edge_owner(_R.READY, "STARTING")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        run_edge_owner(_R.READY, _C.STARTING)  # type: ignore[arg-type]


@pytest.mark.parametrize("owner", list(RunEdgeOwner))
@pytest.mark.parametrize(
    ("current", "target"),
    _ALL_PAIRS,
    ids=[f"{a.value}->{b.value}" for a, b in _ALL_PAIRS],
)
def test_each_authority_accepts_exactly_the_edges_it_owns(
    current: EngineRunState,
    target: EngineRunState,
    owner: RunEdgeOwner,
) -> None:
    """288 cases: the generic authority (``transition_run`` and the coupled terminal
    operation) accepts the 21 non-linked edges, the linked-launch authority
    (``begin_linked_launch``, ``start_linked_run``) exactly the other two, and every
    other pair is refused for the loudest reason -- terminal, non-edge, ownership."""
    stored = _record(current)
    replacement = _advance(stored, target)
    expected = _expected_check(current, target, owner)
    if expected is None:
        assert_run_transition(stored, replacement, owner=owner)
        if owner is _GENERIC:
            assert_run_transition(stored, replacement)
        assert replacement.revision == stored.revision + 1
        return
    with pytest.raises(EngineRunRuleViolation) as info:
        assert_run_transition(stored, replacement, owner=owner)
    assert _check_of(info) is expected


def test_the_generic_and_linked_authorities_partition_the_twenty_three_edges() -> None:
    """Preventive arithmetic over Task 1's table: 23 edges, 2 linked, 21 generic."""
    assert len(ENGINE_RUN_TRANSITIONS.transitions) == 23
    assert len(_ALL_PAIRS) == 144
    accepted: dict[RunEdgeOwner, int] = {owner: 0 for owner in RunEdgeOwner}
    for current, target in _ALL_PAIRS:
        stored = _record(current)
        replacement = _advance(stored, target)
        for owner in RunEdgeOwner:
            try:
                assert_run_transition(stored, replacement, owner=owner)
            except EngineRunRuleViolation:
                continue
            accepted[owner] += 1
    assert accepted == {_GENERIC: 21, _LINKED: 2}
    assert sum(accepted.values()) == len(ENGINE_RUN_TRANSITIONS.transitions)


def test_a_reflexive_pair_is_never_an_edge_because_replay_is_a_service_rule() -> None:
    stored = _record(_R.VALIDATING)
    with pytest.raises(EngineRunRuleViolation) as info:
        assert_run_transition(stored, _advance(stored, _R.VALIDATING))
    assert _check_of(info) is _CHECK.TRANSITION_EDGE


def test_a_transition_between_different_runs_is_an_identity_violation() -> None:
    stored = _record(_R.PENDING)
    replacement = _advance(stored, _R.VALIDATING, run_id=_OTHER_RUN_ID)
    with pytest.raises(EngineRunRuleViolation) as info:
        assert_run_transition(stored, replacement)
    assert _check_of(info) is _CHECK.IDENTITY


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("experiment_id", _OTHER_EXPERIMENT_ID),
        ("logical_slot_id", _OTHER_SLOT_ID),
        ("attempt_token_hash", _OTHER_TOKEN_HASH),
        ("adapter", _OTHER_ADAPTER),
        ("engine", _OTHER_ENGINE),
        ("request_hash", _OTHER_REQUEST_HASH),
        ("created_at_utc", _CREATED - timedelta(seconds=1)),
    ],
)
def test_an_immutable_field_may_not_change_across_an_allowed_edge(
    field: str,
    value: object,
) -> None:
    stored = _record(_R.PENDING)
    replacement = _advance(stored, _R.VALIDATING, **{field: value})
    with pytest.raises(EngineRunRuleViolation) as info:
        assert_run_transition(stored, replacement)
    assert _check_of(info) is _CHECK.TRANSITION_IMMUTABLE_FIELD
    assert field in str(info.value)


def test_attempt_number_predecessor_and_retry_reason_are_immutable_across_an_edge() -> (
    None
):
    initial = _record(_R.PENDING)
    promoted = _advance(
        initial,
        _R.VALIDATING,
        attempt_number=2,
        predecessor_run_id=_PREDECESSOR_RUN_ID,
        retry_reason=RetryTerminalState.FAILED,
    )
    with pytest.raises(EngineRunRuleViolation) as info:
        assert_run_transition(initial, promoted)
    assert _check_of(info) is _CHECK.TRANSITION_IMMUTABLE_FIELD
    assert "attempt_number" in str(info.value)
    successor = _successor(_R.PENDING)
    for field, value in (
        ("predecessor_run_id", _OTHER_RUN_ID),
        ("retry_reason", RetryTerminalState.TIMED_OUT),
    ):
        replacement = _advance(successor, _R.VALIDATING, **{field: value})
        with pytest.raises(EngineRunRuleViolation) as again:
            assert_run_transition(successor, replacement)
        assert _check_of(again) is _CHECK.TRANSITION_IMMUTABLE_FIELD, field
        assert field in str(again.value)
    assert_run_transition(successor, _advance(successor, _R.VALIDATING))


def test_the_availability_observation_is_established_only_on_ready_or_unavailable() -> (
    None
):
    """Plan 3.8 row 14: request-governed on the transition into READY or UNAVAILABLE."""
    validating = _record(_R.VALIDATING)
    ready = _advance(validating, _R.READY)
    assert ready.availability_observation_id == _OBSERVATION_ID
    assert_run_transition(validating, ready)
    unavailable = _advance(validating, _R.UNAVAILABLE)
    assert unavailable.availability_observation_id == _OBSERVATION_ID
    assert_run_transition(validating, unavailable)
    # Any other target from an unobserved state may not invent one.
    for target in (_R.NOT_APPLICABLE, _R.FAILED, _R.CANCELLED, _R.TIMED_OUT):
        invented = _advance(
            validating, target, availability_observation_id=_OBSERVATION_ID
        )
        with pytest.raises(EngineRunRuleViolation) as info:
            assert_run_transition(validating, invented)
        assert _check_of(info) is _CHECK.TRANSITION_AVAILABILITY_OBSERVATION, target
        assert_run_transition(validating, _advance(validating, target))
    pending = _record(_R.PENDING)
    invented = _advance(
        pending, _R.CANCELLED, availability_observation_id=_OBSERVATION_ID
    )
    with pytest.raises(EngineRunRuleViolation) as again:
        assert_run_transition(pending, invented)
    assert _check_of(again) is _CHECK.TRANSITION_AVAILABILITY_OBSERVATION


def test_the_availability_observation_is_carried_unchanged_once_established() -> None:
    ready = _record(_R.READY)
    moved = _advance(
        ready, _R.STARTING, availability_observation_id=_FRESH_OBSERVATION_ID
    )
    with pytest.raises(EngineRunRuleViolation) as info:
        assert_run_transition(ready, moved, owner=_LINKED)
    assert _check_of(info) is _CHECK.TRANSITION_AVAILABILITY_OBSERVATION
    assert_run_transition(ready, _advance(ready, _R.STARTING), owner=_LINKED)
    starting = _record(_R.STARTING)
    moved = _advance(
        starting, _R.RUNNING, availability_observation_id=_FRESH_OBSERVATION_ID
    )
    with pytest.raises(EngineRunRuleViolation) as again:
        assert_run_transition(starting, moved, owner=_LINKED)
    assert _check_of(again) is _CHECK.TRANSITION_AVAILABILITY_OBSERVATION
    running = _record(_R.RUNNING)
    for target in (
        _R.SUCCEEDED,
        _R.SUCCEEDED_WITH_WARNINGS,
        _R.NOT_APPLICABLE,
        _R.FAILED,
        _R.CANCELLED,
        _R.TIMED_OUT,
    ):
        changed = _advance(
            running, target, availability_observation_id=_FRESH_OBSERVATION_ID
        )
        with pytest.raises(EngineRunRuleViolation) as third:
            assert_run_transition(running, changed)
        assert _check_of(third) is _CHECK.TRANSITION_AVAILABILITY_OBSERVATION, target
        assert_run_transition(running, _advance(running, target))


@pytest.mark.parametrize(
    "target", [_R.NOT_APPLICABLE, _R.FAILED, _R.CANCELLED, _R.TIMED_OUT]
)
def test_the_availability_observation_is_never_dropped_where_the_shape_would_allow_it(
    target: EngineRunState,
) -> None:
    """The four terminals admit an absent observation only for a predecessor that
    never had one; a run that reached RUNNING carries its observation into them."""
    running = _record(_R.RUNNING)
    dropped = _advance(running, target, availability_observation_id=_ABSENT)
    assert _missing(dropped.availability_observation_id)
    with pytest.raises(EngineRunRuleViolation) as info:
        assert_run_transition(running, dropped)
    assert _check_of(info) is _CHECK.TRANSITION_AVAILABILITY_OBSERVATION


@pytest.mark.parametrize("current", [_R.READY, _R.STARTING, _R.RUNNING])
def test_a_transition_into_unavailable_may_record_a_fresh_observation(
    current: EngineRunState,
) -> None:
    """Plan 3.8 row 14 makes the field request-governed on the transition into
    UNAVAILABLE, so a fresh unavailable observation is accepted there while an
    omitted request value carries the stored identity forward unchanged."""
    stored = _record(current)
    carried = _advance(stored, _R.UNAVAILABLE)
    assert carried.availability_observation_id == _OBSERVATION_ID
    assert_run_transition(stored, carried)
    fresh = _advance(
        stored, _R.UNAVAILABLE, availability_observation_id=_FRESH_OBSERVATION_ID
    )
    assert fresh.availability_observation_id == _FRESH_OBSERVATION_ID
    assert_run_transition(stored, fresh)


@pytest.mark.parametrize("target", _NON_SUCCESS_TERMINAL_STATES)
def test_a_non_success_terminal_transition_establishes_the_primary_diagnostic(
    target: EngineRunState,
) -> None:
    stored = _record(_R.RUNNING)
    replacement = _advance(stored, target)
    assert replacement.primary_terminal_diagnostic_id == _DIAG_ID
    assert_run_transition(stored, replacement)
    # The shape rule makes the field unrepresentable before the terminal write.
    with pytest.raises(ValidationError):
        _advance(stored, target, primary_terminal_diagnostic_id=_ABSENT)


@pytest.mark.parametrize("target", _SUCCESS_STATES)
def test_a_success_transition_carries_no_primary_terminal_diagnostic(
    target: EngineRunState,
) -> None:
    stored = _record(_R.RUNNING)
    replacement = _advance(stored, target)
    assert _missing(replacement.primary_terminal_diagnostic_id)
    assert_run_transition(stored, replacement)
    with pytest.raises(ValidationError):
        _advance(stored, target, primary_terminal_diagnostic_id=_DIAG_ID)


@pytest.mark.parametrize("delta", [0, 2, -1])
def test_a_transition_increments_the_revision_by_exactly_one(delta: int) -> None:
    stored = _record(_R.VALIDATING)
    replacement = _advance(stored, _R.READY, revision=stored.revision + delta)
    with pytest.raises(EngineRunRuleViolation) as info:
        assert_run_transition(stored, replacement)
    assert _check_of(info) is _CHECK.REVISION


def test_a_transition_never_moves_updated_at_backwards() -> None:
    stored = _record(_R.VALIDATING)
    equal = _advance(stored, _R.READY, updated_at_utc=stored.updated_at_utc)
    assert_run_transition(stored, equal)
    earlier = _advance(
        stored, _R.READY, updated_at_utc=stored.updated_at_utc - timedelta(seconds=1)
    )
    with pytest.raises(EngineRunRuleViolation) as info:
        assert_run_transition(stored, earlier)
    assert _check_of(info) is _CHECK.UPDATED_AT


def test_transition_checks_are_reported_in_a_fixed_order() -> None:
    """Identity, then terminal immutability, then edge, then ownership, then content."""
    stored = _record(_R.PENDING)
    foreign = _record(_R.READY, run_id=_OTHER_RUN_ID, revision=stored.revision + 5)
    with pytest.raises(EngineRunRuleViolation) as info:
        assert_run_transition(stored, foreign)
    assert _check_of(info) is _CHECK.IDENTITY
    wrong_edge = _record(_R.READY, revision=stored.revision + 5)
    with pytest.raises(EngineRunRuleViolation) as again:
        assert_run_transition(stored, wrong_edge)
    assert _check_of(again) is _CHECK.TRANSITION_EDGE
    terminal = _record(_R.SUCCEEDED)
    with pytest.raises(EngineRunRuleViolation) as third:
        assert_run_transition(
            terminal, _record(_R.READY, run_id=_OTHER_RUN_ID, revision=99)
        )
    assert _check_of(third) is _CHECK.IDENTITY
    with pytest.raises(EngineRunRuleViolation) as fourth:
        assert_run_transition(terminal, _record(_R.READY, revision=99))
    assert _check_of(fourth) is _CHECK.TERMINAL_IMMUTABLE
    ready = _record(_R.READY)
    with pytest.raises(EngineRunRuleViolation) as fifth:
        assert_run_transition(
            ready,
            _advance(ready, _R.STARTING, request_hash=_OTHER_REQUEST_HASH, revision=99),
        )
    assert _check_of(fifth) is _CHECK.TRANSITION_EDGE_OWNERSHIP


def test_a_full_lifecycle_walks_through_the_two_authorities() -> None:
    record = _record(_R.PENDING)
    for target, owner in (
        (_R.VALIDATING, _GENERIC),
        (_R.READY, _GENERIC),
        (_R.STARTING, _LINKED),
        (_R.RUNNING, _LINKED),
        (_R.SUCCEEDED, _GENERIC),
    ):
        following = _advance(record, target)
        assert run_edge_owner(record.state, target) is owner
        assert_run_transition(record, following, owner=owner)
        record = following
    assert record.state is _R.SUCCEEDED
    assert record.revision == 5
    assert record.availability_observation_id == _OBSERVATION_ID
    assert _missing(record.primary_terminal_diagnostic_id)
    with pytest.raises(EngineRunRuleViolation) as info:
        assert_terminal_run_immutability(record, _rebuild(record, revision=6))
    assert _check_of(info) is _CHECK.TERMINAL_IMMUTABLE


def test_the_check_vocabulary_is_closed_and_every_member_is_reachable() -> None:
    assert [m.value for m in EngineRunCheck] == [
        "IDENTITY",
        "REVISION",
        "UPDATED_AT",
        "TERMINAL_IMMUTABLE",
        "TRANSITION_EDGE",
        "TRANSITION_EDGE_OWNERSHIP",
        "TRANSITION_IMMUTABLE_FIELD",
        "TRANSITION_AVAILABILITY_OBSERVATION",
    ]
    source = _module_source(engine_run_module)
    for member in EngineRunCheck:
        assert source.count(f"EngineRunCheck.{member.name}") >= 1, member
    violation = EngineRunRuleViolation(_CHECK.IDENTITY, "probe")
    assert isinstance(violation, ValueError)
    assert violation.check is _CHECK.IDENTITY
    assert str(violation) == "probe"


# --- Coupled terminal mapping (plan section 6) ------------------------------------


def _expected_target(
    kind: CommandKind,
    terminal: CommandInvocationState,
    category: DiagnosticCategory | None,
) -> EngineRunState | None:
    """Plan section 6 "Coupled terminal transitions" table, restated as the oracle."""
    if kind is _K.DESCRIBE or terminal is _C.EXITED:
        return None
    if terminal is _C.FAILED_TO_START:
        return (
            _R.UNAVAILABLE
            if category is DiagnosticCategory.ADAPTER_UNAVAILABILITY
            else _R.FAILED
        )
    if terminal is _C.TIMED_OUT:
        return _R.TIMED_OUT
    if terminal is _C.CANCELLED:
        return _R.CANCELLED
    assert terminal is _C.PROTOCOL_FAILED
    return _R.FAILED


_TRIPLES = tuple(
    (kind, predecessor, terminal)
    for kind in CommandKind
    for predecessor in _INVOCATION_PREDECESSORS
    for terminal in _INVOCATION_TERMINAL_STATES
)
_COUPLING_TRIPLES = tuple(
    (kind, predecessor, terminal)
    for kind, predecessor, terminal in _TRIPLES
    if COMMAND_INVOCATION_TRANSITIONS.is_allowed(predecessor, terminal)
)


@pytest.mark.parametrize(
    ("kind", "predecessor", "terminal"),
    _TRIPLES,
    ids=[f"{k.value}:{p.value}->{t.value}" for k, p, t in _TRIPLES],
)
def test_the_coupled_mapping_is_total_over_every_kind_predecessor_terminal_triple(
    kind: CommandKind,
    predecessor: CommandInvocationState,
    terminal: CommandInvocationState,
) -> None:
    """Forty-five triples: a non-edge predecessor is rejected; every edge yields the
    section 6 row, ``MISSING`` for DESCRIBE (no linkage) and for EXITED (no run
    transition); and the run the plan implies for the linked kind and predecessor
    (VALIDATING for VALIDATE; READY, STARTING or RUNNING for RUN) has a Task 1 edge
    to every produced target, so no row demands an impossible run transition."""
    consults_category = kind is not _K.DESCRIBE and terminal is _C.FAILED_TO_START
    category = DiagnosticCategory.ENGINE_RUNTIME if consults_category else MISSING
    if not COMMAND_INVOCATION_TRANSITIONS.is_allowed(predecessor, terminal):
        with pytest.raises(ValueError, match="not a permitted command-invocation edge"):
            coupled_run_terminal_state(
                kind, predecessor, terminal, primary_diagnostic_category=category
            )
        return
    result = coupled_run_terminal_state(
        kind, predecessor, terminal, primary_diagnostic_category=category
    )
    expected = _expected_target(
        kind,
        terminal,
        DiagnosticCategory.ENGINE_RUNTIME if consults_category else None,
    )
    if expected is None:
        assert _missing(result)
        return
    assert result is expected
    assert result in NON_SUCCESS_TERMINAL_ENGINE_RUN_STATES
    implied_run_state = (
        _R.VALIDATING
        if kind is _K.VALIDATE
        else _RUN_STATE_FOR_RUN_INVOCATION[predecessor]
    )
    assert ENGINE_RUN_TRANSITIONS.is_allowed(implied_run_state, result)
    assert run_edge_owner(implied_run_state, result) is _GENERIC


def test_exactly_fourteen_of_the_forty_five_triples_produce_a_run_transition() -> None:
    """Eight invocation edges end in a terminal state (PENDING->CANCELLED,
    STARTING->FAILED_TO_START/CANCELLED/TIMED_OUT, RUNNING->EXITED/CANCELLED/
    TIMED_OUT/PROTOCOL_FAILED); EXITED never couples and DESCRIBE never links, so
    two linked kinds times seven coupling edges produce fourteen run transitions."""
    produced: list[
        tuple[CommandKind, CommandInvocationState, CommandInvocationState]
    ] = []
    for kind, predecessor, terminal in _COUPLING_TRIPLES:
        consults = kind is not _K.DESCRIBE and terminal is _C.FAILED_TO_START
        result = coupled_run_terminal_state(
            kind,
            predecessor,
            terminal,
            primary_diagnostic_category=(
                DiagnosticCategory.ENGINE_RUNTIME if consults else MISSING
            ),
        )
        if not _missing(result):
            produced.append((kind, predecessor, terminal))
    terminal_edges = [
        (a, b)
        for a, b in COMMAND_INVOCATION_TRANSITIONS.transitions
        if b in TERMINAL_COMMAND_INVOCATION_STATES
    ]
    assert len(terminal_edges) == 8
    coupling_edges = [(a, b) for a, b in terminal_edges if b is not _C.EXITED]
    assert len(coupling_edges) == 7
    assert len(produced) == 2 * len(coupling_edges) == 14
    assert all(kind is not _K.DESCRIBE for kind, _, _ in produced)
    assert all(terminal is not _C.EXITED for _, _, terminal in produced)


def test_the_timed_out_rows_name_exactly_the_states_with_an_edge_into_timed_out() -> (
    None
):
    """Plan section 6 pins the current run state only in its three TIMED_OUT rows
    (VALIDATING for VALIDATE, STARTING and RUNNING for RUN by invocation
    predecessor); those are exactly the Task 1 predecessors of TIMED_OUT, so the
    mapping returns the target alone and the transition predicate proves the edge
    from the run's actual state."""
    predecessors = {
        current
        for current, target in ENGINE_RUN_TRANSITIONS.transitions
        if target is _R.TIMED_OUT
    }
    assert predecessors == {_R.VALIDATING, _R.STARTING, _R.RUNNING}
    for predecessor in (_C.STARTING, _C.RUNNING):
        assert coupled_run_terminal_state(_K.VALIDATE, predecessor, _C.TIMED_OUT) is (
            _R.TIMED_OUT
        )
        assert coupled_run_terminal_state(_K.RUN, predecessor, _C.TIMED_OUT) is (
            _R.TIMED_OUT
        )
    for run_state in _ALL_STATES:
        stored = _record(run_state)
        replacement = _advance(stored, _R.TIMED_OUT)
        if run_state in predecessors:
            assert_run_transition(stored, replacement)
        else:
            with pytest.raises(EngineRunRuleViolation):
                assert_run_transition(stored, replacement)


@pytest.mark.parametrize("kind", [_K.VALIDATE, _K.RUN])
@pytest.mark.parametrize("category", list(DiagnosticCategory))
def test_failed_to_start_maps_to_unavailable_only_for_an_availability_diagnostic(
    kind: CommandKind,
    category: DiagnosticCategory,
) -> None:
    result = coupled_run_terminal_state(
        kind, _C.STARTING, _C.FAILED_TO_START, primary_diagnostic_category=category
    )
    expected = (
        _R.UNAVAILABLE
        if category is DiagnosticCategory.ADAPTER_UNAVAILABILITY
        else _R.FAILED
    )
    assert result is expected


@pytest.mark.parametrize("kind", [_K.VALIDATE, _K.RUN])
def test_failed_to_start_requires_the_primary_diagnostic_category(
    kind: CommandKind,
) -> None:
    with pytest.raises(ValueError, match="primary_diagnostic_category"):
        coupled_run_terminal_state(kind, _C.STARTING, _C.FAILED_TO_START)


@pytest.mark.parametrize(
    ("kind", "predecessor", "terminal"),
    [
        triple
        for triple in _COUPLING_TRIPLES
        if not (triple[0] is not _K.DESCRIBE and triple[2] is _C.FAILED_TO_START)
    ],
    ids=lambda v: getattr(v, "value", str(v)),
)
def test_a_category_is_ignored_where_the_mapping_does_not_consult_it(
    kind: CommandKind,
    predecessor: CommandInvocationState,
    terminal: CommandInvocationState,
) -> None:
    """Only the FAILED_TO_START rows read the category (plan section 6); every other
    row's condition is "any", so a service may pass the invocation's primary
    diagnostic category uniformly without changing the answer."""
    without = coupled_run_terminal_state(kind, predecessor, terminal)
    for category in DiagnosticCategory:
        with_category = coupled_run_terminal_state(
            kind, predecessor, terminal, primary_diagnostic_category=category
        )
        assert with_category is without, category
    # It is still type-checked whenever it is supplied (the annotation admits the
    # sentinel, so a bare string is refused at runtime rather than by mypy).
    with pytest.raises(TypeError):
        coupled_run_terminal_state(
            kind,
            predecessor,
            terminal,
            primary_diagnostic_category="ENGINE_RUNTIME",
        )


def test_cancelled_maps_to_cancelled_from_every_predecessor() -> None:
    for kind in (_K.VALIDATE, _K.RUN):
        for predecessor in _INVOCATION_PREDECESSORS:
            assert coupled_run_terminal_state(kind, predecessor, _C.CANCELLED) is (
                _R.CANCELLED
            )


def test_protocol_failed_maps_to_failed() -> None:
    for kind in (_K.VALIDATE, _K.RUN):
        assert coupled_run_terminal_state(kind, _C.RUNNING, _C.PROTOCOL_FAILED) is (
            _R.FAILED
        )


@pytest.mark.parametrize("kind", [_K.VALIDATE, _K.RUN])
def test_exited_produces_no_run_transition_because_semantic_mapping_is_stage_six(
    kind: CommandKind,
) -> None:
    """A captured process exit, even ``0`` mapped to ``SUCCESS``, never selects a run
    state here: success requires the Stage 6 manifest reconciliation."""
    assert _missing(coupled_run_terminal_state(kind, _C.RUNNING, _C.EXITED))


@pytest.mark.parametrize(
    ("predecessor", "terminal"),
    [(p, t) for k, p, t in _COUPLING_TRIPLES if k is _K.DESCRIBE],
    ids=lambda v: getattr(v, "value", str(v)),
)
def test_describe_produces_no_linkage_for_any_terminal_outcome(
    predecessor: CommandInvocationState,
    terminal: CommandInvocationState,
) -> None:
    assert _missing(coupled_run_terminal_state(_K.DESCRIBE, predecessor, terminal))
    assert _missing(
        coupled_run_terminal_state(
            _K.DESCRIBE,
            predecessor,
            terminal,
            primary_diagnostic_category=DiagnosticCategory.ADAPTER_UNAVAILABILITY,
        )
    )


def test_the_coupled_mapping_rejects_a_non_terminal_target_and_foreign_inputs() -> None:
    with pytest.raises(ValueError, match="terminal"):
        coupled_run_terminal_state(_K.RUN, _C.PENDING, _C.STARTING)
    with pytest.raises(ValueError, match="terminal"):
        coupled_run_terminal_state(_K.RUN, _C.STARTING, _C.RUNNING)
    with pytest.raises(TypeError):
        coupled_run_terminal_state("RUN", _C.RUNNING, _C.CANCELLED)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        coupled_run_terminal_state(_K.RUN, "RUNNING", _C.CANCELLED)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        coupled_run_terminal_state(_K.RUN, _C.RUNNING, "CANCELLED")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        coupled_run_terminal_state(
            _K.RUN,
            _C.STARTING,
            _C.FAILED_TO_START,
            primary_diagnostic_category="ADAPTER_UNAVAILABILITY",
        )


# --- Mixed running pair (plan section 6, specification 15.1 and 15.6) ---------------

#: The three lawful pairings of a live ``RUN`` invocation and its run: parent
#: eligibility (a RUN invocation is created against a READY run), then
#: ``begin_linked_launch`` and ``start_linked_run`` advance both sides together.
_LAWFUL_LIVE_PAIRS = (
    (_C.PENDING, _R.READY),
    (_C.STARTING, _R.STARTING),
    (_C.RUNNING, _R.RUNNING),
)


@pytest.mark.parametrize(("invocation_state", "run_state"), _LAWFUL_LIVE_PAIRS)
def test_the_three_lawful_live_pairings_are_not_mixed(
    invocation_state: CommandInvocationState,
    run_state: EngineRunState,
) -> None:
    assert (
        is_mixed_running_pair(_record(run_state), _invocation(invocation_state))
        is False
    )


def test_an_exited_invocation_beside_a_running_run_is_not_mixed() -> None:
    running = _record(_R.RUNNING)
    exited = _invocation(_C.EXITED)
    assert exited.process_exit_category is ProcessExitCategory.SUCCESS
    assert is_mixed_running_pair(running, exited) is False
    # ...and the process-level success still selects no run transition.
    assert _missing(coupled_run_terminal_state(_K.RUN, _C.RUNNING, _C.EXITED))


@pytest.mark.parametrize("run_state", [s for s in _ALL_STATES if s is not _R.RUNNING])
def test_a_running_invocation_with_a_non_running_run_is_mixed(
    run_state: EngineRunState,
) -> None:
    """Plan section 6, first orientation."""
    assert is_mixed_running_pair(_record(run_state), _invocation(_C.RUNNING)) is True


@pytest.mark.parametrize("invocation_state", [_C.PENDING, _C.STARTING])
def test_a_running_run_with_a_pre_handoff_invocation_is_mixed(
    invocation_state: CommandInvocationState,
) -> None:
    """Plan section 6, second orientation, widened from "still STARTING" to the
    whole pre-handoff span: the handoff commits both sides RUNNING together
    (specification 15.1 step 5 and 15.6), so a RUNNING run whose RUN invocation
    never reached RUNNING is impossible from PENDING as much as from STARTING."""
    assert (
        is_mixed_running_pair(_record(_R.RUNNING), _invocation(invocation_state))
        is True
    )


@pytest.mark.parametrize(
    ("invocation_state", "run_state"),
    [(_C.PENDING, _R.STARTING), (_C.STARTING, _R.READY)],
    ids=["run_only_launch", "invocation_only_launch"],
)
def test_a_half_applied_linked_launch_is_mixed(
    invocation_state: CommandInvocationState,
    run_state: EngineRunState,
) -> None:
    """``begin_linked_launch`` moves READY -> STARTING and PENDING -> STARTING in one
    unit of work; Task 6 proves the run-only and invocation-only attempts through
    this predicate, so both half-applied states must be detected."""
    assert (
        is_mixed_running_pair(_record(run_state), _invocation(invocation_state)) is True
    )


@pytest.mark.parametrize("invocation_state", [_C.PENDING, _C.STARTING])
@pytest.mark.parametrize("run_state", [_R.PENDING, _R.VALIDATING])
def test_a_live_run_invocation_against_an_unvalidated_run_is_mixed(
    invocation_state: CommandInvocationState,
    run_state: EngineRunState,
) -> None:
    """A RUN invocation exists only for a READY run (plan section 6 matrix), so a
    live one beside a PENDING or VALIDATING run is never a lawful pair."""
    assert (
        is_mixed_running_pair(_record(run_state), _invocation(invocation_state)) is True
    )


@pytest.mark.parametrize("invocation_state", [_C.PENDING, _C.STARTING])
@pytest.mark.parametrize("run_state", _TERMINAL_STATES)
def test_a_terminal_run_beside_a_pre_handoff_invocation_is_not_a_mixed_running_pair(
    invocation_state: CommandInvocationState,
    run_state: EngineRunState,
) -> None:
    """A run may reach a terminal state through ``transition_run`` while its unlaunched
    RUN invocation is still open (plan section 5, "an injected terminal result");
    that pair is closed by cancelling the invocation, not a launch-handoff defect."""
    assert (
        is_mixed_running_pair(_record(run_state), _invocation(invocation_state))
        is False
    )


@pytest.mark.parametrize("invocation_state", _INVOCATION_TERMINAL_STATES)
@pytest.mark.parametrize("run_state", [_R.RUNNING, _R.STARTING, _R.READY, _R.FAILED])
def test_a_terminal_invocation_is_never_part_of_a_mixed_running_pair(
    invocation_state: CommandInvocationState,
    run_state: EngineRunState,
) -> None:
    """A terminal invocation beside any run is governed by the coupled terminal
    mapping, not by the launch-handoff invariant."""
    assert (
        is_mixed_running_pair(_record(run_state), _invocation(invocation_state))
        is False
    )


def test_exactly_nineteen_of_the_ninety_six_pairs_are_mixed() -> None:
    mixed = {
        (invocation_state, run_state)
        for invocation_state in CommandInvocationState
        for run_state in EngineRunState
        if is_mixed_running_pair(_record(run_state), _invocation(invocation_state))
    }
    expected: set[tuple[CommandInvocationState, EngineRunState]] = {
        (_C.RUNNING, s) for s in _ALL_STATES if s is not _R.RUNNING
    }
    expected |= {
        (_C.PENDING, s) for s in (_R.PENDING, _R.VALIDATING, _R.STARTING, _R.RUNNING)
    }
    expected |= {
        (_C.STARTING, s) for s in (_R.PENDING, _R.VALIDATING, _R.READY, _R.RUNNING)
    }
    assert mixed == expected
    assert len(mixed) == 19
    assert len(CommandInvocationState) * len(EngineRunState) == 96


def test_the_mixed_pair_predicate_requires_a_run_invocation_linked_to_the_run() -> None:
    running = _record(_R.RUNNING)
    with pytest.raises(ValueError, match="RUN"):
        is_mixed_running_pair(
            running, _invocation(_C.RUNNING, command_kind=_K.VALIDATE)
        )
    with pytest.raises(ValueError, match="RUN"):
        is_mixed_running_pair(
            running, _invocation(_C.RUNNING, command_kind=_K.DESCRIBE, run_id=_ABSENT)
        )
    with pytest.raises(ValueError, match="linked"):
        is_mixed_running_pair(running, _invocation(_C.RUNNING, run_id=_OTHER_RUN_ID))


# --- Package surface, purity and task boundary -------------------------------------


def test_the_domain_package_re_exports_every_task_four_name() -> None:
    for name in (
        "LINKED_ONLY_RUN_EDGES",
        "NON_SUCCESS_TERMINAL_ENGINE_RUN_STATES",
        "SUCCESS_ENGINE_RUN_STATES",
        "AttemptTokenMaterial",
        "EngineRunCheck",
        "EngineRunRecord",
        "EngineRunRuleViolation",
        "RunEdgeOwner",
        "assert_run_transition",
        "assert_terminal_run_immutability",
        "coupled_run_terminal_state",
        "is_mixed_running_pair",
        "run_edge_owner",
    ):
        assert name in domain_package.__all__, name
        assert getattr(domain_package, name) is getattr(engine_run_module, name), name


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


def test_the_module_launches_nothing_reads_nothing_and_stays_inside_domain() -> None:
    roots: set[str] = set()
    modules: set[str] = set()
    calls: set[str] = set()
    for node in ast.walk(ast.parse(_module_source(engine_run_module))):
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


def test_the_module_never_reads_the_process_exit_mapping() -> None:
    """An engine-run state is never inferred from a command-process exit: the
    module imports neither the exit category nor the frozen native-exit mapping."""
    source = _module_source(engine_run_module)
    for name in (
        "ProcessExitCategory",
        "process_exit_category_for",
        "RECOGNIZED_NATIVE_EXIT_VALUES",
        "native_exit_value",
        "process_exit_category",
    ):
        assert name not in source, name


def test_the_module_defines_no_task_five_or_later_name() -> None:
    defined = {
        node.name
        for node in ast.walk(ast.parse(_module_source(engine_run_module)))
        if isinstance(node, ast.ClassDef | ast.FunctionDef)
    }
    for later in (
        "RetryDecisionRecord",
        "RetryDecisionOutcome",
        "RetryDenialReason",
        "RetryEvaluationSnapshot",
        "CausalClosureEntry",
        "evaluate_retry_gates",
        "retry_terminal_state_of",
        "SlotAggregationInput",
        "ExperimentAggregationInput",
        "ExperimentAggregationResult",
        "classify_experiment_outcome",
        "EngineRunRepository",
        "UnitOfWork",
        "RunTransitionRequest",
        "AttemptCreationRequest",
        "transition_run",
        "create_attempt",
        "create_successor",
        "evaluate_retry",
        "begin_linked_launch",
        "start_linked_run",
        "transition_invocation_and_run",
        "RunEvent",
        "RunManifest",
        "EngineRunRequest",
    ):
        assert later not in defined, later
