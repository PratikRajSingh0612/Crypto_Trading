"""Stage 5 Task 3: the command-invocation record, its nested process facts, the
section 6 state-governed field shapes, the pure transition and write-once
enrichment predicates, the parent-eligibility function and the per-command
timeout bounds.

Every rule below is transcribed from Stage 5 plan sections 3.7 (the twenty-five
fields in order, their sources and their optionality) and 6 (the eight-row
field-shape table, the frozen process-exit mapping, the parent-eligibility matrix
and the write-once enrichment contract), under specification sections 11.3, 11.5,
14.6, 14.8 and 15.2. The Task 1 ``COMMAND_INVOCATION_TRANSITIONS`` table is the
sole allowed-pair authority and nothing here re-declares an edge.

Two conventions of the merged tree are load-bearing here. An absent
state-governed field is ``MISSING``, never ``None``, and is asserted absent from
**both** dump modes because ``canonical_json`` reaches a model through
``mode="python"``. And a record is never mutated through ``model_copy``, which
skips validators: every "invalid" record is rebuilt through ``model_validate`` so
a rejection is real. Tests that begin green against the committed tree -- the
``CommandKind`` membership Task 1 fixed and the ``CanonicalModel`` configuration
every record inherits -- are labelled preventive in their docstrings.
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
from crypto_lab.domain import command_invocation as invocation_module
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.command_invocation import (
    MAX_DESCRIBE_TIMEOUT_SECONDS,
    MAX_DIAGNOSTIC_IDS,
    MAX_NATIVE_EXIT_VALUE,
    MAX_PID,
    MAX_RUN_TIMEOUT_SECONDS,
    MAX_VALIDATE_TIMEOUT_SECONDS,
    MIN_NATIVE_EXIT_VALUE,
    MIN_TIMEOUT_SECONDS,
    CommandInvocationCheck,
    CommandInvocationRecord,
    CommandInvocationRuleViolation,
    ProcessIdentity,
    ProcessStartFacts,
    TimeoutBounds,
    assert_invocation_transition,
    assert_parent_run_eligibility,
    assert_write_once_enrichment,
    command_timeout_bounds,
)
from crypto_lab.domain.lifecycle import (
    COMMAND_INVOCATION_TRANSITIONS,
    RECOGNIZED_NATIVE_EXIT_VALUES,
    TERMINAL_COMMAND_INVOCATION_STATES,
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ProcessExitCategory,
    process_exit_category_for,
)

_C = CommandInvocationState
_K = CommandKind
_R = EngineRunState
_X = ProcessExitCategory
_CHECK = CommandInvocationCheck

# Lowercase canonical UUID4 text: version nibble 4, variant nibble in [89ab].
_UUID_A = "12345678-1234-4234-8234-123456789abc"
_UUID_B = "9f8e7d6c-5b4a-4321-8fed-cba987654321"
_UUID_C = "0a1b2c3d-4e5f-4a6b-9c7d-8e9f0a1b2c3d"
_INVOCATION_ID = f"inv_{_UUID_A}"
_OTHER_INVOCATION_ID = f"inv_{_UUID_B}"
_RUN_ID = f"run_{_UUID_A}"
_OTHER_RUN_ID = f"run_{_UUID_B}"
_ARTIFACT_ID = f"art_{_UUID_A}"
_OTHER_ARTIFACT_ID = f"art_{_UUID_B}"
# Sorted: "diag_0a..." < "diag_12..." < "diag_9f...".
_DIAG_LOW = f"diag_{_UUID_C}"
_DIAG_MID = f"diag_{_UUID_A}"
_DIAG_HIGH = f"diag_{_UUID_B}"

_REQUEST_HASH = "a" * 64
_OTHER_REQUEST_HASH = "b" * 64
_EXECUTABLE_HASH = "c" * 64

_TIMEOUT = 120
_CREATED = datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)
_LAUNCH = _CREATED + timedelta(seconds=1)
_DEADLINE = _LAUNCH + timedelta(seconds=_TIMEOUT)
_STARTED = _LAUNCH + timedelta(seconds=2)
_COMPLETED = _LAUNCH + timedelta(seconds=10)
_CLEANED = _COMPLETED + timedelta(seconds=1)
_NAIVE = datetime(2026, 9, 6, 12, 0, 0)  # noqa: DTZ001 - deliberate naive probe
_OFFSET = datetime(2026, 9, 6, 13, 0, 0, tzinfo=timezone(timedelta(hours=1)))

#: Plan section 3.7, fields 1 through 25 in the reviewed order.
_RECORD_FIELDS = (
    "schema_version",
    "invocation_id",
    "command_kind",
    "adapter_name",
    "adapter_version",
    "run_id",
    "request_hash",
    "timeout_seconds",
    "deadline_utc",
    "state",
    "process_created",
    "launch_attempted_at_utc",
    "process_started_at_utc",
    "pid_identity",
    "completed_at_utc",
    "native_exit_value",
    "process_exit_category",
    "cleanup_complete",
    "cleanup_completed_at_utc",
    "stderr_artifact_id",
    "primary_diagnostic_id",
    "diagnostic_ids",
    "created_at_utc",
    "updated_at_utc",
    "revision",
)
_OPTIONAL_FIELDS = (
    "run_id",
    "deadline_utc",
    "launch_attempted_at_utc",
    "process_started_at_utc",
    "pid_identity",
    "completed_at_utc",
    "native_exit_value",
    "process_exit_category",
    "cleanup_completed_at_utc",
    "stderr_artifact_id",
    "primary_diagnostic_id",
)
_TIMESTAMP_FIELDS = (
    "deadline_utc",
    "launch_attempted_at_utc",
    "process_started_at_utc",
    "completed_at_utc",
    "cleanup_completed_at_utc",
    "created_at_utc",
    "updated_at_utc",
)
#: Fields 1-8 and 23 never change after creation: plan section 3.7 field 7,
#: specification 11.3 and the section 3.2 carry-forward rule.
_IMMUTABLE_FIELDS = (
    "invocation_id",
    "command_kind",
    "adapter_name",
    "adapter_version",
    "run_id",
    "request_hash",
    "timeout_seconds",
    "created_at_utc",
)
_NON_TERMINAL_STATES = (_C.PENDING, _C.STARTING, _C.RUNNING)
_TERMINAL_STATES = (
    _C.EXITED,
    _C.FAILED_TO_START,
    _C.CANCELLED,
    _C.TIMED_OUT,
    _C.PROTOCOL_FAILED,
)
#: Terminal states whose exit pair is optional (plan section 6 table).
_EXIT_OPTIONAL_STATES = (_C.CANCELLED, _C.TIMED_OUT, _C.PROTOCOL_FAILED)
_ALL_STATES = tuple(CommandInvocationState)
_ALL_PAIRS = tuple((a, b) for a in _ALL_STATES for b in _ALL_STATES)

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


def _pid_identity(**overrides: object) -> ProcessIdentity:
    payload: dict[str, object] = {
        "pid": 4321,
        "creation_identity": "2026-09-06T12:00:03.1234567Z#0001",
        "executable_path": r"C:\adapters\alpha\adapter.exe",
        "executable_hash": _EXECUTABLE_HASH,
        "supervisor_instance_id": "supervisor-01",
    }
    _apply(payload, overrides)
    return ProcessIdentity.model_validate(payload)


def _start_facts(**overrides: object) -> ProcessStartFacts:
    payload: dict[str, object] = {
        "pid_identity": _pid_identity(),
        "process_started_at_utc": _STARTED,
    }
    _apply(payload, overrides)
    return ProcessStartFacts.model_validate(payload)


def _via_default(state: CommandInvocationState) -> CommandInvocationState | None:
    """The predecessor a shaped fixture assumes for the two ambiguous terminals."""
    return _C.RUNNING if state in (_C.CANCELLED, _C.TIMED_OUT) else None


def _payload(
    state: CommandInvocationState,
    via: CommandInvocationState | None = None,
) -> dict[str, object]:
    """A record whose state-governed fields are consistent with ``state``.

    ``via`` names the predecessor for ``CANCELLED`` (``PENDING``, ``STARTING`` or
    ``RUNNING``) and ``TIMED_OUT`` (``STARTING`` or ``RUNNING``), because plan
    section 6 makes their launch and process facts predecessor-dependent.
    """
    via = _via_default(state) if via is None else via
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "invocation_id": _INVOCATION_ID,
        "command_kind": _K.VALIDATE,
        "adapter_name": "adapter.alpha",
        "adapter_version": "1.0.0",
        "run_id": _RUN_ID,
        "request_hash": _REQUEST_HASH,
        "timeout_seconds": _TIMEOUT,
        "state": state,
        "process_created": False,
        "cleanup_complete": False,
        "diagnostic_ids": (),
        "created_at_utc": _CREATED,
        "updated_at_utc": _CREATED,
        "revision": 0,
    }
    revision = 0
    launched = state is not _C.PENDING and not (
        state is _C.CANCELLED and via is _C.PENDING
    )
    if launched:
        payload["deadline_utc"] = _DEADLINE
        payload["launch_attempted_at_utc"] = _LAUNCH
        payload["updated_at_utc"] = _LAUNCH
        revision += 1
    process = state in (_C.RUNNING, _C.EXITED, _C.PROTOCOL_FAILED) or (
        state in (_C.CANCELLED, _C.TIMED_OUT) and via is _C.RUNNING
    )
    if process:
        payload["process_created"] = True
        payload["process_started_at_utc"] = _STARTED
        payload["pid_identity"] = _pid_identity()
        payload["updated_at_utc"] = _STARTED
        revision += 1
    if state in TERMINAL_COMMAND_INVOCATION_STATES:
        payload["completed_at_utc"] = _COMPLETED
        payload["updated_at_utc"] = _COMPLETED
        revision += 1
        if state is _C.EXITED:
            payload["native_exit_value"] = 0
            payload["process_exit_category"] = _X.SUCCESS
        else:
            payload["primary_diagnostic_id"] = _DIAG_MID
            payload["diagnostic_ids"] = (_DIAG_MID,)
    payload["revision"] = revision
    return payload


def _record(
    state: CommandInvocationState = _C.PENDING,
    /,
    **overrides: object,
) -> CommandInvocationRecord:
    """A shaped record; ``via=`` names the predecessor for the two ambiguous
    terminals and every other keyword overrides or, with ``_ABSENT``, removes."""
    via = overrides.pop("via", None)
    assert via is None or isinstance(via, CommandInvocationState)
    payload = _payload(state, via)
    _apply(payload, overrides)
    return CommandInvocationRecord.model_validate(payload)


def _describe(
    state: CommandInvocationState = _C.PENDING,
    **overrides: object,
) -> CommandInvocationRecord:
    return _record(state, command_kind=_K.DESCRIBE, run_id=_ABSENT, **overrides)


def _rebuild(
    instance: CommandInvocationRecord,
    **overrides: object,
) -> CommandInvocationRecord:
    """Rebuild through validation, never through ``model_copy``."""
    payload = instance.model_dump(mode="python")
    _apply(payload, overrides)
    return CommandInvocationRecord.model_validate(payload)


def _advance(
    stored: CommandInvocationRecord,
    target: CommandInvocationState,
    **overrides: object,
) -> CommandInvocationRecord:
    """The replacement a correct service would build for ``stored -> target``.

    Adds exactly the facts the target state establishes -- launch facts on
    ``STARTING``, process facts on ``RUNNING``, completion and either the exit
    pair or the primary diagnostic on a terminal state -- carries everything else
    forward, moves ``updated_at_utc`` forward and increments ``revision``.
    """
    payload = stored.model_dump(mode="python")
    instant = stored.updated_at_utc + timedelta(seconds=1)
    payload["state"] = target
    if target is _C.STARTING:
        payload["launch_attempted_at_utc"] = instant
        payload["deadline_utc"] = instant + timedelta(seconds=stored.timeout_seconds)
    if target is _C.RUNNING:
        payload["process_created"] = True
        payload["process_started_at_utc"] = instant
        payload["pid_identity"] = _pid_identity()
    if target in TERMINAL_COMMAND_INVOCATION_STATES:
        payload["completed_at_utc"] = instant
        if target is _C.EXITED:
            payload["native_exit_value"] = 0
            payload["process_exit_category"] = _X.SUCCESS
        else:
            payload["primary_diagnostic_id"] = _DIAG_MID
            payload["diagnostic_ids"] = tuple(
                sorted({*stored.diagnostic_ids, _DIAG_MID})
            )
    payload["updated_at_utc"] = instant
    payload["revision"] = stored.revision + 1
    _apply(payload, overrides)
    return CommandInvocationRecord.model_validate(payload)


def _enrich(
    stored: CommandInvocationRecord,
    **overrides: object,
) -> CommandInvocationRecord:
    """A same-state replacement at revision + 1 with ``overrides`` applied."""
    payload = stored.model_dump(mode="python")
    payload["updated_at_utc"] = stored.updated_at_utc + timedelta(seconds=1)
    payload["revision"] = stored.revision + 1
    _apply(payload, overrides)
    return CommandInvocationRecord.model_validate(payload)


def _group(name: str) -> dict[str, object]:
    """The state-governed field groups of plan section 6, with consistent values."""
    groups: dict[str, dict[str, object]] = {
        "launch": {"deadline_utc": _DEADLINE, "launch_attempted_at_utc": _LAUNCH},
        "process": {
            "process_created": True,
            "process_started_at_utc": _STARTED,
            "pid_identity": _pid_identity(),
        },
        "exit": {"native_exit_value": 0, "process_exit_category": _X.SUCCESS},
        "completed": {"completed_at_utc": _COMPLETED},
        "stderr": {"stderr_artifact_id": _ARTIFACT_ID},
        "primary": {"primary_diagnostic_id": _DIAG_MID, "diagnostic_ids": (_DIAG_MID,)},
        "cleanup": {"cleanup_complete": True, "cleanup_completed_at_utc": _CLEANED},
    }
    return groups[name]


def _removal(name: str) -> dict[str, object]:
    """The overrides that make a group absent while keeping its flag consistent."""
    removed: dict[str, object] = dict.fromkeys(_group(name), _ABSENT)
    if name == "process":
        removed["process_created"] = False
    if name == "cleanup":
        removed["cleanup_complete"] = False
    if name == "primary":
        # The diagnostic array is required in every state; only the primary goes.
        removed.pop("diagnostic_ids")
    return removed


#: Plan section 6 "Required field shape" column, as prohibited groups per state.
_PROHIBITED_GROUPS: dict[CommandInvocationState, tuple[str, ...]] = {
    _C.PENDING: (
        "launch",
        "process",
        "exit",
        "completed",
        "stderr",
        "primary",
        "cleanup",
    ),
    _C.STARTING: ("process", "exit", "completed", "stderr", "primary", "cleanup"),
    _C.RUNNING: ("exit", "completed", "stderr", "primary", "cleanup"),
    _C.EXITED: (),
    _C.FAILED_TO_START: ("process", "exit"),
    _C.CANCELLED: (),
    _C.TIMED_OUT: (),
    _C.PROTOCOL_FAILED: (),
}
#: The same column, as groups that must be present per state.
_REQUIRED_GROUPS: dict[CommandInvocationState, tuple[str, ...]] = {
    _C.PENDING: (),
    _C.STARTING: ("launch",),
    _C.RUNNING: ("launch", "process"),
    _C.EXITED: ("launch", "process", "completed", "exit"),
    _C.FAILED_TO_START: ("launch", "completed", "primary"),
    _C.CANCELLED: ("completed", "primary"),
    _C.TIMED_OUT: ("launch", "completed", "primary"),
    _C.PROTOCOL_FAILED: ("launch", "process", "completed", "primary"),
}
#: Groups neither required nor prohibited: optional, or predecessor-dependent.
_OPTIONAL_GROUPS: dict[CommandInvocationState, tuple[str, ...]] = {
    _C.PENDING: (),
    _C.STARTING: (),
    _C.RUNNING: (),
    _C.EXITED: ("stderr", "primary", "cleanup"),
    _C.FAILED_TO_START: ("stderr", "cleanup"),
    _C.CANCELLED: ("launch", "process", "exit", "stderr", "cleanup"),
    _C.TIMED_OUT: ("process", "exit", "stderr", "cleanup"),
    _C.PROTOCOL_FAILED: ("exit", "stderr", "cleanup"),
}
_GROUP_NAMES = (
    "launch",
    "process",
    "exit",
    "completed",
    "stderr",
    "primary",
    "cleanup",
)


def _every_instance() -> tuple[CanonicalModel, ...]:
    return (
        _pid_identity(),
        _start_facts(),
        _record(),
        _record(_C.EXITED),
    )


def _module_source(module: ModuleType) -> str:
    assert module.__file__ is not None
    return Path(module.__file__).read_text(encoding="utf-8")


# --- Shared conventions (plan section 3.1) ---------------------------------------


@pytest.mark.parametrize("instance", _every_instance(), ids=lambda m: type(m).__name__)
def test_every_task_three_model_rejects_an_unknown_field(
    instance: CanonicalModel,
) -> None:
    payload = instance.model_dump(mode="python")
    assert type(instance).model_validate(payload) == instance
    payload["unexpected"] = "rejected"
    with pytest.raises(ValidationError, match="extra_forbidden"):
        type(instance).model_validate(payload)


@pytest.mark.parametrize("instance", _every_instance(), ids=lambda m: type(m).__name__)
def test_every_task_three_model_is_frozen(instance: CanonicalModel) -> None:
    """Preventive for the inherited configuration; the nested ``pid_identity`` is
    asserted separately below because deep immutability is not inherited."""
    first = next(iter(type(instance).model_fields))
    with pytest.raises(ValidationError):
        setattr(instance, first, getattr(instance, first))


def test_every_task_three_model_derives_from_the_canonical_base() -> None:
    for model in (ProcessIdentity, ProcessStartFacts, CommandInvocationRecord):
        assert issubclass(model, CanonicalModel)
        assert model.model_config["extra"] == "forbid"
        assert model.model_config["frozen"] is True
        assert model.model_config["strict"] is True


def test_nested_process_identity_is_immutable_through_the_record() -> None:
    record = _record(_C.RUNNING)
    assert not _missing(record.pid_identity)
    with pytest.raises(ValidationError):
        record.pid_identity.pid = 1
    assert type(record.diagnostic_ids) is tuple


def test_strict_mode_refuses_coercion_for_integers_and_booleans() -> None:
    for field, value in (
        ("timeout_seconds", "120"),
        ("revision", "0"),
        ("revision", True),
        ("process_created", 1),
        ("cleanup_complete", 0),
        ("native_exit_value", True),
    ):
        payload = _payload(_C.EXITED)
        payload[field] = value
        with pytest.raises(ValidationError):
            CommandInvocationRecord.model_validate(payload)
    with pytest.raises(ValidationError):
        _pid_identity(pid=True)
    with pytest.raises(ValidationError):
        _pid_identity(pid="4321")


def test_the_record_declares_exactly_the_twenty_five_plan_fields_in_order() -> None:
    assert tuple(CommandInvocationRecord.model_fields) == _RECORD_FIELDS
    assert len(_RECORD_FIELDS) == 25
    assert tuple(ProcessIdentity.model_fields) == (
        "pid",
        "creation_identity",
        "executable_path",
        "executable_hash",
        "supervisor_instance_id",
    )
    assert tuple(ProcessStartFacts.model_fields) == (
        "pid_identity",
        "process_started_at_utc",
    )
    for nested in (ProcessIdentity, ProcessStartFacts):
        assert "schema_version" not in nested.model_fields, nested.__name__


def test_exactly_the_eleven_state_governed_fields_are_optional() -> None:
    required = tuple(
        name
        for name, field in CommandInvocationRecord.model_fields.items()
        if field.is_required()
    )
    assert required == tuple(f for f in _RECORD_FIELDS if f not in _OPTIONAL_FIELDS)
    assert len(required) == 14
    for name in _OPTIONAL_FIELDS:
        assert CommandInvocationRecord.model_fields[name].default is MISSING, name
    schema = CommandInvocationRecord.model_json_schema()
    assert schema["required"] == list(required)


def test_command_kind_holds_exactly_the_three_specification_members() -> None:
    """Preventive: Task 1 fixed the membership; Task 3 consumes it as closed."""
    assert [m.value for m in CommandKind] == ["DESCRIBE", "VALIDATE", "RUN"]
    assert len(CommandKind) == 3


@pytest.mark.parametrize("field", _TIMESTAMP_FIELDS)
def test_a_naive_or_offset_timestamp_is_rejected_on_every_instant_field(
    field: str,
) -> None:
    base = _payload(_C.EXITED)
    base["cleanup_complete"] = True
    base["cleanup_completed_at_utc"] = _CLEANED
    payload = dict(base)
    payload[field] = _NAIVE
    with pytest.raises(ValidationError, match="timezone-aware UTC"):
        CommandInvocationRecord.model_validate(payload)
    payload[field] = _OFFSET
    with pytest.raises(ValidationError, match="offset must be UTC"):
        CommandInvocationRecord.model_validate(payload)
    with pytest.raises(ValidationError, match="timezone-aware UTC"):
        _start_facts(process_started_at_utc=_NAIVE)


def test_every_timestamp_uses_the_forward_schema_view() -> None:
    """Plan section 2.6: every Stage 5 timestamp field uses the calendar-valid view,
    so Task 9's registration passes the merged forward-view guard unchanged."""
    for model in (CommandInvocationRecord, ProcessStartFacts):
        for mode in ("validation", "serialization"):
            schema = model.model_json_schema(mode=mode)
            assert "UtcDateTime" not in schema.get("$defs", {}), model.__name__
            assert "CalendarValidUtcDateTime" in schema["$defs"], model.__name__


def test_the_published_diagnostic_array_declares_its_bound_and_uniqueness() -> None:
    schema = CommandInvocationRecord.model_json_schema()
    ids = schema["properties"]["diagnostic_ids"]
    assert ids["uniqueItems"] is True
    assert ids["maxItems"] == MAX_DIAGNOSTIC_IDS == 64
    assert "default" not in ids
    category = schema["$defs"]["ProcessExitCategory"]["enum"]
    assert category == [m.value for m in ProcessExitCategory]
    assert len(category) == 8


# --- Nested process facts (plan section 3.7) -------------------------------------


def test_process_identity_pid_is_a_strict_integer_in_the_windows_range() -> None:
    assert MAX_PID == 4294967295
    with pytest.raises(ValidationError):
        _pid_identity(pid=0)
    with pytest.raises(ValidationError):
        _pid_identity(pid=MAX_PID + 1)
    assert _pid_identity(pid=1).pid == 1
    assert _pid_identity(pid=MAX_PID).pid == MAX_PID


@pytest.mark.parametrize("field", ["creation_identity", "supervisor_instance_id"])
def test_process_identity_text_fields_are_bounded_text(field: str) -> None:
    with pytest.raises(ValidationError):
        _pid_identity(**{field: ""})
    with pytest.raises(ValidationError):
        _pid_identity(**{field: "x" * 1025})
    assert getattr(_pid_identity(**{field: "x" * 1024}), field) == "x" * 1024


def test_process_identity_executable_path_and_hash_reuse_the_merged_rules() -> None:
    with pytest.raises(ValidationError, match="surrounding whitespace"):
        _pid_identity(executable_path=" C:\\adapter.exe")
    with pytest.raises(ValidationError, match="control character"):
        _pid_identity(executable_path="C:\\adap\x00ter.exe")
    with pytest.raises(ValidationError):
        _pid_identity(executable_hash="G" * 64)
    with pytest.raises(ValidationError):
        _pid_identity(executable_hash="c" * 63)


def test_process_start_facts_require_both_fields() -> None:
    with pytest.raises(ValidationError):
        _start_facts(pid_identity=_ABSENT)
    with pytest.raises(ValidationError):
        _start_facts(process_started_at_utc=_ABSENT)
    facts = _start_facts()
    assert facts.pid_identity == _pid_identity()
    assert facts.process_started_at_utc == _STARTED


# --- Command kind, run linkage and timeout bounds (plan sections 3.7 and 6) -----


@pytest.mark.parametrize("command_kind", list(CommandKind))
@pytest.mark.parametrize("run_present", [True, False], ids=["run_id", "no_run_id"])
def test_run_id_is_absent_for_describe_and_required_otherwise(
    command_kind: CommandKind,
    run_present: bool,
) -> None:
    """All six command/run-id combinations pinned; exactly three are representable."""
    overrides: dict[str, object] = {
        "command_kind": command_kind,
        "run_id": _RUN_ID if run_present else _ABSENT,
    }
    permitted = (command_kind is _K.DESCRIBE) is not run_present
    if permitted:
        record = _record(**overrides)
        assert _missing(record.run_id) is not run_present
    else:
        expected = "DESCRIBE" if command_kind is _K.DESCRIBE else "run_id is required"
        with pytest.raises(ValidationError, match=expected):
            _record(**overrides)


def test_command_timeout_bounds_are_the_configuration_literals_by_kind() -> None:
    assert command_timeout_bounds(_K.DESCRIBE) == TimeoutBounds(1, 300)
    assert command_timeout_bounds(_K.VALIDATE) == TimeoutBounds(1, 1800)
    assert command_timeout_bounds(_K.RUN) == TimeoutBounds(1, 604800)
    assert MIN_TIMEOUT_SECONDS == 1
    assert (
        MAX_DESCRIBE_TIMEOUT_SECONDS,
        MAX_VALIDATE_TIMEOUT_SECONDS,
        MAX_RUN_TIMEOUT_SECONDS,
    ) == (300, 1800, 604800)
    assert {command_timeout_bounds(kind) for kind in CommandKind} == {
        TimeoutBounds(1, 300),
        TimeoutBounds(1, 1800),
        TimeoutBounds(1, 604800),
    }
    bounds = command_timeout_bounds(_K.RUN)
    assert bounds.minimum_seconds == 1
    assert bounds.maximum_seconds == 604800
    with pytest.raises(AttributeError):
        bounds.maximum_seconds = 1  # type: ignore[misc]
    # A bare string is refused even though it equals a member, as in `lifecycle`.
    with pytest.raises(TypeError):
        command_timeout_bounds("DESCRIBE")  # type: ignore[arg-type]


@pytest.mark.parametrize("command_kind", list(CommandKind))
def test_timeout_seconds_is_rejected_outside_its_command_kind_bounds(
    command_kind: CommandKind,
) -> None:
    bounds = command_timeout_bounds(command_kind)
    run_id: object = _ABSENT if command_kind is _K.DESCRIBE else _RUN_ID
    for value in (bounds.minimum_seconds, bounds.maximum_seconds):
        record = _record(
            command_kind=command_kind, run_id=run_id, timeout_seconds=value
        )
        assert record.timeout_seconds == value
    for value in (bounds.minimum_seconds - 1, bounds.maximum_seconds + 1):
        with pytest.raises(ValidationError):
            _record(command_kind=command_kind, run_id=run_id, timeout_seconds=value)


def test_a_launched_record_derives_its_deadline_from_the_launch_instant() -> None:
    """Plan section 3.7 field 9 and specification 14.8: one paired clock
    observation records ``deadline_utc = now_utc + timeout_seconds``."""
    record = _record(_C.STARTING)
    assert record.deadline_utc == _LAUNCH + timedelta(seconds=_TIMEOUT)
    with pytest.raises(ValidationError, match="deadline_utc"):
        _record(_C.STARTING, deadline_utc=_DEADLINE + timedelta(seconds=1))
    with pytest.raises(ValidationError, match="deadline_utc"):
        _record(_C.STARTING, timeout_seconds=_TIMEOUT + 1)
    longer = _record(
        _C.STARTING,
        timeout_seconds=_TIMEOUT + 1,
        deadline_utc=_DEADLINE + timedelta(seconds=1),
    )
    assert longer.deadline_utc == _DEADLINE + timedelta(seconds=1)


# --- State-governed field shapes (plan section 6) ----------------------------------


@pytest.mark.parametrize("state", _ALL_STATES)
def test_every_state_has_a_constructible_consistent_shape(
    state: CommandInvocationState,
) -> None:
    record = _record(state)
    assert record.state is state
    assert _missing(record.completed_at_utc) is not (
        state in TERMINAL_COMMAND_INVOCATION_STATES
    )


def test_the_shape_tables_partition_every_group_for_every_state() -> None:
    for state in _ALL_STATES:
        prohibited = set(_PROHIBITED_GROUPS[state])
        required = set(_REQUIRED_GROUPS[state])
        optional = set(_OPTIONAL_GROUPS[state])
        assert prohibited.isdisjoint(required), state
        assert prohibited.isdisjoint(optional), state
        assert required.isdisjoint(optional), state
        assert prohibited | required | optional == set(_GROUP_NAMES), state
    assert set(_PROHIBITED_GROUPS) == set(_ALL_STATES)


@pytest.mark.parametrize(
    ("state", "group"),
    [(s, g) for s, groups in _PROHIBITED_GROUPS.items() for g in groups],
)
def test_a_prohibited_group_is_rejected_in_its_state(
    state: CommandInvocationState,
    group: str,
) -> None:
    with pytest.raises(ValidationError):
        _record(state, **_group(group))


@pytest.mark.parametrize(
    ("state", "group"),
    [(s, g) for s, groups in _REQUIRED_GROUPS.items() for g in groups],
)
def test_a_required_group_is_rejected_when_absent_in_its_state(
    state: CommandInvocationState,
    group: str,
) -> None:
    with pytest.raises(ValidationError):
        _record(state, **_removal(group))


@pytest.mark.parametrize(
    ("state", "group"),
    [(s, g) for s, groups in _OPTIONAL_GROUPS.items() for g in groups],
)
def test_an_optional_group_is_accepted_present_and_absent_in_its_state(
    state: CommandInvocationState,
    group: str,
) -> None:
    # Predecessor-dependent groups need a predecessor whose other facts are
    # consistent both ways: process facts imply launch facts, so the process
    # variant starts from STARTING and the launch variant from PENDING.
    via = {"process": _C.STARTING, "launch": _C.PENDING}.get(group)
    present = _record(state, via=via, **_group(group))
    absent = _record(state, via=via, **_removal(group))
    for name in _group(group):
        if name in ("process_created", "cleanup_complete", "diagnostic_ids"):
            continue  # flags and the always-present array are never MISSING
        assert getattr(present, name) is not MISSING, name
        assert getattr(absent, name) is MISSING, name


@pytest.mark.parametrize("state", _NON_TERMINAL_STATES)
def test_cleanup_complete_is_false_in_every_non_terminal_state(
    state: CommandInvocationState,
) -> None:
    with pytest.raises(ValidationError, match="cleanup_complete"):
        _record(state, cleanup_complete=True, cleanup_completed_at_utc=_CLEANED)
    with pytest.raises(ValidationError):
        _record(state, cleanup_complete=True)
    assert _record(state).cleanup_complete is False


@pytest.mark.parametrize("state", _TERMINAL_STATES)
def test_cleanup_completed_at_is_present_if_and_only_if_cleanup_complete(
    state: CommandInvocationState,
) -> None:
    with pytest.raises(ValidationError, match="cleanup_completed_at_utc"):
        _record(state, cleanup_complete=True)
    with pytest.raises(ValidationError, match="cleanup_completed_at_utc"):
        _record(state, cleanup_completed_at_utc=_CLEANED)
    cleaned = _record(state, cleanup_complete=True, cleanup_completed_at_utc=_CLEANED)
    assert cleaned.cleanup_completed_at_utc == _CLEANED
    assert _missing(_record(state).cleanup_completed_at_utc)


def test_launch_facts_co_occur() -> None:
    with pytest.raises(ValidationError, match="launch_attempted_at_utc"):
        _record(_C.STARTING, launch_attempted_at_utc=_ABSENT)
    with pytest.raises(ValidationError, match="deadline_utc"):
        _record(_C.STARTING, deadline_utc=_ABSENT)


def test_process_facts_co_occur_with_process_created() -> None:
    with pytest.raises(ValidationError, match="process_started_at_utc"):
        _record(_C.RUNNING, process_started_at_utc=_ABSENT)
    with pytest.raises(ValidationError, match="pid_identity"):
        _record(_C.RUNNING, pid_identity=_ABSENT)
    with pytest.raises(ValidationError, match="process_created"):
        _record(_C.RUNNING, process_created=False)
    with pytest.raises(ValidationError, match="process_created"):
        _record(_C.STARTING, process_created=True)
    with pytest.raises(ValidationError):
        _record(
            _C.CANCELLED,
            via=_C.STARTING,
            process_started_at_utc=_STARTED,
            pid_identity=_pid_identity(),
        )


@pytest.mark.parametrize("state", _TERMINAL_STATES)
def test_completed_at_is_required_in_every_terminal_state(
    state: CommandInvocationState,
) -> None:
    with pytest.raises(ValidationError, match="completed_at_utc"):
        _record(state, completed_at_utc=_ABSENT)


@pytest.mark.parametrize("state", _NON_TERMINAL_STATES)
def test_terminal_only_fields_are_rejected_in_every_non_terminal_state(
    state: CommandInvocationState,
) -> None:
    with pytest.raises(ValidationError, match="completed_at_utc"):
        _record(state, completed_at_utc=_COMPLETED)
    with pytest.raises(ValidationError, match="stderr_artifact_id"):
        _record(state, stderr_artifact_id=_ARTIFACT_ID)
    with pytest.raises(ValidationError, match="primary_diagnostic_id"):
        _record(state, primary_diagnostic_id=_DIAG_MID, diagnostic_ids=(_DIAG_MID,))
    with pytest.raises(ValidationError, match="native_exit_value"):
        _record(state, native_exit_value=0, process_exit_category=_X.SUCCESS)


def test_cancelled_carries_the_launch_and_process_facts_of_its_predecessor() -> None:
    from_pending = _record(_C.CANCELLED, via=_C.PENDING)
    assert _missing(from_pending.deadline_utc)
    assert _missing(from_pending.launch_attempted_at_utc)
    assert from_pending.process_created is False
    from_starting = _record(_C.CANCELLED, via=_C.STARTING)
    assert from_starting.deadline_utc == _DEADLINE
    assert from_starting.process_created is False
    assert _missing(from_starting.pid_identity)
    from_running = _record(_C.CANCELLED, via=_C.RUNNING)
    assert from_running.process_created is True
    assert from_running.pid_identity == _pid_identity()
    # Process facts without launch facts describe no reachable predecessor.
    with pytest.raises(ValidationError, match="deadline_utc"):
        _record(_C.CANCELLED, via=_C.PENDING, **_group("process"))
    with pytest.raises(ValidationError, match="launch_attempted_at_utc"):
        _record(_C.CANCELLED, via=_C.STARTING, launch_attempted_at_utc=_ABSENT)


def test_timed_out_always_carries_launch_facts_and_optionally_process_facts() -> None:
    from_starting = _record(_C.TIMED_OUT, via=_C.STARTING)
    assert from_starting.deadline_utc == _DEADLINE
    assert from_starting.process_created is False
    from_running = _record(_C.TIMED_OUT, via=_C.RUNNING)
    assert from_running.process_created is True
    with pytest.raises(ValidationError, match="deadline_utc"):
        _record(_C.TIMED_OUT, via=_C.STARTING, **_removal("launch"))


@pytest.mark.parametrize("state", _EXIT_OPTIONAL_STATES)
def test_a_later_native_exit_pair_is_both_present_or_both_absent(
    state: CommandInvocationState,
) -> None:
    both = _record(state, native_exit_value=50, process_exit_category=_X.CANCELLED)
    assert both.native_exit_value == 50
    neither = _record(state)
    assert _missing(neither.native_exit_value)
    assert _missing(neither.process_exit_category)
    with pytest.raises(ValidationError, match="process_exit_category"):
        _record(state, native_exit_value=50)
    with pytest.raises(ValidationError, match="native_exit_value"):
        _record(state, process_exit_category=_X.CANCELLED)


def test_exited_requires_the_exit_pair_and_the_process_facts() -> None:
    with pytest.raises(ValidationError, match="native_exit_value"):
        _record(_C.EXITED, **_removal("exit"))
    with pytest.raises(ValidationError, match="process_exit_category"):
        _record(_C.EXITED, process_exit_category=_ABSENT)
    with pytest.raises(ValidationError, match="process_created"):
        _record(_C.EXITED, **_removal("process"))


@pytest.mark.parametrize("native", sorted(RECOGNIZED_NATIVE_EXIT_VALUES))
def test_the_exit_category_must_equal_the_frozen_mapping_of_the_native_value(
    native: int,
) -> None:
    expected = process_exit_category_for(native)
    record = _record(
        _C.EXITED, native_exit_value=native, process_exit_category=expected
    )
    assert record.process_exit_category is expected
    assert _missing(record.primary_diagnostic_id)
    wrong = next(m for m in ProcessExitCategory if m is not expected)
    with pytest.raises(ValidationError, match="process_exit_category_for"):
        _record(_C.EXITED, native_exit_value=native, process_exit_category=wrong)


@pytest.mark.parametrize(
    "native",
    [1, -1, 41, 71, MIN_NATIVE_EXIT_VALUE, MAX_NATIVE_EXIT_VALUE],
)
def test_an_unrecognized_exit_maps_to_runtime_failure_and_needs_a_primary(
    native: int,
) -> None:
    assert native not in RECOGNIZED_NATIVE_EXIT_VALUES
    with pytest.raises(ValidationError, match="unrecognized native exit"):
        _record(
            _C.EXITED,
            native_exit_value=native,
            process_exit_category=_X.RUNTIME_FAILURE,
        )
    record = _record(
        _C.EXITED,
        native_exit_value=native,
        process_exit_category=_X.RUNTIME_FAILURE,
        primary_diagnostic_id=_DIAG_MID,
        diagnostic_ids=(_DIAG_MID,),
    )
    assert record.process_exit_category is _X.RUNTIME_FAILURE
    with pytest.raises(ValidationError, match="process_exit_category_for"):
        _record(
            _C.EXITED,
            native_exit_value=native,
            process_exit_category=_X.SUCCESS,
            primary_diagnostic_id=_DIAG_MID,
            diagnostic_ids=(_DIAG_MID,),
        )


def test_native_exit_value_is_bounded_to_the_signed_and_unsigned_32_bit_span() -> None:
    assert (MIN_NATIVE_EXIT_VALUE, MAX_NATIVE_EXIT_VALUE) == (-2147483648, 4294967295)
    for value in (MIN_NATIVE_EXIT_VALUE - 1, MAX_NATIVE_EXIT_VALUE + 1):
        with pytest.raises(ValidationError):
            _record(
                _C.EXITED,
                native_exit_value=value,
                process_exit_category=_X.RUNTIME_FAILURE,
                primary_diagnostic_id=_DIAG_MID,
                diagnostic_ids=(_DIAG_MID,),
            )


@pytest.mark.parametrize("state", [s for s in _TERMINAL_STATES if s is not _C.EXITED])
def test_primary_diagnostic_is_required_in_every_terminal_state_except_exited(
    state: CommandInvocationState,
) -> None:
    with pytest.raises(ValidationError, match="primary_diagnostic_id"):
        _record(state, primary_diagnostic_id=_ABSENT)
    record = _record(state)
    assert record.primary_diagnostic_id == _DIAG_MID


def test_exited_accepts_an_optional_primary_diagnostic_for_a_recognized_exit() -> None:
    record = _record(
        _C.EXITED, primary_diagnostic_id=_DIAG_MID, diagnostic_ids=(_DIAG_MID,)
    )
    assert record.primary_diagnostic_id == _DIAG_MID
    assert _missing(_record(_C.EXITED).primary_diagnostic_id)


@pytest.mark.parametrize("state", _TERMINAL_STATES)
def test_the_primary_diagnostic_must_be_a_member_of_the_diagnostic_array(
    state: CommandInvocationState,
) -> None:
    with pytest.raises(ValidationError, match="member of diagnostic_ids"):
        _record(state, primary_diagnostic_id=_DIAG_MID, diagnostic_ids=(_DIAG_LOW,))
    with pytest.raises(ValidationError, match="member of diagnostic_ids"):
        _record(state, primary_diagnostic_id=_DIAG_MID, diagnostic_ids=())
    record = _record(
        state,
        primary_diagnostic_id=_DIAG_MID,
        diagnostic_ids=(_DIAG_LOW, _DIAG_MID, _DIAG_HIGH),
    )
    assert record.primary_diagnostic_id in record.diagnostic_ids


def test_diagnostic_ids_are_sorted_unique_bounded_and_explicitly_present() -> None:
    with pytest.raises(ValidationError, match="unique"):
        _record(diagnostic_ids=(_DIAG_MID, _DIAG_MID))
    with pytest.raises(ValidationError, match="sorted"):
        _record(diagnostic_ids=(_DIAG_HIGH, _DIAG_LOW))
    with pytest.raises(ValidationError, match="diagnostic_ids"):
        _record(diagnostic_ids=_ABSENT)
    with pytest.raises(ValidationError):
        _record(diagnostic_ids=None)
    too_many = tuple(sorted(f"diag_{_UUID_A[:-4]}{index:04x}" for index in range(65)))
    with pytest.raises(ValidationError):
        _record(diagnostic_ids=too_many)
    assert len(_record(diagnostic_ids=too_many[:64]).diagnostic_ids) == 64
    assert _record().diagnostic_ids == ()


def test_updated_at_may_not_precede_created_at() -> None:
    with pytest.raises(ValidationError, match="updated_at_utc"):
        _record(updated_at_utc=_CREATED - timedelta(seconds=1))
    assert _record(updated_at_utc=_CREATED).updated_at_utc == _CREATED


def test_revision_is_a_non_negative_strict_integer() -> None:
    with pytest.raises(ValidationError):
        _record(revision=-1)
    assert _record(revision=0).revision == 0
    assert _record(revision=7).revision == 7


# --- Determinism and dumps (plan section 3.1) --------------------------------------


@pytest.mark.parametrize("field", _OPTIONAL_FIELDS)
def test_absent_fields_are_omitted_from_both_dump_modes_and_null_is_rejected(
    field: str,
) -> None:
    record = _describe() if field == "run_id" else _record()
    assert getattr(record, field) is MISSING
    assert field not in record.model_dump(mode="json")
    assert field not in record.model_dump(mode="python")
    payload = record.model_dump(mode="python")
    payload[field] = None
    with pytest.raises(ValidationError):
        CommandInvocationRecord.model_validate(payload)


@pytest.mark.parametrize("state", _ALL_STATES)
def test_every_shaped_record_round_trips_through_json_deterministically(
    state: CommandInvocationState,
) -> None:
    record = (
        _record(state, cleanup_complete=True, cleanup_completed_at_utc=_CLEANED)
        if (state in TERMINAL_COMMAND_INVOCATION_STATES)
        else _record(state)
    )
    again = CommandInvocationRecord.model_validate_json(record.model_dump_json())
    assert again == record
    assert canonical_json_bytes(again) == canonical_json_bytes(record)
    assert canonical_json_bytes(_rebuild(record)) == canonical_json_bytes(record)
    dumped = record.model_dump(mode="json")
    assert tuple(dumped) == tuple(f for f in _RECORD_FIELDS if f in dumped)
    assert dumped["state"] == state.value
    assert dumped["created_at_utc"] == "2026-09-06T12:00:00Z"
    if state is _C.EXITED:
        assert dumped["process_exit_category"] == "SUCCESS"
        assert dumped["native_exit_value"] == 0


def test_json_mode_serializes_nested_process_identity_as_a_plain_object() -> None:
    dumped = _record(_C.RUNNING).model_dump(mode="json")
    assert dumped["pid_identity"] == {
        "pid": 4321,
        "creation_identity": "2026-09-06T12:00:03.1234567Z#0001",
        "executable_path": r"C:\adapters\alpha\adapter.exe",
        "executable_hash": _EXECUTABLE_HASH,
        "supervisor_instance_id": "supervisor-01",
    }
    assert dumped["process_started_at_utc"] == "2026-09-06T12:00:03Z"


# --- Parent eligibility (plan section 6 matrix) -----------------------------------


def _parent_state_id(value: object) -> str:
    return "no_parent" if value is MISSING else str(getattr(value, "value", value))


@pytest.mark.parametrize("command_kind", list(CommandKind))
@pytest.mark.parametrize(
    "parent_state", [*EngineRunState, MISSING], ids=_parent_state_id
)
def test_the_parent_eligibility_matrix_for_every_kind_against_every_parent_state(
    command_kind: CommandKind,
    parent_state: object,
) -> None:
    linked = command_kind is not _K.DESCRIBE
    accepted = {
        (_K.DESCRIBE, MISSING),
        (_K.VALIDATE, _R.VALIDATING),
        (_K.RUN, _R.READY),
    }
    if (command_kind, parent_state) in accepted:
        assert_parent_run_eligibility(
            command_kind,
            run_id=_RUN_ID if linked else MISSING,
            expected_run_revision=3 if linked else MISSING,
            parent_run_state=parent_state,
        )
        return
    with pytest.raises(CommandInvocationRuleViolation) as info:
        assert_parent_run_eligibility(
            command_kind,
            run_id=_RUN_ID if linked else MISSING,
            expected_run_revision=3 if linked else MISSING,
            parent_run_state=parent_state,
        )
    assert info.value.check is _CHECK.PARENT_RUN_STATE


def test_exactly_three_cells_of_the_thirty_nine_are_eligible() -> None:
    cells = [(k, s) for k in CommandKind for s in (*EngineRunState, MISSING)]
    assert len(cells) == 39
    eligible: list[tuple[CommandKind, object]] = []
    for command_kind, parent_state in cells:
        linked = command_kind is not _K.DESCRIBE
        try:
            assert_parent_run_eligibility(
                command_kind,
                run_id=_RUN_ID if linked else MISSING,
                expected_run_revision=0 if linked else MISSING,
                parent_run_state=parent_state,
            )
        except CommandInvocationRuleViolation:
            continue
        eligible.append((command_kind, parent_state))
    assert eligible == [
        (_K.DESCRIBE, MISSING),
        (_K.VALIDATE, _R.VALIDATING),
        (_K.RUN, _R.READY),
    ]


@pytest.mark.parametrize("command_kind", list(CommandKind))
@pytest.mark.parametrize(
    ("run_present", "revision_present"),
    [(True, True), (True, False), (False, True), (False, False)],
    ids=["both", "run_only", "revision_only", "neither"],
)
def test_linkage_presence_is_checked_before_the_parent_state(
    command_kind: CommandKind,
    run_present: bool,
    revision_present: bool,
) -> None:
    linked = command_kind is not _K.DESCRIBE
    required_state: object = {
        _K.DESCRIBE: MISSING,
        _K.VALIDATE: _R.VALIDATING,
        _K.RUN: _R.READY,
    }[command_kind]
    kwargs: dict[str, object] = {
        "run_id": _RUN_ID if run_present else MISSING,
        "expected_run_revision": 3 if revision_present else MISSING,
        "parent_run_state": required_state,
    }
    if run_present is linked and revision_present is linked:
        assert_parent_run_eligibility(command_kind, **kwargs)
        return
    with pytest.raises(CommandInvocationRuleViolation) as info:
        assert_parent_run_eligibility(command_kind, **kwargs)
    assert info.value.check is _CHECK.PARENT_LINKAGE
    # A wrong parent state does not mask the linkage failure.
    kwargs["parent_run_state"] = _R.RUNNING
    with pytest.raises(CommandInvocationRuleViolation) as again:
        assert_parent_run_eligibility(command_kind, **kwargs)
    assert again.value.check is _CHECK.PARENT_LINKAGE


def test_the_eligibility_function_is_pure_and_the_violation_names_its_check() -> None:
    for _ in range(2):  # pure: the same inputs pass the same way twice
        assert_parent_run_eligibility(
            _K.DESCRIBE,
            run_id=MISSING,
            expected_run_revision=MISSING,
            parent_run_state=MISSING,
        )
    violation = CommandInvocationRuleViolation(_CHECK.PARENT_LINKAGE, "probe")
    assert isinstance(violation, ValueError)
    assert violation.check is _CHECK.PARENT_LINKAGE
    assert str(violation) == "probe"
    # A bare string is refused even though it equals a member, as in `lifecycle`
    # and `command_timeout_bounds`; otherwise "DESCRIBE" would read as linked.
    with pytest.raises(TypeError):
        assert_parent_run_eligibility(
            "DESCRIBE",  # type: ignore[arg-type]
            run_id=MISSING,
            expected_run_revision=MISSING,
            parent_run_state=MISSING,
        )


# --- Pure transition predicate (Task 1 table, plan sections 3.7 and 6) ------------


@pytest.mark.parametrize(
    ("current", "target"),
    _ALL_PAIRS,
    ids=[f"{a.value}->{b.value}" for a, b in _ALL_PAIRS],
)
def test_every_ordered_state_pair_is_accepted_exactly_on_the_ten_table_edges(
    current: CommandInvocationState,
    target: CommandInvocationState,
) -> None:
    stored = _record(current)
    allowed = COMMAND_INVOCATION_TRANSITIONS.is_allowed(current, target)
    if allowed:
        replacement = _advance(stored, target)
        assert_invocation_transition(stored, replacement)
        assert replacement.revision == stored.revision + 1
        return
    # A shape-consistent record in the target state at the next revision: the
    # only thing wrong with it is the edge, so the edge is what must be named.
    replacement = _record(target, revision=stored.revision + 1)
    with pytest.raises(CommandInvocationRuleViolation) as info:
        assert_invocation_transition(stored, replacement)
    assert info.value.check is _CHECK.TRANSITION_EDGE


def test_the_transition_table_has_exactly_ten_edges_and_five_terminals() -> None:
    """Preventive: Task 1 pins the arithmetic; Task 3 depends on it."""
    assert len(COMMAND_INVOCATION_TRANSITIONS.transitions) == 10
    assert len(_ALL_PAIRS) == 64
    assert TERMINAL_COMMAND_INVOCATION_STATES == frozenset(_TERMINAL_STATES)


@pytest.mark.parametrize("state", _TERMINAL_STATES)
def test_a_terminal_record_accepts_no_transition_including_replay(
    state: CommandInvocationState,
) -> None:
    stored = _record(state)
    for target in _ALL_STATES:
        replacement = _record(target, revision=stored.revision + 1)
        with pytest.raises(CommandInvocationRuleViolation) as info:
            assert_invocation_transition(stored, replacement)
        assert info.value.check is _CHECK.TRANSITION_EDGE


def test_a_reflexive_pair_is_never_an_edge_because_replay_is_a_service_rule() -> None:
    stored = _record(_C.STARTING)
    replacement = _enrich(stored, diagnostic_ids=(_DIAG_LOW,))
    with pytest.raises(CommandInvocationRuleViolation) as info:
        assert_invocation_transition(stored, replacement)
    assert info.value.check is _CHECK.TRANSITION_EDGE


def test_a_transition_between_different_invocations_is_an_identity_violation() -> None:
    stored = _record(_C.PENDING)
    replacement = _advance(stored, _C.STARTING, invocation_id=_OTHER_INVOCATION_ID)
    with pytest.raises(CommandInvocationRuleViolation) as info:
        assert_invocation_transition(stored, replacement)
    assert info.value.check is _CHECK.IDENTITY


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("command_kind", _K.RUN),
        ("adapter_name", "adapter.beta"),
        ("adapter_version", "1.0.1"),
        ("run_id", _OTHER_RUN_ID),
        ("request_hash", _OTHER_REQUEST_HASH),
        ("created_at_utc", _CREATED - timedelta(seconds=1)),
    ],
)
def test_an_immutable_field_may_not_change_across_an_allowed_edge(
    field: str,
    value: object,
) -> None:
    stored = _record(_C.PENDING)
    replacement = _advance(stored, _C.STARTING, **{field: value})
    with pytest.raises(CommandInvocationRuleViolation) as info:
        assert_invocation_transition(stored, replacement)
    assert info.value.check is _CHECK.TRANSITION_IMMUTABLE_FIELD


def test_timeout_seconds_may_not_change_even_with_a_consistent_deadline() -> None:
    stored = _record(_C.PENDING)
    instant = stored.updated_at_utc + timedelta(seconds=1)
    replacement = _advance(
        stored,
        _C.STARTING,
        timeout_seconds=_TIMEOUT + 1,
        deadline_utc=instant + timedelta(seconds=_TIMEOUT + 1),
    )
    with pytest.raises(CommandInvocationRuleViolation) as info:
        assert_invocation_transition(stored, replacement)
    assert info.value.check is _CHECK.TRANSITION_IMMUTABLE_FIELD


def test_run_id_may_not_appear_or_vanish_across_an_edge() -> None:
    stored = _describe(_C.PENDING)
    replacement = _advance(
        stored, _C.STARTING, command_kind=_K.VALIDATE, run_id=_RUN_ID
    )
    with pytest.raises(CommandInvocationRuleViolation) as info:
        assert_invocation_transition(stored, replacement)
    assert info.value.check is _CHECK.TRANSITION_IMMUTABLE_FIELD


def test_launch_facts_are_established_only_on_pending_to_starting() -> None:
    pending = _record(_C.PENDING)
    # PENDING -> CANCELLED must not invent a deadline it never established.
    cancelled = _advance(pending, _C.CANCELLED, **_group("launch"))
    with pytest.raises(CommandInvocationRuleViolation) as info:
        assert_invocation_transition(pending, cancelled)
    assert info.value.check is _CHECK.TRANSITION_LAUNCH_FACTS
    assert_invocation_transition(pending, _advance(pending, _C.CANCELLED))
    # Once established, both facts are carried forward unchanged.
    starting = _record(_C.STARTING)
    moved = _advance(
        starting,
        _C.RUNNING,
        launch_attempted_at_utc=_LAUNCH + timedelta(seconds=1),
        deadline_utc=_DEADLINE + timedelta(seconds=1),
    )
    with pytest.raises(CommandInvocationRuleViolation) as again:
        assert_invocation_transition(starting, moved)
    assert again.value.check is _CHECK.TRANSITION_LAUNCH_FACTS


def test_process_facts_are_established_only_on_starting_to_running() -> None:
    starting = _record(_C.STARTING)
    for target in (_C.CANCELLED, _C.TIMED_OUT):
        replacement = _advance(starting, target, **_group("process"))
        with pytest.raises(CommandInvocationRuleViolation) as info:
            assert_invocation_transition(starting, replacement)
        assert info.value.check is _CHECK.TRANSITION_PROCESS_FACTS, target
        assert_invocation_transition(starting, _advance(starting, target))
    running = _record(_C.RUNNING)
    # Once owned, the process identity is carried forward unchanged...
    changed = _advance(running, _C.EXITED, pid_identity=_pid_identity(pid=9999))
    with pytest.raises(CommandInvocationRuleViolation) as again:
        assert_invocation_transition(running, changed)
    assert again.value.check is _CHECK.TRANSITION_PROCESS_FACTS
    # ...and never dropped, even where the target shape would permit its absence.
    dropped = _advance(running, _C.CANCELLED, **_removal("process"))
    with pytest.raises(CommandInvocationRuleViolation) as third:
        assert_invocation_transition(running, dropped)
    assert third.value.check is _CHECK.TRANSITION_PROCESS_FACTS


def test_cleanup_changes_only_through_terminal_enrichment_never_a_transition() -> None:
    running = _record(_C.RUNNING)
    for target in (_C.EXITED, _C.CANCELLED, _C.TIMED_OUT, _C.PROTOCOL_FAILED):
        replacement = _advance(running, target, **_group("cleanup"))
        with pytest.raises(CommandInvocationRuleViolation) as info:
            assert_invocation_transition(running, replacement)
        assert info.value.check is _CHECK.TRANSITION_CLEANUP, target


def test_diagnostic_ids_never_lose_a_member_across_a_transition() -> None:
    stored = _record(_C.PENDING, diagnostic_ids=(_DIAG_LOW, _DIAG_HIGH))
    grown = _advance(
        stored, _C.STARTING, diagnostic_ids=(_DIAG_LOW, _DIAG_MID, _DIAG_HIGH)
    )
    assert_invocation_transition(stored, grown)
    same = _advance(stored, _C.STARTING)
    assert_invocation_transition(stored, same)
    shrunk = _advance(stored, _C.STARTING, diagnostic_ids=(_DIAG_LOW,))
    with pytest.raises(CommandInvocationRuleViolation) as info:
        assert_invocation_transition(stored, shrunk)
    assert info.value.check is _CHECK.TRANSITION_DIAGNOSTICS


@pytest.mark.parametrize("delta", [0, 2, -1])
def test_a_transition_increments_the_revision_by_exactly_one(delta: int) -> None:
    stored = _record(_C.STARTING)
    if stored.revision + delta < 0:
        return
    replacement = _advance(stored, _C.RUNNING, revision=stored.revision + delta)
    with pytest.raises(CommandInvocationRuleViolation) as info:
        assert_invocation_transition(stored, replacement)
    assert info.value.check is _CHECK.REVISION


def test_a_transition_never_moves_updated_at_backwards() -> None:
    stored = _record(_C.STARTING)
    equal = _advance(
        stored,
        _C.RUNNING,
        updated_at_utc=stored.updated_at_utc,
        process_started_at_utc=stored.updated_at_utc,
    )
    assert_invocation_transition(stored, equal)
    earlier = _advance(
        stored,
        _C.RUNNING,
        updated_at_utc=stored.updated_at_utc - timedelta(seconds=1),
    )
    with pytest.raises(CommandInvocationRuleViolation) as info:
        assert_invocation_transition(stored, earlier)
    assert info.value.check is _CHECK.UPDATED_AT


def test_a_describe_invocation_walks_its_whole_lifecycle_through_the_predicates() -> (
    None
):
    """Preventive: no rule couples command kind with state, so this begins green.
    It pins that a run-less record passes every pair rule, including the
    MISSING-to-MISSING ``run_id`` immutability comparison, and then enriches."""
    record = _describe(_C.PENDING)
    for target in (_C.STARTING, _C.RUNNING, _C.EXITED):
        following = _advance(record, target)
        assert_invocation_transition(record, following)
        assert _missing(following.run_id)
        assert following.command_kind is _K.DESCRIBE
        record = following
    assert record.state is _C.EXITED
    assert_write_once_enrichment(record, _enrich(record, **_group("cleanup")))


def test_transition_checks_are_reported_in_a_fixed_order() -> None:
    """Identity before edge before content, so the loudest defect is named."""
    stored = _record(_C.PENDING)
    replacement = _record(
        _C.RUNNING,
        invocation_id=_OTHER_INVOCATION_ID,
        revision=stored.revision + 5,
    )
    with pytest.raises(CommandInvocationRuleViolation) as info:
        assert_invocation_transition(stored, replacement)
    assert info.value.check is _CHECK.IDENTITY
    replacement = _record(_C.RUNNING, revision=stored.revision + 5)
    with pytest.raises(CommandInvocationRuleViolation) as again:
        assert_invocation_transition(stored, replacement)
    assert again.value.check is _CHECK.TRANSITION_EDGE


# --- Write-once terminal enrichment (plan section 6) --------------------------------


def _enrichments(state: CommandInvocationState) -> dict[str, dict[str, object]]:
    """The four write-once enrichments, minus any the state's shape prohibits."""
    enrichments: dict[str, dict[str, object]] = {
        "cleanup": _group("cleanup"),
        "stderr": _group("stderr"),
        "diagnostics": {"diagnostic_ids": (_DIAG_LOW, _DIAG_MID)},
    }
    if state in _EXIT_OPTIONAL_STATES:
        enrichments["exit"] = {
            "native_exit_value": 40,
            "process_exit_category": _X.RUNTIME_FAILURE,
        }
    if state is _C.EXITED:
        enrichments["diagnostics"] = {"diagnostic_ids": (_DIAG_LOW,)}
    return enrichments


@pytest.mark.parametrize("state", _TERMINAL_STATES)
def test_each_write_once_enrichment_is_accepted_alone_and_together(
    state: CommandInvocationState,
) -> None:
    stored = _record(state)
    combined: dict[str, object] = {}
    for name, enrichment in _enrichments(state).items():
        replacement = _enrich(stored, **enrichment)
        assert_write_once_enrichment(stored, replacement)
        assert replacement.state is state, name
        combined.update(enrichment)
    assert_write_once_enrichment(stored, _enrich(stored, **combined))


def test_the_exit_pair_is_never_an_enrichment_of_failed_to_start() -> None:
    stored = _record(_C.FAILED_TO_START)
    with pytest.raises(ValidationError):
        _enrich(stored, native_exit_value=40, process_exit_category=_X.RUNTIME_FAILURE)


@pytest.mark.parametrize("state", _NON_TERMINAL_STATES)
def test_a_non_terminal_record_accepts_no_enrichment(
    state: CommandInvocationState,
) -> None:
    stored = _record(state)
    replacement = _enrich(stored, diagnostic_ids=(_DIAG_LOW,))
    with pytest.raises(CommandInvocationRuleViolation) as info:
        assert_write_once_enrichment(stored, replacement)
    assert info.value.check is _CHECK.ENRICHMENT_NOT_TERMINAL


def test_enrichment_never_alters_the_state() -> None:
    stored = _record(_C.CANCELLED)
    replacement = _record(_C.TIMED_OUT, revision=stored.revision + 1)
    with pytest.raises(CommandInvocationRuleViolation) as info:
        assert_write_once_enrichment(stored, replacement)
    assert info.value.check is _CHECK.ENRICHMENT_STATE


def test_enrichment_between_different_invocations_is_an_identity_violation() -> None:
    stored = _record(_C.EXITED)
    replacement = _enrich(
        stored, invocation_id=_OTHER_INVOCATION_ID, **_group("stderr")
    )
    with pytest.raises(CommandInvocationRuleViolation) as info:
        assert_write_once_enrichment(stored, replacement)
    assert info.value.check is _CHECK.IDENTITY


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("adapter_name", "adapter.beta"),
        ("request_hash", _OTHER_REQUEST_HASH),
        ("created_at_utc", _CREATED - timedelta(seconds=1)),
        ("completed_at_utc", _COMPLETED + timedelta(seconds=1)),
        ("process_started_at_utc", _STARTED + timedelta(seconds=1)),
        ("pid_identity", _pid_identity(pid=9999)),
        ("launch_attempted_at_utc", _LAUNCH + timedelta(seconds=1)),
    ],
)
def test_a_non_enrichable_field_may_not_change_under_enrichment(
    field: str,
    value: object,
) -> None:
    stored = _record(_C.CANCELLED)
    overrides: dict[str, object] = {field: value, **_group("stderr")}
    if field == "launch_attempted_at_utc":
        overrides["deadline_utc"] = _DEADLINE + timedelta(seconds=1)
    replacement = _enrich(stored, **overrides)
    with pytest.raises(CommandInvocationRuleViolation) as info:
        assert_write_once_enrichment(stored, replacement)
    assert info.value.check is _CHECK.ENRICHMENT_IMMUTABLE_FIELD


def test_the_primary_diagnostic_is_not_an_enrichment() -> None:
    stored = _record(_C.CANCELLED, diagnostic_ids=(_DIAG_LOW, _DIAG_MID))
    swapped = _enrich(stored, primary_diagnostic_id=_DIAG_LOW)
    with pytest.raises(CommandInvocationRuleViolation) as info:
        assert_write_once_enrichment(stored, swapped)
    assert info.value.check is _CHECK.ENRICHMENT_IMMUTABLE_FIELD
    exited = _record(_C.EXITED)
    added = _enrich(
        exited, primary_diagnostic_id=_DIAG_MID, diagnostic_ids=(_DIAG_MID,)
    )
    with pytest.raises(CommandInvocationRuleViolation) as again:
        assert_write_once_enrichment(exited, added)
    assert again.value.check is _CHECK.ENRICHMENT_IMMUTABLE_FIELD


def test_enrichment_never_overwrites_an_existing_exit_pair() -> None:
    exited = _record(_C.EXITED)
    changed = _enrich(
        exited, native_exit_value=40, process_exit_category=_X.RUNTIME_FAILURE
    )
    with pytest.raises(CommandInvocationRuleViolation) as info:
        assert_write_once_enrichment(exited, changed)
    assert info.value.check is _CHECK.ENRICHMENT_OVERWRITE
    cancelled = _record(
        _C.CANCELLED, native_exit_value=50, process_exit_category=_X.CANCELLED
    )
    removed = _enrich(cancelled, **_removal("exit"), **_group("stderr"))
    with pytest.raises(CommandInvocationRuleViolation) as again:
        assert_write_once_enrichment(cancelled, removed)
    assert again.value.check is _CHECK.ENRICHMENT_OVERWRITE


def test_enrichment_never_reverts_or_moves_a_completed_cleanup() -> None:
    cleaned = _record(_C.TIMED_OUT, **_group("cleanup"))
    reverted = _enrich(cleaned, **_removal("cleanup"), **_group("stderr"))
    with pytest.raises(CommandInvocationRuleViolation) as info:
        assert_write_once_enrichment(cleaned, reverted)
    assert info.value.check is _CHECK.ENRICHMENT_OVERWRITE
    moved = _enrich(cleaned, cleanup_completed_at_utc=_CLEANED + timedelta(seconds=1))
    with pytest.raises(CommandInvocationRuleViolation) as again:
        assert_write_once_enrichment(cleaned, moved)
    assert again.value.check is _CHECK.ENRICHMENT_OVERWRITE


def test_enrichment_never_replaces_or_drops_a_stderr_reference() -> None:
    stored = _record(_C.PROTOCOL_FAILED, **_group("stderr"))
    replaced = _enrich(stored, stderr_artifact_id=_OTHER_ARTIFACT_ID)
    with pytest.raises(CommandInvocationRuleViolation) as info:
        assert_write_once_enrichment(stored, replaced)
    assert info.value.check is _CHECK.ENRICHMENT_OVERWRITE
    dropped = _enrich(stored, stderr_artifact_id=_ABSENT, **_group("cleanup"))
    with pytest.raises(CommandInvocationRuleViolation) as again:
        assert_write_once_enrichment(stored, dropped)
    assert again.value.check is _CHECK.ENRICHMENT_OVERWRITE


def test_enrichment_never_removes_a_recorded_diagnostic() -> None:
    stored = _record(_C.CANCELLED, diagnostic_ids=(_DIAG_LOW, _DIAG_MID))
    shrunk = _enrich(stored, diagnostic_ids=(_DIAG_MID,), **_group("stderr"))
    with pytest.raises(CommandInvocationRuleViolation) as info:
        assert_write_once_enrichment(stored, shrunk)
    assert info.value.check is _CHECK.ENRICHMENT_OVERWRITE


def test_an_identical_existing_value_is_not_an_overwrite() -> None:
    """A replay that restates a stored fact while adding another is accepted; a
    replay that restates everything and adds nothing is rejected as empty."""
    stored = _record(_C.EXITED, **_group("stderr"))
    restated = _enrich(stored, **_group("stderr"), diagnostic_ids=(_DIAG_LOW,))
    assert_write_once_enrichment(stored, restated)
    empty = _enrich(stored, **_group("stderr"))
    with pytest.raises(CommandInvocationRuleViolation) as info:
        assert_write_once_enrichment(stored, empty)
    assert info.value.check is _CHECK.ENRICHMENT_EMPTY


@pytest.mark.parametrize("state", _TERMINAL_STATES)
def test_an_enrichment_that_adds_nothing_is_rejected(
    state: CommandInvocationState,
) -> None:
    stored = _record(state)
    with pytest.raises(CommandInvocationRuleViolation) as info:
        assert_write_once_enrichment(stored, _enrich(stored))
    assert info.value.check is _CHECK.ENRICHMENT_EMPTY


@pytest.mark.parametrize("delta", [0, 2])
def test_an_enrichment_increments_the_revision_by_exactly_one(delta: int) -> None:
    stored = _record(_C.EXITED)
    replacement = _enrich(stored, revision=stored.revision + delta, **_group("stderr"))
    with pytest.raises(CommandInvocationRuleViolation) as info:
        assert_write_once_enrichment(stored, replacement)
    assert info.value.check is _CHECK.REVISION


def test_an_enrichment_never_moves_updated_at_backwards() -> None:
    stored = _record(_C.EXITED)
    equal = _enrich(stored, updated_at_utc=stored.updated_at_utc, **_group("stderr"))
    assert_write_once_enrichment(stored, equal)
    earlier = _enrich(
        stored,
        updated_at_utc=stored.updated_at_utc - timedelta(seconds=1),
        **_group("stderr"),
    )
    with pytest.raises(CommandInvocationRuleViolation) as info:
        assert_write_once_enrichment(stored, earlier)
    assert info.value.check is _CHECK.UPDATED_AT


def test_the_check_vocabulary_is_closed_and_every_member_is_reachable() -> None:
    assert [m.value for m in CommandInvocationCheck] == [
        "IDENTITY",
        "REVISION",
        "UPDATED_AT",
        "PARENT_LINKAGE",
        "PARENT_RUN_STATE",
        "TRANSITION_EDGE",
        "TRANSITION_IMMUTABLE_FIELD",
        "TRANSITION_LAUNCH_FACTS",
        "TRANSITION_PROCESS_FACTS",
        "TRANSITION_CLEANUP",
        "TRANSITION_DIAGNOSTICS",
        "ENRICHMENT_NOT_TERMINAL",
        "ENRICHMENT_STATE",
        "ENRICHMENT_IMMUTABLE_FIELD",
        "ENRICHMENT_OVERWRITE",
        "ENRICHMENT_EMPTY",
    ]
    source = _module_source(invocation_module)
    for member in CommandInvocationCheck:
        assert source.count(f"CommandInvocationCheck.{member.name}") >= 1, member


# --- Package surface, purity and task boundary -------------------------------------


def test_the_domain_package_re_exports_every_task_three_name() -> None:
    for name in (
        "CommandInvocationCheck",
        "CommandInvocationRecord",
        "CommandInvocationRuleViolation",
        "ProcessIdentity",
        "ProcessStartFacts",
        "TimeoutBounds",
        "assert_invocation_transition",
        "assert_parent_run_eligibility",
        "assert_write_once_enrichment",
        "command_timeout_bounds",
    ):
        assert name in domain_package.__all__, name
        assert getattr(domain_package, name) is getattr(invocation_module, name), name


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
    for node in ast.walk(ast.parse(_module_source(invocation_module))):
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


def test_the_module_defines_no_task_four_or_later_name() -> None:
    defined = {
        node.name
        for node in ast.walk(ast.parse(_module_source(invocation_module)))
        if isinstance(node, ast.ClassDef | ast.FunctionDef)
    }
    for later in (
        "EngineRunRecord",
        "AttemptTokenMaterial",
        "is_mixed_running_pair",
        "CommandInvocationRepository",
        "InvocationCreationRequest",
        "transition_invocation",
        "create_invocation",
        "enrich_invocation",
    ):
        assert later not in defined, later
