"""Property tests over the three Stage 5 lifecycle machines (plan section 12, Task 4).

For arbitrary ordered state pairs of each machine, acceptance holds **exactly** on
the tabulated edges: the specification's "Allowed next states" columns (sections
16.1, 17.1 and 15.2) are restated here as the oracle, and every layer that
answers the question -- the Task 1 table and ``is_allowed_transition``, the Task 3
record-pair predicate for the invocation, and the Task 4 record-pair predicate for
the engine run under both its generic and its linked authority -- must agree with
the oracle on every generated pair. A pair is drawn from the full ordered product,
so the forbidden complement is exercised as often as the edges.

Two further engine-run properties pin the shape rules the predicate relies on:
every generated ``(state, attempt_number)`` builds exactly one consistent record,
and the successor facts are present exactly when the attempt number exceeds one.

The experiment and invocation properties begin green against the committed Task 1
and Task 3 trees and are labelled preventive; the engine-run properties are the
Task 4 RED. Generators draw plain enum members and small integers only.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Final

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.domain.command_invocation import (
    CommandInvocationRecord,
    CommandInvocationRuleViolation,
    ProcessIdentity,
    assert_invocation_transition,
)
from crypto_lab.domain.engine_run import (
    LINKED_ONLY_RUN_EDGES,
    NON_SUCCESS_TERMINAL_ENGINE_RUN_STATES,
    EngineRunCheck,
    EngineRunRecord,
    EngineRunRuleViolation,
    RunEdgeOwner,
    assert_run_transition,
    run_edge_owner,
)
from crypto_lab.domain.experiment import AdapterIdentity, EngineIdentity
from crypto_lab.domain.hashing import attempt_token_hash
from crypto_lab.domain.lifecycle import (
    COMMAND_INVOCATION_TRANSITIONS,
    ENGINE_RUN_TRANSITIONS,
    EXPERIMENT_TRANSITIONS,
    TERMINAL_COMMAND_INVOCATION_STATES,
    TERMINAL_ENGINE_RUN_STATES,
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
    ProcessExitCategory,
    RetryTerminalState,
    TransitionTable,
    is_allowed_transition,
)
from crypto_lab.domain.retry import MAX_ATTEMPTS_PER_SLOT

_E = ExperimentState
_R = EngineRunState
_C = CommandInvocationState

# --- The oracle: the specification's "Allowed next states" columns -----------------

_EXPERIMENT_SUCCESSORS: Final[dict[ExperimentState, frozenset[ExperimentState]]] = {
    _E.DRAFT: frozenset({_E.VALIDATED, _E.CANCELLED}),
    _E.VALIDATED: frozenset({_E.DRAFT, _E.QUEUED, _E.CANCELLED}),
    _E.QUEUED: frozenset({_E.RUNNING, _E.FAILED, _E.CANCELLED}),
    _E.RUNNING: frozenset(
        {_E.COMPLETED, _E.COMPLETED_WITH_WARNINGS, _E.FAILED, _E.CANCELLED}
    ),
    _E.COMPLETED: frozenset(),
    _E.COMPLETED_WITH_WARNINGS: frozenset(),
    _E.FAILED: frozenset(),
    _E.CANCELLED: frozenset(),
}
_ENGINE_RUN_SUCCESSORS: Final[dict[EngineRunState, frozenset[EngineRunState]]] = {
    _R.PENDING: frozenset({_R.VALIDATING, _R.CANCELLED}),
    _R.VALIDATING: frozenset(
        {
            _R.READY,
            _R.NOT_APPLICABLE,
            _R.UNAVAILABLE,
            _R.FAILED,
            _R.CANCELLED,
            _R.TIMED_OUT,
        }
    ),
    _R.READY: frozenset({_R.STARTING, _R.UNAVAILABLE, _R.CANCELLED}),
    _R.STARTING: frozenset(
        {_R.RUNNING, _R.FAILED, _R.UNAVAILABLE, _R.CANCELLED, _R.TIMED_OUT}
    ),
    _R.RUNNING: frozenset(
        {
            _R.SUCCEEDED,
            _R.SUCCEEDED_WITH_WARNINGS,
            _R.NOT_APPLICABLE,
            _R.UNAVAILABLE,
            _R.FAILED,
            _R.CANCELLED,
            _R.TIMED_OUT,
        }
    ),
    _R.SUCCEEDED: frozenset(),
    _R.SUCCEEDED_WITH_WARNINGS: frozenset(),
    _R.FAILED: frozenset(),
    _R.CANCELLED: frozenset(),
    _R.TIMED_OUT: frozenset(),
    _R.NOT_APPLICABLE: frozenset(),
    _R.UNAVAILABLE: frozenset(),
}
_COMMAND_INVOCATION_SUCCESSORS: Final[
    dict[CommandInvocationState, frozenset[CommandInvocationState]]
] = {
    _C.PENDING: frozenset({_C.STARTING, _C.CANCELLED}),
    _C.STARTING: frozenset(
        {_C.RUNNING, _C.FAILED_TO_START, _C.CANCELLED, _C.TIMED_OUT}
    ),
    _C.RUNNING: frozenset({_C.EXITED, _C.CANCELLED, _C.TIMED_OUT, _C.PROTOCOL_FAILED}),
    _C.EXITED: frozenset(),
    _C.FAILED_TO_START: frozenset(),
    _C.CANCELLED: frozenset(),
    _C.TIMED_OUT: frozenset(),
    _C.PROTOCOL_FAILED: frozenset(),
}
#: Plan section 5: the two edges owned by the linked operations alone.
_LINKED_EDGES: Final = frozenset({(_R.READY, _R.STARTING), (_R.STARTING, _R.RUNNING)})

_EXPERIMENT_PAIRS = st.tuples(st.sampled_from(list(_E)), st.sampled_from(list(_E)))
_RUN_PAIRS = st.tuples(st.sampled_from(list(_R)), st.sampled_from(list(_R)))
_INVOCATION_PAIRS = st.tuples(st.sampled_from(list(_C)), st.sampled_from(list(_C)))
_RUN_STATES = st.sampled_from(list(_R))
_ATTEMPTS = st.integers(min_value=1, max_value=MAX_ATTEMPTS_PER_SLOT)
_BAD_ATTEMPTS = st.one_of(
    st.integers(min_value=-16, max_value=0),
    st.integers(min_value=MAX_ATTEMPTS_PER_SLOT + 1, max_value=64),
)

# --- Fixtures ---------------------------------------------------------------------

_UUID_A = "12345678-1234-4234-8234-123456789abc"
_UUID_B = "9f8e7d6c-5b4a-4321-8fed-cba987654321"
_CREATED = datetime(2026, 9, 7, 12, 0, 0, tzinfo=UTC)
_RUN_ID = f"run_{_UUID_A}"
_PREDECESSOR_RUN_ID = f"run_{_UUID_B}"
_OBSERVATION_ID = f"avail_{_UUID_A}"
_DIAG_ID = f"diag_{_UUID_A}"
_ADAPTER = AdapterIdentity(adapter_name="adapter.alpha", adapter_version="1.0.0")
_ENGINE = EngineIdentity(engine_name="engine.alpha", engine_version="2.0.0")
_OBSERVATION_PROHIBITED = frozenset({_R.PENDING, _R.VALIDATING})
_OBSERVATION_REQUIRED = frozenset(
    {
        _R.READY,
        _R.STARTING,
        _R.RUNNING,
        _R.SUCCEEDED,
        _R.SUCCEEDED_WITH_WARNINGS,
        _R.UNAVAILABLE,
    }
)


def _missing(value: object) -> bool:
    return value is MISSING


def _run_payload(state: EngineRunState, attempt_number: int) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "run_id": _RUN_ID,
        "experiment_id": f"exp_{_UUID_A}",
        "logical_slot_id": f"slot_{_UUID_A}",
        "attempt_number": attempt_number,
        "attempt_token_hash": attempt_token_hash("A" * 32),
        "state": state,
        "adapter": _ADAPTER,
        "engine": _ENGINE,
        "request_hash": "a" * 64,
        "created_at_utc": _CREATED,
        "updated_at_utc": _CREATED,
        "revision": 0,
    }
    if attempt_number > 1:
        payload["predecessor_run_id"] = _PREDECESSOR_RUN_ID
        payload["retry_reason"] = RetryTerminalState.FAILED
    if state not in _OBSERVATION_PROHIBITED:
        payload["availability_observation_id"] = _OBSERVATION_ID
    if state in NON_SUCCESS_TERMINAL_ENGINE_RUN_STATES:
        payload["primary_terminal_diagnostic_id"] = _DIAG_ID
    return payload


def _run(state: EngineRunState, attempt_number: int = 1) -> EngineRunRecord:
    return EngineRunRecord.model_validate(_run_payload(state, attempt_number))


def _advance_run(stored: EngineRunRecord, target: EngineRunState) -> EngineRunRecord:
    """A shape-valid replacement for ``stored -> target`` at revision + 1."""
    payload = stored.model_dump(mode="python")
    payload["state"] = target
    if target in _OBSERVATION_PROHIBITED:
        payload.pop("availability_observation_id", None)
    elif target in _OBSERVATION_REQUIRED:
        payload.setdefault("availability_observation_id", _OBSERVATION_ID)
    if target in NON_SUCCESS_TERMINAL_ENGINE_RUN_STATES:
        payload["primary_terminal_diagnostic_id"] = _DIAG_ID
    else:
        payload.pop("primary_terminal_diagnostic_id", None)
    payload["updated_at_utc"] = stored.updated_at_utc + timedelta(seconds=1)
    payload["revision"] = stored.revision + 1
    return EngineRunRecord.model_validate(payload)


def _invocation(state: CommandInvocationState) -> CommandInvocationRecord:
    """A shaped ``VALIDATE`` invocation; CANCELLED and TIMED_OUT come from RUNNING."""
    launch = _CREATED + timedelta(seconds=1)
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "invocation_id": f"inv_{_UUID_A}",
        "command_kind": CommandKind.VALIDATE,
        "adapter_name": "adapter.alpha",
        "adapter_version": "1.0.0",
        "run_id": _RUN_ID,
        "request_hash": "a" * 64,
        "timeout_seconds": 120,
        "state": state,
        "process_created": False,
        "cleanup_complete": False,
        "diagnostic_ids": (),
        "created_at_utc": _CREATED,
        "updated_at_utc": _CREATED,
        "revision": 0,
    }
    if state is not _C.PENDING:
        payload["deadline_utc"] = launch + timedelta(seconds=120)
        payload["launch_attempted_at_utc"] = launch
        payload["updated_at_utc"] = launch
        payload["revision"] = 1
    if state in (_C.RUNNING, _C.EXITED, _C.PROTOCOL_FAILED, _C.CANCELLED, _C.TIMED_OUT):
        payload["process_created"] = True
        payload["process_started_at_utc"] = launch + timedelta(seconds=2)
        payload["pid_identity"] = ProcessIdentity.model_validate(
            {
                "pid": 4321,
                "creation_identity": "2026-09-07T12:00:03.1234567Z#0001",
                "executable_path": r"C:\adapters\alpha\adapter.exe",
                "executable_hash": "c" * 64,
                "supervisor_instance_id": "supervisor-01",
            }
        )
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
    return CommandInvocationRecord.model_validate(payload)


def _advance_invocation(
    stored: CommandInvocationRecord,
    target: CommandInvocationState,
) -> CommandInvocationRecord:
    """The replacement a correct service would build for ``stored -> target``; for a
    forbidden pair it is a shape-consistent record of the target state, so the edge
    is the only thing the predicate can reject."""
    if not COMMAND_INVOCATION_TRANSITIONS.is_allowed(stored.state, target):
        payload = _invocation(target).model_dump(mode="python")
        payload["revision"] = stored.revision + 1
        payload["updated_at_utc"] = max(stored.updated_at_utc, _CREATED)
        return CommandInvocationRecord.model_validate(payload)
    payload = stored.model_dump(mode="python")
    instant = stored.updated_at_utc + timedelta(seconds=1)
    payload["state"] = target
    if target is _C.STARTING:
        payload["launch_attempted_at_utc"] = instant
        payload["deadline_utc"] = instant + timedelta(seconds=stored.timeout_seconds)
    if target is _C.RUNNING:
        payload["process_created"] = True
        payload["process_started_at_utc"] = instant
        payload["pid_identity"] = _invocation(_C.RUNNING).pid_identity
    if target in TERMINAL_COMMAND_INVOCATION_STATES:
        payload["completed_at_utc"] = instant
        if target is _C.EXITED:
            payload["native_exit_value"] = 0
            payload["process_exit_category"] = _invocation(
                _C.EXITED
            ).process_exit_category
        else:
            payload["primary_diagnostic_id"] = _DIAG_ID
            payload["diagnostic_ids"] = tuple(
                sorted({*stored.diagnostic_ids, _DIAG_ID})
            )
    payload["updated_at_utc"] = instant
    payload["revision"] = stored.revision + 1
    return CommandInvocationRecord.model_validate(payload)


def _edges[S: StrEnum](successors: Mapping[S, frozenset[S]]) -> frozenset[tuple[S, S]]:
    return frozenset(
        (current, target)
        for current, targets in successors.items()
        for target in targets
    )


def _table_agrees_with_oracle[S: StrEnum](
    table: TransitionTable[S],
    successors: Mapping[S, frozenset[S]],
    current: S,
    target: S,
) -> None:
    expected = target in successors[current]
    assert table.is_allowed(current, target) is expected
    assert is_allowed_transition(current, target) is expected
    assert ((current, target) in table.transitions) is expected
    assert (target in table.permitted_successors(current)) is expected


# --- Tables (preventive against Task 1) ----------------------------------------------


def test_the_oracles_restate_the_three_tables_exactly() -> None:
    """Preventive: the oracle edge sets equal the Task 1 tables, so a later table
    edit cannot pass the properties by moving both sides together."""
    assert _edges(_EXPERIMENT_SUCCESSORS) == EXPERIMENT_TRANSITIONS.transitions
    assert _edges(_ENGINE_RUN_SUCCESSORS) == ENGINE_RUN_TRANSITIONS.transitions
    assert _edges(_COMMAND_INVOCATION_SUCCESSORS) == (
        COMMAND_INVOCATION_TRANSITIONS.transitions
    )
    assert (
        len(_edges(_EXPERIMENT_SUCCESSORS)),
        len(_edges(_ENGINE_RUN_SUCCESSORS)),
        len(_edges(_COMMAND_INVOCATION_SUCCESSORS)),
    ) == (12, 23, 10)
    assert LINKED_ONLY_RUN_EDGES == _LINKED_EDGES
    assert _LINKED_EDGES <= ENGINE_RUN_TRANSITIONS.transitions


@given(pair=_EXPERIMENT_PAIRS)
def test_experiment_pairs_are_accepted_exactly_on_the_twelve_edges(
    pair: tuple[ExperimentState, ExperimentState],
) -> None:
    """Preventive against Task 1: the experiment machine has no record-pair predicate
    in Stage 5 (its edge ownership is a Task 6 service rule), so the table is the
    only layer to check."""
    current, target = pair
    _table_agrees_with_oracle(
        EXPERIMENT_TRANSITIONS, _EXPERIMENT_SUCCESSORS, current, target
    )


@given(pair=_INVOCATION_PAIRS)
def test_invocation_pairs_are_accepted_exactly_on_the_ten_edges(
    pair: tuple[CommandInvocationState, CommandInvocationState],
) -> None:
    """Preventive against Tasks 1 and 3: table and record-pair predicate agree."""
    current, target = pair
    _table_agrees_with_oracle(
        COMMAND_INVOCATION_TRANSITIONS, _COMMAND_INVOCATION_SUCCESSORS, current, target
    )
    stored = _invocation(current)
    replacement = _advance_invocation(stored, target)
    if target in _COMMAND_INVOCATION_SUCCESSORS[current]:
        assert_invocation_transition(stored, replacement)
    else:
        with pytest.raises(CommandInvocationRuleViolation):
            assert_invocation_transition(stored, replacement)


# --- Engine run (Task 4 RED) -------------------------------------------------------


@given(pair=_RUN_PAIRS)
def test_run_pairs_are_accepted_by_the_generic_authority_exactly_on_non_linked_edges(
    pair: tuple[EngineRunState, EngineRunState],
) -> None:
    current, target = pair
    _table_agrees_with_oracle(
        ENGINE_RUN_TRANSITIONS, _ENGINE_RUN_SUCCESSORS, current, target
    )
    stored = _run(current)
    replacement = _advance_run(stored, target)
    edge = target in _ENGINE_RUN_SUCCESSORS[current]
    if edge:
        assert run_edge_owner(current, target) is (
            RunEdgeOwner.LINKED_LAUNCH
            if (current, target) in _LINKED_EDGES
            else RunEdgeOwner.GENERIC
        )
    else:
        with pytest.raises(ValueError, match="not a permitted engine-run edge"):
            run_edge_owner(current, target)
    if edge and (current, target) not in _LINKED_EDGES:
        assert_run_transition(stored, replacement)
        return
    with pytest.raises(EngineRunRuleViolation) as info:
        assert_run_transition(stored, replacement)
    if current in TERMINAL_ENGINE_RUN_STATES:
        assert info.value.check is EngineRunCheck.TERMINAL_IMMUTABLE
    elif not edge:
        assert info.value.check is EngineRunCheck.TRANSITION_EDGE
    else:
        assert info.value.check is EngineRunCheck.TRANSITION_EDGE_OWNERSHIP


@given(pair=_RUN_PAIRS)
def test_run_pairs_are_accepted_by_the_linked_authority_exactly_on_the_two_linked_edges(
    pair: tuple[EngineRunState, EngineRunState],
) -> None:
    current, target = pair
    stored = _run(current)
    replacement = _advance_run(stored, target)
    if (current, target) in _LINKED_EDGES:
        assert_run_transition(stored, replacement, owner=RunEdgeOwner.LINKED_LAUNCH)
        return
    with pytest.raises(EngineRunRuleViolation) as info:
        assert_run_transition(stored, replacement, owner=RunEdgeOwner.LINKED_LAUNCH)
    if current in TERMINAL_ENGINE_RUN_STATES:
        assert info.value.check is EngineRunCheck.TERMINAL_IMMUTABLE
    elif target not in _ENGINE_RUN_SUCCESSORS[current]:
        assert info.value.check is EngineRunCheck.TRANSITION_EDGE
    else:
        assert info.value.check is EngineRunCheck.TRANSITION_EDGE_OWNERSHIP


@given(state=_RUN_STATES, attempt_number=_ATTEMPTS)
def test_every_state_and_attempt_number_builds_exactly_one_consistent_record(
    state: EngineRunState,
    attempt_number: int,
) -> None:
    record = _run(state, attempt_number)
    assert record.state is state
    assert record.attempt_number == attempt_number
    assert _missing(record.predecessor_run_id) is (attempt_number == 1)
    assert _missing(record.retry_reason) is (attempt_number == 1)
    assert _missing(record.primary_terminal_diagnostic_id) is not (
        state in NON_SUCCESS_TERMINAL_ENGINE_RUN_STATES
    )
    assert _missing(record.availability_observation_id) is (
        state in _OBSERVATION_PROHIBITED
    )
    assert _missing(record.finalization_deadline_utc)
    again = EngineRunRecord.model_validate_json(record.model_dump_json())
    assert again == record


@given(state=_RUN_STATES, attempt_number=_BAD_ATTEMPTS)
def test_an_attempt_number_outside_one_through_five_is_rejected_in_every_state(
    state: EngineRunState,
    attempt_number: int,
) -> None:
    with pytest.raises(ValidationError):
        _run(state, attempt_number)


@given(state=_RUN_STATES, attempt_number=_ATTEMPTS)
def test_successor_facts_are_present_exactly_when_the_attempt_number_exceeds_one(
    state: EngineRunState,
    attempt_number: int,
) -> None:
    payload = _run_payload(state, attempt_number)
    if attempt_number == 1:
        payload["predecessor_run_id"] = _PREDECESSOR_RUN_ID
        payload["retry_reason"] = RetryTerminalState.FAILED
    else:
        del payload["predecessor_run_id"]
        del payload["retry_reason"]
    with pytest.raises(ValidationError):
        EngineRunRecord.model_validate(payload)
