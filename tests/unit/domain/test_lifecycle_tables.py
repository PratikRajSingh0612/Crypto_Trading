"""Stage 5 Task 1: lifecycle vocabularies, exhaustive transition tables and the
two byte-neutral enum relocations.

Every edge below is transcribed from the specification -- section 16.1 for the
experiment, section 17.1 for the engine run and section 15.2 for the command
invocation -- which Stage 5 plan sections 4, 5 and 6 restate with their
8/64/12, 12/144/23 and 8/64/10 arithmetic. Each table is asserted by exact set
equality and every forbidden ordered pair by complement, so a silently added or
dropped edge fails here rather than in a later service test.
"""

from __future__ import annotations

import ast
import json
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any, cast

import pytest

from crypto_lab import configuration as configuration_package
from crypto_lab.capabilities import models as capability_models
from crypto_lab.configuration import models as configuration_models
from crypto_lab.domain import compatibility as domain_compatibility
from crypto_lab.domain import lifecycle, ports
from crypto_lab.domain.compatibility import CompatibilityOutcome
from crypto_lab.domain.hashing import HashingProfile
from crypto_lab.domain.lifecycle import (
    COMMAND_INVOCATION_TRANSITIONS,
    ENGINE_RUN_TRANSITIONS,
    EXPERIMENT_TRANSITIONS,
    RECOGNIZED_NATIVE_EXIT_VALUES,
    TERMINAL_COMMAND_INVOCATION_STATES,
    TERMINAL_ENGINE_RUN_STATES,
    TERMINAL_EXPERIMENT_STATES,
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
    ProcessExitCategory,
    RetryTerminalState,
    TransitionTable,
    is_allowed_transition,
    permitted_successors,
    process_exit_category_for,
)
from crypto_lab.schema_registry import render_schema_files

_E = ExperimentState
_R = EngineRunState
_C = CommandInvocationState

# Specification section 16.1, "Allowed next states" column.
_EXPERIMENT_SUCCESSORS: dict[ExperimentState, frozenset[ExperimentState]] = {
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
# Specification section 17.1, "Allowed next states" column.
_ENGINE_RUN_SUCCESSORS: dict[EngineRunState, frozenset[EngineRunState]] = {
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
# Specification section 15.2, "Allowed next states" column.
_COMMAND_INVOCATION_SUCCESSORS: dict[
    CommandInvocationState, frozenset[CommandInvocationState]
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
# Stage 5 plan section 6, frozen process-exit mapping version 1.
_NATIVE_EXIT_MAPPING: dict[int, ProcessExitCategory] = {
    0: ProcessExitCategory.SUCCESS,
    10: ProcessExitCategory.VALIDATION_FAILURE,
    20: ProcessExitCategory.NOT_APPLICABLE,
    30: ProcessExitCategory.UNAVAILABLE,
    40: ProcessExitCategory.RUNTIME_FAILURE,
    50: ProcessExitCategory.CANCELLED,
    60: ProcessExitCategory.TIMED_OUT,
    70: ProcessExitCategory.PROTOCOL_VIOLATION,
}
# The merged docstring of `capabilities.models.CompatibilityOutcome`, which the
# released `capabilities/compatibility-result-v1` schema publishes verbatim as
# the `$defs/CompatibilityOutcome` description. Any change here moves released
# bytes.
_COMPATIBILITY_OUTCOME_DOCSTRING = """\
The four approved outcomes of specification sections 11.5 and 13.4.

``NOT_APPLICABLE`` and ``UNAVAILABLE`` are distinct on purpose and neither may
absorb the other: section 13.4 requires an unrunnable-but-compatible adapter to
record "a terminal availability outcome" and forbids mislabelling it as a
strategy failure."""
_AMBIENT_ROOTS = frozenset(
    {"os", "random", "secrets", "socket", "subprocess", "sys", "time", "uuid"}
)
_AMBIENT_CALLS = frozenset(
    {
        "monotonic",
        "now",
        "perf_counter",
        "today",
        "token_hex",
        "token_urlsafe",
        "utcnow",
        "uuid1",
        "uuid4",
    }
)


def _module_source(module: ModuleType) -> str:
    return Path(module.__file__ or "").read_text(encoding="utf-8")


def _class_definition(source: str, name: str) -> ast.ClassDef:
    matches = [
        node
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ClassDef) and node.name == name
    ]
    assert len(matches) == 1, name
    return matches[0]


def _rendered(name: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(render_schema_files()[PurePosixPath(name)]))


def _edges[S: StrEnum](
    successors: Mapping[S, frozenset[S]],
) -> frozenset[tuple[S, S]]:
    return frozenset(
        (current, target)
        for current, targets in successors.items()
        for target in targets
    )


def _assert_machine_is_exactly[S: StrEnum](
    table: TransitionTable[S],
    successors: Mapping[S, frozenset[S]],
    *,
    state_count: int,
    pair_count: int,
    edge_count: int,
    terminal: frozenset[S],
) -> None:
    """Exact table, exhaustive complement, successors and terminal derivation."""
    states = tuple(table.state_type)
    assert len(states) == state_count
    assert len(states) * len(states) == pair_count
    assert set(successors) == set(states)
    expected = _edges(successors)
    assert len(expected) == edge_count
    assert table.transitions == expected
    assert table.states == frozenset(states)

    allowed = 0
    for current in states:
        for target in states:
            flag = target in successors[current]
            assert table.is_allowed(current, target) is flag, (current, target)
            assert is_allowed_transition(current, target) is flag, (current, target)
            allowed += int(flag)
    assert allowed == edge_count

    for state in states:
        assert table.permitted_successors(state) == successors[state], state
        assert permitted_successors(state) == successors[state], state
        assert (successors[state] == frozenset()) is (state in terminal), state
        assert not table.is_allowed(state, state), state
    assert table.terminal_states == terminal


# --- Vocabularies -----------------------------------------------------------


def test_the_lifecycle_vocabularies_have_exactly_the_specified_members_in_order() -> (
    None
):
    assert [member.value for member in ExperimentState] == [
        "DRAFT",
        "VALIDATED",
        "QUEUED",
        "RUNNING",
        "COMPLETED",
        "COMPLETED_WITH_WARNINGS",
        "FAILED",
        "CANCELLED",
    ]
    assert [member.value for member in EngineRunState] == [
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
    assert [member.value for member in CommandInvocationState] == [
        "PENDING",
        "STARTING",
        "RUNNING",
        "EXITED",
        "FAILED_TO_START",
        "CANCELLED",
        "TIMED_OUT",
        "PROTOCOL_FAILED",
    ]
    assert [member.value for member in CommandKind] == ["DESCRIBE", "VALIDATE", "RUN"]
    assert [member.value for member in ProcessExitCategory] == [
        "SUCCESS",
        "VALIDATION_FAILURE",
        "NOT_APPLICABLE",
        "UNAVAILABLE",
        "RUNTIME_FAILURE",
        "CANCELLED",
        "TIMED_OUT",
        "PROTOCOL_VIOLATION",
    ]
    for vocabulary in (
        ExperimentState,
        EngineRunState,
        CommandInvocationState,
        CommandKind,
        ProcessExitCategory,
        RetryTerminalState,
    ):
        assert vocabulary.__module__ == "crypto_lab.domain.lifecycle"
        assert all(member.value == member.name for member in vocabulary)


# --- Transition tables -------------------------------------------------------


def test_the_experiment_machine_is_eight_states_sixty_four_pairs_twelve_edges() -> None:
    assert EXPERIMENT_TRANSITIONS.state_type is ExperimentState
    _assert_machine_is_exactly(
        EXPERIMENT_TRANSITIONS,
        _EXPERIMENT_SUCCESSORS,
        state_count=8,
        pair_count=64,
        edge_count=12,
        terminal=frozenset(
            {_E.COMPLETED, _E.COMPLETED_WITH_WARNINGS, _E.FAILED, _E.CANCELLED}
        ),
    )
    assert TERMINAL_EXPERIMENT_STATES == EXPERIMENT_TRANSITIONS.terminal_states


def test_the_engine_run_machine_is_twelve_states_144_pairs_twenty_three_edges() -> None:
    assert ENGINE_RUN_TRANSITIONS.state_type is EngineRunState
    _assert_machine_is_exactly(
        ENGINE_RUN_TRANSITIONS,
        _ENGINE_RUN_SUCCESSORS,
        state_count=12,
        pair_count=144,
        edge_count=23,
        terminal=frozenset(
            {
                _R.SUCCEEDED,
                _R.SUCCEEDED_WITH_WARNINGS,
                _R.FAILED,
                _R.CANCELLED,
                _R.TIMED_OUT,
                _R.NOT_APPLICABLE,
                _R.UNAVAILABLE,
            }
        ),
    )
    assert TERMINAL_ENGINE_RUN_STATES == ENGINE_RUN_TRANSITIONS.terminal_states


def test_the_command_invocation_machine_is_eight_states_64_pairs_ten_edges() -> None:
    assert COMMAND_INVOCATION_TRANSITIONS.state_type is CommandInvocationState
    _assert_machine_is_exactly(
        COMMAND_INVOCATION_TRANSITIONS,
        _COMMAND_INVOCATION_SUCCESSORS,
        state_count=8,
        pair_count=64,
        edge_count=10,
        terminal=frozenset(
            {
                _C.EXITED,
                _C.FAILED_TO_START,
                _C.CANCELLED,
                _C.TIMED_OUT,
                _C.PROTOCOL_FAILED,
            }
        ),
    )
    assert (
        TERMINAL_COMMAND_INVOCATION_STATES
        == COMMAND_INVOCATION_TRANSITIONS.terminal_states
    )


def test_the_two_linked_only_run_edges_are_still_table_members() -> None:
    """Edge ownership (plan section 5) is a service rule, not a table rule.

    `READY -> STARTING` and `STARTING -> RUNNING` belong to the linked
    operations of Task 6, but the table itself must still hold them: the table
    answers "is this ordered pair ever permitted", never "who may produce it".
    """
    assert is_allowed_transition(_R.READY, _R.STARTING)
    assert is_allowed_transition(_R.STARTING, _R.RUNNING)


def test_mixed_machine_pairs_are_rejected_rather_than_silently_false() -> None:
    with pytest.raises(TypeError):
        is_allowed_transition(_E.DRAFT, cast(ExperimentState, _R.PENDING))
    with pytest.raises(TypeError):
        is_allowed_transition(cast(ExperimentState, _R.PENDING), _E.DRAFT)
    with pytest.raises(TypeError):
        is_allowed_transition(cast(ExperimentState, "DRAFT"), _E.VALIDATED)
    with pytest.raises(TypeError):
        permitted_successors(cast(ExperimentState, RetryTerminalState.FAILED))
    with pytest.raises(TypeError):
        permitted_successors(cast(ExperimentState, CommandKind.RUN))


def test_a_transition_table_rejects_a_foreign_endpoint_and_a_reflexive_edge() -> None:
    class Probe(StrEnum):
        ALPHA = "ALPHA"
        OMEGA = "OMEGA"

    with pytest.raises(ValueError, match="reflexive"):
        TransitionTable(Probe, frozenset({(Probe.ALPHA, Probe.ALPHA)}))
    with pytest.raises(ValueError, match="member of the state type"):
        TransitionTable(Probe, frozenset({(Probe.ALPHA, cast(Probe, _E.DRAFT))}))
    with pytest.raises(ValueError, match="member of the state type"):
        TransitionTable(Probe, frozenset({(cast(Probe, _E.DRAFT), Probe.OMEGA)}))

    table = TransitionTable(Probe, frozenset({(Probe.ALPHA, Probe.OMEGA)}))
    assert table.states == frozenset({Probe.ALPHA, Probe.OMEGA})
    assert table.terminal_states == frozenset({Probe.OMEGA})
    assert table.is_allowed(Probe.ALPHA, Probe.OMEGA)
    assert not table.is_allowed(Probe.OMEGA, Probe.ALPHA)
    assert table.permitted_successors(Probe.ALPHA) == frozenset({Probe.OMEGA})
    assert table.permitted_successors(Probe.OMEGA) == frozenset()
    with pytest.raises(TypeError):
        table.permitted_successors(cast(Probe, _E.DRAFT))
    with pytest.raises(TypeError):
        table.is_allowed(Probe.ALPHA, cast(Probe, _E.DRAFT))
    with pytest.raises(TypeError):
        table.is_allowed(cast(Probe, _E.DRAFT), Probe.OMEGA)


def test_the_tables_are_immutable_values() -> None:
    with pytest.raises(AttributeError):
        EXPERIMENT_TRANSITIONS.transitions = frozenset()  # type: ignore[misc]
    assert isinstance(EXPERIMENT_TRANSITIONS.transitions, frozenset)
    assert isinstance(TERMINAL_ENGINE_RUN_STATES, frozenset)


# --- Process exit category ----------------------------------------------------


def test_the_frozen_native_exit_mapping_is_exactly_the_eight_specified_values() -> None:
    assert RECOGNIZED_NATIVE_EXIT_VALUES == frozenset(_NATIVE_EXIT_MAPPING)
    assert len(RECOGNIZED_NATIVE_EXIT_VALUES) == 8
    for value, category in _NATIVE_EXIT_MAPPING.items():
        assert process_exit_category_for(value) is category, value


@pytest.mark.parametrize(
    "value",
    [
        -2147483648,
        -1,
        1,
        9,
        11,
        19,
        21,
        29,
        31,
        39,
        41,
        49,
        51,
        59,
        61,
        69,
        71,
        80,
        255,
        2**31 - 1,
        4294967295,
        2**63,
    ],
)
def test_every_unrecognized_native_exit_maps_to_runtime_failure(value: int) -> None:
    assert value not in RECOGNIZED_NATIVE_EXIT_VALUES
    assert process_exit_category_for(value) is ProcessExitCategory.RUNTIME_FAILURE


def test_the_mapping_is_total_over_a_dense_native_exit_range() -> None:
    for value in range(-256, 1024):
        expected = _NATIVE_EXIT_MAPPING.get(value, ProcessExitCategory.RUNTIME_FAILURE)
        assert process_exit_category_for(value) is expected, value


@pytest.mark.parametrize("value", [True, False, 0.0, 10.0, "0", None, b"0"])
def test_a_non_integer_native_exit_value_is_rejected(value: object) -> None:
    with pytest.raises(TypeError, match="built-in integer"):
        process_exit_category_for(cast(int, value))


# --- Relocations --------------------------------------------------------------


def test_retry_terminal_state_is_relocated_into_domain_without_a_docstring() -> None:
    """Plan section 2.5 constraint 2: identical name, members, order; no docstring.

    A docstring would emit a `description` key into the released
    `configuration/application-config-v1` bytes, so the absence is asserted on
    the class body itself and again on the rendered `$defs` node.
    """
    assert RetryTerminalState.__module__ == "crypto_lab.domain.lifecycle"
    assert [member.value for member in RetryTerminalState] == [
        "FAILED",
        "TIMED_OUT",
        "UNAVAILABLE",
    ]
    node = _class_definition(_module_source(lifecycle), "RetryTerminalState")
    assert ast.get_docstring(node) is None
    # Re-exported, not shadowed: deletion from the origin, identity everywhere.
    assert configuration_models.RetryTerminalState is RetryTerminalState
    assert configuration_package.RetryTerminalState is RetryTerminalState
    assert "class RetryTerminalState" not in _module_source(configuration_models)
    rendered = _rendered("configuration/application-config-v1.schema.json")
    assert rendered["$defs"]["RetryTerminalState"] == {
        "enum": ["FAILED", "TIMED_OUT", "UNAVAILABLE"],
        "title": "RetryTerminalState",
        "type": "string",
    }


def test_compatibility_outcome_is_relocated_into_domain_with_its_docstring() -> None:
    """Plan section 2.5 constraint 3: identical name, members, order, docstring."""
    assert CompatibilityOutcome.__module__ == "crypto_lab.domain.compatibility"
    assert [member.value for member in CompatibilityOutcome] == [
        "SUPPORTED",
        "SUPPORTED_WITH_APPROXIMATION",
        "NOT_APPLICABLE",
        "UNAVAILABLE",
    ]
    node = _class_definition(
        _module_source(domain_compatibility), "CompatibilityOutcome"
    )
    assert ast.get_docstring(node) == _COMPATIBILITY_OUTCOME_DOCSTRING
    assert capability_models.CompatibilityOutcome is CompatibilityOutcome
    assert "CompatibilityOutcome" in capability_models.__all__
    assert "class CompatibilityOutcome" not in _module_source(capability_models)
    rendered = _rendered("capabilities/compatibility-result-v1.schema.json")
    assert rendered["$defs"]["CompatibilityOutcome"] == {
        "description": _COMPATIBILITY_OUTCOME_DOCSTRING,
        "enum": [
            "SUPPORTED",
            "SUPPORTED_WITH_APPROXIMATION",
            "NOT_APPLICABLE",
            "UNAVAILABLE",
        ],
        "title": "CompatibilityOutcome",
        "type": "string",
    }


# --- Hashing profiles ---------------------------------------------------------


def test_the_two_stage_five_hashing_profiles_exist_and_reach_no_schema() -> None:
    """Plan section 2.5 constraint 4: safe only because nothing published reaches
    `HashingProfile`, which is why the absence is asserted over every render."""
    assert HashingProfile.EXPERIMENT_CONFIGURATION_V1.value == (
        "experiment-configuration/v1"
    )
    assert HashingProfile.EXPERIMENT_SPEC_V1.value == "experiment-spec/v1"
    assert len(HashingProfile) == 8
    assert len({member.value for member in HashingProfile}) == 8
    for path, contents in render_schema_files().items():
        assert b"HashingProfile" not in contents, path
        assert b"experiment-configuration/v1" not in contents, path
        assert b"experiment-spec/v1" not in contents, path


# --- Ambient-source guard -----------------------------------------------------


@pytest.mark.parametrize(
    "module",
    [lifecycle, domain_compatibility, ports],
    ids=("lifecycle", "compatibility", "ports"),
)
def test_the_new_domain_modules_reach_no_clock_random_or_process_source(
    module: ModuleType,
) -> None:
    roots: set[str] = set()
    calls: set[str] = set()
    for node in ast.walk(ast.parse(_module_source(module))):
        if isinstance(node, ast.Import):
            roots.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            roots.add(node.module.partition(".")[0])
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                calls.add(node.func.attr)
            elif isinstance(node.func, ast.Name):
                calls.add(node.func.id)
    assert roots.isdisjoint(_AMBIENT_ROOTS), sorted(roots & _AMBIENT_ROOTS)
    assert calls.isdisjoint(_AMBIENT_CALLS), sorted(calls & _AMBIENT_CALLS)
