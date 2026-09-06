"""Stage 5 lifecycle vocabularies and their exhaustive transition tables.

Specification section 8 places canonical record types and state-transition
invariants in ``domain``, and section 27.1 lists state-transition tables among
this package's responsibilities. The three machines here are the experiment
(section 16.1), the engine run (section 17.1) and the command invocation
(section 15.2). Every table is closed: an ordered state pair outside it is
forbidden, and the terminal states are exactly the states with no successor.

Edge *ownership* -- which application operation may produce a permitted edge --
is a Stage 5 service rule (plan sections 4 to 6) and is deliberately not encoded
here. A table answers only whether an ordered pair is ever permitted.

``RetryTerminalState`` is relocated here from ``crypto_lab.configuration.models``
so that ``RetryPolicy`` can live in ``domain`` while ``configuration`` keeps its
single inward dependency on ``domain`` (Stage 5 plan sections 2.3 and 2.5). It
renders into the released ``configuration/application-config-v1`` schema by bare
class name and must stay byte-neutral: identical name, identical members in
order, and **no docstring**, because a docstring emits a ``description`` key.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final, cast


class RetryTerminalState(StrEnum):
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    UNAVAILABLE = "UNAVAILABLE"


class ExperimentState(StrEnum):
    """Specification section 16.1: eight members and twelve permitted edges."""

    DRAFT = "DRAFT"
    VALIDATED = "VALIDATED"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    COMPLETED_WITH_WARNINGS = "COMPLETED_WITH_WARNINGS"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class EngineRunState(StrEnum):
    """Specification section 17.1: twelve members, twenty-three permitted edges."""

    PENDING = "PENDING"
    VALIDATING = "VALIDATING"
    READY = "READY"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    SUCCEEDED_WITH_WARNINGS = "SUCCEEDED_WITH_WARNINGS"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNAVAILABLE = "UNAVAILABLE"


class CommandInvocationState(StrEnum):
    """Specification section 15.2: eight members and ten permitted edges."""

    PENDING = "PENDING"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    EXITED = "EXITED"
    FAILED_TO_START = "FAILED_TO_START"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"
    PROTOCOL_FAILED = "PROTOCOL_FAILED"


class CommandKind(StrEnum):
    """Specification section 14.1: the three adapter commands."""

    DESCRIBE = "DESCRIBE"
    VALIDATE = "VALIDATE"
    RUN = "RUN"


class ProcessExitCategory(StrEnum):
    """Specification section 14.6: process-level exit categories, version 1.

    A category is a process fact captured from a native exit value. It is never
    the semantic result of a run, which Stage 6 derives from the validated
    adapter result manifest. There is no ``UNKNOWN_AFTER_RESTART`` member: lost
    native exit facts can never be reconstructed into ``EXITED``.
    """

    SUCCESS = "SUCCESS"
    VALIDATION_FAILURE = "VALIDATION_FAILURE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNAVAILABLE = "UNAVAILABLE"
    RUNTIME_FAILURE = "RUNTIME_FAILURE"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"
    PROTOCOL_VIOLATION = "PROTOCOL_VIOLATION"


#: Section 14.6's frozen exit-code table. Every value outside it is a
#: ``RUNTIME_FAILURE`` that additionally requires a
#: ``PROCESS.UNRECOGNIZED_PROCESS_EXIT`` diagnostic on the ``EXITED`` invocation
#: (Stage 5 plan section 6). The record and service rules that require that
#: diagnostic belong to Tasks 3 and 6, which read the recognized set below rather
#: than re-deriving it.
_NATIVE_EXIT_CATEGORIES: Final[dict[int, ProcessExitCategory]] = {
    0: ProcessExitCategory.SUCCESS,
    10: ProcessExitCategory.VALIDATION_FAILURE,
    20: ProcessExitCategory.NOT_APPLICABLE,
    30: ProcessExitCategory.UNAVAILABLE,
    40: ProcessExitCategory.RUNTIME_FAILURE,
    50: ProcessExitCategory.CANCELLED,
    60: ProcessExitCategory.TIMED_OUT,
    70: ProcessExitCategory.PROTOCOL_VIOLATION,
}
RECOGNIZED_NATIVE_EXIT_VALUES: Final[frozenset[int]] = frozenset(
    _NATIVE_EXIT_CATEGORIES
)


def process_exit_category_for(native_exit_value: int) -> ProcessExitCategory:
    """Map one captured native exit value onto its frozen version-1 category.

    Total over every built-in integer: the eight recognized values map exactly
    and every other value maps to ``RUNTIME_FAILURE``. A ``bool`` is refused
    even though it subclasses ``int``, because a captured exit value is never a
    flag; ``attempt_token_hash`` applies the same strictness to its token.
    """
    if type(native_exit_value) is not int:
        raise TypeError("native exit value must be a built-in integer")
    return _NATIVE_EXIT_CATEGORIES.get(
        native_exit_value, ProcessExitCategory.RUNTIME_FAILURE
    )


@dataclass(frozen=True, slots=True)
class TransitionTable[S: StrEnum]:
    """One closed state machine: its vocabulary and its permitted ordered pairs.

    ``transitions`` holds every permitted ``(current, target)`` pair and nothing
    else; a pair outside it is forbidden. Terminal states are derived, not
    declared, as the members with no outgoing edge, and the tests pin that
    derivation to the specification's explicit terminal lists. Reflexive pairs
    are never edges: an idempotent replay of a stored state is a service rule
    evaluated before the table (plan section 4), not a transition.
    """

    state_type: type[S]
    transitions: frozenset[tuple[S, S]]

    def __post_init__(self) -> None:
        for current, target in self.transitions:
            if (
                type(current) is not self.state_type
                or type(target) is not self.state_type
            ):
                raise ValueError(
                    "every transition endpoint must be a member of the state type"
                )
            if current is target:
                raise ValueError("a transition table holds no reflexive edge")

    @property
    def states(self) -> frozenset[S]:
        """Every member of the machine's vocabulary."""
        return frozenset(self.state_type)

    @property
    def terminal_states(self) -> frozenset[S]:
        """The members with no permitted successor."""
        return self.states - frozenset(current for current, _ in self.transitions)

    def _require_member(self, state: S) -> None:
        if type(state) is not self.state_type:
            raise TypeError(f"state must be a {self.state_type.__name__} member")

    def is_allowed(self, current: S, target: S) -> bool:
        """Return whether the ordered pair is a permitted edge of this machine."""
        self._require_member(current)
        self._require_member(target)
        return (current, target) in self.transitions

    def permitted_successors(self, state: S) -> frozenset[S]:
        """Return every state the given state may move to; empty when terminal."""
        self._require_member(state)
        return frozenset(
            target for current, target in self.transitions if current is state
        )


_E: Final = ExperimentState
_R: Final = EngineRunState
_C: Final = CommandInvocationState

#: Specification section 16.1: 8 states, 64 ordered pairs, 12 permitted.
EXPERIMENT_TRANSITIONS: Final = TransitionTable(
    ExperimentState,
    frozenset(
        {
            (_E.DRAFT, _E.VALIDATED),
            (_E.DRAFT, _E.CANCELLED),
            (_E.VALIDATED, _E.DRAFT),
            (_E.VALIDATED, _E.QUEUED),
            (_E.VALIDATED, _E.CANCELLED),
            (_E.QUEUED, _E.RUNNING),
            (_E.QUEUED, _E.FAILED),
            (_E.QUEUED, _E.CANCELLED),
            (_E.RUNNING, _E.COMPLETED),
            (_E.RUNNING, _E.COMPLETED_WITH_WARNINGS),
            (_E.RUNNING, _E.FAILED),
            (_E.RUNNING, _E.CANCELLED),
        }
    ),
)
#: Specification section 17.1: 12 states, 144 ordered pairs, 23 permitted.
ENGINE_RUN_TRANSITIONS: Final = TransitionTable(
    EngineRunState,
    frozenset(
        {
            (_R.PENDING, _R.VALIDATING),
            (_R.PENDING, _R.CANCELLED),
            (_R.VALIDATING, _R.READY),
            (_R.VALIDATING, _R.NOT_APPLICABLE),
            (_R.VALIDATING, _R.UNAVAILABLE),
            (_R.VALIDATING, _R.FAILED),
            (_R.VALIDATING, _R.CANCELLED),
            (_R.VALIDATING, _R.TIMED_OUT),
            (_R.READY, _R.STARTING),
            (_R.READY, _R.UNAVAILABLE),
            (_R.READY, _R.CANCELLED),
            (_R.STARTING, _R.RUNNING),
            (_R.STARTING, _R.FAILED),
            (_R.STARTING, _R.UNAVAILABLE),
            (_R.STARTING, _R.CANCELLED),
            (_R.STARTING, _R.TIMED_OUT),
            (_R.RUNNING, _R.SUCCEEDED),
            (_R.RUNNING, _R.SUCCEEDED_WITH_WARNINGS),
            (_R.RUNNING, _R.NOT_APPLICABLE),
            (_R.RUNNING, _R.UNAVAILABLE),
            (_R.RUNNING, _R.FAILED),
            (_R.RUNNING, _R.CANCELLED),
            (_R.RUNNING, _R.TIMED_OUT),
        }
    ),
)
#: Specification section 15.2: 8 states, 64 ordered pairs, 10 permitted.
COMMAND_INVOCATION_TRANSITIONS: Final = TransitionTable(
    CommandInvocationState,
    frozenset(
        {
            (_C.PENDING, _C.STARTING),
            (_C.PENDING, _C.CANCELLED),
            (_C.STARTING, _C.RUNNING),
            (_C.STARTING, _C.FAILED_TO_START),
            (_C.STARTING, _C.CANCELLED),
            (_C.STARTING, _C.TIMED_OUT),
            (_C.RUNNING, _C.EXITED),
            (_C.RUNNING, _C.CANCELLED),
            (_C.RUNNING, _C.TIMED_OUT),
            (_C.RUNNING, _C.PROTOCOL_FAILED),
        }
    ),
)

TERMINAL_EXPERIMENT_STATES: Final[frozenset[ExperimentState]] = (
    EXPERIMENT_TRANSITIONS.terminal_states
)
TERMINAL_ENGINE_RUN_STATES: Final[frozenset[EngineRunState]] = (
    ENGINE_RUN_TRANSITIONS.terminal_states
)
TERMINAL_COMMAND_INVOCATION_STATES: Final[frozenset[CommandInvocationState]] = (
    COMMAND_INVOCATION_TRANSITIONS.terminal_states
)

_TABLES: Final[dict[type[StrEnum], object]] = {
    ExperimentState: EXPERIMENT_TRANSITIONS,
    EngineRunState: ENGINE_RUN_TRANSITIONS,
    CommandInvocationState: COMMAND_INVOCATION_TRANSITIONS,
}


def _table_of[S: StrEnum](state: S) -> TransitionTable[S]:
    table = _TABLES.get(type(state))
    if table is None:
        raise TypeError("state must be a member of a Stage 5 lifecycle vocabulary")
    return cast(TransitionTable[S], table)


def is_allowed_transition[S: StrEnum](current: S, target: S) -> bool:
    """Return whether ``current -> target`` is a permitted edge of its machine.

    Dispatches on the enum type of ``current``. A pair drawn from two different
    machines, or from a vocabulary that is not a lifecycle, is a programming
    error and raises ``TypeError`` rather than answering ``False``.
    """
    return _table_of(current).is_allowed(current, target)


def permitted_successors[S: StrEnum](state: S) -> frozenset[S]:
    """Return every permitted successor of ``state``; empty when it is terminal."""
    return _table_of(state).permitted_successors(state)
