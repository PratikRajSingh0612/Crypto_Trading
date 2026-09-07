"""Engine-run record, its section 5 field shapes, and the pure run-side predicates.

Stage 5 plan sections 3.8, 5 and 6, under specification sections 11.3, 11.5, 15.1,
15.2, 15.6, 16.3 and 17. Placement follows plan section 2.3: the canonical record
and its state-governed invariants live in ``domain``, while the operations that
create, transition and couple it -- ``create_attempt``, ``transition_run``,
``begin_linked_launch``, ``start_linked_run``, ``transition_invocation_and_run``
and ``create_successor`` -- are Task 6 and Task 7 application services in
``experiments``, which consume the pure predicates defined here.

An ``EngineRunRecord`` is one logical engine-run attempt for one selected slot of
one experiment: stable ``run_id``, monotonic ``attempt_number`` within the slot,
and a successor's ``predecessor_run_id`` and ``retry_reason`` (specification 17.2).
It is deliberately separate from the command invocation (Task 3): a ``VALIDATE``
or ``RUN`` invocation links to a run by ``run_id``, ``DESCRIBE`` has none, and the
run never duplicates PID, native-exit, command-deadline or stderr facts
(specification 11.5, 15.2). An engine-run state is never inferred from a
command-process exit: this module imports neither the exit vocabulary nor its
frozen mapping, and the coupled terminal mapping below returns nothing for an
``EXITED`` invocation, whose semantic mapping is Stage 6 (plan sections 1.4 and 6).
Nothing here launches, supervises or inspects a process, reads a clock, draws an
identifier, or touches a repository.

Six kinds of rule live here.

1. **Record shape** -- ``EngineRunRecord``'s validator: plan section 3.8's
   optionality column and section 5's "fields that become present" column.
   ``predecessor_run_id`` and ``retry_reason`` are present exactly on a successor
   attempt (``attempt_number > 1``); ``primary_terminal_diagnostic_id`` exactly in
   the five non-success terminal states; ``availability_observation_id`` is absent
   before ``READY``, required from ``READY`` onward and in ``UNAVAILABLE``, and
   predecessor-dependent in the four terminals ``VALIDATING`` reaches directly;
   ``finalization_deadline_utc`` is absent throughout Stage 5.
2. **Edge ownership** -- ``RunEdgeOwner`` and ``run_edge_owner``: plan section 5
   gives ``READY -> STARTING`` and ``STARTING -> RUNNING`` exclusively to the linked
   launch operations and every other table edge to ``transition_run`` and the
   coupled terminal operation.
3. **Terminal immutability** -- ``assert_terminal_run_immutability``: plan section
   3.8 makes a terminal record completely immutable, with no enrichment and no
   revision increment; only a field-for-field identical restatement is not a
   change, because idempotent replay returns the stored record with no write
   (plan section 4).
4. **Transition** -- ``assert_run_transition``: a pure record-pair predicate over
   the Task 1 ``ENGINE_RUN_TRANSITIONS`` table, the sole allowed-pair authority.
   The ``Result``/``Failure`` codes, the expected-revision compare-and-swap and
   the carry-forward of request values are Task 6 service rules; a same-state
   replay is evaluated by the service before the table, so a reflexive pair is
   never an edge.
5. **Coupled terminal mapping** -- ``coupled_run_terminal_state``: plan section
   6's "Coupled terminal transitions" table as a pure total function over
   (command kind, invocation predecessor state, invocation terminal state) plus
   the primary diagnostic category the ``FAILED_TO_START`` rows read.
6. **Mixed running pair** -- ``is_mixed_running_pair``: the launch-handoff
   invariant of plan section 6 and specification 15.6 for a live ``RUN``
   invocation and its run.

Where the plan is silent, these task-local readings are applied and declared here
rather than inferred silently:

- ``availability_observation_id`` is request-governed exactly on a transition
  whose target is ``READY`` or ``UNAVAILABLE`` (plan 3.8 row 14, "R at the
  transition into READY or UNAVAILABLE"; section 3.2 lets a request supply a new
  value for a field the target state governs), so a transition into
  ``UNAVAILABLE`` from ``READY``, ``STARTING`` or ``RUNNING`` may record a fresh
  observation identity; on every other edge it is carried forward unchanged,
  present or absent ("C thereafter"). At the record level the four terminals
  ``VALIDATING`` reaches directly admit it present or absent, because a single
  record cannot see whether its predecessor had one; the pair predicate is what
  forbids dropping it.
- ``predecessor_run_id`` differs from ``run_id``: a successor is always a new
  attempt with a new identifier (specification 17.2), so a self-referencing pair
  is unrepresentable.
- ``schema_version`` joins plan section 5's eleven immutable fields; its
  ``Literal`` admits one value, so the entry is inert and mirrors Task 3.
- ``finalization_deadline_utc`` keeps its Stage 9 type so that Task 9 publishes it
  as an optional property, while the validator rejects every present value
  (plan 3.8 row 15, Task 9).
- ``AttemptTokenMaterial`` is a nested value object without an envelope, following
  the ``ProcessStartFacts`` and ``RetryDecisionInsertOutcome`` precedents; its
  ``repr`` hides the raw token, its dumps carry it because the create-attempt
  caller needs the raw value for the Stage 6 request, and a frozen model's Python
  hashability is not the content hashing plan section 3.8 forbids.
- ``coupled_run_terminal_state`` returns the run **target** alone. Plan section 6
  pins a current run state only in its three ``TIMED_OUT`` rows, and those are
  exactly the Task 1 predecessors of ``TIMED_OUT``; the coupled operation proves
  the edge from the run's actual state through ``assert_run_transition``, which
  also keeps a lawful ``READY -> CANCELLED`` beside a still-open ``VALIDATE``
  invocation representable. The predecessor-specific current state of the two
  ``RUN`` ``TIMED_OUT`` rows is recovered by applying ``is_mixed_running_pair``
  to the stored pair before the coupled write, which
  ``transition_invocation_and_run`` must do: an invocation ``STARTING`` beside a
  run ``RUNNING``, or the reverse, is that predicate's violation, not an edge
  this mapping can see. A (predecessor, terminal) pair that is not a Task 1
  invocation edge is a programming error and raises ``ValueError``; the
  diagnostic category is required exactly for a linked ``FAILED_TO_START``,
  type-checked whenever supplied, and ignored where the row's condition is "any".
- ``is_mixed_running_pair`` covers the whole pre-handoff span: the plan's two
  orientations ("a RUN invocation is RUNNING while its linked run is not", "the
  run is RUNNING while its active RUN invocation is still STARTING"), the same
  orientation from ``PENDING`` (specification 15.6, "only one side RUNNING"), and
  the two half-applied ``begin_linked_launch`` states Task 6 must detect through
  it. A terminal invocation is the coupled terminal mapping's territory, and a
  terminal run beside an unlaunched invocation is a lawful ``transition_run``
  outcome awaiting the invocation's own cancellation, so both are outside it.

Absence is ``MISSING``, never ``None`` (plan section 3.1).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final, Literal, Self

from pydantic import Field, model_validator
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.diagnostics import DiagnosticCategory
from crypto_lab.domain.experiment import AdapterIdentity, EngineIdentity
from crypto_lab.domain.identifiers import (
    AttemptToken,
    AvailabilityObservationId,
    DiagnosticId,
    ExperimentId,
    LogicalSlotId,
    RunId,
    Sha256,
)
from crypto_lab.domain.lifecycle import (
    COMMAND_INVOCATION_TRANSITIONS,
    ENGINE_RUN_TRANSITIONS,
    TERMINAL_COMMAND_INVOCATION_STATES,
    TERMINAL_ENGINE_RUN_STATES,
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    RetryTerminalState,
)
from crypto_lab.domain.retry import MAX_ATTEMPTS_PER_SLOT
from crypto_lab.domain.time import CalendarValidUtcDateTime

_R: Final = EngineRunState
_C: Final = CommandInvocationState
_TERMINAL: Final = TERMINAL_ENGINE_RUN_STATES

#: Specification 17.1: the two terminal states that carry a usable result.
SUCCESS_ENGINE_RUN_STATES: Final[frozenset[EngineRunState]] = frozenset(
    {_R.SUCCEEDED, _R.SUCCEEDED_WITH_WARNINGS}
)
#: Plan section 5: the five terminals that carry ``primary_terminal_diagnostic_id``,
#: which are exactly the states plan section 8.3 admits as a retry predecessor.
NON_SUCCESS_TERMINAL_ENGINE_RUN_STATES: Final[frozenset[EngineRunState]] = (
    TERMINAL_ENGINE_RUN_STATES - SUCCESS_ENGINE_RUN_STATES
)
#: Plan section 5: owned by ``begin_linked_launch`` and ``start_linked_run`` alone.
LINKED_ONLY_RUN_EDGES: Final[frozenset[tuple[EngineRunState, EngineRunState]]] = (
    frozenset({(_R.READY, _R.STARTING), (_R.STARTING, _R.RUNNING)})
)

#: Plan section 3.8 row 14 and section 5: absent before ``READY`` ...
_OBSERVATION_PROHIBITED_STATES: Final[frozenset[EngineRunState]] = frozenset(
    {_R.PENDING, _R.VALIDATING}
)
#: ... present from ``READY`` onward, in the two success terminals ``RUNNING`` alone
#: reaches, and in ``UNAVAILABLE``; the remaining four terminals are
#: predecessor-dependent (module docstring).
_OBSERVATION_REQUIRED_STATES: Final[frozenset[EngineRunState]] = frozenset(
    {
        _R.READY,
        _R.STARTING,
        _R.RUNNING,
        _R.SUCCEEDED,
        _R.SUCCEEDED_WITH_WARNINGS,
        _R.UNAVAILABLE,
    }
)
#: Plan section 3.8 row 14: "R at the transition into READY or UNAVAILABLE".
_OBSERVATION_GOVERNING_TARGETS: Final[frozenset[EngineRunState]] = frozenset(
    {_R.READY, _R.UNAVAILABLE}
)
#: Plan section 6 "Coupled terminal transitions", the rows whose condition is "any".
#: ``FAILED_TO_START`` reads the primary diagnostic category and ``EXITED`` couples
#: nothing, so neither is a member.
_UNCONDITIONAL_COUPLED_TARGETS: Final[dict[CommandInvocationState, EngineRunState]] = {
    _C.TIMED_OUT: _R.TIMED_OUT,
    _C.CANCELLED: _R.CANCELLED,
    _C.PROTOCOL_FAILED: _R.FAILED,
}
#: Plan section 6: a live ``RUN`` invocation and its run advance together --
#: created against a ``READY`` run, then ``begin_linked_launch`` and
#: ``start_linked_run`` move both sides in one unit of work.
_LAWFUL_LIVE_PAIRS: Final[frozenset[tuple[CommandInvocationState, EngineRunState]]] = (
    frozenset(
        {
            (_C.PENDING, _R.READY),
            (_C.STARTING, _R.STARTING),
            (_C.RUNNING, _R.RUNNING),
        }
    )
)


def _is_missing(value: object) -> bool:
    return value is MISSING


class AttemptTokenMaterial(CanonicalModel):
    """The raw attempt token of one attempt, returned beside the record (plan 3.8).

    Explicitly temporary sensitive correlation material: never a field of a
    persisted record, never placed in a diagnostic, and hashed by
    ``attempt_token_hash`` into ``EngineRunRecord.attempt_token_hash`` alone. A
    nested value object, so it carries no envelope ``schema_version`` (plan
    section 3.1). The token is hidden from ``repr`` and ``str``.
    """

    run_id: RunId
    attempt_token: AttemptToken = Field(repr=False)


class EngineRunRecord(CanonicalModel):
    """Specification section 11.3: the authoritative state of one run attempt.

    The eighteen fields of plan section 3.8 in order. State-governed fields are
    ``MISSING`` when absent, and the validator below is the section 5 shape table;
    see the module docstring for the rules and the declared task-local readings.
    """

    schema_version: Literal["1.0.0"]
    run_id: RunId
    experiment_id: ExperimentId
    logical_slot_id: LogicalSlotId
    attempt_number: int = Field(ge=1, le=MAX_ATTEMPTS_PER_SLOT)
    attempt_token_hash: Sha256
    state: EngineRunState
    adapter: AdapterIdentity
    engine: EngineIdentity
    request_hash: Sha256
    predecessor_run_id: RunId | MISSING = MISSING  # type: ignore[valid-type]
    retry_reason: RetryTerminalState | MISSING = MISSING  # type: ignore[valid-type]
    primary_terminal_diagnostic_id: DiagnosticId | MISSING = MISSING  # type: ignore[valid-type]
    availability_observation_id: AvailabilityObservationId | MISSING = MISSING  # type: ignore[valid-type]
    finalization_deadline_utc: CalendarValidUtcDateTime | MISSING = MISSING  # type: ignore[valid-type]
    created_at_utc: CalendarValidUtcDateTime
    updated_at_utc: CalendarValidUtcDateTime
    revision: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_state_governed_shape(self) -> Self:
        self._validate_attempt_lineage()
        self._validate_terminal_diagnostic()
        self._validate_availability_observation()
        self._validate_finalization_deadline()
        self._validate_instants()
        return self

    # -- Plan section 3.8 rows 11 and 12, specification 17.2 ------------------------

    def _validate_attempt_lineage(self) -> None:
        successor = self.attempt_number > 1
        predecessor_present = not _is_missing(self.predecessor_run_id)
        reason_present = not _is_missing(self.retry_reason)
        if successor:
            if not predecessor_present:
                raise ValueError("a successor attempt requires predecessor_run_id")
            if not reason_present:
                raise ValueError("a successor attempt requires retry_reason")
            if self.predecessor_run_id == self.run_id:
                raise ValueError("predecessor_run_id must differ from run_id")
        else:
            if predecessor_present:
                raise ValueError("an initial attempt carries no predecessor_run_id")
            if reason_present:
                raise ValueError("an initial attempt carries no retry_reason")

    # -- Plan section 3.8 row 13 and section 5 ----------------------------------------

    def _validate_terminal_diagnostic(self) -> None:
        required = self.state in NON_SUCCESS_TERMINAL_ENGINE_RUN_STATES
        present = not _is_missing(self.primary_terminal_diagnostic_id)
        if required and not present:
            raise ValueError(
                f"{self.state.value} requires primary_terminal_diagnostic_id"
            )
        if present and not required:
            raise ValueError(
                "primary_terminal_diagnostic_id is present exactly in the five "
                "non-success terminal states"
            )

    # -- Plan section 3.8 row 14 and section 5 ----------------------------------------

    def _validate_availability_observation(self) -> None:
        present = not _is_missing(self.availability_observation_id)
        if self.state in _OBSERVATION_PROHIBITED_STATES and present:
            raise ValueError("availability_observation_id is absent before READY")
        if self.state in _OBSERVATION_REQUIRED_STATES and not present:
            raise ValueError(f"{self.state.value} requires availability_observation_id")

    # -- Plan section 3.8 row 15 ------------------------------------------------------

    def _validate_finalization_deadline(self) -> None:
        if not _is_missing(self.finalization_deadline_utc):
            raise ValueError(
                "finalization_deadline_utc is absent throughout Stage 5; Stage 9 "
                "snapshots it"
            )

    # -- Instants -----------------------------------------------------------------

    def _validate_instants(self) -> None:
        if self.updated_at_utc < self.created_at_utc:
            raise ValueError("updated_at_utc must be at or after created_at_utc")


class EngineRunCheck(StrEnum):
    """The distinguishable rules of the pure predicates, in report order.

    Task 6 maps each onto the diagnostic code plan section 8.6 assigns: an
    identity, terminal, edge, ownership, immutability or observation failure is
    ``CORE.INVARIANT_VIOLATION`` and a moved revision is
    ``PERSISTENCE.CONCURRENCY_CONFLICT``.
    """

    IDENTITY = "IDENTITY"
    REVISION = "REVISION"
    UPDATED_AT = "UPDATED_AT"
    TERMINAL_IMMUTABLE = "TERMINAL_IMMUTABLE"
    TRANSITION_EDGE = "TRANSITION_EDGE"
    TRANSITION_EDGE_OWNERSHIP = "TRANSITION_EDGE_OWNERSHIP"
    TRANSITION_IMMUTABLE_FIELD = "TRANSITION_IMMUTABLE_FIELD"
    TRANSITION_AVAILABILITY_OBSERVATION = "TRANSITION_AVAILABILITY_OBSERVATION"


class EngineRunRuleViolation(ValueError):
    """Raised by the pure predicates below, naming the first failed check."""

    def __init__(self, check: EngineRunCheck, message: str) -> None:
        super().__init__(message)
        self.check = check


class RunEdgeOwner(StrEnum):
    """Plan section 5 edge ownership: which authority may produce a table edge.

    ``GENERIC`` is ``transition_run`` for a core decision and
    ``transition_invocation_and_run`` for a linked invocation's terminal outcome;
    ``LINKED_LAUNCH`` is ``begin_linked_launch`` (``READY -> STARTING``) and
    ``start_linked_run`` (``STARTING -> RUNNING``) alone.
    """

    GENERIC = "GENERIC"
    LINKED_LAUNCH = "LINKED_LAUNCH"


def _require_run_states(*states: EngineRunState) -> None:
    for state in states:
        if type(state) is not EngineRunState:
            raise TypeError("engine-run edge endpoints must be EngineRunState members")


def run_edge_owner(current: EngineRunState, target: EngineRunState) -> RunEdgeOwner:
    """Plan section 5: the sole authority that may produce ``current -> target``.

    Total over the twenty-three table edges. A pair outside the Task 1 table has
    no owner and raises ``ValueError``; a foreign member raises ``TypeError``.
    """
    _require_run_states(current, target)
    if not ENGINE_RUN_TRANSITIONS.is_allowed(current, target):
        raise ValueError(
            f"{current.value} -> {target.value} is not a permitted engine-run edge"
        )
    if (current, target) in LINKED_ONLY_RUN_EDGES:
        return RunEdgeOwner.LINKED_LAUNCH
    return RunEdgeOwner.GENERIC


#: Plan section 5's eleven fields plus the inert envelope (module docstring).
#: ``run_id`` is checked first and separately as the identity rule.
_TRANSITION_IMMUTABLE_FIELDS: Final[tuple[str, ...]] = (
    "schema_version",
    "experiment_id",
    "logical_slot_id",
    "attempt_number",
    "attempt_token_hash",
    "adapter",
    "engine",
    "request_hash",
    "predecessor_run_id",
    "retry_reason",
    "created_at_utc",
)


def _require_same_run(stored: EngineRunRecord, replacement: EngineRunRecord) -> None:
    if replacement.run_id != stored.run_id:
        raise EngineRunRuleViolation(
            EngineRunCheck.IDENTITY,
            "stored and replacement records must share one run_id",
        )


def _require_bookkeeping(stored: EngineRunRecord, replacement: EngineRunRecord) -> None:
    if replacement.revision != stored.revision + 1:
        raise EngineRunRuleViolation(
            EngineRunCheck.REVISION,
            "an accepted transition increments revision by exactly one",
        )
    if replacement.updated_at_utc < stored.updated_at_utc:
        raise EngineRunRuleViolation(
            EngineRunCheck.UPDATED_AT,
            "updated_at_utc never moves backwards",
        )


def assert_terminal_run_immutability(
    stored: EngineRunRecord,
    replacement: EngineRunRecord,
) -> None:
    """Plan section 3.8: does ``replacement`` leave a terminal ``stored`` untouched?

    Checks, in report order: one identity; then, when ``stored`` is terminal,
    every field unchanged -- including ``revision``, because a terminal record
    accepts no further compare-and-swap. A field-for-field identical restatement
    is not a change. A non-terminal ``stored`` is governed by
    ``assert_run_transition`` instead, so the rule holds vacuously and a service
    may apply it to every write. Pure over its arguments.
    """
    _require_same_run(stored, replacement)
    if stored.state not in _TERMINAL:
        return
    for name in EngineRunRecord.model_fields:
        if getattr(replacement, name) != getattr(stored, name):
            raise EngineRunRuleViolation(
                EngineRunCheck.TERMINAL_IMMUTABLE,
                f"{name} may not change: a terminal engine run is completely "
                "immutable and accepts no enrichment or revision increment",
            )


def assert_run_transition(
    stored: EngineRunRecord,
    replacement: EngineRunRecord,
    *,
    owner: RunEdgeOwner = RunEdgeOwner.GENERIC,
) -> None:
    """Plan section 5 over the Task 1 table: is ``stored -> replacement`` lawful?

    Both records are already shape-valid for their own states; this predicate
    adds the pair rules. Checks, in report order: one identity; ``stored`` not
    terminal (a terminal record is never reopened -- a retry is a new attempt); a
    permitted ordered pair; the pair owned by ``owner``; the immutable fields
    unchanged; ``availability_observation_id`` request-governed exactly on a
    transition into ``READY`` or ``UNAVAILABLE`` and otherwise carried forward
    unchanged; revision plus one; and ``updated_at_utc`` not moved backwards.
    The primary terminal diagnostic needs no pair rule: the shape makes it
    unrepresentable before, and mandatory on, a non-success terminal write. Pure
    over its arguments.
    """
    if type(owner) is not RunEdgeOwner:
        raise TypeError("owner must be a RunEdgeOwner member")
    _require_same_run(stored, replacement)
    assert_terminal_run_immutability(stored, replacement)
    if stored.state in _TERMINAL:
        # An identical restatement passes the immutability rule above; it is still
        # not a transition, and the terminal rule -- not the reflexive-edge rule --
        # is the reason a terminal record is never reopened.
        raise EngineRunRuleViolation(
            EngineRunCheck.TERMINAL_IMMUTABLE,
            f"a terminal engine run ({stored.state.value}) accepts no transition; "
            "a retry is a new attempt",
        )
    if not ENGINE_RUN_TRANSITIONS.is_allowed(stored.state, replacement.state):
        raise EngineRunRuleViolation(
            EngineRunCheck.TRANSITION_EDGE,
            f"{stored.state.value} -> {replacement.state.value} is not a permitted "
            "engine-run edge",
        )
    actual_owner = run_edge_owner(stored.state, replacement.state)
    if actual_owner is not owner:
        raise EngineRunRuleViolation(
            EngineRunCheck.TRANSITION_EDGE_OWNERSHIP,
            f"{stored.state.value} -> {replacement.state.value} is owned by "
            f"{actual_owner.value}, not {owner.value}",
        )
    for name in _TRANSITION_IMMUTABLE_FIELDS:
        if getattr(replacement, name) != getattr(stored, name):
            raise EngineRunRuleViolation(
                EngineRunCheck.TRANSITION_IMMUTABLE_FIELD,
                f"{name} is immutable across every transition",
            )
    if (
        replacement.state not in _OBSERVATION_GOVERNING_TARGETS
        and replacement.availability_observation_id
        != stored.availability_observation_id
    ):
        raise EngineRunRuleViolation(
            EngineRunCheck.TRANSITION_AVAILABILITY_OBSERVATION,
            "availability_observation_id is request-governed only on a transition "
            "into READY or UNAVAILABLE and is otherwise carried forward unchanged",
        )
    _require_bookkeeping(stored, replacement)


def coupled_run_terminal_state(
    command_kind: CommandKind,
    invocation_predecessor_state: CommandInvocationState,
    invocation_terminal_state: CommandInvocationState,
    *,
    primary_diagnostic_category: DiagnosticCategory | MISSING = MISSING,  # type: ignore[valid-type]
) -> EngineRunState | MISSING:  # type: ignore[valid-type]
    """Plan section 6 "Coupled terminal transitions": the run target, if any.

    Total over every command kind and every Task 1 invocation edge that ends in a
    terminal state. ``DESCRIBE`` has no run linkage and ``EXITED`` is a process
    fact whose semantic mapping is Stage 6, so both yield ``MISSING``. A
    ``FAILED_TO_START`` invocation maps to ``UNAVAILABLE`` when the primary
    diagnostic category is ``ADAPTER_UNAVAILABILITY`` and to ``FAILED``
    otherwise; ``TIMED_OUT`` maps to ``TIMED_OUT``, ``CANCELLED`` to
    ``CANCELLED`` and ``PROTOCOL_FAILED`` to ``FAILED``, from whichever
    predecessor the invocation table admits. The category is required exactly
    for a linked ``FAILED_TO_START``, type-checked whenever supplied, and ignored
    where the row's condition is "any". Foreign members raise ``TypeError``; a
    pair that is not an invocation edge, or whose target is not terminal, raises
    ``ValueError``. The coupled operation proves the run edge itself through
    ``assert_run_transition`` (module docstring).
    """
    if type(command_kind) is not CommandKind:
        raise TypeError("command kind must be a CommandKind member")
    for state in (invocation_predecessor_state, invocation_terminal_state):
        if type(state) is not CommandInvocationState:
            raise TypeError("invocation states must be CommandInvocationState members")
    category_present = not _is_missing(primary_diagnostic_category)
    if category_present and type(primary_diagnostic_category) is not DiagnosticCategory:
        raise TypeError(
            "primary_diagnostic_category must be a DiagnosticCategory member"
        )
    if not COMMAND_INVOCATION_TRANSITIONS.is_allowed(
        invocation_predecessor_state, invocation_terminal_state
    ):
        raise ValueError(
            f"{invocation_predecessor_state.value} -> "
            f"{invocation_terminal_state.value} is not a permitted "
            "command-invocation edge"
        )
    if invocation_terminal_state not in TERMINAL_COMMAND_INVOCATION_STATES:
        raise ValueError(
            f"{invocation_terminal_state.value} is not a terminal "
            "command-invocation state"
        )
    if command_kind is CommandKind.DESCRIBE:
        return MISSING
    if invocation_terminal_state is _C.EXITED:
        return MISSING
    if invocation_terminal_state is _C.FAILED_TO_START:
        if not category_present:
            raise ValueError(
                "a linked FAILED_TO_START requires primary_diagnostic_category"
            )
        if primary_diagnostic_category is DiagnosticCategory.ADAPTER_UNAVAILABILITY:
            return _R.UNAVAILABLE
        return _R.FAILED
    return _UNCONDITIONAL_COUPLED_TARGETS[invocation_terminal_state]


def is_mixed_running_pair(
    run: EngineRunRecord,
    invocation: CommandInvocationRecord,
) -> bool:
    """Plan section 6 and specification 15.6: is the launch handoff half-applied?

    Defined for a ``RUN``-kind invocation linked to ``run``; any other pairing is
    a programming error and raises ``ValueError``. A terminal invocation is never
    part of a mixed running pair (the coupled terminal mapping governs it). A
    ``RUNNING`` invocation is mixed unless its run is ``RUNNING``. A live
    pre-handoff invocation (``PENDING`` or ``STARTING``) beside a terminal run is
    a lawful ``transition_run`` outcome awaiting the invocation's own
    cancellation; beside a non-terminal run it is mixed unless the pair is one of
    the three lawful live pairings (module docstring). Pure over its arguments.
    """
    if invocation.command_kind is not CommandKind.RUN:
        raise ValueError("is_mixed_running_pair is defined for a RUN-kind invocation")
    if invocation.run_id != run.run_id:
        raise ValueError("the invocation is not linked to the run")
    if invocation.state in TERMINAL_COMMAND_INVOCATION_STATES:
        return False
    if invocation.state is _C.RUNNING:
        return run.state is not _R.RUNNING
    if run.state in _TERMINAL:
        return False
    return (invocation.state, run.state) not in _LAWFUL_LIVE_PAIRS
