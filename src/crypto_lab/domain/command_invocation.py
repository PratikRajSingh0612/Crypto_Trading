"""Command-invocation record, process facts and the section 6 field-shape rules.

Stage 5 plan sections 3.7 and 6, under specification sections 11.3, 11.5, 14.6,
14.8 and 15.2. Placement follows plan section 2.3: the canonical record and its
state-governed invariants live in ``domain``, while the operations that create,
transition and enrich it -- ``create_invocation``, ``transition_invocation``,
``enrich_invocation`` and the linked operations -- are Task 6's application
services in ``experiments``, which consume the pure predicates defined here.

A ``CommandInvocationRecord`` is one command execution attempt: a ``describe``,
``validate`` or ``run`` subprocess. It is deliberately separate from the engine
run (Task 4): ``DESCRIBE`` has no run, ``VALIDATE`` and ``RUN`` link to one by
``run_id``, and an invocation state never implies an engine-run state
(specification 15.2, plan section 6). Nothing here launches, supervises or
inspects a process. ``ProcessIdentity`` and ``ProcessStartFacts`` are the
reviewed data contract for facts a Stage 7 supervisor will observe; Stage 5
accepts them as caller-supplied launch-handoff material.

Four kinds of rule live here.

1. **Record shape** -- ``CommandInvocationRecord``'s validator: plan section 6's
   eight-row table plus the field-level rules of section 3.7. ``run_id`` and the
   timeout bounds follow the command kind; the launch pair (deadline, launch
   instant), the process triple (``process_created``, start instant, identity)
   and the exit pair (native value, category) each co-occur; the category equals
   the frozen ``process_exit_category_for`` mapping of the native value;
   ``cleanup_completed_at_utc`` is present iff ``cleanup_complete``; the primary
   diagnostic is a member of the diagnostic array; and completion, stderr,
   primary-diagnostic and exit facts exist only in a terminal state.
2. **Transition** -- ``assert_invocation_transition``: a pure record-pair
   predicate over the Task 1 ``COMMAND_INVOCATION_TRANSITIONS`` table, the sole
   allowed-pair authority. It exists because a record cannot see its
   predecessor: section 6 makes the ``CANCELLED`` and ``TIMED_OUT`` launch and
   process facts predecessor-dependent, and only a pair can require that launch
   facts are established exactly on ``PENDING -> STARTING`` and process facts
   exactly on ``STARTING -> RUNNING``. Edge *ownership* (the ``RUN``-kind linked
   edges) and the ``Result``/``Failure`` codes are Task 6 service rules and are
   not encoded here; an idempotent same-state replay is likewise a service rule
   evaluated before the table (plan section 4), so a reflexive pair is never an
   edge.
3. **Write-once enrichment** -- ``assert_write_once_enrichment``: section 6's
   closed list of exactly four enrichable things on a terminal record, none of
   which may overwrite an existing value, alter ``state`` or change semantic
   outcome.
4. **Parent eligibility** -- ``assert_parent_run_eligibility``: the command-kind
   half of section 6's ``create_invocation`` matrix, namely linkage presence and
   the required parent run state. The matrix's further checks -- current
   attempt, experiment ``RUNNING``, slot and adapter agreement, revision and
   request-hash equality, no open ``VALIDATE`` or ``RUN`` -- need
   ``EngineRunRecord`` (Task 4), the experiment and repository queries, and
   belong to Task 6's service. The ``DESCRIBE`` row's "timeout bounds only" is
   ``command_timeout_bounds`` together with the shape validator.

Where the plan is silent, these task-local readings are applied and declared
here rather than inferred silently:

- ``primary_diagnostic_id`` is prohibited in ``RUNNING``. Section 6 lists it
  absent in ``PENDING`` and ``STARTING`` and omits it from the ``RUNNING`` row;
  section 3.7 defines it as a terminal-outcome fact ("required in every
  terminal state except ``EXITED``") and specification 15.2 names only primary
  start, cancellation, timeout and protocol diagnostics, so no non-terminal
  state carries one.
- ``deadline_utc`` equals ``launch_attempted_at_utc + timeout_seconds``. Both
  come from the one paired clock observation of the ``PENDING -> STARTING``
  transaction (specification 14.8; plan 3.7 fields 9 and 12), so an inconsistent
  pair is unrepresentable rather than merely unexpected.
- ``updated_at_utc`` is at or after ``created_at_utc``, mirroring the
  ``ExperimentRecord`` rule of plan section 3.6; and across an accepted
  transition or enrichment it never moves backwards (equality permitted),
  because every accepted write takes a fresh instant from the injected clock.
- Fields 1-8 and 23 -- ``schema_version``, ``invocation_id``, ``command_kind``,
  ``adapter_name``, ``adapter_version``, ``run_id``, ``request_hash``,
  ``timeout_seconds`` and ``created_at_utc`` -- are immutable across every
  transition. Section 3.7 marks only ``request_hash`` "immutable" explicitly;
  the rest follows from their creation-time sources, specification 11.3
  ("timeout duration is fixed at creation") and the section 3.2 carry-forward
  rule, which lets a request change only the fields the target state governs.
- ``diagnostic_ids`` never loses a member across a transition or an enrichment:
  a recorded diagnostic identity is a fact, and section 6 admits only
  *additional* identifiers.
- An enrichment that adds none of the four permitted facts is rejected rather
  than accepted as a revision-only write: section 6 counts one increment per
  accepted enrichment, and there is nothing to accept.

Deferred elsewhere and deliberately not checked here: owner and purpose
validation of ``stderr_artifact_id`` (plan section 1.4, Stage 9) and resolution
of the ``PROCESS.UNRECOGNIZED_PROCESS_EXIT`` diagnostic behind an unrecognized
exit's mandatory primary diagnostic (plan section 6, Task 6 through
``DiagnosticReader``); the record requires only that the diagnostic exists.
Absence is ``MISSING``, never ``None`` (plan section 3.1).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from typing import Annotated, Final, Literal, Self, assert_never

from pydantic import Field, field_validator, model_validator
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.descriptors import BoundedText, ExecutablePath
from crypto_lab.domain.identifiers import (
    ArtifactId,
    DiagnosticId,
    InvocationId,
    NormalizedIdentifier,
    RunId,
    Sha256,
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
from crypto_lab.domain.time import CalendarValidUtcDateTime
from crypto_lab.domain.versioning import SemanticVersion

#: Plan section 3.7: the merged ``ProcessConfig`` timeout bounds copied as
#: literals, because neither ``domain`` nor ``experiments`` may import
#: ``configuration`` (plan section 2.2).
MIN_TIMEOUT_SECONDS: Final = 1
MAX_DESCRIBE_TIMEOUT_SECONDS: Final = 300
MAX_VALIDATE_TIMEOUT_SECONDS: Final = 1800
MAX_RUN_TIMEOUT_SECONDS: Final = 604800
#: Plan section 3.7: a process identifier is a positive unsigned 32-bit value.
MAX_PID: Final = 4294967295
#: Plan section 3.7 field 16: the signed and unsigned 32-bit native exit span.
MIN_NATIVE_EXIT_VALUE: Final = -2147483648
MAX_NATIVE_EXIT_VALUE: Final = 4294967295
MAX_DIAGNOSTIC_IDS: Final = 64

_S: Final = CommandInvocationState
_TERMINAL: Final = TERMINAL_COMMAND_INVOCATION_STATES

type NativeExitValue = Annotated[
    int,
    Field(strict=True, ge=MIN_NATIVE_EXIT_VALUE, le=MAX_NATIVE_EXIT_VALUE),
]


def _is_missing(value: object) -> bool:
    return value is MISSING


@dataclass(frozen=True, slots=True)
class TimeoutBounds:
    """The inclusive ``timeout_seconds`` range of one command kind."""

    minimum_seconds: int
    maximum_seconds: int


_TIMEOUT_BOUNDS: Final[dict[CommandKind, TimeoutBounds]] = {
    CommandKind.DESCRIBE: TimeoutBounds(
        MIN_TIMEOUT_SECONDS, MAX_DESCRIBE_TIMEOUT_SECONDS
    ),
    CommandKind.VALIDATE: TimeoutBounds(
        MIN_TIMEOUT_SECONDS, MAX_VALIDATE_TIMEOUT_SECONDS
    ),
    CommandKind.RUN: TimeoutBounds(MIN_TIMEOUT_SECONDS, MAX_RUN_TIMEOUT_SECONDS),
}


def command_timeout_bounds(command_kind: CommandKind) -> TimeoutBounds:
    """Plan section 3.7: 1-300 for DESCRIBE, 1-1800 for VALIDATE, 1-604800 for RUN.

    Total over ``CommandKind``. A bare string is refused even though it would
    hash like a member, matching the strictness of ``lifecycle``.
    """
    if type(command_kind) is not CommandKind:
        raise TypeError("command kind must be a CommandKind member")
    return _TIMEOUT_BOUNDS[command_kind]


class ProcessIdentity(CanonicalModel):
    """Restart-portable identity of one supervised process (plan 3.7, spec 15.1).

    PID alone is insufficient because Windows may reuse it; ownership requires
    the durable creation identity, the executable path and hash from the
    explicit catalog, and the supervisor instance. A nested value object, so it
    carries no envelope ``schema_version`` (plan section 3.1). The path is stored
    as observed text and is never resolved or opened here.
    """

    pid: int = Field(ge=1, le=MAX_PID)
    creation_identity: BoundedText
    executable_path: ExecutablePath
    executable_hash: Sha256
    supervisor_instance_id: BoundedText


class ProcessStartFacts(CanonicalModel):
    """The process-start handoff, one common carrier for every command kind.

    Plan section 3.7. ``process_started_at_utc`` is an operating-system
    observation made by the supervisor and is therefore request-supplied rather
    than clock-derived (plan section 3.2). Task 6 carries it on the
    ``STARTING -> RUNNING`` request for ``DESCRIBE`` and ``VALIDATE`` and on the
    linked start request for ``RUN``, so no command kind is barred from
    ``RUNNING``.
    """

    pid_identity: ProcessIdentity
    process_started_at_utc: CalendarValidUtcDateTime


class CommandInvocationRecord(CanonicalModel):
    """Specification section 11.3: core-owned process facts for one command.

    The twenty-five fields of plan section 3.7 in order. State-governed fields
    are ``MISSING`` when absent, and the validator below is the section 6 shape
    table; see the module docstring for the rules and the declared task-local
    readings.
    """

    schema_version: Literal["1.0.0"]
    invocation_id: InvocationId
    command_kind: CommandKind
    adapter_name: NormalizedIdentifier
    adapter_version: SemanticVersion
    run_id: RunId | MISSING = MISSING  # type: ignore[valid-type]
    request_hash: Sha256
    timeout_seconds: int = Field(ge=MIN_TIMEOUT_SECONDS, le=MAX_RUN_TIMEOUT_SECONDS)
    deadline_utc: CalendarValidUtcDateTime | MISSING = MISSING  # type: ignore[valid-type]
    state: CommandInvocationState
    process_created: bool
    launch_attempted_at_utc: CalendarValidUtcDateTime | MISSING = MISSING  # type: ignore[valid-type]
    process_started_at_utc: CalendarValidUtcDateTime | MISSING = MISSING  # type: ignore[valid-type]
    pid_identity: ProcessIdentity | MISSING = MISSING  # type: ignore[valid-type]
    completed_at_utc: CalendarValidUtcDateTime | MISSING = MISSING  # type: ignore[valid-type]
    native_exit_value: NativeExitValue | MISSING = MISSING  # type: ignore[valid-type]
    process_exit_category: ProcessExitCategory | MISSING = MISSING  # type: ignore[valid-type]
    cleanup_complete: bool
    cleanup_completed_at_utc: CalendarValidUtcDateTime | MISSING = MISSING  # type: ignore[valid-type]
    stderr_artifact_id: ArtifactId | MISSING = MISSING  # type: ignore[valid-type]
    primary_diagnostic_id: DiagnosticId | MISSING = MISSING  # type: ignore[valid-type]
    diagnostic_ids: tuple[DiagnosticId, ...] = Field(
        max_length=MAX_DIAGNOSTIC_IDS,
        # Pydantic emits no `uniqueItems` for a tuple; the runtime rule below
        # rejects duplicates, so the published schema must agree.
        json_schema_extra={"uniqueItems": True},
    )
    created_at_utc: CalendarValidUtcDateTime
    updated_at_utc: CalendarValidUtcDateTime
    revision: int = Field(ge=0)

    @field_validator("diagnostic_ids")
    @classmethod
    def validate_diagnostic_ids(
        cls,
        value: tuple[DiagnosticId, ...],
    ) -> tuple[DiagnosticId, ...]:
        """Order carries no meaning, so it is canonicalized by rejection."""
        if len(set(value)) != len(value):
            raise ValueError("diagnostic identifiers must be unique")
        if value != tuple(sorted(value)):
            raise ValueError("diagnostic identifiers must be sorted")
        return value

    @model_validator(mode="after")
    def validate_state_governed_shape(self) -> Self:
        self._validate_command_kind_rules()
        self._validate_co_occurrence()
        self._validate_terminal_partition()
        self._validate_state_row()
        self._validate_instants()
        return self

    # -- Plan section 3.7 field-level rules --------------------------------------

    def _validate_command_kind_rules(self) -> None:
        if self.command_kind is CommandKind.DESCRIBE:
            if not _is_missing(self.run_id):
                raise ValueError("a DESCRIBE invocation has no run_id")
        elif _is_missing(self.run_id):
            raise ValueError("run_id is required for VALIDATE and RUN")
        bounds = command_timeout_bounds(self.command_kind)
        if not bounds.minimum_seconds <= self.timeout_seconds <= bounds.maximum_seconds:
            raise ValueError(
                f"timeout_seconds must be within {bounds.minimum_seconds}.."
                f"{bounds.maximum_seconds} for {self.command_kind.value}"
            )

    def _validate_co_occurrence(self) -> None:
        if _is_missing(self.deadline_utc) is not _is_missing(
            self.launch_attempted_at_utc
        ):
            raise ValueError("deadline_utc and launch_attempted_at_utc co-occur")
        process_facts = (
            not _is_missing(self.process_started_at_utc),
            not _is_missing(self.pid_identity),
        )
        if process_facts != (self.process_created, self.process_created):
            raise ValueError(
                "process_created, process_started_at_utc and pid_identity co-occur"
            )
        if _is_missing(self.native_exit_value) is not _is_missing(
            self.process_exit_category
        ):
            raise ValueError("native_exit_value and process_exit_category co-occur")
        if not _is_missing(self.native_exit_value):
            expected = process_exit_category_for(self.native_exit_value)
            if self.process_exit_category is not expected:
                raise ValueError(
                    "process_exit_category must equal "
                    "process_exit_category_for(native_exit_value)"
                )
        if _is_missing(self.cleanup_completed_at_utc) is self.cleanup_complete:
            raise ValueError(
                "cleanup_completed_at_utc is present if and only if cleanup_complete"
            )
        if not _is_missing(self.primary_diagnostic_id) and (
            self.primary_diagnostic_id not in self.diagnostic_ids
        ):
            raise ValueError("primary_diagnostic_id must be a member of diagnostic_ids")

    def _validate_terminal_partition(self) -> None:
        terminal = self.state in _TERMINAL
        if _is_missing(self.completed_at_utc) is terminal:
            raise ValueError("completed_at_utc is present exactly in a terminal state")
        if terminal:
            return
        if self.cleanup_complete:
            raise ValueError("cleanup_complete is false in every non-terminal state")
        if not _is_missing(self.stderr_artifact_id):
            raise ValueError("stderr_artifact_id is absent unless terminal")
        if not _is_missing(self.primary_diagnostic_id):
            raise ValueError(
                "primary_diagnostic_id is a terminal-outcome fact and is absent in "
                "PENDING, STARTING and RUNNING"
            )
        if not _is_missing(self.native_exit_value):
            raise ValueError(
                "native_exit_value and process_exit_category are absent in every "
                "non-terminal state"
            )

    # -- Plan section 6 "Required field shape" rows --------------------------------

    def _require_launch_facts(self) -> None:
        if _is_missing(self.deadline_utc):
            raise ValueError(
                f"{self.state.value} requires deadline_utc and launch_attempted_at_utc"
            )

    def _require_process(self, created: bool) -> None:
        if self.process_created is not created:
            raise ValueError(
                f"{self.state.value} requires process_created to be {created}"
            )

    def _require_primary_diagnostic(self) -> None:
        if _is_missing(self.primary_diagnostic_id):
            raise ValueError(f"{self.state.value} requires primary_diagnostic_id")

    def _validate_state_row(self) -> None:
        state = self.state
        if state is _S.PENDING:
            if not _is_missing(self.deadline_utc):
                raise ValueError(
                    "PENDING has no deadline_utc or launch_attempted_at_utc"
                )
            self._require_process(created=False)
        elif state is _S.STARTING:
            self._require_launch_facts()
            self._require_process(created=False)
        elif state is _S.RUNNING:
            self._require_launch_facts()
            self._require_process(created=True)
        elif state is _S.EXITED:
            self._require_launch_facts()
            self._require_process(created=True)
            if _is_missing(self.native_exit_value):
                raise ValueError(
                    "EXITED requires native_exit_value and process_exit_category"
                )
            if (
                self.native_exit_value not in RECOGNIZED_NATIVE_EXIT_VALUES
                and _is_missing(self.primary_diagnostic_id)
            ):
                raise ValueError(
                    "an EXITED record with an unrecognized native exit requires "
                    "primary_diagnostic_id"
                )
        elif state is _S.FAILED_TO_START:
            self._require_launch_facts()
            self._require_process(created=False)
            if not _is_missing(self.native_exit_value):
                raise ValueError(
                    "FAILED_TO_START carries no native_exit_value or "
                    "process_exit_category"
                )
            self._require_primary_diagnostic()
        elif state is _S.CANCELLED:
            self._require_primary_diagnostic()
            if self.process_created and _is_missing(self.deadline_utc):
                raise ValueError(
                    "a CANCELLED record with process facts requires deadline_utc "
                    "and launch_attempted_at_utc"
                )
        elif state is _S.TIMED_OUT:
            self._require_launch_facts()
            self._require_primary_diagnostic()
        elif state is _S.PROTOCOL_FAILED:
            self._require_launch_facts()
            self._require_process(created=True)
            self._require_primary_diagnostic()
        else:  # pragma: no cover - the Task 1 vocabulary is closed at eight
            assert_never(state)

    # -- Instants -----------------------------------------------------------------

    def _validate_instants(self) -> None:
        if self.updated_at_utc < self.created_at_utc:
            raise ValueError("updated_at_utc must be at or after created_at_utc")
        if not _is_missing(self.deadline_utc):
            expected = self.launch_attempted_at_utc + timedelta(
                seconds=self.timeout_seconds
            )
            if self.deadline_utc != expected:
                raise ValueError(
                    "deadline_utc must equal launch_attempted_at_utc + timeout_seconds"
                )


class CommandInvocationCheck(StrEnum):
    """The distinguishable rules of the three pure predicates, in report order.

    Task 6 maps each onto the diagnostic code plan section 8.6 assigns: an
    identity, edge, shape or immutability failure is ``CORE.INVARIANT_VIOLATION``
    and a moved revision is ``PERSISTENCE.CONCURRENCY_CONFLICT``.
    """

    IDENTITY = "IDENTITY"
    REVISION = "REVISION"
    UPDATED_AT = "UPDATED_AT"
    PARENT_LINKAGE = "PARENT_LINKAGE"
    PARENT_RUN_STATE = "PARENT_RUN_STATE"
    TRANSITION_EDGE = "TRANSITION_EDGE"
    TRANSITION_IMMUTABLE_FIELD = "TRANSITION_IMMUTABLE_FIELD"
    TRANSITION_LAUNCH_FACTS = "TRANSITION_LAUNCH_FACTS"
    TRANSITION_PROCESS_FACTS = "TRANSITION_PROCESS_FACTS"
    TRANSITION_CLEANUP = "TRANSITION_CLEANUP"
    TRANSITION_DIAGNOSTICS = "TRANSITION_DIAGNOSTICS"
    ENRICHMENT_NOT_TERMINAL = "ENRICHMENT_NOT_TERMINAL"
    ENRICHMENT_STATE = "ENRICHMENT_STATE"
    ENRICHMENT_IMMUTABLE_FIELD = "ENRICHMENT_IMMUTABLE_FIELD"
    ENRICHMENT_OVERWRITE = "ENRICHMENT_OVERWRITE"
    ENRICHMENT_EMPTY = "ENRICHMENT_EMPTY"


class CommandInvocationRuleViolation(ValueError):
    """Raised by the pure predicates below, naming the first failed check."""

    def __init__(self, check: CommandInvocationCheck, message: str) -> None:
        super().__init__(message)
        self.check = check


#: Plan section 6 parent-eligibility matrix, "Parent run state" column.
_REQUIRED_PARENT_STATE: Final[dict[CommandKind, object]] = {
    CommandKind.DESCRIBE: MISSING,
    CommandKind.VALIDATE: EngineRunState.VALIDATING,
    CommandKind.RUN: EngineRunState.READY,
}


def assert_parent_run_eligibility(
    command_kind: CommandKind,
    *,
    run_id: RunId | MISSING,  # type: ignore[valid-type]
    expected_run_revision: int | MISSING,  # type: ignore[valid-type]
    parent_run_state: EngineRunState | MISSING,  # type: ignore[valid-type]
) -> None:
    """The command-kind half of plan section 6's ``create_invocation`` matrix.

    ``DESCRIBE`` carries neither ``run_id`` nor ``expected_run_revision`` and has
    no parent run; ``VALIDATE`` carries both and its parent is ``VALIDATING``;
    ``RUN`` carries both and its parent is ``READY``. Linkage presence is checked
    before the parent state, so a half-linked request is named as such. Pure over
    its arguments; the matrix's further checks are Task 6's (module docstring).
    """
    if type(command_kind) is not CommandKind:
        raise TypeError("command kind must be a CommandKind member")
    linked = command_kind is not CommandKind.DESCRIBE
    run_present = not _is_missing(run_id)
    revision_present = not _is_missing(expected_run_revision)
    if linked and not (run_present and revision_present):
        raise CommandInvocationRuleViolation(
            CommandInvocationCheck.PARENT_LINKAGE,
            f"{command_kind.value} requires run_id and expected_run_revision",
        )
    if not linked and (run_present or revision_present):
        raise CommandInvocationRuleViolation(
            CommandInvocationCheck.PARENT_LINKAGE,
            "DESCRIBE carries no run_id or expected_run_revision",
        )
    required = _REQUIRED_PARENT_STATE[command_kind]
    if parent_run_state is not required:
        expected = (
            "no parent run" if required is MISSING else f"a {required} parent run"
        )
        raise CommandInvocationRuleViolation(
            CommandInvocationCheck.PARENT_RUN_STATE,
            f"{command_kind.value} requires {expected}",
        )


#: Fields 1-8 and 23 never change after creation: plan section 3.7 field 7,
#: specification 11.3 and the section 3.2 carry-forward rule (module docstring).
#: ``invocation_id`` is checked first and separately as the identity rule.
_TRANSITION_IMMUTABLE_FIELDS: Final[tuple[str, ...]] = (
    "schema_version",
    "command_kind",
    "adapter_name",
    "adapter_version",
    "run_id",
    "request_hash",
    "timeout_seconds",
    "created_at_utc",
)
#: Plan section 6: the four write-once enrichments plus the two bookkeeping
#: fields every accepted write moves. Everything else is immutable once terminal.
_ENRICHABLE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "native_exit_value",
        "process_exit_category",
        "cleanup_complete",
        "cleanup_completed_at_utc",
        "stderr_artifact_id",
        "diagnostic_ids",
        "updated_at_utc",
        "revision",
    }
)


def _require_same_invocation(
    stored: CommandInvocationRecord,
    replacement: CommandInvocationRecord,
) -> None:
    if replacement.invocation_id != stored.invocation_id:
        raise CommandInvocationRuleViolation(
            CommandInvocationCheck.IDENTITY,
            "stored and replacement records must share one invocation_id",
        )


def _require_bookkeeping(
    stored: CommandInvocationRecord,
    replacement: CommandInvocationRecord,
) -> None:
    if replacement.revision != stored.revision + 1:
        raise CommandInvocationRuleViolation(
            CommandInvocationCheck.REVISION,
            "an accepted write increments revision by exactly one",
        )
    if replacement.updated_at_utc < stored.updated_at_utc:
        raise CommandInvocationRuleViolation(
            CommandInvocationCheck.UPDATED_AT,
            "updated_at_utc never moves backwards",
        )


def assert_invocation_transition(
    stored: CommandInvocationRecord,
    replacement: CommandInvocationRecord,
) -> None:
    """Plan section 6 over the Task 1 table: is ``stored -> replacement`` lawful?

    Both records are already shape-valid for their own states; this predicate
    adds the pair rules. Checks, in report order: one identity; a permitted
    ordered pair; fields 1-8 and 23 unchanged; launch facts established exactly
    on ``PENDING -> STARTING`` and otherwise carried unchanged; process facts
    established exactly on ``STARTING -> RUNNING`` and otherwise carried
    unchanged; cleanup untouched, because it changes only through terminal
    enrichment; no recorded diagnostic lost; revision plus one; and
    ``updated_at_utc`` not moved backwards. Pure over its arguments.
    """
    _require_same_invocation(stored, replacement)
    if not COMMAND_INVOCATION_TRANSITIONS.is_allowed(stored.state, replacement.state):
        raise CommandInvocationRuleViolation(
            CommandInvocationCheck.TRANSITION_EDGE,
            f"{stored.state.value} -> {replacement.state.value} is not a permitted "
            "command-invocation edge",
        )
    for name in _TRANSITION_IMMUTABLE_FIELDS:
        if getattr(replacement, name) != getattr(stored, name):
            raise CommandInvocationRuleViolation(
                CommandInvocationCheck.TRANSITION_IMMUTABLE_FIELD,
                f"{name} is immutable across every transition",
            )
    launch_edge = stored.state is _S.PENDING and replacement.state is _S.STARTING
    if not _is_missing(stored.deadline_utc):
        if (
            replacement.deadline_utc != stored.deadline_utc
            or replacement.launch_attempted_at_utc != stored.launch_attempted_at_utc
        ):
            raise CommandInvocationRuleViolation(
                CommandInvocationCheck.TRANSITION_LAUNCH_FACTS,
                "deadline_utc and launch_attempted_at_utc are carried forward "
                "unchanged once established",
            )
    elif _is_missing(replacement.deadline_utc) is launch_edge:
        raise CommandInvocationRuleViolation(
            CommandInvocationCheck.TRANSITION_LAUNCH_FACTS,
            "deadline_utc and launch_attempted_at_utc are established exactly on "
            "PENDING -> STARTING",
        )
    process_edge = stored.state is _S.STARTING and replacement.state is _S.RUNNING
    if stored.process_created:
        if (
            not replacement.process_created
            or replacement.process_started_at_utc != stored.process_started_at_utc
            or replacement.pid_identity != stored.pid_identity
        ):
            raise CommandInvocationRuleViolation(
                CommandInvocationCheck.TRANSITION_PROCESS_FACTS,
                "process facts are carried forward unchanged once the process is owned",
            )
    elif replacement.process_created is not process_edge:
        raise CommandInvocationRuleViolation(
            CommandInvocationCheck.TRANSITION_PROCESS_FACTS,
            "process facts are established exactly on STARTING -> RUNNING",
        )
    if replacement.cleanup_complete or not _is_missing(
        replacement.cleanup_completed_at_utc
    ):
        raise CommandInvocationRuleViolation(
            CommandInvocationCheck.TRANSITION_CLEANUP,
            "cleanup changes only through terminal write-once enrichment",
        )
    if not set(stored.diagnostic_ids) <= set(replacement.diagnostic_ids):
        raise CommandInvocationRuleViolation(
            CommandInvocationCheck.TRANSITION_DIAGNOSTICS,
            "a transition never removes a recorded diagnostic",
        )
    _require_bookkeeping(stored, replacement)


def assert_write_once_enrichment(
    stored: CommandInvocationRecord,
    replacement: CommandInvocationRecord,
) -> None:
    """Plan section 6: is ``replacement`` a lawful write-once enrichment of ``stored``?

    Checks, in report order: one identity; ``stored`` terminal; ``state``
    unchanged; every field outside the four enrichments unchanged; no existing
    enrichable value overwritten, reverted, moved or removed (an identical
    restatement is not an overwrite); at least one fact actually added;
    revision plus one; and ``updated_at_utc`` not moved backwards. Pure over its
    arguments.
    """
    _require_same_invocation(stored, replacement)
    if stored.state not in _TERMINAL:
        raise CommandInvocationRuleViolation(
            CommandInvocationCheck.ENRICHMENT_NOT_TERMINAL,
            "only a terminal record accepts write-once enrichment",
        )
    if replacement.state is not stored.state:
        raise CommandInvocationRuleViolation(
            CommandInvocationCheck.ENRICHMENT_STATE,
            "enrichment never alters state",
        )
    for name in CommandInvocationRecord.model_fields:
        if name in _ENRICHABLE_FIELDS:
            continue
        if getattr(replacement, name) != getattr(stored, name):
            raise CommandInvocationRuleViolation(
                CommandInvocationCheck.ENRICHMENT_IMMUTABLE_FIELD,
                f"{name} is immutable once terminal",
            )
    added = False
    if not _is_missing(stored.native_exit_value):
        if (
            replacement.native_exit_value != stored.native_exit_value
            or replacement.process_exit_category != stored.process_exit_category
        ):
            raise CommandInvocationRuleViolation(
                CommandInvocationCheck.ENRICHMENT_OVERWRITE,
                "enrichment never overwrites a recorded native exit pair",
            )
    elif not _is_missing(replacement.native_exit_value):
        added = True
    if stored.cleanup_complete:
        if (
            not replacement.cleanup_complete
            or replacement.cleanup_completed_at_utc != stored.cleanup_completed_at_utc
        ):
            raise CommandInvocationRuleViolation(
                CommandInvocationCheck.ENRICHMENT_OVERWRITE,
                "enrichment never reverts or moves a completed cleanup",
            )
    elif replacement.cleanup_complete:
        added = True
    if not _is_missing(stored.stderr_artifact_id):
        if replacement.stderr_artifact_id != stored.stderr_artifact_id:
            raise CommandInvocationRuleViolation(
                CommandInvocationCheck.ENRICHMENT_OVERWRITE,
                "enrichment never replaces or drops a recorded stderr reference",
            )
    elif not _is_missing(replacement.stderr_artifact_id):
        added = True
    stored_ids = set(stored.diagnostic_ids)
    replacement_ids = set(replacement.diagnostic_ids)
    if not stored_ids <= replacement_ids:
        raise CommandInvocationRuleViolation(
            CommandInvocationCheck.ENRICHMENT_OVERWRITE,
            "enrichment never removes a recorded diagnostic",
        )
    if replacement_ids != stored_ids:
        added = True
    if not added:
        raise CommandInvocationRuleViolation(
            CommandInvocationCheck.ENRICHMENT_EMPTY,
            "an enrichment must add at least one of the four permitted facts",
        )
    _require_bookkeeping(stored, replacement)
