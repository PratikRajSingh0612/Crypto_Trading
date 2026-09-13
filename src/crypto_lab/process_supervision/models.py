"""The process-supervision records, enums, constants and pure helpers.

Stage 7 plan sections 3.3, 4.2, 6.1, 7.4 and 8.1, under specification sections 8,
14.8, 15.1, 15.2, 15.4 and 15.6. Every record is a strict frozen ``CanonicalModel``
(unknown fields rejected), trust class P (a transient projection) or K (a core
configuration-shaped value), unpublished, with no envelope version and no ``$id``.
Absence is ``MISSING``, never ``None``. No field is annotated ``AttemptToken``, no
record holds an adapter byte, a float or a monotonic reading:
``SupervisionTraceEntry.monotonic_100ns`` is an integer of 100-nanosecond ticks, so
every retained entry canonicalises and the token walk of plan section 11 can cover
it. Nothing here reads a clock, opens a file, touches a process or the environment;
every instant is the caller's injected reading and every path is stored as text.

The records are the vocabulary the later tasks fill: the roots module returns an
``OutputReadFailure`` (plan 7.4) for an output file that exists but cannot be read,
the process controller returns a ``LaunchFailure`` instead of a process and an
instant-free ``ProcessInspection``, the supervisor assembles the trace and the
``SupervisionOutcome``, and the reconciler reports through
``InvocationReconciliation`` and ``ReconciliationReport``.

Task-local readings, declared rather than inferred silently:

- ``LaunchFailure.not_found`` is exactly "winerror 2 or 3 at the popen stage" (plan
  8.2), so the record enforces the biconditional rather than a one-way implication.
- ``ProcessInspection.observed_image_path`` can only be read from a live handle, so
  it is absent whenever the process is not alive; ``observed_creation_identity`` is
  present exactly when it is (plan 3.3).
- ``SupervisionOutcome``: ``protocol_integrity`` is ``VIOLATED`` exactly for a
  ``PROTOCOL_FAILED`` decision (plan 3.3 says "iff", stricter than the merged
  ``CommandResult``); ``command_result.parsed_output`` is present exactly when
  ``output_parse`` is present and holds its strict model, and then equals it with the
  parse's ``source_hash`` (plan 3.3 and 7.4); a ``DESCRIBE`` summary is empty in every
  member, not only in its count (plan 3.3 "empty for ``DESCRIBE``").
- ``InvocationReconciliation.record_after`` names the reconciled invocation and kind,
  and its ``diagnostics`` are unique on identity, as ``CommandResult.diagnostics`` are.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Final, Literal, Self

from pydantic import (
    Field,
    TypeAdapter,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.adapters.catalog import AbsoluteLocalExecutablePath, AdapterCatalogEntry
from crypto_lab.adapters.commands import CommandResult
from crypto_lab.adapters.events import EventRejected, ProtocolEventSummary
from crypto_lab.adapters.manifests import ManifestParse, ValidationResultParse
from crypto_lab.adapters.negotiation import DescriptorParse
from crypto_lab.adapters.vocabulary import ProtocolIntegrityStatus
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.command_invocation import (
    MAX_PID,
    CommandInvocationRecord,
    ProcessIdentity,
)
from crypto_lab.domain.descriptors import BoundedText, ExecutablePath
from crypto_lab.domain.diagnostics import (
    MAX_DETAIL_BYTES,
    MAX_DETAIL_COLLECTION,
    MAX_DETAIL_NODES,
    Diagnostic,
    DiagnosticDetailKey,
    DiagnosticDetailValue,
    _inspect_details,
)
from crypto_lab.domain.identifiers import ExperimentId, InvocationId, RunId, Sha256
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.time import CalendarValidUtcDateTime

__all__ = [
    "COMMAND_ROOT_CEILING",
    "CREATE_SUSPENDED",
    "CTRL_BREAK_EVENT",
    "DESCRIBE_STDERR_PLACEHOLDER",
    "DIRECTORY_CEILING_WITHOUT_LONG_PATHS",
    "FILE_CEILING_WITHOUT_LONG_PATHS",
    "FORCED_TERMINATION_EXIT_CODE",
    "LAUNCH_ARGUMENTS_KEY",
    "LONG_PATH_CEILING",
    "MAX_LAUNCH_ARGUMENTS",
    "PIPE_HOLDER_GRACE_SECONDS",
    "POST_TERMINATION_WAIT_SECONDS",
    "QUEUE_CAPACITY_CHUNKS",
    "READER_JOIN_SECONDS",
    "READ_CHUNK_BYTES",
    "TICK_SECONDS",
    "CleanupAction",
    "CleanupFailure",
    "CleanupReport",
    "CreationIdentity",
    "DescendantIdentity",
    "ExecutableObservation",
    "InterruptOutcome",
    "InvocationReconciliation",
    "LaunchFailure",
    "LaunchSpecification",
    "OutputReadFailure",
    "ProcessInspection",
    "ProcessPresence",
    "ReconciliationAction",
    "ReconciliationReport",
    "RunReconciliationFacts",
    "SupervisionOutcome",
    "SupervisionTraceEntry",
    "SupervisionTraceKind",
    "TerminationReport",
    "catalog_launch_arguments",
    "parse_creation_identity",
    "render_creation_identity",
]

# --- The plan 6.1 constants ----------------------------------------------------------

#: The maximum wait of one supervision-loop iteration (the harness poll interval).
TICK_SECONDS: Final = 0.02
#: The ``read(n)`` size of a pipe reader (``bufsize=0``, so a short read returns
#: what is available).
READ_CHUNK_BYTES: Final = 65_536
#: Bounded queue per pipe: at most 4 MiB in flight, after which the reader blocks
#: and the child's write blocks -- the backpressure.
QUEUE_CAPACITY_CHUNKS: Final = 64
#: The bound on waiting for a terminated tree to exit and for the pipes to reach EOF.
POST_TERMINATION_WAIT_SECONDS: Final = 5.0
#: The bound on joining a reader thread after EOF or termination.
READER_JOIN_SECONDS: Final = 5.0
#: After the root's exit is reaped, how long a pipe may stay idle without EOF before
#: the descendants holding it are terminated; the window restarts per dequeued chunk.
PIPE_HOLDER_GRACE_SECONDS: Final = 1.0
#: ``ERROR_PROCESS_ABORTED``: outside the eight recognized exit values, so it maps to
#: ``RUNTIME_FAILURE``; distinct from ``1``, ``259`` and ``3221225786`` (plan 2.5
#: reading 6).
FORCED_TERMINATION_EXIT_CODE: Final = 1067
#: The ``GenerateConsoleCtrlEvent`` argument for the graceful interrupt.
CTRL_BREAK_EVENT: Final = 1
#: The Win32 process-creation flag the standard-library ``subprocess`` module does
#: not export; combined with ``CREATE_NEW_PROCESS_GROUP`` in the one launch call so
#: the child is resumed only after its Job Object assignment (plan 8.2).
CREATE_SUSPENDED: Final = 0x00000004
#: The value handed to the bounded stderr fold for a ``DESCRIBE``, which has no
#: attempt token while the merged fold refuses an empty one. Built from ``chr(0)``
#: pieces and NUL-bracketed, so no adapter text can contain it.
DESCRIBE_STDERR_PLACEHOLDER: Final = chr(0) + "describe-has-no-attempt-token" + chr(0)
#: The ``runtime_metadata`` key of the fixed launch arguments (plan 4.2).
LAUNCH_ARGUMENTS_KEY: Final = "launch_arguments"
#: The bound of ``catalog_launch_arguments``.
MAX_LAUNCH_ARGUMENTS: Final = 16
#: Plan 7.2: the command root is created with ``CreateDirectoryW`` and is the child's
#: working directory, so it is bounded at 247 regardless of long-path support.
COMMAND_ROOT_CEILING: Final = 247
DIRECTORY_CEILING_WITHOUT_LONG_PATHS: Final = 247
FILE_CEILING_WITHOUT_LONG_PATHS: Final = 259
#: With long-path support the catalog path grammar's own bound is the ceiling.
LONG_PATH_CEILING: Final = 1024

#: Plan 8.1: the creation ``FILETIME`` fits a ``Diagnostic`` detail integer.
_MAX_CREATION_100NS: Final = 2**63 - 1
#: Plan 3.3: ``windows:<pid>:<creation>`` exactly, no leading zero, no sign.
_CREATION_IDENTITY: Final = re.compile(
    r"windows:[1-9][0-9]{0,9}:(?:0|[1-9][0-9]{0,18})"
)
#: Plan 8.2: ``ERROR_FILE_NOT_FOUND`` and ``ERROR_PATH_NOT_FOUND`` at ``popen``.
_NOT_FOUND_WINERRORS: Final[frozenset[int]] = frozenset({2, 3})
_EXECUTABLE_PATH: TypeAdapter[str] = TypeAdapter(AbsoluteLocalExecutablePath)


def _is_missing(value: object) -> bool:
    return value is MISSING


def _require_clean_argument(label: str, value: str) -> None:
    """The ``ExecutablePath`` control-character rule, applied to one argument."""
    if not value:
        raise ValueError(f"{label} must not be empty")
    if any(character < " " or character == "\x7f" for character in value):
        raise ValueError(f"{label} must not contain a control character")


# --- Enums --------------------------------------------------------------------------


class ProcessPresence(StrEnum):
    """What ``ProcessController.inspect`` found behind an identity (plan 8.1)."""

    ALIVE_MATCHING = "ALIVE_MATCHING"
    ALIVE_DIFFERENT_IDENTITY = "ALIVE_DIFFERENT_IDENTITY"
    ABSENT = "ABSENT"
    UNDETERMINED = "UNDETERMINED"


class InterruptOutcome(StrEnum):
    """What ``LaunchedProcess.interrupt`` reports (plan 6.5, 8.3)."""

    DELIVERED = "DELIVERED"
    UNAVAILABLE = "UNAVAILABLE"
    PROCESS_GONE = "PROCESS_GONE"


class CleanupAction(StrEnum):
    """The closed set of cleanup actions a report names (plan 6.7, 7.5, 8.4)."""

    TREE_VERIFIED_DEAD = "TREE_VERIFIED_DEAD"
    JOB_CLOSED = "JOB_CLOSED"
    PROCESS_HANDLE_CLOSED = "PROCESS_HANDLE_CLOSED"
    STDOUT_READER_STOPPED = "STDOUT_READER_STOPPED"
    STDERR_READER_STOPPED = "STDERR_READER_STOPPED"
    PIPES_CLOSED = "PIPES_CLOSED"
    COMMAND_ROOT_REMOVED = "COMMAND_ROOT_REMOVED"


class SupervisionTraceKind(StrEnum):
    """Every supervision fact the observer port can receive (plan 3.3)."""

    PREFLIGHT_ACCEPTED = "PREFLIGHT_ACCEPTED"
    PREFLIGHT_REFUSED = "PREFLIGHT_REFUSED"
    EXECUTABLE_OBSERVED = "EXECUTABLE_OBSERVED"
    STARTING_COMMITTED = "STARTING_COMMITTED"
    REQUEST_WRITTEN = "REQUEST_WRITTEN"
    LAUNCHED = "LAUNCHED"
    LAUNCH_FAILED = "LAUNCH_FAILED"
    PRE_HANDOFF_DEADLINE = "PRE_HANDOFF_DEADLINE"
    PRE_HANDOFF_CANCELLATION = "PRE_HANDOFF_CANCELLATION"
    RUNNING_COMMITTED = "RUNNING_COMMITTED"
    EVENT_ACCEPTED = "EVENT_ACCEPTED"
    EVENT_REPLAYED = "EVENT_REPLAYED"
    EVENT_REJECTED = "EVENT_REJECTED"
    STDOUT_BYTES_COUNTED = "STDOUT_BYTES_COUNTED"
    HEARTBEAT_MISSED = "HEARTBEAT_MISSED"
    CANCELLATION_OBSERVED = "CANCELLATION_OBSERVED"
    INTERRUPT_SENT = "INTERRUPT_SENT"
    INTERRUPT_UNAVAILABLE = "INTERRUPT_UNAVAILABLE"
    FORCED_TERMINATION = "FORCED_TERMINATION"
    EXIT_REAPED = "EXIT_REAPED"
    TERMINAL_DECIDED = "TERMINAL_DECIDED"
    TERMINAL_COMMITTED = "TERMINAL_COMMITTED"
    EXTERNAL_TERMINAL_WINNER = "EXTERNAL_TERMINAL_WINNER"
    ENRICHMENT_COMMITTED = "ENRICHMENT_COMMITTED"
    CLEANUP_ACTION = "CLEANUP_ACTION"
    CLEANUP_FAILED = "CLEANUP_FAILED"
    WRITE_BOUNDARY_VIOLATION = "WRITE_BOUNDARY_VIOLATION"
    RECONCILIATION_DECISION = "RECONCILIATION_DECISION"


class ReconciliationAction(StrEnum):
    """The one action a reconciliation pass applies per record (plan 8.5)."""

    LEFT_PENDING = "LEFT_PENDING"
    TERMINALIZED_FAILED_TO_START = "TERMINALIZED_FAILED_TO_START"
    TERMINALIZED_TIMED_OUT = "TERMINALIZED_TIMED_OUT"
    TERMINALIZED_CANCELLED = "TERMINALIZED_CANCELLED"
    TERMINALIZED_PROTOCOL_FAILED = "TERMINALIZED_PROTOCOL_FAILED"
    LEFT_RUNNING_AWAITING_DEADLINE = "LEFT_RUNNING_AWAITING_DEADLINE"
    CLEANUP_COMPLETED = "CLEANUP_COMPLETED"
    CLEANUP_FAILED = "CLEANUP_FAILED"
    CLEANUP_STILL_FAILING = "CLEANUP_STILL_FAILING"
    INVARIANT_REPORTED = "INVARIANT_REPORTED"
    SKIPPED_EXTERNAL_WINNER = "SKIPPED_EXTERNAL_WINNER"


#: Plan 3.3: the two presences under which a live handle was inspected.
_ALIVE: Final[frozenset[ProcessPresence]] = frozenset(
    {ProcessPresence.ALIVE_MATCHING, ProcessPresence.ALIVE_DIFFERENT_IDENTITY}
)
#: Plan 3.3: the per-event kinds go to the observers and are never retained.
_NEVER_RETAINED: Final[frozenset[SupervisionTraceKind]] = frozenset(
    {SupervisionTraceKind.EVENT_ACCEPTED, SupervisionTraceKind.EVENT_REPLAYED}
)
#: Plan 3.3: the only retained kinds that may repeat within one outcome.
_REPEATABLE: Final[frozenset[SupervisionTraceKind]] = frozenset(
    {SupervisionTraceKind.CLEANUP_ACTION, SupervisionTraceKind.CLEANUP_FAILED}
)


# --- Launch-side records ------------------------------------------------------------


class ExecutableObservation(CanonicalModel):
    """What the supervisor saw of the registered executable before the swap (K).

    Plan 3.3 and 7.2: the catalog path and hash beside the observed facts; the
    observed hash is present exactly when the file is a present regular file with no
    reparse point on it or on any ancestor, and ``verified`` is whether that hash
    equals the expected one.
    """

    executable_path: AbsoluteLocalExecutablePath
    expected_hash: Sha256
    present: bool
    regular_file: bool
    reparse_point: bool
    ancestor_reparse_point: bool
    observed_hash: Sha256 | MISSING = MISSING  # type: ignore[valid-type]
    observed_at_utc: CalendarValidUtcDateTime

    @model_validator(mode="after")
    def validate_hash_presence(self) -> Self:
        hashable = (
            self.present
            and self.regular_file
            and not self.reparse_point
            and not self.ancestor_reparse_point
        )
        if _is_missing(self.observed_hash) is hashable:
            raise ValueError(
                "observed_hash is present exactly when the executable is a present "
                "regular file with no reparse point on it or any ancestor"
            )
        return self

    @property
    def verified(self) -> bool:
        """Whether the observed hash is present and equals the expected hash."""
        return (
            not _is_missing(self.observed_hash)
            and self.observed_hash == self.expected_hash
        )


class LaunchSpecification(CanonicalModel):
    """The complete launch of one command (K; plan 3.3, 4.1, 11).

    ``argv[0]`` is the catalog's absolute executable, followed by the fixed launch
    arguments and ``argument_array(command)``; ``cwd`` is the command root. There is
    no environment field: the controller always passes the empty mapping.
    """

    invocation_id: InvocationId
    argv: tuple[str, ...] = Field(min_length=2)
    cwd: AbsoluteLocalExecutablePath

    @field_validator("argv")
    @classmethod
    def validate_argv(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for index, element in enumerate(value):
            _require_clean_argument(f"argv[{index}]", element)
        try:
            _EXECUTABLE_PATH.validate_python(value[0])
        except ValidationError as error:
            raise ValueError(
                "argv[0] must be an absolute local executable path"
            ) from error
        return value


@dataclass(frozen=True, slots=True)
class CreationIdentity:
    """A parsed ``windows:<pid>:<creation>`` identity (plan 3.3, 8.1).

    ``creation_100ns`` is the process creation ``FILETIME`` in 100-nanosecond ticks
    since 1601, bounded so it fits a ``Diagnostic`` detail integer.
    """

    pid: int
    creation_100ns: int

    def __post_init__(self) -> None:
        if type(self.pid) is not int or not 1 <= self.pid <= MAX_PID:
            raise ValueError(
                f"a creation identity pid is an integer within 1..{MAX_PID}"
            )
        if (
            type(self.creation_100ns) is not int
            or not 0 <= self.creation_100ns <= _MAX_CREATION_100NS
        ):
            raise ValueError(
                "a creation identity creation time is an integer within 0..2**63-1"
            )


def render_creation_identity(pid: int, creation_100ns: int) -> str:
    """Render the durable creation identity text of one process (plan 8.1)."""
    identity = CreationIdentity(pid, creation_100ns)
    return f"windows:{identity.pid}:{identity.creation_100ns}"


def parse_creation_identity(text: str) -> CreationIdentity:
    """Parse the exact ``windows:<pid>:<creation>`` grammar (plan 3.3).

    The merged fixture shapes (``offline-harness:<pid>``, the ISO-plus-ordinal
    doubles), a leading zero, a sign and any surrounding character are refused.
    """
    if type(text) is not str:
        raise TypeError("a creation identity is text")
    if _CREATION_IDENTITY.fullmatch(text) is None:
        raise ValueError("creation identity text must match windows:<pid>:<creation>")
    _, pid_text, creation_text = text.split(":")
    return CreationIdentity(int(pid_text), int(creation_text))


class ProcessInspection(CanonicalModel):
    """What the controller found behind a recorded identity (P; plan 3.3, 8.1).

    No instant: the controller has no clock, and the caller stamps its own trace
    entry. The observed creation identity is present exactly when the process is
    alive; an image path can only be read from a live handle.
    """

    identity: ProcessIdentity
    presence: ProcessPresence
    observed_creation_identity: BoundedText | MISSING = MISSING  # type: ignore[valid-type]
    observed_image_path: ExecutablePath | MISSING = MISSING  # type: ignore[valid-type]

    @model_validator(mode="after")
    def validate_observed_facts(self) -> Self:
        alive = self.presence in _ALIVE
        if _is_missing(self.observed_creation_identity) is alive:
            raise ValueError(
                "observed_creation_identity is present exactly when the process "
                "is alive"
            )
        if not alive and not _is_missing(self.observed_image_path):
            raise ValueError("observed_image_path is observed only from a live process")
        return self


class LaunchFailure(CanonicalModel):
    """What ``ProcessController.launch`` returns instead of a process (P; plan 8.2).

    It carries no ``Diagnostic``: the controller has neither a clock nor the run
    correlation, so the supervisor mints the ``FAILED_TO_START`` primary from these
    fields. ``not_found`` is exactly ``winerror`` 2 or 3 at the ``popen`` stage.
    """

    stage: Literal["popen", "open_process", "resume"]
    os_error_code: int | MISSING = MISSING  # type: ignore[valid-type]
    error_class: BoundedText
    not_found: bool

    @model_validator(mode="after")
    def validate_not_found(self) -> Self:
        expected = (
            self.stage == "popen"
            and not _is_missing(self.os_error_code)
            and self.os_error_code in _NOT_FOUND_WINERRORS
        )
        if self.not_found is not expected:
            raise ValueError(
                "not_found is true exactly for winerror 2 or 3 at the popen stage"
            )
        return self


class OutputReadFailure(CanonicalModel):
    """An output file that exists but cannot be read (P; plan 7.4).

    Returned by the roots module's output read for a sharing violation or an
    access-denied error; the supervisor derives the ``output_unreadable`` fact of its
    ``EXIT_REAPED`` trace entry from it and leaves ``output_parse`` absent. No
    diagnostic is minted for it, because the merged reconcilers already classify a
    missing parse. It carries an optional error number and a bounded class name
    only: never a path, a byte of the file or an exception object.
    """

    os_error_code: int | MISSING = MISSING  # type: ignore[valid-type]
    error_class: BoundedText


# --- Cleanup and termination records -------------------------------------------------


class CleanupFailure(CanonicalModel):
    """One cleanup action that failed (P; plan 3.3).

    ``reason`` is a closed reason word plus an error number, never adapter bytes or
    a path.
    """

    action: CleanupAction
    reason: BoundedText


class CleanupReport(CanonicalModel):
    """The completed and failed cleanup actions of one invocation (P; plan 8.4)."""

    completed: tuple[CleanupAction, ...]
    failures: tuple[CleanupFailure, ...]

    @model_validator(mode="after")
    def validate_partition(self) -> Self:
        if len(set(self.completed)) != len(self.completed):
            raise ValueError("completed actions must be unique")
        failed = [failure.action for failure in self.failures]
        if len(set(failed)) != len(failed):
            raise ValueError("failures must be unique on action")
        if set(failed) & set(self.completed):
            raise ValueError("failures must be disjoint from completed actions")
        return self

    @property
    def complete(self) -> bool:
        """Whether every attempted action completed."""
        return not self.failures


class DescendantIdentity(CanonicalModel):
    """One verified descendant of a supervised root (P; plan 8.3)."""

    pid: int = Field(ge=1, le=MAX_PID)
    creation_identity: BoundedText
    image_path: ExecutablePath | MISSING = MISSING  # type: ignore[valid-type]


class TerminationReport(CanonicalModel):
    """What one tree termination did (P; plan 3.3, 8.3).

    ``exit_code_used`` is present exactly when the termination was forced;
    ``descendants`` is the verified tree snapshot taken before termination; a
    ``TREE_VERIFIED_DEAD`` failure may appear once per surviving process.
    """

    forced: bool
    exit_code_used: int | MISSING = MISSING  # type: ignore[valid-type]
    job_terminated: bool
    descendants: tuple[DescendantIdentity, ...]
    failures: tuple[CleanupFailure, ...]

    @model_validator(mode="after")
    def validate_exit_code(self) -> Self:
        if _is_missing(self.exit_code_used) is self.forced:
            raise ValueError(
                "exit_code_used is present exactly when the termination was forced"
            )
        return self


# --- The trace and the outcome --------------------------------------------------------


class SupervisionTraceEntry(CanonicalModel):
    """One supervision fact delivered to the observers (P; plan 3.3).

    ``facts`` carries identifiers, counts, codes, state names and the
    controller-observed image path only -- never a stdout, stderr, request or output
    byte -- under the ``Diagnostic.details`` bounds; ``rejection`` is present exactly
    on an ``EVENT_REJECTED`` entry and is already redacted by the merged parser.
    """

    kind: SupervisionTraceKind
    invocation_id: InvocationId
    sequence: int = Field(ge=1)
    at_utc: CalendarValidUtcDateTime
    monotonic_100ns: int = Field(ge=0)
    facts: Annotated[
        dict[DiagnosticDetailKey, DiagnosticDetailValue],
        Field(max_length=MAX_DETAIL_COLLECTION),
    ]
    rejection: EventRejected | MISSING = MISSING  # type: ignore[valid-type]

    @field_validator("facts")
    @classmethod
    def validate_facts(
        cls,
        value: dict[DiagnosticDetailKey, DiagnosticDetailValue],
    ) -> dict[DiagnosticDetailKey, DiagnosticDetailValue]:
        nodes = _inspect_details(value)
        if nodes > MAX_DETAIL_NODES:
            raise ValueError("trace facts contain too many nodes")
        if len(canonical_json_bytes(value)) > MAX_DETAIL_BYTES:
            raise ValueError("trace facts exceed maximum encoded bytes")
        return value

    @model_validator(mode="after")
    def validate_rejection(self) -> Self:
        rejected = self.kind is SupervisionTraceKind.EVENT_REJECTED
        if _is_missing(self.rejection) is rejected:
            raise ValueError("rejection is present exactly on an EVENT_REJECTED entry")
        return self


#: Plan 3.3: the parse class each command kind's output file yields.
_PARSE_OF_KIND: Final[dict[CommandKind, type[CanonicalModel]]] = {
    CommandKind.DESCRIBE: DescriptorParse,
    CommandKind.VALIDATE: ValidationResultParse,
    CommandKind.RUN: ManifestParse,
}


def _parsed_model_of(
    parse: DescriptorParse | ValidationResultParse | ManifestParse,
) -> object:
    """The strict model a parse holds, or ``MISSING`` for a failed parse."""
    if isinstance(parse, DescriptorParse):
        return parse.envelope
    if isinstance(parse, ValidationResultParse):
        return parse.result
    return parse.manifest


class SupervisionOutcome(CanonicalModel):
    """What ``ProcessSupervisor.invoke`` returns inside ``Success`` (P; plan 3.3).

    ``command_result`` is the Stage 6 ``CommandResult`` verbatim; ``output_parse`` is
    the byte-level parse of the output file, present only for an ``EXITED``
    invocation; ``trace`` is the bounded retained trace (the per-event kinds are
    delivered to the observers only, and no retained kind other than a cleanup entry
    repeats). See the module docstring for the declared readings.
    """

    command_result: CommandResult
    output_parse: (  # type: ignore[valid-type]
        DescriptorParse | ValidationResultParse | ManifestParse | MISSING
    ) = MISSING
    protocol_summary: ProtocolEventSummary
    stdout_byte_count: int = Field(ge=0)
    replay_count: int = Field(ge=0)
    executable_observation: ExecutableObservation
    trace: tuple[SupervisionTraceEntry, ...]

    @model_validator(mode="after")
    def validate_outcome_shape(self) -> Self:
        self._validate_integrity()
        self._validate_output_parse()
        self._validate_summary_and_counts()
        self._validate_trace()
        return self

    def _validate_integrity(self) -> None:
        state = self.command_result.invocation.state
        violated = (
            self.command_result.protocol_integrity is ProtocolIntegrityStatus.VIOLATED
        )
        if violated is not (state is CommandInvocationState.PROTOCOL_FAILED):
            raise ValueError(
                "protocol_integrity is VIOLATED exactly for a PROTOCOL_FAILED "
                "invocation"
            )

    def _validate_output_parse(self) -> None:
        invocation = self.command_result.invocation
        parsed_model: object = MISSING
        if not _is_missing(self.output_parse):
            if invocation.state is not CommandInvocationState.EXITED:
                raise ValueError(
                    "output_parse is present only for an EXITED invocation"
                )
            expected = _PARSE_OF_KIND[invocation.command_kind]
            if type(self.output_parse) is not expected:
                raise ValueError(
                    f"output_parse must be a {expected.__name__} for command_kind "
                    f"{invocation.command_kind.value}"
                )
            parsed_model = _parsed_model_of(self.output_parse)
        parsed_output = self.command_result.parsed_output
        if _is_missing(parsed_model):
            if not _is_missing(parsed_output):
                raise ValueError(
                    "command_result.parsed_output is present exactly when output_parse "
                    "holds its strict model"
                )
            return
        if parsed_output != parsed_model:
            raise ValueError(
                "command_result.parsed_output must equal the model output_parse holds"
            )
        if (
            self.command_result.parsed_output_source_hash
            != self.output_parse.source_hash
        ):
            raise ValueError(
                "parsed_output_source_hash must equal output_parse.source_hash"
            )

    def _validate_summary_and_counts(self) -> None:
        summary = self.protocol_summary
        if summary.accepted_count != len(self.command_result.accepted_events):
            raise ValueError(
                "protocol_summary.accepted_count must equal the number of accepted "
                "events"
            )
        if self.command_result.invocation.command_kind is CommandKind.DESCRIBE:
            if (
                summary.artifact_declarations
                or summary.warnings
                or summary.adapter_diagnostics
                or not _is_missing(summary.final_result)
                or summary.redactions != 0
            ):
                raise ValueError("protocol_summary is empty for a DESCRIBE")
        elif self.stdout_byte_count != 0:
            raise ValueError(
                "stdout_byte_count is zero unless the command is a DESCRIBE"
            )

    def _validate_trace(self) -> None:
        invocation_id = self.command_result.invocation.invocation_id
        previous = 0
        seen: set[SupervisionTraceKind] = set()
        # "At most one entry carries a rejection" (plan 3.3) follows from the two
        # rules below: a rejection sits exactly on an EVENT_REJECTED entry and that
        # kind may not repeat, so no separate check is needed.
        for entry in self.trace:
            if entry.invocation_id != invocation_id:
                raise ValueError("trace entries must name the invocation")
            if entry.sequence <= previous:
                raise ValueError(
                    "trace entries must be in strictly increasing sequence order"
                )
            previous = entry.sequence
            if entry.kind in _NEVER_RETAINED:
                raise ValueError(
                    f"{entry.kind.value} entries are delivered to the observers and "
                    "never retained"
                )
            if entry.kind in seen and entry.kind not in _REPEATABLE:
                raise ValueError(
                    f"trace kind {entry.kind.value} repeats; only CLEANUP_ACTION and "
                    "CLEANUP_FAILED may repeat"
                )
            seen.add(entry.kind)


# --- Reconciliation records ----------------------------------------------------------


class RunReconciliationFacts(CanonicalModel):
    """The run and experiment facts a reconciliation pass reads (K; plan 3.3, 8.5)."""

    run_id: RunId
    experiment_id: ExperimentId
    run_state: EngineRunState
    run_revision: int = Field(ge=0)
    attempt_token_hash: Sha256
    request_hash: Sha256
    experiment_state: ExperimentState

    @property
    def cancelled(self) -> bool:
        """Plan 2.5 reading 17: the experiment or the linked run is ``CANCELLED``."""
        return (
            self.experiment_state is ExperimentState.CANCELLED
            or self.run_state is EngineRunState.CANCELLED
        )


class InvocationReconciliation(CanonicalModel):
    """The decision one reconciliation pass took for one invocation (P; plan 8.5).

    ``presence`` is present when the process was inspected; ``manifest_present`` is
    present exactly for ``LEFT_RUNNING_AWAITING_DEADLINE`` on a ``RUN``;
    ``diagnostics`` are every diagnostic the pass minted, attached or not.
    """

    invocation_id: InvocationId
    command_kind: CommandKind
    state_before: CommandInvocationState
    action: ReconciliationAction
    record_after: CommandInvocationRecord
    presence: ProcessPresence | MISSING = MISSING  # type: ignore[valid-type]
    manifest_present: bool | MISSING = MISSING  # type: ignore[valid-type]
    diagnostics: tuple[Diagnostic, ...]

    @model_validator(mode="after")
    def validate_decision_shape(self) -> Self:
        if self.record_after.invocation_id != self.invocation_id:
            raise ValueError("record_after must name the reconciled invocation_id")
        if self.record_after.command_kind is not self.command_kind:
            raise ValueError("record_after must carry the reconciled command_kind")
        manifest_reported = (
            self.action is ReconciliationAction.LEFT_RUNNING_AWAITING_DEADLINE
            and self.command_kind is CommandKind.RUN
        )
        if _is_missing(self.manifest_present) is manifest_reported:
            raise ValueError(
                "manifest_present is present exactly for "
                "LEFT_RUNNING_AWAITING_DEADLINE on a RUN"
            )
        identities = [item.diagnostic_id for item in self.diagnostics]
        if len(set(identities)) != len(identities):
            raise ValueError("diagnostics must be unique on diagnostic_id")
        return self


class ReconciliationReport(CanonicalModel):
    """One reconciliation pass over every target record (P; plan 8.5)."""

    supervisor_instance_id: BoundedText
    started_at_utc: CalendarValidUtcDateTime
    entries: tuple[InvocationReconciliation, ...]

    @model_validator(mode="after")
    def validate_entries(self) -> Self:
        identities = [entry.invocation_id for entry in self.entries]
        if len(set(identities)) != len(identities):
            raise ValueError("entries must be unique on invocation_id")
        return self


# --- Fixed launch arguments -----------------------------------------------------------


def catalog_launch_arguments(entry: AdapterCatalogEntry) -> tuple[str, ...]:
    """Plan 4.2: the fixed launch arguments of one catalog entry.

    Reads ``runtime_metadata["launch_arguments"]``: a missing key is ``()``; a list
    of at most ``MAX_LAUNCH_ARGUMENTS`` non-empty strings without control characters
    is returned as a tuple; anything else raises ``ValueError``, which the
    supervisor's preflight turns into ``Failure(CORE.INVARIANT_VIOLATION)``. Pure
    over its argument.
    """
    if not isinstance(entry, AdapterCatalogEntry):
        raise TypeError("catalog_launch_arguments takes an AdapterCatalogEntry")
    metadata = entry.runtime_metadata
    if LAUNCH_ARGUMENTS_KEY not in metadata:
        return ()
    value = metadata[LAUNCH_ARGUMENTS_KEY]
    if type(value) is not list:
        raise ValueError("launch_arguments must be a list of strings")
    if len(value) > MAX_LAUNCH_ARGUMENTS:
        raise ValueError(
            f"launch_arguments holds at most {MAX_LAUNCH_ARGUMENTS} arguments"
        )
    arguments: list[str] = []
    for index, item in enumerate(value):
        if type(item) is not str:
            raise ValueError("launch_arguments elements must be strings")
        _require_clean_argument(f"launch_arguments[{index}]", item)
        arguments.append(item)
    return tuple(arguments)
