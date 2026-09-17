"""The Windows process supervisor: one command from ``PENDING`` to its enrichment.

Stage 7 plan sections 4, 5.3, 6.3-6.7, 7.3-7.5 and Task 6, under specification
sections 8.2, 14.1, 14.7, 14.8, 15.1-15.4 and 15.7. ``WindowsProcessSupervisor`` is the
``ProcessSupervisor`` port's implementation over the five other ports of this package:
every durable write goes through ``InvocationLifecycle`` (the Stage 5 operations behind
it stay the sole writers of invocation and run records), every process action goes
through ``ProcessController`` and the ``LaunchedProcess`` it returns, every byte leaves
a pipe through the bounded readers of this package and reaches the merged Stage 6
parser, framer, stderr fold and output parsers unchanged. The supervisor never calls a
run transition, never decides ``EXITED`` without a reaped exit after both pipes reached
end of stream and the trailing fragment was flushed, never reads a wall clock (the
injected ``Clock`` supplies both instants), never inspects a pid during a live
supervision and never removes a root of an invocation that reached ``RUNNING``.

The loop is one normative order per tick (plan 6.3 steps 0-9): poll once, drain
stdout, drain stderr, then decide in the fixed precedence rejection, drained exit,
cancellation, deadline; a due heartbeat threshold mints once and never decides; a
reaped root whose pipe stays idle has its tree terminated once so end of stream
arrives; the timed wait is bounded by the tick, the remaining deadline and, while a
monitor is armed and not minted and the exit is not reaped, the remaining heartbeat
threshold. Forced tree termination has exactly one owner and fires at most once per
invocation. Every write after the terminal decision is one enrichment (plan 6.6), and
a lost swap is classified by the stored record, never by the failure code (plan 5.3).

The raw attempt token exists here only inside the request envelope the lifecycle
built (whose payload hides it from ``repr``), from which the request bytes, the stderr
fold's token and the parsers' argument are read; no trace fact, detail, message,
dataclass field or record carries it. ``asyncio`` is imported inside ``invoke`` alone
(plan 2.6): the coroutine awaits the decision thread and nothing else here is
asynchronous. The Job Object the controller attaches is a cleanup mechanism and is
never described as a security boundary.

Task-local readings, declared here and in the Task 6 ledger rather than inferred
silently: an ``OSError`` while hashing a present regular executable is refused before
the swap as ``CORE.INVARIANT_VIOLATION`` (an interim the human gate must accept: the
plan's own ``STARTING`` to ``FAILED_TO_START`` path is not constructible because
``ExecutableObservation`` cannot represent a hashless regular file); the heartbeat
term leaves the wait bound once the exit is reaped, because plan 6.2 never mints after
a reap and a due unminted monitor would otherwise contribute zero on every tick; a
describe's single ``STDOUT_BYTES_COUNTED`` entry is emitted at the end of the decision
phase so its fact equals the final count on every describe terminal; only an
end-of-stream marker ends a pipe for the ``EXITED`` decision, while a cancelled read
ends the thread for the close flags; the pipe-holder idle window of a pipe starts at
the reaped exit and restarts on every item dequeued from it; a forced termination on a
``Failure`` path is traced under ``pre_handoff`` for a child that was never owned and
under ``request_defect`` otherwise, and mints no diagnostic because no record is
written.
"""

from __future__ import annotations

import threading
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import PureWindowsPath
from typing import Any, Final

from pydantic import TypeAdapter, ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.adapters.catalog import AdapterCatalogEntry
from crypto_lab.adapters.commands import AdapterCommand, CommandResult, argument_array
from crypto_lab.adapters.diagnostics import (
    ADAPTER_UNAVAILABLE,
    PROCESS_CANCELLED,
    PROCESS_DESCRIBE_TIMED_OUT,
    PROCESS_MISSING_HEARTBEAT,
    PROCESS_RUN_TIMED_OUT,
    PROCESS_START_TIMED_OUT,
    PROCESS_STDERR_TRUNCATED,
    PROCESS_UNRECOGNIZED_PROCESS_EXIT,
    PROCESS_VALIDATE_TIMED_OUT,
    stage6_diagnostic,
)
from crypto_lab.adapters.envelopes import (
    AdapterCommandRequestEnvelope,
    EngineRunRequest,
    request_envelope_bytes,
)
from crypto_lab.adapters.events import (
    EventAcceptanceContext,
    EventAccepted,
    EventRejected,
    EventReplayed,
    HeartbeatPayload,
    InvocationEventLedger,
    parse_protocol_line,
)
from crypto_lab.adapters.limits import (
    MAX_DESCRIPTOR_OUTPUT_BYTES,
    MAX_VALIDATION_RESULT_BYTES,
    PROTOCOL_LIMITS_DEFAULT,
    ProtocolLimits,
)
from crypto_lab.adapters.manifests import (
    ManifestParse,
    ValidationResultParse,
    parse_result_manifest,
    parse_validation_result,
)
from crypto_lab.adapters.negotiation import DescriptorParse, parse_bootstrap_descriptor
from crypto_lab.adapters.sanitization import BoundedStderrCapture, StderrCapture
from crypto_lab.adapters.vocabulary import ProtocolIntegrityStatus
from crypto_lab.domain.command_invocation import (
    CommandInvocationRecord,
    ProcessIdentity,
    ProcessStartFacts,
)
from crypto_lab.domain.descriptors import BoundedText
from crypto_lab.domain.diagnostics import Diagnostic, DiagnosticDetailValue
from crypto_lab.domain.engine_run import EngineRunRecord
from crypto_lab.domain.hashing import attempt_token_hash
from crypto_lab.domain.lifecycle import (
    RECOGNIZED_NATIVE_EXIT_VALUES,
    TERMINAL_COMMAND_INVOCATION_STATES,
    TERMINAL_ENGINE_RUN_STATES,
    CommandInvocationState,
    CommandKind,
)
from crypto_lab.domain.ports import CancellationToken, Clock
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.domain.time import MonotonicInstant
from crypto_lab.process_supervision.deadlines import HeartbeatMonitor, PairedDeadline
from crypto_lab.process_supervision.diagnostics import (
    CORE_IMMUTABLE_INPUT_MISMATCH,
    CORE_INVARIANT_VIOLATION,
    PROCESS_CLEANUP_FAILED,
    PROCESS_FORCED_TERMINATION,
    PROCESS_GRACEFUL_INTERRUPT_UNAVAILABLE,
    PROCESS_JOB_OBJECT_UNAVAILABLE,
    PROCESS_LAUNCH_FAILED,
    PROCESS_WRITE_BOUNDARY_VIOLATION,
    stage7_diagnostic,
    stage7_failure,
)
from crypto_lab.process_supervision.models import (
    DESCRIBE_STDERR_PLACEHOLDER,
    FORCED_TERMINATION_EXIT_CODE,
    PIPE_HOLDER_GRACE_SECONDS,
    POST_TERMINATION_WAIT_SECONDS,
    READER_JOIN_SECONDS,
    TICK_SECONDS,
    CleanupAction,
    CleanupFailure,
    CleanupReport,
    ExecutableObservation,
    InterruptOutcome,
    LaunchFailure,
    LaunchSpecification,
    OutputReadFailure,
    SupervisionOutcome,
    SupervisionTraceEntry,
    SupervisionTraceKind,
    catalog_launch_arguments,
)
from crypto_lab.process_supervision.ports import (
    InvocationLifecycle,
    LaunchedProcess,
    ProcessController,
    SupervisionObserver,
)
from crypto_lab.process_supervision.readers import (
    PipeReader,
    ReaderEnd,
    StdoutFramer,
    drain,
    wait_for_chunk,
)
from crypto_lab.process_supervision.roots import (
    CommandPaths,
    PathPreflight,
    create_command_root,
    observe_executable,
    plan_command_paths,
    preflight_command_paths,
    probe_long_path_support,
    read_output_file,
    remove_command_root,
    snapshot_written_paths,
    write_request_file,
)

__all__ = ["WindowsProcessSupervisor"]

#: Plan 3.5: the ``source_component`` of every diagnostic this module mints.
SOURCE_COMPONENT: Final = "process_supervision.supervisor"
#: Plan 4.1 row 15 and specification 22.2.1: the ``ProcessConfig`` grace range.
MIN_CANCELLATION_GRACE_SECONDS: Final = 0
MAX_CANCELLATION_GRACE_SECONDS: Final = 300
#: Plan 6.4: the kind-specific timeout primary of a ``RUNNING``-origin ``TIMED_OUT``.
_TIMEOUT_CODE: Final[dict[CommandKind, str]] = {
    CommandKind.DESCRIBE: PROCESS_DESCRIBE_TIMED_OUT,
    CommandKind.VALIDATE: PROCESS_VALIDATE_TIMED_OUT,
    CommandKind.RUN: PROCESS_RUN_TIMED_OUT,
}
#: The core-won states whose enrichment may carry the reaped exit pair (plan 6.6).
_PAIR_ADMITTING: Final[frozenset[CommandInvocationState]] = frozenset(
    {
        CommandInvocationState.CANCELLED,
        CommandInvocationState.TIMED_OUT,
        CommandInvocationState.PROTOCOL_FAILED,
    }
)
#: Plan 3.3: the per-event kinds are delivered to the observers and never retained.
_NEVER_RETAINED: Final[frozenset[SupervisionTraceKind]] = frozenset(
    {SupervisionTraceKind.EVENT_ACCEPTED, SupervisionTraceKind.EVENT_REPLAYED}
)
#: The ``reason`` words of ``PROCESS.FORCED_TERMINATION`` this module mints (plan 3.5);
#: a forced termination on a ``Failure`` path is traced only (module docstring).
_MINTED_FORCE_REASONS: Final[frozenset[str]] = frozenset(
    {
        "grace_elapsed",
        "interrupt_unavailable",
        "protocol_failed",
        "pre_handoff",
        "pipe_holder",
        "external_winner",
    }
)
_FORCE_REASON_REQUEST_DEFECT: Final = "request_defect"
#: The exceptions a reader construction or start can raise (plan 3.5 ``open_readers``).
_READER_START_ERRORS: Final = (TypeError, ValueError, RuntimeError, OSError)
_STDOUT: Final = "stdout"
_STDERR: Final = "stderr"
_K: Final = CommandKind
_S: Final = CommandInvocationState
#: ``ProcessIdentity.supervisor_instance_id`` is ``BoundedText``; the constructor
#: applies the same grammar so an over-long id cannot fail after a launch.
_BOUNDED_TEXT: TypeAdapter[str] = TypeAdapter(BoundedText)

type _Facts = dict[str, DiagnosticDetailValue]


def _is_missing(value: object) -> bool:
    return value is MISSING


def _unique(diagnostics: tuple[Diagnostic, ...]) -> tuple[Diagnostic, ...]:
    """First-occurrence unique on identity (the outcome's own rule, plan 3.3)."""
    seen: dict[str, Diagnostic] = {}
    for diagnostic in diagnostics:
        seen.setdefault(diagnostic.diagnostic_id, diagnostic)
    return tuple(seen.values())


def _error_number(error: BaseException) -> int | None:
    if not isinstance(error, OSError):
        return None
    winerror = getattr(error, "winerror", None)
    if isinstance(winerror, int):
        return winerror
    return error.errno if isinstance(error.errno, int) else None


def _reason_parts(failure: CleanupFailure) -> tuple[str, int | None]:
    """A ``CleanupFailure.reason`` of the form ``<word>:<number>``."""
    word, separator, number = failure.reason.partition(":")
    if separator and number.isdigit():
        return word, int(number)
    return failure.reason, None


@dataclass(frozen=True, slots=True)
class _Decision:
    """One terminal decision: the state, its primary (absent for ``EXITED``), the
    additionals that ride the terminal write beside the held ones, and whether the
    child was owned (a ``RUNNING``-origin decision)."""

    state: CommandInvocationState
    primary: Diagnostic | None
    additional: tuple[Diagnostic, ...] = ()
    owned: bool = False


@dataclass(slots=True)
class _Settings:
    """The constructor arguments one supervision reads."""

    lifecycle: InvocationLifecycle
    controller: ProcessController
    clock: Clock
    supervision_root: str
    supervisor_instance_id: str
    cancellation_grace_seconds: int
    describe_limits: ProtocolLimits
    observers: tuple[SupervisionObserver, ...]


@dataclass(slots=True)
class _Readers:
    """The two owned reader threads and their shared stop event (plan 6.7)."""

    stop: threading.Event
    stdout: PipeReader
    stderr: PipeReader

    def of(self, pipe: str) -> PipeReader:
        return self.stdout if pipe == _STDOUT else self.stderr


class WindowsProcessSupervisor:
    """The ``ProcessSupervisor`` implementation (plan Task 6).

    ``cancellation_grace_seconds`` is bounded ``0..300`` (the ``ProcessConfig`` range,
    default the specification's ten); ``describe_limits`` supplies the stderr budget
    of a describe, whose envelope carries no limits; ``preflight`` injects the
    long-path probe result, otherwise the root is probed lazily on the first
    ``invoke`` and the result kept for the instance; ``observers`` receive every
    trace entry on the supervision thread and can never alter a decision.
    """

    def __init__(
        self,
        *,
        lifecycle: InvocationLifecycle,
        controller: ProcessController,
        clock: Clock,
        supervision_root: str,
        supervisor_instance_id: str,
        cancellation_grace_seconds: int = 10,
        describe_limits: ProtocolLimits = PROTOCOL_LIMITS_DEFAULT,
        preflight: PathPreflight | MISSING = MISSING,  # type: ignore[valid-type]
        observers: tuple[SupervisionObserver, ...] = (),
    ) -> None:
        if type(cancellation_grace_seconds) is not int or not (
            MIN_CANCELLATION_GRACE_SECONDS
            <= cancellation_grace_seconds
            <= MAX_CANCELLATION_GRACE_SECONDS
        ):
            raise ValueError(
                "cancellation_grace_seconds must be an integer within "
                f"{MIN_CANCELLATION_GRACE_SECONDS}..{MAX_CANCELLATION_GRACE_SECONDS}"
            )
        if not isinstance(describe_limits, ProtocolLimits):
            raise TypeError("describe_limits must be a ProtocolLimits")
        if type(supervision_root) is not str or not supervision_root:
            raise TypeError("supervision_root must be a non-empty string")
        if type(supervisor_instance_id) is not str or not supervisor_instance_id:
            raise TypeError("supervisor_instance_id must be a non-empty string")
        try:
            _BOUNDED_TEXT.validate_python(supervisor_instance_id)
        except ValidationError as error:
            raise ValueError(
                "supervisor_instance_id must be bounded text (the ProcessIdentity rule)"
            ) from error
        if not isinstance(observers, tuple):
            raise TypeError("observers must be a tuple of observers")
        self._settings = _Settings(
            lifecycle=lifecycle,
            controller=controller,
            clock=clock,
            supervision_root=supervision_root,
            supervisor_instance_id=supervisor_instance_id,
            cancellation_grace_seconds=cancellation_grace_seconds,
            describe_limits=describe_limits,
            observers=observers,
        )
        self._preflight: PathPreflight | None = (
            preflight if isinstance(preflight, PathPreflight) else None
        )
        self._probe_lock = threading.Lock()

    async def invoke(
        self, command: AdapterCommand, cancellation: CancellationToken
    ) -> Result[SupervisionOutcome]:
        """Supervise one command on a decision thread; the token is thread-safe, so
        a caller on the event loop may cancel at any time (plan 6.3)."""
        import asyncio  # plan 2.6: function-local, so the fresh-interpreter probe holds

        return await asyncio.to_thread(self._supervise, command, cancellation)

    def _supervise(
        self, command: AdapterCommand, cancellation: CancellationToken
    ) -> Result[SupervisionOutcome]:
        if not isinstance(command, AdapterCommand):
            raise TypeError("command must be an AdapterCommand")
        if not isinstance(cancellation, CancellationToken):
            raise TypeError("cancellation must implement CancellationToken")
        preflight = self._ensure_preflight()
        if isinstance(preflight, Failure):
            return preflight
        return _Supervision(self._settings, preflight, command, cancellation).execute()

    def _ensure_preflight(self) -> PathPreflight | Failure:
        """Plan 7.2: probe once per instance, lazily, unless a probe was injected."""
        with self._probe_lock:
            if self._preflight is not None:
                return self._preflight
            probed = probe_long_path_support(
                self._settings.supervision_root,
                now=self._settings.clock.now_utc(),
            )
            if isinstance(probed, Failure):
                return probed
            self._preflight = probed.value
            return probed.value


@dataclass(slots=True)
class _Supervision:
    """The state of one ``invoke`` and the steps that move it (plan 6.3)."""

    settings: _Settings
    preflight: PathPreflight
    command: AdapterCommand
    cancellation: CancellationToken
    # -- the record and its correlation --
    record: CommandInvocationRecord | None = None
    running_record: CommandInvocationRecord | None = None
    run: EngineRunRecord | None = None
    # -- the pre-launch facts --
    observation: ExecutableObservation | None = None
    paths: CommandPaths | None = None
    launch_arguments: tuple[str, ...] = ()
    root_attempted: bool = False
    baseline: frozenset[str] | None = None
    #: The envelope is the only holder of the raw token (its payload hides it).
    envelope: AdapterCommandRequestEnvelope | None = field(default=None, repr=False)
    token_hash: str | None = None
    limits: ProtocolLimits | None = None
    capture: BoundedStderrCapture | None = None
    stderr_result: StderrCapture | None = None
    stderr_bytes_fed: int = 0
    truncation: Diagnostic | None = None
    # -- the process --
    launched: LaunchedProcess | None = None
    readers: _Readers | None = None
    deadline: PairedDeadline | None = None
    monitor: HeartbeatMonitor | None = None
    exit_code: int | None = None
    ended: dict[str, bool] = field(
        default_factory=lambda: {_STDOUT: False, _STDERR: False}
    )
    last_item_at: dict[str, MonotonicInstant] = field(default_factory=dict)
    carried: list[bytes | ReaderEnd] = field(default_factory=list)
    forced: bool = False
    exit_reaped_emitted: bool = False
    # -- the protocol --
    framer: StdoutFramer | None = None
    ledger: InvocationEventLedger = field(default_factory=InvocationEventLedger)
    rejection: EventRejected | None = None
    parsing_stopped: bool = False
    flushed: bool = False
    replay_count: int = 0
    stdout_byte_count: int = 0
    output_parse: DescriptorParse | ValidationResultParse | ManifestParse | None = None
    output_unreadable: bool = False
    # -- diagnostics and the trace --
    held: list[Diagnostic] = field(default_factory=list)
    after_terminal: list[Diagnostic] = field(default_factory=list)
    seen: dict[str, Diagnostic] = field(default_factory=dict)
    missing_heartbeat: Diagnostic | None = None
    decision: _Decision | None = None
    reissued: bool = False
    cancellation_observed: bool = False
    winner_emitted: bool = False
    count_emitted: bool = False
    retained: list[SupervisionTraceEntry] = field(default_factory=list)
    sequence: int = 0

    # -- shorthands ---------------------------------------------------------------

    @property
    def lifecycle(self) -> InvocationLifecycle:
        return self.settings.lifecycle

    @property
    def clock(self) -> Clock:
        return self.settings.clock

    @property
    def invocation_id(self) -> str:
        return self.command.invocation_id

    @property
    def kind(self) -> CommandKind:
        return self.command.command_kind

    @property
    def entry(self) -> AdapterCatalogEntry:
        return self.command.catalog_entry

    @property
    def current(self) -> CommandInvocationRecord:
        record = self.record
        if record is None:  # pragma: no cover - a sequencing invariant
            raise ValueError("the record has not been loaded")
        return record

    def _run_ids(self) -> tuple[Any, Any]:
        if self.run is None:
            return MISSING, MISSING
        return self.run.experiment_id, self.run.run_id

    def _token(self) -> str | None:
        """The raw token, read from the envelope's payload at its use sites only."""
        envelope = self.envelope
        if envelope is not None and isinstance(envelope.payload, EngineRunRequest):
            return envelope.payload.attempt_token
        return None

    # -- the trace ------------------------------------------------------------------

    def _emit(
        self,
        kind: SupervisionTraceKind,
        facts: _Facts | None = None,
        *,
        rejection: EventRejected | None = None,
    ) -> None:
        self.sequence += 1
        payload: dict[str, object] = {
            "kind": kind,
            "invocation_id": self.invocation_id,
            "sequence": self.sequence,
            "at_utc": self.clock.now_utc(),
            "monotonic_100ns": round(self.clock.monotonic().seconds * 1e7),
            "facts": dict(facts or {}),
        }
        if rejection is not None:
            payload["rejection"] = rejection
        entry = SupervisionTraceEntry.model_validate(payload)
        if kind not in _NEVER_RETAINED:
            self.retained.append(entry)
        for observer in self.settings.observers:
            with suppress(Exception):  # plan 3.4: an observer never alters a decision
                observer.observe(entry)

    # -- diagnostics ------------------------------------------------------------------

    def _remember(self, diagnostic: Diagnostic) -> Diagnostic:
        self.seen.setdefault(diagnostic.diagnostic_id, diagnostic)
        return diagnostic

    def _mint6(
        self,
        code: str,
        message: str,
        *,
        details: _Facts | None = None,
        causal: tuple[str, ...] = (),
    ) -> Diagnostic:
        experiment_id, run_id = self._run_ids()
        return self._remember(
            stage6_diagnostic(
                code,
                message,
                source_component=SOURCE_COMPONENT,
                timestamp_utc=self.clock.now_utc(),
                experiment_id=experiment_id,
                run_id=run_id,
                invocation_id=self.invocation_id,
                details=details,
                causal_diagnostic_ids=tuple(sorted(set(causal))),
            )
        )

    def _mint7(
        self,
        code: str,
        message: str,
        *,
        details: _Facts | None = None,
        causal: tuple[str, ...] = (),
    ) -> Diagnostic:
        experiment_id, run_id = self._run_ids()
        return self._remember(
            stage7_diagnostic(
                code,
                message,
                source_component=SOURCE_COMPONENT,
                timestamp_utc=self.clock.now_utc(),
                experiment_id=experiment_id,
                run_id=run_id,
                invocation_id=self.invocation_id,
                details=details,
                causal_diagnostic_ids=tuple(sorted(set(causal))),
            )
        )

    def _refuse(
        self, check: str, message: str, details: _Facts | None = None
    ) -> Failure:
        """Plan 4.4: a structural refusal before the swap; nothing is written."""
        experiment_id, run_id = self._run_ids()
        self._emit(
            SupervisionTraceKind.PREFLIGHT_REFUSED,
            {"code": CORE_INVARIANT_VIOLATION, "check": check},
        )
        return stage7_failure(
            CORE_INVARIANT_VIOLATION,
            message,
            source_component=SOURCE_COMPONENT,
            timestamp_utc=self.clock.now_utc(),
            experiment_id=experiment_id,
            run_id=run_id,
            invocation_id=self.invocation_id,
            details={"check": check, **(details or {})},
        )

    def _refused_by(self, failure: Failure) -> Failure:
        codes: list[DiagnosticDetailValue] = [
            diagnostic.error_code for diagnostic in failure.diagnostics
        ]
        self._emit(SupervisionTraceKind.PREFLIGHT_REFUSED, {"codes": codes})
        return failure

    # -- the pre-launch sequence (plan 6.3, 4.4) ---------------------------------------

    def execute(self) -> Result[SupervisionOutcome]:
        refusal = self._load_and_check()
        if refusal is not None:
            return refusal
        observed = self._observe_executable()
        if observed is not None:
            return observed
        if self.cancellation.is_cancellation_requested():
            self._emit(SupervisionTraceKind.PRE_HANDOFF_CANCELLATION)
            return self._decide_and_finish(self._cancelled_decision(owned=False))
        monotonic_at_swap = self.clock.monotonic()
        started = self.lifecycle.begin_start(
            self.invocation_id, expected_revision=self.current.revision
        )
        if isinstance(started, Failure):
            return self._launch_window_failure(started, _S.PENDING)
        self.record = started.value
        self._emit(
            SupervisionTraceKind.STARTING_COMMITTED, {"revision": self.record.revision}
        )
        deadline_utc = self.record.deadline_utc
        if not isinstance(deadline_utc, datetime):  # pragma: no cover - STARTING
            # carries its deadline by the record validator; kept for strict typing.
            raise ValueError("a STARTING record carries deadline_utc")
        self.deadline = PairedDeadline(
            deadline_utc=deadline_utc,
            deadline_monotonic=monotonic_at_swap.plus(self.record.timeout_seconds),
            timeout_seconds=self.record.timeout_seconds,
        )
        observation = self.observation
        if observation is None:  # pragma: no cover - set by _observe_executable
            raise ValueError("the executable was not observed")
        if not observation.verified:
            return self._decide_and_finish(self._executable_decision(observation))
        prepared = self._prepare_request()
        if prepared is not None:
            return self._decide_and_finish(prepared)
        launched = self._launch()
        if isinstance(launched, _Decision):
            return self._decide_and_finish(launched)
        if self.cancellation.is_cancellation_requested():
            self._emit(SupervisionTraceKind.PRE_HANDOFF_CANCELLATION)
            return self._decide_and_finish(self._cancelled_decision(owned=False))
        if self.deadline.passed(self.clock.monotonic()):
            self._emit(SupervisionTraceKind.PRE_HANDOFF_DEADLINE)
            return self._decide_and_finish(self._timeout_decision(owned=False))
        facts = ProcessStartFacts(
            pid_identity=ProcessIdentity(
                pid=launched.pid,
                creation_identity=launched.creation_identity,
                executable_path=self.entry.executable_path,
                executable_hash=self.entry.executable_hash,
                supervisor_instance_id=self.settings.supervisor_instance_id,
            ),
            process_started_at_utc=self.clock.now_utc(),
        )
        running = self.lifecycle.record_process_start(
            self.invocation_id,
            expected_revision=self.current.revision,
            process_start=facts,
        )
        if isinstance(running, Failure):
            return self._launch_window_failure(running, _S.STARTING)
        self.record = running.value
        self.running_record = running.value
        self._emit(
            SupervisionTraceKind.RUNNING_COMMITTED,
            {"revision": self.record.revision, "pid": launched.pid},
        )
        limits = self.limits
        if self.kind is not _K.DESCRIBE and limits is not None:
            self.monitor = HeartbeatMonitor(
                missing_heartbeat_seconds=limits.missing_heartbeat_seconds
            )
            self.monitor.arm(self.clock.monotonic())
        return self._decide_and_finish(self._loop())

    def _load_and_check(self) -> Failure | None:
        loaded = self.lifecycle.load(self.invocation_id)
        if isinstance(loaded, Failure):
            return self._refused_by(loaded)
        record = loaded.value
        self.record = record
        linked = self.lifecycle.linked_run(self.invocation_id)
        if isinstance(linked, Failure):
            return self._refused_by(linked)
        if isinstance(linked.value, EngineRunRecord):
            self.run = linked.value
        if record.state is not _S.PENDING:
            return self._refuse(
                "record_not_pending",
                f"the invocation is {record.state.value}, not PENDING",
            )
        if self.kind is not record.command_kind:
            return self._refuse(
                "command_kind", "the command kind is not the record's command kind"
            )
        if self.command.timeout_seconds != record.timeout_seconds:
            return self._refuse(
                "timeout_seconds", "the command timeout is not the record's timeout"
            )
        if (self.entry.adapter_name, self.entry.adapter_version) != (
            record.adapter_name,
            record.adapter_version,
        ):
            return self._refuse(
                "adapter_identity",
                "the catalog entry is not the record's adapter identity",
            )
        try:
            self.launch_arguments = catalog_launch_arguments(self.entry)
        except ValueError:
            return self._refuse(
                "launch_arguments", "the catalog entry's launch arguments do not decode"
            )
        try:
            paths = plan_command_paths(
                self.settings.supervision_root,
                command_kind=record.command_kind,
                invocation_id=record.invocation_id,
                run_id=record.run_id,
            )
        except ValueError:
            return self._refuse(
                "command_paths", "the command paths cannot be planned for the record"
            )
        if (
            self.command.request_path,
            self.command.output_path,
            self.command.work_dir,
            self.command.result_path,
        ) != (paths.request_path, paths.output_path, paths.work_dir, paths.result_path):
            return self._refuse(
                "command_paths", "the command paths are not the core-selected layout"
            )
        self.paths = paths
        experiment_id, run_id = self._run_ids()
        checked = preflight_command_paths(
            paths,
            self.preflight,
            now=self.clock.now_utc(),
            invocation_id=record.invocation_id,
            run_id=run_id,
            experiment_id=experiment_id,
        )
        if isinstance(checked, Failure):
            return self._refused_by(checked)
        return None

    def _observe_executable(self) -> Failure | None:
        try:
            observation = observe_executable(self.entry, now=self.clock.now_utc())
        except OSError as error:
            # Module docstring: an unreadable regular file is refused before the swap.
            details: _Facts = {"error_class": type(error).__name__}
            number = _error_number(error)
            if number is not None:
                details["os_error_code"] = number
            return self._refuse(
                "executable_unreadable",
                "the registered executable's bytes cannot be read",
                details,
            )
        self.observation = observation
        self._emit(SupervisionTraceKind.PREFLIGHT_ACCEPTED, {"kind": self.kind.value})
        self._emit(
            SupervisionTraceKind.EXECUTABLE_OBSERVED,
            {
                "present": observation.present,
                "regular_file": observation.regular_file,
                "reparse_point": observation.reparse_point,
                "ancestor_reparse_point": observation.ancestor_reparse_point,
                "verified": observation.verified,
            },
        )
        return None

    def _executable_decision(self, observation: ExecutableObservation) -> _Decision:
        """Plan 4.1 row 1 and reading 3: absent is unavailability, present but
        unverifiable is an immutable-input mismatch."""
        if not observation.present:
            primary = self._mint6(
                ADAPTER_UNAVAILABLE,
                "the registered executable is absent",
                details={"reason": "executable_absent"},
            )
            return _Decision(_S.FAILED_TO_START, primary)
        details: _Facts = {"expected_hash": observation.expected_hash}
        if observation.reparse_point:
            details["reason"] = "reparse_point"
        elif observation.ancestor_reparse_point:
            details["reason"] = "ancestor_reparse_point"
        elif not observation.regular_file:
            details["reason"] = "not_regular_file"
        else:
            details["reason"] = "hash_mismatch"
            observed = observation.observed_hash
            if isinstance(observed, str):
                details["observed_hash"] = observed
        primary = self._mint7(
            CORE_IMMUTABLE_INPUT_MISMATCH,
            "the registered executable's identity cannot be verified",
            details=details,
        )
        return _Decision(_S.FAILED_TO_START, primary)

    def _prepare_request(self) -> _Decision | None:
        """Plan 4.3, 7.3: the envelope, its agreement, the root and the request file."""
        record = self.current
        paths = self.paths
        if paths is None:  # pragma: no cover - set by _load_and_check
            raise ValueError("the command paths were not planned")
        built = self.lifecycle.request_envelope(self.invocation_id)
        if isinstance(built, Failure):
            primary = self._mint7(
                CORE_INVARIANT_VIOLATION,
                "the lifecycle could not build the request envelope",
                details={"check": "request_envelope"},
            )
            recorded = tuple(self._remember(d) for d in built.diagnostics)
            return _Decision(_S.FAILED_TO_START, primary, additional=recorded)
        envelope = built.value
        if not self._envelope_agrees(envelope, record, paths):
            primary = self._mint7(
                CORE_INVARIANT_VIOLATION,
                "the request envelope disagrees with the STARTING record",
                details={"check": "envelope_agreement"},
            )
            return _Decision(_S.FAILED_TO_START, primary)
        self.envelope = envelope
        payload = envelope.payload
        if isinstance(payload, EngineRunRequest):
            self.token_hash = attempt_token_hash(payload.attempt_token)
            self.limits = payload.configuration_snapshot.limits
        else:
            self.limits = self.settings.describe_limits
        self.root_attempted = True
        try:
            create_command_root(paths)
        except FileExistsError:
            primary = self._mint7(
                CORE_INVARIANT_VIOLATION,
                "a command root already exists for a fresh invocation",
                details={"check": "command_root_exists"},
            )
            return _Decision(_S.FAILED_TO_START, primary)
        except OSError as error:
            return _Decision(
                _S.FAILED_TO_START, self._launch_failed("create_root", error)
            )
        try:
            write_request_file(paths.request_path, request_envelope_bytes(envelope))
        except OSError as error:
            return _Decision(
                _S.FAILED_TO_START, self._launch_failed("write_request", error)
            )
        token = self._token()
        self.capture = BoundedStderrCapture(
            limit=self.limits.max_stderr_bytes,
            token=DESCRIBE_STDERR_PLACEHOLDER if token is None else token,
        )
        self._emit(SupervisionTraceKind.REQUEST_WRITTEN)
        self.baseline = self._snapshot(paths.command_root)
        return None

    @staticmethod
    def _snapshot(command_root: str) -> frozenset[str] | None:
        """The write-boundary snapshot; a walk that fails never escapes ``invoke``.

        ``None`` marks a walk that failed: a boundary that could not be measured is
        not reported as a violation (neither side may invent strays).
        """
        try:
            return snapshot_written_paths(command_root)
        except OSError:
            return None

    def _envelope_agrees(
        self,
        envelope: AdapterCommandRequestEnvelope,
        record: CommandInvocationRecord,
        paths: CommandPaths,
    ) -> bool:
        if (
            envelope.invocation_id != record.invocation_id
            or envelope.command is not record.command_kind
            or envelope.timeout_seconds != record.timeout_seconds
            or envelope.created_at_utc != record.launch_attempted_at_utc
            or envelope.deadline_utc != record.deadline_utc
        ):
            return False
        payload = envelope.payload
        if isinstance(payload, EngineRunRequest) and isinstance(paths.work_dir, str):
            relative = payload.assigned_work_dir.relative_path.split("/")
            expected = PureWindowsPath(paths.command_root).joinpath(*relative)
            return PureWindowsPath(paths.work_dir) == expected
        return True

    def _launch_failed(self, stage: str, error: BaseException) -> Diagnostic:
        details: _Facts = {"stage": stage, "error_class": type(error).__name__}
        number = _error_number(error)
        if number is not None:
            details["os_error_code"] = number
        return self._mint7(
            PROCESS_LAUNCH_FAILED,
            "the launch failed before the process was owned",
            details=details,
        )

    def _launch(self) -> LaunchedProcess | _Decision:
        """Plan 6.3: launch through the controller, start the readers at once."""
        paths = self.paths
        limits = self.limits
        if paths is None or limits is None:  # pragma: no cover - set earlier
            raise ValueError("the launch inputs are not prepared")
        specification = LaunchSpecification(
            invocation_id=self.invocation_id,
            argv=(
                self.entry.executable_path,
                *self.launch_arguments,
                *argument_array(self.command),
            ),
            cwd=paths.command_root,
        )
        launched = self.settings.controller.launch(specification)
        if isinstance(launched, LaunchFailure):
            facts: _Facts = {"stage": launched.stage, "not_found": launched.not_found}
            details: _Facts = {}
            if isinstance(launched.os_error_code, int):
                facts["os_error_code"] = launched.os_error_code
                details["os_error_code"] = launched.os_error_code
            self._emit(SupervisionTraceKind.LAUNCH_FAILED, facts)
            if launched.not_found:
                primary = self._mint6(
                    ADAPTER_UNAVAILABLE,
                    "process creation could not find the registered executable",
                    details={"reason": "create_process_not_found", **details},
                )
            else:
                primary = self._mint7(
                    PROCESS_LAUNCH_FAILED,
                    "process creation failed",
                    details={
                        "stage": launched.stage,
                        **details,
                        "error_class": launched.error_class,
                    },
                )
            return _Decision(_S.FAILED_TO_START, primary)
        self.launched = launched
        stop = threading.Event()
        try:
            readers = _Readers(
                stop=stop,
                stdout=PipeReader(launched.stdout, stop=stop),
                stderr=PipeReader(launched.stderr, stop=stop),
            )
            self.readers = readers
            if self.kind is not _K.DESCRIBE:
                self.framer = StdoutFramer(max_event_bytes=limits.max_event_bytes)
            readers.stdout.start()
            readers.stderr.start()
        except _READER_START_ERRORS as error:
            # Plan 3.5 stage ``open_readers``: the child exists but was never owned.
            self._emit(
                SupervisionTraceKind.LAUNCH_FAILED,
                {"stage": "open_readers", "not_found": False},
            )
            self._force("pre_handoff")
            return _Decision(
                _S.FAILED_TO_START, self._launch_failed("open_readers", error)
            )
        if not launched.job_available:
            job_details: _Facts = {"fallback": "toolhelp_descendants"}
            if isinstance(launched.job_error_code, int):
                job_details["os_error_code"] = launched.job_error_code
            self.held.append(
                self._mint7(
                    PROCESS_JOB_OBJECT_UNAVAILABLE,
                    "the child could not be assigned to the supervisor's Job Object",
                    details=job_details,
                )
            )
        launch_facts: _Facts = {
            "pid": launched.pid,
            "job_available": launched.job_available,
        }
        if isinstance(launched.image_path, str):
            launch_facts["image_path"] = launched.image_path
        self._emit(SupervisionTraceKind.LAUNCHED, launch_facts)
        return launched

    # -- the loop (plan 6.3 steps 0-9) ------------------------------------------------

    def _loop(self) -> _Decision:
        deadline = self.deadline
        if deadline is None:  # pragma: no cover - set after begin_start
            raise ValueError("the deadline is not paired")
        while True:
            self._poll()
            failed = self._drain_stdout()
            if failed is not None:
                return failed
            self._drain_stderr()
            if self.rejection is not None:
                return _Decision(
                    _S.PROTOCOL_FAILED,
                    self._remember(self.rejection.diagnostic),
                    owned=True,
                )
            if self._exit_complete():
                return _Decision(_S.EXITED, None, owned=True)
            if self.cancellation.is_cancellation_requested():
                if not self.cancellation_observed:
                    self.cancellation_observed = True
                    self._emit(SupervisionTraceKind.CANCELLATION_OBSERVED)
                return self._cancelled_decision(owned=True)
            now = self.clock.monotonic()
            if deadline.passed(now):
                return self._timeout_decision(owned=True)
            self._check_heartbeat(now)
            self._check_pipe_holder(now)
            self._wait(self._wait_bound(now))

    def _poll(self) -> None:
        """Step 0: one ``wait(0.0)`` every tick; the first reaped code is kept."""
        launched = self.launched
        if launched is None:
            return
        code = launched.wait(0.0)
        if code is not None and self.exit_code is None:
            self.exit_code = code
            reaped_at = self.clock.monotonic()
            for pipe in (_STDOUT, _STDERR):
                if not self.ended[pipe]:
                    self.last_item_at[pipe] = reaped_at

    def _note_item(self, pipe: str) -> None:
        self.last_item_at[pipe] = self.clock.monotonic()

    def _marker_of(self, reader: PipeReader) -> ReaderEnd:
        """The marker a reader enqueued (``ended_by`` is set before the put)."""
        ended_by = reader.ended_by
        return ReaderEnd.EOF if ended_by is None else ended_by

    def _drain_stdout(self) -> _Decision | None:
        """Step 1: everything queued (and the item the last wait returned)."""
        readers = self.readers
        if readers is None:
            return None
        items: list[bytes | ReaderEnd] = list(self.carried)
        self.carried = []
        chunks, ended = drain(readers.stdout.queue)
        items.extend(chunks)
        if ended:
            items.append(self._marker_of(readers.stdout))
        if items:
            self._note_item(_STDOUT)
        for item in items:
            if isinstance(item, ReaderEnd):
                # Only end of stream ends the pipe for the EXITED decision; a
                # cancelled read ends the thread and is reported at cleanup.
                if item is ReaderEnd.EOF:
                    self.ended[_STDOUT] = True
                continue
            failed = self._feed_stdout(item)
            if failed is not None:
                return failed
        if (
            self.ended[_STDOUT]
            and not self.flushed
            and self.framer is not None
            and self.running_record is not None
            and self.rejection is None
            and not self.parsing_stopped
        ):
            self.flushed = True
            fragment = self.framer.flush()
            if fragment:
                return self._parse_line(fragment)
        return None

    def _feed_stdout(self, chunk: bytes) -> _Decision | None:
        if self.framer is None:
            self.stdout_byte_count += len(chunk)  # plan 2.5 reading 14: counted only
            return None
        if self.running_record is None:
            # A child that never reached RUNNING (a pre-handoff terminal, a lost
            # handoff swap): the parser is defined for the RUNNING record only, so
            # its bytes are drained and discarded, never parsed or counted.
            return None
        if self.rejection is not None or self.parsing_stopped:
            return None
        for line in self.framer.feed(chunk):
            failed = self._parse_line(line)
            if failed is not None:
                return failed
            if self.rejection is not None or self.parsing_stopped:
                break
        return None

    def _parse_line(self, line: bytes) -> _Decision | None:
        running = self.running_record
        token_hash = self.token_hash
        limits = self.limits
        # The parser is defined for the RUNNING record of a linked kind only; the
        # drains discard bytes before the handoff, so this guard is unreachable.
        if running is None or token_hash is None or limits is None:  # pragma: no cover
            raise ValueError("stdout is parsed only for a RUNNING linked invocation")
        outcome = parse_protocol_line(
            line,
            acceptance=EventAcceptanceContext(
                invocation=running,
                attempt_token_hash=token_hash,
                max_event_bytes=limits.max_event_bytes,
                ledger=self.ledger,
                clock=self.clock,
            ),
        )
        if isinstance(outcome, EventAccepted):
            successor = self.ledger.accept(outcome)
            appended = self.lifecycle.append_event(outcome.event)
            if isinstance(appended, Failure):
                recorded = tuple(self._remember(d) for d in appended.diagnostics)
                if self.decision is None:
                    # Plan 2.5 reading 8: an orchestrator cancellation.
                    primary = self._mint6(
                        PROCESS_CANCELLED,
                        "the event log could not be written while the child ran",
                        causal=tuple(d.diagnostic_id for d in recorded),
                    )
                    return _Decision(
                        _S.CANCELLED, primary, additional=recorded, owned=True
                    )
                self.after_terminal.extend(recorded)
                self.parsing_stopped = True
                return None
            self.ledger = successor
            event = outcome.event
            self._emit(
                SupervisionTraceKind.EVENT_ACCEPTED,
                {"sequence": event.sequence, "event_type": event.event_type.value},
            )
            if isinstance(event.payload, HeartbeatPayload) and self.monitor is not None:
                self.monitor.reset(self.clock.monotonic())
            return None
        if isinstance(outcome, EventReplayed):
            self.replay_count += 1
            self._emit(
                SupervisionTraceKind.EVENT_REPLAYED,
                {"sequence": outcome.event.sequence},
            )
            return None
        self._remember(outcome.diagnostic)
        if self.decision is None:
            self.rejection = outcome
        else:
            self.after_terminal.append(outcome.diagnostic)
            self.parsing_stopped = True
        self._emit(
            SupervisionTraceKind.EVENT_REJECTED,
            {"code": outcome.diagnostic.error_code},
            rejection=outcome,
        )
        return None

    def _drain_stderr(self) -> None:
        """Step 2: every stderr chunk into the bounded fold."""
        readers = self.readers
        if readers is None or self.capture is None:
            return
        chunks, ended = drain(readers.stderr.queue)
        if chunks or ended:
            self._note_item(_STDERR)
        for chunk in chunks:
            self.capture.feed(chunk)
            self.stderr_bytes_fed += len(chunk)
        if ended and self._marker_of(readers.stderr) is ReaderEnd.EOF:
            self.ended[_STDERR] = True

    def _pipes_ended(self) -> bool:
        return self.readers is None or (self.ended[_STDOUT] and self.ended[_STDERR])

    def _exit_complete(self) -> bool:
        """Step 4: a reaped exit, both pipes at end of stream, the fragment flushed."""
        return (
            self.exit_code is not None
            and self.readers is not None
            and self.ended[_STDOUT]
            and self.ended[_STDERR]
            and (self.framer is None or self.flushed)
        )

    def _check_heartbeat(self, now: MonotonicInstant) -> None:
        """Step 7 and plan 6.2: mint once; a reaped exit hands the miss to the exit."""
        monitor = self.monitor
        if monitor is None or monitor.minted or self.exit_code is not None:
            return
        if not monitor.due(now):
            return
        monitor.minted = True
        self.missing_heartbeat = self._mint6(
            PROCESS_MISSING_HEARTBEAT,
            "no heartbeat arrived within the missing-heartbeat threshold",
        )
        self.held.append(self.missing_heartbeat)
        self._emit(
            SupervisionTraceKind.HEARTBEAT_MISSED, {"code": PROCESS_MISSING_HEARTBEAT}
        )

    def _check_pipe_holder(self, now: MonotonicInstant) -> None:
        """Step 8: a reaped root whose pipe stays idle without EOF has a holder."""
        if self.exit_code is None or self.forced or self.readers is None:
            return
        for pipe in (_STDOUT, _STDERR):
            if self.ended[pipe]:
                continue
            marked = self.last_item_at.get(pipe)
            if marked is not None and marked.until(now) >= PIPE_HOLDER_GRACE_SECONDS:
                self._force("pipe_holder")
                return

    def _wait_bound(self, now: MonotonicInstant) -> float:
        """Step 9: the single bound rule (module docstring for the exit clause)."""
        deadline = self.deadline
        if deadline is None:  # pragma: no cover - the loop runs after begin_start
            raise ValueError("the deadline is not paired")
        bound = min(TICK_SECONDS, deadline.remaining(now))
        monitor = self.monitor
        if monitor is not None and not monitor.minted and self.exit_code is None:
            bound = min(bound, monitor.remaining(now))
        return bound

    def _wait(self, bound: float) -> None:
        readers = self.readers
        if readers is None:
            return
        item = wait_for_chunk(readers.stdout.queue, bound)
        if item is not None:
            self.carried.append(item)

    # -- the decision and the terminal write ------------------------------------------

    def _cancelled_decision(self, *, owned: bool) -> _Decision:
        return _Decision(
            _S.CANCELLED,
            self._mint6(PROCESS_CANCELLED, "cancellation was requested"),
            owned=owned,
        )

    def _timeout_decision(self, *, owned: bool) -> _Decision:
        code = _TIMEOUT_CODE[self.kind]
        if not owned and self.kind is _K.RUN:
            code = PROCESS_START_TIMED_OUT
        causal = (
            ()
            if self.missing_heartbeat is None
            else (self.missing_heartbeat.diagnostic_id,)
        )
        return _Decision(
            _S.TIMED_OUT,
            self._mint6(code, "the command deadline passed", causal=causal),
            owned=owned,
        )

    def _decide_and_finish(self, decision: _Decision) -> Result[SupervisionOutcome]:
        self.decision = decision
        facts: _Facts = {"state": decision.state.value}
        if decision.primary is not None:
            facts["code"] = decision.primary.error_code
        self._emit(SupervisionTraceKind.TERMINAL_DECIDED, facts)
        written = self._terminal_write(decision)
        if isinstance(written, Failure | Success):
            return written
        self.record = written
        self._emit(
            SupervisionTraceKind.TERMINAL_COMMITTED,
            {"state": written.state.value, "revision": written.revision},
        )
        self._terminate_phase(decision)
        self._post_decision_drain()
        self._emit_describe_count()
        self._read_output()
        self._emit_exit_reaped()
        self._snapshot_strays()
        report = self._cleanup(remove_root=self.running_record is None)
        return self._enrich_and_build(report)

    def _terminal_additionals(self, decision: _Decision) -> tuple[Diagnostic, ...]:
        """Plan 6.6 step 1: every additional known at the terminal write."""
        additional = [*self.held, *decision.additional]
        if decision.state is _S.EXITED:
            # Both pipes ended, so the fold is finished here (once; a re-issued
            # write reuses the result) and its truncation flag is known.
            self._finish_stderr(mint=False)
            if self.stderr_result is not None and self.stderr_result.truncated:
                additional.append(self._stderr_truncated())
        elif (
            self.limits is not None
            and self.capture is not None
            and self.stderr_bytes_fed > self.limits.max_stderr_bytes
        ):
            additional.append(self._stderr_truncated())
        return _unique(tuple(additional))

    def _stderr_truncated(self) -> Diagnostic:
        """The one ``PROCESS.STDERR_TRUNCATED`` of the invocation, minted once.

        It is held like the Job Object diagnostic: it rides the terminal write and,
        when that write was not ours (an external winner), the enrichment, where the
        lifecycle filters an identifier already on the record (plan 6.6).
        """
        if self.truncation is None:
            self.truncation = self._mint6(
                PROCESS_STDERR_TRUNCATED,
                "stderr exceeded the snapshot's max_stderr_bytes and was truncated",
            )
            self.held.append(self.truncation)
        return self.truncation

    def _finish_stderr(self, *, mint: bool = True) -> None:
        """Finish the fold once; a truncation first seen here is minted and held."""
        if self.capture is None or self.stderr_result is not None:
            return
        self.stderr_result = self.capture.finish()
        if mint and self.stderr_result.truncated:
            self._stderr_truncated()

    def _record_terminal(
        self, decision: _Decision, expected_revision: int
    ) -> Result[CommandInvocationRecord]:
        additional = self._terminal_additionals(decision)
        if decision.state is _S.EXITED:
            code = self.exit_code
            if code is None:  # pragma: no cover - EXITED follows a reaped exit
                raise ValueError("EXITED needs the reaped exit value")
            primary: Any = MISSING
            if code not in RECOGNIZED_NATIVE_EXIT_VALUES:
                primary = self._mint6(
                    PROCESS_UNRECOGNIZED_PROCESS_EXIT,
                    "the child exited with an unrecognized native value",
                    details={"native_exit_value": code},
                )
            return self.lifecycle.record_terminal(
                self.invocation_id,
                expected_revision=expected_revision,
                target_state=_S.EXITED,
                primary=primary,
                additional=additional,
                native_exit_value=code,
            )
        if decision.primary is None:  # pragma: no cover - a core-won state has one
            raise ValueError("a core-won terminal needs a primary diagnostic")
        return self.lifecycle.record_terminal(
            self.invocation_id,
            expected_revision=expected_revision,
            target_state=decision.state,
            primary=decision.primary,
            additional=additional,
            native_exit_value=MISSING,
        )

    def _terminal_write(
        self, decision: _Decision
    ) -> CommandInvocationRecord | Result[SupervisionOutcome]:
        """Plan 5.3: the terminal transition and the classification of a refusal."""
        expected = self.current.revision
        expected_state = self.current.state
        written = self._record_terminal(decision, expected)
        if isinstance(written, Success):
            return written.value
        failure = written
        reload = self.lifecycle.load(self.invocation_id)
        if isinstance(reload, Failure):
            return self._abandon(failure)
        stored = reload.value
        if stored.state in TERMINAL_COMMAND_INVOCATION_STATES:
            return self._external_winner(stored)
        if (
            stored.state is expected_state
            and stored.revision == expected
            and not self.reissued
            and self.run is not None
            and self._run_now_terminal()
        ):
            # The narrow run-moved race: one re-issue on the alone path.
            self.reissued = True
            again = self._record_terminal(decision, expected)
            if isinstance(again, Success):
                return again.value
        return self._abandon(failure)

    def _run_now_terminal(self) -> bool:
        linked = self.lifecycle.linked_run(self.invocation_id)
        return (
            isinstance(linked, Success)
            and isinstance(linked.value, EngineRunRecord)
            and linked.value.state in TERMINAL_ENGINE_RUN_STATES
        )

    def _launch_window_failure(
        self, failure: Failure, expected_state: CommandInvocationState
    ) -> Result[SupervisionOutcome]:
        """Plan 5.3 rows 1-4 after ``begin_start`` or ``record_process_start``."""
        expected = self.current.revision
        reload = self.lifecycle.load(self.invocation_id)
        if isinstance(reload, Failure):
            return self._abandon(failure)
        stored = reload.value
        if stored.state in TERMINAL_COMMAND_INVOCATION_STATES:
            return self._external_winner(stored)
        if stored.state is expected_state and stored.revision == expected:
            primary = self._mint6(
                PROCESS_CANCELLED, "an external winner cancelled the launch"
            )
            resolved = self.lifecycle.resolve_external_winner(
                self.invocation_id, expected_revision=expected, primary=primary
            )
            if isinstance(resolved, Success) and isinstance(
                resolved.value, CommandInvocationRecord
            ):
                self.record = resolved.value
                self._emit_winner(resolved.value)
                if self.launched is not None:
                    self._force("external_winner")
                    self._post_decision_drain()
                self._emit_describe_count()
                if self.launched is not None:
                    self._emit_exit_reaped()
                    self._snapshot_strays()
                report = self._cleanup(remove_root=True)
                return self._enrich_and_build(report)
        return self._abandon(failure)

    def _external_winner(
        self, stored: CommandInvocationRecord
    ) -> Result[SupervisionOutcome]:
        """Plan 5.3 row 1: the stored terminal is returned, never overwritten."""
        self.record = stored
        self._emit_winner(stored)
        if self.launched is None and not self.root_attempted:
            # The PENDING-origin winner: nothing was launched or written.
            self._emit_describe_count()
            return Success[SupervisionOutcome](outcome="SUCCESS", value=self._outcome())
        if self.launched is not None:
            self._force("external_winner")
            self._post_decision_drain()
        self._emit_describe_count()
        self._emit_exit_reaped()
        self._snapshot_strays()
        report = self._cleanup(remove_root=self.running_record is None)
        return self._enrich_and_build(report)

    def _emit_winner(self, stored: CommandInvocationRecord) -> None:
        if self.winner_emitted:
            return
        self.winner_emitted = True
        self._emit(
            SupervisionTraceKind.EXTERNAL_TERMINAL_WINNER, {"state": stored.state.value}
        )

    def _emit_describe_count(self) -> None:
        """Plan 3.3: exactly one entry per describe terminal, with the final count."""
        if self.kind is not _K.DESCRIBE or self.count_emitted:
            return
        self.count_emitted = True
        self._emit(
            SupervisionTraceKind.STDOUT_BYTES_COUNTED,
            {"stdout_byte_count": self.stdout_byte_count},
        )

    def _abandon(self, failure: Failure) -> Failure:
        """Plan 5.3 rows 3-4: an own-request defect or another actor's write; the
        record is left for reconciliation and the original ``Failure`` returned."""
        never_owned = self.running_record is None
        if self.launched is not None:
            self._force("pre_handoff" if never_owned else _FORCE_REASON_REQUEST_DEFECT)
            self._post_decision_drain()
            self._cleanup(remove_root=never_owned)
        elif self.root_attempted:
            self._cleanup(remove_root=True)
        return failure

    # -- termination (plan 6.5) -----------------------------------------------------

    def _force(self, reason: str) -> None:
        """The once-only owner of forced tree termination (plan 6.3 step 8).

        A termination before the decision (the pipe holder) is known at the terminal
        write and rides it; one after ``TERMINAL_COMMITTED`` rides the enrichment.
        """
        launched = self.launched
        if launched is None or self.forced:
            return
        self.forced = True
        report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
        facts: _Facts = {
            "reason": reason,
            "exit_code": FORCED_TERMINATION_EXIT_CODE,
            "descendants_terminated": len(report.descendants),
            "job_object": report.job_terminated,
            "termination_failures": len(report.failures),
        }
        self._emit(SupervisionTraceKind.FORCED_TERMINATION, facts)
        if reason not in _MINTED_FORCE_REASONS:
            return
        diagnostic = self._mint7(
            PROCESS_FORCED_TERMINATION,
            "the process tree was terminated",
            details={
                "reason": reason,
                "exit_code": FORCED_TERMINATION_EXIT_CODE,
                "descendants_terminated": len(report.descendants),
                "job_object": report.job_terminated,
            },
        )
        if self.decision is None:
            self.held.append(diagnostic)
        else:
            self.after_terminal.append(diagnostic)

    def _terminate_phase(self, decision: _Decision) -> None:
        launched = self.launched
        if launched is None or decision.state in (_S.EXITED, _S.FAILED_TO_START):
            return
        if not decision.owned:
            self._force("pre_handoff")
            return
        if decision.state is _S.PROTOCOL_FAILED:
            self._force("protocol_failed")
            return
        outcome = launched.interrupt()
        if outcome is InterruptOutcome.PROCESS_GONE:
            self._force("pipe_holder")
            return
        if outcome is InterruptOutcome.DELIVERED:
            self._emit(SupervisionTraceKind.INTERRUPT_SENT)
            expiry_reason = "grace_elapsed"
        else:
            self._emit(SupervisionTraceKind.INTERRUPT_UNAVAILABLE)
            self.after_terminal.append(
                self._mint7(
                    PROCESS_GRACEFUL_INTERRUPT_UNAVAILABLE,
                    "the graceful interrupt could not be delivered",
                )
            )
            expiry_reason = "interrupt_unavailable"
        grace_end = self.clock.monotonic().plus(
            self.settings.cancellation_grace_seconds
        )
        while True:
            self._poll()
            self._drain_stdout()
            self._drain_stderr()
            if self.exit_code is not None:
                return  # the pipe-holder rule takes over in the post-decision drain
            now = self.clock.monotonic()
            remaining = now.until(grace_end)
            if remaining <= 0.0:
                self._force(expiry_reason)
                return
            self._wait(min(TICK_SECONDS, remaining))

    def _post_decision_drain(self) -> None:
        """Plan 6.3, 6.5: drain both pipes until the exit and both EOFs or the bound."""
        if self.launched is None:
            return
        end = self.clock.monotonic().plus(POST_TERMINATION_WAIT_SECONDS)
        while True:
            self._poll()
            self._drain_stdout()
            self._drain_stderr()
            if self.exit_code is not None and self._pipes_ended():
                return
            now = self.clock.monotonic()
            remaining = now.until(end)
            if remaining <= 0.0:
                return
            self._check_pipe_holder(now)
            self._wait(min(TICK_SECONDS, remaining))

    # -- the epilogue: output, boundary, cleanup, enrichment ------------------------

    def _read_output(self) -> None:
        """Plan 7.4: only for ``EXITED``; at most ceiling + 1 bytes."""
        decision = self.decision
        paths = self.paths
        limits = self.limits
        if (
            decision is None
            or decision.state is not _S.EXITED
            or paths is None
            or limits is None
        ):
            return
        if self.kind is _K.RUN:
            path = paths.result_path
            ceiling = limits.max_manifest_bytes
        else:
            path = paths.output_path
            ceiling = (
                MAX_DESCRIPTOR_OUTPUT_BYTES
                if self.kind is _K.DESCRIBE
                else MAX_VALIDATION_RESULT_BYTES
            )
        if not isinstance(path, str):  # pragma: no cover - the layout guarantees it
            return
        data = read_output_file(path, ceiling=ceiling)
        if isinstance(data, OutputReadFailure):
            self.output_unreadable = True
            return
        if not isinstance(data, bytes):
            return
        if self.kind is _K.DESCRIBE:
            self.output_parse = parse_bootstrap_descriptor(data, max_bytes=ceiling)
            return
        token = self._token()
        if token is None:  # pragma: no cover - a linked kind carries the token
            return
        if self.kind is _K.VALIDATE:
            self.output_parse = parse_validation_result(
                data, max_bytes=ceiling, token=token
            )
        else:
            self.output_parse = parse_result_manifest(
                data, max_bytes=ceiling, token=token
            )

    def _emit_exit_reaped(self) -> None:
        if self.exit_code is None or self.exit_reaped_emitted:
            return
        self.exit_reaped_emitted = True
        facts: _Facts = {"native_exit_value": self.exit_code}
        decision = self.decision
        if decision is not None and decision.state is _S.EXITED:
            facts["output_unreadable"] = self.output_unreadable
        self._emit(SupervisionTraceKind.EXIT_REAPED, facts)

    def _permitted_paths(self, paths: CommandPaths) -> tuple[frozenset[str], str]:
        """Plan 7.3: the permitted set per kind, derived from the planned paths."""
        root = PureWindowsPath(paths.command_root)
        if isinstance(paths.work_dir, str):
            prefix = PureWindowsPath(paths.work_dir).relative_to(root).as_posix() + "/"
            return frozenset(), prefix
        if isinstance(paths.output_path, str):
            output = PureWindowsPath(paths.output_path).relative_to(root).as_posix()
            return frozenset({output}), ""
        return frozenset(), ""  # pragma: no cover - excluded by the layout validator

    def _snapshot_strays(self) -> None:
        """Plan 7.3: the post-exit snapshot difference outside the permitted paths."""
        paths = self.paths
        if self.launched is None or paths is None or not self.root_attempted:
            return
        after = self._snapshot(paths.command_root)
        if after is None or self.baseline is None:
            return
        written = after - self.baseline
        permitted, prefix = self._permitted_paths(paths)
        strays = frozenset(
            path
            for path in written
            if path not in permitted and not (prefix and path.startswith(prefix))
        )
        if not strays:
            return
        self._emit(
            SupervisionTraceKind.WRITE_BOUNDARY_VIOLATION,
            {"stray_path_count": len(strays)},
        )
        self.after_terminal.append(
            self._mint7(
                PROCESS_WRITE_BOUNDARY_VIOLATION,
                "the child wrote outside its permitted paths",
                details={"stray_path_count": len(strays)},
            )
        )

    def _stop_reader(
        self, reader: PipeReader, launched: LaunchedProcess
    ) -> tuple[bool, str]:
        """Plan 6.7: stop, join, cancel a blocked read, join again."""
        if reader.ident is None:
            return True, "STOPPED"  # never started: nothing blocks
        reader.join(READER_JOIN_SECONDS)
        if reader.is_alive():
            native_thread_id = reader.native_thread_id
            if isinstance(native_thread_id, int):
                launched.cancel_read(native_thread_id)
            reader.join(READER_JOIN_SECONDS)
        if reader.is_alive():
            return False, "ALIVE"
        ended_by = reader.ended_by
        return True, "STOPPED" if ended_by is None else ended_by.value

    def _cleanup(self, *, remove_root: bool) -> CleanupReport:
        """Plan 8.4 and 6.7: one owner; no failure skips a later action."""
        completed: list[CleanupAction] = []
        failures: list[CleanupFailure] = []
        ended_by: dict[CleanupAction, str] = {}
        launched = self.launched
        if launched is not None:
            flags = {_STDOUT: True, _STDERR: True}
            readers = self.readers
            if readers is not None:
                readers.stop.set()
                for pipe, action in (
                    (_STDOUT, CleanupAction.STDOUT_READER_STOPPED),
                    (_STDERR, CleanupAction.STDERR_READER_STOPPED),
                ):
                    stopped, how = self._stop_reader(readers.of(pipe), launched)
                    flags[pipe] = stopped
                    if stopped:
                        completed.append(action)
                        ended_by[action] = how
                    else:
                        failures.append(
                            CleanupFailure(action=action, reason="reader_alive:0")
                        )
            closed = launched.close(
                close_stdout=flags[_STDOUT], close_stderr=flags[_STDERR]
            )
            completed.extend(closed.completed)
            failures.extend(closed.failures)
        if remove_root and self.root_attempted and self.paths is not None:
            removal = remove_command_root(self.paths.command_root)
            completed.extend(removal.completed)
            failures.extend(removal.failures)
        for action in completed:
            facts: _Facts = {"action": action.value}
            if action in ended_by:
                facts["ended_by"] = ended_by[action]
            self._emit(SupervisionTraceKind.CLEANUP_ACTION, facts)
        for failure in failures:
            self._emit(
                SupervisionTraceKind.CLEANUP_FAILED,
                {"action": failure.action.value, "reason": failure.reason},
            )
            word, number = _reason_parts(failure)
            details: _Facts = {
                "cleanup_action": failure.action.value,
                "error_class": word,
            }
            if number is not None:
                details["os_error_code"] = number
            self.after_terminal.append(
                self._mint7(
                    PROCESS_CLEANUP_FAILED, "a cleanup action failed", details=details
                )
            )
        return CleanupReport(completed=tuple(completed), failures=tuple(failures))

    def _enrich_and_build(self, report: CleanupReport) -> Result[SupervisionOutcome]:
        """Plan 6.6: exactly one enrichment; plan 5.3 last row on a lost swap."""
        self._finish_stderr()
        record = self.current
        pair: Any = MISSING
        if (
            record.process_created
            and record.state in _PAIR_ADMITTING
            and _is_missing(record.native_exit_value)
            and self.exit_code is not None
        ):
            pair = self.exit_code
        # Held diagnostics already on the record are filtered by the lifecycle; on
        # an external-winner row they ride this, the only write the supervisor makes.
        additional = _unique((*self.held, *self.after_terminal))
        enriched = self.lifecycle.enrich(
            self.invocation_id,
            expected_revision=record.revision,
            native_exit_value=pair,
            cleanup_complete=report.complete,
            additional=additional,
        )
        if isinstance(enriched, Success):
            self.record = enriched.value
            self._emit(
                SupervisionTraceKind.ENRICHMENT_COMMITTED,
                {
                    "revision": enriched.value.revision,
                    "cleanup_complete": report.complete,
                },
            )
        else:
            for diagnostic in enriched.diagnostics:
                self._remember(diagnostic)
            reload = self.lifecycle.load(self.invocation_id)
            if isinstance(reload, Success):
                self.record = reload.value
                carries_all = (
                    (not report.complete or reload.value.cleanup_complete)
                    and (
                        _is_missing(pair)
                        or not _is_missing(reload.value.native_exit_value)
                    )
                    and all(
                        d.diagnostic_id in reload.value.diagnostic_ids
                        for d in additional
                    )
                )
                if not carries_all:
                    self._emit_winner(reload.value)
            else:
                self._emit_winner(record)
        return Success[SupervisionOutcome](outcome="SUCCESS", value=self._outcome())

    def _outcome(self) -> SupervisionOutcome:
        self._finish_stderr()
        record = self.current
        parsed_output: Any = MISSING
        source_hash: Any = MISSING
        output_parse: Any = MISSING
        if self.output_parse is not None:
            output_parse = self.output_parse
            model: object = MISSING
            if isinstance(self.output_parse, DescriptorParse):
                model = self.output_parse.envelope
            elif isinstance(self.output_parse, ValidationResultParse):
                model = self.output_parse.result
            else:
                model = self.output_parse.manifest
            if not _is_missing(model):
                parsed_output = model
                source_hash = self.output_parse.source_hash
        stderr: Any = MISSING if self.stderr_result is None else self.stderr_result
        violated = record.state is _S.PROTOCOL_FAILED
        result = CommandResult(
            invocation=record,
            parsed_output=parsed_output,
            parsed_output_source_hash=source_hash,
            protocol_integrity=(
                ProtocolIntegrityStatus.VIOLATED
                if violated
                else ProtocolIntegrityStatus.INTACT
            ),
            accepted_events=self.ledger.events,
            diagnostics=tuple(self.seen.values()),
            stderr=stderr,
            cancelled=record.state is _S.CANCELLED,
            timed_out=record.state is _S.TIMED_OUT,
        )
        observation = self.observation
        if observation is None:  # pragma: no cover - every outcome follows it
            raise ValueError("the executable was not observed")
        return SupervisionOutcome(
            command_result=result,
            output_parse=output_parse,
            protocol_summary=self.ledger.summary(),
            stdout_byte_count=self.stdout_byte_count,
            replay_count=self.replay_count,
            executable_observation=observation,
            trace=tuple(self.retained),
        )
