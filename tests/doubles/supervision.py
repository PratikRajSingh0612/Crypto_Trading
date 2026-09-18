"""Deterministic test doubles for the Stage 7 supervision ports (plan section 9.2).

Test-resident on purpose: the two ports implemented here, ``DiagnosticRecorder``
(``crypto_lab.experiments.supervision_lifecycle``) and ``ReconciliationSource``
(``crypto_lab.process_supervision.ports``), are implemented in production only by
Stage 8's ``persistence`` package over its tables. Both doubles read and seed the
shared ``InMemoryBackingStore`` of the Stage 5 doubles directly: the recorder seeds a
diagnostic so the merged operations can read it back through the unit of work's
reader, and the source lists the reconciliation targets and the run facts a
reconciliation pass needs.

Stage 7 Task 5 added ``SeedingDiagnosticRecorder`` and ``InMemoryReconciliationSource``.
Task 6 adds the scripted controller and process (``ScriptedProcessController``,
``ScriptedProcess``), the recording lifecycle wrapper and observer, the two
supervision clocks, the production catalog helper ``supervised_catalog_entry_for`` and
``build_supervisor``; Task 8 adds ``TeeController`` (a delegating controller that
snapshots the command root at launch, tees every stdout byte and counts the destructive
calls the supervisor makes) and the Stage 7 fake-script branch of
``supervised_catalog_entry_for`` (``SUPERVISION_FAKE_PATH`` for the six names of
``SUPERVISION_FAKE_NAMES``).
The scripted process launches nothing: its pipes are in-memory scripts that the
supervisor's own reader threads consume, a held pipe blocks the reader on a condition
until ``terminate_tree`` (EOF) or ``cancel_read`` (the real cancelled-read ``OSError``)
releases it, and every ``wait(0.0)`` poll advances the injected fixed clock, so
deadlines, grace windows and the pipe-holder window elapse in ticks. Only
``RealtimeMonotonicClock`` reads the wall monotonic clock (test code may), for the
suites that drive real children while keeping record instants fixed. No thread is
started here and no process is launched.

Task-local readings, declared in the class docstrings below: a re-record of an
already-seeded identity is accepted with the first instance kept, whatever its
instant (identity is content-derived and excludes ``timestamp_utc``); a missing run
or experiment is the repository's ``CORE.INVARIANT_VIOLATION`` stamped with the
fixed doubles instant, because the source holds no clock; ``cancel_read`` releases
the first still-held pipe in ``stdout``, ``stderr`` order, which is the order the
supervisor stops its readers in; ``deliver_stdout`` appends chunks to a held stdout
so a test can make bytes arrive after a terminal decision deterministically.
"""

from __future__ import annotations

import errno
import sys
import threading
import time
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import IO, Any, Final, cast

from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.adapters.catalog import AdapterCatalogEntry
from crypto_lab.adapters.envelopes import AdapterCommandRequestEnvelope
from crypto_lab.adapters.events import RunEvent
from crypto_lab.adapters.limits import PROTOCOL_LIMITS_DEFAULT, ProtocolLimits
from crypto_lab.domain.command_invocation import (
    CommandInvocationRecord,
    NativeExitValue,
    ProcessIdentity,
    ProcessStartFacts,
)
from crypto_lab.domain.descriptors import ExecutablePath
from crypto_lab.domain.diagnostics import Diagnostic
from crypto_lab.domain.engine_run import EngineRunRecord
from crypto_lab.domain.experiment import EngineIdentity
from crypto_lab.domain.hashing import sha256_bytes
from crypto_lab.domain.identifiers import InvocationId, RunId
from crypto_lab.domain.lifecycle import (
    TERMINAL_COMMAND_INVOCATION_STATES,
    CommandInvocationState,
)
from crypto_lab.domain.ports import Clock
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.domain.time import MonotonicInstant
from crypto_lab.experiments.diagnostics import INVARIANT_VIOLATION, stage5_failure
from crypto_lab.process_supervision.models import (
    LAUNCH_ARGUMENTS_KEY,
    TICK_SECONDS,
    CleanupAction,
    CleanupFailure,
    CleanupReport,
    DescendantIdentity,
    InterruptOutcome,
    LaunchFailure,
    LaunchSpecification,
    ProcessInspection,
    ProcessPresence,
    RunReconciliationFacts,
    SupervisionTraceEntry,
    SupervisionTraceKind,
    TerminationReport,
    render_creation_identity,
)
from crypto_lab.process_supervision.ports import (
    InvocationLifecycle,
    LaunchedProcess,
    ProcessController,
    SupervisionObserver,
)
from crypto_lab.process_supervision.roots import PathPreflight, snapshot_written_paths
from crypto_lab.process_supervision.supervisor import WindowsProcessSupervisor
from doubles.experiments import INSTANT, FixedClock, InMemoryBackingStore

SOURCE_COMPONENT: Final = "doubles.supervision"
#: Plan 9.2: the supervisor instance the scripted fixture, the production strategy
#: and the Task 7 identity helpers use (named apart from the harness's constant).
SCRIPTED_SUPERVISOR_INSTANCE_ID: Final = "scripted-supervisor"
#: Plan 9.2: the merged fake's path, derived here so this module never imports the
#: harness (a test pins it equal to the harness's ``FAKE_ADAPTER_PATH``).
FAKE_ADAPTER_PATH: Final[Path] = (
    Path(__file__).resolve().parents[1] / "fake_adapters" / "fake_adapter.py"
)
#: Plan 9.1, 4.2 (Task 8): the Stage 7 fake script and the six names it serves; the
#: name branch of ``supervised_catalog_entry_for`` selects it for exactly these.
SUPERVISION_FAKE_PATH: Final[Path] = (
    Path(__file__).resolve().parents[1] / "fake_adapters" / "supervision_fake.py"
)
SUPERVISION_FAKE_NAMES: Final = frozenset(
    {
        "fake.argv-echo",
        "fake.cancellation-graceful",
        "fake.cancellation-ignores-interrupt",
        "fake.grandchild",
        "fake.grandchild-inherits-stdout",
        "fake.stdout-flood",
    }
)
FAKE_ADAPTER_VERSION: Final = "1.0.0"
FAKE_ENGINE: Final = EngineIdentity(engine_name="fake.engine", engine_version="1.0.0")
#: The scripted process identity: a fixed pid base and creation time per launch.
SCRIPTED_PID_BASE: Final = 42_000
SCRIPTED_CREATION_100NS: Final = 133_700_000_000_000_000
_FOUR_CONTROLLER_ACTIONS: Final = (
    CleanupAction.PIPES_CLOSED,
    CleanupAction.TREE_VERIFIED_DEAD,
    CleanupAction.JOB_CLOSED,
    CleanupAction.PROCESS_HANDLE_CLOSED,
)
_RELEASE_EOF: Final = "eof"
_RELEASE_CANCEL: Final = "cancel"


def _invariant(message: str) -> Failure:
    return stage5_failure(
        INVARIANT_VIOLATION,
        message,
        source_component=SOURCE_COMPONENT,
        timestamp_utc=INSTANT,
    )


# --------------------------------------------------------------------------
# Task 5: the recorder and the reconciliation source
# --------------------------------------------------------------------------


class SeedingDiagnosticRecorder:
    """The ``DiagnosticRecorder`` double: seed the store, remember every call.

    ``record`` seeds the diagnostic into the backing store when its identity is
    absent and accepts an identical re-record with the first instance kept
    (idempotent on ``diagnostic_id``); ``calls`` lists every recorded identity in
    call order, repeats included. It implements ``record`` only, so the Stage 5
    reader-implementation census is untouched.
    """

    def __init__(self, store: InMemoryBackingStore) -> None:
        self._store = store
        self.calls: list[str] = []

    def record(self, diagnostic: Diagnostic) -> Result[None]:
        self.calls.append(diagnostic.diagnostic_id)
        if diagnostic.diagnostic_id not in self._store.diagnostics.live:
            self._store.seed_diagnostic(diagnostic)
        return Success[None](outcome="SUCCESS", value=None)


class InMemoryReconciliationSource:
    """The ``ReconciliationSource`` double over the committed rows (plan 3.4, 8.5).

    ``list_reconciliation_targets`` returns every nonterminal invocation and every
    terminal one with ``cleanup_complete=false``, ordered ``(created_at_utc,
    invocation_id)``; ``run_facts`` reads the run and its experiment.
    """

    def __init__(self, store: InMemoryBackingStore) -> None:
        self._store = store

    def list_reconciliation_targets(
        self,
    ) -> Result[tuple[CommandInvocationRecord, ...]]:
        targets = sorted(
            (
                record
                for record in self._store.committed_command_invocations()
                if record.state not in TERMINAL_COMMAND_INVOCATION_STATES
                or not record.cleanup_complete
            ),
            key=lambda record: (record.created_at_utc, record.invocation_id),
        )
        return Success[tuple[CommandInvocationRecord, ...]](
            outcome="SUCCESS", value=tuple(targets)
        )

    def run_facts(self, run_id: RunId) -> Result[RunReconciliationFacts]:
        run = self._store.engine_runs.live.get(run_id)
        if run is None:
            return _invariant(f"run {run_id} does not exist")
        experiment = self._store.experiments.live.get(run.experiment_id)
        if experiment is None:
            return _invariant(f"experiment {run.experiment_id} does not exist")
        return Success[RunReconciliationFacts](
            outcome="SUCCESS",
            value=RunReconciliationFacts(
                run_id=run.run_id,
                experiment_id=run.experiment_id,
                run_state=run.state,
                run_revision=run.revision,
                attempt_token_hash=run.attempt_token_hash,
                request_hash=run.request_hash,
                experiment_state=experiment.state,
            ),
        )


# --------------------------------------------------------------------------
# Task 6: the two supervision clocks
# --------------------------------------------------------------------------


class SupervisionFixedClock(FixedClock):
    """The scripted fixture's clock: ``rewind_utc`` moves only the UTC instant
    backwards (the own-request-defect row of plan 5.3) and leaves the monotonic
    accumulator untouched; ``advance`` is inherited."""

    def rewind_utc(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError("rewind_utc takes a non-negative number of seconds")
        self._instant = self._instant - timedelta(seconds=seconds)


class RealtimeMonotonicClock(FixedClock):
    """A fixed UTC instant beside the real monotonic clock (plan 3.2, 9.2).

    ``monotonic()`` is ``time.monotonic()`` plus an offset that ``advance_monotonic``
    moves, so a test can push a live deadline while record instants stay
    deterministic; ``now_utc`` and ``advance`` stay ``FixedClock``'s.
    """

    def __init__(self, instant: Any) -> None:
        super().__init__(instant)
        self.offset = 0.0

    def monotonic(self) -> MonotonicInstant:
        return MonotonicInstant(time.monotonic() + self.offset)

    def advance_monotonic(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError("advance_monotonic takes a non-negative number of seconds")
        self.offset += float(seconds)


# --------------------------------------------------------------------------
# Task 6: the scripted process and controller
# --------------------------------------------------------------------------


class _ScriptedStream:
    """One scripted pipe: a chunk per ``read``, then EOF, or a held read.

    Under ``hold_open`` the read after the last chunk blocks on a condition until
    ``release`` names EOF (a ``terminate_tree``) or a cancelled read (the supervisor's
    ``cancel_read``), and ``deliver`` appends chunks that wake the blocked reader.
    """

    def __init__(
        self, chunks: list[bytes], *, hold_open: bool, read_error: bool = False
    ) -> None:
        self._chunks = list(chunks)
        self._index = 0
        self._hold_open = hold_open
        self._read_error = read_error
        self._condition = threading.Condition()
        self._release: str | None = None
        self.closed = False

    @property
    def held(self) -> bool:
        with self._condition:
            return self._hold_open and self._release is None

    def read(self, size: int = -1) -> bytes:
        del size
        with self._condition:
            while True:
                if self._index < len(self._chunks):
                    chunk = self._chunks[self._index]
                    self._index += 1
                    return chunk
                if self._read_error:
                    # A lost pipe: the read fails without an end of stream.
                    raise OSError(errno.EIO, "the pipe read failed")
                if not self._hold_open or self._release == _RELEASE_EOF:
                    return b""
                if self._release == _RELEASE_CANCEL:
                    raise OSError(errno.EINVAL, "the synchronous read was cancelled")
                self._condition.wait()

    def deliver(self, *chunks: bytes) -> None:
        with self._condition:
            self._chunks.extend(chunks)
            self._condition.notify_all()

    def release(self, mode: str) -> bool:
        with self._condition:
            if not self._hold_open or self._release is not None:
                return False
            self._release = mode
            self._condition.notify_all()
            return True

    def close(self) -> None:
        self.closed = True


class ScriptedProcess:
    """The ``LaunchedProcess`` double of plan 9.2, driven by the controller's script.

    ``wait(0.0)`` advances one script step (the controller's poll hook moves the
    clock), the poll numbered ``exit_after`` returns ``exit_code`` and every later
    poll repeats it, a process that had not exited reports the ``terminate_tree``
    code on its next poll, ``interrupt`` reports ``PROCESS_GONE`` once the script
    has exited, ``terminate_tree`` releases a held pipe with EOF unless
    ``release_on_terminate`` is false, and ``cancel_read`` releases the first
    still-held pipe with the real cancelled-read error.
    """

    def __init__(
        self, controller: ScriptedProcessController, specification: LaunchSpecification
    ) -> None:
        self._controller = controller
        self.specification = specification
        self._pid = SCRIPTED_PID_BASE + len(controller.launches)
        self._creation_identity = render_creation_identity(
            self._pid, SCRIPTED_CREATION_100NS + self._pid
        )
        self._stdout = _ScriptedStream(
            controller.stdout_chunks,
            hold_open=controller.hold_stdout_open,
            read_error=controller.stdout_read_error,
        )
        self._stderr = _ScriptedStream(
            controller.stderr_chunks, hold_open=controller.hold_stderr_open
        )
        self._polls = 0
        self._exit_code: int | None = None
        self._terminated_with: int | None = None

    # -- the launch facts --

    @property
    def pid(self) -> int:
        return self._pid

    @property
    def creation_identity(self) -> str:
        return self._creation_identity

    @property
    def stdout(self) -> IO[bytes]:
        return cast("IO[bytes]", self._stdout)

    @property
    def stderr(self) -> IO[bytes]:
        return cast("IO[bytes]", self._stderr)

    @property
    def job_available(self) -> bool:
        return self._controller.job_available

    @property
    def job_error_code(self) -> int | MISSING:  # type: ignore[valid-type]
        return self._controller.job_error_code

    @property
    def image_path(self) -> ExecutablePath | MISSING:  # type: ignore[valid-type]
        return self._controller.image_path

    @property
    def exited(self) -> bool:
        return self._exit_code is not None or self._terminated_with is not None

    # -- the script --

    def deliver_stdout(self, *chunks: bytes) -> None:
        self._stdout.deliver(*chunks)

    def deliver_stderr(self, *chunks: bytes) -> None:
        self._stderr.deliver(*chunks)

    def wait(self, timeout_seconds: float) -> int | None:
        del timeout_seconds
        self._controller.poll()
        if self._exit_code is not None:
            return self._exit_code
        if self._terminated_with is not None:
            self._exit_code = self._terminated_with
            return self._exit_code
        self._polls += 1
        exit_after = self._controller.exit_after
        if exit_after is not None and self._polls >= exit_after:
            self._exit_code = self._controller.exit_code
            return self._exit_code
        return None

    def interrupt(self) -> InterruptOutcome:
        self._controller.interrupt_calls += 1
        if self.exited:
            return InterruptOutcome.PROCESS_GONE
        return self._controller.interrupt_outcome

    def _terminate(self, exit_code: int) -> TerminationReport:
        self._controller.terminated_identities.add(self._creation_identity)
        if not self.exited:
            self._terminated_with = exit_code
        if self._controller.release_on_terminate:
            self._stdout.release(_RELEASE_EOF)
            self._stderr.release(_RELEASE_EOF)
        report = self._controller.terminate_report
        if report is not None:
            return report
        return TerminationReport(
            forced=True,
            exit_code_used=exit_code,
            job_terminated=self._controller.job_available,
            descendants=(),
            failures=(),
        )

    def terminate_tree(self, exit_code: int) -> TerminationReport:
        self._controller.terminate_calls.append(exit_code)
        return self._terminate(exit_code)

    def cancel_read(self, native_thread_id: int) -> bool:
        self._controller.cancel_read_calls.append(native_thread_id)
        for stream in (self._stdout, self._stderr):
            if stream.release(_RELEASE_CANCEL):
                return True
        return False

    def close(self, *, close_stdout: bool, close_stderr: bool) -> CleanupReport:
        self._controller.close_flags.append((close_stdout, close_stderr))
        if close_stdout:
            self._stdout.close()
        if close_stderr:
            self._stderr.close()
        report = self._controller.close_report
        if report is not None:
            return report
        failures = self._controller.close_failures
        failed = {failure.action for failure in failures}
        return CleanupReport(
            completed=tuple(
                action for action in _FOUR_CONTROLLER_ACTIONS if action not in failed
            ),
            failures=failures,
        )


class ScriptedProcessController:
    """The ``ProcessController`` double of plan 9.2: a script and its counters.

    Script defaults: no stdout or stderr chunks, ``exit_after=None`` (never exits
    unless terminated), ``exit_code=0``, no held pipe, ``release_on_terminate=True``,
    ``interrupt_outcome=DELIVERED``, the job attached, ``inspection=ABSENT``, a
    complete termination report and a complete four-action close report. ``launch``
    records every specification, runs the ``on_launch`` hook and returns the scripted
    process or the scripted ``launch_failure``; ``inspect`` reports ``ABSENT`` for any
    identity whose tree this controller or its process terminated; every
    ``wait(0.0)`` poll advances ``clock`` by ``advance_per_poll`` (``TICK_SECONDS`` by
    default). Registered as an observer it records the poll count at each trace
    entry, which is what ``polls_between`` reads.
    """

    def __init__(
        self, *, clock: FixedClock | None = None, advance_per_poll: float = TICK_SECONDS
    ) -> None:
        self.clock = clock
        self.advance_per_poll = advance_per_poll
        # -- the script --
        self.stdout_chunks: list[bytes] = []
        self.stderr_chunks: list[bytes] = []
        self.exit_after: int | None = None
        self.exit_code: int = 0
        self.hold_stdout_open = False
        self.hold_stderr_open = False
        #: A lost stdout pipe: the read after the last chunk raises ``OSError``
        #: instead of returning end of stream (the reader's ``CANCELLED`` marker).
        self.stdout_read_error = False
        self.release_on_terminate = True
        self.interrupt_outcome = InterruptOutcome.DELIVERED
        self.job_available = True
        self.job_error_code: int | MISSING = MISSING  # type: ignore[valid-type]
        self.image_path: ExecutablePath | MISSING = MISSING  # type: ignore[valid-type]
        self.terminate_report: TerminationReport | None = None
        self.close_report: CleanupReport | None = None
        self.close_failures: tuple[CleanupFailure, ...] = ()
        self.inspection = ProcessPresence.ABSENT
        self.launch_failure: LaunchFailure | None = None
        self.on_launch: Callable[[], object] | None = None
        #: Runs with the poll number on every ``wait(0.0)`` poll (a race seam).
        self.on_poll: Callable[[int], object] | None = None
        # -- the record --
        self.launches: tuple[LaunchSpecification, ...] = ()
        self.process: ScriptedProcess | None = None
        self.terminate_calls: list[int] = []
        self.identity_terminate_calls: list[int] = []
        self.interrupt_calls = 0
        self.cancel_read_calls: list[int] = []
        self.close_flags: list[tuple[bool, bool]] = []
        self.inspect_calls: list[ProcessIdentity] = []
        self.terminated_identities: set[str] = set()
        self.polls = 0
        self._marks: list[tuple[SupervisionTraceKind, int]] = []

    def poll(self) -> None:
        self.polls += 1
        if self.clock is not None and self.advance_per_poll > 0:
            self.clock.advance(self.advance_per_poll)
        if self.on_poll is not None:
            self.on_poll(self.polls)

    def launch(
        self, specification: LaunchSpecification
    ) -> ScriptedProcess | LaunchFailure:
        self.launches = (*self.launches, specification)
        if self.on_launch is not None:
            self.on_launch()
        if self.launch_failure is not None:
            return self.launch_failure
        self.process = ScriptedProcess(self, specification)
        return self.process

    def inspect(self, identity: ProcessIdentity) -> ProcessInspection:
        self.inspect_calls.append(identity)
        presence = (
            ProcessPresence.ABSENT
            if identity.creation_identity in self.terminated_identities
            else self.inspection
        )
        if presence in (
            ProcessPresence.ALIVE_MATCHING,
            ProcessPresence.ALIVE_DIFFERENT_IDENTITY,
        ):
            return ProcessInspection(
                identity=identity,
                presence=presence,
                observed_creation_identity=identity.creation_identity,
            )
        return ProcessInspection(identity=identity, presence=presence)

    def terminate_tree(
        self, identity: ProcessIdentity, exit_code: int
    ) -> TerminationReport:
        self.terminate_calls.append(exit_code)
        self.identity_terminate_calls.append(exit_code)
        self.terminated_identities.add(identity.creation_identity)
        process = self.process
        if (
            process is not None
            and process.creation_identity == identity.creation_identity
        ):
            return process._terminate(exit_code)
        report = self.terminate_report
        if report is not None:
            return report
        return TerminationReport(
            forced=True,
            exit_code_used=exit_code,
            job_terminated=False,
            descendants=(),
            failures=(),
        )

    def deliver_stdout(self, *chunks: bytes) -> None:
        """Append chunks to the launched process's held stdout (a test seam)."""
        if self.process is None:
            raise ValueError("no process has been launched")
        self.process.deliver_stdout(*chunks)

    # -- the observer seam for poll marks --

    def observe(self, entry: SupervisionTraceEntry) -> None:
        self._marks.append((entry.kind, self.polls))

    def polls_between(
        self, kind_a: SupervisionTraceKind, kind_b: SupervisionTraceKind
    ) -> int:
        """The polls between the first observer entries of two kinds."""
        first_a = next(polls for kind, polls in self._marks if kind is kind_a)
        first_b = next(polls for kind, polls in self._marks if kind is kind_b)
        return first_b - first_a


# --------------------------------------------------------------------------
# Task 6: the recording lifecycle and observer
# --------------------------------------------------------------------------


class RecordingLifecycle:
    """A structural wrapper over an ``InvocationLifecycle`` (plan 9.2).

    ``calls`` records every port member in call order (an intercepted call
    included); ``before(method, hook)`` runs the hook once before the named call;
    ``fail(method, code)`` returns a one-shot ``Failure`` carrying a Stage 5 code
    instead of the call. A registered hook runs before the interception check.
    """

    def __init__(self, inner: InvocationLifecycle) -> None:
        self._inner = inner
        self.calls: list[str] = []
        self._before: dict[str, Callable[[], object]] = {}
        self._fail: dict[str, str] = {}

    def before(self, method: str, hook: Callable[[], object]) -> None:
        self._before[method] = hook

    def fail(self, method: str, code: str) -> None:
        self._fail[method] = code

    def _enter(self, method: str) -> Failure | None:
        self.calls.append(method)
        hook = self._before.pop(method, None)
        if hook is not None:
            hook()
        code = self._fail.pop(method, None)
        if code is not None:
            return stage5_failure(
                code,
                f"scripted {method} failure",
                source_component=SOURCE_COMPONENT,
                timestamp_utc=INSTANT,
            )
        return None

    def load(self, invocation_id: InvocationId) -> Result[CommandInvocationRecord]:
        intercepted = self._enter("load")
        if intercepted is not None:
            return intercepted
        return self._inner.load(invocation_id)

    def linked_run(
        self, invocation_id: InvocationId
    ) -> Result[EngineRunRecord | MISSING]:  # type: ignore[valid-type]
        intercepted = self._enter("linked_run")
        if intercepted is not None:
            return intercepted
        return self._inner.linked_run(invocation_id)

    def begin_start(
        self, invocation_id: InvocationId, *, expected_revision: int
    ) -> Result[CommandInvocationRecord]:
        intercepted = self._enter("begin_start")
        if intercepted is not None:
            return intercepted
        return self._inner.begin_start(
            invocation_id, expected_revision=expected_revision
        )

    def request_envelope(
        self, invocation_id: InvocationId
    ) -> Result[AdapterCommandRequestEnvelope]:
        intercepted = self._enter("request_envelope")
        if intercepted is not None:
            return intercepted
        return self._inner.request_envelope(invocation_id)

    def record_process_start(
        self,
        invocation_id: InvocationId,
        *,
        expected_revision: int,
        process_start: ProcessStartFacts,
    ) -> Result[CommandInvocationRecord]:
        intercepted = self._enter("record_process_start")
        if intercepted is not None:
            return intercepted
        return self._inner.record_process_start(
            invocation_id,
            expected_revision=expected_revision,
            process_start=process_start,
        )

    def record_terminal(
        self,
        invocation_id: InvocationId,
        *,
        expected_revision: int,
        target_state: CommandInvocationState,
        primary: Diagnostic | MISSING,  # type: ignore[valid-type]
        additional: tuple[Diagnostic, ...],
        native_exit_value: NativeExitValue | MISSING,  # type: ignore[valid-type]
    ) -> Result[CommandInvocationRecord]:
        intercepted = self._enter("record_terminal")
        if intercepted is not None:
            return intercepted
        return self._inner.record_terminal(
            invocation_id,
            expected_revision=expected_revision,
            target_state=target_state,
            primary=primary,
            additional=additional,
            native_exit_value=native_exit_value,
        )

    def enrich(
        self,
        invocation_id: InvocationId,
        *,
        expected_revision: int,
        native_exit_value: NativeExitValue | MISSING,  # type: ignore[valid-type]
        cleanup_complete: bool,
        additional: tuple[Diagnostic, ...],
    ) -> Result[CommandInvocationRecord]:
        intercepted = self._enter("enrich")
        if intercepted is not None:
            return intercepted
        return self._inner.enrich(
            invocation_id,
            expected_revision=expected_revision,
            native_exit_value=native_exit_value,
            cleanup_complete=cleanup_complete,
            additional=additional,
        )

    def append_event(self, event: RunEvent) -> Result[RunEvent]:
        intercepted = self._enter("append_event")
        if intercepted is not None:
            return intercepted
        return self._inner.append_event(event)

    def resolve_external_winner(
        self,
        invocation_id: InvocationId,
        *,
        expected_revision: int,
        primary: Diagnostic,
    ) -> Result[CommandInvocationRecord | MISSING]:  # type: ignore[valid-type]
        intercepted = self._enter("resolve_external_winner")
        if intercepted is not None:
            return intercepted
        return self._inner.resolve_external_winner(
            invocation_id, expected_revision=expected_revision, primary=primary
        )


class RecordingObserver:
    """Collects every ``SupervisionTraceEntry``; ``on(kind, callback)`` hooks run on
    the supervision thread when an entry of that kind is observed (plan 9.2)."""

    def __init__(self) -> None:
        self.entries: list[SupervisionTraceEntry] = []
        self._hooks: dict[
            SupervisionTraceKind, list[Callable[[SupervisionTraceEntry], object]]
        ] = {}

    def on(
        self,
        kind: SupervisionTraceKind,
        callback: Callable[[SupervisionTraceEntry], object],
    ) -> None:
        self._hooks.setdefault(kind, []).append(callback)

    def observe(self, entry: SupervisionTraceEntry) -> None:
        self.entries.append(entry)
        for callback in self._hooks.get(entry.kind, ()):
            callback(entry)


# --------------------------------------------------------------------------
# Task 8: the tee controller (plan 9.2)
# --------------------------------------------------------------------------


class _TeeStream:
    """A read-through over one pipe read end that copies every byte into a sink."""

    def __init__(self, inner: IO[bytes], sink: bytearray) -> None:
        self._inner = inner
        self._sink = sink

    def read(self, size: int = -1) -> bytes:
        data = self._inner.read(size)
        self._sink.extend(data)
        return data

    def readline(self, size: int = -1) -> bytes:
        data = self._inner.readline(size)
        self._sink.extend(data)
        return data

    def close(self) -> None:
        self._inner.close()

    @property
    def closed(self) -> bool:
        return self._inner.closed


class _TeeProcess:
    """A ``LaunchedProcess`` that delegates every member to the inner process, hands the
    supervisor a tee over ``stdout`` and counts the destructive calls on the tee."""

    def __init__(
        self, controller: TeeController, inner: LaunchedProcess, sink: bytearray
    ) -> None:
        self._controller = controller
        self._inner = inner
        self._stdout = _TeeStream(inner.stdout, sink)

    @property
    def pid(self) -> int:
        return self._inner.pid

    @property
    def creation_identity(self) -> str:
        return self._inner.creation_identity

    @property
    def stdout(self) -> IO[bytes]:
        return cast("IO[bytes]", self._stdout)

    @property
    def stderr(self) -> IO[bytes]:
        return self._inner.stderr

    @property
    def job_available(self) -> bool:
        return self._inner.job_available

    @property
    def job_error_code(self) -> int | MISSING:  # type: ignore[valid-type]
        return self._inner.job_error_code

    @property
    def image_path(self) -> ExecutablePath | MISSING:  # type: ignore[valid-type]
        return self._inner.image_path

    def wait(self, timeout_seconds: float) -> int | None:
        return self._inner.wait(timeout_seconds)

    def interrupt(self) -> InterruptOutcome:
        self._controller.interrupt_calls += 1
        return self._inner.interrupt()

    def terminate_tree(self, exit_code: int) -> TerminationReport:
        self._controller.terminate_calls.append(exit_code)
        report = self._inner.terminate_tree(exit_code)
        self._controller.termination_reports.append(report)
        return report

    def cancel_read(self, native_thread_id: int) -> bool:
        self._controller.cancel_read_calls.append(native_thread_id)
        return self._inner.cancel_read(native_thread_id)

    def close(self, *, close_stdout: bool, close_stderr: bool) -> CleanupReport:
        report = self._inner.close(close_stdout=close_stdout, close_stderr=close_stderr)
        self._controller.close_reports.append(report)
        return report


class TeeController:
    """Plan 9.2: wraps a controller; ``launch`` snapshots the command root (the
    write-boundary baseline the strategy subtracts, taken after the request file and
    any planted stale file exist), tees every stdout byte and returns a delegating
    process; ``launches`` lists every ``LaunchSpecification``; the counters record the
    interrupt, termination, read-cancellation and close calls the supervisor makes, so
    a test counts destructive actions instead of trusting idempotence. The row-47
    stale file is planted by the strategy's observer on ``REQUEST_WRITTEN``, never by
    the tee.
    """

    def __init__(self, inner: ProcessController) -> None:
        self.inner = inner
        self.launches: tuple[LaunchSpecification, ...] = ()
        self.baselines: list[frozenset[str] | None] = []
        self.identities: list[tuple[int, str]] = []
        self.stdout_bytes: list[bytearray] = []
        self.interrupt_calls = 0
        self.terminate_calls: list[int] = []
        self.identity_terminate_calls: list[int] = []
        self.termination_reports: list[TerminationReport] = []
        self.close_reports: list[CleanupReport] = []
        self.cancel_read_calls: list[int] = []
        self.inspect_calls: list[ProcessIdentity] = []

    def launch(
        self, specification: LaunchSpecification
    ) -> LaunchedProcess | LaunchFailure:
        self.launches = (*self.launches, specification)
        try:
            baseline: frozenset[str] | None = snapshot_written_paths(specification.cwd)
        except OSError:
            baseline = None
        self.baselines.append(baseline)
        result = self.inner.launch(specification)
        if isinstance(result, LaunchFailure):
            return result
        sink = bytearray()
        self.stdout_bytes.append(sink)
        self.identities.append((result.pid, result.creation_identity))
        return _TeeProcess(self, result, sink)

    def inspect(self, identity: ProcessIdentity) -> ProcessInspection:
        self.inspect_calls.append(identity)
        return self.inner.inspect(identity)

    def terminate_tree(
        self, identity: ProcessIdentity, exit_code: int
    ) -> TerminationReport:
        self.terminate_calls.append(exit_code)
        self.identity_terminate_calls.append(exit_code)
        report = self.inner.terminate_tree(identity, exit_code)
        self.termination_reports.append(report)
        return report

    @property
    def baseline(self) -> frozenset[str] | None:
        """The write-boundary baseline of the last launch (``None`` before one)."""
        return self.baselines[-1] if self.baselines else None

    @property
    def last_stdout(self) -> bytes:
        """Every stdout byte the supervisor read from the last launched process."""
        return bytes(self.stdout_bytes[-1]) if self.stdout_bytes else b""

    @property
    def descendants(self) -> tuple[DescendantIdentity, ...]:
        """Every descendant any termination report recorded, unique, in order."""
        seen: dict[tuple[int, str], DescendantIdentity] = {}
        for report in self.termination_reports:
            for descendant in report.descendants:
                seen.setdefault(
                    (descendant.pid, descendant.creation_identity), descendant
                )
        return tuple(seen.values())


# --------------------------------------------------------------------------
# Task 6: the production catalog entry and the supervisor builder
# --------------------------------------------------------------------------


def supervised_catalog_entry_for(
    adapter_name: str,
    *,
    script: Path | None = None,
    executable: Path | None = None,
) -> AdapterCatalogEntry:
    """Plan 4.2: the venv launcher as the hashed executable with the fixed launch
    arguments ``["-I", "-B", <script>]``; the script is the Stage 7 fake for the six
    ``SUPERVISION_FAKE_NAMES`` and the merged fake otherwise, ``script`` overrides that
    choice, ``executable`` replaces the launcher (its bytes are hashed)."""
    launcher = Path(sys.executable) if executable is None else Path(executable)
    if script is None:
        chosen = (
            SUPERVISION_FAKE_PATH
            if adapter_name in SUPERVISION_FAKE_NAMES
            else FAKE_ADAPTER_PATH
        )
    else:
        chosen = Path(script)
    return AdapterCatalogEntry(
        adapter_name=adapter_name,
        adapter_version=FAKE_ADAPTER_VERSION,
        engine=FAKE_ENGINE,
        executable_path=str(launcher),
        executable_hash=sha256_bytes(launcher.read_bytes()),
        runtime_metadata={LAUNCH_ARGUMENTS_KEY: ["-I", "-B", str(chosen)]},
    )


def build_supervisor(
    *,
    lifecycle: InvocationLifecycle,
    controller: ProcessController,
    clock: Clock,
    supervision_root: str,
    supervisor_instance_id: str = SCRIPTED_SUPERVISOR_INSTANCE_ID,
    cancellation_grace_seconds: int = 1,
    describe_limits: ProtocolLimits = PROTOCOL_LIMITS_DEFAULT,
    preflight: PathPreflight | MISSING = MISSING,  # type: ignore[valid-type]
    observers: tuple[SupervisionObserver, ...] = (),
) -> WindowsProcessSupervisor:
    """A ``WindowsProcessSupervisor`` over the given ports (plan 9.2)."""
    return WindowsProcessSupervisor(
        lifecycle=lifecycle,
        controller=controller,
        clock=clock,
        supervision_root=supervision_root,
        supervisor_instance_id=supervisor_instance_id,
        cancellation_grace_seconds=cancellation_grace_seconds,
        describe_limits=describe_limits,
        preflight=preflight,
        observers=observers,
    )


__all__ = [
    "FAKE_ADAPTER_PATH",
    "SCRIPTED_SUPERVISOR_INSTANCE_ID",
    "SUPERVISION_FAKE_NAMES",
    "SUPERVISION_FAKE_PATH",
    "InMemoryReconciliationSource",
    "RealtimeMonotonicClock",
    "RecordingLifecycle",
    "RecordingObserver",
    "ScriptedProcess",
    "ScriptedProcessController",
    "SeedingDiagnosticRecorder",
    "SupervisionFixedClock",
    "TeeController",
    "build_supervisor",
    "supervised_catalog_entry_for",
]
