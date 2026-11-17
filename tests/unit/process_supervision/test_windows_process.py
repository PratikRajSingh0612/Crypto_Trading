"""Stage 7 Task 4: the Windows process controller over real children (plan 8.1-8.4).

``WindowsProcessController.launch`` creates the child suspended with a new process
group, owns it through an ``OpenProcess`` handle, reads its creation ``FILETIME`` and
image path, assigns it to a kill-on-close Job Object and only then resumes its initial
thread, so nothing the venv launcher spawns can exist outside the job; ``inspect``
decides presence from the creation time and the unsignaled-handle test alone (never
from ``GetExitCodeProcess``, never from the pid, never from the image path);
``terminate_tree`` kills the job when attached and otherwise every Toolhelp-verified
descendant, leaves first, only while its handle is unsignaled; ``interrupt`` is
``CTRL_BREAK`` to the child's own process group; ``close`` closes the pipes whose
readers ended, verifies the tree dead and closes the job and process handles. Every test
launches ``sys.executable -I -B -c`` children through the controller (no ``subprocess``
import here), every ``-c`` program is a module constant that sleeps in
``time.sleep(0.1)`` slices, and every fixture terminates every identity it launched in
``finally:`` and asserts none is ``ALIVE_MATCHING``. Wall time is bounded with
``time.monotonic()`` only, which test code may do.

Fixture hygiene (the correction of 2026-09-18, T8-N-4): the venv launcher that
``sys.executable`` names creates its interpreter child suspended, assigns it to its own
kill-on-close job and only then resumes it, so a job-less launcher ended inside that
window would leave a never-resumed orphan that no job holds. A job-less test therefore
waits, bounded, for the child's ``ready`` line before any destructive action; the
tracker records the launcher and every Toolhelp-verified descendant as pid plus creation
identity while the launcher lives (a pid a child program reports is bound the same way
at once); and the fixture's ``finally`` cleanup ends a root the test did not end once,
through the launched process's own tree termination, closes every owned pipe, job and
process handle, ends an owned identity outside every terminated tree only through the
controller's identity-bound ``terminate_tree`` -- never by pid or name alone -- and
then requires every owned identity to inspect ``ABSENT``; a survivor fails the test.

The termination oracle (the human ruling of 2026-09-18, Option A): the tests assert
the controller's bounded process-safety logic, never the host's process-object
signalling speed. The report of a real tree termination has exactly one of two
accepted shapes -- ``failures == ()``, or exactly one ``CleanupFailure`` whose action
is ``TREE_VERIFIED_DEAD`` and whose reason is exactly ``still_alive:0`` (``_force``'s
bounded-wait result when the host signals the process object only after
``POST_TERMINATION_WAIT_SECONDS``) -- and no other. The root's existing bounded wait
must return exactly ``FORCED_TERMINATION_EXIT_CODE`` when it observes the exit and may
return ``None`` only under the second shape -- or, at a fault-injected site whose fake
made every bounded wait fail so that the report deterministically holds one failure per
kill target, only beside exactly that fake-dictated report. Every owned identity is
then inspected afresh through its identity and must be ``ABSENT``, each after its own
committed bounded wait (``wait_for_handle`` for exactly the production bound on a
creation-verified limited handle: the descendant form of the root's wait, one blocking
wait, never a poll or a sleep). A live process, a different identity, any other
failure shape or any survivor fails the test; the committed termination path runs at
most once per owned tree. A child's own exit (the rulings of 2026-09-19, R1 and the
natural-exit bound) is observed, not forced: exactly one ``wait`` at the module's own
10-second test bound (``_WAIT_BOUND_SECONDS``, a fixture observation bound that leaves
the production post-termination bound untouched), one fresh inspection of the exact pid
plus creation identity that must be ``ABSENT``, then the zero-duration ``wait`` must
return the exact native code -- never ``None``, never retried, never polled; a first
wait that observes no exit fails whatever a later inspection reports. Resource cleanup
(R2) is proved by complete operation-owned accounting -- replaced in method only under
the owner ruling of 2026-11-14, section 1, and only where that accounting is shown
complete: every handle the operation acquires through a reviewed kernel32 creator or
through the standard-library route it reaches is recorded by generation and must end
in a real successful close or stay retained by its named owner -- exactly zero
unaccounted, no tolerance -- and a live table count there is a diagnostic that decides
nothing. Completeness is shown for kernel32 (every call passes the seam) and for the
whole ``Popen`` route, construction included: its static census leaves no site
unresolved -- a site whose receiver the bytecode does not fix is either typed on the
supported path, the monitor judging the receiver it reads at every execution inside
an accounting window, or guarded off that path by a branch production's fixed
arguments never take, its execution failing the window. The census's bound is stated
where it is pinned: a native callable is trusted to return exactly what its role names,
and implicit protocol calls are no sites. The deterministic pin keeps R2's settle
semantics -- a bounded settle to a baseline through the module's monotonic wait: exact
equality, no tolerance, expiry fails -- over an injected counter. Which shape each
termination site observed, every natural exit code, every handle settle, every resume
and accounting record and the in-process resource counts at each fixture cleanup are
written at module teardown under pytest's base temporary directory for the repetition
ledger.
"""

from __future__ import annotations

import ast
import ctypes
import dis
import gc
import inspect
import json
import os
import sys
import threading
import time
from collections.abc import Callable, Generator, Iterable, Iterator, Mapping
from contextlib import suppress
from pathlib import Path
from types import CodeType, FunctionType, ModuleType
from typing import IO, Any, Final, cast

import pytest
from pydantic import BaseModel

from crypto_lab.domain.command_invocation import ProcessIdentity
from crypto_lab.domain.hashing import sha256_bytes
from crypto_lab.process_supervision import windows_api
from crypto_lab.process_supervision import windows_process as windows_process_module
from crypto_lab.process_supervision.models import (
    CREATE_SUSPENDED,
    FORCED_TERMINATION_EXIT_CODE,
    POST_TERMINATION_WAIT_SECONDS,
    QUEUE_CAPACITY_CHUNKS,
    READER_JOIN_SECONDS,
    CleanupAction,
    CleanupFailure,
    DescendantIdentity,
    InterruptOutcome,
    LaunchFailure,
    LaunchSpecification,
    ProcessInspection,
    ProcessPresence,
    TerminationReport,
    parse_creation_identity,
    render_creation_identity,
)
from crypto_lab.process_supervision.ports import LaunchedProcess, ProcessController
from crypto_lab.process_supervision.readers import PipeReader, ReaderEnd
from crypto_lab.process_supervision.windows_api import (
    WindowsApiError,
    close_handle,
    console_process_count,
    create_kill_on_close_job,
    descendants_of,
    is_process_in_job,
    open_process_limited,
    process_times,
    wait_for_handle,
)
from crypto_lab.process_supervision.windows_process import (
    WindowsLaunchedProcess,
    WindowsProcessController,
)
from doubles.experiments import INVOCATION_ID, sample_process_identity

# --------------------------------------------------------------------------
# Module-level values (plan Task 4 "Test helpers": Task 4 precedes the doubles module)
# --------------------------------------------------------------------------

SUPERVISOR_INSTANCE_ID: Final = "windows-process-tests"
EXECUTABLE_PATH: Final = str(Path(sys.executable))
EXECUTABLE_HASH: Final = sha256_bytes(Path(sys.executable).read_bytes())
_WAIT_BOUND_SECONDS: Final = 10.0
_PAUSE: Final = threading.Event()  # never set: ``wait`` on it is a bounded pause
_NOQA_TEXT: Final = "# noqa: S603 - reviewed fixed catalog executable boundary"
_ERROR_INVALID_HANDLE: Final = 6
_CONTROL_C_EXIT: Final = 3221225786  # STATUS_CONTROL_C_EXIT (plan 2.5 reading 6)
_FOUR_ACTIONS: Final = (
    CleanupAction.PIPES_CLOSED,
    CleanupAction.TREE_VERIFIED_DEAD,
    CleanupAction.JOB_CLOSED,
    CleanupAction.PROCESS_HANDLE_CLOSED,
)
#: The ruling's two accepted shapes of a real termination's report (module docstring).
_CLEAN: Final = "clean"
_HOST_DELAYED: Final = "host_delayed"
#: ``_force``'s exact bounded-wait failure text: ``_tree_failure("still_alive", 0)``.
_HOST_DELAYED_REASON: Final = "still_alive:0"
#: Plan 2.6: the import closure of ``windows_process.py`` (``subprocess`` lives here).
_PURE_ROOTS: Final = frozenset(
    {
        "__future__",
        "collections",
        "contextlib",
        "subprocess",
        "typing",
        "pydantic",
        "crypto_lab",
    }
)
_DENIED_ROOTS: Final = frozenset(
    {
        "os",
        "sys",
        "time",
        "signal",
        "shutil",
        "tempfile",
        "stat",
        "io",
        "glob",
        "functools",
        "asyncio",
        "threading",
        "queue",
        "ctypes",
        "socket",
        "types",
        "importlib",
    }
)
_DENIED_PROJECT_MODULES: Final = frozenset(
    {
        "crypto_lab.experiments",
        "crypto_lab.process_supervision.roots",
        "crypto_lab.process_supervision.readers",
        "crypto_lab.process_supervision.diagnostics",
        "crypto_lab.process_supervision.supervisor",
        "crypto_lab.process_supervision.reconciliation",
        "crypto_lab.configuration",
        "crypto_lab.persistence",
        "crypto_lab.cli",
    }
)
_STAGE4_BARE_NAMES: Final = frozenset(
    {"buffer", "context", "note", "problem", "compose", "Loader"}
)
#: The test's own kernel32 binding for the handle-table probe (test code may bind it).
_PROBE = ctypes.WinDLL("kernel32", use_last_error=True)
#: The job-less pipe-holder's acknowledgement (plan Step 3): a sentinel the test creates
#: in the launch's own temporary cwd only after it bound the sleeper and adopted its
#: tree; the intermediate parent exits naturally only once the sentinel exists.
_ACKNOWLEDGEMENT: Final = "acknowledged"

# The three ``-c`` programs (stdlib only; every sleep in 0.1 s slices, plan Task 4). A
# ``LaunchSpecification`` refuses a control character in any argv element, so each
# program is one line: ``any(time.sleep(0.1) for _ in iter(int, 1))`` is the sliced
# forever-loop. A program that will receive an interrupt first prints ``ready``:
# Windows terminates a process that receives a console control event before its loader
# finished initializing with ``STATUS_DLL_INIT_FAILED`` (0xC0000142), so the interrupt
# tests synchronize on that line instead of racing the child's start-up (the host
# probe is recorded in the Task 4 ledger). The same line is the readiness signal of the
# job-less tests (module docstring, T8-N-4): only a running interpreter prints it, so
# the launcher has passed its create-suspended, assign, resume window; a program that
# spawns a sleeper waits for the sleeper's own ``ready`` line before it prints the pid.
_SLEEP_FOREVER: Final = "any(time.sleep(0.1) for _ in iter(int, 1))"
_READY_SLEEPER_PROGRAM: Final = (
    f"import time; print('ready', flush=True); {_SLEEP_FOREVER}"
)
#: The sleeper of the stdout-inheriting spawner: its stdout is the inherited pipe, so
#: its readiness line goes to stderr, which only the spawner reads.
_READY_ON_STDERR_SLEEPER_PROGRAM: Final = (
    f"import sys, time; print('ready', file=sys.stderr, flush=True); {_SLEEP_FOREVER}"
)
#: ``sleep_spec``'s 30 s sleeper with the readiness line, for the job-less tests.
_READY_SLEEP_30_PROGRAM: Final = (
    "import time; print('ready', flush=True); time.sleep(30)"
)
HANDLER_EXITS_50_THEN_SLEEPS: Final = (
    "import signal, sys, time; "
    "signal.signal(signal.SIGBREAK, lambda *_: sys.exit(50)); "
    "print('ready', flush=True); "
    f"{_SLEEP_FOREVER}"
)
SPAWNS_A_SLEEPER_AND_PRINTS_ITS_PID: Final = (
    "import subprocess, sys, time; "
    "child = subprocess.Popen("
    f"[sys.executable, '-I', '-B', '-c', {_READY_SLEEPER_PROGRAM!r}], "
    "stdout=subprocess.PIPE); "
    "assert child.stdout.readline().strip() == b'ready'; "
    "print(child.pid, flush=True); "
    f"{_SLEEP_FOREVER}"
)
#: The job-less pipe-holder (plan Step 3, acknowledgement protocol): once its sleeper
#: printed ``ready`` it prints the sleeper's pid exactly as before, then polls in 0.1 s
#: slices for the sentinel in its own cwd until a fixed deadline of the module bound,
#: never renewed, and exits naturally only once the sentinel exists; without it, it
#: stays alive, so the owned tree stays reachable for cleanup.
SPAWNS_A_SLEEPER_INHERITING_STDOUT_AND_EXITS: Final = (
    "import os, subprocess, sys, time; "
    "child = subprocess.Popen("
    f"[sys.executable, '-I', '-B', '-c', {_READY_ON_STDERR_SLEEPER_PROGRAM!r}], "
    "stdin=subprocess.DEVNULL, stdout=sys.stdout.fileno(), "
    "stderr=subprocess.PIPE); "
    "assert child.stderr.readline().strip() == b'ready'; "
    "print(child.pid, file=sys.stderr, flush=True); "
    f"deadline = time.monotonic() + {_WAIT_BOUND_SECONDS!r}; "
    f"acknowledged = any(os.path.exists({_ACKNOWLEDGEMENT!r}) or time.sleep(0.1) "
    "for _ in iter(lambda: time.monotonic() < deadline, False)); "
    f"acknowledged or {_SLEEP_FOREVER}"
)


# --------------------------------------------------------------------------
# Module-local helpers (plan Task 4 "Test helpers")
# --------------------------------------------------------------------------


def started(result: WindowsLaunchedProcess | LaunchFailure) -> WindowsLaunchedProcess:
    """Assert the launch produced a process and narrow it to the Windows class."""
    assert isinstance(result, WindowsLaunchedProcess), result
    assert not isinstance(result, LaunchFailure)
    return result


def spec_for(argv: list[str], *, cwd: Path) -> LaunchSpecification:
    return LaunchSpecification(
        invocation_id=INVOCATION_ID, argv=tuple(argv), cwd=str(cwd)
    )


def program_spec(code: str, *, cwd: Path) -> LaunchSpecification:
    return spec_for([sys.executable, "-I", "-B", "-c", code], cwd=cwd)


def sleep_spec(cwd: Path) -> LaunchSpecification:
    return spec_for(
        [sys.executable, "-I", "-B", "-c", "import time; time.sleep(30)"], cwd=cwd
    )


def ready_sleep_spec(cwd: Path) -> LaunchSpecification:
    """The 30 s sleeper whose interpreter prints ``ready`` first: every job-less launch
    uses it and waits for the line before any destructive action (module docstring)."""
    return program_spec(_READY_SLEEP_30_PROGRAM, cwd=cwd)


def identity_for(pid: int, creation_identity: str) -> ProcessIdentity:
    return ProcessIdentity(
        pid=pid,
        creation_identity=creation_identity,
        executable_path=EXECUTABLE_PATH,
        executable_hash=EXECUTABLE_HASH,
        supervisor_instance_id=SUPERVISOR_INSTANCE_ID,
    )


def process_identity_for(launched: WindowsLaunchedProcess) -> ProcessIdentity:
    return identity_for(launched.pid, launched.creation_identity)


def own_creation() -> int:
    handle = open_process_limited(os.getpid())
    try:
        return process_times(handle)
    finally:
        close_handle(handle)


def identity_for_own_process(*, creation: int) -> ProcessIdentity:
    return identity_for(os.getpid(), render_creation_identity(os.getpid(), creation))


def inspect_pid(pid: int) -> ProcessPresence:
    """``inspect`` over a rendered identity for that pid: its live creation time when
    the pid can be opened, else a creation of ``0`` (an absent pid is ``ABSENT`` either
    way)."""
    creation = 0
    try:
        handle = open_process_limited(pid)
    except WindowsApiError:
        pass
    else:
        try:
            creation = process_times(handle)
        finally:
            close_handle(handle)
    identity = identity_for(pid, render_creation_identity(pid, creation))
    return WindowsProcessController().inspect(identity).presence


def descendant_identity(report: TerminationReport, pid: int) -> ProcessIdentity:
    """The exact identity a termination report recorded for ``pid``."""
    (descendant,) = (item for item in report.descendants if item.pid == pid)
    return identity_for(pid, descendant.creation_identity)


def inspect_descendant(report: TerminationReport, pid: int) -> ProcessPresence:
    """``inspect`` over the exact identity the termination report recorded for
    ``pid``."""
    return WindowsProcessController().inspect(descendant_identity(report, pid)).presence


def live_identity_for(pid: int) -> ProcessIdentity:
    """The durable identity of a live pid a test-owned child just reported: opened with
    the limited mask, its creation time read and rendered, the handle closed at once,
    and ``ALIVE_MATCHING`` asserted so a stale or reused pid is never adopted."""
    handle = open_process_limited(pid)
    try:
        creation = process_times(handle)
    finally:
        close_handle(handle)
    identity = identity_for(pid, render_creation_identity(pid, creation))
    assert (
        WindowsProcessController().inspect(identity).presence
        is ProcessPresence.ALIVE_MATCHING
    )
    return identity


def _wait_until(predicate: Callable[[], bool]) -> bool:
    deadline = time.monotonic() + _WAIT_BOUND_SECONDS
    while not predicate():
        if time.monotonic() >= deadline:
            return False
        _PAUSE.wait(0.02)
    return True


def _accepted_shape(report: TerminationReport) -> str:
    """The ruling's closed oracle over the report of one real tree termination: shape A
    (``_CLEAN``: no failure) or shape B (``_HOST_DELAYED``: exactly one failure whose
    ``action`` is ``CleanupAction.TREE_VERIFIED_DEAD`` and whose ``reason`` is exactly
    ``still_alive:0``, the bounded-wait result ``_force`` renders when the host signals
    the process object only after ``POST_TERMINATION_WAIT_SECONDS``). Decided on the
    structured fields alone; any other count, action or reason is an assertion
    failure, and the caller still proves every identity ``ABSENT``."""
    if report.failures == ():
        return _CLEAN
    assert len(report.failures) == 1, report.failures
    (failure,) = report.failures
    assert failure.action is CleanupAction.TREE_VERIFIED_DEAD, failure
    assert failure.reason == _HOST_DELAYED_REASON, failure
    return _HOST_DELAYED


def _sole_reason(report: TerminationReport) -> str:
    """The one reason word of a report whose every kill target failed the same way
    because a fake dictated it: the root and each verified descendant yield one
    ``TREE_VERIFIED_DEAD`` failure each, exactly -- structured fields, exact count."""
    assert report.failures
    assert {f.action for f in report.failures} == {CleanupAction.TREE_VERIFIED_DEAD}
    assert len(report.failures) == 1 + len(report.descendants)
    reasons = {f.reason for f in report.failures}
    assert len(reasons) == 1, reasons
    (reason,) = reasons
    return reason


def _native_exit(
    observed: int | None,
    report: TerminationReport,
    *,
    dictated_reason: str | None = None,
) -> None:
    """The ruling's contract for the root's existing bounded wait, over
    ``WindowsLaunchedProcess.wait``'s exact ``int | None`` return: an observed exit is
    exactly ``FORCED_TERMINATION_EXIT_CODE``; no observation within the bound passes
    only when the report is shape B -- or, at a fault-injected site whose fake made
    every bounded wait fail, only when the report is exactly the fake-dictated one
    (``_sole_reason`` equal to ``dictated_reason``, one failure per kill target). The
    caller then proves every identity ``ABSENT`` either way. The report is held to its
    oracle here on both branches, so no call site can pass an unexamined report."""
    if dictated_reason is None:
        shape = _accepted_shape(report)
    else:
        assert _sole_reason(report) == dictated_reason, report
        shape = None
    if observed is not None:
        assert observed == FORCED_TERMINATION_EXIT_CODE, observed
    elif dictated_reason is None:
        assert shape == _HOST_DELAYED, report


def _native_exit_code(observed: int | None, expected: int) -> None:
    """R1: what the zero-duration wait returns after the bounded wait and the fresh
    ``ABSENT`` inspection must be exactly ``expected``; ``None`` is no result."""
    assert observed is not None, "the zero-duration wait after ABSENT returned None"
    assert observed == expected, observed


def _require_absent(identity: ProcessIdentity, presence: ProcessPresence) -> None:
    """The natural-exit oracle's presence step: only ``ABSENT`` passes;
    ``ALIVE_MATCHING``, ``ALIVE_DIFFERENT_IDENTITY`` and ``UNDETERMINED`` each fail by
    name."""
    if presence is not ProcessPresence.ABSENT:
        raise AssertionError(
            f"{identity.creation_identity} is {presence.value}, not ABSENT"
        )


def _exited(launched: WindowsLaunchedProcess, expected: int) -> None:
    """The natural-exit oracle (ruling of 2026-09-19): exactly one ``wait`` at the
    module's 10-second test bound, one fresh inspection of the exact pid plus creation
    identity that must be ``ABSENT``, then exactly one zero-duration ``wait`` that must
    return ``expected`` -- never ``None``, never retried, no poll, no sleep, and no
    production constant. A first wait that returns ``None`` fails whatever the
    inspection reports (plan Step 2): a timeout is never an observed exit. At that
    timeout the root's descendants are recorded first, as diagnostics only."""
    started_at = time.monotonic()
    first = launched.wait(_WAIT_BOUND_SECONDS)
    elapsed = time.monotonic() - started_at
    identity = process_identity_for(launched)
    observed_presence = WindowsProcessController().inspect(identity).presence
    _EVIDENCE.record_exit(
        expected, first, elapsed, observed_presence, identity=identity.creation_identity
    )
    if first is None:
        _EVIDENCE.record_timeout_tree("natural_exit", launched)
    _require_absent(identity, observed_presence)
    assert first is not None, (
        f"the bounded wait observed no exit of {identity.creation_identity}; a later"
        " ABSENT inspection is not an observed natural exit"
    )
    observed = launched.wait(0.0)
    _native_exit_code(observed, expected)


def _settled_handle_count(
    baseline: int, *, count: Callable[[], int] | None = None
) -> None:
    """R2: once every owned identity is ``ABSENT`` and every fixture-owned handle the
    baseline did not include is closed, the current process's handle-table size must
    settle to exactly ``baseline`` within the module bound -- ``_wait_until``,
    monotonic, the existing bounded infrastructure -- with no tolerance; expiry
    fails."""
    reader = _open_handle_count if count is None else count
    readings: list[int] = []

    def equal() -> bool:
        readings.append(reader())
        return readings[-1] == baseline

    settled = _wait_until(equal)
    _EVIDENCE.record_settle(baseline, readings[-1], len(readings), settled)
    assert settled, (
        f"handle count {readings[-1]} did not settle to exactly {baseline} within the"
        " bound"
    )


def _absent(identity: ProcessIdentity) -> float:
    """One fresh identity-safe inspection that must be ``ABSENT``, taken after the
    identity's own committed bounded wait: the pid opened with the limited mask, its
    creation time verified against the identity (a pid that is gone or reused is never
    waited on), ``wait_for_handle`` for exactly ``POST_TERMINATION_WAIT_SECONDS`` --
    the wait the root receives through ``WindowsLaunchedProcess.wait`` -- and the handle
    closed. The wait's result is not the oracle; the inspection is, and an unsignaled
    object is ``ALIVE_MATCHING``, which fails."""
    parsed = parse_creation_identity(identity.creation_identity)
    started_at = time.monotonic()
    with suppress(WindowsApiError):
        handle = open_process_limited(parsed.pid)
        try:
            if process_times(handle) == parsed.creation_100ns:
                wait_for_handle(handle, POST_TERMINATION_WAIT_SECONDS)
        finally:
            close_handle(handle)
    elapsed = time.monotonic() - started_at
    presence = WindowsProcessController().inspect(identity).presence
    assert presence is ProcessPresence.ABSENT, (
        f"{identity.creation_identity} is {presence.value}, not ABSENT"
        f" after {elapsed:.3f}s"
    )
    return elapsed


def _tree_identities(
    launched: WindowsLaunchedProcess, report: TerminationReport
) -> list[ProcessIdentity]:
    """The root and every descendant the termination report enumerated."""
    return [
        process_identity_for(launched),
        *(
            identity_for(item.pid, item.creation_identity)
            for item in report.descendants
        ),
    ]


def _report(*failures: CleanupFailure, descendants: int = 0) -> TerminationReport:
    """A forced, job-less report with exactly these failures and ``descendants``
    fabricated verified descendants (an absent pid under a fixed creation time)."""
    return TerminationReport(
        forced=True,
        exit_code_used=FORCED_TERMINATION_EXIT_CODE,
        job_terminated=False,
        descendants=tuple(
            DescendantIdentity(pid=3, creation_identity=render_creation_identity(3, 1))
            for _ in range(descendants)
        ),
        failures=failures,
    )


def _failure(action: CleanupAction, reason: str) -> CleanupFailure:
    return CleanupFailure(action=action, reason=reason)


def _failing_job_factory() -> int:
    raise WindowsApiError("CreateJobObjectW", 1450)  # ERROR_NO_SYSTEM_RESOURCES


def _null_job_factory() -> int:
    return 0  # ``AssignProcessToJobObject`` refuses a NULL handle


def _open_handle_count() -> int:
    """This process's handle-table size (``GetProcessHandleCount`` over the current
    process pseudo-handle); a test-local probe, the production modules never count."""
    gc.collect()
    count = ctypes.c_ulong(0)
    assert _PROBE.GetProcessHandleCount(ctypes.c_void_p(-1), ctypes.byref(count))
    return count.value


def _diagnostic_handle_count() -> int | str:
    """This process's handle-table size (``GetProcessHandleCount`` over the current
    process pseudo-handle); a test-local probe, the production modules never count. It
    includes unrelated resource lifetimes, so it is only a diagnostic recorded beside
    the accounting: it forces no collection (a finalizer run here could release a
    recorded resource and so decide the accounting) and a failed collection is
    returned as its precise error, never raised -- it neither establishes nor vetoes
    resource-cleanup success."""
    count = ctypes.c_ulong(0)
    try:
        counted = _PROBE.GetProcessHandleCount(ctypes.c_void_p(-1), ctypes.byref(count))
    except Exception as error:  # recorded explicitly; the accounting still decides
        return f"GetProcessHandleCount raised {type(error).__name__}"
    if not counted:
        return f"GetProcessHandleCount failed: {ctypes.get_last_error()}"
    return count.value


def _read_line_bounded(
    stream: IO[bytes], *, launched: WindowsLaunchedProcess | None = None
) -> bytes:
    """One line from a child's pipe within the module bound, read on a daemon thread so
    a child that never writes cannot hang the test. The one bounded join decides: a
    reader still reading when it returns is a timeout, whatever happens afterwards (see
    ``_setup_line``); the reader then stays owned until a fixture cleanup establishes
    that it ended."""
    root = None if launched is None else (launched.pid, launched.creation_identity)
    reader = _SetupReader(stream, root)
    reader.thread.start()
    reader.thread.join(_WAIT_BOUND_SECONDS)
    return _setup_line(reader, launched)


class _SetupReader:
    """The daemon thread one bounded setup read starts and what it observed: the line,
    or the error that ended its read (a cancelled or closed pipe)."""

    def __init__(self, stream: IO[bytes], root: tuple[int, str] | None) -> None:
        self.root = root
        self.lines: list[bytes] = []
        self.errors: list[str] = []
        self.cancellation: object = None
        self.thread = threading.Thread(target=self._read, args=(stream,), daemon=True)

    def _read(self, stream: IO[bytes]) -> None:
        try:
            self.lines.append(stream.readline())
        except (OSError, ValueError) as error:  # a cancelled or closed pipe: no line
            self.errors.append(type(error).__name__)


#: Every setup reader whose bounded read expired, kept by the root it read from until a
#: fixture cleanup establishes that it ended (plan Step 3).
_SETUP_READERS: Final[list[_SetupReader]] = []
#: Every setup reader the autouse ownership check found still reading at the end of its
#: test: ownership transferred here, explicitly, until a later zero-duration look
#: establishes that it ended.
_UNENDED_SETUP_READERS: Final[list[_SetupReader]] = []


def _discoverable_setup_readers() -> list[_SetupReader]:
    """Every setup reader some owning collection of this module still holds."""
    return [*_SETUP_READERS, *_UNENDED_SETUP_READERS]


def _claim_setup_readers(roots: Iterable[tuple[int, str] | None]) -> list[_SetupReader]:
    """Every retained setup reader of these roots, found but left in the registry: a
    claim transfers nothing; ``_end_setup_reader_ownership`` alone removes a reader,
    and only one whose end it established."""
    wanted = set(roots)
    return [reader for reader in _SETUP_READERS if reader.root in wanted]


def _end_setup_reader_ownership(reader: _SetupReader) -> bool:
    """End ownership of a setup reader only once a zero-duration look establishes that
    its thread ended: then it leaves every owning collection. A reader still reading
    stays exactly where it is owned, discoverable (no wait, no retry)."""
    if reader.thread.is_alive():
        return False
    for registry in (_SETUP_READERS, _UNENDED_SETUP_READERS):
        while reader in registry:
            registry.remove(reader)
    return True


def _setup_line(reader: _SetupReader, launched: WindowsLaunchedProcess | None) -> bytes:
    """The bounded setup read's verdict once its one join returned. Expiry is captured
    first: a reader still reading then is a timeout, and stays one even if the
    cancellation ends it or a line arrives afterwards. The reader is retained for the
    cleanup before anything else runs; the root's verified descendants are recorded and
    the blocked read is cancelled -- diagnostics and cleanup that add no wait, whose
    outcome (or failure) is recorded separately and never replaces the timeout."""
    expired = reader.thread.is_alive()
    if not expired:
        line = reader.lines[0] if reader.lines else b""
        assert line, f"the child's pipe ended without a line ({reader.errors or 'EOF'})"
        return line
    _SETUP_READERS.append(reader)  # owned until a cleanup establishes that it ended
    _EVIDENCE.record_timeout_tree("line", launched)
    native_id = reader.thread.native_id
    try:
        if native_id is not None:
            reader.cancellation = windows_api.cancel_synchronous_io(native_id)
    except Exception as error:  # recorded separately; the timeout stays the failure
        reader.cancellation = ":".join(
            (
                type(error).__name__,
                str(getattr(error, "function", "")),
                str(getattr(error, "winerror", "")),
            )
        )
    _EVIDENCE.record_phase(
        "setup_reader_expired", root=reader.root, cancellation=str(reader.cancellation)
    )
    raise AssertionError(
        f"no line from the child within the bound (cancellation: {reader.cancellation})"
    )


def _ready(launched: WindowsLaunchedProcess) -> None:
    """Block, bounded, until the child printed its readiness line: its interpreter is
    created, resumed and running (see the program comment)."""
    line = _read_line_bounded(launched.stdout, launched=launched)
    assert line.strip() == b"ready", line


def _pid_line(
    stream: IO[bytes], *, launched: WindowsLaunchedProcess | None = None
) -> int:
    """The pid a spawner program printed as one line, read within the bound; the program
    prints it only after its spawned sleeper printed ``ready``."""
    return int(_read_line_bounded(stream, launched=launched))


class _ShapeEvidence:
    """Which accepted report shape every real tree termination in this module observed,
    every natural exit code, every handle settle and the in-process resource counts at
    each fixture cleanup, per test and in order, written at module teardown into
    pytest's base temporary directory (``termination-shapes*/shapes.jsonl``) for the
    repetition ledger: a diagnostic record, never an oracle."""

    def __init__(self) -> None:
        self.site = ""
        self.rows: list[dict[str, object]] = []

    def _row(self, kind: str, **fields: object) -> None:
        self.rows.append(
            {"kind": kind, "site": self.site, "ordinal": len(self.rows), **fields}
        )

    def record(self, shape: str, *, origin: str) -> None:
        self._row("shape", origin=origin, shape=shape)

    def record_exit(
        self,
        expected: int,
        observed: int | None,
        elapsed: float,
        presence: ProcessPresence,
        *,
        identity: str,
    ) -> None:
        self._row(
            "natural_exit",
            identity=identity,
            expected=expected,
            observed=observed,
            wait_seconds=elapsed,
            presence=presence.value,
        )

    def record_timeout_tree(
        self, phase: str, launched: WindowsLaunchedProcess | None
    ) -> None:
        """At a natural-exit or line timeout: the root's verified descendants (pid plus
        creation identity) or the precise failure to take that snapshot. Diagnostic
        only: no wait, and never an exception over the failure it describes."""
        if launched is None:
            self._row("timeout_tree", phase=phase, failure="no_root_named")
            return
        try:
            root = launched.creation_identity
            creation = parse_creation_identity(root).creation_100ns
            tree = descendants_of(launched.pid, creation)
        except WindowsApiError as error:
            failure = f"{error.function}:{error.winerror}"
            self._row("timeout_tree", phase=phase, failure=failure)
            return
        except Exception as error:  # the original failure must stay visible
            self._row("timeout_tree", phase=phase, failure=type(error).__name__)
            return
        descendants = [item.creation_identity for item in tree]
        self._row("timeout_tree", phase=phase, root=root, descendants=descendants)

    def record_phase(self, phase: str, **fields: object) -> None:
        """A setup phase: readiness, adoption, acknowledgement or reader state."""
        self._row("phase", phase=phase, **fields)

    def record_resume(
        self,
        *,
        pid: int | None,
        initial_thread: int | None,
        selected_thread: int | None,
        previous_suspend_count: int,
    ) -> None:
        """The launch's resume at the real call: the thread ``CreateProcess`` created,
        the thread ``OpenThread`` selected and ``ResumeThread``'s previous count."""
        self._row(
            "resume",
            pid=pid,
            initial_thread=initial_thread,
            selected_thread=selected_thread,
            previous_suspend_count=previous_suspend_count,
        )

    def record_ledger(
        self,
        operation: _Operation,
        acquired: list[str],
        released_by: list[str],
        problems: list[str],
        live_after: int | str,
    ) -> None:
        """One accounting boundary: every acquisition by generation with its state and
        release route as the verdict saw them, the unaccounted list, and the live table
        counts or the precise failure to collect them (diagnostic only)."""
        self._row(
            "ledger",
            operation=operation.name,
            acquired=acquired,
            released_by=released_by,
            unaccounted=problems,
            receivers=sorted({f"{label} <{kind}>" for label, kind in operation.sites}),
            live_before=operation.live_before,
            live_after=live_after,
        )

    def record_settle(
        self, baseline: int, observed: int, readings: int, settled: bool
    ) -> None:
        self._row(
            "handle_settle",
            baseline=baseline,
            observed=observed,
            readings=readings,
            settled=settled,
        )

    def record_resources(
        self, launched: list[WindowsLaunchedProcess], *, owned: list[str]
    ) -> None:
        """In-process counts after a fixture cleanup: readers alive, streams open,
        process handles open, Job Object handles open (all expected zero), beside the
        owned identities the cleanup judged."""
        self._row(
            "resources",
            owned=owned,
            readers=sum(
                1 for thread in threading.enumerate() if isinstance(thread, PipeReader)
            ),
            streams=sum(
                1
                for item in launched
                for stream in (item.stdout, item.stderr)
                if not stream.closed
            ),
            process_handles=sum(1 for item in launched if item._process_handle_open),
            job_handles=sum(1 for item in launched if item._job_handle_open),
        )

    def write(self, directory: Path) -> Path:
        path = directory / "shapes.jsonl"
        path.write_text(
            "".join(json.dumps(row) + "\n" for row in self.rows), encoding="utf-8"
        )
        return path


_EVIDENCE: Final = _ShapeEvidence()


# --------------------------------------------------------------------------
# Complete operation-owned resource accounting (R2 under the owner ruling of
# 2026-11-14, section 1; plan Step 3; module docstring)
# --------------------------------------------------------------------------

_INVALID_HANDLE: Final = (1 << (8 * ctypes.sizeof(ctypes.c_void_p))) - 1
_TH32CS_SNAPPROCESS: Final = 0x00000002
_TH32CS_SNAPTHREAD: Final = 0x00000004
_THREAD_SUSPEND_RESUME: Final = 0x0002
_THREAD_QUERY_LIMITED_INFORMATION: Final = 0x0800
_FILE_TYPE_UNKNOWN: Final = 0
_FILE_TYPE_PIPE: Final = 3
#: ``FILE_TYPE_DISK`` and ``FILE_TYPE_CHAR``: a number naming one of them names no pipe.
_KNOWN_OTHER_FILE_TYPES: Final = frozenset({1, 2})
_NO_ERROR: Final = 0
#: The reviewed 22-name kernel32 surface, partitioned: each handle creator with the
#: resource class it yields, and every other reviewed name. Pinned against the
#: production surface by AST, so a new name fails until it is classified.
_KERNEL32_CREATOR_CLASSES: Final[Mapping[str, str]] = {
    "OpenProcess": "process",
    "CreateJobObjectW": "job",
    "CreateToolhelp32Snapshot": "snapshot",
    "OpenThread": "thread",
}
_KERNEL32_NON_CREATORS: Final = frozenset(
    {
        "GetProcessTimes",
        "QueryFullProcessImageNameW",
        "GetExitCodeProcess",
        "WaitForSingleObject",
        "CloseHandle",
        "SetInformationJobObject",
        "AssignProcessToJobObject",
        "IsProcessInJob",
        "TerminateJobObject",
        "TerminateProcess",
        "GenerateConsoleCtrlEvent",
        "GetConsoleProcessList",
        "Process32FirstW",
        "Process32NextW",
        "Thread32First",
        "Thread32Next",
        "ResumeThread",
        "CancelSynchronousIo",
    }
)
_SNAPSHOT_CLASSES: Final[Mapping[int, str]] = {
    _TH32CS_SNAPPROCESS: "process_snapshot",
    _TH32CS_SNAPTHREAD: "thread_snapshot",
}
#: The standard-library launch route: every name ``subprocess`` may reach in the four
#: modules it binds, classified once here. An acquisition, release, transfer or
#: observation is recorded by its wrapper; a neutral name or a constant passes through;
#: any other name is recorded as unclassified and fails the accounting (fail closed).
_STDLIB_ROUTE: Final[Mapping[str, Mapping[str, str]]] = {
    "_winapi": {
        "CreatePipe": "acquire",
        "DuplicateHandle": "acquire",
        "CreateProcess": "acquire",
        "CloseHandle": "release",
        "GetCurrentProcess": "neutral",
        "GetFileType": "neutral",
        "TerminateProcess": "neutral",
        "GetExitCodeProcess": "neutral",
        "WaitForSingleObject": "neutral",
        # an existing standard handle, no new reference (only for a ``None`` stream)
        "GetStdHandle": "neutral",
        "DUPLICATE_SAME_ACCESS": "constant",
        "FILE_TYPE_CHAR": "constant",
        "STARTF_USESTDHANDLES": "constant",
        "STARTF_USESHOWWINDOW": "constant",
        "STD_INPUT_HANDLE": "constant",
        "STD_OUTPUT_HANDLE": "constant",
        "STD_ERROR_HANDLE": "constant",
        "SW_HIDE": "constant",
        "STILL_ACTIVE": "constant",
        "WAIT_TIMEOUT": "constant",
        "INFINITE": "constant",
    },
    "msvcrt": {"get_osfhandle": "observe", "open_osfhandle": "transfer"},
    "os": {
        "open": "acquire",
        "close": "release",
        "devnull": "constant",
        "O_RDWR": "constant",
        "fsdecode": "neutral",
        "PathLike": "neutral",
        "path": "neutral",  # path-string helpers
        "environ": "neutral",  # a mapping read only on the ``shell=True`` branch
    },
    "io": {"open": "transfer", "TextIOWrapper": "neutral"},  # text mode wraps a stream
}
#: Exactly what each supported launch route acquires, by class and stream: a failed
#: construction (``Popen`` raises before it returns), a post-creation abandonment and a
#: launch that returns a process.
_FAILED_CONSTRUCTION: Final = (
    "devnull_descriptor",
    "devnull_inheritable",
    "pipe_read:stdout",
    "pipe_write:stdout",
    "pipe_write_inheritable:stdout",
    "pipe_read:stderr",
    "pipe_write:stderr",
    "pipe_write_inheritable:stderr",
)
_ABANDONED_CONSTRUCTION: Final = (
    *_FAILED_CONSTRUCTION,
    "popen_process",
    "popen_thread",
)
_LAUNCH: Final = (
    *_ABANDONED_CONSTRUCTION,
    "process",
    "job",
    "thread_snapshot",
    "thread",
)


def _not_installed(value: int) -> int:
    raise AssertionError("the resource seams are not installed")


def _probe_handle(handle: int) -> str:
    """The state of a pipe read end the C runtime owns, probed by number in this
    process. Only two answers prove its close: ``closed`` when the handle table refuses
    the number, and ``other`` when the number now names a file of a known non-pipe type
    (disk or character). ``pipe`` (open, or an ambiguous reuse), ``unknown`` (a type the
    probe cannot name) and ``failed`` (either query failed with another error) are
    inconclusive: never counted as released."""
    flags = ctypes.c_ulong(0)
    if not _PROBE.GetHandleInformation(ctypes.c_void_p(handle), ctypes.byref(flags)):
        if ctypes.get_last_error() == _ERROR_INVALID_HANDLE:
            return "closed"
        return "failed"
    file_type = _PROBE.GetFileType(ctypes.c_void_p(handle))
    if file_type == _FILE_TYPE_PIPE:
        return "pipe"
    if file_type in _KNOWN_OTHER_FILE_TYPES:
        return "other"
    if file_type == _FILE_TYPE_UNKNOWN and ctypes.get_last_error() == _NO_ERROR:
        return "unknown"
    return "failed"


class _Resource:
    """One acquisition by generation: a number reused later is a new generation and a
    new lifetime, never the same one."""

    def __init__(
        self, generation: int, kind: str, value: int, route: str, namespace: str
    ) -> None:
        self.generation = generation
        self.kind = kind
        self.value = value
        self.route = route
        self.namespace = namespace
        #: ``open``, ``crt`` (C-runtime owned), ``released`` or ``lost``.
        self.state = "open"
        self.released_by = ""
        self.descriptor: int | None = None
        self.os_handle: int | None = None
        self.withheld = False
        #: A planted leak's stream, kept only so that the test can reclaim it.
        self.stream: Any = None

    def describe(self) -> str:
        return f"{self.kind}#{self.generation} via {self.route} ({self.state})"


class _WithheldStream:
    """A planted leak of one pipe read end: ``close`` is withheld, so the stream stays
    open until the test reclaims it after the assertion that has to detect it."""

    def __init__(self, stream: Any) -> None:
        self.stream = stream

    def close(self) -> None:
        return None

    def __getattr__(self, name: str) -> Any:
        return getattr(self.stream, name)


class _Operation:
    """One accounting window: the generations acquired between entry and exit, the
    live table count at entry (a diagnostic only) and, on an installed ledger, every
    receiver site the window executed with the problems the site monitor found."""

    def __init__(self, ledger: _ResourceLedger, name: str) -> None:
        self.ledger = ledger
        self.name = name
        self.start = 0
        self.end = 0
        self.live_before: int | str = 0
        self.sites: list[tuple[str, str]] = []
        self.site_problems: list[str] = []
        self.monitored = False

    def __enter__(self) -> _Operation:
        self.live_before = _diagnostic_handle_count()
        self.start = self.end = len(self.ledger.resources)
        if self.ledger.monitor is not None:
            self.ledger.monitor.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.end = len(self.ledger.resources)
        if self.ledger.monitor is not None:
            self.sites, self.site_problems = self.ledger.monitor.stop()
            self.monitored = True

    @property
    def acquired(self) -> list[_Resource]:
        return self.ledger.resources[self.start : self.end]


class _ResourceLedger:
    """Every acquisition, transfer and release the reviewed seams observe during one
    test -- the kernel32 binding ``windows_api`` calls through, the four modules
    ``subprocess`` binds and the close ``subprocess.Handle`` binds as a default -- by
    generation. A release is recorded only after the real close succeeded; a pipe read
    end the C runtime owns is released only once probing proves its number no longer
    names it; a number acquired again before an observed release marks the earlier
    lifetime lost, never released. ``withhold`` plants a leak by withholding one real
    close, which ``reclaim`` performs after the assertion that has to detect it."""

    def __init__(self) -> None:
        self.resources: list[_Resource] = []
        self.unrelated: list[str] = []
        self.unclassified: list[str] = []
        self.anomalies: list[str] = []
        self.route_calls: list[str] = []
        self.resumes: list[tuple[int | None, int | None, int | None, int]] = []
        self.withhold: set[str] = set()
        #: The receiver-site monitor, present once the seams are installed.
        self.monitor: _SiteMonitor | None = None
        self.real_close_handle: Callable[[int], object] = _not_installed
        self.real_os_close: Callable[[int], object] = _not_installed
        self.real_get_osfhandle: Callable[[int], int] = _not_installed
        self._handles: dict[int, _Resource] = {}
        self._descriptors: dict[int, _Resource] = {}
        self._pipes = 0
        self._resume_threads: dict[int, int] = {}
        self._created: tuple[int, int] | None = None

    def operation(self, name: str) -> _Operation:
        return _Operation(self, name)

    # -- bookkeeping --

    def acquire(
        self, kind: str, value: int, route: str, *, descriptor: bool = False
    ) -> _Resource:
        table = self._descriptors if descriptor else self._handles
        stale = table.get(value)
        if stale is not None:
            self._supersede(stale, value)
        namespace = "descriptor" if descriptor else "handle"
        resource = _Resource(len(self.resources), kind, value, route, namespace)
        self.resources.append(resource)
        table[value] = resource
        return resource

    def _supersede(self, stale: _Resource, value: int) -> None:
        if stale.state == "crt":  # the kernel never hands out a number still open
            self._end(stale, "number_reused")
            return
        stale.state = "lost"
        self._forget(stale)
        self.anomalies.append(
            f"{stale.describe()}: number {value} acquired again unreleased"
        )

    def _forget(self, resource: _Resource) -> None:
        keys = [
            (
                self._handles if resource.namespace == "handle" else self._descriptors,
                resource.value,
            )
        ]
        if resource.descriptor is not None:
            keys.append((self._descriptors, resource.descriptor))
        for table, key in keys:
            if table.get(key) is resource:
                del table[key]

    def _end(self, resource: _Resource, how: str) -> None:
        resource.state = "released"
        resource.released_by = how
        self._forget(resource)

    def release(self, value: int, route: str, *, descriptor: bool = False) -> None:
        table = self._descriptors if descriptor else self._handles
        resource = table.get(value)
        if resource is None:
            self.unrelated.append(route)
            return
        self._end(resource, route)

    def transfer(self, handle: int, descriptor: int) -> None:
        resource = self._handles.get(handle)
        if resource is None:
            self.anomalies.append(f"handle {handle} reached the C runtime unrecorded")
            return
        stale = self._descriptors.get(descriptor)
        if stale is not None:
            self._supersede(stale, descriptor)
        resource.state = "crt"
        resource.descriptor = descriptor
        self._descriptors[descriptor] = resource

    def _withheld(self, resource: _Resource | None) -> bool:
        if resource is None or resource.kind not in self.withhold:
            return False
        self.withhold.discard(resource.kind)
        resource.withheld = True
        return True

    def settle(self) -> None:
        """Probe every pipe read end the C runtime owns: a refused number, or one now
        naming another object type, proves the real close."""
        for resource in self.resources:
            if resource.state == "crt":
                probe = _probe_handle(resource.value)
                if probe in ("closed", "other"):
                    self._end(resource, f"c_runtime_close:{probe}")

    def audit(
        self, operation: _Operation, retained: Mapping[int, str] | None = None
    ) -> list[str]:
        """Exactly zero unaccounted: every resource the operation acquired is released,
        or retained by the named owner (by generation) and still open; on an installed
        ledger the window's receiver sites were monitored and showed no problem."""
        self.settle()
        problems = [f"unclassified route {label}" for label in self.unclassified]
        problems.extend(self.anomalies)
        problems.extend(operation.site_problems)
        if self.monitor is not None and not operation.monitored:
            problems.append(
                f"the receiver sites of {operation.name} were not monitored"
            )
        owners = dict(retained or {})
        for resource in operation.acquired:
            owner = owners.pop(resource.generation, None)
            if resource.state == "released":
                if owner is not None:
                    problems.append(f"{resource.describe()} ended before {owner}")
            elif owner is None:
                problems.append(f"{resource.describe()} is unaccounted")
        problems.extend(
            f"{owner} retains nothing acquired" for owner in owners.values()
        )
        return problems

    def outstanding(self, operation: _Operation) -> list[_Resource]:
        self.settle()
        return [item for item in operation.acquired if item.state != "released"]

    def live(self, value: int) -> _Resource:
        resource = self._handles.get(value)
        assert resource is not None, f"handle {value} is no live recorded acquisition"
        return resource

    def reclaim(self) -> list[str]:
        """Close every withheld (planted) resource for real, after the assertion that
        had to detect it."""
        reclaimed: list[str] = []
        for resource in self.resources:
            if not resource.withheld or resource.state == "released":
                continue
            if resource.stream is not None:
                stream, resource.stream = resource.stream, None
                stream.close()
            elif resource.namespace == "descriptor":
                self.real_os_close(resource.value)
                self._end(resource, "reclaimed")
            else:
                self.real_close_handle(resource.value)
                self._end(resource, "reclaimed")
            reclaimed.append(resource.kind)
        self.settle()
        return reclaimed

    # -- the kernel32 seam --

    def created(self, name: str, args: tuple[Any, ...], handle: int) -> None:
        kind = _KERNEL32_CREATOR_CLASSES[name]
        if kind == "snapshot":
            kind = _SNAPSHOT_CLASSES.get(int(args[0]), kind)
            if kind == "snapshot":
                self.anomalies.append(f"snapshot flags {args[0]} unclassified")
        self.acquire(kind, handle, f"kernel32.{name}")
        if name == "OpenThread" and int(args[0]) & _THREAD_SUSPEND_RESUME:
            self._resume_threads[handle] = int(args[2])

    def resumed(self, thread: int, previous: int) -> None:
        pid, initial = (None, None) if self._created is None else self._created
        selected = self._resume_threads.pop(thread, None)
        self.resumes.append((pid, initial, selected, previous))
        _EVIDENCE.record_resume(
            pid=pid,
            initial_thread=initial,
            selected_thread=selected,
            previous_suspend_count=previous,
        )

    # -- the standard-library route --

    def route_factories(self) -> dict[str, Callable[[Any], Any]]:
        return {
            "_winapi.CreatePipe": self._create_pipe,
            "_winapi.DuplicateHandle": self._duplicate_handle,
            "_winapi.CreateProcess": self._create_process,
            "_winapi.CloseHandle": self._winapi_close_handle,
            "msvcrt.get_osfhandle": self._get_osfhandle,
            "msvcrt.open_osfhandle": self._open_osfhandle,
            "os.open": self._os_open,
            "os.close": self._os_close,
            "io.open": self._io_open,
        }

    def route(self, module: str, name: str, real: Any) -> Any:
        label = f"{module}.{name}"
        self.route_calls.append(label)
        if name not in _STDLIB_ROUTE[module]:
            self.unclassified.append(label)
            return real
        factory = self.route_factories().get(label)
        return real if factory is None else factory(real)

    def _create_pipe(self, real: Callable[..., Any]) -> Callable[..., Any]:
        def create_pipe(*args: Any) -> Any:
            read, write = real(*args)
            if self._pipes > 1:
                self.anomalies.append("a third pipe in one construction")
            stream = ("stdout", "stderr")[min(self._pipes, 1)]
            self._pipes += 1
            self.acquire(f"pipe_read:{stream}", int(read), "_winapi.CreatePipe")
            self.acquire(f"pipe_write:{stream}", int(write), "_winapi.CreatePipe")
            return read, write

        return create_pipe

    def _duplicate_handle(self, real: Callable[..., Any]) -> Callable[..., Any]:
        def duplicate_handle(*args: Any) -> Any:
            duplicate = real(*args)
            source = int(args[1])
            recorded = self._handles.get(source)
            devnull = any(
                item.kind == "devnull_descriptor" and item.os_handle == source
                for item in self._descriptors.values()
            )
            if recorded is not None and recorded.kind.startswith("pipe_write:"):
                kind = recorded.kind.replace("pipe_write:", "pipe_write_inheritable:")
            elif devnull:
                kind = "devnull_inheritable"
            else:
                kind = "duplicate"
                self.anomalies.append("a duplicate of an unrecorded handle")
            self.acquire(kind, int(duplicate), "_winapi.DuplicateHandle")
            return duplicate

        return duplicate_handle

    def _create_process(self, real: Callable[..., Any]) -> Callable[..., Any]:
        def create_process(*args: Any) -> Any:
            process, thread, pid, tid = real(*args)
            self.acquire("popen_process", int(process), "_winapi.CreateProcess")
            self.acquire("popen_thread", int(thread), "_winapi.CreateProcess")
            self._created = (int(pid), int(tid))
            return process, thread, pid, tid

        return create_process

    def _winapi_close_handle(self, real: Callable[..., Any]) -> Callable[..., Any]:
        def close_handle(handle: Any) -> Any:
            if self._withheld(self._handles.get(int(handle))):
                return None
            result = real(handle)
            self.release(int(handle), "_winapi.CloseHandle")
            return result

        return close_handle

    def popen_close(self, real: Callable[[Any], object]) -> Callable[[Any], object]:
        """The replacement for the ``CloseHandle`` default ``subprocess.Handle.Close``
        bound when its class was created (``__del__`` is the same function)."""

        def close(handle: Any) -> object:
            if self._withheld(self._handles.get(int(handle))):
                return None
            result = real(handle)
            self.release(int(handle), "subprocess.Handle.Close")
            return result

        return close

    def _get_osfhandle(self, real: Callable[..., Any]) -> Callable[..., Any]:
        def get_osfhandle(descriptor: Any) -> Any:
            handle = real(descriptor)
            recorded = self._descriptors.get(int(descriptor))
            if recorded is not None and recorded.kind == "devnull_descriptor":
                recorded.os_handle = int(handle)
            return handle

        return get_osfhandle

    def _open_osfhandle(self, real: Callable[..., Any]) -> Callable[..., Any]:
        def open_osfhandle(handle: Any, flags: Any) -> Any:
            descriptor = real(handle, flags)
            self.transfer(int(handle), int(descriptor))
            return descriptor

        return open_osfhandle

    def _os_open(self, real: Callable[..., Any]) -> Callable[..., Any]:
        def os_open(path: Any, flags: Any, *rest: Any) -> Any:
            descriptor = real(path, flags, *rest)
            kind = "devnull_descriptor"
            if path != os.devnull:
                kind = "descriptor"
                self.anomalies.append("os.open of a path other than the null device")
            self._pipes = 0
            self.acquire(kind, int(descriptor), "os.open", descriptor=True)
            return descriptor

        return os_open

    def _os_close(self, real: Callable[..., Any]) -> Callable[..., Any]:
        def os_close(descriptor: Any) -> Any:
            if self._withheld(self._descriptors.get(int(descriptor))):
                return None
            result = real(descriptor)
            self.release(int(descriptor), "os.close", descriptor=True)
            return result

        return os_close

    def _io_open(self, real: Callable[..., Any]) -> Callable[..., Any]:
        def io_open(file: Any, *args: Any, **kwargs: Any) -> Any:
            stream = real(file, *args, **kwargs)
            recorded = self._descriptors.get(file) if isinstance(file, int) else None
            if recorded is None:
                self.anomalies.append("io.open of an unrecorded descriptor")
            elif self._withheld(recorded):
                recorded.stream = stream
                return _WithheldStream(stream)
            return stream

        return io_open


class _LedgerKernel32:
    """The bound ``kernel32`` as ``windows_api`` reaches it during a test: every name
    delegates to the real binding; a successful reviewed creator records its handle, a
    successful ``CloseHandle`` its release, ``ResumeThread`` the previous suspend count
    of the thread ``OpenThread`` selected, all at the real call; an unreviewed name is
    recorded as unclassified. Recording is pure Python, so the last error the binding
    saved for ``windows_api`` is untouched."""

    def __init__(self, ledger: _ResourceLedger, bind: Callable[[], Any]) -> None:
        self._ledger = ledger
        self._bind = bind

    def __getattr__(self, name: str) -> Any:
        function = getattr(self._bind(), name)
        ledger = self._ledger
        if name in _KERNEL32_CREATOR_CLASSES:

            def create(*args: Any) -> Any:
                handle = function(*args)
                if isinstance(handle, int) and handle not in (0, _INVALID_HANDLE):
                    ledger.created(name, args, handle)
                elif handle is not None and not isinstance(handle, int):
                    # a creator result no rule reads as a handle or a failure
                    ledger.anomalies.append(
                        f"kernel32.{name} returned a {type(handle).__name__}"
                    )
                return handle

            return create
        if name == "CloseHandle":

            def close(handle: Any) -> Any:
                result = function(handle)
                if result:
                    ledger.release(int(handle), "kernel32.CloseHandle")
                return result

            return close
        if name == "ResumeThread":

            def resume(thread: Any) -> Any:
                previous = function(thread)
                ledger.resumed(int(thread), int(previous))
                return previous

            return resume
        if name not in _KERNEL32_NON_CREATORS:
            ledger.unclassified.append(f"kernel32.{name}")
        return function


class _RouteProxy:
    """One module ``subprocess`` binds (``_winapi``, ``msvcrt``, ``os`` or ``io``) as
    ``subprocess`` reaches it during a test: every name resolves through the ledger's
    classified route."""

    def __init__(self, ledger: _ResourceLedger, module: str, real: Any) -> None:
        self._ledger = ledger
        self._module = module
        self._real = real

    def __getattr__(self, name: str) -> Any:
        real = getattr(self._real, name)
        if name.startswith("__"):
            return real
        return self._ledger.route(self._module, name, real)


def _install_seams(patch: pytest.MonkeyPatch, ledger: _ResourceLedger) -> None:
    """The reviewed seams, through ``windows_process_module.subprocess`` only: no
    subprocess import here and no production import root or launch changes."""
    launch_module: Any = windows_process_module.subprocess  # type: ignore[attr-defined]
    namespace = vars(launch_module)
    kernel32 = _LedgerKernel32(ledger, windows_api._kernel32)
    patch.setattr(windows_api, "_kernel32", lambda: kernel32)
    ledger.real_close_handle = namespace["_winapi"].CloseHandle
    ledger.real_os_close = namespace["os"].close
    ledger.real_get_osfhandle = namespace["msvcrt"].get_osfhandle
    for module in _STDLIB_ROUTE:
        proxy = _RouteProxy(ledger, module, namespace[module])
        patch.setattr(launch_module, module, proxy)
    close = namespace["Handle"].Close
    (real_close,) = close.__defaults__
    patch.setattr(close, "__defaults__", (ledger.popen_close(real_close),))
    ledger.monitor = _SiteMonitor()


def _require_zero_unaccounted(
    operation: _Operation, *, retained: Mapping[int, str] | None = None
) -> None:
    """R2 under the owner ruling of 2026-11-14 (module docstring): every resource the
    operation acquired through a reviewed creator or the standard-library launch route
    ended in a real successful close or is retained, still open, by its named owner --
    exactly zero unaccounted, no tolerance, and no unclassified route. The verdict and
    its record are taken first; the live table count is collected only afterwards, as
    a diagnostic recorded beside it (a failed collection included) that decides
    nothing."""
    problems = operation.ledger.audit(operation, retained)
    acquired = [item.describe() for item in operation.acquired]
    released_by = [item.released_by for item in operation.acquired]
    live_after = _diagnostic_handle_count()
    _EVIDENCE.record_ledger(operation, acquired, released_by, problems, live_after)
    assert problems == [], (
        "unaccounted resources: "
        + "; ".join(problems)
        + f" (live table {operation.live_before} -> {live_after}, diagnostic only)"
    )


def _require_observed(operation: _Operation, expected: Iterable[str]) -> None:
    """The route really ran: exactly these acquisitions by class and stream, so a
    zero is never vacuous."""
    observed = sorted(item.kind for item in operation.acquired)
    assert observed == sorted(expected), observed


def _require_receivers(operation: _Operation, expected: Iterable[str]) -> None:
    """The construction really ran through its receiver sites under the monitor: at
    least these executed (each judged; the audit fails on any problem), so the
    monitor's zero is never vacuous."""
    assert operation.monitored, operation.name
    missing = sorted(set(expected) - {label for label, _ in operation.sites})
    assert missing == [], missing


def _launch_retention(
    ledger: _ResourceLedger, launched: WindowsLaunchedProcess
) -> dict[int, str]:
    """What a launch deliberately retains, by generation, each with the owner whose
    established lifetime ends it: the process and job handles until ``close``, both pipe
    read ends until the flagged ``close``, the ``Popen`` handle with its object."""
    owners: dict[int, tuple[str, str]] = {
        launched.process_handle: ("process", "process_handle"),
        int(vars(launched._popen)["_handle"]): ("popen_process", "Popen._handle"),
        ledger.real_get_osfhandle(launched.stdout.fileno()): (
            "pipe_read:stdout",
            "stdout",
        ),
        ledger.real_get_osfhandle(launched.stderr.fileno()): (
            "pipe_read:stderr",
            "stderr",
        ),
    }
    if launched.job_handle is not None:
        owners[launched.job_handle] = ("job", "job_handle")
    retained: dict[int, str] = {}
    for value, (kind, owner) in owners.items():
        resource = ledger.live(value)
        assert resource.kind == kind, (resource.describe(), owner)
        retained[resource.generation] = owner
    return retained


def _require_retained(ledger: _ResourceLedger, retained: Mapping[int, str]) -> None:
    """Every retained resource is still open under its owner: nothing closed early."""
    ledger.settle()
    ended = [
        ledger.resources[generation].describe()
        for generation in retained
        if ledger.resources[generation].state not in ("open", "crt")
    ]
    assert ended == [], ended


def _require_released(ledger: _ResourceLedger, retained: Mapping[int, str]) -> None:
    """Every retained resource ended at its established boundary by a real close."""
    ledger.settle()
    still_open = [
        ledger.resources[generation].describe()
        for generation in retained
        if ledger.resources[generation].state != "released"
    ]
    assert still_open == [], still_open


class _UnrelatedChurn:
    """Handle lifetimes no operation owns, inside its accounting window: a kernel32
    handle acquired through the reviewed seam before the window is closed inside it,
    and files opened outside every seam inside the window stay open across its
    boundary."""

    def __init__(self) -> None:
        self._handles: list[int] = []
        self._files: list[IO[bytes]] = []
        self.steps = 0

    def prepare(self) -> None:
        self._handles.append(open_process_limited(os.getpid()))

    def step(self) -> None:
        for handle in self._handles:
            close_handle(handle)
        self._handles = []
        self._files.extend(Path(os.devnull).open("rb", buffering=0) for _ in range(2))
        self.steps += 1

    def close(self) -> None:
        for handle in self._handles:
            with suppress(WindowsApiError):
                close_handle(handle)
        for file in self._files:
            file.close()


class _TimedOutThenAbsent:
    """Natural-exit negative control 6's stand-in for a launched process, with no
    process behind it: its bounded wait observes no exit, its identity names no
    process (so a fresh inspection is ``ABSENT``) and its zero-duration wait would
    report ``0``."""

    def __init__(self) -> None:
        self.pid = 3
        self.creation_identity = render_creation_identity(3, 1)
        self.waits: list[float] = []

    def wait(self, timeout_seconds: float) -> int | None:
        self.waits.append(timeout_seconds)
        return None if timeout_seconds > 0 else 0


class _TrackingController:
    """Delegates to a ``WindowsProcessController`` and owns, as pid plus creation
    identity, every process the tests launch or take over -- the launcher, every
    Toolhelp-verified descendant recorded while the launcher lives, and any pid a child
    program reported -- so that each tree is ended once through the committed path, its
    report held to the ruling's closed oracle and every identity proved ``ABSENT``: in
    the test body through ``shape``, ``ended`` and ``terminate_owned``, otherwise in the
    fixture's ``finally`` through ``cleanup``."""

    def __init__(self, controller: WindowsProcessController) -> None:
        self.controller = controller
        self.launched: list[WindowsLaunchedProcess] = []
        self.owned: dict[tuple[int, str], ProcessIdentity] = {}
        #: Every identity a committed tree termination has already covered.
        self.terminated: set[tuple[int, str]] = set()

    def launch(
        self, specification: LaunchSpecification
    ) -> WindowsLaunchedProcess | LaunchFailure:
        result = self.controller.launch(specification)
        if isinstance(result, WindowsLaunchedProcess):
            self.launched.append(result)
            self.own(process_identity_for(result))
        return result

    def inspect(self, identity: ProcessIdentity) -> ProcessInspection:
        return self.controller.inspect(identity)

    def terminate_tree(
        self, identity: ProcessIdentity, exit_code: int
    ) -> TerminationReport:
        return self.controller.terminate_tree(identity, exit_code)

    def own(self, identity: ProcessIdentity) -> ProcessIdentity:
        """Record an identity (pid plus creation identity) the cleanup accounts for."""
        self.owned[(identity.pid, identity.creation_identity)] = identity
        return identity

    def own_descendants(
        self, launched: WindowsLaunchedProcess, *, expect: int | None = None
    ) -> tuple[DescendantIdentity, ...]:
        """Own every Toolhelp-verified live descendant of a launch while the launcher
        lives (a ready launcher has at least its interpreter child); with ``expect``,
        the pid a program reported must be among them."""
        creation = parse_creation_identity(launched.creation_identity).creation_100ns
        descendants = descendants_of(launched.pid, creation)
        assert descendants, "a ready launcher has at least its interpreter child"
        if expect is not None:
            assert expect in {item.pid for item in descendants}
        for item in descendants:
            self.own(identity_for(item.pid, item.creation_identity))
        return descendants

    def ready(self, launched: WindowsLaunchedProcess) -> tuple[DescendantIdentity, ...]:
        """Wait, bounded, for the child's readiness line, then own the live tree: the
        one call a job-less test makes before any destructive action."""
        _ready(launched)
        return self.own_descendants(launched)

    def adopt(self, identity: ProcessIdentity) -> tuple[DescendantIdentity, ...]:
        """Own the verified live descendants of an owned identity (a reported sleeper's
        interpreter) while their parent lives, before anything may strand them."""
        creation = parse_creation_identity(identity.creation_identity).creation_100ns
        descendants = descendants_of(identity.pid, creation)
        assert descendants, f"{identity.creation_identity} has no descendant to adopt"
        for item in descendants:
            self.own(identity_for(item.pid, item.creation_identity))
        return descendants

    def release(self, launched: WindowsLaunchedProcess) -> None:
        """Forget a launched process whose tree a committed termination ended and whose
        owned handles ``close`` released, so that its retained ``Popen`` handle ends
        with the object (its established lifetime); its identities stay owned and are
        still judged by ``cleanup``."""
        root = process_identity_for(launched)
        assert (root.pid, root.creation_identity) in self.terminated
        assert launched.close(close_stdout=True, close_stderr=True).complete
        self.launched.remove(launched)

    def _mark(self, identities: Iterable[ProcessIdentity]) -> None:
        for identity in identities:
            self.terminated.add((identity.pid, identity.creation_identity))

    def shape(self, report: TerminationReport, *, origin: str = "body") -> str:
        """The closed oracle over a real termination's report (``_accepted_shape``),
        asserted and recorded for the ledger."""
        shape = _accepted_shape(report)
        _EVIDENCE.record(shape, origin=origin)
        return shape

    def ended(
        self,
        launched: WindowsLaunchedProcess,
        report: TerminationReport,
        identities: Iterable[ProcessIdentity] | None = None,
        *,
        dictated_reason: str | None = None,
    ) -> None:
        """The end of the bounded path once a tree's termination returned its report:
        the root's existing bounded wait under the ruling's contract (``_native_exit``;
        ``dictated_reason`` names the one reason a fake dictated for every kill target
        at a fault-injected site), then one fresh inspection of every identity -- by
        default the root and every descendant the report enumerated -- which must be
        ``ABSENT`` (``_absent``)."""
        chosen = list(
            _tree_identities(launched, report) if identities is None else identities
        )
        _native_exit(
            launched.wait(POST_TERMINATION_WAIT_SECONDS),
            report,
            dictated_reason=dictated_reason,
        )
        for identity in chosen:
            _absent(identity)
        self._mark(chosen)

    def terminate_owned(self, identity: ProcessIdentity) -> TerminationReport:
        """The one identity-bound termination of a tree the tracker owns but no launched
        process can end (a job-less root after its handle closed, a sleeper a child
        program reported): the controller path exactly once -- it verifies the creation
        time on the opened handle first, so a reused pid is never touched -- its report
        held to the closed oracle, then the root and every enumerated descendant proved
        ``ABSENT``."""
        key = (identity.pid, identity.creation_identity)
        assert key not in self.terminated, (
            f"{identity.creation_identity} terminated once already"
        )
        report = WindowsProcessController().terminate_tree(
            identity, FORCED_TERMINATION_EXIT_CODE
        )
        _EVIDENCE.record_phase(  # beside "adopted": the owned set's budget evidence
            "terminated_owned",
            root=identity.creation_identity,
            reported=[item.creation_identity for item in report.descendants],
        )
        self.shape(report, origin="owned")
        tree = [
            identity,
            *(
                self.own(identity_for(item.pid, item.creation_identity))
                for item in report.descendants
            ),
        ]
        for each in tree:
            _absent(each)
        self._mark(tree)
        return report

    def _end_root(self, launched: WindowsLaunchedProcess) -> None:
        """Cleanup's one termination of a launched root the test did not end."""
        root = process_identity_for(launched)
        if (root.pid, root.creation_identity) in self.terminated:
            return
        presence = self.controller.inspect(root).presence
        if presence is not ProcessPresence.ALIVE_MATCHING:
            return
        report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
        _EVIDENCE.record_phase(
            "cleanup_terminated_root",
            root=root.creation_identity,
            reported=[item.creation_identity for item in report.descendants],
        )
        self._mark(_tree_identities(launched, report))
        for item in report.descendants:
            self.own(identity_for(item.pid, item.creation_identity))
        self.shape(report, origin="cleanup")

    def cleanup(self) -> None:
        """The fixture's ``finally`` (the ruling's section 1). A launched root the test
        did not end is ended once through its own tree termination and its report held
        to the closed oracle; every owned pipe, job and process handle is closed; an
        owned identity outside every terminated tree that is still ``ALIVE_MATCHING`` is
        ended once through the identity-bound controller path; then every owned identity
        is judged exactly as the body judges one -- ``ABSENT`` after its own committed
        bounded wait (``_absent``), never by an inspection taken before that wait. An
        identity that is not ``ABSENT`` then is a survivor: it fails the test by name
        and, the test having failed, is ended through the identity-bound path so no
        orphan outlives the module -- never cleaned and passed."""
        fresh = WindowsProcessController()
        failures: list[str] = []
        try:
            for launched in self.launched:
                try:
                    self._end_root(launched)
                except AssertionError as error:
                    failures.append(str(error))
                finally:
                    launched.close(close_stdout=True, close_stderr=True)
        finally:
            for key, identity in list(self.owned.items()):
                if key in self.terminated:
                    continue  # covered by a termination: judged below, after its wait
                if fresh.inspect(identity).presence is ProcessPresence.ALIVE_MATCHING:
                    try:
                        self.terminate_owned(identity)
                    except AssertionError as error:
                        failures.append(str(error))
            for identity in list(self.owned.values()):
                try:
                    _absent(identity)
                except AssertionError as error:
                    failures.append(
                        f"{identity.creation_identity} survived its termination:"
                        f" {error}"
                    )
                    presence = fresh.inspect(identity).presence
                    if presence is ProcessPresence.ALIVE_MATCHING:
                        fresh.terminate_tree(identity, FORCED_TERMINATION_EXIT_CODE)
            for reader in _claim_setup_readers(self.owned):
                # Only a reader whose bounded setup read expired (cancelled then).
                # After the existing terminations and absence waits above its writers
                # are gone, so a zero-duration look establishes that it ended: no
                # join and no new observation window.
                _EVIDENCE.record_phase(
                    "setup_reader_claimed",
                    root=reader.root,
                    alive=reader.thread.is_alive(),
                    lines=len(reader.lines),
                    errors=reader.errors,
                )
                if not _end_setup_reader_ownership(reader):
                    # still owned and discoverable in the registry: the autouse check
                    # transfers it, so a failed look never drops a live reader
                    failures.append(f"the setup reader of {reader.root} did not end")
            owned = sorted(item.creation_identity for item in self.owned.values())
            _EVIDENCE.record_resources(self.launched, owned=owned)
            assert failures == [], chr(10).join(failures)


class _TerminateSpy:
    """Observes the ``TerminateProcess`` boundary on a real child: every call's handle
    is checked unsignaled at call time, then the real call is made."""

    def __init__(self) -> None:
        self.calls: list[tuple[int, bool]] = []
        self._real = windows_api.terminate_process

    def __call__(self, handle: int, exit_code: int) -> None:
        self.calls.append((exit_code, not wait_for_handle(handle, 0.0)))
        self._real(handle, exit_code)


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


@pytest.fixture
def tmp_root(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    root.mkdir()
    return root


@pytest.fixture(autouse=True, scope="module")
def _shape_evidence(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[_ShapeEvidence]:
    """Writes which accepted shape every termination site observed (``shapes.jsonl``
    in a ``termination-shapes*`` directory under pytest's base temporary directory)
    once the module's last test has run: evidence for the ledger, not an oracle."""
    try:
        yield _EVIDENCE
    finally:
        unended = [reader.root for reader in _UNENDED_SETUP_READERS]
        if unended:  # still owned and discoverable here, recorded for the ledger
            _EVIDENCE.record_phase("unended_setup_readers_at_module_end", roots=unended)
        _EVIDENCE.write(tmp_path_factory.mktemp("termination-shapes"))


@pytest.fixture(autouse=True)
def _shape_site(request: pytest.FixtureRequest) -> None:
    """Names the running test in the shape evidence."""
    _EVIDENCE.site = request.node.nodeid


@pytest.fixture(autouse=True)
def _setup_reader_ownership() -> Iterator[None]:
    """A setup reader whose bounded read expired must be released by a fixture cleanup
    that established its end; one still reading when its test ends fails that test by
    name (fail closed) and stays owned, transferred to ``_UNENDED_SETUP_READERS``. No
    wait is added."""
    yield
    _check_setup_reader_ownership()


def _check_setup_reader_ownership() -> None:
    """The autouse ownership check at the end of one test (``_setup_reader_ownership``),
    zero-duration looks only. A reader an earlier test's check transferred is released
    once its end is established and otherwise kept (its own test already failed by it).
    A reader of this test whose end is established is released; one still reading is
    transferred explicitly to ``_UNENDED_SETUP_READERS`` -- owned and discoverable --
    and fails this test by name."""
    for reader in list(_UNENDED_SETUP_READERS):
        _end_setup_reader_ownership(reader)
    alive: list[tuple[int, str] | None] = []
    for reader in list(_SETUP_READERS):
        if not _end_setup_reader_ownership(reader):
            _UNENDED_SETUP_READERS.append(reader)  # the transfer, before the removal
            _SETUP_READERS.remove(reader)
            alive.append(reader.root)
    assert alive == [], f"setup readers outlived their test unowned: {alive}"


@pytest.fixture(autouse=True)
def resource_ledger() -> Iterator[_ResourceLedger]:
    """The reviewed seams for every test of this module, on their own patch so that a
    test's ``monkeypatch.undo()`` never removes them: every launch records its resume
    and its acquisitions (evidence everywhere), and the ledger is an oracle only where
    a test asks it at an accounting boundary."""
    ledger = _ResourceLedger()
    with pytest.MonkeyPatch.context() as patch:
        _install_seams(patch, ledger)
        yield ledger


def _tracking(
    job_object_factory: Callable[[], int] | None,
) -> Generator[_TrackingController, None, None]:
    """The one body behind both controller fixtures: ``cleanup`` runs in ``finally`` on
    normal completion, an assertion failure, a helper failure, a timeout or a partial
    setup (a regression test unwinds this generator with an exception to prove it)."""
    controller = (
        WindowsProcessController()
        if job_object_factory is None
        else WindowsProcessController(job_object_factory=job_object_factory)
    )
    tracking = _TrackingController(controller)
    try:
        yield tracking
    finally:
        tracking.cleanup()


@pytest.fixture
def controller() -> Iterator[_TrackingController]:
    yield from _tracking(None)


@pytest.fixture
def controller_without_job() -> Iterator[_TrackingController]:
    yield from _tracking(_failing_job_factory)


# --------------------------------------------------------------------------
# The plan's Step 1 sketch, verbatim (fixture parameters annotated for strict mypy;
# the plan's `and` assertions split for PT018 with every clause kept in order)
# --------------------------------------------------------------------------


def test_a_launched_process_has_a_parsable_creation_identity_and_is_in_our_job(
    controller: _TrackingController, tmp_root: Path
) -> None:
    launched = started(
        controller.launch(
            spec_for(
                [sys.executable, "-I", "-B", "-c", "import time; time.sleep(30)"],
                cwd=tmp_root,
            )
        )
    )
    try:
        identity = parse_creation_identity(launched.creation_identity)
        assert identity.pid == launched.pid
        assert is_process_in_job(launched.process_handle, launched.job_handle)
        assert (
            controller.inspect(process_identity_for(launched)).presence
            is ProcessPresence.ALIVE_MATCHING
        )
    finally:
        report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
        controller.shape(report)
        controller.ended(launched, report)
        launched.close(close_stdout=True, close_stderr=True)


def test_forced_termination_reports_the_constant_as_the_native_exit(
    controller: _TrackingController, tmp_root: Path
) -> None:
    launched = started(controller.launch(sleep_spec(tmp_root)))
    report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    assert report.forced  # PT018: the plan's `and` split
    assert report.exit_code_used == 1067
    # The plan's `report.failures == ()` and `launched.wait(5.0) == 1067`, under the
    # ruling's closed oracle and wait contract (module docstring).
    controller.shape(report)
    controller.ended(launched, report)
    assert launched.close(close_stdout=True, close_stderr=True).complete


def test_terminating_an_already_exited_root_reports_no_failure(
    controller: _TrackingController, tmp_root: Path
) -> None:
    launched = started(
        controller.launch(
            spec_for([sys.executable, "-I", "-B", "-c", "pass"], cwd=tmp_root)
        )
    )
    _exited(launched, 0)  # R1: the plan's `launched.wait(5.0) == 0`
    assert (
        launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE).failures == ()
    )  # access denied on a dead process is not a failure


def test_launch_returns_a_launched_process_or_a_launch_failure_and_never_raises(
    controller: _TrackingController, tmp_root: Path
) -> None:
    result = controller.launch(sleep_spec(tmp_root))
    assert isinstance(result, LaunchedProcess)  # PT018: the plan's `and` split
    assert not isinstance(result, LaunchFailure)
    report = result.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    controller.shape(report)
    controller.ended(result, report)
    result.close(close_stdout=True, close_stderr=True)


def test_cancel_read_unblocks_a_reader_whose_pipe_a_grandchild_still_holds(
    controller_without_job: _TrackingController, tmp_root: Path
) -> None:
    acknowledgement = tmp_root / _ACKNOWLEDGEMENT
    assert not acknowledgement.exists()  # unique to this fixture root, absent at launch
    launched = started(
        controller_without_job.launch(
            program_spec(SPAWNS_A_SLEEPER_INHERITING_STDOUT_AND_EXITS, cwd=tmp_root)
        )
    )
    # printed after the sleeper's ``ready`` line
    sleeper = _pid_line(launched.stderr, launched=launched)
    # The sleeper's launcher has passed its resume window (its interpreter printed the
    # readiness line the fake waited for), and the intermediate parent waits for the
    # acknowledgement: bind the sleeper and adopt its tree now, while all of it lives,
    # and only then acknowledge (plan Step 3).
    sleeper_identity = controller_without_job.own(live_identity_for(sleeper))
    adopted = controller_without_job.adopt(sleeper_identity)
    _EVIDENCE.record_phase(
        "adopted",
        root=launched.creation_identity,
        sleeper=sleeper_identity.creation_identity,
        adopted=[item.creation_identity for item in adopted],
    )
    acknowledgement.touch()
    try:
        reader = PipeReader(
            launched.stdout, capacity=QUEUE_CAPACITY_CHUNKS, stop=threading.Event()
        )  # Task 3's reader, owned by the test here
        reader.start()
        _exited(launched, 0)  # the root is gone; the sleeper holds the write end
        reader.join(READER_JOIN_SECONDS)
        _EVIDENCE.record_phase("reader_after_exit", alive=reader.is_alive())
        assert reader.is_alive()  # blocked inside ReadFile: exactly the §6.7 case
        assert reader.native_thread_id is not None  # Task 3 review F9: the narrow
        assert launched.cancel_read(reader.native_thread_id) is True
        reader.join(READER_JOIN_SECONDS)
        assert not reader.is_alive()  # PT018: the plan's `and` split
        assert reader.ended_by is ReaderEnd.CANCELLED
        assert launched.close(close_stdout=True, close_stderr=True).complete
    finally:
        # the job-less controller cannot reach it: the identity-bound path, once
        controller_without_job.terminate_owned(sleeper_identity)


def test_a_child_that_exits_with_259_is_absent_not_alive(
    controller: _TrackingController, tmp_root: Path
) -> None:
    launched = started(
        controller.launch(
            spec_for(
                [sys.executable, "-I", "-B", "-c", "raise SystemExit(259)"],
                cwd=tmp_root,
            )
        )
    )
    _exited(launched, 259)  # R1: the plan's `launched.wait(5.0) == 259`
    assert (
        controller.inspect(process_identity_for(launched)).presence
        is ProcessPresence.ABSENT
    )  # the handle is signaled; 259 is not liveness
    assert launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE).failures == ()
    assert launched.close(close_stdout=True, close_stderr=True).complete


def test_a_job_kill_of_a_two_process_tree_reports_no_failure(
    controller: _TrackingController, tmp_root: Path
) -> None:
    launched = started(
        controller.launch(
            program_spec(SPAWNS_A_SLEEPER_AND_PRINTS_ITS_PID, cwd=tmp_root)
        )
    )
    grandchild = int(launched.stdout.readline())
    report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    assert report.job_terminated  # PT018: the plan's `and` split
    controller.shape(report)  # the plan's `report.failures == ()`
    assert grandchild in {d.pid for d in report.descendants}
    controller.ended(launched, report)  # the plan's `launched.wait(5.0) == 1067`
    assert inspect_pid(grandchild) is ProcessPresence.ABSENT
    assert inspect_descendant(report, grandchild) is ProcessPresence.ABSENT


def test_an_interrupt_reaches_a_child_that_handles_sigbreak(
    controller: _TrackingController, tmp_root: Path
) -> None:
    # HANDLER_EXITS_50_THEN_SLEEPS installs the handler and then loops
    # `time.sleep(0.1)`: a Python SIGBREAK handler runs only between bytecodes, never
    # inside one long sleep.
    assert console_process_count() >= 1, (
        "the test process is not attached to a console; CTRL_BREAK cannot be generated"
    )
    launched = started(
        controller.launch(
            spec_for(
                [sys.executable, "-I", "-B", "-c", HANDLER_EXITS_50_THEN_SLEEPS],
                cwd=tmp_root,
            )
        )
    )
    _ready(launched)  # the handler is installed and the loader has finished
    assert launched.interrupt() is InterruptOutcome.DELIVERED
    _exited(launched, 50)  # R1: the plan's `launched.wait(5.0) == 50`


def test_a_missing_executable_is_an_availability_failure_not_an_exception(
    controller: _TrackingController, tmp_root: Path
) -> None:
    failure = controller.launch(
        spec_for(["C:\\nowhere\\absent.exe", "describe"], cwd=tmp_root)
    )
    assert isinstance(failure, LaunchFailure)  # PT018: the plan's `and` split
    assert failure.not_found
    assert failure.stage == "popen"  # winerror 2 or 3
    denied = controller.launch(spec_for([str(tmp_root), "describe"], cwd=tmp_root))
    assert isinstance(denied, LaunchFailure)  # PT018: the plan's `and` split
    assert not denied.not_found  # a directory is not an image


def test_a_reused_pid_is_not_ours() -> None:
    identity = identity_for_own_process(
        creation=own_creation() - 1
    )  # our pid, a creation time one tick earlier
    assert (
        WindowsProcessController().inspect(identity).presence
        is ProcessPresence.ALIVE_DIFFERENT_IDENTITY
    )


def test_the_toolhelp_fallback_terminates_a_verified_grandchild(
    controller_without_job: _TrackingController, tmp_root: Path
) -> None:
    launched = started(
        controller_without_job.launch(
            program_spec(SPAWNS_A_SLEEPER_AND_PRINTS_ITS_PID, cwd=tmp_root)
        )
    )
    grandchild = _pid_line(launched.stdout, launched=launched)
    controller_without_job.own_descendants(launched, expect=grandchild)
    report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    assert grandchild in {d.pid for d in report.descendants}
    assert not report.job_terminated
    controller_without_job.shape(report)
    controller_without_job.ended(launched, report)  # the plan's `wait(5.0) == 1067`
    assert inspect_pid(grandchild) is not ProcessPresence.ALIVE_MATCHING
    assert inspect_descendant(report, grandchild) is ProcessPresence.ABSENT


# --------------------------------------------------------------------------
# The plan's "plus" items
# --------------------------------------------------------------------------


def _popen_calls(tree: ast.AST) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "Popen"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
    ]


def _is_subprocess_attribute(node: ast.AST | None, attribute: str) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == attribute
        and isinstance(node.value, ast.Name)
        and node.value.id == "subprocess"
    )


def _popen_pin_violations(tree: ast.AST, source_lines: list[str]) -> list[str]:
    """Plan 8.2 and 11: the exact shape of the one ``Popen`` call, by AST."""
    calls = _popen_calls(tree)
    if len(calls) != 1:
        return [f"expected exactly one Popen call, found {len(calls)}"]
    (call,) = calls
    violations: list[str] = []
    if not (
        len(call.args) == 1
        and isinstance(call.args[0], ast.Call)
        and isinstance(call.args[0].func, ast.Name)
        and call.args[0].func.id == "list"
    ):
        violations.append("argv is not list(...)")
    keywords = {keyword.arg: keyword.value for keyword in call.keywords}
    expected_constants = {"shell": False, "bufsize": 0, "close_fds": True}
    for name, expected in expected_constants.items():
        value = keywords.get(name)
        if not (isinstance(value, ast.Constant) and value.value is expected):
            violations.append(f"{name} is not the constant {expected!r}")
    env = keywords.get("env")
    if not (isinstance(env, ast.Dict) and env.keys == []):
        violations.append("env is not the empty mapping literal")
    if "cwd" not in keywords:
        violations.append("cwd is not passed")
    for name, attribute in (
        ("stdin", "DEVNULL"),
        ("stdout", "PIPE"),
        ("stderr", "PIPE"),
    ):
        if not _is_subprocess_attribute(keywords.get(name), attribute):
            violations.append(f"{name} is not subprocess.{attribute}")
    flags = keywords.get("creationflags")
    if not (
        isinstance(flags, ast.BinOp)
        and isinstance(flags.op, ast.BitOr)
        and _is_subprocess_attribute(flags.left, "CREATE_NEW_PROCESS_GROUP")
        and isinstance(flags.right, ast.Name)
        and flags.right.id == "CREATE_SUSPENDED"
    ):
        violations.append(
            "creationflags is not "
            "subprocess.CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED"
        )
    if _NOQA_TEXT not in source_lines[call.lineno - 1]:
        violations.append("the reviewed noqa text is missing from the Popen line")
    return violations


def _windows_process_source() -> str:
    source = windows_process_module.__file__
    assert source is not None
    return Path(source).read_text(encoding="utf-8")


def test_the_one_popen_call_has_exactly_the_reviewed_shape() -> None:
    source = _windows_process_source()
    assert _popen_pin_violations(ast.parse(source), source.splitlines()) == []
    assert CREATE_SUSPENDED == 4


_POPEN_TEMPLATE: Final = (
    "import subprocess\n"
    "subprocess.Popen(list(a), shell=False, env=<ENV>, cwd=c, "
    "stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, "
    "bufsize=0, close_fds=True, creationflags=<FLAGS>)"
    "  # noqa: S603 - reviewed fixed catalog executable boundary\n"
)
_REVIEWED_FLAGS: Final = "subprocess.CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED"


def _popen_source(*, env: str, flags: str) -> str:
    return _POPEN_TEMPLATE.replace("<ENV>", env).replace("<FLAGS>", flags)


@pytest.mark.parametrize(
    "planted",
    [
        "import subprocess\nsubprocess.Popen('x', shell=True)\n",
        "import subprocess\nsubprocess.Popen(list(a), shell=False, env={}, cwd=c)\n",
        "import subprocess\nsubprocess.Popen(list(a))\nsubprocess.Popen(list(a))\n",
        _popen_source(env="{'A': 'b'}", flags=_REVIEWED_FLAGS),
        _popen_source(env="{}", flags="subprocess.CREATE_NEW_PROCESS_GROUP"),
        _popen_source(env="{}", flags=_REVIEWED_FLAGS).replace("  # noqa", "  #"),
    ],
)
def test_the_popen_pin_rejects_every_planted_deviation(planted: str) -> None:
    assert _popen_pin_violations(ast.parse(planted), planted.splitlines()) != []


def test_the_popen_pin_accepts_the_exact_reviewed_shape_as_a_control() -> None:
    accepted = _popen_source(env="{}", flags=_REVIEWED_FLAGS)
    assert _popen_pin_violations(ast.parse(accepted), accepted.splitlines()) == []


def test_inspect_of_a_finished_process_is_absent(
    controller: _TrackingController, tmp_root: Path
) -> None:
    launched = started(
        controller.launch(
            spec_for([sys.executable, "-I", "-B", "-c", "pass"], cwd=tmp_root)
        )
    )
    _exited(launched, 0)  # R1
    inspection = controller.inspect(process_identity_for(launched))
    assert inspection.presence is ProcessPresence.ABSENT
    assert not isinstance(inspection.observed_creation_identity, str)
    assert not isinstance(inspection.observed_image_path, str)


def test_the_interpreter_the_launcher_spawns_is_inside_the_supervisor_job(
    controller: _TrackingController, tmp_root: Path
) -> None:
    """The positive control for the suspended launch: the venv launcher's child is
    created only after the job assignment, so its membership is deterministic."""
    launched = started(controller.launch(sleep_spec(tmp_root)))
    creation = parse_creation_identity(launched.creation_identity).creation_100ns
    found: list[int] = []

    def interpreter_appeared() -> bool:
        found[:] = [item.pid for item in descendants_of(launched.pid, creation)]
        return bool(found)

    assert _wait_until(interpreter_appeared), "the launcher spawned no interpreter"
    for pid in found:
        handle = open_process_limited(pid)
        try:
            assert is_process_in_job(handle, launched.job_handle)
        finally:
            close_handle(handle)
    # a root "created later" than every child owns nothing: the creation-time guard
    assert descendants_of(launched.pid, 2**62) == ()


def test_after_a_job_kill_terminate_process_reaches_no_signaled_handle(
    controller: _TrackingController, tmp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Plan 8.3: after ``TerminateJobObject`` returned TRUE the job tears its members
    down asynchronously; ``TerminateProcess`` is attempted only on a verified handle
    still unsignaled after the bounded wait."""
    spy = _TerminateSpy()
    monkeypatch.setattr(windows_api, "terminate_process", spy)
    launched = started(
        controller.launch(
            program_spec(SPAWNS_A_SLEEPER_AND_PRINTS_ITS_PID, cwd=tmp_root)
        )
    )
    int(launched.stdout.readline())
    report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    assert report.job_terminated
    controller.shape(report)
    assert len(report.descendants) >= 2
    assert all(unsignaled for _, unsignaled in spy.calls)
    controller.ended(launched, report)


def test_without_a_job_terminate_process_is_attempted_only_on_unsignaled_handles(
    controller_without_job: _TrackingController,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spy = _TerminateSpy()
    monkeypatch.setattr(windows_api, "terminate_process", spy)
    launched = started(
        controller_without_job.launch(
            program_spec(SPAWNS_A_SLEEPER_AND_PRINTS_ITS_PID, cwd=tmp_root)
        )
    )
    int(launched.stdout.readline())
    report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    assert not report.job_terminated
    controller_without_job.shape(report)
    assert 1 <= len(spy.calls) <= 1 + len(report.descendants)
    assert all(
        exit_code == FORCED_TERMINATION_EXIT_CODE and unsignaled
        for exit_code, unsignaled in spy.calls
    )
    controller_without_job.ended(launched, report)


# --------------------------------------------------------------------------
# Surface and structure
# --------------------------------------------------------------------------


def test_the_module_exports_exactly_the_two_classes_and_they_satisfy_the_ports(
    controller: _TrackingController, tmp_root: Path
) -> None:
    assert windows_process_module.__all__ == [
        "WindowsLaunchedProcess",
        "WindowsProcessController",
    ]
    assert isinstance(controller.controller, ProcessController)
    launched = started(controller.launch(sleep_spec(tmp_root)))
    assert isinstance(launched, LaunchedProcess)
    assert not issubclass(WindowsLaunchedProcess, BaseModel)
    assert not hasattr(launched, "model_dump")
    for name in (
        "pid",
        "creation_identity",
        "stdout",
        "stderr",
        "job_available",
        "job_error_code",
        "image_path",
    ):
        assert isinstance(vars(WindowsLaunchedProcess)[name], property), name
    assert isinstance(launched.process_handle, int)
    assert launched.process_handle > 0
    assert isinstance(launched.job_handle, int)
    assert launched.job_handle > 0
    assert launched.job_available is True
    assert not isinstance(launched.job_error_code, int)
    assert isinstance(launched.image_path, str)
    assert Path(launched.image_path).samefile(sys.executable)
    text = repr(launched)
    assert str(launched.process_handle) not in text
    assert launched.image_path not in text


def test_the_module_imports_only_its_plan_roots_and_no_bare_forbidden_name() -> None:
    tree = ast.parse(_windows_process_source())
    roots: set[str] = set()
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.partition(".")[0])
                modules.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            roots.add(node.module.partition(".")[0])
            modules.add(node.module)
    assert roots == _PURE_ROOTS
    assert not roots & _DENIED_ROOTS
    for module in modules:
        assert not any(
            module == denied or module.startswith(denied + ".")
            for denied in _DENIED_PROJECT_MODULES
        ), module
    names = {
        node.id if isinstance(node, ast.Name) else node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Name | ast.Attribute)
    }
    assert not names & _STAGE4_BARE_NAMES
    source = _windows_process_source()
    assert "from __future__ import annotations" in source
    for denied_text in (
        "os.environ",
        "getenv",
        "datetime.now",
        "time.time",
        "sandbox",
    ):
        assert denied_text not in source, denied_text
    assert "a cleanup mechanism, never a security boundary" in source


# --------------------------------------------------------------------------
# Presence: the decision table beyond the sketch
# --------------------------------------------------------------------------


def test_this_process_with_its_true_creation_is_alive_matching_with_an_image() -> None:
    inspection = WindowsProcessController().inspect(
        identity_for_own_process(creation=own_creation())
    )
    assert inspection.presence is ProcessPresence.ALIVE_MATCHING
    assert inspection.observed_creation_identity == render_creation_identity(
        os.getpid(), own_creation()
    )
    assert isinstance(inspection.observed_image_path, str)
    assert inspection.observed_image_path.lower().endswith("python.exe")


def test_a_different_identity_carries_the_observed_identity_but_no_image_path() -> None:
    inspection = WindowsProcessController().inspect(
        identity_for_own_process(creation=own_creation() - 1)
    )
    assert inspection.presence is ProcessPresence.ALIVE_DIFFERENT_IDENTITY
    assert inspection.observed_creation_identity == render_creation_identity(
        os.getpid(), own_creation()
    )
    assert not isinstance(inspection.observed_image_path, str)


def test_a_malformed_or_mismatched_creation_identity_fails_closed() -> None:
    """The merged fixture shape, a pid disagreement and a foreign grammar are all
    ``UNDETERMINED`` -- never an exception, never ``ABSENT``, nothing opened."""
    controller = WindowsProcessController()
    pid = os.getpid()
    for identity in (
        sample_process_identity(),  # "2026-09-07T12:00:03.1234567Z#0001"
        identity_for(pid, f"offline-harness:{pid}"),
        identity_for(pid, render_creation_identity(pid + 4, own_creation())),
        identity_for(pid, "windows:1:01"),
    ):
        inspection = controller.inspect(identity)
        assert inspection.presence is ProcessPresence.UNDETERMINED, identity
        assert not isinstance(inspection.observed_creation_identity, str)
        assert not isinstance(inspection.observed_image_path, str)
        assert inspection.identity == identity


def test_an_absent_pid_is_absent_and_the_system_process_never_is() -> None:
    assert inspect_pid(3) is ProcessPresence.ABSENT
    system = WindowsProcessController().inspect(
        identity_for(4, render_creation_identity(4, 1))
    )
    assert system.presence in (
        ProcessPresence.UNDETERMINED,  # the open is refused: fail closed
        ProcessPresence.ALIVE_DIFFERENT_IDENTITY,  # the open succeeds: not ours
    )


def test_presence_ignores_the_executable_path_hash_and_supervisor_fields() -> None:
    """Plan 8.1: the image path is recorded, never compared."""
    creation = render_creation_identity(os.getpid(), own_creation())
    identity = ProcessIdentity(
        pid=os.getpid(),
        creation_identity=creation,
        executable_path="C:\\elsewhere\\other.exe",
        executable_hash="0" * 64,
        supervisor_instance_id="another-supervisor",
    )
    inspection = WindowsProcessController().inspect(identity)
    assert inspection.presence is ProcessPresence.ALIVE_MATCHING
    assert inspection.identity == identity
    assert inspection.observed_image_path != identity.executable_path


def test_the_open_failure_classifier_maps_only_invalid_parameter_to_absent() -> None:
    classify = windows_process_module._presence_of_open_failure
    assert classify(87) is ProcessPresence.ABSENT
    for code in (5, 6, 0, 1, 1450, 87 + 1):
        assert classify(code) is ProcessPresence.UNDETERMINED


# --------------------------------------------------------------------------
# Exit facts and interrupts
# --------------------------------------------------------------------------


def test_wait_polls_without_blocking_and_memoizes_the_first_reaped_value(
    controller: _TrackingController, tmp_root: Path
) -> None:
    launched = started(
        controller.launch(
            spec_for(
                [sys.executable, "-I", "-B", "-c", "raise SystemExit(7)"],
                cwd=tmp_root,
            )
        )
    )
    sleeper = started(controller.launch(sleep_spec(tmp_root)))
    assert sleeper.wait(0.0) is None
    _exited(launched, 7)  # R1
    assert launched.wait(0.0) == 7  # memoized
    # a reaped root never receives an event
    assert launched.interrupt() is InterruptOutcome.PROCESS_GONE


def test_wait_and_exit_code_bounds_are_checked_before_any_call(
    controller: _TrackingController, tmp_root: Path
) -> None:
    launched = started(controller.launch(sleep_spec(tmp_root)))
    for bad in (-0.5, float("nan"), float("inf")):
        with pytest.raises(ValueError, match="timeout_seconds"):
            launched.wait(bad)
    for bad_code in (-1, 2**32):
        with pytest.raises(ValueError, match="exit_code"):
            launched.terminate_tree(bad_code)
    with pytest.raises(ValueError, match="exit_code"):
        WindowsProcessController().terminate_tree(process_identity_for(launched), -1)


def test_a_handler_less_child_dies_on_the_interrupt_with_the_control_c_status(
    controller: _TrackingController, tmp_root: Path
) -> None:
    """Plan 2.5 reading 6: ``3221225786`` is what a default child reports after
    ``CTRL_BREAK``; distinct from ``50``, ``1067`` and ``259``."""
    assert console_process_count() >= 1
    launched = started(
        controller.launch(program_spec(_READY_SLEEPER_PROGRAM, cwd=tmp_root))
    )
    _ready(launched)  # initialized, no handler
    assert launched.interrupt() is InterruptOutcome.DELIVERED
    _exited(launched, _CONTROL_C_EXIT)  # R1


# --------------------------------------------------------------------------
# Launch facts and launch failures
# --------------------------------------------------------------------------


def test_a_failing_job_factory_reports_the_error_and_the_child_still_launches(
    controller_without_job: _TrackingController, tmp_root: Path
) -> None:
    launched = started(controller_without_job.launch(ready_sleep_spec(tmp_root)))
    controller_without_job.ready(launched)
    assert launched.job_available is False
    assert launched.job_error_code == 1450
    assert launched.job_handle is None
    assert is_process_in_job(launched.process_handle, launched.job_handle) is False
    assert (
        controller_without_job.inspect(process_identity_for(launched)).presence
        is ProcessPresence.ALIVE_MATCHING
    )
    report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    assert report.forced
    assert not report.job_terminated
    controller_without_job.shape(report)
    controller_without_job.ended(launched, report)
    closed = launched.close(close_stdout=True, close_stderr=True)
    assert closed.complete
    assert closed.completed == _FOUR_ACTIONS


def test_a_failing_job_assignment_is_reported_with_its_numeric_code(
    tmp_root: Path,
) -> None:
    tracking = _TrackingController(
        WindowsProcessController(job_object_factory=_null_job_factory)
    )
    try:
        launched = started(tracking.launch(ready_sleep_spec(tmp_root)))
        tracking.ready(launched)
        assert launched.job_available is False
        assert launched.job_error_code == _ERROR_INVALID_HANDLE
        assert launched.job_handle is None
    finally:
        tracking.cleanup()


def _defective_job_factory() -> int:
    raise RuntimeError("a defective factory, not an OSError")


def _non_integer_job_factory() -> int:
    return object()  # type: ignore[return-value]  # ctypes refuses it as a HANDLE


class _OpenSpy:
    """Records every handle ``open_process_limited`` hands out, then delegates."""

    def __init__(self) -> None:
        self.handles: list[int] = []
        self._real = windows_api.open_process_limited

    def __call__(
        self, pid: int, *, terminate: bool = False, set_quota: bool = False
    ) -> int:
        handle = self._real(pid, terminate=terminate, set_quota=set_quota)
        self.handles.append(handle)
        return handle


def _assert_every_descendant_of_this_process_is_absent() -> None:
    """After a launch abandoned on the controller's own bounded path
    (``_abandon_suspended``: terminate, then ``POST_TERMINATION_WAIT_SECONDS``), every
    Toolhelp-verified descendant of the test process -- pid plus creation identity --
    must be ``ABSENT`` after its own committed bounded wait (``_absent``; module
    docstring): a suspended child is never left behind, and the host's signalling speed
    is not the criterion."""
    for descendant in descendants_of(os.getpid(), own_creation()):
        _absent(identity_for(descendant.pid, descendant.creation_identity))


def _assert_every_handle_closed(handles: list[int]) -> None:
    assert handles, "the launch opened no process handle"
    for handle in handles:
        with pytest.raises(WindowsApiError) as caught:
            wait_for_handle(handle, 0.0)
        assert caught.value.winerror == _ERROR_INVALID_HANDLE


def test_a_defective_job_factory_propagates_but_leaves_no_suspended_child(
    tmp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Plan 8.2: a suspended child is never left behind, even when the failure is a
    caller defect rather than a Win32 error; the defect itself still surfaces, and
    the handle opened on the child is closed (review F1)."""
    spy = _OpenSpy()
    monkeypatch.setattr(windows_api, "open_process_limited", spy)
    controller = WindowsProcessController(job_object_factory=_defective_job_factory)
    with pytest.raises(RuntimeError, match="defective"):
        controller.launch(sleep_spec(tmp_root))
    _assert_every_descendant_of_this_process_is_absent()
    _assert_every_handle_closed(spy.handles)


def test_a_factory_returning_no_handle_propagates_and_closes_what_was_opened(
    tmp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review F1: the ``ctypes`` argument error from the job assignment is a defect,
    not a launch failure; it surfaces, the child dies, no handle stays open."""
    spy = _OpenSpy()
    monkeypatch.setattr(windows_api, "open_process_limited", spy)
    controller = WindowsProcessController(job_object_factory=_non_integer_job_factory)
    with pytest.raises(ctypes.ArgumentError):
        controller.launch(sleep_spec(tmp_root))
    _assert_every_descendant_of_this_process_is_absent()
    _assert_every_handle_closed(spy.handles)


def test_launch_failures_carry_a_class_name_and_a_number_but_never_a_path(
    controller: _TrackingController, tmp_root: Path
) -> None:
    absent = controller.launch(
        spec_for(["C:\\nowhere\\absent.exe", "describe"], cwd=tmp_root)
    )
    assert isinstance(absent, LaunchFailure)
    assert absent.os_error_code in (2, 3)
    assert absent.error_class == "FileNotFoundError"
    assert "nowhere" not in absent.model_dump_json()
    denied = controller.launch(spec_for([str(tmp_root), "describe"], cwd=tmp_root))
    assert isinstance(denied, LaunchFailure)
    assert denied.os_error_code == 5
    assert denied.error_class == "PermissionError"
    assert tmp_root.name not in denied.model_dump_json()


def test_a_launch_failure_leaves_no_child_and_no_extra_handle(
    controller: _TrackingController, tmp_root: Path, resource_ledger: _ResourceLedger
) -> None:
    with resource_ledger.operation("failed_construction") as construction:
        failure = controller.launch(
            spec_for(["C:\\nowhere\\absent.exe", "describe"], cwd=tmp_root)
        )
    assert isinstance(failure, LaunchFailure)
    # R2 (owner ruling of 2026-11-14; module docstring): the failed construction
    # acquired exactly these resources -- through a route whose census has no
    # unresolved site and whose receiver sites the monitor judged in this window --
    # released every one by a real close before ``Popen`` raised, retains nothing and
    # created no child (no process handle was ever returned) nor owns one.
    _require_observed(construction, _FAILED_CONSTRUCTION)
    _require_receivers(construction, _FAILED_CONSTRUCTION_RECEIVERS)
    _require_zero_unaccounted(construction)
    assert controller.launched == []
    assert controller.owned == {}


# --------------------------------------------------------------------------
# Handles and cleanup
# --------------------------------------------------------------------------


def test_close_closes_both_owned_handles_and_is_idempotent(
    controller: _TrackingController, tmp_root: Path
) -> None:
    launched = started(controller.launch(sleep_spec(tmp_root)))
    report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    controller.shape(report)
    controller.ended(launched, report)
    job_handle = launched.job_handle
    assert job_handle is not None
    first = launched.close(close_stdout=True, close_stderr=True)
    assert first.complete
    assert first.completed == _FOUR_ACTIONS
    with pytest.raises(WindowsApiError) as caught:
        wait_for_handle(launched.process_handle, 0.0)
    assert caught.value.winerror == _ERROR_INVALID_HANDLE
    with pytest.raises(WindowsApiError):
        is_process_in_job(launched.process_handle, job_handle)
    assert launched.stdout.closed
    assert launched.stderr.closed
    second = launched.close(close_stdout=True, close_stderr=True)
    assert second.complete
    assert second.completed == _FOUR_ACTIONS


def test_close_leaves_a_pipe_open_and_fails_pipes_closed_while_a_reader_is_alive(
    controller: _TrackingController, tmp_root: Path
) -> None:
    launched = started(controller.launch(sleep_spec(tmp_root)))
    termination = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    controller.shape(termination)
    controller.ended(launched, termination)
    report = launched.close(close_stdout=False, close_stderr=True)
    assert not report.complete
    assert [failure.action for failure in report.failures] == [
        CleanupAction.PIPES_CLOSED
    ]
    assert report.failures[0].reason == "reader_alive:0"
    assert not launched.stdout.closed
    assert launched.stderr.closed
    assert set(report.completed) == set(_FOUR_ACTIONS) - {CleanupAction.PIPES_CLOSED}
    final = launched.close(close_stdout=True, close_stderr=True)
    assert final.complete
    assert launched.stdout.closed


def test_close_reports_a_live_tree_and_the_job_kill_on_close_then_ends_it(
    controller: _TrackingController, tmp_root: Path
) -> None:
    launched = started(controller.launch(sleep_spec(tmp_root)))
    report = launched.close(close_stdout=True, close_stderr=True)
    assert not report.complete
    assert [f.action for f in report.failures] == [CleanupAction.TREE_VERIFIED_DEAD]
    assert report.failures[0].reason == "still_alive:1"
    # kill-on-close is the last line of defence: the job handle just closed took
    # the tree with it
    identity = process_identity_for(launched)
    assert _wait_until(
        lambda: (
            WindowsProcessController().inspect(identity).presence
            is ProcessPresence.ABSENT
        )
    )


def test_a_second_close_still_reports_a_root_that_nobody_killed(
    controller_without_job: _TrackingController, tmp_root: Path
) -> None:
    """Review F2: after the first ``close`` released the handle, the root is
    re-inspected through its durable identity (plan 8.4 "re-inspect the root pid"),
    so a still-running job-less root is never reported dead by omission."""
    launched = started(controller_without_job.launch(ready_sleep_spec(tmp_root)))
    controller_without_job.ready(launched)
    try:
        first = launched.close(close_stdout=True, close_stderr=True)
        assert [f.reason for f in first.failures] == ["still_alive:1"]
        second = launched.close(close_stdout=True, close_stderr=True)
        assert [f.action for f in second.failures] == [CleanupAction.TREE_VERIFIED_DEAD]
        assert second.failures[0].reason == "still_alive:1"
    finally:
        # no job: only the test can end this root, through its durable identity
        controller_without_job.terminate_owned(process_identity_for(launched))
    third = launched.close(close_stdout=True, close_stderr=True)
    assert third.complete


def test_without_a_job_a_reaped_root_receives_no_terminate_call(
    controller_without_job: _TrackingController,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Preventive pin (review F6) of plan 8.3 "only while the handle is unsignaled"
    and of R3: a job-less, already reaped root is never sent ``TerminateProcess``
    and the report is not forced."""
    spy = _TerminateSpy()
    monkeypatch.setattr(windows_api, "terminate_process", spy)
    launched = started(
        controller_without_job.launch(
            spec_for([sys.executable, "-I", "-B", "-c", "pass"], cwd=tmp_root)
        )
    )
    _exited(launched, 0)  # R1: the root is reaped before the terminate call
    report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    assert spy.calls == []
    assert not report.forced
    assert not isinstance(report.exit_code_used, int)
    assert report.failures == ()


def test_terminate_tree_and_inspection_leave_the_handle_table_unchanged(
    controller: _TrackingController, tmp_root: Path, resource_ledger: _ResourceLedger
) -> None:
    with resource_ledger.operation("launch") as launch:
        launched = started(
            controller.launch(
                program_spec(SPAWNS_A_SLEEPER_AND_PRINTS_ITS_PID, cwd=tmp_root)
            )
        )
    # R2 (owner ruling of 2026-11-14): the launch's retained resources pre-exist the
    # operations under test, each held by its named owner; every handle an operation
    # under test acquires is released by a real close, exactly, at its own boundary.
    # The three replaced checkpoints (both inspections, the tree termination) reach
    # kernel32 and the post-launch ``Popen`` route only, whose census is complete
    # (``test_the_post_launch_route_reaches_no_unresolved_site``); the launch window
    # reaches the construction route too, its receiver sites judged by the monitor.
    retained = _launch_retention(resource_ledger, launched)
    _require_observed(launch, _LAUNCH)
    _require_receivers(launch, _CONSTRUCTION_RECEIVERS)
    _require_zero_unaccounted(launch, retained=retained)
    int(launched.stdout.readline())
    identity = process_identity_for(launched)
    with resource_ledger.operation("inspect") as inspection:
        controller.inspect(identity)
    _require_zero_unaccounted(inspection)
    with resource_ledger.operation("terminate_tree") as termination:
        report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
        assert len(report.descendants) >= 2
        controller.shape(report)
        controller.ended(launched, report)  # every identity ABSENT
    _require_zero_unaccounted(termination)
    with resource_ledger.operation("inspect_again") as reinspection:
        controller.inspect(identity)
    _require_zero_unaccounted(reinspection)
    _require_retained(resource_ledger, retained)
    # The retained resources end at their established boundaries: ``close`` releases
    # the pipes, the job and the process handle, and the ``Popen`` handle ends with
    # its object.
    with resource_ledger.operation("release") as release:
        controller.release(launched)
        del launched
    _require_zero_unaccounted(release)
    _require_released(resource_ledger, retained)


def test_no_termination_report_or_inspection_carries_a_handle_or_an_instant() -> None:
    fields = {
        *TerminationReport.model_fields,
        *ProcessInspection.model_fields,
        *LaunchFailure.model_fields,
    }
    assert not {name for name in fields if "handle" in name or "at_utc" in name}


# --------------------------------------------------------------------------
# The controller-level terminate_tree (the reconciler's entry, plan 8.1 and 8.5)
# --------------------------------------------------------------------------


def test_the_controller_terminates_a_matching_root_it_did_not_launch(
    controller_without_job: _TrackingController, tmp_root: Path
) -> None:
    """Plan 10 ``test_the_creation_identity_survives_the_loss_of_every_handle`` in its
    Task 4 form: a fresh controller finds the launch ``ALIVE_MATCHING``, terminates
    the verified tree through the durable identity alone and then finds it
    ``ABSENT``."""
    launched = started(
        controller_without_job.launch(
            program_spec(SPAWNS_A_SLEEPER_AND_PRINTS_ITS_PID, cwd=tmp_root)
        )
    )
    grandchild = _pid_line(launched.stdout, launched=launched)
    controller_without_job.own_descendants(launched, expect=grandchild)
    identity = process_identity_for(launched)
    fresh = WindowsProcessController()
    assert fresh.inspect(identity).presence is ProcessPresence.ALIVE_MATCHING
    report = fresh.terminate_tree(identity, FORCED_TERMINATION_EXIT_CODE)
    assert report.forced
    assert report.exit_code_used == FORCED_TERMINATION_EXIT_CODE
    assert not report.job_terminated
    controller_without_job.shape(report)
    assert grandchild in {item.pid for item in report.descendants}
    controller_without_job.ended(launched, report)
    assert fresh.inspect(identity).presence is ProcessPresence.ABSENT
    assert inspect_descendant(report, grandchild) is ProcessPresence.ABSENT


def test_the_controller_never_kills_by_pid_alone(
    controller: _TrackingController, tmp_root: Path
) -> None:
    """A different creation time for a live pid, an absent pid and a malformed
    identity terminate nothing and report no forced call."""
    launched = started(controller.launch(sleep_spec(tmp_root)))
    fresh = WindowsProcessController()
    creation = parse_creation_identity(launched.creation_identity).creation_100ns
    stale = identity_for(
        launched.pid, render_creation_identity(launched.pid, creation - 1)
    )
    for identity in (
        stale,
        identity_for(3, render_creation_identity(3, 1)),
        sample_process_identity(),
    ):
        report = fresh.terminate_tree(identity, FORCED_TERMINATION_EXIT_CODE)
        assert not report.forced
        assert not isinstance(report.exit_code_used, int)
        assert report.descendants == ()
        assert report.failures == ()
    assert launched.wait(0.0) is None  # still running: nothing killed it
    assert (
        fresh.inspect(process_identity_for(launched)).presence
        is ProcessPresence.ALIVE_MATCHING
    )


# --------------------------------------------------------------------------
# Failure normalization by fault injection. These are characterization tests of the
# Win32 failure paths of plan 8.2-8.4 that a healthy host never takes (launch-time API
# failures, wait/terminate/enumeration/close failures): the real API is replaced at the
# ``windows_api`` seam the controller calls through, one function at a time, and the
# real function is restored before any cleanup. They pin behaviour that already
# existed when they were written (no RED preceded them) and are labelled as such.
# --------------------------------------------------------------------------


def _raising(function: str, winerror: int) -> Callable[..., object]:
    def fail(*args: object, **kwargs: object) -> object:
        raise WindowsApiError(function, winerror)

    return fail


def _failing_bounded_wait(
    *, raise_for_positive: bool, result_for_positive: bool = False
) -> Callable[[int, float], bool]:
    """A ``wait_for_handle`` that is real for a zero wait and fails or returns a fixed
    answer for every bounded wait."""
    real = windows_api.wait_for_handle

    def wait(handle: int, timeout_seconds: float) -> bool:
        if timeout_seconds > 0:
            if raise_for_positive:
                raise WindowsApiError("WaitForSingleObject", 6)
            return result_for_positive
        return real(handle, timeout_seconds)

    return wait


class _JobSpy:
    """Records the job handle ``create_kill_on_close_job`` returns, then delegates."""

    def __init__(self) -> None:
        self.handles: list[int] = []
        self._real = windows_api.create_kill_on_close_job

    def __call__(self) -> int:
        handle = self._real()
        self.handles.append(handle)
        return handle


def _resume_defect(pid: int) -> None:
    raise RuntimeError("a defect after the job assignment")


def test_type_errors_are_raised_before_any_call(
    controller: _TrackingController, tmp_root: Path
) -> None:
    with pytest.raises(TypeError, match="job_object_factory"):
        WindowsProcessController(job_object_factory=1)  # type: ignore[arg-type]
    fresh = WindowsProcessController()
    with pytest.raises(TypeError, match="specification"):
        fresh.launch("x")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="identity"):
        fresh.inspect("x")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="identity"):
        fresh.terminate_tree("x", 1)  # type: ignore[arg-type]
    launched = started(controller.launch(sleep_spec(tmp_root)))
    with pytest.raises(TypeError, match="timeout_seconds"):
        launched.wait("1")  # type: ignore[arg-type]


def test_a_popen_error_without_a_win32_number_carries_no_code() -> None:
    failure = windows_process_module._popen_failure(OSError("no number"))
    assert failure.stage == "popen"
    assert not failure.not_found
    assert not isinstance(failure.os_error_code, int)
    assert failure.error_class == "OSError"


def test_a_launched_process_requires_both_pipe_read_ends() -> None:
    class _NoPipes:
        pid = 1
        stdout = None
        stderr = None

    with pytest.raises(ValueError, match="pipe read ends"):
        WindowsLaunchedProcess(
            popen=cast(Any, _NoPipes()),
            process_handle=1,
            job_handle=None,
            job_error_code=1,
            creation_100ns=1,
            image_path=EXECUTABLE_PATH,
        )


def test_an_open_process_failure_at_launch_is_an_open_process_launch_failure(
    tmp_root: Path, monkeypatch: pytest.MonkeyPatch, resource_ledger: _ResourceLedger
) -> None:
    monkeypatch.setattr(windows_api, "open_process_limited", _raising("OpenProcess", 5))
    with resource_ledger.operation("abandoned_construction") as abandonment:
        failure = WindowsProcessController().launch(sleep_spec(tmp_root))
    monkeypatch.undo()
    assert isinstance(failure, LaunchFailure)
    assert failure.stage == "open_process"
    assert failure.os_error_code == 5
    assert failure.error_class == "OpenProcess"
    assert not failure.not_found
    # R2 (owner ruling of 2026-11-14; module docstring): the abandoned launch acquired
    # exactly these resources -- through a route whose census has no unresolved site
    # and whose receiver sites the monitor judged in this window -- and released every
    # one by a real close before ``launch`` returned: both pipes, the temporary
    # endpoints and the ``Popen`` handle with its object. The child's absence is
    # proved independently of the accounting.
    _require_observed(abandonment, _ABANDONED_CONSTRUCTION)
    _require_receivers(abandonment, _CONSTRUCTION_RECEIVERS)
    _require_zero_unaccounted(abandonment)
    _assert_every_descendant_of_this_process_is_absent()  # R2 step 1


@pytest.mark.parametrize(
    ("api", "function"),
    [
        ("process_times", "GetProcessTimes"),
        ("process_image_path", "QueryFullProcessImageNameW"),
    ],
)
def test_an_identity_or_image_failure_at_launch_abandons_the_suspended_child(
    tmp_root: Path, monkeypatch: pytest.MonkeyPatch, api: str, function: str
) -> None:
    spy = _OpenSpy()
    monkeypatch.setattr(windows_api, "open_process_limited", spy)
    monkeypatch.setattr(windows_api, api, _raising(function, 6))
    failure = WindowsProcessController().launch(sleep_spec(tmp_root))
    monkeypatch.undo()
    assert isinstance(failure, LaunchFailure)
    assert failure.stage == "open_process"
    assert failure.os_error_code == 6
    assert failure.error_class == function
    _assert_every_handle_closed(spy.handles)
    _assert_every_descendant_of_this_process_is_absent()


def test_a_resume_failure_is_a_resume_launch_failure_that_closes_the_job_too(
    tmp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    opens = _OpenSpy()
    jobs = _JobSpy()  # passed as the factory: the default is bound at definition
    monkeypatch.setattr(windows_api, "open_process_limited", opens)
    monkeypatch.setattr(
        windows_api, "resume_initial_thread", _raising("ResumeThread", 5)
    )
    controller = WindowsProcessController(job_object_factory=jobs)
    failure = controller.launch(sleep_spec(tmp_root))
    monkeypatch.undo()
    assert isinstance(failure, LaunchFailure)
    assert failure.stage == "resume"
    assert failure.os_error_code == 5
    assert failure.error_class == "ResumeThread"
    assert not failure.not_found
    _assert_every_handle_closed(opens.handles)
    _assert_every_handle_closed(jobs.handles)
    _assert_every_descendant_of_this_process_is_absent()


def test_a_defect_after_the_job_assignment_closes_the_job_and_the_process_handle(
    tmp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    opens = _OpenSpy()
    jobs = _JobSpy()  # passed as the factory: the default is bound at definition
    monkeypatch.setattr(windows_api, "open_process_limited", opens)
    monkeypatch.setattr(windows_api, "resume_initial_thread", _resume_defect)
    controller = WindowsProcessController(job_object_factory=jobs)
    with pytest.raises(RuntimeError, match="after the job assignment"):
        controller.launch(sleep_spec(tmp_root))
    monkeypatch.undo()
    _assert_every_handle_closed(opens.handles)
    _assert_every_handle_closed(jobs.handles)
    _assert_every_descendant_of_this_process_is_absent()


def test_an_unreadable_or_invalid_image_path_is_missing_and_nothing_else_changes(
    controller: _TrackingController, tmp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rows 8-9 of the decision table: the image never decides presence."""
    monkeypatch.setattr(
        windows_api, "process_image_path", lambda handle: "x" * 2000
    )  # longer than ExecutablePath admits
    launched = started(controller.launch(sleep_spec(tmp_root)))
    assert not isinstance(launched.image_path, str)
    identity = process_identity_for(launched)
    inspection = controller.inspect(identity)
    assert inspection.presence is ProcessPresence.ALIVE_MATCHING
    assert not isinstance(inspection.observed_image_path, str)
    monkeypatch.setattr(
        windows_api,
        "process_image_path",
        _raising("QueryFullProcessImageNameW", 6),
    )
    inspection = controller.inspect(identity)
    assert inspection.presence is ProcessPresence.ALIVE_MATCHING
    assert isinstance(inspection.observed_creation_identity, str)
    assert not isinstance(inspection.observed_image_path, str)
    monkeypatch.undo()
    assert isinstance(controller.inspect(identity).observed_image_path, str)


def test_a_times_or_wait_failure_during_inspection_is_undetermined(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rows 5 and 6 of the decision table."""
    identity = identity_for_own_process(creation=own_creation())
    monkeypatch.setattr(windows_api, "process_times", _raising("GetProcessTimes", 6))
    assert (
        WindowsProcessController().inspect(identity).presence
        is ProcessPresence.UNDETERMINED
    )
    monkeypatch.undo()
    monkeypatch.setattr(
        windows_api, "wait_for_handle", _raising("WaitForSingleObject", 6)
    )
    inspection = WindowsProcessController().inspect(identity)
    monkeypatch.undo()
    assert inspection.presence is ProcessPresence.UNDETERMINED
    assert not isinstance(inspection.observed_creation_identity, str)
    assert not isinstance(inspection.observed_image_path, str)


def test_a_terminate_failure_other_than_access_denied_is_reported(
    controller_without_job: _TrackingController,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launched = started(controller_without_job.launch(ready_sleep_spec(tmp_root)))
    controller_without_job.ready(launched)
    monkeypatch.setattr(
        windows_api, "terminate_process", _raising("TerminateProcess", 1)
    )
    report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    monkeypatch.undo()
    assert report.forced
    assert _sole_reason(report) == "terminate_failed:1"
    assert launched.wait(0.0) is None  # nothing killed it
    controller_without_job.terminate_owned(process_identity_for(launched))


def test_a_failed_or_expired_bounded_wait_after_the_kill_is_reported(
    controller_without_job: _TrackingController,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launched = started(controller_without_job.launch(ready_sleep_spec(tmp_root)))
    controller_without_job.ready(launched)
    monkeypatch.setattr(
        windows_api, "wait_for_handle", _failing_bounded_wait(raise_for_positive=True)
    )
    report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    monkeypatch.undo()
    assert report.forced
    assert _sole_reason(report) == "wait_failed:6"
    # the kill was real; the report is the fake's, one failure per kill target
    controller_without_job.ended(launched, report, dictated_reason="wait_failed:6")
    second = started(controller_without_job.launch(ready_sleep_spec(tmp_root)))
    controller_without_job.ready(second)
    monkeypatch.setattr(
        windows_api,
        "wait_for_handle",
        _failing_bounded_wait(raise_for_positive=False, result_for_positive=False),
    )
    report = second.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    monkeypatch.undo()
    assert _sole_reason(report) == "still_alive:0"
    controller_without_job.ended(second, report, dictated_reason="still_alive:0")


def test_a_zero_wait_failure_in_the_kill_loop_is_reported_and_the_root_is_kept(
    controller_without_job: _TrackingController,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launched = started(controller_without_job.launch(ready_sleep_spec(tmp_root)))
    controller_without_job.ready(launched)
    real = windows_api.wait_for_handle

    def zero_wait_fails(handle: int, timeout_seconds: float) -> bool:
        if timeout_seconds == 0.0:
            raise WindowsApiError("WaitForSingleObject", 6)
        return real(handle, timeout_seconds)

    monkeypatch.setattr(windows_api, "wait_for_handle", zero_wait_fails)
    report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    monkeypatch.undo()
    assert not report.forced
    assert _sole_reason(report) == "wait_failed:6"
    assert launched.wait(0.0) is None
    controller_without_job.terminate_owned(process_identity_for(launched))


def test_an_enumeration_failure_is_reported_and_the_root_is_still_killed(
    controller_without_job: _TrackingController,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launched = started(controller_without_job.launch(ready_sleep_spec(tmp_root)))
    controller_without_job.ready(launched)  # the interpreter child is owned first
    monkeypatch.setattr(
        windows_api, "descendants_of", _raising("CreateToolhelp32Snapshot", 87)
    )
    report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    monkeypatch.undo()
    assert report.forced
    assert report.descendants == ()
    assert report.failures[0].action is CleanupAction.TREE_VERIFIED_DEAD
    assert report.failures[0].reason == "enumeration_failed:87"
    # The injected walk failure comes first; what follows is the root's own kill
    # result, held to the closed oracle (shape A or B) like every real kill.
    kill = _report(*report.failures[1:])
    controller_without_job.shape(kill)
    controller_without_job.ended(launched, kill)


def test_a_job_kill_returning_false_falls_back_to_per_process_termination(
    controller: _TrackingController, tmp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launched = started(controller.launch(sleep_spec(tmp_root)))
    monkeypatch.setattr(windows_api, "terminate_job", lambda job, code: False)
    report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    monkeypatch.undo()
    assert report.forced
    assert not report.job_terminated
    controller.shape(report)
    controller.ended(launched, report)


def test_a_wait_failure_after_a_successful_job_kill_is_reported(
    controller: _TrackingController, tmp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launched = started(controller.launch(sleep_spec(tmp_root)))
    monkeypatch.setattr(
        windows_api, "wait_for_handle", _failing_bounded_wait(raise_for_positive=True)
    )
    report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    monkeypatch.undo()
    assert report.job_terminated
    assert _sole_reason(report) == "wait_failed:6"
    controller.ended(launched, report, dictated_reason="wait_failed:6")


class _DescendantFault:
    """Faults injected only on descendant handles opened for termination
    (``terminate=True`` and not the root pid), never on the root or the walk."""

    def __init__(self, root_pid: int, mode: str) -> None:
        self.root_pid = root_pid
        self.mode = mode
        self.faulted: set[int] = set()
        self._open = windows_api.open_process_limited
        self._times = windows_api.process_times

    def open_process_limited(
        self, pid: int, *, terminate: bool = False, set_quota: bool = False
    ) -> int:
        if terminate and pid != self.root_pid and self.mode == "open":
            raise WindowsApiError("OpenProcess", 5)
        handle = self._open(pid, terminate=terminate, set_quota=set_quota)
        if terminate and pid != self.root_pid:
            self.faulted.add(handle)
        return handle

    def process_times(self, handle: int) -> int:
        if handle in self.faulted:
            if self.mode == "times_error":
                raise WindowsApiError("GetProcessTimes", 6)
            if self.mode == "times_mismatch":
                return self._times(handle) + 1
        return self._times(handle)


@pytest.mark.parametrize("mode", ["open", "times_error", "times_mismatch"])
def test_a_descendant_that_cannot_be_reverified_is_left_alone(
    controller_without_job: _TrackingController,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    """Plan 8.3: a descendant is killed only through a handle whose creation time was
    re-verified; one that cannot be reopened, read or matched is skipped, never
    killed by pid."""
    launched = started(
        controller_without_job.launch(
            program_spec(SPAWNS_A_SLEEPER_AND_PRINTS_ITS_PID, cwd=tmp_root)
        )
    )
    grandchild = _pid_line(launched.stdout, launched=launched)
    controller_without_job.own_descendants(launched, expect=grandchild)
    fault = _DescendantFault(launched.pid, mode)
    monkeypatch.setattr(windows_api, "open_process_limited", fault.open_process_limited)
    monkeypatch.setattr(windows_api, "process_times", fault.process_times)
    try:
        report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    finally:
        monkeypatch.undo()
    assert report.forced
    assert grandchild in {item.pid for item in report.descendants}  # enumerated
    controller_without_job.shape(report)
    # only the root was killed: the descendants were left alone by design
    controller_without_job.ended(launched, report, [process_identity_for(launched)])
    assert inspect_descendant(report, grandchild) is ProcessPresence.ALIVE_MATCHING
    controller_without_job.terminate_owned(descendant_identity(report, grandchild))
    assert inspect_descendant(report, grandchild) is ProcessPresence.ABSENT


def test_an_undeliverable_interrupt_is_unavailable_and_a_dying_root_is_gone(
    controller: _TrackingController, tmp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launched = started(controller.launch(sleep_spec(tmp_root)))
    monkeypatch.setattr(windows_api, "generate_console_break", lambda pid: False)
    assert launched.interrupt() is InterruptOutcome.UNAVAILABLE
    assert launched.wait(0.0) is None
    reports: list[TerminationReport] = []

    def kill_then_report_false(pid: int) -> bool:
        assert pid == launched.pid
        # the child exits between the two zero waits (ended through its identity)
        reports.append(controller.terminate_owned(process_identity_for(launched)))
        return False

    monkeypatch.setattr(windows_api, "generate_console_break", kill_then_report_false)
    assert launched.interrupt() is InterruptOutcome.PROCESS_GONE
    monkeypatch.undo()
    (report,) = reports
    controller.ended(launched, report)


def test_an_interrupt_that_cannot_test_the_root_is_unavailable(
    controller_without_job: _TrackingController,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launched = started(controller_without_job.launch(ready_sleep_spec(tmp_root)))
    controller_without_job.ready(launched)
    monkeypatch.setattr(
        windows_api, "wait_for_handle", _raising("WaitForSingleObject", 6)
    )
    assert launched.interrupt() is InterruptOutcome.UNAVAILABLE
    monkeypatch.undo()
    launched.close(close_stdout=True, close_stderr=True)  # still_alive: handle gone
    assert launched.interrupt() is InterruptOutcome.UNAVAILABLE  # cannot be tested
    controller_without_job.terminate_owned(process_identity_for(launched))


def test_close_reports_a_handle_that_cannot_be_closed(
    controller: _TrackingController, tmp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launched = started(controller.launch(sleep_spec(tmp_root)))
    termination = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    controller.shape(termination)
    controller.ended(launched, termination)
    job_handle = launched.job_handle
    assert job_handle is not None
    process_handle = launched.process_handle
    real_close = windows_api.close_handle

    def close_fails(handle: int) -> None:
        if handle in (job_handle, process_handle):
            raise WindowsApiError("CloseHandle", 6)
        real_close(handle)

    monkeypatch.setattr(windows_api, "close_handle", close_fails)
    report = launched.close(close_stdout=True, close_stderr=True)
    monkeypatch.undo()
    assert [f.action for f in report.failures] == [
        CleanupAction.JOB_CLOSED,
        CleanupAction.PROCESS_HANDLE_CLOSED,
    ]
    assert {f.reason for f in report.failures} == {"close_failed:6"}
    close_handle(job_handle)  # the real handles, which the fault left open
    close_handle(process_handle)
    _assert_every_handle_closed([job_handle, process_handle])


def test_close_reports_a_failed_zero_wait_on_the_root(
    controller: _TrackingController, tmp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launched = started(controller.launch(sleep_spec(tmp_root)))
    monkeypatch.setattr(
        windows_api, "wait_for_handle", _raising("WaitForSingleObject", 6)
    )
    report = launched.close(close_stdout=False, close_stderr=False)
    monkeypatch.undo()
    assert [f.action for f in report.failures] == [
        CleanupAction.PIPES_CLOSED,
        CleanupAction.TREE_VERIFIED_DEAD,
    ]
    assert report.failures[1].reason == "wait_failed:6"
    assert not launched.stdout.closed
    assert not launched.stderr.closed
    # kill-on-close ended the tree when the job handle closed
    identity = process_identity_for(launched)
    assert _wait_until(
        lambda: (
            WindowsProcessController().inspect(identity).presence
            is ProcessPresence.ABSENT
        )
    )


def test_the_controller_reports_a_root_it_cannot_open_or_read(
    controller: _TrackingController, tmp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launched = started(controller.launch(sleep_spec(tmp_root)))
    identity = process_identity_for(launched)
    fresh = WindowsProcessController()
    monkeypatch.setattr(windows_api, "open_process_limited", _raising("OpenProcess", 5))
    report = fresh.terminate_tree(identity, FORCED_TERMINATION_EXIT_CODE)
    monkeypatch.undo()
    assert not report.forced
    assert [f.reason for f in report.failures] == ["open_failed:5"]
    monkeypatch.setattr(windows_api, "process_times", _raising("GetProcessTimes", 6))
    report = fresh.terminate_tree(identity, FORCED_TERMINATION_EXIT_CODE)
    monkeypatch.undo()
    assert not report.forced
    assert [f.reason for f in report.failures] == ["open_failed:6"]
    assert launched.wait(0.0) is None  # nothing touched the live root


# --------------------------------------------------------------------------
# Fixture hygiene (the correction of 2026-09-18, T8-N-4; module docstring)
# --------------------------------------------------------------------------


def test_a_job_less_launch_is_ready_and_owned_before_any_destructive_action(
    controller_without_job: _TrackingController, tmp_root: Path
) -> None:
    """The readiness line proves the launcher's interpreter child is created and
    resumed; only then is the tree enumerated, owned and ended, so no launcher is ended
    inside its create-suspended-then-resume window."""
    launched = started(controller_without_job.launch(ready_sleep_spec(tmp_root)))
    descendants = controller_without_job.ready(launched)
    assert len(descendants) >= 1
    fresh = WindowsProcessController()
    for item in descendants:
        assert (item.pid, item.creation_identity) in controller_without_job.owned
        identity = identity_for(item.pid, item.creation_identity)
        assert fresh.inspect(identity).presence is ProcessPresence.ALIVE_MATCHING
    report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    assert {item.pid for item in descendants} <= {d.pid for d in report.descendants}
    controller_without_job.shape(report)
    controller_without_job.ended(launched, report)
    for item in descendants:
        identity = identity_for(item.pid, item.creation_identity)
        assert fresh.inspect(identity).presence is ProcessPresence.ABSENT


def test_the_fixture_cleanup_runs_when_the_test_body_raises(tmp_root: Path) -> None:
    """The fixtures are ``_tracking``; unwinding it with an exception -- what pytest
    does on an assertion failure, a helper failure or a timeout -- still ends every
    owned identity and closes every owned handle."""
    fixture = _tracking(_failing_job_factory)
    tracking = next(fixture)
    launched = started(tracking.launch(ready_sleep_spec(tmp_root)))
    owned = [
        identity_for(item.pid, item.creation_identity)
        for item in tracking.ready(launched)
    ]
    owned.append(process_identity_for(launched))
    with pytest.raises(AssertionError, match="controlled failure"):
        fixture.throw(AssertionError("controlled failure"))
    fresh = WindowsProcessController()
    for identity in owned:
        assert fresh.inspect(identity).presence is ProcessPresence.ABSENT
    assert launched.stdout.closed
    assert launched.stderr.closed
    _assert_every_handle_closed([launched.process_handle])  # job-less: no job handle


def test_the_fixture_cleanup_ends_an_owned_identity_it_did_not_launch(
    tmp_root: Path,
) -> None:
    """A sleeper launched job-less through a controller the tracker does not wrap is
    owned by identity alone and still ended through the identity-bound path in cleanup,
    its interpreter child with it."""
    stray = WindowsProcessController(job_object_factory=_failing_job_factory)
    launched = started(stray.launch(ready_sleep_spec(tmp_root)))
    _ready(launched)
    identity = process_identity_for(launched)
    creation = parse_creation_identity(launched.creation_identity).creation_100ns
    children = descendants_of(launched.pid, creation)
    assert children
    tracking = _TrackingController(WindowsProcessController())
    try:
        tracking.own(identity)
        assert tracking.launched == []
        fresh = WindowsProcessController()
        assert fresh.inspect(identity).presence is ProcessPresence.ALIVE_MATCHING
    finally:
        tracking.cleanup()
    assert fresh.inspect(identity).presence is ProcessPresence.ABSENT
    for child in children:
        _absent(identity_for(child.pid, child.creation_identity))
    assert launched.close(close_stdout=True, close_stderr=True).complete


def test_the_fixture_cleanup_never_terminates_a_mismatched_creation_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ownership is pid plus creation identity: this process under a creation time one
    tick earlier (what a reused pid looks like) and an absent pid reach no
    ``TerminateProcess`` call at all -- and the mismatch, never ``ABSENT``, fails the
    cleanup by name (ruling pins 5 and 8) instead of authorizing anything."""

    def refuse(handle: int, exit_code: int) -> None:
        raise AssertionError("TerminateProcess reached a mismatched identity")

    monkeypatch.setattr(windows_api, "terminate_process", refuse)
    tracking = _TrackingController(WindowsProcessController())
    tracking.own(identity_for_own_process(creation=own_creation() - 1))
    tracking.own(identity_for(3, render_creation_identity(3, 1)))
    with pytest.raises(AssertionError, match="ALIVE_DIFFERENT_IDENTITY") as caught:
        tracking.cleanup()
    assert "TerminateProcess reached" not in str(caught.value)
    assert len(tracking.owned) == 2
    assert (
        WindowsProcessController()
        .inspect(identity_for_own_process(creation=own_creation()))
        .presence
        is ProcessPresence.ALIVE_MATCHING
    )


# --------------------------------------------------------------------------
# The termination oracle (the human ruling of 2026-09-18, Option A; module docstring)
# --------------------------------------------------------------------------


def test_the_accepted_shapes_are_exactly_clean_and_one_host_delayed_wait() -> None:
    """Ruling pins 1 and 2: shape A is ``failures == ()``; shape B is exactly one
    ``TREE_VERIFIED_DEAD`` failure whose reason is the committed ``still_alive:0`` --
    the very record ``_force`` builds through ``_tree_failure`` -- decided on the
    structured action and reason fields, never on message text."""
    assert _accepted_shape(_report()) == _CLEAN
    delayed = _failure(CleanupAction.TREE_VERIFIED_DEAD, _HOST_DELAYED_REASON)
    assert _accepted_shape(_report(delayed)) == _HOST_DELAYED
    assert _HOST_DELAYED_REASON == "still_alive:0"
    assert windows_process_module._tree_failure("still_alive", 0) == delayed
    assert delayed.action is CleanupAction.TREE_VERIFIED_DEAD


@pytest.mark.parametrize(
    "reason",
    [
        "still_alive:1",
        "still_alive:00",
        "still_alive:0 ",
        " still_alive:0",
        "STILL_ALIVE:0",
        "still_alive:0\n",
        "wait_failed:6",
        "terminate_failed:1",
        "enumeration_failed:87",
        "open_failed:5",
    ],
)
def test_any_other_failure_reason_is_rejected(reason: str) -> None:
    """Ruling pin 3 and the mutation-style control: a ``TREE_VERIFIED_DEAD`` failure
    under any reason but the exact ``still_alive:0`` is refused, so a module whose
    accepted reason were replaced by another (``still_alive:1`` among them) fails
    here and in the shape test above."""
    with pytest.raises(AssertionError):
        _accepted_shape(_report(_failure(CleanupAction.TREE_VERIFIED_DEAD, reason)))


def test_the_accepted_reason_under_any_other_action_is_rejected() -> None:
    """Ruling pin 3 on the action field: the exact reason under any other cleanup
    action is not the bounded-wait result."""
    for action in CleanupAction:
        if action is CleanupAction.TREE_VERIFIED_DEAD:
            continue
        with pytest.raises(AssertionError):
            _accepted_shape(_report(_failure(action, _HOST_DELAYED_REASON)))


def test_two_or_more_failures_are_rejected_even_when_each_is_the_accepted_one() -> None:
    """Ruling pin 4."""
    delayed = _failure(CleanupAction.TREE_VERIFIED_DEAD, _HOST_DELAYED_REASON)
    for count in (2, 3):
        with pytest.raises(AssertionError):
            _accepted_shape(_report(*([delayed] * count)))
    other = _failure(CleanupAction.TREE_VERIFIED_DEAD, "wait_failed:6")
    with pytest.raises(AssertionError):
        _accepted_shape(_report(delayed, other))


def test_the_native_exit_is_the_constant_or_none_only_under_shape_b() -> None:
    """Ruling pin 7 and the revised wait: ``WindowsLaunchedProcess.wait`` returns
    ``int | None``; an observed value must be exactly ``FORCED_TERMINATION_EXIT_CODE``,
    and ``None`` is accepted only beside the exact shape-B report."""
    delayed = _report(_failure(CleanupAction.TREE_VERIFIED_DEAD, _HOST_DELAYED_REASON))
    _native_exit(FORCED_TERMINATION_EXIT_CODE, _report())
    _native_exit(FORCED_TERMINATION_EXIT_CODE, delayed)
    _native_exit(None, delayed)
    rejected: list[tuple[int | None, TerminationReport]] = [
        (None, _report()),
        (None, _report(_failure(CleanupAction.TREE_VERIFIED_DEAD, "wait_failed:6"))),
        (None, _report(*([delayed.failures[0]] * 2))),
        (0, _report()),
        (259, _report()),
        (FORCED_TERMINATION_EXIT_CODE - 1, delayed),
        (_CONTROL_C_EXIT, _report()),
        # the observed constant never excuses an unapproved report
        (
            FORCED_TERMINATION_EXIT_CODE,
            _report(_failure(CleanupAction.TREE_VERIFIED_DEAD, "wait_failed:6")),
        ),
        (FORCED_TERMINATION_EXIT_CODE, _report(*([delayed.failures[0]] * 2))),
    ]
    for observed, report in rejected:
        with pytest.raises(AssertionError):
            _native_exit(observed, report)


def test_a_fake_dictated_report_is_accepted_beside_none_only_as_dictated() -> None:
    """The fault-injected sites: when a fake made every bounded wait fail, the report
    holds one ``TREE_VERIFIED_DEAD`` failure per kill target by construction; ``None``
    from the root's wait is accepted only beside exactly that report (the dictated
    reason, one failure per target, no other action), never beside a real-shaped
    report, and an observed exit must still be the constant."""
    delayed = _failure(CleanupAction.TREE_VERIFIED_DEAD, _HOST_DELAYED_REASON)
    wait_failed = _failure(CleanupAction.TREE_VERIFIED_DEAD, "wait_failed:6")
    dictated = _report(delayed, delayed, descendants=1)
    _native_exit(None, dictated, dictated_reason=_HOST_DELAYED_REASON)
    _native_exit(None, _report(wait_failed), dictated_reason="wait_failed:6")
    _native_exit(
        FORCED_TERMINATION_EXIT_CODE, dictated, dictated_reason=_HOST_DELAYED_REASON
    )
    rejected: list[tuple[int | None, TerminationReport, str]] = [
        (None, dictated, "wait_failed:6"),  # another reason than the dictated one
        (None, _report(delayed, descendants=1), _HOST_DELAYED_REASON),  # too few
        (None, _report(delayed, delayed), _HOST_DELAYED_REASON),  # too many
        (None, _report(delayed, wait_failed, descendants=1), "wait_failed:6"),  # mixed
        (None, _report(), _HOST_DELAYED_REASON),  # a clean report dictates nothing
        (
            None,
            _report(_failure(CleanupAction.JOB_CLOSED, "wait_failed:6")),
            "wait_failed:6",
        ),
        (0, dictated, _HOST_DELAYED_REASON),
        (FORCED_TERMINATION_EXIT_CODE - 1, dictated, _HOST_DELAYED_REASON),
        # the observed constant never excuses a report other than the dictated one
        (FORCED_TERMINATION_EXIT_CODE, _report(wait_failed), _HOST_DELAYED_REASON),
        (FORCED_TERMINATION_EXIT_CODE, _report(), "wait_failed:6"),
    ]
    for observed, report, reason in rejected:
        with pytest.raises(AssertionError):
            _native_exit(observed, report, dictated_reason=reason)
    # Without a dictated reason the same two-failure report is not shape B.
    with pytest.raises(AssertionError):
        _native_exit(None, dictated)


def test_the_zero_duration_wait_must_return_the_exact_native_exit() -> None:
    """Natural-exit negative controls 4 and 5: ``None`` from the zero-duration wait
    fails; a wrong code fails; the exact code passes."""
    _native_exit_code(0, 0)
    _native_exit_code(_CONTROL_C_EXIT, _CONTROL_C_EXIT)
    with pytest.raises(AssertionError, match="returned None"):
        _native_exit_code(None, 0)
    for observed, expected in ((1, 0), (0, 7), (259, 0), (1067, 7)):
        with pytest.raises(AssertionError):
            _native_exit_code(observed, expected)


def test_only_absent_passes_the_natural_exit_presence_step() -> None:
    """Natural-exit negative controls 1 to 3 over the presence step: ``ALIVE_MATCHING``,
    ``ALIVE_DIFFERENT_IDENTITY`` and ``UNDETERMINED`` each fail by name; ``ABSENT``
    passes."""
    identity = identity_for(3, render_creation_identity(3, 1))
    _require_absent(identity, ProcessPresence.ABSENT)
    for presence in (
        ProcessPresence.ALIVE_MATCHING,
        ProcessPresence.ALIVE_DIFFERENT_IDENTITY,
        ProcessPresence.UNDETERMINED,
    ):
        with pytest.raises(AssertionError, match=presence.value):
            _require_absent(identity, presence)


def test_a_child_alive_after_the_ten_second_wait_fails_the_natural_exit_oracle(
    controller: _TrackingController, tmp_root: Path
) -> None:
    """Natural-exit negative control 1 on a real child: a sleeper is still
    ``ALIVE_MATCHING`` after the module's one 10-second wait, and the oracle fails by
    name before any zero-duration read. Control 6 (plan Step 2): a first bounded wait
    that observes no exit fails the oracle even when the fresh inspection then reports
    the identity ``ABSENT`` -- a stand-in whose bounded wait returns ``None``, whose
    identity names no process and whose zero-duration wait would report an exit code
    -- and nothing is read after that ``None``."""
    launched = started(controller.launch(sleep_spec(tmp_root)))
    started_at = time.monotonic()
    with pytest.raises(AssertionError, match="ALIVE_MATCHING, not ABSENT"):
        _exited(launched, 0)
    assert time.monotonic() - started_at >= _WAIT_BOUND_SECONDS
    assert launched.wait(0.0) is None  # nothing ended it; the fixture cleanup will
    stand_in = _TimedOutThenAbsent()
    with pytest.raises(AssertionError, match="observed no exit"):
        _exited(cast(WindowsLaunchedProcess, stand_in), 0)
    assert stand_in.waits == [_WAIT_BOUND_SECONDS]


def test_the_handle_count_settles_to_the_exact_baseline_or_fails_at_the_bound() -> None:
    """R2 pins 6 to 8 over an injected counter: a count one above the baseline never
    settles and fails when the bound expires (no tolerance, not even one handle); a
    count that reaches the baseline on a later reading settles; and a count equal at
    once settles on its first reading. The whole-process table is no subject of this
    pin (its real-table subcase is removed under the owner ruling of 2026-11-14, which
    names it; that subcase ran no operation between its baseline and its settle), and
    complete accounting has replaced every live settle (module docstring)."""
    with pytest.raises(AssertionError, match="did not settle to exactly 10 within"):
        _settled_handle_count(10, count=lambda: 11)
    readings = iter([12, 11, 10])
    _settled_handle_count(10, count=lambda: next(readings))
    _settled_handle_count(7, count=lambda: 7)
    settles = [row for row in _EVIDENCE.rows if row["kind"] == "handle_settle"]
    assert {key: settles[-1][key] for key in ("observed", "readings", "settled")} == {
        "observed": 7,
        "readings": 1,
        "settled": True,
    }


def test_the_ruling_oracles_are_used_exactly_where_the_ruling_names_them() -> None:
    """R1, R2, F1 and F2 as structure: the eight natural-exit sites and only they call
    ``_exited``; no positive-bound ``wait`` comparison remains outside ``ended`` and the
    two argument-validation tests; the three fake-dictated sites and only they pass a
    dictated reason; ``_absent`` performs exactly one kernel wait; ``_exited`` performs
    no hidden wait; the handle-count settle is the deterministic pin's alone;
    accounting runs exactly at the ruling's sites and the semantic controls, with its
    live table count a diagnostic only (owner ruling of 2026-11-14)."""
    source = Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    enclosing: dict[int, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for child in ast.walk(node):
                enclosing.setdefault(id(child), node.name)

    def callers(name: str, *, attribute: bool = False) -> set[str]:
        found: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if attribute and isinstance(func, ast.Attribute) and func.attr == name:
                found.add(enclosing[id(node)])
            elif not attribute and isinstance(func, ast.Name) and func.id == name:
                found.add(enclosing[id(node)])
        return found

    # The eight natural-exit sites, plus the one negative control that proves a child
    # still alive after the 10-second wait fails the oracle; nothing else calls it.
    assert callers("_exited") == {
        "test_a_child_alive_after_the_ten_second_wait_fails_the_natural_exit_oracle",
        "test_terminating_an_already_exited_root_reports_no_failure",
        "test_cancel_read_unblocks_a_reader_whose_pipe_a_grandchild_still_holds",
        "test_a_child_that_exits_with_259_is_absent_not_alive",
        "test_an_interrupt_reaches_a_child_that_handles_sigbreak",
        "test_inspect_of_a_finished_process_is_absent",
        "test_wait_polls_without_blocking_and_memoizes_the_first_reaped_value",
        "test_a_handler_less_child_dies_on_the_interrupt_with_the_control_c_status",
        "test_without_a_job_a_reaped_root_receives_no_terminate_call",
    }
    positive_waits: set[tuple[str, str]] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "wait"
            and not (
                isinstance(node.func.value, ast.Name) and node.func.value.id == "_PAUSE"
            )
        ):
            (argument,) = node.args
            if not (isinstance(argument, ast.Constant) and argument.value == 0.0):
                positive_waits.add((enclosing[id(node)], ast.unparse(argument)))
    assert positive_waits == {
        ("ended", "POST_TERMINATION_WAIT_SECONDS"),
        ("_exited", "_WAIT_BOUND_SECONDS"),
        ("test_wait_and_exit_code_bounds_are_checked_before_any_call", "bad"),
        ("test_type_errors_are_raised_before_any_call", "'1'"),
    }
    dictated: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and any(
            keyword.arg == "dictated_reason" for keyword in node.keywords
        ):
            dictated.add(enclosing[id(node)])
    assert dictated == {
        "ended",
        "test_a_failed_or_expired_bounded_wait_after_the_kill_is_reported",
        "test_a_wait_failure_after_a_successful_job_kill_is_reported",
        "test_a_fake_dictated_report_is_accepted_beside_none_only_as_dictated",
    }
    absent = _function_source(tree, "_absent")
    assert absent.count("wait_for_handle(") == 1
    # The natural-exit helper: exactly one non-zero wait, at the module's 10-second
    # bound by name; exactly one fresh inspection; exactly one zero-duration wait; no
    # loop, no poll, no sleep, no production constant, no second bounded wait.
    (exited_node,) = (
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_exited"
    )
    waits = [
        ast.unparse(node.args[0])
        for node in ast.walk(exited_node)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "wait"
    ]
    assert waits == ["_WAIT_BOUND_SECONDS", "0.0"]
    assert _WAIT_BOUND_SECONDS == 10.0
    inspections = [
        node
        for node in ast.walk(exited_node)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "inspect"
    ]
    assert len(inspections) == 1
    assert not any(
        isinstance(node, ast.While | ast.For | ast.AsyncFor | ast.comprehension)
        for node in ast.walk(exited_node)
    )
    # The body without its docstring: prose may name what the code must not do.
    exited = ast.unparse(ast.Module(body=exited_node.body[1:], type_ignores=[]))
    for forbidden in ("_wait_until", "_PAUSE", "wait_for_handle", "POST_TERMINATION"):
        assert forbidden not in exited, forbidden
    assert "sleep" not in exited
    constants = [
        node.value for node in ast.walk(exited_node) if isinstance(node, ast.Constant)
    ]
    assert 5.0 not in constants  # the production bound never appears as a literal
    called = [
        node.func.id
        for node in ast.walk(exited_node)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    ]
    assert "_absent" not in called  # the production-bound helper stays out of this path
    assert called.count("_require_absent") == 1
    assert called.count("_native_exit_code") == 1
    # Complete accounting replaced every live settle (the construction route's census
    # has no unresolved site; module docstring); the deterministic pin stays.
    assert callers("_settled_handle_count") == {
        "test_the_handle_count_settles_to_the_exact_baseline_or_fails_at_the_bound",
    }
    settle = _function_source(tree, "_settled_handle_count")
    assert "_wait_until" in settle
    assert "== baseline" in settle
    assert "abs(" not in settle
    assert "<=" not in settle
    assert "reader = _open_handle_count if count is None else count" in settle
    assert callers("_require_zero_unaccounted") == {
        "test_a_launch_failure_leaves_no_child_and_no_extra_handle",
        "test_terminate_tree_and_inspection_leave_the_handle_table_unchanged",
        "test_an_open_process_failure_at_launch_is_an_open_process_launch_failure",
        "test_an_operation_owned_leak_is_detected_despite_unrelated_handle_closure",
        "test_unrelated_handle_churn_does_not_fail_balanced_operation_cleanup",
        "test_a_reused_handle_number_never_merges_two_lifetimes",
        "test_an_inconclusive_type_probe_never_releases_a_live_pipe",
        "test_a_reused_pipe_number_is_released_only_by_a_known_file_type",
        "test_a_failed_handle_count_diagnostic_neither_blocks_nor_decides_accounting",
        "test_a_failure_while_popen_builds_its_handles_releases_every_acquisition",
        "test_the_receiver_site_monitor_passes_typed_receivers_and_fails_closed",
    }
    assert callers("_require_receivers") == {
        "test_a_launch_failure_leaves_no_child_and_no_extra_handle",
        "test_terminate_tree_and_inspection_leave_the_handle_table_unchanged",
        "test_an_open_process_failure_at_launch_is_an_open_process_launch_failure",
        "test_a_failure_while_popen_builds_its_handles_releases_every_acquisition",
    }
    accounting = _function_source(tree, "_require_zero_unaccounted")
    assert "assert problems == []" in accounting
    assert "abs(" not in accounting
    assert "<=" not in accounting
    # The live count is a diagnostic: taken after the verdict, never raising, never
    # forcing the collection that could finalize (and so release) a resource.
    assert callers("_diagnostic_handle_count") == {
        "__enter__",
        "_require_zero_unaccounted",
    }
    assert accounting.index(".audit(") < accounting.index("_diagnostic_handle_count(")
    diagnostic = _function_source(tree, "_diagnostic_handle_count")
    assert "assert" not in diagnostic
    assert "gc." not in diagnostic


def test_a_live_or_reused_identity_never_passes_the_absence_check() -> None:
    """Ruling pin 5: this process under its own identity is still ``ALIVE_MATCHING``
    after its bounded wait and fails; under a creation time one tick earlier it is
    ``ALIVE_DIFFERENT_IDENTITY`` and fails without being waited on; an absent pid
    passes."""
    with pytest.raises(AssertionError, match="ALIVE_MATCHING"):
        _absent(identity_for_own_process(creation=own_creation()))
    with pytest.raises(AssertionError, match="ALIVE_DIFFERENT_IDENTITY"):
        _absent(identity_for_own_process(creation=own_creation() - 1))
    _absent(identity_for(3, render_creation_identity(3, 1)))


def test_the_fixture_terminates_an_owned_tree_at_most_once(
    controller_without_job: _TrackingController,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ruling pin 9: a tree the body ended and proved ended receives no further
    ``TerminateProcess`` from ``cleanup`` (nor from a second ``cleanup``), and the
    identity-bound ``terminate_owned`` refuses an identity a termination covered."""
    launched = started(controller_without_job.launch(ready_sleep_spec(tmp_root)))
    controller_without_job.ready(launched)
    report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    controller_without_job.shape(report)
    controller_without_job.ended(launched, report)
    root = process_identity_for(launched)
    assert (root.pid, root.creation_identity) in controller_without_job.terminated
    spy = _TerminateSpy()
    monkeypatch.setattr(windows_api, "terminate_process", spy)
    controller_without_job.cleanup()
    controller_without_job.cleanup()
    assert spy.calls == []
    with pytest.raises(AssertionError, match="terminated once already"):
        controller_without_job.terminate_owned(root)


def test_a_surviving_owned_identity_fails_the_cleanup_and_is_still_ended(
    tmp_root: Path,
) -> None:
    """Ruling pin 6: an identity a termination already covered that is still
    ``ALIVE_MATCHING`` after its bounded wait at cleanup is a failure by name -- it is
    ended through the identity-bound path so no orphan outlives the test, and the test
    has failed. Only the root is owned here: owning its interpreter child would let the
    sweep end that child first, and the launcher then exits by itself."""
    tracking = _TrackingController(
        WindowsProcessController(job_object_factory=_failing_job_factory)
    )
    launched = started(tracking.launch(ready_sleep_spec(tmp_root)))
    _ready(launched)
    root = process_identity_for(launched)
    creation = parse_creation_identity(launched.creation_identity).creation_100ns
    children = descendants_of(launched.pid, creation)
    assert children
    tracking.terminated.add((root.pid, root.creation_identity))  # "already covered"
    with pytest.raises(AssertionError, match="survived its termination"):
        tracking.cleanup()
    _absent(root)
    for item in children:
        _absent(identity_for(item.pid, item.creation_identity))
    assert launched.stdout.closed
    assert launched.stderr.closed


def _names_the_forced_exit(node: ast.expr) -> bool:
    if isinstance(node, ast.Constant):
        return bool(node.value == 1067)
    return isinstance(node, ast.Name) and node.id == "FORCED_TERMINATION_EXIT_CODE"


def _function_source(tree: ast.Module, name: str) -> str:
    (function,) = (
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    return ast.unparse(function)


def test_this_module_never_sleeps_and_bounds_every_wait() -> None:
    """No ``time.sleep`` call in test code (the ``-c`` programs are string constants),
    the readiness read uses the module bound, the oracle uses the production bound
    once per identity and never polls, and no skip, xfail or coverage exclusion exists
    in this module."""
    source = Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    sleeps = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "sleep"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "time"
    ]
    assert sleeps == []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for decorator in node.decorator_list:
                text = ast.unparse(decorator)
                assert "skip" not in text
                assert "xfail" not in text
    marker_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"skip", "xfail", "importorskip"}
    ]
    assert marker_calls == []
    assert ("pragma: " + "no cover") not in source
    assert _WAIT_BOUND_SECONDS == 10.0
    assert "_WAIT_BOUND_SECONDS" in _function_source(tree, "_read_line_bounded")
    # The oracle polls nothing: one committed bounded wait, then one inspection.
    for name in ("_absent", "_native_exit", "ended", "terminate_owned", "cleanup"):
        assert "_wait_until" not in _function_source(tree, name), name
        assert "_PAUSE" not in _function_source(tree, name), name
    assert "POST_TERMINATION_WAIT_SECONDS" in _function_source(tree, "_absent")
    assert "POST_TERMINATION_WAIT_SECONDS" in _function_source(tree, "ended")
    # The pid-only helper is gone: every termination goes through an identity.
    defined = {
        node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
    }
    assert "terminate_pid" not in defined
    assert "terminate_owned" in defined
    pid_only_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "terminate_pid"
    ]
    assert pid_only_calls == []
    # No assertion compares a bounded wait with the forced exit code directly: the
    # ruling's wait contract (``_native_exit``) is the only reader of that value.
    direct_waits = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Compare)
        and isinstance(node.left, ast.Call)
        and isinstance(node.left.func, ast.Attribute)
        and node.left.func.attr == "wait"
        and any(_names_the_forced_exit(item) for item in node.comparators)
    ]
    assert direct_waits == []


# --------------------------------------------------------------------------
# Complete accounting and fixture synchronization: the semantic controls (plan Step
# 2) and the accounting instrument's own pins (plan Step 3)
# --------------------------------------------------------------------------

#: Planted leaks for each reviewed kernel32 creator class (both snapshot kinds): one
#: real acquisition through the reviewed seam, deliberately not released.
_KERNEL32_PLANTS: Final[Mapping[str, Callable[[], int]]] = {
    "process": lambda: open_process_limited(os.getpid()),
    "job": create_kill_on_close_job,
    "process_snapshot": lambda: int(
        windows_api._kernel32().CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    ),
    "thread_snapshot": lambda: int(
        windows_api._kernel32().CreateToolhelp32Snapshot(_TH32CS_SNAPTHREAD, 0)
    ),
    "thread": lambda: int(
        windows_api._kernel32().OpenThread(
            _THREAD_QUERY_LIMITED_INFORMATION, False, threading.get_native_id()
        )
    ),
}
#: Planted leaks on the standard-library route: one real close withheld, in a
#: pre-return constructor failure (both pipe streams with every temporary endpoint, and
#: the null device) or in a post-creation abandonment (both ``Popen`` handles).
_ROUTE_PLANTS: Final = (
    "pipe_read:stdout",
    "pipe_read:stderr",
    "pipe_write:stdout",
    "pipe_write:stderr",
    "pipe_write_inheritable:stdout",
    "pipe_write_inheritable:stderr",
    "devnull_descriptor",
    "devnull_inheritable",
    "popen_process",
    "popen_thread",
)
_PLANTED_LEAKS: Final = (*_KERNEL32_PLANTS, *_ROUTE_PLANTS)


def _kernel32_names() -> set[str]:
    """Every ``_kernel32().<name>`` the production binding module reaches, by AST."""
    source = windows_api.__file__
    assert source is not None
    tree = ast.parse(Path(source).read_text(encoding="utf-8"))
    return {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "_kernel32"
    }


def test_the_resource_classification_is_exhaustive_disjoint_and_fail_closed(
    resource_ledger: _ResourceLedger,
) -> None:
    """Plan Step 3, the instrument's own pins: the reviewed kernel32 surface is split
    into creators and non-creators exhaustively and disjointly against the production
    surface itself; every standard-library name the route classifies as an acquisition,
    release, transfer or observation has a recording wrapper and no other name has one;
    and a name neither seam classifies fails the accounting."""
    creators = set(_KERNEL32_CREATOR_CLASSES)
    assert creators.isdisjoint(_KERNEL32_NON_CREATORS)
    assert creators | _KERNEL32_NON_CREATORS == _kernel32_names()
    assert len(creators | _KERNEL32_NON_CREATORS) == 22
    recorded = {
        f"{module}.{name}"
        for module, names in _STDLIB_ROUTE.items()
        for name, role in names.items()
        if role not in ("neutral", "constant")
    }
    assert recorded == set(resource_ledger.route_factories())
    # Every class the ledger can record has its own planted-leak control.
    creator_classes = {
        kind for kind in _KERNEL32_CREATOR_CLASSES.values() if kind != "snapshot"
    } | set(_SNAPSHOT_CLASSES.values())
    assert creator_classes == set(_KERNEL32_PLANTS)
    assert set(_LAUNCH) | creator_classes == set(_PLANTED_LEAKS)
    probe = _ResourceLedger()
    with probe.operation("unclassified") as operation:
        assert _RouteProxy(probe, "os", os).getpid is os.getpid
        assert _LedgerKernel32(probe, lambda: _PROBE).GetProcessHandleCount is not None
    assert probe.unclassified == ["os.getpid", "kernel32.GetProcessHandleCount"]
    assert probe.audit(operation) == [
        "unclassified route os.getpid",
        "unclassified route kernel32.GetProcessHandleCount",
    ]


@pytest.mark.parametrize(
    "planted", _PLANTED_LEAKS, ids=[label.replace(":", "-") for label in _PLANTED_LEAKS]
)
def test_an_operation_owned_leak_is_detected_despite_unrelated_handle_closure(
    planted: str,
    resource_ledger: _ResourceLedger,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Plan Step 2 semantic control (owner ruling of 2026-11-14): one operation-owned
    leak of every required class -- each reviewed kernel32 creator with both snapshot
    kinds, both pipe streams with every temporary endpoint and the null device in a
    pre-return constructor failure, both ``Popen`` handles in a post-creation
    abandonment -- is detected while a handle the operation does not own is closed
    through the same seam inside the same window, which hides the leak from the
    whole-process count the ruling replaces. The planted resource is reclaimed after
    the detecting assertion, even when the control fails, and the window then balances
    exactly."""
    unrelated: int | None = open_process_limited(os.getpid())  # not the operation's
    leaked: int | None = None
    try:
        with resource_ledger.operation(planted) as operation:
            if planted in _KERNEL32_PLANTS:
                leaked = _KERNEL32_PLANTS[planted]()
            else:
                resource_ledger.withhold.add(planted)
                if planted.startswith("popen_"):
                    monkeypatch.setattr(
                        windows_api, "open_process_limited", _raising("OpenProcess", 5)
                    )
                    outcome = WindowsProcessController().launch(sleep_spec(tmp_root))
                    monkeypatch.undo()
                else:
                    outcome = WindowsProcessController().launch(
                        spec_for(["C:\\nowhere\\absent.exe", "describe"], cwd=tmp_root)
                    )
                assert isinstance(outcome, LaunchFailure)
                assert resource_ledger.withhold == set()  # the planted close ran
            assert unrelated is not None
            close_handle(unrelated)  # an unrelated closure through the same seam
            unrelated = None
        outstanding = resource_ledger.outstanding(operation)
        assert [item.kind for item in outstanding] == [planted]
        with pytest.raises(AssertionError, match=f"{planted}#"):
            _require_zero_unaccounted(operation)
    finally:
        if leaked is not None:
            close_handle(leaked)  # reclaimed after the detecting assertion
        resource_ledger.reclaim()
        if unrelated is not None:
            close_handle(unrelated)
    _require_zero_unaccounted(operation)
    if planted.startswith("popen_"):
        _assert_every_descendant_of_this_process_is_absent()


def test_unrelated_handle_churn_does_not_fail_balanced_operation_cleanup(
    tmp_root: Path, resource_ledger: _ResourceLedger, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Plan Step 2 semantic control (owner ruling of 2026-11-14): balanced
    operation-owned cleanup passes while unrelated handles open and close inside every
    window -- a pre-return constructor failure, a post-creation abandonment and a whole
    launch lifecycle whose retained resources keep their owners until their established
    boundaries and then end, the retained ``Popen`` handle with its object. The
    whole-process count the ruling replaces moves with the churn; complete accounting
    does not. The launch's resume is recorded at the real call: the thread it opened is
    the one ``CreateProcess`` created and its previous suspend count is exactly one."""
    tracking = _TrackingController(WindowsProcessController())
    churn = _UnrelatedChurn()
    try:
        churn.prepare()
        with resource_ledger.operation("failed_construction") as failed:
            churn.step()
            failure = tracking.launch(
                spec_for(["C:\\nowhere\\absent.exe", "describe"], cwd=tmp_root)
            )
        assert isinstance(failure, LaunchFailure)
        _require_observed(failed, _FAILED_CONSTRUCTION)
        _require_zero_unaccounted(failed)
        churn.prepare()
        monkeypatch.setattr(
            windows_api, "open_process_limited", _raising("OpenProcess", 5)
        )
        with resource_ledger.operation("abandoned_construction") as abandoned:
            churn.step()
            abandonment = WindowsProcessController().launch(sleep_spec(tmp_root))
        monkeypatch.undo()
        assert isinstance(abandonment, LaunchFailure)
        _require_observed(abandoned, _ABANDONED_CONSTRUCTION)
        _require_zero_unaccounted(abandoned)
        _assert_every_descendant_of_this_process_is_absent()
        churn.prepare()
        with resource_ledger.operation("launch") as launch:
            churn.step()
            launched = started(tracking.launch(sleep_spec(tmp_root)))
        retained = _launch_retention(resource_ledger, launched)
        _require_observed(launch, _LAUNCH)
        _require_zero_unaccounted(launch, retained=retained)
        ((pid, initial, selected, previous),) = resource_ledger.resumes
        assert (pid, selected, previous) == (launched.pid, initial, 1)
        churn.prepare()
        with resource_ledger.operation("terminate_tree") as termination:
            churn.step()
            report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
            tracking.shape(report)
            tracking.ended(launched, report)
        _require_zero_unaccounted(termination)
        _require_retained(resource_ledger, retained)
        churn.prepare()
        with resource_ledger.operation("release") as release:
            churn.step()
            tracking.release(launched)
            del launched
        _require_zero_unaccounted(release)
        _require_released(resource_ledger, retained)
        assert churn.steps == 5  # unrelated churn inside every one of the five windows
        assert resource_ledger.unclassified == []
        assert {
            "_winapi.CreatePipe",
            "_winapi.DuplicateHandle",
            "_winapi.CreateProcess",
            "_winapi.CloseHandle",
            "msvcrt.open_osfhandle",
            "io.open",
            "os.open",
            "os.close",
        } <= set(resource_ledger.route_calls)
    finally:
        churn.close()
        tracking.cleanup()


def test_a_reused_handle_number_never_merges_two_lifetimes(
    resource_ledger: _ResourceLedger,
) -> None:
    """Acquisition generations (plan Step 3): a number closed and acquired again is a
    second lifetime -- the first stays released and a leak of the second is detected
    alone -- and a number acquired again before any observed release marks the earlier
    lifetime lost, never released. A characterization of the accounting instrument
    (nothing on e44ef7f distinguished lifetimes, so no RED preceded it): fed the
    seams' own bookkeeping calls, then through the real seam."""
    synthetic = _ResourceLedger()
    with synthetic.operation("reuse") as reuse:
        first = synthetic.acquire("process", 0x40, "kernel32.OpenProcess")
        synthetic.release(0x40, "kernel32.CloseHandle")
        second = synthetic.acquire("process", 0x40, "kernel32.OpenProcess")
    assert (first.state, second.state) == ("released", "open")
    assert synthetic.outstanding(reuse) == [second]
    assert synthetic.audit(reuse) == [f"{second.describe()} is unaccounted"]
    synthetic.acquire("process", 0x40, "kernel32.OpenProcess")
    assert second.state == "lost"
    assert len(synthetic.anomalies) == 1
    with resource_ledger.operation("reuse_through_the_seam") as real:
        handle = open_process_limited(os.getpid())
        close_handle(handle)
        again = open_process_limited(os.getpid())
    try:
        earlier, later = real.acquired
        _EVIDENCE.record_phase("handle_reuse", same_number=earlier.value == later.value)
        assert (earlier.state, later.state) == ("released", "open")
        assert (earlier.value, later.value) == (handle, again)
        assert earlier.generation < later.generation
        with pytest.raises(AssertionError, match=f"process#{later.generation} "):
            _require_zero_unaccounted(real)
    finally:
        close_handle(again)
    _require_zero_unaccounted(real)


def test_readiness_failure_cleans_the_partially_established_tree_and_reader(
    tmp_root: Path,
) -> None:
    """Plan Step 2 semantic control, missing acknowledgement: the job-less
    pipe-holder's intermediate parent printed the sleeper's pid and must stay alive
    until the test acknowledges, so nothing is stranded before its identities are bound
    -- without the sentinel the root does not exit within the module bound. A setup
    failure there is cleaned completely by the fixture: the partial tree captured while
    it lived (root, intermediate parent, sleeper launcher and interpreter) ends exactly
    once through the identity-safe paths and is ``ABSENT``, and the stdout reader the
    setup started ends at EOF once its writers are gone, distinct from cancellation.
    Anything a failed control leaves alive is reclaimed through the identity-bound
    path."""
    acknowledgement = tmp_root / _ACKNOWLEDGEMENT
    assert not acknowledgement.exists()
    fixture = _tracking(_failing_job_factory)
    tracking = next(fixture)
    captured: dict[tuple[int, str], ProcessIdentity] = {}
    reader: PipeReader | None = None
    survivors: list[ProcessIdentity] = []
    fresh = WindowsProcessController()
    try:
        launched = started(
            tracking.launch(
                program_spec(SPAWNS_A_SLEEPER_INHERITING_STDOUT_AND_EXITS, cwd=tmp_root)
            )
        )
        root = process_identity_for(launched)
        captured[(root.pid, root.creation_identity)] = root
        sleeper = live_identity_for(_pid_line(launched.stderr, launched=launched))
        captured[(sleeper.pid, sleeper.creation_identity)] = sleeper
        for item in tracking.own_descendants(launched, expect=sleeper.pid):
            captured[(item.pid, item.creation_identity)] = identity_for(
                item.pid, item.creation_identity
            )
        reader = PipeReader(
            launched.stdout, capacity=QUEUE_CAPACITY_CHUNKS, stop=threading.Event()
        )
        reader.start()
        # No acknowledgement: the intermediate parent never exits, so the root lives.
        assert not wait_for_handle(launched.process_handle, _WAIT_BOUND_SECONDS)
        assert not acknowledgement.exists()
        _EVIDENCE.record_phase(
            "partial_setup",
            captured=sorted(item.creation_identity for item in captured.values()),
            reader_alive=reader.is_alive(),
        )
        with pytest.raises(AssertionError, match="setup failed before"):
            fixture.throw(AssertionError("setup failed before the acknowledgement"))
    finally:
        try:
            fixture.close()  # an earlier failure still runs the fixture's cleanup
        finally:
            survivors = [
                identity
                for identity in captured.values()
                if fresh.inspect(identity).presence is ProcessPresence.ALIVE_MATCHING
            ]
            for identity in survivors:  # reclaimed after a failed control only
                fresh.terminate_tree(identity, FORCED_TERMINATION_EXIT_CODE)
    assert survivors == []
    assert len(captured) >= 4  # root, intermediate parent, sleeper launcher, sleeper
    for identity in captured.values():
        assert fresh.inspect(identity).presence is ProcessPresence.ABSENT
    assert reader is not None
    reader.join(READER_JOIN_SECONDS)
    assert not reader.is_alive()
    assert reader.ended_by is ReaderEnd.EOF


def test_a_missing_pid_line_cleans_the_partial_tree_and_its_setup_reader(
    tmp_root: Path,
) -> None:
    """Plan Step 2 semantic control, missing PID readiness through the bounded setup
    read itself: the job-less pipe-holder's sleeper holds the launch's stdout and
    nothing ever prints a pid there, so the one bounded read of it expires -- a
    timeout, never a line or an EOF. The actual setup reader is cancelled and stays
    owned; the partial tree is captured by verified identity while its unacknowledged
    intermediate parent lives and before anything destructive; the fixture cleanup
    ends it exactly once through the identity-safe paths, every captured identity is
    ``ABSENT``, and the cleanup establishes that the setup reader ended -- by its
    cancellation, not by an EOF. Anything a failed control leaves alive is reclaimed
    through the identity-bound path."""
    fixture = _tracking(_failing_job_factory)
    tracking = next(fixture)
    captured: dict[tuple[int, str], ProcessIdentity] = {}
    retained: list[_SetupReader] = []
    survivors: list[ProcessIdentity] = []
    fresh = WindowsProcessController()
    try:
        launched = started(
            tracking.launch(
                program_spec(SPAWNS_A_SLEEPER_INHERITING_STDOUT_AND_EXITS, cwd=tmp_root)
            )
        )
        root = process_identity_for(launched)
        captured[(root.pid, root.creation_identity)] = root
        with pytest.raises(
            AssertionError, match="no line from the child within the bound"
        ):
            _pid_line(launched.stdout, launched=launched)
        key = (root.pid, root.creation_identity)
        retained = [item for item in _SETUP_READERS if item.root == key]
        assert len(retained) == 1  # the actual setup reader stays owned
        for item in tracking.own_descendants(launched):  # while the parent lives
            captured[(item.pid, item.creation_identity)] = identity_for(
                item.pid, item.creation_identity
            )
        _EVIDENCE.record_phase(
            "missing_pid_partial_setup",
            captured=sorted(item.creation_identity for item in captured.values()),
            reader_alive=retained[0].thread.is_alive(),
        )
        with pytest.raises(AssertionError, match="setup failed before"):
            fixture.throw(AssertionError("setup failed before the pid line"))
    finally:
        try:
            fixture.close()  # an earlier failure still runs the fixture's cleanup
        finally:
            survivors = [
                identity
                for identity in captured.values()
                if fresh.inspect(identity).presence is ProcessPresence.ALIVE_MATCHING
            ]
            for identity in survivors:  # reclaimed after a failed control only
                fresh.terminate_tree(identity, FORCED_TERMINATION_EXIT_CODE)
    assert survivors == []
    assert len(captured) >= 4  # root, intermediate parent, sleeper launcher, sleeper
    for identity in captured.values():
        assert fresh.inspect(identity).presence is ProcessPresence.ABSENT
    (reader,) = retained
    assert reader not in _SETUP_READERS  # the cleanup claimed it
    assert not reader.thread.is_alive()
    assert reader.cancellation is True
    assert (reader.lines, reader.errors) == ([], ["OSError"])  # cancelled, not EOF


class _ScriptedSetupThread:
    """A setup reader's thread for the expiry controls: still reading when the one
    bounded join returned; the control scripts what its cancellation then does."""

    def __init__(self) -> None:
        self.alive = True
        self.native_id: int | None = threading.get_native_id()

    def is_alive(self) -> bool:
        return self.alive


_SETUP_EXPIRY_SCRIPTS: Final = (
    "cancellation_ends_the_reader",
    "a_line_arrives_after_expiry",
    "cancellation_raises",
)


@pytest.mark.parametrize("script", _SETUP_EXPIRY_SCRIPTS)
def test_an_expired_setup_read_stays_a_timeout_whatever_follows_the_expiry(
    script: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Plan Step 3, the bounded setup read's verdict: once its one join returned with
    the reader still reading, the read has timed out -- even when the cancellation
    then ends the reader, when a line arrives after the expiry, or when the
    cancellation itself fails. The cancellation outcome is recorded separately and
    never replaces the timeout, and the reader stays owned until a cleanup establishes
    that it ended (this control claims it as the cleanup would)."""
    stand_in = _TimedOutThenAbsent()
    reader = _SetupReader(
        cast(IO[bytes], None), (stand_in.pid, stand_in.creation_identity)
    )
    thread = _ScriptedSetupThread()
    reader.thread = cast(threading.Thread, thread)

    def cancel(native_id: int) -> bool:
        assert native_id == thread.native_id
        if script == "cancellation_raises":
            raise WindowsApiError("CancelSynchronousIo", 5)
        if script == "a_line_arrives_after_expiry":
            reader.lines.append(b"4242\r\n")
        else:
            reader.errors.append("OSError")
        thread.alive = False
        return True

    monkeypatch.setattr(windows_api, "cancel_synchronous_io", cancel)
    claimed: list[_SetupReader] = []
    try:
        with pytest.raises(
            AssertionError, match="no line from the child within the bound"
        ):
            _setup_line(reader, cast(WindowsLaunchedProcess, stand_in))
        expected: object = True
        if script == "cancellation_raises":
            expected = "WindowsApiError:CancelSynchronousIo:5"
        assert reader.cancellation == expected
        assert reader in _SETUP_READERS  # retained until a cleanup claims it
    finally:
        thread.alive = False  # the scripted reader ends; claimed as a cleanup would
        claimed = _claim_setup_readers([reader.root])
        released = [item for item in claimed if _end_setup_reader_ownership(item)]
    assert claimed == released == [reader]
    assert reader not in _discoverable_setup_readers()


def _scripted_setup_reader(root: tuple[int, str] | None) -> _SetupReader:
    """A retained setup reader whose thread the control scripts: still reading until
    the control ends it. No process, no pipe and no wait behind it."""
    reader = _SetupReader(cast(IO[bytes], None), root)
    reader.thread = cast(threading.Thread, _ScriptedSetupThread())
    return reader


def _reclaim_scripted_reader(reader: _SetupReader) -> None:
    """End a scripted reader and drop it from every owning collection: run after the
    control's assertions, including when one of them failed."""
    cast(_ScriptedSetupThread, reader.thread).alive = False
    for registry in (_SETUP_READERS, _UNENDED_SETUP_READERS):
        while reader in registry:
            registry.remove(reader)


def test_a_live_setup_reader_stays_owned_when_the_cleanup_reports_it() -> None:
    """Plan Step 3, setup-reader ownership when the cleanup's check fails: a retained
    reader of an owned root that is still reading when the fixture cleanup looks at it
    fails that cleanup by name -- and stays owned and discoverable, never dropped by the
    look that found it alive; a repeated cleanup still finds and still reports it. Its
    ownership ends only once a zero-duration look establishes its end. A scripted
    reader of an absent stand-in identity (no process, so no termination and no wait),
    reclaimed after the assertions."""
    stand_in = _TimedOutThenAbsent()
    reader = _scripted_setup_reader((stand_in.pid, stand_in.creation_identity))
    tracking = _TrackingController(WindowsProcessController())
    tracking.own(identity_for(stand_in.pid, stand_in.creation_identity))
    _SETUP_READERS.append(reader)  # retained as an expired bounded setup read is
    try:
        for _ in range(2):
            with pytest.raises(AssertionError, match=r"setup reader of .* did not end"):
                tracking.cleanup()
            assert reader in _discoverable_setup_readers()  # still owned, still found
        cast(_ScriptedSetupThread, reader.thread).alive = False  # the reader ends
        tracking.cleanup()  # its end is established now: the cleanup passes ...
        assert reader not in _discoverable_setup_readers()  # ... and only now releases
    finally:
        _reclaim_scripted_reader(reader)


def test_a_live_setup_reader_stays_owned_when_the_ownership_check_reports_it() -> None:
    """Plan Step 3, the autouse ownership check's failure path: a setup reader still
    reading and unclaimed when its test ends fails that check by name, and its
    ownership is transferred explicitly to the module's collection of unended readers --
    still discoverable, never cleared by the check that found it alive. A later check
    keeps it while it still reads (reported once, by its own test) and releases it only
    once a zero-duration look establishes its end. A scripted reader, reclaimed after
    the assertions."""
    reader = _scripted_setup_reader(None)
    _SETUP_READERS.append(reader)
    try:
        with pytest.raises(AssertionError, match="setup readers outlived their test"):
            _check_setup_reader_ownership()
        assert reader in _discoverable_setup_readers()  # still owned after the report
        assert reader in _UNENDED_SETUP_READERS  # transferred, explicitly
        assert reader not in _SETUP_READERS
        _check_setup_reader_ownership()  # a later test's check: kept, not re-reported
        assert reader in _UNENDED_SETUP_READERS
        cast(_ScriptedSetupThread, reader.thread).alive = False  # the reader ends
        _check_setup_reader_ownership()  # its end is established: only now released
        assert reader not in _discoverable_setup_readers()
    finally:
        _reclaim_scripted_reader(reader)


class _ProbeFault:
    """This module's own kernel32 binding with one name answering as scripted -- a
    result and the last error it leaves -- and every other name the real binding."""

    def __init__(self, name: str, result: int, last_error: int) -> None:
        self._real = _PROBE
        self._name = name
        self._result = result
        self._last_error = last_error
        self.calls = 0

    def __getattr__(self, name: str) -> Any:
        if name != self._name:
            return getattr(self._real, name)

        def scripted(*args: object) -> int:
            self.calls += 1
            ctypes.set_last_error(self._last_error)
            return self._result

        return scripted


@pytest.mark.parametrize(
    ("result", "last_error"),
    [(0, 0), (0, _ERROR_INVALID_HANDLE)],
    ids=["unknown_type", "failed_type_probe"],
)
def test_an_inconclusive_type_probe_never_releases_a_live_pipe(
    result: int,
    last_error: int,
    resource_ledger: _ResourceLedger,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Plan Step 3, the C-runtime release proof: a live pipe read end the C runtime
    owns, acquired and transferred through the real standard-library seams, meets a
    type probe that is inconclusive -- ``FILE_TYPE_UNKNOWN`` with no error, or the
    probe failing with its error -- so the accounting must still find it outstanding
    and fail. It is reclaimed after that assertion by a real C-runtime close, which the
    real probe then proves by the refused number (the positive real-close control)."""
    route: Any = windows_process_module.subprocess  # type: ignore[attr-defined]
    stream: Any = None
    with resource_ledger.operation("live_pipe") as operation:
        read, write = route._winapi.CreatePipe(None, 0)
        route._winapi.CloseHandle(write)
        stream = route.io.open(route.msvcrt.open_osfhandle(read, 0), "rb", 0)
    fault = _ProbeFault("GetFileType", result, last_error)
    try:
        monkeypatch.setattr(sys.modules[__name__], "_PROBE", fault)
        with pytest.raises(AssertionError, match=r"pipe_read:stdout#\d+ via "):
            _require_zero_unaccounted(operation)
        (pipe,) = resource_ledger.outstanding(operation)
        assert (pipe.kind, pipe.state, pipe.value) == ("pipe_read:stdout", "crt", read)
        assert fault.calls >= 1  # the type probe was asked and was inconclusive
    finally:
        monkeypatch.undo()
        stream.close()  # reclaimed after the detecting assertion: a real close
    _require_zero_unaccounted(operation)
    assert pipe.released_by == "c_runtime_close:closed"


def test_a_reused_pipe_number_is_released_only_by_a_known_file_type(
    resource_ledger: _ResourceLedger,
) -> None:
    """Plan Step 3, handle reuse at a C-runtime-owned read end's number: once that
    number names another object, a known non-pipe file type -- the null device, a
    character file -- proves the pipe's close; an object the type probe cannot type --
    a process handle -- is inconclusive, so the read end stays outstanding and the
    accounting fails, never released. Real handles at the recorded numbers in a
    synthetic ledger; both are closed after the assertions."""
    ledger = _ResourceLedger()
    null_device = Path(os.devnull).open("rb", buffering=0)
    process = open_process_limited(os.getpid())
    try:
        character = resource_ledger.real_get_osfhandle(null_device.fileno())
        with ledger.operation("reused_numbers") as reused:
            known = ledger.acquire("pipe_read:stdout", character, "_winapi.CreatePipe")
            ledger.transfer(character, 1_000_001)
            untyped = ledger.acquire("pipe_read:stderr", process, "_winapi.CreatePipe")
            ledger.transfer(process, 1_000_002)
        assert ledger.outstanding(reused) == [untyped]
        assert (known.state, known.released_by) == (
            "released",
            "c_runtime_close:other",
        )
        assert untyped.state == "crt"
        _EVIDENCE.record_phase("reused_number_probe", probe=_probe_handle(process))
        with pytest.raises(AssertionError, match=r"pipe_read:stderr#\d+ via "):
            _require_zero_unaccounted(reused)
    finally:
        close_handle(process)
        null_device.close()


def test_a_failed_handle_count_diagnostic_neither_blocks_nor_decides_accounting(
    resource_ledger: _ResourceLedger, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Plan Step 3 (owner ruling of 2026-11-14): the live table count is a diagnostic.
    When collecting it fails (``GetProcessHandleCount`` answers FALSE with error 5),
    the accounting window still opens, a balanced operation still balances and an
    unbalanced one still fails by its unaccounted record -- the failed collection is
    recorded beside each verdict and decides neither. The planted handle is closed
    after the detecting assertion."""
    fault = _ProbeFault("GetProcessHandleCount", 0, 5)
    monkeypatch.setattr(sys.modules[__name__], "_PROBE", fault)
    with resource_ledger.operation("balanced_without_a_count") as balanced:
        close_handle(open_process_limited(os.getpid()))
    _require_zero_unaccounted(balanced)
    ledgers = [row for row in _EVIDENCE.rows if row["kind"] == "ledger"]
    failed = "GetProcessHandleCount failed: 5"
    assert (ledgers[-1]["live_before"], ledgers[-1]["live_after"]) == (failed, failed)
    leaked: int | None = None
    try:
        with resource_ledger.operation("unbalanced_without_a_count") as unbalanced:
            leaked = open_process_limited(os.getpid())
        with pytest.raises(
            AssertionError, match=r"process#\d+ via kernel32.OpenProcess"
        ):
            _require_zero_unaccounted(unbalanced)
    finally:
        if leaked is not None:
            close_handle(leaked)  # reclaimed after the detecting assertion
    _require_zero_unaccounted(unbalanced)
    assert fault.calls >= 4  # every count was asked for, and every one failed


# --------------------------------------------------------------------------
# Route completeness (plan Step 3): a static census of the standard-library code the
# supported launch can reach, not a trace of what one launch happened to call
# --------------------------------------------------------------------------

#: Every attribute production reads on its ``Popen`` object (pinned by AST below).
_PRODUCTION_POPEN_SURFACE: Final = frozenset(
    {"pid", "poll", "stderr", "stdout", "terminate", "wait"}
)
#: Every ``subprocess`` name production reads (pinned by AST below).
_PRODUCTION_SUBPROCESS_NAMES: Final = frozenset(
    {"CREATE_NEW_PROCESS_GROUP", "DEVNULL", "PIPE", "Popen", "TimeoutExpired"}
)
#: The roles a reachable name or receiver-fixed site outside the four proxied modules
#: may have; none of them acquires a resource. ``release_seam`` is the ``Handle.Close``
#: default the seams replace; a ``native`` callable is trusted to return no resource the
#: operation owns (whatever it holds internally is the implementation's, acquired and
#: released within the call and outside every ledger -- the bound of this proof);
#: ``python`` is foreign pure-Python bookkeeping; ``data`` a plain read; and
#: ``none_receiver`` a load on a global that is ``None`` here (asserted), which raises
#: before any call. No role is given by attribute name alone: a site whose receiver
#: only dataflow or branch analysis could fix is in ``_RECEIVER_TYPED_SITES`` or
#: ``_OFF_PATH_SITES``, never here.
_NON_ACQUIRING_ROLES: Final = frozenset(
    {"builtin", "data", "native", "none_receiver", "python", "release_seam"}
)
_ROUTE_OUTSIDE_THE_SEAMS: Final[Mapping[str, str]] = {
    # callables bound at definition, which no module proxy sees
    "default:seam._ResourceLedger.popen_close.<locals>.close": "release_seam",
    "default:_winapi.WaitForSingleObject": "native",  # ``_internal_poll``
    "default:_winapi.GetExitCodeProcess": "native",  # ``_internal_poll``
    "default:_warnings.warn": "native",  # ``__del__``
    "global:time.monotonic": "native",
    "wrapper:contextmanager.<locals>.helper": "python",  # ``_on_error_fd_closer``
    "contextlib.ExitStack": "python",
    "threading.Lock": "native",  # no handle on this CPython: SRW lock and condition
    "sys.audit": "native",  # runs installed audit hooks; a hook's holdings are its own
    "sys._getframe": "native",
    "locale.getencoding": "native",
    "warnings.warn": "native",
    "sys.flags": "data",
    "sys.platform": "data",
    "errno.ENOTSUP": "data",
    # ``hasattr(os, ...)`` presence probes on the user and group branches: no call
    "os as LOAD_CONST 'setgroups' in __init__": "data",
    "os as LOAD_CONST 'setregid' in __init__": "data",
    "os as LOAD_CONST 'setreuid' in __init__": "data",
    **{
        f"builtins.{name}": "builtin"
        for name in (
            "EncodingWarning",
            "FileNotFoundError",
            "ImportError",
            "KeyboardInterrupt",
            "OSError",
            "PermissionError",
            "ResourceWarning",
            "RuntimeWarning",
            "TypeError",
            "ValueError",
            "bool",
            "bytes",
            "filter",
            "getattr",
            "hasattr",
            "int",
            "isinstance",
            "len",
            "list",
            "map",
            "min",
            "str",
            "type",
        )
    },
    # ``os.path`` is ``ntpath`` here: pure path-string functions (the shell branch)
    "ntpath.isabs": "python",
    "ntpath.join": "python",
    # Sites whose receiver the bytecode alone fixes, each with its basis:
    # ``_active`` is the module global, ``None`` on Windows (asserted by the census
    # test; no reached code rebinds a global, or it would be listed):
    "Popen.__del__: global _active.append()": "none_receiver",
    # the module attribute ``os.environ`` (``os._Environ``), a mapping read:
    "Popen._execute_child: os.environ.get()": "python",
    # fields of the module attribute ``sys.flags``, a struct sequence:
    "_text_encoding: sys.flags.utf8_mode": "data",
    "_text_encoding: sys.flags.warn_default_encoding": "data",
    # the typed instance's class (``Handle`` defines no ``__class__``), then its name:
    "Handle.__repr__: self.__class__.__name__": "data",
}
#: Every reached site whose receiver the bytecode alone does not fix (a local or
#: parameter, an expression's result, a constant whose method runs its arguments'
#: protocol, a runtime import) is never labelled non-acquiring by its name. Each has
#: exactly one of two dispositions, checked statically against the bytecode and the
#: source (``test_every_receiver_site_is_typed_at_its_load_or_guarded_off_the_path``)
#: and at run time, in every accounting window, by the receiver-site monitor
#: (``_SiteMonitor``), which fails the window's audit (fail closed):
#:
#: * on the supported path, ``_RECEIVER_TYPED_SITES``: the receiver is the local the
#:   bytecode loads immediately before the attribute (for ``str.join`` the argument
#:   loaded immediately after it), and at every execution the monitor reads that local
#:   from the executing frame and requires exactly one of the named types -- each of
#:   which fixes a callee that acquires nothing: own code this census follows, a
#:   builtin container method, the seamed ``Handle.Close``, the C-runtime close of a
#:   recorded stream, foreign pure-Python bookkeeping, a plain data read;
#: * off the supported path, ``_OFF_PATH_SITES``: every instruction of the site lies
#:   in a branch production's fixed ``Popen`` arguments (pinned by AST) or the
#:   interpreter's asserted flags never take, or in a function only such a site calls;
#:   its execution inside any accounting window fails that window.
#:
#: Pinned exactly: a new site fails until it is dispositioned, a gone one is stale.
_RECEIVER_TYPED_SITES: Final[Mapping[str, tuple[str, tuple[str, ...]]]] = {
    # ``_get_handles`` wraps each pipe end it creates in ``Handle`` (the own class)
    "Popen.__init__: c2pread.Detach()": ("c2pread", ("Handle",)),
    "Popen.__init__: errread.Detach()": ("errread", ("Handle",)),
    "Popen.__init__: p2cwrite.Detach()": ("p2cwrite", ("Handle",)),
    # the construction's own streams (unbuffered), or this module's planted wrapper
    "Popen.__init__: f.close()": ("f", ("FileIO", "withheld")),
    "Popen.__init__: fd.Close()": ("fd", ("Handle",)),
    "Popen.__init__: to_close.append()": ("to_close", ("list",)),
    "Popen._close_pipe_fds: c2pwrite.Close": ("c2pwrite", ("Handle",)),
    "Popen._close_pipe_fds: errwrite.Close": ("errwrite", ("Handle",)),
    "Popen._close_pipe_fds: p2cread.Close": ("p2cread", ("Handle",)),
    "Popen._close_pipe_fds: stack.callback()": ("stack", ("ExitStack",)),
    "Popen._execute_child: startupinfo.dwFlags": ("startupinfo", ("STARTUPINFO",)),
    "Popen._execute_child: startupinfo.lpAttributeList": (
        "startupinfo",
        ("STARTUPINFO",),
    ),
    "Popen._execute_child: attribute_list.get()": ("attribute_list", ("dict",)),
    "Popen._get_handles: err_close_fds.append()": ("err_close_fds", ("list",)),
    "Popen._get_handles: err_close_fds.extend()": ("err_close_fds", ("list",)),
    "Popen._on_error_fd_closer: fd.Close()": ("fd", ("Handle",)),
    # the wrapped generator's ``self``: a ``Popen``, read for a plain instance field
    "Popen._on_error_fd_closer: self._devnull": ("self", ("Popen",)),
    "Popen._on_error_fd_closer: to_close.append()": ("to_close", ("list",)),
    "list2cmdline: bs_buf.append()": ("bs_buf", ("list",)),
    "list2cmdline: result.append()": ("result", ("list",)),
    "list2cmdline: result.extend()": ("result", ("list",)),
    # ``''.join(result)``: the argument whose protocol the call runs, a list of text
    "list2cmdline: const str.join()": ("result", ("list_of_str",)),
}
#: The supported path's branches each off-path site lies under (``if <test>``: the
#: body; ``else <test>``: the ``else``, where an ``elif`` chain nests), with their bases
#: pinned by the static test: production passes ``shell=False``, ``stdin=DEVNULL``,
#: ``stdout=PIPE`` and ``stderr=PIPE`` and no ``group``, ``extra_groups``, ``user`` or
#: ``startupinfo`` (each ``None`` by default), and this interpreter runs without
#: ``-X warn_default_encoding``.
_GROUP: Final = "if group is not None"
_EXTRA_GROUPS: Final = "if extra_groups is not None"
_USER: Final = "if user is not None"
_SHELL: Final = "if shell"
_STARTUPINFO_GIVEN: Final = "else startupinfo is None"
_STDIN_OTHER: Final = "else stdin == DEVNULL"
_STDOUT_OTHER: Final = "else stdout == PIPE"
_STDERR_OTHER: Final = "else stderr == PIPE"
_WARN_ENCODING: Final = "if sys.flags.warn_default_encoding"
#: ``STARTUPINFO.copy`` is followed only because the name ``copy`` is loaded; every
#: such load in reached code is this off-path site or inside ``copy`` itself.
_COPY_CALLER: Final = "called only from Popen._execute_child: startupinfo.copy()"
_OFF_PATH_SITES: Final[Mapping[str, tuple[str, ...]]] = {
    "Popen.__init__: <CALL>.gr_gid": (_GROUP, _EXTRA_GROUPS),
    "Popen.__init__: <CALL>.pw_uid": (_USER,),
    "Popen.__init__: IMPORT_NAME grp": (_GROUP, _EXTRA_GROUPS),
    "Popen.__init__: IMPORT_NAME pwd": (_USER,),
    "Popen.__init__: const str.format()": (_GROUP, _EXTRA_GROUPS),
    "Popen.__init__: gids.append()": (_EXTRA_GROUPS,),
    "Popen.__init__: grp.getgrnam()": (_GROUP, _EXTRA_GROUPS),
    "Popen.__init__: pwd.getpwnam()": (_USER,),
    "Popen._execute_child: const str.format()": (_SHELL,),
    "Popen._execute_child: startupinfo.copy()": (_STARTUPINFO_GIVEN,),
    "Popen._get_handles: stdin.fileno()": (_STDIN_OTHER,),
    "Popen._get_handles: stdout.fileno()": (_STDOUT_OTHER,),
    "Popen._get_handles: stderr.fileno()": (_STDERR_OTHER,),
    "STARTUPINFO.copy: self.lpAttributeList.copy()": (_COPY_CALLER,),
    "_text_encoding: f.f_back": (_WARN_ENCODING,),
    "_text_encoding: f.f_code": (_WARN_ENCODING,),
    "_text_encoding: f.f_code.co_filename": (_WARN_ENCODING,),
}
#: The receiver sites a construction window must observe, so that its monitor's zero
#: is never vacuous: every construction (both pipes made and wrapped, the child-side
#: ends closed after ``CreateProcess``, the command line built), then a failed one's
#: cleanup of its own streams, and a failure while the handles are still being built.
_CONSTRUCTION_RECEIVERS: Final = (
    "Popen.__init__: c2pread.Detach()",
    "Popen.__init__: errread.Detach()",
    "Popen._close_pipe_fds: c2pwrite.Close",
    "Popen._close_pipe_fds: errwrite.Close",
    "Popen._close_pipe_fds: p2cread.Close",
    "Popen._close_pipe_fds: stack.callback()",
    "Popen._execute_child: attribute_list.get()",
    "Popen._execute_child: startupinfo.dwFlags",
    "Popen._execute_child: startupinfo.lpAttributeList",
    "Popen._get_handles: err_close_fds.extend()",
    "list2cmdline: const str.join()",
    "list2cmdline: result.append()",
)
_FAILED_CONSTRUCTION_RECEIVERS: Final = (
    *_CONSTRUCTION_RECEIVERS,
    "Popen.__init__: f.close()",
)
_HANDLE_SETUP_FAILURE_RECEIVERS: Final = (
    "Popen._get_handles: err_close_fds.extend()",
    "Popen._on_error_fd_closer: fd.Close()",
    "Popen._on_error_fd_closer: self._devnull",
    "Popen._on_error_fd_closer: to_close.append()",
)
#: The ``sys.monitoring`` tool ids no standard tool reserves (0 debugger, 1 coverage,
#: 2 profiler, 5 optimizer): the monitor takes the first free one per window.
_MONITOR_TOOLS: Final = (3, 4)
_NO_RECEIVER: Final = object()


class _SiteRule:
    """One receiver site's disposition: an off-path site (no receiver local), or the
    receiver local and the exact types it may hold (``items``: the type every element
    of an admitted container must have)."""

    def __init__(
        self,
        label: str,
        local: str | None,
        admitted: tuple[type, ...],
        items: type | None = None,
    ) -> None:
        self.label = label
        self.local = local
        self.admitted = admitted
        self.items = items

    def judge(self, frame: Any, code: CodeType, observed: list[tuple[str, str]]) -> str:
        """The problem one execution of the site shows, or ``""``; the receiver's type
        (never its value) is recorded."""
        if frame.f_code is not code:
            return f"{self.label}: executed outside a frame of its own code"
        if self.local is None:
            observed.append((self.label, "off_path"))
            return f"{self.label}: an off-path site executed"
        receiver = frame.f_locals.get(self.local, _NO_RECEIVER)
        verdict = type(receiver).__qualname__
        admitted = type(receiver) in self.admitted
        if admitted and self.items is not None:
            verdict = f"{verdict}[{self.items.__qualname__}]"
            admitted = all(type(item) is self.items for item in receiver)
        observed.append((self.label, verdict))
        if admitted:
            return ""
        names = ", ".join(kind.__qualname__ for kind in self.admitted)
        return f"{self.label}: receiver {verdict} is none of {names}"


_SITE_TABLE: Final[dict[tuple[CodeType, int], _SiteRule]] = {}


def _receiver_types(
    namespace: Mapping[str, Any],
) -> dict[str, tuple[type, type | None]]:
    """The admitted receiver types by key, resolved to the objects themselves."""
    return {
        "Handle": (namespace["Handle"], None),
        "STARTUPINFO": (namespace["STARTUPINFO"], None),
        "Popen": (namespace["Popen"], None),
        "ExitStack": (_real_global(namespace, "contextlib").ExitStack, None),
        "FileIO": (_real_global(namespace, "io").FileIO, None),
        "withheld": (_WithheldStream, None),
        "list": (list, None),
        "dict": (dict, None),
        "list_of_str": (list, str),
    }


def _receiver_site_table() -> dict[tuple[CodeType, int], _SiteRule]:
    """Every receiver site's instructions -- (code, offset) from the census of the
    supported launch's entry points -- with its rule; computed once per module."""
    if not _SITE_TABLE:
        namespace = _route_namespace()
        locations: dict[str, list[tuple[CodeType, int]]] = {}
        _route_census(namespace, _route_entry_points(namespace), locations=locations)
        types = _receiver_types(namespace)
        for label, places in locations.items():
            if label in _RECEIVER_TYPED_SITES:
                local, keys = _RECEIVER_TYPED_SITES[label]
                resolved = [types[key] for key in keys]
                items = {item for _, item in resolved} - {None}
                rule = _SiteRule(
                    label,
                    local,
                    tuple(kind for kind, _ in resolved),
                    next(iter(items)) if items else None,
                )
            elif label in _OFF_PATH_SITES:
                rule = _SiteRule(label, None, ())
            else:
                continue
            for place in places:
                _SITE_TABLE[place] = rule
    return _SITE_TABLE


class _SiteMonitor:
    """The receiver-site monitor (plan Step 3, route completeness at run time). Inside
    one accounting window it enables ``sys.monitoring`` instruction events on exactly
    the code objects that hold a construction-route receiver site; at a site it judges
    the receiver it reads from the executing frame, and every other instruction is
    disabled at its first event. An off-path site that executes, a receiver of any
    other type or a frame of other code is a problem the window's audit reports. It
    observes only: no wait, no value recorded, no call into the code it watches."""

    def __init__(self) -> None:
        self.observed: list[tuple[str, str]] = []
        self.problems: list[str] = []
        self._tool: int | None = None
        self._codes: set[CodeType] = set()
        self._sites: Mapping[tuple[CodeType, int], _SiteRule] = {}

    def start(self) -> None:
        monitoring = sys.monitoring
        self._sites = _receiver_site_table()
        self._codes = {code for code, _ in self._sites}
        self.observed, self.problems = [], []
        free = [tool for tool in _MONITOR_TOOLS if monitoring.get_tool(tool) is None]
        assert free, "no free sys.monitoring tool id for the receiver-site monitor"
        tool = self._tool = free[0]
        monitoring.use_tool_id(tool, "receiver-site monitor")
        monitoring.register_callback(tool, monitoring.events.INSTRUCTION, self._event)
        for code in self._codes:
            monitoring.set_local_events(tool, code, monitoring.events.INSTRUCTION)

    def stop(self) -> tuple[list[tuple[str, str]], list[str]]:
        monitoring = sys.monitoring
        tool, self._tool = self._tool, None
        if tool is not None:
            for code in self._codes:
                monitoring.set_local_events(tool, code, 0)  # no events
            monitoring.register_callback(tool, monitoring.events.INSTRUCTION, None)
            monitoring.free_tool_id(tool)
        return self.observed, self.problems

    def _event(self, code: CodeType, offset: int) -> object:
        rule = self._sites.get((code, offset))
        if rule is None:
            return sys.monitoring.DISABLE
        problem = rule.judge(sys._getframe(1), code, self.observed)
        if problem:
            self.problems.append(problem)
        return None


def _functions_of(member: object) -> list[FunctionType]:
    """The Python functions behind one class member (plain, static, class, property)."""
    if isinstance(member, staticmethod | classmethod):
        member = member.__func__
    if isinstance(member, property):
        accessors = (member.fget, member.fset, member.fdel)
        return [item for item in accessors if isinstance(item, FunctionType)]
    return [member] if isinstance(member, FunctionType) else []


def _route_namespace() -> dict[str, Any]:
    """``subprocess``'s own globals dictionary, reached through the production module
    only (the seams' proxies inside it are read through to the real modules)."""
    launch_module: Any = windows_process_module.subprocess  # type: ignore[attr-defined]
    return cast(dict[str, Any], vars(launch_module))


def _real_global(namespace: Mapping[str, Any], name: str) -> Any:
    value = namespace[name]
    return value._real if isinstance(value, _RouteProxy) else value


def _route_entry_points(namespace: Mapping[str, Any]) -> list[FunctionType]:
    """The ``subprocess`` code production runs: construction, every ``Popen`` method in
    production's pinned surface, and the end of the object and of its handles."""
    popen = vars(namespace["Popen"])
    names = ["__init__", "__del__", *sorted(_PRODUCTION_POPEN_SURFACE)]
    entry = [item for name in names for item in _functions_of(popen.get(name))]
    entry.extend(_functions_of(vars(namespace["Handle"])["Close"]))
    return entry


def _bound_name(value: object) -> str:
    module = getattr(value, "__module__", None)
    if module == __name__:
        module = "seam"
    return f"{module}.{getattr(value, '__qualname__', type(value).__name__)}"


def _route_census(
    namespace: Mapping[str, Any],
    entry: Iterable[FunctionType],
    *,
    locations: dict[str, list[tuple[CodeType, int]]] | None = None,
    codes_seen: set[CodeType] | None = None,
) -> set[str]:
    """Every name the Python code reachable from ``entry`` can load, statically and
    over-approximated (a branch production never takes is still reached): a module
    global's attribute as ``module.name`` (followed through an attribute that is itself
    a module; a module used otherwise as itself), a builtin as ``builtins.name``, a
    foreign callable global as ``global:...``, every callable default or closure value
    of a reached function as ``default:...`` (bound at definition, so no proxy sees
    it), and a function whose code belongs to another module as ``foreign:...``.

    Every other attribute load is a site, ``function: receiver.name`` (``()`` when it
    is loaded as a method): the receiver as the bytecode alone fixes it -- a local by
    name, ``global x``, a module attribute, ``const <type>``, an attribute chain, or
    ``<opname>``/``<merge>`` when no single producer is known (``COPY 1`` duplicates
    the top of the stack, so it keeps the receiver). A name never certifies a
    receiver: the one receiver the census types is the instance of an own class's
    method (its first argument, never rebound), on which an own member is followed and
    a plain data read lists nothing; an own method name loaded on any other receiver is
    followed and still listed. The module's own functions (by their globals) and the
    members of a class loaded as a global are followed, not listed. ``locations``
    receives every site's instructions (code and offset) and ``codes_seen`` every code
    object read, for the receiver-site monitor and its static checks."""

    def own(value: object) -> bool:
        return isinstance(value, FunctionType) and value.__globals__ is namespace

    def site(label: str, code: CodeType, offset: int) -> None:
        reached.add(label)
        if locations is not None:
            locations.setdefault(label, []).append((code, offset))

    classes: dict[str, list[FunctionType]] = {}
    methods: dict[str, list[FunctionType]] = {}
    instance_codes: set[CodeType] = set()
    for name in namespace:
        value = _real_global(namespace, name)
        if isinstance(value, type) and value.__module__ == namespace["__name__"]:
            members = vars(value)
            classes[name] = [
                item for m in members.values() for item in _functions_of(m)
            ]
            for attribute, member in members.items():
                methods.setdefault(attribute, []).extend(_functions_of(member))
                if isinstance(member, FunctionType | property):
                    instance_codes.update(
                        item.__code__ for item in _functions_of(member)
                    )
    reached: set[str] = set()
    pending = list(entry)
    followed: set[FunctionType] = set()
    if codes_seen is None:
        codes_seen = set()
    while pending:
        function = pending.pop()
        if function in followed:
            continue
        followed.add(function)
        if not own(function):
            wrapped = getattr(function, "__wrapped__", None)
            if isinstance(wrapped, FunctionType) and own(wrapped):
                # a decorator's wrapper: the wrapped function's own code is followed
                reached.add(f"wrapper:{function.__code__.co_qualname}")
                pending.append(wrapped)
                continue
            reached.add("foreign:" + _bound_name(function))
            continue
        bound = [
            *(function.__defaults__ or ()),
            *(function.__kwdefaults__ or {}).values(),
            *(cell.cell_contents for cell in function.__closure__ or ()),
        ]
        for value in bound:
            if own(value):
                pending.append(value)
            elif callable(value):
                reached.add("default:" + _bound_name(value))
        codes = [function.__code__]
        while codes:
            code = codes.pop()
            if code in codes_seen:
                continue
            codes_seen.add(code)
            codes.extend(item for item in code.co_consts if isinstance(item, CodeType))
            instructions = list(dis.get_instructions(code))
            instance = _instance_name(code, instructions, instance_codes)
            module: ModuleType | None = None
            receiver = "<start>"  # what the bytecode fixes about the top of the stack
            typed = False  # whether that is the typed instance itself
            for instruction in instructions:
                name = instruction.argval
                opname = instruction.opname
                if instruction.is_jump_target:
                    receiver = "<merge>"  # more than one producer can reach this point
                    typed = False
                instruction_typed, typed = typed, False
                if module is not None:
                    if opname == "LOAD_ATTR" and not instruction.is_jump_target:
                        reached.add(f"{module.__name__}.{name}")
                        loaded: object = getattr(module, name, None)
                        receiver = f"{module.__name__}.{name}"
                        module = loaded if isinstance(loaded, ModuleType) else None
                        continue
                    # a module escaping as a value: named with its use, unclassified
                    reached.add(
                        f"{module.__name__} as {opname} {instruction.argval!r}"
                        f" in {code.co_name}"
                    )
                    module = None
                if opname == "LOAD_GLOBAL":
                    receiver = f"global {name}"
                    if name not in namespace:
                        reached.add(f"builtins.{name}")
                        continue
                    value = _real_global(namespace, name)
                    if isinstance(value, ModuleType):
                        module = value
                    elif name in classes:
                        pending.extend(classes[name])
                    elif own(value):
                        pending.append(value)
                    elif callable(value):
                        reached.add("global:" + _bound_name(value))
                elif opname == "LOAD_ATTR":
                    called = bool((instruction.arg or 0) & 1)
                    own_members = methods.get(name, [])
                    pending.extend(own_members)  # own code: over-approximated, harmless
                    if not instruction_typed or (called and not own_members):
                        label = f"{code.co_qualname}: {receiver}.{name}"
                        site(label + ("()" if called else ""), code, instruction.offset)
                    receiver = "<method>" if called else f"{receiver}.{name}"
                elif opname == "LOAD_SUPER_ATTR":
                    site(
                        f"{code.co_qualname}: super().{name}", code, instruction.offset
                    )
                    receiver = "<super>"
                elif opname in ("IMPORT_NAME", "STORE_GLOBAL", "DELETE_GLOBAL"):
                    # a runtime import runs foreign code; a rebound global unfixes it
                    label = f"{code.co_qualname}: {opname} {name}"
                    site(label, code, instruction.offset)
                    receiver = f"<{opname}>"
                elif opname in _LOCAL_LOADS:
                    receiver = "self" if name == instance else name
                    typed = name == instance
                elif opname == "LOAD_CONST":
                    receiver = f"const {type(name).__name__}"
                elif opname == "COPY" and instruction.arg == 1:
                    typed = instruction_typed  # the same object again: receiver kept
                else:
                    receiver = f"<{opname}>"
    return reached


#: The 3.12 instructions that push one local or cell variable's value.
_LOCAL_LOADS: Final = frozenset(
    {"LOAD_FAST", "LOAD_FAST_CHECK", "LOAD_FAST_AND_CLEAR", "LOAD_DEREF"}
)


def _instance_name(
    code: CodeType, instructions: list[dis.Instruction], instance_codes: set[CodeType]
) -> str | None:
    """The one receiver the census types: the first argument of a method of one of the
    module's own classes (``self``), and only while the method never rebinds it; a
    closure's copy of it is not typed."""
    if code not in instance_codes or not code.co_argcount:
        return None
    first = code.co_varnames[0]
    rebinds = {"STORE_FAST", "DELETE_FAST", "STORE_DEREF", "DELETE_DEREF"}
    if any(item.opname in rebinds and item.argval == first for item in instructions):
        return None
    return first


def _route_unclassified(reached: Iterable[str]) -> list[str]:
    classified = {
        f"{module}.{name}" for module, names in _STDLIB_ROUTE.items() for name in names
    }
    classified.update(_ROUTE_OUTSIDE_THE_SEAMS)
    return sorted(set(reached) - classified)


def test_every_standard_library_route_the_launch_can_reach_is_classified() -> None:
    """Plan Step 3, route completeness without a trace. Production's whole
    ``subprocess`` surface -- the names it reads on the module and on its ``Popen``
    object -- is pinned by AST. A static census of everything the Python code behind
    that surface can reach (construction, every pinned method, the object's and its
    handles' end, every exception path, every callable bound as a default) is then
    dispositioned name by name and site by site: every name in the four proxied modules
    by the role the seams record it with; every other name, and every site whose
    receiver the bytecode alone fixes, by a role that acquires nothing; every other
    site -- its receiver not fixed by the bytecode -- is either receiver-typed on the
    supported path or guarded off it, pinned exactly (``_RECEIVER_TYPED_SITES``,
    ``_OFF_PATH_SITES``; checked statically by the next test and in every accounting
    window by the site monitor). Every disposition is reached (none stale). A planted
    function with an unclassified acquisition, a bare-module escape and an unseamed
    bound close fails the census (fail closed). The bound: a native callable is trusted
    to return exactly the resources its role names -- what it holds internally is no
    resource the operation owns; implicit protocol calls (``with``, iteration,
    operators) and calls through a local callable are not sites of this census."""
    production = windows_process_module.__file__
    assert production is not None
    tree = ast.parse(Path(production).read_text(encoding="utf-8"))
    popen_reads = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and (
            (isinstance(node.value, ast.Name) and node.value.id == "popen")
            or (isinstance(node.value, ast.Attribute) and node.value.attr == "_popen")
        )
    }
    assert popen_reads == _PRODUCTION_POPEN_SURFACE
    module_reads = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "subprocess"
    }
    assert module_reads == _PRODUCTION_SUBPROCESS_NAMES
    namespace = _route_namespace()
    reached = _route_census(namespace, _route_entry_points(namespace))
    unclassified = _route_unclassified(reached)
    assert set(_RECEIVER_TYPED_SITES).isdisjoint(_OFF_PATH_SITES)
    dispositioned = sorted({*_RECEIVER_TYPED_SITES, *_OFF_PATH_SITES})
    drift = sorted(set(unclassified) ^ set(dispositioned))
    assert unclassified == dispositioned, " ".join(drift)
    assert namespace["_active"] is None  # the ``none_receiver`` site's basis
    proxied = {
        f"{module}.{name}" for module, names in _STDLIB_ROUTE.items() for name in names
    }
    assert sorted(proxied - reached) == []  # no stale seam classification
    assert sorted(set(_ROUTE_OUTSIDE_THE_SEAMS) - reached) == []
    assert set(_ROUTE_OUTSIDE_THE_SEAMS.values()) <= _NON_ACQUIRING_ROLES
    acquiring = {
        f"{module}.{name}"
        for module, names in _STDLIB_ROUTE.items()
        for name, role in names.items()
        if role in ("acquire", "transfer")
    }
    assert acquiring == {
        "_winapi.CreatePipe",
        "_winapi.DuplicateHandle",
        "_winapi.CreateProcess",
        "msvcrt.open_osfhandle",
        "os.open",
        "io.open",
    }
    planted_source = (
        "def planted(close=None):\n"
        "    return os.pipe(), open(os.devnull), _winapi.CreateFile, getattr(\n"
        "        os, 'dup'\n"
        "    )\n"
    )
    (planted_code,) = (
        item
        for item in compile(planted_source, "<planted>", "exec").co_consts
        if isinstance(item, CodeType)
    )
    real_close = _real_global(namespace, "_winapi").CloseHandle
    planted = FunctionType(planted_code, namespace, "planted", (real_close,))
    assert _route_unclassified(_route_census(namespace, [planted])) == [
        "_winapi.CreateFile",
        "builtins.open",
        "default:_winapi.CloseHandle",
        "os as LOAD_CONST 'dup' in planted",
        "os.pipe",
    ]


def test_the_route_census_never_certifies_an_unknown_receivers_call_by_name() -> None:
    """Plan Step 3, route completeness by receiver: an attribute name the census met on
    one receiver (``.get`` on a mapping, ``Close`` on the module's own ``Handle``)
    certifies no other receiver. A planted function compiled with ``subprocess``'s own
    namespace calls ``holder.get()`` and ``holder.Close()`` on a parameter whose object
    and resource behaviour the census cannot know: both calls are reported as
    unclassified sites -- function, receiver and attribute -- never certified from the
    name alone, and never given a non-acquiring label."""
    namespace = _route_namespace()
    planted_source = (
        "def planted(holder):\n    holder.Close()\n    return holder.get()\n"
    )
    (planted_code,) = (
        item
        for item in compile(planted_source, "<planted>", "exec").co_consts
        if isinstance(item, CodeType)
    )
    planted = FunctionType(planted_code, namespace, "planted")
    assert _route_unclassified(_route_census(namespace, [planted])) == [
        "planted: holder.Close()",
        "planted: holder.get()",
    ]


def test_the_post_launch_route_reaches_no_unresolved_site() -> None:
    """Plan Step 3, the route the inspection and tree-termination accounting relies on.
    Once a launch returned, production reads its ``Popen`` object only as
    ``self._popen.pid`` (a plain read) and ``self._popen.poll()`` (from
    ``WindowsLaunchedProcess.wait``), pinned by AST; the object's end runs
    ``Popen.__del__`` and its handle's ``Close`` (``Handle.__del__`` is that function).
    The census of exactly these entries reaches no UNRESOLVED site and nothing
    unclassified, so complete accounting replaces R2's live equality at
    ``test_terminate_tree_and_inspection_leave_the_handle_table_unchanged`` -- whose
    inspection windows reach no ``subprocess`` code at all. Non-vacuous: the census
    reaches the native waits, the seamed close and the ``None`` receiver's site."""
    production = windows_process_module.__file__
    assert production is not None
    tree = ast.parse(Path(production).read_text(encoding="utf-8"))
    after_launch = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "_popen"
    }
    assert after_launch == {"pid", "poll"}
    namespace = _route_namespace()
    popen = vars(namespace["Popen"])
    handle = vars(namespace["Handle"])
    assert handle["__del__"] is handle["Close"]
    entry = [
        *_functions_of(popen["poll"]),
        *_functions_of(popen["__del__"]),
        *_functions_of(handle["Close"]),
    ]
    reached = _route_census(namespace, entry)
    assert _route_unclassified(reached) == []
    assert {
        "default:_winapi.WaitForSingleObject",
        "default:_winapi.GetExitCodeProcess",
        "default:seam._ResourceLedger.popen_close.<locals>.close",
        "Popen.__del__: global _active.append()",
    } <= reached


def _instruction_at(code: CodeType, offset: int) -> tuple[list[dis.Instruction], int]:
    instructions = list(dis.get_instructions(code))
    (index,) = (at for at, item in enumerate(instructions) if item.offset == offset)
    return instructions, index


def _enclosing_branches(tree: ast.AST, line: int) -> set[str]:
    """Every branch of an ``if`` in the source that encloses ``line``: ``if <test>``
    for its body, ``else <test>`` for its ``else`` (where an ``elif`` chain nests)."""
    branches: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        for branch, body in (("if", node.body), ("else", node.orelse)):
            if body and body[0].lineno <= line <= (body[-1].end_lineno or 0):
                branches.add(f"{branch} {ast.unparse(node.test)}")
    return branches


def test_every_receiver_site_is_typed_at_its_load_or_guarded_off_the_path() -> None:
    """Plan Step 3, the construction route's receiver sites, statically; the site
    monitor checks the same instructions at run time in every accounting window. A
    receiver-typed site's receiver is the local loaded immediately before its attribute
    (``COPY 1`` keeps it; ``str.join``'s argument is loaded immediately after), so the
    local the monitor reads is the very object the attribute is read on. Every
    instruction of an off-path site lies, in the standard library's own source, under
    one of its guards, and each guard's basis is pinned: production's ``Popen`` call
    passes ``shell=False``, ``stdin=DEVNULL``, ``stdout=PIPE`` and ``stderr=PIPE`` and
    none of the arguments whose ``None`` default keeps the other branches closed; this
    interpreter runs without ``-X warn_default_encoding``; the name ``copy`` is loaded
    in reached code only at the off-path site and inside ``STARTUPINFO.copy``. Every
    receiver site's instructions are in the monitor's table with their rule."""
    namespace = _route_namespace()
    locations: dict[str, list[tuple[CodeType, int]]] = {}
    codes: set[CodeType] = set()
    _route_census(
        namespace,
        _route_entry_points(namespace),
        locations=locations,
        codes_seen=codes,
    )
    table = _receiver_site_table()
    for label, (local, keys) in _RECEIVER_TYPED_SITES.items():
        assert locations[label], label
        for code, offset in locations[label]:
            instructions, index = _instruction_at(code, offset)
            if keys == ("list_of_str",):
                producer = instructions[index + 1]
            else:
                before = index - 1
                while (instructions[before].opname, instructions[before].arg) == (
                    "COPY",
                    1,
                ):
                    before -= 1
                producer = instructions[before]
            assert (producer.opname in _LOCAL_LOADS, producer.argval) == (True, local)
            assert (table[(code, offset)].label, table[(code, offset)].local) == (
                label,
                local,
            )
    launch_module: Any = windows_process_module.subprocess  # type: ignore[attr-defined]
    source = ast.parse(inspect.getsource(launch_module))
    for label, guards in _OFF_PATH_SITES.items():
        assert locations[label], label
        for code, offset in locations[label]:
            assert (table[(code, offset)].label, table[(code, offset)].local) == (
                label,
                None,
            )
            if guards == (_COPY_CALLER,):
                assert code.co_qualname == "STARTUPINFO.copy", label
                continue
            instructions, index = _instruction_at(code, offset)
            positions = instructions[index].positions
            assert positions is not None
            assert positions.lineno is not None
            branches = _enclosing_branches(source, positions.lineno)
            assert branches & set(guards), (label, positions.lineno, sorted(branches))
    assert len(table) == sum(
        len(locations[label]) for label in (*_RECEIVER_TYPED_SITES, *_OFF_PATH_SITES)
    )
    # The bases of the guards: production's one ``Popen`` call and the defaults.
    production = windows_process_module.__file__
    assert production is not None
    tree = ast.parse(Path(production).read_text(encoding="utf-8"))
    (launch,) = (
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and ast.unparse(node.func) == "subprocess.Popen"
    )
    keywords = {item.arg: ast.unparse(item.value) for item in launch.keywords}
    assert {name: keywords.get(name) for name in ("shell", "stdin", "stdout")} == {
        "shell": "False",
        "stdin": "subprocess.DEVNULL",
        "stdout": "subprocess.PIPE",
    }
    assert keywords.get("stderr") == "subprocess.PIPE"
    closed_by_default = {"group", "extra_groups", "user", "startupinfo"}
    assert closed_by_default.isdisjoint(keywords)
    parameters = inspect.signature(namespace["Popen"]).parameters
    assert {
        name: parameters[name].default for name in closed_by_default
    } == dict.fromkeys(closed_by_default)
    assert sys.flags.warn_default_encoding == 0
    copies = {
        (code, item.offset)
        for code in codes
        for item in dis.get_instructions(code)
        if item.opname == "LOAD_ATTR" and item.argval == "copy"
    }
    assert copies == {
        *locations["Popen._execute_child: startupinfo.copy()"],
        *locations["STARTUPINFO.copy: self.lpAttributeList.copy()"],
    }


class _PlantedReceiver:
    """A receiver of no admitted type at a receiver-typed site: its ``Close`` only
    counts (the planted site monitor control)."""

    def __init__(self) -> None:
        self.closes = 0

    def Close(self) -> None:  # the name the site loads
        self.closes += 1


class _PopenStandIn:
    """The ``self`` of a direct ``_close_pipe_fds`` call: no ``_devnull``, so nothing
    else is closed."""


def test_the_receiver_site_monitor_passes_typed_receivers_and_fails_closed(
    resource_ledger: _ResourceLedger,
) -> None:
    """Plan Step 3, the site monitor's own controls, with no process and no handle
    behind them. A window running the command-line builder executes its receiver sites
    with lists of text: judged admitted, the window balances. A window executing the
    off-path ``STARTUPINFO.copy`` site fails its audit by that site; so does a window
    in which ``_close_pipe_fds`` meets a planted receiver of no admitted type -- named
    with its type, even though its planted close then ran."""
    namespace = _route_namespace()
    with resource_ledger.operation("typed_receivers") as typed:
        command = namespace["list2cmdline"](["a b", "c\\d", 'e"f'])
    assert command == '"a b" c\\d e\\"f'
    assert {kind for _, kind in typed.sites} == {"list", "list[str]"}
    assert {label for label, _ in typed.sites} == {
        "list2cmdline: bs_buf.append()",
        "list2cmdline: const str.join()",
        "list2cmdline: result.append()",
        "list2cmdline: result.extend()",
    }
    _require_zero_unaccounted(typed)
    with resource_ledger.operation("off_path_site") as off_path:
        namespace["STARTUPINFO"]().copy()
    assert off_path.site_problems == [
        "STARTUPINFO.copy: self.lpAttributeList.copy(): an off-path site executed"
    ]
    with pytest.raises(AssertionError, match="an off-path site executed"):
        _require_zero_unaccounted(off_path)
    planted = _PlantedReceiver()
    close_pipe_fds = vars(namespace["Popen"])["_close_pipe_fds"]
    with resource_ledger.operation("untyped_receiver") as untyped:
        close_pipe_fds(_PopenStandIn(), planted, -1, -1, -1, -1, -1)
    assert planted.closes == 1
    assert ("Popen._close_pipe_fds: stack.callback()", "ExitStack") in untyped.sites
    with pytest.raises(
        AssertionError, match=r"p2cread\.Close: receiver _PlantedReceiver is none of"
    ):
        _require_zero_unaccounted(untyped)


class _SecondPipeFails:
    """``_winapi.CreatePipe`` for one construction: the first pipe is real; the second
    fails as the native call does, with an ``OSError`` carrying a Windows error."""

    def __init__(self, real: Callable[..., Any]) -> None:
        self._real = real
        self.calls = 0

    def __call__(self, *args: Any) -> Any:
        self.calls += 1
        if self.calls > 1:
            raise OSError(None, "injected", None, 8)
        return self._real(*args)


def test_a_failure_while_popen_builds_its_handles_releases_every_acquisition(
    tmp_root: Path, resource_ledger: _ResourceLedger, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Plan Step 3, the exception route the census found beside ``CreateProcess``'s: a
    failure while ``Popen`` still builds its handles (the stderr pipe cannot be
    created) unwinds through ``_on_error_fd_closer`` and the handles' own ends. Exactly
    the null device, its inheritable duplicate and the stdout pipe with its inheritable
    endpoint were acquired, and each was released by a real close before ``launch``
    returned the failure; no child exists. A characterization of a route no earlier
    test exercised, so no RED preceded it."""
    winapi = _real_global(_route_namespace(), "_winapi")
    failing = _SecondPipeFails(winapi.CreatePipe)
    monkeypatch.setattr(winapi, "CreatePipe", failing)
    with resource_ledger.operation("handle_setup_failure") as setup:
        failure = WindowsProcessController().launch(sleep_spec(tmp_root))
    monkeypatch.undo()
    assert isinstance(failure, LaunchFailure)
    assert (failure.stage, failure.os_error_code) == ("popen", 8)
    assert failing.calls == 2
    _require_observed(
        setup,
        (
            "devnull_descriptor",
            "devnull_inheritable",
            "pipe_read:stdout",
            "pipe_write:stdout",
            "pipe_write_inheritable:stdout",
        ),
    )
    _require_receivers(setup, _HANDLE_SETUP_FAILURE_RECEIVERS)
    _require_zero_unaccounted(setup)
    _assert_every_descendant_of_this_process_is_absent()  # independent of the ledger
