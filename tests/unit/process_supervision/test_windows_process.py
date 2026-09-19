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
return the exact native code -- never ``None``, never retried, never polled. A
handle-table equality (R2) is a bounded settle
to the captured baseline through the module's monotonic wait: exact equality, no
tolerance, expiry fails. Which shape each termination site observed, every natural exit
code, every handle settle and the in-process resource counts at each fixture cleanup are
written at module teardown under pytest's base temporary directory for the repetition
ledger.
"""

from __future__ import annotations

import ast
import ctypes
import gc
import json
import os
import sys
import threading
import time
from collections.abc import Callable, Generator, Iterable, Iterator
from contextlib import suppress
from pathlib import Path
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
SPAWNS_A_SLEEPER_INHERITING_STDOUT_AND_EXITS: Final = (
    "import subprocess, sys; "
    "child = subprocess.Popen("
    f"[sys.executable, '-I', '-B', '-c', {_READY_ON_STDERR_SLEEPER_PROGRAM!r}], "
    "stdin=subprocess.DEVNULL, stdout=sys.stdout.fileno(), "
    "stderr=subprocess.PIPE); "
    "assert child.stderr.readline().strip() == b'ready'; "
    "print(child.pid, file=sys.stderr, flush=True)"
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
    production constant."""
    started_at = time.monotonic()
    first = launched.wait(_WAIT_BOUND_SECONDS)
    elapsed = time.monotonic() - started_at
    identity = process_identity_for(launched)
    observed_presence = WindowsProcessController().inspect(identity).presence
    _EVIDENCE.record_exit(expected, first, elapsed, observed_presence)
    _require_absent(identity, observed_presence)
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


def _read_line_bounded(stream: IO[bytes]) -> bytes:
    """One line from a child's pipe within the module bound, read on a daemon thread so
    a child that never writes cannot hang the test (the fixture closes the pipe, which
    ends the read)."""
    lines: list[bytes] = []
    thread = threading.Thread(
        target=lambda: lines.append(stream.readline()), daemon=True
    )
    thread.start()
    thread.join(_WAIT_BOUND_SECONDS)
    assert not thread.is_alive(), "no line from the child within the bound"
    return lines[0]


def _ready(launched: WindowsLaunchedProcess) -> None:
    """Block, bounded, until the child printed its readiness line: its interpreter is
    created, resumed and running (see the program comment)."""
    line = _read_line_bounded(launched.stdout)
    assert line.strip() == b"ready", line


def _pid_line(stream: IO[bytes]) -> int:
    """The pid a spawner program printed as one line, read within the bound; the program
    prints it only after its spawned sleeper printed ``ready``."""
    return int(_read_line_bounded(stream))


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
    ) -> None:
        self._row(
            "natural_exit",
            expected=expected,
            observed=observed,
            wait_seconds=elapsed,
            presence=presence.value,
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

    def record_resources(self, launched: list[WindowsLaunchedProcess]) -> None:
        """In-process counts after a fixture cleanup: readers alive, streams open,
        process handles open, Job Object handles open (all expected zero)."""
        self._row(
            "resources",
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
            _EVIDENCE.record_resources(self.launched)
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
        _EVIDENCE.write(tmp_path_factory.mktemp("termination-shapes"))


@pytest.fixture(autouse=True)
def _shape_site(request: pytest.FixtureRequest) -> None:
    """Names the running test in the shape evidence."""
    _EVIDENCE.site = request.node.nodeid


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
    launched = started(
        controller_without_job.launch(
            program_spec(SPAWNS_A_SLEEPER_INHERITING_STDOUT_AND_EXITS, cwd=tmp_root)
        )
    )
    sleeper = _pid_line(launched.stderr)  # printed after the sleeper's ``ready`` line
    # The sleeper's launcher has passed its resume window (its interpreter printed the
    # readiness line the fake waited for); bind its identity now, while it lives.
    sleeper_identity = controller_without_job.own(live_identity_for(sleeper))
    try:
        reader = PipeReader(
            launched.stdout, capacity=QUEUE_CAPACITY_CHUNKS, stop=threading.Event()
        )  # Task 3's reader, owned by the test here
        reader.start()
        _exited(launched, 0)  # the root is gone; the sleeper holds the write end
        reader.join(READER_JOIN_SECONDS)
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
    grandchild = _pid_line(launched.stdout)
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
    controller: _TrackingController, tmp_root: Path
) -> None:
    before = _open_handle_count()
    failure = controller.launch(
        spec_for(["C:\\nowhere\\absent.exe", "describe"], cwd=tmp_root)
    )
    assert isinstance(failure, LaunchFailure)
    # R2: the failed launch owns nothing and left no handle; settle to the baseline
    _settled_handle_count(before)


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
    controller: _TrackingController, tmp_root: Path
) -> None:
    launched = started(
        controller.launch(
            program_spec(SPAWNS_A_SLEEPER_AND_PRINTS_ITS_PID, cwd=tmp_root)
        )
    )
    int(launched.stdout.readline())
    identity = process_identity_for(launched)
    # R2: the baseline is taken with the launch's own handles open; every handle the
    # operations under test open must be closed again, so the table settles back to it.
    before = _open_handle_count()
    controller.inspect(identity)
    _settled_handle_count(before)
    report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    assert len(report.descendants) >= 2
    controller.shape(report)
    controller.ended(launched, report)  # every identity ABSENT before the settle
    _settled_handle_count(before)
    controller.inspect(identity)
    _settled_handle_count(before)


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
    grandchild = _pid_line(launched.stdout)
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
    tmp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(windows_api, "open_process_limited", _raising("OpenProcess", 5))
    before = _open_handle_count()
    failure = WindowsProcessController().launch(sleep_spec(tmp_root))
    monkeypatch.undo()
    assert isinstance(failure, LaunchFailure)
    assert failure.stage == "open_process"
    assert failure.os_error_code == 5
    assert failure.error_class == "OpenProcess"
    assert not failure.not_found
    _assert_every_descendant_of_this_process_is_absent()  # R2 step 1
    _settled_handle_count(before)  # the abandoned launch closed every handle it opened


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
    grandchild = _pid_line(launched.stdout)
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
    name before any zero-duration read."""
    launched = started(controller.launch(sleep_spec(tmp_root)))
    started_at = time.monotonic()
    with pytest.raises(AssertionError, match="ALIVE_MATCHING, not ABSENT"):
        _exited(launched, 0)
    assert time.monotonic() - started_at >= _WAIT_BOUND_SECONDS
    assert launched.wait(0.0) is None  # nothing ended it; the fixture cleanup will


def test_the_handle_count_settles_to_the_exact_baseline_or_fails_at_the_bound() -> None:
    """R2 pins 6 to 8 over an injected counter (the real table drifts as earlier tests'
    objects are finalized, so its long-window behaviour is not the pin's subject): a
    count one above the baseline never settles and fails when the bound expires (no
    tolerance, not even one handle); a count that reaches the baseline on a later
    reading settles; and the real table settles to a baseline captured at once."""
    with pytest.raises(AssertionError, match="did not settle to exactly 10 within"):
        _settled_handle_count(10, count=lambda: 11)
    readings = iter([12, 11, 10])
    _settled_handle_count(10, count=lambda: next(readings))
    _settled_handle_count(_open_handle_count())


def test_the_ruling_oracles_are_used_exactly_where_the_ruling_names_them() -> None:
    """R1, R2, F1 and F2 as structure: the eight natural-exit sites and only they call
    ``_exited``; no positive-bound ``wait`` comparison remains outside ``ended`` and the
    two argument-validation tests; the three fake-dictated sites and only they pass a
    dictated reason; ``_absent`` performs exactly one kernel wait; ``_exited`` performs
    no hidden wait; the handle-count settles are the three named tests."""
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
    assert callers("_settled_handle_count") == {
        "test_a_launch_failure_leaves_no_child_and_no_extra_handle",
        "test_terminate_tree_and_inspection_leave_the_handle_table_unchanged",
        "test_an_open_process_failure_at_launch_is_an_open_process_launch_failure",
        "test_the_handle_count_settles_to_the_exact_baseline_or_fails_at_the_bound",
    }
    settle = _function_source(tree, "_settled_handle_count")
    assert "_wait_until" in settle
    assert "== baseline" in settle
    assert "abs(" not in settle
    assert "<=" not in settle


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
