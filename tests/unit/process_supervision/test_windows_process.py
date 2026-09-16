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
"""

from __future__ import annotations

import ast
import ctypes
import gc
import os
import sys
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, Final, cast

import pytest
from pydantic import BaseModel

from crypto_lab.domain.command_invocation import ProcessIdentity
from crypto_lab.domain.hashing import sha256_bytes
from crypto_lab.process_supervision import windows_api
from crypto_lab.process_supervision import windows_process as windows_process_module
from crypto_lab.process_supervision.models import (
    CREATE_SUSPENDED,
    FORCED_TERMINATION_EXIT_CODE,
    QUEUE_CAPACITY_CHUNKS,
    READER_JOIN_SECONDS,
    CleanupAction,
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
    terminate_process,
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
# probe is recorded in the Task 4 ledger).
_SLEEP_FOREVER: Final = "any(time.sleep(0.1) for _ in iter(int, 1))"
_SLEEPER_PROGRAM: Final = f"import time; {_SLEEP_FOREVER}"
_READY_SLEEPER_PROGRAM: Final = (
    f"import time; print('ready', flush=True); {_SLEEP_FOREVER}"
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
    f"[sys.executable, '-I', '-B', '-c', {_SLEEPER_PROGRAM!r}]); "
    "print(child.pid, flush=True); "
    f"{_SLEEP_FOREVER}"
)
SPAWNS_A_SLEEPER_INHERITING_STDOUT_AND_EXITS: Final = (
    "import subprocess, sys; "
    "child = subprocess.Popen("
    f"[sys.executable, '-I', '-B', '-c', {_SLEEPER_PROGRAM!r}], "
    "stdin=subprocess.DEVNULL, stdout=sys.stdout.fileno(), "
    "stderr=subprocess.DEVNULL); "
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


def inspect_descendant(report: TerminationReport, pid: int) -> ProcessPresence:
    """``inspect`` over the exact identity the termination report recorded for
    ``pid``."""
    (descendant,) = (item for item in report.descendants if item.pid == pid)
    identity = identity_for(pid, descendant.creation_identity)
    return WindowsProcessController().inspect(identity).presence


def terminate_pid(pid: int) -> None:
    """Terminate an orphan the test itself created (a job-less controller cannot)."""
    try:
        handle = open_process_limited(pid, terminate=True)
    except WindowsApiError:
        return  # already gone
    try:
        if not wait_for_handle(handle, 0.0):
            try:
                terminate_process(handle, FORCED_TERMINATION_EXIT_CODE)
            except WindowsApiError:
                pass  # died between the wait and the call
            assert wait_for_handle(handle, 5.0)
    finally:
        close_handle(handle)


def _wait_until(predicate: Callable[[], bool]) -> bool:
    deadline = time.monotonic() + _WAIT_BOUND_SECONDS
    while not predicate():
        if time.monotonic() >= deadline:
            return False
        _PAUSE.wait(0.02)
    return True


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


def _ready(launched: WindowsLaunchedProcess) -> None:
    """Block until the child printed its readiness line (see the program comment)."""
    assert launched.stdout.readline().strip() == b"ready"


class _TrackingController:
    """Delegates to a ``WindowsProcessController`` and remembers every launched process
    so the fixture can terminate it and prove it is no longer ``ALIVE_MATCHING``."""

    def __init__(self, controller: WindowsProcessController) -> None:
        self.controller = controller
        self.launched: list[WindowsLaunchedProcess] = []

    def launch(
        self, specification: LaunchSpecification
    ) -> WindowsLaunchedProcess | LaunchFailure:
        result = self.controller.launch(specification)
        if isinstance(result, WindowsLaunchedProcess):
            self.launched.append(result)
        return result

    def inspect(self, identity: ProcessIdentity) -> ProcessInspection:
        return self.controller.inspect(identity)

    def terminate_tree(
        self, identity: ProcessIdentity, exit_code: int
    ) -> TerminationReport:
        return self.controller.terminate_tree(identity, exit_code)

    def cleanup(self) -> None:
        for launched in self.launched:
            report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
            launched.close(close_stdout=True, close_stderr=True)
            fresh = WindowsProcessController()
            assert (
                fresh.inspect(process_identity_for(launched)).presence
                is not ProcessPresence.ALIVE_MATCHING
            )
            for descendant in report.descendants:
                identity = identity_for(descendant.pid, descendant.creation_identity)
                assert (
                    fresh.inspect(identity).presence
                    is not ProcessPresence.ALIVE_MATCHING
                )


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


@pytest.fixture
def controller() -> Iterator[_TrackingController]:
    tracking = _TrackingController(WindowsProcessController())
    try:
        yield tracking
    finally:
        tracking.cleanup()


@pytest.fixture
def controller_without_job() -> Iterator[_TrackingController]:
    tracking = _TrackingController(
        WindowsProcessController(job_object_factory=_failing_job_factory)
    )
    try:
        yield tracking
    finally:
        tracking.cleanup()


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
        launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
        launched.close(close_stdout=True, close_stderr=True)


def test_forced_termination_reports_the_constant_as_the_native_exit(
    controller: _TrackingController, tmp_root: Path
) -> None:
    launched = started(controller.launch(sleep_spec(tmp_root)))
    report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    assert report.forced  # PT018: the plan's `and` split
    assert report.exit_code_used == 1067
    assert report.failures == ()
    assert launched.wait(5.0) == 1067
    assert launched.close(close_stdout=True, close_stderr=True).complete


def test_terminating_an_already_exited_root_reports_no_failure(
    controller: _TrackingController, tmp_root: Path
) -> None:
    launched = started(
        controller.launch(
            spec_for([sys.executable, "-I", "-B", "-c", "pass"], cwd=tmp_root)
        )
    )
    assert launched.wait(5.0) == 0
    assert (
        launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE).failures == ()
    )  # access denied on a dead process is not a failure


def test_launch_returns_a_launched_process_or_a_launch_failure_and_never_raises(
    controller: _TrackingController, tmp_root: Path
) -> None:
    result = controller.launch(sleep_spec(tmp_root))
    assert isinstance(result, LaunchedProcess)  # PT018: the plan's `and` split
    assert not isinstance(result, LaunchFailure)
    result.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    result.close(close_stdout=True, close_stderr=True)


def test_cancel_read_unblocks_a_reader_whose_pipe_a_grandchild_still_holds(
    controller_without_job: _TrackingController, tmp_root: Path
) -> None:
    launched = started(
        controller_without_job.launch(
            program_spec(SPAWNS_A_SLEEPER_INHERITING_STDOUT_AND_EXITS, cwd=tmp_root)
        )
    )
    sleeper = int(
        launched.stderr.readline()
    )  # the fake prints the sleeper's pid on stderr
    try:
        reader = PipeReader(
            launched.stdout, capacity=QUEUE_CAPACITY_CHUNKS, stop=threading.Event()
        )  # Task 3's reader, owned by the test here
        reader.start()
        assert (
            launched.wait(5.0) == 0
        )  # the root is gone; the sleeper holds the write end
        reader.join(READER_JOIN_SECONDS)
        assert reader.is_alive()  # blocked inside ReadFile: exactly the §6.7 case
        assert reader.native_thread_id is not None  # Task 3 review F9: the narrow
        assert launched.cancel_read(reader.native_thread_id) is True
        reader.join(READER_JOIN_SECONDS)
        assert not reader.is_alive()  # PT018: the plan's `and` split
        assert reader.ended_by is ReaderEnd.CANCELLED
        assert launched.close(close_stdout=True, close_stderr=True).complete
    finally:
        terminate_pid(
            sleeper
        )  # the orphan the test created; the job-less controller cannot reach it


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
    assert launched.wait(5.0) == 259
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
    assert report.failures == ()
    assert grandchild in {d.pid for d in report.descendants}
    assert launched.wait(5.0) == 1067  # PT018: the plan's `and` split
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
    assert launched.wait(5.0) == 50


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
    grandchild = int(launched.stdout.readline())
    report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    assert grandchild in {d.pid for d in report.descendants}
    assert not report.job_terminated
    assert inspect_pid(grandchild) is not ProcessPresence.ALIVE_MATCHING
    assert inspect_descendant(report, grandchild) is ProcessPresence.ABSENT
    assert launched.wait(5.0) == 1067


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
    assert launched.wait(5.0) == 0
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
    assert report.failures == ()
    assert len(report.descendants) >= 2
    assert all(unsignaled for _, unsignaled in spy.calls)
    assert launched.wait(5.0) == 1067


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
    assert report.failures == ()
    assert 1 <= len(spy.calls) <= 1 + len(report.descendants)
    assert all(
        exit_code == FORCED_TERMINATION_EXIT_CODE and unsignaled
        for exit_code, unsignaled in spy.calls
    )
    assert launched.wait(5.0) == 1067


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
    assert launched.wait(5.0) == 7
    assert launched.wait(0.0) == 7
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
    assert launched.wait(5.0) == _CONTROL_C_EXIT


# --------------------------------------------------------------------------
# Launch facts and launch failures
# --------------------------------------------------------------------------


def test_a_failing_job_factory_reports_the_error_and_the_child_still_launches(
    controller_without_job: _TrackingController, tmp_root: Path
) -> None:
    launched = started(controller_without_job.launch(sleep_spec(tmp_root)))
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
    assert report.failures == ()
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
        launched = started(tracking.launch(sleep_spec(tmp_root)))
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


def _assert_no_alive_matching_descendant_of_this_process() -> None:
    for descendant in descendants_of(os.getpid(), own_creation()):
        identity = identity_for(descendant.pid, descendant.creation_identity)
        assert (
            WindowsProcessController().inspect(identity).presence
            is not ProcessPresence.ALIVE_MATCHING
        ), descendant


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
    _assert_no_alive_matching_descendant_of_this_process()
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
    _assert_no_alive_matching_descendant_of_this_process()
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
    assert _open_handle_count() == before


# --------------------------------------------------------------------------
# Handles and cleanup
# --------------------------------------------------------------------------


def test_close_closes_both_owned_handles_and_is_idempotent(
    controller: _TrackingController, tmp_root: Path
) -> None:
    launched = started(controller.launch(sleep_spec(tmp_root)))
    launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    assert launched.wait(5.0) == 1067
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
    launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    assert launched.wait(5.0) == 1067
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
    launched = started(controller_without_job.launch(sleep_spec(tmp_root)))
    try:
        first = launched.close(close_stdout=True, close_stderr=True)
        assert [f.reason for f in first.failures] == ["still_alive:1"]
        second = launched.close(close_stdout=True, close_stderr=True)
        assert [f.action for f in second.failures] == [CleanupAction.TREE_VERIFIED_DEAD]
        assert second.failures[0].reason == "still_alive:1"
    finally:
        terminate_pid(launched.pid)  # no job: only the test can end this root
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
    assert launched.wait(5.0) == 0
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
    before = _open_handle_count()
    controller.inspect(identity)
    assert _open_handle_count() == before
    report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    assert len(report.descendants) >= 2
    assert _open_handle_count() == before
    controller.inspect(identity)
    assert _open_handle_count() == before


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
    grandchild = int(launched.stdout.readline())
    identity = process_identity_for(launched)
    fresh = WindowsProcessController()
    assert fresh.inspect(identity).presence is ProcessPresence.ALIVE_MATCHING
    report = fresh.terminate_tree(identity, FORCED_TERMINATION_EXIT_CODE)
    assert report.forced
    assert report.exit_code_used == FORCED_TERMINATION_EXIT_CODE
    assert not report.job_terminated
    assert report.failures == ()
    assert grandchild in {item.pid for item in report.descendants}
    assert launched.wait(5.0) == FORCED_TERMINATION_EXIT_CODE
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


def _sole_reason(report: TerminationReport) -> str:
    """The one reason word of a report whose every kill target failed the same way:
    the root and each verified descendant yield one ``TREE_VERIFIED_DEAD`` failure each
    (the launcher may already have spawned its interpreter when the tree is walked)."""
    assert report.failures
    assert {f.action for f in report.failures} == {CleanupAction.TREE_VERIFIED_DEAD}
    assert len(report.failures) == 1 + len(report.descendants)
    (reason,) = {f.reason for f in report.failures}
    return reason


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
    _assert_no_alive_matching_descendant_of_this_process()
    assert _open_handle_count() == before


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
    _assert_no_alive_matching_descendant_of_this_process()


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
    _assert_no_alive_matching_descendant_of_this_process()


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
    _assert_no_alive_matching_descendant_of_this_process()


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
    launched = started(controller_without_job.launch(sleep_spec(tmp_root)))
    monkeypatch.setattr(
        windows_api, "terminate_process", _raising("TerminateProcess", 1)
    )
    report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    monkeypatch.undo()
    assert report.forced
    assert _sole_reason(report) == "terminate_failed:1"
    assert launched.wait(0.0) is None  # nothing killed it
    terminate_pid(launched.pid)


def test_a_failed_or_expired_bounded_wait_after_the_kill_is_reported(
    controller_without_job: _TrackingController,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launched = started(controller_without_job.launch(sleep_spec(tmp_root)))
    monkeypatch.setattr(
        windows_api, "wait_for_handle", _failing_bounded_wait(raise_for_positive=True)
    )
    report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    monkeypatch.undo()
    assert report.forced
    assert _sole_reason(report) == "wait_failed:6"
    assert launched.wait(5.0) == FORCED_TERMINATION_EXIT_CODE  # the kill was real
    second = started(controller_without_job.launch(sleep_spec(tmp_root)))
    monkeypatch.setattr(
        windows_api,
        "wait_for_handle",
        _failing_bounded_wait(raise_for_positive=False, result_for_positive=False),
    )
    report = second.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    monkeypatch.undo()
    assert _sole_reason(report) == "still_alive:0"
    assert second.wait(5.0) == FORCED_TERMINATION_EXIT_CODE


def test_a_zero_wait_failure_in_the_kill_loop_is_reported_and_the_root_is_kept(
    controller_without_job: _TrackingController,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launched = started(controller_without_job.launch(sleep_spec(tmp_root)))
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
    terminate_pid(launched.pid)


def test_an_enumeration_failure_is_reported_and_the_root_is_still_killed(
    controller_without_job: _TrackingController,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launched = started(controller_without_job.launch(sleep_spec(tmp_root)))
    monkeypatch.setattr(
        windows_api, "descendants_of", _raising("CreateToolhelp32Snapshot", 87)
    )
    report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    monkeypatch.undo()
    assert report.forced
    assert report.descendants == ()
    assert [f.reason for f in report.failures] == ["enumeration_failed:87"]
    assert launched.wait(5.0) == FORCED_TERMINATION_EXIT_CODE


def test_a_job_kill_returning_false_falls_back_to_per_process_termination(
    controller: _TrackingController, tmp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launched = started(controller.launch(sleep_spec(tmp_root)))
    monkeypatch.setattr(windows_api, "terminate_job", lambda job, code: False)
    report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    monkeypatch.undo()
    assert report.forced
    assert not report.job_terminated
    assert report.failures == ()
    assert launched.wait(5.0) == FORCED_TERMINATION_EXIT_CODE


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
    assert launched.wait(5.0) == FORCED_TERMINATION_EXIT_CODE


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
    grandchild = int(launched.stdout.readline())
    fault = _DescendantFault(launched.pid, mode)
    monkeypatch.setattr(windows_api, "open_process_limited", fault.open_process_limited)
    monkeypatch.setattr(windows_api, "process_times", fault.process_times)
    try:
        report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    finally:
        monkeypatch.undo()
    assert report.forced
    assert grandchild in {item.pid for item in report.descendants}  # enumerated
    assert report.failures == ()
    assert launched.wait(5.0) == FORCED_TERMINATION_EXIT_CODE
    assert inspect_descendant(report, grandchild) is ProcessPresence.ALIVE_MATCHING
    terminate_pid(grandchild)
    assert inspect_descendant(report, grandchild) is ProcessPresence.ABSENT


def test_an_undeliverable_interrupt_is_unavailable_and_a_dying_root_is_gone(
    controller: _TrackingController, tmp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launched = started(controller.launch(sleep_spec(tmp_root)))
    monkeypatch.setattr(windows_api, "generate_console_break", lambda pid: False)
    assert launched.interrupt() is InterruptOutcome.UNAVAILABLE
    assert launched.wait(0.0) is None

    def kill_then_report_false(pid: int) -> bool:
        terminate_pid(pid)  # the child exits between the two zero waits
        return False

    monkeypatch.setattr(windows_api, "generate_console_break", kill_then_report_false)
    assert launched.interrupt() is InterruptOutcome.PROCESS_GONE
    monkeypatch.undo()
    assert launched.wait(5.0) == FORCED_TERMINATION_EXIT_CODE


def test_an_interrupt_that_cannot_test_the_root_is_unavailable(
    controller_without_job: _TrackingController,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launched = started(controller_without_job.launch(sleep_spec(tmp_root)))
    monkeypatch.setattr(
        windows_api, "wait_for_handle", _raising("WaitForSingleObject", 6)
    )
    assert launched.interrupt() is InterruptOutcome.UNAVAILABLE
    monkeypatch.undo()
    launched.close(close_stdout=True, close_stderr=True)  # still_alive: handle gone
    assert launched.interrupt() is InterruptOutcome.UNAVAILABLE  # cannot be tested
    terminate_pid(launched.pid)


def test_close_reports_a_handle_that_cannot_be_closed(
    controller: _TrackingController, tmp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launched = started(controller.launch(sleep_spec(tmp_root)))
    launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    assert launched.wait(5.0) == FORCED_TERMINATION_EXIT_CODE
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
