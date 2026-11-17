"""Stage 7 Task 4: the typed kernel32 bindings of ``windows_api`` (plan 3.1, 8.1-8.3).

Every binding is a ``ctypes`` call into ``kernel32`` bound on first use through the
module-level ``_KERNEL32`` slot, typed through ``ctypes.wintypes`` and wrapped so that a
failure surfaces as ``WindowsApiError`` carrying the API name and the numeric
``GetLastError()`` code only -- never a localized message, a path or a handle. The tests
here are API-level: they use this process's own handle (opened with the limited mask and
never terminated), a pid that cannot exist, a fresh Job Object, the console and the
Toolhelp walk. No child process is launched in this module; the controller tests own the
real children. ``process_exit_code`` on a live handle returns the ``STILL_ACTIVE``
sentinel ``259`` as-is, which is exactly why the controller reads it only after the
handle is signaled.
"""

from __future__ import annotations

import ast
import ctypes
import os
import sys
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from ctypes import wintypes
from pathlib import Path
from typing import Any, Final, get_type_hints

import pytest

from crypto_lab.process_supervision import windows_api
from crypto_lab.process_supervision.models import (
    DescendantIdentity,
    parse_creation_identity,
    render_creation_identity,
)
from crypto_lab.process_supervision.windows_api import (
    WindowsApiError,
    assign_to_job,
    cancel_synchronous_io,
    close_handle,
    console_process_count,
    create_kill_on_close_job,
    descendants_of,
    generate_console_break,
    is_process_in_job,
    open_process_limited,
    process_exit_code,
    process_image_path,
    process_times,
    resume_initial_thread,
    terminate_job,
    terminate_process,
    wait_for_handle,
)

#: A pid that no process can have: Windows pids are multiples of four.
_ABSENT_PID: Final = 3
_ERROR_ACCESS_DENIED: Final = 5
_ERROR_INVALID_HANDLE: Final = 6
_ERROR_NO_MORE_FILES: Final = 18
_ERROR_INVALID_PARAMETER: Final = 87
_STILL_ACTIVE: Final = 259
#: Plan 2.6: the import closure of ``windows_api.py`` (``ctypes`` confined here;
#: ``contextlib`` is a merged root, used for the quiet close in ``finally``).
_PURE_ROOTS: Final = frozenset(
    {"__future__", "contextlib", "ctypes", "typing", "pydantic", "crypto_lab"}
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
        "subprocess",
        "socket",
        "types",
        "importlib",
    }
)
_STAGE4_BARE_NAMES: Final = frozenset(
    {"buffer", "context", "note", "problem", "compose", "Loader"}
)
#: Plan Task 4 and 8.1-8.3: the exact kernel32 functions the module may call.
_API_NAMES: Final = frozenset(
    {
        "OpenProcess",
        "GetProcessTimes",
        "QueryFullProcessImageNameW",
        "GetExitCodeProcess",
        "WaitForSingleObject",
        "CloseHandle",
        "CreateJobObjectW",
        "SetInformationJobObject",
        "AssignProcessToJobObject",
        "IsProcessInJob",
        "TerminateJobObject",
        "TerminateProcess",
        "GenerateConsoleCtrlEvent",
        "GetConsoleProcessList",
        "CreateToolhelp32Snapshot",
        "Process32FirstW",
        "Process32NextW",
        "Thread32First",
        "Thread32Next",
        "OpenThread",
        "ResumeThread",
        "CancelSynchronousIo",
    }
)
_EXPORTED: Final = [
    "WindowsApiError",
    "assign_to_job",
    "cancel_synchronous_io",
    "close_handle",
    "console_process_count",
    "create_kill_on_close_job",
    "descendants_of",
    "generate_console_break",
    "is_process_in_job",
    "open_process_limited",
    "process_exit_code",
    "process_image_path",
    "process_times",
    "resume_initial_thread",
    "terminate_job",
    "terminate_process",
    "wait_for_handle",
]
#: The test's own probe of this process's handle table (``GetProcessHandleCount`` over
#: the current-process pseudo-handle); test code may bind kernel32 itself.
_PROBE = ctypes.WinDLL("kernel32", use_last_error=True)
#: Plan Step 3 (owner ruling of 2026-11-14, section 1): the reviewed surface split into
#: the handle creators, each with the resource class it yields, and every other name;
#: pinned exhaustive and disjoint against ``_API_NAMES`` and the production surface.
_REVIEWED_HANDLE_CREATORS: Final[Mapping[str, str]] = {
    "OpenProcess": "process",
    "CreateJobObjectW": "job",
    "CreateToolhelp32Snapshot": "snapshot",
    "OpenThread": "thread",
}
_REVIEWED_NON_CREATORS: Final = frozenset(
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
_SNAPSHOT_KINDS: Final[Mapping[int, str]] = {
    0x00000002: "process_snapshot",
    0x00000004: "thread_snapshot",
}
_THREAD_QUERY_LIMITED_INFORMATION: Final = 0x0800
_INVALID_HANDLE: Final = (1 << (8 * ctypes.sizeof(ctypes.c_void_p))) - 1


# --------------------------------------------------------------------------
# Module-local helpers
# --------------------------------------------------------------------------


def _diagnostic_handle_count() -> int | str:
    """This process's handle-table size: unrelated lifetimes included, so only a
    diagnostic beside the accounting. It forces no collection (a finalizer run here
    could close a recorded handle and so decide the accounting) and a failed
    collection is returned as its precise error, never raised: it neither establishes
    nor vetoes resource-cleanup success."""
    count = ctypes.c_ulong(0)
    try:
        counted = _PROBE.GetProcessHandleCount(ctypes.c_void_p(-1), ctypes.byref(count))
    except Exception as error:  # recorded explicitly; the accounting still decides
        return f"GetProcessHandleCount raised {type(error).__name__}"
    if not counted:
        return f"GetProcessHandleCount failed: {ctypes.get_last_error()}"
    return count.value


class _HandleRecord:
    """One acquisition by a reviewed creator, by generation: a number reused later is
    a new generation and a new lifetime."""

    def __init__(self, generation: int, kind: str, value: int, route: str) -> None:
        self.generation = generation
        self.kind = kind
        self.value = value
        self.route = route
        self.state = "open"
        self.released_by = ""

    def describe(self) -> str:
        return f"{self.kind}#{self.generation} via {self.route} ({self.state})"


class _Kernel32Ledger:
    """Complete accounting at the kernel32 seam (owner ruling of 2026-11-14): every
    successful reviewed creator records its handle by generation and only a successful
    ``CloseHandle`` of that live number releases it; a number acquired again unreleased
    marks the earlier lifetime lost; an unreviewed name is recorded as unclassified."""

    def __init__(self) -> None:
        self.records: list[_HandleRecord] = []
        self.unrelated: list[int] = []
        self.unclassified: list[str] = []
        self.anomalies: list[str] = []
        #: Every live table count (or the precise failure to collect it): diagnostics.
        self.diagnostics: list[int | str] = []
        self._live: dict[int, _HandleRecord] = {}

    def mark(self) -> int:
        self.diagnostics.append(_diagnostic_handle_count())
        return len(self.records)

    def created(self, name: str, args: tuple[Any, ...], handle: int) -> None:
        kind = _REVIEWED_HANDLE_CREATORS[name]
        if kind == "snapshot":
            kind = _SNAPSHOT_KINDS.get(int(args[0]), kind)
        stale = self._live.pop(handle, None)
        if stale is not None:
            stale.state = "lost"
            self.anomalies.append(f"{stale.describe()}: acquired again unreleased")
        record = _HandleRecord(len(self.records), kind, handle, name)
        self.records.append(record)
        self._live[handle] = record

    def closed(self, handle: int) -> None:
        record = self._live.pop(handle, None)
        if record is None:
            self.unrelated.append(handle)
            return
        record.state = "released"
        record.released_by = "CloseHandle"

    def unaccounted(self, start: int) -> list[_HandleRecord]:
        return [record for record in self.records[start:] if record.state != "released"]

    def require_balanced(self, start: int) -> None:
        """Exactly zero unaccounted acquisitions since ``start`` and no unclassified
        name, no tolerance. The verdict is taken first; the live table count is
        collected only afterwards, recorded (a failed collection included) and named
        in the message as a diagnostic that decides nothing."""
        problems = [f"unclassified kernel32 name {name}" for name in self.unclassified]
        problems.extend(self.anomalies)
        problems.extend(
            f"{record.describe()} is unaccounted" for record in self.unaccounted(start)
        )
        before = self.diagnostics[-1] if self.diagnostics else "not collected"
        after = _diagnostic_handle_count()
        self.diagnostics.append(after)
        assert problems == [], (
            "unaccounted resources: "
            + "; ".join(problems)
            + f" (live table {before} -> {after}, diagnostic only)"
        )


class _LedgerKernel32:
    """The bound ``kernel32`` as ``windows_api`` reaches it inside a ledger window:
    every name delegates to the real binding, recording in pure Python only, so the
    last error the binding saved is untouched."""

    def __init__(self, ledger: _Kernel32Ledger, bind: Callable[[], Any]) -> None:
        self._ledger = ledger
        self._bind = bind

    def __getattr__(self, name: str) -> Any:
        function = getattr(self._bind(), name)
        ledger = self._ledger
        if name in _REVIEWED_HANDLE_CREATORS:

            def create(*args: Any) -> Any:
                handle = function(*args)
                if isinstance(handle, int) and handle not in (0, _INVALID_HANDLE):
                    ledger.created(name, args, handle)
                elif handle is not None and not isinstance(handle, int):
                    # a creator result no rule reads as a handle or a failure
                    ledger.anomalies.append(
                        f"{name} returned a {type(handle).__name__}"
                    )
                return handle

            return create
        if name == "CloseHandle":

            def close(handle: Any) -> Any:
                result = function(handle)
                if result:
                    ledger.closed(int(handle))
                return result

            return close
        if name not in _REVIEWED_NON_CREATORS:
            ledger.unclassified.append(name)
        return function


@contextmanager
def _kernel32_ledger() -> Iterator[_Kernel32Ledger]:
    """The ledger seam on its own patch, so a test's ``monkeypatch.undo()`` inside the
    window leaves it in place (a fault-injection proxy then wraps the ledger)."""
    ledger = _Kernel32Ledger()
    proxy = _LedgerKernel32(ledger, windows_api._kernel32)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(windows_api, "_kernel32", lambda: proxy)
        yield ledger


def _own_creation() -> int:
    handle = open_process_limited(os.getpid())
    try:
        return process_times(handle)
    finally:
        close_handle(handle)


def _module_source() -> str:
    source = windows_api.__file__
    assert source is not None
    return Path(source).read_text(encoding="utf-8")


def _module_tree() -> ast.Module:
    return ast.parse(_module_source())


def _imported_roots(tree: ast.AST) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            roots.add(node.module.partition(".")[0])
    return roots


def _kernel32_attribute_names(tree: ast.AST) -> set[str]:
    """Every ``_kernel32().<name>`` access: the complete API surface the module uses."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == "_kernel32"
        ):
            names.add(node.attr)
    return names


@pytest.fixture
def own_handle() -> Iterator[int]:
    handle = open_process_limited(os.getpid())
    try:
        yield handle
    finally:
        close_handle(handle)


# --------------------------------------------------------------------------
# The plan's named API tests
# --------------------------------------------------------------------------


def test_the_console_event_wrapper_refuses_pid_zero() -> None:
    """Plan 8.3 and 10: pid ``0`` would signal every process on the console."""
    with pytest.raises(ValueError, match="pid"):
        generate_console_break(0)


def test_a_console_break_to_an_absent_group_reports_false_without_raising() -> None:
    assert generate_console_break(_ABSENT_PID) is False


def test_this_process_is_attached_to_a_console() -> None:
    """Plan 10: the precondition of every real-process interrupt test."""
    assert console_process_count() >= 1, (
        "the test process is not attached to a console; the interrupt tests would "
        "observe UNAVAILABLE"
    )


# --------------------------------------------------------------------------
# Identity, times and exit facts on this process
# --------------------------------------------------------------------------


def test_process_times_yields_a_bounded_creation_filetime_that_renders_and_parses(
    own_handle: int,
) -> None:
    creation = process_times(own_handle)
    assert isinstance(creation, int)
    assert 0 < creation <= 2**63 - 1
    text = render_creation_identity(os.getpid(), creation)
    assert parse_creation_identity(text).creation_100ns == creation
    assert process_times(own_handle) == creation  # stable across reads


def test_process_image_path_is_the_absolute_interpreter_image(own_handle: int) -> None:
    image = process_image_path(own_handle)
    assert Path(image).is_absolute()
    assert Path(image).is_file()
    assert image.lower().endswith("python.exe")


def test_a_live_handle_is_unsignaled_and_its_exit_code_is_the_sentinel(
    own_handle: int,
) -> None:
    """The reason liveness is the wait and never ``GetExitCodeProcess`` (plan 8.1)."""
    assert wait_for_handle(own_handle, 0.0) is False
    assert process_exit_code(own_handle) == _STILL_ACTIVE


def test_wait_for_handle_refuses_a_negative_or_non_finite_timeout(
    own_handle: int,
) -> None:
    for bad in (-1.0, float("nan"), float("inf")):
        with pytest.raises(ValueError, match="timeout_seconds"):
            wait_for_handle(own_handle, bad)


# --------------------------------------------------------------------------
# Error normalization: numeric codes, fixed function names, no message text
# --------------------------------------------------------------------------


def test_opening_an_absent_pid_fails_with_invalid_parameter_not_access_denied() -> None:
    with pytest.raises(WindowsApiError) as caught:
        open_process_limited(_ABSENT_PID)
    error = caught.value
    assert isinstance(error, OSError)
    assert error.function == "OpenProcess"
    assert error.winerror == _ERROR_INVALID_PARAMETER
    assert str(error) == "OpenProcess failed"


def test_a_closed_handle_fails_every_call_with_invalid_handle() -> None:
    handle = open_process_limited(os.getpid())
    close_handle(handle)
    for call in (
        lambda: wait_for_handle(handle, 0.0),
        lambda: process_times(handle),
        lambda: process_exit_code(handle),
        lambda: close_handle(handle),
    ):
        with pytest.raises(WindowsApiError) as caught:
            call()
        assert caught.value.winerror == _ERROR_INVALID_HANDLE


def test_terminate_process_without_the_terminate_right_is_access_denied(
    own_handle: int,
) -> None:
    """The limited handle carries no ``PROCESS_TERMINATE``: the call is refused with the
    numeric code and this process keeps running."""
    with pytest.raises(WindowsApiError) as caught:
        terminate_process(own_handle, 1)
    assert caught.value.function == "TerminateProcess"
    assert caught.value.winerror == _ERROR_ACCESS_DENIED


def test_exit_codes_are_bounded_to_a_dword_before_any_call(own_handle: int) -> None:
    for bad in (-1, 2**32):
        with pytest.raises(ValueError, match="exit_code"):
            terminate_process(own_handle, bad)
        with pytest.raises(ValueError, match="exit_code"):
            terminate_job(own_handle, bad)


def test_resume_initial_thread_of_an_absent_pid_names_the_toolhelp_call() -> None:
    with pytest.raises(WindowsApiError) as caught:
        resume_initial_thread(_ABSENT_PID)
    assert caught.value.function == "Thread32Next"
    assert caught.value.winerror == _ERROR_NO_MORE_FILES


def test_cancel_synchronous_io_reports_false_for_an_idle_or_absent_thread() -> None:
    # this thread is not blocked in a synchronous read: nothing to cancel
    assert cancel_synchronous_io(threading.get_native_id()) is False
    assert cancel_synchronous_io(_ABSENT_PID) is False


# --------------------------------------------------------------------------
# Job Objects
# --------------------------------------------------------------------------


def test_a_fresh_job_does_not_contain_this_process_and_none_means_false(
    own_handle: int,
) -> None:
    job = create_kill_on_close_job()
    try:
        assert is_process_in_job(own_handle, job) is False
        assert is_process_in_job(own_handle, None) is False
    finally:
        close_handle(job)


def test_assigning_to_a_null_job_handle_fails_with_invalid_handle(
    own_handle: int,
) -> None:
    with pytest.raises(WindowsApiError) as caught:
        assign_to_job(0, own_handle)
    assert caught.value.function == "AssignProcessToJobObject"
    assert caught.value.winerror == _ERROR_INVALID_HANDLE


def test_terminating_an_empty_job_returns_true_and_harms_nothing(
    own_handle: int,
) -> None:
    job = create_kill_on_close_job()
    try:
        assert terminate_job(job, 1) is True
        assert wait_for_handle(own_handle, 0.0) is False
    finally:
        close_handle(job)


# --------------------------------------------------------------------------
# The Toolhelp descendant walk
# --------------------------------------------------------------------------


def test_the_descendant_walk_of_this_process_is_empty_and_leaks_no_handle(
    own_handle: int,
) -> None:
    creation = process_times(own_handle)
    with _kernel32_ledger() as ledger:
        start = ledger.mark()
        assert descendants_of(os.getpid(), creation) == ()
        # The owner ruling of 2026-11-14: the walk's one real process snapshot and every
        # candidate handle it opened were released by a successful close, exactly.
        ledger.require_balanced(start)
        walked = ledger.records[start:]
        assert [record.kind for record in walked].count("process_snapshot") == 1
        assert {record.kind for record in walked} <= {"process_snapshot", "process"}


def test_the_descendant_walk_returns_committed_descendant_identities() -> None:
    """The return type is the Task 2 record: no second identity type exists."""
    assert get_type_hints(descendants_of)["return"] == tuple[DescendantIdentity, ...]


# --------------------------------------------------------------------------
# Surface, structure layout and import closure
# --------------------------------------------------------------------------


def test_the_module_exports_exactly_the_task_four_api_surface_sorted() -> None:
    assert windows_api.__all__ == _EXPORTED
    for name in _EXPORTED:
        assert callable(getattr(windows_api, name))


def test_the_structures_have_the_win32_x64_sizes() -> None:
    assert ctypes.sizeof(windows_api._FILETIME) == 8
    assert ctypes.sizeof(windows_api._PROCESSENTRY32W) == 568
    assert ctypes.sizeof(windows_api._THREADENTRY32) == 28
    assert ctypes.sizeof(windows_api._JOBOBJECT_EXTENDED_LIMIT_INFORMATION) == 144


def test_kernel32_is_bound_on_first_use_and_only_kernel32_is_bound() -> None:
    tree = _module_tree()
    slot = [
        node
        for node in tree.body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "_KERNEL32"
    ]
    assert len(slot) == 1
    assert isinstance(slot[0].value, ast.Constant)
    assert slot[0].value.value is None
    for node in tree.body:  # no module-level statement binds a library
        if isinstance(node, ast.FunctionDef | ast.ClassDef):
            continue
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                assert child.func.attr != "WinDLL", ast.dump(node)
    dll_names = [
        node.args[0].value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "WinDLL"
        and node.args
        and isinstance(node.args[0], ast.Constant)
    ]
    assert dll_names == ["kernel32"]
    console_process_count()  # any call binds the library
    assert windows_api._KERNEL32 is not None


def test_the_module_calls_exactly_the_reviewed_kernel32_functions() -> None:
    """Plan Task 4 and brief: no process enumeration beyond Toolhelp, no command-line,
    environment, token or memory read of any process."""
    tree = _module_tree()
    assert _kernel32_attribute_names(tree) == _API_NAMES
    source = _module_source()
    for forbidden in (
        "GetCommandLine",
        "GetEnvironmentStrings",
        "NtQueryInformationProcess",
        "ReadProcessMemory",
        "OpenProcessToken",
        "PROCESS_QUERY_INFORMATION",
        "PROCESS_VM_READ",
        "FormatMessage",
        "sandbox",
    ):
        assert forbidden not in source, forbidden


def test_the_module_imports_only_its_plan_roots_and_no_bare_forbidden_name() -> None:
    tree = _module_tree()
    roots = _imported_roots(tree)
    assert roots == _PURE_ROOTS
    assert not roots & _DENIED_ROOTS
    names = {
        node.id if isinstance(node, ast.Name) else node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Name | ast.Attribute)
    }
    assert not names & _STAGE4_BARE_NAMES
    assert "from __future__ import annotations" in _module_source()


def test_windows_api_error_carries_only_the_function_name_and_the_number() -> None:
    error = WindowsApiError("OpenProcess", 87)
    assert (error.function, error.winerror) == ("OpenProcess", 87)
    assert str(error) == "OpenProcess failed"
    assert isinstance(error, OSError)
    assert vars(error) == {"function": "OpenProcess"}


# --------------------------------------------------------------------------
# Failure normalization by fault injection at the kernel32 seam. Characterization
# tests of the API-failure branches a healthy host never takes: a proxy stands in for
# the bound library, answers one function with FALSE and a chosen last error, and
# delegates everything else; no real process is harmed and the real binding is
# restored after each test. No RED preceded them and they are labelled as such.
# --------------------------------------------------------------------------


class _Kernel32Proxy:
    """Delegates to the real ``WinDLL`` except for the overridden function names."""

    def __init__(self, real: ctypes.WinDLL, overrides: dict[str, object]) -> None:
        self._real = real
        self._overrides = overrides

    def __getattr__(self, name: str) -> object:
        if name in self._overrides:
            return self._overrides[name]
        return getattr(self._real, name)


def _failing(code: int, *, result: int = 0) -> object:
    def call(*args: object) -> int:
        ctypes.set_last_error(code)
        return result

    return call


def _with_kernel32_override(
    monkeypatch: pytest.MonkeyPatch, **overrides: object
) -> None:
    proxy = _Kernel32Proxy(windows_api._kernel32(), overrides)
    monkeypatch.setattr(windows_api, "_kernel32", lambda: proxy)


def test_a_sub_millisecond_timeout_waits_one_millisecond_and_text_is_refused(
    own_handle: int,
) -> None:
    assert wait_for_handle(own_handle, 0.0001) is False
    with pytest.raises(TypeError, match="timeout_seconds"):
        wait_for_handle(own_handle, "1")  # type: ignore[arg-type]


def test_a_failed_job_limit_closes_the_new_job_and_raises_with_its_number(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _kernel32_ledger() as ledger:
        start = ledger.mark()
        _with_kernel32_override(monkeypatch, SetInformationJobObject=_failing(87))
        with pytest.raises(WindowsApiError) as caught:
            create_kill_on_close_job()
        monkeypatch.undo()
        # The owner ruling of 2026-11-14: exactly the created job, closed for real.
        (job,) = ledger.records[start:]
        assert (job.route, job.kind) == ("CreateJobObjectW", "job")
        assert (job.state, job.released_by) == ("released", "CloseHandle")
        ledger.require_balanced(start)
    assert caught.value.function == "SetInformationJobObject"
    assert caught.value.winerror == 87


def test_a_failed_resume_names_resume_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    """The proxy answers ``ResumeThread`` with the failure sentinel, so no thread of
    this process is touched."""
    _with_kernel32_override(monkeypatch, ResumeThread=_failing(5, result=0xFFFFFFFF))
    with pytest.raises(WindowsApiError) as caught:
        resume_initial_thread(os.getpid())
    monkeypatch.undo()
    assert caught.value.function == "ResumeThread"
    assert caught.value.winerror == 5


def test_cancel_synchronous_io_is_false_when_the_thread_cannot_be_opened(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _with_kernel32_override(monkeypatch, OpenThread=_failing(87, result=0))
    assert cancel_synchronous_io(threading.get_native_id()) is False


def test_a_failed_process_snapshot_walk_raises_or_is_empty_by_its_number(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _kernel32_ledger() as ledger:
        first = ledger.mark()
        _with_kernel32_override(monkeypatch, Process32FirstW=_failing(87))
        with pytest.raises(WindowsApiError) as caught:
            descendants_of(os.getpid(), 1)
        monkeypatch.undo()
        assert caught.value.function == "Process32FirstW"
        assert caught.value.winerror == 87
        _require_one_released_snapshot(ledger, first)
        ledger.require_balanced(first)
        second = ledger.mark()
        _with_kernel32_override(monkeypatch, Process32FirstW=_failing(18))
        assert descendants_of(os.getpid(), 1) == ()  # ERROR_NO_MORE_FILES: no entries
        monkeypatch.undo()
        _require_one_released_snapshot(ledger, second)  # each snapshot on its own
        ledger.require_balanced(second)


def _require_one_released_snapshot(ledger: _Kernel32Ledger, start: int) -> None:
    (snapshot,) = ledger.records[start:]
    assert (snapshot.route, snapshot.kind) == (
        "CreateToolhelp32Snapshot",
        "process_snapshot",
    )
    assert (snapshot.state, snapshot.released_by) == ("released", "CloseHandle")


#: One planted leak per reviewed creator class (both snapshot kinds): a real
#: acquisition through the reviewed seam, deliberately not released.
_PLANTED_CREATIONS: Final[Mapping[str, tuple[str, Callable[[], int]]]] = {
    "process": ("OpenProcess", lambda: open_process_limited(os.getpid())),
    "job": ("CreateJobObjectW", create_kill_on_close_job),
    "process_snapshot": (
        "CreateToolhelp32Snapshot",
        lambda: int(windows_api._kernel32().CreateToolhelp32Snapshot(0x2, 0)),
    ),
    "thread_snapshot": (
        "CreateToolhelp32Snapshot",
        lambda: int(windows_api._kernel32().CreateToolhelp32Snapshot(0x4, 0)),
    ),
    "thread": (
        "OpenThread",
        lambda: int(
            windows_api._kernel32().OpenThread(
                _THREAD_QUERY_LIMITED_INFORMATION, False, threading.get_native_id()
            )
        ),
    ),
}


def test_every_reviewed_handle_creator_has_resource_ledger_coverage() -> None:
    """Plan Step 2 semantic control (owner ruling of 2026-11-14): the reviewed surface
    is split into creators and non-creators exhaustively and disjointly, against
    ``_API_NAMES`` and the production surface itself; then a planted leak through every
    reviewed creator (both snapshot kinds) is detected, by route and class, while a
    handle the window does not own is closed through the same seam -- which hides the
    leak from the whole-process count the ruling replaces -- and the window balances
    once the plant is reclaimed. The covered creators are observed, not derived from
    the classification; a non-creator acquires nothing."""
    creators = set(_REVIEWED_HANDLE_CREATORS)
    assert creators.isdisjoint(_REVIEWED_NON_CREATORS)
    assert creators | _REVIEWED_NON_CREATORS == _API_NAMES
    assert _kernel32_attribute_names(_module_tree()) == _API_NAMES
    covered: set[str] = set()
    for kind, (route, plant) in _PLANTED_CREATIONS.items():
        unrelated = open_process_limited(os.getpid())  # acquired before the window
        with _kernel32_ledger() as ledger:
            start = ledger.mark()
            leaked = plant()
            close_handle(unrelated)  # an unrelated closure through the same seam
            try:
                (record,) = ledger.unaccounted(start)
                assert (record.route, record.kind, record.value) == (
                    route,
                    kind,
                    leaked,
                )
                with pytest.raises(AssertionError, match="unaccounted"):
                    ledger.require_balanced(start)
            finally:
                close_handle(leaked)  # reclaimed after the detecting assertion
            ledger.require_balanced(start)
            assert ledger.unrelated == [unrelated]
            covered.add(record.route)
    assert covered == creators
    with _kernel32_ledger() as ledger:
        start = ledger.mark()
        assert console_process_count() >= 1
        assert ledger.records[start:] == []
        ledger.require_balanced(start)


#: Every ``ctypes`` name the binding module may load outside an annotation: types and
#: data helpers, none of which reaches a foreign function. ``WinDLL``, the one library
#: binder, is admitted only inside ``_kernel32``; any other ``ctypes`` name -- another
#: library loader (``windll``, ``CDLL``, ...), a function-pointer factory -- escapes.
_CTYPES_DATA_NAMES: Final = frozenset(
    {
        "POINTER",
        "Structure",
        "byref",
        "c_int",
        "c_size_t",
        "c_ulonglong",
        "c_void_p",
        "create_unicode_buffer",
        "get_last_error",
        "sizeof",
    }
)


def _annotation_nodes(tree: ast.AST) -> set[int]:
    """Every node inside an annotation (names there are never loaded at run time)."""
    roots: list[ast.AST] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign | ast.arg) and node.annotation is not None:
            roots.append(node.annotation)
        elif isinstance(node, ast.FunctionDef) and node.returns is not None:
            roots.append(node.returns)
    return {id(item) for root in roots for item in ast.walk(root)}


def _foreign_library_escapes(
    node: ast.AST, inside: set[int], annotations: set[int]
) -> list[str]:
    """A ``ctypes`` route to a library other than the one ``_kernel32`` binds: a
    ``ctypes`` import form other than ``import ctypes`` and ``from ctypes import
    wintypes``, a ``ctypes`` name outside the reviewed data names (``WinDLL`` only
    inside the binder), or a ``wintypes`` name that is not a type."""
    if isinstance(node, ast.Import):
        return [
            f"import {alias.name} at line {node.lineno}"
            for alias in node.names
            if alias.name.split(".")[0] == "ctypes"
            and (alias.name, alias.asname) != ("ctypes", None)
        ]
    if isinstance(node, ast.ImportFrom):
        if (node.module or "").split(".")[0] != "ctypes":
            return []
        forms = {(node.module, alias.name, alias.asname) for alias in node.names}
        if forms == {("ctypes", "wintypes", None)}:
            return []
        return [f"from {node.module} import at line {node.lineno}"]
    if not (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and id(node) not in annotations
    ):
        return []
    if node.value.id == "ctypes":
        if node.attr in _CTYPES_DATA_NAMES or (
            node.attr == "WinDLL" and id(node) in inside
        ):
            return []
        return [f"ctypes.{node.attr} loaded at line {node.lineno}"]
    if node.value.id == "wintypes" and not isinstance(
        getattr(wintypes, node.attr, None), type
    ):
        return [f"wintypes.{node.attr} loaded at line {node.lineno}"]
    return []


def _kernel32_route_escapes(tree: ast.AST) -> list[str]:
    """Every way a module could reach kernel32 other than ``_kernel32().<name>(...)``
    read on the spot: a ``_kernel32()`` result bound, passed or iterated instead of
    read for one attribute; ``_kernel32`` itself used as a value; a reviewed name called
    through any other object; the ``_KERNEL32`` slot read outside ``_kernel32``; and
    every ``ctypes`` route to another library (``_foreign_library_escapes``)."""
    parents = {
        id(child): node
        for node in ast.walk(tree)
        for child in ast.iter_child_nodes(node)
    }
    binder = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_kernel32"
    ]
    inside = {id(item) for node in binder for item in ast.walk(node)}
    annotations = _annotation_nodes(tree)
    escapes: list[str] = []
    for node in ast.walk(tree):
        escapes.extend(_foreign_library_escapes(node, inside, annotations))
        parent = parents.get(id(node))
        if isinstance(node, ast.Name) and node.id == "_kernel32":
            call = (
                parent if isinstance(parent, ast.Call) and parent.func is node else None
            )
            reader = parents.get(id(call)) if call is not None else None
            if not (isinstance(reader, ast.Attribute) and reader.value is call):
                escapes.append(f"_kernel32 used at line {node.lineno}")
        elif isinstance(node, ast.Name) and node.id == "_KERNEL32":
            at_module = isinstance(tree, ast.Module) and any(
                statement is parent for statement in tree.body
            )
            if id(node) not in inside and not at_module:
                escapes.append(f"_KERNEL32 read at line {node.lineno}")
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _API_NAMES
        ):
            receiver = node.func.value
            if not (
                isinstance(receiver, ast.Call)
                and isinstance(receiver.func, ast.Name)
                and receiver.func.id == "_kernel32"
            ):
                escapes.append(f"{node.func.attr} called at line {node.lineno}")
    return escapes


def test_every_kernel32_call_of_the_module_passes_the_ledger_seam() -> None:
    """Route completeness at the kernel32 seam (plan Step 3, owner ruling of
    2026-11-14): the module reaches kernel32 only as ``_kernel32().<name>(...)`` --
    never through a bound result, another object, a dynamic lookup or the slot itself
    -- so every creator call passes the ledger's proxy, which records each handle and
    fails on an unreviewed name or a creator result that is neither a handle nor a
    failure; and it reaches no other library through ``ctypes`` (a closed set of data
    names, the binder only inside ``_kernel32``, ``wintypes`` types only). Pinned on
    the production module and shown to fail closed on planted escapes, while a
    binder-only and annotation-only use stays admitted."""
    assert _kernel32_route_escapes(_module_tree()) == []
    planted = ast.parse(
        "k = _kernel32()\n"
        "k.OpenProcess(1, 0, 2)\n"
        "getattr(_kernel32(), 'OpenThread')\n"
        "_KERNEL32.CloseHandle(3)\n"
        "binder = _kernel32\n"
        "ctypes.windll.ntdll.NtClose(3)\n"
        "ctypes.WinDLL('ntdll')\n"
        "from ctypes import CDLL\n"
        "import ctypes.util\n"
        "wintypes.WinError\n"
    )
    assert sorted(_kernel32_route_escapes(planted)) == [
        "CloseHandle called at line 4",
        "OpenProcess called at line 2",
        "_KERNEL32 read at line 4",
        "_kernel32 used at line 1",
        "_kernel32 used at line 3",
        "_kernel32 used at line 5",
        "ctypes.WinDLL loaded at line 7",
        "ctypes.windll loaded at line 6",
        "from ctypes import at line 8",
        "import ctypes.util at line 9",
        "wintypes.WinError loaded at line 10",
    ]
    admitted = ast.parse(
        "def _kernel32() -> ctypes.WinDLL:\n"
        "    return ctypes.WinDLL('kernel32', use_last_error=True)\n"
        "slot: ctypes.WinDLL | None = None\n"
        "size = ctypes.sizeof(wintypes.DWORD)\n"
    )
    assert _kernel32_route_escapes(admitted) == []
    ledger = _Kernel32Ledger()
    stand_in = _Kernel32Proxy(
        windows_api._kernel32(), {"OpenThread": lambda *_args: "7"}
    )
    assert _LedgerKernel32(ledger, lambda: stand_in).OpenThread(1, 0, 2) == "7"
    assert ledger.anomalies == ["OpenThread returned a str"]
    assert ledger.records == []


def test_a_failed_handle_count_diagnostic_neither_blocks_nor_decides_the_ledger(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Owner ruling of 2026-11-14: the live table count beside the kernel32 ledger is
    a diagnostic. When collecting it fails (``GetProcessHandleCount`` answers FALSE
    with error 5), the window still opens, a balanced window balances and an
    unbalanced one fails by its unaccounted record; every failed collection stays
    recorded. The planted handle is closed after the detecting assertion."""
    probe = _Kernel32Proxy(_PROBE, {"GetProcessHandleCount": _failing(5)})
    monkeypatch.setattr(sys.modules[__name__], "_PROBE", probe)
    with _kernel32_ledger() as ledger:
        start = ledger.mark()
        close_handle(open_process_limited(os.getpid()))
        ledger.require_balanced(start)
        leaked = open_process_limited(os.getpid())
        try:
            with pytest.raises(
                AssertionError, match=r"process#\d+ via OpenProcess \(open\) is unacc"
            ):
                ledger.require_balanced(start)
        finally:
            close_handle(leaked)  # reclaimed after the detecting assertion
        ledger.require_balanced(start)
    assert ledger.diagnostics == ["GetProcessHandleCount failed: 5"] * 4


def test_a_descendant_identity_omits_an_unreadable_or_invalid_image() -> None:
    pid = os.getpid()
    creation = _own_creation()
    without = windows_api._descendant_identity(pid, creation, None)
    assert not isinstance(without.image_path, str)
    invalid = windows_api._descendant_identity(pid, creation, "bad\x00image")
    assert not isinstance(invalid.image_path, str)
    assert invalid.creation_identity == render_creation_identity(pid, creation)


def test_a_candidate_whose_times_or_identity_cannot_be_read_is_not_verified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pid = os.getpid()
    monkeypatch.setattr(
        windows_api, "process_times", lambda handle: 2**63
    )  # renders no identity
    assert windows_api._verified_child(pid, 0) is None
    monkeypatch.undo()

    def times_fail(handle: int) -> int:
        raise WindowsApiError("GetProcessTimes", 6)

    monkeypatch.setattr(windows_api, "process_times", times_fail)
    assert windows_api._verified_child(pid, 0) is None
    monkeypatch.undo()

    def image_fails(handle: int) -> str:
        raise WindowsApiError("QueryFullProcessImageNameW", 6)

    monkeypatch.setattr(windows_api, "process_image_path", image_fails)
    verified = windows_api._verified_child(pid, 0)
    monkeypatch.undo()
    assert verified is not None
    identity, creation = verified
    assert identity.pid == pid
    assert creation == _own_creation()
    assert not isinstance(identity.image_path, str)
