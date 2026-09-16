"""Typed kernel32 bindings for the Windows process controller (plan 3.1, 8.1-8.4).

Every function here is one narrow Win32 call over ``ctypes``, typed through
``ctypes.wintypes`` and bound on first use through the module-level ``_KERNEL32``
slot, so importing this module binds no library and performs no I/O (plan 2.6: the
fresh-import probe of ``tests/unit/test_package_layout.py``). A failure surfaces as
``WindowsApiError`` carrying the API name and the numeric ``GetLastError()`` code only
-- no system message is formatted, no path and no handle is carried -- and the
controller maps it to the Task 2 records. The only enumeration is the Toolhelp
descendant walk from an owned root, verified by parent pid and creation time; no call
reads a command line, an environment block, a token or another process's memory, and
only ``kernel32`` is ever bound. Every handle opened here is closed here (``finally``)
except the two the controller asks for and owns: the process handle from
``open_process_limited`` and the Job Object from ``create_kill_on_close_job``.
``process_exit_code`` returns the raw ``GetExitCodeProcess`` value, ``STILL_ACTIVE``
(259) included, which is why liveness is always ``wait_for_handle(handle, 0.0)`` and
never that value (plan 8.1).

Task-local readings, declared rather than inferred silently:

- ``open_process_limited`` always includes ``SYNCHRONIZE`` beside
  ``PROCESS_QUERY_LIMITED_INFORMATION``; ``terminate=True`` adds ``PROCESS_TERMINATE``
  and ``set_quota=True`` adds ``PROCESS_SET_QUOTA`` (what ``AssignProcessToJobObject``
  needs).
- ``descendants_of`` returns the committed ``DescendantIdentity`` records, so no second
  identity type exists; a candidate is kept when its creation time is not earlier than
  its parent's recorded one (equality is admitted because two creations can share a
  clock tick, while a stale parent pid pointing at a newer process is strictly earlier).
- ``wait_for_handle`` converts seconds to whole milliseconds bounded at ``0xFFFFFFFE``
  (never ``INFINITE``); ``WAIT_FAILED`` raises so the caller can record
  ``wait_failed:<winerror>``.
- ``resume_initial_thread`` resumes the first thread the Toolhelp thread snapshot lists
  for the pid (a suspended new process has exactly one); a pid with no thread surfaces
  as ``Thread32Next`` with ``ERROR_NO_MORE_FILES``.
- ``cancel_synchronous_io`` and ``generate_console_break`` report ``False`` instead of
  raising, because their callers (``LaunchedProcess.cancel_read`` and ``interrupt``)
  report rather than raise; ``generate_console_break`` refuses pid ``0``, which would
  signal every process on the console.
"""

from __future__ import annotations

import ctypes
from contextlib import suppress
from ctypes import wintypes
from typing import Final

from pydantic import ValidationError

from crypto_lab.process_supervision.models import (
    CTRL_BREAK_EVENT,
    DescendantIdentity,
    render_creation_identity,
)

__all__ = [
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

# --- Win32 constants, spelled locally (plan 2.6: no ``os``, ``sys``, ``signal``) ------

#: Access rights: the narrowest masks each call needs (plan 8.1-8.3).
_PROCESS_QUERY_LIMITED_INFORMATION: Final = 0x1000
_PROCESS_TERMINATE: Final = 0x0001
_PROCESS_SET_QUOTA: Final = 0x0100
_SYNCHRONIZE: Final = 0x00100000
_THREAD_SUSPEND_RESUME: Final = 0x0002
_THREAD_TERMINATE: Final = 0x0001
#: Toolhelp snapshot flags.
_TH32CS_SNAPPROCESS: Final = 0x00000002
_TH32CS_SNAPTHREAD: Final = 0x00000004
#: ``JobObjectExtendedLimitInformation`` and the kill-on-close limit flag.
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: Final = 9
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: Final = 0x00002000
#: ``WaitForSingleObject`` statuses; anything else is ``WAIT_FAILED``.
_WAIT_OBJECT_0: Final = 0x00000000
_WAIT_TIMEOUT: Final = 0x00000102
#: The largest finite wait; ``INFINITE`` (``0xFFFFFFFF``) is never passed.
_MAX_WAIT_MILLISECONDS: Final = 0xFFFFFFFE
_RESUME_THREAD_FAILED: Final = 0xFFFFFFFF
_MAX_DWORD: Final = 0xFFFFFFFF
_MAX_PATH: Final = 260
#: The ``QueryFullProcessImageNameW`` buffer, in characters (the NT path bound).
_IMAGE_PATH_BUFFER_CHARACTERS: Final = 32768
_ERROR_NO_MORE_FILES: Final = 18
_INVALID_HANDLE_VALUE: Final = (1 << (8 * ctypes.sizeof(ctypes.c_void_p))) - 1
_INFINITE_SECONDS: Final = frozenset({float("inf"), float("-inf")})

#: Plan 2.6: bound on the first call, never at import.
_KERNEL32: ctypes.WinDLL | None = None


# --- Structures (typed field annotations for strict mypy; ``_fields_`` for ctypes) ----


class _FILETIME(ctypes.Structure):
    dwLowDateTime: int
    dwHighDateTime: int
    _fields_ = (("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD))


class _PROCESSENTRY32W(ctypes.Structure):
    dwSize: int
    cntUsage: int
    th32ProcessID: int
    th32DefaultHeapID: int
    th32ModuleID: int
    cntThreads: int
    th32ParentProcessID: int
    pcPriClassBase: int
    dwFlags: int
    szExeFile: str
    _fields_ = (
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * _MAX_PATH),
    )


class _THREADENTRY32(ctypes.Structure):
    dwSize: int
    cntUsage: int
    th32ThreadID: int
    th32OwnerProcessID: int
    tpBasePri: int
    tpDeltaPri: int
    dwFlags: int
    _fields_ = (
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
    )


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = (
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    )


class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    LimitFlags: int
    _fields_ = (
        ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
        ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    )


class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    BasicLimitInformation: _JOBOBJECT_BASIC_LIMIT_INFORMATION
    _fields_ = (
        ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    )


# --- The error and the binding -------------------------------------------------------


class WindowsApiError(OSError):
    """One failed kernel32 call: the API name and its numeric ``GetLastError()`` code.

    The text is the fixed ``"<function> failed"``: no system message is formatted and no
    path or handle is carried, so the controller can retain the number and the name and
    nothing else (plan 3.5: numeric codes, never OS message text).
    """

    def __init__(self, function: str, winerror: int) -> None:
        super().__init__(winerror, f"{function} failed", None, winerror)
        self.function = function

    def __str__(self) -> str:
        return f"{self.function} failed"


def _configure(library: ctypes.WinDLL) -> None:
    """Declare every binding's argument and return types once (strict typing at the
    boundary; ``HANDLE`` results come back as ``int | None``)."""
    handle = wintypes.HANDLE
    dword = wintypes.DWORD
    bool_ = wintypes.BOOL
    filetime = ctypes.POINTER(_FILETIME)
    library.OpenProcess.argtypes = [dword, bool_, dword]
    library.OpenProcess.restype = handle
    library.GetProcessTimes.argtypes = [handle, filetime, filetime, filetime, filetime]
    library.GetProcessTimes.restype = bool_
    library.QueryFullProcessImageNameW.argtypes = [
        handle,
        dword,
        wintypes.LPWSTR,
        wintypes.LPDWORD,
    ]
    library.QueryFullProcessImageNameW.restype = bool_
    library.GetExitCodeProcess.argtypes = [handle, wintypes.LPDWORD]
    library.GetExitCodeProcess.restype = bool_
    library.WaitForSingleObject.argtypes = [handle, dword]
    library.WaitForSingleObject.restype = dword
    library.CloseHandle.argtypes = [handle]
    library.CloseHandle.restype = bool_
    library.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    library.CreateJobObjectW.restype = handle
    library.SetInformationJobObject.argtypes = [
        handle,
        ctypes.c_int,
        ctypes.POINTER(_JOBOBJECT_EXTENDED_LIMIT_INFORMATION),
        dword,
    ]
    library.SetInformationJobObject.restype = bool_
    library.AssignProcessToJobObject.argtypes = [handle, handle]
    library.AssignProcessToJobObject.restype = bool_
    library.IsProcessInJob.argtypes = [handle, handle, wintypes.PBOOL]
    library.IsProcessInJob.restype = bool_
    library.TerminateJobObject.argtypes = [handle, wintypes.UINT]
    library.TerminateJobObject.restype = bool_
    library.TerminateProcess.argtypes = [handle, wintypes.UINT]
    library.TerminateProcess.restype = bool_
    library.GenerateConsoleCtrlEvent.argtypes = [dword, dword]
    library.GenerateConsoleCtrlEvent.restype = bool_
    library.GetConsoleProcessList.argtypes = [wintypes.LPDWORD, dword]
    library.GetConsoleProcessList.restype = dword
    library.CreateToolhelp32Snapshot.argtypes = [dword, dword]
    library.CreateToolhelp32Snapshot.restype = handle
    process_entry = ctypes.POINTER(_PROCESSENTRY32W)
    library.Process32FirstW.argtypes = [handle, process_entry]
    library.Process32FirstW.restype = bool_
    library.Process32NextW.argtypes = [handle, process_entry]
    library.Process32NextW.restype = bool_
    thread_entry = ctypes.POINTER(_THREADENTRY32)
    library.Thread32First.argtypes = [handle, thread_entry]
    library.Thread32First.restype = bool_
    library.Thread32Next.argtypes = [handle, thread_entry]
    library.Thread32Next.restype = bool_
    library.OpenThread.argtypes = [dword, bool_, dword]
    library.OpenThread.restype = handle
    library.ResumeThread.argtypes = [handle]
    library.ResumeThread.restype = dword
    library.CancelSynchronousIo.argtypes = [handle]
    library.CancelSynchronousIo.restype = bool_


def _kernel32() -> ctypes.WinDLL:
    """Bind ``kernel32`` on the first call (plan 2.6: never at import time)."""
    global _KERNEL32
    if _KERNEL32 is None:
        library = ctypes.WinDLL("kernel32", use_last_error=True)
        _configure(library)
        _KERNEL32 = library
    return _KERNEL32


def _last_error() -> int:
    return int(ctypes.get_last_error())


def _require_true(result: object, function: str) -> None:
    if not result:
        raise WindowsApiError(function, _last_error())


def _require_handle(result: object, function: str) -> int:
    if not isinstance(result, int) or result in (0, _INVALID_HANDLE_VALUE):
        raise WindowsApiError(function, _last_error())
    return result


def _require_dword(value: int, label: str) -> None:
    if type(value) is not int or not 0 <= value <= _MAX_DWORD:
        raise ValueError(f"{label} must be an integer within 0..{_MAX_DWORD}")


def _require_exit_code(exit_code: int) -> None:
    _require_dword(exit_code, "exit_code")


def _milliseconds(timeout_seconds: float) -> int:
    """Whole milliseconds for ``WaitForSingleObject``; finite, never negative, never
    ``INFINITE``; a positive sub-millisecond timeout waits one millisecond."""
    if isinstance(timeout_seconds, bool) or not isinstance(
        timeout_seconds, int | float
    ):
        raise TypeError("timeout_seconds must be a number of seconds")
    if (
        timeout_seconds != timeout_seconds
        or timeout_seconds in _INFINITE_SECONDS
        or timeout_seconds < 0
    ):
        raise ValueError("timeout_seconds must be finite and never negative")
    milliseconds = int(timeout_seconds * 1000)
    if milliseconds == 0 and timeout_seconds > 0:
        milliseconds = 1
    return min(milliseconds, _MAX_WAIT_MILLISECONDS)


def _close_quietly(handle: int) -> None:
    with suppress(WindowsApiError):
        close_handle(handle)


# --- Processes: open, identity, image, exit, wait, close ---------------------------


def open_process_limited(
    pid: int, *, terminate: bool = False, set_quota: bool = False
) -> int:
    """``OpenProcess`` with ``PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE`` (plan
    8.1), plus ``PROCESS_TERMINATE`` and ``PROCESS_SET_QUOTA`` on request (plan 8.2)."""
    _require_dword(pid, "pid")
    access = _PROCESS_QUERY_LIMITED_INFORMATION | _SYNCHRONIZE
    if terminate:
        access |= _PROCESS_TERMINATE
    if set_quota:
        access |= _PROCESS_SET_QUOTA
    return _require_handle(_kernel32().OpenProcess(access, False, pid), "OpenProcess")


def process_times(handle: int) -> int:
    """The process creation ``FILETIME`` as 100-nanosecond ticks since 1601 (plan
    8.1)."""
    creation = _FILETIME()
    exit_time = _FILETIME()
    kernel_time = _FILETIME()
    user_time = _FILETIME()
    _require_true(
        _kernel32().GetProcessTimes(
            handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time),
        ),
        "GetProcessTimes",
    )
    return (int(creation.dwHighDateTime) << 32) | int(creation.dwLowDateTime)


def process_image_path(handle: int) -> str:
    """``QueryFullProcessImageNameW``: the Win32 image path of the process as loaded."""
    name_characters = ctypes.create_unicode_buffer(_IMAGE_PATH_BUFFER_CHARACTERS)
    size = wintypes.DWORD(_IMAGE_PATH_BUFFER_CHARACTERS)
    _require_true(
        _kernel32().QueryFullProcessImageNameW(
            handle, 0, name_characters, ctypes.byref(size)
        ),
        "QueryFullProcessImageNameW",
    )
    return str(name_characters.value)


def process_exit_code(handle: int) -> int:
    """The raw ``GetExitCodeProcess`` value; ``259`` for a live process, so the caller
    reads it only after the handle is signaled (plan 8.1, 8.3)."""
    code = wintypes.DWORD(0)
    _require_true(
        _kernel32().GetExitCodeProcess(handle, ctypes.byref(code)), "GetExitCodeProcess"
    )
    return int(code.value)


def wait_for_handle(handle: int, timeout_seconds: float) -> bool:
    """``WaitForSingleObject``: ``True`` when signaled, ``False`` on timeout; the only
    liveness test (plan 8.1). ``WAIT_FAILED`` raises with its number."""
    milliseconds = _milliseconds(timeout_seconds)
    status = int(_kernel32().WaitForSingleObject(handle, milliseconds))
    if status == _WAIT_OBJECT_0:
        return True
    if status == _WAIT_TIMEOUT:
        return False
    raise WindowsApiError("WaitForSingleObject", _last_error())


def close_handle(handle: int) -> None:
    _require_true(_kernel32().CloseHandle(handle), "CloseHandle")


# --- Job Objects (a cleanup mechanism, plan 8.2-8.4) ------------------------------


def create_kill_on_close_job() -> int:
    """``CreateJobObjectW(NULL, NULL)`` with ``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE``."""
    job = _require_handle(_kernel32().CreateJobObjectW(None, None), "CreateJobObjectW")
    limits = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    limits.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    try:
        _require_true(
            _kernel32().SetInformationJobObject(
                job,
                _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(limits),
                ctypes.sizeof(limits),
            ),
            "SetInformationJobObject",
        )
    except WindowsApiError:
        _close_quietly(job)
        raise
    return job


def assign_to_job(job_handle: int, process_handle: int) -> None:
    _require_true(
        _kernel32().AssignProcessToJobObject(job_handle, process_handle),
        "AssignProcessToJobObject",
    )


def is_process_in_job(process_handle: int, job_handle: int | None) -> bool:
    """``IsProcessInJob``; ``False`` for ``None``, so a ``job_handle: int | None``
    needs no narrowing (plan Task 4)."""
    if job_handle is None:
        return False
    result = wintypes.BOOL(0)
    _require_true(
        _kernel32().IsProcessInJob(process_handle, job_handle, ctypes.byref(result)),
        "IsProcessInJob",
    )
    return bool(result.value)


def terminate_job(job_handle: int, exit_code: int) -> bool:
    """``TerminateJobObject``; ``False`` when the call returned ``FALSE`` (plan 8.3 then
    falls back to per-process termination)."""
    _require_exit_code(exit_code)
    return bool(_kernel32().TerminateJobObject(job_handle, exit_code))


# --- Termination, interrupts and the console --------------------------------------


def terminate_process(handle: int, exit_code: int) -> None:
    """``TerminateProcess``; a ``FALSE`` return raises with its number (the caller
    treats ``ERROR_ACCESS_DENIED`` on a dying process as "wait for the handle", plan
    8.3)."""
    _require_exit_code(exit_code)
    _require_true(_kernel32().TerminateProcess(handle, exit_code), "TerminateProcess")


def generate_console_break(pid: int) -> bool:
    """``GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid)`` to the child's own process
    group (plan 8.3); pid ``0`` is refused because it would signal the whole console."""
    if type(pid) is not int or not 1 <= pid <= _MAX_DWORD:
        raise ValueError(
            "pid must name one process group; pid 0 would signal the whole console"
        )
    return bool(_kernel32().GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid))


def console_process_count() -> int:
    """``GetConsoleProcessList``: how many processes share this console (``0`` when the
    process has none), the precondition of the interrupt tests (plan 10)."""
    identifiers = (wintypes.DWORD * 1)()
    return int(_kernel32().GetConsoleProcessList(identifiers, 1))


# --- Threads: the suspended launch's resume and the blocked read's cancellation ------


def _first_thread_of(pid: int) -> int:
    snapshot = _require_handle(
        _kernel32().CreateToolhelp32Snapshot(_TH32CS_SNAPTHREAD, 0),
        "CreateToolhelp32Snapshot",
    )
    try:
        entry = _THREADENTRY32()
        entry.dwSize = ctypes.sizeof(entry)
        _require_true(
            _kernel32().Thread32First(snapshot, ctypes.byref(entry)), "Thread32First"
        )
        while True:
            if int(entry.th32OwnerProcessID) == pid:
                return int(entry.th32ThreadID)
            _require_true(
                _kernel32().Thread32Next(snapshot, ctypes.byref(entry)), "Thread32Next"
            )
    finally:
        _close_quietly(snapshot)


def resume_initial_thread(pid: int) -> None:
    """Plan 8.2 step 4: the one thread of the still-suspended child, reopened by id
    because ``Popen`` closed the primary thread handle, then ``ResumeThread``."""
    _require_dword(pid, "pid")
    thread_id = _first_thread_of(pid)
    thread = _require_handle(
        _kernel32().OpenThread(_THREAD_SUSPEND_RESUME, False, thread_id), "OpenThread"
    )
    try:
        previous = int(_kernel32().ResumeThread(thread))
        if previous == _RESUME_THREAD_FAILED:
            raise WindowsApiError("ResumeThread", _last_error())
    finally:
        _close_quietly(thread)


def cancel_synchronous_io(native_thread_id: int) -> bool:
    """``OpenThread(THREAD_TERMINATE)`` + ``CancelSynchronousIo`` for a reader blocked
    in a pipe read (plan 6.7); ``False`` on any failure, including nothing to cancel."""
    if type(native_thread_id) is not int or not 1 <= native_thread_id <= _MAX_DWORD:
        return False
    thread = _kernel32().OpenThread(_THREAD_TERMINATE, False, native_thread_id)
    if not isinstance(thread, int) or thread == 0:
        return False
    try:
        return bool(_kernel32().CancelSynchronousIo(thread))
    finally:
        _close_quietly(thread)


# --- The Toolhelp descendant walk (plan 8.3) ---------------------------------------


def _process_children() -> dict[int, list[int]]:
    """One ``TH32CS_SNAPPROCESS`` snapshot as a parent-pid to child-pids map."""
    snapshot = _require_handle(
        _kernel32().CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0),
        "CreateToolhelp32Snapshot",
    )
    children: dict[int, list[int]] = {}
    try:
        entry = _PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        more = bool(_kernel32().Process32FirstW(snapshot, ctypes.byref(entry)))
        if not more:
            code = _last_error()
            if code != _ERROR_NO_MORE_FILES:
                raise WindowsApiError("Process32FirstW", code)
        while more:
            children.setdefault(int(entry.th32ParentProcessID), []).append(
                int(entry.th32ProcessID)
            )
            more = bool(_kernel32().Process32NextW(snapshot, ctypes.byref(entry)))
    finally:
        _close_quietly(snapshot)
    return children


def _descendant_identity(
    pid: int, creation_100ns: int, image_path: str | None
) -> DescendantIdentity:
    text = render_creation_identity(pid, creation_100ns)
    if image_path is not None:
        with suppress(ValidationError):
            return DescendantIdentity(
                pid=pid, creation_identity=text, image_path=image_path
            )
    return DescendantIdentity(pid=pid, creation_identity=text)


def _verified_child(
    pid: int, parent_creation_100ns: int
) -> tuple[DescendantIdentity, int] | None:
    """Open the candidate, keep it only when its creation time is not earlier than its
    parent's recorded one (the PID-reuse guard of plan 8.3), record its image path when
    readable, and close the handle."""
    try:
        handle = open_process_limited(pid)
    except WindowsApiError:
        return None
    try:
        try:
            creation = process_times(handle)
        except WindowsApiError:
            return None
        if creation < parent_creation_100ns:
            return None
        image_path: str | None
        try:
            image_path = process_image_path(handle)
        except WindowsApiError:
            image_path = None
    finally:
        _close_quietly(handle)
    try:
        identity = _descendant_identity(pid, creation, image_path)
    except ValueError:
        return None
    return identity, creation


def descendants_of(
    root_pid: int, root_creation_100ns: int
) -> tuple[DescendantIdentity, ...]:
    """Plan 8.3: the verified descendants of a root, breadth-first, from one snapshot.

    Each candidate is opened with the limited mask, kept only when its creation time is
    not earlier than its parent's recorded creation time, and closed before the next;
    the result holds identities and image paths only, never a handle. The walk starts
    at the root pid, so a descendant whose parent chain has exited is not reachable
    (the plan states this limitation, plan 8.2 and 8.4).
    """
    _require_dword(root_pid, "root_pid")
    children = _process_children()
    verified: list[DescendantIdentity] = []
    seen = {root_pid}
    pending: list[tuple[int, int]] = [(root_pid, root_creation_100ns)]
    while pending:
        parent_pid, parent_creation = pending.pop(0)
        for child_pid in children.get(parent_pid, []):
            if child_pid in seen:
                continue
            seen.add(child_pid)
            verified_child = _verified_child(child_pid, parent_creation)
            if verified_child is None:
                continue
            identity, creation = verified_child
            verified.append(identity)
            pending.append((child_pid, creation))
    return tuple(verified)
