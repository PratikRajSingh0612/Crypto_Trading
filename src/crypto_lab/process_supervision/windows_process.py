"""The Windows process controller: suspended launch, durable creation identity, Job
Objects, console interrupts, verified tree termination and handle cleanup.

Stage 7 plan sections 8.1-8.4 (with 3.4, 6.5 and 6.7), under specification sections
14.1, 15.1, 15.4 and 15.6. ``WindowsProcessController.launch`` performs the one
``Popen`` call in ``src`` -- a list argv, ``shell=False``, the empty environment
mapping, ``stdin`` from the null device, both pipes, ``bufsize=0``, ``close_fds=True``
and ``CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED`` -- then owns the still-suspended
child through its own ``OpenProcess`` handle, reads the creation ``FILETIME`` that
becomes the durable ``windows:<pid>:<creation>`` identity and the image path, assigns
the child to a kill-on-close Job Object and only then resumes its initial thread, so
nothing the venv launcher spawns can exist outside the job. The Job Object is
a cleanup mechanism, never a security boundary. ``inspect`` decides presence from the
creation time and the unsignaled-handle test alone: never from ``GetExitCodeProcess``
(whose ``259`` is both "still active" and a real exit value), never from the pid alone,
never from the image path, which is recorded and not compared. ``terminate_tree``
verifies every descendant by
parent pid and creation time before it acts, kills the job when attached and otherwise
each verified process leaves first, only while its handle is unsignaled, and waits for
death within ``POST_TERMINATION_WAIT_SECONDS`` before it reports. Nothing here mints a
diagnostic, reads a clock, touches the environment or a raw token, or launches anything
but the specification it is handed; every failure is reported through the Task 2
records.

Task-local readings, declared rather than inferred silently:

- A ``ProcessIdentity`` whose creation text does not parse, or whose parsed pid differs
  from ``identity.pid``, is ``UNDETERMINED``: fail closed, nothing opened, nothing
  raised.
- An image-path query failure never changes presence; the path is then ``MISSING``. For
  ``ALIVE_DIFFERENT_IDENTITY`` the path is not queried at all: that live process is not
  ours and no consumer reads it.
- ``TerminationReport.forced`` is true exactly when a termination call
  (``TerminateJobObject`` or ``TerminateProcess``) was issued; a reaped root with
  nothing left to kill and no job reports ``forced=False``.
- The controller-level ``terminate_tree`` verifies the root's creation time first: an
  absent or different-identity root yields an empty report and kills nothing; a root
  that cannot be opened yields one ``TREE_VERIFIED_DEAD`` failure ``open_failed:<n>``.
- ``close`` lists ``JOB_CLOSED`` as completed even when no job was attached, so a report
  from ``close`` always names the same four actions; it is idempotent.
- Reason words are ``<word>:<number>``: ``reader_alive:0``, ``still_alive:<count>``,
  ``terminate_failed:<winerror>``, ``wait_failed:<winerror>``,
  ``close_failed:<winerror>``, ``open_failed:<winerror>``,
  ``enumeration_failed:<winerror>``.
- ``wait`` memoizes the first reaped value; after ``close`` it raises for an unreaped
  child (an invalid handle is a caller defect, and the port lists only ``interrupt``,
  ``terminate_tree``, ``cancel_read`` and ``close`` as never raising).
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from contextlib import suppress
from typing import IO, Final

from pydantic import TypeAdapter, ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.domain.command_invocation import ProcessIdentity
from crypto_lab.domain.descriptors import ExecutablePath
from crypto_lab.process_supervision import windows_api
from crypto_lab.process_supervision.models import (
    CREATE_SUSPENDED,
    POST_TERMINATION_WAIT_SECONDS,
    CleanupAction,
    CleanupFailure,
    CleanupReport,
    CreationIdentity,
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
from crypto_lab.process_supervision.windows_api import WindowsApiError

__all__ = ["WindowsLaunchedProcess", "WindowsProcessController"]

#: Plan 8.1 and 8.3: the two Win32 error numbers the controller distinguishes.
_ERROR_ACCESS_DENIED: Final = 5
_ERROR_INVALID_PARAMETER: Final = 87
#: Plan 8.2: ``ERROR_FILE_NOT_FOUND`` and ``ERROR_PATH_NOT_FOUND`` at ``popen``.
_NOT_FOUND_WINERRORS: Final[frozenset[int]] = frozenset({2, 3})
_MAX_EXIT_CODE: Final = 0xFFFFFFFF
_INFINITE_SECONDS: Final = frozenset({float("inf"), float("-inf")})
_IMAGE_PATH: TypeAdapter[str] = TypeAdapter(ExecutablePath)

# --- Pure helpers --------------------------------------------------------------------


def _presence_of_open_failure(winerror: int) -> ProcessPresence:
    """Plan 8.1: only ``ERROR_INVALID_PARAMETER`` means the pid names no process; access
    denied and every other failure is ``UNDETERMINED``, never ``ABSENT``."""
    if winerror == _ERROR_INVALID_PARAMETER:
        return ProcessPresence.ABSENT
    return ProcessPresence.UNDETERMINED


def _require_exit_code(exit_code: int) -> None:
    if type(exit_code) is not int or not 0 <= exit_code <= _MAX_EXIT_CODE:
        raise ValueError(f"exit_code must be an integer within 0..{_MAX_EXIT_CODE}")


def _require_timeout(timeout_seconds: float) -> None:
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


def _parsed(identity: ProcessIdentity) -> CreationIdentity | None:
    """The committed grammar, and the pid agreement; ``None`` fails closed."""
    try:
        parsed = parse_creation_identity(identity.creation_identity)
    except (TypeError, ValueError):
        return None
    return parsed if parsed.pid == identity.pid else None


def _winerror_of(error: OSError) -> int | MISSING:  # type: ignore[valid-type]
    winerror = getattr(error, "winerror", None)
    return winerror if isinstance(winerror, int) else MISSING


def _image_path_or_missing(handle: int) -> ExecutablePath | MISSING:  # type: ignore[valid-type]
    try:
        text = windows_api.process_image_path(handle)
    except WindowsApiError:
        return MISSING
    try:
        return _IMAGE_PATH.validate_python(text)
    except ValidationError:
        return MISSING


def _close_quietly(handle: int) -> None:
    with suppress(WindowsApiError):
        windows_api.close_handle(handle)


def _tree_failure(word: str, number: int) -> CleanupFailure:
    return CleanupFailure(
        action=CleanupAction.TREE_VERIFIED_DEAD, reason=f"{word}:{number}"
    )


def _inspect_pid(
    pid: int, creation_100ns: int
) -> tuple[ProcessPresence, int | None, ExecutablePath | MISSING]:  # type: ignore[valid-type]
    """The presence decision (plan 8.1): open with the limited mask, read the creation
    time, test the handle unsignaled, compare; the observed creation time and the image
    path are returned beside the presence, and the handle is closed."""
    try:
        handle = windows_api.open_process_limited(pid)
    except WindowsApiError as error:
        return _presence_of_open_failure(error.winerror), None, MISSING
    try:
        try:
            observed = windows_api.process_times(handle)
            signaled = windows_api.wait_for_handle(handle, 0.0)
        except WindowsApiError:
            return ProcessPresence.UNDETERMINED, None, MISSING
        if signaled:
            return ProcessPresence.ABSENT, None, MISSING
        if observed != creation_100ns:
            return ProcessPresence.ALIVE_DIFFERENT_IDENTITY, observed, MISSING
        return ProcessPresence.ALIVE_MATCHING, observed, _image_path_or_missing(handle)
    finally:
        _close_quietly(handle)


def _is_alive_matching(descendant: DescendantIdentity) -> bool:
    parsed = parse_creation_identity(descendant.creation_identity)
    presence, _, _ = _inspect_pid(parsed.pid, parsed.creation_100ns)
    return presence is ProcessPresence.ALIVE_MATCHING


# --- Tree termination (plan 8.3), shared by the launched process and the controller ---


def _open_verified(
    descendants: tuple[DescendantIdentity, ...],
) -> list[int]:
    """Reopen every enumerated descendant with ``PROCESS_TERMINATE`` and keep the handle
    only when its creation time still equals the recorded one (identity first, never a
    pid alone)."""
    handles: list[int] = []
    for descendant in descendants:
        parsed = parse_creation_identity(descendant.creation_identity)
        try:
            handle = windows_api.open_process_limited(parsed.pid, terminate=True)
        except WindowsApiError:
            continue
        try:
            matches = windows_api.process_times(handle) == parsed.creation_100ns
        except WindowsApiError:
            matches = False
        if matches:
            handles.append(handle)
        else:
            _close_quietly(handle)
    return handles


def _force(handle: int, exit_code: int) -> CleanupFailure | None:
    """``TerminateProcess`` then a bounded wait; a handle that becomes signaled is dead
    and never a failure, whether the call returned ``TRUE`` or
    ``ERROR_ACCESS_DENIED``."""
    try:
        windows_api.terminate_process(handle, exit_code)
    except WindowsApiError as error:
        if error.winerror != _ERROR_ACCESS_DENIED:
            return _tree_failure("terminate_failed", error.winerror)
    try:
        if windows_api.wait_for_handle(handle, POST_TERMINATION_WAIT_SECONDS):
            return None
    except WindowsApiError as error:
        return _tree_failure("wait_failed", error.winerror)
    return _tree_failure("still_alive", 0)


def _await_death_or_force(handle: int, exit_code: int) -> CleanupFailure | None:
    """After a successful job kill: wait for the member to die within the bound, and
    force the one that escaped the job (plan 8.3)."""
    try:
        if windows_api.wait_for_handle(handle, POST_TERMINATION_WAIT_SECONDS):
            return None
    except WindowsApiError as error:
        return _tree_failure("wait_failed", error.winerror)
    return _force(handle, exit_code)


def _terminate_tree(
    *,
    root_pid: int,
    root_creation_100ns: int,
    root_handle: int | None,
    job_handle: int | None,
    exit_code: int,
) -> TerminationReport:
    """Plan 8.3: enumerate and verify the tree, kill the job when attached, otherwise
    every verified process leaves first and only while unsignaled; wait for death within
    the bound; report."""
    failures: list[CleanupFailure] = []
    forced = False
    job_terminated = False
    try:
        descendants = windows_api.descendants_of(root_pid, root_creation_100ns)
    except WindowsApiError as error:
        descendants = ()
        failures.append(_tree_failure("enumeration_failed", error.winerror))
    descendant_handles = _open_verified(descendants)
    try:
        if job_handle is not None:
            forced = True
            job_terminated = windows_api.terminate_job(job_handle, exit_code)
        root_handles = [] if root_handle is None else [root_handle]
        if job_terminated:
            for handle in [*root_handles, *descendant_handles]:
                failure = _await_death_or_force(handle, exit_code)
                if failure is not None:
                    failures.append(failure)
        else:
            for handle in [*reversed(descendant_handles), *root_handles]:
                try:
                    unsignaled = not windows_api.wait_for_handle(handle, 0.0)
                except WindowsApiError as error:
                    failures.append(_tree_failure("wait_failed", error.winerror))
                    continue
                if not unsignaled:
                    continue
                forced = True
                failure = _force(handle, exit_code)
                if failure is not None:
                    failures.append(failure)
    finally:
        for handle in descendant_handles:
            _close_quietly(handle)
    return TerminationReport(
        forced=forced,
        exit_code_used=exit_code if forced else MISSING,
        job_terminated=job_terminated,
        descendants=descendants,
        failures=tuple(failures),
    )


def _empty_report(
    failures: tuple[CleanupFailure, ...] = (),
) -> TerminationReport:
    return TerminationReport(
        forced=False, job_terminated=False, descendants=(), failures=failures
    )


# --- The launched process (plan 3.4, 8.2-8.4) -------------------------------------


class WindowsLaunchedProcess:
    """One launched child as the supervisor sees it: the port members plus the two owned
    handles, as a plain class (plan 2.6: never a Pydantic model here).

    ``process_handle`` and ``job_handle`` are process-local facts for the supervisor and
    the tests; nothing serializes them. ``wait(0.0)`` is the poll; ``interrupt``,
    ``terminate_tree``, ``cancel_read`` and ``close`` never raise, they report. The
    ``Popen`` object is retained for the life of this object: its own process handle
    keeps the pid reserved, so a ``terminate_tree`` or re-inspection after ``close``
    can never reach a reused pid, and it is released with the object, after
    ``PROCESS_HANDLE_CLOSED``.
    """

    def __init__(
        self,
        *,
        popen: subprocess.Popen[bytes],
        process_handle: int,
        job_handle: int | None,
        job_error_code: int | MISSING,  # type: ignore[valid-type]
        creation_100ns: int,
        image_path: ExecutablePath | MISSING,  # type: ignore[valid-type]
    ) -> None:
        stdout = popen.stdout
        stderr = popen.stderr
        if stdout is None or stderr is None:
            raise ValueError("a launched process carries both pipe read ends")
        self._popen = popen
        self._stdout: IO[bytes] = stdout
        self._stderr: IO[bytes] = stderr
        self.process_handle = process_handle
        self.job_handle = job_handle
        self._job_error_code = job_error_code
        self._creation_100ns = creation_100ns
        self._creation_identity = render_creation_identity(popen.pid, creation_100ns)
        self._image_path = image_path
        self._exit_code: int | None = None
        self._process_handle_open = True
        self._job_handle_open = job_handle is not None
        self._descendants: list[DescendantIdentity] = []

    # -- the launch facts --

    @property
    def pid(self) -> int:
        return self._popen.pid

    @property
    def creation_identity(self) -> str:
        return self._creation_identity

    @property
    def stdout(self) -> IO[bytes]:
        return self._stdout

    @property
    def stderr(self) -> IO[bytes]:
        return self._stderr

    @property
    def job_available(self) -> bool:
        return self.job_handle is not None

    @property
    def job_error_code(self) -> int | MISSING:  # type: ignore[valid-type]
        return self._job_error_code

    @property
    def image_path(self) -> ExecutablePath | MISSING:  # type: ignore[valid-type]
        return self._image_path

    # -- exit facts --

    def wait(self, timeout_seconds: float) -> int | None:
        """Plan 8.3: wait on the handle, then read the exit value only once it is
        signaled, so ``STILL_ACTIVE`` can never be mistaken for an exit."""
        _require_timeout(timeout_seconds)
        if self._exit_code is not None:
            return self._exit_code
        if not windows_api.wait_for_handle(self.process_handle, timeout_seconds):
            return None
        self._exit_code = windows_api.process_exit_code(self.process_handle)
        self._popen.poll()  # the Popen object learns the exit; its value is not used
        return self._exit_code

    def _root_signaled(self) -> bool | None:
        """``True`` dead, ``False`` alive, ``None`` when the handle cannot tell."""
        if self._exit_code is not None:
            return True
        if not self._process_handle_open:
            return None
        try:
            return windows_api.wait_for_handle(self.process_handle, 0.0)
        except WindowsApiError:
            return None

    def interrupt(self) -> InterruptOutcome:
        """Plan 8.3: ``CTRL_BREAK`` to the child's own group; a signaled root before or
        after the call is ``PROCESS_GONE`` and never receives an event."""
        signaled = self._root_signaled()
        if signaled:
            return InterruptOutcome.PROCESS_GONE
        if signaled is None:
            return InterruptOutcome.UNAVAILABLE
        if windows_api.generate_console_break(self.pid):
            return InterruptOutcome.DELIVERED
        if self._root_signaled():
            return InterruptOutcome.PROCESS_GONE
        return InterruptOutcome.UNAVAILABLE

    # -- termination and cleanup --

    def terminate_tree(self, exit_code: int) -> TerminationReport:
        _require_exit_code(exit_code)
        report = _terminate_tree(
            root_pid=self.pid,
            root_creation_100ns=self._creation_100ns,
            root_handle=self.process_handle if self._process_handle_open else None,
            job_handle=self.job_handle if self._job_handle_open else None,
            exit_code=exit_code,
        )
        recorded = {(item.pid, item.creation_identity) for item in self._descendants}
        for descendant in report.descendants:
            if (descendant.pid, descendant.creation_identity) not in recorded:
                self._descendants.append(descendant)
        return report

    def cancel_read(self, native_thread_id: int) -> bool:
        return windows_api.cancel_synchronous_io(native_thread_id)

    def _verify_tree_dead(self) -> CleanupFailure | None:
        alive = 0
        if self._exit_code is None and self._process_handle_open:
            try:
                if not windows_api.wait_for_handle(self.process_handle, 0.0):
                    alive += 1
            except WindowsApiError as error:
                return _tree_failure("wait_failed", error.winerror)
        elif self._exit_code is None:
            # The owned handle is already closed (a repeated close): re-inspect the
            # root through its identity; the retained Popen handle keeps the pid
            # reserved and the creation check is exact, so this reaches only our child.
            presence, _, _ = _inspect_pid(self.pid, self._creation_100ns)
            if presence is ProcessPresence.ALIVE_MATCHING:
                alive += 1
        alive += sum(1 for item in self._descendants if _is_alive_matching(item))
        return None if alive == 0 else _tree_failure("still_alive", alive)

    def _close_owned_handle(
        self, action: CleanupAction, handle: int | None, is_open: bool
    ) -> CleanupFailure | None:
        if handle is None or not is_open:
            return None
        try:
            windows_api.close_handle(handle)
        except WindowsApiError as error:
            return CleanupFailure(
                action=action, reason=f"close_failed:{error.winerror}"
            )
        return None

    def close(self, *, close_stdout: bool, close_stderr: bool) -> CleanupReport:
        """Plan 8.4 in order: the flagged pipes, the tree verified dead, the job handle
        (kill-on-close is the last line of defence), the process handle."""
        completed: list[CleanupAction] = []
        failures: list[CleanupFailure] = []
        if close_stdout:
            with suppress(OSError, ValueError):
                self._stdout.close()
        if close_stderr:
            with suppress(OSError, ValueError):
                self._stderr.close()
        if close_stdout and close_stderr:
            completed.append(CleanupAction.PIPES_CLOSED)
        else:
            failures.append(
                CleanupFailure(
                    action=CleanupAction.PIPES_CLOSED, reason="reader_alive:0"
                )
            )
        tree_failure = self._verify_tree_dead()
        if tree_failure is None:
            completed.append(CleanupAction.TREE_VERIFIED_DEAD)
        else:
            failures.append(tree_failure)
        if self._exit_code is None and self._process_handle_open:
            # Memoize a reaped exit while the handle is still open, so the Popen
            # object learns it too and a later wait needs no handle.
            with suppress(WindowsApiError):
                self.wait(0.0)
        job_failure = self._close_owned_handle(
            CleanupAction.JOB_CLOSED, self.job_handle, self._job_handle_open
        )
        self._job_handle_open = False
        if job_failure is None:
            completed.append(CleanupAction.JOB_CLOSED)
        else:
            failures.append(job_failure)
        process_failure = self._close_owned_handle(
            CleanupAction.PROCESS_HANDLE_CLOSED,
            self.process_handle,
            self._process_handle_open,
        )
        self._process_handle_open = False
        if process_failure is None:
            completed.append(CleanupAction.PROCESS_HANDLE_CLOSED)
        else:
            failures.append(process_failure)
        return CleanupReport(completed=tuple(completed), failures=tuple(failures))


# --- The controller (plan 3.4, 8.1-8.3) -----------------------------------------------


def _abandon_suspended(popen: subprocess.Popen[bytes]) -> None:
    """Plan 8.2: a launch that fails after ``Popen`` never leaves a suspended child --
    terminate through the ``Popen`` handle, wait within the bound, close both pipes."""
    with suppress(OSError):
        popen.terminate()
    with suppress(subprocess.TimeoutExpired, OSError):
        popen.wait(timeout=POST_TERMINATION_WAIT_SECONDS)
    for stream in (popen.stdout, popen.stderr):
        if stream is not None:
            with suppress(OSError, ValueError):
                stream.close()


def _popen_failure(error: OSError) -> LaunchFailure:
    winerror = _winerror_of(error)
    if isinstance(winerror, int):
        return LaunchFailure(
            stage="popen",
            os_error_code=winerror,
            error_class=type(error).__name__,
            not_found=winerror in _NOT_FOUND_WINERRORS,
        )
    return LaunchFailure(
        stage="popen", error_class=type(error).__name__, not_found=False
    )


def _open_failure(error: WindowsApiError) -> LaunchFailure:
    return LaunchFailure(
        stage="open_process",
        os_error_code=error.winerror,
        error_class=error.function,
        not_found=False,
    )


class WindowsProcessController:
    """Process creation, identity, Job Objects and tree termination (plan 3.4, 8).

    ``job_object_factory`` creates the kill-on-close job of one launch (default: the
    real ``windows_api`` call); a failing factory forces the job-unavailable branch with
    a real child (plan 8.2 step 3). The controller holds no handle of its own: every
    handle it opens belongs to the ``WindowsLaunchedProcess`` it returns or is closed
    before the call returns.
    """

    def __init__(
        self,
        *,
        job_object_factory: Callable[[], int] = windows_api.create_kill_on_close_job,
    ) -> None:
        if not callable(job_object_factory):
            raise TypeError("job_object_factory must be callable")
        self._job_object_factory = job_object_factory

    def launch(
        self, specification: LaunchSpecification
    ) -> WindowsLaunchedProcess | LaunchFailure:
        """Plan 8.2: suspended ``Popen``; own the child; identity and image; job;
        resume."""
        if not isinstance(specification, LaunchSpecification):
            raise TypeError("specification must be a LaunchSpecification")
        argv = specification.argv
        try:
            popen = subprocess.Popen(  # noqa: S603 - reviewed fixed catalog executable boundary
                list(argv),
                shell=False,
                env={},
                cwd=specification.cwd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                close_fds=True,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED,
            )
        except OSError as error:
            return _popen_failure(error)
        try:
            return self._own_assign_and_resume(popen)
        except BaseException:
            # A defect after the creation (an injected factory raising something other
            # than an OSError, for instance) still surfaces, but never leaves a
            # suspended child behind (plan 8.2).
            _abandon_suspended(popen)
            raise

    def _own_assign_and_resume(
        self, popen: subprocess.Popen[bytes]
    ) -> WindowsLaunchedProcess | LaunchFailure:
        """Plan 8.2 steps 2-5 over the still-suspended child."""
        pid = popen.pid
        try:
            process_handle = windows_api.open_process_limited(
                pid, terminate=True, set_quota=True
            )
        except WindowsApiError as error:
            _abandon_suspended(popen)
            return _open_failure(error)
        created_job: int | None = None
        try:
            try:
                creation_100ns = windows_api.process_times(process_handle)
                image_text = windows_api.process_image_path(process_handle)
            except WindowsApiError as error:
                _abandon_suspended(popen)
                _close_quietly(process_handle)
                return _open_failure(error)
            image_path: ExecutablePath | MISSING  # type: ignore[valid-type]
            try:
                image_path = _IMAGE_PATH.validate_python(image_text)
            except ValidationError:
                image_path = MISSING
            job_handle: int | None = None
            job_error_code: int | MISSING = MISSING  # type: ignore[valid-type]
            try:
                job = self._job_object_factory()
            except OSError as error:
                job_error_code = _winerror_of(error)
            else:
                created_job = job
                try:
                    windows_api.assign_to_job(job, process_handle)
                except WindowsApiError as error:
                    job_error_code = error.winerror
                    _close_quietly(job)
                    created_job = None
                else:
                    job_handle = job
            try:
                windows_api.resume_initial_thread(pid)
            except WindowsApiError as error:
                _abandon_suspended(popen)
                if job_handle is not None:
                    _close_quietly(job_handle)
                _close_quietly(process_handle)
                return LaunchFailure(
                    stage="resume",
                    os_error_code=error.winerror,
                    error_class=error.function,
                    not_found=False,
                )
            return WindowsLaunchedProcess(
                popen=popen,
                process_handle=process_handle,
                job_handle=job_handle,
                job_error_code=job_error_code,
                creation_100ns=creation_100ns,
                image_path=image_path,
            )
        except BaseException:
            # A defect (not a Win32 failure, which the branches above report): close
            # what this call opened before the caller terminates the child.
            if isinstance(created_job, int):
                _close_quietly(created_job)
            _close_quietly(process_handle)
            raise

    def inspect(self, identity: ProcessIdentity) -> ProcessInspection:
        """Plan 8.1: matching, reused, absent or undetermined; instant-free."""
        if not isinstance(identity, ProcessIdentity):
            raise TypeError("identity must be a ProcessIdentity")
        parsed = _parsed(identity)
        if parsed is None:
            return ProcessInspection(
                identity=identity, presence=ProcessPresence.UNDETERMINED
            )
        presence, observed, image_path = _inspect_pid(parsed.pid, parsed.creation_100ns)
        if observed is None:
            return ProcessInspection(identity=identity, presence=presence)
        return ProcessInspection(
            identity=identity,
            presence=presence,
            observed_creation_identity=render_creation_identity(parsed.pid, observed),
            observed_image_path=image_path,
        )

    def terminate_tree(
        self, identity: ProcessIdentity, exit_code: int
    ) -> TerminationReport:
        """Plan 8.1 and 8.5: the reconciler's entry; the root's creation time is
        verified on the opened handle before anything is killed; no job is available."""
        if not isinstance(identity, ProcessIdentity):
            raise TypeError("identity must be a ProcessIdentity")
        _require_exit_code(exit_code)
        parsed = _parsed(identity)
        if parsed is None:
            return _empty_report()
        try:
            handle = windows_api.open_process_limited(parsed.pid, terminate=True)
        except WindowsApiError as error:
            if error.winerror == _ERROR_INVALID_PARAMETER:
                return _empty_report()
            return _empty_report((_tree_failure("open_failed", error.winerror),))
        try:
            try:
                creation_100ns = windows_api.process_times(handle)
                signaled = windows_api.wait_for_handle(handle, 0.0)
            except WindowsApiError as error:
                return _empty_report((_tree_failure("open_failed", error.winerror),))
            if signaled or creation_100ns != parsed.creation_100ns:
                return _empty_report()
            return _terminate_tree(
                root_pid=parsed.pid,
                root_creation_100ns=creation_100ns,
                root_handle=handle,
                job_handle=None,
                exit_code=exit_code,
            )
        finally:
            _close_quietly(handle)
