"""Explicitly constructed local runtime services for the CLI composition root.

Stage 10 plan Task 1 (decisions D03 and D04; Matrix B rows B04, B05, B09 and B19).
The composition root constructs these services on purpose; importing this module
reads no clock, draws no entropy, binds no native library and registers no signal
handler. Every such action happens on a call:

- ``RuntimeClock`` reads the aware UTC wall clock and the process-local monotonic
  clock at call time; injected sources replace both in unit tests. The wall-clock
  read in ``_system_utc_now`` is the one ambient read the Stage 5 guard licenses.
- ``RuntimeIdentitySource`` draws entropy-backed canonical UUID4 identifiers, the
  ``audit_`` identifiers ``AuditEventIds`` describes and transient attempt tokens in
  the existing 64-character lowercase hexadecimal form, each validated before it is
  returned and drawn only when requested.
- ``install_cancellation_bridge`` maps ``SIGINT`` and ``SIGBREAK`` to an idempotent
  request on the existing ``ThreadSafeCancellationToken`` for the duration of one
  scope, returns at once from a handler nested inside an earlier one, and restores
  the previous handlers on every exit.
- ``acquire_dispatch_owner`` and ``release_dispatch_owner`` hold a named Windows
  mutex keyed by the database file's physical identity (volume serial and file
  index), so aliases of one database contend and distinct databases do not. The
  kernel releases the mutex when its owning thread or process ends; the next owner
  then observes abandonment, which demands reconciliation before any scheduling and
  carries no process identity to adopt. A Windows mutex is recursive for its owning
  thread, so a composition acquires one database once per process.
- ``probe_storage`` checks the two explicit run-storage roots without creating,
  discovering or redirecting anything: absolute local spellings, existing
  directories, no reparse point, physical identity equal to the lexical path, a
  fixed NTFS volume, and one volume for both roots (specification 22.5).

``kernel32`` is bound here, at call time, by ``_kernel32``; the Windows process
controller's own bindings are neither reused nor extended. A failed acquisition
closes the handle it opened, and a release closes its handle even when the kernel
refuses the release.
"""

from __future__ import annotations

import ctypes
import secrets
import signal
import time
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from ctypes import wintypes
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path, PureWindowsPath
from typing import Any, Final, Protocol
from uuid import UUID

from crypto_lab.audit.sink import AuditEventIds
from crypto_lab.domain.identifiers import (
    AttemptToken,
    AuditEventId,
    ExperimentId,
    InvocationId,
    LogicalSlotId,
    RunId,
    validate_prefixed_uuid4,
)
from crypto_lab.domain.ports import CancellationToken
from crypto_lab.domain.time import MonotonicInstant, require_utc
from crypto_lab.process_supervision.cancellation import ThreadSafeCancellationToken

__all__ = [
    "DispatchOwner",
    "DispatchOwnerState",
    "DispatchRefusal",
    "DispatchRefusalReason",
    "DispatchRelease",
    "RuntimeClock",
    "RuntimeIdentitySource",
    "RuntimeServices",
    "RuntimeWindowsError",
    "StorageProbe",
    "StorageRefusal",
    "StorageRefusalReason",
    "VolumeInspector",
    "acquire_dispatch_owner",
    "create_runtime_services",
    "install_cancellation_bridge",
    "probe_storage",
    "release_dispatch_owner",
]

#: Entropy per drawn UUID and per transient attempt token, in bytes.
_UUID_BYTES: Final = 16
_ATTEMPT_TOKEN_BYTES: Final = 32
_SUPERVISOR_INSTANCE_PREFIX: Final = "supervisor-"
#: The console signals the cancellation bridge maps to a cancellation request.
_CANCELLATION_SIGNALS: Final = (signal.SIGINT, signal.SIGBREAK)
#: Win32 constants, spelled locally.
_WAIT_OBJECT_0: Final = 0x00000000
_WAIT_ABANDONED: Final = 0x00000080
_WAIT_TIMEOUT: Final = 0x00000102
_DRIVE_REMOTE: Final = 4
_DRIVE_FIXED: Final = 3
_FILE_ATTRIBUTE_DIRECTORY: Final = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT: Final = 0x00000400
_VOLUME_PATH_CHARACTERS: Final = 32768
_FILESYSTEM_NAME_CHARACTERS: Final = 261
_SUPPORTED_FILESYSTEM: Final = "NTFS"
#: Session-independent, so every dispatcher of one database contends.
_MUTEX_NAMESPACE: Final = "Global\\crypto_lab.dispatch."
_UNSAFE_DRIVE_PREFIXES: Final = ("\\\\?\\", "\\\\.\\")
_REMOTE_DRIVE_PREFIX: Final = "\\\\"


class RuntimeWindowsError(OSError):
    """One failed kernel32 call: the API name and the numeric ``GetLastError()``."""

    def __init__(self, function: str, winerror: int) -> None:
        super().__init__(winerror, f"{function} failed", None, winerror)
        self.function = function

    def __str__(self) -> str:
        return f"{self.function} failed"


def _kernel32() -> ctypes.WinDLL:
    """Bind the kernel32 functions used here, on every call and never at import."""
    library = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = wintypes.HANDLE
    dword = wintypes.DWORD
    bool_ = wintypes.BOOL
    library.CreateMutexW.argtypes = [wintypes.LPVOID, bool_, wintypes.LPCWSTR]
    library.CreateMutexW.restype = handle
    library.WaitForSingleObject.argtypes = [handle, dword]
    library.WaitForSingleObject.restype = dword
    library.ReleaseMutex.argtypes = [handle]
    library.ReleaseMutex.restype = bool_
    library.CloseHandle.argtypes = [handle]
    library.CloseHandle.restype = bool_
    library.GetVolumePathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, dword]
    library.GetVolumePathNameW.restype = bool_
    library.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    library.GetDriveTypeW.restype = wintypes.UINT
    library.GetVolumeInformationW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        dword,
        wintypes.LPDWORD,
        wintypes.LPDWORD,
        wintypes.LPDWORD,
        wintypes.LPWSTR,
        dword,
    ]
    library.GetVolumeInformationW.restype = bool_
    return library


def _last_error() -> int:
    return int(ctypes.get_last_error())


# --------------------------------------------------------------------------
# Clocks and identities (D03)
# --------------------------------------------------------------------------


def _system_utc_now() -> datetime:
    """The licensed ambient wall-clock read: aware UTC, read on each call."""
    return datetime.now(UTC)


class RuntimeClock:
    """A ``Clock``: the aware UTC wall clock and the process monotonic clock."""

    __slots__ = ("_monotonic_seconds", "_wall")

    def __init__(
        self,
        *,
        wall: Callable[[], datetime] = _system_utc_now,
        monotonic_seconds: Callable[[], float] = time.monotonic,
    ) -> None:
        self._wall = wall
        self._monotonic_seconds = monotonic_seconds

    def now_utc(self) -> datetime:
        reading: object = self._wall()
        if not isinstance(reading, datetime):
            raise TypeError("the wall clock must return a datetime")
        return require_utc(reading)

    def monotonic(self) -> MonotonicInstant:
        return MonotonicInstant(self._monotonic_seconds())


class RuntimeIdentitySource:
    """An ``IdentitySource`` and ``AuditEventIds`` over an entropy source."""

    __slots__ = ("_entropy",)

    def __init__(
        self, *, entropy: Callable[[int], bytes] = secrets.token_bytes
    ) -> None:
        self._entropy = entropy

    def _draw(self, count: int) -> bytes:
        drawn: object = self._entropy(count)
        if type(drawn) is not bytes or len(drawn) != count:
            raise ValueError(f"the entropy source must return exactly {count} bytes")
        return drawn

    def _uuid4(self) -> str:
        return str(UUID(bytes=self._draw(_UUID_BYTES), version=4))

    def _prefixed(self, prefix: str) -> str:
        return validate_prefixed_uuid4(f"{prefix}{self._uuid4()}", prefix)

    def new_experiment_id(self) -> ExperimentId:
        return self._prefixed("exp_")

    def new_run_id(self) -> RunId:
        return self._prefixed("run_")

    def new_invocation_id(self) -> InvocationId:
        return self._prefixed("inv_")

    def new_logical_slot_id(self) -> LogicalSlotId:
        return self._prefixed("slot_")

    def new_audit_event_id(self) -> AuditEventId:
        return self._prefixed("audit_")

    def new_attempt_token(self) -> AttemptToken:
        """Transient sensitive material: hash it before it reaches any record."""
        return self._draw(_ATTEMPT_TOKEN_BYTES).hex()

    def new_supervisor_instance_id(self) -> str:
        """A fresh identity for this process's supervisor; restart draws another."""
        return f"{_SUPERVISOR_INSTANCE_PREFIX}{self._uuid4()}"


# --------------------------------------------------------------------------
# Scoped cancellation (D04)
# --------------------------------------------------------------------------


@contextmanager
def install_cancellation_bridge(
    token: CancellationToken,
    *,
    signals: tuple[signal.Signals, ...] = _CANCELLATION_SIGNALS,
) -> Iterator[CancellationToken]:
    """Map each console signal to ``token.request_cancellation()`` for one scope.

    Python runs signal handlers on the main thread only, between bytecodes, so a
    second signal can run this scope's handler inside an earlier invocation of it --
    including inside the token's own request, where the request holds the token's
    non-reentrant condition lock: after acquiring it and before setting the flag, or
    while it notifies with the flag set. The handler-reentry guarantee: a nested
    invocation of this scope's handler, for either signal, returns at once without
    calling the token while an outer invocation is in progress, so it never
    requests a lock its own thread holds. A closure-local in-progress flag gives
    that guarantee; it is set before either token method is called and cleared in a
    ``finally``, so a request that raises does not disable later signals. Outside an
    invocation, a signal reads the token's state first and requests only while
    cancellation is clear, so a signal handled once cancellation is set is a no-op.
    The guarantee covers this handler only: it does not make a request that other
    main-thread code makes directly on the token safe against a signal handled
    during that request.

    Installation must happen on the main thread (``signal.signal`` refuses
    elsewhere); a failure part way through restores what was installed, and leaving
    the scope by any route restores every previous handler.
    """
    in_progress = False

    def request(signum: int, frame: object) -> None:
        nonlocal in_progress
        del signum, frame
        if in_progress:
            return
        in_progress = True
        try:
            if not token.is_cancellation_requested():
                token.request_cancellation()
        finally:
            in_progress = False

    previous: list[tuple[signal.Signals, Any]] = []
    try:
        for signum in signals:
            prior = signal.getsignal(signum)
            signal.signal(signum, request)
            previous.append((signum, prior))
        yield token
    finally:
        for signum, prior in reversed(previous):
            signal.signal(signum, signal.SIG_DFL if prior is None else prior)


@dataclass(frozen=True, slots=True, kw_only=True)
class RuntimeServices:
    """The explicitly constructed runtime facilities of one CLI process (B04)."""

    clock: RuntimeClock
    identities: RuntimeIdentitySource
    cancellation: ThreadSafeCancellationToken

    @property
    def audit_event_ids(self) -> AuditEventIds:
        return self.identities

    def cancellation_scope(self) -> AbstractContextManager[CancellationToken]:
        """The scoped signal bridge over this process's own cancellation token."""
        return install_cancellation_bridge(self.cancellation)


def create_runtime_services(
    *,
    wall: Callable[[], datetime] = _system_utc_now,
    monotonic_seconds: Callable[[], float] = time.monotonic,
    entropy: Callable[[int], bytes] = secrets.token_bytes,
) -> RuntimeServices:
    """Construct the runtime services; nothing is read, drawn or installed here."""
    return RuntimeServices(
        clock=RuntimeClock(wall=wall, monotonic_seconds=monotonic_seconds),
        identities=RuntimeIdentitySource(entropy=entropy),
        cancellation=ThreadSafeCancellationToken(),
    )


# --------------------------------------------------------------------------
# Dispatch ownership (D04)
# --------------------------------------------------------------------------


class DispatchOwnerState(StrEnum):
    """How the dispatch mutex was obtained."""

    ACQUIRED = "ACQUIRED"
    ABANDONED = "ABANDONED"


class DispatchRefusalReason(StrEnum):
    """Why dispatch ownership was not obtained."""

    CONTENDED = "CONTENDED"
    DATABASE_UNAVAILABLE = "DATABASE_UNAVAILABLE"
    UNSAFE_PATH = "UNSAFE_PATH"
    OWNERSHIP_FAILED = "OWNERSHIP_FAILED"


class DispatchRelease(StrEnum):
    """What releasing an owner did; its handle is closed in every case but the last."""

    RELEASED = "RELEASED"
    CLOSED_WITHOUT_RELEASE = "CLOSED_WITHOUT_RELEASE"
    ALREADY_RELEASED = "ALREADY_RELEASED"


@dataclass(frozen=True, slots=True)
class DispatchRefusal:
    """A stable refusal; ``winerror`` is the numeric kernel code when one applies."""

    reason: DispatchRefusalReason
    winerror: int | None = None


class DispatchOwner:
    """The process's ownership of one database's dispatch mutex.

    ``reconciliation_required`` is true after abandonment: the previous owner ended
    while holding the mutex, so complete reconciliation precedes any scheduling.
    The owner carries no process identity, path or permit to adopt work with.
    """

    __slots__ = ("_handle", "_identity", "_state")

    def __init__(self, handle: int, identity: str, state: DispatchOwnerState) -> None:
        self._handle: int | None = handle
        self._identity = identity
        self._state = state

    @property
    def identity(self) -> str:
        """The canonical physical identity the mutex is named by."""
        return self._identity

    @property
    def state(self) -> DispatchOwnerState:
        return self._state

    @property
    def reconciliation_required(self) -> bool:
        return self._state is DispatchOwnerState.ABANDONED

    @property
    def released(self) -> bool:
        return self._handle is None


def _drive_refusal(path: PureWindowsPath) -> DispatchRefusalReason | None:
    if path.drive.startswith(_REMOTE_DRIVE_PREFIX) or not path.is_absolute():
        return DispatchRefusalReason.UNSAFE_PATH
    return None


def _database_identity(database_path: Path) -> str | DispatchRefusal:
    """The physical identity of an existing database file, or a refusal."""
    reason = _drive_refusal(PureWindowsPath(database_path))
    if reason is not None:
        return DispatchRefusal(reason)
    try:
        status = database_path.stat()
    except FileNotFoundError:
        return DispatchRefusal(DispatchRefusalReason.DATABASE_UNAVAILABLE)
    except OSError as error:
        return DispatchRefusal(
            DispatchRefusalReason.DATABASE_UNAVAILABLE, winerror=error.winerror
        )
    if status.st_file_attributes & _FILE_ATTRIBUTE_DIRECTORY:
        return DispatchRefusal(DispatchRefusalReason.DATABASE_UNAVAILABLE)
    return f"{status.st_dev:x}.{status.st_ino:x}"


def acquire_dispatch_owner(database_path: Path) -> DispatchOwner | DispatchRefusal:
    """Take the dispatch mutex of ``database_path`` without waiting (B09).

    A held mutex is a ``CONTENDED`` refusal; a failure is ``OWNERSHIP_FAILED`` with
    the kernel code. Every path that does not return an owner closes the handle it
    opened, and an exception after a successful wait releases before closing.
    """
    identity = _database_identity(database_path)
    if isinstance(identity, DispatchRefusal):
        return identity
    kernel32 = _kernel32()
    handle = kernel32.CreateMutexW(None, False, f"{_MUTEX_NAMESPACE}{identity}")
    if not handle:
        return DispatchRefusal(
            DispatchRefusalReason.OWNERSHIP_FAILED, winerror=_last_error()
        )
    owner: DispatchOwner | None = None
    status: int | None = None
    try:
        status = int(kernel32.WaitForSingleObject(handle, 0))
        if status == _WAIT_OBJECT_0:
            owner = DispatchOwner(int(handle), identity, DispatchOwnerState.ACQUIRED)
        elif status == _WAIT_ABANDONED:
            owner = DispatchOwner(int(handle), identity, DispatchOwnerState.ABANDONED)
        elif status == _WAIT_TIMEOUT:
            return DispatchRefusal(DispatchRefusalReason.CONTENDED)
        else:
            return DispatchRefusal(
                DispatchRefusalReason.OWNERSHIP_FAILED, winerror=_last_error()
            )
        return owner
    finally:
        if owner is None:
            if status in (_WAIT_OBJECT_0, _WAIT_ABANDONED):
                kernel32.ReleaseMutex(handle)
            kernel32.CloseHandle(handle)


def release_dispatch_owner(owner: DispatchOwner) -> DispatchRelease:
    """Release the mutex on the owning thread and close its handle (B19).

    The handle leaves the owner only once the kernel32 binding is available, so a
    failed binding propagates with the owner still unreleased and retryable.
    """
    handle = owner._handle
    if handle is None:
        return DispatchRelease.ALREADY_RELEASED
    kernel32 = _kernel32()
    owner._handle = None
    released = False
    try:
        released = bool(kernel32.ReleaseMutex(handle))
    finally:
        kernel32.CloseHandle(handle)
    if released:
        return DispatchRelease.RELEASED
    return DispatchRelease.CLOSED_WITHOUT_RELEASE


# --------------------------------------------------------------------------
# Storage probes (B05; specification 22.5)
# --------------------------------------------------------------------------


class StorageRefusalReason(StrEnum):
    """Why an explicit storage root is unsupported."""

    NOT_ABSOLUTE = "NOT_ABSOLUTE"
    UNSAFE_PATH = "UNSAFE_PATH"
    REMOTE = "REMOTE"
    MISSING = "MISSING"
    NOT_A_DIRECTORY = "NOT_A_DIRECTORY"
    REPARSE_POINT = "REPARSE_POINT"
    PHYSICAL_IDENTITY_MISMATCH = "PHYSICAL_IDENTITY_MISMATCH"
    NOT_FIXED = "NOT_FIXED"
    UNSUPPORTED_FILESYSTEM = "UNSUPPORTED_FILESYSTEM"
    WRONG_VOLUME = "WRONG_VOLUME"
    PROBE_FAILED = "PROBE_FAILED"


@dataclass(frozen=True, slots=True)
class StorageRefusal:
    """The first refused root: its role (``staging`` or ``artifacts``) and reason."""

    role: str
    reason: StorageRefusalReason
    winerror: int | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class StorageProbe:
    """Both run-storage roots accepted, on one fixed NTFS volume."""

    staging_root: Path
    artifact_root: Path
    volume_serial: int
    filesystem: str


class VolumeInspector(Protocol):
    """The volume facts of a root; a failure raises ``RuntimeWindowsError``."""

    def volume_root(self, path: Path) -> str:
        """The mount point of the volume holding ``path``."""

    def drive_type(self, volume_root: str) -> int:
        """The ``GetDriveTypeW`` value of the volume."""

    def volume_identity(self, volume_root: str) -> tuple[int, str]:
        """The volume serial number and the file-system name."""


class _Kernel32Volumes:
    """``VolumeInspector`` over kernel32, bound on each call."""

    def volume_root(self, path: Path) -> str:
        characters = ctypes.create_unicode_buffer(_VOLUME_PATH_CHARACTERS)
        if not _kernel32().GetVolumePathNameW(
            str(path), characters, _VOLUME_PATH_CHARACTERS
        ):
            raise RuntimeWindowsError("GetVolumePathNameW", _last_error())
        return characters.value

    def drive_type(self, volume_root: str) -> int:
        return int(_kernel32().GetDriveTypeW(volume_root))

    def volume_identity(self, volume_root: str) -> tuple[int, str]:
        serial = wintypes.DWORD()
        filesystem = ctypes.create_unicode_buffer(_FILESYSTEM_NAME_CHARACTERS)
        if not _kernel32().GetVolumeInformationW(
            volume_root,
            None,
            0,
            ctypes.byref(serial),
            None,
            None,
            filesystem,
            _FILESYSTEM_NAME_CHARACTERS,
        ):
            raise RuntimeWindowsError("GetVolumeInformationW", _last_error())
        return int(serial.value), filesystem.value


def _lexical_refusal(root: Path) -> StorageRefusalReason | None:
    spelled = PureWindowsPath(root)
    if spelled.drive.startswith(_UNSAFE_DRIVE_PREFIXES):
        return StorageRefusalReason.UNSAFE_PATH
    if spelled.drive.startswith(_REMOTE_DRIVE_PREFIX):
        return StorageRefusalReason.REMOTE
    if not spelled.is_absolute():
        return StorageRefusalReason.NOT_ABSOLUTE
    if any(part in (".", "..") for part in spelled.parts):
        return StorageRefusalReason.UNSAFE_PATH
    return None


def _probe_root(
    role: str, root: Path, inspector: VolumeInspector
) -> tuple[int, str] | StorageRefusal:
    """The volume serial and file system of one accepted root, or its refusal."""
    lexical = _lexical_refusal(root)
    if lexical is not None:
        return StorageRefusal(role, lexical)
    try:
        status = root.lstat()
    except FileNotFoundError:
        return StorageRefusal(role, StorageRefusalReason.MISSING)
    except OSError as error:
        return StorageRefusal(role, StorageRefusalReason.PROBE_FAILED, error.winerror)
    if status.st_file_attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        return StorageRefusal(role, StorageRefusalReason.REPARSE_POINT)
    if not status.st_file_attributes & _FILE_ATTRIBUTE_DIRECTORY:
        return StorageRefusal(role, StorageRefusalReason.NOT_A_DIRECTORY)
    try:
        physical = root.resolve(strict=True)
        volume_root = inspector.volume_root(root)
        drive_type = inspector.drive_type(volume_root)
        serial, filesystem = inspector.volume_identity(volume_root)
    except OSError as error:
        return StorageRefusal(role, StorageRefusalReason.PROBE_FAILED, error.winerror)
    if str(physical).casefold() != str(root).casefold():
        return StorageRefusal(role, StorageRefusalReason.PHYSICAL_IDENTITY_MISMATCH)
    if drive_type == _DRIVE_REMOTE:
        return StorageRefusal(role, StorageRefusalReason.REMOTE)
    if drive_type != _DRIVE_FIXED:
        return StorageRefusal(role, StorageRefusalReason.NOT_FIXED)
    if filesystem != _SUPPORTED_FILESYSTEM:
        return StorageRefusal(role, StorageRefusalReason.UNSUPPORTED_FILESYSTEM)
    return serial, filesystem


def probe_storage(
    *,
    staging_root: Path,
    artifact_root: Path,
    inspector: VolumeInspector | None = None,
) -> StorageProbe | StorageRefusal:
    """Probe the explicit staging and artifact roots before any layout exists.

    Only the two given roots are examined; nothing is created, discovered or
    substituted. The first refusal is returned, staging before artifacts.
    """
    volumes: VolumeInspector = _Kernel32Volumes() if inspector is None else inspector
    staging = _probe_root("staging", staging_root, volumes)
    if isinstance(staging, StorageRefusal):
        return staging
    artifacts = _probe_root("artifacts", artifact_root, volumes)
    if isinstance(artifacts, StorageRefusal):
        return artifacts
    if artifacts[0] != staging[0]:
        return StorageRefusal("artifacts", StorageRefusalReason.WRONG_VOLUME)
    return StorageProbe(
        staging_root=staging_root,
        artifact_root=artifact_root,
        volume_serial=staging[0],
        filesystem=staging[1],
    )
