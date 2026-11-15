"""Stage 10 plan Task 1 (U1): the explicitly constructed CLI runtime services.

The initial RED of every selector here is the missing ``crypto_lab.cli.runtime``
module. Each test then pins one Task 1 obligation: call-time UTC and monotonic
readings; entropy-backed identifiers and attempt tokens drawn only on request;
construction without import-time initialization, proved by a fresh-import probe that
the real sources pass and planted eager modules fail; named-mutex dispatch ownership
keyed by physical database identity; abandonment that requires reconciliation; the
scoped signal-to-cancellation bridge, which a signal handled anywhere inside the
token's own request -- after its condition lock is acquired and before the flag is
set, or while it notifies -- never reenters; and the storage probe's refusals.

A Windows mutex belongs to the thread that acquired it, so the in-process contention
and abandonment cases use a second thread; cross-process owner death is Task 7's.
"""

from __future__ import annotations

import _winapi
import builtins
import ctypes
import importlib.util
import re
import signal
import sys
import threading
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from ctypes import wintypes
from datetime import UTC, date, datetime, timedelta, timezone, tzinfo
from functools import partial
from pathlib import Path
from typing import Final, NoReturn
from uuid import UUID

import pytest
from pydantic import TypeAdapter

from crypto_lab.audit.sink import AuditEventIds
from crypto_lab.cli import runtime as runtime_module
from crypto_lab.cli.runtime import (
    DispatchOwner,
    DispatchOwnerState,
    DispatchRefusal,
    DispatchRefusalReason,
    DispatchRelease,
    RuntimeClock,
    RuntimeIdentitySource,
    RuntimeWindowsError,
    StorageProbe,
    StorageRefusal,
    StorageRefusalReason,
    acquire_dispatch_owner,
    create_runtime_services,
    install_cancellation_bridge,
    probe_storage,
    release_dispatch_owner,
)
from crypto_lab.domain.identifiers import (
    AttemptToken,
    AuditEventId,
    ExperimentId,
    InvocationId,
    LogicalSlotId,
    RunId,
)
from crypto_lab.domain.ports import CancellationToken, Clock, IdentitySource
from crypto_lab.domain.time import MonotonicInstant
from crypto_lab.experiments import application_ports as application_ports_module
from crypto_lab.process_supervision.cancellation import ThreadSafeCancellationToken

_INSTANT: Final = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)
_RESULT_TIMEOUT_SECONDS: Final = 30.0
_DRIVE_FIXED: Final = 3
_DRIVE_REMOTE: Final = 4
_DRIVE_REMOVABLE: Final = 2
_SYNCHRONIZE: Final = 0x00100000
_WAIT_OBJECT_0: Final = 0x00000000
_WAIT_TIMEOUT: Final = 0x00000102
_WAIT_FAILED: Final = 0xFFFFFFFF
_ERROR_NOT_OWNER: Final = 288
_FAKE_HANDLE: Final = 0x1234


# --------------------------------------------------------------------------
# The fresh-import probe: guarded imports whose ambient members are sentinels
# --------------------------------------------------------------------------


class _EagerInitialization(AssertionError):
    """A probe sentinel fired: the module did real work while it was imported."""


class _Sentinel:
    """A guarded member: calling it, or reading through it, is eager work."""

    def __init__(self, qualified_name: str, category: str) -> None:
        self._qualified_name = qualified_name
        self._category = category

    def __call__(self, *args: object, **kwargs: object) -> NoReturn:
        del args, kwargs
        raise _EagerInitialization(f"{self._category} {self._qualified_name}")

    def __getattr__(self, name: str) -> NoReturn:
        raise _EagerInitialization(f"{self._category} {self._qualified_name}.{name}")


class _ProbeDateTime(datetime):
    @classmethod
    def now(cls, tz: tzinfo | None = None) -> NoReturn:
        del tz
        raise _EagerInitialization("clock datetime.datetime.now")

    @classmethod
    def utcnow(cls) -> NoReturn:
        raise _EagerInitialization("clock datetime.datetime.utcnow")

    @classmethod
    def today(cls) -> NoReturn:
        raise _EagerInitialization("clock datetime.datetime.today")


class _ProbeDate(date):
    @classmethod
    def today(cls) -> NoReturn:
        raise _EagerInitialization("clock datetime.date.today")


_CLOCK: Final = "clock"
_ENTROPY: Final = "entropy"
_NATIVE: Final = "native"
_SIGNAL: Final = "signal"
#: The members of each guarded module that read a clock, draw entropy, bind a native
#: library or register a signal handler; every other member is the real one.
_GUARDED_MEMBERS: Final[Mapping[str, Mapping[str, str]]] = {
    "time": dict.fromkeys(
        (
            "time",
            "time_ns",
            "monotonic",
            "monotonic_ns",
            "perf_counter",
            "perf_counter_ns",
            "process_time",
            "process_time_ns",
            "thread_time",
            "thread_time_ns",
            "sleep",
        ),
        _CLOCK,
    ),
    "secrets": dict.fromkeys(
        (
            "token_bytes",
            "token_hex",
            "token_urlsafe",
            "randbelow",
            "randbits",
            "choice",
            "SystemRandom",
        ),
        _ENTROPY,
    ),
    "random": dict.fromkeys(
        (
            "random",
            "randint",
            "randrange",
            "randbytes",
            "getrandbits",
            "choice",
            "choices",
            "shuffle",
            "sample",
            "uniform",
            "seed",
            "Random",
            "SystemRandom",
        ),
        _ENTROPY,
    ),
    "uuid": dict.fromkeys(("uuid1", "uuid4"), _ENTROPY),
    "os": dict.fromkeys(("urandom",), _ENTROPY),
    "ctypes": dict.fromkeys(
        ("WinDLL", "CDLL", "OleDLL", "PyDLL", "windll", "cdll", "oledll", "pydll"),
        _NATIVE,
    ),
    "signal": dict.fromkeys(("signal", "set_wakeup_fd", "raise_signal"), _SIGNAL),
}
_GUARDED_ROOTS: Final = frozenset({"datetime", *_GUARDED_MEMBERS})
_REAL_IMPORT: Final = builtins.__import__
_PROBE_MODULE_NAME: Final = "_stage10_fresh_import_probe"


class _GuardedModule:
    """A module stand-in: guarded members are sentinels, the rest is the module."""

    def __init__(self, module: object, guarded: Mapping[str, object]) -> None:
        self._module = module
        self._guarded = guarded

    def __getattr__(self, name: str) -> object:
        if name in self._guarded:
            return self._guarded[name]
        return getattr(self._module, name)


def _guarded(module_name: str, module: object) -> _GuardedModule:
    if module_name == "datetime":
        return _GuardedModule(module, {"datetime": _ProbeDateTime, "date": _ProbeDate})
    members = _GUARDED_MEMBERS[module_name]
    return _GuardedModule(
        module,
        {
            name: _Sentinel(f"{module_name}.{name}", category)
            for name, category in members.items()
        },
    )


def _guarded_import(
    name: str,
    globals_: Mapping[str, object] | None = None,
    locals_: Mapping[str, object] | None = None,
    fromlist: Sequence[str] = (),
    level: int = 0,
) -> object:
    module = _REAL_IMPORT(name, globals_, locals_, fromlist, level)
    module_name = getattr(module, "__name__", None)
    if level == 0 and isinstance(module_name, str) and module_name in _GUARDED_ROOTS:
        return _guarded(module_name, module)
    return module


def _fresh_import_side_effects(source: str, label: str) -> list[str]:
    """Execute ``source`` as a fresh module whose guarded imports are sentinels.

    The same probe runs the real module sources and the planted eager controls, so
    a planted clock read, entropy draw, native binding or signal registration fails
    exactly where the real modules pass.
    """
    spec = importlib.util.spec_from_loader(_PROBE_MODULE_NAME, loader=None)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    namespace_builtins = dict(vars(builtins))
    namespace_builtins["__import__"] = _guarded_import
    module.__dict__["__builtins__"] = namespace_builtins
    assert _PROBE_MODULE_NAME not in sys.modules
    sys.modules[_PROBE_MODULE_NAME] = module
    try:
        code = compile(source, label, "exec", dont_inherit=True)
        exec(code, module.__dict__)  # noqa: S102 - the probe runs reviewed source text
    except _EagerInitialization as fired:
        return [f"{label}: {fired}"]
    finally:
        del sys.modules[_PROBE_MODULE_NAME]
    return []


def _module_source(module: object) -> str:
    path = getattr(module, "__file__", None)
    assert isinstance(path, str)
    return Path(path).read_text(encoding="utf-8")


#: Planted eager modules, each with the category the probe must report.
_PLANTED_EAGER_MODULES: Final[tuple[tuple[str, str], ...]] = (
    ("from datetime import UTC, datetime\nSTARTED_AT = datetime.now(UTC)\n", _CLOCK),
    ("import datetime\nTODAY = datetime.date.today()\n", _CLOCK),
    ("from time import monotonic\nSTARTED = monotonic()\n", _CLOCK),
    ("import secrets\nSEED = secrets.token_bytes(16)\n", _ENTROPY),
    ("import uuid\nIDENTITY = uuid.uuid4()\n", _ENTROPY),
    ("import os\nSEED = os.urandom(16)\n", _ENTROPY),
    (
        "import ctypes\nKERNEL32 = ctypes.WinDLL('kernel32', use_last_error=True)\n",
        _NATIVE,
    ),
    ("import ctypes\nKERNEL32 = ctypes.windll.kernel32\n", _NATIVE),
    ("import signal\nsignal.signal(signal.SIGINT, signal.SIG_IGN)\n", _SIGNAL),
)
#: Planted deferred modules: the same members referenced but never used at import.
_PLANTED_DEFERRED_MODULES: Final[tuple[str, ...]] = (
    "import time\ndef later():\n    return time.monotonic()\n",
    "import secrets\ndef draw(entropy=secrets.token_bytes):\n    return entropy(16)\n",
    "import ctypes\nfrom ctypes import wintypes\nDWORD = wintypes.DWORD\n",
    "import signal\nSIGNALS = (signal.SIGINT, signal.SIGBREAK)\n",
)


# --------------------------------------------------------------------------
# Deterministic doubles
# --------------------------------------------------------------------------


class _CountingWall:
    def __init__(self, value: object) -> None:
        self.calls = 0
        self._value = value

    def __call__(self) -> datetime:
        self.calls += 1
        return self._value  # type: ignore[return-value]


class _CountingMonotonic:
    def __init__(self, value: object) -> None:
        self.calls = 0
        self._value = value

    def __call__(self) -> float:
        self.calls += 1
        return self._value  # type: ignore[return-value]


class _CountingEntropy:
    """Return ``count`` copies of one byte and record every request."""

    def __init__(self, fill: int = 0, *, length_error: int = 0) -> None:
        self.requests: list[int] = []
        self._fill = fill
        self._length_error = length_error

    def __call__(self, count: int) -> bytes:
        self.requests.append(count)
        return bytes([self._fill]) * (count + self._length_error)


def _bytearray_entropy(count: int) -> bytes:
    return bytearray(count)  # type: ignore[return-value]  # the refused draw type


# --------------------------------------------------------------------------
# U1: clocks and identities
# --------------------------------------------------------------------------


def test_runtime_clock_is_utc() -> None:
    services = create_runtime_services()
    clock = services.clock
    assert isinstance(clock, Clock)
    before = datetime.now(UTC)
    reading = clock.now_utc()
    after = datetime.now(UTC)
    assert reading.tzinfo is UTC
    assert reading.utcoffset() == timedelta(0)
    assert before <= reading <= after
    first = clock.monotonic()
    second = clock.monotonic()
    assert isinstance(first, MonotonicInstant)
    assert first <= second
    # Call-time: an injected source is read on every call and never at construction.
    wall = _CountingWall(_INSTANT)
    monotonic = _CountingMonotonic(12.5)
    injected = RuntimeClock(wall=wall, monotonic_seconds=monotonic)
    assert (wall.calls, monotonic.calls) == (0, 0)
    assert injected.now_utc() == _INSTANT
    assert injected.now_utc() == _INSTANT
    assert injected.monotonic() == MonotonicInstant(12.5)
    assert (wall.calls, monotonic.calls) == (2, 1)
    # Aware UTC only: naive and offset readings are refused, never coerced.
    naive = datetime(2026, 11, 15, 12, 0)  # noqa: DTZ001 - the refused reading
    offset = datetime(2026, 11, 15, 13, 0, tzinfo=timezone(timedelta(hours=1)))
    for refused in (naive, offset):
        with pytest.raises(ValueError, match="UTC"):
            RuntimeClock(wall=_CountingWall(refused)).now_utc()
    with pytest.raises(TypeError, match="datetime"):
        RuntimeClock(wall=_CountingWall("2026-11-15T12:00:00Z")).now_utc()
    # Valid monotonic values only: finite, non-negative float seconds.
    for refused_seconds in (12, float("nan"), -1.0, float("inf")):
        source = _CountingMonotonic(refused_seconds)
        with pytest.raises(ValueError, match="monotonic instant"):
            RuntimeClock(monotonic_seconds=source).monotonic()


def test_runtime_identities_validate() -> None:
    entropy = _CountingEntropy(0xFF)
    services = create_runtime_services(entropy=entropy)
    identities = services.identities
    assert isinstance(identities, IdentitySource)
    assert isinstance(services.audit_event_ids, AuditEventIds)
    assert services.audit_event_ids is identities
    assert entropy.requests == []  # construction draws nothing
    drawn: dict[str, str] = {
        "experiment": identities.new_experiment_id(),
        "run": identities.new_run_id(),
        "invocation": identities.new_invocation_id(),
        "slot": identities.new_logical_slot_id(),
        "audit": services.audit_event_ids.new_audit_event_id(),
    }
    assert entropy.requests == [16, 16, 16, 16, 16]  # one draw per request
    adapters: dict[str, TypeAdapter[str]] = {
        "experiment": TypeAdapter(ExperimentId),
        "run": TypeAdapter(RunId),
        "invocation": TypeAdapter(InvocationId),
        "slot": TypeAdapter(LogicalSlotId),
        "audit": TypeAdapter(AuditEventId),
    }
    for kind, value in drawn.items():
        assert adapters[kind].validate_python(value) == value, kind
        assert UUID(value.partition("_")[2]).version == 4, kind
    # The version and variant bits are forced over any entropy, all-zero included.
    zero = RuntimeIdentitySource(entropy=_CountingEntropy(0x00))
    assert zero.new_run_id() == "run_00000000-0000-4000-8000-000000000000"
    token = identities.new_attempt_token()
    assert entropy.requests[-1] == 32
    assert TypeAdapter(AttemptToken).validate_python(token) == token
    assert token == "ff" * 32  # the existing 64-character lowercase hexadecimal form
    supervisor = identities.new_supervisor_instance_id()
    assert entropy.requests[-1] == 16
    assert supervisor == "supervisor-ffffffff-ffff-4fff-bfff-ffffffffffff"
    # The real entropy source yields distinct, valid values on every request.
    real = create_runtime_services().identities
    runs = {real.new_run_id() for _ in range(8)}
    assert len(runs) == 8
    for run_id in runs:
        assert TypeAdapter(RunId).validate_python(run_id) == run_id
    tokens = {real.new_attempt_token() for _ in range(8)}
    assert len(tokens) == 8
    for drawn_token in tokens:
        assert re.fullmatch(r"[0-9a-f]{64}", drawn_token) is not None
    # A short, long or non-bytes draw is refused rather than reshaped.
    for faulty in (_CountingEntropy(length_error=-1), _CountingEntropy(length_error=1)):
        with pytest.raises(ValueError, match="entropy"):
            RuntimeIdentitySource(entropy=faulty).new_experiment_id()
    with pytest.raises(ValueError, match="entropy"):
        RuntimeIdentitySource(entropy=_bytearray_entropy).new_attempt_token()


def test_runtime_construction_is_explicit() -> None:
    # The real sources pass the fresh-import probe: nothing is read, drawn, bound or
    # registered while either Task 1 module is imported.
    for label, module in (
        ("cli/runtime.py", runtime_module),
        ("experiments/application_ports.py", application_ports_module),
    ):
        assert _fresh_import_side_effects(_module_source(module), label) == [], label
    # Planted eager modules fail the same probe with the reported category.
    for source, category in _PLANTED_EAGER_MODULES:
        fired = _fresh_import_side_effects(source, "cli/probe.py")
        assert len(fired) == 1, source
        assert fired[0].startswith(f"cli/probe.py: {category} "), (source, fired)
    for source in _PLANTED_DEFERRED_MODULES:
        assert _fresh_import_side_effects(source, "cli/probe.py") == [], source
    # Construction is explicit and still lazy: no clock read, no draw, no handler.
    handlers_before = _handlers()
    wall = _CountingWall(_INSTANT)
    monotonic = _CountingMonotonic(1.0)
    entropy = _CountingEntropy()
    services = create_runtime_services(
        wall=wall, monotonic_seconds=monotonic, entropy=entropy
    )
    assert (wall.calls, monotonic.calls, entropy.requests) == (0, 0, [])
    assert isinstance(services.cancellation, ThreadSafeCancellationToken)
    assert not services.cancellation.is_cancellation_requested()
    assert _handlers() == handlers_before
    assert create_runtime_services().cancellation is not services.cancellation


# --------------------------------------------------------------------------
# U1: dispatch ownership
# --------------------------------------------------------------------------


class _Interrupted(BaseException):
    """A non-``Exception`` interruption raised inside the kernel stand-in."""


def _kernel32() -> ctypes.WinDLL:
    library = ctypes.WinDLL("kernel32", use_last_error=True)
    library.GetCurrentThreadId.argtypes = []
    library.GetCurrentThreadId.restype = wintypes.DWORD
    library.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    library.OpenThread.restype = wintypes.HANDLE
    library.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    library.WaitForSingleObject.restype = wintypes.DWORD
    library.CloseHandle.argtypes = [wintypes.HANDLE]
    library.CloseHandle.restype = wintypes.BOOL
    return library


_CREATED: Final = "CreateMutexW"
_CLOSED: Final = "CloseHandle"
_CLOSE_FAILED: Final = "CloseHandle failed"


class _MutexHandleLedger:
    """Operation-owned accounting of the runtime's dispatch-mutex handles.

    Installed as the runtime's ``_kernel32``, it binds the real kernel32 on every
    call, as the runtime does, and returns a recording proxy over that binding. Only
    the handles the exercised operations create and close are recorded, in call
    order; nothing else in the process is counted.
    """

    def __init__(self, bind: Callable[[], ctypes.WinDLL]) -> None:
        self._bind = bind
        self.events: list[tuple[str, int]] = []
        #: The planted omitted-close control: the next close never reaches the kernel.
        self.omit_next_close = False
        self.omitted: list[int] = []

    def __call__(self) -> _RecordingKernel32:
        return _RecordingKernel32(self, self._bind())


class _RecordingKernel32:
    """Every function delegates to the real binding; creation and closure record."""

    def __init__(self, ledger: _MutexHandleLedger, library: ctypes.WinDLL) -> None:
        self._ledger = ledger
        self._library = library

    def CreateMutexW(self, attributes: object, owner: bool, name: str) -> int | None:
        handle: int | None = self._library.CreateMutexW(attributes, owner, name)
        self._ledger.events.append((_CREATED, int(handle or 0)))
        return handle

    def CloseHandle(self, handle: int) -> int:
        ledger = self._ledger
        if ledger.omit_next_close:
            ledger.omit_next_close = False
            ledger.omitted.append(int(handle))
            return 1
        closed = int(self._library.CloseHandle(handle))
        ledger.events.append((_CLOSED if closed else _CLOSE_FAILED, int(handle)))
        return closed

    def __getattr__(self, name: str) -> object:
        return getattr(self._library, name)


def _install_handle_ledger(monkeypatch: pytest.MonkeyPatch) -> _MutexHandleLedger:
    ledger = _MutexHandleLedger(runtime_module._kernel32)
    monkeypatch.setattr(runtime_module, "_kernel32", ledger)
    return ledger


def _left_open(events: Sequence[tuple[str, int]]) -> set[int]:
    """Replay recorded operations: the handles they created and have not closed.

    A failed creation or close, a live handle created twice, or a close of a handle
    no recorded operation holds fails the replay.
    """
    held: set[int] = set()
    for event, handle in events:
        if event == _CREATED:
            assert handle != 0, "a mutex creation failed"
            assert handle not in held, f"live handle {handle} was created twice"
            held.add(handle)
        else:
            assert event == _CLOSED, f"closing handle {handle} failed"
            assert handle in held, f"handle {handle} closed but never held"
            held.remove(handle)
    return held


def _assert_operation_handles(
    ledger: _MutexHandleLedger,
    *,
    since: int = 0,
    opened: int,
    retained: frozenset[int] = frozenset(),
) -> None:
    """The operations recorded from ``since`` created ``opened`` mutex handles and
    closed each one exactly once, successfully, except the ``retained`` ones."""
    window = ledger.events[since:]
    assert [event for event, _ in window].count(_CREATED) == opened, window
    assert _left_open(window) == retained, f"operation handles left open: {window}"


def _database(directory: Path, name: str = "lab.sqlite3") -> Path:
    path = directory / name
    path.write_bytes(b"")
    return path


def _on(executor: ThreadPoolExecutor, call: Callable[[], object]) -> object:
    return executor.submit(call).result(timeout=_RESULT_TIMEOUT_SECONDS)


def test_dispatch_owner_contention_and_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = _database(tmp_path)
    nested = tmp_path / "nested"
    nested.mkdir()
    hard_link = tmp_path / "hard-link.sqlite3"
    hard_link.hardlink_to(database)
    aliases = (
        database,
        Path(str(database).upper()),
        nested / ".." / database.name,
        hard_link,
    )
    other = _database(tmp_path, "other.sqlite3")
    ledger = _install_handle_ledger(monkeypatch)
    with ThreadPoolExecutor(max_workers=1) as other_thread:
        owner = acquire_dispatch_owner(database)
        assert isinstance(owner, DispatchOwner)
        try:
            assert owner.state is DispatchOwnerState.ACQUIRED
            assert owner.reconciliation_required is False
            assert owner.released is False
            # The deliberately retained handle is the one the acquisition created.
            [(created, owner_handle)] = ledger.events
            assert created == _CREATED
            contenders = len(ledger.events)
            for alias in aliases:
                contended = _on(other_thread, partial(acquire_dispatch_owner, alias))
                assert contended == DispatchRefusal(DispatchRefusalReason.CONTENDED)
            # Every refused contender closed the handle it opened; only the retained
            # owner's handle is still open.
            _assert_operation_handles(ledger, since=contenders, opened=len(aliases))
            _assert_operation_handles(
                ledger, opened=1 + len(aliases), retained=frozenset({owner_handle})
            )
            independent_start = len(ledger.events)
            independent = _on(other_thread, partial(acquire_dispatch_owner, other))
            assert isinstance(independent, DispatchOwner)
            assert independent.state is DispatchOwnerState.ACQUIRED
            assert independent.identity != owner.identity
            released = _on(other_thread, partial(release_dispatch_owner, independent))
            assert released is DispatchRelease.RELEASED
            _assert_operation_handles(ledger, since=independent_start, opened=1)
        finally:
            assert release_dispatch_owner(owner) is DispatchRelease.RELEASED
        assert owner.released is True
        assert release_dispatch_owner(owner) is DispatchRelease.ALREADY_RELEASED
        # The release closed the retained handle: no operation left a handle open.
        _assert_operation_handles(ledger, opened=2 + len(aliases))
        # Once released, every alias acquires the same canonical identity.
        reacquisitions = len(ledger.events)
        for alias in aliases:
            again = _on(other_thread, partial(acquire_dispatch_owner, alias))
            assert isinstance(again, DispatchOwner), alias
            assert again.identity == owner.identity, alias
            assert again.state is DispatchOwnerState.ACQUIRED
            released = _on(other_thread, partial(release_dispatch_owner, again))
            assert released is DispatchRelease.RELEASED
        _assert_operation_handles(ledger, since=reacquisitions, opened=len(aliases))
    exercised = 2 + 2 * len(aliases)
    _assert_operation_handles(ledger, opened=exercised)
    # Refusals before any kernel object: missing, a directory, unsafe spellings.
    absent = tmp_path / "absent.sqlite3"
    assert acquire_dispatch_owner(absent) == DispatchRefusal(
        DispatchRefusalReason.DATABASE_UNAVAILABLE
    )
    assert not absent.exists()
    assert acquire_dispatch_owner(nested) == DispatchRefusal(
        DispatchRefusalReason.DATABASE_UNAVAILABLE
    )
    for unsafe in (Path("lab.sqlite3"), Path(r"\\server\share\lab.sqlite3")):
        assert acquire_dispatch_owner(unsafe) == DispatchRefusal(
            DispatchRefusalReason.UNSAFE_PATH
        )
    _assert_operation_handles(ledger, opened=exercised)


def test_handle_accounting_rejects_an_omitted_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = _database(tmp_path)
    ledger = _install_handle_ledger(monkeypatch)
    owner = acquire_dispatch_owner(database)
    assert isinstance(owner, DispatchOwner)
    try:
        [(created, owner_handle)] = ledger.events
        assert created == _CREATED
        contenders = len(ledger.events)
        with ThreadPoolExecutor(max_workers=1) as other_thread:
            # The planted defect: the refused contender's close never reaches the
            # kernel, so its real handle stays open until the cleanup below.
            ledger.omit_next_close = True
            try:
                contended = _on(other_thread, partial(acquire_dispatch_owner, database))
                assert contended == DispatchRefusal(DispatchRefusalReason.CONTENDED)
                with pytest.raises(AssertionError, match="operation handles left open"):
                    _assert_operation_handles(ledger, since=contenders, opened=1)
            finally:
                ledger.omit_next_close = False
                for planted in ledger.omitted:
                    assert ledger().CloseHandle(planted)
        # The omitted close was the contender's own handle, not the retained owner's;
        # once it is closed the same accounting is satisfied.
        window = ledger.events[contenders:]
        [(created, contender_handle), (closed, planted_handle)] = window
        assert (created, closed) == (_CREATED, _CLOSED)
        assert ledger.omitted == [contender_handle] == [planted_handle]
        assert contender_handle != owner_handle
        _assert_operation_handles(ledger, since=contenders, opened=1)
        _assert_operation_handles(ledger, opened=2, retained=frozenset({owner_handle}))
    finally:
        assert release_dispatch_owner(owner) is DispatchRelease.RELEASED
    _assert_operation_handles(ledger, opened=2)


class _FakeKernel:
    """A recording stand-in for the runtime's call-time kernel32 binding."""

    def __init__(
        self,
        *,
        handle: int = _FAKE_HANDLE,
        wait_status: int = _WAIT_OBJECT_0,
        wait_raises: bool = False,
        release_succeeds: bool = True,
    ) -> None:
        self.calls: list[tuple[str, object]] = []
        self._handle = handle
        self._wait_status = wait_status
        self._wait_raises = wait_raises
        self._release_succeeds = release_succeeds

    def CreateMutexW(self, attributes: object, owner: bool, name: str) -> int:
        del attributes, owner
        self.calls.append(("CreateMutexW", name))
        if not self._handle:
            ctypes.set_last_error(5)
        return self._handle

    def WaitForSingleObject(self, handle: int, milliseconds: int) -> int:
        self.calls.append(("WaitForSingleObject", (handle, milliseconds)))
        if self._wait_raises:
            raise _Interrupted
        if self._wait_status == _WAIT_FAILED:
            ctypes.set_last_error(6)
        return self._wait_status

    def ReleaseMutex(self, handle: int) -> bool:
        self.calls.append(("ReleaseMutex", handle))
        if not self._release_succeeds:
            ctypes.set_last_error(_ERROR_NOT_OWNER)
        return self._release_succeeds

    def CloseHandle(self, handle: int) -> bool:
        self.calls.append(("CloseHandle", handle))
        return True


def test_failed_dispatch_acquisition_closes_its_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = _database(tmp_path)
    for status, reason in (
        (_WAIT_TIMEOUT, DispatchRefusalReason.CONTENDED),
        (_WAIT_FAILED, DispatchRefusalReason.OWNERSHIP_FAILED),
    ):
        kernel = _FakeKernel(wait_status=status)
        monkeypatch.setattr(runtime_module, "_kernel32", partial(_return, kernel))
        refusal = acquire_dispatch_owner(database)
        assert isinstance(refusal, DispatchRefusal)
        assert refusal.reason is reason
        assert kernel.calls[-1] == ("CloseHandle", _FAKE_HANDLE)
        assert ("ReleaseMutex", _FAKE_HANDLE) not in kernel.calls
    # A failed creation has no handle to close and reports the numeric code only.
    kernel = _FakeKernel(handle=0)
    monkeypatch.setattr(runtime_module, "_kernel32", partial(_return, kernel))
    assert acquire_dispatch_owner(database) == DispatchRefusal(
        DispatchRefusalReason.OWNERSHIP_FAILED, winerror=5
    )
    assert [name for name, _ in kernel.calls] == ["CreateMutexW"]
    # The mutex name is keyed by physical identity, never by the spelled path.
    _, mutex_name = kernel.calls[0]
    assert isinstance(mutex_name, str)
    assert mutex_name.startswith("Global\\crypto_lab.dispatch.")
    assert "sqlite3" not in mutex_name
    assert tmp_path.name.casefold() not in mutex_name.casefold()
    # An interruption while waiting still closes the handle and propagates.
    kernel = _FakeKernel(wait_raises=True)
    monkeypatch.setattr(runtime_module, "_kernel32", partial(_return, kernel))
    with pytest.raises(_Interrupted):
        acquire_dispatch_owner(database)
    assert kernel.calls[-1] == ("CloseHandle", _FAKE_HANDLE)
    # A release that the kernel refuses still closes the handle.
    kernel = _FakeKernel(release_succeeds=False)
    monkeypatch.setattr(runtime_module, "_kernel32", partial(_return, kernel))
    owner = acquire_dispatch_owner(database)
    assert isinstance(owner, DispatchOwner)
    assert release_dispatch_owner(owner) is DispatchRelease.CLOSED_WITHOUT_RELEASE
    assert kernel.calls[-2:] == [
        ("ReleaseMutex", _FAKE_HANDLE),
        ("CloseHandle", _FAKE_HANDLE),
    ]
    assert owner.released is True
    assert release_dispatch_owner(owner) is DispatchRelease.ALREADY_RELEASED


def _return(value: object) -> object:
    return value


class _BindingFailed(OSError):
    """The injected failure of the runtime's call-time kernel32 binding."""


def _refuse_binding() -> NoReturn:
    raise _BindingFailed("kernel32 binding refused")


def test_release_binding_failure_keeps_the_owner_unreleased(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = _database(tmp_path)
    for release_succeeds, outcome in (
        (True, DispatchRelease.RELEASED),
        (False, DispatchRelease.CLOSED_WITHOUT_RELEASE),
    ):
        kernel = _FakeKernel(release_succeeds=release_succeeds)
        monkeypatch.setattr(runtime_module, "_kernel32", partial(_return, kernel))
        owner = acquire_dispatch_owner(database)
        assert isinstance(owner, DispatchOwner)
        acquired = len(kernel.calls)
        # The binding fails after acquisition, so the release reaches no kernel call.
        monkeypatch.setattr(runtime_module, "_kernel32", _refuse_binding)
        with pytest.raises(_BindingFailed):
            release_dispatch_owner(owner)
        assert kernel.calls[acquired:] == []
        # The handle is still outstanding, so the owner must still be unreleased.
        assert owner.released is False
        # With the binding available, the retained handle is released once (or its
        # refused release still closes it) and closed exactly once.
        monkeypatch.setattr(runtime_module, "_kernel32", partial(_return, kernel))
        assert release_dispatch_owner(owner) is outcome
        assert kernel.calls[acquired:] == [
            ("ReleaseMutex", _FAKE_HANDLE),
            ("CloseHandle", _FAKE_HANDLE),
        ]
        assert owner.released is True
        assert release_dispatch_owner(owner) is DispatchRelease.ALREADY_RELEASED
        assert len(kernel.calls) == acquired + 2


def test_abandoned_owner_requires_reconciliation(tmp_path: Path) -> None:
    database = _database(tmp_path)
    acquired: list[object] = []
    thread_handles: list[int] = []

    def acquire_then_exit_without_release() -> None:
        library = _kernel32()
        handle = library.OpenThread(_SYNCHRONIZE, False, library.GetCurrentThreadId())
        assert handle
        thread_handles.append(int(handle))
        acquired.append(acquire_dispatch_owner(database))

    worker = threading.Thread(target=acquire_then_exit_without_release)
    worker.start()
    worker.join(timeout=_RESULT_TIMEOUT_SECONDS)
    assert not worker.is_alive()
    (dead_owner,) = acquired
    assert isinstance(dead_owner, DispatchOwner)
    assert dead_owner.state is DispatchOwnerState.ACQUIRED
    (thread_handle,) = thread_handles
    library = _kernel32()
    try:
        # Wait for the operating-system thread itself: its exit abandons the mutex.
        assert library.WaitForSingleObject(thread_handle, 30_000) == _WAIT_OBJECT_0
    finally:
        assert library.CloseHandle(thread_handle)
    owner = acquire_dispatch_owner(database)
    assert isinstance(owner, DispatchOwner)
    try:
        assert owner.state is DispatchOwnerState.ABANDONED
        assert owner.reconciliation_required is True
        assert owner.identity == dead_owner.identity
        # The result is the abandonment fact alone: no PID, previous-owner identity,
        # path or scheduling permit that could authorize adoption.
        assert {name for name in dir(owner) if not name.startswith("_")} == {
            "identity",
            "reconciliation_required",
            "released",
            "state",
        }
    finally:
        assert release_dispatch_owner(owner) is DispatchRelease.RELEASED
    # The dead thread's handle is closed without a release it no longer owns.
    assert release_dispatch_owner(dead_owner) is DispatchRelease.CLOSED_WITHOUT_RELEASE
    fresh = acquire_dispatch_owner(database)
    assert isinstance(fresh, DispatchOwner)
    try:
        assert fresh.state is DispatchOwnerState.ACQUIRED
        assert fresh.reconciliation_required is False
    finally:
        assert release_dispatch_owner(fresh) is DispatchRelease.RELEASED


# --------------------------------------------------------------------------
# U1: the scoped cancellation bridge
# --------------------------------------------------------------------------


_BRIDGED_SIGNALS: Final = (signal.SIGINT, signal.SIGBREAK)


def _handlers() -> dict[int, object]:
    return {signum: signal.getsignal(signum) for signum in _BRIDGED_SIGNALS}


def _invoke_installed(signum: int) -> None:
    handler = signal.getsignal(signum)
    assert callable(handler)
    handler(signum, None)


def _enter_bridge_unexpectedly() -> None:
    with install_cancellation_bridge(ThreadSafeCancellationToken()):
        pytest.fail("the scope must not be entered")


def test_cancellation_bridge_is_scoped(monkeypatch: pytest.MonkeyPatch) -> None:
    before = _handlers()
    token = ThreadSafeCancellationToken()
    with install_cancellation_bridge(token) as bridged:
        assert bridged is token
        installed = _handlers()
        for signum in _BRIDGED_SIGNALS:
            assert installed[signum] is not before[signum]
        assert not token.is_cancellation_requested()
        _invoke_installed(signal.SIGINT)
        assert token.is_cancellation_requested()
        _invoke_installed(signal.SIGBREAK)  # a second request is a no-op
        _invoke_installed(signal.SIGINT)
        assert token.is_cancellation_requested()
    assert _handlers() == before
    # Restoration on an exception leaving the scope; the exception propagates.
    with (
        pytest.raises(LookupError, match="inside"),
        install_cancellation_bridge(ThreadSafeCancellationToken()),
    ):
        raise LookupError("raised inside the scope")
    assert _handlers() == before
    # A failed second installation restores the first and propagates.
    real_signal = signal.signal

    def refuse_second(signum: int, handler: object) -> object:
        if signum == signal.SIGBREAK and handler is not before[signal.SIGBREAK]:
            raise OSError("installation refused")
        return real_signal(signum, handler)  # type: ignore[arg-type]

    monkeypatch.setattr(signal, "signal", refuse_second)
    with pytest.raises(OSError, match="installation refused"):
        _enter_bridge_unexpectedly()
    monkeypatch.undo()
    assert _handlers() == before
    # Off the main thread nothing is installed and the refusal propagates.
    with ThreadPoolExecutor(max_workers=1) as other_thread:
        with pytest.raises(ValueError, match="main thread"):
            _on(other_thread, _enter_bridge_unexpectedly)
    assert _handlers() == before
    # The services bridge reuses the services' own token.
    services = create_runtime_services()
    with services.cancellation_scope() as scoped:
        assert scoped is services.cancellation
        assert isinstance(scoped, CancellationToken)
        _invoke_installed(signal.SIGBREAK)
    assert services.cancellation.is_cancellation_requested()
    assert _handlers() == before


#: The non-reentrant lock type ``threading.Event`` builds its condition over.
_PLAIN_LOCK_TYPE: Final = type(threading.Lock())


class _RecursiveLockRequest(AssertionError):
    """The thread holding the token's condition lock requested it again."""


class _OwnerCheckedLock:
    """The Event's own non-reentrant lock, refusing its owner's blocking request.

    A blocking request by the owning thread can never be granted, so it fails at once
    with a clear assertion instead of deadlocking the test process; every other
    request reaches the real lock unchanged. ``entered`` runs on context entry,
    immediately after the real lock is acquired and before the ``with`` body; if it
    raises, the acquired lock is released before the failure propagates, because the
    ``with`` statement never reaches ``__exit__`` for an ``__enter__`` that raised.
    """

    def __init__(
        self,
        lock: threading.Lock | None,
        *,
        entered: Callable[[_OwnerCheckedLock], object] | None = None,
    ) -> None:
        assert lock is not None
        assert type(lock) is _PLAIN_LOCK_TYPE, f"not a plain Lock: {lock!r}"
        self._lock: threading.Lock = lock
        self._entered = entered
        self._owner: int | None = None
        self.acquisitions = 0

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        if blocking and self._owner == threading.get_ident():
            raise _RecursiveLockRequest(
                "recursive locking request: the thread holding the token's "
                "non-reentrant condition lock requested it again and would deadlock"
            )
        acquired = self._lock.acquire(blocking, timeout)
        if acquired:
            self._owner = threading.get_ident()
            self.acquisitions += 1
        return acquired

    def release(self) -> None:
        self._owner = None
        self._lock.release()

    def held_by_caller(self) -> bool:
        """The calling thread owns the wrapper and the real lock is held."""
        return self._owner == threading.get_ident() and self._lock.locked()

    def locked(self) -> bool:
        """The real lock is held by some thread."""
        return self._lock.locked()

    def __enter__(self) -> bool:
        acquired = self.acquire()
        entered = self._entered
        if entered is not None:
            try:
                entered(self)
            except BaseException:
                self.release()
                raise
        return acquired

    def __exit__(self, *exc_info: object) -> None:
        self.release()


#: The two ``Event.set`` boundaries at which a signal handler can run while the
#: token's request holds its condition lock.
_PRE_FLAG: Final = "pre-flag"
_NOTIFICATION: Final = "notification"
_SIGNAL_PAIRS: Final = (
    (signal.SIGINT, signal.SIGINT),
    (signal.SIGINT, signal.SIGBREAK),
    (signal.SIGBREAK, signal.SIGINT),
    (signal.SIGBREAK, signal.SIGBREAK),
)


class _ReentryProbe:
    """Reenter one real token at a chosen boundary inside its real ``Event.set``.

    ``token()`` builds a real ``ThreadSafeCancellationToken`` while
    ``threading.Condition`` names the probe condition, so the token's Event keeps its
    real flag, ``set`` and non-reentrant lock; the probe only wraps that lock and
    observes. The first delivery runs ``reenter`` where a signal handled at an
    evaluation-breaker check runs its handler, at one of two boundaries:

    - ``pre-flag``: on entry to the condition, immediately after the real lock is
      acquired and before ``Event.set`` assigns its flag, so cancellation still reads
      clear; a ``reenter`` failure there releases the lock before it propagates.
    - ``notification``: the first ``notify_all``, with the condition held and the
      flag already set.
    """

    def __init__(
        self,
        reenter: Callable[[ThreadSafeCancellationToken], object],
        *,
        boundary: str,
    ) -> None:
        assert boundary in (_PRE_FLAG, _NOTIFICATION), boundary
        self._reenter = reenter
        self._boundary = boundary
        self._pending = 1
        self._token: ThreadSafeCancellationToken | None = None
        self.locks: list[_OwnerCheckedLock] = []
        #: The token's own Event, whose condition the probe lock serves.
        self.event: threading.Event | None = None
        #: Per delivery: (the caller holds the condition lock, cancellation is set).
        self.deliveries: list[tuple[bool, bool]] = []

    def token(self) -> ThreadSafeCancellationToken:
        probe = self

        class _ProbeCondition(threading.Condition):
            def __init__(self, lock: threading.Lock | None = None) -> None:
                checked = _OwnerCheckedLock(lock, entered=probe.entered)
                probe.locks.append(checked)
                super().__init__(checked)  # type: ignore[arg-type]
                self.checked = checked

            def notify_all(self) -> None:
                probe.notified(self.checked)
                super().notify_all()

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(threading, "Condition", _ProbeCondition)
            token = ThreadSafeCancellationToken()
        (checked,) = self.locks
        # The probe lock is the token's actual condition lock, not a bystander.
        event = token._event
        condition = vars(event)["_cond"]
        assert isinstance(condition, _ProbeCondition)
        assert condition.checked is checked
        assert vars(condition)["_lock"] is checked
        self.event = event
        self._token = token
        return token

    def entered(self, lock: _OwnerCheckedLock) -> None:
        if self._boundary == _PRE_FLAG:
            self._deliver(lock)

    def notified(self, lock: _OwnerCheckedLock) -> None:
        if self._boundary == _NOTIFICATION:
            self._deliver(lock)

    def _deliver(self, lock: _OwnerCheckedLock) -> None:
        token = self._token
        if token is None or not self._pending:
            return
        self._pending -= 1
        self.deliveries.append(
            (lock.held_by_caller(), token.is_cancellation_requested())
        )
        self._reenter(token)


def _reenter_installed(signum: int, token: ThreadSafeCancellationToken) -> None:
    del token
    _invoke_installed(signum)


@pytest.mark.parametrize("boundary", [_PRE_FLAG, _NOTIFICATION])
def test_reentry_probe_refuses_a_recursive_lock_request(boundary: str) -> None:
    # The control: the token's own request, reentered at the same boundary, asks
    # again for the lock its caller holds; the probe refuses at once, never hangs,
    # and the lock is released on the way out of either boundary.
    control = _ReentryProbe(
        ThreadSafeCancellationToken.request_cancellation, boundary=boundary
    )
    token = control.token()
    (lock,) = control.locks
    assert not token.is_cancellation_requested()
    with pytest.raises(_RecursiveLockRequest, match="recursive locking request"):
        token.request_cancellation()
    flag_set_at_delivery = boundary == _NOTIFICATION
    assert control.deliveries == [(True, flag_set_at_delivery)]
    # Refused before the flag assignment, the request leaves cancellation clear.
    assert token.is_cancellation_requested() is flag_set_at_delivery
    assert lock.acquisitions == 1
    assert not lock.held_by_caller()
    assert not lock.locked()


class _InjectedRequestFailure(Exception):
    """An injected failure inside the token's request, before its flag is set."""


def _fail_request(token: ThreadSafeCancellationToken) -> NoReturn:
    del token
    raise _InjectedRequestFailure("the request failed before its flag was set")


def test_reentry_probe_releases_the_lock_after_a_failure() -> None:
    # The cleanup control: a callback failure on context entry, before the ``with``
    # body runs, releases the acquired lock, so the next request acquires it again.
    probe = _ReentryProbe(_fail_request, boundary=_PRE_FLAG)
    token = probe.token()
    (lock,) = probe.locks
    with pytest.raises(_InjectedRequestFailure, match="before its flag"):
        token.request_cancellation()
    assert probe.deliveries == [(True, False)]
    assert not token.is_cancellation_requested()
    assert lock.acquisitions == 1
    assert not lock.locked()
    token.request_cancellation()
    assert token.is_cancellation_requested()
    assert lock.acquisitions == 2
    assert not lock.locked()


@pytest.mark.parametrize(("outer", "nested"), _SIGNAL_PAIRS)
def test_cancellation_bridge_refuses_pre_flag_reentry(
    outer: signal.Signals, nested: signal.Signals
) -> None:
    # Each supported signal, reentered by each supported signal after the request
    # acquired the real condition lock and before Event.set assigns its flag: the
    # nested handler still reads cancellation clear, so only the bridge's in-progress
    # guard keeps it from requesting the held lock. The outer request then completes
    # with the one acquisition, and later signals keep the set state without the lock.
    assert {outer, nested} <= set(_BRIDGED_SIGNALS)
    before = _handlers()
    probe = _ReentryProbe(partial(_reenter_installed, nested), boundary=_PRE_FLAG)
    token = probe.token()
    event = probe.event
    (lock,) = probe.locks
    with install_cancellation_bridge(token) as bridged:
        assert bridged is token
        assert not token.is_cancellation_requested()
        _invoke_installed(outer)
        assert probe.deliveries == [(True, False)]
        assert token.is_cancellation_requested()
        assert lock.acquisitions == 1
        _invoke_installed(nested)
        _invoke_installed(outer)
        assert token.is_cancellation_requested()
        assert lock.acquisitions == 1
    assert bridged is token
    assert token._event is event
    assert probe.locks == [lock]
    assert not lock.locked()
    assert _handlers() == before


@pytest.mark.parametrize(("outer", "nested"), _SIGNAL_PAIRS)
def test_cancellation_bridge_refuses_notification_reentry(
    outer: signal.Signals, nested: signal.Signals
) -> None:
    # Each supported signal, reentered by each supported signal inside the real
    # notification: the nested handler never requests the held lock, and later
    # requests keep the set state without the lock.
    assert {outer, nested} <= set(_BRIDGED_SIGNALS)
    before = _handlers()
    probe = _ReentryProbe(partial(_reenter_installed, nested), boundary=_NOTIFICATION)
    token = probe.token()
    (lock,) = probe.locks
    with install_cancellation_bridge(token) as bridged:
        assert bridged is token
        assert not token.is_cancellation_requested()
        _invoke_installed(outer)
        assert probe.deliveries == [(True, True)]
        assert token.is_cancellation_requested()
        assert lock.acquisitions == 1
        _invoke_installed(nested)
        _invoke_installed(outer)
        assert token.is_cancellation_requested()
        assert lock.acquisitions == 1
    assert not lock.held_by_caller()
    assert _handlers() == before


@pytest.mark.parametrize("signum", _BRIDGED_SIGNALS)
def test_cancellation_bridge_clears_its_guard_after_a_failure(
    signum: signal.Signals,
) -> None:
    # A request that fails inside the token leaves the handler's in-progress guard
    # clear: the failure propagates with the lock released and cancellation still
    # clear, and the next signal requests cancellation and completes it.
    before = _handlers()
    probe = _ReentryProbe(_fail_request, boundary=_PRE_FLAG)
    token = probe.token()
    (lock,) = probe.locks
    with install_cancellation_bridge(token):
        with pytest.raises(_InjectedRequestFailure, match="before its flag"):
            _invoke_installed(signum)
        assert probe.deliveries == [(True, False)]
        assert not token.is_cancellation_requested()
        assert lock.acquisitions == 1
        assert not lock.locked()
        _invoke_installed(signum)
        assert token.is_cancellation_requested()
        assert lock.acquisitions == 2
    assert not lock.locked()
    assert _handlers() == before


# --------------------------------------------------------------------------
# U1: the storage probe
# --------------------------------------------------------------------------


def _tree(root: Path) -> tuple[str, ...]:
    return tuple(sorted(path.relative_to(root).as_posix() for path in root.rglob("*")))


class _FakeVolumes:
    """Volume facts keyed by root name; the physical root checks stay real."""

    def __init__(
        self,
        *,
        drive_types: Mapping[str, int] | None = None,
        filesystems: Mapping[str, str] | None = None,
        serials: Mapping[str, int] | None = None,
        failing: str | None = None,
    ) -> None:
        self._drive_types = dict(drive_types or {})
        self._filesystems = dict(filesystems or {})
        self._serials = dict(serials or {})
        self._failing = failing

    def volume_root(self, path: Path) -> str:
        if path.name == self._failing:
            raise RuntimeWindowsError("GetVolumePathNameW", 5)
        return f"{path.name}\\"

    def drive_type(self, volume_root: str) -> int:
        return self._drive_types.get(volume_root.rstrip("\\"), _DRIVE_FIXED)

    def volume_identity(self, volume_root: str) -> tuple[int, str]:
        name = volume_root.rstrip("\\")
        return self._serials.get(name, 0xA1B2C3D4), self._filesystems.get(name, "NTFS")


@pytest.fixture
def storage_roots(tmp_path: Path) -> tuple[Path, Path]:
    staging = tmp_path / "staging"
    artifacts = tmp_path / "artifacts"
    staging.mkdir()
    artifacts.mkdir()
    return staging, artifacts


def test_storage_probe_refuses_unsupported_roots(
    tmp_path: Path, storage_roots: tuple[Path, Path]
) -> None:
    staging, artifacts = storage_roots
    before = _tree(tmp_path)
    accepted = probe_storage(staging_root=staging, artifact_root=artifacts)
    assert isinstance(accepted, StorageProbe)
    assert accepted.staging_root == staging
    assert accepted.artifact_root == artifacts
    assert accepted.filesystem == "NTFS"
    assert _tree(tmp_path) == before

    def refused(
        staging_root: Path,
        artifact_root: Path,
        volumes: _FakeVolumes | None = None,
    ) -> StorageRefusal:
        outcome = probe_storage(
            staging_root=staging_root, artifact_root=artifact_root, inspector=volumes
        )
        assert isinstance(outcome, StorageRefusal), outcome
        assert _tree(tmp_path) == before  # refused before any layout creation
        return outcome

    unsafe = (
        (Path("relative") / "staging", StorageRefusalReason.NOT_ABSOLUTE),
        (Path(r"\\server\share\staging"), StorageRefusalReason.REMOTE),
        (Path(r"\\?\C:\staging"), StorageRefusalReason.UNSAFE_PATH),
        (tmp_path / "staging" / ".." / "staging", StorageRefusalReason.UNSAFE_PATH),
        (tmp_path / "absent", StorageRefusalReason.MISSING),
    )
    for root, reason in unsafe:
        assert refused(root, artifacts) == StorageRefusal("staging", reason), root
    assert not (tmp_path / "absent").exists()
    plain_file = tmp_path / "file"
    plain_file.write_bytes(b"")
    before = _tree(tmp_path)
    assert refused(staging, plain_file) == StorageRefusal(
        "artifacts", StorageRefusalReason.NOT_A_DIRECTORY
    )
    junction = tmp_path / "junction"
    _winapi.CreateJunction(str(artifacts), str(junction))
    (artifacts / "inside").mkdir()
    before = _tree(tmp_path)
    assert refused(junction, artifacts) == StorageRefusal(
        "staging", StorageRefusalReason.REPARSE_POINT
    )
    assert refused(staging, junction / "inside") == StorageRefusal(
        "artifacts", StorageRefusalReason.PHYSICAL_IDENTITY_MISMATCH
    )
    # Volume facts: remote, removable, non-NTFS, different volumes, a failed query.
    volume_cases = (
        (
            _FakeVolumes(drive_types={"staging": _DRIVE_REMOTE}),
            StorageRefusal("staging", StorageRefusalReason.REMOTE),
        ),
        (
            _FakeVolumes(drive_types={"artifacts": _DRIVE_REMOVABLE}),
            StorageRefusal("artifacts", StorageRefusalReason.NOT_FIXED),
        ),
        (
            _FakeVolumes(filesystems={"artifacts": "FAT32"}),
            StorageRefusal("artifacts", StorageRefusalReason.UNSUPPORTED_FILESYSTEM),
        ),
        (
            _FakeVolumes(serials={"artifacts": 0x0BADF00D}),
            StorageRefusal("artifacts", StorageRefusalReason.WRONG_VOLUME),
        ),
        (
            _FakeVolumes(failing="staging"),
            StorageRefusal("staging", StorageRefusalReason.PROBE_FAILED, winerror=5),
        ),
    )
    for volumes, expected in volume_cases:
        assert refused(staging, artifacts, volumes) == expected
    same = probe_storage(
        staging_root=staging, artifact_root=artifacts, inspector=_FakeVolumes()
    )
    assert same == StorageProbe(
        staging_root=staging,
        artifact_root=artifacts,
        volume_serial=0xA1B2C3D4,
        filesystem="NTFS",
    )
