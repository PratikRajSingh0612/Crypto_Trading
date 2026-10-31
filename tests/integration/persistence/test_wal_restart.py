"""An interrupted writer process leaves no partial row (plan 5.1 case C-17; Task 6).

A child interpreter ``P`` -- the venv's ``sys.executable`` with ``-I -B -c`` and the
one-line ``HOLDING_WRITER_PROGRAM``, a list argv and ``shell=False`` -- opens the
migrated database with the stdlib DBAPI, takes the writer lock with
``BEGIN IMMEDIATE``, stages a throwaway table and one row in it (so no record
``CHECK`` is involved and the uncommitted DDL is the partial write the reopen must
not see), reports ``HELD <pid>`` and blocks on stdin. The parent proceeds only after
reading that record -- the proven checkpoint is **work not yet committed** (the lock
held, the DDL and the row staged, no ``COMMIT`` issued) -- asserts that its own
writer gets ``PERSISTENCE.CONCURRENCY_CONFLICT`` from a lock another process holds,
then forcibly terminates the interpreter that actually holds the connection, awaits
that interpreter's exit on a handle it retained while the writer was alive, reaps the
launched process separately, and only then reopens the file through the production
open. The oracle matches that checkpoint: the pre-crash rows are present,
``crash_probe`` is absent, the revision is ``CURRENT``, ``quick_check`` is ``ok``,
the journal mode is still ``wal`` and the ``-wal``/``-shm`` sidecars the interrupted
writer left behind are tolerated (plan 7.5).

Why the writer is identified and not assumed. The venv's ``sys.executable`` may be a
launcher that starts the real interpreter as its own child; terminating and awaiting
the launched process then says nothing about the interpreter holding the SQLite
connection, which can still be tearing down when the reopen begins. The
``InterruptedWriter`` fixture therefore parses the pid the writer reports, accepts it
only when it is the launched process itself or a verified descendant of that live
launch (plan 8.3's creation-time rule, through the process-supervision helpers),
retains a handle opened while the writer was alive, rechecks the creation identity on
that handle, terminates the writer with one fixture-owned forced exit value, waits on
the same handle within the fixture's 30-second bound and asserts the forced exit value.
A missing or malformed readiness record, an unverified pid, an already exited writer,
a wait that does not signal or an exit value other than the forced one fails the test
before any reopen; cleanup is identity-aware and never a kill by pid alone.

Known runtime susceptibility, recorded here with its limit: on Windows, SQLite 3.50
through at least 3.53.x fails a first open with ``SQLITE_IOERR_TRUNCATE`` while any
process still holds a mapping of the ``-shm`` file (upstream check-in ``7c103a0b7d``
adds a fallback). Awaiting the writer's own exit removes the test's stale-holder
window; it neither patches the engine nor protects against an unrelated process
holding such a mapping.

This is process interruption evidence: it is not a power-loss experiment and proves
no storage-hardware failure mode. Nothing here sleeps; the only processes touched are
the one this test launches and the writer it verified as its own. This module is the
twelfth ``subprocess`` importer of the Stage 6 allowlist and the only one under
``tests/integration/persistence`` (plan 2.6, 7.6).
"""

from __future__ import annotations

import io
import re
import subprocess
import sys
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import IO, Final, Protocol, Self

import pytest
from sqlalchemy import text

from crypto_lab.domain.lifecycle import ExperimentState
from crypto_lab.persistence.diagnostics import CONCURRENCY_CONFLICT
from crypto_lab.persistence.migration_runner import (
    RevisionState,
    check_revision,
    schema_objects,
)
from crypto_lab.persistence.schema import EXPECTED_SCHEMA_OBJECTS
from crypto_lab.persistence.unit_of_work import SqliteUnitOfWork
from crypto_lab.process_supervision import windows_api
from crypto_lab.process_supervision.models import (
    FORCED_TERMINATION_EXIT_CODE,
    DescendantIdentity,
    render_creation_identity,
)
from doubles.experiments import INSTANT, FixedClock, sample_experiment
from persistence_support.harness import (
    SqliteHarness,
    code,
    open_test_database,
    put_experiment,
)

_E: Final = ExperimentState
#: Plan Task 6 Step 1: one line -- open the path with ``sqlite3``,
#: ``isolation_level=None``, ``BEGIN IMMEDIATE``, the throwaway table and its row,
#: report ``HELD`` with the interpreter's own pid, flush, block on stdin. The child
#: never commits.
HOLDING_WRITER_PROGRAM: Final = (
    "import os, sqlite3, sys; "
    "connection = sqlite3.connect(sys.argv[1], isolation_level=None); "
    "connection.execute('BEGIN IMMEDIATE'); "
    "connection.execute('CREATE TABLE crash_probe (x INTEGER)'); "
    "connection.execute('INSERT INTO crash_probe VALUES (1)'); "
    "sys.stdout.write('HELD %d\\n' % os.getpid()); "
    "sys.stdout.flush(); "
    "sys.stdin.readline()"
)
#: Plan 5.3: the fixture's lock-wait observation budget (twenty times the
#: configured 100 ms busy timeout) and the lower bound proving the wait happened.
_LOCK_WAIT_LOWER_BOUND_SECONDS: Final = 0.05
_LOCK_WAIT_BUDGET_SECONDS: Final = 2.0
#: The fixture's process-exit bound, unchanged from the committed ``wait(timeout=30)``.
_PROCESS_EXIT_BOUND_SECONDS: Final = 30.0
#: The one forced exit value the fixture uses for the writer. Fixture-owned: it reuses
#: the number the production supervisor passes to a forced tree termination so a
#: forcibly interrupted writer reads the same way as a supervised one, but nothing
#: here depends on production terminating anything.
_FORCED_WRITER_EXIT_CODE: Final = FORCED_TERMINATION_EXIT_CODE
#: The readiness record: exactly ``HELD <pid>`` on one line, read with a byte bound.
_READINESS_LIMIT: Final = 64
_READINESS: Final = re.compile(rb"HELD ([1-9][0-9]{0,9})\r?\n")


def _sidecars(path: Path) -> tuple[bool, bool]:
    """Whether the ``-wal`` and ``-shm`` files exist beside the database."""
    return (
        path.with_name(path.name + "-wal").exists(),
        path.with_name(path.name + "-shm").exists(),
    )


# --------------------------------------------------------------------------
# The interrupted-writer fixture
# --------------------------------------------------------------------------


class _Launched(Protocol):
    """What the fixture needs from a launched process: ``subprocess.Popen`` or a
    double."""

    @property
    def pid(self) -> int: ...

    @property
    def stdin(self) -> IO[bytes] | None: ...

    @property
    def stdout(self) -> IO[bytes] | None: ...

    def poll(self) -> int | None: ...

    def kill(self) -> None: ...

    def wait(self, timeout: float | None = None) -> int: ...


@dataclass(frozen=True, kw_only=True)
class _ProcessApi:
    """The process-supervision Windows API functions the fixture calls, bound once
    so the regression tests can substitute a safe double."""

    open_process_limited: Callable[..., int]
    process_times: Callable[[int], int]
    process_exit_code: Callable[[int], int]
    wait_for_handle: Callable[[int, float], bool]
    terminate_process: Callable[[int, int], None]
    close_handle: Callable[[int], None]
    descendants_of: Callable[[int, int], tuple[DescendantIdentity, ...]]


_WINDOWS: Final = _ProcessApi(
    open_process_limited=windows_api.open_process_limited,
    process_times=windows_api.process_times,
    process_exit_code=windows_api.process_exit_code,
    wait_for_handle=windows_api.wait_for_handle,
    terminate_process=windows_api.terminate_process,
    close_handle=windows_api.close_handle,
    descendants_of=windows_api.descendants_of,
)


def _launch_writer(path: Path) -> subprocess.Popen[bytes]:
    """The committed launch shape: ``sys.executable -I -B -c``, list argv, no shell."""
    return subprocess.Popen(  # noqa: S603 - reviewed list argv, no shell
        [sys.executable, "-I", "-B", "-c", HOLDING_WRITER_PROGRAM, str(path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        shell=False,
    )


class InterruptedWriter:
    """Launch the holding writer, verify which process holds the connection, keep it
    held for the ``with`` body, then interrupt that writer abruptly and await it.

    ``trace`` receives the fixture's ordered events; ``api`` and ``launch`` exist so
    the regression tests below can drive the same code with doubles. On the success
    path ``exit_code`` is the forced value and ``launcher_exit`` the launched
    process's exit after the writer signaled; any other outcome raises before the
    caller can reopen, after identity-aware cleanup of everything this fixture owns.
    """

    def __init__(
        self,
        path: Path,
        *,
        api: _ProcessApi = _WINDOWS,
        launch: Callable[[Path], _Launched] = _launch_writer,
        trace: list[str] | None = None,
    ) -> None:
        self._path = path
        self._api = api
        self._launch = launch
        self._trace: list[str] = trace if trace is not None else []
        self._launched: _Launched | None = None
        self._launcher_handle: int | None = None
        self._launcher_creation: int | None = None
        self._descendants: tuple[DescendantIdentity, ...] = ()
        self._writer_identity: str | None = None
        self._writer_handle: int | None = None
        self._writer_creation: int | None = None
        self.writer_pid: int | None = None
        self.writer_is_launcher: bool | None = None
        self.exit_code: int | None = None
        self.launcher_exit: int | None = None

    @property
    def trace(self) -> tuple[str, ...]:
        return tuple(self._trace)

    def __enter__(self) -> Self:
        try:
            self._launched = self._launch(self._path)
            self._note("launched")
            pid = self._read_readiness()
            self._verify_ownership(pid)
            self._retain_writer(pid)
        except BaseException:
            self._cleanup_after_failure()
            raise
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if exc_type is not None:
            self._cleanup_after_failure()
            return
        try:
            self._interrupt()
            self._reap_launcher()
        except BaseException:
            self._cleanup_after_failure()
            raise
        self._close_all()

    # -- setup --------------------------------------------------------------------

    def _note(self, event: str) -> None:
        self._trace.append(event)

    def _require_launched(self) -> _Launched:
        assert self._launched is not None
        return self._launched

    def _read_readiness(self) -> int:
        launched = self._require_launched()
        assert launched.stdout is not None, "the writer's stdout is not piped"
        line = launched.stdout.readline(_READINESS_LIMIT)
        match = _READINESS.fullmatch(line)
        assert match is not None, (
            f"unexpected readiness record from the writer: {line!r}"
        )
        self._note("ready")
        return int(match.group(1))

    def _verify_ownership(self, pid: int) -> None:
        """The reported pid is the launched process itself or a verified descendant
        of that live launch; anything else is refused before any handle on it exists."""
        launched = self._require_launched()
        self._launcher_handle = self._api.open_process_limited(launched.pid)
        self._launcher_creation = self._api.process_times(self._launcher_handle)
        assert not self._api.wait_for_handle(self._launcher_handle, 0.0), (
            "the launched process exited before ownership was verified"
        )
        if pid == launched.pid:
            self.writer_is_launcher = True
            self._note("writer-is-launcher")
            return
        self._descendants = self._api.descendants_of(
            launched.pid, self._launcher_creation
        )
        matches = [item for item in self._descendants if item.pid == pid]
        assert len(matches) == 1, (
            f"the reported writer pid {pid} is not a verified descendant of the "
            f"launched process {launched.pid}"
        )
        self._writer_identity = str(matches[0].creation_identity)
        self.writer_is_launcher = False
        self._note("writer-is-descendant")

    def _retain_writer(self, pid: int) -> None:
        """Open and keep the writer's handle; record its creation time only once it
        matches the identity verified above, so cleanup never terminates through a
        handle whose identity failed to verify."""
        self._writer_handle = self._api.open_process_limited(pid, terminate=True)
        self.writer_pid = pid
        creation = self._api.process_times(self._writer_handle)
        if self.writer_is_launcher:
            assert creation == self._launcher_creation, (
                "the retained writer handle does not match the launched process"
            )
        else:
            assert render_creation_identity(pid, creation) == self._writer_identity, (
                "the retained writer handle does not match the verified descendant"
            )
        self._writer_creation = creation
        assert not self._api.wait_for_handle(self._writer_handle, 0.0), (
            "the writer exited before it was interrupted"
        )
        self._note("writer-held")

    # -- interruption -------------------------------------------------------------

    def _interrupt(self) -> None:
        handle = self._writer_handle
        assert handle is not None
        assert self._launcher_handle is not None
        assert not self._api.wait_for_handle(self._launcher_handle, 0.0), (
            "the launched process exited before the writer was interrupted"
        )
        assert self._api.process_times(handle) == self._writer_creation, (
            "the writer's creation identity changed on the retained handle"
        )
        assert not self._api.wait_for_handle(handle, 0.0), (
            "the writer exited on its own before the forced interruption; a natural "
            "exit is not the crash checkpoint"
        )
        self._api.terminate_process(handle, _FORCED_WRITER_EXIT_CODE)
        self._note("writer-terminated")
        assert self._api.wait_for_handle(handle, _PROCESS_EXIT_BOUND_SECONDS), (
            f"the writer did not exit within {_PROCESS_EXIT_BOUND_SECONDS:g} s of "
            "the forced termination"
        )
        self._note("writer-signaled")
        exit_code = self._api.process_exit_code(handle)
        assert exit_code == _FORCED_WRITER_EXIT_CODE, (
            f"the writer exited with {exit_code}, not the forced value "
            f"{_FORCED_WRITER_EXIT_CODE}"
        )
        self.exit_code = exit_code

    def _reap_launcher(self) -> None:
        launched = self._require_launched()
        if launched.poll() is None:
            launched.kill()
        self.launcher_exit = launched.wait(timeout=_PROCESS_EXIT_BOUND_SECONDS)
        self._note("launcher-reaped")

    # -- cleanup ------------------------------------------------------------------

    def _close_all(self) -> None:
        launched = self._launched
        if launched is not None:
            for stream in (launched.stdin, launched.stdout):
                if stream is not None and not stream.closed:
                    with suppress(Exception):
                        stream.close()
        for attribute in ("_writer_handle", "_launcher_handle"):
            handle = getattr(self, attribute)
            if handle is not None:
                setattr(self, attribute, None)
                with suppress(Exception):
                    self._api.close_handle(handle)
        self._note("closed")

    def _cleanup_after_failure(self) -> None:
        """Best effort, identity-aware, never masking the original exception: the
        retained writer (if still the same process and alive), the launched process,
        then every descendant enumerated while the launch was alive."""
        handle = self._writer_handle
        if handle is not None and self._writer_creation is not None:
            with suppress(Exception):
                if (
                    not self._api.wait_for_handle(handle, 0.0)
                    and self._api.process_times(handle) == self._writer_creation
                ):
                    self._api.terminate_process(handle, _FORCED_WRITER_EXIT_CODE)
                    self._api.wait_for_handle(handle, _PROCESS_EXIT_BOUND_SECONDS)
        launched = self._launched
        if launched is not None:
            with suppress(Exception):
                if launched.poll() is None:
                    launched.kill()
                launched.wait(timeout=_PROCESS_EXIT_BOUND_SECONDS)
        for item in self._descendants:
            with suppress(Exception):
                self._terminate_if_still_ours(item)
        self._close_all()
        self._note("cleaned-up")

    def _terminate_if_still_ours(self, item: DescendantIdentity) -> None:
        handle = self._api.open_process_limited(item.pid, terminate=True)
        try:
            if self._api.wait_for_handle(handle, 0.0):
                return
            creation = self._api.process_times(handle)
            if render_creation_identity(item.pid, creation) != str(
                item.creation_identity
            ):
                return
            self._api.terminate_process(handle, _FORCED_WRITER_EXIT_CODE)
            self._api.wait_for_handle(handle, _PROCESS_EXIT_BOUND_SECONDS)
        finally:
            self._api.close_handle(handle)


# --------------------------------------------------------------------------
# C-17
# --------------------------------------------------------------------------


def test_an_interrupted_writer_leaves_no_partial_row_after_reopen(
    tmp_path: Path,
) -> None:
    database = open_test_database(tmp_path, clock=FixedClock(INSTANT))
    put_experiment(SqliteHarness(database), sample_experiment(_E.DRAFT))
    database.close()
    with InterruptedWriter(database.path) as held:
        blocked = open_test_database(tmp_path, clock=FixedClock(INSTANT))
        try:
            transaction = SqliteUnitOfWork(blocked, FixedClock(INSTANT)).begin()
            assert (
                code(transaction.experiments.add(sample_experiment(_E.VALIDATED)))
                == CONCURRENCY_CONFLICT
            )
            transaction.rollback()
        finally:
            blocked.close()
    assert held.exit_code == _FORCED_WRITER_EXIT_CODE
    reopened = open_test_database(tmp_path, clock=FixedClock(INSTANT))
    try:
        assert SqliteHarness(reopened).committed_experiments() == (
            sample_experiment(_E.DRAFT),
        )
        with reopened.read_only() as connection:
            names = {row.name for row in schema_objects(connection)}
            assert "crash_probe" not in names
            assert check_revision(connection).state is RevisionState.CURRENT
        assert reopened.consistency_report().foreign_key_violations == 0
    finally:
        reopened.close()


def test_the_lock_of_another_process_is_a_bounded_conflict_and_the_file_recovers(
    tmp_path: Path,
) -> None:
    """C-17's Windows half (plan 5.3, 7.5): the parent's writer waits at least the
    configured timeout and below the fixture budget; after the writer is interrupted
    and awaited, the sidecars it left are tolerated, the schema equals the pinned set,
    ``quick_check`` is ``ok`` and the journal mode is still ``wal``."""
    database = open_test_database(tmp_path, clock=FixedClock(INSTANT))
    stored = sample_experiment(_E.DRAFT)
    put_experiment(SqliteHarness(database), stored)
    database.close()
    path = database.path
    with InterruptedWriter(path) as held:
        blocked = open_test_database(tmp_path, clock=FixedClock(INSTANT))
        try:
            transaction = SqliteUnitOfWork(blocked, FixedClock(INSTANT)).begin()
            started = time.perf_counter()
            refused = transaction.experiments.add(sample_experiment(_E.VALIDATED))
            elapsed = time.perf_counter() - started
            assert code(refused) == CONCURRENCY_CONFLICT
            assert (
                _LOCK_WAIT_LOWER_BOUND_SECONDS <= elapsed < (_LOCK_WAIT_BUDGET_SECONDS)
            )
            # The refused writer stays usable and reads its own snapshot.
            assert transaction.open_failure() is None
            assert SqliteHarness(blocked).committed_experiments() == (stored,)
            transaction.rollback()
        finally:
            blocked.close()
    assert held.exit_code == _FORCED_WRITER_EXIT_CODE
    assert held.launcher_exit is not None
    # The interrupted writer's sidecars may survive; the reopen tolerates them.
    wal_present, _ = _sidecars(path)
    assert wal_present
    reopened = open_test_database(tmp_path, clock=FixedClock(INSTANT))
    try:
        assert SqliteHarness(reopened).committed_experiments() == (stored,)
        with reopened.read_only() as connection:
            assert schema_objects(connection) == EXPECTED_SCHEMA_OBJECTS
            assert check_revision(connection).state is RevisionState.CURRENT
            assert connection.execute(text("PRAGMA quick_check")).scalar_one() == "ok"
            assert connection.execute(text("PRAGMA journal_mode")).scalar_one() == "wal"
        report = reopened.consistency_report()
        assert report.foreign_key_violations == 0
        assert report.spec_projection_mismatches == 0
    finally:
        reopened.close()


# --------------------------------------------------------------------------
# Regression tests for the fixture's ownership guarantee
# --------------------------------------------------------------------------

_LAUNCHER_PID: Final = 500
_WRITER_PID: Final = 501
_STILL_ACTIVE: Final = 259
_SUCCESS_TAIL: Final = (
    "writer-held",
    "writer-terminated",
    "writer-signaled",
    "launcher-reaped",
    "closed",
    "reopen",
)


class _FakeLaunched:
    """A launched-process double: the readiness record on stdout, a stdin pipe, and
    ``poll``/``kill``/``wait`` recorded into the shared log."""

    def __init__(self, pid: int, ready_line: bytes, log: list[str]) -> None:
        self.pid = pid
        self.stdout: IO[bytes] | None = io.BytesIO(ready_line)
        self.stdin: IO[bytes] | None = io.BytesIO()
        self._log = log
        self._returncode: int | None = None

    def poll(self) -> int | None:
        return self._returncode

    def kill(self) -> None:
        self._log.append("launcher.kill")
        self._returncode = 1

    def wait(self, timeout: float | None = None) -> int:
        self._log.append("launcher.wait")
        if self._returncode is None:
            self._returncode = 0
        return self._returncode


@dataclass
class _FakeKernel:
    """A process-API double: pids with creation times, handles that outlive pid
    reuse, a termination that signals only on a positive-timeout wait, and
    programmable deviations for the refusal paths. Nothing real is touched."""

    descendants: tuple[DescendantIdentity, ...] = ()
    writer_creation_changes_at_recheck: bool = False
    writer_pid_reused_after_enumeration: bool = False
    writer_exits_before_interruption: bool = False
    writer_never_signals: bool = False
    exit_code_after_termination: int = _FORCED_WRITER_EXIT_CODE
    log: list[str] = field(default_factory=list)
    closed: list[int] = field(default_factory=list)
    _handles: dict[int, int] = field(default_factory=dict)
    _creation: dict[int, int] = field(
        default_factory=lambda: {_LAUNCHER_PID: 10, _WRITER_PID: 20}
    )
    _alive: dict[int, bool] = field(
        default_factory=lambda: {_LAUNCHER_PID: True, _WRITER_PID: True}
    )
    _exit_codes: dict[int, int] = field(default_factory=dict)
    _pending: set[int] = field(default_factory=set)
    _next_handle: int = 1000
    _writer_times_calls: int = 0
    _writer_zero_waits: int = 0

    def api(self) -> _ProcessApi:
        return _ProcessApi(
            open_process_limited=self.open_process_limited,
            process_times=self.process_times,
            process_exit_code=self.process_exit_code,
            wait_for_handle=self.wait_for_handle,
            terminate_process=self.terminate_process,
            close_handle=self.close_handle,
            descendants_of=self.descendants_of,
        )

    def launched(self, reported_pid: int) -> _FakeLaunched:
        return _FakeLaunched(_LAUNCHER_PID, b"HELD %d\r\n" % reported_pid, self.log)

    def open_process_limited(
        self, pid: int, *, terminate: bool = False, set_quota: bool = False
    ) -> int:
        del set_quota
        if pid not in self._creation:
            raise windows_api.WindowsApiError("OpenProcess", 87)
        handle = self._next_handle
        self._next_handle += 1
        self._handles[handle] = pid
        self.log.append(f"open:{pid}:terminate={terminate}")
        return handle

    def process_times(self, handle: int) -> int:
        pid = self._handles[handle]
        self.log.append(f"times:{pid}")
        if pid == _WRITER_PID:
            self._writer_times_calls += 1
            if self.writer_creation_changes_at_recheck and self._writer_times_calls > 1:
                return 21
        return self._creation[pid]

    def wait_for_handle(self, handle: int, timeout_seconds: float) -> bool:
        pid = self._handles[handle]
        self.log.append(f"wait:{pid}:{timeout_seconds:g}")
        if pid == _WRITER_PID and timeout_seconds == 0.0:
            self._writer_zero_waits += 1
            if self.writer_exits_before_interruption and self._writer_zero_waits > 1:
                self._alive[pid] = False
                self._exit_codes[pid] = 0
        if not self._alive[pid]:
            return True
        if (
            pid in self._pending
            and timeout_seconds > 0
            and not self.writer_never_signals
        ):
            self._alive[pid] = False
            return True
        return False

    def terminate_process(self, handle: int, exit_code: int) -> None:
        pid = self._handles[handle]
        self.log.append(f"terminate:{pid}:{exit_code}")
        self._pending.add(pid)
        self._exit_codes[pid] = self.exit_code_after_termination

    def process_exit_code(self, handle: int) -> int:
        pid = self._handles[handle]
        self.log.append(f"exit_code:{pid}")
        if self._alive[pid]:
            return _STILL_ACTIVE
        return self._exit_codes[pid]

    def close_handle(self, handle: int) -> None:
        self.closed.append(handle)

    def descendants_of(
        self, root_pid: int, root_creation_100ns: int
    ) -> tuple[DescendantIdentity, ...]:
        self.log.append(f"descendants:{root_pid}:{root_creation_100ns}")
        if self.writer_pid_reused_after_enumeration:
            # From here on the writer's pid names a different process.
            self._creation[_WRITER_PID] = 99
        return self.descendants

    def opened_handles(self) -> list[int]:
        return list(self._handles)


def _writer_descendant() -> tuple[DescendantIdentity, ...]:
    return (
        DescendantIdentity(
            pid=_WRITER_PID,
            creation_identity=render_creation_identity(_WRITER_PID, 20),
        ),
    )


def _hold_then_reopen(
    kernel: _FakeKernel, reported_pid: int, reopened: list[str]
) -> None:
    with InterruptedWriter(
        Path("C:/unused/registry.sqlite3"),
        api=kernel.api(),
        launch=lambda _: kernel.launched(reported_pid),
    ):
        pass
    reopened.append("reopen")


def _event_order(log: list[str], *events: str) -> list[int]:
    return [log.index(event) for event in events]


def test_the_fixture_selects_the_reported_writer_instead_of_the_launcher() -> None:
    """The launched process is a launcher; the writer is its verified descendant: the
    retained handle, the termination and the wait all target the writer, and the
    launcher is reaped only after the writer signaled."""
    kernel = _FakeKernel(descendants=_writer_descendant())
    reopened: list[str] = []
    _hold_then_reopen(kernel, _WRITER_PID, reopened)
    assert reopened == ["reopen"]
    assert f"open:{_WRITER_PID}:terminate=True" in kernel.log
    assert f"terminate:{_WRITER_PID}:{_FORCED_WRITER_EXIT_CODE}" in kernel.log
    assert not any(
        item.startswith(f"terminate:{_LAUNCHER_PID}:") for item in kernel.log
    )
    order = _event_order(
        kernel.log,
        f"descendants:{_LAUNCHER_PID}:10",
        f"terminate:{_WRITER_PID}:{_FORCED_WRITER_EXIT_CODE}",
        f"wait:{_WRITER_PID}:30",
        f"exit_code:{_WRITER_PID}",
        "launcher.kill",
        "launcher.wait",
    )
    assert order == sorted(order)
    assert sorted(kernel.closed) == sorted(kernel.opened_handles())


def test_a_launched_process_that_is_itself_the_writer_is_accepted() -> None:
    """Preservation control (already green by construction): when the reported pid is
    the launched process, no descendant walk is needed and that process is the one
    terminated and awaited."""
    kernel = _FakeKernel()
    reopened: list[str] = []
    _hold_then_reopen(kernel, _LAUNCHER_PID, reopened)
    assert reopened == ["reopen"]
    assert not any(item.startswith("descendants:") for item in kernel.log)
    assert f"terminate:{_LAUNCHER_PID}:{_FORCED_WRITER_EXIT_CODE}" in kernel.log
    assert f"wait:{_LAUNCHER_PID}:30" in kernel.log


def test_an_unverified_writer_pid_is_refused_before_any_handle_on_it() -> None:
    kernel = _FakeKernel(descendants=_writer_descendant())
    reopened: list[str] = []
    with pytest.raises(AssertionError, match="not a verified descendant"):
        _hold_then_reopen(kernel, 777, reopened)
    assert reopened == []
    # The reported pid is never opened, let alone terminated; the identity-aware
    # cleanup still sweeps the launch's own verified descendant.
    assert not any(item.startswith("open:777") for item in kernel.log)
    assert not any(item.startswith("terminate:777") for item in kernel.log)
    assert f"terminate:{_WRITER_PID}:{_FORCED_WRITER_EXIT_CODE}" in kernel.log
    assert "launcher.kill" in kernel.log
    assert sorted(kernel.closed) == sorted(kernel.opened_handles())


def test_a_pid_reused_after_enumeration_is_refused_without_termination() -> None:
    """The descendant walk recorded the writer's creation identity; when the pid then
    names a different process, the retained handle fails the identity check and
    nothing is terminated through that handle or through the cleanup sweep."""
    kernel = _FakeKernel(
        descendants=_writer_descendant(), writer_pid_reused_after_enumeration=True
    )
    reopened: list[str] = []
    with pytest.raises(AssertionError, match="does not match the verified descendant"):
        _hold_then_reopen(kernel, _WRITER_PID, reopened)
    assert reopened == []
    assert not any(item.startswith(f"terminate:{_WRITER_PID}:") for item in kernel.log)
    assert "launcher.kill" in kernel.log
    assert sorted(kernel.closed) == sorted(kernel.opened_handles())


def test_a_timed_out_owner_wait_prevents_the_reopen() -> None:
    kernel = _FakeKernel(descendants=_writer_descendant(), writer_never_signals=True)
    reopened: list[str] = []
    with pytest.raises(AssertionError, match="did not exit within 30 s"):
        _hold_then_reopen(kernel, _WRITER_PID, reopened)
    assert reopened == []
    assert f"wait:{_WRITER_PID}:30" in kernel.log
    assert "launcher.kill" in kernel.log
    assert sorted(kernel.closed) == sorted(kernel.opened_handles())


def test_an_identity_change_on_the_retained_handle_prevents_termination() -> None:
    kernel = _FakeKernel(
        descendants=_writer_descendant(), writer_creation_changes_at_recheck=True
    )
    reopened: list[str] = []
    with pytest.raises(AssertionError, match="creation identity changed"):
        _hold_then_reopen(kernel, _WRITER_PID, reopened)
    assert reopened == []
    assert not any(item.startswith(f"terminate:{_WRITER_PID}:") for item in kernel.log)
    assert sorted(kernel.closed) == sorted(kernel.opened_handles())


def test_a_writer_that_exited_on_its_own_is_not_the_crash_checkpoint() -> None:
    kernel = _FakeKernel(
        descendants=_writer_descendant(), writer_exits_before_interruption=True
    )
    reopened: list[str] = []
    with pytest.raises(AssertionError, match="exited on its own"):
        _hold_then_reopen(kernel, _WRITER_PID, reopened)
    assert reopened == []
    assert not any(item.startswith(f"terminate:{_WRITER_PID}:") for item in kernel.log)


def test_an_exit_value_other_than_the_forced_one_is_refused() -> None:
    kernel = _FakeKernel(
        descendants=_writer_descendant(), exit_code_after_termination=0
    )
    reopened: list[str] = []
    with pytest.raises(AssertionError, match="exited with 0, not the forced value"):
        _hold_then_reopen(kernel, _WRITER_PID, reopened)
    assert reopened == []


def test_resources_are_released_when_the_held_body_raises() -> None:
    kernel = _FakeKernel(descendants=_writer_descendant())
    launched = kernel.launched(_WRITER_PID)
    with pytest.raises(RuntimeError, match="body failed"):
        with InterruptedWriter(
            Path("C:/unused/registry.sqlite3"),
            api=kernel.api(),
            launch=lambda _: launched,
        ):
            raise RuntimeError("body failed")
    assert f"terminate:{_WRITER_PID}:{_FORCED_WRITER_EXIT_CODE}" in kernel.log
    assert "launcher.kill" in kernel.log
    assert sorted(kernel.closed) == sorted(kernel.opened_handles())
    assert launched.stdin is not None
    assert launched.stdin.closed
    assert launched.stdout is not None
    assert launched.stdout.closed


def test_a_malformed_readiness_record_is_refused_before_ownership() -> None:
    kernel = _FakeKernel(descendants=_writer_descendant())
    bad = _FakeLaunched(_LAUNCHER_PID, b"HELD\r\n", kernel.log)
    with pytest.raises(AssertionError, match="unexpected readiness record"):
        InterruptedWriter(
            Path("C:/unused/registry.sqlite3"),
            api=kernel.api(),
            launch=lambda _: bad,
        ).__enter__()
    assert not any(item.startswith("open:") for item in kernel.log)
    assert "launcher.kill" in kernel.log


def test_the_real_writer_is_interrupted_and_awaited_before_the_reopen(
    tmp_path: Path,
) -> None:
    """The real fixture over a real writer: the ownership route is one of the two
    accepted ones, the writer is terminated and signaled with the forced value, the
    launched process is reaped afterwards, and the reopen comes last."""
    database = open_test_database(tmp_path, clock=FixedClock(INSTANT))
    put_experiment(SqliteHarness(database), sample_experiment(_E.DRAFT))
    database.close()
    trace: list[str] = []
    with InterruptedWriter(database.path, trace=trace) as held:
        assert held.writer_pid is not None
        assert held.writer_is_launcher is not None
    trace.append("reopen")
    assert held.exit_code == _FORCED_WRITER_EXIT_CODE
    assert held.launcher_exit is not None
    route = "writer-is-launcher" if held.writer_is_launcher else "writer-is-descendant"
    assert route in trace
    assert [item for item in trace if item in _SUCCESS_TAIL] == list(_SUCCESS_TAIL)
    reopened = open_test_database(tmp_path, clock=FixedClock(INSTANT))
    try:
        assert SqliteHarness(reopened).committed_experiments() == (
            sample_experiment(_E.DRAFT),
        )
    finally:
        reopened.close()
