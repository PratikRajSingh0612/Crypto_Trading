"""Stage 9 Task 6, plan 5.1 CP-5 and CP-6 with a real child process (plan 7.1,
7.5; requirement rows R19.3-08, T28.3-10, T28.5-01; 28.3:2096 "no child
survives").

A child interpreter -- the venv's ``sys.executable`` with ``-I -B -c``, a list
argv and ``shell=False`` -- opens the ``FinalizationFixture`` the parent planted
on a path argument and runs one EVIDENCE finalization with a probe that
**blocks** at ``after_moved`` (CP-5: T2 committed, T3 not begun) or at
``inside_registered`` (CP-6: T3 open after its first insert, before its commit)
on a ``threading.Event().wait`` inside the child alone, after reporting
``HELD <pid>`` with its **own interpreter pid**. The parent then applies the
Stage 8 interrupted-writer discipline, re-implemented here because that fixture
is private to its module: on this host ``.venv\\Scripts\\python.exe`` is a
launcher that starts the real interpreter as its own child, so the launched
process is not the SQLite holder (commit ``079395b``). The reported pid is
accepted only when it is the launched process itself or a live descendant of
that launch verified by creation identity (``descendants_of``,
``process_times``, ``render_creation_identity``); a handle opened while the
holder is alive is retained, its creation identity re-checked, the holder
terminated through that handle with the fixture's forced exit value and
awaited on the same handle within the bound, its exit value asserted, the
launcher reaped separately, and only then the database reopened and the
journal recovered. Every descendant enumerated while the launch was alive is
asserted dead before the test ends; nothing is terminated by pid alone and no
process survives.

Durable oracles: CP-5 leaves the journal ``MOVED`` with no reference; CP-6
leaves exactly ``MOVED`` -- never a reference without its commit (SQLite
atomicity + reading 11) -- and, once the dead child's lease has expired (a
restart alone takes no unexpired lease), recovery registers the evidence in
both.

This module is the thirteenth ``subprocess`` importer of the Stage 6 allowlist
(plan 2.6). Nothing here sleeps on a wall clock, imports ``threading`` (the
child's wait is text inside the ``-c`` program) or kills by pid.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from types import TracebackType
from typing import IO, Final, Self

import pytest

from crypto_lab.artifacts.finalizer import EVIDENCE_LEASE_SECONDS, RESULT_LEASE_SECONDS
from crypto_lab.domain.results import Result, Success
from crypto_lab.process_supervision import windows_api
from crypto_lab.process_supervision.models import (
    FORCED_TERMINATION_EXIT_CODE,
    DescendantIdentity,
    render_creation_identity,
)
from doubles.artifacts import sample_evidence_request
from doubles.experiments import INSTANT, INVOCATION_ID, RUN_ID, FixedClock
from persistence_support.artifacts import FinalizationFixture

_TWO_FILES = {
    "stderr.txt": b"engine stderr line one\nengine stderr line two\n",
    "protocol.txt": b"engine protocol line one\n",
}
_TESTS_ROOT: Final = Path(__file__).resolve().parents[2]
#: The child's one-line program: insert the tests root, open the planted fixture
#: on the path argument (the production composition for a ``RESULT`` purpose),
#: rebuild the EVIDENCE or RESULT request from the committed rows and finalize
#: with a probe that reports ``HELD <pid>`` and blocks at the named point. No
#: ``def`` and no ``class`` statement: a compound statement would end the line.
_CHILD_PROGRAM: Final = (
    "import os, sys, threading; "
    "sys.path.insert(0, sys.argv[3]); "
    "from pathlib import Path; "
    "from doubles.experiments import INSTANT, FixedClock; "
    "from doubles.artifacts import INVOCATION_CORRELATION, RUN_OWNER; "
    "from persistence_support.artifacts import FinalizationFixture; "
    "hold = lambda *_: (sys.stdout.write('HELD %d\\n' % os.getpid()), "
    "sys.stdout.flush(), threading.Event().wait()); "
    "noop = lambda *_: None; "
    "names = ['before_prepared', 'after_prepared', 'before_move', 'after_move', "
    "'before_moved', 'after_moved', 'before_registered', 'inside_registered', "
    "'after_registered', 'after_close']; "
    "Probe = type('Probe', (), {name: (hold if name == sys.argv[2] else noop) "
    "for name in names}); "
    "result = sys.argv[4] == 'RESULT'; "
    "fixture = FinalizationFixture.open(Path(sys.argv[1]), "
    "clock=FixedClock(INSTANT), reuse=True, production=result); "
    "request = fixture.result_request_for(RUN_OWNER) if result else "
    "fixture.evidence_request_for(RUN_OWNER, correlation=INVOCATION_CORRELATION); "
    "fixture.finalize(request, probe=Probe()); "
    "fixture.close()"
)
_READINESS_LIMIT: Final = 64
_READINESS: Final = re.compile(rb"HELD ([1-9][0-9]{0,9})\r?\n")
_PROCESS_EXIT_BOUND_SECONDS: Final = 30.0
_FORCED_EXIT_CODE: Final = FORCED_TERMINATION_EXIT_CODE


def _ok[T](result: Result[T]) -> T:
    assert isinstance(result, Success), result
    return result.value


def _launch_child(
    tmp_path: Path, point: str, purpose: str = "EVIDENCE"
) -> subprocess.Popen[bytes]:
    """The committed launch shape: ``sys.executable -I -B -c``, list argv, no shell."""
    return subprocess.Popen(  # noqa: S603 - reviewed list argv, no shell
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            _CHILD_PROGRAM,
            str(tmp_path),
            point,
            str(_TESTS_ROOT),
            purpose,
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
    )


class ProcessHolder:
    """Launch the blocking child, verify which interpreter holds the connection,
    keep it held for the ``with`` body, then terminate that interpreter through
    its retained handle, await it, reap the launcher and prove no descendant
    survives (the Stage 8 interrupted-writer discipline)."""

    def __init__(self, tmp_path: Path, point: str, purpose: str = "EVIDENCE") -> None:
        self._tmp_path = tmp_path
        self._point = point
        self._purpose = purpose
        self._launched: subprocess.Popen[bytes] | None = None
        self._launcher_handle: int | None = None
        self._launcher_creation: int | None = None
        self._descendants: tuple[DescendantIdentity, ...] = ()
        self._holder_identity: str | None = None
        self._holder_handle: int | None = None
        self._holder_creation: int | None = None
        self.holder_pid: int | None = None
        self.holder_is_launcher: bool | None = None
        self.exit_code: int | None = None
        self.launcher_exit: int | None = None
        self.trace: list[str] = []

    def __enter__(self) -> Self:
        try:
            self._launched = _launch_child(self._tmp_path, self._point, self._purpose)
            self.trace.append("launched")
            pid = self._read_readiness()
            self._verify_ownership(pid)
            self._retain_holder(pid)
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
            self._assert_no_descendant_survives()
        except BaseException:
            self._cleanup_after_failure()
            raise
        self._close_all()

    # -- setup ------------------------------------------------------------------

    def _require_launched(self) -> subprocess.Popen[bytes]:
        assert self._launched is not None
        return self._launched

    def _stderr_text(self) -> str:
        launched = self._require_launched()
        stream: IO[bytes] | None = launched.stderr
        if stream is None:
            return ""
        try:
            return stream.read().decode("utf-8", errors="replace")
        except OSError:
            return ""

    def _read_readiness(self) -> int:
        launched = self._require_launched()
        assert launched.stdout is not None, "the child's stdout is not piped"
        line = launched.stdout.readline(_READINESS_LIMIT)
        match = _READINESS.fullmatch(line)
        if match is None:
            launched.wait(timeout=_PROCESS_EXIT_BOUND_SECONDS)
            pytest.fail(
                f"unexpected readiness record from the child: {line!r}; stderr: "
                f"{self._stderr_text()}"
            )
        self.trace.append("ready")
        return int(match.group(1))

    def _verify_ownership(self, pid: int) -> None:
        launched = self._require_launched()
        self._launcher_handle = windows_api.open_process_limited(launched.pid)
        self._launcher_creation = windows_api.process_times(self._launcher_handle)
        assert not windows_api.wait_for_handle(self._launcher_handle, 0.0), (
            "the launched process exited before ownership was verified"
        )
        if pid == launched.pid:
            self.holder_is_launcher = True
            self.trace.append("holder-is-launcher")
            return
        self._descendants = windows_api.descendants_of(
            launched.pid, self._launcher_creation
        )
        matches = [item for item in self._descendants if item.pid == pid]
        assert len(matches) == 1, (
            f"the reported holder pid {pid} is not a verified descendant of the "
            f"launched process {launched.pid}"
        )
        self._holder_identity = str(matches[0].creation_identity)
        self.holder_is_launcher = False
        self.trace.append("holder-is-descendant")

    def _retain_holder(self, pid: int) -> None:
        self._holder_handle = windows_api.open_process_limited(pid, terminate=True)
        self.holder_pid = pid
        creation = windows_api.process_times(self._holder_handle)
        if self.holder_is_launcher:
            assert creation == self._launcher_creation, (
                "the retained holder handle does not match the launched process"
            )
        else:
            assert render_creation_identity(pid, creation) == self._holder_identity, (
                "the retained holder handle does not match the verified descendant"
            )
        self._holder_creation = creation
        assert not windows_api.wait_for_handle(self._holder_handle, 0.0), (
            "the holder exited before it was interrupted"
        )
        self.trace.append("holder-held")

    # -- interruption -----------------------------------------------------------

    def _interrupt(self) -> None:
        handle = self._holder_handle
        assert handle is not None
        assert self._launcher_handle is not None
        assert windows_api.process_times(handle) == self._holder_creation, (
            "the holder's creation identity changed on the retained handle"
        )
        assert not windows_api.wait_for_handle(handle, 0.0), (
            "the holder exited on its own; a natural exit is not the crash checkpoint"
        )
        windows_api.terminate_process(handle, _FORCED_EXIT_CODE)
        self.trace.append("holder-terminated")
        assert windows_api.wait_for_handle(handle, _PROCESS_EXIT_BOUND_SECONDS), (
            f"the holder did not exit within {_PROCESS_EXIT_BOUND_SECONDS:g} s"
        )
        self.trace.append("holder-signaled")
        exit_code = windows_api.process_exit_code(handle)
        assert exit_code == _FORCED_EXIT_CODE, (
            f"the holder exited with {exit_code}, not the forced value "
            f"{_FORCED_EXIT_CODE}"
        )
        self.exit_code = exit_code

    def _reap_launcher(self) -> None:
        launched = self._require_launched()
        if launched.poll() is None:
            launched.kill()
        self.launcher_exit = launched.wait(timeout=_PROCESS_EXIT_BOUND_SECONDS)
        self.trace.append("launcher-reaped")

    def _assert_no_descendant_survives(self) -> None:
        """28.3:2096: every descendant enumerated while the launch was alive is
        dead under its recorded creation identity."""
        for item in self._descendants:
            try:
                handle = windows_api.open_process_limited(item.pid)
            except windows_api.WindowsApiError:
                continue  # the pid names no process any more
            try:
                if windows_api.wait_for_handle(handle, 0.0):
                    continue  # signaled: exited
                creation = windows_api.process_times(handle)
                assert render_creation_identity(item.pid, creation) != str(
                    item.creation_identity
                ), f"descendant {item.pid} survived the termination"
            finally:
                windows_api.close_handle(handle)
        self.trace.append("no-descendant-survives")

    # -- cleanup ------------------------------------------------------------------

    def _close_all(self) -> None:
        launched = self._launched
        if launched is not None:
            for stream in (launched.stdin, launched.stdout, launched.stderr):
                if stream is not None and not stream.closed:
                    try:
                        stream.close()
                    except OSError:
                        pass
        for attribute in ("_holder_handle", "_launcher_handle"):
            handle = getattr(self, attribute)
            if handle is not None:
                setattr(self, attribute, None)
                try:
                    windows_api.close_handle(handle)
                except windows_api.WindowsApiError:
                    pass
        self.trace.append("closed")

    def _cleanup_after_failure(self) -> None:
        handle = self._holder_handle
        if handle is not None and self._holder_creation is not None:
            try:
                if (
                    not windows_api.wait_for_handle(handle, 0.0)
                    and windows_api.process_times(handle) == self._holder_creation
                ):
                    windows_api.terminate_process(handle, _FORCED_EXIT_CODE)
                    windows_api.wait_for_handle(handle, _PROCESS_EXIT_BOUND_SECONDS)
            except windows_api.WindowsApiError:
                pass
        launched = self._launched
        if launched is not None:
            try:
                if launched.poll() is None:
                    launched.kill()
                launched.wait(timeout=_PROCESS_EXIT_BOUND_SECONDS)
            except (OSError, subprocess.TimeoutExpired):
                pass
        for item in self._descendants:
            try:
                self._terminate_if_still_ours(item)
            except windows_api.WindowsApiError:
                pass
        self._close_all()
        self.trace.append("cleaned-up")

    def _terminate_if_still_ours(self, item: DescendantIdentity) -> None:
        handle = windows_api.open_process_limited(item.pid, terminate=True)
        try:
            if windows_api.wait_for_handle(handle, 0.0):
                return
            creation = windows_api.process_times(handle)
            if render_creation_identity(item.pid, creation) != str(
                item.creation_identity
            ):
                return
            windows_api.terminate_process(handle, _FORCED_EXIT_CODE)
            windows_api.wait_for_handle(handle, _PROCESS_EXIT_BOUND_SECONDS)
        finally:
            windows_api.close_handle(handle)


@pytest.fixture
def planted(tmp_path: Path) -> Path:
    """The EVIDENCE pre-state planted and closed, so the child owns the connection."""
    fixture = FinalizationFixture.open(tmp_path, clock=FixedClock(INSTANT))
    try:
        fixture.plant_evidence_prestate(files=_TWO_FILES)
    finally:
        fixture.close()
    return tmp_path


def _reopen(tmp_path: Path, *, production: bool = False) -> FinalizationFixture:
    return FinalizationFixture.open(
        tmp_path, clock=FixedClock(INSTANT), reuse=True, production=production
    )


@pytest.fixture
def planted_result(tmp_path: Path) -> Path:
    """Task 7: the production RESULT pre-state planted and closed, so the child
    owns the connection."""
    fixture = FinalizationFixture.open(
        tmp_path, clock=FixedClock(INSTANT), production=True
    )
    try:
        fixture.plant_result_prestate()
    finally:
        fixture.close()
    return tmp_path


def test_child_killed_after_moved_recovers_evidence_to_registered(
    planted: Path,
) -> None:
    with ProcessHolder(planted, "after_moved") as held:
        assert held.holder_pid is not None
    assert held.exit_code == _FORCED_EXIT_CODE
    assert held.launcher_exit is not None
    assert held.trace[-3:] == ["launcher-reaped", "no-descendant-survives", "closed"]
    reopened = _reopen(planted)
    try:
        before = reopened.durable()
        assert before.journal_state == "MOVED"
        assert before.refs == ()
        assert len(before.object_blobs) == 2
        assert before.audit_actions[-1] == "FINALIZATION_MOVED"
        # The dead child's lease is unexpired at the restart: deferred, untouched.
        assert _ok(reopened.recover()).deferred == 1
        assert reopened.durable().journal == before.journal
        reopened.advance_clock(EVIDENCE_LEASE_SECONDS + 1)
        report = _ok(reopened.recover())
        assert (report.resumed, report.registered) == (1, 1)
        after = reopened.durable()
        assert after.journal_state == "REGISTERED"
        assert len(after.refs) == 2
        assert after.run_revision == 4  # the run row untouched (29.4)
        report_after = reopened.database.consistency_report()
        assert report_after.dangling_diagnostic_references == 0
    finally:
        reopened.close()


def test_child_killed_inside_registered_leaves_moved(planted: Path) -> None:
    with ProcessHolder(planted, "inside_registered") as held:
        assert held.holder_pid is not None
    assert held.exit_code == _FORCED_EXIT_CODE
    assert held.trace[-3:] == ["launcher-reaped", "no-descendant-survives", "closed"]
    reopened = _reopen(planted)
    try:
        before = reopened.durable()
        # T3 was open with its first insert when the holder died: exactly MOVED,
        # never a reference without its commit.
        assert before.journal_state == "MOVED"
        assert before.refs == ()
        assert before.run_artifacts == ()
        assert "FINALIZATION_REGISTERED" not in before.audit_actions
        reopened.advance_clock(EVIDENCE_LEASE_SECONDS + 1)  # the lease expires first
        report = _ok(reopened.recover())
        assert (report.resumed, report.registered) == (1, 1)
        after = reopened.durable()
        assert after.journal_state == "REGISTERED"
        assert len(after.refs) == 2
        request = sample_evidence_request(
            [candidate.candidate_artifact_id for candidate in after.candidates]
        )
        assert request.finalization_purpose == "EVIDENCE"
    finally:
        reopened.close()


def test_child_killed_after_moved_recovers_result_to_registered(
    planted_result: Path,
) -> None:
    """Task 7, CP-5 with a real child over the production composition: the child
    rebuilt the RESULT request from the planted state through the production
    validator and was killed between T2 and T3; the parent recovers the ``MOVED``
    journal to ``REGISTERED`` success -- references, run manifest, member links
    and the run ``SUCCEEDED`` -- once the dead child's lease has expired."""
    with ProcessHolder(planted_result, "after_moved", "RESULT") as held:
        assert held.holder_pid is not None
    assert held.exit_code == _FORCED_EXIT_CODE
    assert held.launcher_exit is not None
    assert held.trace[-3:] == ["launcher-reaped", "no-descendant-survives", "closed"]
    reopened = _reopen(planted_result, production=True)
    try:
        before = reopened.durable()
        assert before.journal_state == "MOVED"
        assert before.refs == ()
        assert before.run_manifests == ()
        assert len(before.object_blobs) == 2
        assert before.run_state == "RUNNING"
        assert before.run_revision == 5  # the deadline snapshot of T1
        assert before.audit_actions[-1] == "FINALIZATION_MOVED"
        # The dead child's lease is unexpired at the restart: deferred, untouched.
        assert _ok(reopened.recover()).deferred == 1
        assert reopened.durable().journal == before.journal
        reopened.advance_clock(RESULT_LEASE_SECONDS + 1)
        report = _ok(reopened.recover())
        assert (report.resumed, report.registered, report.abandoned) == (1, 1, 0)
        after = reopened.durable()
        assert after.journal_state == "REGISTERED"
        assert len(after.refs) == 2
        assert after.run_state == "SUCCEEDED"
        assert after.run_revision == 6
        (manifest,) = after.run_manifests
        assert manifest.run_id == RUN_ID
        members = [
            link
            for link in after.run_artifacts
            if link.link_role == "RESULT_MANIFEST_MEMBER"
        ]
        assert len(members) == 2
        # The deferred pass left its summary row; the resuming pass took the
        # lease over, registered through the production registrar and closed.
        assert after.audit_actions[-6:] == (
            "FINALIZATION_LEASE_ACQUIRED",
            "RUN_MANIFEST_REGISTERED",
            "RUN_SUCCEEDED",
            "FINALIZATION_REGISTERED",
            "RETENTION_DELETED",
            "RECONCILIATION_FINALIZATION_RESUMED",
        )
        request_path = reopened.roots.runtime_root / INVOCATION_ID / "request.json"
        assert not request_path.exists()
        report_after = reopened.database.consistency_report()
        assert report_after.dangling_diagnostic_references == 0
        assert report_after.success_without_manifest == 0
    finally:
        reopened.close()
