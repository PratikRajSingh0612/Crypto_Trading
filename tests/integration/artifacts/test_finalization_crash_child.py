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

Stage 9 Task 8 adds the flow-driven twin of those cells and, with it, this
module to Task 8's file map. The plan requires the proof: Task 8's
Windows-specific tests name "The crash child row through the flow" (plan
8:2753), and section 5 closes its ownership paragraph with "Task 8 re-proves
all of them through the flow" (5:1645-1646; "them" are the RESULT cells of
Task 7, re-proven in process by ``test_stage9_supervised_finalization.py``,
so 8:2753 is the direct authority for the child). Task 8's "Files created" and
"Files modified" paragraphs (8:2715-2725) name only the two new test modules
and the two support modules, none of which is a ``subprocess`` importer, and
its guard paragraph reads "no source file; no new importer" (8:2731): the Stage
6 guard pins the ``subprocess`` importers exactly
(``tests/safety/test_stage6_boundaries.py::_SUBPROCESS_IMPORTERS``) and this
module is the one admitted finalization crash child. A flow-driven child
therefore lives here or needs a fourteenth importer, which 8:2731 rules out;
the omission from the file map is the plan's own inconsistency, recorded here
rather than resolved by widening the allowlist. The second fixed program
(``_FLOW_CHILD_PROGRAM``) drives ``FinalizingSupervisedFlow`` end to end inside
the child -- the describe row, ``prepare_run`` and ``invoke`` through the
production ``WindowsProcessSupervisor``, then ``conclude_and_finalize`` through
the production conclusion -- and blocks at ``after_moved`` or
``inside_registered`` of the first probed finalization (the RESULT finalization
of the success row, the evidence finalization of the checksum-mismatch row);
the parent reuses the same ``ProcessHolder`` discipline and reopens the flow.

This module is the thirteenth ``subprocess`` importer of the Stage 6 allowlist
(plan 2.6). Nothing here sleeps on a wall clock, imports ``threading`` (the
child's wait is text inside the ``-c`` program) or kills by pid.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
from pathlib import Path
from types import TracebackType
from typing import IO, Final, Self

import pytest

from crypto_lab.artifacts.finalizer import EVIDENCE_LEASE_SECONDS, RESULT_LEASE_SECONDS
from crypto_lab.artifacts.journal import (
    FinalizationJournalEntry,
    FinalizationJournalState,
)
from crypto_lab.artifacts.models import (
    ArtifactFinalizationPurpose,
    ArtifactRef,
    CandidateArtifactProducerKind,
    CandidateArtifactState,
)
from crypto_lab.artifacts.ownership import RunArtifactOwner
from crypto_lab.domain.lifecycle import CommandInvocationState, EngineRunState
from crypto_lab.domain.results import Result, Success
from crypto_lab.experiments.finalization import (
    RESULT_MANIFEST_MEMBER,
    RUN_EVIDENCE,
    STDERR_KIND,
)
from crypto_lab.experiments.run_manifest import run_manifest_hash
from crypto_lab.process_supervision import windows_api
from crypto_lab.process_supervision.models import (
    FORCED_TERMINATION_EXIT_CODE,
    DescendantIdentity,
    render_creation_identity,
)
from doubles.artifacts import DurableState, sample_evidence_request
from doubles.experiments import INSTANT, INVOCATION_ID, RUN_ID, FixedClock
from persistence_support.artifacts import (
    FINALIZATION_TIMEOUT_SECONDS,
    FinalizationFixture,
    FinalizingSupervisedFlow,
)

_J: Final = FinalizationJournalState
_P: Final = ArtifactFinalizationPurpose
_R: Final = EngineRunState
_S: Final = CandidateArtifactState
_TWO_FILES = {
    "stderr.txt": b"engine stderr line one\nengine stderr line two\n",
    "protocol.txt": b"engine protocol line one\n",
}
_TESTS_ROOT: Final = Path(__file__).resolve().parents[2]
#: The prelude both one-line programs share: insert the tests root and build the
#: probe that reports ``HELD <pid>`` and blocks at the named point. No ``def``
#: and no ``class`` statement: a compound statement would end the line.
_PROBE_PRELUDE: Final = (
    "import os, sys, threading; "
    "sys.path.insert(0, sys.argv[3]); "
    "from pathlib import Path; "
    "hold = lambda *_: (sys.stdout.write('HELD %d\\n' % os.getpid()), "
    "sys.stdout.flush(), threading.Event().wait()); "
    "noop = lambda *_: None; "
    "names = ['before_prepared', 'after_prepared', 'before_move', 'after_move', "
    "'before_moved', 'after_moved', 'before_registered', 'inside_registered', "
    "'after_registered', 'after_close']; "
    "Probe = type('Probe', (), {name: (hold if name == sys.argv[2] else noop) "
    "for name in names}); "
)
#: The fixture child (Tasks 6 and 7): open the planted fixture on the path
#: argument (the production composition for a ``RESULT`` purpose), rebuild the
#: EVIDENCE or RESULT request from the committed rows and finalize.
_CHILD_PROGRAM: Final = _PROBE_PRELUDE + (
    "from doubles.experiments import INSTANT, FixedClock; "
    "from doubles.artifacts import INVOCATION_CORRELATION, RUN_OWNER; "
    "from persistence_support.artifacts import FinalizationFixture; "
    "result = sys.argv[4] == 'RESULT'; "
    "fixture = FinalizationFixture.open(Path(sys.argv[1]), "
    "clock=FixedClock(INSTANT), reuse=True, production=result); "
    "request = fixture.result_request_for(RUN_OWNER) if result else "
    "fixture.evidence_request_for(RUN_OWNER, correlation=INVOCATION_CORRELATION); "
    "fixture.finalize(request, probe=Probe()); "
    "fixture.close()"
)
#: The flow child (Task 8): compose ``FinalizingSupervisedFlow`` on the path
#: argument, drive the describe row and the success (``RESULT``) or
#: checksum-mismatch (``EVIDENCE``) run through the production supervisor, then
#: conclude through the production composition with the blocking probe; the
#: first probed finalization is the RESULT one of the success row and the
#: evidence one of the failure row (the describe conclusion takes no probe).
_FLOW_CHILD_PROGRAM: Final = _PROBE_PRELUDE + (
    "from persistence_support.artifacts import FinalizingSupervisedFlow; "
    "flow = FinalizingSupervisedFlow.open(Path(sys.argv[1])); "
    "flow.describe(flow.scenario('row01-conformant-describe')); "
    "row = flow.scenario('row03-conformant-run' if sys.argv[4] == 'RESULT' "
    "else 'row36-checksum-mismatch-run'); "
    "run = flow.prepare_run(row); "
    "outcome = flow.invoke(row, run); "
    "flow.conclude_and_finalize(row, run, outcome, probe=Probe()); "
    "flow.close()"
)
_RAW_BYTE_NAMES: Final = frozenset(
    {"request.json", "output.json", "adapter-result-manifest.json"}
)
_READINESS_LIMIT: Final = 64
_READINESS: Final = re.compile(rb"HELD ([1-9][0-9]{0,9})\r?\n")
_PROCESS_EXIT_BOUND_SECONDS: Final = 30.0
_FORCED_EXIT_CODE: Final = FORCED_TERMINATION_EXIT_CODE


def _ok[T](result: Result[T]) -> T:
    assert isinstance(result, Success), result
    return result.value


def _launch_child(
    tmp_path: Path,
    point: str,
    purpose: str = "EVIDENCE",
    program: str = _CHILD_PROGRAM,
) -> subprocess.Popen[bytes]:
    """The committed launch shape: ``sys.executable -I -B -c``, list argv, no
    shell; ``program`` is one of the two fixed one-line programs above."""
    assert program in (_CHILD_PROGRAM, _FLOW_CHILD_PROGRAM)
    return subprocess.Popen(  # noqa: S603 - reviewed list argv, no shell
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            program,
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

    def __init__(
        self,
        tmp_path: Path,
        point: str,
        purpose: str = "EVIDENCE",
        *,
        program: str = _CHILD_PROGRAM,
    ) -> None:
        self._tmp_path = tmp_path
        self._point = point
        self._purpose = purpose
        self._program = program
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
            self._launched = _launch_child(
                self._tmp_path, self._point, self._purpose, self._program
            )
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


# --------------------------------------------------------------------------
# Task 8: CP-5 and CP-6 through the flow, in a real child
# --------------------------------------------------------------------------


def _run_journal(
    state: DurableState, purpose: ArtifactFinalizationPurpose, run_id: str
) -> FinalizationJournalEntry:
    """The run's one journal entry of ``purpose`` (the describe row's
    ``ADAPTER``-owned evidence journal is excluded)."""
    entries = [
        entry
        for entry in state.journal
        if entry.finalization_purpose is purpose
        and isinstance(entry.owner, RunArtifactOwner)
        and entry.owner.run_id == run_id
    ]
    assert len(entries) == 1, entries
    return entries[0]


def _run_journals(
    state: DurableState, purpose: ArtifactFinalizationPurpose, run_id: str
) -> tuple[FinalizationJournalState, ...]:
    return tuple(
        entry.state
        for entry in state.journal
        if entry.finalization_purpose is purpose
        and isinstance(entry.owner, RunArtifactOwner)
        and entry.owner.run_id == run_id
    )


def _run_refs(
    state: DurableState, purpose: ArtifactFinalizationPurpose, run_id: str
) -> tuple[ArtifactRef, ...]:
    return tuple(
        ref
        for ref in state.refs
        if ref.finalization_purpose is purpose
        and isinstance(ref.owner, RunArtifactOwner)
        and ref.owner.run_id == run_id
    )


def _raw_bytes_under(state: DurableState, invocation_id: str) -> list[str]:
    return [
        name
        for name in state.command_root_files
        if name.startswith(f"{invocation_id}/")
        and name.rsplit("/", 1)[-1] in _RAW_BYTE_NAMES
    ]


def _in_order(actions: tuple[str, ...], expected: tuple[str, ...]) -> bool:
    """``expected`` is a subsequence of ``actions``."""
    position = 0
    for action in actions:
        if position < len(expected) and action == expected[position]:
            position += 1
    return position == len(expected)


@pytest.mark.parametrize("purpose", ["RESULT", "EVIDENCE"])
@pytest.mark.parametrize("point", ["after_moved", "inside_registered"])
def test_flow_child_killed_defers_then_recovers(
    tmp_path: Path, point: str, purpose: str
) -> None:
    """Plan 5.1 CP-5 and CP-6 through ``FinalizingSupervisedFlow`` in a real
    child: the child drove the describe row and the run through the production
    supervisor and was killed inside the production conclusion -- between T2 and
    T3 (``after_moved``) or with T3 open after its first insert
    (``inside_registered``) -- of the RESULT finalization (success row) or the
    evidence finalization (checksum-mismatch row). The parent proves the durable
    crash boundary, that a restart defers the unexpired lease untouched, that
    recovery after the lease expires registers within the pinned deadline, and
    that a further pass changes nothing."""
    result_cell = purpose == "RESULT"
    with ProcessHolder(tmp_path, point, purpose, program=_FLOW_CHILD_PROGRAM) as held:
        assert held.holder_pid is not None
        assert held.trace[-1] == "holder-held"
    assert held.exit_code == _FORCED_EXIT_CODE
    assert held.launcher_exit is not None
    assert held.trace[-6:] == [
        "holder-held",
        "holder-terminated",
        "holder-signaled",
        "launcher-reaped",
        "no-descendant-survives",
        "closed",
    ]
    reopened = FinalizingSupervisedFlow.reopen(tmp_path)
    try:
        assert reopened.quick_check() == "ok"
        (run,) = reopened.fresh_runs()
        before = reopened.durable(run.run_id)
        assert before.invocation is not None
        invocation_id = before.invocation.invocation_id
        assert before.invocation.state is CommandInvocationState.EXITED
        # The durable crash boundary: exactly MOVED, never a reference or a
        # manifest without its commit; the moved blobs are in place.
        entry = _run_journal(before, _P[purpose], run.run_id)
        assert entry.state is _J.MOVED
        planned = {move.expected_sha256 for move in entry.planned_paths}
        assert len(planned) == (2 if result_cell else 3)
        assert planned <= set(before.object_blobs)
        assert _run_refs(before, _P[purpose], run.run_id) == ()
        assert before.run_manifests == ()
        assert before.audit_actions[-1] == "FINALIZATION_MOVED"
        # The audit history equals the durable history (the counts are flow-wide:
        # the describe row's evidence journal is REGISTERED, this one is MOVED),
        # so a rolled-back T3 left no FINALIZATION_REGISTERED row behind.
        assert before.audit_actions.count("FINALIZATION_REGISTERED") == len(
            [item for item in before.journal if item.state is _J.REGISTERED]
        )
        assert before.audit_actions.count("FINALIZATION_MOVED") == len(before.journal)
        assert _raw_bytes_under(before, invocation_id) != []
        if result_cell:
            assert run.state is _R.RUNNING
            assert before.run_deadline is not None
            assert "RUN_SUCCEEDED" not in before.audit_actions
            assert _run_journals(before, _P.EVIDENCE, run.run_id) == ()
        else:
            assert run.state is _R.FAILED
            assert _run_journals(before, _P.RESULT, run.run_id) == ()
        # A restart alone takes no unexpired lease: deferred, the journal and the
        # run untouched. In the RESULT cell the crashed conclusion had already
        # staged the run's core evidence (plan 4.4 step 2) and never leased it;
        # under the corrected RV-10 (the ruling of 2026-11-10) that independent
        # CP-1 group resumes and registers in this same pass, so the deferred
        # RESULT journal is the one open journal beside one registered one.
        deferred = reopened.recover()
        assert deferred.process.entries == ()
        assert deferred.artifacts.deferred == 1
        assert (deferred.artifacts.resumed, deferred.artifacts.registered) == (
            (1, 1) if result_cell else (0, 0)
        )
        assert deferred.artifacts.abandoned == 0
        after_deferral = reopened.durable(run.run_id)
        assert _run_journal(after_deferral, _P[purpose], run.run_id) == entry
        assert after_deferral.run == run
        assert _run_refs(after_deferral, _P[purpose], run.run_id) == ()
        # The lease expires inside the pinned finalization deadline, so the
        # takeover registers rather than times out.
        lease = RESULT_LEASE_SECONDS if result_cell else EVIDENCE_LEASE_SECONDS
        assert lease + 1 < FINALIZATION_TIMEOUT_SECONDS
        reopened.clock.advance(lease + 1)
        reports = reopened.recover()
        assert reports.process.entries == ()
        assert (reports.artifacts.resumed, reports.artifacts.registered) == (1, 1)
        assert reports.artifacts.abandoned == 0
        after = reopened.durable(run.run_id)
        registered = _run_journal(after, _P[purpose], run.run_id)
        assert registered.state is _J.REGISTERED
        assert registered.finalization_id == entry.finalization_id
        refs = _run_refs(after, _P[purpose], run.run_id)
        assert {ref.content_hash for ref in refs} == planned
        assert len(refs) == len(planned)
        # Plan 5.1 after recovery: the blob at every finalized path hashes to its
        # reference (``hashlib``, independent of the production hasher), staging
        # is empty and ``objects/`` holds exactly the registered blobs.
        for ref in refs:
            blob = reopened.store.finalized_path_for(ref.content_hash)
            assert hashlib.sha256(blob.read_bytes()).hexdigest() == ref.content_hash
            assert blob.stat().st_size == ref.size_bytes
        assert after.staging_files == ()
        assert set(after.object_blobs) == {ref.content_hash for ref in after.refs}
        # No candidate is left open; every FINALIZING candidate is mapped.
        mapped = {ref.source_candidate_artifact_id for ref in after.refs}
        for candidate in after.candidates:
            assert candidate.state not in (_S.CANDIDATE, _S.VALIDATING), candidate
            if candidate.state is _S.FINALIZING:
                assert candidate.candidate_artifact_id in mapped, candidate
        # Audit history equals durable history after recovery, flow-wide.
        assert after.audit_actions.count("FINALIZATION_REGISTERED") == len(
            [item for item in after.journal if item.state is _J.REGISTERED]
        )
        assert after.audit_actions.count("RUN_MANIFEST_REGISTERED") == len(
            after.run_manifests
        )
        assert after.audit_actions.count("RUN_SUCCEEDED") == len(after.run_manifests)
        new_actions = after.audit_actions[len(after_deferral.audit_actions) :]
        assert new_actions[-1] == "RECONCILIATION_FINALIZATION_RESUMED"
        assert _raw_bytes_under(after, invocation_id) == []
        if result_cell:
            assert after.run_state == "SUCCEEDED"
            assert after.run_revision == run.revision + 1
            (manifest_row,) = after.run_manifests
            assert manifest_row.run_id == run.run_id
            manifest = reopened.fresh_manifest(run.run_id)
            assert manifest is not None
            assert run_manifest_hash(manifest) == manifest_row.run_manifest_hash
            assert {ref.artifact_id for ref in manifest.artifact_refs} == {
                ref.artifact_id for ref in refs
            }
            members = [
                link
                for link in after.run_artifacts
                if link.link_role == RESULT_MANIFEST_MEMBER
            ]
            assert {link.artifact_id for link in members} == {
                ref.artifact_id for ref in refs
            }
            resumed_actions: tuple[str, ...] = (
                "FINALIZATION_LEASE_ACQUIRED",
                "RUN_MANIFEST_REGISTERED",
                "RUN_SUCCEEDED",
                "FINALIZATION_REGISTERED",
                "RECONCILIATION_FINALIZATION_RESUMED",
            )
            assert _in_order(new_actions, resumed_actions), new_actions
            for action in resumed_actions:
                assert new_actions.count(action) == 1, (action, new_actions)
            # The run's core evidence was staged by the crashed conclusion and
            # never leased: plan 5.1 CP-1 (EVIDENCE) resumed it independently
            # in the deferred pass (the corrected RV-10), so every core candidate
            # is FINALIZING and mapped, its journal REGISTERED, and nothing of
            # this run is quarantined.
            core = [
                candidate
                for candidate in after.candidates
                if candidate.producer_kind is CandidateArtifactProducerKind.CORE
                and isinstance(candidate.owner, RunArtifactOwner)
                and candidate.owner.run_id == run.run_id
            ]
            assert len(core) == 3
            for candidate in core:
                assert candidate.state is _S.FINALIZING, candidate
                assert candidate.candidate_artifact_id in mapped
            assert _run_journals(after, _P.EVIDENCE, run.run_id) == (_J.REGISTERED,)
            assert after.quarantine_entries == ()
        else:
            # 29.4: the evidence registered without touching the run.
            assert after.run == run
            assert after.run_manifests == ()
            assert _run_journals(after, _P.RESULT, run.run_id) == ()
            assert len(refs) == 3
            evidence_links = [
                link for link in after.run_artifacts if link.link_role == RUN_EVIDENCE
            ]
            assert {link.artifact_id for link in evidence_links} == {
                ref.artifact_id for ref in refs
            }
            (stderr_ref,) = [ref for ref in refs if ref.artifact_kind == STDERR_KIND]
            assert after.invocation is not None
            assert after.invocation.stderr_artifact_id == stderr_ref.artifact_id
            adapter_states = [
                candidate.state
                for candidate in after.candidates
                if candidate.producer_kind is CandidateArtifactProducerKind.ADAPTER
            ]
            assert adapter_states == [_S.QUARANTINED, _S.QUARANTINED]
            assert len(after.quarantine_entries) == 2
            resumed_actions = (
                "FINALIZATION_LEASE_ACQUIRED",
                "FINALIZATION_REGISTERED",
                "RECONCILIATION_FINALIZATION_RESUMED",
            )
            assert _in_order(new_actions, resumed_actions), new_actions
            for action in resumed_actions:
                assert new_actions.count(action) == 1, (action, new_actions)
        # Idempotence: a further pass changes nothing but its own summary row.
        snapshot = reopened.durable(run.run_id)
        again = reopened.recover()
        assert again.artifacts.changes == 0
        preserved = reopened.durable(run.run_id)
        assert preserved.journal == snapshot.journal
        assert preserved.candidates == snapshot.candidates
        assert preserved.refs == snapshot.refs
        assert preserved.run == snapshot.run
        assert preserved.run_manifests == snapshot.run_manifests
        assert preserved.object_blobs == snapshot.object_blobs
        assert preserved.quarantine_entries == snapshot.quarantine_entries
        assert preserved.command_root_files == snapshot.command_root_files
        assert len(preserved.audit_events) == len(snapshot.audit_events) + 1
        assert reopened.quick_check() == "ok"
        report = reopened.consistency_report()
        assert report.dangling_diagnostic_references == 0
        assert report.success_without_manifest == 0
        assert report.unmapped_finalizing == 0
    finally:
        reopened.close(keep_command_roots=True)
