"""Stage 9 Task 6 and Task 7, plan 5.1: the seven EVIDENCE crash cells, the six
RESULT durable-state halves and the seven RESULT success cells over the SQLite
``FinalizationFixture`` (requirement rows R19.2-10, R19.3-07..09, T28.3-07,
T28.3-10, T28.3-11, A33.5-01, R23.3.1-18; Task 7: R29.3-08..10, T28.3-06).

"Crash" is ``CrashingProbe`` in process -- a ``BaseException`` the finalizer's
``except Exception`` boundary never absorbs, so the durable state is exactly the
state a killed process would leave; CP-5 and CP-6 are re-proven with a real
child in ``test_finalization_crash_child.py``. Durable state is asserted through
fresh read-only sessions after ``reopen()``, which keeps every root. A cell that
leaves an open journal lets its lease expire before recovery: a restart alone
takes no unexpired lease (the RESULT lease ruling of 2026-11-08), and the pass
then takes the lease over by one audited compare-and-swap -- the
``FINALIZATION_LEASE_ACQUIRED`` row at the point the resume began. The RESULT
halves assert the state before recovery and drive the failing recovery
branches of plan 5.1 -- a hash mismatch and a passed deadline -- over the Task 6
memory registrar, which refuses success by construction; the RESULT success
cells (``test_cp{1..7}_result_success``) run over the production registrar and
recovery validator (``production``) and recover to ``REGISTERED`` success. Each
cell asserts the six facets of T28.3-12: rows, journal, references, run and
invocation, audit history equal to durable history, and the filesystem.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from crypto_lab.artifacts.diagnostics import (
    ARTIFACT_FINALIZATION_TIMED_OUT,
    ARTIFACT_RESULT_MANIFEST_INVALID,
    ARTIFACT_VALIDATION_FAILED,
)
from crypto_lab.artifacts.finalizer import EVIDENCE_LEASE_SECONDS, RESULT_LEASE_SECONDS
from crypto_lab.artifacts.journal import FinalizationJournalEntry
from crypto_lab.artifacts.manifest import ArtifactManifest
from crypto_lab.artifacts.models import ArtifactRef
from crypto_lab.artifacts.ports import RegistrationUnitOfWork, ResultRegistration
from crypto_lab.domain.hashing import sha256_bytes
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.experiments.run_manifest import RunManifest, run_manifest_hash
from crypto_lab.persistence.diagnostics import WRITE_FAILED, persistence_failure
from doubles.artifacts import (
    RESULT_FILES,
    RESULT_TIMEOUT_SECONDS,
    CrashingProbe,
    DurableState,
    FinalizationCrash,
    MemoryRegistrar,
    ResultPlan,
)
from doubles.experiments import INSTANT, FixedClock
from persistence_support.artifacts import FinalizationFixture

_TWO_FILES = {
    "stderr.txt": b"engine stderr line one\nengine stderr line two\n",
    "protocol.txt": b"engine protocol line one\n",
}
_EVIDENCE_HASHES = frozenset(sha256_bytes(data) for data in _TWO_FILES.values())
_RESULT_HASHES = frozenset(sha256_bytes(data) for data in RESULT_FILES.values())
_T1_ACTIONS = (
    "ARTIFACT_VALIDATED",
    "ARTIFACT_VALIDATED",
    "FINALIZATION_LEASE_ACQUIRED",
    "FINALIZATION_PREPARED",
)
_SUMMARY = "RECONCILIATION_FINALIZATION_RESUMED"
#: The audit history of an EVIDENCE recovery by where the resume began: from
#: staging (no journal, no takeover), from a ``PREPARED`` journal (the takeover
#: precedes T2) and from a ``MOVED`` journal (the takeover precedes T3).
_RECOVERED_FROM_STAGING = (
    *_T1_ACTIONS,
    "FINALIZATION_MOVED",
    "FINALIZATION_REGISTERED",
    _SUMMARY,
)
_RECOVERED_FROM_PREPARED = (
    *_T1_ACTIONS,
    "FINALIZATION_LEASE_ACQUIRED",
    "FINALIZATION_MOVED",
    "FINALIZATION_REGISTERED",
    _SUMMARY,
)
_RECOVERED_FROM_MOVED = (
    *_T1_ACTIONS,
    "FINALIZATION_MOVED",
    "FINALIZATION_LEASE_ACQUIRED",
    "FINALIZATION_REGISTERED",
    _SUMMARY,
)


def _ok[T](result: Result[T]) -> T:
    assert isinstance(result, Success), (
        "; ".join(f"{item.error_code}: {item.message}" for item in result.diagnostics)
        if isinstance(result, Failure)
        else repr(result)
    )
    return result.value


def _code(result: object) -> str:
    assert isinstance(result, Failure), result
    return result.diagnostics[0].error_code


@pytest.fixture
def fixture(tmp_path: Path) -> Iterator[FinalizationFixture]:
    opened = FinalizationFixture.open(tmp_path, clock=FixedClock(INSTANT))
    try:
        yield opened
    finally:
        opened.close()


@pytest.fixture
def production(tmp_path: Path) -> Iterator[FinalizationFixture]:
    """Task 7: the production registrar, validator and auditor over SQLite."""
    opened = FinalizationFixture.open(
        tmp_path, clock=FixedClock(INSTANT), production=True
    )
    try:
        yield opened
    finally:
        opened.close()


def _crash(
    fixture: FinalizationFixture, request: object, point: str, index: int = 0
) -> None:
    with pytest.raises(FinalizationCrash):
        fixture.finalize(request, probe=CrashingProbe(point, index))  # type: ignore[arg-type]


def _assert_no_dangling(fixture: FinalizationFixture) -> None:
    report = fixture.database.consistency_report()
    assert report.dangling_diagnostic_references == 0
    assert report.success_without_manifest == 0


def _assert_evidence_registered(
    fixture: FinalizationFixture, after: DurableState, *, audit_actions: tuple[str, ...]
) -> None:
    assert after.journal_state == "REGISTERED"
    assert len(after.refs) == 2
    assert {ref.content_hash for ref in after.refs} == _EVIDENCE_HASHES
    assert set(after.object_blobs) == _EVIDENCE_HASHES
    assert after.staging_files == ()
    assert all(state == "FINALIZING" for state in after.candidate_states.values())
    assert after.run_state == "RUNNING"
    assert after.run_revision == 4  # EVIDENCE never touches the run row (29.4)
    assert after.run_deadline is None
    assert after.invocation is not None
    assert after.invocation.state.value == "EXITED"
    assert after.audit_actions == audit_actions
    assert after.quarantine_entries == ()
    _assert_no_dangling(fixture)


def _expire_lease(fixture: FinalizationFixture) -> None:
    """A restart alone takes no unexpired lease: the EVIDENCE lease expires
    before the pass that recovers the cell's journal."""
    fixture.advance_clock(EVIDENCE_LEASE_SECONDS + 1)


# --------------------------------------------------------------------------
# EVIDENCE cells CP-1 .. CP-7
# --------------------------------------------------------------------------


def test_cp1_evidence(fixture: FinalizationFixture) -> None:
    plan = fixture.plant_evidence_prestate(files=_TWO_FILES)
    _crash(fixture, plan.request, "before_prepared")
    before = fixture.durable()
    assert before.journal == ()
    assert all(state == "VALIDATING" for state in before.candidate_states.values())
    assert len(before.staging_files) == 2
    assert before.object_blobs == ()
    assert before.run_state == "RUNNING"
    assert before.run_deadline is None
    assert before.audit_actions == ()
    fixture.reopen()
    report = _ok(fixture.recover())
    assert (report.resumed, report.registered, report.abandoned) == (1, 1, 0)
    _assert_evidence_registered(
        fixture, fixture.durable(), audit_actions=_RECOVERED_FROM_STAGING
    )


def test_cp2_evidence(fixture: FinalizationFixture) -> None:
    plan = fixture.plant_evidence_prestate(files=_TWO_FILES)
    _crash(fixture, plan.request, "after_prepared")
    before = fixture.durable()
    assert before.journal_state == "PREPARED"
    assert all(state == "FINALIZING" for state in before.candidate_states.values())
    assert len(before.staging_files) == 2
    assert before.audit_actions == _T1_ACTIONS
    _expire_lease(fixture)
    fixture.reopen()
    report = _ok(fixture.recover())
    assert (report.resumed, report.registered) == (1, 1)
    _assert_evidence_registered(
        fixture, fixture.durable(), audit_actions=_RECOVERED_FROM_PREPARED
    )


def test_cp3_evidence(fixture: FinalizationFixture) -> None:
    plan = fixture.plant_evidence_prestate(files=_TWO_FILES)
    _crash(fixture, plan.request, "after_move", 0)
    before = fixture.durable()
    assert before.journal_state == "PREPARED"
    assert len(before.object_blobs) == 1
    assert len(before.staging_files) == 1
    _expire_lease(fixture)
    fixture.reopen()
    report = _ok(fixture.recover())
    assert (report.resumed, report.registered) == (1, 1)
    _assert_evidence_registered(
        fixture, fixture.durable(), audit_actions=_RECOVERED_FROM_PREPARED
    )


def test_cp4_evidence(fixture: FinalizationFixture) -> None:
    plan = fixture.plant_evidence_prestate(files=_TWO_FILES)
    _crash(fixture, plan.request, "before_moved")
    before = fixture.durable()
    assert before.journal_state == "PREPARED"
    assert set(before.object_blobs) == _EVIDENCE_HASHES
    assert before.staging_files == ()
    _expire_lease(fixture)
    fixture.reopen()
    report = _ok(fixture.recover())
    assert (report.resumed, report.registered) == (1, 1)
    _assert_evidence_registered(
        fixture, fixture.durable(), audit_actions=_RECOVERED_FROM_PREPARED
    )


def test_cp5_evidence(fixture: FinalizationFixture) -> None:
    plan = fixture.plant_evidence_prestate(files=_TWO_FILES)
    _crash(fixture, plan.request, "after_moved")
    before = fixture.durable()
    assert before.journal_state == "MOVED"
    (entry,) = before.journal
    assert len(entry.observed) == 2
    assert before.refs == ()
    assert before.audit_actions == (*_T1_ACTIONS, "FINALIZATION_MOVED")
    _expire_lease(fixture)
    fixture.reopen()
    report = _ok(fixture.recover())
    assert (report.resumed, report.registered) == (1, 1)
    _assert_evidence_registered(
        fixture, fixture.durable(), audit_actions=_RECOVERED_FROM_MOVED
    )


def test_cp6_evidence(fixture: FinalizationFixture) -> None:
    plan = fixture.plant_evidence_prestate(files=_TWO_FILES)
    _crash(fixture, plan.request, "inside_registered")
    before = fixture.durable()
    # T3 rolled back through the scope's ``finally``: exactly MOVED, never a
    # reference without its commit (SQLite atomicity + reading 11).
    assert before.journal_state == "MOVED"
    assert before.refs == ()
    assert before.run_artifacts == ()
    assert "FINALIZATION_REGISTERED" not in before.audit_actions
    assert fixture.harness.open_transactions() == ()
    _expire_lease(fixture)
    fixture.reopen()
    report = _ok(fixture.recover())
    assert (report.resumed, report.registered) == (1, 1)
    _assert_evidence_registered(
        fixture, fixture.durable(), audit_actions=_RECOVERED_FROM_MOVED
    )


def test_cp6_evidence_rolled_back_t3_leaves_no_projection(
    fixture: FinalizationFixture,
) -> None:
    """Plan 6.2: the projection is written exclusive-create after the blob is
    registered, so the rolled-back T3 of CP-6 leaves no ``manifests/`` file that
    could pass for a committed reference; the committed recovery writes one per
    reference and each restates the row's manifest."""
    plan = fixture.plant_evidence_prestate(files=_TWO_FILES)
    _crash(fixture, plan.request, "inside_registered")
    manifests_root = fixture.roots.store.manifests_root
    assert tuple(manifests_root.glob("*.json")) == ()
    assert fixture.durable().refs == ()
    _expire_lease(fixture)
    fixture.reopen()
    _ok(fixture.recover())
    after = fixture.durable()
    assert len(after.refs) == 2
    stored = {
        manifest.artifact_id: manifest
        for manifest in fixture.harness.committed_manifests()
    }
    for ref in after.refs:
        projection = fixture.roots.store.manifest_path_for(ref.artifact_id)
        assert projection.is_file()
        restated = ArtifactManifest.model_validate_json(projection.read_bytes())
        assert restated == stored[ref.artifact_id]
    assert len(tuple(manifests_root.glob("*.json"))) == 2


def test_cp7_evidence(fixture: FinalizationFixture) -> None:
    result_plan = fixture.plant_result_prestate()
    plan = fixture.plant_evidence_prestate(files=_TWO_FILES)
    _crash(fixture, plan.request, "after_registered")
    before = fixture.durable()
    assert before.journal_state == "REGISTERED"
    assert len(before.refs) == 2
    # An EVIDENCE finalization leaves the command root to the RESULT close or the
    # Stage 7 cleanup: the raw-bearing bytes are still there.
    assert result_plan.roots.request_path.is_file()
    fixture.reopen()
    report = _ok(fixture.recover())
    # The RUNNING run's RESULT candidates are recovered through the validator,
    # which here refuses (Task 7 owns success): quarantined, run FAILED, the
    # root closed. The registered evidence is untouched.
    assert report.registered == 0
    assert report.quarantined == 2
    after = fixture.durable()
    assert [entry.state.value for entry in after.journal] == ["REGISTERED"]
    assert len(after.refs) == 2
    assert not result_plan.roots.request_path.exists()
    second = _ok(fixture.recover())
    assert second.changes == 0
    assert (
        fixture.durable().audit_actions.count("RECONCILIATION_FINALIZATION_RESUMED")
        == 2
    )


# --------------------------------------------------------------------------
# RESULT durable-state halves CP-1 .. CP-6
# --------------------------------------------------------------------------


def _assert_result_prestate(before: DurableState, plan: ResultPlan) -> None:
    assert before.run_state == "RUNNING"
    assert before.invocation is not None
    assert before.invocation.state.value == "EXITED"
    assert before.invocation.revision == plan.invocation.revision
    assert before.refs == ()
    assert before.run_manifests == ()


def _assert_result_timed_out(fixture: FinalizationFixture, plan: ResultPlan) -> None:
    after = fixture.durable()
    assert after.run_state == "TIMED_OUT"
    assert after.run is not None
    assert after.journal_state == "ABANDONED"
    assert after.abandon_reason == ARTIFACT_FINALIZATION_TIMED_OUT
    assert after.refs == ()
    assert after.run_manifests == ()
    assert after.object_blobs == ()
    assert all(state == "QUARANTINED" for state in after.candidate_states.values())
    (entry,) = [
        item for item in after.quarantine_entries if item.entry_id.startswith("fin_")
    ]
    assert len(entry.files) == 2
    assert after.invocation is not None
    assert after.invocation.state.value == "EXITED"
    assert after.invocation.revision == plan.invocation.revision
    assert after.audit_actions.count("FINALIZATION_TIMED_OUT") == 1
    assert after.audit_actions.count("ARTIFACT_QUARANTINED") == 2
    assert after.diagnostic_codes.count(ARTIFACT_FINALIZATION_TIMED_OUT) == 1
    primary = after.run.primary_terminal_diagnostic_id
    assert any(
        diagnostic.diagnostic_id == primary
        and diagnostic.error_code == ARTIFACT_FINALIZATION_TIMED_OUT
        for diagnostic in after.diagnostics
    )
    # The lease closed: the raw-bearing bytes left the command root.
    assert not plan.roots.request_path.exists()
    assert isinstance(plan.roots.result_path, Path)
    assert not plan.roots.result_path.exists()
    _assert_no_dangling(fixture)


def _assert_result_validation_failed(
    fixture: FinalizationFixture, plan: ResultPlan
) -> None:
    after = fixture.durable()
    assert after.run_state == "FAILED"
    assert after.run is not None
    assert after.journal_state == "ABANDONED"
    assert after.abandon_reason == ARTIFACT_VALIDATION_FAILED
    assert after.refs == ()
    assert after.object_blobs == ()
    assert all(state == "QUARANTINED" for state in after.candidate_states.values())
    primary = after.run.primary_terminal_diagnostic_id
    assert any(
        diagnostic.diagnostic_id == primary
        and diagnostic.error_code == ARTIFACT_VALIDATION_FAILED
        for diagnostic in after.diagnostics
    )
    assert after.audit_actions.count("FINALIZATION_ABANDONED") == 1
    assert after.audit_actions.count("RUN_FAILED") == 1
    assert after.audit_actions.count("ARTIFACT_QUARANTINED") == 2
    assert after.invocation is not None
    assert after.invocation.revision == plan.invocation.revision
    assert not plan.roots.request_path.exists()
    _assert_no_dangling(fixture)


def test_cp1_result_durable_state(fixture: FinalizationFixture) -> None:
    plan = fixture.plant_result_prestate()
    _crash(fixture, plan.request, "before_prepared")
    before = fixture.durable()
    _assert_result_prestate(before, plan)
    assert before.journal == ()
    assert all(state == "VALIDATING" for state in before.candidate_states.values())
    assert before.run_deadline is None  # reading 2: no deadline before PREPARED
    assert before.audit_actions == ()
    fixture.reopen()
    # Step 6: the temporary manifest fails validation (the Task 6 validator
    # answers the planted refusal), so the candidates are quarantined and the run
    # fails under the check's diagnostic; the raw-bearing bytes close.
    report = _ok(fixture.recover())
    assert report.quarantined == 2
    assert report.registered == 0
    after = fixture.durable()
    assert after.run_state == "FAILED"
    assert after.run is not None
    assert all(state == "QUARANTINED" for state in after.candidate_states.values())
    assert after.journal == ()
    primary = after.run.primary_terminal_diagnostic_id
    assert any(
        diagnostic.diagnostic_id == primary
        and diagnostic.error_code == ARTIFACT_RESULT_MANIFEST_INVALID
        for diagnostic in after.diagnostics
    )
    assert after.audit_actions.count("RUN_FAILED") == 1
    assert after.audit_actions.count("RECONCILIATION_CANDIDATE_QUARANTINED") == 2
    assert after.audit_actions.count("RETENTION_DELETED") == 1
    assert not plan.roots.request_path.exists()
    assert fixture.memory_validator.calls[0].token_supplied is True
    _assert_no_dangling(fixture)


def test_cp2_result_durable_state(fixture: FinalizationFixture) -> None:
    plan = fixture.plant_result_prestate()
    _crash(fixture, plan.request, "after_prepared")
    before = fixture.durable()
    _assert_result_prestate(before, plan)
    assert before.journal_state == "PREPARED"
    assert all(state == "FINALIZING" for state in before.candidate_states.values())
    assert before.run_deadline == INSTANT.replace(minute=10)
    assert before.run_revision == plan.run.revision + 1
    assert before.object_blobs == ()
    assert before.audit_actions == _T1_ACTIONS
    # The deadline passes across the restart (RV-15, reading 13).
    fixture.advance_clock(RESULT_TIMEOUT_SECONDS + 1)
    fixture.reopen()
    report = _ok(fixture.recover())
    assert (report.resumed, report.abandoned, report.registered) == (1, 1, 0)
    _assert_result_timed_out(fixture, plan)


def test_cp3_result_durable_state(fixture: FinalizationFixture) -> None:
    plan = fixture.plant_result_prestate()
    _crash(fixture, plan.request, "after_move", 0)
    before = fixture.durable()
    _assert_result_prestate(before, plan)
    assert before.journal_state == "PREPARED"
    assert len(before.object_blobs) == 1
    # The second candidate, still in staging, changes before recovery.
    second = plan.candidates[1]
    assert isinstance(plan.roots.work_dir, Path)
    plan.roots.work_dir.joinpath(*second.staging_relative_path.split("/")).write_bytes(
        b"changed while the process was down\n"
    )
    # The RESULT lease expires inside the deadline: the pass takes it over.
    fixture.advance_clock(RESULT_LEASE_SECONDS + 1)
    fixture.reopen()
    report = _ok(fixture.recover())
    assert (report.resumed, report.abandoned) == (1, 1)
    _assert_result_validation_failed(fixture, plan)


def test_cp4_result_durable_state(fixture: FinalizationFixture) -> None:
    plan = fixture.plant_result_prestate()
    _crash(fixture, plan.request, "before_moved")
    before = fixture.durable()
    _assert_result_prestate(before, plan)
    assert before.journal_state == "PREPARED"
    assert set(before.object_blobs) == _RESULT_HASHES
    # A moved blob changes in place: the in-place re-hash is the mismatch.
    (entry,) = before.journal
    first = entry.planned_paths[0]
    fixture.roots.store.finalized_path_for(first.expected_sha256).write_bytes(
        b"corrupted finalized bytes\n"
    )
    # The RESULT lease expires inside the deadline: the pass takes it over.
    fixture.advance_clock(RESULT_LEASE_SECONDS + 1)
    fixture.reopen()
    report = _ok(fixture.recover())
    assert (report.resumed, report.abandoned) == (1, 1)
    _assert_result_validation_failed(fixture, plan)


def test_cp5_result_durable_state(fixture: FinalizationFixture) -> None:
    plan = fixture.plant_result_prestate()
    _crash(fixture, plan.request, "after_moved")
    before = fixture.durable()
    _assert_result_prestate(before, plan)
    assert before.journal_state == "MOVED"
    (entry,) = before.journal
    assert len(entry.observed) == 2
    assert before.run_deadline == INSTANT.replace(minute=10)
    assert before.audit_actions == (*_T1_ACTIONS, "FINALIZATION_MOVED")
    fixture.advance_clock(RESULT_TIMEOUT_SECONDS + 1)
    fixture.reopen()
    report = _ok(fixture.recover())
    assert (report.resumed, report.abandoned, report.registered) == (1, 1, 0)
    _assert_result_timed_out(fixture, plan)


class _StorageFailingRegistrar(MemoryRegistrar):
    """A registrar whose RESULT registration meets the storage class inside T3:
    the finalizer rolls T3 back and leaves the journal MOVED for recovery."""

    def register_result(
        self,
        transaction: RegistrationUnitOfWork,
        journal: FinalizationJournalEntry,
        refs: tuple[ArtifactRef, ...],
        facts: object,
    ) -> Result[ResultRegistration]:
        del transaction, refs, facts
        self.result_calls += 1
        return persistence_failure(
            WRITE_FAILED,
            message=f"registration of {journal.finalization_id} met the I/O class",
            clock=FixedClock(INSTANT),
        )


def test_cp6_result_durable_state(fixture: FinalizationFixture) -> None:
    plan = fixture.plant_result_prestate()
    registrar = _StorageFailingRegistrar()
    failed = fixture.finalize(plan.request, registrar=registrar)
    assert _code(failed) == WRITE_FAILED
    assert registrar.result_calls == 1
    before = fixture.durable()
    _assert_result_prestate(before, plan)
    # Exactly MOVED: never a reference without a manifest, never success
    # without a manifest (SQLite atomicity + reading 11 triggers).
    assert before.journal_state == "MOVED"
    assert before.refs == ()
    assert before.run_manifests == ()
    assert before.run_artifacts == ()
    assert before.run_revision == plan.run.revision + 1
    assert "FINALIZATION_REGISTERED" not in before.audit_actions
    assert fixture.harness.open_transactions() == ()
    fixture.advance_clock(RESULT_TIMEOUT_SECONDS + 1)
    fixture.reopen()
    report = _ok(fixture.recover())
    assert (report.resumed, report.abandoned, report.registered) == (1, 1, 0)
    _assert_result_timed_out(fixture, plan)


# --------------------------------------------------------------------------
# Task 7: the RESULT success cells CP-1 .. CP-7 over the production registrar
# and recovery validator
# --------------------------------------------------------------------------

#: The audit tail of a RESULT registration: the registrar's two facts inside
#: T3, the finalizer's phase-5 fact and the phase-6 close of the raw bytes.
_SUCCESS_TAIL = (
    "RUN_MANIFEST_REGISTERED",
    "RUN_SUCCEEDED",
    "FINALIZATION_REGISTERED",
    "RETENTION_DELETED",
)
_RESULT_RECOVERED_FROM_STAGING = (
    *_T1_ACTIONS,
    "FINALIZATION_MOVED",
    *_SUCCESS_TAIL,
    _SUMMARY,
)
_RESULT_RECOVERED_FROM_PREPARED = (
    *_T1_ACTIONS,
    "FINALIZATION_LEASE_ACQUIRED",
    "FINALIZATION_MOVED",
    *_SUCCESS_TAIL,
    _SUMMARY,
)
_RESULT_RECOVERED_FROM_MOVED = (
    *_T1_ACTIONS,
    "FINALIZATION_MOVED",
    "FINALIZATION_LEASE_ACQUIRED",
    *_SUCCESS_TAIL,
    _SUMMARY,
)
_RESULT_DEADLINE = INSTANT.replace(minute=10)


def _expire_result_lease(fixture: FinalizationFixture) -> None:
    """The RESULT lease (the compiled 300 s) expires inside the 600 s deadline."""
    fixture.advance_clock(RESULT_LEASE_SECONDS + 1)


def _assert_result_success(
    fixture: FinalizationFixture,
    plan: ResultPlan,
    *,
    audit_actions: tuple[str, ...],
) -> None:
    """The six facets of a recovered RESULT success (plan 5.1 after-recovery
    column): rows, journal, references, run and invocation, audit history equal
    to durable history, and the filesystem; the run manifest's self-hash is
    verified separately from its row (29.3:2182)."""
    after = fixture.durable()
    assert after.journal_state == "REGISTERED"
    assert len(after.refs) == 2
    assert {ref.content_hash for ref in after.refs} == _RESULT_HASHES
    assert set(after.object_blobs) == _RESULT_HASHES
    assert after.staging_files == ()
    assert all(state == "FINALIZING" for state in after.candidate_states.values())
    assert after.run_state == "SUCCEEDED"
    assert after.run_revision == plan.run.revision + 2
    assert after.run_deadline == _RESULT_DEADLINE
    assert after.invocation is not None
    assert after.invocation.state.value == "EXITED"
    assert after.invocation.revision == plan.invocation.revision
    (row,) = after.run_manifests
    manifest = RunManifest.model_validate_json(row.manifest_json)
    assert run_manifest_hash(manifest) == row.run_manifest_hash
    assert manifest.run_manifest_hash == row.run_manifest_hash
    assert manifest.run_id == plan.run.run_id
    assert manifest.run_invocation_id == plan.invocation.invocation_id
    assert manifest.sanitized_adapter_result_manifest_hash == (
        plan.request.sanitized_adapter_result_manifest_hash
    )
    assert {ref.artifact_id for ref in manifest.artifact_refs} == {
        ref.artifact_id for ref in after.refs
    }
    members = [
        link
        for link in after.run_artifacts
        if link.link_role == "RESULT_MANIFEST_MEMBER"
    ]
    assert {link.artifact_id for link in members} == {
        ref.artifact_id for ref in after.refs
    }
    assert all(link.run_manifest_id == row.manifest_id for link in members)
    assert after.audit_actions == audit_actions
    assert after.quarantine_entries == ()
    # The lease closed: the raw-bearing bytes left the command root.
    assert not plan.roots.request_path.exists()
    assert isinstance(plan.roots.result_path, Path)
    assert not plan.roots.result_path.exists()
    assert not any(name.endswith(".json") for name in after.command_root_files)
    _assert_no_dangling(fixture)


def test_cp1_result_success(production: FinalizationFixture) -> None:
    plan = production.plant_result_prestate()
    _crash(production, plan.request, "before_prepared")
    before = production.durable()
    _assert_result_prestate(before, plan)
    assert before.journal == ()
    assert all(state == "VALIDATING" for state in before.candidate_states.values())
    assert before.run_deadline is None
    assert before.audit_actions == ()
    production.reopen()
    # Step 6: the production validator validates the temporary manifest under
    # 29.3 and the attempt resumes from phase 2 with a fresh deadline (reading 2).
    report = _ok(production.recover())
    assert (report.resumed, report.registered, report.quarantined) == (1, 1, 0)
    _assert_result_success(
        production, plan, audit_actions=_RESULT_RECOVERED_FROM_STAGING
    )


def test_cp2_result_success(production: FinalizationFixture) -> None:
    plan = production.plant_result_prestate()
    _crash(production, plan.request, "after_prepared")
    before = production.durable()
    _assert_result_prestate(before, plan)
    assert before.journal_state == "PREPARED"
    assert before.run_deadline == _RESULT_DEADLINE
    assert before.audit_actions == _T1_ACTIONS
    _expire_result_lease(production)
    production.reopen()
    report = _ok(production.recover())
    assert (report.resumed, report.registered) == (1, 1)
    _assert_result_success(
        production, plan, audit_actions=_RESULT_RECOVERED_FROM_PREPARED
    )


def test_cp3_result_success(production: FinalizationFixture) -> None:
    plan = production.plant_result_prestate()
    _crash(production, plan.request, "after_move", 0)
    before = production.durable()
    assert before.journal_state == "PREPARED"
    assert len(before.object_blobs) == 1
    # The second candidate is still under the work directory of the root.
    second = plan.candidates[1].staging_relative_path
    assert any(name.endswith(second) for name in before.command_root_files)
    _expire_result_lease(production)
    production.reopen()
    report = _ok(production.recover())
    assert (report.resumed, report.registered) == (1, 1)
    _assert_result_success(
        production, plan, audit_actions=_RESULT_RECOVERED_FROM_PREPARED
    )


def test_cp4_result_success(production: FinalizationFixture) -> None:
    plan = production.plant_result_prestate()
    _crash(production, plan.request, "before_moved")
    before = production.durable()
    assert before.journal_state == "PREPARED"
    assert set(before.object_blobs) == _RESULT_HASHES
    assert before.staging_files == ()
    _expire_result_lease(production)
    production.reopen()
    report = _ok(production.recover())
    assert (report.resumed, report.registered) == (1, 1)
    _assert_result_success(
        production, plan, audit_actions=_RESULT_RECOVERED_FROM_PREPARED
    )


def test_cp5_result_success(production: FinalizationFixture) -> None:
    plan = production.plant_result_prestate()
    _crash(production, plan.request, "after_moved")
    before = production.durable()
    assert before.journal_state == "MOVED"
    (entry,) = before.journal
    assert len(entry.observed) == 2
    assert before.refs == ()
    assert before.run_manifests == ()
    assert before.audit_actions == (*_T1_ACTIONS, "FINALIZATION_MOVED")
    _expire_result_lease(production)
    production.reopen()
    report = _ok(production.recover())
    assert (report.resumed, report.registered) == (1, 1)
    _assert_result_success(production, plan, audit_actions=_RESULT_RECOVERED_FROM_MOVED)


def test_cp6_result_success(production: FinalizationFixture) -> None:
    plan = production.plant_result_prestate()
    _crash(production, plan.request, "inside_registered")
    before = production.durable()
    # T3 rolled back through the scope's ``finally`` after the production
    # registrar had staged the references, the manifest, the links and the run
    # swap: exactly MOVED -- never a reference, a manifest row or a success
    # without its commit (SQLite atomicity + reading 11).
    assert before.journal_state == "MOVED"
    assert before.refs == ()
    assert before.run_manifests == ()
    assert before.run_artifacts == ()
    assert before.run_state == "RUNNING"
    assert before.run_revision == plan.run.revision + 1
    assert "RUN_SUCCEEDED" not in before.audit_actions
    assert "RUN_MANIFEST_REGISTERED" not in before.audit_actions
    assert production.harness.open_transactions() == ()
    _expire_result_lease(production)
    production.reopen()
    report = _ok(production.recover())
    assert (report.resumed, report.registered) == (1, 1)
    _assert_result_success(production, plan, audit_actions=_RESULT_RECOVERED_FROM_MOVED)


def test_cp7_result_success(production: FinalizationFixture) -> None:
    plan = production.plant_result_prestate()
    _crash(production, plan.request, "after_registered")
    before = production.durable()
    assert before.journal_state == "REGISTERED"
    assert len(before.refs) == 2
    assert len(before.run_manifests) == 1
    assert before.run_state == "SUCCEEDED"
    assert before.audit_actions == (
        *_T1_ACTIONS,
        "FINALIZATION_MOVED",
        *_SUCCESS_TAIL[:-1],
    )
    # The phase-6 close never ran: the raw-bearing bytes are still there.
    assert plan.roots.request_path.is_file()
    assert isinstance(plan.roots.result_path, Path)
    assert plan.roots.result_path.is_file()
    production.reopen()
    # Step 9 cleanup: the raw bytes of the terminal run's root removed with its
    # audit fact; nothing else changes.
    report = _ok(production.recover())
    assert (report.registered, report.resumed, report.quarantined) == (0, 0, 0)
    assert report.closed_roots == 1
    _assert_result_success(
        production, plan, audit_actions=_RESULT_RECOVERED_FROM_STAGING
    )
    second = _ok(production.recover())
    assert second.changes == 0
    assert production.durable().audit_actions == (
        *_RESULT_RECOVERED_FROM_STAGING,
        _SUMMARY,
    )
