"""Stage 9 Task 6: the unit halves of the reconciliation rows RV-6, RV-7, RV-9,
RV-10, RV-11, RV-17 and RV-18 over the in-memory unit of work (plan 5.3; the
SQLite halves live in ``tests/integration/artifacts/test_finalization_recovery.py``).

The memory harness composes the same ``reconcile_finalization`` over the memory
store and a real store under ``tmp_path``, so the planted states and the
expected actions read identically to the SQLite rows; the memory registrar and
validator are the Task 6 doubles, so no RESULT success is reachable here.
"""

from __future__ import annotations

import _winapi
import hashlib
import os
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import InstanceOf
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.artifacts.diagnostics import (
    ARTIFACT_MOVE_FAILED,
    ARTIFACT_QUARANTINE_OVERDUE,
    ARTIFACT_RESULT_MANIFEST_INVALID,
    ARTIFACT_VALIDATION_FAILED,
    SECURITY_SENSITIVE_MATERIAL_LEAKAGE,
    artifact_failure,
)
from crypto_lab.artifacts.finalizer import RESULT_LEASE_SECONDS
from crypto_lab.artifacts.journal import FinalizationJournalEntry
from crypto_lab.artifacts.models import (
    ArtifactFinalizationPurpose,
    ArtifactRef,
    ArtifactSourceRole,
    CandidateArtifactProducerKind,
    CandidateArtifactState,
)
from crypto_lab.artifacts.ownership import RunArtifactOwner, artifact_owner_hash
from crypto_lab.artifacts.paths import confine_candidate_path
from crypto_lab.artifacts.ports import (
    RegistrationUnitOfWork,
    ResultRecoveryFacts,
    ResultRegistration,
)
from crypto_lab.artifacts.recovery import (
    QUARANTINE_OVERDUE_SECONDS,
    FinalizationReconciliationReport,
    purge_quarantine,
    reconcile_finalization,
)
from crypto_lab.artifacts.store import (
    QUARANTINE_METADATA_NAME,
    ArtifactStore,
    QuarantineMetadata,
)
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.hashing import _uuid4_shaped, sha256_bytes
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
)
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.persistence.diagnostics import (
    INVARIANT_VIOLATION,
    WRITE_FAILED,
    persistence_failure,
)
from doubles.artifacts import (
    ADAPTER_OWNER,
    ATTEMPT_TOKEN_HASH,
    DIAGNOSTIC_CORRELATION,
    FIXTURE_TOKEN,
    RESULT_TIMEOUT_SECONDS,
    RUN_OWNER,
    SANITIZED_MANIFEST_HASH,
    SOURCE_MANIFEST_HASH,
    SYSTEM_OWNER,
    THIRD_CANDIDATE_ID,
    CrashingProbe,
    FinalizationCrash,
    MemoryCandidateArtifactRepository,
    MemoryDiagnosticWriter,
    MemoryEngineRunRecords,
    MemoryFinalizationHarness,
    MemoryFinalizationJournalRepository,
    MemoryFinalizationTransaction,
    MemoryRecoveryValidator,
    MemoryRegistrar,
    RefusingAuditor,
    ResultPlan,
    bump_candidate,
    plant_core_evidence,
    result_candidates,
    sample_artifact_manifest,
    sample_candidate,
    sample_ref,
)
from doubles.experiments import (
    EXPERIMENT_ID,
    INSTANT,
    INVOCATION_ID,
    OTHER_INVOCATION_ID,
    RUN_ID,
    UUID_D,
    FixedClock,
    sample_invocation,
    sample_run,
)

_S = CandidateArtifactState
_F = ArtifactFinalizationPurpose
_P = CandidateArtifactProducerKind
_ORPHAN_INVOCATION_ID = f"inv_{UUID_D}"
_STRAY_BYTES = b"finalized-looking bytes nobody registered\n"
_STRAY_DIGEST = hashlib.sha256(_STRAY_BYTES).hexdigest()
#: The two ordinary names the candidate grammar refuses (RV-9 orphan operation).
_ORPHAN_NAMES = (
    pytest.param(".hidden", id="dot-prefixed"),
    pytest.param("odd name.bin", id="space-bearing"),
)
#: Directories under ``objects/`` that are no shard of the leaf below them (RV-9
#: routing: a content-address leaf there is misplaced, never canonical). ``zz``
#: is no hex pair, so it can never equal a digest's own shard.
_MISPLACED_DIRECTORIES = (
    pytest.param(".x", id="dot-prefixed"),
    pytest.param("odd dir", id="space-bearing"),
    pytest.param("zz", id="wrong-shard"),
)
#: The components of a canonical path a case-only rename may touch on the
#: supported case-insensitive store (RV-9 case semantics).
_CASE_COMPONENTS = (
    pytest.param("shard", id="shard"),
    pytest.param("leaf", id="leaf"),
)


def _rename_case(store: ArtifactStore, digest: str, component: str) -> Path:
    """A case-only rename of one component of ``digest``'s canonical path -- its
    shard directory (``objects/ab`` -> ``objects/AB``) or its leaf -- as NTFS
    admits it: the very same file, at the very same case-insensitive path. The
    observed-case path is returned."""
    canonical = store.finalized_path_for(digest)
    source = canonical.parent if component == "shard" else canonical
    renamed = source.with_name(source.name.upper())
    assert renamed.name != source.name, source.name
    source.rename(renamed)
    return renamed / digest if component == "shard" else renamed


def _orphan_entry_id(relative: str) -> str:
    """The deterministic RV-9 identity of an orphan: derived from its confined
    relative path under the artifacts root, never from the untrusted name."""
    return f"unregistered_{_uuid4_shaped(sha256_bytes(relative.encode('utf-8')))}"


class _StorageFailingRegistrar(MemoryRegistrar):
    """A registrar whose RESULT registration meets the storage class inside T3:
    the finalizer rolls T3 back and leaves the journal ``MOVED`` (reading 26)."""

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


def _plant_stray_blob(harness: MemoryFinalizationHarness) -> Path:
    """A blob under ``objects/`` that no row and no journal names (RV-9)."""
    target = harness.roots.store.finalized_path_for(_STRAY_DIGEST)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(_STRAY_BYTES)
    return target


def _projections(harness: MemoryFinalizationHarness) -> tuple[Path, ...]:
    return tuple(sorted(harness.roots.store.manifests_root.glob("*.json")))


def _write_failure() -> Failure:
    return persistence_failure(
        WRITE_FAILED,
        message="the transaction could not be committed",
        clock=FixedClock(INSTANT),
        details={"operation": "commit"},
    )


def _read_failure() -> Failure:
    """The classified I/O failure the SQLite reference repository answers when
    its content-hash read is refused at the driver."""
    return persistence_failure(
        WRITE_FAILED,
        message="the reference rows could not be read",
        clock=FixedClock(INSTANT),
        details={"table": "artifact_refs", "operation": "list_by_content_hash"},
    )


def _planted_facts(
    *, timeout_seconds: int = RESULT_TIMEOUT_SECONDS
) -> Result[ResultRecoveryFacts]:
    """The ``ResultRecoveryFacts`` a passing 29.3 validation of the fixture's
    temporary manifest would yield, as the validator double's planted answer."""
    facts = ResultRecoveryFacts(
        run_id=RUN_ID,
        run_invocation_id=INVOCATION_ID,
        experiment_id=EXPERIMENT_ID,
        attempt_token_hash=ATTEMPT_TOKEN_HASH,
        source_adapter_result_manifest_hash=SOURCE_MANIFEST_HASH,
        sanitized_adapter_result_manifest_hash=SANITIZED_MANIFEST_HASH,
        semantic_status="SUCCEEDED",
        finalization_timeout_seconds=timeout_seconds,
        candidate_observations=(),
    )
    return Success[InstanceOf[ResultRecoveryFacts]](outcome="SUCCESS", value=facts)


#: Win32 ``FILE_SHARE_READ`` (``_winapi`` exposes no name for it).
_FILE_SHARE_READ = 0x00000001


def _hold_open_sharing_reads(path: Path) -> int:
    """Open ``path`` sharing reads only: the finalizer's read-only hashing handle
    is admitted, its read-write reopen for the move and any rename are refused."""
    return _winapi.CreateFile(
        str(path),
        _winapi.GENERIC_READ,
        _FILE_SHARE_READ,
        _winapi.NULL,
        _winapi.OPEN_EXISTING,
        0,
        _winapi.NULL,
    )


def _staged_path(harness: MemoryFinalizationHarness, staging_relative: str) -> Path:
    owner_root = harness.roots.staging_root / artifact_owner_hash(RUN_OWNER)
    return owner_root.joinpath(*staging_relative.split("/"))


def _ok[T](result: Result[T]) -> T:
    assert isinstance(result, Success), result
    return result.value


def _code(result: object) -> str:
    assert isinstance(result, Failure), result
    return result.diagnostics[0].error_code


@pytest.fixture
def harness(tmp_path: Path) -> MemoryFinalizationHarness:
    return MemoryFinalizationHarness(tmp_path)


def _cleaned_up(invocation: CommandInvocationRecord) -> CommandInvocationRecord:
    payload = invocation.model_dump(mode="python")
    completed = invocation.completed_at_utc
    assert isinstance(completed, type(INSTANT))
    payload["cleanup_complete"] = True
    payload["cleanup_completed_at_utc"] = completed + timedelta(seconds=1)
    payload["revision"] = invocation.revision + 1
    payload["updated_at_utc"] = completed + timedelta(seconds=1)
    return CommandInvocationRecord.model_validate(
        {key: value for key, value in payload.items() if value is not None}
    )


def test_rv6_orphan_directory_is_quarantined_never_attached(
    harness: MemoryFinalizationHarness,
) -> None:
    harness.plant_run()
    orphan = harness.roots.runtime_root / _ORPHAN_INVOCATION_ID
    (orphan / "runs" / RUN_ID / "work").mkdir(parents=True)
    (orphan / "request.json").write_bytes(b'{"orphan": true}')
    (orphan / "runs" / RUN_ID / "work" / "stray.bin").write_bytes(b"stray\n")
    report = _ok(harness.recover())
    assert isinstance(report, FinalizationReconciliationReport)
    assert report.quarantined == 1
    assert not orphan.exists()
    after = harness.durable()
    (entry,) = after.quarantine_entries
    assert entry.entry_id == _ORPHAN_INVOCATION_ID
    assert entry.files == ("request.json", f"runs/{RUN_ID}/work/stray.bin")
    assert after.audit_actions == (
        "RECONCILIATION_ORPHAN_QUARANTINED",
        "RECONCILIATION_FINALIZATION_RESUMED",
    )
    assert after.candidates == ()


def test_rv7_mismatched_candidate_rows_are_quarantined(
    harness: MemoryFinalizationHarness,
) -> None:
    harness.plant_run()
    harness.store_data.tables.invocations[OTHER_INVOCATION_ID] = sample_invocation(
        CommandInvocationState.EXITED,
        kind=CommandKind.VALIDATE,
        invocation_id=OTHER_INVOCATION_ID,
    )
    owner = RunArtifactOwner(
        owner_kind="RUN",
        experiment_id=EXPERIMENT_ID,
        run_id=RUN_ID,
        invocation_id=OTHER_INVOCATION_ID,
    )
    for candidate in result_candidates(invocation_id=OTHER_INVOCATION_ID, owner=owner):
        harness.store_data.candidates[candidate.candidate_artifact_id] = candidate
    report = _ok(harness.recover())
    assert report.quarantined == 2
    after = harness.durable()
    assert all(state == "QUARANTINED" for state in after.candidate_states.values())
    # Both candidates share the one content-addressed diagnostic (same code,
    # message and owner; the clock instant is not hash material), while each
    # quarantine leaves its own audit row.
    assert after.diagnostic_codes == (ARTIFACT_VALIDATION_FAILED,)
    assert after.audit_actions.count("RECONCILIATION_CANDIDATE_QUARANTINED") == 2
    assert after.run_state == "RUNNING"


def test_rv9_unregistered_content_is_quarantined(
    harness: MemoryFinalizationHarness,
) -> None:
    harness.plant_run()
    stray = b"finalized-looking bytes nobody registered\n"
    digest = hashlib.sha256(stray).hexdigest()
    target = harness.roots.store.finalized_path_for(digest)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(stray)
    # A registered blob beside it stays: its projection resolves to a reference.
    evidence = harness.plant_evidence_prestate()
    _ok(harness.finalize(evidence.request))
    registered = harness.durable().object_blobs
    report = _ok(harness.recover())
    assert report.quarantined == 1
    after = harness.durable()
    assert digest not in after.object_blobs
    assert set(after.object_blobs) == set(registered) - {digest}
    assert any(entry.entry_id == digest for entry in after.quarantine_entries)
    assert after.audit_actions.count("RECONCILIATION_ORPHAN_QUARANTINED") == 1


# --------------------------------------------------------------------------
# RV-9 oracle (plan 6.2): the ``artifact_refs`` row is authoritative, the
# ``manifests/<artifact_id>.json`` projection is neither necessary nor sufficient
# --------------------------------------------------------------------------


def test_rv9_registered_blob_survives_a_missing_projection(
    harness: MemoryFinalizationHarness,
) -> None:
    """Plan 6.2: the projection is a human-inspection file whose absence readers
    tolerate because the row is authoritative; a committed registration whose
    projection is gone is still registered content and never quarantined."""
    evidence = harness.plant_evidence_prestate()
    registered = _ok(harness.finalize(evidence.request))
    assert registered.journal_state == "REGISTERED"
    before = harness.durable()
    assert len(before.refs) == 1
    assert len(before.object_blobs) == 1
    for projection in _projections(harness):
        projection.unlink()
    assert _projections(harness) == ()
    report = _ok(harness.recover())
    assert report.quarantined == 0
    assert report.changes == 0
    after = harness.durable()
    assert after.object_blobs == before.object_blobs
    assert after.refs == before.refs
    assert after.quarantine_entries == ()
    assert "RECONCILIATION_ORPHAN_QUARANTINED" not in after.audit_actions


def test_rv9_well_formed_projection_without_a_row_does_not_register(
    harness: MemoryFinalizationHarness,
) -> None:
    """A projection that validates and names the stray blob's digest is no
    evidence of registration: without the ``artifact_refs`` row the blob is
    quarantined and the stale projection travels with it."""
    harness.plant_run()
    _plant_stray_blob(harness)
    phantom = sample_ref(
        sample_candidate(
            "SYSTEM",
            _F.EVIDENCE,
            producer=_P.CORE,
            state=_S.FINALIZING,
            candidate_artifact_id=THIRD_CANDIDATE_ID,
        ),
        content_hash=_STRAY_DIGEST,
        size_bytes=len(_STRAY_BYTES),
    )
    projection = harness.roots.store.manifest_path_for(phantom.artifact_id)
    projection.write_bytes(canonical_json_bytes(sample_artifact_manifest(phantom)))
    report = _ok(harness.recover())
    assert report.quarantined == 1
    after = harness.durable()
    assert after.refs == ()
    assert _STRAY_DIGEST not in after.object_blobs
    assert not projection.exists()
    (entry,) = [
        entry for entry in after.quarantine_entries if entry.entry_id == _STRAY_DIGEST
    ]
    assert entry.files == (
        f"manifests/{phantom.artifact_id}.json",
        f"objects/{_STRAY_DIGEST[:2]}/{_STRAY_DIGEST}",
    )
    assert after.audit_actions.count("RECONCILIATION_ORPHAN_QUARANTINED") == 1


def test_rv9_open_journal_protects_its_moved_blobs(
    harness: MemoryFinalizationHarness,
) -> None:
    """The applicable open journal protects the blobs it planned: a ``MOVED``
    RESULT journal left open by a storage-class T3 failure keeps its two blobs
    while the stray beside them is quarantined; no projection is involved."""
    plan = harness.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        harness.finalize(plan.request, probe=CrashingProbe("after_moved"))
    moved = harness.durable()
    assert moved.journal_state == "MOVED"
    assert len(moved.object_blobs) == 2
    assert _projections(harness) == ()
    _plant_stray_blob(harness)
    harness.registrar = _StorageFailingRegistrar()
    # The pass takes the journal over once its lease has expired (the ruling).
    harness.advance_clock(RESULT_LEASE_SECONDS + 1)
    report = _ok(harness.recover())
    assert harness.registrar.result_calls == 1
    assert report.quarantined == 1
    after = harness.durable()
    assert after.journal_state == "MOVED"
    assert after.refs == ()
    assert set(after.object_blobs) == set(moved.object_blobs)
    assert _STRAY_DIGEST not in after.object_blobs
    assert [entry.entry_id for entry in after.quarantine_entries] == [_STRAY_DIGEST]


def test_rv9_reference_lookup_failure_preserves_the_blob_and_reports_it(
    harness: MemoryFinalizationHarness,
) -> None:
    """A refused ``artifact_refs`` read is not absence: the pass answers the
    repository's failure, the blob stays under ``objects/`` with no quarantine
    entry and no audit row, every transaction is released, and the next pass --
    the read answering -- quarantines the unregistered blob."""
    harness.plant_run()
    blob = _plant_stray_blob(harness)
    harness.unit_of_work.fail_next_reference_lookup(_read_failure())
    failed = harness.recover()
    assert _code(failed) == WRITE_FAILED
    assert isinstance(failed, Failure)
    assert failed.diagnostics[0].details["operation"] == "list_by_content_hash"
    assert blob.is_file()
    after = harness.durable()
    assert _STRAY_DIGEST in after.object_blobs
    assert after.quarantine_entries == ()
    assert after.audit_actions == ()
    assert harness.unit_of_work.open_transactions() == ()
    report = _ok(harness.recover())
    assert report.quarantined == 1
    assert _STRAY_DIGEST not in harness.durable().object_blobs


def test_rv10_abandoned_core_staging_is_quarantined(
    harness: MemoryFinalizationHarness,
) -> None:
    run, invocation = harness.plant_run()
    plan = harness.plant_evidence_prestate()
    harness.store_data.tables.invocations[invocation.invocation_id] = _cleaned_up(
        invocation
    )
    report = _ok(harness.recover())
    assert (report.quarantined, report.resumed) == (1, 0)
    after = harness.durable()
    (candidate,) = plan.candidates
    assert after.candidate_states[candidate.candidate_artifact_id] == "QUARANTINED"
    assert after.staging_files == ()
    assert after.journal == ()
    assert after.run_revision == run.revision


def test_rv11_unmapped_finalizing_candidate_is_quarantined(
    harness: MemoryFinalizationHarness,
) -> None:
    plan = harness.plant_evidence_prestate()
    (candidate,) = plan.candidates
    finalizing = bump_candidate(bump_candidate(candidate, _S.VALIDATING), _S.FINALIZING)
    harness.store_data.candidates[candidate.candidate_artifact_id] = finalizing
    report = _ok(harness.recover())
    assert report.quarantined == 1
    after = harness.durable()
    assert after.candidate_states[candidate.candidate_artifact_id] == "QUARANTINED"
    assert after.journal == ()
    assert after.refs == ()
    assert after.staging_files == ()


def test_rv17_overdue_quarantine_is_reported_bytes_untouched(
    harness: MemoryFinalizationHarness,
) -> None:
    plan = harness.plant_evidence_prestate(files={"shaped.txt": b"Q" * 40 + b"\n"})
    assert harness.finalize(plan.request).outcome == "FAILURE"
    (entry,) = harness.durable().quarantine_entries
    before = tuple(sorted((harness.roots.quarantine_root / entry.entry_id).rglob("*")))
    harness.advance_clock(QUARANTINE_OVERDUE_SECONDS + 1)
    report = _ok(harness.recover())
    assert report.overdue == 1
    assert report.changes == 0
    after = harness.durable()
    assert after.audit_actions.count("QUARANTINE_OVERDUE") == 1
    assert ARTIFACT_QUARANTINE_OVERDUE in after.diagnostic_codes
    entry_root = harness.roots.quarantine_root / entry.entry_id
    assert tuple(sorted(entry_root.rglob("*"))) == before
    # A second pass reports it again and changes nothing (RV-14 over RV-17).
    second = _ok(harness.recover())
    assert (second.overdue, second.changes) == (1, 0)


def test_rv18_purge_is_refused_under_an_active_lease(
    harness: MemoryFinalizationHarness,
) -> None:
    plan = harness.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        harness.finalize(plan.request, probe=CrashingProbe("after_prepared"))
    (prepared,) = harness.durable().journal
    stray = harness.roots.runtime_root / "stray.txt"
    stray.write_bytes(b"leased bytes\n")
    confined = _ok(
        confine_candidate_path(harness.roots.runtime_root, "stray.txt", now_utc=INSTANT)
    )
    _ok(
        harness.roots.store.quarantine_move(
            confined, prepared.finalization_id, ARTIFACT_MOVE_FAILED, now_utc=INSTANT
        )
    )

    def purge(entry_id: str) -> Result[None]:
        return purge_quarantine(
            entry_id,
            "retention",
            store=harness.roots.store,
            unit_of_work_factory=harness.unit_of_work.begin,
            auditor=harness.auditor,
            clock=harness.clock,
        )

    refused = purge(prepared.finalization_id)
    assert _code(refused) == ARTIFACT_VALIDATION_FAILED
    assert (harness.roots.quarantine_root / prepared.finalization_id).is_dir()
    missing = purge("cand_00000000-0000-4000-8000-000000000000")
    assert _code(missing) == ARTIFACT_VALIDATION_FAILED
    harness.advance_clock(601)
    _ok(harness.recover())  # the deadline passed: the journal is ABANDONED
    _ok(purge(prepared.finalization_id))
    assert not (harness.roots.quarantine_root / prepared.finalization_id).exists()
    assert harness.durable().audit_actions[-1] == "RETENTION_DELETED"


# --------------------------------------------------------------------------
# Fault injection: failed registration, a missing root, refused resumes, storage
# failures and transaction failures met by the pass
# --------------------------------------------------------------------------


def test_validated_result_recovery_resumes_then_task6_registrar_abandons_it(
    harness: MemoryFinalizationHarness,
) -> None:
    """29.3 and plan 5.1 CP-1, the RESULT half Task 6 owns: a validated temporary
    manifest resumes the attempt from phase 2 under a fresh deadline (reading
    2); T3 then meets the Task 6 registrar's refusal, so the journal is
    ABANDONED, the candidates QUARANTINED, the run FAILED under 17.3 by the
    reconciler's finalizer, the moved blobs quarantined and the root closed --
    RESULT success stays unreachable."""
    plan = harness.plant_result_prestate()
    harness.validator.plant(_planted_facts())
    assert harness.durable().run_deadline is None
    report = _ok(harness.recover())
    assert (report.resumed, report.registered, report.abandoned) == (1, 0, 1)
    assert report.quarantined == 0  # the finalizer's own quarantine, not step 4's
    assert harness.registrar.result_calls == 1
    (call,) = harness.validator.calls
    assert call.token_supplied is True
    assert set(call.candidate_ids) == {
        candidate.candidate_artifact_id for candidate in plan.candidates
    }
    after = harness.durable()
    assert after.journal_state == "ABANDONED"
    assert after.abandon_reason == INVARIANT_VIOLATION
    assert after.run_state == "FAILED"
    assert after.run_deadline == INSTANT + timedelta(seconds=RESULT_TIMEOUT_SECONDS)
    assert after.run_revision == plan.run.revision + 2  # the snapshot, then FAILED
    assert all(state == "QUARANTINED" for state in after.candidate_states.values())
    assert after.refs == ()
    assert after.run_manifests == ()
    assert after.object_blobs == ()
    (entry,) = after.quarantine_entries
    assert entry.entry_id == after.journal[0].finalization_id
    assert len(entry.files) == 2
    assert not plan.roots.request_path.exists()  # the lease close (plan 4.3 phase 6)
    assert "FINALIZATION_REGISTERED" not in after.audit_actions
    for action in ("FINALIZATION_ABANDONED", "RUN_FAILED", "RETENTION_DELETED"):
        assert after.audit_actions.count(action) == 1, action
    assert _ok(harness.recover()).changes == 0


def test_result_recovery_without_its_run_root_fails_the_attempt(
    harness: MemoryFinalizationHarness,
) -> None:
    """The RUN root of the attempt is gone (29.3: the manifest must be inside the
    assigned directory): the group is quarantined under
    ``ARTIFACT.RESULT_MANIFEST_INVALID``, the run FAILED, the validator never
    consulted, and no byte is moved because no root confines the files."""
    plan = harness.plant_result_prestate()
    del harness._command_roots[INVOCATION_ID]
    before = harness.durable()
    report = _ok(harness.recover())
    assert (report.resumed, report.quarantined, report.closed_roots) == (0, 2, 0)
    assert harness.validator.calls == []
    after = harness.durable()
    assert after.run_state == "FAILED"
    assert after.run_revision == plan.run.revision + 1
    assert all(state == "QUARANTINED" for state in after.candidate_states.values())
    assert ARTIFACT_RESULT_MANIFEST_INVALID in after.diagnostic_codes
    assert after.quarantine_entries == ()
    assert after.command_root_files == before.command_root_files
    assert after.audit_actions.count("RECONCILIATION_CANDIDATE_QUARANTINED") == 2
    assert after.audit_actions.count("RUN_FAILED") == 1


def test_recovered_facts_that_form_no_request_fail_the_attempt(
    harness: MemoryFinalizationHarness,
) -> None:
    """Facts the validator answers must form a ``ResultFinalizationRequest``; a
    timeout outside the admitted range is ``ARTIFACT.RESULT_MANIFEST_INVALID``,
    the group quarantined with its bytes, the run FAILED and the root closed."""
    plan = harness.plant_result_prestate()
    harness.validator.plant(_planted_facts(timeout_seconds=0))
    report = _ok(harness.recover())
    assert (report.resumed, report.quarantined, report.closed_roots) == (0, 2, 1)
    after = harness.durable()
    assert after.run_state == "FAILED"
    assert all(state == "QUARANTINED" for state in after.candidate_states.values())
    assert ARTIFACT_RESULT_MANIFEST_INVALID in after.diagnostic_codes
    assert {entry.entry_id for entry in after.quarantine_entries} == {
        candidate.candidate_artifact_id for candidate in plan.candidates
    }
    assert not plan.roots.request_path.exists()
    assert after.journal == ()


def test_evidence_resume_refused_before_the_lease_quarantines_via_finalizer(
    harness: MemoryFinalizationHarness,
) -> None:
    """29.4: a core candidate left in staging resumes through the finalizer and
    is revalidated independently; a token-shaped text fails before T1, so the
    finalizer quarantines it under its own entry and audit, no journal exists,
    and the pass counts the resume but neither a registration nor an
    abandonment (the finalizer's quarantine is not among step 4's counts)."""
    plan = harness.plant_evidence_prestate(files={"shaped.txt": b"Q" * 40 + b"\n"})
    (candidate,) = plan.candidates
    report = _ok(harness.recover())
    assert (report.resumed, report.registered, report.abandoned) == (1, 0, 0)
    assert report.quarantined == 0
    after = harness.durable()
    assert after.candidate_states[candidate.candidate_artifact_id] == "QUARANTINED"
    assert after.journal == ()
    assert after.staging_files == ()
    (entry,) = after.quarantine_entries
    assert entry.entry_id == candidate.candidate_artifact_id
    assert after.audit_actions.count("ARTIFACT_QUARANTINED") == 1
    assert _ok(harness.recover()).changes == 0


def test_evidence_resume_whose_move_is_refused_is_abandoned_and_keeps_bytes(
    harness: MemoryFinalizationHarness,
) -> None:
    """Reading 26: a storage failure is not corruption. A staged evidence file
    another handle holds open (reads shared; the move's read-write reopen and
    any rename refused) is hashed and leased, then abandoned under
    ``ARTIFACT.MOVE_FAILED``; its candidate is QUARANTINED while the only copy
    of the bytes stays in staging, because the quarantine move is refused by
    the same handle (29.5: the only recoverable copy is never deleted)."""
    plan = harness.plant_evidence_prestate()
    (candidate,) = plan.candidates
    before = harness.durable()
    staged = _staged_path(harness, candidate.staging_relative_path)
    handle = _hold_open_sharing_reads(staged)
    try:
        report = _ok(harness.recover())
    finally:
        _winapi.CloseHandle(handle)
    assert (report.resumed, report.registered, report.abandoned) == (1, 0, 1)
    after = harness.durable()
    assert after.journal_state == "ABANDONED"
    assert after.abandon_reason == ARTIFACT_MOVE_FAILED
    assert after.candidate_states[candidate.candidate_artifact_id] == "QUARANTINED"
    assert staged.is_file()
    assert after.staging_files == before.staging_files
    assert after.object_blobs == ()
    assert after.quarantine_entries == ()
    assert after.run_revision == before.run_revision  # EVIDENCE never touches the run
    assert after.audit_actions.count("FINALIZATION_ABANDONED") == 1
    assert "FINALIZATION_MOVED" not in after.audit_actions


def _unmapped_finalizing(harness: MemoryFinalizationHarness) -> tuple[Path, str]:
    """The RV-11 state: one FINALIZING candidate no journal names, its bytes staged."""
    plan = harness.plant_evidence_prestate()
    (candidate,) = plan.candidates
    finalizing = bump_candidate(bump_candidate(candidate, _S.VALIDATING), _S.FINALIZING)
    harness.store_data.candidates[candidate.candidate_artifact_id] = finalizing
    return (
        _staged_path(harness, candidate.staging_relative_path),
        candidate.candidate_artifact_id,
    )


def test_quarantine_commit_failure_leaves_candidate_and_bytes_for_the_next_pass(
    harness: MemoryFinalizationHarness,
) -> None:
    """RV-11 under a storage-class commit failure: the quarantine's transaction
    (diagnostic, candidate swap, audit) fails as a whole, the pass answers the
    failure, the candidate stays FINALIZING with its bytes in place, and the
    next pass completes the quarantine."""
    staged, candidate_id = _unmapped_finalizing(harness)
    before = harness.durable()
    harness.unit_of_work.fail_next_committed(_write_failure())
    failed = harness.recover()
    assert _code(failed) == WRITE_FAILED
    assert harness.durable() == before
    assert staged.is_file()
    assert harness.unit_of_work.open_transactions() == ()
    report = _ok(harness.recover())
    assert report.quarantined == 1
    after = harness.durable()
    assert after.candidate_states[candidate_id] == "QUARANTINED"
    assert after.staging_files == ()


def test_quarantine_move_refused_by_a_held_handle_keeps_the_row_and_the_bytes(
    harness: MemoryFinalizationHarness,
) -> None:
    """RV-11 when the staging bytes cannot be moved: the row, diagnostic and
    audit commit; the refused move is tolerated and the next pass, seeing a
    terminal candidate, leaves the bytes where they are (29.5)."""
    staged, candidate_id = _unmapped_finalizing(harness)
    handle = _hold_open_sharing_reads(staged)
    try:
        report = _ok(harness.recover())
    finally:
        _winapi.CloseHandle(handle)
    assert report.quarantined == 1
    after = harness.durable()
    assert after.candidate_states[candidate_id] == "QUARANTINED"
    assert staged.is_file()
    assert after.quarantine_entries == ()
    assert after.audit_actions.count("RECONCILIATION_CANDIDATE_QUARANTINED") == 1
    assert _ok(harness.recover()).changes == 0
    assert staged.is_file()


def test_summary_commit_failure_is_reported_and_the_next_pass_closes_normally(
    harness: MemoryFinalizationHarness,
) -> None:
    harness.plant_run()
    harness.unit_of_work.fail_next_committed(_write_failure())
    failed = harness.recover()
    assert _code(failed) == WRITE_FAILED
    assert harness.durable().audit_actions == ()
    report = _ok(harness.recover())
    assert report.changes == 0
    assert harness.durable().audit_actions == ("RECONCILIATION_FINALIZATION_RESUMED",)


# --------------------------------------------------------------------------
# 17.3 after a refusal before T1: the rows the finalizer already quarantined
# --------------------------------------------------------------------------

_LEAKING_FILES = {
    "results/native.bin": b"prefix " + FIXTURE_TOKEN.encode("ascii") + b" suffix\n",
    "results/second.bin": b"clean native result bytes\n",
}


def test_pre_lease_refusal_during_result_recovery_fails_the_attempt_once(
    harness: MemoryFinalizationHarness,
) -> None:
    """A validated temporary manifest whose candidate bytes still carry the raw
    attempt token: the finalizer refuses before T1 and quarantines every RESULT
    candidate itself (14.7). The pass then fails the run under that diagnostic
    and closes the root -- leaving the rows the finalizer already moved at their
    revision rather than re-quarantining them -- and a second pass changes
    nothing."""
    plan = harness.plant_result_prestate(files=_LEAKING_FILES)
    harness.validator.plant(_planted_facts())
    report = _ok(harness.recover())
    assert (report.resumed, report.registered, report.abandoned) == (1, 0, 0)
    assert report.quarantined == 0  # the finalizer's own quarantine, not step 4's
    assert report.closed_roots == 1
    after = harness.durable()
    assert after.journal == ()
    assert all(state == "QUARANTINED" for state in after.candidate_states.values())
    assert after.run_state == "FAILED"
    assert after.run is not None
    primary = after.run.primary_terminal_diagnostic_id
    assert any(
        diagnostic.diagnostic_id == primary
        and diagnostic.error_code == SECURITY_SENSITIVE_MATERIAL_LEAKAGE
        for diagnostic in after.diagnostics
    )
    assert after.audit_actions.count("RUN_FAILED") == 1
    assert "RECONCILIATION_CANDIDATE_QUARANTINED" not in after.audit_actions
    assert after.audit_actions.count("RETENTION_DELETED") == 1
    assert not plan.roots.request_path.exists()
    assert {entry.entry_id for entry in after.quarantine_entries} == {
        candidate.candidate_artifact_id for candidate in plan.candidates
    }
    assert _ok(harness.recover()).changes == 0


# --------------------------------------------------------------------------
# Fault injection at the members each step consults, and the stray entries of
# the runtime, object and quarantine roots
# --------------------------------------------------------------------------


def _fail_call(
    monkeypatch: pytest.MonkeyPatch,
    owner: type,
    method: str,
    failure: Failure,
    *,
    call: int = 1,
) -> None:
    """Replace ``owner.method`` so that its ``call``-th invocation, counted across
    every transaction from this moment on, answers ``failure``; every other
    invocation runs the original."""
    original = getattr(owner, method)
    counter = {"calls": 0}

    def patched(self: object, *args: Any, **kwargs: Any) -> Any:
        counter["calls"] += 1
        if counter["calls"] == call:
            return failure
        return original(self, *args, **kwargs)

    monkeypatch.setattr(owner, method, patched)


def _hold_open_without_sharing(path: Path) -> int:
    return _winapi.CreateFile(
        str(path),
        _winapi.GENERIC_READ,
        0,
        _winapi.NULL,
        _winapi.OPEN_EXISTING,
        0,
        _winapi.NULL,
    )


def _refusing(harness: MemoryFinalizationHarness, action: str) -> RefusingAuditor:
    refusing = RefusingAuditor(
        harness.audit_ids,
        harness.clock,
        refused_action=action,
        failure=_write_failure(),
    )
    harness.auditor = refusing
    return refusing


def _reconcile_at(
    harness: MemoryFinalizationHarness, runtime_root: Path
) -> Result[FinalizationReconciliationReport]:
    return reconcile_finalization(
        unit_of_work_factory=harness.unit_of_work.begin,
        store=harness.roots.store,
        hasher=harness.hasher,
        registrar=harness.registrar,
        recovery_validator=harness.validator,
        auditor=harness.auditor,
        clock=harness.clock,
        runtime_root=runtime_root,
        command_roots=harness.command_roots,
        token_material=harness.token_material,
    )


def test_open_journal_listing_fault_fails_the_pass_before_any_change(
    harness: MemoryFinalizationHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = harness.plant_result_prestate()
    before = harness.durable()
    _fail_call(
        monkeypatch, MemoryFinalizationJournalRepository, "list_open", _write_failure()
    )
    failed = harness.recover()
    assert _code(failed) == WRITE_FAILED
    assert harness.durable() == before
    assert plan.roots.request_path.is_file()


@pytest.mark.parametrize(
    ("owner", "method", "call"),
    [
        pytest.param(
            MemoryCandidateArtifactRepository, "list_recoverable", 1, id="candidates"
        ),
        pytest.param(
            MemoryFinalizationJournalRepository, "list_open", 2, id="journals"
        ),
    ],
)
def test_candidate_step_read_faults_fail_the_pass_before_any_change(
    harness: MemoryFinalizationHarness,
    monkeypatch: pytest.MonkeyPatch,
    owner: type,
    method: str,
    call: int,
) -> None:
    harness.plant_result_prestate()
    before = harness.durable()
    _fail_call(monkeypatch, owner, method, _write_failure(), call=call)
    failed = harness.recover()
    assert _code(failed) == WRITE_FAILED
    assert harness.durable() == before


def test_terminal_journal_whose_read_fails_is_not_counted(
    harness: MemoryFinalizationHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The report counts what the pass could read back: a resumed journal whose
    terminal state cannot be re-read after the resume counts as neither."""
    plan = harness.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        harness.finalize(plan.request, probe=CrashingProbe("after_moved"))
    harness.advance_clock(RESULT_LEASE_SECONDS + 1)
    _fail_call(
        monkeypatch, MemoryFinalizationJournalRepository, "get", _write_failure()
    )
    report = _ok(harness.recover())
    assert (report.resumed, report.abandoned, report.registered) == (1, 0, 0)
    assert harness.durable().journal_state == "ABANDONED"


def test_stray_directories_under_the_runtime_root_are_left_alone(
    harness: MemoryFinalizationHarness,
) -> None:
    """Step 9 attaches nothing by name: a directory not shaped like a command
    root is neither entered nor quarantined, and an ``inv_`` root whose
    invocation names no run (a DESCRIBE) is left to its own cleanup."""
    harness.plant_run()
    junk = harness.roots.runtime_root / "not-a-command-root"
    junk.mkdir()
    (junk / "file.txt").write_bytes(b"left alone\n")
    describe_root = harness.roots.runtime_root / OTHER_INVOCATION_ID
    describe_root.mkdir()
    (describe_root / "request.json").write_bytes(b'{"describe": true}')
    harness.store_data.tables.invocations[OTHER_INVOCATION_ID] = sample_invocation(
        CommandInvocationState.EXITED,
        kind=CommandKind.DESCRIBE,
        invocation_id=OTHER_INVOCATION_ID,
    )
    report = _ok(harness.recover())
    assert (report.quarantined, report.changes) == (0, 0)
    assert (junk / "file.txt").is_file()
    assert (describe_root / "request.json").is_file()
    assert harness.durable().quarantine_entries == ()


def test_runtime_root_must_be_absolute_and_may_be_absent(
    harness: MemoryFinalizationHarness,
) -> None:
    harness.plant_run()
    with pytest.raises(ValueError, match="absolute"):
        _reconcile_at(harness, Path("relative-root"))
    report = _ok(_reconcile_at(harness, harness.roots.runtime_root / "absent"))
    assert report.changes == 0


def test_orphan_root_with_a_held_file_is_quarantined_as_far_as_possible(
    harness: MemoryFinalizationHarness,
) -> None:
    """RV-6 when one file of the orphan root cannot be moved: the other files are
    quarantined and audited, the held file and its directories stay, and the next
    pass finishes the entry once the handle is released."""
    harness.plant_run()
    orphan = harness.roots.runtime_root / _ORPHAN_INVOCATION_ID
    work = orphan / "runs" / RUN_ID / "work"
    work.mkdir(parents=True)
    (orphan / "request.json").write_bytes(b'{"orphan": true}')
    held = work / "held.bin"
    held.write_bytes(b"held\n")
    handle = _hold_open_without_sharing(held)
    try:
        report = _ok(harness.recover())
    finally:
        _winapi.CloseHandle(handle)
    assert report.quarantined == 1
    assert held.is_file()
    assert not (orphan / "request.json").exists()
    (entry,) = harness.durable().quarantine_entries
    assert entry.files == ("request.json",)
    second = _ok(harness.recover())
    assert second.quarantined == 1
    assert not orphan.exists()
    (entry,) = harness.durable().quarantine_entries
    assert entry.files == ("request.json", f"runs/{RUN_ID}/work/held.bin")


def test_orphan_file_whose_name_the_path_grammar_refuses_stays_in_place(
    harness: MemoryFinalizationHarness,
) -> None:
    """RV-6 never moves what it cannot confine: a file whose name the candidate
    path grammar refuses stays with its directory while the rest of the orphan
    is quarantined and the orphan audited."""
    harness.plant_run()
    orphan = harness.roots.runtime_root / _ORPHAN_INVOCATION_ID
    orphan.mkdir()
    (orphan / "request.json").write_bytes(b'{"orphan": true}')
    odd = orphan / "odd name.json"
    odd.write_bytes(b"odd\n")
    report = _ok(harness.recover())
    assert report.quarantined == 1
    assert odd.is_file()
    assert not (orphan / "request.json").exists()
    (entry,) = harness.durable().quarantine_entries
    assert entry.files == ("request.json",)
    assert (
        harness.durable().audit_actions.count("RECONCILIATION_ORPHAN_QUARANTINED") == 1
    )


def test_orphan_audit_refusal_fails_the_pass_after_the_bytes_moved(
    harness: MemoryFinalizationHarness,
) -> None:
    harness.plant_run()
    orphan = harness.roots.runtime_root / _ORPHAN_INVOCATION_ID
    orphan.mkdir()
    (orphan / "request.json").write_bytes(b'{"orphan": true}')
    refusing = _refusing(harness, "RECONCILIATION_ORPHAN_QUARANTINED")
    failed = harness.recover()
    assert _code(failed) == WRITE_FAILED
    assert refusing.refusals == 1
    assert not orphan.exists()  # the move is a filesystem fact
    assert harness.durable().audit_actions == ()


def test_terminal_root_with_an_open_result_journal_is_not_closed(
    harness: MemoryFinalizationHarness,
) -> None:
    """RV-8's close waits for the journal: a terminal run whose RESULT journal
    is still open under a live holder's lease keeps its raw-bearing bytes."""
    plan = harness.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        harness.finalize(plan.request, probe=CrashingProbe("after_moved"))
    current = harness.store_data.tables.runs[RUN_ID]
    harness.store_data.tables.runs[RUN_ID] = sample_run(
        EngineRunState.CANCELLED, revision=current.revision + 1
    )
    report = _ok(harness.recover())
    assert (report.deferred, report.closed_roots, report.changes) == (1, 0, 0)
    assert plan.roots.request_path.is_file()


def test_terminal_attempt_without_command_roots_quarantines_rows_only(
    harness: MemoryFinalizationHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RV-8 when the RUN root is unknown to the lookup: the rows are quarantined
    without a byte move and no root is closed."""
    plan = harness.plant_result_prestate()
    current = harness.store_data.tables.runs[RUN_ID]
    harness.store_data.tables.runs[RUN_ID] = sample_run(
        EngineRunState.FAILED, revision=current.revision + 1
    )
    monkeypatch.setattr(harness, "command_roots", lambda invocation_id: MISSING)
    report = _ok(harness.recover())
    assert (report.quarantined, report.closed_roots) == (2, 0)
    after = harness.durable()
    assert all(state == "QUARANTINED" for state in after.candidate_states.values())
    assert after.quarantine_entries == ()
    assert plan.roots.request_path.is_file()


def _failed_attempt(harness: MemoryFinalizationHarness) -> Any:
    """RV-8's pre-state: two CANDIDATE rows of a FAILED run with an EXITED
    run-command invocation and its root."""
    plan = harness.plant_result_prestate()
    current = harness.store_data.tables.runs[RUN_ID]
    harness.store_data.tables.runs[RUN_ID] = sample_run(
        EngineRunState.FAILED, revision=current.revision + 1
    )
    return plan


def test_close_root_journal_read_fault_fails_the_pass_after_the_quarantine(
    harness: MemoryFinalizationHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = _failed_attempt(harness)
    _fail_call(
        monkeypatch,
        MemoryFinalizationJournalRepository,
        "list_open",
        _write_failure(),
        call=3,
    )
    failed = harness.recover()
    assert _code(failed) == WRITE_FAILED
    after = harness.durable()
    assert all(state == "QUARANTINED" for state in after.candidate_states.values())
    assert plan.roots.request_path.is_file()
    report = _ok(harness.recover())
    assert report.closed_roots == 1
    assert not plan.roots.request_path.exists()


@pytest.mark.parametrize("fault", ["audit", "commit"])
def test_close_root_transaction_faults_fail_the_pass_after_the_removal(
    harness: MemoryFinalizationHarness, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    """The raw-byte removal is a filesystem fact; its transaction refused, the
    pass fails without the ``RETENTION_DELETED`` row and the next pass has
    nothing left to close."""
    plan = _failed_attempt(harness)
    if fault == "audit":
        _refusing(harness, "RETENTION_DELETED")
    else:
        _fail_call(
            monkeypatch,
            MemoryFinalizationTransaction,
            "commit",
            _write_failure(),
            call=3,
        )
    failed = harness.recover()
    assert _code(failed) == WRITE_FAILED
    assert not plan.roots.request_path.exists()
    assert "RETENTION_DELETED" not in harness.durable().audit_actions
    report = _ok(harness.recover())
    assert (report.closed_roots, report.changes) == (0, 0)


def _planted_refusal() -> Failure:
    """A 29.3 refusal with a known diagnostic: its identity is content-addressed
    (the clock instant is not hash material), so a pass that re-derives the same
    refusal records the same diagnostic."""
    return artifact_failure(
        ARTIFACT_RESULT_MANIFEST_INVALID,
        message="the temporary manifest names a candidate the rows do not",
        now_utc=INSTANT,
    )


def _assert_attempt_failed_under(
    harness: MemoryFinalizationHarness, plan: ResultPlan, diagnostic_id: str
) -> None:
    """17.3 completed once: the run FAILED under ``diagnostic_id`` as its primary
    terminal diagnostic, every candidate QUARANTINED under the same diagnostic
    with its bytes in the entry keyed by its identity, the root closed."""
    after = harness.durable()
    assert after.run_state == "FAILED"
    assert after.run is not None
    assert after.run.primary_terminal_diagnostic_id == diagnostic_id
    assert after.run_revision == plan.run.revision + 1
    assert all(state == "QUARANTINED" for state in after.candidate_states.values())
    for candidate in after.candidates:
        assert candidate.validation_observations[-1].diagnostic_id == diagnostic_id
    assert any(
        diagnostic.diagnostic_id == diagnostic_id for diagnostic in after.diagnostics
    )
    assert after.audit_actions.count("RUN_FAILED") == 1
    assert after.audit_actions.count("RECONCILIATION_CANDIDATE_QUARANTINED") == 2
    assert {entry.entry_id for entry in after.quarantine_entries} == {
        candidate.candidate_artifact_id for candidate in plan.candidates
    }
    assert not plan.roots.request_path.exists()


def test_quarantine_fault_inside_a_failed_recovery_check_fails_the_pass(
    harness: MemoryFinalizationHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A candidate swap refused inside 17.3's one transaction leaves the
    pre-state -- the run RUNNING beside its recoverable rows -- and the next
    pass completes the failure once."""
    plan = harness.plant_result_prestate()
    refusal = _planted_refusal()
    harness.validator.plant(refusal)
    before = harness.durable()
    _fail_call(
        monkeypatch,
        MemoryCandidateArtifactRepository,
        "compare_and_swap",
        _write_failure(),
    )
    failed = harness.recover()
    assert _code(failed) == WRITE_FAILED
    assert harness.durable() == before
    report = _ok(harness.recover())
    assert (report.quarantined, report.closed_roots) == (2, 1)
    _assert_attempt_failed_under(harness, plan, refusal.diagnostics[0].diagnostic_id)
    assert _ok(harness.recover()).changes == 0


@pytest.mark.parametrize(
    ("owner", "method", "call"),
    [
        pytest.param(MemoryEngineRunRecords, "get", 2, id="run-read"),
        pytest.param(MemoryDiagnosticWriter, "record", 1, id="diagnostic"),
        pytest.param(MemoryEngineRunRecords, "compare_and_swap", 1, id="run-write"),
        pytest.param(MemoryFinalizationTransaction, "commit", 1, id="commit"),
    ],
)
def test_terminal_write_faults_leave_the_failed_check_retryable(
    harness: MemoryFinalizationHarness,
    monkeypatch: pytest.MonkeyPatch,
    owner: type,
    method: str,
    call: int,
) -> None:
    """17.3 after a failed check is one transaction: the run ``RUNNING -> FAILED``
    and the candidates ``-> QUARANTINED`` commit together or not at all. A
    refused terminal write therefore leaves the pre-state -- the recoverable rows
    beside a RUNNING run -- never quarantined rows the next pass can no longer
    list beside a run no pass would fail; the next pass re-derives the same
    refusal and completes 17.3 once under the same diagnostic."""
    plan = harness.plant_result_prestate()
    refusal = _planted_refusal()
    harness.validator.plant(refusal)
    before = harness.durable()
    _fail_call(monkeypatch, owner, method, _write_failure(), call=call)
    failed = harness.recover()
    assert _code(failed) == WRITE_FAILED
    during = harness.durable()
    assert during.run_state == "RUNNING"
    assert during.run_revision == plan.run.revision
    assert during.candidate_states == before.candidate_states
    assert during == before
    assert plan.roots.request_path.is_file()
    monkeypatch.undo()
    report = _ok(harness.recover())
    assert (report.resumed, report.quarantined, report.closed_roots) == (0, 2, 1)
    _assert_attempt_failed_under(harness, plan, refusal.diagnostics[0].diagnostic_id)
    assert _ok(harness.recover()).changes == 0


def test_terminal_write_audit_refusal_leaves_the_failed_check_retryable(
    harness: MemoryFinalizationHarness,
) -> None:
    plan = harness.plant_result_prestate()
    refusal = _planted_refusal()
    harness.validator.plant(refusal)
    before = harness.durable()
    normal = harness.auditor
    refusing = _refusing(harness, "RUN_FAILED")
    failed = harness.recover()
    assert _code(failed) == WRITE_FAILED
    assert refusing.refusals == 1
    assert harness.durable() == before
    harness.auditor = normal
    report = _ok(harness.recover())
    assert (report.quarantined, report.closed_roots) == (2, 1)
    _assert_attempt_failed_under(harness, plan, refusal.diagnostics[0].diagnostic_id)
    assert _ok(harness.recover()).changes == 0


def test_result_candidates_of_a_missing_invocation_are_quarantined(
    harness: MemoryFinalizationHarness,
) -> None:
    """RV-7 when the run-command invocation row is gone: the candidates are
    quarantined under their identities (their bytes with them) and the command
    root, naming no invocation any more, is the RV-6 orphan of the same pass."""
    plan = harness.plant_result_prestate()
    del harness.store_data.tables.invocations[INVOCATION_ID]
    report = _ok(harness.recover())
    assert report.quarantined == 3
    after = harness.durable()
    assert all(state == "QUARANTINED" for state in after.candidate_states.values())
    assert {entry.entry_id for entry in after.quarantine_entries} == {
        INVOCATION_ID,
        *(candidate.candidate_artifact_id for candidate in plan.candidates),
    }
    assert not plan.roots.command_root.exists()
    assert after.run_state == "RUNNING"
    assert any(
        "does not exist" in diagnostic.message for diagnostic in after.diagnostics
    )


def test_result_candidates_of_a_run_neither_running_nor_terminal_wait(
    harness: MemoryFinalizationHarness,
) -> None:
    plan = harness.plant_result_prestate()
    current = harness.store_data.tables.runs[RUN_ID]
    harness.store_data.tables.runs[RUN_ID] = sample_run(
        EngineRunState.STARTING, revision=current.revision + 1
    )
    before = harness.durable()
    report = _ok(harness.recover())
    assert report.changes == 0
    after = harness.durable()
    assert after.candidates == before.candidates
    assert plan.roots.request_path.is_file()


def test_diagnostic_correlated_core_staging_resumes_from_phase_two(
    harness: MemoryFinalizationHarness,
) -> None:
    evidence = harness.plant_evidence_prestate(
        owner=SYSTEM_OWNER, correlation=DIAGNOSTIC_CORRELATION
    )
    report = _ok(harness.recover())
    assert (report.resumed, report.registered) == (1, 1)
    after = harness.durable()
    assert after.journal_state == "REGISTERED"
    (ref,) = after.refs
    assert (
        ref.source_candidate_artifact_id == evidence.candidates[0].candidate_artifact_id
    )


def _forbidden_descriptor_staging(harness: MemoryFinalizationHarness) -> None:
    """Core staging whose role admits no DIAGNOSTIC correlation: the group forms
    no EVIDENCE request."""
    candidates = plant_core_evidence(
        harness.roots.store,
        owner=ADAPTER_OWNER,
        correlation=DIAGNOSTIC_CORRELATION,
        files={"descriptor.json": b'{"adapter_name": "adapter.alpha"}\n'},
        source_role=ArtifactSourceRole.ADAPTER_DESCRIPTOR_EVIDENCE,
        artifact_kind="adapter-descriptor",
    )
    for candidate in candidates:
        harness.store_data.candidates[candidate.candidate_artifact_id] = candidate


def test_core_staging_whose_role_forbids_its_correlation_is_quarantined(
    harness: MemoryFinalizationHarness,
) -> None:
    _forbidden_descriptor_staging(harness)
    report = _ok(harness.recover())
    assert report.quarantined == 1
    after = harness.durable()
    assert all(state == "QUARANTINED" for state in after.candidate_states.values())
    assert any(
        "forms no EVIDENCE request" in diagnostic.message
        for diagnostic in after.diagnostics
    )
    assert after.staging_files == ()
    # An ADAPTER owner's quarantine carries no run correlation.
    (quarantined,) = [
        event
        for event in after.audit_events
        if event.action.value == "RECONCILIATION_CANDIDATE_QUARANTINED"
    ]
    assert not isinstance(quarantined.run_id, str)


def test_unregistered_blob_that_cannot_be_moved_is_left_for_the_next_pass(
    harness: MemoryFinalizationHarness,
) -> None:
    harness.plant_run()
    stray = _plant_stray_blob(harness)
    handle = _hold_open_without_sharing(stray)
    try:
        report = _ok(harness.recover())
    finally:
        _winapi.CloseHandle(handle)
    assert report.quarantined == 0
    assert stray.is_file()
    assert "RECONCILIATION_ORPHAN_QUARANTINED" not in harness.durable().audit_actions
    second = _ok(harness.recover())
    assert second.quarantined == 1
    assert not stray.exists()


def test_unregistered_blob_audit_refusal_fails_the_pass_after_the_move(
    harness: MemoryFinalizationHarness,
) -> None:
    harness.plant_run()
    stray = _plant_stray_blob(harness)
    refusing = _refusing(harness, "RECONCILIATION_ORPHAN_QUARANTINED")
    failed = harness.recover()
    assert _code(failed) == WRITE_FAILED
    assert refusing.refusals == 1
    assert not stray.exists()
    assert harness.durable().audit_actions == ()


def test_unregistered_content_sweep_journal_read_fault_fails_the_pass(
    harness: MemoryFinalizationHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness.plant_run()
    stray = _plant_stray_blob(harness)
    _fail_call(
        monkeypatch,
        MemoryFinalizationJournalRepository,
        "list_open",
        _write_failure(),
        call=3,
    )
    failed = harness.recover()
    assert _code(failed) == WRITE_FAILED
    assert stray.is_file()


def test_unreadable_projections_never_decide_a_sweep(
    harness: MemoryFinalizationHarness,
) -> None:
    """Plan 6.2: a projection that is a directory or not a manifest is skipped;
    the stray blob is still quarantined by the rows' verdict alone."""
    harness.plant_run()
    stray = _plant_stray_blob(harness)
    manifests_root = harness.roots.store.manifests_root
    (manifests_root / "directory.json").mkdir()
    (manifests_root / "garbage.json").write_bytes(b"not a manifest")
    report = _ok(harness.recover())
    assert report.quarantined == 1
    assert not stray.exists()
    assert (manifests_root / "directory.json").is_dir()
    assert (manifests_root / "garbage.json").is_file()


def _overdue_entry(harness: MemoryFinalizationHarness) -> str:
    stray = harness.roots.runtime_root / "stray.txt"
    stray.write_bytes(b"overdue bytes\n")
    confined = _ok(
        confine_candidate_path(harness.roots.runtime_root, "stray.txt", now_utc=INSTANT)
    )
    _ok(
        harness.roots.store.quarantine_move(
            confined, "manual-entry", ARTIFACT_MOVE_FAILED, now_utc=INSTANT
        )
    )
    harness.advance_clock(QUARANTINE_OVERDUE_SECONDS + 1)
    return "manual-entry"


def test_quarantine_entry_without_metadata_is_never_overdue(
    harness: MemoryFinalizationHarness,
) -> None:
    harness.plant_run()
    bare = harness.roots.quarantine_root / "bare-entry"
    bare.mkdir()
    (bare / "file.txt").write_bytes(b"no metadata\n")
    harness.advance_clock(QUARANTINE_OVERDUE_SECONDS + 1)
    report = _ok(harness.recover())
    assert report.overdue == 0
    assert "QUARANTINE_OVERDUE" not in harness.durable().audit_actions


@pytest.mark.parametrize(
    ("owner", "method"),
    [
        pytest.param(MemoryDiagnosticWriter, "record", id="diagnostic"),
        pytest.param(MemoryFinalizationTransaction, "commit", id="commit"),
    ],
)
def test_overdue_report_faults_fail_the_pass_and_the_next_pass_reports(
    harness: MemoryFinalizationHarness,
    monkeypatch: pytest.MonkeyPatch,
    owner: type,
    method: str,
) -> None:
    harness.plant_run()
    _overdue_entry(harness)
    _fail_call(monkeypatch, owner, method, _write_failure())
    failed = harness.recover()
    assert _code(failed) == WRITE_FAILED
    assert "QUARANTINE_OVERDUE" not in harness.durable().audit_actions
    monkeypatch.undo()
    report = _ok(harness.recover())
    assert report.overdue == 1


def test_overdue_audit_refusal_fails_the_pass(
    harness: MemoryFinalizationHarness,
) -> None:
    harness.plant_run()
    _overdue_entry(harness)
    refusing = _refusing(harness, "QUARANTINE_OVERDUE")
    failed = harness.recover()
    assert _code(failed) == WRITE_FAILED
    assert refusing.refusals == 1
    assert ARTIFACT_QUARANTINE_OVERDUE not in harness.durable().diagnostic_codes


def _purge(harness: MemoryFinalizationHarness, entry_id: str) -> Result[None]:
    return purge_quarantine(
        entry_id,
        "retention-test",
        store=harness.roots.store,
        unit_of_work_factory=harness.unit_of_work.begin,
        auditor=harness.auditor,
        clock=harness.clock,
    )


def test_purge_refuses_an_unknown_entry_and_a_refused_journal_read(
    harness: MemoryFinalizationHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    entry_id = _overdue_entry(harness)
    missing = _purge(harness, "no-such-entry")
    assert _code(missing) == ARTIFACT_VALIDATION_FAILED
    assert "does not exist" in missing.diagnostics[0].message  # type: ignore[union-attr]
    _fail_call(
        monkeypatch, MemoryFinalizationJournalRepository, "list_open", _write_failure()
    )
    failed = _purge(harness, entry_id)
    assert _code(failed) == WRITE_FAILED
    assert (harness.roots.quarantine_root / entry_id / "stray.txt").is_file()


def test_purge_of_a_held_file_is_refused_and_leaves_the_entry(
    harness: MemoryFinalizationHarness,
) -> None:
    entry_id = _overdue_entry(harness)
    held = harness.roots.quarantine_root / entry_id / "stray.txt"
    handle = _hold_open_without_sharing(held)
    try:
        refused = _purge(harness, entry_id)
    finally:
        _winapi.CloseHandle(handle)
    assert _code(refused) == ARTIFACT_MOVE_FAILED
    assert held.is_file()
    assert harness.durable().audit_actions == ()


@pytest.mark.parametrize("fault", ["audit", "commit"])
def test_purge_transaction_faults_are_answered_after_the_removal(
    harness: MemoryFinalizationHarness, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    entry_id = _overdue_entry(harness)
    if fault == "audit":
        _refusing(harness, "RETENTION_DELETED")
    else:
        _fail_call(
            monkeypatch, MemoryFinalizationTransaction, "commit", _write_failure()
        )
    failed = _purge(harness, entry_id)
    assert _code(failed) == WRITE_FAILED
    assert not (harness.roots.quarantine_root / entry_id).exists()
    assert "RETENTION_DELETED" not in harness.durable().audit_actions


def test_purge_proceeds_when_the_open_journals_name_another_entry(
    harness: MemoryFinalizationHarness,
) -> None:
    entry_id = _overdue_entry(harness)
    evidence = harness.plant_evidence_prestate()
    with pytest.raises(FinalizationCrash):
        harness.finalize(evidence.request, probe=CrashingProbe("after_prepared"))
    assert harness.durable().journal_state == "PREPARED"
    purged = _purge(harness, entry_id)
    assert isinstance(purged, Success), purged
    assert not (harness.roots.quarantine_root / entry_id).exists()


# -- the remaining quarantine, close and sweep branches ------------------------------


@pytest.mark.parametrize(
    ("owner", "method"),
    [
        pytest.param(MemoryCandidateArtifactRepository, "get", id="row-read"),
        pytest.param(MemoryDiagnosticWriter, "record", id="diagnostic"),
    ],
)
def test_quarantine_transaction_faults_fail_the_pass_unchanged(
    harness: MemoryFinalizationHarness,
    monkeypatch: pytest.MonkeyPatch,
    owner: type,
    method: str,
) -> None:
    """The quarantine re-reads the row and records the diagnostic inside its own
    transaction; either refused, the pass answers the failure with nothing
    written."""
    harness.plant_result_prestate()
    before = harness.durable()
    _fail_call(monkeypatch, owner, method, _write_failure())
    failed = harness.recover()
    assert _code(failed) == WRITE_FAILED
    assert harness.durable() == before


def test_evidence_group_quarantine_fault_fails_the_pass_unchanged(
    harness: MemoryFinalizationHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    _forbidden_descriptor_staging(harness)
    before = harness.durable()
    _fail_call(
        monkeypatch,
        MemoryCandidateArtifactRepository,
        "compare_and_swap",
        _write_failure(),
    )
    failed = harness.recover()
    assert _code(failed) == WRITE_FAILED
    assert harness.durable() == before


@pytest.mark.parametrize(
    ("owner", "method"),
    [
        pytest.param(MemoryDiagnosticWriter, "record", id="diagnostic"),
        pytest.param(MemoryCandidateArtifactRepository, "compare_and_swap", id="swap"),
    ],
)
def test_terminal_attempt_quarantine_fault_fails_the_pass_unchanged(
    harness: MemoryFinalizationHarness,
    monkeypatch: pytest.MonkeyPatch,
    owner: type,
    method: str,
) -> None:
    """RV-8's quarantine of a terminal attempt's candidates runs one transaction
    per candidate with no run write; its diagnostic record or its swap refused,
    the pass answers the failure with nothing written and the root untouched."""
    plan = _failed_attempt(harness)
    before = harness.durable()
    _fail_call(monkeypatch, owner, method, _write_failure())
    failed = harness.recover()
    assert _code(failed) == WRITE_FAILED
    assert harness.durable() == before
    assert plan.roots.request_path.is_file()


class _CancellingValidator(MemoryRecoveryValidator):
    """The 29.3 check during which a terminal winner moves the run: the default
    refusal is answered after the run row changed under the pass."""

    def __init__(self, harness: MemoryFinalizationHarness) -> None:
        super().__init__(harness.clock)
        self._harness = harness

    def validate_temporary_manifest(
        self,
        roots: Any,
        token: Any,
        candidates: Any,
    ) -> Result[ResultRecoveryFacts]:
        runs = self._harness.store_data.tables.runs
        current = runs[RUN_ID]
        runs[RUN_ID] = sample_run(
            EngineRunState.CANCELLED, revision=current.revision + 1
        )
        return super().validate_temporary_manifest(roots, token, candidates)


def test_run_moved_during_the_recovery_check_is_left_to_its_winner(
    harness: MemoryFinalizationHarness,
) -> None:
    """17.3 never overwrites a terminal winner: the run a cancellation moved
    while the check ran keeps its state and revision, the candidates are still
    quarantined and the root still closed."""
    plan = harness.plant_result_prestate()
    harness.validator = _CancellingValidator(harness)
    report = _ok(harness.recover())
    assert (report.quarantined, report.closed_roots) == (2, 1)
    after = harness.durable()
    assert after.run_state == "CANCELLED"
    assert "RUN_FAILED" not in after.audit_actions
    assert all(state == "QUARANTINED" for state in after.candidate_states.values())
    assert not plan.roots.request_path.exists()


def test_abandoned_core_staging_without_bytes_is_quarantined_without_a_move(
    harness: MemoryFinalizationHarness,
) -> None:
    """RV-10 when the staged bytes are already gone: the row is quarantined and
    audited; nothing is moved and no quarantine entry is created."""
    evidence = harness.plant_evidence_prestate()
    (candidate,) = evidence.candidates
    invocation = harness.store_data.tables.invocations[INVOCATION_ID]
    harness.store_data.tables.invocations[INVOCATION_ID] = _cleaned_up(invocation)
    _staged_path(harness, candidate.staging_relative_path).unlink()
    report = _ok(harness.recover())
    assert report.quarantined == 1
    after = harness.durable()
    assert after.candidate_states[candidate.candidate_artifact_id] == "QUARANTINED"
    assert after.quarantine_entries == ()
    assert after.audit_actions.count("RECONCILIATION_CANDIDATE_QUARANTINED") == 1


def test_step_nine_close_fault_fails_the_pass_and_the_next_pass_closes(
    harness: MemoryFinalizationHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no recoverable rows left, step 9 owns the close of a terminal run's
    root; its journal read refused, the pass fails and the root waits."""
    plan = _failed_attempt(harness)
    harness.store_data.candidates.clear()
    _fail_call(
        monkeypatch,
        MemoryFinalizationJournalRepository,
        "list_open",
        _write_failure(),
        call=3,
    )
    failed = harness.recover()
    assert _code(failed) == WRITE_FAILED
    assert plan.roots.request_path.is_file()
    report = _ok(harness.recover())
    assert report.closed_roots == 1
    assert not plan.roots.request_path.exists()


def test_absent_objects_root_has_nothing_to_sweep(
    harness: MemoryFinalizationHarness,
) -> None:
    harness.plant_run()
    harness.roots.store.objects_root.rmdir()
    report = _ok(harness.recover())
    assert report.changes == 0


def test_absent_manifests_root_never_decides_a_sweep(
    harness: MemoryFinalizationHarness,
) -> None:
    harness.plant_run()
    harness.roots.store.manifests_root.rmdir()
    stray = _plant_stray_blob(harness)
    report = _ok(harness.recover())
    assert report.quarantined == 1
    assert not stray.exists()


def test_a_grammar_refused_projection_stays_while_the_orphan_blob_is_quarantined(
    harness: MemoryFinalizationHarness,
) -> None:
    """RV-9 never moves what it cannot confine: a projection under ``manifests/``
    whose name the candidate path grammar refuses stays in place (the orphan
    operation is scoped to ``objects/``), while the stray blob is quarantined
    under its digest and the space-bearing file beside it under its derived
    orphan identity."""
    harness.plant_run()
    stray = _plant_stray_blob(harness)
    odd_blob = harness.roots.store.objects_root / "odd name.bin"
    odd_blob.write_bytes(b"unconfinable\n")
    phantom = sample_ref(
        sample_candidate(
            "SYSTEM",
            _F.EVIDENCE,
            producer=_P.CORE,
            state=_S.FINALIZING,
            candidate_artifact_id=THIRD_CANDIDATE_ID,
        ),
        content_hash=_STRAY_DIGEST,
        size_bytes=len(_STRAY_BYTES),
    )
    odd_projection = harness.roots.store.manifests_root / "odd name.json"
    odd_projection.write_bytes(canonical_json_bytes(sample_artifact_manifest(phantom)))
    report = _ok(harness.recover())
    assert report.quarantined == 2
    assert not stray.exists()
    assert not odd_blob.exists()
    assert odd_projection.is_file()
    entries = harness.durable().quarantine_entries
    assert {entry.entry_id for entry in entries} == {
        _STRAY_DIGEST,
        _orphan_entry_id("objects/odd name.bin"),
    }
    assert _ok(harness.recover()).changes == 0


def test_non_content_addressed_file_under_objects_gets_a_derived_identity(
    harness: MemoryFinalizationHarness,
) -> None:
    """RV-9 for a file the store never wrote whose name the path grammar admits:
    unregistered by construction -- no row registers a path outside
    ``objects/<hh>/<sha256>``, so the rows are never asked about the name and the
    armed content-hash read fault is never consumed -- it is quarantined under an
    identity derived from its confined relative path, never the untrusted name,
    with no digest claim; the metadata keeps the path for inspection and a
    second pass changes nothing."""
    harness.plant_run()
    stray = harness.roots.store.objects_root / "stray.tmp"
    stray.write_bytes(b"not a blob\n")
    harness.unit_of_work.fail_next_reference_lookup(_read_failure())
    report = _ok(harness.recover())
    assert report.quarantined == 1
    assert not stray.exists()
    after = harness.durable()
    (entry,) = after.quarantine_entries
    assert entry.entry_id != "stray.tmp"
    assert entry.entry_id.startswith("unregistered_")
    assert entry.files == ("objects/stray.tmp",)
    metadata_path = (
        harness.roots.quarantine_root / entry.entry_id / QUARANTINE_METADATA_NAME
    )
    metadata = QuarantineMetadata.model_validate_json(metadata_path.read_bytes())
    assert metadata.relative_path == "objects/stray.tmp"
    assert not isinstance(metadata.sha256, str)
    assert (metadata_path.parent / "objects" / "stray.tmp").read_bytes() == (
        b"not a blob\n"
    )
    (quarantined,) = [
        event
        for event in after.audit_events
        if event.action.value == "RECONCILIATION_ORPHAN_QUARANTINED"
    ]
    assert quarantined.correlation_id == entry.entry_id
    # The read fault is still armed: no content-hash read was ever issued.
    assert harness.unit_of_work.take_pending_reference_lookup_failure() is not None
    assert _ok(harness.recover()).changes == 0


@pytest.mark.parametrize("name", _ORPHAN_NAMES)
def test_rv9_grammar_refused_name_under_objects_is_quarantined_as_an_orphan(
    harness: MemoryFinalizationHarness, name: str
) -> None:
    """RV-9 over an ordinary file under ``objects/`` whose name the candidate path
    grammar refuses (a leading dot, a space): the orphan confinement admits it,
    the bytes move into an audited entry keyed by the identity derived from the
    confined relative path and lie at the plan 6.2 layout
    ``<quarantine>/<entry_id>/<original relative path>``, the metadata is
    readable, names that path and claims no digest, no reference is created,
    and a second pass changes nothing."""
    harness.plant_run()
    before = harness.durable()
    relative = f"objects/{name}"
    stray = harness.roots.store.objects_root / name
    stray.write_bytes(b"not a blob\n")
    report = _ok(harness.recover())
    assert report.quarantined == 1
    assert not stray.exists()
    after = harness.durable()
    (entry,) = after.quarantine_entries
    assert entry.entry_id == _orphan_entry_id(relative)
    assert name not in entry.entry_id
    assert entry.reason_code == ARTIFACT_VALIDATION_FAILED
    assert entry.files == (relative,)
    metadata_path = (
        harness.roots.quarantine_root / entry.entry_id / QUARANTINE_METADATA_NAME
    )
    metadata = QuarantineMetadata.model_validate_json(metadata_path.read_bytes())
    assert metadata.entry_id == entry.entry_id
    assert metadata.relative_path == relative
    assert metadata.source_root == str(harness.roots.artifacts_root)
    assert metadata.size_bytes == len(b"not a blob\n")
    assert not isinstance(metadata.sha256, str)
    assert (metadata_path.parent / "objects" / name).read_bytes() == b"not a blob\n"
    assert after.refs == before.refs
    assert after.object_blobs == before.object_blobs == ()
    (quarantined,) = [
        event
        for event in after.audit_events
        if event.action.value == "RECONCILIATION_ORPHAN_QUARANTINED"
    ]
    assert quarantined.correlation_id == entry.entry_id
    assert after.audit_actions == (
        "RECONCILIATION_ORPHAN_QUARANTINED",
        "RECONCILIATION_FINALIZATION_RESUMED",
    )
    assert _ok(harness.recover()).changes == 0
    assert harness.durable().quarantine_entries == (entry,)


def test_rv9_orphan_with_a_second_hard_link_is_left_for_a_later_pass(
    harness: MemoryFinalizationHarness,
) -> None:
    """The orphan confinement keeps the hard-link rule: an aliased ``.hidden``
    is left unmoved and unaudited; once the alias is gone the next pass
    quarantines it."""
    harness.plant_run()
    stray = harness.roots.store.objects_root / ".hidden"
    stray.write_bytes(b"not a blob\n")
    alias = harness.roots.runtime_root / "alias.bin"
    os.link(stray, alias)
    try:
        report = _ok(harness.recover())
        assert report.quarantined == 0
        assert stray.read_bytes() == b"not a blob\n"
        after = harness.durable()
        assert after.quarantine_entries == ()
        assert after.audit_actions == ("RECONCILIATION_FINALIZATION_RESUMED",)
    finally:
        alias.unlink()
    second = _ok(harness.recover())
    assert second.quarantined == 1
    assert not stray.exists()


def test_rv9_files_reached_through_a_junction_under_objects_are_never_moved(
    harness: MemoryFinalizationHarness,
) -> None:
    """A junction planted under ``objects/`` leads outside the store: the files
    behind it -- whatever their names -- are refused by the ancestor reparse rule
    of both confinements and nothing outside the root is opened or moved."""
    harness.plant_run()
    elsewhere = harness.roots.artifacts_root.parent / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / ".secret").write_bytes(b"outside\n")
    (elsewhere / "odd name.bin").write_bytes(b"outside too\n")
    (elsewhere / "stray.tmp").write_bytes(b"outside as well\n")
    junction = harness.roots.store.objects_root / "jx"
    _winapi.CreateJunction(str(elsewhere), str(junction))
    try:
        report = _ok(harness.recover())
    finally:
        os.rmdir(junction)
    assert report.quarantined == 0
    assert sorted(path.name for path in elsewhere.iterdir()) == [
        ".secret",
        "odd name.bin",
        "stray.tmp",
    ]
    assert (elsewhere / ".secret").read_bytes() == b"outside\n"
    after = harness.durable()
    assert after.quarantine_entries == ()
    assert after.audit_actions == ("RECONCILIATION_FINALIZATION_RESUMED",)


def test_rv9_orphan_no_identity_can_be_derived_from_is_left_in_place(
    harness: MemoryFinalizationHarness,
) -> None:
    """A name NTFS stores but UTF-8 cannot encode (a lone surrogate, built at
    runtime) is refused by the orphan grammar before any identity is derived:
    the pass answers a Result, never raises, and leaves the bytes in place."""
    harness.plant_run()
    stray = harness.roots.store.objects_root / f"bad{chr(0xDCFF)}name"
    stray.write_bytes(b"not a blob\n")
    report = _ok(harness.recover())
    assert report.quarantined == 0
    assert stray.read_bytes() == b"not a blob\n"
    after = harness.durable()
    assert after.quarantine_entries == ()
    assert after.audit_actions == ("RECONCILIATION_FINALIZATION_RESUMED",)
    assert _ok(harness.recover()).changes == 0


def test_rv9_orphan_whose_quarantine_destination_is_unsafe_is_left_in_place(
    harness: MemoryFinalizationHarness,
) -> None:
    """A reparse point planted where the orphan's entry root belongs is refused
    before anything is created or moved on its far side: the orphan stays, no
    audit row is written; with the junction gone the next pass quarantines it
    under that very identity."""
    harness.plant_run()
    stray = harness.roots.store.objects_root / ".hidden"
    stray.write_bytes(b"not a blob\n")
    entry_id = _orphan_entry_id("objects/.hidden")
    elsewhere = harness.roots.artifacts_root.parent / "elsewhere"
    elsewhere.mkdir()
    entry_root = harness.roots.quarantine_root / entry_id
    _winapi.CreateJunction(str(elsewhere), str(entry_root))
    try:
        report = _ok(harness.recover())
        assert report.quarantined == 0
        assert stray.read_bytes() == b"not a blob\n"
        assert list(elsewhere.iterdir()) == []
        after = harness.durable()
        assert after.quarantine_entries == ()
        assert after.audit_actions == ("RECONCILIATION_FINALIZATION_RESUMED",)
    finally:
        os.rmdir(entry_root)
    second = _ok(harness.recover())
    assert second.quarantined == 1
    assert not stray.exists()
    (entry,) = harness.durable().quarantine_entries
    assert entry.entry_id == entry_id
    assert entry.files == ("objects/.hidden",)


# --------------------------------------------------------------------------
# RV-9 routing: a canonical object is classified by its complete root-relative
# layout ``objects/<hh>/<sha256>`` with the shard matching the leaf, never by
# the leaf alone; a content-address leaf anywhere else is misplaced content.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("directory", _MISPLACED_DIRECTORIES)
def test_rv9_misplaced_content_address_is_quarantined_as_an_orphan(
    harness: MemoryFinalizationHarness, directory: str
) -> None:
    """A file whose leaf is the valid content address of its own bytes but which
    lies under a dot-prefixed, space-bearing or non-matching directory is no
    canonical object: the rows are never asked about it (the armed content-hash
    read fault is never consumed), it goes through the orphan operation under the
    identity derived from its confined relative path and lies at the plan 6.2
    layout ``<quarantine>/<entry_id>/<original relative path>`` with the
    metadata naming that path and no digest claim, no reference is created and
    a second pass changes nothing."""
    harness.plant_run()
    before = harness.durable()
    relative = f"objects/{directory}/{_STRAY_DIGEST}"
    stray = harness.roots.store.objects_root / directory / _STRAY_DIGEST
    stray.parent.mkdir()
    stray.write_bytes(_STRAY_BYTES)
    harness.unit_of_work.fail_next_reference_lookup(_read_failure())
    report = _ok(harness.recover())
    assert report.quarantined == 1
    assert not stray.exists()
    after = harness.durable()
    (entry,) = after.quarantine_entries
    assert entry.entry_id == _orphan_entry_id(relative)
    assert _STRAY_DIGEST not in entry.entry_id
    assert entry.reason_code == ARTIFACT_VALIDATION_FAILED
    assert entry.files == (relative,)
    metadata_path = (
        harness.roots.quarantine_root / entry.entry_id / QUARANTINE_METADATA_NAME
    )
    metadata = QuarantineMetadata.model_validate_json(metadata_path.read_bytes())
    assert metadata.entry_id == entry.entry_id
    assert metadata.relative_path == relative
    assert metadata.source_root == str(harness.roots.artifacts_root)
    assert metadata.size_bytes == len(_STRAY_BYTES)
    assert not isinstance(metadata.sha256, str)
    assert metadata_path.parent.joinpath(*relative.split("/")).read_bytes() == (
        _STRAY_BYTES
    )
    assert after.refs == before.refs == ()
    assert after.object_blobs == ()
    (quarantined,) = [
        event
        for event in after.audit_events
        if event.action.value == "RECONCILIATION_ORPHAN_QUARANTINED"
    ]
    assert quarantined.correlation_id == entry.entry_id
    assert after.audit_actions == (
        "RECONCILIATION_ORPHAN_QUARANTINED",
        "RECONCILIATION_FINALIZATION_RESUMED",
    )
    # The read fault is still armed: the rows were never asked about the leaf.
    assert harness.unit_of_work.take_pending_reference_lookup_failure() is not None
    assert _ok(harness.recover()).changes == 0
    assert harness.durable().quarantine_entries == (entry,)


def test_rv9_same_digest_orphan_is_quarantined_while_the_registered_blob_stays(
    harness: MemoryFinalizationHarness,
) -> None:
    """The same-digest control over a reference: a registered canonical blob and
    a misplaced copy of its very bytes under ``objects/.x/<sha256>``. Protection
    is decided by the complete durable path the ``artifact_refs`` row names, so
    only the misplaced copy is quarantined -- as an orphan, no digest claim --
    while the canonical blob, its row and its projection stay exactly as they
    were; no reference is created and a second pass changes nothing."""
    evidence = harness.plant_evidence_prestate()
    _ok(harness.finalize(evidence.request))
    before = harness.durable()
    (ref,) = before.refs
    digest = ref.content_hash
    canonical = harness.roots.store.finalized_path_for(digest)
    payload = canonical.read_bytes()
    assert hashlib.sha256(payload).hexdigest() == digest
    misplaced = harness.roots.store.objects_root / ".x" / digest
    misplaced.parent.mkdir()
    misplaced.write_bytes(payload)
    projections = _projections(harness)
    assert len(projections) == 1
    assert harness.durable().object_blobs == (digest, digest)
    report = _ok(harness.recover())
    assert report.quarantined == 1
    assert not misplaced.exists()
    assert canonical.read_bytes() == payload
    after = harness.durable()
    assert after.refs == before.refs
    assert after.object_blobs == (digest,)
    assert _projections(harness) == projections
    (entry,) = after.quarantine_entries
    assert entry.entry_id == _orphan_entry_id(f"objects/.x/{digest}")
    assert entry.entry_id != digest
    assert entry.files == (f"objects/.x/{digest}",)
    metadata_path = (
        harness.roots.quarantine_root / entry.entry_id / QUARANTINE_METADATA_NAME
    )
    metadata = QuarantineMetadata.model_validate_json(metadata_path.read_bytes())
    assert metadata.relative_path == f"objects/.x/{digest}"
    assert not isinstance(metadata.sha256, str)
    assert (metadata_path.parent / "objects" / ".x" / digest).read_bytes() == payload
    assert after.audit_actions.count("RECONCILIATION_ORPHAN_QUARANTINED") == 1
    assert _ok(harness.recover()).changes == 0
    assert harness.durable().refs == before.refs
    assert harness.durable().quarantine_entries == (entry,)
    assert canonical.read_bytes() == payload


def test_rv9_same_digest_orphan_is_quarantined_while_the_open_journal_blob_stays(
    harness: MemoryFinalizationHarness,
) -> None:
    """The same-digest control over an open journal: a ``MOVED`` RESULT journal
    under an unexpired lease is deferred and protects the blobs it planned by
    their complete finalized paths; a misplaced copy of one of those blobs under
    ``objects/odd dir/<sha256>`` is no planned path and is quarantined as an
    orphan, while the journal, its run and both canonical blobs stay."""
    plan = harness.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        harness.finalize(plan.request, probe=CrashingProbe("after_moved"))
    moved = harness.durable()
    assert moved.journal_state == "MOVED"
    assert len(moved.object_blobs) == 2
    (journal,) = moved.journal
    digest = journal.planned_paths[0].expected_sha256
    canonical = harness.roots.store.finalized_path_for(digest)
    payload = canonical.read_bytes()
    misplaced = harness.roots.store.objects_root / "odd dir" / digest
    misplaced.parent.mkdir()
    misplaced.write_bytes(payload)
    report = _ok(harness.recover())
    assert (report.deferred, report.resumed, report.quarantined) == (1, 0, 1)
    assert harness.registrar.result_calls == 0
    assert not misplaced.exists()
    assert canonical.read_bytes() == payload
    after = harness.durable()
    assert after.journal == moved.journal
    assert after.run_state == "RUNNING"
    assert after.refs == ()
    assert after.object_blobs == moved.object_blobs
    (entry,) = after.quarantine_entries
    assert entry.entry_id == _orphan_entry_id(f"objects/odd dir/{digest}")
    assert entry.files == (f"objects/odd dir/{digest}",)
    assert _ok(harness.recover()).changes == 0
    assert harness.durable().journal == moved.journal


# --------------------------------------------------------------------------
# RV-9 case semantics: the supported store is case-insensitive, so a canonical
# object and its protection are decided case-folded as Windows does -- a
# case-only rename of a shard or leaf leaves the very same file at the very
# path a row or a planned move names -- while the complete-path rule stays.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("component", _CASE_COMPONENTS)
def test_rv9_case_renamed_canonical_path_keeps_a_registered_blob(
    harness: MemoryFinalizationHarness, component: str
) -> None:
    """A registered blob whose shard directory or leaf received a case-only
    rename is still the file at the complete path its ``artifact_refs`` row
    names on the supported case-insensitive store: it is classified canonical,
    the row protects it, its bytes and rows are untouched, nothing is
    quarantined or audited as an orphan, and a second pass changes nothing."""
    evidence = harness.plant_evidence_prestate()
    _ok(harness.finalize(evidence.request))
    before = harness.durable()
    (ref,) = before.refs
    digest = ref.content_hash
    observed = _rename_case(harness.roots.store, digest, component)
    payload = observed.read_bytes()
    assert hashlib.sha256(payload).hexdigest() == digest
    report = _ok(harness.recover())
    assert report.quarantined == 0
    assert report.changes == 0
    assert observed.read_bytes() == payload
    assert harness.roots.store.finalized_path_for(digest).read_bytes() == payload
    after = harness.durable()
    assert after.refs == before.refs
    assert after.candidates == before.candidates
    assert after.journal == before.journal
    assert len(after.object_blobs) == len(before.object_blobs) == 1
    assert after.quarantine_entries == ()
    assert "RECONCILIATION_ORPHAN_QUARANTINED" not in after.audit_actions
    assert after.audit_actions == (
        *before.audit_actions,
        "RECONCILIATION_FINALIZATION_RESUMED",
    )
    assert _ok(harness.recover()).changes == 0
    assert harness.durable().refs == before.refs
    assert harness.durable().quarantine_entries == ()
    assert observed.read_bytes() == payload


def test_rv9_case_renamed_shard_keeps_an_open_journal_blob(
    harness: MemoryFinalizationHarness,
) -> None:
    """A ``MOVED`` RESULT journal under an unexpired lease is deferred and
    protects the blobs it planned by their complete finalized paths, compared
    case-folded: a case-only rename of one blob's shard directory leaves it
    protected, its bytes, the journal and the run untouched, nothing
    quarantined, and a second pass changes nothing."""
    plan = harness.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        harness.finalize(plan.request, probe=CrashingProbe("after_moved"))
    moved = harness.durable()
    assert moved.journal_state == "MOVED"
    assert len(moved.object_blobs) == 2
    (journal,) = moved.journal
    digest = journal.planned_paths[0].expected_sha256
    observed = _rename_case(harness.roots.store, digest, "shard")
    payload = observed.read_bytes()
    assert hashlib.sha256(payload).hexdigest() == digest
    report = _ok(harness.recover())
    assert (report.deferred, report.resumed, report.quarantined) == (1, 0, 0)
    assert report.changes == 0
    assert harness.registrar.result_calls == 0
    assert observed.read_bytes() == payload
    after = harness.durable()
    assert after.journal == moved.journal
    assert after.run_state == "RUNNING"
    assert after.refs == ()
    assert after.candidates == moved.candidates
    assert sorted(after.object_blobs) == sorted(moved.object_blobs)
    assert after.quarantine_entries == ()
    assert after.audit_actions == (
        *moved.audit_actions,
        "RECONCILIATION_FINALIZATION_RESUMED",
    )
    assert _ok(harness.recover()).changes == 0
    assert harness.durable().journal == moved.journal
    assert harness.durable().quarantine_entries == ()
    assert observed.read_bytes() == payload


def test_rv9_unregistered_blob_under_a_case_renamed_shard_is_quarantined(
    harness: MemoryFinalizationHarness,
) -> None:
    """The positive control of the case rule: an unregistered blob whose shard
    directory received a case-only rename is still a canonical object -- the
    rows are asked by its digest -- and, no row naming it, is quarantined under
    its digest with the digest claim, its observed-case path kept under the
    entry; a second pass changes nothing."""
    harness.plant_run()
    _plant_stray_blob(harness)
    observed = _rename_case(harness.roots.store, _STRAY_DIGEST, "shard")
    relative = observed.relative_to(harness.roots.artifacts_root).as_posix()
    assert relative != f"objects/{_STRAY_DIGEST[:2]}/{_STRAY_DIGEST}"
    assert relative.casefold() == f"objects/{_STRAY_DIGEST[:2]}/{_STRAY_DIGEST}"
    report = _ok(harness.recover())
    assert report.quarantined == 1
    assert not observed.exists()
    after = harness.durable()
    assert after.object_blobs == ()
    (entry,) = after.quarantine_entries
    assert entry.entry_id == _STRAY_DIGEST
    assert entry.reason_code == ARTIFACT_VALIDATION_FAILED
    assert entry.files == (relative,)
    metadata_path = (
        harness.roots.quarantine_root / entry.entry_id / QUARANTINE_METADATA_NAME
    )
    metadata = QuarantineMetadata.model_validate_json(metadata_path.read_bytes())
    assert metadata.relative_path == relative
    assert metadata.sha256 == _STRAY_DIGEST
    assert metadata_path.parent.joinpath(*relative.split("/")).read_bytes() == (
        _STRAY_BYTES
    )
    assert after.audit_actions.count("RECONCILIATION_ORPHAN_QUARANTINED") == 1
    assert _ok(harness.recover()).changes == 0
    assert harness.durable().quarantine_entries == (entry,)
