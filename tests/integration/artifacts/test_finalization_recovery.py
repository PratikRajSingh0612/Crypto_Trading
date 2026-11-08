"""Stage 9 Task 6, plan 5.3: the twelve reconciliation rows Task 6 owns
(RV-5..RV-18 less RV-12 and RV-13, which are Task 5's; RV-1..RV-4 are Task 7's),
the leased raw-byte survival and close, and the terminal-attempt rule, over the
SQLite ``FinalizationFixture`` (requirement rows R29.2-04, R29.2-05, R14.7-05,
R14.7-06, R14.7-07, R15.6-02, R17.3-02, R17.3-03, R19.1-20, R29.1-04,
R29.2-01..03, R29.5-02, T28.3-06 cleanup half).

Every planted state is a state the committed state machines reach or, where
the row says "planted raw", a row the Stage 9 repositories admit but the
production operations never write before the moment reconciliation sees it.
"""

from __future__ import annotations

import _winapi
import hashlib
import os
from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.artifacts.diagnostics import (
    ARTIFACT_FINALIZATION_TIMED_OUT,
    ARTIFACT_MOVE_FAILED,
    ARTIFACT_QUARANTINE_OVERDUE,
    ARTIFACT_RESULT_MANIFEST_INVALID,
    ARTIFACT_VALIDATION_FAILED,
    artifact_failure,
)
from crypto_lab.artifacts.finalizer import (
    EVIDENCE_LEASE_SECONDS,
    RESULT_LEASE_SECONDS,
    close_raw_bytes,
)
from crypto_lab.artifacts.journal import FinalizationJournalEntry
from crypto_lab.artifacts.models import (
    ArtifactFinalizationPurpose,
    ArtifactRef,
    CandidateArtifactProducerKind,
    CandidateArtifactState,
)
from crypto_lab.artifacts.ownership import RunArtifactOwner
from crypto_lab.artifacts.paths import confine_candidate_path
from crypto_lab.artifacts.ports import (
    CommandRootPaths,
    RegistrationUnitOfWork,
    ResultRegistration,
)
from crypto_lab.artifacts.recovery import QUARANTINE_OVERDUE_SECONDS, purge_quarantine
from crypto_lab.artifacts.store import (
    QUARANTINE_METADATA_NAME,
    ArtifactStore,
    QuarantineMetadata,
)
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.hashing import _uuid4_shaped, sha256_bytes
from crypto_lab.domain.lifecycle import CommandInvocationState, CommandKind
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.persistence.diagnostics import (
    CONCURRENCY_CONFLICT,
    WRITE_FAILED,
    persistence_failure,
)
from doubles.artifacts import (
    EVIDENCE_FILES,
    INVOCATION_CORRELATION,
    RESULT_FILES,
    RESULT_TIMEOUT_SECONDS,
    RUN_OWNER,
    THIRD_CANDIDATE_ID,
    CrashingProbe,
    FinalizationCrash,
    MemoryRegistrar,
    RecordingProbe,
    RefusingAuditor,
    ResultPlan,
    bump_candidate,
    result_candidates,
    sample_artifact_manifest,
    sample_candidate,
    sample_ref,
)
from doubles.experiments import (
    EXPERIMENT_ID,
    INSTANT,
    OTHER_INVOCATION_ID,
    RUN_ID,
    UUID_D,
    FixedClock,
    sample_invocation,
)
from persistence_support.artifacts import FinalizationFixture
from persistence_support.harness import (
    cursor_fault,
    engine_of,
    put_invocation,
    sqlite_error,
)

_S = CandidateArtifactState
_F = ArtifactFinalizationPurpose
_P = CandidateArtifactProducerKind
_ORPHAN_INVOCATION_ID = f"inv_{UUID_D}"
_STRAY_BYTES = b"finalized-looking bytes nobody registered\n"
_STRAY_DIGEST = hashlib.sha256(_STRAY_BYTES).hexdigest()
#: ``SQLITE_IOERR | (1 << 8)``: the extended code of a failed page read.
_SQLITE_IOERR_READ = 266
#: The primary I/O code: at ``do_commit`` the Stage 8 classifier's write failure.
_SQLITE_IOERR = 10
#: The predicate of the reference repository's content-hash read alone (the
#: ``list_recoverable`` subquery also reads ``artifact_refs``, by candidate).
_CONTENT_HASH_PREDICATE = "WHERE artifact_refs.content_hash"


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


def _plant_stray_blob(fixture: FinalizationFixture) -> Path:
    """A blob under ``objects/`` that no row and no journal names (RV-9)."""
    target = fixture.roots.store.finalized_path_for(_STRAY_DIGEST)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(_STRAY_BYTES)
    return target


def _projections(fixture: FinalizationFixture) -> tuple[Path, ...]:
    return tuple(sorted(fixture.roots.store.manifests_root.glob("*.json")))


def _ok[T](result: Result[T]) -> T:
    assert isinstance(result, Success), result
    return result.value


def _code(result: object) -> str:
    assert isinstance(result, Failure), result
    return result.diagnostics[0].error_code


def _message(result: object) -> str:
    assert isinstance(result, Failure), result
    return result.diagnostics[0].message


def _assert_consistent(fixture: FinalizationFixture) -> None:
    report = fixture.database.consistency_report()
    assert report.dangling_diagnostic_references == 0
    assert report.success_without_manifest == 0


@pytest.fixture
def fixture(tmp_path: Path) -> Iterator[FinalizationFixture]:
    opened = FinalizationFixture.open(tmp_path, clock=FixedClock(INSTANT))
    try:
        yield opened
    finally:
        opened.close()


def _hold_open_without_sharing(path: Path) -> int:
    """Open ``path`` with share mode 0 (the Stage 7 share-lock fixture)."""
    return _winapi.CreateFile(
        str(path),
        _winapi.GENERIC_READ,
        0,
        _winapi.NULL,
        _winapi.OPEN_EXISTING,
        0,
        _winapi.NULL,
    )


def _cleaned_up(invocation: CommandInvocationRecord) -> CommandInvocationRecord:
    """The invocation after the Stage 7 cleanup: ``cleanup_complete`` and its
    instant."""
    payload = invocation.model_dump(mode="python")
    completed = invocation.completed_at_utc
    assert isinstance(completed, datetime)
    payload["cleanup_complete"] = True
    payload["cleanup_completed_at_utc"] = completed + timedelta(seconds=1)
    payload["revision"] = invocation.revision + 1
    payload["updated_at_utc"] = completed + timedelta(seconds=1)
    return CommandInvocationRecord.model_validate(
        {key: value for key, value in payload.items() if value is not MISSING}
    )


# --------------------------------------------------------------------------
# RV-5, RV-6, RV-7
# --------------------------------------------------------------------------


def test_rv5(fixture: FinalizationFixture) -> None:
    fixture.plant_run(invocation_state=CommandInvocationState.RUNNING)
    plan = fixture.plant_result_prestate()
    before = fixture.durable()
    report = _ok(fixture.recover())
    assert report.changes == 0
    after = fixture.durable()
    # Step 4 skips an attempt that is not EXITED: no Stage 9 write at all.
    assert after.candidates == before.candidates
    assert after.run == before.run
    assert after.invocation == before.invocation
    assert after.journal == ()
    assert after.command_root_files == before.command_root_files
    assert after.audit_actions == ("RECONCILIATION_FINALIZATION_RESUMED",)
    assert plan.roots.request_path.is_file()


def test_rv6(fixture: FinalizationFixture) -> None:
    fixture.plant_run()
    orphan = fixture.roots.runtime_root / _ORPHAN_INVOCATION_ID
    (orphan / "runs" / RUN_ID / "work").mkdir(parents=True)
    (orphan / "request.json").write_bytes(b'{"orphan": true}')
    (orphan / "runs" / RUN_ID / "work" / "stray.bin").write_bytes(b"stray bytes\n")
    report = _ok(fixture.recover())
    assert report.quarantined == 1
    after = fixture.durable()
    assert not orphan.exists()
    (entry,) = after.quarantine_entries
    assert entry.entry_id == _ORPHAN_INVOCATION_ID
    assert entry.files == ("request.json", f"runs/{RUN_ID}/work/stray.bin")
    assert after.audit_actions.count("RECONCILIATION_ORPHAN_QUARANTINED") == 1
    # Never attached by name: no candidate, journal or reference names it.
    assert after.candidates == ()
    assert after.journal == ()


def test_rv7(fixture: FinalizationFixture) -> None:
    fixture.plant_run()
    put_invocation(
        fixture.harness.lifecycle(),
        sample_invocation(
            CommandInvocationState.EXITED,
            kind=CommandKind.VALIDATE,
            invocation_id=OTHER_INVOCATION_ID,
        ),
    )
    mismatched_owner = RunArtifactOwner(
        owner_kind="RUN",
        experiment_id=EXPERIMENT_ID,
        run_id=RUN_ID,
        invocation_id=OTHER_INVOCATION_ID,
    )
    fixture.harness.put_owner(mismatched_owner)
    # Planted raw: RESULT candidates whose owner invocation is the VALIDATE.
    for candidate in result_candidates(
        invocation_id=OTHER_INVOCATION_ID, owner=mismatched_owner
    ):
        fixture.harness.put_candidate(candidate)
    report = _ok(fixture.recover())
    assert report.quarantined == 2
    after = fixture.durable()
    assert all(state == "QUARANTINED" for state in after.candidate_states.values())
    for candidate in after.candidates:
        failed = [
            observation
            for observation in candidate.validation_observations
            if observation.outcome == "FAILED"
        ]
        assert [item.error_code for item in failed] == [ARTIFACT_VALIDATION_FAILED]
    assert after.run_state == "RUNNING"
    assert after.audit_actions.count("RECONCILIATION_CANDIDATE_QUARANTINED") == 2


# --------------------------------------------------------------------------
# RV-8, RV-9, RV-10, RV-11
# --------------------------------------------------------------------------


def test_rv8(fixture: FinalizationFixture) -> None:
    plan = fixture.plant_result_prestate()
    failed = fixture.fail_run_by_verdict()
    assert plan.roots.request_path.is_file()
    assert isinstance(plan.roots.result_path, Path)
    assert plan.roots.result_path.is_file()
    report = _ok(fixture.recover())
    assert report.quarantined == 2
    assert report.closed_roots == 1
    after = fixture.durable()
    assert all(state == "QUARANTINED" for state in after.candidate_states.values())
    assert after.run_state == "FAILED"
    assert after.run_revision == failed.revision
    assert after.refs == ()
    assert after.journal == ()
    # The staging bytes moved to quarantine, one entry per candidate.
    assert {entry.entry_id for entry in after.quarantine_entries} == {
        candidate.candidate_artifact_id for candidate in plan.candidates
    }
    assert not any(name.endswith(".bin") for name in after.command_root_files)
    # The token-bearing root's raw bytes are closed (plan 4.3 phase 6).
    assert not plan.roots.request_path.exists()
    assert not plan.roots.result_path.exists()
    assert after.audit_actions.count("RETENTION_DELETED") == 1
    assert RESULT_FILES


def test_rv9(fixture: FinalizationFixture) -> None:
    fixture.plant_run()
    stray = b"finalized-looking bytes nobody registered\n"
    digest = hashlib.sha256(stray).hexdigest()
    target = fixture.roots.store.finalized_path_for(digest)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(stray)
    report = _ok(fixture.recover())
    assert report.quarantined == 1
    after = fixture.durable()
    assert after.object_blobs == ()
    (entry,) = after.quarantine_entries
    assert entry.entry_id == digest
    assert entry.files == (f"objects/{digest[:2]}/{digest}",)
    assert after.audit_actions.count("RECONCILIATION_ORPHAN_QUARANTINED") == 1
    assert after.refs == ()


def test_rv9_registered_blob_survives_a_missing_projection(
    fixture: FinalizationFixture,
) -> None:
    """Plan 6.2: the ``artifact_refs`` row is authoritative and the projection's
    absence is tolerated; recovery never quarantines a committed registration
    whose ``manifests/<artifact_id>.json`` is gone."""
    plan = fixture.plant_evidence_prestate()
    registered = _ok(fixture.finalize_evidence(plan))
    assert registered.journal_state == "REGISTERED"
    before = fixture.durable()
    assert len(before.refs) == 1
    assert len(before.object_blobs) == 1
    for projection in _projections(fixture):
        projection.unlink()
    assert _projections(fixture) == ()
    fixture.reopen()
    report = _ok(fixture.recover())
    assert report.quarantined == 0
    assert report.changes == 0
    after = fixture.durable()
    assert after.object_blobs == before.object_blobs
    assert after.refs == before.refs
    assert after.quarantine_entries == ()
    assert "RECONCILIATION_ORPHAN_QUARANTINED" not in after.audit_actions


def test_rv9_well_formed_projection_without_a_row_does_not_register(
    fixture: FinalizationFixture,
) -> None:
    """A projection that validates and names the stray blob's digest is no
    evidence of registration: without the row the blob is quarantined and the
    stale projection travels with it."""
    fixture.plant_run()
    _plant_stray_blob(fixture)
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
    projection = fixture.roots.store.manifest_path_for(phantom.artifact_id)
    projection.write_bytes(canonical_json_bytes(sample_artifact_manifest(phantom)))
    report = _ok(fixture.recover())
    assert report.quarantined == 1
    after = fixture.durable()
    assert after.refs == ()
    assert after.object_blobs == ()
    assert not projection.exists()
    (entry,) = after.quarantine_entries
    assert entry.entry_id == _STRAY_DIGEST
    assert entry.files == (
        f"manifests/{phantom.artifact_id}.json",
        f"objects/{_STRAY_DIGEST[:2]}/{_STRAY_DIGEST}",
    )
    assert after.audit_actions.count("RECONCILIATION_ORPHAN_QUARANTINED") == 1


def test_rv9_open_journal_protects_its_moved_blobs(
    fixture: FinalizationFixture,
) -> None:
    """The applicable open journal protects the blobs it planned: a ``MOVED``
    RESULT journal left open by a storage-class T3 failure keeps its two blobs
    while the stray beside them is quarantined; no projection is involved."""
    plan = fixture.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        fixture.finalize_result(plan, probe=CrashingProbe("after_moved"))
    moved = fixture.durable()
    assert moved.journal_state == "MOVED"
    assert len(moved.object_blobs) == 2
    assert _projections(fixture) == ()
    _plant_stray_blob(fixture)
    fixture.registrar = _StorageFailingRegistrar()
    # The pass takes the journal over once its lease has expired (the ruling).
    fixture.advance_clock(RESULT_LEASE_SECONDS + 1)
    fixture.reopen()
    report = _ok(fixture.recover())
    assert fixture.registrar.result_calls == 1
    assert report.quarantined == 1
    after = fixture.durable()
    assert after.journal_state == "MOVED"
    assert after.refs == ()
    assert set(after.object_blobs) == set(moved.object_blobs)
    assert _STRAY_DIGEST not in after.object_blobs
    assert [entry.entry_id for entry in after.quarantine_entries] == [_STRAY_DIGEST]
    assert after.run_state == "RUNNING"


def test_rv9_reference_lookup_failure_preserves_the_blob_and_reports_it(
    fixture: FinalizationFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A content-hash read refused at the driver (``SQLITE_IOERR_READ``) is the
    classified ``PERSISTENCE.WRITE_FAILED`` naming ``artifact_refs`` and
    ``list_by_content_hash``, never absence: the pass answers it, the blob stays
    under ``objects/`` with no quarantine entry and no audit row, no transaction
    is left open, and the next pass -- the read answering -- quarantines the
    unregistered blob."""
    fixture.plant_run()
    blob = _plant_stray_blob(fixture)
    with cursor_fault(fixture.database, monkeypatch) as fault:
        fault.arm(
            sqlite_error(_SQLITE_IOERR_READ, "SQLITE_IOERR_READ"),
            when=lambda statement: _CONTENT_HASH_PREDICATE in statement,
        )
        failed = fixture.recover()
        assert not fault.armed, fault.passed
        (fired,) = fault.fired
        assert _CONTENT_HASH_PREDICATE in fired
    assert _code(failed) == WRITE_FAILED
    assert isinstance(failed, Failure)
    details = failed.diagnostics[0].details
    assert details["table"] == "artifact_refs"
    assert details["operation"] == "list_by_content_hash"
    assert blob.is_file()
    after = fixture.durable()
    assert _STRAY_DIGEST in after.object_blobs
    assert after.quarantine_entries == ()
    assert after.audit_actions == ()
    assert fixture.harness.open_transactions() == ()
    report = _ok(fixture.recover())
    assert report.quarantined == 1
    assert fixture.durable().object_blobs == ()


def _orphan_entry_id(relative: str) -> str:
    """The deterministic RV-9 identity of an orphan: derived from its confined
    relative path under the artifacts root, never from the untrusted name."""
    return f"unregistered_{_uuid4_shaped(sha256_bytes(relative.encode('utf-8')))}"


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


@pytest.mark.parametrize(
    "name",
    [
        pytest.param(".hidden", id="dot-prefixed"),
        pytest.param("odd name.bin", id="space-bearing"),
    ],
)
def test_rv9_grammar_refused_name_under_objects_is_quarantined_as_an_orphan(
    fixture: FinalizationFixture, name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An ordinary file under ``objects/`` whose name the candidate path grammar
    refuses (a leading dot, a space) is quarantined through the orphan operation
    over SQLite: the content-hash read is never issued for it (the driver fault
    armed at that statement never fires), the bytes move into an audited entry
    keyed by the identity derived from the confined relative path and lie at the
    plan 6.2 layout ``<quarantine>/<entry_id>/<original relative path>``, the
    metadata is readable, names that path and claims no digest, no
    ``artifact_refs`` row appears, no transaction is left open and a second
    pass changes nothing."""
    fixture.plant_run()
    before = fixture.durable()
    relative = f"objects/{name}"
    stray = fixture.roots.store.objects_root / name
    stray.write_bytes(b"not a blob\n")
    with cursor_fault(fixture.database, monkeypatch) as fault:
        fault.arm(
            sqlite_error(_SQLITE_IOERR_READ, "SQLITE_IOERR_READ"),
            when=lambda statement: _CONTENT_HASH_PREDICATE in statement,
        )
        report = _ok(fixture.recover())
        assert fault.armed
        assert fault.fired == []
    assert report.quarantined == 1
    assert not stray.exists()
    after = fixture.durable()
    (entry,) = after.quarantine_entries
    assert entry.entry_id == _orphan_entry_id(relative)
    assert name not in entry.entry_id
    assert entry.reason_code == ARTIFACT_VALIDATION_FAILED
    assert entry.files == (relative,)
    metadata_path = (
        fixture.roots.quarantine_root / entry.entry_id / QUARANTINE_METADATA_NAME
    )
    metadata = QuarantineMetadata.model_validate_json(metadata_path.read_bytes())
    assert metadata.entry_id == entry.entry_id
    assert metadata.relative_path == relative
    assert metadata.source_root == str(fixture.roots.artifacts_root)
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
    assert fixture.harness.open_transactions() == ()
    assert _ok(fixture.recover()).changes == 0
    assert fixture.durable().quarantine_entries == (entry,)


def test_rv9_orphan_with_a_second_hard_link_is_left_for_a_later_pass(
    fixture: FinalizationFixture,
) -> None:
    """The orphan confinement keeps the hard-link rule over SQLite: an aliased
    ``.hidden`` is left unmoved and unaudited with no row written; once the
    alias is gone the next pass quarantines it."""
    fixture.plant_run()
    stray = fixture.roots.store.objects_root / ".hidden"
    stray.write_bytes(b"not a blob\n")
    alias = fixture.roots.runtime_root / "alias.bin"
    os.link(stray, alias)
    try:
        report = _ok(fixture.recover())
        assert report.quarantined == 0
        assert stray.read_bytes() == b"not a blob\n"
        after = fixture.durable()
        assert after.quarantine_entries == ()
        assert after.audit_actions == ("RECONCILIATION_FINALIZATION_RESUMED",)
    finally:
        alias.unlink()
    second = _ok(fixture.recover())
    assert second.quarantined == 1
    assert not stray.exists()
    assert fixture.harness.open_transactions() == ()


def test_rv9_non_content_addressed_file_gets_a_derived_identity(
    fixture: FinalizationFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file under ``objects/`` whose name is no content address is unregistered
    by construction: no row registers a path outside ``objects/<hh>/<sha256>``,
    so the content-hash read is never issued for it (the driver fault armed at
    that statement never fires); the entry is keyed by an identity derived from
    the confined relative path rather than the untrusted name, the metadata
    records the path and no digest, and the pass is idempotent."""
    fixture.plant_run()
    stray = fixture.roots.store.objects_root / "stray.tmp"
    stray.write_bytes(b"not a blob\n")
    with cursor_fault(fixture.database, monkeypatch) as fault:
        fault.arm(
            sqlite_error(_SQLITE_IOERR_READ, "SQLITE_IOERR_READ"),
            when=lambda statement: _CONTENT_HASH_PREDICATE in statement,
        )
        report = _ok(fixture.recover())
        assert fault.armed
        assert fault.fired == []
    assert report.quarantined == 1
    assert not stray.exists()
    after = fixture.durable()
    (entry,) = after.quarantine_entries
    assert entry.entry_id != "stray.tmp"
    assert entry.entry_id.startswith("unregistered_")
    assert entry.files == ("objects/stray.tmp",)
    metadata_path = (
        fixture.roots.quarantine_root / entry.entry_id / QUARANTINE_METADATA_NAME
    )
    metadata = QuarantineMetadata.model_validate_json(metadata_path.read_bytes())
    assert metadata.relative_path == "objects/stray.tmp"
    assert not isinstance(metadata.sha256, str)
    (quarantined,) = [
        event
        for event in after.audit_events
        if event.action.value == "RECONCILIATION_ORPHAN_QUARANTINED"
    ]
    assert quarantined.correlation_id == entry.entry_id
    assert _ok(fixture.recover()).changes == 0


# RV-9 routing over SQLite: a canonical object is classified by its complete
# root-relative layout ``objects/<hh>/<sha256>`` with the shard matching the
# leaf, never by the leaf alone.


@pytest.mark.parametrize(
    "directory",
    [
        pytest.param(".x", id="dot-prefixed"),
        pytest.param("odd dir", id="space-bearing"),
        pytest.param("zz", id="wrong-shard"),
    ],
)
def test_rv9_misplaced_content_address_is_quarantined_as_an_orphan(
    fixture: FinalizationFixture, directory: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file whose leaf is the valid content address of its own bytes but which
    lies under a dot-prefixed, space-bearing or non-matching directory is no
    canonical object over SQLite: the content-hash read is never issued for it
    (the driver fault armed at that statement never fires), the bytes move into
    an audited entry keyed by the identity derived from the confined relative
    path and lie at the plan 6.2 layout
    ``<quarantine>/<entry_id>/<original relative path>`` with the metadata naming
    that path and no digest, no ``artifact_refs`` row appears, no transaction is
    left open and a second pass changes nothing."""
    fixture.plant_run()
    before = fixture.durable()
    relative = f"objects/{directory}/{_STRAY_DIGEST}"
    stray = fixture.roots.store.objects_root / directory / _STRAY_DIGEST
    stray.parent.mkdir()
    stray.write_bytes(_STRAY_BYTES)
    with cursor_fault(fixture.database, monkeypatch) as fault:
        fault.arm(
            sqlite_error(_SQLITE_IOERR_READ, "SQLITE_IOERR_READ"),
            when=lambda statement: _CONTENT_HASH_PREDICATE in statement,
        )
        report = _ok(fixture.recover())
        assert fault.armed
        assert fault.fired == []
    assert report.quarantined == 1
    assert not stray.exists()
    after = fixture.durable()
    (entry,) = after.quarantine_entries
    assert entry.entry_id == _orphan_entry_id(relative)
    assert _STRAY_DIGEST not in entry.entry_id
    assert entry.reason_code == ARTIFACT_VALIDATION_FAILED
    assert entry.files == (relative,)
    metadata_path = (
        fixture.roots.quarantine_root / entry.entry_id / QUARANTINE_METADATA_NAME
    )
    metadata = QuarantineMetadata.model_validate_json(metadata_path.read_bytes())
    assert metadata.entry_id == entry.entry_id
    assert metadata.relative_path == relative
    assert metadata.source_root == str(fixture.roots.artifacts_root)
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
    assert fixture.harness.open_transactions() == ()
    assert _ok(fixture.recover()).changes == 0
    assert fixture.durable().quarantine_entries == (entry,)


def test_rv9_same_digest_orphan_is_quarantined_while_the_registered_blob_stays(
    fixture: FinalizationFixture,
) -> None:
    """The same-digest control over a committed reference: a registered canonical
    blob and a misplaced copy of its very bytes under ``objects/.x/<sha256>``.
    Protection is decided by the complete durable path the ``artifact_refs`` row
    names, so only the misplaced copy is quarantined -- as an orphan, no digest
    claim -- while the canonical blob, its row and its projection stay; no
    reference is created and a second pass changes nothing."""
    plan = fixture.plant_evidence_prestate()
    registered = _ok(fixture.finalize_evidence(plan))
    assert registered.journal_state == "REGISTERED"
    before = fixture.durable()
    (ref,) = before.refs
    digest = ref.content_hash
    canonical = fixture.roots.store.finalized_path_for(digest)
    payload = canonical.read_bytes()
    assert hashlib.sha256(payload).hexdigest() == digest
    misplaced = fixture.roots.store.objects_root / ".x" / digest
    misplaced.parent.mkdir()
    misplaced.write_bytes(payload)
    projections = _projections(fixture)
    assert len(projections) == 1
    assert fixture.durable().object_blobs == (digest, digest)
    fixture.reopen()
    report = _ok(fixture.recover())
    assert report.quarantined == 1
    assert not misplaced.exists()
    assert canonical.read_bytes() == payload
    after = fixture.durable()
    assert after.refs == before.refs
    assert after.object_blobs == (digest,)
    assert _projections(fixture) == projections
    (entry,) = after.quarantine_entries
    assert entry.entry_id == _orphan_entry_id(f"objects/.x/{digest}")
    assert entry.entry_id != digest
    assert entry.files == (f"objects/.x/{digest}",)
    metadata_path = (
        fixture.roots.quarantine_root / entry.entry_id / QUARANTINE_METADATA_NAME
    )
    metadata = QuarantineMetadata.model_validate_json(metadata_path.read_bytes())
    assert metadata.relative_path == f"objects/.x/{digest}"
    assert not isinstance(metadata.sha256, str)
    assert (metadata_path.parent / "objects" / ".x" / digest).read_bytes() == payload
    assert after.audit_actions.count("RECONCILIATION_ORPHAN_QUARANTINED") == 1
    assert fixture.harness.open_transactions() == ()
    assert _ok(fixture.recover()).changes == 0
    assert fixture.durable().refs == before.refs
    assert fixture.durable().quarantine_entries == (entry,)
    assert canonical.read_bytes() == payload
    _assert_consistent(fixture)


def test_rv9_same_digest_orphan_is_quarantined_while_the_open_journal_blob_stays(
    fixture: FinalizationFixture,
) -> None:
    """The same-digest control over an open journal: a ``MOVED`` RESULT journal
    under an unexpired lease is deferred and protects the blobs it planned by
    their complete finalized paths; a misplaced copy of one of those blobs under
    ``objects/odd dir/<sha256>`` is no planned path and is quarantined as an
    orphan, while the journal, its run and both canonical blobs stay."""
    plan = fixture.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        fixture.finalize_result(plan, probe=CrashingProbe("after_moved"))
    moved = fixture.durable()
    assert moved.journal_state == "MOVED"
    assert len(moved.object_blobs) == 2
    (journal,) = moved.journal
    digest = journal.planned_paths[0].expected_sha256
    canonical = fixture.roots.store.finalized_path_for(digest)
    payload = canonical.read_bytes()
    misplaced = fixture.roots.store.objects_root / "odd dir" / digest
    misplaced.parent.mkdir()
    misplaced.write_bytes(payload)
    fixture.reopen()
    report = _ok(fixture.recover())
    assert (report.deferred, report.resumed, report.quarantined) == (1, 0, 1)
    assert fixture.registrar.result_calls == 0
    assert not misplaced.exists()
    assert canonical.read_bytes() == payload
    after = fixture.durable()
    assert after.journal == moved.journal
    assert after.run_state == "RUNNING"
    assert after.refs == ()
    assert after.object_blobs == moved.object_blobs
    (entry,) = after.quarantine_entries
    assert entry.entry_id == _orphan_entry_id(f"objects/odd dir/{digest}")
    assert entry.files == (f"objects/odd dir/{digest}",)
    assert fixture.harness.open_transactions() == ()
    assert _ok(fixture.recover()).changes == 0
    assert fixture.durable().journal == moved.journal


# RV-9 case semantics over SQLite: the supported store is case-insensitive, so
# a canonical object and its protection are decided case-folded as Windows does
# -- a case-only rename of a shard or leaf leaves the very same file at the very
# path a row or a planned move names -- while the complete-path rule stays.


@pytest.mark.parametrize(
    "component", [pytest.param("shard", id="shard"), pytest.param("leaf", id="leaf")]
)
def test_rv9_case_renamed_canonical_path_keeps_a_registered_blob(
    fixture: FinalizationFixture, component: str
) -> None:
    """A registered blob whose shard directory or leaf received a case-only
    rename is still the file at the complete path its ``artifact_refs`` row
    names on the supported case-insensitive store: across a reopen it is
    classified canonical, the row protects it, its bytes and rows are untouched,
    nothing is quarantined or audited as an orphan, no transaction is left open
    and a second pass changes nothing."""
    plan = fixture.plant_evidence_prestate()
    registered = _ok(fixture.finalize_evidence(plan))
    assert registered.journal_state == "REGISTERED"
    before = fixture.durable()
    (ref,) = before.refs
    digest = ref.content_hash
    observed = _rename_case(fixture.roots.store, digest, component)
    payload = observed.read_bytes()
    assert hashlib.sha256(payload).hexdigest() == digest
    fixture.reopen()
    report = _ok(fixture.recover())
    assert report.quarantined == 0
    assert report.changes == 0
    assert observed.read_bytes() == payload
    assert fixture.roots.store.finalized_path_for(digest).read_bytes() == payload
    after = fixture.durable()
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
    assert fixture.harness.open_transactions() == ()
    assert _ok(fixture.recover()).changes == 0
    assert fixture.durable().refs == before.refs
    assert fixture.durable().quarantine_entries == ()
    assert observed.read_bytes() == payload
    _assert_consistent(fixture)


def test_rv9_case_renamed_shard_keeps_an_open_journal_blob(
    fixture: FinalizationFixture,
) -> None:
    """A ``MOVED`` RESULT journal under an unexpired lease is deferred and
    protects the blobs it planned by their complete finalized paths, compared
    case-folded: a case-only rename of one blob's shard directory leaves it
    protected across a reopen, its bytes, the journal and the run untouched,
    nothing quarantined, and a second pass changes nothing."""
    plan = fixture.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        fixture.finalize_result(plan, probe=CrashingProbe("after_moved"))
    moved = fixture.durable()
    assert moved.journal_state == "MOVED"
    assert len(moved.object_blobs) == 2
    (journal,) = moved.journal
    digest = journal.planned_paths[0].expected_sha256
    observed = _rename_case(fixture.roots.store, digest, "shard")
    payload = observed.read_bytes()
    assert hashlib.sha256(payload).hexdigest() == digest
    fixture.reopen()
    report = _ok(fixture.recover())
    assert (report.deferred, report.resumed, report.quarantined) == (1, 0, 0)
    assert report.changes == 0
    assert fixture.registrar.result_calls == 0
    assert observed.read_bytes() == payload
    after = fixture.durable()
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
    assert fixture.harness.open_transactions() == ()
    assert _ok(fixture.recover()).changes == 0
    assert fixture.durable().journal == moved.journal
    assert fixture.durable().quarantine_entries == ()
    assert observed.read_bytes() == payload


def test_rv9_unregistered_blob_under_a_case_renamed_shard_is_quarantined(
    fixture: FinalizationFixture,
) -> None:
    """The positive control of the case rule over SQLite: an unregistered blob
    whose shard directory received a case-only rename is still a canonical
    object -- the rows are asked by its digest -- and, no row naming it, is
    quarantined under its digest with the digest claim, its observed-case path
    kept under the entry; no transaction is left open and a second pass changes
    nothing."""
    fixture.plant_run()
    _plant_stray_blob(fixture)
    observed = _rename_case(fixture.roots.store, _STRAY_DIGEST, "shard")
    relative = observed.relative_to(fixture.roots.artifacts_root).as_posix()
    assert relative != f"objects/{_STRAY_DIGEST[:2]}/{_STRAY_DIGEST}"
    assert relative.casefold() == f"objects/{_STRAY_DIGEST[:2]}/{_STRAY_DIGEST}"
    report = _ok(fixture.recover())
    assert report.quarantined == 1
    assert not observed.exists()
    after = fixture.durable()
    assert after.object_blobs == ()
    (entry,) = after.quarantine_entries
    assert entry.entry_id == _STRAY_DIGEST
    assert entry.reason_code == ARTIFACT_VALIDATION_FAILED
    assert entry.files == (relative,)
    metadata_path = (
        fixture.roots.quarantine_root / entry.entry_id / QUARANTINE_METADATA_NAME
    )
    metadata = QuarantineMetadata.model_validate_json(metadata_path.read_bytes())
    assert metadata.relative_path == relative
    assert metadata.sha256 == _STRAY_DIGEST
    assert metadata_path.parent.joinpath(*relative.split("/")).read_bytes() == (
        _STRAY_BYTES
    )
    assert after.audit_actions.count("RECONCILIATION_ORPHAN_QUARANTINED") == 1
    assert fixture.harness.open_transactions() == ()
    assert _ok(fixture.recover()).changes == 0
    assert fixture.durable().quarantine_entries == (entry,)


def test_rv10(fixture: FinalizationFixture) -> None:
    prestate = fixture.plant_run()
    plan = fixture.plant_evidence_prestate()
    # The invocation's Stage 7 cleanup completed: the staging is abandoned.
    transaction = fixture.begin()
    _ok(
        transaction.command_invocations.compare_and_swap(
            prestate.invocation.revision, _cleaned_up(prestate.invocation)
        )
    )
    _ok(transaction.commit())
    report = _ok(fixture.recover())
    assert report.quarantined == 1
    assert report.resumed == 0
    after = fixture.durable()
    (candidate,) = plan.candidates
    assert after.candidate_states[candidate.candidate_artifact_id] == "QUARANTINED"
    assert after.staging_files == ()
    assert after.journal == ()
    (entry,) = after.quarantine_entries
    assert entry.entry_id == candidate.candidate_artifact_id


def test_rv11(fixture: FinalizationFixture) -> None:
    plan = fixture.plant_evidence_prestate()
    (candidate,) = plan.candidates
    transaction = fixture.begin()
    validating = _ok(
        transaction.candidate_artifacts.compare_and_swap(
            candidate.revision, bump_candidate(candidate, _S.VALIDATING)
        )
    )
    finalizing = _ok(
        transaction.candidate_artifacts.compare_and_swap(
            validating.revision, bump_candidate(validating, _S.FINALIZING)
        )
    )
    _ok(transaction.commit())
    assert finalizing.state is _S.FINALIZING
    report = _ok(fixture.recover())
    assert report.quarantined == 1
    after = fixture.durable()
    assert after.candidate_states[candidate.candidate_artifact_id] == "QUARANTINED"
    assert after.journal == ()
    assert after.refs == ()
    assert after.staging_files == ()


# --------------------------------------------------------------------------
# RV-14, RV-15, RV-16
# --------------------------------------------------------------------------


def test_rv14(fixture: FinalizationFixture) -> None:
    plan = fixture.plant_result_prestate()
    fixture.plant_evidence_prestate()
    with pytest.raises(FinalizationCrash):
        fixture.finalize_result(plan, probe=CrashingProbe("after_moved"))
    first = _ok(fixture.recover())
    assert first.changes > 0
    after_first = fixture.durable()
    second = _ok(fixture.recover())
    assert second.changes == 0
    assert (second.resumed, second.registered, second.abandoned) == (0, 0, 0)
    after_second = fixture.durable()
    assert after_second.journal == after_first.journal
    assert after_second.candidates == after_first.candidates
    assert after_second.refs == after_first.refs
    assert after_second.run == after_first.run
    assert after_second.quarantine_entries == after_first.quarantine_entries
    assert after_second.command_root_files == after_first.command_root_files
    appended = after_second.audit_events[len(after_first.audit_events) :]
    assert [event.action.value for event in appended] == [
        "RECONCILIATION_FINALIZATION_RESUMED"
    ]
    assert appended[0].outcome.value == "SUCCEEDED"
    assert appended[0].details["changes"] == 0


def test_rv15(fixture: FinalizationFixture) -> None:
    plan = fixture.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        fixture.finalize_result(plan, probe=CrashingProbe("after_moved"))
    fixture.advance_clock(RESULT_TIMEOUT_SECONDS + 1)
    fixture.reopen()
    report = _ok(fixture.recover())
    assert (report.abandoned, report.registered) == (1, 0)
    after = fixture.durable()
    assert after.run_state == "TIMED_OUT"
    assert after.journal_state == "ABANDONED"
    assert after.abandon_reason == ARTIFACT_FINALIZATION_TIMED_OUT
    assert after.object_blobs == ()
    assert after.refs == ()
    assert after.run_manifests == ()
    assert after.audit_actions.count("FINALIZATION_TIMED_OUT") == 1
    # Never success afterwards: a second pass changes nothing more.
    assert _ok(fixture.recover()).changes == 0


def test_rv16(fixture: FinalizationFixture) -> None:
    plan = fixture.plant_evidence_prestate()
    with pytest.raises(FinalizationCrash):
        fixture.finalize_evidence(plan, probe=CrashingProbe("after_moved"))
    failed = fixture.fail_run_by_verdict()
    fixture.advance_clock(EVIDENCE_LEASE_SECONDS + 1)  # the lease expires first
    report = _ok(fixture.recover())
    assert (report.resumed, report.registered) == (1, 1)
    after = fixture.durable()
    assert after.journal_state == "REGISTERED"
    assert len(after.refs) == 1
    assert after.run_state == "FAILED"
    assert after.run_revision == failed.revision  # the run row untouched (29.4)
    assert {link.link_role for link in after.run_artifacts} == {"RUN_EVIDENCE"}


# --------------------------------------------------------------------------
# RV-17 and RV-18: quarantine age and purge
# --------------------------------------------------------------------------


def test_rv17(fixture: FinalizationFixture) -> None:
    plan = fixture.plant_result_prestate()
    first = plan.candidates[0]
    assert isinstance(plan.roots.work_dir, Path)
    plan.roots.work_dir.joinpath(*first.staging_relative_path.split("/")).write_bytes(
        b"tampered\n"
    )
    assert _code(fixture.finalize_result(plan)) == ARTIFACT_VALIDATION_FAILED
    (entry,) = fixture.durable().quarantine_entries
    assert entry.entry_id == first.candidate_artifact_id
    entry_root = fixture.roots.quarantine_root / entry.entry_id
    files_before = tuple(sorted(entry_root.rglob("*")))
    fixture.advance_clock(QUARANTINE_OVERDUE_SECONDS + 1)
    report = _ok(fixture.recover())
    assert report.overdue == 1
    after = fixture.durable()
    assert after.audit_actions.count("QUARANTINE_OVERDUE") == 1
    assert ARTIFACT_QUARANTINE_OVERDUE in after.diagnostic_codes
    files_after = tuple(sorted(entry_root.rglob("*")))
    assert files_after == files_before  # bytes untouched (reading 8)
    # The overdue entry is reported, never moved or removed; the pass also
    # quarantined the attempt's remaining candidate through the validator.
    assert entry in fixture.durable().quarantine_entries


def test_rv18(fixture: FinalizationFixture) -> None:
    plan = fixture.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        fixture.finalize_result(plan, probe=CrashingProbe("after_prepared"))
    (prepared,) = fixture.durable().journal
    # An entry keyed by the open finalization: a leased candidate's bytes.
    stray = fixture.roots.runtime_root / "stray.txt"
    stray.write_bytes(b"leased bytes\n")
    confined = _ok(
        confine_candidate_path(fixture.roots.runtime_root, "stray.txt", now_utc=INSTANT)
    )
    _ok(
        fixture.roots.store.quarantine_move(
            confined, prepared.finalization_id, ARTIFACT_MOVE_FAILED, now_utc=INSTANT
        )
    )
    refused = purge_quarantine(
        prepared.finalization_id,
        "retention-test",
        store=fixture.roots.store,
        unit_of_work_factory=fixture.begin,
        auditor=fixture.auditor,
        clock=fixture.clock,
    )
    assert _code(refused) == ARTIFACT_VALIDATION_FAILED
    assert (fixture.roots.quarantine_root / prepared.finalization_id).is_dir()
    # Once the journal is terminal (the deadline passes), the purge proceeds.
    fixture.advance_clock(RESULT_TIMEOUT_SECONDS + 1)
    _ok(fixture.recover())
    purged = purge_quarantine(
        prepared.finalization_id,
        "retention-test",
        store=fixture.roots.store,
        unit_of_work_factory=fixture.begin,
        auditor=fixture.auditor,
        clock=fixture.clock,
    )
    assert isinstance(purged, Success), purged
    assert not (fixture.roots.quarantine_root / prepared.finalization_id).exists()
    after = fixture.durable()
    assert after.audit_actions[-1] == "RETENTION_DELETED"
    assert after.audit_events[-1].details["purge"] is True


# --------------------------------------------------------------------------
# Raw bytes: survive the lease, vanish at the close; terminal never reopened
# --------------------------------------------------------------------------


def test_raw_bytes_survive_lease_and_vanish_at_close(
    fixture: FinalizationFixture,
) -> None:
    plan = fixture.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        fixture.finalize_result(plan, probe=CrashingProbe("after_moved"))
    # The lease is open: request.json and the adapter result manifest survive,
    # and a pass under the unexpired lease defers the journal and keeps them.
    assert plan.roots.request_path.is_file()
    assert isinstance(plan.roots.result_path, Path)
    assert plan.roots.result_path.is_file()
    assert _ok(fixture.recover()).deferred == 1
    assert plan.roots.request_path.is_file()
    fixture.advance_clock(RESULT_LEASE_SECONDS + 1)
    _ok(fixture.recover())  # the memory registrar abandons the RESULT: the lease closes
    assert not plan.roots.request_path.exists()
    assert not plan.roots.result_path.exists()
    assert fixture.durable().audit_actions.count("RETENTION_DELETED") == 1
    # The primitive itself: a removal refused by a held handle is quarantined when
    # the move succeeds and retained when it does not; both are audited.
    second = fixture.plant_evidence_prestate()  # a second root to close
    del second
    held_root = fixture.roots.runtime_root / OTHER_INVOCATION_ID
    held_root.mkdir()
    request_path = held_root / "request.json"
    request_path.write_bytes(b'{"held": true}')
    output_path = held_root / "output.json"
    output_path.write_bytes(b'{"typed": "output"}')
    roots = CommandRootPaths(
        command_root=held_root, request_path=request_path, output_path=output_path
    )
    handle = _hold_open_without_sharing(request_path)
    try:
        transaction = fixture.begin()
        closed = _ok(
            close_raw_bytes(
                roots,
                store=fixture.roots.store,
                unit_of_work=transaction,
                auditor=fixture.auditor,
                correlation=OTHER_INVOCATION_ID,
                clock=fixture.clock,
            )
        )
        _ok(transaction.commit())
    finally:
        _winapi.CloseHandle(handle)
    assert closed.removed == 1  # output.json
    assert closed.quarantined + closed.retained == 1
    assert not output_path.exists()
    after = fixture.durable()
    assert after.audit_actions[-2:] == ("RETENTION_DELETED", "ARTIFACT_QUARANTINED")
    assert after.audit_events[-1].outcome.value == (
        "SUCCEEDED" if closed.quarantined == 1 else "FAILED"
    )
    # After the handle is released, a second close removes what was retained.
    transaction = fixture.begin()
    again = _ok(
        close_raw_bytes(
            roots,
            store=fixture.roots.store,
            unit_of_work=transaction,
            auditor=fixture.auditor,
            correlation=OTHER_INVOCATION_ID,
            clock=fixture.clock,
        )
    )
    _ok(transaction.commit())
    assert again.retained == 0
    assert not request_path.exists()
    assert INVOCATION_CORRELATION.kind == "INVOCATION"
    assert RUN_OWNER.run_id == RUN_ID


def test_restart_defers_an_unexpired_lease_until_expiry(
    fixture: FinalizationFixture,
) -> None:
    """The RESULT lease ruling of 2026-11-08 over SQLite: a restart alone grants
    no authority over an unexpired lease, so the pass defers the open journal and
    preserves every recoverable byte and row; past the lease and inside the
    deadline the next pass takes the lease over by one compare-and-swap and
    completes (here to the Task 6 registrar's abandonment)."""
    plan = fixture.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        fixture.finalize_result(plan, probe=CrashingProbe("after_prepared"))
    before = fixture.durable()
    (prepared,) = before.journal
    fixture.reopen()
    report = _ok(fixture.recover())
    assert (report.deferred, report.resumed, report.changes) == (1, 0, 0)
    assert (report.registered, report.abandoned, report.quarantined) == (0, 0, 0)
    deferred = fixture.durable()
    assert deferred.journal == before.journal
    assert deferred.candidates == before.candidates
    assert deferred.command_root_files == before.command_root_files
    assert deferred.object_blobs == ()
    assert deferred.quarantine_entries == ()
    assert deferred.run == before.run
    assert deferred.audit_actions == (
        *before.audit_actions,
        "RECONCILIATION_FINALIZATION_RESUMED",
    )
    assert deferred.audit_events[-1].details["deferred"] == 1
    assert plan.roots.request_path.is_file()
    fixture.advance_clock(RESULT_LEASE_SECONDS + 1)
    second = _ok(fixture.recover())
    assert (second.deferred, second.resumed) == (0, 1)
    assert (second.abandoned, second.registered) == (1, 0)
    after = fixture.durable()
    (entry,) = after.journal
    assert entry.state.value == "ABANDONED"
    # The takeover, then MOVED, then the abandonment: three writes.
    assert entry.revision == prepared.revision + 3
    assert entry.finalization_deadline_utc == prepared.finalization_deadline_utc
    assert after.run_state == "FAILED"
    assert after.audit_actions.count("FINALIZATION_LEASE_ACQUIRED") == 2
    assert all(state == "QUARANTINED" for state in after.candidate_states.values())
    assert not plan.roots.request_path.exists()


def test_terminal_attempts_never_reopened(fixture: FinalizationFixture) -> None:
    plan = fixture.plant_result_prestate()
    failed = fixture.fail_run_by_verdict()
    before_invocation = fixture.durable().invocation
    _ok(fixture.recover())
    _ok(fixture.recover())
    after = fixture.durable()
    assert after.run_state == "FAILED"
    assert after.run_revision == failed.revision
    assert after.journal == ()
    assert after.run_manifests == ()
    assert after.invocation == before_invocation
    assert after.invocation is not None
    assert after.invocation.state.value == "EXITED"
    assert all(state == "QUARANTINED" for state in after.candidate_states.values())
    assert plan.request.run_id == RUN_ID


# --------------------------------------------------------------------------
# Fault injection over SQLite: an audit refusal inside a phase or a recovery
# transaction, and the timeout path losing the run compare-and-swap
# --------------------------------------------------------------------------


def _write_failure() -> Failure:
    return persistence_failure(
        WRITE_FAILED,
        message="the audit row could not be appended",
        clock=FixedClock(INSTANT),
    )


def _refusing(fixture: FinalizationFixture, action: str) -> RefusingAuditor:
    refusing = RefusingAuditor(
        fixture.audit_ids,
        fixture.clock,
        refused_action=action,
        failure=_write_failure(),
    )
    fixture.auditor = refusing
    return refusing


def test_t1_audit_refusal_rolls_back_the_lease_and_recovery_completes(
    fixture: FinalizationFixture,
) -> None:
    """The phase audit commits or rolls back with its state change: a refused
    ``FINALIZATION_PREPARED`` append rolls T1 back as a whole (no journal, no
    lease, not even the ``ARTIFACT_VALIDATED`` rows appended earlier in T1); the
    candidates stay VALIDATING with their bytes, and recovery registers."""
    plan = fixture.plant_evidence_prestate()
    normal = fixture.auditor
    refusing = _refusing(fixture, "FINALIZATION_PREPARED")
    failed = fixture.finalize_evidence(plan)
    assert _code(failed) == WRITE_FAILED
    assert refusing.refusals == 1
    during = fixture.durable()
    assert during.journal == ()
    assert all(state == "VALIDATING" for state in during.candidate_states.values())
    assert during.audit_actions == ()
    assert len(during.staging_files) == 1
    assert during.object_blobs == ()
    assert fixture.harness.open_transactions() == ()
    fixture.auditor = normal
    fixture.reopen()
    report = _ok(fixture.recover())
    assert (report.resumed, report.registered) == (1, 1)
    after = fixture.durable()
    assert after.journal_state == "REGISTERED"
    assert len(after.refs) == 1
    assert after.staging_files == ()
    assert after.audit_actions[-2:] == (
        "FINALIZATION_REGISTERED",
        "RECONCILIATION_FINALIZATION_RESUMED",
    )


def test_t3_audit_refusal_rolls_back_registration_and_recovery_registers(
    fixture: FinalizationFixture,
) -> None:
    """A refused ``FINALIZATION_REGISTERED`` append rolls T3 back: no reference,
    no link, no projection (plan 6.2), the journal exactly MOVED for recovery
    (reading 26: the storage class leaves the journal where it was)."""
    plan = fixture.plant_evidence_prestate()
    normal = fixture.auditor
    refusing = _refusing(fixture, "FINALIZATION_REGISTERED")
    failed = fixture.finalize_evidence(plan)
    assert _code(failed) == WRITE_FAILED
    assert refusing.refusals == 1
    during = fixture.durable()
    assert during.journal_state == "MOVED"
    assert during.refs == ()
    assert during.run_artifacts == ()
    assert _projections(fixture) == ()
    assert during.audit_actions[-1] == "FINALIZATION_MOVED"
    fixture.auditor = normal
    fixture.advance_clock(EVIDENCE_LEASE_SECONDS + 1)  # the lease expires first
    fixture.reopen()
    report = _ok(fixture.recover())
    assert (report.resumed, report.registered) == (1, 1)
    after = fixture.durable()
    assert after.journal_state == "REGISTERED"
    assert len(after.refs) == 1
    assert len(_projections(fixture)) == 1
    assert after.audit_actions.count("FINALIZATION_REGISTERED") == 1


class _CommitFaultAt(RecordingProbe):
    """Replace the dialect's DBAPI commit at one probe point -- the Stage 8 fault
    at the ``do_commit`` boundary, so every statement of the transaction ran and
    the real ``COMMIT`` is never issued -- one-shot: the fault restores the
    original before it raises, so the transactions that follow (recovery, the
    replay) commit normally."""

    def __init__(
        self,
        fixture: FinalizationFixture,
        monkeypatch: pytest.MonkeyPatch,
        point: str,
    ) -> None:
        super().__init__()
        self._fixture = fixture
        self._monkeypatch = monkeypatch
        self._point = point
        self.fired = 0

    def _arm(self, point: str) -> None:
        if point != self._point:
            return
        engine = engine_of(self._fixture.database)
        monkeypatch = self._monkeypatch

        def failing_commit(dbapi_connection: object) -> None:
            del dbapi_connection
            self.fired += 1
            monkeypatch.undo()
            raise sqlite_error(_SQLITE_IOERR, "SQLITE_IOERR")

        monkeypatch.setattr(engine.dialect, "do_commit", failing_commit)

    def before_registered(self) -> None:
        super().before_registered()
        self._arm("before_registered")


def test_t3_commit_failure_at_the_dialect_boundary_leaves_moved_for_recovery(
    fixture: FinalizationFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The accepted plan's T3 COMMIT failure over SQLite (R21.2-02, R21.2.1-07,
    R21.2.1-08): the fault is the dialect ``do_commit`` boundary, so every T3
    statement ran -- the reference and its manifest, the ``RUN_EVIDENCE`` link,
    the REGISTERED swap, the audit row -- and the COMMIT itself was refused.
    Nothing of T3 survives (no partial registration, no projection), the durable
    journal is exactly MOVED with its observed move beside the moved blob, the
    resume follows the lease rules (deferred inside the lease, taken over past
    it) and the replay afterwards creates no duplicate. As in every crash cell,
    the durable state is read through fresh sessions after ``reopen()``."""
    plan = fixture.plant_evidence_prestate()
    (candidate,) = plan.candidates
    probe = _CommitFaultAt(fixture, monkeypatch, "before_registered")
    failed = fixture.finalize_evidence(plan, probe=probe)
    assert _code(failed) == WRITE_FAILED
    assert _message(failed) == "the transaction could not be committed"
    assert probe.fired == 1
    assert probe.reached[-1] == "inside_registered"  # T3 ran up to its COMMIT
    assert fixture.harness.open_transactions() == ()
    fixture.reopen()
    during = fixture.durable()
    (moved,) = during.journal
    assert moved.state.value == "MOVED"
    assert len(moved.observed) == 1
    digest = sha256_bytes(EVIDENCE_FILES["stderr.txt"])
    assert moved.observed[0].observed_sha256 == digest
    assert during.refs == ()
    assert during.run_artifacts == ()
    assert _projections(fixture) == ()
    assert during.object_blobs == (digest,)
    assert during.staging_files == ()
    assert during.candidate_states == {candidate.candidate_artifact_id: "FINALIZING"}
    assert "FINALIZATION_REGISTERED" not in during.audit_actions
    assert during.audit_actions[-1] == "FINALIZATION_MOVED"
    _assert_consistent(fixture)
    # The lease rules: the pass after the restart, inside the lease, defers the
    # journal unchanged.
    deferred = _ok(fixture.recover())
    assert (deferred.deferred, deferred.resumed, deferred.changes) == (1, 0, 0)
    held = fixture.durable()
    assert held.journal == during.journal
    assert held.refs == ()
    assert held.object_blobs == during.object_blobs
    # Past the lease the pass takes it over and completes the registration once.
    fixture.advance_clock(EVIDENCE_LEASE_SECONDS + 1)
    report = _ok(fixture.recover())
    assert (report.resumed, report.registered, report.abandoned) == (1, 1, 0)
    after = fixture.durable()
    assert after.journal_state == "REGISTERED"
    (ref,) = after.refs
    assert ref.content_hash == digest
    assert len(after.run_artifacts) == 1
    assert len(_projections(fixture)) == 1
    assert after.audit_actions.count("FINALIZATION_REGISTERED") == 1
    assert after.audit_actions.count("FINALIZATION_LEASE_ACQUIRED") == 2
    _assert_consistent(fixture)
    # The replay: the stored result, no second reference, link, row or blob.
    again = _ok(fixture.finalize_evidence(plan))
    assert again.replayed is True
    assert again.finalization_id == moved.finalization_id
    final = fixture.durable()
    assert final.refs == after.refs
    assert final.run_artifacts == after.run_artifacts
    assert final.journal == after.journal
    assert final.object_blobs == (digest,)
    assert final.audit_actions == (*after.audit_actions, "FINALIZATION_REPLAYED")
    assert _ok(fixture.recover()).changes == 0


def test_recovery_quarantine_audit_refusal_leaves_candidate_and_bytes(
    fixture: FinalizationFixture,
) -> None:
    """A refused ``RECONCILIATION_CANDIDATE_QUARANTINED`` append rolls the
    quarantine transaction back (row, diagnostic and audit alike); the pass
    answers the failure before any byte moves and before the summary row, and
    the next pass completes the quarantine."""
    plan = fixture.plant_evidence_prestate()
    (candidate,) = plan.candidates
    transaction = fixture.begin()
    validating = _ok(
        transaction.candidate_artifacts.compare_and_swap(
            candidate.revision, bump_candidate(candidate, _S.VALIDATING)
        )
    )
    _ok(
        transaction.candidate_artifacts.compare_and_swap(
            validating.revision, bump_candidate(validating, _S.FINALIZING)
        )
    )
    _ok(transaction.commit())
    before = fixture.durable()
    normal = fixture.auditor
    refusing = _refusing(fixture, "RECONCILIATION_CANDIDATE_QUARANTINED")
    failed = fixture.recover()
    assert _code(failed) == WRITE_FAILED
    assert refusing.refusals == 1
    assert fixture.durable() == before
    assert fixture.harness.open_transactions() == ()
    fixture.auditor = normal
    report = _ok(fixture.recover())
    assert report.quarantined == 1
    after = fixture.durable()
    assert after.candidate_states[candidate.candidate_artifact_id] == "QUARANTINED"
    assert after.staging_files == ()
    assert after.audit_actions == (
        "RECONCILIATION_CANDIDATE_QUARANTINED",
        "RECONCILIATION_FINALIZATION_RESUMED",
    )


_ENGINE_RUN_UPDATE = "UPDATE engine_runs"


def _planted_refusal() -> Failure:
    """A 29.3 refusal with a known diagnostic: its identity is content-addressed
    (the clock instant is not hash material), so a pass that re-derives the same
    refusal records the same diagnostic."""
    return artifact_failure(
        ARTIFACT_RESULT_MANIFEST_INVALID,
        message="the temporary manifest names a candidate the rows do not",
        now_utc=INSTANT,
    )


def _fail_next_commit(
    fixture: FinalizationFixture, monkeypatch: pytest.MonkeyPatch
) -> list[int]:
    """The Stage 8 fault at the dialect ``do_commit`` boundary, armed now and
    one-shot: the next COMMIT issued is refused after every statement of its
    transaction ran, and the original is restored before the error is raised."""
    engine = engine_of(fixture.database)
    fired: list[int] = []

    def failing_commit(dbapi_connection: object) -> None:
        del dbapi_connection
        fired.append(1)
        monkeypatch.undo()
        raise sqlite_error(_SQLITE_IOERR, "SQLITE_IOERR")

    monkeypatch.setattr(engine.dialect, "do_commit", failing_commit)
    return fired


@pytest.mark.parametrize("fault", ["run-write", "commit"])
def test_terminal_write_fault_leaves_the_failed_check_retryable_after_reopen(
    fixture: FinalizationFixture, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    """17.3 after a failed check over SQLite: the ``RUNNING -> FAILED`` update
    refused at the driver, or the one transaction's COMMIT refused at the dialect
    boundary, leaves exactly the pre-state through a fresh connection -- the run
    RUNNING at its revision beside its CANDIDATE rows and their bytes -- and the
    pass after the restart re-derives the refusal, fails the run under the same
    diagnostic, quarantines the candidates, closes the root; a further pass after
    another reopen changes nothing."""
    plan = fixture.plant_result_prestate()
    refusal = _planted_refusal()
    fixture.validator.plant(refusal)
    before = fixture.durable()
    if fault == "run-write":
        with cursor_fault(fixture.database, monkeypatch) as armed:
            armed.arm(
                sqlite_error(_SQLITE_IOERR, "SQLITE_IOERR"),
                when=lambda statement: _ENGINE_RUN_UPDATE in statement,
            )
            failed = fixture.recover()
            assert not armed.armed, armed.passed
    else:
        fired = _fail_next_commit(fixture, monkeypatch)
        failed = fixture.recover()
        assert len(fired) == 1
    assert _code(failed) == WRITE_FAILED
    assert fixture.harness.open_transactions() == ()
    fixture.reopen()
    during = fixture.durable()
    assert during.run_state == "RUNNING"
    assert during.run_revision == plan.run.revision
    assert during.candidate_states == before.candidate_states
    assert during == before
    assert plan.roots.request_path.is_file()
    report = _ok(fixture.recover())
    assert (report.resumed, report.quarantined, report.closed_roots) == (0, 2, 1)
    fixture.reopen()
    after = fixture.durable()
    diagnostic_id = refusal.diagnostics[0].diagnostic_id
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
    _assert_consistent(fixture)
    assert _ok(fixture.recover()).changes == 0
    fixture.reopen()
    final = fixture.durable()
    assert (final.run, final.candidates, final.quarantine_entries) == (
        after.run,
        after.candidates,
        after.quarantine_entries,
    )


def test_summary_audit_refusal_reports_failure_after_the_steps_committed(
    fixture: FinalizationFixture,
) -> None:
    """Every step commits its own transaction, so a refused summary row fails the
    pass after its work is durable; the next pass finds nothing to change and
    appends the summary (RV-14)."""
    fixture.plant_run()
    _plant_stray_blob(fixture)
    normal = fixture.auditor
    refusing = _refusing(fixture, "RECONCILIATION_FINALIZATION_RESUMED")
    failed = fixture.recover()
    assert _code(failed) == WRITE_FAILED
    assert refusing.refusals == 1
    during = fixture.durable()
    assert during.object_blobs == ()
    (entry,) = during.quarantine_entries
    assert entry.entry_id == _STRAY_DIGEST
    assert during.audit_actions == ("RECONCILIATION_ORPHAN_QUARANTINED",)
    fixture.auditor = normal
    second = _ok(fixture.recover())
    assert second.changes == 0
    assert fixture.durable().audit_actions == (
        "RECONCILIATION_ORPHAN_QUARANTINED",
        "RECONCILIATION_FINALIZATION_RESUMED",
    )


def test_rv15_timeout_losing_the_run_swap_is_superseded(
    fixture: FinalizationFixture,
) -> None:
    """Plan 4.5 and reading 1: the deadline passed over a MOVED RESULT journal
    whose run a terminal winner moved meanwhile. ``record_timeout`` loses the
    run compare-and-swap, so the journal is ABANDONED(SUPERSEDED) -- the stored
    ``PERSISTENCE.CONCURRENCY_CONFLICT`` -- rather than TIMED_OUT; the run stays
    CANCELLED at the winner's revision and the moved blobs are quarantined."""
    plan = fixture.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        fixture.finalize_result(plan, probe=CrashingProbe("after_moved"))
    cancelled = fixture.cancel_run()
    fixture.advance_clock(RESULT_TIMEOUT_SECONDS + 1)
    fixture.reopen()
    report = _ok(fixture.recover())
    assert (report.resumed, report.abandoned, report.registered) == (1, 1, 0)
    after = fixture.durable()
    assert after.journal_state == "ABANDONED"
    assert after.abandon_reason == CONCURRENCY_CONFLICT
    assert after.run_state == "CANCELLED"
    assert after.run_revision == cancelled.revision
    assert after.refs == ()
    assert after.object_blobs == ()
    assert len(after.quarantine_entries) == 1
    assert "FINALIZATION_TIMED_OUT" not in after.audit_actions
    assert after.audit_actions.count("FINALIZATION_ABANDONED") == 1


# --------------------------------------------------------------------------
# RV-15 precedence: an exhausted deadline is polled before any revalidation or
# hash of a resumed RESULT journal can select a different failure outcome
# --------------------------------------------------------------------------


def _staged_path(plan: ResultPlan, index: int) -> Path:
    candidate = plan.candidates[index]
    assert isinstance(plan.roots.work_dir, Path)
    return plan.roots.work_dir.joinpath(*candidate.staging_relative_path.split("/"))


def _expire_deadline_across_restart(
    fixture: FinalizationFixture, plan: ResultPlan, point: str, index: int = 0
) -> FinalizationJournalEntry:
    """Crash at ``point``, let the immutable deadline pass, restart; the open
    journal as stored before the resume."""
    with pytest.raises(FinalizationCrash):
        fixture.finalize_result(plan, probe=CrashingProbe(point, index))
    (entry,) = fixture.durable().journal
    fixture.advance_clock(RESULT_TIMEOUT_SECONDS + 1)
    fixture.reopen()
    return entry


def _disturb_staged(plan: ResultPlan, disturbance: str) -> None:
    """The staged candidate bytes change or vanish while the process is down."""
    if disturbance == "mutated":
        _staged_path(plan, 0).write_bytes(b"changed while the process was down\n")
    else:
        for index in range(len(plan.candidates)):
            _staged_path(plan, index).unlink()


def _disturb_blob(
    fixture: FinalizationFixture, entry: FinalizationJournalEntry, disturbance: str
) -> None:
    """The first moved blob changes in place or vanishes while the process is down."""
    blob = fixture.roots.store.finalized_path_for(
        entry.planned_paths[0].expected_sha256
    )
    if disturbance == "mutated":
        blob.write_bytes(b"corrupted finalized bytes\n")
    else:
        blob.unlink()


def _resume_expired(fixture: FinalizationFixture, plan: ResultPlan, route: str) -> None:
    """Resume the open journal by the route under test: the reconciler's pass or
    a newcomer under the same identity after the lease expired."""
    if route == "recover":
        report = _ok(fixture.recover())
        assert (report.resumed, report.abandoned, report.registered) == (1, 1, 0)
    else:
        timed_out = fixture.finalize_result(plan)
        assert _code(timed_out) == ARTIFACT_FINALIZATION_TIMED_OUT
        assert "deadline passed" in _message(timed_out)


def _assert_timed_out_before_revalidation(
    fixture: FinalizationFixture,
    plan: ResultPlan,
    before: FinalizationJournalEntry,
    *,
    fin_files: int,
) -> None:
    after = fixture.durable()
    assert after.run_state == "TIMED_OUT"
    assert after.run is not None
    (entry,) = after.journal
    assert entry.state.value == "ABANDONED"
    assert entry.abandon_reason == ARTIFACT_FINALIZATION_TIMED_OUT
    # No lease was taken over past the deadline: the timeout is the one
    # compare-and-swap at the stored revision, and the deadline never moved.
    assert entry.revision == before.revision + 1
    assert entry.finalization_deadline_utc == before.finalization_deadline_utc
    assert after.refs == ()
    assert after.run_manifests == ()
    assert all(state == "QUARANTINED" for state in after.candidate_states.values())
    # RV-15's diagnostic is the run's primary; the disturbed bytes never selected
    # a validation outcome, because the deadline was polled first.
    assert ARTIFACT_VALIDATION_FAILED not in after.diagnostic_codes
    assert after.diagnostic_codes.count(ARTIFACT_FINALIZATION_TIMED_OUT) == 1
    primary = after.run.primary_terminal_diagnostic_id
    assert any(
        diagnostic.diagnostic_id == primary
        and diagnostic.error_code == ARTIFACT_FINALIZATION_TIMED_OUT
        for diagnostic in after.diagnostics
    )
    assert after.audit_actions.count("FINALIZATION_TIMED_OUT") == 1
    assert "FINALIZATION_ABANDONED" not in after.audit_actions
    assert after.audit_actions.count("FINALIZATION_LEASE_ACQUIRED") == 1
    assert after.audit_actions.count("ARTIFACT_QUARANTINED") == 2
    assert fixture.registrar.result_calls == 0
    # The remaining bytes: whatever the journal still reaches is quarantined
    # under the finalization's entry; nothing is left where a reader could take
    # it for finalized content.
    fin_entries = [
        item for item in after.quarantine_entries if item.entry_id.startswith("fin_")
    ]
    if fin_files == 0:
        assert fin_entries == []
    else:
        (fin_entry,) = fin_entries
        assert len(fin_entry.files) == fin_files
    # The lease closed: the raw-bearing bytes left the command root.
    assert not plan.roots.request_path.exists()
    assert isinstance(plan.roots.result_path, Path)
    assert not plan.roots.result_path.exists()
    _assert_consistent(fixture)


@pytest.mark.parametrize("route", ["recover", "finalize"])
@pytest.mark.parametrize("disturbance", ["mutated", "missing"])
def test_rv15_prepared_journal_times_out_before_revalidation(
    fixture: FinalizationFixture, disturbance: str, route: str
) -> None:
    """A PREPARED RESULT journal whose deadline passed while its staged bytes
    were disturbed: the exhausted deadline is RV-15's timeout, never the
    revalidation's ``ARTIFACT.VALIDATION_FAILED``; the staged bytes still present
    travel to the finalization's quarantine entry, absent ones leave nothing."""
    plan = fixture.plant_result_prestate()
    prepared = _expire_deadline_across_restart(fixture, plan, "after_prepared")
    _disturb_staged(plan, disturbance)
    _resume_expired(fixture, plan, route)
    _assert_timed_out_before_revalidation(
        fixture, plan, prepared, fin_files=2 if disturbance == "mutated" else 0
    )
    after = fixture.durable()
    assert after.object_blobs == ()
    assert after.staging_files == ()
    assert "FINALIZATION_MOVED" not in after.audit_actions
    assert _ok(fixture.recover()).changes == 0


@pytest.mark.parametrize("route", ["recover", "finalize"])
@pytest.mark.parametrize("disturbance", ["mutated", "missing"])
def test_rv15_moved_journal_times_out_before_rehash(
    fixture: FinalizationFixture, disturbance: str, route: str
) -> None:
    """A MOVED RESULT journal whose deadline passed while a moved blob was
    disturbed: the timeout path, never a reference; the blobs still present are
    quarantined under the finalization's entry, a vanished one is skipped."""
    plan = fixture.plant_result_prestate()
    moved = _expire_deadline_across_restart(fixture, plan, "after_moved")
    _disturb_blob(fixture, moved, disturbance)
    _resume_expired(fixture, plan, route)
    _assert_timed_out_before_revalidation(
        fixture, plan, moved, fin_files=2 if disturbance == "mutated" else 1
    )
    after = fixture.durable()
    assert after.object_blobs == ()
    assert _ok(fixture.recover()).changes == 0


@pytest.mark.parametrize("route", ["recover", "finalize"])
def test_rv15_half_moved_prepared_journal_times_out_and_the_pass_sweeps_the_blob(
    fixture: FinalizationFixture, route: str
) -> None:
    """The CP-3 shape past its deadline: one blob moved before the crash, the
    other candidate still staged and mutated. The timeout polls first, so no
    revalidation runs; the journal never observed the moved blob, so the
    timeout quarantines the staged bytes alone and the blob stays unregistered
    content under ``objects/`` until RV-9 sweeps it -- in the same pass through
    the reconciler, in the next pass after a newcomer's timeout."""
    plan = fixture.plant_result_prestate()
    prepared = _expire_deadline_across_restart(fixture, plan, "after_move", 0)
    assert len(fixture.roots.object_blobs()) == 1
    _staged_path(plan, 1).write_bytes(b"changed while the process was down\n")
    if route == "recover":
        report = _ok(fixture.recover())
        assert (report.resumed, report.abandoned, report.registered) == (1, 1, 0)
        assert report.quarantined == 1  # RV-9: the unregistered blob
    else:
        assert _code(fixture.finalize_result(plan)) == ARTIFACT_FINALIZATION_TIMED_OUT
        assert len(fixture.roots.object_blobs()) == 1
        sweep = _ok(fixture.recover())
        assert (sweep.resumed, sweep.quarantined) == (0, 1)
    _assert_timed_out_before_revalidation(fixture, plan, prepared, fin_files=1)
    after = fixture.durable()
    assert after.object_blobs == ()
    assert after.staging_files == ()
    digest_entries = [
        item
        for item in after.quarantine_entries
        if not item.entry_id.startswith("fin_")
    ]
    assert [item.entry_id for item in digest_entries] == [
        prepared.planned_paths[0].expected_sha256
    ]
    assert after.audit_actions.count("RECONCILIATION_ORPHAN_QUARANTINED") == 1
    assert _ok(fixture.recover()).changes == 0


@pytest.mark.parametrize("route", ["recover", "finalize"])
def test_rv15_prepared_timeout_losing_the_run_swap_preserves_the_winner(
    fixture: FinalizationFixture, route: str
) -> None:
    """The deadline passed over a PREPARED journal with disturbed staged bytes
    while a terminal winner moved the run: the deadline still polls first, so the
    outcome is the timeout path losing its run compare-and-swap --
    ``ABANDONED(PERSISTENCE.CONCURRENCY_CONFLICT)`` -- never the revalidation's
    code; the run stays at the winner's state and revision."""
    plan = fixture.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        fixture.finalize_result(plan, probe=CrashingProbe("after_prepared"))
    (prepared,) = fixture.durable().journal
    cancelled = fixture.cancel_run()
    fixture.advance_clock(RESULT_TIMEOUT_SECONDS + 1)
    fixture.reopen()
    _disturb_staged(plan, "mutated")
    if route == "recover":
        report = _ok(fixture.recover())
        assert (report.resumed, report.abandoned, report.registered) == (1, 1, 0)
    else:
        superseded = fixture.finalize_result(plan)
        assert _code(superseded) == CONCURRENCY_CONFLICT
    after = fixture.durable()
    (entry,) = after.journal
    assert entry.state.value == "ABANDONED"
    assert entry.abandon_reason == CONCURRENCY_CONFLICT
    assert entry.revision == prepared.revision + 1
    assert after.run_state == "CANCELLED"
    assert after.run_revision == cancelled.revision
    assert after.refs == ()
    assert after.object_blobs == ()
    assert all(state == "QUARANTINED" for state in after.candidate_states.values())
    assert ARTIFACT_VALIDATION_FAILED not in after.diagnostic_codes
    assert ARTIFACT_FINALIZATION_TIMED_OUT not in after.diagnostic_codes
    assert "FINALIZATION_TIMED_OUT" not in after.audit_actions
    assert after.audit_actions.count("FINALIZATION_ABANDONED") == 1
    assert after.audit_actions.count("FINALIZATION_LEASE_ACQUIRED") == 1
    (fin_entry,) = [
        item for item in after.quarantine_entries if item.entry_id.startswith("fin_")
    ]
    assert len(fin_entry.files) == 2
    assert not plan.roots.request_path.exists()
    assert fixture.registrar.result_calls == 0
    assert after.audit_actions.count("RUN_FAILED") == 0
