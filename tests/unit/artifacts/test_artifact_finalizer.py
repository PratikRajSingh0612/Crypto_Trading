"""Stage 9 Task 6: the core artifact finalizer over the in-memory unit of work
(plan 4.2, 4.3, 4.7; requirement rows F8.1-5, F8.2-4, F8.2-8, R11.5-11,
R14.5-02, R14.7-03, R19.1-04, R19.1-09, R19.1-21, R19.2-01, R19.2-03, R19.2-07,
R21.2-02, R21.2.1-03, R23.3.1-14, R23.3.1-15, R30.3-01).

Every test drives ``CoreArtifactFinalizer.finalize`` through the ``send(None)``
driver over ``MemoryFinalizationHarness``: the rows live in the memory store,
the bytes under ``tmp_path`` are hashed and moved for real. The memory
registrar refuses every RESULT registration (Task 7 owns RESULT success), so a
RESULT finalization here ends in a refusal or ``ABANDONED`` and never in
``REGISTERED``; EVIDENCE finalizations run the whole protocol.
"""

from __future__ import annotations

import _winapi
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, BinaryIO, Final

import pytest
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.artifacts.diagnostics import (
    ARTIFACT_FINALIZATION_TIMED_OUT,
    ARTIFACT_MOVE_FAILED,
    ARTIFACT_PATH_BOUNDARY_VIOLATION,
    ARTIFACT_VALIDATION_FAILED,
    SECURITY_SENSITIVE_MATERIAL_LEAKAGE,
    artifact_failure,
)
from crypto_lab.artifacts.finalizer import (
    EVIDENCE_LEASE_SECONDS,
    PROCESS_CANCELLED,
    RESULT_LEASE_SECONDS,
    CoreArtifactFinalizer,
    close_raw_bytes,
    close_result_lease,
    cooperative_checkpoint,
)
from crypto_lab.artifacts.hashing import HashScan, StreamingContentHasher
from crypto_lab.artifacts.journal import (
    FinalizationJournalEntry,
    FinalizationJournalState,
)
from crypto_lab.artifacts.manifest import ArtifactManifest, artifact_manifest_hash
from crypto_lab.artifacts.models import (
    ArtifactFinalizationPurpose,
    ArtifactSourceRole,
    CandidateArtifactState,
    FinalizationResult,
)
from crypto_lab.artifacts.ownership import ArtifactOwnerRef
from crypto_lab.artifacts.paths import ConfinedPath
from crypto_lab.artifacts.ports import (
    CanonicalQualification,
    CommandRootPaths,
    NoProbe,
)
from crypto_lab.artifacts.requests import EvidenceCorrelation
from crypto_lab.artifacts.store import MoveOutcome
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.engine_run import AttemptTokenMaterial
from crypto_lab.domain.hashing import artifact_id_for, sha256_bytes
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.persistence.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
    WRITE_FAILED,
    persistence_failure,
)
from doubles.artifacts import (
    ADAPTER_OWNER,
    ATTEMPT_TOKEN_HASH,
    DATASET_OWNER,
    DIAGNOSTIC_CORRELATION,
    EVIDENCE_FILES,
    EXPERIMENT_OWNER,
    FIXTURE_TOKEN,
    INVOCATION_CORRELATION,
    RESULT_TIMEOUT_SECONDS,
    RUN_MANIFEST_HASH,
    RUN_MANIFEST_ID,
    RUN_OWNER,
    RUN_OWNER_WITHOUT_INVOCATION,
    SANITIZED_MANIFEST_HASH,
    STRATEGY_OWNER,
    SYSTEM_OWNER,
    CrashingProbe,
    DurableState,
    FinalizationCrash,
    FlagCancellationToken,
    MemoryArtifactRepository,
    MemoryCandidateArtifactRepository,
    MemoryCommandInvocationRecords,
    MemoryDiagnosticWriter,
    MemoryEngineRunRecords,
    MemoryFinalizationHarness,
    MemoryFinalizationJournalRepository,
    MemoryFinalizationTransaction,
    MemoryResultLeaseRepository,
    MemoryRunArtifactRepository,
    MemoryRunManifestRepository,
    RecordingLog,
    RecordingProbe,
    RefusingAuditor,
    ResultPlan,
    bump_candidate,
    bump_journal,
    count_checkpoints,
    plant_core_evidence,
    renew_journal,
    run_coroutine,
    sample_artifact_manifest,
    sample_evidence_request,
    sample_journal,
    sample_ref,
    sample_result_request,
)
from doubles.experiments import (
    EXPERIMENT_ID,
    INSTANT,
    INVOCATION_ID,
    OTHER_INVOCATION_ID,
    OTHER_REQUEST_HASH,
    OTHER_RUN_ID,
    RUN_ID,
    FixedClock,
    sample_invocation,
    sample_run,
)

_S = CandidateArtifactState
_TWO_EVIDENCE_FILES = {
    "stderr.txt": b"engine stderr line one\nengine stderr line two\n",
    "protocol.txt": b"engine protocol line\n",
}
_JSON_FILES = {"descriptor.json": b'{"adapter_name": "adapter.alpha"}\n'}
_LEAKING_FILES = {
    "results/native.bin": b"prefix " + FIXTURE_TOKEN.encode("ascii") + b" suffix\n",
    "results/second.bin": b"clean native result bytes\n",
}


def _ok[T](result: Result[T]) -> T:
    assert isinstance(result, Success), result
    return result.value


def _code(result: object) -> str:
    assert isinstance(result, Failure), result
    assert len(result.diagnostics) == 1, result
    return result.diagnostics[0].error_code


def _message(result: object) -> str:
    assert isinstance(result, Failure), result
    return result.diagnostics[0].message


@pytest.fixture
def harness(tmp_path: Path) -> MemoryFinalizationHarness:
    return MemoryFinalizationHarness(tmp_path)


# --------------------------------------------------------------------------
# F8.1-5, F8.2-4: the explicit mappings per purpose
# --------------------------------------------------------------------------


def test_finalize_returns_explicit_mappings_per_purpose(
    harness: MemoryFinalizationHarness,
) -> None:
    evidence = harness.plant_evidence_prestate(files=_TWO_EVIDENCE_FILES)
    registered = _ok(harness.finalize(evidence.request))
    assert isinstance(registered, FinalizationResult)
    assert registered.finalization_purpose.value == "EVIDENCE"
    assert registered.journal_state == "REGISTERED"
    assert registered.replayed is False
    assert not isinstance(registered.run_manifest_id, str)
    assert not isinstance(registered.run_manifest_hash, str)
    expected = tuple(
        (
            candidate.candidate_artifact_id,
            artifact_id_for(
                candidate.candidate_artifact_id,
                sha256_bytes(
                    _TWO_EVIDENCE_FILES[
                        candidate.staging_relative_path.rsplit("/", 1)[-1]
                    ]
                ),
            ),
        )
        for candidate in evidence.candidates
    )
    assert (
        tuple(
            (mapping.candidate_artifact_id, mapping.artifact_id)
            for mapping in registered.candidate_to_artifact_refs
        )
        == expected
    )
    durable = harness.durable()
    assert durable.journal_state == "REGISTERED"
    assert {ref.artifact_id for ref in durable.refs} == {
        artifact for _, artifact in expected
    }
    assert all(state == "FINALIZING" for state in durable.candidate_states.values())
    assert durable.staging_files == ()
    assert set(durable.object_blobs) == {
        sha256_bytes(data) for data in _TWO_EVIDENCE_FILES.values()
    }
    # The RUN owner's evidence links were recorded by the registrar.
    assert {link.link_role for link in durable.run_artifacts} == {"RUN_EVIDENCE"}
    assert len(durable.run_artifacts) == 2

    # RESULT: the memory registrar refuses inside T3, so the finalization is
    # abandoned, never registered -- Task 7 owns RESULT success.
    result = harness.plant_result_prestate()
    refused = harness.finalize(result.request)
    assert _code(refused) == INVARIANT_VIOLATION
    assert "Task 6 memory registrar" in _message(refused)
    after = harness.durable()
    assert len(after.journal) == 2
    result_journal = [
        entry for entry in after.journal if entry.finalization_purpose.value == "RESULT"
    ]
    assert len(result_journal) == 1
    assert result_journal[0].state.value == "ABANDONED"
    assert result_journal[0].abandon_reason == INVARIANT_VIOLATION
    assert len(after.refs) == 2  # the evidence references only
    for candidate in result.candidates:
        assert after.candidate_states[candidate.candidate_artifact_id] == "QUARANTINED"
    assert after.run_state == "RUNNING"  # the caller fails the run (plan 4.4 step 3)
    assert harness.registrar.result_calls == 1


# --------------------------------------------------------------------------
# R14.5-02, R19.2-01: the nine-step order through the probe
# --------------------------------------------------------------------------


def test_nine_step_order_observed_by_probe(harness: MemoryFinalizationHarness) -> None:
    evidence = harness.plant_evidence_prestate(files=_TWO_EVIDENCE_FILES)
    probe = RecordingProbe()
    _ok(harness.finalize(evidence.request, probe=probe))
    assert probe.reached == [
        "before_prepared",
        "after_prepared",
        "before_move:0",
        "after_move:0",
        "before_move:1",
        "after_move:1",
        "before_moved",
        "after_moved",
        "before_registered",
        "inside_registered",
        "after_registered",
    ]
    # An EVIDENCE finalization never closes a command root (plan 4.3 phase 6).
    assert "after_close" not in probe.reached
    result = harness.plant_result_prestate()
    result_probe = RecordingProbe()
    harness.finalize(result.request, probe=result_probe)
    assert result_probe.reached[:8] == probe.reached[:8]
    assert result_probe.reached[8] == "before_registered"
    assert result_probe.reached[-1] == "after_close"
    assert "inside_registered" not in result_probe.reached


def test_cooperative_checkpoint_yields_once_per_boundary(
    harness: MemoryFinalizationHarness,
) -> None:
    checkpoint = cooperative_checkpoint()
    awaited = checkpoint.__await__()
    assert next(awaited) is None
    with pytest.raises(StopIteration):
        next(awaited)
    evidence = harness.plant_evidence_prestate()
    finalizer = harness.finalizer(RecordingProbe())
    outcome, yields = count_checkpoints(
        finalizer.finalize(evidence.request, FlagCancellationToken())
    )
    _ok(outcome)
    # The suspension points of an EVIDENCE finalization with one move: after
    # phase 0, after ``before_prepared``, after ``after_prepared``, after the
    # move, after T2 and after T3 (plan 4.3: a checkpoint at every phase boundary).
    assert yields == 6


# --------------------------------------------------------------------------
# F8.2-8, R23.3.1-15: no transaction across hashing or a move
# --------------------------------------------------------------------------


class _SpyHasher(StreamingContentHasher):
    """A ``ContentHasher`` recording how many transactions were open per stream."""

    def __init__(self) -> None:
        super().__init__()
        self.open_transactions: Callable[[], tuple[object, ...]] = tuple
        self.open_during: list[int] = []

    def sha256_stream(self, source: BinaryIO) -> str:
        self.open_during.append(len(self.open_transactions()))
        return super().sha256_stream(source)

    def sha256_and_scan(
        self,
        source: BinaryIO,
        token: AttemptTokenMaterial | MISSING,  # type: ignore[valid-type]
        *,
        detect_token_shape: bool = False,
    ) -> HashScan:
        self.open_during.append(len(self.open_transactions()))
        return super().sha256_and_scan(
            source, token, detect_token_shape=detect_token_shape
        )


def test_no_transaction_open_across_hashing_or_moves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spy = _SpyHasher()
    harness = MemoryFinalizationHarness(tmp_path, hasher=spy)
    spy.open_transactions = harness.unit_of_work.open_transactions
    evidence = harness.plant_evidence_prestate(files=_TWO_EVIDENCE_FILES)
    store = harness.roots.store
    original_move = store.atomic_move
    open_during_moves: list[int] = []

    def spied_move(
        confined: ConfinedPath, target: Path, *, now_utc: object
    ) -> Result[MoveOutcome]:
        open_during_moves.append(len(harness.unit_of_work.open_transactions()))
        assert isinstance(now_utc, type(INSTANT))
        return original_move(confined, target, now_utc=now_utc)

    monkeypatch.setattr(store, "atomic_move", spied_move)
    _ok(harness.finalize(evidence.request))
    # Phase 1 streams each candidate once (hash and scan), phase 4 re-hashes each
    # moved blob in place; never with a transaction open.
    assert len(spy.open_during) == 4
    assert spy.open_during == [0, 0, 0, 0]
    assert open_during_moves == [0, 0]
    # The four-transaction protocol never holds two transactions at once.
    assert harness.unit_of_work.max_open == 1
    assert harness.unit_of_work.open_transactions() == ()


# --------------------------------------------------------------------------
# R23.3.1-14, R23.3.1-16: the step-one fields by purpose
# --------------------------------------------------------------------------


def test_step_one_fields_by_purpose(harness: MemoryFinalizationHarness) -> None:
    evidence = harness.plant_evidence_prestate()
    with pytest.raises(FinalizationCrash):
        harness.finalize(evidence.request, probe=CrashingProbe("after_prepared"))
    durable = harness.durable()
    (entry,) = durable.journal
    assert entry.state.value == "PREPARED"
    assert entry.finalization_purpose.value == "EVIDENCE"
    assert entry.correlation == INVOCATION_CORRELATION
    assert not isinstance(entry.run_id, str)
    assert not isinstance(entry.finalization_deadline_utc, type(INSTANT))
    assert not isinstance(entry.expected_run_revision, int)
    assert entry.lease_expires_at_utc == INSTANT.replace(
        minute=INSTANT.minute + EVIDENCE_LEASE_SECONDS // 60
    )
    assert entry.observed == ()
    assert durable.run_revision == 4  # the EVIDENCE lease touched no run row
    assert durable.run_deadline is None
    assert all(state == "FINALIZING" for state in durable.candidate_states.values())

    result = harness.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        harness.finalize(result.request, probe=CrashingProbe("after_prepared"))
    after = harness.durable()
    (result_entry,) = [
        item for item in after.journal if item.finalization_purpose.value == "RESULT"
    ]
    assert not isinstance(result_entry.correlation, EvidenceCorrelation)
    assert result_entry.run_id == RUN_ID
    assert result_entry.run_invocation_id == INVOCATION_ID
    assert result_entry.attempt_token_hash == ATTEMPT_TOKEN_HASH
    assert (
        result_entry.source_adapter_result_manifest_hash
        == result.request.source_adapter_result_manifest_hash
    )
    assert (
        result_entry.sanitized_adapter_result_manifest_hash
        == result.request.sanitized_adapter_result_manifest_hash
    )
    expected_deadline = INSTANT.replace(minute=INSTANT.minute + 10)
    assert result_entry.finalization_deadline_utc == expected_deadline
    # The lease is the compiled interval capped at the deadline (plan 4.3 phase
    # 4 renews it, RC-13 takes it over before the deadline).
    assert result_entry.lease_expires_at_utc == INSTANT.replace(minute=5)
    # The journal stores the revision after the deadline snapshot (reading 1).
    assert result_entry.expected_run_revision == result.run.revision + 1
    assert result_entry.expected_invocation_revision == result.invocation.revision
    assert after.run_deadline == expected_deadline
    assert after.run_revision == result.run.revision + 1
    assert after.run_state == "RUNNING"


# --------------------------------------------------------------------------
# R11.5-11 (registry half), R19.1-04: owner inconsistent with the registry
# --------------------------------------------------------------------------


def test_owner_inconsistent_with_registry_refused_before_io(
    harness: MemoryFinalizationHarness,
) -> None:
    evidence = harness.plant_evidence_prestate()
    before = harness.durable()
    foreign = sample_evidence_request(
        [candidate.candidate_artifact_id for candidate in evidence.candidates],
        owner=SYSTEM_OWNER,
        correlation=DIAGNOSTIC_CORRELATION,
    )
    refused = harness.finalize(foreign, probe=RecordingProbe())
    assert _code(refused) == INVARIANT_VIOLATION
    assert "registered owner" in _message(refused)
    after = harness.durable()
    assert after == before  # nothing written, nothing moved
    assert harness.auditor.facts == []


# --------------------------------------------------------------------------
# R14.7-03, R14.7-04, R21.2.1-05: leakage rejects every RESULT candidate
# --------------------------------------------------------------------------


def test_leakage_rejects_every_result_candidate(
    harness: MemoryFinalizationHarness,
) -> None:
    result = harness.plant_result_prestate(files=_LEAKING_FILES)
    refused = harness.finalize(result.request)
    assert _code(refused) == SECURITY_SENSITIVE_MATERIAL_LEAKAGE
    durable = harness.durable()
    assert durable.journal == ()
    assert durable.refs == ()
    assert durable.object_blobs == ()
    assert all(state == "QUARANTINED" for state in durable.candidate_states.values())
    assert set(durable.candidate_states) == {
        candidate.candidate_artifact_id for candidate in result.candidates
    }
    quarantined = {
        candidate.candidate_artifact_id: candidate for candidate in durable.candidates
    }
    codes = {
        identity: {
            observation.error_code
            for observation in candidate.validation_observations
            if observation.outcome == "FAILED"
        }
        for identity, candidate in quarantined.items()
    }
    assert all(
        failed == {SECURITY_SENSITIVE_MATERIAL_LEAKAGE} for failed in codes.values()
    )
    # The bytes left the work directory for the quarantine, one entry per candidate.
    assert {entry.entry_id for entry in durable.quarantine_entries} == set(quarantined)
    assert not any(name.endswith(".bin") for name in durable.command_root_files)
    assert durable.audit_actions.count("ARTIFACT_LEAKAGE_DETECTED") == 1
    assert durable.audit_actions.count("ARTIFACT_QUARANTINED") == 2
    assert durable.run_state == "RUNNING"
    # The raw token never reaches a diagnostic, an observation or an audit detail.
    rendered = [canonical_json_bytes(diagnostic) for diagnostic in durable.diagnostics]
    rendered.extend(canonical_json_bytes(event) for event in durable.audit_events)
    rendered.extend(canonical_json_bytes(candidate) for candidate in durable.candidates)
    assert not any(FIXTURE_TOKEN.encode("ascii") in blob for blob in rendered)


# --------------------------------------------------------------------------
# R19.1-09, R19.1-11, R19.1-12: evidence roles and owners
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("owner", "correlation", "role", "files", "kind"),
    [
        (RUN_OWNER, INVOCATION_CORRELATION, None, None, None),
        (SYSTEM_OWNER, DIAGNOSTIC_CORRELATION, None, None, None),
        (
            ADAPTER_OWNER,
            EvidenceCorrelation(kind="INVOCATION", invocation_id=OTHER_INVOCATION_ID),
            None,
            None,
            None,
        ),
        (
            ADAPTER_OWNER,
            EvidenceCorrelation(kind="INVOCATION", invocation_id=OTHER_INVOCATION_ID),
            ArtifactSourceRole.ADAPTER_DESCRIPTOR_EVIDENCE,
            _JSON_FILES,
            "adapter-descriptor",
        ),
        (
            EXPERIMENT_OWNER,
            DIAGNOSTIC_CORRELATION,
            None,
            _JSON_FILES,
            "configuration-snapshot",
        ),
        (DATASET_OWNER, DIAGNOSTIC_CORRELATION, None, _JSON_FILES, "dataset-manifest"),
        (
            STRATEGY_OWNER,
            DIAGNOSTIC_CORRELATION,
            None,
            _JSON_FILES,
            "strategy-snapshot",
        ),
    ],
    ids=[
        "run-core-evidence",
        "system-core-evidence",
        "adapter-describe-stderr",
        "adapter-descriptor",
        "experiment-input",
        "dataset-input",
        "strategy-input",
    ],
)
def test_evidence_roles_and_owners(
    harness: MemoryFinalizationHarness,
    owner: ArtifactOwnerRef,
    correlation: EvidenceCorrelation,
    role: ArtifactSourceRole | None,
    files: dict[str, bytes] | None,
    kind: str | None,
) -> None:
    harness.plant_run()
    # The ADAPTER rows name a DESCRIBE invocation of that adapter (plan 3.1.1 row 3).
    describe = sample_invocation(
        CommandInvocationState.EXITED,
        kind=CommandKind.DESCRIBE,
        invocation_id=OTHER_INVOCATION_ID,
    )
    harness.store_data.tables.invocations[OTHER_INVOCATION_ID] = describe
    candidates = plant_core_evidence(
        harness.roots.store,
        owner=owner,
        correlation=correlation,
        files=files if files is not None else {"stderr.txt": b"stderr text\n"},
        source_role=role,
        artifact_kind=kind if kind is not None else "stderr-capture",
    )
    for candidate in candidates:
        harness.store_data.candidates[candidate.candidate_artifact_id] = candidate
    request = sample_evidence_request(
        [candidate.candidate_artifact_id for candidate in candidates],
        owner=owner,
        correlation=correlation,
        source_role=role,
    )
    registered = _ok(harness.finalize(request))
    assert registered.owner == owner
    durable = harness.durable()
    assert durable.journal_state == "REGISTERED"
    (ref,) = durable.refs
    assert ref.owner == owner
    assert ref.source_role is (role or candidates[0].source_role)
    assert ref.producer_kind.value == "CORE"
    # Only a RUN owner gains run links; the run row is never touched (reading 5).
    assert len(durable.run_artifacts) == (1 if owner == RUN_OWNER else 0)
    assert durable.run_revision == 4
    assert durable.run_state == "RUNNING"


def test_adapter_core_evidence_requires_a_describe_invocation(
    harness: MemoryFinalizationHarness,
) -> None:
    harness.plant_run()  # the fixture RUN invocation is a RUN command, not DESCRIBE
    candidates = plant_core_evidence(
        harness.roots.store, owner=ADAPTER_OWNER, correlation=INVOCATION_CORRELATION
    )
    for candidate in candidates:
        harness.store_data.candidates[candidate.candidate_artifact_id] = candidate
    request = sample_evidence_request(
        [candidate.candidate_artifact_id for candidate in candidates],
        owner=ADAPTER_OWNER,
        correlation=INVOCATION_CORRELATION,
    )
    before = harness.durable()
    refused = harness.finalize(request)
    assert _code(refused) == ARTIFACT_VALIDATION_FAILED
    assert "DESCRIBE" in _message(refused)
    assert harness.durable() == before


# --------------------------------------------------------------------------
# R19.1-21, R19.2-07: quarantined or corrupt
# --------------------------------------------------------------------------


def test_failed_candidate_is_quarantined_or_corrupt(
    harness: MemoryFinalizationHarness,
) -> None:
    # A declared hash that differs from the bytes: CORRUPT at HASH.
    result = harness.plant_result_prestate()
    first = result.candidates[0]
    target = result.roots.work_dir.joinpath(*first.staging_relative_path.split("/"))
    assert isinstance(target, Path)
    target.write_bytes(b"tampered after declaration\n")
    refused = harness.finalize(result.request)
    assert _code(refused) == ARTIFACT_VALIDATION_FAILED
    durable = harness.durable()
    assert durable.candidate_states[first.candidate_artifact_id] == "CORRUPT"
    assert durable.audit_actions.count("ARTIFACT_CORRUPT") == 1
    assert {entry.entry_id for entry in durable.quarantine_entries} == {
        first.candidate_artifact_id
    }
    assert durable.journal == ()
    # A token-shaped run in text evidence: QUARANTINED at REDACTION.
    shaped = plant_core_evidence(
        harness.roots.store,
        owner=SYSTEM_OWNER,
        correlation=DIAGNOSTIC_CORRELATION,
        files={"shaped.txt": b"token-shaped " + b"Q" * 40 + b"\n"},
    )
    for candidate in shaped:
        harness.store_data.candidates[candidate.candidate_artifact_id] = candidate
    refused_shape = harness.finalize(
        sample_evidence_request(
            [candidate.candidate_artifact_id for candidate in shaped],
            owner=SYSTEM_OWNER,
            correlation=DIAGNOSTIC_CORRELATION,
        )
    )
    assert _code(refused_shape) == SECURITY_SENSITIVE_MATERIAL_LEAKAGE
    after = harness.durable()
    assert after.candidate_states[shaped[0].candidate_artifact_id] == "QUARANTINED"
    # The CORRUPT candidate audited ``ARTIFACT_CORRUPT``; the shaped one is the
    # first ``ARTIFACT_QUARANTINED`` (after its ``ARTIFACT_LEAKAGE_DETECTED``).
    assert after.audit_actions.count("ARTIFACT_QUARANTINED") == 1
    assert after.audit_actions.count("ARTIFACT_LEAKAGE_DETECTED") == 1
    # Malformed JSON of a JSON kind: QUARANTINED at SCHEMA.
    malformed = plant_core_evidence(
        harness.roots.store,
        owner=EXPERIMENT_OWNER,
        correlation=DIAGNOSTIC_CORRELATION,
        files={"snapshot.json": b'{"unterminated": '},
        artifact_kind="configuration-snapshot",
    )
    for candidate in malformed:
        harness.store_data.candidates[candidate.candidate_artifact_id] = candidate
    refused_json = harness.finalize(
        sample_evidence_request(
            [candidate.candidate_artifact_id for candidate in malformed],
            owner=EXPERIMENT_OWNER,
            correlation=DIAGNOSTIC_CORRELATION,
        )
    )
    assert _code(refused_json) == ARTIFACT_VALIDATION_FAILED
    final = harness.durable()
    assert final.candidate_states[malformed[0].candidate_artifact_id] == "QUARANTINED"
    assert final.staging_files == ()


# --------------------------------------------------------------------------
# R19.2-03: the manifest facts fixed at step four
# --------------------------------------------------------------------------


class _AdvancingProbe(RecordingProbe):
    """Advance the clock at ``after_moved`` so T3's instant differs from T1's."""

    def __init__(self, clock: FixedClock) -> None:
        super().__init__()
        self._clock = clock

    def after_moved(self) -> None:
        super().after_moved()
        self._clock.advance(5)


def test_manifest_built_at_step_four(harness: MemoryFinalizationHarness) -> None:
    evidence = harness.plant_evidence_prestate()
    (candidate,) = evidence.candidates
    data = next(iter(harness.store_data.candidates.values()))
    assert data is candidate
    expected_hash = sha256_bytes(b"engine stderr line one\nengine stderr line two\n")
    probe = _AdvancingProbe(harness.clock)
    registered = _ok(harness.finalize(evidence.request, probe=probe))
    (mapping,) = registered.candidate_to_artifact_refs
    durable = harness.durable()
    (entry,) = durable.journal
    (planned,) = entry.planned_paths
    (observed,) = entry.observed
    # The facts fixed before the lease are the facts T3 wrote (plan 4.3 phase 1).
    assert planned.expected_sha256 == expected_hash == observed.observed_sha256
    assert mapping.content_hash == expected_hash
    assert mapping.artifact_id == artifact_id_for(
        candidate.candidate_artifact_id, expected_hash
    )
    (ref,) = durable.refs
    assert ref.content_hash == expected_hash
    assert (
        ref.size_bytes
        == planned.expected_size_bytes
        == len(b"engine stderr line one\nengine stderr line two\n")
    )
    assert ref.finalized_relative_path == planned.finalized_relative_path
    assert ref.created_at_utc == candidate.created_at_utc
    # T3 adds only ``finalized_at_utc`` (and the validation diagnostic ids).
    assert ref.finalized_at_utc == INSTANT.replace(second=5)
    manifest_path = harness.roots.store.manifest_path_for(ref.artifact_id)
    assert manifest_path.is_file()
    reader = harness.unit_of_work.begin()
    stored = _ok(reader.artifact_refs.get_manifest(ref.artifact_id))
    reader.rollback()
    assert manifest_path.read_bytes() == canonical_json_bytes(stored)
    assert stored.artifact_manifest_hash == artifact_manifest_hash(stored)
    assert stored.validation_diagnostic_ids == ()
    assert stored.finalized_at_utc == ref.finalized_at_utc


# --------------------------------------------------------------------------
# R21.2.1-03, R21.2.1-04, R21.2.1-06: path violation and validation failure
# --------------------------------------------------------------------------


def test_path_violation_and_validation_failure_outcomes(
    harness: MemoryFinalizationHarness,
) -> None:
    result = harness.plant_result_prestate()
    first, second = result.candidates
    missing = result.roots.work_dir.joinpath(*second.staging_relative_path.split("/"))
    assert isinstance(missing, Path)
    missing.unlink()
    refused = harness.finalize(result.request)
    assert _code(refused) == ARTIFACT_PATH_BOUNDARY_VIOLATION
    durable = harness.durable()
    # The candidate at fault is quarantined in phase 0; nothing else is written.
    assert durable.candidate_states[second.candidate_artifact_id] == "QUARANTINED"
    assert durable.candidate_states[first.candidate_artifact_id] == "CANDIDATE"
    assert durable.journal == ()
    assert durable.audit_actions == ("ARTIFACT_QUARANTINED",)
    (quarantined,) = [
        candidate
        for candidate in durable.candidates
        if candidate.candidate_artifact_id == second.candidate_artifact_id
    ]
    (observation,) = quarantined.validation_observations
    assert observation.stage == "PATH"
    assert observation.error_code == ARTIFACT_PATH_BOUNDARY_VIOLATION
    assert isinstance(observation.diagnostic_id, str)
    assert observation.diagnostic_id in {
        diagnostic.diagnostic_id for diagnostic in durable.diagnostics
    }
    assert durable.run_state == "RUNNING"


# --------------------------------------------------------------------------
# R21.2-02, R21.2.1-07, R21.2.1-08: a persistence failure at T3's commit
# --------------------------------------------------------------------------


class _ArmingProbe(RecordingProbe):
    """Arm one commit failure right before T3 opens."""

    def __init__(self, harness: MemoryFinalizationHarness) -> None:
        super().__init__()
        self._harness = harness

    def before_registered(self) -> None:
        super().before_registered()
        self._harness.unit_of_work.fail_next_commit(
            persistence_failure(
                WRITE_FAILED,
                message="the transaction could not be committed",
                clock=FixedClock(INSTANT),
                details={"operation": "commit"},
            )
        )


def test_persistence_failure_rolls_back_journal_drives_recovery(
    harness: MemoryFinalizationHarness,
) -> None:
    evidence = harness.plant_evidence_prestate()
    failed = harness.finalize(evidence.request, probe=_ArmingProbe(harness))
    assert _code(failed) == WRITE_FAILED
    before = harness.durable()
    assert before.journal_state == "MOVED"
    assert before.refs == ()
    assert "FINALIZATION_REGISTERED" not in before.audit_actions
    assert before.audit_actions[-1] == "FINALIZATION_MOVED"
    assert len(before.object_blobs) == 1
    # The pass resumes the journal once its lease has expired (the ruling).
    harness.advance_clock(EVIDENCE_LEASE_SECONDS + 1)
    report = _ok(harness.recover())
    assert report.resumed == 1
    assert report.registered == 1
    assert report.abandoned == 0
    after = harness.durable()
    assert after.journal_state == "REGISTERED"
    assert len(after.refs) == 1
    assert after.audit_actions.count("FINALIZATION_REGISTERED") == 1
    assert after.audit_actions.count("RECONCILIATION_FINALIZATION_RESUMED") == 1


def test_registration_refusal_rolls_back_t3_before_abandonment(
    harness: MemoryFinalizationHarness,
) -> None:
    """The carried record_finalization phase-2 follow-up: a refusal met at a
    later insert of the batch leaves no partial batch because the finalizer
    rolls T3 back before it abandons."""
    evidence = harness.plant_evidence_prestate(files=_TWO_EVIDENCE_FILES)
    first, second = evidence.candidates
    second_hash = sha256_bytes(_TWO_EVIDENCE_FILES["stderr.txt"])
    # A reference already recorded for the second candidate: the second insert of
    # the batch is the duplicate conflict, after the first insert succeeded.
    planted = sample_ref(
        second.model_copy(update={"state": _S.FINALIZING}),
        content_hash=second_hash,
        size_bytes=len(_TWO_EVIDENCE_FILES["stderr.txt"]),
    )
    harness.store_data.refs[planted.artifact_id] = (
        planted,
        sample_artifact_manifest(planted),
    )
    refused = harness.finalize(evidence.request)
    assert _code(refused) == CONCURRENCY_CONFLICT
    durable = harness.durable()
    assert durable.refs == (planted,)
    assert durable.journal_state == "ABANDONED"
    assert durable.abandon_reason == CONCURRENCY_CONFLICT
    assert "FINALIZATION_REGISTERED" not in durable.audit_actions
    assert durable.audit_actions.count("FINALIZATION_ABANDONED") == 1
    assert durable.candidate_states[first.candidate_artifact_id] == "QUARANTINED"
    assert durable.object_blobs == ()
    assert len(durable.quarantine_entries) == 1


def test_rolled_back_t3_leaves_no_projection_a_commit_writes_one(
    harness: MemoryFinalizationHarness,
) -> None:
    """Plan 6.2: the ``manifests/<artifact_id>.json`` projection is written
    exclusive-create *after* the blob is registered, so a rolled-back T3 leaves
    nothing a reader could mistake for a committed reference; the committed
    registration writes it and the file restates the authoritative row."""
    evidence = harness.plant_evidence_prestate()
    with pytest.raises(FinalizationCrash):
        harness.finalize(evidence.request, probe=CrashingProbe("inside_registered"))
    durable = harness.durable()
    assert durable.refs == ()
    assert durable.journal_state == "MOVED"
    manifests_root = harness.roots.store.manifests_root
    assert tuple(manifests_root.glob("*.json")) == ()
    harness.advance_clock(EVIDENCE_LEASE_SECONDS + 1)  # the lease expires first
    _ok(harness.recover())
    after = harness.durable()
    (ref,) = after.refs
    projection = harness.roots.store.manifest_path_for(ref.artifact_id)
    assert projection.is_file()
    stored = harness.store_data.refs[ref.artifact_id][1]
    assert ArtifactManifest.model_validate_json(projection.read_bytes()) == stored
    assert tuple(manifests_root.glob("*.json")) == (projection,)


def test_projection_is_exclusive_create_and_its_failure_is_tolerated(
    harness: MemoryFinalizationHarness,
) -> None:
    """Plan 6.2: the projection is exclusive-create, so a file already at the
    projection path is kept byte for byte; a path that cannot be written leaves
    the committed registration intact and is logged, never a failure."""
    evidence = harness.plant_evidence_prestate(files=_TWO_EVIDENCE_FILES)
    first, second = evidence.candidates

    def artifact_id_of(candidate_id: str, relative_path: str) -> str:
        leaf = relative_path.rsplit("/", 1)[-1]
        return artifact_id_for(candidate_id, sha256_bytes(_TWO_EVIDENCE_FILES[leaf]))

    first_id = artifact_id_of(first.candidate_artifact_id, first.staging_relative_path)
    second_id = artifact_id_of(
        second.candidate_artifact_id, second.staging_relative_path
    )
    pre_existing = harness.roots.store.manifest_path_for(first_id)
    pre_existing.write_bytes(b'{"kept": "as-is"}\n')
    # A directory at the second projection path makes the exclusive create fail.
    harness.roots.store.manifest_path_for(second_id).mkdir()
    log = RecordingLog()
    registered = _ok(harness.finalize(evidence.request, log=log))
    assert registered.journal_state == "REGISTERED"
    durable = harness.durable()
    assert {ref.artifact_id for ref in durable.refs} == {first_id, second_id}
    assert pre_existing.read_bytes() == b'{"kept": "as-is"}\n'
    assert harness.roots.store.manifest_path_for(second_id).is_dir()
    warnings = [
        fact
        for fact in log.facts
        if fact.severity == "WARNING" and "projection" in fact.message
    ]
    assert [fact.event_code for fact in warnings] == [ARTIFACT_MOVE_FAILED]
    assert second_id in warnings[0].message
    assert log.facts[-1].event_code == "ARTIFACT.FINALIZATION_REGISTERED"


# --------------------------------------------------------------------------
# Fault injection: T1 and T2 commit failures, the T4 close whose audit fails
# --------------------------------------------------------------------------


def _write_failure() -> Failure:
    return persistence_failure(
        WRITE_FAILED,
        message="the transaction could not be committed",
        clock=FixedClock(INSTANT),
    )


class _CommitFailureAt(RecordingProbe):
    """Arm one commit failure for the next begun transaction at one probe point:
    ``before_prepared`` targets T1, ``before_moved`` targets T2."""

    def __init__(self, harness: MemoryFinalizationHarness, point: str) -> None:
        super().__init__()
        self._harness = harness
        self._point = point

    def _arm(self, point: str) -> None:
        if point == self._point:
            self._harness.unit_of_work.fail_next_commit(_write_failure())

    def before_prepared(self) -> None:
        super().before_prepared()
        self._arm("before_prepared")

    def before_moved(self) -> None:
        super().before_moved()
        self._arm("before_moved")


def test_t1_commit_failure_leaves_no_lease_and_recovery_resumes(
    harness: MemoryFinalizationHarness,
) -> None:
    """T1 meets the storage class at commit: no journal, no lease, no T1 audit
    row; the candidates stay VALIDATING from phase 1's own short transactions
    with their bytes in staging (the CP-1 shape), and recovery resumes from
    phase 2."""
    evidence = harness.plant_evidence_prestate()
    failed = harness.finalize(
        evidence.request, probe=_CommitFailureAt(harness, "before_prepared")
    )
    assert _code(failed) == WRITE_FAILED
    before = harness.durable()
    assert before.journal == ()
    assert all(state == "VALIDATING" for state in before.candidate_states.values())
    assert before.audit_actions == ()
    assert len(before.staging_files) == 1
    assert before.object_blobs == ()
    assert harness.unit_of_work.open_transactions() == ()
    report = _ok(harness.recover())
    assert (report.resumed, report.registered) == (1, 1)
    after = harness.durable()
    assert after.journal_state == "REGISTERED"
    assert len(after.refs) == 1
    assert after.staging_files == ()


def test_t2_commit_failure_leaves_prepared_blobs_and_recovery_registers(
    harness: MemoryFinalizationHarness,
) -> None:
    """T2 meets the storage class at commit: the blob is at its finalized path
    while the journal is still PREPARED (the CP-4 shape) and no
    ``FINALIZATION_MOVED`` row exists; recovery re-hashes in place, writes MOVED
    and registers."""
    evidence = harness.plant_evidence_prestate()
    failed = harness.finalize(
        evidence.request, probe=_CommitFailureAt(harness, "before_moved")
    )
    assert _code(failed) == WRITE_FAILED
    before = harness.durable()
    assert before.journal_state == "PREPARED"
    assert len(before.object_blobs) == 1
    assert before.staging_files == ()
    assert before.audit_actions[-1] == "FINALIZATION_PREPARED"
    assert before.refs == ()
    harness.advance_clock(EVIDENCE_LEASE_SECONDS + 1)  # the lease expires first
    report = _ok(harness.recover())
    assert (report.resumed, report.registered) == (1, 1)
    after = harness.durable()
    assert after.journal_state == "REGISTERED"
    assert after.audit_actions.count("FINALIZATION_MOVED") == 1
    assert len(after.refs) == 1


def test_result_lease_close_failure_is_logged_not_fatal(
    harness: MemoryFinalizationHarness,
) -> None:
    """T4 never changes the finalization's outcome: when the close's audit fails,
    the raw bytes are already removed (a filesystem fact no transaction undoes),
    the ``RETENTION_DELETED`` row is absent because its transaction rolled back,
    and the failure is logged so the gap is visible."""
    result = harness.plant_result_prestate()
    refusing = RefusingAuditor(
        harness.audit_ids,
        harness.clock,
        refused_action="RETENTION_DELETED",
        failure=_write_failure(),
    )
    harness.auditor = refusing
    log = RecordingLog()
    refused = harness.finalize(result.request, log=log)
    assert _code(refused) == INVARIANT_VIOLATION  # the registrar's refusal stands
    assert refusing.refusals == 1
    durable = harness.durable()
    assert durable.journal_state == "ABANDONED"
    assert "RETENTION_DELETED" not in durable.audit_actions
    assert durable.audit_actions.count("FINALIZATION_ABANDONED") == 1
    assert not result.roots.request_path.exists()
    assert isinstance(result.roots.result_path, Path)
    assert not result.roots.result_path.exists()
    warnings = [
        fact
        for fact in log.facts
        if fact.severity == "WARNING" and "close" in fact.message
    ]
    assert [fact.event_code for fact in warnings] == [WRITE_FAILED]


# --------------------------------------------------------------------------
# R30.3-01: every phase audited in its transaction
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("point", "expected"),
    [
        (
            "after_prepared",
            (
                "ARTIFACT_VALIDATED",
                "FINALIZATION_LEASE_ACQUIRED",
                "FINALIZATION_PREPARED",
            ),
        ),
        (
            "after_moved",
            (
                "ARTIFACT_VALIDATED",
                "FINALIZATION_LEASE_ACQUIRED",
                "FINALIZATION_PREPARED",
                "FINALIZATION_MOVED",
            ),
        ),
        (
            "inside_registered",
            (
                "ARTIFACT_VALIDATED",
                "FINALIZATION_LEASE_ACQUIRED",
                "FINALIZATION_PREPARED",
                "FINALIZATION_MOVED",
            ),
        ),
    ],
)
def test_every_phase_audited_in_its_transaction(
    harness: MemoryFinalizationHarness, point: str, expected: tuple[str, ...]
) -> None:
    evidence = harness.plant_evidence_prestate()
    with pytest.raises(FinalizationCrash):
        harness.finalize(evidence.request, probe=CrashingProbe(point))
    durable = harness.durable()
    assert durable.audit_actions == expected
    assert durable.refs == ()
    assert harness.unit_of_work.open_transactions() == ()
    if point == "inside_registered":
        # T3 rolled back through the scope's ``finally``: the journal stays MOVED.
        assert durable.journal_state == "MOVED"
    completed = harness.plant_evidence_prestate(
        owner=SYSTEM_OWNER, correlation=DIAGNOSTIC_CORRELATION
    )
    _ok(harness.finalize(completed.request))
    appended = harness.durable().audit_actions[len(expected) :]
    assert appended == (
        "ARTIFACT_VALIDATED",
        "FINALIZATION_LEASE_ACQUIRED",
        "FINALIZATION_PREPARED",
        "FINALIZATION_MOVED",
        "FINALIZATION_REGISTERED",
    )


# --------------------------------------------------------------------------
# F8.2-4: the cancellation token before PREPARED
# --------------------------------------------------------------------------


class _CancellingProbe(RecordingProbe):
    def __init__(self, token: FlagCancellationToken, point: str) -> None:
        super().__init__()
        self._token = token
        self._point = point

    def before_prepared(self) -> None:
        super().before_prepared()
        if self._point == "before_prepared":
            self._token.request_cancellation()

    def after_prepared(self) -> None:
        super().after_prepared()
        if self._point == "after_prepared":
            self._token.request_cancellation()


def test_cancellation_token_refuses_before_prepared(
    harness: MemoryFinalizationHarness,
) -> None:
    evidence = harness.plant_evidence_prestate()
    before = harness.durable()
    requested = FlagCancellationToken(requested=True)
    refused = harness.finalize(evidence.request, cancellation=requested)
    assert _code(refused) == PROCESS_CANCELLED
    assert harness.durable() == before
    # Requested after phase 1 but before T1: still the phase-0 refusal, the
    # candidates stay VALIDATING for recovery and no journal row exists.
    token = FlagCancellationToken()
    refused_late = harness.finalize(
        evidence.request,
        probe=_CancellingProbe(token, "before_prepared"),
        cancellation=token,
    )
    assert _code(refused_late) == PROCESS_CANCELLED
    during = harness.durable()
    assert all(state == "VALIDATING" for state in during.candidate_states.values())
    assert during.journal == ()
    # Requested after T1: ignored; the finalization completes (plan 4.3).
    token_after = FlagCancellationToken()
    _ok(
        harness.finalize(
            evidence.request,
            probe=_CancellingProbe(token_after, "after_prepared"),
            cancellation=token_after,
        )
    )
    assert harness.durable().journal_state == "REGISTERED"
    assert token_after.polls >= 2


# --------------------------------------------------------------------------
# RC-11: an adapter-produced candidate cannot be evidence
# --------------------------------------------------------------------------


def test_adapter_candidate_cannot_be_evidence(
    harness: MemoryFinalizationHarness,
) -> None:
    result = harness.plant_result_prestate()
    before = harness.durable()
    request = sample_evidence_request(
        [candidate.candidate_artifact_id for candidate in result.candidates],
        owner=RUN_OWNER,
        correlation=INVOCATION_CORRELATION,
    )
    refused = harness.finalize(request)
    assert _code(refused) == ARTIFACT_VALIDATION_FAILED
    assert "adapter-produced candidate cannot be evidence" in _message(refused)
    assert harness.durable() == before


# --------------------------------------------------------------------------
# RC-10 (memory half): replay returns the stored result
# --------------------------------------------------------------------------


def test_evidence_replay_returns_the_stored_result(
    harness: MemoryFinalizationHarness,
) -> None:
    evidence = harness.plant_evidence_prestate()
    first = _ok(harness.finalize(evidence.request))
    before = harness.durable()
    again = _ok(harness.finalize(evidence.request, probe=RecordingProbe()))
    assert again.replayed is True
    assert again.model_copy(update={"replayed": False}) == first
    after = harness.durable()
    assert after.journal == before.journal
    assert after.refs == before.refs
    assert after.candidates == before.candidates
    assert after.audit_actions == (*before.audit_actions, "FINALIZATION_REPLAYED")


def test_finalizer_holds_no_token_and_no_state_between_calls(
    harness: MemoryFinalizationHarness,
) -> None:
    finalizer = harness.finalizer(NoProbe())
    assert isinstance(finalizer, CoreArtifactFinalizer)
    result = harness.plant_result_prestate()
    harness.finalize(result.request)
    for name, value in vars(finalizer).items():
        assert not isinstance(value, AttemptTokenMaterial), name
        assert value is not FIXTURE_TOKEN, name
    assert RESULT_TIMEOUT_SECONDS == 600
    assert EXPERIMENT_ID == RUN_OWNER.experiment_id


# --------------------------------------------------------------------------
# The RESULT lease ruling of 2026-11-08: the lease expires before the immutable
# deadline, renewal is capped at the deadline, a takeover is one durable
# compare-and-swap, a stale holder or newcomer is refused, a restart defers an
# unexpired lease, and an exhausted deadline never registers
# --------------------------------------------------------------------------


class _ClockAdvancingProbe(RecordingProbe):
    """Advance the fixed clock once at ``after_move(index)``; optionally crash at
    ``after_moved`` so the ``MOVED`` row is the durable state under test."""

    def __init__(
        self,
        clock: FixedClock,
        *,
        index: int,
        seconds: float,
        crash_after_moved: bool = False,
    ) -> None:
        super().__init__()
        self._clock = clock
        self._index = index
        self._seconds = seconds
        self._crash_after_moved = crash_after_moved

    def after_move(self, index: int) -> None:
        super().after_move(index)
        if index == self._index:
            self._clock.advance(self._seconds)

    def after_moved(self) -> None:
        super().after_moved()
        if self._crash_after_moved:
            raise FinalizationCrash("after_moved")


def _park(
    harness: MemoryFinalizationHarness, request: Any, *, sends: int
) -> Coroutine[Any, Any, Result[FinalizationResult]]:
    """Start a finalization and leave it suspended after ``sends`` checkpoints:
    three park it with T1 committed and nothing moved, five with T2 committed
    (``test_cooperative_checkpoint_yields_once_per_boundary``)."""
    coroutine = harness.finalizer(RecordingProbe()).finalize(
        request, FlagCancellationToken()
    )
    for _ in range(sends):
        coroutine.send(None)
    return coroutine


def _renew_externally(
    harness: MemoryFinalizationHarness,
    entry: FinalizationJournalEntry,
    lease: datetime,
) -> FinalizationJournalEntry:
    """Another newcomer's takeover written directly: the reflexive renewal at the
    stored revision, committed."""
    transaction = harness.unit_of_work.begin()
    renewed = _ok(
        transaction.finalization_journal.compare_and_swap(
            entry.revision, renew_journal(entry, lease)
        )
    )
    _ok(transaction.commit())
    return renewed


def _lease_acquisitions(durable: DurableState) -> list[Any]:
    return [
        event
        for event in durable.audit_events
        if event.action.value == "FINALIZATION_LEASE_ACQUIRED"
    ]


def test_result_lease_expires_before_the_immutable_deadline(
    harness: MemoryFinalizationHarness,
) -> None:
    result = harness.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        harness.finalize(result.request, probe=CrashingProbe("after_prepared"))
    durable = harness.durable()
    (prepared,) = durable.journal
    deadline = prepared.finalization_deadline_utc
    assert isinstance(deadline, datetime)
    # The deadline is snapshotted once: prepared_at plus the request's timeout.
    assert deadline == prepared.prepared_at_utc + timedelta(
        seconds=RESULT_TIMEOUT_SECONDS
    )
    assert durable.run_deadline == deadline
    # The lease is the compiled interval capped at the deadline, so it expires
    # strictly before the deadline and leaves a takeover window (RC-13, CP-2).
    assert RESULT_LEASE_SECONDS == EVIDENCE_LEASE_SECONDS == 300
    assert prepared.lease_expires_at_utc == prepared.prepared_at_utc + timedelta(
        seconds=RESULT_LEASE_SECONDS
    )
    assert prepared.lease_expires_at_utc < deadline
    (acquired,) = _lease_acquisitions(durable)
    assert acquired.details["lease_seconds"] == RESULT_LEASE_SECONDS
    assert acquired.details["timeout_seconds"] == RESULT_TIMEOUT_SECONDS
    assert "takeover" not in acquired.details


def test_renewal_is_capped_at_the_deadline_and_leaves_it_unchanged(
    harness: MemoryFinalizationHarness,
) -> None:
    result = harness.plant_result_prestate()
    # 400 s pass during the moves: an uncapped renewal at T2 would reach 700 s.
    probe = _ClockAdvancingProbe(
        harness.clock,
        index=1,
        seconds=RESULT_TIMEOUT_SECONDS - RESULT_LEASE_SECONDS + 100,
        crash_after_moved=True,
    )
    with pytest.raises(FinalizationCrash):
        harness.finalize(result.request, probe=probe)
    durable = harness.durable()
    (moved,) = durable.journal
    assert moved.state.value == "MOVED"
    assert moved.revision == 2
    deadline = moved.finalization_deadline_utc
    assert isinstance(deadline, datetime)
    assert deadline == INSTANT + timedelta(seconds=RESULT_TIMEOUT_SECONDS)
    assert harness.clock.now_utc() + timedelta(seconds=RESULT_LEASE_SECONDS) > deadline
    assert moved.lease_expires_at_utc == deadline
    assert durable.run_deadline == deadline


def test_takeover_renews_the_lease_durably_before_any_move(
    harness: MemoryFinalizationHarness,
) -> None:
    result = harness.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        harness.finalize(result.request, probe=CrashingProbe("after_prepared"))
    (prepared,) = harness.durable().journal
    deadline = prepared.finalization_deadline_utc
    assert isinstance(deadline, datetime)
    harness.advance_clock(RESULT_LEASE_SECONDS + 1)
    # The newcomer crashes after the takeover and before its first move.
    with pytest.raises(FinalizationCrash):
        harness.finalize(result.request, probe=CrashingProbe("before_move", 0))
    taken = harness.durable()
    (entry,) = taken.journal
    assert entry.state.value == "PREPARED"
    assert entry.revision == prepared.revision + 1
    assert entry.lease_expires_at_utc == min(
        harness.clock.now_utc() + timedelta(seconds=RESULT_LEASE_SECONDS), deadline
    )
    assert entry.lease_expires_at_utc > prepared.lease_expires_at_utc
    assert entry.finalization_deadline_utc == deadline
    assert taken.run_deadline == deadline
    assert taken.object_blobs == ()
    assert sum(name.endswith(".bin") for name in taken.command_root_files) == 2
    first, second = _lease_acquisitions(taken)
    assert "takeover" not in first.details
    assert second.details["takeover"] is True
    assert second.details["from_revision"] == prepared.revision
    # The takeover is durable: a third finalizer one second later meets RC-12
    # under the newcomer's lease instead of taking over again.
    harness.advance_clock(1)
    refused = harness.finalize(result.request)
    assert _code(refused) == CONCURRENCY_CONFLICT
    assert "active lease" in _message(refused)
    assert harness.durable() == taken


def test_stale_newcomer_is_refused_before_any_move(
    harness: MemoryFinalizationHarness,
) -> None:
    result = harness.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        harness.finalize(result.request, probe=CrashingProbe("after_prepared"))
    (prepared,) = harness.durable().journal
    deadline = prepared.finalization_deadline_utc
    assert isinstance(deadline, datetime)
    harness.advance_clock(RESULT_LEASE_SECONDS + 1)
    # Another newcomer took the expired lease first.
    _renew_externally(harness, prepared, deadline)
    before = harness.durable()
    assert before.journal[0].revision == prepared.revision + 1
    refused = harness.finalizer().resume_journal(prepared)
    assert _code(refused) == CONCURRENCY_CONFLICT
    # Refused at the compare-and-swap: no move, no hash, no row, no audit.
    assert harness.durable() == before
    assert before.object_blobs == ()
    assert sum(name.endswith(".bin") for name in before.command_root_files) == 2


def test_restart_defers_an_unexpired_result_lease_until_expiry(
    harness: MemoryFinalizationHarness,
) -> None:
    result = harness.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        harness.finalize(result.request, probe=CrashingProbe("after_prepared"))
    before = harness.durable()
    assert before.journal_state == "PREPARED"
    report = _ok(harness.recover())
    assert (report.deferred, report.resumed, report.changes) == (1, 0, 0)
    assert (report.registered, report.abandoned, report.quarantined) == (0, 0, 0)
    deferred = harness.durable()
    # Recoverable material preserved: the journal, the candidates, the staged
    # bytes, the command root and the run row are exactly as the crash left them.
    assert deferred.journal == before.journal
    assert deferred.candidates == before.candidates
    assert deferred.staging_files == before.staging_files
    assert deferred.command_root_files == before.command_root_files
    assert deferred.object_blobs == before.object_blobs == ()
    assert deferred.quarantine_entries == ()
    assert deferred.run == before.run
    assert deferred.audit_actions == (
        *before.audit_actions,
        "RECONCILIATION_FINALIZATION_RESUMED",
    )
    assert deferred.audit_events[-1].details["deferred"] == 1
    assert result.roots.request_path.is_file()
    # Past the lease and inside the deadline, the pass takes over; the Task 6
    # registrar's refusal then abandons the attempt (RESULT success is Task 7's).
    harness.advance_clock(RESULT_LEASE_SECONDS + 1)
    second = _ok(harness.recover())
    assert (second.deferred, second.resumed) == (0, 1)
    assert (second.abandoned, second.registered) == (1, 0)
    after = harness.durable()
    assert after.journal_state == "ABANDONED"
    assert after.run_state == "FAILED"
    assert len(_lease_acquisitions(after)) == 2
    assert all(state == "QUARANTINED" for state in after.candidate_states.values())


def test_restart_defers_an_unexpired_evidence_lease_until_expiry(
    harness: MemoryFinalizationHarness,
) -> None:
    evidence = harness.plant_evidence_prestate()
    with pytest.raises(FinalizationCrash):
        harness.finalize(evidence.request, probe=CrashingProbe("after_moved"))
    before = harness.durable()
    assert before.journal_state == "MOVED"
    report = _ok(harness.recover())
    assert (report.deferred, report.resumed) == (1, 0)
    assert (report.registered, report.changes) == (0, 0)
    deferred = harness.durable()
    assert deferred.journal == before.journal
    assert deferred.object_blobs == before.object_blobs  # the planned blob stays
    assert deferred.refs == ()
    assert deferred.quarantine_entries == ()
    harness.advance_clock(EVIDENCE_LEASE_SECONDS + 1)
    second = _ok(harness.recover())
    assert (second.deferred, second.resumed, second.registered) == (0, 1, 1)
    after = harness.durable()
    assert after.journal_state == "REGISTERED"
    assert len(after.refs) == 1
    assert len(_lease_acquisitions(after)) == 2


def test_live_holder_keeps_its_lease_across_a_reconciliation_pass(
    harness: MemoryFinalizationHarness,
) -> None:
    evidence = harness.plant_evidence_prestate()
    holder = _park(harness, evidence.request, sends=3)
    assert harness.durable().journal_state == "PREPARED"
    # The pass finds the live holder's unexpired lease and defers it.
    report = _ok(harness.recover())
    assert (report.deferred, report.resumed, report.registered) == (1, 0, 0)
    registered = _ok(run_coroutine(holder))
    assert registered.journal_state == "REGISTERED"
    after = harness.durable()
    assert after.journal_state == "REGISTERED"
    assert len(after.refs) == 1
    assert len(_lease_acquisitions(after)) == 1  # no takeover happened
    assert after.audit_actions.count("FINALIZATION_REGISTERED") == 1


def test_superseded_holder_is_fenced_from_abandonment_and_quarantine(
    harness: MemoryFinalizationHarness,
) -> None:
    evidence = harness.plant_evidence_prestate()
    holder = _park(harness, evidence.request, sends=3)  # T1 committed, no move
    harness.advance_clock(EVIDENCE_LEASE_SECONDS + 1)
    newcomer = _ok(harness.finalize(evidence.request))
    assert newcomer.journal_state == "REGISTERED"
    taken = harness.durable()
    assert taken.journal_state == "REGISTERED"
    assert len(_lease_acquisitions(taken)) == 2
    # The superseded holder wakes: its staged file is gone and it tries to
    # abandon; the stale revision fences every write, so nothing changes.
    stale = run_coroutine(holder)
    assert isinstance(stale, Failure)
    assert harness.durable() == taken
    assert "FINALIZATION_ABANDONED" not in taken.audit_actions
    assert "ARTIFACT_QUARANTINED" not in taken.audit_actions
    assert taken.quarantine_entries == ()
    assert len(taken.refs) == 1


def test_superseded_holder_is_fenced_from_registration(
    harness: MemoryFinalizationHarness,
) -> None:
    evidence = harness.plant_evidence_prestate()
    holder = _park(harness, evidence.request, sends=5)  # T2 committed: MOVED
    assert harness.durable().journal_state == "MOVED"
    harness.advance_clock(EVIDENCE_LEASE_SECONDS + 1)
    newcomer = _ok(harness.finalize(evidence.request))
    taken = harness.durable()
    assert taken.journal_state == "REGISTERED"
    assert [ref.artifact_id for ref in taken.refs] == [
        mapping.artifact_id for mapping in newcomer.candidate_to_artifact_refs
    ]
    stale = run_coroutine(holder)
    assert isinstance(stale, Failure)
    assert harness.durable() == taken
    assert taken.audit_actions.count("FINALIZATION_REGISTERED") == 1
    assert "FINALIZATION_ABANDONED" not in taken.audit_actions


def test_registration_is_refused_after_deadline_exhaustion(
    harness: MemoryFinalizationHarness,
) -> None:
    result = harness.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        harness.finalize(result.request, probe=CrashingProbe("after_moved"))
    harness.advance_clock(RESULT_TIMEOUT_SECONDS + 1)
    timed_out = harness.finalize(result.request)
    assert _code(timed_out) == ARTIFACT_FINALIZATION_TIMED_OUT
    assert harness.registrar.result_calls == 0
    after = harness.durable()
    assert after.run_state == "TIMED_OUT"
    assert after.journal_state == "ABANDONED"
    assert after.abandon_reason == ARTIFACT_FINALIZATION_TIMED_OUT
    assert after.refs == ()
    assert after.object_blobs == ()
    assert len(_lease_acquisitions(after)) == 1  # nothing left to lease
    assert not result.roots.request_path.exists()


# Branch pins for ``_take_over``: the gate both callers filter before, and its
# audit and commit failures, each leaving the journal exactly as stored.


def test_resume_journal_refuses_an_unexpired_lease_directly(
    harness: MemoryFinalizationHarness,
) -> None:
    result = harness.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        harness.finalize(result.request, probe=CrashingProbe("after_prepared"))
    before = harness.durable()
    (prepared,) = before.journal
    refused = harness.finalizer().resume_journal(prepared)
    assert _code(refused) == CONCURRENCY_CONFLICT
    assert "active lease" in _message(refused)
    assert harness.durable() == before
    assert harness.unit_of_work.open_transactions() == ()


def test_takeover_audit_refusal_rolls_the_renewal_back(
    harness: MemoryFinalizationHarness,
) -> None:
    result = harness.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        harness.finalize(result.request, probe=CrashingProbe("after_prepared"))
    before = harness.durable()
    (prepared,) = before.journal
    harness.advance_clock(RESULT_LEASE_SECONDS + 1)
    refusing = RefusingAuditor(
        harness.audit_ids,
        harness.clock,
        refused_action="FINALIZATION_LEASE_ACQUIRED",
        failure=_write_failure(),
    )
    harness.auditor = refusing
    refused = harness.finalizer().resume_journal(prepared)
    assert _code(refused) == WRITE_FAILED
    assert refusing.refusals == 1
    # The renewal and its audit row commit or roll back together.
    assert harness.durable() == before
    assert harness.unit_of_work.open_transactions() == ()


def test_takeover_commit_failure_leaves_the_journal_for_the_next_pass(
    harness: MemoryFinalizationHarness,
) -> None:
    result = harness.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        harness.finalize(result.request, probe=CrashingProbe("after_prepared"))
    before = harness.durable()
    (prepared,) = before.journal
    harness.advance_clock(RESULT_LEASE_SECONDS + 1)
    harness.unit_of_work.fail_next_committed(_write_failure())
    refused = harness.finalizer().resume_journal(prepared)
    assert _code(refused) == WRITE_FAILED
    assert harness.durable() == before  # reading 26: the journal stays as stored
    assert harness.unit_of_work.open_transactions() == ()


# --------------------------------------------------------------------------
# Fault injection at every repository member a phase transaction consults: the
# transaction commits or rolls back as a whole and the finalizer answers the
# failure the member met (reading 26); the refusal branches of phases 0 and 2
# --------------------------------------------------------------------------

_FILE_SHARE_READ: Final = 0x00000001
_J = FinalizationJournalState
_F = ArtifactFinalizationPurpose


def _fail_call(
    monkeypatch: pytest.MonkeyPatch,
    owner: type,
    method: str,
    failure: Failure,
    *,
    call: int = 1,
) -> None:
    """Replace ``owner.method`` so that its ``call``-th invocation, counted across
    every transaction from this moment on, answers ``failure`` instead of running;
    every other invocation runs the original (the memory twin of one refused
    statement at the Stage 8 driver boundary)."""
    original = getattr(owner, method)
    counter = {"calls": 0}

    def patched(self: object, *args: Any, **kwargs: Any) -> Any:
        counter["calls"] += 1
        if counter["calls"] == call:
            return failure
        return original(self, *args, **kwargs)

    monkeypatch.setattr(owner, method, patched)


def _hold_open(path: Path, share_mode: int) -> int:
    """Hold ``path`` open with ``share_mode``: zero refuses every other open,
    ``_FILE_SHARE_READ`` admits a read-only handle and refuses a read-write reopen
    and any rename."""
    return _winapi.CreateFile(
        str(path),
        _winapi.GENERIC_READ,
        share_mode,
        _winapi.NULL,
        _winapi.OPEN_EXISTING,
        0,
        _winapi.NULL,
    )


def _result_staged(result: ResultPlan, index: int) -> Path:
    assert isinstance(result.roots.work_dir, Path)
    candidate = result.candidates[index]
    return result.roots.work_dir.joinpath(*candidate.staging_relative_path.split("/"))


def _refusing(harness: MemoryFinalizationHarness, action: str) -> RefusingAuditor:
    refusing = RefusingAuditor(
        harness.audit_ids,
        harness.clock,
        refused_action=action,
        failure=_write_failure(),
    )
    harness.auditor = refusing
    return refusing


def _bin_files(durable: DurableState) -> int:
    return sum(name.endswith(".bin") for name in durable.command_root_files)


# -- the abandonment transaction (plan 4.3's failure column) ---------------------


def _assert_abandonment_rolled_back(
    harness: MemoryFinalizationHarness, result: ResultPlan
) -> None:
    durable = harness.durable()
    assert durable.journal_state == "MOVED"
    assert all(state == "FINALIZING" for state in durable.candidate_states.values())
    assert len(durable.object_blobs) == 2
    assert durable.quarantine_entries == ()
    assert durable.run_state == "RUNNING"
    assert "FINALIZATION_ABANDONED" not in durable.audit_actions
    assert "ARTIFACT_QUARANTINED" not in durable.audit_actions
    assert durable.audit_actions[-1] == "FINALIZATION_MOVED"
    assert durable.diagnostics == ()
    # The journal is not terminal, so the lease never closed the root.
    assert result.roots.request_path.is_file()
    assert harness.unit_of_work.open_transactions() == ()


@pytest.mark.parametrize(
    ("owner", "method", "call", "expected"),
    [
        pytest.param(
            MemoryFinalizationJournalRepository,
            "compare_and_swap",
            2,
            INVARIANT_VIOLATION,
            id="journal-swap-answers-the-cause",
        ),
        pytest.param(MemoryDiagnosticWriter, "record", 1, WRITE_FAILED, id="diag"),
        pytest.param(
            MemoryCandidateArtifactRepository,
            "compare_and_swap",
            5,
            WRITE_FAILED,
            id="candidate-swap",
        ),
        pytest.param(
            MemoryFinalizationTransaction, "commit", 5, WRITE_FAILED, id="commit"
        ),
    ],
)
def test_abandonment_member_faults_leave_the_journal_moved(
    harness: MemoryFinalizationHarness,
    monkeypatch: pytest.MonkeyPatch,
    owner: type,
    method: str,
    call: int,
    expected: str,
) -> None:
    """A member refused inside the abandonment transaction rolls the whole
    abandonment back: the journal stays MOVED for recovery, the candidates
    FINALIZING, the blobs in place, nothing quarantined. A refused journal swap
    answers the failure that caused the abandonment (another holder owns the
    journal now); every other member answers its own failure."""
    result = harness.plant_result_prestate()
    _fail_call(monkeypatch, owner, method, _write_failure(), call=call)
    failed = harness.finalize(result.request)
    assert _code(failed) == expected
    _assert_abandonment_rolled_back(harness, result)


@pytest.mark.parametrize("action", ["FINALIZATION_ABANDONED", "ARTIFACT_QUARANTINED"])
def test_abandonment_audit_refusal_rolls_the_abandonment_back(
    harness: MemoryFinalizationHarness, action: str
) -> None:
    result = harness.plant_result_prestate()
    refusing = _refusing(harness, action)
    failed = harness.finalize(result.request)
    assert _code(failed) == WRITE_FAILED
    assert refusing.refusals == 1
    _assert_abandonment_rolled_back(harness, result)


# -- the timeout transaction (plan 4.5) -------------------------------------------


def _moved_past_the_deadline(
    harness: MemoryFinalizationHarness,
) -> tuple[ResultPlan, DurableState]:
    result = harness.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        harness.finalize(result.request, probe=CrashingProbe("after_moved"))
    before = harness.durable()
    harness.advance_clock(RESULT_TIMEOUT_SECONDS + 1)
    return result, before


def _assert_timeout_rolled_back(
    harness: MemoryFinalizationHarness, result: ResultPlan, before: DurableState
) -> None:
    after = harness.durable()
    assert after.journal == before.journal
    assert after.candidates == before.candidates
    assert after.run == before.run
    assert after.object_blobs == before.object_blobs
    assert after.quarantine_entries == ()
    assert after.audit_actions == before.audit_actions
    assert after.diagnostics == before.diagnostics
    assert result.roots.request_path.is_file()
    assert harness.unit_of_work.open_transactions() == ()


@pytest.mark.parametrize(
    ("owner", "method"),
    [
        pytest.param(MemoryResultLeaseRepository, "record_timeout", id="run-timeout"),
        pytest.param(
            MemoryFinalizationJournalRepository, "compare_and_swap", id="journal-swap"
        ),
        pytest.param(MemoryDiagnosticWriter, "record", id="diagnostic"),
        pytest.param(
            MemoryCandidateArtifactRepository, "compare_and_swap", id="candidate-swap"
        ),
        pytest.param(MemoryFinalizationTransaction, "commit", id="commit"),
    ],
)
def test_timeout_member_faults_leave_the_journal_and_run_for_the_next_pass(
    harness: MemoryFinalizationHarness,
    monkeypatch: pytest.MonkeyPatch,
    owner: type,
    method: str,
) -> None:
    """A storage-class refusal inside the timeout transaction -- including the
    run's ``RUNNING -> TIMED_OUT`` write itself -- rolls it back as a whole: the
    run stays RUNNING at its revision, the journal MOVED, and the next poll of
    the deadline times the attempt out."""
    result, before = _moved_past_the_deadline(harness)
    _fail_call(monkeypatch, owner, method, _write_failure())
    failed = harness.finalize(result.request)
    assert _code(failed) == WRITE_FAILED
    _assert_timeout_rolled_back(harness, result, before)
    timed_out = harness.finalize(result.request)
    assert _code(timed_out) == ARTIFACT_FINALIZATION_TIMED_OUT
    assert harness.durable().run_state == "TIMED_OUT"


@pytest.mark.parametrize("action", ["FINALIZATION_TIMED_OUT", "ARTIFACT_QUARANTINED"])
def test_timeout_audit_refusal_rolls_the_timeout_back(
    harness: MemoryFinalizationHarness, action: str
) -> None:
    result, before = _moved_past_the_deadline(harness)
    refusing = _refusing(harness, action)
    failed = harness.finalize(result.request)
    assert _code(failed) == WRITE_FAILED
    assert refusing.refusals == 1
    _assert_timeout_rolled_back(harness, result, before)


def test_timeout_skips_a_candidate_another_write_already_quarantined(
    harness: MemoryFinalizationHarness,
) -> None:
    """The timeout quarantines the FINALIZING candidates of the journal; one
    already QUARANTINED by an earlier write is left at its revision."""
    result, before = _moved_past_the_deadline(harness)
    first = result.candidates[0].candidate_artifact_id
    stored = harness.store_data.candidates[first]
    quarantined = bump_candidate(stored, _S.QUARANTINED)
    harness.store_data.candidates[first] = quarantined
    timed_out = harness.finalize(result.request)
    assert _code(timed_out) == ARTIFACT_FINALIZATION_TIMED_OUT
    after = harness.durable()
    assert after.journal_state == "ABANDONED"
    assert after.abandon_reason == ARTIFACT_FINALIZATION_TIMED_OUT
    assert all(state == "QUARANTINED" for state in after.candidate_states.values())
    assert harness.store_data.candidates[first] == quarantined  # untouched
    assert after.audit_actions.count("ARTIFACT_QUARANTINED") == 2
    assert before.journal_state == "MOVED"


# -- the phase-1 quarantine and the phase-0 quarantine transactions ---------------


@pytest.mark.parametrize(
    ("owner", "method", "call"),
    [
        pytest.param(MemoryDiagnosticWriter, "record", 1, id="diagnostic"),
        pytest.param(
            MemoryCandidateArtifactRepository, "compare_and_swap", 3, id="swap"
        ),
        pytest.param(MemoryFinalizationTransaction, "commit", 3, id="commit"),
    ],
)
def test_phase_one_quarantine_member_faults_leave_the_candidate_validating(
    harness: MemoryFinalizationHarness,
    monkeypatch: pytest.MonkeyPatch,
    owner: type,
    method: str,
    call: int,
) -> None:
    """Reading 26 at phase 1: a storage failure inside the quarantine transaction
    classifies nothing -- the failing candidate stays VALIDATING with its bytes in
    staging, no diagnostic, no audit row, no quarantine entry -- for recovery."""
    result = harness.plant_result_prestate()
    _result_staged(result, 0).write_bytes(b"tampered after declaration\n")
    _fail_call(monkeypatch, owner, method, _write_failure(), call=call)
    failed = harness.finalize(result.request)
    assert _code(failed) == WRITE_FAILED
    durable = harness.durable()
    assert all(state == "VALIDATING" for state in durable.candidate_states.values())
    assert durable.journal == ()
    assert durable.quarantine_entries == ()
    assert durable.audit_actions == ()
    assert durable.diagnostics == ()
    assert _bin_files(durable) == 2
    assert harness.unit_of_work.open_transactions() == ()


def test_phase_one_quarantine_audit_refusal_leaves_the_candidate_validating(
    harness: MemoryFinalizationHarness,
) -> None:
    result = harness.plant_result_prestate()
    _result_staged(result, 0).write_bytes(b"tampered after declaration\n")
    refusing = _refusing(harness, "ARTIFACT_CORRUPT")
    failed = harness.finalize(result.request)
    assert _code(failed) == WRITE_FAILED
    assert refusing.refusals == 1
    durable = harness.durable()
    assert all(state == "VALIDATING" for state in durable.candidate_states.values())
    assert durable.quarantine_entries == ()
    assert durable.audit_actions == ()


def test_two_corrupt_candidates_keep_the_first_refusal_as_primary(
    harness: MemoryFinalizationHarness,
) -> None:
    """Two proven mismatches, neither a leakage: both candidates are CORRUPT and
    quarantined, and the refusal returned is the first candidate's."""
    result = harness.plant_result_prestate()
    _result_staged(result, 0).write_bytes(b"tampered after declaration\n")
    _result_staged(result, 1).write_bytes(b"also tampered\n")
    refused = harness.finalize(result.request)
    assert _code(refused) == ARTIFACT_VALIDATION_FAILED
    durable = harness.durable()
    assert all(state == "CORRUPT" for state in durable.candidate_states.values())
    assert durable.audit_actions.count("ARTIFACT_CORRUPT") == 2
    assert {entry.entry_id for entry in durable.quarantine_entries} == {
        candidate.candidate_artifact_id for candidate in result.candidates
    }
    assert durable.journal == ()
    assert _bin_files(durable) == 0


def test_a_candidate_that_cannot_be_read_stays_validating(
    harness: MemoryFinalizationHarness,
) -> None:
    """Reading 26 at the hash: a candidate the store cannot open proves nothing,
    so the refusal is ``ARTIFACT.MOVE_FAILED`` and no row is classified."""
    result = harness.plant_result_prestate()
    handle = _hold_open(_result_staged(result, 0), 0)
    try:
        refused = harness.finalize(result.request)
    finally:
        _winapi.CloseHandle(handle)
    assert _code(refused) == ARTIFACT_MOVE_FAILED
    durable = harness.durable()
    assert all(state == "VALIDATING" for state in durable.candidate_states.values())
    assert durable.journal == ()
    assert durable.quarantine_entries == ()
    assert durable.audit_actions == ()
    assert _bin_files(durable) == 2


@pytest.mark.parametrize(
    ("owner", "method"),
    [
        pytest.param(MemoryDiagnosticWriter, "record", id="diagnostic"),
        pytest.param(MemoryCandidateArtifactRepository, "compare_and_swap", id="swap"),
        pytest.param(MemoryFinalizationTransaction, "commit", id="commit"),
    ],
)
def test_phase_zero_quarantine_member_faults_write_nothing(
    harness: MemoryFinalizationHarness,
    monkeypatch: pytest.MonkeyPatch,
    owner: type,
    method: str,
) -> None:
    """The phase-0 quarantine of an unconfined candidate is one transaction: a
    refused member leaves every row CANDIDATE and nothing written or moved."""
    result = harness.plant_result_prestate()
    _result_staged(result, 1).unlink()
    before = harness.durable()
    _fail_call(monkeypatch, owner, method, _write_failure())
    failed = harness.finalize(result.request)
    assert _code(failed) == WRITE_FAILED
    assert harness.durable() == before
    assert all(state == "CANDIDATE" for state in before.candidate_states.values())
    assert harness.unit_of_work.open_transactions() == ()


def test_phase_zero_quarantine_audit_refusal_writes_nothing(
    harness: MemoryFinalizationHarness,
) -> None:
    result = harness.plant_result_prestate()
    _result_staged(result, 1).unlink()
    before = harness.durable()
    refusing = _refusing(harness, "ARTIFACT_QUARANTINED")
    failed = harness.finalize(result.request)
    assert _code(failed) == WRITE_FAILED
    assert refusing.refusals == 1
    assert harness.durable() == before


@pytest.mark.parametrize(
    ("owner", "method"),
    [
        pytest.param(MemoryCandidateArtifactRepository, "compare_and_swap", id="swap"),
        pytest.param(MemoryFinalizationTransaction, "commit", id="commit"),
    ],
)
def test_validating_swap_faults_leave_the_candidate_as_it_was(
    harness: MemoryFinalizationHarness,
    monkeypatch: pytest.MonkeyPatch,
    owner: type,
    method: str,
) -> None:
    """The ``CANDIDATE -> VALIDATING`` swap of phase 1 is its own short
    transaction: refused, nothing is hashed, written or moved."""
    evidence = harness.plant_evidence_prestate()
    before = harness.durable()
    _fail_call(monkeypatch, owner, method, _write_failure())
    failed = harness.finalize(evidence.request)
    assert _code(failed) == WRITE_FAILED
    assert harness.durable() == before
    assert before.candidate_states == {
        evidence.candidates[0].candidate_artifact_id: "CANDIDATE"
    }


# -- T1 ---------------------------------------------------------------------------


def _assert_no_lease(harness: MemoryFinalizationHarness) -> None:
    durable = harness.durable()
    assert durable.journal == ()
    assert all(state == "VALIDATING" for state in durable.candidate_states.values())
    assert durable.audit_actions == ()
    assert durable.object_blobs == ()
    assert durable.run_deadline is None
    assert harness.unit_of_work.open_transactions() == ()


@pytest.mark.parametrize(
    ("owner", "method", "call"),
    [
        pytest.param(
            MemoryFinalizationJournalRepository,
            "find_evidence_identity",
            2,
            id="identity-lookup",
        ),
        pytest.param(
            MemoryCandidateArtifactRepository, "compare_and_swap", 2, id="swap"
        ),
        pytest.param(MemoryFinalizationJournalRepository, "prepare", 1, id="prepare"),
    ],
)
def test_t1_member_faults_leave_no_lease(
    harness: MemoryFinalizationHarness,
    monkeypatch: pytest.MonkeyPatch,
    owner: type,
    method: str,
    call: int,
) -> None:
    evidence = harness.plant_evidence_prestate()
    _fail_call(monkeypatch, owner, method, _write_failure(), call=call)
    failed = harness.finalize(evidence.request)
    assert _code(failed) == WRITE_FAILED
    _assert_no_lease(harness)
    assert len(harness.durable().staging_files) == 1


@pytest.mark.parametrize(
    "action", ["ARTIFACT_VALIDATED", "FINALIZATION_LEASE_ACQUIRED"]
)
def test_t1_audit_refusal_leaves_no_lease(
    harness: MemoryFinalizationHarness, action: str
) -> None:
    evidence = harness.plant_evidence_prestate()
    refusing = _refusing(harness, action)
    failed = harness.finalize(evidence.request)
    assert _code(failed) == WRITE_FAILED
    assert refusing.refusals == 1
    _assert_no_lease(harness)


@pytest.mark.parametrize(
    ("owner", "method", "call"),
    [
        pytest.param(
            MemoryResultLeaseRepository, "active_attempt_facts", 1, id="facts"
        ),
        pytest.param(
            MemoryFinalizationJournalRepository,
            "find_result_identity",
            2,
            id="identity-lookup",
        ),
    ],
)
def test_t1_result_read_faults_leave_no_lease_and_no_refusal_row(
    harness: MemoryFinalizationHarness,
    monkeypatch: pytest.MonkeyPatch,
    owner: type,
    method: str,
    call: int,
) -> None:
    """A read the RESULT branch of T1 cannot complete is the storage failure
    itself, not a lease refusal: no ``FINALIZATION_LEASE_REFUSED`` row."""
    result = harness.plant_result_prestate()
    _fail_call(monkeypatch, owner, method, _write_failure(), call=call)
    failed = harness.finalize(result.request)
    assert _code(failed) == WRITE_FAILED
    _assert_no_lease(harness)
    assert _bin_files(harness.durable()) == 2


def test_t1_deadline_snapshot_fault_is_a_lease_refusal(
    harness: MemoryFinalizationHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The run compare-and-swap that snapshots the deadline is the lease; its
    refusal is audited as ``FINALIZATION_LEASE_REFUSED`` and no journal exists."""
    result = harness.plant_result_prestate()
    _fail_call(
        monkeypatch, MemoryResultLeaseRepository, "snapshot_deadline", _write_failure()
    )
    failed = harness.finalize(result.request)
    assert _code(failed) == WRITE_FAILED
    durable = harness.durable()
    assert durable.journal == ()
    assert durable.run_deadline is None
    assert durable.run_revision == result.run.revision
    assert all(state == "VALIDATING" for state in durable.candidate_states.values())
    assert durable.audit_actions == ("FINALIZATION_LEASE_REFUSED",)
    assert durable.audit_events[-1].details["reason"] == WRITE_FAILED


class _PlantingProbe(RecordingProbe):
    """Plant a journal row right before T1 opens: the journal another process
    wrote between the phase-0 lookup and the T1 lookup."""

    def __init__(
        self, harness: MemoryFinalizationHarness, entry: FinalizationJournalEntry
    ) -> None:
        super().__init__()
        self._harness = harness
        self._entry = entry

    def before_prepared(self) -> None:
        super().before_prepared()
        self._harness.store_data.tables.journal[self._entry.finalization_id] = (
            self._entry
        )


def test_t1_refuses_a_result_journal_written_after_the_phase_zero_lookup(
    harness: MemoryFinalizationHarness,
) -> None:
    result = harness.plant_result_prestate()
    planted = sample_journal(
        _J.PREPARED,
        _F.RESULT,
        candidate_artifact_ids=[c.candidate_artifact_id for c in result.candidates],
    )
    refused = harness.finalize(result.request, probe=_PlantingProbe(harness, planted))
    assert _code(refused) == CONCURRENCY_CONFLICT
    assert "already names this attempt" in _message(refused)
    durable = harness.durable()
    assert durable.journal == (planted,)
    assert all(state == "VALIDATING" for state in durable.candidate_states.values())
    assert durable.audit_actions == ()
    assert durable.run_deadline is None


def test_t1_refuses_an_evidence_journal_written_after_the_phase_zero_lookup(
    harness: MemoryFinalizationHarness,
) -> None:
    evidence = harness.plant_evidence_prestate()
    planted = sample_journal(
        _J.PREPARED,
        _F.EVIDENCE,
        owner=RUN_OWNER,
        correlation=INVOCATION_CORRELATION,
        candidate_artifact_ids=[c.candidate_artifact_id for c in evidence.candidates],
    )
    refused = harness.finalize(evidence.request, probe=_PlantingProbe(harness, planted))
    assert _code(refused) == CONCURRENCY_CONFLICT
    assert "already names this identity" in _message(refused)
    durable = harness.durable()
    assert durable.journal == (planted,)
    assert all(state == "VALIDATING" for state in durable.candidate_states.values())
    assert durable.audit_actions == ()


# -- the lease refusals before T1 (plan 4.4, 4.7 (e)) ------------------------------


def _assert_lease_refused(
    harness: MemoryFinalizationHarness, refused: object, code: str, fragment: str
) -> None:
    assert _code(refused) == code
    assert fragment in _message(refused)
    durable = harness.durable()
    assert durable.journal == ()
    assert all(state == "VALIDATING" for state in durable.candidate_states.values())
    assert durable.audit_actions == ("FINALIZATION_LEASE_REFUSED",)
    assert durable.audit_events[-1].details["reason"] == code
    assert durable.run_deadline is None
    assert _bin_files(durable) == 2
    assert harness.unit_of_work.open_transactions() == ()


def test_lease_refused_when_the_run_revision_moved(
    harness: MemoryFinalizationHarness,
) -> None:
    result = harness.plant_result_prestate()
    stale = sample_result_request(
        [c.candidate_artifact_id for c in result.candidates],
        run=result.run,
        invocation=result.invocation,
        expected_run_revision=result.run.revision + 1,
    )
    _assert_lease_refused(
        harness, harness.finalize(stale), CONCURRENCY_CONFLICT, "is at revision"
    )


@pytest.mark.parametrize(
    ("state", "kind"),
    [
        pytest.param(CommandInvocationState.RUNNING, CommandKind.RUN, id="running"),
        pytest.param(
            CommandInvocationState.EXITED, CommandKind.VALIDATE, id="validate"
        ),
    ],
)
def test_lease_refused_when_the_invocation_is_not_the_exited_run_command(
    harness: MemoryFinalizationHarness,
    state: CommandInvocationState,
    kind: CommandKind,
) -> None:
    result = harness.plant_result_prestate()
    harness.store_data.tables.invocations[INVOCATION_ID] = sample_invocation(
        state, kind=kind
    )
    _assert_lease_refused(
        harness,
        harness.finalize(result.request),
        INVARIANT_VIOLATION,
        "not the EXITED run-command invocation",
    )


def test_lease_refused_when_the_invocation_has_no_exit_facts(
    harness: MemoryFinalizationHarness,
) -> None:
    """An EXITED row whose exit facts are absent (a raw row no production write
    produces) is refused before any lease: the finalizer never infers them."""
    result = harness.plant_result_prestate()
    exited = harness.store_data.tables.invocations[INVOCATION_ID]
    harness.store_data.tables.invocations[INVOCATION_ID] = exited.model_copy(
        update={"process_exit_category": MISSING}
    )
    _assert_lease_refused(
        harness,
        harness.finalize(result.request),
        INVARIANT_VIOLATION,
        "has no captured exit facts",
    )


def test_lease_refused_when_the_invocation_revision_moved(
    harness: MemoryFinalizationHarness,
) -> None:
    result = harness.plant_result_prestate()
    stale = sample_result_request(
        [c.candidate_artifact_id for c in result.candidates],
        run=result.run,
        invocation=result.invocation,
        expected_invocation_revision=result.invocation.revision + 1,
    )
    _assert_lease_refused(
        harness, harness.finalize(stale), CONCURRENCY_CONFLICT, "is at revision"
    )


def test_lease_refused_when_the_token_hash_is_not_the_runs(
    harness: MemoryFinalizationHarness,
) -> None:
    result = harness.plant_result_prestate()
    foreign = sample_result_request(
        [c.candidate_artifact_id for c in result.candidates],
        run=result.run,
        invocation=result.invocation,
        attempt_token_hash="c" * 64,
    )
    _assert_lease_refused(
        harness,
        harness.finalize(foreign),
        INVARIANT_VIOLATION,
        "attempt token hash is not the run's",
    )


def test_lease_refused_when_a_later_attempt_exists(
    harness: MemoryFinalizationHarness,
) -> None:
    result = harness.plant_result_prestate()
    harness.store_data.tables.runs[OTHER_RUN_ID] = sample_run(
        EngineRunState.RUNNING,
        run_id=OTHER_RUN_ID,
        attempt_number=2,
        predecessor_run_id=RUN_ID,
    )
    _assert_lease_refused(
        harness,
        harness.finalize(result.request),
        INVARIANT_VIOLATION,
        "not the latest attempt",
    )


def test_lease_refused_when_the_experiment_is_not_running(
    harness: MemoryFinalizationHarness,
) -> None:
    result = harness.plant_result_prestate()
    harness.store_data.tables.experiments[EXPERIMENT_ID] = ExperimentState.COMPLETED
    _assert_lease_refused(
        harness,
        harness.finalize(result.request),
        INVARIANT_VIOLATION,
        "is not RUNNING",
    )


def test_lease_refused_when_the_invocation_is_not_the_active_run_command(
    harness: MemoryFinalizationHarness,
) -> None:
    result = harness.plant_result_prestate()
    harness.store_data.tables.invocations[INVOCATION_ID] = sample_invocation(
        CommandInvocationState.EXITED, request_hash=OTHER_REQUEST_HASH
    )
    _assert_lease_refused(
        harness,
        harness.finalize(result.request),
        INVARIANT_VIOLATION,
        "not the active run-command",
    )


#: The row reads of the T1 lease check, counted from the start of ``finalize``:
#: the phase-1 association read of the ruling of 2026-11-09 (the run row, before
#: any swap; a RESULT reads no invocation there) precedes the memory lease
#: repository's own run read and the check's run read, so the check's run read is
#: the third ``engine_runs.get`` and its invocation read the first
#: ``command_invocations.get``.
@pytest.mark.parametrize(
    ("owner", "method", "call"),
    [
        pytest.param(MemoryEngineRunRecords, "get", 3, id="run"),
        pytest.param(MemoryCommandInvocationRecords, "get", 1, id="invocation"),
    ],
)
def test_lease_refused_when_the_row_reads_of_the_check_fail(
    harness: MemoryFinalizationHarness,
    monkeypatch: pytest.MonkeyPatch,
    owner: type,
    method: str,
    call: int,
) -> None:
    result = harness.plant_result_prestate()
    _fail_call(monkeypatch, owner, method, _write_failure(), call=call)
    _assert_lease_refused(
        harness,
        harness.finalize(result.request),
        WRITE_FAILED,
        "could not be committed",
    )


def test_lease_refusal_whose_audit_fails_answers_the_audit_failure(
    harness: MemoryFinalizationHarness,
) -> None:
    result = harness.plant_result_prestate()
    harness.store_data.tables.experiments[EXPERIMENT_ID] = ExperimentState.COMPLETED
    refusing = _refusing(harness, "FINALIZATION_LEASE_REFUSED")
    failed = harness.finalize(result.request)
    assert _code(failed) == WRITE_FAILED
    assert refusing.refusals == 1
    durable = harness.durable()
    assert durable.journal == ()
    assert durable.audit_actions == ()


# -- T2 and the in-place re-hash (reading 18) ---------------------------------------


def _assert_still_prepared(
    harness: MemoryFinalizationHarness, blobs: int
) -> DurableState:
    durable = harness.durable()
    assert durable.journal_state == "PREPARED"
    assert len(durable.object_blobs) == blobs
    assert "FINALIZATION_MOVED" not in durable.audit_actions
    assert durable.audit_actions[-1] == "FINALIZATION_PREPARED"
    assert durable.refs == ()
    assert harness.unit_of_work.open_transactions() == ()
    return durable


def test_t2_journal_swap_fault_leaves_the_prepared_journal(
    harness: MemoryFinalizationHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = harness.plant_evidence_prestate()
    _fail_call(
        monkeypatch,
        MemoryFinalizationJournalRepository,
        "compare_and_swap",
        _write_failure(),
    )
    failed = harness.finalize(evidence.request)
    assert _code(failed) == WRITE_FAILED
    _assert_still_prepared(harness, blobs=1)


def test_t2_audit_refusal_leaves_the_prepared_journal(
    harness: MemoryFinalizationHarness,
) -> None:
    evidence = harness.plant_evidence_prestate()
    refusing = _refusing(harness, "FINALIZATION_MOVED")
    failed = harness.finalize(evidence.request)
    assert _code(failed) == WRITE_FAILED
    assert refusing.refusals == 1
    _assert_still_prepared(harness, blobs=1)


class _BeforeMovedProbe(RecordingProbe):
    """Disturb the moved blob at ``before_moved``, between the move and T2's
    in-place re-hash."""

    def __init__(self, action: Callable[[], object]) -> None:
        super().__init__()
        self._action = action

    def before_moved(self) -> None:
        super().before_moved()
        self._action()


def _evidence_blob(harness: MemoryFinalizationHarness) -> Path:
    return harness.roots.store.finalized_path_for(
        sha256_bytes(EVIDENCE_FILES["stderr.txt"])
    )


def test_moved_blob_that_vanished_before_the_rehash_abandons(
    harness: MemoryFinalizationHarness,
) -> None:
    evidence = harness.plant_evidence_prestate()
    blob = _evidence_blob(harness)
    refused = harness.finalize(
        evidence.request, probe=_BeforeMovedProbe(lambda: blob.unlink())
    )
    assert _code(refused) == ARTIFACT_VALIDATION_FAILED
    assert "could not be re-read in place" in _message(refused)
    durable = harness.durable()
    assert durable.journal_state == "ABANDONED"
    assert durable.abandon_reason == ARTIFACT_VALIDATION_FAILED
    assert durable.object_blobs == ()
    assert all(state == "QUARANTINED" for state in durable.candidate_states.values())


def test_moved_blob_that_cannot_be_reread_abandons_as_a_storage_failure(
    harness: MemoryFinalizationHarness,
) -> None:
    evidence = harness.plant_evidence_prestate()
    blob = _evidence_blob(harness)
    handles: list[int] = []
    try:
        refused = harness.finalize(
            evidence.request,
            probe=_BeforeMovedProbe(lambda: handles.append(_hold_open(blob, 0))),
        )
    finally:
        for handle in handles:
            _winapi.CloseHandle(handle)
    assert _code(refused) == ARTIFACT_MOVE_FAILED
    durable = harness.durable()
    assert durable.journal_state == "ABANDONED"
    assert durable.abandon_reason == ARTIFACT_MOVE_FAILED
    # The held blob could not be quarantined either; it is swept by RV-9 later.
    assert len(durable.object_blobs) == 1
    assert all(state == "QUARANTINED" for state in durable.candidate_states.values())


def test_moved_blob_rewritten_before_the_rehash_abandons(
    harness: MemoryFinalizationHarness,
) -> None:
    evidence = harness.plant_evidence_prestate()
    blob = _evidence_blob(harness)
    refused = harness.finalize(
        evidence.request,
        probe=_BeforeMovedProbe(lambda: blob.write_bytes(b"rewritten in place\n")),
    )
    assert _code(refused) == ARTIFACT_VALIDATION_FAILED
    assert "differs from the planned facts" in _message(refused)
    durable = harness.durable()
    assert durable.journal_state == "ABANDONED"
    assert durable.object_blobs == ()
    (entry,) = durable.quarantine_entries
    assert len(entry.files) == 1


def test_deadline_passing_between_the_moves_and_t2_times_out(
    harness: MemoryFinalizationHarness,
) -> None:
    """Plan 4.3 phase 4's poll: the deadline passed after the last move and
    before the MOVED write is the timeout, never MOVED."""
    result = harness.plant_result_prestate()
    timed_out = harness.finalize(
        result.request,
        probe=_BeforeMovedProbe(
            lambda: harness.advance_clock(RESULT_TIMEOUT_SECONDS + 1)
        ),
    )
    assert _code(timed_out) == ARTIFACT_FINALIZATION_TIMED_OUT
    durable = harness.durable()
    assert durable.journal_state == "ABANDONED"
    assert durable.abandon_reason == ARTIFACT_FINALIZATION_TIMED_OUT
    assert durable.run_state == "TIMED_OUT"
    assert "FINALIZATION_MOVED" not in durable.audit_actions
    assert durable.object_blobs == ()
    assert harness.registrar.result_calls == 0


# -- T3 ---------------------------------------------------------------------------


def _assert_still_moved_for_recovery(harness: MemoryFinalizationHarness) -> None:
    durable = harness.durable()
    assert durable.journal_state == "MOVED"
    assert durable.refs == ()
    assert durable.run_artifacts == ()
    assert tuple(harness.roots.store.manifests_root.glob("*.json")) == ()
    assert "FINALIZATION_REGISTERED" not in durable.audit_actions
    assert durable.audit_actions[-1] == "FINALIZATION_MOVED"
    assert harness.unit_of_work.open_transactions() == ()


@pytest.mark.parametrize(
    ("owner", "method", "call"),
    [
        pytest.param(MemoryArtifactRepository, "stage_reference", 1, id="stage"),
        pytest.param(MemoryRunArtifactRepository, "link", 1, id="registrar-link"),
        pytest.param(
            MemoryFinalizationJournalRepository, "compare_and_swap", 2, id="swap"
        ),
    ],
)
def test_t3_evidence_member_faults_leave_the_journal_moved(
    harness: MemoryFinalizationHarness,
    monkeypatch: pytest.MonkeyPatch,
    owner: type,
    method: str,
    call: int,
) -> None:
    evidence = harness.plant_evidence_prestate()
    _fail_call(monkeypatch, owner, method, _write_failure(), call=call)
    failed = harness.finalize(evidence.request)
    assert _code(failed) == WRITE_FAILED
    _assert_still_moved_for_recovery(harness)
    assert len(harness.durable().object_blobs) == 1


def test_t3_result_facts_fault_leaves_the_journal_moved(
    harness: MemoryFinalizationHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = harness.plant_result_prestate()
    _fail_call(
        monkeypatch,
        MemoryResultLeaseRepository,
        "active_attempt_facts",
        _write_failure(),
        call=2,
    )
    failed = harness.finalize(result.request)
    assert _code(failed) == WRITE_FAILED
    _assert_still_moved_for_recovery(harness)
    assert harness.registrar.result_calls == 0
    assert result.roots.request_path.is_file()


def test_run_moved_before_registration_abandons_as_superseded(
    harness: MemoryFinalizationHarness,
) -> None:
    """Plan 4.4 step 3 and reading 1: the run that moved between T1 and T3 is
    another winner's; the registration is refused and the journal
    ``ABANDONED(SUPERSEDED)`` -- the stored conflict code."""
    result = harness.plant_result_prestate()

    def cancel_run() -> None:
        current = harness.store_data.tables.runs[RUN_ID]
        harness.store_data.tables.runs[RUN_ID] = sample_run(
            EngineRunState.CANCELLED, revision=current.revision + 1
        )

    refused = harness.finalize(result.request, probe=_BeforeMovedProbe(cancel_run))
    assert _code(refused) == CONCURRENCY_CONFLICT
    assert "before registration" in _message(refused)
    durable = harness.durable()
    assert durable.journal_state == "ABANDONED"
    assert durable.abandon_reason == CONCURRENCY_CONFLICT
    assert durable.run_state == "CANCELLED"
    assert harness.registrar.result_calls == 0


def test_resumed_journal_whose_candidate_lost_its_media_abandons(
    harness: MemoryFinalizationHarness,
) -> None:
    """The references are built from the observed facts and the candidate row;
    a row that no longer names an admitted media type is the invariant and the
    journal is abandoned under it."""
    evidence = harness.plant_evidence_prestate()
    (candidate,) = evidence.candidates
    with pytest.raises(FinalizationCrash):
        harness.finalize(evidence.request, probe=CrashingProbe("after_moved"))
    identity = candidate.candidate_artifact_id
    stored = harness.store_data.candidates[identity]
    harness.store_data.candidates[identity] = stored.model_copy(
        update={"artifact_kind": "unknown-kind"}
    )
    harness.advance_clock(EVIDENCE_LEASE_SECONDS + 1)
    report = _ok(harness.recover())
    assert (report.resumed, report.abandoned, report.registered) == (1, 1, 0)
    durable = harness.durable()
    assert durable.journal_state == "ABANDONED"
    assert durable.abandon_reason == INVARIANT_VIOLATION
    assert durable.refs == ()
    assert durable.object_blobs == ()


# -- phase 0: the lookup, the replay and the candidate checks ----------------------


@pytest.mark.parametrize(
    ("owner", "method"),
    [
        pytest.param(
            MemoryFinalizationJournalRepository, "find_evidence_identity", id="lookup"
        ),
        pytest.param(MemoryCandidateArtifactRepository, "get", id="candidate"),
    ],
)
def test_phase_zero_read_faults_write_nothing(
    harness: MemoryFinalizationHarness,
    monkeypatch: pytest.MonkeyPatch,
    owner: type,
    method: str,
) -> None:
    evidence = harness.plant_evidence_prestate()
    before = harness.durable()
    _fail_call(monkeypatch, owner, method, _write_failure())
    failed = harness.finalize(evidence.request)
    assert _code(failed) == WRITE_FAILED
    assert harness.durable() == before
    assert harness.unit_of_work.open_transactions() == ()


def test_an_abandoned_identity_is_refused_as_a_conflict(
    harness: MemoryFinalizationHarness,
) -> None:
    result = harness.plant_result_prestate()
    assert _code(harness.finalize(result.request)) == INVARIANT_VIOLATION
    before = harness.durable()
    assert before.journal_state == "ABANDONED"
    again = harness.finalize(result.request)
    assert _code(again) == CONCURRENCY_CONFLICT
    assert "was abandoned" in _message(again)
    assert harness.durable() == before


def test_replay_whose_audit_fails_answers_the_failure(
    harness: MemoryFinalizationHarness,
) -> None:
    evidence = harness.plant_evidence_prestate()
    _ok(harness.finalize(evidence.request))
    before = harness.durable()
    refusing = _refusing(harness, "FINALIZATION_REPLAYED")
    failed = harness.finalize(evidence.request)
    assert _code(failed) == WRITE_FAILED
    assert refusing.refusals == 1
    assert harness.durable() == before


def _plant_registered_result_journal(
    harness: MemoryFinalizationHarness, result: ResultPlan
) -> FinalizationJournalEntry:
    """A RESULT journal that reached REGISTERED (the Task 7 registrar's durable
    outcome), written through the journal's own transitions."""
    entry = sample_journal(
        _J.PREPARED,
        _F.RESULT,
        candidate_artifact_ids=[c.candidate_artifact_id for c in result.candidates],
    )
    transaction = harness.unit_of_work.begin()
    _ok(transaction.finalization_journal.prepare(entry))
    moved = _ok(
        transaction.finalization_journal.compare_and_swap(
            entry.revision, bump_journal(entry, _J.MOVED)
        )
    )
    registered = _ok(
        transaction.finalization_journal.compare_and_swap(
            moved.revision, bump_journal(moved, _J.REGISTERED)
        )
    )
    _ok(transaction.commit())
    return registered


@dataclass(frozen=True, slots=True, kw_only=True)
class _RunManifestFacts:
    """The ``run_manifests`` row as facts (the ports' read-only view)."""

    manifest_id: str
    run_id: str
    experiment_id: str
    run_invocation_id: str
    attempt_token_hash: str
    sanitized_adapter_result_manifest_hash: str
    semantic_status: str
    process_exit_category: str
    manifest_json: str
    run_manifest_hash: str
    registered_at_utc: datetime


def test_result_replay_returns_the_stored_result_with_its_run_manifest(
    harness: MemoryFinalizationHarness,
) -> None:
    """A REGISTERED RESULT journal replays the stored result carrying the run
    manifest facts of its row (plan 3.1), audited once as a replay."""
    result = harness.plant_result_prestate()
    registered = _plant_registered_result_journal(harness, result)
    harness.store_data.tables.run_manifests[RUN_ID] = _RunManifestFacts(
        manifest_id=RUN_MANIFEST_ID,
        run_id=RUN_ID,
        experiment_id=EXPERIMENT_ID,
        run_invocation_id=INVOCATION_ID,
        attempt_token_hash=ATTEMPT_TOKEN_HASH,
        sanitized_adapter_result_manifest_hash=SANITIZED_MANIFEST_HASH,
        semantic_status="SUCCEEDED",
        process_exit_category="SUCCESS",
        manifest_json="{}",
        run_manifest_hash=RUN_MANIFEST_HASH,
        registered_at_utc=INSTANT,
    )
    replayed = _ok(harness.finalize(result.request))
    assert replayed.replayed is True
    assert replayed.finalization_id == registered.finalization_id
    assert replayed.journal_state == "REGISTERED"
    assert replayed.run_manifest_id == RUN_MANIFEST_ID
    assert replayed.run_manifest_hash == RUN_MANIFEST_HASH
    assert len(replayed.candidate_to_artifact_refs) == 2
    assert harness.durable().audit_actions == ("FINALIZATION_REPLAYED",)


def test_result_replay_requires_the_run_manifest(
    harness: MemoryFinalizationHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A REGISTERED RESULT journal replays its stored result with the run
    manifest facts (plan 3.1); a missing row is the invariant and a refused read
    is the storage failure."""
    result = harness.plant_result_prestate()
    _plant_registered_result_journal(harness, result)
    before = harness.durable()
    assert before.journal_state == "REGISTERED"
    refused = harness.finalize(result.request)
    assert _code(refused) == INVARIANT_VIOLATION
    assert "requires its run manifest" in _message(refused)
    assert harness.durable() == before
    _fail_call(monkeypatch, MemoryRunManifestRepository, "get", _write_failure())
    failed = harness.finalize(result.request)
    assert _code(failed) == WRITE_FAILED
    assert harness.durable() == before


def test_result_without_its_run_root_is_refused_before_io(
    harness: MemoryFinalizationHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = harness.plant_result_prestate()
    before = harness.durable()
    monkeypatch.setattr(harness, "command_roots", lambda invocation_id: MISSING)
    refused = harness.finalize(result.request)
    assert _code(refused) == INVARIANT_VIOLATION
    assert "requires the RUN root" in _message(refused)
    assert harness.durable() == before


def test_result_without_token_material_is_refused_before_any_swap(
    harness: MemoryFinalizationHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = harness.plant_result_prestate()
    before = harness.durable()
    monkeypatch.setattr(harness, "token_material", lambda invocation_id: MISSING)
    refused = harness.finalize(result.request)
    assert _code(refused) == INVARIANT_VIOLATION
    assert "attempt token material" in _message(refused)
    assert harness.durable() == before


def test_describe_lookup_fault_writes_nothing(
    harness: MemoryFinalizationHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness.plant_run()
    candidates = plant_core_evidence(
        harness.roots.store, owner=ADAPTER_OWNER, correlation=INVOCATION_CORRELATION
    )
    for candidate in candidates:
        harness.store_data.candidates[candidate.candidate_artifact_id] = candidate
    request = sample_evidence_request(
        [candidate.candidate_artifact_id for candidate in candidates],
        owner=ADAPTER_OWNER,
        correlation=INVOCATION_CORRELATION,
    )
    before = harness.durable()
    _fail_call(monkeypatch, MemoryCommandInvocationRecords, "get", _write_failure())
    failed = harness.finalize(request)
    assert _code(failed) == WRITE_FAILED
    assert harness.durable() == before


def test_result_request_over_an_evidence_candidate_is_refused(
    harness: MemoryFinalizationHarness,
) -> None:
    evidence = harness.plant_evidence_prestate()
    result = harness.plant_result_prestate()
    mixed = sample_result_request(
        [c.candidate_artifact_id for c in evidence.candidates],
        run=result.run,
        invocation=result.invocation,
    )
    before = harness.durable()
    refused = harness.finalize(mixed)
    assert _code(refused) == ARTIFACT_VALIDATION_FAILED
    assert "purpose differs" in _message(refused)
    assert harness.durable() == before


def test_evidence_request_with_another_role_than_the_candidate_is_refused(
    harness: MemoryFinalizationHarness,
) -> None:
    harness.plant_run()
    describe = sample_invocation(
        CommandInvocationState.EXITED,
        kind=CommandKind.DESCRIBE,
        invocation_id=OTHER_INVOCATION_ID,
    )
    harness.store_data.tables.invocations[OTHER_INVOCATION_ID] = describe
    correlation = EvidenceCorrelation(
        kind="INVOCATION", invocation_id=OTHER_INVOCATION_ID
    )
    candidates = plant_core_evidence(
        harness.roots.store, owner=ADAPTER_OWNER, correlation=correlation
    )
    for candidate in candidates:
        harness.store_data.candidates[candidate.candidate_artifact_id] = candidate
    request = sample_evidence_request(
        [candidate.candidate_artifact_id for candidate in candidates],
        owner=ADAPTER_OWNER,
        correlation=correlation,
        source_role=ArtifactSourceRole.ADAPTER_DESCRIPTOR_EVIDENCE,
    )
    before = harness.durable()
    refused = harness.finalize(request)
    assert _code(refused) == ARTIFACT_VALIDATION_FAILED
    assert "role differs" in _message(refused)
    assert harness.durable() == before


@pytest.mark.parametrize(
    ("states", "code", "fragment"),
    [
        pytest.param(
            (_S.QUARANTINED,), ARTIFACT_VALIDATION_FAILED, "is terminal", id="terminal"
        ),
        pytest.param(
            (_S.VALIDATING, _S.FINALIZING),
            INVARIANT_VIOLATION,
            "without an open journal",
            id="finalizing",
        ),
    ],
)
def test_terminal_or_orphaned_finalizing_candidates_are_refused(
    harness: MemoryFinalizationHarness,
    states: tuple[CandidateArtifactState, ...],
    code: str,
    fragment: str,
) -> None:
    evidence = harness.plant_evidence_prestate()
    (candidate,) = evidence.candidates
    stored = candidate
    for state in states:
        stored = bump_candidate(stored, state)
    harness.store_data.candidates[candidate.candidate_artifact_id] = stored
    before = harness.durable()
    refused = harness.finalize(evidence.request)
    assert _code(refused) == code
    assert fragment in _message(refused)
    assert harness.durable() == before


def test_core_kind_without_an_admitted_media_type_is_quarantined(
    harness: MemoryFinalizationHarness,
) -> None:
    harness.plant_run()
    candidates = plant_core_evidence(
        harness.roots.store,
        owner=RUN_OWNER,
        correlation=INVOCATION_CORRELATION,
        artifact_kind="unknown-kind",
    )
    for candidate in candidates:
        harness.store_data.candidates[candidate.candidate_artifact_id] = candidate
    request = sample_evidence_request(
        [candidate.candidate_artifact_id for candidate in candidates],
        owner=RUN_OWNER,
        correlation=INVOCATION_CORRELATION,
    )
    refused = harness.finalize(request)
    assert _code(refused) == ARTIFACT_VALIDATION_FAILED
    assert "no admitted media type" in _message(refused)
    durable = harness.durable()
    (quarantined,) = durable.candidates
    assert quarantined.state is _S.QUARANTINED
    assert quarantined.validation_observations[-1].stage == "MEDIA"
    assert durable.staging_files == ()
    assert [entry.entry_id for entry in durable.quarantine_entries] == [
        candidates[0].candidate_artifact_id
    ]
    assert durable.journal == ()


def test_system_owner_diagnostic_evidence_resumes_from_a_moved_journal(
    harness: MemoryFinalizationHarness,
) -> None:
    """A resumed EVIDENCE journal of a non-RUN owner under a DIAGNOSTIC
    correlation derives no invocation correlation at all and registers."""
    evidence = harness.plant_evidence_prestate(
        owner=SYSTEM_OWNER, correlation=DIAGNOSTIC_CORRELATION
    )
    with pytest.raises(FinalizationCrash):
        harness.finalize(evidence.request, probe=CrashingProbe("after_moved"))
    harness.advance_clock(EVIDENCE_LEASE_SECONDS + 1)
    report = _ok(harness.recover())
    assert (report.resumed, report.registered) == (1, 1)
    durable = harness.durable()
    (ref,) = durable.refs
    assert ref.owner == SYSTEM_OWNER
    assert durable.run_artifacts == ()


def test_run_owner_without_an_invocation_registers_and_resumes(
    harness: MemoryFinalizationHarness,
) -> None:
    """A RUN owner whose attempt has no invocation yet (a DIAGNOSTIC-correlated
    evidence set): the manifest lineage names the experiment and the run only,
    and a resumed journal of that shape derives its correlation the same way."""
    evidence = harness.plant_evidence_prestate(
        owner=RUN_OWNER_WITHOUT_INVOCATION, correlation=DIAGNOSTIC_CORRELATION
    )
    with pytest.raises(FinalizationCrash):
        harness.finalize(evidence.request, probe=CrashingProbe("after_moved"))
    harness.advance_clock(EVIDENCE_LEASE_SECONDS + 1)
    report = _ok(harness.recover())
    assert (report.resumed, report.registered) == (1, 1)
    durable = harness.durable()
    (ref,) = durable.refs
    assert ref.owner == RUN_OWNER_WITHOUT_INVOCATION
    manifest = harness.store_data.refs[ref.artifact_id][1]
    assert manifest.lineage.run_id == RUN_ID
    assert not isinstance(manifest.lineage.invocation_id, str)
    assert len(durable.run_artifacts) == 1


# -- the lease close and the remaining bytes ----------------------------------------


def test_deduplicated_move_leaves_the_shared_blob_alone_on_abandonment(
    harness: MemoryFinalizationHarness,
) -> None:
    """Reading 21: two candidates with equal bytes share one blob; the second
    move deduplicates, and the abandonment quarantines the blob once -- the
    deduplicated move owns nothing to quarantine."""
    data = b"identical native result bytes\n" * 2
    result = harness.plant_result_prestate(
        files={"results/first.bin": data, "results/second.bin": data}
    )
    refused = harness.finalize(result.request)
    assert _code(refused) == INVARIANT_VIOLATION
    durable = harness.durable()
    assert durable.journal_state == "ABANDONED"
    (entry,) = durable.journal
    assert sorted(move.deduplicated for move in entry.observed) == [False, True]
    assert durable.object_blobs == ()
    (quarantine,) = durable.quarantine_entries
    assert len(quarantine.files) == 1
    assert all(state == "QUARANTINED" for state in durable.candidate_states.values())


class _BeforeRegisteredProbe(RecordingProbe):
    def __init__(self, action: Callable[[], object]) -> None:
        super().__init__()
        self._action = action

    def before_registered(self) -> None:
        super().before_registered()
        self._action()


def test_a_blob_gone_before_abandonment_is_skipped_by_the_quarantine(
    harness: MemoryFinalizationHarness,
) -> None:
    result = harness.plant_result_prestate()
    blob = harness.roots.store.finalized_path_for(
        str(result.candidates[0].adapter_declared_hash)
    )
    refused = harness.finalize(
        result.request, probe=_BeforeRegisteredProbe(lambda: blob.unlink())
    )
    assert _code(refused) == INVARIANT_VIOLATION
    durable = harness.durable()
    assert durable.journal_state == "ABANDONED"
    assert durable.object_blobs == ()
    (quarantine,) = durable.quarantine_entries
    assert len(quarantine.files) == 1


def test_close_result_lease_refuses_an_open_or_evidence_journal(
    harness: MemoryFinalizationHarness,
) -> None:
    result = harness.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        harness.finalize(result.request, probe=CrashingProbe("after_prepared"))
    (prepared,) = harness.durable().journal
    evidence = sample_journal(_J.REGISTERED, _F.EVIDENCE)
    for journal in (prepared, evidence):
        refused = close_result_lease(
            journal,
            result.roots,
            store=harness.roots.store,
            unit_of_work_factory=harness.unit_of_work.begin,
            auditor=harness.auditor,
            clock=harness.clock,
        )
        assert _code(refused) == INVARIANT_VIOLATION
        assert "closes its command root" in _message(refused)
    assert result.roots.request_path.is_file()


def test_close_result_lease_commit_failure_is_answered_after_the_removal(
    harness: MemoryFinalizationHarness,
) -> None:
    """The removal is a filesystem fact the transaction cannot undo: a refused
    commit answers the failure, the bytes are gone and no audit row exists."""
    result = harness.plant_result_prestate()
    assert _code(harness.finalize(result.request)) == INVARIANT_VIOLATION
    (abandoned,) = harness.durable().journal
    before = harness.durable()
    result.roots.request_path.write_bytes(b'{"recreated": true}')
    harness.unit_of_work.fail_next_committed(_write_failure())
    failed = close_result_lease(
        abandoned,
        result.roots,
        store=harness.roots.store,
        unit_of_work_factory=harness.unit_of_work.begin,
        auditor=harness.auditor,
        clock=harness.clock,
    )
    assert _code(failed) == WRITE_FAILED
    assert not result.roots.request_path.exists()
    assert harness.durable().audit_actions == before.audit_actions
    assert harness.unit_of_work.open_transactions() == ()


def test_close_raw_bytes_refuses_a_foreign_paths_object(
    harness: MemoryFinalizationHarness,
) -> None:
    transaction = harness.unit_of_work.begin()
    try:
        with pytest.raises(TypeError, match="CommandRootPaths"):
            close_raw_bytes(
                "not paths",  # type: ignore[arg-type]
                store=harness.roots.store,
                unit_of_work=transaction,
                auditor=harness.auditor,
                correlation=OTHER_INVOCATION_ID,
                clock=harness.clock,
            )
    finally:
        transaction.rollback()
    assert harness.durable().audit_actions == ()


def test_close_raw_bytes_retains_a_raw_path_that_is_a_directory(
    harness: MemoryFinalizationHarness,
) -> None:
    """A raw-bearing path that is a directory is never removed or moved: the
    removal fails, the confinement refuses it and the close retains it, audited
    as a failed deletion and a failed quarantine."""
    root = harness.roots.runtime_root / OTHER_INVOCATION_ID
    root.mkdir()
    request_path = root / "request.json"
    request_path.mkdir()
    output_path = root / "output.json"
    output_path.write_bytes(b'{"typed": "output"}')
    roots = CommandRootPaths(
        command_root=root, request_path=request_path, output_path=output_path
    )
    transaction = harness.unit_of_work.begin()
    closed = _ok(
        close_raw_bytes(
            roots,
            store=harness.roots.store,
            unit_of_work=transaction,
            auditor=harness.auditor,
            correlation=OTHER_INVOCATION_ID,
            clock=harness.clock,
        )
    )
    _ok(transaction.commit())
    assert (closed.removed, closed.missing, closed.quarantined, closed.retained) == (
        1,
        0,
        0,
        1,
    )
    assert request_path.is_dir()
    assert not output_path.exists()
    durable = harness.durable()
    assert durable.audit_actions == ("RETENTION_DELETED", "ARTIFACT_QUARANTINED")
    assert [event.outcome.value for event in durable.audit_events] == [
        "FAILED",
        "FAILED",
    ]


def test_close_raw_bytes_quarantine_audit_refusal_is_answered(
    harness: MemoryFinalizationHarness,
) -> None:
    root = harness.roots.runtime_root / OTHER_INVOCATION_ID
    root.mkdir()
    request_path = root / "request.json"
    request_path.write_bytes(b'{"held": true}')
    roots = CommandRootPaths(
        command_root=root, request_path=request_path, output_path=root / "output.json"
    )
    refusing = _refusing(harness, "ARTIFACT_QUARANTINED")
    handle = _hold_open(request_path, 0)
    try:
        transaction = harness.unit_of_work.begin()
        failed = close_raw_bytes(
            roots,
            store=harness.roots.store,
            unit_of_work=transaction,
            auditor=refusing,
            correlation=OTHER_INVOCATION_ID,
            clock=harness.clock,
        )
        transaction.rollback()
    finally:
        _winapi.CloseHandle(handle)
    assert _code(failed) == WRITE_FAILED
    assert refusing.refusals == 1
    assert request_path.is_file()
    assert harness.durable().audit_actions == ()


# -- the constructor, the request type, the late cancellation, the resume guard ---


def test_constructor_refuses_foreign_collaborators(
    harness: MemoryFinalizationHarness,
) -> None:
    good: dict[str, Any] = {
        "unit_of_work_factory": harness.unit_of_work.begin,
        "clock": harness.clock,
        "hasher": harness.hasher,
        "store": harness.roots.store,
        "probe": NoProbe(),
        "registrar": harness.registrar,
        "auditor": harness.auditor,
    }
    for name, expected in (
        ("store", "ArtifactStore"),
        ("hasher", "ContentHasher"),
        ("probe", "FinalizationProbe"),
        ("unit_of_work_factory", "callable"),
    ):
        arguments = dict(good)
        arguments[name] = object()
        with pytest.raises(TypeError, match=expected):
            CoreArtifactFinalizer(
                arguments["unit_of_work_factory"],
                arguments["clock"],
                arguments["hasher"],
                arguments["store"],
                arguments["probe"],
                arguments["registrar"],
                arguments["auditor"],
                command_roots=harness.command_roots,
                token_material=harness.token_material,
            )


def test_finalize_refuses_a_foreign_request(
    harness: MemoryFinalizationHarness,
) -> None:
    before = harness.durable()
    refused = run_coroutine(
        harness.finalizer().finalize(
            "not a request",  # type: ignore[arg-type]
            FlagCancellationToken(),
        )
    )
    assert _code(refused) == INVARIANT_VIOLATION
    assert "ResultFinalizationRequest" in _message(refused)
    assert harness.durable() == before


class _LateCancellation:
    """Cancellation requested at the second poll: after phase 0, before phase 1."""

    def __init__(self) -> None:
        self.polls = 0

    def is_cancellation_requested(self) -> bool:
        self.polls += 1
        return self.polls >= 2

    def request_cancellation(self) -> None:
        return None


def test_cancellation_at_the_phase_one_poll_refuses_before_any_swap(
    harness: MemoryFinalizationHarness,
) -> None:
    evidence = harness.plant_evidence_prestate()
    before = harness.durable()
    token = _LateCancellation()
    refused = run_coroutine(
        harness.finalizer(RecordingProbe()).finalize(evidence.request, token)
    )
    assert _code(refused) == PROCESS_CANCELLED
    assert token.polls == 2
    assert harness.durable() == before


def test_resume_journal_refuses_a_terminal_entry(
    harness: MemoryFinalizationHarness,
) -> None:
    result = harness.plant_result_prestate()
    assert _code(harness.finalize(result.request)) == INVARIANT_VIOLATION
    (abandoned,) = harness.durable().journal
    before = harness.durable()
    refused = harness.finalizer().resume_journal(abandoned)
    assert _code(refused) == INVARIANT_VIOLATION
    assert "is not open" in _message(refused)
    assert harness.durable() == before


def test_resume_journal_read_faults_leave_the_journal_as_stored(
    harness: MemoryFinalizationHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = harness.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        harness.finalize(result.request, probe=CrashingProbe("after_prepared"))
    before = harness.durable()
    (prepared,) = before.journal
    harness.advance_clock(RESULT_LEASE_SECONDS + 1)
    _fail_call(monkeypatch, MemoryCandidateArtifactRepository, "get", _write_failure())
    failed = harness.finalizer().resume_journal(prepared)
    assert _code(failed) == WRITE_FAILED
    assert harness.durable() == before
    monkeypatch.undo()
    monkeypatch.setattr(harness, "command_roots", lambda invocation_id: MISSING)
    unlocated = harness.finalizer().resume_journal(prepared)
    assert _code(unlocated) == INVARIANT_VIOLATION
    assert "requires the RUN root" in _message(unlocated)
    assert harness.durable() == before


# -- the revalidation of a PREPARED journal (CP-2 and CP-3 recovery) ---------------


def _prepared_after_the_lease(
    harness: MemoryFinalizationHarness, point: str, index: int = 0
) -> tuple[ResultPlan, FinalizationJournalEntry]:
    result = harness.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        harness.finalize(result.request, probe=CrashingProbe(point, index))
    (prepared,) = harness.durable().journal
    assert prepared.state is _J.PREPARED
    harness.advance_clock(RESULT_LEASE_SECONDS + 1)
    return result, prepared


def test_staged_candidate_that_cannot_be_read_abandons_the_resumed_journal(
    harness: MemoryFinalizationHarness,
) -> None:
    result, _ = _prepared_after_the_lease(harness, "after_prepared")
    handle = _hold_open(_result_staged(result, 0), 0)
    try:
        refused = harness.finalize(result.request)
    finally:
        _winapi.CloseHandle(handle)
    assert _code(refused) == ARTIFACT_MOVE_FAILED
    durable = harness.durable()
    assert durable.journal_state == "ABANDONED"
    assert durable.abandon_reason == ARTIFACT_MOVE_FAILED
    assert all(state == "QUARANTINED" for state in durable.candidate_states.values())
    assert durable.object_blobs == ()
    assert durable.run_state == "RUNNING"  # the caller owns the FAILED write


def test_resumed_prepared_journal_whose_move_is_refused_abandons(
    harness: MemoryFinalizationHarness,
) -> None:
    """Reading 26 on the resumed phase 3: the revalidation's read-only hash is
    admitted by the shared-read handle, the move's read-write reopen is not;
    the journal is abandoned under ``ARTIFACT.MOVE_FAILED`` before T2 and the
    held bytes stay in staging as the only copy."""
    result, _ = _prepared_after_the_lease(harness, "after_prepared")
    handle = _hold_open(_result_staged(result, 0), _FILE_SHARE_READ)
    try:
        refused = harness.finalize(result.request)
    finally:
        _winapi.CloseHandle(handle)
    assert _code(refused) == ARTIFACT_MOVE_FAILED
    durable = harness.durable()
    assert durable.journal_state == "ABANDONED"
    assert durable.abandon_reason == ARTIFACT_MOVE_FAILED
    assert "FINALIZATION_MOVED" not in durable.audit_actions
    assert durable.object_blobs == ()
    assert _result_staged(result, 0).is_file()
    assert all(state == "QUARANTINED" for state in durable.candidate_states.values())


def test_staged_candidate_neither_staged_nor_finalized_abandons(
    harness: MemoryFinalizationHarness,
) -> None:
    result, _ = _prepared_after_the_lease(harness, "after_prepared")
    _result_staged(result, 0).unlink()
    refused = harness.finalize(result.request)
    assert _code(refused) == ARTIFACT_VALIDATION_FAILED
    assert "neither in staging nor at its finalized path" in _message(refused)
    durable = harness.durable()
    assert durable.journal_state == "ABANDONED"
    assert durable.abandon_reason == ARTIFACT_VALIDATION_FAILED
    (entry,) = durable.quarantine_entries
    assert len(entry.files) == 1  # the other staged candidate


def test_moved_blob_that_cannot_be_reread_abandons_the_resumed_journal(
    harness: MemoryFinalizationHarness,
) -> None:
    result, prepared = _prepared_after_the_lease(harness, "after_move", 0)
    blob = harness.roots.store.finalized_path_for(
        prepared.planned_paths[0].expected_sha256
    )
    handle = _hold_open(blob, 0)
    try:
        refused = harness.finalize(result.request)
    finally:
        _winapi.CloseHandle(handle)
    assert _code(refused) == ARTIFACT_MOVE_FAILED
    durable = harness.durable()
    assert durable.journal_state == "ABANDONED"
    assert durable.abandon_reason == ARTIFACT_MOVE_FAILED
    assert blob.is_file()  # held: swept by RV-9 later
    assert all(state == "QUARANTINED" for state in durable.candidate_states.values())


@pytest.mark.parametrize(
    ("method", "call"),
    [
        pytest.param("get", 2, id="run-read"),
        pytest.param("compare_and_swap", 1, id="run-write"),
    ],
)
def test_reconciler_run_write_faults_leave_the_abandonment_for_the_next_pass(
    harness: MemoryFinalizationHarness,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    call: int,
) -> None:
    """17.3 inside the abandonment transaction: a refused read or write of the
    run row rolls the abandonment back with it; the pass records no change and
    the journal stays MOVED under its renewed lease for the next pass."""
    result = harness.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        harness.finalize(result.request, probe=CrashingProbe("after_moved"))
    (moved,) = harness.durable().journal
    harness.advance_clock(RESULT_LEASE_SECONDS + 1)
    _fail_call(monkeypatch, MemoryEngineRunRecords, method, _write_failure(), call=call)
    report = _ok(harness.recover())
    assert (report.resumed, report.abandoned, report.registered) == (1, 0, 0)
    after = harness.durable()
    assert after.journal_state == "MOVED"
    assert after.journal[0].revision == moved.revision + 1  # the takeover only
    assert after.run_state == "RUNNING"
    assert all(state == "FINALIZING" for state in after.candidate_states.values())
    assert "FINALIZATION_ABANDONED" not in after.audit_actions
    assert "RUN_FAILED" not in after.audit_actions
    assert len(after.object_blobs) == 2


# --------------------------------------------------------------------------
# The canonical evidence ruling of 2026-11-09: available material is scanned
# exactly for either purpose once its association is validated, a token-free
# validation is never reported as an exact scan, and the canonical contract is
# consulted only through a registrar that also answers it
# --------------------------------------------------------------------------

_CANONICAL_DOCUMENT: Final = (
    b'{"content_hash":"' + b"7" * 64 + b'","message":"plain words"}'
)
_CANONICAL_KIND: Final = "sanitized-adapter-result-manifest"


def _audit_details(durable: DurableState, action: str) -> list[dict[str, Any]]:
    return [
        dict(event.details)
        for event in durable.audit_events
        if event.action.value == action
    ]


def _plant_run_evidence(
    harness: MemoryFinalizationHarness,
    files: dict[str, bytes],
    *,
    artifact_kind: str = "stderr-capture",
) -> tuple[tuple[str, ...], Any]:
    """RUN-owned core evidence under the invocation correlation, as rows and
    staged bytes, with the request over exactly those candidates."""
    candidates = plant_core_evidence(
        harness.roots.store,
        owner=RUN_OWNER,
        correlation=INVOCATION_CORRELATION,
        files=files,
        artifact_kind=artifact_kind,
    )
    for candidate in candidates:
        harness.store_data.candidates[candidate.candidate_artifact_id] = candidate
    ids = tuple(candidate.candidate_artifact_id for candidate in candidates)
    request = sample_evidence_request(
        list(ids), owner=RUN_OWNER, correlation=INVOCATION_CORRELATION
    )
    return ids, request


class _QualifyingRegistrar:
    """The memory registrar beside one fixed canonical verdict: the shape of the
    production registrar, which answers ``CanonicalEvidenceQualifier`` too."""

    def __init__(self, inner: Any, answer: Result[Any]) -> None:
        self._inner = inner
        self.answer = answer
        self.qualified: list[tuple[str, tuple[bytes, ...]]] = []

    def register_result(
        self, transaction: Any, journal: Any, refs: Any, facts: Any
    ) -> Any:
        return self._inner.register_result(transaction, journal, refs, facts)

    def register_evidence(self, transaction: Any, journal: Any, refs: Any) -> Any:
        return self._inner.register_evidence(transaction, journal, refs)

    def qualify_evidence(
        self, candidate: Any, records: tuple[bytes, ...]
    ) -> Result[Any]:
        self.qualified.append((candidate.candidate_artifact_id, records))
        return self.answer


def _qualified_answer(*uncontrolled: str) -> Success[Any]:
    return Success[Any](
        outcome="SUCCESS",
        value=CanonicalQualification(
            records=1, uncontrolled_strings=tuple(uncontrolled)
        ),
    )


def _finalizer_over(
    harness: MemoryFinalizationHarness, registrar: Any
) -> CoreArtifactFinalizer:
    return CoreArtifactFinalizer(
        harness.unit_of_work.begin,
        harness.clock,
        harness.hasher,
        harness.roots.store,
        RecordingProbe(),
        registrar,
        harness.auditor,
        command_roots=harness.command_roots,
        token_material=harness.token_material,
    )


def test_evidence_material_from_the_lookup_is_scanned_exactly(
    harness: MemoryFinalizationHarness,
) -> None:
    """A run root under the harness lets the lookup answer the attempt's
    material, so RUN-owned evidence is scanned for the exact raw token -- the
    refusal names the token, not a shape, and audits the leakage -- while a
    clean sibling registers with its validation audited as an exact scan."""
    harness.plant_result_prestate()
    leaking = b"adapter wrote " + FIXTURE_TOKEN.encode("ascii") + b"\n"
    (leaking_id,), request = _plant_run_evidence(harness, {"stderr.txt": leaking})
    refused = harness.finalize(request)
    assert _code(refused) == SECURITY_SENSITIVE_MATERIAL_LEAKAGE
    assert "raw attempt token" in _message(refused)
    assert FIXTURE_TOKEN not in _message(refused)
    durable = harness.durable()
    assert durable.candidate_states[leaking_id] == "QUARANTINED"
    assert "ARTIFACT_LEAKAGE_DETECTED" in durable.audit_actions
    (clean_id,), clean = _plant_run_evidence(
        harness, {"protocol.txt": b"clean protocol text\n"}
    )
    assert clean_id != leaking_id
    registered = _ok(harness.finalize(clean))
    assert registered.journal_state == "REGISTERED"
    assert _audit_details(harness.durable(), "ARTIFACT_VALIDATED") == [
        {"purpose": "EVIDENCE", "exact_scan": True, "canonical": False}
    ]


def test_material_that_is_not_the_runs_is_refused_before_any_swap(
    harness: MemoryFinalizationHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ruling: material is validated against the authoritative run and
    invocation -- the stored attempt token hash included -- before use, for a
    RESULT request, for RUN-owned evidence and for a caller-supplied transient
    material alike; a mismatch is the invariant and nothing is written."""
    result = harness.plant_result_prestate()
    before = harness.durable()
    wrong_hash = AttemptTokenMaterial(run_id=RUN_ID, attempt_token="B" * 32)
    foreign = AttemptTokenMaterial(run_id=OTHER_RUN_ID, attempt_token=FIXTURE_TOKEN)
    monkeypatch.setattr(harness, "token_material", lambda invocation_id: wrong_hash)
    refused = harness.finalize(result.request)
    assert _code(refused) == INVARIANT_VIOLATION
    assert "attempt token material" in _message(refused)
    assert "B" * 32 not in _message(refused)
    assert harness.durable() == before
    monkeypatch.setattr(harness, "token_material", lambda invocation_id: foreign)
    refused = harness.finalize(result.request)
    assert _code(refused) == INVARIANT_VIOLATION
    assert harness.durable() == before
    evidence = harness.plant_evidence_prestate()
    before = harness.durable()
    refused = harness.finalize(evidence.request)
    assert _code(refused) == INVARIANT_VIOLATION
    assert "attempt token material" in _message(refused)
    assert harness.durable() == before
    monkeypatch.setattr(harness, "token_material", lambda invocation_id: MISSING)
    supplied = run_coroutine(
        harness.finalizer().finalize(
            evidence.request, FlagCancellationToken(), token_material=wrong_hash
        )
    )
    assert _code(supplied) == INVARIANT_VIOLATION
    assert harness.durable() == before


def test_evidence_without_material_is_token_free_and_never_reported_exact(
    harness: MemoryFinalizationHarness,
) -> None:
    """No run root: the lookup answers nothing, the evidence registers on the
    whole-content rule alone and its validation is audited as not exactly
    scanned (the ruling: missing material is never a successful exact scan)."""
    evidence = harness.plant_evidence_prestate()
    assert not isinstance(harness.token_material(INVOCATION_ID), AttemptTokenMaterial)
    registered = _ok(harness.finalize(evidence.request))
    assert registered.journal_state == "REGISTERED"
    assert _audit_details(harness.durable(), "ARTIFACT_VALIDATED") == [
        {"purpose": "EVIDENCE", "exact_scan": False, "canonical": False}
    ]


def test_finalize_scans_evidence_with_the_callers_transient_material(
    harness: MemoryFinalizationHarness,
) -> None:
    """The ruling: material a caller's frame already holds reaches the phase-1
    scan of that one call -- the lookup answers nothing here -- and never
    becomes an attribute of the finalizer."""
    leaking = b"leak " + FIXTURE_TOKEN.encode("ascii") + b"\n"
    evidence = harness.plant_evidence_prestate(files={"stderr.txt": leaking})
    assert not isinstance(harness.token_material(INVOCATION_ID), AttemptTokenMaterial)
    finalizer = harness.finalizer()
    material = AttemptTokenMaterial(run_id=RUN_ID, attempt_token=FIXTURE_TOKEN)
    refused = run_coroutine(
        finalizer.finalize(
            evidence.request, FlagCancellationToken(), token_material=material
        )
    )
    assert _code(refused) == SECURITY_SENSITIVE_MATERIAL_LEAKAGE
    assert "raw attempt token" in _message(refused)
    for name, value in vars(finalizer).items():
        assert not isinstance(value, AttemptTokenMaterial), name


def test_canonical_json_is_refused_without_a_qualifying_registrar(
    harness: MemoryFinalizationHarness,
) -> None:
    """The Task 6 memory registrar answers no canonical contract, so plan 4.6
    bytes -- a digest-bearing canonical JSON document -- stay under the
    whole-content scan and are refused as token-shaped, exactly as before."""
    harness.plant_run()
    (candidate_id,), request = _plant_run_evidence(
        harness, {"a.json": _CANONICAL_DOCUMENT}, artifact_kind=_CANONICAL_KIND
    )
    refused = harness.finalize(request)
    assert _code(refused) == SECURITY_SENSITIVE_MATERIAL_LEAKAGE
    assert "token-shaped" in _message(refused)
    assert harness.durable().candidate_states[candidate_id] == "QUARANTINED"


def test_a_qualifying_registrar_admits_canonical_json_and_audits_it(
    harness: MemoryFinalizationHarness,
) -> None:
    """The same bytes register when the registrar also answers the canonical
    contract -- the finalizer hands it the candidate and the one record -- and
    the validation is audited as canonical and not exactly scanned."""
    harness.plant_run()
    (candidate_id,), request = _plant_run_evidence(
        harness, {"b.json": _CANONICAL_DOCUMENT}, artifact_kind=_CANONICAL_KIND
    )
    qualifying = _QualifyingRegistrar(
        harness.registrar, _qualified_answer("plain words")
    )
    finalizer = _finalizer_over(harness, qualifying)
    registered = _ok(
        run_coroutine(finalizer.finalize(request, FlagCancellationToken()))
    )
    assert registered.journal_state == "REGISTERED"
    assert qualifying.qualified == [(candidate_id, (_CANONICAL_DOCUMENT,))]
    durable = harness.durable()
    assert len(durable.refs) == 1
    assert _audit_details(durable, "ARTIFACT_VALIDATED") == [
        {"purpose": "EVIDENCE", "exact_scan": False, "canonical": True}
    ]


def test_a_registrar_that_refuses_the_contract_quarantines_at_schema(
    harness: MemoryFinalizationHarness,
) -> None:
    """Content that is the model but disagrees with the authoritative facts is
    refused at ``SCHEMA`` with the qualifier's reason: a quarantine, never a
    CORRUPT classification, no journal and no blob."""
    harness.plant_run()
    (candidate_id,), request = _plant_run_evidence(
        harness, {"c.json": _CANONICAL_DOCUMENT}, artifact_kind=_CANONICAL_KIND
    )
    refusing = _QualifyingRegistrar(
        harness.registrar,
        artifact_failure(
            ARTIFACT_VALIDATION_FAILED,
            message="the sanitized row disagrees with the staged bytes",
            now_utc=INSTANT,
        ),
    )
    finalizer = _finalizer_over(harness, refusing)
    refused = run_coroutine(finalizer.finalize(request, FlagCancellationToken()))
    assert _code(refused) == ARTIFACT_VALIDATION_FAILED
    assert "disagrees" in _message(refused)
    durable = harness.durable()
    assert durable.candidate_states == {candidate_id: "QUARANTINED"}
    (quarantined,) = durable.candidates
    assert quarantined.validation_observations[-1].stage == "SCHEMA"
    assert durable.journal == ()
    assert durable.object_blobs == ()
