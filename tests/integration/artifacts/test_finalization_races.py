"""Stage 9 Task 6 and Task 7, plan 5.2: the race rows as sequential
interleavings over the SQLite ``FinalizationFixture`` (requirement rows
R14.8-02, R14.8-03, R15.7-03, R17.2-01, R17.2-02, R19.1-01, R19.1-06..08,
R19.3-01, R19.3-02, R19.3-05, R19.4-07, R21.2.1-01, R29.3-07, R29.6-01, T28.3-01,
T28.3-08, F7.2-1, R15.7-01, R15.7-02, R23.3-02, R23.3.1-13; Task 7: F7.1-2,
R19.1-10, R19.3-03, R19.3-04, R19.3-06, R29.4-02, A33.6-04, R17.2-01, R29.6-01).

True concurrency is not constructible over one SQLite file (Stage 8 plan 270);
every row is driven by the test in the order plan 5.2 names. The Task 6 memory
registrar refuses RESULT registration, so RC-13 is proven to its MOVED half over
the default fixture (``test_rc13_takeover_reaches_moved``); its success half and
RC-3, RC-6, RC-9, RC-15, RC-16 and RC-17 run over the production registrar,
validator and auditor (``production``), where the first RESULT success of the
project's test history is committed only through ``ResultRegistrar``.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from crypto_lab.adapters.sanitization import StderrCapture
from crypto_lab.artifacts.diagnostics import (
    ARTIFACT_FINALIZATION_TIMED_OUT,
    ARTIFACT_VALIDATION_FAILED,
)
from crypto_lab.artifacts.finalizer import EVIDENCE_LEASE_SECONDS, RESULT_LEASE_SECONDS
from crypto_lab.artifacts.models import ArtifactFinalizationPurpose
from crypto_lab.artifacts.ownership import RunArtifactOwner
from crypto_lab.domain.diagnostics import DiagnosticCategory
from crypto_lab.domain.hashing import sha256_bytes
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.experiments.finalization import (
    finalize_evidence,
    protocol_capture_evidence,
    stderr_evidence,
)
from crypto_lab.experiments.invocation_service import transition_invocation_and_run
from crypto_lab.experiments.requests import (
    CoupledTransitionRequest,
    InvocationTransitionRequest,
    RunTransitionRequest,
)
from crypto_lab.persistence.diagnostics import CONCURRENCY_CONFLICT, INVARIANT_VIOLATION
from doubles.artifacts import (
    INVOCATION_CORRELATION,
    RESULT_FILES,
    RESULT_TIMEOUT_SECONDS,
    RUN_OWNER,
    SANITIZED_MANIFEST_HASH,
    CrashingProbe,
    FinalizationCrash,
    RecordingProbe,
    ResultPlan,
    plant_command_root,
    renew_journal,
    result_candidates,
    sample_evidence_request,
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
    THIRD_DIAG_ID,
    UUID_C,
    FixedClock,
    sample_diagnostic,
    sample_invocation,
)
from persistence_support.artifacts import FinalizationFixture, ProductionResultPlan
from persistence_support.harness import put_invocation

_THIRD_INVOCATION_ID = f"inv_{UUID_C}"
_OTHER_SANITIZED_HASH = "f" * 64


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


def _message(result: object) -> str:
    assert isinstance(result, Failure), result
    return result.diagnostics[0].message


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


def _assert_result_registered(
    fixture: FinalizationFixture, plan: ResultPlan, *, run_revision: int
) -> None:
    """The durable shape of one RESULT success: refs, blobs, manifest, member
    links, the run in a success state at ``run_revision`` and the raw-bearing
    bytes closed (plan 4.3 phases 5 and 6)."""
    after = fixture.durable()
    assert after.journal_state == "REGISTERED"
    assert len(after.refs) == len(plan.candidates)
    assert {ref.content_hash for ref in after.refs} == {
        candidate.adapter_declared_hash for candidate in plan.candidates
    }
    assert set(after.object_blobs) == {ref.content_hash for ref in after.refs}
    assert after.run_state in ("SUCCEEDED", "SUCCEEDED_WITH_WARNINGS")
    assert after.run_revision == run_revision
    (manifest,) = after.run_manifests
    assert manifest.run_id == plan.run.run_id
    assert manifest.run_invocation_id == plan.invocation.invocation_id
    assert manifest.sanitized_adapter_result_manifest_hash == (
        plan.request.sanitized_adapter_result_manifest_hash
    )
    members = [
        link
        for link in after.run_artifacts
        if link.link_role == "RESULT_MANIFEST_MEMBER"
    ]
    assert {link.artifact_id for link in members} == {
        ref.artifact_id for ref in after.refs
    }
    assert all(link.run_manifest_id == manifest.manifest_id for link in members)
    assert all(state == "FINALIZING" for state in after.candidate_states.values())
    assert not plan.roots.request_path.exists()
    assert isinstance(plan.roots.result_path, Path)
    assert not plan.roots.result_path.exists()
    for action in (
        "RUN_MANIFEST_REGISTERED",
        "RUN_SUCCEEDED",
        "FINALIZATION_REGISTERED",
    ):
        assert after.audit_actions.count(action) == 1, action
    report = fixture.database.consistency_report()
    assert report.dangling_diagnostic_references == 0
    assert report.success_without_manifest == 0


class _AdvancingProbe(RecordingProbe):
    """Advance the fixed clock past the deadline at one probe point."""

    def __init__(self, clock: FixedClock, point: str, index: int = 0) -> None:
        super().__init__()
        self._clock = clock
        self._point = point
        self._index = index

    def after_move(self, index: int) -> None:
        super().after_move(index)
        if self._point == "after_move" and index == self._index:
            self._clock.advance(RESULT_TIMEOUT_SECONDS + 1)

    def after_moved(self) -> None:
        super().after_moved()
        if self._point == "after_moved":
            self._clock.advance(RESULT_TIMEOUT_SECONDS + 1)


# --------------------------------------------------------------------------
# RC-1: cancellation before the lease
# --------------------------------------------------------------------------


def test_rc1(fixture: FinalizationFixture) -> None:
    plan = fixture.plant_result_prestate()
    evidence = fixture.plant_evidence_prestate()
    cancelled = fixture.cancel_run()
    assert cancelled.state.value == "CANCELLED"
    refused = fixture.finalize(plan.request)
    assert _code(refused) == INVARIANT_VIOLATION
    assert "not RUNNING" in _message(refused)
    during = fixture.durable()
    assert during.journal == ()
    assert during.audit_actions[-1] == "FINALIZATION_LEASE_REFUSED"
    for candidate in plan.candidates:
        assert during.candidate_states[candidate.candidate_artifact_id] == "VALIDATING"
    # EVIDENCE for the same invocation still finalizes (RC-9's non-interference).
    _ok(fixture.finalize(evidence.request))
    report = _ok(fixture.recover())
    assert report.quarantined == 2
    after = fixture.durable()
    assert after.run_state == "CANCELLED"
    assert after.run_revision == cancelled.revision
    for candidate in plan.candidates:
        assert after.candidate_states[candidate.candidate_artifact_id] == "QUARANTINED"
    assert len(after.refs) == 1  # the evidence reference only
    assert after.run_manifests == ()
    assert not plan.roots.request_path.exists()
    assert not any(name.endswith(".bin") for name in after.command_root_files)


# --------------------------------------------------------------------------
# RC-2: cancellation wins between MOVED and REGISTERED
# --------------------------------------------------------------------------


def test_rc2_cancellation_between_moved_and_registered_abandons(
    fixture: FinalizationFixture,
) -> None:
    plan = fixture.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        fixture.finalize_result(plan, probe=CrashingProbe("after_moved"))
    before = fixture.durable()
    assert before.journal_state == "MOVED"
    assert before.refs == ()
    fixture.cancel_run()  # Stage 5 transition_run(CANCELLED), CANCELLATION diagnostic
    # The pass takes the journal over once its lease has expired (the ruling).
    fixture.advance_clock(RESULT_LEASE_SECONDS + 1)
    report = _ok(fixture.recover())
    after = fixture.durable()
    assert report.abandoned == 1
    assert after.journal_state == "ABANDONED"
    assert after.abandon_reason == "PERSISTENCE.CONCURRENCY_CONFLICT"
    assert after.run_state == "CANCELLED"
    assert after.refs == ()
    assert after.run_manifests == ()
    assert after.object_blobs == ()
    assert len(after.quarantine_entries) == 1  # keyed by finalization_id (6.2)
    assert after.quarantine_entries[0].entry_id.startswith("fin_")
    appended = after.audit_actions[len(before.audit_actions) :]
    assert appended.count("FINALIZATION_ABANDONED") == 1
    assert appended.count("ARTIFACT_QUARANTINED") == 2  # one per candidate
    assert appended.index("FINALIZATION_ABANDONED") < appended.index(
        "ARTIFACT_QUARANTINED"
    )
    assert sum(action.startswith("RECONCILIATION_") for action in appended) == 1
    assert all(state == "QUARANTINED" for state in after.candidate_states.values())


# --------------------------------------------------------------------------
# RC-4 and RC-5: the deadline wins
# --------------------------------------------------------------------------


def test_rc4(fixture: FinalizationFixture) -> None:
    plan = fixture.plant_result_prestate()
    timed_out = fixture.finalize(
        plan.request, probe=_AdvancingProbe(fixture.clock, "after_moved")
    )
    assert _code(timed_out) == ARTIFACT_FINALIZATION_TIMED_OUT
    after = fixture.durable()
    assert after.run_state == "TIMED_OUT"
    assert after.journal_state == "ABANDONED"
    assert after.abandon_reason == ARTIFACT_FINALIZATION_TIMED_OUT
    assert after.object_blobs == ()
    assert after.refs == ()
    assert after.run_manifests == ()
    assert after.invocation is not None
    assert after.invocation.state.value == "EXITED"
    assert after.invocation.revision == plan.invocation.revision
    assert after.audit_actions.count("FINALIZATION_TIMED_OUT") == 1
    report = _ok(fixture.recover())
    assert report.registered == 0
    assert fixture.durable().run_state == "TIMED_OUT"


def test_rc5(fixture: FinalizationFixture) -> None:
    plan = fixture.plant_result_prestate()
    timed_out = fixture.finalize(
        plan.request, probe=_AdvancingProbe(fixture.clock, "after_move", 0)
    )
    assert _code(timed_out) == ARTIFACT_FINALIZATION_TIMED_OUT
    after = fixture.durable()
    assert after.run_state == "TIMED_OUT"
    assert after.journal_state == "ABANDONED"
    assert after.object_blobs == ()  # the first blob quarantined
    (entry,) = after.quarantine_entries
    assert entry.entry_id.startswith("fin_")
    assert len(entry.files) == 2  # the first blob and the never-moved second
    assert not any(name.endswith(".bin") for name in after.command_root_files)
    assert after.refs == ()


# --------------------------------------------------------------------------
# RC-7, RC-8, RC-12, RC-13: identity and lease precedence
# --------------------------------------------------------------------------


def test_rc7(fixture: FinalizationFixture) -> None:
    plan = fixture.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        fixture.finalize_result(plan, probe=CrashingProbe("after_prepared"))
    before = fixture.durable()
    different = sample_result_request(
        [candidate.candidate_artifact_id for candidate in plan.candidates],
        run=plan.run,
        invocation=plan.invocation,
        sanitized_hash=_OTHER_SANITIZED_HASH,
    )
    assert different.idempotency_key != plan.request.idempotency_key
    refused = fixture.finalize(different)
    assert _code(refused) == CONCURRENCY_CONFLICT
    assert "different identity" in _message(refused)
    assert fixture.durable() == before


def test_rc8(fixture: FinalizationFixture) -> None:
    plan = fixture.plant_result_prestate()
    # (a) the run's own EXITED VALIDATE invocation: not the run-command.
    put_invocation(
        fixture.harness.lifecycle(),
        sample_invocation(
            CommandInvocationState.EXITED,
            kind=CommandKind.VALIDATE,
            invocation_id=OTHER_INVOCATION_ID,
        ),
    )
    validate_owner = RunArtifactOwner(
        owner_kind="RUN",
        experiment_id=EXPERIMENT_ID,
        run_id=RUN_ID,
        invocation_id=OTHER_INVOCATION_ID,
    )
    before = fixture.durable()
    refused = fixture.finalize(
        sample_result_request(
            [candidate.candidate_artifact_id for candidate in plan.candidates],
            run=plan.run,
            invocation=plan.invocation,
            owner=validate_owner,
        )
    )
    assert _code(refused) == INVARIANT_VIOLATION
    assert fixture.durable() == before
    # (b) a second RUN invocation row planted raw with another request identity:
    # EXITED and RUN-kind, but not the run's active run-command.
    planted = sample_invocation(
        CommandInvocationState.EXITED,
        kind=CommandKind.RUN,
        invocation_id=_THIRD_INVOCATION_ID,
        request_hash=OTHER_REQUEST_HASH,
    )
    put_invocation(fixture.harness.lifecycle(), planted)
    planted_owner = RunArtifactOwner(
        owner_kind="RUN",
        experiment_id=EXPERIMENT_ID,
        run_id=RUN_ID,
        invocation_id=_THIRD_INVOCATION_ID,
    )
    fixture.harness.put_owner(planted_owner)
    roots = plant_command_root(
        fixture.roots.runtime_root, invocation_id=_THIRD_INVOCATION_ID
    )
    fixture._command_roots[_THIRD_INVOCATION_ID] = roots
    candidates = result_candidates(
        invocation_id=_THIRD_INVOCATION_ID, owner=planted_owner
    )
    for candidate in candidates:
        fixture.harness.put_candidate(candidate)
    refused_planted = fixture.finalize(
        sample_result_request(
            [candidate.candidate_artifact_id for candidate in candidates],
            run=plan.run,
            invocation=planted,
            owner=planted_owner,
        )
    )
    assert _code(refused_planted) == INVARIANT_VIOLATION
    assert "not the active run-command" in _message(refused_planted)
    after = fixture.durable()
    assert after.journal == ()
    assert after.audit_actions[-1] == "FINALIZATION_LEASE_REFUSED"
    assert after.run_state == "RUNNING"
    assert after.run_deadline is None


def test_rc12(fixture: FinalizationFixture) -> None:
    plan = fixture.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        fixture.finalize_result(plan, probe=CrashingProbe("after_prepared"))
    before = fixture.durable()
    assert before.journal_state == "PREPARED"
    refused = fixture.finalize_result(plan)
    assert _code(refused) == CONCURRENCY_CONFLICT
    assert "active lease" in _message(refused)
    assert fixture.durable() == before


def test_rc13_takeover_reaches_moved(fixture: FinalizationFixture) -> None:
    plan = fixture.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        fixture.finalize_result(plan, probe=CrashingProbe("after_prepared"))
    (prepared,) = fixture.durable().journal
    # The lease (the compiled 300 s) expires before the deadline (600 s).
    fixture.advance_clock(RESULT_LEASE_SECONDS + 1)
    with pytest.raises(FinalizationCrash):
        fixture.finalize_result(plan, probe=CrashingProbe("after_moved"))
    after = fixture.durable()
    (moved,) = after.journal
    assert moved.finalization_id == prepared.finalization_id
    assert moved.state.value == "MOVED"
    assert len(moved.observed) == 2
    assert moved.lease_expires_at_utc > prepared.lease_expires_at_utc
    assert moved.finalization_deadline_utc == prepared.finalization_deadline_utc
    # The takeover is its own durable compare-and-swap (the ruling of
    # 2026-11-08): one revision and one audited lease acquisition before T2.
    assert moved.revision == prepared.revision + 2
    assert after.audit_actions.count("FINALIZATION_LEASE_ACQUIRED") == 2
    assert after.run_state == "RUNNING"
    assert after.run_revision == plan.run.revision + 1
    assert len(after.object_blobs) == 2
    assert after.refs == ()


def test_renewal_capped_at_the_deadline_keeps_the_holder_until_exhaustion(
    fixture: FinalizationFixture,
) -> None:
    """The RESULT lease ruling of 2026-11-08 at its boundary. The lease is the
    compiled ``RESULT_LEASE_SECONDS`` capped at the immutable deadline, so a
    renewal late in the attempt writes a lease equal to the deadline. Under that
    capped lease the holder wins at every instant before the deadline (RC-12,
    ``PERSISTENCE.CONCURRENCY_CONFLICT``), and once the deadline has passed a
    newcomer under the same identity meets the timeout path, never ``MOVED`` and
    never a registration (RV-15; specification 23.3.1:1723 "expiry never creates
    success")."""
    assert RESULT_LEASE_SECONDS == EVIDENCE_LEASE_SECONDS
    plan = fixture.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        fixture.finalize_result(plan, probe=CrashingProbe("after_prepared"))
    (prepared,) = fixture.durable().journal
    deadline = prepared.finalization_deadline_utc
    assert isinstance(deadline, datetime)
    assert deadline == INSTANT + timedelta(seconds=RESULT_TIMEOUT_SECONDS)
    assert prepared.lease_expires_at_utc == INSTANT + timedelta(
        seconds=RESULT_LEASE_SECONDS
    )
    # The holder's renewal capped at the deadline.
    capped = renew_journal(prepared, deadline)
    transaction = fixture.begin()
    _ok(transaction.finalization_journal.compare_and_swap(prepared.revision, capped))
    _ok(transaction.commit())
    before = fixture.durable()
    assert before.journal[0].lease_expires_at_utc == deadline
    assert before.journal[0].finalization_deadline_utc == deadline
    # One second before the deadline: the lease is active, the holder wins.
    fixture.advance_clock(RESULT_TIMEOUT_SECONDS - 1)
    refused = fixture.finalize_result(plan)
    assert _code(refused) == CONCURRENCY_CONFLICT
    assert "active lease" in _message(refused)
    assert fixture.durable() == before
    # One second after it: the lease is expired and so is the deadline; the
    # newcomer under the same identity is the timeout path, never MOVED.
    fixture.advance_clock(2)
    timed_out = fixture.finalize_result(plan)
    assert _code(timed_out) == ARTIFACT_FINALIZATION_TIMED_OUT
    after = fixture.durable()
    (journal,) = after.journal
    assert journal.finalization_id == prepared.finalization_id
    assert journal.state.value == "ABANDONED"
    assert after.abandon_reason == ARTIFACT_FINALIZATION_TIMED_OUT
    assert journal.observed == ()
    assert after.run_state == "TIMED_OUT"
    assert after.refs == ()
    assert after.object_blobs == ()
    assert "FINALIZATION_MOVED" not in after.audit_actions
    assert after.audit_actions.count("FINALIZATION_TIMED_OUT") == 1


# --------------------------------------------------------------------------
# RC-10 and RC-11: evidence replay and the adapter-produced refusal
# --------------------------------------------------------------------------


def test_rc10(fixture: FinalizationFixture) -> None:
    plan = fixture.plant_evidence_prestate()
    first = _ok(fixture.finalize_evidence(plan))
    before = fixture.durable()
    again = _ok(fixture.finalize_evidence(plan))
    assert again.replayed is True
    assert again.model_copy(update={"replayed": False}) == first
    after = fixture.durable()
    assert after.journal == before.journal
    assert after.refs == before.refs
    assert after.candidates == before.candidates
    assert after.run_artifacts == before.run_artifacts
    assert after.audit_actions == (*before.audit_actions, "FINALIZATION_REPLAYED")


def test_rc11(fixture: FinalizationFixture) -> None:
    plan = fixture.plant_result_prestate()
    before = fixture.durable()
    refused = fixture.finalize(
        sample_evidence_request(
            [candidate.candidate_artifact_id for candidate in plan.candidates],
            owner=RUN_OWNER,
            correlation=INVOCATION_CORRELATION,
        )
    )
    assert _code(refused) == ARTIFACT_VALIDATION_FAILED
    assert "adapter-produced candidate cannot be evidence" in _message(refused)
    assert fixture.durable() == before


# --------------------------------------------------------------------------
# RC-14: the Stage 6 verdict failed the run first
# --------------------------------------------------------------------------


def test_rc14(fixture: FinalizationFixture) -> None:
    plan = fixture.plant_result_prestate()
    failed = fixture.fail_run_by_verdict()
    refused = fixture.finalize_result(plan)
    assert _code(refused) == INVARIANT_VIOLATION
    during = fixture.durable()
    assert during.journal == ()
    assert during.run_manifests == ()
    # Never relabeled as evidence: an EVIDENCE request over them is RC-11.
    relabeled = fixture.finalize(
        sample_evidence_request(
            [candidate.candidate_artifact_id for candidate in plan.candidates],
            owner=RUN_OWNER,
            correlation=INVOCATION_CORRELATION,
        )
    )
    assert _code(relabeled) == ARTIFACT_VALIDATION_FAILED
    report = _ok(fixture.recover())
    assert report.quarantined == 2
    after = fixture.durable()
    assert after.run_state == "FAILED"
    assert after.run_revision == failed.revision
    assert all(state == "QUARANTINED" for state in after.candidate_states.values())
    assert after.refs == ()
    assert not plan.roots.request_path.exists()
    assert not any(name.endswith(".bin") for name in after.command_root_files)
    assert after.audit_actions.count("RETENTION_DELETED") == 1
    sanitized = plan.request.sanitized_adapter_result_manifest_hash
    assert sanitized == SANITIZED_MANIFEST_HASH
    assert RESULT_FILES


# --------------------------------------------------------------------------
# Task 7: the rows that end in RESULT success through the production registrar
# --------------------------------------------------------------------------


def test_rc6(production: FinalizationFixture) -> None:
    """RC-6: two equal RESULT requests. The first reaches ``REGISTERED`` success
    through the production registrar -- the first ``SUCCEEDED`` run of the
    project's test history; the second is the stored replay with ``replayed``
    set and writes exactly one ``FINALIZATION_REPLAYED`` audit row."""
    plan = production.plant_result_prestate()
    first = _ok(production.finalize_result(plan))
    assert first.journal_state == "REGISTERED"
    assert first.replayed is False
    assert isinstance(first.run_manifest_id, str)
    # The snapshot (RUNNING -> RUNNING) and the success swap: two revisions.
    _assert_result_registered(production, plan, run_revision=plan.run.revision + 2)
    before = production.durable()
    again = _ok(production.finalize_result(plan))
    assert again.replayed is True
    assert again.model_copy(update={"replayed": False}) == first
    after = production.durable()
    assert after.journal == before.journal
    assert after.refs == before.refs
    assert after.candidates == before.candidates
    assert after.run == before.run
    assert after.run_manifests == before.run_manifests
    assert after.run_artifacts == before.run_artifacts
    assert after.object_blobs == before.object_blobs
    assert after.audit_actions == (*before.audit_actions, "FINALIZATION_REPLAYED")


def test_rc3(production: FinalizationFixture) -> None:
    """RC-3: the finalization reached ``REGISTERED`` first. The generic run
    cancellation is refused against the terminal run (its diagnostic recorded,
    its effect nil) and ``cancel_experiment``, which reads no run (reading 23),
    still swaps the experiment to ``CANCELLED`` above the ``SUCCEEDED`` run."""
    plan = production.plant_result_prestate()
    _ok(production.finalize_result(plan))
    succeeded = production.durable()
    assert succeeded.run_state == "SUCCEEDED"
    refused = production.try_transition_run(
        RUN_ID,
        EngineRunState.CANCELLED,
        sample_diagnostic(
            THIRD_DIAG_ID,
            error_code="PROCESS.CANCELLED",
            category=DiagnosticCategory.CANCELLATION,
            retriable=False,
        ),
    )
    assert _code(refused) == INVARIANT_VIOLATION
    assert "terminal" in _message(refused)
    cancelled = _ok(production.cancel_experiment())
    assert cancelled.state is ExperimentState.CANCELLED
    after = production.durable()
    assert after.run == succeeded.run
    assert after.run_manifests == succeeded.run_manifests
    assert after.refs == succeeded.refs
    assert after.journal == succeeded.journal
    assert production.current_experiment().state is ExperimentState.CANCELLED
    # The ineffective cancellation left only its recorded diagnostic.
    assert THIRD_DIAG_ID in {item.diagnostic_id for item in after.diagnostics}
    assert after.run is not None
    assert after.run.primary_terminal_diagnostic_id != THIRD_DIAG_ID


_STDERR_TEXT = "engine stderr line one\nengine stderr line two\n"
_TERMINAL_OUTCOMES = (
    EngineRunState.SUCCEEDED,
    EngineRunState.FAILED,
    EngineRunState.CANCELLED,
    EngineRunState.TIMED_OUT,
    EngineRunState.UNAVAILABLE,
    EngineRunState.NOT_APPLICABLE,
)
_GENERIC_DIAGNOSTICS = {
    EngineRunState.TIMED_OUT: ("PROCESS.TIMED_OUT", DiagnosticCategory.TIMEOUT),
    EngineRunState.UNAVAILABLE: (
        "ADAPTER.UNAVAILABLE",
        DiagnosticCategory.ADAPTER_UNAVAILABILITY,
    ),
    EngineRunState.NOT_APPLICABLE: (
        "COMPATIBILITY.NOT_APPLICABLE",
        DiagnosticCategory.COMPATIBILITY,
    ),
}


def _reach(
    fixture: FinalizationFixture, plan: ResultPlan, outcome: EngineRunState
) -> None:
    """Reach ``outcome`` through the Stage 5/6 operations -- the Task 7 registrar
    for ``SUCCEEDED``, the verdict and cancellation paths the fixture offers, and
    the generic ``transition_run`` for the remaining three (lifecycle 241-247)."""
    if outcome is EngineRunState.SUCCEEDED:
        _ok(fixture.finalize_result(plan))
    elif outcome is EngineRunState.FAILED:
        fixture.fail_run_by_verdict()
    elif outcome is EngineRunState.CANCELLED:
        fixture.cancel_run()
    else:
        code, category = _GENERIC_DIAGNOSTICS[outcome]
        _ok(
            fixture.try_transition_run(
                RUN_ID,
                outcome,
                sample_diagnostic(
                    THIRD_DIAG_ID, error_code=code, category=category, retriable=False
                ),
            )
        )


@pytest.mark.parametrize("outcome", _TERMINAL_OUTCOMES, ids=lambda state: state.value)
def test_rc9(production: FinalizationFixture, outcome: EngineRunState) -> None:
    """RC-9 (reading 5): after every terminal outcome the invocation's stderr and
    protocol-capture evidence, produced by the Task 7 producers and finalized
    through the production registrar, registers with ``RUN_EVIDENCE`` links and
    the write-once stderr enrichment while the run row's revision stays what the
    outcome left; a ``run_manifests`` row exists only for success."""
    plan = production.plant_result_prestate()
    assert isinstance(plan, ProductionResultPlan)
    _reach(production, plan, outcome)
    before = production.durable()
    assert before.run_state == outcome.value
    unit_of_work = production.unit_of_work()
    stderr = _ok(
        stderr_evidence(
            StderrCapture(
                retained_byte_count=len(_STDERR_TEXT.encode("utf-8")),
                truncated=False,
                source_hash=sha256_bytes(_STDERR_TEXT.encode("utf-8")),
                sanitized_text=_STDERR_TEXT,
            ),
            RUN_OWNER,
            INVOCATION_ID,
            store=production.roots.store,
            unit_of_work=unit_of_work,
            auditor=production.auditor,
            clock=production.clock,
        )
    )
    capture = _ok(
        protocol_capture_evidence(
            plan.events,
            RUN_OWNER,
            INVOCATION_ID,
            store=production.roots.store,
            unit_of_work=unit_of_work,
            clock=production.clock,
        )
    )
    registered = _ok(
        finalize_evidence(
            (stderr, capture), INVOCATION_CORRELATION, finalizer=production.finalizer()
        )
    )
    assert registered.journal_state == "REGISTERED"
    assert len(registered.candidate_to_artifact_refs) == 2
    after = production.durable()
    # The run row is untouched by the EVIDENCE REGISTERED commit (reading 5).
    assert after.run == before.run
    evidence_refs = [
        ref
        for ref in after.refs
        if ref.finalization_purpose is ArtifactFinalizationPurpose.EVIDENCE
    ]
    assert {ref.artifact_id for ref in evidence_refs} == {
        mapping.artifact_id for mapping in registered.candidate_to_artifact_refs
    }
    links = [link for link in after.run_artifacts if link.link_role == "RUN_EVIDENCE"]
    assert {link.artifact_id for link in links} == {
        ref.artifact_id for ref in evidence_refs
    }
    assert all(link.run_id == RUN_ID for link in links)
    (stderr_ref,) = [
        ref for ref in evidence_refs if ref.artifact_kind == "stderr-capture"
    ]
    assert after.invocation is not None
    assert after.invocation.stderr_artifact_id == stderr_ref.artifact_id
    assert after.audit_actions.count("STDERR_EVIDENCE_LINKED") == 1
    if outcome is EngineRunState.SUCCEEDED:
        assert len(after.run_manifests) == 1
        assert len(
            [ref for ref in after.refs if ref.finalization_purpose.value == "RESULT"]
        ) == len(plan.candidates)
    else:
        assert after.run_manifests == ()
        assert not any(
            link.link_role == "RESULT_MANIFEST_MEMBER" for link in after.run_artifacts
        )
    report = production.database.consistency_report()
    assert report.dangling_diagnostic_references == 0
    assert report.success_without_manifest == 0


def test_rc13(production: FinalizationFixture) -> None:
    """RC-13's success half: the newcomer takes over the expired ``PREPARED``
    lease under the same ``finalization_id`` and completes to ``REGISTERED``
    success through the production registrar."""
    plan = production.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        production.finalize_result(plan, probe=CrashingProbe("after_prepared"))
    (prepared,) = production.durable().journal
    production.advance_clock(RESULT_LEASE_SECONDS + 1)
    completed = _ok(production.finalize_result(plan))
    assert completed.finalization_id == prepared.finalization_id
    assert completed.journal_state == "REGISTERED"
    assert completed.replayed is False
    _assert_result_registered(production, plan, run_revision=plan.run.revision + 2)
    after = production.durable()
    (registered,) = after.journal
    assert registered.finalization_id == prepared.finalization_id
    assert registered.revision > prepared.revision
    assert after.audit_actions.count("FINALIZATION_LEASE_ACQUIRED") == 2


def _coupled_timeout(fixture: FinalizationFixture) -> CoupledTransitionRequest:
    """The command-deadline path's coupled request: invocation and run to
    ``TIMED_OUT`` at their current revisions."""
    before = fixture.durable()
    assert before.invocation is not None
    assert before.run is not None
    return CoupledTransitionRequest(
        schema_version="1.0.0",
        invocation=InvocationTransitionRequest(
            schema_version="1.0.0",
            invocation_id=INVOCATION_ID,
            expected_revision=before.invocation.revision,
            target_state=CommandInvocationState.TIMED_OUT,
            reason_code="PROCESS.TIMED_OUT",
            diagnostic_ids=(),
        ),
        run=RunTransitionRequest(
            schema_version="1.0.0",
            run_id=RUN_ID,
            expected_revision=before.run.revision,
            target_state=EngineRunState.TIMED_OUT,
            reason_code="PROCESS.TIMED_OUT",
        ),
    )


def test_rc15_pair_refused(production: FinalizationFixture) -> None:
    """RC-15 (a): under a ``PREPARED`` RESULT journal the command-deadline path's
    coupled transition is refused -- the invocation is terminal (``EXITED``) --
    and nothing moves; the lease holder then completes to success."""
    plan = production.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        production.finalize_result(plan, probe=CrashingProbe("after_prepared"))
    before = production.durable()
    assert before.journal_state == "PREPARED"
    refused = transition_invocation_and_run(
        _coupled_timeout(production),
        unit_of_work=production.unit_of_work(),
        clock=production.clock,
    )
    assert _code(refused) == INVARIANT_VIOLATION
    assert "terminal invocation" in _message(refused)
    assert production.durable() == before
    production.advance_clock(RESULT_LEASE_SECONDS + 1)
    completed = _ok(production.finalize_result(plan))
    assert completed.journal_state == "REGISTERED"
    _assert_result_registered(production, plan, run_revision=plan.run.revision + 2)


def test_rc15_generic_timeout_wins(production: FinalizationFixture) -> None:
    """RC-15 (b): the generic ``transition_run(RUNNING -> TIMED_OUT)`` wins after
    ``EXITED`` (it never loads the invocation), so the resumed finalization's T3
    loses the revision arbiter: ``ABANDONED`` under the stored conflict, the
    blobs quarantined, no reference and no manifest; the run stays ``TIMED_OUT``
    at the winner's revision (reading 23)."""
    plan = production.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        production.finalize_result(plan, probe=CrashingProbe("after_prepared"))
    (prepared,) = production.durable().journal
    code, category = _GENERIC_DIAGNOSTICS[EngineRunState.TIMED_OUT]
    timed_out = _ok(
        production.try_transition_run(
            RUN_ID,
            EngineRunState.TIMED_OUT,
            sample_diagnostic(
                THIRD_DIAG_ID, error_code=code, category=category, retriable=False
            ),
        )
    )
    assert timed_out.state is EngineRunState.TIMED_OUT
    production.advance_clock(RESULT_LEASE_SECONDS + 1)
    report = _ok(production.recover())
    assert (report.resumed, report.abandoned, report.registered) == (1, 1, 0)
    after = production.durable()
    (entry,) = after.journal
    assert entry.finalization_id == prepared.finalization_id
    assert entry.state.value == "ABANDONED"
    assert entry.abandon_reason == CONCURRENCY_CONFLICT
    assert after.run_state == "TIMED_OUT"
    assert after.run_revision == timed_out.revision
    assert after.refs == ()
    assert after.run_manifests == ()
    assert after.object_blobs == ()
    assert all(state == "QUARANTINED" for state in after.candidate_states.values())
    assert "RUN_SUCCEEDED" not in after.audit_actions
    assert "RUN_MANIFEST_REGISTERED" not in after.audit_actions
    assert after.audit_actions.count("FINALIZATION_ABANDONED") == 1
    assert not plan.roots.request_path.exists()
    consistency = production.database.consistency_report()
    assert consistency.success_without_manifest == 0


def test_rc16(production: FinalizationFixture) -> None:
    """RC-16 (reading 4): attempt 1 failed and attempt 2 of the slot finalizes
    normally; attempt 1's stale RESULT identity is refused -- its run is terminal
    and it is no longer the slot's latest attempt -- and recovery sweeps its
    candidates (RV-8) and closes its root."""
    first = production.plant_result_prestate()
    failed = production.fail_run_by_verdict()
    assert failed.state is EngineRunState.FAILED
    successor = production.plant_attempt(
        run_id=OTHER_RUN_ID,
        invocation_id=OTHER_INVOCATION_ID,
        attempt_number=2,
        predecessor_run_id=RUN_ID,
    )
    second = production.plant_production_result(successor)
    completed = _ok(production.finalize_result(second))
    assert completed.journal_state == "REGISTERED"
    latest = production.durable(OTHER_RUN_ID)
    assert latest.run_state == "SUCCEEDED"
    assert latest.run_revision == successor.run.revision + 2
    (manifest,) = latest.run_manifests
    assert manifest.run_id == OTHER_RUN_ID
    refused = production.finalize_result(first)
    assert _code(refused) == INVARIANT_VIOLATION
    assert "not RUNNING" in _message(refused)
    transaction = production.begin()
    try:
        stale = _ok(
            transaction.result_leases.active_attempt_facts(RUN_ID, INVOCATION_ID)
        )
        current = _ok(
            transaction.result_leases.active_attempt_facts(
                OTHER_RUN_ID, OTHER_INVOCATION_ID
            )
        )
    finally:
        transaction.rollback()
    assert stale.is_latest_attempt is False
    assert current.is_latest_attempt is True
    report = _ok(production.recover())
    assert report.quarantined == 2
    assert report.closed_roots == 1
    after = production.durable()
    assert after.run_state == "FAILED"
    assert after.run_revision == failed.revision
    for candidate in first.candidates:
        assert after.candidate_states[candidate.candidate_artifact_id] == "QUARANTINED"
    for candidate in second.candidates:
        assert after.candidate_states[candidate.candidate_artifact_id] == "FINALIZING"
    assert len(after.run_manifests) == 1
    assert not first.roots.request_path.exists()
    assert not second.roots.request_path.exists()
    assert [entry.finalization_id for entry in after.journal] == [
        completed.finalization_id
    ]


def test_rc17(production: FinalizationFixture) -> None:
    """RC-17 (reading 23): ``cancel_experiment`` between T2 and T3 touches no run,
    so the resumed finalization registers success under a ``CANCELLED``
    experiment; the experiment's runs are cancelled only by ``transition_run``,
    which here loses to the terminal run."""
    plan = production.plant_result_prestate()
    with pytest.raises(FinalizationCrash):
        production.finalize_result(plan, probe=CrashingProbe("after_moved"))
    assert production.durable().journal_state == "MOVED"
    cancelled = _ok(production.cancel_experiment())
    assert cancelled.state is ExperimentState.CANCELLED
    assert production.durable().run_state == "RUNNING"
    production.advance_clock(RESULT_LEASE_SECONDS + 1)
    report = _ok(production.recover())
    assert (report.resumed, report.registered, report.abandoned) == (1, 1, 0)
    _assert_result_registered(production, plan, run_revision=plan.run.revision + 2)
    assert production.current_experiment().state is ExperimentState.CANCELLED
    after = production.durable()
    assert after.audit_actions.count("FINALIZATION_LEASE_ACQUIRED") == 2
    refused = production.try_transition_run(
        RUN_ID,
        EngineRunState.CANCELLED,
        sample_diagnostic(
            THIRD_DIAG_ID,
            error_code="PROCESS.CANCELLED",
            category=DiagnosticCategory.CANCELLATION,
            retriable=False,
        ),
    )
    assert _code(refused) == INVARIANT_VIOLATION
    assert production.durable().run == after.run
