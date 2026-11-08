"""Stage 9 Task 6, plan 5.2: the eleven race rows Task 6 owns, as sequential
interleavings over the SQLite ``FinalizationFixture`` (requirement rows
R14.8-02, R14.8-03, R15.7-03, R17.2-01, R17.2-02, R19.1-01, R19.1-06..08,
R19.3-01, R19.3-02, R19.3-05, R19.4-07, R21.2.1-01, R29.3-07, R29.6-01, T28.3-01,
T28.3-08, F7.2-1, R15.7-01, R15.7-02, R23.3-02, R23.3.1-13).

True concurrency is not constructible over one SQLite file (Stage 8 plan 270);
every row is driven by the test in the order plan 5.2 names. The memory
registrar refuses RESULT registration, so RC-13 is proven to its MOVED half here
(``test_rc13_takeover_reaches_moved``); its success half and RC-3, RC-9, RC-15,
RC-16 and RC-17 are Task 7's.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from crypto_lab.artifacts.diagnostics import (
    ARTIFACT_FINALIZATION_TIMED_OUT,
    ARTIFACT_VALIDATION_FAILED,
)
from crypto_lab.artifacts.finalizer import EVIDENCE_LEASE_SECONDS, RESULT_LEASE_SECONDS
from crypto_lab.artifacts.ownership import RunArtifactOwner
from crypto_lab.domain.lifecycle import CommandInvocationState, CommandKind
from crypto_lab.domain.results import Failure, Result, Success
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
    plant_command_root,
    renew_journal,
    result_candidates,
    sample_evidence_request,
    sample_result_request,
)
from doubles.experiments import (
    EXPERIMENT_ID,
    INSTANT,
    OTHER_INVOCATION_ID,
    OTHER_REQUEST_HASH,
    RUN_ID,
    UUID_C,
    FixedClock,
    sample_invocation,
)
from persistence_support.artifacts import FinalizationFixture
from persistence_support.harness import put_invocation

_THIRD_INVOCATION_ID = f"inv_{UUID_C}"
_OTHER_SANITIZED_HASH = "f" * 64


def _ok[T](result: Result[T]) -> T:
    assert isinstance(result, Success), result
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
