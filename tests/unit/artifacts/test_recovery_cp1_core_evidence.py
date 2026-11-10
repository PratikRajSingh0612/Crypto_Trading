"""Stage 9 Task 6 correction (the ruling of 2026-11-10): the RV-10 predicate of
``reconcile_finalization`` step 4 against the independently recoverable CP-1
CORE EVIDENCE of plan 5.1.

Plan 5.3 RV-10 quarantines abandoned ``CANDIDATE``/``VALIDATING`` core staging
"older than their invocation's cleanup"; plan 5.1 CP-1 (the EVIDENCE column)
has step 4 revalidate the core candidates independently and resume from phase
2. Every supervised ``EXITED`` invocation carries ``cleanup_complete`` before
the conclusion stages its evidence (the Stage 7 supervisor completes the cleanup
inside ``invoke``; plan 4.4 step 2 stages afterwards), so a predicate on the
flag alone quarantined every CP-1 group -- the Task 8 composition finding. The
cases here pin the temporal reading over the memory harness: a group whose
newest candidate was staged at or after the invocation's
``cleanup_completed_at_utc`` resumes through the finalizer and is revalidated
independently; a group staged before that instant is abandoned staging and
quarantined; a group whose correlation names no invocation row is quarantined
whatever its instant; the finalizer's revalidation and the terminal RESULT
restrictions (RV-8) are unchanged. The newest member decides for the group
(``_predates_cleanup`` states why): the one conclusion stages every member
after the cleanup, so a group staged on both sides of the instant is a planted
state, and it resumes whole with every member revalidated by the finalizer
rather than split by instant or quarantined for one older row.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.artifacts.models import CandidateArtifactState
from crypto_lab.artifacts.requests import EvidenceCorrelation
from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.lifecycle import EngineRunState
from crypto_lab.domain.results import Result, Success
from doubles.artifacts import (
    EVIDENCE_FILES,
    INVOCATION_CORRELATION,
    RUN_OWNER,
    MemoryFinalizationHarness,
    plant_core_evidence,
)
from doubles.experiments import INVOCATION_ID, OTHER_INVOCATION_ID, RUN_ID, sample_run

_S = CandidateArtifactState
_SHAPED_FILES = {"shaped.txt": b"Q" * 40 + b"\n"}
_SECOND_FILES = {"protocol.txt": b"engine protocol line one\n"}


def _ok[T](result: Result[T]) -> T:
    assert isinstance(result, Success), result
    return result.value


def _completed_at(invocation: CommandInvocationRecord) -> datetime:
    completed = invocation.completed_at_utc
    assert isinstance(completed, datetime), "an EXITED invocation has completed"
    return completed


def _cleaned_up_at(
    invocation: CommandInvocationRecord, instant: datetime
) -> CommandInvocationRecord:
    """The invocation with its Stage 7 cleanup completed at ``instant``."""
    payload = invocation.model_dump(mode="python")
    payload["cleanup_complete"] = True
    payload["cleanup_completed_at_utc"] = instant
    payload["revision"] = invocation.revision + 1
    payload["updated_at_utc"] = max(invocation.updated_at_utc, instant)
    return CommandInvocationRecord.model_validate(
        {
            key: value
            for key, value in payload.items()
            if value is not None and value is not MISSING
        }
    )


def _plant_cleaned_up_run(
    harness: MemoryFinalizationHarness,
) -> tuple[int, datetime]:
    """The planted run with its EXITED invocation cleaned up at its completion
    instant; returns the run revision and the cleanup instant."""
    run, invocation = harness.plant_run()
    cleanup_at = _completed_at(invocation)
    harness.store_data.tables.invocations[INVOCATION_ID] = _cleaned_up_at(
        invocation, cleanup_at
    )
    return run.revision, cleanup_at


def _stage(
    harness: MemoryFinalizationHarness,
    staged_at: datetime,
    *,
    files: dict[str, bytes] | None = None,
    correlation: EvidenceCorrelation = INVOCATION_CORRELATION,
) -> tuple[str, ...]:
    """Core evidence of the run owner staged at ``staged_at``, its rows planted;
    the harness clock moves to the staging instant when it is later."""
    candidates = plant_core_evidence(
        harness.roots.store,
        owner=RUN_OWNER,
        correlation=correlation,
        files=EVIDENCE_FILES if files is None else files,
        now_utc=staged_at,
    )
    for candidate in candidates:
        harness.store_data.candidates[candidate.candidate_artifact_id] = candidate
    lag = (staged_at - harness.clock.now_utc()).total_seconds()
    if lag > 0:
        harness.advance_clock(lag)
    return tuple(candidate.candidate_artifact_id for candidate in candidates)


@pytest.fixture
def harness(tmp_path: Path) -> MemoryFinalizationHarness:
    return MemoryFinalizationHarness(tmp_path)


@pytest.mark.parametrize("offset_seconds", [0, 1], ids=["at-cleanup", "after"])
def test_core_evidence_staged_at_or_after_the_cleanup_resumes(
    harness: MemoryFinalizationHarness, offset_seconds: int
) -> None:
    """Plan 5.1 CP-1 (EVIDENCE): core staging left before its lease by a
    conclusion that ran after the invocation's cleanup is not abandoned
    staging; step 4 resumes it through the finalizer, which revalidates it
    independently and registers it without touching the run (29.4)."""
    run_revision, cleanup_at = _plant_cleaned_up_run(harness)
    (candidate_id,) = _stage(harness, cleanup_at + timedelta(seconds=offset_seconds))
    report = _ok(harness.recover())
    assert (report.resumed, report.registered) == (1, 1)
    assert (report.quarantined, report.abandoned) == (0, 0)
    after = harness.durable()
    assert after.candidate_states[candidate_id] == "FINALIZING"
    (ref,) = after.refs
    assert ref.source_candidate_artifact_id == candidate_id
    assert after.journal_state == "REGISTERED"
    assert after.staging_files == ()
    assert after.quarantine_entries == ()
    assert after.run_revision == run_revision
    assert "RECONCILIATION_CANDIDATE_QUARANTINED" not in after.audit_actions
    assert after.audit_actions.count("FINALIZATION_REGISTERED") == 1
    assert _ok(harness.recover()).changes == 0


def test_core_evidence_staged_before_the_cleanup_is_quarantined(
    harness: MemoryFinalizationHarness,
) -> None:
    """RV-10 retained: staging older than the invocation's cleanup is abandoned
    and quarantined with its bytes; nothing resumes."""
    run_revision, cleanup_at = _plant_cleaned_up_run(harness)
    (candidate_id,) = _stage(harness, cleanup_at - timedelta(seconds=1))
    report = _ok(harness.recover())
    assert (report.resumed, report.registered, report.quarantined) == (0, 0, 1)
    after = harness.durable()
    assert after.candidate_states[candidate_id] == "QUARANTINED"
    assert after.staging_files == ()
    assert after.journal == ()
    assert after.refs == ()
    (entry,) = after.quarantine_entries
    assert entry.entry_id == candidate_id
    assert after.run_revision == run_revision
    assert after.audit_actions.count("RECONCILIATION_CANDIDATE_QUARANTINED") == 1
    assert _ok(harness.recover()).changes == 0


def test_a_group_staged_around_the_cleanup_resumes_whole(
    harness: MemoryFinalizationHarness,
) -> None:
    """The predicate is the group's: a member at or after the cleanup shows the
    conclusion staged into this group after it, so the group -- a planted mixed
    state, since the one conclusion stages every member after the cleanup (plan
    4.4 step 2) -- resumes as one request and the finalizer revalidates both
    members; the pass neither splits it by instant nor quarantines it whole for
    the older row."""
    run_revision, cleanup_at = _plant_cleaned_up_run(harness)
    (older,) = _stage(harness, cleanup_at - timedelta(seconds=1))
    (newer,) = _stage(harness, cleanup_at + timedelta(seconds=1), files=_SECOND_FILES)
    report = _ok(harness.recover())
    assert (report.resumed, report.registered, report.quarantined) == (1, 1, 0)
    after = harness.durable()
    assert after.candidate_states[older] == "FINALIZING"
    assert after.candidate_states[newer] == "FINALIZING"
    assert {ref.source_candidate_artifact_id for ref in after.refs} == {older, newer}
    assert after.journal_state == "REGISTERED"
    assert after.staging_files == ()
    assert after.run_revision == run_revision


def test_core_evidence_of_a_missing_invocation_is_quarantined(
    harness: MemoryFinalizationHarness,
) -> None:
    """RV-10 retained: staging whose INVOCATION correlation names no invocation
    row is abandoned staging, whatever its instant."""
    _, cleanup_at = _plant_cleaned_up_run(harness)
    orphaned = EvidenceCorrelation(kind="INVOCATION", invocation_id=OTHER_INVOCATION_ID)
    (candidate_id,) = _stage(
        harness, cleanup_at + timedelta(seconds=1), correlation=orphaned
    )
    report = _ok(harness.recover())
    assert (report.resumed, report.quarantined) == (0, 1)
    after = harness.durable()
    assert after.candidate_states[candidate_id] == "QUARANTINED"
    assert after.journal == ()
    assert after.staging_files == ()


def test_a_resumed_group_is_still_revalidated_by_the_finalizer(
    harness: MemoryFinalizationHarness,
) -> None:
    """29.4 and plan 5.1 CP-1: the resume is the finalizer's own validation; a
    token-shaped text staged after the cleanup is refused before T1 and
    quarantined under the finalizer's entry and audit, never registered."""
    _, cleanup_at = _plant_cleaned_up_run(harness)
    (candidate_id,) = _stage(
        harness, cleanup_at + timedelta(seconds=1), files=_SHAPED_FILES
    )
    report = _ok(harness.recover())
    assert (report.resumed, report.registered, report.abandoned) == (1, 0, 0)
    assert report.quarantined == 0  # the finalizer's quarantine, not step 4's
    after = harness.durable()
    assert after.candidate_states[candidate_id] == "QUARANTINED"
    assert after.journal == ()
    assert after.refs == ()
    assert after.staging_files == ()
    (entry,) = after.quarantine_entries
    assert entry.entry_id == candidate_id
    assert after.audit_actions.count("ARTIFACT_QUARANTINED") == 1
    assert "RECONCILIATION_CANDIDATE_QUARANTINED" not in after.audit_actions
    assert _ok(harness.recover()).changes == 0


def test_terminal_result_restrictions_hold_under_a_cleaned_up_invocation(
    harness: MemoryFinalizationHarness,
) -> None:
    """RV-8 unchanged: the RESULT candidates of a terminal attempt whose
    invocation completed its cleanup are quarantined and never finalized, and
    the attempt's root is closed."""
    plan = harness.plant_result_prestate()
    invocation = harness.store_data.tables.invocations[INVOCATION_ID]
    harness.store_data.tables.invocations[INVOCATION_ID] = _cleaned_up_at(
        invocation, _completed_at(invocation)
    )
    current = harness.store_data.tables.runs[RUN_ID]
    harness.store_data.tables.runs[RUN_ID] = sample_run(
        EngineRunState.FAILED, revision=current.revision + 1
    )
    report = _ok(harness.recover())
    assert (report.resumed, report.registered) == (0, 0)
    assert (report.quarantined, report.closed_roots) == (2, 1)
    after = harness.durable()
    assert all(state == "QUARANTINED" for state in after.candidate_states.values())
    assert after.journal == ()
    assert after.run_state == "FAILED"
    assert not plan.roots.request_path.exists()
    assert harness.validator.calls == []
