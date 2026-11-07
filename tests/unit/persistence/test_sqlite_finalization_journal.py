"""The SQLite finalization journal (Stage 9 plan 3.3, 4.1, 4.3; Task 5).

One active RESULT lease per attempt: the partial unique index over ``run_id``
for a ``RESULT`` entry in ``PREPARED`` or ``MOVED`` refuses a second open lease
as ``PERSISTENCE.CONCURRENCY_CONFLICT`` until the first leaves those states
(23.3:1688); the RESULT identity index refuses a replay of an identity whatever
its state. RESULT and EVIDENCE identities are disjoint: ``find_result_identity``
and ``find_evidence_identity`` answer each purpose's entry and ``MISSING`` for
the other. A lease renewal advances ``lease_expires_at_utc`` and nothing else and
never passes the finalization deadline -- the record refuses it, the table
``CHECK`` refuses a raw write of it and the monotonic trigger refuses a raw change
of the deadline, every refusal ``CORE.INVARIANT_VIOLATION``. ``get`` answers the
invariant containing ``does not exist`` for a missing identity, ``prepare``
admits ``PREPARED`` alone and refuses a repeated identity as the conflict, and
``list_open`` answers the ``PREPARED`` and ``MOVED`` entries in preparation order.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from crypto_lab.artifacts.journal import (
    FinalizationJournalEntry,
    FinalizationJournalState,
)
from crypto_lab.artifacts.models import ArtifactFinalizationPurpose
from crypto_lab.artifacts.ownership import artifact_owner_hash
from crypto_lab.domain.hashing import candidate_set_hash_for
from crypto_lab.domain.results import Failure, Result
from crypto_lab.persistence.codecs import utc_to_micros
from crypto_lab.persistence.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
)
from doubles.artifacts import (
    DEADLINE,
    DIAGNOSTIC_CORRELATION,
    INVOCATION_CORRELATION,
    LEASE_EXPIRY,
    OTHER_CANDIDATE_ID,
    RUN_OWNER,
    SOURCE_MANIFEST_HASH,
    SYSTEM_OWNER,
    THIRD_CANDIDATE_ID,
    bump_journal,
    renew_journal,
    sample_journal,
)
from doubles.experiments import DIAG_ID, INSTANT, INVOCATION_ID, OTHER_INVOCATION_ID
from persistence_support.artifacts import ArtifactHarness
from persistence_support.harness import code, commit, ok

_J = FinalizationJournalState
_F = ArtifactFinalizationPurpose
_OTHER_SOURCE_HASH = "b" * 64
_BY_IDENTITY = "finalization_id"


def _message(result: object) -> str:
    assert isinstance(result, Failure), result
    return result.diagnostics[0].message


def _absent(result: Result[Any]) -> bool:
    """Is ``result`` the ``Success(MISSING)`` answer of an identity probe?"""
    return not isinstance(ok(result), FinalizationJournalEntry)


def _sorted(*entries: FinalizationJournalEntry) -> tuple[FinalizationJournalEntry, ...]:
    return tuple(sorted(entries, key=lambda entry: getattr(entry, _BY_IDENTITY)))


def test_one_active_result_lease_per_attempt(
    artifact_harness: ArtifactHarness,
) -> None:
    artifact_harness.seed_result_prestate()
    first = sample_journal(_J.PREPARED, _F.RESULT)
    second = sample_journal(
        _J.PREPARED,
        _F.RESULT,
        candidate_artifact_ids=(OTHER_CANDIDATE_ID,),
        source_adapter_result_manifest_hash=_OTHER_SOURCE_HASH,
    )
    assert first.finalization_id != second.finalization_id
    artifact_harness.put_journal(first)
    # A second open RESULT lease for the same run is refused by the partial
    # unique index, classified as the conflict; nothing is written.
    transaction = artifact_harness.begin()
    refused = transaction.finalization_journal.prepare(second)
    assert code(refused) == CONCURRENCY_CONFLICT
    commit(transaction)
    assert artifact_harness.committed_journal() == (first,)
    # Once the first lease leaves PREPARED/MOVED the slot is free again.
    transaction = artifact_harness.begin()
    abandoned = ok(
        transaction.finalization_journal.compare_and_swap(
            first.revision, bump_journal(first, _J.ABANDONED)
        )
    )
    ok(transaction.finalization_journal.prepare(second))
    commit(transaction)
    assert artifact_harness.committed_journal() == _sorted(abandoned, second)
    # The RESULT identity itself is unique whatever its state: a replay of the
    # abandoned identity is the conflict too.
    transaction = artifact_harness.begin()
    replay = transaction.finalization_journal.prepare(first)
    assert code(replay) == CONCURRENCY_CONFLICT
    transaction.rollback()
    # EVIDENCE entries hold no run lease: two open ones for one owner coexist.
    transaction = artifact_harness.begin()
    evidence = sample_journal(_J.PREPARED, _F.EVIDENCE)
    sibling = sample_journal(
        _J.PREPARED, _F.EVIDENCE, candidate_artifact_ids=(THIRD_CANDIDATE_ID,)
    )
    ok(transaction.finalization_journal.prepare(evidence))
    ok(transaction.finalization_journal.prepare(sibling))
    commit(transaction)
    assert len(artifact_harness.committed_journal()) == 4


def test_result_and_evidence_identities_disjoint(
    artifact_harness: ArtifactHarness,
) -> None:
    artifact_harness.seed_result_prestate()
    result = sample_journal(_J.PREPARED, _F.RESULT)
    evidence = sample_journal(_J.PREPARED, _F.EVIDENCE)
    assert result.finalization_id != evidence.finalization_id
    artifact_harness.put_journal(result)
    artifact_harness.put_journal(evidence)
    transaction = artifact_harness.begin()
    journal = transaction.finalization_journal
    found_result = journal.find_result_identity(INVOCATION_ID, SOURCE_MANIFEST_HASH)
    assert ok(found_result) == result
    system_hash = artifact_owner_hash(SYSTEM_OWNER)
    set_hash = evidence.candidate_set_hash
    found_evidence = journal.find_evidence_identity(
        system_hash, "DIAGNOSTIC", DIAG_ID, set_hash
    )
    assert ok(found_evidence) == evidence
    # Each identity space answers MISSING for the other purpose's facts and for
    # any changed component of its own tuple.
    run_hash = artifact_owner_hash(RUN_OWNER)
    other_set_hash = candidate_set_hash_for((OTHER_CANDIDATE_ID,))
    assert other_set_hash != set_hash
    probes = (
        journal.find_result_identity(INVOCATION_ID, _OTHER_SOURCE_HASH),
        journal.find_result_identity(OTHER_INVOCATION_ID, SOURCE_MANIFEST_HASH),
        journal.find_evidence_identity(run_hash, "DIAGNOSTIC", DIAG_ID, set_hash),
        journal.find_evidence_identity(
            system_hash, "INVOCATION", INVOCATION_ID, set_hash
        ),
        journal.find_evidence_identity(
            system_hash, "DIAGNOSTIC", DIAG_ID, other_set_hash
        ),
    )
    assert all(_absent(probe) for probe in probes)
    # The same owner and correlation over a different candidate set is a distinct
    # EVIDENCE identity and coexists; the same tuple again is the conflict.
    sibling = sample_journal(
        _J.PREPARED, _F.EVIDENCE, candidate_artifact_ids=(THIRD_CANDIDATE_ID,)
    )
    assert sibling.finalization_id != evidence.finalization_id
    ok(journal.prepare(sibling))
    assert code(journal.prepare(evidence)) == CONCURRENCY_CONFLICT
    # A different correlation over the same set is distinct as well.
    other_link = sample_journal(
        _J.PREPARED, _F.EVIDENCE, correlation=INVOCATION_CORRELATION
    )
    ok(journal.prepare(other_link))
    assert ok(journal.list_open(_F.RESULT)) == (result,)
    assert ok(journal.list_open(_F.EVIDENCE)) == _sorted(evidence, sibling, other_link)
    assert len(ok(journal.list_open())) == 4
    commit(transaction)
    assert DIAGNOSTIC_CORRELATION.correlation_id == DIAG_ID


def test_renew_never_extends_deadline(artifact_harness: ArtifactHarness) -> None:
    artifact_harness.seed_result_prestate()
    prepared = sample_journal(_J.PREPARED, _F.RESULT)
    assert prepared.finalization_deadline_utc == DEADLINE
    assert prepared.lease_expires_at_utc == LEASE_EXPIRY
    artifact_harness.put_journal(prepared)
    # The record refuses a lease past the deadline before any write.
    with pytest.raises(ValidationError, match="must not pass the finalization"):
        renew_journal(prepared, DEADLINE + timedelta(seconds=1))
    transaction = artifact_harness.begin()
    journal = transaction.finalization_journal
    # A renewal up to the deadline is the one lawful same-state write.
    renewal = renew_journal(prepared, DEADLINE)
    renewed = ok(journal.compare_and_swap(prepared.revision, renewal))
    assert renewed.lease_expires_at_utc == DEADLINE
    assert renewed.finalization_deadline_utc == DEADLINE
    assert renewed.state is _J.PREPARED
    # A same-state write that does not advance the lease is refused.
    stalled_write = journal.compare_and_swap(
        renewed.revision, renew_journal(renewed, DEADLINE)
    )
    assert code(stalled_write) == INVARIANT_VIOLATION
    assert "must advance" in _message(stalled_write)
    # A write that moves the deadline is refused: the deadline is immutable.
    later = DEADLINE + timedelta(minutes=1)
    retargeted = bump_journal(
        renewed,
        _J.PREPARED,
        finalization_deadline_utc=later,
        lease_expires_at_utc=later,
    )
    retarget_write = journal.compare_and_swap(renewed.revision, retargeted)
    assert code(retarget_write) == INVARIANT_VIOLATION
    assert "finalization_deadline_utc is immutable" in _message(retarget_write)
    commit(transaction)
    assert artifact_harness.committed_journal() == (renewed,)
    # The table refuses the same two writes raw: the lease CHECK and the
    # monotonic trigger, both the invariant.
    beyond = artifact_harness.refuse(
        "UPDATE finalization_journal SET lease_expires_at_utc = ? "
        "WHERE finalization_id = ?",
        (utc_to_micros(DEADLINE + timedelta(seconds=1)), prepared.finalization_id),
    )
    assert beyond.code == INVARIANT_VIOLATION
    assert "lease_within_deadline" in beyond.message
    shifted = artifact_harness.refuse(
        "UPDATE finalization_journal SET finalization_deadline_utc = ? "
        "WHERE finalization_id = ?",
        (utc_to_micros(later), prepared.finalization_id),
    )
    assert shifted.code == INVARIANT_VIOLATION
    assert "deadline is immutable" in shifted.message
    assert artifact_harness.committed_journal() == (renewed,)
    # An EVIDENCE lease has no deadline: it renews arbitrarily far (reading 13).
    evidence = sample_journal(_J.PREPARED, _F.EVIDENCE)
    artifact_harness.put_journal(evidence)
    transaction = artifact_harness.begin()
    far = renew_journal(evidence, INSTANT + timedelta(days=30))
    renewed_far = transaction.finalization_journal.compare_and_swap(
        evidence.revision, far
    )
    assert ok(renewed_far) == far
    commit(transaction)


def test_find_identity_methods(artifact_harness: ArtifactHarness) -> None:
    artifact_harness.seed_result_prestate()
    prepared = sample_journal(_J.PREPARED, _F.RESULT)
    moved = sample_journal(_J.MOVED, _F.RESULT)
    evidence = sample_journal(_J.PREPARED, _F.EVIDENCE)
    system_hash = artifact_owner_hash(SYSTEM_OWNER)
    transaction = artifact_harness.begin()
    journal = transaction.finalization_journal
    # Nothing is stored yet: the probes answer MISSING, the read the invariant.
    assert _absent(journal.find_result_identity(INVOCATION_ID, SOURCE_MANIFEST_HASH))
    assert _absent(
        journal.find_evidence_identity(
            system_hash, "DIAGNOSTIC", DIAG_ID, evidence.candidate_set_hash
        )
    )
    missing = journal.get(prepared.finalization_id)
    assert code(missing) == INVARIANT_VIOLATION
    assert "does not exist" in _message(missing)
    assert ok(journal.list_open()) == ()
    # prepare admits PREPARED alone.
    refused = journal.prepare(moved)
    assert code(refused) == INVARIANT_VIOLATION
    assert "must be prepared in state PREPARED" in _message(refused)
    assert ok(journal.prepare(prepared)) is None
    assert code(journal.prepare(prepared)) == CONCURRENCY_CONFLICT
    assert ok(journal.get(prepared.finalization_id)) == prepared
    found = journal.find_result_identity(INVOCATION_ID, SOURCE_MANIFEST_HASH)
    assert ok(found) == prepared
    ok(journal.prepare(evidence))
    commit(transaction)
    # list_open follows the state: MOVED stays open, REGISTERED and ABANDONED close.
    transaction = artifact_harness.begin()
    journal = transaction.finalization_journal
    advanced = ok(
        journal.compare_and_swap(prepared.revision, bump_journal(prepared, _J.MOVED))
    )
    assert ok(journal.list_open(_F.RESULT)) == (advanced,)
    registration = bump_journal(advanced, _J.REGISTERED)
    registered = ok(journal.compare_and_swap(advanced.revision, registration))
    assert ok(journal.list_open(_F.RESULT)) == ()
    assert ok(journal.list_open()) == (evidence,)
    found = journal.find_result_identity(INVOCATION_ID, SOURCE_MANIFEST_HASH)
    assert ok(found) == registered
    abandonment = bump_journal(evidence, _J.ABANDONED)
    closed = ok(journal.compare_and_swap(evidence.revision, abandonment))
    assert ok(journal.list_open()) == ()
    assert closed.abandon_reason == "ARTIFACT.VALIDATION_FAILED"
    commit(transaction)
    assert artifact_harness.committed_journal() == _sorted(registered, closed)
