"""The shared artifact port contract suite (Stage 9 plan 4.1, 7.1; Task 5).

Every case speaks only through the ``CandidateArtifactRepository`` and
``ArtifactRepository`` member shapes of plan 4.1 and runs against two kinds: the
minimal in-memory pair of ``doubles.artifacts`` (``memory``) and the production
SQLite repositories over a migrated database (``sqlite``). The answer shapes are
the Stage 8 failure vocabulary: a missing identity is ``CORE.INVARIANT_VIOLATION``
containing ``does not exist``; a duplicate identity, a missing compare-and-swap
row and a stale revision are ``PERSISTENCE.CONCURRENCY_CONFLICT``; a wrong
replacement step, a refused domain transition and a payload of the other record
type are the invariant; and no method raises. The reference repository is the
only writer of references, through ``stage_reference`` then
``record_finalization``, and refuses a candidate payload at the boundary (plan
3.5 "candidate != reference", requirement rows F8.1-2, F8.1-3, F8.2-1, F8.2-2).
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import pytest
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.artifacts.models import (
    ArtifactFinalizationPurpose,
    ArtifactRef,
    CandidateArtifact,
    CandidateArtifactProducerKind,
    CandidateArtifactState,
    CandidateFinalization,
    FinalizationResult,
)
from crypto_lab.artifacts.ownership import RunArtifactOwner
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.persistence.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
)
from crypto_lab.persistence.unit_of_work import SqliteTransaction
from doubles.artifacts import (
    CANDIDATE_ID,
    OTHER_CANDIDATE_ID,
    RUN_MANIFEST_HASH,
    RUN_MANIFEST_ID,
    RUN_OWNER,
    SYSTEM_OWNER,
    THIRD_CANDIDATE_ID,
    MemoryArtifactRepository,
    MemoryArtifactStore,
    MemoryCandidateArtifactRepository,
    bump_candidate,
    sample_artifact_manifest,
    sample_candidate,
    sample_finalization_result,
    sample_mapping,
    sample_ref,
)
from doubles.experiments import (
    EXPERIMENT_ID,
    INSTANT,
    OTHER_INVOCATION_ID,
    OTHER_RUN_ID,
    UUID_D,
    UUID_E,
    FixedClock,
)
from persistence_support.artifacts import ArtifactHarness
from persistence_support.harness import code, ok, open_test_database

_S = CandidateArtifactState
_F = ArtifactFinalizationPurpose
_P = CandidateArtifactProducerKind
#: Two more candidate identities beside the three ``doubles.artifacts`` names.
_EVIDENCE_CANDIDATE_ID = f"cand_{UUID_D}"
_SYSTEM_CANDIDATE_ID = f"cand_{UUID_E}"
#: The RUN owner of another run's attempt: a valid owner for a RESULT
#: finalization, and never a row (the result is the input, not what is stored).
_OTHER_RUN_OWNER = RunArtifactOwner(
    owner_kind="RUN",
    experiment_id=EXPERIMENT_ID,
    run_id=OTHER_RUN_ID,
    invocation_id=OTHER_INVOCATION_ID,
)


# --------------------------------------------------------------------------
# The two kinds behind one factory fixture (plan 7.1: kinds ``memory``, ``sqlite``)
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _MemoryPorts:
    """The memory pair over one store; ``commit`` publishes nothing extra."""

    candidate_artifacts: MemoryCandidateArtifactRepository
    artifact_refs: MemoryArtifactRepository

    def commit(self) -> Result[None]:
        return Success[None](outcome="SUCCESS", value=None)

    def rollback(self) -> None:
        return None


class ContractHarness(Protocol):
    """One backing store, its pre-state and the ability to open the two ports."""

    def seed(self) -> None: ...

    def begin(self) -> SqliteTransaction | _MemoryPorts: ...

    def committed_candidates(self) -> tuple[CandidateArtifact, ...]: ...

    def committed_refs(self) -> tuple[ArtifactRef, ...]: ...


@dataclass(frozen=True, slots=True)
class _MemoryHarness:
    store: MemoryArtifactStore

    def seed(self) -> None:
        return None

    def begin(self) -> _MemoryPorts:
        return _MemoryPorts(
            MemoryCandidateArtifactRepository(self.store),
            MemoryArtifactRepository(self.store),
        )

    def committed_candidates(self) -> tuple[CandidateArtifact, ...]:
        return self.store.committed_candidates()

    def committed_refs(self) -> tuple[ArtifactRef, ...]:
        return self.store.committed_refs()


@dataclass(frozen=True, slots=True)
class _SqliteHarness:
    inner: ArtifactHarness

    def seed(self) -> None:
        self.inner.seed_result_prestate()

    def begin(self) -> SqliteTransaction:
        return self.inner.begin()

    def committed_candidates(self) -> tuple[CandidateArtifact, ...]:
        return self.inner.committed_candidates()

    def committed_refs(self) -> tuple[ArtifactRef, ...]:
        return self.inner.committed_refs()


@pytest.fixture(params=["memory", "sqlite"])
def harness(
    request: pytest.FixtureRequest, tmp_path: Path
) -> Iterator[ContractHarness]:
    if request.param == "memory":
        yield _MemoryHarness(MemoryArtifactStore())
        return
    inner = ArtifactHarness(open_test_database(tmp_path, clock=FixedClock(INSTANT)))
    try:
        yield _SqliteHarness(inner)
    finally:
        inner.close()


def _message(result: object) -> str:
    assert isinstance(result, Failure), result
    return result.diagnostics[0].message


def _commit(ports: SqliteTransaction | _MemoryPorts) -> None:
    committed = ports.commit()
    assert isinstance(committed, Success), committed


def _put_candidate(
    harness: ContractHarness, record: CandidateArtifact
) -> CandidateArtifact:
    ports = harness.begin()
    ok(ports.candidate_artifacts.add(record))
    _commit(ports)
    return record


def _finalize(
    harness: ContractHarness, candidate: CandidateArtifact
) -> CandidateArtifact:
    """Drive a committed ``CANDIDATE`` to ``FINALIZING`` through the port."""
    ports = harness.begin()
    validating = ok(
        ports.candidate_artifacts.compare_and_swap(
            candidate.revision, bump_candidate(candidate, _S.VALIDATING)
        )
    )
    finalizing = ok(
        ports.candidate_artifacts.compare_and_swap(
            validating.revision, bump_candidate(validating, _S.FINALIZING)
        )
    )
    _commit(ports)
    return finalizing


def _record(harness: ContractHarness, ref: ArtifactRef) -> ArtifactRef:
    ports = harness.begin()
    ok(ports.artifact_refs.stage_reference(ref, sample_artifact_manifest(ref)))
    result = sample_finalization_result((ref,))
    (recorded,) = ok(ports.artifact_refs.record_finalization(result))
    _commit(ports)
    return recorded


def _stage(ports: SqliteTransaction | _MemoryPorts, *refs: ArtifactRef) -> None:
    for ref in refs:
        ok(ports.artifact_refs.stage_reference(ref, sample_artifact_manifest(ref)))


def _by_identity(*refs: ArtifactRef) -> tuple[ArtifactRef, ...]:
    """``committed_refs()`` order: by ``artifact_id``."""
    return tuple(sorted(refs, key=lambda ref: ref.artifact_id))


def _finalizing(harness: ContractHarness, **fields: Any) -> ArtifactRef:
    """The reference of a committed ``FINALIZING`` candidate built from ``fields``."""
    candidate = sample_candidate(state=_S.FINALIZING, **fields)
    return sample_ref(_put_candidate(harness, candidate))


#: One later-item refusal: label, the staged references, the result, the message.
_Scenario = tuple[str, tuple[ArtifactRef, ...], FinalizationResult, str]


def _as_evidence(refs: tuple[ArtifactRef, ...]) -> FinalizationResult:
    """A valid EVIDENCE finalization over the mappings of ``refs`` (RESULT
    references included): the purpose flipped and the run-manifest facts an
    EVIDENCE result may not carry removed."""
    return sample_finalization_result(
        refs,
        finalization_purpose=_F.EVIDENCE,
        run_manifest_id=MISSING,
        run_manifest_hash=MISSING,
    )


def _as_result(refs: tuple[ArtifactRef, ...]) -> FinalizationResult:
    """A valid RESULT finalization over the mappings of ``refs`` (EVIDENCE
    references included): the purpose flipped and both run-manifest facts
    supplied; its owner is the first reference's RUN owner."""
    return sample_finalization_result(
        refs,
        finalization_purpose=_F.RESULT,
        run_manifest_id=RUN_MANIFEST_ID,
        run_manifest_hash=RUN_MANIFEST_HASH,
    )


# --------------------------------------------------------------------------
# F8.1-2, F8.1-3, F8.2-1, F8.2-2: the two shapes never inhabit each other's port
# --------------------------------------------------------------------------


def test_reference_repository_refuses_candidate_payload(
    harness: ContractHarness,
) -> None:
    harness.seed()
    finalizing = _finalize(harness, _put_candidate(harness, sample_candidate()))
    ref = sample_ref(finalizing)
    manifest = sample_artifact_manifest(ref)
    foreign: Any = finalizing
    ports = harness.begin()
    # The write boundary refuses the candidate as a reference and stages nothing.
    refused = ports.artifact_refs.stage_reference(foreign, manifest)
    assert code(refused) == INVARIANT_VIOLATION
    unstaged = ports.artifact_refs.record_finalization(
        sample_finalization_result((ref,))
    )
    assert code(unstaged) == INVARIANT_VIOLATION
    assert "not staged" in _message(unstaged)
    # A candidate identity is no reference identity.
    missing = ports.artifact_refs.get(finalizing.candidate_artifact_id)
    assert code(missing) == INVARIANT_VIOLATION
    assert "does not exist" in _message(missing)
    # And the candidate port refuses a reference payload the same way.
    reference_payload: Any = ref
    assert code(ports.candidate_artifacts.add(reference_payload)) == INVARIANT_VIOLATION
    _commit(ports)
    assert harness.committed_refs() == ()
    assert harness.committed_candidates() == (finalizing,)


# --------------------------------------------------------------------------
# The plan 4.1 answer shapes, per method
# --------------------------------------------------------------------------


def test_candidate_get_and_add_answer_shapes(harness: ContractHarness) -> None:
    harness.seed()
    record = sample_candidate()
    ports = harness.begin()
    missing = ports.candidate_artifacts.get(CANDIDATE_ID)
    assert code(missing) == INVARIANT_VIOLATION
    assert "does not exist" in _message(missing)
    assert ok(ports.candidate_artifacts.add(record)) is None
    assert code(ports.candidate_artifacts.add(record)) == CONCURRENCY_CONFLICT
    assert ok(ports.candidate_artifacts.get(CANDIDATE_ID)) == record
    _commit(ports)
    assert harness.committed_candidates() == (record,)


def test_candidate_compare_and_swap_precedence(harness: ContractHarness) -> None:
    """Stage 8 plan 4.3.1 verbatim: missing -> conflict, stale -> conflict, wrong
    step -> invariant, refused edge -> invariant, valid -> the replacement."""
    harness.seed()
    stored = _put_candidate(harness, sample_candidate())
    ports = harness.begin()
    repository = ports.candidate_artifacts
    absent = sample_candidate(candidate_artifact_id=OTHER_CANDIDATE_ID)
    missing_row = repository.compare_and_swap(0, bump_candidate(absent, _S.VALIDATING))
    assert code(missing_row) == CONCURRENCY_CONFLICT
    assert "does not exist for compare-and-swap" in _message(missing_row)
    stale = repository.compare_and_swap(
        stored.revision + 5, bump_candidate(stored, _S.VALIDATING)
    )
    assert code(stale) == CONCURRENCY_CONFLICT
    skipped = bump_candidate(bump_candidate(stored, _S.VALIDATING), _S.FINALIZING)
    wrong_step = repository.compare_and_swap(stored.revision, skipped)
    assert code(wrong_step) == INVARIANT_VIOLATION
    # CANDIDATE -> FINALIZING is not a candidate edge (plan 4.3 phases 0-3).
    leap = repository.compare_and_swap(
        stored.revision, bump_candidate(stored, _S.FINALIZING)
    )
    assert code(leap) == INVARIANT_VIOLATION
    assert "not a permitted candidate edge" in _message(leap)
    assert ok(repository.get(CANDIDATE_ID)) == stored
    validating = bump_candidate(stored, _S.VALIDATING)
    assert ok(repository.compare_and_swap(stored.revision, validating)) == validating
    quarantined = bump_candidate(validating, _S.QUARANTINED)
    swapped = repository.compare_and_swap(validating.revision, quarantined)
    assert ok(swapped) == quarantined
    # A terminal candidate accepts no further write.
    frozen = repository.compare_and_swap(
        quarantined.revision, bump_candidate(quarantined, _S.CORRUPT)
    )
    assert code(frozen) == INVARIANT_VIOLATION
    assert "terminal candidate" in _message(frozen)
    _commit(ports)
    assert harness.committed_candidates() == (quarantined,)


def test_list_recoverable_filters_and_excludes_mapped_candidates(
    harness: ContractHarness,
) -> None:
    """Plan 4.1: ``list_recoverable`` answers the requested states for the optional
    owner and purpose, sorted by identity, and never a ``FINALIZING`` candidate
    that already has a reference (RV-12, 19.1:1358)."""
    harness.seed()
    mapped = _finalize(harness, _put_candidate(harness, sample_candidate()))
    _record(harness, sample_ref(mapped))
    pending = _finalize(
        harness,
        _put_candidate(
            harness, sample_candidate(candidate_artifact_id=OTHER_CANDIDATE_ID)
        ),
    )
    quarantined = sample_candidate(
        "SYSTEM",
        _F.EVIDENCE,
        producer=_P.CORE,
        state=_S.QUARANTINED,
        candidate_artifact_id=THIRD_CANDIDATE_ID,
    )
    _put_candidate(harness, quarantined)
    both = (_S.FINALIZING, _S.QUARANTINED)
    ports = harness.begin()
    repository = ports.candidate_artifacts
    assert ok(repository.list_recoverable((_S.FINALIZING,))) == (pending,)
    assert ok(repository.list_recoverable(both)) == (quarantined, pending)
    by_run = repository.list_recoverable((_S.FINALIZING,), owner=RUN_OWNER)
    assert ok(by_run) == (pending,)
    assert ok(repository.list_recoverable((_S.QUARANTINED,), owner=RUN_OWNER)) == ()
    by_system = repository.list_recoverable(both, owner=SYSTEM_OWNER)
    assert ok(by_system) == (quarantined,)
    evidence = repository.list_recoverable(both, purpose=_F.EVIDENCE)
    assert ok(evidence) == (quarantined,)
    assert ok(repository.list_recoverable(both, limit=1)) == (quarantined,)
    assert ok(repository.list_recoverable((_S.CANDIDATE,))) == ()
    # The mapped candidate is still readable and still FINALIZING; it is excluded,
    # not touched.
    assert ok(repository.get(CANDIDATE_ID)) == mapped
    ports.rollback()


def test_reference_answer_shapes_and_record_finalization(
    harness: ContractHarness,
) -> None:
    harness.seed()
    candidate = _put_candidate(harness, sample_candidate())
    ref = sample_ref(candidate)
    manifest = sample_artifact_manifest(ref)
    result = sample_finalization_result((ref,))
    ports = harness.begin()
    refs = ports.artifact_refs
    missing = refs.get(ref.artifact_id)
    assert code(missing) == INVARIANT_VIOLATION
    assert "does not exist" in _message(missing)
    assert code(refs.get_manifest(ref.artifact_id)) == INVARIANT_VIOLATION
    assert ok(refs.list_by_owner(RUN_OWNER)) == ()
    unstaged = refs.record_finalization(result)
    assert code(unstaged) == INVARIANT_VIOLATION
    assert "not staged" in _message(unstaged)
    # A staged manifest must describe the reference it accompanies.
    other = sample_ref(candidate, content_hash="f" * 64)
    disagreeing = refs.stage_reference(ref, sample_artifact_manifest(other))
    assert code(disagreeing) == INVARIANT_VIOLATION
    assert ok(refs.stage_reference(ref, manifest)) is None
    # The staged reference must match its mapping.
    mismatched = sample_finalization_result(
        (ref,),
        candidate_to_artifact_refs=(
            CandidateFinalization(
                candidate_artifact_id=ref.source_candidate_artifact_id,
                artifact_id=ref.artifact_id,
                content_hash=ref.content_hash,
                size_bytes=ref.size_bytes + 1,
                deduplicated=False,
            ),
        ),
    )
    mismatch = refs.record_finalization(mismatched)
    assert code(mismatch) == INVARIANT_VIOLATION
    assert "does not match its mapping" in _message(mismatch)
    # The source candidate is still CANDIDATE: no reference may be recorded.
    not_finalizing = refs.record_finalization(result)
    assert code(not_finalizing) == INVARIANT_VIOLATION
    assert "is not FINALIZING" in _message(not_finalizing)
    _commit(ports)
    assert harness.committed_refs() == ()
    finalizing = _finalize(harness, candidate)
    ports = harness.begin()
    refs = ports.artifact_refs
    ok(refs.stage_reference(ref, manifest))
    assert ok(refs.record_finalization(result)) == (ref,)
    assert ok(refs.get(ref.artifact_id)) == ref
    assert ok(refs.get_manifest(ref.artifact_id)) == manifest
    assert ok(refs.list_by_owner(RUN_OWNER)) == (ref,)
    assert ok(refs.list_by_owner(RUN_OWNER, _F.RESULT)) == (ref,)
    assert ok(refs.list_by_owner(RUN_OWNER, _F.EVIDENCE)) == ()
    assert ok(refs.list_by_owner(SYSTEM_OWNER)) == ()
    # A second recording of the same identity is the conflict, not an exception.
    ok(refs.stage_reference(ref, manifest))
    assert code(refs.record_finalization(result)) == CONCURRENCY_CONFLICT
    _commit(ports)
    assert harness.committed_refs() == (ref,)
    assert harness.committed_candidates() == (finalizing,)


# --------------------------------------------------------------------------
# Staged pairs are transaction-local: rollback and closure discard them
# --------------------------------------------------------------------------


def test_staged_references_do_not_survive_rollback_or_closure(
    harness: ContractHarness,
) -> None:
    """A pair staged with ``stage_reference`` belongs to the transaction that
    staged it: after ``rollback()``, and after ``commit()`` without recording, a
    later transaction finds nothing staged -- exactly as SQLite's per-transaction
    repository answers -- while a pair staged and recorded in one transaction is
    durable and reads back in a later one."""
    harness.seed()
    finalizing = _finalize(harness, _put_candidate(harness, sample_candidate()))
    ref = sample_ref(finalizing)
    manifest = sample_artifact_manifest(ref)
    result = sample_finalization_result((ref,))
    abandoned = harness.begin()
    ok(abandoned.artifact_refs.stage_reference(ref, manifest))
    abandoned.rollback()
    later = harness.begin()
    unstaged = later.artifact_refs.record_finalization(result)
    assert code(unstaged) == INVARIANT_VIOLATION
    assert "not staged" in _message(unstaged)
    # Closing a transaction without recording discards its staging as well.
    ok(later.artifact_refs.stage_reference(ref, manifest))
    _commit(later)
    assert harness.committed_refs() == ()
    closed = harness.begin()
    discarded = closed.artifact_refs.record_finalization(result)
    assert code(discarded) == INVARIANT_VIOLATION
    assert "not staged" in _message(discarded)
    # Staged and recorded in one transaction, the pair is durable.
    ok(closed.artifact_refs.stage_reference(ref, manifest))
    assert ok(closed.artifact_refs.record_finalization(result)) == (ref,)
    _commit(closed)
    assert harness.committed_refs() == (ref,)
    reader = harness.begin()
    assert ok(reader.artifact_refs.get(ref.artifact_id)) == ref
    assert ok(reader.artifact_refs.get_manifest(ref.artifact_id)) == manifest
    reader.rollback()


# --------------------------------------------------------------------------
# record_finalization records the references of one finalization, all or none
# --------------------------------------------------------------------------


def test_record_finalization_refuses_another_owner_or_purpose(
    harness: ContractHarness,
) -> None:
    """Plan 4.1: ``record_finalization(result)`` inserts the references *of that
    finalization*, so a staged reference must carry the result's owner and
    purpose; one that does not is ``CORE.INVARIANT_VIOLATION``, inserts nothing
    and leaves the transaction usable. Every record here is a valid canonical
    record -- the result is the input and never a row, so a RESULT finalization
    of another run's attempt needs no run -- and the same staged pairs record
    under their matching finalizations afterwards."""
    harness.seed()
    result_ref = _finalizing(harness)
    evidence_ref = _finalizing(
        harness,
        owner_kind="RUN",
        purpose=_F.EVIDENCE,
        producer=_P.CORE,
        candidate_artifact_id=_EVIDENCE_CANDIDATE_ID,
    )
    mismatched: tuple[tuple[FinalizationResult, str], ...] = (
        # A RESULT finalization of another run's attempt naming this run's
        # reference.
        (sample_finalization_result((result_ref,), owner=_OTHER_RUN_OWNER), "owner"),
        # A SYSTEM-owned EVIDENCE finalization naming a RUN-owned evidence
        # reference.
        (sample_finalization_result((evidence_ref,), owner=SYSTEM_OWNER), "owner"),
        # An EVIDENCE finalization naming a RESULT reference, and the reverse.
        (_as_evidence((result_ref,)), "purpose"),
        (_as_result((evidence_ref,)), "purpose"),
    )
    ports = harness.begin()
    refs = ports.artifact_refs
    _stage(ports, result_ref, evidence_ref)
    for result, fragment in mismatched:
        refused = refs.record_finalization(result)
        assert code(refused) == INVARIANT_VIOLATION, fragment
        assert f"does not carry the finalization's {fragment}" in _message(refused)
    for ref in (result_ref, evidence_ref):
        missing = refs.get(ref.artifact_id)
        assert code(missing) == INVARIANT_VIOLATION
        assert "does not exist" in _message(missing)
    # The matching finalizations record the very same staged pairs.
    matching = sample_finalization_result((result_ref,))
    assert ok(refs.record_finalization(matching)) == (result_ref,)
    evidence = sample_finalization_result((evidence_ref,))
    assert ok(refs.record_finalization(evidence)) == (evidence_ref,)
    _commit(ports)
    assert harness.committed_refs() == _by_identity(result_ref, evidence_ref)


def test_a_later_mapping_refusal_records_none_of_the_batch(
    harness: ContractHarness,
) -> None:
    """Every mapping is validated before the first insert: a valid first mapping
    followed by a refused second one records neither -- the first is unreadable
    in the same transaction and absent after that transaction commits -- for
    each validation refusal (not staged, mapping mismatch, another owner,
    another purpose, not ``FINALIZING``); a pre-existing reference is unchanged
    throughout; and a valid two-reference batch answers both references in
    mapping order."""
    harness.seed()
    existing = _record(harness, _finalizing(harness))
    first = _finalizing(harness, candidate_artifact_id=OTHER_CANDIDATE_ID)
    pending_candidate = _put_candidate(
        harness, sample_candidate(candidate_artifact_id=THIRD_CANDIDATE_ID)
    )
    pending = sample_ref(pending_candidate)
    run_evidence = _finalizing(
        harness,
        owner_kind="RUN",
        purpose=_F.EVIDENCE,
        producer=_P.CORE,
        candidate_artifact_id=_EVIDENCE_CANDIDATE_ID,
    )
    system_evidence = _finalizing(
        harness,
        owner_kind="SYSTEM",
        purpose=_F.EVIDENCE,
        producer=_P.CORE,
        candidate_artifact_id=_SYSTEM_CANDIDATE_ID,
    )
    shorter = CandidateFinalization(
        candidate_artifact_id=pending.source_candidate_artifact_id,
        artifact_id=pending.artifact_id,
        content_hash=pending.content_hash,
        size_bytes=pending.size_bytes + 1,
        deduplicated=False,
    )
    scenarios: tuple[_Scenario, ...] = (
        (
            "second not staged",
            (first,),
            sample_finalization_result((first, pending)),
            "not staged",
        ),
        (
            "second mapping mismatch",
            (first, pending),
            sample_finalization_result(
                (first, pending),
                candidate_to_artifact_refs=(sample_mapping(first), shorter),
            ),
            "does not match its mapping",
        ),
        (
            "second of another owner",
            (run_evidence, system_evidence),
            sample_finalization_result((run_evidence, system_evidence)),
            "does not carry the finalization's owner",
        ),
        (
            "second of another purpose",
            (first, run_evidence),
            sample_finalization_result((first, run_evidence)),
            "does not carry the finalization's purpose",
        ),
        (
            "second not FINALIZING",
            (first, pending),
            sample_finalization_result((first, pending)),
            "is not FINALIZING",
        ),
    )
    for label, staged, result, fragment in scenarios:
        ports = harness.begin()
        refs = ports.artifact_refs
        _stage(ports, *staged)
        refused = refs.record_finalization(result)
        assert code(refused) == INVARIANT_VIOLATION, label
        assert fragment in _message(refused), label
        # Neither mapping was inserted: the valid first one is unreadable in this
        # very transaction, and a successful commit publishes nothing of it.
        missing = refs.get(staged[0].artifact_id)
        assert code(missing) == INVARIANT_VIOLATION, label
        assert "does not exist" in _message(missing), label
        _commit(ports)
        assert harness.committed_refs() == (existing,), label
    # A valid two-reference batch, recorded in the order that is not the sorted
    # order, answers both references in mapping order.
    second = sample_ref(_finalize(harness, pending_candidate))
    batch = tuple(
        sorted((first, second), key=lambda ref: ref.artifact_id, reverse=True)
    )
    ports = harness.begin()
    _stage(ports, *batch)
    result = sample_finalization_result(batch)
    assert ok(ports.artifact_refs.record_finalization(result)) == batch
    _commit(ports)
    assert harness.committed_refs() == _by_identity(existing, first, second)
