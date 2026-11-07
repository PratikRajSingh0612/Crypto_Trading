"""The six Stage 9 repositories, the Stage 9 codecs, the in-transaction diagnostic
writer, the lease facts and the artifact consistency counts over SQLite (Stage 9
plan 3.3, 4.1, 4.7; Task 5).

Every new row round-trips through its production codec and repository and reads
back equal from a fresh session; egress re-validates the stored row and refuses a
reinterpretation as ``CORE.INVARIANT_VIOLATION`` (reading 10); registering a
reference leaves its candidate an immutable historical ``FINALIZING`` record
(R19.2-06) that ``list_recoverable`` no longer lists (RV-12); references are never
updated (RV-13); the candidate and journal compare-and-swaps keep the Stage 8
4.3.1 order verbatim; ``SqliteDiagnosticWriter.record`` is idempotent inside the
caller's transaction and leaves nothing behind on rollback; ``active_attempt_facts``
is a value object of revisions, states and categories; and the four artifact
counts appended to ``consistency_report()`` move exactly with the rows that
define them while the eight Stage 8 counts and constructions stay as they were.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Final, Protocol

import pytest
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.artifacts.journal import FinalizationJournalState
from crypto_lab.artifacts.models import (
    ArtifactFinalizationPurpose,
    ArtifactRef,
    CandidateArtifact,
    CandidateArtifactProducerKind,
    CandidateArtifactState,
)
from crypto_lab.domain.diagnostics import Diagnostic, DiagnosticCategory
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
    ProcessExitCategory,
)
from crypto_lab.domain.results import Failure
from crypto_lab.persistence.artifact_codecs import (
    decode_artifact_manifest,
    decode_artifact_ref,
    decode_audit_event,
    decode_candidate_artifact,
    decode_finalization_journal_entry,
    encode_artifact_ref,
    encode_audit_event,
    encode_candidate_artifact,
    encode_finalization_journal_entry,
)
from crypto_lab.persistence.artifact_repositories import (
    RunArtifactLink,
    RunManifestFacts,
    SanitizedManifestFacts,
    SqliteArtifactRepository,
    SqliteCandidateArtifactRepository,
    SqliteFinalizationJournalRepository,
    SqliteRunArtifactRepository,
    SqliteRunManifestRepository,
    SqliteSanitizedManifestRepository,
    SqliteValidationResultRepository,
    ValidationResultFacts,
)
from crypto_lab.persistence.audit_sink import SqliteAuditSink, SqliteDiagnosticWriter
from crypto_lab.persistence.database import ConsistencyReport
from crypto_lab.persistence.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
    WRITE_FAILED,
)
from crypto_lab.persistence.repositories import (
    ResultLeaseFacts,
    SqliteEngineRunRepository,
)
from crypto_lab.persistence.unit_of_work import SqliteTransaction
from doubles.artifacts import (
    ADAPTER_ACTOR,
    ATTEMPT_TOKEN_HASH,
    CANDIDATE_ID,
    DEADLINE,
    OTHER_CANDIDATE_ID,
    RUN_MANIFEST_HASH,
    RUN_MANIFEST_ID,
    RUN_OWNER,
    SANITIZED_MANIFEST_HASH,
    SOURCE_MANIFEST_HASH,
    SYSTEM_OWNER,
    THIRD_CANDIDATE_ID,
    bump_candidate,
    bump_journal,
    sample_artifact_manifest,
    sample_audit_event,
    sample_candidate,
    sample_finalization_result,
    sample_journal,
    sample_mapping,
    sample_ref,
)
from doubles.experiments import (
    DIAG_ID,
    EXPERIMENT_ID,
    INSTANT,
    INVOCATION_ID,
    OTHER_DIAG_ID,
    OTHER_INVOCATION_ID,
    OTHER_RUN_ID,
    RUN_ID,
    SLOT_B,
    THIRD_DIAG_ID,
    UUID_D,
    UUID_E,
    FixedClock,
    sample_diagnostic,
    sample_invocation,
    sample_run,
)
from persistence_support.artifacts import ArtifactHarness
from persistence_support.harness import (
    causal_edges,
    code,
    commit,
    cursor_fault,
    ok,
    put_invocation,
    put_run,
    sql_identity_literal,
    sqlite_error,
)

_S = CandidateArtifactState
_P = CandidateArtifactProducerKind
_F = ArtifactFinalizationPurpose
_J = FinalizationJournalState
_CLOCK = FixedClock(INSTANT)
#: A fourth candidate identity beside the three ``doubles.artifacts`` names.
_EVIDENCE_CANDIDATE_ID: Final = f"cand_{UUID_D}"
_INSERT_REF: Final = "INSERT INTO artifact_refs"


def _zero_report() -> ConsistencyReport:
    """Every one of the twelve counts named, so the fixture pins the appended four."""
    return ConsistencyReport(
        dangling_diagnostic_references=0,
        slot_identity_mismatches=0,
        spec_projection_mismatches=0,
        queued_without_snapshot=0,
        causal_edge_mismatches=0,
        unresolved_causal_references=0,
        registry_projection_mismatches=0,
        foreign_key_violations=0,
        unmapped_finalizing=0,
        refs_without_manifest_file=0,
        success_without_manifest=0,
        journal_open=0,
    )


def _stage9(report: ConsistencyReport) -> tuple[int, int, int, int]:
    """The four Stage 9 counts of the one report, in field order."""
    return (
        report.unmapped_finalizing,
        report.refs_without_manifest_file,
        report.success_without_manifest,
        report.journal_open,
    )


def _message(result: object) -> str:
    assert isinstance(result, Failure), result
    return result.diagnostics[0].message


def _details(result: object) -> dict[str, object]:
    assert isinstance(result, Failure), result
    return dict(result.diagnostics[0].details)


def _finalizing(
    harness: ArtifactHarness,
    *,
    candidate_artifact_id: str = CANDIDATE_ID,
    owner_kind: str = "RUN",
    purpose: ArtifactFinalizationPurpose = _F.RESULT,
    producer: CandidateArtifactProducerKind = _P.ADAPTER,
) -> CandidateArtifact:
    record = sample_candidate(
        owner_kind,
        purpose,
        producer=producer,
        state=_S.FINALIZING,
        candidate_artifact_id=candidate_artifact_id,
    )
    harness.put_candidate(record)
    return record


def _sanitized_facts(**overrides: object) -> SanitizedManifestFacts:
    payload: dict[str, object] = {
        "sanitized_adapter_result_manifest_hash": SANITIZED_MANIFEST_HASH,
        "run_id": RUN_ID,
        "run_invocation_id": INVOCATION_ID,
        "experiment_id": EXPERIMENT_ID,
        "attempt_token_hash": ATTEMPT_TOKEN_HASH,
        "source_adapter_result_manifest_hash": SOURCE_MANIFEST_HASH,
        "semantic_status": "SUCCEEDED",
        "manifest_json": '{"attempt_token_hash":"' + ATTEMPT_TOKEN_HASH + '"}',
        "evidence_artifact_id": MISSING,
        "recorded_at_utc": INSTANT,
    }
    payload.update(overrides)
    return SanitizedManifestFacts(**payload)  # type: ignore[arg-type]


def _manifest_facts(**overrides: object) -> RunManifestFacts:
    payload: dict[str, object] = {
        "manifest_id": RUN_MANIFEST_ID,
        "run_id": RUN_ID,
        "experiment_id": EXPERIMENT_ID,
        "run_invocation_id": INVOCATION_ID,
        "attempt_token_hash": ATTEMPT_TOKEN_HASH,
        "sanitized_adapter_result_manifest_hash": SANITIZED_MANIFEST_HASH,
        "semantic_status": "SUCCEEDED",
        "process_exit_category": "SUCCESS",
        "manifest_json": '{"run_id":"' + RUN_ID + '"}',
        "run_manifest_hash": RUN_MANIFEST_HASH,
        "registered_at_utc": INSTANT,
    }
    payload.update(overrides)
    return RunManifestFacts(**payload)  # type: ignore[arg-type]


def _validation_facts(**overrides: object) -> ValidationResultFacts:
    payload: dict[str, object] = {
        "invocation_id": OTHER_INVOCATION_ID,
        "run_id": RUN_ID,
        "experiment_id": EXPERIMENT_ID,
        "validation_result_hash": "d" * 64,
        "outcome": "PASSED",
        "result_json": '{"outcome":"PASSED"}',
        "evidence_artifact_id": MISSING,
        "recorded_at_utc": INSTANT,
    }
    payload.update(overrides)
    return ValidationResultFacts(**payload)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Round trips for every new row (plan 3.3) through codec and repository
# --------------------------------------------------------------------------


def test_candidate_round_trip(artifact_harness: ArtifactHarness) -> None:
    artifact_harness.seed_result_prestate()
    adapter = sample_candidate()
    core = sample_candidate(
        "SYSTEM",
        _F.EVIDENCE,
        producer=_P.CORE,
        state=_S.VALIDATING,
        candidate_artifact_id=OTHER_CANDIDATE_ID,
    )
    for record in (adapter, core):
        row = encode_candidate_artifact(record)
        assert ok(decode_candidate_artifact(row, owner=record.owner, clock=_CLOCK)) == (
            record
        )
        artifact_harness.put_candidate(record)
    # The ADAPTER row denormalizes the RUN owner's run and invocation; the CORE
    # row of a SYSTEM owner carries neither and no declared fact.
    adapter_row = encode_candidate_artifact(adapter)
    assert (adapter_row["run_id"], adapter_row["invocation_id"]) == (
        RUN_ID,
        INVOCATION_ID,
    )
    core_row = encode_candidate_artifact(core)
    assert core_row["run_id"] is None
    assert core_row["adapter_declared_hash"] is None
    assert artifact_harness.committed_candidates() == (adapter, core)
    transaction = artifact_harness.begin()
    assert ok(transaction.candidate_artifacts.get(CANDIDATE_ID)) == adapter
    assert ok(transaction.candidate_artifacts.get(OTHER_CANDIDATE_ID)) == core
    transaction.rollback()


def test_reference_and_manifest_round_trip(artifact_harness: ArtifactHarness) -> None:
    artifact_harness.seed_result_prestate()
    candidate = _finalizing(artifact_harness)
    ref = sample_ref(candidate)
    manifest = sample_artifact_manifest(ref)
    row = encode_artifact_ref(ref, manifest)
    assert ok(decode_artifact_ref(row, owner=ref.owner, clock=_CLOCK)) == ref
    assert ok(decode_artifact_manifest(row, clock=_CLOCK)) == manifest
    # The stored manifest must carry the row's own hash; a disagreement is refused.
    torn = decode_artifact_manifest(
        {**row, "artifact_manifest_hash": "f" * 64}, clock=_CLOCK
    )
    assert code(torn) == INVARIANT_VIOLATION
    assert _details(torn)["operation"] == "decode"
    # A manifest describing another artifact never pairs with the reference.
    with pytest.raises(ValueError, match="same finalized artifact"):
        encode_artifact_ref(
            ref, sample_artifact_manifest(sample_ref(candidate, content_hash="f" * 64))
        )
    transaction = artifact_harness.begin()
    ok(transaction.artifact_refs.stage_reference(ref, manifest))
    result = sample_finalization_result((ref,))
    assert ok(transaction.artifact_refs.record_finalization(result)) == (ref,)
    commit(transaction)
    assert artifact_harness.committed_refs() == (ref,)
    assert artifact_harness.committed_manifests() == (manifest,)
    fresh = artifact_harness.begin()
    assert ok(fresh.artifact_refs.get(ref.artifact_id)) == ref
    assert ok(fresh.artifact_refs.get_manifest(ref.artifact_id)) == manifest
    assert ok(fresh.artifact_refs.list_by_owner(RUN_OWNER)) == (ref,)
    fresh.rollback()


def test_journal_round_trip_both_purposes(artifact_harness: ArtifactHarness) -> None:
    artifact_harness.seed_result_prestate()
    result = sample_journal(_J.PREPARED, _F.RESULT)
    evidence = sample_journal(_J.MOVED, _F.EVIDENCE)
    result_row = encode_finalization_journal_entry(result)
    evidence_row = encode_finalization_journal_entry(evidence)
    # RESULT flattens no correlation; EVIDENCE flattens its typed correlation.
    assert (result_row["correlation_kind"], result_row["correlation_id"]) == (
        None,
        None,
    )
    assert (evidence_row["correlation_kind"], evidence_row["correlation_id"]) == (
        "DIAGNOSTIC",
        DIAG_ID,
    )
    assert result_row["finalization_deadline_utc"] is not None
    assert evidence_row["finalization_deadline_utc"] is None
    for entry, row in ((result, result_row), (evidence, evidence_row)):
        decoded = decode_finalization_journal_entry(
            row, owner=entry.owner, clock=_CLOCK
        )
        assert ok(decoded) == entry
    # A correlation kind without its identifier, or a kind outside the three, is
    # a torn row, refused on egress.
    torn = decode_finalization_journal_entry(
        {**evidence_row, "correlation_id": None}, owner=evidence.owner, clock=_CLOCK
    )
    assert code(torn) == INVARIANT_VIOLATION
    unknown_kind = decode_finalization_journal_entry(
        {**evidence_row, "correlation_kind": "BOGUS"},
        owner=evidence.owner,
        clock=_CLOCK,
    )
    assert code(unknown_kind) == INVARIANT_VIOLATION
    assert _details(unknown_kind)["location"] == "payload"
    artifact_harness.put_journal(result)
    artifact_harness.put_journal(evidence)
    assert set(artifact_harness.committed_journal()) == {result, evidence}
    transaction = artifact_harness.begin()
    assert ok(transaction.finalization_journal.get(result.finalization_id)) == result
    assert (
        ok(transaction.finalization_journal.get(evidence.finalization_id)) == evidence
    )
    transaction.rollback()


def test_audit_event_codec_round_trip(artifact_harness: ArtifactHarness) -> None:
    core = sample_audit_event()
    adapter = sample_audit_event(
        actor=ADAPTER_ACTOR, audit_event_id=f"audit_{UUID_D}", run_id=MISSING
    )
    for event in (core, adapter):
        row = encode_audit_event(event)
        assert "audit_sequence" not in row
        assert ok(decode_audit_event(row, clock=_CLOCK)) == event
    adapter_row = encode_audit_event(adapter)
    assert adapter_row["actor_adapter_name"] == "adapter.alpha"
    assert adapter_row["run_id"] is None
    # A row whose details disagree with their hash is refused on egress.
    torn = decode_audit_event(
        {**encode_audit_event(core), "details_hash": "f" * 64}, clock=_CLOCK
    )
    assert code(torn) == INVARIANT_VIOLATION
    # ``core`` references the fixture run; the prestate plants its row.
    artifact_harness.seed_result_prestate()
    transaction = artifact_harness.begin()
    assert isinstance(transaction.audit, SqliteAuditSink)
    ok(transaction.audit.append(core))
    ok(transaction.audit.append(adapter))
    commit(transaction)
    assert artifact_harness.committed_audit_events() == (core, adapter)


def test_registration_facts_round_trips(artifact_harness: ArtifactHarness) -> None:
    artifact_harness.seed_result_prestate()
    put_invocation(
        artifact_harness.lifecycle(),
        sample_invocation(
            CommandInvocationState.EXITED,
            kind=CommandKind.VALIDATE,
            invocation_id=OTHER_INVOCATION_ID,
        ),
    )
    evidence_candidate = _finalizing(
        artifact_harness,
        owner_kind="RUN",
        purpose=_F.EVIDENCE,
        producer=_P.CORE,
        candidate_artifact_id=THIRD_CANDIDATE_ID,
    )
    result_candidate = _finalizing(artifact_harness)
    evidence_ref = sample_ref(evidence_candidate)
    result_ref = sample_ref(result_candidate)
    artifact_harness.put_ref(evidence_ref, sample_artifact_manifest(evidence_ref))
    artifact_harness.put_ref(result_ref, sample_artifact_manifest(result_ref))
    sanitized = _sanitized_facts()
    manifest = _manifest_facts()
    validation = _validation_facts()
    transaction = artifact_harness.begin()
    # Absent facts answer MISSING, never a failure.
    assert not isinstance(
        ok(transaction.sanitized_manifests.get(SANITIZED_MANIFEST_HASH)),
        SanitizedManifestFacts,
    )
    assert not isinstance(ok(transaction.run_manifests.get(RUN_ID)), RunManifestFacts)
    assert not isinstance(
        ok(transaction.validation_results.get(OTHER_INVOCATION_ID)),
        ValidationResultFacts,
    )
    assert ok(transaction.run_artifacts.list_for_run(RUN_ID)) == ()
    ok(transaction.sanitized_manifests.add(sanitized))
    assert ok(transaction.sanitized_manifests.get(SANITIZED_MANIFEST_HASH)) == sanitized
    assert code(transaction.sanitized_manifests.add(sanitized)) == CONCURRENCY_CONFLICT
    ok(transaction.run_manifests.add(manifest))
    assert ok(transaction.run_manifests.get(RUN_ID)) == manifest
    assert code(transaction.run_manifests.add(manifest)) == CONCURRENCY_CONFLICT
    ok(transaction.validation_results.add(validation))
    assert ok(transaction.validation_results.get(OTHER_INVOCATION_ID)) == validation
    # Evidence links are written once: a RESULT reference is refused by the
    # trigger, a repeated link is the zero-row conflict.
    sanitized_repository = transaction.sanitized_manifests
    wrong = sanitized_repository.link_evidence(
        SANITIZED_MANIFEST_HASH, result_ref.artifact_id
    )
    assert code(wrong) == INVARIANT_VIOLATION
    ok(
        sanitized_repository.link_evidence(
            SANITIZED_MANIFEST_HASH, evidence_ref.artifact_id
        )
    )
    linked = ok(sanitized_repository.get(SANITIZED_MANIFEST_HASH))
    assert linked.evidence_artifact_id == evidence_ref.artifact_id
    again = sanitized_repository.link_evidence(
        SANITIZED_MANIFEST_HASH, evidence_ref.artifact_id
    )
    assert code(again) == CONCURRENCY_CONFLICT
    absent = sanitized_repository.link_evidence("9" * 64, evidence_ref.artifact_id)
    assert code(absent) == CONCURRENCY_CONFLICT
    ok(
        transaction.validation_results.link_evidence(
            OTHER_INVOCATION_ID, evidence_ref.artifact_id
        )
    )
    relinked = ok(transaction.validation_results.get(OTHER_INVOCATION_ID))
    assert relinked.evidence_artifact_id == evidence_ref.artifact_id
    # Links: the role must be one of the two, a member needs its manifest.
    bad_role = transaction.run_artifacts.link(
        RunArtifactLink(
            run_id=RUN_ID,
            artifact_id=evidence_ref.artifact_id,
            link_role="EVIDENCE",
            experiment_id=EXPERIMENT_ID,
            run_manifest_id=MISSING,
        )
    )
    assert code(bad_role) == INVARIANT_VIOLATION
    evidence_link = RunArtifactLink(
        run_id=RUN_ID,
        artifact_id=evidence_ref.artifact_id,
        link_role="RUN_EVIDENCE",
        experiment_id=EXPERIMENT_ID,
        run_manifest_id=MISSING,
    )
    member_link = RunArtifactLink(
        run_id=RUN_ID,
        artifact_id=result_ref.artifact_id,
        link_role="RESULT_MANIFEST_MEMBER",
        experiment_id=EXPERIMENT_ID,
        run_manifest_id=RUN_MANIFEST_ID,
    )
    ok(transaction.run_artifacts.link(evidence_link))
    ok(transaction.run_artifacts.link(member_link))
    assert code(transaction.run_artifacts.link(evidence_link)) == CONCURRENCY_CONFLICT
    assert ok(transaction.run_artifacts.list_for_run(RUN_ID)) == (
        member_link,
        evidence_link,
    )
    commit(transaction)
    assert artifact_harness.committed_run_manifests() == (manifest,)
    assert artifact_harness.committed_run_artifacts() == (member_link, evidence_link)


# --------------------------------------------------------------------------
# The facts boundaries are structural (plan 4.1): shapes declared here alone
# --------------------------------------------------------------------------
#
# Nothing below inherits from, or is, a persistence type. The four frozen
# dataclasses are the facts a later port may hand the repositories; the five
# protocols are the read-only readers a later port may declare over the answers.
# Strict mypy over this module is the static contract check: every ``add`` and
# ``link`` call below type-checks only because the repository boundary is a
# structural read-only interface, and every annotated assignment type-checks
# only because the repository's own value satisfies the reader by shape.


@dataclass(frozen=True, slots=True, kw_only=True)
class _ForeignSanitizedFacts:
    sanitized_adapter_result_manifest_hash: str
    run_id: str
    run_invocation_id: str
    experiment_id: str
    attempt_token_hash: str
    source_adapter_result_manifest_hash: str
    semantic_status: str
    manifest_json: str
    evidence_artifact_id: str | MISSING  # type: ignore[valid-type]
    recorded_at_utc: datetime


@dataclass(frozen=True, slots=True, kw_only=True)
class _ForeignRunManifestFacts:
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


@dataclass(frozen=True, slots=True, kw_only=True)
class _ForeignValidationFacts:
    invocation_id: str
    run_id: str
    experiment_id: str
    validation_result_hash: str
    outcome: str
    result_json: str
    evidence_artifact_id: str | MISSING  # type: ignore[valid-type]
    recorded_at_utc: datetime


@dataclass(frozen=True, slots=True, kw_only=True)
class _ForeignRunArtifactLink:
    run_id: str
    artifact_id: str
    link_role: str
    experiment_id: str
    run_manifest_id: str | MISSING  # type: ignore[valid-type]


class _SanitizedFactsReader(Protocol):
    @property
    def sanitized_adapter_result_manifest_hash(self) -> str: ...

    @property
    def run_id(self) -> str: ...

    @property
    def run_invocation_id(self) -> str: ...

    @property
    def experiment_id(self) -> str: ...

    @property
    def attempt_token_hash(self) -> str: ...

    @property
    def source_adapter_result_manifest_hash(self) -> str: ...

    @property
    def semantic_status(self) -> str: ...

    @property
    def manifest_json(self) -> str: ...

    @property
    def evidence_artifact_id(self) -> str | MISSING: ...  # type: ignore[valid-type]

    @property
    def recorded_at_utc(self) -> datetime: ...


class _RunManifestFactsReader(Protocol):
    @property
    def manifest_id(self) -> str: ...

    @property
    def run_id(self) -> str: ...

    @property
    def experiment_id(self) -> str: ...

    @property
    def run_invocation_id(self) -> str: ...

    @property
    def attempt_token_hash(self) -> str: ...

    @property
    def sanitized_adapter_result_manifest_hash(self) -> str: ...

    @property
    def semantic_status(self) -> str: ...

    @property
    def process_exit_category(self) -> str: ...

    @property
    def manifest_json(self) -> str: ...

    @property
    def run_manifest_hash(self) -> str: ...

    @property
    def registered_at_utc(self) -> datetime: ...


class _ValidationFactsReader(Protocol):
    @property
    def invocation_id(self) -> str: ...

    @property
    def run_id(self) -> str: ...

    @property
    def experiment_id(self) -> str: ...

    @property
    def validation_result_hash(self) -> str: ...

    @property
    def outcome(self) -> str: ...

    @property
    def result_json(self) -> str: ...

    @property
    def evidence_artifact_id(self) -> str | MISSING: ...  # type: ignore[valid-type]

    @property
    def recorded_at_utc(self) -> datetime: ...


class _RunArtifactLinkReader(Protocol):
    @property
    def run_id(self) -> str: ...

    @property
    def artifact_id(self) -> str: ...

    @property
    def link_role(self) -> str: ...

    @property
    def experiment_id(self) -> str: ...

    @property
    def run_manifest_id(self) -> str | MISSING: ...  # type: ignore[valid-type]


class _ResultLeaseFactsReader(Protocol):
    @property
    def run_id(self) -> str: ...

    @property
    def run_invocation_id(self) -> str: ...

    @property
    def experiment_id(self) -> str: ...

    @property
    def run_state(self) -> EngineRunState: ...

    @property
    def run_revision(self) -> int: ...

    @property
    def attempt_token_hash(self) -> str: ...

    @property
    def deadline_snapshotted(self) -> bool: ...

    @property
    def invocation_state(self) -> CommandInvocationState: ...

    @property
    def invocation_revision(self) -> int: ...

    @property
    def command_kind(self) -> CommandKind: ...

    @property
    def process_exit_category(self) -> ProcessExitCategory | MISSING: ...  # type: ignore[valid-type]

    @property
    def experiment_state(self) -> ExperimentState | MISSING: ...  # type: ignore[valid-type]

    @property
    def is_latest_attempt(self) -> bool: ...


def test_facts_boundaries_are_structural(artifact_harness: ArtifactHarness) -> None:
    """Plan 4.1: the registration-facts repositories consume read-only structural
    facts interfaces, never the persistence dataclasses by name. Statically (strict
    mypy over this module): a facts value declared above, nominally unrelated to
    any persistence type, is accepted by ``add`` and ``link``, and every answer --
    the registration facts, the links and the lease facts -- is assignable to a
    reader declared above. At runtime the same rows round-trip through the
    production repositories and read back equal to the repository's own values."""
    artifact_harness.seed_result_prestate()
    put_invocation(
        artifact_harness.lifecycle(),
        sample_invocation(
            CommandInvocationState.EXITED,
            kind=CommandKind.VALIDATE,
            invocation_id=OTHER_INVOCATION_ID,
        ),
    )
    result_ref = sample_ref(_finalizing(artifact_harness))
    artifact_harness.put_ref(result_ref, sample_artifact_manifest(result_ref))
    transaction = artifact_harness.begin()
    ok(
        transaction.sanitized_manifests.add(
            _ForeignSanitizedFacts(
                sanitized_adapter_result_manifest_hash=SANITIZED_MANIFEST_HASH,
                run_id=RUN_ID,
                run_invocation_id=INVOCATION_ID,
                experiment_id=EXPERIMENT_ID,
                attempt_token_hash=ATTEMPT_TOKEN_HASH,
                source_adapter_result_manifest_hash=SOURCE_MANIFEST_HASH,
                semantic_status="SUCCEEDED",
                manifest_json='{"attempt_token_hash":"' + ATTEMPT_TOKEN_HASH + '"}',
                evidence_artifact_id=MISSING,
                recorded_at_utc=INSTANT,
            )
        )
    )
    ok(
        transaction.run_manifests.add(
            _ForeignRunManifestFacts(
                manifest_id=RUN_MANIFEST_ID,
                run_id=RUN_ID,
                experiment_id=EXPERIMENT_ID,
                run_invocation_id=INVOCATION_ID,
                attempt_token_hash=ATTEMPT_TOKEN_HASH,
                sanitized_adapter_result_manifest_hash=SANITIZED_MANIFEST_HASH,
                semantic_status="SUCCEEDED",
                process_exit_category="SUCCESS",
                manifest_json='{"run_id":"' + RUN_ID + '"}',
                run_manifest_hash=RUN_MANIFEST_HASH,
                registered_at_utc=INSTANT,
            )
        )
    )
    ok(
        transaction.validation_results.add(
            _ForeignValidationFacts(
                invocation_id=OTHER_INVOCATION_ID,
                run_id=RUN_ID,
                experiment_id=EXPERIMENT_ID,
                validation_result_hash="d" * 64,
                outcome="PASSED",
                result_json='{"outcome":"PASSED"}',
                evidence_artifact_id=MISSING,
                recorded_at_utc=INSTANT,
            )
        )
    )
    ok(
        transaction.run_artifacts.link(
            _ForeignRunArtifactLink(
                run_id=RUN_ID,
                artifact_id=result_ref.artifact_id,
                link_role="RESULT_MANIFEST_MEMBER",
                experiment_id=EXPERIMENT_ID,
                run_manifest_id=RUN_MANIFEST_ID,
            )
        )
    )
    # Every answer is a reader by shape (the annotated assignments are the static
    # check) and the repository's own value at runtime.
    sanitized = ok(transaction.sanitized_manifests.get(SANITIZED_MANIFEST_HASH))
    assert isinstance(sanitized, SanitizedManifestFacts)
    sanitized_reader: _SanitizedFactsReader = sanitized
    assert sanitized_reader.source_adapter_result_manifest_hash == (
        SOURCE_MANIFEST_HASH
    )
    assert sanitized == _sanitized_facts()
    manifest = ok(transaction.run_manifests.get(RUN_ID))
    assert isinstance(manifest, RunManifestFacts)
    manifest_reader: _RunManifestFactsReader = manifest
    assert manifest_reader.run_manifest_hash == RUN_MANIFEST_HASH
    assert manifest == _manifest_facts()
    validation = ok(transaction.validation_results.get(OTHER_INVOCATION_ID))
    assert isinstance(validation, ValidationResultFacts)
    validation_reader: _ValidationFactsReader = validation
    assert validation_reader.outcome == "PASSED"
    assert validation == _validation_facts()
    listed = ok(transaction.run_artifacts.list_for_run(RUN_ID))
    links: tuple[_RunArtifactLinkReader, ...] = listed
    assert [(link.link_role, link.run_manifest_id) for link in links] == [
        ("RESULT_MANIFEST_MEMBER", RUN_MANIFEST_ID)
    ]
    facts = ok(transaction.result_leases.active_attempt_facts(RUN_ID, INVOCATION_ID))
    lease: _ResultLeaseFactsReader = facts
    assert lease.deadline_snapshotted is True
    assert lease.run_state is EngineRunState.RUNNING
    commit(transaction)
    assert artifact_harness.committed_run_manifests() == (_manifest_facts(),)
    assert [
        link.artifact_id for link in artifact_harness.committed_run_artifacts()
    ] == [result_ref.artifact_id]


# --------------------------------------------------------------------------
# R10.4-03: egress re-validates and refuses a reinterpretation
# --------------------------------------------------------------------------


def test_egress_revalidates_and_refuses_reinterpretation(
    artifact_harness: ArtifactHarness,
) -> None:
    artifact_harness.seed_result_prestate()
    candidate = _finalizing(artifact_harness)
    journal = sample_journal(_J.MOVED, _F.RESULT)
    artifact_harness.put_journal(journal)
    # A quarantined candidate without a failed observation is a shape the record
    # refuses; the table admits the raw write (state is not an immutable column).
    artifact_harness.execute(
        "UPDATE candidate_artifacts SET state = 'QUARANTINED' "
        "WHERE candidate_artifact_id = ?",
        (CANDIDATE_ID,),
    )
    transaction = artifact_harness.begin()
    refused = transaction.candidate_artifacts.get(CANDIDATE_ID)
    assert code(refused) == INVARIANT_VIOLATION
    details = _details(refused)
    assert details["operation"] == "decode"
    assert details["table"] == "candidate_artifacts"
    assert details["identity"] == CANDIDATE_ID
    listed = transaction.candidate_artifacts.list_recoverable((_S.QUARANTINED,))
    assert code(listed) == INVARIANT_VIOLATION
    # A compare-and-swap over a torn row is refused before any write.
    swap = transaction.candidate_artifacts.compare_and_swap(
        candidate.revision, bump_candidate(candidate, _S.QUARANTINED)
    )
    assert code(swap) == INVARIANT_VIOLATION
    # A RESULT entry whose stored owner is a SYSTEM owner is a reinterpretation.
    transaction.rollback()
    artifact_harness.execute(
        "UPDATE finalization_journal SET owner_hash = ? WHERE finalization_id = ?",
        (artifact_harness.put_owner(SYSTEM_OWNER), journal.finalization_id),
    )
    transaction = artifact_harness.begin()
    torn = transaction.finalization_journal.get(journal.finalization_id)
    assert code(torn) == INVARIANT_VIOLATION
    assert _details(torn)["table"] == "finalization_journal"
    # The journal compare-and-swap re-reads the stored entry at step d and refuses
    # the torn row there, before its lawful MOVED -> REGISTERED write.
    journal_swap = transaction.finalization_journal.compare_and_swap(
        journal.revision, bump_journal(journal, _J.REGISTERED)
    )
    assert code(journal_swap) == INVARIANT_VIOLATION
    assert _details(journal_swap)["operation"] == "decode"
    probe = transaction.finalization_journal.find_result_identity(
        INVOCATION_ID, SOURCE_MANIFEST_HASH
    )
    assert code(probe) == INVARIANT_VIOLATION
    assert code(transaction.finalization_journal.list_open()) == INVARIANT_VIOLATION
    transaction.rollback()
    # A MOVED entry whose observed moves vanished is refused the same way.
    artifact_harness.execute(
        "UPDATE finalization_journal SET owner_hash = ?, observed_json = '[]' "
        "WHERE finalization_id = ?",
        (artifact_harness.put_owner(RUN_OWNER), journal.finalization_id),
    )
    transaction = artifact_harness.begin()
    assert (
        code(transaction.finalization_journal.get(journal.finalization_id))
        == INVARIANT_VIOLATION
    )
    transaction.rollback()


# --------------------------------------------------------------------------
# R19.2-06, RV-12, RV-13
# --------------------------------------------------------------------------


def test_registration_leaves_candidate_finalizing(
    artifact_harness: ArtifactHarness,
) -> None:
    artifact_harness.seed_result_prestate()
    candidate = _finalizing(artifact_harness)
    ref = sample_ref(candidate)
    transaction = artifact_harness.begin()
    ok(transaction.artifact_refs.stage_reference(ref, sample_artifact_manifest(ref)))
    ok(
        transaction.artifact_refs.record_finalization(
            sample_finalization_result((ref,))
        )
    )
    commit(transaction)
    assert artifact_harness.committed_candidates() == (candidate,)
    transaction = artifact_harness.begin()
    stored = ok(transaction.candidate_artifacts.get(CANDIDATE_ID))
    assert stored.state is _S.FINALIZING
    assert stored.revision == candidate.revision
    # The one lawful write left is the reflexive FINALIZING restatement beside
    # the registered mapping; without the mapping it is refused.
    restated = bump_candidate(candidate, _S.FINALIZING)
    unlinked = transaction.candidate_artifacts.compare_and_swap(
        candidate.revision, restated
    )
    assert code(unlinked) == INVARIANT_VIOLATION
    assert "registered mapping" in _message(unlinked)
    linked = ok(
        transaction.candidate_artifacts.compare_and_swap(
            candidate.revision, restated, registered_mapping=sample_mapping(ref)
        )
    )
    assert linked.state is _S.FINALIZING
    commit(transaction)
    assert artifact_harness.committed_candidates() == (linked,)
    assert artifact_harness.committed_refs() == (ref,)


def test_list_recoverable_excludes_mapped_finalizing(
    artifact_harness: ArtifactHarness,
) -> None:
    artifact_harness.seed_result_prestate()
    mapped = _finalizing(artifact_harness)
    unmapped = _finalizing(artifact_harness, candidate_artifact_id=OTHER_CANDIDATE_ID)
    validating = sample_candidate(
        state=_S.VALIDATING, candidate_artifact_id=THIRD_CANDIDATE_ID
    )
    artifact_harness.put_candidate(validating)
    ref = sample_ref(mapped)
    artifact_harness.put_ref(ref, sample_artifact_manifest(ref))
    transaction = artifact_harness.begin()
    repository = transaction.candidate_artifacts
    assert ok(repository.list_recoverable((_S.FINALIZING,))) == (unmapped,)
    assert ok(repository.list_recoverable((_S.FINALIZING, _S.VALIDATING))) == (
        validating,
        unmapped,
    )
    by_owner = repository.list_recoverable((_S.FINALIZING,), owner=RUN_OWNER)
    assert ok(by_owner) == (unmapped,)
    by_purpose = repository.list_recoverable((_S.FINALIZING,), purpose=_F.EVIDENCE)
    assert ok(by_purpose) == ()
    assert ok(repository.list_recoverable((_S.FINALIZING, _S.VALIDATING), limit=1)) == (
        validating,
    )
    # The mapped candidate is untouched: still readable, still FINALIZING.
    assert ok(repository.get(CANDIDATE_ID)) == mapped
    transaction.rollback()


def test_refs_never_update(artifact_harness: ArtifactHarness) -> None:
    artifact_harness.seed_result_prestate()
    candidate = _finalizing(artifact_harness)
    ref = sample_ref(candidate)
    manifest = sample_artifact_manifest(ref)
    artifact_harness.put_ref(ref, manifest)
    for statement, parameters in (
        (
            "UPDATE artifact_refs SET size_bytes = size_bytes + 1 "
            "WHERE artifact_id = ?",
            (ref.artifact_id,),
        ),
        (
            "UPDATE artifact_refs SET manifest_json = '{}' WHERE artifact_id = ?",
            (ref.artifact_id,),
        ),
        ("DELETE FROM artifact_refs WHERE artifact_id = ?", (ref.artifact_id,)),
    ):
        refusal = artifact_harness.refuse(statement, parameters)
        assert refusal.code == INVARIANT_VIOLATION
        assert "insert-only" in refusal.message
    # The repository offers no update path: its public surface is the four reads
    # and the staged write of plan 4.1.
    public = {
        name for name in dir(SqliteArtifactRepository) if not name.startswith("_")
    }
    assert public == {
        "get",
        "get_manifest",
        "list_by_owner",
        "record_finalization",
        "stage_reference",
    }
    assert artifact_harness.committed_refs() == (ref,)
    assert artifact_harness.committed_manifests() == (manifest,)


def test_a_torn_reference_row_is_refused_on_egress(
    artifact_harness: ArtifactHarness,
) -> None:
    """Reading 10 over ``artifact_refs``: a stored row whose ``artifact_id`` is not
    the identity derived from its source candidate and content hash -- a fact no
    CHECK can compute -- is refused by ``decode_artifact_ref`` and therefore by
    ``get`` and ``list_by_owner`` as ``CORE.INVARIANT_VIOLATION`` naming the decode
    and the record-level rule; the self-consistent manifest beside it still reads;
    the refusal is not the I/O class, so the transaction stays usable; and the
    consistency report counts the row."""
    artifact_harness.seed_result_prestate()
    good = sample_ref(_finalizing(artifact_harness))
    artifact_harness.put_ref(good, sample_artifact_manifest(good))
    source = sample_ref(
        _finalizing(artifact_harness, candidate_artifact_id=OTHER_CANDIDATE_ID)
    )
    torn_id = f"art_{UUID_E}"
    torn_row = dict(encode_artifact_ref(source, sample_artifact_manifest(source)))
    torn_row["artifact_id"] = torn_id
    artifact_harness.plant_raw("artifact_refs", torn_row)
    direct = decode_artifact_ref(torn_row, owner=RUN_OWNER, clock=_CLOCK)
    assert code(direct) == INVARIANT_VIOLATION
    assert _details(direct) == {
        "table": "artifact_refs",
        "identity": torn_id,
        "location": "record",
        "operation": "decode",
    }
    transaction = artifact_harness.begin()
    refs = transaction.artifact_refs
    refused = refs.get(torn_id)
    assert code(refused) == INVARIANT_VIOLATION
    assert _details(refused) == _details(direct)
    assert code(refs.list_by_owner(RUN_OWNER)) == INVARIANT_VIOLATION
    assert code(refs.list_by_owner(RUN_OWNER, _F.RESULT)) == INVARIANT_VIOLATION
    assert ok(refs.list_by_owner(RUN_OWNER, _F.EVIDENCE)) == ()
    assert ok(refs.list_by_owner(SYSTEM_OWNER)) == ()
    # The manifest column describes the artifact the row was built for and is
    # self-consistent, so it reads; the reference row around it does not.
    assert ok(refs.get_manifest(torn_id)).artifact_id == source.artifact_id
    assert transaction.open_failure() is None
    assert ok(refs.get(good.artifact_id)) == good
    transaction.rollback()
    report = artifact_harness.database.consistency_report()
    assert (report.refs_without_manifest_file, report.unmapped_finalizing) == (1, 0)


# --------------------------------------------------------------------------
# Compare-and-swap precedence (Stage 8 plan 4.3.1 verbatim, plan 4.7)
# --------------------------------------------------------------------------


def test_candidate_compare_and_swap_precedence(
    artifact_harness: ArtifactHarness,
) -> None:
    artifact_harness.seed_result_prestate()
    stored = sample_candidate()
    artifact_harness.put_candidate(stored)
    transaction = artifact_harness.begin()
    repository = transaction.candidate_artifacts
    assert isinstance(repository, SqliteCandidateArtifactRepository)
    absent = sample_candidate(candidate_artifact_id=OTHER_CANDIDATE_ID)
    missing_row = repository.compare_and_swap(0, bump_candidate(absent, _S.VALIDATING))
    assert code(missing_row) == CONCURRENCY_CONFLICT
    assert "does not exist for compare-and-swap" in _message(missing_row)
    absent_read = repository.get(OTHER_CANDIDATE_ID)
    assert code(absent_read) == INVARIANT_VIOLATION
    assert "does not exist" in _message(absent_read)
    stale = repository.compare_and_swap(
        stored.revision + 5, bump_candidate(stored, _S.VALIDATING)
    )
    assert code(stale) == CONCURRENCY_CONFLICT
    skipped = bump_candidate(bump_candidate(stored, _S.VALIDATING), _S.FINALIZING)
    assert code(repository.compare_and_swap(stored.revision, skipped)) == (
        INVARIANT_VIOLATION
    )
    assert ok(repository.get(CANDIDATE_ID)) == stored
    validating = bump_candidate(stored, _S.VALIDATING)
    assert ok(repository.compare_and_swap(stored.revision, validating)) == validating
    assert ok(repository.get(CANDIDATE_ID)) == validating
    fresh = artifact_harness.begin()
    assert ok(fresh.candidate_artifacts.get(CANDIDATE_ID)) == stored
    fresh.rollback()
    # The pre-read sees this transaction's own swap: the same expected revision
    # is stale now.
    again = repository.compare_and_swap(stored.revision, validating)
    assert code(again) == CONCURRENCY_CONFLICT
    transaction.rollback()
    assert artifact_harness.committed_candidates() == (stored,)
    # Step f: a conditional UPDATE that touches no row is the conflict.
    artifact_harness.install_ignoring_update_trigger(
        "candidate_artifacts",
        f"NEW.candidate_artifact_id = {sql_identity_literal(CANDIDATE_ID)}",
    )
    transaction = artifact_harness.begin()
    ignored = transaction.candidate_artifacts.compare_and_swap(
        stored.revision, validating
    )
    assert code(ignored) == CONCURRENCY_CONFLICT
    assert ok(transaction.candidate_artifacts.get(CANDIDATE_ID)) == stored
    commit(transaction)
    assert artifact_harness.committed_candidates() == (stored,)


def test_journal_compare_and_swap_precedence(artifact_harness: ArtifactHarness) -> None:
    artifact_harness.seed_result_prestate()
    stored = sample_journal(_J.PREPARED, _F.RESULT)
    artifact_harness.put_journal(stored)
    transaction = artifact_harness.begin()
    repository = transaction.finalization_journal
    assert isinstance(repository, SqliteFinalizationJournalRepository)
    absent = sample_journal(_J.PREPARED, _F.EVIDENCE)
    missing_row = repository.compare_and_swap(0, bump_journal(absent, _J.MOVED))
    assert code(missing_row) == CONCURRENCY_CONFLICT
    assert "does not exist for compare-and-swap" in _message(missing_row)
    stale = repository.compare_and_swap(
        stored.revision + 5, bump_journal(stored, _J.MOVED)
    )
    assert code(stale) == CONCURRENCY_CONFLICT
    skipped = bump_journal(bump_journal(stored, _J.MOVED), _J.REGISTERED)
    assert code(repository.compare_and_swap(stored.revision, skipped)) == (
        INVARIANT_VIOLATION
    )
    # PREPARED -> REGISTERED is not a journal edge (23.3.1:1719-1723).
    leap = repository.compare_and_swap(
        stored.revision, bump_journal(stored, _J.REGISTERED)
    )
    assert code(leap) == INVARIANT_VIOLATION
    assert "not a permitted journal edge" in _message(leap)
    moved = bump_journal(stored, _J.MOVED)
    assert ok(repository.compare_and_swap(stored.revision, moved)) == moved
    fresh = artifact_harness.begin()
    assert ok(fresh.finalization_journal.get(stored.finalization_id)) == stored
    fresh.rollback()
    registered = bump_journal(moved, _J.REGISTERED)
    assert ok(repository.compare_and_swap(moved.revision, registered)) == registered
    terminal = repository.compare_and_swap(
        registered.revision, bump_journal(registered, _J.ABANDONED)
    )
    assert code(terminal) == INVARIANT_VIOLATION
    assert "terminal journal entry" in _message(terminal)
    commit(transaction)
    assert artifact_harness.committed_journal() == (registered,)
    # Step f over the journal: the ignored conditional update is the conflict.
    second = sample_journal(
        _J.PREPARED,
        _F.RESULT,
        candidate_artifact_ids=(OTHER_CANDIDATE_ID,),
        source_adapter_result_manifest_hash="b" * 64,
    )
    artifact_harness.put_journal(second)
    artifact_harness.install_ignoring_update_trigger(
        "finalization_journal",
        f"NEW.finalization_id = {sql_identity_literal(second.finalization_id)}",
    )
    transaction = artifact_harness.begin()
    ignored = transaction.finalization_journal.compare_and_swap(
        second.revision, bump_journal(second, _J.MOVED)
    )
    assert code(ignored) == CONCURRENCY_CONFLICT
    transaction.rollback()
    assert set(artifact_harness.committed_journal()) == {registered, second}


# --------------------------------------------------------------------------
# The in-transaction diagnostic writer (plan 4.1, 4.8)
# --------------------------------------------------------------------------


def test_diagnostic_writer_is_idempotent_and_rolls_back(
    artifact_harness: ArtifactHarness,
) -> None:
    artifact_harness.seed_result_prestate()
    first = sample_diagnostic()
    second = sample_diagnostic(OTHER_DIAG_ID, causal_diagnostic_ids=(DIAG_ID,))
    transaction = artifact_harness.begin()
    writer = transaction.diagnostics_writer
    assert isinstance(writer, SqliteDiagnosticWriter)
    assert ok(writer.record(first)) is None
    # An identical re-record and a re-record differing only in its timestamp are
    # absorbed; a same-identity record with different content is refused.
    assert ok(writer.record(first)) is None
    restamped = sample_diagnostic(timestamp_utc=INSTANT + timedelta(seconds=5))
    assert ok(writer.record(restamped)) is None
    different = sample_diagnostic(retriable=False)
    refused = writer.record(different)
    assert code(refused) == INVARIANT_VIOLATION
    assert "different content" in _message(refused)
    assert ok(writer.record(second)) is None
    # The rows and causal edges join the caller's transaction: not durable yet.
    assert causal_edges(artifact_harness.database) == ()
    fresh = artifact_harness.begin()
    assert code(fresh.diagnostics.get(DIAG_ID)) == INVARIANT_VIOLATION
    fresh.rollback()
    commit(transaction)
    assert causal_edges(artifact_harness.database) == ((OTHER_DIAG_ID, DIAG_ID),)
    reader = artifact_harness.begin()
    assert ok(reader.diagnostics.get(DIAG_ID)) == first
    assert ok(reader.diagnostics.get(OTHER_DIAG_ID)) == second
    reader.rollback()
    # A rolled-back phase leaves no diagnostic row and no edge behind.
    third: Diagnostic = sample_diagnostic(
        THIRD_DIAG_ID, causal_diagnostic_ids=(DIAG_ID, OTHER_DIAG_ID)
    )
    abandoned = artifact_harness.begin()
    ok(abandoned.diagnostics_writer.record(third))
    assert ok(abandoned.diagnostics.get(THIRD_DIAG_ID)) == third
    abandoned.rollback()
    assert causal_edges(artifact_harness.database) == ((OTHER_DIAG_ID, DIAG_ID),)
    reader = artifact_harness.begin()
    assert code(reader.diagnostics.get(THIRD_DIAG_ID)) == INVARIANT_VIOLATION
    reader.rollback()


# --------------------------------------------------------------------------
# active_attempt_facts (plan 4.1, reading 4)
# --------------------------------------------------------------------------


def test_active_attempt_facts(artifact_harness: ArtifactHarness) -> None:
    prestate = artifact_harness.seed_result_prestate()
    transaction = artifact_harness.begin()
    leases = transaction.result_leases
    assert isinstance(leases, SqliteEngineRunRepository)
    facts = ok(leases.active_attempt_facts(RUN_ID, INVOCATION_ID))
    assert facts == ResultLeaseFacts(
        run_id=RUN_ID,
        run_invocation_id=INVOCATION_ID,
        experiment_id=EXPERIMENT_ID,
        run_state=EngineRunState.RUNNING,
        run_revision=prestate.run.revision,
        attempt_token_hash=ATTEMPT_TOKEN_HASH,
        deadline_snapshotted=True,
        invocation_state=CommandInvocationState.EXITED,
        invocation_revision=prestate.invocation.revision,
        command_kind=CommandKind.RUN,
        process_exit_category=ProcessExitCategory.SUCCESS,
        experiment_state=ExperimentState.QUEUED,
        is_latest_attempt=True,
    )
    # A missing run or invocation is the invariant naming the absence; an
    # invocation of another run is the invariant too.
    missing_run = leases.active_attempt_facts(OTHER_RUN_ID, INVOCATION_ID)
    assert code(missing_run) == INVARIANT_VIOLATION
    assert "does not exist" in _message(missing_run)
    missing_invocation = leases.active_attempt_facts(RUN_ID, OTHER_INVOCATION_ID)
    assert code(missing_invocation) == INVARIANT_VIOLATION
    assert "does not exist" in _message(missing_invocation)
    transaction.rollback()
    put_run(
        artifact_harness.lifecycle(),
        sample_run(EngineRunState.PENDING, run_id=OTHER_RUN_ID, logical_slot_id=SLOT_B),
    )
    put_invocation(
        artifact_harness.lifecycle(),
        sample_invocation(
            CommandInvocationState.PENDING,
            invocation_id=OTHER_INVOCATION_ID,
            run_id=OTHER_RUN_ID,
        ),
    )
    transaction = artifact_harness.begin()
    foreign = transaction.result_leases.active_attempt_facts(
        RUN_ID, OTHER_INVOCATION_ID
    )
    assert code(foreign) == INVARIANT_VIOLATION
    assert "not linked" in _message(foreign)
    pending = ok(
        transaction.result_leases.active_attempt_facts(
            OTHER_RUN_ID, OTHER_INVOCATION_ID
        )
    )
    assert pending.run_state is EngineRunState.PENDING
    assert pending.deadline_snapshotted is False
    assert pending.invocation_state is CommandInvocationState.PENDING
    assert not isinstance(pending.process_exit_category, ProcessExitCategory)
    assert pending.is_latest_attempt is True
    transaction.rollback()


def test_active_attempt_facts_names_a_superseded_attempt(
    artifact_harness: ArtifactHarness,
) -> None:
    """Reading 4: the latest-attempt predicate is a fact, not a verdict; a
    terminal predecessor with a successor answers ``is_latest_attempt=False``."""
    lifecycle = artifact_harness.lifecycle()
    lifecycle.seed_diagnostic(sample_diagnostic())
    prestate = artifact_harness.seed_result_prestate(
        run_state=EngineRunState.FAILED, deadline=None
    )
    successor = sample_run(
        EngineRunState.PENDING,
        run_id=OTHER_RUN_ID,
        attempt_number=2,
        predecessor_run_id=RUN_ID,
    )
    put_run(lifecycle, successor)
    transaction = artifact_harness.begin()
    facts = ok(transaction.result_leases.active_attempt_facts(RUN_ID, INVOCATION_ID))
    assert facts.run_state is EngineRunState.FAILED
    assert facts.run_revision == prestate.run.revision
    assert facts.deadline_snapshotted is False
    assert facts.is_latest_attempt is False
    assert facts.invocation_state is CommandInvocationState.EXITED
    transaction.rollback()


# --------------------------------------------------------------------------
# The transaction members and the four artifact consistency counts
# --------------------------------------------------------------------------


def test_transaction_exposes_the_finalization_members(
    artifact_harness: ArtifactHarness,
) -> None:
    transaction = artifact_harness.begin()
    assert isinstance(
        transaction.candidate_artifacts, SqliteCandidateArtifactRepository
    )
    assert isinstance(transaction.artifact_refs, SqliteArtifactRepository)
    assert isinstance(
        transaction.finalization_journal, SqliteFinalizationJournalRepository
    )
    assert isinstance(transaction.run_manifests, SqliteRunManifestRepository)
    assert isinstance(
        transaction.sanitized_manifests, SqliteSanitizedManifestRepository
    )
    assert isinstance(transaction.validation_results, SqliteValidationResultRepository)
    assert isinstance(transaction.run_artifacts, SqliteRunArtifactRepository)
    assert isinstance(transaction.result_leases, SqliteEngineRunRepository)
    assert transaction.result_leases is transaction.engine_runs
    assert isinstance(transaction.diagnostics_writer, SqliteDiagnosticWriter)
    assert isinstance(transaction.audit, SqliteAuditSink)
    commit(transaction)
    # Every member is gated by the transaction's lifecycle exactly as the Stage 8
    # members are: a released transaction answers no member.
    for name in (
        "candidate_artifacts",
        "artifact_refs",
        "finalization_journal",
        "run_manifests",
        "sanitized_manifests",
        "validation_results",
        "run_artifacts",
        "result_leases",
        "diagnostics_writer",
        "audit",
    ):
        with pytest.raises(RuntimeError):
            getattr(transaction, name)


def test_consistency_report_carries_the_four_stage9_counts(
    artifact_harness: ArtifactHarness,
) -> None:
    """Stage 9 plan Task 5: ``consistency_report`` gains the four artifact counts
    as fields appended after the eight Stage 8 counts; the eight-argument
    positional and keyword constructions stay valid and default the appended
    four to zero, so every existing whole-report equality still holds."""
    report = artifact_harness.database.consistency_report()
    assert _stage9(report) == (0, 0, 0, 0)
    zero = _zero_report()
    assert report == zero
    assert ConsistencyReport(*([0] * 8)) == zero
    assert (
        ConsistencyReport(
            dangling_diagnostic_references=0,
            slot_identity_mismatches=0,
            spec_projection_mismatches=0,
            queued_without_snapshot=0,
            causal_edge_mismatches=0,
            unresolved_causal_references=0,
            registry_projection_mismatches=0,
            foreign_key_violations=0,
        )
        == zero
    )


def test_artifact_consistency_counts(artifact_harness: ArtifactHarness) -> None:
    database = artifact_harness.database
    assert database.consistency_report() == _zero_report()
    artifact_harness.seed_result_prestate()
    # The seeded Stage 8 parents are the baseline every step compares against as a
    # whole report: a Stage 9 row moves its own count and nothing else.
    baseline = database.consistency_report()
    assert _stage9(baseline) == (0, 0, 0, 0)
    # unmapped_finalizing: a FINALIZING candidate with neither a reference nor an
    # open journal naming it (RV-11); an open journal covers it, a closed one does
    # not, a reference does.
    candidate = _finalizing(artifact_harness)
    assert database.consistency_report() == replace(baseline, unmapped_finalizing=1)
    journal = sample_journal(_J.PREPARED, _F.RESULT)
    artifact_harness.put_journal(journal)
    assert database.consistency_report() == replace(baseline, journal_open=1)
    transaction = artifact_harness.begin()
    moved = ok(
        transaction.finalization_journal.compare_and_swap(
            journal.revision, bump_journal(journal, _J.MOVED)
        )
    )
    commit(transaction)
    assert database.consistency_report() == replace(baseline, journal_open=1)
    transaction = artifact_harness.begin()
    ok(
        transaction.finalization_journal.compare_and_swap(
            moved.revision, bump_journal(moved, _J.REGISTERED)
        )
    )
    commit(transaction)
    assert database.consistency_report() == replace(baseline, unmapped_finalizing=1)
    ref = sample_ref(candidate)
    manifest = sample_artifact_manifest(ref)
    artifact_harness.put_ref(ref, manifest)
    assert database.consistency_report() == baseline
    # refs_without_manifest_file: a stored manifest that does not describe its row.
    other = _finalizing(artifact_harness, candidate_artifact_id=OTHER_CANDIDATE_ID)
    other_ref = sample_ref(other)
    torn_row = dict(encode_artifact_ref(other_ref, sample_artifact_manifest(other_ref)))
    torn_row["manifest_json"] = '{"artifact_id":"art_' + UUID_D + '"}'
    artifact_harness.plant_raw("artifact_refs", torn_row)
    torn_only = replace(baseline, refs_without_manifest_file=1)
    assert database.consistency_report() == torn_only
    # success_without_manifest: a success-state run with no run manifest. The
    # second run carries the sample run's adapter and engine identity under
    # ``SLOT_B``, which the Stage 8 ``slot_identity_mismatches`` count observes
    # (1), so from here the four Stage 9 counts are asserted as a projection of
    # the one report.
    put_run(
        artifact_harness.lifecycle(),
        sample_run(
            EngineRunState.SUCCEEDED, run_id=OTHER_RUN_ID, logical_slot_id=SLOT_B
        ),
    )
    report = database.consistency_report()
    assert _stage9(report) == (0, 1, 1, 0)
    assert report.slot_identity_mismatches == 1
    # journal_open counts PREPARED and MOVED entries alone.
    artifact_harness.put_journal(sample_journal(_J.PREPARED, _F.EVIDENCE))
    assert _stage9(database.consistency_report()) == (0, 1, 1, 1)
    # The torn reference is exactly what egress refuses to read back (reading 10).
    transaction = artifact_harness.begin()
    torn = transaction.artifact_refs.get_manifest(other_ref.artifact_id)
    assert code(torn) == INVARIANT_VIOLATION
    assert ok(transaction.artifact_refs.get_manifest(ref.artifact_id)) == manifest
    transaction.rollback()


# --------------------------------------------------------------------------
# Injected driver faults: every statement a repository issues answers the
# classified I/O failure, never an exception (Stage 8 plan 6.5, reading 3)
# --------------------------------------------------------------------------

#: ``SQLITE_IOERR | (1 << 8)``: the extended code of a failed page read.
_SQLITE_IOERR_READ: Final = 266
_SEEDED_CANDIDATE: Final = sample_candidate(state=_S.FINALIZING)
_SEEDED_REF: Final = sample_ref(_SEEDED_CANDIDATE)
_SEEDED_JOURNAL: Final = sample_journal(_J.PREPARED, _F.RESULT)
_PENDING_REF: Final = sample_ref(
    sample_candidate(state=_S.FINALIZING, candidate_artifact_id=OTHER_CANDIDATE_ID)
)


def _from(table: str) -> Callable[[str], bool]:
    """Admits the ``SELECT`` reading ``table`` (an ``UPDATE`` has no ``FROM``)."""
    pattern = re.compile(rf"\bFROM {table}\b")
    return lambda statement: pattern.search(statement) is not None


def _starts(prefix: str) -> Callable[[str], bool]:
    return lambda statement: statement.startswith(prefix)


class _Second:
    """Admits the second statement ``admits`` accepts while the fault is armed, so
    a method that issues one statement shape twice is refused at its later
    statement; the count resets when it fires, so the predicate is reusable."""

    def __init__(self, admits: Callable[[str], bool]) -> None:
        self._admits = admits
        self._seen = 0

    def __call__(self, statement: str) -> bool:
        if not self._admits(statement):
            return False
        self._seen += 1
        if self._seen < 2:
            return False
        self._seen = 0
        return True


def _record_pending(transaction: SqliteTransaction) -> object:
    ok(
        transaction.artifact_refs.stage_reference(
            _PENDING_REF, sample_artifact_manifest(_PENDING_REF)
        )
    )
    return transaction.artifact_refs.record_finalization(
        sample_finalization_result((_PENDING_REF,))
    )


_FAULTED_CALLS: Final[
    tuple[tuple[str, Callable[[str], bool], Callable[[SqliteTransaction], object]], ...]
] = (
    (
        "candidate_artifacts get",
        _from("candidate_artifacts"),
        lambda t: t.candidate_artifacts.get(CANDIDATE_ID),
    ),
    (
        "candidate_artifacts add",
        _starts("INSERT INTO candidate_artifacts"),
        lambda t: t.candidate_artifacts.add(
            sample_candidate(candidate_artifact_id=THIRD_CANDIDATE_ID)
        ),
    ),
    (
        "candidate_artifacts compare_and_swap",
        _from("candidate_artifacts"),
        lambda t: t.candidate_artifacts.compare_and_swap(
            _SEEDED_CANDIDATE.revision,
            bump_candidate(_SEEDED_CANDIDATE, _S.QUARANTINED),
        ),
    ),
    (
        "candidate_artifacts compare_and_swap",
        _starts("UPDATE candidate_artifacts"),
        lambda t: t.candidate_artifacts.compare_and_swap(
            _SEEDED_CANDIDATE.revision,
            bump_candidate(_SEEDED_CANDIDATE, _S.QUARANTINED),
        ),
    ),
    (
        "candidate_artifacts list_recoverable",
        _from("candidate_artifacts"),
        lambda t: t.candidate_artifacts.list_recoverable((_S.FINALIZING,)),
    ),
    (
        "artifact_refs get",
        _from("artifact_refs"),
        lambda t: t.artifact_refs.get(_SEEDED_REF.artifact_id),
    ),
    (
        "artifact_refs get_manifest",
        _from("artifact_refs"),
        lambda t: t.artifact_refs.get_manifest(_SEEDED_REF.artifact_id),
    ),
    (
        "artifact_refs list_by_owner",
        _from("artifact_refs"),
        lambda t: t.artifact_refs.list_by_owner(RUN_OWNER),
    ),
    (
        "artifact_refs record_finalization",
        _from("candidate_artifacts"),
        _record_pending,
    ),
    (
        "artifact_refs record_finalization",
        _starts("INSERT INTO artifact_refs"),
        _record_pending,
    ),
    (
        "finalization_journal get",
        _from("finalization_journal"),
        lambda t: t.finalization_journal.get(_SEEDED_JOURNAL.finalization_id),
    ),
    (
        "finalization_journal prepare",
        _starts("INSERT INTO finalization_journal"),
        lambda t: t.finalization_journal.prepare(
            sample_journal(_J.PREPARED, _F.EVIDENCE)
        ),
    ),
    (
        "finalization_journal compare_and_swap",
        _from("finalization_journal"),
        lambda t: t.finalization_journal.compare_and_swap(
            _SEEDED_JOURNAL.revision, bump_journal(_SEEDED_JOURNAL, _J.MOVED)
        ),
    ),
    (
        "finalization_journal compare_and_swap",
        _starts("UPDATE finalization_journal"),
        lambda t: t.finalization_journal.compare_and_swap(
            _SEEDED_JOURNAL.revision, bump_journal(_SEEDED_JOURNAL, _J.MOVED)
        ),
    ),
    (
        "finalization_journal list_open",
        _from("finalization_journal"),
        lambda t: t.finalization_journal.list_open(),
    ),
    (
        "finalization_journal find_result_identity",
        _from("finalization_journal"),
        lambda t: t.finalization_journal.find_result_identity(
            INVOCATION_ID, SOURCE_MANIFEST_HASH
        ),
    ),
    (
        "finalization_journal find_evidence_identity",
        _from("finalization_journal"),
        lambda t: t.finalization_journal.find_evidence_identity(
            "0" * 64, "DIAGNOSTIC", DIAG_ID, "1" * 64
        ),
    ),
    (
        "run_manifests get",
        _from("run_manifests"),
        lambda t: t.run_manifests.get(RUN_ID),
    ),
    (
        "run_manifests add",
        _starts("INSERT INTO run_manifests"),
        lambda t: t.run_manifests.add(_manifest_facts()),
    ),
    (
        "sanitized_adapter_result_manifests get",
        _from("sanitized_adapter_result_manifests"),
        lambda t: t.sanitized_manifests.get(SANITIZED_MANIFEST_HASH),
    ),
    (
        "sanitized_adapter_result_manifests add",
        _starts("INSERT INTO sanitized_adapter_result_manifests"),
        lambda t: t.sanitized_manifests.add(_sanitized_facts()),
    ),
    (
        "sanitized_adapter_result_manifests link_evidence",
        _starts("UPDATE sanitized_adapter_result_manifests"),
        lambda t: t.sanitized_manifests.link_evidence(
            SANITIZED_MANIFEST_HASH, _SEEDED_REF.artifact_id
        ),
    ),
    (
        "adapter_validation_results get",
        _from("adapter_validation_results"),
        lambda t: t.validation_results.get(OTHER_INVOCATION_ID),
    ),
    (
        "adapter_validation_results add",
        _starts("INSERT INTO adapter_validation_results"),
        lambda t: t.validation_results.add(_validation_facts()),
    ),
    (
        "adapter_validation_results link_evidence",
        _starts("UPDATE adapter_validation_results"),
        lambda t: t.validation_results.link_evidence(
            OTHER_INVOCATION_ID, _SEEDED_REF.artifact_id
        ),
    ),
    (
        "run_artifacts list_for_run",
        _from("run_artifacts"),
        lambda t: t.run_artifacts.list_for_run(RUN_ID),
    ),
    (
        "run_artifacts link",
        _starts("INSERT INTO run_artifacts"),
        lambda t: t.run_artifacts.link(
            RunArtifactLink(
                run_id=RUN_ID,
                artifact_id=_SEEDED_REF.artifact_id,
                link_role="RUN_EVIDENCE",
                experiment_id=EXPERIMENT_ID,
                run_manifest_id=MISSING,
            )
        ),
    ),
    (
        "engine_runs active_attempt_facts",
        _from("command_invocations"),
        lambda t: t.result_leases.active_attempt_facts(RUN_ID, INVOCATION_ID),
    ),
    (
        # The latest-attempt read is the second ``engine_runs`` statement of the
        # facts call (the first is the run itself).
        "engine_runs latest_attempt",
        _Second(_from("engine_runs")),
        lambda t: t.result_leases.active_attempt_facts(RUN_ID, INVOCATION_ID),
    ),
    # Every record read rebuilds its owner from ``artifact_owners``; a refusal at
    # that read is the same I/O-class failure, naming the registry's table.
    (
        "artifact_owners get",
        _from("artifact_owners"),
        lambda t: t.candidate_artifacts.get(CANDIDATE_ID),
    ),
    (
        "artifact_owners get",
        _from("artifact_owners"),
        lambda t: t.candidate_artifacts.compare_and_swap(
            _SEEDED_CANDIDATE.revision,
            bump_candidate(_SEEDED_CANDIDATE, _S.QUARANTINED),
        ),
    ),
    (
        "artifact_owners get",
        _from("artifact_owners"),
        lambda t: t.candidate_artifacts.list_recoverable((_S.FINALIZING,)),
    ),
    (
        "artifact_owners get",
        _from("artifact_owners"),
        lambda t: t.artifact_refs.get(_SEEDED_REF.artifact_id),
    ),
    (
        "artifact_owners get",
        _from("artifact_owners"),
        lambda t: t.artifact_refs.list_by_owner(RUN_OWNER),
    ),
    (
        "artifact_owners get",
        _from("artifact_owners"),
        lambda t: t.finalization_journal.get(_SEEDED_JOURNAL.finalization_id),
    ),
    (
        "artifact_owners get",
        _from("artifact_owners"),
        lambda t: t.finalization_journal.compare_and_swap(
            _SEEDED_JOURNAL.revision, bump_journal(_SEEDED_JOURNAL, _J.MOVED)
        ),
    ),
    (
        "artifact_owners get",
        _from("artifact_owners"),
        lambda t: t.finalization_journal.list_open(),
    ),
    (
        "artifact_owners get",
        _from("artifact_owners"),
        lambda t: t.finalization_journal.find_result_identity(
            INVOCATION_ID, SOURCE_MANIFEST_HASH
        ),
    ),
)


@pytest.mark.parametrize(
    ("label", "when", "attempt"),
    _FAULTED_CALLS,
    ids=[f"{index:02d}-{label}" for index, (label, _, _) in enumerate(_FAULTED_CALLS)],
)
def test_a_refused_statement_is_the_classified_io_failure(
    artifact_harness: ArtifactHarness,
    monkeypatch: pytest.MonkeyPatch,
    label: str,
    when: Callable[[str], bool],
    attempt: Callable[[SqliteTransaction], object],
) -> None:
    """Each statement a Stage 9 repository issues, refused at the driver by
    ``SQLITE_IOERR_READ``: the classified ``PERSISTENCE.WRITE_FAILED`` naming the
    table and operation, the transaction logically failed at once, and a fresh
    transaction reading normally afterwards."""
    artifact_harness.seed_result_prestate()
    artifact_harness.put_candidate(_SEEDED_CANDIDATE)
    artifact_harness.put_candidate(
        sample_candidate(state=_S.FINALIZING, candidate_artifact_id=OTHER_CANDIDATE_ID)
    )
    artifact_harness.put_ref(_SEEDED_REF, sample_artifact_manifest(_SEEDED_REF))
    artifact_harness.put_journal(_SEEDED_JOURNAL)
    table, operation = label.split(" ")
    with cursor_fault(artifact_harness.database, monkeypatch) as fault:
        transaction = artifact_harness.begin()
        fault.arm(sqlite_error(_SQLITE_IOERR_READ, "SQLITE_IOERR_READ"), when=when)
        refused = attempt(transaction)
        assert not fault.armed, (label, fault.passed)
        assert code(refused) == WRITE_FAILED
        details = _details(refused)
        assert details["table"] == table
        assert details["operation"] == operation
        assert details["sqlite_errorcode"] == _SQLITE_IOERR_READ
        assert details["sqlite_errorname"] == "SQLITE_IOERR_READ"
        assert "SELECT" not in _message(refused)
        # The transaction is logically failed: every later call answers the same
        # failure and issues no statement.
        issued = len(fault.passed)
        assert transaction.candidate_artifacts.get(CANDIDATE_ID) is refused
        assert transaction.finalization_journal.list_open() is refused
        assert transaction.audit.append(sample_audit_event()) is refused
        assert len(fault.passed) == issued
        assert transaction.commit() is refused
    fresh = artifact_harness.begin()
    assert ok(fresh.candidate_artifacts.get(CANDIDATE_ID)) == _SEEDED_CANDIDATE
    assert ok(fresh.artifact_refs.get(_SEEDED_REF.artifact_id)) == _SEEDED_REF
    fresh.rollback()


def test_a_failed_transaction_answers_every_stage9_member_without_sql(
    artifact_harness: ArtifactHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Stage 8 plan 4.2 over the Stage 9 members: once one I/O-class refusal has
    logically failed the transaction, every finalization, registration, lease,
    diagnostic and audit member answers the SAME stored ``Failure`` through its
    gate and issues no statement; staging a reference consults no gate and issues
    no SQL; ``commit()`` publishes nothing; a fresh transaction reads normally."""
    artifact_harness.seed_result_prestate()
    artifact_harness.put_candidate(_SEEDED_CANDIDATE)
    artifact_harness.put_candidate(
        sample_candidate(state=_S.FINALIZING, candidate_artifact_id=OTHER_CANDIDATE_ID)
    )
    artifact_harness.put_ref(_SEEDED_REF, sample_artifact_manifest(_SEEDED_REF))
    artifact_harness.put_journal(_SEEDED_JOURNAL)
    timeout = sample_diagnostic(
        OTHER_DIAG_ID,
        error_code="ARTIFACT.FINALIZATION_TIMED_OUT",
        category=DiagnosticCategory.TIMEOUT,
        retriable=False,
    )
    with cursor_fault(artifact_harness.database, monkeypatch) as fault:
        transaction = artifact_harness.begin()
        fault.arm(
            sqlite_error(_SQLITE_IOERR_READ, "SQLITE_IOERR_READ"),
            when=_from("candidate_artifacts"),
        )
        refused = transaction.candidate_artifacts.get(CANDIDATE_ID)
        assert code(refused) == WRITE_FAILED
        assert transaction.open_failure() is refused
        issued = len(fault.passed)
        candidates = transaction.candidate_artifacts
        refs = transaction.artifact_refs
        journal = transaction.finalization_journal
        leases = transaction.result_leases
        # Staging keeps the pair in memory for ``record_finalization``: no gate,
        # no statement; the recording below is what the failed gate refuses.
        assert (
            ok(
                refs.stage_reference(
                    _PENDING_REF, sample_artifact_manifest(_PENDING_REF)
                )
            )
            is None
        )
        answers: tuple[tuple[str, object], ...] = (
            (
                "candidate_artifacts.add",
                candidates.add(
                    sample_candidate(candidate_artifact_id=THIRD_CANDIDATE_ID)
                ),
            ),
            (
                "candidate_artifacts.compare_and_swap",
                candidates.compare_and_swap(
                    _SEEDED_CANDIDATE.revision,
                    bump_candidate(_SEEDED_CANDIDATE, _S.QUARANTINED),
                ),
            ),
            (
                "candidate_artifacts.list_recoverable",
                candidates.list_recoverable((_S.FINALIZING,)),
            ),
            ("artifact_refs.get", refs.get(_SEEDED_REF.artifact_id)),
            ("artifact_refs.get_manifest", refs.get_manifest(_SEEDED_REF.artifact_id)),
            ("artifact_refs.list_by_owner", refs.list_by_owner(RUN_OWNER)),
            (
                "artifact_refs.record_finalization",
                refs.record_finalization(sample_finalization_result((_PENDING_REF,))),
            ),
            ("finalization_journal.get", journal.get(_SEEDED_JOURNAL.finalization_id)),
            (
                "finalization_journal.prepare",
                journal.prepare(sample_journal(_J.PREPARED, _F.EVIDENCE)),
            ),
            (
                "finalization_journal.compare_and_swap",
                journal.compare_and_swap(
                    _SEEDED_JOURNAL.revision, bump_journal(_SEEDED_JOURNAL, _J.MOVED)
                ),
            ),
            ("finalization_journal.list_open", journal.list_open()),
            (
                "finalization_journal.find_result_identity",
                journal.find_result_identity(INVOCATION_ID, SOURCE_MANIFEST_HASH),
            ),
            (
                "finalization_journal.find_evidence_identity",
                journal.find_evidence_identity(
                    "0" * 64, "DIAGNOSTIC", DIAG_ID, "1" * 64
                ),
            ),
            ("run_manifests.add", transaction.run_manifests.add(_manifest_facts())),
            ("run_manifests.get", transaction.run_manifests.get(RUN_ID)),
            (
                "sanitized_manifests.add",
                transaction.sanitized_manifests.add(_sanitized_facts()),
            ),
            (
                "sanitized_manifests.get",
                transaction.sanitized_manifests.get(SANITIZED_MANIFEST_HASH),
            ),
            (
                "sanitized_manifests.link_evidence",
                transaction.sanitized_manifests.link_evidence(
                    SANITIZED_MANIFEST_HASH, _SEEDED_REF.artifact_id
                ),
            ),
            (
                "validation_results.add",
                transaction.validation_results.add(_validation_facts()),
            ),
            (
                "validation_results.get",
                transaction.validation_results.get(OTHER_INVOCATION_ID),
            ),
            (
                "validation_results.link_evidence",
                transaction.validation_results.link_evidence(
                    OTHER_INVOCATION_ID, _SEEDED_REF.artifact_id
                ),
            ),
            (
                "run_artifacts.link",
                transaction.run_artifacts.link(
                    RunArtifactLink(
                        run_id=RUN_ID,
                        artifact_id=_SEEDED_REF.artifact_id,
                        link_role="RUN_EVIDENCE",
                        experiment_id=EXPERIMENT_ID,
                        run_manifest_id=MISSING,
                    )
                ),
            ),
            (
                "run_artifacts.list_for_run",
                transaction.run_artifacts.list_for_run(RUN_ID),
            ),
            (
                "result_leases.snapshot_deadline",
                leases.snapshot_deadline(1, RUN_ID, DEADLINE),
            ),
            ("result_leases.record_timeout", leases.record_timeout(1, RUN_ID, timeout)),
            (
                "result_leases.active_attempt_facts",
                leases.active_attempt_facts(RUN_ID, INVOCATION_ID),
            ),
            (
                "diagnostics_writer.record",
                transaction.diagnostics_writer.record(sample_diagnostic()),
            ),
            (
                "audit.append_sequenced",
                transaction.audit.append_sequenced(sample_audit_event()),
            ),
        )
        for label, answer in answers:
            assert answer is refused, label
        assert len(fault.passed) == issued
        assert transaction.commit() is refused
    fresh = artifact_harness.begin()
    assert ok(fresh.candidate_artifacts.get(CANDIDATE_ID)) == _SEEDED_CANDIDATE
    assert ok(fresh.finalization_journal.get(_SEEDED_JOURNAL.finalization_id)) == (
        _SEEDED_JOURNAL
    )
    assert ok(fresh.run_artifacts.list_for_run(RUN_ID)) == ()
    fresh.rollback()
    assert artifact_harness.committed_refs() == (_SEEDED_REF,)
    assert artifact_harness.count("audit_events") == 0


# --------------------------------------------------------------------------
# record_finalization: every mapping validated before the first insert
# --------------------------------------------------------------------------


def _by_identity(*refs: ArtifactRef) -> tuple[ArtifactRef, ...]:
    """``committed_refs()`` order: by ``artifact_id``."""
    return tuple(sorted(refs, key=lambda ref: ref.artifact_id))


def _stage(transaction: SqliteTransaction, *refs: ArtifactRef) -> None:
    for ref in refs:
        manifest = sample_artifact_manifest(ref)
        ok(transaction.artifact_refs.stage_reference(ref, manifest))


def test_a_later_mapping_refusal_issues_no_insert(
    artifact_harness: ArtifactHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Plan 4.1 over SQLite: ``record_finalization`` validates every mapping
    before its first ``INSERT``. A valid first mapping followed by a second one
    of another purpose is the invariant naming the finalization, the statement
    recorder sees candidate-state reads and no insert at all, the first
    reference is unreadable on the inserting connection itself, the transaction
    stays usable (not the I/O class), and the same transaction then records the
    valid two-reference batch in mapping order."""
    artifact_harness.seed_result_prestate()
    existing = sample_ref(_finalizing(artifact_harness))
    artifact_harness.put_ref(existing, sample_artifact_manifest(existing))
    first = sample_ref(
        _finalizing(artifact_harness, candidate_artifact_id=OTHER_CANDIDATE_ID)
    )
    second = sample_ref(
        _finalizing(artifact_harness, candidate_artifact_id=THIRD_CANDIDATE_ID)
    )
    evidence = sample_ref(
        _finalizing(
            artifact_harness,
            candidate_artifact_id=_EVIDENCE_CANDIDATE_ID,
            purpose=_F.EVIDENCE,
            producer=_P.CORE,
        )
    )
    foreign = sample_finalization_result((first, evidence))
    with cursor_fault(artifact_harness.database, monkeypatch) as recorder:
        transaction = artifact_harness.begin()
        refs = transaction.artifact_refs
        _stage(transaction, first, second, evidence)
        before = len(recorder.passed)
        refused = refs.record_finalization(foreign)
        assert code(refused) == INVARIANT_VIOLATION
        assert "does not carry the finalization's purpose" in _message(refused)
        assert _details(refused) == {
            "table": "artifact_refs",
            "operation": "record_finalization",
            "identity": foreign.finalization_id,
        }
        issued = recorder.passed[before:]
        assert issued, "the valid first mapping's candidate state was read"
        assert all(_from("candidate_artifacts")(statement) for statement in issued)
        assert not any(statement.startswith(_INSERT_REF) for statement in issued)
        assert transaction.open_failure() is None
        missing = refs.get(first.artifact_id)
        assert code(missing) == INVARIANT_VIOLATION
        assert "does not exist" in _message(missing)
        batch = tuple(
            sorted((first, second), key=lambda ref: ref.artifact_id, reverse=True)
        )
        assert ok(refs.record_finalization(sample_finalization_result(batch))) == batch
        commit(transaction)
    assert artifact_harness.committed_refs() == _by_identity(existing, first, second)


def test_a_fault_at_a_later_statement_of_the_batch_commits_nothing(
    artifact_harness: ArtifactHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The database-failure semantics of both phases over a two-mapping batch: a
    refused second candidate read refuses the batch before any insert; a refused
    second insert refuses it after the first. Either way the answer is the
    classified ``PERSISTENCE.WRITE_FAILED`` naming ``artifact_refs`` and
    ``record_finalization``, the transaction is logically failed (``commit()``
    answers the same failure) and nothing of the batch is durable."""
    artifact_harness.seed_result_prestate()
    existing = sample_ref(_finalizing(artifact_harness))
    artifact_harness.put_ref(existing, sample_artifact_manifest(existing))
    first = sample_ref(
        _finalizing(artifact_harness, candidate_artifact_id=OTHER_CANDIDATE_ID)
    )
    second = sample_ref(
        _finalizing(artifact_harness, candidate_artifact_id=THIRD_CANDIDATE_ID)
    )
    result = sample_finalization_result((first, second))
    faults: tuple[tuple[str, Callable[[str], bool], int], ...] = (
        ("second candidate read", _Second(_from("candidate_artifacts")), 0),
        ("second insert", _Second(_starts(_INSERT_REF)), 1),
    )
    for label, when, inserts_before in faults:
        with cursor_fault(artifact_harness.database, monkeypatch) as fault:
            transaction = artifact_harness.begin()
            _stage(transaction, first, second)
            error = sqlite_error(_SQLITE_IOERR_READ, "SQLITE_IOERR_READ")
            fault.arm(error, when=when)
            refused = transaction.artifact_refs.record_finalization(result)
            assert not fault.armed, label
            assert code(refused) == WRITE_FAILED, label
            details = _details(refused)
            assert details["table"] == "artifact_refs", label
            assert details["operation"] == "record_finalization", label
            inserted = [s for s in fault.passed if s.startswith(_INSERT_REF)]
            assert len(inserted) == inserts_before, label
            assert transaction.open_failure() is refused, label
            assert transaction.commit() is refused, label
        assert artifact_harness.committed_refs() == (existing,), label
