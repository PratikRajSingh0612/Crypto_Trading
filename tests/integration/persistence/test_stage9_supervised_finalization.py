"""Stage 9 Task 8 (plan 7.1, 7.2 and section 8): artifact finalization composed
over the supervised SQLite flow.

Every row here drives a real fake adapter through the production
``WindowsProcessSupervisor`` over one migrated SQLite file and then concludes
the invocation through the production composition -- ``observe_candidates``
before the verdict, ``semantic_outcome_or_replay``, ``conclude_command`` with
the production ``CoreArtifactFinalizer`` over the production ``ResultRegistrar``
and ``AuditFactRecorder``, ``conclude_describe`` for the describe row,
``reconcile_invocations`` then ``reconcile_finalization`` for recovery. Every
durable assertion is a fresh read of the file after the writer returned; the
blob hashes are recomputed with ``hashlib`` independently of the production
hasher.

Test-local readings, declared rather than inferred silently:

- The Stage 8 import pin of ``tests/persistence_support/supervised.py`` is exact
  and its import set is unchanged in Stage 9: the one Stage 8 member Task 8
  extends there is ``close(keep_command_roots=True)`` (plan 7.1), with no new
  import, and ``test_stage8_supervised_flow.py`` stays unchanged (plan 7.4), so
  the Stage 9 members live on ``FinalizingSupervisedFlow`` in
  ``persistence_support/artifacts.py``, a subclass over the Stage 8 flow.
- "Crash" is ``CrashingProbe`` in process (plan section 5: Tasks 6, 7, 8); the
  RESULT cells crash the success row's RESULT finalization and the EVIDENCE
  cells crash the failure row's evidence finalization, where the first and only
  ``finalize`` is the evidence one. The real-child CP-5/CP-6 proof stays with
  ``tests/integration/artifacts/test_finalization_crash_child.py``; the SQLite
  holder of these cells is the test process, and the fake adapter launched by
  the supervisor is proven not to survive before every reopen.
- The fake catalogue admits a conformant ``VALIDATE`` only for adapters whose
  ``RUN`` succeeds, so the step-9 closure of the attempt's ``VALIDATE`` root is
  proven on the conformant attempt (``row02`` then ``row03``); the failure rows
  are ``row28`` (no candidates) and ``row36`` (two candidates quarantined).
- Through ``semantic_outcome_or_replay`` a run cancelled after ``EXITED`` answers
  with the Stage 6 core-win outcome, so the cancellation row asserts what the
  composition produces: candidates registered then quarantined by recovery, the
  evidence finalized, the root closed and the run row untouched by
  ``cancel_experiment``.
- The six facets of T28.3-12 are asserted by ``_assert_six_facets`` after each
  row's recovery: candidate rows, journal, references against the blobs,
  run and invocation, audit history equal to durable history, filesystem.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Final

import pytest
from pydantic import ValidationError

from contract.scenarios import Scenario
from crypto_lab.adapters.diagnostics import ENGINE_RUNTIME_FAILURE
from crypto_lab.adapters.reconciliation import SemanticReconciliation
from crypto_lab.adapters.vocabulary import ReconciliationVerdict, SemanticStatus
from crypto_lab.artifacts.diagnostics import (
    ARTIFACT_FINALIZATION_TIMED_OUT,
    ARTIFACT_VALIDATION_FAILED,
)
from crypto_lab.artifacts.finalizer import EVIDENCE_LEASE_SECONDS, RESULT_LEASE_SECONDS
from crypto_lab.artifacts.journal import FinalizationJournalState
from crypto_lab.artifacts.models import (
    ArtifactFinalizationPurpose,
    ArtifactRef,
    ArtifactSourceRole,
    CandidateArtifactProducerKind,
    CandidateArtifactState,
    FinalizationResult,
)
from crypto_lab.artifacts.ownership import (
    AdapterArtifactOwner,
    DatasetArtifactOwner,
    ExperimentArtifactOwner,
    RunArtifactOwner,
    StrategyArtifactOwner,
    SystemArtifactOwner,
    artifact_owner_hash,
)
from crypto_lab.artifacts.ports import CommandRootPaths, FinalizationProbe
from crypto_lab.artifacts.requests import EvidenceCorrelation
from crypto_lab.audit.models import AuditAction, LogRecord, LogSeverity
from crypto_lab.audit.redaction import (
    REDACTED,
    contains_token_shape,
    is_denylisted_key,
    redact_details,
)
from crypto_lab.domain.engine_run import SUCCESS_ENGINE_RUN_STATES, EngineRunRecord
from crypto_lab.domain.hashing import sha256_bytes
from crypto_lab.domain.lifecycle import (
    TERMINAL_ENGINE_RUN_STATES,
    CommandInvocationState,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.results import Failure, Success
from crypto_lab.experiments.finalization import (
    DIAGNOSTIC_REPORT_KIND,
    INPUT_SNAPSHOT_KINDS,
    PROTOCOL_CAPTURE_KIND,
    RESULT_MANIFEST_MEMBER,
    RUN_EVIDENCE,
    SANITIZED_MANIFEST_KIND,
    STDERR_KIND,
    CommandConclusion,
    diagnostic_report_evidence,
    finalize_evidence,
    input_snapshot_evidence,
)
from crypto_lab.experiments.run_manifest import RunManifest, run_manifest_hash
from crypto_lab.persistence.database import ConsistencyReport
from crypto_lab.process_supervision.models import (
    SupervisionOutcome,
    SupervisionTraceEntry,
    SupervisionTraceKind,
)
from doubles.artifacts import CrashingProbe, DurableState, FinalizationCrash
from doubles.experiments import INVOCATION_ID
from persistence_support.artifacts import (
    FINALIZATION_TIMEOUT_SECONDS,
    FINALIZING_CONFIG,
    ClockAdvancingProbe,
    FinalizingSupervisedFlow,
    configuration_audit_bytes,
    dataset_identity_bytes,
    strategy_identity_bytes,
)
from persistence_support.harness import ok

_C: Final = CommandInvocationState
_E: Final = ExperimentState
_J: Final = FinalizationJournalState
_P: Final = ArtifactFinalizationPurpose
_R: Final = EngineRunState
_S: Final = CandidateArtifactState
_V: Final = ReconciliationVerdict

_CONFORMANT_DESCRIBE: Final = "row01-conformant-describe"
_CONFORMANT_VALIDATE: Final = "row02-conformant-validate"
_SUCCESS_RUN: Final = "row03-conformant-run"
_WARNING_RUN: Final = "row04-warnings-run"
_EXIT_40_RUN: Final = "row28-exit-40-run"
_CHECKSUM_MISMATCH_RUN: Final = "row36-checksum-mismatch-run"
_FAILURE_RUNS: Final = (_EXIT_40_RUN, _CHECKSUM_MISMATCH_RUN)
#: The seven crash points of plan 5.1 as ``CrashingProbe(point, index)``.
_CRASH_POINTS: Final[tuple[tuple[str, int], ...]] = (
    ("before_prepared", 0),
    ("after_prepared", 0),
    ("after_move", 0),
    ("before_moved", 0),
    ("after_moved", 0),
    ("inside_registered", 0),
    ("after_registered", 0),
)
#: The cells that leave an open journal under an unexpired lease: a restart alone
#: takes no unexpired lease (the ruling of 2026-11-08), so the pass defers first.
_LEASED_POINTS: Final = frozenset(
    {"after_prepared", "after_move", "before_moved", "after_moved", "inside_registered"}
)
_EVIDENCE_KINDS_OF_RUN: Final = frozenset(
    {STDERR_KIND, PROTOCOL_CAPTURE_KIND, SANITIZED_MANIFEST_KIND}
)
_RAW_BYTE_NAMES: Final = frozenset(
    {"request.json", "output.json", "adapter-result-manifest.json"}
)
_SYSTEM_COMPONENT: Final = "tests.stage9-supervised-flow"
#: The flow's log component and the event-code prefix of its trace projection.
_LOG_COMPONENT: Final = "persistence-support.finalizing-flow"
_TRACE_EVENT_PREFIX: Final = "SUPERVISION."
#: The closed Stage 9 audit vocabulary: 25 actions, none of them a supervision
#: fact (plan 3.2; ``tests/unit/audit/test_audit_models.py`` pins the members).
_AUDIT_ACTION_COUNT: Final = 25
#: The crafted trace facts of the redaction case: a run of 40 url-safe characters
#: and a 64-character hex digest, both in the token-shape grammar.
_SHAPED_FACT: Final = "Q" * 40
_DIGEST_FACT: Final = "a" * 64


# --------------------------------------------------------------------------
# Fixtures and drivers
# --------------------------------------------------------------------------


@pytest.fixture
def finalizing_flow(tmp_path: Path) -> Iterator[FinalizingSupervisedFlow]:
    """One finalizing composition over one migrated database; closed in
    teardown, which terminates and awaits every launched child."""
    flow = FinalizingSupervisedFlow.open(tmp_path, config=FINALIZING_CONFIG)
    try:
        yield flow
    finally:
        flow.close()


@dataclass(frozen=True, slots=True)
class _Driven:
    """One attempt driven through the supervisor and the conclusion."""

    run_id: str
    experiment_id: str
    validate_invocation_id: str | None
    run_invocation_id: str
    outcome: SupervisionOutcome
    conclusion: CommandConclusion | None
    #: The blobs present before the conclusion (the describe row's evidence).
    blobs_before: tuple[str, ...] = ()


def _describe(flow: FinalizingSupervisedFlow) -> None:
    flow.describe(flow.scenario(_CONFORMANT_DESCRIBE))


def _ready_run(
    flow: FinalizingSupervisedFlow, row: Scenario, *, through_validate: bool
) -> tuple[EngineRunRecord, str | None]:
    """The attempt at ``READY``: through the conformant ``VALIDATE`` invocation
    of the same adapter when asked, else by the Stage 8 transition."""
    if not through_validate:
        return flow.prepare_run(row), None
    validate_row = flow.scenario(_CONFORMANT_VALIDATE)
    assert validate_row.adapter_name == row.adapter_name
    run = flow.prepare_run(validate_row)
    assert run.state is _R.VALIDATING
    validated = flow.invoke(validate_row, run)
    concluded = flow.conclude_and_finalize(validate_row, run, validated)
    assert isinstance(concluded, CommandConclusion)
    assert concluded.run.state is _R.READY
    assert isinstance(concluded.run.availability_observation_id, str)
    return flow.fresh_run(run.run_id), validated.command_result.invocation.invocation_id


def _drive(
    flow: FinalizingSupervisedFlow,
    name: str,
    *,
    probe: FinalizationProbe | None = None,
    through_validate: bool = False,
) -> _Driven:
    row = flow.scenario(name)
    run, validate_invocation_id = _ready_run(
        flow, row, through_validate=through_validate
    )
    assert run.state is _R.READY
    outcome = flow.invoke(row, run)
    assert flow.max_open_during_child == 0
    conclusion = flow.conclude_and_finalize(row, run, outcome, probe=probe)
    return _Driven(
        run_id=run.run_id,
        experiment_id=run.experiment_id,
        validate_invocation_id=validate_invocation_id,
        run_invocation_id=outcome.command_result.invocation.invocation_id,
        outcome=outcome,
        conclusion=conclusion,
    )


def _blob_sha256(path: Path) -> str:
    """The independent digest: ``hashlib`` over the whole file."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _declared_hashes(outcome: SupervisionOutcome) -> dict[str, str]:
    """The adapter's declared digests by relative path, from the accepted events."""
    return {
        record.payload.relative_path: record.payload.declared_sha256
        for record in outcome.protocol_summary.artifact_declarations
    }


def _refs_of_purpose(
    refs: tuple[ArtifactRef, ...], purpose: ArtifactFinalizationPurpose
) -> tuple[ArtifactRef, ...]:
    return tuple(ref for ref in refs if ref.finalization_purpose is purpose)


def _journals_of_purpose(
    flow: FinalizingSupervisedFlow, purpose: ArtifactFinalizationPurpose, run_id: str
) -> tuple[FinalizationJournalState, ...]:
    return tuple(
        entry.state
        for entry in flow.fresh_journal()
        if entry.finalization_purpose is purpose
        and isinstance(entry.owner, RunArtifactOwner)
        and entry.owner.run_id == run_id
    )


def _raw_bytes_under(flow: FinalizingSupervisedFlow, invocation_id: str) -> list[str]:
    return [
        name
        for name in flow.command_root_files()
        if name.startswith(f"{invocation_id}/")
        and name.rsplit("/", 1)[-1] in _RAW_BYTE_NAMES
    ]


def _assert_no_dangling(flow: FinalizingSupervisedFlow) -> ConsistencyReport:
    report = flow.consistency_report()
    assert report.dangling_diagnostic_references == 0
    assert report.success_without_manifest == 0
    assert report.unmapped_finalizing == 0
    return report


def _assert_six_facets(
    flow: FinalizingSupervisedFlow,
    driven: _Driven,
    *,
    run_state: EngineRunState,
) -> DurableState:
    """T28.3-12 after the row's recovery: (1) candidate rows, (2) journal, (3)
    references against their blobs and manifests, (4) run and invocation, (5)
    audit history equal to durable history, (6) the filesystem; plus the
    consistency report and ``quick_check``."""
    after = flow.durable(driven.run_id)
    # 1. Rows: nothing is left open; every FINALIZING candidate is mapped.
    mapped = {ref.source_candidate_artifact_id for ref in after.refs}
    for candidate in after.candidates:
        assert candidate.state not in (_S.CANDIDATE, _S.VALIDATING), candidate
        if candidate.state is _S.FINALIZING:
            assert candidate.candidate_artifact_id in mapped, candidate
    for ref in after.refs:
        assert after.candidate_states[ref.source_candidate_artifact_id] == "FINALIZING"
    # 2. Journal: every entry is terminal.
    assert all(entry.state in (_J.REGISTERED, _J.ABANDONED) for entry in after.journal)
    registered = [entry for entry in after.journal if entry.state is _J.REGISTERED]
    abandoned = [entry for entry in after.journal if entry.state is _J.ABANDONED]
    # 3. References: the blob at the finalized path hashes to the reference and a
    #    manifest row exists for each.
    manifests = {item.artifact_id for item in flow.harness.committed_manifests()}
    for ref in after.refs:
        blob = flow.store.finalized_path_for(ref.content_hash)
        assert blob.is_file(), ref.artifact_id
        assert _blob_sha256(blob) == ref.content_hash
        assert blob.stat().st_size == ref.size_bytes
        assert ref.artifact_id in manifests
    # 4. Run and invocation.
    assert after.run is not None
    assert after.run.state is run_state
    assert after.invocation is not None
    assert after.invocation.invocation_id == driven.run_invocation_id
    assert after.invocation.state is _C.EXITED
    assert after.invocation.cleanup_complete is True
    # 5. Audit history equals durable history (the counts are flow-wide).
    actions = after.audit_actions
    assert actions.count("FINALIZATION_REGISTERED") == len(registered)
    assert actions.count("FINALIZATION_ABANDONED") + actions.count(
        "FINALIZATION_TIMED_OUT"
    ) == len(abandoned)
    success_runs = [
        run for run in flow.fresh_runs() if run.state in SUCCESS_ENGINE_RUN_STATES
    ]
    assert actions.count("RUN_MANIFEST_REGISTERED") == len(after.run_manifests)
    assert actions.count("RUN_SUCCEEDED") == len(after.run_manifests)
    assert len(success_runs) == len(after.run_manifests)
    assert (driven.run_id in {row.run_id for row in after.run_manifests}) is (
        run_state in SUCCESS_ENGINE_RUN_STATES
    )
    # 6. Filesystem: objects hold exactly the registered blobs, core staging is
    #    empty and no raw-bearing byte survives under a terminal run's roots.
    assert set(after.object_blobs) == {ref.content_hash for ref in after.refs}
    assert after.staging_files == ()
    if run_state in TERMINAL_ENGINE_RUN_STATES:
        assert _raw_bytes_under(flow, driven.run_invocation_id) == []
        if driven.validate_invocation_id is not None:
            assert _raw_bytes_under(flow, driven.validate_invocation_id) == []
    _assert_no_dangling(flow)
    assert flow.quick_check() == "ok"
    return after


# --------------------------------------------------------------------------
# The success and warning rows
# --------------------------------------------------------------------------


def _assert_success(
    flow: FinalizingSupervisedFlow,
    driven: _Driven,
    *,
    run_state: EngineRunState,
    semantic_status: SemanticStatus,
) -> CommandConclusion:
    conclusion = driven.conclusion
    assert isinstance(conclusion, CommandConclusion)
    assert conclusion.replayed is False
    assert not isinstance(conclusion.evidence_failure, Failure)
    # The run, its manifest row and the manifest record.
    stored = flow.fresh_run(driven.run_id)
    assert stored.state is run_state
    assert conclusion.run == stored
    manifest = flow.fresh_manifest(driven.run_id)
    assert isinstance(manifest, RunManifest)
    assert manifest == conclusion.run_manifest
    assert manifest.run_id == driven.run_id
    assert manifest.run_invocation_id == driven.run_invocation_id
    assert manifest.semantic_status == semantic_status.value
    assert run_manifest_hash(manifest) == manifest.run_manifest_hash
    facts = flow.fresh_manifest_facts(driven.run_id)
    assert facts.run_manifest_hash == manifest.run_manifest_hash
    assert facts.attempt_token_hash == stored.attempt_token_hash
    # Two RESULT references: the adapter's two declared candidates, their blobs
    # hashed independently and equal to the declarations.
    declared = _declared_hashes(driven.outcome)
    assert len(declared) == 2
    result_refs = _refs_of_purpose(flow.fresh_refs(driven.run_id), _P.RESULT)
    assert len(result_refs) == 2
    assert sorted(ref.artifact_id for ref in result_refs) == sorted(
        ref.artifact_id for ref in conclusion.result_refs
    )
    assert {ref.content_hash for ref in result_refs} == set(declared.values())
    for ref in result_refs:
        assert ref.producer_kind is CandidateArtifactProducerKind.ADAPTER
        assert ref.source_role is ArtifactSourceRole.ENGINE_NATIVE_RESULT
        assert isinstance(ref.owner, RunArtifactOwner)
        assert ref.owner.run_id == driven.run_id
        assert ref.owner.invocation_id == driven.run_invocation_id
        blob = flow.store.finalized_path_for(ref.content_hash)
        assert _blob_sha256(blob) == ref.content_hash
    assert {ref.artifact_id for ref in manifest.artifact_refs} == {
        ref.artifact_id for ref in result_refs
    }
    # Member links and evidence links.
    links = flow.fresh_links(driven.run_id)
    members = [link for link in links if link.link_role == RESULT_MANIFEST_MEMBER]
    assert {link.artifact_id for link in members} == {
        ref.artifact_id for ref in result_refs
    }
    assert all(link.run_manifest_id == manifest.manifest_id for link in members)
    evidence_links = [link for link in links if link.link_role == RUN_EVIDENCE]
    evidence_refs = _refs_of_purpose(flow.fresh_refs(driven.run_id), _P.EVIDENCE)
    assert {link.artifact_id for link in evidence_links} >= {
        ref.artifact_id for ref in conclusion.evidence_refs
    }
    assert {ref.artifact_id for ref in conclusion.evidence_refs} <= {
        ref.artifact_id for ref in evidence_refs
    }
    # The sanitized-manifest row carries its evidence reference; the stderr
    # evidence is linked on the invocation.
    sanitized = flow.fresh_sanitized_manifest(
        manifest.sanitized_adapter_result_manifest_hash
    )
    by_kind = {ref.artifact_kind: ref for ref in conclusion.evidence_refs}
    assert set(by_kind) == _EVIDENCE_KINDS_OF_RUN
    assert (
        sanitized.evidence_artifact_id == by_kind[SANITIZED_MANIFEST_KIND].artifact_id
    )
    invocation = flow.fresh_invocation(driven.run_invocation_id)
    assert invocation.state is _C.EXITED
    assert invocation.stderr_artifact_id == by_kind[STDERR_KIND].artifact_id
    # The journal: RESULT and EVIDENCE both REGISTERED for this run.
    assert _journals_of_purpose(flow, _P.RESULT, driven.run_id) == (_J.REGISTERED,)
    assert _J.REGISTERED in _journals_of_purpose(flow, _P.EVIDENCE, driven.run_id)
    # The RESULT lease closed the RUN root's raw-bearing bytes.
    assert _raw_bytes_under(flow, driven.run_invocation_id) == []
    # ``objects/`` holds exactly the blobs of every reference of this flow.
    assert set(flow.object_blobs()) == {
        ref.content_hash for ref in flow.harness.committed_refs()
    }
    assert flow.quarantine_entries() == ()
    return conclusion


def test_success_row_registers_manifest_and_refs(
    finalizing_flow: FinalizingSupervisedFlow,
) -> None:
    flow = finalizing_flow
    _describe(flow)
    driven = _drive(flow, _SUCCESS_RUN, through_validate=True)
    conclusion = _assert_success(
        flow, driven, run_state=_R.SUCCEEDED, semantic_status=SemanticStatus.SUCCEEDED
    )
    assert isinstance(conclusion.run_manifest, RunManifest)
    assert conclusion.run_manifest.warnings == ()
    assert len(conclusion.run_manifest.metrics) == 1
    # The VALIDATE invocation of the same attempt finalized its own evidence and
    # left its request material for the Stage 7 resume rule; the step-9 sweep of
    # the terminal attempt closes it.
    validate_id = driven.validate_invocation_id
    assert validate_id is not None
    validation = flow.fresh_validation_result(validate_id)
    assert isinstance(validation.evidence_artifact_id, str)
    validate_invocation = flow.fresh_invocation(validate_id)
    assert isinstance(validate_invocation.stderr_artifact_id, str)
    assert _raw_bytes_under(flow, validate_id) != []
    reports = flow.recover()
    assert reports.process.entries == ()
    assert reports.artifacts.closed_roots == 1
    assert reports.artifacts.registered == 0
    assert _raw_bytes_under(flow, validate_id) == []
    # Reading 24: a second conclusion of the same outcome answers with the stored
    # conclusion and invokes no operation.
    audit_before = len(flow.fresh_audit())
    row = flow.scenario(_SUCCESS_RUN)
    replayed = flow.conclude_and_finalize(row, conclusion.run, driven.outcome)
    assert isinstance(replayed, CommandConclusion)
    assert replayed.replayed is True
    assert replayed.run_manifest == conclusion.run_manifest
    assert replayed.result_refs == conclusion.result_refs
    assert len(flow.fresh_audit()) == audit_before
    experiment = flow.fresh_experiment(driven.experiment_id)
    assert experiment.state is _E.RUNNING
    _assert_six_facets(flow, driven, run_state=_R.SUCCEEDED)


def test_warning_row_succeeds_with_warnings(
    finalizing_flow: FinalizingSupervisedFlow,
) -> None:
    flow = finalizing_flow
    _describe(flow)
    driven = _drive(flow, _WARNING_RUN)
    conclusion = _assert_success(
        flow,
        driven,
        run_state=_R.SUCCEEDED_WITH_WARNINGS,
        semantic_status=SemanticStatus.SUCCEEDED_WITH_WARNINGS,
    )
    assert isinstance(conclusion.run_manifest, RunManifest)
    assert len(conclusion.run_manifest.warnings) == 1
    assert isinstance(conclusion.finalization, FinalizationResult)
    assert (
        conclusion.finalization.run_manifest_id == conclusion.run_manifest.manifest_id
    )
    flow.recover()
    _assert_six_facets(flow, driven, run_state=_R.SUCCEEDED_WITH_WARNINGS)


# --------------------------------------------------------------------------
# The failure, cancellation and finalization-timeout rows
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", _FAILURE_RUNS)
def test_failure_row_keeps_only_evidence(
    finalizing_flow: FinalizingSupervisedFlow, name: str
) -> None:
    flow = finalizing_flow
    _describe(flow)
    driven = _drive(flow, name)
    row = flow.scenario(name)
    conclusion = driven.conclusion
    assert isinstance(conclusion, CommandConclusion)
    assert conclusion.run.state is _R.FAILED
    assert not isinstance(conclusion.finalization, FinalizationResult)
    assert not isinstance(conclusion.run_manifest, RunManifest)
    assert conclusion.result_refs == ()
    primary = flow.fresh_diagnostic(conclusion.run.primary_terminal_diagnostic_id)
    assert primary.error_code == row.primary_code
    # No manifest, no RESULT reference, no RESULT journal.
    assert flow.fresh_manifest(driven.run_id) is None
    assert _refs_of_purpose(flow.fresh_refs(driven.run_id), _P.RESULT) == ()
    assert _journals_of_purpose(flow, _P.RESULT, driven.run_id) == ()
    # The stderr, protocol-capture and sanitized-manifest evidence is present.
    kinds = {ref.artifact_kind for ref in conclusion.evidence_refs}
    assert kinds == _EVIDENCE_KINDS_OF_RUN
    assert _journals_of_purpose(flow, _P.EVIDENCE, driven.run_id) == (_J.REGISTERED,)
    # Plan 4.4 step 5: the RUN root's raw-bearing bytes are gone before recover().
    assert _raw_bytes_under(flow, driven.run_invocation_id) == []
    before = flow.durable(driven.run_id)
    adapter_candidates = [
        candidate
        for candidate in before.candidates
        if candidate.producer_kind is CandidateArtifactProducerKind.ADAPTER
    ]
    expected_candidates = len(_declared_hashes(driven.outcome))
    assert len(adapter_candidates) == expected_candidates
    assert all(candidate.state is _S.CANDIDATE for candidate in adapter_candidates)
    reports = flow.recover()
    assert reports.process.entries == ()
    assert reports.artifacts.registered == 0
    assert reports.artifacts.quarantined == expected_candidates
    after = flow.durable(driven.run_id)
    assert after.run_state == "FAILED"
    assert after.run_manifests == ()
    for candidate in adapter_candidates:
        assert after.candidate_states[candidate.candidate_artifact_id] == "QUARANTINED"
    assert len(after.quarantine_entries) == expected_candidates
    second = flow.recover()
    assert second.artifacts.changes == 0
    _assert_six_facets(flow, driven, run_state=_R.FAILED)


def test_cancellation_row(finalizing_flow: FinalizingSupervisedFlow) -> None:
    """RC-1 through the production run-cancel edge: ``transition_run`` to
    ``CANCELLED`` with a ``CANCELLATION`` diagnostic after ``EXITED``;
    ``cancel_experiment`` is issued too and leaves the run row untouched."""
    flow = finalizing_flow
    _describe(flow)
    row = flow.scenario(_SUCCESS_RUN)
    run = flow.prepare_run(row)
    outcome = flow.invoke(row, run)
    invocation_id = outcome.command_result.invocation.invocation_id
    exited = flow.fresh_run(run.run_id)
    assert exited.state is _R.RUNNING
    cancelled = flow.cancel_run(run.run_id)
    assert cancelled.state is _R.CANCELLED
    assert cancelled.revision == exited.revision + 1
    primary = flow.fresh_diagnostic(cancelled.primary_terminal_diagnostic_id)
    assert primary.category.value == "CANCELLATION"
    assert primary.invocation_id == invocation_id
    experiment = flow.cancel_experiment(run.experiment_id)
    assert experiment.state is _E.CANCELLED
    assert flow.fresh_run(run.run_id) == cancelled  # the run row is untouched
    conclusion = flow.conclude_and_finalize(row, run, outcome)
    assert isinstance(conclusion, CommandConclusion)
    assert conclusion.run.state is _R.CANCELLED
    assert not isinstance(conclusion.finalization, FinalizationResult)
    assert not isinstance(conclusion.run_manifest, RunManifest)
    assert conclusion.result_refs == ()
    assert {ref.artifact_kind for ref in conclusion.evidence_refs} == {
        STDERR_KIND,
        PROTOCOL_CAPTURE_KIND,
    }
    assert _journals_of_purpose(flow, _P.RESULT, run.run_id) == ()
    assert flow.fresh_manifest(run.run_id) is None
    assert _raw_bytes_under(flow, invocation_id) == []
    before = flow.durable(run.run_id)
    adapter_candidates = [
        candidate
        for candidate in before.candidates
        if candidate.producer_kind is CandidateArtifactProducerKind.ADAPTER
    ]
    assert len(adapter_candidates) == 2
    assert all(candidate.state is _S.CANDIDATE for candidate in adapter_candidates)
    reports = flow.recover()
    assert reports.artifacts.quarantined == 2
    assert reports.artifacts.registered == 0
    after = flow.durable(run.run_id)
    assert after.run == cancelled
    assert after.run_manifests == ()
    assert len(after.quarantine_entries) == 2
    driven = _Driven(
        run_id=run.run_id,
        experiment_id=run.experiment_id,
        validate_invocation_id=None,
        run_invocation_id=invocation_id,
        outcome=outcome,
        conclusion=conclusion,
    )
    _assert_six_facets(flow, driven, run_state=_R.CANCELLED)


def test_finalization_timeout_row(finalizing_flow: FinalizingSupervisedFlow) -> None:
    """RC-4 with the flow's advancing clock: the deadline passes between
    ``after_moved`` and T3, so T3 records the timeout, the run moves to
    ``TIMED_OUT``, the journal is abandoned and the moved blobs are quarantined;
    the invocation stays ``EXITED`` and the evidence still finalizes."""
    flow = finalizing_flow
    _describe(flow)
    probe = ClockAdvancingProbe(
        "after_moved", flow.clock, FINALIZATION_TIMEOUT_SECONDS + 1
    )
    driven = _drive(flow, _SUCCESS_RUN, probe=probe)
    assert probe.fired == 1
    assert probe.reached == 2  # the RESULT and the evidence finalization
    conclusion = driven.conclusion
    assert isinstance(conclusion, CommandConclusion)
    assert conclusion.run.state is _R.TIMED_OUT
    assert not isinstance(conclusion.finalization, FinalizationResult)
    assert not isinstance(conclusion.run_manifest, RunManifest)
    assert conclusion.result_refs == ()
    primary = flow.fresh_diagnostic(conclusion.run.primary_terminal_diagnostic_id)
    assert primary.error_code == ARTIFACT_FINALIZATION_TIMED_OUT
    assert primary.invocation_id == driven.run_invocation_id
    assert _journals_of_purpose(flow, _P.RESULT, driven.run_id) == (_J.ABANDONED,)
    (entry,) = [
        item for item in flow.fresh_journal() if item.finalization_purpose is _P.RESULT
    ]
    assert entry.abandon_reason == ARTIFACT_FINALIZATION_TIMED_OUT
    assert flow.fresh_manifest(driven.run_id) is None
    assert _refs_of_purpose(flow.fresh_refs(driven.run_id), _P.RESULT) == ()
    assert {ref.artifact_kind for ref in conclusion.evidence_refs} == (
        _EVIDENCE_KINDS_OF_RUN
    )
    after = flow.durable(driven.run_id)
    adapter_states = [
        candidate.state
        for candidate in after.candidates
        if candidate.producer_kind is CandidateArtifactProducerKind.ADAPTER
    ]
    assert adapter_states == [_S.QUARANTINED, _S.QUARANTINED]
    (quarantine,) = [
        item for item in after.quarantine_entries if item.entry_id.startswith("fin_")
    ]
    assert len(quarantine.files) == 2
    assert after.audit_actions.count("FINALIZATION_TIMED_OUT") == 1
    assert after.invocation is not None
    assert after.invocation.state is _C.EXITED
    assert _raw_bytes_under(flow, driven.run_invocation_id) == []
    reports = flow.recover()
    assert reports.artifacts.changes == 0
    _assert_six_facets(flow, driven, run_state=_R.TIMED_OUT)


# --------------------------------------------------------------------------
# Every crash point through the production registrar
# --------------------------------------------------------------------------


def _run_refs(before: DurableState, run_id: str) -> tuple[ArtifactRef, ...]:
    """The references whose ``RUN`` owner names the run (the describe row's
    ``ADAPTER``-owned references are excluded)."""
    return tuple(
        ref
        for ref in before.refs
        if isinstance(ref.owner, RunArtifactOwner) and ref.owner.run_id == run_id
    )


def _new_blobs(before: DurableState, driven: _Driven) -> set[str]:
    """The blobs the conclusion added beside the describe row's evidence."""
    return set(before.object_blobs) - set(driven.blobs_before)


def _planned_hashes(
    flow: FinalizingSupervisedFlow, purpose: ArtifactFinalizationPurpose, run_id: str
) -> tuple[str, ...]:
    """The planned content hashes of the run's one journal of ``purpose``, in
    the finalizer's move order."""
    entries = [
        entry
        for entry in flow.fresh_journal()
        if entry.finalization_purpose is purpose
        and isinstance(entry.owner, RunArtifactOwner)
        and entry.owner.run_id == run_id
    ]
    assert len(entries) == 1, entries
    return tuple(move.expected_sha256 for move in entries[0].planned_paths)


def _assert_result_cell_before_recovery(
    flow: FinalizingSupervisedFlow, driven: _Driven, point: str
) -> None:
    before = flow.durable(driven.run_id)
    journals = _journals_of_purpose(flow, _P.RESULT, driven.run_id)
    adapter_states = {
        candidate.candidate_artifact_id: candidate.state
        for candidate in before.candidates
        if candidate.producer_kind is CandidateArtifactProducerKind.ADAPTER
    }
    assert len(adapter_states) == 2
    assert before.run is not None
    new_blobs = _new_blobs(before, driven)
    if point == "before_prepared":
        assert journals == ()
        assert set(adapter_states.values()) == {_S.VALIDATING}
        assert before.run.state is _R.RUNNING
        assert before.run_deadline is None
        assert new_blobs == set()
    elif point in ("after_prepared", "after_move", "before_moved"):
        assert journals == (_J.PREPARED,)
        assert set(adapter_states.values()) == {_S.FINALIZING}
        assert before.run.state is _R.RUNNING
        assert before.run_deadline is not None
        planned = _planned_hashes(flow, _P.RESULT, driven.run_id)
        assert len(planned) == 2
        expected = {
            "after_prepared": set(),
            "after_move": {planned[0]},
            "before_moved": set(planned),
        }
        assert new_blobs == expected[point]
    elif point in ("after_moved", "inside_registered"):
        assert journals == (_J.MOVED,)
        assert _run_refs(before, driven.run_id) == ()
        assert before.run_manifests == ()
        assert before.run.state is _R.RUNNING
        assert "RUN_SUCCEEDED" not in before.audit_actions
        assert "RUN_MANIFEST_REGISTERED" not in before.audit_actions
        assert new_blobs == set(_planned_hashes(flow, _P.RESULT, driven.run_id))
    else:
        assert point == "after_registered"
        assert journals == (_J.REGISTERED,)
        assert len(_refs_of_purpose(_run_refs(before, driven.run_id), _P.RESULT)) == 2
        assert len(before.run_manifests) == 1
        assert before.run.state is _R.SUCCEEDED
        # The phase-6 close never ran: the raw-bearing bytes are still there.
        assert _raw_bytes_under(flow, driven.run_invocation_id) != []
    # The crash aborted the conclusion before its evidence finalization.
    assert _journals_of_purpose(flow, _P.EVIDENCE, driven.run_id) == ()
    assert before.invocation is not None
    assert before.invocation.state is _C.EXITED
    assert flow.unit_of_work.open_transactions() == ()


def _assert_evidence_cell_before_recovery(
    flow: FinalizingSupervisedFlow, driven: _Driven, point: str
) -> None:
    before = flow.durable(driven.run_id)
    journals = _journals_of_purpose(flow, _P.EVIDENCE, driven.run_id)
    core_states = {
        candidate.candidate_artifact_id: candidate.state
        for candidate in before.candidates
        if candidate.producer_kind is CandidateArtifactProducerKind.CORE
        and isinstance(candidate.owner, RunArtifactOwner)
    }
    assert len(core_states) == 3
    assert before.run is not None
    assert before.run.state is _R.FAILED
    assert before.run_manifests == ()
    assert _journals_of_purpose(flow, _P.RESULT, driven.run_id) == ()
    blobs = set(before.object_blobs)
    if point == "before_prepared":
        assert journals == ()
        assert set(core_states.values()) == {_S.VALIDATING}
        assert _new_blobs(before, driven) == set()
    elif point in ("after_prepared", "after_move", "before_moved"):
        assert journals == (_J.PREPARED,)
        assert set(core_states.values()) == {_S.FINALIZING}
        planned = _planned_hashes(flow, _P.EVIDENCE, driven.run_id)
        assert len(planned) == 3
        if point == "after_prepared":
            assert _new_blobs(before, driven) == set()
        elif point == "after_move":
            # The first planned move is in place (it may deduplicate against the
            # describe row's blob); the others are still in staging.
            assert planned[0] in blobs
            assert _new_blobs(before, driven) <= {planned[0]}
        else:
            assert set(planned) <= blobs
    elif point in ("after_moved", "inside_registered"):
        assert journals == (_J.MOVED,)
        assert _run_refs(before, driven.run_id) == ()
        assert set(_planned_hashes(flow, _P.EVIDENCE, driven.run_id)) <= blobs
        assert before.audit_actions[-1] == "FINALIZATION_MOVED"
    else:
        assert point == "after_registered"
        assert journals == (_J.REGISTERED,)
        assert len(_run_refs(before, driven.run_id)) == 3
    # The crash aborted the conclusion before its terminal close: the RUN root's
    # raw-bearing bytes are still there for the step-9 sweep.
    assert _raw_bytes_under(flow, driven.run_invocation_id) != []
    assert flow.unit_of_work.open_transactions() == ()


def _assert_result_cell_recovered(
    flow: FinalizingSupervisedFlow, driven: _Driven
) -> None:
    """Plan 5.1, the RESULT recovery column: the attempt registers to success
    through the production registrar. The run's core evidence, staged by the
    crashed conclusion and never leased, is the independently recoverable CP-1
    group of the EVIDENCE column: under the corrected RV-10 (the ruling of
    2026-11-10) the pass resumes and registers it instead of quarantining it
    for the invocation's completed cleanup, so every core candidate is
    FINALIZING and mapped and nothing of the run is quarantined."""
    after = flow.durable(driven.run_id)
    assert after.run_state == "SUCCEEDED"
    assert _journals_of_purpose(flow, _P.RESULT, driven.run_id) == (_J.REGISTERED,)
    declared = _declared_hashes(driven.outcome)
    result_refs = _refs_of_purpose(after.refs, _P.RESULT)
    assert {ref.content_hash for ref in result_refs} == set(declared.values())
    (row,) = after.run_manifests
    manifest = RunManifest.model_validate_json(row.manifest_json)
    assert run_manifest_hash(manifest) == row.run_manifest_hash
    assert {ref.artifact_id for ref in manifest.artifact_refs} == {
        ref.artifact_id for ref in result_refs
    }
    members = [
        link for link in after.run_artifacts if link.link_role == RESULT_MANIFEST_MEMBER
    ]
    assert {link.artifact_id for link in members} == {
        ref.artifact_id for ref in result_refs
    }
    core = [
        candidate
        for candidate in after.candidates
        if candidate.producer_kind is CandidateArtifactProducerKind.CORE
        and isinstance(candidate.owner, RunArtifactOwner)
        and candidate.owner.run_id == driven.run_id
    ]
    assert {candidate.artifact_kind for candidate in core} == _EVIDENCE_KINDS_OF_RUN
    mapped = {ref.source_candidate_artifact_id for ref in after.refs}
    for candidate in core:
        assert candidate.state is _S.FINALIZING, candidate
        assert candidate.candidate_artifact_id in mapped
    assert _journals_of_purpose(flow, _P.EVIDENCE, driven.run_id) == (_J.REGISTERED,)
    evidence_refs = [
        ref
        for ref in _refs_of_purpose(after.refs, _P.EVIDENCE)
        if isinstance(ref.owner, RunArtifactOwner) and ref.owner.run_id == driven.run_id
    ]
    assert {ref.artifact_kind for ref in evidence_refs} == _EVIDENCE_KINDS_OF_RUN
    assert after.quarantine_entries == ()
    assert _raw_bytes_under(flow, driven.run_invocation_id) == []


def _assert_evidence_cell_recovered(
    flow: FinalizingSupervisedFlow, driven: _Driven
) -> None:
    """Plan 5.1, the EVIDENCE recovery column: the evidence registers without
    touching the run (29.4). For CP-1 the column reads "step 4 revalidates the
    core candidates independently and resumes from phase 2": the corrected
    RV-10 (the ruling of 2026-11-10) no longer quarantines core staging for the
    invocation's completed cleanup when the staging is not older than it."""
    after = flow.durable(driven.run_id)
    assert after.run_state == "FAILED"
    assert after.run_manifests == ()
    assert _journals_of_purpose(flow, _P.RESULT, driven.run_id) == ()
    assert _journals_of_purpose(flow, _P.EVIDENCE, driven.run_id) == (_J.REGISTERED,), (
        "plan 5.1 CP-1 EVIDENCE: step 4 revalidates the core candidates and "
        "resumes from phase 2; the pass left them as",
        {
            candidate.artifact_kind: candidate.state.value
            for candidate in after.candidates
            if candidate.producer_kind is CandidateArtifactProducerKind.CORE
            and isinstance(candidate.owner, RunArtifactOwner)
        },
        after.audit_actions[-3:],
    )
    evidence_refs = [
        ref
        for ref in _refs_of_purpose(after.refs, _P.EVIDENCE)
        if isinstance(ref.owner, RunArtifactOwner)
    ]
    assert {ref.artifact_kind for ref in evidence_refs} == _EVIDENCE_KINDS_OF_RUN
    adapter_states = [
        candidate.state
        for candidate in after.candidates
        if candidate.producer_kind is CandidateArtifactProducerKind.ADAPTER
    ]
    assert adapter_states == [_S.QUARANTINED, _S.QUARANTINED]
    assert len(after.quarantine_entries) == 2
    assert _raw_bytes_under(flow, driven.run_invocation_id) == []


@pytest.mark.parametrize("purpose", ["RESULT", "EVIDENCE"])
@pytest.mark.parametrize(("point", "index"), _CRASH_POINTS)
def test_every_crash_point_through_production_registrar(
    tmp_path: Path, point: str, index: int, purpose: str
) -> None:
    result_cell = purpose == "RESULT"
    name = _SUCCESS_RUN if result_cell else _CHECKSUM_MISMATCH_RUN
    flow = FinalizingSupervisedFlow.open(tmp_path, config=FINALIZING_CONFIG)
    try:
        _describe(flow)
        row = flow.scenario(name)
        run = flow.prepare_run(row)
        outcome = flow.invoke(row, run)
        driven = _Driven(
            run_id=run.run_id,
            experiment_id=run.experiment_id,
            validate_invocation_id=None,
            run_invocation_id=outcome.command_result.invocation.invocation_id,
            outcome=outcome,
            conclusion=None,
            blobs_before=flow.object_blobs(),
        )
        with pytest.raises(FinalizationCrash):
            flow.conclude_and_finalize(
                row, run, outcome, probe=CrashingProbe(point, index)
            )
        if result_cell:
            _assert_result_cell_before_recovery(flow, driven, point)
        else:
            _assert_evidence_cell_before_recovery(flow, driven, point)
        # 28.3:2096: the fake adapter the supervisor launched does not survive;
        # the command roots are kept for recovery.
        assert flow.assert_no_child_survives() >= 1
    finally:
        flow.close(keep_command_roots=True)
    reopened = FinalizingSupervisedFlow.reopen(tmp_path)
    try:
        assert reopened.quick_check() == "ok"
        if point in _LEASED_POINTS:
            deferred = reopened.recover()
            assert deferred.process.entries == ()
            assert deferred.artifacts.deferred == 1
            assert deferred.artifacts.abandoned == 0
            lease = RESULT_LEASE_SECONDS if result_cell else EVIDENCE_LEASE_SECONDS
            reopened.clock.advance(lease + 1)
        reports = reopened.recover()
        assert reports.process.entries == ()
        assert reports.artifacts.abandoned == 0
        if result_cell:
            _assert_result_cell_recovered(reopened, driven)
        else:
            _assert_evidence_cell_recovered(reopened, driven)
        # A second recovery preserves the durable state.
        snapshot = reopened.durable(driven.run_id)
        again = reopened.recover()
        assert again.artifacts.changes == 0
        preserved = reopened.durable(driven.run_id)
        assert preserved.journal == snapshot.journal
        assert preserved.candidates == snapshot.candidates
        assert preserved.refs == snapshot.refs
        assert preserved.run == snapshot.run
        assert preserved.run_manifests == snapshot.run_manifests
        assert preserved.object_blobs == snapshot.object_blobs
        assert preserved.quarantine_entries == snapshot.quarantine_entries
        assert len(preserved.audit_events) == len(snapshot.audit_events) + 1
        _assert_six_facets(
            reopened, driven, run_state=_R.SUCCEEDED if result_cell else _R.FAILED
        )
    finally:
        reopened.close(keep_command_roots=True)


# --------------------------------------------------------------------------
# The six owner variants through the production routes
# --------------------------------------------------------------------------


def _first_audit_event_id(flow: FinalizingSupervisedFlow) -> str:
    events = flow.fresh_audit()
    assert events, "no audit event has been committed yet"
    return events[0].audit_event_id


def _refusal_text(result: object) -> str:
    """The codes and messages of a ``Failure``, for an assertion message."""
    if not isinstance(result, Failure):
        return repr(result)
    return "; ".join(
        f"{item.error_code}: {item.message}" for item in result.diagnostics
    )


def _finalize_snapshot(
    flow: FinalizingSupervisedFlow,
    owner: ExperimentArtifactOwner | DatasetArtifactOwner | StrategyArtifactOwner,
    payload: bytes,
    expected_hash: str,
) -> ArtifactRef:
    """Plan 4.6 and reading 7: the input snapshot through the one production
    entry point, then ``finalize_evidence`` over the staged candidate."""
    assert sha256_bytes(payload) == expected_hash
    audit_event_id = _first_audit_event_id(flow)
    staged = input_snapshot_evidence(
        owner,
        payload,
        expected_hash,
        audit_event_id,
        store=flow.store,
        unit_of_work=flow.unit_of_work,
        clock=flow.clock,
    )
    assert isinstance(staged, Success), _refusal_text(staged)
    candidate = staged.value
    assert candidate.artifact_kind == INPUT_SNAPSHOT_KINDS[owner.owner_kind]
    finalized = finalize_evidence(
        (candidate,),
        EvidenceCorrelation(kind="AUDIT", audit_event_id=audit_event_id),
        finalizer=flow.finalizer(),
    )
    assert isinstance(finalized, Success), _refusal_text(finalized)
    assert finalized.value.journal_state == "REGISTERED"
    (mapping,) = finalized.value.candidate_to_artifact_refs
    ref = flow.fresh_ref(mapping.artifact_id)
    assert ref.content_hash == expected_hash
    assert artifact_owner_hash(ref.owner) == artifact_owner_hash(owner)
    assert _blob_sha256(flow.store.finalized_path_for(ref.content_hash)) == (
        expected_hash
    )
    return ref


@pytest.mark.parametrize(
    "kind", ["RUN", "ADAPTER", "EXPERIMENT", "DATASET", "STRATEGY", "SYSTEM"]
)
def test_owner_variants_end_to_end(
    finalizing_flow: FinalizingSupervisedFlow, kind: str
) -> None:
    flow = finalizing_flow
    described = flow.describe(flow.scenario(_CONFORMANT_DESCRIBE))
    if kind == "ADAPTER":
        # Plan 4.6: ``describe()`` -> ``conclude_describe``: the descriptor and
        # the stderr evidence under the ADAPTER owner of the describe row, the
        # stderr enrichment on the describe invocation, no run row, no close.
        refs = described.evidence_refs
        assert {ref.source_role for ref in refs} == {
            ArtifactSourceRole.ADAPTER_DESCRIPTOR_EVIDENCE,
            ArtifactSourceRole.CORE_EVIDENCE,
        }
        owner = flow.fresh_owner(described.owner_hash)
        assert isinstance(owner, AdapterArtifactOwner)
        for ref in refs:
            assert isinstance(ref.owner, AdapterArtifactOwner)
            assert artifact_owner_hash(ref.owner) == described.owner_hash
            assert ref.producer_kind is CandidateArtifactProducerKind.CORE
        invocation_id = described.outcome.command_result.invocation.invocation_id
        invocation = flow.fresh_invocation(invocation_id)
        stderr = [ref for ref in refs if ref.artifact_kind == STDERR_KIND]
        assert len(stderr) == 1
        assert invocation.stderr_artifact_id == stderr[0].artifact_id
        assert flow.run_states() == frozenset()
        assert _raw_bytes_under(flow, invocation_id) != []  # a describe root stays
        return
    driven = _drive(flow, _SUCCESS_RUN if kind != "SYSTEM" else _EXIT_40_RUN)
    conclusion = driven.conclusion
    assert isinstance(conclusion, CommandConclusion)
    if kind == "RUN":
        refs = flow.fresh_refs(driven.run_id)
        assert len(_refs_of_purpose(refs, _P.RESULT)) == 2
        assert {ref.artifact_kind for ref in _refs_of_purpose(refs, _P.EVIDENCE)} == (
            _EVIDENCE_KINDS_OF_RUN
        )
        for ref in refs:
            assert isinstance(ref.owner, RunArtifactOwner)
            assert ref.owner.run_id == driven.run_id
            assert ref.owner.invocation_id == driven.run_invocation_id
        return
    if kind == "EXPERIMENT":
        snapshot = flow.frozen_snapshot(driven.experiment_id)
        ref = _finalize_snapshot(
            flow,
            ExperimentArtifactOwner(
                owner_kind="EXPERIMENT", experiment_id=driven.experiment_id
            ),
            configuration_audit_bytes(snapshot),
            snapshot.configuration_audit_hash,
        )
        assert ref.source_role is ArtifactSourceRole.EXPERIMENT_INPUT
        return
    # The dataset and strategy facts are read back from the authoritative
    # registry under the hashes the frozen experiment spec names, never rebuilt
    # from the fixture builders.
    experiment = flow.fresh_experiment(driven.experiment_id)
    if kind == "DATASET":
        descriptor, partitions = flow.fresh_dataset(
            experiment.spec.dataset_version_hash
        )
        assert descriptor.content_hash == experiment.spec.dataset_version_hash
        assert len(partitions) >= 1
        ref = _finalize_snapshot(
            flow,
            DatasetArtifactOwner(
                owner_kind="DATASET", dataset_id=descriptor.dataset_id
            ),
            dataset_identity_bytes(descriptor, partitions),
            descriptor.content_hash,
        )
        assert ref.source_role is ArtifactSourceRole.DATASET_INPUT
        return
    if kind == "STRATEGY":
        # The owner names exactly one version identity: the content hash the
        # registry fact is (plan 4.6 ``strategy_version_hash``).
        version = flow.fresh_strategy_version(experiment.spec.strategy_version_hash)
        assert version.content_hash == experiment.spec.strategy_version_hash
        ref = _finalize_snapshot(
            flow,
            StrategyArtifactOwner(
                owner_kind="STRATEGY", strategy_version_hash=version.content_hash
            ),
            strategy_identity_bytes(version),
            version.content_hash,
        )
        assert ref.source_role is ArtifactSourceRole.STRATEGY_INPUT
        return
    assert kind == "SYSTEM"
    # A diagnostic-report projection of the failed run's recorded primary.
    primary = flow.fresh_diagnostic(conclusion.run.primary_terminal_diagnostic_id)
    owner = SystemArtifactOwner(
        owner_kind="SYSTEM",
        core_component=_SYSTEM_COMPONENT,
        correlation_id=primary.diagnostic_id,
    )
    staged = ok(
        diagnostic_report_evidence(
            (primary,),
            owner,
            primary.diagnostic_id,
            store=flow.store,
            unit_of_work=flow.unit_of_work,
            clock=flow.clock,
        )
    )
    assert staged.artifact_kind == DIAGNOSTIC_REPORT_KIND
    finalized = ok(
        finalize_evidence(
            (staged,),
            EvidenceCorrelation(kind="DIAGNOSTIC", diagnostic_id=primary.diagnostic_id),
            finalizer=flow.finalizer(),
        )
    )
    assert finalized.journal_state == "REGISTERED"
    (mapping,) = finalized.candidate_to_artifact_refs
    ref = flow.fresh_ref(mapping.artifact_id)
    assert isinstance(ref.owner, SystemArtifactOwner)
    assert ref.owner == owner
    assert ref.source_role is ArtifactSourceRole.CORE_EVIDENCE
    assert ref.producer_kind is CandidateArtifactProducerKind.CORE


# --------------------------------------------------------------------------
# Confinement, native preservation, the shared pipeline, failure data
# --------------------------------------------------------------------------


def test_adapter_wrote_only_under_its_work_dir(
    finalizing_flow: FinalizingSupervisedFlow,
) -> None:
    """F24.1-1, R15.5-06, R18.3-03: every byte the adapter produced lies under
    its assigned work directory; nothing appears beside the request file at the
    root or under the artifact roots before the conclusion."""
    flow = finalizing_flow
    _describe(flow)
    row = flow.scenario(_SUCCESS_RUN)
    run = flow.prepare_run(row)
    blobs_before = flow.object_blobs()  # the describe row's two evidence blobs
    assert len(blobs_before) == 2
    outcome = flow.invoke(row, run)
    invocation_id = outcome.command_result.invocation.invocation_id
    paths = flow.command_roots(invocation_id)
    assert isinstance(paths, CommandRootPaths)
    assert isinstance(paths.work_dir, Path)
    work_prefix = f"{invocation_id}/runs/{run.run_id}/work/"
    for name in flow.command_root_files():
        if not name.startswith(f"{invocation_id}/"):
            continue
        request_or_work = name == f"{invocation_id}/request.json" or name.startswith(
            work_prefix
        )
        assert request_or_work, name
    declared = _declared_hashes(outcome)
    for relative in declared:
        candidate = paths.work_dir.joinpath(*relative.split("/"))
        assert candidate.is_file()
        assert candidate.resolve().is_relative_to(paths.work_dir.resolve())
    assert flow.object_blobs() == blobs_before  # the adapter reached no store root
    assert flow.staging_files() == ()
    conclusion = flow.conclude_and_finalize(row, run, outcome)
    assert isinstance(conclusion, CommandConclusion)
    assert conclusion.run.state is _R.SUCCEEDED
    # The observations the verdict consumed were confined under the work dir:
    # the registered candidates carry exactly the declared relative paths.
    adapter_candidates = [
        candidate
        for candidate in flow.fresh_candidates()
        if candidate.producer_kind is CandidateArtifactProducerKind.ADAPTER
    ]
    assert {c.staging_relative_path for c in adapter_candidates} == set(declared)


def test_native_output_preserved_as_result_only_on_success(
    finalizing_flow: FinalizingSupervisedFlow,
) -> None:
    """R19.4-07, R19.4-08, R20.1-01..03: the native result bytes are registered
    unmodified (the blob's independently measured hash equals the adapter's
    declaration) and only on success; a failed run's result candidates are
    quarantined and never relabeled as evidence."""
    flow = finalizing_flow
    _describe(flow)
    success = _drive(flow, _SUCCESS_RUN)
    declared = _declared_hashes(success.outcome)
    declarations = {
        record.payload.relative_path: record.payload
        for record in success.outcome.protocol_summary.artifact_declarations
    }
    result_refs = _refs_of_purpose(flow.fresh_refs(success.run_id), _P.RESULT)
    assert len(result_refs) == len(declared) == 2
    by_hash = {ref.content_hash: ref for ref in result_refs}
    for relative, payload in declarations.items():
        ref = by_hash[declared[relative]]
        blob = flow.store.finalized_path_for(ref.content_hash)
        assert _blob_sha256(blob) == payload.declared_sha256
        assert blob.stat().st_size == payload.declared_size_bytes == ref.size_bytes
        assert ref.artifact_kind == payload.artifact_kind
        assert ref.media_type == payload.media_type
        assert ref.producer_kind is CandidateArtifactProducerKind.ADAPTER
    failure = _drive(flow, _CHECKSUM_MISMATCH_RUN)
    assert isinstance(failure.conclusion, CommandConclusion)
    assert failure.conclusion.run.state is _R.FAILED
    primary = flow.fresh_diagnostic(
        failure.conclusion.run.primary_terminal_diagnostic_id
    )
    assert primary.error_code == ARTIFACT_VALIDATION_FAILED
    assert _refs_of_purpose(flow.fresh_refs(failure.run_id), _P.RESULT) == ()
    flow.recover()
    after = flow.durable(failure.run_id)
    failed_candidates = [
        candidate
        for candidate in after.candidates
        if candidate.producer_kind is CandidateArtifactProducerKind.ADAPTER
        and isinstance(candidate.owner, RunArtifactOwner)
        and candidate.owner.run_id == failure.run_id
    ]
    assert len(failed_candidates) == 2
    assert all(candidate.state is _S.QUARANTINED for candidate in failed_candidates)
    adapter_candidate_ids = {c.candidate_artifact_id for c in failed_candidates}
    for ref in after.refs:
        assert ref.source_candidate_artifact_id not in adapter_candidate_ids
        if ref.finalization_purpose is _P.EVIDENCE:
            assert ref.producer_kind is CandidateArtifactProducerKind.CORE
    assert set(after.object_blobs) == {ref.content_hash for ref in after.refs}
    assert flow.fresh_manifest(failure.run_id) is None


def test_both_purposes_share_the_pipeline_only_result_succeeds(
    finalizing_flow: FinalizingSupervisedFlow,
) -> None:
    """A33.6-01 and reading 5: RESULT and EVIDENCE run the same journal protocol
    (both audited through every phase) and only RESULT writes a run manifest or
    moves the run; the EVIDENCE commit leaves the run revision unchanged."""
    flow = finalizing_flow
    _describe(flow)
    driven = _drive(flow, _SUCCESS_RUN)
    conclusion = driven.conclusion
    assert isinstance(conclusion, CommandConclusion)
    journals = [
        entry
        for entry in flow.fresh_journal()
        if isinstance(entry.owner, RunArtifactOwner)
        and entry.owner.run_id == driven.run_id
    ]
    purposes = sorted(entry.finalization_purpose.value for entry in journals)
    assert purposes == ["EVIDENCE", "RESULT"]
    assert all(entry.state is _J.REGISTERED for entry in journals)
    (result_entry,) = [e for e in journals if e.finalization_purpose is _P.RESULT]
    (evidence_entry,) = [e for e in journals if e.finalization_purpose is _P.EVIDENCE]
    assert isinstance(result_entry.finalization_deadline_utc, datetime)
    assert not isinstance(evidence_entry.finalization_deadline_utc, datetime)
    actions = tuple(event.action.value for event in flow.fresh_audit())
    for phase in (
        "FINALIZATION_LEASE_ACQUIRED",
        "FINALIZATION_PREPARED",
        "FINALIZATION_MOVED",
        "FINALIZATION_REGISTERED",
    ):
        assert actions.count(phase) >= 2, phase
    assert actions.count("RUN_MANIFEST_REGISTERED") == 1
    assert actions.count("RUN_SUCCEEDED") == 1
    assert isinstance(conclusion.finalization, FinalizationResult)
    assert isinstance(conclusion.finalization.run_manifest_id, str)
    # Reading 5: the success swap used the journal's post-snapshot revision and
    # the later EVIDENCE commit did not move the run again.
    assert isinstance(result_entry.expected_run_revision, int)
    assert conclusion.run.revision == result_entry.expected_run_revision + 1
    assert flow.fresh_run(driven.run_id).revision == conclusion.run.revision
    registered_at = {
        entry.finalization_purpose.value: entry.updated_at_utc for entry in journals
    }
    assert registered_at["EVIDENCE"] >= registered_at["RESULT"]
    evidence_refs = _refs_of_purpose(flow.fresh_refs(driven.run_id), _P.EVIDENCE)
    links = flow.fresh_links(driven.run_id)
    assert {link.artifact_id for link in links if link.link_role == RUN_EVIDENCE} == {
        ref.artifact_id for ref in evidence_refs
    }
    assert all(
        not isinstance(link.run_manifest_id, str)
        for link in links
        if link.link_role == RUN_EVIDENCE
    )


def test_failure_exposes_code_category_retriable_evidence(
    finalizing_flow: FinalizingSupervisedFlow,
) -> None:
    """R30.4-01, R30.5-01 (data only): a failed run exposes its primary
    diagnostic's code, category and retriability and its finalized evidence;
    the run manifest, metrics and result references exist only for success."""
    flow = finalizing_flow
    _describe(flow)
    driven = _drive(flow, _EXIT_40_RUN)
    conclusion = driven.conclusion
    assert isinstance(conclusion, CommandConclusion)
    assert conclusion.run.state is _R.FAILED
    primary = flow.fresh_diagnostic(conclusion.run.primary_terminal_diagnostic_id)
    assert primary.error_code == ENGINE_RUNTIME_FAILURE
    assert primary.category.value == "ENGINE_RUNTIME"
    assert isinstance(primary.retriable, bool)
    assert primary.run_id == driven.run_id
    assert primary.invocation_id == driven.run_invocation_id
    assert primary.diagnostic_id in conclusion.invocation.diagnostic_ids
    evidence = _refs_of_purpose(flow.fresh_refs(driven.run_id), _P.EVIDENCE)
    assert {ref.artifact_kind for ref in evidence} == _EVIDENCE_KINDS_OF_RUN
    for ref in evidence:
        assert ref.producer_kind is CandidateArtifactProducerKind.CORE
        assert flow.store.finalized_path_for(ref.content_hash).is_file()
    assert not isinstance(conclusion.run_manifest, RunManifest)
    assert conclusion.result_refs == ()
    assert flow.fresh_manifest(driven.run_id) is None
    assert conclusion.invocation.state is _C.EXITED
    assert conclusion.invocation.native_exit_value == 40


# --------------------------------------------------------------------------
# Every row: dangling references, reopen consistency, platform paths
# --------------------------------------------------------------------------


_EXPECTED_STATES: Final = {
    "success": _R.SUCCEEDED,
    "warning": _R.SUCCEEDED_WITH_WARNINGS,
    "exit-40": _R.FAILED,
    "checksum-mismatch": _R.FAILED,
    "cancellation": _R.CANCELLED,
    "timeout": _R.TIMED_OUT,
}
#: The six rows, each checked on its own flow so a later row can never obscure
#: an earlier row's durable state.
_ROW_LABELS: Final = tuple(_EXPECTED_STATES)


def _drive_row(flow: FinalizingSupervisedFlow, label: str) -> _Driven:
    """One of the six rows -- success (through the conformant ``VALIDATE``),
    warning, both failures, cancellation and the finalization timeout -- on a
    flow whose describe row has already run."""
    if label == "success":
        return _drive(flow, _SUCCESS_RUN, through_validate=True)
    if label == "warning":
        return _drive(flow, _WARNING_RUN)
    if label == "exit-40":
        return _drive(flow, _EXIT_40_RUN)
    if label == "checksum-mismatch":
        return _drive(flow, _CHECKSUM_MISMATCH_RUN)
    if label == "cancellation":
        cancel_row = flow.scenario(_SUCCESS_RUN)
        run = flow.prepare_run(cancel_row)
        outcome = flow.invoke(cancel_row, run)
        flow.cancel_run(run.run_id)
        return _Driven(
            run_id=run.run_id,
            experiment_id=run.experiment_id,
            validate_invocation_id=None,
            run_invocation_id=outcome.command_result.invocation.invocation_id,
            outcome=outcome,
            conclusion=flow.conclude_and_finalize(cancel_row, run, outcome),
        )
    assert label == "timeout", label
    return _drive(
        flow,
        _SUCCESS_RUN,
        probe=ClockAdvancingProbe(
            "after_moved", flow.clock, FINALIZATION_TIMEOUT_SECONDS + 1
        ),
    )


@pytest.mark.parametrize("label", _ROW_LABELS)
def test_zero_dangling_diagnostics_after_every_row(
    finalizing_flow: FinalizingSupervisedFlow, label: str
) -> None:
    """I-9: the caller records every minted diagnostic, so no record references
    a diagnostic that is not stored -- checked right after the row's conclusion,
    again after its recovery, then the six facets, each row on its own flow."""
    flow = finalizing_flow
    _describe(flow)
    driven = _drive_row(flow, label)
    assert isinstance(driven.conclusion, CommandConclusion), label
    assert driven.conclusion.run.state is _EXPECTED_STATES[label], label
    _assert_no_dangling(flow)
    flow.recover()
    _assert_no_dangling(flow)
    _assert_six_facets(flow, driven, run_state=_EXPECTED_STATES[label])


def test_zero_dangling_diagnostics_across_all_rows_on_one_flow(
    finalizing_flow: FinalizingSupervisedFlow,
) -> None:
    """I-9 with every row on one file: the flow-wide counts of the six facets
    (manifests against success runs, audit rows against journal entries) hold
    with all six rows present, which no single-row case exercises."""
    flow = finalizing_flow
    _describe(flow)
    rows = {label: _drive_row(flow, label) for label in _ROW_LABELS}
    for label, driven in rows.items():
        assert isinstance(driven.conclusion, CommandConclusion), label
        assert driven.conclusion.run.state is _EXPECTED_STATES[label], label
    _assert_no_dangling(flow)
    flow.recover()
    _assert_no_dangling(flow)
    for label, driven in rows.items():
        _assert_six_facets(flow, driven, run_state=_EXPECTED_STATES[label])


@pytest.mark.parametrize("label", _ROW_LABELS)
def test_reopen_after_every_row_is_consistent(tmp_path: Path, label: str) -> None:
    """Each row on its own file: recovered, hashed after a WAL checkpoint and
    closed with its command roots kept; the reopened file is byte-identical,
    passes ``quick_check``, reports all twelve consistency counts zero before
    and after an idle recovery pass, and holds the six facets."""
    expected = _EXPECTED_STATES[label]
    flow = FinalizingSupervisedFlow.open(tmp_path, config=FINALIZING_CONFIG)
    try:
        _describe(flow)
        driven = _drive_row(flow, label)
        flow.recover()
        assert flow.assert_no_child_survives() >= 1
        before = flow.database_sha256()  # WAL checkpointed before hashing
    finally:
        flow.close(keep_command_roots=True)
    reopened = FinalizingSupervisedFlow.reopen(tmp_path)
    try:
        assert reopened.quick_check() == "ok"
        assert reopened.database_sha256() == before
        assert reopened.fresh_run(driven.run_id).state is expected
        assert reopened.consistency_report() == ConsistencyReport(*([0] * 12))
        reports = reopened.recover()
        assert reports.process.entries == ()
        assert reports.artifacts.changes == 0
        assert reopened.run_states() == frozenset({expected})
        assert reopened.consistency_report() == ConsistencyReport(*([0] * 12))
        assert reopened.quick_check() == "ok"
        _assert_six_facets(reopened, driven, run_state=expected)
    finally:
        reopened.close(keep_command_roots=True)


def test_paths_with_spaces_and_unicode_pass(tmp_path: Path) -> None:
    """Plan 7.5: the flow's roots under a component with a space and a non-ASCII
    character; the success row, its recovery and the six facets hold."""
    root = tmp_path / "sp ä"
    root.mkdir()
    flow = FinalizingSupervisedFlow.open(root, config=FINALIZING_CONFIG)
    try:
        _describe(flow)
        driven = _drive(flow, _SUCCESS_RUN)
        _assert_success(
            flow,
            driven,
            run_state=_R.SUCCEEDED,
            semantic_status=SemanticStatus.SUCCEEDED,
        )
        assert " " in str(flow.store.objects_root)
        assert "ä" in str(flow.store.objects_root)
        flow.recover()
        _assert_six_facets(flow, driven, run_state=_R.SUCCEEDED)
        assert not isinstance(
            flow.fresh_run(driven.run_id).primary_terminal_diagnostic_id, str
        )
    finally:
        flow.close()


def test_describe_row_reaches_described_verdict(
    finalizing_flow: FinalizingSupervisedFlow,
) -> None:
    """The describe row's verdict and observation are the Stage 8 ones; the
    Stage 9 conclusion adds the two ADAPTER-owned evidence references."""
    described = finalizing_flow.describe(finalizing_flow.scenario(_CONFORMANT_DESCRIBE))
    assert isinstance(described.reconciliation, SemanticReconciliation)
    assert described.reconciliation.verdict is _V.DESCRIBED
    assert len(described.evidence_refs) == 2


# --------------------------------------------------------------------------
# The supervision trace projection (Task 8, amended by the ruling of 2026-11-10)
# --------------------------------------------------------------------------


def _log_lines(flow: FinalizingSupervisedFlow) -> tuple[bytes, ...]:
    """Every line the production JSON Lines writer put under the logs root, in
    file then line order (the writer's ``core-*.jsonl`` files)."""
    lines: list[bytes] = []
    for path in sorted(flow.logs_root.glob("core-*.jsonl")):
        lines.extend(line for line in path.read_bytes().split(b"\n") if line)
    return tuple(lines)


def _supervision_records(lines: tuple[bytes, ...]) -> tuple[LogRecord, ...]:
    """The projected trace: every line decoded as the versioned ``LogRecord``
    whose event code carries the supervision prefix, in written order."""
    records = tuple(LogRecord.model_validate_json(line) for line in lines)
    return tuple(
        record
        for record in records
        if record.event_code.startswith(_TRACE_EVENT_PREFIX)
    )


def test_supervision_trace_is_projected_as_log_records_not_audit_events(
    finalizing_flow: FinalizingSupervisedFlow,
) -> None:
    """Task 8 as amended: every ``SupervisionTraceEntry`` the production
    supervisor delivered for the describe and the run invocation is one
    ``LogRecord`` written through the production ``JsonLinesLogWriter`` -- event
    code ``SUPERVISION.<kind>``, the invocation as its correlation, the entry's
    facts with its ordinals as redaction-fixed details -- and never an
    ``AuditEvent``: the closed ``AuditAction`` vocabulary names no supervision
    fact and the audit table gains no row across ``invoke``. The raw attempt
    token is absent from every line, no detail key is denylisted and no string
    is token-shaped. The ``LAUNCHED`` entry's controller-observed ``image_path``
    travels as the Stage 7 trace carries it. This proves the test-support
    projection alone and discharges nothing of Stage 10 O-13."""
    flow = finalizing_flow
    described = flow.describe(flow.scenario(_CONFORMANT_DESCRIBE))
    row = flow.scenario(_SUCCESS_RUN)
    run = flow.prepare_run(row)
    audit_before = len(flow.fresh_audit())
    outcome = flow.invoke(row, run)
    assert len(flow.fresh_audit()) == audit_before
    entries: tuple[SupervisionTraceEntry, ...] = (
        *described.outcome.trace,
        *outcome.trace,
    )
    assert described.outcome.trace
    assert outcome.trace
    invocation_ids = {
        described.outcome.command_result.invocation.invocation_id,
        outcome.command_result.invocation.invocation_id,
    }
    assert {entry.invocation_id for entry in entries} == invocation_ids
    lines = _log_lines(flow)
    records = _supervision_records(lines)
    assert len(records) == len(entries)
    for record, entry in zip(records, entries, strict=True):
        assert record.event_code == f"{_TRACE_EVENT_PREFIX}{entry.kind.value}"
        assert record.correlation_id == entry.invocation_id
        assert record.invocation_id == entry.invocation_id
        assert record.component == _LOG_COMPONENT
        assert record.severity is LogSeverity.INFO
        assert record.timestamp_utc == entry.at_utc
        assert record.details == redact_details(
            {
                **entry.facts,
                "sequence": entry.sequence,
                "monotonic_100ns": entry.monotonic_100ns,
            }
        )
        assert not any(is_denylisted_key(key) for key in record.details)
        assert not contains_token_shape(record.message)
    launched = [
        record
        for record in records
        if record.event_code == f"{_TRACE_EVENT_PREFIX}LAUNCHED"
    ]
    assert len(launched) == 2
    assert all("image_path" in record.details for record in launched)
    token = flow.raw_token(run.run_id).encode("utf-8")
    assert len(token) >= 32
    assert all(token not in line for line in lines)
    assert len(AuditAction) == _AUDIT_ACTION_COUNT
    assert not any(action.value.startswith("SUPERVISION") for action in AuditAction)
    assert {event.action for event in flow.fresh_audit()} <= set(AuditAction)


def test_projection_redacts_token_shaped_trace_facts(
    finalizing_flow: FinalizingSupervisedFlow,
) -> None:
    """The sanitized-details clause of the projection, proven on a crafted entry
    rather than on whatever the real trace carries: the facts the production
    supervisor emits are identifiers, codes, counts, state names, reason words
    and booleans, and the one operator-shaped string among them -- the
    controller-observed ``image_path`` of ``LAUNCHED`` -- is token-shaped only
    under a host path with a long enough url-safe run, so the equality against
    ``redact_details`` above holds with redaction removed whenever no real fact
    is token-shaped. Here a ``SupervisionTraceEntry`` whose facts carry a
    40-character url-safe run at the top level and a hex digest in a nested
    object is written through the production writer as one ``LogRecord`` with
    both values ``[REDACTED]``, every other fact and the ordinals intact, the
    kind as the event code, the invocation as the correlation and neither
    literal anywhere in the written line. A denylisted fact key never reaches
    the projection: the entry model itself refuses it."""
    flow = finalizing_flow
    entry = SupervisionTraceEntry(
        kind=SupervisionTraceKind.CLEANUP_ACTION,
        invocation_id=INVOCATION_ID,
        sequence=7,
        at_utc=flow.clock.now_utc(),
        monotonic_100ns=1_234,
        facts={
            "action": "JOB_CLOSED",
            "note": _SHAPED_FACT,
            "nested": {"digest": _DIGEST_FACT, "count": 2},
        },
    )
    assert contains_token_shape(_SHAPED_FACT)
    assert contains_token_shape(_DIGEST_FACT)
    before = len(_log_lines(flow))
    assert flow.log.project_trace((entry,)) == 1
    lines = _log_lines(flow)
    assert len(lines) == before + 1
    (record,) = _supervision_records(lines[before:])
    assert record.event_code == f"{_TRACE_EVENT_PREFIX}CLEANUP_ACTION"
    assert record.correlation_id == INVOCATION_ID
    assert record.invocation_id == INVOCATION_ID
    assert record.component == _LOG_COMPONENT
    assert record.timestamp_utc == entry.at_utc
    assert record.details == {
        "action": "JOB_CLOSED",
        "note": REDACTED,
        "nested": {"digest": REDACTED, "count": 2},
        "sequence": 7,
        "monotonic_100ns": 1_234,
    }
    assert _SHAPED_FACT.encode("utf-8") not in lines[-1]
    assert _DIGEST_FACT.encode("utf-8") not in lines[-1]
    with pytest.raises(ValidationError, match="secret-like"):
        SupervisionTraceEntry(
            kind=SupervisionTraceKind.CLEANUP_ACTION,
            invocation_id=INVOCATION_ID,
            sequence=8,
            at_utc=flow.clock.now_utc(),
            monotonic_100ns=1_235,
            facts={"attempt_token": "benign"},
        )
