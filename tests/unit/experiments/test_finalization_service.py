"""Stage 9 Task 7: the finalization service over SQLite -- ``conclude_command``,
``conclude_describe``, the step-0 observation, the seven evidence producers,
the production registrar, the run failure path, the replay wrapper and the
recovery validator (plan 4.4, 4.6, 29.3; requirement rows R30.3-01, T28.2-02,
T28.3-06, R19.1-10, R29.1-01, R24.4-01).

Every case composes ``FinalizationFixture.open(..., production=True)``: the
production ``ResultRegistrar``, ``ResultRecoveryValidator`` and
``AuditFactRecorder`` over the migrated test database, and the RESULT
pre-state as the real adapter wire (the manifest, the ledger, the sanitized
row). The verdict each case hands ``conclude_command`` is the Stage 6
``reconcile_run`` over that wire, so the service is exercised exactly as the
Task 8 flow will call it. After every service call the database's consistency
report shows zero dangling diagnostic references.

Several cases finalize core evidence whose bytes are schema-validated JSON or
JSON Lines carrying SHA-256 digests and prefixed identifiers (the sanitized
manifest, the protocol capture, the adapter descriptor, the diagnostic report).
Under the canonical evidence ruling of 2026-11-09
(``docs/decisions/2026-11-09-stage9-canonical-evidence-validation-clarification.md``)
the production ``ResultRegistrar`` answers the plan 4.6 canonical contract --
the bytes are the approved producer's model, re-serialize to the very bytes
and agree with the stored row, the ledger, the recorded diagnostics or the
describe invocation -- so the finalizer holds only their uncontrolled strings
to the token-shape rule and scans them for the exact raw token whenever the
attempt's material is available; unqualified content keeps the whole-content
protection.
"""

from __future__ import annotations

import _winapi
import json
import os
import shutil
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, Final, cast

import pytest
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.adapters.catalog import AdapterCatalogEntry
from crypto_lab.adapters.commands import CommandResult
from crypto_lab.adapters.diagnostics import (
    PROCESS_STDERR_TRUNCATED,
    PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
    stage6_diagnostic,
)
from crypto_lab.adapters.events import (
    ArtifactProducedPayload,
    FinalResultPayload,
    ProtocolEventSummary,
    RunEvent,
    run_event_content_hash,
)
from crypto_lab.adapters.limits import (
    MAX_DESCRIPTOR_OUTPUT_BYTES,
    MAX_RESULT_MANIFEST_BYTES,
)
from crypto_lab.adapters.manifests import (
    AdapterValidationResult,
    SanitizedAdapterResultManifest,
    parse_result_manifest,
    sanitize_result_manifest,
    validation_result_hash,
)
from crypto_lab.adapters.negotiation import (
    BootstrapDescriptorEnvelope,
    DescriptorParse,
    parse_bootstrap_descriptor,
)
from crypto_lab.adapters.reconciliation import (
    CandidateObservation,
    ReconciliationRuleViolation,
    SemanticReconciliation,
    reconcile_describe,
    reconcile_run,
)
from crypto_lab.adapters.sanitization import StderrCapture
from crypto_lab.adapters.vocabulary import (
    NEGOTIABLE_SCHEMA_NAMES,
    ProtocolIntegrityStatus,
    ReconciliationVerdict,
    SemanticStatus,
    ValidationOutcome,
)
from crypto_lab.artifacts.diagnostics import (
    ARTIFACT_FINALIZATION_TIMED_OUT,
    ARTIFACT_MOVE_FAILED,
    ARTIFACT_PATH_BOUNDARY_VIOLATION,
    ARTIFACT_RESULT_MANIFEST_INVALID,
    ARTIFACT_VALIDATION_FAILED,
    SECURITY_SENSITIVE_MATERIAL_LEAKAGE,
    artifact_failure,
)
from crypto_lab.artifacts.finalizer import CoreArtifactFinalizer
from crypto_lab.artifacts.hashing import StreamingContentHasher
from crypto_lab.artifacts.models import (
    ArtifactFinalizationPurpose,
    ArtifactSourceRole,
    CandidateArtifactProducerKind,
    CandidateArtifactState,
    FinalizationResult,
)
from crypto_lab.artifacts.ownership import (
    AdapterArtifactOwner,
    RunArtifactOwner,
    artifact_owner_hash,
)
from crypto_lab.artifacts.ports import (
    CanonicalEvidenceQualifier,
    CanonicalQualification,
    CommandRootPaths,
)
from crypto_lab.artifacts.requests import EvidenceCorrelation
from crypto_lab.domain.base import SCHEMA_VERSION, CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes, canonical_json_text
from crypto_lab.domain.descriptors import (
    AdapterDescriptor,
    EngineDescriptor,
    OperatingSystem,
    SupportedSchemaVersion,
)
from crypto_lab.domain.diagnostics import Diagnostic, DiagnosticCategory
from crypto_lab.domain.engine_run import AttemptTokenMaterial
from crypto_lab.domain.hashing import (
    HashingProfile,
    artifact_id_for,
    candidate_artifact_id_for,
    core_candidate_artifact_id_for,
    profile_hash,
    request_id_for,
    sha256_bytes,
)
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ProcessExitCategory,
)
from crypto_lab.domain.metrics import MetricValueType
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.experiments import finalization as finalization_module
from crypto_lab.experiments.finalization import (
    DIAGNOSTIC_REPORT_KIND,
    INPUT_SNAPSHOT_KINDS,
    PROTOCOL_CAPTURE_KIND,
    SANITIZED_MANIFEST_KIND,
    SOURCE_COMPONENT,
    STDERR_KIND,
    VALIDATION_RESULT_KIND,
    CommandConclusion,
    ConclusionConfig,
    EvidenceRegistrar,
    ResultRecoveryValidator,
    ResultRegistrar,
    conclude_command,
    conclude_describe,
    declared_candidate_paths,
    descriptor_evidence,
    diagnostic_report_evidence,
    evidence_request_for,
    fail_run_for_refusal,
    finalize_evidence,
    input_snapshot_evidence,
    observe_candidates,
    protocol_capture_evidence,
    register_result_candidates,
    sanitized_manifest_leaf,
    sanitized_result_manifest_evidence,
    semantic_outcome_or_replay,
    stage_core_evidence,
    stderr_evidence,
    uncontrolled_strings_of,
    validation_result_evidence,
)
from crypto_lab.experiments.requests import SemanticOutcomeRequest
from crypto_lab.experiments.run_manifest import RunManifest
from crypto_lab.experiments.semantic_outcome import SemanticOutcome
from crypto_lab.persistence.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
    WRITE_FAILED,
)
from doubles.artifacts import (
    ADAPTER_OWNER,
    DATASET_OWNER,
    EXPERIMENT_OWNER,
    FIXTURE_TOKEN,
    INVOCATION_CORRELATION,
    RESULT_FILES,
    RESULT_TIMEOUT_SECONDS,
    RUN_OWNER,
    RUN_OWNER_WITHOUT_INVOCATION,
    SYSTEM_OWNER,
    RecordingProbe,
    RefusingAuditor,
    result_candidates,
    sample_candidate,
    sample_journal,
    sample_result_request,
)
from doubles.experiments import (
    DIAG_ID,
    EXECUTABLE_HASH,
    EXPERIMENT_ID,
    INSTANT,
    INVOCATION_ID,
    OTHER_DIAG_ID,
    OTHER_EXPERIMENT_ID,
    OTHER_INVOCATION_ID,
    OTHER_RUN_ID,
    RUN_ID,
    SLOT_A,
    THIRD_DIAG_ID,
    FixedClock,
    sample_diagnostic,
    sample_invocation,
)
from persistence_support.artifacts import (
    DEFAULT_NEGOTIATED_VERSIONS,
    FinalizationFixture,
    ProductionResultPlan,
)
from persistence_support.harness import (
    cursor_fault,
    engine_of,
    put_invocation,
    sqlite_error,
)

_STDERR_TEXT: Final = "engine stderr line one\nengine stderr line two\n"
_SHAPED_TEXT: Final = "token-shaped " + "Q" * 40 + "\n"
_WRONG_TOKEN: Final = "B" * 32
#: A synthetic, non-secret marker planted in invalid stored input and in injected
#: exception text: its absence from a diagnostic, an audit event or a log line
#: proves the translation carried neither (reading 7).
_INPUT_MARKER: Final = "zz-synthetic-input-marker-19c4"
#: The ``Diagnostic.message`` bound (``domain.diagnostics``).
_DIAGNOSTIC_MESSAGE_BOUND: Final = 1024
_EMPTY_SUMMARY: Final = ProtocolEventSummary(
    accepted_count=0,
    last_sequence=0,
    artifact_declarations=(),
    warnings=(),
    adapter_diagnostics=(),
    redactions=0,
)
_P = CandidateArtifactProducerKind
_F = ArtifactFinalizationPurpose
_R = ArtifactSourceRole
_S = CandidateArtifactState


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
def production(tmp_path: Path) -> Iterator[FinalizationFixture]:
    opened = FinalizationFixture.open(
        tmp_path, clock=FixedClock(INSTANT), production=True
    )
    try:
        yield opened
    finally:
        opened.close()


@contextmanager
def _fresh(tmp_path: Path, name: str) -> Iterator[FinalizationFixture]:
    """A second production fixture under its own one-letter directory (one run
    each; the core staging layout leaves little room under the Windows path
    limit beneath a pytest temporary root)."""
    assert len(name) == 1, name
    root = tmp_path / name
    root.mkdir()
    opened = FinalizationFixture.open(root, clock=FixedClock(INSTANT), production=True)
    try:
        yield opened
    finally:
        opened.close()


def _config(fixture: FinalizationFixture) -> ConclusionConfig:
    registrar = fixture.registrar
    assert isinstance(registrar, ResultRegistrar)
    return ConclusionConfig(
        store=fixture.roots.store,
        hasher=fixture.hasher,
        auditor=fixture.auditor,
        finalization_timeout_seconds=RESULT_TIMEOUT_SECONDS,
        registrar=registrar,
    )


def _capture(text: str = _STDERR_TEXT, *, truncated: bool = False) -> StderrCapture:
    data = text.encode("utf-8")
    return StderrCapture(
        retained_byte_count=len(data),
        truncated=truncated,
        source_hash=sha256_bytes(data),
        sanitized_text=text,
    )


def _plan(fixture: FinalizationFixture, **overrides: Any) -> ProductionResultPlan:
    return fixture.plant_production_result(**overrides)


def _token(fixture: FinalizationFixture) -> AttemptTokenMaterial:
    material = fixture.token_material(INVOCATION_ID)
    assert isinstance(material, AttemptTokenMaterial)
    return material


def _observe(
    fixture: FinalizationFixture, plan: ProductionResultPlan
) -> tuple[CandidateObservation, ...]:
    assert isinstance(plan.roots.work_dir, Path)
    return _ok(
        observe_candidates(
            plan.roots.work_dir,
            declared_candidate_paths(plan.summary, plan.parse),
            _token(fixture),
            hasher=fixture.hasher,
            clock=fixture.clock,
        )
    )


def _reconcile(
    fixture: FinalizationFixture,
    plan: ProductionResultPlan,
    observations: tuple[CandidateObservation, ...] | None = None,
) -> SemanticReconciliation:
    experiment = fixture.current_experiment()
    assert not isinstance(experiment.slot_compatibility, type(MISSING))
    (slot,) = [
        entry
        for entry in experiment.slot_compatibility
        if entry.logical_slot_id == SLOT_A
    ]
    return reconcile_run(
        plan.invocation,
        plan.run,
        experiment,
        slot,
        plan.parse,
        plan.summary,
        _observe(fixture, plan) if observations is None else observations,
        DEFAULT_NEGOTIATED_VERSIONS,
        MISSING,
        now_utc=fixture.clock.now_utc(),
    )


def _command_result(
    plan: ProductionResultPlan,
    *,
    stderr: StderrCapture | None = None,
    events: bool = True,
    parsed: bool = True,
) -> CommandResult:
    payload: dict[str, Any] = {
        "invocation": plan.invocation,
        "protocol_integrity": ProtocolIntegrityStatus.INTACT,
        "accepted_events": plan.events if events else (),
        "diagnostics": (),
        "cancelled": False,
        "timed_out": False,
    }
    if parsed:
        payload["parsed_output"] = plan.parse.manifest
        payload["parsed_output_source_hash"] = plan.parse.source_hash
    if stderr is not None:
        payload["stderr"] = stderr
    return CommandResult.model_validate(payload)


def _reconcile_without_manifest(
    fixture: FinalizationFixture, plan: ProductionResultPlan
) -> SemanticReconciliation:
    """The verdict of an exit that owed a manifest and wrote none: ``FAILED``
    under ``ARTIFACT.RESULT_MANIFEST_INVALID`` with no sanitized manifest."""
    experiment = fixture.current_experiment()
    assert not isinstance(experiment.slot_compatibility, type(MISSING))
    (slot,) = [
        entry
        for entry in experiment.slot_compatibility
        if entry.logical_slot_id == SLOT_A
    ]
    return reconcile_run(
        plan.invocation,
        plan.run,
        experiment,
        slot,
        MISSING,
        plan.summary,
        (),
        DEFAULT_NEGOTIATED_VERSIONS,
        MISSING,
        now_utc=fixture.clock.now_utc(),
    )


def _conclude(
    fixture: FinalizationFixture,
    plan: ProductionResultPlan,
    *,
    stderr: StderrCapture | None = None,
    events: bool = True,
    parsed: bool = True,
    outcome: SemanticOutcome | None = None,
    observations: tuple[CandidateObservation, ...] | None = None,
) -> Result[CommandConclusion]:
    observed = _observe(fixture, plan) if observations is None else observations
    if outcome is None:
        outcome = SemanticOutcome(
            invocation=plan.invocation,
            run=plan.run,
            reconciliation=_reconcile(fixture, plan, observed),
        )
    return conclude_command(
        outcome,
        _command_result(plan, stderr=stderr, events=events, parsed=parsed),
        plan.parse if parsed else MISSING,
        plan.summary,
        observed,
        roots=plan.roots,
        token=fixture.token_material(INVOCATION_ID),
        config=_config(fixture),
        unit_of_work=fixture.unit_of_work(),
        finalizer=fixture.finalizer(),
        clock=fixture.clock,
    )


def _staged_bytes(fixture: FinalizationFixture, candidate: Any) -> bytes:
    owner_root = fixture.roots.staging_root / artifact_owner_hash(candidate.owner)
    return owner_root.joinpath(*candidate.staging_relative_path.split("/")).read_bytes()


def _stage_stderr(
    fixture: FinalizationFixture,
    capture: StderrCapture | None = None,
    owner: Any = RUN_OWNER,
    invocation_id: str = INVOCATION_ID,
) -> Any:
    return _ok(
        stderr_evidence(
            _capture() if capture is None else capture,
            owner,
            invocation_id,
            store=fixture.roots.store,
            unit_of_work=fixture.unit_of_work(),
            auditor=fixture.auditor,
            clock=fixture.clock,
        )
    )


def _stderr_result(
    fixture: FinalizationFixture,
    capture: StderrCapture,
    owner: Any,
    invocation_id: str,
    *,
    unit_of_work: Any = None,
) -> Result[Any]:
    """``stderr_evidence`` through the production route, the answer unwrapped
    by the caller (a refusal is the subject of several cases)."""
    return stderr_evidence(
        capture,
        owner,
        invocation_id,
        store=fixture.roots.store,
        unit_of_work=fixture.unit_of_work() if unit_of_work is None else unit_of_work,
        auditor=fixture.auditor,
        clock=fixture.clock,
    )


def _assert_consistent(fixture: FinalizationFixture) -> None:
    report = fixture.database.consistency_report()
    assert report.dangling_diagnostic_references == 0
    assert report.success_without_manifest == 0


def _forbidden(*args: object, **kwargs: object) -> object:
    raise AssertionError(f"forbidden call: {args!r} {kwargs!r}")


class _RecordingFinalizer:
    """An ``ArtifactFinalizer`` wrapper recording the purpose, the transient
    material and the cancellation token of every ``finalize`` call before
    delegating."""

    def __init__(self, inner: CoreArtifactFinalizer) -> None:
        self._inner = inner
        self.received: list[tuple[str, object]] = []
        self.cancellations: list[Any] = []

    async def finalize(
        self,
        request: Any,
        cancellation: Any,
        *,
        token_material: Any = MISSING,
    ) -> Result[FinalizationResult]:
        self.received.append((str(request.finalization_purpose), token_material))
        self.cancellations.append(cancellation)
        return await self._inner.finalize(
            request, cancellation, token_material=token_material
        )


class _AdvancingProbe(RecordingProbe):
    """Advance the fixed clock past the deadline at ``after_moved``."""

    def __init__(self, clock: FixedClock) -> None:
        super().__init__()
        self._clock = clock

    def after_moved(self) -> None:
        super().after_moved()
        self._clock.advance(RESULT_TIMEOUT_SECONDS + 1)


# --------------------------------------------------------------------------
# The RESULT branch through conclude_command
# --------------------------------------------------------------------------


def test_success_committed_only_with_manifest_and_refs(
    production: FinalizationFixture,
) -> None:
    """Reading 11: success is written in the same T3 as the run manifest, the
    references and the member links -- the registrar's facts precede the run
    swap and the trigger-guarded invariant holds afterwards."""
    plan = _plan(production)
    conclusion = _ok(_conclude(production, plan))
    assert conclusion.run.state is EngineRunState.SUCCEEDED
    assert conclusion.replayed is False
    assert isinstance(conclusion.finalization, FinalizationResult)
    assert conclusion.finalization.journal_state == "REGISTERED"
    manifest = conclusion.run_manifest
    assert isinstance(manifest, RunManifest)
    assert len(conclusion.result_refs) == 2
    assert {ref.artifact_id for ref in conclusion.result_refs} == {
        ref.artifact_id for ref in manifest.artifact_refs
    }
    after = production.durable()
    (row,) = after.run_manifests
    assert row.run_manifest_hash == manifest.run_manifest_hash
    assert row.manifest_id == manifest.manifest_id
    actions = after.audit_actions
    assert (
        actions.index("RUN_MANIFEST_REGISTERED")
        < actions.index("RUN_SUCCEEDED")
        < actions.index("FINALIZATION_REGISTERED")
    )
    members = [
        link
        for link in after.run_artifacts
        if link.link_role == "RESULT_MANIFEST_MEMBER"
    ]
    assert {link.artifact_id for link in members} == {
        ref.artifact_id for ref in conclusion.result_refs
    }
    assert after.run_revision == plan.run.revision + 2
    _assert_consistent(production)


def test_only_result_branch_creates_links_manifest_success(
    production: FinalizationFixture,
) -> None:
    """Reading 5 beside plan 4.4: the EVIDENCE branch writes ``RUN_EVIDENCE``
    links and leaves the run row and ``run_manifests`` untouched; only the
    RESULT branch writes the manifest, the member links and the success."""
    plan = _plan(production)
    _ok(production.finalize_result(plan))
    mid = production.durable()
    assert mid.run_state == "SUCCEEDED"
    (row,) = mid.run_manifests
    members = [
        link for link in mid.run_artifacts if link.link_role == "RESULT_MANIFEST_MEMBER"
    ]
    assert len(members) == 2
    assert all(link.run_manifest_id == row.manifest_id for link in members)
    stderr = _stage_stderr(production)
    _ok(
        finalize_evidence(
            (stderr,), INVOCATION_CORRELATION, finalizer=production.finalizer()
        )
    )
    after = production.durable()
    # The EVIDENCE branch touched neither the run row nor the manifest table.
    assert after.run == mid.run
    assert after.run_manifests == mid.run_manifests
    evidence_links = [
        link for link in after.run_artifacts if link.link_role == "RUN_EVIDENCE"
    ]
    assert len(evidence_links) == 1
    assert not isinstance(evidence_links[0].run_manifest_id, str)
    assert len(after.run_artifacts) == 3
    _assert_consistent(production)


def test_sanitized_manifest_is_run_evidence_after_any_outcome(
    production: FinalizationFixture,
) -> None:
    """Plan 4.6 and T28.3-06: the sanitized manifest's canonical JSON is
    ``RUN``-owned ``CORE_EVIDENCE`` under the invocation correlation, its row is
    written once, and it registers after a non-success outcome too (here the
    Stage 6 verdict failed the run), with the row linked to the reference.

    The bytes carry SHA-256 digests and prefixed identifiers; they register
    because the production registrar qualifies them against the stored row
    (the ruling of 2026-11-09), not because the shape rule was relaxed."""
    plan = _plan(production, sanitized_row=False)
    failed = production.fail_run_by_verdict()
    staged = _ok(
        sanitized_result_manifest_evidence(
            plan.sanitized,
            RUN_OWNER,
            store=production.roots.store,
            unit_of_work=production.unit_of_work(),
            clock=production.clock,
        )
    )
    sanitized_hash = plan.sanitized.sanitized_adapter_result_manifest_hash
    assert staged.finalization_purpose is _F.EVIDENCE
    assert staged.producer_kind is _P.CORE
    assert staged.source_role is _R.CORE_EVIDENCE
    assert staged.staging_relative_path == (
        f"INVOCATION/{INVOCATION_ID}/{sanitized_manifest_leaf()}"
    )
    assert sanitized_hash not in staged.staging_relative_path
    assert production.harness.count("sanitized_adapter_result_manifests") == 1
    again = _ok(
        sanitized_result_manifest_evidence(
            plan.sanitized,
            RUN_OWNER,
            store=production.roots.store,
            unit_of_work=production.unit_of_work(),
            clock=production.clock,
        )
    )
    assert again == staged
    assert production.harness.count("sanitized_adapter_result_manifests") == 1
    data = _staged_bytes(production, staged)
    assert data == canonical_json_bytes(plan.sanitized)
    assert FIXTURE_TOKEN.encode("utf-8") not in data
    registered = _ok(
        finalize_evidence(
            (staged,), INVOCATION_CORRELATION, finalizer=production.finalizer()
        )
    )
    (mapping,) = registered.candidate_to_artifact_refs
    after = production.durable()
    assert after.run_state == "FAILED"
    assert after.run_revision == failed.revision
    transaction = production.begin()
    try:
        facts = _ok(transaction.sanitized_manifests.get(sanitized_hash))
    finally:
        transaction.rollback()
    assert not isinstance(facts, type(MISSING))
    assert facts.evidence_artifact_id == mapping.artifact_id
    assert {link.link_role for link in after.run_artifacts} == {"RUN_EVIDENCE"}
    _assert_consistent(production)


def test_artifact_produced_creates_only_a_candidate(
    production: FinalizationFixture,
) -> None:
    """Plan 4.4 step 2: each accepted ``ARTIFACT_PRODUCED`` declaration becomes
    one ``CANDIDATE`` row naming its event -- no reference, no journal, no blob,
    no audit row, no run write -- and registration is idempotent."""
    plan = _plan(production, plant_candidates=False)
    assert production.durable().candidates == ()
    created = _ok(
        register_result_candidates(
            plan.summary.artifact_declarations,
            RUN_OWNER,
            unit_of_work=production.unit_of_work(),
            clock=production.clock,
        )
    )
    declarations = {
        record.payload.relative_path: record
        for record in plan.summary.artifact_declarations
    }
    assert [item.candidate_artifact_id for item in created] == sorted(
        candidate_artifact_id_for(RUN_ID, INVOCATION_ID, path) for path in declarations
    )
    for candidate in created:
        record = declarations[candidate.staging_relative_path]
        assert candidate.state is _S.CANDIDATE
        assert candidate.producer_kind is _P.ADAPTER
        assert candidate.finalization_purpose is _F.RESULT
        assert candidate.source_role is _R.ENGINE_NATIVE_RESULT
        assert candidate.source_event_id == record.event_id
        assert candidate.adapter_declared_hash == record.payload.declared_sha256
        assert candidate.adapter_declared_size == record.payload.declared_size_bytes
        assert candidate.adapter_declared_media_type == record.payload.media_type
    after = production.durable()
    assert after.candidates == created
    assert after.refs == ()
    assert after.journal == ()
    assert after.object_blobs == ()
    assert after.run_manifests == ()
    assert after.audit_actions == ()
    assert after.run == plan.run
    again = _ok(
        register_result_candidates(
            plan.summary.artifact_declarations,
            RUN_OWNER,
            unit_of_work=production.unit_of_work(),
            clock=production.clock,
        )
    )
    assert again == created
    assert production.durable().candidates == created


def test_stderr_truncation_diagnostic_and_audit(
    production: FinalizationFixture,
) -> None:
    """Plan 4.6 (14.7:1014): a truncated capture records
    ``PROCESS.STDERR_TRUNCATED`` and the ``STDERR_TRUNCATED`` fact with the
    retained count; an untruncated one records neither. The adapter owner's
    capture is correlated to its planted ``DESCRIBE`` invocation (plan 3.1.1
    row 3)."""
    production.plant_run()
    _plant_invocation(production, OTHER_INVOCATION_ID, CommandKind.DESCRIBE)
    _stage_stderr(production)
    clean = production.durable()
    assert PROCESS_STDERR_TRUNCATED not in clean.diagnostic_codes
    assert "STDERR_TRUNCATED" not in clean.audit_actions
    truncated = _capture("partial engine stderr\n", truncated=True)
    staged = _stage_stderr(production, truncated, ADAPTER_OWNER, OTHER_INVOCATION_ID)
    assert staged.artifact_kind == STDERR_KIND
    assert _staged_bytes(production, staged) == b"partial engine stderr\n"
    after = production.durable()
    assert after.diagnostic_codes.count(PROCESS_STDERR_TRUNCATED) == 1
    (diagnostic,) = [
        item
        for item in after.diagnostics
        if item.error_code == PROCESS_STDERR_TRUNCATED
    ]
    assert diagnostic.invocation_id == OTHER_INVOCATION_ID
    assert diagnostic.details == {"retained_byte_count": truncated.retained_byte_count}
    assert after.audit_actions.count("STDERR_TRUNCATED") == 1
    (event,) = [
        item for item in after.audit_events if item.action.value == "STDERR_TRUNCATED"
    ]
    assert event.correlation_id == OTHER_INVOCATION_ID
    assert event.invocation_id == OTHER_INVOCATION_ID
    assert event.details == {"retained_byte_count": truncated.retained_byte_count}
    _assert_consistent(production)


def test_unsanitized_stdout_never_staged(production: FinalizationFixture) -> None:
    """Plan 4.6: the protocol capture is the JSON Lines of the sanitized
    ``RunEvent`` records -- the hash in the token's place, no raw token and no
    raw stdout line."""
    plan = _plan(production)
    staged = _ok(
        protocol_capture_evidence(
            plan.events,
            RUN_OWNER,
            INVOCATION_ID,
            store=production.roots.store,
            unit_of_work=production.unit_of_work(),
            clock=production.clock,
        )
    )
    assert staged.artifact_kind == "protocol-capture"
    data = _staged_bytes(production, staged)
    assert data == b"".join(
        canonical_json_bytes(event) + b"\n" for event in plan.events
    )
    assert FIXTURE_TOKEN.encode("utf-8") not in data
    lines = data.split(b"\n")[:-1]
    assert len(lines) == len(plan.events)
    for line in lines:
        document = json.loads(line)
        assert "attempt_token" not in document
        assert document["attempt_token_hash"] == plan.run.attempt_token_hash
        RunEvent.model_validate_json(line)


def test_core_staging_root_by_owner(production: FinalizationFixture) -> None:
    """Plan 4.6: core evidence enters staging only through ``store.write_staged``
    under ``<owner hash>/<correlation kind>/<correlation id>/<leaf>``, so two
    owners' captures of the same leaf never share a root or an identity; a role
    outside plan 3.1.1 for the owner is refused before any I/O. The adapter
    owner's capture is correlated to its planted ``DESCRIBE`` invocation."""
    production.plant_run()
    _plant_invocation(production, OTHER_INVOCATION_ID, CommandKind.DESCRIBE)
    run_side = _stage_stderr(production)
    adapter_side = _stage_stderr(
        production, _capture("adapter stderr\n"), ADAPTER_OWNER, OTHER_INVOCATION_ID
    )
    assert run_side.candidate_artifact_id != adapter_side.candidate_artifact_id
    run_hash = artifact_owner_hash(RUN_OWNER)
    adapter_hash = artifact_owner_hash(ADAPTER_OWNER)
    files = production.roots.staging_files()
    assert f"{run_hash}/INVOCATION/{INVOCATION_ID}/stderr.txt" in files
    assert f"{adapter_hash}/INVOCATION/{OTHER_INVOCATION_ID}/stderr.txt" in files
    assert run_side.candidate_artifact_id == core_candidate_artifact_id_for(
        run_hash, "INVOCATION", INVOCATION_ID, "stderr.txt"
    )
    before = production.durable()
    refused = stage_core_evidence(
        RUN_OWNER,
        _R.ADAPTER_DESCRIPTOR_EVIDENCE,
        "adapter-descriptor",
        "adapter-descriptor.json",
        b"{}",
        INVOCATION_CORRELATION,
        store=production.roots.store,
        unit_of_work=production.unit_of_work(),
        clock=production.clock,
    )
    assert _code(refused) == ARTIFACT_VALIDATION_FAILED
    assert production.roots.staging_files() == files
    assert production.durable().candidates == before.candidates


def test_timeout_never_retries_in_place(production: FinalizationFixture) -> None:
    """Plan 4.5 and 23.3.1:1723: a RESULT finalization that exhausts its deadline
    moves the run to ``TIMED_OUT`` and abandons the journal; the same request is
    refused afterwards and recovery registers nothing -- a retry is a new
    attempt, never a reopening in place."""
    plan = _plan(production)
    timed_out = production.finalize(
        plan.request, probe=_AdvancingProbe(production.clock)
    )
    assert _code(timed_out) == ARTIFACT_FINALIZATION_TIMED_OUT
    after = production.durable()
    assert after.run_state == "TIMED_OUT"
    assert after.journal_state == "ABANDONED"
    assert after.abandon_reason == ARTIFACT_FINALIZATION_TIMED_OUT
    assert after.refs == ()
    assert after.run_manifests == ()
    again = production.finalize_result(plan)
    assert _code(again) == CONCURRENCY_CONFLICT
    assert "abandoned" in _message(again)
    report = _ok(production.recover())
    assert report.registered == 0
    later = production.durable()
    assert later.run == after.run
    assert later.journal == after.journal
    assert later.run_manifests == ()
    _assert_consistent(production)


def test_dataset_input_evidence_hash_equals_registry(
    production: FinalizationFixture,
) -> None:
    """Plan 4.6 and O-12: an input snapshot is staged only when its bytes hash
    to the registry fact; differing bytes are refused before anything is
    staged. The experiment owner (its row exists) proves the staging half; the
    dataset owner's refusal arises before any owner row is needed."""
    production.plant_run()
    payload = b'{"rows": 3, "symbol": "BTC-USD"}\n'
    audit_event_id = production.audit_ids.new_audit_event_id()
    staged = _ok(
        input_snapshot_evidence(
            EXPERIMENT_OWNER,
            payload,
            sha256_bytes(payload),
            audit_event_id,
            store=production.roots.store,
            unit_of_work=production.unit_of_work(),
            clock=production.clock,
        )
    )
    kind = INPUT_SNAPSHOT_KINDS["EXPERIMENT"]
    assert staged.source_role is _R.EXPERIMENT_INPUT
    assert staged.artifact_kind == kind
    assert staged.staging_relative_path == f"AUDIT/{audit_event_id}/{kind}.json"
    assert _staged_bytes(production, staged) == payload
    files = production.roots.staging_files()
    candidates = production.durable().candidates
    for owner in (DATASET_OWNER, EXPERIMENT_OWNER):
        refused = input_snapshot_evidence(
            owner,
            payload,
            "0" * 64,
            audit_event_id,
            store=production.roots.store,
            unit_of_work=production.unit_of_work(),
            clock=production.clock,
        )
        assert _code(refused) == ARTIFACT_VALIDATION_FAILED
        assert "differ" in _message(refused)
    assert production.roots.staging_files() == files
    assert production.durable().candidates == candidates
    assert INPUT_SNAPSHOT_KINDS["DATASET"] == "dataset-manifest"


def test_identity_violation_blocks_result_not_evidence(
    production: FinalizationFixture,
) -> None:
    """29.3: a token that does not hash to the run's durable hash -- or no token
    at all -- blocks the RESULT branch with
    ``PROTOCOL.IDENTITY_OR_SEQUENCE_VIOLATION``; the invocation's evidence still
    finalizes (29.1 non-interference)."""
    plan = _plan(production)
    validator = ResultRecoveryValidator(
        unit_of_work=production.unit_of_work(),
        hasher=production.hasher,
        negotiated_versions=DEFAULT_NEGOTIATED_VERSIONS,
        finalization_timeout_seconds=RESULT_TIMEOUT_SECONDS,
        clock=production.clock,
    )
    wrong = validator.validate_temporary_manifest(
        plan.roots,
        AttemptTokenMaterial(run_id=RUN_ID, attempt_token=_WRONG_TOKEN),
        plan.candidates,
    )
    assert _code(wrong) == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    assert _WRONG_TOKEN not in _message(wrong)
    absent = validator.validate_temporary_manifest(plan.roots, MISSING, plan.candidates)
    assert _code(absent) == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    stderr = _stage_stderr(production)
    registered = _ok(
        finalize_evidence(
            (stderr,), INVOCATION_CORRELATION, finalizer=production.finalizer()
        )
    )
    assert registered.journal_state == "REGISTERED"
    after = production.durable()
    assert after.run_state == "RUNNING"
    assert after.run_revision == plan.run.revision
    assert [ref.finalization_purpose for ref in after.refs] == [_F.EVIDENCE]
    assert after.run_manifests == ()
    _assert_consistent(production)


def test_manifest_invalid_fails_run(production: FinalizationFixture) -> None:
    """Plan 4.4 steps 0 and 3 (R30.3-01): a refusal of the ``ARTIFACT`` class
    moves the run ``RUNNING -> FAILED`` under its diagnostic, audits
    ``RUN_FAILED`` by name in the same transaction and closes the root's raw
    bytes; a run that moved meanwhile is the conflict and nothing is written."""
    plan = _plan(production)
    refusal = artifact_failure(
        ARTIFACT_RESULT_MANIFEST_INVALID,
        message="the temporary result manifest does not validate",
        now_utc=production.clock.now_utc(),
        experiment_id=EXPERIMENT_ID,
        run_id=RUN_ID,
        invocation_id=INVOCATION_ID,
    )
    diagnostic = refusal.diagnostics[0]
    _ok(
        fail_run_for_refusal(
            refusal,
            run_id=RUN_ID,
            expected_run_revision=plan.run.revision,
            roots=plan.roots,
            config=_config(production),
            unit_of_work=production.unit_of_work(),
            clock=production.clock,
        )
    )
    after = production.durable()
    assert after.run_state == "FAILED"
    assert after.run is not None
    assert after.run.revision == plan.run.revision + 1
    assert after.run.primary_terminal_diagnostic_id == diagnostic.diagnostic_id
    assert diagnostic.diagnostic_id in {
        item.diagnostic_id for item in after.diagnostics
    }
    assert after.audit_actions == ("RUN_FAILED", "RETENTION_DELETED")
    (failed_event, _) = after.audit_events
    assert failed_event.correlation_id == INVOCATION_ID
    assert failed_event.details == {"reason": ARTIFACT_RESULT_MANIFEST_INVALID}
    assert failed_event.outcome.value == "FAILED"
    assert not plan.roots.request_path.exists()
    assert isinstance(plan.roots.result_path, Path)
    assert not plan.roots.result_path.exists()
    conflict = fail_run_for_refusal(
        refusal,
        run_id=RUN_ID,
        expected_run_revision=plan.run.revision,
        roots=plan.roots,
        config=_config(production),
        unit_of_work=production.unit_of_work(),
        clock=production.clock,
    )
    assert _code(conflict) == CONCURRENCY_CONFLICT
    assert production.durable() == after
    _assert_consistent(production)


def test_diagnostic_report_evidence_sanitized(
    production: FinalizationFixture,
) -> None:
    """Plan 4.6 (21.3): the diagnostic report is the recorded ``Diagnostic``
    closure as JSON Lines sorted by identity under the ``DIAGNOSTIC``
    correlation of its primary -- bounded, redacted records by construction."""
    production.plant_run()
    diagnostics = (
        sample_diagnostic(
            OTHER_DIAG_ID,
            error_code=ARTIFACT_VALIDATION_FAILED,
            category=DiagnosticCategory.ARTIFACT_CORRUPTION,
            retriable=False,
        ),
        sample_diagnostic(
            DIAG_ID,
            error_code=ARTIFACT_RESULT_MANIFEST_INVALID,
            category=DiagnosticCategory.ARTIFACT_CORRUPTION,
            retriable=False,
            causal_diagnostic_ids=(OTHER_DIAG_ID,),
        ),
    )
    staged = _ok(
        diagnostic_report_evidence(
            diagnostics,
            RUN_OWNER,
            DIAG_ID,
            store=production.roots.store,
            unit_of_work=production.unit_of_work(),
            clock=production.clock,
        )
    )
    assert staged.artifact_kind == "diagnostic-report"
    assert staged.source_role is _R.CORE_EVIDENCE
    assert (
        staged.staging_relative_path == f"DIAGNOSTIC/{DIAG_ID}/diagnostic-report.jsonl"
    )
    data = _staged_bytes(production, staged)
    ordered = sorted(diagnostics, key=lambda item: item.diagnostic_id)
    assert data == b"".join(canonical_json_bytes(item) + b"\n" for item in ordered)
    assert FIXTURE_TOKEN.encode("utf-8") not in data
    first = json.loads(data.split(b"\n")[0])
    assert first["diagnostic_id"] == ordered[0].diagnostic_id
    system = _ok(
        diagnostic_report_evidence(
            diagnostics,
            SYSTEM_OWNER,
            DIAG_ID,
            store=production.roots.store,
            unit_of_work=production.unit_of_work(),
            clock=production.clock,
        )
    )
    assert system.candidate_artifact_id != staged.candidate_artifact_id
    assert _staged_bytes(production, system) == data


def test_causal_chain_terminal_references_artifact_findings(
    production: FinalizationFixture,
) -> None:
    """A terminal diagnostic that names a recorded artifact finding as its cause
    keeps the chain whole: the run's primary references the finding and the
    consistency report shows no dangling reference."""
    plan = _plan(production)
    finding = sample_diagnostic(
        OTHER_DIAG_ID,
        error_code=ARTIFACT_VALIDATION_FAILED,
        category=DiagnosticCategory.ARTIFACT_CORRUPTION,
        retriable=False,
    )
    transaction = production.begin()
    try:
        _ok(transaction.diagnostics_writer.record(finding))
        _ok(transaction.commit())
    finally:
        transaction.rollback()
    terminal = sample_diagnostic(
        THIRD_DIAG_ID,
        error_code=ARTIFACT_RESULT_MANIFEST_INVALID,
        category=DiagnosticCategory.ARTIFACT_CORRUPTION,
        retriable=False,
        causal_diagnostic_ids=(OTHER_DIAG_ID,),
    )
    _ok(
        fail_run_for_refusal(
            Failure(outcome="FAILURE", diagnostics=(terminal,)),
            run_id=RUN_ID,
            expected_run_revision=plan.run.revision,
            roots=plan.roots,
            config=_config(production),
            unit_of_work=production.unit_of_work(),
            clock=production.clock,
        )
    )
    after = production.durable()
    assert after.run is not None
    assert after.run.primary_terminal_diagnostic_id == THIRD_DIAG_ID
    stored = {item.diagnostic_id: item for item in after.diagnostics}
    assert stored[THIRD_DIAG_ID].causal_diagnostic_ids == (OTHER_DIAG_ID,)
    assert stored[OTHER_DIAG_ID].error_code == ARTIFACT_VALIDATION_FAILED
    _assert_consistent(production)


def test_non_success_never_waits_for_evidence(
    production: FinalizationFixture, tmp_path: Path
) -> None:
    """29.1: the evidence outcome never gates the conclusion. A refused evidence
    finalization (a token-shaped stderr) is carried as ``evidence_failure``
    beside the RESULT success, and a failed verdict concludes at once -- the
    root closed, no finalization, no evidence awaited."""
    plan = _plan(production)
    conclusion = _ok(_conclude(production, plan, stderr=_capture(_SHAPED_TEXT)))
    assert conclusion.run.state is EngineRunState.SUCCEEDED
    assert isinstance(conclusion.finalization, FinalizationResult)
    assert isinstance(conclusion.evidence_failure, Failure)
    assert _code(conclusion.evidence_failure) == SECURITY_SENSITIVE_MATERIAL_LEAKAGE
    assert conclusion.evidence_refs == ()
    _assert_consistent(production)
    with _fresh(tmp_path, "f") as other:
        failed_plan = _plan(other)
        failed_run = other.fail_run_by_verdict()
        # An exit that owed a manifest and wrote none: FAILED, nothing sanitized.
        reconciliation = _reconcile_without_manifest(other, failed_plan)
        assert reconciliation.verdict is ReconciliationVerdict.FAILED
        assert not isinstance(reconciliation.primary_diagnostic, type(MISSING))
        assert reconciliation.primary_diagnostic.error_code == (
            ARTIFACT_RESULT_MANIFEST_INVALID
        )
        outcome = SemanticOutcome(
            invocation=failed_plan.invocation,
            run=failed_run,
            reconciliation=reconciliation,
        )
        concluded = _ok(
            _conclude(
                other,
                failed_plan,
                outcome=outcome,
                observations=(),
                events=False,
                parsed=False,
            )
        )
        assert concluded.run.state is EngineRunState.FAILED
        assert not isinstance(concluded.finalization, FinalizationResult)
        assert not isinstance(concluded.run_manifest, RunManifest)
        assert concluded.evidence_refs == ()
        assert not isinstance(concluded.evidence_failure, Failure)
        assert not failed_plan.roots.request_path.exists()
        after = other.durable()
        assert after.run_manifests == ()
        assert after.audit_actions.count("RETENTION_DELETED") == 1
        assert reconciliation.diagnostics[0].diagnostic_id in {
            item.diagnostic_id for item in after.diagnostics
        }
        _assert_consistent(other)


def test_one_correlation_across_finalization_diagnostics_audit(
    production: FinalizationFixture,
) -> None:
    """Plan 4.8: every audit row of one finalization carries its
    ``finalization_id`` as the correlation and the run's identities; the
    evidence finalization of the same invocation carries its own."""
    plan = _plan(production)
    conclusion = _ok(_conclude(production, plan, events=False))
    assert isinstance(conclusion.finalization, FinalizationResult)
    result_id = conclusion.finalization.finalization_id
    stderr = _stage_stderr(production)
    evidence = _ok(
        finalize_evidence(
            (stderr,), INVOCATION_CORRELATION, finalizer=production.finalizer()
        )
    )
    assert result_id != evidence.finalization_id
    after = production.durable()
    by_correlation: dict[str, list[str]] = {}
    for event in after.audit_events:
        by_correlation.setdefault(event.correlation_id, []).append(event.action.value)
    assert by_correlation[result_id] == [
        "ARTIFACT_VALIDATED",
        "ARTIFACT_VALIDATED",
        "FINALIZATION_LEASE_ACQUIRED",
        "FINALIZATION_PREPARED",
        "FINALIZATION_MOVED",
        "RUN_MANIFEST_REGISTERED",
        "RUN_SUCCEEDED",
        "FINALIZATION_REGISTERED",
        "RETENTION_DELETED",
    ]
    assert by_correlation[evidence.finalization_id] == [
        "ARTIFACT_VALIDATED",
        "FINALIZATION_LEASE_ACQUIRED",
        "FINALIZATION_PREPARED",
        "FINALIZATION_MOVED",
        "FINALIZATION_REGISTERED",
    ]
    for event in after.audit_events:
        if event.correlation_id == result_id:
            assert event.experiment_id == EXPERIMENT_ID
            assert event.run_id == RUN_ID
            assert event.invocation_id == INVOCATION_ID
    assert by_correlation[INVOCATION_ID] == ["STDERR_EVIDENCE_LINKED"]
    _assert_consistent(production)


def test_manifest_validation_sanitization_generation_reconciliation(
    production: FinalizationFixture,
) -> None:
    """The chain of plan 4.4: the parsed manifest sanitizes to the fixture's
    sanitized representation, reconciles to ``RESULT_FINALIZATION_ELIGIBLE``
    and generates a ``RunManifest`` whose provenance, hashes, metrics and
    references derive from it alone."""
    plan = _plan(production)
    parse = parse_result_manifest(
        plan.manifest_bytes, max_bytes=MAX_RESULT_MANIFEST_BYTES, token=FIXTURE_TOKEN
    )
    assert parse == plan.parse
    assert parse.redactions == 0
    sanitized = sanitize_result_manifest(parse, plan.summary)
    assert sanitized == plan.sanitized
    assert sanitized.attempt_token_hash == plan.run.attempt_token_hash
    assert sanitized.source_adapter_result_manifest_hash == sha256_bytes(
        plan.manifest_bytes
    )
    reconciliation = _reconcile(production, plan)
    assert reconciliation.verdict is ReconciliationVerdict.RESULT_FINALIZATION_ELIGIBLE
    assert reconciliation.sanitized_manifest == sanitized
    assert reconciliation.semantic_status is SemanticStatus.SUCCEEDED
    conclusion = _ok(_conclude(production, plan, events=False))
    manifest = conclusion.run_manifest
    assert isinstance(manifest, RunManifest)
    assert manifest.provenance == sanitized.provenance
    assert manifest.sanitized_adapter_result_manifest_hash == (
        sanitized.sanitized_adapter_result_manifest_hash
    )
    assert manifest.attempt_token_hash == sanitized.attempt_token_hash
    assert manifest.semantic_status == "SUCCEEDED"
    assert manifest.process_exit_category is ProcessExitCategory.SUCCESS
    assert (manifest.started_at_utc, manifest.completed_at_utc) == (
        sanitized.started_at_utc,
        sanitized.completed_at_utc,
    )
    (metric,) = manifest.metrics
    assert metric.metric_name == "total-return"
    assert metric.value == Decimal("0.125")
    assert metric.unit == "ratio"
    assert metric.value_type is MetricValueType.RATIO
    assert metric.source_artifact_id in {
        ref.artifact_id for ref in manifest.artifact_refs
    }
    assert manifest.diagnostics == ()
    assert manifest.warnings == ()
    assert manifest.approximations == ()
    assert {ref.source_candidate_artifact_id for ref in manifest.artifact_refs} == set(
        sanitized.candidate_artifact_ids
    )
    assert manifest.run_invocation_id == INVOCATION_ID
    _assert_consistent(production)


def test_protocol_capture_regenerated_from_ledger(
    production: FinalizationFixture,
) -> None:
    """T28.2-02: the protocol capture is regenerated from the durable ledger --
    each line a stored sanitized event whose content hash recomputes -- and the
    same ledger regenerates the same bytes; a different sequence is a different
    payload the store refuses under the same path."""
    plan = _plan(production)
    transaction = production.begin()
    try:
        ledger = _ok(transaction.engine_runs.list_events(INVOCATION_ID))
    finally:
        transaction.rollback()
    assert ledger == plan.events
    staged = _ok(
        protocol_capture_evidence(
            ledger,
            RUN_OWNER,
            INVOCATION_ID,
            store=production.roots.store,
            unit_of_work=production.unit_of_work(),
            clock=production.clock,
        )
    )
    data = _staged_bytes(production, staged)
    lines = data.split(b"\n")[:-1]
    assert len(lines) == len(ledger)
    for line, event in zip(lines, ledger, strict=True):
        decoded = RunEvent.model_validate_json(line)
        assert decoded == event
        assert run_event_content_hash(decoded) == event.content_hash
    again = _ok(
        protocol_capture_evidence(
            ledger,
            RUN_OWNER,
            INVOCATION_ID,
            store=production.roots.store,
            unit_of_work=production.unit_of_work(),
            clock=production.clock,
        )
    )
    assert again == staged
    reordered = protocol_capture_evidence(
        tuple(reversed(ledger)),
        RUN_OWNER,
        INVOCATION_ID,
        store=production.roots.store,
        unit_of_work=production.unit_of_work(),
        clock=production.clock,
    )
    assert _code(reordered) == INVARIANT_VIOLATION
    assert _staged_bytes(production, staged) == data


def test_adapter_claiming_core_ids_rejected(production: FinalizationFixture) -> None:
    """A RESULT request or a recovery group that names a core-produced candidate
    is refused: the finalizer before any lease, the recovery validator before
    any read of the manifest."""
    plan = _plan(production)
    stderr = _stage_stderr(production)
    claiming = sample_result_request(
        [
            *(candidate.candidate_artifact_id for candidate in plan.candidates),
            stderr.candidate_artifact_id,
        ],
        run=plan.run,
        invocation=plan.invocation,
        source_hash=plan.parse.source_hash,
        sanitized_hash=plan.sanitized.sanitized_adapter_result_manifest_hash,
    )
    refused = production.finalize(claiming)
    assert _code(refused) == ARTIFACT_VALIDATION_FAILED
    assert stderr.candidate_artifact_id in _message(refused)
    after = production.durable()
    assert after.journal == ()
    assert after.run_state == "RUNNING"
    assert after.run_manifests == ()
    group = production.validator.validate_temporary_manifest(
        plan.roots, _token(production), (*plan.candidates, stderr)
    )
    assert _code(group) == ARTIFACT_VALIDATION_FAILED
    assert "adapter-produced" in _message(group)


def test_adapter_diagnostic_ids_are_stable(production: FinalizationFixture) -> None:
    """The verdict's diagnostics are content-addressed: two reconciliations of
    the same inputs mint the same identity, and the conclusion records it once
    however often it is concluded."""
    plan = _plan(production)
    observations = _observe(production, plan)
    wrong = tuple(
        item.model_copy(update={"observed_sha256": "0" * 64}) for item in observations
    )
    first = _reconcile(production, plan, wrong)
    second = _reconcile(production, plan, wrong)
    assert first.verdict is ReconciliationVerdict.FAILED
    assert not isinstance(first.primary_diagnostic, type(MISSING))
    assert first.primary_diagnostic.error_code == ARTIFACT_VALIDATION_FAILED
    assert (
        first.primary_diagnostic.diagnostic_id
        == second.primary_diagnostic.diagnostic_id
    )
    failed_run = production.fail_run_by_verdict()
    outcome = SemanticOutcome(
        invocation=plan.invocation, run=failed_run, reconciliation=first
    )
    for _ in range(2):
        concluded = _ok(
            _conclude(
                production, plan, outcome=outcome, observations=wrong, events=False
            )
        )
        assert concluded.run.state is EngineRunState.FAILED
    recorded = [
        item
        for item in production.durable().diagnostics
        if item.diagnostic_id == first.primary_diagnostic.diagnostic_id
    ]
    assert len(recorded) == 1
    _assert_consistent(production)


def test_source_hash_persisted_bytes_not(production: FinalizationFixture) -> None:
    """Plan 3.10 and 14.7: the exact-byte hash of the adapter manifest is
    persisted on the sanitized row, the journal and the run manifest; the
    token-bearing bytes themselves are never persisted and leave the root at
    the close."""
    plan = _plan(production)
    source_hash = sha256_bytes(plan.manifest_bytes)
    conclusion = _ok(_conclude(production, plan, events=False))
    assert conclusion.run.state is EngineRunState.SUCCEEDED
    after = production.durable()
    # The sanitized-manifest evidence registers beside the result (the ruling
    # of 2026-11-09), so the RESULT journal is the one carrying the source hash.
    (journal,) = [
        entry for entry in after.journal if entry.finalization_purpose is _F.RESULT
    ]
    assert journal.source_adapter_result_manifest_hash == source_hash
    (row,) = after.run_manifests
    transaction = production.begin()
    try:
        facts = _ok(
            transaction.sanitized_manifests.get(
                plan.sanitized.sanitized_adapter_result_manifest_hash
            )
        )
    finally:
        transaction.rollback()
    assert not isinstance(facts, type(MISSING))
    assert facts.source_adapter_result_manifest_hash == source_hash
    assert source_hash not in after.object_blobs
    assert isinstance(plan.roots.result_path, Path)
    assert not plan.roots.result_path.exists()
    for text in (row.manifest_json, facts.manifest_json):
        assert FIXTURE_TOKEN not in text
    database_bytes = (production.tmp_path / "registry.sqlite3").read_bytes()
    assert plan.manifest_bytes not in database_bytes
    assert FIXTURE_TOKEN.encode("utf-8") not in database_bytes


def test_stderr_artifact_id_enriched_once(production: FinalizationFixture) -> None:
    """Plan 4.6: the first stderr evidence reference enriches the invocation's
    ``stderr_artifact_id`` once (``assert_write_once_enrichment``) with the
    ``STDERR_EVIDENCE_LINKED`` fact; a later stderr-kind reference under the same
    invocation leaves it unchanged."""
    plan = _plan(production)
    first = _stage_stderr(production)
    registered = _ok(
        finalize_evidence(
            (first,), INVOCATION_CORRELATION, finalizer=production.finalizer()
        )
    )
    (mapping,) = registered.candidate_to_artifact_refs
    after = production.durable()
    assert after.invocation is not None
    assert after.invocation.stderr_artifact_id == mapping.artifact_id
    assert after.invocation.revision == plan.invocation.revision + 1
    assert after.audit_actions.count("STDERR_EVIDENCE_LINKED") == 1
    second = _ok(
        stage_core_evidence(
            RUN_OWNER,
            _R.CORE_EVIDENCE,
            STDERR_KIND,
            "stderr-second.txt",
            b"later engine stderr\n",
            INVOCATION_CORRELATION,
            store=production.roots.store,
            unit_of_work=production.unit_of_work(),
            clock=production.clock,
        )
    )
    _ok(
        finalize_evidence(
            (second,), INVOCATION_CORRELATION, finalizer=production.finalizer()
        )
    )
    later = production.durable()
    assert later.invocation is not None
    assert later.invocation.stderr_artifact_id == mapping.artifact_id
    assert later.invocation.revision == plan.invocation.revision + 1
    assert later.audit_actions.count("STDERR_EVIDENCE_LINKED") == 1
    assert len(later.refs) == 2
    _assert_consistent(production)


# --------------------------------------------------------------------------
# conclude_describe
# --------------------------------------------------------------------------

_ENGINE_NAME: Final = "engine.alpha"
_ENGINE_VERSION: Final = "2.3.4"


def _descriptor() -> AdapterDescriptor:
    return AdapterDescriptor.model_validate(
        {
            "schema_version": SCHEMA_VERSION,
            "adapter_name": ADAPTER_OWNER.adapter_name,
            "adapter_version": ADAPTER_OWNER.adapter_version,
            "engine": EngineDescriptor(
                schema_version="1.0.0",
                engine_name=_ENGINE_NAME,
                engine_version=_ENGINE_VERSION,
                engine_family="alpha.family",
                planned_role="Offline fake adapter.",
                known_limitations=(),
            ),
            "supported_protocol_versions": ("1.0.0",),
            "supported_schema_versions": tuple(
                SupportedSchemaVersion(schema_name=name, schema_version=SCHEMA_VERSION)
                for name in NEGOTIABLE_SCHEMA_NAMES
            ),
            "capability_vocabulary_version": "capabilities/v1",
            "native_capabilities": ("data.ohlcv", "market.spot"),
            "approximated_capabilities": (),
            "unsupported_capabilities": (),
            "supported_operating_systems": (OperatingSystem.WINDOWS,),
            "runtime_requirements": ("CPython 3.12",),
            "network_required": False,
            "credentials_required": False,
            "known_modeling_limitations": (),
            "executable_hash": EXECUTABLE_HASH,
        }
    )


def _envelope_bytes(descriptor: AdapterDescriptor) -> bytes:
    envelope = BootstrapDescriptorEnvelope.model_validate(
        {
            "bootstrap_schema_version": SCHEMA_VERSION,
            "adapter_name": descriptor.adapter_name,
            "adapter_version": descriptor.adapter_version,
            "engine_name": descriptor.engine.engine_name,
            "engine_version": descriptor.engine.engine_version,
            "executable_hash": descriptor.executable_hash,
            "supported_protocol_versions": descriptor.supported_protocol_versions,
            "supported_schema_versions": descriptor.supported_schema_versions,
            "capability_vocabulary_versions": (
                descriptor.capability_vocabulary_version,
            ),
            "descriptor_payload_hash": sha256_bytes(canonical_json_bytes(descriptor)),
            "descriptor": descriptor,
        }
    )
    return canonical_json_bytes(envelope)


class _NoRunReads:
    """A unit of work whose transactions refuse the ``engine_runs`` member."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def begin(self) -> Any:
        return _NoRunReadsTransaction(self._inner.begin())


class _NoRunReadsTransaction:
    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def __getattr__(self, name: str) -> Any:
        if name == "engine_runs":
            raise AssertionError("a describe conclusion read or wrote engine_runs")
        return getattr(self._inner, name)


def test_conclude_describe_stages_descriptor_and_stderr_only(
    production: FinalizationFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Plan 4.6: both describe producers finalize under the ``ADAPTER`` owner
    (engine from the parsed envelope) with the ``INVOCATION`` correlation naming
    the ``DESCRIBE`` invocation, whose ``stderr_artifact_id`` is enriched; no
    ``engine_runs`` read or write, no ``close_raw_bytes`` call, and the root's
    ``request.json`` and ``output.json`` stay. A describe conclusion is truly
    token-free: neither finalization receives material (the ruling of
    2026-11-09), and the descriptor's digests qualify against the describe
    invocation and the owner instead."""
    production.plant_run()
    describe = sample_invocation(
        CommandInvocationState.EXITED,
        kind=CommandKind.DESCRIBE,
        invocation_id=OTHER_INVOCATION_ID,
    )
    put_invocation(production.harness.lifecycle(), describe)
    root = production.roots.runtime_root / OTHER_INVOCATION_ID
    root.mkdir()
    request_path = root / "request.json"
    output_path = root / "output.json"
    output_bytes = _envelope_bytes(_descriptor())
    request_path.write_bytes(b'{"schema_version": "1.0.0", "command": "describe"}')
    output_path.write_bytes(output_bytes)
    roots = CommandRootPaths(
        command_root=root, request_path=request_path, output_path=output_path
    )
    parse = parse_bootstrap_descriptor(
        output_bytes, max_bytes=MAX_DESCRIPTOR_OUTPUT_BYTES
    )
    assert isinstance(parse, DescriptorParse)
    assert isinstance(parse.envelope, BootstrapDescriptorEnvelope)
    reconciliation = reconcile_describe(
        describe,
        parse,
        0,
        catalog_entry=AdapterCatalogEntry(
            adapter_name=ADAPTER_OWNER.adapter_name,
            adapter_version=ADAPTER_OWNER.adapter_version,
            engine=production.current_run().engine,
            executable_path="C:/adapters/alpha/adapter.exe",
            executable_hash=EXECUTABLE_HASH,
            runtime_metadata={},
        ),
        now_utc=production.clock.now_utc(),
    )
    assert reconciliation.verdict is ReconciliationVerdict.DESCRIBED
    command_result = CommandResult(
        invocation=describe,
        parsed_output=parse.envelope,
        parsed_output_source_hash=parse.source_hash,
        protocol_integrity=ProtocolIntegrityStatus.INTACT,
        accepted_events=(),
        diagnostics=(),
        stderr=_capture("describe stderr\n"),
        cancelled=False,
        timed_out=False,
    )
    guarded: Any = _NoRunReads(production.unit_of_work())
    finalizer = CoreArtifactFinalizer(
        guarded.begin,
        production.clock,
        production.hasher,
        production.roots.store,
        RecordingProbe(),
        production.registrar,
        production.auditor,
        command_roots=production.command_roots,
        token_material=production.token_material,
    )
    monkeypatch.setattr(finalization_module, "close_raw_bytes", _forbidden)
    recording = _RecordingFinalizer(finalizer)
    refs = _ok(
        conclude_describe(
            command_result,
            parse,
            reconciliation,
            roots=roots,
            config=_config(production),
            unit_of_work=guarded,
            finalizer=recording,
            clock=production.clock,
        )
    )
    assert recording.received == [("EVIDENCE", MISSING), ("EVIDENCE", MISSING)]
    assert {ref.artifact_kind for ref in refs} == {"adapter-descriptor", STDERR_KIND}
    expected_owner = AdapterArtifactOwner(
        owner_kind="ADAPTER",
        adapter_name=ADAPTER_OWNER.adapter_name,
        adapter_version=ADAPTER_OWNER.adapter_version,
        engine_name=_ENGINE_NAME,
        engine_version=_ENGINE_VERSION,
    )
    assert all(ref.owner == expected_owner for ref in refs)
    journal = production.harness.committed_journal()
    assert len(journal) == 2
    assert all(entry.finalization_purpose is _F.EVIDENCE for entry in journal)
    assert all(entry.owner == expected_owner for entry in journal)
    assert all(
        entry.correlation is not None
        and entry.correlation.kind == "INVOCATION"
        and entry.correlation.correlation_id == OTHER_INVOCATION_ID
        for entry in journal
    )
    (stored,) = [
        item
        for item in production.harness.lifecycle().committed_command_invocations()
        if item.invocation_id == OTHER_INVOCATION_ID
    ]
    (stderr_ref,) = [ref for ref in refs if ref.artifact_kind == STDERR_KIND]
    assert stored.stderr_artifact_id == stderr_ref.artifact_id
    assert request_path.is_file()
    assert output_path.is_file()
    assert production.durable().run_manifests == ()
    _assert_consistent(production)


# --------------------------------------------------------------------------
# Step 0: observation; the close rules; replay; registration order; 29.3
# --------------------------------------------------------------------------


def test_observe_candidates_streams_and_scans(production: FinalizationFixture) -> None:
    """Plan 4.4 step 0: every declared path is confined, then streamed in fixed
    chunks for its digest and the exact-byte token scan; a leaking file is
    observed as such, a never-written file is not observed, and an escaping
    path is refused before any open."""
    plan = _plan(production)
    assert isinstance(plan.roots.work_dir, Path)
    work_dir = plan.roots.work_dir
    chunks: list[int] = []
    hasher = StreamingContentHasher(chunk_size=16, on_chunk=chunks.append)
    observed = _ok(
        observe_candidates(
            work_dir,
            declared_candidate_paths(plan.summary, plan.parse),
            _token(production),
            hasher=hasher,
            clock=production.clock,
        )
    )
    assert [item.relative_path for item in observed] == list(RESULT_FILES)
    for item in observed:
        data = RESULT_FILES[item.relative_path]
        assert item.observed_sha256 == sha256_bytes(data)
        assert item.observed_size_bytes == len(data)
        assert item.contains_attempt_token is False
    assert max(chunks) <= 16
    assert len(chunks) >= sum(-(-len(data) // 16) for data in RESULT_FILES.values())
    leaking = work_dir / "results" / "leak.bin"
    leaking.write_bytes(b"prefix " + FIXTURE_TOKEN.encode("utf-8") + b" suffix\n")
    (leak,) = _ok(
        observe_candidates(
            work_dir,
            ("results/leak.bin",),
            _token(production),
            hasher=production.hasher,
            clock=production.clock,
        )
    )
    assert leak.contains_attempt_token is True
    unwritten = _ok(
        observe_candidates(
            work_dir,
            ("results/missing.bin",),
            _token(production),
            hasher=production.hasher,
            clock=production.clock,
        )
    )
    assert unwritten == ()
    escaping = observe_candidates(
        work_dir,
        ("../escape.bin",),
        _token(production),
        hasher=production.hasher,
        clock=production.clock,
    )
    assert _code(escaping) == ARTIFACT_PATH_BOUNDARY_VIOLATION


def test_observe_candidates_refuses_junction_before_open(
    production: FinalizationFixture, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Plan 4.4 step 0: a junction at a declared path is
    ``ARTIFACT.PATH_BOUNDARY_VIOLATION`` and is never opened; the refusal arises
    before any request exists, ``fail_run_for_refusal`` moves the run
    ``RUNNING -> FAILED`` under it, audits ``RUN_FAILED`` and closes the root,
    and the invocation's stderr evidence is still staged and finalized."""
    plan = _plan(production)
    assert isinstance(plan.roots.work_dir, Path)
    work_dir = plan.roots.work_dir
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    for relative, data in RESULT_FILES.items():
        (elsewhere / Path(relative).name).write_bytes(data)
    shutil.rmtree(work_dir / "results")
    _winapi.CreateJunction(str(elsewhere), str(work_dir / "results"))
    try:
        monkeypatch.setattr(finalization_module, "scan_confined", _forbidden)
        refusal = observe_candidates(
            work_dir,
            declared_candidate_paths(plan.summary, plan.parse),
            _token(production),
            hasher=production.hasher,
            clock=production.clock,
        )
        assert _code(refusal) == ARTIFACT_PATH_BOUNDARY_VIOLATION
        assert isinstance(refusal, Failure)
        _ok(
            fail_run_for_refusal(
                refusal,
                run_id=RUN_ID,
                expected_run_revision=plan.run.revision,
                roots=plan.roots,
                config=_config(production),
                unit_of_work=production.unit_of_work(),
                clock=production.clock,
            )
        )
    finally:
        os.rmdir(work_dir / "results")
    after = production.durable()
    assert after.run_state == "FAILED"
    assert after.run is not None
    primary = after.run.primary_terminal_diagnostic_id
    assert any(
        item.diagnostic_id == primary
        and item.error_code == ARTIFACT_PATH_BOUNDARY_VIOLATION
        for item in after.diagnostics
    )
    assert "RUN_FAILED" in after.audit_actions
    assert not plan.roots.request_path.exists()
    assert isinstance(plan.roots.result_path, Path)
    assert not plan.roots.result_path.exists()
    monkeypatch.undo()
    stderr = _stage_stderr(production)
    registered = _ok(
        finalize_evidence(
            (stderr,), INVOCATION_CORRELATION, finalizer=production.finalizer()
        )
    )
    assert registered.journal_state == "REGISTERED"
    assert production.durable().run_state == "FAILED"
    _assert_consistent(production)


def test_conclude_command_uses_the_step_zero_observations(
    production: FinalizationFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Plan 4.4: the observations the request carried are the ones the verdict
    judged; ``conclude_command`` never re-observes or re-scans the work
    directory itself (the finalizer's phase 1 re-hashes under its own
    confinement)."""
    plan = _plan(production)
    observations = _observe(production, plan)
    reconciliation = _reconcile(production, plan, observations)
    assert reconciliation.verdict is ReconciliationVerdict.RESULT_FINALIZATION_ELIGIBLE
    monkeypatch.setattr(finalization_module, "observe_candidates", _forbidden)
    monkeypatch.setattr(finalization_module, "scan_confined", _forbidden)
    conclusion = _ok(
        conclude_command(
            SemanticOutcome(
                invocation=plan.invocation, run=plan.run, reconciliation=reconciliation
            ),
            _command_result(plan, events=False),
            plan.parse,
            plan.summary,
            observations,
            roots=plan.roots,
            token=_token(production),
            config=_config(production),
            unit_of_work=production.unit_of_work(),
            finalizer=production.finalizer(),
            clock=production.clock,
        )
    )
    assert conclusion.run.state is EngineRunState.SUCCEEDED
    assert isinstance(conclusion.run_manifest, RunManifest)
    assert {ref.content_hash for ref in conclusion.result_refs} == {
        item.observed_sha256 for item in observations
    }


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


def test_conclude_command_closes_raw_bytes_without_a_lease(
    production: FinalizationFixture, tmp_path: Path
) -> None:
    """Plan 4.4 step 5: a terminal run that took no RESULT lease leaves no
    ``request.json`` or ``adapter-result-manifest.json`` under its root -- the
    Stage 6 ``FAILED`` verdict (RC-14, a held file quarantined and audited), the
    step-3 ``RUNNING -> FAILED`` refusal and a lease refused against a
    ``CANCELLED`` run; a ``PERSISTENCE.CONCURRENCY_CONFLICT`` and a
    ``VALIDATE -> READY`` conclusion leave them in place."""
    # (a) RC-14: the Stage 6 verdict failed the run first.
    plan = _plan(production)
    failed_run = production.fail_run_by_verdict()
    wrong = tuple(
        item.model_copy(update={"observed_sha256": "0" * 64})
        for item in _observe(production, plan)
    )
    outcome = SemanticOutcome(
        invocation=plan.invocation,
        run=failed_run,
        reconciliation=_reconcile(production, plan, wrong),
    )
    assert isinstance(plan.roots.result_path, Path)
    handle = _hold_open_without_sharing(plan.roots.result_path)
    try:
        concluded = _ok(
            _conclude(
                production, plan, outcome=outcome, observations=wrong, events=False
            )
        )
    finally:
        _winapi.CloseHandle(handle)
    assert concluded.run.state is EngineRunState.FAILED
    assert not plan.roots.request_path.exists()
    after = production.durable()
    # The close is audited under the invocation correlation: the removal and
    # the quarantine of the held manifest (its handle refused the removal).
    close_events = [
        event for event in after.audit_events if event.correlation_id == INVOCATION_ID
    ]
    assert [event.action.value for event in close_events] == [
        "RETENTION_DELETED",
        "ARTIFACT_QUARANTINED",
    ]
    assert close_events[0].details["removed"] == 1
    assert close_events[0].details["missing"] == 0
    # (b) the step-3 refusal: the finalizer refuses a corrupted candidate.
    with _fresh(tmp_path, "b") as other:
        corrupt = _plan(other)
        reconciliation = _reconcile(other, corrupt)
        assert isinstance(corrupt.roots.work_dir, Path)
        corrupt.roots.work_dir.joinpath("results", "native.bin").write_bytes(
            b"changed after the verdict\n"
        )
        concluded = _ok(
            _conclude(
                other,
                corrupt,
                outcome=SemanticOutcome(
                    invocation=corrupt.invocation,
                    run=corrupt.run,
                    reconciliation=reconciliation,
                ),
                events=False,
            )
        )
        assert concluded.run.state is EngineRunState.FAILED
        assert not isinstance(concluded.finalization, FinalizationResult)
        state = other.durable()
        assert "RUN_FAILED" in state.audit_actions
        assert state.run is not None
        assert any(
            item.diagnostic_id == state.run.primary_terminal_diagnostic_id
            and item.error_code == ARTIFACT_VALIDATION_FAILED
            for item in state.diagnostics
        )
        assert not corrupt.roots.request_path.exists()
        assert isinstance(corrupt.roots.result_path, Path)
        assert not corrupt.roots.result_path.exists()
        _assert_consistent(other)
    # (c) a lease refused against a run cancelled meanwhile closes the root.
    with _fresh(tmp_path, "c") as other:
        late = _plan(other)
        reconciliation = _reconcile(other, late)
        cancelled = other.cancel_run()
        refused = _conclude(
            other,
            late,
            outcome=SemanticOutcome(
                invocation=late.invocation, run=late.run, reconciliation=reconciliation
            ),
            events=False,
        )
        assert _code(refused) == INVARIANT_VIOLATION
        assert "not RUNNING" in _message(refused)
        assert not late.roots.request_path.exists()
        state = other.durable()
        assert state.run_state == "CANCELLED"
        assert state.run_revision == cancelled.revision
        assert state.audit_actions.count("RETENTION_DELETED") == 1
    # (d) a conflict leaves the raw bytes in place.
    with _fresh(tmp_path, "d") as other:
        stale_plan = _plan(other)
        reconciliation = _reconcile(other, stale_plan)
        stale_run = stale_plan.run.model_copy(
            update={"revision": stale_plan.run.revision + 7}
        )
        conflict = _conclude(
            other,
            stale_plan,
            outcome=SemanticOutcome(
                invocation=stale_plan.invocation,
                run=stale_run,
                reconciliation=reconciliation,
            ),
            events=False,
        )
        assert _code(conflict) == CONCURRENCY_CONFLICT
        assert stale_plan.roots.request_path.is_file()
        assert isinstance(stale_plan.roots.result_path, Path)
        assert stale_plan.roots.result_path.is_file()
        assert other.durable().run_state == "RUNNING"
    # (e) a VALIDATE -> READY conclusion is not terminal: nothing closes.
    with _fresh(tmp_path, "e") as other:
        prestate = other.plant_run(run_state=EngineRunState.READY)
        validate = sample_invocation(
            CommandInvocationState.EXITED,
            kind=CommandKind.VALIDATE,
            invocation_id=OTHER_INVOCATION_ID,
        )
        put_invocation(other.harness.lifecycle(), validate)
        root = other.roots.runtime_root / OTHER_INVOCATION_ID
        root.mkdir()
        (root / "request.json").write_bytes(b'{"command": "validate"}')
        (root / "output.json").write_bytes(b'{"outcome": "READY"}')
        roots = CommandRootPaths(
            command_root=root,
            request_path=root / "request.json",
            output_path=root / "output.json",
        )
        validated = SemanticReconciliation.model_validate(
            {
                "command_kind": CommandKind.VALIDATE,
                "verdict": ReconciliationVerdict.VALIDATED_READY,
                "run_target_state": EngineRunState.READY,
                "diagnostics": (),
            }
        )
        ready = _ok(
            conclude_command(
                SemanticOutcome(
                    invocation=validate, run=prestate.run, reconciliation=validated
                ),
                CommandResult(
                    invocation=validate,
                    protocol_integrity=ProtocolIntegrityStatus.INTACT,
                    accepted_events=(),
                    diagnostics=(),
                    stderr=_capture("validate stderr\n"),
                    cancelled=False,
                    timed_out=False,
                ),
                MISSING,
                _EMPTY_SUMMARY,
                (),
                roots=roots,
                token=MISSING,
                config=_config(other),
                unit_of_work=other.unit_of_work(),
                finalizer=other.finalizer(),
                clock=other.clock,
            )
        )
        assert ready.run.state is EngineRunState.READY
        assert (root / "request.json").is_file()
        assert (root / "output.json").is_file()
        assert len(ready.evidence_refs) == 1
        assert other.durable().candidates != ()


def test_post_success_replay_returns_stored_conclusion(
    production: FinalizationFixture, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reading 24: a run already in a success state answers with its stored
    conclusion and the Stage 6 operation is not invoked; any other run goes
    through ``apply_command_semantic_outcome`` unchanged."""
    plan = _plan(production)
    observations = _observe(production, plan)
    conclusion = _ok(
        _conclude(production, plan, observations=observations, events=False)
    )
    request = SemanticOutcomeRequest(
        schema_version="1.0.0",
        invocation_id=INVOCATION_ID,
        expected_invocation_revision=plan.invocation.revision,
        run_id=RUN_ID,
        expected_run_revision=conclusion.run.revision,
        parsed_output=plan.parse,
        protocol_summary=plan.summary,
        candidate_observations=observations,
        negotiated_versions=DEFAULT_NEGOTIATED_VERSIONS,
    )
    monkeypatch.setattr(
        finalization_module, "apply_command_semantic_outcome", _forbidden
    )
    replay = _ok(
        semantic_outcome_or_replay(
            request, unit_of_work=production.unit_of_work(), clock=production.clock
        )
    )
    assert isinstance(replay, CommandConclusion)
    assert replay.replayed is True
    assert replay.run == conclusion.run
    assert replay.run_manifest == conclusion.run_manifest
    assert {ref.artifact_id for ref in replay.result_refs} == {
        ref.artifact_id for ref in conclusion.result_refs
    }
    # The stored conclusion restates the registered evidence: here the sanitized
    # manifest alone (no events, no stderr were handed in).
    assert {ref.artifact_id for ref in replay.evidence_refs} == {
        ref.artifact_id for ref in conclusion.evidence_refs
    }
    assert [ref.artifact_kind for ref in replay.evidence_refs] == [
        SANITIZED_MANIFEST_KIND
    ]
    sentinel = artifact_failure(
        ARTIFACT_VALIDATION_FAILED,
        message="the Stage 6 operation was invoked",
        now_utc=production.clock.now_utc(),
    )
    with _fresh(tmp_path, "r") as other:
        running = _plan(other)
        monkeypatch.setattr(
            finalization_module,
            "apply_command_semantic_outcome",
            lambda *args, **kwargs: sentinel,
        )
        delegated = semantic_outcome_or_replay(
            request.model_copy(update={"expected_run_revision": running.run.revision}),
            unit_of_work=other.unit_of_work(),
            clock=other.clock,
        )
        assert delegated is sentinel


def test_register_result_candidates_after_exited_only(
    production: FinalizationFixture, tmp_path: Path
) -> None:
    """Plan 4.4 step 2: candidates are registered only after the invocation is
    durably ``EXITED``; a terminal invocation that is not ``EXITED`` concludes
    with the invariant and registers nothing."""
    production.plant_run(invocation_state=CommandInvocationState.CANCELLED)
    plan = _plan(production, plant_candidates=False)
    cancelled = production.cancel_run()
    refused = conclude_command(
        SemanticOutcome(
            invocation=plan.invocation,
            run=cancelled,
            superseded_by=EngineRunState.CANCELLED,
        ),
        CommandResult(
            invocation=plan.invocation,
            protocol_integrity=ProtocolIntegrityStatus.INTACT,
            accepted_events=plan.events,
            diagnostics=(),
            cancelled=True,
            timed_out=False,
        ),
        MISSING,
        plan.summary,
        (),
        roots=plan.roots,
        token=_token(production),
        config=_config(production),
        unit_of_work=production.unit_of_work(),
        finalizer=production.finalizer(),
        clock=production.clock,
    )
    assert _code(refused) == INVARIANT_VIOLATION
    assert "not EXITED" in _message(refused)
    after = production.durable()
    assert after.candidates == ()
    assert after.journal == ()
    assert after.staging_files == ()
    with _fresh(tmp_path, "x") as other:
        exited = _plan(other, plant_candidates=False)
        concluded = _ok(_conclude(other, exited, events=False))
        assert concluded.run.state is EngineRunState.SUCCEEDED
        registered = [
            item
            for item in other.durable().candidates
            if item.finalization_purpose is _F.RESULT
        ]
        assert {item.candidate_artifact_id for item in registered} == {
            item.candidate_artifact_id for item in exited.candidates
        }
        assert all(item.producer_kind is _P.ADAPTER for item in registered)


def test_recovery_validator_rejects_each_29_3_failure(
    production: FinalizationFixture, tmp_path: Path
) -> None:
    """29.3 over the production validator: every check refuses with its own
    code and the happy path yields the facts the request derives from."""
    plan = _plan(production)
    validator = production.validator
    token = _token(production)
    happy = _ok(
        validator.validate_temporary_manifest(plan.roots, token, plan.candidates)
    )
    assert happy.sanitized_adapter_result_manifest_hash == (
        plan.sanitized.sanitized_adapter_result_manifest_hash
    )
    assert happy.source_adapter_result_manifest_hash == plan.parse.source_hash
    assert happy.semantic_status == "SUCCEEDED"
    assert happy.finalization_timeout_seconds == RESULT_TIMEOUT_SECONDS
    assert {item.candidate_artifact_id for item in happy.candidate_observations} == {
        item.candidate_artifact_id for item in plan.candidates
    }
    describe_root = production.roots.runtime_root / OTHER_INVOCATION_ID
    describe_root.mkdir()
    (describe_root / "request.json").write_bytes(b"{}")
    (describe_root / "output.json").write_bytes(b"{}")
    not_run = CommandRootPaths(
        command_root=describe_root,
        request_path=describe_root / "request.json",
        output_path=describe_root / "output.json",
    )
    assert (
        _code(validator.validate_temporary_manifest(not_run, token, plan.candidates))
        == INVARIANT_VIOLATION
    )
    empty = validator.validate_temporary_manifest(plan.roots, token, ())
    assert _code(empty) == ARTIFACT_VALIDATION_FAILED
    core = _stage_stderr(production)
    mixed = validator.validate_temporary_manifest(
        plan.roots, token, (*plan.candidates, core)
    )
    assert _code(mixed) == ARTIFACT_VALIDATION_FAILED
    assert "adapter-produced" in _message(mixed)
    for material in (
        MISSING,
        AttemptTokenMaterial(run_id=RUN_ID, attempt_token=_WRONG_TOKEN),
    ):
        identity = validator.validate_temporary_manifest(
            plan.roots, material, plan.candidates
        )
        assert _code(identity) == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    third = result_candidates(files={"results/third.bin": b"undeclared\n"})
    for candidate in third:
        production.harness.put_candidate(candidate)
    extra = validator.validate_temporary_manifest(
        plan.roots, token, (*plan.candidates, *third)
    )
    assert _code(extra) == ARTIFACT_VALIDATION_FAILED
    assert "declarations" in _message(extra)
    with _fresh(tmp_path, "r") as other:
        other.plant_run(invocation_state=CommandInvocationState.RUNNING)
        running = _plan(other)
        refused = other.validator.validate_temporary_manifest(
            running.roots, _token(other), running.candidates
        )
        assert _code(refused) == ARTIFACT_RESULT_MANIFEST_INVALID
        assert "EXITED" in _message(refused)
    with _fresh(tmp_path, "a") as other:
        absent = _plan(other)
        assert isinstance(absent.roots.result_path, Path)
        absent.roots.result_path.unlink()
        refused = other.validator.validate_temporary_manifest(
            absent.roots, _token(other), absent.candidates
        )
        assert _code(refused) == ARTIFACT_RESULT_MANIFEST_INVALID
        assert "absent" in _message(refused)
    with _fresh(tmp_path, "o") as other:
        oversized = _plan(other)
        assert isinstance(oversized.roots.result_path, Path)
        oversized.roots.result_path.write_bytes(
            b"{" + b" " * MAX_RESULT_MANIFEST_BYTES + b"}"
        )
        refused = other.validator.validate_temporary_manifest(
            oversized.roots, _token(other), oversized.candidates
        )
        assert _code(refused) == ARTIFACT_RESULT_MANIFEST_INVALID
        assert "ceiling" in _message(refused)
    with _fresh(tmp_path, "p") as other:
        foreign = _plan(other)
        document = json.loads(foreign.manifest_bytes)
        document["provenance"]["request_hash"] = "f" * 64
        assert isinstance(foreign.roots.result_path, Path)
        foreign.roots.result_path.write_bytes(json.dumps(document).encode("utf-8"))
        refused = other.validator.validate_temporary_manifest(
            foreign.roots, _token(other), foreign.candidates
        )
        assert _code(refused) == ARTIFACT_RESULT_MANIFEST_INVALID
        assert "provenance" in _message(refused)
    with _fresh(tmp_path, "g") as other:
        changed = _plan(other)
        assert isinstance(changed.roots.work_dir, Path)
        changed.roots.work_dir.joinpath("results", "native.bin").write_bytes(
            b"changed while the process was down\n"
        )
        refused = other.validator.validate_temporary_manifest(
            changed.roots, _token(other), changed.candidates
        )
        assert _code(refused) == ARTIFACT_VALIDATION_FAILED
        assert "declared size and hash" in _message(refused)
    with _fresh(tmp_path, "l") as other:
        leaking = _plan(other)
        assert isinstance(leaking.roots.work_dir, Path)
        leaking.roots.work_dir.joinpath("results", "native.bin").write_bytes(
            b"leak " + FIXTURE_TOKEN.encode("utf-8") + b"\n"
        )
        refused = other.validator.validate_temporary_manifest(
            leaking.roots, _token(other), leaking.candidates
        )
        assert _code(refused) == SECURITY_SENSITIVE_MATERIAL_LEAKAGE
        assert FIXTURE_TOKEN not in _message(refused)


# --------------------------------------------------------------------------
# The canonical evidence ruling of 2026-11-09 through the production registrar
# --------------------------------------------------------------------------

#: The same run's owner under its other (planted) invocation: the owner rows
#: are keyed to an existing run and invocation, so a disagreeing owner is a
#: sibling of the fixture's run rather than another run.
_SIBLING_OWNER: Final = RunArtifactOwner(
    owner_kind="RUN",
    experiment_id=EXPERIMENT_ID,
    run_id=RUN_ID,
    invocation_id=OTHER_INVOCATION_ID,
)
_DIGEST_SHAPED: Final = "7" * 64
#: A third invocation identity: the ``DESCRIBE`` invocation of the fixture's
#: adapter that the descriptor cases correlate with.
_DESCRIBE_INVOCATION_ID: Final = "inv_33333333-4444-4555-8666-777777777777"


def _plant_invocation(
    fixture: FinalizationFixture, invocation_id: str, kind: CommandKind
) -> None:
    put_invocation(
        fixture.harness.lifecycle(),
        sample_invocation(
            CommandInvocationState.EXITED, kind=kind, invocation_id=invocation_id
        ),
    )


class _Loose(CanonicalModel):
    """A record whose fields declare no grammar: every string under ``Any`` is
    uncontrolled and a leaf the classifier does not know is refused outright."""

    note: Any
    raw: Any


def _diagnostic_correlation(diagnostic_id: str) -> EvidenceCorrelation:
    return EvidenceCorrelation(kind="DIAGNOSTIC", diagnostic_id=diagnostic_id)


def _record(fixture: FinalizationFixture, *diagnostics: Diagnostic) -> None:
    transaction = fixture.begin()
    try:
        for diagnostic in diagnostics:
            _ok(transaction.diagnostics_writer.record(diagnostic))
        _ok(transaction.commit())
    finally:
        transaction.rollback()


def _validation_result(
    plan: ProductionResultPlan, invocation_id: str = INVOCATION_ID
) -> AdapterValidationResult:
    return _validation_result_of(plan.run.attempt_token_hash, invocation_id)


def _validation_result_of(
    attempt_token_hash: str, invocation_id: str
) -> AdapterValidationResult:
    """A ``VALID`` sanitized validation result of the fixture's run under
    ``invocation_id``, its result hash recomputed."""
    fields: dict[str, Any] = {
        "schema_version": "1.0.0",
        "protocol_version": "1.0.0",
        "request_id": request_id_for(RUN_ID),
        "invocation_id": invocation_id,
        "run_id": RUN_ID,
        "attempt_token_hash": attempt_token_hash,
        "outcome": ValidationOutcome.VALID,
        "diagnostics": (),
        "validated_at_utc": INSTANT,
    }
    draft = AdapterValidationResult.model_construct(**fields, result_hash="0" * 64)
    return AdapterValidationResult.model_validate(
        {**fields, "result_hash": validation_result_hash(draft)}
    )


def _stage(
    fixture: FinalizationFixture,
    owner: Any,
    kind: str,
    leaf: str,
    payload: bytes,
    correlation: EvidenceCorrelation,
    *,
    role: ArtifactSourceRole = _R.CORE_EVIDENCE,
) -> Any:
    return _ok(
        stage_core_evidence(
            owner,
            role,
            kind,
            leaf,
            payload,
            correlation,
            store=fixture.roots.store,
            unit_of_work=fixture.unit_of_work(),
            clock=fixture.clock,
        )
    )


def _finalize(
    fixture: FinalizationFixture,
    candidates: tuple[Any, ...],
    correlation: EvidenceCorrelation = INVOCATION_CORRELATION,
) -> Result[FinalizationResult]:
    return finalize_evidence(candidates, correlation, finalizer=fixture.finalizer())


def _validated_details(fixture: FinalizationFixture) -> list[dict[str, Any]]:
    return [
        dict(event.details)
        for event in fixture.durable().audit_events
        if event.action.value == "ARTIFACT_VALIDATED"
    ]


def test_each_canonical_producer_qualifies_and_registers(
    production: FinalizationFixture,
) -> None:
    """The ruling over every plan 4.6 producer of a run: the protocol capture,
    the sanitized manifest, the validation result, the structured stderr
    fallback and the diagnostic report (``RUN`` and ``SYSTEM`` owned) carry
    digests and identifiers in their controlled fields, qualify against the
    ledger, the rows, the recorded diagnostics and the invocation, and register
    with their validation audited as canonical; the run row is untouched and
    the exact scan is reported only where the run's material was available."""
    plan = _plan(production)
    # The validation-result row belongs to a VALIDATE invocation: the run's
    # sibling invocation, under the run owner naming it.
    _plant_invocation(production, OTHER_INVOCATION_ID, CommandKind.VALIDATE)
    other = EvidenceCorrelation(kind="INVOCATION", invocation_id=OTHER_INVOCATION_ID)
    before = production.durable()
    assert isinstance(production.registrar, CanonicalEvidenceQualifier)
    capture = _ok(
        protocol_capture_evidence(
            plan.events,
            RUN_OWNER,
            INVOCATION_ID,
            store=production.roots.store,
            unit_of_work=production.unit_of_work(),
            clock=production.clock,
        )
    )
    manifest = _ok(
        sanitized_result_manifest_evidence(
            plan.sanitized,
            RUN_OWNER,
            store=production.roots.store,
            unit_of_work=production.unit_of_work(),
            clock=production.clock,
        )
    )
    fallback = _stage_stderr(
        production,
        StderrCapture(
            retained_byte_count=0, truncated=False, source_hash=sha256_bytes(b"")
        ),
    )
    registered = _ok(_finalize(production, (capture, manifest, fallback)))
    assert registered.journal_state == "REGISTERED"
    assert len(registered.candidate_to_artifact_refs) == 3
    result = _ok(
        validation_result_evidence(
            _validation_result(plan, OTHER_INVOCATION_ID),
            _SIBLING_OWNER,
            store=production.roots.store,
            unit_of_work=production.unit_of_work(),
            clock=production.clock,
        )
    )
    registered = _ok(_finalize(production, (result,), other))
    assert registered.journal_state == "REGISTERED"
    diagnostics = (
        sample_diagnostic(
            OTHER_DIAG_ID,
            error_code=ARTIFACT_VALIDATION_FAILED,
            category=DiagnosticCategory.ARTIFACT_CORRUPTION,
            retriable=False,
        ),
        sample_diagnostic(
            DIAG_ID,
            error_code=ARTIFACT_RESULT_MANIFEST_INVALID,
            category=DiagnosticCategory.ARTIFACT_CORRUPTION,
            retriable=False,
            causal_diagnostic_ids=(OTHER_DIAG_ID,),
        ),
    )
    _record(production, *diagnostics)
    for owner in (RUN_OWNER, SYSTEM_OWNER):
        report = _ok(
            diagnostic_report_evidence(
                diagnostics,
                owner,
                DIAG_ID,
                store=production.roots.store,
                unit_of_work=production.unit_of_work(),
                clock=production.clock,
            )
        )
        registered = _ok(
            _finalize(production, (report,), _diagnostic_correlation(DIAG_ID))
        )
        assert registered.journal_state == "REGISTERED"
    # An input snapshot answers no contract (Task 8 exercises the kind): its
    # token-free bytes register under the whole-content rule, not as canonical.
    payload = b'{"rows": 3, "symbol": "BTC-USD"}\n'
    audit_event_id = production.audit_ids.new_audit_event_id()
    snapshot = _ok(
        input_snapshot_evidence(
            EXPERIMENT_OWNER,
            payload,
            sha256_bytes(payload),
            audit_event_id,
            store=production.roots.store,
            unit_of_work=production.unit_of_work(),
            clock=production.clock,
        )
    )
    registered = _ok(
        _finalize(
            production,
            (snapshot,),
            EvidenceCorrelation(kind="AUDIT", audit_event_id=audit_event_id),
        )
    )
    assert registered.journal_state == "REGISTERED"
    after = production.durable()
    assert after.run == before.run
    assert after.run_manifests == ()
    details = _validated_details(production)
    # In finalization order: the three invocation-correlated candidates of the
    # run owner (material available), the sibling's validation result (no root
    # for that invocation), the RUN-owned and the SYSTEM-owned report, and the
    # input snapshot that answers no contract.
    assert [(item["canonical"], item["exact_scan"]) for item in details] == [
        (True, True),
        (True, True),
        (True, True),
        (True, False),
        (True, True),
        (True, False),
        (False, False),
    ]
    assert {ref.artifact_kind for ref in after.refs} == {
        PROTOCOL_CAPTURE_KIND,
        SANITIZED_MANIFEST_KIND,
        VALIDATION_RESULT_KIND,
        STDERR_KIND,
        DIAGNOSTIC_REPORT_KIND,
        INPUT_SNAPSHOT_KINDS["EXPERIMENT"],
    }
    _assert_consistent(production)


def _report(
    fixture: FinalizationFixture,
    diagnostics: tuple[Diagnostic, ...],
    owner: Any,
    primary: str,
) -> Any:
    return _ok(
        diagnostic_report_evidence(
            diagnostics,
            owner,
            primary,
            store=fixture.roots.store,
            unit_of_work=fixture.unit_of_work(),
            clock=fixture.clock,
        )
    )


def _refused(
    fixture: FinalizationFixture,
    candidate: Any,
    correlation: EvidenceCorrelation,
    code: str,
    fragment: str,
) -> None:
    refused = _finalize(fixture, (candidate,), correlation)
    assert _code(refused) == code, _message(refused)
    assert fragment in _message(refused)
    assert _DIGEST_SHAPED not in _message(refused)
    states = fixture.durable().candidate_states
    assert states[candidate.candidate_artifact_id] == "QUARANTINED"


def test_canonical_content_that_disagrees_with_the_facts_is_refused(
    production: FinalizationFixture,
) -> None:
    """Plan 4.6 bytes staged where the facts disagree are ``ARTIFACT.
    VALIDATION_FAILED`` at ``SCHEMA`` and quarantined: a role or owner kind the
    producer never uses, another leaf, another run's owner, a run owner's other
    invocation, a manifest or validation result without its stored row, a
    ledger out of sequence, a describe parse without an envelope or under
    another adapter or a non-describe invocation, a diagnostic report whose
    correlation names no record, whose record belongs to another run, is not
    recorded or differs from the recorded one. Bytes that are not the kind's
    model -- a forged label, a non-canonical serialization, a malformed stderr
    fallback -- keep the whole-content protection; stderr free text that is a
    JSON document registers as plain text; a record whose uncontrolled field
    carries a digest-shaped string is token-shaped material although every
    controlled field is legitimate; a JSON Lines record that is not one strict
    document is refused before the qualifier is asked."""
    plan = _plan(production, sanitized_row=False)
    # The run's sibling VALIDATE invocation (the owner rows are keyed to an
    # existing run and invocation) and the adapter's DESCRIBE invocation the
    # descriptor cases correlate with (the finalizer's own describe check
    # admits an adapter owner's evidence under no other correlation).
    _plant_invocation(production, OTHER_INVOCATION_ID, CommandKind.VALIDATE)
    _plant_invocation(production, _DESCRIBE_INVOCATION_ID, CommandKind.DESCRIBE)
    other = EvidenceCorrelation(kind="INVOCATION", invocation_id=OTHER_INVOCATION_ID)
    describe = EvidenceCorrelation(
        kind="INVOCATION", invocation_id=_DESCRIBE_INVOCATION_ID
    )
    qualifier = production.registrar
    assert isinstance(qualifier, CanonicalEvidenceQualifier)
    manifest_bytes = canonical_json_bytes(plan.sanitized)
    result_bytes = canonical_json_bytes(_validation_result(plan))
    failed = ARTIFACT_VALIDATION_FAILED
    leakage = SECURITY_SENSITIVE_MATERIAL_LEAKAGE
    system_role = _stage(
        production,
        SYSTEM_OWNER,
        SANITIZED_MANIFEST_KIND,
        sanitized_manifest_leaf(),
        manifest_bytes,
        INVOCATION_CORRELATION,
    )
    _refused(production, system_role, INVOCATION_CORRELATION, failed, "owner")
    other_leaf = _stage(
        production,
        RUN_OWNER,
        SANITIZED_MANIFEST_KIND,
        "other-manifest.json",
        manifest_bytes,
        INVOCATION_CORRELATION,
    )
    _refused(production, other_leaf, INVOCATION_CORRELATION, failed, "correlation")
    foreign = _stage(
        production,
        _SIBLING_OWNER,
        SANITIZED_MANIFEST_KIND,
        sanitized_manifest_leaf(),
        manifest_bytes,
        other,
    )
    _refused(production, foreign, other, failed, "owner")
    no_row = _stage(
        production,
        RUN_OWNER,
        SANITIZED_MANIFEST_KIND,
        sanitized_manifest_leaf(),
        manifest_bytes,
        INVOCATION_CORRELATION,
    )
    _refused(production, no_row, INVOCATION_CORRELATION, failed, "stored row")
    foreign_result = _stage(
        production,
        _SIBLING_OWNER,
        VALIDATION_RESULT_KIND,
        "validation-result.json",
        result_bytes,
        other,
    )
    _refused(production, foreign_result, other, failed, "owner")
    no_result_row = _stage(
        production,
        RUN_OWNER,
        VALIDATION_RESULT_KIND,
        "validation-result.json",
        result_bytes,
        INVOCATION_CORRELATION,
    )
    _refused(production, no_result_row, INVOCATION_CORRELATION, failed, "stored row")
    pretty = json.dumps(json.loads(result_bytes), indent=2).encode("utf-8")
    non_canonical = _stage(
        production,
        RUN_OWNER,
        VALIDATION_RESULT_KIND,
        "validation-result.json",
        pretty,
        other,
    )
    _refused(production, non_canonical, other, leakage, "token-shaped")
    misplaced = _stage(
        production,
        RUN_OWNER,
        PROTOCOL_CAPTURE_KIND,
        "protocol-capture.jsonl",
        canonical_json_bytes(plan.events[0]) + b"\n",
        other,
    )
    _refused(production, misplaced, other, failed, "correlation")
    reordered = _stage(
        production,
        RUN_OWNER,
        PROTOCOL_CAPTURE_KIND,
        "protocol-capture.jsonl",
        b"".join(canonical_json_bytes(event) + b"\n" for event in plan.events[::-1]),
        INVOCATION_CORRELATION,
    )
    _refused(production, reordered, INVOCATION_CORRELATION, failed, "ledger")
    forged = _stage(
        production,
        _SIBLING_OWNER,
        PROTOCOL_CAPTURE_KIND,
        "protocol-capture.jsonl",
        manifest_bytes + b"\n",
        other,
    )
    _refused(production, forged, other, leakage, "token-shaped")
    parse = parse_bootstrap_descriptor(
        _envelope_bytes(_descriptor()), max_bytes=MAX_DESCRIPTOR_OUTPUT_BYTES
    )
    assert isinstance(parse, DescriptorParse)
    no_envelope = parse_bootstrap_descriptor(
        b"not a descriptor", max_bytes=MAX_DESCRIPTOR_OUTPUT_BYTES
    )
    assert isinstance(no_envelope, DescriptorParse)
    descriptor_role = _R.ADAPTER_DESCRIPTOR_EVIDENCE
    envelope_less = _stage(
        production,
        ADAPTER_OWNER,
        "adapter-descriptor",
        "adapter-descriptor.json",
        canonical_json_bytes(no_envelope),
        describe,
        role=descriptor_role,
    )
    _refused(production, envelope_less, describe, failed, "envelope")
    # The finalizer's phase-0 describe check already refuses an adapter owner
    # under another adapter's or a non-describe invocation; the contract's own
    # refusals for those are asked of the registrar directly.
    beta = AdapterArtifactOwner(
        owner_kind="ADAPTER", adapter_name="adapter.beta", adapter_version="1.2.0"
    )
    other_adapter = _stage(
        production,
        beta,
        "adapter-descriptor",
        "adapter-descriptor.json",
        canonical_json_bytes(parse),
        describe,
        role=descriptor_role,
    )
    verdict = qualifier.qualify_evidence(other_adapter, (canonical_json_bytes(parse),))
    assert _code(verdict) == failed
    assert "owner" in _message(verdict)
    run_invocation = _stage(
        production,
        ADAPTER_OWNER,
        "adapter-descriptor",
        "adapter-descriptor.json",
        canonical_json_bytes(parse),
        INVOCATION_CORRELATION,
        role=descriptor_role,
    )
    verdict = qualifier.qualify_evidence(run_invocation, (canonical_json_bytes(parse),))
    assert _code(verdict) == failed
    assert "invocation" in _message(verdict)
    shaped = sample_diagnostic(THIRD_DIAG_ID).model_copy(
        update={"message": _DIGEST_SHAPED}
    )
    _record(production, shaped)
    report = _report(production, (shaped,), RUN_OWNER, THIRD_DIAG_ID)
    third = _diagnostic_correlation(THIRD_DIAG_ID)
    first = _diagnostic_correlation(DIAG_ID)
    _refused(production, report, third, leakage, "uncontrolled")
    unrelated = _report(production, (shaped,), SYSTEM_OWNER, DIAG_ID)
    _refused(production, unrelated, first, failed, "correlation")
    other_run = sample_diagnostic(DIAG_ID, run_id=OTHER_RUN_ID)
    foreign_report = _report(production, (other_run,), RUN_OWNER, DIAG_ID)
    _refused(production, foreign_report, first, failed, "owner")
    unrecorded_id = "diag_11111111-2222-4333-8444-555555555555"
    unrecorded = _report(
        production, (sample_diagnostic(unrecorded_id),), SYSTEM_OWNER, unrecorded_id
    )
    refused = _finalize(
        production, (unrecorded,), _diagnostic_correlation(unrecorded_id)
    )
    assert _code(refused) == failed
    changed = shaped.model_copy(update={"message": "changed after recording"})
    drifted = _report(production, (changed,), SYSTEM_OWNER, THIRD_DIAG_ID)
    _refused(production, drifted, third, failed, "recorded diagnostics")
    second = _diagnostic_correlation(OTHER_DIAG_ID)
    broken = _stage(
        production,
        RUN_OWNER,
        DIAGNOSTIC_REPORT_KIND,
        "diagnostic-report.jsonl",
        canonical_json_bytes(shaped) + b"\n{broken\n",
        second,
    )
    _refused(production, broken, second, failed, "well-formed")
    fallback = json.dumps(
        {
            "retained_byte_count": 0,
            "source_hash": sha256_bytes(b""),
            "truncated": False,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    misplaced_fallback = _stage(
        production, RUN_OWNER, STDERR_KIND, "stderr.txt", fallback, other
    )
    _refused(production, misplaced_fallback, other, failed, "invocation")
    malformed = json.dumps(
        {"retained_byte_count": -1, "source_hash": "0" * 64, "truncated": False},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    bad_fallback = _stage(
        production, _SIBLING_OWNER, STDERR_KIND, "stderr.txt", malformed, other
    )
    _refused(production, bad_fallback, other, leakage, "token-shaped")
    json_text = _stage_stderr(production, _capture('{"level": "info"}\n'))
    registered = _ok(_finalize(production, (json_text,)))
    assert registered.journal_state == "REGISTERED"
    assert _validated_details(production) == [
        {"purpose": "EVIDENCE", "exact_scan": True, "canonical": False}
    ]
    assert len(production.durable().refs) == 1
    _assert_consistent(production)


def test_conclusion_hands_its_frame_material_to_every_finalization(
    production: FinalizationFixture,
) -> None:
    """The ruling: the material the caller's frame already holds reaches the
    phase-1 scan of the RESULT and the EVIDENCE finalizations of one conclusion
    -- obtained before the terminal close removes ``request.json`` -- so the
    canonical evidence of a success registers beside the result."""
    plan = _plan(production)
    observed = _observe(production, plan)
    outcome = SemanticOutcome(
        invocation=plan.invocation,
        run=plan.run,
        reconciliation=_reconcile(production, plan, observed),
    )
    material = _token(production)
    recording = _RecordingFinalizer(production.finalizer())
    conclusion = _ok(
        conclude_command(
            outcome,
            _command_result(plan, stderr=_capture()),
            plan.parse,
            plan.summary,
            observed,
            roots=plan.roots,
            token=material,
            config=_config(production),
            unit_of_work=production.unit_of_work(),
            finalizer=recording,
            clock=production.clock,
        )
    )
    assert recording.received == [("RESULT", material), ("EVIDENCE", material)]
    assert conclusion.run.state is EngineRunState.SUCCEEDED
    assert not isinstance(conclusion.evidence_failure, Failure)
    assert {ref.artifact_kind for ref in conclusion.evidence_refs} == {
        STDERR_KIND,
        PROTOCOL_CAPTURE_KIND,
        SANITIZED_MANIFEST_KIND,
    }
    assert not plan.roots.request_path.exists()
    details = _validated_details(production)
    assert all(item["exact_scan"] is True for item in details)
    _assert_consistent(production)


def test_uncontrolled_strings_follow_the_declared_types(
    production: FinalizationFixture,
) -> None:
    """The classifier behind the qualifier: a string is controlled only when
    its declared type is a closed identifier or digest grammar, a literal or an
    enumeration; free text, adapter-chosen identifiers, error codes, mapping
    keys and every string under ``Any`` are uncontrolled, the descriptor
    header's echo of a controlled envelope value is controlled by mirroring,
    and a leaf the classifier does not know is refused."""
    plan = _plan(production)
    diagnostic = sample_diagnostic(DIAG_ID).model_copy(
        update={
            "message": _DIGEST_SHAPED,
            "details": {
                "relative_path": "results/native.bin",
                "nested": {"count": 3, "flag": True, "note": "x"},
            },
        }
    )
    strings = uncontrolled_strings_of(diagnostic)
    assert {
        _DIGEST_SHAPED,
        "relative_path",
        "results/native.bin",
        "nested",
        "count",
        "flag",
        "note",
        "x",
        "doubles.experiments",
        "ENGINE.RUNTIME_FAILURE",
    } <= set(strings)
    assert {
        DIAG_ID,
        RUN_ID,
        INVOCATION_ID,
        EXPERIMENT_ID,
        "ERROR",
        "ENGINE_RUNTIME",
        "1.0.0",
    }.isdisjoint(strings)
    for event in plan.events:
        strings = uncontrolled_strings_of(event)
        assert {
            event.event_id,
            event.run_id,
            event.invocation_id,
            event.attempt_token_hash,
            event.wire_event_hash,
            event.content_hash,
        }.isdisjoint(strings)
        payload = event.payload
        if isinstance(payload, ArtifactProducedPayload):
            assert payload.relative_path in strings
            assert payload.artifact_kind in strings
            assert payload.declared_sha256 not in strings
        if isinstance(payload, FinalResultPayload):
            assert payload.manifest_relative_path in strings
            assert payload.source_adapter_result_manifest_hash not in strings
    sanitized = plan.sanitized
    strings = uncontrolled_strings_of(sanitized)
    assert sanitized.sanitized_adapter_result_manifest_hash not in strings
    assert sanitized.source_adapter_result_manifest_hash not in strings
    assert sanitized.provenance.request_hash not in strings
    assert sanitized.adapter_manifest_id not in strings
    assert sanitized.provenance.adapter.adapter_name in strings
    for declaration in sanitized.candidate_declarations:
        assert declaration.artifact_kind in strings
        assert declaration.candidate_artifact_id not in strings
        assert declaration.declared_sha256 not in strings
    parse = parse_bootstrap_descriptor(
        _envelope_bytes(_descriptor()), max_bytes=MAX_DESCRIPTOR_OUTPUT_BYTES
    )
    assert isinstance(parse, DescriptorParse)
    strings = uncontrolled_strings_of(parse)
    assert EXECUTABLE_HASH in strings  # the permissive header echoes it as text
    assert parse.source_hash not in strings
    assert "Offline fake adapter." in strings
    mirrored = uncontrolled_strings_of(parse, mirrored=frozenset({EXECUTABLE_HASH}))
    assert EXECUTABLE_HASH not in mirrored
    assert "Offline fake adapter." in mirrored
    assert "free" in uncontrolled_strings_of(_Loose(note="free", raw=1))
    with pytest.raises(TypeError, match="unsupported"):
        uncontrolled_strings_of(_Loose(note="free", raw=b"bytes"))


# --------------------------------------------------------------------------
# The contract boundaries the Task 7 coverage report left unexercised
# --------------------------------------------------------------------------

#: A later attempt's run-command invocation (``plant_attempt``): the invocation
#: of another run a crossed owner can name.
_ATTEMPT_INVOCATION_ID: Final = "inv_44444444-5555-4666-8777-888888888888"
_AUDIT_REFUSED: Final = "TEST.AUDIT_REFUSED"
_STDERR_LEAF: Final = "stderr.txt"


@dataclass(frozen=True, slots=True, kw_only=True)
class _SanitizedRow:
    """A ``sanitized_adapter_result_manifests`` row planted through its port."""

    sanitized_adapter_result_manifest_hash: str
    run_id: str
    run_invocation_id: str
    experiment_id: str
    attempt_token_hash: str
    source_adapter_result_manifest_hash: str
    semantic_status: str
    manifest_json: str
    evidence_artifact_id: Any
    recorded_at_utc: datetime


@dataclass(frozen=True, slots=True, kw_only=True)
class _ValidationRow:
    """An ``adapter_validation_results`` row planted through its port."""

    invocation_id: str
    run_id: str
    experiment_id: str
    validation_result_hash: str
    outcome: str
    result_json: str
    evidence_artifact_id: Any
    recorded_at_utc: datetime


def _audit_refusal(fixture: FinalizationFixture) -> Failure:
    """The injected audit-side fault: a diagnostic under a test-only code."""
    return Failure(
        outcome="FAILURE",
        diagnostics=(
            sample_diagnostic(
                THIRD_DIAG_ID,
                error_code=_AUDIT_REFUSED,
                category=DiagnosticCategory.ARTIFACT_CORRUPTION,
                retriable=False,
                timestamp_utc=fixture.clock.now_utc(),
            ),
        ),
    )


def _config_with(fixture: FinalizationFixture, auditor: Any) -> ConclusionConfig:
    registrar = fixture.registrar
    assert isinstance(registrar, ResultRegistrar)
    return ConclusionConfig(
        store=fixture.roots.store,
        hasher=fixture.hasher,
        auditor=auditor,
        finalization_timeout_seconds=RESULT_TIMEOUT_SECONDS,
        registrar=registrar,
    )


def _fallback_bytes() -> bytes:
    """Plan 4.6's structured stderr record of an empty capture, canonical."""
    return json.dumps(
        {
            "retained_byte_count": 0,
            "source_hash": sha256_bytes(b""),
            "truncated": False,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _core_stderr_id(owner: Any, invocation_id: str) -> str:
    return core_candidate_artifact_id_for(
        artifact_owner_hash(owner), "INVOCATION", invocation_id, _STDERR_LEAF
    )


def _assert_result_rolled_back(
    fixture: FinalizationFixture,
    plan: ProductionResultPlan,
    refused: object,
    code: str,
    fragment: str | None,
) -> None:
    """The T3 rollback of a refused RESULT registration: the run still
    ``RUNNING`` with the T1 deadline snapshot as its one committed write, no
    manifest, reference, link or success fact, the journal ``ABANDONED`` under
    the refusal's code and every requested candidate quarantined."""
    assert _code(refused) == code, _message(refused)
    if fragment is not None:
        assert fragment in _message(refused)
    after = fixture.durable()
    assert after.run_state == "RUNNING"
    assert after.run_revision == plan.run.revision + 1
    assert after.run_manifests == ()
    assert after.refs == ()
    assert after.run_artifacts == ()
    assert after.journal_state == "ABANDONED"
    assert after.abandon_reason == code
    assert "RUN_MANIFEST_REGISTERED" not in after.audit_actions
    assert "RUN_SUCCEEDED" not in after.audit_actions
    (entry,) = after.journal
    states = after.candidate_states
    assert all(states[item] == "QUARANTINED" for item in entry.candidate_artifact_ids)
    _assert_consistent(fixture)


def test_registrar_refusals_roll_back_the_result_transaction(
    production: FinalizationFixture, tmp_path: Path
) -> None:
    """Plan 4.4 under the finalizer's failure column: a RESULT registration the
    production registrar refuses inside T3 -- no sanitized manifest stored or
    remembered, a request whose source hash or candidate set disagrees with the
    sanitized manifest, the evidence-only registrar, a refused ``RUN_SUCCEEDED``
    fact -- is rolled back whole: the run stays ``RUNNING`` at its revision, no
    manifest, reference, member link or success fact is committed, the journal
    is ``ABANDONED`` under the refusal's code and the candidates quarantined."""
    unrecorded = _plan(production, sanitized_row=False)
    _assert_result_rolled_back(
        production,
        unrecorded,
        production.finalize_result(unrecorded),
        INVARIANT_VIOLATION,
        "no sanitized manifest",
    )
    with _fresh(tmp_path, "s") as other:
        plan = _plan(other)
        drifted = sample_result_request(
            [item.candidate_artifact_id for item in plan.candidates],
            run=plan.run,
            invocation=plan.invocation,
            source_hash="f" * 64,
            sanitized_hash=plan.sanitized.sanitized_adapter_result_manifest_hash,
        )
        _assert_result_rolled_back(
            other,
            plan,
            other.finalize(drifted),
            INVARIANT_VIOLATION,
            "source_adapter_result_manifest_hash",
        )
    with _fresh(tmp_path, "h") as other:
        plan = _plan(other)
        first, second = plan.candidates
        partial = sample_result_request(
            [first.candidate_artifact_id],
            run=plan.run,
            invocation=plan.invocation,
            source_hash=plan.parse.source_hash,
            sanitized_hash=plan.sanitized.sanitized_adapter_result_manifest_hash,
        )
        _assert_result_rolled_back(
            other, plan, other.finalize(partial), INVARIANT_VIOLATION, "candidates"
        )
        states = other.durable().candidate_states
        assert states[second.candidate_artifact_id] == "CANDIDATE"
    with _fresh(tmp_path, "v") as other:
        plan = _plan(other)
        evidence_only = EvidenceRegistrar(
            other.auditor, other.clock, transactions=other.begin
        )
        _assert_result_rolled_back(
            other,
            plan,
            other.finalize(plan.request, registrar=evidence_only),
            INVARIANT_VIOLATION,
            "registers no RESULT",
        )
    with _fresh(tmp_path, "u") as other:
        plan = _plan(other)
        refusing = RefusingAuditor(
            other.audit_ids,
            other.clock,
            refused_action="RUN_SUCCEEDED",
            failure=_audit_refusal(other),
        )
        registrar = ResultRegistrar(refusing, other.clock, transactions=other.begin)
        _assert_result_rolled_back(
            other,
            plan,
            other.finalize(plan.request, registrar=registrar),
            _AUDIT_REFUSED,
            "fixture diagnostic",
        )
        # The registrar reached its last fact: the manifest fact it appended
        # before the refusal was rolled back with the run swap it followed.
        assert [fact.action for fact in refusing.facts] == ["RUN_MANIFEST_REGISTERED"]
        assert refusing.refusals == 1


def test_refused_row_writes_leave_no_partial_registration(
    production: FinalizationFixture, tmp_path: Path
) -> None:
    """A row the database refuses mid-transaction (a test-only trigger on one
    Stage 9 table) is the classified ``CORE.INVARIANT_VIOLATION`` and nothing of
    that transaction survives: the run-manifest insert refused inside the
    conclusion's T3 abandons the RESULT finalization, the abandoned journal's
    own phase-6 close removes the root's raw bytes and the conclusion then
    fails the run under the invariant (21.2.1) while its valid sanitized-manifest
    evidence still registers; the member link refused inside a direct
    finalization leaves the run ``RUNNING`` for its caller; the second candidate
    insert of step 2 registers neither candidate; the sanitized and
    validation-result rows stage no evidence; a refused core candidate row
    leaves the staged bytes for the retry that writes the row."""
    plan = _plan(production)
    production.harness.install_refusing_trigger(
        "run_manifests", f"NEW.run_id = '{RUN_ID}'"
    )
    concluded = _ok(_conclude(production, plan, events=False))
    _assert_run_failed_after_abandonment(
        production, plan, concluded, None, from_state="MOVED"
    )
    assert not isinstance(concluded.evidence_failure, Failure)
    assert [ref.artifact_kind for ref in concluded.evidence_refs] == [
        SANITIZED_MANIFEST_KIND
    ]
    assert production.harness.count("run_manifests") == 0
    with _fresh(tmp_path, "k") as other:
        plan = _plan(other)
        other.harness.install_refusing_trigger(
            "run_artifacts", f"NEW.run_id = '{RUN_ID}'"
        )
        _assert_result_rolled_back(
            other, plan, other.finalize_result(plan), INVARIANT_VIOLATION, None
        )
    with _fresh(tmp_path, "n") as other:
        plan = _plan(other, plant_candidates=False)
        last = plan.summary.artifact_declarations[-1].payload.relative_path
        last_id = candidate_artifact_id_for(RUN_ID, INVOCATION_ID, last)
        other.harness.install_refusing_trigger(
            "candidate_artifacts", f"NEW.candidate_artifact_id = '{last_id}'"
        )
        registration = register_result_candidates(
            plan.summary.artifact_declarations,
            RUN_OWNER,
            unit_of_work=other.unit_of_work(),
            clock=other.clock,
        )
        assert _code(registration) == INVARIANT_VIOLATION
        assert other.durable().candidates == ()
    with _fresh(tmp_path, "w") as other:
        plan = _plan(other, sanitized_row=False)
        before = other.durable()
        other.harness.install_refusing_trigger(
            "sanitized_adapter_result_manifests", f"NEW.run_id = '{RUN_ID}'"
        )
        manifest_row = sanitized_result_manifest_evidence(
            plan.sanitized,
            RUN_OWNER,
            store=other.roots.store,
            unit_of_work=other.unit_of_work(),
            clock=other.clock,
        )
        assert _code(manifest_row) == INVARIANT_VIOLATION
        assert other.harness.count("sanitized_adapter_result_manifests") == 0
        after = other.durable()
        assert after.staging_files == before.staging_files
        assert after.candidates == before.candidates
    with _fresh(tmp_path, "y") as other:
        plan = _plan(other)
        before = other.durable()
        other.harness.install_refusing_trigger(
            "adapter_validation_results", f"NEW.run_id = '{RUN_ID}'"
        )
        result_row = validation_result_evidence(
            _validation_result(plan),
            RUN_OWNER,
            store=other.roots.store,
            unit_of_work=other.unit_of_work(),
            clock=other.clock,
        )
        assert _code(result_row) == INVARIANT_VIOLATION
        assert other.harness.count("adapter_validation_results") == 0
        assert other.durable().staging_files == before.staging_files
    with _fresh(tmp_path, "z") as other:
        other.plant_run()
        core_id = _core_stderr_id(RUN_OWNER, INVOCATION_ID)
        other.harness.install_refusing_trigger(
            "candidate_artifacts", f"NEW.candidate_artifact_id = '{core_id}'"
        )
        core_row = stderr_evidence(
            _capture(),
            RUN_OWNER,
            INVOCATION_ID,
            store=other.roots.store,
            unit_of_work=other.unit_of_work(),
            auditor=other.auditor,
            clock=other.clock,
        )
        assert _code(core_row) == INVARIANT_VIOLATION
        after = other.durable()
        assert core_id not in after.candidate_states
        assert after.refs == ()
        run_hash = artifact_owner_hash(RUN_OWNER)
        assert (
            f"{run_hash}/INVOCATION/{INVOCATION_ID}/stderr.txt" in after.staging_files
        )


def test_refused_audit_appends_roll_back_their_transactions(
    production: FinalizationFixture,
) -> None:
    """The audit-side fault of each short transaction: a refused ``RUN_FAILED``
    fact leaves the run ``RUNNING`` with the refusal's diagnostic unrecorded and
    the raw bytes in place; a refused ``STDERR_TRUNCATED`` fact leaves the
    truncation diagnostic unrecorded while the staged capture, committed by its
    own earlier transaction, stands."""
    plan = _plan(production)
    refusing = RefusingAuditor(
        production.audit_ids,
        production.clock,
        refused_action="RUN_FAILED",
        failure=_audit_refusal(production),
    )
    refusal = artifact_failure(
        ARTIFACT_RESULT_MANIFEST_INVALID,
        message="the temporary result manifest does not validate",
        now_utc=production.clock.now_utc(),
        experiment_id=EXPERIMENT_ID,
        run_id=RUN_ID,
        invocation_id=INVOCATION_ID,
    )
    refused = fail_run_for_refusal(
        refusal,
        run_id=RUN_ID,
        expected_run_revision=plan.run.revision,
        roots=plan.roots,
        config=_config_with(production, refusing),
        unit_of_work=production.unit_of_work(),
        clock=production.clock,
    )
    assert _code(refused) == _AUDIT_REFUSED
    assert refusing.refusals == 1
    after = production.durable()
    assert after.run_state == "RUNNING"
    assert after.run_revision == plan.run.revision
    assert refusal.diagnostics[0].diagnostic_id not in {
        item.diagnostic_id for item in after.diagnostics
    }
    assert after.audit_actions == ()
    assert plan.roots.request_path.is_file()
    assert isinstance(plan.roots.result_path, Path)
    assert plan.roots.result_path.is_file()
    truncating = RefusingAuditor(
        production.audit_ids,
        production.clock,
        refused_action="STDERR_TRUNCATED",
        failure=_audit_refusal(production),
    )
    staged = stderr_evidence(
        _capture("partial engine stderr\n", truncated=True),
        RUN_OWNER,
        INVOCATION_ID,
        store=production.roots.store,
        unit_of_work=production.unit_of_work(),
        auditor=truncating,
        clock=production.clock,
    )
    assert _code(staged) == _AUDIT_REFUSED
    later = production.durable()
    assert PROCESS_STDERR_TRUNCATED not in later.diagnostic_codes
    assert "STDERR_TRUNCATED" not in later.audit_actions
    assert later.candidate_states[_core_stderr_id(RUN_OWNER, INVOCATION_ID)] == (
        "CANDIDATE"
    )
    _assert_consistent(production)


def test_stored_rows_and_ledger_are_the_facts_for_canonical_content(
    production: FinalizationFixture,
) -> None:
    """The ruling's fact checks compare text with text and record with record:
    a sanitized manifest or validation result whose stored row holds other text
    than the staged bytes is refused at its stored row; a protocol capture whose
    second record is a well-formed event of the right run and invocation that
    the ledger does not hold is refused at the ledger (every record is checked,
    not the first alone); a stderr fallback whose invocation belongs to another
    run is refused at the invocation; a stderr capture that is a JSON array or
    a non-canonical fallback document is not the producer's record and keeps
    the whole-content protection."""
    plan = _plan(production, sanitized_row=False)
    _plant_invocation(production, OTHER_INVOCATION_ID, CommandKind.VALIDATE)
    other = EvidenceCorrelation(kind="INVOCATION", invocation_id=OTHER_INVOCATION_ID)
    failed = ARTIFACT_VALIDATION_FAILED
    manifest_text = canonical_json_text(plan.sanitized)
    assert "engine.alpha" in manifest_text
    # The validation-result row belongs to a VALIDATE invocation (the schema's
    # own trigger): the run's sibling invocation, under the owner naming it.
    result = _validation_result(plan, OTHER_INVOCATION_ID)
    result_text = canonical_json_text(result)
    assert result_text.count('"VALID"') == 1
    transaction = production.begin()
    try:
        _ok(
            transaction.sanitized_manifests.add(
                _SanitizedRow(
                    sanitized_adapter_result_manifest_hash=(
                        plan.sanitized.sanitized_adapter_result_manifest_hash
                    ),
                    run_id=RUN_ID,
                    run_invocation_id=INVOCATION_ID,
                    experiment_id=EXPERIMENT_ID,
                    attempt_token_hash=plan.sanitized.attempt_token_hash,
                    source_adapter_result_manifest_hash=plan.parse.source_hash,
                    semantic_status="SUCCEEDED",
                    manifest_json=manifest_text.replace("engine.alpha", "engine.omega"),
                    evidence_artifact_id=MISSING,
                    recorded_at_utc=production.clock.now_utc(),
                )
            )
        )
        _ok(
            transaction.validation_results.add(
                _ValidationRow(
                    invocation_id=OTHER_INVOCATION_ID,
                    run_id=RUN_ID,
                    experiment_id=EXPERIMENT_ID,
                    validation_result_hash=result.result_hash,
                    outcome="VALID",
                    result_json=result_text.replace('"VALID"', '"INVALID"'),
                    evidence_artifact_id=MISSING,
                    recorded_at_utc=production.clock.now_utc(),
                )
            )
        )
        _ok(transaction.commit())
    finally:
        transaction.rollback()
    drifted_manifest = _stage(
        production,
        RUN_OWNER,
        SANITIZED_MANIFEST_KIND,
        sanitized_manifest_leaf(),
        manifest_text.encode("utf-8"),
        INVOCATION_CORRELATION,
    )
    _refused(production, drifted_manifest, INVOCATION_CORRELATION, failed, "stored row")
    drifted_result = _stage(
        production,
        _SIBLING_OWNER,
        VALIDATION_RESULT_KIND,
        "validation-result.json",
        canonical_json_bytes(result),
        other,
    )
    _refused(production, drifted_result, other, failed, "stored row")
    first, second = plan.events[0], plan.events[1]
    shifted = second.model_copy(
        update={"received_at_utc": second.received_at_utc + timedelta(seconds=1)}
    )
    unledgered = RunEvent.model_validate(
        {
            **shifted.model_dump(mode="python"),
            "content_hash": run_event_content_hash(shifted),
        }
    )
    assert unledgered.event_id == second.event_id
    capture = _stage(
        production,
        RUN_OWNER,
        PROTOCOL_CAPTURE_KIND,
        "protocol-capture.jsonl",
        canonical_json_bytes(first) + b"\n" + canonical_json_bytes(unledgered) + b"\n",
        INVOCATION_CORRELATION,
    )
    _refused(production, capture, INVOCATION_CORRELATION, failed, "ledger")
    listed = _stage_stderr(production, _capture("[1, 2]\n"))
    registered = _ok(_finalize(production, (listed,)))
    assert registered.journal_state == "REGISTERED"
    pretty = json.dumps(json.loads(_fallback_bytes()), indent=2).encode("utf-8")
    loose_fallback = _stage(
        production, _SIBLING_OWNER, STDERR_KIND, _STDERR_LEAF, pretty, other
    )
    _refused(
        production,
        loose_fallback,
        other,
        SECURITY_SENSITIVE_MATERIAL_LEAKAGE,
        "token-shaped",
    )
    assert _validated_details(production) == [
        {"purpose": "EVIDENCE", "exact_scan": True, "canonical": False}
    ]
    # A run-owned fallback under an invocation of another run: the attempt
    # planted after this run failed names the crossed invocation.
    production.fail_run_by_verdict()
    production.plant_attempt(
        run_id=OTHER_RUN_ID,
        invocation_id=_ATTEMPT_INVOCATION_ID,
        attempt_number=2,
        predecessor_run_id=RUN_ID,
    )
    crossed = RunArtifactOwner(
        owner_kind="RUN",
        experiment_id=EXPERIMENT_ID,
        run_id=RUN_ID,
        invocation_id=_ATTEMPT_INVOCATION_ID,
    )
    candidate = sample_candidate(
        "RUN",
        _F.EVIDENCE,
        producer=_P.CORE,
        owner=crossed,
        artifact_kind=STDERR_KIND,
        staging_relative_path=f"INVOCATION/{_ATTEMPT_INVOCATION_ID}/{_STDERR_LEAF}",
    )
    qualifier = production.registrar
    assert isinstance(qualifier, CanonicalEvidenceQualifier)
    verdict = qualifier.qualify_evidence(candidate, (_fallback_bytes(),))
    assert _code(verdict) == failed
    assert "invocation" in _message(verdict)
    _assert_consistent(production)


def test_qualification_is_closed_to_the_registrar_and_the_candidate_shape(
    production: FinalizationFixture,
) -> None:
    """A kind label alone never qualifies: an adapter-produced RESULT candidate
    wearing a canonical kind, a core candidate of a kind no producer owns and a
    registrar composed without the fact-reading transactions each answer no
    contract, so their bytes keep the whole-content protection and a digest-
    bearing fallback registers through none of them; the result registrar
    registers no EVIDENCE journal as a RESULT; the classifier refuses a
    non-model and a non-string mapping key; a diagnostic whose dynamic detail
    key is digest-shaped is token-shaped material under the ruling."""
    plan = _plan(production)
    qualifier = production.registrar
    assert isinstance(qualifier, ResultRegistrar)
    fallback = _fallback_bytes()
    labelled = plan.candidates[0].model_copy(update={"artifact_kind": STDERR_KIND})
    assert not isinstance(
        _ok(qualifier.qualify_evidence(labelled, (fallback,))), CanonicalQualification
    )
    unowned_kind = sample_candidate(
        "RUN",
        _F.EVIDENCE,
        producer=_P.CORE,
        artifact_kind="engine-log",
        staging_relative_path=f"INVOCATION/{INVOCATION_ID}/engine.log",
    )
    assert not isinstance(
        _ok(qualifier.qualify_evidence(unowned_kind, (fallback,))),
        CanonicalQualification,
    )
    stderr = _stage_stderr(
        production,
        StderrCapture(
            retained_byte_count=0, truncated=False, source_hash=sha256_bytes(b"")
        ),
    )
    assert _staged_bytes(production, stderr) == fallback
    qualified = _ok(qualifier.qualify_evidence(stderr, (fallback,)))
    assert isinstance(qualified, CanonicalQualification)
    assert qualified == CanonicalQualification(records=1, uncontrolled_strings=())
    blind = EvidenceRegistrar(production.auditor, production.clock)
    assert not isinstance(
        _ok(blind.qualify_evidence(stderr, (fallback,))), CanonicalQualification
    )
    refused = production.finalize(
        evidence_request_for((stderr,), INVOCATION_CORRELATION), registrar=blind
    )
    assert _code(refused) == SECURITY_SENSITIVE_MATERIAL_LEAKAGE
    assert "token-shaped" in _message(refused)
    after = production.durable()
    assert after.refs == ()
    assert after.candidate_states[stderr.candidate_artifact_id] == "QUARANTINED"
    transaction = production.begin()
    try:
        wrong_purpose = qualifier.register_result(
            transaction, sample_journal(purpose=_F.EVIDENCE), (), cast("Any", None)
        )
    finally:
        transaction.rollback()
    assert _code(wrong_purpose) == INVARIANT_VIOLATION
    assert "not a RESULT journal" in _message(wrong_purpose)
    with pytest.raises(TypeError, match="pydantic model"):
        uncontrolled_strings_of(cast("Any", "free text"))
    with pytest.raises(TypeError, match="mapping keys"):
        uncontrolled_strings_of(_Loose(note="free", raw={1: "x"}))
    keyed = sample_diagnostic(THIRD_DIAG_ID).model_copy(
        update={"details": {_DIGEST_SHAPED: 1}}
    )
    assert _DIGEST_SHAPED in uncontrolled_strings_of(keyed)
    _record(production, keyed)
    report = _report(production, (keyed,), RUN_OWNER, THIRD_DIAG_ID)
    _refused(
        production,
        report,
        _diagnostic_correlation(THIRD_DIAG_ID),
        SECURITY_SENSITIVE_MATERIAL_LEAKAGE,
        "uncontrolled",
    )
    _assert_consistent(production)


def test_validate_conclusion_links_its_validation_result_evidence(
    production: FinalizationFixture,
) -> None:
    """Plan 4.6 for a ``VALIDATE`` conclusion: the reconciliation's sanitized
    validation result is staged as ``RUN``-owned ``CORE_EVIDENCE`` with its
    ``adapter_validation_results`` row written once, finalized under the
    validate invocation's correlation without material (no root of that
    invocation holds any), qualified against its row and linked to its
    reference beside the stderr; the run stays ``READY``, no manifest exists
    and nothing closes; a second staging of the same result is the same
    candidate and the row stays one."""
    prestate = production.plant_run(run_state=EngineRunState.READY)
    validate = sample_invocation(
        CommandInvocationState.EXITED,
        kind=CommandKind.VALIDATE,
        invocation_id=OTHER_INVOCATION_ID,
    )
    put_invocation(production.harness.lifecycle(), validate)
    root = production.roots.runtime_root / OTHER_INVOCATION_ID
    root.mkdir()
    (root / "request.json").write_bytes(b'{"command": "validate"}')
    (root / "output.json").write_bytes(b'{"outcome": "VALID"}')
    roots = CommandRootPaths(
        command_root=root,
        request_path=root / "request.json",
        output_path=root / "output.json",
    )
    result = _validation_result_of(prestate.run.attempt_token_hash, OTHER_INVOCATION_ID)
    validated = SemanticReconciliation.model_validate(
        {
            "command_kind": CommandKind.VALIDATE,
            "verdict": ReconciliationVerdict.VALIDATED_READY,
            "run_target_state": EngineRunState.READY,
            "diagnostics": (),
            "sanitized_validation_result": result,
        }
    )
    recording = _RecordingFinalizer(production.finalizer())
    conclusion = _ok(
        conclude_command(
            SemanticOutcome(
                invocation=validate, run=prestate.run, reconciliation=validated
            ),
            CommandResult(
                invocation=validate,
                protocol_integrity=ProtocolIntegrityStatus.INTACT,
                accepted_events=(),
                diagnostics=(),
                stderr=_capture("validate stderr\n"),
                cancelled=False,
                timed_out=False,
            ),
            MISSING,
            _EMPTY_SUMMARY,
            (),
            roots=roots,
            token=MISSING,
            config=_config(production),
            unit_of_work=production.unit_of_work(),
            finalizer=recording,
            clock=production.clock,
        )
    )
    assert recording.received == [("EVIDENCE", MISSING)]
    assert conclusion.run.state is EngineRunState.READY
    assert not isinstance(conclusion.finalization, FinalizationResult)
    assert not isinstance(conclusion.run_manifest, RunManifest)
    assert not isinstance(conclusion.evidence_failure, Failure)
    assert {ref.artifact_kind for ref in conclusion.evidence_refs} == {
        STDERR_KIND,
        VALIDATION_RESULT_KIND,
    }
    (result_ref,) = [
        ref
        for ref in conclusion.evidence_refs
        if ref.artifact_kind == VALIDATION_RESULT_KIND
    ]
    (stderr_ref,) = [
        ref for ref in conclusion.evidence_refs if ref.artifact_kind == STDERR_KIND
    ]
    assert all(ref.owner == _SIBLING_OWNER for ref in conclusion.evidence_refs)
    assert production.harness.count("adapter_validation_results") == 1
    transaction = production.begin()
    try:
        facts = _ok(transaction.validation_results.get(OTHER_INVOCATION_ID))
        stored = _ok(transaction.command_invocations.get(OTHER_INVOCATION_ID))
    finally:
        transaction.rollback()
    assert not isinstance(facts, type(MISSING))
    assert facts.evidence_artifact_id == result_ref.artifact_id
    assert facts.result_json == canonical_json_text(result)
    assert stored.stderr_artifact_id == stderr_ref.artifact_id
    assert sorted(
        (item["canonical"], item["exact_scan"])
        for item in _validated_details(production)
    ) == [(False, False), (True, False)]
    assert (root / "request.json").is_file()
    assert (root / "output.json").is_file()
    after = production.durable()
    assert after.run_manifests == ()
    assert {link.link_role for link in after.run_artifacts} == {"RUN_EVIDENCE"}
    again = _ok(
        validation_result_evidence(
            result,
            _SIBLING_OWNER,
            store=production.roots.store,
            unit_of_work=production.unit_of_work(),
            clock=production.clock,
        )
    )
    assert again.candidate_artifact_id == result_ref.source_candidate_artifact_id
    assert production.harness.count("adapter_validation_results") == 1
    _assert_consistent(production)


def test_describe_conclusions_refuse_other_kinds_and_stage_without_a_parse(
    production: FinalizationFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``conclude_describe`` concludes an ``EXITED`` ``DESCRIBE`` and nothing else:
    a run-command result and a cancelled describe are the invariant with
    nothing staged or recorded; a describe whose output never parsed as an
    envelope records the reconciliation's diagnostic, stages the stderr alone
    under the adapter owner without engine identity, finalizes it token-free
    and closes no root."""
    plan = _plan(production)
    before = production.durable()
    run_result = conclude_describe(
        _command_result(plan, events=False),
        MISSING,
        _reconcile(production, plan),
        roots=plan.roots,
        config=_config(production),
        unit_of_work=production.unit_of_work(),
        finalizer=production.finalizer(),
        clock=production.clock,
    )
    assert _code(run_result) == INVARIANT_VIOLATION
    assert "DESCRIBE" in _message(run_result)
    cancelled = sample_invocation(
        CommandInvocationState.CANCELLED,
        kind=CommandKind.DESCRIBE,
        invocation_id=OTHER_INVOCATION_ID,
    )
    not_exited = conclude_describe(
        CommandResult(
            invocation=cancelled,
            protocol_integrity=ProtocolIntegrityStatus.INTACT,
            accepted_events=(),
            diagnostics=(),
            stderr=_capture("describe stderr\n"),
            cancelled=True,
            timed_out=False,
        ),
        MISSING,
        _reconcile(production, plan),
        roots=plan.roots,
        config=_config(production),
        unit_of_work=production.unit_of_work(),
        finalizer=production.finalizer(),
        clock=production.clock,
    )
    assert _code(not_exited) == INVARIANT_VIOLATION
    assert "not EXITED" in _message(not_exited)
    assert production.durable() == before
    describe = sample_invocation(
        CommandInvocationState.EXITED,
        kind=CommandKind.DESCRIBE,
        invocation_id=_DESCRIBE_INVOCATION_ID,
    )
    put_invocation(production.harness.lifecycle(), describe)
    root = production.roots.runtime_root / _DESCRIBE_INVOCATION_ID
    root.mkdir()
    request_path = root / "request.json"
    output_path = root / "output.json"
    request_path.write_bytes(b'{"schema_version": "1.0.0", "command": "describe"}')
    output_path.write_bytes(b"not a descriptor")
    roots = CommandRootPaths(
        command_root=root, request_path=request_path, output_path=output_path
    )
    no_envelope = parse_bootstrap_descriptor(
        b"not a descriptor", max_bytes=MAX_DESCRIPTOR_OUTPUT_BYTES
    )
    assert isinstance(no_envelope, DescriptorParse)
    assert not isinstance(no_envelope.envelope, BootstrapDescriptorEnvelope)
    reconciliation = reconcile_describe(
        describe,
        no_envelope,
        len(b"not a descriptor"),
        catalog_entry=AdapterCatalogEntry(
            adapter_name=ADAPTER_OWNER.adapter_name,
            adapter_version=ADAPTER_OWNER.adapter_version,
            engine=production.current_run().engine,
            executable_path="C:/adapters/alpha/adapter.exe",
            executable_hash=EXECUTABLE_HASH,
            runtime_metadata={},
        ),
        now_utc=production.clock.now_utc(),
    )
    assert reconciliation.verdict is not ReconciliationVerdict.DESCRIBED
    assert len(reconciliation.diagnostics) == 1
    monkeypatch.setattr(finalization_module, "close_raw_bytes", _forbidden)
    recording = _RecordingFinalizer(production.finalizer())
    refs = _ok(
        conclude_describe(
            CommandResult(
                invocation=describe,
                protocol_integrity=ProtocolIntegrityStatus.INTACT,
                accepted_events=(),
                diagnostics=(),
                stderr=_capture("describe stderr\n"),
                cancelled=False,
                timed_out=False,
            ),
            MISSING,
            reconciliation,
            roots=roots,
            config=_config(production),
            unit_of_work=production.unit_of_work(),
            finalizer=recording,
            clock=production.clock,
        )
    )
    assert recording.received == [("EVIDENCE", MISSING)]
    (stderr_ref,) = refs
    assert stderr_ref.artifact_kind == STDERR_KIND
    assert stderr_ref.owner == ADAPTER_OWNER
    assert not isinstance(ADAPTER_OWNER.engine_name, str)
    after = production.durable()
    assert reconciliation.diagnostics[0].diagnostic_id in {
        item.diagnostic_id for item in after.diagnostics
    }
    assert [ref.artifact_kind for ref in after.refs] == [STDERR_KIND]
    assert request_path.is_file()
    assert output_path.is_file()
    assert after.run == before.run
    _assert_consistent(production)


#: The ``DESCRIBE`` invocation of another adapter and an identity the registry
#: never held: two correlations an ``ADAPTER`` owner's core evidence may not name.
_BETA_DESCRIBE_INVOCATION_ID: Final = "inv_55555555-6666-4777-8888-999999999999"
_UNKNOWN_INVOCATION_ID: Final = "inv_66666666-7777-4888-8999-aaaaaaaaaaaa"


def test_adapter_core_evidence_requires_its_own_describe_invocation(
    production: FinalizationFixture,
) -> None:
    """Plan 3.1.1 row 3 at the staging boundary (plan 4.6): an ``ADAPTER``
    owner's ``CORE_EVIDENCE`` enters staging only under an ``INVOCATION``
    correlation naming a ``DESCRIBE`` invocation of that adapter and version,
    read from the authoritative invocation row before any filesystem work. An
    ``AUDIT`` or ``DIAGNOSTIC`` correlation, an invocation the registry does not
    hold, the adapter's ``VALIDATE`` invocation and another adapter's
    ``DESCRIBE`` are refused with no staged byte, candidate row, diagnostic or
    audit fact (a truncated capture records no truncation either); the matching
    ``DESCRIBE`` stages without an ``engine_runs`` read, finalizes under that
    correlation and enriches that invocation."""
    production.plant_run()
    _plant_invocation(production, _DESCRIBE_INVOCATION_ID, CommandKind.DESCRIBE)
    _plant_invocation(production, OTHER_INVOCATION_ID, CommandKind.VALIDATE)
    put_invocation(
        production.harness.lifecycle(),
        sample_invocation(
            CommandInvocationState.EXITED,
            kind=CommandKind.DESCRIBE,
            invocation_id=_BETA_DESCRIBE_INVOCATION_ID,
            adapter_name="adapter.beta",
            adapter_version="1.2.0",
        ),
    )
    diagnostic = sample_diagnostic(DIAG_ID)
    _record(production, diagnostic)
    before = production.durable()
    payload = b"adapter stderr\n"
    audit = EvidenceCorrelation(
        kind="AUDIT", audit_event_id=production.audit_ids.new_audit_event_id()
    )
    misfiled = stage_core_evidence(
        ADAPTER_OWNER,
        _R.CORE_EVIDENCE,
        STDERR_KIND,
        "stderr.txt",
        payload,
        audit,
        store=production.roots.store,
        unit_of_work=production.unit_of_work(),
        clock=production.clock,
    )
    assert _code(misfiled) == ARTIFACT_VALIDATION_FAILED
    assert "DESCRIBE" in _message(misfiled)
    report = diagnostic_report_evidence(
        (diagnostic,),
        cast("Any", ADAPTER_OWNER),
        DIAG_ID,
        store=production.roots.store,
        unit_of_work=production.unit_of_work(),
        clock=production.clock,
    )
    assert _code(report) == ARTIFACT_VALIDATION_FAILED
    assert "DESCRIBE" in _message(report)
    unknown = _stderr_result(
        production, _capture("adapter stderr\n"), ADAPTER_OWNER, _UNKNOWN_INVOCATION_ID
    )
    assert _code(unknown) == INVARIANT_VIOLATION
    assert "does not exist" in _message(unknown)
    validate = _stderr_result(
        production,
        _capture("partial adapter stderr\n", truncated=True),
        ADAPTER_OWNER,
        OTHER_INVOCATION_ID,
    )
    assert _code(validate) == ARTIFACT_VALIDATION_FAILED
    assert "DESCRIBE" in _message(validate)
    foreign = _stderr_result(
        production,
        _capture("adapter stderr\n"),
        ADAPTER_OWNER,
        _BETA_DESCRIBE_INVOCATION_ID,
    )
    assert _code(foreign) == ARTIFACT_VALIDATION_FAILED
    assert "DESCRIBE" in _message(foreign)
    after = production.durable()
    assert after == before
    assert after.staging_files == before.staging_files
    assert PROCESS_STDERR_TRUNCATED not in after.diagnostic_codes
    assert "STDERR_TRUNCATED" not in after.audit_actions
    guarded: Any = _NoRunReads(production.unit_of_work())
    staged = _ok(
        _stderr_result(
            production,
            _capture("adapter stderr\n"),
            ADAPTER_OWNER,
            _DESCRIBE_INVOCATION_ID,
            unit_of_work=guarded,
        )
    )
    assert staged.owner == ADAPTER_OWNER
    assert staged.source_role is _R.CORE_EVIDENCE
    assert staged.staging_relative_path == (
        f"INVOCATION/{_DESCRIBE_INVOCATION_ID}/stderr.txt"
    )
    assert _staged_bytes(production, staged) == payload
    assert production.durable().candidate_states[staged.candidate_artifact_id] == (
        "CANDIDATE"
    )
    describe = EvidenceCorrelation(
        kind="INVOCATION", invocation_id=_DESCRIBE_INVOCATION_ID
    )
    registered = _ok(
        finalize_evidence((staged,), describe, finalizer=production.finalizer())
    )
    assert registered.journal_state == "REGISTERED"
    (mapping,) = registered.candidate_to_artifact_refs
    (stored,) = [
        item
        for item in production.harness.lifecycle().committed_command_invocations()
        if item.invocation_id == _DESCRIBE_INVOCATION_ID
    ]
    assert stored.stderr_artifact_id == mapping.artifact_id
    assert production.durable().run == before.run
    _assert_consistent(production)


def test_conclusion_survives_a_result_timeout_and_keeps_its_evidence(
    production: FinalizationFixture,
) -> None:
    """Plan 4.5 beside 29.1 through ``conclude_command``: a RESULT finalization
    that exhausts its deadline has already moved the run ``RUNNING -> TIMED_OUT``
    and closed the root, so the conclusion neither fails the run a second time
    nor closes twice; it concludes without a finalization or manifest while the
    invocation's evidence -- the frame's material still in hand after the
    close -- finalizes with the exact scan and registers."""
    plan = _plan(production)
    observed = _observe(production, plan)
    outcome = SemanticOutcome(
        invocation=plan.invocation,
        run=plan.run,
        reconciliation=_reconcile(production, plan, observed),
    )
    conclusion = _ok(
        conclude_command(
            outcome,
            _command_result(plan, stderr=_capture()),
            plan.parse,
            plan.summary,
            observed,
            roots=plan.roots,
            token=_token(production),
            config=_config(production),
            unit_of_work=production.unit_of_work(),
            finalizer=production.finalizer(_AdvancingProbe(production.clock)),
            clock=production.clock,
        )
    )
    assert conclusion.run.state is EngineRunState.TIMED_OUT
    assert conclusion.replayed is False
    assert not isinstance(conclusion.finalization, FinalizationResult)
    assert not isinstance(conclusion.run_manifest, RunManifest)
    assert conclusion.result_refs == ()
    assert not isinstance(conclusion.evidence_failure, Failure)
    assert {ref.artifact_kind for ref in conclusion.evidence_refs} == {
        STDERR_KIND,
        PROTOCOL_CAPTURE_KIND,
        SANITIZED_MANIFEST_KIND,
    }
    after = production.durable()
    assert after.run_state == "TIMED_OUT"
    assert after.run_manifests == ()
    assert {link.link_role for link in after.run_artifacts} == {"RUN_EVIDENCE"}
    (entry,) = [
        item for item in after.journal if item.finalization_purpose is _F.RESULT
    ]
    assert entry.state.value == "ABANDONED"
    assert entry.abandon_reason == ARTIFACT_FINALIZATION_TIMED_OUT
    assert "RUN_FAILED" not in after.audit_actions
    assert after.audit_actions.count("RETENTION_DELETED") == 1
    assert not plan.roots.request_path.exists()
    assert isinstance(plan.roots.result_path, Path)
    assert not plan.roots.result_path.exists()
    assert all(item["exact_scan"] is True for item in _validated_details(production))
    _assert_consistent(production)


def test_builders_and_observation_refuse_malformed_inputs(
    production: FinalizationFixture,
) -> None:
    """The builders refuse before any I/O: an evidence request needs at least
    one candidate, one owner and one role across them; result candidates belong
    to a ``RUN`` owner with its invocation; the observation needs an absolute
    work directory and observes a path declared twice once; the composition
    facts and the recovery validator bound the finalization timeout."""
    plan = _plan(production)
    _plant_invocation(production, _DESCRIBE_INVOCATION_ID, CommandKind.DESCRIBE)
    describe = EvidenceCorrelation(
        kind="INVOCATION", invocation_id=_DESCRIBE_INVOCATION_ID
    )
    with pytest.raises(ValueError, match="at least one"):
        finalize_evidence((), INVOCATION_CORRELATION, finalizer=production.finalizer())
    run_stderr = _stage_stderr(production)
    adapter_stderr = _stage_stderr(
        production, _capture("adapter stderr\n"), ADAPTER_OWNER, _DESCRIBE_INVOCATION_ID
    )
    with pytest.raises(ValueError, match="shares its owner"):
        finalize_evidence(
            (run_stderr, adapter_stderr),
            INVOCATION_CORRELATION,
            finalizer=production.finalizer(),
        )
    parse = parse_bootstrap_descriptor(
        _envelope_bytes(_descriptor()), max_bytes=MAX_DESCRIPTOR_OUTPUT_BYTES
    )
    assert isinstance(parse, DescriptorParse)
    descriptor = _ok(
        descriptor_evidence(
            parse,
            ADAPTER_OWNER,
            _DESCRIBE_INVOCATION_ID,
            store=production.roots.store,
            unit_of_work=production.unit_of_work(),
            clock=production.clock,
        )
    )
    assert descriptor.source_role is not adapter_stderr.source_role
    with pytest.raises(ValueError, match="shares its role"):
        finalize_evidence(
            (descriptor, adapter_stderr), describe, finalizer=production.finalizer()
        )
    after = production.durable()
    assert after.journal == ()
    assert after.refs == ()
    for owner in (ADAPTER_OWNER, RUN_OWNER_WITHOUT_INVOCATION):
        with pytest.raises(ValueError, match="RUN owner"):
            register_result_candidates(
                plan.summary.artifact_declarations,
                cast("Any", owner),
                unit_of_work=production.unit_of_work(),
                clock=production.clock,
            )
    with pytest.raises(ValueError, match="absolute"):
        observe_candidates(
            Path("relative"),
            ("results/native.bin",),
            _token(production),
            hasher=production.hasher,
            clock=production.clock,
        )
    assert isinstance(plan.roots.work_dir, Path)
    twice = _ok(
        observe_candidates(
            plan.roots.work_dir,
            ("results/native.bin", "results/native.bin"),
            _token(production),
            hasher=production.hasher,
            clock=production.clock,
        )
    )
    assert [item.relative_path for item in twice] == ["results/native.bin"]
    for seconds in (0, 3601, True):
        with pytest.raises(ValueError, match="must be within"):
            ConclusionConfig(
                store=production.roots.store,
                hasher=production.hasher,
                auditor=production.auditor,
                finalization_timeout_seconds=cast("Any", seconds),
            )
        with pytest.raises(ValueError, match="must be within"):
            ResultRecoveryValidator(
                unit_of_work=production.unit_of_work(),
                hasher=production.hasher,
                negotiated_versions=DEFAULT_NEGOTIATED_VERSIONS,
                finalization_timeout_seconds=cast("Any", seconds),
                clock=production.clock,
            )


def test_recovery_and_replay_refuse_unknown_runs_and_foreign_material(
    production: FinalizationFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """29.3 and reading 24 at their loads: material naming another run proves
    no identity even when its token is the attempt's; candidates of a run the
    registry does not hold are refused at the load with the work directory
    never observed; a replay request for an unknown run is refused before the
    Stage 6 operation is consulted; a run in no success state is handed to that
    operation and its answer returned unchanged."""
    plan = _plan(production)
    validator = production.validator
    foreign = validator.validate_temporary_manifest(
        plan.roots,
        AttemptTokenMaterial(run_id=OTHER_RUN_ID, attempt_token=FIXTURE_TOKEN),
        plan.candidates,
    )
    assert _code(foreign) == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    assert FIXTURE_TOKEN not in _message(foreign)
    strangers = result_candidates(
        run_id=OTHER_RUN_ID,
        invocation_id=OTHER_INVOCATION_ID,
        owner=RunArtifactOwner(
            owner_kind="RUN",
            experiment_id=EXPERIMENT_ID,
            run_id=OTHER_RUN_ID,
            invocation_id=OTHER_INVOCATION_ID,
        ),
    )
    monkeypatch.setattr(finalization_module, "observe_candidates", _forbidden)
    unknown = validator.validate_temporary_manifest(
        plan.roots, _token(production), strangers
    )
    assert _code(unknown) == INVARIANT_VIOLATION
    assert "does not exist" in _message(unknown)
    monkeypatch.undo()
    observed = _observe(production, plan)
    request = SemanticOutcomeRequest(
        schema_version="1.0.0",
        invocation_id=INVOCATION_ID,
        expected_invocation_revision=plan.invocation.revision,
        run_id=OTHER_RUN_ID,
        expected_run_revision=plan.run.revision,
        parsed_output=plan.parse,
        protocol_summary=plan.summary,
        candidate_observations=observed,
        negotiated_versions=DEFAULT_NEGOTIATED_VERSIONS,
    )
    monkeypatch.setattr(
        finalization_module, "apply_command_semantic_outcome", _forbidden
    )
    missing_run = semantic_outcome_or_replay(
        request, unit_of_work=production.unit_of_work(), clock=production.clock
    )
    assert _code(missing_run) == INVARIANT_VIOLATION
    assert "does not exist" in _message(missing_run)
    monkeypatch.undo()
    applied = SemanticOutcome(
        invocation=plan.invocation,
        run=plan.run,
        reconciliation=_reconcile(production, plan, observed),
    )
    monkeypatch.setattr(
        finalization_module,
        "apply_command_semantic_outcome",
        lambda *args, **kwargs: Success[SemanticOutcome](
            outcome="SUCCESS", value=applied
        ),
    )
    delegated = _ok(
        semantic_outcome_or_replay(
            request.model_copy(update={"run_id": RUN_ID}),
            unit_of_work=production.unit_of_work(),
            clock=production.clock,
        )
    )
    assert delegated is applied
    assert production.durable().run_state == "RUNNING"


def test_fail_run_without_raw_bytes_and_a_conclusion_without_the_memo(
    production: FinalizationFixture, tmp_path: Path
) -> None:
    """Plan 4.4 step 5 is conditional: a refusal failing a run whose root holds
    no raw byte audits ``RUN_FAILED`` alone and closes nothing; a composition
    without the registrar memo still registers the success from the sanitized
    row the step-2 staging wrote, the row being the durable source."""
    plan = _plan(production)
    assert isinstance(plan.roots.result_path, Path)
    plan.roots.request_path.unlink()
    plan.roots.result_path.unlink()
    refusal = artifact_failure(
        ARTIFACT_VALIDATION_FAILED,
        message="a declared candidate changed after the verdict",
        now_utc=production.clock.now_utc(),
        experiment_id=EXPERIMENT_ID,
        run_id=RUN_ID,
        invocation_id=INVOCATION_ID,
    )
    _ok(
        fail_run_for_refusal(
            refusal,
            run_id=RUN_ID,
            expected_run_revision=plan.run.revision,
            roots=plan.roots,
            config=_config(production),
            unit_of_work=production.unit_of_work(),
            clock=production.clock,
        )
    )
    after = production.durable()
    assert after.run_state == "FAILED"
    assert after.run_revision == plan.run.revision + 1
    assert after.audit_actions == ("RUN_FAILED",)
    _assert_consistent(production)
    with _fresh(tmp_path, "m") as other:
        plan = _plan(other)
        observed = _observe(other, plan)
        config = ConclusionConfig(
            store=other.roots.store,
            hasher=other.hasher,
            auditor=other.auditor,
            finalization_timeout_seconds=RESULT_TIMEOUT_SECONDS,
        )
        assert config.registrar is None
        conclusion = _ok(
            conclude_command(
                SemanticOutcome(
                    invocation=plan.invocation,
                    run=plan.run,
                    reconciliation=_reconcile(other, plan, observed),
                ),
                _command_result(plan, events=False),
                plan.parse,
                plan.summary,
                observed,
                roots=plan.roots,
                token=_token(other),
                config=config,
                unit_of_work=other.unit_of_work(),
                finalizer=other.finalizer(),
                clock=other.clock,
            )
        )
        assert conclusion.run.state is EngineRunState.SUCCEEDED
        assert isinstance(conclusion.run_manifest, RunManifest)
        assert [ref.artifact_kind for ref in conclusion.evidence_refs] == [
            SANITIZED_MANIFEST_KIND
        ]
        assert not isinstance(conclusion.evidence_failure, Failure)
        _assert_consistent(other)


# --------------------------------------------------------------------------
# The remaining Task 7 coverage gaps (the verify-f37ba508becb report): contract
# conditions reached through the production entry points
# --------------------------------------------------------------------------

#: Further ``DESCRIBE`` invocations of the fixture's adapter: one per describe
#: conclusion case, since a describe root and its staging leaves are per
#: invocation.
_MORE_DESCRIBE_INVOCATION_IDS: Final = (
    "inv_77777777-8888-4999-8aaa-bbbbbbbbbbbb",
    "inv_88888888-9999-4aaa-8bbb-cccccccccccc",
    "inv_99999999-aaaa-4bbb-8ccc-dddddddddddd",
)
#: Token-free JSON (one JSON Lines record too) that is no producer's model.
_LOOSE_JSON: Final = b'{"note":"not the model"}\n'
_DESCRIPTOR_LEAF: Final = "adapter-descriptor.json"
_ENGINE_OWNER: Final = AdapterArtifactOwner(
    owner_kind="ADAPTER",
    adapter_name=ADAPTER_OWNER.adapter_name,
    adapter_version=ADAPTER_OWNER.adapter_version,
    engine_name=_ENGINE_NAME,
    engine_version=_ENGINE_VERSION,
)


@dataclass(frozen=True, slots=True)
class _DescribeContext:
    """One ``DESCRIBE`` invocation with its command root, the parse of its
    output and the Stage 6 describe reconciliation over that parse."""

    invocation: Any
    roots: CommandRootPaths
    parse: DescriptorParse
    reconciliation: SemanticReconciliation


def _command_root(
    fixture: FinalizationFixture, invocation_id: str, output: bytes
) -> CommandRootPaths:
    """A token-free command root (``request.json`` and ``output.json``) of a
    ``DESCRIBE`` or ``VALIDATE`` invocation under the runtime root."""
    root = fixture.roots.runtime_root / invocation_id
    root.mkdir()
    request_path = root / "request.json"
    output_path = root / "output.json"
    request_path.write_bytes(b'{"schema_version": "1.0.0", "command": "token-free"}')
    output_path.write_bytes(output)
    return CommandRootPaths(
        command_root=root, request_path=request_path, output_path=output_path
    )


def _describe_context(
    fixture: FinalizationFixture,
    invocation_id: str,
    *,
    stored: bool = True,
    envelope: bool = True,
) -> _DescribeContext:
    describe = sample_invocation(
        CommandInvocationState.EXITED,
        kind=CommandKind.DESCRIBE,
        invocation_id=invocation_id,
    )
    if stored:
        put_invocation(fixture.harness.lifecycle(), describe)
    output = _envelope_bytes(_descriptor()) if envelope else b"not a descriptor"
    roots = _command_root(fixture, invocation_id, output)
    parse = parse_bootstrap_descriptor(output, max_bytes=MAX_DESCRIPTOR_OUTPUT_BYTES)
    assert isinstance(parse, DescriptorParse)
    assert isinstance(parse.envelope, BootstrapDescriptorEnvelope) is envelope
    reconciliation = reconcile_describe(
        describe,
        parse,
        0 if envelope else len(output),
        catalog_entry=AdapterCatalogEntry(
            adapter_name=ADAPTER_OWNER.adapter_name,
            adapter_version=ADAPTER_OWNER.adapter_version,
            engine=fixture.current_run().engine,
            executable_path="C:/adapters/alpha/adapter.exe",
            executable_hash=EXECUTABLE_HASH,
            runtime_metadata={},
        ),
        now_utc=fixture.clock.now_utc(),
    )
    return _DescribeContext(
        invocation=describe, roots=roots, parse=parse, reconciliation=reconciliation
    )


def _describe_command_result(
    context: _DescribeContext, *, stderr: StderrCapture | None
) -> CommandResult:
    payload: dict[str, Any] = {
        "invocation": context.invocation,
        "protocol_integrity": ProtocolIntegrityStatus.INTACT,
        "accepted_events": (),
        "diagnostics": (),
        "cancelled": False,
        "timed_out": False,
    }
    envelope = context.parse.envelope
    if isinstance(envelope, BootstrapDescriptorEnvelope):
        payload["parsed_output"] = envelope
        payload["parsed_output_source_hash"] = context.parse.source_hash
    if stderr is not None:
        payload["stderr"] = stderr
    return CommandResult.model_validate(payload)


def _conclude_describe(
    fixture: FinalizationFixture,
    context: _DescribeContext,
    *,
    stderr: StderrCapture | None = None,
    with_parse: bool = True,
) -> Result[Any]:
    return conclude_describe(
        _describe_command_result(context, stderr=stderr),
        context.parse if with_parse else MISSING,
        context.reconciliation,
        roots=context.roots,
        config=_config(fixture),
        unit_of_work=fixture.unit_of_work(),
        finalizer=fixture.finalizer(),
        clock=fixture.clock,
    )


def _assert_evidence_abandoned(
    fixture: FinalizationFixture, candidate: Any, refused: object, code: str
) -> None:
    """The T3 rollback of a refused EVIDENCE registration: no reference, the one
    journal ``ABANDONED`` under the refusal's code, the candidate quarantined
    and no ``FINALIZATION_REGISTERED`` fact."""
    assert _code(refused) == code, _message(refused)
    after = fixture.durable()
    assert after.refs == ()
    assert after.journal_state == "ABANDONED"
    assert after.abandon_reason == code
    assert after.candidate_states[candidate.candidate_artifact_id] == "QUARANTINED"
    assert "FINALIZATION_REGISTERED" not in after.audit_actions
    _assert_consistent(fixture)


def _assert_refused_before_any_lease(
    fixture: FinalizationFixture, plan: ProductionResultPlan, refused: object
) -> None:
    """A conclusion ended by a step-2 refusal: the invariant returned, the run
    row as planted, no journal, reference, manifest or fact, the raw bytes in
    place."""
    assert _code(refused) == INVARIANT_VIOLATION, _message(refused)
    after = fixture.durable()
    assert after.run == plan.run
    assert after.journal == ()
    assert after.refs == ()
    assert after.run_manifests == ()
    assert after.audit_actions == ()
    assert plan.roots.request_path.is_file()
    assert isinstance(plan.roots.result_path, Path)
    assert plan.roots.result_path.is_file()
    _assert_consistent(fixture)


def test_non_model_bytes_of_canonical_kinds_keep_the_whole_content_rule(
    production: FinalizationFixture, tmp_path: Path
) -> None:
    """The ruling: bytes under a canonical kind that are not the producer's
    model answer no contract. Token-free non-model JSON staged as the
    sanitized-manifest, descriptor and diagnostic-report kinds registers as
    plain content (``canonical`` false) through the production registrar, and
    the sanitized-manifest link finds neither a run manifest nor a memo and
    writes no row. Composed without the fact-reading transactions the registrar
    links that kind through the ``run_manifests`` row alone: after a success
    linked the stored row to its evidence, a later candidate of the kind leaves
    the link as it stands and a ``SYSTEM`` owner's never reaches the row."""
    plan = _plan(production, sanitized_row=False)
    _plant_invocation(production, _DESCRIBE_INVOCATION_ID, CommandKind.DESCRIBE)
    describe = EvidenceCorrelation(
        kind="INVOCATION", invocation_id=_DESCRIBE_INVOCATION_ID
    )
    first = _diagnostic_correlation(DIAG_ID)
    _record(production, sample_diagnostic(DIAG_ID))
    plain_manifest = _stage(
        production,
        RUN_OWNER,
        SANITIZED_MANIFEST_KIND,
        sanitized_manifest_leaf(),
        _LOOSE_JSON,
        INVOCATION_CORRELATION,
    )
    plain_descriptor = _stage(
        production,
        ADAPTER_OWNER,
        "adapter-descriptor",
        _DESCRIPTOR_LEAF,
        _LOOSE_JSON,
        describe,
        role=_R.ADAPTER_DESCRIPTOR_EVIDENCE,
    )
    plain_report = _stage(
        production,
        RUN_OWNER,
        DIAGNOSTIC_REPORT_KIND,
        "diagnostic-report.jsonl",
        _LOOSE_JSON,
        first,
    )
    for candidate, correlation in (
        (plain_manifest, INVOCATION_CORRELATION),
        (plain_descriptor, describe),
        (plain_report, first),
    ):
        registered = _ok(_finalize(production, (candidate,), correlation))
        assert registered.journal_state == "REGISTERED"
    assert [item["canonical"] for item in _validated_details(production)] == [
        False,
        False,
        False,
    ]
    assert production.harness.count("sanitized_adapter_result_manifests") == 0
    after = production.durable()
    assert after.run == plan.run
    assert {ref.artifact_kind for ref in after.refs} == {
        SANITIZED_MANIFEST_KIND,
        "adapter-descriptor",
        DIAGNOSTIC_REPORT_KIND,
    }
    _assert_consistent(production)
    with _fresh(tmp_path, "b") as other:
        linked = _plan(other)
        conclusion = _ok(_conclude(other, linked, events=False))
        assert conclusion.run.state is EngineRunState.SUCCEEDED
        (evidence_ref,) = conclusion.evidence_refs
        assert evidence_ref.artifact_kind == SANITIZED_MANIFEST_KIND
        sanitized_hash = linked.sanitized.sanitized_adapter_result_manifest_hash
        blind = EvidenceRegistrar(other.auditor, other.clock)
        copies = tuple(
            _stage(
                other,
                owner,
                SANITIZED_MANIFEST_KIND,
                "sanitized-manifest-copy.json",
                _LOOSE_JSON,
                INVOCATION_CORRELATION,
            )
            for owner in (RUN_OWNER, SYSTEM_OWNER)
        )
        for copy in copies:
            registered = _ok(
                other.finalize(
                    evidence_request_for((copy,), INVOCATION_CORRELATION),
                    registrar=blind,
                )
            )
            assert registered.journal_state == "REGISTERED"
        transaction = other.begin()
        try:
            facts = _ok(transaction.sanitized_manifests.get(sanitized_hash))
        finally:
            transaction.rollback()
        assert not isinstance(facts, type(MISSING))
        assert facts.evidence_artifact_id == evidence_ref.artifact_id
        assert other.harness.count("sanitized_adapter_result_manifests") == 1
        assert len(other.durable().refs) == len(linked.candidates) + 3
        _assert_consistent(other)


def test_registration_refusals_roll_back_link_and_enrichment_writes(
    production: FinalizationFixture, tmp_path: Path
) -> None:
    """Each refused EVIDENCE registration write is rolled back whole: a refused
    ``RUN_EVIDENCE`` link, a stderr enrichment of an invocation that is not
    terminal, and a refused sanitized-manifest or validation-result evidence
    link (the row's one ``UPDATE``) each abandon the journal under the refusal's
    code with no reference, link or enrichment committed, the run row untouched
    and the candidate quarantined."""
    plan = _plan(production)
    stderr = _stage_stderr(production)
    production.harness.install_refusing_trigger(
        "run_artifacts", f"NEW.run_id = '{RUN_ID}'"
    )
    _assert_evidence_abandoned(
        production, stderr, _finalize(production, (stderr,)), INVARIANT_VIOLATION
    )
    after = production.durable()
    assert after.run == plan.run
    assert after.run_artifacts == ()
    assert after.invocation is not None
    assert not isinstance(after.invocation.stderr_artifact_id, str)
    with _fresh(tmp_path, "n") as other:
        other.plant_run(invocation_state=CommandInvocationState.RUNNING)
        stderr = _stage_stderr(other)
        refused = _finalize(other, (stderr,))
        _assert_evidence_abandoned(other, stderr, refused, INVARIANT_VIOLATION)
        assert "enrichment" in _message(refused)
        state = other.durable()
        assert state.run_artifacts == ()
        assert state.invocation is not None
        assert state.invocation.state is CommandInvocationState.RUNNING
        assert not isinstance(state.invocation.stderr_artifact_id, str)
        assert "STDERR_EVIDENCE_LINKED" not in state.audit_actions
    with _fresh(tmp_path, "u") as other:
        recorded = _plan(other)
        manifest = _ok(
            sanitized_result_manifest_evidence(
                recorded.sanitized,
                RUN_OWNER,
                store=other.roots.store,
                unit_of_work=other.unit_of_work(),
                clock=other.clock,
            )
        )
        other.harness.install_refusing_trigger(
            "sanitized_adapter_result_manifests",
            f"NEW.run_id = '{RUN_ID}'",
            event="UPDATE",
        )
        _assert_evidence_abandoned(
            other, manifest, _finalize(other, (manifest,)), INVARIANT_VIOLATION
        )
        transaction = other.begin()
        try:
            facts = _ok(
                transaction.sanitized_manifests.get(
                    recorded.sanitized.sanitized_adapter_result_manifest_hash
                )
            )
        finally:
            transaction.rollback()
        assert not isinstance(facts, type(MISSING))
        assert not isinstance(facts.evidence_artifact_id, str)
    with _fresh(tmp_path, "v") as other:
        validated = _plan(other)
        _plant_invocation(other, OTHER_INVOCATION_ID, CommandKind.VALIDATE)
        result = _ok(
            validation_result_evidence(
                _validation_result(validated, OTHER_INVOCATION_ID),
                _SIBLING_OWNER,
                store=other.roots.store,
                unit_of_work=other.unit_of_work(),
                clock=other.clock,
            )
        )
        other.harness.install_refusing_trigger(
            "adapter_validation_results",
            f"NEW.invocation_id = '{OTHER_INVOCATION_ID}'",
            event="UPDATE",
        )
        sibling = EvidenceCorrelation(
            kind="INVOCATION", invocation_id=OTHER_INVOCATION_ID
        )
        _assert_evidence_abandoned(
            other, result, _finalize(other, (result,), sibling), INVARIANT_VIOLATION
        )
        transaction = other.begin()
        try:
            stored = _ok(transaction.validation_results.get(OTHER_INVOCATION_ID))
        finally:
            transaction.rollback()
        assert not isinstance(stored, type(MISSING))
        assert not isinstance(stored.evidence_artifact_id, str)


def test_recovery_refuses_foreign_groups_unknown_loads_and_a_junction(
    production: FinalizationFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """29.3 at its remaining refusals: a group whose first candidate is not a
    ``RUN`` owner's with its invocation; candidates naming an invocation or an
    experiment the registry does not hold (refused at the load, the work
    directory never observed); a junction planted at a declared path after the
    exit (refused before any open, nothing registered); and the qualifier's
    invocation fact read of an invocation the registry does not hold. A
    validator composed without a registrar answers the production facts."""
    plan = _plan(production)
    validator = production.validator
    token = _token(production)
    facts = _ok(
        validator.validate_temporary_manifest(plan.roots, token, plan.candidates)
    )
    unregistered = ResultRecoveryValidator(
        unit_of_work=production.unit_of_work(),
        hasher=production.hasher,
        negotiated_versions=DEFAULT_NEGOTIATED_VERSIONS,
        finalization_timeout_seconds=RESULT_TIMEOUT_SECONDS,
        clock=production.clock,
    )
    assert (
        _ok(
            unregistered.validate_temporary_manifest(plan.roots, token, plan.candidates)
        )
        == facts
    )
    adapter_first = sample_candidate("ADAPTER", _F.EVIDENCE, producer=_P.CORE)
    refused = validator.validate_temporary_manifest(
        plan.roots, token, (adapter_first, *plan.candidates)
    )
    assert _code(refused) == ARTIFACT_VALIDATION_FAILED
    assert "RUN-owned" in _message(refused)
    monkeypatch.setattr(finalization_module, "observe_candidates", _forbidden)
    unknown_owner = RunArtifactOwner(
        owner_kind="RUN",
        experiment_id=EXPERIMENT_ID,
        run_id=RUN_ID,
        invocation_id=_UNKNOWN_INVOCATION_ID,
    )
    foreign_owner = RunArtifactOwner(
        owner_kind="RUN",
        experiment_id=OTHER_EXPERIMENT_ID,
        run_id=RUN_ID,
        invocation_id=INVOCATION_ID,
    )
    for owner in (unknown_owner, foreign_owner):
        group = result_candidates(owner=owner, invocation_id=str(owner.invocation_id))
        refused = validator.validate_temporary_manifest(plan.roots, token, group)
        assert _code(refused) == INVARIANT_VIOLATION
        assert "does not exist" in _message(refused)
    monkeypatch.undo()
    qualifier = production.registrar
    assert isinstance(qualifier, CanonicalEvidenceQualifier)
    candidate = sample_candidate(
        "RUN",
        _F.EVIDENCE,
        producer=_P.CORE,
        owner=unknown_owner,
        artifact_kind=STDERR_KIND,
        staging_relative_path=f"INVOCATION/{_UNKNOWN_INVOCATION_ID}/{_STDERR_LEAF}",
    )
    verdict = qualifier.qualify_evidence(candidate, (_fallback_bytes(),))
    assert _code(verdict) == INVARIANT_VIOLATION
    assert "does not exist" in _message(verdict)
    assert isinstance(plan.roots.work_dir, Path)
    work_dir = plan.roots.work_dir
    elsewhere = production.tmp_path / "elsewhere"
    elsewhere.mkdir()
    for relative, data in RESULT_FILES.items():
        (elsewhere / Path(relative).name).write_bytes(data)
    shutil.rmtree(work_dir / "results")
    _winapi.CreateJunction(str(elsewhere), str(work_dir / "results"))
    try:
        monkeypatch.setattr(finalization_module, "scan_confined", _forbidden)
        refused = validator.validate_temporary_manifest(
            plan.roots, token, plan.candidates
        )
    finally:
        os.rmdir(work_dir / "results")
    assert _code(refused) == ARTIFACT_PATH_BOUNDARY_VIOLATION
    after = production.durable()
    assert after.run == plan.run
    assert after.journal == ()
    assert after.refs == ()
    _assert_consistent(production)


def _sanitized_row_of(
    plan: ProductionResultPlan, manifest_json: str, now: datetime
) -> _SanitizedRow:
    """The plan's sanitized row with ``manifest_json`` in place of the sanitized
    manifest's canonical text."""
    return _SanitizedRow(
        sanitized_adapter_result_manifest_hash=(
            plan.sanitized.sanitized_adapter_result_manifest_hash
        ),
        run_id=RUN_ID,
        run_invocation_id=INVOCATION_ID,
        experiment_id=EXPERIMENT_ID,
        attempt_token_hash=plan.sanitized.attempt_token_hash,
        source_adapter_result_manifest_hash=plan.parse.source_hash,
        semantic_status="SUCCEEDED",
        manifest_json=manifest_json,
        evidence_artifact_id=MISSING,
        recorded_at_utc=now,
    )


def _plant_sanitized_row_text(
    fixture: FinalizationFixture, plan: ProductionResultPlan, manifest_json: str
) -> None:
    """The plan's sanitized row planted through its port with ``manifest_json``
    in place of the sanitized manifest's canonical text."""
    transaction = fixture.begin()
    try:
        _ok(
            transaction.sanitized_manifests.add(
                _sanitized_row_of(plan, manifest_json, fixture.clock.now_utc())
            )
        )
        _ok(transaction.commit())
    finally:
        transaction.rollback()


def _sanitized_document(plan: ProductionResultPlan) -> dict[str, Any]:
    """The plan's sanitized manifest as the JSON object its row stores."""
    document = json.loads(canonical_json_text(plan.sanitized))
    assert isinstance(document, dict)
    return document


def _compact(document: dict[str, Any]) -> str:
    return json.dumps(document, sort_keys=True, separators=(",", ":"))


def _raising_with_marker(*args: object, **kwargs: object) -> Any:
    """A stand-in for a validation step that raises: the exception text exceeds
    the diagnostic bound and carries the synthetic marker, so a handler that
    interpolated it would overflow the bound or leak the text."""
    del args, kwargs
    raise ValueError(f"{_INPUT_MARKER} " * 60)


def _assert_fixed_reason_without_input_text(
    fixture: FinalizationFixture, refused: object, fragment: str
) -> None:
    """Reading 7: the translated invariant carries a fixed reason within the
    ``Diagnostic`` bound, and neither the exception text nor the planted input
    reaches the returned diagnostic, a recorded diagnostic, an audit event or a
    log line of the finalizer."""
    assert _code(refused) == INVARIANT_VIOLATION, _message(refused)
    message = _message(refused)
    assert fragment in message
    assert len(message) <= _DIAGNOSTIC_MESSAGE_BOUND
    assert "validation error" not in message
    assert _INPUT_MARKER not in repr(refused)
    after = fixture.durable()
    for diagnostic in after.diagnostics:
        assert "validation error" not in diagnostic.message
        assert _INPUT_MARKER not in repr(diagnostic)
    for event in after.audit_events:
        assert _INPUT_MARKER not in repr(event)
    for fact in fixture.log.facts:
        assert _INPUT_MARKER not in repr(fact)


def test_result_registration_rolls_back_corrupt_rows_and_refused_row_writes(
    production: FinalizationFixture, tmp_path: Path
) -> None:
    """Plan 4.4 inside T3: a stored sanitized row whose text no longer parses as
    the sanitized manifest (one field outside its vocabulary), a remembered
    manifest whose row write the database refuses and a reference row the
    database refuses each roll the RESULT registration back whole -- the run
    stays ``RUNNING`` at its lease revision, no manifest, reference or success
    fact is committed and the journal is ``ABANDONED`` under the invariant."""
    plan = _plan(production, sanitized_row=False)
    text = canonical_json_text(plan.sanitized)
    assert text.count('"semantic_status":"SUCCEEDED"') == 1
    _plant_sanitized_row_text(
        production,
        plan,
        text.replace('"semantic_status":"SUCCEEDED"', '"semantic_status":"BOGUS"'),
    )
    _assert_result_rolled_back(
        production,
        plan,
        production.finalize_result(plan),
        INVARIANT_VIOLATION,
        "does not validate",
    )
    with _fresh(tmp_path, "m") as other:
        remembered = _plan(other, sanitized_row=False)
        registrar = other.registrar
        assert isinstance(registrar, ResultRegistrar)
        registrar.remember(remembered.sanitized)
        other.harness.install_refusing_trigger(
            "sanitized_adapter_result_manifests", f"NEW.run_id = '{RUN_ID}'"
        )
        _assert_result_rolled_back(
            other,
            remembered,
            other.finalize_result(remembered),
            INVARIANT_VIOLATION,
            None,
        )
        assert other.harness.count("sanitized_adapter_result_manifests") == 0
    with _fresh(tmp_path, "f") as other:
        referenced = _plan(other)
        first = referenced.candidates[0]
        refused_id = artifact_id_for(
            first.candidate_artifact_id, str(first.adapter_declared_hash)
        )
        other.harness.install_refusing_trigger(
            "artifact_refs", f"NEW.artifact_id = '{refused_id}'"
        )
        _assert_result_rolled_back(
            other,
            referenced,
            other.finalize_result(referenced),
            INVARIANT_VIOLATION,
            None,
        )


def test_a_stored_manifest_missing_many_fields_is_still_the_invariant(
    production: FinalizationFixture,
) -> None:
    """Reading 7: a stored sanitized row whose object carries only
    ``schema_version`` -- every other field missing -- is the same
    ``CORE.INVARIANT_VIOLATION`` as a one-field corruption. The registrar
    translates the parse failure into a fixed, bounded reason instead of
    interpolating the many-field exception text, which would overflow the
    diagnostic bound and escape T3 as an exception; the RESULT registration
    rolls back whole and the run stays ``RUNNING`` at its lease revision."""
    plan = _plan(production, sanitized_row=False)
    _plant_sanitized_row_text(production, plan, '{"schema_version":"1.0.0"}')
    refused = production.finalize(plan.request, log=production.log)
    _assert_result_rolled_back(
        production, plan, refused, INVARIANT_VIOLATION, "does not validate"
    )
    _assert_fixed_reason_without_input_text(production, refused, "does not validate")


def test_malformed_stored_manifests_share_one_bounded_invariant(
    production: FinalizationFixture, tmp_path: Path
) -> None:
    """Reading 7 over the stored object's refusal shapes -- fields of the wrong
    type, an unexpected field named by the synthetic marker, a literal outside
    its vocabulary beside a missing field -- each the fixed invariant through
    the production registrar with the T3 rollback: the reason stays within the
    bound and neither the marker nor the exception text reaches the returned
    diagnostic, the recorded one, an audit event or a log line. Text that is
    not a JSON object never reaches the registrar: the row's schema check
    (migration r0002) refuses it at the store under the same code, so
    malformed JSON is refused one boundary earlier."""
    typed = _plan(production, sanitized_row=False)
    document = _sanitized_document(typed)
    document["run_id"] = 12345
    document["candidate_metrics"] = _INPUT_MARKER
    document["started_at_utc"] = _INPUT_MARKER
    _plant_sanitized_row_text(production, typed, _compact(document))
    refused = production.finalize(typed.request, log=production.log)
    _assert_result_rolled_back(
        production, typed, refused, INVARIANT_VIOLATION, "does not validate"
    )
    _assert_fixed_reason_without_input_text(production, refused, "does not validate")
    with _fresh(tmp_path, "x") as other:
        extra = _plan(other, sanitized_row=False)
        document = _sanitized_document(extra)
        document[_INPUT_MARKER] = _INPUT_MARKER
        _plant_sanitized_row_text(other, extra, _compact(document))
        refused = other.finalize(extra.request, log=other.log)
        _assert_result_rolled_back(
            other, extra, refused, INVARIANT_VIOLATION, "does not validate"
        )
        _assert_fixed_reason_without_input_text(other, refused, "does not validate")
    with _fresh(tmp_path, "l") as other:
        literal = _plan(other, sanitized_row=False)
        document = _sanitized_document(literal)
        document["protocol_version"] = _INPUT_MARKER
        del document["provenance"]
        _plant_sanitized_row_text(other, literal, _compact(document))
        refused = other.finalize(literal.request, log=other.log)
        _assert_result_rolled_back(
            other, literal, refused, INVARIANT_VIOLATION, "does not validate"
        )
        _assert_fixed_reason_without_input_text(other, refused, "does not validate")
    with _fresh(tmp_path, "j") as other:
        unparsable = _plan(other, sanitized_row=False)
        before = other.durable()
        for text in (f'{{"schema_version": {_INPUT_MARKER}', f'["{_INPUT_MARKER}"]'):
            transaction = other.begin()
            try:
                planted = transaction.sanitized_manifests.add(
                    _sanitized_row_of(unparsable, text, other.clock.now_utc())
                )
            finally:
                transaction.rollback()
            assert _code(planted) == INVARIANT_VIOLATION, text
            assert _INPUT_MARKER not in repr(planted)
        assert other.durable() == before
        assert other.harness.count("sanitized_adapter_result_manifests") == 0


def _assert_run_failed_after_abandonment(
    fixture: FinalizationFixture,
    plan: ProductionResultPlan,
    concluded: CommandConclusion,
    fragment: str | None,
    *,
    from_state: str,
) -> Diagnostic:
    """21.2.1 (``CORE.INVARIANT_VIOLATION``: fail the affected run) through
    ``conclude_command`` once the finalizer abandoned the RESULT journal under
    the invariant: the run durably ``FAILED`` at its post-lease revision with
    the invariant diagnostic as primary, ``RUN_FAILED`` once under the
    invocation correlation, no run manifest, result reference, member link or
    success fact, the journal ``ABANDONED`` under the invariant from
    ``from_state`` with every requested candidate quarantined by that very
    diagnostic, and the token-bearing root closed exactly once (the finalizer's
    T4; the failure path found no raw byte to close again). Returns the primary
    diagnostic for the caller's own checks."""
    assert concluded.run.state is EngineRunState.FAILED
    assert concluded.run.revision == plan.run.revision + 2
    assert concluded.replayed is False
    assert not isinstance(concluded.finalization, FinalizationResult)
    assert not isinstance(concluded.run_manifest, RunManifest)
    assert concluded.result_refs == ()
    after = fixture.durable()
    assert after.run == concluded.run
    assert after.run_state == "FAILED"
    assert after.run_revision == plan.run.revision + 2
    (entry,) = [
        item for item in after.journal if item.finalization_purpose is _F.RESULT
    ]
    assert entry.state.value == "ABANDONED"
    assert entry.abandon_reason == INVARIANT_VIOLATION
    assert entry.expected_run_revision == plan.run.revision + 1
    assert after.run is not None
    primary_id = after.run.primary_terminal_diagnostic_id
    assert isinstance(primary_id, str)
    (primary,) = [
        item for item in after.diagnostics if item.diagnostic_id == primary_id
    ]
    assert primary.error_code == INVARIANT_VIOLATION
    if fragment is not None:
        assert fragment in primary.message
    assert len(primary.message) <= _DIAGNOSTIC_MESSAGE_BOUND
    assert entry.candidate_artifact_ids
    states = after.candidate_states
    for candidate in after.candidates:
        if candidate.candidate_artifact_id not in entry.candidate_artifact_ids:
            continue
        assert states[candidate.candidate_artifact_id] == "QUARANTINED"
        (quarantine,) = [
            observation
            for observation in candidate.validation_observations
            if observation.stage == "MOVE" and observation.outcome == "FAILED"
        ]
        assert quarantine.error_code == INVARIANT_VIOLATION
        assert quarantine.diagnostic_id == primary_id
    assert after.run_manifests == ()
    assert all(ref.finalization_purpose is _F.EVIDENCE for ref in after.refs)
    assert all(link.link_role == "RUN_EVIDENCE" for link in after.run_artifacts)
    actions = after.audit_actions
    assert actions.count("RUN_FAILED") == 1
    (failed_event,) = [
        event for event in after.audit_events if event.action.value == "RUN_FAILED"
    ]
    assert failed_event.correlation_id == INVOCATION_ID
    assert failed_event.outcome.value == "FAILED"
    assert failed_event.details == {"reason": INVARIANT_VIOLATION}
    (abandoned_event,) = [
        event
        for event in after.audit_events
        if event.action.value == "FINALIZATION_ABANDONED"
    ]
    assert abandoned_event.details["reason"] == INVARIANT_VIOLATION
    assert abandoned_event.details["from_state"] == from_state
    assert actions.count("ARTIFACT_QUARANTINED") >= len(entry.candidate_artifact_ids)
    assert "RUN_MANIFEST_REGISTERED" not in actions
    assert "RUN_SUCCEEDED" not in actions
    assert actions.count("RETENTION_DELETED") == 1
    assert not plan.roots.request_path.exists()
    assert isinstance(plan.roots.result_path, Path)
    assert not plan.roots.result_path.exists()
    _assert_consistent(fixture)
    return primary


def _assert_failed_run_survives_a_reopen(
    fixture: FinalizationFixture, plan: ProductionResultPlan, primary_id: str
) -> None:
    """The terminal facts read back after the database is closed and reopened
    (plan 7.1): nothing of the ``FAILED`` write lived in a session."""
    fixture.reopen()
    reopened = fixture.durable()
    assert reopened.run_state == "FAILED"
    assert reopened.run_revision == plan.run.revision + 2
    assert reopened.run is not None
    assert reopened.run.primary_terminal_diagnostic_id == primary_id
    assert primary_id in {item.diagnostic_id for item in reopened.diagnostics}
    (entry,) = [
        item for item in reopened.journal if item.finalization_purpose is _F.RESULT
    ]
    assert entry.state.value == "ABANDONED"
    assert entry.abandon_reason == INVARIANT_VIOLATION
    assert reopened.run_manifests == ()
    assert all(ref.finalization_purpose is _F.EVIDENCE for ref in reopened.refs)
    assert reopened.audit_actions.count("RUN_FAILED") == 1
    assert reopened.audit_actions.count("RETENTION_DELETED") == 1
    _assert_consistent(fixture)


def test_an_abandoned_registrar_invariant_fails_the_run_in_the_conclusion(
    production: FinalizationFixture,
) -> None:
    """21.2.1 through ``conclude_command`` when the T3 registrar meets a stored
    sanitized row that is not the manifest: the finalizer abandons the RESULT
    journal under ``CORE.INVARIANT_VIOLATION`` from ``MOVED``, quarantines the
    candidates and closes the token-bearing root, and the conclusion -- the
    caller that owns the run's ``FAILED`` write (plan 4.4 step 3) -- moves the
    run ``RUNNING -> FAILED`` at its durable post-lease revision through
    ``fail_run_for_refusal`` with the invariant diagnostic as primary, audits
    ``RUN_FAILED`` once and closes nothing a second time. The conclusion then
    continues to the staged evidence (29.1): here the sanitized-manifest
    evidence disagrees with the planted row, so the one evidence request is
    refused without touching the run's outcome. Reading 7 holds over the whole
    route: the fixed reason stays within the bound and the planted marker
    reaches no diagnostic, fact, log line or returned value."""
    plan = _plan(production, sanitized_row=False)
    document = _sanitized_document(plan)
    document[_INPUT_MARKER] = _INPUT_MARKER
    _plant_sanitized_row_text(production, plan, _compact(document))
    observed = _observe(production, plan)
    concluded = _ok(
        conclude_command(
            SemanticOutcome(
                invocation=plan.invocation,
                run=plan.run,
                reconciliation=_reconcile(production, plan, observed),
            ),
            _command_result(plan, stderr=_capture(), events=False),
            plan.parse,
            plan.summary,
            observed,
            roots=plan.roots,
            token=_token(production),
            config=_config(production),
            unit_of_work=production.unit_of_work(),
            finalizer=production.finalizer(log=production.log),
            clock=production.clock,
        )
    )
    primary = _assert_run_failed_after_abandonment(
        production, plan, concluded, "does not validate", from_state="MOVED"
    )
    assert "validation error" not in primary.message
    assert isinstance(concluded.evidence_failure, Failure)
    assert _code(concluded.evidence_failure) == ARTIFACT_VALIDATION_FAILED
    assert concluded.evidence_refs == ()
    assert _INPUT_MARKER not in repr(concluded)
    after = production.durable()
    assert after.refs == ()
    assert after.run_artifacts == ()
    for diagnostic in after.diagnostics:
        assert "validation error" not in diagnostic.message
        assert _INPUT_MARKER not in repr(diagnostic)
    for event in after.audit_events:
        assert _INPUT_MARKER not in repr(event)
    for fact in production.log.facts:
        assert _INPUT_MARKER not in repr(fact)
    _assert_failed_run_survives_a_reopen(production, plan, primary.diagnostic_id)


def test_a_phase_three_blob_collision_fails_the_run_and_keeps_its_evidence(
    production: FinalizationFixture,
) -> None:
    """21.2.1 through ``conclude_command`` when the finalizer's phase 3 meets a
    finalized blob at a candidate's content address whose bytes differ (reading
    21: ``CORE.INVARIANT_VIOLATION``, nothing overwritten or deleted): the
    journal is abandoned from ``PREPARED`` under the invariant, the run moves
    ``RUNNING -> FAILED`` at its post-lease revision with that diagnostic as
    primary, and the invocation's stderr, protocol capture and sanitized
    manifest -- each agreeing with its facts -- continue through the production
    evidence route after the terminal write and register under the invocation
    correlation, the stderr enrichment included."""
    plan = _plan(production)
    first = plan.candidates[0]
    blob = production.roots.store.finalized_path_for(str(first.adapter_declared_hash))
    blob.parent.mkdir(parents=True, exist_ok=True)
    planted = b"another blob already stands at this content address\n"
    blob.write_bytes(planted)
    concluded = _ok(_conclude(production, plan, stderr=_capture()))
    primary = _assert_run_failed_after_abandonment(
        production,
        plan,
        concluded,
        "differs from the content hash",
        from_state="PREPARED",
    )
    assert blob.read_bytes() == planted
    assert not isinstance(concluded.evidence_failure, Failure)
    assert {ref.artifact_kind for ref in concluded.evidence_refs} == {
        STDERR_KIND,
        PROTOCOL_CAPTURE_KIND,
        SANITIZED_MANIFEST_KIND,
    }
    assert isinstance(concluded.invocation.stderr_artifact_id, str)
    after = production.durable()
    assert {link.link_role for link in after.run_artifacts} == {"RUN_EVIDENCE"}
    assert len(after.run_artifacts) == 3
    assert after.invocation is not None
    enriched = after.invocation.stderr_artifact_id
    assert enriched == concluded.invocation.stderr_artifact_id
    (evidence_entry,) = [
        item for item in after.journal if item.finalization_purpose is _F.EVIDENCE
    ]
    assert evidence_entry.state.value == "REGISTERED"
    assert after.quarantine_entries
    assert all(item["exact_scan"] is True for item in _validated_details(production))
    _assert_failed_run_survives_a_reopen(production, plan, primary.diagnostic_id)


def test_a_journal_read_fault_after_the_invariant_is_the_storage_failure(
    production: FinalizationFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The Stage 8 fault boundary at the conclusion's read that tells a
    permanent abandonment from a pre-lease invariant -- the RESULT journal
    looked up after the finalizer returned ``CORE.INVARIANT_VIOLATION``. A
    driver fault there is ``PERSISTENCE.WRITE_FAILED`` returned in place of the
    invariant with the failure path never started: the run ``RUNNING`` at its
    lease revision, the journal ``ABANDONED``, no ``RUN_FAILED`` fact -- the
    storage failure reported, never a silent fall-through. The read position is
    the finalizer's deterministic statement order over this fixture: its own
    journal reads at the open, T1, T2 and the abandonment precede it."""
    plan = _plan(production, sanitized_row=False)
    _plant_sanitized_row_text(production, plan, '{"schema_version":"1.0.0"}')
    with cursor_fault(production.database, monkeypatch) as fault:
        fault.arm(_read_error(), when=_reads("finalization_journal", skip=4))
        refused = _conclude(production, plan, stderr=_capture(), events=False)
        assert not fault.armed
    assert _code(refused) == WRITE_FAILED, _message(refused)
    state = production.durable()
    assert state.run_state == "RUNNING"
    assert state.run_revision == plan.run.revision + 1
    assert state.journal_state == "ABANDONED"
    assert state.abandon_reason == INVARIANT_VIOLATION
    assert "RUN_FAILED" not in state.audit_actions
    assert state.run_manifests == ()
    assert state.refs == ()
    assert state.audit_actions.count("RETENTION_DELETED") == 1
    assert not plan.roots.request_path.exists()
    # The conclusion stopped at that read: the staged stderr awaits no
    # finalization and the stored invariant is the only recorded refusal.
    stderr_id = _core_stderr_id(RUN_OWNER, INVOCATION_ID)
    assert state.candidate_states[stderr_id] == "CANDIDATE"
    assert state.journal[0].candidate_artifact_ids
    _assert_consistent(production)


def test_sibling_validation_handlers_translate_to_fixed_bounded_reasons(
    production: FinalizationFixture, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Reading 7 at the module's other exception translations: the run-manifest
    construction and the success swap inside the RESULT T3, the write-once
    stderr enrichment inside the EVIDENCE T3 and the ``FAILED`` write of the
    run failure path each meet a validation step whose exception text exceeds
    the diagnostic bound and carries the synthetic marker. Each is the fixed
    invariant with its transaction rolled back and the text reaching nothing."""
    built = _plan(production)
    monkeypatch.setattr(finalization_module, "_run_manifest", _raising_with_marker)
    refused = production.finalize(built.request, log=production.log)
    monkeypatch.undo()
    _assert_result_rolled_back(
        production, built, refused, INVARIANT_VIOLATION, "run manifest"
    )
    _assert_fixed_reason_without_input_text(production, refused, "does not validate")
    with _fresh(tmp_path, "s") as other:
        swapped = _plan(other)
        monkeypatch.setattr(
            finalization_module, "assert_run_transition", _raising_with_marker
        )
        refused = other.finalize(swapped.request, log=other.log)
        monkeypatch.undo()
        _assert_result_rolled_back(
            other, swapped, refused, INVARIANT_VIOLATION, "admits no success write"
        )
        _assert_fixed_reason_without_input_text(other, refused, "success write")
    with _fresh(tmp_path, "e") as other:
        _plan(other)
        stderr = _stage_stderr(other)
        monkeypatch.setattr(
            finalization_module, "assert_write_once_enrichment", _raising_with_marker
        )
        refused = finalize_evidence(
            (stderr,), INVOCATION_CORRELATION, finalizer=other.finalizer(log=other.log)
        )
        monkeypatch.undo()
        _assert_evidence_abandoned(other, stderr, refused, INVARIANT_VIOLATION)
        _assert_fixed_reason_without_input_text(
            other, refused, "admits no stderr enrichment"
        )
        state = other.durable()
        assert state.invocation is not None
        assert not isinstance(state.invocation.stderr_artifact_id, str)
    with _fresh(tmp_path, "f") as other:
        failing = _plan(other)
        refusal = artifact_failure(
            ARTIFACT_RESULT_MANIFEST_INVALID,
            message="the temporary result manifest does not validate",
            now_utc=other.clock.now_utc(),
            experiment_id=EXPERIMENT_ID,
            run_id=RUN_ID,
            invocation_id=INVOCATION_ID,
        )
        before = other.durable()
        monkeypatch.setattr(
            finalization_module, "assert_run_transition", _raising_with_marker
        )
        refused = fail_run_for_refusal(
            refusal,
            run_id=RUN_ID,
            expected_run_revision=failing.run.revision,
            roots=failing.roots,
            config=_config(other),
            unit_of_work=other.unit_of_work(),
            clock=other.clock,
        )
        monkeypatch.undo()
        _assert_fixed_reason_without_input_text(
            other, refused, "admits no FAILED write"
        )
        assert other.durable() == before
        assert failing.roots.request_path.is_file()


def test_registrar_and_recovery_rule_refusals_carry_their_fixed_reasons(
    production: FinalizationFixture, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Two more translations with fixed reasons. A stored sanitized row whose
    object is a valid ``FAILED`` manifest filed under the journal's success
    hash parses, agrees with the journal on every identity and is still the
    registrar's invariant (``registers no RESULT``) with the T3 rollback. A
    caller-error rule violation raised by the Stage 6 reconciliation inside the
    recovery validator is the invariant carrying the rule's own fixed text,
    with nothing written."""
    plan = _plan(production, sanitized_row=False)
    document = _sanitized_document(plan)
    document["semantic_status"] = "FAILED"
    document["candidate_artifact_ids"] = []
    document["candidate_declarations"] = []
    document["diagnostics"] = [
        {
            "error_code": "ENGINE.CRASHED",
            "category": "ENGINE_RUNTIME",
            "severity": "ERROR",
            "message": "the engine reported a runtime failure",
            "retriable": True,
            "details": {},
            "causal_event_ids": [],
        }
    ]
    content = {
        name: value
        for name, value in document.items()
        if name != "sanitized_adapter_result_manifest_hash"
    }
    document["sanitized_adapter_result_manifest_hash"] = profile_hash(
        HashingProfile.SANITIZED_ADAPTER_RESULT_MANIFEST_V1, content
    )
    failed = SanitizedAdapterResultManifest.model_validate_json(_compact(document))
    assert failed.semantic_status is SemanticStatus.FAILED
    _plant_sanitized_row_text(production, plan, _compact(document))
    _assert_result_rolled_back(
        production,
        plan,
        production.finalize_result(plan),
        INVARIANT_VIOLATION,
        "FAILED manifest registers no RESULT",
    )
    with _fresh(tmp_path, "v") as other:
        recovered = _plan(other)
        before = other.durable()

        def violating(*args: object, **kwargs: object) -> Any:
            del args, kwargs
            raise ReconciliationRuleViolation("the invocation is not linked to the run")

        monkeypatch.setattr(finalization_module, "reconcile_run", violating)
        refused = other.validator.validate_temporary_manifest(
            recovered.roots, _token(other), recovered.candidates
        )
        monkeypatch.undo()
        assert _code(refused) == INVARIANT_VIOLATION
        assert _message(refused) == "the invocation is not linked to the run"
        assert other.durable() == before


def test_conclude_command_returns_step_two_refusals_before_any_lease(
    production: FinalizationFixture, tmp_path: Path
) -> None:
    """Plan 4.4 step 2 under the failure column, through ``conclude_command``: a
    refused result-candidate row, a refused stderr, protocol-capture or
    sanitized-manifest staging and a refused validation-result row each end the
    conclusion with the database's invariant before any lease -- the run row,
    the raw bytes and the journal untouched, nothing finalized. A conclusion
    the core superseded (the run cancelled before the verdict applied) carries
    no reconciliation: it stages and finalizes the evidence that exists and
    closes its terminal root."""
    plan = _plan(production, plant_candidates=False)
    last = plan.summary.artifact_declarations[-1].payload.relative_path
    last_id = candidate_artifact_id_for(RUN_ID, INVOCATION_ID, last)
    production.harness.install_refusing_trigger(
        "candidate_artifacts", f"NEW.candidate_artifact_id = '{last_id}'"
    )
    _assert_refused_before_any_lease(
        production, plan, _conclude(production, plan, events=False)
    )
    assert production.durable().candidates == ()
    run_hash = artifact_owner_hash(RUN_OWNER)
    with _fresh(tmp_path, "s") as other:
        staged = _plan(other)
        stderr_id = _core_stderr_id(RUN_OWNER, INVOCATION_ID)
        other.harness.install_refusing_trigger(
            "candidate_artifacts", f"NEW.candidate_artifact_id = '{stderr_id}'"
        )
        _assert_refused_before_any_lease(
            other, staged, _conclude(other, staged, stderr=_capture(), events=False)
        )
        assert f"{run_hash}/INVOCATION/{INVOCATION_ID}/stderr.txt" in (
            other.durable().staging_files
        )
    with _fresh(tmp_path, "t") as other:
        captured = _plan(other)
        capture_id = core_candidate_artifact_id_for(
            run_hash, "INVOCATION", INVOCATION_ID, "protocol-capture.jsonl"
        )
        other.harness.install_refusing_trigger(
            "candidate_artifacts", f"NEW.candidate_artifact_id = '{capture_id}'"
        )
        _assert_refused_before_any_lease(other, captured, _conclude(other, captured))
    with _fresh(tmp_path, "w") as other:
        unrecorded = _plan(other, sanitized_row=False)
        other.harness.install_refusing_trigger(
            "sanitized_adapter_result_manifests", f"NEW.run_id = '{RUN_ID}'"
        )
        _assert_refused_before_any_lease(
            other, unrecorded, _conclude(other, unrecorded, events=False)
        )
        assert other.harness.count("sanitized_adapter_result_manifests") == 0
    with _fresh(tmp_path, "y") as other:
        prestate = other.plant_run(run_state=EngineRunState.READY)
        validate = sample_invocation(
            CommandInvocationState.EXITED,
            kind=CommandKind.VALIDATE,
            invocation_id=OTHER_INVOCATION_ID,
        )
        put_invocation(other.harness.lifecycle(), validate)
        roots = _command_root(other, OTHER_INVOCATION_ID, b'{"outcome": "VALID"}')
        other.harness.install_refusing_trigger(
            "adapter_validation_results", f"NEW.invocation_id = '{OTHER_INVOCATION_ID}'"
        )
        validated = SemanticReconciliation.model_validate(
            {
                "command_kind": CommandKind.VALIDATE,
                "verdict": ReconciliationVerdict.VALIDATED_READY,
                "run_target_state": EngineRunState.READY,
                "diagnostics": (),
                "sanitized_validation_result": _validation_result_of(
                    prestate.run.attempt_token_hash, OTHER_INVOCATION_ID
                ),
            }
        )
        refused = conclude_command(
            SemanticOutcome(
                invocation=validate, run=prestate.run, reconciliation=validated
            ),
            CommandResult(
                invocation=validate,
                protocol_integrity=ProtocolIntegrityStatus.INTACT,
                accepted_events=(),
                diagnostics=(),
                cancelled=False,
                timed_out=False,
            ),
            MISSING,
            _EMPTY_SUMMARY,
            (),
            roots=roots,
            token=MISSING,
            config=_config(other),
            unit_of_work=other.unit_of_work(),
            finalizer=other.finalizer(),
            clock=other.clock,
        )
        assert _code(refused) == INVARIANT_VIOLATION
        state = other.durable()
        assert state.run == prestate.run
        assert state.journal == ()
        assert state.refs == ()
        assert state.staging_files == ()
        assert other.harness.count("adapter_validation_results") == 0
        assert roots.request_path.is_file()
    with _fresh(tmp_path, "p") as other:
        superseded = _plan(other)
        cancelled = other.cancel_run()
        concluded = _ok(
            _conclude(
                other,
                superseded,
                outcome=SemanticOutcome(
                    invocation=superseded.invocation,
                    run=cancelled,
                    superseded_by=EngineRunState.CANCELLED,
                ),
                observations=(),
                stderr=_capture(),
                events=False,
                parsed=False,
            )
        )
        assert concluded.run.state is EngineRunState.CANCELLED
        assert concluded.run.revision == cancelled.revision
        assert not isinstance(concluded.finalization, FinalizationResult)
        assert not isinstance(concluded.run_manifest, RunManifest)
        assert [ref.artifact_kind for ref in concluded.evidence_refs] == [STDERR_KIND]
        assert not isinstance(concluded.evidence_failure, Failure)
        assert not superseded.roots.request_path.exists()
        state = other.durable()
        assert state.run_state == "CANCELLED"
        assert state.run_manifests == ()
        assert state.audit_actions.count("RETENTION_DELETED") == 1
        _assert_consistent(other)


def test_run_failure_refusals_reach_the_caller_and_write_nothing(
    production: FinalizationFixture, tmp_path: Path
) -> None:
    """Plan 4.4 steps 0 and 3 when the failure path itself is refused: a run the
    registry does not hold, a refusal diagnostic already recorded with other
    content (the content-addressed collision) and a refused ``RUN_FAILED`` fact
    inside a conclusion each reach the caller as the refusal with the run still
    ``RUNNING``, no diagnostic or fact committed and the raw bytes in place; a
    verdict diagnostic colliding the same way ends the conclusion before
    anything is staged."""
    plan = _plan(production)
    refusal = artifact_failure(
        ARTIFACT_RESULT_MANIFEST_INVALID,
        message="the temporary result manifest does not validate",
        now_utc=production.clock.now_utc(),
        experiment_id=EXPERIMENT_ID,
        run_id=RUN_ID,
        invocation_id=INVOCATION_ID,
    )
    before = production.durable()
    unknown = fail_run_for_refusal(
        refusal,
        run_id=OTHER_RUN_ID,
        expected_run_revision=plan.run.revision,
        roots=plan.roots,
        config=_config(production),
        unit_of_work=production.unit_of_work(),
        clock=production.clock,
    )
    assert _code(unknown) == INVARIANT_VIOLATION
    assert "does not exist" in _message(unknown)
    assert production.durable() == before
    twin = refusal.diagnostics[0].model_copy(
        update={"message": "recorded earlier with other content"}
    )
    _record(production, twin)
    collided = fail_run_for_refusal(
        refusal,
        run_id=RUN_ID,
        expected_run_revision=plan.run.revision,
        roots=plan.roots,
        config=_config(production),
        unit_of_work=production.unit_of_work(),
        clock=production.clock,
    )
    assert _code(collided) == INVARIANT_VIOLATION
    assert "different content" in _message(collided)
    after = production.durable()
    assert after.run == plan.run
    assert after.audit_actions == ()
    assert plan.roots.request_path.is_file()
    (stored,) = [
        item for item in after.diagnostics if item.diagnostic_id == twin.diagnostic_id
    ]
    assert stored.message == twin.message
    _assert_consistent(production)
    with _fresh(tmp_path, "c") as other:
        colliding = _plan(other)
        wrong = tuple(
            item.model_copy(update={"observed_sha256": "0" * 64})
            for item in _observe(other, colliding)
        )
        reconciliation = _reconcile(other, colliding, wrong)
        primary = reconciliation.primary_diagnostic
        assert isinstance(primary, Diagnostic)
        _record(
            other,
            primary.model_copy(
                update={"message": "recorded earlier with other content"}
            ),
        )
        state = other.durable()
        refused = _conclude(
            other,
            colliding,
            outcome=SemanticOutcome(
                invocation=colliding.invocation,
                run=colliding.run,
                reconciliation=reconciliation,
            ),
            observations=wrong,
            stderr=_capture(),
            events=False,
        )
        assert _code(refused) == INVARIANT_VIOLATION
        assert "different content" in _message(refused)
        assert other.durable() == state
    with _fresh(tmp_path, "r") as other:
        corrupt = _plan(other)
        reconciliation = _reconcile(other, corrupt)
        assert isinstance(corrupt.roots.work_dir, Path)
        corrupt.roots.work_dir.joinpath("results", "native.bin").write_bytes(
            b"changed after the verdict\n"
        )
        refusing = RefusingAuditor(
            other.audit_ids,
            other.clock,
            refused_action="RUN_FAILED",
            failure=_audit_refusal(other),
        )
        refused = conclude_command(
            SemanticOutcome(
                invocation=corrupt.invocation,
                run=corrupt.run,
                reconciliation=reconciliation,
            ),
            _command_result(corrupt, events=False),
            corrupt.parse,
            corrupt.summary,
            (),
            roots=corrupt.roots,
            token=_token(other),
            config=_config_with(other, refusing),
            unit_of_work=other.unit_of_work(),
            finalizer=other.finalizer(),
            clock=other.clock,
        )
        assert _code(refused) == _AUDIT_REFUSED
        assert refusing.refusals == 1
        state = other.durable()
        # The finalizer refused before any lease: the run row is as planted and
        # the refused failure path committed neither the FAILED write nor its
        # diagnostic.
        assert state.run == corrupt.run
        assert "RUN_FAILED" not in state.audit_actions
        assert state.run_manifests == ()
        assert state.refs == ()
        assert corrupt.roots.request_path.is_file()
        _assert_consistent(other)


def test_conclude_describe_returns_its_staging_and_finalization_failures(
    production: FinalizationFixture,
) -> None:
    """Plan 4.6 for ``conclude_describe`` under its failure column: a describe
    without a stderr capture finalizes the descriptor alone; a descriptor whose
    staging path already holds other bytes is the store's invariant with
    nothing finalized and no stderr staged; a describe invocation the registry
    does not hold refuses its stderr at the staging boundary; a reconciliation
    diagnostic already recorded with other content ends the conclusion before
    any staging; and a token-shaped stderr is the finalizer's refusal returned
    to the caller beside the registered descriptor, the capture quarantined (no
    29.1 tolerance applies to a describe)."""
    production.plant_run()
    second_id, third_id, fourth_id = _MORE_DESCRIBE_INVOCATION_IDS
    described = _describe_context(production, _DESCRIBE_INVOCATION_ID)
    refs = _ok(_conclude_describe(production, described))
    assert [ref.artifact_kind for ref in refs] == ["adapter-descriptor"]
    assert all(ref.owner == _ENGINE_OWNER for ref in refs)
    before = production.durable()
    assert before.journal_state == "REGISTERED"
    assert [ref.artifact_kind for ref in before.refs] == ["adapter-descriptor"]
    occupied = _describe_context(production, second_id)
    planted = _stage(
        production,
        _ENGINE_OWNER,
        "adapter-descriptor",
        _DESCRIPTOR_LEAF,
        _LOOSE_JSON,
        EvidenceCorrelation(kind="INVOCATION", invocation_id=second_id),
        role=_R.ADAPTER_DESCRIPTOR_EVIDENCE,
    )
    differing = _conclude_describe(
        production, occupied, stderr=_capture("describe stderr\n")
    )
    assert _code(differing) == INVARIANT_VIOLATION
    after = production.durable()
    assert after.journal == before.journal
    assert after.refs == before.refs
    assert _staged_bytes(production, planted) == _LOOSE_JSON
    engine_hash = artifact_owner_hash(_ENGINE_OWNER)
    assert f"{engine_hash}/INVOCATION/{second_id}/stderr.txt" not in (
        after.staging_files
    )
    unstored = _describe_context(production, _UNKNOWN_INVOCATION_ID, stored=False)
    refused = _conclude_describe(
        production, unstored, stderr=_capture("describe stderr\n"), with_parse=False
    )
    assert _code(refused) == INVARIANT_VIOLATION
    assert "does not exist" in _message(refused)
    assert production.durable().staging_files == after.staging_files
    unparsed = _describe_context(production, third_id, envelope=False)
    (primary,) = unparsed.reconciliation.diagnostics
    _record(
        production,
        primary.model_copy(update={"message": "recorded earlier with other content"}),
    )
    colliding = _conclude_describe(
        production, unparsed, stderr=_capture("describe stderr\n"), with_parse=False
    )
    assert _code(colliding) == INVARIANT_VIOLATION
    assert "different content" in _message(colliding)
    assert production.durable().staging_files == after.staging_files
    shaped = _describe_context(production, fourth_id)
    leaked = _conclude_describe(production, shaped, stderr=_capture(_SHAPED_TEXT))
    assert _code(leaked) == SECURITY_SENSITIVE_MATERIAL_LEAKAGE
    final = production.durable()
    assert [ref.artifact_kind for ref in final.refs] == [
        "adapter-descriptor",
        "adapter-descriptor",
    ]
    assert final.candidate_states[_core_stderr_id(_ENGINE_OWNER, fourth_id)] == (
        "QUARANTINED"
    )
    assert final.run == before.run
    for context in (described, occupied, unstored, unparsed, shaped):
        assert context.roots.request_path.is_file()
    _assert_consistent(production)


def test_replay_refuses_an_unknown_invocation_for_a_succeeded_run(
    production: FinalizationFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reading 24 at its load: a request naming a succeeded run under an
    invocation the registry does not hold is refused at the stored conclusion's
    invocation read; the Stage 6 operation is never consulted and nothing is
    written."""
    plan = _plan(production)
    observations = _observe(production, plan)
    conclusion = _ok(
        _conclude(production, plan, observations=observations, events=False)
    )
    assert conclusion.run.state is EngineRunState.SUCCEEDED
    before = production.durable()
    request = SemanticOutcomeRequest(
        schema_version="1.0.0",
        invocation_id=_UNKNOWN_INVOCATION_ID,
        expected_invocation_revision=plan.invocation.revision,
        run_id=RUN_ID,
        expected_run_revision=conclusion.run.revision,
        parsed_output=plan.parse,
        protocol_summary=plan.summary,
        candidate_observations=observations,
        negotiated_versions=DEFAULT_NEGOTIATED_VERSIONS,
    )
    monkeypatch.setattr(
        finalization_module, "apply_command_semantic_outcome", _forbidden
    )
    refused = semantic_outcome_or_replay(
        request, unit_of_work=production.unit_of_work(), clock=production.clock
    )
    assert _code(refused) == INVARIANT_VIOLATION
    assert "does not exist" in _message(refused)
    assert production.durable() == before


def test_declared_paths_and_the_conclusion_token_follow_the_verdict(
    production: FinalizationFixture,
) -> None:
    """Plan 4.4 step 0 and plan 4.3: the declared paths are the accepted
    ``ARTIFACT_PRODUCED`` declarations alone when no manifest parsed or the
    manifest is not a success, and their union with the manifest's declarations
    for a success; the cancellation token a conclusion hands each of its
    finalizations never reports a request (after T1 the run compare-and-swap
    decides)."""
    plan = _plan(production)
    event_paths = tuple(
        record.payload.relative_path for record in plan.summary.artifact_declarations
    )
    assert declared_candidate_paths(plan.summary, MISSING) == event_paths
    assert declared_candidate_paths(_EMPTY_SUMMARY, plan.parse) == tuple(RESULT_FILES)
    manifest = cast("Any", plan.parse.manifest)
    failed_parse = plan.parse.model_copy(
        update={
            "manifest": manifest.model_copy(
                update={"semantic_status": SemanticStatus.FAILED}
            )
        }
    )
    assert declared_candidate_paths(_EMPTY_SUMMARY, failed_parse) == ()
    assert declared_candidate_paths(plan.summary, failed_parse) == event_paths
    recording = _RecordingFinalizer(production.finalizer())
    conclusion = _ok(
        conclude_command(
            SemanticOutcome(
                invocation=plan.invocation,
                run=plan.run,
                reconciliation=_reconcile(production, plan),
            ),
            _command_result(plan, events=False),
            plan.parse,
            plan.summary,
            _observe(production, plan),
            roots=plan.roots,
            token=_token(production),
            config=_config(production),
            unit_of_work=production.unit_of_work(),
            finalizer=recording,
            clock=production.clock,
        )
    )
    assert conclusion.run.state is EngineRunState.SUCCEEDED
    result_token, evidence_token = recording.cancellations
    assert result_token.is_cancellation_requested() is False
    result_token.request_cancellation()
    assert result_token.is_cancellation_requested() is False
    assert evidence_token.is_cancellation_requested() is False
    _assert_consistent(production)


def test_a_colliding_truncation_diagnostic_leaves_the_capture_staged(
    production: FinalizationFixture,
) -> None:
    """Plan 4.6 (14.7:1014) when the truncation record itself is refused: the
    ``PROCESS.STDERR_TRUNCATED`` diagnostic is content-addressed, so a record
    already stored under its identity with other content is the recorder's
    invariant returned to the caller; the staged capture, committed by its own
    earlier transaction, stands as a ``CANDIDATE`` while neither the diagnostic
    nor the ``STDERR_TRUNCATED`` fact is committed."""
    production.plant_run()
    capture = _capture("partial engine stderr\n", truncated=True)
    expected = stage6_diagnostic(
        PROCESS_STDERR_TRUNCATED,
        "stderr exceeded the retained budget and was truncated before redaction",
        source_component=SOURCE_COMPONENT,
        timestamp_utc=production.clock.now_utc(),
        experiment_id=EXPERIMENT_ID,
        run_id=RUN_ID,
        invocation_id=INVOCATION_ID,
        details={"retained_byte_count": capture.retained_byte_count},
    )
    _record(
        production,
        expected.model_copy(update={"message": "recorded earlier with other content"}),
    )
    refused = _stderr_result(production, capture, RUN_OWNER, INVOCATION_ID)
    assert _code(refused) == INVARIANT_VIOLATION
    assert "different content" in _message(refused)
    after = production.durable()
    assert after.candidate_states[_core_stderr_id(RUN_OWNER, INVOCATION_ID)] == (
        "CANDIDATE"
    )
    assert "STDERR_TRUNCATED" not in after.audit_actions
    (stored,) = [
        item
        for item in after.diagnostics
        if item.diagnostic_id == expected.diagnostic_id
    ]
    assert stored.message != expected.message
    _assert_consistent(production)


# --------------------------------------------------------------------------
# Driver faults at the authoritative reads, the writes and the commits (the
# Stage 8 fault boundary): every refusal is the classified storage failure and
# nothing of the faulted transaction survives
# --------------------------------------------------------------------------

_SQLITE_IOERR: Final = 10
_SQLITE_IOERR_READ: Final = 266


def _read_error() -> Any:
    return sqlite_error(_SQLITE_IOERR_READ, "SQLITE_IOERR_READ")


def _reads(table: str, *, skip: int = 0) -> Callable[[str], bool]:
    """A statement predicate admitting the first ``SELECT`` from ``table`` after
    ``skip`` earlier ones ran."""
    seen = 0

    def admits(statement: str) -> bool:
        nonlocal seen
        text = statement.lstrip()
        if not text.startswith("SELECT") or f"FROM {table}" not in text:
            return False
        seen += 1
        return seen > skip

    return admits


def _touches(table: str) -> Callable[[str], bool]:
    return lambda statement: table in statement


def _updates(table: str, *, skip: int = 0) -> Callable[[str], bool]:
    seen = 0

    def admits(statement: str) -> bool:
        nonlocal seen
        if not statement.lstrip().startswith(f"UPDATE {table}"):
            return False
        seen += 1
        return seen > skip

    return admits


@contextmanager
def _commit_fault(
    fixture: FinalizationFixture, monkeypatch: pytest.MonkeyPatch
) -> Iterator[list[int]]:
    """The Stage 8 fault at the dialect ``do_commit`` boundary, one-shot: the
    next ``COMMIT`` is refused with ``SQLITE_IOERR`` and the original restored."""
    engine = engine_of(fixture.database)
    fired: list[int] = []

    def failing_commit(dbapi_connection: object) -> None:
        del dbapi_connection
        fired.append(1)
        monkeypatch.undo()
        raise sqlite_error(_SQLITE_IOERR, "SQLITE_IOERR")

    monkeypatch.setattr(engine.dialect, "do_commit", failing_commit)
    try:
        yield fired
    finally:
        monkeypatch.undo()


def _assert_left_moved(
    fixture: FinalizationFixture, candidate: Any, refused: object
) -> None:
    """A T3 storage failure keeps the storage posture: the journal ``MOVED`` for
    recovery, the candidate ``FINALIZING``, no reference registered."""
    assert _code(refused) == WRITE_FAILED, _message(refused)
    after = fixture.durable()
    assert after.journal_state == "MOVED"
    assert after.refs == ()
    assert after.candidate_states[candidate.candidate_artifact_id] == "FINALIZING"
    assert "FINALIZATION_REGISTERED" not in after.audit_actions
    _assert_consistent(fixture)


def _assert_result_left_moved(
    fixture: FinalizationFixture, plan: ProductionResultPlan, refused: object
) -> None:
    """A T3 storage failure of a RESULT registration keeps the storage posture:
    the journal ``MOVED`` for recovery, the run ``RUNNING`` at its lease
    revision, no manifest, reference or success fact."""
    assert _code(refused) == WRITE_FAILED, _message(refused)
    state = fixture.durable()
    assert state.run_state == "RUNNING"
    assert state.run_revision == plan.run.revision + 1
    assert state.journal_state == "MOVED"
    assert state.run_manifests == ()
    assert state.refs == ()
    assert "RUN_SUCCEEDED" not in state.audit_actions
    _assert_consistent(fixture)


def _assert_left_validating(
    fixture: FinalizationFixture, candidate: Any, refused: object
) -> None:
    """A phase-1 fact read that failed keeps the storage posture (the ruling):
    ``ARTIFACT.MOVE_FAILED``, the candidate ``VALIDATING``, nothing moved."""
    assert _code(refused) == ARTIFACT_MOVE_FAILED, _message(refused)
    after = fixture.durable()
    assert after.refs == ()
    assert after.candidate_states[candidate.candidate_artifact_id] == "VALIDATING"
    assert after.object_blobs == ()
    _assert_consistent(fixture)


def test_driver_read_faults_at_the_fact_reads_are_storage_failures(
    production: FinalizationFixture, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A driver fault at each authoritative read of the integration is the
    classified ``PERSISTENCE.WRITE_FAILED`` returned to the caller with nothing
    written: the owner registration of a result or core candidate (core bytes
    stay staged without their row), the sanitized and validation row reads
    before staging, the recovery validator's loads of the invocation, the
    experiment and the ledger (the work directory never observed), the run
    failure path's compare-and-swap, the stored conclusion's four reads of a
    replay, and the conclusion's read of the manifest it just registered (the
    registered success stands, the conclusion reports the read)."""
    plan = _plan(production, sanitized_row=False, plant_candidates=False)
    before = production.durable()
    with cursor_fault(production.database, monkeypatch) as fault:
        fault.arm(_read_error(), when=_touches("artifact_owners"))
        owners = register_result_candidates(
            plan.summary.artifact_declarations,
            RUN_OWNER,
            unit_of_work=production.unit_of_work(),
            clock=production.clock,
        )
        assert not fault.armed
    assert _code(owners) == WRITE_FAILED
    assert production.durable() == before
    with cursor_fault(production.database, monkeypatch) as fault:
        fault.arm(_read_error(), when=_touches("artifact_owners"))
        core = _stderr_result(production, _capture(), RUN_OWNER, INVOCATION_ID)
        assert not fault.armed
    assert _code(core) == WRITE_FAILED
    staged = production.durable()
    assert staged.candidates == ()
    run_hash = artifact_owner_hash(RUN_OWNER)
    assert staged.staging_files == (
        f"{run_hash}/INVOCATION/{INVOCATION_ID}/stderr.txt",
    )
    with cursor_fault(production.database, monkeypatch) as fault:
        fault.arm(_read_error(), when=_reads("sanitized_adapter_result_manifests"))
        manifest = sanitized_result_manifest_evidence(
            plan.sanitized,
            RUN_OWNER,
            store=production.roots.store,
            unit_of_work=production.unit_of_work(),
            clock=production.clock,
        )
        assert not fault.armed
    assert _code(manifest) == WRITE_FAILED
    with cursor_fault(production.database, monkeypatch) as fault:
        fault.arm(_read_error(), when=_reads("adapter_validation_results"))
        result = validation_result_evidence(
            _validation_result(plan),
            RUN_OWNER,
            store=production.roots.store,
            unit_of_work=production.unit_of_work(),
            clock=production.clock,
        )
        assert not fault.armed
    assert _code(result) == WRITE_FAILED
    assert production.durable() == staged
    assert production.harness.count("sanitized_adapter_result_manifests") == 0
    assert production.harness.count("adapter_validation_results") == 0
    token = _token(production)
    candidates = result_candidates()
    monkeypatch.setattr(finalization_module, "observe_candidates", _forbidden)
    refused: Result[Any]
    for table in ("command_invocations", "experiments", "run_events"):
        with cursor_fault(production.database, monkeypatch) as fault:
            fault.arm(_read_error(), when=_reads(table))
            refused = production.validator.validate_temporary_manifest(
                plan.roots, token, candidates
            )
            assert not fault.armed, table
        assert _code(refused) == WRITE_FAILED, table
    monkeypatch.undo()
    refusal = artifact_failure(
        ARTIFACT_RESULT_MANIFEST_INVALID,
        message="the temporary result manifest does not validate",
        now_utc=production.clock.now_utc(),
        experiment_id=EXPERIMENT_ID,
        run_id=RUN_ID,
        invocation_id=INVOCATION_ID,
    )
    with cursor_fault(production.database, monkeypatch) as fault:
        fault.arm(_read_error(), when=_updates("engine_runs"))
        swapped = fail_run_for_refusal(
            refusal,
            run_id=RUN_ID,
            expected_run_revision=plan.run.revision,
            roots=plan.roots,
            config=_config(production),
            unit_of_work=production.unit_of_work(),
            clock=production.clock,
        )
        assert not fault.armed
    assert _code(swapped) == WRITE_FAILED
    assert production.durable() == staged
    assert plan.roots.request_path.is_file()
    with _fresh(tmp_path, "r") as other:
        replayed = _plan(other)
        observations = _observe(other, replayed)
        conclusion = _ok(
            _conclude(other, replayed, observations=observations, events=False)
        )
        request = SemanticOutcomeRequest(
            schema_version="1.0.0",
            invocation_id=INVOCATION_ID,
            expected_invocation_revision=replayed.invocation.revision,
            run_id=RUN_ID,
            expected_run_revision=conclusion.run.revision,
            parsed_output=replayed.parse,
            protocol_summary=replayed.summary,
            candidate_observations=observations,
            negotiated_versions=DEFAULT_NEGOTIATED_VERSIONS,
        )
        settled = other.durable()
        monkeypatch.setattr(
            finalization_module, "apply_command_semantic_outcome", _forbidden
        )
        for table in (
            "command_invocations",
            "run_manifests",
            "run_artifacts",
            "artifact_refs",
        ):
            with cursor_fault(other.database, monkeypatch) as fault:
                fault.arm(_read_error(), when=_reads(table))
                refused = semantic_outcome_or_replay(
                    request, unit_of_work=other.unit_of_work(), clock=other.clock
                )
                assert not fault.armed, table
            assert _code(refused) == WRITE_FAILED, table
            monkeypatch.setattr(
                finalization_module, "apply_command_semantic_outcome", _forbidden
            )
        monkeypatch.undo()
        assert other.durable() == settled
    with _fresh(tmp_path, "m") as other:
        registered = _plan(other)
        with cursor_fault(other.database, monkeypatch) as fault:
            fault.arm(_read_error(), when=_reads("run_manifests"))
            refused = _conclude(other, registered, events=False)
            assert not fault.armed
        assert _code(refused) == WRITE_FAILED
        state = other.durable()
        assert state.run_state == "SUCCEEDED"
        assert len(state.run_manifests) == 1
        assert [ref.finalization_purpose for ref in state.refs] == [
            _F.RESULT,
            _F.RESULT,
        ]
        _assert_consistent(other)


def test_driver_read_faults_in_evidence_registration_keep_the_posture(
    production: FinalizationFixture, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The ruling's storage posture for the canonical fact checks and the T3
    links: a fault at the qualifier's read of the sanitized row, the validation
    row or the ledger is ``ARTIFACT.MOVE_FAILED`` with the candidate left
    ``VALIDATING``; a fault at the registration's read of the run manifest or the
    sanitized row for the evidence link, at the stderr enrichment's
    compare-and-swap, at the RESULT registrar's read of the sanitized manifest
    or at its run compare-and-swap leaves the journal ``MOVED`` for recovery with
    nothing registered."""
    plan = _plan(production)
    manifest = _ok(
        sanitized_result_manifest_evidence(
            plan.sanitized,
            RUN_OWNER,
            store=production.roots.store,
            unit_of_work=production.unit_of_work(),
            clock=production.clock,
        )
    )
    with cursor_fault(production.database, monkeypatch) as fault:
        fault.arm(_read_error(), when=_reads("sanitized_adapter_result_manifests"))
        refused = _finalize(production, (manifest,))
        assert not fault.armed
    _assert_left_validating(production, manifest, refused)
    with _fresh(tmp_path, "v") as other:
        validated = _plan(other)
        _plant_invocation(other, OTHER_INVOCATION_ID, CommandKind.VALIDATE)
        result = _ok(
            validation_result_evidence(
                _validation_result(validated, OTHER_INVOCATION_ID),
                _SIBLING_OWNER,
                store=other.roots.store,
                unit_of_work=other.unit_of_work(),
                clock=other.clock,
            )
        )
        sibling = EvidenceCorrelation(
            kind="INVOCATION", invocation_id=OTHER_INVOCATION_ID
        )
        with cursor_fault(other.database, monkeypatch) as fault:
            fault.arm(_read_error(), when=_reads("adapter_validation_results"))
            refused = _finalize(other, (result,), sibling)
            assert not fault.armed
        _assert_left_validating(other, result, refused)
    with _fresh(tmp_path, "l") as other:
        ledgered = _plan(other)
        capture = _ok(
            protocol_capture_evidence(
                ledgered.events,
                RUN_OWNER,
                INVOCATION_ID,
                store=other.roots.store,
                unit_of_work=other.unit_of_work(),
                clock=other.clock,
            )
        )
        with cursor_fault(other.database, monkeypatch) as fault:
            fault.arm(_read_error(), when=_reads("run_events"))
            refused = _finalize(other, (capture,))
            assert not fault.armed
        _assert_left_validating(other, capture, refused)
    for letter, table, skip in (
        ("a", "run_manifests", 0),
        ("b", "sanitized_adapter_result_manifests", 1),
    ):
        with _fresh(tmp_path, letter) as other:
            linked = _plan(other)
            staged = _ok(
                sanitized_result_manifest_evidence(
                    linked.sanitized,
                    RUN_OWNER,
                    store=other.roots.store,
                    unit_of_work=other.unit_of_work(),
                    clock=other.clock,
                )
            )
            with cursor_fault(other.database, monkeypatch) as fault:
                fault.arm(_read_error(), when=_reads(table, skip=skip))
                refused = _finalize(other, (staged,))
                assert not fault.armed, table
            _assert_left_moved(other, staged, refused)
    with _fresh(tmp_path, "e") as other:
        _plan(other)
        stderr = _stage_stderr(other)
        with cursor_fault(other.database, monkeypatch) as fault:
            fault.arm(_read_error(), when=_updates("command_invocations"))
            refused = _finalize(other, (stderr,))
            assert not fault.armed
        _assert_left_moved(other, stderr, refused)
        state = other.durable()
        assert state.invocation is not None
        assert not isinstance(state.invocation.stderr_artifact_id, str)
    for letter, when in (
        ("s", _reads("sanitized_adapter_result_manifests")),
        ("w", _updates("engine_runs", skip=1)),
    ):
        with _fresh(tmp_path, letter) as other:
            result_plan = _plan(other)
            with cursor_fault(other.database, monkeypatch) as fault:
                fault.arm(_read_error(), when=when)
                refused = other.finalize_result(result_plan)
                assert not fault.armed, letter
            assert _code(refused) == WRITE_FAILED, _message(refused)
            state = other.durable()
            assert state.run_state == "RUNNING"
            assert state.run_revision == result_plan.run.revision + 1
            assert state.journal_state == "MOVED"
            assert state.run_manifests == ()
            assert state.refs == ()
            assert "RUN_SUCCEEDED" not in state.audit_actions
            _assert_consistent(other)


def test_commit_and_close_faults_roll_back_their_short_transactions(
    production: FinalizationFixture, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A refused ``COMMIT`` at the dialect boundary of each short transaction is
    the storage failure with nothing of that transaction durable: the result
    candidate registration, a core candidate row (its bytes stay staged), the
    truncation record of a capture already staged, the sanitized and validation
    rows, the run failure write and the conclusion's diagnostic record; a
    refused ``RETENTION_DELETED`` fact rolls the run failure write and the
    terminal close's transaction back alike."""
    plan = _plan(production, sanitized_row=False, plant_candidates=False)
    _plant_invocation(production, OTHER_INVOCATION_ID, CommandKind.VALIDATE)
    before = production.durable()
    refused: Result[Any]
    with _commit_fault(production, monkeypatch) as fired:
        refused = register_result_candidates(
            plan.summary.artifact_declarations,
            RUN_OWNER,
            unit_of_work=production.unit_of_work(),
            clock=production.clock,
        )
    assert fired == [1]
    assert _code(refused) == WRITE_FAILED
    assert _message(refused) == "the transaction could not be committed"
    # As in every commit-fault cell, the durable state is read through fresh
    # sessions after ``reopen()``.
    production.reopen()
    assert production.durable() == before
    with _commit_fault(production, monkeypatch) as fired:
        refused = _stderr_result(production, _capture(), RUN_OWNER, INVOCATION_ID)
    assert fired == [1]
    assert _code(refused) == WRITE_FAILED
    production.reopen()
    staged = production.durable()
    assert staged.candidates == ()
    run_hash = artifact_owner_hash(RUN_OWNER)
    assert staged.staging_files == (
        f"{run_hash}/INVOCATION/{INVOCATION_ID}/stderr.txt",
    )
    with _commit_fault(production, monkeypatch) as fired:
        refused = sanitized_result_manifest_evidence(
            plan.sanitized,
            RUN_OWNER,
            store=production.roots.store,
            unit_of_work=production.unit_of_work(),
            clock=production.clock,
        )
    assert fired == [1]
    assert _code(refused) == WRITE_FAILED
    production.reopen()
    with _commit_fault(production, monkeypatch) as fired:
        refused = validation_result_evidence(
            _validation_result(plan, OTHER_INVOCATION_ID),
            _SIBLING_OWNER,
            store=production.roots.store,
            unit_of_work=production.unit_of_work(),
            clock=production.clock,
        )
    assert fired == [1]
    assert _code(refused) == WRITE_FAILED
    production.reopen()
    assert production.durable() == staged
    assert production.harness.count("sanitized_adapter_result_manifests") == 0
    assert production.harness.count("adapter_validation_results") == 0
    with _fresh(tmp_path, "t") as other:
        other.plant_run()
        truncated = _capture("partial engine stderr\n", truncated=True)
        first = _stage_stderr(other, truncated)
        with _commit_fault(other, monkeypatch) as fired:
            refused = _stderr_result(other, truncated, RUN_OWNER, INVOCATION_ID)
        assert fired == [1]
        assert _code(refused) == WRITE_FAILED
        other.reopen()
        state = other.durable()
        assert state.audit_actions.count("STDERR_TRUNCATED") == 1
        assert state.diagnostic_codes.count(PROCESS_STDERR_TRUNCATED) == 1
        assert state.candidate_states[first.candidate_artifact_id] == "CANDIDATE"
    refusal = artifact_failure(
        ARTIFACT_RESULT_MANIFEST_INVALID,
        message="the temporary result manifest does not validate",
        now_utc=production.clock.now_utc(),
        experiment_id=EXPERIMENT_ID,
        run_id=RUN_ID,
        invocation_id=INVOCATION_ID,
    )
    with _fresh(tmp_path, "f") as other:
        bare = _plan(other)
        assert isinstance(bare.roots.result_path, Path)
        bare.roots.request_path.unlink()
        bare.roots.result_path.unlink()
        with _commit_fault(other, monkeypatch) as fired:
            refused = fail_run_for_refusal(
                refusal,
                run_id=RUN_ID,
                expected_run_revision=bare.run.revision,
                roots=bare.roots,
                config=_config(other),
                unit_of_work=other.unit_of_work(),
                clock=other.clock,
            )
        assert fired == [1]
        assert _code(refused) == WRITE_FAILED
        other.reopen()
        state = other.durable()
        assert state.run == bare.run
        assert state.audit_actions == ()
        assert refusal.diagnostics[0].diagnostic_id not in {
            item.diagnostic_id for item in state.diagnostics
        }
    with _fresh(tmp_path, "d") as other:
        verdict_plan = _plan(other)
        wrong = tuple(
            item.model_copy(update={"observed_sha256": "0" * 64})
            for item in _observe(other, verdict_plan)
        )
        reconciliation = _reconcile(other, verdict_plan, wrong)
        assert reconciliation.diagnostics != ()
        state = other.durable()
        with _commit_fault(other, monkeypatch) as fired:
            refused = _conclude(
                other,
                verdict_plan,
                outcome=SemanticOutcome(
                    invocation=verdict_plan.invocation,
                    run=verdict_plan.run,
                    reconciliation=reconciliation,
                ),
                observations=wrong,
                stderr=_capture(),
                events=False,
            )
        assert fired == [1]
        assert _code(refused) == WRITE_FAILED
        other.reopen()
        assert other.durable() == state
    refusing = RefusingAuditor(
        production.audit_ids,
        production.clock,
        refused_action="RETENTION_DELETED",
        failure=_audit_refusal(production),
    )
    with _fresh(tmp_path, "c") as other:
        closing = _plan(other)
        refused = fail_run_for_refusal(
            refusal,
            run_id=RUN_ID,
            expected_run_revision=closing.run.revision,
            roots=closing.roots,
            config=_config_with(other, refusing),
            unit_of_work=other.unit_of_work(),
            clock=other.clock,
        )
        assert _code(refused) == _AUDIT_REFUSED
        assert refusing.refusals == 1
        state = other.durable()
        assert state.run == closing.run
        assert state.audit_actions == ()
    with _fresh(tmp_path, "g") as other:
        terminal = _plan(other)
        failed_run = other.fail_run_by_verdict()
        reconciliation = _reconcile_without_manifest(other, terminal)
        refused = conclude_command(
            SemanticOutcome(
                invocation=terminal.invocation,
                run=failed_run,
                reconciliation=reconciliation,
            ),
            _command_result(terminal, events=False, parsed=False),
            MISSING,
            terminal.summary,
            (),
            roots=terminal.roots,
            token=_token(other),
            config=_config_with(other, refusing),
            unit_of_work=other.unit_of_work(),
            finalizer=other.finalizer(),
            clock=other.clock,
        )
        assert _code(refused) == _AUDIT_REFUSED
        assert refusing.refusals == 2
        state = other.durable()
        assert state.run_state == "FAILED"
        assert state.run_revision == failed_run.revision
        assert "RETENTION_DELETED" not in state.audit_actions
        assert reconciliation.diagnostics[0].diagnostic_id in {
            item.diagnostic_id for item in state.diagnostics
        }
        _assert_consistent(other)


def test_registrar_read_faults_inside_t3_leave_the_journal_moved(
    production: FinalizationFixture, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The Stage 8 fault boundary at the RESULT registrar's remaining reads
    inside T3 -- the candidate rows behind the references, the run-command
    invocation whose diagnostics the manifest restates and the run row the
    success swap compares -- is ``PERSISTENCE.WRITE_FAILED`` with T3 rolled
    back: the journal stays ``MOVED`` for recovery, the run ``RUNNING`` at its
    lease revision, no manifest, reference or success fact committed. A fault
    at the stderr enrichment's invocation load inside the EVIDENCE T3 leaves
    that journal ``MOVED`` with the invocation unenriched. The read positions
    are the finalizer's deterministic statement order over this fixture."""
    for letter, table, skip in (
        ("c", "candidate_artifacts", 6),
        ("i", "command_invocations", 3),
        ("r", "engine_runs", 13),
    ):
        with _fresh(tmp_path, letter) as other:
            result_plan = _plan(other)
            with cursor_fault(other.database, monkeypatch) as fault:
                fault.arm(_read_error(), when=_reads(table, skip=skip))
                refused = other.finalize_result(result_plan)
                assert not fault.armed, table
            _assert_result_left_moved(other, result_plan, refused)
    _plan(production)
    stderr = _stage_stderr(production)
    with cursor_fault(production.database, monkeypatch) as fault:
        fault.arm(_read_error(), when=_reads("command_invocations", skip=1))
        refused = _finalize(production, (stderr,))
        assert not fault.armed
    _assert_left_moved(production, stderr, refused)
    state = production.durable()
    assert state.invocation is not None
    assert not isinstance(state.invocation.stderr_artifact_id, str)


def test_conclusion_tail_read_faults_report_the_storage_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A driver fault at each read of the conclusion's tail after the RESULT
    registration committed -- the references of the result, the references of
    the finalized evidence, the fresh run row and the fresh invocation row --
    is ``PERSISTENCE.WRITE_FAILED`` returned to the caller while the committed
    success stands: the run ``SUCCEEDED``, one run manifest, the two RESULT
    references and, once its finalization ran, the EVIDENCE reference."""
    cells = (
        ("a", "artifact_refs", 0, ["RESULT", "RESULT"]),
        ("b", "artifact_refs", 2, ["EVIDENCE", "RESULT", "RESULT"]),
        ("r", "engine_runs", 25, ["EVIDENCE", "RESULT", "RESULT"]),
        ("i", "command_invocations", 5, ["EVIDENCE", "RESULT", "RESULT"]),
    )
    for letter, table, skip, purposes in cells:
        with _fresh(tmp_path, letter) as other:
            plan = _plan(other)
            observed = _observe(other, plan)
            outcome = SemanticOutcome(
                invocation=plan.invocation,
                run=plan.run,
                reconciliation=_reconcile(other, plan, observed),
            )
            with cursor_fault(other.database, monkeypatch) as fault:
                fault.arm(_read_error(), when=_reads(table, skip=skip))
                refused = _conclude(
                    other, plan, events=False, outcome=outcome, observations=observed
                )
                assert not fault.armed, letter
            assert _code(refused) == WRITE_FAILED, letter
            state = other.durable()
            assert state.run_state == "SUCCEEDED", letter
            assert state.run_revision == plan.run.revision + 2, letter
            assert len(state.run_manifests) == 1, letter
            assert sorted(ref.finalization_purpose.value for ref in state.refs) == (
                purposes
            ), letter
            _assert_consistent(other)


def test_conclusion_run_reads_after_a_finalizer_refusal_are_storage_failures(
    production: FinalizationFixture, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Plan 4.4 step 3 when the run row cannot be re-read after the finalizer
    refused. Behind an ``ARTIFACT.*`` refusal the failure path never starts:
    the run row is as planted, no ``RUN_FAILED`` fact, the raw bytes in place.
    Behind a ``CORE.INVARIANT_VIOLATION`` of the registrar the abandonment
    stands -- journal ``ABANDONED`` under the invariant, candidates quarantined,
    the root already closed by the finalizer's T4 -- and the conclusion reports
    the storage failure of the run re-read that precedes its failure path in
    place of the invariant; the ``FAILED`` write never started."""
    corrupt = _plan(production)
    reconciliation = _reconcile(production, corrupt)
    assert isinstance(corrupt.roots.work_dir, Path)
    corrupt.roots.work_dir.joinpath("results", "native.bin").write_bytes(
        b"changed after the verdict\n"
    )
    with cursor_fault(production.database, monkeypatch) as fault:
        fault.arm(_read_error(), when=_reads("engine_runs", skip=2))
        refused = _conclude(
            production,
            corrupt,
            outcome=SemanticOutcome(
                invocation=corrupt.invocation,
                run=corrupt.run,
                reconciliation=reconciliation,
            ),
            observations=(),
            events=False,
        )
        assert not fault.armed
    assert _code(refused) == WRITE_FAILED, _message(refused)
    state = production.durable()
    assert state.run == corrupt.run
    assert state.journal == ()
    assert state.run_manifests == ()
    assert "RUN_FAILED" not in state.audit_actions
    assert corrupt.roots.request_path.is_file()
    _assert_consistent(production)
    with _fresh(tmp_path, "k") as other:
        bad = _plan(other, sanitized_row=False)
        _plant_sanitized_row_text(other, bad, '{"schema_version":"1.0.0"}')
        with cursor_fault(other.database, monkeypatch) as fault:
            fault.arm(_read_error(), when=_reads("engine_runs", skip=17))
            refused = _conclude(other, bad, stderr=_capture(), events=False)
            assert not fault.armed
        assert _code(refused) == WRITE_FAILED, _message(refused)
        state = other.durable()
        assert state.run_state == "RUNNING"
        assert state.run_revision == bad.run.revision + 1
        assert state.journal_state == "ABANDONED"
        assert state.abandon_reason == INVARIANT_VIOLATION
        assert state.run_manifests == ()
        assert state.refs == ()
        assert state.audit_actions.count("RETENTION_DELETED") == 1
        assert not bad.roots.request_path.exists()
        _assert_consistent(other)
