"""Stage 6 Task 7: `SemanticOutcomeRequest`, `SemanticOutcome` and
`apply_command_semantic_outcome` (Stage 6 plan sections 3.12, 9.3, 10, 13 and 14
Task 7; specification 8.1-8.2, 14.6, 15.2, 17.1, 19.4, 21.2.1, 23.2, 29.6).

The operation is the authoritative application effect of the four Task 6 layers: it
consumes one Task 6 reconciliation over one `EXITED` invocation and its run, applies
the proposed run target through the Stage 5 run rules and enriches the invocation
with the minted diagnostic identities in one unit of work. Every test runs against
the in-memory doubles through a root unit of work, seeds state through its own
transaction and reads the committed store back, so a "no write" assertion is a
statement about durable state. No process is launched, no artifact finalized, no
`RunManifest` built and no run ever reaches a success state.
"""

from __future__ import annotations

import ast
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Final, cast

import pytest
from pydantic import ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab import experiments as experiments_package
from crypto_lab.adapters.diagnostics import (
    ADAPTER_UNAVAILABLE,
    ARTIFACT_RESULT_MANIFEST_INVALID,
    COMPAT_LATE_NOT_APPLICABLE,
    COMPAT_NOT_APPLICABLE,
    ENGINE_RUNTIME_FAILURE,
    PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
    PROTOCOL_MALFORMED_JSONL,
    SCHEMA_REQUEST_INVALID,
    SECURITY_SENSITIVE_MATERIAL_LEAKAGE,
    stage6_diagnostic,
)
from crypto_lab.adapters.envelopes import NegotiatedVersions
from crypto_lab.adapters.events import (
    ArtifactDeclarationRecord,
    ArtifactProducedPayload,
    FinalResultPayload,
    ProtocolEventSummary,
    ProtocolWarning,
)
from crypto_lab.adapters.limits import (
    MAX_CANDIDATE_ARTIFACTS,
    MAX_RESULT_MANIFEST_BYTES,
    MAX_VALIDATION_RESULT_BYTES,
    RESULT_MANIFEST_RELATIVE_PATH,
)
from crypto_lab.adapters.manifests import (
    ManifestParse,
    ValidationResultParse,
    parse_result_manifest,
    parse_validation_result,
)
from crypto_lab.adapters.reconciliation import CandidateObservation
from crypto_lab.adapters.vocabulary import (
    NEGOTIABLE_SCHEMA_NAMES,
    ReconciliationVerdict,
    SemanticStatus,
    ValidationOutcome,
)
from crypto_lab.domain.base import SCHEMA_VERSION, CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.command_invocation import (
    MAX_DIAGNOSTIC_IDS,
    CommandInvocationCheck,
    CommandInvocationRecord,
    CommandInvocationRuleViolation,
)
from crypto_lab.domain.descriptors import SupportedSchemaVersion
from crypto_lab.domain.diagnostics import Diagnostic
from crypto_lab.domain.engine_run import (
    SUCCESS_ENGINE_RUN_STATES,
    EngineRunCheck,
    EngineRunRecord,
    EngineRunRuleViolation,
)
from crypto_lab.domain.experiment import ExperimentRecord, SelectedEngineSlot
from crypto_lab.domain.hashing import (
    _uuid4_shaped,
    attempt_token_hash,
    request_id_for,
    sha256_bytes,
)
from crypto_lab.domain.lifecycle import (
    TERMINAL_ENGINE_RUN_STATES,
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.experiments.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
    stage5_failure,
)
from crypto_lab.experiments.invocation_service import (
    begin_linked_launch,
    create_invocation,
)
from crypto_lab.experiments.ports import (
    DiagnosticReader,
    EngineRunRepository,
    ExperimentRepository,
    RetryDecisionRepository,
    RuntimeAvailabilityObservationReader,
    UnitOfWork,
)
from crypto_lab.experiments.requests import (
    MAX_CANDIDATE_OBSERVATIONS,
    REQUEST_OPERATIONS,
    InvocationCreationRequest,
    LinkedLaunchRequest,
    RunTransitionRequest,
    SemanticOutcomeRequest,
)
from crypto_lab.experiments.run_service import transition_run
from crypto_lab.experiments.semantic_outcome import (
    SemanticOutcome,
    apply_command_semantic_outcome,
)
from crypto_lab.schema_registry import SCHEMA_DEFINITIONS
from doubles.experiments import (
    ADAPTER_BETA,
    ATTEMPT_TOKEN,
    AVAIL_A,
    DATASET_HASH,
    DIAG_ID,
    ENGINE_BETA,
    EXPERIMENT_ID,
    INSTANT,
    INVOCATION_ID,
    OTHER_INVOCATION_ID,
    OTHER_RUN_ID,
    REQUEST_HASH,
    RUN_ID,
    SLOT_A,
    SLOT_B,
    STRATEGY_HASH,
    CallRecorder,
    CountingClock,
    FixedClock,
    InMemoryBackingStore,
    InMemoryUnitOfWork,
    MemberOverridingUnitOfWork,
    RecordingUnitOfWork,
    SequentialIdentitySource,
    sample_diagnostic,
    sample_draft,
    sample_experiment,
    sample_invocation,
    sample_run,
    sequential_diagnostic_id,
)

_K = CommandKind
_R = EngineRunState
_C = CommandInvocationState
_E = ExperimentState
_S = SemanticStatus
_O = ValidationOutcome
_V = ReconciliationVerdict

_NOW: Final = INSTANT + timedelta(minutes=30)
_LATER: Final = _NOW + timedelta(hours=3)
_STARTED: Final = "2026-09-07T12:05:00Z"
_COMPLETED: Final = "2026-09-07T12:10:00Z"
_HASH: Final = "a" * 64
_OTHER_HASH: Final = "b" * 64
_TOKEN_HASH: Final = attempt_token_hash(ATTEMPT_TOKEN)
_REQUEST_ID: Final = request_id_for(RUN_ID)
_SOURCE: Final = "experiments.semantic_outcome"
_REPOSITORY_SOURCE: Final = "doubles.experiments"
_STUB_SOURCE: Final = "test.semantic-outcome"
_OPERATION: Final = "apply_command_semantic_outcome"
_REQUEST_FIELDS: Final = (
    "invocation_id",
    "expected_invocation_revision",
    "run_id",
    "expected_run_revision",
    "parsed_output",
    "protocol_summary",
    "candidate_observations",
    "negotiated_versions",
    "protocol_failure",
)
_OUTCOME_FIELDS: Final = ("invocation", "run", "reconciliation", "superseded_by")
#: Plan 3.11's closing sentence plus the Task 6 layer names no request may carry.
_DERIVED_FIELD_NAMES: Final = frozenset(
    {
        "revision",
        "state",
        "outcome",
        "verdict",
        "run_target_state",
        "semantic_status",
        "process_exit_category",
        "attempt_token",
        "attempt_token_hash",
        "primary_diagnostic",
        "diagnostic_id",
        "diagnostic_ids",
        "superseded_by",
        "finalization_eligible",
    }
)
_MAX_OBSERVATIONS: Final = 2 * MAX_CANDIDATE_ARTIFACTS
#: The step-1 and step-2 read set: the invocation and the run, in that order.
_LOAD_PAIR: Final = (("command_invocations", "get"), ("engine_runs", "get"))
#: The step-4 read.
_LOAD_EXPERIMENT: Final = (("experiments", "get"),)
#: The step-6 authoritative reads: the slot's latest attempt, then the run's
#: VALIDATE and RUN invocations.
_PRECONDITION_READS: Final = (
    ("engine_runs", "latest_attempt"),
    ("command_invocations", "list_for_run"),
    ("command_invocations", "list_for_run"),
)
_RUN_SWAP: Final = (("engine_runs", "compare_and_swap"),)
_INVOCATION_SWAP: Final = (("command_invocations", "compare_and_swap"),)
_PURE_ROOTS: Final = frozenset(
    {"__future__", "collections", "datetime", "typing", "pydantic", "crypto_lab"}
)
_INFRASTRUCTURE_ROOTS: Final = frozenset(
    {
        "subprocess",
        "os",
        "sys",
        "pathlib",
        "time",
        "random",
        "secrets",
        "io",
        "shutil",
        "tempfile",
        "glob",
        "importlib",
        "socket",
        "sqlite3",
        "sqlalchemy",
        "alembic",
        "asyncio",
        "threading",
    }
)
_STAGE4_BARE_NAMES: Final = frozenset(
    {"buffer", "context", "note", "problem", "compose", "Loader", "get_snippet"}
)
_LATER_STAGE_NAMES: Final = frozenset(
    {
        "RunManifest",
        "ArtifactRef",
        "CandidateArtifact",
        "ArtifactFinalizer",
        "ProcessSupervisor",
        "CancellationToken",
        "MonotonicInstant",
        "FinalizationResult",
    }
)
#: Attribute names the operation must never touch: the ledger, the success states,
#: the validator bypass and the Stage 5 operation that opens its own transaction.
_FORBIDDEN_ATTRIBUTES: Final = frozenset(
    {
        "SUCCEEDED",
        "SUCCEEDED_WITH_WARNINGS",
        "model_copy",
        "list_events",
        "append_event",
        "from_events",
        "InvocationEventLedger",
        "enrich_invocation",
        "transition_run",
        "reconcile_describe",
        "semantic_exit_reading",
        "utcnow",
        "today",
    }
)


def _missing(value: object) -> bool:
    return value is MISSING


def _code(result: object) -> str:
    assert isinstance(result, Failure), result
    assert len(result.diagnostics) == 1
    return result.diagnostics[0].error_code


def _ok[T](result: Success[T] | Failure) -> T:
    assert isinstance(result, Success), result
    return result.value


def _commit(unit_of_work: UnitOfWork) -> None:
    committed = unit_of_work.commit()
    assert isinstance(committed, Success), committed


def _derived(prefix: str, seed: str) -> str:
    return f"{prefix}_{_uuid4_shaped(sha256_bytes(seed.encode('utf-8')))}"


def _stdlib_digest(document: object) -> str:
    return hashlib.sha256(
        json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()


def _encode(document: dict[str, Any]) -> bytes:
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _assert_token_free(*values: object) -> None:
    for value in values:
        text = canonical_json_bytes(value).decode("utf-8")
        assert ATTEMPT_TOKEN not in text
        assert ATTEMPT_TOKEN not in repr(value)


def _assert_service_failure(
    result: object, code: str, *, now: datetime = _NOW, source: str = _SOURCE
) -> Diagnostic:
    """Exactly one Stage 5 diagnostic, stamped by the service at the clock instant,
    token-free and free of the pydantic wording the Stage 5 factory never emits."""
    assert isinstance(result, Failure), result
    assert len(result.diagnostics) == 1
    diagnostic = result.diagnostics[0]
    assert diagnostic.error_code == code
    assert diagnostic.source_component == source
    assert diagnostic.timestamp_utc == now
    assert diagnostic.retriable is (code == CONCURRENCY_CONFLICT)
    if source == _SOURCE:
        assert diagnostic.experiment_id == EXPERIMENT_ID
        assert diagnostic.run_id == RUN_ID
        assert diagnostic.invocation_id == INVOCATION_ID
    _assert_token_free(diagnostic)
    assert "pydantic" not in diagnostic.message.lower()
    assert "validation error" not in diagnostic.message.lower()
    return diagnostic


# --------------------------------------------------------------------------
# Adapter material (the Task 6 recipes, minimal)
# --------------------------------------------------------------------------

_ADAPTER_DIAGNOSTIC: Final[dict[str, Any]] = {
    "error_code": "ENGINE.DATA_GAP",
    "category": "ENGINE_RUNTIME",
    "severity": "ERROR",
    "message": "one bar missing",
    "retriable": True,
    "details": {"bars": 1},
    "causal_event_ids": [],
}
_EMPTY_SUMMARY: Final = ProtocolEventSummary(
    accepted_count=0,
    last_sequence=0,
    artifact_declarations=(),
    warnings=(),
    adapter_diagnostics=(),
    redactions=0,
)
_EXPERIMENT: Final = sample_experiment(_E.RUNNING)
_MANIFEST_ID: Final = _derived("amf", "manifest")
_NEGOTIATED: Final = NegotiatedVersions(
    protocol_version="1.0.0",
    schema_versions=tuple(
        SupportedSchemaVersion(schema_name=name, schema_version=SCHEMA_VERSION)
        for name in NEGOTIABLE_SCHEMA_NAMES
    ),
    capability_vocabulary_version="capabilities/v1",
)
_PROVENANCE: Final[dict[str, Any]] = {
    "experiment_spec_hash": _EXPERIMENT.spec_hash,
    "request_hash": REQUEST_HASH,
    "strategy_version_hash": STRATEGY_HASH,
    "dataset_version_hash": DATASET_HASH,
    "configuration_hash": _EXPERIMENT.spec.configuration_hash,
    "adapter": {"adapter_name": "adapter.alpha", "adapter_version": "1.0.0"},
    "engine": {"engine_name": "engine.alpha", "engine_version": "2.3.4"},
    "negotiated_versions": _NEGOTIATED.model_dump(mode="json"),
    "comparison_level": "LEVEL_2",
    "logical_slot_id": SLOT_A,
    "attempt_number": 1,
}
_WARNING: Final[dict[str, Any]] = {
    "warning_code": "ADAPTER.APPROXIMATED_FILLS",
    "message": "fills approximated at bar close",
    "impact": "Level 3 comparison prevented.",
    "prevented_comparison_levels": ["LEVEL_3"],
}
_DECLARATION: Final[dict[str, Any]] = {
    "relative_path": "results/native.bin",
    "artifact_kind": "engine.native",
    "media_type": "application/octet-stream",
    "declared_size_bytes": 12,
    "declared_sha256": _HASH,
}
_SUCCESS_STATUSES: Final = (_S.SUCCEEDED, _S.SUCCEEDED_WITH_WARNINGS)


def _validation_document(**updates: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema_version": "1.0.0",
        "protocol_version": "1.0.0",
        "request_id": _REQUEST_ID,
        "invocation_id": INVOCATION_ID,
        "run_id": RUN_ID,
        "attempt_token_hash": _TOKEN_HASH,
        "outcome": "VALID",
        "diagnostics": [],
        "validated_at_utc": _STARTED,
    }
    document.update(updates)
    if document["outcome"] != "VALID" and not document["diagnostics"]:
        document["diagnostics"] = [_ADAPTER_DIAGNOSTIC]
    document["result_hash"] = _stdlib_digest(document)
    return document


def _validation_parse(
    document: dict[str, Any] | None = None, *, raw: bytes | None = None
) -> ValidationResultParse:
    output = _encode(_validation_document() if document is None else document)
    return parse_validation_result(
        raw if raw is not None else output,
        max_bytes=MAX_VALIDATION_RESULT_BYTES,
        token=ATTEMPT_TOKEN,
    )


def _manifest_document(**updates: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema_version": "1.0.0",
        "protocol_version": "1.0.0",
        "adapter_manifest_id": _MANIFEST_ID,
        "experiment_id": EXPERIMENT_ID,
        "run_id": RUN_ID,
        "invocation_id": INVOCATION_ID,
        "attempt_token": ATTEMPT_TOKEN,
        "semantic_status": "SUCCEEDED",
        "started_at_utc": _STARTED,
        "completed_at_utc": _COMPLETED,
        "provenance": dict(_PROVENANCE),
        "candidate_artifacts": [_DECLARATION],
        "candidate_metrics": [],
        "diagnostics": [],
        "warnings": [],
        "approximations": [],
    }
    document.update(updates)
    status = _S(document["semantic_status"])
    if status not in _SUCCESS_STATUSES:
        document["candidate_artifacts"] = updates.get("candidate_artifacts", [])
        if not document["diagnostics"]:
            document["diagnostics"] = [_ADAPTER_DIAGNOSTIC]
        document["warnings"] = updates.get("warnings", [])
    elif status is _S.SUCCEEDED_WITH_WARNINGS and not document["warnings"]:
        document["warnings"] = [_WARNING]
    return document


def _manifest_parse(document: dict[str, Any] | None = None) -> ManifestParse:
    return parse_result_manifest(
        _encode(_manifest_document() if document is None else document),
        max_bytes=MAX_RESULT_MANIFEST_BYTES,
        token=ATTEMPT_TOKEN,
    )


def _warning(document: dict[str, Any] = _WARNING) -> ProtocolWarning:
    # JSON mode: the strict python mode refuses the fixture's list for a tuple.
    return ProtocolWarning.model_validate_json(json.dumps(document))


def _summary(
    *declarations: dict[str, Any],
    warnings: tuple[dict[str, Any], ...] = (),
    final: ManifestParse | None = None,
    final_hash: str | None = None,
) -> ProtocolEventSummary:
    records = tuple(
        ArtifactDeclarationRecord(
            event_id=_derived("evt", f"artifact:{index}"),
            payload=ArtifactProducedPayload.model_validate(declaration),
        )
        for index, declaration in enumerate(declarations, start=1)
    )
    facts: dict[str, Any] = {
        "artifact_declarations": records,
        "warnings": tuple(_warning(item) for item in warnings),
        "adapter_diagnostics": (),
        "redactions": 0,
    }
    count = len(records) + len(warnings)
    if final is not None:
        manifest = final.manifest
        assert not _missing(manifest)
        facts["final_result"] = FinalResultPayload(
            manifest_relative_path=RESULT_MANIFEST_RELATIVE_PATH,
            source_adapter_result_manifest_hash=(
                final.source_hash if final_hash is None else final_hash
            ),
            semantic_status=manifest.semantic_status,
        )
        count += 1
    facts["accepted_count"] = count
    facts["last_sequence"] = count
    return ProtocolEventSummary.model_validate(facts)


def _observation(
    declaration: dict[str, Any], *, contains_attempt_token: bool = False
) -> CandidateObservation:
    return CandidateObservation.model_validate(
        {
            "relative_path": declaration["relative_path"],
            "observed_size_bytes": declaration["declared_size_bytes"],
            "observed_sha256": declaration["declared_sha256"],
            "contains_attempt_token": contains_attempt_token,
        }
    )


def _protocol_failure(invocation_id: str = INVOCATION_ID) -> Diagnostic:
    return stage6_diagnostic(
        PROTOCOL_MALFORMED_JSONL,
        "stdout line is not a JSON object",
        source_component="adapters.events",
        timestamp_utc=INSTANT,
        invocation_id=invocation_id,
        details={"byte_length": 3, "source_hash": _HASH},
    )


@dataclass(frozen=True, slots=True)
class _RunMaterial:
    """A consistent manifest, summary and observation set for one run outcome."""

    output: ManifestParse
    summary: ProtocolEventSummary
    observations: tuple[CandidateObservation, ...]


def _run_material(
    status: SemanticStatus,
    *,
    leaking: bool = False,
    final_hash: str | None = None,
) -> _RunMaterial:
    success = status in _SUCCESS_STATUSES
    declarations = (_DECLARATION,) if success else ()
    warnings = (_WARNING,) if status is _S.SUCCEEDED_WITH_WARNINGS else ()
    output = _manifest_parse(
        _manifest_document(
            semantic_status=status.value,
            candidate_artifacts=list(declarations),
            warnings=list(warnings),
        )
    )
    return _RunMaterial(
        output=output,
        summary=_summary(
            *declarations, warnings=warnings, final=output, final_hash=final_hash
        ),
        observations=tuple(
            _observation(item, contains_attempt_token=leaking) for item in declarations
        ),
    )


# --------------------------------------------------------------------------
# Seeding, requests and the operation
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Seeded:
    """One backing store with the experiment, run and invocation it holds."""

    store: InMemoryBackingStore
    experiment: ExperimentRecord
    run: EngineRunRecord
    invocation: CommandInvocationRecord

    def snapshot(self) -> tuple[object, ...]:
        """Every committed row, so a "no write" assertion compares durable state."""
        return (
            self.store.committed_experiments(),
            self.store.committed_engine_runs(),
            self.store.committed_command_invocations(),
            self.store.committed_run_events(),
            self.store.committed_retry_decisions(),
            tuple(sorted(self.store.diagnostics.live)),
        )

    def stored_run(self) -> EngineRunRecord:
        (run,) = (
            record
            for record in self.store.committed_engine_runs()
            if record.run_id == self.run.run_id
        )
        return run

    def stored_invocation(self) -> CommandInvocationRecord:
        (invocation,) = (
            record
            for record in self.store.committed_command_invocations()
            if record.invocation_id == self.invocation.invocation_id
        )
        return invocation


def _seed(
    *,
    experiment: ExperimentRecord | None = None,
    run: EngineRunRecord | None = None,
    invocation: CommandInvocationRecord | None = None,
    extra: tuple[EngineRunRecord | CommandInvocationRecord, ...] = (),
    seed_experiment: bool = True,
) -> _Seeded:
    experiment = _EXPERIMENT if experiment is None else experiment
    run = sample_run(_R.VALIDATING) if run is None else run
    invocation = (
        sample_invocation(_C.EXITED, kind=_K.VALIDATE)
        if invocation is None
        else invocation
    )
    store = InMemoryBackingStore()
    transaction = InMemoryUnitOfWork(store).begin()
    if seed_experiment:
        _ok(transaction.experiments.add(experiment))
    _ok(transaction.engine_runs.add_attempt(run))
    _ok(transaction.command_invocations.add(invocation))
    for record in extra:
        if isinstance(record, EngineRunRecord):
            _ok(transaction.engine_runs.add_attempt(record))
        else:
            _ok(transaction.command_invocations.add(record))
    _commit(transaction)
    return _Seeded(store=store, experiment=experiment, run=run, invocation=invocation)


def _validate_seed(exit_value: int = 0) -> _Seeded:
    return _seed(
        run=sample_run(_R.VALIDATING),
        invocation=sample_invocation(
            _C.EXITED, kind=_K.VALIDATE, native_exit_value=exit_value
        ),
    )


def _run_seed(exit_value: int = 0) -> _Seeded:
    return _seed(
        run=sample_run(_R.RUNNING),
        invocation=sample_invocation(
            _C.EXITED, kind=_K.RUN, native_exit_value=exit_value
        ),
    )


def _request(
    seeded: _Seeded,
    *,
    invocation_revision: int | None = None,
    run_revision: int | None = None,
    **overrides: Any,
) -> SemanticOutcomeRequest:
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "invocation_id": seeded.invocation.invocation_id,
        "expected_invocation_revision": (
            seeded.invocation.revision
            if invocation_revision is None
            else invocation_revision
        ),
        "run_id": seeded.run.run_id,
        "expected_run_revision": (
            seeded.run.revision if run_revision is None else run_revision
        ),
        "protocol_summary": _EMPTY_SUMMARY,
        "candidate_observations": (),
        "negotiated_versions": _NEGOTIATED,
    }
    payload.update(overrides)
    return SemanticOutcomeRequest.model_validate(payload)


def _validate_request(
    seeded: _Seeded, outcome: ValidationOutcome | None = _O.VALID, **overrides: Any
) -> SemanticOutcomeRequest:
    if outcome is not None:
        overrides.setdefault(
            "parsed_output",
            _validation_parse(_validation_document(outcome=outcome.value)),
        )
    return _request(seeded, **overrides)


def _run_request(
    seeded: _Seeded, status: SemanticStatus | None = _S.SUCCEEDED, **overrides: Any
) -> SemanticOutcomeRequest:
    if status is not None:
        material = _run_material(status)
        overrides.setdefault("parsed_output", material.output)
        overrides.setdefault("protocol_summary", material.summary)
        overrides.setdefault("candidate_observations", material.observations)
    return _request(seeded, **overrides)


def _apply(
    request: SemanticOutcomeRequest,
    unit_of_work: UnitOfWork,
    *,
    clock: FixedClock | None = None,
) -> Result[SemanticOutcome]:
    return apply_command_semantic_outcome(
        request,
        unit_of_work=unit_of_work,
        clock=FixedClock(_NOW) if clock is None else clock,
    )


def _recording(seeded: _Seeded) -> tuple[RecordingUnitOfWork, CallRecorder]:
    recorder = CallRecorder()
    return RecordingUnitOfWork(InMemoryUnitOfWork(seeded.store), recorder), recorder


def _apply_recorded(
    seeded: _Seeded, request: SemanticOutcomeRequest, *, clock: FixedClock | None = None
) -> tuple[Result[SemanticOutcome], tuple[tuple[str, str], ...]]:
    root, recorder = _recording(seeded)
    result = _apply(request, root, clock=clock)
    return result, recorder.repositories()


def _stub_conflict() -> Failure:
    return stage5_failure(
        CONCURRENCY_CONFLICT,
        "simulated lost compare-and-swap",
        source_component=_STUB_SOURCE,
        timestamp_utc=INSTANT,
    )


def _always_lose(*_args: object, **_kwargs: object) -> Failure:
    return _stub_conflict()


def _transition(seeded: _Seeded, request: RunTransitionRequest) -> EngineRunRecord:
    return _ok(
        transition_run(
            request,
            unit_of_work=InMemoryUnitOfWork(seeded.store),
            clock=FixedClock(_NOW + timedelta(seconds=1)),
        )
    )


def _run_transition(
    run: EngineRunRecord,
    target: EngineRunState,
    *,
    primary_terminal_diagnostic_id: str | None = None,
    availability_observation_id: str | None = None,
) -> RunTransitionRequest:
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "run_id": run.run_id,
        "expected_revision": run.revision,
        "target_state": target,
        "reason_code": "EXPERIMENT.OPERATOR_DECISION",
    }
    if primary_terminal_diagnostic_id is not None:
        payload["primary_terminal_diagnostic_id"] = primary_terminal_diagnostic_id
    if availability_observation_id is not None:
        payload["availability_observation_id"] = availability_observation_id
    return RunTransitionRequest.model_validate(payload)


# --------------------------------------------------------------------------
# Two test-local units of work: a single lost swap that then proceeds, and a
# single lost commit. The run and invocation repositories have no coordination
# hook (the doubles' hooks are experiment- and retry-scoped), so the reload-once
# driver's second pass can be proven only by intercepting the real method once.
# --------------------------------------------------------------------------


class _Intercepted:
    """Delegates every attribute to ``target`` except one method, which is routed
    through ``interceptor(real_method, *args, **kwargs)``."""

    def __init__(
        self, target: object, method: str, interceptor: Callable[..., object]
    ) -> None:
        self._target = target
        self._method = method
        self._interceptor = interceptor

    def __getattr__(self, name: str) -> Any:
        real = getattr(self._target, name)
        if name != self._method:
            return real

        def call(*args: Any, **kwargs: Any) -> Any:
            return self._interceptor(real, *args, **kwargs)

        return call


class _InterceptingUnitOfWork:
    """A ``UnitOfWork`` over an ``InMemoryUnitOfWork`` that intercepts one member
    method with a callable that receives the real method; ``begins`` counts the
    transactions opened so a test can pin the reload-once driver's two passes."""

    def __init__(
        self,
        inner: InMemoryUnitOfWork,
        member: str,
        method: str,
        interceptor: Callable[..., object],
        counter: list[int] | None = None,
    ) -> None:
        self._inner = inner
        self._member = member
        self._method = method
        self._interceptor = interceptor
        self._counter = [0] if counter is None else counter

    @property
    def begins(self) -> int:
        return self._counter[0]

    def begin(self) -> _InterceptingUnitOfWork:
        self._counter[0] += 1
        return _InterceptingUnitOfWork(
            self._inner.begin(),
            self._member,
            self._method,
            self._interceptor,
            self._counter,
        )

    def commit(self) -> Result[None]:
        return self._inner.commit()

    def rollback(self) -> None:
        self._inner.rollback()

    def _member_of(self, name: str) -> Any:
        target = getattr(self._inner, name)
        if name != self._member:
            return target
        return _Intercepted(target, self._method, self._interceptor)

    @property
    def experiments(self) -> ExperimentRepository:
        return cast("ExperimentRepository", self._member_of("experiments"))

    @property
    def engine_runs(self) -> EngineRunRepository:
        return cast("EngineRunRepository", self._member_of("engine_runs"))

    @property
    def command_invocations(self) -> Any:
        return self._member_of("command_invocations")

    @property
    def retry_decisions(self) -> RetryDecisionRepository:
        return cast("RetryDecisionRepository", self._member_of("retry_decisions"))

    @property
    def availability_observations(self) -> RuntimeAvailabilityObservationReader:
        return cast(
            "RuntimeAvailabilityObservationReader",
            self._member_of("availability_observations"),
        )

    @property
    def diagnostics(self) -> DiagnosticReader:
        return cast("DiagnosticReader", self._member_of("diagnostics"))


class _CommitLosingOnceUnitOfWork:
    """A ``UnitOfWork`` whose first ``commit`` reports a commit-time conflict and
    rolls back, and whose later commits delegate (the driver's commit-time reload)."""

    def __init__(
        self, inner: InMemoryUnitOfWork, losses: list[int] | None = None
    ) -> None:
        self._inner = inner
        self._losses = [1] if losses is None else losses
        self.commits = 0

    def begin(self) -> _CommitLosingOnceUnitOfWork:
        return _CommitLosingOnceUnitOfWork(self._inner.begin(), self._losses)

    def commit(self) -> Result[None]:
        if self._losses[0] > 0:
            self._losses[0] -= 1
            self._inner.rollback()
            return _stub_conflict()
        return self._inner.commit()

    def rollback(self) -> None:
        self._inner.rollback()

    @property
    def experiments(self) -> ExperimentRepository:
        return self._inner.experiments

    @property
    def engine_runs(self) -> EngineRunRepository:
        return self._inner.engine_runs

    @property
    def command_invocations(self) -> Any:
        return self._inner.command_invocations

    @property
    def retry_decisions(self) -> RetryDecisionRepository:
        return self._inner.retry_decisions

    @property
    def availability_observations(self) -> RuntimeAvailabilityObservationReader:
        return self._inner.availability_observations

    @property
    def diagnostics(self) -> DiagnosticReader:
        return self._inner.diagnostics


def _lose_once(losses: int = 1) -> Callable[..., object]:
    remaining = [losses]

    def interceptor(real: Callable[..., object], *args: Any, **kwargs: Any) -> object:
        if remaining[0] > 0:
            remaining[0] -= 1
            return _stub_conflict()
        return real(*args, **kwargs)

    return interceptor


# --------------------------------------------------------------------------
# A. The seventeenth request and the outcome projection (plan 3.12, 2.6)
# --------------------------------------------------------------------------


def test_the_seventeenth_request_maps_one_to_one_onto_the_operation() -> None:
    assert len(REQUEST_OPERATIONS) == 17
    assert REQUEST_OPERATIONS[SemanticOutcomeRequest] == _OPERATION
    assert tuple(REQUEST_OPERATIONS)[-1] is SemanticOutcomeRequest
    assert tuple(REQUEST_OPERATIONS.values()).count(_OPERATION) == 1
    assert len(set(REQUEST_OPERATIONS.values())) == 17
    assert SemanticOutcomeRequest.__module__ == "crypto_lab.experiments.requests"
    assert apply_command_semantic_outcome.__name__ == _OPERATION
    assert apply_command_semantic_outcome.__module__ == (
        "crypto_lab.experiments.semantic_outcome"
    )


def test_the_request_declares_the_plan_field_order_and_no_derived_state() -> None:
    assert tuple(SemanticOutcomeRequest.model_fields) == (
        "schema_version",
        *_REQUEST_FIELDS,
    )
    assert not _DERIVED_FIELD_NAMES & set(SemanticOutcomeRequest.model_fields)
    assert tuple(SemanticOutcome.model_fields) == _OUTCOME_FIELDS


def test_the_request_is_strict_frozen_and_closed() -> None:
    seeded = _validate_seed()
    request = _validate_request(seeded)
    payload = request.model_dump(mode="python")
    assert SemanticOutcomeRequest.model_validate(payload) == request
    with pytest.raises(ValidationError):
        SemanticOutcomeRequest.model_validate({**payload, "verdict": "FAILED"})
    with pytest.raises(ValidationError):
        SemanticOutcomeRequest.model_validate({**payload, "schema_version": "1.0.1"})
    with pytest.raises(ValidationError):
        request.__setattr__("expected_run_revision", 9)
    with pytest.raises(ValidationError):
        SemanticOutcomeRequest.model_validate({**payload, "expected_run_revision": -1})
    with pytest.raises(ValidationError):
        SemanticOutcomeRequest.model_validate({**payload, "expected_run_revision": "1"})
    # Absent optional material is MISSING, never None, in both dump modes.
    bare = _request(seeded)
    assert _missing(bare.parsed_output)
    assert _missing(bare.protocol_failure)
    for mode in ("python", "json"):
        assert None not in bare.model_dump(mode=mode).values()


def test_the_request_admits_either_parse_outcome_or_none_and_nothing_else() -> None:
    seeded = _validate_seed()
    validation = _validation_parse()
    manifest = _manifest_parse()
    assert _request(seeded, parsed_output=validation).parsed_output == validation
    assert _request(seeded, parsed_output=manifest).parsed_output == manifest
    assert _missing(_request(seeded).parsed_output)
    with pytest.raises(ValidationError):
        _request(seeded, parsed_output="not a parse outcome")
    with pytest.raises(ValidationError):
        _request(seeded, parsed_output=_protocol_failure())
    with pytest.raises(ValidationError):
        _request(seeded, protocol_failure=validation)


def test_the_request_bounds_candidate_observations_and_requires_unique_paths() -> None:
    seeded = _run_seed()
    observations = tuple(
        CandidateObservation(
            relative_path=f"results/candidate-{index}.bin",
            observed_size_bytes=index,
            observed_sha256=_HASH,
            contains_attempt_token=False,
        )
        for index in range(_MAX_OBSERVATIONS + 1)
    )
    accepted = _request(seeded, candidate_observations=observations[:_MAX_OBSERVATIONS])
    assert len(accepted.candidate_observations) == _MAX_OBSERVATIONS
    # The request's bound is the reconciler's bound, spelled once in each module.
    assert MAX_CANDIDATE_OBSERVATIONS == _MAX_OBSERVATIONS == 512
    with pytest.raises(ValidationError):
        _request(seeded, candidate_observations=observations)
    with pytest.raises(ValidationError, match="unique"):
        _request(
            seeded,
            candidate_observations=(observations[0], observations[0]),
        )


def test_the_package_exports_exactly_the_task_seven_surface() -> None:
    exported = set(experiments_package.__all__)
    assert {"SemanticOutcome", "SemanticOutcomeRequest", _OPERATION} <= exported
    assert experiments_package.SemanticOutcome is SemanticOutcome
    assert experiments_package.SemanticOutcomeRequest is SemanticOutcomeRequest
    assert experiments_package.apply_command_semantic_outcome is (
        apply_command_semantic_outcome
    )
    assert issubclass(SemanticOutcomeRequest, CanonicalModel)
    assert issubclass(SemanticOutcome, CanonicalModel)
    # Unpublished by decision (plan 12.1): no registry entry names either model. The
    # registry count itself is pinned by the Stage 3 and 5 guards, never here.
    assert all(
        "semantic-outcome" not in definition.relative_path.as_posix()
        for definition in SCHEMA_DEFINITIONS
    )


def test_the_outcome_projection_enforces_its_shape() -> None:
    invocation = sample_invocation(_C.EXITED, kind=_K.VALIDATE)
    ready = sample_run(_R.READY)
    cancelled = sample_run(_R.CANCELLED)
    assert SemanticOutcome(
        invocation=invocation, run=cancelled, superseded_by=_R.CANCELLED
    )
    with pytest.raises(ValidationError, match="reconciliation"):
        # An absent reconciliation is the core-win answer alone (plan 10 step 3).
        SemanticOutcome(invocation=invocation, run=ready)
    with pytest.raises(ValidationError, match="reconciliation"):
        SemanticOutcome(
            invocation=invocation, run=sample_run(_R.FAILED), superseded_by=_R.FAILED
        )
    with pytest.raises(ValidationError, match="superseded_by"):
        SemanticOutcome(
            invocation=invocation, run=cancelled, superseded_by=_R.TIMED_OUT
        )
    with pytest.raises(ValidationError, match="linked"):
        SemanticOutcome(
            invocation=sample_invocation(
                _C.EXITED, kind=_K.VALIDATE, run_id=OTHER_RUN_ID
            ),
            run=cancelled,
            superseded_by=_R.CANCELLED,
        )
    with pytest.raises(ValidationError, match="success"):
        SemanticOutcome(
            invocation=sample_invocation(_C.EXITED, kind=_K.RUN),
            run=sample_run(_R.SUCCEEDED),
            superseded_by=_R.SUCCEEDED,
        )
    with pytest.raises(ValidationError):
        SemanticOutcome.model_validate(
            {
                "invocation": invocation,
                "run": cancelled,
                "superseded_by": "CANCELLED",
                "x": 1,
            }
        )


# --------------------------------------------------------------------------
# B. Step 1: the shape of the loaded pair (plan 10 step 1)
# --------------------------------------------------------------------------


def test_a_describe_invocation_has_no_semantic_outcome_to_apply() -> None:
    describe = sample_invocation(
        _C.EXITED, kind=_K.DESCRIBE, adapter_name="fake.conformant"
    )
    seeded = _seed(invocation=describe)
    before = seeded.snapshot()
    result, calls = _apply_recorded(seeded, _request(seeded))
    diagnostic = _assert_service_failure(result, INVARIANT_VIOLATION)
    assert diagnostic.details["command_kind"] == "DESCRIBE"
    assert calls == _LOAD_PAIR
    assert seeded.snapshot() == before


@pytest.mark.parametrize(
    "state",
    [
        _C.PENDING,
        _C.STARTING,
        _C.RUNNING,
        _C.CANCELLED,
        _C.TIMED_OUT,
        _C.PROTOCOL_FAILED,
    ],
    ids=lambda state: state.value,
)
def test_only_an_exited_invocation_is_reconciled(state: CommandInvocationState) -> None:
    seeded = _seed(invocation=sample_invocation(state, kind=_K.VALIDATE))
    before = seeded.snapshot()
    result, calls = _apply_recorded(seeded, _request(seeded))
    diagnostic = _assert_service_failure(result, INVARIANT_VIOLATION)
    assert diagnostic.details["stored_state"] == state.value
    assert calls == _LOAD_PAIR
    assert seeded.snapshot() == before


def test_an_invocation_linked_to_another_run_is_an_invariant_violation() -> None:
    other = sample_run(_R.VALIDATING, run_id=OTHER_RUN_ID, logical_slot_id=SLOT_B)
    seeded = _seed(
        invocation=sample_invocation(_C.EXITED, kind=_K.VALIDATE, run_id=OTHER_RUN_ID),
        extra=(other,),
    )
    before = seeded.snapshot()
    result, calls = _apply_recorded(seeded, _validate_request(seeded))
    _assert_service_failure(result, INVARIANT_VIOLATION)
    assert calls == _LOAD_PAIR
    assert seeded.snapshot() == before


@pytest.mark.parametrize(
    ("kind", "output"),
    [(_K.VALIDATE, _manifest_parse()), (_K.RUN, _validation_parse())],
    ids=["manifest-for-validate", "validation-result-for-run"],
)
def test_a_parse_outcome_of_the_wrong_kind_is_an_invariant_violation(
    kind: CommandKind, output: ManifestParse | ValidationResultParse
) -> None:
    seeded = _validate_seed() if kind is _K.VALIDATE else _run_seed()
    before = seeded.snapshot()
    result, calls = _apply_recorded(seeded, _request(seeded, parsed_output=output))
    diagnostic = _assert_service_failure(result, INVARIANT_VIOLATION)
    assert diagnostic.details["command_kind"] == kind.value
    assert calls == _LOAD_PAIR
    assert seeded.snapshot() == before


def test_a_missing_invocation_or_run_is_the_repository_invariant_violation() -> None:
    seeded = _validate_seed()
    before = seeded.snapshot()
    absent = _request(seeded, invocation_id=OTHER_INVOCATION_ID)
    _assert_repository_failure(_apply(absent, InMemoryUnitOfWork(seeded.store)))
    absent_run = _request(seeded, run_id=OTHER_RUN_ID)
    _assert_repository_failure(_apply(absent_run, InMemoryUnitOfWork(seeded.store)))
    assert seeded.snapshot() == before


def _assert_repository_failure(result: object) -> None:
    assert _code(result) == INVARIANT_VIOLATION
    assert isinstance(result, Failure)
    assert result.diagnostics[0].source_component == _REPOSITORY_SOURCE


# --------------------------------------------------------------------------
# C. Step 2: expected revisions before every state precondition (plan 10 step 2)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("offset", [-1, 1], ids=["stale", "future"])
def test_a_wrong_invocation_revision_is_a_stable_conflict(offset: int) -> None:
    seeded = _validate_seed()
    before = seeded.snapshot()
    request = _validate_request(
        seeded, invocation_revision=seeded.invocation.revision + offset
    )
    result, calls = _apply_recorded(seeded, request)
    diagnostic = _assert_service_failure(result, CONCURRENCY_CONFLICT)
    assert diagnostic.details == {
        "expected_revision": seeded.invocation.revision + offset,
        "stored_revision": seeded.invocation.revision,
    }
    assert calls == _LOAD_PAIR
    assert seeded.snapshot() == before


@pytest.mark.parametrize("offset", [-1, 1], ids=["stale", "future"])
def test_a_wrong_run_revision_is_a_stable_conflict(offset: int) -> None:
    seeded = _run_seed()
    before = seeded.snapshot()
    request = _run_request(seeded, run_revision=seeded.run.revision + offset)
    result, calls = _apply_recorded(seeded, request)
    diagnostic = _assert_service_failure(result, CONCURRENCY_CONFLICT)
    assert diagnostic.details == {
        "expected_revision": seeded.run.revision + offset,
        "stored_revision": seeded.run.revision,
    }
    assert diagnostic.run_id == RUN_ID
    assert calls == _LOAD_PAIR
    assert seeded.snapshot() == before


def test_the_revision_check_precedes_the_state_preconditions() -> None:
    """Plan 10 step 2 / Task 7 Step 1: after ``begin_linked_launch`` a re-issue with
    the pre-launch run revision is a stable conflict; one with the post-launch
    revision is the invariant violation of a ``STARTING`` run the validate
    reconciler does not admit."""
    seeded = _seed(
        run=sample_run(_R.READY),
        extra=(
            sample_invocation(
                _C.PENDING, kind=_K.RUN, invocation_id=OTHER_INVOCATION_ID
            ),
        ),
    )
    launched = _ok(
        begin_linked_launch(
            LinkedLaunchRequest(
                schema_version="1.0.0",
                invocation_id=OTHER_INVOCATION_ID,
                expected_invocation_revision=0,
                run_id=RUN_ID,
                expected_run_revision=seeded.run.revision,
            ),
            unit_of_work=InMemoryUnitOfWork(seeded.store),
            clock=FixedClock(_NOW),
        )
    )
    assert launched.run.state is _R.STARTING
    before = seeded.snapshot()
    stale = _validate_request(seeded, run_revision=seeded.run.revision)
    _assert_service_failure(
        _apply(stale, InMemoryUnitOfWork(seeded.store)), CONCURRENCY_CONFLICT
    )
    current = _validate_request(seeded, run_revision=launched.run.revision)
    diagnostic = _assert_service_failure(
        _apply(current, InMemoryUnitOfWork(seeded.store)), INVARIANT_VIOLATION
    )
    assert "STARTING" in diagnostic.message
    assert seeded.snapshot() == before


# --------------------------------------------------------------------------
# D. Step 3: a core win is returned unchanged (plan 10 step 3, spec 17.1)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "state"),
    [
        (_K.VALIDATE, _R.CANCELLED),
        (_K.VALIDATE, _R.TIMED_OUT),
        (_K.RUN, _R.CANCELLED),
        (_K.RUN, _R.TIMED_OUT),
    ],
    ids=lambda item: item.value,
)
def test_a_run_already_cancelled_or_timed_out_is_returned_as_superseded(
    kind: CommandKind, state: EngineRunState
) -> None:
    seeded = _seed(
        run=sample_run(state), invocation=sample_invocation(_C.EXITED, kind=kind)
    )
    before = seeded.snapshot()
    clock = CountingClock(_NOW)
    request = _validate_request(seeded) if kind is _K.VALIDATE else _run_request(seeded)
    result, calls = _apply_recorded(seeded, request, clock=clock)
    outcome = _ok(result)
    assert outcome.invocation == seeded.invocation
    assert outcome.run == seeded.run
    assert _missing(outcome.reconciliation)
    assert outcome.superseded_by is state
    assert calls == _LOAD_PAIR
    assert clock.reads == 1
    assert seeded.snapshot() == before
    # Idempotent: the same answer again, still no write.
    assert _ok(_apply(request, InMemoryUnitOfWork(seeded.store))) == outcome
    assert seeded.snapshot() == before


# --------------------------------------------------------------------------
# E. Step 4: the experiment, the frozen slot and the reconciler's own rules
# --------------------------------------------------------------------------


def test_a_validate_summary_carrying_declarations_is_an_invariant_violation() -> None:
    seeded = _validate_seed()
    before = seeded.snapshot()
    request = _validate_request(seeded, protocol_summary=_summary(_DECLARATION))
    result, calls = _apply_recorded(seeded, request)
    _assert_service_failure(result, INVARIANT_VIOLATION)
    assert calls == (*_LOAD_PAIR, *_LOAD_EXPERIMENT)
    assert seeded.snapshot() == before


def test_a_protocol_failure_naming_another_invocation_is_an_invariant_violation() -> (
    None
):
    seeded = _run_seed()
    before = seeded.snapshot()
    request = _run_request(
        seeded, protocol_failure=_protocol_failure(OTHER_INVOCATION_ID)
    )
    result, calls = _apply_recorded(seeded, request)
    _assert_service_failure(result, INVARIANT_VIOLATION)
    assert calls == (*_LOAD_PAIR, *_LOAD_EXPERIMENT)
    assert seeded.snapshot() == before


@pytest.mark.parametrize(
    ("kind", "state"),
    [(_K.VALIDATE, _R.STARTING), (_K.VALIDATE, _R.RUNNING), (_K.RUN, _R.READY)],
    ids=lambda item: item.value,
)
def test_a_run_state_the_reconciler_does_not_admit_is_an_invariant_violation(
    kind: CommandKind, state: EngineRunState
) -> None:
    seeded = _seed(
        run=sample_run(state), invocation=sample_invocation(_C.EXITED, kind=kind)
    )
    before = seeded.snapshot()
    request = _validate_request(seeded) if kind is _K.VALIDATE else _run_request(seeded)
    result, calls = _apply_recorded(seeded, request)
    diagnostic = _assert_service_failure(result, INVARIANT_VIOLATION)
    assert state.value in diagnostic.message
    assert calls == (*_LOAD_PAIR, *_LOAD_EXPERIMENT)
    assert seeded.snapshot() == before


def test_a_run_whose_slot_has_no_frozen_compatibility_entry_is_an_invariant() -> None:
    single = sample_draft(
        selected_engine_slots=(
            SelectedEngineSlot(
                logical_slot_id=SLOT_B,
                slot_ordinal=0,
                adapter=ADAPTER_BETA,
                engine=ENGINE_BETA,
            ),
        )
    )
    experiment = sample_experiment(_E.RUNNING, draft=single)
    assert tuple(entry.logical_slot_id for entry in experiment.slot_compatibility) == (
        SLOT_B,
    )
    seeded = _seed(experiment=experiment)
    before = seeded.snapshot()
    result, calls = _apply_recorded(seeded, _validate_request(seeded))
    diagnostic = _assert_service_failure(result, INVARIANT_VIOLATION)
    assert diagnostic.details["logical_slot_id"] == SLOT_A
    assert calls == (*_LOAD_PAIR, *_LOAD_EXPERIMENT)
    assert seeded.snapshot() == before


def test_a_missing_experiment_is_the_repository_invariant_violation() -> None:
    seeded = _seed(seed_experiment=False)
    before = seeded.snapshot()
    result, calls = _apply_recorded(seeded, _validate_request(seeded))
    assert _code(result) == INVARIANT_VIOLATION
    assert isinstance(result, Failure)
    assert result.diagnostics[0].source_component == _REPOSITORY_SOURCE
    assert calls == (*_LOAD_PAIR, *_LOAD_EXPERIMENT)
    assert seeded.snapshot() == before


# --------------------------------------------------------------------------
# F. First application of every verdict (plan 9.3, 10 steps 7-9)
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Scenario:
    """One Task 6 verdict driven end to end: its inputs and the mapped run state."""

    name: str
    kind: CommandKind
    exit_value: int
    verdict: ReconciliationVerdict
    target: EngineRunState | None
    code: str | None
    validation_outcome: ValidationOutcome | None = None
    status: SemanticStatus | None = None
    observation_expected: bool = True

    def seed(self) -> _Seeded:
        if self.kind is _K.VALIDATE:
            return _validate_seed(self.exit_value)
        return _run_seed(self.exit_value)

    def request(self, seeded: _Seeded, **overrides: Any) -> SemanticOutcomeRequest:
        if self.kind is _K.VALIDATE:
            return _validate_request(seeded, self.validation_outcome, **overrides)
        return _run_request(seeded, self.status, **overrides)

    @property
    def writes_run(self) -> bool:
        return self.target is not None

    @property
    def writes_invocation(self) -> bool:
        return self.code is not None


_SCENARIOS: Final = (
    _Scenario(
        "validated-ready",
        _K.VALIDATE,
        0,
        _V.VALIDATED_READY,
        _R.READY,
        None,
        validation_outcome=_O.VALID,
    ),
    _Scenario(
        "validate-not-applicable",
        _K.VALIDATE,
        20,
        _V.NOT_APPLICABLE,
        _R.NOT_APPLICABLE,
        COMPAT_NOT_APPLICABLE,
        validation_outcome=_O.NOT_APPLICABLE,
        observation_expected=False,
    ),
    _Scenario(
        "validate-unavailable",
        _K.VALIDATE,
        30,
        _V.UNAVAILABLE,
        _R.UNAVAILABLE,
        ADAPTER_UNAVAILABLE,
        validation_outcome=_O.UNAVAILABLE,
    ),
    _Scenario(
        "validate-failed",
        _K.VALIDATE,
        10,
        _V.FAILED,
        _R.FAILED,
        SCHEMA_REQUEST_INVALID,
        validation_outcome=_O.INVALID,
        observation_expected=False,
    ),
    _Scenario(
        "result-finalization-eligible",
        _K.RUN,
        0,
        _V.RESULT_FINALIZATION_ELIGIBLE,
        None,
        None,
        status=_S.SUCCEEDED,
    ),
    _Scenario(
        "eligible-with-warnings",
        _K.RUN,
        0,
        _V.RESULT_FINALIZATION_ELIGIBLE,
        None,
        None,
        status=_S.SUCCEEDED_WITH_WARNINGS,
    ),
    _Scenario(
        "run-late-not-applicable",
        _K.RUN,
        20,
        _V.NOT_APPLICABLE,
        _R.NOT_APPLICABLE,
        COMPAT_LATE_NOT_APPLICABLE,
        status=_S.NOT_APPLICABLE,
    ),
    _Scenario(
        "run-late-unavailable",
        _K.RUN,
        30,
        _V.UNAVAILABLE,
        _R.UNAVAILABLE,
        ADAPTER_UNAVAILABLE,
        status=_S.UNAVAILABLE,
    ),
    _Scenario(
        "run-failed-declaration",
        _K.RUN,
        0,
        _V.FAILED,
        _R.FAILED,
        ENGINE_RUNTIME_FAILURE,
        status=_S.FAILED,
    ),
    _Scenario(
        "run-crashed-without-manifest",
        _K.RUN,
        40,
        _V.FAILED,
        _R.FAILED,
        ENGINE_RUNTIME_FAILURE,
        status=None,
    ),
)
_WRITING_SCENARIOS: Final = tuple(item for item in _SCENARIOS if item.writes_run)
_ELIGIBLE: Final = _SCENARIOS[4]
_READY: Final = _SCENARIOS[0]
_VALIDATE_FAILED: Final = _SCENARIOS[3]
_RUN_FAILED: Final = _SCENARIOS[9]
_SCENARIO_IDS: Final = [item.name for item in _SCENARIOS]


def _expected_calls(scenario: _Scenario) -> tuple[tuple[str, str], ...]:
    calls: tuple[tuple[str, str], ...] = (
        *_LOAD_PAIR,
        *_LOAD_EXPERIMENT,
        *_PRECONDITION_READS,
    )
    if scenario.writes_run:
        calls = (*calls, *_RUN_SWAP)
    if scenario.writes_invocation:
        calls = (*calls, *_INVOCATION_SWAP)
    return calls


def _first_application(
    scenario: _Scenario, *, clock: FixedClock | None = None
) -> tuple[
    _Seeded, SemanticOutcomeRequest, SemanticOutcome, tuple[tuple[str, str], ...]
]:
    seeded = scenario.seed()
    request = scenario.request(seeded)
    result, calls = _apply_recorded(seeded, request, clock=clock)
    return seeded, request, _ok(result), calls


@pytest.mark.parametrize("scenario", _SCENARIOS, ids=_SCENARIO_IDS)
def test_every_verdict_lands_the_run_in_its_mapped_state(scenario: _Scenario) -> None:
    seeded, request, outcome, calls = _first_application(scenario)
    reconciliation = outcome.reconciliation
    assert not _missing(reconciliation)
    assert reconciliation.command_kind is scenario.kind
    assert reconciliation.verdict is scenario.verdict
    assert _missing(outcome.superseded_by)
    assert calls == _expected_calls(scenario)
    assert outcome.run == seeded.stored_run()
    assert outcome.invocation == seeded.stored_invocation()
    assert outcome.run.state not in SUCCESS_ENGINE_RUN_STATES
    # The experiment is never written.
    assert seeded.store.committed_experiments() == (seeded.experiment,)
    if scenario.target is None:
        assert outcome.run == seeded.run
        assert outcome.run.state is _R.RUNNING
        assert outcome.invocation == seeded.invocation
        assert not _missing(reconciliation.sanitized_manifest)
        assert reconciliation.semantic_status is scenario.status
        return
    assert outcome.run.state is scenario.target
    assert outcome.run.revision == seeded.run.revision + 1
    assert outcome.run.updated_at_utc == _NOW
    if scenario.code is None:
        assert _missing(reconciliation.primary_diagnostic)
        assert _missing(outcome.run.primary_terminal_diagnostic_id)
        assert outcome.invocation == seeded.invocation
    else:
        primary = reconciliation.primary_diagnostic
        assert not _missing(primary)
        assert primary.error_code == scenario.code
        assert outcome.run.primary_terminal_diagnostic_id == primary.diagnostic_id
        assert outcome.invocation.state is _C.EXITED
        assert outcome.invocation.diagnostic_ids == (primary.diagnostic_id,)
        assert outcome.invocation.revision == seeded.invocation.revision + 1
        assert outcome.invocation.updated_at_utc == _NOW
        assert _missing(outcome.invocation.primary_diagnostic_id)
    if scenario.observation_expected:
        assert outcome.run.availability_observation_id == AVAIL_A
    else:
        assert _missing(outcome.run.availability_observation_id)
    _assert_token_free(outcome.run, outcome.invocation, reconciliation)
    assert request.parsed_output == scenario.request(seeded).parsed_output


def test_the_slot_observation_is_written_exactly_on_ready_and_unavailable() -> None:
    for scenario in _WRITING_SCENARIOS:
        _, _, outcome, _ = _first_application(scenario)
        present = not _missing(outcome.run.availability_observation_id)
        if scenario.target in (_R.READY, _R.UNAVAILABLE):
            assert present, scenario.name
            assert outcome.run.availability_observation_id == AVAIL_A
        elif scenario.kind is _K.VALIDATE:
            assert not present, scenario.name
        else:
            # A RUNNING run already carried the slot's observation; it is carried.
            assert outcome.run.availability_observation_id == AVAIL_A


def test_the_late_not_applicable_primary_cites_the_explaining_adapter_diagnostic() -> (
    None
):
    _, _, outcome, _ = _first_application(_SCENARIOS[6])
    primary = outcome.reconciliation.primary_diagnostic
    assert primary.error_code == COMPAT_LATE_NOT_APPLICABLE
    assert primary.details["adapter_error_code"] == "ENGINE.DATA_GAP"
    assert primary.details["adapter_manifest_id"] == _MANIFEST_ID
    assert primary.causal_diagnostic_ids == ()
    assert outcome.run.primary_terminal_diagnostic_id == primary.diagnostic_id


def test_a_crash_without_a_manifest_records_the_absence_as_a_detail() -> None:
    _, _, outcome, _ = _first_application(_RUN_FAILED)
    primary = outcome.reconciliation.primary_diagnostic
    assert primary.error_code == ENGINE_RUNTIME_FAILURE
    assert primary.details["manifest_present"] is False
    assert primary.retriable is True
    assert _missing(outcome.reconciliation.sanitized_manifest)


def test_a_protocol_failure_is_applied_as_the_run_primary() -> None:
    seeded = _run_seed()
    failure = _protocol_failure()
    request = _run_request(seeded, protocol_failure=failure)
    outcome = _ok(_apply(request, InMemoryUnitOfWork(seeded.store)))
    assert outcome.reconciliation.verdict is _V.FAILED
    assert outcome.reconciliation.primary_diagnostic == failure
    assert outcome.run.state is _R.FAILED
    assert outcome.run.primary_terminal_diagnostic_id == failure.diagnostic_id
    assert outcome.invocation.diagnostic_ids == (failure.diagnostic_id,)
    # The favourable manifest never overrides the protocol failure (plan 9.2).
    assert not _missing(outcome.reconciliation.sanitized_manifest)


def test_a_protocol_failure_already_on_the_invocation_is_not_re_added() -> None:
    failure = _protocol_failure()
    invocation = CommandInvocationRecord.model_validate(
        {
            **sample_invocation(_C.EXITED, kind=_K.RUN).model_dump(mode="python"),
            "diagnostic_ids": (failure.diagnostic_id,),
        }
    )
    seeded = _seed(run=sample_run(_R.RUNNING), invocation=invocation)
    request = _run_request(seeded, protocol_failure=failure)
    result, calls = _apply_recorded(seeded, request)
    outcome = _ok(result)
    assert outcome.run.state is _R.FAILED
    assert outcome.run.primary_terminal_diagnostic_id == failure.diagnostic_id
    assert outcome.invocation == seeded.invocation
    assert calls == (*_LOAD_PAIR, *_LOAD_EXPERIMENT, *_PRECONDITION_READS, *_RUN_SWAP)
    # A re-issue at the new run revision replays: the run is at its target and the
    # invocation already carries the identity.
    replay = _ok(
        _apply(
            _replay_request(seeded, request, outcome), InMemoryUnitOfWork(seeded.store)
        )
    )
    assert replay == outcome


@pytest.mark.parametrize(
    ("name", "overrides", "code"),
    [
        (
            "final-result-hash-mismatch",
            {
                "protocol_summary": _run_material(
                    _S.SUCCEEDED, final_hash=_OTHER_HASH
                ).summary
            },
            ARTIFACT_RESULT_MANIFEST_INVALID,
        ),
        (
            "leaking-candidate",
            {
                "candidate_observations": _run_material(
                    _S.SUCCEEDED, leaking=True
                ).observations
            },
            SECURITY_SENSITIVE_MATERIAL_LEAKAGE,
        ),
        (
            "manifest-for-another-attempt",
            {
                "parsed_output": _manifest_parse(
                    _manifest_document(invocation_id=OTHER_INVOCATION_ID)
                )
            },
            PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
        ),
    ],
    ids=["final-result-hash-mismatch", "leaking-candidate", "stale-manifest"],
)
def test_a_favourable_exit_and_manifest_never_succeed_past_a_failed_check(
    name: str, overrides: dict[str, Any], code: str
) -> None:
    del name
    seeded = _run_seed(0)
    request = _run_request(seeded, **overrides)
    outcome = _ok(_apply(request, InMemoryUnitOfWork(seeded.store)))
    assert outcome.reconciliation.verdict is _V.FAILED
    assert outcome.reconciliation.primary_diagnostic.error_code == code
    assert outcome.run.state is _R.FAILED
    assert outcome.run == seeded.stored_run()


def test_a_stale_validation_result_fails_the_run_at_the_identity_check() -> None:
    seeded = _validate_seed(0)
    stale = _validation_parse(_validation_document(invocation_id=OTHER_INVOCATION_ID))
    outcome = _ok(
        _apply(_request(seeded, parsed_output=stale), InMemoryUnitOfWork(seeded.store))
    )
    primary = outcome.reconciliation.primary_diagnostic
    assert primary.error_code == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    assert outcome.run.state is _R.FAILED
    assert _missing(outcome.reconciliation.sanitized_validation_result)


def test_the_operation_reads_the_injected_clock_once_and_stamps_both_records() -> None:
    clock = CountingClock(_LATER)
    _, _, outcome, _ = _first_application(_VALIDATE_FAILED, clock=clock)
    assert clock.reads == 1
    assert outcome.run.updated_at_utc == _LATER
    assert outcome.invocation.updated_at_utc == _LATER
    assert outcome.reconciliation.primary_diagnostic.timestamp_utc == _LATER


def test_the_request_and_its_parse_outcome_are_never_mutated() -> None:
    seeded = _run_seed(0)
    request = _run_request(seeded)
    frozen = request.model_dump(mode="python")
    _ok(_apply(request, InMemoryUnitOfWork(seeded.store)))
    assert request.model_dump(mode="python") == frozen
    assert isinstance(request.parsed_output, ManifestParse)
    assert request.parsed_output.manifest.attempt_token == ATTEMPT_TOKEN


def test_the_raw_token_reaches_no_authoritative_record_or_diagnostic() -> None:
    seeded = _run_seed(0)
    request = _run_request(seeded, _S.SUCCEEDED_WITH_WARNINGS)
    assert isinstance(request.parsed_output, ManifestParse)
    assert (
        ATTEMPT_TOKEN in canonical_json_bytes(request.parsed_output.manifest).decode()
    )
    outcome = _ok(_apply(request, InMemoryUnitOfWork(seeded.store)))
    _assert_token_free(
        outcome.run,
        outcome.invocation,
        outcome.reconciliation,
        *seeded.store.committed_engine_runs(),
        *seeded.store.committed_command_invocations(),
    )
    failed = _run_seed(40)
    result = _ok(_apply(_run_request(failed, None), InMemoryUnitOfWork(failed.store)))
    _assert_token_free(result, *result.reconciliation.diagnostics)


# --------------------------------------------------------------------------
# G. Step 6: the authoritative reads before any write (plan 10 step 6, 1.5 item 3)
# --------------------------------------------------------------------------

_PRECONDITION_SCENARIOS: Final = (_READY, _VALIDATE_FAILED, _ELIGIBLE, _RUN_FAILED)
_PRECONDITION_IDS: Final = [item.name for item in _PRECONDITION_SCENARIOS]


def _successor(run: EngineRunRecord) -> EngineRunRecord:
    return sample_run(
        _R.PENDING,
        run_id=OTHER_RUN_ID,
        attempt_number=run.attempt_number + 1,
        predecessor_run_id=run.run_id,
        logical_slot_id=run.logical_slot_id,
    )


@pytest.mark.parametrize("scenario", _PRECONDITION_SCENARIOS, ids=_PRECONDITION_IDS)
def test_a_run_that_is_not_the_slots_current_attempt_is_refused(
    scenario: _Scenario,
) -> None:
    seeded = scenario.seed()
    transaction = InMemoryUnitOfWork(seeded.store).begin()
    _ok(transaction.engine_runs.add_attempt(_successor(seeded.run)))
    _commit(transaction)
    before = seeded.snapshot()
    result, calls = _apply_recorded(seeded, scenario.request(seeded))
    diagnostic = _assert_service_failure(result, INVARIANT_VIOLATION)
    assert diagnostic.details["latest_attempt_run_id"] == OTHER_RUN_ID
    assert calls == (*_LOAD_PAIR, *_LOAD_EXPERIMENT, _PRECONDITION_READS[0])
    assert seeded.snapshot() == before


@pytest.mark.parametrize("scenario", _PRECONDITION_SCENARIOS, ids=_PRECONDITION_IDS)
@pytest.mark.parametrize(
    "state", [_E.COMPLETED, _E.FAILED, _E.CANCELLED], ids=lambda state: state.value
)
def test_an_experiment_no_longer_running_refuses_a_first_application(
    scenario: _Scenario, state: ExperimentState
) -> None:
    experiment = sample_experiment(state, include_compatibility=True)
    seeded = scenario.seed()
    transaction = InMemoryUnitOfWork(seeded.store).begin()
    replacement = ExperimentRecord.model_validate(
        {
            **experiment.model_dump(mode="python"),
            "revision": seeded.experiment.revision + 1,
            "updated_at_utc": _NOW,
        }
    )
    _ok(
        transaction.experiments.compare_and_swap(
            seeded.experiment.revision, replacement
        )
    )
    _commit(transaction)
    before = seeded.snapshot()
    result, calls = _apply_recorded(seeded, scenario.request(seeded))
    diagnostic = _assert_service_failure(result, INVARIANT_VIOLATION)
    assert diagnostic.details["experiment_state"] == state.value
    assert calls == (*_LOAD_PAIR, *_LOAD_EXPERIMENT, *_PRECONDITION_READS[:1])
    assert seeded.snapshot() == before


@pytest.mark.parametrize("scenario", _PRECONDITION_SCENARIOS, ids=_PRECONDITION_IDS)
@pytest.mark.parametrize(
    "other_kind", [_K.VALIDATE, _K.RUN], ids=lambda kind: kind.value
)
def test_a_second_open_invocation_of_the_run_refuses_a_first_application(
    scenario: _Scenario, other_kind: CommandKind
) -> None:
    seeded = scenario.seed()
    other = sample_invocation(
        _C.PENDING,
        kind=other_kind,
        invocation_id=OTHER_INVOCATION_ID,
        created_at_utc=INSTANT + timedelta(minutes=1),
    )
    transaction = InMemoryUnitOfWork(seeded.store).begin()
    _ok(transaction.command_invocations.add(other))
    _commit(transaction)
    before = seeded.snapshot()
    result, calls = _apply_recorded(seeded, scenario.request(seeded))
    diagnostic = _assert_service_failure(result, INVARIANT_VIOLATION)
    assert diagnostic.details["open_invocation_id"] == OTHER_INVOCATION_ID
    assert diagnostic.details["open_command_kind"] == other_kind.value
    expected_reads = 2 if other_kind is _K.VALIDATE else 3
    assert calls == (
        *_LOAD_PAIR,
        *_LOAD_EXPERIMENT,
        *_PRECONDITION_READS[:expected_reads],
    )
    assert seeded.snapshot() == before


def _stub_success(value: object) -> Callable[..., object]:
    def answer(*_args: object, **_kwargs: object) -> Success[Any]:
        return Success[Any](outcome="SUCCESS", value=value)

    return answer


@pytest.mark.parametrize(
    ("member", "method"),
    [("engine_runs", "latest_attempt"), ("command_invocations", "list_for_run")],
    ids=["latest-attempt", "list-for-run"],
)
def test_a_repository_read_fault_at_step_six_is_returned_without_a_write(
    member: str, method: str
) -> None:
    seeded = _VALIDATE_FAILED.seed()
    before = seeded.snapshot()
    root = MemberOverridingUnitOfWork(
        InMemoryUnitOfWork(seeded.store), member, {method: _always_lose}
    )
    result = _apply(_VALIDATE_FAILED.request(seeded), root)
    # The repository's own failure is returned unchanged; a Failure is never
    # reloaded, so exactly one transaction was opened.
    assert result == _stub_conflict()
    assert root.begins == 1
    assert seeded.snapshot() == before


def test_a_slot_without_a_latest_attempt_is_an_impossible_aggregate_state() -> None:
    seeded = _VALIDATE_FAILED.seed()
    before = seeded.snapshot()
    root = MemberOverridingUnitOfWork(
        InMemoryUnitOfWork(seeded.store),
        "engine_runs",
        {"latest_attempt": _stub_success(MISSING)},
    )
    result = _apply(_VALIDATE_FAILED.request(seeded), root)
    diagnostic = _assert_service_failure(result, INVARIANT_VIOLATION)
    assert diagnostic.details["latest_attempt_run_id"] == "MISSING"
    assert seeded.snapshot() == before


def test_a_terminal_sibling_invocation_does_not_block_a_first_application() -> None:
    seeded = _READY.seed()
    sibling = sample_invocation(
        _C.CANCELLED,
        kind=_K.VALIDATE,
        invocation_id=OTHER_INVOCATION_ID,
        via=_C.PENDING,
        created_at_utc=INSTANT - timedelta(minutes=1),
    )
    transaction = InMemoryUnitOfWork(seeded.store).begin()
    _ok(transaction.command_invocations.add(sibling))
    _commit(transaction)
    outcome = _ok(_apply(_READY.request(seeded), InMemoryUnitOfWork(seeded.store)))
    assert outcome.run.state is _R.READY


def test_finalization_eligibility_performs_the_authoritative_reads_every_issue() -> (
    None
):
    seeded = _ELIGIBLE.seed()
    request = _ELIGIBLE.request(seeded)
    before = seeded.snapshot()
    for _ in range(2):
        result, calls = _apply_recorded(seeded, request)
        outcome = _ok(result)
        assert outcome.reconciliation.verdict is _V.RESULT_FINALIZATION_ELIGIBLE
        assert outcome.run.state is _R.RUNNING
        assert outcome.run.revision == seeded.run.revision
        assert calls == (*_LOAD_PAIR, *_LOAD_EXPERIMENT, *_PRECONDITION_READS)
        assert seeded.snapshot() == before


# --------------------------------------------------------------------------
# H. Atomicity: both writes or neither (plan 10 steps 7-8, spec 15.2, 23.2)
# --------------------------------------------------------------------------


def test_a_lost_run_swap_rolls_back_and_the_second_loss_returns_the_conflict() -> None:
    seeded = _VALIDATE_FAILED.seed()
    before = seeded.snapshot()
    root = MemberOverridingUnitOfWork(
        InMemoryUnitOfWork(seeded.store),
        "engine_runs",
        {"compare_and_swap": _always_lose},
    )
    result = _apply(_VALIDATE_FAILED.request(seeded), root)
    assert result == _stub_conflict()
    assert root.begins == 2
    assert seeded.snapshot() == before


def test_a_lost_invocation_swap_rolls_back_the_run_write_too() -> None:
    seeded = _VALIDATE_FAILED.seed()
    before = seeded.snapshot()
    root = MemberOverridingUnitOfWork(
        InMemoryUnitOfWork(seeded.store),
        "command_invocations",
        {"compare_and_swap": _always_lose},
    )
    result = _apply(_VALIDATE_FAILED.request(seeded), root)
    assert result == _stub_conflict()
    assert root.begins == 2
    assert seeded.snapshot() == before
    assert seeded.stored_run().state is _R.VALIDATING


@pytest.mark.parametrize(
    ("member", "scenario"),
    [
        ("engine_runs", _VALIDATE_FAILED),
        ("command_invocations", _VALIDATE_FAILED),
        ("engine_runs", _READY),
        ("engine_runs", _RUN_FAILED),
    ],
    ids=["run-swap", "invocation-swap", "ready-run-swap", "run-kind-run-swap"],
)
def test_a_swap_lost_once_is_reloaded_once_and_then_applied_exactly_once(
    member: str, scenario: _Scenario
) -> None:
    seeded = scenario.seed()
    root = _InterceptingUnitOfWork(
        InMemoryUnitOfWork(seeded.store), member, "compare_and_swap", _lose_once()
    )
    outcome = _ok(_apply(scenario.request(seeded), root))
    assert root.begins == 2
    assert outcome.run == seeded.stored_run()
    assert outcome.invocation == seeded.stored_invocation()
    assert outcome.run.state is scenario.target
    assert outcome.run.revision == seeded.run.revision + 1
    if scenario.writes_invocation:
        assert outcome.invocation.revision == seeded.invocation.revision + 1


def test_a_commit_time_conflict_is_reloaded_once_and_then_committed() -> None:
    seeded = _VALIDATE_FAILED.seed()
    root = _CommitLosingOnceUnitOfWork(InMemoryUnitOfWork(seeded.store))
    outcome = _ok(_apply(_VALIDATE_FAILED.request(seeded), root))
    assert outcome.run == seeded.stored_run()
    assert outcome.run.state is _R.FAILED
    assert outcome.invocation == seeded.stored_invocation()
    assert outcome.invocation.diagnostic_ids == (
        outcome.reconciliation.primary_diagnostic.diagnostic_id,
    )


def test_a_rebuilt_unit_of_work_over_the_same_store_sees_every_committed_effect() -> (
    None
):
    seeded, request, outcome, _ = _first_application(_VALIDATE_FAILED)
    rebuilt = InMemoryUnitOfWork(seeded.store)
    transaction = rebuilt.begin()
    assert _ok(transaction.engine_runs.get(RUN_ID)) == outcome.run
    assert _ok(transaction.command_invocations.get(INVOCATION_ID)) == outcome.invocation
    transaction.rollback()
    replay = _request(
        seeded,
        invocation_revision=outcome.invocation.revision,
        run_revision=outcome.run.revision,
        parsed_output=request.parsed_output,
    )
    assert _ok(_apply(replay, rebuilt)) == outcome


def test_an_unrepresentable_run_replacement_is_returned_and_nothing_is_written(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded = _VALIDATE_FAILED.seed()
    before = seeded.snapshot()
    failure = stage5_failure(
        INVARIANT_VIOLATION,
        "simulated unrepresentable replacement",
        source_component=_STUB_SOURCE,
        timestamp_utc=INSTANT,
    )
    monkeypatch.setattr(
        "crypto_lab.experiments.semantic_outcome.run_replacement",
        lambda *_args, **_kwargs: failure,
    )
    result, calls = _apply_recorded(seeded, _VALIDATE_FAILED.request(seeded))
    assert result == failure
    assert calls == (*_LOAD_PAIR, *_LOAD_EXPERIMENT, *_PRECONDITION_READS)
    assert seeded.snapshot() == before


def test_a_run_pair_rule_violation_maps_through_the_stage_five_rule_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded = _VALIDATE_FAILED.seed()
    before = seeded.snapshot()

    def refuse(*_args: object, **_kwargs: object) -> None:
        raise EngineRunRuleViolation(
            EngineRunCheck.REVISION, "simulated moved revision"
        )

    monkeypatch.setattr(
        "crypto_lab.experiments.semantic_outcome.assert_run_transition", refuse
    )
    result, calls = _apply_recorded(seeded, _VALIDATE_FAILED.request(seeded))
    diagnostic = _assert_service_failure(
        result, CONCURRENCY_CONFLICT, source="experiments.run_service"
    )
    assert diagnostic.details == {"check": "REVISION"}
    assert calls == (*_LOAD_PAIR, *_LOAD_EXPERIMENT, *_PRECONDITION_READS)
    assert seeded.snapshot() == before


def test_an_enrichment_predicate_violation_maps_like_the_stage_five_services(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded = _VALIDATE_FAILED.seed()
    before = seeded.snapshot()

    def refuse(*_args: object, **_kwargs: object) -> None:
        raise CommandInvocationRuleViolation(
            CommandInvocationCheck.REVISION, "simulated moved revision"
        )

    monkeypatch.setattr(
        "crypto_lab.experiments.semantic_outcome.assert_write_once_enrichment", refuse
    )
    result, calls = _apply_recorded(seeded, _VALIDATE_FAILED.request(seeded))
    diagnostic = _assert_service_failure(result, CONCURRENCY_CONFLICT)
    assert diagnostic.details == {"check": "REVISION"}
    assert calls == (*_LOAD_PAIR, *_LOAD_EXPERIMENT, *_PRECONDITION_READS, *_RUN_SWAP)
    assert seeded.snapshot() == before


def test_an_enrichment_the_record_cannot_carry_rolls_back_the_run_write() -> None:
    """An invocation already carrying ``MAX_DIAGNOSTIC_IDS`` identities cannot take
    one more; the run write of step 7 is rolled back with it."""
    full = CommandInvocationRecord.model_validate(
        {
            **sample_invocation(
                _C.EXITED, kind=_K.VALIDATE, native_exit_value=10
            ).model_dump(mode="python"),
            "diagnostic_ids": tuple(
                sequential_diagnostic_id(index) for index in range(MAX_DIAGNOSTIC_IDS)
            ),
        }
    )
    seeded = _seed(run=sample_run(_R.VALIDATING), invocation=full)
    before = seeded.snapshot()
    result, calls = _apply_recorded(seeded, _VALIDATE_FAILED.request(seeded))
    diagnostic = _assert_service_failure(result, INVARIANT_VIOLATION)
    assert diagnostic.details["diagnostic_count"] == MAX_DIAGNOSTIC_IDS + 1
    assert calls == (*_LOAD_PAIR, *_LOAD_EXPERIMENT, *_PRECONDITION_READS, *_RUN_SWAP)
    assert seeded.snapshot() == before
    assert seeded.stored_run().state is _R.VALIDATING


# --------------------------------------------------------------------------
# I. Replay, supersession and divergence (plan 10 step 5, spec 29.6)
# --------------------------------------------------------------------------


def _replay_request(
    seeded: _Seeded, request: SemanticOutcomeRequest, outcome: SemanticOutcome
) -> SemanticOutcomeRequest:
    return SemanticOutcomeRequest.model_validate(
        {
            **request.model_dump(mode="python"),
            "expected_invocation_revision": outcome.invocation.revision,
            "expected_run_revision": outcome.run.revision,
        }
    )


@pytest.mark.parametrize(
    "scenario", _WRITING_SCENARIOS, ids=[s.name for s in _WRITING_SCENARIOS]
)
def test_an_identical_re_issue_returns_the_stored_pair_and_writes_nothing(
    scenario: _Scenario,
) -> None:
    seeded, request, outcome, _ = _first_application(scenario)
    after_first = seeded.snapshot()
    clock = CountingClock(_LATER)
    result, calls = _apply_recorded(
        seeded, _replay_request(seeded, request, outcome), clock=clock
    )
    replay = _ok(result)
    assert replay.invocation == outcome.invocation
    assert replay.run == outcome.run
    assert _missing(replay.superseded_by)
    assert replay.reconciliation.verdict is outcome.reconciliation.verdict
    # Identities are content-derived: an advanced clock recomputes the same ids.
    assert tuple(d.diagnostic_id for d in replay.reconciliation.diagnostics) == tuple(
        d.diagnostic_id for d in outcome.reconciliation.diagnostics
    )
    assert clock.reads == 1
    assert calls == (*_LOAD_PAIR, *_LOAD_EXPERIMENT)
    assert seeded.snapshot() == after_first


@pytest.mark.parametrize(
    "scenario", _WRITING_SCENARIOS, ids=[s.name for s in _WRITING_SCENARIOS]
)
def test_a_re_issue_with_the_pre_write_revisions_is_a_stable_conflict(
    scenario: _Scenario,
) -> None:
    seeded, request, _, _ = _first_application(scenario)
    after_first = seeded.snapshot()
    result, calls = _apply_recorded(seeded, request)
    _assert_service_failure(result, CONCURRENCY_CONFLICT)
    assert calls == _LOAD_PAIR
    assert seeded.snapshot() == after_first


def test_a_replay_survives_a_successor_attempt_and_an_aggregated_experiment() -> None:
    seeded, request, outcome, _ = _first_application(_VALIDATE_FAILED)
    transaction = InMemoryUnitOfWork(seeded.store).begin()
    _ok(transaction.engine_runs.add_attempt(_successor(seeded.run)))
    completed = ExperimentRecord.model_validate(
        {
            **sample_experiment(_E.FAILED, include_compatibility=True).model_dump(
                mode="python"
            ),
            "revision": seeded.experiment.revision + 1,
            "updated_at_utc": _NOW,
        }
    )
    _ok(transaction.experiments.compare_and_swap(seeded.experiment.revision, completed))
    _commit(transaction)
    after = seeded.snapshot()
    result, calls = _apply_recorded(seeded, _replay_request(seeded, request, outcome))
    replay = _ok(result)
    assert replay.run == outcome.run
    assert replay.invocation == outcome.invocation
    assert _missing(replay.superseded_by)
    assert calls == (*_LOAD_PAIR, *_LOAD_EXPERIMENT)
    assert seeded.snapshot() == after


def test_a_replay_after_the_run_invocation_was_created_is_still_a_replay() -> None:
    """Plan Task 7 Step 1: ``create_invocation(RUN)`` alone leaves the run revision
    unchanged, so the re-issue is still answered from the replay step."""
    seeded, request, outcome, _ = _first_application(_READY)
    created = _ok(
        create_invocation(
            InvocationCreationRequest(
                schema_version="1.0.0",
                command_kind=_K.RUN,
                adapter_name="adapter.alpha",
                adapter_version="1.0.0",
                run_id=RUN_ID,
                expected_run_revision=outcome.run.revision,
                request_hash=REQUEST_HASH,
                timeout_seconds=120,
            ),
            unit_of_work=InMemoryUnitOfWork(seeded.store),
            clock=FixedClock(_NOW + timedelta(minutes=1)),
            identity_source=SequentialIdentitySource(),
        )
    )
    assert created.command_kind is _K.RUN
    assert created.state is _C.PENDING
    assert seeded.stored_run().revision == outcome.run.revision
    after = seeded.snapshot()
    replay = _ok(
        _apply(
            _replay_request(seeded, request, outcome), InMemoryUnitOfWork(seeded.store)
        )
    )
    assert replay.run == outcome.run
    assert replay.run.revision == outcome.run.revision
    assert seeded.snapshot() == after


def test_a_lawful_later_core_move_from_ready_is_reported_as_superseded() -> None:
    seeded, request, outcome, _ = _first_application(_READY)
    moved = _transition(
        seeded,
        _run_transition(
            outcome.run,
            _R.UNAVAILABLE,
            primary_terminal_diagnostic_id=DIAG_ID,
            availability_observation_id=AVAIL_A,
        ),
    )
    assert moved.state is _R.UNAVAILABLE
    after = seeded.snapshot()
    replay = SemanticOutcomeRequest.model_validate(
        {
            **request.model_dump(mode="python"),
            "expected_invocation_revision": outcome.invocation.revision,
            "expected_run_revision": moved.revision,
        }
    )
    result, calls = _apply_recorded(seeded, replay)
    superseded = _ok(result)
    assert superseded.run == moved
    assert superseded.invocation == outcome.invocation
    assert superseded.superseded_by is _R.UNAVAILABLE
    assert superseded.reconciliation.verdict is _V.VALIDATED_READY
    assert calls == (*_LOAD_PAIR, *_LOAD_EXPERIMENT)
    assert seeded.snapshot() == after


def test_a_core_decision_at_the_same_target_with_its_own_primary_supersedes() -> None:
    seeded = _VALIDATE_FAILED.seed()
    seeded.store.seed_diagnostic(sample_diagnostic(DIAG_ID))
    moved = _transition(
        seeded,
        _run_transition(seeded.run, _R.FAILED, primary_terminal_diagnostic_id=DIAG_ID),
    )
    after = seeded.snapshot()
    request = _VALIDATE_FAILED.request(seeded, run_revision=moved.revision)
    result, calls = _apply_recorded(seeded, request)
    superseded = _ok(result)
    assert superseded.run == moved
    assert superseded.run.primary_terminal_diagnostic_id == DIAG_ID
    assert superseded.superseded_by is _R.FAILED
    assert superseded.reconciliation.verdict is _V.FAILED
    assert (
        superseded.reconciliation.primary_diagnostic.error_code
        == SCHEMA_REQUEST_INVALID
    )
    assert calls == (*_LOAD_PAIR, *_LOAD_EXPERIMENT)
    assert seeded.snapshot() == after


def test_finalization_eligibility_over_a_run_failed_by_the_core_is_superseded() -> None:
    seeded = _ELIGIBLE.seed()
    seeded.store.seed_diagnostic(sample_diagnostic(DIAG_ID))
    moved = _transition(
        seeded,
        _run_transition(seeded.run, _R.FAILED, primary_terminal_diagnostic_id=DIAG_ID),
    )
    after = seeded.snapshot()
    result, calls = _apply_recorded(
        seeded, _ELIGIBLE.request(seeded, run_revision=moved.revision)
    )
    superseded = _ok(result)
    assert superseded.run == moved
    assert superseded.superseded_by is _R.FAILED
    assert superseded.reconciliation.verdict is _V.RESULT_FINALIZATION_ELIGIBLE
    assert not _missing(superseded.reconciliation.sanitized_manifest)
    assert calls == (*_LOAD_PAIR, *_LOAD_EXPERIMENT)
    assert seeded.snapshot() == after


@pytest.mark.parametrize(
    ("scenario", "state"),
    [
        (_ELIGIBLE, _R.NOT_APPLICABLE),
        (_ELIGIBLE, _R.UNAVAILABLE),
        (_RUN_FAILED, _R.NOT_APPLICABLE),
    ],
    ids=[
        "eligible-over-not-applicable",
        "eligible-over-unavailable",
        "failed-over-not-applicable",
    ],
)
def test_a_run_moved_to_another_admitted_terminal_is_superseded_without_a_write(
    scenario: _Scenario, state: EngineRunState
) -> None:
    seeded = scenario.seed()
    seeded.store.seed_diagnostic(sample_diagnostic(DIAG_ID))
    moved = _transition(
        seeded,
        _run_transition(
            seeded.run,
            state,
            primary_terminal_diagnostic_id=DIAG_ID,
            availability_observation_id=AVAIL_A if state is _R.UNAVAILABLE else None,
        ),
    )
    after = seeded.snapshot()
    superseded = _ok(
        _apply(
            scenario.request(seeded, run_revision=moved.revision),
            InMemoryUnitOfWork(seeded.store),
        )
    )
    assert superseded.run == moved
    assert superseded.superseded_by is state
    assert superseded.reconciliation.verdict is scenario.verdict
    assert seeded.snapshot() == after


def test_a_ready_run_re_issued_with_inputs_that_now_fail_is_divergent() -> None:
    seeded, request, outcome, _ = _first_application(_READY)
    after = seeded.snapshot()
    divergent = _validate_request(
        seeded,
        _O.INVALID,
        invocation_revision=outcome.invocation.revision,
        run_revision=outcome.run.revision,
    )
    assert divergent != request
    result, calls = _apply_recorded(seeded, divergent)
    diagnostic = _assert_service_failure(result, INVARIANT_VIOLATION)
    assert diagnostic.details["stored_state"] == "READY"
    assert diagnostic.details["run_target_state"] == "FAILED"
    assert calls == (*_LOAD_PAIR, *_LOAD_EXPERIMENT)
    assert seeded.snapshot() == after


def test_a_run_at_target_missing_the_recomputed_identity_is_divergent() -> None:
    # Recompute the primary a first application would mint, then seed a run that
    # carries it as primary beside an invocation that never recorded it.
    _, _, outcome, _ = _first_application(_VALIDATE_FAILED)
    primary = outcome.reconciliation.primary_diagnostic
    divergent = _seed(
        run=sample_run(
            _R.FAILED,
            primary_terminal_diagnostic_id=primary.diagnostic_id,
            observed=False,
        ),
        invocation=sample_invocation(_C.EXITED, kind=_K.VALIDATE, native_exit_value=10),
    )
    before = divergent.snapshot()
    result, calls = _apply_recorded(divergent, _VALIDATE_FAILED.request(divergent))
    diagnostic = _assert_service_failure(result, INVARIANT_VIOLATION)
    assert diagnostic.details["stored_state"] == "FAILED"
    assert calls == (*_LOAD_PAIR, *_LOAD_EXPERIMENT)
    assert divergent.snapshot() == before


def test_the_returned_diagnostics_are_seeded_once_and_recomputed_identically() -> None:
    seeded, request, outcome, _ = _first_application(_RUN_FAILED)
    for diagnostic in outcome.reconciliation.diagnostics:
        seeded.store.seed_diagnostic(diagnostic)
    replay = _ok(
        _apply(
            _replay_request(seeded, request, outcome), InMemoryUnitOfWork(seeded.store)
        )
    )
    assert replay.reconciliation.diagnostics == outcome.reconciliation.diagnostics
    for diagnostic in replay.reconciliation.diagnostics:
        with pytest.raises(ValueError, match="already seeded"):
            seeded.store.seed_diagnostic(diagnostic)
    transaction = InMemoryUnitOfWork(seeded.store).begin()
    stored = _ok(
        transaction.diagnostics.get(outcome.run.primary_terminal_diagnostic_id)
    )
    assert stored == outcome.reconciliation.primary_diagnostic
    transaction.rollback()


# --------------------------------------------------------------------------
# J. Boundaries: purity, dependency direction and no success path (plan 13, 2.6)
# --------------------------------------------------------------------------


def _module_source(repository_root: Path, relative: str) -> str:
    return (repository_root / "src" / "crypto_lab" / relative).read_text(
        encoding="utf-8"
    )


def test_the_operation_module_imports_only_pure_roots_and_defining_modules(
    repository_root: Path,
) -> None:
    tree = ast.parse(_module_source(repository_root, "experiments/semantic_outcome.py"))
    roots: set[str] = set()
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.partition(".")[0])
                modules.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            roots.add(node.module.partition(".")[0])
            modules.add(node.module)
    assert roots <= _PURE_ROOTS
    assert not roots & _INFRASTRUCTURE_ROOTS
    adapters_modules = {
        name for name in modules if name.startswith("crypto_lab.adapters")
    }
    assert adapters_modules == {
        "crypto_lab.adapters.manifests",
        "crypto_lab.adapters.reconciliation",
    }
    assert "crypto_lab.adapters" not in modules
    assert not any(name.startswith("crypto_lab.persistence") for name in modules)
    assert not any(
        name.startswith("crypto_lab.process_supervision") for name in modules
    )
    assert not any(name.startswith("crypto_lab.artifacts") for name in modules)


def test_the_operation_module_defines_no_later_stage_name_or_forbidden_attribute(
    repository_root: Path,
) -> None:
    tree = ast.parse(_module_source(repository_root, "experiments/semantic_outcome.py"))
    defined = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
    }
    assert not defined & _LATER_STAGE_NAMES
    assert {"SemanticOutcome", "apply_command_semantic_outcome"} <= defined
    names = {
        node.id if isinstance(node, ast.Name) else node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Name | ast.Attribute)
    }
    assert not names & _STAGE4_BARE_NAMES
    assert not names & _FORBIDDEN_ATTRIBUTES
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "open"
        for node in ast.walk(tree)
    )


def test_the_request_module_reaches_adapters_only_through_defining_modules(
    repository_root: Path,
) -> None:
    tree = ast.parse(_module_source(repository_root, "experiments/requests.py"))
    imported = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    assert {
        "crypto_lab.adapters.envelopes",
        "crypto_lab.adapters.events",
        "crypto_lab.adapters.manifests",
        "crypto_lab.adapters.reconciliation",
        "crypto_lab.adapters.limits",
    } <= imported
    assert "crypto_lab.adapters" not in imported


def test_no_adapters_module_imports_the_experiments_package(
    repository_root: Path,
) -> None:
    adapters = repository_root / "src" / "crypto_lab" / "adapters"
    for path in sorted(adapters.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module is not None:
                assert not node.module.startswith("crypto_lab.experiments"), path
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith("crypto_lab.experiments"), path


def test_no_verdict_can_move_a_run_to_a_success_state() -> None:
    for scenario in _SCENARIOS:
        _, _, outcome, _ = _first_application(scenario)
        assert outcome.run.state not in SUCCESS_ENGINE_RUN_STATES, scenario.name
        target = outcome.reconciliation.run_target_state
        assert _missing(target) or target not in SUCCESS_ENGINE_RUN_STATES
    reachable = {
        scenario.target for scenario in _SCENARIOS if scenario.target is not None
    }
    assert reachable == {_R.READY, _R.NOT_APPLICABLE, _R.UNAVAILABLE, _R.FAILED}
    assert not reachable & SUCCESS_ENGINE_RUN_STATES
    assert reachable - TERMINAL_ENGINE_RUN_STATES == {_R.READY}


def test_the_stage_five_run_and_invocation_services_are_not_edited_for_this_operation(
    repository_root: Path,
) -> None:
    """Plan 1.5 item 3: the missing authoritative read is owned here; ``transition_run``
    keeps its one-record read set and the Stage 5 predicates are untouched."""
    run_service = _module_source(repository_root, "experiments/run_service.py")
    assert "semantic" not in run_service
    assert "list_for_run" not in run_service
    engine_run = _module_source(repository_root, "domain/engine_run.py")
    assert "semantic_outcome" not in engine_run
    assert "SemanticOutcome" not in engine_run
    command_invocation = _module_source(repository_root, "domain/command_invocation.py")
    assert "SemanticOutcome" not in command_invocation
