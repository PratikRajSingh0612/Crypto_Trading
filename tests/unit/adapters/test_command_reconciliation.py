"""Stage 6 Task 6: `CommandResult` and the three command reconcilers (Stage 6 plan
sections 3.7, 3.11, 5.4, 9.1-9.4; specification 14.1, 14.6, 14.7, 15.7, 19.4, 21.2.1).

`CommandResult` is the transient supervisor projection whose parsed-output branch is
selected by the invocation's command kind; `reconcile_describe`, `reconcile_validate`
and `reconcile_run` turn an `EXITED` invocation, its records and its parse outcomes
into one `SemanticReconciliation` -- a verdict, a proposed run target and exactly one
diagnostic at the first failing check -- and never a success run state, a launched
process, a persisted row, a finalized artifact or a `RunManifest`.
"""

from __future__ import annotations

import ast
import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final, Never

import pytest
from pydantic import ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab import adapters as adapters_package
from crypto_lab.adapters import commands, exit_codes, reconciliation
from crypto_lab.adapters.catalog import AdapterCatalogEntry
from crypto_lab.adapters.commands import CommandResult
from crypto_lab.adapters.diagnostics import (
    ADAPTER_UNAVAILABLE,
    ARTIFACT_PATH_BOUNDARY_VIOLATION,
    ARTIFACT_RESULT_MANIFEST_INVALID,
    ARTIFACT_VALIDATION_FAILED,
    COMPAT_LATE_NOT_APPLICABLE,
    COMPAT_NOT_APPLICABLE,
    ENGINE_RUNTIME_FAILURE,
    PROCESS_UNRECOGNIZED_PROCESS_EXIT,
    PROTOCOL_ADAPTER_REPORTED_VIOLATION,
    PROTOCOL_DESCRIBE_OUTPUT_INVALID,
    PROTOCOL_EVENT_TOO_LARGE,
    PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
    PROTOCOL_MALFORMED_JSONL,
    PROTOCOL_STDOUT_CONTAMINATION,
    PROTOCOL_UNSUPPORTED_VERSION,
    PROTOCOL_VALIDATION_RESULT_INVALID,
    SCHEMA_REQUEST_INVALID,
    SECURITY_SENSITIVE_MATERIAL_LEAKAGE,
    STAGE6_DIAGNOSTIC_CODES,
    stage6_diagnostic,
)
from crypto_lab.adapters.envelopes import NegotiatedVersions
from crypto_lab.adapters.events import (
    ArtifactDeclarationRecord,
    ArtifactProducedPayload,
    FinalResultPayload,
    HeartbeatPayload,
    ProtocolEventSummary,
    ProtocolWarning,
    RunEvent,
    run_event_content_hash,
)
from crypto_lab.adapters.limits import (
    MAX_CANDIDATE_ARTIFACTS,
    MAX_DESCRIPTOR_OUTPUT_BYTES,
    MAX_RESULT_MANIFEST_BYTES,
    MAX_VALIDATION_RESULT_BYTES,
    RESULT_MANIFEST_RELATIVE_PATH,
)
from crypto_lab.adapters.manifests import (
    AdapterResultManifest,
    AdapterValidationResult,
    ManifestParse,
    ValidationResultParse,
    parse_result_manifest,
    parse_validation_result,
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
    reconcile_validate,
)
from crypto_lab.adapters.sanitization import REDACTION_PLACEHOLDER, StderrCapture
from crypto_lab.adapters.vocabulary import (
    NEGOTIABLE_SCHEMA_NAMES,
    NegotiationOutcome,
    ProtocolEventType,
    ProtocolIntegrityStatus,
    ReconciliationVerdict,
    SemanticStatus,
    ValidationOutcome,
)
from crypto_lab.domain.base import SCHEMA_VERSION
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.compatibility import CompatibilityOutcome
from crypto_lab.domain.descriptors import (
    AdapterDescriptor,
    EngineDescriptor,
    OperatingSystem,
    SupportedSchemaVersion,
)
from crypto_lab.domain.diagnostics import Diagnostic
from crypto_lab.domain.engine_run import SUCCESS_ENGINE_RUN_STATES
from crypto_lab.domain.experiment import EngineIdentity
from crypto_lab.domain.hashing import (
    _uuid4_shaped,
    attempt_token_hash,
    request_id_for,
    sha256_bytes,
)
from crypto_lab.domain.lifecycle import (
    RECOGNIZED_NATIVE_EXIT_VALUES,
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
    ProcessExitCategory,
)
from crypto_lab.experiments.diagnostics import UNRECOGNIZED_PROCESS_EXIT
from doubles.experiments import (
    ATTEMPT_TOKEN,
    DATASET_HASH,
    EXPERIMENT_ID,
    INSTANT,
    INVOCATION_ID,
    OTHER_EXPERIMENT_ID,
    OTHER_INVOCATION_ID,
    OTHER_REQUEST_HASH,
    OTHER_RUN_ID,
    REQUEST_HASH,
    RUN_ID,
    SLOT_A,
    SLOT_B,
    STRATEGY_HASH,
    sample_experiment,
    sample_invocation,
    sample_run,
    sample_slot_compatibility,
)

_K = CommandKind
_S = SemanticStatus
_O = ValidationOutcome
_V = ReconciliationVerdict
_R = EngineRunState
_C = CommandInvocationState
_I = ProtocolIntegrityStatus

_NOW: Final = datetime(2026, 9, 11, 12, 0, tzinfo=UTC)
_LATER: Final = _NOW + timedelta(hours=3)
_STARTED: Final = "2026-09-11T10:00:00Z"
_COMPLETED: Final = "2026-09-11T10:05:00Z"
_HASH: Final = "a" * 64
_OTHER_HASH: Final = "b" * 64
_WRONG_TOKEN: Final = "B" * 32
_TOKEN_HASH: Final = attempt_token_hash(ATTEMPT_TOKEN)
_REQUEST_ID: Final = request_id_for(RUN_ID)
_ADAPTER_NAME: Final = "fake.conformant"
_ADAPTER_VERSION: Final = "1.0.0"
_EXECUTABLE_PATH: Final = "C:/adapters/fake_adapter.py"
_SUCCESS_VERDICTS: Final = frozenset(
    {_V.DESCRIBED, _V.VALIDATED_READY, _V.RESULT_FINALIZATION_ELIGIBLE}
)
_RECOGNIZED: Final = (0, 10, 20, 30, 40, 50, 60, 70)
_UNRECOGNIZED_EXIT: Final = 3
_EXITS: Final = (*_RECOGNIZED, _UNRECOGNIZED_EXIT)
_STAGE4_BARE_NAMES: Final = frozenset(
    {"buffer", "context", "note", "problem", "compose", "Loader", "get_snippet"}
)
_PURE_ROOTS: Final = frozenset(
    {
        "__future__",
        "collections",
        "dataclasses",
        "datetime",
        "typing",
        "pydantic",
        "crypto_lab",
    }
)
_TASK6_EXPORTS: Final = frozenset(
    {
        "CandidateObservation",
        "CommandResult",
        "ReconciliationRuleViolation",
        "SemanticExitReading",
        "SemanticReconciliation",
        "reconcile_describe",
        "reconcile_run",
        "reconcile_validate",
        "semantic_exit_reading",
    }
)
_RECONCILIATION_FIELDS: Final = (
    "command_kind",
    "verdict",
    "run_target_state",
    "semantic_status",
    "primary_diagnostic",
    "diagnostics",
    "sanitized_manifest",
    "sanitized_validation_result",
    "negotiation",
    "descriptor",
)
_RECONCILIATION_OPTIONAL: Final = (
    "run_target_state",
    "semantic_status",
    "primary_diagnostic",
    "sanitized_manifest",
    "sanitized_validation_result",
    "negotiation",
    "descriptor",
)
_OBSERVATION_FIELDS: Final = (
    "relative_path",
    "observed_size_bytes",
    "observed_sha256",
    "contains_attempt_token",
)
_COMMAND_RESULT_FIELDS: Final = (
    "invocation",
    "parsed_output",
    "parsed_output_source_hash",
    "protocol_integrity",
    "accepted_events",
    "diagnostics",
    "stderr",
    "cancelled",
    "timed_out",
)
_COMMAND_RESULT_OPTIONAL: Final = (
    "parsed_output",
    "parsed_output_source_hash",
    "stderr",
)
#: Plan 9.3: the run target of each verdict.
_TARGET_OF_VERDICT: Final[dict[ReconciliationVerdict, EngineRunState | None]] = {
    _V.DESCRIBED: None,
    _V.DESCRIBE_UNAVAILABLE: None,
    _V.VALIDATED_READY: _R.READY,
    _V.NOT_APPLICABLE: _R.NOT_APPLICABLE,
    _V.UNAVAILABLE: _R.UNAVAILABLE,
    _V.FAILED: _R.FAILED,
    _V.RESULT_FINALIZATION_ELIGIBLE: None,
}


def _missing(value: object) -> bool:
    return value is MISSING


def _forbidden(*_args: object, **_kwargs: object) -> Never:
    raise AssertionError("Task 6 performed runtime work")


def _derived(prefix: str, seed: str) -> str:
    return f"{prefix}_{_uuid4_shaped(sha256_bytes(seed.encode('utf-8')))}"


def _event_id(seed: object) -> str:
    return _derived("evt", str(seed))


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


def _code(outcome: SemanticReconciliation) -> str | None:
    primary = outcome.primary_diagnostic
    return None if _missing(primary) else primary.error_code


def _mismatched(outcome: SemanticReconciliation) -> list[str]:
    """The ``mismatched_fields`` detail of the primary, typed as the list it is."""
    fields = outcome.primary_diagnostic.details["mismatched_fields"]
    assert isinstance(fields, list)
    assert all(isinstance(name, str) for name in fields)
    return [str(name) for name in fields]


def _assert_token_free(*values: object) -> None:
    for value in values:
        text = canonical_json_bytes(value).decode("utf-8")
        assert ATTEMPT_TOKEN not in text
        assert _WRONG_TOKEN not in text
        assert ATTEMPT_TOKEN not in repr(value)


# --- Records ------------------------------------------------------------------------

_EXPERIMENT: Final = sample_experiment(ExperimentState.RUNNING)
_SLOT: Final = _EXPERIMENT.slot_compatibility[0]
_APPROXIMATED_COMPATIBILITY: Final = sample_slot_compatibility(
    outcomes={SLOT_A: CompatibilityOutcome.SUPPORTED_WITH_APPROXIMATION}
)
_APPROXIMATED_EXPERIMENT: Final = sample_experiment(
    ExperimentState.RUNNING, slot_compatibility=_APPROXIMATED_COMPATIBILITY
)
_APPROXIMATED_SLOT: Final = _APPROXIMATED_COMPATIBILITY[0]
_APPROXIMATION: Final = _APPROXIMATED_SLOT.approximation_ids[0]
_RUN: Final = sample_run(_R.RUNNING)
_VALIDATING_RUN: Final = sample_run(_R.VALIDATING)
_STALE_RUN: Final = sample_run(_R.VALIDATING, run_id=OTHER_RUN_ID, attempt_number=2)
_UNRECOGNIZED_PRIMARY: Final = stage6_diagnostic(
    PROCESS_UNRECOGNIZED_PROCESS_EXIT,
    "the child exited with an unrecognized native value",
    source_component="doubles.experiments",
    timestamp_utc=INSTANT,
    invocation_id=INVOCATION_ID,
)
_CATALOG_ENTRY: Final = AdapterCatalogEntry(
    adapter_name=_ADAPTER_NAME,
    adapter_version=_ADAPTER_VERSION,
    engine=EngineIdentity(engine_name="fake.engine", engine_version="1.0.0"),
    executable_path=_EXECUTABLE_PATH,
    executable_hash=_HASH,
    runtime_metadata={},
)


def _invocation(
    kind: CommandKind = _K.RUN,
    exit_value: int = 0,
    state: CommandInvocationState = _C.EXITED,
    **overrides: Any,
) -> Any:
    payload: dict[str, Any] = {"kind": kind, "native_exit_value": exit_value}
    if exit_value not in RECOGNIZED_NATIVE_EXIT_VALUES:
        payload["primary_diagnostic_id"] = _UNRECOGNIZED_PRIMARY.diagnostic_id
    if kind is _K.DESCRIBE:
        payload["adapter_name"] = _ADAPTER_NAME
        payload["adapter_version"] = _ADAPTER_VERSION
    payload.update(overrides)
    return sample_invocation(state, **payload)


def _protocol_failure(invocation_id: str = INVOCATION_ID) -> Diagnostic:
    return stage6_diagnostic(
        PROTOCOL_MALFORMED_JSONL,
        "stdout line is not a JSON object",
        source_component="adapters.events",
        timestamp_utc=INSTANT,
        invocation_id=invocation_id,
        details={"byte_length": 3, "source_hash": _HASH},
    )


# --- Describe material --------------------------------------------------------------


def _schema(name: str, version: str = SCHEMA_VERSION) -> SupportedSchemaVersion:
    return SupportedSchemaVersion(schema_name=name, schema_version=version)


def _descriptor(**updates: object) -> AdapterDescriptor:
    payload: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "adapter_name": _ADAPTER_NAME,
        "adapter_version": _ADAPTER_VERSION,
        "engine": EngineDescriptor(
            schema_version="1.0.0",
            engine_name="fake.engine",
            engine_version="1.0.0",
            engine_family="fake.family",
            planned_role="Offline fake adapter.",
            known_limitations=(),
        ),
        "supported_protocol_versions": ("1.0.0",),
        "supported_schema_versions": tuple(
            _schema(name) for name in NEGOTIABLE_SCHEMA_NAMES
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
        "executable_hash": _HASH,
    }
    payload.update(updates)
    return AdapterDescriptor.model_validate(payload)


def _envelope(
    descriptor: AdapterDescriptor | None = None,
) -> BootstrapDescriptorEnvelope:
    described = _descriptor() if descriptor is None else descriptor
    return BootstrapDescriptorEnvelope.model_validate(
        {
            "bootstrap_schema_version": SCHEMA_VERSION,
            "adapter_name": described.adapter_name,
            "adapter_version": described.adapter_version,
            "engine_name": described.engine.engine_name,
            "engine_version": described.engine.engine_version,
            "executable_hash": described.executable_hash,
            "supported_protocol_versions": described.supported_protocol_versions,
            "supported_schema_versions": described.supported_schema_versions,
            "capability_vocabulary_versions": (
                described.capability_vocabulary_version,
            ),
            "descriptor_payload_hash": sha256_bytes(canonical_json_bytes(described)),
            "descriptor": described,
        }
    )


def _describe_document(**updates: Any) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(canonical_json_bytes(_envelope()))
    document.update(updates)
    return document


def _describe_parse(output: bytes) -> DescriptorParse:
    return parse_bootstrap_descriptor(output, max_bytes=MAX_DESCRIPTOR_OUTPUT_BYTES)


def _describe(
    invocation: Any = None,
    output: Any = None,
    *,
    stdout_bytes_seen: int = 0,
    catalog_entry: AdapterCatalogEntry = _CATALOG_ENTRY,
    now_utc: datetime = _NOW,
) -> SemanticReconciliation:
    if invocation is None:
        invocation = _invocation(_K.DESCRIBE, 0)
    if output is None:
        output = _describe_parse(canonical_json_bytes(_envelope()))
    return reconcile_describe(
        invocation,
        output,
        stdout_bytes_seen,
        catalog_entry=catalog_entry,
        now_utc=now_utc,
    )


# --- Validate material --------------------------------------------------------------

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
    supplied = "result_hash" in updates
    result_hash = updates.pop("result_hash", None)
    document.update(updates)
    if document["outcome"] != "VALID" and not document["diagnostics"]:
        document["diagnostics"] = [_ADAPTER_DIAGNOSTIC]
    document["result_hash"] = result_hash if supplied else _stdlib_digest(document)
    return document


def _validation_parse(
    document: dict[str, Any] | None = None,
    *,
    raw: bytes | None = None,
    token: str = ATTEMPT_TOKEN,
) -> ValidationResultParse:
    output = _encode(_validation_document() if document is None else document)
    return parse_validation_result(
        raw if raw is not None else output,
        max_bytes=MAX_VALIDATION_RESULT_BYTES,
        token=token,
    )


def _validation_model(**updates: Any) -> AdapterValidationResult:
    return AdapterValidationResult.model_validate_json(
        json.dumps(_validation_document(**updates))
    )


def _validate(
    invocation: Any = None,
    run: Any = _VALIDATING_RUN,
    output: Any = None,
    *,
    summary: ProtocolEventSummary = _EMPTY_SUMMARY,
    protocol_failure: Any = MISSING,
    now_utc: datetime = _NOW,
) -> SemanticReconciliation:
    if invocation is None:
        invocation = _invocation(_K.VALIDATE, 0)
    if output is None:
        output = _validation_parse()
    return reconcile_validate(
        invocation, run, output, summary, protocol_failure, now_utc=now_utc
    )


def _validate_case(
    outcome: ValidationOutcome,
    exit_value: int,
    *,
    output_present: bool = True,
    **document_updates: Any,
) -> SemanticReconciliation:
    output: Any = MISSING
    if output_present:
        output = _validation_parse(
            _validation_document(outcome=outcome.value, **document_updates)
        )
    return _validate(_invocation(_K.VALIDATE, exit_value), output=output)


# --- Run material -------------------------------------------------------------------

_MANIFEST_ID: Final = _derived("amf", "manifest")
_NEGOTIATED: Final = NegotiatedVersions(
    protocol_version="1.0.0",
    schema_versions=tuple(_schema(name) for name in NEGOTIABLE_SCHEMA_NAMES),
    capability_vocabulary_version="capabilities/v1",
)
_OTHER_NEGOTIATED: Final = NegotiatedVersions(
    protocol_version="1.0.0",
    schema_versions=tuple(_schema(name) for name in NEGOTIABLE_SCHEMA_NAMES),
    capability_vocabulary_version="capabilities/v2",
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
_OTHER_WARNING: Final[dict[str, Any]] = {
    "warning_code": "ADAPTER.SLIPPAGE_ASSUMED",
    "message": "slippage assumed",
    "impact": "None.",
    "prevented_comparison_levels": [],
}
_DECLARATION: Final[dict[str, Any]] = {
    "relative_path": "results/native.bin",
    "artifact_kind": "engine.native",
    "media_type": "application/octet-stream",
    "declared_size_bytes": 12,
    "declared_sha256": _HASH,
}
_SECOND_DECLARATION: Final[dict[str, Any]] = {
    "relative_path": "results/normalized.json",
    "artifact_kind": "normalized.result",
    "media_type": "application/json",
    "declared_size_bytes": 34,
    "declared_sha256": _OTHER_HASH,
}
_SUCCESS_STATUSES: Final = (_S.SUCCEEDED, _S.SUCCEEDED_WITH_WARNINGS)


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
    provenance_updates = updates.pop("provenance", None)
    document.update(updates)
    if provenance_updates is not None:
        document["provenance"] = {**_PROVENANCE, **provenance_updates}
    status = _S(document["semantic_status"])
    if status not in _SUCCESS_STATUSES:
        document["candidate_artifacts"] = updates.get("candidate_artifacts", [])
        if not document["diagnostics"]:
            document["diagnostics"] = [_ADAPTER_DIAGNOSTIC]
        document["warnings"] = updates.get("warnings", [])
    elif status is _S.SUCCEEDED_WITH_WARNINGS and not document["warnings"]:
        document["warnings"] = [_WARNING]
    return document


def _manifest_parse(
    document: dict[str, Any] | None = None,
    *,
    raw: bytes | None = None,
    token: str = ATTEMPT_TOKEN,
) -> ManifestParse:
    output = _encode(_manifest_document() if document is None else document)
    return parse_result_manifest(
        raw if raw is not None else output,
        max_bytes=MAX_RESULT_MANIFEST_BYTES,
        token=token,
    )


def _manifest_model(**updates: Any) -> AdapterResultManifest:
    return AdapterResultManifest.model_validate_json(
        json.dumps(_manifest_document(**updates))
    )


def _warning(document: dict[str, Any] = _WARNING) -> ProtocolWarning:
    # JSON mode: the strict python mode refuses the fixture's list for a tuple.
    return ProtocolWarning.model_validate_json(json.dumps(document))


def _summary(
    *declarations: dict[str, Any],
    warnings: tuple[dict[str, Any], ...] = (),
    final: ManifestParse | None = None,
    final_path: str = RESULT_MANIFEST_RELATIVE_PATH,
    final_hash: str | None = None,
    final_status: SemanticStatus | None = None,
) -> ProtocolEventSummary:
    records = tuple(
        ArtifactDeclarationRecord(
            event_id=_event_id(f"artifact:{index}"),
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
            manifest_relative_path=final_path,
            source_adapter_result_manifest_hash=(
                final.source_hash if final_hash is None else final_hash
            ),
            semantic_status=(
                manifest.semantic_status if final_status is None else final_status
            ),
        )
        count += 1
    facts["accepted_count"] = count
    facts["last_sequence"] = count
    return ProtocolEventSummary.model_validate(facts)


def _observation(
    declaration: dict[str, Any],
    *,
    contains_attempt_token: bool = False,
    **overrides: Any,
) -> CandidateObservation:
    payload: dict[str, Any] = {
        "relative_path": declaration["relative_path"],
        "observed_size_bytes": declaration["declared_size_bytes"],
        "observed_sha256": declaration["declared_sha256"],
        "contains_attempt_token": contains_attempt_token,
    }
    payload.update(overrides)
    return CandidateObservation.model_validate(payload)


def _observations(
    *declarations: dict[str, Any], contains_attempt_token: bool = False
) -> tuple[CandidateObservation, ...]:
    return tuple(
        _observation(item, contains_attempt_token=contains_attempt_token)
        for item in declarations
    )


_ABSENT: Final = object()


def _run(
    invocation: Any = None,
    run: Any = _RUN,
    experiment: Any = _EXPERIMENT,
    slot: Any = _SLOT,
    output: Any = _ABSENT,
    summary: Any = _ABSENT,
    observations: Any = _ABSENT,
    *,
    negotiated: NegotiatedVersions = _NEGOTIATED,
    protocol_failure: Any = MISSING,
    now_utc: datetime = _NOW,
) -> SemanticReconciliation:
    if invocation is None:
        invocation = _invocation(_K.RUN, 0)
    if output is _ABSENT:
        output = _manifest_parse()
    parsed = isinstance(output, ManifestParse) and not _missing(output.manifest)
    if summary is _ABSENT:
        summary = _summary(_DECLARATION, final=output) if parsed else _EMPTY_SUMMARY
    if observations is _ABSENT:
        observations = _observations(_DECLARATION) if parsed else ()
    return reconcile_run(
        invocation,
        run,
        experiment,
        slot,
        output,
        summary,
        observations,
        negotiated,
        protocol_failure,
        now_utc=now_utc,
    )


def _run_case(
    status: SemanticStatus,
    exit_value: int,
    *,
    output_present: bool = True,
    declarations: tuple[dict[str, Any], ...] | None = None,
    event_declarations: tuple[dict[str, Any], ...] | None = None,
    warnings: tuple[dict[str, Any], ...] | None = None,
    event_warnings: tuple[dict[str, Any], ...] | None = None,
    observations: Any = _ABSENT,
    experiment: Any = _EXPERIMENT,
    slot: Any = _SLOT,
    run: Any = _RUN,
    negotiated: NegotiatedVersions = _NEGOTIATED,
    protocol_failure: Any = MISSING,
    now_utc: datetime = _NOW,
    final: bool = True,
    **document_updates: Any,
) -> SemanticReconciliation:
    """A consistent manifest, summary and observation set for ``status`` under
    ``exit_value``, so the exit column is the first check that can fail."""
    success = status in _SUCCESS_STATUSES
    if declarations is None:
        declarations = (_DECLARATION,) if success else ()
    if warnings is None:
        warnings = (_WARNING,) if status is _S.SUCCEEDED_WITH_WARNINGS else ()
    if event_declarations is None:
        event_declarations = declarations
    if event_warnings is None:
        event_warnings = warnings
    output: Any = MISSING
    summary = _EMPTY_SUMMARY
    if output_present:
        output = _manifest_parse(
            _manifest_document(
                semantic_status=status.value,
                candidate_artifacts=list(declarations),
                warnings=list(warnings),
                **document_updates,
            )
        )
        summary = _summary(
            *event_declarations,
            warnings=event_warnings,
            final=output if final and not _missing(output.manifest) else None,
        )
    elif event_declarations:
        summary = _summary(*event_declarations, warnings=event_warnings)
    if observations is _ABSENT:
        observations = _observations(*event_declarations)
    return _run(
        _invocation(_K.RUN, exit_value),
        run,
        experiment,
        slot,
        output,
        summary,
        observations,
        negotiated=negotiated,
        protocol_failure=protocol_failure,
        now_utc=now_utc,
    )


# --- CommandResult material ---------------------------------------------------------


def _run_event(sequence: int = 1, **changes: Any) -> RunEvent:
    fields: dict[str, Any] = {
        "schema_version": "1.0.0",
        "protocol_version": "1.0.0",
        "event_id": _event_id(f"{INVOCATION_ID}:{sequence}"),
        "invocation_id": INVOCATION_ID,
        "run_id": RUN_ID,
        "attempt_token_hash": _TOKEN_HASH,
        "sequence": sequence,
        "event_type": ProtocolEventType.HEARTBEAT,
        "timestamp_utc": _NOW,
        "payload": HeartbeatPayload(activity_counter=sequence, phase="warmup"),
        "received_at_utc": _NOW,
        "wire_event_hash": _HASH,
    }
    fields.update(changes)
    draft = RunEvent.model_construct(**fields, content_hash=_HASH)
    return RunEvent.model_validate(
        {**fields, "content_hash": run_event_content_hash(draft)}
    )


def _parsed_output_for(kind: CommandKind) -> Any:
    if kind is _K.DESCRIBE:
        return _envelope()
    if kind is _K.VALIDATE:
        return _validation_model()
    return _manifest_model()


def _command_result_fields(
    kind: CommandKind = _K.RUN,
    state: CommandInvocationState = _C.EXITED,
    **overrides: Any,
) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "invocation": _invocation(kind, 0, state),
        "parsed_output": _parsed_output_for(kind),
        "parsed_output_source_hash": _HASH,
        "protocol_integrity": (
            _I.VIOLATED if state is _C.PROTOCOL_FAILED else _I.INTACT
        ),
        "accepted_events": () if kind is _K.DESCRIBE else (_run_event(1),),
        "diagnostics": (),
        "cancelled": state is _C.CANCELLED,
        "timed_out": state is _C.TIMED_OUT,
    }
    for name, value in overrides.items():
        if value is _ABSENT:
            fields.pop(name, None)
        else:
            fields[name] = value
    return fields


def _command_result(
    kind: CommandKind = _K.RUN,
    state: CommandInvocationState = _C.EXITED,
    **overrides: Any,
) -> CommandResult:
    return CommandResult.model_validate(
        _command_result_fields(kind, state, **overrides)
    )


# --- Inventory, field order and purity ----------------------------------------------


def test_the_package_exports_the_task_six_surface_sorted() -> None:
    exported = adapters_package.__all__
    assert _TASK6_EXPORTS <= set(exported), sorted(_TASK6_EXPORTS - set(exported))
    assert len(set(exported)) == len(exported)
    constants = [name for name in exported if name.isupper()]
    classes = [name for name in exported if not name.isupper() and name[0].isupper()]
    functions = [name for name in exported if name[0].islower()]
    assert list(exported) == [*constants, *classes, *functions]
    for group in (constants, classes, functions):
        assert group == sorted(group)
    for name in ("RunManifest", "ProcessSupervisor", "CandidateArtifact"):
        assert name not in exported


def test_command_result_is_defined_in_the_commands_module() -> None:
    """Plan 2.6: `CommandResult` is released by Task 6 and lives in commands.py."""
    assert CommandResult.__module__ == commands.__name__
    assert commands.CommandResult is CommandResult


@pytest.mark.parametrize(
    ("model", "expected", "optional"),
    [
        (SemanticReconciliation, _RECONCILIATION_FIELDS, _RECONCILIATION_OPTIONAL),
        (CandidateObservation, _OBSERVATION_FIELDS, ()),
        (CommandResult, _COMMAND_RESULT_FIELDS, _COMMAND_RESULT_OPTIONAL),
    ],
    ids=lambda value: value.__name__ if isinstance(value, type) else "fields",
)
def test_each_model_declares_exactly_the_plan_fields_in_order(
    model: type[Any], expected: tuple[str, ...], optional: tuple[str, ...]
) -> None:
    assert tuple(model.model_fields) == expected
    for name, field in model.model_fields.items():
        assert field.is_required() is (name not in optional), name
    # Trust classes P and K (plan 3.1): unpublished, no envelope version.
    assert "schema_version" not in model.model_fields
    assert "protocol_version" not in model.model_fields


def test_no_task_six_model_carries_the_raw_token_by_type() -> None:
    for model in (SemanticReconciliation, CandidateObservation, CommandResult):
        assert "attempt_token" not in model.model_fields
        for name, field in model.model_fields.items():
            if name == "parsed_output":
                continue
            assert "AttemptToken" not in repr(field.annotation), (model.__name__, name)
    branch = repr(CommandResult.model_fields["parsed_output"].annotation)
    for member in (
        "BootstrapDescriptorEnvelope",
        "AdapterValidationResult",
        "AdapterResultManifest",
    ):
        assert member in branch


def _scan(source: str) -> tuple[set[str], set[str], set[str]]:
    tree = ast.parse(source)
    roots: set[str] = set()
    packages: set[str] = set()
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            roots.add(node.module.partition(".")[0])
            if node.module.startswith("crypto_lab."):
                packages.add(node.module.split(".")[1])
        elif isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        if isinstance(node, ast.Call):
            target = node.func
            called = (
                target.id
                if isinstance(target, ast.Name)
                else getattr(target, "attr", "")
            )
            assert called not in {"open", "now", "utcnow", "today"}, ast.dump(node)
    return roots, packages, names


@pytest.mark.parametrize("module", [reconciliation, exit_codes, commands])
def test_each_task_six_module_imports_only_pure_roots_and_uses_no_forbidden_name(
    module: Any,
) -> None:
    source = Path(module.__file__ or "").read_text(encoding="utf-8")
    roots, packages, names = _scan(source)
    assert roots <= _PURE_ROOTS, sorted(roots - _PURE_ROOTS)
    assert packages <= {"domain", "adapters"}, sorted(packages)
    assert names & _STAGE4_BARE_NAMES == set()
    for forbidden in ("subprocess", "socket", "random", "environ", "getenv"):
        assert forbidden not in source
    # Plan 2.6 / Stage 5 scan: no attribute read of causal_diagnostic_ids, no
    # get_many, no repository, unit of work or persistence in a pure reconciler.
    assert ".causal_diagnostic_ids" not in source
    assert "get_many" not in source
    for name in ("UnitOfWork", "Repository", "compare_and_swap", "RunManifest"):
        assert name not in source.replace("CommandInvocationRepository", "")
    defined = {
        node.name
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ClassDef | ast.FunctionDef)
    }
    assert defined & {"RunManifest", "ProcessSupervisor", "CandidateArtifact"} == set()


def test_the_bare_name_scan_finds_a_planted_name() -> None:
    planted = "Loader = compose(problem)\nresult = Loader.compose\n"
    assert _scan(planted)[2] & _STAGE4_BARE_NAMES == {"Loader", "compose", "problem"}
    with pytest.raises(AssertionError):
        _scan("value = now()\n")


def test_task_six_launches_reads_persists_and_connects_to_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("subprocess.Popen", _forbidden)
    monkeypatch.setattr("socket.create_connection", _forbidden)
    monkeypatch.setattr("os.getenv", _forbidden)
    monkeypatch.setattr("builtins.open", _forbidden)
    monkeypatch.setattr("time.monotonic", _forbidden)
    monkeypatch.setattr("random.random", _forbidden)
    assert _describe().verdict is _V.DESCRIBED
    assert _validate().verdict is _V.VALIDATED_READY
    assert _run().verdict is _V.RESULT_FINALIZATION_ELIGIBLE
    assert _command_result().invocation.state is _C.EXITED


# --- CandidateObservation -----------------------------------------------------------


def test_a_candidate_observation_is_strict_frozen_bounded_and_token_free() -> None:
    observation = _observation(_DECLARATION)
    assert observation.relative_path == "results/native.bin"
    assert observation.contains_attempt_token is False
    with pytest.raises(ValidationError, match="frozen"):
        observation.contains_attempt_token = True
    with pytest.raises(ValidationError, match="relative_path"):
        _observation(_DECLARATION, relative_path="../escape.bin")
    with pytest.raises(ValidationError, match="observed_size_bytes"):
        _observation(_DECLARATION, observed_size_bytes=-1)
    with pytest.raises(ValidationError, match="observed_size_bytes"):
        _observation(_DECLARATION, observed_size_bytes=2**53)
    with pytest.raises(ValidationError, match="observed_sha256"):
        _observation(_DECLARATION, observed_sha256="A" * 64)
    with pytest.raises(ValidationError, match="contains_attempt_token"):
        CandidateObservation.model_validate(
            {**observation.model_dump(), "contains_attempt_token": 1}
        )
    with pytest.raises(ValidationError, match="extra_forbidden"):
        _observation(_DECLARATION, attempt_token=ATTEMPT_TOKEN)
    _assert_token_free(observation)


# --- CommandResult ------------------------------------------------------------------


@pytest.mark.parametrize("kind", list(CommandKind))
def test_each_kind_accepts_its_own_output_branch_and_absence(kind: CommandKind) -> None:
    result = _command_result(kind)
    assert result.invocation.command_kind is kind
    assert type(result.parsed_output) is type(_parsed_output_for(kind))
    absent = _command_result(
        kind, parsed_output=_ABSENT, parsed_output_source_hash=_ABSENT
    )
    assert _missing(absent.parsed_output)
    assert _missing(absent.parsed_output_source_hash)
    assert _missing(absent.stderr)
    with_stderr = _command_result(
        kind,
        stderr=StderrCapture(
            retained_byte_count=0, truncated=False, source_hash=_HASH, sanitized_text=""
        ),
    )
    assert not _missing(with_stderr.stderr)


@pytest.mark.parametrize("kind", list(CommandKind))
@pytest.mark.parametrize("foreign", list(CommandKind))
def test_a_parsed_output_of_a_foreign_kind_is_rejected(
    kind: CommandKind, foreign: CommandKind
) -> None:
    if kind is foreign:
        return
    with pytest.raises(ValidationError, match="command_kind") as captured:
        _command_result(kind, parsed_output=_parsed_output_for(foreign))
    assert ATTEMPT_TOKEN not in str(captured.value)


def test_a_parsed_output_requires_its_source_hash() -> None:
    with pytest.raises(ValidationError, match="parsed_output_source_hash"):
        _command_result(parsed_output_source_hash=_ABSENT)
    # A malformed output has a source hash and no parsed model: representable.
    result = _command_result(parsed_output=_ABSENT)
    assert result.parsed_output_source_hash == _HASH


@pytest.mark.parametrize("state", [_C.PENDING, _C.STARTING, _C.RUNNING])
def test_a_non_terminal_invocation_is_rejected(state: CommandInvocationState) -> None:
    with pytest.raises(ValidationError, match="terminal"):
        _command_result(
            _K.RUN, state, parsed_output=_ABSENT, parsed_output_source_hash=_ABSENT
        )


@pytest.mark.parametrize(
    "state",
    [_C.EXITED, _C.CANCELLED, _C.TIMED_OUT, _C.PROTOCOL_FAILED, _C.FAILED_TO_START],
)
def test_every_terminal_state_is_representable_with_its_own_flags(
    state: CommandInvocationState,
) -> None:
    result = _command_result(
        _K.RUN, state, parsed_output=_ABSENT, parsed_output_source_hash=_ABSENT
    )
    assert result.cancelled is (state is _C.CANCELLED)
    assert result.timed_out is (state is _C.TIMED_OUT)
    if state is _C.PROTOCOL_FAILED:
        assert result.protocol_integrity is _I.VIOLATED


def test_cancellation_and_timeout_flags_cannot_masquerade_as_an_exited_result() -> None:
    with pytest.raises(ValidationError, match="cancelled"):
        _command_result(_K.RUN, _C.EXITED, cancelled=True)
    with pytest.raises(ValidationError, match="timed_out"):
        _command_result(_K.RUN, _C.EXITED, timed_out=True)
    with pytest.raises(ValidationError, match="cancelled"):
        _command_result(_K.RUN, _C.CANCELLED, cancelled=False)
    with pytest.raises(ValidationError, match="timed_out"):
        _command_result(_K.RUN, _C.TIMED_OUT, timed_out=False)
    with pytest.raises(ValidationError, match="cancelled"):
        _command_result(_K.RUN, _C.TIMED_OUT, cancelled=True)


def test_a_protocol_failed_invocation_requires_a_violated_integrity_status() -> None:
    with pytest.raises(ValidationError, match="protocol_integrity"):
        _command_result(_K.RUN, _C.PROTOCOL_FAILED, protocol_integrity=_I.INTACT)
    # The direct unit case of plan 9.2 check (1): EXITED beside VIOLATED is
    # representable; the reconciler, not the model, decides what it means.
    violated = _command_result(_K.RUN, _C.EXITED, protocol_integrity=_I.VIOLATED)
    assert violated.protocol_integrity is _I.VIOLATED
    assert not _missing(violated.parsed_output)


def test_accepted_events_are_empty_for_describe_and_contiguous_for_the_invocation() -> (
    None
):
    with pytest.raises(ValidationError, match="DESCRIBE"):
        _command_result(_K.DESCRIBE, accepted_events=(_run_event(1),))
    with pytest.raises(ValidationError, match="sequence"):
        _command_result(_K.RUN, accepted_events=(_run_event(2),))
    with pytest.raises(ValidationError, match="sequence"):
        _command_result(_K.RUN, accepted_events=(_run_event(1), _run_event(3)))
    with pytest.raises(ValidationError, match="invocation"):
        _command_result(
            _K.RUN, accepted_events=(_run_event(1, invocation_id=OTHER_INVOCATION_ID),)
        )
    with pytest.raises(ValidationError, match="run"):
        _command_result(_K.RUN, accepted_events=(_run_event(1, run_id=OTHER_RUN_ID),))
    ordered = _command_result(_K.RUN, accepted_events=(_run_event(1), _run_event(2)))
    assert [event.sequence for event in ordered.accepted_events] == [1, 2]


def test_diagnostics_are_unique_on_identity_and_bounded() -> None:
    diagnostic = _protocol_failure()
    result = _command_result(diagnostics=(diagnostic,))
    assert result.diagnostics == (diagnostic,)
    with pytest.raises(ValidationError, match="unique"):
        _command_result(diagnostics=(diagnostic, diagnostic))


def test_the_command_result_is_frozen_strict_and_closed() -> None:
    result = _command_result()
    with pytest.raises(ValidationError, match="frozen"):
        result.cancelled = True
    fields = _command_result_fields()
    with pytest.raises(ValidationError, match="extra_forbidden"):
        CommandResult.model_validate({**fields, "success": True})
    with pytest.raises(ValidationError, match="cancelled"):
        CommandResult.model_validate({**fields, "cancelled": "false"})
    with pytest.raises(ValidationError, match="protocol_integrity"):
        CommandResult.model_validate({**fields, "protocol_integrity": "OK"})
    with pytest.raises(ValidationError, match="invocation"):
        CommandResult.model_validate({**fields, "invocation": _RUN})


def test_the_command_result_hides_the_raw_token_and_creates_no_success() -> None:
    result = _command_result(_K.RUN)
    assert ATTEMPT_TOKEN not in repr(result)
    assert ATTEMPT_TOKEN not in str(result)
    # The manifest branch is trust class W and carries the token in its dump; the
    # describe and validate branches are token-free throughout (plan 3.7, 13).
    for kind in (_K.DESCRIBE, _K.VALIDATE):
        _assert_token_free(_command_result(kind))
    for name in ("verdict", "run_target_state", "succeeded", "run_manifest"):
        assert name not in CommandResult.model_fields
    assert not any(
        name in {"launch", "persist", "finalize", "transition"}
        for name in dir(CommandResult)
    )


# --- SemanticReconciliation ---------------------------------------------------------


def _rebuilt(base: SemanticReconciliation, **changes: Any) -> SemanticReconciliation:
    payload = base.model_dump(mode="python")
    for name, value in changes.items():
        if value is _ABSENT:
            payload.pop(name, None)
        else:
            payload[name] = value
    return SemanticReconciliation.model_validate(payload)


def test_a_reconciliation_never_carries_a_success_run_target() -> None:
    failed = _run_case(_S.SUCCEEDED, 40)
    assert failed.verdict is _V.FAILED
    for state in SUCCESS_ENGINE_RUN_STATES:
        with pytest.raises(ValidationError, match="run_target_state"):
            _rebuilt(failed, run_target_state=state)
    for verdict, target in _TARGET_OF_VERDICT.items():
        assert target not in SUCCESS_ENGINE_RUN_STATES, verdict


def test_the_run_target_is_exactly_the_plan_nine_three_target_of_the_verdict() -> None:
    failed = _run_case(_S.SUCCEEDED, 40)
    with pytest.raises(ValidationError, match="run_target_state"):
        _rebuilt(failed, run_target_state=_ABSENT)
    with pytest.raises(ValidationError, match="run_target_state"):
        _rebuilt(failed, run_target_state=_R.READY)
    eligible = _run_case(_S.SUCCEEDED, 0)
    assert _missing(eligible.run_target_state)
    with pytest.raises(ValidationError, match="run_target_state"):
        _rebuilt(eligible, run_target_state=_R.FAILED)
    described = _describe()
    with pytest.raises(ValidationError, match="run_target_state"):
        _rebuilt(described, run_target_state=_R.READY)


def test_the_diagnostics_are_exactly_the_primary_or_empty() -> None:
    failed = _run_case(_S.SUCCEEDED, 40)
    primary = failed.primary_diagnostic
    assert failed.diagnostics == (primary,)
    with pytest.raises(ValidationError, match="diagnostics"):
        _rebuilt(failed, diagnostics=())
    with pytest.raises(ValidationError, match="diagnostics"):
        _rebuilt(failed, diagnostics=(primary, primary))
    with pytest.raises(ValidationError, match="diagnostics"):
        _rebuilt(failed, diagnostics=(_protocol_failure(), primary))
    with pytest.raises(ValidationError, match="primary_diagnostic"):
        _rebuilt(failed, primary_diagnostic=_ABSENT)
    eligible = _run_case(_S.SUCCEEDED, 0)
    assert eligible.diagnostics == ()
    with pytest.raises(ValidationError, match="diagnostic"):
        _rebuilt(eligible, primary_diagnostic=primary, diagnostics=(primary,))


def test_verdicts_are_paired_with_their_command_kind() -> None:
    described = _describe()
    with pytest.raises(ValidationError, match="command_kind"):
        _rebuilt(described, command_kind=_K.RUN)
    ready = _validate()
    with pytest.raises(ValidationError, match="command_kind"):
        _rebuilt(ready, command_kind=_K.RUN, sanitized_validation_result=_ABSENT)
    eligible = _run_case(_S.SUCCEEDED, 0)
    with pytest.raises(ValidationError, match="command_kind"):
        _rebuilt(eligible, command_kind=_K.VALIDATE)
    failed = _run_case(_S.SUCCEEDED, 40)
    with pytest.raises(ValidationError, match="command_kind"):
        _rebuilt(failed, command_kind=_K.DESCRIBE)


def test_evidence_fields_belong_to_their_command_kind_only() -> None:
    described = _describe()
    ready = _validate()
    eligible = _run_case(_S.SUCCEEDED, 0)
    with pytest.raises(ValidationError, match="descriptor"):
        _rebuilt(eligible, descriptor=described.descriptor)
    with pytest.raises(ValidationError, match="negotiation"):
        _rebuilt(eligible, negotiation=described.negotiation)
    with pytest.raises(ValidationError, match="sanitized_validation_result"):
        _rebuilt(
            eligible, sanitized_validation_result=ready.sanitized_validation_result
        )
    with pytest.raises(ValidationError, match="sanitized_manifest"):
        _rebuilt(ready, sanitized_manifest=eligible.sanitized_manifest)
    with pytest.raises(ValidationError, match="semantic_status"):
        _rebuilt(ready, semantic_status=_S.SUCCEEDED)
    with pytest.raises(ValidationError, match="semantic_status"):
        _rebuilt(eligible, semantic_status=_ABSENT)
    # Preventive (began green): the carried status is the sanitized manifest's.
    with pytest.raises(ValidationError, match="semantic_status"):
        _rebuilt(eligible, semantic_status=_S.FAILED)
    with pytest.raises(ValidationError, match="sanitized_manifest"):
        _rebuilt(eligible, sanitized_manifest=_ABSENT, semantic_status=_ABSENT)


def test_a_described_verdict_requires_a_negotiated_descriptor_and_no_diagnostic() -> (
    None
):
    described = _describe()
    assert described.negotiation.outcome is NegotiationOutcome.NEGOTIATED
    with pytest.raises(ValidationError, match="descriptor"):
        _rebuilt(described, descriptor=_ABSENT)
    with pytest.raises(ValidationError, match="negotiation"):
        _rebuilt(described, negotiation=_ABSENT)
    unavailable = _describe(
        output=_describe_parse(
            canonical_json_bytes(
                _envelope(_descriptor(supported_protocol_versions=("2.0.0",)))
            )
        )
    )
    assert unavailable.negotiation.outcome is NegotiationOutcome.FAILED
    with pytest.raises(ValidationError, match="NEGOTIATED"):
        _rebuilt(
            described,
            negotiation=unavailable.negotiation,
            descriptor=unavailable.descriptor,
        )
    # Preventive (began green): the converse contradiction is refused too.
    with pytest.raises(ValidationError, match="NEGOTIATED"):
        _rebuilt(unavailable, negotiation=described.negotiation)
    primary = unavailable.primary_diagnostic
    with pytest.raises(ValidationError, match="diagnostic"):
        _rebuilt(described, primary_diagnostic=primary, diagnostics=(primary,))


def test_the_reconciliation_is_frozen_strict_and_closed() -> None:
    outcome = _run_case(_S.SUCCEEDED, 0)
    with pytest.raises(ValidationError, match="frozen"):
        outcome.verdict = _V.FAILED
    payload = outcome.model_dump(mode="python")
    with pytest.raises(ValidationError, match="extra_forbidden"):
        SemanticReconciliation.model_validate({**payload, "succeeded": True})
    with pytest.raises(ValidationError, match="verdict"):
        SemanticReconciliation.model_validate({**payload, "verdict": "SUCCEEDED"})
    assert SemanticReconciliation.model_validate(payload) == outcome


# --- reconcile_describe --------------------------------------------------------------


def test_describe_preconditions_raise_by_name() -> None:
    with pytest.raises(ReconciliationRuleViolation, match="DESCRIBE"):
        _describe(_invocation(_K.VALIDATE, 0))
    with pytest.raises(ReconciliationRuleViolation, match="EXITED"):
        _describe(_invocation(_K.DESCRIBE, 0, _C.RUNNING))
    with pytest.raises(ReconciliationRuleViolation, match="EXITED"):
        _describe(_invocation(_K.DESCRIBE, 0, _C.TIMED_OUT))
    with pytest.raises(ReconciliationRuleViolation, match="EXITED"):
        _describe(_invocation(_K.DESCRIBE, 0, _C.CANCELLED))
    with pytest.raises(TypeError, match="CommandInvocationRecord"):
        _describe(_RUN)
    with pytest.raises(TypeError, match="DescriptorParse"):
        _describe(output=_manifest_parse())
    with pytest.raises(TypeError, match="stdout_bytes_seen"):
        _describe(stdout_bytes_seen=True)
    with pytest.raises(ValueError, match="stdout_bytes_seen"):
        _describe(stdout_bytes_seen=-1)
    with pytest.raises(TypeError, match="AdapterCatalogEntry"):
        _describe(catalog_entry=_descriptor())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="now_utc"):
        _describe(now_utc="2026-09-11T12:00:00Z")  # type: ignore[arg-type]


def test_a_conformant_describe_is_described_with_descriptor_and_negotiation() -> None:
    outcome = _describe()
    assert outcome.command_kind is _K.DESCRIBE
    assert outcome.verdict is _V.DESCRIBED
    assert _missing(outcome.run_target_state)
    assert _missing(outcome.primary_diagnostic)
    assert outcome.diagnostics == ()
    assert outcome.descriptor == _descriptor()
    assert outcome.negotiation.outcome is NegotiationOutcome.NEGOTIATED
    for name in (
        "semantic_status",
        "sanitized_manifest",
        "sanitized_validation_result",
    ):
        assert _missing(getattr(outcome, name)), name
    _assert_token_free(outcome)


def test_any_stdout_byte_during_describe_is_contamination_before_everything() -> None:
    outcome = _describe(stdout_bytes_seen=1)
    assert outcome.verdict is _V.DESCRIBE_UNAVAILABLE
    assert _code(outcome) == PROTOCOL_STDOUT_CONTAMINATION
    assert outcome.primary_diagnostic.details == {"stdout_bytes_seen": 1}
    assert outcome.primary_diagnostic.invocation_id == INVOCATION_ID
    assert _missing(outcome.descriptor)
    assert _missing(outcome.negotiation)
    # Precedence: contamination beats a nonzero exit and an absent output alike.
    absent = _describe(_invocation(_K.DESCRIBE, 30), MISSING, stdout_bytes_seen=7)
    assert _code(absent) == PROTOCOL_STDOUT_CONTAMINATION


_DESCRIBE_EXIT_CODES: Final = {
    10: SCHEMA_REQUEST_INVALID,
    20: ENGINE_RUNTIME_FAILURE,
    30: ADAPTER_UNAVAILABLE,
    40: ENGINE_RUNTIME_FAILURE,
    50: ENGINE_RUNTIME_FAILURE,
    60: ENGINE_RUNTIME_FAILURE,
    70: PROTOCOL_ADAPTER_REPORTED_VIOLATION,
    _UNRECOGNIZED_EXIT: ENGINE_RUNTIME_FAILURE,
    -1: ENGINE_RUNTIME_FAILURE,
}


@pytest.mark.parametrize(("exit_value", "code"), sorted(_DESCRIBE_EXIT_CODES.items()))
def test_a_nonzero_describe_exit_reads_its_cell_with_or_without_output(
    exit_value: int, code: str
) -> None:
    absent = _describe(_invocation(_K.DESCRIBE, exit_value), MISSING)
    assert absent.verdict is _V.DESCRIBE_UNAVAILABLE
    assert _code(absent) == code
    details = absent.primary_diagnostic.details
    assert details["output_present"] is False
    assert details["native_exit_value"] == exit_value
    assert _missing(absent.run_target_state)
    assert _missing(absent.descriptor)
    present = _describe(_invocation(_K.DESCRIBE, exit_value))
    assert _code(present) == code
    assert "output_present" not in present.primary_diagnostic.details
    # A valid descriptor cannot succeed when the process outcome contradicts it,
    # and it is not carried: checks (5)-(6) were never reached.
    assert _missing(present.descriptor)
    assert _missing(present.negotiation)
    if exit_value not in RECOGNIZED_NATIVE_EXIT_VALUES:
        for outcome in (absent, present):
            assert outcome.primary_diagnostic.causal_diagnostic_ids == (
                _UNRECOGNIZED_PRIMARY.diagnostic_id,
            )
            assert _UNRECOGNIZED_PRIMARY.error_code == UNRECOGNIZED_PROCESS_EXIT
    else:
        assert absent.primary_diagnostic.causal_diagnostic_ids == ()


def test_a_describe_exiting_thirty_with_no_output_is_adapter_unavailable() -> None:
    outcome = _describe(_invocation(_K.DESCRIBE, 30), MISSING)
    assert (outcome.verdict, _code(outcome)) == (
        _V.DESCRIBE_UNAVAILABLE,
        ADAPTER_UNAVAILABLE,
    )
    assert outcome.primary_diagnostic.retriable is True


def test_exit_zero_with_no_output_or_no_header_is_describe_output_invalid() -> None:
    absent = _describe(output=MISSING)
    assert (absent.verdict, _code(absent)) == (
        _V.DESCRIBE_UNAVAILABLE,
        PROTOCOL_DESCRIBE_OUTPUT_INVALID,
    )
    assert "output_present" not in absent.primary_diagnostic.details
    for raw in (b"not json", b"[]", b"\xff\xfe", b"{" * 3):
        parsed = _describe_parse(raw)
        assert _missing(parsed.header)
        outcome = _describe(output=parsed)
        assert _code(outcome) == PROTOCOL_DESCRIBE_OUTPUT_INVALID
        assert outcome.primary_diagnostic.details["byte_length"] == len(raw)
        assert outcome.primary_diagnostic.details["source_hash"] == sha256_bytes(raw)


@pytest.mark.parametrize(
    ("changes", "field"),
    [
        ({"adapter_name": "fake.other"}, "adapter_name"),
        ({"adapter_version": "1.0.1"}, "adapter_version"),
        ({"executable_hash": _OTHER_HASH}, "executable_hash"),
        ({"adapter_name": None}, "adapter_name"),
        ({"executable_hash": 7}, "executable_hash"),
    ],
    ids=["name", "version", "hash", "absent-name", "typed-hash"],
)
def test_a_describe_header_identity_differing_from_the_catalog_reports_identity(
    changes: dict[str, Any], field: str
) -> None:
    """Spec 21.2.1: identity before schema. The document is also strict-invalid
    (the header no longer mirrors the descriptor), and identity still wins."""
    document = _describe_document()
    for name, value in changes.items():
        if value is None:
            document.pop(name)
        else:
            document[name] = value
    parsed = _describe_parse(_encode(document))
    assert not _missing(parsed.failure_code)
    outcome = _describe(output=parsed)
    assert (outcome.verdict, _code(outcome)) == (
        _V.DESCRIBE_UNAVAILABLE,
        PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
    )
    assert outcome.primary_diagnostic.details["mismatched_fields"] == [field]
    assert "fake.other" not in canonical_json_bytes(outcome).decode()
    assert _missing(outcome.descriptor)


def test_a_recorded_describe_failure_code_surfaces_after_identity() -> None:
    unsupported = _describe(
        output=_describe_parse(
            _encode(_describe_document(bootstrap_schema_version="2.0.0"))
        )
    )
    assert _code(unsupported) == PROTOCOL_UNSUPPORTED_VERSION
    invalid = _describe(
        output=_describe_parse(_encode(_describe_document(unexpected="field")))
    )
    assert _code(invalid) == PROTOCOL_DESCRIBE_OUTPUT_INVALID
    for outcome in (unsupported, invalid):
        assert outcome.verdict is _V.DESCRIBE_UNAVAILABLE
        assert _missing(outcome.descriptor)
        assert _missing(outcome.negotiation)


def test_a_failed_negotiation_is_unavailable_yet_carries_its_descriptor() -> None:
    descriptor = _descriptor(supported_protocol_versions=("2.0.0",))
    outcome = _describe(
        output=_describe_parse(canonical_json_bytes(_envelope(descriptor)))
    )
    assert (outcome.verdict, _code(outcome)) == (
        _V.DESCRIBE_UNAVAILABLE,
        ADAPTER_UNAVAILABLE,
    )
    assert outcome.descriptor == descriptor
    assert outcome.negotiation.outcome is NegotiationOutcome.FAILED
    assert outcome.negotiation.reason_codes == (ADAPTER_UNAVAILABLE,)
    assert outcome.primary_diagnostic.details["negotiation_outcome"] == "FAILED"


def test_describe_never_proposes_a_run_target_and_is_deterministic() -> None:
    cases = (
        _describe(),
        _describe(stdout_bytes_seen=1),
        _describe(_invocation(_K.DESCRIBE, 40), MISSING),
        _describe(output=MISSING),
    )
    for outcome in cases:
        assert _missing(outcome.run_target_state)
        assert _missing(outcome.semantic_status)
    first = _describe(_invocation(_K.DESCRIBE, 40), MISSING, now_utc=_NOW)
    second = _describe(_invocation(_K.DESCRIBE, 40), MISSING, now_utc=_LATER)
    assert (
        first.primary_diagnostic.diagnostic_id
        == second.primary_diagnostic.diagnostic_id
    )
    assert first.primary_diagnostic.timestamp_utc == _NOW
    assert second.primary_diagnostic.timestamp_utc == _LATER


# --- reconcile_validate --------------------------------------------------------------


def test_validate_preconditions_raise_by_name() -> None:
    with pytest.raises(ReconciliationRuleViolation, match="VALIDATE"):
        _validate(_invocation(_K.RUN, 0))
    with pytest.raises(ReconciliationRuleViolation, match="VALIDATE"):
        _validate(_invocation(_K.DESCRIBE, 0))
    with pytest.raises(ReconciliationRuleViolation, match="EXITED"):
        _validate(_invocation(_K.VALIDATE, 0, _C.RUNNING))
    with pytest.raises(ReconciliationRuleViolation, match="EXITED"):
        _validate(_invocation(_K.VALIDATE, 0, _C.PROTOCOL_FAILED))
    with pytest.raises(ReconciliationRuleViolation, match="run"):
        _validate(run=sample_run(_R.VALIDATING, run_id=OTHER_RUN_ID))
    with pytest.raises(ReconciliationRuleViolation, match="invocation"):
        _validate(protocol_failure=_protocol_failure(OTHER_INVOCATION_ID))
    with pytest.raises(ReconciliationRuleViolation, match="VALIDATE"):
        _validate(summary=_summary(_DECLARATION))
    with pytest.raises(TypeError, match="ValidationResultParse"):
        _validate(output=_manifest_parse())
    with pytest.raises(TypeError, match="ProtocolEventSummary"):
        _validate(summary=_DECLARATION)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="Diagnostic"):
        _validate(protocol_failure="PROTOCOL.MALFORMED_JSONL")
    with pytest.raises(TypeError, match="EngineRunRecord"):
        _validate(run=_EXPERIMENT)


@pytest.mark.parametrize(
    "state", [_R.VALIDATING, _R.READY, _R.NOT_APPLICABLE, _R.UNAVAILABLE, _R.FAILED]
)
def test_validate_admits_the_pre_state_and_every_state_it_can_produce(
    state: EngineRunState,
) -> None:
    outcome = _validate(run=sample_run(state))
    assert outcome.verdict is _V.VALIDATED_READY


@pytest.mark.parametrize(
    "state",
    [
        _R.PENDING,
        _R.STARTING,
        _R.RUNNING,
        _R.SUCCEEDED,
        _R.SUCCEEDED_WITH_WARNINGS,
        _R.CANCELLED,
        _R.TIMED_OUT,
    ],
)
def test_validate_rejects_every_other_run_state(state: EngineRunState) -> None:
    with pytest.raises(ReconciliationRuleViolation, match=state.value):
        _validate(run=sample_run(state))


def test_a_valid_result_on_exit_zero_is_validated_ready_without_a_diagnostic() -> None:
    outcome = _validate()
    assert outcome.command_kind is _K.VALIDATE
    assert outcome.verdict is _V.VALIDATED_READY
    assert outcome.run_target_state is _R.READY
    assert _missing(outcome.primary_diagnostic)
    assert outcome.diagnostics == ()
    assert outcome.sanitized_validation_result == _validation_model()
    for name in ("semantic_status", "sanitized_manifest", "negotiation", "descriptor"):
        assert _missing(getattr(outcome, name)), name
    _assert_token_free(outcome)


def test_a_protocol_failure_overrides_a_valid_result_and_is_the_primary() -> None:
    failure = _protocol_failure()
    outcome = _validate(protocol_failure=failure)
    assert outcome.verdict is _V.FAILED
    assert outcome.run_target_state is _R.FAILED
    assert outcome.primary_diagnostic == failure
    assert outcome.diagnostics == (failure,)
    # The strict-valid result of this invocation is still recorded as evidence.
    assert not _missing(outcome.sanitized_validation_result)
    # It beats the exit reading on every exit.
    for exit_value in _EXITS:
        assert (
            _validate(
                _invocation(_K.VALIDATE, exit_value), protocol_failure=failure
            ).primary_diagnostic
            == failure
        )


def test_validation_output_without_a_header_is_validation_result_invalid() -> None:
    for raw in (b"not json", b"[1]", b"\xff", b"{" * 3):
        parsed = _validation_parse(raw=raw)
        assert _missing(parsed.header)
        outcome = _validate(output=parsed)
        assert (outcome.verdict, _code(outcome)) == (
            _V.FAILED,
            PROTOCOL_VALIDATION_RESULT_INVALID,
        )
        assert outcome.primary_diagnostic.details["byte_length"] == len(raw)
        assert _missing(outcome.sanitized_validation_result)


@pytest.mark.parametrize("exit_value", [0, 20, 30])
def test_a_missing_validation_output_on_a_required_exit_is_invalid_without_detail(
    exit_value: int,
) -> None:
    outcome = _validate(_invocation(_K.VALIDATE, exit_value), output=MISSING)
    assert (outcome.verdict, _code(outcome)) == (
        _V.FAILED,
        PROTOCOL_VALIDATION_RESULT_INVALID,
    )
    assert "output_present" not in outcome.primary_diagnostic.details


@pytest.mark.parametrize(
    ("exit_value", "code"),
    [
        (10, SCHEMA_REQUEST_INVALID),
        (40, ENGINE_RUNTIME_FAILURE),
        (50, ENGINE_RUNTIME_FAILURE),
        (60, ENGINE_RUNTIME_FAILURE),
        (70, PROTOCOL_ADAPTER_REPORTED_VIOLATION),
        (_UNRECOGNIZED_EXIT, ENGINE_RUNTIME_FAILURE),
    ],
)
def test_a_missing_validation_output_on_a_non_required_exit_keeps_the_exit_code(
    exit_value: int, code: str
) -> None:
    outcome = _validate(_invocation(_K.VALIDATE, exit_value), output=MISSING)
    assert (outcome.verdict, _code(outcome)) == (_V.FAILED, code)
    details = outcome.primary_diagnostic.details
    assert details["output_present"] is False
    assert details["native_exit_value"] == exit_value
    assert details["process_exit_category"] == ProcessExitCategory(
        exit_codes.semantic_exit_reading(_K.VALIDATE, exit_value).process_exit_category
    )


@pytest.mark.parametrize(
    ("changes", "fields"),
    [
        ({"invocation_id": OTHER_INVOCATION_ID}, ["invocation_id"]),
        ({"run_id": OTHER_RUN_ID}, ["run_id"]),
        ({"request_id": request_id_for(OTHER_RUN_ID)}, ["request_id"]),
        (
            {"attempt_token_hash": attempt_token_hash(_WRONG_TOKEN)},
            ["attempt_token_hash"],
        ),
        ({"invocation_id": None}, ["invocation_id"]),
        ({"attempt_token_hash": None}, ["attempt_token_hash"]),
        ({"invocation_id": 7, "run_id": ""}, ["invocation_id", "run_id"]),
    ],
    ids=[
        "invocation",
        "run",
        "request",
        "token-hash",
        "absent-invocation",
        "absent-hash",
        "typed",
    ],
)
def test_a_validation_header_identity_differing_from_the_records_reports_identity(
    changes: dict[str, Any], fields: list[str]
) -> None:
    document = _validation_document()
    for name, value in changes.items():
        if value is None:
            document.pop(name)
        else:
            document[name] = value
    document["result_hash"] = _stdlib_digest(
        {key: value for key, value in document.items() if key != "result_hash"}
    )
    outcome = _validate(output=_validation_parse(document))
    assert (outcome.verdict, _code(outcome)) == (
        _V.FAILED,
        PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
    )
    assert outcome.primary_diagnostic.details["mismatched_fields"] == fields
    assert _missing(outcome.sanitized_validation_result)
    _assert_token_free(outcome)


def test_a_mis_identified_and_malformed_validation_result_reports_identity() -> None:
    document = _validation_document(invocation_id=OTHER_INVOCATION_ID)
    document["unexpected"] = "field"
    parsed = _validation_parse(document)
    assert parsed.failure_code == PROTOCOL_VALIDATION_RESULT_INVALID
    outcome = _validate(output=parsed)
    assert _code(outcome) == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION


def test_a_stale_attempt_result_never_reconciles_for_the_successor() -> None:
    """Scenario 47: attempt 1's result handed to attempt 2's validate."""
    stale = _validation_parse()
    outcome = _validate(
        _invocation(
            _K.VALIDATE, 0, invocation_id=OTHER_INVOCATION_ID, run_id=OTHER_RUN_ID
        ),
        _STALE_RUN,
        stale,
    )
    assert _code(outcome) == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    assert set(_mismatched(outcome)) == {
        "invocation_id",
        "request_id",
        "run_id",
    }


def test_a_recorded_validation_failure_code_surfaces_after_identity() -> None:
    unsupported = _validate(
        output=_validation_parse(_validation_document(protocol_version="2.0.0"))
    )
    assert _code(unsupported) == PROTOCOL_UNSUPPORTED_VERSION
    document = _validation_document()
    document["unexpected"] = "field"
    invalid = _validate(output=_validation_parse(document))
    assert _code(invalid) == PROTOCOL_VALIDATION_RESULT_INVALID
    wrong_hash = _validate(
        output=_validation_parse(_validation_document(result_hash=_OTHER_HASH))
    )
    assert _code(wrong_hash) == PROTOCOL_VALIDATION_RESULT_INVALID
    redacted = _validate(
        output=_validation_parse(
            _validation_document(
                outcome="INVALID",
                diagnostics=[
                    {**_ADAPTER_DIAGNOSTIC, "message": f"see {ATTEMPT_TOKEN}"}
                ],
            )
        )
    )
    assert _code(redacted) == PROTOCOL_VALIDATION_RESULT_INVALID
    for outcome in (unsupported, invalid, wrong_hash, redacted):
        assert outcome.verdict is _V.FAILED
        assert _missing(outcome.sanitized_validation_result)
        _assert_token_free(outcome)


def _validate_expectation(
    outcome: ValidationOutcome, exit_value: int
) -> tuple[ReconciliationVerdict, str | None]:
    if exit_value == 0:
        if outcome is _O.VALID:
            return _V.VALIDATED_READY, None
        return _V.FAILED, PROTOCOL_VALIDATION_RESULT_INVALID
    if exit_value == 10:
        if outcome is _O.INVALID:
            return _V.FAILED, SCHEMA_REQUEST_INVALID
        return _V.FAILED, PROTOCOL_VALIDATION_RESULT_INVALID
    if exit_value == 20:
        if outcome is _O.NOT_APPLICABLE:
            return _V.NOT_APPLICABLE, COMPAT_NOT_APPLICABLE
        return _V.FAILED, PROTOCOL_VALIDATION_RESULT_INVALID
    if exit_value == 30:
        if outcome is _O.UNAVAILABLE:
            return _V.UNAVAILABLE, ADAPTER_UNAVAILABLE
        return _V.FAILED, PROTOCOL_VALIDATION_RESULT_INVALID
    if exit_value == 70:
        return _V.FAILED, PROTOCOL_ADAPTER_REPORTED_VIOLATION
    return _V.FAILED, ENGINE_RUNTIME_FAILURE


_VALIDATE_MATRIX: Final = [
    (outcome, exit_value) for exit_value in _EXITS for outcome in ValidationOutcome
]


@pytest.mark.parametrize(
    ("outcome", "exit_value"),
    _VALIDATE_MATRIX,
    ids=[f"{exit_value}-{outcome.value}" for outcome, exit_value in _VALIDATE_MATRIX],
)
def test_every_recognized_exit_against_every_validation_outcome(
    outcome: ValidationOutcome, exit_value: int
) -> None:
    verdict, code = _validate_expectation(outcome, exit_value)
    reconciled = _validate_case(outcome, exit_value)
    assert reconciled.verdict is verdict
    assert _code(reconciled) == code
    assert reconciled.run_target_state == (_TARGET_OF_VERDICT[verdict] or MISSING)
    # Every strict-valid result of this invocation is recorded, whatever the exit.
    assert reconciled.sanitized_validation_result.outcome is outcome
    if code is None:
        assert reconciled.diagnostics == ()
    else:
        primary = reconciled.primary_diagnostic
        assert primary.error_code == code
        assert primary.category is STAGE6_DIAGNOSTIC_CODES[code].category
        assert primary.retriable is STAGE6_DIAGNOSTIC_CODES[code].retriable
        assert primary.invocation_id == INVOCATION_ID
        assert primary.run_id == RUN_ID
        assert primary.experiment_id == EXPERIMENT_ID
        details = primary.details
        assert details["native_exit_value"] == exit_value
        if code == PROTOCOL_VALIDATION_RESULT_INVALID:
            assert details["declared_outcome"] == outcome.value
        if exit_value not in RECOGNIZED_NATIVE_EXIT_VALUES:
            assert primary.causal_diagnostic_ids == (
                _UNRECOGNIZED_PRIMARY.diagnostic_id,
            )
        else:
            assert primary.causal_diagnostic_ids == ()
    _assert_token_free(reconciled)


def test_a_validate_exiting_forty_after_writing_valid_records_the_output() -> None:
    outcome = _validate_case(_O.VALID, 40)
    assert (outcome.verdict, _code(outcome)) == (_V.FAILED, ENGINE_RUNTIME_FAILURE)
    assert outcome.sanitized_validation_result.outcome is _O.VALID
    assert "output_present" not in outcome.primary_diagnostic.details
    assert outcome.primary_diagnostic.retriable is True


def test_validate_never_launches_run_and_is_deterministic_under_the_clock() -> None:
    ready = _validate()
    assert ready.run_target_state is _R.READY
    assert ready.run_target_state not in SUCCESS_ENGINE_RUN_STATES
    first = _validate_case(_O.INVALID, 0)
    second = _validate(
        _invocation(_K.VALIDATE, 0),
        output=_validation_parse(_validation_document(outcome="INVALID")),
        now_utc=_LATER,
    )
    assert (
        first.primary_diagnostic.diagnostic_id
        == second.primary_diagnostic.diagnostic_id
    )
    assert first.model_dump(exclude={"primary_diagnostic", "diagnostics"}) == (
        second.model_dump(exclude={"primary_diagnostic", "diagnostics"})
    )


# --- reconcile_run -------------------------------------------------------------------


def test_run_preconditions_raise_by_name() -> None:
    with pytest.raises(ReconciliationRuleViolation, match="RUN"):
        _run(_invocation(_K.VALIDATE, 0))
    with pytest.raises(ReconciliationRuleViolation, match="RUN"):
        _run(_invocation(_K.DESCRIBE, 0))
    with pytest.raises(ReconciliationRuleViolation, match="EXITED"):
        _run(_invocation(_K.RUN, 0, _C.RUNNING))
    with pytest.raises(ReconciliationRuleViolation, match="EXITED"):
        _run(_invocation(_K.RUN, 0, _C.CANCELLED))
    with pytest.raises(ReconciliationRuleViolation, match="run"):
        _run(run=sample_run(_R.RUNNING, run_id=OTHER_RUN_ID))
    with pytest.raises(ReconciliationRuleViolation, match="experiment"):
        _run(
            experiment=sample_experiment(
                ExperimentState.RUNNING, experiment_id=OTHER_EXPERIMENT_ID
            )
        )
    with pytest.raises(ReconciliationRuleViolation, match="slot"):
        _run(slot=_EXPERIMENT.slot_compatibility[1])
    with pytest.raises(ReconciliationRuleViolation, match="slot"):
        _run(slot=_APPROXIMATED_SLOT)
    with pytest.raises(ReconciliationRuleViolation, match="invocation"):
        _run(protocol_failure=_protocol_failure(OTHER_INVOCATION_ID))
    with pytest.raises(ReconciliationRuleViolation, match="relative_path"):
        _run(observations=_observations(_DECLARATION, _DECLARATION))
    too_many = tuple(
        _observation({**_DECLARATION, "relative_path": f"results/{index}.bin"})
        for index in range(2 * MAX_CANDIDATE_ARTIFACTS + 1)
    )
    with pytest.raises(ReconciliationRuleViolation, match="observations"):
        _run(observations=too_many)
    with pytest.raises(TypeError, match="ManifestParse"):
        _run(output=_validation_parse())
    with pytest.raises(TypeError, match="NegotiatedVersions"):
        _run(negotiated=_NEGOTIATED.model_dump())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="CandidateObservation"):
        _run(observations=(_DECLARATION,))
    with pytest.raises(TypeError, match="SlotCompatibility"):
        _run(slot=_RUN)
    with pytest.raises(TypeError, match="ExperimentRecord"):
        _run(experiment=_RUN)


@pytest.mark.parametrize(
    "state", [_R.RUNNING, _R.NOT_APPLICABLE, _R.UNAVAILABLE, _R.FAILED]
)
def test_run_admits_the_pre_state_and_every_state_it_can_produce(
    state: EngineRunState,
) -> None:
    assert _run(run=sample_run(state)).verdict is _V.RESULT_FINALIZATION_ELIGIBLE


@pytest.mark.parametrize(
    "state",
    [
        _R.PENDING,
        _R.VALIDATING,
        _R.READY,
        _R.STARTING,
        _R.SUCCEEDED,
        _R.SUCCEEDED_WITH_WARNINGS,
        _R.CANCELLED,
        _R.TIMED_OUT,
    ],
)
def test_run_rejects_every_other_run_state(state: EngineRunState) -> None:
    with pytest.raises(ReconciliationRuleViolation, match=state.value):
        _run(run=sample_run(state))


def test_a_conformant_run_is_result_finalization_eligible_and_nothing_more() -> None:
    parsed = _manifest_parse()
    outcome = _run(output=parsed)
    assert outcome.command_kind is _K.RUN
    assert outcome.verdict is _V.RESULT_FINALIZATION_ELIGIBLE
    assert _missing(outcome.run_target_state)
    assert _missing(outcome.primary_diagnostic)
    assert outcome.diagnostics == ()
    assert outcome.semantic_status is _S.SUCCEEDED
    sanitized = outcome.sanitized_manifest
    assert sanitized.source_adapter_result_manifest_hash == parsed.source_hash
    assert sanitized.sanitized_adapter_result_manifest_hash != parsed.source_hash
    assert sanitized.attempt_token_hash == _TOKEN_HASH
    assert len(sanitized.candidate_artifact_ids) == 1
    for name in ("sanitized_validation_result", "negotiation", "descriptor"):
        assert _missing(getattr(outcome, name)), name
    for name in ("run_manifest", "artifact_refs", "finalized"):
        assert name not in SemanticReconciliation.model_fields
    _assert_token_free(outcome)


def test_a_protocol_failure_overrides_a_valid_manifest_and_is_the_primary() -> None:
    failure = _protocol_failure()
    outcome = _run(protocol_failure=failure)
    assert outcome.verdict is _V.FAILED
    assert outcome.run_target_state is _R.FAILED
    assert outcome.primary_diagnostic == failure
    assert outcome.diagnostics == (failure,)
    # The consistent manifest of this invocation stays EVIDENCE material.
    assert not _missing(outcome.sanitized_manifest)
    for exit_value in _EXITS:
        assert (
            _run_case(
                _S.SUCCEEDED, exit_value, protocol_failure=failure
            ).primary_diagnostic
            == failure
        )
    # A protocol failure also beats leakage and the absent-manifest rows.
    leaking = _run(
        observations=_observations(_DECLARATION, contains_attempt_token=True),
        protocol_failure=failure,
    )
    assert leaking.primary_diagnostic == failure
    assert _run(output=MISSING, protocol_failure=failure).primary_diagnostic == failure


def test_manifest_bytes_without_a_header_are_result_manifest_invalid() -> None:
    for raw in (b"not json", b"[]", b"\xff\xfe", b"{" * 3):
        parsed = _manifest_parse(raw=raw)
        assert _missing(parsed.header)
        outcome = _run(output=parsed, summary=_EMPTY_SUMMARY, observations=())
        assert (outcome.verdict, _code(outcome)) == (
            _V.FAILED,
            ARTIFACT_RESULT_MANIFEST_INVALID,
        )
        assert outcome.primary_diagnostic.details["byte_length"] == len(raw)
        assert _missing(outcome.sanitized_manifest)
        assert _missing(outcome.semantic_status)


@pytest.mark.parametrize(
    ("changes", "fields"),
    [
        ({"invocation_id": OTHER_INVOCATION_ID}, ["invocation_id"]),
        ({"run_id": OTHER_RUN_ID}, ["run_id"]),
        ({"attempt_token": _WRONG_TOKEN}, ["attempt_token_hash"]),
        ({"attempt_token": None}, ["attempt_token_hash"]),
        ({"invocation_id": None}, ["invocation_id"]),
        ({"attempt_token": 12}, ["attempt_token_hash"]),
        (
            {"invocation_id": OTHER_INVOCATION_ID, "run_id": OTHER_RUN_ID},
            ["invocation_id", "run_id"],
        ),
    ],
    ids=[
        "invocation",
        "run",
        "wrong-token",
        "absent-token",
        "absent-invocation",
        "typed-token",
        "both",
    ],
)
def test_a_manifest_header_identity_differing_from_the_records_reports_identity(
    changes: dict[str, Any], fields: list[str]
) -> None:
    document = _manifest_document()
    for name, value in changes.items():
        if value is None:
            document.pop(name)
        else:
            document[name] = value
    parsed = _manifest_parse(document)
    outcome = _run(
        output=parsed,
        summary=_summary(_DECLARATION),
        observations=_observations(_DECLARATION),
    )
    assert (outcome.verdict, _code(outcome)) == (
        _V.FAILED,
        PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
    )
    assert outcome.primary_diagnostic.details["mismatched_fields"] == fields
    assert _missing(outcome.sanitized_manifest)
    _assert_token_free(outcome)


def test_a_mis_identified_and_malformed_manifest_reports_identity() -> None:
    document = _manifest_document(invocation_id=OTHER_INVOCATION_ID)
    document["unexpected"] = "field"
    parsed = _manifest_parse(document)
    assert parsed.failure_code == ARTIFACT_RESULT_MANIFEST_INVALID
    assert _code(_run(output=parsed, summary=_EMPTY_SUMMARY, observations=())) == (
        PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    )


def test_a_recorded_manifest_failure_code_surfaces_after_identity() -> None:
    unsupported = _run(
        output=_manifest_parse(_manifest_document(protocol_version="2.0.0")),
        summary=_EMPTY_SUMMARY,
        observations=(),
    )
    assert _code(unsupported) == PROTOCOL_UNSUPPORTED_VERSION
    escape = _run(
        output=_manifest_parse(
            _manifest_document(
                candidate_artifacts=[{**_DECLARATION, "relative_path": "C:/escape.bin"}]
            )
        ),
        summary=_EMPTY_SUMMARY,
        observations=(),
    )
    assert _code(escape) == ARTIFACT_PATH_BOUNDARY_VIOLATION
    assert "escape" not in canonical_json_bytes(escape).decode()
    document = _manifest_document()
    document["unexpected"] = "field"
    invalid = _run(
        output=_manifest_parse(document), summary=_EMPTY_SUMMARY, observations=()
    )
    assert _code(invalid) == ARTIFACT_RESULT_MANIFEST_INVALID
    for outcome in (unsupported, escape, invalid):
        assert outcome.verdict is _V.FAILED
        assert outcome.run_target_state is _R.FAILED
        assert _missing(outcome.sanitized_manifest)


@pytest.mark.parametrize(
    ("document_updates", "negotiated", "field"),
    [
        ({"experiment_id": OTHER_EXPERIMENT_ID}, _NEGOTIATED, "experiment_id"),
        (
            {"provenance": {"request_hash": OTHER_REQUEST_HASH}},
            _NEGOTIATED,
            "request_hash",
        ),
        (
            {"provenance": {"experiment_spec_hash": _OTHER_HASH}},
            _NEGOTIATED,
            "experiment_spec_hash",
        ),
        ({"provenance": {"logical_slot_id": SLOT_B}}, _NEGOTIATED, "logical_slot_id"),
        ({"provenance": {"attempt_number": 2}}, _NEGOTIATED, "attempt_number"),
        (
            {
                "provenance": {
                    "adapter": {
                        "adapter_name": "adapter.beta",
                        "adapter_version": "1.2.0",
                    }
                }
            },
            _NEGOTIATED,
            "adapter",
        ),
        (
            {
                "provenance": {
                    "engine": {"engine_name": "engine.beta", "engine_version": "2.3.4"}
                }
            },
            _NEGOTIATED,
            "engine",
        ),
        (
            {"provenance": {"comparison_level": "LEVEL_1"}},
            _NEGOTIATED,
            "comparison_level",
        ),
        (
            {"provenance": {"strategy_version_hash": _OTHER_HASH}},
            _NEGOTIATED,
            "strategy_version_hash",
        ),
        (
            {"provenance": {"dataset_version_hash": _OTHER_HASH}},
            _NEGOTIATED,
            "dataset_version_hash",
        ),
        (
            {"provenance": {"configuration_hash": _OTHER_HASH}},
            _NEGOTIATED,
            "configuration_hash",
        ),
        (
            {
                "provenance": {
                    "negotiated_versions": _OTHER_NEGOTIATED.model_dump(mode="json")
                }
            },
            _NEGOTIATED,
            "negotiated_versions",
        ),
        ({}, _OTHER_NEGOTIATED, "negotiated_versions"),
    ],
    ids=lambda value: value if isinstance(value, str) else "",
)
def test_a_manifest_provenance_differing_from_the_records_is_result_manifest_invalid(
    document_updates: dict[str, Any], negotiated: NegotiatedVersions, field: str
) -> None:
    outcome = _run_case(_S.SUCCEEDED, 0, negotiated=negotiated, **document_updates)
    assert (outcome.verdict, _code(outcome)) == (
        _V.FAILED,
        ARTIFACT_RESULT_MANIFEST_INVALID,
    )
    assert outcome.primary_diagnostic.details["mismatched_fields"] == [field]
    assert _missing(outcome.sanitized_manifest)


def test_the_final_result_pointer_must_name_the_manifest_exactly() -> None:
    parsed = _manifest_parse()
    observations = _observations(_DECLARATION)
    for summary in (
        _summary(_DECLARATION),
        _summary(_DECLARATION, final=parsed, final_path="results/other.json"),
        _summary(_DECLARATION, final=parsed, final_hash=_OTHER_HASH),
        _summary(_DECLARATION, final=parsed, final_status=_S.FAILED),
    ):
        outcome = _run(output=parsed, summary=summary, observations=observations)
        assert (outcome.verdict, _code(outcome)) == (
            _V.FAILED,
            ARTIFACT_RESULT_MANIFEST_INVALID,
        )
        assert _missing(outcome.sanitized_manifest)
        assert "final_result" in _mismatched(outcome)[0]


def test_a_leaking_candidate_is_leakage_and_a_redacted_manifest_is_not() -> None:
    leaking = _run(
        observations=_observations(_DECLARATION, contains_attempt_token=True)
    )
    assert (leaking.verdict, _code(leaking)) == (
        _V.FAILED,
        SECURITY_SENSITIVE_MATERIAL_LEAKAGE,
    )
    assert leaking.primary_diagnostic.details["leaking_candidates"] == 1
    assert (
        "results/native.bin"
        not in canonical_json_bytes(leaking.primary_diagnostic).decode()
    )
    # The manifest itself is consistent, so its sanitized form remains EVIDENCE.
    assert not _missing(leaking.sanitized_manifest)
    # Leakage is checked with or without a manifest and precedes the exit column.
    abandoned = _run(
        _invocation(_K.RUN, 40),
        output=MISSING,
        summary=_summary(_DECLARATION),
        observations=_observations(_DECLARATION, contains_attempt_token=True),
    )
    assert _code(abandoned) == SECURITY_SENSITIVE_MATERIAL_LEAKAGE
    # Scenario 40: the token inside a warning message is redacted on both sides --
    # the manifest by the manifest parser, the event by the line parser (built here
    # already redacted, as the ledger would hold it).
    warning = {**_WARNING, "message": f"fills approximated {ATTEMPT_TOKEN}"}
    redacted_warning = {
        **_WARNING,
        "message": f"fills approximated {REDACTION_PLACEHOLDER}",
    }
    redacted = _run_case(
        _S.SUCCEEDED_WITH_WARNINGS,
        0,
        warnings=(warning,),
        event_warnings=(redacted_warning,),
    )
    assert redacted.verdict is _V.RESULT_FINALIZATION_ELIGIBLE
    assert redacted.sanitized_manifest.warnings[0].message.endswith(
        REDACTION_PLACEHOLDER
    )
    _assert_token_free(redacted)


def test_success_declarations_must_equal_the_accepted_events_as_five_tuples() -> None:
    missing_event = _run_case(_S.SUCCEEDED, 0, event_declarations=())
    extra_event = _run_case(
        _S.SUCCEEDED, 0, event_declarations=(_DECLARATION, _SECOND_DECLARATION)
    )
    differing = _run_case(
        _S.SUCCEEDED,
        0,
        event_declarations=({**_DECLARATION, "declared_sha256": _OTHER_HASH},),
    )
    for outcome in (missing_event, extra_event, differing):
        assert (outcome.verdict, _code(outcome)) == (
            _V.FAILED,
            ARTIFACT_RESULT_MANIFEST_INVALID,
        )
        assert _missing(outcome.sanitized_manifest)
        details = outcome.primary_diagnostic.details
        assert set(details) >= {"declared_candidates", "accepted_declarations"}
        assert (
            "results/" not in canonical_json_bytes(outcome.primary_diagnostic).decode()
        )


def test_a_truthful_failed_manifest_after_declarations_keeps_the_exit_posture() -> None:
    """Scenario 48: check (9) is scoped to success statuses; check (10) compares
    manifest declarations only, so the abandoned candidate may be absent."""
    for observations in (_observations(_DECLARATION), ()):
        outcome = _run_case(
            _S.FAILED, 40, event_declarations=(_DECLARATION,), observations=observations
        )
        assert (outcome.verdict, _code(outcome)) == (_V.FAILED, ENGINE_RUNTIME_FAILURE)
        assert outcome.primary_diagnostic.retriable is True
        assert not _missing(outcome.sanitized_manifest)
        assert outcome.sanitized_manifest.candidate_artifact_ids == ()
        assert outcome.semantic_status is _S.FAILED


def test_a_declaration_without_a_matching_observation_is_validation_failed() -> None:
    absent = _run_case(_S.SUCCEEDED, 0, observations=())
    wrong_hash = _run_case(
        _S.SUCCEEDED,
        0,
        observations=(_observation(_DECLARATION, observed_sha256=_OTHER_HASH),),
    )
    wrong_size = _run_case(
        _S.SUCCEEDED,
        0,
        observations=(_observation(_DECLARATION, observed_size_bytes=13),),
    )
    for outcome in (absent, wrong_hash, wrong_size):
        assert (outcome.verdict, _code(outcome)) == (
            _V.FAILED,
            ARTIFACT_VALIDATION_FAILED,
        )
        assert outcome.primary_diagnostic.retriable is False
        # The manifest is internally consistent; the file is not. EVIDENCE stays.
        assert not _missing(outcome.sanitized_manifest)
    # An observation of an undeclared path is ignored by check (10).
    extra = _run_case(
        _S.SUCCEEDED, 0, observations=_observations(_DECLARATION, _SECOND_DECLARATION)
    )
    assert extra.verdict is _V.RESULT_FINALIZATION_ELIGIBLE


def test_manifest_warnings_must_be_a_superset_of_the_accepted_warning_events() -> None:
    event_only = _run_case(_S.SUCCEEDED, 0, event_warnings=(_WARNING,))
    differing = _run_case(
        _S.SUCCEEDED_WITH_WARNINGS,
        0,
        warnings=(_WARNING,),
        event_warnings=(_OTHER_WARNING,),
    )
    for outcome in (event_only, differing):
        assert (outcome.verdict, _code(outcome)) == (
            _V.FAILED,
            ARTIFACT_RESULT_MANIFEST_INVALID,
        )
        assert _missing(outcome.sanitized_manifest)
    superset = _run_case(
        _S.SUCCEEDED_WITH_WARNINGS,
        0,
        warnings=(_WARNING, _OTHER_WARNING),
        event_warnings=(_WARNING,),
    )
    assert superset.verdict is _V.RESULT_FINALIZATION_ELIGIBLE
    assert superset.semantic_status is _S.SUCCEEDED_WITH_WARNINGS
    assert len(superset.sanitized_manifest.warnings) == 2


def test_manifest_approximations_must_equal_the_slots_approximation_identities() -> (
    None
):
    declared = _run_case(_S.SUCCEEDED, 0, approximations=[_APPROXIMATION])
    assert (declared.verdict, _code(declared)) == (
        _V.FAILED,
        ARTIFACT_RESULT_MANIFEST_INVALID,
    )
    assert declared.primary_diagnostic.details["mismatched_fields"] == [
        "approximations"
    ]
    omitted = _run_case(
        _S.SUCCEEDED, 0, experiment=_APPROXIMATED_EXPERIMENT, slot=_APPROXIMATED_SLOT
    )
    assert _code(omitted) == ARTIFACT_RESULT_MANIFEST_INVALID
    echoed = _run_case(
        _S.SUCCEEDED,
        0,
        experiment=_APPROXIMATED_EXPERIMENT,
        slot=_APPROXIMATED_SLOT,
        approximations=[_APPROXIMATION],
    )
    assert echoed.verdict is _V.RESULT_FINALIZATION_ELIGIBLE
    assert echoed.sanitized_manifest.approximations == (_APPROXIMATION,)


def _run_expectation(
    status: SemanticStatus, exit_value: int
) -> tuple[ReconciliationVerdict, str | None]:
    if exit_value == 0:
        if status in _SUCCESS_STATUSES:
            return _V.RESULT_FINALIZATION_ELIGIBLE, None
        if status is _S.FAILED:
            return _V.FAILED, ENGINE_RUNTIME_FAILURE
        return _V.FAILED, ARTIFACT_RESULT_MANIFEST_INVALID
    if exit_value == 20:
        if status is _S.NOT_APPLICABLE:
            return _V.NOT_APPLICABLE, COMPAT_LATE_NOT_APPLICABLE
        return _V.FAILED, ARTIFACT_RESULT_MANIFEST_INVALID
    if exit_value == 30:
        if status is _S.UNAVAILABLE:
            return _V.UNAVAILABLE, ADAPTER_UNAVAILABLE
        return _V.FAILED, ARTIFACT_RESULT_MANIFEST_INVALID
    agreeing = {
        10: {_S.FAILED},
        40: {_S.FAILED},
        50: {_S.FAILED, _S.CANCELLED},
        60: {_S.FAILED, _S.TIMED_OUT},
        70: {_S.FAILED},
    }.get(exit_value, {_S.FAILED})
    if status not in agreeing:
        return _V.FAILED, ARTIFACT_RESULT_MANIFEST_INVALID
    if exit_value == 10:
        return _V.FAILED, SCHEMA_REQUEST_INVALID
    if exit_value == 70:
        return _V.FAILED, PROTOCOL_ADAPTER_REPORTED_VIOLATION
    return _V.FAILED, ENGINE_RUNTIME_FAILURE


_RUN_MATRIX: Final = [
    (status, exit_value) for exit_value in _EXITS for status in SemanticStatus
]


@pytest.mark.parametrize(
    ("status", "exit_value"),
    _RUN_MATRIX,
    ids=[f"{exit_value}-{status.value}" for status, exit_value in _RUN_MATRIX],
)
def test_every_recognized_exit_against_every_semantic_status(
    status: SemanticStatus, exit_value: int
) -> None:
    verdict, code = _run_expectation(status, exit_value)
    outcome = _run_case(status, exit_value)
    assert outcome.verdict is verdict
    assert _code(outcome) == code
    assert outcome.run_target_state == (_TARGET_OF_VERDICT[verdict] or MISSING)
    # The manifest passed identity and every declaration check, so it is EVIDENCE.
    assert not _missing(outcome.sanitized_manifest)
    assert outcome.semantic_status is status
    assert outcome.sanitized_manifest.semantic_status is status
    if code is None:
        assert outcome.diagnostics == ()
    else:
        primary = outcome.primary_diagnostic
        assert primary.error_code == code
        assert primary.category is STAGE6_DIAGNOSTIC_CODES[code].category
        assert primary.retriable is STAGE6_DIAGNOSTIC_CODES[code].retriable
        assert (primary.experiment_id, primary.run_id, primary.invocation_id) == (
            EXPERIMENT_ID,
            RUN_ID,
            INVOCATION_ID,
        )
        details = primary.details
        assert details["native_exit_value"] == exit_value
        assert "manifest_present" not in details
        if code == ARTIFACT_RESULT_MANIFEST_INVALID:
            assert details["declared_semantic_status"] == status.value
        if code in {COMPAT_LATE_NOT_APPLICABLE, ADAPTER_UNAVAILABLE}:
            assert details["adapter_error_code"] == _ADAPTER_DIAGNOSTIC["error_code"]
            assert details["adapter_manifest_id"] == _MANIFEST_ID
        # Only the exit-derived runtime failure of an unrecognized exit cites the
        # invocation's PROCESS.UNRECOGNIZED_PROCESS_EXIT primary; a contradiction
        # on such an exit is its own finding.
        if (
            exit_value not in RECOGNIZED_NATIVE_EXIT_VALUES
            and code == ENGINE_RUNTIME_FAILURE
        ):
            assert primary.causal_diagnostic_ids == (
                _UNRECOGNIZED_PRIMARY.diagnostic_id,
            )
        else:
            assert primary.causal_diagnostic_ids == ()
    _assert_token_free(outcome)


@pytest.mark.parametrize("exit_value", _EXITS)
def test_an_absent_manifest_reads_the_exit_column(exit_value: int) -> None:
    outcome = _run_case(_S.SUCCEEDED, exit_value, output_present=False)
    assert outcome.verdict is _V.FAILED
    assert outcome.run_target_state is _R.FAILED
    assert _missing(outcome.sanitized_manifest)
    assert _missing(outcome.semantic_status)
    details = outcome.primary_diagnostic.details
    if exit_value in {0, 20, 30}:
        assert _code(outcome) == ARTIFACT_RESULT_MANIFEST_INVALID
        assert "manifest_present" not in details
    else:
        expected = {
            10: SCHEMA_REQUEST_INVALID,
            70: PROTOCOL_ADAPTER_REPORTED_VIOLATION,
        }.get(exit_value, ENGINE_RUNTIME_FAILURE)
        assert _code(outcome) == expected
        assert details["manifest_present"] is False
        assert details["native_exit_value"] == exit_value
        if exit_value not in RECOGNIZED_NATIVE_EXIT_VALUES:
            assert outcome.primary_diagnostic.causal_diagnostic_ids == (
                _UNRECOGNIZED_PRIMARY.diagnostic_id,
            )


def test_a_late_not_applicable_or_unavailable_manifest_cites_its_diagnostic() -> None:
    late = _run_case(_S.NOT_APPLICABLE, 20)
    assert (late.verdict, _code(late), late.run_target_state) == (
        _V.NOT_APPLICABLE,
        COMPAT_LATE_NOT_APPLICABLE,
        _R.NOT_APPLICABLE,
    )
    unavailable = _run_case(_S.UNAVAILABLE, 30)
    assert (unavailable.verdict, _code(unavailable), unavailable.run_target_state) == (
        _V.UNAVAILABLE,
        ADAPTER_UNAVAILABLE,
        _R.UNAVAILABLE,
    )
    for outcome in (late, unavailable):
        details = outcome.primary_diagnostic.details
        assert details["adapter_error_code"] == "ENGINE.DATA_GAP"
        assert details["adapter_manifest_id"] == _MANIFEST_ID
        assert outcome.primary_diagnostic.causal_diagnostic_ids == ()
        assert not _missing(outcome.sanitized_manifest)
    # Without the explaining manifest neither late outcome exists.
    for exit_value in (20, 30):
        assert _code(_run_case(_S.SUCCEEDED, exit_value, output_present=False)) == (
            ARTIFACT_RESULT_MANIFEST_INVALID
        )


def test_exit_zero_with_a_failed_manifest_is_a_truthful_retriable_failure() -> None:
    outcome = _run_case(_S.FAILED, 0)
    assert (outcome.verdict, _code(outcome)) == (_V.FAILED, ENGINE_RUNTIME_FAILURE)
    assert outcome.primary_diagnostic.retriable is True
    assert outcome.run_target_state is _R.FAILED
    assert not _missing(outcome.sanitized_manifest)


def test_exit_seventy_is_a_contradiction_for_success_and_a_report_for_failure() -> None:
    assert _code(_run_case(_S.SUCCEEDED, 70)) == ARTIFACT_RESULT_MANIFEST_INVALID
    assert _code(_run_case(_S.FAILED, 70)) == PROTOCOL_ADAPTER_REPORTED_VIOLATION


def test_run_is_deterministic_under_the_clock_and_mutates_nothing() -> None:
    first = _run_case(_S.SUCCEEDED, 40, now_utc=_NOW)
    second = _run_case(_S.SUCCEEDED, 40, now_utc=_LATER)
    assert (
        first.primary_diagnostic.diagnostic_id
        == second.primary_diagnostic.diagnostic_id
    )
    assert first.model_dump(exclude={"primary_diagnostic", "diagnostics"}) == (
        second.model_dump(exclude={"primary_diagnostic", "diagnostics"})
    )
    assert first.primary_diagnostic.timestamp_utc == _NOW
    assert second.primary_diagnostic.timestamp_utc == _LATER
    eligible_first = _run_case(_S.SUCCEEDED, 0, now_utc=_NOW)
    eligible_second = _run_case(_S.SUCCEEDED, 0, now_utc=_LATER)
    assert eligible_first == eligible_second
    assert canonical_json_bytes(eligible_first) == canonical_json_bytes(eligible_second)


# --- No false success ----------------------------------------------------------------


def _foreign_validation_as_manifest() -> ManifestParse:
    return _manifest_parse(raw=_encode(_validation_document()))


def _foreign_descriptor_as_validation() -> ValidationResultParse:
    return _validation_parse(raw=canonical_json_bytes(_envelope()))


def _foreign_manifest_as_descriptor() -> DescriptorParse:
    return _describe_parse(_encode(_manifest_document()))


_NO_FALSE_SUCCESS: Final[dict[str, Callable[[], SemanticReconciliation]]] = {
    "run-exit-0-no-output": lambda: _run_case(_S.SUCCEEDED, 0, output_present=False),
    "validate-exit-0-no-output": lambda: _validate_case(
        _O.VALID, 0, output_present=False
    ),
    "describe-exit-0-no-output": lambda: _describe(output=MISSING),
    "run-exit-0-malformed": lambda: _run(
        output=_manifest_parse(raw=b"not json"), summary=_EMPTY_SUMMARY, observations=()
    ),
    "validate-exit-0-malformed": lambda: _validate(
        output=_validation_parse(raw=b"not json")
    ),
    "describe-exit-0-malformed": lambda: _describe(output=_describe_parse(b"not json")),
    "run-exit-0-foreign-branch": lambda: _run(
        output=_foreign_validation_as_manifest(),
        summary=_EMPTY_SUMMARY,
        observations=(),
    ),
    "validate-exit-0-foreign-branch": lambda: _validate(
        output=_foreign_descriptor_as_validation()
    ),
    "describe-exit-0-foreign-branch": lambda: _describe(
        output=_foreign_manifest_as_descriptor()
    ),
    "run-exit-0-wrong-invocation": lambda: _run_case(
        _S.SUCCEEDED, 0, invocation_id=OTHER_INVOCATION_ID
    ),
    "validate-exit-0-wrong-invocation": lambda: _validate_case(
        _O.VALID, 0, invocation_id=OTHER_INVOCATION_ID
    ),
    "run-exit-0-wrong-run": lambda: _run_case(_S.SUCCEEDED, 0, run_id=OTHER_RUN_ID),
    "validate-exit-0-wrong-run": lambda: _validate_case(
        _O.VALID, 0, run_id=OTHER_RUN_ID
    ),
    "run-exit-0-wrong-token": lambda: _run_case(
        _S.SUCCEEDED, 0, attempt_token=_WRONG_TOKEN
    ),
    "validate-exit-0-wrong-token-hash": lambda: _validate_case(
        _O.VALID, 0, attempt_token_hash=attempt_token_hash(_WRONG_TOKEN)
    ),
    "run-exit-0-protocol-failure": lambda: _run(protocol_failure=_protocol_failure()),
    "validate-exit-0-protocol-failure": lambda: _validate(
        protocol_failure=_protocol_failure()
    ),
    "run-success-declaration-failure-exit": lambda: _run_case(_S.SUCCEEDED, 40),
    "run-success-declaration-timeout-exit": lambda: _run_case(_S.SUCCEEDED, 60),
    "run-success-declaration-cancel-exit": lambda: _run_case(_S.SUCCEEDED, 50),
    "run-success-declaration-request-exit": lambda: _run_case(_S.SUCCEEDED, 10),
    "run-success-declaration-violation-exit": lambda: _run_case(_S.SUCCEEDED, 70),
    "run-unknown-exit-favorable-output": lambda: _run_case(
        _S.SUCCEEDED, _UNRECOGNIZED_EXIT
    ),
    "validate-unknown-exit-favorable-output": lambda: _validate_case(
        _O.VALID, _UNRECOGNIZED_EXIT
    ),
    "validate-stale-attempt-output": lambda: _validate(
        _invocation(
            _K.VALIDATE, 0, invocation_id=OTHER_INVOCATION_ID, run_id=OTHER_RUN_ID
        ),
        _STALE_RUN,
        _validation_parse(),
    ),
    "run-stale-invocation-manifest": lambda: _run(
        _invocation(_K.RUN, 0, invocation_id=OTHER_INVOCATION_ID),
        summary=_summary(_DECLARATION),
        observations=_observations(_DECLARATION),
    ),
    "run-favorable-output-after-protocol-failure": lambda: _run_case(
        _S.SUCCEEDED, 0, protocol_failure=_protocol_failure()
    ),
    "run-exit-0-not-applicable-manifest": lambda: _run_case(_S.NOT_APPLICABLE, 0),
    "run-exit-0-leaking-candidate": lambda: _run(
        observations=_observations(_DECLARATION, contains_attempt_token=True)
    ),
    "run-exit-0-declaration-without-event": lambda: _run_case(
        _S.SUCCEEDED, 0, event_declarations=()
    ),
    "run-exit-0-declaration-without-file": lambda: _run_case(
        _S.SUCCEEDED, 0, observations=()
    ),
    "run-exit-0-no-final-result": lambda: _run_case(_S.SUCCEEDED, 0, final=False),
    "describe-nonzero-exit-valid-descriptor": lambda: _describe(
        _invocation(_K.DESCRIBE, 40)
    ),
    "describe-exit-0-contaminated": lambda: _describe(stdout_bytes_seen=1),
    "describe-exit-0-failed-negotiation": lambda: _describe(
        output=_describe_parse(
            canonical_json_bytes(
                _envelope(_descriptor(supported_protocol_versions=("2.0.0",)))
            )
        )
    ),
}


@pytest.mark.parametrize("case", sorted(_NO_FALSE_SUCCESS))
def test_no_adversarial_row_reaches_a_success_verdict(case: str) -> None:
    outcome = _NO_FALSE_SUCCESS[case]()
    assert outcome.verdict not in _SUCCESS_VERDICTS, case
    assert outcome.run_target_state not in SUCCESS_ENGINE_RUN_STATES
    assert not _missing(outcome.primary_diagnostic)
    assert len(outcome.diagnostics) == 1
    assert outcome.primary_diagnostic.error_code in STAGE6_DIAGNOSTIC_CODES
    if outcome.command_kind is _K.DESCRIBE:
        assert _missing(outcome.run_target_state)
    else:
        assert not _missing(outcome.run_target_state)
    _assert_token_free(outcome)


def test_the_no_false_success_proof_covers_every_prompt_row() -> None:
    """The rows the task prompt names, each present at least once above."""
    names = set(_NO_FALSE_SUCCESS)
    for fragment in (
        "exit-0-no-output",
        "exit-0-malformed",
        "exit-0-foreign-branch",
        "exit-0-wrong-invocation",
        "exit-0-wrong-run",
        "exit-0-wrong-token",
        "exit-0-protocol-failure",
        "success-declaration-failure-exit",
        "success-declaration-timeout-exit",
        "success-declaration-cancel-exit",
        "unknown-exit-favorable-output",
        "stale",
        "favorable-output-after-protocol-failure",
    ):
        assert any(fragment in name for name in names), fragment


def test_exit_messages_are_keyed_on_the_imported_codes_without_a_fallback() -> None:
    """Reviewer note: a respelled key or a silent default message would move a
    diagnostic identity under drift instead of failing loudly (plan 9.4)."""
    table = reconciliation._EXIT_MESSAGES
    assert set(table) == {
        SCHEMA_REQUEST_INVALID,
        ENGINE_RUNTIME_FAILURE,
        ADAPTER_UNAVAILABLE,
        COMPAT_NOT_APPLICABLE,
        COMPAT_LATE_NOT_APPLICABLE,
        PROTOCOL_ADAPTER_REPORTED_VIOLATION,
    }
    for code in table:
        assert reconciliation._exit_message(code) == table[code]
    with pytest.raises(KeyError):
        reconciliation._exit_message(PROCESS_UNRECOGNIZED_PROCESS_EXIT)


def test_a_protocol_failure_primary_must_be_a_parser_rejection_code() -> None:
    """Plan 9.2 check (1): the primary is the parser's rejection diagnostic, so it
    carries one of the six codes ``parse_protocol_line`` mints (plan 9.4), which
    include the path-located artifact code; any other code is a caller error."""
    foreign = stage6_diagnostic(
        ENGINE_RUNTIME_FAILURE,
        "not a parser rejection",
        source_component="adapters.events",
        timestamp_utc=INSTANT,
        invocation_id=INVOCATION_ID,
    )
    with pytest.raises(ReconciliationRuleViolation, match="parser"):
        _validate(protocol_failure=foreign)
    with pytest.raises(ReconciliationRuleViolation, match="parser"):
        _run(protocol_failure=foreign)
    for code in (
        PROTOCOL_STDOUT_CONTAMINATION,
        PROTOCOL_MALFORMED_JSONL,
        PROTOCOL_EVENT_TOO_LARGE,
        PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
        PROTOCOL_UNSUPPORTED_VERSION,
        ARTIFACT_PATH_BOUNDARY_VIOLATION,
    ):
        rejection = stage6_diagnostic(
            code,
            "rejected stdout line",
            source_component="adapters.events",
            timestamp_utc=INSTANT,
            invocation_id=INVOCATION_ID,
        )
        assert _run(protocol_failure=rejection).primary_diagnostic == rejection
        assert _validate(protocol_failure=rejection).primary_diagnostic == rejection


def test_a_cancelled_or_timed_out_invocation_never_reaches_a_reconciler() -> None:
    for state in (_C.CANCELLED, _C.TIMED_OUT, _C.PROTOCOL_FAILED, _C.FAILED_TO_START):
        with pytest.raises(ReconciliationRuleViolation, match="EXITED"):
            _run(_invocation(_K.RUN, 0, state))
        with pytest.raises(ReconciliationRuleViolation, match="EXITED"):
            _validate(_invocation(_K.VALIDATE, 0, state))
        with pytest.raises(ReconciliationRuleViolation, match="EXITED"):
            _describe(_invocation(_K.DESCRIBE, 0, state))


def test_every_emitted_code_is_a_stage_six_code_and_the_set_is_pinned() -> None:
    emitted = {
        _code(outcome)
        for outcome in (
            *(factory() for factory in _NO_FALSE_SUCCESS.values()),
            *(_run_case(status, exit_value) for status, exit_value in _RUN_MATRIX),
            *(
                _validate_case(outcome, exit_value)
                for outcome, exit_value in _VALIDATE_MATRIX
            ),
            *(
                _describe(_invocation(_K.DESCRIBE, exit_value), MISSING)
                for exit_value in _EXITS
            ),
            _describe(
                output=_describe_parse(
                    _encode(_describe_document(bootstrap_schema_version="2.0.0"))
                )
            ),
            _run_case(_S.SUCCEEDED, 0, observations=()),
            _run_case(_S.SUCCEEDED, 0, event_declarations=()),
            _run(
                output=_manifest_parse(
                    _manifest_document(
                        candidate_artifacts=[
                            {**_DECLARATION, "relative_path": "C:/x.bin"}
                        ]
                    )
                ),
                summary=_EMPTY_SUMMARY,
                observations=(),
            ),
        )
    }
    emitted.discard(None)
    assert emitted == {
        PROTOCOL_STDOUT_CONTAMINATION,
        PROTOCOL_DESCRIBE_OUTPUT_INVALID,
        PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
        PROTOCOL_UNSUPPORTED_VERSION,
        PROTOCOL_VALIDATION_RESULT_INVALID,
        PROTOCOL_ADAPTER_REPORTED_VIOLATION,
        PROTOCOL_MALFORMED_JSONL,
        SCHEMA_REQUEST_INVALID,
        COMPAT_NOT_APPLICABLE,
        COMPAT_LATE_NOT_APPLICABLE,
        ADAPTER_UNAVAILABLE,
        ENGINE_RUNTIME_FAILURE,
        ARTIFACT_RESULT_MANIFEST_INVALID,
        ARTIFACT_PATH_BOUNDARY_VIOLATION,
        ARTIFACT_VALIDATION_FAILED,
        SECURITY_SENSITIVE_MATERIAL_LEAKAGE,
    }
    assert emitted <= set(STAGE6_DIAGNOSTIC_CODES)
