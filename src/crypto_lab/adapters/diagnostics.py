"""The closed Stage 6 diagnostic table and factory (Stage 6 plan section 9.4).

``STAGE6_DIAGNOSTIC_CODES`` maps each of the twenty-five Stage 6 codes to its
category, retry posture and severity; the category choices resolve the dual
rows of specification 21.2.1 toward the retry posture each row states, and
every code maps onto an existing ``DiagnosticCategory`` member because the
enum is published inside the frozen ``domain/diagnostic-v1`` schema (plan 2.4).
``CORE.*``, ``PERSISTENCE.*`` and ``RETRY.*`` stay Stage 5 codes minted only
through the Stage 5 factory; ``PROCESS.UNRECOGNIZED_PROCESS_EXIT`` appears in
both tables with an identical posture, so the harness can mint the diagnostic
Stage 5's ``EXITED`` transition demands, and the two factories produce the same
``Diagnostic`` for the same inputs. ``COMPAT.LATE_NOT_APPLICABLE`` is the merged
``REASON_LATE_NOT_APPLICABLE`` object of ``domain/aggregation.py``, imported
rather than respelled.

``stage6_diagnostic`` and ``stage6_failure`` mirror the Stage 5 factory
(``experiments/diagnostics.py``, which ``adapters`` may not import): identity is
derived with ``DIAGNOSTIC_IDENTITY_V1`` over the same payload shape, excluding
``timestamp_utc``, so a re-issue over the same reconciliation inputs recomputes
the same identities (plan section 10 replay rule). A code outside the table,
a run correlation without an experiment correlation, a command-category code
(``ENGINE_RUNTIME``, ``PROTOCOL``, ``TIMEOUT``, ``CANCELLATION``) without an
``invocation_id``, and ``details`` the ``Diagnostic`` validator would reject
are refused before any hash is computed. Severity comes from the table, never
from the caller: ``PROCESS.STDERR_TRUNCATED`` and ``PROCESS.MISSING_HEARTBEAT``
are warnings, everything else is an error.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Final, cast

from pydantic import JsonValue
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.domain.aggregation import REASON_LATE_NOT_APPLICABLE
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.diagnostics import (
    MAX_DETAIL_BYTES,
    MAX_DETAIL_NODES,
    Diagnostic,
    DiagnosticCategory,
    DiagnosticDetailValue,
    DiagnosticSeverity,
    _inspect_details,
)
from crypto_lab.domain.hashing import HashingProfile, _uuid4_shaped, profile_hash
from crypto_lab.domain.identifiers import (
    DiagnosticId,
    ExperimentId,
    InvocationId,
    NormalizedIdentifier,
    RunId,
)
from crypto_lab.domain.results import Failure

PROTOCOL_STDOUT_CONTAMINATION: Final = "PROTOCOL.STDOUT_CONTAMINATION"
PROTOCOL_MALFORMED_JSONL: Final = "PROTOCOL.MALFORMED_JSONL"
PROTOCOL_EVENT_TOO_LARGE: Final = "PROTOCOL.EVENT_TOO_LARGE"
PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION: Final = (
    "PROTOCOL.IDENTITY_OR_SEQUENCE_VIOLATION"
)
PROTOCOL_UNSUPPORTED_VERSION: Final = "PROTOCOL.UNSUPPORTED_VERSION"
PROTOCOL_ADAPTER_REPORTED_VIOLATION: Final = "PROTOCOL.ADAPTER_REPORTED_VIOLATION"
PROTOCOL_VALIDATION_RESULT_INVALID: Final = "PROTOCOL.VALIDATION_RESULT_INVALID"
PROTOCOL_DESCRIBE_OUTPUT_INVALID: Final = "PROTOCOL.DESCRIBE_OUTPUT_INVALID"
SCHEMA_REQUEST_INVALID: Final = "SCHEMA.REQUEST_INVALID"
COMPAT_NOT_APPLICABLE: Final = "COMPAT.NOT_APPLICABLE"
#: The merged aggregation reason object, imported rather than respelled.
COMPAT_LATE_NOT_APPLICABLE: Final = REASON_LATE_NOT_APPLICABLE
ADAPTER_UNAVAILABLE: Final = "ADAPTER.UNAVAILABLE"
ENGINE_RUNTIME_FAILURE: Final = "ENGINE.RUNTIME_FAILURE"
PROCESS_UNRECOGNIZED_PROCESS_EXIT: Final = "PROCESS.UNRECOGNIZED_PROCESS_EXIT"
PROCESS_STDERR_TRUNCATED: Final = "PROCESS.STDERR_TRUNCATED"
PROCESS_MISSING_HEARTBEAT: Final = "PROCESS.MISSING_HEARTBEAT"
PROCESS_DESCRIBE_TIMED_OUT: Final = "PROCESS.DESCRIBE_TIMED_OUT"
PROCESS_VALIDATE_TIMED_OUT: Final = "PROCESS.VALIDATE_TIMED_OUT"
PROCESS_START_TIMED_OUT: Final = "PROCESS.START_TIMED_OUT"
PROCESS_RUN_TIMED_OUT: Final = "PROCESS.RUN_TIMED_OUT"
PROCESS_CANCELLED: Final = "PROCESS.CANCELLED"
ARTIFACT_RESULT_MANIFEST_INVALID: Final = "ARTIFACT.RESULT_MANIFEST_INVALID"
ARTIFACT_PATH_BOUNDARY_VIOLATION: Final = "ARTIFACT.PATH_BOUNDARY_VIOLATION"
ARTIFACT_VALIDATION_FAILED: Final = "ARTIFACT.VALIDATION_FAILED"
SECURITY_SENSITIVE_MATERIAL_LEAKAGE: Final = "SECURITY.SENSITIVE_MATERIAL_LEAKAGE"


@dataclass(frozen=True, slots=True)
class Stage6DiagnosticPosture:
    """The category, retry posture and severity plan section 9.4 fixes for one code."""

    category: DiagnosticCategory
    retriable: bool
    severity: DiagnosticSeverity


_D = DiagnosticCategory
_S = DiagnosticSeverity

#: Plan section 9.4, read literally: the closed Stage 6 code table.
STAGE6_DIAGNOSTIC_CODES: Final[Mapping[str, Stage6DiagnosticPosture]] = {
    PROTOCOL_STDOUT_CONTAMINATION: Stage6DiagnosticPosture(
        _D.PROTOCOL, False, _S.ERROR
    ),
    PROTOCOL_MALFORMED_JSONL: Stage6DiagnosticPosture(_D.PROTOCOL, False, _S.ERROR),
    PROTOCOL_EVENT_TOO_LARGE: Stage6DiagnosticPosture(_D.PROTOCOL, False, _S.ERROR),
    PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION: Stage6DiagnosticPosture(
        _D.PROTOCOL, False, _S.ERROR
    ),
    PROTOCOL_UNSUPPORTED_VERSION: Stage6DiagnosticPosture(_D.PROTOCOL, False, _S.ERROR),
    PROTOCOL_ADAPTER_REPORTED_VIOLATION: Stage6DiagnosticPosture(
        _D.PROTOCOL, False, _S.ERROR
    ),
    PROTOCOL_VALIDATION_RESULT_INVALID: Stage6DiagnosticPosture(
        _D.PROTOCOL, False, _S.ERROR
    ),
    PROTOCOL_DESCRIBE_OUTPUT_INVALID: Stage6DiagnosticPosture(
        _D.PROTOCOL, False, _S.ERROR
    ),
    SCHEMA_REQUEST_INVALID: Stage6DiagnosticPosture(
        _D.SCHEMA_VALIDATION, False, _S.ERROR
    ),
    COMPAT_NOT_APPLICABLE: Stage6DiagnosticPosture(_D.COMPATIBILITY, False, _S.ERROR),
    COMPAT_LATE_NOT_APPLICABLE: Stage6DiagnosticPosture(
        _D.COMPATIBILITY, False, _S.ERROR
    ),
    ADAPTER_UNAVAILABLE: Stage6DiagnosticPosture(
        _D.ADAPTER_UNAVAILABILITY, True, _S.ERROR
    ),
    ENGINE_RUNTIME_FAILURE: Stage6DiagnosticPosture(_D.ENGINE_RUNTIME, True, _S.ERROR),
    PROCESS_UNRECOGNIZED_PROCESS_EXIT: Stage6DiagnosticPosture(
        _D.ENGINE_RUNTIME, True, _S.ERROR
    ),
    PROCESS_STDERR_TRUNCATED: Stage6DiagnosticPosture(
        _D.ENGINE_RUNTIME, True, _S.WARNING
    ),
    PROCESS_MISSING_HEARTBEAT: Stage6DiagnosticPosture(_D.TIMEOUT, True, _S.WARNING),
    PROCESS_DESCRIBE_TIMED_OUT: Stage6DiagnosticPosture(_D.TIMEOUT, False, _S.ERROR),
    PROCESS_VALIDATE_TIMED_OUT: Stage6DiagnosticPosture(_D.TIMEOUT, True, _S.ERROR),
    PROCESS_START_TIMED_OUT: Stage6DiagnosticPosture(_D.TIMEOUT, True, _S.ERROR),
    PROCESS_RUN_TIMED_OUT: Stage6DiagnosticPosture(_D.TIMEOUT, True, _S.ERROR),
    PROCESS_CANCELLED: Stage6DiagnosticPosture(_D.CANCELLATION, False, _S.ERROR),
    ARTIFACT_RESULT_MANIFEST_INVALID: Stage6DiagnosticPosture(
        _D.ARTIFACT_CORRUPTION, False, _S.ERROR
    ),
    ARTIFACT_PATH_BOUNDARY_VIOLATION: Stage6DiagnosticPosture(
        _D.ARTIFACT_CORRUPTION, False, _S.ERROR
    ),
    ARTIFACT_VALIDATION_FAILED: Stage6DiagnosticPosture(
        _D.ARTIFACT_CORRUPTION, False, _S.ERROR
    ),
    SECURITY_SENSITIVE_MATERIAL_LEAKAGE: Stage6DiagnosticPosture(
        _D.SECURITY, False, _S.ERROR
    ),
}

#: The four categories whose diagnostics require an invocation (``Diagnostic``
#: rule, specification 21.1), checked here by name before hashing.
_COMMAND_CATEGORIES: Final[frozenset[DiagnosticCategory]] = frozenset(
    {_D.ENGINE_RUNTIME, _D.PROTOCOL, _D.TIMEOUT, _D.CANCELLATION}
)


def _is_missing(value: object) -> bool:
    return value is MISSING


def stage6_diagnostic(
    code: str,
    message: str,
    *,
    source_component: NormalizedIdentifier,
    timestamp_utc: datetime,
    experiment_id: ExperimentId | MISSING = MISSING,  # type: ignore[valid-type]
    run_id: RunId | MISSING = MISSING,  # type: ignore[valid-type]
    invocation_id: InvocationId | MISSING = MISSING,  # type: ignore[valid-type]
    details: Mapping[str, DiagnosticDetailValue] | None = None,
    causal_diagnostic_ids: tuple[DiagnosticId, ...] = (),
) -> Diagnostic:
    """Build one Stage 6 diagnostic whose identity is a function of its content.

    ``code`` must be a member of ``STAGE6_DIAGNOSTIC_CODES``; category, retry
    posture and severity come from that table, never from the caller.
    ``timestamp_utc`` is the caller's injected-clock instant and is excluded
    from the identity payload. ``details`` is inspected with the ``Diagnostic``
    detail rules (bounds and secret-like keys) before it enters the hash.
    """
    posture = STAGE6_DIAGNOSTIC_CODES.get(code)
    if posture is None:
        raise ValueError(f"{code!r} is not a Stage 6 code")
    if not _is_missing(run_id) and _is_missing(experiment_id):
        raise ValueError("a run correlation requires an experiment correlation")
    if posture.category in _COMMAND_CATEGORIES and _is_missing(invocation_id):
        raise ValueError(f"{code} requires invocation_id")
    detail_payload: dict[str, DiagnosticDetailValue] = dict(details or {})
    nodes = _inspect_details(detail_payload)
    if nodes > MAX_DETAIL_NODES:
        raise ValueError("diagnostic details contain too many nodes")
    if len(canonical_json_bytes(detail_payload)) > MAX_DETAIL_BYTES:
        raise ValueError("diagnostic details exceed maximum encoded bytes")
    payload: dict[str, JsonValue] = {
        "schema_version": "1.0.0",
        "error_code": code,
        "category": posture.category.value,
        "severity": posture.severity.value,
        "source_component": source_component,
        "message": message,
        "retriable": posture.retriable,
        "details": cast("JsonValue", detail_payload),
    }
    correlation: dict[str, object] = {}
    if not _is_missing(experiment_id):
        payload["experiment_id"] = experiment_id
        correlation["experiment_id"] = experiment_id
    if not _is_missing(run_id):
        payload["run_id"] = run_id
        correlation["run_id"] = run_id
    if not _is_missing(invocation_id):
        payload["invocation_id"] = invocation_id
        correlation["invocation_id"] = invocation_id
    payload["causal_diagnostic_ids"] = list(causal_diagnostic_ids)
    identity = _uuid4_shaped(
        profile_hash(HashingProfile.DIAGNOSTIC_IDENTITY_V1, payload),
    )
    return Diagnostic.model_validate(
        {
            "schema_version": "1.0.0",
            "diagnostic_id": f"diag_{identity}",
            "severity": posture.severity,
            "error_code": code,
            "category": posture.category,
            "message": message,
            "source_component": source_component,
            "retriable": posture.retriable,
            "timestamp_utc": timestamp_utc,
            "details": detail_payload,
            "causal_diagnostic_ids": causal_diagnostic_ids,
            **correlation,
        }
    )


def stage6_failure(
    code: str,
    message: str,
    *,
    source_component: NormalizedIdentifier,
    timestamp_utc: datetime,
    experiment_id: ExperimentId | MISSING = MISSING,  # type: ignore[valid-type]
    run_id: RunId | MISSING = MISSING,  # type: ignore[valid-type]
    invocation_id: InvocationId | MISSING = MISSING,  # type: ignore[valid-type]
    details: Mapping[str, DiagnosticDetailValue] | None = None,
    causal_diagnostic_ids: tuple[DiagnosticId, ...] = (),
) -> Failure:
    """A ``Failure`` carrying exactly one Stage 6 diagnostic."""
    return Failure(
        outcome="FAILURE",
        diagnostics=(
            stage6_diagnostic(
                code,
                message,
                source_component=source_component,
                timestamp_utc=timestamp_utc,
                experiment_id=experiment_id,
                run_id=run_id,
                invocation_id=invocation_id,
                details=details,
                causal_diagnostic_ids=causal_diagnostic_ids,
            ),
        ),
    )
