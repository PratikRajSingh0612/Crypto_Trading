"""The closed Stage 7 diagnostic table and factory (Stage 7 plan section 3.5).

``STAGE7_DIAGNOSTIC_CODES`` maps each of the thirteen Stage 7 codes to its
category, retry posture and severity; every code maps onto an existing
``DiagnosticCategory`` member because the enum is published inside the frozen
``domain/diagnostic-v1`` schema, and the hard-block column restates the Stage 5
retry partition of ``domain/retry.py``. The table never repeats a Stage 6 code (the
merged codes Stage 7 mints go through ``stage6_diagnostic``) and meets the Stage 5
table in exactly the three core literals, which are respelled here because this
package may not import ``experiments``; the two factories produce the same
``Diagnostic`` for the same inputs.

``stage7_diagnostic`` and ``stage7_failure`` mirror the Stage 6 factory line for
line, with the same check order: table lookup; ``run_id`` requires
``experiment_id``; every ``PROCESS.*`` code except ``PROCESS.PATH_PREFLIGHT_REJECTED``
-- a ``Failure``-only code, never a persisted primary, whose ``invocation_id`` is
accepted missing only for the long-path probe of plan 7.2, the one minting site
with no invocation -- requires ``invocation_id`` unconditionally, and the three core
literals follow the Stage 5 category rule; ``_inspect_details`` and the node and
byte bounds before any hash; the identical ``DIAGNOSTIC_IDENTITY_V1`` payload, so
identity excludes ``timestamp_utc`` and is a function of content alone. Severity
comes from the table, never from the caller. This module reads no clock: the
instant is always the caller's injected reading.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Final, cast

from pydantic import JsonValue
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.adapters.diagnostics import STAGE6_DIAGNOSTIC_CODES
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

__all__ = [
    "CORE_IMMUTABLE_INPUT_MISMATCH",
    "CORE_INVARIANT_VIOLATION",
    "PERSISTENCE_CONCURRENCY_CONFLICT",
    "PROCESS_CLEANUP_FAILED",
    "PROCESS_FORCED_TERMINATION",
    "PROCESS_GRACEFUL_INTERRUPT_UNAVAILABLE",
    "PROCESS_JOB_OBJECT_UNAVAILABLE",
    "PROCESS_LAUNCH_FAILED",
    "PROCESS_LAUNCH_NOT_COMMITTED",
    "PROCESS_ORCHESTRATOR_RESTART_LOST_SUPERVISION",
    "PROCESS_PATH_PREFLIGHT_REJECTED",
    "PROCESS_PID_REUSE_DETECTED",
    "PROCESS_WRITE_BOUNDARY_VIOLATION",
    "STAGE7_DIAGNOSTIC_CODES",
    "Stage7DiagnosticPosture",
    "stage7_diagnostic",
    "stage7_failure",
]

PROCESS_LAUNCH_FAILED: Final = "PROCESS.LAUNCH_FAILED"
PROCESS_LAUNCH_NOT_COMMITTED: Final = "PROCESS.LAUNCH_NOT_COMMITTED"
PROCESS_PATH_PREFLIGHT_REJECTED: Final = "PROCESS.PATH_PREFLIGHT_REJECTED"
PROCESS_GRACEFUL_INTERRUPT_UNAVAILABLE: Final = "PROCESS.GRACEFUL_INTERRUPT_UNAVAILABLE"
PROCESS_JOB_OBJECT_UNAVAILABLE: Final = "PROCESS.JOB_OBJECT_UNAVAILABLE"
PROCESS_FORCED_TERMINATION: Final = "PROCESS.FORCED_TERMINATION"
PROCESS_CLEANUP_FAILED: Final = "PROCESS.CLEANUP_FAILED"
PROCESS_PID_REUSE_DETECTED: Final = "PROCESS.PID_REUSE_DETECTED"
PROCESS_ORCHESTRATOR_RESTART_LOST_SUPERVISION: Final = (
    "PROCESS.ORCHESTRATOR_RESTART_LOST_SUPERVISION"
)
PROCESS_WRITE_BOUNDARY_VIOLATION: Final = "PROCESS.WRITE_BOUNDARY_VIOLATION"
#: The three core literals of ``experiments.diagnostics``, respelled because this
#: package may not import ``experiments``; a test pins them equal.
CORE_INVARIANT_VIOLATION: Final = "CORE.INVARIANT_VIOLATION"
CORE_IMMUTABLE_INPUT_MISMATCH: Final = "CORE.IMMUTABLE_INPUT_MISMATCH"
PERSISTENCE_CONCURRENCY_CONFLICT: Final = "PERSISTENCE.CONCURRENCY_CONFLICT"


@dataclass(frozen=True, slots=True)
class Stage7DiagnosticPosture:
    """The category, retry posture and severity plan section 3.5 fixes for one code."""

    category: DiagnosticCategory
    retriable: bool
    severity: DiagnosticSeverity


_D = DiagnosticCategory
_S = DiagnosticSeverity

#: Plan section 3.5, read literally: the closed Stage 7 code table.
STAGE7_DIAGNOSTIC_CODES: Final[Mapping[str, Stage7DiagnosticPosture]] = {
    PROCESS_LAUNCH_FAILED: Stage7DiagnosticPosture(_D.ENGINE_RUNTIME, True, _S.ERROR),
    PROCESS_LAUNCH_NOT_COMMITTED: Stage7DiagnosticPosture(
        _D.ENGINE_RUNTIME, True, _S.ERROR
    ),
    PROCESS_PATH_PREFLIGHT_REJECTED: Stage7DiagnosticPosture(
        _D.USER_CONFIGURATION, False, _S.ERROR
    ),
    PROCESS_GRACEFUL_INTERRUPT_UNAVAILABLE: Stage7DiagnosticPosture(
        _D.ENGINE_RUNTIME, True, _S.WARNING
    ),
    PROCESS_JOB_OBJECT_UNAVAILABLE: Stage7DiagnosticPosture(
        _D.ENGINE_RUNTIME, True, _S.WARNING
    ),
    PROCESS_FORCED_TERMINATION: Stage7DiagnosticPosture(
        _D.ENGINE_RUNTIME, True, _S.WARNING
    ),
    PROCESS_CLEANUP_FAILED: Stage7DiagnosticPosture(_D.ENGINE_RUNTIME, True, _S.ERROR),
    PROCESS_PID_REUSE_DETECTED: Stage7DiagnosticPosture(
        _D.ENGINE_RUNTIME, True, _S.WARNING
    ),
    PROCESS_ORCHESTRATOR_RESTART_LOST_SUPERVISION: Stage7DiagnosticPosture(
        _D.ENGINE_RUNTIME, True, _S.ERROR
    ),
    PROCESS_WRITE_BOUNDARY_VIOLATION: Stage7DiagnosticPosture(
        _D.ENGINE_RUNTIME, True, _S.WARNING
    ),
    CORE_INVARIANT_VIOLATION: Stage7DiagnosticPosture(
        _D.INTERNAL_INVARIANT, False, _S.ERROR
    ),
    CORE_IMMUTABLE_INPUT_MISMATCH: Stage7DiagnosticPosture(
        _D.INTERNAL_INVARIANT, False, _S.ERROR
    ),
    PERSISTENCE_CONCURRENCY_CONFLICT: Stage7DiagnosticPosture(
        _D.PERSISTENCE, True, _S.ERROR
    ),
}

#: Plan 3.5: the Stage 7 table never repeats a Stage 6 code.
_STAGE6_OVERLAP: Final[frozenset[str]] = frozenset(STAGE7_DIAGNOSTIC_CODES) & frozenset(
    STAGE6_DIAGNOSTIC_CODES
)
if _STAGE6_OVERLAP:  # pragma: no cover - the two closed tables are disjoint
    raise ValueError("the Stage 7 diagnostic table repeats a Stage 6 code")

#: Plan 3.5: every ``PROCESS.*`` row but the preflight rejection requires an
#: invocation unconditionally.
_INVOCATION_REQUIRED_CODES: Final[frozenset[str]] = frozenset(
    code
    for code in STAGE7_DIAGNOSTIC_CODES
    if code.startswith("PROCESS.") and code != PROCESS_PATH_PREFLIGHT_REJECTED
)
#: The four categories whose diagnostics require an invocation (``Diagnostic``
#: rule, specification 21.1); the Stage 5 category rule the core literals follow.
_COMMAND_CATEGORIES: Final[frozenset[DiagnosticCategory]] = frozenset(
    {_D.ENGINE_RUNTIME, _D.PROTOCOL, _D.TIMEOUT, _D.CANCELLATION}
)


def _is_missing(value: object) -> bool:
    return value is MISSING


def stage7_diagnostic(
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
    """Build one Stage 7 diagnostic whose identity is a function of its content.

    ``code`` must be a member of ``STAGE7_DIAGNOSTIC_CODES``; category, retry
    posture and severity come from that table, never from the caller.
    ``timestamp_utc`` is the caller's injected-clock instant and is excluded from
    the identity payload. ``details`` is inspected with the ``Diagnostic`` detail
    rules (bounds and secret-like keys) before it enters the hash. Callers pass
    ``causal_diagnostic_ids`` sorted and unique.
    """
    posture = STAGE7_DIAGNOSTIC_CODES.get(code)
    if posture is None:
        raise ValueError(f"{code!r} is not a Stage 7 code")
    if not _is_missing(run_id) and _is_missing(experiment_id):
        raise ValueError("a run correlation requires an experiment correlation")
    if (
        code in _INVOCATION_REQUIRED_CODES or posture.category in _COMMAND_CATEGORIES
    ) and _is_missing(invocation_id):
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


def stage7_failure(
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
    """A ``Failure`` carrying exactly one Stage 7 diagnostic."""
    return Failure(
        outcome="FAILURE",
        diagnostics=(
            stage7_diagnostic(
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
