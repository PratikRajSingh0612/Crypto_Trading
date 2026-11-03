"""The closed ``ARTIFACT.*``/``SECURITY.*`` code table and its factory.

Stage 9 plan Task 1 ("Interfaces produced") and plan 4.5 under specification
21.2.1. ``artifacts`` may not import ``adapters`` (plan 2.6), so the four Stage 6
literals this package raises -- ``RESULT_MANIFEST_INVALID``,
``PATH_BOUNDARY_VIOLATION``, ``VALIDATION_FAILED`` and
``SENSITIVE_MATERIAL_LEAKAGE`` -- are re-declared here with the posture of
``adapters/diagnostics.py`` and pinned equal by test, so there is one posture,
not two. Three codes are new: ``FINALIZATION_TIMED_OUT`` (``TIMEOUT``,
``retriable=False``, 21.2.1:1536), ``MOVE_FAILED`` (``PERSISTENCE``,
``retriable=False``: a move failure is a storage failure, not corruption,
reading 26 -- outside the hard-blocking partition so a successor stays possible
through ``RetryPolicy``) and ``QUARANTINE_OVERDUE`` (the 24-hour quarantine age
check of plan 1.6 item 8; declared reading: category ``PERSISTENCE``, severity
``WARNING``, ``retriable=False`` -- an operational retention fact about stored
bytes, neither corruption nor a timeout).

``artifact_diagnostic`` and ``artifact_failure`` mirror the Stage 6 factory:
identity is ``DIAGNOSTIC_IDENTITY_V1`` over the same payload shape excluding the
clock instant, so the same facts recompute the same identity (plan 10 replay
rule) and, for the four shared codes, the same ``Diagnostic`` the Stage 6
factory would build. ``source_component`` is the fixed ``core.artifacts``;
a code outside the table, a ``TIMEOUT`` without an ``invocation_id`` and a run
correlation without an experiment correlation are refused before any hash.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Final, cast

from pydantic import JsonValue
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.domain.diagnostics import (
    Diagnostic,
    DiagnosticCategory,
    DiagnosticSeverity,
)
from crypto_lab.domain.hashing import HashingProfile, _uuid4_shaped, profile_hash
from crypto_lab.domain.identifiers import (
    DiagnosticId,
    ExperimentId,
    InvocationId,
    RunId,
)
from crypto_lab.domain.results import Failure

ARTIFACT_RESULT_MANIFEST_INVALID: Final = "ARTIFACT.RESULT_MANIFEST_INVALID"
ARTIFACT_PATH_BOUNDARY_VIOLATION: Final = "ARTIFACT.PATH_BOUNDARY_VIOLATION"
ARTIFACT_VALIDATION_FAILED: Final = "ARTIFACT.VALIDATION_FAILED"
SECURITY_SENSITIVE_MATERIAL_LEAKAGE: Final = "SECURITY.SENSITIVE_MATERIAL_LEAKAGE"
ARTIFACT_FINALIZATION_TIMED_OUT: Final = "ARTIFACT.FINALIZATION_TIMED_OUT"
ARTIFACT_MOVE_FAILED: Final = "ARTIFACT.MOVE_FAILED"
ARTIFACT_QUARANTINE_OVERDUE: Final = "ARTIFACT.QUARANTINE_OVERDUE"
#: The fixed source component of every artifact-family diagnostic.
ARTIFACT_SOURCE_COMPONENT: Final = "core.artifacts"


@dataclass(frozen=True, slots=True)
class ArtifactDiagnosticPosture:
    """The category, retry posture and severity fixed for one artifact code."""

    category: DiagnosticCategory
    retriable: bool
    severity: DiagnosticSeverity


_D = DiagnosticCategory
_S = DiagnosticSeverity

#: Specification 21.2.1 rows for the artifact family, read literally; the first
#: four equal ``adapters.diagnostics.STAGE6_DIAGNOSTIC_CODES`` (pinned by test).
ARTIFACT_DIAGNOSTIC_CODES: Final[Mapping[str, ArtifactDiagnosticPosture]] = {
    ARTIFACT_RESULT_MANIFEST_INVALID: ArtifactDiagnosticPosture(
        _D.ARTIFACT_CORRUPTION, False, _S.ERROR
    ),
    ARTIFACT_PATH_BOUNDARY_VIOLATION: ArtifactDiagnosticPosture(
        _D.ARTIFACT_CORRUPTION, False, _S.ERROR
    ),
    ARTIFACT_VALIDATION_FAILED: ArtifactDiagnosticPosture(
        _D.ARTIFACT_CORRUPTION, False, _S.ERROR
    ),
    SECURITY_SENSITIVE_MATERIAL_LEAKAGE: ArtifactDiagnosticPosture(
        _D.SECURITY, False, _S.ERROR
    ),
    ARTIFACT_FINALIZATION_TIMED_OUT: ArtifactDiagnosticPosture(
        _D.TIMEOUT, False, _S.ERROR
    ),
    ARTIFACT_MOVE_FAILED: ArtifactDiagnosticPosture(_D.PERSISTENCE, False, _S.ERROR),
    ARTIFACT_QUARANTINE_OVERDUE: ArtifactDiagnosticPosture(
        _D.PERSISTENCE, False, _S.WARNING
    ),
}

#: The categories whose diagnostics require an invocation (``Diagnostic`` rule).
_COMMAND_CATEGORIES: Final[frozenset[DiagnosticCategory]] = frozenset(
    {_D.ENGINE_RUNTIME, _D.PROTOCOL, _D.TIMEOUT, _D.CANCELLATION}
)


def _is_missing(value: object) -> bool:
    return value is MISSING


def artifact_diagnostic(
    code: str,
    *,
    message: str,
    invocation_id: InvocationId | MISSING = MISSING,  # type: ignore[valid-type]
    run_id: RunId | MISSING = MISSING,  # type: ignore[valid-type]
    experiment_id: ExperimentId | MISSING = MISSING,  # type: ignore[valid-type]
    causal_ids: tuple[DiagnosticId, ...] = (),
    now_utc: datetime,
) -> Diagnostic:
    """Build one artifact-family diagnostic whose identity is a function of its
    content; ``now_utc`` is the injected clock instant and never hash material."""
    posture = ARTIFACT_DIAGNOSTIC_CODES.get(code)
    if posture is None:
        raise ValueError(f"{code!r} is not an artifact code")
    if not _is_missing(run_id) and _is_missing(experiment_id):
        raise ValueError("a run correlation requires an experiment correlation")
    if posture.category in _COMMAND_CATEGORIES and _is_missing(invocation_id):
        raise ValueError(f"{code} requires invocation_id")
    if len(set(causal_ids)) != len(causal_ids) or causal_ids != tuple(
        sorted(causal_ids)
    ):
        raise ValueError("causal diagnostic ids must be unique and sorted")
    payload: dict[str, JsonValue] = {
        "schema_version": "1.0.0",
        "error_code": code,
        "category": posture.category.value,
        "severity": posture.severity.value,
        "source_component": ARTIFACT_SOURCE_COMPONENT,
        "message": message,
        "retriable": posture.retriable,
        "details": cast("JsonValue", {}),
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
    payload["causal_diagnostic_ids"] = list(causal_ids)
    identity = _uuid4_shaped(
        profile_hash(HashingProfile.DIAGNOSTIC_IDENTITY_V1, payload)
    )
    return Diagnostic.model_validate(
        {
            "schema_version": "1.0.0",
            "diagnostic_id": f"diag_{identity}",
            "severity": posture.severity,
            "error_code": code,
            "category": posture.category,
            "message": message,
            "source_component": ARTIFACT_SOURCE_COMPONENT,
            "retriable": posture.retriable,
            "timestamp_utc": now_utc,
            "details": {},
            "causal_diagnostic_ids": causal_ids,
            **correlation,
        }
    )


def artifact_failure(
    code: str,
    *,
    message: str,
    invocation_id: InvocationId | MISSING = MISSING,  # type: ignore[valid-type]
    run_id: RunId | MISSING = MISSING,  # type: ignore[valid-type]
    experiment_id: ExperimentId | MISSING = MISSING,  # type: ignore[valid-type]
    causal_ids: tuple[DiagnosticId, ...] = (),
    now_utc: datetime,
) -> Failure:
    """A ``Failure`` carrying exactly one artifact-family diagnostic."""
    return Failure(
        outcome="FAILURE",
        diagnostics=(
            artifact_diagnostic(
                code,
                message=message,
                invocation_id=invocation_id,
                run_id=run_id,
                experiment_id=experiment_id,
                causal_ids=causal_ids,
                now_utc=now_utc,
            ),
        ),
    )


__all__ = (
    "ARTIFACT_DIAGNOSTIC_CODES",
    "ARTIFACT_FINALIZATION_TIMED_OUT",
    "ARTIFACT_MOVE_FAILED",
    "ARTIFACT_PATH_BOUNDARY_VIOLATION",
    "ARTIFACT_QUARANTINE_OVERDUE",
    "ARTIFACT_RESULT_MANIFEST_INVALID",
    "ARTIFACT_SOURCE_COMPONENT",
    "ARTIFACT_VALIDATION_FAILED",
    "SECURITY_SENSITIVE_MATERIAL_LEAKAGE",
    "ArtifactDiagnosticPosture",
    "artifact_diagnostic",
    "artifact_failure",
)
