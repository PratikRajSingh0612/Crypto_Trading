"""The Stage 5 diagnostic factory with content-derived identity.

Plan sections 3.3 and 8.6, under specification section 21. Stage 5 mints
diagnostics only inside ``Failure`` values and persists none (plan 1.4); the six
codes below are the whole Stage 5 vocabulary -- three introduced here and three
reused -- and each maps onto an existing ``DiagnosticCategory`` member, because
the enum is published inside the frozen ``domain/diagnostic-v1`` schema (plan
2.5 constraint 1).

Identity is **derived, not drawn** (plan 3.3): the merged
``HashingProfile.DIAGNOSTIC_IDENTITY_V1`` content derivation of the Stage 4
factories (``capabilities/policy.py`` and the ``strategy`` modules) is reused,
extended with the correlation identifiers a Stage 5 diagnostic carries
(``experiment_id``, ``run_id``, ``invocation_id`` when present) and the causal
identifiers, and excluding ``timestamp_utc``, so identity stays a function of
content alone. The instant comes from the operation's injected ``Clock``; this
module reads no clock, draws no random value and touches no repository.

Task-local readings, declared here: every Stage 5 failure diagnostic has severity
``ERROR``; ``source_component`` is a required ``NormalizedIdentifier`` naming the
emitting service or double; ``PROCESS.UNRECOGNIZED_PROCESS_EXIT`` is in the table
for completeness -- Stage 5 reads it through ``DiagnosticReader`` (plan 6) and a
Stage 7 supervisor mints it -- and, like every ``ENGINE_RUNTIME`` diagnostic, it
requires ``invocation_id`` (``Diagnostic``'s own validator enforces that).
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
    DiagnosticDetailValue,
    DiagnosticSeverity,
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

#: Plan section 8.6: the three reused codes ...
CONCURRENCY_CONFLICT: Final = "PERSISTENCE.CONCURRENCY_CONFLICT"
INVARIANT_VIOLATION: Final = "CORE.INVARIANT_VIOLATION"
IMMUTABLE_INPUT_MISMATCH: Final = "CORE.IMMUTABLE_INPUT_MISMATCH"
#: ... and the three Stage 5 introduces.
RETRY_DECISION_CONFLICT: Final = "RETRY.DECISION_CONFLICT"
RETRY_NOT_BEFORE_NOT_REACHED: Final = "RETRY.NOT_BEFORE_NOT_REACHED"
UNRECOGNIZED_PROCESS_EXIT: Final = "PROCESS.UNRECOGNIZED_PROCESS_EXIT"


@dataclass(frozen=True, slots=True)
class DiagnosticPosture:
    """The category and retry posture plan section 8.6 fixes for one code."""

    category: DiagnosticCategory
    retriable: bool


#: Plan section 8.6, read literally: the closed Stage 5 code table.
STAGE5_DIAGNOSTIC_CODES: Final[Mapping[str, DiagnosticPosture]] = {
    CONCURRENCY_CONFLICT: DiagnosticPosture(DiagnosticCategory.PERSISTENCE, True),
    INVARIANT_VIOLATION: DiagnosticPosture(
        DiagnosticCategory.INTERNAL_INVARIANT, False
    ),
    IMMUTABLE_INPUT_MISMATCH: DiagnosticPosture(
        DiagnosticCategory.INTERNAL_INVARIANT, False
    ),
    RETRY_DECISION_CONFLICT: DiagnosticPosture(
        DiagnosticCategory.INTERNAL_INVARIANT, False
    ),
    RETRY_NOT_BEFORE_NOT_REACHED: DiagnosticPosture(
        DiagnosticCategory.PERSISTENCE, True
    ),
    UNRECOGNIZED_PROCESS_EXIT: DiagnosticPosture(
        DiagnosticCategory.ENGINE_RUNTIME, True
    ),
}


def _is_missing(value: object) -> bool:
    return value is MISSING


def stage5_diagnostic(
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
    """Build one Stage 5 diagnostic whose identity is a function of its content.

    ``code`` must be a member of ``STAGE5_DIAGNOSTIC_CODES``; the category and
    retry posture come from that table, never from the caller. ``timestamp_utc``
    is the operation's clock instant and is excluded from the identity payload.
    Two ``Diagnostic`` rules are checked up front so a caller learns them by
    name: ``run_id`` may be supplied only together with ``experiment_id``, and an
    ``ENGINE_RUNTIME`` code requires ``invocation_id``.
    """
    posture = STAGE5_DIAGNOSTIC_CODES.get(code)
    if posture is None:
        raise ValueError(f"{code!r} is not a Stage 5 code")
    if not _is_missing(run_id) and _is_missing(experiment_id):
        raise ValueError("a run correlation requires an experiment correlation")
    if posture.category is DiagnosticCategory.ENGINE_RUNTIME and _is_missing(
        invocation_id
    ):
        raise ValueError(f"{code} requires invocation_id")
    detail_payload: dict[str, DiagnosticDetailValue] = dict(details or {})
    payload: dict[str, JsonValue] = {
        "schema_version": "1.0.0",
        "error_code": code,
        "category": posture.category.value,
        "severity": DiagnosticSeverity.ERROR.value,
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
            "severity": DiagnosticSeverity.ERROR,
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


def stage5_failure(
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
    """A ``Failure`` carrying exactly one Stage 5 diagnostic."""
    return Failure(
        outcome="FAILURE",
        diagnostics=(
            stage5_diagnostic(
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
