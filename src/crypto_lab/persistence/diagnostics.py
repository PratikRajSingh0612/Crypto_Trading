"""The closed Stage 8 diagnostic table and its ``Failure`` factory.

Plan section 2.5 reading 9 (specification 21.2: "more specific codes may be added
within a category") and section 2.3. ``STAGE8_DIAGNOSTIC_CODES`` maps the four
``PERSISTENCE.*`` codes and ``CORE.INVARIANT_VIOLATION`` to their category and
retry posture; ``persistence_failure`` mints a ``Failure`` carrying exactly one
diagnostic whose identity is a function of its content -- the merged
``DIAGNOSTIC_IDENTITY_V1`` derivation of the Stage 5 and Stage 7 factories, which
excludes ``timestamp_utc`` -- stamped from the injected ``Clock`` and attributed
to ``source_component`` ``persistence`` (plan 6.5). The two codes shared with
Stage 5 are respelled literals, because ``persistence`` may not import
``experiments``; a Task 1 test pins them equal to ``experiments.diagnostics``
exactly as ``process_supervision/diagnostics.py`` is pinned, and the same test
proves the two factories mint the same ``Diagnostic`` for the same inputs. Every
code maps onto an existing ``DiagnosticCategory`` member: the enum is published
inside the frozen ``domain/diagnostic-v1`` schema and does not change.

This module reads no clock (the instant is always the caller's injected
reading), imports no infrastructure root, touches no database and defines no
correlation parameters: a persistence failure describes the storage operation
that refused, never a lifecycle record, so ``experiment_id``, ``run_id`` and
``invocation_id`` stay ``MISSING`` and ``causal_diagnostic_ids`` stays empty.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, cast

from pydantic import JsonValue

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
from crypto_lab.domain.ports import Clock
from crypto_lab.domain.results import Failure

__all__ = [
    "CONCURRENCY_CONFLICT",
    "INVARIANT_VIOLATION",
    "MIGRATION_MISMATCH",
    "PERSISTENCE_SOURCE_COMPONENT",
    "STAGE8_DIAGNOSTIC_CODES",
    "STORAGE_UNAVAILABLE",
    "WRITE_FAILED",
    "Stage8DiagnosticPosture",
    "persistence_failure",
]

#: The two codes shared with Stage 5, respelled because ``persistence`` may not
#: import ``experiments``; a Task 1 test pins them equal to the Stage 5 constants.
CONCURRENCY_CONFLICT: Final = "PERSISTENCE.CONCURRENCY_CONFLICT"
INVARIANT_VIOLATION: Final = "CORE.INVARIANT_VIOLATION"
#: The three codes Stage 8 introduces within the ``PERSISTENCE`` category
#: (reading 9): disk-full, read-only or I/O refusals of a write; a database
#: revision the entry point does not admit; a file that cannot be opened, a
#: PRAGMA that cannot be applied or read back, a failed ``quick_check`` or a
#: foreign ``application_id``.
WRITE_FAILED: Final = "PERSISTENCE.WRITE_FAILED"
MIGRATION_MISMATCH: Final = "PERSISTENCE.MIGRATION_MISMATCH"
STORAGE_UNAVAILABLE: Final = "PERSISTENCE.STORAGE_UNAVAILABLE"
#: Every persistence-minted diagnostic names this component (plan 6.5).
PERSISTENCE_SOURCE_COMPONENT: Final = "persistence"


@dataclass(frozen=True, slots=True)
class Stage8DiagnosticPosture:
    """The category and retry posture reading 9 fixes for one code."""

    category: DiagnosticCategory
    retriable: bool


#: Reading 9, read literally: the closed Stage 8 code table. Only the conflict
#: is retriable (after a reload); the write, migration and storage refusals and
#: the invariant are not.
STAGE8_DIAGNOSTIC_CODES: Final[Mapping[str, Stage8DiagnosticPosture]] = {
    CONCURRENCY_CONFLICT: Stage8DiagnosticPosture(DiagnosticCategory.PERSISTENCE, True),
    WRITE_FAILED: Stage8DiagnosticPosture(DiagnosticCategory.PERSISTENCE, False),
    MIGRATION_MISMATCH: Stage8DiagnosticPosture(DiagnosticCategory.PERSISTENCE, False),
    STORAGE_UNAVAILABLE: Stage8DiagnosticPosture(DiagnosticCategory.PERSISTENCE, False),
    INVARIANT_VIOLATION: Stage8DiagnosticPosture(
        DiagnosticCategory.INTERNAL_INVARIANT, False
    ),
}


def persistence_failure(
    code: str,
    *,
    message: str,
    clock: Clock,
    details: Mapping[str, DiagnosticDetailValue] | None = None,
) -> Failure:
    """A ``Failure`` carrying exactly one Stage 8 diagnostic.

    ``code`` must be a member of ``STAGE8_DIAGNOSTIC_CODES``; the category and
    retry posture come from that table, never from the caller, and the severity
    is always ``ERROR``. ``details`` is inspected with the ``Diagnostic`` detail
    rules (bounds and secret-like keys) before it enters the identity hash; the
    instant read from ``clock`` is excluded from that hash, so identity is a
    function of content alone.
    """
    posture = STAGE8_DIAGNOSTIC_CODES.get(code)
    if posture is None:
        raise ValueError(f"{code!r} is not a Stage 8 code")
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
        "severity": DiagnosticSeverity.ERROR.value,
        "source_component": PERSISTENCE_SOURCE_COMPONENT,
        "message": message,
        "retriable": posture.retriable,
        "details": cast("JsonValue", detail_payload),
        "causal_diagnostic_ids": [],
    }
    identity = _uuid4_shaped(
        profile_hash(HashingProfile.DIAGNOSTIC_IDENTITY_V1, payload),
    )
    diagnostic = Diagnostic.model_validate(
        {
            "schema_version": "1.0.0",
            "diagnostic_id": f"diag_{identity}",
            "severity": DiagnosticSeverity.ERROR,
            "error_code": code,
            "category": posture.category,
            "message": message,
            "source_component": PERSISTENCE_SOURCE_COMPONENT,
            "retriable": posture.retriable,
            "timestamp_utc": clock.now_utc(),
            "details": detail_payload,
            "causal_diagnostic_ids": (),
        }
    )
    return Failure(outcome="FAILURE", diagnostics=(diagnostic,))
