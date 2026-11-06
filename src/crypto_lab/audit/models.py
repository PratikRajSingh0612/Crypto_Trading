"""Audit event, actor and log record contracts.

Stage 9 plan sections 3.1 and 3.2 under specification 11.3:586, 30.1 and
30.3. Placement follows plan 2.3: the records live in ``crypto_lab.audit`` and
import ``domain`` alone (specification 27.1).

- ``AuditAction`` is the closed set of 25 Stage 9 actions, ``AuditOutcome`` the
  three outcomes and ``LogSeverity`` the five severities of plan 3.2.
- ``AuditActor`` is ``LOCAL_USER``, ``CORE`` or a named adapter identity: the
  ``ADAPTER`` kind carries both adapter fields and the other two carry neither.
- ``AuditEvent`` is the append-only record of one meaningful core action. It
  has no ordering field: ordering is the audit identifier sequence the sink
  assigns (plan reading 9, specification 30.2). The actions tied to one command
  invocation -- the run's terminal and manifest writes driven by the run
  command's exit facts, the two stderr facts, the RESULT finalization timeout
  (EVIDENCE journals carry no deadline, reading 13) -- require
  ``invocation_id``; the other nineteen act on candidates, journals, owners and
  quarantine entries that may have no invocation at all. ``details_hash`` is
  the ``AUDIT_EVENT_DETAILS_V1`` profile over ``details``, recomputed on every
  validation, and ``details`` is a ``BoundedDetails``: the Stage 3 detail
  ceilings and the redaction fixed point.
- ``LogRecord`` is the versioned JSON Lines record of specification 30.1 with
  the same bounded, redaction-fixed ``details`` and a ``message`` that carries no
  token-shaped run.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import ClassVar, Final, Literal, Self, cast

from pydantic import ConfigDict, JsonValue, model_validator
from pydantic.experimental.missing_sentinel import MISSING
from pydantic.json_schema import JsonSchemaValue

from crypto_lab.audit.redaction import BoundedDetails, contains_token_shape
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.diagnostics import (
    BoundedMessage,
    DiagnosticDetailValue,
    ErrorCode,
)
from crypto_lab.domain.hashing import HashingProfile, profile_hash
from crypto_lab.domain.identifiers import (
    ArtifactId,
    AuditEventId,
    CorrelationId,
    ExperimentId,
    InvocationId,
    NormalizedIdentifier,
    RunId,
    Sha256,
)
from crypto_lab.domain.time import CalendarValidUtcDateTime
from crypto_lab.domain.versioning import SemanticVersion

# --- Vocabulary (plan 3.2) -----------------------------------------------------------


class AuditAction(StrEnum):
    ARTIFACT_CANDIDATE_REGISTERED = "ARTIFACT_CANDIDATE_REGISTERED"
    ARTIFACT_VALIDATED = "ARTIFACT_VALIDATED"
    ARTIFACT_VALIDATION_FAILED = "ARTIFACT_VALIDATION_FAILED"
    ARTIFACT_OWNER_PURPOSE_SELECTED = "ARTIFACT_OWNER_PURPOSE_SELECTED"
    FINALIZATION_LEASE_ACQUIRED = "FINALIZATION_LEASE_ACQUIRED"
    FINALIZATION_LEASE_REFUSED = "FINALIZATION_LEASE_REFUSED"
    FINALIZATION_PREPARED = "FINALIZATION_PREPARED"
    FINALIZATION_MOVED = "FINALIZATION_MOVED"
    FINALIZATION_REGISTERED = "FINALIZATION_REGISTERED"
    FINALIZATION_REPLAYED = "FINALIZATION_REPLAYED"
    FINALIZATION_ABANDONED = "FINALIZATION_ABANDONED"
    FINALIZATION_TIMED_OUT = "FINALIZATION_TIMED_OUT"
    ARTIFACT_QUARANTINED = "ARTIFACT_QUARANTINED"
    ARTIFACT_CORRUPT = "ARTIFACT_CORRUPT"
    ARTIFACT_LEAKAGE_DETECTED = "ARTIFACT_LEAKAGE_DETECTED"
    RUN_SUCCEEDED = "RUN_SUCCEEDED"
    RUN_FAILED = "RUN_FAILED"
    RUN_MANIFEST_REGISTERED = "RUN_MANIFEST_REGISTERED"
    STDERR_TRUNCATED = "STDERR_TRUNCATED"
    STDERR_EVIDENCE_LINKED = "STDERR_EVIDENCE_LINKED"
    RECONCILIATION_FINALIZATION_RESUMED = "RECONCILIATION_FINALIZATION_RESUMED"
    RECONCILIATION_CANDIDATE_QUARANTINED = "RECONCILIATION_CANDIDATE_QUARANTINED"
    RECONCILIATION_ORPHAN_QUARANTINED = "RECONCILIATION_ORPHAN_QUARANTINED"
    RETENTION_DELETED = "RETENTION_DELETED"
    QUARANTINE_OVERDUE = "QUARANTINE_OVERDUE"


class AuditOutcome(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    REFUSED = "REFUSED"
    FAILED = "FAILED"


class LogSeverity(StrEnum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


type AuditActorKind = Literal["LOCAL_USER", "CORE", "ADAPTER"]

#: Specification 11.3:586 by name: the actions tied to one command invocation.
INVOCATION_REQUIRED_ACTIONS: Final[frozenset[AuditAction]] = frozenset(
    {
        AuditAction.RUN_SUCCEEDED,
        AuditAction.RUN_FAILED,
        AuditAction.RUN_MANIFEST_REGISTERED,
        AuditAction.STDERR_TRUNCATED,
        AuditAction.STDERR_EVIDENCE_LINKED,
        AuditAction.FINALIZATION_TIMED_OUT,
    }
)


def _is_missing(value: object) -> bool:
    return value is MISSING


# --- The actor (plan 3.1, nested) ----------------------------------------------------


class AuditActor(CanonicalModel):
    """``LOCAL_USER``, ``CORE`` or a named adapter identity."""

    kind: AuditActorKind
    adapter_name: NormalizedIdentifier | MISSING = MISSING  # type: ignore[valid-type]
    adapter_version: SemanticVersion | MISSING = MISSING  # type: ignore[valid-type]

    @model_validator(mode="after")
    def validate_adapter_identity(self) -> Self:
        named = not _is_missing(self.adapter_name)
        versioned = not _is_missing(self.adapter_version)
        if self.kind == "ADAPTER":
            if not (named and versioned):
                raise ValueError(
                    "an ADAPTER actor requires adapter_name and adapter_version"
                )
        elif named or versioned:
            raise ValueError(f"a {self.kind} actor names no adapter")
        return self


CORE_ACTOR: Final = AuditActor(kind="CORE")
LOCAL_USER_ACTOR: Final = AuditActor(kind="LOCAL_USER")


# --- The event (plan 3.1) -------------------------------------------------------------


def audit_details_hash(details: Mapping[str, DiagnosticDetailValue]) -> Sha256:
    """``AUDIT_EVENT_DETAILS_V1`` over an event's details (key order is not hash
    material: the envelope is canonical JSON)."""
    payload = cast("dict[str, JsonValue]", dict(details))
    return profile_hash(HashingProfile.AUDIT_EVENT_DETAILS_V1, payload)


def _audit_event_schema_extra(schema: JsonSchemaValue) -> None:
    schema["allOf"] = [
        {
            "if": {
                "properties": {
                    "action": {
                        "enum": sorted(
                            action.value for action in INVOCATION_REQUIRED_ACTIONS
                        )
                    }
                },
                "required": ["action"],
            },
            "then": {"required": ["invocation_id"]},
        }
    ]


class AuditEvent(CanonicalModel):
    """Specification 11.3:586: the append-only record of a meaningful core action.

    Immutable, bounded, free of raw tokens and secrets by the ``BoundedDetails``
    fixed point, and without an ordering field (ordering is the sink's audit
    sequence, specification 30.2).
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_audit_event_schema_extra
    )

    schema_version: Literal["1.0.0"]
    audit_event_id: AuditEventId
    action: AuditAction
    actor: AuditActor
    outcome: AuditOutcome
    experiment_id: ExperimentId | MISSING = MISSING  # type: ignore[valid-type]
    run_id: RunId | MISSING = MISSING  # type: ignore[valid-type]
    invocation_id: InvocationId | MISSING = MISSING  # type: ignore[valid-type]
    artifact_id: ArtifactId | MISSING = MISSING  # type: ignore[valid-type]
    timestamp_utc: CalendarValidUtcDateTime
    correlation_id: CorrelationId
    details_hash: Sha256
    details: BoundedDetails

    @model_validator(mode="after")
    def validate_shape(self) -> Self:
        if self.action in INVOCATION_REQUIRED_ACTIONS and _is_missing(
            self.invocation_id
        ):
            raise ValueError(f"{self.action.value} requires invocation_id")
        if self.details_hash != audit_details_hash(self.details):
            raise ValueError(
                "details_hash must equal profile_hash(AUDIT_EVENT_DETAILS_V1, details)"
            )
        return self


# --- The log record (plan 3.1; specification 30.1) ------------------------------------


class LogRecord(CanonicalModel):
    """One structured local log line: timestamp, severity, component, event
    code, correlation, the optional experiment, run, invocation, adapter and
    engine, a bounded message and bounded, redaction-fixed details."""

    schema_version: Literal["1.0.0"]
    timestamp_utc: CalendarValidUtcDateTime
    severity: LogSeverity
    component: NormalizedIdentifier
    event_code: ErrorCode
    correlation_id: CorrelationId
    experiment_id: ExperimentId | MISSING = MISSING  # type: ignore[valid-type]
    run_id: RunId | MISSING = MISSING  # type: ignore[valid-type]
    invocation_id: InvocationId | MISSING = MISSING  # type: ignore[valid-type]
    adapter: NormalizedIdentifier | MISSING = MISSING  # type: ignore[valid-type]
    engine: NormalizedIdentifier | MISSING = MISSING  # type: ignore[valid-type]
    message: BoundedMessage
    details: BoundedDetails

    @model_validator(mode="after")
    def validate_message(self) -> Self:
        if contains_token_shape(self.message):
            raise ValueError("message must be a redaction fixed point")
        return self


__all__ = (
    "CORE_ACTOR",
    "INVOCATION_REQUIRED_ACTIONS",
    "LOCAL_USER_ACTOR",
    "AuditAction",
    "AuditActor",
    "AuditActorKind",
    "AuditEvent",
    "AuditOutcome",
    "LogRecord",
    "LogSeverity",
    "audit_details_hash",
)
