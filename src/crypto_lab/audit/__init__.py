"""Diagnostics and audit boundary for the research core.

Stage 9 Task 2 adds the audit contracts of specification 11.3:586 and 30: the
append-only ``AuditEvent`` with its actor, action and outcome vocabularies, the
JSON Lines ``LogRecord`` and its bounded, rotated writer, field-level redaction
over detail trees, the correlation context of 30.2 and the ``AuditSink``,
``AuditEventIds`` and ``LogSink`` ports -- all importing ``domain`` alone
(specification 27.1). The SQLite sink arrives with the persistence increments
of a later Stage 9 task.
"""

from crypto_lab.audit.correlation import CorrelationContext
from crypto_lab.audit.jsonl import (
    AUDIT_LOG_WRITE_FAILED,
    AUDIT_SOURCE_COMPONENT,
    LOG_FILE_BYTES,
    MAX_RETAINED_FILES,
    JsonLinesLogWriter,
    log_write_failure,
)
from crypto_lab.audit.models import (
    CORE_ACTOR,
    INVOCATION_REQUIRED_ACTIONS,
    LOCAL_USER_ACTOR,
    AuditAction,
    AuditActor,
    AuditActorKind,
    AuditEvent,
    AuditOutcome,
    LogRecord,
    LogSeverity,
    audit_details_hash,
)
from crypto_lab.audit.redaction import (
    REDACTED,
    TOKEN_SHAPE_PATTERN,
    BoundedDetails,
    contains_token_shape,
    is_denylisted_key,
    redact_details,
    validate_bounded_details,
)
from crypto_lab.audit.sink import AuditEventIds, AuditSink, LogSink

__all__ = (
    "AUDIT_LOG_WRITE_FAILED",
    "AUDIT_SOURCE_COMPONENT",
    "CORE_ACTOR",
    "INVOCATION_REQUIRED_ACTIONS",
    "LOCAL_USER_ACTOR",
    "LOG_FILE_BYTES",
    "MAX_RETAINED_FILES",
    "REDACTED",
    "TOKEN_SHAPE_PATTERN",
    "AuditAction",
    "AuditActor",
    "AuditActorKind",
    "AuditEvent",
    "AuditEventIds",
    "AuditOutcome",
    "AuditSink",
    "BoundedDetails",
    "CorrelationContext",
    "JsonLinesLogWriter",
    "LogRecord",
    "LogSeverity",
    "LogSink",
    "audit_details_hash",
    "contains_token_shape",
    "is_denylisted_key",
    "log_write_failure",
    "redact_details",
    "validate_bounded_details",
)
