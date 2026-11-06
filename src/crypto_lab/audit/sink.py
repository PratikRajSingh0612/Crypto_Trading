"""The append-only audit interface, its identity source and the log sink.

Stage 9 plan section 4.1 (specification 8.2:340): pure structural ports. The
SQLite ``AuditSink`` arrives with the persistence increments of a later task and
joins the caller's transaction; ``AuditEventIds`` is the deterministic source of
``audit_`` identifiers the sink's callers draw from; ``LogSink`` is the optional
projection the finalizer and the reconciler write human-reconstructible lines
through -- never a record of truth (specification 30.1: console output is a
projection; the audit table is authoritative). Every method answers a
``Result``; none raises for an operational failure.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from crypto_lab.audit.models import AuditEvent, LogRecord
from crypto_lab.domain.identifiers import AuditEventId
from crypto_lab.domain.results import Result


@runtime_checkable
class AuditEventIds(Protocol):
    """Draw fresh ``audit_`` identifiers, already in canonical form."""

    def new_audit_event_id(self) -> AuditEventId:
        """Return a fresh ``audit_`` identifier."""


@runtime_checkable
class AuditSink(Protocol):
    """Append one validated audit event; the sink assigns the ordering."""

    def append(self, event: AuditEvent) -> Result[None]:
        """Append ``event`` in the caller's transaction when there is one."""


@runtime_checkable
class LogSink(Protocol):
    """Write one structured log record; a projection, never evidence."""

    def write(self, record: LogRecord) -> Result[None]:
        """Write ``record``; an I/O failure is a ``Failure``, never an exception."""


__all__ = (
    "AuditEventIds",
    "AuditSink",
    "LogSink",
)
