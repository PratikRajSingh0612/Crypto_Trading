"""The SQLite audit sink, the autonomous recorder and the in-transaction
diagnostic writer (Stage 9 plan 4.1, 4.8; specification 23.3.1:1714, 30.2).

``SqliteAuditSink(scope)`` satisfies the ``crypto_lab.audit.sink.AuditSink`` port
structurally over one ``TransactionScope``: ``append`` joins the caller's
transaction ("append joins the action transaction when possible"), so a rolled-back
phase leaves no audit row and audit history equals durable history. SQLite assigns
``audit_sequence`` (reading 9: the durable append sequence is the ordering
authority) and the sink answers ``AuditAppended`` carrying the identifier beside
that sequence. A duplicate ``audit_event_id`` is ``PERSISTENCE.CONCURRENCY_CONFLICT``
(a repeated identity, the Stage 8 vocabulary); a CHECK refusal is
``CORE.INVARIANT_VIOLATION`` through ``SqliteDatabase.classify``; the I/O class
closes the transaction exactly as every other member does
(``TransactionScope.refused``).

``SqliteAuditRecorder(database, clock)`` appends in its own short transaction for
callers outside a unit of work (the reconciler), returning the same answer.

Ingress (plan 3.3, 4.8), shared by the sink and the recorder and checked on the
connection that inserts the row, before the insert: a present ``run_id`` is a
reference and must name an ``engine_runs`` row on that connection, so a run the
caller added earlier in its own, still uncommitted transaction resolves; an
omitted ``run_id`` supplies no run reference to resolve and stays governed by the
canonical ``AuditEvent`` model alone. An unresolved reference is
``CORE.INVARIANT_VIOLATION`` and inserts nothing; a refused lookup is the
classified failure naming the table read, with the transaction-failure semantics
of every other refused statement. No actor, discriminator, identifier convention
or heuristic over action names, details or correlation text takes part.

``SqliteDiagnosticWriter(scope)`` is the in-transaction, idempotent counterpart of
the Stage 8 ``SqliteDiagnosticRecorder``: ``record(diagnostic)`` inserts the
diagnostic row and its causal edges inside the caller's transaction, absorbs an
identical re-record and refuses a same-identity re-record with different content
as ``CORE.INVARIANT_VIOLATION``. The finalizer's phases audit and record their
diagnostics in the same transaction as the state change they describe.

Nothing here reads a clock of its own, names a raw attempt token or touches the
filesystem.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import InstanceOf
from sqlalchemy import insert, select, text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError

from crypto_lab.audit.models import AuditEvent
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.diagnostics import Diagnostic
from crypto_lab.domain.identifiers import AuditEventId
from crypto_lab.domain.ports import Clock
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.persistence.artifact_codecs import encode_audit_event
from crypto_lab.persistence.codecs import decode_diagnostic, encode_diagnostic
from crypto_lab.persistence.database import SqliteDatabase
from crypto_lab.persistence.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
    persistence_failure,
)
from crypto_lab.persistence.registries import _BACK_EDGES, _FORWARD_EDGES
from crypto_lab.persistence.repositories import TransactionScope
from crypto_lab.persistence.schema import AuditEventRow, DiagnosticRow, EngineRunRow

__all__ = [
    "AuditAppended",
    "SqliteAuditRecorder",
    "SqliteAuditSink",
    "SqliteDiagnosticWriter",
]

_TABLE = "audit_events"
#: The table the ingress lookup reads; a refused lookup names it.
_RUNS = "engine_runs"


@dataclass(frozen=True, slots=True)
class AuditAppended:
    """The sink's answer: the event identifier beside its durable sequence."""

    audit_event_id: AuditEventId
    audit_sequence: int


def _append(connection: Connection, event: AuditEvent) -> int:
    """Insert the row and return the sequence SQLite assigned; raises ``DBAPIError``."""
    values = encode_audit_event(event)
    connection.execute(insert(AuditEventRow).values(**values))
    sequence = connection.execute(
        select(AuditEventRow.audit_sequence).where(
            AuditEventRow.audit_event_id == event.audit_event_id
        )
    ).scalar_one()
    return int(sequence)


def _duplicate(error: DBAPIError) -> bool:
    message = str(getattr(error, "orig", error))
    return "UNIQUE constraint failed: audit_events.audit_event_id" in message


def _unresolved_run(connection: Connection, event: AuditEvent) -> str | None:
    """The ingress check of plan 3.3 and 4.8 over the inserting connection.

    A present ``run_id`` is a reference and must name an ``engine_runs`` row on
    this connection; an omitted ``run_id`` supplies no reference to resolve and
    stays governed by the ``AuditEvent`` model alone. Answers the identity that
    failed to resolve, or ``None``; raises ``DBAPIError`` when the lookup is
    refused, for the caller to classify as it classifies its insert.
    """
    run_id = event.run_id
    if not isinstance(run_id, str):
        return None
    found = connection.execute(
        select(EngineRunRow.run_id).where(EngineRunRow.run_id == run_id)
    ).scalar_one_or_none()
    return None if found is not None else run_id


def _unresolved_message(identity: str, run_id: str) -> str:
    return f"audit event {identity} references run {run_id}, which does not exist"


class SqliteAuditSink:
    """``AuditSink`` over one transaction's connection (plan 4.8)."""

    __slots__ = ("_scope",)

    def __init__(self, scope: TransactionScope) -> None:
        self._scope = scope

    def append(self, event: AuditEvent) -> Result[None]:
        """The ``AuditSink`` port shape: the sequence stays with the row."""
        appended = self.append_sequenced(event)
        if isinstance(appended, Failure):
            return appended
        return Success[None](outcome="SUCCESS", value=None)

    def append_sequenced(self, event: AuditEvent) -> Result[AuditAppended]:
        """``append`` answering the identifier beside its durable sequence."""
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        identity = event.audit_event_id
        try:
            unresolved = _unresolved_run(opened, event)
        except DBAPIError as error:
            return self._scope.refused(
                error, table=_RUNS, operation="append", identity=identity
            )
        if unresolved is not None:
            return self._scope.invariant(
                _unresolved_message(identity, unresolved),
                table=_TABLE,
                operation="append",
                identity=identity,
            )
        try:
            sequence = _append(opened, event)
        except DBAPIError as error:
            if _duplicate(error):
                return self._scope.conflict(
                    f"audit event {identity} is already appended",
                    table=_TABLE,
                    operation="append",
                    identity=identity,
                )
            return self._scope.refused(
                error, table=_TABLE, operation="append", identity=identity
            )
        return Success[InstanceOf[AuditAppended]](
            outcome="SUCCESS",
            value=AuditAppended(audit_event_id=identity, audit_sequence=sequence),
        )


class SqliteAuditRecorder:
    """The standalone sink: one autonomous short transaction per append."""

    __slots__ = ("_clock", "_database")

    def __init__(self, database: SqliteDatabase, *, clock: Clock) -> None:
        self._database = database
        self._clock = clock

    def append(self, event: AuditEvent) -> Result[None]:
        """The ``AuditSink`` port shape over an autonomous transaction."""
        appended = self.append_sequenced(event)
        if isinstance(appended, Failure):
            return appended
        return Success[None](outcome="SUCCESS", value=None)

    def append_sequenced(self, event: AuditEvent) -> Result[AuditAppended]:
        identity = event.audit_event_id
        try:
            with self._database.connection() as connection:
                return self._write(connection, event)
        except PoolTimeoutError as error:
            return self._database.failure(
                SqliteDatabase.classify(error),
                message="the audit transaction could not be opened",
                details={"table": _TABLE, "operation": "append", "identity": identity},
            )

    def _write(
        self, connection: Connection, event: AuditEvent
    ) -> Result[AuditAppended]:
        """The ingress check, then the insert and commit, on the one connection."""
        identity = event.audit_event_id
        try:
            unresolved = _unresolved_run(connection, event)
        except DBAPIError as error:
            return self._refused(error, table=_RUNS, identity=identity)
        if unresolved is not None:
            return persistence_failure(
                INVARIANT_VIOLATION,
                message=_unresolved_message(identity, unresolved),
                clock=self._clock,
                details={"table": _TABLE, "operation": "append", "identity": identity},
            )
        try:
            sequence = _append(connection, event)
            connection.commit()
        except DBAPIError as error:
            if _duplicate(error):
                return persistence_failure(
                    CONCURRENCY_CONFLICT,
                    message=f"audit event {identity} is already appended",
                    clock=self._clock,
                    details={
                        "table": _TABLE,
                        "operation": "append",
                        "identity": identity,
                    },
                )
            return self._refused(error, table=_TABLE, identity=identity)
        return Success[InstanceOf[AuditAppended]](
            outcome="SUCCESS",
            value=AuditAppended(audit_event_id=identity, audit_sequence=sequence),
        )

    def _refused(self, error: DBAPIError, *, table: str, identity: str) -> Failure:
        return self._database.failure(
            SqliteDatabase.classify(error),
            message=f"append on {table} was refused by the database",
            details={"table": table, "operation": "append", "identity": identity},
        )


def _content_without_timestamp(diagnostic: Diagnostic) -> bytes:
    payload = diagnostic.model_dump(mode="json")
    del payload["timestamp_utc"]
    return canonical_json_bytes(payload)


class SqliteDiagnosticWriter:
    """The in-transaction, idempotent diagnostic writer (plan 4.1, Task 5)."""

    __slots__ = ("_scope",)

    def __init__(self, scope: TransactionScope) -> None:
        self._scope = scope

    def record(self, diagnostic: Diagnostic) -> Result[None]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        identity = diagnostic.diagnostic_id
        try:
            opened.execute(
                insert(DiagnosticRow)
                .values(**encode_diagnostic(diagnostic))
                .prefix_with("OR IGNORE")
            )
            row = (
                opened.execute(
                    select(DiagnosticRow).where(DiagnosticRow.diagnostic_id == identity)
                )
                .mappings()
                .one()
            )
            stored = decode_diagnostic(
                {str(key): value for key, value in row.items()},
                clock=self._scope.clock,
            )
            if isinstance(stored, Failure):
                return self._scope.absorb(stored)
            if _content_without_timestamp(stored.value) != _content_without_timestamp(
                diagnostic
            ):
                return self._scope.invariant(
                    f"diagnostic {identity} is already recorded with different content",
                    table="diagnostics",
                    operation="record",
                    identity=identity,
                )
            opened.execute(text(_FORWARD_EDGES), {"diagnostic_id": identity})
            opened.execute(text(_BACK_EDGES), {"diagnostic_id": identity})
        except DBAPIError as error:
            return self._scope.refused(
                error, table="diagnostics", operation="record", identity=identity
            )
        return Success[None](outcome="SUCCESS", value=None)
