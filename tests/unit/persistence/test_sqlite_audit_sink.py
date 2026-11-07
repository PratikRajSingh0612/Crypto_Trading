"""The SQLite audit sink and recorder (Stage 9 plan 4.8, Task 5; spec 23.3.1:1714).

``append`` joins the caller's transaction and SQLite assigns the durable
``audit_sequence`` in append order (reading 9); the table is append-only (a raw
``UPDATE`` or ``DELETE`` is refused by the Stage 9 trigger and classifies as
``CORE.INVARIANT_VIOLATION``); a repeated ``audit_event_id`` is the conflict; the
autonomous recorder commits its own short transaction; and a rolled-back
transaction leaves no audit row behind, so audit history equals durable history.

Ingress (plan 3.3, 4.8): a present ``run_id`` is a reference and must name an
``engine_runs`` row on the connection that inserts the event, checked before the
insert by both public append forms of the sink and of the recorder; an omitted
``run_id`` supplies no reference and stays governed by ``AuditEvent`` alone. An
unresolved reference is ``CORE.INVARIANT_VIOLATION`` and inserts no row; a
refused lookup is the classified I/O failure with the established
transaction-failure semantics.
"""

from __future__ import annotations

import json
from datetime import timedelta

import pytest
from pydantic.experimental.missing_sentinel import MISSING
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from crypto_lab.audit.models import AuditAction, AuditEvent
from crypto_lab.domain.results import Failure, Success
from crypto_lab.persistence.audit_sink import SqliteAuditRecorder
from crypto_lab.persistence.codecs import encode_diagnostic
from crypto_lab.persistence.database import SqliteDatabase
from crypto_lab.persistence.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
    STORAGE_UNAVAILABLE,
    WRITE_FAILED,
)
from doubles.artifacts import SequentialAuditIds, sample_audit_event
from doubles.experiments import (
    DIAG_ID,
    INSTANT,
    OTHER_DIAG_ID,
    OTHER_RUN_ID,
    RUN_ID,
    FixedClock,
    sample_diagnostic,
    sample_run,
    sequential_diagnostic_id,
)
from persistence_support.artifacts import ArtifactHarness
from persistence_support.harness import (
    SqliteHarness,
    accept_any_revision,
    causal_edges,
    code,
    commit,
    cursor_fault,
    ok,
    put_lifecycle_parents,
    raw_connection,
    sqlite_error,
)

_ROWS_SQL = "SELECT audit_sequence, audit_event_id, action FROM audit_events ORDER BY 1"
#: ``SQLITE_IOERR | (1 << 8)``: the extended code of a failed page read.
_SQLITE_IOERR_READ = 266


def _details(result: object) -> dict[str, object]:
    assert isinstance(result, Failure), result
    return dict(result.diagnostics[0].details)


def _message(result: object) -> str:
    assert isinstance(result, Failure), result
    return result.diagnostics[0].message


def _reads_engine_runs(statement: str) -> bool:
    """The run lookup that precedes every insert (an ``INSERT`` has no ``FROM``)."""
    return "FROM engine_runs" in statement


def _rows(database: SqliteDatabase) -> list[tuple[int, str, str]]:
    connection = raw_connection(database.path)
    try:
        return [
            (int(sequence), str(identity), str(action))
            for sequence, identity, action in connection.execute(_ROWS_SQL).fetchall()
        ]
    finally:
        connection.close()


def _events(count: int) -> tuple[AuditEvent, ...]:
    ids = SequentialAuditIds("audit-sink")
    actions = (
        AuditAction.ARTIFACT_CANDIDATE_REGISTERED,
        AuditAction.ARTIFACT_VALIDATED,
        AuditAction.FINALIZATION_PREPARED,
    )
    return tuple(
        sample_audit_event(
            actions[index % len(actions)],
            audit_event_id=ids.new_audit_event_id(),
            timestamp_utc=INSTANT + timedelta(seconds=index),
        )
        for index in range(count)
    )


def test_append_only_and_sequence_ordered(sqlite_harness: SqliteHarness) -> None:
    events = _events(3)
    put_lifecycle_parents(sqlite_harness, run=True)
    transaction = sqlite_harness.unit_of_work().begin()
    appended = [ok(transaction.audit.append_sequenced(event)) for event in events]
    assert [item.audit_sequence for item in appended] == [1, 2, 3]
    assert [item.audit_event_id for item in appended] == [
        event.audit_event_id for event in events
    ]
    # The port shape answers ``None``; the row carries the sequence.
    assert isinstance(transaction.audit.append(_events(4)[3]), Success)
    duplicate = transaction.audit.append(events[0])
    assert code(duplicate) == CONCURRENCY_CONFLICT
    commit(transaction)
    rows = _rows(sqlite_harness.database)
    assert [row[0] for row in rows] == [1, 2, 3, 4]
    assert [row[1] for row in rows[:3]] == [event.audit_event_id for event in events]
    # Append-only: the Stage 9 triggers refuse every UPDATE and DELETE, and the
    # refusal classifies as the invariant through the single authority.
    for statement in (
        "UPDATE audit_events SET outcome = 'FAILED' WHERE audit_sequence = 1",
        "DELETE FROM audit_events WHERE audit_sequence = 1",
    ):
        with sqlite_harness.database.connection() as connection:
            with pytest.raises(DBAPIError) as info:
                connection.execute(text(statement))
            assert SqliteDatabase.classify(info.value) == INVARIANT_VIOLATION
            assert "append-only" in str(info.value.orig)
    assert len(_rows(sqlite_harness.database)) == 4


def test_joins_caller_transaction(sqlite_harness: SqliteHarness) -> None:
    (event,) = _events(1)
    put_lifecycle_parents(sqlite_harness, run=True)
    transaction = sqlite_harness.unit_of_work().begin()
    ok(transaction.audit.append(event))
    # Not yet durable: the append joined the open transaction.
    assert _rows(sqlite_harness.database) == []
    commit(transaction)
    assert _rows(sqlite_harness.database) == [
        (1, event.audit_event_id, event.action.value)
    ]


def test_recorder_autonomous(sqlite_harness: SqliteHarness) -> None:
    event, second = _events(2)
    put_lifecycle_parents(sqlite_harness, run=True)
    recorder = SqliteAuditRecorder(sqlite_harness.database, clock=FixedClock(INSTANT))
    appended = ok(recorder.append_sequenced(event))
    assert appended.audit_sequence == 1
    assert appended.audit_event_id == event.audit_event_id
    assert _rows(sqlite_harness.database) == [
        (1, event.audit_event_id, event.action.value)
    ]
    repeated = recorder.append(event)
    assert isinstance(repeated, Failure)
    assert code(repeated) == CONCURRENCY_CONFLICT
    assert len(_rows(sqlite_harness.database)) == 1
    # The port shape answers ``None`` on its own committed transaction; the row
    # takes the next durable sequence.
    assert ok(recorder.append(second)) is None
    assert _rows(sqlite_harness.database) == [
        (1, event.audit_event_id, event.action.value),
        (2, second.audit_event_id, second.action.value),
    ]


def test_recorder_maps_a_checkout_timeout_to_a_storage_failure(
    sqlite_harness: SqliteHarness,
) -> None:
    """An exhausted pool at the recorder's checkout is the classified
    ``PERSISTENCE.STORAGE_UNAVAILABLE`` naming the table, operation and event,
    never an exception and never a row; the recorder recovers once the pooled
    connection is released (the Stage 8 diagnostic recorder's shape)."""
    (event,) = _events(1)
    put_lifecycle_parents(sqlite_harness, run=True)
    opened = SqliteDatabase.open(
        sqlite_harness.database.path,
        busy_timeout_ms=100,
        clock=FixedClock(INSTANT),
        revision_policy=accept_any_revision,
        pool_size=1,
        max_overflow=0,
        pool_timeout_seconds=0.1,
    )
    single = ok(opened)
    try:
        recorder = SqliteAuditRecorder(single, clock=FixedClock(INSTANT))
        with single.connection() as held:
            held.execute(text("SELECT 1"))
            refused = recorder.append_sequenced(event)
            assert code(refused) == STORAGE_UNAVAILABLE
            assert isinstance(refused, Failure)
            assert refused.diagnostics[0].message == (
                "the audit transaction could not be opened"
            )
            assert _details(refused) == {
                "table": "audit_events",
                "operation": "append",
                "identity": event.audit_event_id,
            }
            assert recorder.append(event) is not refused
            assert code(recorder.append(event)) == STORAGE_UNAVAILABLE
        assert _rows(sqlite_harness.database) == []
        assert ok(recorder.append_sequenced(event)).audit_sequence == 1
    finally:
        single.close()
    assert _rows(sqlite_harness.database) == [
        (1, event.audit_event_id, event.action.value)
    ]


def test_the_writer_refuses_a_stored_row_the_record_refuses(
    artifact_harness: ArtifactHarness,
) -> None:
    """A diagnostics row SQL accepts but the canonical model refuses (an unsorted
    causal tuple passes the array CHECK, the Stage 8 registries precedent) is
    ``CORE.INVARIANT_VIOLATION`` from the writer's read-back, naming the table,
    identity and column; the ``INSERT OR IGNORE`` kept the stored row, no edge
    was written, the refusal is not the I/O class so the transaction stays
    usable, and nothing of the attempt survives a rollback."""
    corrupt = sequential_diagnostic_id(7)
    corrupt_row = dict(encode_diagnostic(sample_diagnostic(diagnostic_id=corrupt)))
    corrupt_row["causal_diagnostic_ids"] = json.dumps([OTHER_DIAG_ID, DIAG_ID])
    artifact_harness.plant_raw("diagnostics", corrupt_row)
    artifact_harness.seed_result_prestate()
    transaction = artifact_harness.begin()
    writer = transaction.diagnostics_writer
    refused = writer.record(sample_diagnostic(diagnostic_id=corrupt))
    assert code(refused) == INVARIANT_VIOLATION
    assert _details(refused) == {
        "table": "diagnostics",
        "identity": corrupt,
        "location": "causal_diagnostic_ids",
        "operation": "decode",
    }
    assert transaction.open_failure() is None
    # The transaction is still usable: a well-formed diagnostic records, and its
    # edge toward the corrupt identity derives from the stored JSON column.
    assert (
        ok(writer.record(sample_diagnostic(causal_diagnostic_ids=(corrupt,)))) is None
    )
    assert ok(transaction.diagnostics.get(DIAG_ID)).causal_diagnostic_ids == (corrupt,)
    transaction.rollback()
    assert artifact_harness.count("diagnostics") == 1
    assert causal_edges(artifact_harness.database) == ()
    reader = artifact_harness.begin()
    assert code(reader.diagnostics.get(corrupt)) == INVARIANT_VIOLATION
    assert code(reader.diagnostics.get(DIAG_ID)) == INVARIANT_VIOLATION
    reader.rollback()


def test_a_refused_append_or_record_is_the_classified_io_failure(
    sqlite_harness: SqliteHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An injected ``SQLITE_IOERR_READ`` at the insert: the sink joining a
    transaction, the autonomous recorder and the diagnostic writer each answer
    the classified ``PERSISTENCE.WRITE_FAILED`` naming their table, never raise,
    and leave no row behind."""
    (event,) = _events(1)
    diagnostic = sample_diagnostic()
    put_lifecycle_parents(sqlite_harness, run=True)
    recorder = SqliteAuditRecorder(sqlite_harness.database, clock=FixedClock(INSTANT))
    with cursor_fault(sqlite_harness.database, monkeypatch) as fault:
        transaction = sqlite_harness.unit_of_work().begin()
        fault.arm(
            sqlite_error(_SQLITE_IOERR_READ, "SQLITE_IOERR_READ"),
            when=lambda statement: statement.startswith("INSERT INTO audit_events"),
        )
        refused = transaction.audit.append_sequenced(event)
        assert not fault.armed
        assert code(refused) == WRITE_FAILED
        assert _details(refused)["table"] == "audit_events"
        assert _details(refused)["operation"] == "append"
        # The I/O class closes the transaction (Stage 8 reading 3).
        assert transaction.audit.append(event) is refused
        assert transaction.commit() is refused
        fault.arm(
            sqlite_error(_SQLITE_IOERR_READ, "SQLITE_IOERR_READ"),
            when=lambda statement: statement.startswith("INSERT INTO audit_events"),
        )
        autonomous = recorder.append_sequenced(event)
        assert not fault.armed
        assert code(autonomous) == WRITE_FAILED
        assert _details(autonomous)["table"] == "audit_events"
        transaction = sqlite_harness.unit_of_work().begin()
        fault.arm(
            sqlite_error(_SQLITE_IOERR_READ, "SQLITE_IOERR_READ"),
            when=lambda statement: statement.startswith("INSERT OR IGNORE"),
        )
        written = transaction.diagnostics_writer.record(diagnostic)
        assert not fault.armed
        assert code(written) == WRITE_FAILED
        assert _details(written)["table"] == "diagnostics"
        assert _details(written)["operation"] == "record"
        transaction.rollback()
    assert _rows(sqlite_harness.database) == []
    reader = sqlite_harness.unit_of_work().begin()
    assert code(reader.diagnostics.get(diagnostic.diagnostic_id)) == INVARIANT_VIOLATION
    reader.rollback()


def test_rollback_leaves_no_audit_row(sqlite_harness: SqliteHarness) -> None:
    first, second = _events(2)
    put_lifecycle_parents(sqlite_harness, run=True)
    abandoned = sqlite_harness.unit_of_work().begin()
    assert ok(abandoned.audit.append_sequenced(first)).audit_sequence == 1
    abandoned.rollback()
    assert _rows(sqlite_harness.database) == []
    durable = sqlite_harness.unit_of_work().begin()
    appended = ok(durable.audit.append_sequenced(second))
    commit(durable)
    # The rolled-back sequence was never durable, so the first durable append is 1.
    assert appended.audit_sequence == 1
    assert _rows(sqlite_harness.database) == [
        (1, second.audit_event_id, second.action.value)
    ]


def test_a_present_run_reference_must_resolve(sqlite_harness: SqliteHarness) -> None:
    """Plan 3.3 and 4.8 ingress: a present ``run_id`` is a reference and must name
    an ``engine_runs`` row on the inserting connection; an omitted ``run_id``
    supplies no reference. Both public append forms of the sink and of the
    recorder refuse the unresolved reference as ``CORE.INVARIANT_VIOLATION``
    before inserting; the refusing transaction stays usable; an omitted
    reference is admitted; a run added earlier in the caller's own uncommitted
    transaction resolves on that connection and on no other; once the run is
    durable the recorder resolves it too; a reference to another, nonexistent
    run is refused while the fixture run exists."""
    put_lifecycle_parents(sqlite_harness)  # the experiment alone: no run row
    ids = SequentialAuditIds("audit-ingress")
    # One event per public append form, so each answer stands on its own.
    events = tuple(
        sample_audit_event(audit_event_id=ids.new_audit_event_id()) for _ in range(4)
    )
    omitted = sample_audit_event(
        audit_event_id=ids.new_audit_event_id(), run_id=MISSING
    )
    recorder = SqliteAuditRecorder(sqlite_harness.database, clock=FixedClock(INSTANT))
    transaction = sqlite_harness.unit_of_work().begin()
    # The autonomous forms first: nothing holds the writer lock they would need
    # if they accepted, so each answer is the form's own.
    answers = (
        recorder.append(events[0]),
        recorder.append_sequenced(events[1]),
        transaction.audit.append(events[2]),
        transaction.audit.append_sequenced(events[3]),
    )
    assert all(isinstance(answer, Failure) for answer in answers), answers
    for event, refused in zip(events, answers, strict=True):
        assert code(refused) == INVARIANT_VIOLATION
        assert RUN_ID in _message(refused)
        assert "does not exist" in _message(refused)
        assert _details(refused) == {
            "table": "audit_events",
            "operation": "append",
            "identity": event.audit_event_id,
        }
    assert transaction.open_failure() is None
    assert _rows(sqlite_harness.database) == []
    # An omitted reference is admitted in the same, still usable transaction.
    assert ok(transaction.audit.append_sequenced(omitted)).audit_sequence == 1
    # A run added earlier in this very transaction resolves on its connection...
    ok(transaction.engine_runs.add_attempt(sample_run()))
    assert ok(transaction.audit.append_sequenced(events[2])).audit_sequence == 2
    # ...and on no other: the recorder's own connection sees no such run yet.
    assert code(recorder.append(events[0])) == INVARIANT_VIOLATION
    commit(transaction)
    assert _rows(sqlite_harness.database) == [
        (1, omitted.audit_event_id, omitted.action.value),
        (2, events[2].audit_event_id, events[2].action.value),
    ]
    # Durable now: the recorder resolves the same reference on its own connection.
    assert ok(recorder.append_sequenced(events[0])).audit_sequence == 3
    fourth = sample_audit_event(audit_event_id=ids.new_audit_event_id(), run_id=MISSING)
    assert ok(recorder.append(fourth)) is None
    # Another run that does not exist is refused while the fixture run exists.
    foreign = sample_audit_event(
        audit_event_id=ids.new_audit_event_id(), run_id=OTHER_RUN_ID
    )
    later = sqlite_harness.unit_of_work().begin()
    for refused in (later.audit.append(foreign), recorder.append_sequenced(foreign)):
        assert code(refused) == INVARIANT_VIOLATION
        assert OTHER_RUN_ID in _message(refused)
    later.rollback()
    assert len(_rows(sqlite_harness.database)) == 4


def test_a_failed_run_lookup_is_the_classified_io_failure(
    sqlite_harness: SqliteHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An injected ``SQLITE_IOERR_READ`` at the run lookup that precedes the
    insert: the sink answers the classified ``PERSISTENCE.WRITE_FAILED`` naming
    the table it read, the I/O class closes the transaction exactly as a refused
    insert does (every later call and ``commit()`` answer the same ``Failure``
    and issue no statement), the recorder answers the same classification on its
    own connection, no audit row exists, and the transient fault over, the same
    event appends."""
    (event,) = _events(1)
    put_lifecycle_parents(sqlite_harness, run=True)
    recorder = SqliteAuditRecorder(sqlite_harness.database, clock=FixedClock(INSTANT))
    with cursor_fault(sqlite_harness.database, monkeypatch) as fault:
        transaction = sqlite_harness.unit_of_work().begin()
        fault.arm(
            sqlite_error(_SQLITE_IOERR_READ, "SQLITE_IOERR_READ"),
            when=_reads_engine_runs,
        )
        refused = transaction.audit.append_sequenced(event)
        assert not fault.armed
        assert code(refused) == WRITE_FAILED
        assert _details(refused)["table"] == "engine_runs"
        assert _details(refused)["operation"] == "append"
        assert _details(refused)["identity"] == event.audit_event_id
        assert _details(refused)["sqlite_errorcode"] == _SQLITE_IOERR_READ
        assert transaction.open_failure() is refused
        issued = len(fault.passed)
        assert transaction.audit.append(event) is refused
        assert len(fault.passed) == issued
        assert transaction.commit() is refused
        fault.arm(
            sqlite_error(_SQLITE_IOERR_READ, "SQLITE_IOERR_READ"),
            when=_reads_engine_runs,
        )
        autonomous = recorder.append(event)
        assert not fault.armed
        assert code(autonomous) == WRITE_FAILED
        assert _details(autonomous) == {
            "table": "engine_runs",
            "operation": "append",
            "identity": event.audit_event_id,
        }
    assert _rows(sqlite_harness.database) == []
    assert ok(recorder.append_sequenced(event)).audit_sequence == 1
    assert _rows(sqlite_harness.database) == [
        (1, event.audit_event_id, event.action.value)
    ]
