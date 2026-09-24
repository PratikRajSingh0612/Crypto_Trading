"""Sanitized run events over the migrated schema (plan 3.3.5, 4.3; case C-14).

``append_event`` replays an identical stored event without writing, refuses a
second event under one key, refuses a reused ``event_id`` under another key and
loses a concurrent identical append as a conflict; ``list_events`` is
sequence-ordered and empty for an invocation with no events. The composite
foreign key -- an event belonging to its invocation's own run, and a
``DESCRIBE`` invocation owning none -- is case C-26 and is asserted in
``test_sqlite_constraints.py``. Every case runs against the file-backed
database.
"""

from __future__ import annotations

from crypto_lab.persistence.diagnostics import CONCURRENCY_CONFLICT
from doubles.experiments import INVOCATION_ID, OTHER_INVOCATION_ID, UUID_C
from persistence_support.harness import (
    OTHER_EVENT_ID,
    SqliteHarness,
    code,
    commit,
    ok,
    put_lifecycle_parents,
    sample_run_event,
)


def test_append_event_replays_identical_and_refuses_conflicting_content(
    sqlite_harness: SqliteHarness,
) -> None:
    put_lifecycle_parents(sqlite_harness, run=True, invocation=True)
    event = sample_run_event(sequence=1)
    transaction = sqlite_harness.unit_of_work().begin()
    assert ok(transaction.engine_runs.append_event(event)) == event
    # An identical replay returns the stored event and writes nothing.
    assert ok(transaction.engine_runs.append_event(event)) == event
    assert len(ok(transaction.engine_runs.list_events(INVOCATION_ID))) == 1
    # The same key with other content is a conflict, not a second row.
    divergent = sample_run_event(sequence=1, phase="teardown")
    assert divergent.content_hash != event.content_hash
    assert code(transaction.engine_runs.append_event(divergent)) == (
        CONCURRENCY_CONFLICT
    )
    # A reused event_id under another key is a conflict too.
    reused = sample_run_event(sequence=2, event_id=event.event_id)
    assert code(transaction.engine_runs.append_event(reused)) == CONCURRENCY_CONFLICT
    assert len(ok(transaction.engine_runs.list_events(INVOCATION_ID))) == 1
    commit(transaction)
    fresh = sqlite_harness.unit_of_work().begin()
    assert ok(fresh.engine_runs.list_events(INVOCATION_ID)) == (event,)
    fresh.rollback()


def test_a_concurrent_identical_append_loses_as_a_conflict(
    sqlite_harness: SqliteHarness,
) -> None:
    put_lifecycle_parents(sqlite_harness, run=True, invocation=True)
    event = sample_run_event(sequence=1)
    first = sqlite_harness.unit_of_work().begin()
    second = sqlite_harness.unit_of_work().begin()
    assert ok(second.engine_runs.list_events(event.invocation_id)) == ()
    ok(first.engine_runs.append_event(event))
    commit(first)
    assert code(second.engine_runs.append_event(event)) == CONCURRENCY_CONFLICT
    second.rollback()
    third = sqlite_harness.unit_of_work().begin()
    assert ok(third.engine_runs.append_event(event)) == event
    third.rollback()


def test_list_events_is_sequence_ordered_and_empty_for_an_unknown_invocation(
    sqlite_harness: SqliteHarness,
) -> None:
    put_lifecycle_parents(sqlite_harness, run=True, invocation=True)
    first = sample_run_event(sequence=1)
    second = sample_run_event(sequence=2, event_id=OTHER_EVENT_ID)
    third = sample_run_event(sequence=3, event_id=f"evt_{UUID_C}")
    transaction = sqlite_harness.unit_of_work().begin()
    # Inserted out of order; the read is sequence-ordered regardless.
    for event in (third, first, second):
        ok(transaction.engine_runs.append_event(event))
    listed = ok(transaction.engine_runs.list_events(INVOCATION_ID))
    assert type(listed) is tuple
    assert listed == (first, second, third)
    assert [event.sequence for event in listed] == [1, 2, 3]
    assert ok(transaction.engine_runs.list_events(OTHER_INVOCATION_ID)) == ()
    commit(transaction)
    fresh = sqlite_harness.unit_of_work().begin()
    assert ok(fresh.engine_runs.list_events(INVOCATION_ID)) == (first, second, third)
    fresh.rollback()
