"""The finalization deadline at the repository and table (Stage 9 plan 4.1, 4.5,
reading 9; Task 5).

``snapshot_deadline`` is the one ``RUNNING -> RUNNING`` write: it adds
``finalization_deadline_utc`` under ``assert_deadline_snapshot`` and swaps the run
at the expected revision, so a stale revision is the conflict and a run outside
``RUNNING`` or already snapshotted is the invariant; the column is admitted only
after that snapshot (the codec's state-governed pair); once set, the
``engine_runs_deadline_immutable`` trigger refuses every change, classified as
``CORE.INVARIANT_VIOLATION``; and ``record_timeout`` moves a ``RUNNING`` run to
``TIMED_OUT`` with the ``TIMEOUT`` diagnostic as primary, carrying the deadline.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from crypto_lab.domain.diagnostics import DiagnosticCategory
from crypto_lab.domain.engine_run import EngineRunRecord
from crypto_lab.domain.lifecycle import EngineRunState
from crypto_lab.domain.results import Failure
from crypto_lab.persistence.codecs import encode_engine_run, utc_to_micros
from crypto_lab.persistence.database import SqliteDatabase
from crypto_lab.persistence.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
)
from doubles.experiments import (
    INSTANT,
    OTHER_DIAG_ID,
    OTHER_RUN_ID,
    RUN_ID,
    SLOT_B,
    sample_diagnostic,
    sample_run,
)
from persistence_support.harness import (
    SqliteHarness,
    code,
    commit,
    ok,
    put_lifecycle_parents,
    put_run,
)

_R = EngineRunState
_DEADLINE = INSTANT + timedelta(minutes=5)
_LATER_DEADLINE = INSTANT + timedelta(minutes=9)


def _message(result: object) -> str:
    assert isinstance(result, Failure), result
    return result.diagnostics[0].message


def _running(sqlite_harness: SqliteHarness) -> EngineRunRecord:
    put_lifecycle_parents(sqlite_harness, observation=True)
    record = sample_run(_R.RUNNING)
    put_run(sqlite_harness, record)
    return record


def _stored_deadline(database: SqliteDatabase) -> object:
    with database.read_only() as connection:
        return connection.execute(
            text("SELECT finalization_deadline_utc FROM engine_runs WHERE run_id = :r"),
            {"r": RUN_ID},
        ).scalar_one()


def test_deadline_column_admitted_only_after_snapshot(
    sqlite_harness: SqliteHarness,
) -> None:
    stored = _running(sqlite_harness)
    assert "finalization_deadline_utc" not in encode_engine_run(stored)
    assert _stored_deadline(sqlite_harness.database) is None
    transaction = sqlite_harness.unit_of_work().begin()
    snapshotted = ok(
        transaction.result_leases.snapshot_deadline(stored.revision, RUN_ID, _DEADLINE)
    )
    commit(transaction)
    assert snapshotted.state is _R.RUNNING
    assert snapshotted.revision == stored.revision + 1
    assert snapshotted.finalization_deadline_utc == _DEADLINE
    assert _stored_deadline(sqlite_harness.database) == utc_to_micros(_DEADLINE)
    (committed,) = sqlite_harness.committed_engine_runs()
    assert committed == snapshotted
    assert encode_engine_run(committed)["finalization_deadline_utc"] == utc_to_micros(
        _DEADLINE
    )
    # Only a RUNNING run admits the snapshot.
    put_run(
        sqlite_harness,
        sample_run(_R.READY, run_id=OTHER_RUN_ID, logical_slot_id=SLOT_B),
    )
    refusing = sqlite_harness.unit_of_work().begin()
    refused = refusing.result_leases.snapshot_deadline(
        sample_run(_R.READY).revision, OTHER_RUN_ID, _DEADLINE
    )
    assert code(refused) == INVARIANT_VIOLATION
    refusing.rollback()


def test_deadline_immutable_once_set(sqlite_harness: SqliteHarness) -> None:
    stored = _running(sqlite_harness)
    transaction = sqlite_harness.unit_of_work().begin()
    ok(transaction.result_leases.snapshot_deadline(stored.revision, RUN_ID, _DEADLINE))
    commit(transaction)
    # A second snapshot is refused before any write.
    again = sqlite_harness.unit_of_work().begin()
    refused = again.result_leases.snapshot_deadline(
        stored.revision + 1, RUN_ID, _LATER_DEADLINE
    )
    assert code(refused) == INVARIANT_VIOLATION
    again.rollback()
    # The trigger refuses a raw change and a raw clearing alike.
    for value in (utc_to_micros(_LATER_DEADLINE), None):
        with sqlite_harness.database.connection() as connection:
            with pytest.raises(DBAPIError) as info:
                connection.execute(
                    text(
                        "UPDATE engine_runs SET finalization_deadline_utc = :v "
                        "WHERE run_id = :r"
                    ),
                    {"v": value, "r": RUN_ID},
                )
            assert SqliteDatabase.classify(info.value) == INVARIANT_VIOLATION
            assert "immutable" in str(info.value.orig)
    assert _stored_deadline(sqlite_harness.database) == utc_to_micros(_DEADLINE)


def test_snapshot_deadline_is_a_cas(sqlite_harness: SqliteHarness) -> None:
    stored = _running(sqlite_harness)
    transaction = sqlite_harness.unit_of_work().begin()
    stale = transaction.result_leases.snapshot_deadline(
        stored.revision + 1, RUN_ID, _DEADLINE
    )
    assert code(stale) == CONCURRENCY_CONFLICT
    absent = transaction.result_leases.snapshot_deadline(0, OTHER_RUN_ID, _DEADLINE)
    assert code(absent) == INVARIANT_VIOLATION
    assert isinstance(absent, Failure)
    assert "does not exist" in absent.diagnostics[0].message
    # A deadline the record cannot carry (a naive instant) is the invariant
    # before any write, not an exception.
    naive = transaction.result_leases.snapshot_deadline(
        stored.revision, RUN_ID, _DEADLINE.replace(tzinfo=None)
    )
    assert code(naive) == INVARIANT_VIOLATION
    assert "admits no deadline snapshot" in _message(naive)
    transaction.rollback()
    assert _stored_deadline(sqlite_harness.database) is None
    (committed,) = sqlite_harness.committed_engine_runs()
    assert committed == stored


def test_record_timeout_is_a_cas(sqlite_harness: SqliteHarness) -> None:
    """Plan 4.5 at the repository boundary, the Stage 8 4.3.1 order: a stale
    revision is the conflict and a missing run the invariant naming the absence,
    both decided on the pre-read before any write; the stored run is untouched."""
    stored = _running(sqlite_harness)
    timeout = sample_diagnostic(
        OTHER_DIAG_ID,
        error_code="ARTIFACT.FINALIZATION_TIMED_OUT",
        category=DiagnosticCategory.TIMEOUT,
        retriable=False,
    )
    sqlite_harness.seed_diagnostic(timeout)
    transaction = sqlite_harness.unit_of_work().begin()
    leases = transaction.result_leases
    stale = leases.record_timeout(stored.revision + 1, RUN_ID, timeout)
    assert code(stale) == CONCURRENCY_CONFLICT
    assert isinstance(stale, Failure)
    assert f"is at revision {stored.revision}" in _message(stale)
    assert dict(stale.diagnostics[0].details) == {
        "table": "engine_runs",
        "operation": "record_timeout",
        "identity": RUN_ID,
    }
    absent = leases.record_timeout(0, OTHER_RUN_ID, timeout)
    assert code(absent) == INVARIANT_VIOLATION
    assert "does not exist" in _message(absent)
    assert ok(leases.get(RUN_ID)) == stored
    transaction.rollback()
    (committed,) = sqlite_harness.committed_engine_runs()
    assert committed == stored
    assert committed.state is _R.RUNNING


def test_record_timeout_requires_running(sqlite_harness: SqliteHarness) -> None:
    stored = _running(sqlite_harness)
    timeout = sample_diagnostic(
        OTHER_DIAG_ID,
        error_code="ARTIFACT.FINALIZATION_TIMED_OUT",
        category=DiagnosticCategory.TIMEOUT,
        retriable=False,
    )
    sqlite_harness.seed_diagnostic(timeout)
    transaction = sqlite_harness.unit_of_work().begin()
    snapshotted = ok(
        transaction.result_leases.snapshot_deadline(stored.revision, RUN_ID, _DEADLINE)
    )
    wrong_category = transaction.result_leases.record_timeout(
        snapshotted.revision, RUN_ID, sample_diagnostic()
    )
    assert code(wrong_category) == INVARIANT_VIOLATION
    timed_out = ok(
        transaction.result_leases.record_timeout(snapshotted.revision, RUN_ID, timeout)
    )
    commit(transaction)
    assert timed_out.state is _R.TIMED_OUT
    assert timed_out.primary_terminal_diagnostic_id == OTHER_DIAG_ID
    assert timed_out.finalization_deadline_utc == _DEADLINE
    assert timed_out.revision == snapshotted.revision + 1
    (committed,) = sqlite_harness.committed_engine_runs()
    assert committed == timed_out
    # A terminal run admits no further timeout; a READY run is not RUNNING.
    terminal = sqlite_harness.unit_of_work().begin()
    assert (
        code(terminal.result_leases.record_timeout(timed_out.revision, RUN_ID, timeout))
        == INVARIANT_VIOLATION
    )
    put_run(
        sqlite_harness,
        sample_run(_R.READY, run_id=OTHER_RUN_ID, logical_slot_id=SLOT_B),
    )
    ready = sample_run(_R.READY, run_id=OTHER_RUN_ID)
    assert (
        code(
            terminal.result_leases.record_timeout(ready.revision, OTHER_RUN_ID, timeout)
        )
        == INVARIANT_VIOLATION
    )
    terminal.rollback()
