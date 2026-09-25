"""An interrupted writer process leaves no partial row (plan 5.1 case C-17; Task 6).

A child interpreter ``P`` -- the venv's ``sys.executable`` with ``-I -B -c`` and the
one-line ``HOLDING_WRITER_PROGRAM``, a list argv and ``shell=False`` -- opens the
migrated database with the stdlib DBAPI, takes the writer lock with
``BEGIN IMMEDIATE``, stages a throwaway table and one row in it (so no record
``CHECK`` is involved and the uncommitted DDL is the partial write the reopen must
not see), prints ``HELD`` and blocks on stdin. The parent proceeds only after
reading that line -- the proven checkpoint is **work not yet committed** (the lock
held, the DDL and the row staged, no ``COMMIT`` issued) -- asserts that its own
writer gets ``PERSISTENCE.CONCURRENCY_CONFLICT`` from a lock another process holds,
then terminates the child and awaits its exit in ``finally:`` before reopening the
file through the production open. The oracle matches that checkpoint: the pre-crash
rows are present, ``crash_probe`` is absent, the revision is ``CURRENT``,
``quick_check`` is ``ok``, the journal mode is still ``wal`` and the ``-wal``/``-shm``
sidecars the interrupted writer left behind are tolerated (plan 7.5).

This is process interruption evidence: it is not a power-loss experiment and proves
no storage-hardware failure mode. Nothing here sleeps; the child is the only process
touched and only through the ``Popen`` handle this test owns. This module is the
twelfth ``subprocess`` importer of the Stage 6 allowlist and the only one under
``tests/integration/persistence`` (plan 2.6, 7.6).
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from typing import Final

from sqlalchemy import text

from crypto_lab.domain.lifecycle import ExperimentState
from crypto_lab.persistence.diagnostics import CONCURRENCY_CONFLICT
from crypto_lab.persistence.migration_runner import (
    RevisionState,
    check_revision,
    schema_objects,
)
from crypto_lab.persistence.schema import EXPECTED_SCHEMA_OBJECTS
from crypto_lab.persistence.unit_of_work import SqliteUnitOfWork
from doubles.experiments import INSTANT, FixedClock, sample_experiment
from persistence_support.harness import (
    SqliteHarness,
    code,
    open_test_database,
    put_experiment,
)

_E: Final = ExperimentState
#: Plan Task 6 Step 1: one line -- open the path with ``sqlite3``,
#: ``isolation_level=None``, ``BEGIN IMMEDIATE``, the throwaway table and its row,
#: print ``HELD``, flush, block on stdin. The child never commits.
HOLDING_WRITER_PROGRAM: Final = (
    "import sqlite3, sys; "
    "connection = sqlite3.connect(sys.argv[1], isolation_level=None); "
    "connection.execute('BEGIN IMMEDIATE'); "
    "connection.execute('CREATE TABLE crash_probe (x INTEGER)'); "
    "connection.execute('INSERT INTO crash_probe VALUES (1)'); "
    "sys.stdout.write('HELD\\n'); "
    "sys.stdout.flush(); "
    "sys.stdin.readline()"
)
#: Plan 5.3: the fixture's lock-wait observation budget (twenty times the
#: configured 100 ms busy timeout) and the lower bound proving the wait happened.
_LOCK_WAIT_LOWER_BOUND_SECONDS: Final = 0.05
_LOCK_WAIT_BUDGET_SECONDS: Final = 2.0


def _sidecars(path: Path) -> tuple[bool, bool]:
    """Whether the ``-wal`` and ``-shm`` files exist beside the database."""
    return (
        path.with_name(path.name + "-wal").exists(),
        path.with_name(path.name + "-shm").exists(),
    )


def test_an_interrupted_writer_leaves_no_partial_row_after_reopen(
    tmp_path: Path,
) -> None:
    database = open_test_database(tmp_path, clock=FixedClock(INSTANT))
    put_experiment(SqliteHarness(database), sample_experiment(_E.DRAFT))
    database.close()
    child = subprocess.Popen(  # noqa: S603 - reviewed list argv, no shell
        [sys.executable, "-I", "-B", "-c", HOLDING_WRITER_PROGRAM, str(database.path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        shell=False,
    )
    try:
        assert child.stdout is not None
        assert child.stdout.readline().strip() == b"HELD"
        blocked = open_test_database(tmp_path, clock=FixedClock(INSTANT))
        try:
            transaction = SqliteUnitOfWork(blocked, FixedClock(INSTANT)).begin()
            assert (
                code(transaction.experiments.add(sample_experiment(_E.VALIDATED)))
                == CONCURRENCY_CONFLICT
            )
            transaction.rollback()
        finally:
            blocked.close()
    finally:
        child.kill()
        child.wait(timeout=30)
    reopened = open_test_database(tmp_path, clock=FixedClock(INSTANT))
    try:
        assert SqliteHarness(reopened).committed_experiments() == (
            sample_experiment(_E.DRAFT),
        )
        with reopened.read_only() as connection:
            names = {row.name for row in schema_objects(connection)}
            assert "crash_probe" not in names
            assert check_revision(connection).state is RevisionState.CURRENT
        assert reopened.consistency_report().foreign_key_violations == 0
    finally:
        reopened.close()


def test_the_lock_of_another_process_is_a_bounded_conflict_and_the_file_recovers(
    tmp_path: Path,
) -> None:
    """C-17's Windows half (plan 5.3, 7.5): the parent's writer waits at least the
    configured timeout and below the fixture budget; after the child is killed and
    awaited, the sidecars it left are tolerated, the schema equals the pinned set,
    ``quick_check`` is ``ok`` and the journal mode is still ``wal``."""
    database = open_test_database(tmp_path, clock=FixedClock(INSTANT))
    stored = sample_experiment(_E.DRAFT)
    put_experiment(SqliteHarness(database), stored)
    database.close()
    path = database.path
    with subprocess.Popen(  # noqa: S603 - reviewed list argv, no shell
        [sys.executable, "-I", "-B", "-c", HOLDING_WRITER_PROGRAM, str(path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        shell=False,
    ) as child:
        try:
            assert child.stdout is not None
            assert child.stdout.readline().strip() == b"HELD"
            assert child.poll() is None
            blocked = open_test_database(tmp_path, clock=FixedClock(INSTANT))
            try:
                transaction = SqliteUnitOfWork(blocked, FixedClock(INSTANT)).begin()
                started = time.perf_counter()
                refused = transaction.experiments.add(sample_experiment(_E.VALIDATED))
                elapsed = time.perf_counter() - started
                assert code(refused) == CONCURRENCY_CONFLICT
                assert (
                    _LOCK_WAIT_LOWER_BOUND_SECONDS
                    <= elapsed
                    < (_LOCK_WAIT_BUDGET_SECONDS)
                )
                # The refused writer stays usable and reads its own snapshot.
                assert transaction.open_failure() is None
                assert SqliteHarness(blocked).committed_experiments() == (stored,)
                transaction.rollback()
            finally:
                blocked.close()
        finally:
            child.kill()
            child.wait(timeout=30)
    assert child.returncode is not None
    # The interrupted writer's sidecars may survive; the reopen tolerates them.
    wal_present, _ = _sidecars(path)
    assert wal_present
    reopened = open_test_database(tmp_path, clock=FixedClock(INSTANT))
    try:
        assert SqliteHarness(reopened).committed_experiments() == (stored,)
        with reopened.read_only() as connection:
            assert schema_objects(connection) == EXPECTED_SCHEMA_OBJECTS
            assert check_revision(connection).state is RevisionState.CURRENT
            assert connection.execute(text("PRAGMA quick_check")).scalar_one() == "ok"
            assert connection.execute(text("PRAGMA journal_mode")).scalar_one() == "wal"
        report = reopened.consistency_report()
        assert report.foreign_key_violations == 0
        assert report.spec_projection_mismatches == 0
    finally:
        reopened.close()
