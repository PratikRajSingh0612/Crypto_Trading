"""The SQLite database boundary: ``SqliteDatabase`` (plan Task 1, sections 6.1-6.5).

The engine, the PRAGMA policy and its read-back, connection lifetime, read-only
sessions, DBAPI-error classification, path composition and the identity and
integrity checks of an open, proven against real temporary databases and
separate connections: the library probes of plan section 2.8 and cases C-15,
C-16, C-19 and C-20 of section 5.1, plus the Windows platform cases of section
7.5 that Task 1 owns (spaces and Unicode in the path, the held lock, the
read-only session). Task 6 adds case C-18 (the read-only attribute) and the
deferred I/O-class handler tests: injected driver faults at the cursor and
dialect-commit boundaries exercising every ``except DBAPIError`` handler of the
lifecycle repositories and the unit of work, each labelled as injected rather than
physical (plan 4.2, 6.5). The final section pins the plan section 2.6 guard
expectations Task 1 trips.

Declared readings, so nothing is inferred silently:

- ``SqliteDatabase.open`` accepts the pool parameters as keyword-only arguments
  with the section 6.1 defaults, so the pool-of-one probe is constructible
  without a private hook; production callers never pass them.
- ``classify`` also accepts the pool's own checkout-timeout error, which is not a
  DBAPI error, and maps it to ``PERSISTENCE.STORAGE_UNAVAILABLE`` so this task can
  prove the mapping; Task 4's ``begin()`` keeps its own branch for it.
- ``SQLITE_CANTOPEN`` classifies as ``PERSISTENCE.WRITE_FAILED`` (its write-time
  meaning, section 6.5); ``open`` collapses every non-conflict refusal to
  ``PERSISTENCE.STORAGE_UNAVAILABLE`` because an open performs no write, so the
  same code observed at open is storage unavailability.
"""

from __future__ import annotations

import ast
import os
import sqlite3
import stat
import threading
import time
import tomllib
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import DBAPIError, IntegrityError, OperationalError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError
from sqlalchemy.pool import QueuePool

from crypto_lab.artifacts.ownership import SystemArtifactOwner
from crypto_lab.configuration.models import ApplicationConfig, DatabaseConfig
from crypto_lab.configuration.snapshot import snapshot_configuration
from crypto_lab.domain.diagnostics import DiagnosticCategory
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.persistence import database as database_module
from crypto_lab.persistence.database import (
    APPLICATION_ID,
    SqliteDatabase,
    database_path,
)
from crypto_lab.persistence.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
    MIGRATION_MISMATCH,
    STORAGE_UNAVAILABLE,
    WRITE_FAILED,
    persistence_failure,
)
from crypto_lab.persistence.migration_runner import open_database
from crypto_lab.persistence.registries import SqliteDiagnosticRecorder
from crypto_lab.persistence.unit_of_work import SqliteTransaction, SqliteUnitOfWork
from doubles.experiments import (
    AVAIL_A,
    AVAIL_B,
    DIAG_ID,
    EXPERIMENT_ID,
    INSTANT,
    INVOCATION_ID,
    OTHER_DIAG_ID,
    RUN_ID,
    SLOT_A,
    FixedClock,
    sample_diagnostic,
    sample_experiment,
    sample_invocation,
    sample_observation,
    sample_retry_decision,
    sample_run,
)
from persistence_support.harness import (
    SqliteHarness,
    accept_any_revision,
    bump,
    bump_invocation,
    bump_run,
    code,
    commit,
    file_sha256,
    ok,
    open_test_database,
    put_invocation,
    put_lifecycle_parents,
    raw_connection,
    sample_dataset_with_partitions,
    sample_run_event,
    sample_strategy_version,
)

_REPOSITORY = Path(__file__).resolve().parents[3]
_STAGE3_GUARD = _REPOSITORY / "tests/safety/test_stage3_boundaries.py"
_STAGE5_GUARD = _REPOSITORY / "tests/safety/test_stage5_boundaries.py"
_STAGE7_GUARD = _REPOSITORY / "tests/safety/test_stage7_boundaries.py"
_DEPENDENCY_GUARD = _REPOSITORY / "tests/safety/test_project_dependencies.py"
_TOOLING_GUARD = _REPOSITORY / "tests/safety/test_gitnexus_development_tooling.py"
_ARCHITECTURE_GUARD = (
    _REPOSITORY / "tests/architecture/test_package_import_boundaries.py"
)
_PACKAGE_LAYOUT = _REPOSITORY / "tests/unit/test_package_layout.py"
_PREFLIGHT_TESTS = (
    _REPOSITORY / "tests/unit/process_supervision/test_supervisor_preflight.py"
)
_RECONCILIATION_TESTS = (
    _REPOSITORY / "tests/unit/process_supervision/test_restart_reconciliation.py"
)
_VERIFICATION_GUIDE = _REPOSITORY / "docs/development/verification.md"
#: A foreign ``application_id`` (``0x12345678``) for C-20 (a).
_FOREIGN_APPLICATION_ID = 305419896
#: The wrapped "Dependency changes" clause Task 1 rewords (plan 1.6 item 9), in
#: the ruled wording: the preceding exclusions stay, "database stack" leaves the
#: list, and the two new sentences name the only permitted direct database-stack
#: dependencies and their gate without the literal the containment guard forbids.
_DEPENDENCY_SENTENCE = "\n".join(
    (
        "No dependency operation may install an engine, exchange client, networking",
        "client, or GitNexus. SQLAlchemy and Alembic are the only permitted direct",
        "database-stack dependencies. Their acquisition is subject to the approved",
        "SQLite persistence gates; ordinary verification remains offline.",
    )
)


# --------------------------------------------------------------------------
# Module-local helpers (plan 7.1: ``_pragma`` is Task 1's module-local name)
# --------------------------------------------------------------------------


def _pragma(connection: Connection, name: str) -> object:
    value: object = connection.execute(text(f"PRAGMA {name}")).scalar_one()
    return value


def _dbapi(connection: Connection) -> sqlite3.Connection:
    dbapi = connection.connection.dbapi_connection
    assert isinstance(dbapi, sqlite3.Connection)
    return dbapi


def _errorcode(error: DBAPIError) -> int:
    original = error.orig
    assert isinstance(original, sqlite3.Error)
    return original.sqlite_errorcode


def _synthesized(sqlite_errorcode: int, sqlite_errorname: str) -> DBAPIError:
    """A wrapped DBAPI error carrying one extended result code (plan 2.8 row 4)."""
    original = sqlite3.OperationalError("synthesized")
    original.sqlite_errorcode = sqlite_errorcode
    original.sqlite_errorname = sqlite_errorname
    return OperationalError("INSERT INTO probe VALUES (1)", None, original)


def _open(path: Path, clock: FixedClock) -> Result[SqliteDatabase]:
    return SqliteDatabase.open(
        path,
        busy_timeout_ms=100,
        clock=clock,
        revision_policy=accept_any_revision,
    )


def _rows(connection: Connection, statement: str) -> list[tuple[object, ...]]:
    return [tuple(row) for row in connection.execute(text(statement)).all()]


def _details(result: object) -> dict[str, object]:
    assert isinstance(result, Failure)
    (diagnostic,) = result.diagnostics
    return dict(diagnostic.details)


def _literal(path: Path, name: str) -> Any:
    """The literal assigned to ``name`` at module level, ``frozenset`` unwrapped."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        if value is None or not any(
            isinstance(target, ast.Name) and target.id == name for target in targets
        ):
            continue
        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "frozenset"
            and len(value.args) == 1
        ):
            return frozenset(ast.literal_eval(value.args[0]))
        return ast.literal_eval(value)
    raise AssertionError(f"{name} is not assigned a literal in {path}")


# --------------------------------------------------------------------------
# Path composition and the open (plan 6.2 steps 1-5; C-19, C-20)
# --------------------------------------------------------------------------


def test_database_path_is_a_pure_join_of_runtime_root_and_filename() -> None:
    config = DatabaseConfig()
    assert database_path(Path("C:/lab/runtime"), config) == Path(
        "C:/lab/runtime/crypto_lab.sqlite3"
    )
    with pytest.raises(ValueError, match="absolute"):
        database_path(Path("runtime"), config)


def test_database_path_honours_a_configured_filename() -> None:
    config = DatabaseConfig(filename="registry.sqlite3")
    assert database_path(Path("C:/lab/runtime"), config) == Path(
        "C:/lab/runtime/registry.sqlite3"
    )


def test_open_applies_and_reads_back_every_pragma(tmp_path: Path) -> None:
    opened = SqliteDatabase.open(
        tmp_path / "x.sqlite3",
        busy_timeout_ms=100,
        clock=FixedClock(INSTANT),
        revision_policy=accept_any_revision,
    )
    assert isinstance(opened, Success)
    with opened.value.connection() as connection:
        assert _pragma(connection, "journal_mode") == "wal"
        assert _pragma(connection, "foreign_keys") == 1
        assert _pragma(connection, "synchronous") == 2
        assert _pragma(connection, "busy_timeout") == 100
    opened.value.close()


def test_open_exposes_the_absolute_path_and_the_configured_timeout(
    tmp_path: Path,
) -> None:
    path = tmp_path / "exposed.sqlite3"
    database = ok(
        SqliteDatabase.open(
            path,
            busy_timeout_ms=250,
            clock=FixedClock(INSTANT),
            revision_policy=accept_any_revision,
        )
    )
    try:
        assert database.path == path
        assert database.path.is_absolute()
        assert database.busy_timeout_ms == 250
        with database.connection() as connection:
            assert _pragma(connection, "busy_timeout") == 250
            assert _dbapi(connection).isolation_level is None
    finally:
        database.close()
        database.close()


def test_open_never_creates_a_directory(tmp_path: Path) -> None:
    missing = tmp_path / "absent" / "x.sqlite3"
    opened = SqliteDatabase.open(
        missing,
        busy_timeout_ms=100,
        clock=FixedClock(INSTANT),
        revision_policy=accept_any_revision,
    )
    assert code(opened) == STORAGE_UNAVAILABLE
    assert not missing.parent.exists()


def test_open_refuses_a_relative_path_and_a_directory(tmp_path: Path) -> None:
    relative = _open(Path("relative.sqlite3"), FixedClock(INSTANT))
    assert code(relative) == STORAGE_UNAVAILABLE
    assert not Path("relative.sqlite3").exists()
    directory = _open(tmp_path, FixedClock(INSTANT))
    assert code(directory) == STORAGE_UNAVAILABLE
    assert _details(directory) == {"operation": "open"}
    assert sorted(path.name for path in tmp_path.iterdir()) == []


def test_open_refuses_an_out_of_range_busy_timeout(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="busy_timeout_ms"):
        SqliteDatabase.open(
            tmp_path / "x.sqlite3",
            busy_timeout_ms=99,
            clock=FixedClock(INSTANT),
            revision_policy=accept_any_revision,
        )
    assert not (tmp_path / "x.sqlite3").exists()


def test_a_foreign_or_corrupt_file_is_refused_without_mutation(
    tmp_path: Path,
) -> None:
    corrupt = tmp_path / "corrupt.sqlite3"
    corrupt.write_bytes(b"not a database" * 64)
    before = file_sha256(corrupt)
    opened = SqliteDatabase.open(
        corrupt,
        busy_timeout_ms=100,
        clock=FixedClock(INSTANT),
        revision_policy=accept_any_revision,
    )
    assert code(opened) == STORAGE_UNAVAILABLE
    assert file_sha256(corrupt) == before


def test_a_corrupt_file_refusal_names_the_sqlite_result_code(tmp_path: Path) -> None:
    corrupt = tmp_path / "corrupt.sqlite3"
    corrupt.write_bytes(b"not a database" * 64)

    opened = _open(corrupt, FixedClock(INSTANT))

    assert isinstance(opened, Failure)
    (diagnostic,) = opened.diagnostics
    assert diagnostic.error_code == STORAGE_UNAVAILABLE
    assert diagnostic.category is DiagnosticCategory.PERSISTENCE
    assert diagnostic.retriable is False
    assert diagnostic.timestamp_utc == INSTANT
    assert diagnostic.details == {
        "operation": "open",
        "sqlite_errorcode": 26,
        "sqlite_errorname": "SQLITE_NOTADB",
    }


def test_a_foreign_application_id_is_refused_without_mutation(tmp_path: Path) -> None:
    """C-20 (a): a valid SQLite file that another application owns."""
    path = tmp_path / "foreign.sqlite3"
    holder = raw_connection(path)
    try:
        holder.execute(f"PRAGMA application_id = {_FOREIGN_APPLICATION_ID}")
        holder.execute("CREATE TABLE foreign_table (x INTEGER)")
    finally:
        holder.close()
    before = file_sha256(path)

    opened = _open(path, FixedClock(INSTANT))

    assert code(opened) == STORAGE_UNAVAILABLE
    assert _details(opened) == {
        "operation": "open",
        "application_id": _FOREIGN_APPLICATION_ID,
    }
    assert file_sha256(path) == before
    reader = raw_connection(path)
    try:
        assert reader.execute("PRAGMA journal_mode").fetchone() == ("delete",)
    finally:
        reader.close()


def test_an_unstamped_file_with_user_tables_is_refused_without_mutation(
    tmp_path: Path,
) -> None:
    """Plan 6.2 step 3: ``application_id`` 0 is an empty candidate only without
    user tables; a populated unstamped file is foreign."""
    path = tmp_path / "unstamped.sqlite3"
    holder = raw_connection(path)
    try:
        holder.execute("CREATE TABLE somebody_elses (x INTEGER)")
    finally:
        holder.close()
    before = file_sha256(path)

    opened = _open(path, FixedClock(INSTANT))

    assert code(opened) == STORAGE_UNAVAILABLE
    assert _details(opened) == {"operation": "open", "application_id": 0}
    assert file_sha256(path) == before


def test_a_file_stamped_with_our_application_id_opens(tmp_path: Path) -> None:
    path = tmp_path / "ours.sqlite3"
    holder = raw_connection(path)
    try:
        holder.execute(f"PRAGMA application_id = {APPLICATION_ID}")
        holder.execute("CREATE TABLE ours (x INTEGER)")
    finally:
        holder.close()

    database = ok(_open(path, FixedClock(INSTANT)))
    try:
        with database.read_only() as reader:
            assert _pragma(reader, "application_id") == APPLICATION_ID
            assert _pragma(reader, "journal_mode") == "wal"
    finally:
        database.close()


def test_a_quick_check_failure_is_storage_unavailable(tmp_path: Path) -> None:
    """Plan 6.2 step 5: a stamped, WAL-mode file whose pages no longer verify."""
    path = tmp_path / "damaged.sqlite3"
    database = ok(_open(path, FixedClock(INSTANT)))
    try:
        with database.connection() as connection:
            connection.execute(
                text(
                    "CREATE TABLE probe (x INTEGER PRIMARY KEY, payload TEXT NOT NULL)"
                )
            )
            for index in range(200):
                connection.execute(
                    text("INSERT INTO probe VALUES (:x, :payload)"),
                    {"x": index, "payload": f"{index:04d}" * 50},
                )
            connection.commit()
    finally:
        database.close()
    stamper = raw_connection(path)
    try:
        stamper.execute(f"PRAGMA application_id = {APPLICATION_ID}")
        page_count = stamper.execute("PRAGMA page_count").fetchone()
        freelist = stamper.execute("PRAGMA freelist_count").fetchone()
    finally:
        stamper.close()
    assert page_count is not None
    assert page_count[0] >= 4
    assert freelist == (0,)
    # Header bytes 32..35 hold the first freelist trunk page (0: none) and 36..39
    # the freelist page count. Claiming seven freelist pages that do not exist
    # keeps the header openable but makes ``quick_check`` report the mismatch
    # as a row instead of ``ok`` (a trashed page would raise ``SQLITE_CORRUPT``
    # instead, which is the DBAPI-error path of ``open``).
    with path.open("r+b") as handle:
        handle.seek(32)
        assert handle.read(4) == b"\x00\x00\x00\x00"
        handle.seek(36)
        handle.write(b"\x00\x00\x00\x07")
    before = file_sha256(path)

    opened = _open(path, FixedClock(INSTANT))

    assert code(opened) == STORAGE_UNAVAILABLE
    details = _details(opened)
    assert details["operation"] == "quick_check", details
    assert isinstance(details["quick_check"], str)
    assert details["quick_check"] != "ok"
    assert "freelist" in details["quick_check"].lower()
    assert file_sha256(path) == before


def test_a_pragma_read_back_mismatch_is_storage_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Plan 6.1: a mismatch closes the connection and fails the caller."""
    monkeypatch.setattr(database_module, "_EXPECTED_SYNCHRONOUS", 3)

    opened = _open(tmp_path / "mismatch.sqlite3", FixedClock(INSTANT))

    assert code(opened) == STORAGE_UNAVAILABLE
    assert _details(opened) == {
        "operation": "connect",
        "setting": "synchronous",
        "expected": 3,
        "actual": 2,
    }


def test_an_open_time_cantopen_is_storage_unavailable(tmp_path: Path) -> None:
    """``SQLITE_CANTOPEN`` is a write failure at a statement and storage
    unavailability at open (plan 6.5): an invalid Windows filename cannot open."""
    opened = _open(tmp_path / "in<valid>.sqlite3", FixedClock(INSTANT))

    assert code(opened) == STORAGE_UNAVAILABLE
    details = _details(opened)
    assert details["operation"] == "open"
    assert details["sqlite_errorcode"] == 14
    assert details["sqlite_errorname"] == "SQLITE_CANTOPEN"
    assert SqliteDatabase.classify(_synthesized(14, "SQLITE_CANTOPEN")) == WRITE_FAILED


def test_a_locked_file_at_open_is_a_bounded_conflict(tmp_path: Path) -> None:
    """A writer lock held by another connection while the open switches the
    journal mode is the retriable ``PERSISTENCE.CONCURRENCY_CONFLICT``
    (``SQLITE_BUSY``), not storage unavailability; the open succeeds once the
    holder releases. The refusal is bounded above by the fixture budget only:
    SQLite returns ``SQLITE_BUSY`` without invoking the busy handler when a
    connection holding a shared lock tries to promote it while another holds the
    reserved lock (its deadlock-avoidance rule), so no lower bound is asserted."""
    path = tmp_path / "locked.sqlite3"
    stamper = raw_connection(path)
    try:
        stamper.execute(f"PRAGMA application_id = {APPLICATION_ID}")
    finally:
        stamper.close()
    holder = raw_connection(path)
    try:
        holder.execute("BEGIN IMMEDIATE")
        started = time.perf_counter()
        refused = _open(path, FixedClock(INSTANT))
        elapsed = time.perf_counter() - started
        assert code(refused) == CONCURRENCY_CONFLICT
        details = _details(refused)
        assert details["operation"] == "open"
        assert details["sqlite_errorcode"] == 5
        assert details["sqlite_errorname"] == "SQLITE_BUSY"
        assert elapsed < 2.0
        holder.execute("ROLLBACK")
    finally:
        holder.close()

    database = ok(_open(path, FixedClock(INSTANT)))
    try:
        with database.read_only() as reader:
            assert _pragma(reader, "journal_mode") == "wal"
    finally:
        database.close()


def test_the_revision_policy_runs_last_and_its_failure_closes_the_open(
    tmp_path: Path,
) -> None:
    """Plan 6.2 step 6: the policy sees the verified connection and its
    ``Failure`` is returned unchanged; nothing stays checked out."""
    seen: list[tuple[Connection, object]] = []
    clock = FixedClock(INSTANT)

    def refusing(connection: Connection) -> Result[None]:
        seen.append((connection, _pragma(connection, "journal_mode")))
        return persistence_failure(
            MIGRATION_MISMATCH, message="database is behind head", clock=clock
        )

    opened = SqliteDatabase.open(
        tmp_path / "policy.sqlite3",
        busy_timeout_ms=100,
        clock=clock,
        revision_policy=refusing,
    )

    assert code(opened) == MIGRATION_MISMATCH
    assert isinstance(opened, Failure)
    assert opened.diagnostics[0].message == "database is behind head"
    ((connection, journal_mode),) = seen
    assert journal_mode == "wal"
    assert connection.closed


def test_a_raising_revision_policy_propagates_after_the_engine_is_disposed(
    tmp_path: Path,
) -> None:
    """A policy that raises is a programmer defect: the exception propagates
    unchanged and the engine the open built is disposed first, so the file is
    reopenable afterwards."""
    path = tmp_path / "raising.sqlite3"

    def raising(connection: Connection) -> Result[None]:
        del connection
        raise RuntimeError("policy defect")

    with pytest.raises(RuntimeError, match="policy defect"):
        SqliteDatabase.open(
            path,
            busy_timeout_ms=100,
            clock=FixedClock(INSTANT),
            revision_policy=raising,
        )

    database = ok(_open(path, FixedClock(INSTANT)))
    try:
        with database.read_only() as reader:
            assert _pragma(reader, "journal_mode") == "wal"
    finally:
        database.close()


def test_journal_mode_persists_in_the_file_across_a_reopen(tmp_path: Path) -> None:
    """Plan 6.1: WAL is persistent in the file; the other settings are per connection
    and re-applied on every physical connect."""
    path = tmp_path / "persist.sqlite3"
    first = ok(_open(path, FixedClock(INSTANT)))
    first.close()
    raw = raw_connection(path)
    try:
        assert raw.execute("PRAGMA journal_mode").fetchone() == ("wal",)
        assert raw.execute("PRAGMA foreign_keys").fetchone() == (0,)
    finally:
        raw.close()

    second = ok(_open(path, FixedClock(INSTANT)))
    try:
        with second.connection() as connection:
            assert _pragma(connection, "journal_mode") == "wal"
            assert _pragma(connection, "foreign_keys") == 1
            assert _pragma(connection, "synchronous") == 2
            assert _pragma(connection, "busy_timeout") == 100
    finally:
        second.close()


def test_a_path_with_spaces_and_unicode_components_opens(tmp_path: Path) -> None:
    """Plan 7.5: Windows paths with spaces and Unicode components open and
    round-trip through an independent connection."""
    directory = tmp_path / "läb data ü"
    directory.mkdir()
    path = directory / "crypto läb.sqlite3"

    database = ok(_open(path, FixedClock(INSTANT)))
    try:
        assert database.path == path
        with database.connection() as connection:
            connection.execute(text("CREATE TABLE probe (x INTEGER PRIMARY KEY)"))
            connection.execute(text("INSERT INTO probe VALUES (7)"))
            connection.commit()
        with database.read_only() as reader:
            assert _rows(reader, "SELECT x FROM probe") == [(7,)]
        independent = raw_connection(path)
        try:
            assert independent.execute("SELECT x FROM probe").fetchall() == [(7,)]
            assert independent.execute("PRAGMA journal_mode").fetchone() == ("wal",)
        finally:
            independent.close()
    finally:
        database.close()


# --------------------------------------------------------------------------
# Connections, the writer lock and the snapshot (plan 2.8 probes; C-15, C-16)
# --------------------------------------------------------------------------


def test_a_held_writer_lock_fails_the_writer_as_a_bounded_conflict(
    bare_database: SqliteDatabase,
) -> None:
    # bare_database (§7.1): an unmigrated file opened with accept_any_revision;
    # the probe table is throwaway, so no Task 2 schema is needed here.
    holder = raw_connection(bare_database.path)
    try:
        holder.execute("BEGIN IMMEDIATE")
        started = time.perf_counter()
        with bare_database.connection() as connection:
            with pytest.raises(OperationalError) as caught:
                connection.execute(text("CREATE TABLE probe (x INTEGER)"))
        elapsed = time.perf_counter() - started
        assert bare_database.classify(caught.value) == CONCURRENCY_CONFLICT
        assert 0.05 <= elapsed < 2.0
    finally:
        holder.close()


def test_a_held_writer_lock_leaves_the_writer_usable(
    bare_database: SqliteDatabase,
) -> None:
    """C-15's second half: the refused writer rolls back and proceeds once the
    holder releases; the busy error carries ``SQLITE_BUSY`` (5)."""
    holder = raw_connection(bare_database.path)
    try:
        holder.execute("BEGIN IMMEDIATE")
        with bare_database.connection() as connection:
            with pytest.raises(OperationalError) as caught:
                connection.execute(text("CREATE TABLE probe (x INTEGER)"))
            assert _errorcode(caught.value) == 5
            holder.execute("ROLLBACK")
            connection.rollback()
            connection.execute(text("CREATE TABLE probe (x INTEGER)"))
            connection.commit()
        with bare_database.read_only() as reader:
            assert _rows(reader, "SELECT count(*) FROM probe") == [(0,)]
    finally:
        holder.close()


def test_a_stale_snapshot_write_is_refused_immediately(
    bare_database: SqliteDatabase,
) -> None:
    with bare_database.connection() as setup:
        setup.execute(text("CREATE TABLE probe (x INTEGER PRIMARY KEY, y INTEGER)"))
        setup.execute(text("INSERT INTO probe VALUES (1, 0)"))
        setup.commit()
    with bare_database.connection() as reader:
        # The first statement autobegins the deferred transaction (§2.8 recipe).
        assert reader.execute(text("SELECT y FROM probe")).scalar_one() == 0
        other = raw_connection(bare_database.path)
        try:
            other.execute("UPDATE probe SET y = 1 WHERE x = 1")
            other.commit()
        finally:
            other.close()
        started = time.perf_counter()
        with pytest.raises(OperationalError) as caught:
            reader.execute(text("UPDATE probe SET y = 2 WHERE x = 1"))
        elapsed = time.perf_counter() - started
        assert isinstance(caught.value.orig, sqlite3.Error)
        assert caught.value.orig.sqlite_errorcode == 517
        assert bare_database.classify(caught.value) == CONCURRENCY_CONFLICT
        assert elapsed < 0.1
        # The refused statement did not end the transaction.
        assert reader.execute(text("SELECT y FROM probe")).scalar_one() == 0


def test_a_refused_insert_leaves_the_transaction_open_for_a_later_commit(
    bare_database: SqliteDatabase,
) -> None:
    """Plan 2.5 reading 3: a constraint refusal aborts the statement alone."""
    with bare_database.connection() as setup:
        setup.execute(text("CREATE TABLE probe (x INTEGER PRIMARY KEY)"))
        setup.execute(text("INSERT INTO probe VALUES (1)"))
        setup.commit()
    with bare_database.connection() as connection:
        with pytest.raises(IntegrityError) as caught:
            connection.execute(text("INSERT INTO probe VALUES (1)"))
        assert _errorcode(caught.value) == 1555
        assert bare_database.classify(caught.value) == CONCURRENCY_CONFLICT
        assert _dbapi(connection).in_transaction
        connection.execute(text("INSERT INTO probe VALUES (2)"))
        connection.commit()
        assert not _dbapi(connection).in_transaction
    with bare_database.read_only() as reader:
        assert _rows(reader, "SELECT x FROM probe ORDER BY x") == [(1,), (2,)]


def test_unique_and_primary_key_violations_are_conflicts(
    bare_database: SqliteDatabase,
) -> None:
    with bare_database.connection() as setup:
        setup.execute(
            text("CREATE TABLE probe (x INTEGER PRIMARY KEY, y TEXT NOT NULL)")
        )
        setup.execute(text("CREATE UNIQUE INDEX probe_y ON probe (y)"))
        setup.execute(text("INSERT INTO probe VALUES (1, 'one')"))
        setup.commit()
    with bare_database.connection() as connection:
        with pytest.raises(IntegrityError) as primary:
            connection.execute(text("INSERT INTO probe VALUES (1, 'other')"))
        assert _errorcode(primary.value) == 1555
        assert bare_database.classify(primary.value) == CONCURRENCY_CONFLICT
        with pytest.raises(IntegrityError) as unique:
            connection.execute(text("INSERT INTO probe VALUES (2, 'one')"))
        assert _errorcode(unique.value) == 2067
        assert bare_database.classify(unique.value) == CONCURRENCY_CONFLICT
        connection.execute(text("INSERT INTO probe VALUES (2, 'two')"))
        connection.commit()
    with bare_database.read_only() as reader:
        assert _rows(reader, "SELECT x, y FROM probe ORDER BY x") == [
            (1, "one"),
            (2, "two"),
        ]


def test_foreign_key_check_trigger_and_not_null_violations_are_invariants(
    bare_database: SqliteDatabase,
) -> None:
    with bare_database.connection() as setup:
        setup.execute(text("CREATE TABLE parent (id INTEGER PRIMARY KEY)"))
        setup.execute(
            text(
                "CREATE TABLE child ("
                "id INTEGER PRIMARY KEY, "
                "parent_id INTEGER NOT NULL REFERENCES parent (id), "
                "amount INTEGER NOT NULL CHECK (amount > 0), "
                "label TEXT NOT NULL)"
            )
        )
        setup.execute(
            text(
                "CREATE TRIGGER refuse_label BEFORE INSERT ON child "
                "WHEN NEW.label = 'refused' "
                "BEGIN SELECT RAISE(ABORT, 'test: label refused'); END"
            )
        )
        setup.execute(text("INSERT INTO parent VALUES (1)"))
        setup.commit()
    with bare_database.connection() as connection:
        for statement, expected in (
            ("INSERT INTO child VALUES (1, 99, 1, 'ok')", 787),
            ("INSERT INTO child VALUES (2, 1, 0, 'ok')", 275),
            ("INSERT INTO child VALUES (3, 1, 1, 'refused')", 1811),
            ("INSERT INTO child (id, parent_id, amount) VALUES (4, 1, 1)", 1299),
        ):
            with pytest.raises(IntegrityError) as caught:
                connection.execute(text(statement))
            assert _errorcode(caught.value) == expected, statement
            assert bare_database.classify(caught.value) == INVARIANT_VIOLATION
        connection.execute(text("INSERT INTO child VALUES (5, 1, 1, 'ok')"))
        connection.commit()
    with bare_database.read_only() as reader:
        assert _rows(reader, "SELECT id FROM child") == [(5,)]


def test_a_savepoint_rolls_back_exactly_the_statements_after_it(
    bare_database: SqliteDatabase,
) -> None:
    """Plan 2.8: ``INSERT``, ``SAVEPOINT``, ``INSERT``, refused ``INSERT``,
    ``ROLLBACK TO``, ``COMMIT`` -- only the first row is durable."""
    with bare_database.connection() as setup:
        setup.execute(text("CREATE TABLE probe (x INTEGER PRIMARY KEY)"))
        setup.commit()
    with bare_database.connection() as connection:
        connection.execute(text("INSERT INTO probe VALUES (1)"))
        nested = connection.begin_nested()
        connection.execute(text("INSERT INTO probe VALUES (2)"))
        with pytest.raises(IntegrityError) as caught:
            connection.execute(text("INSERT INTO probe VALUES (1)"))
        assert bare_database.classify(caught.value) == CONCURRENCY_CONFLICT
        nested.rollback()
        connection.commit()
    with bare_database.read_only() as reader:
        assert _rows(reader, "SELECT x FROM probe ORDER BY x") == [(1,)]


def test_a_dropped_connection_rolls_back_its_open_transaction(
    bare_database: SqliteDatabase,
) -> None:
    """Leaving the ``connection()`` block without ``commit()`` publishes nothing."""
    with bare_database.connection() as setup:
        setup.execute(text("CREATE TABLE probe (x INTEGER PRIMARY KEY)"))
        setup.commit()
    with bare_database.connection() as abandoned:
        abandoned.execute(text("INSERT INTO probe VALUES (1)"))
    with bare_database.read_only() as reader:
        assert _rows(reader, "SELECT count(*) FROM probe") == [(0,)]


def test_a_pooled_connection_reused_from_a_second_thread_keeps_its_pragmas(
    bare_database: SqliteDatabase,
) -> None:
    """Plan 2.8: ``check_same_thread=False``; the PRAGMAs applied on the physical
    connect persist for the connection's life."""
    with bare_database.connection() as first:
        physical = _dbapi(first)
        assert _pragma(first, "busy_timeout") == 100
    observed: dict[str, object] = {}

    def worker() -> None:
        with bare_database.connection() as second:
            observed["same_physical_connection"] = _dbapi(second) is physical
            observed["journal_mode"] = _pragma(second, "journal_mode")
            observed["foreign_keys"] = _pragma(second, "foreign_keys")
            observed["synchronous"] = _pragma(second, "synchronous")
            observed["busy_timeout"] = _pragma(second, "busy_timeout")

    thread = threading.Thread(target=worker, name="pool-reuse-probe")
    thread.start()
    thread.join(timeout=10)
    assert not thread.is_alive()
    assert observed == {
        "same_physical_connection": True,
        "journal_mode": "wal",
        "foreign_keys": 1,
        "synchronous": 2,
        "busy_timeout": 100,
    }


def test_a_pool_of_one_refuses_a_second_checkout_within_the_pool_timeout(
    tmp_path: Path,
) -> None:
    """Plan 2.8: exhaustion raises the pool's own timeout error, not a DBAPI error,
    after the checkout timeout; it classifies as storage unavailability."""
    database = ok(
        SqliteDatabase.open(
            tmp_path / "pool.sqlite3",
            busy_timeout_ms=100,
            clock=FixedClock(INSTANT),
            revision_policy=accept_any_revision,
            pool_size=1,
            max_overflow=0,
            pool_timeout_seconds=0.2,
        )
    )

    def second_checkout() -> None:
        with database.connection():
            raise AssertionError("a second checkout must not succeed")

    try:
        with database.connection():
            started = time.perf_counter()
            with pytest.raises(PoolTimeoutError) as caught:
                second_checkout()
            elapsed = time.perf_counter() - started
        assert not isinstance(caught.value, DBAPIError)
        assert 0.1 <= elapsed < 2.0
        assert database.classify(caught.value) == STORAGE_UNAVAILABLE
        with database.connection() as recovered:
            assert _pragma(recovered, "journal_mode") == "wal"
    finally:
        database.close()


def test_read_only_performs_no_write_and_never_blocks_a_writer(
    bare_database: SqliteDatabase,
) -> None:
    """Plan 4.2: a read-only session is a deferred ``BEGIN``, reads and a
    ``ROLLBACK``; it holds one snapshot and takes no writer lock."""
    with bare_database.connection() as setup:
        setup.execute(text("CREATE TABLE probe (x INTEGER PRIMARY KEY, y INTEGER)"))
        setup.execute(text("INSERT INTO probe VALUES (1, 0)"))
        setup.commit()
    with bare_database.read_only() as reader:
        physical = _dbapi(reader)
        before = physical.total_changes
        assert reader.execute(text("SELECT y FROM probe WHERE x = 1")).scalar_one() == 0
        other = raw_connection(bare_database.path)
        try:
            other.execute("UPDATE probe SET y = 1 WHERE x = 1")
        finally:
            other.close()
        assert reader.execute(text("SELECT y FROM probe WHERE x = 1")).scalar_one() == 0
        assert physical.total_changes == before
        assert physical.in_transaction
    assert not physical.in_transaction
    with bare_database.read_only() as fresh:
        assert fresh.execute(text("SELECT y FROM probe WHERE x = 1")).scalar_one() == 1


def test_close_disposes_every_connection_and_a_reopen_sees_the_rows(
    tmp_path: Path,
) -> None:
    path = tmp_path / "closed.sqlite3"
    database = ok(_open(path, FixedClock(INSTANT)))
    with database.connection() as connection:
        # Task 2's ``open_for_migration`` stamps an EMPTY file before the first
        # table exists; the probe does the same so the reopen recognises the file.
        connection.execute(text(f"PRAGMA application_id = {APPLICATION_ID}"))
        connection.execute(text("CREATE TABLE probe (x INTEGER PRIMARY KEY)"))
        connection.execute(text("INSERT INTO probe VALUES (3)"))
        connection.commit()
    database.close()
    database.close()
    holder = raw_connection(path)
    try:
        holder.execute("BEGIN IMMEDIATE")
        holder.execute("ROLLBACK")
    finally:
        holder.close()

    reopened = ok(_open(path, FixedClock(INSTANT)))
    try:
        with reopened.read_only() as reader:
            assert _rows(reader, "SELECT x FROM probe") == [(3,)]
    finally:
        reopened.close()


# --------------------------------------------------------------------------
# The stable failure mapping (plan 6.5)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sqlite_errorcode", "sqlite_errorname", "expected"),
    [
        (5, "SQLITE_BUSY", CONCURRENCY_CONFLICT),
        (261, "SQLITE_BUSY_RECOVERY", CONCURRENCY_CONFLICT),
        (517, "SQLITE_BUSY_SNAPSHOT", CONCURRENCY_CONFLICT),
        (773, "SQLITE_BUSY_TIMEOUT", CONCURRENCY_CONFLICT),
        (6, "SQLITE_LOCKED", CONCURRENCY_CONFLICT),
        (262, "SQLITE_LOCKED_SHAREDCACHE", CONCURRENCY_CONFLICT),
        (2067, "SQLITE_CONSTRAINT_UNIQUE", CONCURRENCY_CONFLICT),
        (1555, "SQLITE_CONSTRAINT_PRIMARYKEY", CONCURRENCY_CONFLICT),
        (787, "SQLITE_CONSTRAINT_FOREIGNKEY", INVARIANT_VIOLATION),
        (275, "SQLITE_CONSTRAINT_CHECK", INVARIANT_VIOLATION),
        (1811, "SQLITE_CONSTRAINT_TRIGGER", INVARIANT_VIOLATION),
        (1299, "SQLITE_CONSTRAINT_NOTNULL", INVARIANT_VIOLATION),
        (13, "SQLITE_FULL", WRITE_FAILED),
        (10, "SQLITE_IOERR", WRITE_FAILED),
        (266, "SQLITE_IOERR_READ", WRITE_FAILED),
        (3338, "SQLITE_IOERR_ACCESS", WRITE_FAILED),
        (8, "SQLITE_READONLY", WRITE_FAILED),
        (1032, "SQLITE_READONLY_DBMOVED", WRITE_FAILED),
        (7, "SQLITE_NOMEM", WRITE_FAILED),
        (14, "SQLITE_CANTOPEN", WRITE_FAILED),
        (11, "SQLITE_CORRUPT", STORAGE_UNAVAILABLE),
        (26, "SQLITE_NOTADB", STORAGE_UNAVAILABLE),
        (3, "SQLITE_PERM", STORAGE_UNAVAILABLE),
        (23, "SQLITE_AUTH", STORAGE_UNAVAILABLE),
        (1, "SQLITE_ERROR", STORAGE_UNAVAILABLE),
        (19, "SQLITE_CONSTRAINT", STORAGE_UNAVAILABLE),
        (2579, "SQLITE_CONSTRAINT_ROWID", STORAGE_UNAVAILABLE),
    ],
)
def test_classify_maps_each_extended_result_code(
    sqlite_errorcode: int,
    sqlite_errorname: str,
    expected: str,
) -> None:
    error = _synthesized(sqlite_errorcode, sqlite_errorname)
    assert SqliteDatabase.classify(error) == expected


def test_classify_treats_an_error_without_a_result_code_as_unavailable() -> None:
    wrapped = DBAPIError("SELECT 1", None, ValueError("no sqlite code"))
    assert SqliteDatabase.classify(wrapped) == STORAGE_UNAVAILABLE
    assert SqliteDatabase.classify(PoolTimeoutError("pool exhausted")) == (
        STORAGE_UNAVAILABLE
    )


def test_failure_mints_one_persistence_diagnostic_from_the_injected_clock(
    tmp_path: Path,
) -> None:
    clock = FixedClock(INSTANT)
    database = ok(_open(tmp_path / "failure.sqlite3", clock))
    try:
        clock.advance(30)
        failure = database.failure(
            WRITE_FAILED,
            message="the database is full",
            details={"sqlite_errorcode": 13, "operation": "insert"},
        )
        plain = database.failure(CONCURRENCY_CONFLICT, message="row moved")
    finally:
        database.close()
    (diagnostic,) = failure.diagnostics
    assert diagnostic.error_code == WRITE_FAILED
    assert diagnostic.category is DiagnosticCategory.PERSISTENCE
    assert diagnostic.source_component == "persistence"
    assert diagnostic.retriable is False
    assert diagnostic.timestamp_utc == clock.now_utc()
    assert diagnostic.timestamp_utc != INSTANT
    assert diagnostic.details == {"sqlite_errorcode": 13, "operation": "insert"}
    assert plain.diagnostics[0].retriable is True
    assert plain.diagnostics[0].details == {}


# --------------------------------------------------------------------------
# C-18 and the I/O class (Task 6): the read-only attribute, and injected driver
# faults at the cursor and dialect-commit boundaries
# --------------------------------------------------------------------------
#
# Evidence labels. The read-only attribute is a real operating-system fault: the
# file itself refuses every write. Every other fault below is INJECTED at the
# driver boundary -- the dialect's ``do_execute`` replaced so the DBAPI cursor
# never runs the statement and a ``sqlite3`` error carrying one extended result
# code is raised in its place, or the dialect's ``do_commit`` replaced so the
# DBAPI commit is never issued -- and proves the production handler's response
# to that error at that boundary. None of them is a disk-full, power-loss or
# storage-hardware experiment. Every patch is undone by ``monkeypatch`` when the
# context exits or the test ends.

_E = ExperimentState
_R = EngineRunState
_C = CommandInvocationState
_SQLITE_BUSY = 5
_SQLITE_READONLY = 8
_SQLITE_IOERR = 10
_SQLITE_FULL = 13
_SQLITE_IOERR_READ = 266
#: Plan 6.5: the bounded details a refused statement may carry -- the table, the
#: operation, the identity and the result code; never SQL, parameters or values.
_REFUSED_DETAIL_KEYS = frozenset(
    {"table", "operation", "identity", "sqlite_errorcode", "sqlite_errorname"}
)
_LEAK_MARKERS = ("SELECT", "INSERT", "UPDATE", "DELETE", "?", "{", '"')
#: A sixth fixture identity for the rows the write attempts would insert.
_UUID_F = "6f6f6f6f-3333-4444-a555-666677778888"
#: ``(label, table, operation, identity, call)``; the four lifecycle repositories
#: carry their exact details, the five persistence-owned members carry ``None``.
_WriteAttempt = tuple[
    str, str | None, str | None, str | None, Callable[[SqliteTransaction], object]
]
#: ``(table, operation, identity, call)`` for every lifecycle read handler.
_ReadAttempt = tuple[str, str, str, Callable[[SqliteTransaction], object]]
#: ``(table, operation, identity, when, call)``: a disk-full fault on the statement
#: ``when`` admits, inside the multi-statement write ``call`` issues.
_DiskFullCase = tuple[
    str, str, str, Callable[[str], bool], Callable[[SqliteTransaction], object]
]


def _pool_checked_out(database: SqliteDatabase) -> int:
    """Connections the pool has lent out, not counting this probe's own."""
    with database.connection() as connection:
        pool = connection.engine.pool
        assert isinstance(pool, QueuePool)
        return pool.checkedout() - 1


def _engine_of(database: SqliteDatabase) -> Engine:
    with database.connection() as connection:
        return connection.engine


def _sqlite_error(
    sqlite_errorcode: int, sqlite_errorname: str
) -> sqlite3.OperationalError:
    """A DBAPI error carrying one extended result code (plan 2.8 row 4), raised
    at the driver boundary before the statement reaches SQLite."""
    error = sqlite3.OperationalError("injected driver fault")
    error.sqlite_errorcode = sqlite_errorcode
    error.sqlite_errorname = sqlite_errorname
    return error


class _CursorFault:
    """A one-shot fault at the dialect's ``do_execute`` boundary: the last SQLAlchemy
    step before the DBAPI cursor runs a statement, inside the block whose errors
    the connection wraps as ``DBAPIError`` (the engine's ``before_cursor_execute``
    event is dispatched outside that block, so an error raised there would escape
    unwrapped and never reach a repository handler).

    ``arm`` schedules one error for the next statement ``when`` admits; every
    statement that ran instead is recorded in ``passed`` so a test can prove
    whether an earlier statement of a multi-statement method had executed. The
    patch is undone by ``monkeypatch`` when the context exits.
    """

    def __init__(self, engine: Engine, monkeypatch: pytest.MonkeyPatch) -> None:
        self._original = engine.dialect.do_execute
        self._pending: sqlite3.Error | None = None
        self._when: Callable[[str], bool] = lambda statement: True
        self.passed: list[str] = []
        self.fired: list[str] = []
        monkeypatch.setattr(engine.dialect, "do_execute", self._execute)

    def arm(
        self, error: sqlite3.Error, *, when: Callable[[str], bool] | None = None
    ) -> None:
        self._pending = error
        self._when = (lambda statement: True) if when is None else when

    def _execute(
        self, cursor: Any, statement: str, parameters: Any, context: Any = None
    ) -> None:
        if self._pending is not None and self._when(statement):
            error, self._pending = self._pending, None
            self.fired.append(statement)
            raise error
        self.passed.append(statement)
        self._original(cursor, statement, parameters, context)


@contextmanager
def _cursor_fault(
    database: SqliteDatabase, monkeypatch: pytest.MonkeyPatch
) -> Iterator[_CursorFault]:
    fault = _CursorFault(_engine_of(database), monkeypatch)
    try:
        yield fault
    finally:
        monkeypatch.undo()


def _message(result: object) -> str:
    assert isinstance(result, Failure), result
    (diagnostic,) = result.diagnostics
    return diagnostic.message


def _assert_bounded_refusal(
    result: object,
    *,
    expected_code: str,
    table: str | None,
    operation: str | None,
    identity: str | None,
    sqlite_errorcode: int | None,
    sqlite_errorname: str | None,
) -> None:
    """Plan 6.5: the stable code, the bounded details and no leaked SQL, parameter,
    record value or raw token; the lifecycle repositories name their table,
    operation and identity exactly."""
    assert code(result) == expected_code
    details = _details(result)
    assert set(details) <= _REFUSED_DETAIL_KEYS
    if table is not None:
        assert details["table"] == table
        assert details["operation"] == operation
        assert details["identity"] == identity
        assert _message(result) == f"{operation} on {table} was refused by the database"
    if sqlite_errorcode is not None:
        assert details["sqlite_errorcode"] == sqlite_errorcode
        assert details["sqlite_errorname"] == sqlite_errorname
    for value in (_message(result), *details.values()):
        for marker in _LEAK_MARKERS:
            assert marker not in str(value), (marker, value)


def _seed_for_writes(harness: SqliteHarness) -> None:
    """A QUEUED parent at 2, its observation, a PENDING run at 0, a PENDING RUN-kind
    invocation at 0 and the fixture diagnostic: one stored row per compare-and-swap
    repository and every parent a write attempt references."""
    put_lifecycle_parents(harness, run=True, observation=True)
    put_invocation(harness, sample_invocation(_C.PENDING))
    harness.seed_diagnostic(sample_diagnostic())


def _write_attempts() -> tuple[_WriteAttempt, ...]:
    """Every write method of the transaction, one attempt each, over the seeded
    rows; the four lifecycle repositories carry their exact table and operation,
    the five persistence-owned members are asserted on code and codes alone."""
    queued = sample_experiment(_E.QUEUED)
    pending_run = sample_run(_R.PENDING)
    pending_invocation = sample_invocation(_C.PENDING)
    other_experiment = sample_experiment(_E.DRAFT, experiment_id=f"exp_{_UUID_F}")
    other_run = sample_run(_R.PENDING, run_id=f"run_{_UUID_F}")
    describe = sample_invocation(
        _C.PENDING, kind=CommandKind.DESCRIBE, invocation_id=f"inv_{_UUID_F}"
    )
    owner = SystemArtifactOwner(
        owner_kind="SYSTEM", core_component="persistence", correlation_id="task-six"
    )
    return (
        (
            "experiments.add",
            "experiments",
            "add",
            other_experiment.experiment_id,
            lambda transaction: transaction.experiments.add(other_experiment),
        ),
        (
            "experiments.compare_and_swap",
            "experiments",
            "compare_and_swap",
            EXPERIMENT_ID,
            lambda transaction: transaction.experiments.compare_and_swap(
                queued.revision, bump(queued)
            ),
        ),
        (
            "engine_runs.add_attempt",
            "engine_runs",
            "add_attempt",
            other_run.run_id,
            lambda transaction: transaction.engine_runs.add_attempt(other_run),
        ),
        (
            "engine_runs.compare_and_swap",
            "engine_runs",
            "compare_and_swap",
            RUN_ID,
            lambda transaction: transaction.engine_runs.compare_and_swap(
                pending_run.revision, bump_run(pending_run, _R.VALIDATING)
            ),
        ),
        (
            "engine_runs.append_event",
            "run_events",
            "append_event",
            sample_run_event().event_id,
            lambda transaction: transaction.engine_runs.append_event(
                sample_run_event()
            ),
        ),
        (
            "command_invocations.add",
            "command_invocations",
            "add",
            describe.invocation_id,
            lambda transaction: transaction.command_invocations.add(describe),
        ),
        (
            "command_invocations.compare_and_swap",
            "command_invocations",
            "compare_and_swap",
            INVOCATION_ID,
            lambda transaction: transaction.command_invocations.compare_and_swap(
                pending_invocation.revision,
                bump_invocation(pending_invocation, _C.STARTING),
            ),
        ),
        (
            "retry_decisions.insert_if_absent",
            "retry_decisions",
            "insert_if_absent",
            RUN_ID,
            lambda transaction: transaction.retry_decisions.insert_if_absent(
                sample_retry_decision()
            ),
        ),
        (
            "configuration_snapshots.freeze",
            None,
            None,
            None,
            lambda transaction: transaction.configuration_snapshots.freeze(
                EXPERIMENT_ID, snapshot_configuration(ApplicationConfig())
            ),
        ),
        (
            "availability_observation_writer.add",
            None,
            None,
            None,
            lambda transaction: transaction.availability_observation_writer.add(
                sample_observation(AVAIL_B)
            ),
        ),
        (
            "strategy_versions.register",
            None,
            None,
            None,
            lambda transaction: transaction.strategy_versions.register(
                sample_strategy_version()
            ),
        ),
        (
            "datasets.register",
            None,
            None,
            None,
            lambda transaction: transaction.datasets.register(
                *sample_dataset_with_partitions()
            ),
        ),
        (
            "artifact_owners.register",
            None,
            None,
            None,
            lambda transaction: transaction.artifact_owners.register(owner),
        ),
    )


#: Every read handler of the four lifecycle repositories: the method, its table,
#: operation and identity details, and the call that reaches it first.
_READ_ATTEMPTS: tuple[_ReadAttempt, ...] = (
    (
        "experiments",
        "get",
        EXPERIMENT_ID,
        lambda transaction: transaction.experiments.get(EXPERIMENT_ID),
    ),
    (
        "experiments",
        "compare_and_swap",
        EXPERIMENT_ID,
        lambda transaction: transaction.experiments.compare_and_swap(
            2, bump(sample_experiment(_E.QUEUED))
        ),
    ),
    (
        "engine_runs",
        "get",
        RUN_ID,
        lambda transaction: transaction.engine_runs.get(RUN_ID),
    ),
    (
        "engine_runs",
        "compare_and_swap",
        RUN_ID,
        lambda transaction: transaction.engine_runs.compare_and_swap(
            0, bump_run(sample_run(_R.PENDING), _R.VALIDATING)
        ),
    ),
    (
        "engine_runs",
        "count_attempts",
        SLOT_A,
        lambda transaction: transaction.engine_runs.count_attempts(
            EXPERIMENT_ID, SLOT_A
        ),
    ),
    (
        "engine_runs",
        "latest_attempt",
        SLOT_A,
        lambda transaction: transaction.engine_runs.latest_attempt(
            EXPERIMENT_ID, SLOT_A
        ),
    ),
    (
        "engine_runs",
        "get_by_attempt_number",
        SLOT_A,
        lambda transaction: transaction.engine_runs.get_by_attempt_number(
            EXPERIMENT_ID, SLOT_A, 1
        ),
    ),
    (
        "run_events",
        "list_events",
        INVOCATION_ID,
        lambda transaction: transaction.engine_runs.list_events(INVOCATION_ID),
    ),
    (
        "command_invocations",
        "get",
        INVOCATION_ID,
        lambda transaction: transaction.command_invocations.get(INVOCATION_ID),
    ),
    (
        "command_invocations",
        "compare_and_swap",
        INVOCATION_ID,
        lambda transaction: transaction.command_invocations.compare_and_swap(
            0, bump_invocation(sample_invocation(_C.PENDING), _C.STARTING)
        ),
    ),
    (
        "command_invocations",
        "list_for_run",
        RUN_ID,
        lambda transaction: transaction.command_invocations.list_for_run(
            RUN_ID, CommandKind.RUN
        ),
    ),
    (
        "retry_decisions",
        "get_by_predecessor",
        RUN_ID,
        lambda transaction: transaction.retry_decisions.get_by_predecessor(
            SLOT_A, RUN_ID
        ),
    ),
    (
        "retry_decisions",
        "insert_if_absent",
        RUN_ID,
        lambda transaction: transaction.retry_decisions.insert_if_absent(
            sample_retry_decision()
        ),
    ),
)
_READ_IDS = [f"{table}.{operation}" for table, operation, _, _ in _READ_ATTEMPTS]


def _assert_closed_then_released(
    database: SqliteDatabase, transaction: SqliteTransaction, refused: object
) -> None:
    """Plan 4.2, the I/O-class rule: the transaction is closed -- every later member
    call and ``commit()`` return the same stored ``Failure`` -- and the release
    returns the connection to the pool."""
    assert transaction.open_failure() is refused
    assert transaction.experiments.get(EXPERIMENT_ID) is refused
    assert transaction.engine_runs.count_attempts(EXPERIMENT_ID, SLOT_A) is refused
    assert transaction.configuration_snapshots.get(EXPERIMENT_ID) is refused
    assert _pool_checked_out(database) == 1
    assert transaction.commit() is refused
    with pytest.raises(RuntimeError, match="closed"):
        _ = transaction.experiments
    transaction.rollback()
    assert _pool_checked_out(database) == 0


def test_a_read_only_database_file_fails_writes_with_write_failed(
    tmp_path: Path,
) -> None:
    """C-18: the file is set read-only after initialization; ``open_database``
    succeeds for reading; every write is ``PERSISTENCE.WRITE_FAILED`` at the write
    with a ``SQLITE_READONLY*`` code; a lifecycle transaction so refused is closed by
    the I/O-class rule and released by ``rollback()``; a fresh transaction and a
    read-only session then read every row."""
    clock = FixedClock(INSTANT)
    database = open_test_database(tmp_path, clock=clock)
    harness = SqliteHarness(database)
    _seed_for_writes(harness)
    experiments = harness.committed_experiments()
    runs = harness.committed_engine_runs()
    invocations = harness.committed_command_invocations()
    harness.close()
    path = database.path
    os.chmod(path, stat.S_IREAD)
    try:
        assert not os.access(path, os.W_OK)
        reopened = ok(open_database(path, busy_timeout_ms=100, clock=clock))
        try:
            for label, table, operation, identity, attempt in _write_attempts():
                transaction = SqliteUnitOfWork(reopened, clock).begin()
                refused = attempt(transaction)
                assert isinstance(refused, Failure), (label, refused)
                _assert_bounded_refusal(
                    refused,
                    expected_code=WRITE_FAILED,
                    table=table,
                    operation=operation,
                    identity=identity,
                    sqlite_errorcode=None,
                    sqlite_errorname=None,
                )
                details = _details(refused)
                errorcode = details["sqlite_errorcode"]
                assert isinstance(errorcode, int)
                assert errorcode & 0xFF == _SQLITE_READONLY
                assert str(details["sqlite_errorname"]).startswith("SQLITE_READONLY")
                if table is not None:
                    _assert_closed_then_released(reopened, transaction, refused)
                else:
                    # The five persistence-owned members return the write failure
                    # at the call; the transaction is released here (see the
                    # ledger's recorded gap on the closing rule for these members).
                    transaction.rollback()
                    assert _pool_checked_out(reopened) == 0
            # Reading is unaffected: a fresh transaction, then a read-only session.
            fresh = SqliteUnitOfWork(reopened, clock).begin()
            try:
                assert ok(fresh.experiments.get(EXPERIMENT_ID)) == experiments[0]
                assert ok(fresh.engine_runs.get(RUN_ID)) == runs[0]
                assert (
                    ok(fresh.command_invocations.get(INVOCATION_ID)) == (invocations[0])
                )
                assert ok(fresh.diagnostics.get(DIAG_ID)) == sample_diagnostic()
                assert ok(fresh.availability_observations.get(AVAIL_A)) == (
                    sample_observation(AVAIL_A)
                )
            finally:
                fresh.rollback()
            readers = SqliteHarness(reopened)
            assert readers.committed_experiments() == experiments
            assert readers.committed_engine_runs() == runs
            assert readers.committed_command_invocations() == invocations
            assert readers.committed_retry_decisions() == ()
            report = reopened.consistency_report()
            # The QUEUED parent was inserted by ``add`` (scaffolding, plan 4.6);
            # every other count is zero and every count was computed read-only.
            assert report.queued_without_snapshot == 1
            assert report.dangling_diagnostic_references == 0
            assert report.slot_identity_mismatches == 0
            assert report.spec_projection_mismatches == 0
            assert report.causal_edge_mismatches == 0
            assert report.unresolved_causal_references == 0
            assert report.registry_projection_mismatches == 0
            assert report.foreign_key_violations == 0
            assert _pool_checked_out(reopened) == 0
        finally:
            reopened.close()
    finally:
        os.chmod(path, stat.S_IREAD | stat.S_IWRITE)


def test_a_read_only_file_refuses_the_autonomous_recorder_as_write_failed(
    tmp_path: Path,
) -> None:
    """C-18 for the one writer with its own transaction: ``record`` returns the
    write failure, records nothing and holds no connection afterwards."""
    clock = FixedClock(INSTANT)
    database = open_test_database(tmp_path, clock=clock)
    database.close()
    path = database.path
    os.chmod(path, stat.S_IREAD)
    try:
        reopened = ok(open_database(path, busy_timeout_ms=100, clock=clock))
        try:
            recorder = SqliteDiagnosticRecorder(reopened, clock=clock)
            refused = recorder.record(sample_diagnostic(OTHER_DIAG_ID))
            _assert_bounded_refusal(
                refused,
                expected_code=WRITE_FAILED,
                table="diagnostics",
                operation="record",
                identity=OTHER_DIAG_ID,
                sqlite_errorcode=None,
                sqlite_errorname=None,
            )
            assert str(_details(refused)["sqlite_errorname"]).startswith(
                "SQLITE_READONLY"
            )
            assert _pool_checked_out(reopened) == 0
            fresh = SqliteUnitOfWork(reopened, clock).begin()
            try:
                assert code(fresh.diagnostics.get(OTHER_DIAG_ID)) == INVARIANT_VIOLATION
            finally:
                fresh.rollback()
        finally:
            reopened.close()
    finally:
        os.chmod(path, stat.S_IREAD | stat.S_IWRITE)


def test_the_scope_gate_refuses_a_retained_repository_after_release(
    sqlite_database: SqliteDatabase,
) -> None:
    """A repository object kept past its transaction's release is a programmer
    defect at the gate itself (reading 2), not a silent statement in autocommit."""
    transaction = SqliteUnitOfWork(sqlite_database, FixedClock(INSTANT)).begin()
    retained = transaction.experiments
    commit(transaction)
    with pytest.raises(RuntimeError, match="closed"):
        retained.get(EXPERIMENT_ID)
    assert _pool_checked_out(sqlite_database) == 0


@pytest.mark.parametrize(
    ("table", "operation", "identity", "attempt"), _READ_ATTEMPTS, ids=_READ_IDS
)
def test_an_injected_read_fault_closes_the_transaction_as_write_failed(
    sqlite_harness: SqliteHarness,
    monkeypatch: pytest.MonkeyPatch,
    table: str,
    operation: str,
    identity: str,
    attempt: Callable[[SqliteTransaction], object],
) -> None:
    """The deferred ``except DBAPIError`` handler of every read: an I/O-class code
    raised at the driver boundary before the statement reaches SQLite is the
    write failure (plan 6.5 row 5, reading 3), it closes the transaction, and the
    data is untouched."""
    _seed_for_writes(sqlite_harness)
    database = sqlite_harness.database
    before = sqlite_harness.committed_engine_runs()
    with _cursor_fault(database, monkeypatch) as fault:
        transaction = sqlite_harness.unit_of_work().begin()
        fault.arm(_sqlite_error(_SQLITE_IOERR_READ, "SQLITE_IOERR_READ"))
        refused = attempt(transaction)
        # The transaction's BEGIN ran; the very first read was the refused statement.
        assert len(fault.fired) == 1
        assert fault.passed == ["BEGIN"]
        _assert_bounded_refusal(
            refused,
            expected_code=WRITE_FAILED,
            table=table,
            operation=operation,
            identity=identity,
            sqlite_errorcode=_SQLITE_IOERR_READ,
            sqlite_errorname="SQLITE_IOERR_READ",
        )
        _assert_closed_then_released(database, transaction, refused)
    assert sqlite_harness.committed_engine_runs() == before
    fresh = sqlite_harness.unit_of_work().begin()
    try:
        assert ok(fresh.experiments.get(EXPERIMENT_ID)).revision == 2
    finally:
        fresh.rollback()


def test_an_injected_disk_full_stages_nothing_wherever_it_strikes(
    sqlite_harness: SqliteHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``SQLITE_FULL`` at the first statement and at a later statement of the
    multi-statement writes: the earlier statements are proven to have executed,
    the savepoint or statement is rolled back, the transaction is closed, and a
    fresh reader sees nothing of the method."""
    _seed_for_writes(sqlite_harness)
    database = sqlite_harness.database
    other = sample_experiment(_E.DRAFT, experiment_id=f"exp_{_UUID_F}")
    cases: tuple[_DiskFullCase, ...] = (
        (
            "experiments",
            "add",
            other.experiment_id,
            lambda statement: "INSERT INTO experiments" in statement,
            lambda transaction: transaction.experiments.add(other),
        ),
        (
            "engine_slots",
            "add",
            other.experiment_id,
            lambda statement: "INSERT INTO engine_slots" in statement,
            lambda transaction: transaction.experiments.add(other),
        ),
        (
            "run_events",
            "append_event",
            sample_run_event().event_id,
            lambda statement: statement.startswith("INSERT"),
            lambda transaction: transaction.engine_runs.append_event(
                sample_run_event()
            ),
        ),
        (
            "retry_decisions",
            "insert_if_absent",
            RUN_ID,
            lambda statement: statement.startswith("INSERT"),
            lambda transaction: transaction.retry_decisions.insert_if_absent(
                sample_retry_decision()
            ),
        ),
    )
    for table, operation, identity, when, attempt in cases:
        with _cursor_fault(database, monkeypatch) as fault:
            transaction = sqlite_harness.unit_of_work().begin()
            fault.arm(_sqlite_error(_SQLITE_FULL, "SQLITE_FULL"), when=when)
            refused = attempt(transaction)
            assert len(fault.fired) == 1
            executed_first = [
                statement
                for statement in fault.passed
                if statement.startswith(("INSERT", "SELECT"))
            ]
            if table == "engine_slots":
                # The experiment row's INSERT ran before the slot INSERT was refused.
                assert any("INSERT INTO experiments" in s for s in executed_first)
            elif operation in {"append_event", "insert_if_absent"}:
                # The method's reads ran; the INSERT after them was refused.
                assert executed_first
                assert all(s.startswith("SELECT") for s in executed_first)
            else:
                assert executed_first == []
            _assert_bounded_refusal(
                refused,
                expected_code=WRITE_FAILED,
                table=table,
                operation=operation,
                identity=identity,
                sqlite_errorcode=_SQLITE_FULL,
                sqlite_errorname="SQLITE_FULL",
            )
            _assert_closed_then_released(database, transaction, refused)
        # Nothing of the method survived: the other experiment and its slots are
        # absent, the events and decisions tables are still empty.
        fresh = sqlite_harness.unit_of_work().begin()
        try:
            assert code(fresh.experiments.get(other.experiment_id)) == (
                INVARIANT_VIOLATION
            )
            assert ok(fresh.engine_runs.list_events(INVOCATION_ID)) == ()
            assert code(fresh.retry_decisions.get_by_predecessor(SLOT_A, RUN_ID)) == (
                INVARIANT_VIOLATION
            )
        finally:
            fresh.rollback()
        with database.read_only() as reader:
            slot_rows = reader.execute(
                text(
                    "SELECT count(*) FROM engine_slots "
                    "WHERE experiment_id = :experiment_id"
                ),
                {"experiment_id": other.experiment_id},
            ).scalar_one()
            assert slot_rows == 0


def test_an_unclassified_driver_error_leaves_the_transaction_usable(
    sqlite_harness: SqliteHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A DBAPI error carrying no result code is ``PERSISTENCE.STORAGE_UNAVAILABLE``
    with no code details; it is not the I/O class, so the transaction stays
    usable: the repeated read succeeds and ``commit()`` succeeds."""
    _seed_for_writes(sqlite_harness)
    database = sqlite_harness.database
    with _cursor_fault(database, monkeypatch) as fault:
        transaction = sqlite_harness.unit_of_work().begin()
        fault.arm(sqlite3.OperationalError("injected driver fault without a code"))
        refused = transaction.experiments.get(EXPERIMENT_ID)
        _assert_bounded_refusal(
            refused,
            expected_code=STORAGE_UNAVAILABLE,
            table="experiments",
            operation="get",
            identity=EXPERIMENT_ID,
            sqlite_errorcode=None,
            sqlite_errorname=None,
        )
        assert "sqlite_errorcode" not in _details(refused)
        assert transaction.open_failure() is None
        assert ok(transaction.experiments.get(EXPERIMENT_ID)).revision == 2
        commit(transaction)
    assert _pool_checked_out(database) == 0


def test_a_failed_begin_leaves_a_closed_transaction_that_rollback_releases(
    sqlite_database: SqliteDatabase, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Plan 4.2 ``begin()``: a ``BEGIN`` the driver refuses leaves the transaction
    closed with ``PERSISTENCE.STORAGE_UNAVAILABLE`` naming the result code; every
    member and ``commit()`` answer with it and ``rollback()`` releases the
    connection that was acquired."""
    clock = FixedClock(INSTANT)
    with _cursor_fault(sqlite_database, monkeypatch) as fault:
        fault.arm(
            _sqlite_error(_SQLITE_IOERR, "SQLITE_IOERR"),
            when=lambda statement: statement == "BEGIN",
        )
        root = SqliteUnitOfWork(sqlite_database, clock)
        transaction = root.begin()
        assert fault.fired == ["BEGIN"]
        failure = transaction.open_failure()
        assert failure is not None
        assert code(failure) == STORAGE_UNAVAILABLE
        assert _details(failure) == {
            "operation": "begin",
            "sqlite_errorcode": _SQLITE_IOERR,
            "sqlite_errorname": "SQLITE_IOERR",
        }
        assert transaction.experiments.get(EXPERIMENT_ID) is failure
        assert transaction.datasets.get_by_hash("a" * 64) is failure
        assert root.open_transactions() == (transaction,)
        assert _pool_checked_out(sqlite_database) == 1
        transaction.rollback()
        assert root.open_transactions() == ()
        assert _pool_checked_out(sqlite_database) == 0
        with pytest.raises(RuntimeError, match="closed"):
            transaction.commit()


@pytest.mark.parametrize(
    ("error", "expected_code"),
    [
        (_sqlite_error(_SQLITE_BUSY, "SQLITE_BUSY"), CONCURRENCY_CONFLICT),
        (_sqlite_error(_SQLITE_IOERR, "SQLITE_IOERR"), WRITE_FAILED),
    ],
    ids=["checkpoint_race", "io_class"],
)
def test_a_commit_refused_before_the_dbapi_commit_rolls_back_and_releases(
    sqlite_harness: SqliteHarness,
    monkeypatch: pytest.MonkeyPatch,
    error: sqlite3.OperationalError,
    expected_code: str,
) -> None:
    """Plan 4.2 ``commit()``: the injection replaces the dialect's DBAPI commit, so
    the real ``COMMIT`` is never issued and the outcome is unambiguous -- nothing
    committed. A busy code is the conflict, an I/O code the write failure; both
    roll back first and return the connection."""
    database = sqlite_harness.database
    engine = _engine_of(database)

    def failing_commit(dbapi_connection: object) -> None:
        del dbapi_connection
        raise error

    monkeypatch.setattr(engine.dialect, "do_commit", failing_commit)
    transaction = sqlite_harness.unit_of_work().begin()
    ok(transaction.experiments.add(sample_experiment(_E.DRAFT)))
    refused = transaction.commit()
    assert code(refused) == expected_code
    assert _message(refused) == "the transaction could not be committed"
    assert _details(refused) == {
        "operation": "commit",
        "sqlite_errorcode": error.sqlite_errorcode,
        "sqlite_errorname": error.sqlite_errorname,
    }
    with pytest.raises(RuntimeError, match="closed"):
        _ = transaction.experiments
    transaction.rollback()
    monkeypatch.undo()
    assert _pool_checked_out(database) == 0
    assert sqlite_harness.committed_experiments() == ()
    assert sqlite_harness.open_transactions() == ()


def test_a_non_dbapi_error_at_commit_releases_the_connection_before_it_escapes(
    sqlite_harness: SqliteHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = sqlite_harness.database
    engine = _engine_of(database)

    def defective_commit(dbapi_connection: object) -> None:
        del dbapi_connection
        raise RuntimeError("injected non-DBAPI defect at commit")

    monkeypatch.setattr(engine.dialect, "do_commit", defective_commit)
    transaction = sqlite_harness.unit_of_work().begin()
    ok(transaction.experiments.add(sample_experiment(_E.DRAFT)))
    with pytest.raises(RuntimeError, match="injected non-DBAPI defect"):
        transaction.commit()
    monkeypatch.undo()
    with pytest.raises(RuntimeError, match="closed"):
        _ = transaction.experiments
    assert _pool_checked_out(database) == 0
    assert sqlite_harness.committed_experiments() == ()
    assert sqlite_harness.open_transactions() == ()


# --------------------------------------------------------------------------
# Plan 2.6: the guard expectations this task trips
# --------------------------------------------------------------------------


def test_the_source_allowlist_and_import_roots_name_the_database_modules() -> None:
    allowed = _literal(_STAGE3_GUARD, "_ALLOWED_SOURCE_FILES")
    assert {"persistence/database.py", "persistence/diagnostics.py"} <= allowed
    assert len(allowed) == 110  # Tasks 1-5 appended the fifteen Stage 8 modules
    roots = _literal(_STAGE3_GUARD, "_ALLOWED_IMPORT_ROOTS")
    assert "sqlalchemy" in roots
    assert "alembic" in roots  # Task 2 added it
    assert roots.isdisjoint({"sqlite3", "os", "sys", "time", "logging"})
    assert len(roots) == 29
    modules = _literal(_PACKAGE_LAYOUT, "PACKAGE_MODULES")
    anchor = modules.index("crypto_lab.persistence")
    assert modules[anchor + 1 : anchor + 3] == (
        "crypto_lab.persistence.database",
        "crypto_lab.persistence.diagnostics",
    )
    assert len(modules) == 110


def test_the_two_cross_pins_moved_to_the_running_sizes() -> None:
    preflight = _PREFLIGHT_TESTS.read_text(encoding="utf-8")
    reconciliation = _RECONCILIATION_TESTS.read_text(encoding="utf-8")
    for source in (preflight, reconciliation):
        assert "len(allowed) == 110" in source
        assert "len(modules) == 110" in source
        assert "len(allowed) == 95" not in source
        assert "len(modules) == 95" not in source
    assert "len(roots) == 29" in preflight
    assert "len(roots) == 27" not in preflight


def test_the_infrastructure_exemptions_include_the_database_module_pair() -> None:
    """Task 1's pair is exempt; the exact set (thirteen pairs after Task 5's
    ``reconciliation_source.py``) is pinned by ``test_sqlite_migrations.py``."""
    pairs = _literal(_STAGE5_GUARD, "_INFRASTRUCTURE_EXEMPTIONS")
    assert ("process_supervision/windows_process.py", "subprocess") in pairs
    assert ("persistence/database.py", "sqlalchemy") in pairs
    # The rewritten exemption test keeps its three Stage 7 controls and adds the
    # three Stage 8 mirrors: ``sqlalchemy`` in ``experiments/ports.py``, a planted
    # ``persistence/probe.py`` and ``time`` in ``persistence/database.py`` all fail.
    guard = _STAGE5_GUARD.read_text(encoding="utf-8")
    for mirror in (
        '"experiments/ports.py"',
        '"persistence/probe.py"',
        '("persistence/database.py", "sqlalchemy")',
    ):
        assert mirror in guard, mirror


def test_the_dependency_guards_admit_exactly_the_four_runtime_requirements() -> None:
    expected = _literal(_DEPENDENCY_GUARD, "_EXPECTED_RUNTIME_REQUIREMENTS")
    assert expected == (
        "alembic>=1.13,<2",
        "pydantic>=2.12,<3",
        "pyyaml>=6.0.3,<7",
        "sqlalchemy>=2.0,<3",
    )
    families = _literal(_DEPENDENCY_GUARD, "_PROHIBITED_FAMILIES")
    assert len(families) == 27
    assert "sqlalchemy" not in families
    assert "alembic" not in families
    assert {"binance", "ccxt", "requests", "pandas", "openai"} <= set(families)
    pyproject = tomllib.loads((_REPOSITORY / "pyproject.toml").read_text("utf-8"))
    assert pyproject["project"]["dependencies"] == list(expected)
    tooling = _TOOLING_GUARD.read_text(encoding="utf-8")
    assert '"alembic>=1.13,<2",' in tooling
    assert '"sqlalchemy>=2.0,<3",' in tooling


def test_the_stage_seven_shape_scan_is_retired_and_its_stage_nine_half_kept() -> None:
    source = _STAGE7_GUARD.read_text(encoding="utf-8")
    for retired in (
        "def test_stage_eight_persistence_has_not_started",
        "def test_the_stage_eight_path_scan_detects_each_shape",
        "_stage8_shaped_paths",
        "_STAGE8_SHAPED_PATTERN",
        "_STAGE8_SCAN_ROOTS",
        "_STAGE8_SCAN_SKIP",
    ):
        assert retired not in source, retired
    assert "def test_stage_nine_finalization_names_stay_deferred" in source
    names = _literal(_STAGE7_GUARD, "_STAGE8_AND_LATER_NAMES")
    assert len(names) == 9
    assert "RunManifest" in names


def test_the_architecture_closure_names_persistence() -> None:
    # The scanner keys packages by their bare name (``_CAPABILITIES = "capabilities"``
    # and the others), so the persistence constant follows that convention.
    assert _literal(_ARCHITECTURE_GUARD, "_PERSISTENCE") == "persistence"
    assert _literal(_ARCHITECTURE_GUARD, "_ALLOWED_FOR_PERSISTENCE") == (
        "crypto_lab.domain",
        "crypto_lab.experiments",
        "crypto_lab.adapters",
        "crypto_lab.process_supervision",
        "crypto_lab.artifacts",
        "crypto_lab.datasets",
        "crypto_lab.strategy",
        "crypto_lab.configuration",
        "crypto_lab.persistence",
    )
    assert _literal(_ARCHITECTURE_GUARD, "_PROHIBITED_FOR_PERSISTENCE") == (
        "crypto_lab.capabilities",
        "crypto_lab.cli",
        "crypto_lab.schema_registry",
    )


def test_the_verification_guide_names_the_database_stack_exception() -> None:
    guide = _VERIFICATION_GUIDE.read_text(encoding="utf-8")
    assert _DEPENDENCY_SENTENCE in guide
    assert "database stack, or GitNexus" not in guide
