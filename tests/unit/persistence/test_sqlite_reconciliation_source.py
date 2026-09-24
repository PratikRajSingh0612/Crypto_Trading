"""The SQLite ``ReconciliationSource`` over the migrated schema (plan 4.5, Task 5).

``SqliteReconciliationSource(database, clock)`` lists every nonterminal invocation
and every terminal one whose cleanup is incomplete, ordered ``(created_at_utc,
invocation_id)`` with ties broken by the identifier; reads a run and its experiment
as ``RunReconciliationFacts`` from one snapshot; refuses a missing run or a run
whose experiment is absent as ``CORE.INVARIANT_VIOLATION`` saying ``does not
exist``; refuses a row that fails egress as the invariant naming it and never
returns a partial population; turns a checkout or statement the database refuses
into the classified persistence ``Failure`` rather than an empty success; issues
no write (the pooled connection's ``total_changes`` and every recorded statement
prove it); is served by the reconciliation-listing index (``EXPLAIN QUERY PLAN``
names it); releases its read-only session on every path so nothing is open while
the reconciler inspects a process; and returns validated records that stay usable
after the database is closed. Every case runs against the file-backed database.

Test-local readings, declared rather than inferred silently:

- ``total_changes(database)`` is the plan's module-local helper: the
  ``sqlite3.Connection.total_changes`` of the one physical connection the pool
  holds while every transaction is released. The pool's public counters prove the
  precondition (exactly one connection exists and it is the one checked out), so
  the reading is the connection the source's read-only session reuses and a
  write issued on it -- committed or not -- would move the count.
- The statement recorder is SQLAlchemy's public ``before_cursor_execute`` hook on
  the engine the database's own connection reports; it captures exactly the SQL
  the source issues, so the ``EXPLAIN QUERY PLAN`` proof runs the source's own
  listing statement and not a copy of it.
- The verbatim listing sketch is preceded by one ``_seed_parents`` line: the
  invocations' foreign keys need their experiment, observations and runs, which
  the sketch's ``_put_invocation`` shorthand does not seed.
- A run whose experiment is absent is unconstructible through the repositories
  (the foreign key refuses it), so that branch is seeded through a raw connection
  with foreign keys off: the same shape-valid row the codec would write, minus
  its parent.
"""

from __future__ import annotations

import inspect
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Final

import pytest
from pydantic.experimental.missing_sentinel import MISSING
from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlalchemy.pool import QueuePool

from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.lifecycle import (
    TERMINAL_COMMAND_INVOCATION_STATES,
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.results import Failure, Success
from crypto_lab.experiments.experiment_service import cancel_experiment
from crypto_lab.experiments.requests import CancelExperimentRequest
from crypto_lab.experiments.supervision_lifecycle import Stage5InvocationLifecycle
from crypto_lab.persistence import reconciliation_source as reconciliation_source_module
from crypto_lab.persistence.codecs import encode_engine_run
from crypto_lab.persistence.database import SqliteDatabase
from crypto_lab.persistence.diagnostics import (
    INVARIANT_VIOLATION,
    STORAGE_UNAVAILABLE,
)
from crypto_lab.persistence.reconciliation_source import SqliteReconciliationSource
from crypto_lab.persistence.registries import SqliteDiagnosticRecorder
from crypto_lab.process_supervision.models import (
    ProcessInspection,
    ProcessPresence,
    ReconciliationAction,
    RunReconciliationFacts,
)
from crypto_lab.process_supervision.ports import ReconciliationSource
from crypto_lab.process_supervision.reconciliation import reconcile_invocations
from crypto_lab.process_supervision.roots import PathPreflight
from doubles.experiments import (
    ADAPTER_BETA,
    AVAIL_A,
    AVAIL_B,
    ENGINE_BETA,
    EXPERIMENT_ID,
    INSTANT,
    OTHER_RUN_ID,
    RUN_ID,
    SLOT_B,
    THIRD_RUN_ID,
    UUID_E,
    FixedClock,
    sample_diagnostic,
    sample_invocation,
    sample_observation,
    sample_run,
)
from doubles.supervision import (
    SCRIPTED_SUPERVISOR_INSTANCE_ID,
    ScriptedProcessController,
)
from persistence_support.harness import (
    SqliteHarness,
    accept_any_revision,
    bump_invocation,
    code,
    ok,
    open_test_database,
    put_invocation,
    put_lifecycle_parents,
    put_run,
    raw_connection,
)

_C: Final = CommandInvocationState
_K: Final = CommandKind
_R: Final = EngineRunState
#: The listing index of plan 3.3.4 and the ``(state, deadline_utc)`` index of
#: specification 23.3.1 (plan 1.5 note 4).
_LISTING_INDEX: Final = "ix_command_invocations_reconciliation_listing"
_DEADLINE_INDEX: Final = "ix_command_invocations_state_deadline_utc"


def _inv(ordinal: int) -> str:
    """A UUID4-shaped invocation identifier distinct per ordinal."""
    return f"inv_00000000-0000-4000-8000-{ordinal:012d}"


def _at(seconds: int) -> datetime:
    return INSTANT + timedelta(seconds=seconds)


def _seeded(
    state: CommandInvocationState,
    *,
    ordinal: int,
    kind: CommandKind,
    created: int,
    run_id: str = RUN_ID,
    cleanup_complete: bool = False,
) -> CommandInvocationRecord:
    """One shape-valid invocation; terminal rows may be marked cleanup-complete."""
    record = sample_invocation(
        state,
        kind=kind,
        invocation_id=_inv(ordinal),
        run_id=run_id,
        created_at_utc=_at(created),
    )
    if not cleanup_complete:
        return record
    payload = record.model_dump(mode="python")
    payload["cleanup_complete"] = True
    payload["cleanup_completed_at_utc"] = payload["completed_at_utc"]
    return CommandInvocationRecord.model_validate(payload)


#: Plan Task 5 Step 1: the seed, in insertion order. Two rows share one
#: ``created_at_utc`` (ordinals 3 and 4, inserted 4 before 3) so the tie is broken
#: by ``invocation_id`` and not by insertion; the earliest row is inserted last.
RECONCILIATION_SEED: Final[tuple[CommandInvocationRecord, ...]] = (
    _seeded(_C.PENDING, ordinal=1, kind=_K.DESCRIBE, created=0),
    _seeded(_C.STARTING, ordinal=2, kind=_K.DESCRIBE, created=1),
    _seeded(_C.STARTING, ordinal=4, kind=_K.VALIDATE, created=2),
    _seeded(_C.PENDING, ordinal=3, kind=_K.RUN, created=2),
    _seeded(_C.RUNNING, ordinal=5, kind=_K.RUN, created=3, run_id=OTHER_RUN_ID),
    _seeded(_C.EXITED, ordinal=6, kind=_K.RUN, created=4, cleanup_complete=True),
    _seeded(_C.CANCELLED, ordinal=7, kind=_K.VALIDATE, created=5, run_id=OTHER_RUN_ID),
    _seeded(
        _C.TIMED_OUT, ordinal=8, kind=_K.DESCRIBE, created=6, cleanup_complete=True
    ),
    _seeded(
        _C.PROTOCOL_FAILED,
        ordinal=10,
        kind=_K.RUN,
        created=7,
        run_id=OTHER_RUN_ID,
        cleanup_complete=True,
    ),
    _seeded(_C.FAILED_TO_START, ordinal=9, kind=_K.DESCRIBE, created=-10),
)
#: The nonterminal rows and the terminal rows with incomplete cleanup, in
#: ``(created_at_utc, invocation_id)`` order.
EXPECTED_TARGET_ORDER: Final[list[str]] = [
    _inv(9),
    _inv(1),
    _inv(2),
    _inv(3),
    _inv(4),
    _inv(5),
    _inv(7),
]
EXCLUDED_ROWS: Final[frozenset[str]] = frozenset({_inv(6), _inv(8), _inv(10)})


def _put_invocation(harness: SqliteHarness, record: CommandInvocationRecord) -> None:
    put_invocation(harness, record)


def _code(result: object) -> str:
    return code(result)


def _seed_parents(harness: SqliteHarness) -> None:
    """The experiment, its two observations, both runs and the shared diagnostic."""
    put_lifecycle_parents(harness, run=True, observation=True)
    harness.seed_observation(sample_observation(AVAIL_B))
    put_run(
        harness,
        sample_run(
            _R.RUNNING,
            run_id=OTHER_RUN_ID,
            logical_slot_id=SLOT_B,
            adapter=ADAPTER_BETA,
            engine=ENGINE_BETA,
            availability_observation_id=AVAIL_B,
        ),
    )
    harness.seed_diagnostic(sample_diagnostic())


def _seed_all(harness: SqliteHarness) -> None:
    _seed_parents(harness)
    for record in RECONCILIATION_SEED:
        _put_invocation(harness, record)


def _engine_of(database: SqliteDatabase) -> Engine:
    with database.connection() as connection:
        return connection.engine


def _checked_out(database: SqliteDatabase) -> int:
    """Connections the pool has lent out, not counting this probe's own."""
    with database.connection() as connection:
        pool = connection.engine.pool
        assert isinstance(pool, QueuePool)
        return pool.checkedout() - 1


def total_changes(database: SqliteDatabase) -> int:
    """``total_changes`` of the database's one pooled connection (plan 4.5).

    The pool holds exactly one physical connection while every transaction is
    released; the public counters assert it, so this is the connection the
    source's read-only session reuses.
    """
    with database.connection() as connection:
        pool = connection.engine.pool
        assert isinstance(pool, QueuePool)
        assert (pool.checkedout(), pool.checkedin()) == (1, 0)
        dbapi = connection.connection.dbapi_connection
        assert isinstance(dbapi, sqlite3.Connection)
        return dbapi.total_changes


class _StatementRecorder:
    """Every SQL statement the engine executes while the recorder is attached."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        self.statements: list[tuple[str, tuple[Any, ...]]] = []

    def _record(
        self,
        connection: Any,
        cursor: Any,
        statement: str,
        parameters: Any,
        context: Any,
        executemany: bool,
    ) -> None:
        del connection, cursor, context, executemany
        self.statements.append((statement, tuple(parameters)))

    @contextmanager
    def attached(self) -> Iterator[_StatementRecorder]:
        event.listen(self._engine, "before_cursor_execute", self._record)
        try:
            yield self
        finally:
            event.remove(self._engine, "before_cursor_execute", self._record)

    def verbs(self) -> list[str]:
        return [statement.split(None, 1)[0].upper() for statement, _ in self.statements]

    def listing_statement(self) -> tuple[str, tuple[Any, ...]]:
        (found,) = (
            item
            for item in self.statements
            if "FROM command_invocations" in item[0] and "ORDER BY" in item[0]
        )
        return found


def _query_plan(
    database: SqliteDatabase, sql: str, parameters: tuple[Any, ...]
) -> tuple[str, ...]:
    """The detail lines of ``EXPLAIN QUERY PLAN`` through an independent connection."""
    connection = raw_connection(database.path)
    try:
        rows = connection.execute(f"EXPLAIN QUERY PLAN {sql}", parameters).fetchall()
    finally:
        connection.close()
    return tuple(str(row[-1]) for row in rows)


def _searches_with(plan: tuple[str, ...], index: str) -> bool:
    """Does the plan ``SEARCH`` (not merely scan) through ``index``?"""
    return any("SEARCH" in line and index in line for line in plan)


def _insert_run_without_its_experiment(database: SqliteDatabase) -> str:
    """A shape-valid ``engine_runs`` row whose experiment does not exist.

    Unconstructible through the repositories (the foreign key refuses it), so it
    is written through a raw connection with foreign keys off: exactly the
    columns the codec writes, minus the parent rows.
    """
    orphan = sample_run(
        _R.RUNNING,
        run_id=THIRD_RUN_ID,
        experiment_id=f"exp_{UUID_E}",
        availability_observation_id=AVAIL_A,
    )
    values = encode_engine_run(orphan)
    columns = ", ".join(values)
    placeholders = ", ".join("?" for _ in values)
    connection = raw_connection(database.path)
    try:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute(
            f"INSERT INTO engine_runs ({columns}) VALUES ({placeholders})",  # noqa: S608
            tuple(values.values()),
        )
    finally:
        connection.close()
    return orphan.experiment_id


# --------------------------------------------------------------------------
# Plan Task 5 Step 1 (verbatim)
# --------------------------------------------------------------------------


def test_listing_returns_exactly_the_nonterminal_and_incomplete_cleanup_rows(
    sqlite_harness: SqliteHarness,
) -> None:
    _seed_parents(sqlite_harness)
    for record in RECONCILIATION_SEED:
        _put_invocation(sqlite_harness, record)
    source = SqliteReconciliationSource(sqlite_harness.database, FixedClock(INSTANT))
    listed = source.list_reconciliation_targets()
    assert isinstance(listed, Success)
    assert [record.invocation_id for record in listed.value] == EXPECTED_TARGET_ORDER
    assert all(
        record.state not in TERMINAL_COMMAND_INVOCATION_STATES
        or not record.cleanup_complete
        for record in listed.value
    )


def test_run_facts_for_a_missing_run_or_experiment_is_an_invariant(
    sqlite_harness: SqliteHarness,
) -> None:
    source = SqliteReconciliationSource(sqlite_harness.database, FixedClock(INSTANT))
    assert _code(source.run_facts(RUN_ID)) == INVARIANT_VIOLATION


def test_the_source_issues_no_write(sqlite_harness: SqliteHarness) -> None:
    before = total_changes(sqlite_harness.database)
    SqliteReconciliationSource(
        sqlite_harness.database, FixedClock(INSTANT)
    ).list_reconciliation_targets()
    assert total_changes(sqlite_harness.database) == before


# --------------------------------------------------------------------------
# Target selection, ordering and the excluded rows
# --------------------------------------------------------------------------


def test_every_excluded_row_is_terminal_with_its_cleanup_complete(
    sqlite_harness: SqliteHarness,
) -> None:
    _seed_all(sqlite_harness)
    source = SqliteReconciliationSource(sqlite_harness.database, FixedClock(INSTANT))
    listed = ok(source.list_reconciliation_targets())
    listed_ids = {record.invocation_id for record in listed}
    assert listed_ids.isdisjoint(EXCLUDED_ROWS)
    assert listed_ids | EXCLUDED_ROWS == {r.invocation_id for r in RECONCILIATION_SEED}
    stored = {
        record.invocation_id: record
        for record in sqlite_harness.committed_command_invocations()
    }
    for excluded in EXCLUDED_ROWS:
        assert stored[excluded].state in TERMINAL_COMMAND_INVOCATION_STATES
        assert stored[excluded].cleanup_complete is True
    # The listed records are the stored records, decoded whole.
    assert list(listed) == [stored[identity] for identity in EXPECTED_TARGET_ORDER]
    assert type(listed) is tuple


def test_ordering_is_by_creation_instant_then_invocation_id(
    sqlite_harness: SqliteHarness,
) -> None:
    _seed_all(sqlite_harness)
    source = SqliteReconciliationSource(sqlite_harness.database, FixedClock(INSTANT))
    listed = ok(source.list_reconciliation_targets())
    keys = [(record.created_at_utc, record.invocation_id) for record in listed]
    assert keys == sorted(keys)
    # The tie: two rows at one instant, the later-inserted one listed first
    # because its identifier sorts first.
    third, fourth = (record for record in listed if record.created_at_utc == _at(2))
    assert (third.invocation_id, fourth.invocation_id) == (_inv(3), _inv(4))
    # The earliest row was inserted last and is listed first.
    assert listed[0].invocation_id == _inv(9)


def test_an_empty_database_lists_no_target(sqlite_harness: SqliteHarness) -> None:
    source = SqliteReconciliationSource(sqlite_harness.database, FixedClock(INSTANT))
    assert ok(source.list_reconciliation_targets()) == ()


# --------------------------------------------------------------------------
# Run facts: ownership join, missing parents, validated values
# --------------------------------------------------------------------------


def test_run_facts_read_the_run_and_its_owning_experiment(
    sqlite_harness: SqliteHarness,
) -> None:
    _seed_parents(sqlite_harness)
    source = SqliteReconciliationSource(sqlite_harness.database, FixedClock(INSTANT))
    facts = ok(source.run_facts(OTHER_RUN_ID))
    assert isinstance(facts, RunReconciliationFacts)
    (run,) = (
        record
        for record in sqlite_harness.committed_engine_runs()
        if record.run_id == OTHER_RUN_ID
    )
    (experiment,) = sqlite_harness.committed_experiments()
    assert facts == RunReconciliationFacts(
        run_id=run.run_id,
        experiment_id=run.experiment_id,
        run_state=run.state,
        run_revision=run.revision,
        attempt_token_hash=run.attempt_token_hash,
        request_hash=run.request_hash,
        experiment_state=experiment.state,
    )
    assert facts.experiment_id == EXPERIMENT_ID
    assert facts.run_state is _R.RUNNING
    assert facts.experiment_state is ExperimentState.QUEUED
    assert facts.cancelled is False


def test_run_facts_follow_a_later_cancellation_on_the_next_call(
    sqlite_harness: SqliteHarness,
) -> None:
    _seed_parents(sqlite_harness)
    clock = FixedClock(INSTANT)
    source = SqliteReconciliationSource(sqlite_harness.database, clock)
    before = ok(source.run_facts(RUN_ID))
    assert before.cancelled is False
    (experiment,) = sqlite_harness.committed_experiments()
    ok(
        cancel_experiment(
            CancelExperimentRequest(
                schema_version="1.0.0",
                experiment_id=EXPERIMENT_ID,
                expected_revision=experiment.revision,
                correlation_id="task5-cancel",
            ),
            unit_of_work=sqlite_harness.unit_of_work(),
            clock=clock,
        )
    )
    after = ok(source.run_facts(RUN_ID))
    assert after.experiment_state is ExperimentState.CANCELLED
    assert after.cancelled is True
    # The earlier value is a snapshot, not a live view.
    assert before.experiment_state is ExperimentState.QUEUED


def test_a_missing_run_and_a_missing_experiment_each_name_what_is_absent(
    sqlite_harness: SqliteHarness,
) -> None:
    _seed_parents(sqlite_harness)
    source = SqliteReconciliationSource(sqlite_harness.database, FixedClock(INSTANT))
    missing_run = source.run_facts(THIRD_RUN_ID)
    assert isinstance(missing_run, Failure)
    assert _code(missing_run) == INVARIANT_VIOLATION
    assert f"run {THIRD_RUN_ID} does not exist" in missing_run.diagnostics[0].message
    assert missing_run.diagnostics[0].details["identity"] == THIRD_RUN_ID
    absent_experiment = _insert_run_without_its_experiment(sqlite_harness.database)
    missing_experiment = source.run_facts(THIRD_RUN_ID)
    assert isinstance(missing_experiment, Failure)
    assert _code(missing_experiment) == INVARIANT_VIOLATION
    assert (
        f"experiment {absent_experiment} does not exist"
        in missing_experiment.diagnostics[0].message
    )
    assert missing_experiment.diagnostics[0].details["identity"] == absent_experiment
    # A sound pair is still read after the orphan exists: the join is by ownership.
    assert ok(source.run_facts(RUN_ID)).experiment_id == EXPERIMENT_ID


# --------------------------------------------------------------------------
# Refusals: egress, storage, never an empty success
# --------------------------------------------------------------------------


def test_a_row_failing_egress_refuses_the_whole_listing_naming_the_row(
    sqlite_harness: SqliteHarness,
) -> None:
    _seed_all(sqlite_harness)
    connection = raw_connection(sqlite_harness.database.path)
    try:
        # Five characters pass the column CHECK; ``SemanticVersion`` refuses them.
        connection.execute(
            "UPDATE command_invocations SET adapter_version = ? "
            "WHERE invocation_id = ?",
            ("abcde", _inv(3)),
        )
    finally:
        connection.close()
    source = SqliteReconciliationSource(sqlite_harness.database, FixedClock(INSTANT))
    refused = source.list_reconciliation_targets()
    assert isinstance(refused, Failure)
    assert _code(refused) == INVARIANT_VIOLATION
    details = refused.diagnostics[0].details
    assert details["table"] == "command_invocations"
    assert details["identity"] == _inv(3)
    assert details["operation"] == "decode"
    assert _checked_out(sqlite_harness.database) == 0


def test_a_run_or_experiment_row_failing_egress_refuses_the_facts_naming_it(
    sqlite_harness: SqliteHarness,
) -> None:
    """Both records of one facts read pass through their codecs (reading 10)."""
    _seed_parents(sqlite_harness)
    source = SqliteReconciliationSource(sqlite_harness.database, FixedClock(INSTANT))
    assert ok(source.run_facts(OTHER_RUN_ID)).run_id == OTHER_RUN_ID
    connection = raw_connection(sqlite_harness.database.path)
    try:
        # The run row: five characters pass the column CHECK, the record refuses.
        connection.execute(
            "UPDATE engine_runs SET adapter_version = ? WHERE run_id = ?",
            ("abcde", OTHER_RUN_ID),
        )
        # The experiment row: valid JSON passes the column CHECK (a QUEUED row is
        # not guarded by the frozen-spec trigger for this column), the record
        # refuses the shape.
        connection.execute(
            "UPDATE experiments SET slot_compatibility = ? WHERE experiment_id = ?",
            ('[{"bogus": 1}]', EXPERIMENT_ID),
        )
    finally:
        connection.close()
    run_refused = source.run_facts(OTHER_RUN_ID)
    assert isinstance(run_refused, Failure)
    assert _code(run_refused) == INVARIANT_VIOLATION
    assert run_refused.diagnostics[0].details["table"] == "engine_runs"
    assert run_refused.diagnostics[0].details["identity"] == OTHER_RUN_ID
    assert run_refused.diagnostics[0].details["operation"] == "decode"
    experiment_refused = source.run_facts(RUN_ID)  # this run's row is still sound
    assert isinstance(experiment_refused, Failure)
    assert _code(experiment_refused) == INVARIANT_VIOLATION
    assert experiment_refused.diagnostics[0].details["table"] == "experiments"
    assert experiment_refused.diagnostics[0].details["identity"] == EXPERIMENT_ID
    assert experiment_refused.diagnostics[0].details["operation"] == "decode"
    assert _checked_out(sqlite_harness.database) == 0


def test_a_database_without_the_schema_is_a_storage_failure_not_an_empty_listing(
    bare_database: SqliteDatabase,
) -> None:
    source = SqliteReconciliationSource(bare_database, FixedClock(INSTANT))
    listed = source.list_reconciliation_targets()
    assert isinstance(listed, Failure)
    assert _code(listed) == STORAGE_UNAVAILABLE
    assert listed.diagnostics[0].details["operation"] == "list_reconciliation_targets"
    facts = source.run_facts(RUN_ID)
    assert isinstance(facts, Failure)
    assert _code(facts) == STORAGE_UNAVAILABLE
    assert facts.diagnostics[0].details["operation"] == "run_facts"
    assert _checked_out(bare_database) == 0


def test_an_exhausted_pool_is_a_storage_failure_and_the_session_is_released(
    sqlite_harness: SqliteHarness, fixed_clock: FixedClock
) -> None:
    _seed_parents(sqlite_harness)
    single = ok(
        SqliteDatabase.open(
            sqlite_harness.database.path,
            busy_timeout_ms=100,
            clock=fixed_clock,
            revision_policy=accept_any_revision,
            pool_size=1,
            max_overflow=0,
            pool_timeout_seconds=0.1,
        )
    )
    try:
        source = SqliteReconciliationSource(single, fixed_clock)
        assert ok(source.run_facts(RUN_ID)).run_id == RUN_ID
        with single.connection():
            listed = source.list_reconciliation_targets()
            facts = source.run_facts(RUN_ID)
        assert _code(listed) == STORAGE_UNAVAILABLE
        assert _code(facts) == STORAGE_UNAVAILABLE
        # The pool of one is whole again: the refused checkouts held nothing.
        assert ok(source.list_reconciliation_targets()) == ()
        assert _checked_out(single) == 0
    finally:
        single.close()


# --------------------------------------------------------------------------
# No write, the indexes, and the released session
# --------------------------------------------------------------------------


def test_every_statement_of_a_pass_is_a_read_and_the_listing_uses_the_index(
    sqlite_harness: SqliteHarness,
) -> None:
    _seed_all(sqlite_harness)
    database = sqlite_harness.database
    source = SqliteReconciliationSource(database, FixedClock(INSTANT))
    recorder = _StatementRecorder(_engine_of(database))
    before = total_changes(database)
    with recorder.attached():
        listed = ok(source.list_reconciliation_targets())
        facts = ok(source.run_facts(OTHER_RUN_ID))
    assert len(listed) == len(EXPECTED_TARGET_ORDER)
    assert facts.run_id == OTHER_RUN_ID
    assert total_changes(database) == before
    verbs = recorder.verbs()
    assert verbs
    assert set(verbs) <= {"BEGIN", "SELECT"}
    assert verbs.count("BEGIN") == 2  # one read-only session per call
    sql, parameters = recorder.listing_statement()
    plan = _query_plan(database, sql, parameters)
    assert _searches_with(plan, _LISTING_INDEX), plan
    # Plan 1.5 note 4: the reconciler evaluates deadlines in memory; the
    # ``(state, deadline_utc)`` index specification 23.3.1 requires is what a
    # deadline filter over the same table uses.
    deadline_plan = _query_plan(
        database,
        "SELECT invocation_id FROM command_invocations "
        "WHERE state = ? AND deadline_utc <= ?",
        ("RUNNING", 0),
    )
    assert _searches_with(deadline_plan, _DEADLINE_INDEX), deadline_plan


def test_the_session_is_released_on_every_path_and_nothing_is_open_afterwards(
    sqlite_harness: SqliteHarness,
) -> None:
    _seed_all(sqlite_harness)
    database = sqlite_harness.database
    source = SqliteReconciliationSource(database, FixedClock(INSTANT))
    assert _checked_out(database) == 0
    ok(source.list_reconciliation_targets())
    assert _checked_out(database) == 0
    ok(source.run_facts(RUN_ID))
    assert _checked_out(database) == 0
    assert _code(source.run_facts(THIRD_RUN_ID)) == INVARIANT_VIOLATION
    assert _checked_out(database) == 0
    # A fresh writer is not blocked by anything the source left behind.
    transaction = sqlite_harness.unit_of_work().begin()
    stored = ok(transaction.command_invocations.get(_inv(1)))
    ok(
        transaction.command_invocations.compare_and_swap(
            0, bump_invocation(stored, _C.STARTING)
        )
    )
    ok(transaction.commit())
    assert _stored_state(sqlite_harness, _inv(1)) is _C.STARTING


def _stored_state(harness: SqliteHarness, invocation_id: str) -> CommandInvocationState:
    """The committed state of one invocation, read through a fresh transaction."""
    transaction = harness.unit_of_work().begin()
    try:
        return ok(transaction.command_invocations.get(invocation_id)).state
    finally:
        transaction.rollback()


def test_the_listing_is_a_snapshot_and_a_later_write_keeps_its_cas_protection(
    sqlite_harness: SqliteHarness,
) -> None:
    _seed_all(sqlite_harness)
    source = SqliteReconciliationSource(sqlite_harness.database, FixedClock(INSTANT))
    listed = ok(source.list_reconciliation_targets())
    (stale,) = (record for record in listed if record.invocation_id == _inv(1))
    assert stale.state is _C.PENDING
    # Another actor moves the row after the listing returned.
    transaction = sqlite_harness.unit_of_work().begin()
    ok(
        transaction.command_invocations.compare_and_swap(
            0, bump_invocation(stale, _C.STARTING)
        )
    )
    ok(transaction.commit())
    # The returned list does not follow the write; a new call does.
    assert stale.state is _C.PENDING
    (current,) = (
        record
        for record in ok(source.list_reconciliation_targets())
        if record.invocation_id == _inv(1)
    )
    assert current.state is _C.STARTING
    assert current.revision == 1
    # A write carrying the stale revision is refused at the call: the existing
    # compare-and-swap protection is what keeps a stale list from winning.
    later = sqlite_harness.unit_of_work().begin()
    refused = later.command_invocations.compare_and_swap(
        stale.revision, bump_invocation(stale, _C.STARTING)
    )
    assert _code(refused) == "PERSISTENCE.CONCURRENCY_CONFLICT"
    later.rollback()


def test_records_are_validated_and_stay_usable_after_the_database_closes(
    tmp_path: Path, fixed_clock: FixedClock
) -> None:
    database = open_test_database(tmp_path, clock=fixed_clock)
    harness = SqliteHarness(database)
    try:
        _seed_all(harness)
        source = SqliteReconciliationSource(database, fixed_clock)
        assert isinstance(source, ReconciliationSource)
        listed = ok(source.list_reconciliation_targets())
        facts = ok(source.run_facts(RUN_ID))
    finally:
        harness.close()
    # Detached: every value is a validated record, readable with the engine gone.
    assert all(isinstance(record, CommandInvocationRecord) for record in listed)
    assert [record.invocation_id for record in listed] == EXPECTED_TARGET_ORDER
    assert listed[1].model_dump(mode="json")["state"] == "PENDING"
    assert facts.model_dump(mode="json")["run_id"] == RUN_ID


class _CheckoutRecordingController(ScriptedProcessController):
    """The scripted controller, recording the pool's lent connections at inspect."""

    def __init__(self, database: SqliteDatabase) -> None:
        super().__init__(clock=None)
        self._database = database
        self.checked_out_at_inspect: list[int] = []

    def inspect(self, identity: Any) -> ProcessInspection:
        self.checked_out_at_inspect.append(_checked_out(self._database))
        return super().inspect(identity)


def test_no_connection_is_lent_while_the_reconciler_inspects_a_process(
    sqlite_harness: SqliteHarness, tmp_path: Path
) -> None:
    _seed_parents(sqlite_harness)
    _put_invocation(
        sqlite_harness,
        _seeded(_C.RUNNING, ordinal=5, kind=_K.RUN, created=3, run_id=OTHER_RUN_ID),
    )
    database = sqlite_harness.database
    clock = FixedClock(INSTANT)
    controller = _CheckoutRecordingController(database)
    controller.inspection = ProcessPresence.ABSENT
    report = ok(
        reconcile_invocations(
            source=SqliteReconciliationSource(database, clock),
            lifecycle=Stage5InvocationLifecycle(
                unit_of_work=sqlite_harness.unit_of_work(),
                clock=clock,
                diagnostics=SqliteDiagnosticRecorder(database, clock=clock),
            ),
            controller=controller,
            preflight=PathPreflight(
                supervision_root=str(tmp_path / "supervision"),
                long_paths_supported=False,
                directory_ceiling=247,
                file_ceiling=259,
                probed_at_utc=INSTANT,
            ),
            clock=clock,
            supervisor_instance_id=SCRIPTED_SUPERVISOR_INSTANCE_ID,
            observer=MISSING,
        )
    )
    (entry,) = report.entries
    assert entry.action is ReconciliationAction.LEFT_RUNNING_AWAITING_DEADLINE
    assert controller.checked_out_at_inspect == [0]
    assert _checked_out(database) == 0
    assert sqlite_harness.open_transactions() == ()


@pytest.mark.parametrize("member", ["list_reconciliation_targets", "run_facts"])
def test_the_source_matches_the_port_signature_member_by_member(member: str) -> None:
    port = inspect.signature(getattr(ReconciliationSource, member))
    implementation = inspect.signature(getattr(SqliteReconciliationSource, member))
    assert tuple(implementation.parameters) == tuple(port.parameters)
    assert reconciliation_source_module.__all__ == ["SqliteReconciliationSource"]
