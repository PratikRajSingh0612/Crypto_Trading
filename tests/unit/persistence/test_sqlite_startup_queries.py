"""Stage 10 plan Task 2: the detached startup projections over SQLite (Matrix B
row B11, plan section 4.2).

``SqliteReconciliationSource.work_inventory`` implements the application query port
``ApplicationQueryPort`` over the migrated schema: one short read-only session
reads every experiment, engine run, command invocation and retry decision in
canonical identity order, the session is released before any row is decoded, and
the decoded records are assembled into one validated ``DurableWorkInventory``.
``SqliteDatabase.read_work_inventory`` owns the session and the failure mapping,
``SqliteDatabase.read_consistency`` and ``SqliteDatabase.verify_revision`` are the
fail-closed twins of the consistency report and the revision policy the startup
coordinator rechecks after it owns dispatch.

Declared readings:

- "Complete" means every row of the four tables, compared with the harness's own
  committed readers, which open their own sessions and decode independently.
- "Detached" means the returned records stay valid and equal after the database
  that produced them is closed, and no connection is checked out once the call
  has returned.
- "Fail closed" means a refused statement, a refused fetch, a row that fails
  egress and a population whose relationships do not close are each a
  ``Failure``; none is an empty or partial inventory.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Final

import pytest
from sqlalchemy.pool import QueuePool

from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.results import Failure, Success
from crypto_lab.experiments.application_ports import (
    ApplicationQueryPort,
    DurableWorkInventory,
)
from crypto_lab.experiments.requests import RetryEvaluationRequest
from crypto_lab.experiments.retry import evaluate_retry
from crypto_lab.persistence.codecs import encode_engine_run
from crypto_lab.persistence.database import ConsistencyReport, SqliteDatabase
from crypto_lab.persistence.diagnostics import (
    INVARIANT_VIOLATION,
    MIGRATION_MISMATCH,
    STORAGE_UNAVAILABLE,
    persistence_failure,
)
from crypto_lab.persistence.migration_runner import (
    RevisionState,
    check_revision,
    open_database,
)
from crypto_lab.persistence.reconciliation_source import SqliteReconciliationSource
from doubles.experiments import (
    ADAPTER_BETA,
    AVAIL_A,
    AVAIL_B,
    ENGINE_BETA,
    EXPERIMENT_ID,
    INSTANT,
    OTHER_EXPERIMENT_ID,
    OTHER_RUN_ID,
    RUN_ID,
    SLOT_A,
    SLOT_B,
    THIRD_RUN_ID,
    UUID_E,
    FixedClock,
    sample_diagnostic,
    sample_draft,
    sample_experiment,
    sample_invocation,
    sample_observation,
    sample_retry_policy,
    sample_run,
)
from persistence_support.harness import (
    SqliteHarness,
    code,
    cursor_fault,
    fetch_fault,
    ok,
    put_experiment,
    put_invocation,
    put_run,
    raw_connection,
    sqlite_error,
)

_C: Final = CommandInvocationState
_E: Final = ExperimentState
_K: Final = CommandKind
_R: Final = EngineRunState
#: ``SQLITE_CORRUPT``: an unlisted code, so the single failure authority maps it to
#: storage unavailability rather than a conflict or a write failure.
_CORRUPT: Final = (11, "SQLITE_CORRUPT")
#: The evaluation instant of the seeded retry decision (after every fixture instant).
_DECIDED_AT: Final = INSTANT + timedelta(minutes=1)


def _inv(ordinal: int) -> str:
    return f"inv_00000000-0000-4000-8000-{ordinal:012d}"


#: Inserted out of identity order (3, 1, 2) so the inventory's order is its own.
_INVOCATIONS: Final[tuple[CommandInvocationRecord, ...]] = (
    sample_invocation(
        _C.PENDING,
        kind=_K.DESCRIBE,
        invocation_id=_inv(3),
        created_at_utc=INSTANT + timedelta(seconds=3),
    ),
    sample_invocation(
        _C.RUNNING,
        kind=_K.RUN,
        invocation_id=_inv(1),
        run_id=OTHER_RUN_ID,
        created_at_utc=INSTANT + timedelta(seconds=1),
    ),
    sample_invocation(
        _C.EXITED,
        kind=_K.VALIDATE,
        invocation_id=_inv(2),
        created_at_utc=INSTANT + timedelta(seconds=2),
    ),
)


def _seed(harness: SqliteHarness) -> None:
    """Two experiments (inserted B before A), two attempts, three invocations and
    one ALLOWED retry decision committed through the real ``evaluate_retry``."""
    policy = sample_retry_policy(retry_delay_seconds=30)
    experiment = sample_experiment(_E.RUNNING, draft=sample_draft(retry_policy=policy))
    predecessor = sample_run(_R.FAILED)
    harness.seed_observation(sample_observation(AVAIL_A))
    harness.seed_observation(sample_observation(AVAIL_B))
    harness.seed_diagnostic(sample_diagnostic())
    put_experiment(
        harness, sample_experiment(_E.DRAFT, experiment_id=OTHER_EXPERIMENT_ID)
    )
    put_experiment(harness, experiment)
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
    put_run(harness, predecessor)
    for record in _INVOCATIONS:
        put_invocation(harness, record)
    ok(
        evaluate_retry(
            RetryEvaluationRequest(
                schema_version="1.0.0",
                experiment_id=EXPERIMENT_ID,
                logical_slot_id=SLOT_A,
                predecessor_run_id=RUN_ID,
                expected_experiment_revision=experiment.revision,
                expected_predecessor_revision=predecessor.revision,
            ),
            unit_of_work=harness.unit_of_work(),
            clock=FixedClock(_DECIDED_AT),
        )
    )


def _reading(table: str) -> Callable[[str], bool]:
    """A fault predicate admitting exactly the statement that reads ``table``."""

    def admits(statement: str) -> bool:
        return f"FROM {table}" in statement

    return admits


def _checked_out(database: SqliteDatabase) -> int:
    """Connections the pool has lent out, not counting this probe's own."""
    with database.connection() as connection:
        pool = connection.engine.pool
        assert isinstance(pool, QueuePool)
        return pool.checkedout() - 1


def _insert_orphan_run(database: SqliteDatabase) -> None:
    """A run naming an absent experiment: only a raw insert with foreign keys off
    can plant it, so the population's relationships do not close."""
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


def _corrupt_run_row(database: SqliteDatabase) -> None:
    """One stored run whose request hash is no SHA-256 (CHECKs bypassed)."""
    connection = raw_connection(database.path)
    try:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute(
            "UPDATE engine_runs SET request_hash = 'not-a-hash' WHERE run_id = ?",
            (OTHER_RUN_ID,),
        )
    finally:
        connection.close()


def _assert_inventory_matches_committed_rows(
    inventory: DurableWorkInventory, harness: SqliteHarness
) -> None:
    assert inventory.experiments == harness.committed_experiments()
    assert inventory.engine_runs == harness.committed_engine_runs()
    assert inventory.command_invocations == harness.committed_command_invocations()
    assert inventory.retry_decisions == harness.committed_retry_decisions()


def test_startup_queries_are_complete_detached_and_fail_closed(
    sqlite_harness: SqliteHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = sqlite_harness.database
    clock = FixedClock(INSTANT)
    _seed(sqlite_harness)
    source = SqliteReconciliationSource(database, clock)
    assert isinstance(source, ApplicationQueryPort)
    inventory = ok(source.work_inventory())
    assert isinstance(inventory, DurableWorkInventory)
    _assert_inventory_matches_committed_rows(inventory, sqlite_harness)
    # Every population is present and in canonical identity order.
    assert [record.experiment_id for record in inventory.experiments] == [
        EXPERIMENT_ID,
        OTHER_EXPERIMENT_ID,
    ]
    assert [record.run_id for record in inventory.engine_runs] == [RUN_ID, OTHER_RUN_ID]
    assert [record.invocation_id for record in inventory.command_invocations] == [
        _inv(1),
        _inv(2),
        _inv(3),
    ]
    (decision,) = inventory.retry_decisions
    assert decision.predecessor_run_id == RUN_ID
    assert decision.decided_at_utc == _DECIDED_AT
    # One short session, released before the call returned; nothing written.
    assert _checked_out(database) == 0
    assert sqlite_harness.open_transactions() == ()
    # Read failures at the statement and at the fetch are classified refusals.
    for table in ("experiments", "engine_runs", "command_invocations"):
        with cursor_fault(database, monkeypatch) as fault:
            fault.arm(sqlite_error(*_CORRUPT), when=_reading(table))
            refused = source.work_inventory()
            assert not fault.armed, table
        assert code(refused) == STORAGE_UNAVAILABLE, table
        assert isinstance(refused, Failure)
        assert refused.diagnostics[0].details["operation"] == "work_inventory"
        assert _checked_out(database) == 0
    with fetch_fault(monkeypatch) as fetch:
        fetch.arm(
            sqlite_error(*_CORRUPT),
            when=lambda statement: "FROM retry_decisions" in statement,
        )
        refused = source.work_inventory()
        assert not fetch.armed
    assert code(refused) == STORAGE_UNAVAILABLE
    # A row that fails egress refuses the whole inventory, never a partial one.
    _corrupt_run_row(database)
    malformed = source.work_inventory()
    assert code(malformed) == INVARIANT_VIOLATION
    assert isinstance(malformed, Failure)
    assert malformed.diagnostics[0].details["table"] == "engine_runs"
    assert malformed.diagnostics[0].details["identity"] == OTHER_RUN_ID
    # Detached: the earlier inventory survives the database that produced it.
    database.close()
    assert inventory.model_dump(mode="json")["engine_runs"][0]["run_id"] == RUN_ID


def test_startup_queries_refuse_a_population_whose_relationships_do_not_close(
    sqlite_harness: SqliteHarness,
) -> None:
    database = sqlite_harness.database
    _seed(sqlite_harness)
    _insert_orphan_run(database)
    refused = SqliteReconciliationSource(database, FixedClock(INSTANT)).work_inventory()
    assert code(refused) == INVARIANT_VIOLATION
    assert isinstance(refused, Failure)
    details = refused.diagnostics[0].details
    assert details["operation"] == "work_inventory"
    assert "unknown experiment" in refused.diagnostics[0].message


def test_startup_queries_survive_reopen(
    sqlite_harness: SqliteHarness, tmp_path: Path
) -> None:
    _seed(sqlite_harness)
    path = sqlite_harness.database.path
    first = ok(
        SqliteReconciliationSource(
            sqlite_harness.database, FixedClock(INSTANT)
        ).work_inventory()
    )
    sqlite_harness.close()
    for reopening in range(2):
        reopened = ok(
            open_database(path, busy_timeout_ms=100, clock=FixedClock(_DECIDED_AT))
        )
        try:
            again = ok(
                SqliteReconciliationSource(
                    reopened, FixedClock(_DECIDED_AT)
                ).work_inventory()
            )
        finally:
            reopened.close()
        assert again == first, reopening
        assert again.model_dump(mode="json") == first.model_dump(mode="json")
    assert path.parent == tmp_path


def test_startup_consistency_and_revision_reads_fail_closed(
    sqlite_database: SqliteDatabase, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fail-closed twins: twelve explicit counts or a classified ``Failure``;
    a revision policy over a fresh connection whose refused read is a ``Failure``
    and whose own verdict is returned unchanged."""
    report = ok(sqlite_database.read_consistency())
    assert isinstance(report, ConsistencyReport)
    assert report == ConsistencyReport(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    with cursor_fault(sqlite_database, monkeypatch) as fault:
        fault.arm(
            sqlite_error(*_CORRUPT),
            when=lambda statement: "finalization_journal" in statement,
        )
        refused = sqlite_database.read_consistency()
        assert not fault.armed
    assert code(refused) == STORAGE_UNAVAILABLE
    assert isinstance(refused, Failure)
    assert refused.diagnostics[0].details["operation"] == "consistency_report"
    observed: list[RevisionState] = []

    def current_only(connection: object) -> Success[None] | Failure:
        state = check_revision(connection).state  # type: ignore[arg-type]
        observed.append(state)
        if state is RevisionState.CURRENT:
            return Success[None](outcome="SUCCESS", value=None)
        return persistence_failure(
            MIGRATION_MISMATCH, message="not current", clock=FixedClock(INSTANT)
        )

    assert isinstance(sqlite_database.verify_revision(current_only), Success)
    assert observed == [RevisionState.CURRENT]
    with cursor_fault(sqlite_database, monkeypatch) as fault:
        fault.arm(sqlite_error(*_CORRUPT))
        unread = sqlite_database.verify_revision(current_only)
    assert code(unread) == STORAGE_UNAVAILABLE
    assert isinstance(unread, Failure)
    assert unread.diagnostics[0].details["operation"] == "verify_revision"
