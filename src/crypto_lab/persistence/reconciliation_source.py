"""The SQLite ``ReconciliationSource`` (plan 4.5, Task 5).

``SqliteReconciliationSource(database, clock)`` implements the Stage 7 port
``crypto_lab.process_supervision.ports.ReconciliationSource`` over the Task 2
tables, structurally and without naming it. Each call opens one read-only
session -- ``SqliteDatabase.read_only()``: a deferred ``BEGIN``, the reads, then
``ROLLBACK`` in the context manager's ``finally`` -- so no connection, snapshot
or lock survives the call, and the reconciler inspects, terminates, cleans up
and writes only after the session has closed. Both members decode the rows
they read after the session is released, so every value they return is a
validated record detached from any connection. The source issues no write.

``list_reconciliation_targets`` selects every nonterminal invocation and every
terminal one whose ``cleanup_complete`` is false, ordered
``(created_at_utc, invocation_id)`` -- the predicate is written as the two
index-served disjuncts ``state IN (nonterminal)`` and
``state IN (terminal) AND cleanup_complete = 0`` so the
``(state, cleanup_complete, created_at_utc, invocation_id)`` index of plan 3.3.4
serves it -- and decodes every row through the Task 3 codec (reading 10). A row
that fails egress is ``CORE.INVARIANT_VIOLATION`` naming it, and the listing is
then refused as a whole: a partial population is never returned.

``run_facts`` reads the run and its experiment in one ``SELECT`` from one
snapshot (``engine_runs`` outer-joined to ``experiments`` on ``experiment_id``,
every column of both tables labelled by table), decodes both records through
their codecs and assembles ``RunReconciliationFacts`` from the validated records
alone. A missing run, and a run whose experiment is absent, are each
``CORE.INVARIANT_VIOLATION`` saying ``does not exist`` (reading 4) -- both from
the same snapshot, so a missing experiment is a genuine invariant, never a race
artefact.

A checkout or statement the database refuses -- a DBAPI error, or the pool's own
timeout, which is not a DBAPI error -- is the classified persistence ``Failure``
of plan 6.5, never an empty success. The clock is read only to stamp failures.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

from sqlalchemy import Select, select
from sqlalchemy.engine import RowMapping
from sqlalchemy.exc import DBAPIError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError
from sqlalchemy.sql import FromClause
from sqlalchemy.sql.elements import Label

from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.diagnostics import DiagnosticDetailValue
from crypto_lab.domain.identifiers import RunId
from crypto_lab.domain.lifecycle import (
    TERMINAL_COMMAND_INVOCATION_STATES,
    CommandInvocationState,
)
from crypto_lab.domain.ports import Clock
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.persistence.codecs import (
    decode_command_invocation,
    decode_engine_run,
    decode_experiment,
)
from crypto_lab.persistence.database import SqliteDatabase
from crypto_lab.persistence.diagnostics import INVARIANT_VIOLATION, persistence_failure
from crypto_lab.persistence.schema import (
    CommandInvocationRow,
    EngineRunRow,
    ExperimentRow,
)
from crypto_lab.process_supervision.models import RunReconciliationFacts

__all__ = ["SqliteReconciliationSource"]

#: The two disjuncts of plan 4.5's predicate, as the closed state vocabulary
#: partitions it: every state is either nonterminal or terminal.
_NONTERMINAL_STATES: Final[tuple[str, ...]] = tuple(
    sorted(
        state.value
        for state in CommandInvocationState
        if state not in TERMINAL_COMMAND_INVOCATION_STATES
    )
)
_TERMINAL_STATES: Final[tuple[str, ...]] = tuple(
    sorted(state.value for state in TERMINAL_COMMAND_INVOCATION_STATES)
)
#: The labels that split one joined row back into its two tables' columns.
_RUN_PREFIX: Final = "run__"
_EXPERIMENT_PREFIX: Final = "experiment__"
_LISTING: Final = "list_reconciliation_targets"
_FACTS: Final = "run_facts"

#: Plan 4.5: the listing, served by ``ix_command_invocations_reconciliation_listing``.
_TARGET_LISTING: Final[Select[tuple[CommandInvocationRow]]] = (
    select(CommandInvocationRow)
    .where(
        CommandInvocationRow.state.in_(_NONTERMINAL_STATES)
        | (
            CommandInvocationRow.state.in_(_TERMINAL_STATES)
            & (CommandInvocationRow.cleanup_complete == 0)
        )
    )
    .order_by(CommandInvocationRow.created_at_utc, CommandInvocationRow.invocation_id)
)


def _labelled(table: FromClause, prefix: str) -> list[Label[Any]]:
    return [column.label(f"{prefix}{column.name}") for column in table.c]


#: Plan 4.5: one ``SELECT`` joining the run to its experiment on ``experiment_id``;
#: the outer join keeps a run whose experiment is absent so that absence can be
#: named, from the same snapshot as the run.
_RUN_FACTS: Final = select(
    *_labelled(EngineRunRow.__table__, _RUN_PREFIX),
    *_labelled(ExperimentRow.__table__, _EXPERIMENT_PREFIX),
).select_from(
    EngineRunRow.__table__.outerjoin(
        ExperimentRow.__table__,
        EngineRunRow.__table__.c.experiment_id
        == ExperimentRow.__table__.c.experiment_id,
    )
)


def _values(row: RowMapping) -> dict[str, object]:
    """One stored row as the codecs' ``Mapping[str, object]``."""
    return {str(key): value for key, value in row.items()}


def _split(row: Mapping[str, object], prefix: str) -> dict[str, object]:
    """The columns of one table out of a labelled joined row."""
    return {
        key[len(prefix) :]: value
        for key, value in row.items()
        if key.startswith(prefix)
    }


class SqliteReconciliationSource:
    """``ReconciliationSource`` over one read-only session per call (plan 4.5)."""

    __slots__ = ("_clock", "_database")

    def __init__(self, database: SqliteDatabase, clock: Clock) -> None:
        self._database = database
        self._clock = clock

    def list_reconciliation_targets(
        self,
    ) -> Result[tuple[CommandInvocationRecord, ...]]:
        try:
            with self._database.read_only() as connection:
                rows = connection.execute(_TARGET_LISTING).mappings().all()
        except (DBAPIError, PoolTimeoutError) as error:
            return self._refused(error, table="command_invocations", operation=_LISTING)
        records: list[CommandInvocationRecord] = []
        for row in rows:
            decoded = decode_command_invocation(_values(row), clock=self._clock)
            if isinstance(decoded, Failure):
                return decoded
            records.append(decoded.value)
        return Success[tuple[CommandInvocationRecord, ...]](
            outcome="SUCCESS", value=tuple(records)
        )

    def run_facts(self, run_id: RunId) -> Result[RunReconciliationFacts]:
        try:
            with self._database.read_only() as connection:
                row = (
                    connection.execute(
                        _RUN_FACTS.where(EngineRunRow.__table__.c.run_id == run_id)
                    )
                    .mappings()
                    .first()
                )
        except (DBAPIError, PoolTimeoutError) as error:
            return self._refused(
                error, table="engine_runs", operation=_FACTS, identity=run_id
            )
        if row is None:
            return self._missing("run", run_id, table="engine_runs")
        joined = _values(row)
        run = decode_engine_run(_split(joined, _RUN_PREFIX), clock=self._clock)
        if isinstance(run, Failure):
            return run
        experiment_columns = _split(joined, _EXPERIMENT_PREFIX)
        if experiment_columns.get("experiment_id") is None:
            return self._missing(
                "experiment", run.value.experiment_id, table="experiments"
            )
        experiment = decode_experiment(experiment_columns, clock=self._clock)
        if isinstance(experiment, Failure):
            return experiment
        return Success[RunReconciliationFacts](
            outcome="SUCCESS",
            value=RunReconciliationFacts(
                run_id=run.value.run_id,
                experiment_id=run.value.experiment_id,
                run_state=run.value.state,
                run_revision=run.value.revision,
                attempt_token_hash=run.value.attempt_token_hash,
                request_hash=run.value.request_hash,
                experiment_state=experiment.value.state,
            ),
        )

    # -- failures (plan 6.5) ---------------------------------------------------

    def _missing(self, kind: str, identity: str, *, table: str) -> Failure:
        """Reading 4: a missing identity is the invariant and says what is absent."""
        return persistence_failure(
            INVARIANT_VIOLATION,
            message=f"{kind} {identity} does not exist",
            clock=self._clock,
            details={"table": table, "operation": _FACTS, "identity": identity},
        )

    def _refused(
        self,
        error: DBAPIError | PoolTimeoutError,
        *,
        table: str,
        operation: str,
        identity: str = "",
    ) -> Failure:
        """A refused checkout or read mapped through the single failure authority."""
        details: dict[str, DiagnosticDetailValue] = {
            "table": table,
            "operation": operation,
        }
        if identity:
            details["identity"] = identity
        origin = getattr(error, "orig", None)
        for name in ("sqlite_errorcode", "sqlite_errorname"):
            value = getattr(origin, name, None)
            if isinstance(value, int | str) and not isinstance(value, bool):
                details[name] = value
        return persistence_failure(
            SqliteDatabase.classify(error),
            message=f"{operation} on {table} was refused by the database",
            clock=self._clock,
            details=details,
        )
