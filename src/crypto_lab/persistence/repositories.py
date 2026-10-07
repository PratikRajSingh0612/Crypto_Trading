"""The four lifecycle repositories over the Task 3 codecs (plan 4.3, Task 4).

``SqliteExperimentRepository``, ``SqliteEngineRunRepository``,
``SqliteCommandInvocationRepository`` and ``SqliteRetryDecisionRepository``
implement the Stage 5 ports of plan 4.3 as SQLAlchemy Core statements on the one
connection their ``SqliteTransaction`` owns. There is no ORM session, no identity
map and no deferred flush: every statement executes when the method issues it and
nowhere else, so nothing a method did not issue can be written and no implicit
flush can reorder the compare-and-swap precedence of plan 4.3.1 (reading 21).
A repository never commits, never rolls the transaction back and never opens a
connection of its own; durability is the owning unit of work's decision.

``TransactionScope`` is the single gate. Every method begins with
``open_statement()``, which raises ``RuntimeError`` on a finished transaction (a
programmer defect, reading 2), returns the stored ``Failure`` on a transaction the
I/O-class rule closed, and otherwise hands back the connection. The connection is
reachable no other way, so a closed transaction cannot issue a statement -- which
matters because SQLite may already have ended the transaction after an I/O error
and a later statement would otherwise run, and commit, in autocommit mode. The
four repositories here close the transaction through ``refused``; the five
persistence-owned members the unit of work binds over the Task 3 registries hand
their results back through ``absorb``, which stores a ``PERSISTENCE.WRITE_FAILED``
the registry classified exactly as ``refused`` stores one, so plan 4.2's member
rule holds for every member of the transaction.

Compare-and-swap follows plan 4.3.1 in order and stops at the first refusal:
(a) pre-read the stored row on this transaction's own connection, which sees its
WAL snapshot plus every write this transaction has itself issued; (b) no row ->
``PERSISTENCE.CONCURRENCY_CONFLICT``; (c) a stored revision other than the
expected one -> the same conflict, decided before the replacement is inspected;
(d) a replacement whose revision is not ``expected + 1`` ->
``CORE.INVARIANT_VIOLATION``; (d') for experiments, the frozen-spec and queue-edge
guards of reading 13 and reading 22; (e) the conditional
``UPDATE ... WHERE <identity> = ? AND revision = ?``, which proves its own
precondition and is the first mutating statement any of these paths issues;
(f) zero affected rows, a refused write promotion or a busy timeout ->
the conflict; (g) one affected row -> provisional success. Steps b to d' issue no
mutating statement and open no savepoint, so a refused replacement leaves the
stored row exactly as it was.

The three methods that issue more than one statement --
``ExperimentRepository.add``, the slot-rewriting ``compare_and_swap`` -- wrap them
in one ``SAVEPOINT`` entered at step e, never before, and any refusal rolls back
to it, so a failed mutation leaves nothing of itself staged (reading 21, C-29).
The ``engine_slots`` projection rewrite is the one ``DELETE`` Stage 8 issues
(plan 3.3.2); it is legal only while the stored experiment is pre-``QUEUED``,
where the ``RESTRICT`` key proves no run can reference those slot rows.

Rule N4: ``encode_engine_run`` has no column for ``finalization_deadline_utc``.
``_encoded_run`` tests that condition directly rather than catching the codec's
``ValueError``, which has other causes, and returns ``CORE.INVARIANT_VIOLATION``
through the approved factory. The codec's contract is unchanged, the message
names the rule, the record's values never enter a diagnostic, and in
compare-and-swap the check happens at step e, so a missing or stale row still
refuses as a conflict first.

Every ``Failure`` carries one diagnostic from ``persistence/diagnostics.py``
stamped with the injected clock; the clock is read for nothing else, so the
operations' pinned clock-read counts hold. ``details`` names the table, the
operation, the identity and the SQLite result code, and never the SQL text of a
statement that could contain row values (plan 6.5).
"""

from __future__ import annotations

from typing import Any, Final

from pydantic import ValidationError
from pydantic.experimental.missing_sentinel import MISSING
from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import DBAPIError

from crypto_lab.adapters.events import RunEvent
from crypto_lab.configuration.models import ApplicationConfig
from crypto_lab.configuration.retry_policy import retry_policy_from_config
from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.diagnostics import DiagnosticDetailValue
from crypto_lab.domain.engine_run import EngineRunRecord
from crypto_lab.domain.experiment import (
    ExperimentRecord,
    experiment_configuration_hash,
)
from crypto_lab.domain.identifiers import (
    ExperimentId,
    InvocationId,
    LogicalSlotId,
    RunId,
)
from crypto_lab.domain.lifecycle import CommandKind, ExperimentState
from crypto_lab.domain.ports import Clock
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.domain.retry import RetryDecisionRecord
from crypto_lab.experiments.ports import RetryDecisionInsertOutcome
from crypto_lab.persistence.codecs import (
    RowValues,
    decode_command_invocation,
    decode_engine_run,
    decode_experiment,
    decode_retry_decision,
    decode_run_event,
    encode_command_invocation,
    encode_engine_run,
    encode_engine_slots,
    encode_experiment,
    encode_retry_decision,
    encode_run_event,
)
from crypto_lab.persistence.database import SqliteDatabase
from crypto_lab.persistence.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
    WRITE_FAILED,
    persistence_failure,
)
from crypto_lab.persistence.schema import (
    CommandInvocationRow,
    EngineRunRow,
    EngineSlotRow,
    ExperimentRow,
    RetryDecisionRow,
    RunEventRow,
)

__all__ = [
    "SqliteCommandInvocationRepository",
    "SqliteEngineRunRepository",
    "SqliteExperimentRepository",
    "SqliteRetryDecisionRepository",
    "TransactionScope",
]

#: Reading 3: the I/O class alone closes the transaction, because SQLite may
#: have ended it already. Every other refusal -- conflict, invariant, and the
#: unclassified storage faults ``classify`` maps to ``STORAGE_UNAVAILABLE`` by
#: default -- aborts its statement alone and leaves the transaction usable.
_CLOSING_CODES: Final[frozenset[str]] = frozenset({WRITE_FAILED})
#: Plan 4.3.1 step d': the two states a spec may still change in. The set is
#: exactly the T-EXP-FROZEN predicate's ``NOT IN (DRAFT, VALIDATED)``, so the
#: repository and the SQL layer refuse the same rows; a terminal experiment that
#: never reached QUEUED is therefore refused here rather than by T-EXP-TERMINAL,
#: with the same code.
_PRE_QUEUE_STATES: Final[frozenset[str]] = frozenset(
    {ExperimentState.DRAFT.value, ExperimentState.VALIDATED.value}
)


def _values(row: RowMapping) -> dict[str, object]:
    """One stored row as the codecs' ``Mapping[str, object]``.

    A ``RowMapping`` is keyed by column name here, but SQLAlchemy types its keys
    wider than ``str``; the copy narrows the type without changing a value.
    """
    return {str(key): value for key, value in row.items()}


def _none() -> Success[None]:
    return Success[None](outcome="SUCCESS", value=None)


def _absent() -> Success[Any]:
    """An ordinary ``MISSING`` answer, not a failure (the port's two probes)."""
    nothing: Any = MISSING
    return Success(outcome="SUCCESS", value=nothing)


class TransactionScope:
    """The mutable state every member of one ``SqliteTransaction`` shares.

    Constructed by the unit of work at ``begin()``. ``connection`` is ``None``
    exactly when the **checkout** failed; a failed ``BEGIN`` leaves the acquired
    connection bound with ``failure`` set, so ``rollback()`` can release it.
    Either way ``failure`` holds the ``PERSISTENCE.STORAGE_UNAVAILABLE`` every
    member call returns.
    """

    __slots__ = ("_clock", "_connection", "_failure", "_finished")

    def __init__(
        self,
        *,
        connection: Connection | None,
        clock: Clock,
        failure: Failure | None = None,
    ) -> None:
        self._connection = connection
        self._clock = clock
        self._failure = failure
        self._finished = False

    @property
    def clock(self) -> Clock:
        """The injected clock every failure diagnostic is stamped from."""
        return self._clock

    @property
    def failure(self) -> Failure | None:
        """The stored ``Failure`` of a closed transaction, or ``None``."""
        return self._failure

    @property
    def finished(self) -> bool:
        """Has ``commit()`` or ``rollback()`` already released this transaction?"""
        return self._finished

    def open_statement(self) -> Connection | Failure:
        """The one gate to the connection (plan 4.2).

        A finished transaction raises; a closed one answers with its stored
        ``Failure``; otherwise the caller may issue its statement.
        """
        if self._finished:
            raise RuntimeError("the transaction is closed")
        if self._failure is not None:
            return self._failure
        if self._connection is None:  # pragma: no cover - set with ``failure``
            raise RuntimeError("the transaction holds no connection")
        return self._connection

    def finish(self) -> None:
        """Mark the transaction released; every later member call is a defect."""
        self._finished = True
        self._connection = None

    def refused(
        self,
        error: DBAPIError,
        *,
        table: str,
        operation: str,
        identity: str,
    ) -> Failure:
        """Plan 6.5: one refused statement mapped through the single authority.

        An I/O-class code closes the transaction (plan 4.2), so every later
        member call and ``commit()`` return this same ``Failure`` and only
        ``rollback()`` releases the connection.
        """
        code = SqliteDatabase.classify(error)
        details: dict[str, DiagnosticDetailValue] = {
            "table": table,
            "operation": operation,
            "identity": identity,
        }
        for name in ("sqlite_errorcode", "sqlite_errorname"):
            value = getattr(error.orig, name, None)
            if isinstance(value, int | str) and not isinstance(value, bool):
                details[name] = value
        failure = persistence_failure(
            code,
            message=f"{operation} on {table} was refused by the database",
            clock=self._clock,
            details=details,
        )
        if code in _CLOSING_CODES and self._failure is None:
            self._failure = failure
        return failure

    def absorb[T](self, result: Result[T]) -> Result[T]:
        """Plan 4.2 for a member built over a bare connection: its own I/O-class
        ``Failure`` closes the transaction exactly as ``refused`` does.

        The transaction-bound members that are not lifecycle repositories -- the
        five persistence-owned writers and registries (readings 11, 12 and 22),
        the observation reader's guard and the gate-bound diagnostic reader --
        return the ``Failure`` their Task 3 class classified through
        ``persistence_failure`` without a scope to store it in, whether the
        refused statement was a write or a read. This stores the first such
        ``PERSISTENCE.WRITE_FAILED`` -- the same object the caller receives -- so
        the transaction is *logically failed* at once: every later member call
        and ``commit()`` answer with it and issue no SQL, and ``commit()``
        publishes nothing. Nothing is released here: the connection stays checked
        out and the transaction registered until an owner finalizer --
        ``commit()``, which returns the stored failure after releasing, or
        ``rollback()`` -- *physically releases* it (the lazy-release ruling).
        Every other result -- a ``Success``, a conflict, an invariant, an
        unclassified storage fault -- passes through unchanged and the
        transaction stays usable.
        """
        if (
            isinstance(result, Failure)
            and self._failure is None
            and any(item.error_code in _CLOSING_CODES for item in result.diagnostics)
        ):
            self._failure = result
        return result

    def conflict(
        self, message: str, *, table: str, operation: str, identity: str
    ) -> Failure:
        """A durable-state conflict the caller must reread (spec 23.2)."""
        return self._stamped(
            CONCURRENCY_CONFLICT,
            message,
            table=table,
            operation=operation,
            identity=identity,
        )

    def invariant(
        self, message: str, *, table: str, operation: str, identity: str
    ) -> Failure:
        """An impossible aggregate state the caller asked for (reading 4)."""
        return self._stamped(
            INVARIANT_VIOLATION,
            message,
            table=table,
            operation=operation,
            identity=identity,
        )

    def missing(
        self, kind: str, identity: str, *, table: str, operation: str = "get"
    ) -> Failure:
        """Reading 4: a missing identity is the invariant and says what is absent."""
        return self.invariant(
            f"{kind} {identity} does not exist",
            table=table,
            operation=operation,
            identity=identity,
        )

    def _stamped(
        self, code: str, message: str, *, table: str, operation: str, identity: str
    ) -> Failure:
        return persistence_failure(
            code,
            message=message,
            clock=self._clock,
            details={"table": table, "operation": operation, "identity": identity},
        )


def _revision_refusal(
    scope: TransactionScope,
    stored: RowMapping | None,
    *,
    expected_revision: int,
    replacement_revision: int,
    kind: str,
    table: str,
    identity: str,
) -> Failure | None:
    """Plan 4.3.1 steps b, c and d, in that order, over the pre-read row.

    Shared by the three compare-and-swap repositories so the order is written
    once. None of the three refusals issues a mutating statement.
    """
    if stored is None:
        return scope.conflict(
            f"{kind} {identity} does not exist for compare-and-swap",
            table=table,
            operation="compare_and_swap",
            identity=identity,
        )
    stored_revision = stored["revision"]
    if stored_revision != expected_revision:
        return scope.conflict(
            f"{kind} {identity} is at revision {stored_revision}, "
            f"not {expected_revision}",
            table=table,
            operation="compare_and_swap",
            identity=identity,
        )
    if replacement_revision != expected_revision + 1:
        return scope.invariant(
            f"{kind} replacement must carry revision {expected_revision + 1}, "
            f"not {replacement_revision}",
            table=table,
            operation="compare_and_swap",
            identity=identity,
        )
    return None


class SqliteExperimentRepository:
    """``ExperimentRepository`` over one transaction's connection (plan 4.3)."""

    __slots__ = ("_scope",)

    def __init__(self, scope: TransactionScope) -> None:
        self._scope = scope

    def get(self, experiment_id: ExperimentId) -> Result[ExperimentRecord]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        try:
            row = (
                opened.execute(
                    select(ExperimentRow).where(
                        ExperimentRow.experiment_id == experiment_id
                    )
                )
                .mappings()
                .first()
            )
        except DBAPIError as error:
            return self._scope.refused(
                error, table="experiments", operation="get", identity=experiment_id
            )
        if row is None:
            return self._scope.missing("experiment", experiment_id, table="experiments")
        return decode_experiment(_values(row), clock=self._scope.clock)

    def add(self, record: ExperimentRecord) -> Result[None]:
        """One savepoint around the experiment row and its slot projection (C-29)."""
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        identity = record.experiment_id
        table = "experiments"
        try:
            with opened.begin_nested():
                opened.execute(
                    insert(ExperimentRow).values(**encode_experiment(record))
                )
                table = "engine_slots"
                for slot in encode_engine_slots(record):
                    opened.execute(insert(EngineSlotRow).values(**slot))
        except DBAPIError as error:
            return self._scope.refused(
                error, table=table, operation="add", identity=identity
            )
        return _none()

    def compare_and_swap(
        self,
        expected_revision: int,
        replacement: ExperimentRecord,
    ) -> Result[ExperimentRecord]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        identity = replacement.experiment_id
        try:
            stored = (
                opened.execute(
                    select(
                        ExperimentRow.revision,
                        ExperimentRow.state,
                        ExperimentRow.spec_hash,
                        ExperimentRow.configuration_snapshot_json,
                        ExperimentRow.material_base_configuration_hash,
                    ).where(ExperimentRow.experiment_id == identity)
                )
                .mappings()
                .first()
            )
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table="experiments",
                operation="compare_and_swap",
                identity=identity,
            )
        refusal = _revision_refusal(
            self._scope,
            stored,
            expected_revision=expected_revision,
            replacement_revision=replacement.revision,
            kind="experiment",
            table="experiments",
            identity=identity,
        )
        if refusal is not None:
            return refusal
        assert stored is not None  # noqa: S101 - narrowed by _revision_refusal
        refusal = self._frozen_refusal(stored, replacement, identity)
        if refusal is not None:
            return refusal
        return self._write(opened, stored, expected_revision, replacement)

    def _frozen_refusal(
        self,
        stored: RowMapping,
        replacement: ExperimentRecord,
        identity: str,
    ) -> Failure | None:
        """Plan 4.3.1 step d': the frozen spec (reading 13) and the queue edge
        (reading 22). Neither check issues a statement."""
        stored_state = str(stored["state"])
        if (
            stored_state not in _PRE_QUEUE_STATES
            and replacement.spec_hash != stored["spec_hash"]
        ):
            return self._invariant(
                "the experiment spec is frozen from QUEUED onward", identity
            )
        if (
            replacement.state is not ExperimentState.QUEUED
            or stored_state != ExperimentState.VALIDATED.value
        ):
            return None
        snapshot = stored["configuration_snapshot_json"]
        base_hash = stored["material_base_configuration_hash"]
        if not isinstance(snapshot, str) or not isinstance(base_hash, str):
            return self._invariant(
                "queueing requires a frozen configuration snapshot", identity
            )
        if (
            experiment_configuration_hash(replacement.spec, base_hash)
            != replacement.spec.configuration_hash
        ):
            return self._invariant(
                "the frozen snapshot's base hash does not reproduce the spec's "
                "configuration hash",
                identity,
            )
        try:
            config = ApplicationConfig.model_validate_json(snapshot)
        except ValidationError:
            return self._invariant(
                "the frozen configuration snapshot is not a valid configuration",
                identity,
            )
        if retry_policy_from_config(config.scheduler.retry) != (
            replacement.spec.retry_policy
        ):
            return self._invariant(
                "the frozen configuration's retry policy differs from the spec's",
                identity,
            )
        return None

    def _invariant(self, message: str, identity: str) -> Failure:
        return self._scope.invariant(
            message,
            table="experiments",
            operation="compare_and_swap",
            identity=identity,
        )

    def _write(
        self,
        opened: Connection,
        stored: RowMapping,
        expected_revision: int,
        replacement: ExperimentRecord,
    ) -> Result[ExperimentRecord]:
        """Plan 4.3.1 step e: the conditional update, and the slot rewrite that a
        pre-``QUEUED`` spec change needs, inside one savepoint entered here."""
        identity = replacement.experiment_id
        rewrite = (
            str(stored["state"]) in _PRE_QUEUE_STATES
            and replacement.spec_hash != stored["spec_hash"]
        )
        table = "experiments"
        try:
            if rewrite:
                with opened.begin_nested():
                    affected = self._conditional_update(
                        opened, expected_revision, replacement
                    )
                    if affected == 1:
                        table = "engine_slots"
                        opened.execute(
                            delete(EngineSlotRow).where(
                                EngineSlotRow.experiment_id == identity
                            )
                        )
                        for slot in encode_engine_slots(replacement):
                            opened.execute(insert(EngineSlotRow).values(**slot))
            else:
                affected = self._conditional_update(
                    opened, expected_revision, replacement
                )
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table=table,
                operation="compare_and_swap",
                identity=identity,
            )
        if affected != 1:
            return self._scope.conflict(
                f"experiment {identity} was not updated at revision "
                f"{expected_revision}",
                table="experiments",
                operation="compare_and_swap",
                identity=identity,
            )
        return Success[ExperimentRecord](outcome="SUCCESS", value=replacement)

    def _conditional_update(
        self,
        opened: Connection,
        expected_revision: int,
        replacement: ExperimentRecord,
    ) -> int:
        """The record columns of plan 3.3.1 -- never the four snapshot columns,
        which only ``SqliteConfigurationSnapshotWriter.freeze`` writes."""
        outcome = opened.execute(
            update(ExperimentRow)
            .where(
                ExperimentRow.experiment_id == replacement.experiment_id,
                ExperimentRow.revision == expected_revision,
            )
            .values(**encode_experiment(replacement))
        )
        return outcome.rowcount


class SqliteEngineRunRepository:
    """``EngineRunRepository`` over one transaction's connection (plan 4.3)."""

    __slots__ = ("_scope",)

    def __init__(self, scope: TransactionScope) -> None:
        self._scope = scope

    def get(self, run_id: RunId) -> Result[EngineRunRecord]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        try:
            row = (
                opened.execute(
                    select(EngineRunRow).where(EngineRunRow.run_id == run_id)
                )
                .mappings()
                .first()
            )
        except DBAPIError as error:
            return self._scope.refused(
                error, table="engine_runs", operation="get", identity=run_id
            )
        if row is None:
            return self._scope.missing("run", run_id, table="engine_runs")
        return decode_engine_run(_values(row), clock=self._scope.clock)

    def add_attempt(self, record: EngineRunRecord) -> Result[None]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        encoded = self._encoded_run(record, operation="add_attempt")
        if isinstance(encoded, Failure):
            return encoded
        try:
            opened.execute(insert(EngineRunRow).values(**encoded))
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table="engine_runs",
                operation="add_attempt",
                identity=record.run_id,
            )
        return _none()

    def compare_and_swap(
        self,
        expected_revision: int,
        replacement: EngineRunRecord,
    ) -> Result[EngineRunRecord]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        identity = replacement.run_id
        try:
            stored = (
                opened.execute(
                    select(EngineRunRow.revision).where(EngineRunRow.run_id == identity)
                )
                .mappings()
                .first()
            )
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table="engine_runs",
                operation="compare_and_swap",
                identity=identity,
            )
        refusal = _revision_refusal(
            self._scope,
            stored,
            expected_revision=expected_revision,
            replacement_revision=replacement.revision,
            kind="run",
            table="engine_runs",
            identity=identity,
        )
        if refusal is not None:
            return refusal
        encoded = self._encoded_run(replacement, operation="compare_and_swap")
        if isinstance(encoded, Failure):
            return encoded
        try:
            outcome = opened.execute(
                update(EngineRunRow)
                .where(
                    EngineRunRow.run_id == identity,
                    EngineRunRow.revision == expected_revision,
                )
                .values(**encoded)
            )
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table="engine_runs",
                operation="compare_and_swap",
                identity=identity,
            )
        if outcome.rowcount != 1:
            return self._scope.conflict(
                f"run {identity} was not updated at revision {expected_revision}",
                table="engine_runs",
                operation="compare_and_swap",
                identity=identity,
            )
        return Success[EngineRunRecord](outcome="SUCCESS", value=replacement)

    def count_attempts(
        self,
        experiment_id: ExperimentId,
        logical_slot_id: LogicalSlotId,
    ) -> Result[int]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        try:
            counted = opened.execute(
                select(func.count())
                .select_from(EngineRunRow)
                .where(
                    EngineRunRow.experiment_id == experiment_id,
                    EngineRunRow.logical_slot_id == logical_slot_id,
                )
            ).scalar_one()
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table="engine_runs",
                operation="count_attempts",
                identity=logical_slot_id,
            )
        return Success[int](outcome="SUCCESS", value=int(counted))

    def latest_attempt(
        self,
        experiment_id: ExperimentId,
        logical_slot_id: LogicalSlotId,
    ) -> Result[EngineRunRecord | MISSING]:  # type: ignore[valid-type]
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        try:
            row = (
                opened.execute(
                    select(EngineRunRow)
                    .where(
                        EngineRunRow.experiment_id == experiment_id,
                        EngineRunRow.logical_slot_id == logical_slot_id,
                    )
                    .order_by(EngineRunRow.attempt_number.desc())
                    .limit(1)
                )
                .mappings()
                .first()
            )
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table="engine_runs",
                operation="latest_attempt",
                identity=logical_slot_id,
            )
        if row is None:
            return _absent()
        return decode_engine_run(_values(row), clock=self._scope.clock)

    def get_by_attempt_number(
        self,
        experiment_id: ExperimentId,
        logical_slot_id: LogicalSlotId,
        attempt_number: int,
    ) -> Result[EngineRunRecord | MISSING]:  # type: ignore[valid-type]
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        try:
            row = (
                opened.execute(
                    select(EngineRunRow).where(
                        EngineRunRow.experiment_id == experiment_id,
                        EngineRunRow.logical_slot_id == logical_slot_id,
                        EngineRunRow.attempt_number == attempt_number,
                    )
                )
                .mappings()
                .first()
            )
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table="engine_runs",
                operation="get_by_attempt_number",
                identity=logical_slot_id,
            )
        if row is None:
            return _absent()
        return decode_engine_run(_values(row), clock=self._scope.clock)

    def append_event(self, event: RunEvent) -> Result[RunEvent]:
        """Idempotent on an identical stored event; a conflict on either collision."""
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        identity = event.event_id
        try:
            stored = (
                opened.execute(
                    select(RunEventRow).where(
                        RunEventRow.invocation_id == event.invocation_id,
                        RunEventRow.sequence == event.sequence,
                    )
                )
                .mappings()
                .first()
            )
            if stored is not None:
                return self._replayed(stored, event)
            clashing = opened.execute(
                select(RunEventRow.sequence).where(RunEventRow.event_id == identity)
            ).scalar_one_or_none()
            if clashing is not None:
                return self._scope.conflict(
                    f"event {identity} is already stored at sequence {clashing} of "
                    f"invocation {event.invocation_id}",
                    table="run_events",
                    operation="append_event",
                    identity=identity,
                )
            opened.execute(insert(RunEventRow).values(**encode_run_event(event)))
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table="run_events",
                operation="append_event",
                identity=identity,
            )
        return Success[RunEvent](outcome="SUCCESS", value=event)

    def _replayed(self, stored: RowMapping, event: RunEvent) -> Result[RunEvent]:
        """The stored event when its content matches, else the key conflict."""
        decoded = decode_run_event(_values(stored), clock=self._scope.clock)
        if isinstance(decoded, Failure):
            return decoded
        if decoded.value.content_hash == event.content_hash:
            return decoded
        return self._scope.conflict(
            f"event {event.sequence} of invocation {event.invocation_id} is "
            "already stored with another content hash",
            table="run_events",
            operation="append_event",
            identity=event.event_id,
        )

    def list_events(self, invocation_id: InvocationId) -> Result[tuple[RunEvent, ...]]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        try:
            rows = (
                opened.execute(
                    select(RunEventRow)
                    .where(RunEventRow.invocation_id == invocation_id)
                    .order_by(RunEventRow.sequence)
                )
                .mappings()
                .all()
            )
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table="run_events",
                operation="list_events",
                identity=invocation_id,
            )
        decoded = [
            decode_run_event(_values(row), clock=self._scope.clock) for row in rows
        ]
        failures = [item for item in decoded if isinstance(item, Failure)]
        if failures:
            return failures[0]
        return Success[tuple[RunEvent, ...]](
            outcome="SUCCESS",
            value=tuple(item.value for item in decoded if isinstance(item, Success)),
        )

    def _encoded_run(
        self, record: EngineRunRecord, *, operation: str
    ) -> RowValues | Failure:
        """Rule N4, decided at this boundary and nowhere else.

        The condition is tested directly rather than caught, because
        ``encode_engine_run`` can raise ``ValueError`` for reasons that are not
        rule N4 -- a non-UTC instant, a refused serialization -- and reporting
        one of those as a finalization deadline would be a wrong diagnostic. The
        codec's contract is untouched; the message names the rule, never the
        exception text, a bound parameter or a record value; and no validated
        record reaches this branch, because the committed ``EngineRunRecord``
        validator forces the field absent.
        """
        if "finalization_deadline_utc" in record.model_dump(mode="json"):
            return self._scope.invariant(
                f"engine run {record.run_id} carries a finalization deadline, "
                "which rule N4 gives no column",
                table="engine_runs",
                operation=operation,
                identity=record.run_id,
            )
        return encode_engine_run(record)


class SqliteCommandInvocationRepository:
    """``CommandInvocationRepository`` over one transaction's connection (4.3)."""

    __slots__ = ("_scope",)

    def __init__(self, scope: TransactionScope) -> None:
        self._scope = scope

    def get(self, invocation_id: InvocationId) -> Result[CommandInvocationRecord]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        try:
            row = (
                opened.execute(
                    select(CommandInvocationRow).where(
                        CommandInvocationRow.invocation_id == invocation_id
                    )
                )
                .mappings()
                .first()
            )
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table="command_invocations",
                operation="get",
                identity=invocation_id,
            )
        if row is None:
            return self._scope.missing(
                "invocation", invocation_id, table="command_invocations"
            )
        return decode_command_invocation(_values(row), clock=self._scope.clock)

    def add(self, record: CommandInvocationRecord) -> Result[None]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        try:
            opened.execute(
                insert(CommandInvocationRow).values(**encode_command_invocation(record))
            )
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table="command_invocations",
                operation="add",
                identity=record.invocation_id,
            )
        return _none()

    def compare_and_swap(
        self,
        expected_revision: int,
        replacement: CommandInvocationRecord,
    ) -> Result[CommandInvocationRecord]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        identity = replacement.invocation_id
        try:
            stored = (
                opened.execute(
                    select(CommandInvocationRow.revision).where(
                        CommandInvocationRow.invocation_id == identity
                    )
                )
                .mappings()
                .first()
            )
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table="command_invocations",
                operation="compare_and_swap",
                identity=identity,
            )
        refusal = _revision_refusal(
            self._scope,
            stored,
            expected_revision=expected_revision,
            replacement_revision=replacement.revision,
            kind="invocation",
            table="command_invocations",
            identity=identity,
        )
        if refusal is not None:
            return refusal
        try:
            outcome = opened.execute(
                update(CommandInvocationRow)
                .where(
                    CommandInvocationRow.invocation_id == identity,
                    CommandInvocationRow.revision == expected_revision,
                )
                .values(**encode_command_invocation(replacement))
            )
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table="command_invocations",
                operation="compare_and_swap",
                identity=identity,
            )
        if outcome.rowcount != 1:
            return self._scope.conflict(
                f"invocation {identity} was not updated at revision "
                f"{expected_revision}",
                table="command_invocations",
                operation="compare_and_swap",
                identity=identity,
            )
        return Success[CommandInvocationRecord](outcome="SUCCESS", value=replacement)

    def list_for_run(
        self,
        run_id: RunId,
        command_kind: CommandKind,
    ) -> Result[tuple[CommandInvocationRecord, ...]]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        try:
            rows = (
                opened.execute(
                    select(CommandInvocationRow)
                    .where(
                        CommandInvocationRow.run_id == run_id,
                        CommandInvocationRow.command_kind == command_kind.value,
                    )
                    .order_by(
                        CommandInvocationRow.created_at_utc,
                        CommandInvocationRow.invocation_id,
                    )
                )
                .mappings()
                .all()
            )
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table="command_invocations",
                operation="list_for_run",
                identity=run_id,
            )
        decoded = [
            decode_command_invocation(_values(row), clock=self._scope.clock)
            for row in rows
        ]
        failures = [item for item in decoded if isinstance(item, Failure)]
        if failures:
            return failures[0]
        return Success[tuple[CommandInvocationRecord, ...]](
            outcome="SUCCESS",
            value=tuple(item.value for item in decoded if isinstance(item, Success)),
        )


class SqliteRetryDecisionRepository:
    """``RetryDecisionRepository`` over one transaction's connection (plan 4.3)."""

    __slots__ = ("_scope",)

    def __init__(self, scope: TransactionScope) -> None:
        self._scope = scope

    def get_by_predecessor(
        self,
        logical_slot_id: LogicalSlotId,
        predecessor_run_id: RunId,
    ) -> Result[RetryDecisionRecord]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        try:
            row = (
                opened.execute(
                    select(RetryDecisionRow).where(
                        RetryDecisionRow.logical_slot_id == logical_slot_id,
                        RetryDecisionRow.predecessor_run_id == predecessor_run_id,
                    )
                )
                .mappings()
                .first()
            )
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table="retry_decisions",
                operation="get_by_predecessor",
                identity=predecessor_run_id,
            )
        if row is None:
            return self._scope.invariant(
                f"retry decision for predecessor {predecessor_run_id} of slot "
                f"{logical_slot_id} does not exist",
                table="retry_decisions",
                operation="get_by_predecessor",
                identity=predecessor_run_id,
            )
        return decode_retry_decision(_values(row), clock=self._scope.clock)

    def insert_if_absent(
        self,
        record: RetryDecisionRecord,
    ) -> Result[RetryDecisionInsertOutcome]:
        """Insert when the key is absent from this transaction's view; otherwise
        return the stored winner. Neither row is ever modified."""
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        identity = record.predecessor_run_id
        try:
            row = (
                opened.execute(
                    select(RetryDecisionRow).where(
                        RetryDecisionRow.logical_slot_id == record.logical_slot_id,
                        RetryDecisionRow.predecessor_run_id == identity,
                    )
                )
                .mappings()
                .first()
            )
            if row is not None:
                stored = decode_retry_decision(_values(row), clock=self._scope.clock)
                if isinstance(stored, Failure):
                    return stored
                return Success[RetryDecisionInsertOutcome](
                    outcome="SUCCESS",
                    value=RetryDecisionInsertOutcome(
                        inserted=False, record=stored.value
                    ),
                )
            opened.execute(
                insert(RetryDecisionRow).values(**encode_retry_decision(record))
            )
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table="retry_decisions",
                operation="insert_if_absent",
                identity=identity,
            )
        return Success[RetryDecisionInsertOutcome](
            outcome="SUCCESS",
            value=RetryDecisionInsertOutcome(inserted=True, record=record),
        )
