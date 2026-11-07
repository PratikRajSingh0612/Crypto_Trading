"""SQLite test support for the Stage 9 artifact persistence suites (plan 7.1,
Task 5).

``ArtifactHarness(database)`` is ``PortHarness``-style over ``SqliteUnitOfWork``:
it wraps the Stage 8 ``SqliteHarness`` so every unit of work it hands out is
tracked and rolled back at ``close()``, seeds the RESULT pre-state the Stage 9
rows reference (``seed_result_prestate``: the experiment, the availability
observation, a ``RUNNING`` run with its deadline snapshotted through
``snapshot_deadline``, the ``EXITED`` run-command invocation and the owner rows
of plan 3.3), writes committed candidates, references, journal entries and
registration facts through the production repositories (``put_candidate``,
``put_ref``, ``put_journal``, ``put_sanitized_manifest``, ``put_run_manifest``,
``put_validation_result``, ``put_run_artifact``), reads committed state back
through a fresh read-only session decoded by the production codecs
(``committed_candidates``, ``committed_refs``, ``committed_manifests``,
``committed_journal``, ``committed_audit_events``, ``committed_run_manifests``,
``committed_run_artifacts``), and offers the raw-statement side the trigger
refusal tests need: ``plant_raw(table, row)`` inserts one row through the
independent stdlib connection after checking the table and columns against the
metadata, ``refuse(statement, parameters)`` executes one statement through the
engine and returns its classified refusal (failing the test when the statement
is accepted), ``execute(statement, parameters)`` commits a positive control, and
``install_refusing_trigger(table, when)`` / ``install_ignoring_update_trigger``
install test-only triggers from fixed DDL text plus one checked identity literal
(the Stage 8 ``sql_identity_literal`` rule: SQLite admits no bound parameter
inside ``CREATE TRIGGER``).

``token_scan(path_or_bytes, token)`` is the test-side exact-byte scan --
``bytes.find`` over the whole file, an implementation independent of the
production scanner it cross-checks -- and ``scan_tree_for_token(root, token)``
applies it to every file under ``root``.

Nothing here imports ``subprocess``, launches a child or reads a clock of its
own; every failure is stamped from the shared ``FixedClock(INSTANT)``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Final

import pytest
from pydantic.experimental.missing_sentinel import MISSING
from sqlalchemy import Select, select
from sqlalchemy.exc import DBAPIError

from crypto_lab.artifacts.journal import (
    FinalizationJournalEntry,
    FinalizationJournalState,
)
from crypto_lab.artifacts.manifest import ArtifactManifest
from crypto_lab.artifacts.models import ArtifactRef, CandidateArtifact
from crypto_lab.artifacts.ownership import ArtifactOwnerRef
from crypto_lab.audit.models import AuditEvent
from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.engine_run import EngineRunRecord
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
)
from crypto_lab.persistence.artifact_codecs import (
    decode_artifact_manifest,
    decode_artifact_ref,
    decode_audit_event,
    decode_candidate_artifact,
    decode_finalization_journal_entry,
    encode_artifact_ref,
    encode_finalization_journal_entry,
)
from crypto_lab.persistence.artifact_repositories import (
    RunArtifactLink,
    RunManifestFacts,
    SanitizedManifestFacts,
    ValidationResultFacts,
)
from crypto_lab.persistence.codecs import micros_to_utc_text
from crypto_lab.persistence.database import SqliteDatabase
from crypto_lab.persistence.registries import SqliteArtifactOwnerRegistry
from crypto_lab.persistence.schema import (
    STAGE8_TABLE_COUNT,
    TABLES_IN_DEPENDENCY_ORDER,
    ArtifactRefRow,
    AuditEventRow,
    CandidateArtifactRow,
    FinalizationJournalRow,
    RunArtifactRow,
    RunManifestRow,
    metadata,
)
from crypto_lab.persistence.unit_of_work import SqliteTransaction, SqliteUnitOfWork
from doubles.artifacts import (
    ADAPTER_OWNER,
    DEADLINE,
    RUN_OWNER,
    RUN_OWNER_WITHOUT_INVOCATION,
    SYSTEM_OWNER,
)
from doubles.experiments import (
    INSTANT,
    RUN_ID,
    FixedClock,
    sample_invocation,
    sample_run,
)
from persistence_support.harness import (
    SqliteHarness,
    commit,
    ok,
    put_invocation,
    put_lifecycle_parents,
    put_run,
    raw_connection,
    sql_identity_literal,
)

__all__ = [
    "STAGE9_TABLES",
    "TRIGGER_TABLES",
    "ArtifactHarness",
    "Refusal",
    "ResultPrestate",
    "scan_tree_for_token",
    "token_scan",
]

#: Plan 3.3: the eight Stage 9 tables, in dependency order.
STAGE9_TABLES: Final[tuple[str, ...]] = TABLES_IN_DEPENDENCY_ORDER[STAGE8_TABLE_COUNT:]
#: The tables a test-only trigger may be installed on: the Stage 9 tables and the
#: two Stage 8 tables Stage 9 triggers touch.
TRIGGER_TABLES: Final[frozenset[str]] = frozenset(
    {*STAGE9_TABLES, "engine_runs", "command_invocations"}
)
_TRIGGER_EVENTS: Final[frozenset[str]] = frozenset({"INSERT", "UPDATE"})
#: ``NEW.<column> = '<identity>'``: the only ``WHEN`` shape an installer admits.
_WHEN_GRAMMAR: Final = re.compile(r"^NEW\.([a-z_]+) = ('[a-z]+_[0-9a-f-]{36}')$")
#: The owner rows the default pre-state registers, in registration order.
DEFAULT_OWNERS: Final[tuple[ArtifactOwnerRef, ...]] = (
    RUN_OWNER,
    RUN_OWNER_WITHOUT_INVOCATION,
    SYSTEM_OWNER,
    ADAPTER_OWNER,
)


@dataclass(frozen=True, slots=True)
class Refusal:
    """One refused raw statement: the classified code and the driver's message."""

    code: str
    message: str


@dataclass(frozen=True, slots=True)
class ResultPrestate:
    """The rows ``seed_result_prestate`` committed, as the records it wrote; the
    owner hashes are parallel to the ``owners`` it registered."""

    run: EngineRunRecord
    invocation: CommandInvocationRecord
    owners: tuple[ArtifactOwnerRef, ...]
    owner_hashes: tuple[str, ...]


def _instant(value: object) -> datetime:
    return datetime.fromisoformat(micros_to_utc_text(int(str(value))))


def _optional_text(value: object) -> Any:
    return value if isinstance(value, str) else MISSING


def token_scan(path_or_bytes: Path | bytes, token: str | bytes) -> bool:
    """Does the file (or the bytes) contain ``token`` exactly? ``bytes.find`` over
    the whole content, independent of the production scanner."""
    if isinstance(path_or_bytes, Path):
        data = path_or_bytes.read_bytes()
    else:
        data = path_or_bytes
    needle = token.encode("utf-8") if isinstance(token, str) else token
    if not needle:
        raise ValueError("token must not be empty")
    return data.find(needle) != -1


def scan_tree_for_token(root: Path, token: str | bytes) -> tuple[Path, ...]:
    """Every regular file under ``root`` whose bytes contain ``token``, sorted."""
    return tuple(
        path
        for path in sorted(root.rglob("*"))
        if path.is_file() and token_scan(path, token)
    )


class ArtifactHarness:
    """``PortHarness``-style support over one migrated SQLite database (plan 7.1)."""

    __slots__ = ("_clock", "_inner", "database")

    def __init__(self, database: SqliteDatabase) -> None:
        self.database = database
        self._inner = SqliteHarness(database)
        self._clock = FixedClock(INSTANT)

    # -- Units of work -------------------------------------------------------

    def unit_of_work(self) -> SqliteUnitOfWork:
        """A fresh root over the same database, tracked for teardown."""
        return self._inner.unit_of_work()

    def begin(self) -> SqliteTransaction:
        """One open transaction over a fresh root."""
        return self.unit_of_work().begin()

    def lifecycle(self) -> SqliteHarness:
        """The Stage 8 harness underneath, for the lifecycle helpers."""
        return self._inner

    def open_transactions(self) -> tuple[SqliteTransaction, ...]:
        return self._inner.open_transactions()

    def close(self) -> None:
        """Roll back every surviving transaction, then dispose the engine."""
        self._inner.close()

    # -- Pre-state ------------------------------------------------------------

    def seed_result_prestate(
        self,
        *,
        run_state: EngineRunState = EngineRunState.RUNNING,
        deadline: datetime | None = DEADLINE,
        invocation_state: CommandInvocationState = CommandInvocationState.EXITED,
        owners: tuple[ArtifactOwnerRef, ...] = DEFAULT_OWNERS,
    ) -> ResultPrestate:
        """The parents every Stage 9 row references: the experiment and
        observation, the run in ``run_state`` (its deadline snapshotted when
        ``RUNNING`` and ``deadline`` is given), the run-command invocation in
        ``invocation_state`` and the owner rows."""
        put_lifecycle_parents(self._inner, observation=True)
        run = sample_run(run_state)
        put_run(self._inner, run)
        if deadline is not None and run_state is EngineRunState.RUNNING:
            transaction = self.begin()
            run = ok(
                transaction.result_leases.snapshot_deadline(
                    run.revision, RUN_ID, deadline
                )
            )
            commit(transaction)
        invocation = sample_invocation(invocation_state, kind=CommandKind.RUN)
        put_invocation(self._inner, invocation)
        hashes = tuple(self.put_owner(owner) for owner in owners)
        return ResultPrestate(
            run=run, invocation=invocation, owners=owners, owner_hashes=hashes
        )

    def put_owner(self, owner: ArtifactOwnerRef) -> str:
        """Register one owner row in its own committed transaction."""
        transaction = self.begin()
        owner_hash = ok(transaction.artifact_owners.register(owner))
        commit(transaction)
        return owner_hash

    # -- Committed writers ----------------------------------------------------

    def put_candidate(self, record: CandidateArtifact) -> None:
        transaction = self.begin()
        ok(transaction.candidate_artifacts.add(record))
        commit(transaction)

    def put_ref(self, ref: ArtifactRef, manifest: ArtifactManifest) -> None:
        """Plant one reference row raw (its candidate must be ``FINALIZING``)."""
        self.plant_raw("artifact_refs", encode_artifact_ref(ref, manifest))

    def put_journal(self, entry: FinalizationJournalEntry) -> None:
        """``prepare`` a ``PREPARED`` entry; plant any other state raw."""
        if entry.state is FinalizationJournalState.PREPARED:
            transaction = self.begin()
            ok(transaction.finalization_journal.prepare(entry))
            commit(transaction)
            return
        row = encode_finalization_journal_entry(entry)
        self.plant_raw("finalization_journal", row)

    def put_sanitized_manifest(self, facts: SanitizedManifestFacts) -> None:
        transaction = self.begin()
        ok(transaction.sanitized_manifests.add(facts))
        commit(transaction)

    def put_run_manifest(self, facts: RunManifestFacts) -> None:
        transaction = self.begin()
        ok(transaction.run_manifests.add(facts))
        commit(transaction)

    def put_validation_result(self, facts: ValidationResultFacts) -> None:
        transaction = self.begin()
        ok(transaction.validation_results.add(facts))
        commit(transaction)

    def put_run_artifact(self, link: RunArtifactLink) -> None:
        transaction = self.begin()
        ok(transaction.run_artifacts.link(link))
        commit(transaction)

    # -- Committed readers (a fresh read-only session each) -------------------

    def committed_candidates(self) -> tuple[CandidateArtifact, ...]:
        statement = select(CandidateArtifactRow).order_by(
            CandidateArtifactRow.candidate_artifact_id
        )
        return tuple(
            ok(decode_candidate_artifact(row, owner=owner, clock=self._clock))
            for row, owner in self._owned_rows(statement)
        )

    def committed_refs(self) -> tuple[ArtifactRef, ...]:
        statement = select(ArtifactRefRow).order_by(ArtifactRefRow.artifact_id)
        return tuple(
            ok(decode_artifact_ref(row, owner=owner, clock=self._clock))
            for row, owner in self._owned_rows(statement)
        )

    def committed_manifests(self) -> tuple[ArtifactManifest, ...]:
        statement = select(ArtifactRefRow).order_by(ArtifactRefRow.artifact_id)
        return tuple(
            ok(decode_artifact_manifest(row, clock=self._clock))
            for row in self._rows(statement)
        )

    def committed_journal(self) -> tuple[FinalizationJournalEntry, ...]:
        statement = select(FinalizationJournalRow).order_by(
            FinalizationJournalRow.finalization_id
        )
        return tuple(
            ok(decode_finalization_journal_entry(row, owner=owner, clock=self._clock))
            for row, owner in self._owned_rows(statement)
        )

    def committed_audit_events(self) -> tuple[AuditEvent, ...]:
        statement = select(AuditEventRow).order_by(AuditEventRow.audit_sequence)
        return tuple(
            ok(decode_audit_event(row, clock=self._clock))
            for row in self._rows(statement)
        )

    def committed_run_manifests(self) -> tuple[RunManifestFacts, ...]:
        statement = select(RunManifestRow).order_by(RunManifestRow.manifest_id)
        return tuple(
            RunManifestFacts(
                manifest_id=str(row["manifest_id"]),
                run_id=str(row["run_id"]),
                experiment_id=str(row["experiment_id"]),
                run_invocation_id=str(row["run_invocation_id"]),
                attempt_token_hash=str(row["attempt_token_hash"]),
                sanitized_adapter_result_manifest_hash=str(
                    row["sanitized_adapter_result_manifest_hash"]
                ),
                semantic_status=str(row["semantic_status"]),
                process_exit_category=str(row["process_exit_category"]),
                manifest_json=str(row["manifest_json"]),
                run_manifest_hash=str(row["run_manifest_hash"]),
                registered_at_utc=_instant(row["registered_at_utc"]),
            )
            for row in self._rows(statement)
        )

    def committed_run_artifacts(self) -> tuple[RunArtifactLink, ...]:
        statement = select(RunArtifactRow).order_by(
            RunArtifactRow.run_id,
            RunArtifactRow.link_role,
            RunArtifactRow.artifact_id,
        )
        return tuple(
            RunArtifactLink(
                run_id=str(row["run_id"]),
                artifact_id=str(row["artifact_id"]),
                link_role=str(row["link_role"]),
                experiment_id=str(row["experiment_id"]),
                run_manifest_id=_optional_text(row["run_manifest_id"]),
            )
            for row in self._rows(statement)
        )

    def count(self, table: str) -> int:
        """``SELECT count(*)`` of one table through the stdlib connection."""
        _require_table(table)
        connection = raw_connection(self.database.path)
        try:
            statement = f"SELECT count(*) FROM {table}"  # noqa: S608
            (total,) = connection.execute(statement).fetchone()
            return int(total)
        finally:
            connection.close()

    # -- Raw statements -------------------------------------------------------

    def plant_raw(self, table: str, row: Mapping[str, object]) -> None:
        """Insert one row through the independent stdlib connection.

        ``table`` must be a metadata table and every key a column of it; the
        statement text is composed from those checked names alone and every
        value is a bound parameter.
        """
        statement, parameters = _insert_statement(table, row)
        connection = raw_connection(self.database.path)
        try:
            connection.execute(statement, parameters)
        finally:
            connection.close()

    def refuse_insert(self, table: str, row: Mapping[str, object]) -> Refusal:
        """``refuse`` over the insert of ``row``, composed as ``plant_raw`` does."""
        statement, parameters = _insert_statement(table, row)
        return self.refuse(statement, parameters)

    def refuse(self, statement: str, parameters: tuple[object, ...] = ()) -> Refusal:
        """Execute one statement through the engine and return its classified
        refusal; a statement the database accepts fails the test."""
        with self.database.connection() as connection:
            try:
                connection.exec_driver_sql(statement, parameters)
            except DBAPIError as error:
                connection.rollback()
                return Refusal(
                    code=SqliteDatabase.classify(error), message=str(error.orig)
                )
            connection.rollback()
        pytest.fail(f"the database accepted a statement it must refuse: {statement}")

    def execute(self, statement: str, parameters: tuple[object, ...] = ()) -> None:
        """Execute and commit one positive-control statement through the engine."""
        with self.database.connection() as connection:
            connection.exec_driver_sql(statement, parameters)
            connection.commit()

    def install_refusing_trigger(
        self, table: str, when: str, *, event: str = "INSERT"
    ) -> None:
        """A test-only ``BEFORE <event>`` trigger refusing the row ``when`` names.

        ``when`` is ``NEW.<column> = '<identity>'`` over one fixture identity
        (the ``sql_identity_literal`` grammar); nothing else is admitted into the
        DDL text.
        """
        verb = _require_event(event).lower()
        _execute_ddl(
            self.database,
            f"CREATE TRIGGER test_refuse_{table}_{verb} "
            f"BEFORE {_require_event(event)} ON {_require_trigger_table(table)} "
            f"WHEN {_require_when(when)} "
            f"BEGIN SELECT RAISE(ABORT, 'test: {table} {verb} refused'); END",
        )

    def install_ignoring_update_trigger(self, table: str, when: str) -> None:
        """A test-only ``BEFORE UPDATE`` trigger skipping the row ``when`` names
        (``RAISE(IGNORE)``), the one way a conditional ``UPDATE`` reports zero rows
        from inside one connection (Stage 8 plan 4.3.1 step f)."""
        _execute_ddl(
            self.database,
            f"CREATE TRIGGER test_ignore_{table}_update "
            f"BEFORE UPDATE ON {_require_trigger_table(table)} "
            f"WHEN {_require_when(when)} BEGIN SELECT RAISE(IGNORE); END",
        )

    # -- Internals -------------------------------------------------------------

    def _rows(self, statement: Select[Any]) -> tuple[dict[str, object], ...]:
        with self.database.read_only() as connection:
            return tuple(
                {str(key): value for key, value in row.items()}
                for row in connection.execute(statement).mappings().all()
            )

    def _owned_rows(
        self, statement: Select[Any]
    ) -> tuple[tuple[dict[str, object], ArtifactOwnerRef], ...]:
        with self.database.read_only() as connection:
            registry = SqliteArtifactOwnerRegistry(connection, clock=self._clock)
            rows = connection.execute(statement).mappings().all()
            return tuple(
                (
                    {str(key): value for key, value in row.items()},
                    ok(registry.get(str(row["owner_hash"]))),
                )
                for row in rows
            )


def _require_table(table: str) -> str:
    if table not in TABLES_IN_DEPENDENCY_ORDER:
        raise ValueError(f"{table} is not a metadata table")
    return table


def _insert_statement(
    table: str, row: Mapping[str, object]
) -> tuple[str, tuple[object, ...]]:
    """The parameterized insert of ``row`` into the checked ``table``: the text
    is composed from metadata column names alone, every value is bound."""
    _require_table(table)
    columns = tuple(row)
    unknown = set(columns) - set(metadata.tables[table].columns.keys())
    if unknown:
        raise ValueError(f"{table} has no column {sorted(unknown)}")
    names = ", ".join(columns)
    placeholders = ", ".join("?" for _ in columns)
    statement = f"INSERT INTO {table} ({names}) VALUES ({placeholders})"  # noqa: S608
    return statement, tuple(row[column] for column in columns)


def _require_trigger_table(table: str) -> str:
    if table not in TRIGGER_TABLES:
        raise ValueError(f"{table} admits no test-only trigger")
    return table


def _require_event(event: str) -> str:
    if event not in _TRIGGER_EVENTS:
        raise ValueError(f"{event} is not a test-only trigger event")
    return event


def _require_when(when: str) -> str:
    matched = _WHEN_GRAMMAR.match(when)
    if matched is None:
        raise ValueError("when must be NEW.<column> = '<fixture identity>'")
    literal = matched.group(2)
    if sql_identity_literal(literal[1:-1]) != literal:
        raise ValueError("when must name a fixture identity")
    return when


def _execute_ddl(database: SqliteDatabase, statement: str) -> None:
    connection = raw_connection(database.path)
    try:
        connection.execute(statement)
    finally:
        connection.close()
