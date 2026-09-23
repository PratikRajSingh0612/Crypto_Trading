"""The SQLite database boundary: engine, PRAGMA policy, sessions, failure mapping.

Plan Task 1 (sections 6.1, 6.2 steps 1-5 and 6.5; specification 23, 27.2 and
29.1). ``SqliteDatabase`` owns every DBAPI-level fact of Stage 8: one SQLAlchemy
engine over a bounded queue pool whose connect hook applies ``foreign_keys=ON``,
``synchronous=FULL`` and the configured ``busy_timeout`` on every physical
connection, switches the file to WAL once an open has verified its identity, and
reads every setting back -- a mismatch closes the connection and fails the caller
with ``PERSISTENCE.STORAGE_UNAVAILABLE``. The DBAPI's implicit transactions are
disabled (``isolation_level=None``) and the engine's ``begin`` hook issues the one
explicit deferred ``BEGIN`` per transaction (the plan 2.8 recipe), so reads
establish one WAL snapshot and the first write takes the writer lock. ``open``
performs the plan 6.2 steps 1-5 -- an absolute path whose parent exists, identity
through ``application_id``, WAL, read-back, ``quick_check`` -- and then applies
the caller's ``revision_policy`` as step 6; Task 2's entry points supply the
policy. Every refusal is a read-only outcome for an existing file: nothing
creates a directory, rebuilds or deletes a file. An absent path whose parent
exists is created by SQLite on the first connect and switched to WAL once the
identity check passes, before the policy runs (the unmigrated ``bare_database``
of the Task 1 probes), so Task 2's ``open_database`` decides itself, before
calling ``open``, that an absent path is a refusal rather than a creation.
``classify`` is the single authority of plan 6.5,
reading the extended result code from the wrapped DBAPI exception's ``orig``;
the SQLite result codes are local ``Final`` integers because no persistence
module imports ``sqlite3``.

Nothing here reads configuration, the environment, the current directory or a
home directory: the caller composes the path from ``paths.runtime_root`` and
``database.filename`` through ``database_path``. The engine is bound only inside
``open``, never at import, so the package stays import-side-effect free.

Task-local decisions, declared here and asserted by the Task 1 tests:

- ``open`` exposes the pool parameters as keyword-only arguments defaulting to
  the plan 6.1 values (size 8, overflow 2, checkout timeout 5 s) so the
  pool-of-one probe is constructible; production callers never pass them.
- ``classify`` also accepts the pool's own checkout-timeout error, which is not
  a DBAPI error, and maps it to ``PERSISTENCE.STORAGE_UNAVAILABLE``; Task 4's
  ``begin()`` keeps its own branch for it.
- ``SQLITE_CANTOPEN`` classifies as ``PERSISTENCE.WRITE_FAILED``, its
  statement-time meaning; ``open`` collapses every non-conflict refusal to
  ``PERSISTENCE.STORAGE_UNAVAILABLE`` because an open performs no write, while
  a busy lock at open stays the retriable ``PERSISTENCE.CONCURRENCY_CONFLICT``.
- ``Result[SqliteDatabase]`` is constructed as
  ``Success[InstanceOf[SqliteDatabase]]``: ``CanonicalModel`` admits no
  arbitrary type, and ``pydantic.InstanceOf`` is the one route that needs
  neither a configuration change nor the ``pydantic_core`` import root; the
  static return type stays ``Result[SqliteDatabase]``.
- The journal-mode switch runs in the connect hook, gated by the identity check
  of the open, so it executes outside any transaction and its read-back happens
  on every physical connect; on a file already in WAL mode it is a no-op.

Task 3 adds ``ConsistencyReport`` and ``SqliteDatabase.consistency_report()``
(plan 4.6): the eight read-only counts over the Task 2 schema -- dangling
diagnostic references, slot identity mismatches, spec projection mismatches,
scaffolding queued without a snapshot, causal-edge mismatches, unresolved causal
references, registry projection mismatches and ``PRAGMA foreign_key_check`` rows
-- each computed by its own SQL statement inside one read-only session. The
module still imports no new root: the queries are ``text()`` statements and the
report is a frozen dataclass.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from pydantic import InstanceOf
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import URL, Connection, Engine
from sqlalchemy.engine.interfaces import DBAPIConnection
from sqlalchemy.exc import DBAPIError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError
from sqlalchemy.pool import ConnectionPoolEntry, QueuePool

from crypto_lab.configuration.models import DatabaseConfig
from crypto_lab.domain.diagnostics import DiagnosticDetailValue, ErrorCode
from crypto_lab.domain.lifecycle import ExperimentState
from crypto_lab.domain.ports import Clock
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.persistence.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
    STORAGE_UNAVAILABLE,
    WRITE_FAILED,
    persistence_failure,
)

__all__ = [
    "APPLICATION_ID",
    "POOL_MAX_OVERFLOW",
    "POOL_SIZE",
    "POOL_TIMEOUT_SECONDS",
    "ConsistencyReport",
    "RevisionPolicy",
    "SqliteDatabase",
    "database_path",
]

#: Plan 6.1: ``CLB1`` as a 32-bit header value, set by Task 2's
#: ``open_for_migration`` when the database is empty and read back on every open.
APPLICATION_ID: Final[int] = 0x434C4231
#: Plan 6.1: the bounded queue pool (proposed values, confirmed by the probes).
POOL_SIZE: Final[int] = 8
POOL_MAX_OVERFLOW: Final[int] = 2
POOL_TIMEOUT_SECONDS: Final[float] = 5.0
#: ``DatabaseConfig.busy_timeout_ms`` bounds, re-checked here because the PRAGMA
#: text is composed from the integer.
_MIN_BUSY_TIMEOUT_MS: Final[int] = 100
_MAX_BUSY_TIMEOUT_MS: Final[int] = 60_000
#: The read-back values of the plan 6.1 settings.
_EXPECTED_JOURNAL_MODE: Final[str] = "wal"
_EXPECTED_FOREIGN_KEYS: Final[int] = 1
_EXPECTED_SYNCHRONOUS: Final[int] = 2
#: Plan 6.2 step 3: user tables are every table whose name is not SQLite's own.
_USER_TABLE_COUNT: Final[str] = (
    "SELECT count(*) FROM sqlite_master "
    "WHERE type = 'table' AND substr(name, 1, 7) <> 'sqlite_'"
)
_MAX_QUICK_CHECK_DETAIL: Final[int] = 512

# SQLite result codes as local integers (no persistence module imports
# ``sqlite3``): the primary code is the low byte of an extended code.
_SQLITE_BUSY: Final[int] = 5
_SQLITE_LOCKED: Final[int] = 6
_SQLITE_NOMEM: Final[int] = 7
_SQLITE_READONLY: Final[int] = 8
_SQLITE_IOERR: Final[int] = 10
_SQLITE_FULL: Final[int] = 13
_SQLITE_CANTOPEN: Final[int] = 14
_SQLITE_CONSTRAINT_CHECK: Final[int] = 275
_SQLITE_CONSTRAINT_FOREIGNKEY: Final[int] = 787
_SQLITE_CONSTRAINT_NOTNULL: Final[int] = 1299
_SQLITE_CONSTRAINT_PRIMARYKEY: Final[int] = 1555
_SQLITE_CONSTRAINT_TRIGGER: Final[int] = 1811
_SQLITE_CONSTRAINT_UNIQUE: Final[int] = 2067
#: Plan 6.5 row 1: ``SQLITE_BUSY`` with every ``SQLITE_BUSY_*`` (the snapshot
#: refusal included) and ``SQLITE_LOCKED``; row 2: the two identity collisions.
_CONFLICT_PRIMARY_CODES: Final[frozenset[int]] = frozenset(
    {_SQLITE_BUSY, _SQLITE_LOCKED}
)
_CONFLICT_EXTENDED_CODES: Final[frozenset[int]] = frozenset(
    {_SQLITE_CONSTRAINT_UNIQUE, _SQLITE_CONSTRAINT_PRIMARYKEY}
)
#: Plan 6.5 row 4: an impossible aggregate state written by the caller.
_INVARIANT_EXTENDED_CODES: Final[frozenset[int]] = frozenset(
    {
        _SQLITE_CONSTRAINT_FOREIGNKEY,
        _SQLITE_CONSTRAINT_CHECK,
        _SQLITE_CONSTRAINT_TRIGGER,
        _SQLITE_CONSTRAINT_NOTNULL,
    }
)
#: Plan 6.5 row 5 and reading 3: the I/O class of a write. ``SQLITE_CORRUPT``,
#: ``SQLITE_NOTADB``, ``SQLITE_PERM``, ``SQLITE_AUTH`` and every unlisted code
#: fall through to storage unavailability.
_WRITE_FAILED_PRIMARY_CODES: Final[frozenset[int]] = frozenset(
    {_SQLITE_FULL, _SQLITE_IOERR, _SQLITE_READONLY, _SQLITE_NOMEM, _SQLITE_CANTOPEN}
)

type RevisionPolicy = Callable[[Connection], Result[None]]


# --------------------------------------------------------------------------
# Plan 4.6: the eight read-only consistency counts (Task 3)
# --------------------------------------------------------------------------


def _quoted_states(states: frozenset[ExperimentState]) -> str:
    return ", ".join(f"'{state.value}'" for state in ExperimentState if state in states)


def _instant_text_sql(column: str) -> str:
    """Render an E5 microsecond column back to canonical UTC text inside SQL.

    Floor seconds through ``strftime(..., 'unixepoch')`` and a six-digit fraction
    only when it is non-zero -- exactly ``format_utc``'s 20- or 27-character form
    -- so a typed instant projection compares with its ``record`` snapshot text
    to the microsecond (rule N6). ``%`` keeps the dividend's sign in SQLite, so
    the fraction is normalized into ``0..999999`` before the seconds are derived.
    """
    fraction = f"((({column} % 1000000) + 1000000) % 1000000)"
    seconds = f"(({column} - {fraction}) / 1000000)"
    return (
        f"(strftime('%Y-%m-%dT%H:%M:%S', {seconds}, 'unixepoch') || "
        f"CASE WHEN {fraction} = 0 THEN 'Z' ELSE printf('.%06dZ', {fraction}) END)"
    )


def _projection_mismatch_sql(
    table: str,
    text_projections: tuple[tuple[str, str], ...],
    instant_projections: tuple[str, ...],
) -> str:
    """Rows of ``table`` whose typed columns differ from their ``record`` snapshot."""
    terms = [
        f"{column} IS NOT json_extract(record, '{path}')"
        for column, path in text_projections
    ]
    terms.extend(
        f"{_instant_text_sql(column)} IS NOT json_extract(record, '$.{column}')"
        for column in instant_projections
    )
    return f"SELECT count(*) FROM {table} WHERE {' OR '.join(terms)}"  # noqa: S608


#: One spec slot and one ``engine_slots`` row agree on every projected column.
_SLOT_AGREES: Final = (
    "s.logical_slot_id = json_extract(j.value, '$.logical_slot_id') "
    "AND s.slot_ordinal = json_extract(j.value, '$.slot_ordinal') "
    "AND s.adapter_name = json_extract(j.value, '$.adapter.adapter_name') "
    "AND s.adapter_version = json_extract(j.value, '$.adapter.adapter_version') "
    "AND s.engine_name = json_extract(j.value, '$.engine.engine_name') "
    "AND s.engine_version = json_extract(j.value, '$.engine.engine_version')"
)
_DANGLING_DIAGNOSTIC_REFERENCES_SQL: Final = (
    "SELECT count(*) FROM ("
    "SELECT primary_terminal_diagnostic_id AS diagnostic_id FROM engine_runs "
    "WHERE primary_terminal_diagnostic_id IS NOT NULL "
    "UNION ALL SELECT primary_diagnostic_id FROM command_invocations "
    "WHERE primary_diagnostic_id IS NOT NULL "
    "UNION ALL SELECT j.value "
    "FROM command_invocations i, json_each(i.diagnostic_ids) j "
    "UNION ALL SELECT primary_terminal_diagnostic_id FROM retry_decisions"
    ") refs WHERE refs.diagnostic_id NOT IN (SELECT diagnostic_id FROM diagnostics)"
)
_SLOT_IDENTITY_MISMATCHES_SQL: Final = (
    "SELECT count(*) FROM engine_runs r JOIN engine_slots s "
    "ON s.experiment_id = r.experiment_id AND s.logical_slot_id = r.logical_slot_id "
    "WHERE r.adapter_name <> s.adapter_name OR r.adapter_version <> s.adapter_version "
    "OR r.engine_name <> s.engine_name OR r.engine_version <> s.engine_version"
)
# Composed from the module constant ``_SLOT_AGREES`` alone; no caller value enters.
_SPEC_PROJECTION_MISMATCHES_SQL: Final = (
    "SELECT count(*) FROM experiments e WHERE "  # noqa: S608
    "e.strategy_version_hash IS NOT json_extract(e.spec, '$.strategy_version_hash') "
    "OR e.dataset_version_hash IS NOT json_extract(e.spec, '$.dataset_version_hash') "
    "OR EXISTS (SELECT 1 FROM json_each(e.spec, '$.selected_engine_slots') j "
    "WHERE NOT EXISTS (SELECT 1 FROM engine_slots s "
    f"WHERE s.experiment_id = e.experiment_id AND {_SLOT_AGREES})) "
    "OR EXISTS (SELECT 1 FROM engine_slots s WHERE s.experiment_id = e.experiment_id "
    "AND NOT EXISTS (SELECT 1 FROM json_each(e.spec, '$.selected_engine_slots') j "
    f"WHERE {_SLOT_AGREES}))"
)
#: Reading 22: ``CANCELLED`` from ``DRAFT``/``VALIDATED`` lawfully has no snapshot.
#: The state list is generated from ``ExperimentState``; no caller value enters.
_QUEUED_WITHOUT_SNAPSHOT_SQL: Final = (
    "SELECT count(*) FROM experiments WHERE state NOT IN ("  # noqa: S608
    + _quoted_states(
        frozenset(
            {
                ExperimentState.DRAFT,
                ExperimentState.VALIDATED,
                ExperimentState.CANCELLED,
            }
        )
    )
    + ") AND configuration_snapshot_json IS NULL"
)
_CAUSAL_EDGE_MISMATCHES_SQL: Final = (
    "SELECT ("
    "SELECT count(*) FROM diagnostics d, json_each(d.causal_diagnostic_ids) j "
    "WHERE j.value IN (SELECT diagnostic_id FROM diagnostics) "
    "AND NOT EXISTS (SELECT 1 FROM diagnostic_causes c "
    "WHERE c.diagnostic_id = d.diagnostic_id AND c.causal_diagnostic_id = j.value)"
    ") + ("
    "SELECT count(*) FROM diagnostic_causes c WHERE NOT EXISTS ("
    "SELECT 1 FROM diagnostics d, json_each(d.causal_diagnostic_ids) j "
    "WHERE d.diagnostic_id = c.diagnostic_id AND j.value = c.causal_diagnostic_id)"
    ")"
)
_UNRESOLVED_CAUSAL_REFERENCES_SQL: Final = (
    "SELECT count(*) FROM diagnostics d, json_each(d.causal_diagnostic_ids) j "
    "WHERE j.value NOT IN (SELECT diagnostic_id FROM diagnostics)"
)
_REGISTRY_PROJECTION_SQL: Final[tuple[str, ...]] = (
    _projection_mismatch_sql(
        "strategy_versions",
        (
            ("content_hash", "$.content_hash"),
            ("strategy_version_id", "$.strategy_version_id"),
            ("strategy_id", "$.strategy_id"),
            ("schema_version", "$.schema_version"),
            ("hashing_profile_version", "$.hashing_profile_version"),
        ),
        ("created_at_utc",),
    ),
    _projection_mismatch_sql(
        "datasets",
        (
            ("dataset_id", "$.dataset_id"),
            ("content_hash", "$.content_hash"),
            ("schema_version", "$.schema_version"),
            ("venue", "$.venue"),
            ("instrument_canonical_id", "$.instrument.canonical_id"),
            ("data_type", "$.data_type"),
            ("timeframe", "$.timeframe"),
            ("validation_status", "$.validation_status"),
        ),
        ("start_utc", "end_utc", "created_at_utc"),
    ),
    _projection_mismatch_sql(
        "dataset_partitions",
        (
            ("partition_id", "$.partition_id"),
            ("dataset_id", "$.dataset_id"),
            ("ordinal", "$.ordinal"),
            ("content_hash", "$.content_hash"),
            ("raw_checksum", "$.raw_checksum"),
            ("normalized_checksum", "$.normalized_checksum"),
            ("relative_path", "$.relative_path"),
            ("row_count", "$.row_count"),
        ),
        ("start_utc", "end_utc"),
    ),
)
_FOREIGN_KEY_CHECK_SQL: Final = "PRAGMA foreign_key_check"


@dataclass(frozen=True, slots=True)
class ConsistencyReport:
    """Plan 4.6: the eight read-only counts, every one computed by its own query.

    The tests and the Stage 10 startup verification assert them zero;
    ``queued_without_snapshot`` alone is non-zero for rows test scaffolding
    inserts directly at or after ``QUEUED`` (reading 22).
    """

    dangling_diagnostic_references: int
    slot_identity_mismatches: int
    spec_projection_mismatches: int
    queued_without_snapshot: int
    causal_edge_mismatches: int
    unresolved_causal_references: int
    registry_projection_mismatches: int
    foreign_key_violations: int


class _ConnectionPolicyMismatch(Exception):
    """A setting read back with a value other than the one applied (plan 6.1)."""

    def __init__(self, setting: str, expected: int | str, actual: object) -> None:
        super().__init__(
            f"PRAGMA {setting} read back {actual!r} instead of {expected!r}"
        )
        self.setting = setting
        self.expected = expected
        self.actual = actual

    def details(self) -> dict[str, DiagnosticDetailValue]:
        actual: DiagnosticDetailValue = (
            self.actual
            if isinstance(self.actual, int | str) and not isinstance(self.actual, bool)
            else repr(self.actual)
        )
        return {
            "operation": "connect",
            "setting": self.setting,
            "expected": self.expected,
            "actual": actual,
        }


class _ConnectionPolicy:
    """The connect hook: apply the per-connection settings and read them back.

    ``journal_mode_authorized`` is switched on by ``SqliteDatabase.open`` after
    the identity check, so a foreign or corrupt file is never switched to WAL;
    from then on every physical connect applies the idempotent switch outside
    any transaction and verifies ``journal_mode`` with the other settings.
    """

    __slots__ = ("busy_timeout_ms", "journal_mode_authorized")

    def __init__(self, busy_timeout_ms: int) -> None:
        self.busy_timeout_ms = busy_timeout_ms
        self.journal_mode_authorized = False

    def expected_settings(self) -> dict[str, int | str]:
        expected: dict[str, int | str] = {
            "foreign_keys": _EXPECTED_FOREIGN_KEYS,
            "synchronous": _EXPECTED_SYNCHRONOUS,
            "busy_timeout": self.busy_timeout_ms,
        }
        if self.journal_mode_authorized:
            expected["journal_mode"] = _EXPECTED_JOURNAL_MODE
        return expected

    def on_connect(
        self,
        dbapi_connection: DBAPIConnection,
        connection_record: ConnectionPoolEntry,
    ) -> None:
        del connection_record
        try:
            cursor = dbapi_connection.cursor()
            try:
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA synchronous=FULL")
                cursor.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
                if self.journal_mode_authorized:
                    cursor.execute("PRAGMA journal_mode=WAL")
                for setting, expected in self.expected_settings().items():
                    cursor.execute(f"PRAGMA {setting}")
                    actual: object = cursor.fetchall()[0][0]
                    if actual != expected:
                        raise _ConnectionPolicyMismatch(setting, expected, actual)
            finally:
                cursor.close()
        except BaseException:
            dbapi_connection.close()
            raise


def _emit_begin(connection: Connection) -> None:
    """The engine's ``begin`` hook: one explicit deferred ``BEGIN`` (plan 2.8)."""
    connection.exec_driver_sql("BEGIN")


def _scalar_int(connection: Connection, statement: str) -> int:
    return int(connection.execute(text(statement)).scalar_one())


def _sqlite_result_code(error: DBAPIError) -> int | None:
    extended = getattr(error.orig, "sqlite_errorcode", None)
    if isinstance(extended, int) and not isinstance(extended, bool):
        return extended
    return None


def _result_code_details(error: DBAPIError) -> dict[str, DiagnosticDetailValue]:
    candidates = {
        "sqlite_errorcode": getattr(error.orig, "sqlite_errorcode", None),
        "sqlite_errorname": getattr(error.orig, "sqlite_errorname", None),
    }
    details: dict[str, DiagnosticDetailValue] = {
        key: value for key, value in candidates.items() if isinstance(value, int | str)
    }
    return details


def _path_refusal(path: Path) -> str | None:
    """Plan 6.2 step 1: the reasons an open refuses before touching the file."""
    if not path.is_absolute():
        return "database path must be absolute"
    if not path.parent.is_dir():
        return "database directory does not exist"
    if path.is_dir():
        return "database path is a directory"
    return None


def database_path(runtime_root: Path, config: DatabaseConfig) -> Path:
    """The pure join of the runtime root and the configured filename (plan 6.2)."""
    if not runtime_root.is_absolute():
        raise ValueError("runtime root must be an absolute path")
    return runtime_root / config.filename


class SqliteDatabase:
    """One SQLite file behind one engine (plan 6.1 and 6.2)."""

    __slots__ = ("_clock", "_engine", "_path", "_policy")

    def __init__(
        self,
        *,
        engine: Engine,
        path: Path,
        clock: Clock,
        policy: _ConnectionPolicy,
    ) -> None:
        self._engine = engine
        self._path = path
        self._clock = clock
        self._policy = policy

    @classmethod
    def open(
        cls,
        path: Path,
        *,
        busy_timeout_ms: int,
        clock: Clock,
        revision_policy: RevisionPolicy,
        pool_size: int = POOL_SIZE,
        max_overflow: int = POOL_MAX_OVERFLOW,
        pool_timeout_seconds: float = POOL_TIMEOUT_SECONDS,
    ) -> Result[SqliteDatabase]:
        """Plan 6.2 steps 1-5, then ``revision_policy`` as step 6.

        A refusal returns the ``Failure`` and disposes the engine; an existing
        file is never rebuilt or deleted and no directory is created. An absent
        path whose parent exists is created by SQLite before the policy runs, so
        the caller refuses such a path first when a creation is not wanted. A
        policy that raises is a programmer defect: the exception propagates after
        the engine is disposed. ``busy_timeout_ms`` outside the
        ``DatabaseConfig`` range is a programmer defect too (``ValueError``).
        """
        if not _MIN_BUSY_TIMEOUT_MS <= busy_timeout_ms <= _MAX_BUSY_TIMEOUT_MS:
            raise ValueError("busy_timeout_ms must be within 100..60000")
        path_refusal = _path_refusal(path)
        if path_refusal is not None:
            return persistence_failure(
                STORAGE_UNAVAILABLE,
                message=path_refusal,
                clock=clock,
                details={"operation": "open"},
            )
        policy = _ConnectionPolicy(busy_timeout_ms)
        engine = create_engine(
            URL.create("sqlite", database=str(path)),
            poolclass=QueuePool,
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_timeout=pool_timeout_seconds,
            connect_args={
                "check_same_thread": False,
                "timeout": busy_timeout_ms / 1000,
                "isolation_level": None,
            },
        )
        event.listen(engine, "connect", policy.on_connect)
        event.listen(engine, "begin", _emit_begin)
        database = cls(engine=engine, path=path, clock=clock, policy=policy)
        try:
            refusal = database._verify_identity()
            if refusal is None:
                policy.journal_mode_authorized = True
                refusal = database._verify_storage()
            if refusal is None:
                refusal = database._apply_revision_policy(revision_policy)
        except _ConnectionPolicyMismatch as mismatch:
            refusal = database.failure(
                STORAGE_UNAVAILABLE, message=str(mismatch), details=mismatch.details()
            )
        except DBAPIError as error:
            refusal = database._open_failure(error)
        except BaseException:
            database.close()
            raise
        if refusal is not None:
            database.close()
            return refusal
        return Success[InstanceOf[SqliteDatabase]](outcome="SUCCESS", value=database)

    @property
    def path(self) -> Path:
        """The absolute database path the caller composed."""
        return self._path

    @property
    def busy_timeout_ms(self) -> int:
        """The configured busy timeout applied on every connection."""
        return self._policy.busy_timeout_ms

    @contextmanager
    def connection(self) -> Iterator[Connection]:
        """A pooled connection with the PRAGMAs verified: the unit of work's checkout.

        The first statement autobegins the deferred transaction; leaving the
        block without ``commit()`` rolls it back and returns the connection.
        Checkout failures propagate: a DBAPI error or the pool's timeout error,
        both of which ``classify`` maps.
        """
        with self._engine.connect() as connection:
            yield connection

    @contextmanager
    def read_only(self) -> Iterator[Connection]:
        """A read-only session (plan 4.2): a deferred ``BEGIN``, reads, ``ROLLBACK``.

        It never takes the writer lock and never blocks a writer; the session is
        structural, so the caller issues reads only.
        """
        with self._engine.connect() as connection:
            connection.begin()
            try:
                yield connection
            finally:
                connection.rollback()

    @staticmethod
    def classify(error: DBAPIError | PoolTimeoutError) -> ErrorCode:
        """Plan 6.5: the stable failure mapping over the extended result code."""
        if not isinstance(error, DBAPIError):
            return STORAGE_UNAVAILABLE
        extended = _sqlite_result_code(error)
        if extended is None:
            return STORAGE_UNAVAILABLE
        primary = extended & 0xFF
        if primary in _CONFLICT_PRIMARY_CODES or extended in _CONFLICT_EXTENDED_CODES:
            return CONCURRENCY_CONFLICT
        if extended in _INVARIANT_EXTENDED_CODES:
            return INVARIANT_VIOLATION
        if primary in _WRITE_FAILED_PRIMARY_CODES:
            return WRITE_FAILED
        return STORAGE_UNAVAILABLE

    def failure(
        self,
        code: str,
        *,
        message: str,
        details: Mapping[str, DiagnosticDetailValue] | None = None,
    ) -> Failure:
        """One persistence diagnostic stamped from the injected clock (plan 6.5)."""
        return persistence_failure(
            code, message=message, clock=self._clock, details=details
        )

    def consistency_report(self) -> ConsistencyReport:
        """Plan 4.6: the eight counts over one read-only session, none defaulted.

        Every member is read-only SQL over the Task 2 schema (``json_each`` over
        the E7/E8 columns, the composite slot key, the N6 projections rendered
        back to canonical text, ``PRAGMA foreign_key_check``); a query that fails
        raises rather than reporting a clean count.
        """
        with self.read_only() as connection:
            return ConsistencyReport(
                dangling_diagnostic_references=_scalar_int(
                    connection, _DANGLING_DIAGNOSTIC_REFERENCES_SQL
                ),
                slot_identity_mismatches=_scalar_int(
                    connection, _SLOT_IDENTITY_MISMATCHES_SQL
                ),
                spec_projection_mismatches=_scalar_int(
                    connection, _SPEC_PROJECTION_MISMATCHES_SQL
                ),
                queued_without_snapshot=_scalar_int(
                    connection, _QUEUED_WITHOUT_SNAPSHOT_SQL
                ),
                causal_edge_mismatches=_scalar_int(
                    connection, _CAUSAL_EDGE_MISMATCHES_SQL
                ),
                unresolved_causal_references=_scalar_int(
                    connection, _UNRESOLVED_CAUSAL_REFERENCES_SQL
                ),
                registry_projection_mismatches=sum(
                    _scalar_int(connection, statement)
                    for statement in _REGISTRY_PROJECTION_SQL
                ),
                foreign_key_violations=len(
                    connection.execute(text(_FOREIGN_KEY_CHECK_SQL)).all()
                ),
            )

    def close(self) -> None:
        """Dispose the pool, closing every connection; idempotent."""
        self._engine.dispose()

    def _verify_identity(self) -> Failure | None:
        """Plan 6.2 step 3, on a connection discarded afterwards so that the next
        physical connect applies the journal-mode switch outside any transaction."""
        with self._engine.connect() as connection:
            application_id = _scalar_int(connection, "PRAGMA application_id")
            user_tables = _scalar_int(connection, _USER_TABLE_COUNT)
            connection.rollback()
            connection.invalidate()
        if application_id == APPLICATION_ID or (
            application_id == 0 and user_tables == 0
        ):
            return None
        return self.failure(
            STORAGE_UNAVAILABLE,
            message="the database belongs to another application",
            details={"operation": "open", "application_id": application_id},
        )

    def _verify_storage(self) -> Failure | None:
        """Plan 6.2 steps 4-5 on a fresh physical connection: the connect hook has
        switched WAL and read back every setting; ``quick_check`` must be ``ok``."""
        with self._engine.connect() as connection:
            verdicts = [
                str(value)
                for value in connection.execute(text("PRAGMA quick_check"))
                .scalars()
                .all()
            ]
            connection.rollback()
        if verdicts == ["ok"]:
            return None
        return self.failure(
            STORAGE_UNAVAILABLE,
            message="the database failed its integrity check",
            details={
                "operation": "quick_check",
                "quick_check": "; ".join(verdicts)[:_MAX_QUICK_CHECK_DETAIL],
            },
        )

    def _apply_revision_policy(self, revision_policy: RevisionPolicy) -> Failure | None:
        """Plan 6.2 step 6: the caller's policy over a verified connection."""
        with self._engine.connect() as connection:
            verdict = revision_policy(connection)
            connection.rollback()
        if isinstance(verdict, Failure):
            return verdict
        return None

    def _open_failure(self, error: DBAPIError) -> Failure:
        """A DBAPI error during an open: a busy lock stays a retriable conflict and
        every other code is storage unavailability, because an open writes nothing."""
        code = self.classify(error)
        if code == CONCURRENCY_CONFLICT:
            message = "the database is locked by another connection"
        else:
            code = STORAGE_UNAVAILABLE
            message = "the database could not be opened"
        details: dict[str, DiagnosticDetailValue] = {
            "operation": "open",
            **_result_code_details(error),
        }
        return self.failure(code, message=message, details=details)
