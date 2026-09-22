"""The revision-state vocabulary, the migration runner and the two entry points.

Plan sections 6.2 and 6.4 (specification 23.4, 29.2 step 2). This is the only
persistence module that imports ``alembic.command``, ``alembic.config``,
``alembic.script`` and ``alembic.runtime``; ``database.py`` never imports Alembic.

``check_revision`` classifies a connection's database into one of the five
``RevisionState`` members (reading 15): no stamped revision and no user table is
``EMPTY``; a stamped head is ``CURRENT``; a stamped revision the script directory
knows is ``BEHIND``; a stamped identifier it does not know -- an unsupported newer
or foreign database -- is ``UNKNOWN``; user tables without a stamped revision are
``UNVERSIONED``. A version table holding more than one identifier is also
``UNKNOWN`` (its identifiers are reported comma-joined), because no entry point
admits an inconsistent version table. ``open_database`` admits ``CURRENT`` only and
``open_for_migration`` admits ``EMPTY``, ``BEHIND`` and ``CURRENT``; every other
state is ``PERSISTENCE.MIGRATION_MISMATCH`` carrying the state, the stamped
revision and the expected head, and every refusal issues reads only.

Opening (section 6.2, the Task 1 review finding R1-01): the normal open refuses an
absent database file itself, with ``PERSISTENCE.STORAGE_UNAVAILABLE``, before the
Task 1 primitive -- which would create the file -- runs; ``open_for_migration`` on
an absent path is the one creation Stage 8 performs, and it stamps
``APPLICATION_ID`` when the database is ``EMPTY`` so the identity check admits the
file from then on. Every other opening refusal (a relative path, a missing
directory, a directory, a corrupt or foreign file, a failed PRAGMA read-back or
``quick_check``) is the primitive's own.

``apply_migrations`` requires ``EMPTY`` or ``BEHIND`` and runs
``alembic.command.upgrade(config, "head")`` with the database's connection placed
in ``config.attributes["connection"]``; ``env.py`` configures
``transaction_per_migration=True`` and the runner ends its own read transaction
before handing the connection over, so Alembic owns one transaction per revision
and a raising revision rolls back to the prior revision (C-22), reported as
``PERSISTENCE.WRITE_FAILED`` naming the revision that raised. ``metadata_drift``
is Alembic's metadata comparison rendered as stable one-line descriptions, with
``alembic_version`` excluded; ``schema_objects`` is the ``sqlite_master`` listing
the pinned ``schema.EXPECTED_SCHEMA_OBJECTS`` is compared with. The programmatic
``Config`` sets ``script_location`` to the packaged directory resolved from this
module's own ``__file__`` (never from the working directory) and ``path_separator``
(Alembic 1.16+ name of the fixed separator); there is no ``alembic.ini`` and no
logging configuration. Nothing here reads configuration, the environment or a
clock: every failure is stamped from the injected ``Clock``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from alembic.util.exc import CommandError
from pydantic import InstanceOf
from pydantic.experimental.missing_sentinel import MISSING
from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError

from crypto_lab.domain.diagnostics import DiagnosticDetailValue
from crypto_lab.domain.ports import Clock
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.persistence import schema
from crypto_lab.persistence.database import APPLICATION_ID, SqliteDatabase
from crypto_lab.persistence.diagnostics import (
    MIGRATION_MISMATCH,
    STORAGE_UNAVAILABLE,
    WRITE_FAILED,
    persistence_failure,
)
from crypto_lab.persistence.schema import SchemaObject, normalized_sql

__all__ = [
    "RevisionReport",
    "RevisionState",
    "apply_migrations",
    "check_revision",
    "expected_head",
    "metadata_drift",
    "open_database",
    "open_for_migration",
    "schema_objects",
]

#: The packaged script directory, a pure path join on this module's location.
_PACKAGED_SCRIPT_LOCATION: Final = Path(__file__).parent / "migrations"
#: User tables are every table that is neither SQLite's own nor Alembic's.
_USER_TABLE_COUNT: Final = (
    "SELECT count(*) FROM sqlite_master WHERE type = 'table' "
    "AND name NOT LIKE 'sqlite%' AND name <> 'alembic_version'"
)
#: Every table, index and trigger except SQLite's internal objects.
_SCHEMA_OBJECTS: Final = (
    "SELECT type, name, tbl_name, sql FROM sqlite_master "
    "WHERE type IN ('table', 'index', 'trigger') AND name NOT LIKE 'sqlite%'"
)
_READ_APPLICATION_ID: Final = "PRAGMA application_id"
_STAMP_APPLICATION_ID: Final = f"PRAGMA application_id = {APPLICATION_ID}"
_ABSENT_FILE_MESSAGE: Final = "database file does not exist"


class RevisionState(StrEnum):
    """Plan 6.4: the five classifications of a database's stamped revision."""

    EMPTY = "EMPTY"
    CURRENT = "CURRENT"
    BEHIND = "BEHIND"
    UNKNOWN = "UNKNOWN"
    UNVERSIONED = "UNVERSIONED"


_MIGRATABLE_STATES: Final = frozenset({RevisionState.EMPTY, RevisionState.BEHIND})
_NORMAL_OPEN_STATES: Final = frozenset({RevisionState.CURRENT})
_MIGRATION_OPEN_STATES: Final = _MIGRATABLE_STATES | _NORMAL_OPEN_STATES


@dataclass(frozen=True, slots=True, kw_only=True)
class RevisionReport:
    """The outcome of ``check_revision``: state, stamped revision, expected head."""

    state: RevisionState
    current_revision: str | MISSING  # type: ignore[valid-type]
    expected_head: str


def _config(script_location: Path | None) -> Config:
    config = Config()
    location = _PACKAGED_SCRIPT_LOCATION if script_location is None else script_location
    config.set_main_option("script_location", str(location))
    config.set_main_option("path_separator", "os")
    return config


def _script_directory(script_location: Path | None) -> ScriptDirectory:
    return ScriptDirectory.from_config(_config(script_location))


def _single_head(script: ScriptDirectory) -> str:
    heads = script.get_heads()
    if len(heads) != 1:
        raise RuntimeError(
            f"the script directory must have exactly one head, found {len(heads)}"
        )
    return heads[0]


def expected_head(*, script_location: Path | None = None) -> str:
    """The one head of the script directory; two heads are a programmer defect."""
    return _single_head(_script_directory(script_location))


def check_revision(
    connection: Connection, *, script_location: Path | None = None
) -> RevisionReport:
    """Plan 6.4: classify the connection's database against the script directory.

    Reads only: the stamped revision through Alembic's migration context and
    the user-table count from ``sqlite_master``.
    """
    script = _script_directory(script_location)
    head = _single_head(script)
    stamped = MigrationContext.configure(connection).get_current_heads()
    user_tables = int(connection.execute(text(_USER_TABLE_COUNT)).scalar_one())
    if len(stamped) == 0:
        state = RevisionState.EMPTY if user_tables == 0 else RevisionState.UNVERSIONED
        return RevisionReport(state=state, current_revision=MISSING, expected_head=head)
    if len(stamped) != 1:
        return RevisionReport(
            state=RevisionState.UNKNOWN,
            current_revision=",".join(sorted(stamped)),
            expected_head=head,
        )
    (current,) = stamped
    try:
        script.get_revision(current)
    except CommandError:
        return RevisionReport(
            state=RevisionState.UNKNOWN, current_revision=current, expected_head=head
        )
    state = RevisionState.CURRENT if current == head else RevisionState.BEHIND
    return RevisionReport(state=state, current_revision=current, expected_head=head)


def _mismatch_details(
    operation: str, report: RevisionReport
) -> dict[str, DiagnosticDetailValue]:
    details: dict[str, DiagnosticDetailValue] = {
        "operation": operation,
        "state": report.state.value,
    }
    if isinstance(report.current_revision, str):
        details["current_revision"] = report.current_revision
    details["expected_head"] = report.expected_head
    return details


def _mismatch(
    clock: Clock, operation: str, report: RevisionReport, admitted: str
) -> Failure:
    return persistence_failure(
        MIGRATION_MISMATCH,
        message=f"database revision state is {report.state.value}; {admitted}",
        clock=clock,
        details=_mismatch_details(operation, report),
    )


def _admitting(
    states: frozenset[RevisionState], clock: Clock, admitted: str
) -> Callable[[Connection], Result[None]]:
    """Plan 6.2 step 6: the revision policy an entry point hands to the primitive."""

    def policy(connection: Connection) -> Result[None]:
        report = check_revision(connection)
        if report.state in states:
            return Success[None](outcome="SUCCESS", value=None)
        return _mismatch(clock, "open", report, admitted)

    return policy


def open_database(
    path: Path, *, busy_timeout_ms: int, clock: Clock
) -> Result[SqliteDatabase]:
    """Plan 6.2: open an existing, current database for normal use.

    An absent file in an existing directory is refused here, before the
    primitive that would create it runs (R1-01); nothing is created, stamped or
    migrated. Every other step is the Task 1 primitive's with the ``CURRENT``-only
    revision policy as step 6.
    """
    if path.is_absolute() and path.parent.is_dir() and not path.exists():
        return persistence_failure(
            STORAGE_UNAVAILABLE,
            message=_ABSENT_FILE_MESSAGE,
            clock=clock,
            details={"operation": "open"},
        )
    return SqliteDatabase.open(
        path,
        busy_timeout_ms=busy_timeout_ms,
        clock=clock,
        revision_policy=_admitting(
            _NORMAL_OPEN_STATES, clock, "a current database is required"
        ),
    )


def open_for_migration(
    path: Path, *, busy_timeout_ms: int, clock: Clock
) -> Result[SqliteDatabase]:
    """Plan 6.2: open a database for ``apply_migrations``.

    Admits ``EMPTY``, ``BEHIND`` and ``CURRENT``; an absent path in an existing
    directory is created by the primitive (the one creation Stage 8 performs) and,
    when the state is ``EMPTY``, stamped with ``APPLICATION_ID`` before the
    baseline revision runs (plan 6.1).
    """
    opened = SqliteDatabase.open(
        path,
        busy_timeout_ms=busy_timeout_ms,
        clock=clock,
        revision_policy=_admitting(
            _MIGRATION_OPEN_STATES,
            clock,
            "an empty, behind or current database is required",
        ),
    )
    if isinstance(opened, Failure):
        return opened
    database = opened.value
    try:
        with database.connection() as connection:
            stamped = int(connection.execute(text(_READ_APPLICATION_ID)).scalar_one())
            if stamped == 0:
                connection.execute(text(_STAMP_APPLICATION_ID))
                connection.commit()
    except DBAPIError as error:
        database.close()
        return database.failure(
            database.classify(error),
            message="the application identity could not be stamped",
            details={"operation": "stamp", **_result_code_details(error)},
        )
    except BaseException:
        database.close()
        raise
    return opened


def _result_code_details(error: DBAPIError) -> dict[str, DiagnosticDetailValue]:
    candidates = {
        "sqlite_errorcode": getattr(error.orig, "sqlite_errorcode", None),
        "sqlite_errorname": getattr(error.orig, "sqlite_errorname", None),
    }
    return {
        key: value for key, value in candidates.items() if isinstance(value, int | str)
    }


def _failing_revision(script: ScriptDirectory, current: object) -> str:
    """The revision the upgrade path would apply next after ``current``."""
    parent = current if isinstance(current, str) else None
    for revision in script.walk_revisions():
        if revision.down_revision == parent:
            return revision.revision
    # A consistent linear history always names a child of the stamped revision
    # (or its base when nothing is stamped); only an inconsistent directory
    # reaches this line, so the head is the best available name.
    return _single_head(script)  # pragma: no cover - unreachable for a linear history


def apply_migrations(
    database: SqliteDatabase, *, script_location: Path | None = None
) -> Result[RevisionReport]:
    """Plan 6.4: upgrade an ``EMPTY`` or ``BEHIND`` database to the head.

    Each revision runs inside its own transaction; a raising revision is rolled
    back by Alembic and reported as ``PERSISTENCE.WRITE_FAILED`` naming it, with
    the database left at the prior revision (C-22). Any other state is
    ``PERSISTENCE.MIGRATION_MISMATCH`` and nothing is run or stamped.
    """
    script = _script_directory(script_location)
    with database.connection() as connection:
        report = check_revision(connection, script_location=script_location)
        connection.rollback()
        if report.state not in _MIGRATABLE_STATES:
            return database.failure(
                MIGRATION_MISMATCH,
                message=f"database revision state is {report.state.value}; "
                "apply_migrations requires EMPTY or BEHIND",
                details=_mismatch_details("upgrade", report),
            )
        config = _config(script_location)
        config.attributes["connection"] = connection
        try:
            command.upgrade(config, "head")
        except Exception as error:  # a raising revision, rolled back by Alembic
            connection.rollback()
            after = check_revision(connection, script_location=script_location)
            connection.rollback()
            revision = _failing_revision(script, after.current_revision)
            details: dict[str, DiagnosticDetailValue] = {
                "operation": "upgrade",
                "revision": revision,
                "error_type": type(error).__name__,
            }
            if isinstance(error, DBAPIError):
                details.update(_result_code_details(error))
            return database.failure(
                WRITE_FAILED,
                message=f"migration revision {revision} failed and was rolled back",
                details=details,
            )
        connection.rollback()
        final = check_revision(connection, script_location=script_location)
        connection.rollback()
    return Success[InstanceOf[RevisionReport]](outcome="SUCCESS", value=final)


def _include_name(
    name: str | None, type_: str, parent_names: Mapping[str, str | None]
) -> bool:
    del parent_names
    return not (type_ == "table" and name == "alembic_version")


def _label(item: object) -> str:
    name = getattr(item, "name", None)
    if isinstance(name, str):
        return name
    if item is None:
        return "-"
    if isinstance(item, str):
        return item
    if isinstance(item, Mapping):
        return "{" + ", ".join(sorted(str(key) for key in item)) + "}"
    return type(item).__name__


def _describe(diff: object) -> str:
    if isinstance(diff, list):
        return "; ".join(_describe(item) for item in diff)
    if isinstance(diff, tuple) and diff:
        kind, *rest = diff
        return " ".join([str(kind), *(_label(item) for item in rest)])
    return " ".join(repr(diff).split())


def metadata_drift(connection: Connection) -> tuple[str, ...]:
    """Plan 6.4: Alembic's comparison of the live database with ``schema.metadata``,
    rendered as stable one-line descriptions; empty on a migrated database."""
    opts: dict[str, Any] = {
        "compare_type": True,
        "compare_server_default": True,
        "include_name": _include_name,
        "target_metadata": schema.metadata,
    }
    diffs = compare_metadata(
        MigrationContext.configure(connection, opts=opts), schema.metadata
    )
    return tuple(_describe(diff) for diff in diffs)


def schema_objects(connection: Connection) -> tuple[SchemaObject, ...]:
    """Plan 6.4: every table, index and trigger of ``sqlite_master`` with its
    normalized SQL, sorted by type, table and name; SQLite's internal objects
    are omitted."""
    rows = connection.execute(text(_SCHEMA_OBJECTS)).all()
    objects = [
        SchemaObject(
            str(row._mapping["type"]),
            str(row._mapping["name"]),
            str(row._mapping["tbl_name"]),
            normalized_sql(str(row._mapping["sql"] or "")),
        )
        for row in rows
    ]
    return tuple(sorted(objects, key=lambda row: (row.type, row.table, row.name)))
