"""Revision ``r0002_stage9_artifacts`` against the baseline (Stage 9 plan 6.6, Task 5).

A database at ``r0001`` is ``BEHIND`` and upgrades to ``r0002``; a database at
``r0002`` is ``CURRENT``; a newer or foreign stamp is ``UNKNOWN`` and refused. A
database upgraded from ``r0001`` and a fresh ``r0002`` database have identical
``sqlite_master`` objects, both equal to the derived ``EXPECTED_SCHEMA_OBJECTS``,
and ``metadata_drift() == ()``. ``downgrade()`` removes every Stage 9 trigger,
index and table and retains the nullable ``engine_runs.finalization_deadline_utc``
column by decision (plan 2.4), recorded as the function's own last statement. The
script directory has exactly one head, ``r0002``, whose down revision is the
baseline, which is itself unchanged.
"""

from __future__ import annotations

import ast
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.engine import Connection

from crypto_lab.domain.results import Failure
from crypto_lab.persistence import migrations, schema
from crypto_lab.persistence.database import SqliteDatabase
from crypto_lab.persistence.migration_runner import (
    RevisionState,
    apply_migrations,
    check_revision,
    expected_head,
    metadata_drift,
    open_database,
    open_for_migration,
    schema_objects,
)
from crypto_lab.persistence.migrations.versions import (
    r0001_stage8_baseline,
    r0002_stage9_artifacts,
)
from doubles.experiments import INSTANT, FixedClock
from persistence_support.harness import code, ok, open_test_database

_BASELINE = "r0001_stage8_baseline"
_HEAD = "r0002_stage9_artifacts"
_PACKAGED_SCRIPTS = Path(migrations.__file__).resolve().parent
_RESIDUE_STATEMENT = "-- finalization_deadline_utc retained"
_STAGE9_TABLES = schema.TABLES_IN_DEPENDENCY_ORDER[schema.STAGE8_TABLE_COUNT :]


def _clock() -> FixedClock:
    return FixedClock(INSTANT)


def _config(connection: Connection) -> Config:
    config = Config()
    config.set_main_option("script_location", str(_PACKAGED_SCRIPTS))
    config.set_main_option("path_separator", "os")
    config.attributes["connection"] = connection
    return config


def _open_at_baseline(path: Path) -> SqliteDatabase:
    """A database migrated to ``r0001`` only, through Alembic's own upgrade."""
    database = ok(open_for_migration(path, busy_timeout_ms=100, clock=_clock()))
    with database.connection() as connection:
        command.upgrade(_config(connection), _BASELINE)
    return database


def _columns(connection: Connection, table: str) -> list[str]:
    rows = connection.execute(text(f"PRAGMA table_info({table})")).all()
    return [str(row._mapping["name"]) for row in rows]


def _object_names(connection: Connection, kind: str) -> set[str]:
    rows = connection.execute(
        text("SELECT name FROM sqlite_master WHERE type = :kind"), {"kind": kind}
    ).scalars()
    return {str(name) for name in rows if not str(name).startswith("sqlite_")}


def test_r0001_is_behind_r0002_is_current_newer_blocks(tmp_path: Path) -> None:
    path = tmp_path / "staged.sqlite3"
    database = _open_at_baseline(path)
    try:
        with database.read_only() as connection:
            report = check_revision(connection)
            assert report.state is RevisionState.BEHIND
            assert report.current_revision == _BASELINE
            assert report.expected_head == _HEAD
            assert "candidate_artifacts" not in _object_names(connection, "table")
            assert "finalization_deadline_utc" not in _columns(
                connection, "engine_runs"
            )
        applied = ok(apply_migrations(database))
        assert applied.state is RevisionState.CURRENT
        assert applied.current_revision == _HEAD
        with database.read_only() as connection:
            assert check_revision(connection).state is RevisionState.CURRENT
            assert set(_STAGE9_TABLES) <= _object_names(connection, "table")
            assert "finalization_deadline_utc" in _columns(connection, "engine_runs")
        # A newer stamp the packaged directory does not know is UNKNOWN and refused.
        with database.connection() as connection:
            connection.execute(
                text("UPDATE alembic_version SET version_num = 'r0003_future_stage'")
            )
            connection.commit()
        with database.read_only() as connection:
            newer = check_revision(connection)
            assert newer.state is RevisionState.UNKNOWN
            assert newer.current_revision == "r0003_future_stage"
    finally:
        database.close()
    refused = open_database(path, busy_timeout_ms=100, clock=_clock())
    assert isinstance(refused, Failure)
    assert code(refused) == "PERSISTENCE.MIGRATION_MISMATCH"


def test_upgrade_from_r0001_equals_fresh_r0002(tmp_path: Path) -> None:
    upgraded = _open_at_baseline(tmp_path / "upgraded.sqlite3")
    fresh = open_test_database(tmp_path, clock=_clock())
    try:
        ok(apply_migrations(upgraded))
        with upgraded.read_only() as connection:
            upgraded_objects = schema_objects(connection)
            assert metadata_drift(connection) == ()
            assert connection.execute(text("PRAGMA foreign_key_check")).all() == []
        with fresh.read_only() as connection:
            fresh_objects = schema_objects(connection)
            assert metadata_drift(connection) == ()
    finally:
        upgraded.close()
        fresh.close()
    assert upgraded_objects == fresh_objects
    assert upgraded_objects == schema.EXPECTED_SCHEMA_OBJECTS
    # The added column renders exactly as ALTER TABLE appends it: after the last
    # Stage 8 column and before the table constraints (plan 2.4, reading 9).
    engine_runs = next(row for row in fresh_objects if row.name == "engine_runs")
    assert (
        "revision INTEGER NOT NULL, finalization_deadline_utc INTEGER, CONSTRAINT"
        in engine_runs.sql
    )


def test_downgrade_leaves_column_with_recorded_warning(tmp_path: Path) -> None:
    database = open_test_database(tmp_path, clock=_clock())
    try:
        with database.connection() as connection:
            command.downgrade(_config(connection), _BASELINE)
        with database.read_only() as connection:
            report = check_revision(connection)
            assert report.state is RevisionState.BEHIND
            assert report.current_revision == _BASELINE
            tables = _object_names(connection, "table")
            assert tables.isdisjoint(_STAGE9_TABLES)
            stage8 = schema.TABLES_IN_DEPENDENCY_ORDER[: schema.STAGE8_TABLE_COUNT]
            assert tables >= set(stage8)
            triggers = _object_names(connection, "trigger")
            assert not any(
                f"trg_{rule}" in name
                for name in triggers
                for rule in schema.STAGE9_TRIGGER_RULES
            )
            assert triggers == {
                statement.split()[2] for statement in schema.TRIGGER_SQL
            }
            indexes = _object_names(connection, "index")
            assert "ix_engine_runs_finalization_deadline_utc" not in indexes
            assert not any(
                name.startswith(f"ix_{table}") or name.startswith(f"uq_{table}")
                for name in indexes
                for table in _STAGE9_TABLES
            )
            # The documented, tested, non-destructive residue (plan 2.4, 6.6).
            assert "finalization_deadline_utc" in _columns(connection, "engine_runs")
            assert connection.execute(text("PRAGMA quick_check")).scalar_one() == "ok"
    finally:
        database.close()
    revision_path = _PACKAGED_SCRIPTS / "versions" / f"{_HEAD}.py"
    source = revision_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    downgrade = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "downgrade"
    )
    last = downgrade.body[-1]
    assert isinstance(last, ast.Expr)
    assert ast.unparse(last.value) == f"op.execute({_RESIDUE_STATEMENT!r})"
    assert "drop_column" not in source


def test_script_directory_has_one_head_named_r0002() -> None:
    assert expected_head() == _HEAD
    versions = _PACKAGED_SCRIPTS / "versions"
    assert sorted(path.name for path in versions.glob("*.py")) == [
        "__init__.py",
        f"{_BASELINE}.py",
        f"{_HEAD}.py",
    ]
    assert r0002_stage9_artifacts.revision == _HEAD
    assert r0002_stage9_artifacts.down_revision == _BASELINE
    assert r0002_stage9_artifacts.branch_labels is None
    assert r0002_stage9_artifacts.depends_on is None
    assert r0001_stage8_baseline.revision == _BASELINE
    assert r0001_stage8_baseline.down_revision is None


def test_the_stage_nine_constants_are_partitioned_from_the_baseline() -> None:
    """``r0001`` executes ``TRIGGER_SQL`` and ``PARTIAL_INDEX_SQL`` by reference, so
    those keep their Stage 8 content; the Stage 9 statements are separate and
    name only Stage 9 objects."""
    assert len(schema.PARTIAL_INDEX_SQL) == 3
    assert len(schema.STAGE9_PARTIAL_INDEX_SQL) == 4
    assert len(schema.STAGE9_TRIGGER_RULES) == 16
    assert len(schema.STAGE9_TRIGGER_SQL) == 21
    assert set(schema.STAGE9_TRIGGER_SQL).isdisjoint(schema.TRIGGER_SQL)
    assert set(schema.STAGE9_PARTIAL_INDEX_SQL).isdisjoint(schema.PARTIAL_INDEX_SQL)
    stage8_tables = schema.TABLES_IN_DEPENDENCY_ORDER[: schema.STAGE8_TABLE_COUNT]
    for statement in schema.TRIGGER_SQL:
        assert statement.split(" ON ")[1].split()[0] in stage8_tables
    for statement in schema.STAGE9_TRIGGER_SQL:
        table = statement.split(" ON ")[1].split()[0]
        assert table in (*_STAGE9_TABLES, "engine_runs", "command_invocations")
    for statement in schema.PARTIAL_INDEX_SQL:
        assert "finalization_deadline_utc" not in statement
    assert any(
        "ix_engine_runs_finalization_deadline_utc" in statement
        for statement in schema.STAGE9_PARTIAL_INDEX_SQL
    )
