"""Fixtures for the Stage 8 persistence unit tests (plan section 7.1).

Task 1 owns ``fixed_clock`` (``FixedClock(INSTANT)``) and ``bare_database``: an
**unmigrated** ``SqliteDatabase`` opened on ``tmp_path / "bare.sqlite3"`` with the
accepting revision policy and closed in teardown, for the Task 1 probes that
create throwaway tables (cases C-15 and C-16). Task 2 adds the migrated
``sqlite_database`` (``open_test_database``, closed in teardown), ``seeded_database``
(the migrated database plus the raw ``INSERT`` rows of
``test_sqlite_constraints.SEED_STATEMENTS`` -- one shape-valid literal row per
table in the plan 6.4 dependency order, executed through ``raw_connection`` because
no codec exists before Task 3) and ``two_revision_script_directory`` (a
``tmp_path`` copy of the packaged script directory plus a generated
``r0002_test_failing.py`` whose ``upgrade()`` creates ``half_table`` and then
raises; cases C-21 ``BEHIND`` and C-22). Task 4 adds ``sqlite_harness``; no fixture
is redefined by a later task. The seed rows are imported relatively: this
directory is the ``persistence`` test package (Task 1's authorized marker), so
the constraints module and this conftest share one qualified module identity
under pytest and the pinned mypy configuration alike.
"""

from __future__ import annotations

import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from crypto_lab.domain.results import Success
from crypto_lab.persistence import migrations
from crypto_lab.persistence.database import SqliteDatabase
from doubles.experiments import INSTANT, FixedClock
from persistence_support.harness import (
    SqliteHarness,
    accept_any_revision,
    open_test_database,
    raw_connection,
)

from .test_sqlite_constraints import SEED_STATEMENTS

#: The generated second revision of ``two_revision_script_directory``: a
#: ``create_table`` followed by a raise, so the per-migration transaction must
#: roll the half-created table back and leave the database at revision one.
_FAILING_REVISION_SOURCE = '''"""Test-only successor: creates a table, then raises."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "r0002_test_failing"
down_revision = "r0001_stage8_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("half_table", sa.Column("x", sa.Integer(), nullable=False))
    raise RuntimeError("test revision failure after create_table")


def downgrade() -> None:
    op.drop_table("half_table")
'''


@pytest.fixture
def fixed_clock() -> FixedClock:
    """The fixed instant every persistence test stamps its failures with."""
    return FixedClock(INSTANT)


@pytest.fixture
def bare_database(
    tmp_path: Path,
    fixed_clock: FixedClock,
) -> Iterator[SqliteDatabase]:
    """An unmigrated database with no schema, closed in teardown (plan 7.1)."""
    opened = SqliteDatabase.open(
        tmp_path / "bare.sqlite3",
        busy_timeout_ms=100,
        clock=fixed_clock,
        revision_policy=accept_any_revision,
    )
    assert isinstance(opened, Success), opened
    database = opened.value
    try:
        yield database
    finally:
        database.close()


@pytest.fixture
def sqlite_database(
    tmp_path: Path,
    fixed_clock: FixedClock,
) -> Iterator[SqliteDatabase]:
    """The migrated database at ``tmp_path / "registry.sqlite3"`` (plan 7.1)."""
    database = open_test_database(tmp_path, clock=fixed_clock)
    try:
        yield database
    finally:
        database.close()


@pytest.fixture
def seeded_database(sqlite_database: SqliteDatabase) -> SqliteDatabase:
    """The migrated database holding one shape-valid raw row per table (C-27)."""
    connection = raw_connection(sqlite_database.path)
    try:
        connection.execute("BEGIN")
        for statement, parameters in SEED_STATEMENTS:
            connection.execute(statement, parameters)
        connection.execute("COMMIT")
    finally:
        connection.close()
    return sqlite_database


@pytest.fixture
def sqlite_harness(sqlite_database: SqliteDatabase) -> Iterator[SqliteHarness]:
    """The Task 4 harness over the migrated database (plan 7.1).

    ``close()`` rolls back every transaction a test left open -- an abandoned
    one included -- and then disposes the engine, so no lock or handle survives.
    """
    harness = SqliteHarness(sqlite_database)
    try:
        yield harness
    finally:
        harness.close()


@pytest.fixture
def two_revision_script_directory(tmp_path: Path) -> Path:
    """A copy of the packaged script directory plus a failing second revision."""
    source = Path(migrations.__file__).resolve().parent
    target = tmp_path / "two_revision_scripts"
    shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__"))
    (target / "versions" / "r0002_test_failing.py").write_text(
        _FAILING_REVISION_SOURCE, encoding="utf-8"
    )
    return target
