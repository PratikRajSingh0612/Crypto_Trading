"""Fixtures for the Stage 8 persistence unit tests (plan section 7.1).

Task 1 owns ``fixed_clock`` (``FixedClock(INSTANT)``) and ``bare_database``: an
**unmigrated** ``SqliteDatabase`` opened on ``tmp_path / "bare.sqlite3"`` with the
accepting revision policy and closed in teardown, for the Task 1 probes that
create throwaway tables (cases C-15 and C-16). Task 2 adds the migrated
``sqlite_database``, ``seeded_database`` and ``two_revision_script_directory``
fixtures beside it and Task 4 adds ``sqlite_harness``; no fixture is redefined by
a later task.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from crypto_lab.domain.results import Success
from crypto_lab.persistence.database import SqliteDatabase
from doubles.experiments import INSTANT, FixedClock
from persistence_support.harness import accept_any_revision


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
