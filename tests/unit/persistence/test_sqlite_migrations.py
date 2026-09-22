"""The migration runner, the revision-state vocabulary and the two entry points.

Plan Task 2 Step 1 (sections 6.2, 6.4, 6.6, readings 15, 16, 17; cases C-21 and
C-22; the Task 1 review finding R1-01). The five opening cases are kept apart:
an absent target is a storage refusal that creates nothing (section 6.2: "a normal
``open_database`` on an absent path is ``STORAGE_UNAVAILABLE``, not a creation");
an inaccessible target -- a directory, a corrupt file, a foreign ``application_id``
-- is a storage refusal through the Task 1 primitive; an existing empty database is
the ``EMPTY`` revision state, admitted only by ``open_for_migration``; a database at
the expected revision opens; an ``UNKNOWN`` or ``UNVERSIONED`` database is refused
by both entry points. Every refusal leaves the file bytes unchanged and releases
every handle. The migration gate ``scripts/verify_migrations.py`` is exercised
in-process through ``main(argv)`` and proven able to fail through ``run_checks``.
The section 2.6 guard expectations Task 2 trips close the module.
"""

from __future__ import annotations

import ast
import importlib.metadata
import shutil
import tempfile
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic import context as migration_context
from alembic.config import Config
from alembic.runtime.environment import EnvironmentContext
from alembic.runtime.migration import MigrationContext, RevisionStep
from alembic.script import ScriptDirectory
from sqlalchemy import Integer, Text, TextClause, text
from sqlalchemy.engine import Connection

from crypto_lab.domain.results import Failure
from crypto_lab.persistence import migration_runner, migrations
from crypto_lab.persistence.database import APPLICATION_ID
from crypto_lab.persistence.diagnostics import (
    MIGRATION_MISMATCH,
    STORAGE_UNAVAILABLE,
    WRITE_FAILED,
)
from crypto_lab.persistence.migration_runner import (
    RevisionReport,
    RevisionState,
    apply_migrations,
    check_revision,
    expected_head,
    metadata_drift,
    open_database,
    open_for_migration,
    schema_objects,
)
from crypto_lab.persistence.migrations import env as env_module
from crypto_lab.persistence.migrations.versions import r0001_stage8_baseline
from crypto_lab.persistence.schema import EXPECTED_SCHEMA_OBJECTS
from doubles.experiments import INSTANT, FixedClock
from persistence_support.harness import (
    code,
    file_sha256,
    ok,
    open_test_database,
    raw_connection,
)
from verify_migrations import main as verify_migrations_main
from verify_migrations import run_checks

_REPOSITORY = Path(__file__).resolve().parents[3]
_STAGE3_GUARD = _REPOSITORY / "tests/safety/test_stage3_boundaries.py"
_STAGE5_GUARD = _REPOSITORY / "tests/safety/test_stage5_boundaries.py"
_LAUNCHER_GUARD = _REPOSITORY / "tests/safety/test_uv_launcher.py"
_PACKAGE_LAYOUT = _REPOSITORY / "tests/unit/test_package_layout.py"
_PREFLIGHT_TESTS = (
    _REPOSITORY / "tests/unit/process_supervision/test_supervisor_preflight.py"
)
_RECONCILIATION_TESTS = (
    _REPOSITORY / "tests/unit/process_supervision/test_restart_reconciliation.py"
)
_LAUNCHER = _REPOSITORY / "scripts/invoke-uv.ps1"
_VERIFIER = _REPOSITORY / "scripts/verify.ps1"
_VERIFICATION_GUIDE = _REPOSITORY / "docs/development/verification.md"
_README = _REPOSITORY / "README.md"
_BASELINE = "r0001_stage8_baseline"
_PACKAGED_SCRIPTS = Path(migrations.__file__).resolve().parent
#: Plan section 2.6: the six Task 2 source paths and the seven exemption pairs.
_TASK2_SOURCE_PATHS = frozenset(
    {
        "persistence/schema.py",
        "persistence/migration_runner.py",
        "persistence/migrations/__init__.py",
        "persistence/migrations/env.py",
        "persistence/migrations/versions/__init__.py",
        "persistence/migrations/versions/r0001_stage8_baseline.py",
    }
)
_TASK2_MODULES = (
    "crypto_lab.persistence.schema",
    "crypto_lab.persistence.migration_runner",
    "crypto_lab.persistence.migrations",
    "crypto_lab.persistence.migrations.env",
    "crypto_lab.persistence.migrations.versions",
    "crypto_lab.persistence.migrations.versions.r0001_stage8_baseline",
)
_EXPECTED_EXEMPTIONS = frozenset(
    {
        ("process_supervision/windows_process.py", "subprocess"),
        ("persistence/database.py", "sqlalchemy"),
        ("persistence/schema.py", "sqlalchemy"),
        ("persistence/migration_runner.py", "sqlalchemy"),
        ("persistence/migration_runner.py", "alembic"),
        ("persistence/migrations/env.py", "sqlalchemy"),
        ("persistence/migrations/env.py", "alembic"),
        ("persistence/migrations/versions/r0001_stage8_baseline.py", "sqlalchemy"),
        ("persistence/migrations/versions/r0001_stage8_baseline.py", "alembic"),
    }
)
_EXTRA_TABLE_REVISION_SOURCE = '''"""Test-only successor: adds one table."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "r0002_test_extra"
down_revision = "r0001_stage8_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("extra_table", sa.Column("x", sa.Integer(), nullable=False))


def downgrade() -> None:
    op.drop_table("extra_table")
'''
_SECOND_HEAD_REVISION_SOURCE = '''"""Test-only sibling head (the one-head control)."""

from __future__ import annotations

from alembic import op

revision = "r0002_test_sibling"
down_revision = "r0001_stage8_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("SELECT 1")


def downgrade() -> None:
    op.execute("SELECT 1")
'''
_DBAPI_FAILING_REVISION_SOURCE = '''"""Test-only successor: a refused statement."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "r0002_test_dbapi"
down_revision = "r0001_stage8_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(sa.text("INSERT INTO no_such_table (x) VALUES (1)"))


def downgrade() -> None:
    op.execute(sa.text("SELECT 1"))
'''
_THIRD_REVISION_SOURCE = '''"""Test-only third revision above the failing one."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "r0003_test_third"
down_revision = "r0002_test_failing"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(sa.text("SELECT 1"))


def downgrade() -> None:
    op.execute(sa.text("SELECT 1"))
'''


# --------------------------------------------------------------------------
# Module-local helpers (plan 7.1: ``stamp_unknown_revision`` is Task 2's
# module-local name; the rest serve the opening and gate cases)
# --------------------------------------------------------------------------


def _clock() -> FixedClock:
    return FixedClock(INSTANT)


def _details(result: object) -> dict[str, object]:
    assert isinstance(result, Failure)
    (diagnostic,) = result.diagnostics
    return dict(diagnostic.details)


def _message(result: object) -> str:
    assert isinstance(result, Failure)
    (diagnostic,) = result.diagnostics
    return diagnostic.message


def _listing(directory: Path) -> list[str]:
    return sorted(entry.name for entry in directory.iterdir())


def stamp_unknown_revision(path: Path, revision: str) -> None:
    """Overwrite the stamped revision with an identifier no script directory knows."""
    connection = raw_connection(path)
    try:
        connection.execute("UPDATE alembic_version SET version_num = ?", (revision,))
    finally:
        connection.close()


def _raw(path: Path, statement: str) -> None:
    connection = raw_connection(path)
    try:
        connection.execute(statement)
    finally:
        connection.close()


def _user_tables(connection: Connection) -> list[str]:
    rows = connection.execute(
        text(
            "SELECT name FROM sqlite_master WHERE type = 'table' "
            "AND name NOT LIKE 'sqlite%' ORDER BY name"
        )
    ).scalars()
    return [str(name) for name in rows]


def _script_directory_with(tmp_path: Path, name: str, *sources: str) -> Path:
    """A copy of the packaged script directory plus the given revision sources."""
    target = tmp_path / name
    shutil.copytree(
        _PACKAGED_SCRIPTS, target, ignore=shutil.ignore_patterns("__pycache__")
    )
    for source in sources:
        revision = source.split('revision = "', 1)[1].split('"', 1)[0]
        (target / "versions" / f"{revision}.py").write_text(source, encoding="utf-8")
    return target


def _alembic_config(connection: object) -> Config:
    """A test-local programmatic configuration mirroring the runner's shape."""
    config = Config()
    config.set_main_option("script_location", str(_PACKAGED_SCRIPTS))
    config.set_main_option("path_separator", "os")
    config.attributes["connection"] = connection
    return config


def _literal(path: Path, name: str) -> Any:
    """The literal assigned to ``name`` at module level, ``frozenset`` unwrapped."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        if value is None or not any(
            isinstance(target, ast.Name) and target.id == name for target in targets
        ):
            continue
        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "frozenset"
            and len(value.args) == 1
        ):
            return frozenset(ast.literal_eval(value.args[0]))
        return ast.literal_eval(value)
    raise AssertionError(f"{name} is not assigned a literal in {path}")


# --------------------------------------------------------------------------
# The script directory (readings 17 and 18; the ordered history)
# --------------------------------------------------------------------------


def test_the_script_directory_has_exactly_one_head_named_by_the_baseline() -> None:
    assert expected_head() == _BASELINE


def test_the_migration_history_is_the_one_baseline_revision() -> None:
    """Reading 18: one revision file beside an ignored ``__init__.py`` (reading 17),
    identifier-safe, with no down revision."""
    versions = _PACKAGED_SCRIPTS / "versions"
    assert sorted(path.name for path in versions.glob("*.py")) == [
        "__init__.py",
        f"{_BASELINE}.py",
    ]
    assert r0001_stage8_baseline.revision == _BASELINE
    assert r0001_stage8_baseline.down_revision is None
    assert (_PACKAGED_SCRIPTS / "script.py.mako").is_file()
    assert not (_REPOSITORY / "alembic.ini").exists()


def test_expected_head_follows_a_test_script_directory_and_refuses_two_heads(
    tmp_path: Path,
) -> None:
    extra = _script_directory_with(tmp_path, "extra", _EXTRA_TABLE_REVISION_SOURCE)
    assert expected_head(script_location=extra) == "r0002_test_extra"
    forked = _script_directory_with(
        tmp_path, "forked", _EXTRA_TABLE_REVISION_SOURCE, _SECOND_HEAD_REVISION_SOURCE
    )
    with pytest.raises(RuntimeError, match="exactly one head"):
        expected_head(script_location=forked)


# --------------------------------------------------------------------------
# Opening (plan 6.2; R1-01; C-21)
# --------------------------------------------------------------------------


def test_a_normal_open_refuses_an_absent_path_and_creates_nothing(
    tmp_path: Path,
) -> None:
    """R1-01 closed at the Task 2 boundary: the normal open refuses an absent
    database before any primitive that could create it runs, so no main file,
    no sidecar and no directory entry appears and nothing is initialized,
    migrated, stamped or written."""
    path = tmp_path / "absent.sqlite3"
    before = _listing(tmp_path)

    refused = open_database(path, busy_timeout_ms=100, clock=_clock())

    assert code(refused) == STORAGE_UNAVAILABLE
    assert _message(refused) == "database file does not exist"
    assert _details(refused) == {"operation": "open"}
    assert not path.exists()
    assert not (tmp_path / "absent.sqlite3-wal").exists()
    assert not (tmp_path / "absent.sqlite3-shm").exists()
    assert not (tmp_path / "absent.sqlite3-journal").exists()
    assert _listing(tmp_path) == before


def test_both_entry_points_refuse_an_inaccessible_target_without_mutation(
    tmp_path: Path,
) -> None:
    """A directory path, a non-SQLite file and a foreign ``application_id`` are
    storage refusals through the Task 1 primitive for both entry points; the
    bytes of the existing files stay unchanged (C-20 through the new boundary)."""
    directory = tmp_path / "a-directory.sqlite3"
    directory.mkdir()
    assert code(open_database(directory, busy_timeout_ms=100, clock=_clock())) == (
        STORAGE_UNAVAILABLE
    )
    assert code(open_for_migration(directory, busy_timeout_ms=100, clock=_clock())) == (
        STORAGE_UNAVAILABLE
    )
    assert _listing(directory) == []

    corrupt = tmp_path / "corrupt.sqlite3"
    corrupt.write_bytes(b"not a database" * 64)
    before = file_sha256(corrupt)
    assert code(open_database(corrupt, busy_timeout_ms=100, clock=_clock())) == (
        STORAGE_UNAVAILABLE
    )
    assert code(open_for_migration(corrupt, busy_timeout_ms=100, clock=_clock())) == (
        STORAGE_UNAVAILABLE
    )
    assert file_sha256(corrupt) == before

    foreign = tmp_path / "foreign.sqlite3"
    stamper = raw_connection(foreign)
    try:
        stamper.execute("PRAGMA application_id = 305419896")
        stamper.execute("CREATE TABLE theirs (x INTEGER)")
    finally:
        stamper.close()
    before = file_sha256(foreign)
    refused = open_database(foreign, busy_timeout_ms=100, clock=_clock())
    assert code(refused) == STORAGE_UNAVAILABLE
    assert _details(refused)["application_id"] == 305419896
    assert code(open_for_migration(foreign, busy_timeout_ms=100, clock=_clock())) == (
        STORAGE_UNAVAILABLE
    )
    assert file_sha256(foreign) == before


def test_every_revision_state_is_classified_and_refusals_do_not_mutate(
    tmp_path: Path,
) -> None:
    """C-21 over one file, in the order the plan's sketch walks it: the absent
    path is R1-01's storage refusal; the empty database ``open_for_migration``
    leaves behind is ``EMPTY`` (a mismatch for the normal open); the migrated
    file is ``CURRENT``; a stamped unknown identifier is ``UNKNOWN`` for both entry
    points. Every refusal leaves the file's SHA-256 unchanged."""
    path = tmp_path / "x.sqlite3"
    absent = open_database(path, busy_timeout_ms=100, clock=_clock())
    assert code(absent) == STORAGE_UNAVAILABLE
    assert not path.exists()

    migrating = ok(open_for_migration(path, busy_timeout_ms=100, clock=_clock()))
    with migrating.read_only() as connection:
        report = check_revision(connection)
        assert report.state is RevisionState.EMPTY
        assert not isinstance(report.current_revision, str)
        assert report.expected_head == _BASELINE
    migrating.close()
    assert path.is_file()
    before = file_sha256(path)
    empty = open_database(path, busy_timeout_ms=100, clock=_clock())
    assert code(empty) == MIGRATION_MISMATCH
    assert _details(empty) == {
        "operation": "open",
        "state": "EMPTY",
        "expected_head": _BASELINE,
    }
    assert file_sha256(path) == before

    migrating = ok(open_for_migration(path, busy_timeout_ms=100, clock=_clock()))
    applied = ok(apply_migrations(migrating))
    assert applied.state is RevisionState.CURRENT
    assert applied.current_revision == _BASELINE
    assert applied.expected_head == _BASELINE
    migrating.close()
    current = ok(open_database(path, busy_timeout_ms=100, clock=_clock()))
    with current.read_only() as connection:
        assert check_revision(connection).state is RevisionState.CURRENT
    current.close()

    stamp_unknown_revision(path, "zz_future")
    before = file_sha256(path)
    unknown = open_database(path, busy_timeout_ms=100, clock=_clock())
    assert code(unknown) == MIGRATION_MISMATCH
    assert _details(unknown) == {
        "operation": "open",
        "state": "UNKNOWN",
        "current_revision": "zz_future",
        "expected_head": _BASELINE,
    }
    assert (
        code(open_for_migration(path, busy_timeout_ms=100, clock=_clock()))
        == MIGRATION_MISMATCH
    )
    assert file_sha256(path) == before


def test_an_unversioned_database_is_refused_by_both_entry_points(
    tmp_path: Path,
) -> None:
    """User tables without ``alembic_version`` are ``UNVERSIONED`` (reading 15):
    refused by both entry points with the bytes unchanged."""
    database = open_test_database(tmp_path, clock=_clock())
    database.close()
    path = tmp_path / "registry.sqlite3"
    _raw(path, "DROP TABLE alembic_version")
    before = file_sha256(path)

    refused = open_database(path, busy_timeout_ms=100, clock=_clock())

    assert code(refused) == MIGRATION_MISMATCH
    assert _details(refused)["state"] == "UNVERSIONED"
    assert "current_revision" not in _details(refused)
    assert (
        code(open_for_migration(path, busy_timeout_ms=100, clock=_clock()))
        == MIGRATION_MISMATCH
    )
    assert file_sha256(path) == before


def test_a_two_row_version_table_is_unknown_and_refused(tmp_path: Path) -> None:
    """An inconsistent version table (two stamped heads) is admitted by no entry
    point; ``check_revision`` classifies it as ``UNKNOWN``."""
    database = open_test_database(tmp_path, clock=_clock())
    database.close()
    path = tmp_path / "registry.sqlite3"
    _raw(path, "INSERT INTO alembic_version (version_num) VALUES ('zz_other')")
    before = file_sha256(path)

    refused = open_database(path, busy_timeout_ms=100, clock=_clock())

    assert code(refused) == MIGRATION_MISMATCH
    assert _details(refused)["state"] == "UNKNOWN"
    assert (
        code(open_for_migration(path, busy_timeout_ms=100, clock=_clock()))
        == MIGRATION_MISMATCH
    )
    assert file_sha256(path) == before


def test_a_current_database_is_refused_by_apply_migrations(tmp_path: Path) -> None:
    """``apply_migrations`` admits ``EMPTY`` and ``BEHIND`` only; a current
    database is a mismatch and nothing is re-run or stamped."""
    database = open_test_database(tmp_path, clock=_clock())
    try:
        refused = apply_migrations(database)
        assert code(refused) == MIGRATION_MISMATCH
        assert _details(refused) == {
            "operation": "upgrade",
            "state": "CURRENT",
            "current_revision": _BASELINE,
            "expected_head": _BASELINE,
        }
        with database.read_only() as connection:
            assert check_revision(connection).state is RevisionState.CURRENT
    finally:
        database.close()


def test_a_behind_database_is_admitted_by_apply_migrations_only(
    tmp_path: Path,
) -> None:
    """C-21 ``BEHIND`` through a two-revision script directory whose second
    revision succeeds: the migrated file is ``BEHIND`` that directory, upgrades to
    its head, and is then an unsupported newer database (``UNKNOWN``, spec 23.4)
    for the packaged directory -- refused by the normal open without mutation."""
    scripts = _script_directory_with(tmp_path, "extra", _EXTRA_TABLE_REVISION_SOURCE)
    database = open_test_database(tmp_path, clock=_clock())
    try:
        with database.read_only() as connection:
            report = check_revision(connection, script_location=scripts)
            assert report.state is RevisionState.BEHIND
            assert report.current_revision == _BASELINE
            assert report.expected_head == "r0002_test_extra"
        applied = ok(apply_migrations(database, script_location=scripts))
        assert applied.state is RevisionState.CURRENT
        assert applied.current_revision == "r0002_test_extra"
        with database.read_only() as connection:
            assert "extra_table" in _user_tables(connection)
            newer = check_revision(connection)
            assert newer.state is RevisionState.UNKNOWN
            assert newer.current_revision == "r0002_test_extra"
    finally:
        database.close()
    path = tmp_path / "registry.sqlite3"
    before = file_sha256(path)
    refused = open_database(path, busy_timeout_ms=100, clock=_clock())
    assert code(refused) == MIGRATION_MISMATCH
    assert _details(refused)["state"] == "UNKNOWN"
    assert file_sha256(path) == before


def test_a_behind_database_refuses_the_normal_open_and_admits_migration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """C-21 ``BEHIND`` through the two entry points (review finding R2-01): with
    the packaged script location pointed at a two-revision directory, the
    migrated file is ``BEHIND`` -- refused by ``open_database`` without mutation
    and admitted by ``open_for_migration``, which stamps nothing on it."""
    database = open_test_database(tmp_path, clock=_clock())
    database.close()
    path = tmp_path / "registry.sqlite3"
    scripts = _script_directory_with(tmp_path, "extra", _EXTRA_TABLE_REVISION_SOURCE)
    monkeypatch.setattr(migration_runner, "_PACKAGED_SCRIPT_LOCATION", scripts)
    before = file_sha256(path)

    refused = open_database(path, busy_timeout_ms=100, clock=_clock())

    assert code(refused) == MIGRATION_MISMATCH
    assert _details(refused) == {
        "operation": "open",
        "state": "BEHIND",
        "current_revision": _BASELINE,
        "expected_head": "r0002_test_extra",
    }
    assert file_sha256(path) == before
    admitted = ok(open_for_migration(path, busy_timeout_ms=100, clock=_clock()))
    with admitted.read_only() as connection:
        assert check_revision(connection).state is RevisionState.BEHIND
    admitted.close()
    assert file_sha256(path) == before


def test_application_id_is_stamped_on_empty_and_read_back_afterwards(
    tmp_path: Path,
) -> None:
    """Plan 6.1: ``open_for_migration`` sets ``application_id`` when the state is
    ``EMPTY``, before the baseline runs; the stamp survives the migration."""
    path = tmp_path / "x.sqlite3"
    database = ok(open_for_migration(path, busy_timeout_ms=100, clock=_clock()))
    database.close()
    reader = raw_connection(path)
    try:
        assert reader.execute("PRAGMA application_id").fetchone() == (APPLICATION_ID,)
        assert reader.execute("PRAGMA journal_mode").fetchone() == ("wal",)
    finally:
        reader.close()
    database = ok(open_for_migration(path, busy_timeout_ms=100, clock=_clock()))
    ok(apply_migrations(database))
    database.close()
    reader = raw_connection(path)
    try:
        assert reader.execute("PRAGMA application_id").fetchone() == (APPLICATION_ID,)
    finally:
        reader.close()


def test_a_refused_open_releases_every_handle(tmp_path: Path) -> None:
    """A refusal by either entry point leaves no connection or file handle behind:
    the file can be renamed and removed on Windows straight afterwards."""
    database = open_test_database(tmp_path, clock=_clock())
    database.close()
    path = tmp_path / "registry.sqlite3"
    stamp_unknown_revision(path, "zz_future")

    assert code(open_database(path, busy_timeout_ms=100, clock=_clock())) == (
        MIGRATION_MISMATCH
    )
    assert code(open_for_migration(path, busy_timeout_ms=100, clock=_clock())) == (
        MIGRATION_MISMATCH
    )

    moved = path.with_name("moved.sqlite3")
    path.rename(moved)
    moved.unlink()
    assert _listing(tmp_path) == []


def test_open_test_database_migrates_once_and_reopens_a_current_file(
    tmp_path: Path,
) -> None:
    """Plan 7.1: one helper serves the first open and every reopen."""
    database = open_test_database(tmp_path, clock=_clock())
    try:
        with database.read_only() as connection:
            assert check_revision(connection).state is RevisionState.CURRENT
    finally:
        database.close()
    path = tmp_path / "registry.sqlite3"
    before = file_sha256(path)
    reopened = open_test_database(tmp_path, clock=_clock())
    try:
        with reopened.read_only() as connection:
            assert check_revision(connection).state is RevisionState.CURRENT
            assert schema_objects(connection) == EXPECTED_SCHEMA_OBJECTS
    finally:
        reopened.close()
    assert file_sha256(path) == before


# --------------------------------------------------------------------------
# The runner (plan 6.4; C-22; reading 16)
# --------------------------------------------------------------------------


def test_a_failing_revision_rolls_back_to_the_prior_revision(
    tmp_path: Path, two_revision_script_directory: Path
) -> None:
    path = tmp_path / "x.sqlite3"
    opened = ok(open_for_migration(path, busy_timeout_ms=100, clock=_clock()))
    failed = apply_migrations(opened, script_location=two_revision_script_directory)
    assert code(failed) == WRITE_FAILED
    assert _details(failed) == {
        "operation": "upgrade",
        "revision": "r0002_test_failing",
        "error_type": "RuntimeError",
    }
    with opened.read_only() as connection:
        report = check_revision(
            connection, script_location=two_revision_script_directory
        )
        assert report.state is RevisionState.BEHIND
        assert report.current_revision == _BASELINE
        assert "half_table" not in {row.name for row in schema_objects(connection)}
        assert connection.execute(text("PRAGMA quick_check")).scalar_one() == "ok"
    opened.close()


def test_apply_migrations_reports_a_current_database_after_the_upgrade(
    tmp_path: Path,
) -> None:
    """The returned report is the ``CURRENT`` one and ``foreign_key_check`` is
    empty after the upgrade."""
    path = tmp_path / "x.sqlite3"
    opened = ok(open_for_migration(path, busy_timeout_ms=100, clock=_clock()))
    try:
        report = ok(apply_migrations(opened))
        assert isinstance(report, RevisionReport)
        assert report.state is RevisionState.CURRENT
        with opened.read_only() as connection:
            assert connection.execute(text("PRAGMA foreign_key_check")).all() == []
            assert metadata_drift(connection) == ()
    finally:
        opened.close()


def test_downgrade_returns_the_database_to_empty_with_no_user_table(
    tmp_path: Path,
) -> None:
    """The baseline's ``downgrade()`` drops every trigger, index and table it
    created; the version table is emptied by Alembic and the state is ``EMPTY``."""
    database = open_test_database(tmp_path, clock=_clock())
    try:
        with database.connection() as connection:
            command.downgrade(_alembic_config(connection), "base")
        with database.read_only() as connection:
            assert _user_tables(connection) == ["alembic_version"]
            assert [row.name for row in schema_objects(connection)] == [
                "alembic_version"
            ]
            report = check_revision(connection)
            assert report.state is RevisionState.EMPTY
            assert not isinstance(report.current_revision, str)
        with database.connection() as connection:
            assert (
                connection.execute(
                    text("SELECT count(*) FROM alembic_version")
                ).scalar_one()
                == 0
            )
    finally:
        database.close()


def test_a_revision_raising_a_dbapi_error_reports_its_result_code(
    tmp_path: Path,
) -> None:
    """C-22 with a refused statement instead of a raising revision: the DBAPI
    error's result code joins the details, the revision is named and the
    database stays at the prior revision."""
    scripts = _script_directory_with(tmp_path, "dbapi", _DBAPI_FAILING_REVISION_SOURCE)
    path = tmp_path / "x.sqlite3"
    opened = ok(open_for_migration(path, busy_timeout_ms=100, clock=_clock()))
    try:
        failed = apply_migrations(opened, script_location=scripts)
        assert code(failed) == WRITE_FAILED
        assert _details(failed) == {
            "operation": "upgrade",
            "revision": "r0002_test_dbapi",
            "error_type": "OperationalError",
            "sqlite_errorcode": 1,
            "sqlite_errorname": "SQLITE_ERROR",
        }
        with opened.read_only() as connection:
            report = check_revision(connection, script_location=scripts)
            assert report.state is RevisionState.BEHIND
            assert report.current_revision == _BASELINE
    finally:
        opened.close()


def test_the_failing_revision_is_named_when_a_later_one_exists(
    tmp_path: Path, two_revision_script_directory: Path
) -> None:
    """The failing revision is found below the head: with a third revision above
    the failing second one, the report still names the second."""
    (two_revision_script_directory / "versions" / "r0003_test_third.py").write_text(
        _THIRD_REVISION_SOURCE, encoding="utf-8"
    )
    assert expected_head(script_location=two_revision_script_directory) == (
        "r0003_test_third"
    )
    path = tmp_path / "x.sqlite3"
    opened = ok(open_for_migration(path, busy_timeout_ms=100, clock=_clock()))
    try:
        failed = apply_migrations(opened, script_location=two_revision_script_directory)
        assert code(failed) == WRITE_FAILED
        assert _details(failed)["revision"] == "r0002_test_failing"
        with opened.read_only() as connection:
            report = check_revision(
                connection, script_location=two_revision_script_directory
            )
            assert report.state is RevisionState.BEHIND
            assert report.current_revision == _BASELINE
    finally:
        opened.close()


def test_a_stamp_failure_closes_the_database_and_names_the_operation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A DBAPI error while stamping ``application_id`` is returned as the
    classified failure with the result code, the engine is disposed and every
    handle is released (the file can be removed)."""
    monkeypatch.setattr(
        migration_runner,
        "_STAMP_APPLICATION_ID",
        "INSERT INTO no_such_table (x) VALUES (1)",
    )
    path = tmp_path / "x.sqlite3"

    refused = open_for_migration(path, busy_timeout_ms=100, clock=_clock())

    assert code(refused) == STORAGE_UNAVAILABLE
    assert _message(refused) == "the application identity could not be stamped"
    assert _details(refused) == {
        "operation": "stamp",
        "sqlite_errorcode": 1,
        "sqlite_errorname": "SQLITE_ERROR",
    }
    path.unlink()
    assert _listing(tmp_path) == []


def test_a_raising_stamp_propagates_after_the_engine_is_disposed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-DBAPI exception while stamping is a programmer defect: it propagates
    unchanged after the engine is disposed, so the file is removable."""

    def raising_text(statement: str) -> TextClause:
        if statement == migration_runner._STAMP_APPLICATION_ID:
            raise RuntimeError("stamp defect")
        return text(statement)

    monkeypatch.setattr(migration_runner, "text", raising_text)
    path = tmp_path / "x.sqlite3"

    with pytest.raises(RuntimeError, match="stamp defect"):
        open_for_migration(path, busy_timeout_ms=100, clock=_clock())

    path.unlink()
    assert _listing(tmp_path) == []


def test_drift_descriptions_render_every_diff_shape_on_one_line() -> None:
    """Plan 6.4: Alembic's diff entries -- tuples, nested lists for the modify
    operations, schema ``None``, names, option mappings and type objects -- are
    rendered as stable one-line descriptions."""
    describe = migration_runner._describe
    assert describe(("remove_index", Text())) == "remove_index Text"
    assert describe(("add_column", None, "datasets", "probe")) == (
        "add_column - datasets probe"
    )
    assert (
        describe(
            [
                (
                    "modify_type",
                    None,
                    "t",
                    "c",
                    {"existing_nullable": True},
                    Text(),
                    Integer(),
                )
            ]
        )
        == "modify_type - t c {existing_nullable} Text Integer"
    )
    assert describe(()) == "()"
    assert describe("odd\nentry") == "'odd\\nentry'"


def test_env_module_runs_the_migration_when_the_proxy_is_established(
    tmp_path: Path,
) -> None:
    """Reading 16, the positive half: executed while Alembic's proxy is
    established with the runner's connection in ``config.attributes``, the module
    runs the migrations. Re-executing the packaged module under its own name is
    the only way the coverage source measures that path, because Alembic loads
    ``env.py`` as a module named ``env``."""
    path = tmp_path / "x.sqlite3"
    database = ok(open_for_migration(path, busy_timeout_ms=100, clock=_clock()))
    try:
        with database.connection() as connection:
            config = _alembic_config(connection)
            script = ScriptDirectory.from_config(config)

            def upgrade(revision: str, context: MigrationContext) -> list[RevisionStep]:
                del context
                # The exact callback ``alembic.command.upgrade`` installs.
                return script._upgrade_revs("head", revision)

            with EnvironmentContext(config, script, fn=upgrade):
                module = importlib.reload(env_module)
            assert callable(module.run_migrations)
        with database.read_only() as connection:
            assert check_revision(connection).state is RevisionState.CURRENT
            assert schema_objects(connection) == EXPECTED_SCHEMA_OBJECTS
    finally:
        database.close()


def test_env_module_refuses_a_connection_attribute_of_the_wrong_type() -> None:
    config = _alembic_config("not a connection")
    script = ScriptDirectory.from_config(config)
    with (
        EnvironmentContext(config, script),
        pytest.raises(TypeError, match="SQLAlchemy connection"),
    ):
        importlib.reload(env_module)


def test_env_module_imports_without_running_a_migration() -> None:
    module = importlib.import_module("crypto_lab.persistence.migrations.env")
    assert callable(module.run_migrations)


def test_the_locked_environment_declares_no_alembic_plugin_entry_point() -> None:
    """Alembic 1.20 loads every ``alembic.plugins`` entry point when its runtime
    is imported; the locked environment declares none, so importing the runner
    executes no third-party plugin (the fresh-import layout probe answers that
    discovery with an empty selection for the same reason)."""
    assert list(importlib.metadata.entry_points(group="alembic.plugins")) == []


def test_the_alembic_proxy_is_absent_outside_a_migration_run() -> None:
    """Reading 16, the library fact ``env.py`` relies on: outside a run the proxy
    module carries no ``config`` and its proxied functions raise."""
    with pytest.raises(AttributeError):
        _ = migration_context.config
    # ``NameError`` before the first run of the process; ``AttributeError`` once a
    # run has installed and removed the proxy (``_proxy`` is then ``None``).
    with pytest.raises((NameError, AttributeError)):
        migration_context.is_offline_mode()


# --------------------------------------------------------------------------
# The migration gate (plan 6.6)
# --------------------------------------------------------------------------


def test_verify_migrations_returns_zero_and_removes_its_temporary_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The gate creates and inspects only its own temporary database and removes
    the directory afterwards; it prints nothing on success."""
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))

    assert verify_migrations_main([]) == 0

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    assert _listing(tmp_path) == []


def test_verify_migrations_refuses_any_argument(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert verify_migrations_main(["extra"]) == 1
    assert "accepts no arguments" in capsys.readouterr().err


def test_verify_migrations_fails_when_the_migrated_schema_differs(
    tmp_path: Path,
) -> None:
    """Negative controls: a script directory whose head adds a table fails the
    drift and object checks; a mutated pinned expectation fails the object
    check; the reasons name the failed checks."""
    scripts = _script_directory_with(tmp_path, "extra", _EXTRA_TABLE_REVISION_SOURCE)
    reasons = run_checks(
        tmp_path / "drift",
        script_location=scripts,
        expected_objects=EXPECTED_SCHEMA_OBJECTS,
    )
    assert any("metadata_drift" in reason for reason in reasons)
    assert any("schema_objects" in reason for reason in reasons)
    assert any("extra_table" in reason for reason in reasons)

    reasons = run_checks(
        tmp_path / "objects",
        script_location=None,
        expected_objects=EXPECTED_SCHEMA_OBJECTS[:-1],
    )
    assert len(reasons) == 1
    assert "schema_objects" in reasons[0]

    assert (
        run_checks(
            tmp_path / "clean",
            script_location=None,
            expected_objects=EXPECTED_SCHEMA_OBJECTS,
        )
        == []
    )


def test_verify_migrations_fails_on_a_failing_revision(
    tmp_path: Path, two_revision_script_directory: Path
) -> None:
    reasons = run_checks(
        tmp_path / "failing",
        script_location=two_revision_script_directory,
        expected_objects=EXPECTED_SCHEMA_OBJECTS,
    )
    assert len(reasons) == 1
    assert "apply_migrations" in reasons[0]
    assert "PERSISTENCE.WRITE_FAILED" in reasons[0]


def test_verify_migrations_imports_no_subprocess_and_reads_no_environment() -> None:
    source = (_REPOSITORY / "scripts/verify_migrations.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert "subprocess" not in imported
    assert "os" not in imported
    assert "os.environ" not in source
    assert "getenv" not in source


# --------------------------------------------------------------------------
# The section 2.6 guard expectations Task 2 trips
# --------------------------------------------------------------------------


def test_the_source_allowlist_and_import_roots_name_the_migration_modules() -> None:
    allowed = _literal(_STAGE3_GUARD, "_ALLOWED_SOURCE_FILES")
    assert _TASK2_SOURCE_PATHS <= allowed
    assert len(allowed) == 103  # Task 2 appended the six migration modules
    roots = _literal(_STAGE3_GUARD, "_ALLOWED_IMPORT_ROOTS")
    assert "alembic" in roots
    assert len(roots) == 29
    modules = _literal(_PACKAGE_LAYOUT, "PACKAGE_MODULES")
    start = modules.index("crypto_lab.persistence.diagnostics") + 1
    assert tuple(modules[start : start + len(_TASK2_MODULES)]) == _TASK2_MODULES
    assert len(modules) == 103


def test_the_two_cross_pins_moved_to_the_task_two_sizes() -> None:
    for path in (_PREFLIGHT_TESTS, _RECONCILIATION_TESTS):
        source = path.read_text(encoding="utf-8")
        assert "len(allowed) == 103" in source
        assert "len(modules) == 103" in source
    preflight = _PREFLIGHT_TESTS.read_text(encoding="utf-8")
    assert "len(roots) == 29" in preflight


def test_the_infrastructure_exemptions_are_exactly_the_nine_reviewed_pairs() -> None:
    assert _literal(_STAGE5_GUARD, "_INFRASTRUCTURE_EXEMPTIONS") == _EXPECTED_EXEMPTIONS


def test_the_launcher_and_verifier_pins_name_the_migration_check() -> None:
    """Plan 2.6 (Launcher and verifier pins): the profile is a Python-bearing
    operation with an argv row and a rejection row; the verifier step sits
    between the generated-schema check and the test suite; both scripts carry
    the clause and the step."""
    operations = _literal(_LAUNCHER_GUARD, "_PYTHON_BEARING_OPERATIONS")
    assert "migration-check" in operations
    assert list(operations) == sorted(operations)
    profiles = _literal(_STAGE3_GUARD, "_EXPECTED_VERIFICATION_PROFILES")
    assert len(profiles) == 10
    position = profiles.index(("migration-check",))
    assert profiles[position - 1] == ("schema-generate-check",)
    assert profiles[position + 1] == ("pytest-all",)
    launcher = _LAUNCHER.read_text(encoding="utf-8")
    assert launcher.count('"migration-check"') == 1
    assert 'throw "migration-check accepts no arguments"' in launcher
    assert launcher.count('"scripts\\verify_migrations.py"') == 1
    verifier = _VERIFIER.read_text(encoding="utf-8")
    steps = [
        line.split("==> ", 1)[1].rstrip('"')
        for line in verifier.splitlines()
        if "==> " in line
    ]
    assert steps.index("Check migrations") == steps.index("Check generated schemas") + 1
    assert steps.index("Run test suite") == steps.index("Check migrations") + 1
    assert len(steps) == 11
    guide = _VERIFICATION_GUIDE.read_text(encoding="utf-8")
    assert "7. launcher `migration-check`" in guide
    assert "11. direct `git diff --check`" in guide
    assert "## Migration workflow" in guide
    readme = _README.read_text(encoding="utf-8")
    assert "The eleven-operation workflow" in readme
    assert "The ten-operation workflow" not in readme


def test_no_sqlite_import_reaches_a_persistence_module() -> None:
    """Global constraint: ``sqlite3``, ``os``, ``sys``, ``time`` and the other
    denied roots appear in no persistence module; the DBAPI is reached only
    through SQLAlchemy."""
    denied = {
        "sqlite3",
        "os",
        "sys",
        "time",
        "io",
        "shutil",
        "tempfile",
        "logging",
        "threading",
        "asyncio",
        "ctypes",
        "queue",
        "subprocess",
        "types",
    }
    package = _REPOSITORY / "src/crypto_lab/persistence"
    for module in sorted(package.rglob("*.py")):
        tree = ast.parse(module.read_text(encoding="utf-8"))
        roots = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            (node.module or "").split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.level == 0
        }
        assert roots.isdisjoint(denied), (module.name, roots & denied)
