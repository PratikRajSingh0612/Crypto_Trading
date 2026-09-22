"""Verify the packaged Alembic baseline against a throwaway database (plan 6.6).

The ``migration-check`` launcher profile runs this script with the fixed ``-I -B``
interpreter flags and no arguments. ``main`` creates a temporary directory,
initializes and migrates ``verify.sqlite3`` inside it through
``open_for_migration`` and ``apply_migrations`` -- the same explicit initialization
path production uses, never ``metadata.create_all`` -- and asserts exactly one
head, a ``CURRENT`` revision report at that head, no metadata drift, the pinned
``sqlite_master`` objects, every plan 6.1 connection setting read back,
``quick_check`` ``ok`` and an empty ``PRAGMA foreign_key_check``; then it closes
the database and removes the directory. It inspects or creates only that
database: no ambient application database is discovered, no configuration and
no environment variable is read, no child process is launched. Exit ``0`` on
success, ``1`` with one line per failed check on standard error.

``run_checks`` is the in-process form the tests use to prove the gate can fail:
it takes the directory, an optional script location and the expected object
tuple, so a script directory whose head adds a table, a failing revision or a
mutated expectation each produce named reasons. The clock stamped into any
persistence diagnostic is a fixed instant; the script reads no clock.
"""

from __future__ import annotations

import sys
import tempfile
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from sqlalchemy import text

from crypto_lab.domain.results import Failure
from crypto_lab.domain.time import MonotonicInstant
from crypto_lab.persistence.database import APPLICATION_ID
from crypto_lab.persistence.migration_runner import (
    RevisionState,
    apply_migrations,
    check_revision,
    expected_head,
    metadata_drift,
    open_for_migration,
    schema_objects,
)
from crypto_lab.persistence.schema import EXPECTED_SCHEMA_OBJECTS, SchemaObject

#: Plan 6.1: the settings read back on the verification database's connection;
#: ``busy_timeout`` is the ``DatabaseConfig`` default the script opens with.
_BUSY_TIMEOUT_MS: Final = 5000
_EXPECTED_SETTINGS: Final[dict[str, int | str]] = {
    "journal_mode": "wal",
    "foreign_keys": 1,
    "synchronous": 2,
    "busy_timeout": _BUSY_TIMEOUT_MS,
    "application_id": APPLICATION_ID,
}
_INSTANT: Final = datetime(2026, 1, 1, tzinfo=UTC)


class _FixedClock:
    """The instant stamped into a persistence diagnostic; never the wall clock."""

    def now_utc(self) -> datetime:
        return _INSTANT

    def monotonic(self) -> MonotonicInstant:
        return MonotonicInstant(0.0)


def _reason(failure: Failure) -> str:
    (diagnostic,) = failure.diagnostics
    return f"{diagnostic.error_code}: {diagnostic.message}"


def _object_differences(
    actual: tuple[SchemaObject, ...], expected: tuple[SchemaObject, ...]
) -> list[str]:
    actual_by_key = {(row.type, row.name): row for row in actual}
    expected_by_key = {(row.type, row.name): row for row in expected}
    reasons = [
        f"schema_objects: unexpected {kind} {name}"
        for kind, name in sorted(set(actual_by_key) - set(expected_by_key))
    ]
    reasons.extend(
        f"schema_objects: missing {kind} {name}"
        for kind, name in sorted(set(expected_by_key) - set(actual_by_key))
    )
    reasons.extend(
        f"schema_objects: differs {kind} {name}"
        for kind, name in sorted(set(actual_by_key) & set(expected_by_key))
        if actual_by_key[kind, name] != expected_by_key[kind, name]
    )
    return reasons


def run_checks(
    directory: Path,
    *,
    script_location: Path | None = None,
    expected_objects: tuple[SchemaObject, ...] = EXPECTED_SCHEMA_OBJECTS,
) -> list[str]:
    """Initialize ``directory / "verify.sqlite3"`` and run every check.

    Returns one reason per failed check; an empty list is success. The caller
    owns ``directory`` (created when absent) and its removal.
    """
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "verify.sqlite3"
    try:
        head = expected_head(script_location=script_location)
    except RuntimeError as error:
        return [f"expected_head: {error}"]
    opened = open_for_migration(
        path, busy_timeout_ms=_BUSY_TIMEOUT_MS, clock=_FixedClock()
    )
    if isinstance(opened, Failure):
        return [f"open_for_migration: {_reason(opened)}"]
    database = opened.value
    reasons: list[str] = []
    try:
        applied = apply_migrations(database, script_location=script_location)
        if isinstance(applied, Failure):
            return [f"apply_migrations: {_reason(applied)}"]
        with database.read_only() as connection:
            report = check_revision(connection, script_location=script_location)
            if (
                report.state is not RevisionState.CURRENT
                or report.current_revision != head
            ):
                reasons.append(
                    f"check_revision: state {report.state.value}, revision "
                    f"{report.current_revision!r}, expected head {head}"
                )
            reasons.extend(
                f"metadata_drift: {line}" for line in metadata_drift(connection)
            )
            reasons.extend(
                _object_differences(schema_objects(connection), expected_objects)
            )
            for setting, expected in _EXPECTED_SETTINGS.items():
                actual = connection.execute(text(f"PRAGMA {setting}")).scalar_one()
                if actual != expected:
                    reasons.append(
                        f"pragma {setting}: {actual!r} instead of {expected!r}"
                    )
            verdicts = [
                str(value)
                for value in connection.execute(text("PRAGMA quick_check")).scalars()
            ]
            if verdicts != ["ok"]:
                reasons.append(f"quick_check: {'; '.join(verdicts)}")
            violations = connection.execute(text("PRAGMA foreign_key_check")).all()
            if violations:
                reasons.append(f"foreign_key_check: {len(violations)} violation(s)")
    finally:
        database.close()
    return reasons


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments:
        print("verify_migrations accepts no arguments", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory(prefix="crypto-lab-migration-check-") as tmp:
        reasons = run_checks(Path(tmp))
    for reason in reasons:
        print(reason, file=sys.stderr)
    return 1 if reasons else 0


if __name__ == "__main__":
    sys.exit(main())
