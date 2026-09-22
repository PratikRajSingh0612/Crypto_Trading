"""SQLite test support helpers for the Stage 8 persistence suites (plan 7.1).

Task 1 creates this module with exactly five helpers -- ``raw_connection``,
``file_sha256``, ``accept_any_revision``, ``ok`` and ``code`` -- and later tasks
extend it as plan section 7.1 tabulates, each helper in the task that first needs
it. ``raw_connection`` is the independent stdlib connection the concurrency cases
use for lock holders and raw statements; it is never bound to the engine under
test. ``file_sha256`` serves the no-mutation assertions of the refused opens.
``accept_any_revision`` is the accepting ``revision_policy`` the Task 1 database
probes pass to ``SqliteDatabase.open`` (written ``_accept`` in the plan's
sketches) so an unmigrated file opens. ``ok`` and ``code`` are the two ``Result``
narrowers every later task's tests use, with the same shapes as the shared
contract module's private ``_ok`` and ``_code`` helpers, which stay private and
are not imported here. The module never imports ``subprocess`` and never
launches a child.
"""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

from sqlalchemy.engine import Connection

from crypto_lab.domain.results import Failure, Result, Success

__all__ = ["accept_any_revision", "code", "file_sha256", "ok", "raw_connection"]


def raw_connection(path: Path) -> sqlite3.Connection:
    """A stdlib connection with explicit transaction control.

    ``isolation_level=None`` disables the DBAPI's implicit ``BEGIN``, so a lock
    holder issues ``BEGIN IMMEDIATE`` itself and a raw statement autocommits.
    The caller closes it in ``finally:`` (plan 7.5).
    """
    return sqlite3.connect(path, isolation_level=None)


def file_sha256(path: Path) -> str:
    """The SHA-256 hex digest of the main database file, for C-20 and C-21."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def accept_any_revision(connection: Connection) -> Result[None]:
    """The accepting revision policy: ``Success(None)`` without reading anything."""
    del connection
    return Success[None](outcome="SUCCESS", value=None)


def ok[T](result: Success[T] | Failure) -> T:
    """Narrow a ``Result`` to its ``Success`` value, failing on a ``Failure``."""
    assert isinstance(result, Success), result
    return result.value


def code(result: object) -> str:
    """Narrow a ``Result`` to the error code of its single ``Failure`` diagnostic."""
    assert isinstance(result, Failure), result
    assert len(result.diagnostics) == 1
    return result.diagnostics[0].error_code
