"""The bounded, rotated JSON Lines log writer.

Specification 30.1 and Stage 9 plan 4.8 under reading 15: core logs are JSON
Lines of the versioned ``LogRecord`` schema, local, bounded and rotated
deterministically. ``JsonLinesLogWriter.open(logs_root, retained_files, clock)``
appends canonical ``LogRecord`` lines to ``core-00000.jsonl`` under the explicit
root the caller supplies (no configuration, environment, current-directory or
home-directory read anywhere in this package), rotates by renaming the active
file to the next zero-padded archive index when the compiled ``LOG_FILE_BYTES``
ceiling would be exceeded, refuses a line that alone exceeds the ceiling before
rotating or writing anything, and deletes the oldest archives beyond
``retained_files`` (the active file is additional). Redaction runs before
serialization, so a record that bypassed validation still cannot put a
token-shaped value or a denylisted key's value on disk.

The filesystem is touched only inside ``open``, ``write`` and ``close``: the
module body defines and compiles, nothing more. ``pathlib`` is the only
filesystem surface. ``Path.rename`` is the one move primitive: on Windows it
refuses an existing target, so an archive index is never overwritten and the
writer picks the next free one; the active handle is flushed and closed before
the rename (Windows refuses to rename an open file) and a fresh active file is
opened afterwards. Every I/O failure is a ``Result`` failure carrying one
``AUDIT.LOG_WRITE_FAILED`` diagnostic (category ``PERSISTENCE``, not retriable)
whose identity is a function of its content, the artifacts factory pattern;
the writer stays usable afterwards whenever the active file could be reopened.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import BinaryIO, Final, cast

from pydantic import JsonValue

from crypto_lab.audit.models import LogRecord
from crypto_lab.audit.redaction import REDACTED, contains_token_shape, redact_details
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.diagnostics import (
    Diagnostic,
    DiagnosticCategory,
    DiagnosticSeverity,
)
from crypto_lab.domain.hashing import HashingProfile, _uuid4_shaped, profile_hash
from crypto_lab.domain.ports import Clock
from crypto_lab.domain.results import Failure, Result, Success

#: Reading 15: the compiled byte ceiling of one log file; not a configuration key.
LOG_FILE_BYTES: Final = 8 * 1024 * 1024
#: ``LoggingConfig.retained_files`` is 1 through 100 (``configuration/models.py``).
MAX_RETAINED_FILES: Final = 100
AUDIT_LOG_WRITE_FAILED: Final = "AUDIT.LOG_WRITE_FAILED"
AUDIT_SOURCE_COMPONENT: Final = "core.audit"
_ACTIVE_INDEX: Final = 0
_MAX_ARCHIVE_INDEX: Final = 99_999
_SEEK_END: Final = 2
_MAX_MESSAGE_CHARACTERS: Final = 1024
_LOG_FILE_NAME: Final = re.compile(r"core-([0-9]{5})\.jsonl")


def _log_file_name(index: int) -> str:
    return f"core-{index:05d}.jsonl"


def log_write_failure(message: str, *, now_utc: datetime) -> Failure:
    """A ``Failure`` carrying one ``AUDIT.LOG_WRITE_FAILED`` diagnostic.

    Identity is ``DIAGNOSTIC_IDENTITY_V1`` over the content excluding the clock
    instant, so the same failure recomputes the same identity.
    """
    bounded = message[:_MAX_MESSAGE_CHARACTERS] or "log write failed"
    payload: dict[str, JsonValue] = {
        "schema_version": "1.0.0",
        "error_code": AUDIT_LOG_WRITE_FAILED,
        "category": DiagnosticCategory.PERSISTENCE.value,
        "severity": DiagnosticSeverity.ERROR.value,
        "source_component": AUDIT_SOURCE_COMPONENT,
        "message": bounded,
        "retriable": False,
        "details": cast("JsonValue", {}),
        "causal_diagnostic_ids": [],
    }
    identity = _uuid4_shaped(
        profile_hash(HashingProfile.DIAGNOSTIC_IDENTITY_V1, payload)
    )
    diagnostic = Diagnostic.model_validate(
        {
            "schema_version": "1.0.0",
            "diagnostic_id": f"diag_{identity}",
            "severity": DiagnosticSeverity.ERROR,
            "error_code": AUDIT_LOG_WRITE_FAILED,
            "category": DiagnosticCategory.PERSISTENCE,
            "message": bounded,
            "source_component": AUDIT_SOURCE_COMPONENT,
            "retriable": False,
            "timestamp_utc": now_utc,
            "details": {},
            "causal_diagnostic_ids": (),
        }
    )
    return Failure(outcome="FAILURE", diagnostics=(diagnostic,))


def _render_line(record: LogRecord) -> bytes:
    """Redact, then serialize one canonical JSON line (with its newline)."""
    if not isinstance(record, LogRecord):
        raise TypeError("a log line renders a LogRecord")
    details = redact_details(record.details)
    message = REDACTED if contains_token_shape(record.message) else record.message
    document = record.model_dump(mode="json")
    document["details"] = details
    document["message"] = message
    return canonical_json_bytes(document) + b"\n"


def _archive_indexes(root: Path) -> list[int]:
    indexes: list[int] = []
    for path in root.iterdir():
        matched = _LOG_FILE_NAME.fullmatch(path.name)
        if matched is not None and int(matched.group(1)) != _ACTIVE_INDEX:
            indexes.append(int(matched.group(1)))
    return sorted(indexes)


class JsonLinesLogWriter:
    """The bounded, rotated JSON Lines writer over one explicit root.

    Construct through ``open``; ``write`` appends one record; ``close`` releases
    the active handle and is idempotent.
    """

    __slots__ = (
        "_active_bytes",
        "_clock",
        "_file_bytes",
        "_handle",
        "_next_index",
        "_retained_files",
        "_root",
    )

    def __init__(
        self,
        *,
        root: Path,
        retained_files: int,
        clock: Clock,
        file_bytes: int,
        handle: BinaryIO,
        active_bytes: int,
        next_index: int,
    ) -> None:
        self._root = root
        self._retained_files = retained_files
        self._clock = clock
        self._file_bytes = file_bytes
        self._handle: BinaryIO | None = handle
        self._active_bytes = active_bytes
        self._next_index = next_index

    @classmethod
    def open(
        cls,
        logs_root: Path,
        *,
        retained_files: int,
        clock: Clock,
        file_bytes: int = LOG_FILE_BYTES,
    ) -> Result[JsonLinesLogWriter]:
        """Create the root if absent (its parent must exist), open the active
        file for appending and resume the archive index; a caller's argument
        error is raised, an I/O failure is a ``Failure``."""
        if not isinstance(logs_root, Path):
            raise TypeError("logs_root must be a pathlib.Path")
        if not logs_root.is_absolute():
            raise ValueError("logs_root must be an absolute path")
        if type(retained_files) is not int:
            raise TypeError("retained_files must be an int")
        if not 1 <= retained_files <= MAX_RETAINED_FILES:
            raise ValueError(f"retained_files must be 1 through {MAX_RETAINED_FILES}")
        if type(file_bytes) is not int:
            raise TypeError("file_bytes must be an int")
        if not 1 <= file_bytes <= LOG_FILE_BYTES:
            raise ValueError(f"file_bytes must be 1 through {LOG_FILE_BYTES}")
        try:
            logs_root.mkdir(exist_ok=True)
            indexes = _archive_indexes(logs_root)
            handle = (logs_root / _log_file_name(_ACTIVE_INDEX)).open("ab")
        except OSError as error:
            return log_write_failure(
                f"log root could not be opened: {error}", now_utc=clock.now_utc()
            )
        try:
            active_bytes = handle.seek(0, _SEEK_END)
        except OSError as error:
            handle.close()
            return log_write_failure(
                f"active log file could not be measured: {error}",
                now_utc=clock.now_utc(),
            )
        writer = cls(
            root=logs_root,
            retained_files=retained_files,
            clock=clock,
            file_bytes=file_bytes,
            handle=handle,
            active_bytes=active_bytes,
            next_index=(indexes[-1] if indexes else _ACTIVE_INDEX) + 1,
        )
        return Success(outcome="SUCCESS", value=writer)

    @property
    def file_bytes(self) -> int:
        return self._file_bytes

    @property
    def retained_files(self) -> int:
        return self._retained_files

    def write(self, record: LogRecord) -> Result[None]:
        """Append one redacted canonical line, rotating first when it would
        exceed the ceiling; a line that alone exceeds the ceiling is refused
        before any rotation; every failure is a ``Failure`` and writes nothing."""
        if self._handle is None:
            return log_write_failure(
                "log writer is closed", now_utc=self._clock.now_utc()
            )
        try:
            line = _render_line(record)
        except (TypeError, ValueError) as error:
            return log_write_failure(
                f"log record could not be rendered: {type(error).__name__}",
                now_utc=self._clock.now_utc(),
            )
        if len(line) > self._file_bytes:
            return log_write_failure(
                f"log line of {len(line)} bytes exceeds the {self._file_bytes}"
                " byte file ceiling",
                now_utc=self._clock.now_utc(),
            )
        try:
            if (
                self._active_bytes > 0
                and self._active_bytes + len(line) > self._file_bytes
            ):
                self._rotate()
            active = self._handle
            if active is None:  # pragma: no cover - _rotate reopens or raises
                raise OSError("log writer has no open file")
            active.write(line)
            active.flush()
        except OSError as error:
            return log_write_failure(
                f"log line could not be written: {error}",
                now_utc=self._clock.now_utc(),
            )
        self._active_bytes += len(line)
        return Success(outcome="SUCCESS", value=None)

    def close(self) -> None:
        """Release the active handle; idempotent."""
        handle = self._handle
        if handle is not None:
            self._handle = None
            handle.close()

    def _rotate(self) -> None:
        handle = self._handle
        if handle is None:  # pragma: no cover - write checks the handle first
            raise OSError("log writer is closed")
        handle.flush()
        handle.close()
        self._handle = None
        active = self._root / _log_file_name(_ACTIVE_INDEX)
        try:
            self._rename_to_next_archive(active)
        finally:
            reopened = active.open("ab")
            self._handle = reopened
            self._active_bytes = reopened.seek(0, _SEEK_END)
        self._prune_archives()

    def _rename_to_next_archive(self, active: Path) -> None:
        while True:
            if self._next_index > _MAX_ARCHIVE_INDEX:
                raise OSError("log archive index space is exhausted")
            target = self._root / _log_file_name(self._next_index)
            try:
                active.rename(target)
            except FileExistsError:
                self._next_index += 1
                continue
            self._next_index += 1
            return

    def _prune_archives(self) -> None:
        archives = _archive_indexes(self._root)
        excess = len(archives) - self._retained_files
        for index in archives[: max(excess, 0)]:
            (self._root / _log_file_name(index)).unlink()


__all__ = (
    "AUDIT_LOG_WRITE_FAILED",
    "AUDIT_SOURCE_COMPONENT",
    "LOG_FILE_BYTES",
    "MAX_RETAINED_FILES",
    "JsonLinesLogWriter",
    "log_write_failure",
)
