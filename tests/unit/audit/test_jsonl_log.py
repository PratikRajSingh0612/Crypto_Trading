"""Stage 9 Task 2: the bounded, rotated JSON Lines log writer (plan 4.8 and
reading 15 under specification 30.1; R30.1-01, R30.1-03).

The writer appends canonical ``LogRecord`` lines to ``core-00000.jsonl`` under
an explicit root, renames the active file to the next zero-padded archive
index when the compiled ceiling would be exceeded, keeps at most
``retained_files`` archives, redacts before serialization, refuses a line that
alone exceeds the ceiling before rotating or writing anything, and answers
every I/O failure with a ``Result`` failure. The ceiling is injected small here
so rotation and refusal are observable; the compiled value stays 8 MiB.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

import crypto_lab.audit.jsonl as jsonl_module
from crypto_lab.audit.jsonl import (
    AUDIT_LOG_WRITE_FAILED,
    AUDIT_SOURCE_COMPONENT,
    LOG_FILE_BYTES,
    JsonLinesLogWriter,
)
from crypto_lab.audit.models import LogRecord
from crypto_lab.audit.redaction import REDACTED
from crypto_lab.audit.sink import LogSink
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.diagnostics import DiagnosticCategory, DiagnosticSeverity
from crypto_lab.domain.results import Failure, Success
from doubles.artifacts import sample_log_record
from doubles.experiments import INSTANT, FixedClock

_ACTIVE = "core-00000.jsonl"
_TOKEN = "T" * 40


def _record(ordinal: int) -> LogRecord:
    return sample_log_record(details={"ordinal": ordinal})


def _open(
    root: Path, *, retained_files: int = 2, file_bytes: int | None = None
) -> JsonLinesLogWriter:
    clock = FixedClock(INSTANT)
    if file_bytes is None:
        opened = JsonLinesLogWriter.open(
            root, retained_files=retained_files, clock=clock
        )
    else:
        opened = JsonLinesLogWriter.open(
            root, retained_files=retained_files, clock=clock, file_bytes=file_bytes
        )
    assert isinstance(opened, Success), opened
    return opened.value


def _line_bytes(tmp_path: Path) -> int:
    """The exact byte length of one ``_record`` line, measured, not assumed."""
    probe = _open(tmp_path / "probe")
    assert isinstance(probe.write(_record(0)), Success)
    probe.close()
    return (tmp_path / "probe" / _ACTIVE).stat().st_size


def _ordinals(path: Path) -> list[object]:
    raw = path.read_bytes()
    assert raw == b"" or raw.endswith(b"\n")
    return [
        LogRecord.model_validate_json(line).details["ordinal"]
        for line in raw.split(b"\n")
        if line
    ]


def _names(root: Path) -> list[str]:
    return sorted(path.name for path in root.iterdir())


def test_record_schema_rotation_and_retention(tmp_path: Path) -> None:
    line_bytes = _line_bytes(tmp_path)
    root = tmp_path / "logs"
    writer = _open(root, retained_files=2, file_bytes=2 * line_bytes)
    assert writer.file_bytes == 2 * line_bytes
    assert writer.retained_files == 2
    for ordinal in range(9):
        assert isinstance(writer.write(_record(ordinal)), Success)
    writer.close()
    # Two lines per file; rotations at writes 3, 5, 7 and 9 produced archives
    # 1-4; retention kept the two newest and deleted 1 and 2 in that order.
    assert _names(root) == [_ACTIVE, "core-00003.jsonl", "core-00004.jsonl"]
    assert _ordinals(root / "core-00003.jsonl") == [4, 5]
    assert _ordinals(root / "core-00004.jsonl") == [6, 7]
    assert _ordinals(root / _ACTIVE) == [8]
    for path in root.iterdir():
        assert path.stat().st_size <= 2 * line_bytes
    # Every surviving line is a canonical LogRecord (the versioned log schema).
    for path in root.iterdir():
        for line in path.read_bytes().split(b"\n"):
            if line:
                record = LogRecord.model_validate_json(line)
                assert canonical_json_bytes(record) == line
    # Reopening the same root resumes the active file and the archive index.
    resumed = _open(root, retained_files=2, file_bytes=2 * line_bytes)
    assert isinstance(resumed.write(_record(9)), Success)
    assert isinstance(resumed.write(_record(10)), Success)
    resumed.close()
    assert _names(root) == [_ACTIVE, "core-00004.jsonl", "core-00005.jsonl"]
    assert _ordinals(root / "core-00005.jsonl") == [8, 9]
    assert _ordinals(root / _ACTIVE) == [10]
    # The compiled ceiling is the default and the only admitted maximum.
    assert LOG_FILE_BYTES == 8 * 1024 * 1024
    assert _open(tmp_path / "default").file_bytes == LOG_FILE_BYTES


def test_rotation_rename_on_windows(tmp_path: Path) -> None:
    """A rename over an existing archive index is refused by ``Path.rename`` on
    Windows, so the writer picks the next index and the planted file survives."""
    assert sys.platform == "win32"
    line_bytes = _line_bytes(tmp_path)
    root = tmp_path / "logs"
    writer = _open(root, retained_files=5, file_bytes=line_bytes)
    assert isinstance(writer.write(_record(0)), Success)
    planted = root / "core-00001.jsonl"
    planted.write_bytes(b"planted\n")
    assert isinstance(writer.write(_record(1)), Success)
    assert planted.read_bytes() == b"planted\n"
    assert _ordinals(root / "core-00002.jsonl") == [0]
    assert _ordinals(root / _ACTIVE) == [1]
    assert isinstance(writer.write(_record(2)), Success)
    assert _names(root) == [
        _ACTIVE,
        "core-00001.jsonl",
        "core-00002.jsonl",
        "core-00003.jsonl",
    ]
    assert _ordinals(root / "core-00003.jsonl") == [1]
    writer.close()


def test_redaction_before_serialization(tmp_path: Path) -> None:
    """A record that bypassed validation still cannot put a token-shaped value
    or a denylisted key's value on disk."""
    root = tmp_path / "logs"
    writer = _open(root)
    leaking = sample_log_record().model_copy(
        update={
            "details": {"leak": _TOKEN, "nested": [{"inner": f"x {_TOKEN}"}]},
            "message": f"token {_TOKEN}",
        }
    )
    assert isinstance(writer.write(leaking), Success)
    secret_keyed = sample_log_record().model_copy(
        update={"details": {"api_key": "plain", "ok": "kept"}}
    )
    assert isinstance(writer.write(secret_keyed), Success)
    writer.close()
    raw = (root / _ACTIVE).read_bytes()
    assert _TOKEN.encode() not in raw
    assert b"plain" not in raw
    first, second, trailing = raw.split(b"\n")
    assert trailing == b""
    redacted = LogRecord.model_validate_json(first)
    assert redacted.details == {"leak": REDACTED, "nested": [{"inner": REDACTED}]}
    assert redacted.message == REDACTED
    assert redacted.event_code == "ARTIFACT.VALIDATED"
    assert b'"api_key":"[REDACTED]"' in second
    assert b'"ok":"kept"' in second


def test_open_creates_nothing_at_import(tmp_path: Path) -> None:
    """The module body only defines; the directory and the active file exist
    after ``open`` and nowhere else; a missing parent is a failure, not a tree."""
    source_path = Path(str(jsonl_module.__file__))
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    module_level_calls = [
        ast.unparse(node.func)
        for statement in tree.body
        if not isinstance(statement, ast.FunctionDef | ast.ClassDef)
        for node in ast.walk(statement)
        if isinstance(node, ast.Call)
    ]
    assert set(module_level_calls) <= {"re.compile"}
    roots = {
        (node.module or "").partition(".")[0]
        if isinstance(node, ast.ImportFrom)
        else alias.name.partition(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import | ast.ImportFrom)
        for alias in node.names
    }
    assert roots <= {
        "__future__",
        "collections",
        "datetime",
        "pathlib",
        "re",
        "typing",
        "pydantic",
        "crypto_lab",
    }
    assert roots.isdisjoint(
        {"os", "io", "shutil", "tempfile", "errno", "logging", "time", "json"}
    )
    root = tmp_path / "logs"
    assert not root.exists()
    writer = _open(root)
    assert _names(root) == [_ACTIVE]
    assert (root / _ACTIVE).stat().st_size == 0
    writer.close()
    missing = tmp_path / "absent" / "logs"
    opened = JsonLinesLogWriter.open(
        missing, retained_files=2, clock=FixedClock(INSTANT)
    )
    assert isinstance(opened, Failure)
    assert not (tmp_path / "absent").exists()


def test_write_failure_is_a_result(tmp_path: Path) -> None:
    clock = FixedClock(INSTANT)
    blocker = tmp_path / "logs"
    blocker.write_bytes(b"")
    opened = JsonLinesLogWriter.open(blocker, retained_files=2, clock=clock)
    assert isinstance(opened, Failure)
    (diagnostic,) = opened.diagnostics
    assert diagnostic.error_code == AUDIT_LOG_WRITE_FAILED == "AUDIT.LOG_WRITE_FAILED"
    assert diagnostic.category is DiagnosticCategory.PERSISTENCE
    assert diagnostic.severity is DiagnosticSeverity.ERROR
    assert diagnostic.retriable is False
    assert diagnostic.source_component == AUDIT_SOURCE_COMPONENT == "core.audit"
    assert diagnostic.timestamp_utc == INSTANT
    assert diagnostic.details == {}
    assert diagnostic.causal_diagnostic_ids == ()
    # Writing after close is a failure, and close is idempotent.
    writer = _open(tmp_path / "closed")
    writer.close()
    writer.close()
    failed = writer.write(sample_log_record())
    assert isinstance(failed, Failure)
    assert failed.diagnostics[0].error_code == AUDIT_LOG_WRITE_FAILED
    assert "closed" in failed.diagnostics[0].message
    # A record that cannot be rendered is a failure and writes nothing.
    writer = _open(tmp_path / "render")
    unrenderable = sample_log_record().model_copy(update={"details": {"ratio": 0.5}})
    assert isinstance(writer.write(unrenderable), Failure)
    assert (tmp_path / "render" / _ACTIVE).stat().st_size == 0
    not_a_record = writer.write("not a record")  # type: ignore[arg-type]
    assert isinstance(not_a_record, Failure)
    assert not_a_record.diagnostics[0].message.endswith("TypeError")
    assert (tmp_path / "render" / _ACTIVE).stat().st_size == 0
    assert isinstance(writer.write(sample_log_record()), Success)
    writer.close()
    # A rotation refused by the filesystem (the active file held open by another
    # handle) is a failure; the pending line is not written and the writer stays
    # usable once the handle is released.
    line_bytes = _line_bytes(tmp_path)
    root = tmp_path / "held"
    writer = _open(root, retained_files=2, file_bytes=line_bytes)
    assert isinstance(writer.write(_record(0)), Success)
    with (root / _ACTIVE).open("rb") as held:
        refused = writer.write(_record(1))
        assert isinstance(refused, Failure)
        assert refused.diagnostics[0].error_code == AUDIT_LOG_WRITE_FAILED
        assert held.read() == (root / _ACTIVE).read_bytes()
    assert _ordinals(root / _ACTIVE) == [0]
    assert isinstance(writer.write(_record(1)), Success)
    assert _ordinals(root / "core-00001.jsonl") == [0]
    assert _ordinals(root / _ACTIVE) == [1]
    writer.close()


def test_an_exhausted_archive_index_space_is_a_write_failure(tmp_path: Path) -> None:
    """Reading 15: the archive index space is finite. Past ``core-99999.jsonl``
    a rotation is refused as a ``Failure``; nothing is renamed, the pending line
    is not written and the active file keeps its content."""
    line_bytes = _line_bytes(tmp_path)
    root = tmp_path / "logs"
    root.mkdir()
    last = root / "core-99999.jsonl"
    last.write_bytes(b"last\n")
    writer = _open(root, retained_files=2, file_bytes=line_bytes)
    assert isinstance(writer.write(_record(0)), Success)
    refused = writer.write(_record(1))
    assert isinstance(refused, Failure)
    assert refused.diagnostics[0].error_code == AUDIT_LOG_WRITE_FAILED
    assert "exhausted" in refused.diagnostics[0].message
    assert _names(root) == [_ACTIVE, "core-99999.jsonl"]
    assert _ordinals(root / _ACTIVE) == [0]
    assert last.read_bytes() == b"last\n"
    writer.close()


def test_an_oversized_line_is_refused_on_an_empty_active_file(tmp_path: Path) -> None:
    """A serialized line (newline included) that alone exceeds ``file_bytes`` is
    refused before anything is rotated or written: the empty active file stays
    empty, no archive appears, no file ever exceeds the ceiling, the record is
    untouched and the writer keeps working for a line that fits."""
    line_bytes = _line_bytes(tmp_path)
    root = tmp_path / "logs"
    writer = _open(root, retained_files=2, file_bytes=line_bytes - 1)
    record = _record(0)
    before = record.model_copy()
    refused = writer.write(record)
    assert isinstance(refused, Failure)
    (diagnostic,) = refused.diagnostics
    assert diagnostic.error_code == AUDIT_LOG_WRITE_FAILED
    assert "exceeds" in diagnostic.message
    assert record == before
    assert _names(root) == [_ACTIVE]
    assert (root / _ACTIVE).read_bytes() == b""
    # A record without details renders shorter than ``_record`` and still fits.
    assert isinstance(writer.write(sample_log_record(details={})), Success)
    writer.close()
    assert _names(root) == [_ACTIVE]
    for path in root.iterdir():
        assert 0 < path.stat().st_size <= line_bytes - 1


def test_an_oversized_line_is_refused_without_rotating(tmp_path: Path) -> None:
    """With content in the active file and an archive already present, the
    oversized line is refused before the rotation it would otherwise trigger:
    every existing file keeps its name and bytes, nothing oversized is created,
    and the next fitting line rotates and is written as usual."""
    line_bytes = _line_bytes(tmp_path)
    root = tmp_path / "logs"
    writer = _open(root, retained_files=2, file_bytes=line_bytes)
    assert isinstance(writer.write(_record(0)), Success)
    assert isinstance(writer.write(_record(1)), Success)
    assert _names(root) == [_ACTIVE, "core-00001.jsonl"]
    snapshot = {path.name: path.read_bytes() for path in root.iterdir()}
    oversized = sample_log_record(details={"ordinal": 2, "pad": "p"})
    before = oversized.model_copy()
    refused = writer.write(oversized)
    assert isinstance(refused, Failure)
    (diagnostic,) = refused.diagnostics
    assert diagnostic.error_code == AUDIT_LOG_WRITE_FAILED
    assert "exceeds" in diagnostic.message
    assert oversized == before
    assert {path.name: path.read_bytes() for path in root.iterdir()} == snapshot
    assert isinstance(writer.write(_record(2)), Success)
    writer.close()
    assert _names(root) == [_ACTIVE, "core-00001.jsonl", "core-00002.jsonl"]
    assert _ordinals(root / "core-00001.jsonl") == [0]
    assert _ordinals(root / "core-00002.jsonl") == [1]
    assert _ordinals(root / _ACTIVE) == [2]
    for path in root.iterdir():
        assert path.stat().st_size <= line_bytes


def test_a_line_exactly_at_the_ceiling_is_written(tmp_path: Path) -> None:
    """The boundary is inclusive: a line whose byte length equals ``file_bytes``
    fills an empty active file exactly, and a second such line rotates and then
    fills the fresh active file exactly."""
    line_bytes = _line_bytes(tmp_path)
    root = tmp_path / "logs"
    writer = _open(root, retained_files=2, file_bytes=line_bytes)
    assert isinstance(writer.write(_record(0)), Success)
    assert _names(root) == [_ACTIVE]
    assert (root / _ACTIVE).stat().st_size == line_bytes
    assert isinstance(writer.write(_record(1)), Success)
    writer.close()
    assert _names(root) == [_ACTIVE, "core-00001.jsonl"]
    assert (root / "core-00001.jsonl").stat().st_size == line_bytes
    assert (root / _ACTIVE).stat().st_size == line_bytes
    assert _ordinals(root / "core-00001.jsonl") == [0]
    assert _ordinals(root / _ACTIVE) == [1]


def test_an_active_file_that_cannot_be_measured_is_an_open_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The size probe after the append-open sits inside the I/O boundary: its
    failure is a ``Failure`` and the handle that refused it is closed."""

    class _Unmeasurable:
        closed = False

        def seek(self, offset: int, whence: int = 0) -> int:
            raise OSError("seek refused")

        def close(self) -> None:
            self.closed = True

    handle = _Unmeasurable()
    monkeypatch.setattr(Path, "open", lambda *args, **kwargs: handle)
    opened = JsonLinesLogWriter.open(
        tmp_path / "logs", retained_files=2, clock=FixedClock(INSTANT)
    )
    assert isinstance(opened, Failure)
    assert opened.diagnostics[0].error_code == AUDIT_LOG_WRITE_FAILED
    assert "measured" in opened.diagnostics[0].message
    assert handle.closed
    assert _names(tmp_path / "logs") == []


def test_open_validates_its_explicit_inputs(tmp_path: Path) -> None:
    clock = FixedClock(INSTANT)
    with_root = tmp_path / "logs"
    for retained in (0, -1, 101):
        with pytest.raises(ValueError, match="retained_files"):
            JsonLinesLogWriter.open(with_root, retained_files=retained, clock=clock)
    for ceiling in (0, LOG_FILE_BYTES + 1):
        with pytest.raises(ValueError, match="file_bytes"):
            JsonLinesLogWriter.open(
                with_root, retained_files=2, clock=clock, file_bytes=ceiling
            )
    with pytest.raises(ValueError, match="absolute"):
        JsonLinesLogWriter.open(Path("relative/logs"), retained_files=2, clock=clock)
    with pytest.raises(TypeError, match="retained_files"):
        JsonLinesLogWriter.open(with_root, retained_files=True, clock=clock)
    with pytest.raises(TypeError, match="file_bytes"):
        JsonLinesLogWriter.open(
            with_root, retained_files=2, clock=clock, file_bytes=True
        )
    with pytest.raises(TypeError, match="Path"):
        JsonLinesLogWriter.open(str(with_root), retained_files=2, clock=clock)  # type: ignore[arg-type]
    assert not with_root.exists()
    writer = _open(with_root)
    assert isinstance(writer, LogSink)
    writer.close()
