"""The section 5.2 normalized container, its checksums and the raw checksum.

The expected bytes are built on the test side from the fixture definitions
(hand-written literals for the small series, a plain loop over the fixture's
arithmetic for the sixty-row fixtures) and hashed with ``hashlib`` here, so the
container's bytes, its SHA-256 checksums, its line count and ``row_count`` are
pinned independently of the implementation. The writer is also pinned on its
file-system behaviour and on its boundary: it returns
``Success[NormalizedContainer]`` or the ``OFFLINE_DATA.OUTPUT_DIRECTORY``
refusal (line ``0``, value length ``0``, the path never recorded); it creates
the caller's destination exclusively, inspects the destination's own entry
without following it so that an existing entry (a dangling reparse point
included, whose target is then never created) is refused before the create,
never creates a directory, refuses a reparse-point directory before it
opens anything, removes the partial file it created when the write fails,
still refuses when that removal fails, and is repeatable across two fresh
directories. No ``OSError`` and no path ``ValueError`` escapes it;
``ProviderContractError`` (reading R7) is the one exception that does.
``raw_checksum`` is pinned against a test-side digest of the fixture bytes,
the reader's byte ceiling and the reader's input-path refusals.
"""

from __future__ import annotations

import _winapi
import errno
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import IO, Any

import pytest
from crypto_lab.domain.diagnostics import (
    Diagnostic,
    DiagnosticCategory,
    DiagnosticSeverity,
)
from crypto_lab.domain.results import Failure, Success

from crypto_lab_offline_data.candle_csv import (
    DEFAULT_MAX_BYTES,
    WHOLE_INPUT_LINE,
    CandleRow,
    read_ohlcv_csv,
)
from crypto_lab_offline_data.diagnostics import (
    SOURCE_COMPONENT,
    ProviderContractError,
    RefusalCode,
)
from crypto_lab_offline_data.normalize import (
    COLUMN_SCHEMA_VERSION,
    CONTAINER_FORMAT,
    NormalizedContainer,
    RawChecksum,
    raw_checksum,
    write_normalized_container,
)
from crypto_lab_offline_data.providers import Clock, IdProvider
from crypto_lab_offline_data.validation import ValidatedSeries, validate_series

START = datetime(2024, 1, 1, tzinfo=UTC)
FIXTURE_ROW_COUNT = 60
CLEAN_BYTE_COUNT = 3821
GAPS_DUPLICATES_FIXTURE = "btcusdt-1m-gaps-duplicates.valid.csv"
GAPS_DUPLICATES_MINUTES = (
    *range(20),
    *range(23, 30),
    30,
    30,
    *range(31, 45),
    45,
    45,
    *range(46, 61),
)
DIFFERING_DUPLICATE_MINUTE = 45
DIFFERING_CLOSE = "42000.56"
DIFFERING_VOLUME = "145.6"
SHA256_HEX = re.compile(r"[0-9a-f]{64}")
CANONICAL_NUMBER = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?")
UTC_TEXT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
KEY_ORDER = ["close", "high", "low", "open", "open_time_utc", "volume"]
SMALL_SERIES_BYTES = (
    b'{"close":"42000.5","high":"42001.1","low":"41999","open":"42000",'
    b'"open_time_utc":"2024-01-01T00:00:00Z","volume":"0.5"}\n'
    b'{"close":"42000.5","high":"42000.5","low":"42000.5","open":"42000.5",'
    b'"open_time_utc":"2024-01-01T00:01:00Z","volume":"0"}\n'
)
MALFORMED_DIAGNOSTIC_ID = "diag_not-a-canonical-uuid4"
NAIVE_INSTANT = datetime(2026, 1, 2, 3, 4, 5)  # noqa: DTZ001
PARTIAL_PREFIX_LENGTH = 16


def _bar(
    open_time: datetime,
    *,
    line: int,
    open_price: str = "42000",
    high: str = "42001",
    low: str = "41999",
    close: str = "42000.5",
    volume: str = "100",
) -> CandleRow:
    return CandleRow(
        open_time_utc=open_time,
        open=Decimal(open_price),
        high=Decimal(high),
        low=Decimal(low),
        close=Decimal(close),
        volume=Decimal(volume),
        line=line,
    )


def _validated_rows(
    rows: tuple[CandleRow, ...], ids: IdProvider, clock: Clock
) -> ValidatedSeries:
    result = validate_series(rows, timeframe="1m", ids=ids, clock=clock)
    assert isinstance(result, Success)
    return result.value


def _validated_fixture(path: Path, ids: IdProvider, clock: Clock) -> ValidatedSeries:
    read = read_ohlcv_csv(path, ids=ids, clock=clock)
    assert isinstance(read, Success)
    return _validated_rows(read.value, ids, clock)


def _one_row_series(ids: IdProvider, clock: Clock) -> ValidatedSeries:
    return _validated_rows((_bar(START, line=2),), ids, clock)


def _canonical(text: str) -> str:
    """Test-side canonical form: drop trailing zeros after a point, then the point."""
    if "." not in text:
        return text
    return text.rstrip("0").rstrip(".")


def _line(
    open_time: str,
    *,
    open_price: str,
    high: str,
    low: str,
    close: str,
    volume: str,
) -> bytes:
    fields = (
        ("close", _canonical(close)),
        ("high", _canonical(high)),
        ("low", _canonical(low)),
        ("open", _canonical(open_price)),
        ("open_time_utc", open_time),
        ("volume", _canonical(volume)),
    )
    body = ",".join(f'"{key}":"{value}"' for key, value in fields)
    return f"{{{body}}}\n".encode("ascii")


def _fixture_fields(minute: int) -> dict[str, str]:
    """The fixture arithmetic: minute ``m`` is ``42000.mm`` and friends."""
    open_time = (START + timedelta(minutes=minute)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "open_time": open_time,
        "open_price": f"42000.{minute:02d}",
        "high": f"42001.{minute:02d}",
        "low": f"41999.{minute:02d}",
        "close": f"42000.5{minute % 10}",
        "volume": f"1{minute:02d}.{minute % 10}",
    }


def _expected_clean_lines() -> list[bytes]:
    return [_line(**_fixture_fields(minute)) for minute in range(FIXTURE_ROW_COUNT)]


def _expected_gaps_duplicates_lines() -> list[bytes]:
    lines: list[bytes] = []
    seen_differing = False
    for minute in GAPS_DUPLICATES_MINUTES:
        fields = _fixture_fields(minute)
        if minute == DIFFERING_DUPLICATE_MINUTE:
            if seen_differing:
                fields["close"] = DIFFERING_CLOSE
                fields["volume"] = DIFFERING_VOLUME
            seen_differing = True
        lines.append(_line(**fields))
    return lines


def _single_refusal(
    result: Success[Any] | Failure,
    code: RefusalCode,
    *,
    line: int,
    value_length: int,
    ids: IdProvider,
    clock: Clock,
) -> Diagnostic:
    """Assert one section 5.4 diagnostic and return it for further checks."""
    assert isinstance(result, Failure)
    assert len(result.diagnostics) == 1
    diagnostic = result.diagnostics[0]
    assert diagnostic.error_code == code.value
    assert diagnostic.details == {
        "line": line,
        "rule": code.value,
        "value_length": value_length,
    }
    assert diagnostic.severity is DiagnosticSeverity.ERROR
    assert diagnostic.category is DiagnosticCategory.SCHEMA_VALIDATION
    assert diagnostic.source_component == SOURCE_COMPONENT
    assert diagnostic.retriable is False
    assert diagnostic.diagnostic_id == ids.diagnostic_id()
    assert diagnostic.timestamp_utc == clock.now_utc()
    assert diagnostic.causal_diagnostic_ids == ()
    assert str(line) in diagnostic.message
    assert code.value in diagnostic.message
    return diagnostic


def _assert_value_absent(diagnostic: Diagnostic, value: str) -> None:
    serialized = json.dumps(diagnostic.model_dump(mode="json"))
    assert value not in serialized


def _assert_path_absent(diagnostic: Diagnostic, path: Path) -> None:
    _assert_value_absent(diagnostic, str(path))
    _assert_value_absent(diagnostic, path.as_posix())
    _assert_value_absent(diagnostic, path.name)


def _output_directory_refusal(
    result: Success[Any] | Failure,
    path: Path,
    *,
    ids: IdProvider,
    clock: Clock,
) -> Diagnostic:
    """Assert the whole-input ``OUTPUT_DIRECTORY`` refusal that never names ``path``."""
    diagnostic = _single_refusal(
        result,
        RefusalCode.OUTPUT_DIRECTORY,
        line=WHOLE_INPUT_LINE,
        value_length=0,
        ids=ids,
        clock=clock,
    )
    _assert_path_absent(diagnostic, path)
    return diagnostic


def _container(result: Success[NormalizedContainer] | Failure) -> NormalizedContainer:
    assert isinstance(result, Success)
    assert result.outcome == "SUCCESS"
    assert isinstance(result.value, NormalizedContainer)
    return result.value


def _written(
    series: ValidatedSeries, destination: Path, ids: IdProvider, clock: Clock
) -> NormalizedContainer:
    return _container(
        write_normalized_container(series, destination, ids=ids, clock=clock)
    )


def _snapshot(directory: Path) -> tuple[tuple[str, int], ...]:
    """Names and sizes of a directory's entries; directories carry size -1."""
    entries: list[tuple[str, int]] = []
    for entry in sorted(directory.iterdir()):
        size = entry.stat().st_size if entry.is_file() else -1
        entries.append((entry.name, size))
    return tuple(entries)


def _assert_container_matches(
    container: NormalizedContainer, destination: Path, expected: bytes
) -> None:
    data = destination.read_bytes()
    assert data == expected
    digest = hashlib.sha256(expected).hexdigest()
    assert container.content_hash == digest
    assert container.normalized_checksum == digest
    assert container.bytes_written == len(expected)
    assert container.bytes_written == destination.stat().st_size
    assert container.row_count == expected.count(b"\n")
    assert data.endswith(b"\n")
    assert b"\r" not in data


class _CountingIds:
    """An ``IdProvider`` that counts the draws of each method."""

    def __init__(self) -> None:
        self.calls = {"dataset_id": 0, "partition_id": 0, "diagnostic_id": 0}

    def dataset_id(self) -> str:
        self.calls["dataset_id"] += 1
        return "ds_8b2d4f6a-1c3e-4a5b-b7d9-0e2f4a6c8b1d"

    def partition_id(self) -> str:
        self.calls["partition_id"] += 1
        return "part_8b2d4f6a-1c3e-4a5b-b7d9-0e2f4a6c8b1d"

    def diagnostic_id(self) -> str:
        self.calls["diagnostic_id"] += 1
        return "diag_8b2d4f6a-1c3e-4a5b-b7d9-0e2f4a6c8b1d"


class _CountingClock:
    """A ``Clock`` that counts its draws."""

    def __init__(self) -> None:
        self.calls = 0

    def now_utc(self) -> datetime:
        self.calls += 1
        return datetime(2031, 12, 31, 23, 59, 59, tzinfo=UTC)


class _MalformedIds:
    """An ``IdProvider`` whose ``diag_`` value the core refuses (reading R7)."""

    def dataset_id(self) -> str:
        return "ds_0f8c2a4e-6b3d-4f1a-9c7e-2d5b8a1f3c6e"

    def partition_id(self) -> str:
        return "part_7a1d3e5f-9b2c-4d6e-8f1a-3c5e7b9d1f2a"

    def diagnostic_id(self) -> str:
        return MALFORMED_DIAGNOSTIC_ID


class _NaiveClock:
    """A ``Clock`` whose instant the core refuses (reading R7)."""

    def now_utc(self) -> datetime:
        return NAIVE_INSTANT


def _spy_on_exclusive_open(patch: pytest.MonkeyPatch) -> list[Path]:
    """Record every path opened through ``Path.open``; only ``"xb"`` is expected."""
    opened: list[Path] = []
    real_open = Path.open

    def spying_open(self: Path, mode: str = "r") -> Any:
        assert mode == "xb"
        opened.append(self)
        return real_open(self, "xb")

    patch.setattr(Path, "open", spying_open)
    return opened


def _record_unlinks(patch: pytest.MonkeyPatch, *, fail: bool = False) -> list[Path]:
    """Record every ``Path.unlink`` call; with ``fail`` each one raises instead."""
    unlinked: list[Path] = []
    real_unlink = Path.unlink

    def recording_unlink(self: Path, missing_ok: bool = False) -> None:
        unlinked.append(self)
        if fail:
            raise PermissionError(errno.EACCES, "injected removal failure")
        real_unlink(self, missing_ok)

    patch.setattr(Path, "unlink", recording_unlink)
    return unlinked


class _FailingHandle:
    """A handle over a real exclusively created file that fails after a prefix.

    ``write`` puts ``PARTIAL_PREFIX_LENGTH`` bytes on disk, records the file's
    size as seen on disk and then fails, either there or at the close that
    ends the ``with`` block. The inner handle is always closed before the
    failure propagates: on Windows an open handle would make the writer's
    removal fail for a reason the test does not mean to exercise.
    """

    def __init__(
        self, inner: IO[bytes], path: Path, observed: list[int], *, at_close: bool
    ) -> None:
        self._inner = inner
        self._path = path
        self._observed = observed
        self._at_close = at_close

    def __enter__(self) -> _FailingHandle:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._inner.close()
        if self._at_close and exc_info[0] is None:
            raise OSError(errno.EIO, "injected close failure")

    def write(self, data: bytes) -> int:
        self._inner.write(data[:PARTIAL_PREFIX_LENGTH])
        self._inner.flush()
        self._observed.append(self._path.stat().st_size)
        if self._at_close:
            return PARTIAL_PREFIX_LENGTH
        raise OSError(errno.ENOSPC, "injected write failure")


def _fail_the_write(patch: pytest.MonkeyPatch, *, at_close: bool) -> list[int]:
    """Make the writer's exclusive create succeed and its write fail mid-way."""
    observed: list[int] = []
    real_open = Path.open

    def failing_open(self: Path, mode: str = "r") -> _FailingHandle:
        assert mode == "xb"
        return _FailingHandle(real_open(self, "xb"), self, observed, at_close=at_close)

    patch.setattr(Path, "open", failing_open)
    return observed


def _dangling_junction(tmp_path: Path) -> tuple[Path, Path, Path]:
    """An output directory, a dangling junction in it and its missing target.

    ``_winapi.CreateJunction`` needs an existing directory as its target, so
    the target is created, linked and then removed: the junction's own entry
    stays and points at nothing. The target sits beside the output directory,
    not inside it, so a create that followed the junction would land outside
    the directory the caller named. Returns ``(output, link, target)``.
    """
    output = tmp_path / "output"
    output.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "target"
    target.mkdir()
    link = output / "part-0000.ndjson"
    _winapi.CreateJunction(str(target), str(link))
    target.rmdir()
    assert link.is_junction()
    assert not link.exists()
    assert _snapshot(outside) == ()
    return output, link, target


# --- the container bytes and checksums -------------------------------------


def test_a_small_series_writes_exactly_the_expected_canonical_bytes(
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    rows = (
        _bar(
            START,
            line=2,
            open_price="42000.00",
            high="42001.10",
            low="41999",
            close="42000.50",
            volume="0.50",
        ),
        _bar(
            START + timedelta(minutes=1),
            line=3,
            open_price="42000.5",
            high="42000.5",
            low="42000.5",
            close="42000.5",
            volume="0",
        ),
    )
    series = _validated_rows(rows, fixed_ids, fixed_clock)
    destination = tmp_path / "part-0000.ndjson"

    result = write_normalized_container(
        series, destination, ids=fixed_ids, clock=fixed_clock
    )

    assert isinstance(result, Success)
    assert result.outcome == "SUCCESS"
    container = result.value
    assert isinstance(container, NormalizedContainer)
    _assert_container_matches(container, destination, SMALL_SERIES_BYTES)
    assert container.row_count == 2
    assert SMALL_SERIES_BYTES.count(b"\n") == 2
    assert b"42000.00" not in destination.read_bytes()
    assert b"0.50" not in destination.read_bytes()


def test_the_clean_fixture_container_matches_the_independently_built_bytes(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    series = _validated_fixture(clean_fixture, fixed_ids, fixed_clock)
    expected_lines = _expected_clean_lines()
    expected = b"".join(expected_lines)
    destination = tmp_path / "part-0000.ndjson"

    container = _written(series, destination, fixed_ids, fixed_clock)

    _assert_container_matches(container, destination, expected)
    assert container.row_count == FIXTURE_ROW_COUNT
    assert container.row_count == series.row_count
    assert len(expected_lines) == FIXTURE_ROW_COUNT
    assert expected_lines[0] == (
        b'{"close":"42000.5","high":"42001","low":"41999","open":"42000",'
        b'"open_time_utc":"2024-01-01T00:00:00Z","volume":"100"}\n'
    )
    assert expected_lines[59] == (
        b'{"close":"42000.59","high":"42001.59","low":"41999.59","open":"42000.59",'
        b'"open_time_utc":"2024-01-01T00:59:00Z","volume":"159.9"}\n'
    )


def test_the_gaps_duplicates_container_keeps_every_duplicate_row(
    tmp_path: Path,
    candles_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    series = _validated_fixture(
        candles_root / GAPS_DUPLICATES_FIXTURE, fixed_ids, fixed_clock
    )
    expected_lines = _expected_gaps_duplicates_lines()
    expected = b"".join(expected_lines)
    destination = tmp_path / "part-0000.ndjson"

    container = _written(series, destination, fixed_ids, fixed_clock)

    _assert_container_matches(container, destination, expected)
    assert container.row_count == FIXTURE_ROW_COUNT
    assert len(GAPS_DUPLICATES_MINUTES) == FIXTURE_ROW_COUNT
    lines = destination.read_bytes().split(b"\n")[:-1]
    assert len(lines) == FIXTURE_ROW_COUNT
    identical = [line for line in lines if b'"2024-01-01T00:30:00Z"' in line]
    assert len(identical) == 2
    assert identical[0] == identical[1]
    differing = [line for line in lines if b'"2024-01-01T00:45:00Z"' in line]
    assert len(differing) == 2
    assert differing[0] != differing[1]
    assert b'"close":"42000.56"' in differing[1]
    assert b'"volume":"145.6"' in differing[1]
    assert not any(b'"2024-01-01T00:21:00Z"' in line for line in lines)
    assert b'"open_time_utc":"2024-01-01T01:00:00Z"' in lines[-1]


def test_every_line_is_one_json_object_of_six_string_fields_in_key_order(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    series = _validated_fixture(clean_fixture, fixed_ids, fixed_clock)
    destination = tmp_path / "part-0000.ndjson"

    _written(series, destination, fixed_ids, fixed_clock)

    text = destination.read_bytes().decode("ascii")
    lines = text.split("\n")
    assert lines[-1] == ""
    for line in lines[:-1]:
        record = json.loads(line)
        assert list(record) == KEY_ORDER
        assert all(isinstance(value, str) for value in record.values())
        assert UTC_TEXT.fullmatch(record["open_time_utc"]) is not None
        for key in ("open", "high", "low", "close", "volume"):
            assert CANONICAL_NUMBER.fullmatch(record[key]) is not None, key
        assert " " not in line


def test_writing_the_same_series_into_two_fresh_directories_is_repeatable(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    first_series = _validated_fixture(clean_fixture, fixed_ids, fixed_clock)
    second_series = _validated_fixture(clean_fixture, fixed_ids, fixed_clock)
    first_directory = tmp_path / "first"
    second_directory = tmp_path / "second"
    first_directory.mkdir()
    second_directory.mkdir()
    first_path = first_directory / "part-0000.ndjson"
    second_path = second_directory / "part-0000.ndjson"

    first = _written(first_series, first_path, fixed_ids, fixed_clock)
    second = _written(second_series, second_path, fixed_ids, fixed_clock)

    assert first == second
    assert first_path.read_bytes() == second_path.read_bytes()
    assert hashlib.sha256(first_path.read_bytes()).hexdigest() == first.content_hash
    assert _snapshot(first_directory) == _snapshot(second_directory)
    assert _snapshot(first_directory) == (("part-0000.ndjson", first.bytes_written),)


def test_checksums_are_one_lowercase_sha256_of_the_container(
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    series = _one_row_series(fixed_ids, fixed_clock)
    destination = tmp_path / "part-0000.ndjson"

    container = _written(series, destination, fixed_ids, fixed_clock)

    assert SHA256_HEX.fullmatch(container.content_hash) is not None
    assert container.content_hash == container.normalized_checksum
    written = destination.read_bytes()
    assert container.content_hash == hashlib.sha256(written).hexdigest()
    assert container.row_count == 1
    assert container.bytes_written == len(destination.read_bytes())


# --- the writer's refusals: existing targets --------------------------------


def test_the_writer_refuses_an_existing_file_and_leaves_it_untouched(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """An existing destination is the refusal: never opened, overwritten or removed."""
    series = _one_row_series(fixed_ids, fixed_clock)
    destination = tmp_path / "part-0000.ndjson"
    destination.write_bytes(b"sentinel\n")
    before = _snapshot(tmp_path)

    with monkeypatch.context() as patch:
        opened = _spy_on_exclusive_open(patch)
        unlinked = _record_unlinks(patch)
        result = write_normalized_container(
            series, destination, ids=fixed_ids, clock=fixed_clock
        )

    _output_directory_refusal(result, destination, ids=fixed_ids, clock=fixed_clock)
    assert opened == []
    assert unlinked == []
    assert destination.read_bytes() == b"sentinel\n"
    assert _snapshot(tmp_path) == before == (("part-0000.ndjson", 9),)


def test_the_writer_refuses_a_directory_destination(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    series = _one_row_series(fixed_ids, fixed_clock)
    destination = tmp_path / "directory"
    destination.mkdir()
    before = _snapshot(tmp_path)

    with monkeypatch.context() as patch:
        opened = _spy_on_exclusive_open(patch)
        result = write_normalized_container(
            series, destination, ids=fixed_ids, clock=fixed_clock
        )

    _output_directory_refusal(result, destination, ids=fixed_ids, clock=fixed_clock)
    assert opened == []
    assert destination.is_dir()
    assert list(destination.iterdir()) == []
    assert _snapshot(tmp_path) == before == (("directory", -1),)


def test_the_writer_refuses_a_reparse_point_destination_without_following_it(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """A junction at the destination is an existing entry: refused, never followed."""
    series = _one_row_series(fixed_ids, fixed_clock)
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "part-0000.ndjson"
    _winapi.CreateJunction(str(target), str(link))
    try:
        before = _snapshot(tmp_path)
        with monkeypatch.context() as patch:
            opened = _spy_on_exclusive_open(patch)
            result = write_normalized_container(
                series, link, ids=fixed_ids, clock=fixed_clock
            )
        after = _snapshot(tmp_path)
        inside_target = list(target.iterdir())
    finally:
        link.rmdir()

    _output_directory_refusal(result, link, ids=fixed_ids, clock=fixed_clock)
    assert opened == []
    assert inside_target == []
    assert after == before == (("part-0000.ndjson", -1), ("target", -1))
    assert not link.exists()
    assert target.is_dir()


def test_the_writer_refuses_a_dangling_reparse_point_destination_unfollowed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """A dangling junction at the destination is an existing entry: refused.

    Its target is missing and lies outside the output directory. An exclusive
    create that followed the entry would create that target, so the entry is
    refused on its own attributes before anything is opened: the junction
    stays, still dangling, and no file appears anywhere.
    """
    series = _one_row_series(fixed_ids, fixed_clock)
    output, link, target = _dangling_junction(tmp_path)
    outside = target.parent
    before = (_snapshot(output), _snapshot(outside))
    try:
        with monkeypatch.context() as patch:
            opened = _spy_on_exclusive_open(patch)
            unlinked = _record_unlinks(patch)
            result = write_normalized_container(
                series, link, ids=fixed_ids, clock=fixed_clock
            )
        after = (_snapshot(output), _snapshot(outside))
        still_junction = link.is_junction()
        still_dangling = not link.exists()
        target_created = target.exists() or target.is_symlink()
    finally:
        link.rmdir()

    _output_directory_refusal(result, link, ids=fixed_ids, clock=fixed_clock)
    assert opened == []
    assert unlinked == []
    assert after == before == ((("part-0000.ndjson", -1),), ())
    assert still_junction
    assert still_dangling
    assert not target_created
    assert _snapshot(outside) == ()


def test_the_destination_entry_is_inspected_before_the_exclusive_create(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """The entry at the destination is refused by inspection, not by the create.

    The injected create stands in for the platform's reparse of a dangling
    entry: called on the junction, it creates the junction's target outside
    the output directory. The writer must never reach it, whatever the
    platform would do with the real create.
    """
    series = _one_row_series(fixed_ids, fixed_clock)
    output, link, target = _dangling_junction(tmp_path)
    outside = target.parent
    opened: list[Path] = []
    real_open = Path.open

    def following_open(self: Path, mode: str = "r") -> Any:
        assert mode == "xb"
        opened.append(self)
        return real_open(target, "xb")

    try:
        with monkeypatch.context() as patch:
            patch.setattr(Path, "open", following_open)
            unlinked = _record_unlinks(patch)
            result = write_normalized_container(
                series, link, ids=fixed_ids, clock=fixed_clock
            )
        outside_entries = _snapshot(outside)
        output_entries = _snapshot(output)
        still_junction = link.is_junction()
    finally:
        link.rmdir()

    _output_directory_refusal(result, link, ids=fixed_ids, clock=fixed_clock)
    assert opened == []
    assert unlinked == []
    assert outside_entries == ()
    assert output_entries == (("part-0000.ndjson", -1),)
    assert still_junction
    assert not target.exists()


def test_a_failing_destination_inspection_is_the_refusal_with_nothing_opened(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """Only the platform's "no such entry" answer lets the create proceed.

    An inspection of the destination's own entry that fails for any other
    reason is the refusal: nothing is opened, nothing is owned, nothing is
    removed, and the path never enters the diagnostic. The directory's own
    inspection passes through untouched, so the fault is scoped to the entry.
    """
    series = _one_row_series(fixed_ids, fixed_clock)
    destination = tmp_path / "part-0000.ndjson"
    inspected: list[Path] = []
    real_lstat = Path.lstat

    def failing_lstat(self: Path) -> Any:
        inspected.append(self)
        if self == destination:
            raise PermissionError(errno.EACCES, "injected inspection failure")
        return real_lstat(self)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "lstat", failing_lstat)
        opened = _spy_on_exclusive_open(patch)
        unlinked = _record_unlinks(patch)
        result = write_normalized_container(
            series, destination, ids=fixed_ids, clock=fixed_clock
        )

    _output_directory_refusal(result, destination, ids=fixed_ids, clock=fixed_clock)
    assert inspected == [tmp_path, destination]
    assert opened == []
    assert unlinked == []
    assert list(tmp_path.iterdir()) == []


# --- the writer's refusals: the destination's directory ---------------------


def test_the_writer_refuses_a_missing_directory_and_creates_nothing(
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    series = _one_row_series(fixed_ids, fixed_clock)
    destination = tmp_path / "absent" / "part-0000.ndjson"

    result = write_normalized_container(
        series, destination, ids=fixed_ids, clock=fixed_clock
    )

    _output_directory_refusal(result, destination, ids=fixed_ids, clock=fixed_clock)
    assert not (tmp_path / "absent").exists()
    assert list(tmp_path.iterdir()) == []


def test_the_writer_refuses_a_directory_that_is_a_file(
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    series = _one_row_series(fixed_ids, fixed_clock)
    blocker = tmp_path / "blocker"
    blocker.write_bytes(b"not a directory\n")
    destination = blocker / "part-0000.ndjson"

    result = write_normalized_container(
        series, destination, ids=fixed_ids, clock=fixed_clock
    )

    _output_directory_refusal(result, destination, ids=fixed_ids, clock=fixed_clock)
    assert blocker.read_bytes() == b"not a directory\n"
    assert _snapshot(tmp_path) == (("blocker", 16),)


def test_the_writer_refuses_a_reparse_point_directory_before_it_opens_anything(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """A junction as the destination's directory is refused on its own attributes.

    Nothing is opened for the refused write. The control mirrors the reader's
    rule: a regular directory reached through a junction in an ancestor is not
    itself a reparse point, so a destination inside it is written.
    """
    series = _one_row_series(fixed_ids, fixed_clock)
    target = tmp_path / "target"
    target.mkdir()
    (target / "sub").mkdir()
    link = tmp_path / "link"
    _winapi.CreateJunction(str(target), str(link))
    refused_destination = link / "part-0000.ndjson"
    control_destination = link / "sub" / "part-0000.ndjson"
    try:
        with monkeypatch.context() as patch:
            opened = _spy_on_exclusive_open(patch)
            refused = write_normalized_container(
                series, refused_destination, ids=fixed_ids, clock=fixed_clock
            )
            control = write_normalized_container(
                series, control_destination, ids=fixed_ids, clock=fixed_clock
            )
        target_entries = _snapshot(target)
    finally:
        link.rmdir()

    assert opened == [control_destination]
    _output_directory_refusal(
        refused, refused_destination, ids=fixed_ids, clock=fixed_clock
    )
    container = _container(control)
    assert target_entries == (("sub", -1),)
    assert _snapshot(target / "sub") == (("part-0000.ndjson", container.bytes_written),)
    assert not (target / "part-0000.ndjson").exists()


def test_the_writer_refuses_an_unwritable_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """A denied exclusive create is the refusal; nothing was owned, nothing removed."""
    series = _one_row_series(fixed_ids, fixed_clock)
    destination = tmp_path / "part-0000.ndjson"

    def denied_open(self: Path, mode: str = "r") -> Any:
        assert mode == "xb"
        raise PermissionError(errno.EACCES, "injected unwritable directory")

    with monkeypatch.context() as patch:
        patch.setattr(Path, "open", denied_open)
        unlinked = _record_unlinks(patch)
        result = write_normalized_container(
            series, destination, ids=fixed_ids, clock=fixed_clock
        )

    _output_directory_refusal(result, destination, ids=fixed_ids, clock=fixed_clock)
    assert unlinked == []
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "relative",
    ["embedded\x00nul.ndjson", "embedded\x00nul/part-0000.ndjson"],
    ids=["in-the-name", "in-the-directory"],
)
def test_a_destination_the_platform_rejects_is_refused_not_a_value_error(
    relative: str,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """An embedded NUL raises ``ValueError`` from the path operations; it converts.

    The raw path cannot appear in JSON (its NUL is escaped), so the
    discriminating checks are its JSON-escaped spelling and its NUL-free parent.
    """
    series = _one_row_series(fixed_ids, fixed_clock)
    destination = tmp_path / relative
    assert "\x00" in str(destination)

    result = write_normalized_container(
        series, destination, ids=fixed_ids, clock=fixed_clock
    )

    diagnostic = _output_directory_refusal(
        result, destination, ids=fixed_ids, clock=fixed_clock
    )
    _assert_value_absent(diagnostic, json.dumps(str(destination))[1:-1])
    _assert_value_absent(diagnostic, tmp_path.name)
    assert list(tmp_path.iterdir()) == []


# --- the writer's refusals: a write that fails after the create -------------


@pytest.mark.parametrize("at_close", [False, True], ids=["at-write", "at-close"])
def test_a_write_that_fails_mid_way_leaves_no_partial_file(
    at_close: bool,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """The partial file the writer created is removed; the refusal is returned."""
    series = _validated_fixture(clean_fixture, fixed_ids, fixed_clock)
    destination = tmp_path / "part-0000.ndjson"

    with monkeypatch.context() as patch:
        observed = _fail_the_write(patch, at_close=at_close)
        unlinked = _record_unlinks(patch)
        result = write_normalized_container(
            series, destination, ids=fixed_ids, clock=fixed_clock
        )

    _output_directory_refusal(result, destination, ids=fixed_ids, clock=fixed_clock)
    assert observed == [PARTIAL_PREFIX_LENGTH]
    assert unlinked == [destination]
    assert not destination.exists()
    assert list(tmp_path.iterdir()) == []


def test_a_failed_removal_of_the_partial_file_is_still_the_refusal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """When the cleanup itself fails nothing crosses: the refusal is returned."""
    series = _validated_fixture(clean_fixture, fixed_ids, fixed_clock)
    expected = b"".join(_expected_clean_lines())
    destination = tmp_path / "part-0000.ndjson"

    with monkeypatch.context() as patch:
        observed = _fail_the_write(patch, at_close=False)
        unlinked = _record_unlinks(patch, fail=True)
        result = write_normalized_container(
            series, destination, ids=fixed_ids, clock=fixed_clock
        )

    _output_directory_refusal(result, destination, ids=fixed_ids, clock=fixed_clock)
    assert observed == [PARTIAL_PREFIX_LENGTH]
    assert unlinked == [destination]
    assert destination.read_bytes() == expected[:PARTIAL_PREFIX_LENGTH]


def test_the_writer_opens_the_destination_once_in_exclusive_create_mode(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    series = _one_row_series(fixed_ids, fixed_clock)
    destination = tmp_path / "part-0000.ndjson"
    opened: list[tuple[Path, tuple[Any, ...], dict[str, Any]]] = []
    real_open = Path.open

    def spying_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        opened.append((self, args, kwargs))
        return real_open(self, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "open", spying_open)
        unlinked = _record_unlinks(patch)
        result = write_normalized_container(
            series, destination, ids=fixed_ids, clock=fixed_clock
        )

    _container(result)
    assert opened == [(destination, ("xb",), {})]
    assert unlinked == []


# --- the writer's provider contract (R7) ------------------------------------


def test_the_writer_draws_no_provider_value_when_it_writes(
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    series = _one_row_series(fixed_ids, fixed_clock)
    ids = _CountingIds()
    clock = _CountingClock()

    counted = write_normalized_container(
        series, tmp_path / "counted.ndjson", ids=ids, clock=clock
    )
    faulty = write_normalized_container(
        series, tmp_path / "faulty.ndjson", ids=_MalformedIds(), clock=_NaiveClock()
    )

    assert _container(counted) == _container(faulty)
    assert ids.calls == {"dataset_id": 0, "partition_id": 0, "diagnostic_id": 0}
    assert clock.calls == 0


def test_the_writer_draws_each_provider_value_exactly_once_on_a_refusal(
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    series = _one_row_series(fixed_ids, fixed_clock)
    destination = tmp_path / "part-0000.ndjson"
    destination.write_bytes(b"sentinel\n")
    ids = _CountingIds()
    clock = _CountingClock()

    result = write_normalized_container(series, destination, ids=ids, clock=clock)

    assert ids.calls == {"dataset_id": 0, "partition_id": 0, "diagnostic_id": 1}
    assert clock.calls == 1
    _output_directory_refusal(result, destination, ids=ids, clock=clock)
    assert destination.read_bytes() == b"sentinel\n"


def test_the_writer_raises_the_contract_error_for_a_malformed_id(
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    series = _one_row_series(fixed_ids, fixed_clock)
    destination = tmp_path / "part-0000.ndjson"
    destination.write_bytes(b"sentinel\n")

    with pytest.raises(RuntimeError) as info:
        write_normalized_container(
            series, destination, ids=_MalformedIds(), clock=fixed_clock
        )

    error = info.value
    assert type(error) is ProviderContractError
    assert error.method == "diagnostic_id"
    assert error.__cause__ is None
    assert MALFORMED_DIAGNOSTIC_ID not in str(error)
    assert destination.read_bytes() == b"sentinel\n"


def test_the_writer_raises_the_contract_error_for_a_naive_instant(
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    series = _one_row_series(fixed_ids, fixed_clock)
    destination = tmp_path / "absent" / "part-0000.ndjson"

    with pytest.raises(RuntimeError) as info:
        write_normalized_container(
            series, destination, ids=fixed_ids, clock=_NaiveClock()
        )

    error = info.value
    assert type(error) is ProviderContractError
    assert error.method == "now_utc"
    assert str(NAIVE_INSTANT) not in str(error)
    assert list(tmp_path.iterdir()) == []


def test_a_partial_file_is_removed_before_a_provider_fault_is_raised(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """The cleanup precedes the provider draw, so a fault never leaves a partial."""
    series = _validated_fixture(clean_fixture, fixed_ids, fixed_clock)
    destination = tmp_path / "part-0000.ndjson"

    with monkeypatch.context() as patch:
        observed = _fail_the_write(patch, at_close=False)
        with pytest.raises(ProviderContractError) as info:
            write_normalized_container(
                series, destination, ids=_MalformedIds(), clock=fixed_clock
            )

    assert info.value.method == "diagnostic_id"
    assert observed == [PARTIAL_PREFIX_LENGTH]
    assert not destination.exists()
    assert list(tmp_path.iterdir()) == []


# --- constants and value types ----------------------------------------------


def test_container_constants_are_pinned_and_never_name_the_production_format() -> None:
    assert COLUMN_SCHEMA_VERSION == "0.1.0"
    assert CONTAINER_FORMAT == "normalized-ndjson/0.1.0"
    assert "parquet" not in CONTAINER_FORMAT.lower()
    assert "parquet" not in COLUMN_SCHEMA_VERSION.lower()


def test_normalized_container_is_frozen() -> None:
    container = NormalizedContainer(
        bytes_written=1,
        content_hash="0" * 64,
        normalized_checksum="0" * 64,
        row_count=1,
    )

    with pytest.raises(AttributeError):
        container.row_count = 2  # type: ignore[misc]


# --- the raw checksum --------------------------------------------------------


class _SpyReadHandle:
    """A binary handle wrapper that records every size passed to ``read``."""

    def __init__(self, inner: IO[bytes], sizes: list[int]) -> None:
        self._inner = inner
        self._sizes = sizes

    def __enter__(self) -> _SpyReadHandle:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._inner.close()

    def read(self, size: int = -1) -> bytes:
        self._sizes.append(size)
        return self._inner.read(size)


def _spy_on_read_open(patch: pytest.MonkeyPatch) -> tuple[list[Path], list[int]]:
    """Record every path opened through ``Path.open`` and every read size."""
    opened: list[Path] = []
    sizes: list[int] = []
    real_open = Path.open

    def spying_open(self: Path, mode: str = "r") -> _SpyReadHandle:
        assert mode == "rb"
        opened.append(self)
        return _SpyReadHandle(real_open(self, "rb"), sizes)

    patch.setattr(Path, "open", spying_open)
    return opened, sizes


class _FailingReadHandle:
    """A binary handle whose bounded read fails and whose closes are recorded."""

    def __init__(self, closed: list[bool]) -> None:
        self._closed = closed

    def __enter__(self) -> _FailingReadHandle:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._closed.append(True)

    def read(self, size: int = -1) -> bytes:
        raise OSError(errno.EIO, "injected read failure")


def _checksum(result: Success[RawChecksum] | Failure) -> RawChecksum:
    assert isinstance(result, Success)
    assert result.outcome == "SUCCESS"
    assert isinstance(result.value, RawChecksum)
    return result.value


def _input_path_refusal(
    result: Success[Any] | Failure,
    path: Path,
    *,
    ids: IdProvider,
    clock: Clock,
) -> Diagnostic:
    """Assert the whole-input ``INPUT_PATH`` refusal that never names ``path``."""
    diagnostic = _single_refusal(
        result,
        RefusalCode.INPUT_PATH,
        line=WHOLE_INPUT_LINE,
        value_length=0,
        ids=ids,
        clock=clock,
    )
    _assert_path_absent(diagnostic, path)
    return diagnostic


def test_raw_checksum_of_the_clean_fixture_is_the_digest_of_its_exact_bytes(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """The raw digest covers the input's exact digits, which the container loses."""
    data = clean_fixture.read_bytes()
    assert len(data) == CLEAN_BYTE_COUNT
    assert b"42000.00" in data
    series = _validated_fixture(clean_fixture, fixed_ids, fixed_clock)
    container = _written(series, tmp_path / "part-0000.ndjson", fixed_ids, fixed_clock)

    result = raw_checksum(
        clean_fixture, max_bytes=DEFAULT_MAX_BYTES, ids=fixed_ids, clock=fixed_clock
    )

    checksum = _checksum(result)
    assert checksum.sha256 == hashlib.sha256(data).hexdigest()
    assert SHA256_HEX.fullmatch(checksum.sha256) is not None
    assert checksum.byte_count == CLEAN_BYTE_COUNT
    assert checksum.sha256 != container.content_hash
    assert checksum.byte_count != container.bytes_written
    assert b"42000.00" not in (tmp_path / "part-0000.ndjson").read_bytes()


def test_raw_checksums_of_the_two_fixtures_differ_at_an_equal_byte_count(
    candles_root: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    gaps_duplicates = candles_root / GAPS_DUPLICATES_FIXTURE

    clean = _checksum(
        raw_checksum(
            clean_fixture, max_bytes=DEFAULT_MAX_BYTES, ids=fixed_ids, clock=fixed_clock
        )
    )
    other = _checksum(
        raw_checksum(
            gaps_duplicates,
            max_bytes=DEFAULT_MAX_BYTES,
            ids=fixed_ids,
            clock=fixed_clock,
        )
    )

    assert clean.byte_count == other.byte_count == CLEAN_BYTE_COUNT
    assert clean.sha256 != other.sha256
    assert other.sha256 == hashlib.sha256(gaps_duplicates.read_bytes()).hexdigest()


def test_raw_checksum_is_repeatable(
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    first = raw_checksum(
        clean_fixture, max_bytes=DEFAULT_MAX_BYTES, ids=fixed_ids, clock=fixed_clock
    )
    second = raw_checksum(
        clean_fixture, max_bytes=CLEAN_BYTE_COUNT, ids=fixed_ids, clock=fixed_clock
    )

    assert _checksum(first) == _checksum(second)


def test_raw_checksum_at_and_over_the_byte_ceiling(
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """At the ceiling the bytes are hashed; one byte over is the reader's refusal."""
    at_ceiling = raw_checksum(
        clean_fixture, max_bytes=CLEAN_BYTE_COUNT, ids=fixed_ids, clock=fixed_clock
    )
    one_over = raw_checksum(
        clean_fixture, max_bytes=CLEAN_BYTE_COUNT - 1, ids=fixed_ids, clock=fixed_clock
    )
    zero = raw_checksum(clean_fixture, max_bytes=0, ids=fixed_ids, clock=fixed_clock)

    assert _checksum(at_ceiling).byte_count == CLEAN_BYTE_COUNT
    _single_refusal(
        one_over,
        RefusalCode.SIZE_CEILING,
        line=WHOLE_INPUT_LINE,
        value_length=CLEAN_BYTE_COUNT,
        ids=fixed_ids,
        clock=fixed_clock,
    )
    _single_refusal(
        zero,
        RefusalCode.SIZE_CEILING,
        line=WHOLE_INPUT_LINE,
        value_length=1,
        ids=fixed_ids,
        clock=fixed_clock,
    )


def test_raw_checksum_reads_the_input_once_one_byte_past_the_ceiling(
    monkeypatch: pytest.MonkeyPatch,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    with monkeypatch.context() as patch:
        opened, sizes = _spy_on_read_open(patch)
        result = raw_checksum(
            clean_fixture, max_bytes=CLEAN_BYTE_COUNT, ids=fixed_ids, clock=fixed_clock
        )

    assert opened == [clean_fixture]
    assert sizes == [CLEAN_BYTE_COUNT + 1]
    assert _checksum(result).byte_count == CLEAN_BYTE_COUNT


@pytest.mark.parametrize("max_bytes", [-1, -2, -DEFAULT_MAX_BYTES])
def test_raw_checksum_refuses_a_negative_ceiling_before_the_input_is_opened(
    max_bytes: int,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """An absent path is the proof: opening it would be the ``INPUT_PATH`` refusal."""
    absent = tmp_path / "absent.csv"

    with monkeypatch.context() as patch:
        opened, sizes = _spy_on_read_open(patch)
        result = raw_checksum(
            absent, max_bytes=max_bytes, ids=fixed_ids, clock=fixed_clock
        )

    assert opened == []
    assert sizes == []
    _single_refusal(
        result,
        RefusalCode.SIZE_CEILING,
        line=WHOLE_INPUT_LINE,
        value_length=0,
        ids=fixed_ids,
        clock=fixed_clock,
    )


def test_raw_checksum_refuses_a_missing_input_path_without_naming_it(
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    absent = tmp_path / "absent.csv"

    result = raw_checksum(
        absent, max_bytes=DEFAULT_MAX_BYTES, ids=fixed_ids, clock=fixed_clock
    )

    _input_path_refusal(result, absent, ids=fixed_ids, clock=fixed_clock)
    assert not absent.exists()


def test_raw_checksum_refuses_a_directory_input_path(
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    directory = tmp_path / "input.csv"
    directory.mkdir()

    result = raw_checksum(
        directory, max_bytes=DEFAULT_MAX_BYTES, ids=fixed_ids, clock=fixed_clock
    )

    _input_path_refusal(result, directory, ids=fixed_ids, clock=fixed_clock)
    assert directory.is_dir()


def test_raw_checksum_refuses_a_reparse_point_input_before_it_is_opened(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """The reader's rule, reused: the junction is refused, the file through it read."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "input.csv").write_bytes(clean_fixture.read_bytes())
    link = tmp_path / "link.csv"
    _winapi.CreateJunction(str(target), str(link))
    try:
        with monkeypatch.context() as patch:
            opened, sizes = _spy_on_read_open(patch)
            result = raw_checksum(
                link, max_bytes=DEFAULT_MAX_BYTES, ids=fixed_ids, clock=fixed_clock
            )
            through = raw_checksum(
                link / "input.csv",
                max_bytes=DEFAULT_MAX_BYTES,
                ids=fixed_ids,
                clock=fixed_clock,
            )
    finally:
        link.rmdir()

    assert opened == [link / "input.csv"]
    assert sizes == [DEFAULT_MAX_BYTES + 1]
    _input_path_refusal(result, link, ids=fixed_ids, clock=fixed_clock)
    expected = hashlib.sha256(clean_fixture.read_bytes()).hexdigest()
    assert _checksum(through) == RawChecksum(
        sha256=expected, byte_count=CLEAN_BYTE_COUNT
    )


def test_raw_checksum_refuses_a_failing_bounded_read_and_closes_the_handle(
    monkeypatch: pytest.MonkeyPatch,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    closed: list[bool] = []

    def failing_open(self: Path, mode: str = "r") -> _FailingReadHandle:
        assert mode == "rb"
        return _FailingReadHandle(closed)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "open", failing_open)
        result = raw_checksum(
            clean_fixture, max_bytes=DEFAULT_MAX_BYTES, ids=fixed_ids, clock=fixed_clock
        )

    assert closed == [True]
    _input_path_refusal(result, clean_fixture, ids=fixed_ids, clock=fixed_clock)


def test_raw_checksum_refuses_an_embedded_nul_path_before_it_is_opened(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    path = tmp_path / "embedded\x00nul.csv"

    with monkeypatch.context() as patch:
        opened, sizes = _spy_on_read_open(patch)
        result = raw_checksum(
            path, max_bytes=DEFAULT_MAX_BYTES, ids=fixed_ids, clock=fixed_clock
        )

    assert opened == []
    assert sizes == []
    diagnostic = _input_path_refusal(result, path, ids=fixed_ids, clock=fixed_clock)
    _assert_value_absent(diagnostic, json.dumps(str(path))[1:-1])
    _assert_value_absent(diagnostic, tmp_path.name)


def test_raw_checksum_draws_no_provider_value_when_it_succeeds(
    clean_fixture: Path,
) -> None:
    ids = _CountingIds()
    clock = _CountingClock()

    counted = raw_checksum(
        clean_fixture, max_bytes=DEFAULT_MAX_BYTES, ids=ids, clock=clock
    )
    faulty = raw_checksum(
        clean_fixture,
        max_bytes=DEFAULT_MAX_BYTES,
        ids=_MalformedIds(),
        clock=_NaiveClock(),
    )

    assert _checksum(counted) == _checksum(faulty)
    assert ids.calls == {"dataset_id": 0, "partition_id": 0, "diagnostic_id": 0}
    assert clock.calls == 0


def test_raw_checksum_draws_each_provider_value_exactly_once_on_a_refusal(
    tmp_path: Path,
) -> None:
    ids = _CountingIds()
    clock = _CountingClock()

    result = raw_checksum(
        tmp_path / "absent.csv", max_bytes=DEFAULT_MAX_BYTES, ids=ids, clock=clock
    )

    assert isinstance(result, Failure)
    assert ids.calls == {"dataset_id": 0, "partition_id": 0, "diagnostic_id": 1}
    assert clock.calls == 1


def test_raw_checksum_raises_the_contract_error_for_a_malformed_id(
    tmp_path: Path,
    fixed_clock: Clock,
) -> None:
    with pytest.raises(RuntimeError) as info:
        raw_checksum(
            tmp_path / "absent.csv",
            max_bytes=DEFAULT_MAX_BYTES,
            ids=_MalformedIds(),
            clock=fixed_clock,
        )

    error = info.value
    assert type(error) is ProviderContractError
    assert error.method == "diagnostic_id"
    assert error.__cause__ is None
    assert MALFORMED_DIAGNOSTIC_ID not in str(error)


def test_raw_checksum_raises_the_contract_error_for_a_naive_instant(
    clean_fixture: Path,
    fixed_ids: IdProvider,
) -> None:
    with pytest.raises(RuntimeError) as info:
        raw_checksum(clean_fixture, max_bytes=-1, ids=fixed_ids, clock=_NaiveClock())

    error = info.value
    assert type(error) is ProviderContractError
    assert error.method == "now_utc"
    assert str(NAIVE_INSTANT) not in str(error)


def test_raw_checksum_is_frozen() -> None:
    checksum = RawChecksum(sha256="0" * 64, byte_count=1)

    with pytest.raises(AttributeError):
        checksum.byte_count = 2  # type: ignore[misc]
