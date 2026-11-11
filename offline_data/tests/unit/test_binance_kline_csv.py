"""The strict ``binance-spot-kline-csv/1`` reader of the second-slice plan.

Every row of the plan's section 3 fixture table is pinned here on the three
edges of a refusal: the closed error code, the one-based line and value length
recorded in ``details``, and the absence of the offending value from the whole
serialized diagnostic. The committed SYNTHETIC fixtures carry the plan's named
cases; the remaining grammar rules, the line-1 precedence of the header rule,
the per-row rule order, the integer timestamp window on both edges, the
twenty-digit bound (a 21-digit and a 4400-digit token refused without an
``int`` call), the exact integer-arithmetic conversion without a float, the
shared input-path and ceiling rules and the provider contract (reading R7) are
exercised through files written byte-exactly into ``tmp_path``. No fixture is
real market data: the values are synthetic and labelled so by their names.
"""

from __future__ import annotations

import _winapi
import json
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from pathlib import Path
from typing import IO, NoReturn

import pytest
from crypto_lab.datasets.models import DuplicateInterval, TimeInterval
from crypto_lab.domain.diagnostics import (
    Diagnostic,
    DiagnosticCategory,
    DiagnosticSeverity,
)
from crypto_lab.domain.results import Failure, Success
from crypto_lab.domain.time import require_utc

from crypto_lab_offline_data import binance_kline_csv
from crypto_lab_offline_data.binance_kline_csv import (
    FIELD_COUNT,
    FIRST_ROW_LINE,
    MAX_TIMESTAMP_DIGITS,
    UNIT_DIVISORS,
    WINDOW_END_SECONDS,
    WINDOW_START_SECONDS,
    TimestampUnit,
    read_binance_kline_csv,
)
from crypto_lab_offline_data.candle_csv import (
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_ROWS,
    WHOLE_INPUT_LINE,
    CandleRow,
)
from crypto_lab_offline_data.diagnostics import (
    SOURCE_COMPONENT,
    ProviderContractError,
    RefusalCode,
)
from crypto_lab_offline_data.providers import Clock, IdProvider
from crypto_lab_offline_data.validation import validate_series

MS = TimestampUnit.MILLISECONDS
US = TimestampUnit.MICROSECONDS
ROW_COUNT = 60
MS_FIXTURE = "SYNTHETIC-BTCUSDT-1m-2024-12-31-ms.valid.csv"
US_FIXTURE = "SYNTHETIC-BTCUSDT-1m-2025-01-01-us.valid.csv"
GAPS_FIXTURE = "SYNTHETIC-BTCUSDT-1m-gaps-duplicates-us.valid.csv"
INVALID_FIXTURES = (
    "SYNTHETIC-close-not-after-open.csv",
    "SYNTHETIC-eleven-fields.csv",
    "SYNTHETIC-empty.csv",
    "SYNTHETIC-exponent-volume.csv",
    "SYNTHETIC-header-row.csv",
    "SYNTHETIC-high-below-low.csv",
    "SYNTHETIC-ms-declared-us.csv",
    "SYNTHETIC-negative-quote-volume.csv",
    "SYNTHETIC-off-grid-seconds.csv",
    "SYNTHETIC-open-time-21-digits.csv",
    "SYNTHETIC-open-time-at-2100.csv",
    "SYNTHETIC-open-time-before-2017.csv",
    "SYNTHETIC-open-time-signed.csv",
    "SYNTHETIC-thirteen-fields.csv",
    "SYNTHETIC-trades-fractional.csv",
    "SYNTHETIC-unsorted.csv",
    "SYNTHETIC-us-declared-ms.csv",
    "SYNTHETIC-zero-price.csv",
)
#: 2024-12-31T23:00:00Z in milliseconds and 2025-01-01T00:00:00Z in microseconds.
MS_FIRST_OPEN = 1_735_686_000_000
US_FIRST_OPEN = 1_735_689_600_000_000
MS_STEP = 60_000
US_STEP = 60_000_000
MS_FIRST_INSTANT = datetime(2024, 12, 31, 23, 0, tzinfo=UTC)
US_FIRST_INSTANT = datetime(2025, 1, 1, tzinfo=UTC)
MS_ROW_LENGTH = 148
US_ROW_LENGTH = 154
MS_BYTE_COUNT = ROW_COUNT * (MS_ROW_LENGTH + 1)
US_BYTE_COUNT = ROW_COUNT * (US_ROW_LENGTH + 1)
DOCUMENTED_HEADER = (
    "Open time,Open,High,Low,Close,Volume,Close time,Quote asset volume,"
    "Number of trades,Taker buy base asset volume,Taker buy quote asset volume,"
    "Ignore"
)
EPOCH_2017 = 1_483_228_800
EPOCH_2100 = 4_102_444_800
NUMBER_POSITIONS = (1, 2, 3, 4, 5, 7, 9, 10)
PRICE_POSITIONS = (1, 2, 3, 4)
CLOSE_TIME_POSITION = 6
TRADES_POSITION = 8
IGNORE_POSITION = 11
#: The first open time spelled with Arabic-Indic digits: ``[0-9]`` refuses them,
#: ``int`` and ``str.isdigit`` would not.
ARABIC_INDIC_OPEN = "".join(chr(0x0660 + int(digit)) for digit in str(US_FIRST_OPEN))
ARABIC_INDIC_ONE = chr(0x0661)


def _fields(open_time: int, step: int, minute: int) -> list[str]:
    """One synthetic twelve-field row in the documented eight-decimal style."""
    return [
        str(open_time),
        f"93500.{minute:02d}000000",
        f"93501.{minute:02d}000000",
        f"93499.{minute:02d}000000",
        f"93500.{minute:02d}500000",
        f"{10 + minute // 10}.{minute % 10}0000000",
        str(open_time + step - 1),
        f"9350{minute:02d}.50000000",
        f"{100 + minute}",
        f"5.{minute:02d}000000",
        f"4675{minute:02d}.25000000",
        "0",
    ]


def _us_fields(minute: int) -> list[str]:
    return _fields(US_FIRST_OPEN + US_STEP * minute, US_STEP, minute)


def _ms_fields(minute: int) -> list[str]:
    return _fields(MS_FIRST_OPEN + MS_STEP * minute, MS_STEP, minute)


def _with(fields: list[str], index: int, text: str) -> list[str]:
    changed = list(fields)
    changed[index] = text
    return changed


def _line(fields: list[str]) -> str:
    return ",".join(fields) + "\n"


def _write(path: Path, text: str) -> Path:
    """Write ``text`` byte-exactly, without platform newline translation."""
    path.write_bytes(text.encode("utf-8"))
    return path


def _read(path: Path, unit: TimestampUnit, ids: IdProvider, clock: Clock) -> object:
    return read_binance_kline_csv(path, timestamp_unit=unit, ids=ids, clock=clock)


def _rows(result: object) -> tuple[CandleRow, ...]:
    assert isinstance(result, Success)
    assert result.outcome == "SUCCESS"
    rows = result.value
    assert isinstance(rows, tuple)
    assert all(isinstance(row, CandleRow) for row in rows)
    return rows


def _single_refusal(
    result: object,
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
    assert diagnostic.message == f"line {line} refused by rule {code.value}"
    return diagnostic


def _assert_value_absent(diagnostic: Diagnostic, value: str) -> None:
    serialized = json.dumps(diagnostic.model_dump(mode="json"))
    assert value not in serialized


@pytest.fixture
def binance_root(sub_project_root: Path) -> Path:
    """The committed SYNTHETIC Binance fixture directory."""
    return sub_project_root / "tests" / "fixtures" / "binance"


@pytest.fixture
def binance_invalid_root(binance_root: Path) -> Path:
    return binance_root / "invalid"


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
        return "not-a-diagnostic-id"


class _NaiveClock:
    """A ``Clock`` whose instant the core refuses (reading R7)."""

    def now_utc(self) -> datetime:
        return datetime(2026, 1, 2, 3, 4, 5)  # noqa: DTZ001


class _SpyHandle:
    """A binary handle wrapper that records every size passed to ``read``."""

    def __init__(self, inner: IO[bytes], sizes: list[int]) -> None:
        self._inner = inner
        self._sizes = sizes

    def __enter__(self) -> _SpyHandle:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._inner.close()

    def read(self, size: int = -1) -> bytes:
        self._sizes.append(size)
        return self._inner.read(size)


def _spy_on_open(monkeypatch: pytest.MonkeyPatch) -> tuple[list[Path], list[int]]:
    """Record every path opened through ``Path.open`` and every read size."""
    opened: list[Path] = []
    sizes: list[int] = []
    real_open = Path.open

    def spying_open(self: Path, mode: str = "r") -> _SpyHandle:
        assert mode == "rb"
        opened.append(self)
        return _SpyHandle(real_open(self, "rb"), sizes)

    monkeypatch.setattr(Path, "open", spying_open)
    return opened, sizes


def _spy_on_int(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record every text the reader module converts with ``int``.

    Binding ``int`` in the module namespace shadows the builtin for that
    module's code alone, so the record is exactly the reader's own conversions.
    """
    converted: list[str] = []

    def spying_int(text: str) -> int:
        converted.append(text)
        return int(text)

    monkeypatch.setattr(binance_kline_csv, "int", spying_int, raising=False)
    return converted


def _forbid_float(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make any ``float`` reference in the reader module fail the test."""

    def forbidden_float(*args: object) -> NoReturn:
        raise AssertionError("the reader must not use float arithmetic")

    monkeypatch.setattr(binance_kline_csv, "float", forbidden_float, raising=False)


# --- the interface -------------------------------------------------------------


def test_the_timestamp_unit_is_a_closed_two_member_string_enum() -> None:
    assert issubclass(TimestampUnit, StrEnum)
    assert [unit.value for unit in TimestampUnit] == ["milliseconds", "microseconds"]
    assert TimestampUnit("milliseconds") is MS
    assert TimestampUnit("microseconds") is US
    assert UNIT_DIVISORS == {MS: 1_000, US: 1_000_000}
    with pytest.raises(ValueError, match="seconds"):
        TimestampUnit("seconds")


def test_the_window_and_grammar_constants_are_the_plan_literals() -> None:
    assert WINDOW_START_SECONDS == EPOCH_2017
    assert WINDOW_END_SECONDS == EPOCH_2100
    assert WINDOW_START_SECONDS == int(datetime(2017, 1, 1, tzinfo=UTC).timestamp())
    assert WINDOW_END_SECONDS == int(datetime(2100, 1, 1, tzinfo=UTC).timestamp())
    assert FIELD_COUNT == 12
    assert FIRST_ROW_LINE == 1
    assert MAX_TIMESTAMP_DIGITS == 20
    assert len(str(WINDOW_END_SECONDS * UNIT_DIVISORS[US] - 1)) == 16
    assert len(str(WINDOW_START_SECONDS * UNIT_DIVISORS[MS])) == 13


def test_the_rows_are_slice_one_candle_rows_without_the_dropped_fields(
    binance_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """Fields 7 to 12 are checked and dropped: the row type is unchanged."""
    rows = _rows(_read(binance_root / US_FIXTURE, US, fixed_ids, fixed_clock))

    assert tuple(CandleRow.__dataclass_fields__) == (
        "open_time_utc",
        "open",
        "high",
        "low",
        "close",
        "volume",
        "line",
    )
    assert all(type(row) is CandleRow for row in rows)


# --- the valid fixtures ----------------------------------------------------------


def _assert_sixty_synthetic_rows(rows: tuple[CandleRow, ...], first: datetime) -> None:
    assert len(rows) == ROW_COUNT
    for index, row in enumerate(rows):
        assert row.line == index + 1
        assert row.open_time_utc == first + timedelta(minutes=index)
        assert row.open_time_utc.tzinfo is not None
        assert row.open_time_utc.utcoffset() == timedelta(0)
        assert require_utc(row.open_time_utc) == row.open_time_utc
        for value in (row.open, row.high, row.low, row.close, row.volume):
            assert type(value) is Decimal
            assert value.is_finite()
        assert str(row.open) == f"93500.{index:02d}000000"
        assert str(row.high) == f"93501.{index:02d}000000"
        assert str(row.low) == f"93499.{index:02d}000000"
        assert str(row.close) == f"93500.{index:02d}500000"
        assert str(row.volume) == f"{10 + index // 10}.{index % 10}0000000"
        assert row.open == Decimal(f"93500.{index:02d}")
        assert row.open.as_tuple().exponent == -8
        assert row.low <= row.open <= row.high
        assert row.low <= row.close <= row.high
        assert row.volume >= 0


def test_the_millisecond_fixture_reads_sixty_minutes_ending_at_the_transition(
    binance_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    rows = _rows(_read(binance_root / MS_FIXTURE, MS, fixed_ids, fixed_clock))

    _assert_sixty_synthetic_rows(rows, MS_FIRST_INSTANT)
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    assert rows[0].open_time_utc == epoch + timedelta(milliseconds=MS_FIRST_OPEN)
    assert rows[0].open_time_utc == datetime(2024, 12, 31, 23, 0, tzinfo=UTC)
    assert rows[59].open_time_utc == datetime(2024, 12, 31, 23, 59, tzinfo=UTC)
    assert rows[59].close == Decimal("93500.59500000")


def test_the_microsecond_fixture_reads_sixty_minutes_from_the_transition(
    binance_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    rows = _rows(_read(binance_root / US_FIXTURE, US, fixed_ids, fixed_clock))

    _assert_sixty_synthetic_rows(rows, US_FIRST_INSTANT)
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    assert rows[0].open_time_utc == epoch + timedelta(microseconds=US_FIRST_OPEN)
    assert rows[0].open_time_utc == datetime(2025, 1, 1, tzinfo=UTC)
    assert rows[59].open_time_utc == datetime(2025, 1, 1, 0, 59, tzinfo=UTC)


def test_the_two_unit_fixtures_meet_one_minute_apart_at_the_transition(
    binance_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """13-digit millisecond and 16-digit microsecond values read to one timeline."""
    ms_rows = _rows(_read(binance_root / MS_FIXTURE, MS, fixed_ids, fixed_clock))
    us_rows = _rows(_read(binance_root / US_FIXTURE, US, fixed_ids, fixed_clock))

    assert us_rows[0].open_time_utc - ms_rows[59].open_time_utc == timedelta(minutes=1)
    assert len(str(MS_FIRST_OPEN)) == 13
    assert len(str(US_FIRST_OPEN)) == 16


def test_the_gaps_duplicates_fixture_validates_with_one_gap_and_one_duplicate(
    binance_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """The reader checks no grid; the existing validation records the facts."""
    rows = _rows(_read(binance_root / GAPS_FIXTURE, US, fixed_ids, fixed_clock))

    validated = validate_series(rows, timeframe="1m", ids=fixed_ids, clock=fixed_clock)

    assert len(rows) == ROW_COUNT
    assert isinstance(validated, Success)
    series = validated.value
    at = US_FIRST_INSTANT
    assert series.missing_intervals == (
        TimeInterval(
            start_utc=at + timedelta(minutes=20), end_utc=at + timedelta(minutes=21)
        ),
    )
    assert series.duplicate_intervals == (
        DuplicateInterval(
            start_utc=at + timedelta(minutes=30),
            end_utc=at + timedelta(minutes=31),
            duplicate_count=2,
        ),
    )
    assert series.observations == ()
    assert series.start_utc == at
    assert series.end_utc == at + timedelta(hours=1)
    assert series.row_count == ROW_COUNT
    assert rows[29].open_time_utc == rows[30].open_time_utc
    assert rows[29] == replace(rows[30], line=30)


def test_a_coarser_file_declared_one_minute_surfaces_as_missing_intervals(
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """The reader checks no timeframe: spacing is the validator's business."""
    text = "".join(_line(_us_fields(minute)) for minute in (0, 5, 10))
    path = _write(tmp_path / "five-minute.csv", text)

    rows = _rows(_read(path, US, fixed_ids, fixed_clock))
    one_minute = validate_series(rows, timeframe="1m", ids=fixed_ids, clock=fixed_clock)
    five_minutes = validate_series(
        rows, timeframe="5m", ids=fixed_ids, clock=fixed_clock
    )

    assert isinstance(one_minute, Success)
    assert isinstance(five_minutes, Success)
    assert len(one_minute.value.missing_intervals) == 2
    assert five_minutes.value.missing_intervals == ()


# --- the fixture files themselves ---------------------------------------------------


def test_every_fixture_is_synthetic_lf_ascii_with_the_pinned_byte_counts(
    binance_root: Path,
    binance_invalid_root: Path,
) -> None:
    """Every file is labelled SYNTHETIC-, LF-terminated ASCII without a BOM."""
    files = sorted(path for path in binance_root.rglob("*") if path.is_file())

    assert files
    for path in files:
        data = path.read_bytes()
        assert path.name.startswith("SYNTHETIC-"), path.name
        assert b"\r" not in data, path.name
        assert not data.startswith(b"\xef\xbb\xbf"), path.name
        data.decode("ascii")
    for name, byte_count, row_length in (
        (MS_FIXTURE, MS_BYTE_COUNT, MS_ROW_LENGTH),
        (US_FIXTURE, US_BYTE_COUNT, US_ROW_LENGTH),
        (GAPS_FIXTURE, US_BYTE_COUNT, US_ROW_LENGTH),
    ):
        data = (binance_root / name).read_bytes()
        assert len(data) == byte_count
        assert data.endswith(b"\n")
        lines = data[:-1].split(b"\n")
        assert len(lines) == ROW_COUNT
        assert all(len(line) == row_length for line in lines)
        assert all(line.count(b",") == FIELD_COUNT - 1 for line in lines)
    invalid_names = tuple(sorted(p.name for p in binance_invalid_root.iterdir()))
    assert (binance_invalid_root / "SYNTHETIC-empty.csv").read_bytes() == b""
    assert invalid_names == INVALID_FIXTURES
    assert len(INVALID_FIXTURES) == 18


# --- the invalid fixtures: section 3's table ------------------------------------------


@pytest.mark.parametrize(
    ("name", "unit", "code", "line", "value_length", "offending"),
    [
        ("SYNTHETIC-header-row.csv", US, RefusalCode.CSV_HEADER, 1, 147, "Open time"),
        ("SYNTHETIC-header-row.csv", MS, RefusalCode.CSV_HEADER, 1, 147, "Open time"),
        ("SYNTHETIC-empty.csv", US, RefusalCode.EMPTY_SERIES, 1, 0, None),
        ("SYNTHETIC-empty.csv", MS, RefusalCode.EMPTY_SERIES, 1, 0, None),
        (
            "SYNTHETIC-eleven-fields.csv",
            US,
            RefusalCode.CSV_ROW_SHAPE,
            2,
            US_ROW_LENGTH - 2,
            "467501.25000000",
        ),
        (
            "SYNTHETIC-thirteen-fields.csv",
            US,
            RefusalCode.CSV_ROW_SHAPE,
            2,
            US_ROW_LENGTH + 2,
            "467501.25000000,0,0",
        ),
        (
            "SYNTHETIC-ms-declared-us.csv",
            US,
            RefusalCode.TIMESTAMP_UNIT,
            1,
            13,
            "1735686000000",
        ),
        (
            "SYNTHETIC-us-declared-ms.csv",
            MS,
            RefusalCode.TIMESTAMP_UNIT,
            1,
            16,
            "1735689600000000",
        ),
        (
            "SYNTHETIC-open-time-21-digits.csv",
            US,
            RefusalCode.CSV_TIMESTAMP,
            2,
            21,
            "1" + "0" * 20,
        ),
        (
            "SYNTHETIC-open-time-before-2017.csv",
            US,
            RefusalCode.TIMESTAMP_UNIT,
            2,
            16,
            "1483228799000000",
        ),
        (
            "SYNTHETIC-open-time-at-2100.csv",
            US,
            RefusalCode.TIMESTAMP_UNIT,
            2,
            16,
            "4102444800000000",
        ),
        (
            "SYNTHETIC-close-not-after-open.csv",
            US,
            RefusalCode.CSV_TIMESTAMP,
            2,
            16,
            "1735689660000000",
        ),
        (
            "SYNTHETIC-open-time-signed.csv",
            US,
            RefusalCode.CSV_TIMESTAMP,
            2,
            17,
            "-1735689660000000",
        ),
        ("SYNTHETIC-trades-fractional.csv", US, RefusalCode.CSV_NUMBER, 2, 5, "101.5"),
        ("SYNTHETIC-exponent-volume.csv", US, RefusalCode.CSV_NUMBER, 2, 6, "1.01E1"),
        (
            "SYNTHETIC-negative-quote-volume.csv",
            US,
            RefusalCode.CSV_NUMBER,
            2,
            16,
            "-935001.50000000",
        ),
        ("SYNTHETIC-zero-price.csv", US, RefusalCode.CSV_NUMBER, 2, 10, "0.00000000"),
    ],
)
def test_each_invalid_fixture_is_refused_with_code_line_and_length_only(
    name: str,
    unit: TimestampUnit,
    code: RefusalCode,
    line: int,
    value_length: int,
    offending: str | None,
    binance_invalid_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    result = _read(binance_invalid_root / name, unit, fixed_ids, fixed_clock)

    diagnostic = _single_refusal(
        result,
        code,
        line=line,
        value_length=value_length,
        ids=fixed_ids,
        clock=fixed_clock,
    )
    if offending is not None:
        _assert_value_absent(diagnostic, offending)


def test_the_documented_header_line_length_is_the_recorded_value_length(
    binance_invalid_root: Path,
) -> None:
    header_line = (binance_invalid_root / "SYNTHETIC-header-row.csv").read_bytes()

    assert len(DOCUMENTED_HEADER) == 147
    assert DOCUMENTED_HEADER.count(",") == FIELD_COUNT - 1
    assert header_line.split(b"\n")[0] == DOCUMENTED_HEADER.encode("ascii")


@pytest.mark.parametrize(
    ("name", "row_count", "code", "line", "value_length"),
    [
        ("SYNTHETIC-high-below-low.csv", 2, RefusalCode.PRICE_SANITY, 2, 8),
        ("SYNTHETIC-unsorted.csv", 3, RefusalCode.ORDERING, 3, 20),
        ("SYNTHETIC-off-grid-seconds.csv", 2, RefusalCode.TIMEFRAME_GRID, 2, 20),
    ],
)
def test_the_reader_accepts_what_only_the_validator_refuses(
    name: str,
    row_count: int,
    code: RefusalCode,
    line: int,
    value_length: int,
    binance_invalid_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """Grid, ordering and price sanity stay ``validate_series`` rules."""
    rows = _rows(_read(binance_invalid_root / name, US, fixed_ids, fixed_clock))

    validated = validate_series(rows, timeframe="1m", ids=fixed_ids, clock=fixed_clock)

    assert len(rows) == row_count
    _single_refusal(
        validated,
        code,
        line=line,
        value_length=value_length,
        ids=fixed_ids,
        clock=fixed_clock,
    )


# --- the timestamp window on the integer (section 2.2) ---------------------------


@pytest.mark.parametrize("unit", [MS, US])
def test_the_lower_window_edge_is_inclusive_on_the_integer(
    unit: TimestampUnit,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    divisor = UNIT_DIVISORS[unit]
    edge = WINDOW_START_SECONDS * divisor
    step = 60 * divisor
    accepted = _write(tmp_path / "at-2017.csv", _line(_fields(edge, step, 0)))
    refused = _write(tmp_path / "before-2017.csv", _line(_fields(edge - 1, step, 0)))

    rows = _rows(_read(accepted, unit, fixed_ids, fixed_clock))
    result = _read(refused, unit, fixed_ids, fixed_clock)

    assert rows[0].open_time_utc == datetime(2017, 1, 1, tzinfo=UTC)
    diagnostic = _single_refusal(
        result,
        RefusalCode.TIMESTAMP_UNIT,
        line=1,
        value_length=len(str(edge - 1)),
        ids=fixed_ids,
        clock=fixed_clock,
    )
    _assert_value_absent(diagnostic, str(edge - 1))


@pytest.mark.parametrize("unit", [MS, US])
def test_the_upper_window_edge_is_exclusive_on_the_integer(
    unit: TimestampUnit,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """``end - 1`` is the last admitted value; ``end`` itself is refused.

    The last admitted value is reached as a close time, because an open time at
    ``end - 1`` leaves no in-window close time: that row passes its open field
    (both conversions are recorded) and is refused at its close field.
    """
    divisor = UNIT_DIVISORS[unit]
    end = WINDOW_END_SECONDS * divisor
    step = 60 * divisor
    last_minute = _fields(end - step, step, 0)
    assert last_minute[CLOSE_TIME_POSITION] == str(end - 1)
    accepted = _write(tmp_path / "last-minute.csv", _line(last_minute))
    open_at_end = _write(
        tmp_path / "at-2100.csv", _line(_with(last_minute, 0, str(end)))
    )
    open_at_last = _with(last_minute, 0, str(end - 1))
    close_at_end = _write(
        tmp_path / "close-at-2100.csv",
        _line(_with(open_at_last, CLOSE_TIME_POSITION, str(end))),
    )
    converted = _spy_on_int(monkeypatch)

    rows = _rows(_read(accepted, unit, fixed_ids, fixed_clock))
    at_end = _read(open_at_end, unit, fixed_ids, fixed_clock)
    before_close = len(converted)
    at_close = _read(close_at_end, unit, fixed_ids, fixed_clock)

    assert rows[0].open_time_utc == datetime(2099, 12, 31, 23, 59, tzinfo=UTC)
    _single_refusal(
        at_end,
        RefusalCode.TIMESTAMP_UNIT,
        line=1,
        value_length=len(str(end)),
        ids=fixed_ids,
        clock=fixed_clock,
    )
    _single_refusal(
        at_close,
        RefusalCode.TIMESTAMP_UNIT,
        line=1,
        value_length=len(str(end)),
        ids=fixed_ids,
        clock=fixed_clock,
    )
    assert converted[before_close:] == [str(end - 1), str(end)]


@pytest.mark.parametrize(
    ("unit", "value", "expected"),
    [
        (
            US,
            1_735_689_600_123_456,
            datetime(2025, 1, 1, 0, 0, 0, 123_456, tzinfo=UTC),
        ),
        (MS, 1_735_689_600_123, datetime(2025, 1, 1, 0, 0, 0, 123_000, tzinfo=UTC)),
        (MS, 1_735_689_600_001, datetime(2025, 1, 1, 0, 0, 0, 1_000, tzinfo=UTC)),
        (US, 1_735_689_600_000_001, datetime(2025, 1, 1, 0, 0, 0, 1, tzinfo=UTC)),
        (
            US,
            4_102_444_799_999_998,
            datetime(2099, 12, 31, 23, 59, 59, 999_998, tzinfo=UTC),
        ),
        (
            MS,
            4_102_444_799_998,
            datetime(2099, 12, 31, 23, 59, 59, 998_000, tzinfo=UTC),
        ),
    ],
)
def test_a_sub_second_remainder_converts_to_the_exact_microsecond_without_float(
    unit: TimestampUnit,
    value: int,
    expected: datetime,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """``divmod`` on the integer, never a float: the microsecond is exact.

    The close time is set at the open time plus one unit, so the row is read
    whatever the open time's position in the window.
    """
    _forbid_float(monkeypatch)
    fields = _with(_us_fields(0), 0, str(value))
    fields = _with(fields, CLOSE_TIME_POSITION, str(value + 1))
    path = _write(tmp_path / "remainder.csv", _line(fields))

    rows = _rows(_read(path, unit, fixed_ids, fixed_clock))

    assert rows[0].open_time_utc == expected
    assert rows[0].open_time_utc.microsecond == expected.microsecond


# --- the digit bound: 20, 21 and 4400 digits --------------------------------------


def test_a_twenty_digit_token_passes_the_grammar_and_fails_the_window(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    token = "9" * MAX_TIMESTAMP_DIGITS
    text = _line(_us_fields(0)) + _line(_with(_us_fields(1), 0, token))
    path = _write(tmp_path / "twenty.csv", text)
    converted = _spy_on_int(monkeypatch)

    result = _read(path, US, fixed_ids, fixed_clock)

    _single_refusal(
        result,
        RefusalCode.TIMESTAMP_UNIT,
        line=2,
        value_length=20,
        ids=fixed_ids,
        clock=fixed_clock,
    )
    assert converted[-1] == token


@pytest.mark.parametrize("digits", [21, 4400])
@pytest.mark.parametrize(
    "position", [0, CLOSE_TIME_POSITION], ids=["open-time", "close-time"]
)
def test_a_longer_digit_run_is_refused_without_any_integer_conversion(
    digits: int,
    position: int,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """Beyond twenty digits the grammar refuses first: ``int`` never sees the token.

    The interpreter's integer-string limit is lowered to its minimum for the
    read, so a conversion of the 4400-digit token would raise ``ValueError``
    instead of returning; the refusal shows that no conversion was attempted.
    """
    token = "1" * digits
    text = _line(_us_fields(0)) + _line(_with(_us_fields(1), position, token))
    path = _write(tmp_path / "long-token.csv", text)
    converted = _spy_on_int(monkeypatch)
    previous_limit = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(640)
    try:
        result = _read(path, US, fixed_ids, fixed_clock)
    finally:
        sys.set_int_max_str_digits(previous_limit)

    diagnostic = _single_refusal(
        result,
        RefusalCode.CSV_TIMESTAMP,
        line=2,
        value_length=digits,
        ids=fixed_ids,
        clock=fixed_clock,
    )
    _assert_value_absent(diagnostic, token[:21])
    assert all(len(text) <= MAX_TIMESTAMP_DIGITS for text in converted)
    assert token not in converted
    assert len(converted) == 2 + position // CLOSE_TIME_POSITION


def test_a_4400_digit_line_one_is_the_header_refusal_without_conversion(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    token = "1" * 4400
    line_one = _line(_with(_us_fields(0), 0, token))
    path = _write(tmp_path / "long-line-one.csv", line_one + _line(_us_fields(1)))
    converted = _spy_on_int(monkeypatch)

    result = _read(path, US, fixed_ids, fixed_clock)

    _single_refusal(
        result,
        RefusalCode.CSV_HEADER,
        line=1,
        value_length=len(line_one) - 1,
        ids=fixed_ids,
        clock=fixed_clock,
    )
    assert converted == []


@pytest.mark.parametrize("position", NUMBER_POSITIONS)
def test_a_4400_digit_number_is_the_number_refusal(
    position: int,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """The canonical-length bound of the slice-1 number rule refuses it."""
    token = "1" * 4400
    text = _line(_us_fields(0)) + _line(_with(_us_fields(1), position, token))
    path = _write(tmp_path / "long-number.csv", text)

    result = _read(path, US, fixed_ids, fixed_clock)

    _single_refusal(
        result,
        RefusalCode.CSV_NUMBER,
        line=2,
        value_length=4400,
        ids=fixed_ids,
        clock=fixed_clock,
    )


# --- line 1: the header rule and its precedence ------------------------------------


def _first_field(text: str) -> str:
    return ",".join(_with(_us_fields(0), 0, text))


FIRST_LINE_CASES = [
    ("", RefusalCode.CSV_ROW_SHAPE),
    ("|".join(_us_fields(0)), RefusalCode.CSV_ROW_SHAPE),
    (";".join(_us_fields(0)), RefusalCode.CSV_ROW_SHAPE),
    (_first_field("-" + str(US_FIRST_OPEN)), RefusalCode.CSV_TIMESTAMP),
    (_first_field("+" + str(US_FIRST_OPEN)), RefusalCode.CSV_TIMESTAMP),
    (_first_field("1" * 21), RefusalCode.CSV_TIMESTAMP),
    (_first_field(" " + str(US_FIRST_OPEN)), RefusalCode.CSV_TIMESTAMP),
    (_first_field(str(US_FIRST_OPEN) + " "), RefusalCode.CSV_TIMESTAMP),
    (_first_field(str(US_FIRST_OPEN) + ".0"), RefusalCode.CSV_TIMESTAMP),
    (_first_field("2025-01-01T00:00:00Z"), RefusalCode.CSV_TIMESTAMP),
    (_first_field(""), RefusalCode.CSV_TIMESTAMP),
    (_first_field('"' + str(US_FIRST_OPEN) + '"'), RefusalCode.CSV_TIMESTAMP),
    (_first_field(ARABIC_INDIC_OPEN), RefusalCode.CSV_TIMESTAMP),
    (DOCUMENTED_HEADER, RefusalCode.CSV_TIMESTAMP),
    ("open_time_utc,open,high,low,close,volume", RefusalCode.CSV_ROW_SHAPE),
]


@pytest.mark.parametrize(("first_line", "row_code"), FIRST_LINE_CASES)
@pytest.mark.parametrize("unit", [MS, US])
def test_a_first_field_that_is_not_one_to_twenty_digits_is_the_header_refusal(
    first_line: str,
    row_code: RefusalCode,
    unit: TimestampUnit,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """Line 1 is held to the header rule first, whatever the declared unit.

    The same text at line 2, after a line 1 the header rule admits, is refused
    by the row rule it then violates, so the precedence is line 1's alone. The
    Arabic-Indic case shows the grammar is ``[0-9]``, which ``int`` is not.
    """
    valid = _us_fields(0) if unit is US else _ms_fields(0)
    line_one = _write(tmp_path / "line-one.csv", first_line + "\n" + _line(valid))
    line_two = _write(tmp_path / "line-two.csv", _line(valid) + first_line + "\n")

    at_line_one = _read(line_one, unit, fixed_ids, fixed_clock)
    at_line_two = _read(line_two, unit, fixed_ids, fixed_clock)

    diagnostic = _single_refusal(
        at_line_one,
        RefusalCode.CSV_HEADER,
        line=1,
        value_length=len(first_line),
        ids=fixed_ids,
        clock=fixed_clock,
    )
    if first_line:
        _assert_value_absent(diagnostic, first_line)
    first_field = first_line.split(",")[0]
    row_length = len(first_line)
    expected = row_length if row_code is RefusalCode.CSV_ROW_SHAPE else len(first_field)
    _single_refusal(
        at_line_two,
        row_code,
        line=2,
        value_length=expected,
        ids=fixed_ids,
        clock=fixed_clock,
    )


def test_a_blank_line_one_is_the_header_refusal_and_an_empty_file_is_not(
    tmp_path: Path,
    binance_invalid_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """Zero lines is the empty series at line 1; one blank line is a header."""
    blank = _write(tmp_path / "blank.csv", "\n")
    crlf_blank = _write(tmp_path / "crlf-blank.csv", "\r\n")
    empty_fixture = binance_invalid_root / "SYNTHETIC-empty.csv"

    empty = _read(empty_fixture, US, fixed_ids, fixed_clock)
    blank_result = _read(blank, US, fixed_ids, fixed_clock)
    crlf_result = _read(crlf_blank, US, fixed_ids, fixed_clock)

    _single_refusal(
        empty,
        RefusalCode.EMPTY_SERIES,
        line=FIRST_ROW_LINE,
        value_length=0,
        ids=fixed_ids,
        clock=fixed_clock,
    )
    for result in (blank_result, crlf_result):
        _single_refusal(
            result,
            RefusalCode.CSV_HEADER,
            line=1,
            value_length=0,
            ids=fixed_ids,
            clock=fixed_clock,
        )


def test_a_byte_order_mark_is_a_header_refusal(
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    path = tmp_path / "bom.csv"
    path.write_bytes(b"\xef\xbb\xbf" + _line(_us_fields(0)).encode("utf-8"))

    result = _read(path, US, fixed_ids, fixed_clock)

    _single_refusal(
        result,
        RefusalCode.CSV_HEADER,
        line=1,
        value_length=US_ROW_LENGTH + 1,
        ids=fixed_ids,
        clock=fixed_clock,
    )


@pytest.mark.parametrize("unit", [MS, US])
def test_once_line_one_passes_the_header_rule_it_is_parsed_as_a_row(
    unit: TimestampUnit,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """A digit-led line 1 with eleven fields is the row-shape refusal at line 1."""
    short = _us_fields(0)[:11]
    text = _line(short) + _line(_us_fields(1))
    path = _write(tmp_path / "eleven-at-line-one.csv", text)

    result = _read(path, unit, fixed_ids, fixed_clock)

    _single_refusal(
        result,
        RefusalCode.CSV_ROW_SHAPE,
        line=1,
        value_length=US_ROW_LENGTH - 2,
        ids=fixed_ids,
        clock=fixed_clock,
    )


# --- row shape and the per-row rule order -------------------------------------------


@pytest.mark.parametrize(
    ("body", "line"),
    [
        (_line(_us_fields(0)) + "\n" + _line(_us_fields(1)), 2),
        (_line(_us_fields(0)) + _line(_us_fields(1)) + "\n", 3),
        (_line(_us_fields(0)) + "\r\n" + _line(_us_fields(1)), 2),
    ],
)
def test_a_blank_line_inside_the_body_is_a_row_shape_refusal(
    body: str,
    line: int,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    path = _write(tmp_path / "blank-line.csv", body)

    result = _read(path, US, fixed_ids, fixed_clock)

    _single_refusal(
        result,
        RefusalCode.CSV_ROW_SHAPE,
        line=line,
        value_length=0,
        ids=fixed_ids,
        clock=fixed_clock,
    )


@pytest.mark.parametrize("field_count", [1, 6, 11, 13, 24])
def test_any_field_count_but_twelve_is_a_row_shape_refusal(
    field_count: int,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    fields = (_us_fields(1) * 2)[:field_count]
    row = ",".join(fields)
    path = _write(tmp_path / "shape.csv", _line(_us_fields(0)) + row + "\n")

    result = _read(path, US, fixed_ids, fixed_clock)

    diagnostic = _single_refusal(
        result,
        RefusalCode.CSV_ROW_SHAPE,
        line=2,
        value_length=len(row),
        ids=fixed_ids,
        clock=fixed_clock,
    )
    _assert_value_absent(diagnostic, row)


MINUTE_ONE_CLOSE = str(US_FIRST_OPEN + US_STEP)
RULE_ORDER_CASES = [
    ("shape-before-unit", {0: "1735686060000", 11: None}, RefusalCode.CSV_ROW_SHAPE),
    ("timestamp-before-number", {0: "abc", 5: "x"}, RefusalCode.CSV_TIMESTAMP),
    (
        "unit-before-price",
        {0: "1735686060000", 1: "0.00000000"},
        RefusalCode.TIMESTAMP_UNIT,
    ),
    ("open-before-high", {1: "0.00000000", 2: "x"}, RefusalCode.CSV_NUMBER),
    (
        "close-price-before-close-time",
        {4: "0.00000000", 6: "abc"},
        RefusalCode.CSV_NUMBER,
    ),
    (
        "volume-before-close-time",
        {5: "-1", 6: MINUTE_ONE_CLOSE},
        RefusalCode.CSV_NUMBER,
    ),
    (
        "close-time-before-quote",
        {6: MINUTE_ONE_CLOSE, 7: "x"},
        RefusalCode.CSV_TIMESTAMP,
    ),
    (
        "close-unit-before-quote",
        {6: "1735686119999", 7: "x"},
        RefusalCode.TIMESTAMP_UNIT,
    ),
    ("quote-before-trades", {7: "x", 8: "1.5"}, RefusalCode.CSV_NUMBER),
    ("trades-before-taker-base", {8: "1.5", 9: "x"}, RefusalCode.CSV_NUMBER),
    ("taker-base-before-taker-quote", {9: "1e1", 10: "x"}, RefusalCode.CSV_NUMBER),
    ("taker-quote-alone", {10: ""}, RefusalCode.CSV_NUMBER),
]


@pytest.mark.parametrize(
    ("changes", "code"),
    [(changes, code) for _, changes, code in RULE_ORDER_CASES],
    ids=[case_id for case_id, _, _ in RULE_ORDER_CASES],
)
def test_a_row_breaking_two_rules_is_refused_by_the_first_in_field_order(
    changes: dict[int, str | None],
    code: RefusalCode,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """``None`` drops the field, so the row's shape breaks before any value rule."""
    fields = _us_fields(1)
    for index, text in changes.items():
        fields[index] = "" if text is None else text
    if None in changes.values():
        fields = fields[:11]
    row = ",".join(fields)
    first_offender = min(index for index, text in changes.items() if text is not None)
    expected = (
        len(row) if code is RefusalCode.CSV_ROW_SHAPE else len(fields[first_offender])
    )
    path = _write(tmp_path / "order.csv", _line(_us_fields(0)) + row + "\n")

    result = _read(path, US, fixed_ids, fixed_clock)

    _single_refusal(
        result,
        code,
        line=2,
        value_length=expected,
        ids=fixed_ids,
        clock=fixed_clock,
    )


# --- the numeric fields: the slice-1 grammar in every checked position -------------


@pytest.mark.parametrize(
    "number",
    [
        ".5",
        "5.",
        "+1.5",
        "-1.5",
        "1e5",
        "1E5",
        "1.5e-3",
        "0x10",
        " 1.5",
        "1.5 ",
        "1_000",
        "NaN",
        "Infinity",
        "inf",
        "1.5.5",
        "",
        '"1.5"',
        "1" * 257,
    ],
)
@pytest.mark.parametrize("position", NUMBER_POSITIONS)
def test_every_non_grammar_number_is_refused_in_every_numeric_field(
    number: str,
    position: int,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    fields = _with(_us_fields(1), position, number)
    path = _write(tmp_path / "number.csv", _line(_us_fields(0)) + _line(fields))

    result = _read(path, US, fixed_ids, fixed_clock)

    diagnostic = _single_refusal(
        result,
        RefusalCode.CSV_NUMBER,
        line=2,
        value_length=len(number),
        ids=fixed_ids,
        clock=fixed_clock,
    )
    if number:
        _assert_value_absent(diagnostic, number)


@pytest.mark.parametrize("position", PRICE_POSITIONS)
def test_a_zero_price_is_a_number_refusal_and_a_zero_volume_is_not(
    position: int,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    zero_price_fields = _with(_us_fields(0), position, "0.00000000")
    zero_price = _write(tmp_path / "zero-price.csv", _line(zero_price_fields))
    zero_volume_fields = _with(_us_fields(0), 5, "0")
    zero_volume_fields = _with(zero_volume_fields, 7, "0.0")
    zero_volume_fields = _with(zero_volume_fields, 9, "0.00000000")
    zero_volumes = _write(tmp_path / "zero-volumes.csv", _line(zero_volume_fields))

    refused = _read(zero_price, US, fixed_ids, fixed_clock)
    rows = _rows(_read(zero_volumes, US, fixed_ids, fixed_clock))

    _single_refusal(
        refused,
        RefusalCode.CSV_NUMBER,
        line=1,
        value_length=10,
        ids=fixed_ids,
        clock=fixed_clock,
    )
    assert rows[0].volume == Decimal(0)
    assert str(rows[0].volume) == "0"


@pytest.mark.parametrize(
    ("trades", "accepted"),
    [
        ("0", True),
        ("1", True),
        ("007", True),
        ("10234", True),
        ("1" * 256, True),
        ("1" * 257, False),
        ("101.5", False),
        ("1.0", False),
        ("-1", False),
        ("+1", False),
        ("1e3", False),
        ("", False),
        (" 1", False),
        ("1 ", False),
        (ARABIC_INDIC_ONE, False),
    ],
)
def test_the_number_of_trades_is_an_unsigned_integer_within_the_canonical_bound(
    trades: str,
    accepted: bool,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    fields = _with(_us_fields(0), TRADES_POSITION, trades)
    path = _write(tmp_path / "trades.csv", _line(fields))

    result = _read(path, US, fixed_ids, fixed_clock)

    if accepted:
        assert len(_rows(result)) == 1
    else:
        _single_refusal(
            result,
            RefusalCode.CSV_NUMBER,
            line=1,
            value_length=len(trades),
            ids=fixed_ids,
            clock=fixed_clock,
        )


def test_the_checked_fields_are_not_retained(
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """Two rows differing only in fields 7 to 12 read to equal candle rows."""
    first = _us_fields(0)
    second = list(first)
    second[6] = str(US_FIRST_OPEN + 1)
    second[7] = "1.00000000"
    second[8] = "1"
    second[9] = "0.00000001"
    second[10] = "0.00000002"
    second[11] = "anything but a comma"
    one = _write(tmp_path / "one.csv", _line(first))
    two = _write(tmp_path / "two.csv", _line(second))

    rows_one = _rows(_read(one, US, fixed_ids, fixed_clock))
    rows_two = _rows(_read(two, US, fixed_ids, fixed_clock))

    assert rows_one == rows_two


# --- field 12 (``Ignore``) and the close-time relation -----------------------------


@pytest.mark.parametrize("ignore", ["0", "", "abc", " ", "0 ", "x y", "1.5e3", '"0"'])
def test_the_ignore_field_is_any_comma_free_text_and_is_dropped(
    ignore: str,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """Field 12 is not interpreted: its value is UNVERIFIED by the documentation."""
    path = _write(tmp_path / "ignore.csv", _line(_with(_us_fields(0), 11, ignore)))
    reference = _write(tmp_path / "reference.csv", _line(_us_fields(0)))

    rows = _rows(_read(path, US, fixed_ids, fixed_clock))

    assert rows == _rows(_read(reference, US, fixed_ids, fixed_clock))


def _unit_fields(unit: TimestampUnit, minute: int) -> list[str]:
    return _ms_fields(minute) if unit is MS else _us_fields(minute)


def _consumed_delimiter(ending: str) -> str:
    """The part of ``ending`` the reader's splitter consumes: LF or CRLF only."""
    if ending.endswith("\r\n"):
        return "\r\n"
    return "\n" if ending.endswith("\n") else ""


#: The residual carriage returns field 12 may hold once the splitter has
#: consumed the LF or CRLF delimiter: a lone terminal ``\r`` on the final line
#: (which no later line may follow), after opaque text or as the whole field;
#: the first ``\r`` of a ``\r\r\n`` ending; and a ``\r`` embedded in the opaque
#: text under either delimiter. Each shape is placed at line 1 and at a later
#: body line and, where a later line can follow, both as the final line and
#: before one. (A field that is ``\r`` followed by LF is a CRLF ending with an
#: empty field 12, accepted, not a residual carriage return.)
RESIDUAL_CR_SHAPES = [
    ("lone-terminal-cr", "0", "\r", False),
    ("cr-only-field", "", "\r", False),
    ("cr-cr-lf", "0", "\r\r\n", True),
    ("embedded-cr-lf", "opaque\rtext", "\n", True),
    ("embedded-cr-crlf", "opaque\rtext", "\r\n", True),
]
RESIDUAL_CR_CASES = [
    (
        f"{shape}-line-{line}-{'before-final' if followed else 'final'}",
        ignore,
        ending,
        line,
        followed,
    )
    for shape, ignore, ending, may_follow in RESIDUAL_CR_SHAPES
    for line in (1, 2)
    for followed in ((False, True) if may_follow else (False,))
]


@pytest.mark.parametrize("unit", [MS, US])
@pytest.mark.parametrize(
    ("ignore", "ending", "line", "followed"),
    [case[1:] for case in RESIDUAL_CR_CASES],
    ids=[case[0] for case in RESIDUAL_CR_CASES],
)
def test_a_residual_carriage_return_in_field_twelve_is_the_row_shape_refusal(
    ignore: str,
    ending: str,
    line: int,
    followed: bool,
    unit: TimestampUnit,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """A carriage return is a line ending only when a line feed follows it.

    An unpaired carriage return stays in its logical row; once fields 1 to 11
    pass, a residual one in field 12 is ``CSV_ROW_SHAPE`` at that line with the
    complete logical row's length (the carriage returns included, the consumed
    LF or CRLF excluded). Nothing is stripped or repaired, and the twelve-field
    row proves the width rule is not what refused it.
    """
    malformed = ",".join(_with(_unit_fields(unit, line - 1), 11, ignore)) + ending
    record = malformed[: len(malformed) - len(_consumed_delimiter(ending))]
    before = "".join(_line(_unit_fields(unit, minute)) for minute in range(line - 1))
    after = _line(_unit_fields(unit, line)) if followed else ""
    path = _write(tmp_path / "residual-cr.csv", before + malformed + after)

    result = _read(path, unit, fixed_ids, fixed_clock)

    assert "\r" in record
    assert record.count(",") == FIELD_COUNT - 1
    diagnostic = _single_refusal(
        result,
        RefusalCode.CSV_ROW_SHAPE,
        line=line,
        value_length=len(record),
        ids=fixed_ids,
        clock=fixed_clock,
    )
    _assert_value_absent(diagnostic, "opaque")
    _assert_value_absent(diagnostic, "\\r")


def test_a_file_of_cr_only_line_endings_is_one_row_of_too_many_fields(
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """With CR-only endings the file is one logical line of twenty-three fields.

    Field 12 of the first row and field 1 of the second merge around the
    carriage return, so the width rule refuses line 1 with the whole text's
    length; nothing is repaired.
    """
    cr_only_text = ",".join(_us_fields(0)) + "\r" + ",".join(_us_fields(1)) + "\r"
    cr_only = _write(tmp_path / "cr-only.csv", cr_only_text)

    refused = _read(cr_only, US, fixed_ids, fixed_clock)

    assert cr_only_text.count(",") == 2 * FIELD_COUNT - 2
    _single_refusal(
        refused,
        RefusalCode.CSV_ROW_SHAPE,
        line=1,
        value_length=len(cr_only_text),
        ids=fixed_ids,
        clock=fixed_clock,
    )


def test_the_residual_cr_diagnostic_names_line_rule_and_length_only(
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """One structured diagnostic, pinned on every edge.

    The existing code, the logical line, the complete logical-row length (the
    one-character field 12 of the reference row replaced by ``ignore``, plus the
    terminal carriage return), the standard message, and no value or path.
    """
    ignore = "opaque\rtext"
    record = ",".join(_with(_us_fields(1), IGNORE_POSITION, ignore)) + "\r"
    path = _write(tmp_path / "cr-diagnostic.csv", _line(_us_fields(0)) + record)

    result = _read(path, US, fixed_ids, fixed_clock)

    assert len(record) == US_ROW_LENGTH - len("0") + len(ignore) + len("\r")
    diagnostic = _single_refusal(
        result,
        RefusalCode.CSV_ROW_SHAPE,
        line=2,
        value_length=len(record),
        ids=fixed_ids,
        clock=fixed_clock,
    )
    assert diagnostic.error_code == "OFFLINE_DATA.CSV_ROW_SHAPE"
    assert diagnostic.details == {
        "line": 2,
        "rule": "OFFLINE_DATA.CSV_ROW_SHAPE",
        "value_length": len(record),
    }
    assert diagnostic.message == "line 2 refused by rule OFFLINE_DATA.CSV_ROW_SHAPE"
    _assert_value_absent(diagnostic, "opaque")
    _assert_value_absent(diagnostic, "\\r")
    _assert_value_absent(diagnostic, record)
    _assert_value_absent(diagnostic, str(path))
    _assert_value_absent(diagnostic, path.as_posix())
    _assert_value_absent(diagnostic, path.name)


@pytest.mark.parametrize("unit", [MS, US])
def test_the_residual_cr_refusal_draws_the_diagnostic_id_and_the_instant_once(
    unit: TimestampUnit,
    tmp_path: Path,
) -> None:
    ids = _CountingIds()
    clock = _CountingClock()
    record = ",".join(_unit_fields(unit, 0)) + "\r"
    path = _write(tmp_path / "cr-draws.csv", record)

    result = _read(path, unit, ids, clock)

    assert isinstance(result, Failure)
    assert result.diagnostics[0].error_code == RefusalCode.CSV_ROW_SHAPE.value
    assert ids.calls == {"dataset_id": 0, "partition_id": 0, "diagnostic_id": 1}
    assert clock.calls == 1


def test_a_refused_provider_value_on_the_residual_cr_refusal_raises(
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """The new refusal propagates a provider fault like every other (reading R7)."""
    path = _write(tmp_path / "cr-fault.csv", ",".join(_us_fields(0)) + "\r")

    with pytest.raises(ProviderContractError) as ids_info:
        _read(path, US, _MalformedIds(), fixed_clock)
    with pytest.raises(ProviderContractError) as clock_info:
        _read(path, US, fixed_ids, _NaiveClock())

    assert ids_info.value.method == "diagnostic_id"
    assert "not-a-diagnostic-id" not in str(ids_info.value)
    assert ids_info.value.__cause__ is None
    assert clock_info.value.method == "now_utc"
    assert "2026" not in str(clock_info.value)


EARLIER_RULE_CASES = [
    ("header-before-cr", 1, {0: "abc"}, RefusalCode.CSV_HEADER),
    ("width-before-cr", 2, {11: None}, RefusalCode.CSV_ROW_SHAPE),
    ("open-time-before-cr", 2, {0: "abc"}, RefusalCode.CSV_TIMESTAMP),
    ("open-unit-before-cr", 2, {0: "1735686060000"}, RefusalCode.TIMESTAMP_UNIT),
    ("open-price-before-cr", 2, {1: "0.00000000"}, RefusalCode.CSV_NUMBER),
    ("volume-before-cr", 2, {5: "-1"}, RefusalCode.CSV_NUMBER),
    ("close-time-before-cr", 2, {6: "abc"}, RefusalCode.CSV_TIMESTAMP),
    ("close-order-before-cr", 2, {6: MINUTE_ONE_CLOSE}, RefusalCode.CSV_TIMESTAMP),
    ("close-unit-before-cr", 2, {6: "1735686119999"}, RefusalCode.TIMESTAMP_UNIT),
    ("trades-before-cr", 2, {8: "1.5"}, RefusalCode.CSV_NUMBER),
    ("taker-quote-before-cr", 2, {10: ""}, RefusalCode.CSV_NUMBER),
]


@pytest.mark.parametrize(
    ("line", "changes", "code"),
    [case[1:] for case in EARLIER_RULE_CASES],
    ids=[case[0] for case in EARLIER_RULE_CASES],
)
def test_an_earlier_rule_wins_over_a_residual_cr_in_field_twelve(
    line: int,
    changes: dict[int, str | None],
    code: RefusalCode,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """The line-1 header rule, the width rule and every field rule of fields 1
    to 11 keep precedence over the field-12 carriage return, which is checked
    last; ``None`` drops field 12 so the width rule fires with the CR present."""
    fields = _us_fields(line - 1)
    for index, text in changes.items():
        fields[index] = "" if text is None else text
    if None in changes.values():
        fields = fields[:11]
    record = ",".join(fields) + "\r"
    offenders = [index for index, text in changes.items() if text is not None]
    whole_line = code in {RefusalCode.CSV_HEADER, RefusalCode.CSV_ROW_SHAPE}
    expected = len(record) if whole_line else len(fields[offenders[0]])
    before = "".join(_line(_us_fields(minute)) for minute in range(line - 1))
    path = _write(tmp_path / "earlier-rule.csv", before + record)

    result = _read(path, US, fixed_ids, fixed_clock)

    _single_refusal(
        result,
        code,
        line=line,
        value_length=expected,
        ids=fixed_ids,
        clock=fixed_clock,
    )


@pytest.mark.parametrize(
    ("close_offset", "code"),
    [
        (0, RefusalCode.CSV_TIMESTAMP),
        (-1, RefusalCode.CSV_TIMESTAMP),
        (1, None),
        (US_STEP - 1, None),
        (US_STEP, None),
    ],
    ids=["equal", "before", "one-unit-after", "interval-end", "next-open"],
)
def test_the_close_time_must_be_strictly_after_the_open_time(
    close_offset: int,
    code: RefusalCode | None,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """Only the strict order is enforced; the interval relation is not checked."""
    close_text = str(US_FIRST_OPEN + close_offset)
    fields = _with(_us_fields(0), CLOSE_TIME_POSITION, close_text)
    path = _write(tmp_path / "close.csv", _line(fields))

    result = _read(path, US, fixed_ids, fixed_clock)

    if code is None:
        assert len(_rows(result)) == 1
    else:
        diagnostic = _single_refusal(
            result,
            code,
            line=1,
            value_length=len(close_text),
            ids=fixed_ids,
            clock=fixed_clock,
        )
        _assert_value_absent(diagnostic, close_text)


@pytest.mark.parametrize(
    ("close_text", "code"),
    [
        ("1" * 21, RefusalCode.CSV_TIMESTAMP),
        ("abc", RefusalCode.CSV_TIMESTAMP),
        ("-" + str(US_FIRST_OPEN + 1), RefusalCode.CSV_TIMESTAMP),
        ("1735689659999", RefusalCode.TIMESTAMP_UNIT),
        (str(EPOCH_2100 * 1_000_000), RefusalCode.TIMESTAMP_UNIT),
        ("2025-01-01T00:00:59Z", RefusalCode.CSV_TIMESTAMP),
    ],
)
def test_the_close_time_is_held_to_the_grammar_and_the_window(
    close_text: str,
    code: RefusalCode,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    fields = _with(_us_fields(0), CLOSE_TIME_POSITION, close_text)
    path = _write(tmp_path / "close-grammar.csv", _line(fields))

    result = _read(path, US, fixed_ids, fixed_clock)

    diagnostic = _single_refusal(
        result,
        code,
        line=1,
        value_length=len(close_text),
        ids=fixed_ids,
        clock=fixed_clock,
    )
    _assert_value_absent(diagnostic, close_text)


# --- the shared input rules: path, ceilings, encoding, line endings -------------------


def _input_path_refusal(
    result: object,
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
    _assert_value_absent(diagnostic, str(path))
    _assert_value_absent(diagnostic, path.as_posix())
    _assert_value_absent(diagnostic, path.name)
    return diagnostic


def test_a_missing_input_path_is_refused_without_naming_it(
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    absent = tmp_path / "absent.csv"
    assert not absent.exists()

    result = _read(absent, US, fixed_ids, fixed_clock)

    _input_path_refusal(result, absent, ids=fixed_ids, clock=fixed_clock)
    assert not absent.exists()


def test_a_directory_input_path_is_refused_without_a_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    directory = tmp_path / "input.csv"
    directory.mkdir()
    opened, sizes = _spy_on_open(monkeypatch)

    result = _read(directory, US, fixed_ids, fixed_clock)

    assert sizes == []
    assert opened == [directory]
    _input_path_refusal(result, directory, ids=fixed_ids, clock=fixed_clock)
    assert directory.is_dir()


def test_a_reparse_point_input_path_is_refused_before_it_is_opened(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    binance_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """A junction is refused on its own attributes; the file behind it reads."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "input.csv").write_bytes((binance_root / US_FIXTURE).read_bytes())
    link = tmp_path / "link.csv"
    _winapi.CreateJunction(str(target), str(link))
    try:
        opened, sizes = _spy_on_open(monkeypatch)
        result = _read(link, US, fixed_ids, fixed_clock)
        through = _read(link / "input.csv", US, fixed_ids, fixed_clock)
    finally:
        link.rmdir()

    assert opened == [link / "input.csv"]
    assert sizes == [DEFAULT_MAX_BYTES + 1]
    _input_path_refusal(result, link, ids=fixed_ids, clock=fixed_clock)
    assert len(_rows(through)) == ROW_COUNT
    assert not link.exists()


def test_an_embedded_nul_in_the_input_path_is_refused_before_it_is_opened(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    path = tmp_path / "embedded\x00nul.csv"
    opened, sizes = _spy_on_open(monkeypatch)

    result = _read(path, US, fixed_ids, fixed_clock)

    assert sizes == []
    assert opened == []
    diagnostic = _input_path_refusal(result, path, ids=fixed_ids, clock=fixed_clock)
    _assert_value_absent(diagnostic, json.dumps(str(path))[1:-1])


@pytest.mark.parametrize("max_bytes", [-1, -2, -DEFAULT_MAX_BYTES])
def test_a_negative_byte_ceiling_is_refused_before_the_input_is_opened(
    max_bytes: int,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    absent = tmp_path / "absent.csv"
    opened, sizes = _spy_on_open(monkeypatch)

    result = read_binance_kline_csv(
        absent,
        timestamp_unit=US,
        ids=fixed_ids,
        clock=fixed_clock,
        max_bytes=max_bytes,
    )

    assert sizes == []
    assert opened == []
    _single_refusal(
        result,
        RefusalCode.SIZE_CEILING,
        line=WHOLE_INPUT_LINE,
        value_length=0,
        ids=fixed_ids,
        clock=fixed_clock,
    )


def test_the_size_ceilings_refuse_without_truncation(
    binance_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    fixture = binance_root / US_FIXTURE
    assert DEFAULT_MAX_ROWS == 1_048_576
    assert DEFAULT_MAX_BYTES == 64 * 1024 * 1024
    assert fixture.stat().st_size == US_BYTE_COUNT

    def read(**limits: int) -> object:
        return read_binance_kline_csv(
            fixture, timestamp_unit=US, ids=fixed_ids, clock=fixed_clock, **limits
        )

    assert len(_rows(read(max_rows=ROW_COUNT))) == ROW_COUNT
    _single_refusal(
        read(max_rows=ROW_COUNT - 1),
        RefusalCode.SIZE_CEILING,
        line=ROW_COUNT,
        value_length=US_ROW_LENGTH,
        ids=fixed_ids,
        clock=fixed_clock,
    )
    _single_refusal(
        read(max_rows=10),
        RefusalCode.SIZE_CEILING,
        line=11,
        value_length=US_ROW_LENGTH,
        ids=fixed_ids,
        clock=fixed_clock,
    )
    assert len(_rows(read(max_bytes=US_BYTE_COUNT))) == ROW_COUNT
    _single_refusal(
        read(max_bytes=US_BYTE_COUNT - 1),
        RefusalCode.SIZE_CEILING,
        line=WHOLE_INPUT_LINE,
        value_length=US_BYTE_COUNT,
        ids=fixed_ids,
        clock=fixed_clock,
    )
    _single_refusal(
        read(max_bytes=0),
        RefusalCode.SIZE_CEILING,
        line=WHOLE_INPUT_LINE,
        value_length=1,
        ids=fixed_ids,
        clock=fixed_clock,
    )


@pytest.mark.parametrize(
    ("trailer", "line", "value_length"),
    [
        (b"\n" + _line(_us_fields(2)).encode("ascii"), 2, US_ROW_LENGTH),
        (b"", 2, US_ROW_LENGTH),
        (b"\r\n", 2, US_ROW_LENGTH),
        (b"\r", 2, US_ROW_LENGTH + 1),
    ],
)
def test_non_utf8_bytes_are_an_encoding_refusal_naming_the_byte_line(
    trailer: bytes,
    line: int,
    value_length: int,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    corrupt = ",".join(_us_fields(1)).encode("ascii")
    corrupt = corrupt[:17] + b"\xff" + corrupt[18:]
    path = tmp_path / "latin1-byte.csv"
    path.write_bytes(_line(_us_fields(0)).encode("ascii") + corrupt + trailer)

    result = _read(path, US, fixed_ids, fixed_clock)

    _single_refusal(
        result,
        RefusalCode.CSV_ENCODING,
        line=line,
        value_length=value_length,
        ids=fixed_ids,
        clock=fixed_clock,
    )


def test_crlf_line_endings_and_a_missing_final_newline_read_identically(
    tmp_path: Path,
    binance_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    lf_bytes = (binance_root / US_FIXTURE).read_bytes()
    crlf_bytes = lf_bytes.replace(b"\n", b"\r\n")
    crlf = tmp_path / "crlf.csv"
    crlf.write_bytes(crlf_bytes)
    unterminated = tmp_path / "unterminated.csv"
    unterminated.write_bytes(lf_bytes[:-1])
    crlf_unterminated = tmp_path / "crlf-unterminated.csv"
    crlf_unterminated.write_bytes(crlf_bytes[:-2])

    reference = _rows(_read(binance_root / US_FIXTURE, US, fixed_ids, fixed_clock))

    for path in (crlf, unterminated, crlf_unterminated):
        assert _rows(_read(path, US, fixed_ids, fixed_clock)) == reference
    assert [row.line for row in reference] == list(range(1, ROW_COUNT + 1))


def test_reading_is_deterministic(
    binance_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    first = _rows(_read(binance_root / GAPS_FIXTURE, US, fixed_ids, fixed_clock))
    second = _rows(_read(binance_root / GAPS_FIXTURE, US, fixed_ids, fixed_clock))

    assert first == second
    assert [row.open_time_utc for row in first] == [r.open_time_utc for r in second]


# --- the provider contract (reading R7) -----------------------------------------------


def test_an_accepted_input_draws_no_provider_value(binance_root: Path) -> None:
    ids = _CountingIds()
    clock = _CountingClock()

    rows = _rows(_read(binance_root / MS_FIXTURE, MS, ids, clock))

    assert len(rows) == ROW_COUNT
    assert ids.calls == {"dataset_id": 0, "partition_id": 0, "diagnostic_id": 0}
    assert clock.calls == 0


@pytest.mark.parametrize(
    ("name", "unit"),
    [
        ("SYNTHETIC-header-row.csv", US),
        ("SYNTHETIC-empty.csv", US),
        ("SYNTHETIC-ms-declared-us.csv", US),
        ("SYNTHETIC-us-declared-ms.csv", MS),
        ("SYNTHETIC-open-time-21-digits.csv", US),
        ("SYNTHETIC-trades-fractional.csv", US),
    ],
)
def test_a_refusal_draws_the_diagnostic_id_and_the_instant_exactly_once(
    name: str,
    unit: TimestampUnit,
    binance_invalid_root: Path,
) -> None:
    ids = _CountingIds()
    clock = _CountingClock()

    result = _read(binance_invalid_root / name, unit, ids, clock)

    assert isinstance(result, Failure)
    assert ids.calls == {"dataset_id": 0, "partition_id": 0, "diagnostic_id": 1}
    assert clock.calls == 1


def test_a_refused_provider_value_raises_the_contract_error_on_a_refusal_only(
    binance_root: Path,
    binance_invalid_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """A faulty provider is never observed on an accepted input (reading R7)."""
    wrong_unit = binance_invalid_root / "SYNTHETIC-ms-declared-us.csv"
    header = binance_invalid_root / "SYNTHETIC-header-row.csv"

    accepted = _read(binance_root / US_FIXTURE, US, _MalformedIds(), _NaiveClock())
    with pytest.raises(ProviderContractError) as ids_info:
        _read(wrong_unit, US, _MalformedIds(), fixed_clock)
    with pytest.raises(ProviderContractError) as clock_info:
        _read(header, US, fixed_ids, _NaiveClock())

    assert len(_rows(accepted)) == ROW_COUNT
    assert ids_info.value.method == "diagnostic_id"
    assert "not-a-diagnostic-id" not in str(ids_info.value)
    assert ids_info.value.__cause__ is None
    assert clock_info.value.method == "now_utc"
    assert "2026" not in str(clock_info.value)


def test_an_embedded_nul_refusal_still_raises_the_provider_contract_error(
    tmp_path: Path,
    fixed_clock: Clock,
) -> None:
    """The path ``ValueError`` conversion sits outside the provider draws."""
    path = tmp_path / "embedded\x00nul.csv"

    with pytest.raises(ProviderContractError) as caught:
        _read(path, US, _MalformedIds(), fixed_clock)

    assert caught.value.method == "diagnostic_id"
