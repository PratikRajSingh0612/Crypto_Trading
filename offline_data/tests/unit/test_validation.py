"""The section 4 rule matrix over ``ohlcv-csv/1`` rows (Task 2).

One test per section 4 row, pinned on both valid fixtures, on the four new
invalid fixtures and on directly constructed ``CandleRow`` values. Every
refusal is asserted on the same three edges as the reader's: the closed error
code, the one-based line and value length in ``details``, and the absence of
the offending value from the serialized diagnostic. Interval bounds,
duplicate counts, observations and ``row_count`` are pinned with explicit
expected values, never recomputed from the implementation. The reader refuses
a signed or zero price as ``OFFLINE_DATA.CSV_NUMBER`` before the validator can
see it, so the validator's ``PRICE_SANITY`` and ``VOLUME`` rules are exercised
with directly constructed rows and the negative-price fixture is pinned on the
reader's refusal separately.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from crypto_lab.datasets.models import DuplicateInterval, TimeInterval
from crypto_lab.domain.diagnostics import (
    Diagnostic,
    DiagnosticCategory,
    DiagnosticSeverity,
)
from crypto_lab.domain.results import Failure, Success
from pydantic import ValidationError

from crypto_lab_offline_data.candle_csv import (
    FIRST_ROW_LINE,
    WHOLE_INPUT_LINE,
    CandleRow,
    read_ohlcv_csv,
)
from crypto_lab_offline_data.diagnostics import (
    SOURCE_COMPONENT,
    ProviderContractError,
    RefusalCode,
)
from crypto_lab_offline_data.providers import Clock, IdProvider
from crypto_lab_offline_data.validation import (
    DIFFERING_DUPLICATE_OBSERVATION,
    SUPPORTED_TIMEFRAME_SECONDS,
    ValidatedSeries,
    validate_series,
)

GAPS_DUPLICATES_FIXTURE = "btcusdt-1m-gaps-duplicates.valid.csv"
FIXTURE_ROW_COUNT = 60
FIXTURE_BYTE_COUNT = 3821
GAPS_DUPLICATES_DISTINCT_OPEN_TIMES = 58
START = datetime(2024, 1, 1, tzinfo=UTC)
TIMESTAMP_TEXT_LENGTH = 20
MALFORMED_DIAGNOSTIC_ID = "diag_not-a-canonical-uuid4"
NAIVE_INSTANT = datetime(2026, 1, 2, 3, 4, 5)  # noqa: DTZ001
NAIVE_OPEN_TIME = datetime(2024, 1, 1, 0, 1)  # noqa: DTZ001
OFFSET_OPEN_TIME = datetime(
    2024, 1, 1, 5, 31, tzinfo=timezone(timedelta(hours=5, minutes=30))
)
ZERO_OFFSET_OPEN_TIME = datetime(
    2024, 1, 1, 0, 1, tzinfo=timezone(timedelta(0), "zero-offset")
)
OVERSIZED_DIGITS = 300


def _at(minute: int) -> datetime:
    return START + timedelta(minutes=minute)


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


def _bars(*open_times: datetime) -> tuple[CandleRow, ...]:
    """Default-valued rows at the given open times, lines from the first row."""
    return tuple(
        _bar(open_time, line=index + FIRST_ROW_LINE)
        for index, open_time in enumerate(open_times)
    )


def _series(result: Success[ValidatedSeries] | Failure) -> ValidatedSeries:
    assert isinstance(result, Success)
    assert result.outcome == "SUCCESS"
    assert isinstance(result.value, ValidatedSeries)
    return result.value


def _single_refusal(
    result: Success[ValidatedSeries] | Failure,
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


def _read_rows(path: Path, ids: IdProvider, clock: Clock) -> tuple[CandleRow, ...]:
    result = read_ohlcv_csv(path, ids=ids, clock=clock)
    assert isinstance(result, Success)
    return result.value


class _ValueIds:
    """An ``IdProvider`` whose ``diagnostic_id`` hands back one configured value."""

    def __init__(self, value: Any) -> None:
        self._value = value

    def dataset_id(self) -> str:
        return "ds_8b2d4f6a-1c3e-4a5b-b7d9-0e2f4a6c8b1d"

    def partition_id(self) -> str:
        return "part_8b2d4f6a-1c3e-4a5b-b7d9-0e2f4a6c8b1d"

    def diagnostic_id(self) -> Any:
        return self._value


class _ValueClock:
    """A ``Clock`` that hands back one configured value."""

    def __init__(self, value: Any) -> None:
        self._value = value

    def now_utc(self) -> Any:
        return self._value


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


# --- the clean case (section 4 last row; R4, R5) ---------------------------


def test_clean_fixture_is_the_clean_case_with_every_row_kept(
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    rows = _read_rows(clean_fixture, fixed_ids, fixed_clock)

    series = _series(
        validate_series(rows, timeframe="1m", ids=fixed_ids, clock=fixed_clock)
    )

    assert series.rows == rows
    assert len(series.rows) == FIXTURE_ROW_COUNT
    assert series.row_count == FIXTURE_ROW_COUNT
    assert series.missing_intervals == ()
    assert series.duplicate_intervals == ()
    assert series.observations == ()
    assert series.start_utc == _at(0)
    assert series.end_utc == _at(60)
    assert series.end_utc == rows[-1].open_time_utc + timedelta(minutes=1)


def test_validated_series_is_frozen(
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    series = _series(
        validate_series(_bars(_at(0)), timeframe="1m", ids=fixed_ids, clock=fixed_clock)
    )

    with pytest.raises(AttributeError):
        series.row_count = 2  # type: ignore[misc]


# --- gaps and duplicates fixture (Duplicates, Missing bars, Row count) -----


def test_gaps_duplicates_fixture_records_the_gap_and_both_duplicate_groups(
    candles_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    path = candles_root / GAPS_DUPLICATES_FIXTURE
    assert path.stat().st_size == FIXTURE_BYTE_COUNT
    assert path.read_bytes().count(b"\n") == FIXTURE_ROW_COUNT + 1
    rows = _read_rows(path, fixed_ids, fixed_clock)
    assert len(rows) == FIXTURE_ROW_COUNT

    series = _series(
        validate_series(rows, timeframe="1m", ids=fixed_ids, clock=fixed_clock)
    )

    assert series.rows == rows
    assert series.row_count == FIXTURE_ROW_COUNT
    assert series.missing_intervals == (
        TimeInterval(start_utc=_at(20), end_utc=_at(23)),
    )
    assert series.duplicate_intervals == (
        DuplicateInterval(start_utc=_at(30), end_utc=_at(31), duplicate_count=2),
        DuplicateInterval(start_utc=_at(45), end_utc=_at(46), duplicate_count=2),
    )
    assert series.observations == (DIFFERING_DUPLICATE_OBSERVATION,)
    assert series.start_utc == _at(0)
    assert series.end_utc == _at(61)
    assert rows[-1].open_time_utc == _at(60)
    distinct = len({row.open_time_utc for row in rows})
    assert distinct == GAPS_DUPLICATES_DISTINCT_OPEN_TIMES
    extra_rows = sum(d.duplicate_count - 1 for d in series.duplicate_intervals)
    assert series.row_count - extra_rows == distinct
    assert [row.line for row in rows if row.open_time_utc == _at(30)] == [29, 30]
    assert [row.line for row in rows if row.open_time_utc == _at(45)] == [45, 46]
    identical = [row for row in rows if row.open_time_utc == _at(30)]
    assert replace(identical[0], line=0) == replace(identical[1], line=0)
    differing = [row for row in rows if row.open_time_utc == _at(45)]
    assert differing[0].close != differing[1].close
    assert differing[0].volume != differing[1].volume
    assert all(_at(m) not in {r.open_time_utc for r in rows} for m in (20, 21, 22))


def test_differing_duplicate_observation_names_no_value_and_is_bounded_text() -> None:
    assert isinstance(DIFFERING_DUPLICATE_OBSERVATION, str)
    assert 1 <= len(DIFFERING_DUPLICATE_OBSERVATION) <= 1024
    assert "duplicate" in DIFFERING_DUPLICATE_OBSERVATION
    assert "differing" in DIFFERING_DUPLICATE_OBSERVATION
    assert "42000" not in DIFFERING_DUPLICATE_OBSERVATION
    assert "parquet" not in DIFFERING_DUPLICATE_OBSERVATION.lower()


# --- Ordering --------------------------------------------------------------


def test_unsorted_fixture_is_refused_at_the_decreasing_row(
    invalid_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    rows = _read_rows(invalid_root / "unsorted.csv", fixed_ids, fixed_clock)
    assert [row.open_time_utc for row in rows] == [_at(0), _at(2), _at(1)]

    result = validate_series(rows, timeframe="1m", ids=fixed_ids, clock=fixed_clock)

    diagnostic = _single_refusal(
        result,
        RefusalCode.ORDERING,
        line=4,
        value_length=TIMESTAMP_TEXT_LENGTH,
        ids=fixed_ids,
        clock=fixed_clock,
    )
    _assert_value_absent(diagnostic, "2024-01-01T00:01:00Z")


def test_a_decrease_after_a_duplicate_group_is_still_an_ordering_refusal(
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    rows = _bars(_at(0), _at(1), _at(1), _at(0))

    result = validate_series(rows, timeframe="1m", ids=fixed_ids, clock=fixed_clock)

    _single_refusal(
        result,
        RefusalCode.ORDERING,
        line=5,
        value_length=TIMESTAMP_TEXT_LENGTH,
        ids=fixed_ids,
        clock=fixed_clock,
    )


# --- Duplicates ------------------------------------------------------------


def test_identical_duplicates_are_kept_and_recorded_without_an_observation(
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    rows = _bars(_at(0), _at(1), _at(1), _at(1), _at(2))

    series = _series(
        validate_series(rows, timeframe="1m", ids=fixed_ids, clock=fixed_clock)
    )

    assert series.rows == rows
    assert series.row_count == 5
    assert series.duplicate_intervals == (
        DuplicateInterval(start_utc=_at(1), end_utc=_at(2), duplicate_count=3),
    )
    assert series.observations == ()
    assert series.missing_intervals == ()
    assert series.start_utc == _at(0)
    assert series.end_utc == _at(3)


def test_differing_duplicates_raise_one_observation_however_many_groups_differ(
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    rows = (
        _bar(_at(0), line=2),
        _bar(_at(0), line=3, close="42000.75"),
        _bar(_at(1), line=4),
        _bar(_at(1), line=5, volume="7"),
        _bar(_at(2), line=6),
    )

    series = _series(
        validate_series(rows, timeframe="1m", ids=fixed_ids, clock=fixed_clock)
    )

    assert series.rows == rows
    assert series.duplicate_intervals == (
        DuplicateInterval(start_utc=_at(0), end_utc=_at(1), duplicate_count=2),
        DuplicateInterval(start_utc=_at(1), end_utc=_at(2), duplicate_count=2),
    )
    assert series.observations == (DIFFERING_DUPLICATE_OBSERVATION,)
    assert len(set(series.observations)) == len(series.observations)
    assert series.observations == tuple(sorted(series.observations))


def test_duplicates_differing_only_in_decimal_rendering_are_identical(
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """``42000.50`` and ``42000.5`` normalize to the same line, so they agree."""
    rows = (
        _bar(_at(0), line=2, close="42000.50", volume="100.0"),
        _bar(_at(0), line=3, close="42000.5", volume="100"),
    )

    series = _series(
        validate_series(rows, timeframe="1m", ids=fixed_ids, clock=fixed_clock)
    )

    assert series.duplicate_intervals == (
        DuplicateInterval(start_utc=_at(0), end_utc=_at(1), duplicate_count=2),
    )
    assert series.observations == ()


def test_a_duplicate_group_at_the_end_of_the_series_is_recorded(
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    rows = (
        _bar(_at(0), line=2),
        _bar(_at(1), line=3),
        _bar(_at(1), line=4, open_price="42000.25"),
    )

    series = _series(
        validate_series(rows, timeframe="1m", ids=fixed_ids, clock=fixed_clock)
    )

    assert series.duplicate_intervals == (
        DuplicateInterval(start_utc=_at(1), end_utc=_at(2), duplicate_count=2),
    )
    assert series.observations == (DIFFERING_DUPLICATE_OBSERVATION,)
    assert series.end_utc == _at(2)
    assert series.row_count == 3


# --- Timeframe grid --------------------------------------------------------


def test_off_grid_fixture_is_refused_at_the_off_grid_row(
    invalid_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    rows = _read_rows(invalid_root / "off-grid.csv", fixed_ids, fixed_clock)
    assert rows[1].open_time_utc == datetime(2024, 1, 1, 0, 1, 30, tzinfo=UTC)

    result = validate_series(rows, timeframe="1m", ids=fixed_ids, clock=fixed_clock)

    diagnostic = _single_refusal(
        result,
        RefusalCode.TIMEFRAME_GRID,
        line=3,
        value_length=TIMESTAMP_TEXT_LENGTH,
        ids=fixed_ids,
        clock=fixed_clock,
    )
    _assert_value_absent(diagnostic, "2024-01-01T00:01:30Z")


def test_the_clean_one_minute_fixture_is_off_the_five_minute_grid(
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    rows = _read_rows(clean_fixture, fixed_ids, fixed_clock)

    result = validate_series(rows, timeframe="5m", ids=fixed_ids, clock=fixed_clock)

    _single_refusal(
        result,
        RefusalCode.TIMEFRAME_GRID,
        line=3,
        value_length=TIMESTAMP_TEXT_LENGTH,
        ids=fixed_ids,
        clock=fixed_clock,
    )


def test_a_sub_second_open_time_is_off_every_grid(
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    rows = _bars(_at(0), _at(1) + timedelta(microseconds=1))

    result = validate_series(rows, timeframe="1m", ids=fixed_ids, clock=fixed_clock)

    _single_refusal(
        result,
        RefusalCode.TIMEFRAME_GRID,
        line=3,
        value_length=27,
        ids=fixed_ids,
        clock=fixed_clock,
    )


def test_supported_timeframes_are_exactly_the_six_of_section_four() -> None:
    assert SUPPORTED_TIMEFRAME_SECONDS == {
        "1m": 60,
        "5m": 300,
        "15m": 900,
        "1h": 3600,
        "4h": 14400,
        "1d": 86400,
    }
    assert list(SUPPORTED_TIMEFRAME_SECONDS) == ["1m", "5m", "15m", "1h", "4h", "1d"]


@pytest.mark.parametrize(
    ("timeframe", "step"),
    [
        ("1m", timedelta(minutes=1)),
        ("5m", timedelta(minutes=5)),
        ("15m", timedelta(minutes=15)),
        ("1h", timedelta(hours=1)),
        ("4h", timedelta(hours=4)),
        ("1d", timedelta(days=1)),
    ],
)
def test_each_supported_timeframe_validates_rows_on_its_grid_half_open(
    timeframe: str,
    step: timedelta,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    rows = _bars(START, START + step, START + 2 * step)

    series = _series(
        validate_series(rows, timeframe=timeframe, ids=fixed_ids, clock=fixed_clock)
    )

    assert series.rows == rows
    assert series.start_utc == START
    assert series.end_utc == START + 3 * step
    assert series.missing_intervals == ()
    assert series.duplicate_intervals == ()
    assert series.row_count == 3
    off_grid = _bars(START, START + step // 2)
    off_grid_result = validate_series(
        off_grid, timeframe=timeframe, ids=fixed_ids, clock=fixed_clock
    )
    _single_refusal(
        off_grid_result,
        RefusalCode.TIMEFRAME_GRID,
        line=3,
        value_length=TIMESTAMP_TEXT_LENGTH,
        ids=fixed_ids,
        clock=fixed_clock,
    )


@pytest.mark.parametrize(
    "timeframe",
    ["1s", "30s", "1w", "2m", "60m", "3h", "2d", "1M", "1H", "m1", "", "1m "],
)
def test_an_unsupported_timeframe_is_refused_for_the_whole_input(
    timeframe: str,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """The slice supports six timeframes; the rest are refused before any row."""
    rows = _bars(_at(0), _at(1))

    result = validate_series(
        rows, timeframe=timeframe, ids=fixed_ids, clock=fixed_clock
    )

    diagnostic = _single_refusal(
        result,
        RefusalCode.TIMEFRAME_GRID,
        line=WHOLE_INPUT_LINE,
        value_length=len(timeframe),
        ids=fixed_ids,
        clock=fixed_clock,
    )
    if timeframe.strip():
        assert timeframe not in diagnostic.message
        assert timeframe not in json.dumps(diagnostic.details)


def test_an_unsupported_timeframe_is_refused_before_an_empty_series(
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    result = validate_series((), timeframe="2m", ids=fixed_ids, clock=fixed_clock)

    _single_refusal(
        result,
        RefusalCode.TIMEFRAME_GRID,
        line=WHOLE_INPUT_LINE,
        value_length=2,
        ids=fixed_ids,
        clock=fixed_clock,
    )


# --- Missing bars ----------------------------------------------------------


def test_a_single_missing_bar_is_one_half_open_interval(
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    rows = _bars(_at(0), _at(2))

    series = _series(
        validate_series(rows, timeframe="1m", ids=fixed_ids, clock=fixed_clock)
    )

    assert series.rows == rows
    assert series.missing_intervals == (TimeInterval(start_utc=_at(1), end_utc=_at(2)),)
    assert series.duplicate_intervals == ()
    assert series.observations == ()
    assert series.row_count == 2
    assert series.start_utc == _at(0)
    assert series.end_utc == _at(3)


def test_several_gaps_are_recorded_in_order_and_never_filled(
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    rows = _bars(_at(0), _at(1), _at(4), _at(5), _at(9))

    series = _series(
        validate_series(rows, timeframe="1m", ids=fixed_ids, clock=fixed_clock)
    )

    assert series.rows == rows
    assert len(series.rows) == 5
    assert series.missing_intervals == (
        TimeInterval(start_utc=_at(2), end_utc=_at(4)),
        TimeInterval(start_utc=_at(6), end_utc=_at(9)),
    )
    keys = [(i.start_utc, i.end_utc) for i in series.missing_intervals]
    assert keys == sorted(keys)
    assert series.end_utc == _at(10)


def test_a_gap_after_a_duplicate_group_starts_one_step_after_the_group(
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    rows = _bars(_at(0), _at(0), _at(3))

    series = _series(
        validate_series(rows, timeframe="1m", ids=fixed_ids, clock=fixed_clock)
    )

    assert series.duplicate_intervals == (
        DuplicateInterval(start_utc=_at(0), end_utc=_at(1), duplicate_count=2),
    )
    assert series.missing_intervals == (TimeInterval(start_utc=_at(1), end_utc=_at(3)),)
    assert series.row_count == 3


def test_a_gap_on_the_daily_grid_is_measured_in_days(
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    rows = _bars(START, START + timedelta(days=3))

    series = _series(
        validate_series(rows, timeframe="1d", ids=fixed_ids, clock=fixed_clock)
    )

    assert series.missing_intervals == (
        TimeInterval(
            start_utc=START + timedelta(days=1), end_utc=START + timedelta(days=3)
        ),
    )
    assert series.end_utc == START + timedelta(days=4)


# --- Price sanity ----------------------------------------------------------


def test_high_below_low_fixture_passes_the_reader_and_is_refused_by_the_validator(
    invalid_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    rows = _read_rows(invalid_root / "high-below-low.csv", fixed_ids, fixed_clock)
    assert rows[1].high == Decimal("41998.01")
    assert rows[1].low == Decimal("41999.01")

    result = validate_series(rows, timeframe="1m", ids=fixed_ids, clock=fixed_clock)

    diagnostic = _single_refusal(
        result,
        RefusalCode.PRICE_SANITY,
        line=3,
        value_length=8,
        ids=fixed_ids,
        clock=fixed_clock,
    )
    _assert_value_absent(diagnostic, "41998.01")


def test_negative_price_fixture_is_refused_by_the_reader_as_a_csv_number(
    invalid_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """Task 1's numeric refusal is preserved: the validator never sees the row."""
    result = read_ohlcv_csv(
        invalid_root / "negative-price.csv", ids=fixed_ids, clock=fixed_clock
    )

    assert isinstance(result, Failure)
    diagnostic = result.diagnostics[0]
    assert diagnostic.error_code == RefusalCode.CSV_NUMBER.value
    assert diagnostic.error_code != RefusalCode.PRICE_SANITY.value
    assert diagnostic.details == {
        "line": 3,
        "rule": RefusalCode.CSV_NUMBER.value,
        "value_length": 9,
    }
    _assert_value_absent(diagnostic, "-42000.01")


@pytest.mark.parametrize(
    ("overrides", "value_length", "offending"),
    [
        ({"open_price": "-41999.5"}, 8, "-41999.5"),
        ({"high": "0"}, 1, None),
        ({"low": "-0.25"}, 5, "-0.25"),
        ({"close": "0"}, 1, None),
        ({"high": "41998.75", "close": "41998.9"}, 8, "41998.75"),
        ({"open_price": "42001.125"}, 9, "42001.125"),
        ({"open_price": "41998.875"}, 9, "41998.875"),
        ({"close": "42001.375"}, 9, "42001.375"),
        ({"close": "41998.625"}, 9, "41998.625"),
    ],
)
def test_price_sanity_violations_in_constructed_rows_are_refused(
    overrides: dict[str, str],
    value_length: int,
    offending: str | None,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """Non-positive prices and prices outside ``[low, high]`` are refusals."""
    rows = (_bar(_at(0), line=2), _bar(_at(1), line=3, **overrides))

    result = validate_series(rows, timeframe="1m", ids=fixed_ids, clock=fixed_clock)

    diagnostic = _single_refusal(
        result,
        RefusalCode.PRICE_SANITY,
        line=3,
        value_length=value_length,
        ids=fixed_ids,
        clock=fixed_clock,
    )
    if offending is not None:
        _assert_value_absent(diagnostic, offending)


def test_prices_on_the_boundaries_of_the_range_are_sane(
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    rows = (
        _bar(_at(0), line=2, open_price="41999", close="42001"),
        _bar(_at(1), line=3, open_price="42001", close="41999"),
        _bar(_at(2), line=4, open_price="5", high="5", low="5", close="5"),
    )

    series = _series(
        validate_series(rows, timeframe="1m", ids=fixed_ids, clock=fixed_clock)
    )

    assert series.rows == rows


# --- Volume ----------------------------------------------------------------


def test_a_negative_volume_in_a_constructed_row_is_refused(
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    rows = (_bar(_at(0), line=2), _bar(_at(1), line=3, volume="-0.5"))

    result = validate_series(rows, timeframe="1m", ids=fixed_ids, clock=fixed_clock)

    diagnostic = _single_refusal(
        result,
        RefusalCode.VOLUME,
        line=3,
        value_length=4,
        ids=fixed_ids,
        clock=fixed_clock,
    )
    _assert_value_absent(diagnostic, "-0.5")


def test_a_zero_volume_is_accepted(
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    rows = (_bar(_at(0), line=2, volume="0"), _bar(_at(1), line=3, volume="0.0"))

    series = _series(
        validate_series(rows, timeframe="1m", ids=fixed_ids, clock=fixed_clock)
    )

    assert series.rows == rows


# --- Decimal form ----------------------------------------------------------


@pytest.mark.parametrize(
    ("overrides", "value_length"),
    [
        ({"open_price": "NaN"}, 3),
        ({"high": "Infinity"}, 8),
        ({"volume": "-0"}, 2),
        ({"close": "1" * OVERSIZED_DIGITS}, OVERSIZED_DIGITS),
    ],
)
def test_a_value_without_a_canonical_form_is_refused_as_a_csv_number(
    overrides: dict[str, str],
    value_length: int,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """Non-finite, negative-zero and oversized values have no ``format_decimal``.

    The reader's grammar never admits them; a directly constructed row that
    carries one is refused with the reader's own code, and the core
    ``ValueError`` behind the refusal never escapes.
    """
    rows = (_bar(_at(0), line=2), _bar(_at(1), line=3, **overrides))

    result = validate_series(rows, timeframe="1m", ids=fixed_ids, clock=fixed_clock)

    _single_refusal(
        result,
        RefusalCode.CSV_NUMBER,
        line=3,
        value_length=value_length,
        ids=fixed_ids,
        clock=fixed_clock,
    )


# --- Timezone --------------------------------------------------------------


@pytest.mark.parametrize(
    ("open_time", "value_length", "offending"),
    [
        (NAIVE_OPEN_TIME, 19, "2024-01-01T00:01:00"),
        (OFFSET_OPEN_TIME, 25, "2024-01-01T05:31:00+05:30"),
    ],
)
def test_a_naive_or_offset_open_time_in_a_constructed_row_is_refused(
    open_time: datetime,
    value_length: int,
    offending: str,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    rows = (_bar(_at(0), line=2), _bar(open_time, line=3))

    result = validate_series(rows, timeframe="1m", ids=fixed_ids, clock=fixed_clock)

    diagnostic = _single_refusal(
        result,
        RefusalCode.CSV_TIMESTAMP,
        line=3,
        value_length=value_length,
        ids=fixed_ids,
        clock=fixed_clock,
    )
    _assert_value_absent(diagnostic, offending)


def test_a_zero_offset_open_time_is_utc(
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    rows = (_bar(_at(0), line=2), _bar(ZERO_OFFSET_OPEN_TIME, line=3))

    series = _series(
        validate_series(rows, timeframe="1m", ids=fixed_ids, clock=fixed_clock)
    )

    assert series.rows == rows
    assert series.end_utc == _at(2)
    assert series.end_utc.utcoffset() == timedelta(0)


# --- Interval and row count ------------------------------------------------


def test_a_single_row_spans_exactly_one_step(
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    rows = _bars(_at(7))

    series = _series(
        validate_series(rows, timeframe="1m", ids=fixed_ids, clock=fixed_clock)
    )

    assert series.start_utc == _at(7)
    assert series.end_utc == _at(8)
    assert series.row_count == 1
    assert series.start_utc.tzinfo is not None
    assert series.start_utc.utcoffset() == timedelta(0)
    assert series.end_utc.utcoffset() == timedelta(0)


def test_row_count_counts_every_kept_row_including_duplicates(
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    rows = _bars(_at(0), _at(0), _at(0), _at(1), _at(5))

    series = _series(
        validate_series(rows, timeframe="1m", ids=fixed_ids, clock=fixed_clock)
    )

    assert series.row_count == 5
    assert series.row_count == len(series.rows)
    assert series.duplicate_intervals[0].duplicate_count == 3
    assert series.missing_intervals == (TimeInterval(start_utc=_at(2), end_utc=_at(5)),)


# --- Empty series ----------------------------------------------------------


def test_an_empty_row_tuple_is_the_reader_header_only_refusal(
    invalid_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """Task 1 and Task 2 pin one answer: the same ``Failure``, field for field."""
    from_reader = read_ohlcv_csv(
        invalid_root / "header-only.csv", ids=fixed_ids, clock=fixed_clock
    )

    from_validator = validate_series(
        (), timeframe="1m", ids=fixed_ids, clock=fixed_clock
    )

    _single_refusal(
        from_validator,
        RefusalCode.EMPTY_SERIES,
        line=FIRST_ROW_LINE,
        value_length=0,
        ids=fixed_ids,
        clock=fixed_clock,
    )
    assert FIRST_ROW_LINE == 2
    assert from_validator == from_reader


# --- Check order -----------------------------------------------------------


@pytest.mark.parametrize(
    ("rows", "code", "line"),
    [
        (
            (_bar(_at(0), line=2), _bar(NAIVE_OPEN_TIME, line=3, open_price="-1")),
            RefusalCode.CSV_TIMESTAMP,
            3,
        ),
        (
            (
                _bar(_at(0), line=2),
                _bar(_at(1) + timedelta(seconds=30), line=3, open_price="-1"),
            ),
            RefusalCode.TIMEFRAME_GRID,
            3,
        ),
        (
            (
                _bar(_at(0), line=2),
                _bar(_at(1), line=3, open_price="NaN", high="1", low="2"),
            ),
            RefusalCode.CSV_NUMBER,
            3,
        ),
        (
            (_bar(_at(0), line=2), _bar(_at(1), line=3, high="1", volume="-1")),
            RefusalCode.PRICE_SANITY,
            3,
        ),
        (
            (_bar(_at(1), line=2), _bar(_at(0), line=3, volume="-1")),
            RefusalCode.VOLUME,
            3,
        ),
        (
            (_bar(_at(2), line=2), _bar(_at(1) + timedelta(seconds=30), line=3)),
            RefusalCode.TIMEFRAME_GRID,
            3,
        ),
    ],
)
def test_a_row_breaking_two_rules_is_refused_by_the_documented_first_rule(
    rows: tuple[CandleRow, ...],
    code: RefusalCode,
    line: int,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """Per row: timezone, grid, decimal form, price sanity, volume, then ordering."""
    result = validate_series(rows, timeframe="1m", ids=fixed_ids, clock=fixed_clock)

    assert isinstance(result, Failure)
    assert result.diagnostics[0].error_code == code.value
    assert result.diagnostics[0].details["line"] == line


# --- Provider contract (R7) ------------------------------------------------


def test_validate_series_draws_no_provider_value_when_it_accepts_the_rows(
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    rows = _read_rows(clean_fixture, fixed_ids, fixed_clock)
    ids = _CountingIds()
    clock = _CountingClock()

    counted = validate_series(rows, timeframe="1m", ids=ids, clock=clock)
    faulty = validate_series(
        rows,
        timeframe="1m",
        ids=_ValueIds(MALFORMED_DIAGNOSTIC_ID),
        clock=_ValueClock(NAIVE_INSTANT),
    )

    assert isinstance(counted, Success)
    assert isinstance(faulty, Success)
    assert ids.calls == {"dataset_id": 0, "partition_id": 0, "diagnostic_id": 0}
    assert clock.calls == 0


def test_validate_series_draws_each_provider_value_exactly_once_on_a_refusal() -> None:
    ids = _CountingIds()
    clock = _CountingClock()

    result = validate_series(
        _bars(_at(1), _at(0)), timeframe="1m", ids=ids, clock=clock
    )

    assert isinstance(result, Failure)
    assert ids.calls == {"dataset_id": 0, "partition_id": 0, "diagnostic_id": 1}
    assert clock.calls == 1


@pytest.mark.parametrize(
    "rows",
    [(), _bars(_at(1), _at(0)), (_bar(_at(0), line=2, volume="-1"),)],
)
def test_validate_series_raises_the_contract_error_for_a_malformed_id(
    rows: tuple[CandleRow, ...],
    fixed_clock: Clock,
) -> None:
    with pytest.raises(RuntimeError) as info:
        validate_series(
            rows,
            timeframe="1m",
            ids=_ValueIds(MALFORMED_DIAGNOSTIC_ID),
            clock=fixed_clock,
        )

    error = info.value
    assert type(error) is ProviderContractError
    assert not isinstance(error, ValidationError)
    assert error.method == "diagnostic_id"
    assert error.__cause__ is None
    assert MALFORMED_DIAGNOSTIC_ID not in str(error)


def test_validate_series_raises_the_contract_error_for_a_naive_instant(
    fixed_ids: IdProvider,
) -> None:
    with pytest.raises(RuntimeError) as info:
        validate_series(
            _bars(_at(0), _at(1) + timedelta(seconds=1)),
            timeframe="1m",
            ids=fixed_ids,
            clock=_ValueClock(NAIVE_INSTANT),
        )

    error = info.value
    assert type(error) is ProviderContractError
    assert error.method == "now_utc"
    assert str(NAIVE_INSTANT) not in str(error)


def test_validate_series_raises_the_contract_error_for_an_unsupported_timeframe(
    fixed_clock: Clock,
) -> None:
    """The whole-input timeframe refusal draws the providers like every refusal."""
    with pytest.raises(RuntimeError) as info:
        validate_series(
            _bars(_at(0)),
            timeframe="2m",
            ids=_ValueIds(MALFORMED_DIAGNOSTIC_ID),
            clock=fixed_clock,
        )

    assert type(info.value) is ProviderContractError
