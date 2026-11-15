"""The section 4 validation rules over ``ohlcv-csv/1`` rows.

``validate_series`` takes the rows the reader accepted, in input order, and
either returns a ``ValidatedSeries`` or one section 5.4 refusal. Every row is
kept and the order is preserved: nothing is interpolated, dropped or
de-duplicated. The checks run in one documented order. For the whole input:
the timeframe must be one of the six this slice supports (``1m``, ``5m``,
``15m``, ``1h``, ``4h``, ``1d``; any other value is the refusal
``OFFLINE_DATA.TIMEFRAME_GRID`` at line ``0`` naming only the length of the
value), then the series must hold at least one row (``OFFLINE_DATA.EMPTY_SERIES``
at line ``2``, the reader's header-only answer). Then per row, in input order:
the open time must be timezone-aware UTC (``OFFLINE_DATA.CSV_TIMESTAMP``); it
must sit on the timeframe grid from the Unix epoch
(``OFFLINE_DATA.TIMEFRAME_GRID``); each of the five values must have a canonical
``format_decimal`` form (``OFFLINE_DATA.CSV_NUMBER``: non-finite, negative-zero
and over-long values, which the reader's grammar never admits); the four prices
must be positive, ``high`` must not be below ``low`` and ``open`` and ``close``
must lie within ``[low, high]`` (``OFFLINE_DATA.PRICE_SANITY``, naming the first
field in the order open, high, low, close that breaks a rule, then ``high`` for
a reversed range, then ``open`` and ``close`` for a value outside the range);
the volume must be non-negative (``OFFLINE_DATA.VOLUME``); and the open time
must not decrease (``OFFLINE_DATA.ORDERING``). The refusal names the one-based
line of the row and the length of the offending value in its canonical text
(``format_utc`` for an open time, ``isoformat`` for one that is not UTC,
``format_decimal`` for a number, ``str`` for a number without a canonical form),
never the value.

Equal consecutive open times form one duplicate group recorded as a
``DuplicateInterval`` over one step with the group's row count; a group whose
rows differ in any of the five values (compared as ``Decimal`` values, so
``42000.50`` and ``42000.5`` agree) raises the single partition observation
``DIFFERING_DUPLICATE_OBSERVATION``. A jump of more than one step between
distinct open times records a ``TimeInterval`` from the first missing open time
to the next present one. The series bounds are half-open: ``start_utc`` is the
first open time and ``end_utc`` the last open time plus one step (reading R5).
``row_count`` is the number of rows kept, duplicates included.

The core ``ValueError`` reachable here (``require_utc`` on a row's open time,
``format_decimal`` on a row's value) is converted into a refusal; every
provider draw happens through ``refusal`` outside those handlers, so a
``ProviderContractError`` (reading R7) is the only exception that crosses this
boundary and no provider is drawn on the accepting path.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal

from crypto_lab.datasets.models import DuplicateInterval, TimeInterval
from crypto_lab.domain.financial import format_decimal
from crypto_lab.domain.results import Failure, Success
from crypto_lab.domain.time import format_utc, require_utc

from crypto_lab_offline_data.candle_csv import (
    FIRST_ROW_LINE,
    WHOLE_INPUT_LINE,
    CandleRow,
)
from crypto_lab_offline_data.diagnostics import RefusalCode, refusal
from crypto_lab_offline_data.providers import Clock, IdProvider

#: The timeframes this slice supports and their step in seconds (section 4).
SUPPORTED_TIMEFRAME_SECONDS = {
    "1m": 60,
    "5m": 300,
    "15m": 900,
    "1h": 3600,
    "4h": 14400,
    "1d": 86400,
}
#: The partition quality observation raised when a duplicate group differs.
DIFFERING_DUPLICATE_OBSERVATION = (
    "duplicate open times with differing values: every source row is kept and "
    "none is reconciled; see duplicate_intervals"
)


@dataclass(frozen=True, slots=True)
class ValidatedSeries:
    """The accepted rows with the section 4 facts about them."""

    rows: tuple[CandleRow, ...]
    missing_intervals: tuple[TimeInterval, ...]
    duplicate_intervals: tuple[DuplicateInterval, ...]
    observations: tuple[str, ...]
    start_utc: datetime
    end_utc: datetime
    row_count: int


type ValidationResult = Success[ValidatedSeries] | Failure


def validate_series(
    rows: tuple[CandleRow, ...],
    *,
    timeframe: str,
    ids: IdProvider,
    clock: Clock,
) -> ValidationResult:
    """Apply the section 4 rules to ``rows`` in order, or return one refusal."""
    step_seconds = SUPPORTED_TIMEFRAME_SECONDS.get(timeframe)
    if step_seconds is None:
        return refusal(
            RefusalCode.TIMEFRAME_GRID,
            line=WHOLE_INPUT_LINE,
            value_length=len(timeframe),
            ids=ids,
            clock=clock,
        )
    if not rows:
        return refusal(
            RefusalCode.EMPTY_SERIES,
            line=FIRST_ROW_LINE,
            value_length=0,
            ids=ids,
            clock=clock,
        )
    step = timedelta(seconds=step_seconds)
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    times: list[datetime] = []
    for row in rows:
        open_time = _utc_or_none(row.open_time_utc)
        if open_time is None:
            return refusal(
                RefusalCode.CSV_TIMESTAMP,
                line=row.line,
                value_length=len(row.open_time_utc.isoformat()),
                ids=ids,
                clock=clock,
            )
        if (open_time - epoch) % step:
            return refusal(
                RefusalCode.TIMEFRAME_GRID,
                line=row.line,
                value_length=len(format_utc(open_time)),
                ids=ids,
                clock=clock,
            )
        refused = _refused_value(row)
        if refused is not None:
            code, value_length = refused
            return refusal(
                code,
                line=row.line,
                value_length=value_length,
                ids=ids,
                clock=clock,
            )
        if times and open_time < times[-1]:
            return refusal(
                RefusalCode.ORDERING,
                line=row.line,
                value_length=len(format_utc(open_time)),
                ids=ids,
                clock=clock,
            )
        times.append(open_time)
    missing, duplicates, differing = _quality_facts(rows, times, step)
    series = ValidatedSeries(
        rows=rows,
        missing_intervals=missing,
        duplicate_intervals=duplicates,
        observations=(DIFFERING_DUPLICATE_OBSERVATION,) if differing else (),
        start_utc=times[0],
        end_utc=times[-1] + step,
        row_count=len(rows),
    )
    return Success[ValidatedSeries](outcome="SUCCESS", value=series)


def _quality_facts(
    rows: tuple[CandleRow, ...],
    times: list[datetime],
    step: timedelta,
) -> tuple[tuple[TimeInterval, ...], tuple[DuplicateInterval, ...], bool]:
    """The missing intervals, duplicate intervals and differing flag of a series.

    ``times`` holds the validated UTC open time of each row, non-decreasing and
    on the grid. Each run of equal open times is one duplicate group; a jump of
    more than one step from a group's open time to the next records a gap.
    """
    missing: list[TimeInterval] = []
    duplicates: list[DuplicateInterval] = []
    differing = False
    group_start = 0
    for index in range(1, len(rows) + 1):
        if index < len(rows) and times[index] == times[group_start]:
            continue
        group_time = times[group_start]
        group_size = index - group_start
        if group_size >= 2:
            duplicates.append(
                DuplicateInterval(
                    start_utc=group_time,
                    end_utc=group_time + step,
                    duplicate_count=group_size,
                )
            )
            if any(
                not _same_values(rows[member], rows[group_start])
                for member in range(group_start + 1, index)
            ):
                differing = True
        if index < len(rows) and times[index] > group_time + step:
            missing.append(
                TimeInterval(start_utc=group_time + step, end_utc=times[index])
            )
        group_start = index
    return tuple(missing), tuple(duplicates), differing


def _utc_or_none(value: datetime) -> datetime | None:
    """``value`` as UTC when it is timezone-aware UTC, else ``None``.

    The core ``ValueError`` is converted here, outside every provider draw.
    """
    try:
        return require_utc(value)
    except ValueError:
        return None


def _canonical_or_none(value: Decimal) -> str | None:
    """The ``format_decimal`` text of ``value``, or ``None`` when it has none."""
    try:
        return format_decimal(value)
    except ValueError:
        return None


def _refused_value(row: CandleRow) -> tuple[RefusalCode, int] | None:
    """The refusal code and offending value length for ``row``'s values, if any.

    Decimal form first (every value must have a canonical text), then the
    price rules in the order open, high, low, close for positivity, ``high``
    for a reversed range and ``open`` then ``close`` for a value outside
    ``[low, high]``, then the volume sign.
    """
    prices = (
        ("open", row.open),
        ("high", row.high),
        ("low", row.low),
        ("close", row.close),
    )
    canonical: dict[str, str] = {}
    for name, value in (*prices, ("volume", row.volume)):
        text = _canonical_or_none(value)
        if text is None:
            return RefusalCode.CSV_NUMBER, len(str(value))
        canonical[name] = text
    for name, price in prices:
        if price <= 0:
            return RefusalCode.PRICE_SANITY, len(canonical[name])
    if row.high < row.low:
        return RefusalCode.PRICE_SANITY, len(canonical["high"])
    for name, price in (("open", row.open), ("close", row.close)):
        if price < row.low or price > row.high:
            return RefusalCode.PRICE_SANITY, len(canonical[name])
    if row.volume < 0:
        return RefusalCode.VOLUME, len(canonical["volume"])
    return None


def _same_values(row: CandleRow, other: CandleRow) -> bool:
    """Whether two rows agree in all five values, compared as ``Decimal``."""
    return (row.open, row.high, row.low, row.close, row.volume) == (
        other.open,
        other.high,
        other.low,
        other.close,
        other.volume,
    )
