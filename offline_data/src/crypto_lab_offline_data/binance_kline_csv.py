"""The strict ``binance-spot-kline-csv/1`` reader (second-slice plan, section 2).

Input contract: an already extracted Binance Spot historical kline CSV file as
the user placed it on disk, with the twelve documented columns in the
documented order (open time, open, high, low, close, volume, close time, quote
asset volume, number of trades, taker buy base asset volume, taker buy quote
asset volume, ignore) and no header row. The caller declares the unit of the
two time columns (``TimestampUnit``: ``milliseconds`` for Spot files before
2025-01-01, ``microseconds`` from that date); the reader never guesses it, and
the declared unit applies to the whole file.

The shared rules are the ``ohlcv-csv/1`` reader's own, reused by import: the
input-path and size-ceiling rules, UTF-8 without a byte order mark, LF or CRLF
line endings, a missing final newline accepted, the number grammar and the
refusal construction. The format's own rules apply per line in field order,
so a row that breaks two rules is refused by the first:

- Line 1 is held to the header rule first: a first comma-separated field that
  is not an unsigned decimal integer of one to twenty digits (a blank line, a
  documented-column-names header, a pipe-delimited line) is ``CSV_HEADER`` at
  line 1 with the line's length. An empty file is ``EMPTY_SERIES`` at line 1,
  the line at which the first data row was expected. Once the rule passes,
  every line, line 1 included, is a data row.
- Exactly twelve comma-separated fields, else ``CSV_ROW_SHAPE`` with the line's
  length (a blank body line included).
- Fields 1 and 7 (open and close time) are ``[0-9]{1,20}``, else
  ``CSV_TIMESTAMP`` with the field's length: a longer digit run is refused by
  the grammar before any integer conversion, so the interpreter's
  integer-string digit limit is never reached. The integer is then checked
  against the admissible window on the integer itself,
  ``1483228800 * divisor <= value < 4102444800 * divisor`` (the epoch seconds
  of 2017-01-01T00:00:00Z and 2100-01-01T00:00:00Z), else ``TIMESTAMP_UNIT``
  with the field's length; a millisecond value declared as microseconds (1970)
  and a microsecond value declared as milliseconds (far beyond 2100) are
  exactly what this rule refuses. The close time must be strictly greater than
  the open time, else ``CSV_TIMESTAMP`` with the close field's length; no
  interval relation is enforced because the reader checks no timeframe.
- Fields 2 to 5 are positive numbers and fields 6, 8, 10 and 11 numbers under
  the slice-1 grammar (exact ``Decimal``, no sign, no exponent, within the
  core's canonical bound), else ``CSV_NUMBER`` with the field's length; field
  9 is an unsigned integer within the same bound, else ``CSV_NUMBER``.
- Field 12, checked last, may hold no carriage return, else ``CSV_ROW_SHAPE``
  with the line's length: the splitter consumes only LF and CRLF, so a lone
  terminal carriage return, the first carriage return of a CR CR LF ending and
  a carriage return embedded in the field all stay in the logical row, whose
  recorded length counts them and excludes the consumed delimiter; nothing is
  stripped or repaired. Otherwise field 12 is any comma-free text and is not
  interpreted.

Only fields 1 to 6 are retained, as the unchanged ``CandleRow``: fields 7 to 12
are checked for shape and dropped. The open time is converted by integer
arithmetic alone (``divmod`` by the unit's divisor, then a ``timedelta`` of
whole seconds and microseconds from the epoch), so the instant is exact and no
float is ever used, and because the window check precedes construction no
``OverflowError`` or ``ValueError`` can arise. Grid, spacing, ordering, gaps
and duplicates stay ``validate_series`` rules on the retained open time. The
reader writes nothing, draws its providers only when it builds a refusal, and
lets only ``ProviderContractError`` cross (reading R7); a diagnostic names the
line, the rule and the offending value's length, never the value.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from pathlib import Path

from crypto_lab.domain.results import Failure, Success

from crypto_lab_offline_data.candle_csv import (
    _LINE_BREAK,
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_ROWS,
    PRICE_FIELD_COUNT,
    WHOLE_INPUT_LINE,
    CandleRow,
    ReadResult,
    _byte_line,
    _byte_line_length,
    _parse_number,
    _read_bounded,
)
from crypto_lab_offline_data.diagnostics import RefusalCode, refusal
from crypto_lab_offline_data.providers import Clock, IdProvider

#: The twelve documented kline columns of one row (section 2.2).
FIELD_COUNT = 12
#: There is no header row: the first data row is line 1.
FIRST_ROW_LINE = 1
#: The longest digit run the time grammar admits; ``int`` is applied to no
#: longer token, so the interpreter's integer-string limit is never reached.
MAX_TIMESTAMP_DIGITS = 20
#: The admissible window on the integer: the epoch seconds of
#: 2017-01-01T00:00:00Z (inclusive) and 2100-01-01T00:00:00Z (exclusive), as
#: integer literals so that import time constructs no ``datetime``.
WINDOW_START_SECONDS = 1_483_228_800
WINDOW_END_SECONDS = 4_102_444_800
_MICROSECONDS_PER_SECOND = 1_000_000
_TIMESTAMP_PATTERN = re.compile(r"[0-9]{1,20}")
_COUNT_PATTERN = re.compile(r"[0-9]+")
#: Zero-based positions of the time, count and ignore fields (section 2.2
#: numbers the fields 1 to 12).
_OPEN_TIME = 0
_CLOSE_TIME = 6
_TRADES = 8
_IGNORE = 11


class TimestampUnit(StrEnum):
    """The unit of the open and close time fields, declared by the caller."""

    MILLISECONDS = "milliseconds"
    MICROSECONDS = "microseconds"


#: Units per second of each declared unit: the divisor of the window check and
#: of the integer conversion.
UNIT_DIVISORS = {
    TimestampUnit.MILLISECONDS: 1_000,
    TimestampUnit.MICROSECONDS: 1_000_000,
}


def read_binance_kline_csv(
    path: Path,
    *,
    timestamp_unit: TimestampUnit,
    ids: IdProvider,
    clock: Clock,
    max_rows: int = DEFAULT_MAX_ROWS,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> ReadResult:
    """Read one ``binance-spot-kline-csv/1`` input into its rows, or refuse once.

    ``timestamp_unit`` is the declared unit of fields 1 and 7 for the whole
    file. The shared rules come first in the slice-1 order (negative ceiling,
    input path, byte ceiling, encoding), then the line-1 header rule, then
    every line as a data row in field order; the row ceiling is checked before
    a row is parsed.
    """
    divisor = UNIT_DIVISORS[timestamp_unit]
    if max_bytes < 0:
        return refusal(
            RefusalCode.SIZE_CEILING,
            line=WHOLE_INPUT_LINE,
            value_length=0,
            ids=ids,
            clock=clock,
        )
    data = _read_bounded(path, max_bytes)
    if data is None:
        return refusal(
            RefusalCode.INPUT_PATH,
            line=WHOLE_INPUT_LINE,
            value_length=0,
            ids=ids,
            clock=clock,
        )
    if len(data) > max_bytes:
        return refusal(
            RefusalCode.SIZE_CEILING,
            line=WHOLE_INPUT_LINE,
            value_length=len(data),
            ids=ids,
            clock=clock,
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        return refusal(
            RefusalCode.CSV_ENCODING,
            line=_byte_line(data, error.start),
            value_length=_byte_line_length(data, error.start),
            ids=ids,
            clock=clock,
        )
    lines = _LINE_BREAK.split(text)
    if lines[-1] == "":
        lines.pop()
    if not lines:
        return refusal(
            RefusalCode.EMPTY_SERIES,
            line=FIRST_ROW_LINE,
            value_length=0,
            ids=ids,
            clock=clock,
        )
    if _TIMESTAMP_PATTERN.fullmatch(lines[0].partition(",")[0]) is None:
        return refusal(
            RefusalCode.CSV_HEADER,
            line=FIRST_ROW_LINE,
            value_length=len(lines[0]),
            ids=ids,
            clock=clock,
        )
    rows: list[CandleRow] = []
    for line, record in enumerate(lines, start=FIRST_ROW_LINE):
        if line > max_rows:
            return refusal(
                RefusalCode.SIZE_CEILING,
                line=line,
                value_length=len(record),
                ids=ids,
                clock=clock,
            )
        parsed = _parse_row(record, line, divisor=divisor, ids=ids, clock=clock)
        if isinstance(parsed, Failure):
            return parsed
        rows.append(parsed)
    return Success[tuple[CandleRow, ...]](outcome="SUCCESS", value=tuple(rows))


def _parse_row(
    record: str,
    line: int,
    *,
    divisor: int,
    ids: IdProvider,
    clock: Clock,
) -> CandleRow | Failure:
    """One data row in field order; the first broken rule is the refusal."""
    fields = record.split(",")
    if len(fields) != FIELD_COUNT:
        return refusal(
            RefusalCode.CSV_ROW_SHAPE,
            line=line,
            value_length=len(record),
            ids=ids,
            clock=clock,
        )
    open_value = _timestamp_integer(fields[_OPEN_TIME], divisor)
    if isinstance(open_value, RefusalCode):
        return _field_refusal(open_value, fields[_OPEN_TIME], line, ids, clock)
    values: list[Decimal] = []
    for position in range(_OPEN_TIME + 1, _CLOSE_TIME):
        value = _parse_number(fields[position], price=position <= PRICE_FIELD_COUNT)
        if value is None:
            return _field_refusal(
                RefusalCode.CSV_NUMBER, fields[position], line, ids, clock
            )
        values.append(value)
    close_value = _timestamp_integer(fields[_CLOSE_TIME], divisor)
    if isinstance(close_value, RefusalCode):
        return _field_refusal(close_value, fields[_CLOSE_TIME], line, ids, clock)
    if close_value <= open_value:
        return _field_refusal(
            RefusalCode.CSV_TIMESTAMP, fields[_CLOSE_TIME], line, ids, clock
        )
    for position in range(_CLOSE_TIME + 1, _IGNORE):
        if not _checked_number(fields[position], count=position == _TRADES):
            return _field_refusal(
                RefusalCode.CSV_NUMBER, fields[position], line, ids, clock
            )
    if "\r" in fields[_IGNORE]:
        return refusal(
            RefusalCode.CSV_ROW_SHAPE,
            line=line,
            value_length=len(record),
            ids=ids,
            clock=clock,
        )
    open_price, high, low, close, volume = values
    return CandleRow(
        open_time_utc=_instant(open_value, divisor),
        open=open_price,
        high=high,
        low=low,
        close=close,
        volume=volume,
        line=line,
    )


def _field_refusal(
    code: RefusalCode,
    text: str,
    line: int,
    ids: IdProvider,
    clock: Clock,
) -> Failure:
    """The refusal of one field: its line and its length, never its text."""
    return refusal(code, line=line, value_length=len(text), ids=ids, clock=clock)


def _timestamp_integer(text: str, divisor: int) -> int | RefusalCode:
    """The in-window integer of a time field, or the rule that refuses it.

    The grammar is checked first, so ``int`` is applied to at most twenty
    digits; the window is then checked on the integer, before any ``datetime``
    is constructed from it.
    """
    if _TIMESTAMP_PATTERN.fullmatch(text) is None:
        return RefusalCode.CSV_TIMESTAMP
    value = int(text)
    if not WINDOW_START_SECONDS * divisor <= value < WINDOW_END_SECONDS * divisor:
        return RefusalCode.TIMESTAMP_UNIT
    return value


def _checked_number(text: str, *, count: bool) -> bool:
    """Whether a checked, unretained numeric field conforms to its grammar.

    The slice-1 number rule (exact ``Decimal``, no sign, no exponent, within
    the canonical bound) for the volumes; for the number of trades, an unsigned
    integer within the same bound.
    """
    if count and _COUNT_PATTERN.fullmatch(text) is None:
        return False
    return _parse_number(text, price=False) is not None


def _instant(value: int, divisor: int) -> datetime:
    """The aware UTC instant of an in-window integer, by integer arithmetic."""
    seconds, remainder = divmod(value, divisor)
    return datetime(1970, 1, 1, tzinfo=UTC) + timedelta(
        seconds=seconds, microseconds=remainder * (_MICROSECONDS_PER_SECOND // divisor)
    )
