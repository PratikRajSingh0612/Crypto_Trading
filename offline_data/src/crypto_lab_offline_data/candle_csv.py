"""The strict ``ohlcv-csv/1`` reader of plan section 3.

Input contract: UTF-8 text with LF or CRLF line endings and no byte order
mark (a carriage return is a line ending only when a line feed follows it; an
unpaired carriage return stays in its line, which is then refused by the rule
it violates); the first line is exactly
``open_time_utc,open,high,low,close,volume``; every data row has exactly six
comma-separated fields with no quoting; the
open time is ``YYYY-MM-DDTHH:MM:SSZ`` to the second with a literal ``Z`` and
must be a real calendar instant; each of the five numbers is a run of digits
optionally followed by one point and a run of digits (no sign, exponent, bare
``.5`` or ``5.``), within the core's 256-character canonical bound; the four
prices are positive and the volume is non-negative; the input holds at most
``max_rows`` data rows and ``max_bytes`` bytes. A missing final newline is
accepted; a blank line inside the body is not. Every violation is one section
5.4 refusal naming the one-based line and the rule, never the value, and
nothing is truncated, converted or repaired.

Prices and volumes are ``decimal.Decimal`` built from the exact source text,
so ``42000.10`` keeps its digits; open times are timezone-aware UTC
``datetime`` values. The reader performs at most one bounded read of the input
and never writes; a negative ``max_bytes`` is refused as the size-ceiling rule
before the input path is inspected, so no negative size ever reaches a read
call and the recorded value length is ``0``. The input path itself is then
inspected without following it: a missing path, a reparse point, a directory,
an unreadable file, a bounded read that fails or a path the platform rejects
outright (an embedded NUL, which ``lstat`` refuses with ``ValueError`` rather
than ``OSError``) is the whole-input refusal ``OFFLINE_DATA.INPUT_PATH`` (line
``0``, value length ``0``, the path never recorded), so neither an ``OSError``
nor a path-operation ``ValueError`` escapes. The core ``ValueError`` reachable
here (the canonical-decimal bound of ``format_decimal``) is converted into a
refusal at this boundary. The one exception that crosses it is
``ProviderContractError`` (reading R7): the reader draws its providers only
when it builds a refusal, and a value the core refuses is a fault of the
caller's composition, raised and never converted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from pathlib import Path

from crypto_lab.domain.financial import format_decimal
from crypto_lab.domain.results import Failure, Success
from crypto_lab.domain.time import require_utc

from crypto_lab_offline_data.diagnostics import RefusalCode, refusal
from crypto_lab_offline_data.providers import Clock, IdProvider

EXPECTED_HEADER = "open_time_utc,open,high,low,close,volume"
FIELD_COUNT = 6
PRICE_FIELD_COUNT = 4
DEFAULT_MAX_ROWS = 1_048_576
DEFAULT_MAX_BYTES = 64 * 1024 * 1024
#: ``details["line"]`` of a refusal that concerns the whole input.
WHOLE_INPUT_LINE = 0
#: The line at which the first data row is expected; the header is line 1.
FIRST_ROW_LINE = 2
#: Win32 ``FILE_ATTRIBUTE_REPARSE_POINT``: a path carrying it is refused, never
#: followed; on a platform without the attribute no path carries it.
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_TIMESTAMP_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"
)
_NUMBER_PATTERN = re.compile(r"[0-9]+(?:\.[0-9]+)?")
#: A line ending is a line feed or a carriage return directly followed by one;
#: the alternation tries ``\r\n`` first, so the first of ``\r\r\n`` stays in
#: its line and a carriage return with no following line feed is never split.
_LINE_BREAK = re.compile(r"\r\n|\n")


@dataclass(frozen=True, slots=True)
class CandleRow:
    """One accepted input row; ``line`` is its one-based line in the input."""

    open_time_utc: datetime
    open: Decimal
    high: Decimal
    low: Decimal
    close: Decimal
    volume: Decimal
    line: int


type ReadResult = Success[tuple[CandleRow, ...]] | Failure


def read_ohlcv_csv(
    path: Path,
    *,
    ids: IdProvider,
    clock: Clock,
    max_rows: int = DEFAULT_MAX_ROWS,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> ReadResult:
    """Read one ``ohlcv-csv/1`` input into its rows, or return one refusal."""
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
    header = lines[0] if lines else ""
    if header != EXPECTED_HEADER:
        return refusal(
            RefusalCode.CSV_HEADER,
            line=1,
            value_length=len(header),
            ids=ids,
            clock=clock,
        )
    if len(lines) == 1:
        return refusal(
            RefusalCode.EMPTY_SERIES,
            line=FIRST_ROW_LINE,
            value_length=0,
            ids=ids,
            clock=clock,
        )
    rows: list[CandleRow] = []
    for line, record in enumerate(lines[1:], start=FIRST_ROW_LINE):
        if line - 1 > max_rows:
            return refusal(
                RefusalCode.SIZE_CEILING,
                line=line,
                value_length=len(record),
                ids=ids,
                clock=clock,
            )
        parsed = _parse_row(record, line, ids=ids, clock=clock)
        if isinstance(parsed, Failure):
            return parsed
        rows.append(parsed)
    return Success[tuple[CandleRow, ...]](outcome="SUCCESS", value=tuple(rows))


def _read_bounded(path: Path, max_bytes: int) -> bytes | None:
    """At most ``max_bytes + 1`` bytes of the file at ``path``, else ``None``.

    The path is inspected without following it: a reparse point (its own
    attributes, so a junction or symbolic link is refused rather than resolved),
    a missing path, a directory, an unreadable file, a read that fails and a
    path the platform rejects outright (an embedded NUL, which ``lstat`` refuses
    with ``ValueError`` rather than ``OSError``) all yield ``None``, which the
    caller turns into the ``INPUT_PATH`` refusal, so neither error leaves the
    reader. No provider is drawn inside the handler, so it can never swallow a
    ``ProviderContractError``.
    """
    try:
        attributes = int(getattr(path.lstat(), "st_file_attributes", 0))
        if attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            return None
        with path.open("rb") as handle:
            return handle.read(max_bytes + 1)
    except (OSError, ValueError):
        return None


def _byte_line(data: bytes, position: int) -> int:
    """The one-based line holding the byte at ``position``."""
    return data.count(b"\n", 0, position) + 1


def _byte_line_length(data: bytes, position: int) -> int:
    """The byte length, without its terminator, of the line at ``position``.

    A trailing carriage return is part of the terminator only when the line
    feed that pairs with it follows; on an unterminated final line it counts.
    """
    start = data.rfind(b"\n", 0, position) + 1
    end = data.find(b"\n", position)
    if end < 0:
        return len(data) - start
    return len(data[start:end].removesuffix(b"\r"))


def _parse_row(
    record: str,
    line: int,
    *,
    ids: IdProvider,
    clock: Clock,
) -> CandleRow | Failure:
    fields = record.split(",")
    if len(fields) != FIELD_COUNT:
        return refusal(
            RefusalCode.CSV_ROW_SHAPE,
            line=line,
            value_length=len(record),
            ids=ids,
            clock=clock,
        )
    timestamp_text, *number_texts = fields
    open_time_utc = _parse_timestamp(timestamp_text)
    if open_time_utc is None:
        return refusal(
            RefusalCode.CSV_TIMESTAMP,
            line=line,
            value_length=len(timestamp_text),
            ids=ids,
            clock=clock,
        )
    values: list[Decimal] = []
    for position, number_text in enumerate(number_texts):
        value = _parse_number(number_text, price=position < PRICE_FIELD_COUNT)
        if value is None:
            return refusal(
                RefusalCode.CSV_NUMBER,
                line=line,
                value_length=len(number_text),
                ids=ids,
                clock=clock,
            )
        values.append(value)
    open_price, high, low, close, volume = values
    return CandleRow(
        open_time_utc=open_time_utc,
        open=open_price,
        high=high,
        low=low,
        close=close,
        volume=volume,
        line=line,
    )


def _parse_timestamp(text: str) -> datetime | None:
    """A ``YYYY-MM-DDTHH:MM:SSZ`` real instant as aware UTC, else ``None``."""
    if _TIMESTAMP_PATTERN.fullmatch(text) is None:
        return None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return require_utc(parsed)


def _parse_number(text: str, *, price: bool) -> Decimal | None:
    """The exact ``Decimal`` of a grammar-conforming field, else ``None``.

    ``format_decimal`` is called for its canonical-length bound only; the
    rendered form is Task 2's normalization and is not kept here. A price must
    be positive; the grammar admits no sign, so zero is the only value refused.
    """
    if _NUMBER_PATTERN.fullmatch(text) is None:
        return None
    value = Decimal(text)
    try:
        format_decimal(value)
    except ValueError:
        return None
    if price and value <= 0:
        return None
    return value
