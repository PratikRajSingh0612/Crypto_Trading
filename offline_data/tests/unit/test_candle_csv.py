"""The strict ``ohlcv-csv/1`` reader of plan section 3.

Every refusal is asserted on three edges: the closed error code, the one-based
line and value length recorded in ``details``, and the absence of the offending
value from the whole serialized diagnostic. The committed fixtures cover the
plan's named refusals; the remaining grammar rules are exercised through files
written byte-exactly into ``tmp_path`` so the input contract is pinned rule by
rule on every platform. The input-path rule of section 5.4 is pinned on every
scoped shape: a missing path, a directory, an unreadable file, a reparse point
and a bounded read that fails are the whole-input refusal
``OFFLINE_DATA.INPUT_PATH`` naming neither the path nor its file name, and no
``OSError`` escapes the reader.
"""

from __future__ import annotations

import _winapi
import errno
import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import IO

import pytest
from crypto_lab.domain.diagnostics import (
    Diagnostic,
    DiagnosticCategory,
    DiagnosticSeverity,
)
from crypto_lab.domain.results import Failure, Success
from crypto_lab.domain.time import require_utc

from crypto_lab_offline_data.candle_csv import (
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_ROWS,
    EXPECTED_HEADER,
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

CLEAN_ROW_COUNT = 60
CLEAN_BYTE_COUNT = 3821
ROW_LINE_LENGTH = 62
HEADER_LINE = EXPECTED_HEADER + "\n"
FIRST_ROW = "2024-01-01T00:00:00Z,42000.00,42001.00,41999.00,42000.50,100.0\n"
SECOND_ROW = "2024-01-01T00:01:00Z,42000.01,42001.01,41999.01,42000.51,101.1\n"
NUMBER_FIELDS = ("open", "high", "low", "close", "volume")


def _row(*fields: str) -> str:
    return ",".join(fields) + "\n"


def _write(path: Path, text: str) -> Path:
    """Write ``text`` byte-exactly, without platform newline translation."""
    path.write_bytes(text.encode("utf-8"))
    return path


def _single_refusal(
    result: Success[tuple[CandleRow, ...]] | Failure,
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


def test_clean_fixture_reads_sixty_rows_as_decimals_and_utc(
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    result = read_ohlcv_csv(clean_fixture, ids=fixed_ids, clock=fixed_clock)

    assert isinstance(result, Success)
    assert result.outcome == "SUCCESS"
    rows = result.value
    assert isinstance(rows, tuple)
    assert len(rows) == CLEAN_ROW_COUNT
    first_open = datetime(2024, 1, 1, tzinfo=UTC)
    for index, row in enumerate(rows):
        assert isinstance(row, CandleRow)
        assert row.line == index + 2
        assert row.open_time_utc == first_open + timedelta(minutes=index)
        assert row.open_time_utc.tzinfo is not None
        assert row.open_time_utc.utcoffset() == timedelta(0)
        assert require_utc(row.open_time_utc) == row.open_time_utc
        for name in NUMBER_FIELDS:
            value = getattr(row, name)
            assert type(value) is Decimal
            assert value.is_finite()
        assert row.low <= row.open <= row.high
        assert row.low <= row.close <= row.high
        assert row.volume >= 0
    assert str(rows[0].open) == "42000.00"
    assert str(rows[0].volume) == "100.0"
    assert str(rows[10].open) == "42000.10"
    assert rows[59].close == Decimal("42000.59")
    assert rows[59].open_time_utc == datetime(2024, 1, 1, 0, 59, tzinfo=UTC)


def test_candle_row_is_frozen() -> None:
    row = CandleRow(
        open_time_utc=datetime(2024, 1, 1, tzinfo=UTC),
        open=Decimal("1"),
        high=Decimal("2"),
        low=Decimal("1"),
        close=Decimal("2"),
        volume=Decimal("0"),
        line=2,
    )
    with pytest.raises(AttributeError):
        row.open = Decimal("3")  # type: ignore[misc]


@pytest.mark.parametrize(
    ("name", "code", "line", "value_length", "offending"),
    [
        (
            "naive-timestamp.csv",
            RefusalCode.CSV_TIMESTAMP,
            3,
            19,
            "2024-01-01T00:01:00",
        ),
        (
            "offset-timestamp.csv",
            RefusalCode.CSV_TIMESTAMP,
            3,
            25,
            "2024-01-01T00:01:00+00:00",
        ),
        ("float-exponent.csv", RefusalCode.CSV_NUMBER, 3, 10, "4.200001e4"),
        (
            "wrong-header.csv",
            RefusalCode.CSV_HEADER,
            1,
            36,
            "timestamp,open,high,low,close,volume",
        ),
        (
            "extra-column.csv",
            RefusalCode.CSV_ROW_SHAPE,
            3,
            64,
            "42000.01,42001.01,41999.01,42000.51,101.1,7",
        ),
        ("empty.csv", RefusalCode.CSV_HEADER, 1, 0, None),
        ("header-only.csv", RefusalCode.EMPTY_SERIES, 2, 0, None),
    ],
)
def test_invalid_fixture_is_refused_with_code_line_and_length_only(
    name: str,
    code: RefusalCode,
    line: int,
    value_length: int,
    offending: str | None,
    invalid_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    result = read_ohlcv_csv(invalid_root / name, ids=fixed_ids, clock=fixed_clock)

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


def test_size_ceilings_refuse_without_truncation(
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    assert DEFAULT_MAX_ROWS == 1_048_576
    assert DEFAULT_MAX_BYTES == 64 * 1024 * 1024
    assert clean_fixture.stat().st_size == CLEAN_BYTE_COUNT

    at_row_ceiling = read_ohlcv_csv(
        clean_fixture,
        ids=fixed_ids,
        clock=fixed_clock,
        max_rows=CLEAN_ROW_COUNT,
    )
    assert isinstance(at_row_ceiling, Success)
    assert len(at_row_ceiling.value) == CLEAN_ROW_COUNT

    one_row_over = read_ohlcv_csv(
        clean_fixture,
        ids=fixed_ids,
        clock=fixed_clock,
        max_rows=CLEAN_ROW_COUNT - 1,
    )
    _single_refusal(
        one_row_over,
        RefusalCode.SIZE_CEILING,
        line=CLEAN_ROW_COUNT + 1,
        value_length=ROW_LINE_LENGTH,
        ids=fixed_ids,
        clock=fixed_clock,
    )

    ten_rows = read_ohlcv_csv(
        clean_fixture,
        ids=fixed_ids,
        clock=fixed_clock,
        max_rows=10,
    )
    _single_refusal(
        ten_rows,
        RefusalCode.SIZE_CEILING,
        line=12,
        value_length=ROW_LINE_LENGTH,
        ids=fixed_ids,
        clock=fixed_clock,
    )

    at_byte_ceiling = read_ohlcv_csv(
        clean_fixture,
        ids=fixed_ids,
        clock=fixed_clock,
        max_bytes=CLEAN_BYTE_COUNT,
    )
    assert isinstance(at_byte_ceiling, Success)
    assert len(at_byte_ceiling.value) == CLEAN_ROW_COUNT

    one_byte_over = read_ohlcv_csv(
        clean_fixture,
        ids=fixed_ids,
        clock=fixed_clock,
        max_bytes=CLEAN_BYTE_COUNT - 1,
    )
    _single_refusal(
        one_byte_over,
        RefusalCode.SIZE_CEILING,
        line=WHOLE_INPUT_LINE,
        value_length=CLEAN_BYTE_COUNT,
        ids=fixed_ids,
        clock=fixed_clock,
    )
    assert WHOLE_INPUT_LINE == 0


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


@pytest.mark.parametrize("max_bytes", [-1, -2, -DEFAULT_MAX_BYTES])
def test_a_negative_byte_ceiling_is_refused_before_the_input_is_opened(
    max_bytes: int,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """An absent path is the proof: opening it would raise ``FileNotFoundError``."""
    absent = tmp_path / "absent.csv"
    assert not absent.exists()

    result = read_ohlcv_csv(
        absent,
        ids=fixed_ids,
        clock=fixed_clock,
        max_bytes=max_bytes,
    )

    _single_refusal(
        result,
        RefusalCode.SIZE_CEILING,
        line=WHOLE_INPUT_LINE,
        value_length=0,
        ids=fixed_ids,
        clock=fixed_clock,
    )
    assert not absent.exists()


def test_a_negative_byte_ceiling_never_reaches_the_read_call(
    monkeypatch: pytest.MonkeyPatch,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """``-2`` would become ``read(-1)``, an unbounded read; nothing is read at all."""
    opened, sizes = _spy_on_open(monkeypatch)

    result = read_ohlcv_csv(
        clean_fixture,
        ids=fixed_ids,
        clock=fixed_clock,
        max_bytes=-2,
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


def test_a_zero_byte_ceiling_still_opens_and_reads_one_byte(
    monkeypatch: pytest.MonkeyPatch,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """Zero is not negative: the input is opened once and read one byte past it."""
    opened, sizes = _spy_on_open(monkeypatch)

    result = read_ohlcv_csv(
        clean_fixture,
        ids=fixed_ids,
        clock=fixed_clock,
        max_bytes=0,
    )

    assert sizes == [1]
    assert opened == [clean_fixture]
    _single_refusal(
        result,
        RefusalCode.SIZE_CEILING,
        line=WHOLE_INPUT_LINE,
        value_length=1,
        ids=fixed_ids,
        clock=fixed_clock,
    )


def test_crlf_line_endings_read_identically_to_lf(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    crlf = tmp_path / "crlf.csv"
    crlf.write_bytes(clean_fixture.read_bytes().replace(b"\n", b"\r\n"))

    lf_result = read_ohlcv_csv(clean_fixture, ids=fixed_ids, clock=fixed_clock)
    crlf_result = read_ohlcv_csv(crlf, ids=fixed_ids, clock=fixed_clock)

    assert isinstance(lf_result, Success)
    assert isinstance(crlf_result, Success)
    assert crlf_result.value == lf_result.value


def test_a_missing_final_newline_is_accepted(
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    text = HEADER_LINE + FIRST_ROW + SECOND_ROW.rstrip("\n")
    path = _write(tmp_path / "no-final-newline.csv", text)

    result = read_ohlcv_csv(path, ids=fixed_ids, clock=fixed_clock)

    assert isinstance(result, Success)
    assert [row.line for row in result.value] == [2, 3]


def test_crlf_rows_without_a_final_newline_are_accepted(
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """Retained acceptance: CRLF endings and an unterminated valid final row."""
    text = (HEADER_LINE + FIRST_ROW + SECOND_ROW.rstrip("\n")).replace("\n", "\r\n")
    path = _write(tmp_path / "crlf-no-final-newline.csv", text)

    result = read_ohlcv_csv(path, ids=fixed_ids, clock=fixed_clock)

    assert isinstance(result, Success)
    assert [row.line for row in result.value] == [2, 3]


@pytest.mark.parametrize(
    ("text", "code", "line", "value_length", "paired"),
    [
        (
            EXPECTED_HEADER + "\r",
            RefusalCode.CSV_HEADER,
            1,
            len(EXPECTED_HEADER) + 1,
            (RefusalCode.EMPTY_SERIES, 2, 0),
        ),
        (
            HEADER_LINE + FIRST_ROW.rstrip("\n") + "\r",
            RefusalCode.CSV_NUMBER,
            2,
            len("100.0\r"),
            None,
        ),
        (
            HEADER_LINE + FIRST_ROW + SECOND_ROW.rstrip("\n") + "\r",
            RefusalCode.CSV_NUMBER,
            3,
            len("101.1\r"),
            None,
        ),
        (
            HEADER_LINE + FIRST_ROW + "\r",
            RefusalCode.CSV_ROW_SHAPE,
            3,
            1,
            (RefusalCode.CSV_ROW_SHAPE, 3, 0),
        ),
    ],
)
def test_an_unpaired_final_carriage_return_is_refused(
    text: str,
    code: RefusalCode,
    line: int,
    value_length: int,
    paired: tuple[RefusalCode, int, int] | None,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """A carriage return is a line ending only when a line feed follows it.

    Unpaired, it stays in its line and the line is refused by the rule it then
    violates, with the carriage return counted in the value length. The paired
    control appends the missing line feed to the same bytes: the row cases then
    read cleanly, the header case becomes the header-only refusal and the bare
    carriage return becomes an ordinary blank line.
    """
    refused = _write(tmp_path / "unpaired-cr.csv", text)
    control = _write(tmp_path / "paired-crlf.csv", text + "\n")

    result = read_ohlcv_csv(refused, ids=fixed_ids, clock=fixed_clock)
    control_result = read_ohlcv_csv(control, ids=fixed_ids, clock=fixed_clock)

    _single_refusal(
        result,
        code,
        line=line,
        value_length=value_length,
        ids=fixed_ids,
        clock=fixed_clock,
    )
    if paired is None:
        assert isinstance(control_result, Success)
    else:
        paired_code, paired_line, paired_length = paired
        _single_refusal(
            control_result,
            paired_code,
            line=paired_line,
            value_length=paired_length,
            ids=fixed_ids,
            clock=fixed_clock,
        )


@pytest.mark.parametrize(
    ("body", "line"),
    [
        (FIRST_ROW + "\n" + SECOND_ROW, 3),
        (FIRST_ROW + SECOND_ROW + "\n", 4),
        (FIRST_ROW + "\r\n" + SECOND_ROW, 3),
    ],
)
def test_a_blank_line_inside_the_body_is_a_row_shape_refusal(
    body: str,
    line: int,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    path = _write(tmp_path / "blank-line.csv", HEADER_LINE + body)

    result = read_ohlcv_csv(path, ids=fixed_ids, clock=fixed_clock)

    _single_refusal(
        result,
        RefusalCode.CSV_ROW_SHAPE,
        line=line,
        value_length=0,
        ids=fixed_ids,
        clock=fixed_clock,
    )


def test_too_few_fields_is_a_row_shape_refusal(
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    short_row = "2024-01-01T00:01:00Z,42000.01,42001.01,41999.01,42000.51"
    text = HEADER_LINE + FIRST_ROW + short_row + "\n"
    path = _write(tmp_path / "five-fields.csv", text)

    result = read_ohlcv_csv(path, ids=fixed_ids, clock=fixed_clock)

    diagnostic = _single_refusal(
        result,
        RefusalCode.CSV_ROW_SHAPE,
        line=3,
        value_length=len(short_row),
        ids=fixed_ids,
        clock=fixed_clock,
    )
    _assert_value_absent(diagnostic, short_row)


@pytest.mark.parametrize(
    ("trailer", "line", "value_length"),
    [
        (b"\n" + SECOND_ROW.encode("utf-8"), 3, ROW_LINE_LENGTH),
        (b"", 3, ROW_LINE_LENGTH),
        (b"\r\n", 3, ROW_LINE_LENGTH),
        (b"\r", 3, ROW_LINE_LENGTH + 1),
    ],
)
def test_non_utf8_bytes_are_an_encoding_refusal(
    trailer: bytes,
    line: int,
    value_length: int,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    corrupt_row = b"2024-01-01T00:01:00Z,\xff2000.01,42001.01,41999.01,42000.51,101.1"
    path = tmp_path / "latin1-byte.csv"
    path.write_bytes(
        HEADER_LINE.encode("utf-8") + FIRST_ROW.encode("utf-8") + corrupt_row + trailer
    )

    result = read_ohlcv_csv(path, ids=fixed_ids, clock=fixed_clock)

    _single_refusal(
        result,
        RefusalCode.CSV_ENCODING,
        line=line,
        value_length=value_length,
        ids=fixed_ids,
        clock=fixed_clock,
    )


def test_a_byte_order_mark_is_a_header_refusal(
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    path = tmp_path / "bom.csv"
    path.write_bytes(b"\xef\xbb\xbf" + (HEADER_LINE + FIRST_ROW).encode("utf-8"))

    result = read_ohlcv_csv(path, ids=fixed_ids, clock=fixed_clock)

    _single_refusal(
        result,
        RefusalCode.CSV_HEADER,
        line=1,
        value_length=len(EXPECTED_HEADER) + 1,
        ids=fixed_ids,
        clock=fixed_clock,
    )


@pytest.mark.parametrize(
    "header",
    [
        "open_time_utc,open,high,low,close,volume,",
        "open_time_utc,open,high,low,close",
        "Open_Time_Utc,open,high,low,close,volume",
        " open_time_utc,open,high,low,close,volume",
        "open_time_utc;open;high;low;close;volume",
    ],
)
def test_any_header_other_than_the_exact_one_is_refused(
    header: str,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    path = _write(tmp_path / "header.csv", header + "\n" + FIRST_ROW)

    result = read_ohlcv_csv(path, ids=fixed_ids, clock=fixed_clock)

    diagnostic = _single_refusal(
        result,
        RefusalCode.CSV_HEADER,
        line=1,
        value_length=len(header),
        ids=fixed_ids,
        clock=fixed_clock,
    )
    _assert_value_absent(diagnostic, header)


@pytest.mark.parametrize(
    "timestamp",
    [
        "2024-01-01 00:00:00Z",
        "2024-01-01T00:00:00.000Z",
        "2024-01-01T00:00:00.000000Z",
        "2024-01-01T00:00Z",
        "20240101T000000Z",
        "2024-01-01T00:00:00z",
        "2024-01-01T00:00:00 Z",
        "2024-01-01T00:00:00+05:30",
        "2024-01-01T00:00:00-00:00",
        "1704067200",
        "2024-02-30T00:00:00Z",
        "2024-01-01T24:00:00Z",
        "2024-13-01T00:00:00Z",
        "",
    ],
)
def test_every_non_canonical_timestamp_form_is_refused(
    timestamp: str,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    bad_row = _row(timestamp, "42000.01", "42001.01", "41999.01", "42000.51", "101.1")
    path = _write(tmp_path / "timestamp.csv", HEADER_LINE + FIRST_ROW + bad_row)

    result = read_ohlcv_csv(path, ids=fixed_ids, clock=fixed_clock)

    diagnostic = _single_refusal(
        result,
        RefusalCode.CSV_TIMESTAMP,
        line=3,
        value_length=len(timestamp),
        ids=fixed_ids,
        clock=fixed_clock,
    )
    if timestamp:
        _assert_value_absent(diagnostic, timestamp)


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
        "1" * 257,
    ],
)
@pytest.mark.parametrize("position", range(len(NUMBER_FIELDS)))
def test_every_non_grammar_number_is_refused_in_every_field(
    number: str,
    position: int,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    fields = ["42000.01", "42001.01", "41999.01", "42000.51", "101.1"]
    fields[position] = number
    bad_row = _row("2024-01-01T00:01:00Z", *fields)
    path = _write(tmp_path / "number.csv", HEADER_LINE + FIRST_ROW + bad_row)

    result = read_ohlcv_csv(path, ids=fixed_ids, clock=fixed_clock)

    diagnostic = _single_refusal(
        result,
        RefusalCode.CSV_NUMBER,
        line=3,
        value_length=len(number),
        ids=fixed_ids,
        clock=fixed_clock,
    )
    if number:
        _assert_value_absent(diagnostic, number)


@pytest.mark.parametrize("position", range(4))
def test_a_zero_price_is_a_number_refusal(
    position: int,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    fields = ["42000.01", "42001.01", "41999.01", "42000.51", "101.1"]
    fields[position] = "0.00"
    row = _row("2024-01-01T00:00:00Z", *fields)
    path = _write(tmp_path / "zero-price.csv", HEADER_LINE + row)

    result = read_ohlcv_csv(path, ids=fixed_ids, clock=fixed_clock)

    _single_refusal(
        result,
        RefusalCode.CSV_NUMBER,
        line=2,
        value_length=4,
        ids=fixed_ids,
        clock=fixed_clock,
    )


@pytest.mark.parametrize("volume", ["0", "0.0", "0.000"])
def test_a_zero_volume_is_accepted(
    volume: str,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    row = _row(
        "2024-01-01T00:00:00Z", "42000.01", "42001.01", "41999.01", "42000.51", volume
    )
    path = _write(tmp_path / "zero-volume.csv", HEADER_LINE + row)

    result = read_ohlcv_csv(path, ids=fixed_ids, clock=fixed_clock)

    assert isinstance(result, Success)
    assert result.value[0].volume == Decimal(0)
    assert str(result.value[0].volume) == str(Decimal(volume))


def test_digits_are_parsed_exactly_from_the_source_text(
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """Leading zeros, trailing zeros and long fractions survive as written."""
    row = _row(
        "2024-01-01T00:00:00Z",
        "007.50",
        "42001.000",
        "41999.123456789012345678",
        "42000.5",
        "0.000000001",
    )
    path = _write(tmp_path / "exact-digits.csv", HEADER_LINE + row)

    result = read_ohlcv_csv(path, ids=fixed_ids, clock=fixed_clock)

    assert isinstance(result, Success)
    candle = result.value[0]
    assert candle.open == Decimal("7.50")
    assert candle.open.as_tuple().exponent == -2
    assert str(candle.high) == "42001.000"
    assert str(candle.low) == "41999.123456789012345678"
    assert str(candle.close) == "42000.5"
    assert candle.volume == Decimal("0.000000001")
    assert candle.volume.as_tuple() == Decimal("0.000000001").as_tuple()


def test_the_longest_canonical_decimal_text_is_accepted(
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """A 256-digit integer is the core's canonical maximum; 257 is refused above."""
    row = _row("2024-01-01T00:00:00Z", "1" * 256, "9" * 256, "1", "1", "0")
    path = _write(tmp_path / "max-digits.csv", HEADER_LINE + row)

    result = read_ohlcv_csv(path, ids=fixed_ids, clock=fixed_clock)

    assert isinstance(result, Success)
    assert result.value[0].open == Decimal("1" * 256)


def test_the_refusal_codes_are_the_closed_section_five_four_set() -> None:
    assert [code.value for code in RefusalCode] == [
        "OFFLINE_DATA.CSV_ENCODING",
        "OFFLINE_DATA.CSV_HEADER",
        "OFFLINE_DATA.CSV_ROW_SHAPE",
        "OFFLINE_DATA.CSV_TIMESTAMP",
        "OFFLINE_DATA.CSV_NUMBER",
        "OFFLINE_DATA.SIZE_CEILING",
        "OFFLINE_DATA.ORDERING",
        "OFFLINE_DATA.TIMEFRAME_GRID",
        "OFFLINE_DATA.PRICE_SANITY",
        "OFFLINE_DATA.VOLUME",
        "OFFLINE_DATA.EMPTY_SERIES",
        "OFFLINE_DATA.OUTPUT_DIRECTORY",
        "OFFLINE_DATA.INPUT_PATH",
        "OFFLINE_DATA.METADATA_FIELD",
        "OFFLINE_DATA.TIMESTAMP_UNIT",
    ]


def _input_path_refusal(
    result: Success[tuple[CandleRow, ...]] | Failure,
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
    """A missing input is the ``INPUT_PATH`` refusal, not a ``FileNotFoundError``."""
    absent = tmp_path / "absent.csv"
    assert not absent.exists()

    result = read_ohlcv_csv(absent, ids=fixed_ids, clock=fixed_clock)

    _input_path_refusal(result, absent, ids=fixed_ids, clock=fixed_clock)
    assert not absent.exists()


def test_a_directory_input_path_is_refused_without_a_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """A directory is the ``INPUT_PATH`` refusal; its open fails and nothing is read."""
    directory = tmp_path / "input.csv"
    directory.mkdir()
    opened, sizes = _spy_on_open(monkeypatch)

    result = read_ohlcv_csv(directory, ids=fixed_ids, clock=fixed_clock)

    assert sizes == []
    assert opened == [directory]
    _input_path_refusal(result, directory, ids=fixed_ids, clock=fixed_clock)
    assert directory.is_dir()


def test_an_unreadable_input_file_is_refused_until_it_is_released(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """A file held open with share mode 0 cannot be opened: ``INPUT_PATH``.

    The same bytes read cleanly once the holder releases them, so the refusal
    is the unreadability and nothing else.
    """
    locked = tmp_path / "locked.csv"
    locked.write_bytes(clean_fixture.read_bytes())
    handle = _winapi.CreateFile(
        str(locked),
        _winapi.GENERIC_READ,
        0,
        _winapi.NULL,
        _winapi.OPEN_EXISTING,
        0,
        _winapi.NULL,
    )
    try:
        while_held = read_ohlcv_csv(locked, ids=fixed_ids, clock=fixed_clock)
    finally:
        _winapi.CloseHandle(handle)
    released = read_ohlcv_csv(locked, ids=fixed_ids, clock=fixed_clock)

    _input_path_refusal(while_held, locked, ids=fixed_ids, clock=fixed_clock)
    assert isinstance(released, Success)
    assert len(released.value) == CLEAN_ROW_COUNT


def test_a_reparse_point_input_path_is_refused_before_it_is_opened(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """A junction is refused on its own attributes, never opened or followed.

    The reparse point is the path itself: the regular file reached through the
    junction is not a reparse point and reads cleanly, which is the control
    that the rule inspects the input path and does not walk its ancestors.
    """
    target = tmp_path / "target"
    target.mkdir()
    (target / "input.csv").write_bytes(clean_fixture.read_bytes())
    link = tmp_path / "link.csv"
    _winapi.CreateJunction(str(target), str(link))
    try:
        opened, sizes = _spy_on_open(monkeypatch)
        result = read_ohlcv_csv(link, ids=fixed_ids, clock=fixed_clock)
        through = read_ohlcv_csv(link / "input.csv", ids=fixed_ids, clock=fixed_clock)
    finally:
        link.rmdir()

    assert opened == [link / "input.csv"]
    assert sizes == [DEFAULT_MAX_BYTES + 1]
    _input_path_refusal(result, link, ids=fixed_ids, clock=fixed_clock)
    assert isinstance(through, Success)
    assert len(through.value) == CLEAN_ROW_COUNT
    assert not link.exists()
    assert (target / "input.csv").is_file()


class _FailingHandle:
    """A binary handle whose bounded read fails and whose closes are recorded."""

    def __init__(self, closed: list[bool]) -> None:
        self._closed = closed

    def __enter__(self) -> _FailingHandle:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._closed.append(True)

    def read(self, size: int = -1) -> bytes:
        raise OSError(errno.EIO, "injected read failure")


def test_a_failing_bounded_read_is_refused_and_the_handle_is_closed(
    monkeypatch: pytest.MonkeyPatch,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """An ``OSError`` from the one bounded read is ``INPUT_PATH``; nothing leaks."""
    closed: list[bool] = []

    def failing_open(self: Path, mode: str = "r") -> _FailingHandle:
        assert mode == "rb"
        return _FailingHandle(closed)

    monkeypatch.setattr(Path, "open", failing_open)

    result = read_ohlcv_csv(clean_fixture, ids=fixed_ids, clock=fixed_clock)

    assert closed == [True]
    _input_path_refusal(result, clean_fixture, ids=fixed_ids, clock=fixed_clock)


@pytest.mark.parametrize(
    "relative",
    ["embedded\x00nul.csv", "\x00input.csv", "embedded\x00nul/input.csv"],
    ids=["in-the-name", "leading", "in-a-parent"],
)
def test_an_embedded_nul_in_the_input_path_is_refused_before_it_is_opened(
    relative: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """A path the platform rejects outright is ``INPUT_PATH``, not a ``ValueError``.

    ``lstat`` refuses an embedded NUL with ``ValueError`` rather than ``OSError``;
    the reader converts it like every other path failure and never reaches
    ``open``. The raw path cannot appear in JSON (its NUL is escaped), so the
    discriminating checks are its JSON-escaped spelling and its NUL-free parent.
    """
    path = tmp_path / relative
    assert "\x00" in str(path)
    opened, sizes = _spy_on_open(monkeypatch)

    result = read_ohlcv_csv(path, ids=fixed_ids, clock=fixed_clock)

    assert sizes == []
    assert opened == []
    diagnostic = _input_path_refusal(result, path, ids=fixed_ids, clock=fixed_clock)
    _assert_value_absent(diagnostic, json.dumps(str(path))[1:-1])
    _assert_value_absent(diagnostic, tmp_path.name)


class _MalformedIds:
    """An ``IdProvider`` whose ``diag_`` value the core refuses (reading R7)."""

    def dataset_id(self) -> str:
        return "ds_0f8c2a4e-6b3d-4f1a-9c7e-2d5b8a1f3c6e"

    def partition_id(self) -> str:
        return "part_7a1d3e5f-9b2c-4d6e-8f1a-3c5e7b9d1f2a"

    def diagnostic_id(self) -> str:
        return "not-a-diagnostic-id"


def test_an_embedded_nul_refusal_still_raises_the_provider_contract_error(
    tmp_path: Path,
    fixed_clock: Clock,
) -> None:
    """The path ``ValueError`` conversion sits outside the provider draws.

    The NUL path is refused, the refusal draws a malformed identifier and the
    resulting ``ProviderContractError`` crosses the reader unconverted.
    """
    path = tmp_path / "embedded\x00nul.csv"

    with pytest.raises(ProviderContractError) as caught:
        read_ohlcv_csv(path, ids=_MalformedIds(), clock=fixed_clock)

    assert caught.value.method == "diagnostic_id"
    assert "not-a-diagnostic-id" not in str(caught.value)
