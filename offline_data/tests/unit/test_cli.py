"""The ``normalize`` command of plan Task 3 and its module entry point.

The command is pinned on its exit table (``0`` success, ``1`` refusal, ``2``
argument parsing only, ``3`` provider fault), on the accepted sequence (read,
validate, raw checksum, one draw of each provider value snapshotted into fixed
providers, the output directory created immediately before the first write,
then the container, the metadata and the two JSON files, with no draw after the
first write), on its ``--output`` handling (relative or absolute, created when
absent, a file, a reparse point, a missing parent, an embedded NUL or an
existing output name is the ``OUTPUT_DIRECTORY`` refusal, nothing is written
outside it and unrelated entries are preserved), on its cleanup (every file the
command created is removed in reverse order when a later step fails, the
completed container included, and a removal that fails is still the refusal),
and on its diagnostics, which name no value and no path. The provider draw
counts are asserted on every path, malformed provider values exit ``3`` without
exposing the value, and the module entry point is run through ``runpy`` with the
production providers.
"""

from __future__ import annotations

import _winapi
import errno
import hashlib
import importlib
import json
import runpy
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any

import pytest
from _pytest.capture import CaptureResult
from crypto_lab.datasets.models import (
    DatasetDescriptor,
    DatasetPartition,
    DatasetValidationStatus,
    RawSourceProvenance,
)
from crypto_lab.domain.identifiers import validate_prefixed_uuid4
from crypto_lab.domain.results import Failure
from crypto_lab.domain.time import require_utc
from pydantic import TypeAdapter

from crypto_lab_offline_data import cli
from crypto_lab_offline_data.candle_csv import WHOLE_INPUT_LINE
from crypto_lab_offline_data.cli import (
    DESCRIPTOR_FILE_NAME,
    EXIT_ARGUMENTS,
    EXIT_PROVIDER_FAULT,
    EXIT_REFUSAL,
    EXIT_SUCCESS,
    OUTPUT_FILE_NAMES,
    PARTITIONS_FILE_NAME,
    PROGRAM,
    build_parser,
    normalize_command,
)
from crypto_lab_offline_data.diagnostics import (
    SOURCE_COMPONENT,
    ProviderContractError,
    RefusalCode,
    refusal,
)
from crypto_lab_offline_data.metadata import (
    CONTAINER_FILE_NAME,
    DEFAULT_SOURCE,
    P2_B1_LIMITATION,
    P2_B3_LIMITATION,
)
from crypto_lab_offline_data.providers import Clock, IdProvider

INSTRUMENT_ID = "BINANCE:BTC/USDT:SPOT"
FIXED_DATASET_ID = "ds_0f8c2a4e-6b3d-4f1a-9c7e-2d5b8a1f3c6e"
FIXED_PARTITION_ID = "part_7a1d3e5f-9b2c-4d6e-8f1a-3c5e7b9d1f2a"
FIXED_DIAGNOSTIC_ID = "diag_3c9e1b7d-5f2a-4b8c-a6d4-9e1f3b5d7c2a"
FIXED_INSTANT_TEXT = "2026-01-02T03:04:05Z"
OTHER_DATASET_ID = "ds_8b2d4f6a-1c3e-4a5b-b7d9-0e2f4a6c8b1d"
OTHER_PARTITION_ID = "part_8b2d4f6a-1c3e-4a5b-b7d9-0e2f4a6c8b1d"
OTHER_DIAGNOSTIC_ID = "diag_8b2d4f6a-1c3e-4a5b-b7d9-0e2f4a6c8b1d"
OTHER_INSTANT = datetime(2031, 12, 31, 23, 59, 59, tzinfo=UTC)
OTHER_INSTANT_TEXT = "2031-12-31T23:59:59Z"
MALFORMED_SUFFIX = "not-a-canonical-uuid4"
NAIVE_INSTANT = datetime(2026, 1, 2, 3, 4, 5)  # noqa: DTZ001
PARTIAL_PREFIX_LENGTH = 16
UNRELATED_NAME = "notes.txt"
UNRELATED_BYTES = b"pre-existing\n"
NO_DRAWS = {"dataset_id": 0, "partition_id": 0, "diagnostic_id": 0}
REFUSAL_DRAWS = {"dataset_id": 0, "partition_id": 0, "diagnostic_id": 1}
DATASET_DRAW = {"dataset_id": 1, "partition_id": 0, "diagnostic_id": 0}
TWO_DRAWS = {"dataset_id": 1, "partition_id": 1, "diagnostic_id": 0}
SNAPSHOT_DRAWS = {"dataset_id": 1, "partition_id": 1, "diagnostic_id": 1}
COMPLETE_ARGV = [
    "normalize",
    "--input",
    "x.csv",
    "--output",
    "out",
    "--instrument",
    "A:B/C:SPOT",
    "--timeframe",
    "1m",
]
#: A harmless token that is no option and no prefix of one, so argparse reports
#: it as ``unrecognized arguments:`` rather than as an abbreviation.
UNRECOGNIZED_SENTINEL = "--zz-unrecognized-sentinel"
OHLCV_FORMAT = "ohlcv-csv/1"
BINANCE_FORMAT = "binance-spot-kline-csv/1"
BINANCE_SOURCE = "synthetic-binance-fixture"
#: One synthetic twelve-field microsecond row (2025-01-01T00:00:00Z), used only
#: to build malformed carriage-return inputs under ``tmp_path``.
SYNTHETIC_US_ROW = (
    "1735689600000000,93500.00000000,93501.00000000,93499.00000000,"
    "93500.50000000,10.00000000,1735689659999999,935000.50000000,100,"
    "5.00000000,467500.25000000,0"
)
EMBEDDED_CR_IGNORE = "opaque\rtext"
#: Inputs whose only defect is a residual carriage return in field 12, with the
#: complete logical-row length the refusal must record (the consumed LF or CRLF
#: excluded, every carriage return included).
MALFORMED_CR_INPUTS = [
    ("lone-terminal-cr", SYNTHETIC_US_ROW + "\r", len(SYNTHETIC_US_ROW) + 1),
    ("cr-cr-lf", SYNTHETIC_US_ROW + "\r\r\n", len(SYNTHETIC_US_ROW) + 1),
    (
        "embedded-cr",
        SYNTHETIC_US_ROW[:-1] + EMBEDDED_CR_IGNORE + "\n",
        len(SYNTHETIC_US_ROW) - 1 + len(EMBEDDED_CR_IGNORE),
    ),
]
BINANCE_UNITS = {
    "SYNTHETIC-BTCUSDT-1m-2024-12-31-ms": "milliseconds",
    "SYNTHETIC-BTCUSDT-1m-2025-01-01-us": "microseconds",
    "SYNTHETIC-BTCUSDT-1m-gaps-duplicates-us": "microseconds",
}
BINANCE_STEMS = tuple(BINANCE_UNITS)
PARTITIONS_ADAPTER: TypeAdapter[tuple[DatasetPartition, ...]] = TypeAdapter(
    tuple[DatasetPartition, ...]
)


def _without(option: str) -> list[str]:
    """``COMPLETE_ARGV`` without one option and its value."""
    index = COMPLETE_ARGV.index(option)
    return COMPLETE_ARGV[:index] + COMPLETE_ARGV[index + 2 :]


def _names(directory: Path) -> list[str]:
    return sorted(entry.name for entry in directory.iterdir())


def _fault_line(method: str) -> str:
    return f"provider method {method} returned a value the core refuses\n"


def _argv(
    input_path: Path | str,
    output: Path | str,
    *,
    instrument: str = INSTRUMENT_ID,
    timeframe: str = "1m",
    source: str | None = None,
    input_format: str | None = None,
    timestamp_unit: str | None = None,
) -> list[str]:
    argv = [
        "normalize",
        "--input",
        str(input_path),
        "--output",
        str(output),
        "--instrument",
        instrument,
        "--timeframe",
        timeframe,
    ]
    if source is not None:
        argv.extend(["--source", source])
    if input_format is not None:
        argv.extend(["--input-format", input_format])
    if timestamp_unit is not None:
        argv.extend(["--timestamp-unit", timestamp_unit])
    return argv


def _snapshot(directory: Path) -> tuple[tuple[str, int], ...]:
    """Names and sizes of a directory's entries; directories carry size -1."""
    entries: list[tuple[str, int]] = []
    for entry in sorted(directory.iterdir()):
        size = entry.stat().st_size if entry.is_file() else -1
        entries.append((entry.name, size))
    return tuple(entries)


def _output_with_unrelated_entry(tmp_path: Path) -> Path:
    output = tmp_path / "output"
    output.mkdir()
    (output / UNRELATED_NAME).write_bytes(UNRELATED_BYTES)
    return output


def _printed_refusal(
    captured: CaptureResult[str],
    code: RefusalCode,
    *,
    value_length: int,
    diagnostic_id: str,
    instant_text: str,
    line: int = WHOLE_INPUT_LINE,
) -> dict[str, Any]:
    """Assert the one canonical-JSON refusal line on stdout and return it."""
    assert captured.err == ""
    assert captured.out.endswith("\n")
    assert captured.out.count("\n") == 1
    printed = json.loads(captured.out)
    assert isinstance(printed, dict)
    assert printed["outcome"] == "FAILURE"
    assert len(printed["diagnostics"]) == 1
    diagnostic = printed["diagnostics"][0]
    assert diagnostic["error_code"] == code.value
    assert diagnostic["details"] == {
        "line": line,
        "rule": code.value,
        "value_length": value_length,
    }
    assert diagnostic["severity"] == "ERROR"
    assert diagnostic["category"] == "SCHEMA_VALIDATION"
    assert diagnostic["source_component"] == SOURCE_COMPONENT
    assert diagnostic["retriable"] is False
    assert diagnostic["diagnostic_id"] == diagnostic_id
    assert diagnostic["timestamp_utc"] == instant_text
    assert diagnostic["causal_diagnostic_ids"] == []
    assert str(line) in diagnostic["message"]
    assert code.value in diagnostic["message"]
    return printed


def _assert_path_absent(text: str, path: Path) -> None:
    assert str(path) not in text
    assert path.as_posix() not in text
    assert path.name not in text
    assert json.dumps(str(path))[1:-1] not in text


class _CountingIds:
    """An ``IdProvider`` that counts the draws of each method."""

    def __init__(self) -> None:
        self.calls = {"dataset_id": 0, "partition_id": 0, "diagnostic_id": 0}

    def dataset_id(self) -> str:
        self.calls["dataset_id"] += 1
        return OTHER_DATASET_ID

    def partition_id(self) -> str:
        self.calls["partition_id"] += 1
        return OTHER_PARTITION_ID

    def diagnostic_id(self) -> str:
        self.calls["diagnostic_id"] += 1
        return OTHER_DIAGNOSTIC_ID


class _CountingClock:
    """A ``Clock`` that counts its draws."""

    def __init__(self) -> None:
        self.calls = 0

    def now_utc(self) -> datetime:
        self.calls += 1
        return OTHER_INSTANT


class _ValueIds:
    """An ``IdProvider`` handing back one configured value for one method."""

    def __init__(self, method: str, value: Any) -> None:
        self._method = method
        self._value = value
        self.calls = {"dataset_id": 0, "partition_id": 0, "diagnostic_id": 0}

    def _answer(self, method: str, valid: str) -> Any:
        self.calls[method] += 1
        return self._value if method == self._method else valid

    def dataset_id(self) -> Any:
        return self._answer("dataset_id", OTHER_DATASET_ID)

    def partition_id(self) -> Any:
        return self._answer("partition_id", OTHER_PARTITION_ID)

    def diagnostic_id(self) -> Any:
        return self._answer("diagnostic_id", OTHER_DIAGNOSTIC_ID)


class _ValueClock:
    """A ``Clock`` that hands back one configured value."""

    def __init__(self, value: Any) -> None:
        self._value = value
        self.calls = 0

    def now_utc(self) -> Any:
        self.calls += 1
        return self._value


class _LoggingIds:
    """An ``IdProvider`` appending each draw to a shared event log."""

    def __init__(self, log: list[tuple[str, ...]]) -> None:
        self._log = log

    def dataset_id(self) -> str:
        self._log.append(("draw", "dataset_id"))
        return FIXED_DATASET_ID

    def partition_id(self) -> str:
        self._log.append(("draw", "partition_id"))
        return FIXED_PARTITION_ID

    def diagnostic_id(self) -> str:
        self._log.append(("draw", "diagnostic_id"))
        return FIXED_DIAGNOSTIC_ID


class _LoggingClock:
    """A ``Clock`` appending each draw to a shared event log."""

    def __init__(self, log: list[tuple[str, ...]]) -> None:
        self._log = log

    def now_utc(self) -> datetime:
        self._log.append(("draw", "now_utc"))
        return datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def _log_filesystem(patch: pytest.MonkeyPatch, log: list[tuple[str, ...]]) -> None:
    """Append every ``Path.mkdir`` and ``Path.open`` to the shared event log."""
    real_mkdir = Path.mkdir
    real_open = Path.open

    def logging_mkdir(self: Path, *args: Any, **kwargs: Any) -> None:
        log.append(("mkdir", self.name))
        real_mkdir(self, *args, **kwargs)

    def logging_open(self: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        log.append(("open", mode, self.name))
        return real_open(self, mode, *args, **kwargs)

    patch.setattr(Path, "mkdir", logging_mkdir)
    patch.setattr(Path, "open", logging_open)


def _record_mkdirs(patch: pytest.MonkeyPatch) -> list[Path]:
    recorded: list[Path] = []
    real_mkdir = Path.mkdir

    def recording_mkdir(self: Path, *args: Any, **kwargs: Any) -> None:
        recorded.append(self)
        real_mkdir(self, *args, **kwargs)

    patch.setattr(Path, "mkdir", recording_mkdir)
    return recorded


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
    """A handle over a real exclusively created file that fails after a prefix."""

    def __init__(
        self, inner: IO[bytes], path: Path, observed: list[str], *, at_close: bool
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
        self._observed.append(self._path.name)
        if self._at_close:
            return PARTIAL_PREFIX_LENGTH
        raise OSError(errno.ENOSPC, "injected write failure")


def _fail_the_write_of(
    patch: pytest.MonkeyPatch, name: str, *, at_close: bool = False
) -> list[str]:
    """Make the exclusive create of ``name`` succeed and its write fail mid-way."""
    observed: list[str] = []
    real_open = Path.open

    def failing_open(self: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if mode == "xb" and self.name == name:
            return _FailingHandle(
                real_open(self, "xb"), self, observed, at_close=at_close
            )
        return real_open(self, mode, *args, **kwargs)

    patch.setattr(Path, "open", failing_open)
    return observed


def _deny_the_create_of(patch: pytest.MonkeyPatch, name: str) -> None:
    """Make the exclusive create of ``name`` fail as an unwritable directory would."""
    real_open = Path.open

    def denying_open(self: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if mode == "xb" and self.name == name:
            raise PermissionError(errno.EACCES, "injected unwritable directory")
        return real_open(self, mode, *args, **kwargs)

    patch.setattr(Path, "open", denying_open)


def _junction(target: Path, link: Path) -> None:
    _winapi.CreateJunction(str(target), str(link))


# --- argument parsing: exit 2 -------------------------------------------------


def test_the_exit_codes_are_the_plan_table() -> None:
    assert EXIT_SUCCESS == 0
    assert EXIT_REFUSAL == 1
    assert EXIT_ARGUMENTS == 2
    assert EXIT_PROVIDER_FAULT == 3
    assert OUTPUT_FILE_NAMES == (
        "part-0000.ndjson",
        "descriptor.json",
        "partitions.json",
    )
    assert OUTPUT_FILE_NAMES == (
        CONTAINER_FILE_NAME,
        DESCRIPTOR_FILE_NAME,
        PARTITIONS_FILE_NAME,
    )
    assert PROGRAM == "crypto-lab-offline-data"


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["unknown"],
        ["normalize"],
        ["normalize", "--input", "x.csv"],
        _without("--input"),
        _without("--output"),
        _without("--instrument"),
        _without("--timeframe"),
        [*COMPLETE_ARGV, "--extra"],
        [*COMPLETE_ARGV, "positional"],
        [*COMPLETE_ARGV, "--source"],
    ],
)
def test_missing_or_unknown_arguments_exit_two_and_draw_nothing(
    argv: list[str],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ids = _CountingIds()
    clock = _CountingClock()

    with pytest.MonkeyPatch.context() as patch:
        patch.chdir(tmp_path)
        code = normalize_command(argv, ids=ids, clock=clock)

    captured = capsys.readouterr()
    assert code == EXIT_ARGUMENTS == 2
    assert captured.out == ""
    assert captured.err.startswith("usage: crypto-lab-offline-data")
    assert ids.calls == NO_DRAWS
    assert clock.calls == 0
    assert list(tmp_path.iterdir()) == []


def test_an_unrecognized_argument_is_argparse_s_own_exit_two_naming_the_token(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Argparse's ``unrecognized arguments:`` message echoes the caller's token.

    The command's own refusals name no value; argparse's exit-2 usage errors go
    to standard error, may echo caller argv, and precede every provider draw
    and every write. The custom converters and couplings keep their narrower
    no-echo guarantee, pinned by the tests around this one.
    """
    ids = _CountingIds()
    clock = _CountingClock()
    argv = [*COMPLETE_ARGV, UNRECOGNIZED_SENTINEL]

    with pytest.MonkeyPatch.context() as patch:
        patch.chdir(tmp_path)
        code = normalize_command(argv, ids=ids, clock=clock)

    captured = capsys.readouterr()
    assert code == EXIT_ARGUMENTS
    assert captured.out == ""
    assert captured.err.startswith("usage: crypto-lab-offline-data")
    assert "unrecognized arguments:" in captured.err
    assert UNRECOGNIZED_SENTINEL in captured.err
    assert ids.calls == NO_DRAWS
    assert clock.calls == 0
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "instrument",
    [
        "binance:btc/usdt:spot",
        "BINANCE:BTC/USDT",
        "BINANCE:BTC/USDT:PERP",
        "BINANCE:BTC/BTC:SPOT",
        "BTC/USDT",
        "",
        "BINANCE:" + "B" * 33 + "/USDT:SPOT",
    ],
)
def test_a_non_canonical_instrument_is_an_argument_error_that_never_echoes_it(
    instrument: str,
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "output"

    code = normalize_command(
        _argv(clean_fixture, output, instrument=instrument),
        ids=fixed_ids,
        clock=fixed_clock,
    )

    captured = capsys.readouterr()
    assert code == EXIT_ARGUMENTS
    assert captured.out == ""
    assert "--instrument" in captured.err
    if instrument:
        assert instrument not in captured.err
    assert not output.exists()


@pytest.mark.parametrize("source", ["", "s" * 1025])
def test_an_unbounded_source_is_an_argument_error(
    source: str,
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "output"

    code = normalize_command(
        _argv(clean_fixture, output, source=source), ids=fixed_ids, clock=fixed_clock
    )

    captured = capsys.readouterr()
    assert code == EXIT_ARGUMENTS
    assert "--source" in captured.err
    assert "1024" in captured.err
    if source:
        assert source not in captured.err
    assert not output.exists()


def test_help_exits_zero_and_names_the_normalize_command(
    fixed_ids: IdProvider,
    fixed_clock: Clock,
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = normalize_command(["--help"], ids=fixed_ids, clock=fixed_clock)
    normalize_help = normalize_command(
        ["normalize", "--help"], ids=fixed_ids, clock=fixed_clock
    )

    captured = capsys.readouterr()
    assert code == EXIT_SUCCESS
    assert normalize_help == EXIT_SUCCESS
    assert captured.out.startswith("usage: crypto-lab-offline-data")
    assert "normalize" in captured.out
    for option in (
        "--input",
        "--output",
        "--instrument",
        "--timeframe",
        "--source",
        "--input-format",
        "--timestamp-unit",
    ):
        assert option in captured.out
    assert "{ohlcv-csv/1,binance-spot-kline-csv/1}" in captured.out
    assert "{milliseconds,microseconds}" in captured.out
    assert build_parser().prog == PROGRAM


def test_an_exit_two_leaves_an_existing_output_directory_untouched(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = _output_with_unrelated_entry(tmp_path)
    before = _snapshot(output)
    argv = ["normalize", "--input", str(clean_fixture), "--output", str(output)]

    code = normalize_command(argv, ids=fixed_ids, clock=fixed_clock)

    assert code == EXIT_ARGUMENTS
    assert _snapshot(output) == before == ((UNRELATED_NAME, len(UNRELATED_BYTES)),)
    assert (output / UNRELATED_NAME).read_bytes() == UNRELATED_BYTES
    assert capsys.readouterr().out == ""


# --- success: exit 0 -----------------------------------------------------------


def test_a_successful_run_writes_the_three_files_and_prints_nothing(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "output"
    working_directory = Path.cwd()
    cwd_before = _snapshot(working_directory)
    fixture_directory_before = _snapshot(clean_fixture.parent)

    code = normalize_command(
        _argv(clean_fixture, output), ids=fixed_ids, clock=fixed_clock
    )

    captured = capsys.readouterr()
    assert code == EXIT_SUCCESS == 0
    assert captured.out == ""
    assert captured.err == ""
    assert _names(output) == sorted(OUTPUT_FILE_NAMES)
    assert _snapshot(tmp_path) == (("output", -1),)
    assert _snapshot(working_directory) == cwd_before
    assert _snapshot(clean_fixture.parent) == fixture_directory_before
    descriptor = DatasetDescriptor.model_validate_json(
        (output / DESCRIPTOR_FILE_NAME).read_bytes(), strict=True
    )
    assert descriptor.dataset_id == FIXED_DATASET_ID
    assert descriptor.partition_ids == (FIXED_PARTITION_ID,)
    assert descriptor.source == DEFAULT_SOURCE
    assert descriptor.timeframe == "1m"
    assert descriptor.instrument.canonical_id == INSTRUMENT_ID
    assert descriptor.raw_source_provenance[0].source_record == clean_fixture.name
    container = (output / CONTAINER_FILE_NAME).read_bytes()
    assert container.count(b"\n") == 60
    assert hashlib.sha256(container).hexdigest() == descriptor.normalized_checksums[0]


def test_a_successful_run_draws_each_provider_value_exactly_once(
    tmp_path: Path,
    clean_fixture: Path,
) -> None:
    """One snapshot: the writer and the metadata builder receive fixed providers."""
    ids = _CountingIds()
    clock = _CountingClock()

    code = normalize_command(
        _argv(clean_fixture, tmp_path / "output"), ids=ids, clock=clock
    )

    assert code == EXIT_SUCCESS
    assert ids.calls == SNAPSHOT_DRAWS
    assert clock.calls == 1
    descriptor = DatasetDescriptor.model_validate_json(
        (tmp_path / "output" / DESCRIPTOR_FILE_NAME).read_bytes(), strict=True
    )
    assert descriptor.dataset_id == OTHER_DATASET_ID
    assert descriptor.partition_ids == (OTHER_PARTITION_ID,)
    assert descriptor.created_at_utc == OTHER_INSTANT
    assert descriptor.imported_at_utc == OTHER_INSTANT


def test_the_sequence_validates_and_snapshots_before_the_first_write(
    tmp_path: Path,
    clean_fixture: Path,
) -> None:
    """Draws precede the directory creation, which precedes the first write."""
    log: list[tuple[str, ...]] = []
    output = tmp_path / "output"

    with pytest.MonkeyPatch.context() as patch:
        _log_filesystem(patch, log)
        code = normalize_command(
            _argv(clean_fixture, output),
            ids=_LoggingIds(log),
            clock=_LoggingClock(log),
        )

    assert code == EXIT_SUCCESS
    assert log == [
        ("open", "rb", clean_fixture.name),
        ("open", "rb", clean_fixture.name),
        ("draw", "dataset_id"),
        ("draw", "partition_id"),
        ("draw", "diagnostic_id"),
        ("draw", "now_utc"),
        ("mkdir", "output"),
        ("open", "xb", CONTAINER_FILE_NAME),
        ("open", "xb", DESCRIPTOR_FILE_NAME),
        ("open", "xb", PARTITIONS_FILE_NAME),
    ]
    first_write = log.index(("open", "xb", CONTAINER_FILE_NAME))
    assert log[first_write - 1] == ("mkdir", "output")
    assert all(event[0] != "draw" for event in log[first_write:])


def test_a_relative_output_is_created_under_the_working_directory(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    with pytest.MonkeyPatch.context() as patch:
        patch.chdir(tmp_path)
        code = normalize_command(
            _argv(clean_fixture, "relative-output"), ids=fixed_ids, clock=fixed_clock
        )

    assert code == EXIT_SUCCESS
    assert _snapshot(tmp_path) == (("relative-output", -1),)
    assert _names(tmp_path / "relative-output") == sorted(OUTPUT_FILE_NAMES)


def test_an_existing_empty_output_directory_is_used_as_is(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    output = tmp_path / "output"
    output.mkdir()

    with pytest.MonkeyPatch.context() as patch:
        created = _record_mkdirs(patch)
        code = normalize_command(
            _argv(clean_fixture, output), ids=fixed_ids, clock=fixed_clock
        )

    assert code == EXIT_SUCCESS
    assert created == []
    assert _names(output) == sorted(OUTPUT_FILE_NAMES)


def test_unrelated_entries_in_the_output_directory_are_preserved_on_success(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    output = _output_with_unrelated_entry(tmp_path)

    code = normalize_command(
        _argv(clean_fixture, output), ids=fixed_ids, clock=fixed_clock
    )

    assert code == EXIT_SUCCESS
    assert (output / UNRELATED_NAME).read_bytes() == UNRELATED_BYTES
    assert _names(output) == sorted((*OUTPUT_FILE_NAMES, UNRELATED_NAME))


def test_the_source_argument_reaches_the_descriptor(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    output = tmp_path / "output"

    code = normalize_command(
        _argv(clean_fixture, output, source="archive mirror"),
        ids=fixed_ids,
        clock=fixed_clock,
    )

    assert code == EXIT_SUCCESS
    descriptor = DatasetDescriptor.model_validate_json(
        (output / DESCRIPTOR_FILE_NAME).read_bytes(), strict=True
    )
    assert descriptor.source == "archive mirror"


# --- refusals before the snapshot: exit 1 --------------------------------------


def test_a_refused_input_exits_one_prints_the_refusal_and_creates_nothing(
    tmp_path: Path,
    invalid_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ids = _CountingIds()
    clock = _CountingClock()
    output = tmp_path / "output"
    input_path = invalid_root / "header-only.csv"

    with pytest.MonkeyPatch.context() as patch:
        created = _record_mkdirs(patch)
        code = normalize_command(_argv(input_path, output), ids=ids, clock=clock)

    captured = capsys.readouterr()
    assert code == EXIT_REFUSAL == 1
    _printed_refusal(
        captured,
        RefusalCode.EMPTY_SERIES,
        line=2,
        value_length=0,
        diagnostic_id=OTHER_DIAGNOSTIC_ID,
        instant_text=OTHER_INSTANT_TEXT,
    )
    _assert_path_absent(captured.out, input_path)
    _assert_path_absent(captured.out, output)
    assert ids.calls == REFUSAL_DRAWS
    assert clock.calls == 1
    assert created == []
    assert not output.exists()
    assert list(tmp_path.iterdir()) == []


def test_a_missing_input_is_the_input_path_refusal_that_never_names_it(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    absent = tmp_path / "absent-input.csv"
    output = tmp_path / "output"

    code = normalize_command(_argv(absent, output), ids=fixed_ids, clock=fixed_clock)

    captured = capsys.readouterr()
    assert code == EXIT_REFUSAL
    _printed_refusal(
        captured,
        RefusalCode.INPUT_PATH,
        value_length=0,
        diagnostic_id=FIXED_DIAGNOSTIC_ID,
        instant_text=FIXED_INSTANT_TEXT,
    )
    _assert_path_absent(captured.out, absent)
    _assert_path_absent(captured.out, tmp_path)
    assert not output.exists()


@pytest.mark.parametrize("timeframe", ["1w", "1s", "2m", "minute"])
def test_an_unsupported_timeframe_is_the_grid_refusal_not_an_argument_error(
    timeframe: str,
    tmp_path: Path,
    clean_fixture: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ids = _CountingIds()
    clock = _CountingClock()
    output = tmp_path / "output"

    code = normalize_command(
        _argv(clean_fixture, output, timeframe=timeframe), ids=ids, clock=clock
    )

    captured = capsys.readouterr()
    assert code == EXIT_REFUSAL
    _printed_refusal(
        captured,
        RefusalCode.TIMEFRAME_GRID,
        value_length=len(timeframe),
        diagnostic_id=OTHER_DIAGNOSTIC_ID,
        instant_text=OTHER_INSTANT_TEXT,
    )
    assert f'"{timeframe}"' not in captured.out
    assert ids.calls == REFUSAL_DRAWS
    assert clock.calls == 1
    assert not output.exists()


def test_a_raw_checksum_refusal_exits_one_before_any_snapshot_is_drawn(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    clean_fixture: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The third step's refusal is mapped like the first two; nothing is created."""
    ids = _CountingIds()
    clock = _CountingClock()
    output = tmp_path / "output"

    def refusing_checksum(*args: Any, **kwargs: Any) -> Failure:
        return refusal(
            RefusalCode.INPUT_PATH,
            line=WHOLE_INPUT_LINE,
            value_length=0,
            ids=kwargs["ids"],
            clock=kwargs["clock"],
        )

    monkeypatch.setattr(cli, "raw_checksum", refusing_checksum)

    code = normalize_command(_argv(clean_fixture, output), ids=ids, clock=clock)

    captured = capsys.readouterr()
    assert code == EXIT_REFUSAL
    _printed_refusal(
        captured,
        RefusalCode.INPUT_PATH,
        value_length=0,
        diagnostic_id=OTHER_DIAGNOSTIC_ID,
        instant_text=OTHER_INSTANT_TEXT,
    )
    assert ids.calls == REFUSAL_DRAWS
    assert clock.calls == 1
    assert not output.exists()


def test_an_exit_one_leaves_an_existing_output_directory_untouched(
    tmp_path: Path,
    invalid_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = _output_with_unrelated_entry(tmp_path)
    before = _snapshot(output)

    code = normalize_command(
        _argv(invalid_root / "unsorted.csv", output), ids=fixed_ids, clock=fixed_clock
    )

    assert code == EXIT_REFUSAL
    assert _snapshot(output) == before
    assert (output / UNRELATED_NAME).read_bytes() == UNRELATED_BYTES
    _printed_refusal(
        capsys.readouterr(),
        RefusalCode.ORDERING,
        line=4,
        value_length=20,
        diagnostic_id=FIXED_DIAGNOSTIC_ID,
        instant_text=FIXED_INSTANT_TEXT,
    )


# --- the output directory: exit 1 after the snapshot ---------------------------


def _assert_output_directory_refusal(
    captured: CaptureResult[str],
    *paths: Path,
) -> None:
    _printed_refusal(
        captured,
        RefusalCode.OUTPUT_DIRECTORY,
        value_length=0,
        diagnostic_id=OTHER_DIAGNOSTIC_ID,
        instant_text=OTHER_INSTANT_TEXT,
    )
    for path in paths:
        _assert_path_absent(captured.out, path)


def test_an_output_that_is_a_file_is_refused_and_left_untouched(
    tmp_path: Path,
    clean_fixture: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ids = _CountingIds()
    clock = _CountingClock()
    output = tmp_path / "output"
    output.write_bytes(b"a file, not a directory\n")

    with pytest.MonkeyPatch.context() as patch:
        created = _record_mkdirs(patch)
        unlinked = _record_unlinks(patch)
        code = normalize_command(_argv(clean_fixture, output), ids=ids, clock=clock)

    captured = capsys.readouterr()
    assert code == EXIT_REFUSAL
    _assert_output_directory_refusal(captured, output)
    assert ids.calls == SNAPSHOT_DRAWS
    assert clock.calls == 1
    assert created == []
    assert unlinked == []
    assert output.read_bytes() == b"a file, not a directory\n"
    assert _snapshot(tmp_path) == (("output", 24),)


def test_an_output_that_is_a_reparse_point_is_refused_and_never_followed(
    tmp_path: Path,
    clean_fixture: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "output"
    _junction(target, link)
    try:
        code = normalize_command(
            _argv(clean_fixture, link), ids=_CountingIds(), clock=_CountingClock()
        )
        target_entries = _snapshot(target)
        link_entries = _snapshot(link)
    finally:
        link.rmdir()

    captured = capsys.readouterr()
    assert code == EXIT_REFUSAL
    _assert_output_directory_refusal(captured, link, target)
    assert target_entries == ()
    assert link_entries == ()
    assert _snapshot(tmp_path) == (("target", -1),)


def test_a_dangling_reparse_point_output_is_refused_and_its_target_not_created(
    tmp_path: Path,
    clean_fixture: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "output"
    _junction(target, link)
    target.rmdir()
    assert link.is_junction()
    assert not link.exists()
    try:
        with pytest.MonkeyPatch.context() as patch:
            created = _record_mkdirs(patch)
            code = normalize_command(
                _argv(clean_fixture, link), ids=_CountingIds(), clock=_CountingClock()
            )
        target_created = target.exists()
    finally:
        link.rmdir()

    captured = capsys.readouterr()
    assert code == EXIT_REFUSAL
    _assert_output_directory_refusal(captured, link, target)
    assert created == []
    assert not target_created
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("name", OUTPUT_FILE_NAMES)
def test_an_output_already_holding_an_output_name_is_refused_and_untouched(
    name: str,
    tmp_path: Path,
    clean_fixture: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = _output_with_unrelated_entry(tmp_path)
    (output / name).write_bytes(b"sentinel\n")
    before = _snapshot(output)

    with pytest.MonkeyPatch.context() as patch:
        unlinked = _record_unlinks(patch)
        code = normalize_command(
            _argv(clean_fixture, output), ids=_CountingIds(), clock=_CountingClock()
        )

    captured = capsys.readouterr()
    assert code == EXIT_REFUSAL
    _assert_output_directory_refusal(captured, output)
    assert unlinked == []
    assert _snapshot(output) == before
    assert (output / name).read_bytes() == b"sentinel\n"
    assert (output / UNRELATED_NAME).read_bytes() == UNRELATED_BYTES


def test_an_output_holding_a_dangling_link_at_an_output_name_is_refused(
    tmp_path: Path,
    clean_fixture: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The entry is inspected without following it, so a dangling link counts."""
    output = tmp_path / "output"
    output.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "target"
    target.mkdir()
    link = output / DESCRIPTOR_FILE_NAME
    _junction(target, link)
    target.rmdir()
    try:
        code = normalize_command(
            _argv(clean_fixture, output), ids=_CountingIds(), clock=_CountingClock()
        )
        output_entries = _snapshot(output)
        outside_entries = _snapshot(outside)
    finally:
        link.rmdir()

    captured = capsys.readouterr()
    assert code == EXIT_REFUSAL
    _assert_output_directory_refusal(captured, output, target)
    assert output_entries == ((DESCRIPTOR_FILE_NAME, -1),)
    assert outside_entries == ()


def test_an_output_whose_parent_is_missing_cannot_be_created_and_is_refused(
    tmp_path: Path,
    clean_fixture: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "absent-parent" / "output"

    code = normalize_command(
        _argv(clean_fixture, output), ids=_CountingIds(), clock=_CountingClock()
    )

    captured = capsys.readouterr()
    assert code == EXIT_REFUSAL
    _assert_output_directory_refusal(captured, output, output.parent)
    assert list(tmp_path.iterdir()) == []


def test_an_output_the_platform_rejects_is_refused_not_a_value_error(
    tmp_path: Path,
    clean_fixture: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "embedded\x00nul"

    code = normalize_command(
        _argv(clean_fixture, output), ids=_CountingIds(), clock=_CountingClock()
    )

    captured = capsys.readouterr()
    assert code == EXIT_REFUSAL
    _assert_output_directory_refusal(captured, output)
    assert tmp_path.name not in captured.out
    assert list(tmp_path.iterdir()) == []


def test_an_output_refusal_uses_the_snapshot_and_draws_nothing_fresh(
    tmp_path: Path,
    clean_fixture: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """After the snapshot every refusal carries the reserved id and instant."""
    output = tmp_path / "output"
    output.write_bytes(b"blocker\n")
    log: list[tuple[str, ...]] = []

    code = normalize_command(
        _argv(clean_fixture, output), ids=_LoggingIds(log), clock=_LoggingClock(log)
    )

    captured = capsys.readouterr()
    assert code == EXIT_REFUSAL
    assert log == [
        ("draw", "dataset_id"),
        ("draw", "partition_id"),
        ("draw", "diagnostic_id"),
        ("draw", "now_utc"),
    ]
    _printed_refusal(
        captured,
        RefusalCode.OUTPUT_DIRECTORY,
        value_length=0,
        diagnostic_id=FIXED_DIAGNOSTIC_ID,
        instant_text=FIXED_INSTANT_TEXT,
    )


# --- failures after the first write: reverse-order cleanup --------------------


def test_a_failed_container_write_exits_one_with_the_partial_removed(
    tmp_path: Path,
    clean_fixture: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The writer removes its partial; the command created nothing else yet."""
    output = _output_with_unrelated_entry(tmp_path)

    with pytest.MonkeyPatch.context() as patch:
        observed = _fail_the_write_of(patch, CONTAINER_FILE_NAME)
        unlinked = _record_unlinks(patch)
        code = normalize_command(
            _argv(clean_fixture, output), ids=_CountingIds(), clock=_CountingClock()
        )

    captured = capsys.readouterr()
    assert code == EXIT_REFUSAL
    _assert_output_directory_refusal(captured, output)
    assert observed == [CONTAINER_FILE_NAME]
    assert unlinked == [output / CONTAINER_FILE_NAME]
    assert _snapshot(output) == ((UNRELATED_NAME, len(UNRELATED_BYTES)),)


@pytest.mark.parametrize("at_close", [False, True], ids=["at-write", "at-close"])
def test_a_failed_descriptor_write_removes_the_partial_then_the_container(
    at_close: bool,
    tmp_path: Path,
    clean_fixture: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = _output_with_unrelated_entry(tmp_path)

    with pytest.MonkeyPatch.context() as patch:
        observed = _fail_the_write_of(patch, DESCRIPTOR_FILE_NAME, at_close=at_close)
        unlinked = _record_unlinks(patch)
        code = normalize_command(
            _argv(clean_fixture, output), ids=_CountingIds(), clock=_CountingClock()
        )

    captured = capsys.readouterr()
    assert code == EXIT_REFUSAL
    _assert_output_directory_refusal(captured, output)
    assert observed == [DESCRIPTOR_FILE_NAME]
    assert unlinked == [output / DESCRIPTOR_FILE_NAME, output / CONTAINER_FILE_NAME]
    assert _snapshot(output) == ((UNRELATED_NAME, len(UNRELATED_BYTES)),)


@pytest.mark.parametrize("at_close", [False, True], ids=["at-write", "at-close"])
def test_a_failed_partitions_write_removes_every_created_file_in_reverse(
    at_close: bool,
    tmp_path: Path,
    clean_fixture: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = _output_with_unrelated_entry(tmp_path)

    with pytest.MonkeyPatch.context() as patch:
        observed = _fail_the_write_of(patch, PARTITIONS_FILE_NAME, at_close=at_close)
        unlinked = _record_unlinks(patch)
        code = normalize_command(
            _argv(clean_fixture, output), ids=_CountingIds(), clock=_CountingClock()
        )

    captured = capsys.readouterr()
    assert code == EXIT_REFUSAL
    _assert_output_directory_refusal(captured, output)
    assert observed == [PARTITIONS_FILE_NAME]
    assert unlinked == [
        output / PARTITIONS_FILE_NAME,
        output / DESCRIPTOR_FILE_NAME,
        output / CONTAINER_FILE_NAME,
    ]
    assert _snapshot(output) == ((UNRELATED_NAME, len(UNRELATED_BYTES)),)


def test_a_denied_descriptor_create_removes_the_completed_container(
    tmp_path: Path,
    clean_fixture: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A failure before the create owns no JSON file; the container is removed."""
    output = _output_with_unrelated_entry(tmp_path)

    with pytest.MonkeyPatch.context() as patch:
        _deny_the_create_of(patch, DESCRIPTOR_FILE_NAME)
        unlinked = _record_unlinks(patch)
        code = normalize_command(
            _argv(clean_fixture, output), ids=_CountingIds(), clock=_CountingClock()
        )

    captured = capsys.readouterr()
    assert code == EXIT_REFUSAL
    _assert_output_directory_refusal(captured, output)
    assert unlinked == [output / CONTAINER_FILE_NAME]
    assert _snapshot(output) == ((UNRELATED_NAME, len(UNRELATED_BYTES)),)


def test_a_failed_cleanup_is_still_the_refusal_with_nothing_crossing(
    tmp_path: Path,
    clean_fixture: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Every removal is attempted in reverse order even when each one fails."""
    output = _output_with_unrelated_entry(tmp_path)

    with pytest.MonkeyPatch.context() as patch:
        observed = _fail_the_write_of(patch, PARTITIONS_FILE_NAME)
        unlinked = _record_unlinks(patch, fail=True)
        code = normalize_command(
            _argv(clean_fixture, output), ids=_CountingIds(), clock=_CountingClock()
        )

    captured = capsys.readouterr()
    assert code == EXIT_REFUSAL
    _assert_output_directory_refusal(captured, output)
    assert observed == [PARTITIONS_FILE_NAME]
    assert unlinked == [
        output / PARTITIONS_FILE_NAME,
        output / DESCRIPTOR_FILE_NAME,
        output / CONTAINER_FILE_NAME,
    ]
    assert (output / PARTITIONS_FILE_NAME).stat().st_size == PARTIAL_PREFIX_LENGTH
    assert (output / UNRELATED_NAME).read_bytes() == UNRELATED_BYTES


def test_a_metadata_refusal_after_the_container_write_removes_the_container(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    clean_fixture: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``METADATA_FIELD`` is unreachable through the command (section 5.4): its
    ``--source`` is bounded at parsing, its ``input_name`` is the regular file
    the reader opened and its digests are the hashing functions' own; the
    refusal is injected to pin that the command maps it like any refusal, exit
    ``1``, from the snapshot providers, with the container removed."""
    output = _output_with_unrelated_entry(tmp_path)

    def refusing_build(*args: Any, **kwargs: Any) -> Failure:
        return refusal(
            RefusalCode.METADATA_FIELD,
            line=WHOLE_INPUT_LINE,
            value_length=0,
            ids=kwargs["ids"],
            clock=kwargs["clock"],
        )

    monkeypatch.setattr(cli, "build_dataset_metadata", refusing_build)
    ids = _CountingIds()
    clock = _CountingClock()

    with pytest.MonkeyPatch.context() as patch:
        unlinked = _record_unlinks(patch)
        code = normalize_command(_argv(clean_fixture, output), ids=ids, clock=clock)

    captured = capsys.readouterr()
    assert code == EXIT_REFUSAL
    _printed_refusal(
        captured,
        RefusalCode.METADATA_FIELD,
        value_length=0,
        diagnostic_id=OTHER_DIAGNOSTIC_ID,
        instant_text=OTHER_INSTANT_TEXT,
    )
    assert "OFFLINE_DATA.METADATA_FIELD" in captured.out
    assert "INPUT_PATH" not in captured.out
    assert ids.calls == SNAPSHOT_DRAWS
    assert clock.calls == 1
    assert unlinked == [output / CONTAINER_FILE_NAME]
    assert _snapshot(output) == ((UNRELATED_NAME, len(UNRELATED_BYTES)),)


def test_a_provider_fault_after_the_container_write_exits_three_after_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    clean_fixture: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Unreachable with validated snapshots; injected to pin the exit-3 cleanup."""
    output = _output_with_unrelated_entry(tmp_path)

    def faulting_build(*args: Any, **kwargs: Any) -> Failure:
        raise ProviderContractError("dataset_id")

    monkeypatch.setattr(cli, "build_dataset_metadata", faulting_build)

    with pytest.MonkeyPatch.context() as patch:
        unlinked = _record_unlinks(patch)
        code = normalize_command(
            _argv(clean_fixture, output), ids=_CountingIds(), clock=_CountingClock()
        )

    captured = capsys.readouterr()
    assert code == EXIT_PROVIDER_FAULT
    assert captured.out == _fault_line("dataset_id")
    assert unlinked == [output / CONTAINER_FILE_NAME]
    assert _snapshot(output) == ((UNRELATED_NAME, len(UNRELATED_BYTES)),)


# --- provider faults: exit 3 -----------------------------------------------------


@pytest.mark.parametrize(
    ("method", "value", "expected_calls"),
    [
        ("dataset_id", f"ds_{MALFORMED_SUFFIX}", DATASET_DRAW),
        ("dataset_id", OTHER_PARTITION_ID, DATASET_DRAW),
        ("dataset_id", None, DATASET_DRAW),
        ("partition_id", f"part_{MALFORMED_SUFFIX}", TWO_DRAWS),
        ("partition_id", OTHER_DATASET_ID, TWO_DRAWS),
        ("diagnostic_id", f"diag_{MALFORMED_SUFFIX}", SNAPSHOT_DRAWS),
        ("diagnostic_id", None, SNAPSHOT_DRAWS),
    ],
)
def test_a_malformed_identifier_exits_three_before_the_output_is_created(
    method: str,
    value: Any,
    expected_calls: dict[str, int],
    tmp_path: Path,
    clean_fixture: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The faulty draw stops the snapshot; the clock is drawn after the ids."""
    ids = _ValueIds(method, value)
    clock = _CountingClock()
    output = tmp_path / "output"

    with pytest.MonkeyPatch.context() as patch:
        created = _record_mkdirs(patch)
        code = normalize_command(_argv(clean_fixture, output), ids=ids, clock=clock)

    captured = capsys.readouterr()
    assert code == EXIT_PROVIDER_FAULT == 3
    assert captured.err == ""
    assert captured.out == _fault_line(method)
    if isinstance(value, str):
        assert value not in captured.out
    assert ids.calls == expected_calls
    assert clock.calls == 0
    assert created == []
    assert not output.exists()
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("value", [NAIVE_INSTANT, "2026-01-02T03:04:05Z", None])
def test_a_refused_instant_exits_three_before_the_output_is_created(
    value: Any,
    tmp_path: Path,
    clean_fixture: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ids = _CountingIds()
    clock = _ValueClock(value)
    output = tmp_path / "output"

    code = normalize_command(_argv(clean_fixture, output), ids=ids, clock=clock)

    captured = capsys.readouterr()
    assert code == EXIT_PROVIDER_FAULT
    assert captured.out == _fault_line("now_utc")
    assert str(value) not in captured.out
    assert ids.calls == SNAPSHOT_DRAWS
    assert clock.calls == 1
    assert not output.exists()


def test_a_provider_fault_during_an_input_refusal_exits_three(
    tmp_path: Path,
    invalid_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The reader's refusal draws the faulty diagnostic id: R7, mapped to exit 3."""
    ids = _ValueIds("diagnostic_id", f"diag_{MALFORMED_SUFFIX}")
    output = tmp_path / "output"

    code = normalize_command(
        _argv(invalid_root / "header-only.csv", output),
        ids=ids,
        clock=_CountingClock(),
    )

    captured = capsys.readouterr()
    assert code == EXIT_PROVIDER_FAULT
    assert "diagnostic_id" in captured.out
    assert MALFORMED_SUFFIX not in captured.out
    assert ids.calls == REFUSAL_DRAWS
    assert not output.exists()


def test_an_exit_three_leaves_an_existing_output_directory_untouched(
    tmp_path: Path,
    clean_fixture: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = _output_with_unrelated_entry(tmp_path)
    before = _snapshot(output)

    code = normalize_command(
        _argv(clean_fixture, output),
        ids=_ValueIds("dataset_id", "ds_" + MALFORMED_SUFFIX),
        clock=_CountingClock(),
    )

    assert code == EXIT_PROVIDER_FAULT
    assert _snapshot(output) == before
    assert (output / UNRELATED_NAME).read_bytes() == UNRELATED_BYTES
    assert MALFORMED_SUFFIX not in capsys.readouterr().out


# --- the binance-spot-kline-csv/1 input format (second-slice plan, section 2.4) ---


@pytest.fixture
def binance_root(sub_project_root: Path) -> Path:
    return sub_project_root / "tests" / "fixtures" / "binance"


def _binance_argv(
    fixture: Path,
    output: Path | str,
    *,
    timeframe: str = "1m",
    unit: str | None = None,
    source: str | None = BINANCE_SOURCE,
) -> list[str]:
    """The Binance arguments; the unit defaults to the valid fixture's own."""
    stem = fixture.name.removesuffix(".valid.csv")
    return _argv(
        fixture,
        output,
        timeframe=timeframe,
        source=source,
        input_format=BINANCE_FORMAT,
        timestamp_unit=BINANCE_UNITS[stem] if unit is None else unit,
    )


def _descriptor(output: Path) -> DatasetDescriptor:
    return DatasetDescriptor.model_validate_json(
        (output / DESCRIPTOR_FILE_NAME).read_bytes(), strict=True
    )


def _partitions(output: Path) -> tuple[DatasetPartition, ...]:
    return PARTITIONS_ADAPTER.validate_json(
        (output / PARTITIONS_FILE_NAME).read_bytes(), strict=True
    )


def _output_bytes(output: Path) -> tuple[bytes, ...]:
    return tuple((output / name).read_bytes() for name in OUTPUT_FILE_NAMES)


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("--input-format", "parquet/1"),
        ("--input-format", "OHLCV-CSV/1"),
        ("--input-format", "binance-spot-kline-csv/2"),
        ("--input-format", ""),
        ("--timestamp-unit", "secs"),
        ("--timestamp-unit", "nanos"),
        ("--timestamp-unit", "Microseconds"),
        ("--timestamp-unit", ""),
    ],
)
def test_the_two_new_arguments_are_closed_choices_that_never_echo_the_value(
    option: str,
    value: str,
    tmp_path: Path,
    binance_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ids = _CountingIds()
    clock = _CountingClock()
    output = tmp_path / "output"
    fixture = binance_root / f"{BINANCE_STEMS[1]}.valid.csv"
    argv = [*_binance_argv(fixture, output), option, value]

    code = normalize_command(argv, ids=ids, clock=clock)

    captured = capsys.readouterr()
    assert code == EXIT_ARGUMENTS
    assert captured.out == ""
    assert captured.err.startswith("usage: crypto-lab-offline-data")
    assert option in captured.err
    if value:
        assert value not in captured.err
    assert ids.calls == NO_DRAWS
    assert clock.calls == 0
    assert not output.exists()


def test_the_timestamp_unit_is_required_with_the_binance_format(
    tmp_path: Path,
    binance_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ids = _CountingIds()
    clock = _CountingClock()
    output = tmp_path / "output"
    fixture = binance_root / f"{BINANCE_STEMS[1]}.valid.csv"

    code = normalize_command(
        _argv(fixture, output, input_format=BINANCE_FORMAT), ids=ids, clock=clock
    )

    captured = capsys.readouterr()
    assert code == EXIT_ARGUMENTS
    assert captured.out == ""
    assert captured.err.startswith("usage: crypto-lab-offline-data")
    assert "--timestamp-unit" in captured.err
    assert "required" in captured.err
    assert ids.calls == NO_DRAWS
    assert clock.calls == 0
    assert not output.exists()


@pytest.mark.parametrize("input_format", [None, OHLCV_FORMAT])
@pytest.mark.parametrize("unit", ["milliseconds", "microseconds"])
def test_the_timestamp_unit_is_refused_with_the_default_format(
    input_format: str | None,
    unit: str,
    tmp_path: Path,
    clean_fixture: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ids = _CountingIds()
    clock = _CountingClock()
    output = tmp_path / "output"
    argv = _argv(clean_fixture, output, input_format=input_format, timestamp_unit=unit)

    code = normalize_command(argv, ids=ids, clock=clock)

    captured = capsys.readouterr()
    assert code == EXIT_ARGUMENTS
    assert captured.out == ""
    assert "--timestamp-unit" in captured.err
    assert OHLCV_FORMAT in captured.err
    assert ids.calls == NO_DRAWS
    assert clock.calls == 0
    assert not output.exists()


@pytest.mark.parametrize(
    "timeframe", ["5m", "15m", "1h", "4h", "1d", "1w", "1s", "2m", "60s", "", "1M"]
)
def test_a_timeframe_other_than_one_minute_is_an_argument_error_for_binance(
    timeframe: str,
    tmp_path: Path,
    binance_root: Path,
    clean_fixture: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Exit 2 for the Binance format; the same value stays exit 1 for ohlcv-csv/1."""
    ids = _CountingIds()
    clock = _CountingClock()
    output = tmp_path / "output"
    fixture = binance_root / f"{BINANCE_STEMS[1]}.valid.csv"

    code = normalize_command(
        _binance_argv(fixture, output, timeframe=timeframe), ids=ids, clock=clock
    )
    captured = capsys.readouterr()
    control = normalize_command(
        _argv(
            clean_fixture,
            tmp_path / "control",
            timeframe=timeframe,
            input_format=OHLCV_FORMAT,
        ),
        ids=_CountingIds(),
        clock=_CountingClock(),
    )
    control_captured = capsys.readouterr()

    assert code == EXIT_ARGUMENTS
    assert captured.out == ""
    assert "--timeframe" in captured.err
    assert "1m" in captured.err
    if timeframe:
        assert f" {timeframe}" not in captured.err
    assert ids.calls == NO_DRAWS
    assert clock.calls == 0
    assert not output.exists()
    assert control == EXIT_REFUSAL
    assert RefusalCode.TIMEFRAME_GRID.value in control_captured.out
    assert not (tmp_path / "control").exists()


def test_an_argument_coupling_error_leaves_an_existing_output_directory_untouched(
    tmp_path: Path,
    binance_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = _output_with_unrelated_entry(tmp_path)
    before = _snapshot(output)
    fixture = binance_root / f"{BINANCE_STEMS[0]}.valid.csv"

    code = normalize_command(
        _argv(fixture, output, input_format=BINANCE_FORMAT),
        ids=fixed_ids,
        clock=fixed_clock,
    )

    assert code == EXIT_ARGUMENTS
    assert _snapshot(output) == before == ((UNRELATED_NAME, len(UNRELATED_BYTES)),)
    assert capsys.readouterr().out == ""


def test_the_default_input_format_is_unchanged_by_the_new_arguments(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """Omitting ``--input-format`` and naming ``ohlcv-csv/1`` emit the same bytes."""
    omitted = tmp_path / "omitted"
    explicit = tmp_path / "explicit"

    omitted_code = normalize_command(
        _argv(clean_fixture, omitted), ids=fixed_ids, clock=fixed_clock
    )
    explicit_code = normalize_command(
        _argv(clean_fixture, explicit, input_format=OHLCV_FORMAT),
        ids=fixed_ids,
        clock=fixed_clock,
    )

    assert omitted_code == explicit_code == EXIT_SUCCESS
    assert _output_bytes(omitted) == _output_bytes(explicit)
    descriptor = _descriptor(omitted)
    (partition,) = _partitions(omitted)
    assert descriptor.raw_source_provenance[0].source_name == "ohlcv-csv"
    assert descriptor.raw_source_provenance[0].source_version == "1.0.0"
    assert descriptor.known_limitations == (P2_B1_LIMITATION,)
    assert partition.quality_observations == (P2_B1_LIMITATION,)
    for data in _output_bytes(omitted):
        assert b"P2-B3" not in data
        assert b"binance" not in data


def test_a_binance_run_writes_the_three_files_with_its_provenance_and_limitations(
    tmp_path: Path,
    binance_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "output"
    fixture = binance_root / f"{BINANCE_STEMS[1]}.valid.csv"
    raw_sha256 = hashlib.sha256(fixture.read_bytes()).hexdigest()

    code = normalize_command(
        _binance_argv(fixture, output), ids=fixed_ids, clock=fixed_clock
    )

    captured = capsys.readouterr()
    assert code == EXIT_SUCCESS
    assert captured.out == ""
    assert captured.err == ""
    assert _names(output) == sorted(OUTPUT_FILE_NAMES)
    descriptor = _descriptor(output)
    (partition,) = _partitions(output)
    assert descriptor.raw_source_provenance == (
        RawSourceProvenance(
            source_name="binance-spot-kline-csv",
            source_version="1.0.0",
            source_record=fixture.name,
            source_hash=raw_sha256,
        ),
    )
    assert partition.raw_source_provenance == descriptor.raw_source_provenance
    assert descriptor.raw_checksums == (raw_sha256,)
    assert partition.raw_checksum == raw_sha256
    assert descriptor.source == BINANCE_SOURCE
    assert descriptor.timeframe == "1m"
    assert descriptor.instrument.canonical_id == INSTRUMENT_ID
    assert descriptor.dataset_id == FIXED_DATASET_ID
    assert descriptor.known_limitations == (P2_B3_LIMITATION, P2_B1_LIMITATION)
    assert partition.quality_observations == (P2_B3_LIMITATION, P2_B1_LIMITATION)
    assert descriptor.known_limitations == tuple(sorted(descriptor.known_limitations))
    assert descriptor.validation_status is DatasetValidationStatus.VALID
    assert descriptor.start_utc == datetime(2025, 1, 1, tzinfo=UTC)
    assert descriptor.end_utc == datetime(2025, 1, 1, 1, 0, tzinfo=UTC)
    container = (output / CONTAINER_FILE_NAME).read_bytes()
    assert container.count(b"\n") == 60 == partition.row_count
    assert hashlib.sha256(container).hexdigest() == partition.content_hash
    assert descriptor.normalized_checksums == (partition.content_hash,)
    descriptor_text = (output / DESCRIPTOR_FILE_NAME).read_text(encoding="utf-8")
    assert str(fixture.parent) not in descriptor_text
    assert fixture.parent.as_posix() not in descriptor_text


def test_a_binance_run_with_the_default_source_records_local_fixture(
    tmp_path: Path,
    binance_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    output = tmp_path / "output"
    fixture = binance_root / f"{BINANCE_STEMS[0]}.valid.csv"

    code = normalize_command(
        _binance_argv(fixture, output, source=None), ids=fixed_ids, clock=fixed_clock
    )

    assert code == EXIT_SUCCESS
    descriptor = _descriptor(output)
    assert descriptor.source == DEFAULT_SOURCE == "local-fixture"
    assert descriptor.start_utc == datetime(2024, 12, 31, 23, 0, tzinfo=UTC)
    assert descriptor.end_utc == datetime(2025, 1, 1, tzinfo=UTC)


def test_a_binance_run_follows_the_accepted_sequence_and_draws_once(
    tmp_path: Path,
    binance_root: Path,
) -> None:
    log: list[tuple[str, ...]] = []
    output = tmp_path / "output"
    fixture = binance_root / f"{BINANCE_STEMS[2]}.valid.csv"

    with pytest.MonkeyPatch.context() as patch:
        _log_filesystem(patch, log)
        code = normalize_command(
            _binance_argv(fixture, output),
            ids=_LoggingIds(log),
            clock=_LoggingClock(log),
        )

    assert code == EXIT_SUCCESS
    assert log == [
        ("open", "rb", fixture.name),
        ("open", "rb", fixture.name),
        ("draw", "dataset_id"),
        ("draw", "partition_id"),
        ("draw", "diagnostic_id"),
        ("draw", "now_utc"),
        ("mkdir", "output"),
        ("open", "xb", CONTAINER_FILE_NAME),
        ("open", "xb", DESCRIPTOR_FILE_NAME),
        ("open", "xb", PARTITIONS_FILE_NAME),
    ]
    descriptor = _descriptor(output)
    assert descriptor.validation_status is DatasetValidationStatus.VALID_WITH_WARNINGS
    assert len(descriptor.missing_intervals) == 1
    assert len(descriptor.duplicate_intervals) == 1


@pytest.mark.parametrize(
    ("name", "unit", "code", "line", "value_length"),
    [
        (
            "SYNTHETIC-ms-declared-us.csv",
            "microseconds",
            RefusalCode.TIMESTAMP_UNIT,
            1,
            13,
        ),
        (
            "SYNTHETIC-us-declared-ms.csv",
            "milliseconds",
            RefusalCode.TIMESTAMP_UNIT,
            1,
            16,
        ),
        ("SYNTHETIC-header-row.csv", "microseconds", RefusalCode.CSV_HEADER, 1, 147),
        ("SYNTHETIC-empty.csv", "milliseconds", RefusalCode.EMPTY_SERIES, 1, 0),
        ("SYNTHETIC-unsorted.csv", "microseconds", RefusalCode.ORDERING, 3, 20),
    ],
)
def test_a_refused_binance_input_exits_one_and_creates_nothing(
    name: str,
    unit: str,
    code: RefusalCode,
    line: int,
    value_length: int,
    tmp_path: Path,
    binance_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ids = _CountingIds()
    clock = _CountingClock()
    output = tmp_path / "output"
    input_path = binance_root / "invalid" / name

    with pytest.MonkeyPatch.context() as patch:
        created = _record_mkdirs(patch)
        exit_code = normalize_command(
            _binance_argv(input_path, output, unit=unit), ids=ids, clock=clock
        )

    captured = capsys.readouterr()
    assert exit_code == EXIT_REFUSAL
    _printed_refusal(
        captured,
        code,
        line=line,
        value_length=value_length,
        diagnostic_id=OTHER_DIAGNOSTIC_ID,
        instant_text=OTHER_INSTANT_TEXT,
    )
    _assert_path_absent(captured.out, input_path)
    _assert_path_absent(captured.out, output)
    assert ids.calls == REFUSAL_DRAWS
    assert clock.calls == 1
    assert created == []
    assert not output.exists()


@pytest.mark.parametrize(
    ("text", "value_length"),
    [case[1:] for case in MALFORMED_CR_INPUTS],
    ids=[case[0] for case in MALFORMED_CR_INPUTS],
)
def test_a_residual_carriage_return_binance_input_exits_one_and_creates_nothing(
    text: str,
    value_length: int,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The reader's field-12 refusal is the command's exit 1, nothing written.

    The canonical ``CSV_ROW_SHAPE`` line names the logical line and the complete
    logical-row length only; no directory is created, no file is written, the
    input is untouched and the one diagnostic draw is the only draw.
    """
    ids = _CountingIds()
    clock = _CountingClock()
    output = tmp_path / "output"
    input_path = tmp_path / "SYNTHETIC-residual-cr.csv"
    input_path.write_bytes(text.encode("ascii"))
    argv = _binance_argv(input_path, output, unit="microseconds")

    with pytest.MonkeyPatch.context() as patch:
        created = _record_mkdirs(patch)
        exit_code = normalize_command(argv, ids=ids, clock=clock)

    captured = capsys.readouterr()
    assert exit_code == EXIT_REFUSAL
    _printed_refusal(
        captured,
        RefusalCode.CSV_ROW_SHAPE,
        line=1,
        value_length=value_length,
        diagnostic_id=OTHER_DIAGNOSTIC_ID,
        instant_text=OTHER_INSTANT_TEXT,
    )
    assert "\\r" not in captured.out
    assert "opaque" not in captured.out
    _assert_path_absent(captured.out, input_path)
    _assert_path_absent(captured.out, output)
    assert ids.calls == REFUSAL_DRAWS
    assert clock.calls == 1
    assert created == []
    assert not output.exists()
    assert input_path.read_bytes() == text.encode("ascii")
    assert _names(tmp_path) == [input_path.name]


def test_a_failed_partitions_write_on_a_binance_run_removes_every_created_file(
    tmp_path: Path,
    binance_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Cleanup is unchanged: the created files go in reverse order, exit 1."""
    output = _output_with_unrelated_entry(tmp_path)
    fixture = binance_root / f"{BINANCE_STEMS[1]}.valid.csv"

    with pytest.MonkeyPatch.context() as patch:
        observed = _fail_the_write_of(patch, PARTITIONS_FILE_NAME)
        unlinked = _record_unlinks(patch)
        code = normalize_command(
            _binance_argv(fixture, output), ids=_CountingIds(), clock=_CountingClock()
        )

    captured = capsys.readouterr()
    assert code == EXIT_REFUSAL
    _assert_output_directory_refusal(captured, output)
    assert observed == [PARTITIONS_FILE_NAME]
    assert unlinked == [
        output / PARTITIONS_FILE_NAME,
        output / DESCRIPTOR_FILE_NAME,
        output / CONTAINER_FILE_NAME,
    ]
    assert _snapshot(output) == ((UNRELATED_NAME, len(UNRELATED_BYTES)),)


@pytest.mark.parametrize("stem", BINANCE_STEMS)
def test_the_binance_command_output_equals_the_committed_goldens_byte_for_byte(
    stem: str,
    tmp_path: Path,
    binance_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    output = tmp_path / "output"
    fixture = binance_root / f"{stem}.valid.csv"
    golden = binance_root / "golden"

    code = normalize_command(
        _binance_argv(fixture, output), ids=fixed_ids, clock=fixed_clock
    )

    assert code == EXIT_SUCCESS
    descriptor_bytes = (output / DESCRIPTOR_FILE_NAME).read_bytes()
    partitions_bytes = (output / PARTITIONS_FILE_NAME).read_bytes()
    assert descriptor_bytes == (golden / f"{stem}.descriptor.json").read_bytes()
    assert partitions_bytes == (golden / f"{stem}.partitions.json").read_bytes()
    hash_file = (golden / f"{stem}.content_hash.txt").read_bytes()
    assert hash_file == (_descriptor(output).content_hash + "\n").encode("ascii")
    assert b"\r" not in hash_file


# --- the module entry point -------------------------------------------------------


def test_the_module_entry_point_runs_the_command_with_the_production_providers(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    clean_fixture: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "output"
    before = datetime.now(UTC)
    monkeypatch.setattr(sys, "argv", [PROGRAM, *_argv(clean_fixture, output)])
    monkeypatch.delitem(sys.modules, "crypto_lab_offline_data.__main__", raising=False)

    with pytest.raises(SystemExit) as info:
        runpy.run_module("crypto_lab_offline_data", run_name="__main__")

    assert info.value.code == EXIT_SUCCESS
    assert capsys.readouterr().out == ""
    assert _names(output) == sorted(OUTPUT_FILE_NAMES)
    descriptor = DatasetDescriptor.model_validate_json(
        (output / DESCRIPTOR_FILE_NAME).read_bytes(), strict=True
    )
    assert (
        validate_prefixed_uuid4(descriptor.dataset_id, "ds_") == descriptor.dataset_id
    )
    assert validate_prefixed_uuid4(descriptor.partition_ids[0], "part_")
    assert descriptor.dataset_id != FIXED_DATASET_ID
    assert before <= require_utc(descriptor.created_at_utc) <= datetime.now(UTC)
    assert descriptor.created_at_utc == descriptor.imported_at_utc


def test_importing_the_entry_point_as_a_module_runs_nothing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Imported under its own name the guard is false: no parse, no exit, no file."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", [PROGRAM, "normalize"])
    monkeypatch.delitem(sys.modules, "crypto_lab_offline_data.__main__", raising=False)

    module = importlib.import_module("crypto_lab_offline_data.__main__")

    assert module.normalize_command is normalize_command
    assert capsys.readouterr() == ("", "")
    assert list(tmp_path.iterdir()) == []


def test_the_module_entry_point_exits_two_without_arguments(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", [PROGRAM])
    monkeypatch.delitem(sys.modules, "crypto_lab_offline_data.__main__", raising=False)

    with pytest.raises(SystemExit) as info:
        runpy.run_module("crypto_lab_offline_data", run_name="__main__")

    assert info.value.code == EXIT_ARGUMENTS
    assert capsys.readouterr().err.startswith("usage: crypto-lab-offline-data")
    assert list(tmp_path.iterdir()) == []
