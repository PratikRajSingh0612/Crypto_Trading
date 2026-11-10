"""The ``normalize`` command of plan Task 3 and its exit table.

``normalize_command`` composes the slice in the accepted order: it reads the
input (``read_ohlcv_csv``), validates it (``validate_series``), digests the raw
bytes (``raw_checksum``), draws each provider value once (``dataset_id``,
``partition_id``, ``diagnostic_id``, ``now_utc``, in that order, each validated
when drawn) and snapshots them into fixed providers, inspects and creates
``--output`` immediately before its first write, writes the container
(``write_normalized_container``), builds the metadata
(``build_dataset_metadata``) and writes ``descriptor.json`` and
``partitions.json`` as the canonical JSON bytes of the models (a JSON array for
the partitions), each through one exclusive create. Every call after the
snapshot receives the fixed providers, so nothing is drawn after the first
write and every later refusal carries the reserved identifier and instant.

Exit codes (plan section 1.6, reading R7): ``0`` success; ``1`` refusal, the
``Failure`` of any step, ``OFFLINE_DATA.INPUT_PATH``,
``OFFLINE_DATA.METADATA_FIELD`` (mapped like any refusal, though unreachable
through this command: ``--source`` is bounded at parsing, ``input_name`` is the
regular file the reader opened and the digests are the hashing functions' own)
and ``OFFLINE_DATA.OUTPUT_DIRECTORY`` included; ``2`` argument parsing only, which
is argparse's own exit for a missing, unknown or malformed argument (a
``--instrument`` the core helper cannot parse and a ``--source`` outside the
core's bounded-text range are refused there, with messages that never echo the
value, while an unsupported ``--timeframe`` is ``validate_series``'s
``TIMEFRAME_GRID`` refusal, exit ``1``, never an argparse error); ``3``
provider fault, the ``ProviderContractError`` any step raises.

``--output`` is taken as given (a relative path is relative to the working
directory) and inspected on its own entry without following it: an absent path
is created with one ``mkdir()`` (its parent must exist); an existing regular
directory is used when it holds none of ``part-0000.ndjson``,
``descriptor.json`` and ``partitions.json`` (any entry at one of those names, a
dangling reparse point included, is refused); a file, a reparse point, a path
that cannot be created and a path the platform rejects are the
``OUTPUT_DIRECTORY`` refusal. Nothing is written outside it and unrelated
entries inside it are never touched.

Cleanup: the command records each file as soon as its exclusive create has
returned and, when a later step fails or a provider fault is raised, removes
those files in reverse order, the completed container included, attempting
each removal even after one fails; a removal that itself fails changes
nothing, the outcome in flight (the refusal or the exit ``3``) stands and
nothing crosses. A partial container is the writer's own to remove. The
directory the command created is never removed, so on exits ``1``, ``2`` and
``3`` ``--output`` holds nothing the command created beyond that directory
and any created file whose removal failed. Every scoped ``OSError`` and the
``ValueError`` a path the platform rejects raises are converted in the helpers
below, and no provider is drawn inside those handlers.

On exit ``1`` the command prints the ``Failure`` as one canonical JSON line and
on exit ``3`` the fault's message, which names the provider method only; both
name no value and no path. On exit ``0`` it prints nothing. The lines go to
standard output because the sub-project's guards admit no ``sys`` import and
therefore no standard-error handle.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from crypto_lab.domain.canonical_json import canonical_json_bytes, canonical_json_text
from crypto_lab.domain.records import InstrumentRef, MarketType, parse_instrument_id
from crypto_lab.domain.results import Failure

from crypto_lab_offline_data.candle_csv import (
    DEFAULT_MAX_BYTES,
    WHOLE_INPUT_LINE,
    read_ohlcv_csv,
)
from crypto_lab_offline_data.diagnostics import (
    ProviderContractError,
    RefusalCode,
    refusal,
)
from crypto_lab_offline_data.metadata import (
    BOUNDED_TEXT_MAX_LENGTH,
    CONTAINER_FILE_NAME,
    DEFAULT_SOURCE,
    SCHEMA_VERSION,
    build_dataset_metadata,
    drawn_identifier,
    drawn_instant,
)
from crypto_lab_offline_data.normalize import (
    _is_absent,
    _is_reparse_point,
    raw_checksum,
    write_normalized_container,
)
from crypto_lab_offline_data.providers import Clock, IdProvider
from crypto_lab_offline_data.validation import validate_series

PROGRAM = "crypto-lab-offline-data"
DESCRIPTOR_FILE_NAME = "descriptor.json"
PARTITIONS_FILE_NAME = "partitions.json"
#: The three entries the command creates under ``--output``, in write order.
OUTPUT_FILE_NAMES = (CONTAINER_FILE_NAME, DESCRIPTOR_FILE_NAME, PARTITIONS_FILE_NAME)
EXIT_SUCCESS = 0
EXIT_REFUSAL = 1
EXIT_ARGUMENTS = 2
EXIT_PROVIDER_FAULT = 3


@dataclass(frozen=True, slots=True)
class _SnapshotIds:
    """The three identifiers drawn once, served as a fixed ``IdProvider``."""

    dataset: str
    partition: str
    diagnostic: str

    def dataset_id(self) -> str:
        return self.dataset

    def partition_id(self) -> str:
        return self.partition

    def diagnostic_id(self) -> str:
        return self.diagnostic


@dataclass(frozen=True, slots=True)
class _SnapshotClock:
    """The one instant drawn once, served as a fixed ``Clock``."""

    instant: datetime

    def now_utc(self) -> datetime:
        return self.instant


def build_parser() -> argparse.ArgumentParser:
    """The command parser: one ``normalize`` command with its five options."""
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description="Offline historical candle data: the first bounded slice.",
    )
    commands = parser.add_subparsers(dest="command", required=True, metavar="command")
    normalize = commands.add_parser(
        "normalize",
        help="read one ohlcv-csv/1 input and emit its interim container and metadata",
    )
    normalize.add_argument("--input", required=True, help="the ohlcv-csv/1 input file")
    normalize.add_argument(
        "--output",
        required=True,
        help="the output directory, created when absent; must hold no output name",
    )
    normalize.add_argument(
        "--instrument",
        required=True,
        type=_instrument_argument,
        help="the canonical instrument identity VENUE:BASE/QUOTE:MARKET",
    )
    normalize.add_argument(
        "--timeframe",
        required=True,
        help="the bar timeframe: 1m, 5m, 15m, 1h, 4h or 1d",
    )
    normalize.add_argument(
        "--source",
        default=DEFAULT_SOURCE,
        type=_source_argument,
        help=(
            f"the descriptor source text, 1 to {BOUNDED_TEXT_MAX_LENGTH} characters "
            f"(default: {DEFAULT_SOURCE})"
        ),
    )
    return parser


def _instrument_argument(text: str) -> InstrumentRef:
    """Parse ``--instrument`` with the core helper into an ``InstrumentRef``."""
    try:
        venue, base, quote, market = parse_instrument_id(text)
        return InstrumentRef(
            schema_version=SCHEMA_VERSION,
            canonical_id=text,
            venue=venue,
            base_asset=base,
            quote_asset=quote,
            market_type=MarketType(market),
        )
    except ValueError:
        raise argparse.ArgumentTypeError(
            "instrument must be a canonical VENUE:BASE/QUOTE:MARKET identity"
        ) from None


def _source_argument(text: str) -> str:
    """Bound ``--source`` to the core's bounded-text range."""
    if not 1 <= len(text) <= BOUNDED_TEXT_MAX_LENGTH:
        raise argparse.ArgumentTypeError(
            f"source must be 1 to {BOUNDED_TEXT_MAX_LENGTH} characters"
        )
    return text


def normalize_command(
    argv: Sequence[str] | None,
    *,
    ids: IdProvider,
    clock: Clock,
) -> int:
    """Run ``normalize`` over ``argv`` (``None``: the process arguments); exit code.

    argparse's own exits (``2`` for an argument error, ``0`` for ``--help``) are
    returned as they are; a ``ProviderContractError`` from any step removes the
    files the command created and exits ``3``.
    """
    try:
        arguments = build_parser().parse_args(argv)
    except SystemExit as exit_request:
        return (
            exit_request.code if isinstance(exit_request.code, int) else EXIT_ARGUMENTS
        )
    created: list[Path] = []
    try:
        return _run(arguments, created, ids=ids, clock=clock)
    except ProviderContractError as fault:
        _remove_created(created)
        print(fault)
        return EXIT_PROVIDER_FAULT


def _run(
    arguments: argparse.Namespace,
    created: list[Path],
    *,
    ids: IdProvider,
    clock: Clock,
) -> int:
    """The accepted sequence; ``created`` records every file once it is owned."""
    input_path = Path(arguments.input)
    read = read_ohlcv_csv(input_path, ids=ids, clock=clock)
    if isinstance(read, Failure):
        return _refused(read)
    validated = validate_series(
        read.value, timeframe=arguments.timeframe, ids=ids, clock=clock
    )
    if isinstance(validated, Failure):
        return _refused(validated)
    raw = raw_checksum(input_path, max_bytes=DEFAULT_MAX_BYTES, ids=ids, clock=clock)
    if isinstance(raw, Failure):
        return _refused(raw)
    snapshot_ids = _SnapshotIds(
        dataset=drawn_identifier(ids, "dataset_id"),
        partition=drawn_identifier(ids, "partition_id"),
        diagnostic=drawn_identifier(ids, "diagnostic_id"),
    )
    snapshot_clock = _SnapshotClock(instant=drawn_instant(clock))
    output = Path(arguments.output)
    if not _prepare_output_directory(output):
        return _refused(_output_refusal(snapshot_ids, snapshot_clock))
    container_path = output / CONTAINER_FILE_NAME
    written = write_normalized_container(
        validated.value, container_path, ids=snapshot_ids, clock=snapshot_clock
    )
    if isinstance(written, Failure):
        return _refused(written)
    created.append(container_path)
    built = build_dataset_metadata(
        validated.value,
        written.value,
        raw.value,
        instrument=arguments.instrument,
        timeframe=arguments.timeframe,
        source=arguments.source,
        input_name=input_path.name,
        ids=snapshot_ids,
        clock=snapshot_clock,
    )
    if isinstance(built, Failure):
        _remove_created(created)
        return _refused(built)
    documents = (
        (DESCRIPTOR_FILE_NAME, canonical_json_bytes(built.value.descriptor)),
        (PARTITIONS_FILE_NAME, canonical_json_bytes(list(built.value.partitions))),
    )
    for name, data in documents:
        if not _write_new_file(output / name, data, created):
            _remove_created(created)
            return _refused(_output_refusal(snapshot_ids, snapshot_clock))
    return EXIT_SUCCESS


def _refused(failure: Failure) -> int:
    """Print the refusal as one canonical JSON line and return exit ``1``."""
    print(canonical_json_text(failure))
    return EXIT_REFUSAL


def _output_refusal(ids: IdProvider, clock: Clock) -> Failure:
    """The whole-input ``OUTPUT_DIRECTORY`` refusal from the fixed providers."""
    return refusal(
        RefusalCode.OUTPUT_DIRECTORY,
        line=WHOLE_INPUT_LINE,
        value_length=0,
        ids=ids,
        clock=clock,
    )


def _prepare_output_directory(output: Path) -> bool:
    """Create ``output`` when absent or accept it as an empty-enough directory.

    The entry is inspected without following it: an absent path is created
    with one ``mkdir()`` (no parent is created); an existing entry must not be
    a reparse point, must be a directory and must hold no entry of any kind at
    the three output names. Every ``OSError`` and the ``ValueError`` of a path
    the platform rejects are converted into ``False``; no provider is drawn.
    """
    try:
        if _is_absent(output):
            output.mkdir()
            return True
        if _is_reparse_point(output) or not output.is_dir():
            return False
        return all(_is_absent(output / name) for name in OUTPUT_FILE_NAMES)
    except (OSError, ValueError):
        return False


def _write_new_file(path: Path, data: bytes, created: list[Path]) -> bool:
    """Create ``path`` exclusively and write ``data``; record it once owned.

    The path joins ``created`` as soon as the exclusive create has returned,
    before the write, so a partial file is removed by the caller's reverse-order
    cleanup like a completed one. A failure before the create owns nothing.
    """
    try:
        with path.open("xb") as handle:
            created.append(path)
            handle.write(data)
    except (OSError, ValueError):
        return False
    return True


def _remove_created(created: Sequence[Path]) -> None:
    """Remove the files the command created, last first; a failure changes nothing."""
    for path in reversed(created):
        try:
            path.unlink()
        except OSError:
            pass
