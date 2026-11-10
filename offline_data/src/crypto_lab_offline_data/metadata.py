"""Dataset metadata emission of plan sections 5.1 and 5.4.

``build_dataset_metadata`` turns the products of the earlier steps, a
``ValidatedSeries`` (Task 2), the ``NormalizedContainer`` its write produced
and the ``RawChecksum`` of the input bytes, into the core's own
``DatasetDescriptor`` and the one ``DatasetPartition`` of this slice, mapped
field by field as section 5.1 prescribes. The identifiers and the one instant
come from the injected providers: one ``ds_`` draw, one ``part_`` draw and one
``now_utc`` draw that fills both ``imported_at_utc`` and ``created_at_utc``.
``venue`` and ``instrument`` come from the ``InstrumentRef`` the command built
with the core's ``parse_instrument_id``; ``source`` is the command's bounded
text; the single ``RawSourceProvenance`` names the input format's identity
from the literal ``SOURCE_IDENTITIES`` table (``ohlcv-csv`` at version
``1.0.0`` for the default ``source_format``, ``binance-spot-kline-csv`` at
``1.0.0`` for the second slice's format), the bounded input file name and the
raw checksum; the bounds, intervals, ``row_count`` and both checksums are the
validated series' and the container's; ``validation_status`` is ``VALID`` when
the series has no missing and no duplicate interval and ``VALID_WITH_WARNINGS``
otherwise (reading R4; a refused input never reaches this function, so
``INVALID`` is never emitted); and ``known_limitations`` and the partition's
``quality_observations`` both carry the P2-B1 text naming the interim
container, for ``binance-spot-kline-csv/1`` runs the P2-B3 text naming what
that format drops as well, each tuple sorted (the core requires sorted
collections, so the ``P2-B3:`` text lands first) and the latter sorted
together with the differing-duplicate observation when the series raised it
(reading R3). Every existing call keeps the default ``source_format`` and
emits bytes identical to the first slice's.

The content hash follows section 5.4: the descriptor is built with a
placeholder ``content_hash`` of sixty-four zeros, hashed with the core's
``dataset_metadata_hash`` (whose profile excludes the placeholder together
with the identifiers and instants), re-created through
``DatasetDescriptor.model_validate`` over its dump with the digest in place,
and checked with ``validate_dataset_identity``. ``model_copy(update=...)`` is
never used, so every field passes the core validators.

The boundary is the sub-project's usual one. An unsupported timeframe is the
``OFFLINE_DATA.TIMEFRAME_GRID`` refusal at line ``0`` naming the argument's
length, decided before any provider is drawn. The ``ds_`` and ``part_``
identifiers and the one instant are drawn and validated next, before any core
model is built and outside every handler, so ``ProviderContractError``
(reading R7) is the only exception that crosses. The core models are then
built inside one handler that converts a core ``ValueError`` (the Pydantic
``ValidationError`` included) into the refusal ``OFFLINE_DATA.METADATA_FIELD``
of section 5.4: a core model refused a value this function records from its
arguments or its consumed products, a ``source`` or ``input_name`` outside
the core's ``BoundedText`` bounds, a ``content_hash``, ``normalized_checksum``
or ``sha256`` of the consumed ``NormalizedContainer`` or ``RawChecksum`` that
is not the core's ``Sha256`` form, or any other recorded field of the consumed
``ValidatedSeries``, ``NormalizedContainer`` or ``RawChecksum`` (``row_count``,
``start_utc``, ``end_utc``, the interval tuples, the observations) the core
refuses. The refusal is at line ``0`` with value length ``0`` because that one
handler covers every recorded field and does not inspect the core's error, so
it attributes no length; its message names the rule and never the value. The
``diag_`` identifier and the diagnostic's instant are drawn after the handler,
inside ``refusal``, so no provider draw sits inside it. ``METADATA_FIELD`` is
never emitted for ``INPUT_PATH``'s cases and never replaced by ``INPUT_PATH``;
it is not reachable through the command, whose ``--source`` is bounded at
argument parsing, whose ``input_name`` is the name of the regular file the
reader opened and whose digests are the hashing functions' own, and which maps
it like any refusal (exit ``1``).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Final, Literal

from crypto_lab.datasets.hashing import (
    dataset_metadata_hash,
    validate_dataset_identity,
)
from crypto_lab.datasets.models import (
    DatasetDataType,
    DatasetDescriptor,
    DatasetPartition,
    DatasetValidationStatus,
    RawSourceProvenance,
)
from crypto_lab.domain.identifiers import validate_prefixed_uuid4
from crypto_lab.domain.records import InstrumentRef
from crypto_lab.domain.results import Failure, Success
from crypto_lab.domain.time import require_utc

from crypto_lab_offline_data import __version__
from crypto_lab_offline_data.candle_csv import WHOLE_INPUT_LINE
from crypto_lab_offline_data.diagnostics import (
    SOURCE_COMPONENT,
    ProviderContractError,
    RefusalCode,
    refusal,
)
from crypto_lab_offline_data.normalize import (
    COLUMN_SCHEMA_VERSION,
    NormalizedContainer,
    RawChecksum,
)
from crypto_lab_offline_data.providers import (
    DATASET_ID_PREFIX,
    DIAGNOSTIC_ID_PREFIX,
    PARTITION_ID_PREFIX,
    Clock,
    IdProvider,
)
from crypto_lab_offline_data.validation import (
    SUPPORTED_TIMEFRAME_SECONDS,
    ValidatedSeries,
)

#: The core schema version of every descriptor and partition this slice emits.
SCHEMA_VERSION: Final = "1.0.0"


class InputFormat(StrEnum):
    """The closed set of input formats the command reads (second slice, 2.5)."""

    OHLCV_CSV_1 = "ohlcv-csv/1"
    BINANCE_SPOT_KLINE_CSV_1 = "binance-spot-kline-csv/1"


#: The provenance ``source_name`` and ``source_version`` of ``ohlcv-csv/1``.
SOURCE_NAME = "ohlcv-csv"
SOURCE_VERSION = "1.0.0"
#: The provenance identity of each input format, a literal table (second
#: slice, section 2.5); its ``ohlcv-csv/1`` pair equals the two constants above.
SOURCE_IDENTITIES = {
    InputFormat.OHLCV_CSV_1: ("ohlcv-csv", "1.0.0"),
    InputFormat.BINANCE_SPOT_KLINE_CSV_1: ("binance-spot-kline-csv", "1.0.0"),
}
#: The ``normalization_implementation`` identifier: the distribution's name.
NORMALIZATION_IMPLEMENTATION = SOURCE_COMPONENT
#: The command's default ``--source`` (section 5.1).
DEFAULT_SOURCE = "local-fixture"
#: The input contract admits only ``Z``, so the original timezone is UTC.
ORIGINAL_TIMEZONE = "UTC"
#: The one container file of this slice (section 5.3).
CONTAINER_FILE_NAME = "part-0000.ndjson"
#: The ``content_hash`` the descriptor carries while its hash is computed.
PLACEHOLDER_CONTENT_HASH = "0" * 64
#: The core's ``BoundedText`` length bound, applied to ``source`` and the input name.
BOUNDED_TEXT_MAX_LENGTH = 1024
#: The one ``known_limitations`` entry and partition observation (P2-B1, R3).
P2_B1_LIMITATION = (
    "interim container normalized-ndjson/0.1.0; Parquet partition emission "
    "requires the pyarrow acquisition (P2-B1)"
)
#: The second limitation of ``binance-spot-kline-csv/1`` runs (second slice,
#: section 2.6): what the format drops, and that no real archive was ingested.
P2_B3_LIMITATION = (
    "P2-B3: binance-spot-kline-csv/1 fields 7 to 12 (close time, quote asset "
    "volume, number of trades, taker buy volumes, ignore) are validated for "
    "shape and not retained; synthetic fixtures only, no real Binance archive "
    "ingested"
)
_IDENTIFIER_PREFIXES = {
    "dataset_id": DATASET_ID_PREFIX,
    "partition_id": PARTITION_ID_PREFIX,
    "diagnostic_id": DIAGNOSTIC_ID_PREFIX,
}

type IdentifierMethod = Literal["dataset_id", "partition_id", "diagnostic_id"]


@dataclass(frozen=True, slots=True)
class DatasetBundle:
    """The descriptor and its partitions, identity validated."""

    descriptor: DatasetDescriptor
    partitions: tuple[DatasetPartition, ...]


type MetadataResult = Success[DatasetBundle] | Failure


def drawn_identifier(ids: IdProvider, method: IdentifierMethod) -> str:
    """Draw one prefixed identifier and validate it against the core grammar.

    A value that is not a string or that the core refuses is a fault of the
    caller's composition (reading R7): ``ProviderContractError`` names the
    method and never the value, and the core error is not chained.
    """
    value = getattr(ids, method)()
    if not isinstance(value, str):
        raise ProviderContractError(method)
    try:
        return validate_prefixed_uuid4(value, _IDENTIFIER_PREFIXES[method])
    except ValueError:
        raise ProviderContractError(method) from None


def drawn_instant(clock: Clock) -> datetime:
    """Draw one instant and validate that it is timezone-aware UTC (R7)."""
    value = clock.now_utc()
    if not isinstance(value, datetime):
        raise ProviderContractError("now_utc")
    try:
        return require_utc(value)
    except ValueError:
        raise ProviderContractError("now_utc") from None


def build_dataset_metadata(
    series: ValidatedSeries,
    container: NormalizedContainer,
    raw: RawChecksum,
    *,
    instrument: InstrumentRef,
    timeframe: str,
    source: str,
    input_name: str,
    ids: IdProvider,
    clock: Clock,
    source_format: InputFormat = InputFormat.OHLCV_CSV_1,
) -> MetadataResult:
    """Build the section 5.1 descriptor and partition with the section 5.4 identity.

    ``timeframe`` is checked first and refused as ``TIMEFRAME_GRID`` at line
    ``0`` before any draw; the ``ds_`` and ``part_`` identifiers and the one
    instant are then drawn and validated outside every handler; the core
    models are built inside one handler whose only effect is to leave
    ``bundle`` unset, and the ``METADATA_FIELD`` refusal (line ``0``, value
    length ``0``) is drawn after it, so no provider draw sits inside a handler
    that converts a core error. ``source_format`` selects the provenance
    identity and the limitation texts; its default is the first slice's format.
    """
    if timeframe not in SUPPORTED_TIMEFRAME_SECONDS:
        return refusal(
            RefusalCode.TIMEFRAME_GRID,
            line=WHOLE_INPUT_LINE,
            value_length=len(timeframe),
            ids=ids,
            clock=clock,
        )
    dataset_id = drawn_identifier(ids, "dataset_id")
    partition_id = drawn_identifier(ids, "partition_id")
    instant = drawn_instant(clock)
    try:
        bundle: DatasetBundle | None = _bundle(
            series,
            container,
            raw,
            instrument=instrument,
            timeframe=timeframe,
            source=source,
            input_name=input_name,
            dataset_id=dataset_id,
            partition_id=partition_id,
            instant=instant,
            source_format=source_format,
        )
    except ValueError:
        bundle = None
    if bundle is None:
        return refusal(
            RefusalCode.METADATA_FIELD,
            line=WHOLE_INPUT_LINE,
            value_length=0,
            ids=ids,
            clock=clock,
        )
    return Success[DatasetBundle](outcome="SUCCESS", value=bundle)


def _bundle(
    series: ValidatedSeries,
    container: NormalizedContainer,
    raw: RawChecksum,
    *,
    instrument: InstrumentRef,
    timeframe: str,
    source: str,
    input_name: str,
    dataset_id: str,
    partition_id: str,
    instant: datetime,
    source_format: InputFormat,
) -> DatasetBundle:
    """The section 5.1 models with the section 5.4 identity; core errors propagate."""
    source_name, source_version = SOURCE_IDENTITIES[source_format]
    limitations = _limitations(source_format)
    provenance = RawSourceProvenance(
        source_name=source_name,
        source_version=source_version,
        source_record=input_name,
        source_hash=raw.sha256,
    )
    partition = DatasetPartition(
        schema_version=SCHEMA_VERSION,
        partition_id=partition_id,
        dataset_id=dataset_id,
        ordinal=0,
        relative_path=f"datasets/{dataset_id}/{CONTAINER_FILE_NAME}",
        content_hash=container.content_hash,
        row_count=container.row_count,
        start_utc=series.start_utc,
        end_utc=series.end_utc,
        raw_checksum=raw.sha256,
        normalized_checksum=container.normalized_checksum,
        column_schema_version=COLUMN_SCHEMA_VERSION,
        raw_source_provenance=(provenance,),
        quality_observations=tuple(sorted({*limitations, *series.observations})),
    )
    has_quality_facts = bool(series.missing_intervals or series.duplicate_intervals)
    status = (
        DatasetValidationStatus.VALID_WITH_WARNINGS
        if has_quality_facts
        else DatasetValidationStatus.VALID
    )
    placeholder = DatasetDescriptor(
        schema_version=SCHEMA_VERSION,
        dataset_id=dataset_id,
        content_hash=PLACEHOLDER_CONTENT_HASH,
        source=source,
        venue=instrument.venue,
        instrument=instrument,
        data_type=DatasetDataType.OHLCV,
        timeframe=timeframe,
        start_utc=series.start_utc,
        end_utc=series.end_utc,
        original_timezone=ORIGINAL_TIMEZONE,
        normalized_to_utc=True,
        imported_at_utc=instant,
        raw_source_provenance=(provenance,),
        normalization_implementation=NORMALIZATION_IMPLEMENTATION,
        normalization_version=__version__,
        validation_status=status,
        partition_ids=(partition_id,),
        missing_intervals=series.missing_intervals,
        duplicate_intervals=series.duplicate_intervals,
        diagnostic_ids=(),
        raw_checksums=(raw.sha256,),
        normalized_checksums=(container.normalized_checksum,),
        column_schema_version=COLUMN_SCHEMA_VERSION,
        known_limitations=tuple(sorted(limitations)),
        created_at_utc=instant,
    )
    partitions = (partition,)
    digest = dataset_metadata_hash(placeholder, partitions)
    descriptor = DatasetDescriptor.model_validate(
        {**placeholder.model_dump(), "content_hash": digest}
    )
    validate_dataset_identity(descriptor, partitions)
    return DatasetBundle(descriptor=descriptor, partitions=partitions)


def _limitations(source_format: InputFormat) -> tuple[str, ...]:
    """The limitation texts of a run: P2-B1 always, P2-B3 for the Binance format."""
    if source_format == InputFormat.BINANCE_SPOT_KLINE_CSV_1:
        return (P2_B1_LIMITATION, P2_B3_LIMITATION)
    return (P2_B1_LIMITATION,)
