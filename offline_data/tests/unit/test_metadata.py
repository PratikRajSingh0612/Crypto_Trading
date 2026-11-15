"""Dataset metadata emission of plan sections 5.1 and 5.4 (Task 3).

``build_dataset_metadata`` is pinned field by field against the section 5.1
mapping for both valid fixtures: every descriptor and partition field is
asserted with an explicit expected value built on the test side (the fixture
bytes hashed with ``hashlib``, the fixture definitions for the bounds and
intervals, the fixed identifiers and instant of ``conftest``), and the field
sets are pinned by name so no field is forgotten or added. The content hash is
recomputed with the core's own ``dataset_metadata_hash`` and checked with
``validate_dataset_identity``, and it is shown to exclude the identifiers and
instants the hashing profile excludes, so the golden hash of a fixture is
stable across providers. The clean fixture is ``VALID`` and the gaps-duplicates
fixture ``VALID_WITH_WARNINGS`` (reading R4). The boundary is pinned as every
other public function's: one section 5.4 refusal for an unsupported timeframe
(``TIMEFRAME_GRID`` at line ``0`` with the argument's length) and for a value
the core models refuse that the function records from its arguments or its
consumed products (``METADATA_FIELD`` at line ``0`` with value length ``0``: a
``source`` or ``input_name`` at each side of the bounds, a corrupt digest in
the consumed ``RawChecksum`` or ``NormalizedContainer``, and a recorded field
of the consumed ``ValidatedSeries`` the core refuses; the value never enters
the diagnostic and the code is never ``INPUT_PATH``), never a core
``ValidationError`` escaping; and ``ProviderContractError`` (reading R7) for a
provider value the core refuses, drawn and validated before any core model is
built and outside the one converting handler, with the draw counts and the
draw order pinned on every path.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

import pytest
from crypto_lab.datasets.hashing import (
    dataset_metadata_hash,
    validate_dataset_identity,
)
from crypto_lab.datasets.models import (
    DatasetDataType,
    DatasetDescriptor,
    DatasetPartition,
    DatasetValidationStatus,
    DuplicateInterval,
    RawSourceProvenance,
    TimeInterval,
)
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.diagnostics import (
    Diagnostic,
    DiagnosticCategory,
    DiagnosticSeverity,
)
from crypto_lab.domain.records import InstrumentRef, MarketType
from crypto_lab.domain.results import Failure, Success
from pydantic import ValidationError

from crypto_lab_offline_data import __version__
from crypto_lab_offline_data.binance_kline_csv import (
    TimestampUnit,
    read_binance_kline_csv,
)
from crypto_lab_offline_data.candle_csv import (
    DEFAULT_MAX_BYTES,
    WHOLE_INPUT_LINE,
    read_ohlcv_csv,
)
from crypto_lab_offline_data.diagnostics import (
    SOURCE_COMPONENT,
    ProviderContractError,
    RefusalCode,
)
from crypto_lab_offline_data.metadata import (
    BOUNDED_TEXT_MAX_LENGTH,
    CONTAINER_FILE_NAME,
    DEFAULT_SOURCE,
    NORMALIZATION_IMPLEMENTATION,
    ORIGINAL_TIMEZONE,
    P2_B1_LIMITATION,
    P2_B3_LIMITATION,
    PLACEHOLDER_CONTENT_HASH,
    SOURCE_IDENTITIES,
    SOURCE_NAME,
    SOURCE_VERSION,
    DatasetBundle,
    InputFormat,
    build_dataset_metadata,
    drawn_identifier,
    drawn_instant,
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
from crypto_lab_offline_data.validation import (
    DIFFERING_DUPLICATE_OBSERVATION,
    ValidatedSeries,
    validate_series,
)

FIXED_DATASET_ID = "ds_0f8c2a4e-6b3d-4f1a-9c7e-2d5b8a1f3c6e"
FIXED_PARTITION_ID = "part_7a1d3e5f-9b2c-4d6e-8f1a-3c5e7b9d1f2a"
FIXED_DIAGNOSTIC_ID = "diag_3c9e1b7d-5f2a-4b8c-a6d4-9e1f3b5d7c2a"
FIXED_INSTANT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
OTHER_DATASET_ID = "ds_8b2d4f6a-1c3e-4a5b-b7d9-0e2f4a6c8b1d"
OTHER_PARTITION_ID = "part_8b2d4f6a-1c3e-4a5b-b7d9-0e2f4a6c8b1d"
OTHER_DIAGNOSTIC_ID = "diag_8b2d4f6a-1c3e-4a5b-b7d9-0e2f4a6c8b1d"
OTHER_INSTANT = datetime(2031, 12, 31, 23, 59, 59, tzinfo=UTC)
MALFORMED_IDENTIFIER = "not-a-canonical-uuid4"
NAIVE_INSTANT = datetime(2026, 1, 2, 3, 4, 5)  # noqa: DTZ001
GAPS_DUPLICATES_FIXTURE = "btcusdt-1m-gaps-duplicates.valid.csv"
CLEAN_FIXTURE = "btcusdt-1m-clean.valid.csv"
INSTRUMENT_ID = "BINANCE:BTC/USDT:SPOT"
START = datetime(2024, 1, 1, tzinfo=UTC)
FIXTURE_ROW_COUNT = 60
PLAN_LIMITATION_TEXT = (
    "interim container normalized-ndjson/0.1.0; Parquet partition emission "
    "requires the pyarrow acquisition (P2-B1)"
)
BINANCE_PLAN_LIMITATION_TEXT = (
    "P2-B3: binance-spot-kline-csv/1 fields 7 to 12 (close time, quote asset "
    "volume, number of trades, taker buy volumes, ignore) are validated for "
    "shape and not retained; synthetic fixtures only, no real Binance archive "
    "ingested"
)
BINANCE_US_FIXTURE = "SYNTHETIC-BTCUSDT-1m-2025-01-01-us.valid.csv"
BINANCE_START = datetime(2025, 1, 1, tzinfo=UTC)
DESCRIPTOR_FIELDS = {
    "schema_version",
    "dataset_id",
    "content_hash",
    "source",
    "venue",
    "instrument",
    "data_type",
    "timeframe",
    "start_utc",
    "end_utc",
    "original_timezone",
    "normalized_to_utc",
    "imported_at_utc",
    "raw_source_provenance",
    "normalization_implementation",
    "normalization_version",
    "validation_status",
    "partition_ids",
    "missing_intervals",
    "duplicate_intervals",
    "diagnostic_ids",
    "raw_checksums",
    "normalized_checksums",
    "column_schema_version",
    "known_limitations",
    "created_at_utc",
}
PARTITION_FIELDS = {
    "schema_version",
    "partition_id",
    "dataset_id",
    "ordinal",
    "relative_path",
    "content_hash",
    "row_count",
    "start_utc",
    "end_utc",
    "raw_checksum",
    "normalized_checksum",
    "column_schema_version",
    "raw_source_provenance",
    "quality_observations",
}


def _at(minute: int) -> datetime:
    return START + timedelta(minutes=minute)


def _instrument() -> InstrumentRef:
    return InstrumentRef(
        schema_version="1.0.0",
        canonical_id=INSTRUMENT_ID,
        venue="BINANCE",
        base_asset="BTC",
        quote_asset="USDT",
        market_type=MarketType.SPOT,
    )


@dataclass(frozen=True, slots=True)
class _Inputs:
    """The Task 1 and Task 2 products one metadata build consumes."""

    series: ValidatedSeries
    container: NormalizedContainer
    raw: RawChecksum
    container_path: Path
    input_name: str
    raw_sha256: str


def _inputs(fixture: Path, directory: Path, ids: IdProvider, clock: Clock) -> _Inputs:
    read = read_ohlcv_csv(fixture, ids=ids, clock=clock)
    return _products(read, fixture, directory, ids, clock)


def _binance_inputs(
    fixture: Path, directory: Path, ids: IdProvider, clock: Clock
) -> _Inputs:
    read = read_binance_kline_csv(
        fixture, timestamp_unit=TimestampUnit.MICROSECONDS, ids=ids, clock=clock
    )
    return _products(read, fixture, directory, ids, clock)


def _products(
    read: object, fixture: Path, directory: Path, ids: IdProvider, clock: Clock
) -> _Inputs:
    assert isinstance(read, Success)
    validated = validate_series(read.value, timeframe="1m", ids=ids, clock=clock)
    assert isinstance(validated, Success)
    container_path = directory / CONTAINER_FILE_NAME
    written = write_normalized_container(
        validated.value, container_path, ids=ids, clock=clock
    )
    assert isinstance(written, Success)
    raw = raw_checksum(fixture, max_bytes=DEFAULT_MAX_BYTES, ids=ids, clock=clock)
    assert isinstance(raw, Success)
    return _Inputs(
        series=validated.value,
        container=written.value,
        raw=raw.value,
        container_path=container_path,
        input_name=fixture.name,
        raw_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),
    )


def _build(
    inputs: _Inputs,
    ids: IdProvider,
    clock: Clock,
    *,
    timeframe: str = "1m",
    source: str = DEFAULT_SOURCE,
    input_name: str | None = None,
    raw: RawChecksum | None = None,
    container: NormalizedContainer | None = None,
) -> Success[DatasetBundle] | Failure:
    return build_dataset_metadata(
        inputs.series,
        inputs.container if container is None else container,
        inputs.raw if raw is None else raw,
        instrument=_instrument(),
        timeframe=timeframe,
        source=source,
        input_name=inputs.input_name if input_name is None else input_name,
        ids=ids,
        clock=clock,
    )


def _build_for(
    inputs: _Inputs,
    ids: IdProvider,
    clock: Clock,
    source_format: InputFormat,
) -> Success[DatasetBundle] | Failure:
    """Build with an explicit ``source_format``; ``_build`` keeps the default."""
    return build_dataset_metadata(
        inputs.series,
        inputs.container,
        inputs.raw,
        instrument=_instrument(),
        timeframe="1m",
        source=DEFAULT_SOURCE,
        input_name=inputs.input_name,
        ids=ids,
        clock=clock,
        source_format=source_format,
    )


def _bundle(result: Success[DatasetBundle] | Failure) -> DatasetBundle:
    assert isinstance(result, Success)
    assert result.outcome == "SUCCESS"
    assert isinstance(result.value, DatasetBundle)
    assert isinstance(result.value.descriptor, DatasetDescriptor)
    assert len(result.value.partitions) == 1
    assert all(isinstance(p, DatasetPartition) for p in result.value.partitions)
    return result.value


def _single_refusal(
    result: Success[Any] | Failure,
    code: RefusalCode,
    *,
    line: int,
    value_length: int,
    diagnostic_id: str,
    instant: datetime,
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
    assert diagnostic.diagnostic_id == diagnostic_id
    assert diagnostic.timestamp_utc == instant
    assert diagnostic.causal_diagnostic_ids == ()
    assert str(line) in diagnostic.message
    assert code.value in diagnostic.message
    return diagnostic


def _assert_value_absent(diagnostic: Diagnostic, value: str) -> None:
    serialized = json.dumps(diagnostic.model_dump(mode="json"))
    assert value not in serialized


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

    def _answer(self, method: str, valid: str) -> Any:
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

    def now_utc(self) -> Any:
        return self._value


class _LoggingIds:
    """An ``IdProvider`` appending each draw to a shared event log."""

    def __init__(self, log: list[str]) -> None:
        self._log = log

    def dataset_id(self) -> str:
        self._log.append("dataset_id")
        return OTHER_DATASET_ID

    def partition_id(self) -> str:
        self._log.append("partition_id")
        return OTHER_PARTITION_ID

    def diagnostic_id(self) -> str:
        self._log.append("diagnostic_id")
        return OTHER_DIAGNOSTIC_ID


class _LoggingClock:
    """A ``Clock`` appending each draw to a shared event log."""

    def __init__(self, log: list[str]) -> None:
        self._log = log

    def now_utc(self) -> datetime:
        self._log.append("now_utc")
        return OTHER_INSTANT


def _metadata_field_refusal(
    result: Success[Any] | Failure,
    *,
    diagnostic_id: str = OTHER_DIAGNOSTIC_ID,
    instant: datetime = OTHER_INSTANT,
) -> Diagnostic:
    """Assert the section 5.4 ``METADATA_FIELD`` refusal: line 0, value length 0.

    The code is asserted by its literal and shown distinct from ``INPUT_PATH``,
    so the test cannot pass by aliasing one member to the other.
    """
    diagnostic = _single_refusal(
        result,
        RefusalCode.METADATA_FIELD,
        line=WHOLE_INPUT_LINE,
        value_length=0,
        diagnostic_id=diagnostic_id,
        instant=instant,
    )
    assert diagnostic.error_code == "OFFLINE_DATA.METADATA_FIELD"
    assert diagnostic.error_code != RefusalCode.INPUT_PATH.value
    assert diagnostic.message == "line 0 refused by rule OFFLINE_DATA.METADATA_FIELD"
    assert diagnostic.details == {
        "line": 0,
        "rule": "OFFLINE_DATA.METADATA_FIELD",
        "value_length": 0,
    }
    assert "INPUT_PATH" not in json.dumps(diagnostic.model_dump(mode="json"))
    return diagnostic


# --- section 5.1: the clean fixture ----------------------------------------


def test_the_clean_descriptor_maps_every_section_five_one_field(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    inputs = _inputs(clean_fixture, tmp_path, fixed_ids, fixed_clock)
    container_sha256 = hashlib.sha256(inputs.container_path.read_bytes()).hexdigest()

    bundle = _bundle(_build(inputs, fixed_ids, fixed_clock))

    descriptor = bundle.descriptor
    assert set(descriptor.model_dump(mode="json")) == DESCRIPTOR_FIELDS
    assert descriptor.schema_version == "1.0.0"
    assert descriptor.dataset_id == FIXED_DATASET_ID
    assert descriptor.source == "local-fixture" == DEFAULT_SOURCE
    assert descriptor.venue == "BINANCE"
    assert descriptor.instrument == _instrument()
    assert descriptor.instrument.canonical_id == INSTRUMENT_ID
    assert descriptor.data_type is DatasetDataType.OHLCV
    assert descriptor.timeframe == "1m"
    assert descriptor.start_utc == _at(0)
    assert descriptor.end_utc == _at(60)
    assert descriptor.original_timezone == "UTC" == ORIGINAL_TIMEZONE
    assert descriptor.normalized_to_utc is True
    assert descriptor.imported_at_utc == FIXED_INSTANT
    assert descriptor.created_at_utc == FIXED_INSTANT
    assert descriptor.raw_source_provenance == (
        RawSourceProvenance(
            source_name="ohlcv-csv",
            source_version="1.0.0",
            source_record=CLEAN_FIXTURE,
            source_hash=inputs.raw_sha256,
        ),
    )
    assert descriptor.normalization_implementation == "crypto-lab-offline-data"
    assert descriptor.normalization_version == "0.1.0" == __version__
    assert descriptor.validation_status is DatasetValidationStatus.VALID
    assert descriptor.partition_ids == (FIXED_PARTITION_ID,)
    assert descriptor.missing_intervals == ()
    assert descriptor.duplicate_intervals == ()
    assert descriptor.diagnostic_ids == ()
    assert descriptor.raw_checksums == (inputs.raw_sha256,)
    assert descriptor.normalized_checksums == (container_sha256,)
    assert descriptor.column_schema_version == "0.1.0" == COLUMN_SCHEMA_VERSION
    assert descriptor.known_limitations == (PLAN_LIMITATION_TEXT,)
    assert descriptor.content_hash == dataset_metadata_hash(
        descriptor, bundle.partitions
    )
    assert descriptor.content_hash != PLACEHOLDER_CONTENT_HASH


def test_the_clean_partition_maps_every_section_five_one_field(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    inputs = _inputs(clean_fixture, tmp_path, fixed_ids, fixed_clock)
    container_bytes = inputs.container_path.read_bytes()
    container_sha256 = hashlib.sha256(container_bytes).hexdigest()

    bundle = _bundle(_build(inputs, fixed_ids, fixed_clock))

    (partition,) = bundle.partitions
    assert set(partition.model_dump(mode="json")) == PARTITION_FIELDS
    assert partition.schema_version == "1.0.0"
    assert partition.partition_id == FIXED_PARTITION_ID
    assert partition.dataset_id == FIXED_DATASET_ID == bundle.descriptor.dataset_id
    assert partition.ordinal == 0
    assert partition.relative_path == f"datasets/{FIXED_DATASET_ID}/part-0000.ndjson"
    assert partition.relative_path.endswith(f"/{CONTAINER_FILE_NAME}")
    assert partition.content_hash == container_sha256
    assert partition.row_count == FIXTURE_ROW_COUNT == container_bytes.count(b"\n")
    assert partition.start_utc == bundle.descriptor.start_utc == _at(0)
    assert partition.end_utc == bundle.descriptor.end_utc == _at(60)
    assert partition.raw_checksum == inputs.raw_sha256
    assert partition.normalized_checksum == container_sha256 == partition.content_hash
    assert partition.column_schema_version == "0.1.0"
    assert partition.raw_source_provenance == bundle.descriptor.raw_source_provenance
    assert partition.quality_observations == (PLAN_LIMITATION_TEXT,)


def test_the_source_argument_and_input_name_feed_the_descriptor(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    inputs = _inputs(clean_fixture, tmp_path, fixed_ids, fixed_clock)

    bundle = _bundle(
        _build(
            inputs,
            fixed_ids,
            fixed_clock,
            source="archive-mirror 2024",
            input_name="renamed-input.csv",
        )
    )

    assert bundle.descriptor.source == "archive-mirror 2024"
    (provenance,) = bundle.descriptor.raw_source_provenance
    assert provenance.source_record == "renamed-input.csv"
    assert provenance.source_hash == inputs.raw_sha256
    assert bundle.partitions[0].raw_source_provenance == (provenance,)


# --- section 5.1: the gaps-duplicates fixture (reading R4) ------------------


def test_the_gaps_duplicates_fixture_is_valid_with_warnings_with_its_intervals(
    tmp_path: Path,
    candles_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    fixture = candles_root / GAPS_DUPLICATES_FIXTURE
    inputs = _inputs(fixture, tmp_path, fixed_ids, fixed_clock)
    container_sha256 = hashlib.sha256(inputs.container_path.read_bytes()).hexdigest()

    bundle = _bundle(_build(inputs, fixed_ids, fixed_clock))

    descriptor = bundle.descriptor
    (partition,) = bundle.partitions
    assert descriptor.validation_status is DatasetValidationStatus.VALID_WITH_WARNINGS
    assert descriptor.missing_intervals == (
        TimeInterval(start_utc=_at(20), end_utc=_at(23)),
    )
    assert descriptor.duplicate_intervals == (
        DuplicateInterval(start_utc=_at(30), end_utc=_at(31), duplicate_count=2),
        DuplicateInterval(start_utc=_at(45), end_utc=_at(46), duplicate_count=2),
    )
    assert descriptor.diagnostic_ids == ()
    assert descriptor.known_limitations == (PLAN_LIMITATION_TEXT,)
    assert descriptor.start_utc == _at(0)
    assert descriptor.end_utc == _at(61)
    assert descriptor.raw_checksums == (inputs.raw_sha256,)
    assert descriptor.normalized_checksums == (container_sha256,)
    assert partition.quality_observations == (
        DIFFERING_DUPLICATE_OBSERVATION,
        PLAN_LIMITATION_TEXT,
    )
    assert partition.quality_observations == tuple(
        sorted(partition.quality_observations)
    )
    assert partition.row_count == FIXTURE_ROW_COUNT
    assert partition.content_hash == container_sha256
    (provenance,) = descriptor.raw_source_provenance
    assert provenance.source_record == GAPS_DUPLICATES_FIXTURE
    assert provenance.source_hash == inputs.raw_sha256
    assert descriptor.content_hash == dataset_metadata_hash(
        descriptor, bundle.partitions
    )


def test_the_two_fixtures_yield_different_content_hashes(
    tmp_path: Path,
    clean_fixture: Path,
    candles_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    first = tmp_path / "clean"
    second = tmp_path / "gaps"
    first.mkdir()
    second.mkdir()

    clean_inputs = _inputs(clean_fixture, first, fixed_ids, fixed_clock)
    gaps_inputs = _inputs(
        candles_root / GAPS_DUPLICATES_FIXTURE, second, fixed_ids, fixed_clock
    )

    clean = _bundle(_build(clean_inputs, fixed_ids, fixed_clock))
    gaps = _bundle(_build(gaps_inputs, fixed_ids, fixed_clock))

    assert clean.descriptor.content_hash != gaps.descriptor.content_hash
    assert clean.partitions[0].content_hash != gaps.partitions[0].content_hash
    assert clean.descriptor.dataset_id == gaps.descriptor.dataset_id


# --- section 5.4: the content-hash construction ------------------------------


def test_the_content_hash_is_the_core_hash_of_the_placeholder_descriptor(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """The placeholder is excluded by the profile, so both descriptors hash alike."""
    inputs = _inputs(clean_fixture, tmp_path, fixed_ids, fixed_clock)

    bundle = _bundle(_build(inputs, fixed_ids, fixed_clock))

    descriptor = bundle.descriptor
    placeholder = DatasetDescriptor.model_validate(
        {**descriptor.model_dump(), "content_hash": PLACEHOLDER_CONTENT_HASH}
    )
    expected = dataset_metadata_hash(placeholder, bundle.partitions)
    assert PLACEHOLDER_CONTENT_HASH == "0" * 64
    assert descriptor.content_hash == expected
    assert dataset_metadata_hash(descriptor, bundle.partitions) == expected
    validate_dataset_identity(descriptor, bundle.partitions)
    with pytest.raises(ValueError, match="content_hash"):
        validate_dataset_identity(placeholder, bundle.partitions)


def test_the_content_hash_excludes_identifiers_and_instants(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """Different providers change the ids and instants but never the hash."""
    inputs = _inputs(clean_fixture, tmp_path, fixed_ids, fixed_clock)

    fixed = _bundle(_build(inputs, fixed_ids, fixed_clock))
    other = _bundle(_build(inputs, _CountingIds(), _CountingClock()))

    assert fixed.descriptor.dataset_id != other.descriptor.dataset_id
    assert fixed.descriptor.created_at_utc != other.descriptor.created_at_utc
    assert fixed.partitions[0].partition_id != other.partitions[0].partition_id
    assert fixed.partitions[0].relative_path != other.partitions[0].relative_path
    assert fixed.descriptor.content_hash == other.descriptor.content_hash
    validate_dataset_identity(other.descriptor, other.partitions)


def test_a_changed_material_field_changes_the_content_hash(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    inputs = _inputs(clean_fixture, tmp_path, fixed_ids, fixed_clock)

    default = _bundle(_build(inputs, fixed_ids, fixed_clock))
    renamed = _bundle(_build(inputs, fixed_ids, fixed_clock, source="other-source"))

    assert default.descriptor.content_hash != renamed.descriptor.content_hash
    validate_dataset_identity(renamed.descriptor, renamed.partitions)


def test_the_bundle_is_frozen_and_carries_exactly_the_two_products(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    inputs = _inputs(clean_fixture, tmp_path, fixed_ids, fixed_clock)

    bundle = _bundle(_build(inputs, fixed_ids, fixed_clock))

    assert tuple(DatasetBundle.__dataclass_fields__) == ("descriptor", "partitions")
    with pytest.raises(AttributeError):
        bundle.partitions = ()  # type: ignore[misc]


# --- constants ---------------------------------------------------------------


def test_the_limitation_text_is_the_plan_literal_and_names_the_container() -> None:
    assert P2_B1_LIMITATION == PLAN_LIMITATION_TEXT
    assert CONTAINER_FORMAT in P2_B1_LIMITATION
    assert "(P2-B1)" in P2_B1_LIMITATION
    assert SOURCE_NAME == "ohlcv-csv"
    assert SOURCE_VERSION == "1.0.0"
    assert NORMALIZATION_IMPLEMENTATION == SOURCE_COMPONENT == "crypto-lab-offline-data"
    assert DEFAULT_SOURCE == "local-fixture"
    assert CONTAINER_FILE_NAME == "part-0000.ndjson"
    assert "parquet" not in CONTAINER_FILE_NAME.lower()
    assert BOUNDED_TEXT_MAX_LENGTH == 1024


# --- the boundary: refusals ---------------------------------------------------


@pytest.mark.parametrize("timeframe", ["1w", "1s", "2m", "", "1M"])
def test_an_unsupported_timeframe_is_the_grid_refusal_at_line_zero(
    timeframe: str,
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    inputs = _inputs(clean_fixture, tmp_path, fixed_ids, fixed_clock)
    ids = _CountingIds()
    clock = _CountingClock()

    result = _build(inputs, ids, clock, timeframe=timeframe)

    diagnostic = _single_refusal(
        result,
        RefusalCode.TIMEFRAME_GRID,
        line=WHOLE_INPUT_LINE,
        value_length=len(timeframe),
        diagnostic_id=OTHER_DIAGNOSTIC_ID,
        instant=OTHER_INSTANT,
    )
    if timeframe:
        _assert_value_absent(diagnostic, f'"{timeframe}"')
    assert ids.calls == {"dataset_id": 0, "partition_id": 0, "diagnostic_id": 1}
    assert clock.calls == 1


@pytest.mark.parametrize("input_name", ["", "x" * (BOUNDED_TEXT_MAX_LENGTH + 1)])
def test_an_unbounded_input_name_is_the_metadata_field_refusal(
    input_name: str,
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """The input's name cannot be recorded: ``METADATA_FIELD``, never ``INPUT_PATH``."""
    inputs = _inputs(clean_fixture, tmp_path, fixed_ids, fixed_clock)
    ids = _CountingIds()
    clock = _CountingClock()

    result = _build(inputs, ids, clock, input_name=input_name)

    diagnostic = _metadata_field_refusal(result)
    if input_name:
        _assert_value_absent(diagnostic, input_name)
    assert ids.calls == {"dataset_id": 1, "partition_id": 1, "diagnostic_id": 1}
    assert clock.calls == 2


@pytest.mark.parametrize("length", [1, BOUNDED_TEXT_MAX_LENGTH])
def test_an_input_name_and_a_source_at_each_bound_are_accepted(
    length: int,
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    inputs = _inputs(clean_fixture, tmp_path, fixed_ids, fixed_clock)
    name = "n" * length
    source = "s" * length

    bundle = _bundle(
        _build(inputs, fixed_ids, fixed_clock, input_name=name, source=source)
    )

    assert bundle.descriptor.raw_source_provenance[0].source_record == name
    assert bundle.descriptor.source == source


@pytest.mark.parametrize("source", ["", "s" * (BOUNDED_TEXT_MAX_LENGTH + 1)])
def test_an_unbounded_source_is_the_metadata_field_refusal(
    source: str,
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    inputs = _inputs(clean_fixture, tmp_path, fixed_ids, fixed_clock)
    ids = _CountingIds()
    clock = _CountingClock()

    result = _build(inputs, ids, clock, source=source)

    diagnostic = _metadata_field_refusal(result)
    if source:
        _assert_value_absent(diagnostic, source)
    assert ids.calls == {"dataset_id": 1, "partition_id": 1, "diagnostic_id": 1}
    assert clock.calls == 2


CORRUPT_DIGESTS = [
    "not-a-digest",
    "NOT-HEX" * 8,
    "",
    "a" * 63,
    "a" * 65,
    "A" * 64,
    "g" * 64,
]


@pytest.mark.parametrize("digest", CORRUPT_DIGESTS)
def test_a_corrupt_raw_checksum_digest_is_the_metadata_field_refusal(
    digest: str,
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """A direct caller's corrupt ``RawChecksum`` is a core refusal converted here."""
    inputs = _inputs(clean_fixture, tmp_path, fixed_ids, fixed_clock)
    ids = _CountingIds()
    clock = _CountingClock()

    result = _build(inputs, ids, clock, raw=replace(inputs.raw, sha256=digest))

    diagnostic = _metadata_field_refusal(result)
    if digest:
        _assert_value_absent(diagnostic, digest)
    assert ids.calls == {"dataset_id": 1, "partition_id": 1, "diagnostic_id": 1}
    assert clock.calls == 2


@pytest.mark.parametrize("field", ["content_hash", "normalized_checksum"])
@pytest.mark.parametrize("digest", CORRUPT_DIGESTS)
def test_a_corrupt_container_digest_is_the_metadata_field_refusal(
    field: str,
    digest: str,
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """Either digest of a corrupt ``NormalizedContainer`` is converted here."""
    inputs = _inputs(clean_fixture, tmp_path, fixed_ids, fixed_clock)
    ids = _CountingIds()
    clock = _CountingClock()
    corrupt = (
        replace(inputs.container, content_hash=digest)
        if field == "content_hash"
        else replace(inputs.container, normalized_checksum=digest)
    )
    assert getattr(corrupt, field) == digest

    result = _build(inputs, ids, clock, container=corrupt)

    diagnostic = _metadata_field_refusal(result)
    if digest:
        _assert_value_absent(diagnostic, digest)
    assert ids.calls == {"dataset_id": 1, "partition_id": 1, "diagnostic_id": 1}
    assert clock.calls == 2


def _refused_series_fields(series: ValidatedSeries) -> dict[str, dict[str, Any]]:
    """Recorded ``ValidatedSeries`` field values the core models refuse.

    A naive ``start_utc`` or ``end_utc`` (the core's ``UtcDateTime`` requires an
    aware UTC instant), an empty and an over-long observation (``BoundedText``),
    an inverted bound (start must precede end), and an unsorted or duplicated
    missing-interval tuple (unique sorted tuples). Each case is one ``replace``
    of the series the fixture validated, so only the named field differs.
    """
    gap = TimeInterval(start_utc=_at(20), end_utc=_at(23))
    return {
        "naive-start": {"start_utc": series.start_utc.replace(tzinfo=None)},
        "naive-end": {"end_utc": series.end_utc.replace(tzinfo=None)},
        "empty-observation": {"observations": ("",)},
        "long-observation": {"observations": ("o" * (BOUNDED_TEXT_MAX_LENGTH + 1),)},
        "inverted-bounds": {"start_utc": series.end_utc, "end_utc": series.start_utc},
        "unsorted-missing": {
            "missing_intervals": (
                TimeInterval(start_utc=_at(40), end_utc=_at(41)),
                gap,
            )
        },
        "duplicate-missing": {"missing_intervals": (gap, gap)},
    }


REFUSED_SERIES_CASES = [
    "naive-start",
    "naive-end",
    "empty-observation",
    "long-observation",
    "inverted-bounds",
    "unsorted-missing",
    "duplicate-missing",
]


@pytest.mark.parametrize("case", REFUSED_SERIES_CASES)
def test_a_refused_recorded_series_field_is_the_metadata_field_refusal(
    case: str,
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """A consumed ``ValidatedSeries`` field the core refuses is converted here.

    The naive instants are derived from the series' own bounds, not from the
    clock, so their text is absent from the diagnostic for a reason and not
    because the diagnostic's own ``timestamp_utc`` happens to contain it.
    """
    inputs = _inputs(clean_fixture, tmp_path, fixed_ids, fixed_clock)
    changes = _refused_series_fields(inputs.series)[case]
    assert all(getattr(inputs.series, name) != value for name, value in changes.items())
    corrupt = replace(inputs.series, **changes)
    ids = _CountingIds()
    clock = _CountingClock()

    result = build_dataset_metadata(
        corrupt,
        inputs.container,
        inputs.raw,
        instrument=_instrument(),
        timeframe="1m",
        source=DEFAULT_SOURCE,
        input_name=inputs.input_name,
        ids=ids,
        clock=clock,
    )

    diagnostic = _metadata_field_refusal(result)
    for value in changes.values():
        if isinstance(value, datetime):
            _assert_value_absent(diagnostic, value.isoformat())
            assert str(value.year) not in diagnostic.message
        elif isinstance(value, tuple):
            for item in value:
                text = item if isinstance(item, str) else item.start_utc.isoformat()
                if text:
                    _assert_value_absent(diagnostic, text)
    assert ids.calls == {"dataset_id": 1, "partition_id": 1, "diagnostic_id": 1}
    assert clock.calls == 2


def test_a_negative_recorded_container_row_count_is_the_metadata_field_refusal(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """The partition's ``row_count`` is ``ge=0``; a negative count is converted here."""
    inputs = _inputs(clean_fixture, tmp_path, fixed_ids, fixed_clock)
    ids = _CountingIds()
    clock = _CountingClock()

    result = _build(
        inputs, ids, clock, container=replace(inputs.container, row_count=-1)
    )

    _metadata_field_refusal(result)
    assert ids.calls == {"dataset_id": 1, "partition_id": 1, "diagnostic_id": 1}
    assert clock.calls == 2


def test_the_metadata_field_refusal_is_distinct_from_the_input_path_refusal(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """The reader's input-path case keeps its code; the recorded-field case has its own.

    Section 5.4: ``METADATA_FIELD`` is never emitted for ``INPUT_PATH``'s cases
    and never replaced by ``INPUT_PATH``.
    """
    inputs = _inputs(clean_fixture, tmp_path, fixed_ids, fixed_clock)
    absent = tmp_path / "absent-input.csv"

    read = read_ohlcv_csv(absent, ids=fixed_ids, clock=fixed_clock)
    digest = raw_checksum(
        absent, max_bytes=DEFAULT_MAX_BYTES, ids=fixed_ids, clock=fixed_clock
    )
    built = _build(inputs, fixed_ids, fixed_clock, source="")

    assert RefusalCode.METADATA_FIELD.value == "OFFLINE_DATA.METADATA_FIELD"
    assert RefusalCode.METADATA_FIELD.name == "METADATA_FIELD"
    assert len({RefusalCode.METADATA_FIELD, RefusalCode.INPUT_PATH}) == 2
    assert len({code.value for code in RefusalCode}) == len(RefusalCode)
    assert RefusalCode("OFFLINE_DATA.METADATA_FIELD") is RefusalCode.METADATA_FIELD
    for result in (read, digest):
        assert isinstance(result, Failure)
        assert result.diagnostics[0].error_code == RefusalCode.INPUT_PATH.value
    assert isinstance(built, Failure)
    assert built.diagnostics[0].error_code == RefusalCode.METADATA_FIELD.value
    assert {d.error_code for d in built.diagnostics} == {"OFFLINE_DATA.METADATA_FIELD"}


def test_the_metadata_field_refusal_message_names_the_rule_only(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    inputs = _inputs(clean_fixture, tmp_path, fixed_ids, fixed_clock)
    marker = "unrecorded-marker-7f3a"

    result = _build(inputs, fixed_ids, fixed_clock, source=f"{marker}" + "s" * 1024)

    diagnostic = _metadata_field_refusal(
        result, diagnostic_id=FIXED_DIAGNOSTIC_ID, instant=FIXED_INSTANT
    )
    assert diagnostic.message == "line 0 refused by rule OFFLINE_DATA.METADATA_FIELD"
    _assert_value_absent(diagnostic, marker)
    assert diagnostic.details == {
        "line": 0,
        "rule": "OFFLINE_DATA.METADATA_FIELD",
        "value_length": 0,
    }


def test_no_validation_error_escapes_the_metadata_boundary(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    inputs = _inputs(clean_fixture, tmp_path, fixed_ids, fixed_clock)
    naive_series = replace(
        inputs.series, start_utc=inputs.series.start_utc.replace(tzinfo=None)
    )

    results = [
        _build(inputs, fixed_ids, fixed_clock, source=""),
        _build(inputs, fixed_ids, fixed_clock, input_name=""),
        _build(inputs, fixed_ids, fixed_clock, timeframe="1w"),
        _build(inputs, fixed_ids, fixed_clock, raw=replace(inputs.raw, sha256="")),
        build_dataset_metadata(
            naive_series,
            inputs.container,
            inputs.raw,
            instrument=_instrument(),
            timeframe="1m",
            source=DEFAULT_SOURCE,
            input_name=inputs.input_name,
            ids=fixed_ids,
            clock=fixed_clock,
        ),
    ]

    failures = [result for result in results if isinstance(result, Failure)]

    assert len(failures) == len(results) == 5
    assert [len(failure.diagnostics) for failure in failures] == [1, 1, 1, 1, 1]
    assert [failure.diagnostics[0].error_code for failure in failures] == [
        RefusalCode.METADATA_FIELD.value,
        RefusalCode.METADATA_FIELD.value,
        RefusalCode.TIMEFRAME_GRID.value,
        RefusalCode.METADATA_FIELD.value,
        RefusalCode.METADATA_FIELD.value,
    ]


# --- the converting handler: draw order and position (section 5.4, R7) ------


def _function_definition(module: ast.Module, name: str) -> ast.FunctionDef:
    definitions = [
        node
        for node in module.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    assert len(definitions) == 1
    return definitions[0]


def _call_names(node: ast.AST) -> list[str]:
    """The names every call under ``node`` targets, in source order."""
    names: list[str] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            func = child.func
            if isinstance(func, ast.Name):
                names.append(func.id)
            elif isinstance(func, ast.Attribute):
                names.append(func.attr)
            else:
                names.append(ast.dump(func))
    return names


def test_the_converting_handler_wraps_only_the_model_construction(
    sub_project_root: Path,
) -> None:
    """Structural pin of section 5.4: one ``try`` around ``_bundle`` alone.

    The behavioural tests cannot tell a draw moved inside the ``try`` from one
    outside it, nor a ``refusal`` returned from the ``except`` from one drawn
    after it (``ProviderContractError`` is no ``ValueError`` either way), so
    the source is pinned: ``build_dataset_metadata`` holds exactly one ``try``;
    the only call anywhere inside that statement, handler included, is
    ``_bundle``; the handler converts ``ValueError`` alone and binds no name,
    so the core error is never inspected; the two identifier draws and the
    instant draw precede the ``try`` (after the timeframe refusal); and the
    one ``refusal`` call of the ``METADATA_FIELD`` path follows it.
    """
    source = sub_project_root / "src" / "crypto_lab_offline_data" / "metadata.py"
    module = ast.parse(source.read_text(encoding="utf-8"))
    function = _function_definition(module, "build_dataset_metadata")
    tries = [node for node in ast.walk(function) if isinstance(node, ast.Try)]

    assert len(tries) == 1
    (handler_try,) = tries
    assert _call_names(handler_try) == ["_bundle"]
    assert len(handler_try.handlers) == 1
    (handler,) = handler_try.handlers
    assert isinstance(handler.type, ast.Name)
    assert handler.type.id == "ValueError"
    assert handler.name is None
    assert handler_try.orelse == []
    assert handler_try.finalbody == []
    try_index = function.body.index(handler_try)
    before = [n for s in function.body[:try_index] for n in _call_names(s)]
    after = [n for s in function.body[try_index + 1 :] for n in _call_names(s)]
    draws = [n for n in before if n in {"drawn_identifier", "drawn_instant"}]
    assert draws == ["drawn_identifier", "drawn_identifier", "drawn_instant"]
    assert before.count("refusal") == 1
    assert before.index("refusal") < before.index("drawn_identifier")
    assert after.count("refusal") == 1
    assert not {"drawn_identifier", "drawn_instant"} & set(after)


def test_the_identifiers_and_instant_are_drawn_before_the_handler_and_the_diag_after(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """Section 5.4: ``ds_``, ``part_`` and the instant first; ``diag_`` after.

    On the refusal path the log is the exact sequence ``dataset_id``,
    ``partition_id``, ``now_utc`` (the recorded instant), ``diagnostic_id``,
    ``now_utc`` (the diagnostic's instant); on the success path it stops after
    the first three.
    """
    inputs = _inputs(clean_fixture, tmp_path, fixed_ids, fixed_clock)
    refused_log: list[str] = []
    accepted_log: list[str] = []

    refused = _build(
        inputs, _LoggingIds(refused_log), _LoggingClock(refused_log), source=""
    )
    accepted = _build(inputs, _LoggingIds(accepted_log), _LoggingClock(accepted_log))

    _metadata_field_refusal(refused)
    _bundle(accepted)
    assert refused_log == [
        "dataset_id",
        "partition_id",
        "now_utc",
        "diagnostic_id",
        "now_utc",
    ]
    assert accepted_log == ["dataset_id", "partition_id", "now_utc"]
    assert refused_log[:3] == accepted_log


@pytest.mark.parametrize(
    ("method", "value"),
    [
        ("dataset_id", f"ds_{MALFORMED_IDENTIFIER}"),
        ("dataset_id", None),
        ("partition_id", f"part_{MALFORMED_IDENTIFIER}"),
        ("partition_id", OTHER_DATASET_ID),
        ("diagnostic_id", f"diag_{MALFORMED_IDENTIFIER}"),
        ("diagnostic_id", None),
    ],
)
def test_a_provider_fault_crossing_a_refused_field_is_raised_not_converted(
    method: str,
    value: Any,
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """Provider validation sits outside the converting handler (R7).

    With a ``source`` the core refuses and a provider the core refuses at the
    same time, the outcome is the provider fault, never a ``METADATA_FIELD``
    refusal and never a core error: the ``ds_`` and ``part_`` draws are
    validated before the handler and the ``diag_`` draw inside ``refusal``,
    after it.
    """
    inputs = _inputs(clean_fixture, tmp_path, fixed_ids, fixed_clock)

    with pytest.raises(RuntimeError) as info:
        _build(inputs, _ValueIds(method, value), fixed_clock, source="")

    error = info.value
    assert type(error) is ProviderContractError
    assert not isinstance(error, ValidationError)
    assert error.method == method
    assert error.__cause__ is None
    if isinstance(value, str):
        assert value not in str(error)


@pytest.mark.parametrize("value", [NAIVE_INSTANT, "2026-01-02T03:04:05Z", None])
def test_a_clock_fault_crossing_a_refused_field_is_raised_not_converted(
    value: Any,
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    inputs = _inputs(clean_fixture, tmp_path, fixed_ids, fixed_clock)

    with pytest.raises(RuntimeError) as info:
        _build(inputs, fixed_ids, _ValueClock(value), input_name="")

    error = info.value
    assert type(error) is ProviderContractError
    assert error.method == "now_utc"
    assert error.__cause__ is None
    assert str(value) not in str(error)


# --- the boundary: the provider contract (R7) --------------------------------


def test_build_dataset_metadata_draws_each_provider_value_once_on_success(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    inputs = _inputs(clean_fixture, tmp_path, fixed_ids, fixed_clock)
    ids = _CountingIds()
    clock = _CountingClock()

    bundle = _bundle(_build(inputs, ids, clock))

    assert ids.calls == {"dataset_id": 1, "partition_id": 1, "diagnostic_id": 0}
    assert clock.calls == 1
    assert bundle.descriptor.dataset_id == OTHER_DATASET_ID
    assert bundle.partitions[0].partition_id == OTHER_PARTITION_ID
    assert bundle.descriptor.imported_at_utc == OTHER_INSTANT
    assert bundle.descriptor.created_at_utc == OTHER_INSTANT


@pytest.mark.parametrize(
    ("method", "value"),
    [
        ("dataset_id", f"ds_{MALFORMED_IDENTIFIER}"),
        ("dataset_id", OTHER_PARTITION_ID),
        ("dataset_id", None),
        ("partition_id", f"part_{MALFORMED_IDENTIFIER}"),
        ("partition_id", OTHER_DATASET_ID),
        ("partition_id", b"part_8b2d4f6a-1c3e-4a5b-b7d9-0e2f4a6c8b1d"),
    ],
)
def test_build_dataset_metadata_raises_the_contract_error_for_a_refused_id(
    method: str,
    value: Any,
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    inputs = _inputs(clean_fixture, tmp_path, fixed_ids, fixed_clock)

    with pytest.raises(RuntimeError) as info:
        _build(inputs, _ValueIds(method, value), fixed_clock)

    error = info.value
    assert type(error) is ProviderContractError
    assert not isinstance(error, ValidationError)
    assert error.method == method
    assert method in str(error)
    assert error.__cause__ is None
    if isinstance(value, str):
        assert value not in str(error)
    assert repr(value) not in str(error)


@pytest.mark.parametrize("value", [NAIVE_INSTANT, "2026-01-02T03:04:05Z", None])
def test_build_dataset_metadata_raises_the_contract_error_for_a_refused_instant(
    value: Any,
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    inputs = _inputs(clean_fixture, tmp_path, fixed_ids, fixed_clock)

    with pytest.raises(RuntimeError) as info:
        _build(inputs, fixed_ids, _ValueClock(value))

    error = info.value
    assert type(error) is ProviderContractError
    assert error.method == "now_utc"
    assert error.__cause__ is None
    assert str(value) not in str(error)


def test_the_refusal_path_raises_the_contract_error_for_a_malformed_diagnostic_id(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """The diagnostic id is drawn only for a refusal, where it is validated too."""
    inputs = _inputs(clean_fixture, tmp_path, fixed_ids, fixed_clock)
    faulty = _ValueIds("diagnostic_id", f"diag_{MALFORMED_IDENTIFIER}")

    accepted = _build(inputs, faulty, fixed_clock)
    with pytest.raises(RuntimeError) as info:
        _build(inputs, faulty, fixed_clock, timeframe="1w")

    _bundle(accepted)
    assert type(info.value) is ProviderContractError
    assert info.value.method == "diagnostic_id"
    assert MALFORMED_IDENTIFIER not in str(info.value)


def test_the_draw_helpers_validate_against_the_core_grammar(
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    assert drawn_identifier(fixed_ids, "dataset_id") == FIXED_DATASET_ID
    assert drawn_identifier(fixed_ids, "partition_id") == FIXED_PARTITION_ID
    assert drawn_identifier(fixed_ids, "diagnostic_id") == FIXED_DIAGNOSTIC_ID
    assert drawn_instant(fixed_clock) == FIXED_INSTANT
    with pytest.raises(ProviderContractError) as info:
        drawn_identifier(_ValueIds("diagnostic_id", FIXED_DATASET_ID), "diagnostic_id")
    assert info.value.method == "diagnostic_id"
    with pytest.raises(ProviderContractError) as clock_info:
        drawn_instant(_ValueClock(NAIVE_INSTANT))
    assert clock_info.value.method == "now_utc"


# --- the second slice (section 2.5): input formats and source identities -------------


def test_the_input_format_is_a_closed_enum_with_the_literal_identity_table() -> None:
    assert issubclass(InputFormat, StrEnum)
    assert [item.value for item in InputFormat] == [
        "ohlcv-csv/1",
        "binance-spot-kline-csv/1",
    ]
    assert InputFormat("ohlcv-csv/1") is InputFormat.OHLCV_CSV_1
    assert (
        InputFormat("binance-spot-kline-csv/1") is InputFormat.BINANCE_SPOT_KLINE_CSV_1
    )
    assert SOURCE_IDENTITIES == {
        InputFormat.OHLCV_CSV_1: ("ohlcv-csv", "1.0.0"),
        InputFormat.BINANCE_SPOT_KLINE_CSV_1: ("binance-spot-kline-csv", "1.0.0"),
    }
    assert SOURCE_IDENTITIES[InputFormat.OHLCV_CSV_1] == (SOURCE_NAME, SOURCE_VERSION)
    assert set(SOURCE_IDENTITIES) == set(InputFormat)
    with pytest.raises(ValueError, match="parquet"):
        InputFormat("parquet/1")


def test_the_source_format_parameter_is_keyword_only_with_the_default() -> None:
    parameter = inspect.signature(build_dataset_metadata).parameters["source_format"]

    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is InputFormat.OHLCV_CSV_1


def test_the_default_source_format_keeps_the_slice_one_bundle_byte_identical(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    inputs = _inputs(clean_fixture, tmp_path, fixed_ids, fixed_clock)

    default = _bundle(_build(inputs, fixed_ids, fixed_clock))
    explicit = _bundle(
        _build_for(inputs, fixed_ids, fixed_clock, InputFormat.OHLCV_CSV_1)
    )

    default_bytes = canonical_json_bytes(default.descriptor)
    assert default_bytes == canonical_json_bytes(explicit.descriptor)
    assert canonical_json_bytes(list(default.partitions)) == canonical_json_bytes(
        list(explicit.partitions)
    )
    assert default.descriptor.raw_source_provenance[0].source_name == "ohlcv-csv"
    assert default.descriptor.known_limitations == (PLAN_LIMITATION_TEXT,)
    assert default.partitions[0].quality_observations == (PLAN_LIMITATION_TEXT,)
    assert b"P2-B3" not in default_bytes
    assert b"P2-B3" not in canonical_json_bytes(list(default.partitions))


def test_the_binance_source_format_threads_its_identity_and_the_second_limitation(
    tmp_path: Path,
    sub_project_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    fixture = sub_project_root / "tests" / "fixtures" / "binance" / BINANCE_US_FIXTURE
    inputs = _binance_inputs(fixture, tmp_path, fixed_ids, fixed_clock)
    container_sha256 = hashlib.sha256(inputs.container_path.read_bytes()).hexdigest()

    bundle = _bundle(
        _build_for(inputs, fixed_ids, fixed_clock, InputFormat.BINANCE_SPOT_KLINE_CSV_1)
    )

    descriptor = bundle.descriptor
    (partition,) = bundle.partitions
    assert descriptor.raw_source_provenance == (
        RawSourceProvenance(
            source_name="binance-spot-kline-csv",
            source_version="1.0.0",
            source_record=BINANCE_US_FIXTURE,
            source_hash=inputs.raw_sha256,
        ),
    )
    assert partition.raw_source_provenance == descriptor.raw_source_provenance
    assert descriptor.known_limitations == (
        BINANCE_PLAN_LIMITATION_TEXT,
        PLAN_LIMITATION_TEXT,
    )
    assert descriptor.known_limitations == tuple(sorted(descriptor.known_limitations))
    assert partition.quality_observations == (
        BINANCE_PLAN_LIMITATION_TEXT,
        PLAN_LIMITATION_TEXT,
    )
    assert descriptor.validation_status is DatasetValidationStatus.VALID
    assert descriptor.start_utc == BINANCE_START
    assert descriptor.end_utc == BINANCE_START + timedelta(hours=1)
    assert descriptor.raw_checksums == (inputs.raw_sha256,)
    assert descriptor.normalized_checksums == (container_sha256,)
    assert partition.row_count == FIXTURE_ROW_COUNT
    assert descriptor.timeframe == "1m"
    assert descriptor.source == DEFAULT_SOURCE
    assert descriptor.content_hash == dataset_metadata_hash(
        descriptor, bundle.partitions
    )
    validate_dataset_identity(descriptor, bundle.partitions)


def test_the_binance_observations_sort_with_the_differing_duplicate_text(
    tmp_path: Path,
    candles_root: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """Both limitation tuples are ``tuple(sorted(...))``: the P2-B3 text sorts first."""
    inputs = _inputs(
        candles_root / GAPS_DUPLICATES_FIXTURE, tmp_path, fixed_ids, fixed_clock
    )

    bundle = _bundle(
        _build_for(inputs, fixed_ids, fixed_clock, InputFormat.BINANCE_SPOT_KLINE_CSV_1)
    )

    (partition,) = bundle.partitions
    assert partition.quality_observations == (
        BINANCE_PLAN_LIMITATION_TEXT,
        DIFFERING_DUPLICATE_OBSERVATION,
        PLAN_LIMITATION_TEXT,
    )
    assert partition.quality_observations == tuple(
        sorted(partition.quality_observations)
    )
    assert bundle.descriptor.known_limitations == (
        BINANCE_PLAN_LIMITATION_TEXT,
        PLAN_LIMITATION_TEXT,
    )
    assert (
        bundle.descriptor.validation_status
        is DatasetValidationStatus.VALID_WITH_WARNINGS
    )


def test_the_second_limitation_text_is_the_plan_literal_within_the_core_bound() -> None:
    assert P2_B3_LIMITATION == BINANCE_PLAN_LIMITATION_TEXT
    assert P2_B3_LIMITATION.startswith("P2-B3: binance-spot-kline-csv/1 fields 7 to 12")
    assert "not retained" in P2_B3_LIMITATION
    assert "synthetic fixtures only" in P2_B3_LIMITATION
    assert "no real Binance archive ingested" in P2_B3_LIMITATION
    assert "P2-B1" not in P2_B3_LIMITATION
    assert 1 <= len(P2_B3_LIMITATION) <= BOUNDED_TEXT_MAX_LENGTH
    assert P2_B3_LIMITATION < P2_B1_LIMITATION
    assert sorted((P2_B1_LIMITATION, P2_B3_LIMITATION)) == [
        P2_B3_LIMITATION,
        P2_B1_LIMITATION,
    ]


def test_the_source_format_is_material_to_the_content_hash(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    inputs = _inputs(clean_fixture, tmp_path, fixed_ids, fixed_clock)

    ohlcv = _bundle(_build_for(inputs, fixed_ids, fixed_clock, InputFormat.OHLCV_CSV_1))
    binance = _bundle(
        _build_for(inputs, fixed_ids, fixed_clock, InputFormat.BINANCE_SPOT_KLINE_CSV_1)
    )

    assert ohlcv.descriptor.content_hash != binance.descriptor.content_hash
    assert ohlcv.descriptor.dataset_id == binance.descriptor.dataset_id
    assert ohlcv.partitions[0].content_hash == binance.partitions[0].content_hash
    validate_dataset_identity(binance.descriptor, binance.partitions)
