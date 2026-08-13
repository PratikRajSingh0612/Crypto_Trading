from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from crypto_lab.datasets.models import (
    DatasetDataType,
    DatasetDescriptor,
    DatasetPartition,
    DatasetValidationStatus,
    DuplicateInterval,
    RawSourceProvenance,
    TimeInterval,
)
from crypto_lab.domain.records import InstrumentRef, MarketType

_DS = "ds_12345678-1234-4234-8234-123456789abc"
_PART = "part_12345678-1234-4234-8234-123456789abc"
_START = datetime(2026, 1, 1, tzinfo=UTC)
_END = datetime(2026, 1, 2, tzinfo=UTC)
_OMIT = object()


def _provenance() -> RawSourceProvenance:
    return RawSourceProvenance(
        source_name="fixture.source",
        source_version="1.0.0",
        source_record="fixture",
        source_hash="1" * 64,
    )


def _partition(**updates: object) -> DatasetPartition:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "partition_id": _PART,
        "dataset_id": _DS,
        "ordinal": 0,
        "relative_path": "ohlcv/part.parquet",
        "content_hash": "0" * 64,
        "row_count": 10,
        "start_utc": _START,
        "end_utc": _END,
        "raw_checksum": "1" * 64,
        "normalized_checksum": "2" * 64,
        "column_schema_version": "1.0.0",
        "raw_source_provenance": (_provenance(),),
        "quality_observations": (),
    }
    payload.update(updates)
    return DatasetPartition.model_validate(payload)


def _descriptor(**updates: object) -> DatasetDescriptor:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "dataset_id": _DS,
        "content_hash": "0" * 64,
        "source": "fixture",
        "venue": "BINANCE",
        "instrument": InstrumentRef(
            schema_version="1.0.0",
            canonical_id="BINANCE:BTC/USDT:SPOT",
            venue="BINANCE",
            base_asset="BTC",
            quote_asset="USDT",
            market_type=MarketType.SPOT,
        ),
        "data_type": DatasetDataType.OHLCV,
        "timeframe": "1m",
        "start_utc": _START,
        "end_utc": _END,
        "original_timezone": "UTC",
        "normalized_to_utc": True,
        "raw_source_provenance": (_provenance(),),
        "normalization_implementation": "fixture.normalizer",
        "normalization_version": "1.0.0",
        "validation_status": DatasetValidationStatus.VALID,
        "partition_ids": (_PART,),
        "missing_intervals": (),
        "duplicate_intervals": (),
        "diagnostic_ids": (),
        "raw_checksums": ("1" * 64,),
        "normalized_checksums": ("2" * 64,),
        "column_schema_version": "1.0.0",
        "known_limitations": (),
        "created_at_utc": _END,
    }
    payload.update(updates)
    for field, value in tuple(payload.items()):
        if value is _OMIT:
            del payload[field]
    return DatasetDescriptor.model_validate(payload)


def test_dataset_models_round_trip_with_explicit_arrays() -> None:
    partition = _partition()
    descriptor = _descriptor()
    assert (
        DatasetPartition.model_validate_json(partition.model_dump_json()) == partition
    )
    assert (
        DatasetDescriptor.model_validate_json(descriptor.model_dump_json())
        == descriptor
    )
    for model, fields in (
        (partition, ("raw_source_provenance", "quality_observations")),
        (
            descriptor,
            (
                "missing_intervals",
                "duplicate_intervals",
                "diagnostic_ids",
                "known_limitations",
            ),
        ),
    ):
        for field in fields:
            payload = model.model_dump(mode="python")
            del payload[field]
            with pytest.raises(ValidationError, match="Field required"):
                type(model).model_validate(payload)


def test_absent_descriptor_fields_serialize_away_and_null_is_rejected() -> None:
    descriptor = _descriptor()
    dumped = descriptor.model_dump(mode="json")
    assert "imported_at_utc" not in dumped
    with pytest.raises(ValidationError):
        _descriptor(imported_at_utc=None)
    with pytest.raises(ValidationError):
        _descriptor(timeframe=None)


@pytest.mark.parametrize(
    "path",
    [
        "",
        "/root/file",
        "//server/share",
        r"folder\file",
        "C:/file",
        "file:stream",
        "../file",
        "folder/../file",
        "folder//file",
        "folder/./file",
        "folder/\x00file",
        "folder/\x1ffile",
        "folder/AUX.txt",
        "con",
        "folder/file.",
        "folder/file ",
        "folder/inv*lid",
        "folder/<invalid>",
    ],
)
def test_partition_path_rejects_unsafe_raw_syntax(path: str) -> None:
    with pytest.raises(ValidationError):
        _partition(relative_path=path)


def test_partition_quality_and_duplicate_interval_rules() -> None:
    with pytest.raises(ValidationError, match="start must precede end"):
        _partition(start_utc=_END, end_utc=_START)
    with pytest.raises(ValidationError, match="requires a quality observation"):
        _partition(row_count=0)
    with pytest.raises(ValidationError, match="must be sorted"):
        _partition(quality_observations=("z", "a"))
    provenance = _provenance()
    with pytest.raises(ValidationError, match="partition provenance must be unique"):
        _partition(raw_source_provenance=(provenance, provenance))
    earlier = RawSourceProvenance(
        source_name="aaa.source",
        source_version="1.0.0",
        source_record="fixture",
        source_hash="1" * 64,
    )
    with pytest.raises(ValidationError, match="partition provenance must be sorted"):
        _partition(raw_source_provenance=(provenance, earlier))
    with pytest.raises(ValidationError):
        DuplicateInterval(
            start_utc=_START,
            end_utc=_END,
            duplicate_count=1,
        )
    assert (
        DuplicateInterval(
            start_utc=_START,
            end_utc=_END,
            duplicate_count=2,
        ).duplicate_count
        == 2
    )


def test_standalone_and_descriptor_intervals_require_valid_ordering() -> None:
    with pytest.raises(ValidationError, match="start must precede end"):
        TimeInterval(start_utc=_END, end_utc=_START)
    middle = datetime(2026, 1, 1, 12, tzinfo=UTC)
    earlier = TimeInterval(start_utc=_START, end_utc=middle)
    later = TimeInterval(start_utc=middle, end_utc=_END)
    with pytest.raises(ValidationError, match="missing intervals must be sorted"):
        _descriptor(
            missing_intervals=(later, earlier),
            validation_status=DatasetValidationStatus.VALID_WITH_WARNINGS,
        )
    earlier_duplicate = DuplicateInterval(
        start_utc=_START,
        end_utc=middle,
        duplicate_count=2,
    )
    later_duplicate = DuplicateInterval(
        start_utc=middle,
        end_utc=_END,
        duplicate_count=2,
    )
    with pytest.raises(ValidationError, match="duplicate intervals must be sorted"):
        _descriptor(
            duplicate_intervals=(later_duplicate, earlier_duplicate),
            validation_status=DatasetValidationStatus.VALID_WITH_WARNINGS,
        )


def test_descriptor_status_timeframe_and_duplicate_rules() -> None:
    with pytest.raises(ValidationError, match="start must precede end"):
        _descriptor(start_utc=_END, end_utc=_START)
    foreign_instrument = InstrumentRef(
        schema_version="1.0.0",
        canonical_id="KRAKEN:BTC/USD:SPOT",
        venue="KRAKEN",
        base_asset="BTC",
        quote_asset="USD",
        market_type=MarketType.SPOT,
    )
    with pytest.raises(ValidationError, match="venue must match instrument"):
        _descriptor(instrument=foreign_instrument)
    with pytest.raises(ValidationError, match="require a timeframe"):
        _descriptor(timeframe=_OMIT)
    with pytest.raises(ValidationError, match="prohibit a timeframe"):
        _descriptor(data_type=DatasetDataType.TRADES, timeframe="1m")
    assert (
        _descriptor(data_type=DatasetDataType.TRADES, timeframe=_OMIT).data_type
        is DatasetDataType.TRADES
    )
    with pytest.raises(ValidationError, match="requires a quality fact"):
        _descriptor(validation_status=DatasetValidationStatus.VALID_WITH_WARNINGS)
    with pytest.raises(ValidationError, match="require a diagnostic"):
        _descriptor(validation_status=DatasetValidationStatus.INVALID)
    interval = TimeInterval(start_utc=_START, end_utc=_END)
    for update in (
        {"raw_source_provenance": (_provenance(), _provenance())},
        {
            "missing_intervals": (interval, interval),
            "validation_status": DatasetValidationStatus.VALID_WITH_WARNINGS,
        },
        {"partition_ids": (_PART, _PART)},
        {"unexpected": "rejected"},
    ):
        with pytest.raises(ValidationError):
            _descriptor(**update)


def test_ordered_checksum_tuples_may_contain_valid_duplicate_hashes() -> None:
    other_partition = "part_22345678-1234-4234-8234-123456789abc"
    descriptor = _descriptor(
        partition_ids=(_PART, other_partition),
        raw_checksums=("1" * 64, "1" * 64),
        normalized_checksums=("2" * 64, "2" * 64),
    )
    assert descriptor.raw_checksums == ("1" * 64, "1" * 64)
    assert descriptor.normalized_checksums == ("2" * 64, "2" * 64)
