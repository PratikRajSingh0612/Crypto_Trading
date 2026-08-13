from __future__ import annotations

from datetime import UTC, datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st

from crypto_lab.datasets.hashing import dataset_metadata_hash
from crypto_lab.datasets.models import (
    DatasetDataType,
    DatasetDescriptor,
    DatasetPartition,
    DatasetValidationStatus,
    RawSourceProvenance,
)
from crypto_lab.domain.records import InstrumentRef, MarketType

_DS = "ds_12345678-1234-4234-8234-123456789abc"
_PART = "part_12345678-1234-4234-8234-123456789abc"
_START = datetime(2026, 1, 1, tzinfo=UTC)
_END = datetime(2026, 1, 2, tzinfo=UTC)


def _provenance() -> RawSourceProvenance:
    return RawSourceProvenance(
        source_name="fixture.source",
        source_version="1.0.0",
        source_record="fixture",
        source_hash="1" * 64,
    )


def _models(
    *,
    row_count: int = 1,
    relative_path: str = "data/part.parquet",
) -> tuple[DatasetDescriptor, DatasetPartition]:
    partition = DatasetPartition(
        schema_version="1.0.0",
        partition_id=_PART,
        dataset_id=_DS,
        ordinal=0,
        relative_path=relative_path,
        content_hash="0" * 64,
        row_count=row_count,
        start_utc=_START,
        end_utc=_END,
        raw_checksum="1" * 64,
        normalized_checksum="2" * 64,
        column_schema_version="1.0.0",
        raw_source_provenance=(_provenance(),),
        quality_observations=(),
    )
    descriptor = DatasetDescriptor(
        schema_version="1.0.0",
        dataset_id=_DS,
        content_hash="0" * 64,
        source="fixture",
        venue="BINANCE",
        instrument=InstrumentRef(
            schema_version="1.0.0",
            canonical_id="BINANCE:BTC/USDT:SPOT",
            venue="BINANCE",
            base_asset="BTC",
            quote_asset="USDT",
            market_type=MarketType.SPOT,
        ),
        data_type=DatasetDataType.OHLCV,
        timeframe="1m",
        start_utc=_START,
        end_utc=_END,
        original_timezone="UTC",
        normalized_to_utc=True,
        raw_source_provenance=(_provenance(),),
        normalization_implementation="fixture.normalizer",
        normalization_version="1.0.0",
        validation_status=DatasetValidationStatus.VALID,
        partition_ids=(_PART,),
        missing_intervals=(),
        duplicate_intervals=(),
        diagnostic_ids=(),
        raw_checksums=("1" * 64,),
        normalized_checksums=("2" * 64,),
        column_schema_version="1.0.0",
        known_limitations=(),
        created_at_utc=_END,
    )
    return descriptor, partition


def _rebuild_partition(
    partition: DatasetPartition,
    **updates: object,
) -> DatasetPartition:
    payload = partition.model_dump(mode="python")
    payload.update(updates)
    return DatasetPartition.model_validate(payload)


@given(
    row_count=st.integers(min_value=1, max_value=1_000_000),
    leaf=st.text(
        alphabet="abcdefghijklmnopqrstuvwxyz0123456789",
        min_size=1,
        max_size=16,
    ),
)
def test_hash_is_deterministic_and_material_field_sensitive(
    row_count: int,
    leaf: str,
) -> None:
    descriptor, partition = _models(
        row_count=row_count,
        relative_path=f"data/{leaf}.parquet",
    )
    baseline = dataset_metadata_hash(descriptor, (partition,))
    assert dataset_metadata_hash(descriptor, (partition,)) == baseline
    changed = _rebuild_partition(partition, row_count=row_count + 1)
    assert dataset_metadata_hash(descriptor, (changed,)) != baseline
    changed_content = _rebuild_partition(partition, content_hash="f" * 64)
    assert dataset_metadata_hash(descriptor, (changed_content,)) != baseline


@given(
    order=st.permutations(
        (
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
        )
    )
)
def test_descriptor_object_key_permutation_is_irrelevant(
    order: list[str],
) -> None:
    descriptor, partition = _models()
    payload = descriptor.model_dump(mode="python")
    rebuilt = DatasetDescriptor.model_validate({key: payload[key] for key in order})
    assert dataset_metadata_hash(rebuilt, (partition,)) == dataset_metadata_hash(
        descriptor,
        (partition,),
    )


@given(bad_ordinal=st.integers(min_value=1, max_value=100))
def test_generated_ordinal_mismatches_are_rejected(
    bad_ordinal: int,
) -> None:
    descriptor, partition = _models()
    changed = _rebuild_partition(partition, ordinal=bad_ordinal)
    with pytest.raises(ValueError, match="ordinal"):
        dataset_metadata_hash(descriptor, (changed,))
