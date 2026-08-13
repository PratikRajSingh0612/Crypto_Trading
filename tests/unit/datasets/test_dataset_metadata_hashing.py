from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Never, Protocol

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
    RawSourceProvenance,
)
from crypto_lab.domain.records import InstrumentRef, MarketType

_DS = "ds_12345678-1234-4234-8234-123456789abc"
_OTHER_DS = "ds_22345678-1234-4234-8234-123456789abc"
_PARTS = (
    "part_12345678-1234-4234-8234-123456789abc",
    "part_22345678-1234-4234-8234-123456789abc",
)
_START = datetime(2026, 1, 1, tzinfo=UTC)
_MIDDLE = datetime(2026, 1, 2, tzinfo=UTC)
_END = datetime(2026, 1, 3, tzinfo=UTC)
_DATASET_GOLDEN = "4d5a2f34bc8a02d40c3a07943f5b7afb00513a1527da2e712eda1f3886091ba2"


class PartitionTransform(Protocol):
    def __call__(
        self,
        partitions: tuple[DatasetPartition, ...],
    ) -> tuple[DatasetPartition, ...]: ...


def _provenance() -> RawSourceProvenance:
    return RawSourceProvenance(
        source_name="fixture.source",
        source_version="1.0.0",
        source_record="fixture",
        source_hash="1" * 64,
    )


def _partition(
    *,
    partition_id: str,
    ordinal: int,
    start: datetime,
    end: datetime,
    raw: str,
    normalized: str,
) -> DatasetPartition:
    return DatasetPartition(
        schema_version="1.0.0",
        partition_id=partition_id,
        dataset_id=_DS,
        ordinal=ordinal,
        relative_path=f"ohlcv/{ordinal}.parquet",
        content_hash=str(ordinal + 3) * 64,
        row_count=10 + ordinal,
        start_utc=start,
        end_utc=end,
        raw_checksum=raw,
        normalized_checksum=normalized,
        column_schema_version="1.0.0",
        raw_source_provenance=(_provenance(),),
        quality_observations=(),
    )


def _rebuild_partition(
    partition: DatasetPartition,
    **updates: object,
) -> DatasetPartition:
    payload = partition.model_dump(mode="python")
    payload.update(updates)
    return DatasetPartition.model_validate(payload)


def _rebuild_descriptor(
    descriptor: DatasetDescriptor,
    **updates: object,
) -> DatasetDescriptor:
    payload = descriptor.model_dump(mode="python")
    payload.update(updates)
    return DatasetDescriptor.model_validate(payload)


def _models() -> tuple[DatasetDescriptor, tuple[DatasetPartition, ...]]:
    partitions = (
        _partition(
            partition_id=_PARTS[0],
            ordinal=0,
            start=_START,
            end=_MIDDLE,
            raw="1" * 64,
            normalized="2" * 64,
        ),
        _partition(
            partition_id=_PARTS[1],
            ordinal=1,
            start=_MIDDLE,
            end=_END,
            raw="2" * 64,
            normalized="1" * 64,
        ),
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
        partition_ids=_PARTS,
        missing_intervals=(),
        duplicate_intervals=(),
        diagnostic_ids=(),
        raw_checksums=("1" * 64, "2" * 64),
        normalized_checksums=("2" * 64, "1" * 64),
        column_schema_version="1.0.0",
        known_limitations=(),
        created_at_utc=_END,
    )
    return descriptor, partitions


def _reverse(
    partitions: tuple[DatasetPartition, ...],
) -> tuple[DatasetPartition, ...]:
    return tuple(reversed(partitions))


def _duplicate_ordinal(
    partitions: tuple[DatasetPartition, ...],
) -> tuple[DatasetPartition, ...]:
    return (partitions[0], _rebuild_partition(partitions[1], ordinal=0))


def _foreign_dataset(
    partitions: tuple[DatasetPartition, ...],
) -> tuple[DatasetPartition, ...]:
    return (
        partitions[0],
        _rebuild_partition(partitions[1], dataset_id=_OTHER_DS),
    )


_MISMATCHES: list[PartitionTransform] = [
    _reverse,
    _duplicate_ordinal,
    _foreign_dataset,
]


def test_hash_is_deterministic_and_identity_validation_is_explicit() -> None:
    descriptor, partitions = _models()
    digest = dataset_metadata_hash(descriptor, partitions)
    assert digest == _DATASET_GOLDEN
    assert dataset_metadata_hash(descriptor, partitions) == digest
    validate_dataset_identity(
        _rebuild_descriptor(descriptor, content_hash=digest),
        partitions,
    )
    with pytest.raises(ValueError, match="does not match"):
        validate_dataset_identity(descriptor, partitions)


def test_operational_fields_are_hash_invariant() -> None:
    descriptor, partitions = _models()
    baseline = dataset_metadata_hash(descriptor, partitions)
    changed_parts = tuple(
        _rebuild_partition(
            item,
            dataset_id=_OTHER_DS,
            partition_id=f"part_{index + 3}2345678-1234-4234-8234-123456789abc",
            relative_path=f"renamed/{index}.parquet",
        )
        for index, item in enumerate(partitions)
    )
    changed_descriptor = _rebuild_descriptor(
        descriptor,
        dataset_id=_OTHER_DS,
        partition_ids=tuple(item.partition_id for item in changed_parts),
        content_hash="f" * 64,
        created_at_utc=datetime(2030, 1, 1, tzinfo=UTC),
        imported_at_utc=_MIDDLE,
    )
    assert dataset_metadata_hash(changed_descriptor, changed_parts) == baseline


def test_material_fields_change_the_hash() -> None:
    descriptor, partitions = _models()
    baseline = dataset_metadata_hash(descriptor, partitions)
    changed = _rebuild_partition(partitions[0], row_count=12)
    assert dataset_metadata_hash(descriptor, (changed, partitions[1])) != baseline
    changed_content = _rebuild_partition(partitions[0], content_hash="f" * 64)
    assert (
        dataset_metadata_hash(descriptor, (changed_content, partitions[1])) != baseline
    )


@pytest.mark.parametrize("transform", list(_MISMATCHES))
def test_order_ordinal_and_dataset_mismatches_are_rejected(
    transform: PartitionTransform,
) -> None:
    descriptor, partitions = _models()
    with pytest.raises(ValueError, match=r"partition|ordinal|dataset"):
        dataset_metadata_hash(descriptor, transform(partitions))


def test_checksum_and_schema_mismatches_are_rejected() -> None:
    descriptor, partitions = _models()
    changed_descriptor = _rebuild_descriptor(
        descriptor,
        raw_checksums=tuple(reversed(descriptor.raw_checksums)),
    )
    with pytest.raises(ValueError, match="raw checksums"):
        dataset_metadata_hash(changed_descriptor, partitions)
    changed_descriptor = _rebuild_descriptor(
        descriptor,
        normalized_checksums=tuple(reversed(descriptor.normalized_checksums)),
    )
    with pytest.raises(ValueError, match="normalized checksums"):
        dataset_metadata_hash(changed_descriptor, partitions)
    changed_partition = _rebuild_partition(
        partitions[1],
        column_schema_version="2.0.0",
    )
    with pytest.raises(ValueError, match="column schema version"):
        dataset_metadata_hash(descriptor, (partitions[0], changed_partition))


def test_partition_bounds_identity_and_provenance_mismatches_are_rejected() -> None:
    descriptor, partitions = _models()
    outside = _rebuild_partition(
        partitions[0],
        start_utc=datetime(2025, 12, 31, tzinfo=UTC),
    )
    with pytest.raises(ValueError, match="bounds escape"):
        dataset_metadata_hash(descriptor, (outside, partitions[1]))
    absent_provenance = RawSourceProvenance(
        source_name="other.source",
        source_version="1.0.0",
        source_record="fixture",
        source_hash="f" * 64,
    )
    changed = _rebuild_partition(
        partitions[0],
        raw_source_provenance=(absent_provenance,),
    )
    with pytest.raises(ValueError, match="provenance is absent"):
        dataset_metadata_hash(descriptor, (changed, partitions[1]))
    wrong_identity = _rebuild_descriptor(
        descriptor,
        partition_ids=tuple(reversed(descriptor.partition_ids)),
    )
    with pytest.raises(ValueError, match="partition order"):
        dataset_metadata_hash(wrong_identity, partitions)
    wrong_ordinal = _rebuild_partition(partitions[1], ordinal=7)
    with pytest.raises(ValueError, match="ordinal"):
        dataset_metadata_hash(descriptor, (partitions[0], wrong_ordinal))


def test_hashing_never_opens_partition_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor, partitions = _models()

    def forbidden(*_args: object, **_kwargs: object) -> Never:
        raise AssertionError("dataset hashing accessed the filesystem")

    monkeypatch.setattr(Path, "open", forbidden)
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "stat", forbidden)
    dataset_metadata_hash(descriptor, partitions)
