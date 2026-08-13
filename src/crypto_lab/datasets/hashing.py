"""Deterministic in-memory dataset metadata identity."""

from __future__ import annotations

from typing import cast

from pydantic import JsonValue

from crypto_lab.datasets.models import DatasetDescriptor, DatasetPartition
from crypto_lab.domain.hashing import HashingProfile, profile_hash
from crypto_lab.domain.identifiers import Sha256


def _ordered_partitions(
    descriptor: DatasetDescriptor,
    partitions: tuple[DatasetPartition, ...],
) -> tuple[DatasetPartition, ...]:
    by_id = {partition.partition_id: partition for partition in partitions}
    if len(by_id) != len(partitions):
        raise ValueError("partition IDs must be unique")
    if tuple(by_id) != descriptor.partition_ids:
        raise ValueError("partition order must match descriptor partition_ids")
    for expected_ordinal, partition in enumerate(partitions):
        if partition.dataset_id != descriptor.dataset_id:
            raise ValueError("partition belongs to another dataset")
        if partition.ordinal != expected_ordinal:
            raise ValueError("partition ordinal does not match descriptor order")
        if (
            partition.start_utc < descriptor.start_utc
            or partition.end_utc > descriptor.end_utc
        ):
            raise ValueError("partition bounds escape descriptor bounds")
        if any(
            provenance not in descriptor.raw_source_provenance
            for provenance in partition.raw_source_provenance
        ):
            raise ValueError("partition provenance is absent from descriptor")
    if tuple(item.raw_checksum for item in partitions) != descriptor.raw_checksums:
        raise ValueError("raw checksums do not match ordered partitions")
    if (
        tuple(item.normalized_checksum for item in partitions)
        != descriptor.normalized_checksums
    ):
        raise ValueError("normalized checksums do not match ordered partitions")
    if any(
        item.column_schema_version != descriptor.column_schema_version
        for item in partitions
    ):
        raise ValueError("partition column schema version does not match descriptor")
    return partitions


def dataset_metadata_hash(
    descriptor: DatasetDescriptor,
    partitions: tuple[DatasetPartition, ...],
) -> Sha256:
    """Hash material metadata only; never open a partition path."""
    ordered = _ordered_partitions(descriptor, partitions)
    descriptor_payload = descriptor.model_dump(
        mode="json",
        exclude={
            "content_hash",
            "created_at_utc",
            "dataset_id",
            "diagnostic_ids",
            "imported_at_utc",
            "partition_ids",
        },
    )
    partition_payloads = [
        partition.model_dump(
            mode="json",
            exclude={
                "dataset_id",
                "partition_id",
                "relative_path",
            },
        )
        for partition in ordered
    ]
    return profile_hash(
        HashingProfile.DATASET_METADATA_V1,
        {
            "descriptor": cast(JsonValue, descriptor_payload),
            "partitions": cast(
                JsonValue,
                partition_payloads,
            ),
        },
    )


def validate_dataset_identity(
    descriptor: DatasetDescriptor,
    partitions: tuple[DatasetPartition, ...],
) -> None:
    if dataset_metadata_hash(descriptor, partitions) != descriptor.content_hash:
        raise ValueError("dataset content_hash does not match material metadata")
