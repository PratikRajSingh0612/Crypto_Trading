"""Immutable dataset metadata boundary; Project 1 performs no ingestion."""

from crypto_lab.datasets.hashing import dataset_metadata_hash, validate_dataset_identity
from crypto_lab.datasets.models import (
    DatasetDataType,
    DatasetDescriptor,
    DatasetPartition,
    DatasetValidationStatus,
    DuplicateInterval,
    RawSourceProvenance,
    TimeInterval,
)

__all__ = (
    "DatasetDataType",
    "DatasetDescriptor",
    "DatasetPartition",
    "DatasetValidationStatus",
    "DuplicateInterval",
    "RawSourceProvenance",
    "TimeInterval",
    "dataset_metadata_hash",
    "validate_dataset_identity",
)
