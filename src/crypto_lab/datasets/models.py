"""Immutable dataset metadata contracts; no ingestion or file access."""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, ClassVar, Literal, Self

from pydantic import (
    ConfigDict,
    Field,
    StringConstraints,
    WithJsonSchema,
    field_validator,
    model_validator,
)
from pydantic.experimental.missing_sentinel import MISSING
from pydantic.json_schema import JsonSchemaValue

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.identifiers import (
    AssetCode,
    DatasetId,
    DatasetPartitionId,
    DiagnosticId,
    NormalizedIdentifier,
    Sha256,
    exact_string_schema,
)
from crypto_lab.domain.records import InstrumentRef
from crypto_lab.domain.time import UtcDateTime
from crypto_lab.domain.versioning import SemanticVersion

BoundedText = Annotated[
    str, StringConstraints(strict=True, min_length=1, max_length=1024)
]
Timeframe = Annotated[
    str,
    StringConstraints(
        strict=True, pattern=r"^[1-9][0-9]*(?:s|m|h|d|w)$", max_length=16
    ),
    WithJsonSchema(
        exact_string_schema(
            r"^[1-9][0-9]*(?:s|m|h|d|w)$",
            max_length=16,
        )
    ),
]
_WINDOWS_RESERVED_SEGMENT_PATTERN = (
    r"(?:^|/)(?:[Aa][Uu][Xx]|[Cc][Oo][Nn]|[Nn][Uu][Ll]|[Pp][Rr][Nn]|"
    r"[Cc][Oo][Mm][1-9]|[Ll][Pp][Tt][1-9])"
    r"(?:\.[^/]*)?(?:/|(?![\s\S]))"
)
_REGISTRY_RELATIVE_PATH_SCHEMA: JsonSchemaValue = {
    "type": "string",
    "minLength": 1,
    "maxLength": 1024,
    "allOf": [
        {
            "pattern": (
                r"^[^/<>:\"\\|?*\x00-\x1f]+"
                r"(?:/[^/<>:\"\\|?*\x00-\x1f]+)*(?![\s\S])"
            )
        },
        {"not": {"pattern": r"(?:^|/)\.{1,2}(?:/|(?![\s\S]))"}},
        {"not": {"pattern": r"[ .](?:/|(?![\s\S]))"}},
        {"not": {"pattern": _WINDOWS_RESERVED_SEGMENT_PATTERN}},
    ],
}
RegistryRelativePath = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=1024),
    WithJsonSchema(_REGISTRY_RELATIVE_PATH_SCHEMA),
]


class DatasetDataType(StrEnum):
    OHLCV = "OHLCV"
    TRADES = "TRADES"
    QUOTES = "QUOTES"
    ORDER_BOOK_L2 = "ORDER_BOOK_L2"


class DatasetValidationStatus(StrEnum):
    VALID = "VALID"
    VALID_WITH_WARNINGS = "VALID_WITH_WARNINGS"
    INVALID = "INVALID"


class TimeInterval(CanonicalModel):
    """Half-open interval with inclusive start and exclusive end."""

    start_utc: UtcDateTime
    end_utc: UtcDateTime

    @model_validator(mode="after")
    def validate_bounds(self) -> Self:
        if self.start_utc >= self.end_utc:
            raise ValueError("interval start must precede end")
        return self


class RawSourceProvenance(CanonicalModel):
    source_name: NormalizedIdentifier
    source_version: SemanticVersion
    source_record: BoundedText
    source_hash: Sha256


def _validate_relative_path(value: str) -> str:
    if re.search(r"[<>:\"\\|?*\x00-\x1f]", value) is not None:
        raise ValueError("dataset path contains forbidden syntax")
    segments = value.split("/")
    for segment in segments:
        trimmed = segment.rstrip(" .")
        stem = trimmed.partition(".")[0].upper()
        if (
            segment in {"", ".", ".."}
            or trimmed != segment
            or stem
            in {
                "AUX",
                "CON",
                "NUL",
                "PRN",
                *(f"COM{number}" for number in range(1, 10)),
                *(f"LPT{number}" for number in range(1, 10)),
            }
        ):
            raise ValueError("dataset path contains an unsafe Windows segment")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts:
        raise ValueError("dataset path must be registry-relative")
    if path.as_posix() != value:
        raise ValueError("dataset path must use canonical POSIX syntax")
    return value


def _set_unique_items(schema: JsonSchemaValue, fields: tuple[str, ...]) -> None:
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise TypeError("dataset schema properties must be an object")
    for field in fields:
        field_schema = properties.get(field)
        if not isinstance(field_schema, dict):
            raise TypeError(f"dataset schema field {field!r} must be an object")
        field_schema["uniqueItems"] = True


def _partition_schema_extra(schema: JsonSchemaValue) -> None:
    _set_unique_items(schema, ("raw_source_provenance", "quality_observations"))
    schema["allOf"] = [
        {
            "if": {
                "properties": {"row_count": {"const": 0}},
                "required": ["row_count"],
            },
            "then": {"properties": {"quality_observations": {"minItems": 1}}},
        }
    ]


class DatasetPartition(CanonicalModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_partition_schema_extra
    )

    schema_version: Literal["1.0.0"]
    partition_id: DatasetPartitionId
    dataset_id: DatasetId
    ordinal: int = Field(ge=0)
    relative_path: RegistryRelativePath
    content_hash: Sha256
    row_count: int = Field(ge=0)
    start_utc: UtcDateTime
    end_utc: UtcDateTime
    raw_checksum: Sha256
    normalized_checksum: Sha256
    column_schema_version: SemanticVersion
    raw_source_provenance: tuple[RawSourceProvenance, ...] = Field(
        min_length=1,
        max_length=64,
    )
    quality_observations: tuple[BoundedText, ...] = Field(max_length=64)

    @field_validator("relative_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        return _validate_relative_path(value)

    @field_validator("quality_observations")
    @classmethod
    def validate_observations(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("quality observations must be unique")
        if value != tuple(sorted(value)):
            raise ValueError("quality observations must be sorted")
        return value

    @field_validator("raw_source_provenance")
    @classmethod
    def validate_provenance(
        cls,
        value: tuple[RawSourceProvenance, ...],
    ) -> tuple[RawSourceProvenance, ...]:
        if len(set(value)) != len(value):
            raise ValueError("partition provenance must be unique")
        keys = tuple(
            (
                item.source_name,
                item.source_version,
                item.source_record,
                item.source_hash,
            )
            for item in value
        )
        if keys != tuple(sorted(keys)):
            raise ValueError("partition provenance must be sorted")
        return value

    @model_validator(mode="after")
    def validate_partition(self) -> Self:
        if self.start_utc >= self.end_utc:
            raise ValueError("partition start must precede end")
        if self.row_count == 0 and not self.quality_observations:
            raise ValueError("zero-row partition requires a quality observation")
        return self


class DuplicateInterval(TimeInterval):
    """Half-open interval with at least two observed source rows."""

    duplicate_count: int = Field(ge=2)


def _descriptor_schema_extra(schema: JsonSchemaValue) -> None:
    _set_unique_items(
        schema,
        (
            "raw_source_provenance",
            "partition_ids",
            "missing_intervals",
            "duplicate_intervals",
            "diagnostic_ids",
            "known_limitations",
        ),
    )
    schema["allOf"] = [
        {
            "if": {
                "properties": {"data_type": {"const": "OHLCV"}},
                "required": ["data_type"],
            },
            "then": {"required": ["timeframe"]},
            "else": {"not": {"required": ["timeframe"]}},
        },
        {
            "if": {
                "properties": {"validation_status": {"const": "VALID"}},
                "required": ["validation_status"],
            },
            "then": {
                "properties": {
                    "missing_intervals": {"maxItems": 0},
                    "duplicate_intervals": {"maxItems": 0},
                    "diagnostic_ids": {"maxItems": 0},
                }
            },
        },
        {
            "if": {
                "properties": {"validation_status": {"const": "VALID_WITH_WARNINGS"}},
                "required": ["validation_status"],
            },
            "then": {
                "anyOf": [
                    {"properties": {"missing_intervals": {"minItems": 1}}},
                    {"properties": {"duplicate_intervals": {"minItems": 1}}},
                    {"properties": {"diagnostic_ids": {"minItems": 1}}},
                ]
            },
        },
        {
            "if": {
                "properties": {"validation_status": {"const": "INVALID"}},
                "required": ["validation_status"],
            },
            "then": {"properties": {"diagnostic_ids": {"minItems": 1}}},
        },
    ]


def _is_missing(value: object) -> bool:
    return value is MISSING


class DatasetDescriptor(CanonicalModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_descriptor_schema_extra
    )

    schema_version: Literal["1.0.0"]
    dataset_id: DatasetId
    content_hash: Sha256
    source: BoundedText
    venue: AssetCode
    instrument: InstrumentRef
    data_type: DatasetDataType
    timeframe: Timeframe | MISSING = MISSING  # type: ignore[valid-type]
    start_utc: UtcDateTime
    end_utc: UtcDateTime
    original_timezone: BoundedText
    normalized_to_utc: Literal[True]
    imported_at_utc: UtcDateTime | MISSING = MISSING  # type: ignore[valid-type]
    raw_source_provenance: tuple[RawSourceProvenance, ...] = Field(
        min_length=1, max_length=64
    )
    normalization_implementation: NormalizedIdentifier
    normalization_version: SemanticVersion
    validation_status: DatasetValidationStatus
    partition_ids: tuple[DatasetPartitionId, ...] = Field(min_length=1, max_length=4096)
    missing_intervals: tuple[TimeInterval, ...] = Field(max_length=4096)
    duplicate_intervals: tuple[DuplicateInterval, ...] = Field(max_length=4096)
    diagnostic_ids: tuple[DiagnosticId, ...] = Field(max_length=256)
    raw_checksums: tuple[Sha256, ...] = Field(min_length=1, max_length=4096)
    normalized_checksums: tuple[Sha256, ...] = Field(min_length=1, max_length=4096)
    column_schema_version: SemanticVersion
    known_limitations: tuple[BoundedText, ...] = Field(max_length=64)
    created_at_utc: UtcDateTime

    @field_validator(
        "partition_ids",
        "diagnostic_ids",
        "known_limitations",
    )
    @classmethod
    def validate_unique_tuple(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("dataset collection must contain unique values")
        return value

    @field_validator("missing_intervals")
    @classmethod
    def validate_missing_intervals(
        cls,
        value: tuple[TimeInterval, ...],
    ) -> tuple[TimeInterval, ...]:
        if len(set(value)) != len(value):
            raise ValueError("missing intervals must be unique")
        keys = tuple((item.start_utc, item.end_utc) for item in value)
        if keys != tuple(sorted(keys)):
            raise ValueError("missing intervals must be sorted")
        return value

    @field_validator("duplicate_intervals")
    @classmethod
    def validate_duplicate_intervals(
        cls,
        value: tuple[DuplicateInterval, ...],
    ) -> tuple[DuplicateInterval, ...]:
        if len(set(value)) != len(value):
            raise ValueError("duplicate intervals must be unique")
        keys = tuple(
            (item.start_utc, item.end_utc, item.duplicate_count) for item in value
        )
        if keys != tuple(sorted(keys)):
            raise ValueError("duplicate intervals must be sorted")
        return value

    @field_validator("diagnostic_ids", "known_limitations")
    @classmethod
    def validate_sorted_collections(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(value)):
            raise ValueError("dataset collection must be sorted")
        return value

    @field_validator("raw_source_provenance")
    @classmethod
    def validate_unique_provenance(
        cls,
        value: tuple[RawSourceProvenance, ...],
    ) -> tuple[RawSourceProvenance, ...]:
        if len(set(value)) != len(value):
            raise ValueError("raw source provenance must be unique")
        keys = tuple(
            (
                item.source_name,
                item.source_version,
                item.source_record,
                item.source_hash,
            )
            for item in value
        )
        if keys != tuple(sorted(keys)):
            raise ValueError("raw source provenance must be sorted")
        return value

    @model_validator(mode="after")
    def validate_descriptor(self) -> Self:
        if self.start_utc >= self.end_utc:
            raise ValueError("dataset start must precede end")
        if self.venue != self.instrument.venue:
            raise ValueError("dataset venue must match instrument")
        if self.data_type is DatasetDataType.OHLCV and _is_missing(self.timeframe):
            raise ValueError("OHLCV datasets require a timeframe")
        if self.data_type is not DatasetDataType.OHLCV and not _is_missing(
            self.timeframe
        ):
            raise ValueError("non-OHLCV datasets prohibit a timeframe")
        has_quality_facts = bool(self.missing_intervals or self.duplicate_intervals)
        if self.validation_status is DatasetValidationStatus.VALID:
            if has_quality_facts or self.diagnostic_ids:
                raise ValueError("VALID datasets cannot retain warning/error facts")
        elif self.validation_status is DatasetValidationStatus.VALID_WITH_WARNINGS:
            if not (has_quality_facts or self.diagnostic_ids):
                raise ValueError("warning status requires a quality fact")
        elif not self.diagnostic_ids:
            raise ValueError("INVALID datasets require a diagnostic")
        return self
