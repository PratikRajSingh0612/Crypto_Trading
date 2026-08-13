"""Structural engine and adapter descriptors without runtime behavior."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, ClassVar, Literal, Self

from pydantic import (
    ConfigDict,
    Field,
    StringConstraints,
    WithJsonSchema,
    field_validator,
    model_validator,
)
from pydantic.json_schema import JsonSchemaValue

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.identifiers import (
    NormalizedIdentifier,
    Sha256,
    exact_string_schema,
)
from crypto_lab.domain.versioning import SemanticVersion, parse_semantic_version

BoundedText = Annotated[
    str, StringConstraints(strict=True, min_length=1, max_length=1024)
]
CapabilityName = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=3,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$",
    ),
    WithJsonSchema(
        exact_string_schema(
            r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$",
            min_length=3,
            max_length=128,
        )
    ),
]
VocabularyVersion = Annotated[
    str,
    StringConstraints(
        strict=True, pattern=r"^capabilities/v[1-9][0-9]*$", max_length=32
    ),
    WithJsonSchema(
        exact_string_schema(
            r"^capabilities/v[1-9][0-9]*$",
            max_length=32,
        )
    ),
]


class OperatingSystem(StrEnum):
    WINDOWS = "WINDOWS"
    LINUX = "LINUX"
    MACOS = "MACOS"


def _unique_sorted_text(value: tuple[str, ...], label: str) -> tuple[str, ...]:
    if len(set(value)) != len(value):
        raise ValueError(f"{label} must be unique")
    if value != tuple(sorted(value)):
        raise ValueError(f"{label} must be sorted")
    return value


def _unique_sorted_versions(
    value: tuple[SemanticVersion, ...],
    label: str,
) -> tuple[SemanticVersion, ...]:
    if len(set(value)) != len(value):
        raise ValueError(f"{label} must be unique")
    if value != tuple(sorted(value, key=parse_semantic_version)):
        raise ValueError(f"{label} must be numerically sorted")
    return value


def _set_unique_items(schema: JsonSchemaValue, fields: tuple[str, ...]) -> None:
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise TypeError("descriptor schema properties must be an object")
    for field in fields:
        field_schema = properties.get(field)
        if not isinstance(field_schema, dict):
            raise TypeError(f"descriptor schema field {field!r} must be an object")
        field_schema["uniqueItems"] = True


def _engine_schema_extra(schema: JsonSchemaValue) -> None:
    _set_unique_items(schema, ("known_limitations",))


def _descriptor_schema_extra(schema: JsonSchemaValue) -> None:
    _set_unique_items(
        schema,
        (
            "supported_protocol_versions",
            "supported_schema_versions",
            "native_capabilities",
            "approximated_capabilities",
            "unsupported_capabilities",
            "supported_operating_systems",
            "runtime_requirements",
            "known_modeling_limitations",
        ),
    )


class EngineDescriptor(CanonicalModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_engine_schema_extra
    )

    schema_version: Literal["1.0.0"]
    engine_name: NormalizedIdentifier
    engine_version: SemanticVersion
    engine_family: NormalizedIdentifier
    planned_role: BoundedText
    known_limitations: tuple[BoundedText, ...] = Field(max_length=64)

    @field_validator("known_limitations")
    @classmethod
    def validate_limitations(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_sorted_text(value, "engine limitations")


class SupportedSchemaVersion(CanonicalModel):
    schema_name: NormalizedIdentifier
    schema_version: SemanticVersion


class AdapterDescriptor(CanonicalModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_descriptor_schema_extra
    )

    schema_version: Literal["1.0.0"]
    adapter_name: NormalizedIdentifier
    adapter_version: SemanticVersion
    engine: EngineDescriptor
    supported_protocol_versions: tuple[SemanticVersion, ...] = Field(
        min_length=1, max_length=32
    )
    supported_schema_versions: tuple[SupportedSchemaVersion, ...] = Field(
        min_length=1,
        max_length=128,
    )
    capability_vocabulary_version: VocabularyVersion
    native_capabilities: tuple[CapabilityName, ...] = Field(max_length=256)
    approximated_capabilities: tuple[CapabilityName, ...] = Field(max_length=256)
    unsupported_capabilities: tuple[CapabilityName, ...] = Field(max_length=256)
    supported_operating_systems: tuple[OperatingSystem, ...] = Field(
        min_length=1, max_length=8
    )
    runtime_requirements: tuple[BoundedText, ...] = Field(max_length=64)
    network_required: bool
    credentials_required: bool
    known_modeling_limitations: tuple[BoundedText, ...] = Field(max_length=64)
    executable_hash: Sha256

    @field_validator("supported_protocol_versions")
    @classmethod
    def validate_versions(
        cls,
        value: tuple[SemanticVersion, ...],
    ) -> tuple[SemanticVersion, ...]:
        return _unique_sorted_versions(value, "supported versions")

    @field_validator("supported_schema_versions")
    @classmethod
    def validate_schema_versions(
        cls,
        value: tuple[SupportedSchemaVersion, ...],
    ) -> tuple[SupportedSchemaVersion, ...]:
        keys = tuple(
            (item.schema_name, parse_semantic_version(item.schema_version))
            for item in value
        )
        if len(set(keys)) != len(keys):
            raise ValueError("supported schema versions must be unique")
        if keys != tuple(sorted(keys)):
            raise ValueError("supported schema versions must be sorted")
        return value

    @field_validator(
        "native_capabilities",
        "approximated_capabilities",
        "unsupported_capabilities",
        "runtime_requirements",
        "known_modeling_limitations",
    )
    @classmethod
    def validate_sorted_text(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_sorted_text(value, "descriptor collection")

    @field_validator("supported_operating_systems")
    @classmethod
    def validate_operating_systems(
        cls,
        value: tuple[OperatingSystem, ...],
    ) -> tuple[OperatingSystem, ...]:
        if len(set(value)) != len(value):
            raise ValueError("operating systems must be unique")
        if value != tuple(sorted(value, key=str)):
            raise ValueError("operating systems must be sorted")
        return value

    @model_validator(mode="after")
    def validate_capability_sets(self) -> Self:
        native = set(self.native_capabilities)
        approximated = set(self.approximated_capabilities)
        unsupported = set(self.unsupported_capabilities)
        if native & approximated or native & unsupported or approximated & unsupported:
            raise ValueError("capability declaration sets must be disjoint")
        return self
