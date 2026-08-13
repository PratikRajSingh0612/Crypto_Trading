"""Closed deterministic registry for the Stage 3 JSON Schemas."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from pydantic import TypeAdapter

from crypto_lab.adapters.descriptors import AdapterDescriptor, EngineDescriptor
from crypto_lab.artifacts.ownership import ARTIFACT_OWNER_ADAPTER
from crypto_lab.configuration.models import ApplicationConfig
from crypto_lab.datasets.models import DatasetDescriptor, DatasetPartition
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.diagnostics import Diagnostic
from crypto_lab.domain.records import InstrumentRef, Money, Price, Quantity

JSON_SCHEMA_DRAFT = "https://json-schema.org/draft/2020-12/schema"


@dataclass(frozen=True, slots=True)
class SchemaDefinition:
    relative_path: PurePosixPath
    schema_id: str
    adapter: TypeAdapter[Any]


SCHEMA_DEFINITIONS: tuple[SchemaDefinition, ...] = (
    SchemaDefinition(
        PurePosixPath("domain/instrument-ref-v1.schema.json"),
        "urn:crypto-lab:schema:domain:instrument-ref:1.0.0",
        TypeAdapter(InstrumentRef),
    ),
    SchemaDefinition(
        PurePosixPath("domain/money-v1.schema.json"),
        "urn:crypto-lab:schema:domain:money:1.0.0",
        TypeAdapter(Money),
    ),
    SchemaDefinition(
        PurePosixPath("domain/price-v1.schema.json"),
        "urn:crypto-lab:schema:domain:price:1.0.0",
        TypeAdapter(Price),
    ),
    SchemaDefinition(
        PurePosixPath("domain/quantity-v1.schema.json"),
        "urn:crypto-lab:schema:domain:quantity:1.0.0",
        TypeAdapter(Quantity),
    ),
    SchemaDefinition(
        PurePosixPath("domain/diagnostic-v1.schema.json"),
        "urn:crypto-lab:schema:domain:diagnostic:1.0.0",
        TypeAdapter(Diagnostic),
    ),
    SchemaDefinition(
        PurePosixPath("configuration/application-config-v1.schema.json"),
        "urn:crypto-lab:schema:configuration:application-config:1.0.0",
        TypeAdapter(ApplicationConfig),
    ),
    SchemaDefinition(
        PurePosixPath("datasets/dataset-partition-v1.schema.json"),
        "urn:crypto-lab:schema:datasets:dataset-partition:1.0.0",
        TypeAdapter(DatasetPartition),
    ),
    SchemaDefinition(
        PurePosixPath("datasets/dataset-descriptor-v1.schema.json"),
        "urn:crypto-lab:schema:datasets:dataset-descriptor:1.0.0",
        TypeAdapter(DatasetDescriptor),
    ),
    SchemaDefinition(
        PurePosixPath("protocol/engine-descriptor-v1.schema.json"),
        "urn:crypto-lab:schema:protocol:engine-descriptor:1.0.0",
        TypeAdapter(EngineDescriptor),
    ),
    SchemaDefinition(
        PurePosixPath("protocol/adapter-descriptor-v1.schema.json"),
        "urn:crypto-lab:schema:protocol:adapter-descriptor:1.0.0",
        TypeAdapter(AdapterDescriptor),
    ),
    SchemaDefinition(
        PurePosixPath("artifacts/artifact-owner-ref-v1.schema.json"),
        "urn:crypto-lab:schema:artifacts:artifact-owner-ref:1.0.0",
        ARTIFACT_OWNER_ADAPTER,
    ),
)


def render_schema_files() -> dict[PurePosixPath, bytes]:
    """Render the closed schema registry as canonical UTF-8 plus one LF."""
    paths = tuple(item.relative_path for item in SCHEMA_DEFINITIONS)
    identifiers = tuple(item.schema_id for item in SCHEMA_DEFINITIONS)
    if len(set(paths)) != len(paths) or len(set(identifiers)) != len(identifiers):
        raise RuntimeError("schema registry paths and IDs must be unique")
    rendered: dict[PurePosixPath, bytes] = {}
    for definition in SCHEMA_DEFINITIONS:
        schema = definition.adapter.json_schema(mode="serialization")
        schema["$schema"] = JSON_SCHEMA_DRAFT
        schema["$id"] = definition.schema_id
        rendered[definition.relative_path] = canonical_json_bytes(schema) + b"\n"
    return rendered
