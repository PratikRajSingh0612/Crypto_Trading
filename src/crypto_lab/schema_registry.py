"""Closed deterministic registry for the Stage 3 to Stage 6 JSON Schemas.

The eleven Stage 3 entries come first, in their original order, followed by the
nine Stage 4 strategy and capability entries, the seven Stage 5 experiment, run,
invocation, retry and aggregation entries (Stage 5 plan Task 9) and then the
eight Stage 6 protocol entries at positions 27-34 (Stage 6 plan Task 9, section
12.1): the bootstrap descriptor envelope, the negotiation result, the
command-discriminated request envelope, the wire event envelope, the sanitized
`RunEvent`, the validation result, the adapter result manifest and the sanitized
manifest. Existing entries are never reordered: the order is the generation
order, and a published `$id` is a permanent contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from pydantic import TypeAdapter

from crypto_lab.adapters.envelopes import AdapterCommandRequestEnvelope
from crypto_lab.adapters.events import ProtocolEventEnvelope, RunEvent
from crypto_lab.adapters.manifests import (
    AdapterResultManifest,
    AdapterValidationResult,
    SanitizedAdapterResultManifest,
)
from crypto_lab.adapters.negotiation import (
    BootstrapDescriptorEnvelope,
    NegotiationResult,
)
from crypto_lab.artifacts.ownership import ARTIFACT_OWNER_ADAPTER
from crypto_lab.capabilities.comparison import ComparisonEligibilityResult
from crypto_lab.capabilities.models import (
    ApproximationDeclaration,
    CapabilityDeclaration,
    CapabilityRequirement,
    CompatibilityResult,
)
from crypto_lab.configuration.models import ApplicationConfig
from crypto_lab.datasets.models import DatasetDescriptor, DatasetPartition
from crypto_lab.domain.aggregation import ExperimentAggregationResult
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.descriptors import (
    AdapterDescriptor,
    EngineDescriptor,
    RuntimeAvailabilityObservation,
)
from crypto_lab.domain.diagnostics import Diagnostic
from crypto_lab.domain.engine_run import EngineRunRecord
from crypto_lab.domain.experiment import ExperimentRecord, ExperimentSpec
from crypto_lab.domain.records import InstrumentRef, Money, Price, Quantity
from crypto_lab.domain.retry import RetryDecisionRecord, RetryPolicy
from crypto_lab.strategy.expressions import EXPRESSION_ADAPTER
from crypto_lab.strategy.models import StrategySpec
from crypto_lab.strategy.versioning import StrategyVersion

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
    SchemaDefinition(
        PurePosixPath("strategy/strategy-spec-v1.schema.json"),
        "urn:crypto-lab:schema:strategy:strategy-spec:1.0.0",
        TypeAdapter(StrategySpec),
    ),
    SchemaDefinition(
        PurePosixPath("strategy/strategy-version-v1.schema.json"),
        "urn:crypto-lab:schema:strategy:strategy-version:1.0.0",
        TypeAdapter(StrategyVersion),
    ),
    SchemaDefinition(
        PurePosixPath("strategy/expression-v1.schema.json"),
        "urn:crypto-lab:schema:strategy:expression:1.0.0",
        EXPRESSION_ADAPTER,
    ),
    SchemaDefinition(
        PurePosixPath("capabilities/capability-requirement-v1.schema.json"),
        "urn:crypto-lab:schema:capabilities:capability-requirement:1.0.0",
        TypeAdapter(CapabilityRequirement),
    ),
    SchemaDefinition(
        PurePosixPath("capabilities/capability-declaration-v1.schema.json"),
        "urn:crypto-lab:schema:capabilities:capability-declaration:1.0.0",
        TypeAdapter(CapabilityDeclaration),
    ),
    SchemaDefinition(
        PurePosixPath("capabilities/approximation-declaration-v1.schema.json"),
        "urn:crypto-lab:schema:capabilities:approximation-declaration:1.0.0",
        TypeAdapter(ApproximationDeclaration),
    ),
    SchemaDefinition(
        PurePosixPath("capabilities/compatibility-result-v1.schema.json"),
        "urn:crypto-lab:schema:capabilities:compatibility-result:1.0.0",
        TypeAdapter(CompatibilityResult),
    ),
    SchemaDefinition(
        PurePosixPath("capabilities/runtime-availability-observation-v1.schema.json"),
        "urn:crypto-lab:schema:capabilities:runtime-availability-observation:1.0.0",
        TypeAdapter(RuntimeAvailabilityObservation),
    ),
    SchemaDefinition(
        PurePosixPath("capabilities/comparison-eligibility-result-v1.schema.json"),
        "urn:crypto-lab:schema:capabilities:comparison-eligibility-result:1.0.0",
        TypeAdapter(ComparisonEligibilityResult),
    ),
    SchemaDefinition(
        PurePosixPath("experiments/experiment-spec-v1.schema.json"),
        "urn:crypto-lab:schema:experiments:experiment-spec:1.0.0",
        TypeAdapter(ExperimentSpec),
    ),
    SchemaDefinition(
        PurePosixPath("experiments/experiment-record-v1.schema.json"),
        "urn:crypto-lab:schema:experiments:experiment-record:1.0.0",
        TypeAdapter(ExperimentRecord),
    ),
    SchemaDefinition(
        PurePosixPath("experiments/engine-run-record-v1.schema.json"),
        "urn:crypto-lab:schema:experiments:engine-run-record:1.0.0",
        TypeAdapter(EngineRunRecord),
    ),
    SchemaDefinition(
        PurePosixPath("experiments/command-invocation-record-v1.schema.json"),
        "urn:crypto-lab:schema:experiments:command-invocation-record:1.0.0",
        TypeAdapter(CommandInvocationRecord),
    ),
    SchemaDefinition(
        PurePosixPath("experiments/retry-policy-v1.schema.json"),
        "urn:crypto-lab:schema:experiments:retry-policy:1.0.0",
        TypeAdapter(RetryPolicy),
    ),
    SchemaDefinition(
        PurePosixPath("experiments/retry-decision-record-v1.schema.json"),
        "urn:crypto-lab:schema:experiments:retry-decision-record:1.0.0",
        TypeAdapter(RetryDecisionRecord),
    ),
    SchemaDefinition(
        PurePosixPath("experiments/experiment-aggregation-result-v1.schema.json"),
        "urn:crypto-lab:schema:experiments:experiment-aggregation-result:1.0.0",
        TypeAdapter(ExperimentAggregationResult),
    ),
    SchemaDefinition(
        PurePosixPath("protocol/bootstrap-descriptor-envelope-v1.schema.json"),
        "urn:crypto-lab:schema:protocol:bootstrap-descriptor-envelope:1.0.0",
        TypeAdapter(BootstrapDescriptorEnvelope),
    ),
    SchemaDefinition(
        PurePosixPath("protocol/negotiation-result-v1.schema.json"),
        "urn:crypto-lab:schema:protocol:negotiation-result:1.0.0",
        TypeAdapter(NegotiationResult),
    ),
    SchemaDefinition(
        PurePosixPath("protocol/adapter-command-request-envelope-v1.schema.json"),
        "urn:crypto-lab:schema:protocol:adapter-command-request-envelope:1.0.0",
        TypeAdapter(AdapterCommandRequestEnvelope),
    ),
    SchemaDefinition(
        PurePosixPath("protocol/protocol-event-envelope-v1.schema.json"),
        "urn:crypto-lab:schema:protocol:protocol-event-envelope:1.0.0",
        TypeAdapter(ProtocolEventEnvelope),
    ),
    SchemaDefinition(
        PurePosixPath("protocol/run-event-v1.schema.json"),
        "urn:crypto-lab:schema:protocol:run-event:1.0.0",
        TypeAdapter(RunEvent),
    ),
    SchemaDefinition(
        PurePosixPath("protocol/adapter-validation-result-v1.schema.json"),
        "urn:crypto-lab:schema:protocol:adapter-validation-result:1.0.0",
        TypeAdapter(AdapterValidationResult),
    ),
    SchemaDefinition(
        PurePosixPath("protocol/adapter-result-manifest-v1.schema.json"),
        "urn:crypto-lab:schema:protocol:adapter-result-manifest:1.0.0",
        TypeAdapter(AdapterResultManifest),
    ),
    SchemaDefinition(
        PurePosixPath("protocol/sanitized-adapter-result-manifest-v1.schema.json"),
        "urn:crypto-lab:schema:protocol:sanitized-adapter-result-manifest:1.0.0",
        TypeAdapter(SanitizedAdapterResultManifest),
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
