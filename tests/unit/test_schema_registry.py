from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Final, cast

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import TypeAdapter
from pydantic import ValidationError as PydanticValidationError
from pydantic.json_schema import JsonSchemaMode

from crypto_lab.artifacts.ownership import ARTIFACT_OWNER_ADAPTER
from crypto_lab.capabilities.comparison import (
    ComparisonEligibilityResult,
    ComparisonMaterial,
)
from crypto_lab.capabilities.models import (
    ApproximationDeclaration,
    CapabilityDeclaration,
    CapabilityRequirement,
    CompatibilityResult,
)
from crypto_lab.configuration.models import ApplicationConfig
from crypto_lab.datasets.models import DatasetDescriptor, DatasetPartition
from crypto_lab.domain.aggregation import (
    AggregationVerdict,
    ExperimentAggregationResult,
)
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.compatibility import CompatibilityOutcome
from crypto_lab.domain.descriptors import (
    _EXECUTABLE_PATH_SCHEMA_PATTERN,
    MAX_EXECUTABLE_PATH_CHARACTERS,
    AdapterDescriptor,
    EngineDescriptor,
    RuntimeAvailabilityObservation,
)
from crypto_lab.domain.diagnostics import Diagnostic
from crypto_lab.domain.engine_run import EngineRunRecord
from crypto_lab.domain.experiment import ExperimentRecord, ExperimentSpec
from crypto_lab.domain.identifiers import exact_string_schema
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
    ProcessExitCategory,
)
from crypto_lab.domain.records import InstrumentRef, Money, Price, Quantity
from crypto_lab.domain.results import Success
from crypto_lab.domain.retry import RetryDecisionRecord, RetryPolicy
from crypto_lab.schema_registry import (
    JSON_SCHEMA_DRAFT,
    SCHEMA_DEFINITIONS,
    render_schema_files,
)
from crypto_lab.strategy.evaluation import Bar
from crypto_lab.strategy.expressions import EXPRESSION_ADAPTER, MAX_EXPRESSION_DEPTH
from crypto_lab.strategy.loader import StrategyLoader
from crypto_lab.strategy.models import (
    MAX_FEATURE_PARAMETERS,
    MAX_PARAMETERS,
    StrategySpec,
)
from crypto_lab.strategy.versioning import StrategyVersion
from doubles.experiments import (
    AVAIL_B,
    EXPERIMENT_ID,
    SLOT_A,
    SLOT_B,
    sample_allowed_retry_decision,
    sample_experiment,
    sample_invocation,
    sample_retry_decision,
    sample_retry_policy,
    sample_run,
    sample_slot_compatibility,
)
from generate_schemas import _check, _write

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

_EXPECTED = {
    PurePosixPath(
        "domain/instrument-ref-v1.schema.json"
    ): "urn:crypto-lab:schema:domain:instrument-ref:1.0.0",
    PurePosixPath(
        "domain/money-v1.schema.json"
    ): "urn:crypto-lab:schema:domain:money:1.0.0",
    PurePosixPath(
        "domain/price-v1.schema.json"
    ): "urn:crypto-lab:schema:domain:price:1.0.0",
    PurePosixPath(
        "domain/quantity-v1.schema.json"
    ): "urn:crypto-lab:schema:domain:quantity:1.0.0",
    PurePosixPath(
        "domain/diagnostic-v1.schema.json"
    ): "urn:crypto-lab:schema:domain:diagnostic:1.0.0",
    PurePosixPath(
        "configuration/application-config-v1.schema.json"
    ): "urn:crypto-lab:schema:configuration:application-config:1.0.0",
    PurePosixPath(
        "datasets/dataset-partition-v1.schema.json"
    ): "urn:crypto-lab:schema:datasets:dataset-partition:1.0.0",
    PurePosixPath(
        "datasets/dataset-descriptor-v1.schema.json"
    ): "urn:crypto-lab:schema:datasets:dataset-descriptor:1.0.0",
    PurePosixPath(
        "protocol/engine-descriptor-v1.schema.json"
    ): "urn:crypto-lab:schema:protocol:engine-descriptor:1.0.0",
    PurePosixPath(
        "protocol/adapter-descriptor-v1.schema.json"
    ): "urn:crypto-lab:schema:protocol:adapter-descriptor:1.0.0",
    PurePosixPath(
        "artifacts/artifact-owner-ref-v1.schema.json"
    ): "urn:crypto-lab:schema:artifacts:artifact-owner-ref:1.0.0",
    PurePosixPath(
        "strategy/strategy-spec-v1.schema.json"
    ): "urn:crypto-lab:schema:strategy:strategy-spec:1.0.0",
    PurePosixPath(
        "strategy/strategy-version-v1.schema.json"
    ): "urn:crypto-lab:schema:strategy:strategy-version:1.0.0",
    PurePosixPath(
        "strategy/expression-v1.schema.json"
    ): "urn:crypto-lab:schema:strategy:expression:1.0.0",
    PurePosixPath(
        "capabilities/capability-requirement-v1.schema.json"
    ): "urn:crypto-lab:schema:capabilities:capability-requirement:1.0.0",
    PurePosixPath(
        "capabilities/capability-declaration-v1.schema.json"
    ): "urn:crypto-lab:schema:capabilities:capability-declaration:1.0.0",
    PurePosixPath(
        "capabilities/approximation-declaration-v1.schema.json"
    ): "urn:crypto-lab:schema:capabilities:approximation-declaration:1.0.0",
    PurePosixPath(
        "capabilities/compatibility-result-v1.schema.json"
    ): "urn:crypto-lab:schema:capabilities:compatibility-result:1.0.0",
    PurePosixPath(
        "capabilities/runtime-availability-observation-v1.schema.json"
    ): "urn:crypto-lab:schema:capabilities:runtime-availability-observation:1.0.0",
    PurePosixPath(
        "capabilities/comparison-eligibility-result-v1.schema.json"
    ): "urn:crypto-lab:schema:capabilities:comparison-eligibility-result:1.0.0",
    PurePosixPath(
        "experiments/experiment-spec-v1.schema.json"
    ): "urn:crypto-lab:schema:experiments:experiment-spec:1.0.0",
    PurePosixPath(
        "experiments/experiment-record-v1.schema.json"
    ): "urn:crypto-lab:schema:experiments:experiment-record:1.0.0",
    PurePosixPath(
        "experiments/engine-run-record-v1.schema.json"
    ): "urn:crypto-lab:schema:experiments:engine-run-record:1.0.0",
    PurePosixPath(
        "experiments/command-invocation-record-v1.schema.json"
    ): "urn:crypto-lab:schema:experiments:command-invocation-record:1.0.0",
    PurePosixPath(
        "experiments/retry-policy-v1.schema.json"
    ): "urn:crypto-lab:schema:experiments:retry-policy:1.0.0",
    PurePosixPath(
        "experiments/retry-decision-record-v1.schema.json"
    ): "urn:crypto-lab:schema:experiments:retry-decision-record:1.0.0",
    PurePosixPath(
        "experiments/experiment-aggregation-result-v1.schema.json"
    ): "urn:crypto-lab:schema:experiments:experiment-aggregation-result:1.0.0",
}


def _schemas() -> dict[PurePosixPath, dict[str, Any]]:
    """The live registry render. Use this to assert what the *renderer* emits."""
    return {
        path: cast(dict[str, Any], json.loads(contents))
        for path, contents in render_schema_files().items()
    }


def _committed_schemas() -> dict[PurePosixPath, dict[str, Any]]:
    """The committed bytes on disk. Use this to assert what *ships*.

    The two are held equal by
    `test_every_rendered_schema_equals_its_committed_generated_file`, so either
    would satisfy a correctness claim. They are not interchangeable for
    *detectability*: an assertion that reads only the render cannot fail on a
    hand-edited committed file, leaving the render-versus-disk test as the sole
    guard for that whole class. Stage 4's published-contract assertions
    therefore read the file, which is what the wheel and the sdist carry.
    """
    root = _REPOSITORY_ROOT / "schemas"
    return {
        definition.relative_path: cast(
            dict[str, Any],
            json.loads((root / definition.relative_path.as_posix()).read_bytes()),
        )
        for definition in SCHEMA_DEFINITIONS
    }


def _references(value: object) -> tuple[str, ...]:
    if isinstance(value, dict):
        direct = (value["$ref"],) if isinstance(value.get("$ref"), str) else ()
        return direct + tuple(
            reference for nested in value.values() for reference in _references(nested)
        )
    if isinstance(value, list):
        return tuple(reference for nested in value for reference in _references(nested))
    return ()


def _patterns(value: object) -> tuple[str, ...]:
    if isinstance(value, dict):
        direct = (value["pattern"],) if isinstance(value.get("pattern"), str) else ()
        return direct + tuple(
            pattern for nested in value.values() for pattern in _patterns(nested)
        )
    if isinstance(value, list):
        return tuple(pattern for nested in value for pattern in _patterns(nested))
    return ()


def _resolve_local_ref(
    document: dict[str, Any],
    node: dict[str, Any],
) -> dict[str, Any]:
    resolved = node
    seen: set[str] = set()
    while isinstance(resolved.get("$ref"), str):
        reference = cast(str, resolved["$ref"])
        if not reference.startswith("#/") or reference in seen:
            raise AssertionError(f"invalid local schema reference: {reference}")
        seen.add(reference)
        target: object = document
        for token in reference.removeprefix("#/").split("/"):
            if not isinstance(target, dict):
                raise AssertionError(f"unresolvable schema reference: {reference}")
            target = target[token.replace("~1", "/").replace("~0", "~")]
        if not isinstance(target, dict):
            raise AssertionError(f"schema reference is not an object: {reference}")
        resolved = cast(dict[str, Any], target)
    return resolved


def test_registry_has_exactly_the_closed_twenty_seven_paths_and_ids() -> None:
    assert {
        definition.relative_path: definition.schema_id
        for definition in SCHEMA_DEFINITIONS
    } == _EXPECTED
    assert len(SCHEMA_DEFINITIONS) == 27


def test_every_schema_is_deterministic_draft_2020_12() -> None:
    first = render_schema_files()
    assert render_schema_files() == first
    assert set(first) == set(_EXPECTED)
    for path, contents in first.items():
        assert contents.endswith(b"\n")
        assert not contents.endswith(b"\n\n")
        schema = cast(dict[str, Any], json.loads(contents))
        assert schema["$schema"] == JSON_SCHEMA_DRAFT
        assert schema["$id"] == _EXPECTED[path]
        Draft202012Validator.check_schema(schema)


def test_every_schema_reference_is_document_local() -> None:
    for schema in _schemas().values():
        assert all(reference.startswith("#/") for reference in _references(schema))


def test_every_schema_pattern_uses_absolute_end_semantics() -> None:
    patterns = tuple(
        pattern for schema in _schemas().values() for pattern in _patterns(schema)
    )
    assert patterns
    assert all(not pattern.endswith("$") for pattern in patterns)


@pytest.mark.parametrize(
    ("path", "field"),
    [
        (PurePosixPath("domain/money-v1.schema.json"), "amount"),
        (PurePosixPath("domain/price-v1.schema.json"), "value"),
        (PurePosixPath("domain/quantity-v1.schema.json"), "value"),
    ],
)
def test_decimal_schema_fields_are_string_only(
    path: PurePosixPath,
    field: str,
) -> None:
    document = _schemas()[path]
    field_schema = _resolve_local_ref(document, document["properties"][field])
    assert field_schema["type"] == "string"
    assert "pattern" in field_schema
    assert "maxLength" in field_schema


def test_diagnostic_schema_compiles_signed_64_bit_detail_bounds() -> None:
    schema = _schemas()[PurePosixPath("domain/diagnostic-v1.schema.json")]
    validator = Draft202012Validator(schema)
    document = {
        "schema_version": "1.0.0",
        "diagnostic_id": "diag_12345678-1234-4234-8234-123456789abc",
        "severity": "ERROR",
        "error_code": "CONFIG.LAYER_INVALID",
        "category": "USER_CONFIGURATION",
        "message": "Configuration layer is invalid.",
        "source_component": "configuration.loader",
        "retriable": False,
        "timestamp_utc": "2026-08-10T00:00:00Z",
        "details": {"count": 0},
        "causal_diagnostic_ids": [],
    }
    for boundary in (-(2**63), 2**63 - 1):
        validator.validate({**document, "details": {"count": boundary}})
    for invalid in (-(2**63) - 1, 2**63, 0.5):
        with pytest.raises(JsonSchemaValidationError):
            validator.validate({**document, "details": {"count": invalid}})
    for error_code in ("invalid", "CONFIG", "CONFIG.bad"):
        with pytest.raises(JsonSchemaValidationError):
            validator.validate({**document, "error_code": error_code})
    invalid_details = (
        {"message": "x" * 2049},
        {"items": list(range(65))},
        {f"key{index}": index for index in range(65)},
        {"x" * 129: "value"},
    )
    for details in invalid_details:
        with pytest.raises(JsonSchemaValidationError):
            validator.validate({**document, "details": details})
    for field in ("experiment_id", "run_id", "invocation_id", "engine"):
        with pytest.raises(JsonSchemaValidationError):
            validator.validate({**document, field: None})
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(
            {
                **document,
                "run_id": "run_12345678-1234-4234-8234-123456789abc",
            }
        )
    with pytest.raises(JsonSchemaValidationError):
        validator.validate({**document, "category": "ENGINE_RUNTIME"})
    validator.validate(
        {
            **document,
            "category": "ENGINE_RUNTIME",
            "invocation_id": "inv_12345678-1234-4234-8234-123456789abc",
        }
    )
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(
            {
                **document,
                "causal_diagnostic_ids": [
                    "diag_22345678-1234-4234-8234-123456789abc",
                    "diag_22345678-1234-4234-8234-123456789abc",
                ],
            }
        )


def test_configuration_schema_compiles_local_windows_path_rules() -> None:
    schema = _schemas()[
        PurePosixPath("configuration/application-config-v1.schema.json")
    ]
    validator = Draft202012Validator(schema)
    validator.validate({"paths": {"runtime_root": "safe/root"}})
    validator.validate({"paths": {"runtime_root": r"C:\safe\root"}})
    for invalid in (
        r"C:drive-relative",
        r"\rooted-without-drive",
        r"\\server\share",
        "folder/../escape",
        "folder/name:stream",
        "folder/CON",
        "folder/bad?name",
        "folder/control\x1f",
        "folder/trailing.",
    ):
        with pytest.raises(JsonSchemaValidationError):
            validator.validate({"paths": {"runtime_root": invalid}})
    validator.validate({"database": {"filename": "crypto_lab.sqlite3"}})
    for filename in ("CON", "aux.db", "trailing.", "trailing ", "bad?.db"):
        with pytest.raises(JsonSchemaValidationError):
            validator.validate({"database": {"filename": filename}})
    entry = {
        "adapter_name": "adapter.alpha",
        "adapter_version": "1.0.0",
        "executable_path": r"C:\adapters\adapter.exe",
        "executable_hash": "a" * 64,
        "runtime_metadata": {},
    }
    validator.validate({"adapters": {"entries": [entry]}})
    with pytest.raises(JsonSchemaValidationError):
        validator.validate({"adapters": {"entries": [entry, entry]}})
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(
            {
                "scheduler": {
                    "retry": {
                        "automatically_retry_terminal_states": [
                            "FAILED",
                            "FAILED",
                        ]
                    }
                }
            }
        )
    invalid_entries = (
        {**entry, "executable_path": "relative.exe"},
        {**entry, "runtime_metadata": {"count": 2**63}},
        {**entry, "runtime_metadata": {"count": -(2**63) - 1}},
        {**entry, "runtime_metadata": {"ratio": 0.5}},
        {**entry, "runtime_metadata": {"text": "x" * 2049}},
        {**entry, "runtime_metadata": {"items": list(range(65))}},
        {
            **entry,
            "runtime_metadata": {f"key{index}": index for index in range(65)},
        },
        {**entry, "runtime_metadata": {"x" * 129: "value"}},
    )
    for invalid_entry in invalid_entries:
        with pytest.raises(JsonSchemaValidationError):
            validator.validate({"adapters": {"entries": [invalid_entry]}})


def test_utc_and_structured_schema_version_shapes_are_explicit() -> None:
    schemas = _schemas()
    partition = schemas[PurePosixPath("datasets/dataset-partition-v1.schema.json")]
    start_utc = _resolve_local_ref(partition, partition["properties"]["start_utc"])
    assert start_utc["pattern"].endswith(r"Z(?![\s\S])")
    validator = Draft202012Validator(start_utc)
    validator.validate("2026-08-10T00:00:00Z")
    for terminator in ("\n", "\r", "\r\n"):
        with pytest.raises(JsonSchemaValidationError):
            validator.validate("2026-08-10T00:00:00Z" + terminator)
    adapter = schemas[PurePosixPath("protocol/adapter-descriptor-v1.schema.json")]
    supported = adapter["properties"]["supported_schema_versions"]
    assert supported["type"] == "array"
    assert "SupportedSchemaVersion" in supported["items"]["$ref"]


def test_dataset_partition_schema_enforces_safe_registry_relative_paths() -> None:
    schema = _schemas()[PurePosixPath("datasets/dataset-partition-v1.schema.json")]
    validator = Draft202012Validator(schema)
    provenance = {
        "source_name": "fixture.source",
        "source_version": "1.0.0",
        "source_record": "fixture",
        "source_hash": "3" * 64,
    }
    document = {
        "schema_version": "1.0.0",
        "partition_id": "part_12345678-1234-4234-8234-123456789abc",
        "dataset_id": "ds_12345678-1234-4234-8234-123456789abc",
        "ordinal": 0,
        "relative_path": "ohlcv/part.parquet",
        "content_hash": "0" * 64,
        "row_count": 1,
        "start_utc": "2026-01-01T00:00:00Z",
        "end_utc": "2026-01-02T00:00:00Z",
        "raw_checksum": "1" * 64,
        "normalized_checksum": "2" * 64,
        "column_schema_version": "1.0.0",
        "raw_source_provenance": [provenance],
        "quality_observations": [],
    }
    validator.validate(document)
    for path in (
        "/root/file",
        "//server/share",
        r"folder\file",
        "C:/file",
        "file:stream",
        "../file",
        "folder//file",
        "folder/AUX.txt",
        "folder/control\x1f",
        "folder/trailing.",
        "folder/trailing ",
    ):
        with pytest.raises(JsonSchemaValidationError):
            validator.validate({**document, "relative_path": path})
    for invalid in (
        {**document, "row_count": 0},
        {
            **document,
            "raw_source_provenance": [provenance, provenance],
        },
        {**document, "quality_observations": ["duplicate", "duplicate"]},
    ):
        with pytest.raises(JsonSchemaValidationError):
            validator.validate(invalid)
    validator.validate({**document, "row_count": 0, "quality_observations": ["empty"]})


def test_dataset_descriptor_schema_matches_expressible_runtime_invariants() -> None:
    schema = _schemas()[PurePosixPath("datasets/dataset-descriptor-v1.schema.json")]
    validator = Draft202012Validator(schema)
    provenance = {
        "source_name": "fixture.source",
        "source_version": "1.0.0",
        "source_record": "fixture",
        "source_hash": "3" * 64,
    }
    interval = {
        "start_utc": "2026-01-01T00:00:00Z",
        "end_utc": "2026-01-02T00:00:00Z",
    }
    diagnostic_id = "diag_12345678-1234-4234-8234-123456789abc"
    partition_id = "part_12345678-1234-4234-8234-123456789abc"
    document = {
        "schema_version": "1.0.0",
        "dataset_id": "ds_12345678-1234-4234-8234-123456789abc",
        "content_hash": "0" * 64,
        "source": "fixture",
        "venue": "BINANCE",
        "instrument": {
            "schema_version": "1.0.0",
            "canonical_id": "BINANCE:BTC/USDT:SPOT",
            "venue": "BINANCE",
            "base_asset": "BTC",
            "quote_asset": "USDT",
            "market_type": "SPOT",
        },
        "data_type": "OHLCV",
        "timeframe": "1m",
        "start_utc": "2026-01-01T00:00:00Z",
        "end_utc": "2026-01-02T00:00:00Z",
        "original_timezone": "UTC",
        "normalized_to_utc": True,
        "raw_source_provenance": [provenance],
        "normalization_implementation": "fixture.normalizer",
        "normalization_version": "1.0.0",
        "validation_status": "VALID",
        "partition_ids": [partition_id],
        "missing_intervals": [],
        "duplicate_intervals": [],
        "diagnostic_ids": [],
        "raw_checksums": ["1" * 64],
        "normalized_checksums": ["2" * 64],
        "column_schema_version": "1.0.0",
        "known_limitations": [],
        "created_at_utc": "2026-01-02T00:00:00Z",
    }
    validator.validate(document)
    invalid_documents = (
        {key: value for key, value in document.items() if key != "timeframe"},
        {**document, "data_type": "TRADES"},
        {**document, "timeframe": None},
        {**document, "imported_at_utc": None},
        {**document, "partition_ids": [partition_id, partition_id]},
        {**document, "raw_source_provenance": [provenance, provenance]},
        {**document, "known_limitations": ["same", "same"]},
        {**document, "validation_status": "VALID", "missing_intervals": [interval]},
        {**document, "validation_status": "VALID_WITH_WARNINGS"},
        {**document, "validation_status": "INVALID"},
        {
            **document,
            "validation_status": "VALID_WITH_WARNINGS",
            "diagnostic_ids": [diagnostic_id, diagnostic_id],
        },
    )
    for invalid in invalid_documents:
        with pytest.raises(JsonSchemaValidationError):
            validator.validate(invalid)
    trades = {**document, "data_type": "TRADES"}
    del trades["timeframe"]
    validator.validate(trades)
    validator.validate(
        {
            **document,
            "validation_status": "VALID_WITH_WARNINGS",
            "missing_intervals": [interval],
        }
    )
    validator.validate(
        {
            **document,
            "validation_status": "INVALID",
            "diagnostic_ids": [diagnostic_id],
        }
    )


def test_descriptor_schemas_reject_duplicate_collection_items() -> None:
    schemas = _schemas()
    engine = {
        "schema_version": "1.0.0",
        "engine_name": "engine.alpha",
        "engine_version": "1.0.0",
        "engine_family": "engine.alpha",
        "planned_role": "structural fixture",
        "known_limitations": [],
    }
    engine_validator = Draft202012Validator(
        schemas[PurePosixPath("protocol/engine-descriptor-v1.schema.json")]
    )
    engine_validator.validate(engine)
    with pytest.raises(JsonSchemaValidationError):
        engine_validator.validate({**engine, "known_limitations": ["same", "same"]})
    schema_version = {"schema_name": "domain.money", "schema_version": "1.0.0"}
    adapter = {
        "schema_version": "1.0.0",
        "adapter_name": "adapter.alpha",
        "adapter_version": "1.0.0",
        "engine": engine,
        "supported_protocol_versions": ["1.0.0"],
        "supported_schema_versions": [schema_version],
        "capability_vocabulary_version": "capabilities/v1",
        "native_capabilities": ["market.data"],
        "approximated_capabilities": [],
        "unsupported_capabilities": [],
        "supported_operating_systems": ["WINDOWS"],
        "runtime_requirements": [],
        "network_required": False,
        "credentials_required": False,
        "known_modeling_limitations": [],
        "executable_hash": "a" * 64,
    }
    adapter_validator = Draft202012Validator(
        schemas[PurePosixPath("protocol/adapter-descriptor-v1.schema.json")]
    )
    adapter_validator.validate(adapter)
    duplicate_values: dict[str, object] = {
        "supported_protocol_versions": ["1.0.0", "1.0.0"],
        "supported_schema_versions": [schema_version, schema_version],
        "native_capabilities": ["market.data", "market.data"],
        "supported_operating_systems": ["WINDOWS", "WINDOWS"],
        "runtime_requirements": ["same", "same"],
        "known_modeling_limitations": ["same", "same"],
    }
    for field, duplicate in duplicate_values.items():
        with pytest.raises(JsonSchemaValidationError):
            adapter_validator.validate({**adapter, field: duplicate})


def test_owner_schema_has_all_six_discriminated_branches() -> None:
    schema = _schemas()[PurePosixPath("artifacts/artifact-owner-ref-v1.schema.json")]
    schema_text = json.dumps(schema, sort_keys=True)
    assert '"null"' not in schema_text
    assert '"default": null' not in schema_text
    assert len(schema["oneOf"]) == 6
    assert set(schema["discriminator"]["mapping"]) == {
        "RUN",
        "EXPERIMENT",
        "DATASET",
        "STRATEGY",
        "ADAPTER",
        "SYSTEM",
    }
    documents = [
        {
            "owner_kind": "RUN",
            "experiment_id": "exp_12345678-1234-4234-8234-123456789abc",
            "run_id": "run_12345678-1234-4234-8234-123456789abc",
        },
        {
            "owner_kind": "EXPERIMENT",
            "experiment_id": "exp_12345678-1234-4234-8234-123456789abc",
        },
        {
            "owner_kind": "DATASET",
            "dataset_id": "ds_12345678-1234-4234-8234-123456789abc",
        },
        {"owner_kind": "STRATEGY", "strategy_version_hash": "a" * 64},
        {
            "owner_kind": "ADAPTER",
            "adapter_name": "adapter.alpha",
            "adapter_version": "1.0.0",
        },
        {
            "owner_kind": "SYSTEM",
            "core_component": "schema_registry",
            "correlation_id": "stage3",
        },
    ]
    validator = Draft202012Validator(schema)
    for document in documents:
        validator.validate(document)
    with pytest.raises(JsonSchemaValidationError):
        validator.validate({**documents[-1], "unexpected": True})
    explicit_null_documents = [
        {**documents[0], "invocation_id": None},
        {
            "owner_kind": "STRATEGY",
            "strategy_version_id": None,
            "strategy_version_hash": "a" * 64,
        },
        {**documents[4], "engine_name": None},
        {**documents[4], "engine_version": None},
    ]
    for invalid_document in explicit_null_documents:
        with pytest.raises(JsonSchemaValidationError):
            validator.validate(invalid_document)
    conditional_failures = [
        {"owner_kind": "STRATEGY"},
        {
            "owner_kind": "STRATEGY",
            "strategy_version_id": "strv_12345678-1234-4234-8234-123456789abc",
            "strategy_version_hash": "a" * 64,
        },
        {**documents[4], "engine_name": "engine.alpha"},
        {**documents[4], "engine_version": "1.0.0"},
    ]
    for conditional_failure in conditional_failures:
        with pytest.raises(JsonSchemaValidationError):
            validator.validate(conditional_failure)


def test_instrument_schema_rejects_extra_fields() -> None:
    schema = _schemas()[PurePosixPath("domain/instrument-ref-v1.schema.json")]
    validator = Draft202012Validator(schema)
    document = {
        "schema_version": "1.0.0",
        "canonical_id": "BINANCE:BTC/USDT:SPOT",
        "venue": "BINANCE",
        "base_asset": "BTC",
        "quote_asset": "USDT",
        "market_type": "SPOT",
    }
    validator.validate(document)
    with pytest.raises(JsonSchemaValidationError):
        validator.validate({**document, "unexpected": True})


def test_generator_detects_missing_changed_and_unexpected_files(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    expected = render_schema_files()
    assert _write(tmp_path, expected) == 0
    assert _check(tmp_path, expected) == 0
    first_path = next(iter(expected))
    target = tmp_path.joinpath(*first_path.parts)
    target.write_bytes(b"changed\n")
    assert _check(tmp_path, expected) == 1
    assert "changed schema" in capsys.readouterr().err
    target.unlink()
    assert _check(tmp_path, expected) == 1
    assert "missing schema" in capsys.readouterr().err
    assert _write(tmp_path, expected) == 0
    (tmp_path / "foreign.schema.json").write_text("{}\n", encoding="utf-8")
    assert _check(tmp_path, expected) == 1
    assert "unexpected schema" in capsys.readouterr().err
    assert _write(tmp_path, expected) == 1
    assert (tmp_path / "foreign.schema.json").is_file()


def test_generator_rejects_symlinked_entries_without_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = render_schema_files()
    assert _write(tmp_path, expected) == 0
    target = tmp_path.joinpath(*next(iter(expected)).parts)
    original = Path.is_symlink

    def _reported_symlink(path: Path) -> bool:
        return path == target or original(path)

    monkeypatch.setattr(Path, "is_symlink", _reported_symlink)
    with pytest.raises(ValueError, match="must not be a symlink"):
        _write(tmp_path, expected)


# --- Task 8: the closed twenty-entry registry, extended to twenty-seven by Stage 5
#     Task 9 -------------------------------------------------------------------------
#
# `_EXPECTED` above is keyed by path, so a set comparison against it proves
# membership but says nothing about *order*, about which adapter renders which
# `$id`, or about the bytes on disk. A published `$id` is a permanent contract
# and the eleven Stage 3 and nine Stage 4 entries are frozen output, so the
# assertions below pin the ordered tuples, the per-entry adapter, and the on-disk
# bytes as well. Stage 5 (plan section 2.7) appends its seven entries at positions
# 20-26 and reorders nothing.

_RENDER_MODES: Final[tuple[JsonSchemaMode, ...]] = ("validation", "serialization")

_STAGE3_PATHS: Final = (
    "domain/instrument-ref-v1.schema.json",
    "domain/money-v1.schema.json",
    "domain/price-v1.schema.json",
    "domain/quantity-v1.schema.json",
    "domain/diagnostic-v1.schema.json",
    "configuration/application-config-v1.schema.json",
    "datasets/dataset-partition-v1.schema.json",
    "datasets/dataset-descriptor-v1.schema.json",
    "protocol/engine-descriptor-v1.schema.json",
    "protocol/adapter-descriptor-v1.schema.json",
    "artifacts/artifact-owner-ref-v1.schema.json",
)

_STAGE4_PATHS: Final = (
    "strategy/strategy-spec-v1.schema.json",
    "strategy/strategy-version-v1.schema.json",
    "strategy/expression-v1.schema.json",
    "capabilities/capability-requirement-v1.schema.json",
    "capabilities/capability-declaration-v1.schema.json",
    "capabilities/approximation-declaration-v1.schema.json",
    "capabilities/compatibility-result-v1.schema.json",
    "capabilities/runtime-availability-observation-v1.schema.json",
    "capabilities/comparison-eligibility-result-v1.schema.json",
)

#: Stage 5 plan Task 9: the seven experiments entries, appended in this order at
#: positions 20-26. Every path is a new lexical descendant of `schemas/experiments/`
#: and every identifier is a new permanent `urn:crypto-lab:schema:experiments:*`.
_STAGE5_PATHS: Final = (
    "experiments/experiment-spec-v1.schema.json",
    "experiments/experiment-record-v1.schema.json",
    "experiments/engine-run-record-v1.schema.json",
    "experiments/command-invocation-record-v1.schema.json",
    "experiments/retry-policy-v1.schema.json",
    "experiments/retry-decision-record-v1.schema.json",
    "experiments/experiment-aggregation-result-v1.schema.json",
)

# Two entries register a module-level adapter singleton rather than a fresh
# `TypeAdapter`, so identity is the exact assertion for them and the adapted
# type is the exact assertion for the other twenty-five. Stage 5 adds no singleton.
_EXPECTED_ADAPTER_SINGLETONS: Final = {
    "artifacts/artifact-owner-ref-v1.schema.json": ARTIFACT_OWNER_ADAPTER,
    "strategy/expression-v1.schema.json": EXPRESSION_ADAPTER,
}

_EXPECTED_ADAPTED_TYPES: Final = {
    "domain/instrument-ref-v1.schema.json": InstrumentRef,
    "domain/money-v1.schema.json": Money,
    "domain/price-v1.schema.json": Price,
    "domain/quantity-v1.schema.json": Quantity,
    "domain/diagnostic-v1.schema.json": Diagnostic,
    "configuration/application-config-v1.schema.json": ApplicationConfig,
    "datasets/dataset-partition-v1.schema.json": DatasetPartition,
    "datasets/dataset-descriptor-v1.schema.json": DatasetDescriptor,
    "protocol/engine-descriptor-v1.schema.json": EngineDescriptor,
    "protocol/adapter-descriptor-v1.schema.json": AdapterDescriptor,
    "strategy/strategy-spec-v1.schema.json": StrategySpec,
    "strategy/strategy-version-v1.schema.json": StrategyVersion,
    "capabilities/capability-requirement-v1.schema.json": CapabilityRequirement,
    "capabilities/capability-declaration-v1.schema.json": CapabilityDeclaration,
    "capabilities/approximation-declaration-v1.schema.json": ApproximationDeclaration,
    "capabilities/compatibility-result-v1.schema.json": CompatibilityResult,
    "capabilities/runtime-availability-observation-v1.schema.json": (
        RuntimeAvailabilityObservation
    ),
    "capabilities/comparison-eligibility-result-v1.schema.json": (
        ComparisonEligibilityResult
    ),
    "experiments/experiment-spec-v1.schema.json": ExperimentSpec,
    "experiments/experiment-record-v1.schema.json": ExperimentRecord,
    "experiments/engine-run-record-v1.schema.json": EngineRunRecord,
    "experiments/command-invocation-record-v1.schema.json": CommandInvocationRecord,
    "experiments/retry-policy-v1.schema.json": RetryPolicy,
    "experiments/retry-decision-record-v1.schema.json": RetryDecisionRecord,
    "experiments/experiment-aggregation-result-v1.schema.json": (
        ExperimentAggregationResult
    ),
}

_EXPRESSION_OPERATORS: Final = (
    "add",
    "and",
    "crosses_above",
    "crosses_below",
    "divide",
    "equal",
    "greater_than",
    "greater_than_or_equal",
    "is_missing",
    "less_than",
    "less_than_or_equal",
    "literal",
    "maximum",
    "minimum",
    "multiply",
    "negate",
    "not",
    "not_equal",
    "or",
    "ref",
    "subtract",
)

# Published `uniqueItems`, partitioned by what the runtime rule actually is.
# Both halves are pinned by exact pointer rather than by field name, because
# `reasons`, `approximations`, and `declared_differences` each name a
# whole-value collection on one record and a key-based one on another, so a
# name-keyed assertion could not tell the two apart.
#
# WHOLE-VALUE: the runtime accepts two items that differ anywhere, so
# `uniqueItems` expresses the rule exactly. Measured, not assumed: for each
# owning model a pair sharing the plausible narrower key but differing elsewhere
# is accepted by the runtime.
_WHOLE_VALUE_UNIQUE_POINTERS: Final[tuple[tuple[str, str], ...]] = (
    (
        "strategy/strategy-spec-v1.schema.json",
        "/$defs/CapabilityRequirement/properties/comparison_levels",
    ),
    ("strategy/strategy-spec-v1.schema.json", "/$defs/Universe/properties/instruments"),
    (
        "strategy/strategy-version-v1.schema.json",
        "/$defs/CapabilityRequirement/properties/comparison_levels",
    ),
    (
        "strategy/strategy-version-v1.schema.json",
        "/$defs/Universe/properties/instruments",
    ),
    (
        "capabilities/capability-requirement-v1.schema.json",
        "/properties/comparison_levels",
    ),
    ("capabilities/capability-declaration-v1.schema.json", "/properties/limitations"),
    (
        "capabilities/approximation-declaration-v1.schema.json",
        "/properties/prevented_comparison_levels",
    ),
    (
        "capabilities/compatibility-result-v1.schema.json",
        "/$defs/ApproximationDeclaration/properties/prevented_comparison_levels",
    ),
    ("capabilities/compatibility-result-v1.schema.json", "/properties/reasons"),
    (
        "capabilities/comparison-eligibility-result-v1.schema.json",
        "/$defs/ApproximationDeclaration/properties/prevented_comparison_levels",
    ),
    (
        "capabilities/comparison-eligibility-result-v1.schema.json",
        "/properties/declared_differences",
    ),
    (
        "capabilities/comparison-eligibility-result-v1.schema.json",
        "/properties/reasons",
    ),
)

# KEY-BASED: the runtime deduplicates on a designated key, so `uniqueItems` is a
# sound but partial tightening -- it rejects an exact repeat and lets a
# key-colliding pair through. Recorded rather than claimed exact.
_KEY_BASED_UNIQUE_POINTERS: Final[tuple[tuple[str, str], ...]] = (
    ("capabilities/compatibility-result-v1.schema.json", "/properties/approximations"),
    (
        "capabilities/comparison-eligibility-result-v1.schema.json",
        "/$defs/ComparisonInput/properties/approximations",
    ),
    (
        "capabilities/comparison-eligibility-result-v1.schema.json",
        "/$defs/ComparisonInput/properties/assumptions",
    ),
    (
        "capabilities/comparison-eligibility-result-v1.schema.json",
        "/$defs/ComparisonInput/properties/declared_differences",
    ),
)


def _ordered_paths() -> tuple[str, ...]:
    return tuple(
        definition.relative_path.as_posix() for definition in SCHEMA_DEFINITIONS
    )


def _resolve_pointer(document: dict[str, Any], pointer: str) -> dict[str, Any]:
    """Resolve a `/`-separated pointer, so a position can be pinned exactly."""
    target: Any = document
    for token in pointer.split("/"):
        if token == "":
            continue
        target = target[int(token)] if isinstance(target, list) else target[token]
    if not isinstance(target, dict):
        raise AssertionError(f"pointer does not name a subschema: {pointer}")
    return cast(dict[str, Any], target)


def test_the_eleven_stage_three_entries_keep_their_original_leading_order() -> None:
    """Stage 4 appends; it never reorders frozen output."""
    assert _ordered_paths()[:11] == _STAGE3_PATHS
    assert tuple(
        definition.schema_id for definition in SCHEMA_DEFINITIONS[:11]
    ) == tuple(_EXPECTED[PurePosixPath(name)] for name in _STAGE3_PATHS)


def test_the_nine_stage_four_entries_are_appended_in_the_approved_order() -> None:
    """Stage 5 appends after them; positions 11-19 stay exactly the Stage 4 nine."""
    assert _ordered_paths()[11:20] == _STAGE4_PATHS
    assert len(_STAGE4_PATHS) == 9


def test_the_seven_stage_five_entries_are_appended_in_the_approved_order() -> None:
    """Stage 5 plan Task 9: positions 20-26, in the plan's order, and nothing after."""
    assert _ordered_paths()[20:] == _STAGE5_PATHS
    assert len(_STAGE5_PATHS) == 7
    assert tuple(
        definition.schema_id for definition in SCHEMA_DEFINITIONS[20:]
    ) == tuple(_EXPECTED[PurePosixPath(name)] for name in _STAGE5_PATHS)
    assert all(name.startswith("experiments/") for name in _STAGE5_PATHS)
    assert all(
        _EXPECTED[PurePosixPath(name)].startswith("urn:crypto-lab:schema:experiments:")
        for name in _STAGE5_PATHS
    )


def test_the_ordered_path_and_identifier_tuples_are_exact_and_unique() -> None:
    paths = _ordered_paths()
    identifiers = tuple(definition.schema_id for definition in SCHEMA_DEFINITIONS)
    assert paths == _STAGE3_PATHS + _STAGE4_PATHS + _STAGE5_PATHS
    assert identifiers == tuple(
        _EXPECTED[PurePosixPath(name)]
        for name in _STAGE3_PATHS + _STAGE4_PATHS + _STAGE5_PATHS
    )
    assert len(paths) == 27
    assert len(set(paths)) == 27
    assert len(set(identifiers)) == 27


def test_every_registry_entry_carries_its_exact_adapter() -> None:
    assert len(_EXPECTED_ADAPTER_SINGLETONS) + len(_EXPECTED_ADAPTED_TYPES) == 27
    assert not any(name in _EXPECTED_ADAPTER_SINGLETONS for name in _STAGE5_PATHS)
    for definition in SCHEMA_DEFINITIONS:
        name = definition.relative_path.as_posix()
        singleton = _EXPECTED_ADAPTER_SINGLETONS.get(name)
        if singleton is not None:
            assert definition.adapter is singleton, name
            continue
        assert isinstance(definition.adapter, TypeAdapter), name
        assert definition.adapter._type is _EXPECTED_ADAPTED_TYPES[name], name


def test_every_rendered_schema_equals_its_committed_generated_file() -> None:
    """Generated bytes are reviewed source, so the file is the contract."""
    rendered = render_schema_files()
    root = _REPOSITORY_ROOT / "schemas"
    assert len(rendered) == 27
    for path, contents in rendered.items():
        target = root.joinpath(*path.parts)
        assert target.is_file(), path
        assert target.read_bytes() == contents, path


def test_the_schemas_directory_holds_exactly_the_twenty_seven_registered_files() -> (
    None
):
    """Two directions: every registered file exists, and no unregistered file does."""
    root = _REPOSITORY_ROOT / "schemas"
    found = tuple(
        sorted(
            candidate.relative_to(root).as_posix()
            for candidate in root.rglob("*")
            if candidate.is_file()
        )
    )
    assert found == tuple(sorted(_STAGE3_PATHS + _STAGE4_PATHS + _STAGE5_PATHS))
    assert len(found) == 27


def test_every_committed_schema_file_is_valid_draft_2020_12_json() -> None:
    root = _REPOSITORY_ROOT / "schemas"
    for name in _STAGE3_PATHS + _STAGE4_PATHS + _STAGE5_PATHS:
        document = json.loads((root / name).read_bytes())
        assert isinstance(document, dict), name
        assert document["$schema"] == JSON_SCHEMA_DRAFT, name
        assert document["$id"] == _EXPECTED[PurePosixPath(name)], name
        Draft202012Validator.check_schema(document)


def test_no_schema_publishes_an_implementation_only_value() -> None:
    """`mappingproxy` is the exact leak an immutable-mapping serializer risks."""
    for path, contents in render_schema_files().items():
        assert b"mappingproxy" not in contents, path
        assert b"MappingProxyType" not in contents, path


def test_the_expression_schema_is_rooted_at_the_recursive_dispatcher() -> None:
    """The closed 21-member contract itself is pinned against the published bytes.

    It moved to the "published expression dispatcher" section at the end of this
    module when the recursive `oneOf` projection was replaced by Draft 2020-12
    conditional dispatch: the shape is now a 21-clause `allOf`, and asserting it
    against the reviewed file rather than against the live render is what makes
    the assertion about what ships.
    """
    document = _committed_schemas()[PurePosixPath("strategy/expression-v1.schema.json")]
    assert document["$ref"] == "#/$defs/Expression"
    assert "oneOf" not in document["$defs"]["Expression"]


def _published_unique_items_pointers() -> tuple[tuple[str, str], ...]:
    """Every published Stage 4 position that carries `uniqueItems: true`."""
    found: list[tuple[str, str]] = []

    def walk(node: object, name: str, pointer: str) -> None:
        if isinstance(node, dict):
            if node.get("uniqueItems") is True:
                found.append((name, pointer))
            for key, value in node.items():
                walk(value, name, f"{pointer}/{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, name, f"{pointer}/{index}")

    documents = _committed_schemas()
    for name in _STAGE4_PATHS:
        walk(documents[PurePosixPath(name)], name, "")
    return tuple(found)


def test_every_whole_value_uniqueness_field_publishes_unique_items() -> None:
    """The twelve positions where `uniqueItems` is the exact runtime rule."""
    documents = _committed_schemas()
    for name, pointer in _WHOLE_VALUE_UNIQUE_POINTERS:
        node = _resolve_pointer(documents[PurePosixPath(name)], pointer)
        assert node["type"] == "array", (name, pointer)
        assert node["uniqueItems"] is True, (name, pointer)
    assert len(_WHOLE_VALUE_UNIQUE_POINTERS) == 12
    assert len(set(_WHOLE_VALUE_UNIQUE_POINTERS)) == 12


def test_the_key_based_collections_publish_only_a_partial_tightening() -> None:
    """The four positions where the runtime key is narrower than the whole item.

    Pinned rather than omitted: the register in `docs/development/verification.md`
    states that these four are a sound partial tightening rather than an exact
    encoding, and a silent move between the two halves would make that register
    wrong without failing anything.
    """
    documents = _committed_schemas()
    for name, pointer in _KEY_BASED_UNIQUE_POINTERS:
        node = _resolve_pointer(documents[PurePosixPath(name)], pointer)
        assert node["type"] == "array", (name, pointer)
        assert node["uniqueItems"] is True, (name, pointer)
    assert len(_KEY_BASED_UNIQUE_POINTERS) == 4


def test_comparison_input_publishes_its_key_uniqueness_exactly() -> None:
    """`contains`/`minContains`/`maxContains` over a closed enum, per key.

    This is the one place a key-based rule *is* published exactly, and nothing
    else asserted it. Both key domains are closed fourteen-member enums, so one
    clause per member is an exact encoding rather than an approximation:
    `assumptions` is total at exactly one entry per material, and
    `declared_differences` admits at most one per category. `uniqueItems` at
    these two positions is therefore redundant reinforcement, not the
    enforcement mechanism -- which is why deleting these clauses must fail here.
    """
    document = _committed("capabilities/comparison-eligibility-result-v1.schema.json")
    definitions = document["$defs"]
    materials = definitions["ComparisonMaterial"]["enum"]
    categories = definitions["DifferenceCategory"]["enum"]
    assert len(materials) == 14
    assert len(categories) == 14

    clauses = definitions["ComparisonInput"]["allOf"]
    expectations = {
        "assumptions": ("material", materials, 1),
        "declared_differences": ("category", categories, 0),
    }
    seen: dict[str, list[str]] = {}
    for clause in clauses:
        for field, (key, _, minimum) in expectations.items():
            node = clause.get("properties", {}).get(field)
            if node is None:
                continue
            for inner in node["allOf"]:
                assert inner["minContains"] == minimum, (field, inner)
                assert inner["maxContains"] == 1, (field, inner)
                condition = inner["contains"]
                assert condition["required"] == [key], (field, condition)
                seen.setdefault(field, []).append(condition["properties"][key]["const"])

    for field, (_, values, _) in expectations.items():
        assert seen[field] == list(values), field
        assert len(seen[field]) == 14, field

    # Behavioural, against the shipped bytes: the exact encoding must actually
    # reject a key collision and accept the legal baseline.
    validator = _validator("capabilities/comparison-eligibility-result-v1.schema.json")
    side: dict[str, Any] = {
        "schema_version": "1.0.0",
        "comparison_level": "LEVEL_1",
        "engine_name": "engine.alpha",
        "engine_version": "1.0.0",
        "adapter_name": "adapter.alpha",
        "adapter_version": "1.0.0",
        "canonical_schema_version": "1.0.0",
        "methodology_version": "1.0.0",
        "strategy_version_hash": "a" * 64,
        "dataset_version_hash": "b" * 64,
        "assumptions": [
            {"material": material, "value_hash": f"{index:064d}"}
            for index, material in enumerate(materials)
        ],
        "approximations": [],
        "declared_differences": [],
    }
    baseline: dict[str, Any] = {
        "schema_version": "1.0.0",
        "outcome": "ELIGIBLE",
        "requested_level": "LEVEL_1",
        "achieved_level": "LEVEL_1",
        "left": side,
        "right": side,
        "reasons": [],
        "declared_differences": [],
    }
    validator.validate(baseline)

    collided = json.loads(json.dumps(side))
    collided["assumptions"][-1]["material"] = materials[0]
    _rejects(
        validator,
        {**baseline, "left": collided},
        "two assumptions naming the same material",
    )

    duplicated_category = json.loads(json.dumps(side))
    duplicated_category["declared_differences"] = [
        {"category": categories[0], "detail": "One bar later."},
        {"category": categories[0], "detail": "Two bars later."},
    ]
    _rejects(
        validator,
        {**baseline, "left": duplicated_category},
        "two side differences in the same category",
    )


def test_the_two_uniqueness_halves_are_exactly_the_published_census() -> None:
    """Closure: no published `uniqueItems` position is unclassified."""
    published = _published_unique_items_pointers()
    classified = _WHOLE_VALUE_UNIQUE_POINTERS + _KEY_BASED_UNIQUE_POINTERS

    assert len(published) == 16
    assert set(published) == set(classified)
    assert len(set(classified)) == 16
    assert not set(_WHOLE_VALUE_UNIQUE_POINTERS) & set(_KEY_BASED_UNIQUE_POINTERS)


def test_bars_ago_carries_its_exact_bounds_everywhere_it_propagates() -> None:
    documents = _committed_schemas()
    reached = 0
    for name in _STAGE4_PATHS:
        node = documents[PurePosixPath(name)].get("$defs", {}).get("RefExpression")
        if node is None:
            continue
        assert node["properties"]["bars_ago"] == {
            "maximum": 4096,
            "minimum": 0,
            "title": "Bars Ago",
            "type": "integer",
        }, name
        reached += 1
    assert reached == 3


def test_executable_path_publishes_the_exact_reviewed_pattern() -> None:
    documents = _committed_schemas()
    observation = documents[
        PurePosixPath("capabilities/runtime-availability-observation-v1.schema.json")
    ]
    node = observation["properties"]["executable_path"]
    # The reviewed source constant ends with `$`; `exact_string_schema` replaces
    # that with the project's absolute `(?![\s\S])` ending, so the published
    # pattern is asserted against the projection rather than the raw constant.
    assert node == {
        **exact_string_schema(
            _EXECUTABLE_PATH_SCHEMA_PATTERN,
            min_length=1,
            max_length=MAX_EXECUTABLE_PATH_CHARACTERS,
        ),
        "title": "Executable Path",
    }
    assert MAX_EXECUTABLE_PATH_CHARACTERS == 1024
    assert node["pattern"].endswith(r"(?![\s\S])")
    assert not node["pattern"].endswith("$")
    validator = Draft202012Validator(node)
    validator.validate(r"C:\adapters\adapter.exe")
    for invalid in (" leading", "trailing ", "inner\ttab", "\u00a0nbsp", ""):
        with pytest.raises(JsonSchemaValidationError):
            validator.validate(invalid)


def test_the_strategy_mapping_fields_keep_their_published_bounds() -> None:
    """Rendered in `mode="serialization"`, where a serializer can drop a bound.

    Asserted against the committed bytes of **both** carriers, and against the
    live render, because a mapping bound can be lost at three different points:
    in the model, in the render, or between the render and the file. The
    `StrategySpec` root moves between the two carriers -- it is the document root
    in `strategy-spec-v1` and a `$defs` entry in `strategy-version-v1` -- so the
    assertion follows it rather than assuming one shape.
    """
    identifier = {"$ref": "#/$defs/NormalizedIdentifier"}
    live = _schemas()
    sources: list[tuple[str, dict[str, Any]]] = []
    for carrier in (
        "strategy/strategy-spec-v1.schema.json",
        "strategy/strategy-version-v1.schema.json",
    ):
        for label, document in (
            (f"{carrier} on disk", _committed(carrier)),
            (f"{carrier} live render", live[PurePosixPath(carrier)]),
        ):
            definitions = document["$defs"]
            spec = definitions.get("StrategySpec", document)
            sources.append((label, spec))
            sources.append((f"{label} feature", definitions["FeatureDefinition"]))

    assert len(sources) == 8
    for label, node in sources:
        parameters = node["properties"]["parameters"]
        assert parameters["type"] == "object", label
        assert parameters["propertyNames"] == identifier, label
        if label.endswith("feature"):
            assert parameters["maxProperties"] == MAX_FEATURE_PARAMETERS, label
            assert parameters["additionalProperties"] == identifier, label
        else:
            assert parameters["maxProperties"] == MAX_PARAMETERS, label
            assert parameters["additionalProperties"] == {
                "$ref": "#/$defs/ParameterDefinition"
            }, label
    assert MAX_PARAMETERS == 128
    assert MAX_FEATURE_PARAMETERS == 32


def test_the_forward_utc_view_propagates_identically_through_every_container() -> None:
    """Item 21: the calendar and clock branches are the same bytes everywhere.

    The branch grammars themselves are proven exhaustively in
    `tests/unit/domain/test_time.py`; what this pins is that every published
    Stage 4 container renders the *same* view rather than a per-schema variant,
    and that no Stage 4 schema keeps the permissive legacy definition.
    """
    documents = _committed_schemas()
    renderings: set[str] = set()
    carriers: list[str] = []
    for name in _STAGE4_PATHS:
        definitions = documents[PurePosixPath(name)].get("$defs", {})
        assert "UtcDateTime" not in definitions, name
        view = definitions.get("CalendarValidUtcDateTime")
        if view is None:
            continue
        assert len(view["allOf"]) == 3, name
        assert view["allOf"][0]["format"] == "date-time", name
        renderings.add(json.dumps(view, sort_keys=True))
        carriers.append(name)
    assert carriers == [
        "strategy/strategy-spec-v1.schema.json",
        "strategy/strategy-version-v1.schema.json",
        "capabilities/runtime-availability-observation-v1.schema.json",
    ]
    assert len(renderings) == 1


def test_the_internal_bar_model_is_not_published_as_a_canonical_schema() -> None:
    """`Bar.timestamp_utc` stays on the legacy alias, and this is why.

    The forward-view rule is scoped to *published* Stage 4 schemas. `Bar` is a
    Stage 4 model with no registry entry, no permanent `$id`, and no position in
    the reachable `$defs` graph of any registered adapter, so it publishes
    nothing to be wrong about. If it is ever registered this test fails first,
    and `test_every_published_stage_four_timestamp_uses_the_forward_view` in
    `tests/unit/domain/test_time.py` then forces an explicit timestamp decision
    rather than letting the permissive grammar reach a new `$id`.
    """
    # Every entry, singleton adapters included: a singleton rooted at `Bar` would
    # publish it inline rather than in `$defs`, so the second half below would
    # not see it. That is the root-registration leg, and it is closed here.
    for definition in SCHEMA_DEFINITIONS:
        assert definition.adapter._type is not Bar, definition.schema_id

    published: set[str] = set()
    for definition in SCHEMA_DEFINITIONS:
        for mode in _RENDER_MODES:
            schema = definition.adapter.json_schema(mode=mode)
            published |= set(schema.get("$defs", {}))
    # Non-vacuity: the walk must demonstrably reach the Stage 4 graph, or the
    # four absences below would be satisfied by an empty set.
    assert {
        "StrategySpec",
        "FeatureDefinition",
        "RefExpression",
        "CalendarValidUtcDateTime",
        "ComparisonInput",
    } <= published
    for unpublished in ("Bar", "EvaluationResult", "FeatureSeries", "SignalSeries"):
        assert unpublished not in published, unpublished


# --- Task 8: runtime and published contract agree on real documents ------------
#
# Every assertion below validates against the **committed bytes on disk**, not
# against `render_schema_files()`, because the file is what ships in the wheel
# and the sdist. Each negative is paired with an accepting baseline, so a
# rejection can never be an artifact of an already-invalid document.

_COMMITTED_ROOT = _REPOSITORY_ROOT / "schemas"
_STRATEGY_FIXTURES = _REPOSITORY_ROOT / "tests" / "fixtures" / "strategy"
_OBSERVED_AT = datetime(2026, 8, 18, 12, 0, 0, tzinfo=UTC)
_UUID_TAIL = "12345678-1234-4234-8234-123456789abc"


def _committed(name: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((_COMMITTED_ROOT / name).read_bytes()))


def _validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(_committed(name))


def _rejects(validator: Draft202012Validator, document: object, label: str) -> None:
    assert not validator.is_valid(document), label


def test_every_committed_valid_strategy_fixture_is_accepted_on_disk() -> None:
    """Nine golden inputs, through the loader, against the shipped bytes."""
    version_validator = _validator("strategy/strategy-version-v1.schema.json")
    spec_validator = _validator("strategy/strategy-spec-v1.schema.json")
    expression_validator = _validator("strategy/expression-v1.schema.json")

    sources = sorted(_STRATEGY_FIXTURES.glob("*.yaml"))
    assert len(sources) == 9
    per_fixture: dict[str, int] = {}
    for source in sources:
        outcome = StrategyLoader.load(source.read_bytes(), source.name, _OBSERVED_AT)
        assert isinstance(outcome, Success), (source.name, outcome)
        version = outcome.value
        document = version.model_dump(mode="json")
        version_validator.validate(document)
        spec_validator.validate(document["strategy_spec"])
        validated = 0
        for block in ("entry_rules", "exit_rules"):
            for rule in document["strategy_spec"][block]:
                expression_validator.validate(rule["expression"])
                validated += 1
        per_fixture[source.name] = validated
    # Exact rather than a lower bound: `>=` would still pass if a fixture lost
    # its exit rule, which is exactly the regression this is here to catch.
    assert per_fixture == {
        "adjacent_entry_exit.valid.yaml": 2,
        "bar_offsets.valid.yaml": 2,
        "crossover_equality.valid.yaml": 2,
        "decimal_rounding.valid.yaml": 2,
        "missing_input.valid.yaml": 2,
        "sma_cross_long.commented.yaml": 2,
        "sma_cross_long.reordered_keys.yaml": 2,
        "sma_cross_long.valid.yaml": 2,
        "warm_up_boundary.valid.yaml": 2,
    }
    assert sum(per_fixture.values()) == 18


def _valid_spec_document() -> dict[str, Any]:
    source = _STRATEGY_FIXTURES / "sma_cross_long.valid.yaml"
    outcome = StrategyLoader.load(source.read_bytes(), source.name, _OBSERVED_AT)
    assert isinstance(outcome, Success), outcome
    return cast(dict[str, Any], outcome.value.model_dump(mode="json")["strategy_spec"])


def _replaced(document: dict[str, Any], pointer: str, value: Any) -> dict[str, Any]:
    """A deep copy of `document` with one dotted path replaced."""
    clone = cast(dict[str, Any], json.loads(json.dumps(document)))
    target: Any = clone
    tokens = pointer.split(".")
    for token in tokens[:-1]:
        target = target[int(token)] if token.isdigit() else target[token]
    last = tokens[-1]
    target[int(last) if last.isdigit() else last] = value
    return clone


def test_the_committed_strategy_spec_schema_rejects_every_expressible_violation() -> (
    None
):
    validator = _validator("strategy/strategy-spec-v1.schema.json")
    baseline = _valid_spec_document()
    validator.validate(baseline)

    instrument = baseline["universe"]["instruments"][0]
    identifier_rule = {"op": "ref", "id": "close", "bars_ago": 0}
    violations: tuple[tuple[str, dict[str, Any]], ...] = (
        ("market_type widened", _replaced(baseline, "market_type", "FUTURES")),
        ("direction widened", _replaced(baseline, "direction", "SHORT")),
        (
            "leverage above one",
            _replaced(baseline, "risk_assumptions.leverage", "2"),
        ),
        (
            "shorting enabled",
            _replaced(baseline, "risk_assumptions.shorting_allowed", True),
        ),
        (
            "approximation default widened",
            _replaced(
                baseline,
                "supported_approximation_policy.default",
                "ALLOW_DECLARED",
            ),
        ),
        ("schema version drift", _replaced(baseline, "schema_version", "1.0.1")),
        (
            "impossible calendar date",
            _replaced(
                baseline, "authoring_metadata.created_at_utc", "2026-02-30T00:00:00Z"
            ),
        ),
        (
            "hour twenty-four",
            _replaced(
                baseline, "authoring_metadata.created_at_utc", "2026-01-01T24:00:00Z"
            ),
        ),
        (
            "minute sixty",
            _replaced(
                baseline, "authoring_metadata.created_at_utc", "2026-01-01T00:60:00Z"
            ),
        ),
        (
            "leap second",
            _replaced(
                baseline, "authoring_metadata.created_at_utc", "2026-01-01T00:00:60Z"
            ),
        ),
        (
            "year zero",
            _replaced(
                baseline, "authoring_metadata.created_at_utc", "0000-01-01T00:00:00Z"
            ),
        ),
        (
            "non-leap February 29",
            _replaced(
                baseline, "authoring_metadata.created_at_utc", "2100-02-29T00:00:00Z"
            ),
        ),
        (
            "duplicate instrument",
            _replaced(baseline, "universe.instruments", [instrument, instrument]),
        ),
        (
            "empty universe",
            _replaced(baseline, "universe.instruments", []),
        ),
        ("unexpected field", {**baseline, "unexpected": True}),
        (
            "sizing fraction above one",
            _replaced(baseline, "sizing_intent.fraction", "1.5"),
        ),
        ("timeframe zero", _replaced(baseline, "timeframe", "0m")),
        (
            "comparison level outside the enum",
            _replaced(baseline, "comparison_requirements.maximum_level", "LEVEL_4"),
        ),
        (
            "parameter key not normalized",
            _replaced(
                baseline,
                "parameters",
                {"Fast_Period": {"value_type": "INTEGER", "value": 5}},
            ),
        ),
        (
            "parameter type disagreement",
            _replaced(
                baseline,
                "parameters",
                {"fast_period": {"value_type": "INTEGER", "value": "five"}},
            ),
        ),
        (
            "bounds on a non-numeric parameter",
            _replaced(
                baseline,
                "parameters",
                {
                    "label": {
                        "value_type": "STRING",
                        "value": "x",
                        "minimum": "a",
                    }
                },
            ),
        ),
        (
            "unknown expression operator",
            _replaced(
                baseline,
                "entry_rules.0.expression",
                {"op": "unknown_op", "left": identifier_rule, "right": identifier_rule},
            ),
        ),
        (
            "negative bar offset",
            _replaced(
                baseline,
                "entry_rules.0.expression",
                {"op": "ref", "id": "close", "bars_ago": -1},
            ),
        ),
        (
            "bar offset above the bound",
            _replaced(
                baseline,
                "entry_rules.0.expression",
                {"op": "ref", "id": "close", "bars_ago": 4097},
            ),
        ),
        ("no entry rule", _replaced(baseline, "entry_rules", [])),
        (
            "lifecycle-only extension claiming an economic effect",
            _replaced(
                baseline,
                "engine_extensions",
                [
                    {
                        "adapter_name": "adapter.alpha",
                        "extension_id": "ext.alpha",
                        "version": "1.0.0",
                        "content_hash": "a" * 64,
                        "purpose": "fixture",
                        "lifecycle_effect": "LIFECYCLE_HOOKS_ONLY",
                        "economic_effect": "PREVENTS_LEVEL_2",
                    }
                ],
            ),
        ),
    )
    for label, document in violations:
        _rejects(validator, document, label)
    assert len(violations) == 26

    # Over-rejection guard: every real instant the runtime accepts must pass.
    for accepted in (
        "0001-01-01T00:00:00Z",
        "0004-02-29T00:00:00Z",
        "2000-02-29T12:00:00Z",
        "2024-02-29T23:59:59Z",
        "2026-12-31T23:59:59.123456Z",
        "9999-12-31T23:59:59Z",
    ):
        validator.validate(
            _replaced(baseline, "authoring_metadata.created_at_utc", accepted)
        )


def test_the_committed_capability_schemas_publish_their_state_contracts() -> None:
    requirement = {
        "schema_version": "1.0.0",
        "capability": "market.spot",
        "required": True,
        "minimum_semantics": "capabilities/v1",
        "approximation_policy": "REJECT",
        "comparison_levels": ["LEVEL_1", "LEVEL_2"],
    }
    declaration = {
        "schema_version": "1.0.0",
        "capability": "market.spot",
        "support_kind": "NATIVE",
        "evidence_note": "Native spot support.",
        "limitations": ["Bar granularity only."],
    }
    approximation = {
        "schema_version": "1.0.0",
        "approximation_id": f"appx_{_UUID_TAIL}",
        "capability": "execution.partial_fills",
        "method": "Fills at the bar close.",
        "expected_impact": "Understates slippage.",
        "prevented_comparison_levels": ["LEVEL_1", "LEVEL_2"],
        "adapter_version": "1.0.0",
    }

    requirement_validator = _validator(
        "capabilities/capability-requirement-v1.schema.json"
    )
    declaration_validator = _validator(
        "capabilities/capability-declaration-v1.schema.json"
    )
    approximation_validator = _validator(
        "capabilities/approximation-declaration-v1.schema.json"
    )
    requirement_validator.validate(requirement)
    declaration_validator.validate(declaration)
    approximation_validator.validate(approximation)

    _rejects(
        requirement_validator,
        {**requirement, "comparison_levels": ["LEVEL_2", "LEVEL_1"]},
        "unsorted comparison levels",
    )
    _rejects(
        requirement_validator,
        {**requirement, "comparison_levels": ["LEVEL_1", "LEVEL_1"]},
        "duplicate comparison levels",
    )
    _rejects(
        requirement_validator,
        {**requirement, "minimum_semantics": "capabilities/v2"},
        "vocabulary version drift",
    )
    _rejects(
        declaration_validator,
        {**declaration, "limitations": ["same", "same"]},
        "duplicate limitations",
    )
    _rejects(
        declaration_validator,
        {**declaration, "support_kind": "PARTIAL"},
        "support kind outside the partition",
    )
    _rejects(
        approximation_validator,
        {**approximation, "prevented_comparison_levels": ["LEVEL_3", "LEVEL_1"]},
        "unsorted prevented levels",
    )

    observation = {
        "schema_version": "1.0.0",
        "availability_observation_id": f"avail_{_UUID_TAIL}",
        "adapter_name": "adapter.alpha",
        "adapter_version": "1.0.0",
        "executable_path": r"C:\adapters\adapter.exe",
        "executable_hash": "a" * 64,
        "runtime_version": "1.0.0",
        "operating_system": "WINDOWS",
        "available": True,
        "observed_at_utc": "2026-08-10T00:00:00Z",
        "expires_at_utc": "2026-08-11T00:00:00Z",
        "network_required": False,
        "credentials_required": False,
    }
    observation_validator = _validator(
        "capabilities/runtime-availability-observation-v1.schema.json"
    )
    observation_validator.validate(observation)
    observation_validator.validate(
        {
            **observation,
            "available": False,
            "reason_code": "CAPABILITY.RUNTIME_UNAVAILABLE",
        }
    )
    _rejects(
        observation_validator,
        {**observation, "reason_code": "CAPABILITY.RUNTIME_UNAVAILABLE"},
        "available observation carrying an unavailability code",
    )
    _rejects(
        observation_validator,
        {**observation, "available": False},
        "unavailable observation carrying no code",
    )
    for impossible in (
        "2026-02-30T00:00:00Z",
        "2026-01-01T24:00:00Z",
        "2026-01-01T00:60:00Z",
        "2026-01-01T00:00:60Z",
        "0000-01-01T00:00:00Z",
        "2100-02-29T00:00:00Z",
    ):
        _rejects(
            observation_validator,
            {**observation, "observed_at_utc": impossible},
            f"impossible instant {impossible}",
        )
    # The over-rejection half. A calendar tightening that rejects real instants
    # would satisfy every negative above, so the real edges are asserted too.
    for real in (
        "0004-02-29T00:00:00Z",
        "2000-02-29T23:59:59Z",
        "2024-02-29T00:00:00Z",
        "9999-12-31T23:59:59Z",
        "2026-08-10T00:00:00.123456Z",
        "0001-01-01T00:00:00Z",
    ):
        observation_validator.validate({**observation, "observed_at_utc": real})

    result = {
        "schema_version": "1.0.0",
        "outcome": "SUPPORTED",
        "capability_vocabulary_version": "capabilities/v1",
        "requested_comparison_level": "LEVEL_1",
        "adapter_name": "adapter.alpha",
        "adapter_version": "1.0.0",
        "availability_observation_id": f"avail_{_UUID_TAIL}",
        "reasons": [],
        "approximations": [],
    }
    scoped = {"error_code": "CAPABILITY.REQUIREMENT_UNMET", "capability": "market.spot"}
    unscoped = {"error_code": "CAPABILITY.RUNTIME_UNAVAILABLE"}
    result_validator = _validator("capabilities/compatibility-result-v1.schema.json")
    result_validator.validate(result)
    result_validator.validate(
        {
            **result,
            "outcome": "SUPPORTED_WITH_APPROXIMATION",
            "approximations": [approximation],
        }
    )
    result_validator.validate(
        {**result, "outcome": "UNAVAILABLE", "reasons": [unscoped]}
    )
    result_validator.validate(
        {**result, "outcome": "NOT_APPLICABLE", "reasons": [scoped]}
    )
    for label, document in (
        ("supported carrying a reason", {**result, "reasons": [unscoped]}),
        (
            "supported carrying an approximation",
            {**result, "approximations": [approximation]},
        ),
        (
            "approximated outcome with no approximation",
            {**result, "outcome": "SUPPORTED_WITH_APPROXIMATION"},
        ),
        ("unavailable outcome with no reason", {**result, "outcome": "UNAVAILABLE"}),
        (
            "not-applicable outcome with an approximation",
            {
                **result,
                "outcome": "NOT_APPLICABLE",
                "reasons": [scoped],
                "approximations": [approximation],
            },
        ),
        (
            "unscoped code carrying a scope",
            {
                **result,
                "outcome": "UNAVAILABLE",
                "reasons": [{**unscoped, "capability": "market.spot"}],
            },
        ),
        (
            "scoped code carrying no scope",
            {
                **result,
                "outcome": "NOT_APPLICABLE",
                "reasons": [{"error_code": "CAPABILITY.REQUIREMENT_UNMET"}],
            },
        ),
        (
            "error code outside the closed table",
            {
                **result,
                "outcome": "UNAVAILABLE",
                "reasons": [{"error_code": "CAPABILITY.INVENTED"}],
            },
        ),
        (
            "capability outside the vocabulary",
            {
                **result,
                "outcome": "NOT_APPLICABLE",
                "reasons": [{**scoped, "capability": "market.invented"}],
            },
        ),
    ):
        _rejects(result_validator, document, label)


def test_the_committed_eligibility_schema_publishes_its_state_contracts() -> None:
    materials = tuple(ComparisonMaterial)
    assert len(materials) == 14
    side: dict[str, Any] = {
        "schema_version": "1.0.0",
        "comparison_level": "LEVEL_1",
        "engine_name": "engine.alpha",
        "engine_version": "1.0.0",
        "adapter_name": "adapter.alpha",
        "adapter_version": "1.0.0",
        "canonical_schema_version": "1.0.0",
        "methodology_version": "1.0.0",
        "strategy_version_hash": "a" * 64,
        "dataset_version_hash": "b" * 64,
        "assumptions": [
            {"material": material.value, "value_hash": f"{index:064d}"}
            for index, material in enumerate(materials)
        ],
        "approximations": [],
        "declared_differences": [],
    }
    eligible: dict[str, Any] = {
        "schema_version": "1.0.0",
        "outcome": "ELIGIBLE",
        "requested_level": "LEVEL_1",
        "achieved_level": "LEVEL_1",
        "left": side,
        "right": side,
        "reasons": [],
        "declared_differences": [],
    }
    difference = {"category": "SIGNAL_TIMING", "detail": "One bar later."}
    validator = _validator("capabilities/comparison-eligibility-result-v1.schema.json")
    validator.validate(eligible)
    validator.validate(
        {
            **eligible,
            "outcome": "ELIGIBLE_WITH_DECLARED_DIFFERENCES",
            "declared_differences": [difference],
        }
    )
    ineligible = {
        key: value for key, value in eligible.items() if key != "achieved_level"
    }
    validator.validate(
        {
            **ineligible,
            "outcome": "INELIGIBLE",
            "reasons": [{"error_code": "COMPARISON.LEVEL_UNSUPPORTED"}],
        }
    )

    short_side = {
        **side,
        "assumptions": side["assumptions"][:-1],
    }
    duplicated_side = {
        **side,
        "assumptions": [
            side["assumptions"][0],
            *side["assumptions"][1:-1],
            side["assumptions"][0],
        ],
    }
    for label, document in (
        (
            "eligible carrying a reason",
            {
                **eligible,
                "reasons": [{"error_code": "COMPARISON.LEVEL_UNSUPPORTED"}],
            },
        ),
        ("eligible with no achieved level", {**ineligible, "outcome": "ELIGIBLE"}),
        (
            "ineligible carrying an achieved level",
            {
                **eligible,
                "outcome": "INELIGIBLE",
                "reasons": [{"error_code": "COMPARISON.LEVEL_UNSUPPORTED"}],
            },
        ),
        ("ineligible with no reason", {**ineligible, "outcome": "INELIGIBLE"}),
        (
            "achieved level below requested",
            {
                **eligible,
                "requested_level": "LEVEL_2",
                "achieved_level": "LEVEL_1",
            },
        ),
        (
            "eligible carrying a declared difference",
            {
                **eligible,
                "declared_differences": [difference],
            },
        ),
        (
            "declared-differences outcome with nothing declared",
            {
                **eligible,
                "outcome": "ELIGIBLE_WITH_DECLARED_DIFFERENCES",
            },
        ),
        ("incomplete assumption set", {**eligible, "left": short_side}),
        ("duplicated assumption material", {**eligible, "left": duplicated_side}),
        (
            "scoped reason carrying no material",
            {
                **ineligible,
                "outcome": "INELIGIBLE",
                "reasons": [{"error_code": "COMPARISON.ASSUMPTION_MISMATCH"}],
            },
        ),
        (
            "unscoped reason carrying a material",
            {
                **ineligible,
                "outcome": "INELIGIBLE",
                "reasons": [
                    {
                        "error_code": "COMPARISON.LEVEL_UNSUPPORTED",
                        "material": "UNIVERSE",
                    }
                ],
            },
        ),
        (
            "approximation-scoped reason carrying a material",
            {
                **ineligible,
                "outcome": "INELIGIBLE",
                "reasons": [
                    {
                        "error_code": "COMPARISON.APPROXIMATION_EXCLUDES_LEVEL",
                        "material": "UNIVERSE",
                    }
                ],
            },
        ),
        (
            "difference category outside the closed fourteen",
            {
                **eligible,
                "outcome": "ELIGIBLE_WITH_DECLARED_DIFFERENCES",
                "declared_differences": [{"category": "OTHER", "detail": "x"}],
            },
        ),
        ("unexpected field", {**eligible, "unexpected": True}),
    ):
        _rejects(validator, document, label)


# --- Task 8: the published expression dispatcher, at the file level ------------
#
# `tests/unit/strategy/test_strategy_expressions.py` pins this contract at the
# adapter level, in both render modes, against `canonical_json_bytes`. What is
# pinned here is the *published file*: the reviewed bytes that ship in the wheel
# and the sdist, after registry rendering, canonical key sorting, file
# generation, and re-parsing. Both levels are needed -- only the file level can
# catch a projection that survives the adapter and is then lost, and only the
# adapter level can catch a mode that is never published.
#
# The table below is restated rather than derived from the emitting hook, so a
# change to that hook cannot silently redefine the contract it is checked
# against. Its order is the union's own declaration order, which is also the
# order of the published `op` enum.

_EXPRESSION_DISPATCH_TABLE: Final[tuple[tuple[str, str], ...]] = (
    ("literal", "LiteralExpression"),
    ("ref", "RefExpression"),
    ("not", "NotExpression"),
    ("negate", "NegateExpression"),
    ("is_missing", "IsMissingExpression"),
    ("add", "AddExpression"),
    ("subtract", "SubtractExpression"),
    ("multiply", "MultiplyExpression"),
    ("divide", "DivideExpression"),
    ("minimum", "MinimumExpression"),
    ("maximum", "MaximumExpression"),
    ("equal", "EqualExpression"),
    ("not_equal", "NotEqualExpression"),
    ("less_than", "LessThanExpression"),
    ("less_than_or_equal", "LessThanOrEqualExpression"),
    ("greater_than", "GreaterThanExpression"),
    ("greater_than_or_equal", "GreaterThanOrEqualExpression"),
    ("crosses_above", "CrossesAboveExpression"),
    ("crosses_below", "CrossesBelowExpression"),
    ("and", "AndExpression"),
    ("or", "OrExpression"),
)
_EXPRESSION_DISPATCH_OPERATIONS: Final = tuple(
    operation for operation, _ in _EXPRESSION_DISPATCH_TABLE
)
_EXPRESSION_DISPATCH_REFERENCES: Final = tuple(
    f"#/$defs/{model}" for _, model in _EXPRESSION_DISPATCH_TABLE
)

# Every published file whose `$defs` carries the recursive dispatcher: the
# expression record itself plus the two strategy records that embed it.
_EXPRESSION_CARRIERS: Final = (
    "strategy/expression-v1.schema.json",
    "strategy/strategy-spec-v1.schema.json",
    "strategy/strategy-version-v1.schema.json",
)

# The four fields through which a node reaches a child expression. A condition
# that could see any of them would reintroduce the cost the old `oneOf` had.
_EXPRESSION_CHILD_FIELDS: Final = ("left", "right", "operand", "operands")

_EXPRESSION_LEAF: Final[dict[str, Any]] = {"op": "ref", "id": "close", "bars_ago": 0}

_EXPRESSION_VERDICTS: Final[tuple[tuple[str, dict[str, Any], bool], ...]] = (
    ("leaf reference", _EXPRESSION_LEAF, True),
    (
        "binary node",
        {"op": "add", "left": _EXPRESSION_LEAF, "right": _EXPRESSION_LEAF},
        True,
    ),
    ("unary node", {"op": "not", "operand": _EXPRESSION_LEAF}, True),
    ("variadic node", {"op": "and", "operands": [_EXPRESSION_LEAF]}, True),
    ("typed literal", {"op": "literal", "value_type": "INTEGER", "value": 3}, True),
    ("missing op", {"left": _EXPRESSION_LEAF, "right": _EXPRESSION_LEAF}, False),
    (
        "unknown op",
        {"op": "power", "left": _EXPRESSION_LEAF, "right": _EXPRESSION_LEAF},
        False,
    ),
    (
        "known op, unary shape on a binary node",
        {"op": "add", "operand": _EXPRESSION_LEAF},
        False,
    ),
    ("known op, missing right operand", {"op": "add", "left": _EXPRESSION_LEAF}, False),
    (
        "known op, binary shape on a unary node",
        {"op": "not", "left": _EXPRESSION_LEAF, "right": _EXPRESSION_LEAF},
        False,
    ),
    (
        "extra field on the selected branch",
        {**_EXPRESSION_LEAF, "unexpected": 1},
        False,
    ),
    (
        "another branch's field on the selected branch",
        {"op": "not", "operand": _EXPRESSION_LEAF, "bars_ago": 0},
        False,
    ),
    (
        "literal value disagreeing with its declared type",
        {"op": "literal", "value_type": "INTEGER", "value": "3"},
        False,
    ),
    ("empty operand list", {"op": "and", "operands": []}, False),
    ("invalid child two levels down", {"op": "not", "operand": {"op": "power"}}, False),
)


def _keys_anywhere(node: object) -> set[str]:
    """Every object key reachable from `node`, at any nesting level."""
    found: set[str] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            found.add(key)
            found |= _keys_anywhere(value)
    elif isinstance(node, list):
        for item in node:
            found |= _keys_anywhere(item)
    return found


def _dispatcher_of(carrier: str) -> dict[str, Any]:
    return cast(dict[str, Any], _committed(carrier)["$defs"]["Expression"])


def _embedded_expression_root(carrier: str) -> dict[str, Any]:
    """A derived root that reaches one carrier's own published dispatcher.

    `strategy-spec-v1` and `strategy-version-v1` are rooted at their record, so
    an expression node needs this indirection. The `$defs` block handed over is
    the carrier's own, unmodified, which is what keeps the result a statement
    about the published bytes rather than about a reconstruction.
    """
    document = _committed(carrier)
    return {
        "$schema": document["$schema"],
        "$defs": document["$defs"],
        "$ref": "#/$defs/Expression",
    }


@pytest.mark.parametrize("carrier", _EXPRESSION_CARRIERS)
def test_the_published_dispatcher_replaced_the_recursive_union(carrier: str) -> None:
    """Items 1-4, 6, 13: the exact published root shape, in every carrier."""
    dispatcher = _dispatcher_of(carrier)

    assert "oneOf" not in dispatcher, carrier
    assert "anyOf" not in dispatcher, carrier
    assert dispatcher["type"] == "object", carrier
    assert dispatcher["required"] == ["op"], carrier
    assert len(dispatcher["allOf"]) == 21, carrier
    # Closing the root would reject `left`, `right`, `operand`, and `operands`,
    # which the root never names; field closure belongs to each branch model.
    assert "additionalProperties" not in dispatcher, carrier
    assert set(dispatcher) == {
        "allOf",
        "discriminator",
        "properties",
        "required",
        "type",
    }, carrier


def test_the_published_operation_enum_is_the_closed_twenty_one_set() -> None:
    """Item 5, plus the sorted closure this module has always pinned."""
    assert len(_EXPRESSION_DISPATCH_TABLE) == 21
    assert tuple(sorted(_EXPRESSION_DISPATCH_OPERATIONS)) == _EXPRESSION_OPERATORS
    for carrier in _EXPRESSION_CARRIERS:
        properties = _dispatcher_of(carrier)["properties"]
        expected = {"op": {"enum": list(_EXPRESSION_DISPATCH_OPERATIONS)}}
        assert properties == expected, carrier
        assert len(set(properties["op"]["enum"])) == 21, carrier


@pytest.mark.parametrize("carrier", _EXPRESSION_CARRIERS)
def test_every_published_dispatch_condition_is_shallow(carrier: str) -> None:
    """Items 7, 8: the invariant that keeps the published bytes tractable.

    The whole `if` is pinned literally rather than merely checked for the absence
    of a `$ref`, because any keyword that could reach a child expression would
    restore exponential cost whether or not it spelled itself as a reference.
    """
    for clause, operation in zip(
        _dispatcher_of(carrier)["allOf"],
        _EXPRESSION_DISPATCH_OPERATIONS,
        strict=True,
    ):
        assert set(clause) == {"if", "then"}, (carrier, operation)
        condition = clause["if"]
        assert condition == {
            "properties": {"op": {"const": operation}},
            "required": ["op"],
        }, (carrier, operation)
        reachable = _keys_anywhere(condition)
        assert reachable == {"properties", "op", "const", "required"}, (
            carrier,
            operation,
        )
        for forbidden in ("$ref", "oneOf", "anyOf", *_EXPRESSION_CHILD_FIELDS):
            assert forbidden not in reachable, (carrier, operation, forbidden)


@pytest.mark.parametrize("carrier", _EXPRESSION_CARRIERS)
def test_the_published_dispatch_mapping_is_an_exact_bijection(carrier: str) -> None:
    """Items 9-12: one shallow condition and one recursive branch per operation."""
    definitions = _committed(carrier)["$defs"]
    clauses = _dispatcher_of(carrier)["allOf"]
    operations = [clause["if"]["properties"]["op"]["const"] for clause in clauses]
    branches = [clause["then"] for clause in clauses]
    references = [branch["$ref"] for branch in branches]

    assert operations == list(_EXPRESSION_DISPATCH_OPERATIONS), carrier
    assert len(set(operations)) == 21, carrier
    assert branches == [
        {"$ref": reference} for reference in _EXPRESSION_DISPATCH_REFERENCES
    ], carrier
    assert len(set(references)) == 21, carrier
    assert dict(zip(operations, references, strict=True)) == dict(
        zip(
            _EXPRESSION_DISPATCH_OPERATIONS,
            _EXPRESSION_DISPATCH_REFERENCES,
            strict=True,
        )
    ), carrier
    for operation, model in _EXPRESSION_DISPATCH_TABLE:
        branch = definitions[model]
        assert branch["type"] == "object", (carrier, model)
        assert branch["additionalProperties"] is False, (carrier, model)
        assert branch["properties"]["op"] == {
            "const": operation,
            "title": "Op",
            "type": "string",
        }, (carrier, operation)


@pytest.mark.parametrize("carrier", _EXPRESSION_CARRIERS)
def test_only_the_matching_branch_recurses_into_a_child(carrier: str) -> None:
    """The structural half of tractability: exactly one recursive descent.

    Every child carrier on every branch model points at the corrected dispatcher
    rather than at a copy, so a node is dispatched once per level instead of
    being offered to all twenty-one alternatives.
    """
    definitions = _committed(carrier)["$defs"]
    recursive_models = 0
    families: set[str] = set()
    for _, model in _EXPRESSION_DISPATCH_TABLE:
        properties = definitions[model]["properties"]
        present = [field for field in _EXPRESSION_CHILD_FIELDS if field in properties]
        if not present:
            continue
        recursive_models += 1
        families.add(",".join(present))
        for field in present:
            node = properties[field]
            target = node["items"] if field == "operands" else node
            assert target == {"$ref": "#/$defs/Expression"}, (carrier, model, field)
    # Non-vacuity: `literal` and `ref` are the only two leaf branches, and all
    # three recursive shape families must be represented.
    assert recursive_models == 19, carrier
    assert families == {"operand", "left,right", "operands"}, carrier


@pytest.mark.parametrize("carrier", _EXPRESSION_CARRIERS)
def test_the_published_discriminator_is_exact_and_not_load_bearing(
    carrier: str,
) -> None:
    """Items 14, 15: retained as a tooling annotation Draft 2020-12 ignores."""
    discriminator = _dispatcher_of(carrier)["discriminator"]

    assert discriminator["propertyName"] == "op", carrier
    assert discriminator["mapping"] == dict(
        zip(
            _EXPRESSION_DISPATCH_OPERATIONS,
            _EXPRESSION_DISPATCH_REFERENCES,
            strict=True,
        )
    ), carrier

    annotated_root = _embedded_expression_root(carrier)
    stripped_root = cast(dict[str, Any], json.loads(json.dumps(annotated_root)))
    del stripped_root["$defs"]["Expression"]["discriminator"]
    Draft202012Validator.check_schema(stripped_root)
    annotated = Draft202012Validator(annotated_root)
    unannotated = Draft202012Validator(stripped_root)
    for label, subject, _ in _EXPRESSION_VERDICTS:
        assert annotated.is_valid(subject) == unannotated.is_valid(subject), (
            carrier,
            label,
        )


@pytest.mark.parametrize("carrier", _EXPRESSION_CARRIERS)
def test_the_published_dispatcher_decides_every_representative_document(
    carrier: str,
) -> None:
    """Items 16-19, each rejection paired with an accepting baseline."""
    validator = Draft202012Validator(_embedded_expression_root(carrier))
    accepted = 0
    for label, subject, expected in _EXPRESSION_VERDICTS:
        assert validator.is_valid(subject) is expected, (carrier, label)
        accepted += int(expected)
    # Non-vacuity: the corpus must exercise both verdicts, or every rejection
    # above could be an artifact of a schema that rejects everything.
    assert accepted == 5, carrier
    assert len(_EXPRESSION_VERDICTS) - accepted == 10, carrier


@pytest.mark.parametrize("carrier", _EXPRESSION_CARRIERS)
def test_every_expression_carrier_is_valid_draft_2020_12(carrier: str) -> None:
    """Item 20, at the file root and at the derived expression root."""
    Draft202012Validator.check_schema(_committed(carrier))
    Draft202012Validator.check_schema(_embedded_expression_root(carrier))


_INTEGER_FLOAT_RESIDUALS: Final[tuple[tuple[str, dict[str, Any]], ...]] = (
    ("bars_ago as 0.0", {"op": "ref", "id": "a", "bars_ago": 0.0}),
    ("bars_ago as 4096.0", {"op": "ref", "id": "a", "bars_ago": 4096.0}),
    ("bars_ago in exponent form", {"op": "ref", "id": "a", "bars_ago": 1e1}),
    ("bars_ago as negative zero", {"op": "ref", "id": "a", "bars_ago": -0.0}),
    (
        "integer literal as 3.0",
        {"op": "literal", "value_type": "INTEGER", "value": 3.0},
    ),
    (
        "integer literal in exponent form",
        {"op": "literal", "value_type": "INTEGER", "value": 3e0},
    ),
)


@pytest.mark.parametrize("carrier", _EXPRESSION_CARRIERS)
def test_the_integer_spelling_residual_stays_one_directional(carrier: str) -> None:
    """An inexpressible residual, pinned so it cannot widen unnoticed.

    Draft 2020-12 defines `type: "integer"` as *any* number with a zero
    fractional part, and offers no keyword for the lexical form, so a published
    integer field cannot reject `0.0`, `1e1`, or `-0.0` while accepting `0`. The
    runtime is strict and does reject them. The published bytes are therefore a
    strict superset here, which is the safe direction: no document the runtime
    accepts is rejected.

    Pinned rather than left implicit for two reasons. If the runtime ever
    loosened to accept these spellings, the divergence would vanish and this
    test would say so. If a future schema change tried to close the gap and
    over-rejected genuine integers, the paired controls below would fail.
    """
    validator = Draft202012Validator(_embedded_expression_root(carrier))
    for label, subject in _INTEGER_FLOAT_RESIDUALS:
        assert validator.is_valid(subject), (carrier, label)
        with pytest.raises(PydanticValidationError):
            EXPRESSION_ADAPTER.validate_json(json.dumps(subject))

    # Controls, so the assertions above cannot be satisfied by a schema that
    # accepts everything or a runtime that rejects everything.
    integral = {"op": "ref", "id": "a", "bars_ago": 0}
    fractional = {"op": "ref", "id": "a", "bars_ago": 0.5}
    assert validator.is_valid(integral), carrier
    EXPRESSION_ADAPTER.validate_json(json.dumps(integral))
    assert not validator.is_valid(fractional), carrier
    with pytest.raises(PydanticValidationError):
        EXPRESSION_ADAPTER.validate_json(json.dumps(fractional))


def test_the_published_dispatcher_is_identical_in_both_generation_modes() -> None:
    """The published file is `mode="serialization"`; validation must agree.

    A mode-dependent dispatcher would mean the reviewed bytes describe only one
    of the two projections these models can emit, so the two are compared
    directly rather than assumed equal.
    """
    published = _dispatcher_of("strategy/expression-v1.schema.json")
    for label, adapter in (
        ("expression", EXPRESSION_ADAPTER),
        ("strategy-spec", TypeAdapter(StrategySpec)),
        ("strategy-version", TypeAdapter(StrategyVersion)),
    ):
        for mode in _RENDER_MODES:
            emitted = adapter.json_schema(mode=mode)
            assert emitted["$defs"]["Expression"] == published, (label, mode)


# --- Task 8: the published bytes stay tractable --------------------------------
#
# The committed expression tests prove the *source* projection is tractable. What
# is proven here is that the property survives registry rendering, canonical key
# sorting, file generation, and re-parsing -- the four steps between the emitting
# hook and what a consumer actually validates against.
#
# Key sorting is why this is a separate proof rather than a restatement. Under
# the old recursive `oneOf`, sorting placed a branch's recursive `left` ahead of
# its discriminating `op`, so even `oneOf`'s short-circuiting post-match scan
# recursed into children; and later same-shape binary branches were exponential
# even unsorted, because every earlier branch recursed before the matching one
# was reached. Conditional dispatch removes both mechanisms: an `if` cannot see a
# child at all, and exactly one `then` descends.
#
# The ten-second ceiling is a coarse safety ceiling, not a microbenchmark. The
# old dispatcher already exceeded it at depth four while the new one decides
# depth twenty-four in milliseconds, so no plausible machine sits between them.

_PUBLISHED_TRACTABILITY_BOUND_SECONDS: Final = 10.0

# The child imports only `json`, `jsonschema`, and `time`. The claim is about the
# published bytes, so importing the project models would weaken it.
_PUBLISHED_TRACTABILITY_PROBE: Final = """
from __future__ import annotations

import json
import sys
import time

from jsonschema import Draft202012Validator

schemas_root = sys.argv[1]
levels = int(sys.argv[2]) - 1

LEAF = {"op": "ref", "id": "close", "bars_ago": 0}
UNARY = ("not", "negate", "is_missing")
VARIADIC = ("and", "or")
BINARY = (
    "add",
    "subtract",
    "multiply",
    "divide",
    "minimum",
    "maximum",
    "equal",
    "not_equal",
    "less_than",
    "less_than_or_equal",
    "greater_than",
    "greater_than_or_equal",
    "crosses_above",
    "crosses_below",
)
CARRIERS = (
    "strategy/expression-v1.schema.json",
    "strategy/strategy-spec-v1.schema.json",
    "strategy/strategy-version-v1.schema.json",
)


def chain(op, count, seed=None):
    node = dict(LEAF) if seed is None else seed
    for _ in range(count):
        if op in UNARY:
            node = {"op": op, "operand": node}
        elif op in VARIADIC:
            node = {"op": op, "operands": [node, dict(LEAF)]}
        else:
            node = {"op": op, "left": node, "right": dict(LEAF)}
    return node


def variable(name):
    return {"op": "ref", "id": name, "bars_ago": 0}


cases = [
    (
        "ordinary-six-variable-rule",
        {
            "op": "greater_than",
            "left": {
                "op": "divide",
                "left": {
                    "op": "multiply",
                    "left": {
                        "op": "add",
                        "left": variable("a"),
                        "right": variable("b"),
                    },
                    "right": {
                        "op": "subtract",
                        "left": variable("c"),
                        "right": variable("d"),
                    },
                },
                "right": {"op": "add", "left": variable("e"), "right": variable("f")},
            },
            "right": {"op": "literal", "value_type": "DECIMAL", "value": "1.5"},
        },
        True,
    ),
    ("valid-unary-family-at-max-depth", chain("not", levels), True),
    ("valid-binary-family-at-max-depth", chain("add", levels), True),
    ("valid-variadic-family-at-max-depth", chain("and", levels), True),
    (
        "invalid-deep-arity",
        chain("add", levels, {"op": "add", "left": dict(LEAF)}),
        False,
    ),
    (
        "invalid-deep-unknown-op",
        chain("crosses_below", levels, {"op": "power", "operand": dict(LEAF)}),
        False,
    ),
    (
        "invalid-deep-extra-field",
        chain("or", levels, {"op": "ref", "id": "a", "bars_ago": 0, "extra": 1}),
        False,
    ),
    (
        "invalid-deep-missing-op",
        chain("multiply", levels, {"left": dict(LEAF)}),
        False,
    ),
]
for op in UNARY + BINARY + VARIADIC:
    cases.append(("valid-%s-at-max-depth" % op, chain(op, levels), True))

results = []
for carrier in CARRIERS:
    with open("%s/%s" % (schemas_root, carrier), "rb") as handle:
        document = json.loads(handle.read())
    validator = Draft202012Validator(
        {
            "$schema": document["$schema"],
            "$defs": document["$defs"],
            "$ref": "#/$defs/Expression",
        }
    )
    for name, subject, expected in cases:
        started = time.perf_counter()
        valid = validator.is_valid(subject)
        results.append(
            {
                "carrier": carrier,
                "case": name,
                "expected": expected,
                "valid": valid,
                "seconds": time.perf_counter() - started,
            }
        )
print(json.dumps(results))
"""


@pytest.fixture(scope="module")
def published_tractability_results() -> list[dict[str, Any]]:
    """Decide the whole depth-bound matrix in one bounded child process.

    One child rather than one per case: a fresh interpreter costs more than every
    measured case put together. The subprocess timeout is a hang detector; the
    per-case contract is asserted by the tests that consume this.
    """
    command = [
        sys.executable,
        "-I",
        "-B",
        "-c",
        _PUBLISHED_TRACTABILITY_PROBE,
        str(_COMMITTED_ROOT),
        str(MAX_EXPRESSION_DEPTH),
    ]
    try:
        completed = subprocess.run(  # noqa: S603 - fixed local interpreter
            command,
            check=False,
            capture_output=True,
            shell=False,
            text=True,
            timeout=180,
        )
    except subprocess.TimeoutExpired:  # pragma: no cover - hang detector
        pytest.fail(
            "the published expression bytes did not decide the bounded "
            "depth-24 matrix within 180s"
        )
    assert completed.returncode == 0, completed.stderr
    decoded: list[dict[str, Any]] = json.loads(completed.stdout)
    return decoded


def test_the_published_tractability_matrix_covers_every_recursive_family(
    published_tractability_results: list[dict[str, Any]],
) -> None:
    """Coverage first: the bound below means nothing over the wrong corpus."""
    assert MAX_EXPRESSION_DEPTH == 24
    carriers = {result["carrier"] for result in published_tractability_results}
    cases = {result["case"] for result in published_tractability_results}

    assert carriers == set(_EXPRESSION_CARRIERS)
    for family in (
        "valid-unary-family-at-max-depth",
        "valid-binary-family-at-max-depth",
        "valid-variadic-family-at-max-depth",
        "ordinary-six-variable-rule",
    ):
        assert family in cases, family
    for operation, _ in _EXPRESSION_DISPATCH_TABLE:
        if operation in ("literal", "ref"):
            continue
        assert f"valid-{operation}-at-max-depth" in cases, operation
    assert len({case for case in cases if case.startswith("invalid-")}) == 4
    assert len(published_tractability_results) == len(cases) * len(_EXPRESSION_CARRIERS)


def test_every_published_depth_bound_document_is_decided_within_the_bound(
    published_tractability_results: list[dict[str, Any]],
) -> None:
    for result in published_tractability_results:
        assert result["seconds"] < _PUBLISHED_TRACTABILITY_BOUND_SECONDS, result


def test_every_published_depth_bound_document_gets_the_right_verdict(
    published_tractability_results: list[dict[str, Any]],
) -> None:
    for result in published_tractability_results:
        assert result["valid"] is result["expected"], result


# --- Task 8: the eleven Stage 3 schemas are pinned independently of the render -
#
# Every other preservation assertion in this module compares the committed bytes
# with `render_schema_files()`. That pair moves together: change a Stage 3 model
# and regenerate, and both sides agree on the new bytes while a released `$id`
# has silently changed meaning. The digests below are the independent anchor, so
# the two-sided change fails here even though it satisfies everything else.
#
# They are literals rather than a `git show main:` read on purpose: an ordinary
# test must not depend on the branch it happens to run from, or on Git being
# present at all. Each value was derived from the working tree, confirmed equal
# to the corresponding `main` blob in both directions, and reviewed before
# commit.

_STAGE3_SHA256: Final[dict[str, str]] = {
    "domain/instrument-ref-v1.schema.json": (
        "153fae2fe9931b5efb31c63836121415dd72110c794916c055c9d74076d4085b"
    ),
    "domain/money-v1.schema.json": (
        "5b1455c5187b6cc7308266bb7eda4e97e4115ef197180b2a6437ec56a3d37b85"
    ),
    "domain/price-v1.schema.json": (
        "9a9051a0d4a3600e628d73ba68b4c719737f2ea38f8698d81069f58ec743b7d8"
    ),
    "domain/quantity-v1.schema.json": (
        "2b58e1c2ed51579c2922303ba1045b2186d85dfcab00ecd09bc9b98bc1ffb080"
    ),
    "domain/diagnostic-v1.schema.json": (
        "00e21d0126ba70741f2bef69161ab3462fe7b8bddb6a9464d28cc02e8d054dc7"
    ),
    "configuration/application-config-v1.schema.json": (
        "9eb04d6d0dae1b5f1b0689783b072d72e2f66a9d1471812a79f46ef58d8bbb68"
    ),
    "datasets/dataset-partition-v1.schema.json": (
        "36ab683883af7af8f0e385c360111a25ab8108c6e5d4cb9178f2caca8b4bff7f"
    ),
    "datasets/dataset-descriptor-v1.schema.json": (
        "aa455aad18a9c6c5cb619ee013c993365390038358208601be4faaffb2046e84"
    ),
    "protocol/engine-descriptor-v1.schema.json": (
        "7ebcc6467d9eef695d777843a000140f0f9da4f1ef7c1faf465f6a5a69ddf2d1"
    ),
    "protocol/adapter-descriptor-v1.schema.json": (
        "8fadb5ea78a02950f191989df27fe12d09f66d3e5c62c13d20a54ae423b06e58"
    ),
    "artifacts/artifact-owner-ref-v1.schema.json": (
        "ff51637b65d9ad1f14973ac97c57d4626d7f622555edd52ad102d7047a352a5d"
    ),
}


def test_the_eleven_stage_three_schema_files_match_their_reviewed_digests() -> None:
    """The one assertion a simultaneous source change and regeneration fails."""
    assert tuple(sorted(_STAGE3_SHA256)) == tuple(sorted(_STAGE3_PATHS))
    assert len(_STAGE3_SHA256) == 11
    for name, expected in _STAGE3_SHA256.items():
        actual = hashlib.sha256((_COMMITTED_ROOT / name).read_bytes()).hexdigest()
        assert actual == expected, name


def test_the_stage_three_digests_are_keyed_on_paths_not_on_a_count() -> None:
    """A renamed or dropped Stage 3 file must fail rather than pass vacuously."""
    for name in _STAGE3_PATHS:
        assert (_COMMITTED_ROOT / name).is_file(), name
        assert name in _STAGE3_SHA256, name
    for name in _STAGE4_PATHS:
        assert name not in _STAGE3_SHA256, name


# --- Stage 5 Task 1: the nine Stage 4 schemas are pinned the same way ----------
#
# Stage 5 plan section 2.5 relocates `RetryTerminalState` (entry 5,
# `configuration/application-config-v1`) and `CompatibilityOutcome` (entry 17,
# `capabilities/compatibility-result-v1`) into `domain`, and requires each move
# to be byte-neutral or not performed. Section 2.7 assigns this block to Task 1
# so the digest gate covers all twenty existing schemas before any other Stage 5
# change lands. Each value was derived from the working tree at the Stage 5 base
# commit and confirmed equal to the corresponding `main` blob in both directions.
# Task 9 added the Stage-5-absent half of the key guard once `_STAGE5_PATHS` and
# the seven Stage 5 entries existed.

_STAGE4_SHA256: Final[dict[str, str]] = {
    "strategy/strategy-spec-v1.schema.json": (
        "6874d259a04384720862f0a6a6325be740080431a4ebcf8e8d37ed416c9dde9c"
    ),
    "strategy/strategy-version-v1.schema.json": (
        "35127c235062d067e451514dcdfbc703f8fda4d99b3c63c94ea9beb4eb37500d"
    ),
    "strategy/expression-v1.schema.json": (
        "84d967a8afff10e48ee0129a74b666eb5902e2f4b1d307fe63bba7f0fda9b465"
    ),
    "capabilities/capability-requirement-v1.schema.json": (
        "fda291aed5395f7d0d947d05a5e596de7ef827f53421ded061ad11b7e3f17e81"
    ),
    "capabilities/capability-declaration-v1.schema.json": (
        "e89b2cf02135f0c3a284f4351555fb6bba8be9e6c8b512aebf58339a275b9817"
    ),
    "capabilities/approximation-declaration-v1.schema.json": (
        "ea73a819ca178d8a7e5bbd98412e66bf486b92c91f8dfb7214f84abc8b27ff1c"
    ),
    "capabilities/compatibility-result-v1.schema.json": (
        "de2863c06038653045187748d494851d3aad14323215028951d11639990f80bb"
    ),
    "capabilities/runtime-availability-observation-v1.schema.json": (
        "ec92c4402f6e4c9ad1ac4a248d30ae9a28c8065e1b97f8d275583c5f339f469b"
    ),
    "capabilities/comparison-eligibility-result-v1.schema.json": (
        "21bb21350fcc2fb1bb512cf14f799ec05eb58b6d06665492bbd5265adbfea08d"
    ),
}


def test_the_nine_stage_four_schema_files_match_their_reviewed_digests() -> None:
    """The one assertion a simultaneous Stage 4 model change and regeneration fails."""
    assert tuple(sorted(_STAGE4_SHA256)) == tuple(sorted(_STAGE4_PATHS))
    assert len(_STAGE4_SHA256) == 9
    for name, expected in _STAGE4_SHA256.items():
        actual = hashlib.sha256((_COMMITTED_ROOT / name).read_bytes()).hexdigest()
        assert actual == expected, name


def test_the_stage_four_digests_are_keyed_on_paths_not_on_a_count() -> None:
    """A renamed or dropped Stage 4 file must fail rather than pass vacuously."""
    for name in _STAGE4_PATHS:
        assert (_COMMITTED_ROOT / name).is_file(), name
        assert name in _STAGE4_SHA256, name
    for name in _STAGE3_PATHS:
        assert name not in _STAGE4_SHA256, name
    for name in _STAGE5_PATHS:
        assert name not in _STAGE4_SHA256, name


def test_the_two_relocation_bearing_entries_render_their_pinned_bytes() -> None:
    """Entries 5 and 17 are the two schemas the Task 1 relocations could move.

    Pinned against the **render**, not only the committed file: hashing the file
    alone would still pass if a relocation changed what generation emits, since
    nothing regenerates during a test run. `RetryTerminalState` must keep
    rendering with no `description`, because the moved class carries no
    docstring; `CompatibilityOutcome` must keep rendering its byte-identical one.
    """
    ordered = _ordered_paths()
    config_path = "configuration/application-config-v1.schema.json"
    result_path = "capabilities/compatibility-result-v1.schema.json"
    assert ordered[5] == config_path
    assert ordered[17] == result_path

    rendered = render_schema_files()
    config_digest = hashlib.sha256(rendered[PurePosixPath(config_path)]).hexdigest()
    result_digest = hashlib.sha256(rendered[PurePosixPath(result_path)]).hexdigest()
    assert config_digest == _STAGE3_SHA256[config_path]
    assert result_digest == _STAGE4_SHA256[result_path]

    committed = _committed_schemas()
    assert committed[PurePosixPath(config_path)]["$defs"]["RetryTerminalState"] == {
        "enum": ["FAILED", "TIMED_OUT", "UNAVAILABLE"],
        "title": "RetryTerminalState",
        "type": "string",
    }
    outcome = committed[PurePosixPath(result_path)]["$defs"]["CompatibilityOutcome"]
    assert set(outcome) == {"description", "enum", "title", "type"}
    assert outcome["enum"] == [
        "SUPPORTED",
        "SUPPORTED_WITH_APPROXIMATION",
        "NOT_APPLICABLE",
        "UNAVAILABLE",
    ]
    assert outcome["title"] == "CompatibilityOutcome"
    assert outcome["type"] == "string"
    assert outcome["description"].startswith(
        "The four approved outcomes of specification sections 11.5 and 13.4."
    )


# --- Stage 5 Task 9: the seven experiments schemas are pinned the same way -------
#
# Plan section 2.7 assigns this block to Task 9: seven digests keyed on
# `_STAGE5_PATHS`, with key equality, `== 7` and Stage-3-and-Stage-4-absent
# assertions, so a renamed, dropped or hand-edited Stage 5 file fails rather than
# passing vacuously. Each value was derived from the `schema-generate-write` output
# of the Task 9 tree after every byte of the seven files had been read and reviewed
# (docs/development/verification.md, "Generated bytes are reviewed source"); the
# twenty pre-existing digests above were re-verified unchanged in the same tree.

_STAGE5_SHA256: Final[dict[str, str]] = {
    "experiments/experiment-spec-v1.schema.json": (
        "d1c7880abdd0ba067fda4aed408d46b679e62eda6eb1f7fa01ac1e5af57f6e6b"
    ),
    "experiments/experiment-record-v1.schema.json": (
        "5b832b7d6406e38ab36a1c36746e033d84b32d44b457aeb3cb64e24a7259eb9b"
    ),
    "experiments/engine-run-record-v1.schema.json": (
        "41131b755a3a66aa21834652b6fc7f5cc606741b51e95d4b26d4de3c56ce01cc"
    ),
    "experiments/command-invocation-record-v1.schema.json": (
        "295ef1eaa92b74f60aab3344c146c76ccbfefe3c1c5d795283d4bfc7308e1916"
    ),
    "experiments/retry-policy-v1.schema.json": (
        "7f08b5cfbcf4e832292b32a55f98c281a4e2abcd298f595ae058381dfa240841"
    ),
    "experiments/retry-decision-record-v1.schema.json": (
        "fa9b4b073f7ec0d375d8f518ee4f89248bfd8621b92c6e18db191f832f256b82"
    ),
    "experiments/experiment-aggregation-result-v1.schema.json": (
        "1dbbb90ba16e4d2085b2d1c6992d2fdb514e95fd20b2388aa81ec9f99b2d1db8"
    ),
}


def test_the_seven_stage_five_schema_files_match_their_reviewed_digests() -> None:
    """The one assertion a simultaneous Stage 5 model change and regeneration fails."""
    assert tuple(sorted(_STAGE5_SHA256)) == tuple(sorted(_STAGE5_PATHS))
    assert len(_STAGE5_SHA256) == 7
    for name, expected in _STAGE5_SHA256.items():
        actual = hashlib.sha256((_COMMITTED_ROOT / name).read_bytes()).hexdigest()
        assert actual == expected, name


def test_the_stage_five_digests_are_keyed_on_paths_not_on_a_count() -> None:
    """A renamed or dropped Stage 5 file must fail rather than pass vacuously."""
    for name in _STAGE5_PATHS:
        assert (_COMMITTED_ROOT / name).is_file(), name
        assert name in _STAGE5_SHA256, name
    for name in _STAGE3_PATHS + _STAGE4_PATHS:
        assert name not in _STAGE5_SHA256, name
    assert not set(_STAGE5_SHA256) & set(_STAGE3_SHA256)
    assert not set(_STAGE5_SHA256) & set(_STAGE4_SHA256)


def test_the_twenty_pre_existing_schemas_are_byte_identical_after_stage_five() -> None:
    """Plan 2.5 and Task 9: registering seven entries changed none of the twenty.

    Both the live render and the committed file are held to the pinned digests,
    so neither a model drift that regeneration would publish nor a hand edit of
    a released file can hide behind the Stage 5 extension.
    """
    frozen = {**_STAGE3_SHA256, **_STAGE4_SHA256}
    assert len(frozen) == 20
    rendered = render_schema_files()
    for name, expected in frozen.items():
        path = PurePosixPath(name)
        assert hashlib.sha256(rendered[path]).hexdigest() == expected, name
        committed = hashlib.sha256((_COMMITTED_ROOT / name).read_bytes()).hexdigest()
        assert committed == expected, name


# --- Stage 5 Task 9: the published contracts of the seven schemas ------------------
#
# Asserted against the committed bytes on disk, as the Stage 4 contract tests are,
# so a hand-edited file cannot pass on the strength of the live render. Positive
# documents are built by the Stage 5 in-memory fixture material and dumped through
# the runtime, so every accepting baseline is a document the runtime itself
# accepts; every negative table is paired with that baseline, so a rejection can
# never be an artifact of an already-invalid document.

_STAGE5_CLOSED_ENUMS: Final[dict[str, dict[str, tuple[str, ...]]]] = {
    "experiments/experiment-spec-v1.schema.json": {
        "SlippageModel": ("NONE", "FIXED_BASIS_POINTS"),
        "SignalToOrderTiming": ("NEXT_BAR_OPEN", "SAME_BAR_CLOSE"),
        "BarOrderPriority": ("EXITS_BEFORE_ENTRIES", "ENTRIES_BEFORE_EXITS"),
        "FillConvention": ("FULL_FILL", "PARTIAL_FILLS_ALLOWED"),
        "ComparisonLevel": ("LEVEL_1", "LEVEL_2", "LEVEL_3"),
        "RetryTerminalState": ("FAILED", "TIMED_OUT", "UNAVAILABLE"),
    },
    "experiments/experiment-record-v1.schema.json": {
        "ExperimentState": (
            "DRAFT",
            "VALIDATED",
            "QUEUED",
            "RUNNING",
            "COMPLETED",
            "COMPLETED_WITH_WARNINGS",
            "FAILED",
            "CANCELLED",
        ),
        "CompatibilityOutcome": (
            "SUPPORTED",
            "SUPPORTED_WITH_APPROXIMATION",
            "NOT_APPLICABLE",
            "UNAVAILABLE",
        ),
        "RetryTerminalState": ("FAILED", "TIMED_OUT", "UNAVAILABLE"),
    },
    "experiments/engine-run-record-v1.schema.json": {
        "EngineRunState": (
            "PENDING",
            "VALIDATING",
            "READY",
            "STARTING",
            "RUNNING",
            "SUCCEEDED",
            "SUCCEEDED_WITH_WARNINGS",
            "FAILED",
            "CANCELLED",
            "TIMED_OUT",
            "NOT_APPLICABLE",
            "UNAVAILABLE",
        ),
        "RetryTerminalState": ("FAILED", "TIMED_OUT", "UNAVAILABLE"),
    },
    "experiments/command-invocation-record-v1.schema.json": {
        "CommandInvocationState": (
            "PENDING",
            "STARTING",
            "RUNNING",
            "EXITED",
            "FAILED_TO_START",
            "CANCELLED",
            "TIMED_OUT",
            "PROTOCOL_FAILED",
        ),
        "CommandKind": ("DESCRIBE", "VALIDATE", "RUN"),
        # Plan section 6 and Task 9: the eight v1 members, asserted member by
        # member; there is no `UNKNOWN_AFTER_RESTART`.
        "ProcessExitCategory": (
            "SUCCESS",
            "VALIDATION_FAILURE",
            "NOT_APPLICABLE",
            "UNAVAILABLE",
            "RUNTIME_FAILURE",
            "CANCELLED",
            "TIMED_OUT",
            "PROTOCOL_VIOLATION",
        ),
    },
    "experiments/retry-policy-v1.schema.json": {
        "RetryTerminalState": ("FAILED", "TIMED_OUT", "UNAVAILABLE"),
    },
    "experiments/retry-decision-record-v1.schema.json": {
        "RetryDecisionOutcome": ("ALLOWED", "DENIED"),
        "RetryDenialReason": (
            "ATTEMPT_BUDGET_EXHAUSTED",
            "TERMINAL_STATE_NOT_RETRYABLE",
            "PRIMARY_DIAGNOSTIC_NOT_RETRIABLE",
            "HARD_BLOCKED_OUTCOME",
            "EXPERIMENT_TERMINAL",
            "AVAILABILITY_OBSERVATION_NOT_FRESH",
        ),
        # Plan section 3.9: field 8 publishes the full twelve-member enum and the
        # runtime narrows it to the five non-success terminals (recorded residual).
        "EngineRunState": (
            "PENDING",
            "VALIDATING",
            "READY",
            "STARTING",
            "RUNNING",
            "SUCCEEDED",
            "SUCCEEDED_WITH_WARNINGS",
            "FAILED",
            "CANCELLED",
            "TIMED_OUT",
            "NOT_APPLICABLE",
            "UNAVAILABLE",
        ),
        "RetryTerminalState": ("FAILED", "TIMED_OUT", "UNAVAILABLE"),
    },
    "experiments/experiment-aggregation-result-v1.schema.json": {
        "AggregationVerdict": (
            "NOT_YET_TERMINAL",
            "COMPLETED",
            "COMPLETED_WITH_WARNINGS",
            "FAILED",
            "CANCELLED",
        ),
    },
}

#: Plan sections 3.4-3.10: the field order of every top-level record is
#: contractual, and `required` is emitted in declaration order, so the exact
#: tuples pin both the required set and the order.
_STAGE5_REQUIRED: Final[dict[str, tuple[str, ...]]] = {
    "experiments/experiment-spec-v1.schema.json": (
        "schema_version",
        "strategy_version_hash",
        "dataset_version_hash",
        "selected_engine_slots",
        "starting_balance",
        "fee_assumptions",
        "slippage_assumptions",
        "execution_assumptions",
        "comparison_level",
        "retry_policy",
        "configuration_hash",
        "created_at_utc",
    ),
    "experiments/experiment-record-v1.schema.json": (
        "schema_version",
        "experiment_id",
        "spec",
        "spec_hash",
        "state",
        "created_at_utc",
        "updated_at_utc",
        "revision",
    ),
    "experiments/engine-run-record-v1.schema.json": (
        "schema_version",
        "run_id",
        "experiment_id",
        "logical_slot_id",
        "attempt_number",
        "attempt_token_hash",
        "state",
        "adapter",
        "engine",
        "request_hash",
        "created_at_utc",
        "updated_at_utc",
        "revision",
    ),
    "experiments/command-invocation-record-v1.schema.json": (
        "schema_version",
        "invocation_id",
        "command_kind",
        "adapter_name",
        "adapter_version",
        "request_hash",
        "timeout_seconds",
        "state",
        "process_created",
        "cleanup_complete",
        "diagnostic_ids",
        "created_at_utc",
        "updated_at_utc",
        "revision",
    ),
    "experiments/retry-policy-v1.schema.json": (
        "schema_version",
        "maximum_attempts_per_slot",
        "automatically_retry_terminal_states",
        "retry_delay_seconds",
        "require_fresh_availability_observation_for_unavailable",
    ),
    "experiments/retry-decision-record-v1.schema.json": (
        "schema_version",
        "experiment_id",
        "logical_slot_id",
        "predecessor_run_id",
        "experiment_spec_hash",
        "retry_policy",
        "created_attempt_count",
        "predecessor_terminal_state",
        "primary_terminal_diagnostic_id",
        "outcome",
        "decided_at_utc",
    ),
    "experiments/experiment-aggregation-result-v1.schema.json": (
        "schema_version",
        "experiment_id",
        "verdict",
        "reason_codes",
    ),
}

#: The state-governed fields each record publishes as optional properties (plan
#: sections 3.6-3.9): present in `properties`, absent from `required`.
_STAGE5_OPTIONAL: Final[dict[str, tuple[str, ...]]] = {
    "experiments/experiment-spec-v1.schema.json": (),
    "experiments/experiment-record-v1.schema.json": (
        "slot_compatibility",
        "cancellation_correlation_id",
    ),
    "experiments/engine-run-record-v1.schema.json": (
        "predecessor_run_id",
        "retry_reason",
        "primary_terminal_diagnostic_id",
        "availability_observation_id",
        "finalization_deadline_utc",
    ),
    "experiments/command-invocation-record-v1.schema.json": (
        "run_id",
        "deadline_utc",
        "launch_attempted_at_utc",
        "process_started_at_utc",
        "pid_identity",
        "completed_at_utc",
        "native_exit_value",
        "process_exit_category",
        "cleanup_completed_at_utc",
        "stderr_artifact_id",
        "primary_diagnostic_id",
    ),
    "experiments/retry-policy-v1.schema.json": (),
    "experiments/retry-decision-record-v1.schema.json": (
        "denial_reason",
        "hard_block_error_code",
        "availability_observation_id",
        "retry_not_before_utc",
        "reserved_successor_attempt_number",
    ),
    "experiments/experiment-aggregation-result-v1.schema.json": (),
}

#: Every Stage 5 position that carries `uniqueItems: true`. All nine are
#: WHOLE-VALUE exact: the runtime rejects any repeated item (`approximation_ids`,
#: `diagnostic_ids`, `reason_codes` and the retry states are unique by rule, and
#: distinct ordinals make every accepted `selected_engine_slots` member distinct).
_STAGE5_UNIQUE_POINTERS: Final[tuple[tuple[str, str], ...]] = (
    ("experiments/experiment-spec-v1.schema.json", "/properties/selected_engine_slots"),
    (
        "experiments/experiment-spec-v1.schema.json",
        "/$defs/RetryPolicy/properties/automatically_retry_terminal_states",
    ),
    (
        "experiments/experiment-record-v1.schema.json",
        "/$defs/ExperimentSpec/properties/selected_engine_slots",
    ),
    (
        "experiments/experiment-record-v1.schema.json",
        "/$defs/RetryPolicy/properties/automatically_retry_terminal_states",
    ),
    (
        "experiments/experiment-record-v1.schema.json",
        "/$defs/SlotCompatibility/properties/approximation_ids",
    ),
    (
        "experiments/command-invocation-record-v1.schema.json",
        "/properties/diagnostic_ids",
    ),
    (
        "experiments/retry-policy-v1.schema.json",
        "/properties/automatically_retry_terminal_states",
    ),
    (
        "experiments/retry-decision-record-v1.schema.json",
        "/$defs/RetryPolicy/properties/automatically_retry_terminal_states",
    ),
    (
        "experiments/experiment-aggregation-result-v1.schema.json",
        "/properties/reason_codes",
    ),
)


def _stage5_unique_items_pointers() -> tuple[tuple[str, str], ...]:
    found: list[tuple[str, str]] = []

    def walk(node: object, name: str, pointer: str) -> None:
        if isinstance(node, dict):
            if node.get("uniqueItems") is True:
                found.append((name, pointer))
            for key, value in node.items():
                walk(value, name, f"{pointer}/{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, name, f"{pointer}/{index}")

    documents = _committed_schemas()
    for name in _STAGE5_PATHS:
        walk(documents[PurePosixPath(name)], name, "")
    return tuple(found)


def _closed_objects(node: object) -> tuple[dict[str, Any], ...]:
    """Every object schema reachable in the document, for the `extra="forbid"` pin."""
    found: list[dict[str, Any]] = []
    if isinstance(node, dict):
        if node.get("type") == "object" and "properties" in node:
            found.append(cast(dict[str, Any], node))
        for value in node.values():
            found.extend(_closed_objects(value))
    elif isinstance(node, list):
        for value in node:
            found.extend(_closed_objects(value))
    return tuple(found)


def test_the_stage_five_schemas_publish_their_closed_enums() -> None:
    documents = _committed_schemas()
    for name, enums in _STAGE5_CLOSED_ENUMS.items():
        definitions = documents[PurePosixPath(name)]["$defs"]
        for title, members in enums.items():
            node = definitions[title]
            assert node["type"] == "string", (name, title)
            assert node["title"] == title, (name, title)
            assert tuple(node["enum"]) == members, (name, title)
            assert len(set(members)) == len(members), (name, title)
        # `RetryTerminalState` renders with no `description` everywhere it appears
        # (plan 2.5 constraint 2), exactly as in the released configuration schema.
        if "RetryTerminalState" in enums:
            assert set(definitions["RetryTerminalState"]) == {"enum", "title", "type"}
    exit_categories = _STAGE5_CLOSED_ENUMS[
        "experiments/command-invocation-record-v1.schema.json"
    ]["ProcessExitCategory"]
    assert len(exit_categories) == 8
    assert "UNKNOWN_AFTER_RESTART" not in exit_categories
    assert tuple(member.value for member in ProcessExitCategory) == exit_categories


def test_the_stage_five_schemas_publish_their_required_and_optional_fields() -> None:
    documents = _committed_schemas()
    for name in _STAGE5_PATHS:
        document = documents[PurePosixPath(name)]
        required = _STAGE5_REQUIRED[name]
        optional = _STAGE5_OPTIONAL[name]
        assert tuple(document["required"]) == required, name
        assert set(document["properties"]) == set(required) | set(optional), name
        assert not set(required) & set(optional), name
        assert document["properties"]["schema_version"] == {
            "const": "1.0.0",
            "title": "Schema Version",
            "type": "string",
        }, name
        assert document["title"] == _EXPECTED_ADAPTED_TYPES[name].__name__, name
        for node in _closed_objects(document):
            assert node["additionalProperties"] is False, (name, node.get("title"))


def test_the_stage_five_unique_items_census_is_exactly_the_nine_positions() -> None:
    documents = _committed_schemas()
    for name, pointer in _STAGE5_UNIQUE_POINTERS:
        node = _resolve_pointer(documents[PurePosixPath(name)], pointer)
        assert node["type"] == "array", (name, pointer)
        assert node["uniqueItems"] is True, (name, pointer)
    published = _stage5_unique_items_pointers()
    assert set(published) == set(_STAGE5_UNIQUE_POINTERS)
    assert len(published) == 9
    assert len(set(_STAGE5_UNIQUE_POINTERS)) == 9


def test_every_stage_five_schema_is_identical_in_both_generation_modes() -> None:
    """The published file is `mode="serialization"`; validation must agree.

    A mode-dependent projection would mean the reviewed bytes describe only one
    of the two projections these models can emit, so the two are compared
    directly rather than assumed equal, for every Stage 5 entry.
    """
    for name in _STAGE5_PATHS:
        adapter: TypeAdapter[Any] = TypeAdapter(_EXPECTED_ADAPTED_TYPES[name])
        emitted = {mode: adapter.json_schema(mode=mode) for mode in _RENDER_MODES}
        assert emitted["validation"] == emitted["serialization"], name
        published = dict(_committed(name))
        del published["$schema"]
        del published["$id"]
        assert emitted["serialization"] == published, name


def _dumped(record: object) -> dict[str, Any]:
    """The runtime's own JSON projection; `MISSING` fields are omitted, not null."""
    assert isinstance(record, CanonicalModel)
    return record.model_dump(mode="json")


def _stage5_baselines() -> dict[str, tuple[dict[str, Any], ...]]:
    """Runtime-accepted documents, several states each, for every Stage 5 schema."""
    experiments = (
        sample_experiment(ExperimentState.DRAFT),
        sample_experiment(ExperimentState.VALIDATED),
        sample_experiment(ExperimentState.QUEUED),
        sample_experiment(ExperimentState.RUNNING),
        sample_experiment(ExperimentState.COMPLETED),
        sample_experiment(ExperimentState.CANCELLED),
        sample_experiment(ExperimentState.CANCELLED, include_compatibility=True),
        sample_experiment(
            ExperimentState.QUEUED,
            slot_compatibility=sample_slot_compatibility(
                outcomes={
                    SLOT_A: CompatibilityOutcome.SUPPORTED_WITH_APPROXIMATION,
                    SLOT_B: CompatibilityOutcome.NOT_APPLICABLE,
                }
            ),
        ),
    )
    runs = (
        sample_run(EngineRunState.PENDING),
        sample_run(EngineRunState.VALIDATING),
        sample_run(EngineRunState.READY),
        sample_run(EngineRunState.RUNNING),
        sample_run(EngineRunState.SUCCEEDED),
        sample_run(EngineRunState.FAILED),
        sample_run(EngineRunState.NOT_APPLICABLE),
        sample_run(EngineRunState.UNAVAILABLE),
        sample_run(EngineRunState.SUCCEEDED_WITH_WARNINGS, attempt_number=2),
    )
    invocations = (
        sample_invocation(CommandInvocationState.PENDING, kind=CommandKind.DESCRIBE),
        sample_invocation(CommandInvocationState.STARTING, kind=CommandKind.VALIDATE),
        sample_invocation(CommandInvocationState.RUNNING, kind=CommandKind.VALIDATE),
        sample_invocation(CommandInvocationState.EXITED, kind=CommandKind.RUN),
        sample_invocation(
            CommandInvocationState.EXITED, kind=CommandKind.RUN, native_exit_value=99
        ),
        sample_invocation(CommandInvocationState.FAILED_TO_START),
        sample_invocation(
            CommandInvocationState.CANCELLED, via=CommandInvocationState.PENDING
        ),
        sample_invocation(
            CommandInvocationState.TIMED_OUT, via=CommandInvocationState.STARTING
        ),
        sample_invocation(CommandInvocationState.PROTOCOL_FAILED),
    )
    policies = (
        sample_retry_policy(),
        sample_retry_policy(
            maximum_attempts_per_slot=1,
            automatically_retry_terminal_states=(),
            retry_delay_seconds=0,
        ),
    )
    decisions = (
        sample_retry_decision(),
        sample_allowed_retry_decision(),
        sample_allowed_retry_decision(
            predecessor_terminal_state=EngineRunState.UNAVAILABLE,
            availability_observation_id=AVAIL_B,
        ),
    )
    results = (
        ExperimentAggregationResult(
            schema_version="1.0.0",
            experiment_id=EXPERIMENT_ID,
            verdict=AggregationVerdict.COMPLETED,
            reason_codes=(),
        ),
        ExperimentAggregationResult(
            schema_version="1.0.0",
            experiment_id=EXPERIMENT_ID,
            verdict=AggregationVerdict.COMPLETED_WITH_WARNINGS,
            reason_codes=(
                "EXPERIMENT.SLOT_SUCCEEDED_WITH_WARNINGS",
                "EXPERIMENT.SLOT_USED_APPROXIMATION",
            ),
        ),
    )
    return {
        "experiments/experiment-spec-v1.schema.json": tuple(
            _dumped(record.spec) for record in experiments[:1]
        ),
        "experiments/experiment-record-v1.schema.json": tuple(
            _dumped(record) for record in experiments
        ),
        "experiments/engine-run-record-v1.schema.json": tuple(
            _dumped(record) for record in runs
        ),
        "experiments/command-invocation-record-v1.schema.json": tuple(
            _dumped(record) for record in invocations
        ),
        "experiments/retry-policy-v1.schema.json": tuple(
            _dumped(record) for record in policies
        ),
        "experiments/retry-decision-record-v1.schema.json": tuple(
            _dumped(record) for record in decisions
        ),
        "experiments/experiment-aggregation-result-v1.schema.json": tuple(
            _dumped(record) for record in results
        ),
    }


def test_every_stage_five_baseline_the_runtime_accepts_is_accepted_on_disk() -> None:
    """The over-rejection half: no runtime-valid record is refused by its schema."""
    baselines = _stage5_baselines()
    assert set(baselines) == set(_STAGE5_PATHS)
    total = 0
    for name, documents in baselines.items():
        validator = _validator(name)
        assert documents, name
        for document in documents:
            validator.validate(document)
            # Round trip: the dumped document is exactly what the runtime re-reads.
            _runtime_accepts(name, document)
            total += 1
    assert total == 34


def _runtime_adapter(name: str) -> TypeAdapter[Any]:
    return TypeAdapter(_EXPECTED_ADAPTED_TYPES[name])


def _runtime_accepts(name: str, document: dict[str, Any]) -> None:
    """JSON-mode validation: the strict models read JSON, not coerced Python."""
    _runtime_adapter(name).validate_json(json.dumps(document))


def _runtime_rejects(name: str, document: dict[str, Any]) -> None:
    with pytest.raises(PydanticValidationError):
        _runtime_adapter(name).validate_json(json.dumps(document))


def _baseline(name: str, index: int = 0) -> dict[str, Any]:
    """A deep copy of one runtime-accepted baseline, safe to mutate."""
    return cast(
        dict[str, Any], json.loads(json.dumps(_stage5_baselines()[name][index]))
    )


def _nested(base: dict[str, Any], key: str, **changes: object) -> dict[str, Any]:
    """`base` with the nested object at `key` shallowly updated."""
    return {**base, key: {**base[key], **changes}}


def _without(base: dict[str, Any], key: str) -> dict[str, Any]:
    return {name: value for name, value in base.items() if name != key}


_SPEC: Final = "experiments/experiment-spec-v1.schema.json"
_RECORD: Final = "experiments/experiment-record-v1.schema.json"
_RUN: Final = "experiments/engine-run-record-v1.schema.json"
_INVOCATION: Final = "experiments/command-invocation-record-v1.schema.json"
_POLICY: Final = "experiments/retry-policy-v1.schema.json"
_DECISION: Final = "experiments/retry-decision-record-v1.schema.json"
_RESULT: Final = "experiments/experiment-aggregation-result-v1.schema.json"
_APPX: Final = f"appx_{_UUID_TAIL}"
_DIAG: Final = f"diag_{_UUID_TAIL}"


def test_the_committed_experiment_spec_schema_rejects_every_expressible_violation() -> (
    None
):
    validator = _validator(_SPEC)
    spec = _baseline(_SPEC)
    validator.validate(spec)
    slots = cast(list[dict[str, Any]], spec["selected_engine_slots"])
    ninth = [json.loads(json.dumps(slots[0])) for _ in range(9)]
    policy = cast(dict[str, Any], spec["retry_policy"])
    cases: tuple[tuple[str, dict[str, Any]], ...] = (
        ("unknown field", {**spec, "engine_count": 2}),
        ("wrong envelope version", {**spec, "schema_version": "1.0.1"}),
        ("no selected slot", {**spec, "selected_engine_slots": []}),
        ("nine selected slots", {**spec, "selected_engine_slots": ninth}),
        ("repeated slot item", {**spec, "selected_engine_slots": [*slots, slots[0]]}),
        (
            "slot ordinal above seven",
            {**spec, "selected_engine_slots": [{**slots[0], "slot_ordinal": 8}]},
        ),
        (
            "price precision above eighteen",
            _nested(spec, "execution_assumptions", price_precision=19),
        ),
        (
            "rounding mode outside the literal",
            _nested(spec, "execution_assumptions", rounding_mode="ROUND_HALF_UP"),
        ),
        ("negative fee rate", _nested(spec, "fee_assumptions", maker_fee_rate="-0.1")),
        ("float fee rate", _nested(spec, "fee_assumptions", taker_fee_rate=0.1)),
        (
            "slippage model outside the enum",
            _nested(spec, "slippage_assumptions", model="LINEAR"),
        ),
        (
            "attempt budget above five",
            {**spec, "retry_policy": {**policy, "maximum_attempts_per_slot": 6}},
        ),
        (
            "attempt budget below one",
            {**spec, "retry_policy": {**policy, "maximum_attempts_per_slot": 0}},
        ),
        (
            "retry delay above three hundred",
            {**spec, "retry_policy": {**policy, "retry_delay_seconds": 301}},
        ),
        (
            "duplicate retry state",
            _nested(
                spec,
                "retry_policy",
                automatically_retry_terminal_states=["FAILED", "FAILED"],
            ),
        ),
        (
            "foreign retry state",
            _nested(
                spec,
                "retry_policy",
                automatically_retry_terminal_states=["CANCELLED"],
            ),
        ),
        (
            "fresh-availability requirement relaxed",
            _nested(
                spec,
                "retry_policy",
                require_fresh_availability_observation_for_unavailable=False,
            ),
        ),
        ("malformed strategy hash", {**spec, "strategy_version_hash": "A" * 64}),
        ("short dataset hash", {**spec, "dataset_version_hash": "1" * 63}),
        ("impossible instant", {**spec, "created_at_utc": "2026-02-30T00:00:00Z"}),
        ("naive instant", {**spec, "created_at_utc": "2026-08-10T00:00:00"}),
        ("comparison level outside the enum", {**spec, "comparison_level": "LEVEL_4"}),
        (
            "money without its envelope",
            {
                **spec,
                "starting_balance": _without(
                    spec["starting_balance"], "schema_version"
                ),
            },
        ),
    )
    assert len(cases) == 23
    for label, document in cases:
        _rejects(validator, document, label)
        _runtime_rejects(_SPEC, document)


def test_the_committed_experiment_record_schema_rejects_every_expressible_violation() -> (  # noqa: E501
    None
):
    validator = _validator(_RECORD)
    record = _baseline(_RECORD, 2)  # QUEUED, so `slot_compatibility` is present
    validator.validate(record)
    compatibility = cast(list[dict[str, Any]], record["slot_compatibility"])
    approximated = {
        **compatibility[0],
        "outcome": "SUPPORTED_WITH_APPROXIMATION",
        "approximation_ids": [_APPX, _APPX],
    }
    cases: tuple[tuple[str, dict[str, Any]], ...] = (
        ("unknown field", {**record, "owner": "me"}),
        ("state outside the enum", {**record, "state": "PAUSED"}),
        ("negative revision", {**record, "revision": -1}),
        ("float revision", {**record, "revision": 1.5}),
        ("malformed experiment id", {**record, "experiment_id": "exp_not-a-uuid"}),
        (
            "correlation id with whitespace",
            {**record, "state": "CANCELLED", "cancellation_correlation_id": "c 1"},
        ),
        (
            "compatibility outcome outside the enum",
            {**record, "slot_compatibility": [{**compatibility[0], "outcome": "X"}]},
        ),
        (
            "duplicate approximation identifiers",
            {**record, "slot_compatibility": [approximated, compatibility[1]]},
        ),
        ("spec missing", _without(record, "spec")),
    )
    assert len(cases) == 9
    for label, document in cases:
        _rejects(validator, document, label)
        _runtime_rejects(_RECORD, document)


def test_the_committed_engine_run_record_schema_rejects_every_expressible_violation() -> (  # noqa: E501
    None
):
    validator = _validator(_RUN)
    run = _baseline(_RUN, 5)  # FAILED
    validator.validate(run)
    cases: tuple[tuple[str, dict[str, Any]], ...] = (
        ("unknown field", {**run, "pid": 4321}),
        ("attempt number zero", {**run, "attempt_number": 0}),
        ("attempt number six", {**run, "attempt_number": 6}),
        ("state outside the enum", {**run, "state": "PAUSED"}),
        ("retry reason outside the enum", {**run, "retry_reason": "CANCELLED"}),
        (
            "malformed predecessor id",
            {**run, "predecessor_run_id": f"exp_{_UUID_TAIL}"},
        ),
        (
            "impossible finalization deadline",
            {**run, "finalization_deadline_utc": "2026-01-01T24:00:00Z"},
        ),
        ("adapter without a version", {**run, "adapter": {"adapter_name": "a.b"}}),
    )
    assert len(cases) == 8
    for label, document in cases:
        _rejects(validator, document, label)
        _runtime_rejects(_RUN, document)


def test_the_committed_command_invocation_schema_rejects_every_expressible_violation() -> (  # noqa: E501
    None
):
    validator = _validator(_INVOCATION)
    exited = _baseline(_INVOCATION, 3)  # RUN, EXITED with native exit 0
    validator.validate(exited)
    cases: tuple[tuple[str, dict[str, Any]], ...] = (
        ("unknown field", {**exited, "exit_code": 0}),
        ("timeout below one", {**exited, "timeout_seconds": 0}),
        ("timeout above the run bound", {**exited, "timeout_seconds": 604801}),
        ("native exit below the span", {**exited, "native_exit_value": -2147483649}),
        ("native exit above the span", {**exited, "native_exit_value": 4294967296}),
        ("fractional native exit", {**exited, "native_exit_value": 0.5}),
        (
            "exit category outside the eight",
            {**exited, "process_exit_category": "UNKNOWN_AFTER_RESTART"},
        ),
        ("command kind outside the enum", {**exited, "command_kind": "INSPECT"}),
        ("state outside the enum", {**exited, "state": "SUSPENDED"}),
        ("pid zero", _nested(exited, "pid_identity", pid=0)),
        (
            "executable path with a leading space",
            _nested(exited, "pid_identity", executable_path=" C:\\a.exe"),
        ),
        ("duplicate diagnostic identifiers", {**exited, "diagnostic_ids": [_DIAG] * 2}),
        ("string process_created", {**exited, "process_created": "true"}),
    )
    assert len(cases) == 13
    for label, document in cases:
        _rejects(validator, document, label)
        _runtime_rejects(_INVOCATION, document)


def test_the_committed_retry_and_aggregation_schemas_reject_every_expressible_violation() -> (  # noqa: E501
    None
):
    policy_validator = _validator(_POLICY)
    decision_validator = _validator(_DECISION)
    result_validator = _validator(_RESULT)
    policy = _baseline(_POLICY)
    allowed = _baseline(_DECISION, 1)
    result = _baseline(_RESULT, 1)
    policy_validator.validate(policy)
    decision_validator.validate(allowed)
    result_validator.validate(result)
    states = "automatically_retry_terminal_states"
    policy_cases: tuple[tuple[str, dict[str, Any]], ...] = (
        ("unknown field", {**policy, "backoff": "exponential"}),
        ("four retry states", {**policy, states: ["FAILED"] * 4}),
        ("retry states as a string", {**policy, states: "FAILED"}),
        ("delay below zero", {**policy, "retry_delay_seconds": -1}),
        ("missing delay", _without(policy, "retry_delay_seconds")),
    )
    decision_cases: tuple[tuple[str, dict[str, Any]], ...] = (
        ("unknown field", {**allowed, "successor_run_id": f"run_{_UUID_TAIL}"}),
        ("outcome outside the enum", {**allowed, "outcome": "DEFERRED"}),
        ("denial reason outside the enum", {**allowed, "denial_reason": "VETO"}),
        ("reserved number one", {**allowed, "reserved_successor_attempt_number": 1}),
        ("reserved number six", {**allowed, "reserved_successor_attempt_number": 6}),
        ("created count zero", {**allowed, "created_attempt_count": 0}),
        ("created count six", {**allowed, "created_attempt_count": 6}),
        ("lowercase hard-block code", {**allowed, "hard_block_error_code": "core.x"}),
        (
            "impossible not-before instant",
            {**allowed, "retry_not_before_utc": "2100-02-29T00:00:00Z"},
        ),
        (
            "policy missing its envelope",
            {
                **allowed,
                "retry_policy": _without(allowed["retry_policy"], "schema_version"),
            },
        ),
    )
    many = [f"EXPERIMENT.CODE_{index:02d}" for index in range(33)]
    result_cases: tuple[tuple[str, dict[str, Any]], ...] = (
        ("unknown field", {**result, "score": 1}),
        ("verdict outside the enum", {**result, "verdict": "PARTIAL"}),
        ("duplicate reason codes", {**result, "reason_codes": ["EXPERIMENT.X"] * 2}),
        ("lowercase reason code", {**result, "reason_codes": ["experiment.slot"]}),
        ("unnamespaced reason code", {**result, "reason_codes": ["FAILED"]}),
        ("thirty-three reason codes", {**result, "reason_codes": many}),
    )
    assert (len(policy_cases), len(decision_cases), len(result_cases)) == (5, 10, 6)
    for label, document in policy_cases:
        _rejects(policy_validator, document, label)
        _runtime_rejects(_POLICY, document)
    for label, document in decision_cases:
        _rejects(decision_validator, document, label)
        _runtime_rejects(_DECISION, document)
    for label, document in result_cases:
        _rejects(result_validator, document, label)
        _runtime_rejects(_RESULT, document)


def test_the_stage_five_runtime_only_rules_stay_one_directional() -> None:
    """The recorded residuals: the published bytes are a superset of the runtime.

    Each document below is ACCEPTED by the committed schema and REJECTED by the
    runtime validator, which is the safe direction (no runtime-valid record is
    refused). They are pinned so a residual cannot silently invert into an
    over-rejection or widen unnoticed; docs/development/verification.md records
    each one. `finalization_deadline_utc` is the plan's own Task 9 residual: it is
    published as an optional property that the Stage 5 runtime always rejects.
    """
    spec = _baseline(_SPEC)
    draft = _baseline(_RECORD, 0)
    queued = _baseline(_RECORD, 2)
    ready = _baseline(_RUN, 2)
    failed = _baseline(_RUN, 5)
    exited = _baseline(_INVOCATION, 3)
    denied = _baseline(_DECISION, 0)
    allowed = _baseline(_DECISION, 1)
    result = _baseline(_RESULT, 1)
    slots = cast(list[dict[str, Any]], spec["selected_engine_slots"])
    swapped = [{**slots[0], "slot_ordinal": 1}, {**slots[1], "slot_ordinal": 0}]
    residuals: tuple[tuple[str, str, dict[str, Any]], ...] = (
        (
            _SPEC,
            "non-positive starting balance (the released Money schema is frozen)",
            _nested(spec, "starting_balance", amount="0"),
        ),
        (_SPEC, "slot ordinals not 0..n-1", {**spec, "selected_engine_slots": swapped}),
        (
            _SPEC,
            "basis points present under slippage model NONE",
            {**spec, "slippage_assumptions": {"model": "NONE", "basis_points": "5"}},
        ),
        (
            _RECORD,
            "slot_compatibility present before QUEUED",
            {**draft, "slot_compatibility": queued["slot_compatibility"]},
        ),
        (
            _RECORD,
            "cancellation_correlation_id outside CANCELLED",
            {**queued, "cancellation_correlation_id": "cancel-1"},
        ),
        (
            _RECORD,
            "spec_hash disagreeing with the spec",
            {**queued, "spec_hash": "f" * 64},
        ),
        (
            _RECORD,
            "updated_at_utc before created_at_utc",
            {**queued, "updated_at_utc": "2000-01-01T00:00:00Z"},
        ),
        (
            _RUN,
            "finalization_deadline_utc present (plan 3.8 row 15, Task 9)",
            {**ready, "finalization_deadline_utc": "2026-09-08T00:00:00Z"},
        ),
        (
            _RUN,
            "successor without predecessor and reason",
            {**ready, "attempt_number": 2},
        ),
        (
            _RUN,
            "non-success terminal without primary_terminal_diagnostic_id",
            _without(failed, "primary_terminal_diagnostic_id"),
        ),
        (
            _INVOCATION,
            "process_exit_category disagreeing with the frozen native-exit mapping",
            {**exited, "process_exit_category": "CANCELLED"},
        ),
        (
            _INVOCATION,
            "timeout above the DESCRIBE bound (the schema carries the RUN envelope)",
            {**exited, "command_kind": "DESCRIBE", "timeout_seconds": 301},
        ),
        (
            _INVOCATION,
            "primary_diagnostic_id outside diagnostic_ids",
            {**exited, "primary_diagnostic_id": _DIAG, "diagnostic_ids": []},
        ),
        (
            _INVOCATION,
            "deadline_utc not launch_attempted_at_utc + timeout_seconds",
            {**exited, "deadline_utc": "2026-09-07T12:00:02Z"},
        ),
        (
            _DECISION,
            "DENIED decision carrying retry_not_before_utc",
            {**denied, "retry_not_before_utc": allowed["retry_not_before_utc"]},
        ),
        (
            _DECISION,
            "reserved_successor_attempt_number not created_attempt_count + 1",
            {**allowed, "reserved_successor_attempt_number": 3},
        ),
        (
            _DECISION,
            "predecessor_terminal_state SUCCEEDED (plan 3.9 residual)",
            {**allowed, "predecessor_terminal_state": "SUCCEEDED"},
        ),
        (
            _RESULT,
            "unsorted reason codes (unbounded domain, sortedness inexpressible)",
            {**result, "reason_codes": list(reversed(result["reason_codes"]))},
        ),
    )
    assert len(residuals) == 18
    for name, label, document in residuals:
        _validator(name).validate(document)
        _runtime_rejects(name, document)
        assert label
