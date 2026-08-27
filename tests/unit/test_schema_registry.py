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
from crypto_lab.domain.descriptors import (
    _EXECUTABLE_PATH_SCHEMA_PATTERN,
    MAX_EXECUTABLE_PATH_CHARACTERS,
    AdapterDescriptor,
    EngineDescriptor,
    RuntimeAvailabilityObservation,
)
from crypto_lab.domain.diagnostics import Diagnostic
from crypto_lab.domain.identifiers import exact_string_schema
from crypto_lab.domain.records import InstrumentRef, Money, Price, Quantity
from crypto_lab.domain.results import Success
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


def test_registry_has_exactly_the_closed_twenty_paths_and_ids() -> None:
    assert {
        definition.relative_path: definition.schema_id
        for definition in SCHEMA_DEFINITIONS
    } == _EXPECTED
    assert len(SCHEMA_DEFINITIONS) == 20


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


# --- Task 8: the closed twenty-entry registry ----------------------------------
#
# `_EXPECTED` above is keyed by path, so a set comparison against it proves
# membership but says nothing about *order*, about which adapter renders which
# `$id`, or about the bytes on disk. A published `$id` is a permanent contract
# and the eleven Stage 3 entries are frozen output, so the assertions below pin
# the ordered tuples, the per-entry adapter, and the on-disk bytes as well.

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

# Two entries register a module-level adapter singleton rather than a fresh
# `TypeAdapter`, so identity is the exact assertion for them and the adapted
# type is the exact assertion for the other eighteen.
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
    assert _ordered_paths()[11:] == _STAGE4_PATHS
    assert len(_STAGE4_PATHS) == 9


def test_the_ordered_path_and_identifier_tuples_are_exact_and_unique() -> None:
    paths = _ordered_paths()
    identifiers = tuple(definition.schema_id for definition in SCHEMA_DEFINITIONS)
    assert paths == _STAGE3_PATHS + _STAGE4_PATHS
    assert identifiers == tuple(
        _EXPECTED[PurePosixPath(name)] for name in _STAGE3_PATHS + _STAGE4_PATHS
    )
    assert len(paths) == 20
    assert len(set(paths)) == 20
    assert len(set(identifiers)) == 20


def test_every_registry_entry_carries_its_exact_adapter() -> None:
    assert len(_EXPECTED_ADAPTER_SINGLETONS) + len(_EXPECTED_ADAPTED_TYPES) == 20
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
    assert len(rendered) == 20
    for path, contents in rendered.items():
        target = root.joinpath(*path.parts)
        assert target.is_file(), path
        assert target.read_bytes() == contents, path


def test_the_schemas_directory_holds_exactly_the_twenty_registered_files() -> None:
    root = _REPOSITORY_ROOT / "schemas"
    found = tuple(
        sorted(
            candidate.relative_to(root).as_posix()
            for candidate in root.rglob("*")
            if candidate.is_file()
        )
    )
    assert found == tuple(sorted(_STAGE3_PATHS + _STAGE4_PATHS))


def test_every_committed_schema_file_is_valid_draft_2020_12_json() -> None:
    root = _REPOSITORY_ROOT / "schemas"
    for name in _STAGE3_PATHS + _STAGE4_PATHS:
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
