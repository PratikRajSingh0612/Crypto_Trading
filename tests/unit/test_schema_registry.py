from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError

from crypto_lab.schema_registry import (
    JSON_SCHEMA_DRAFT,
    SCHEMA_DEFINITIONS,
    render_schema_files,
)
from generate_schemas import _check, _write

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
}


def _schemas() -> dict[PurePosixPath, dict[str, Any]]:
    return {
        path: cast(dict[str, Any], json.loads(contents))
        for path, contents in render_schema_files().items()
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


def test_registry_has_exactly_the_closed_eleven_paths_and_ids() -> None:
    assert {
        definition.relative_path: definition.schema_id
        for definition in SCHEMA_DEFINITIONS
    } == _EXPECTED
    assert len(SCHEMA_DEFINITIONS) == 11


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
