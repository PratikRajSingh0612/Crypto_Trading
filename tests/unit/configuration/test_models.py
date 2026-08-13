from __future__ import annotations

import json

import pytest
from pydantic import BaseModel, ValidationError

from crypto_lab.configuration.models import (
    AdapterEntryConfig,
    AdaptersConfig,
    ApplicationConfig,
    CliOverrides,
    ConfigurationLayer,
    DatabaseConfig,
    LoggingConfig,
    PathsConfig,
    PolicyConfig,
    ProcessConfig,
    ProtocolConfig,
    RetryConfig,
    SchedulerConfig,
)

_HASH = "a" * 64


def _adapter(name: str, version: str) -> AdapterEntryConfig:
    return AdapterEntryConfig(
        adapter_name=name,
        adapter_version=version,
        executable_path=r"C:\adapters\adapter.exe",
        executable_hash=_HASH,
    )


def test_compiled_defaults_match_the_fixed_table() -> None:
    config = ApplicationConfig()
    assert config.schema_version == "1.0.0"
    assert config.paths.model_dump() == {
        "runtime_root": "runtime",
        "data_root": "data",
        "artifacts_root": "artifacts",
        "logs_root": "logs",
        "runtimes_root": "runtimes",
    }
    assert config.database == DatabaseConfig()
    assert config.scheduler == SchedulerConfig()
    assert config.process == ProcessConfig()
    assert config.protocol == ProtocolConfig()
    assert config.logging == LoggingConfig()
    assert config.adapters == AdaptersConfig()
    assert config.policy == PolicyConfig()


@pytest.mark.parametrize(
    ("model_type", "payload"),
    [
        (PathsConfig, {"unexpected": 1}),
        (DatabaseConfig, {"unexpected": 1}),
        (RetryConfig, {"unexpected": 1}),
        (SchedulerConfig, {"unexpected": 1}),
        (ProcessConfig, {"unexpected": 1}),
        (ProtocolConfig, {"unexpected": 1}),
        (LoggingConfig, {"unexpected": 1}),
        (AdaptersConfig, {"unexpected": 1}),
        (PolicyConfig, {"unexpected": 1}),
        (ApplicationConfig, {"unexpected": 1}),
        (ConfigurationLayer, {"schema_version": "1.0.0", "unexpected": 1}),
    ],
)
def test_every_configuration_boundary_rejects_unknown_fields(
    model_type: type[BaseModel],
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        model_type.model_validate(payload)


def test_nested_partial_layer_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ConfigurationLayer.model_validate(
            {
                "schema_version": "1.0.0",
                "scheduler": {"retry": {"unexpected": 1}},
            }
        )


@pytest.mark.parametrize(
    "section",
    [
        "paths",
        "database",
        "scheduler",
        "process",
        "protocol",
        "logging",
        "adapters",
        "policy",
    ],
)
def test_every_partial_section_rejects_unknown_fields(section: str) -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ConfigurationLayer.model_validate(
            {"schema_version": "1.0.0", section: {"unexpected": 1}}
        )


@pytest.mark.parametrize(
    "payload",
    [
        {"database": {"busy_timeout_ms": 99}},
        {"database": {"busy_timeout_ms": 60001}},
        {"scheduler": {"max_concurrent_runs": 0}},
        {"scheduler": {"max_concurrent_runs": 9}},
        {"scheduler": {"retry": {"maximum_attempts_per_slot": 0}}},
        {"scheduler": {"retry": {"maximum_attempts_per_slot": 6}}},
        {"scheduler": {"retry": {"retry_delay_seconds": -1}}},
        {"scheduler": {"retry": {"retry_delay_seconds": 301}}},
        {"process": {"heartbeat_interval_seconds": 0}},
        {"process": {"heartbeat_interval_seconds": 301}},
        {"process": {"missing_heartbeat_seconds": 1}},
        {"process": {"missing_heartbeat_seconds": 901}},
        {"process": {"describe_timeout_seconds": 0}},
        {"process": {"describe_timeout_seconds": 301}},
        {"process": {"validate_timeout_seconds": 0}},
        {"process": {"validate_timeout_seconds": 1801}},
        {"process": {"default_run_timeout_seconds": 0}},
        {"process": {"default_run_timeout_seconds": 604801}},
        {"process": {"finalization_timeout_seconds": 0}},
        {"process": {"finalization_timeout_seconds": 3601}},
        {"process": {"cancellation_grace_seconds": -1}},
        {"process": {"cancellation_grace_seconds": 301}},
        {"protocol": {"max_event_bytes": 4095}},
        {"protocol": {"max_event_bytes": 1048577}},
        {"protocol": {"max_manifest_bytes": 65535}},
        {"protocol": {"max_manifest_bytes": 16777217}},
        {"logging": {"max_stderr_bytes_per_invocation": 1048575}},
        {"logging": {"max_stderr_bytes_per_invocation": 52428801}},
        {"logging": {"retained_files": 0}},
        {"logging": {"retained_files": 101}},
    ],
)
def test_numeric_values_fail_outside_the_fixed_bounds(
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        ApplicationConfig.model_validate(payload)


@pytest.mark.parametrize(
    "payload",
    [
        {"database": {"busy_timeout_ms": 100}},
        {"database": {"busy_timeout_ms": 60_000}},
        {"scheduler": {"max_concurrent_runs": 1}},
        {"scheduler": {"max_concurrent_runs": 8}},
        {"scheduler": {"retry": {"maximum_attempts_per_slot": 1}}},
        {"scheduler": {"retry": {"maximum_attempts_per_slot": 5}}},
        {"scheduler": {"retry": {"retry_delay_seconds": 0}}},
        {"scheduler": {"retry": {"retry_delay_seconds": 300}}},
        {
            "process": {
                "heartbeat_interval_seconds": 1,
                "missing_heartbeat_seconds": 2,
            }
        },
        {
            "process": {
                "heartbeat_interval_seconds": 300,
                "missing_heartbeat_seconds": 900,
            }
        },
        {"process": {"describe_timeout_seconds": 1}},
        {"process": {"describe_timeout_seconds": 300}},
        {"process": {"validate_timeout_seconds": 1}},
        {"process": {"validate_timeout_seconds": 1_800}},
        {"process": {"default_run_timeout_seconds": 1}},
        {"process": {"default_run_timeout_seconds": 604_800}},
        {"process": {"finalization_timeout_seconds": 1}},
        {"process": {"finalization_timeout_seconds": 3_600}},
        {"process": {"cancellation_grace_seconds": 0}},
        {"process": {"cancellation_grace_seconds": 300}},
        {"protocol": {"max_event_bytes": 4_096}},
        {"protocol": {"max_event_bytes": 1_048_576}},
        {"protocol": {"max_manifest_bytes": 65_536}},
        {"protocol": {"max_manifest_bytes": 16_777_216}},
        {"logging": {"max_stderr_bytes_per_invocation": 1_048_576}},
        {"logging": {"max_stderr_bytes_per_invocation": 52_428_800}},
        {"logging": {"retained_files": 1}},
        {"logging": {"retained_files": 100}},
    ],
)
def test_numeric_values_accept_both_fixed_bounds(payload: dict[str, object]) -> None:
    ApplicationConfig.model_validate(payload)


def test_heartbeat_ratio_and_retry_normalization() -> None:
    with pytest.raises(ValidationError, match="at least twice"):
        ProcessConfig(
            heartbeat_interval_seconds=30,
            missing_heartbeat_seconds=59,
        )
    retry = RetryConfig.model_validate(
        {"automatically_retry_terminal_states": ("UNAVAILABLE", "FAILED")}
    )
    assert retry.automatically_retry_terminal_states == (
        "FAILED",
        "UNAVAILABLE",
    )
    with pytest.raises(ValidationError, match="unique"):
        RetryConfig.model_validate(
            {"automatically_retry_terminal_states": ("FAILED", "FAILED")}
        )
    with pytest.raises(ValidationError, match="foreign"):
        RetryConfig.model_validate(
            {"automatically_retry_terminal_states": ("CANCELLED",)}
        )
    with pytest.raises(ValidationError):
        RetryConfig.model_validate(
            {"require_fresh_availability_observation_for_unavailable": False}
        )


def test_adapter_catalog_is_sorted_unique_and_rejects_secret_like_keys() -> None:
    first = _adapter("adapter.alpha", "1.0.0")
    second = _adapter("adapter.beta", "1.0.0")
    assert AdaptersConfig(entries=(first, second)).entries == (first, second)
    with pytest.raises(ValidationError, match="ordered"):
        AdaptersConfig(entries=(second, first))
    with pytest.raises(ValidationError, match="unique"):
        AdaptersConfig(entries=(first, first))
    colliding = first.model_copy(update={"executable_hash": "b" * 64})
    with pytest.raises(ValidationError, match="unique"):
        AdaptersConfig(entries=(first, colliding))
    with pytest.raises(ValidationError, match="secret-like"):
        AdapterEntryConfig(
            adapter_name="adapter.alpha",
            adapter_version="1.0.0",
            executable_path=r"C:\adapter.exe",
            executable_hash=_HASH,
            runtime_metadata={"nested": {"nested_api_key_value": "forbidden"}},
        )
    for invalid_metadata in (
        {"attempt_token": "raw-token-is-forbidden"},
        {"apiKey": "forbidden"},
        {"accessToken": "forbidden"},
        {"authToken": "forbidden"},
        {"attemptToken": "forbidden"},
        {"credentials": "forbidden"},
        {"ratio": 0.5},
        {"count": 2**63},
        {"count": -(2**63) - 1},
    ):
        with pytest.raises(ValidationError):
            AdapterEntryConfig.model_validate(
                {
                    "adapter_name": "adapter.alpha",
                    "adapter_version": "1.0.0",
                    "executable_path": r"C:\adapter.exe",
                    "executable_hash": _HASH,
                    "runtime_metadata": invalid_metadata,
                }
            )


def test_runtime_metadata_rejects_depth_nodes_and_encoded_bytes() -> None:
    nested: object = "leaf"
    for _ in range(10):
        nested = {"nested": nested}
    groups = [{f"key{index}": index for index in range(64)} for _ in range(4)]
    for metadata, message in (
        ({"root": nested}, "maximum depth"),
        ({"groups": groups}, "too many nodes"),
        ({"payload": ["x" * 2_048 for _ in range(8)]}, "encoded bytes"),
    ):
        with pytest.raises(ValidationError, match=message):
            AdapterEntryConfig.model_validate(
                {
                    "adapter_name": "adapter.alpha",
                    "adapter_version": "1.0.0",
                    "executable_path": r"C:\adapter.exe",
                    "executable_hash": _HASH,
                    "runtime_metadata": metadata,
                }
            )


def test_adapter_catalog_has_a_compiled_maximum_of_32_entries() -> None:
    entries = tuple(
        _adapter(f"adapter.item{index:02d}", "1.0.0") for index in range(32)
    )
    assert AdaptersConfig(entries=entries).entries == entries
    with pytest.raises(ValidationError):
        AdaptersConfig(
            entries=(
                *entries,
                _adapter("adapter.overflow", "1.0.0"),
            )
        )


@pytest.mark.parametrize(
    "value",
    [
        r"C:drive-relative",
        r"\rooted-without-drive",
        r"\\server\share",
        "folder//child",
        "folder/./child",
        "folder/name:stream",
        "folder/CON",
        "folder/trailing. ",
        "folder/root?/file",
        "folder/bad<name",
        "folder/control\x1f",
    ],
)
def test_application_path_models_reject_unsafe_windows_syntax(value: str) -> None:
    with pytest.raises(ValidationError):
        PathsConfig(runtime_root=value)


def test_emitted_path_patterns_are_ecma_262_portable() -> None:
    encoded = json.dumps(ApplicationConfig.model_json_schema(mode="serialization"))
    assert "(?i" not in encoded
    assert "[Aa][Uu][Xx]" in encoded


@pytest.mark.parametrize(
    "value",
    [
        "relative.exe",
        r"\\server\share\adapter.exe",
        r"C:\adapters\bad?.exe",
        r"C:\adapters\CON.exe",
        r"C:\adapters\name.exe:stream",
    ],
)
def test_adapter_executable_requires_safe_absolute_local_path(value: str) -> None:
    with pytest.raises(ValidationError):
        AdapterEntryConfig(
            adapter_name="adapter.alpha",
            adapter_version="1.0.0",
            executable_path=value,
            executable_hash=_HASH,
        )


def test_policy_is_literal_false_and_cli_surface_is_closed() -> None:
    for field in ("allow_network", "allow_credentials", "allow_live"):
        with pytest.raises(ValidationError):
            PolicyConfig.model_validate({field: True})
    assert set(CliOverrides.model_fields) == {
        "runtime_root",
        "data_root",
        "artifacts_root",
        "logs_root",
        "runtimes_root",
        "max_concurrent_runs",
        "maximum_attempts_per_slot",
        "automatically_retry_terminal_states",
        "retry_delay_seconds",
        "heartbeat_interval_seconds",
        "missing_heartbeat_seconds",
        "describe_timeout_seconds",
        "validate_timeout_seconds",
        "default_run_timeout_seconds",
        "finalization_timeout_seconds",
        "cancellation_grace_seconds",
    }
    with pytest.raises(ValidationError, match="extra_forbidden"):
        CliOverrides.model_validate({"allow_network": False})


def test_filename_path_and_foreign_policy_keys_are_rejected() -> None:
    for filename in (
        "../database.sqlite3",
        "CON",
        "nul.sqlite3",
        "database.sqlite3.",
        "database.sqlite3 ",
        "database:stream",
    ):
        with pytest.raises(ValidationError):
            DatabaseConfig(filename=filename)
    with pytest.raises(ValidationError):
        PathsConfig(runtime_root="")
    for key in ("shell", "shorting", "margin", "futures", "leverage"):
        with pytest.raises(ValidationError, match="extra_forbidden"):
            PolicyConfig.model_validate({key: False})
