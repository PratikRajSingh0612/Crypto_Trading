from __future__ import annotations

import pytest
from pydantic import JsonValue, ValidationError

from crypto_lab.configuration.models import (
    AdapterEntryConfig,
    AdaptersConfig,
    ApplicationConfig,
    DatabaseConfig,
    LoggingConfig,
    PathsConfig,
    ProcessConfig,
    ProtocolConfig,
    RetryConfig,
    SchedulerConfig,
)
from crypto_lab.configuration.snapshot import (
    ConfigSnapshot,
    configuration_audit_hash,
    material_base_configuration_hash,
    snapshot_configuration,
)
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.hashing import HashingProfile, profile_hash


def _replace(
    config: ApplicationConfig,
    field: str,
    value: object,
) -> ApplicationConfig:
    payload = config.model_dump(mode="python")
    payload[field] = value
    return ApplicationConfig.model_validate(payload)


def _catalog() -> AdaptersConfig:
    return AdaptersConfig(
        entries=(
            AdapterEntryConfig(
                adapter_name="adapter.alpha",
                adapter_version="1.0.0",
                executable_path=r"C:\adapter.exe",
                executable_hash="a" * 64,
            ),
        )
    )


def test_audit_hash_changes_for_every_configuration_section() -> None:
    base = ApplicationConfig()
    variants = (
        _replace(base, "paths", PathsConfig(runtime_root="other")),
        _replace(base, "database", DatabaseConfig(busy_timeout_ms=6000)),
        _replace(
            base,
            "scheduler",
            SchedulerConfig(max_concurrent_runs=2, retry=base.scheduler.retry),
        ),
        _replace(base, "process", ProcessConfig(describe_timeout_seconds=31)),
        _replace(base, "protocol", ProtocolConfig(max_event_bytes=4097)),
        _replace(
            base,
            "logging",
            LoggingConfig(
                max_stderr_bytes_per_invocation=52_428_800,
                retained_files=11,
            ),
        ),
        _replace(base, "adapters", _catalog()),
    )
    baseline = configuration_audit_hash(base)
    assert all(configuration_audit_hash(item) != baseline for item in variants)


def test_material_hash_has_the_exact_operational_exclusions() -> None:
    base = ApplicationConfig()
    variants = (
        _replace(base, "paths", PathsConfig(runtime_root="other")),
        _replace(base, "database", DatabaseConfig(busy_timeout_ms=6000)),
        _replace(
            base,
            "scheduler",
            SchedulerConfig(max_concurrent_runs=2, retry=base.scheduler.retry),
        ),
        _replace(
            base,
            "logging",
            LoggingConfig(
                max_stderr_bytes_per_invocation=(
                    base.logging.max_stderr_bytes_per_invocation
                ),
                retained_files=11,
            ),
        ),
        _replace(base, "adapters", _catalog()),
    )
    baseline = material_base_configuration_hash(base)
    assert all(material_base_configuration_hash(item) == baseline for item in variants)


def test_material_hash_changes_for_each_variable_material_section() -> None:
    base = ApplicationConfig()
    variants = (
        _replace(
            base,
            "scheduler",
            SchedulerConfig(retry=RetryConfig(maximum_attempts_per_slot=2)),
        ),
        _replace(base, "process", ProcessConfig(describe_timeout_seconds=31)),
        _replace(base, "protocol", ProtocolConfig(max_event_bytes=4097)),
        _replace(
            base,
            "logging",
            LoggingConfig(max_stderr_bytes_per_invocation=1_048_576),
        ),
    )
    baseline = material_base_configuration_hash(base)
    assert all(material_base_configuration_hash(item) != baseline for item in variants)


def test_fixed_policy_is_present_in_the_material_projection() -> None:
    config = ApplicationConfig()
    payload: dict[str, JsonValue] = {
        "scheduler": {"retry": config.scheduler.retry.model_dump(mode="json")},
        "process": config.process.model_dump(mode="json"),
        "protocol": config.protocol.model_dump(mode="json"),
        "logging": {
            "max_stderr_bytes_per_invocation": (
                config.logging.max_stderr_bytes_per_invocation
            )
        },
        "policy": config.policy.model_dump(mode="json"),
    }
    assert material_base_configuration_hash(config) == profile_hash(
        HashingProfile.CONFIGURATION_MATERIAL_BASE_V1,
        payload,
    )


def test_snapshot_and_hashes_are_deterministic_under_key_ordering() -> None:
    left = ApplicationConfig.model_validate(
        {"scheduler": {"max_concurrent_runs": 2}, "schema_version": "1.0.0"}
    )
    right = ApplicationConfig.model_validate(
        {"schema_version": "1.0.0", "scheduler": {"max_concurrent_runs": 2}}
    )
    left_snapshot = snapshot_configuration(left)
    right_snapshot = snapshot_configuration(right)
    assert left_snapshot == right_snapshot
    assert canonical_json_bytes(left_snapshot) == canonical_json_bytes(right_snapshot)
    assert left_snapshot.configuration_audit_hash == configuration_audit_hash(left)


def test_snapshot_retains_immutable_canonical_text_after_source_mutation() -> None:
    config = ApplicationConfig(adapters=_catalog())
    entry = config.adapters.entries[0]
    entry.runtime_metadata["nested"] = {"mode": "safe"}
    snapshot = snapshot_configuration(config)
    snapshot_bytes = canonical_json_bytes(snapshot)
    entry.runtime_metadata["nested"] = {"mode": "changed"}
    assert canonical_json_bytes(snapshot) == snapshot_bytes
    restored = ApplicationConfig.model_validate_json(snapshot.configuration_json)
    assert restored.adapters.entries[0].runtime_metadata == {"nested": {"mode": "safe"}}


def test_hash_and_snapshot_boundaries_revalidate_mutated_nested_metadata() -> None:
    config = ApplicationConfig(adapters=_catalog())
    config.adapters.entries[0].runtime_metadata["customer_api_key"] = "forbidden"
    with pytest.raises(ValidationError, match="secret-like"):
        configuration_audit_hash(config)
    with pytest.raises(ValidationError, match="secret-like"):
        material_base_configuration_hash(config)
    with pytest.raises(ValidationError, match="secret-like"):
        snapshot_configuration(config)


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        (
            "configuration_json",
            '{ "schema_version": "1.0.0" }',
            "not canonical",
        ),
        ("configuration_audit_hash", "b" * 64, "audit hash mismatch"),
        (
            "material_base_configuration_hash",
            "c" * 64,
            "material hash mismatch",
        ),
    ],
)
def test_direct_snapshot_validation_recomputes_every_derived_field(
    field: str,
    replacement: str,
    message: str,
) -> None:
    payload = snapshot_configuration(ApplicationConfig()).model_dump(mode="python")
    payload[field] = replacement
    with pytest.raises(ValidationError, match=message):
        ConfigSnapshot.model_validate(payload)


def test_direct_snapshot_json_rejects_invalid_config_without_echo() -> None:
    marker = "INPUT_MARKER_MUST_NOT_APPEAR"
    payload = snapshot_configuration(ApplicationConfig()).model_dump(mode="json")
    payload["configuration_json"] = f'{{"schema_version":"1.0.0","{marker}":1}}'
    encoded = canonical_json_bytes(payload)
    with pytest.raises(ValidationError, match="snapshot JSON is invalid") as captured:
        ConfigSnapshot.model_validate_json(encoded)
    assert marker not in str(captured.value)


def test_direct_snapshot_validation_enforces_utf8_byte_ceiling_before_parse() -> None:
    payload = snapshot_configuration(ApplicationConfig()).model_dump(mode="python")
    payload["configuration_json"] = "é" * 600_000
    with pytest.raises(ValidationError, match="maximum encoded bytes"):
        ConfigSnapshot.model_validate(payload)


def test_largest_adapter_catalog_remains_snapshot_eligible() -> None:
    entries = tuple(
        AdapterEntryConfig(
            adapter_name=f"adapter.item{index:02d}",
            adapter_version="1.0.0",
            executable_path=rf"C:\adapters\item{index:02d}.exe",
            executable_hash="a" * 64,
            runtime_metadata={"description": "x" * 2_048},
        )
        for index in range(32)
    )
    snapshot = snapshot_configuration(
        ApplicationConfig(adapters=AdaptersConfig(entries=entries))
    )
    assert len(snapshot.configuration_json.encode("utf-8")) <= 1_048_576
