"""Stage 6 Task 1: the compiled protocol limits and the `ProtocolLimits`
snapshot (Stage 6 plan section 3.2).

Every constant is asserted by value and type, the public constant surface is
asserted closed, every `ProtocolLimits` bound is exercised at both edges and one
beyond on each side, and the configuration-derived literals are proven equal to
the `configuration` bounds they mirror: the plan copies them as literals so that
`adapters` needs no `configuration` import, and this test is what keeps the two
copies equal.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel, TypeAdapter, ValidationError

from crypto_lab.adapters import limits
from crypto_lab.adapters.limits import PROTOCOL_LIMITS_DEFAULT, ProtocolLimits
from crypto_lab.configuration.models import (
    AdaptersConfig,
    LoggingConfig,
    ProcessConfig,
    ProtocolConfig,
)
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.command_invocation import MAX_DIAGNOSTIC_IDS
from crypto_lab.domain.diagnostics import Diagnostic

#: Plan section 3.2, read literally.
_EXPECTED_CONSTANTS: dict[str, object] = {
    "PROTOCOL_VERSION": "1.0.0",
    "MAX_EVENT_LINE_BYTES": 1_048_576,
    "MIN_EVENT_LINE_BYTES": 4_096,
    "MAX_RESULT_MANIFEST_BYTES": 16_777_216,
    "MIN_RESULT_MANIFEST_BYTES": 65_536,
    "MAX_STDERR_BYTES": 52_428_800,
    "MIN_STDERR_BYTES": 1_048_576,
    "MAX_DESCRIPTOR_OUTPUT_BYTES": 1_048_576,
    "MAX_VALIDATION_RESULT_BYTES": 1_048_576,
    "MAX_SEQUENCE": 1_000_000,
    "MAX_CANDIDATE_ARTIFACTS": 256,
    "MAX_CANDIDATE_METRICS": 256,
    "MAX_ADAPTER_DIAGNOSTICS": 64,
    "MAX_WARNINGS": 64,
    "MAX_APPROXIMATIONS": 64,
    "MAX_CAUSAL_EVENT_IDS": 32,
    "MAX_DECLARED_SIZE_BYTES": 2**53 - 1,
    "MAX_COUNTER": 2**53 - 1,
    "MAX_RELATIVE_PATH_CHARACTERS": 512,
    "MAX_PATH_SEGMENTS": 32,
    "MAX_SEGMENT_CHARACTERS": 255,
    "MAX_CONTAMINATION_SAMPLE_BYTES": 256,
    "MAX_CATALOG_ENTRIES": 32,
    "RESULT_MANIFEST_RELATIVE_PATH": "adapter-result-manifest.json",
    "HEARTBEAT_INTERVAL_BOUNDS": (1, 300),
    "MISSING_HEARTBEAT_BOUNDS": (2, 900),
}
_FIELD_ORDER = (
    "max_event_bytes",
    "max_manifest_bytes",
    "max_stderr_bytes",
    "heartbeat_interval_seconds",
    "missing_heartbeat_seconds",
)
_DEFAULTS: dict[str, int] = {
    "max_event_bytes": 1_048_576,
    "max_manifest_bytes": 16_777_216,
    "max_stderr_bytes": 52_428_800,
    "heartbeat_interval_seconds": 15,
    "missing_heartbeat_seconds": 45,
}


def _limits(**overrides: int) -> ProtocolLimits:
    return ProtocolLimits.model_validate({**_DEFAULTS, **overrides})


def _schema_property(model: type[BaseModel], field: str) -> dict[str, Any]:
    prop: dict[str, Any] = model.model_json_schema()["properties"][field]
    return prop


@pytest.mark.parametrize(("name", "expected"), sorted(_EXPECTED_CONSTANTS.items()))
def test_each_limit_is_exactly_the_plan_value(name: str, expected: object) -> None:
    actual = getattr(limits, name)
    assert actual == expected
    assert type(actual) is type(expected)


def test_the_public_constant_surface_is_exactly_the_plan_table() -> None:
    """A closed set, not a lower bound: an extra or renamed constant fails here."""
    public = {name for name in vars(limits) if name.isupper()}
    assert public == set(_EXPECTED_CONSTANTS) | {"PROTOCOL_LIMITS_DEFAULT"}


def test_the_collection_bounds_mirror_the_domain_diagnostic_bounds() -> None:
    """Plan 2.2: `MAX_DIAGNOSTIC_IDS` is mirrored by the 3.2 collection bounds,
    and `MAX_CAUSAL_EVENT_IDS` mirrors `Diagnostic.causal_diagnostic_ids`."""
    assert (
        limits.MAX_ADAPTER_DIAGNOSTICS
        == limits.MAX_WARNINGS
        == limits.MAX_APPROXIMATIONS
        == MAX_DIAGNOSTIC_IDS
    )
    causal = _schema_property(Diagnostic, "causal_diagnostic_ids")
    assert causal["maxItems"] == limits.MAX_CAUSAL_EVENT_IDS


def test_the_configuration_bounds_are_copied_as_equal_literals() -> None:
    event = _schema_property(ProtocolConfig, "max_event_bytes")
    manifest = _schema_property(ProtocolConfig, "max_manifest_bytes")
    stderr = _schema_property(LoggingConfig, "max_stderr_bytes_per_invocation")
    interval = _schema_property(ProcessConfig, "heartbeat_interval_seconds")
    missing = _schema_property(ProcessConfig, "missing_heartbeat_seconds")
    assert (event["minimum"], event["maximum"]) == (
        limits.MIN_EVENT_LINE_BYTES,
        limits.MAX_EVENT_LINE_BYTES,
    )
    assert (manifest["minimum"], manifest["maximum"]) == (
        limits.MIN_RESULT_MANIFEST_BYTES,
        limits.MAX_RESULT_MANIFEST_BYTES,
    )
    assert (stderr["minimum"], stderr["maximum"]) == (
        limits.MIN_STDERR_BYTES,
        limits.MAX_STDERR_BYTES,
    )
    assert (interval["minimum"], interval["maximum"]) == (
        limits.HEARTBEAT_INTERVAL_BOUNDS
    )
    assert (missing["minimum"], missing["maximum"]) == limits.MISSING_HEARTBEAT_BOUNDS
    assert _schema_property(AdaptersConfig, "entries")["maxItems"] == (
        limits.MAX_CATALOG_ENTRIES
    )
    assert (event["default"], manifest["default"], stderr["default"]) == (
        limits.MAX_EVENT_LINE_BYTES,
        limits.MAX_RESULT_MANIFEST_BYTES,
        limits.MAX_STDERR_BYTES,
    )
    assert (interval["default"], missing["default"]) == (15, 45)


def test_protocol_limits_declares_exactly_the_plan_fields_in_order() -> None:
    """A nested value object (plan 3.1): no envelope version, every field required."""
    assert tuple(ProtocolLimits.model_fields) == _FIELD_ORDER
    assert "schema_version" not in ProtocolLimits.model_fields
    for field in ProtocolLimits.model_fields.values():
        assert field.is_required()


def test_the_default_snapshot_is_built_from_the_configuration_defaults() -> None:
    assert type(PROTOCOL_LIMITS_DEFAULT) is ProtocolLimits
    assert PROTOCOL_LIMITS_DEFAULT == _limits()
    process = ProcessConfig()
    protocol = ProtocolConfig()
    logging = LoggingConfig()
    assert PROTOCOL_LIMITS_DEFAULT == ProtocolLimits(
        max_event_bytes=protocol.max_event_bytes,
        max_manifest_bytes=protocol.max_manifest_bytes,
        max_stderr_bytes=logging.max_stderr_bytes_per_invocation,
        heartbeat_interval_seconds=process.heartbeat_interval_seconds,
        missing_heartbeat_seconds=process.missing_heartbeat_seconds,
    )


@pytest.mark.parametrize(
    ("field", "low", "high", "companions"),
    [
        ("max_event_bytes", 4_096, 1_048_576, {}),
        ("max_manifest_bytes", 65_536, 16_777_216, {}),
        ("max_stderr_bytes", 1_048_576, 52_428_800, {}),
        # The ratio rule needs a companion at each edge: an interval of 300 needs
        # a threshold of at least 600, and a threshold of 2 needs an interval of 1.
        ("heartbeat_interval_seconds", 1, 300, {"missing_heartbeat_seconds": 600}),
        ("missing_heartbeat_seconds", 2, 900, {"heartbeat_interval_seconds": 1}),
    ],
)
def test_each_bound_accepts_its_edges_and_rejects_one_beyond(
    field: str,
    low: int,
    high: int,
    companions: dict[str, int],
) -> None:
    assert getattr(_limits(**companions, **{field: low}), field) == low
    assert getattr(_limits(**companions, **{field: high}), field) == high
    for outside in (low - 1, high + 1):
        with pytest.raises(ValidationError):
            _limits(**companions, **{field: outside})


@pytest.mark.parametrize(
    ("interval", "missing", "accepted"),
    [
        (15, 30, True),
        (15, 29, False),
        (300, 600, True),
        (300, 599, False),
        (1, 2, True),
        (2, 3, False),
    ],
)
def test_the_missing_heartbeat_threshold_is_at_least_twice_the_interval(
    interval: int,
    missing: int,
    accepted: bool,
) -> None:
    if accepted:
        snapshot = _limits(
            heartbeat_interval_seconds=interval, missing_heartbeat_seconds=missing
        )
        assert snapshot.missing_heartbeat_seconds == missing
    else:
        with pytest.raises(ValidationError, match="at least twice"):
            _limits(
                heartbeat_interval_seconds=interval,
                missing_heartbeat_seconds=missing,
            )


def test_protocol_limits_is_strict_frozen_and_closed() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ProtocolLimits.model_validate({**_DEFAULTS, "max_line_bytes": 1})
    for coerced in ("1048576", 1048576.0, True):
        with pytest.raises(ValidationError):
            ProtocolLimits.model_validate({**_DEFAULTS, "max_event_bytes": coerced})
    for field in _FIELD_ORDER:
        payload = dict(_DEFAULTS)
        del payload[field]
        with pytest.raises(ValidationError, match="required"):
            ProtocolLimits.model_validate(payload)
        with pytest.raises(ValidationError):
            ProtocolLimits.model_validate({**_DEFAULTS, field: None})
    snapshot = _limits()
    with pytest.raises(ValidationError, match="frozen"):
        snapshot.max_event_bytes = 4_096
    with pytest.raises(ValidationError, match="frozen"):
        PROTOCOL_LIMITS_DEFAULT.heartbeat_interval_seconds = 1
    assert snapshot == PROTOCOL_LIMITS_DEFAULT


def test_protocol_limits_round_trips_and_dumps_deterministically() -> None:
    snapshot = _limits(max_event_bytes=4_096)
    assert ProtocolLimits.model_validate(snapshot.model_dump(mode="python")) == snapshot
    assert ProtocolLimits.model_validate_json(snapshot.model_dump_json()) == snapshot
    assert TypeAdapter(ProtocolLimits).validate_json(snapshot.model_dump_json()) == (
        snapshot
    )
    assert tuple(snapshot.model_dump(mode="json")) == _FIELD_ORDER
    assert canonical_json_bytes(snapshot) == canonical_json_bytes(
        _limits(max_event_bytes=4_096)
    )
    assert canonical_json_bytes(snapshot) == (
        b'{"heartbeat_interval_seconds":15,"max_event_bytes":4096,'
        b'"max_manifest_bytes":16777216,"max_stderr_bytes":52428800,'
        b'"missing_heartbeat_seconds":45}'
    )
