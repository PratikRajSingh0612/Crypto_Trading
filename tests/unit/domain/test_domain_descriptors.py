"""The Task 6 relocation of the shared descriptor contracts into ``domain``.

Plan section 5.7 moves ``EngineDescriptor``, ``SupportedSchemaVersion``,
``AdapterDescriptor``, and ``OperatingSystem`` out of ``adapters/descriptors.py``
so ``capabilities`` never needs an inward edge on ``adapters``, and Appendix E
requires the private helpers and both ``json_schema_extra`` hooks to move with
them. ``RuntimeAvailabilityObservation`` is new here, because specification
section 8.2 places it in ``CompatibilityResolver.resolve`` and section 11.3
classifies it as a canonical domain record.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

import pytest
from pydantic import ValidationError

from crypto_lab.adapters import descriptors as adapter_descriptors
from crypto_lab.domain import capability_names
from crypto_lab.domain import descriptors as domain_descriptors
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.descriptors import (
    MAX_EXECUTABLE_PATH_CHARACTERS,
    AdapterDescriptor,
    EngineDescriptor,
    OperatingSystem,
    RuntimeAvailabilityObservation,
    SupportedSchemaVersion,
)
from crypto_lab.schema_registry import render_schema_files

# Recorded from the committed tree at the Task 6 base commit
# `bdeb9bc206636a51d09a93b531f6aad246c4ead8`, before any relocation edit. Plan
# Task 6 step 12 makes byte identity across the relocation a mandatory blocking
# gate; pinning the digest here makes that gate executable rather than manual.
_PRE_TASK6_ADAPTER_DESCRIPTOR_SHA256 = (
    "8fadb5ea78a02950f191989df27fe12d09f66d3e5c62c13d20a54ae423b06e58"
)
_PRE_TASK6_ENGINE_DESCRIPTOR_SHA256 = (
    "7ebcc6467d9eef695d777843a000140f0f9da4f1ef7c1faf465f6a5a69ddf2d1"
)
# Appendix E fixes this list exactly, including ``BoundedText``: without it the
# "public surface is unchanged" claim in plan sections 1.2 and 6.2 is false.
_EXPECTED_ADAPTER_EXPORTS = [
    "AdapterDescriptor",
    "BoundedText",
    "CapabilityName",
    "EngineDescriptor",
    "OperatingSystem",
    "SupportedSchemaVersion",
    "VocabularyVersion",
]
# Specification section 11.3's minimum-field list for the record, in that order.
_EXPECTED_OBSERVATION_FIELDS = (
    "schema_version",
    "availability_observation_id",
    "adapter_name",
    "adapter_version",
    "executable_path",
    "executable_hash",
    "runtime_version",
    "operating_system",
    "available",
    "reason_code",
    "observed_at_utc",
    "expires_at_utc",
    "network_required",
    "credentials_required",
)
_OBSERVED = datetime(2026, 8, 24, 12, 0, 0, tzinfo=UTC)
_EXPIRES = datetime(2026, 8, 24, 13, 0, 0, tzinfo=UTC)


def _engine(**updates: object) -> EngineDescriptor:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "engine_name": "engine.alpha",
        "engine_version": "1.2.3",
        "engine_family": "engine.family",
        "planned_role": "Research simulation.",
        "known_limitations": ("No live trading.",),
    }
    payload.update(updates)
    return EngineDescriptor.model_validate(payload)


def _descriptor(**updates: object) -> AdapterDescriptor:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "adapter_name": "adapter.alpha",
        "adapter_version": "1.0.0",
        "engine": _engine(),
        "supported_protocol_versions": ("1.0.0",),
        "supported_schema_versions": (
            SupportedSchemaVersion(
                schema_name="domain.instrument-ref",
                schema_version="1.0.0",
            ),
        ),
        "capability_vocabulary_version": "capabilities/v1",
        "native_capabilities": ("data.ohlcv", "market.spot"),
        "approximated_capabilities": (),
        "unsupported_capabilities": (),
        "supported_operating_systems": (OperatingSystem.WINDOWS,),
        "runtime_requirements": ("CPython 3.12",),
        "network_required": False,
        "credentials_required": False,
        "known_modeling_limitations": (),
        "executable_hash": "a" * 64,
    }
    payload.update(updates)
    return AdapterDescriptor.model_validate(payload)


def _observation(**updates: object) -> RuntimeAvailabilityObservation:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "availability_observation_id": "avail_2c4d6e80-1f3a-4b5c-9d8e-7f6a5b4c3d2e",
        "adapter_name": "adapter.alpha",
        "adapter_version": "1.0.0",
        "executable_path": "C:/adapters/alpha/adapter.exe",
        "executable_hash": "a" * 64,
        "runtime_version": "3.12.13",
        "operating_system": OperatingSystem.WINDOWS,
        "available": True,
        "observed_at_utc": _OBSERVED,
        "expires_at_utc": _EXPIRES,
        "network_required": False,
        "credentials_required": False,
    }
    payload.update(updates)
    return RuntimeAvailabilityObservation.model_validate(payload)


def test_every_relocated_name_is_one_object_through_both_import_paths() -> None:
    """Re-export identity, not merely a same-named copy.

    A duplicated definition would satisfy every construction test in this module
    while silently giving ``adapters`` and ``domain`` two distinct classes, so the
    two schemas could then drift apart without any test noticing.
    """
    for name in ("AdapterDescriptor", "EngineDescriptor", "SupportedSchemaVersion"):
        assert getattr(adapter_descriptors, name) is getattr(
            domain_descriptors, name
        ), name
    assert adapter_descriptors.OperatingSystem is domain_descriptors.OperatingSystem
    assert adapter_descriptors.BoundedText is domain_descriptors.BoundedText
    assert adapter_descriptors.CapabilityName is capability_names.CapabilityName
    assert adapter_descriptors.VocabularyVersion is capability_names.VocabularyVersion


def test_the_relocated_classes_are_owned_by_the_domain_module() -> None:
    """Ownership is asserted on ``__module__``, which a re-export cannot fake."""
    for model in (EngineDescriptor, SupportedSchemaVersion, AdapterDescriptor):
        assert model.__module__ == "crypto_lab.domain.descriptors", model.__name__
    assert OperatingSystem.__module__ == "crypto_lab.domain.descriptors"


def test_the_adapter_module_public_surface_is_exactly_the_appendix_e_list() -> None:
    """``__all__`` is mandatory, not cosmetic.

    Strict mypy implies ``--no-implicit-reexport``, so without it every existing
    ``from crypto_lab.adapters.descriptors import ...`` site fails type checking.
    """
    assert adapter_descriptors.__all__ == _EXPECTED_ADAPTER_EXPORTS


def test_the_adapter_module_defines_no_relocated_definition_of_its_own() -> None:
    """Appendix E requires deletion, not shadowing.

    The private helpers and both ``json_schema_extra`` hooks must move with the
    classes: a helper left behind would force ``domain/descriptors.py`` to import
    ``crypto_lab.adapters``, which is exactly the dependency-direction violation
    section 5.7 exists to remove.
    """
    source = Path(adapter_descriptors.__file__ or "").read_text(encoding="utf-8")
    for definition in (
        "class EngineDescriptor",
        "class SupportedSchemaVersion",
        "class AdapterDescriptor",
        "class OperatingSystem",
        "def _unique_sorted_text",
        "def _unique_sorted_versions",
        "def _set_unique_items",
        "def _engine_schema_extra",
        "def _descriptor_schema_extra",
        "BoundedText = ",
        "CapabilityName = ",
        "VocabularyVersion = ",
    ):
        assert definition not in source, definition


def test_the_protocol_descriptor_schemas_are_byte_identical_after_relocation(
    repository_root: Path,
) -> None:
    """The mandatory blocking gate of Task 6 step 12, as an executable pin.

    The digests are taken from what the registry **renders** from the relocated
    source, not from the committed files. That distinction is the whole point:
    hashing the on-disk files would still pass if the relocation changed what
    generation emits, since nothing regenerates them during a test run. The
    committed bytes are then asserted equal to the rendered bytes, so the pin
    covers both "generation is unchanged" and "the tree matches generation".

    The mechanism it verifies: the generated ``$defs`` are keyed by bare class and
    alias names, never by module path, and the capability annotations are inlined
    with no ``$def``, so a verbatim move cannot change the emitted bytes.
    """
    rendered = render_schema_files()
    adapter_path = PurePosixPath("protocol/adapter-descriptor-v1.schema.json")
    engine_path = PurePosixPath("protocol/engine-descriptor-v1.schema.json")

    assert hashlib.sha256(rendered[adapter_path]).hexdigest() == (
        _PRE_TASK6_ADAPTER_DESCRIPTOR_SHA256
    )
    assert hashlib.sha256(rendered[engine_path]).hexdigest() == (
        _PRE_TASK6_ENGINE_DESCRIPTOR_SHA256
    )

    schemas = repository_root / "schemas"
    assert (schemas / adapter_path).read_bytes() == rendered[adapter_path]
    assert (schemas / engine_path).read_bytes() == rendered[engine_path]
    # Task 6 registers nothing, so the closed registry must still hold eleven.
    assert len(rendered) == 11


def test_a_descriptor_built_through_either_import_path_is_the_same_record() -> None:
    through_adapters = adapter_descriptors.AdapterDescriptor.model_validate(
        _descriptor().model_dump(mode="python")
    )
    through_domain = _descriptor()
    assert through_adapters == through_domain
    assert canonical_json_bytes(through_adapters) == canonical_json_bytes(
        through_domain
    )


def test_the_relocated_validators_still_reject_unsorted_and_overlapping_sets() -> None:
    """Proves the validators moved with the classes rather than being dropped."""
    with pytest.raises(ValidationError):
        _descriptor(native_capabilities=("market.spot", "data.ohlcv"))
    with pytest.raises(ValidationError):
        _descriptor(native_capabilities=("market.spot", "market.spot"))
    with pytest.raises(ValidationError):
        _descriptor(
            native_capabilities=("market.spot",),
            unsupported_capabilities=("market.spot",),
        )
    with pytest.raises(ValidationError):
        _engine(known_limitations=("b.", "a."))
    with pytest.raises(ValidationError):
        _descriptor(
            supported_operating_systems=(
                OperatingSystem.WINDOWS,
                OperatingSystem.WINDOWS,
            )
        )
    with pytest.raises(ValidationError):
        _descriptor(
            supported_operating_systems=(
                OperatingSystem.WINDOWS,
                OperatingSystem.LINUX,
            )
        )
    with pytest.raises(ValidationError):
        _descriptor(supported_protocol_versions=("1.10.0", "1.2.0"))
    with pytest.raises(ValidationError):
        _descriptor(supported_protocol_versions=("1.0.0", "1.0.0"))


def test_the_relocated_schema_hooks_refuse_a_shape_they_cannot_annotate() -> None:
    """The two ``json_schema_extra`` hooks Appendix E calls easy to overlook.

    Pydantic emits no ``uniqueItems`` for a tuple field, so these hooks add it. A
    hook that shrugged at an unexpected shape would publish a weaker generated
    contract than the runtime enforces, and the descriptor schema is exactly the
    artifact Task 6 must keep byte-identical.
    """
    with pytest.raises(TypeError):
        domain_descriptors._engine_schema_extra({"properties": "not-an-object"})
    with pytest.raises(TypeError):
        domain_descriptors._descriptor_schema_extra(
            {"properties": {"supported_protocol_versions": None}}
        )


def test_the_observation_declares_exactly_the_specification_field_list() -> None:
    """Specification section 11.3's minimum fields, in that order.

    The plan's section 9 field-list paragraph (plan line 2941) requires the field
    set to come from the specification rather than be invented, and this record
    does have an 11.3 row -- unlike ``CompatibilityResult``.
    """
    assert tuple(RuntimeAvailabilityObservation.model_fields) == (
        _EXPECTED_OBSERVATION_FIELDS
    )


def test_an_available_observation_carries_no_reason_code() -> None:
    observation = _observation()
    assert observation.available is True
    # Both modes. Plan section 5.5.1 item 10 makes python mode load-bearing on its
    # own, because `canonical_json._normalize` reaches a model through
    # `model_dump(mode="python")` and raises on an unsupported type, so a sentinel
    # leaking there would break every canonical-bytes path.
    assert "reason_code" not in observation.model_dump(mode="json")
    assert "reason_code" not in observation.model_dump(mode="python")
    with pytest.raises(ValidationError):
        _observation(reason_code="CAPABILITY.RUNTIME_UNAVAILABLE")


def test_an_unavailable_observation_requires_a_reason_code() -> None:
    with pytest.raises(ValidationError):
        _observation(available=False)
    observation = _observation(
        available=False,
        reason_code="CAPABILITY.RUNTIME_UNAVAILABLE",
    )
    assert observation.reason_code == "CAPABILITY.RUNTIME_UNAVAILABLE"
    assert observation.model_dump(mode="json")["reason_code"] == (
        "CAPABILITY.RUNTIME_UNAVAILABLE"
    )


def test_expiry_must_follow_the_observation_instant() -> None:
    with pytest.raises(ValidationError):
        _observation(expires_at_utc=_OBSERVED)
    with pytest.raises(ValidationError):
        _observation(expires_at_utc=datetime(2026, 8, 24, 11, tzinfo=UTC))


def test_the_observation_rejects_naive_time_and_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        _observation(observed_at_utc=datetime(2026, 8, 24, 12, 0, 0))  # noqa: DTZ001
    with pytest.raises(ValidationError):
        _observation(unexpected="value")


@pytest.mark.parametrize(
    "value",
    [
        "",
        " C:/adapters/alpha/adapter.exe",
        "C:/adapters/alpha/adapter.exe ",
        "C:/adapters/alpha/\x00adapter.exe",
        "C:/adapters/alpha/\nadapter.exe",
        "C:/adapters/alpha/\x7fadapter.exe",
        "C:/" + "a" * MAX_EXECUTABLE_PATH_CHARACTERS,
    ],
)
def test_the_executable_path_rejects_unsafe_text(value: str) -> None:
    with pytest.raises(ValidationError):
        _observation(executable_path=value)


def test_the_observation_is_frozen_and_holds_no_mutable_container() -> None:
    observation = _observation()
    with pytest.raises(ValidationError):
        observation.available = False
    for name in _EXPECTED_OBSERVATION_FIELDS:
        value = getattr(observation, name, None)
        assert not isinstance(value, dict | list | set | bytearray), name


def test_both_dump_modes_are_detached_from_the_stored_record() -> None:
    observation = _observation()
    python_mode = observation.model_dump(mode="python")
    json_mode = observation.model_dump(mode="json")
    python_mode["adapter_name"] = "mutated"
    json_mode["adapter_name"] = "mutated"
    assert observation.adapter_name == "adapter.alpha"
    assert observation.model_dump(mode="python")["adapter_name"] == "adapter.alpha"


def test_both_round_trips_restore_an_equal_immutable_record() -> None:
    observation = _observation(
        available=False,
        reason_code="CAPABILITY.RUNTIME_UNAVAILABLE",
    )
    from_python = RuntimeAvailabilityObservation.model_validate(
        observation.model_dump(mode="python")
    )
    from_json = RuntimeAvailabilityObservation.model_validate_json(
        observation.model_dump_json()
    )
    assert from_python == observation
    assert from_json == observation
    assert canonical_json_bytes(from_json) == canonical_json_bytes(observation)
    with pytest.raises(ValidationError):
        from_json.available = True


def test_canonical_bytes_are_deterministic_and_key_ordered() -> None:
    first = canonical_json_bytes(_observation())
    second = canonical_json_bytes(_observation())
    assert first == second
    assert first.startswith(b'{"adapter_name":"adapter.alpha"')
