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
import json
import sys
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

import crypto_lab.domain.time as time_module
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
    # Task 6 itself registered nothing; Task 8 then appended the nine Stage 4
    # entries, taking the closed registry to twenty. The two protocol digests
    # pinned above are what this test actually guards, and they are unchanged --
    # the count is updated rather than relaxed so the guard stays exact.
    assert len(rendered) == 20


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


# ---------------------------------------------------------------------------
# `executable_path` runtime/schema parity
#
# `_validate_executable_path` enforces two rules that `StringConstraints` never
# renders, so the generated schema published a contract weaker than the runtime:
# a document with edge whitespace or an interior control character was accepted
# by `Draft202012Validator` and rejected by ordinary validated construction.
# `ExecutablePath` was the only annotated type in the Stage 4 schema set with no
# `WithJsonSchema` at all, against a repository convention that publishes every
# expressible validator rule -- `SourceName`, `SemanticVersion`, every
# identifier, `PositiveDecimal`, and `InstrumentId` all do.
#
# The runtime validator is deliberately unchanged. Only the published schema
# gains the rule it was missing.
# ---------------------------------------------------------------------------

#: Python 3.12 `str.isspace()`, frozen as an explicit finite contract. This is
#: the classifier `value != value.strip()` actually uses, and it is **not**
#: ECMA `\s`: `\s` omits U+001C-U+001F and U+0085, so using it would leave the
#: published pattern accepting values the runtime rejects. Proven equal to the
#: computed set by `test_the_frozen_whitespace_set_is_exactly_cpython_isspace`.
_PYTHON_WHITESPACE_CODEPOINTS = frozenset(
    {0x09, 0x0A, 0x0B, 0x0C, 0x0D}
    | {0x1C, 0x1D, 0x1E, 0x1F, 0x20}
    | {0x85, 0xA0, 0x1680}
    | set(range(0x2000, 0x200B))
    | {0x2028, 0x2029, 0x202F, 0x205F, 0x3000}
)
#: Rejected anywhere by `_validate_executable_path`'s `character < " "` and
#: `character == "\x7f"` tests.
_CONTROL_CODEPOINTS = frozenset(set(range(0x00, 0x20)) | {0x7F})
#: Neither is Python whitespace, so the runtime accepts both at an edge. U+200B
#: is the reason the published range stops at U+200A rather than U+200B.
_NOT_PYTHON_WHITESPACE = ("\ufeff", "\u200b")

_VALID_EXECUTABLE_PATHS = (
    r"C:\adapters\alpha\adapter.exe",
    "C:/adapters/alpha/adapter.exe",
    "C:/Program Files/alpha/adapter.exe",
    "C:/adapters/alpha\u00a0beta/adapter.exe",
    "C:/adapters/alpha\u0085beta/adapter.exe",
    "\ufeffC:/adapters/alpha/adapter.exe",
    "C:/adapters/alpha/adapter.exe\u200b",
)


def _observation_document(**updates: object) -> dict[str, Any]:
    """A complete valid JSON-mode document, so no unrelated field can fail."""
    document: dict[str, Any] = _observation().model_dump(mode="json")
    document.update(updates)
    return document


def _observation_schema(mode: str) -> dict[str, Any]:
    schema: dict[str, Any] = RuntimeAvailabilityObservation.model_json_schema(
        mode=mode  # type: ignore[arg-type]
    )
    return schema


def _executable_path_node(mode: str) -> dict[str, Any]:
    node: dict[str, Any] = _observation_schema(mode)["properties"]["executable_path"]
    return node


def _rejects(document: dict[str, Any]) -> bool:
    """True when ordinary validated construction rejects exactly this field."""
    try:
        RuntimeAvailabilityObservation.model_validate_json(json.dumps(document))
    except ValidationError as failure:
        return [error["loc"] for error in failure.errors()] == [("executable_path",)]
    return False


def test_the_frozen_whitespace_set_is_exactly_cpython_isspace() -> None:
    """A finite contract test, not environment discovery.

    `_validate_executable_path` classifies edge whitespace with
    `str.strip()`, whose character set is `str.isspace()`. The published pattern
    enumerates that set literally, so this proves the enumeration is complete
    and has no surplus member under the project's pinned CPython 3.12.
    """
    computed = {
        codepoint for codepoint in range(sys.maxunicode + 1) if chr(codepoint).isspace()
    }
    assert computed == _PYTHON_WHITESPACE_CODEPOINTS
    assert len(_PYTHON_WHITESPACE_CODEPOINTS) == 29
    for character in _NOT_PYTHON_WHITESPACE:
        assert not character.isspace()


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_the_executable_path_schema_publishes_a_pattern(mode: str) -> None:
    node = _executable_path_node(mode)
    assert "pattern" in node, "published schema must carry the runtime rule"
    assert node["type"] == "string"
    assert node["minLength"] == 1
    assert node["maxLength"] == MAX_EXECUTABLE_PATH_CHARACTERS


def test_both_schema_modes_publish_the_identical_pattern() -> None:
    validation = _executable_path_node("validation")["pattern"]
    serialization = _executable_path_node("serialization")["pattern"]
    assert validation == serialization


def test_the_published_pattern_uses_no_whitespace_shorthand() -> None:
    """`\\s` is not the contract: it omits U+001C-U+001F and U+0085.

    The `[\\s\\S]` pair in the project's absolute end assertion means "any
    character" and does not classify whitespace, so it is excluded from this
    check rather than exempted by hand-waving.
    """
    pattern = _executable_path_node("serialization")["pattern"]
    assert pattern.endswith(r"(?![\s\S])")
    assert not pattern.endswith("$")
    assert r"\s" not in pattern.removesuffix(r"(?![\s\S])")


@pytest.mark.parametrize("codepoint", sorted(_PYTHON_WHITESPACE_CODEPOINTS))
def test_every_edge_whitespace_codepoint_is_rejected_at_both_edges(
    codepoint: int,
) -> None:
    character = chr(codepoint)
    body = "C:/adapters/alpha/adapter.exe"
    validator = Draft202012Validator(_observation_schema("serialization"))
    for value in (character + body, body + character):
        document = _observation_document(executable_path=value)
        assert _rejects(document), f"runtime must reject U+{codepoint:04X} at an edge"
        assert not validator.is_valid(document), (
            f"schema must reject U+{codepoint:04X} at an edge"
        )


@pytest.mark.parametrize("codepoint", sorted(_CONTROL_CODEPOINTS))
def test_every_control_codepoint_is_rejected_at_start_middle_and_end(
    codepoint: int,
) -> None:
    character = chr(codepoint)
    validator = Draft202012Validator(_observation_schema("serialization"))
    values = (
        character + "C:/adapters/adapter.exe",
        "C:/adapters/" + character + "adapter.exe",
        "C:/adapters/adapter.exe" + character,
    )
    for value in values:
        document = _observation_document(executable_path=value)
        assert _rejects(document), f"runtime must reject U+{codepoint:04X}"
        assert not validator.is_valid(document), f"schema must reject U+{codepoint:04X}"


@pytest.mark.parametrize(
    "value",
    [
        " C:/adapters/alpha/adapter.exe",
        "C:/adapters/alpha/adapter.exe ",
        "\u00a0C:/adapters/alpha/adapter.exe",
        "C:/adapters/alpha/adapter.exe\u3000",
        "C:/adapters/alpha/\u001fadapter.exe",
        "C:/adapters/alpha/adapter.exe\n",
    ],
)
def test_the_six_reported_gap_documents_are_rejected_on_both_sides(value: str) -> None:
    """The exact documents the blocker report demonstrated the gap with."""
    document = _observation_document(executable_path=value)
    assert _rejects(document)
    validator = Draft202012Validator(_observation_schema("serialization"))
    assert not validator.is_valid(document)


@pytest.mark.parametrize("value", _VALID_EXECUTABLE_PATHS)
def test_an_accepted_path_is_accepted_by_runtime_and_schema_alike(value: str) -> None:
    """Over-rejection is a defect too: interior non-control whitespace,
    U+FEFF, and U+200B must all survive."""
    document = _observation_document(executable_path=value)
    RuntimeAvailabilityObservation.model_validate_json(json.dumps(document))
    for mode in ("validation", "serialization"):
        Draft202012Validator(_observation_schema(mode)).validate(document)


def test_the_baseline_observation_document_is_valid_on_both_sides() -> None:
    document = _observation_document()
    RuntimeAvailabilityObservation.model_validate_json(json.dumps(document))
    for mode in ("validation", "serialization"):
        schema = _observation_schema(mode)
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(document)


# --------------------------------------------------------------------------
# Stage 4 runtime/schema parity closure -- the ``available`` <-> ``reason_code``
# biconditional (clauses OBS-A1 and OBS-A2)
#
# `validate_observation` enforces the biconditional in both directions, and the
# published schema declared neither direction: `reason_code` was correctly
# absent from `required`, but its absence was permitted *unconditionally* rather
# than exactly in the state that permits it. Stage 3 publishes this same shape by
# hand -- `_diagnostic_schema_extra` (`domain/diagnostics.py:181-199`) and both
# artifact-owner hooks (`artifacts/ownership.py:69-103`) -- so the mechanism and
# the committed published-enforcement test both already exist here.
#
# `expires_at_utc > observed_at_utc` stays a runtime-only residual: it compares
# two RFC-3339 instants drawn from an unbounded domain, and Draft 2020-12 has no
# keyword relating two sibling values. Pinned below as an executable fact.
# --------------------------------------------------------------------------

_UNAVAILABLE_CODE = "CAPABILITY.RUNTIME_UNAVAILABLE"


def _unavailable_document(**updates: object) -> dict[str, Any]:
    """The complete valid *unavailable* baseline, the mirror of the available one."""
    document = _observation_document(available=False, reason_code=_UNAVAILABLE_CODE)
    document.update(updates)
    return document


def _observation_rejects(document: dict[str, Any]) -> bool:
    """True when ordinary validated construction rejects the whole document."""
    try:
        RuntimeAvailabilityObservation.model_validate_json(json.dumps(document))
    except ValidationError:
        return True
    return False


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_both_availability_baselines_are_accepted_on_every_side(mode: str) -> None:
    """Non-vacuity: the two complete valid documents agree before any mutation."""
    for document in (_observation_document(), _unavailable_document()):
        RuntimeAvailabilityObservation.model_validate_json(json.dumps(document))
        schema = _observation_schema(mode)
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(document)


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_obs_a1_an_available_observation_may_not_carry_a_reason_code(
    mode: str,
) -> None:
    """Clause OBS-A1. Runtime rejects it; the published schema must too."""
    document = _observation_document(reason_code=_UNAVAILABLE_CODE)
    assert _observation_rejects(document)
    assert not Draft202012Validator(_observation_schema(mode)).is_valid(document)


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_obs_a2_an_unavailable_observation_must_carry_a_reason_code(
    mode: str,
) -> None:
    """Clause OBS-A2. The other direction of the same biconditional."""
    document = _observation_document(available=False)
    assert "reason_code" not in document
    assert _observation_rejects(document)
    assert not Draft202012Validator(_observation_schema(mode)).is_valid(document)


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_the_biconditional_is_published_as_two_separable_conditions(
    mode: str,
) -> None:
    """Two branches, not one -- so removing either is caught on its own.

    Asserted structurally as well as behaviourally: a single `oneOf` would pass
    the two behaviour tests above while making the mutation battery unable to
    kill one direction independently.
    """
    schema = _observation_schema(mode)
    branches = schema["allOf"]
    assert len(branches) == 2
    conditions = [
        branch["if"]["properties"]["available"]["const"] for branch in branches
    ]
    assert conditions == [True, False]
    assert branches[0]["then"] == {"not": {"required": ["reason_code"]}}
    assert branches[1]["then"] == {"required": ["reason_code"]}


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_reason_code_stays_optional_and_unnarrowed_at_the_property(mode: str) -> None:
    """The condition is added; the property contract is untouched.

    `reason_code` must stay out of `required` -- absence is legal in the
    available state -- and its value schema must still be exactly the shared
    `ErrorCode` reference, so nothing here narrows the frozen Stage 3 type.
    """
    schema = _observation_schema(mode)
    assert "reason_code" not in schema["required"]
    assert schema["properties"]["reason_code"] == {
        "$ref": "#/$defs/ErrorCode",
        "title": "Reason Code",
    }


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_the_observation_hook_preserves_every_previously_emitted_keyword(
    mode: str,
) -> None:
    """Additive, asserted keyword by keyword rather than by absence of failure."""
    schema = _observation_schema(mode)
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    assert schema["title"] == "RuntimeAvailabilityObservation"
    assert schema["required"] == [
        name for name in _EXPECTED_OBSERVATION_FIELDS if name != "reason_code"
    ]
    assert list(schema["properties"]) == list(_EXPECTED_OBSERVATION_FIELDS)
    # the executable-path contract the previous correction published is intact
    node = _executable_path_node(mode)
    assert node["type"] == "string"
    assert node["maxLength"] == MAX_EXECUTABLE_PATH_CHARACTERS


def test_the_two_sibling_descriptor_schemas_gain_no_conditional() -> None:
    """The hook is owned by one model; its two frozen Stage 3 housemates are not.

    `EngineDescriptor` and `AdapterDescriptor` live in this module and render the
    already-published `engine-descriptor-v1` and `adapter-descriptor-v1`. A hook
    reached through a shared helper would move their bytes.
    """
    for model in (EngineDescriptor, AdapterDescriptor):
        for mode in ("validation", "serialization"):
            schema = model.model_json_schema(mode=mode)
            for keyword in ("allOf", "if", "then", "else", "oneOf", "not"):
                assert keyword not in schema, (model.__name__, mode, keyword)


def test_the_temporal_ordering_rule_stays_a_runtime_only_residual() -> None:
    """Clause OBS-C1, pinned as an executable fact rather than an assertion.

    `expires_at_utc > observed_at_utc` relates two RFC-3339 instants over an
    unbounded domain. Draft 2020-12 has no `$data` reference and no keyword that
    compares two sibling values, so the published schema deliberately does not
    claim this rule and runtime validation stays authoritative for it.
    """
    observed = _observation_document()["observed_at_utc"]
    document = _observation_document(expires_at_utc=observed)
    assert _observation_rejects(document)
    for mode in ("validation", "serialization"):
        assert Draft202012Validator(_observation_schema(mode)).is_valid(document)


def test_the_observation_correction_changes_no_canonical_byte() -> None:
    """Schema metadata only: every valid record dumps and hashes as before."""
    available = _observation()
    unavailable = RuntimeAvailabilityObservation.model_validate_json(
        json.dumps(_unavailable_document())
    )
    assert canonical_json_bytes(available) == (
        b'{"adapter_name":"adapter.alpha","adapter_version":"1.0.0",'
        b'"availability_observation_id":'
        b'"avail_2c4d6e80-1f3a-4b5c-9d8e-7f6a5b4c3d2e",'
        b'"available":true,"credentials_required":false,'
        b'"executable_hash":"' + b"a" * 64 + b'",'
        b'"executable_path":"C:/adapters/alpha/adapter.exe",'
        b'"expires_at_utc":"2026-08-24T13:00:00Z","network_required":false,'
        b'"observed_at_utc":"2026-08-24T12:00:00Z","operating_system":"WINDOWS",'
        b'"runtime_version":"3.12.13","schema_version":"1.0.0"}'
    )
    assert list(available.model_dump(mode="json")) == [
        name for name in _EXPECTED_OBSERVATION_FIELDS if name != "reason_code"
    ]
    assert unavailable.model_dump(mode="json")["reason_code"] == _UNAVAILABLE_CODE
    assert list(RuntimeAvailabilityObservation.model_fields) == list(
        _EXPECTED_OBSERVATION_FIELDS
    )


_IMPOSSIBLE_INSTANTS = (
    "0000-01-01T00:00:00Z",
    "2026-00-01T00:00:00Z",
    "2026-13-01T00:00:00Z",
    "2026-01-00T00:00:00Z",
    "2026-01-32T00:00:00Z",
    "2026-02-29T00:00:00Z",
    "2025-02-29T00:00:00Z",
    "2026-02-30T00:00:00Z",
    "2026-04-31T00:00:00Z",
    "1900-02-29T00:00:00Z",
    "2100-02-29T00:00:00Z",
    "2026-01-01T24:00:00Z",
    "2026-01-01T00:60:00Z",
    "2026-01-01T00:00:60Z",
    "2026-01-01T99:99:99Z",
)


@pytest.mark.parametrize("instant", _IMPOSSIBLE_INSTANTS)
@pytest.mark.parametrize("field", ["observed_at_utc", "expires_at_utc"])
def test_the_observation_schema_rejects_an_impossible_instant(
    field: str, instant: str
) -> None:
    """The Stage 4 half of the `UtcDateTime` calendar gap, now closed.

    `parse_utc` routes through `datetime.fromisoformat`, so it has always rejected
    an impossible calendar date and an out-of-range clock, while the legacy
    `UtcDateTime` projection published only `[0-9]{2}` runs and accepted both.
    That projection is frozen into three released Stage 3 `$id`s, so it could not
    be tightened in place; both of this record's timestamps now carry the
    forward-only `CalendarValidUtcDateTime` view instead, and the published
    grammar agrees with the runtime in **both** render modes.

    The legacy projection stays permissive on purpose -- that is what keeps the
    eleven Stage 3 files byte-identical -- and it is pinned as a frozen residual
    by `test_the_legacy_projection_stays_a_frozen_stage_three_residual` in
    `tests/unit/domain/test_time.py`.
    """
    document = _observation_document(**{field: instant})
    assert _observation_rejects(document), instant
    for mode in ("validation", "serialization"):
        assert not Draft202012Validator(_observation_schema(mode)).is_valid(document), (
            mode,
            instant,
        )


def test_the_observation_schema_over_rejects_no_real_instant() -> None:
    """The only failure mode a hand-written calendar regex has. Every one of
    these is a real instant the runtime accepts, so the schema must too."""
    pairs = (
        ("2024-02-29T00:00:00Z", "2024-03-01T00:00:00Z"),
        ("2000-02-29T00:00:00Z", "2000-03-01T00:00:00Z"),
        ("0004-02-29T00:00:00Z", "0004-03-01T00:00:00Z"),
        ("0001-01-01T00:00:00Z", "0001-01-02T00:00:00Z"),
        ("2026-02-28T23:59:59Z", "2026-03-01T00:00:00Z"),
        ("2026-04-30T00:00:00.000001Z", "2026-05-01T00:00:00Z"),
        ("9999-12-30T00:00:00Z", "9999-12-31T23:59:59Z"),
    )
    for observed, expires in pairs:
        document = _observation_document(
            observed_at_utc=observed, expires_at_utc=expires
        )
        RuntimeAvailabilityObservation.model_validate_json(json.dumps(document))
        for mode in ("validation", "serialization"):
            Draft202012Validator(_observation_schema(mode)).validate(document)


def _assert_forward_view_definition(schema: dict[str, Any]) -> None:
    """The named alias is hoisted to one shared `$defs` entry, exactly as the
    legacy `$defs/UtcDateTime` was, so the whole grammar is asserted once."""
    definition = schema["$defs"]["CalendarValidUtcDateTime"]
    assert set(definition) == {"allOf"}
    branches = definition["allOf"]
    assert len(branches) == 3
    assert branches[0] == {
        "type": "string",
        "format": "date-time",
        "pattern": time_module._UTC_SCHEMA_PATTERN,
    }
    assert branches[1] == {
        "type": "string",
        "pattern": time_module._CALENDAR_DATE_PREFIX_PATTERN,
    }
    assert branches[2] == {
        "type": "string",
        "pattern": time_module._CLOCK_TIME_PREFIX_PATTERN,
    }
    # The permissive shared entry is gone from this schema entirely, so no other
    # field can still be reaching the loose grammar.
    assert "UtcDateTime" not in schema["$defs"]


@pytest.mark.parametrize("mode", ["validation", "serialization"])
@pytest.mark.parametrize("field", ["observed_at_utc", "expires_at_utc"])
def test_both_observation_timestamps_publish_the_forward_view(
    field: str, mode: str
) -> None:
    """Structural, so a field silently reverted to the legacy alias is caught
    even if some other clause happens to reject the sample documents."""
    schema = _observation_schema(mode)
    assert schema["properties"][field] == {"$ref": "#/$defs/CalendarValidUtcDateTime"}
    _assert_forward_view_definition(schema)
