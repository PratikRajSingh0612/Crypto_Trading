"""Test strategy-version identity: what the content hash includes and excludes.

Plan section 5.5 fixes the hashed payload exactly. These tests pin every material
inclusion and every non-material exclusion, so no later change can silently move a
field across that boundary.

Every specification here is built from ``sma_cross_long.valid.yaml`` decoded through
the committed safe YAML boundary and then mutated as **plain data** before strict
model construction. Mutating plain data rather than a validated model is what keeps
these tests independent of the loader facade, which has its own module.
"""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

import crypto_lab.domain.time as time_module
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.hashing import HashingProfile, profile_hash, sha256_bytes
from crypto_lab.domain.results import Success
from crypto_lab.strategy.expressions import EXPRESSION_SEMANTICS_VERSION
from crypto_lab.strategy.models import StrategySpec
from crypto_lab.strategy.versioning import (
    STRATEGY_VERSION_PROFILE_VERSION,
    StrategySourceProvenance,
    StrategyVersion,
    sorted_extension_hashes,
    strategy_version_hash,
    strategy_version_identifier,
    strategy_version_payload,
)
from crypto_lab.strategy.yaml_source import load_yaml_document

_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "strategy"
_OBSERVED_AT = datetime(2026, 8, 18, 12, 0, 0, tzinfo=UTC)
_OTHER_OBSERVED_AT = datetime(2027, 1, 2, 3, 4, 5, tzinfo=UTC)
_STRATEGY_ID = "strat_3f2504e0-4f89-41d3-9a0c-0305e82c3301"
_OTHER_STRATEGY_ID = "strat_1f2504e0-4f89-41d3-9a0c-0305e82c3399"
_VERSION_ID = "strv_12345678-1234-4234-8234-123456789abc"
_OTHER_VERSION_ID = "strv_87654321-4321-4321-8321-cba987654321"

_EXTENSION_ONE: dict[str, Any] = {
    "adapter_name": "adapter.alpha",
    "extension_id": "ext.one",
    "version": "1.0.0",
    "content_hash": "1" * 64,
    "purpose": "Adds a declared lifecycle hook only.",
    "lifecycle_effect": "LIFECYCLE_HOOKS_ONLY",
    "economic_effect": "NONE",
}
_EXTENSION_TWO: dict[str, Any] = {
    "adapter_name": "adapter.beta",
    "extension_id": "ext.two",
    "version": "2.3.4",
    "content_hash": "2" * 64,
    "purpose": "Alters execution behaviour and prevents Level 2 parity.",
    "lifecycle_effect": "ALTERS_EXECUTION_BEHAVIOR",
    "economic_effect": "PREVENTS_LEVEL_2",
}


def _document(name: str) -> dict[str, Any]:
    """Decode one fixture through the committed safe YAML boundary."""
    outcome = load_yaml_document(
        (_FIXTURES / name).read_bytes(),
        name.replace("/", "."),
        _OBSERVED_AT,
    )
    assert isinstance(outcome, Success), outcome
    value = outcome.value.value
    assert isinstance(value, dict)
    return copy.deepcopy(value)


def _base_mapping() -> dict[str, Any]:
    return _document("sma_cross_long.valid.yaml")


def _spec(mapping: dict[str, Any]) -> StrategySpec:
    """The committed Task 2 idiom: canonical JSON bytes into JSON-mode validation.

    ``CanonicalModel`` is ``strict=True``, so python-mode validation of a plain
    mapping would reject a string where an enum belongs.
    """
    return StrategySpec.model_validate_json(canonical_json_bytes(mapping))


def _base_spec() -> StrategySpec:
    return _spec(_base_mapping())


def _provenance(
    *,
    source_name: str = "sma_cross_long.valid.yaml",
    observed_at_utc: datetime = _OBSERVED_AT,
) -> StrategySourceProvenance:
    payload = b"schema_version: placeholder"
    return StrategySourceProvenance(
        source_name=source_name,
        source_bytes_sha256=sha256_bytes(payload),
        source_byte_length=len(payload),
        observed_at_utc=observed_at_utc,
    )


def _version(
    spec: StrategySpec,
    *,
    strategy_version_id: str = _VERSION_ID,
    provenance: StrategySourceProvenance | None = None,
    created_at_utc: datetime = _OBSERVED_AT,
) -> StrategyVersion:
    return StrategyVersion(
        schema_version="1.0.0",
        strategy_version_id=strategy_version_id,
        strategy_id=spec.strategy_id,
        content_hash=strategy_version_hash(spec),
        strategy_spec=spec,
        extension_hashes=tuple(sorted_extension_hashes(spec.engine_extensions)),
        hashing_profile_version=STRATEGY_VERSION_PROFILE_VERSION,
        created_at_utc=created_at_utc,
        source_provenance=provenance if provenance is not None else _provenance(),
    )


# --- The profile and the exact payload ------------------------------------


def test_the_strategy_version_hashing_profile_exists() -> None:
    assert HashingProfile.STRATEGY_VERSION_V1.value == "strategy-version/v1"


def test_the_declared_profile_version_matches_the_hashing_profile() -> None:
    assert STRATEGY_VERSION_PROFILE_VERSION == HashingProfile.STRATEGY_VERSION_V1.value


def test_the_payload_carries_exactly_the_five_plan_section_5_5_keys() -> None:
    payload = strategy_version_payload(_base_spec())
    assert set(payload) == {
        "strategy_spec",
        "strategy_schema_version",
        "expression_semantics_version",
        "hashing_profile_version",
        "extension_hashes",
    }


def test_the_payload_values_are_exactly_the_plan_section_5_5_values() -> None:
    spec = _base_spec()
    payload = strategy_version_payload(spec)
    assert payload["strategy_spec"] == spec.model_dump(mode="json")
    assert payload["strategy_schema_version"] == spec.schema_version
    assert payload["expression_semantics_version"] == EXPRESSION_SEMANTICS_VERSION
    assert payload["hashing_profile_version"] == "strategy-version/v1"
    assert payload["extension_hashes"] == []


def test_the_embedded_specification_dump_excludes_no_field() -> None:
    """Item 1 says `model_dump(mode="json")` with no exclusions."""
    payload = strategy_version_payload(_base_spec())
    embedded = payload["strategy_spec"]
    assert isinstance(embedded, dict)
    assert set(embedded) == set(StrategySpec.model_fields)
    assert len(embedded) == 21


def test_the_payload_is_json_encodable_plain_data() -> None:
    """`profile_hash` types the payload `dict[str, JsonValue]`; no model, no tuple."""
    payload = strategy_version_payload(_base_spec())
    assert json.loads(json.dumps(payload)) == payload
    assert isinstance(payload["extension_hashes"], list)


def test_the_hash_is_exactly_the_profile_hash_of_the_payload() -> None:
    spec = _base_spec()
    assert strategy_version_hash(spec) == profile_hash(
        HashingProfile.STRATEGY_VERSION_V1,
        strategy_version_payload(spec),
    )


def test_the_hash_is_a_lowercase_sha256_digest() -> None:
    digest = strategy_version_hash(_base_spec())
    assert len(digest) == 64
    assert digest == digest.lower()
    assert set(digest) <= set("0123456789abcdef")


# --- Formatting invariance over the committed hash-equivalent triple -------


@pytest.mark.parametrize(
    "name",
    [
        "sma_cross_long.reordered_keys.yaml",
        "sma_cross_long.commented.yaml",
    ],
)
def test_a_formatting_variant_produces_the_same_content_hash(name: str) -> None:
    """Section 6.5.4's triple: comments, whitespace, and key order are immaterial."""
    assert strategy_version_hash(_spec(_document(name))) == strategy_version_hash(
        _base_spec()
    )


def test_the_three_formatting_variants_are_not_byte_identical_sources() -> None:
    """Otherwise the invariance above would be trivially true."""
    sources = {
        (_FIXTURES / name).read_bytes()
        for name in (
            "sma_cross_long.valid.yaml",
            "sma_cross_long.reordered_keys.yaml",
            "sma_cross_long.commented.yaml",
        )
    }
    assert len(sources) == 3


# --- Every material field changes the hash when changed alone -------------


def _with_extensions(*declarations: dict[str, Any]) -> dict[str, Any]:
    mapping = _base_mapping()
    mapping["engine_extensions"] = [copy.deepcopy(item) for item in declarations]
    return mapping


def _mutate_strategy_id(mapping: dict[str, Any]) -> None:
    mapping["strategy_id"] = _OTHER_STRATEGY_ID


def _mutate_display_name(mapping: dict[str, Any]) -> None:
    mapping["display_name"] = "SMA Cross Long, revised"


def _mutate_description(mapping: dict[str, Any]) -> None:
    mapping["description"] = "A different declared economic intent."


def _mutate_strategy_family(mapping: dict[str, Any]) -> None:
    mapping["strategy_family"] = "mean_reversion"


def _mutate_timeframe(mapping: dict[str, Any]) -> None:
    mapping["timeframe"] = "4h"


def _mutate_universe(mapping: dict[str, Any]) -> None:
    mapping["universe"]["instruments"] = ["BINANCE:ETH/USDT:SPOT"]


def _mutate_required_capabilities(mapping: dict[str, Any]) -> None:
    mapping["required_capabilities"][0]["required"] = False


def _mutate_parameters(mapping: dict[str, Any]) -> None:
    mapping["parameters"]["fast_period"]["value"] = 21


def _mutate_features(mapping: dict[str, Any]) -> None:
    mapping["features"][0]["warm_up_bars"] = 19


def _mutate_entry_rules(mapping: dict[str, Any]) -> None:
    mapping["entry_rules"][0]["id"] = "enter_crossover"


def _mutate_exit_rules(mapping: dict[str, Any]) -> None:
    mapping["exit_rules"][0]["expression"]["op"] = "less_than"


def _mutate_sizing_intent(mapping: dict[str, Any]) -> None:
    mapping["sizing_intent"]["fraction"] = "0.5"


def _mutate_warm_up_requirements(mapping: dict[str, Any]) -> None:
    mapping["warm_up_requirements"]["minimum_bars"] = 51


def _mutate_comparison_requirements(mapping: dict[str, Any]) -> None:
    mapping["comparison_requirements"]["maximum_level"] = "LEVEL_1"


def _mutate_engine_extensions(mapping: dict[str, Any]) -> None:
    mapping["engine_extensions"] = [copy.deepcopy(_EXTENSION_ONE)]


def _mutate_authoring_metadata(mapping: dict[str, Any]) -> None:
    mapping["authoring_metadata"]["created_at_utc"] = "2026-08-11T00:00:00Z"


_MATERIAL_MUTATIONS = {
    "strategy_id": _mutate_strategy_id,
    "display_name": _mutate_display_name,
    "description": _mutate_description,
    "strategy_family": _mutate_strategy_family,
    "timeframe": _mutate_timeframe,
    "universe": _mutate_universe,
    "required_capabilities": _mutate_required_capabilities,
    "parameters": _mutate_parameters,
    "features": _mutate_features,
    "entry_rules": _mutate_entry_rules,
    "exit_rules": _mutate_exit_rules,
    "sizing_intent": _mutate_sizing_intent,
    "warm_up_requirements": _mutate_warm_up_requirements,
    "comparison_requirements": _mutate_comparison_requirements,
    "engine_extensions": _mutate_engine_extensions,
    "authoring_metadata": _mutate_authoring_metadata,
}

# Fixed to a single admissible value by `strategy/v1` policy, so no in-model
# mutation exists to test. Their presence in the hashed payload is proven
# structurally instead, by `test_the_embedded_specification_dump_excludes_no_field`.
_POLICY_FIXED_FIELDS = frozenset(
    {
        "schema_version",
        "market_type",
        "direction",
        "risk_assumptions",
        "supported_approximation_policy",
    }
)


def test_the_mutation_table_covers_every_specification_field() -> None:
    assert set(_MATERIAL_MUTATIONS) | _POLICY_FIXED_FIELDS == set(
        StrategySpec.model_fields
    )
    assert not set(_MATERIAL_MUTATIONS) & _POLICY_FIXED_FIELDS


@pytest.mark.parametrize("field_name", sorted(_MATERIAL_MUTATIONS))
def test_changing_one_material_field_changes_the_content_hash(field_name: str) -> None:
    mapping = _base_mapping()
    _MATERIAL_MUTATIONS[field_name](mapping)
    mutated = _spec(mapping)
    baseline = _base_spec()
    dumped_baseline = baseline.model_dump(mode="json")
    dumped_mutated = mutated.model_dump(mode="json")
    differing = {
        name
        for name in StrategySpec.model_fields
        if dumped_baseline[name] != dumped_mutated[name]
    }
    assert differing == {field_name}, differing
    assert strategy_version_hash(mutated) != strategy_version_hash(baseline)


@pytest.mark.parametrize(
    "field_name", sorted(_POLICY_FIXED_FIELDS - {"schema_version"})
)
def test_a_policy_fixed_field_admits_exactly_one_value(field_name: str) -> None:
    """Documents why these fields carry no mutation case rather than omitting them."""
    mapping = _base_mapping()
    alternatives: dict[str, Any] = {
        "market_type": "FUTURES",
        "direction": "SHORT",
        "risk_assumptions": {"leverage": "2", "shorting_allowed": False},
        "supported_approximation_policy": {"default": "ALLOW_DECLARED"},
    }
    mapping[field_name] = alternatives[field_name]
    with pytest.raises(ValidationError):
        _spec(mapping)


def test_a_specification_reserialized_through_python_mode_hashes_identically() -> None:
    """Independent equality, not self-comparison: two distinct model instances."""
    first = _base_spec()
    second = StrategySpec.model_validate(first.model_dump(mode="python"))
    assert first is not second
    assert strategy_version_hash(first) == strategy_version_hash(second)


# --- Extension declarations ----------------------------------------------


def test_adding_one_extension_changes_the_content_hash() -> None:
    without = _spec(_with_extensions())
    with_one = _spec(_with_extensions(_EXTENSION_ONE))
    assert strategy_version_hash(with_one) != strategy_version_hash(without)


def test_removing_one_extension_changes_the_content_hash() -> None:
    both = _spec(_with_extensions(_EXTENSION_ONE, _EXTENSION_TWO))
    one = _spec(_with_extensions(_EXTENSION_ONE))
    assert strategy_version_hash(one) != strategy_version_hash(both)


def test_altering_one_extension_content_hash_changes_the_content_hash() -> None:
    altered = copy.deepcopy(_EXTENSION_ONE)
    altered["content_hash"] = "3" * 64
    assert strategy_version_hash(
        _spec(_with_extensions(altered, _EXTENSION_TWO))
    ) != strategy_version_hash(_spec(_with_extensions(_EXTENSION_ONE, _EXTENSION_TWO)))


def test_altering_a_non_hash_extension_field_changes_the_content_hash() -> None:
    """The whole declaration is material, not only its content hash."""
    altered = copy.deepcopy(_EXTENSION_ONE)
    altered["purpose"] = "A different declared purpose."
    assert strategy_version_hash(
        _spec(_with_extensions(altered))
    ) != strategy_version_hash(_spec(_with_extensions(_EXTENSION_ONE)))


def test_reordering_equivalent_extension_declarations_leaves_the_hash_unchanged() -> (
    None
):
    forward = _spec(_with_extensions(_EXTENSION_ONE, _EXTENSION_TWO))
    reversed_source = _spec(_with_extensions(_EXTENSION_TWO, _EXTENSION_ONE))
    assert strategy_version_hash(forward) == strategy_version_hash(reversed_source)


def test_duplicate_extension_declarations_are_rejected_by_the_model() -> None:
    with pytest.raises(ValidationError):
        _spec(_with_extensions(_EXTENSION_ONE, _EXTENSION_ONE))


def test_extension_hashes_use_a_numeric_rather_than_lexicographic_version_key() -> None:
    """`1.10.0` must follow `1.9.0`; a text comparison would invert them.

    This pins the **comparison key**, not the presence of the sort: a validated
    `StrategySpec` already normalizes `engine_extensions` on the same key, so
    deleting Task 5's own sort entirely still passes this. That case belongs to
    `test_sorted_extension_hashes_normalizes_an_unsorted_input_sequence`, which is
    the only test that reaches the sort with an input the model has not ordered.
    """
    late = copy.deepcopy(_EXTENSION_ONE)
    late["version"] = "1.10.0"
    late["content_hash"] = "a" * 64
    early = copy.deepcopy(_EXTENSION_ONE)
    early["version"] = "1.9.0"
    early["content_hash"] = "b" * 64
    spec = _spec(_with_extensions(late, early))
    assert sorted_extension_hashes(spec.engine_extensions) == ["b" * 64, "a" * 64]


def test_sorted_extension_hashes_normalizes_an_unsorted_input_sequence() -> None:
    """The sort is reachable from Task 5's own surface, not only from the model.

    Deliberately asserts against **literal** expected orders rather than against the
    forward result, so deleting the sort cannot be absorbed by both sides changing
    together. The second case carries the numeric-versus-lexicographic pair too, so
    this single test guards both the presence of the sort and its key.
    """
    spec = _spec(_with_extensions(_EXTENSION_ONE, _EXTENSION_TWO))
    reversed_input = tuple(reversed(spec.engine_extensions))
    assert sorted_extension_hashes(spec.engine_extensions) == ["1" * 64, "2" * 64]
    assert sorted_extension_hashes(reversed_input) == ["1" * 64, "2" * 64]

    late = copy.deepcopy(_EXTENSION_ONE)
    late["version"] = "1.10.0"
    late["content_hash"] = "a" * 64
    early = copy.deepcopy(_EXTENSION_ONE)
    early["version"] = "1.9.0"
    early["content_hash"] = "b" * 64
    numeric = _spec(_with_extensions(late, early))
    assert sorted_extension_hashes(tuple(reversed(numeric.engine_extensions))) == [
        "b" * 64,
        "a" * 64,
    ]


def test_the_payload_extension_hashes_match_the_declared_order() -> None:
    spec = _spec(_with_extensions(_EXTENSION_TWO, _EXTENSION_ONE))
    payload = strategy_version_payload(spec)
    assert payload["extension_hashes"] == ["1" * 64, "2" * 64]


# --- Non-material fields --------------------------------------------------


def test_the_payload_names_no_provenance_or_operational_field() -> None:
    """No provenance or operational key appears anywhere in the hashed bytes."""
    payload = strategy_version_payload(_spec(_with_extensions(_EXTENSION_ONE)))
    encoded = json.dumps(payload)
    for excluded in (
        "source_name",
        "source_bytes_sha256",
        "source_byte_length",
        "observed_at_utc",
        "strategy_version_id",
        "source_provenance",
    ):
        assert excluded not in payload
        assert f'"{excluded}"' not in encoded


def test_the_payload_carries_no_self_hash_field() -> None:
    """`content_hash` is not a payload key.

    It is deliberately not banned from the encoded bytes: `content_hash` is also a
    field of `EngineExtensionDeclaration`, where it is material by plan section 5.5
    item 5, so a blanket text ban would forbid the very thing that must be included.
    """
    payload = strategy_version_payload(_spec(_with_extensions(_EXTENSION_ONE)))
    assert "content_hash" not in payload
    embedded = payload["strategy_spec"]
    assert isinstance(embedded, dict)
    assert "content_hash" not in embedded
    declarations = embedded["engine_extensions"]
    assert isinstance(declarations, list)
    assert [
        item["content_hash"] for item in declarations if isinstance(item, dict)
    ] == ["1" * 64]


def test_the_source_name_is_absent_from_the_hashed_bytes() -> None:
    """Not merely absent as a key: absent as a value."""
    spec = _base_spec()
    marker = "distinctivesourcelabel"
    version = _version(spec, provenance=_provenance(source_name=f"{marker}.yaml"))
    assert marker not in json.dumps(strategy_version_payload(spec))
    assert version.content_hash == strategy_version_hash(spec)


def test_changing_the_source_name_leaves_the_content_hash_unchanged() -> None:
    spec = _base_spec()
    first = _version(spec, provenance=_provenance(source_name="one.yaml"))
    second = _version(spec, provenance=_provenance(source_name="two.yaml"))
    assert first.source_provenance.source_name != second.source_provenance.source_name
    assert first.content_hash == second.content_hash


def test_changing_the_observed_time_leaves_the_content_hash_unchanged() -> None:
    spec = _base_spec()
    first = _version(spec, provenance=_provenance(observed_at_utc=_OBSERVED_AT))
    second = _version(
        spec,
        provenance=_provenance(observed_at_utc=_OTHER_OBSERVED_AT),
        created_at_utc=_OTHER_OBSERVED_AT,
    )
    assert (
        first.source_provenance.observed_at_utc
        != second.source_provenance.observed_at_utc
    )
    assert first.created_at_utc != second.created_at_utc
    assert first.content_hash == second.content_hash


def test_changing_the_version_identifier_leaves_the_content_hash_unchanged() -> None:
    spec = _base_spec()
    first = _version(spec, strategy_version_id=_VERSION_ID)
    second = _version(spec, strategy_version_id=_OTHER_VERSION_ID)
    assert first.strategy_version_id != second.strategy_version_id
    assert first.content_hash == second.content_hash


def test_changing_the_source_bytes_alone_leaves_the_content_hash_unchanged() -> None:
    """Raw YAML text is provenance, never identity."""
    spec = _base_spec()
    baseline = _version(spec)
    varied = StrategyVersion(
        schema_version="1.0.0",
        strategy_version_id=_VERSION_ID,
        strategy_id=spec.strategy_id,
        content_hash=strategy_version_hash(spec),
        strategy_spec=spec,
        extension_hashes=(),
        hashing_profile_version=STRATEGY_VERSION_PROFILE_VERSION,
        created_at_utc=_OBSERVED_AT,
        source_provenance=StrategySourceProvenance(
            source_name="sma_cross_long.valid.yaml",
            source_bytes_sha256=sha256_bytes(b"# a comment only\n"),
            source_byte_length=17,
            observed_at_utc=_OBSERVED_AT,
        ),
    )
    assert (
        baseline.source_provenance.source_bytes_sha256
        != varied.source_provenance.source_bytes_sha256
    )
    assert baseline.content_hash == varied.content_hash


# --- The record ------------------------------------------------------------


def test_the_strategy_version_field_list_is_exactly_the_specification_order() -> None:
    """Specification 11.3's eight minimum fields plus the documented addition.

    Asserted as an ordered tuple, not a set: plan lines 2739 to 2750 require the
    specification's minimum fields "in that order", with `source_provenance` as the
    one documented addition appended last.
    """
    assert tuple(StrategyVersion.model_fields) == (
        "schema_version",
        "strategy_version_id",
        "strategy_id",
        "content_hash",
        "strategy_spec",
        "extension_hashes",
        "hashing_profile_version",
        "created_at_utc",
        "source_provenance",
    )


def test_the_source_provenance_field_list_is_exactly_the_plan_order() -> None:
    assert tuple(StrategySourceProvenance.model_fields) == (
        "source_name",
        "source_bytes_sha256",
        "source_byte_length",
        "observed_at_utc",
    )


def test_a_strategy_version_is_frozen_and_rejects_mutation() -> None:
    version = _version(_base_spec())
    for field_name in StrategyVersion.model_fields:
        with pytest.raises(ValidationError):
            setattr(version, field_name, getattr(version, field_name))


def test_a_source_provenance_record_is_frozen_and_rejects_mutation() -> None:
    provenance = _provenance()
    with pytest.raises(ValidationError):
        provenance.source_name = "other.yaml"


def test_a_strategy_version_rejects_an_unknown_field() -> None:
    version = _version(_base_spec())
    payload = version.model_dump(mode="python")
    payload["unexpected"] = 1
    with pytest.raises(ValidationError):
        StrategyVersion.model_validate(payload)


def test_a_strategy_version_rejects_a_content_hash_that_is_not_recomputed() -> None:
    spec = _base_spec()
    with pytest.raises(ValidationError):
        StrategyVersion(
            schema_version="1.0.0",
            strategy_version_id=_VERSION_ID,
            strategy_id=spec.strategy_id,
            content_hash="0" * 64,
            strategy_spec=spec,
            extension_hashes=(),
            hashing_profile_version=STRATEGY_VERSION_PROFILE_VERSION,
            created_at_utc=_OBSERVED_AT,
            source_provenance=_provenance(),
        )


def test_a_strategy_version_rejects_a_dropped_extension_hash() -> None:
    spec = _spec(_with_extensions(_EXTENSION_ONE, _EXTENSION_TWO))
    with pytest.raises(ValidationError):
        StrategyVersion(
            schema_version="1.0.0",
            strategy_version_id=_VERSION_ID,
            strategy_id=spec.strategy_id,
            content_hash=strategy_version_hash(spec),
            strategy_spec=spec,
            extension_hashes=("1" * 64,),
            hashing_profile_version=STRATEGY_VERSION_PROFILE_VERSION,
            created_at_utc=_OBSERVED_AT,
            source_provenance=_provenance(),
        )


def test_a_strategy_version_rejects_a_strategy_id_that_contradicts_its_spec() -> None:
    spec = _base_spec()
    with pytest.raises(ValidationError):
        StrategyVersion(
            schema_version="1.0.0",
            strategy_version_id=_VERSION_ID,
            strategy_id=_OTHER_STRATEGY_ID,
            content_hash=strategy_version_hash(spec),
            strategy_spec=spec,
            extension_hashes=(),
            hashing_profile_version=STRATEGY_VERSION_PROFILE_VERSION,
            created_at_utc=_OBSERVED_AT,
            source_provenance=_provenance(),
        )


def test_a_strategy_version_accepts_the_declared_extension_hashes() -> None:
    spec = _spec(_with_extensions(_EXTENSION_TWO, _EXTENSION_ONE))
    version = _version(spec)
    assert version.extension_hashes == ("1" * 64, "2" * 64)
    assert version.strategy_id == _STRATEGY_ID


def test_the_version_identifier_is_derived_from_the_content_hash_alone() -> None:
    spec = _base_spec()
    digest = strategy_version_hash(spec)
    derived = strategy_version_identifier(digest)
    assert derived.startswith("strv_")
    assert derived == strategy_version_identifier(digest)
    assert derived != strategy_version_identifier("0" * 64)


def test_the_derived_version_identifier_validates_as_a_strategy_version_id() -> None:
    spec = _base_spec()
    version = _version(
        spec,
        strategy_version_id=strategy_version_identifier(strategy_version_hash(spec)),
    )
    assert version.strategy_version_id == strategy_version_identifier(
        strategy_version_hash(spec)
    )


# --- Deep immutability of the material mapping fields ----------------------
#
# `CanonicalModel` sets `frozen=True`, which is shallow: it stops attribute
# rebinding but not mutation of a nested container. Both mapping fields reach
# the hashed payload through `spec.model_dump(mode="json")`, so an in-place
# insertion used to succeed and leave the recorded `content_hash` stale. These
# assert the invariant, so a regression fails here rather than in a hash.


def test_the_spec_parameter_mapping_rejects_in_place_insertion() -> None:
    version = _version(_base_spec())
    recorded = version.content_hash
    replacement = next(iter(version.strategy_spec.parameters.values()))

    with pytest.raises(TypeError):
        version.strategy_spec.parameters["injected_key"] = replacement  # type: ignore[index]

    assert "injected_key" not in version.strategy_spec.parameters
    assert version.content_hash == recorded
    assert strategy_version_hash(version.strategy_spec) == recorded


def test_the_feature_parameter_mapping_rejects_in_place_insertion() -> None:
    version = _version(_base_spec())
    recorded = version.content_hash
    feature = version.strategy_spec.features[0]

    with pytest.raises(TypeError):
        feature.parameters["injected_key"] = "fast_period"  # type: ignore[index]

    assert "injected_key" not in feature.parameters
    assert version.content_hash == recorded
    assert strategy_version_hash(version.strategy_spec) == recorded


# --- Mapping order: preserved in the record, immaterial to identity ---------
#
# `json.dumps` rather than `canonical_json_bytes` throughout this block:
# `canonical_json_bytes` sorts object keys, which would destroy the very
# difference under test before the model ever saw it.


def _reordered(mapping: dict[str, Any]) -> dict[str, Any]:
    return dict(reversed(list(mapping.items())))


def _spec_from_json(mapping: dict[str, Any]) -> StrategySpec:
    return StrategySpec.model_validate_json(json.dumps(mapping))


def test_the_validated_parameter_insertion_order_is_preserved() -> None:
    """No validator may sort either mapping merely to make it immutable."""
    mapping = _base_mapping()
    straight = _spec_from_json(mapping)
    declared = tuple(mapping["parameters"])

    mapping["parameters"] = _reordered(mapping["parameters"])
    reversed_spec = _spec_from_json(mapping)

    assert tuple(straight.parameters) == declared
    assert tuple(reversed_spec.parameters) == tuple(reversed(declared))
    assert tuple(reversed_spec.parameters) != tuple(straight.parameters)


def test_the_validated_feature_parameter_insertion_order_is_preserved() -> None:
    mapping = _base_mapping()
    mapping["features"][0]["parameters"] = {
        "period": "fast_period",
        "other": "slow_period",
    }
    forward = _spec_from_json(mapping)

    mapping["features"][0]["parameters"] = _reordered(
        mapping["features"][0]["parameters"]
    )
    backward = _spec_from_json(mapping)

    assert tuple(forward.features[0].parameters) == ("period", "other")
    assert tuple(backward.features[0].parameters) == ("other", "period")


def test_mapping_insertion_order_alone_does_not_change_identity() -> None:
    """Order is preserved in the record yet immaterial to the hash, because
    canonical JSON sorts object keys before they are ever hashed."""
    mapping = _base_mapping()
    mapping["features"][0]["parameters"] = {
        "period": "fast_period",
        "other": "slow_period",
    }
    straight = _spec_from_json(mapping)

    mapping["parameters"] = _reordered(mapping["parameters"])
    mapping["features"][0]["parameters"] = _reordered(
        mapping["features"][0]["parameters"]
    )
    reordered = _spec_from_json(mapping)

    # Non-vacuity: the two records genuinely iterate in different orders.
    assert tuple(reordered.parameters) != tuple(straight.parameters)
    assert tuple(reordered.features[0].parameters) != tuple(
        straight.features[0].parameters
    )

    assert canonical_json_bytes(reordered) == canonical_json_bytes(straight)
    assert strategy_version_hash(reordered) == strategy_version_hash(straight)


# --- Feature parameters are material content -------------------------------


def test_changing_one_feature_parameter_value_changes_the_hash() -> None:
    mapping = _base_mapping()
    baseline = strategy_version_hash(_spec(mapping))

    mapping["features"][0]["parameters"]["period"] = "slow_period"

    assert strategy_version_hash(_spec(mapping)) != baseline


def test_adding_one_feature_parameter_changes_the_hash() -> None:
    """Model-level rather than loader-level: the operation-signature check that
    would reject an unexpected parameter belongs to the Task 4 graph validator,
    so this isolates the identity question from that diagnostic."""
    mapping = _base_mapping()
    baseline = strategy_version_hash(_spec(mapping))

    mapping["features"][0]["parameters"]["extra"] = "slow_period"

    assert strategy_version_hash(_spec(mapping)) != baseline


def test_removing_one_feature_parameter_changes_the_hash() -> None:
    mapping = _base_mapping()
    baseline = strategy_version_hash(_spec(mapping))

    mapping["features"][0]["parameters"] = {}

    assert strategy_version_hash(_spec(mapping)) != baseline


# --------------------------------------------------------------------------
# Forward-only UTC schema view -- the two `StrategyVersion` timestamps
# --------------------------------------------------------------------------
#
# `parse_utc` routes JSON text through `datetime.fromisoformat`, so it has always
# rejected an impossible calendar date and an out-of-range clock, while the legacy
# `UtcDateTime` projection published only `[0-9]{2}` runs and accepted both. That
# projection is frozen into three released Stage 3 `$id`s, so it could not be
# tightened in place. `StrategyVersion.created_at_utc` and
# `StrategySourceProvenance.observed_at_utc` now carry the forward-only
# `CalendarValidUtcDateTime` view. Both reach `strategy/strategy-version-v1`.

_IMPOSSIBLE_VERSION_INSTANTS = (
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

_REAL_VERSION_INSTANTS = (
    "0001-01-01T00:00:00Z",
    "0004-02-29T00:00:00Z",
    "0400-02-29T00:00:00Z",
    "2000-02-29T00:00:00Z",
    "2024-02-29T00:00:00Z",
    "2026-02-28T23:59:59Z",
    "2026-04-30T00:00:00.000001Z",
    "9999-12-31T23:59:59Z",
)

_VERSION_TIMESTAMP_FIELDS = ("created_at_utc", "observed_at_utc")


def _version_document(field: str, instant: str) -> dict[str, Any]:
    """A complete valid version document with exactly one timestamp replaced."""
    document: dict[str, Any] = json.loads(_version(_base_spec()).model_dump_json())
    if field == "created_at_utc":
        document["created_at_utc"] = instant
    else:
        document["source_provenance"]["observed_at_utc"] = instant
    return document


def _version_schema(mode: str) -> dict[str, Any]:
    schema: dict[str, Any] = StrategyVersion.model_json_schema(
        mode=mode  # type: ignore[arg-type]
    )
    return schema


def _version_accepts(document: dict[str, Any]) -> bool:
    try:
        StrategyVersion.model_validate_json(json.dumps(document))
    except ValidationError:
        return False
    return True


def test_the_version_baseline_document_agrees_on_every_side() -> None:
    """Non-vacuity for every clause below: one complete valid document."""
    document = json.loads(_version(_base_spec()).model_dump_json())
    assert _version_accepts(document)
    for mode in ("validation", "serialization"):
        schema = _version_schema(mode)
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(document)


@pytest.mark.parametrize("instant", _IMPOSSIBLE_VERSION_INSTANTS)
@pytest.mark.parametrize("field", _VERSION_TIMESTAMP_FIELDS)
def test_the_version_schema_rejects_an_impossible_instant(
    field: str, instant: str
) -> None:
    document = _version_document(field, instant)
    assert not _version_accepts(document)
    for mode in ("validation", "serialization"):
        assert not Draft202012Validator(_version_schema(mode)).is_valid(document), (
            mode,
            field,
            instant,
        )


@pytest.mark.parametrize("instant", _REAL_VERSION_INSTANTS)
@pytest.mark.parametrize("field", _VERSION_TIMESTAMP_FIELDS)
def test_the_version_schema_over_rejects_no_real_instant(
    field: str, instant: str
) -> None:
    """The only failure mode a hand-written calendar regex has. Neither of these
    two timestamps is material to identity, so a real instant must survive."""
    document = _version_document(field, instant)
    assert _version_accepts(document)
    for mode in ("validation", "serialization"):
        Draft202012Validator(_version_schema(mode)).validate(document)


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_both_version_timestamps_publish_the_forward_view(mode: str) -> None:
    """Structural, so a field silently reverted to the legacy alias is caught
    even when no sample document happens to fail."""
    schema = _version_schema(mode)
    reference = {"$ref": "#/$defs/CalendarValidUtcDateTime"}
    assert schema["properties"]["created_at_utc"] == reference
    provenance = schema["$defs"]["StrategySourceProvenance"]["properties"]
    assert provenance["observed_at_utc"] == reference
    # And the embedded specification's own timestamp resolves to the same entry.
    authoring = schema["$defs"]["AuthoringMetadata"]["properties"]
    assert authoring["created_at_utc"] == reference

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
    # `strategy-version-v1` reaches `UtcDateTime` through exactly these three
    # fields, so once all three migrate the permissive shared definition must be
    # gone from the schema entirely.
    assert "UtcDateTime" not in schema["$defs"]


def test_the_version_view_changes_no_canonical_byte_or_hash() -> None:
    """Schema projection only. Both migrated fields sit outside the identity
    payload, so this pins the whole record rather than only the fields."""
    spec = _base_spec()
    version = _version(spec)
    assert version.content_hash == strategy_version_hash(spec)
    assert canonical_json_bytes(version.source_provenance) == (
        b'{"observed_at_utc":"2026-08-18T12:00:00Z",'
        b'"source_byte_length":27,'
        b'"source_bytes_sha256":'
        b'"' + sha256_bytes(b"schema_version: placeholder").encode("ascii") + b'",'
        b'"source_name":"sma_cross_long.valid.yaml"}'
    )
    assert list(StrategyVersion.model_fields) == [
        "schema_version",
        "strategy_version_id",
        "strategy_id",
        "content_hash",
        "strategy_spec",
        "extension_hashes",
        "hashing_profile_version",
        "created_at_utc",
        "source_provenance",
    ]
    assert list(StrategySourceProvenance.model_fields) == [
        "source_name",
        "source_bytes_sha256",
        "source_byte_length",
        "observed_at_utc",
    ]
