"""Test the Task 2 domain contracts `StrategySpec` depends on.

Covers `CapabilityName`, `VocabularyVersion`, `ComparisonLevel`,
`ApproximationPolicy`, and `CapabilityRequirement`, including items B and C of
the plan's reviewed correction on hash-material field types.

`CapabilityName` and `VocabularyVersion` are relocated here from
`adapters/descriptors.py` per plan section 5.7. Task 6 deletes the adapters
definitions and re-exports these, and `schema-generate-check` must keep
`adapter-descriptor-v1.schema.json` byte-identical across that swap — so a
constraint drift introduced here would only surface four tasks later. Two tests
below pin the two definitions against each other for exactly that reason.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import TypeAdapter, ValidationError

import crypto_lab.domain as domain_package
from crypto_lab.adapters import descriptors as adapters_descriptors
from crypto_lab.domain.capability_names import CapabilityName, VocabularyVersion
from crypto_lab.domain.capability_requirements import (
    ApproximationPolicy,
    CapabilityRequirement,
)
from crypto_lab.domain.comparison_levels import ComparisonLevel

_CAPABILITY_ADAPTER: TypeAdapter[str] = TypeAdapter(CapabilityName)
_VOCABULARY_ADAPTER: TypeAdapter[str] = TypeAdapter(VocabularyVersion)
_REQUIREMENT_ADAPTER: TypeAdapter[CapabilityRequirement] = TypeAdapter(
    CapabilityRequirement
)

_REQUIREMENT: dict[str, Any] = {
    "schema_version": "1.0.0",
    "capability": "market.spot",
    "required": True,
    "minimum_semantics": "capabilities/v1",
    "approximation_policy": "REJECT",
    "comparison_levels": ["LEVEL_1", "LEVEL_2"],
}


def _requirement(**overrides: object) -> CapabilityRequirement:
    return _REQUIREMENT_ADAPTER.validate_json(json.dumps(_REQUIREMENT | overrides))


# --- Relocated name constraints, pinned against the adapters definitions ---


def test_the_relocated_capability_name_matches_the_adapters_definition() -> None:
    relocated = _CAPABILITY_ADAPTER.json_schema()
    inherited = TypeAdapter(adapters_descriptors.CapabilityName).json_schema()

    assert relocated == inherited


def test_the_relocated_vocabulary_version_matches_the_adapters_definition() -> None:
    relocated = _VOCABULARY_ADAPTER.json_schema()
    inherited = TypeAdapter(adapters_descriptors.VocabularyVersion).json_schema()

    assert relocated == inherited


@pytest.mark.parametrize(
    "name",
    ["market.spot", "data.ohlcv", "execution.bar_market", "runtime.backtest"],
)
def test_a_vocabulary_capability_name_is_accepted(name: str) -> None:
    assert _CAPABILITY_ADAPTER.validate_python(name) == name


@pytest.mark.parametrize(
    "name",
    ["Market.Spot", "market", "market.", ".spot", "market spot", "market-spot", "ab"],
)
def test_a_malformed_capability_name_is_rejected(name: str) -> None:
    with pytest.raises(ValidationError):
        _CAPABILITY_ADAPTER.validate_python(name)


def test_the_vocabulary_version_accepts_only_the_capabilities_form() -> None:
    assert _VOCABULARY_ADAPTER.validate_python("capabilities/v1") == "capabilities/v1"
    assert _VOCABULARY_ADAPTER.validate_python("capabilities/v2") == "capabilities/v2"
    for rejected in ("capabilities/v0", "capabilities/1", "capability/v1", "v1", ""):
        with pytest.raises(ValidationError):
            _VOCABULARY_ADAPTER.validate_python(rejected)


# --- `ComparisonLevel` ----------------------------------------------------


def test_the_comparison_level_vocabulary_is_exactly_three_members() -> None:
    assert [member.value for member in ComparisonLevel] == [
        "LEVEL_1",
        "LEVEL_2",
        "LEVEL_3",
    ]


def test_comparison_levels_sort_in_their_declared_order() -> None:
    """Sorting is by value, so the canonical order is also the numeric order."""
    assert sorted(ComparisonLevel, key=str) == [
        ComparisonLevel.LEVEL_1,
        ComparisonLevel.LEVEL_2,
        ComparisonLevel.LEVEL_3,
    ]


# --- Item B: `ApproximationPolicy` ----------------------------------------


def test_the_approximation_policy_vocabulary_is_exactly_two_members() -> None:
    assert [member.value for member in ApproximationPolicy] == [
        "REJECT",
        "ALLOW_DECLARED",
    ]


def test_no_permissive_or_wildcard_policy_exists() -> None:
    values = {member.value for member in ApproximationPolicy}

    for forbidden in ("ALLOW_ANY", "PREFER", "AUTO", "BEST_EFFORT", "ANY", "*"):
        assert forbidden not in values


@pytest.mark.parametrize("policy", ["REJECT", "ALLOW_DECLARED"])
def test_an_explicit_policy_round_trips(policy: str) -> None:
    requirement = _requirement(approximation_policy=policy)

    assert requirement.approximation_policy.value == policy
    dumped = requirement.model_dump(mode="json")
    assert dumped["approximation_policy"] == policy
    assert _REQUIREMENT_ADAPTER.validate_json(json.dumps(dumped)) == requirement


@pytest.mark.parametrize(
    "policy",
    ["ALLOW_ANY", "PREFER", "AUTO", "BEST_EFFORT", "reject", "allow_declared", ""],
)
def test_an_unknown_policy_value_is_rejected(policy: str) -> None:
    with pytest.raises(ValidationError):
        _requirement(approximation_policy=policy)


def test_the_requirement_policy_is_required_with_no_injected_default() -> None:
    """No implicit default may be injected: an omitted policy must fail."""
    payload = {
        name: value
        for name, value in _REQUIREMENT.items()
        if name != "approximation_policy"
    }

    with pytest.raises(ValidationError):
        _REQUIREMENT_ADAPTER.validate_json(json.dumps(payload))

    field = CapabilityRequirement.model_fields["approximation_policy"]
    assert field.is_required()


# --- Item C: `minimum_semantics` ------------------------------------------


def test_the_exact_minimum_semantics_value_is_accepted() -> None:
    assert _requirement().minimum_semantics == "capabilities/v1"


@pytest.mark.parametrize(
    "value",
    ["1.0.0", "v1", "capability/v1", "capabilities/v2", "", "CAPABILITIES/V1", None, 1],
)
def test_any_other_minimum_semantics_value_is_rejected(value: object) -> None:
    """A future value requires a new reviewed schema and vocabulary migration."""
    with pytest.raises(ValidationError):
        _requirement(minimum_semantics=value)


def test_minimum_semantics_is_required() -> None:
    payload = {
        name: value
        for name, value in _REQUIREMENT.items()
        if name != "minimum_semantics"
    }

    with pytest.raises(ValidationError):
        _REQUIREMENT_ADAPTER.validate_json(json.dumps(payload))


def test_minimum_semantics_is_not_a_semantic_version_or_free_text() -> None:
    schema = _REQUIREMENT_ADAPTER.json_schema()
    field_schema = schema["properties"]["minimum_semantics"]

    assert field_schema.get("const") == "capabilities/v1"
    assert "pattern" not in field_schema


# --- Specification 11.3 field set -----------------------------------------


def test_the_requirement_carries_exactly_the_six_specified_fields() -> None:
    assert list(CapabilityRequirement.model_fields) == [
        "schema_version",
        "capability",
        "required",
        "minimum_semantics",
        "approximation_policy",
        "comparison_levels",
    ]


def test_a_complete_requirement_is_accepted() -> None:
    requirement = _requirement()

    assert requirement.capability == "market.spot"
    assert requirement.required is True
    assert requirement.approximation_policy is ApproximationPolicy.REJECT
    assert requirement.comparison_levels == (
        ComparisonLevel.LEVEL_1,
        ComparisonLevel.LEVEL_2,
    )


def test_an_unknown_requirement_field_is_rejected() -> None:
    with pytest.raises(ValidationError):
        _requirement(fallback_capability="market.margin")


def test_a_requirement_is_frozen() -> None:
    requirement = _requirement()

    with pytest.raises(ValidationError):
        requirement.required = False


def test_an_explicit_empty_comparison_level_set_is_accepted() -> None:
    """Specification 11.5 requires an explicit empty array rather than absence.

    An empty set scopes the requirement to no particular level; Task 6 consumes
    that meaning during resolution.
    """
    assert _requirement(comparison_levels=[]).comparison_levels == ()


@pytest.mark.parametrize(
    "levels",
    [
        ["LEVEL_2", "LEVEL_1"],
        ["LEVEL_1", "LEVEL_1"],
        ["LEVEL_4"],
        ["level_1"],
        ["LEVEL_1", "LEVEL_2", "LEVEL_3", "LEVEL_1"],
    ],
)
def test_an_unsorted_duplicated_or_unknown_level_set_is_rejected(
    levels: list[str],
) -> None:
    with pytest.raises(ValidationError):
        _requirement(comparison_levels=levels)


def test_a_non_vocabulary_capability_is_rejected_by_the_name_contract() -> None:
    with pytest.raises(ValidationError):
        _requirement(capability="Market Spot")


def test_the_requirement_schema_version_is_the_canonical_literal() -> None:
    assert _requirement().schema_version == "1.0.0"
    with pytest.raises(ValidationError):
        _requirement(schema_version="strategy/v1")


# --- Package surface ------------------------------------------------------


def test_the_domain_package_re_exports_every_task_two_name() -> None:
    for name in (
        "ApproximationPolicy",
        "CapabilityName",
        "CapabilityRequirement",
        "ComparisonLevel",
        "Failure",
        "Result",
        "Success",
        "VocabularyVersion",
    ):
        assert name in domain_package.__all__
        assert getattr(domain_package, name) is not None


def test_every_re_exported_domain_name_resolves_exactly_once() -> None:
    """Ordering is enforced by Ruff's `RUF022`, so this pins the other half:
    no duplicate entry, and no name exported that cannot be resolved."""
    exported = list(domain_package.__all__)

    assert len(exported) == len(set(exported))
    for name in exported:
        assert hasattr(domain_package, name), name
