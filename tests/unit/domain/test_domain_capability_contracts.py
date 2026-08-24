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
from typing import Any, Literal

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import TypeAdapter, ValidationError

import crypto_lab.domain as domain_package
from crypto_lab.adapters import descriptors as adapters_descriptors
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.capability_names import CapabilityName, VocabularyVersion
from crypto_lab.domain.capability_requirements import (
    MAX_REQUIREMENT_COMPARISON_LEVELS,
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


# --------------------------------------------------------------------------
# Runtime/schema uniqueness agreement -- final pre-Task-8 closure
# --------------------------------------------------------------------------
#
# `validate_levels_are_unique_and_sorted` rejects a duplicate, and plan section
# 3.1 requires `json_schema_extra` to supply the `uniqueItems` Pydantic does not
# emit for a tuple field. This field carried the validator and not the keyword,
# so a standards-compliant Draft 2020-12 validator accepted a document ordinary
# Pydantic validation rejects. Task 8 publishes this record directly as
# `capabilities/capability-requirement-v1.schema.json`, and again through the
# `$defs` of `strategy-spec-v1` and `strategy-version-v1`, so the disagreement
# had to be closed before publication. Same defect class as the
# `ApproximationDeclaration.prevented_comparison_levels` and
# `CapabilityDeclaration.limitations` correction in commit `00879f6`.

_SCHEMA_MODES: tuple[Literal["validation", "serialization"], ...] = (
    "validation",
    "serialization",
)


def _requirement_document(levels: list[str]) -> dict[str, Any]:
    """A **complete** requirement document, not an isolated property node.

    Validated through `Draft202012Validator` against the whole generated model
    schema exactly as an external consumer would validate it; a hand-built array
    schema would prove nothing about the record Task 8 publishes.
    """
    return _REQUIREMENT | {"comparison_levels": levels}


@pytest.mark.parametrize("mode", _SCHEMA_MODES)
def test_the_comparison_level_tuple_emits_unique_items_in_both_modes(
    mode: Literal["validation", "serialization"],
) -> None:
    """The published contract must not be weaker than the runtime one.

    Both modes: the registry renders `mode="serialization"`, while
    `model_json_schema()` and `TypeAdapter.json_schema()` default to
    `validation`, and the two are generated independently.
    """
    assert (
        CapabilityRequirement.model_json_schema(mode=mode)["properties"][
            "comparison_levels"
        ]["uniqueItems"]
        is True
    )


@pytest.mark.parametrize("mode", _SCHEMA_MODES)
def test_the_registry_type_adapter_path_emits_it_too(
    mode: Literal["validation", "serialization"],
) -> None:
    """`schema_registry.render_schema_files` renders through a `TypeAdapter`.

    Task 8's Appendix F entry is `TypeAdapter(CapabilityRequirement)`, so the
    keyword must survive that call and not only the classmethod.
    """
    schema = _REQUIREMENT_ADAPTER.json_schema(mode=mode)

    assert schema["properties"]["comparison_levels"]["uniqueItems"] is True


@pytest.mark.parametrize("mode", _SCHEMA_MODES)
def test_the_generated_requirement_schema_rejects_duplicate_levels(
    mode: Literal["validation", "serialization"],
) -> None:
    """The defect stated as an executable fact.

    Before the correction this exact document was **accepted** by the generated
    schema and **rejected** by Pydantic.
    """
    schema = CapabilityRequirement.model_json_schema(mode=mode)
    Draft202012Validator.check_schema(schema)

    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(schema).validate(
            _requirement_document(["LEVEL_1", "LEVEL_1"])
        )


@pytest.mark.parametrize("mode", _SCHEMA_MODES)
def test_the_generated_requirement_schema_accepts_distinct_levels(
    mode: Literal["validation", "serialization"],
) -> None:
    """The correction must narrow nothing beyond uniqueness."""
    schema = CapabilityRequirement.model_json_schema(mode=mode)
    document = _requirement_document(["LEVEL_1", "LEVEL_2", "LEVEL_3"])

    Draft202012Validator(schema).validate(document)
    assert len(document["comparison_levels"]) == MAX_REQUIREMENT_COMPARISON_LEVELS


@pytest.mark.parametrize("mode", _SCHEMA_MODES)
def test_the_generated_requirement_schema_still_accepts_the_empty_level_set(
    mode: Literal["validation", "serialization"],
) -> None:
    """Specification 11.5's explicit empty array must stay valid.

    An empty array satisfies `uniqueItems` trivially, but the field carries no
    `minItems` and the emptiness is specified behaviour rather than an accident,
    so it is pinned on the schema side too.
    """
    schema = CapabilityRequirement.model_json_schema(mode=mode)

    Draft202012Validator(schema).validate(_requirement_document([]))
    assert "minItems" not in schema["properties"]["comparison_levels"]


@pytest.mark.parametrize("mode", _SCHEMA_MODES)
def test_the_unique_items_addition_preserves_every_other_keyword(
    mode: Literal["validation", "serialization"],
) -> None:
    """Exactly one keyword is added; the node is otherwise identical.

    The keyword set is transcribed from evidence captured before the edit, not
    from the current code, so this fails if the fix replaced the node rather
    than extending it. `ComparisonLevel` reaches the array through a `$ref`, so
    the referenced definition is checked too -- a widened item schema would
    otherwise be invisible here.
    """
    schema = CapabilityRequirement.model_json_schema(mode=mode)
    node = schema["properties"]["comparison_levels"]

    assert set(node) == {"type", "items", "maxItems", "title", "uniqueItems"}
    assert node["type"] == "array"
    assert node["items"] == {"$ref": "#/$defs/ComparisonLevel"}
    assert node["maxItems"] == MAX_REQUIREMENT_COMPARISON_LEVELS
    assert node["title"] == "Comparison Levels"
    assert schema["additionalProperties"] is False
    # Literal, not derived from `ComparisonLevel` or from `model_fields`. An
    # independent review of the previous correction pointed out that a
    # self-derived expectation moves with the thing it claims to check, so it
    # would not notice a widened item schema or a lost required field.
    assert schema["$defs"]["ComparisonLevel"]["enum"] == [
        "LEVEL_1",
        "LEVEL_2",
        "LEVEL_3",
    ]
    assert schema["$defs"]["ComparisonLevel"]["type"] == "string"
    assert schema["required"] == [
        "schema_version",
        "capability",
        "required",
        "minimum_semantics",
        "approximation_policy",
        "comparison_levels",
    ]


@pytest.mark.parametrize("mode", _SCHEMA_MODES)
def test_no_other_requirement_property_gained_unique_items(
    mode: Literal["validation", "serialization"],
) -> None:
    """The constraint must land on the intended field only."""
    schema = CapabilityRequirement.model_json_schema(mode=mode)
    marked = {
        name
        for name, node in schema["properties"].items()
        if isinstance(node, dict) and node.get("uniqueItems") is True
    }

    assert marked == {"comparison_levels"}


@pytest.mark.parametrize("mode", _SCHEMA_MODES)
def test_sortedness_stays_an_inexpressible_residual(
    mode: Literal["validation", "serialization"],
) -> None:
    """Only the expressible half of the divergence is closed, and that is stated.

    `validate_levels_are_unique_and_sorted` rejects an unsorted array too, and
    Draft 2020-12 has no ordering keyword. So `["LEVEL_2", "LEVEL_1"]` still
    passes the published schema and still fails at runtime. Recorded as an
    executable fact rather than as a comment, so a later reader cannot mistake
    "runtime/schema agreement" for "absolute equivalence", and so that the day a
    dialect can express ordering this test is the one that has to change.
    """
    schema = CapabilityRequirement.model_json_schema(mode=mode)
    unsorted = _requirement_document(["LEVEL_2", "LEVEL_1"])

    Draft202012Validator(schema).validate(unsorted)
    with pytest.raises(ValidationError, match="sorted"):
        _REQUIREMENT_ADAPTER.validate_json(json.dumps(unsorted))


# Preventive runtime evidence. These begin GREEN: runtime uniqueness already
# exists and is unchanged by this correction. They are declared so the agreement
# is guarded from both sides rather than only from the schema side.


def test_pydantic_still_rejects_duplicate_comparison_levels() -> None:
    """Preventive: the runtime half of the agreement.

    The message is asserted, so removing only the uniqueness clause of
    `validate_levels_are_unique_and_sorted` -- leaving the sortedness clause,
    which a duplicate pair also satisfies -- cannot pass this.
    """
    with pytest.raises(ValidationError, match="unique"):
        _REQUIREMENT_ADAPTER.validate_json(
            json.dumps(_requirement_document(["LEVEL_1", "LEVEL_1"]))
        )


def test_pydantic_still_accepts_distinct_levels_as_a_sorted_tuple() -> None:
    """Preventive: tuple representation, ordering, and frozenness are unchanged."""
    requirement = _requirement(comparison_levels=["LEVEL_1", "LEVEL_2", "LEVEL_3"])
    value = requirement.comparison_levels

    assert isinstance(value, tuple)
    assert list(value) == sorted(value, key=str)
    assert value == (
        ComparisonLevel.LEVEL_1,
        ComparisonLevel.LEVEL_2,
        ComparisonLevel.LEVEL_3,
    )
    assert CapabilityRequirement.model_config["frozen"] is True
    with pytest.raises(ValidationError):
        requirement.comparison_levels = ()


def test_both_requirement_dump_modes_keep_their_shape() -> None:
    """Preventive: a schema keyword must not alter either serialized form."""
    requirement = _requirement()
    python_mode = requirement.model_dump(mode="python")
    json_mode = requirement.model_dump(mode="json")

    assert set(python_mode) == set(json_mode) == set(CapabilityRequirement.model_fields)
    assert isinstance(python_mode["comparison_levels"], tuple)
    assert isinstance(json_mode["comparison_levels"], list)
    assert [str(item) for item in python_mode["comparison_levels"]] == json_mode[
        "comparison_levels"
    ]


def test_the_correction_changes_no_requirement_canonical_byte() -> None:
    """`uniqueItems` is a schema keyword, not a field: no instance may move.

    The literals were captured from the pre-correction tree.
    """
    assert canonical_json_bytes(_requirement()) == (
        b'{"approximation_policy":"REJECT","capability":"market.spot",'
        b'"comparison_levels":["LEVEL_1","LEVEL_2"],'
        b'"minimum_semantics":"capabilities/v1","required":true,'
        b'"schema_version":"1.0.0"}'
    )
    assert canonical_json_bytes(_requirement(comparison_levels=[])) == (
        b'{"approximation_policy":"REJECT","capability":"market.spot",'
        b'"comparison_levels":[],"minimum_semantics":"capabilities/v1",'
        b'"required":true,"schema_version":"1.0.0"}'
    )
