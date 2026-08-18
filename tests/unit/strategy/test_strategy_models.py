"""Test the strict strategy models of plan Task 2 steps 12 and 14.

At step 12 this module covers **only** `EngineExtensionDeclaration`, `Direction`,
and the two extension-effect classifications of item D of the plan's reviewed
correction. A module-level import of `StrategySpec` here would fail collection
and leave step 12 with no clean GREEN, so the `StrategySpec` coverage is appended
in step 14.
"""

from __future__ import annotations

import json
from collections.abc import Mapping as CollectionsMapping
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, get_args, get_origin

import pytest
from pydantic import TypeAdapter, ValidationError

from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.capability_requirements import ApproximationPolicy
from crypto_lab.domain.identifiers import NormalizedIdentifier
from crypto_lab.domain.records import MarketType
from crypto_lab.domain.results import Success
from crypto_lab.strategy.expressions import LiteralValueType
from crypto_lab.strategy.models import (
    MAX_FEATURE_PARAMETERS,
    MAX_PARAMETERS,
    Direction,
    EngineExtensionDeclaration,
    ExtensionEconomicEffect,
    ExtensionLifecycleEffect,
    FeatureDefinition,
    ParameterDefinition,
    StrategySpec,
    _frozen_mapping,
)
from crypto_lab.strategy.yaml_source import load_yaml_document

_CONTENT_HASH = "3f" * 32

_DECLARATION: dict[str, Any] = {
    "adapter_name": "vectorbt_adapter",
    "extension_id": "bar_close_hook",
    "version": "1.0.0",
    "content_hash": _CONTENT_HASH,
    "purpose": "Adapts the bar-close lifecycle hook without altering execution.",
    "lifecycle_effect": "LIFECYCLE_HOOKS_ONLY",
    "economic_effect": "NONE",
}

_DECLARATION_ADAPTER: TypeAdapter[EngineExtensionDeclaration] = TypeAdapter(
    EngineExtensionDeclaration
)


def _declaration(**overrides: object) -> EngineExtensionDeclaration:
    return _DECLARATION_ADAPTER.validate_json(json.dumps(_DECLARATION | overrides))


# --- Specification 12.6 field set -----------------------------------------


def test_the_declaration_carries_exactly_the_seven_specified_fields() -> None:
    """The first three are Task 5's `extension_hashes` sort key, so a rename
    here would propagate straight into a permanent `content_hash`."""
    assert list(EngineExtensionDeclaration.model_fields) == [
        "adapter_name",
        "extension_id",
        "version",
        "content_hash",
        "purpose",
        "lifecycle_effect",
        "economic_effect",
    ]


def test_a_complete_declaration_is_accepted() -> None:
    declaration = _declaration()

    assert declaration.adapter_name == "vectorbt_adapter"
    assert declaration.extension_id == "bar_close_hook"
    assert declaration.version == "1.0.0"
    assert declaration.content_hash == _CONTENT_HASH
    assert declaration.lifecycle_effect is ExtensionLifecycleEffect.LIFECYCLE_HOOKS_ONLY
    assert declaration.economic_effect is ExtensionEconomicEffect.NONE


def test_an_unknown_field_is_rejected() -> None:
    with pytest.raises(ValidationError):
        _declaration(entry_point="module:function")


@pytest.mark.parametrize("field", list(_DECLARATION))
def test_every_field_is_required(field: str) -> None:
    payload = {name: value for name, value in _DECLARATION.items() if name != field}

    with pytest.raises(ValidationError):
        _DECLARATION_ADAPTER.validate_json(json.dumps(payload))


def test_a_declaration_is_frozen() -> None:
    declaration = _declaration()

    with pytest.raises(ValidationError):
        declaration.economic_effect = ExtensionEconomicEffect.PREVENTS_LEVEL_2


def test_malformed_identity_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        _declaration(adapter_name="VectorBT Adapter")
    with pytest.raises(ValidationError):
        _declaration(version="1.0")
    with pytest.raises(ValidationError):
        _declaration(content_hash="3f")
    with pytest.raises(ValidationError):
        _declaration(purpose="")


# --- Item D: extension classifications ------------------------------------


def test_the_lifecycle_effect_vocabulary_is_exactly_two_members() -> None:
    assert [member.value for member in ExtensionLifecycleEffect] == [
        "LIFECYCLE_HOOKS_ONLY",
        "ALTERS_EXECUTION_BEHAVIOR",
    ]


def test_the_economic_effect_vocabulary_is_exactly_three_members() -> None:
    assert [member.value for member in ExtensionEconomicEffect] == [
        "NONE",
        "PREVENTS_LEVEL_2",
        "PREVENTS_LEVEL_1_AND_LEVEL_2",
    ]


def test_there_is_no_level_three_or_bare_level_one_economic_effect() -> None:
    """Specification 12.6 bounds an extension's economic effect to Level 1 or 2,
    and 25.2 makes Level 2 a superset of Level 1. This says nothing about
    `ApproximationDeclaration.prevented_comparison_levels`, which a later task
    owns and which specification 13.4 requires to admit Level 3."""
    values = {member.value for member in ExtensionEconomicEffect}

    assert "PREVENTS_LEVEL_3" not in values
    assert "PREVENTS_LEVEL_1" not in values


@pytest.mark.parametrize(
    ("field", "unknown"),
    [
        ("lifecycle_effect", "LIFECYCLE_HOOKS"),
        ("lifecycle_effect", "ALTERS_EXECUTION"),
        ("lifecycle_effect", "lifecycle_hooks_only"),
        ("lifecycle_effect", ""),
        ("economic_effect", "PREVENTS_LEVEL_3"),
        ("economic_effect", "PREVENTS_LEVEL_1"),
        ("economic_effect", "none"),
        ("economic_effect", ""),
    ],
)
def test_an_unknown_classification_value_is_rejected(field: str, unknown: str) -> None:
    with pytest.raises(ValidationError):
        _declaration(**{field: unknown})


@pytest.mark.parametrize(
    "economic_effect",
    ["PREVENTS_LEVEL_2", "PREVENTS_LEVEL_1_AND_LEVEL_2"],
)
def test_lifecycle_hooks_only_requires_no_economic_effect(
    economic_effect: str,
) -> None:
    """`LIFECYCLE_HOOKS_ONLY` is specification 12.6's "only adapt lifecycle
    hooks" alternative, so it cannot also prevent parity."""
    with pytest.raises(ValidationError) as failure:
        _declaration(economic_effect=economic_effect)

    assert "STRATEGY.EXTENSION_DECLARATION" in str(failure.value)


@pytest.mark.parametrize(
    "economic_effect",
    ["NONE", "PREVENTS_LEVEL_2", "PREVENTS_LEVEL_1_AND_LEVEL_2"],
)
def test_altering_execution_behavior_admits_every_economic_effect(
    economic_effect: str,
) -> None:
    declaration = _declaration(
        lifecycle_effect="ALTERS_EXECUTION_BEHAVIOR",
        economic_effect=economic_effect,
    )

    assert declaration.economic_effect.value == economic_effect


def test_both_classifications_survive_a_canonical_round_trip() -> None:
    declaration = _declaration(
        lifecycle_effect="ALTERS_EXECUTION_BEHAVIOR",
        economic_effect="PREVENTS_LEVEL_1_AND_LEVEL_2",
    )
    dumped = declaration.model_dump(mode="json")

    assert dumped["lifecycle_effect"] == "ALTERS_EXECUTION_BEHAVIOR"
    assert dumped["economic_effect"] == "PREVENTS_LEVEL_1_AND_LEVEL_2"
    assert _DECLARATION_ADAPTER.validate_json(json.dumps(dumped)) == declaration


# --- `Direction` ----------------------------------------------------------


def test_the_direction_vocabulary_is_exactly_two_uppercase_members() -> None:
    assert [member.value for member in Direction] == ["LONG", "SHORT"]


# --- Step 14: `StrategySpec` ----------------------------------------------

_FIXTURES = Path(__file__).parents[2] / "fixtures" / "strategy"
_OBSERVED_AT = datetime(2026, 8, 16, tzinfo=UTC)


def _document(name: str = "sma_cross_long.valid.yaml") -> dict[str, Any]:
    """Load one fixture through the real production path."""
    result = load_yaml_document((_FIXTURES / name).read_bytes(), name, _OBSERVED_AT)
    assert isinstance(result, Success), result
    value = result.value.value
    assert isinstance(value, dict)
    return dict(value)


def _spec(**overrides: object) -> StrategySpec:
    payload = _document() | overrides
    return StrategySpec.model_validate_json(canonical_json_bytes(payload))


def _nested(section: str, **overrides: object) -> StrategySpec:
    block = _document()[section]
    assert isinstance(block, dict)
    return _spec(**{section: block | overrides})


def test_the_spec_carries_exactly_the_twenty_one_specified_fields() -> None:
    assert list(StrategySpec.model_fields) == [
        "schema_version",
        "strategy_id",
        "display_name",
        "description",
        "strategy_family",
        "market_type",
        "direction",
        "timeframe",
        "universe",
        "required_capabilities",
        "parameters",
        "features",
        "entry_rules",
        "exit_rules",
        "sizing_intent",
        "risk_assumptions",
        "warm_up_requirements",
        "comparison_requirements",
        "supported_approximation_policy",
        "engine_extensions",
        "authoring_metadata",
    ]


def test_the_valid_fixture_is_accepted_through_the_production_path() -> None:
    spec = _spec()

    assert spec.schema_version == "1.0.0"
    assert spec.strategy_id == "strat_3f2504e0-4f89-41d3-9a0c-0305e82c3301"
    assert spec.market_type is MarketType.SPOT
    assert spec.direction is Direction.LONG
    assert spec.timeframe == "1h"
    assert spec.universe.instruments == ("BINANCE:BTC/USDT:SPOT",)
    assert len(spec.required_capabilities) == 5
    assert tuple(spec.parameters) == ("fast_period", "slow_period")
    assert tuple(feature.id for feature in spec.features) == ("fast_sma", "slow_sma")
    assert spec.entry_rules[0].id == "enter_cross"
    assert spec.exit_rules[0].id == "exit_cross"
    assert spec.engine_extensions == ()


def test_an_unknown_top_level_field_is_rejected() -> None:
    with pytest.raises(ValidationError):
        _spec(promotion_policy="AUTOMATIC")


def test_an_unknown_nested_field_is_rejected() -> None:
    with pytest.raises(ValidationError):
        _nested("universe", exchange="BINANCE")


@pytest.mark.parametrize("field", list(_document()))
def test_every_top_level_field_is_required(field: str) -> None:
    payload = {name: value for name, value in _document().items() if name != field}

    with pytest.raises(ValidationError):
        StrategySpec.model_validate_json(canonical_json_bytes(payload))


def test_a_spec_is_frozen() -> None:
    spec = _spec()

    with pytest.raises(ValidationError):
        spec.timeframe = "4h"


def test_formatting_variants_validate_to_one_identical_spec() -> None:
    """Comments, whitespace, and top-level key order carry no content.

    This asserts **model equality**, not `content_hash` equality: strategy
    hashing is a later task, and proving it here would consume that task's own
    evidence.
    """
    canonical = _spec()

    for name in (
        "sma_cross_long.reordered_keys.yaml",
        "sma_cross_long.commented.yaml",
    ):
        payload = canonical_json_bytes(_document(name))
        assert StrategySpec.model_validate_json(payload) == canonical


# --- Initial safety policy ------------------------------------------------


@pytest.mark.parametrize("market_type", ["MARGIN", "FUTURES", "EQUITIES"])
def test_a_forbidden_market_type_is_rejected_with_its_code(market_type: str) -> None:
    with pytest.raises(ValidationError) as failure:
        _spec(market_type=market_type)

    assert "STRATEGY.POLICY_FORBIDDEN_MARKET" in str(failure.value)


def test_a_forbidden_direction_is_rejected_with_its_code() -> None:
    with pytest.raises(ValidationError) as failure:
        _spec(direction="SHORT")

    assert "STRATEGY.POLICY_FORBIDDEN_DIRECTION" in str(failure.value)


def test_leverage_above_one_and_shorting_are_rejected() -> None:
    """Leverage, margin, futures, and shorting are repository safety boundaries."""
    with pytest.raises(ValidationError):
        _nested("risk_assumptions", leverage="2")
    with pytest.raises(ValidationError):
        _nested("risk_assumptions", shorting_allowed=True)


def test_a_sizing_fraction_above_one_is_rejected() -> None:
    assert _nested("sizing_intent", fraction="0.5") is not None
    with pytest.raises(ValidationError):
        _nested("sizing_intent", fraction="1.5")


# --- Item B: the top-level approximation policy ---------------------------


def test_the_top_level_default_policy_must_be_reject() -> None:
    default = _spec().supported_approximation_policy.default
    assert default is ApproximationPolicy.REJECT
    with pytest.raises(ValidationError):
        _nested("supported_approximation_policy", default="ALLOW_DECLARED")


def test_the_top_level_default_policy_is_required() -> None:
    with pytest.raises(ValidationError):
        _spec(supported_approximation_policy={})


def test_an_allow_declared_requirement_beside_the_reject_default_is_accepted() -> None:
    """The two govern disjoint sets, so this is not a contradiction.

    Reading the fixed `REJECT` default as a ceiling would make
    `SUPPORTED_WITH_APPROXIMATION` unreachable.
    """
    requirements = _document()["required_capabilities"]
    assert isinstance(requirements, list)
    relaxed = [dict(entry) for entry in requirements]
    relaxed[3]["approximation_policy"] = "ALLOW_DECLARED"

    spec = _spec(required_capabilities=relaxed)

    policies = {
        requirement.capability: requirement.approximation_policy
        for requirement in spec.required_capabilities
    }
    assert policies["execution.bar_market"] is ApproximationPolicy.ALLOW_DECLARED
    assert spec.supported_approximation_policy.default is ApproximationPolicy.REJECT


# --- Collection canonicalization -----------------------------------------


def test_required_capabilities_are_normalized_into_capability_order() -> None:
    """The fixture authors them in specification 13.1's reading order."""
    spec = _spec()

    capabilities = [item.capability for item in spec.required_capabilities]
    assert capabilities == sorted(capabilities)
    assert capabilities == [
        "data.ohlcv",
        "direction.long",
        "execution.bar_market",
        "market.spot",
        "runtime.backtest",
    ]


def test_a_duplicated_required_capability_is_rejected() -> None:
    requirements = _document()["required_capabilities"]
    assert isinstance(requirements, list)

    with pytest.raises(ValidationError):
        _spec(required_capabilities=[*requirements, requirements[0]])


def test_engine_extension_order_is_normalized_to_one_model() -> None:
    """Task 5 requires reordering declared extensions to leave the hash alone,
    so the model canonicalizes the order rather than rejecting an unsorted one."""
    first = _DECLARATION | {"extension_id": "aaa_hook"}
    second = _DECLARATION | {"extension_id": "zzz_hook"}

    forward = _spec(engine_extensions=[first, second])
    reverse = _spec(engine_extensions=[second, first])

    assert forward == reverse
    assert tuple(item.extension_id for item in forward.engine_extensions) == (
        "aaa_hook",
        "zzz_hook",
    )


def test_a_duplicated_engine_extension_is_rejected() -> None:
    with pytest.raises(ValidationError):
        _spec(engine_extensions=[_DECLARATION, dict(_DECLARATION)])


# --- Parameter bounds -----------------------------------------------------


def test_a_parameter_value_outside_its_declared_bounds_is_rejected() -> None:
    parameters = _document()["parameters"]
    assert isinstance(parameters, dict)
    below = {name: dict(entry) for name, entry in parameters.items()}
    below["fast_period"]["minimum"] = 50

    with pytest.raises(ValidationError) as failure:
        _spec(parameters=below)

    assert "STRATEGY.PARAMETER_OUT_OF_BOUNDS" in str(failure.value)


def test_a_parameter_minimum_above_its_maximum_is_rejected() -> None:
    """Bound consistency is reported distinctly from an out-of-bounds value.

    The message assertion matters: with the two checks in the other order an
    inconsistent pair always trips a value comparison first, so this test would
    pass on the `PARAMETER_OUT_OF_BOUNDS` branch and deleting the consistency
    check would leave the suite green.
    """
    with pytest.raises(ValidationError) as failure:
        _spec(
            parameters={
                "fast_period": {
                    "value_type": "INTEGER",
                    "value": 20,
                    "minimum": 30,
                    "maximum": 10,
                }
            }
        )

    assert "minimum must not exceed its maximum" in str(failure.value)
    assert "PARAMETER_OUT_OF_BOUNDS" not in str(failure.value)


def test_a_duplicated_universe_instrument_is_rejected() -> None:
    with pytest.raises(ValidationError):
        _nested("universe", instruments=["BINANCE:BTC/USDT:SPOT"] * 2)


def test_universe_instruments_are_normalized_into_canonical_order() -> None:
    spec = _nested(
        "universe",
        instruments=["BINANCE:ETH/USDT:SPOT", "BINANCE:BTC/USDT:SPOT"],
    )

    assert spec.universe.instruments == (
        "BINANCE:BTC/USDT:SPOT",
        "BINANCE:ETH/USDT:SPOT",
    )


def test_a_bound_on_a_non_numeric_parameter_is_rejected() -> None:
    with pytest.raises(ValidationError):
        _spec(
            parameters={
                "label": {
                    "value_type": "STRING",
                    "value": "x",
                    "minimum": "a",
                }
            }
        )


# --- Deliberate non-responsibilities -------------------------------------


def test_a_duplicate_feature_id_is_not_rejected_at_the_model_level() -> None:
    """Plan Task 4 step 1 owns `STRATEGY.FEATURE_DUPLICATE_ID`.

    Rejecting it here would make that task's expected RED unobservable, so this
    test pins the boundary rather than the behaviour.
    """
    features = _document()["features"]
    assert isinstance(features, list)

    spec = _spec(features=[features[0], features[0]])

    assert len(spec.features) == 2


def test_an_unresolvable_reference_is_not_rejected_at_the_model_level() -> None:
    """Plan Task 3 step 3 owns `STRATEGY.REFERENCE_UNKNOWN`."""
    rules = _document()["entry_rules"]
    assert isinstance(rules, list)
    rule = dict(rules[0])
    rule["expression"] = {
        "op": "ref",
        "id": "never_declared",
        "bars_ago": 0,
    }

    assert _spec(entry_rules=[rule]) is not None


# --- Findings resolved after the independent Task 2 review ----------------


def test_a_parameter_rejects_a_decimal_subclass_in_every_slot() -> None:
    """`ParameterDefinition` carries the same exact-type invariant as the literal
    node. `parse_decimal` admits any `Decimal` instance, so without this a
    subclass restating its own text could enter the hashed payload."""

    class _WideDecimal(Decimal):
        pass

    for slot in ("value", "minimum", "maximum"):
        payload: dict[str, Any] = {
            "value_type": LiteralValueType.DECIMAL,
            "value": Decimal("5"),
        }
        payload[slot] = _WideDecimal("5")
        with pytest.raises(ValidationError):
            ParameterDefinition(**payload)


def test_a_maximum_bound_on_a_non_numeric_parameter_is_rejected() -> None:
    for bound in ("minimum", "maximum"):
        with pytest.raises(ValidationError):
            _spec(
                parameters={"label": {"value_type": "STRING", "value": "x", bound: "a"}}
            )


def test_the_spec_survives_the_strategy_version_hash_payload_shape() -> None:
    """Section 5.5 item 1 hashes `spec.model_dump(mode="json")`.

    Task 2 does not hash anything, but it must prove that payload is canonical
    JSON at all: `MISSING` sentinels must be omitted rather than reaching
    `canonical_json_bytes`, which raises `TypeError` on an unrecognised type.
    """
    spec = _spec()
    payload = spec.model_dump(mode="json")

    assert canonical_json_bytes(payload)
    assert "maximum" not in payload["parameters"]["fast_period"]
    assert "unit" not in payload["parameters"]["fast_period"]
    assert payload["parameters"]["fast_period"]["minimum"] == 2
    # A JSON-mode payload re-validates in JSON mode; `model_validate` is Python
    # mode and would demand real `Decimal`s and enum members.
    assert StrategySpec.model_validate_json(canonical_json_bytes(payload)) == spec


def test_the_spec_round_trips_through_a_python_mode_dump() -> None:
    """Python-mode dumps keep real `Decimal` values, matching `CanonicalDecimal`."""
    spec = _spec()

    assert StrategySpec.model_validate(spec.model_dump()) == spec


def test_engine_extensions_sort_versions_numerically_not_lexically() -> None:
    """`"1.10.0" < "1.9.0"` as text, so a text sort would disagree with the
    merged `_unique_sorted_versions` precedent the later hashing task follows."""
    older = _DECLARATION | {"version": "1.9.0"}
    newer = _DECLARATION | {"version": "1.10.0"}

    spec = _spec(engine_extensions=[newer, older])

    assert tuple(item.version for item in spec.engine_extensions) == (
        "1.9.0",
        "1.10.0",
    )


def test_the_three_variants_load_to_one_identical_document() -> None:
    """Stronger than model equality: the loader preserves sequence order, so dict
    equality proves the variants differ only in mapping-key order and comments.

    Model equality alone would tolerate a variant that reordered
    `required_capabilities`, `universe.instruments`, or `engine_extensions`, since
    `StrategySpec` normalizes all three.
    """
    canonical = _document()

    for name in (
        "sma_cross_long.reordered_keys.yaml",
        "sma_cross_long.commented.yaml",
    ):
        assert _document(name) == canonical


# --- Deep immutability of the two material mapping fields -------------------
#
# `CanonicalModel` sets `frozen=True`, which blocks attribute rebinding and
# nothing more: a `dict` field stayed mutable through ordinary public item
# access. Both mappings reach the strategy-version payload through
# `spec.model_dump(mode="json")`, so an in-place edit changed hash material
# after construction. Plan section 5.5.1 freezes both. These tests pin the
# public contract, not the implementation type, except where the runtime type
# *is* the contract.

_MUTATOR_CALLS: tuple[tuple[str, tuple[object, ...]], ...] = (
    ("clear", ()),
    ("popitem", ()),
    ("update", ({"injected_key": "injected_value"},)),
    ("setdefault", ("injected_key", "injected_value")),
    ("pop", ("fast_period",)),
)


def _assert_mapping_is_immutable(mapping: Any, present_key: str) -> None:
    """Assert immutability without over-specifying which method is absent.

    `MappingProxyType` omits the mutators entirely, so a missing method raises
    `AttributeError` while item assignment and deletion raise `TypeError`. The
    contract asserted here is that no route mutates, not that any particular
    spelling raises any particular class.
    """
    before = dict(mapping)

    with pytest.raises(TypeError):
        mapping[present_key] = next(iter(mapping.values()))
    with pytest.raises(TypeError):
        del mapping[present_key]
    for name, arguments in _MUTATOR_CALLS:
        with pytest.raises((AttributeError, TypeError)):
            getattr(mapping, name)(*arguments)

    assert dict(mapping) == before


def _feature_parameters(spec: StrategySpec) -> Any:
    return spec.features[0].parameters


def test_both_mapping_fields_are_annotated_mapping_not_dict() -> None:
    spec_annotation = StrategySpec.model_fields["parameters"].annotation
    feature_annotation = FeatureDefinition.model_fields["parameters"].annotation

    for annotation in (spec_annotation, feature_annotation):
        assert get_origin(annotation) is CollectionsMapping
        assert get_origin(annotation) is not dict

    assert get_args(spec_annotation)[1] is ParameterDefinition
    # The key type and the feature value type are `NormalizedIdentifier`, an
    # `Annotated[str, ...]` alias, so the underlying runtime type is `str`.
    for annotation in (spec_annotation, feature_annotation):
        assert get_args(annotation)[0] is NormalizedIdentifier
    assert get_args(feature_annotation)[1] is NormalizedIdentifier


def test_both_mapping_fields_are_not_dict_at_runtime() -> None:
    spec = _spec()

    assert not isinstance(spec.parameters, dict)
    assert not isinstance(_feature_parameters(spec), dict)
    assert isinstance(spec.parameters, CollectionsMapping)
    assert isinstance(_feature_parameters(spec), CollectionsMapping)


def test_an_empty_feature_parameter_mapping_is_still_not_a_dict() -> None:
    """`{}` is a `dict` instance, so the empty case needs its own proof."""
    block = _document()["features"]
    assert isinstance(block, list)
    features = [item | {"parameters": {}} for item in block]

    spec = _spec(features=features)

    assert dict(_feature_parameters(spec)) == {}
    assert not isinstance(_feature_parameters(spec), dict)


def test_the_spec_parameter_mapping_rejects_every_mutation_route() -> None:
    _assert_mapping_is_immutable(_spec().parameters, "fast_period")


def test_the_feature_parameter_mapping_rejects_every_mutation_route() -> None:
    _assert_mapping_is_immutable(_feature_parameters(_spec()), "period")


def test_the_frozen_mapping_helper_copies_before_it_wraps() -> None:
    """The one assertion that fails if `_frozen_mapping` stops copying.

    A private helper is tested directly here because the invariant is not
    observable through the public boundary: pydantic-core builds a fresh `dict`
    when validating a parametrized `Mapping` in either mode, so by the time a
    validator runs, the mapping is already detached and
    `MappingProxyType(validated)` would behave identically. The copy is kept as
    defence in depth per plan section 5.5.1 item 9, and a requirement no test can
    fail on is a requirement that silently rots.
    """
    source = {"alpha": "beta"}

    frozen = _frozen_mapping(source)
    source["gamma"] = "delta"
    del source["alpha"]

    assert dict(frozen) == {"alpha": "beta"}
    assert "gamma" not in frozen


def test_mutating_the_caller_input_after_construction_leaves_both_unchanged() -> None:
    """The caller's own mapping is detached from the constructed record.

    This passes with or without `_frozen_mapping`'s copy, because validation
    already rebuilds the mapping; the helper's own test is what pins the copy.
    What this does prove is the property a caller actually depends on: no
    post-construction edit to the source document reaches a validated record.
    """
    payload = _document()
    spec_source = payload["parameters"]
    feature_source = payload["features"][0]["parameters"]
    assert isinstance(spec_source, dict)
    assert isinstance(feature_source, dict)

    spec = StrategySpec.model_validate_json(canonical_json_bytes(payload))
    recorded_spec_keys = tuple(spec.parameters)
    recorded_feature = dict(_feature_parameters(spec))

    spec_source["injected_key"] = {"value_type": "INTEGER", "value": 1}
    spec_source.pop("fast_period")
    feature_source["injected_key"] = "slow_period"

    assert tuple(spec.parameters) == recorded_spec_keys
    assert "injected_key" not in spec.parameters
    assert dict(_feature_parameters(spec)) == recorded_feature


def test_mutating_a_model_dump_result_leaves_both_mappings_unchanged() -> None:
    spec = _spec()
    recorded_spec_keys = tuple(spec.parameters)
    recorded_feature = dict(_feature_parameters(spec))

    for mode in ("python", "json"):
        dumped = spec.model_dump(mode=mode)
        assert type(dumped["parameters"]) is dict
        assert type(dumped["features"][0]["parameters"]) is dict

        dumped["parameters"]["injected_key"] = {"value_type": "INTEGER", "value": 1}
        dumped["parameters"].pop("fast_period")
        dumped["features"][0]["parameters"]["injected_key"] = "slow_period"

    assert tuple(spec.parameters) == recorded_spec_keys
    assert "injected_key" not in spec.parameters
    assert dict(_feature_parameters(spec)) == recorded_feature


@pytest.mark.parametrize("mode", ["python", "json"])
def test_a_round_trip_restores_immutable_mappings_in_both_modes(mode: str) -> None:
    spec = _spec()
    dumped = spec.model_dump(mode=mode)

    if mode == "python":
        restored = StrategySpec.model_validate(dumped)
    else:
        restored = StrategySpec.model_validate_json(canonical_json_bytes(dumped))

    assert restored == spec
    assert not isinstance(restored.parameters, dict)
    assert not isinstance(_feature_parameters(restored), dict)
    _assert_mapping_is_immutable(restored.parameters, "fast_period")
    _assert_mapping_is_immutable(_feature_parameters(restored), "period")


def test_a_contained_parameter_definition_is_still_frozen() -> None:
    definition = _spec().parameters["fast_period"]

    with pytest.raises(ValidationError):
        definition.value = 99


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_both_mapping_fields_keep_their_object_json_schema(mode: Any) -> None:
    """The published contract must stay an object with the same value schema.

    Both modes are asserted because the schema registry renders
    `mode="serialization"`, and a field serializer replaces that mode's schema
    with its own return type's schema -- so the serializer's annotation, not the
    field's, is what a generated schema publishes.
    """
    schema = StrategySpec.model_json_schema(mode=mode)
    definitions = schema["$defs"]
    spec_parameters = schema["properties"]["parameters"]
    feature_parameters = definitions["FeatureDefinition"]["properties"]["parameters"]

    def resolved(node: dict[str, Any]) -> dict[str, Any]:
        """Inside a model schema a named type is a `$ref`; inline it to compare."""
        reference = node.get("$ref")
        if reference is None:
            return node
        assert reference.startswith("#/$defs/")
        target: dict[str, Any] = definitions[reference.removeprefix("#/$defs/")]
        return target

    assert spec_parameters["type"] == "object"
    assert feature_parameters["type"] == "object"
    assert spec_parameters["additionalProperties"] == {
        "$ref": "#/$defs/ParameterDefinition"
    }

    # The exact `NormalizedIdentifier` schema, not a loosened string.
    identifier = TypeAdapter(NormalizedIdentifier).json_schema()
    assert resolved(feature_parameters["additionalProperties"]) == identifier
    assert resolved(spec_parameters["propertyNames"]) == identifier
    assert resolved(feature_parameters["propertyNames"]) == identifier

    # The declared bound must survive into *both* modes. A field serializer
    # replaces the serialization-mode schema with its own return type's schema,
    # which carries no `max_length`, so this is the assertion that catches a
    # silently weakened published contract.
    assert spec_parameters["maxProperties"] == MAX_PARAMETERS
    assert feature_parameters["maxProperties"] == MAX_FEATURE_PARAMETERS


def test_both_mapping_length_bounds_still_reject_an_oversized_mapping() -> None:
    """The freeze runs after `max_length`, so the bound must still be enforced."""
    with pytest.raises(ValidationError):
        _spec(
            parameters={
                f"p{index:04d}": {"value_type": "INTEGER", "value": 1}
                for index in range(MAX_PARAMETERS + 1)
            }
        )

    block = _document()["features"]
    assert isinstance(block, list)
    oversized = {
        f"p{index:04d}": "fast_period" for index in range(MAX_FEATURE_PARAMETERS + 1)
    }
    with pytest.raises(ValidationError):
        _spec(features=[block[0] | {"parameters": oversized}, *block[1:]])


def test_the_feature_definition_carries_exactly_its_seven_fields() -> None:
    assert list(FeatureDefinition.model_fields) == [
        "id",
        "operation",
        "inputs",
        "parameters",
        "output_type",
        "warm_up_bars",
        "missing_value_policy",
    ]
