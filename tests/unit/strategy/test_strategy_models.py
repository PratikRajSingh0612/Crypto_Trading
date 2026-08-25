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
from typing import Any, Literal, get_args, get_origin

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import TypeAdapter, ValidationError

from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.capability_requirements import ApproximationPolicy
from crypto_lab.domain.hashing import sha256_bytes
from crypto_lab.domain.identifiers import NormalizedIdentifier
from crypto_lab.domain.records import InstrumentId, MarketType
from crypto_lab.domain.results import Success
from crypto_lab.strategy.expressions import LiteralValueType
from crypto_lab.strategy.models import (
    MAX_FEATURE_PARAMETERS,
    MAX_PARAMETERS,
    MAX_UNIVERSE_INSTRUMENTS,
    Direction,
    EngineExtensionDeclaration,
    ExtensionEconomicEffect,
    ExtensionLifecycleEffect,
    FeatureDefinition,
    ParameterDefinition,
    StrategySpec,
    Universe,
    _frozen_mapping,
)
from crypto_lab.strategy.versioning import (
    STRATEGY_VERSION_PROFILE_VERSION,
    StrategySourceProvenance,
    StrategyVersion,
    sorted_extension_hashes,
    strategy_version_hash,
    strategy_version_identifier,
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


# --------------------------------------------------------------------------
# Runtime/schema uniqueness agreement -- final pre-Task-8 closure
# --------------------------------------------------------------------------
#
# `validate_instruments_are_unique_and_sorted` rejects a duplicate, and plan
# section 3.1 requires `json_schema_extra` to supply the `uniqueItems` Pydantic
# does not emit for a tuple field. `Universe.instruments` carried the validator
# and not the keyword, so a standards-compliant Draft 2020-12 validator accepted
# a document ordinary Pydantic validation rejects. Task 8 publishes this record
# through the `$defs` of both `strategy-spec-v1` and `strategy-version-v1`, so
# both containers are pinned rather than only the nearer one. Same defect class
# as the `capabilities/models.py` correction in commit `00879f6`.

_SCHEMA_MODES: tuple[Literal["validation", "serialization"], ...] = (
    "validation",
    "serialization",
)
_CONTAINERS: tuple[str, ...] = ("StrategySpec", "StrategyVersion")
_BTC = "BINANCE:BTC/USDT:SPOT"
_ETH = "BINANCE:ETH/USDT:SPOT"
_PROVENANCE_BYTES = b"schema_version: placeholder"

# The two nodes this correction is allowed to move, as JSON pointers. Both are
# reached through `$defs` in both containers, because `StrategySpec.universe`
# and `StrategySpec.required_capabilities` are model-typed.
_EXPECTED_UNIQUE_PATHS = {
    "/$defs/CapabilityRequirement/properties/comparison_levels/uniqueItems",
    "/$defs/Universe/properties/instruments/uniqueItems",
}
# Unique **by a designated semantic key** at runtime, never by whole value. A
# flat `uniqueItems` would be strictly weaker than the real rule -- two
# structurally distinct objects can share a key -- so asserting these stay
# unmarked prevents a later change from publishing a false equivalence.
_KEY_UNIQUE_SPEC_FIELDS = ("required_capabilities", "engine_extensions")


def _model_for(container: str) -> type[StrategySpec] | type[StrategyVersion]:
    return StrategySpec if container == "StrategySpec" else StrategyVersion


def _containing_schema(
    container: str,
    mode: Literal["validation", "serialization"],
) -> dict[str, Any]:
    return _model_for(container).model_json_schema(mode=mode)


def _spec_properties(container: str, schema: dict[str, Any]) -> dict[str, Any]:
    """`StrategySpec`'s own property map, wherever it sits in this container."""
    if container == "StrategySpec":
        properties: dict[str, Any] = schema["properties"]
        return properties
    nested: dict[str, Any] = schema["$defs"]["StrategySpec"]["properties"]
    return nested


def _unique_item_paths(node: Any, prefix: str = "") -> set[str]:
    """Every JSON-pointer path in a schema where `uniqueItems` is `True`.

    A whole-document walk rather than a scan of top-level `properties`: the two
    corrected fields are only ever reached through `$defs`, and the previous
    correction's independent review found that a `properties`-only assertion
    leaves exactly that path unguarded.
    """
    found: set[str] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            path = f"{prefix}/{key}"
            if key == "uniqueItems" and value is True:
                found.add(path)
            else:
                found |= _unique_item_paths(value, path)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found |= _unique_item_paths(value, f"{prefix}/{index}")
    return found


def _provenance() -> StrategySourceProvenance:
    return StrategySourceProvenance(
        source_name="sma_cross_long.valid.yaml",
        source_bytes_sha256=sha256_bytes(_PROVENANCE_BYTES),
        source_byte_length=len(_PROVENANCE_BYTES),
        observed_at_utc=_OBSERVED_AT,
    )


def _version(spec: StrategySpec) -> StrategyVersion:
    """A real record: `validate_identity_is_recomputed` recomputes the hash."""
    content_hash = strategy_version_hash(spec)
    return StrategyVersion(
        schema_version="1.0.0",
        strategy_version_id=strategy_version_identifier(content_hash),
        strategy_id=spec.strategy_id,
        content_hash=content_hash,
        strategy_spec=spec,
        extension_hashes=tuple(sorted_extension_hashes(spec.engine_extensions)),
        hashing_profile_version=STRATEGY_VERSION_PROFILE_VERSION,
        created_at_utc=_OBSERVED_AT,
        source_provenance=_provenance(),
    )


def _spec_document(instruments: list[str]) -> dict[str, Any]:
    """A **complete** specification document carrying exactly `instruments`.

    Taken from a validated record's own JSON dump rather than from the raw
    fixture, so the same bytes are legal input to both render modes; a
    serialization-mode schema describes what a serializer emits.
    """
    document = _spec().model_dump(mode="json")
    document["universe"]["instruments"] = instruments
    return document


def _duplicate_version_document() -> dict[str, Any]:
    """A complete version document whose universe repeats one instrument.

    Edited as plain data after construction, so it is byte-identical to the
    valid record apart from the array under test. Its `content_hash` no longer
    matches the edited specification -- deliberately: JSON Schema never
    recomputes identity, and at runtime `Universe`'s field validator trips
    before `validate_identity_is_recomputed` is reached, so the rejection this
    is paired against is the uniqueness rule and not the hash rule.
    """
    document = _version(_spec()).model_dump(mode="json")
    document["strategy_spec"]["universe"]["instruments"] = [_BTC, _BTC]
    return document


@pytest.mark.parametrize("container", _CONTAINERS)
@pytest.mark.parametrize("mode", _SCHEMA_MODES)
def test_the_universe_instrument_tuple_emits_unique_items(
    container: str,
    mode: Literal["validation", "serialization"],
) -> None:
    """The published contract must not be weaker than the runtime one.

    Both containers and both modes: the registry renders `serialization` while
    `model_json_schema()` defaults to `validation`, and Task 8 publishes
    `strategy-spec-v1` and `strategy-version-v1` separately.
    """
    schema = _containing_schema(container, mode)

    assert (
        schema["$defs"]["Universe"]["properties"]["instruments"]["uniqueItems"] is True
    )


@pytest.mark.parametrize("container", _CONTAINERS)
@pytest.mark.parametrize("mode", _SCHEMA_MODES)
def test_the_registry_type_adapter_path_emits_universe_unique_items(
    container: str,
    mode: Literal["validation", "serialization"],
) -> None:
    """`schema_registry.render_schema_files` renders through a `TypeAdapter`."""
    schema = TypeAdapter(_model_for(container)).json_schema(mode=mode)

    assert (
        schema["$defs"]["Universe"]["properties"]["instruments"]["uniqueItems"] is True
    )


@pytest.mark.parametrize("container", _CONTAINERS)
@pytest.mark.parametrize("mode", _SCHEMA_MODES)
def test_the_universe_addition_preserves_every_other_keyword(
    container: str,
    mode: Literal["validation", "serialization"],
) -> None:
    """Exactly one keyword is added; the node is otherwise identical.

    The keyword set is transcribed from evidence captured before the edit, so
    this fails if the fix replaced the node rather than extending it.

    The item schema is checked twice, deliberately. Comparing the container's
    `$defs` entry with `TypeAdapter(InstrumentId).json_schema()` proves the two
    renderings agree, but it is **circular** as a widening proof: both sides
    re-derive from the same annotated type, so widening `InstrumentId` moves
    them together. The literal bounds below are the non-circular half, and they
    were transcribed from the pre-correction capture.
    """
    schema = _containing_schema(container, mode)
    universe = schema["$defs"]["Universe"]
    node = universe["properties"]["instruments"]

    assert set(node) == {
        "type",
        "items",
        "maxItems",
        "minItems",
        "title",
        "uniqueItems",
    }
    assert node["type"] == "array"
    assert node["items"] == {"$ref": "#/$defs/InstrumentId"}
    assert node["maxItems"] == MAX_UNIVERSE_INSTRUMENTS
    assert node["minItems"] == 1
    assert node["title"] == "Instruments"
    identifier = schema["$defs"]["InstrumentId"]
    assert identifier == TypeAdapter(InstrumentId).json_schema(mode=mode)
    assert identifier["type"] == "string"
    assert identifier["minLength"] == 10
    assert identifier["maxLength"] == 107
    assert len(identifier["allOf"]) == 2
    assert all(set(branch) == {"pattern"} for branch in identifier["allOf"])
    assert universe["required"] == ["kind", "instruments"]
    assert universe["additionalProperties"] is False


@pytest.mark.parametrize("container", _CONTAINERS)
@pytest.mark.parametrize("mode", _SCHEMA_MODES)
def test_the_constraint_lands_on_exactly_the_two_intended_nodes(
    container: str,
    mode: Literal["validation", "serialization"],
) -> None:
    """A whole-schema walk, so nothing gains the keyword unnoticed.

    `CapabilityRequirement.comparison_levels` appears here because
    `StrategySpec.required_capabilities` is a tuple of that model: it is
    propagation of the same field contract corrected in
    `domain/capability_requirements.py`, not a second collateral change.
    """
    schema = _containing_schema(container, mode)

    assert _unique_item_paths(schema) == _EXPECTED_UNIQUE_PATHS


@pytest.mark.parametrize("container", _CONTAINERS)
@pytest.mark.parametrize("mode", _SCHEMA_MODES)
def test_the_key_unique_collections_stay_unmarked(
    container: str,
    mode: Literal["validation", "serialization"],
) -> None:
    """Uniqueness by semantic key is not expressible as flat `uniqueItems`.

    `normalize_required_capabilities` rejects a repeated `capability`, and
    `normalize_engine_extensions` rejects a repeated `(adapter_name,
    extension_id, version)`. Two structurally different objects can break either
    rule while remaining distinct under `uniqueItems`, so marking them would
    publish a constraint that is not the runtime one and would read as a claim
    of equivalence that does not hold.

    **This is a deliberate choice, not the repository's settled convention, and
    an independent review was right to say so.** Two shipped schemas already
    mark key-unique collections with flat `uniqueItems`:
    `AdaptersConfig.entries` in `application-config-v1` (unique by
    `(adapter_name, adapter_version)` over a five-field record) and
    `AdapterDescriptor.supported_schema_versions` in `adapter-descriptor-v1`
    (unique by `(schema_name, version)`). Neither is wrong -- a whole-object
    duplicate is always also a key duplicate, so the keyword never rejects a
    runtime-valid document; it is simply a partial constraint. Leaving these two
    unmarked is the stricter reading of "publish only what the runtime means",
    and the divergence is recorded in the task ledger for Task 8 rather than
    silently settled here.
    """
    properties = _spec_properties(container, _containing_schema(container, mode))

    for field in _KEY_UNIQUE_SPEC_FIELDS:
        assert properties[field]["type"] == "array"
        assert "uniqueItems" not in properties[field]


@pytest.mark.parametrize("mode", _SCHEMA_MODES)
def test_the_generated_spec_schema_rejects_duplicate_instruments(
    mode: Literal["validation", "serialization"],
) -> None:
    """The defect stated as an executable fact.

    Before the correction this exact document was **accepted** by the generated
    schema and **rejected** by Pydantic.
    """
    schema = StrategySpec.model_json_schema(mode=mode)
    Draft202012Validator.check_schema(schema)

    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(schema).validate(_spec_document([_BTC, _BTC]))


@pytest.mark.parametrize("mode", _SCHEMA_MODES)
def test_the_generated_version_schema_rejects_duplicate_instruments(
    mode: Literal["validation", "serialization"],
) -> None:
    """Propagation proved by enforcement, not merely by the keyword's presence."""
    schema = StrategyVersion.model_json_schema(mode=mode)
    Draft202012Validator.check_schema(schema)

    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(schema).validate(_duplicate_version_document())


@pytest.mark.parametrize("mode", _SCHEMA_MODES)
def test_the_generated_spec_schema_accepts_distinct_instruments(
    mode: Literal["validation", "serialization"],
) -> None:
    """The correction must narrow nothing beyond uniqueness."""
    document = _spec_document([_BTC, _ETH])

    Draft202012Validator(StrategySpec.model_json_schema(mode=mode)).validate(document)
    assert document["universe"]["instruments"] == [_BTC, _ETH]


@pytest.mark.parametrize("mode", _SCHEMA_MODES)
def test_the_generated_version_schema_accepts_distinct_instruments(
    mode: Literal["validation", "serialization"],
) -> None:
    """A complete, hash-consistent record with two instruments still validates."""
    version = _version(_nested("universe", instruments=[_ETH, _BTC]))
    document = version.model_dump(mode="json")

    Draft202012Validator(StrategyVersion.model_json_schema(mode=mode)).validate(
        document
    )
    assert document["strategy_spec"]["universe"]["instruments"] == [_BTC, _ETH]


# Preventive runtime evidence. These begin GREEN: runtime uniqueness already
# exists and is unchanged by this correction. They are declared so the agreement
# is guarded from both sides rather than only from the schema side.


def test_pydantic_still_rejects_duplicate_instruments() -> None:
    """Preventive: the runtime half of the agreement, with its own message.

    Asserting the message matters because the same validator also sorts; a
    change that dropped only the uniqueness branch would otherwise pass.
    """
    with pytest.raises(ValidationError, match="unique"):
        _nested("universe", instruments=[_BTC, _BTC])


def test_universe_instruments_remain_a_normalized_frozen_tuple() -> None:
    """Preventive: representation, ordering, and frozenness are unchanged.

    Unlike `comparison_levels`, this validator **normalizes** an unsorted array
    rather than rejecting it, so an unsorted input is legal at runtime and the
    schema accepting one is agreement rather than divergence. The only residual
    is that Draft 2020-12 cannot advertise that the emitted array is sorted.
    """
    spec = _nested("universe", instruments=[_ETH, _BTC])

    assert isinstance(spec.universe.instruments, tuple)
    assert spec.universe.instruments == (_BTC, _ETH)
    assert Universe.model_config["frozen"] is True
    assert StrategySpec.model_config["frozen"] is True
    assert StrategyVersion.model_config["frozen"] is True
    with pytest.raises(ValidationError):
        spec.universe.instruments = ()


def test_the_affected_models_keep_their_exact_field_order() -> None:
    """Preventive: the correction adds metadata, never a field."""
    assert list(Universe.model_fields) == ["kind", "instruments"]
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


@pytest.mark.parametrize("mode", ["python", "json"])
def test_both_universe_dump_modes_keep_their_shape(mode: Any) -> None:
    """Preventive: a schema keyword must not alter either serialized form."""
    spec = _nested("universe", instruments=[_ETH, _BTC])
    dumped = spec.model_dump(mode=mode)["universe"]

    assert set(dumped) == set(Universe.model_fields)
    if mode == "python":
        assert isinstance(dumped["instruments"], tuple)
    else:
        assert dumped["instruments"] == [_BTC, _ETH]


def test_the_correction_changes_no_strategy_canonical_byte_or_hash() -> None:
    """Recorded before the edit and compared after.

    `uniqueItems` is a JSON Schema keyword, not a model field, so no valid
    instance's canonical serialization and no content identity may move. The
    full specification and version documents are pinned by digest and length
    rather than transcribed, because both run to thousands of bytes; the two
    short records the correction actually touches are pinned literally.
    """
    spec = _spec()
    version = _version(spec)
    spec_bytes = canonical_json_bytes(spec.model_dump(mode="json"))
    version_bytes = canonical_json_bytes(version.model_dump(mode="json"))

    assert canonical_json_bytes(spec.universe.model_dump(mode="json")) == (
        b'{"instruments":["BINANCE:BTC/USDT:SPOT"],"kind":"STATIC"}'
    )
    assert canonical_json_bytes(
        spec.required_capabilities[0].model_dump(mode="json")
    ) == (
        b'{"approximation_policy":"REJECT","capability":"data.ohlcv",'
        b'"comparison_levels":["LEVEL_1","LEVEL_2"],'
        b'"minimum_semantics":"capabilities/v1","required":true,'
        b'"schema_version":"1.0.0"}'
    )
    assert len(spec_bytes) == 2583
    assert sha256_bytes(spec_bytes) == (
        "035163fa4240c58bebde17a73840744100240821ddd4fd53e28bd4ee6678bc6a"
    )
    assert len(version_bytes) == 3161
    assert sha256_bytes(version_bytes) == (
        "f72def0278f7ea7964d330d9b573c7fda262dfe60bc0dc6c7c414c0d5d31bdee"
    )


def test_the_strategy_content_hash_is_unchanged_for_the_same_semantic_input() -> None:
    """Identity is the strictest canonical-byte proof available for a strategy.

    `strategy_version_payload` embeds the whole `model_dump(mode="json")`, so a
    single moved byte anywhere in the specification changes this digest.
    """
    spec = _spec()
    content_hash = strategy_version_hash(spec)

    assert content_hash == (
        "14f59d879338f36a91f639e932567dba35cc17b835cfb16d7a4362c05b23c29e"
    )
    assert strategy_version_identifier(content_hash) == (
        "strv_14f59d87-9338-436a-91f6-39e932567dba"
    )
    assert _version(spec).content_hash == content_hash


# --------------------------------------------------------------------------
# Stage 4 runtime/schema parity closure -- clauses SPEC-A1, SPEC-A2, RISK-A1,
# RISK-A2, SIZE-A1, EXT-A1, PARAM-A1..A3
#
# Each clause is a rule ordinary validated construction enforces and the
# generated schema omitted. Two are safety boundaries: `validate_market_type_policy`
# accepts SPOT only and `validate_direction_policy` accepts LONG only, while the
# published `$defs` emitted the full four-member `MarketType` and two-member
# `Direction` -- so `FUTURES` and `SHORT` validated against a schema whose own
# `Direction` description already said "Initial policy accepts only `LONG`".
#
# Every narrowing here is published **at the field**, never on the shared type.
# `MarketType` is a `$defs` entry in the frozen `domain/instrument-ref-v1` and
# `datasets/dataset-descriptor-v1`, and `PositiveDecimal` is one in the frozen
# `domain/price-v1`: narrowing either type would move released Stage 3 bytes.
# --------------------------------------------------------------------------

_STRATEGY_SPEC_ADAPTER: TypeAdapter[StrategySpec] = TypeAdapter(StrategySpec)
_PARAMETER_ADAPTER: TypeAdapter[ParameterDefinition] = TypeAdapter(ParameterDefinition)


def _spec_schema(mode: str) -> dict[str, Any]:
    schema: dict[str, Any] = StrategySpec.model_json_schema(
        mode=mode  # type: ignore[arg-type]
    )
    return schema


def _spec_json(**overrides: Any) -> dict[str, Any]:
    document = _document()
    document.update(overrides)
    return document


def _spec_section(section: str, **overrides: Any) -> dict[str, Any]:
    document = _document()
    block = document[section]
    assert isinstance(block, dict)
    document[section] = block | overrides
    return document


def _spec_accepts(document: dict[str, Any]) -> bool:
    try:
        _STRATEGY_SPEC_ADAPTER.validate_json(canonical_json_bytes(document))
    except ValidationError:
        return False
    return True


def _param_accepts(document: dict[str, Any]) -> bool:
    try:
        _PARAMETER_ADAPTER.validate_json(json.dumps(document))
    except ValidationError:
        return False
    return True


def _nested_root(parent: dict[str, Any], name: str) -> dict[str, Any]:
    return {"$defs": parent["$defs"], "$ref": f"#/$defs/{name}"}


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_the_spec_baseline_document_agrees_on_every_side(mode: str) -> None:
    """Non-vacuity for every clause below: one complete valid document."""
    document = _document()
    assert _spec_accepts(document)
    schema = _spec_schema(mode)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(document)


# --- SPEC-A1 and SPEC-A2: the two safety boundaries ---


@pytest.mark.parametrize("mode", ["validation", "serialization"])
@pytest.mark.parametrize("market_type", ["MARGIN", "FUTURES", "EQUITIES"])
def test_spec_a1_a_forbidden_market_type_is_rejected_by_the_published_schema(
    mode: str, market_type: str
) -> None:
    """Clause SPEC-A1. Every non-SPOT member is named in the failure output."""
    document = _spec_json(market_type=market_type)
    assert not _spec_accepts(document)
    assert not Draft202012Validator(_spec_schema(mode)).is_valid(document)


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_spec_a2_a_forbidden_direction_is_rejected_by_the_published_schema(
    mode: str,
) -> None:
    """Clause SPEC-A2."""
    document = _spec_json(direction="SHORT")
    assert not _spec_accepts(document)
    assert not Draft202012Validator(_spec_schema(mode)).is_valid(document)


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_the_policy_constants_are_published_at_the_field_not_on_the_type(
    mode: str,
) -> None:
    """The scoping trap, asserted in both directions.

    `MarketType` is a `$defs` entry in two already-released Stage 3 schemas, so
    the full four-member enum must survive on the type while the field publishes
    `const`. `Direction` reaches no Stage 3 schema but is treated identically:
    the type is the domain vocabulary and the field is this version's policy.
    """
    schema = _spec_schema(mode)
    assert schema["$defs"]["MarketType"]["enum"] == [
        "SPOT",
        "MARGIN",
        "FUTURES",
        "EQUITIES",
    ]
    assert schema["$defs"]["Direction"]["enum"] == ["LONG", "SHORT"]
    assert "const" not in schema["$defs"]["MarketType"]
    assert "const" not in schema["$defs"]["Direction"]
    assert schema["properties"]["market_type"]["const"] == "SPOT"
    assert schema["properties"]["direction"]["const"] == "LONG"
    # the field still references the shared type, so the enum still applies
    assert "$ref" in json.dumps(schema["properties"]["market_type"])
    assert "$ref" in json.dumps(schema["properties"]["direction"])


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_the_two_policy_fields_stay_required_in_their_declared_position(
    mode: str,
) -> None:
    schema = _spec_schema(mode)
    assert "market_type" in schema["required"]
    assert "direction" in schema["required"]
    assert list(schema["properties"]) == list(StrategySpec.model_fields)


# --- RISK-A1 and RISK-A2 ---


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_risk_a1_shorting_allowed_is_published_as_a_constant_false(mode: str) -> None:
    """Clause RISK-A1: a single-field constant a validator enforced and the
    schema published as a bare `{"type": "boolean"}`."""
    document = _spec_section("risk_assumptions", shorting_allowed=True)
    assert not _spec_accepts(document)
    schema = _spec_schema(mode)
    assert not Draft202012Validator(schema).is_valid(document)
    node = schema["$defs"]["RiskAssumptions"]["properties"]["shorting_allowed"]
    assert node["const"] is False
    assert node["type"] == "boolean"


@pytest.mark.parametrize("mode", ["validation", "serialization"])
@pytest.mark.parametrize("leverage", ["2", "0.5", "1.000000001", "10"])
def test_risk_a2_a_leverage_other_than_one_is_rejected(
    mode: str, leverage: str
) -> None:
    """Clause RISK-A2. The JSON-accepted set is exactly `{"1"}`.

    `POSITIVE_DECIMAL_PATTERN` requires any fractional part to end in `[1-9]` and
    forbids a leading zero, so `"1.0"`, `"1.00"`, `"01"`, and `"1E+0"` never reach
    the validator at all -- they are rejected by the pattern on both sides
    already. `const: "1"` therefore over-rejects nothing.
    """
    document = _spec_section("risk_assumptions", leverage=leverage)
    assert not _spec_accepts(document)
    assert not Draft202012Validator(_spec_schema(mode)).is_valid(document)


@pytest.mark.parametrize("mode", ["validation", "serialization"])
@pytest.mark.parametrize("leverage", ["1.0", "1.00", "01", "1E+0"])
def test_the_non_canonical_spellings_of_one_were_already_rejected_on_both_sides(
    mode: str, leverage: str
) -> None:
    """The measurement that settles the `const: "1"` classification.

    These four are rejected by the *pattern*, before and after this correction, by
    runtime and schema alike. That is what proves the JSON-accepted set of
    `leverage` is the single string `"1"` rather than every spelling of one.
    """
    document = _spec_section("risk_assumptions", leverage=leverage)
    assert not _spec_accepts(document)
    assert not Draft202012Validator(_spec_schema(mode)).is_valid(document)


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_the_leverage_constant_is_a_json_string_and_preserves_the_shared_pattern(
    mode: str,
) -> None:
    """`const: "1"`, never `const: "1.0"` and never a JSON number.

    `PositiveDecimal` is a `$defs` entry in the frozen `domain/price-v1`, so the
    `const` is published at the field and the shared definition keeps its pattern.
    """
    schema = _spec_schema(mode)
    node = schema["$defs"]["RiskAssumptions"]["properties"]["leverage"]
    assert node["const"] == "1"
    assert node["const"] != "1.0"
    assert not isinstance(node["const"], (int, float))
    shared = schema["$defs"]["PositiveDecimal"]
    assert shared["type"] == "string"
    assert "const" not in shared
    assert (
        shared["pattern"]
        == r"^(?:[1-9][0-9]*(?:\.[0-9]*[1-9])?|0\.[0-9]*[1-9])(?![\s\S])"
    )
    assert shared["maxLength"] == 256


# --- SIZE-A1 ---


@pytest.mark.parametrize("mode", ["validation", "serialization"])
@pytest.mark.parametrize("fraction", ["2", "1.5", "10", "1.000000001"])
def test_size_a1_a_sizing_fraction_above_one_is_rejected(
    mode: str, fraction: str
) -> None:
    """Clause SIZE-A1: `validate_fraction_is_a_fraction` rejects it."""
    document = _spec_section("sizing_intent", fraction=fraction)
    assert not _spec_accepts(document)
    assert not Draft202012Validator(_spec_schema(mode)).is_valid(document)


@pytest.mark.parametrize("mode", ["validation", "serialization"])
@pytest.mark.parametrize(
    "fraction",
    ["1", "0.5", "0.1", "0.01", "0.999999999", "0.0000000001"],
)
def test_size_a1_every_legal_fraction_including_the_boundary_is_accepted(
    mode: str, fraction: str
) -> None:
    """Over-rejection is the failure mode a pattern invites; `"1"` is the exact
    inclusive boundary and must survive."""
    document = _spec_section("sizing_intent", fraction=fraction)
    assert _spec_accepts(document)
    Draft202012Validator(_spec_schema(mode)).validate(document)


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_the_fraction_bound_is_added_beside_the_shared_pattern(mode: str) -> None:
    """Additive: a second `pattern` cannot sit beside the first in one object, so
    the narrowing goes in an `allOf` and the inherited `$ref` keeps its own."""
    schema = _spec_schema(mode)
    node = schema["$defs"]["SizingIntent"]["properties"]["fraction"]
    assert node["allOf"] == [{"pattern": r"^(?:1|0\.[0-9]*[1-9])(?![\s\S])"}]
    assert "$ref" in json.dumps(node)
    assert "const" not in schema["$defs"]["PositiveDecimal"]


# --- EXT-A1 ---


@pytest.mark.parametrize("mode", ["validation", "serialization"])
@pytest.mark.parametrize("effect", ["PREVENTS_LEVEL_2", "PREVENTS_LEVEL_1_AND_LEVEL_2"])
def test_ext_a1_a_lifecycle_only_extension_requires_economic_effect_none(
    mode: str, effect: str
) -> None:
    """Clause EXT-A1, measured on the standalone record."""
    document = _DECLARATION | {"economic_effect": effect}
    with pytest.raises(ValidationError):
        _DECLARATION_ADAPTER.validate_json(json.dumps(document))
    schema = EngineExtensionDeclaration.model_json_schema(mode=mode)  # type: ignore[arg-type]
    assert not Draft202012Validator(schema).is_valid(document)


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_ext_a1_every_effect_pair_the_runtime_accepts_is_still_accepted(
    mode: str,
) -> None:
    """Four positive pairs: the lifecycle-only row plus all three altering rows."""
    schema = EngineExtensionDeclaration.model_json_schema(mode=mode)  # type: ignore[arg-type]
    Draft202012Validator.check_schema(schema)
    accepted = [
        ("LIFECYCLE_HOOKS_ONLY", "NONE"),
        ("ALTERS_EXECUTION_BEHAVIOR", "NONE"),
        ("ALTERS_EXECUTION_BEHAVIOR", "PREVENTS_LEVEL_2"),
        ("ALTERS_EXECUTION_BEHAVIOR", "PREVENTS_LEVEL_1_AND_LEVEL_2"),
    ]
    for lifecycle, economic in accepted:
        document = _DECLARATION | {
            "lifecycle_effect": lifecycle,
            "economic_effect": economic,
        }
        _DECLARATION_ADAPTER.validate_json(json.dumps(document))
        Draft202012Validator(schema).validate(document)


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_the_extension_condition_survives_into_both_container_definitions(
    mode: str,
) -> None:
    """`strategy-spec-v1` and `strategy-version-v1` both publish this record."""
    schema = _spec_schema(mode)
    node = schema["$defs"]["EngineExtensionDeclaration"]
    assert len(node["allOf"]) == 1
    assert (
        node["allOf"][0]["if"]["properties"]["lifecycle_effect"]["const"]
        == "LIFECYCLE_HOOKS_ONLY"
    )
    assert node["allOf"][0]["then"]["properties"]["economic_effect"]["const"] == "NONE"
    assert node["required"] == list(EngineExtensionDeclaration.model_fields)


# --- PARAM-A1..A3 ---

_PARAMETER_POSITIVES: list[dict[str, Any]] = [
    {"value_type": "BOOLEAN", "value": True},
    {"value_type": "BOOLEAN", "value": False},
    {"value_type": "INTEGER", "value": 0},
    {"value_type": "INTEGER", "value": -(2**63)},
    {"value_type": "INTEGER", "value": 2**63 - 1},
    {"value_type": "INTEGER", "value": 5, "minimum": 5, "maximum": 5},
    {"value_type": "INTEGER", "value": 5, "minimum": 1},
    {"value_type": "INTEGER", "value": 5, "maximum": 9},
    {"value_type": "INTEGER", "value": 5, "unit": "bars"},
    {"value_type": "DECIMAL", "value": "0.5"},
    {"value_type": "DECIMAL", "value": "1", "minimum": "0.1", "maximum": "2"},
    {"value_type": "DECIMAL", "value": "-1.5"},
    {"value_type": "STRING", "value": ""},
    {"value_type": "STRING", "value": "x" * 8192},
    {"value_type": "IDENTIFIER", "value": "a"},
    {"value_type": "IDENTIFIER", "value": "some.dotted_name"},
]


@pytest.mark.parametrize("mode", ["validation", "serialization"])
@pytest.mark.parametrize("document", _PARAMETER_POSITIVES)
def test_every_runtime_valid_parameter_definition_is_still_accepted(
    mode: str, document: dict[str, Any]
) -> None:
    """Sixteen positive samples across all five literal types and every bound
    combination, because five conditional branches invite over-rejection."""
    root = _nested_root(_spec_schema(mode), "ParameterDefinition")
    assert _param_accepts(document), document
    Draft202012Validator(root).validate(document)


@pytest.mark.parametrize("mode", ["validation", "serialization"])
@pytest.mark.parametrize(
    "document",
    [
        {"value_type": "INTEGER", "value": "5"},
        {"value_type": "BOOLEAN", "value": 1},
        {"value_type": "DECIMAL", "value": 1},
        {"value_type": "STRING", "value": 5},
        {"value_type": "IDENTIFIER", "value": "Not_An_Identifier"},
    ],
)
def test_param_a1_the_value_must_match_its_declared_value_type(
    mode: str, document: dict[str, Any]
) -> None:
    """Clause PARAM-A1. The same exact-identity invariant `LiteralExpression`
    already publishes as five `if`/`then` pairs in this same package -- the
    source comment on `validate_bounds` names it in exactly those words."""
    root = _nested_root(_spec_schema(mode), "ParameterDefinition")
    assert not _param_accepts(document), document
    assert not Draft202012Validator(root).is_valid(document)


@pytest.mark.parametrize("mode", ["validation", "serialization"])
@pytest.mark.parametrize(
    "document",
    [
        {"value_type": "INTEGER", "value": 5, "minimum": "1"},
        {"value_type": "INTEGER", "value": 5, "maximum": "9"},
        {"value_type": "DECIMAL", "value": "1.5", "minimum": 1},
        {"value_type": "DECIMAL", "value": "1.5", "maximum": 2},
    ],
)
def test_param_a2_each_bound_must_match_the_declared_value_type_too(
    mode: str, document: dict[str, Any]
) -> None:
    """Clause PARAM-A2: `validate_bounds` dispatches all three of `value`,
    `minimum`, and `maximum` through the same table, so all three are published."""
    root = _nested_root(_spec_schema(mode), "ParameterDefinition")
    assert not _param_accepts(document), document
    assert not Draft202012Validator(root).is_valid(document)


@pytest.mark.parametrize("mode", ["validation", "serialization"])
@pytest.mark.parametrize("value_type", ["BOOLEAN", "STRING", "IDENTIFIER"])
@pytest.mark.parametrize("bound", ["minimum", "maximum"])
def test_param_a3_only_numeric_parameters_accept_bounds(
    mode: str, value_type: str, bound: str
) -> None:
    """Clause PARAM-A3, six independent cases named by type and bound."""
    values = {"BOOLEAN": True, "STRING": "text", "IDENTIFIER": "some.name"}
    document = {
        "value_type": value_type,
        "value": values[value_type],
        bound: values[value_type],
    }
    root = _nested_root(_spec_schema(mode), "ParameterDefinition")
    assert not _param_accepts(document)
    assert not Draft202012Validator(root).is_valid(document)


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_the_parameter_branches_are_derived_from_the_literal_contract(
    mode: str,
) -> None:
    """One source of truth: the branch table is the expression module's own.

    Hand-copying it would let `ParameterDefinition`'s published bounds drift from
    `LiteralExpression`'s, which is the drift this clause exists because of.
    """
    schema = _spec_schema(mode)
    parameter = schema["$defs"]["ParameterDefinition"]
    literal = schema["$defs"]["LiteralExpression"]
    assert len(parameter["allOf"]) == len(LiteralValueType) + 1
    literal_values = {
        clause["if"]["properties"]["value_type"]["const"]: clause["then"]["properties"][
            "value"
        ]
        for clause in literal["allOf"]
    }
    for clause in parameter["allOf"][: len(LiteralValueType)]:
        member = clause["if"]["properties"]["value_type"]["const"]
        branch = clause["then"]["properties"]
        assert branch["value"] == literal_values[member], member
        assert branch["minimum"] == literal_values[member], member
        assert branch["maximum"] == literal_values[member], member
    guard = parameter["allOf"][-1]["if"]["properties"]["value_type"]["enum"]
    assert guard == ["BOOLEAN", "STRING", "IDENTIFIER"]
    assert parameter["allOf"][-1]["then"] == {
        "allOf": [
            {"not": {"required": ["minimum"]}},
            {"not": {"required": ["maximum"]}},
        ]
    }
    assert parameter["required"] == ["value_type", "value"]


def test_the_bound_comparison_rules_stay_runtime_only() -> None:
    """Clause PARAM-C1 and PARAM-C2, pinned as executable facts.

    `minimum <= maximum` and `minimum <= value <= maximum` compare two numbers
    over an unbounded domain. Draft 2020-12 has no keyword relating two sibling
    values, so the published schema deliberately does not claim either rule.
    """
    documents: list[dict[str, Any]] = [
        {"value_type": "INTEGER", "value": 5, "minimum": 9, "maximum": 10},
        {"value_type": "INTEGER", "value": 5, "minimum": 10, "maximum": 1},
        {"value_type": "DECIMAL", "value": "5", "minimum": "9"},
    ]
    for mode in ("validation", "serialization"):
        root = _nested_root(_spec_schema(mode), "ParameterDefinition")
        for document in documents:
            assert not _param_accepts(document), document
            assert Draft202012Validator(root).is_valid(document), document


def test_the_key_based_uniqueness_rules_stay_runtime_only() -> None:
    """Clauses SPEC-C1 and SPEC-C2.

    `required_capabilities` is unique by `capability` and `engine_extensions` by
    `(adapter_name, extension_id, version)`. Neither key domain is closed --
    `CapabilityName`, `NormalizedIdentifier`, and `SemanticVersion` are all
    pattern-constrained strings -- so there is no finite `contains` enumeration
    and a flat `uniqueItems` would be strictly weaker than the runtime rule.
    """
    document = _document()
    capabilities = document["required_capabilities"]
    assert isinstance(capabilities, list)
    document["required_capabilities"] = [
        capabilities[0],
        dict(capabilities[0]) | {"required": False},
    ]
    assert not _spec_accepts(document)
    for mode in ("validation", "serialization"):
        assert Draft202012Validator(_spec_schema(mode)).is_valid(document)


def test_the_strategy_parity_correction_changes_no_canonical_byte() -> None:
    """Schema metadata only. The content hash is the permanent identity, so it is
    pinned literally rather than recomputed on both sides of a comparison."""
    spec = _spec()
    assert strategy_version_hash(spec) == (
        "14f59d879338f36a91f639e932567dba35cc17b835cfb16d7a4362c05b23c29e"
    )
    assert strategy_version_identifier(strategy_version_hash(spec)) == (
        "strv_14f59d87-9338-436a-91f6-39e932567dba"
    )
    assert len(canonical_json_bytes(spec)) == 2583
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
    assert spec.market_type is MarketType.SPOT
    assert spec.direction is Direction.LONG
    assert list(ParameterDefinition.model_fields) == [
        "value_type",
        "value",
        "minimum",
        "maximum",
        "unit",
    ]
