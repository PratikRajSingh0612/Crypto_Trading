"""Test static expression type checking and reference validation (plan Task 3).

Task 3 validates trees built from the closed `Expression` union that Task 2
owns. Per-node arity, discriminator closure, the model-level `bars_ago` bound,
and the model-level depth bound belong to
`tests/unit/strategy/test_strategy_expressions.py`; this module covers only the
static checker.
"""

from __future__ import annotations

from datetime import UTC, datetime
from inspect import signature
from pathlib import Path
from typing import Any, get_args

import pytest
from pydantic import ValidationError

from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.diagnostics import DiagnosticCategory, DiagnosticDetailValue
from crypto_lab.domain.results import (
    MAX_RESULT_DIAGNOSTICS,
    Failure,
    Result,
    Success,
)
from crypto_lab.strategy.expressions import (
    _NODE_MODELS,
    MAX_EXPRESSION_DEPTH,
    ExpressionNode,
    LiteralExpression,
    LiteralValueType,
    NotExpression,
    RefExpression,
)
from crypto_lab.strategy.models import RuleDefinition, StrategySpec
from crypto_lab.strategy.validation import (
    _ACCEPTED_OPERAND_TYPES,
    _MESSAGES,
    _RESULT_TYPES,
    _TYPE_RULES,
    SOURCE_BAR_FIELDS,
    _child_operands,
    _TypeRule,
    validate_strategy_expressions,
)
from crypto_lab.strategy.yaml_source import load_yaml_document

_FIXTURES = Path(__file__).parents[2] / "fixtures" / "strategy"
_OBSERVED_AT = datetime(2026, 8, 16, tzinfo=UTC)


def _document() -> dict[str, Any]:
    """Load the valid fixture through the real production path."""
    name = "sma_cross_long.valid.yaml"
    result = load_yaml_document((_FIXTURES / name).read_bytes(), name, _OBSERVED_AT)
    assert isinstance(result, Success), result
    value = result.value.value
    assert isinstance(value, dict)
    return dict(value)


def _spec(**overrides: object) -> StrategySpec:
    payload = _document() | overrides
    return StrategySpec.model_validate_json(canonical_json_bytes(payload))


def _entry(expression: dict[str, Any]) -> StrategySpec:
    """Return the fixture spec with exactly one entry rule."""
    return _spec(entry_rules=[{"id": "enter_probe", "expression": expression}])


def _validate(spec: StrategySpec) -> Result[StrategySpec]:
    return validate_strategy_expressions(spec, _OBSERVED_AT)


def _failure(spec: StrategySpec) -> Failure:
    result = _validate(spec)
    assert isinstance(result, Failure), result
    return result


def _findings(spec: StrategySpec) -> list[tuple[str, str, str]]:
    """Return `(rule_id, node_path, error_code)` for every diagnostic, in order."""
    findings: list[tuple[str, str, str]] = []
    for diagnostic in _failure(spec).diagnostics:
        rule_id = diagnostic.details["rule_id"]
        node_path = diagnostic.details["node_path"]
        assert isinstance(rule_id, str)
        assert isinstance(node_path, str)
        findings.append((rule_id, node_path, diagnostic.error_code))
    return findings


_TRUE = {"op": "literal", "value_type": "BOOLEAN", "value": True}
_ZERO = {"op": "literal", "value_type": "DECIMAL", "value": "0"}
_ONE_INT = {"op": "literal", "value_type": "INTEGER", "value": 1}
_TEXT = {"op": "literal", "value_type": "STRING", "value": "20"}
_OTHER_TEXT = {"op": "literal", "value_type": "STRING", "value": "21"}
_NAME = {"op": "literal", "value_type": "IDENTIFIER", "value": "fast_sma"}
_FAST = {"op": "ref", "id": "fast_sma", "bars_ago": 0}
_SLOW = {"op": "ref", "id": "slow_sma", "bars_ago": 0}

_MISMATCH = "STRATEGY.EXPRESSION_TYPE_MISMATCH"

_ARITHMETIC_OPS = ("add", "subtract", "multiply", "divide", "minimum", "maximum")
_ORDERING_OPS = (
    "less_than",
    "less_than_or_equal",
    "greater_than",
    "greater_than_or_equal",
)
_EQUALITY_OPS = ("equal", "not_equal")
_CROSSOVER_OPS = ("crosses_above", "crosses_below")


def _accepted(spec: StrategySpec) -> None:
    result = _validate(spec)
    assert isinstance(result, Success), result
    assert result.value == spec


# --- Steps 1 and 2: operator signatures and type inference ------------------


def test_the_unchanged_fixture_specification_is_accepted() -> None:
    _accepted(_spec())


def test_a_boolean_operand_of_add_is_rejected() -> None:
    """`add` accepts numeric operands only, and returns `DECIMAL`."""
    spec = _entry(
        {
            "op": "greater_than",
            "left": {"op": "add", "left": _TRUE, "right": _FAST},
            "right": _ZERO,
        }
    )

    assert _findings(spec) == [("enter_probe", "expression.left.left", _MISMATCH)]


@pytest.mark.parametrize("op", _ARITHMETIC_OPS)
def test_every_arithmetic_operator_rejects_a_boolean_operand(op: str) -> None:
    spec = _entry(
        {
            "op": "greater_than",
            "left": {"op": op, "left": _TRUE, "right": _FAST},
            "right": _ZERO,
        }
    )

    assert _findings(spec) == [("enter_probe", "expression.left.left", _MISMATCH)]


@pytest.mark.parametrize("op", _ARITHMETIC_OPS)
def test_every_arithmetic_operator_accepts_mixed_integer_and_decimal(op: str) -> None:
    _accepted(
        _entry(
            {
                "op": "greater_than",
                "left": {"op": op, "left": _ONE_INT, "right": _ZERO},
                "right": _ZERO,
            }
        )
    )


def test_a_decimal_operand_of_and_is_rejected() -> None:
    """Boolean operators accept booleans only."""
    spec = _entry({"op": "and", "operands": [_ZERO, _TRUE]})

    assert _findings(spec) == [("enter_probe", "expression.operands[0]", _MISMATCH)]


def test_a_decimal_operand_of_or_is_rejected() -> None:
    spec = _entry({"op": "or", "operands": [_TRUE, _ZERO]})

    assert _findings(spec) == [("enter_probe", "expression.operands[1]", _MISMATCH)]


def test_arithmetic_returns_decimal_and_is_not_a_boolean() -> None:
    """Proves the inferred result type, not merely the operand types."""
    spec = _entry(
        {"op": "and", "operands": [{"op": "add", "left": _ZERO, "right": _ZERO}]}
    )

    assert _findings(spec) == [("enter_probe", "expression.operands[0]", _MISMATCH)]


def test_a_string_compared_to_an_integer_is_rejected() -> None:
    """Equality needs compatible operands; the diagnostic names the operator."""
    spec = _entry({"op": "equal", "left": _TEXT, "right": _ONE_INT})

    assert _findings(spec) == [("enter_probe", "expression", _MISMATCH)]


@pytest.mark.parametrize("op", _EQUALITY_OPS)
def test_every_equality_operator_rejects_an_identifier_compared_to_a_string(
    op: str,
) -> None:
    spec = _entry({"op": op, "left": _NAME, "right": _TEXT})

    assert _findings(spec) == [("enter_probe", "expression", _MISMATCH)]


def test_equality_never_treats_a_boolean_as_an_integer() -> None:
    spec = _entry({"op": "equal", "left": _TRUE, "right": _ONE_INT})

    assert _findings(spec) == [("enter_probe", "expression", _MISMATCH)]


@pytest.mark.parametrize("op", _EQUALITY_OPS)
@pytest.mark.parametrize(
    ("left", "right"),
    [
        (_TRUE, _TRUE),
        (_ONE_INT, _ZERO),
        (_TEXT, _OTHER_TEXT),
        (_NAME, _NAME),
    ],
)
def test_equality_accepts_every_matching_kind(
    op: str,
    left: dict[str, Any],
    right: dict[str, Any],
) -> None:
    _accepted(_entry({"op": op, "left": left, "right": right}))


@pytest.mark.parametrize("op", _ORDERING_OPS)
def test_every_ordering_operator_rejects_both_non_numeric_operands(op: str) -> None:
    """Ordering is numeric-only, and each offending operand is named."""
    spec = _entry({"op": op, "left": _TEXT, "right": _OTHER_TEXT})

    assert _findings(spec) == [
        ("enter_probe", "expression.left", _MISMATCH),
        ("enter_probe", "expression.right", _MISMATCH),
    ]


@pytest.mark.parametrize("op", _ORDERING_OPS)
def test_every_ordering_operator_accepts_numeric_operands(op: str) -> None:
    _accepted(_entry({"op": op, "left": _ONE_INT, "right": _ZERO}))


@pytest.mark.parametrize("op", _CROSSOVER_OPS)
def test_every_crossover_operator_rejects_a_boolean_operand(op: str) -> None:
    spec = _entry({"op": op, "left": _TRUE, "right": _FAST})

    assert _findings(spec) == [("enter_probe", "expression.left", _MISMATCH)]


@pytest.mark.parametrize("op", _CROSSOVER_OPS)
def test_every_crossover_operator_accepts_two_numeric_series(op: str) -> None:
    _accepted(_entry({"op": op, "left": _FAST, "right": _SLOW}))


def test_not_requires_a_boolean_operand() -> None:
    spec = _entry({"op": "not", "operand": _ZERO})

    assert _findings(spec) == [("enter_probe", "expression.operand", _MISMATCH)]


def test_not_accepts_a_boolean_operand_and_returns_boolean() -> None:
    _accepted(_entry({"op": "not", "operand": {"op": "not", "operand": _TRUE}}))


def test_negate_requires_a_numeric_operand() -> None:
    spec = _entry(
        {"op": "equal", "left": {"op": "negate", "operand": _TRUE}, "right": _ZERO}
    )

    assert _findings(spec) == [("enter_probe", "expression.left.operand", _MISMATCH)]


def test_negate_returns_decimal() -> None:
    _accepted(
        _entry(
            {
                "op": "greater_than",
                "left": {"op": "negate", "operand": _ONE_INT},
                "right": _ZERO,
            }
        )
    )


@pytest.mark.parametrize("operand", [_TRUE, _ZERO, _ONE_INT, _TEXT, _NAME, _FAST])
def test_is_missing_accepts_every_operand_type_and_returns_boolean(
    operand: dict[str, Any],
) -> None:
    _accepted(_entry({"op": "is_missing", "operand": operand}))


def test_a_literal_carries_its_declared_type_without_coercion() -> None:
    """A decimal-shaped `STRING` stays a string, so arithmetic rejects it."""
    spec = _entry(
        {
            "op": "greater_than",
            "left": {"op": "add", "left": _TEXT, "right": _ZERO},
            "right": _ZERO,
        }
    )

    assert _findings(spec) == [("enter_probe", "expression.left.left", _MISMATCH)]


# --- Step 3: reference resolution -------------------------------------------


def _ref(name: str, bars_ago: int = 0) -> dict[str, Any]:
    return {"op": "ref", "id": name, "bars_ago": bars_ago}


def _details(spec: StrategySpec) -> list[dict[str, DiagnosticDetailValue]]:
    return [dict(diagnostic.details) for diagnostic in _failure(spec).diagnostics]


_UNKNOWN = "STRATEGY.REFERENCE_UNKNOWN"
_DECIMAL_BAR_FIELDS = ("bar.open", "bar.high", "bar.low", "bar.close", "bar.volume")


def test_an_undeclared_parameter_reference_is_rejected() -> None:
    spec = _entry(
        {"op": "greater_than", "left": _ref("missing_period"), "right": _ZERO}
    )

    assert _findings(spec) == [("enter_probe", "expression.left", _UNKNOWN)]


def test_an_undeclared_source_field_reference_is_rejected() -> None:
    """`bar.vwap` is not one of the six permitted source bar fields."""
    spec = _entry({"op": "greater_than", "left": _ref("bar.vwap"), "right": _ZERO})

    assert _findings(spec) == [("enter_probe", "expression.left", _UNKNOWN)]


def test_an_undeclared_feature_reference_is_rejected() -> None:
    spec = _entry({"op": "crosses_above", "left": _ref("medium.sma"), "right": _SLOW})

    assert _findings(spec) == [("enter_probe", "expression.left", _UNKNOWN)]


def test_an_unresolved_reference_reports_the_offending_name_only_once() -> None:
    """No cascading type defect is stacked on top of the reference defect."""
    spec = _entry({"op": "and", "operands": [_ref("missing_period")]})

    assert _details(spec) == [
        {
            "rule_collection": "entry_rules",
            "rule_id": "enter_probe",
            "node_path": "expression.operands[0]",
            "reference_id": "missing_period",
        }
    ]


@pytest.mark.parametrize("side", ["left", "right"])
def test_an_unresolved_equality_operand_reports_no_cascading_pair_defect(
    side: str,
) -> None:
    """Equality compares a pair, so one unresolved side suppresses the pair check."""
    operands = {"left": _ONE_INT, "right": _ONE_INT} | {side: _ref("missing_period")}
    spec = _entry({"op": "equal", **operands})

    assert _findings(spec) == [("enter_probe", f"expression.{side}", _UNKNOWN)]


def test_every_rule_collection_is_validated() -> None:
    spec = _spec(
        entry_rules=[{"id": "enter_probe", "expression": _ref("missing_entry")}],
        exit_rules=[{"id": "exit_probe", "expression": _ref("missing_exit")}],
    )

    assert _findings(spec) == [
        ("enter_probe", "expression", _UNKNOWN),
        ("exit_probe", "expression", _UNKNOWN),
    ]


@pytest.mark.parametrize("field", _DECIMAL_BAR_FIELDS)
def test_every_numeric_source_bar_field_resolves_to_decimal(field: str) -> None:
    _accepted(_entry({"op": "greater_than", "left": _ref(field), "right": _ZERO}))

    mistyped = _entry({"op": "and", "operands": [_ref(field)]})
    assert _findings(mistyped) == [("enter_probe", "expression.operands[0]", _MISMATCH)]
    assert _details(mistyped)[0]["observed_type"] == "DECIMAL"


def test_the_timestamp_source_bar_field_resolves_to_string() -> None:
    _accepted(
        _entry({"op": "equal", "left": _ref("bar.timestamp_utc"), "right": _TEXT})
    )

    mistyped = _entry(
        {"op": "greater_than", "left": _ref("bar.timestamp_utc"), "right": _ZERO}
    )
    assert _findings(mistyped) == [("enter_probe", "expression.left", _MISMATCH)]
    assert _details(mistyped)[0]["observed_type"] == "STRING"


def test_a_declared_parameter_resolves_to_its_declared_value_type() -> None:
    """`fast_period` is declared `INTEGER` in the fixture."""
    _accepted(
        _entry({"op": "greater_than", "left": _ref("fast_period"), "right": _ZERO})
    )

    mistyped = _entry({"op": "and", "operands": [_ref("fast_period")]})
    assert _findings(mistyped) == [("enter_probe", "expression.operands[0]", _MISMATCH)]
    assert _details(mistyped)[0]["observed_type"] == "INTEGER"


def test_a_declared_feature_resolves_to_its_declared_output_type() -> None:
    """`fast_sma` is declared `DECIMAL` in the fixture."""
    mistyped = _entry({"op": "and", "operands": [_FAST]})

    assert _findings(mistyped) == [("enter_probe", "expression.operands[0]", _MISMATCH)]
    assert _details(mistyped)[0]["observed_type"] == "DECIMAL"


def test_a_reference_to_the_current_closed_bar_is_accepted() -> None:
    _accepted(
        _entry({"op": "crosses_above", "left": _ref("fast_sma", 0), "right": _SLOW})
    )


@pytest.mark.parametrize("bars_ago", [1, 2, 50, 4096])
def test_a_positive_historical_offset_is_accepted(bars_ago: int) -> None:
    _accepted(
        _entry(
            {
                "op": "greater_than",
                "left": _ref("fast_sma", bars_ago),
                "right": _ref("bar.close", bars_ago),
            }
        )
    )


# Every edge of the documented precedence chain is asserted separately.
# `NormalizedIdentifier` is `^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`, so a dotted
# `bar.close` is a legal feature ID and a legal parameter key and all three
# namespaces can genuinely collide. Each test below drives its probe through a
# numeric operator and shadows the winner with a `BOOLEAN` declaration, so the
# losing resolution would be a type mismatch rather than a silent pass.


def _numeric_probe(name: str, **overrides: object) -> StrategySpec:
    return _spec(
        entry_rules=[
            _rule(
                "enter_probe",
                {"op": "greater_than", "left": _ref(name), "right": _ZERO},
            )
        ],
        **overrides,
    )


def _boolean_feature(feature_id: str) -> dict[str, Any]:
    declaration = dict(_document()["features"][0])
    return declaration | {"id": feature_id, "output_type": "BOOLEAN"}


def test_a_source_bar_field_outranks_a_colliding_parameter() -> None:
    """Bar fields are reserved, so a parameter cannot shadow one."""
    parameters = dict(_document()["parameters"])
    parameters["bar.close"] = {"value_type": "BOOLEAN", "value": True}

    _accepted(_numeric_probe("bar.close", parameters=parameters))


def test_a_source_bar_field_outranks_a_colliding_feature() -> None:
    """Bar fields also outrank a declared feature, not only a parameter."""
    features = [*_document()["features"], _boolean_feature("bar.close")]

    _accepted(_numeric_probe("bar.close", features=features))


def test_a_declared_feature_outranks_a_colliding_parameter() -> None:
    """`fast_sma` is a DECIMAL feature in the fixture; the parameter is BOOLEAN."""
    parameters = dict(_document()["parameters"])
    parameters["fast_sma"] = {"value_type": "BOOLEAN", "value": True}

    _accepted(_numeric_probe("fast_sma", parameters=parameters))


def test_the_losing_side_of_each_precedence_edge_is_genuinely_boolean() -> None:
    """Guards the three tests above from passing because the shadow is numeric.

    Each asserts acceptance, so a shadow that happened to type-check numerically
    would make them vacuous. Here the same declarations win on a name no higher
    namespace claims, and the resulting mismatch proves they are BOOLEAN.
    """
    parameters = dict(_document()["parameters"])
    parameters["shadow.probe"] = {"value_type": "BOOLEAN", "value": True}
    features = [*_document()["features"], _boolean_feature("other.probe")]

    assert _findings(_numeric_probe("shadow.probe", parameters=parameters)) == [
        ("enter_probe", "expression.left", _MISMATCH)
    ]
    assert _findings(_numeric_probe("other.probe", features=features)) == [
        ("enter_probe", "expression.left", _MISMATCH)
    ]


# --- Step 5: the checker's own depth bound -----------------------------------

_DEPTH_EXCEEDED = "STRATEGY.EXPRESSION_DEPTH_EXCEEDED"
_DEEPEST_PATH = "expression" + ".operand" * MAX_EXPRESSION_DEPTH


def _deep_expression(depth: int) -> ExpressionNode:
    """Return a `not` chain of exactly `depth` nodes.

    Built with `model_construct` on purpose: Task 2's `AfterValidator` on the
    `Expression` annotation rejects a tree past `MAX_EXPRESSION_DEPTH` at
    construction, so a validated tree could never reach the checker's own bound.
    That bound is deliberate redundancy the plan requires, and this is the only
    way to exercise it.
    """
    node: ExpressionNode = LiteralExpression(
        op="literal", value_type=LiteralValueType.BOOLEAN, value=True
    )
    for _ in range(depth - 1):
        node = NotExpression.model_construct(op="not", operand=node)
    return node


def _deep_spec(depth: int) -> StrategySpec:
    rule = RuleDefinition.model_construct(
        id="deep_probe", expression=_deep_expression(depth)
    )
    return _spec().model_copy(update={"entry_rules": (rule,)})


def test_the_task_2_model_already_rejects_a_tree_past_the_depth_bound() -> None:
    """Preserved Task 2 boundary; it is why `model_construct` is required below."""
    with pytest.raises(ValidationError):
        RuleDefinition(
            id="deep_probe",
            expression=_deep_expression(MAX_EXPRESSION_DEPTH + 1),
        )


def test_a_tree_at_the_depth_bound_is_accepted_by_the_checker() -> None:
    _accepted(_deep_spec(MAX_EXPRESSION_DEPTH))


def test_a_tree_past_the_depth_bound_is_rejected_by_the_checker() -> None:
    spec = _deep_spec(MAX_EXPRESSION_DEPTH + 1)

    assert _findings(spec) == [("deep_probe", _DEEPEST_PATH, _DEPTH_EXCEEDED)]
    assert _details(spec)[0]["maximum_depth"] == MAX_EXPRESSION_DEPTH


def test_the_depth_diagnostic_is_classified_as_a_security_defect() -> None:
    """It bounds an adversarial document's nesting, exactly as the loader's does."""
    diagnostics = _failure(_deep_spec(MAX_EXPRESSION_DEPTH + 1)).diagnostics

    assert diagnostics[0].category is DiagnosticCategory.SECURITY


def test_a_far_deeper_tree_terminates_without_recursion() -> None:
    """Traversal is iterative and stops descending below the bound."""
    spec = _deep_spec(5_000)

    assert _findings(spec) == [("deep_probe", _DEEPEST_PATH, _DEPTH_EXCEEDED)]


# --- Step 6: completeness, deduplication, and stable ordering -----------------


def _rule(rule_id: str, expression: dict[str, Any]) -> dict[str, Any]:
    return {"id": rule_id, "expression": expression}


def test_every_simultaneous_defect_in_one_rule_is_returned() -> None:
    """Four distinct defects of three kinds, none of them masking another."""
    spec = _entry(
        {
            "op": "and",
            "operands": [
                _ZERO,
                {"op": "add", "left": _TRUE, "right": _ref("missing_period")},
                {"op": "equal", "left": _TEXT, "right": _ONE_INT},
            ],
        }
    )

    assert _findings(spec) == [
        ("enter_probe", "expression.operands[0]", _MISMATCH),
        ("enter_probe", "expression.operands[1]", _MISMATCH),
        ("enter_probe", "expression.operands[1].left", _MISMATCH),
        ("enter_probe", "expression.operands[1].right", _UNKNOWN),
        ("enter_probe", "expression.operands[2]", _MISMATCH),
    ]


def test_diagnostics_are_sorted_by_rule_id_then_node_path_then_error_code() -> None:
    """Generation order is entry-then-exit; the returned order is the sort key's."""
    spec = _spec(
        entry_rules=[_rule("zulu_probe", {"op": "and", "operands": [_ZERO]})],
        exit_rules=[_rule("alpha_probe", {"op": "and", "operands": [_ZERO]})],
    )

    assert _findings(spec) == [
        ("alpha_probe", "expression.operands[0]", _MISMATCH),
        ("zulu_probe", "expression.operands[0]", _MISMATCH),
    ]


def test_node_paths_sort_lexicographically_rather_than_by_generation_order() -> None:
    """`operands[10]` precedes `operands[2]` under the plan's textual key."""
    operands: list[dict[str, Any]] = [_TRUE] * 11
    operands[2] = _ZERO
    operands[10] = _ZERO
    spec = _entry({"op": "and", "operands": operands})

    assert _findings(spec) == [
        ("enter_probe", "expression.operands[10]", _MISMATCH),
        ("enter_probe", "expression.operands[2]", _MISMATCH),
    ]


def test_an_identical_defect_in_two_indistinguishable_rules_is_deduplicated() -> None:
    """Two rules sharing an id and a defect are indistinguishable to a diagnostic."""
    duplicate = {"op": "and", "operands": [_ZERO]}
    spec = _spec(
        entry_rules=[_rule("dup_probe", duplicate), _rule("dup_probe", duplicate)]
    )

    assert _findings(spec) == [("dup_probe", "expression.operands[0]", _MISMATCH)]


def test_the_same_defect_at_two_different_nodes_is_not_deduplicated() -> None:
    """Deduplication is not lossy: `node_path` is part of the diagnostic identity."""
    spec = _entry({"op": "and", "operands": [_ZERO, _ZERO]})

    assert _findings(spec) == [
        ("enter_probe", "expression.operands[0]", _MISMATCH),
        ("enter_probe", "expression.operands[1]", _MISMATCH),
    ]


def test_the_same_rule_id_in_both_collections_stays_distinct_and_ordered() -> None:
    """The sort key ties, so the stable sort keeps the entry rule first."""
    duplicate = {"op": "and", "operands": [_ZERO]}
    spec = _spec(
        entry_rules=[_rule("both_probe", duplicate)],
        exit_rules=[_rule("both_probe", duplicate)],
    )
    diagnostics = _failure(spec).diagnostics

    assert len(diagnostics) == 2
    assert diagnostics[0].diagnostic_id != diagnostics[1].diagnostic_id
    assert [diagnostic.details["rule_collection"] for diagnostic in diagnostics] == [
        "entry_rules",
        "exit_rules",
    ]


def test_two_runs_over_equal_inputs_are_byte_identical_including_identifiers() -> None:
    spec = _entry({"op": "and", "operands": [_ZERO, _ref("missing_period")]})

    first = canonical_json_bytes(_failure(spec))
    second = canonical_json_bytes(
        _failure(_entry({"op": "and", "operands": [_ZERO, _ref("missing_period")]}))
    )

    assert first == second


def test_declaration_order_of_the_namespaces_cannot_change_the_result() -> None:
    """Reordered parameters and features yield byte-identical diagnostics.

    The parameter mapping is reordered with `model_copy` rather than in the source
    document, because `_spec` routes through `canonical_json_bytes`, which sorts
    object keys — a reordered source mapping would be silently re-sorted and the
    assertion would prove nothing about the scope builder's dict iteration.
    """
    features = list(_document()["features"])
    bad_rule = [
        _rule("enter_probe", {"op": "and", "operands": [_FAST, _ref("missing_period")]})
    ]
    straight = _spec(features=features, entry_rules=bad_rule)
    reordered = _spec(
        features=list(reversed(features)), entry_rules=bad_rule
    ).model_copy(
        update={"parameters": dict(reversed(list(straight.parameters.items())))}
    )

    assert list(straight.parameters) != list(reordered.parameters)
    assert straight.features != reordered.features
    assert canonical_json_bytes(_failure(straight)) == canonical_json_bytes(
        _failure(reordered)
    )


def test_the_diagnostic_count_is_bounded_by_the_result_contract() -> None:
    """More defects than `Failure` admits are truncated, never raised."""
    operands: list[dict[str, Any]] = [_ZERO] * 64
    spec = _spec(
        entry_rules=[
            _rule(f"probe_{letter}", {"op": "and", "operands": operands})
            for letter in ("a", "b", "c", "d", "e")
        ]
    )
    diagnostics = _failure(spec).diagnostics

    assert len(diagnostics) == MAX_RESULT_DIAGNOSTICS
    retained = {diagnostic.details["rule_id"] for diagnostic in diagnostics}
    assert retained == {"probe_a", "probe_b", "probe_c", "probe_d"}


# --- A rule is a signal, so its root expression must be BOOLEAN ---------------


@pytest.mark.parametrize(
    "root",
    [
        {"op": "add", "left": _ZERO, "right": _ZERO},
        {"op": "negate", "operand": _ZERO},
        _ZERO,
        _ONE_INT,
        _TEXT,
        _NAME,
        _FAST,
    ],
)
def test_a_rule_whose_root_is_not_boolean_is_rejected(root: dict[str, Any]) -> None:
    """Specification 12.3.2: a rule never becomes true through truthiness."""
    spec = _entry(root)

    assert _findings(spec) == [("enter_probe", "expression", _MISMATCH)]
    assert _details(spec)[0]["expected_types"] == ["BOOLEAN"]


def test_a_non_boolean_exit_rule_root_is_rejected() -> None:
    spec = _spec(exit_rules=[_rule("exit_probe", _ZERO)])

    assert _findings(spec) == [("exit_probe", "expression", _MISMATCH)]


def test_an_unresolved_root_reference_reports_no_cascading_root_defect() -> None:
    spec = _entry(_ref("missing_period"))

    assert _findings(spec) == [("enter_probe", "expression", _UNKNOWN)]


# --- Closed operator dispatch (no reflection, no callable resolution) ---------


def test_the_dispatch_table_covers_exactly_the_closed_union() -> None:
    """Membership is proven against the union itself, so no operator can drift.

    Nothing falls through at runtime: a node kind added without a signature
    fails this test rather than reaching an unreachable defensive branch.
    """
    union_ops: set[str] = set()
    for model in _NODE_MODELS:
        discriminator = get_args(model.model_fields["op"].annotation)
        assert len(discriminator) == 1
        assert isinstance(discriminator[0], str)
        union_ops.add(discriminator[0])

    assert union_ops == set(_TYPE_RULES) | {"literal", "ref"}
    assert len(union_ops) == 21


def test_every_dispatch_table_value_is_data_rather_than_a_callable() -> None:
    """No strategy-supplied string can resolve a Python callable."""
    for rule in _TYPE_RULES.values():
        assert isinstance(rule, _TypeRule)
    for result in _RESULT_TYPES.values():
        assert isinstance(result, LiteralValueType)
    for accepted in _ACCEPTED_OPERAND_TYPES.values():
        assert all(isinstance(member, LiteralValueType) for member in accepted)
    assert set(_RESULT_TYPES) == set(_TypeRule)


def test_the_permitted_source_bar_fields_are_exactly_the_six_named_fields() -> None:
    assert sorted(SOURCE_BAR_FIELDS) == [
        "bar.close",
        "bar.high",
        "bar.low",
        "bar.open",
        "bar.timestamp_utc",
        "bar.volume",
    ]


# --- Reference-offset boundary preserved from Task 2 --------------------------


def test_a_negative_offset_is_rejected_by_its_own_exact_diagnostic() -> None:
    """Task 2's model gate, preserved. Task 3 never sees such a tree."""
    with pytest.raises(ValidationError) as raised:
        RefExpression(op="ref", id="fast_sma", bars_ago=-1)

    assert "STRATEGY.REFERENCE_NEGATIVE_OFFSET" in str(raised.value)


@pytest.mark.parametrize("bars_ago", [-1, -2, -4096])
def test_no_accepted_reference_model_can_carry_a_negative_offset(bars_ago: int) -> None:
    with pytest.raises(ValidationError):
        _entry({"op": "not", "operand": _ref("fast_sma", bars_ago)})


def test_every_accepted_reference_in_a_validated_specification_is_historical() -> None:
    spec = _spec()
    offsets = [
        node.bars_ago
        for rules in (spec.entry_rules, spec.exit_rules)
        for rule in rules
        for node in _reference_nodes(rule.expression)
    ]

    assert offsets != []
    assert all(offset >= 0 for offset in offsets)


def _reference_nodes(node: ExpressionNode) -> list[RefExpression]:
    found: list[RefExpression] = []
    pending = [node]
    while pending:
        current = pending.pop()
        if isinstance(current, RefExpression):
            found.append(current)
        pending.extend(operand for _, operand in _child_operands(current))
    return found


# --- The static entry point holds no evaluation state ------------------------


def test_the_entry_point_accepts_no_runtime_bar_state() -> None:
    """Signature inspection, so a harmless refactor cannot break it."""
    parameters = signature(validate_strategy_expressions).parameters

    assert list(parameters) == ["spec", "observed_at_utc"]
    assert parameters["spec"].annotation == "StrategySpec"
    assert parameters["observed_at_utc"].annotation == "datetime"


def test_the_module_emits_exactly_its_own_three_error_codes() -> None:
    """`STRATEGY.REFERENCE_FUTURE_BAR` is unreachable here and is not emitted.

    A future or still-open bar can only be named by a negative `bars_ago`, which
    Task 2 rejects before static validation, and this checker holds no bar-state
    context that could observe one. The code remains reserved in the closed
    Stage 4 vocabulary for the layer that owns evaluation context.
    """
    assert sorted(_MESSAGES) == [
        "STRATEGY.EXPRESSION_DEPTH_EXCEEDED",
        "STRATEGY.EXPRESSION_TYPE_MISMATCH",
        "STRATEGY.REFERENCE_UNKNOWN",
    ]
    assert "STRATEGY.REFERENCE_FUTURE_BAR" not in _MESSAGES
