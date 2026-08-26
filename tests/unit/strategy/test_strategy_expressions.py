"""Test the closed discriminated expression AST of plan Task 2 step 11.

Covers every node kind, arity, discriminator closure, the model-level `bars_ago`
and depth bounds, and every literal test required by item A of the plan's
reviewed correction on hash-material field types.

The primary production path is YAML source -> `canonical_json_bytes` ->
`model_validate_json`, so these tests default to **JSON mode** and exercise
Python mode explicitly where the two contracts differ.
"""

from __future__ import annotations

import json
import subprocess
import sys
from copy import deepcopy
from decimal import Decimal
from typing import Any, Literal

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import TypeAdapter, ValidationError

from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.strategy.expressions import (
    EXPRESSION_ADAPTER,
    EXPRESSION_SEMANTICS_VERSION,
    MAX_BARS_AGO,
    MAX_EXPRESSION_DEPTH,
    MAX_EXPRESSION_OPERANDS,
    MAX_LITERAL_INTEGER,
    MAX_LITERAL_STRING_CHARACTERS,
    MIN_LITERAL_INTEGER,
    ExpressionNode,
    LiteralExpression,
    LiteralValueType,
    RefExpression,
)
from crypto_lab.strategy.models import StrategySpec
from crypto_lab.strategy.versioning import StrategyVersion
from crypto_lab.strategy.yaml_source import (
    MAX_INTEGER_VALUE,
    MAX_SCALAR_CHARACTERS,
    MIN_INTEGER_VALUE,
)

_LEAF: dict[str, Any] = {"op": "ref", "id": "fast_sma", "bars_ago": 0}

_UNARY_OPS = ("not", "negate", "is_missing")
_BINARY_OPS = (
    "add",
    "subtract",
    "multiply",
    "divide",
    "minimum",
    "maximum",
    "equal",
    "not_equal",
    "less_than",
    "less_than_or_equal",
    "greater_than",
    "greater_than_or_equal",
    "crosses_above",
    "crosses_below",
)
_VARIADIC_OPS = ("and", "or")


def _load(payload: object) -> ExpressionNode:
    """Validate through the union adapter in JSON mode, the production path."""
    return EXPRESSION_ADAPTER.validate_json(json.dumps(payload))


def _literal(value_type: str, value: object) -> LiteralExpression:
    node = _load({"op": "literal", "value_type": value_type, "value": value})
    assert isinstance(node, LiteralExpression)
    return node


def _nest(depth: int) -> dict[str, Any]:
    """Return a tree whose total node depth is exactly ``depth``."""
    tree: dict[str, Any] = dict(_LEAF)
    for _ in range(depth - 1):
        tree = {"op": "not", "operand": tree}
    return tree


# --- Node inventory, arity, and discriminator closure ----------------------


def _root_schema(mode: str) -> dict[str, Any]:
    """Resolve the adapter's root `$ref`, which a `type` alias always produces."""
    schema = EXPRESSION_ADAPTER.json_schema(mode=mode)  # type: ignore[arg-type]
    reference = schema.get("$ref")
    if reference is None:
        return schema
    resolved: dict[str, Any] = schema["$defs"][reference.rsplit("/", 1)[-1]]
    return resolved


def test_the_union_is_closed_at_exactly_the_twenty_one_specified_nodes() -> None:
    ops = {"literal", "ref", *_UNARY_OPS, *_BINARY_OPS, *_VARIADIC_OPS}

    assert len(ops) == 21
    emitted = set(_root_schema("validation")["discriminator"]["mapping"])
    assert emitted == ops


def test_the_semantics_version_is_expressions_v1() -> None:
    assert EXPRESSION_SEMANTICS_VERSION == "expressions/v1"


@pytest.mark.parametrize("op", _UNARY_OPS)
def test_a_unary_node_accepts_exactly_one_operand(op: str) -> None:
    assert _load({"op": op, "operand": _LEAF}) is not None


@pytest.mark.parametrize("op", _UNARY_OPS)
def test_a_unary_node_rejects_a_missing_operand(op: str) -> None:
    with pytest.raises(ValidationError):
        _load({"op": op})


@pytest.mark.parametrize("op", _UNARY_OPS)
def test_a_unary_node_rejects_a_second_operand(op: str) -> None:
    with pytest.raises(ValidationError):
        _load({"op": op, "operand": _LEAF, "right": _LEAF})


@pytest.mark.parametrize("op", _BINARY_OPS)
def test_a_binary_node_accepts_exactly_two_operands(op: str) -> None:
    assert _load({"op": op, "left": _LEAF, "right": _LEAF}) is not None


@pytest.mark.parametrize("op", _BINARY_OPS)
def test_a_binary_node_rejects_a_missing_right_operand(op: str) -> None:
    with pytest.raises(ValidationError):
        _load({"op": op, "left": _LEAF})


@pytest.mark.parametrize("op", _BINARY_OPS)
def test_a_binary_node_rejects_a_unary_operand_field(op: str) -> None:
    with pytest.raises(ValidationError):
        _load({"op": op, "operand": _LEAF})


@pytest.mark.parametrize("op", _VARIADIC_OPS)
def test_a_boolean_node_accepts_an_ordered_non_empty_operand_list(op: str) -> None:
    assert _load({"op": op, "operands": [_LEAF, _LEAF]}) is not None


@pytest.mark.parametrize("op", _VARIADIC_OPS)
def test_a_boolean_node_rejects_an_empty_operand_list(op: str) -> None:
    with pytest.raises(ValidationError):
        _load({"op": op, "operands": []})


@pytest.mark.parametrize("op", _VARIADIC_OPS)
def test_a_boolean_node_rejects_more_operands_than_the_bound(op: str) -> None:
    with pytest.raises(ValidationError):
        _load({"op": op, "operands": [_LEAF] * (MAX_EXPRESSION_OPERANDS + 1)})


def test_an_unknown_op_is_rejected_by_the_discriminated_union() -> None:
    with pytest.raises(ValidationError):
        _load({"op": "power", "left": _LEAF, "right": _LEAF})


def test_a_missing_op_is_rejected_by_the_discriminated_union() -> None:
    with pytest.raises(ValidationError):
        _load({"left": _LEAF, "right": _LEAF})


def test_an_unknown_field_on_a_node_is_rejected() -> None:
    with pytest.raises(ValidationError):
        _load({"op": "ref", "id": "fast_sma", "bars_ago": 0, "lookahead": 1})


# --- `ref` offsets ---------------------------------------------------------


def test_a_reference_accepts_a_zero_and_a_positive_offset() -> None:
    for bars_ago in (0, 1, 64):
        reference = _load({"op": "ref", "id": "fast_sma", "bars_ago": bars_ago})
        assert isinstance(reference, RefExpression)
        assert reference.bars_ago == bars_ago


def test_a_negative_offset_is_rejected_with_the_negative_offset_code() -> None:
    """Plan Task 3 step 3 relies on Task 2 emitting this exact code here."""
    with pytest.raises(ValidationError) as failure:
        _load({"op": "ref", "id": "fast_sma", "bars_ago": -1})

    assert "STRATEGY.REFERENCE_NEGATIVE_OFFSET" in str(failure.value)


def test_a_non_identifier_reference_target_is_rejected() -> None:
    with pytest.raises(ValidationError):
        _load({"op": "ref", "id": "Fast SMA", "bars_ago": 0})


def test_an_unbounded_offset_is_rejected() -> None:
    """An unbounded offset would admit an absurd integer into a permanent hash."""
    assert _load({"op": "ref", "id": "fast_sma", "bars_ago": MAX_BARS_AGO}) is not None
    with pytest.raises(ValidationError):
        _load({"op": "ref", "id": "fast_sma", "bars_ago": MAX_BARS_AGO + 1})


def test_a_non_integer_offset_is_rejected() -> None:
    for offset in ("0", 0.0, True, None):
        with pytest.raises(ValidationError):
            _load({"op": "ref", "id": "fast_sma", "bars_ago": offset})


# --- `bars_ago` runtime/schema parity --------------------------------------
#
# `Field(le=MAX_BARS_AGO)` renders `maximum`, but the lower bound lives in
# `validate_offset_is_not_negative`, which `Field` never renders -- so the
# generated schema accepted `bars_ago: -1` while the runtime rejected it. The
# bound is published through `json_schema_extra` rather than by adding `ge=0`
# **on purpose**: `ge=0` would make pydantic-core reject a negative value before
# the field validator runs, replacing the plan-mandated
# `STRATEGY.REFERENCE_NEGATIVE_OFFSET` diagnostic with a generic
# `greater_than_equal` error. Plan Task 3 step 3 depends on that exact code, so
# `test_the_negative_offset_error_is_the_project_code_and_not_a_pydantic_bound`
# below pins the error's `type` as well as its message.


def test_the_reference_offset_schema_publishes_its_lower_bound() -> None:
    for mode in ("validation", "serialization"):
        schema = EXPRESSION_ADAPTER.json_schema(mode=mode)
        node = schema["$defs"]["RefExpression"]["properties"]["bars_ago"]
        assert node["type"] == "integer"
        assert node["minimum"] == 0, f"{mode} mode must publish the lower bound"
        assert node["maximum"] == MAX_BARS_AGO


def test_the_reference_offset_lower_bound_reaches_both_strategy_schemas() -> None:
    """`RefExpression` is republished through `$defs` by both records."""
    for adapter in (TypeAdapter(StrategySpec), TypeAdapter(StrategyVersion)):
        for mode in ("validation", "serialization"):
            schema = adapter.json_schema(mode=mode)
            node = schema["$defs"]["RefExpression"]["properties"]["bars_ago"]
            assert node["minimum"] == 0
            assert node["maximum"] == MAX_BARS_AGO


def test_the_generated_schema_agrees_with_the_runtime_on_every_offset() -> None:
    for mode in ("validation", "serialization"):
        schema = EXPRESSION_ADAPTER.json_schema(mode=mode)
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        for accepted in (0, 1, MAX_BARS_AGO):
            document = {"op": "ref", "id": "fast_sma", "bars_ago": accepted}
            assert _load(document) is not None
            validator.validate(document)
        for rejected in (-1, MAX_BARS_AGO + 1):
            document = {"op": "ref", "id": "fast_sma", "bars_ago": rejected}
            with pytest.raises(ValidationError):
                _load(document)
            with pytest.raises(JsonSchemaValidationError):
                validator.validate(document)


def test_the_negative_offset_error_is_the_project_code_and_not_a_pydantic_bound() -> (
    None
):
    """Kills the `ge=0` shortcut, which would silently change the diagnostic.

    A `field_validator` raising `ValueError` surfaces as pydantic type
    ``value_error``; a `Field(ge=0)` constraint surfaces as
    ``greater_than_equal`` and never reaches the validator. Asserting the type
    is what makes the distinction executable rather than a comment.
    """
    with pytest.raises(ValidationError) as failure:
        _load({"op": "ref", "id": "fast_sma", "bars_ago": -1})

    errors = failure.value.errors()
    assert [error["type"] for error in errors] == ["value_error"]
    assert [error["loc"] for error in errors] == [("ref", "bars_ago")]
    assert "STRATEGY.REFERENCE_NEGATIVE_OFFSET" in str(failure.value)
    assert "greater_than_equal" not in str(failure.value)


def test_publishing_the_offset_bound_changed_no_canonical_byte() -> None:
    """The correction is schema metadata only, so hash material is untouched."""
    reference = _load({"op": "ref", "id": "fast_sma", "bars_ago": 3})
    assert canonical_json_bytes(reference) == (
        b'{"bars_ago":3,"id":"fast_sma","op":"ref"}'
    )


# --- Model-level depth bound ----------------------------------------------


def test_a_tree_at_the_maximum_depth_is_accepted() -> None:
    assert _load(_nest(MAX_EXPRESSION_DEPTH)) is not None


def test_a_tree_deeper_than_the_maximum_is_rejected_with_the_depth_code() -> None:
    with pytest.raises(ValidationError) as failure:
        _load(_nest(MAX_EXPRESSION_DEPTH + 1))

    assert "STRATEGY.EXPRESSION_DEPTH_EXCEEDED" in str(failure.value)


def test_depth_counts_through_every_operand_carrier() -> None:
    """A boolean node's operand list and a binary node's pair both nest."""
    deep = _nest(MAX_EXPRESSION_DEPTH - 1)
    with pytest.raises(ValidationError):
        _load({"op": "and", "operands": [_LEAF, {"op": "not", "operand": deep}]})
    with pytest.raises(ValidationError):
        _load({"op": "add", "left": {"op": "not", "operand": deep}, "right": _LEAF})


# --- Item A: literal value contract ---------------------------------------


def test_the_literal_value_type_vocabulary_is_exactly_five_members() -> None:
    assert [member.value for member in LiteralValueType] == [
        "BOOLEAN",
        "INTEGER",
        "DECIMAL",
        "STRING",
        "IDENTIFIER",
    ]


def test_value_type_precedes_value_in_field_order() -> None:
    """The dispatcher reads `info.data`, which holds only earlier fields."""
    assert list(LiteralExpression.model_fields) == ["op", "value_type", "value"]


@pytest.mark.parametrize(
    ("value_type", "value", "expected"),
    [
        ("BOOLEAN", True, True),
        ("BOOLEAN", False, False),
        ("INTEGER", 20, 20),
        ("INTEGER", -5, -5),
        ("INTEGER", 0, 0),
        ("DECIMAL", "1", Decimal("1")),
        ("DECIMAL", "1.5", Decimal("1.5")),
        ("DECIMAL", "-2.25", Decimal("-2.25")),
        ("STRING", "hello", "hello"),
        ("IDENTIFIER", "fast_sma", "fast_sma"),
        ("IDENTIFIER", "bar.close", "bar.close"),
    ],
)
def test_a_valid_value_is_accepted_for_every_value_type(
    value_type: str,
    value: object,
    expected: object,
) -> None:
    literal = _literal(value_type, value)

    assert isinstance(literal, LiteralExpression)
    assert literal.value == expected
    assert type(literal.value) is type(expected)


# Every mismatched pair, stated explicitly rather than computed, because this
# table is the accepted set of a permanent `content_hash`.
_REJECTED_PAIRS = [
    ("BOOLEAN", 20),
    ("BOOLEAN", 0),
    ("BOOLEAN", "true"),
    ("BOOLEAN", "1.5"),
    ("BOOLEAN", 1.5),
    ("BOOLEAN", None),
    ("BOOLEAN", [True]),
    ("BOOLEAN", {"a": True}),
    ("INTEGER", True),
    ("INTEGER", False),
    ("INTEGER", "20"),
    ("INTEGER", 1.5),
    ("INTEGER", 20.0),
    ("INTEGER", None),
    ("INTEGER", [20]),
    ("INTEGER", {"a": 20}),
    ("DECIMAL", 1),
    ("DECIMAL", 1.5),
    ("DECIMAL", True),
    ("DECIMAL", None),
    ("DECIMAL", ["1.5"]),
    ("DECIMAL", {"a": "1.5"}),
    ("DECIMAL", "1.50"),
    ("DECIMAL", "1e3"),
    ("DECIMAL", "+1"),
    ("DECIMAL", "-0"),
    ("DECIMAL", "abc"),
    ("STRING", 1),
    ("STRING", True),
    ("STRING", 1.5),
    ("STRING", None),
    ("STRING", ["a"]),
    ("STRING", {"a": "a"}),
    ("IDENTIFIER", 1),
    ("IDENTIFIER", True),
    ("IDENTIFIER", None),
    ("IDENTIFIER", ""),
    ("IDENTIFIER", "Not An Id"),
    ("IDENTIFIER", "1abc"),
    ("IDENTIFIER", "trailing_"),
    ("IDENTIFIER", ["fast_sma"]),
]


@pytest.mark.parametrize(("value_type", "value"), _REJECTED_PAIRS)
def test_a_mismatched_value_is_rejected(value_type: str, value: object) -> None:
    with pytest.raises(ValidationError):
        _literal(value_type, value)


def test_a_bool_is_rejected_as_an_integer() -> None:
    """`isinstance(True, int)` is True, so only an exact type check works."""
    with pytest.raises(ValidationError):
        _literal("INTEGER", True)

    assert type(_literal("INTEGER", 1).value) is int


def test_an_integer_is_rejected_as_a_decimal() -> None:
    with pytest.raises(ValidationError):
        _literal("DECIMAL", 1)


def test_a_decimal_like_string_is_retained_as_a_string() -> None:
    for text in ("1", "1.50", "1e3", "true", "~", "0x20"):
        literal = _literal("STRING", text)
        assert isinstance(literal, LiteralExpression)
        assert literal.value == text
        assert type(literal.value) is str


def test_the_same_text_as_decimal_and_as_string_differs_in_canonical_bytes() -> None:
    decimal_literal = _literal("DECIMAL", "1")
    string_literal = _literal("STRING", "1")
    assert isinstance(decimal_literal, LiteralExpression)
    assert isinstance(string_literal, LiteralExpression)

    decimal_payload = decimal_literal.model_dump(mode="json")
    string_payload = string_literal.model_dump(mode="json")
    decimal_bytes = canonical_json_bytes(decimal_payload)
    string_bytes = canonical_json_bytes(string_payload)

    assert decimal_bytes != string_bytes
    # The `value` bytes are *identical* -- both render "1" -- so `value_type` is
    # the only distinguishing material. Asserting inequality alone would pass
    # vacuously if the difference ever came from somewhere else, so pin the
    # discriminating token itself.
    assert decimal_payload["value"] == string_payload["value"] == "1"
    assert b'"value_type":"DECIMAL"' in decimal_bytes
    assert b'"value_type":"STRING"' in string_bytes


def test_an_identifier_literal_enforces_the_normalized_identifier_contract() -> None:
    for accepted in ("fast_sma", "bar.close", "indicator.sma", "a"):
        assert _literal("IDENTIFIER", accepted) is not None
    for rejected in ("A", "_a", "a__b", "a-", "a.", "a b"):
        with pytest.raises(ValidationError):
            _literal("IDENTIFIER", rejected)


def test_an_unknown_value_type_is_rejected() -> None:
    for unknown in ("FLOAT", "NULL", "decimal", "", "IDENTIFIER "):
        with pytest.raises(ValidationError):
            _literal(unknown, "1")


def test_a_missing_value_type_or_value_is_rejected() -> None:
    with pytest.raises(ValidationError):
        _load({"op": "literal", "value": "1"})
    with pytest.raises(ValidationError):
        _load({"op": "literal", "value_type": "STRING"})


# --- Item A: Python-mode contract and the defensive invariant -------------


def test_python_mode_requires_a_real_decimal_and_an_enum_member() -> None:
    literal = LiteralExpression(
        op="literal",
        value_type=LiteralValueType.DECIMAL,
        value=Decimal("1.5"),
    )

    assert literal.value == Decimal("1.5")
    assert type(literal.value) is Decimal


def test_python_mode_rejects_a_decimal_supplied_as_text() -> None:
    """`parse_decimal` accepts a canonical string only at the JSON boundary."""
    with pytest.raises(ValidationError):
        LiteralExpression(
            op="literal",
            value_type=LiteralValueType.DECIMAL,
            value="1.5",
        )


def test_python_mode_normalizes_a_non_canonical_decimal_on_serialization() -> None:
    literal = LiteralExpression(
        op="literal",
        value_type=LiteralValueType.DECIMAL,
        value=Decimal("1.50"),
    )

    assert literal.model_dump(mode="json")["value"] == "1.5"


def test_the_defensive_invariant_rejects_a_decimal_subclass() -> None:
    """A `Decimal` subclass passes `isinstance` but can restate its own text.

    This is the reachable arm of the post-validation invariant: `parse_decimal`
    admits any `Decimal` instance, so only an exact runtime-type check keeps a
    subclass -- whose `__str__` or `__format__` could differ -- out of a
    permanent `content_hash`.
    """

    class _WideDecimal(Decimal):
        pass

    with pytest.raises(ValidationError):
        LiteralExpression(
            op="literal",
            value_type=LiteralValueType.DECIMAL,
            value=_WideDecimal("1.5"),
        )


# --- Item A: per-branch bounds -------------------------------------------


def test_literal_bounds_mirror_the_loader_bounds() -> None:
    """The model bounds are declared locally so importing a model never loads
    PyYAML; this test is what stops the two copies from drifting."""
    assert MAX_LITERAL_STRING_CHARACTERS == MAX_SCALAR_CHARACTERS
    assert MIN_LITERAL_INTEGER == MIN_INTEGER_VALUE
    assert MAX_LITERAL_INTEGER == MAX_INTEGER_VALUE


def test_an_integer_beyond_the_signed_64_bit_range_is_rejected() -> None:
    assert _literal("INTEGER", MAX_LITERAL_INTEGER) is not None
    with pytest.raises(ValidationError):
        _literal("INTEGER", MAX_LITERAL_INTEGER + 1)
    with pytest.raises(ValidationError):
        _literal("INTEGER", MIN_LITERAL_INTEGER - 1)


def test_an_over_long_string_literal_is_rejected() -> None:
    assert _literal("STRING", "x" * MAX_LITERAL_STRING_CHARACTERS) is not None
    with pytest.raises(ValidationError):
        _literal("STRING", "x" * (MAX_LITERAL_STRING_CHARACTERS + 1))


# --- Item A: generated-schema agreement ----------------------------------

_SCHEMA_CASES = [
    ("BOOLEAN", True, True),
    ("BOOLEAN", 20, False),
    ("INTEGER", 20, True),
    ("INTEGER", True, False),
    ("INTEGER", "20", False),
    ("DECIMAL", "1.5", True),
    ("DECIMAL", "1.50", False),
    ("DECIMAL", 1, False),
    ("STRING", "1.50", True),
    ("STRING", 1, False),
    ("IDENTIFIER", "fast_sma", True),
    ("IDENTIFIER", "Not An Id", False),
]


@pytest.mark.parametrize(("value_type", "value", "accepted"), _SCHEMA_CASES)
@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_the_generated_literal_schema_agrees_with_the_runtime_contract(
    mode: str,
    value_type: str,
    value: object,
    accepted: bool,
) -> None:
    """The schema must encode the value_type/value relationship itself.

    Specification section 12.4 makes the generated schema the normative union
    definition, so an unconstrained scalar union there would be weaker than the
    runtime contract even while every runtime test passed.
    """
    schema = TypeAdapter(LiteralExpression).json_schema(mode=mode)  # type: ignore[arg-type]
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    payload = {"op": "literal", "value_type": value_type, "value": value}

    if accepted:
        validator.validate(payload)
        return
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(payload)


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_the_generated_literal_schema_constrains_every_value_type(mode: str) -> None:
    schema = TypeAdapter(LiteralExpression).json_schema(mode=mode)  # type: ignore[arg-type]
    branches = schema["allOf"]
    constrained = {
        branch["if"]["properties"]["value_type"]["const"] for branch in branches
    }

    assert constrained == {member.value for member in LiteralValueType}


def _patterns(node: object) -> list[str]:
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "pattern" and isinstance(value, str):
                found.append(value)
            else:
                found.extend(_patterns(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_patterns(item))
    return found


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_no_generated_expression_pattern_ends_with_a_dollar_anchor(mode: str) -> None:
    """Mirrors `test_every_schema_pattern_uses_absolute_end_semantics`.

    A hand-inlined `CANONICAL_DECIMAL_PATTERN` would be `$`-terminated and would
    fail that repository guard once Task 8 registers this schema, so the
    conditional branches must derive their sub-schemas from the existing types.
    """
    emitted = EXPRESSION_ADAPTER.json_schema(mode=mode)  # type: ignore[arg-type]
    patterns = _patterns(emitted)

    assert patterns != []
    for pattern in patterns:
        assert not pattern.endswith("$")
        assert pattern.endswith(r"(?![\s\S])")


# --- Round trips ----------------------------------------------------------


def test_a_tree_round_trips_through_canonical_json() -> None:
    payload = {
        "op": "and",
        "operands": [
            {
                "op": "crosses_above",
                "left": {"op": "ref", "id": "fast_sma", "bars_ago": 0},
                "right": {"op": "ref", "id": "slow_sma", "bars_ago": 0},
            },
            {
                "op": "greater_than",
                "left": {"op": "literal", "value_type": "DECIMAL", "value": "1.5"},
                "right": {"op": "literal", "value_type": "INTEGER", "value": 1},
            },
        ],
    }
    tree = _load(payload)
    assert tree is not None

    dumped = tree.model_dump(mode="json")
    assert canonical_json_bytes(dumped) == canonical_json_bytes(payload)
    assert _load(dumped) == tree


def test_a_frozen_node_rejects_mutation() -> None:
    reference = _load(_LEAF)
    assert isinstance(reference, RefExpression)

    with pytest.raises(ValidationError):
        reference.bars_ago = 1


# --------------------------------------------------------------------------
# Stage 4 runtime/schema parity closure -- the shared literal branch table and
# clause EXPR-C1
#
# `literal_value_branches` exists so `ParameterDefinition` can publish the same
# per-`value_type` dispatch this module already publishes for `LiteralExpression`
# without restating the table. A restated copy would drift, and the drift would
# be invisible: both nodes would still validate their own documents correctly
# while disagreeing with each other.
# --------------------------------------------------------------------------


def test_the_public_branch_table_is_exactly_what_the_literal_node_publishes() -> None:
    """The accessor and the emitted schema are the same table, not two copies."""
    from crypto_lab.strategy.expressions import literal_value_branches

    branches = literal_value_branches()
    assert set(branches) == set(LiteralValueType)
    schema = LiteralExpression.model_json_schema()
    emitted = {
        clause["if"]["properties"]["value_type"]["const"]: clause["then"]["properties"][
            "value"
        ]
        for clause in schema["allOf"]
    }
    assert {member.value: branch for member, branch in branches.items()} == emitted


def test_the_public_branch_table_hands_out_an_independent_copy() -> None:
    """A shared mutable table would let one consumer's schema mutate another's."""
    from crypto_lab.strategy.expressions import literal_value_branches

    first = literal_value_branches()
    first[LiteralValueType.INTEGER]["minimum"] = 0
    second = literal_value_branches()
    assert second[LiteralValueType.INTEGER]["minimum"] == MIN_LITERAL_INTEGER
    assert (
        LiteralExpression.model_json_schema()["allOf"][1]["then"]["properties"][
            "value"
        ]["minimum"]
        == MIN_LITERAL_INTEGER
    )


def test_the_literal_node_still_publishes_its_five_branches_unchanged() -> None:
    """Preservation: exposing the table must not alter what this module emits."""
    for mode in ("validation", "serialization"):
        schema = LiteralExpression.model_json_schema(mode=mode)
        assert len(schema["allOf"]) == 5
        assert [
            clause["if"]["properties"]["value_type"]["const"]
            for clause in schema["allOf"]
        ] == [member.value for member in LiteralValueType]
        assert schema["allOf"][0]["then"]["properties"]["value"] == {"type": "boolean"}
        assert schema["allOf"][1]["then"]["properties"]["value"] == {
            "type": "integer",
            "minimum": MIN_LITERAL_INTEGER,
            "maximum": MAX_LITERAL_INTEGER,
        }
        assert schema["allOf"][3]["then"]["properties"]["value"] == {
            "type": "string",
            "maxLength": MAX_LITERAL_STRING_CHARACTERS,
        }


def test_the_expression_depth_bound_stays_a_runtime_only_residual() -> None:
    """Clause EXPR-C1, recorded rather than published.

    `_bound_expression_depth` caps nesting at `MAX_EXPRESSION_DEPTH`, and
    `expression-v1` is a recursive schema whose nodes `$ref` `Expression` back.
    Draft 2020-12 has no recursion-depth keyword. The only exact encoding
    **replaces** the recursive reference graph with twenty-four numbered
    non-recursive tiers -- which is a different schema shape rather than an
    additive annotation, cannot be produced by a model-level `json_schema_extra`
    hook, and would multiply the published bytes by roughly the depth bound.
    There is also no sound weaker subset: any shallower bound would reject valid
    expressions. So the published schema deliberately does not claim this rule and
    runtime validation stays authoritative for it.
    """
    node: dict[str, Any] = {"op": "literal", "value_type": "BOOLEAN", "value": True}
    for _ in range(MAX_EXPRESSION_DEPTH + 6):
        node = {"op": "not", "operand": node}
    with pytest.raises(ValidationError):
        EXPRESSION_ADAPTER.validate_json(json.dumps(node))
    for mode in ("validation", "serialization"):
        schema = EXPRESSION_ADAPTER.json_schema(mode=mode)
        assert Draft202012Validator(schema).is_valid(node)
        assert "maxDepth" not in json.dumps(schema)


# --------------------------------------------------------------------------
# The recursive dispatcher publishes shallow conditional dispatch
#
# `$defs/Expression` used to publish a 21-member recursive `oneOf`.
# `discriminator` is an OpenAPI annotation and not a Draft 2020-12 keyword, so
# a conformant validator gets no help from it and must evaluate the
# alternatives to decide `oneOf`'s exactly-one rule. Fourteen operators share
# the recursive `left`/`right` shape, so a rejected alternative still descends
# into the shared children before it can fail, and cost grows by roughly the
# number of same-shape branches per nesting level.
#
# That alone is exponential for any operator with earlier same-shape branches,
# because `oneOf` evaluates pre-match alternatives with `iter_errors`, which
# collects every error and so cannot short-circuit: `crosses_below` chains cost
# 0.64 s, 5.7 s and over 20 s at depths 3, 4 and 5 even against the unsorted
# emitted dict.
#
# Canonical rendering extends it to the rest. `canonical_json_bytes` sorts keys,
# so inside a branch the recursive `left` is validated *before* the
# discriminating `op`, and `oneOf`'s short-circuiting post-match scan recurses
# instead of failing on the const. That is what catches `add` -- the first
# binary branch, and the one operator with no earlier same-shape alternative:
# 0.18 s at depth 3 and 2.6 s at depth 4 against the published rendering,
# against 0.007 s unsorted. An ordinary six-operator rule takes 45 s, and depth
# 24, which the runtime permits, never finishes.
#
# So every assertion below runs against `_published`, the canonical rendering,
# and not against the raw dict. A tractability test written against the raw
# dict and an `add` chain would have passed while the published bytes stayed
# exponential.
#
# The correction leaves the runtime tagged union untouched and republishes the
# same closed 21-member contract as shallow `if`/`then` clauses: at most one
# condition matches a document, only the matching `then` recurses, and no
# alternative ever visits a child expression.
# --------------------------------------------------------------------------

_MODES = ("validation", "serialization")

# Restated here on purpose. Production derives this table from `_NODE_MODELS`
# and the emitted branch references; a test that derived it the same way would
# assert nothing. The order is the union's own declaration order.
_DISPATCH_TABLE: tuple[tuple[str, str], ...] = (
    ("literal", "LiteralExpression"),
    ("ref", "RefExpression"),
    ("not", "NotExpression"),
    ("negate", "NegateExpression"),
    ("is_missing", "IsMissingExpression"),
    ("add", "AddExpression"),
    ("subtract", "SubtractExpression"),
    ("multiply", "MultiplyExpression"),
    ("divide", "DivideExpression"),
    ("minimum", "MinimumExpression"),
    ("maximum", "MaximumExpression"),
    ("equal", "EqualExpression"),
    ("not_equal", "NotEqualExpression"),
    ("less_than", "LessThanExpression"),
    ("less_than_or_equal", "LessThanOrEqualExpression"),
    ("greater_than", "GreaterThanExpression"),
    ("greater_than_or_equal", "GreaterThanOrEqualExpression"),
    ("crosses_above", "CrossesAboveExpression"),
    ("crosses_below", "CrossesBelowExpression"),
    ("and", "AndExpression"),
    ("or", "OrExpression"),
)
_DISPATCH_OPERATIONS = tuple(operation for operation, _ in _DISPATCH_TABLE)
_DISPATCH_REFERENCES = tuple(f"#/$defs/{model}" for _, model in _DISPATCH_TABLE)


def _published(mode: str) -> dict[str, Any]:
    """Return the schema exactly as `render_schema_files` publishes it.

    Key sorting is load-bearing rather than cosmetic here: it is what orders a
    branch's recursive `left` ahead of its discriminating `op`.
    """
    emitted = EXPRESSION_ADAPTER.json_schema(mode=mode)  # type: ignore[arg-type]
    published: dict[str, Any] = json.loads(canonical_json_bytes(emitted))
    return published


def _dispatcher(mode: str) -> dict[str, Any]:
    node: dict[str, Any] = _published(mode)["$defs"]["Expression"]
    return node


def _keys_anywhere(node: object) -> set[str]:
    """Every object key reachable from `node`, at any nesting level."""
    found: set[str] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            found.add(key)
            found |= _keys_anywhere(value)
    elif isinstance(node, list):
        for item in node:
            found |= _keys_anywhere(item)
    return found


@pytest.mark.parametrize("mode", _MODES)
def test_the_expression_dispatcher_is_not_a_recursive_one_of(mode: str) -> None:
    dispatcher = _dispatcher(mode)

    assert "oneOf" not in dispatcher
    assert "anyOf" not in dispatcher
    assert dispatcher["type"] == "object"
    assert dispatcher["required"] == ["op"]
    assert dispatcher["properties"] == {"op": {"enum": list(_DISPATCH_OPERATIONS)}}
    assert len(dispatcher["allOf"]) == 21


@pytest.mark.parametrize("mode", _MODES)
def test_the_dispatcher_operation_enum_is_the_exact_twenty_one_operations(
    mode: str,
) -> None:
    enumerated = _dispatcher(mode)["properties"]["op"]["enum"]

    assert enumerated == list(_DISPATCH_OPERATIONS)
    assert len(set(enumerated)) == 21
    assert set(enumerated) == {
        "literal",
        "ref",
        *_UNARY_OPS,
        *_BINARY_OPS,
        *_VARIADIC_OPS,
    }


@pytest.mark.parametrize("mode", _MODES)
def test_every_dispatcher_condition_is_shallow(mode: str) -> None:
    """The invariant that makes the published union tractable.

    A condition that could reach a child expression would reintroduce exactly
    the cost `oneOf` had, so the whole clause is pinned literally rather than
    only checked for the absence of a `$ref`.
    """
    for clause, operation in zip(
        _dispatcher(mode)["allOf"], _DISPATCH_OPERATIONS, strict=True
    ):
        assert set(clause) == {"if", "then"}, operation
        condition = clause["if"]
        assert condition == {
            "properties": {"op": {"const": operation}},
            "required": ["op"],
        }, operation
        reachable = _keys_anywhere(condition)
        assert reachable == {"properties", "op", "const", "required"}, operation
        assert "$ref" not in reachable, operation
        assert "oneOf" not in reachable, operation
        assert "anyOf" not in reachable, operation
        for carrier in ("left", "right", "operand", "operands"):
            assert carrier not in reachable, operation


@pytest.mark.parametrize("mode", _MODES)
def test_the_dispatch_mapping_is_exactly_one_branch_per_operation(mode: str) -> None:
    dispatcher = _dispatcher(mode)
    clauses = dispatcher["allOf"]
    operations = [clause["if"]["properties"]["op"]["const"] for clause in clauses]
    references = [clause["then"] for clause in clauses]

    assert operations == list(_DISPATCH_OPERATIONS)
    assert len(set(operations)) == 21
    assert references == [{"$ref": reference} for reference in _DISPATCH_REFERENCES]
    assert len({reference["$ref"] for reference in references}) == 21
    for clause in clauses:
        assert set(clause["then"]) == {"$ref"}


@pytest.mark.parametrize("mode", _MODES)
def test_every_dispatch_target_is_a_defined_branch_schema(mode: str) -> None:
    published = _published(mode)
    definitions = published["$defs"]

    for reference, (_, model) in zip(
        _DISPATCH_REFERENCES, _DISPATCH_TABLE, strict=True
    ):
        assert reference.removeprefix("#/$defs/") in definitions, reference
        branch = definitions[model]
        assert branch["type"] == "object", model
        assert branch["additionalProperties"] is False, model


@pytest.mark.parametrize("mode", _MODES)
def test_the_dispatcher_root_does_not_close_the_property_set(mode: str) -> None:
    """Closing the root would reject the branch fields the root never names.

    Field closure already belongs to each branch model, which carries
    `additionalProperties: false` of its own; adding it at the dispatcher would
    reject `left`, `right`, `operand`, and `operands` on every node.
    """
    dispatcher = _dispatcher(mode)

    assert "additionalProperties" not in dispatcher
    validator = Draft202012Validator(_published(mode))
    assert validator.is_valid({"op": "add", "left": _LEAF, "right": _LEAF})
    assert validator.is_valid({"op": "not", "operand": _LEAF})
    assert validator.is_valid({"op": "and", "operands": [_LEAF]})


@pytest.mark.parametrize("mode", _MODES)
def test_the_retained_discriminator_maps_every_operation(mode: str) -> None:
    discriminator = _dispatcher(mode)["discriminator"]

    assert discriminator["propertyName"] == "op"
    assert discriminator["mapping"] == dict(
        zip(_DISPATCH_OPERATIONS, _DISPATCH_REFERENCES, strict=True)
    )


@pytest.mark.parametrize("mode", _MODES)
def test_validation_does_not_depend_on_the_retained_discriminator(mode: str) -> None:
    """`discriminator` is a tooling annotation; Draft 2020-12 ignores it."""
    published = _published(mode)
    stripped = deepcopy(published)
    del stripped["$defs"]["Expression"]["discriminator"]
    Draft202012Validator.check_schema(stripped)
    with_annotation = Draft202012Validator(published)
    without_annotation = Draft202012Validator(stripped)

    for _, document, _ in _ACCEPTANCE_CORPUS:
        assert with_annotation.is_valid(document) == without_annotation.is_valid(
            document
        ), document


@pytest.mark.parametrize("mode", _MODES)
def test_the_published_schema_is_valid_draft_2020_12(mode: str) -> None:
    Draft202012Validator.check_schema(_published(mode))


# --- The dispatch table fails closed ---------------------------------------
#
# The table is derived from the node models and from the references pydantic
# emits, so nothing pins the two together except these guards. A future
# pydantic that renamed a branch, or a node model added without an `op`, must
# stop generation rather than publish a dispatcher pointing somewhere else.


def _emitted_union(
    mapping: dict[str, str] | None = None,
    branches: list[str] | None = None,
) -> dict[str, Any]:
    full = {operation: f"#/$defs/{model}" for operation, model in _DISPATCH_TABLE}
    return {
        "oneOf": [
            {"$ref": reference}
            for reference in (branches if branches is not None else list(full.values()))
        ],
        "discriminator": {
            "propertyName": "op",
            "mapping": full if mapping is None else mapping,
        },
    }


def test_the_dispatch_hook_rejects_an_operation_the_union_does_not_carry() -> None:
    from crypto_lab.strategy.expressions import _ConditionalDispatch

    incomplete = {
        operation: f"#/$defs/{model}" for operation, model in _DISPATCH_TABLE[:-1]
    }

    def handler(_schema: Any) -> dict[str, Any]:
        return _emitted_union(mapping=incomplete)

    with pytest.raises(RuntimeError, match="one to one onto ops"):
        _ConditionalDispatch().__get_pydantic_json_schema__(None, handler)  # type: ignore[arg-type]


def test_the_dispatch_hook_rejects_a_branch_set_that_is_not_a_bijection() -> None:
    from crypto_lab.strategy.expressions import _ConditionalDispatch

    def handler(_schema: Any) -> dict[str, Any]:
        return _emitted_union(branches=["#/$defs/AddExpression"])

    with pytest.raises(RuntimeError, match="one to one onto models"):
        _ConditionalDispatch().__get_pydantic_json_schema__(None, handler)  # type: ignore[arg-type]


def test_a_node_without_exactly_one_literal_op_is_rejected() -> None:
    from crypto_lab.domain.base import CanonicalModel
    from crypto_lab.strategy.expressions import _operation_of

    class _TwoValuedOp(CanonicalModel):
        op: Literal["add", "subtract"]

    with pytest.raises(TypeError, match="exactly one Literal op"):
        _operation_of(_TwoValuedOp)


def test_a_node_with_no_op_field_reports_the_same_contract() -> None:
    """Not a bare `KeyError`: the guard names the contract that was broken."""
    from crypto_lab.domain.base import CanonicalModel
    from crypto_lab.strategy.expressions import _operation_of

    class _NoOp(CanonicalModel):
        operand: int

    with pytest.raises(TypeError, match="exactly one Literal op"):
        _operation_of(_NoOp)


# Replacing a schema means discarding whatever the handler produced. These pin
# the shape being discarded, so a future Pydantic that emitted more at the union
# node could not have it silently dropped from a normative contract.


def test_the_dispatch_hook_rejects_a_sibling_keyword_at_the_union_node() -> None:
    from crypto_lab.strategy.expressions import _ConditionalDispatch

    def handler(_schema: Any) -> dict[str, Any]:
        return {**_emitted_union(), "title": "Expression"}

    with pytest.raises(RuntimeError, match="not a bare oneOf"):
        _ConditionalDispatch().__get_pydantic_json_schema__(None, handler)  # type: ignore[arg-type]


def test_the_dispatch_hook_rejects_a_discriminator_on_another_property() -> None:
    from crypto_lab.strategy.expressions import _ConditionalDispatch

    def handler(_schema: Any) -> dict[str, Any]:
        emitted = _emitted_union()
        emitted["discriminator"]["propertyName"] = "kind"
        return emitted

    with pytest.raises(RuntimeError, match="not a bare oneOf"):
        _ConditionalDispatch().__get_pydantic_json_schema__(None, handler)  # type: ignore[arg-type]


def test_the_dispatch_hook_rejects_a_constraint_beside_a_branch_reference() -> None:
    """Draft 2020-12 applies `$ref` siblings, so dropping one would weaken it."""
    from crypto_lab.strategy.expressions import _ConditionalDispatch

    def handler(_schema: Any) -> dict[str, Any]:
        emitted = _emitted_union()
        emitted["oneOf"][0]["maxProperties"] = 2
        return emitted

    with pytest.raises(RuntimeError, match="not a bare oneOf"):
        _ConditionalDispatch().__get_pydantic_json_schema__(None, handler)  # type: ignore[arg-type]


# --- Accept-set equivalence ------------------------------------------------
#
# Every document is decided three ways -- runtime, validation-mode schema, and
# serialization-mode schema -- and all three must agree. Depth stays at or below
# `MAX_EXPRESSION_DEPTH`, because the depth bound is the one recorded
# runtime-only residual (clause EXPR-C1) and is not an accept-set defect.


def _chain(op: str, levels: int, seed: dict[str, Any] | None = None) -> dict[str, Any]:
    node: dict[str, Any] = dict(_LEAF) if seed is None else seed
    for _ in range(levels):
        if op in _UNARY_OPS:
            node = {"op": op, "operand": node}
        elif op in _VARIADIC_OPS:
            node = {"op": op, "operands": [node, dict(_LEAF)]}
        else:
            node = {"op": op, "left": node, "right": dict(_LEAF)}
    return node


def _variable(name: str) -> dict[str, Any]:
    return {"op": "ref", "id": name, "bars_ago": 0}


# `((a+b)*(c-d))/(e+f) > 1.5` -- six binary operators, the shape a hand-written
# trading rule actually has, and the case the old dispatcher could not decide.
_ORDINARY_RULE: dict[str, Any] = {
    "op": "greater_than",
    "left": {
        "op": "divide",
        "left": {
            "op": "multiply",
            "left": {"op": "add", "left": _variable("a"), "right": _variable("b")},
            "right": {
                "op": "subtract",
                "left": _variable("c"),
                "right": _variable("d"),
            },
        },
        "right": {"op": "add", "left": _variable("e"), "right": _variable("f")},
    },
    "right": {"op": "literal", "value_type": "DECIMAL", "value": "1.5"},
}


def _valid_shapes() -> list[tuple[str, Any, bool]]:
    cases: list[tuple[str, Any, bool]] = [
        (
            "literal-boolean",
            {"op": "literal", "value_type": "BOOLEAN", "value": True},
            True,
        ),
        (
            "literal-integer",
            {"op": "literal", "value_type": "INTEGER", "value": 20},
            True,
        ),
        (
            "literal-decimal",
            {"op": "literal", "value_type": "DECIMAL", "value": "1.5"},
            True,
        ),
        (
            "literal-string",
            {"op": "literal", "value_type": "STRING", "value": "x"},
            True,
        ),
        (
            "literal-identifier",
            {"op": "literal", "value_type": "IDENTIFIER", "value": "fast_sma"},
            True,
        ),
        ("ref", dict(_LEAF), True),
    ]
    for op in _UNARY_OPS:
        cases.append((f"unary-{op}", {"op": op, "operand": dict(_LEAF)}, True))
    for op in _BINARY_OPS:
        cases.append(
            (
                f"binary-{op}",
                {"op": op, "left": dict(_LEAF), "right": dict(_LEAF)},
                True,
            )
        )
    for op in _VARIADIC_OPS:
        cases.append((f"variadic-{op}", {"op": op, "operands": [dict(_LEAF)]}, True))
    return cases


_ACCEPTANCE_CORPUS: tuple[tuple[str, Any, bool], ...] = (
    *_valid_shapes(),
    # boundaries
    ("ref-offset-zero", {"op": "ref", "id": "a", "bars_ago": 0}, True),
    ("ref-offset-max", {"op": "ref", "id": "a", "bars_ago": MAX_BARS_AGO}, True),
    (
        "literal-integer-min",
        {"op": "literal", "value_type": "INTEGER", "value": MIN_LITERAL_INTEGER},
        True,
    ),
    (
        "literal-integer-max",
        {"op": "literal", "value_type": "INTEGER", "value": MAX_LITERAL_INTEGER},
        True,
    ),
    (
        "literal-string-max",
        {
            "op": "literal",
            "value_type": "STRING",
            "value": "x" * MAX_LITERAL_STRING_CHARACTERS,
        },
        True,
    ),
    ("variadic-max-operands", {"op": "and", "operands": [dict(_LEAF)] * 64}, True),
    # Nesting, one family at a time and mixed. Depth is deliberately kept low
    # here even though the runtime permits 24: this corpus is validated
    # in-process with no timeout, so if the dispatcher were ever reverted a
    # deep case would hang the run instead of failing it, and a guard that
    # hangs reports nothing. Depth-24 verdicts for all nineteen recursive
    # families are asserted instead by the bounded subprocess matrix below,
    # which cannot hang.
    ("nested-unary", _chain("not", 3), True),
    ("nested-binary", _chain("multiply", 3), True),
    ("nested-variadic", _chain("or", 3), True),
    ("mixed-operations", _ORDINARY_RULE, True),
    # rejections
    ("unknown-op", {"op": "power", "left": dict(_LEAF), "right": dict(_LEAF)}, False),
    ("missing-op", {"left": dict(_LEAF), "right": dict(_LEAF)}, False),
    ("op-not-a-string", {"op": 5, "left": dict(_LEAF), "right": dict(_LEAF)}, False),
    ("op-empty-string", {"op": "", "left": dict(_LEAF), "right": dict(_LEAF)}, False),
    ("op-cased", {"op": "ADD", "left": dict(_LEAF), "right": dict(_LEAF)}, False),
    ("not-an-object", "add", False),
    ("null", None, False),
    ("array", [dict(_LEAF)], False),
    ("empty-object", {}, False),
    ("binary-missing-right", {"op": "add", "left": dict(_LEAF)}, False),
    ("binary-with-unary-field", {"op": "add", "operand": dict(_LEAF)}, False),
    (
        "unary-with-second-operand",
        {"op": "not", "operand": dict(_LEAF), "right": dict(_LEAF)},
        False,
    ),
    ("variadic-empty", {"op": "and", "operands": []}, False),
    ("variadic-over-bound", {"op": "or", "operands": [dict(_LEAF)] * 65}, False),
    ("variadic-not-a-list", {"op": "and", "operands": dict(_LEAF)}, False),
    ("extra-field", {"op": "ref", "id": "a", "bars_ago": 0, "lookahead": 1}, False),
    ("ref-negative-offset", {"op": "ref", "id": "a", "bars_ago": -1}, False),
    (
        "ref-offset-over-bound",
        {"op": "ref", "id": "a", "bars_ago": MAX_BARS_AGO + 1},
        False,
    ),
    ("ref-offset-text", {"op": "ref", "id": "a", "bars_ago": "0"}, False),
    ("ref-offset-boolean", {"op": "ref", "id": "a", "bars_ago": True}, False),
    ("ref-bad-identifier", {"op": "ref", "id": "Fast SMA", "bars_ago": 0}, False),
    ("ref-missing-offset", {"op": "ref", "id": "a"}, False),
    (
        "literal-unknown-value-type",
        {"op": "literal", "value_type": "FLOAT", "value": 1},
        False,
    ),
    (
        "literal-boolean-holding-integer",
        {"op": "literal", "value_type": "BOOLEAN", "value": 20},
        False,
    ),
    (
        "literal-integer-holding-boolean",
        {"op": "literal", "value_type": "INTEGER", "value": True},
        False,
    ),
    (
        "literal-decimal-non-canonical",
        {"op": "literal", "value_type": "DECIMAL", "value": "1.50"},
        False,
    ),
    (
        "literal-identifier-invalid",
        {"op": "literal", "value_type": "IDENTIFIER", "value": "Not An Id"},
        False,
    ),
    ("literal-missing-value", {"op": "literal", "value_type": "STRING"}, False),
    (
        "child-is-not-an-expression",
        {"op": "add", "left": "close", "right": dict(_LEAF)},
        False,
    ),
    (
        "child-has-an-unknown-op",
        {"op": "add", "left": {"op": "power"}, "right": dict(_LEAF)},
        False,
    ),
    (
        "deep-child-arity-error",
        _chain("add", 3, {"op": "add", "left": dict(_LEAF)}),
        False,
    ),
    (
        "deep-child-unknown-op",
        _chain("not", 3, {"op": "power", "operand": dict(_LEAF)}),
        False,
    ),
    (
        "deep-child-extra-field",
        _chain("or", 3, {"op": "ref", "id": "a", "bars_ago": 0, "extra": 1}),
        False,
    ),
)


def _runtime_accepts(document: object) -> bool:
    try:
        EXPRESSION_ADAPTER.validate_json(json.dumps(document))
    except ValidationError:
        return False
    return True


def test_the_acceptance_corpus_exercises_both_verdicts() -> None:
    """A corpus that only accepted, or only rejected, would prove nothing."""
    accepted = [name for name, _, expected in _ACCEPTANCE_CORPUS if expected]
    rejected = [name for name, _, expected in _ACCEPTANCE_CORPUS if not expected]

    assert len(accepted) >= 30
    assert len(rejected) >= 30
    assert len({name for name, _, _ in _ACCEPTANCE_CORPUS}) == len(_ACCEPTANCE_CORPUS)


@pytest.mark.parametrize(
    ("name", "document", "expected"),
    [(name, document, expected) for name, document, expected in _ACCEPTANCE_CORPUS],
    ids=[name for name, _, _ in _ACCEPTANCE_CORPUS],
)
def test_the_runtime_and_both_published_modes_decide_every_document_alike(
    name: str,
    document: object,
    expected: bool,
) -> None:
    assert _runtime_accepts(document) is expected, name
    for mode in _MODES:
        validator = Draft202012Validator(_published(mode))
        assert validator.is_valid(document) is expected, (name, mode)


def _leaf_documents() -> st.SearchStrategy[Any]:
    return st.sampled_from(
        [
            {"op": "ref", "id": "close", "bars_ago": 0},
            {"op": "ref", "id": "close", "bars_ago": -1},
            {"op": "literal", "value_type": "BOOLEAN", "value": True},
            {"op": "literal", "value_type": "INTEGER", "value": True},
            {"op": "literal", "value_type": "DECIMAL", "value": "1.5"},
            {"op": "ref", "id": "close"},
            {"op": "power"},
            {},
        ]
    )


def _tree_strategy(depth: int) -> st.SearchStrategy[Any]:
    if depth <= 1:
        return _leaf_documents()
    child = _tree_strategy(depth - 1)
    return st.one_of(
        _leaf_documents(),
        st.builds(
            lambda op, operand: {"op": op, "operand": operand},
            st.sampled_from([*_UNARY_OPS, "add"]),
            child,
        ),
        st.builds(
            lambda op, left, right: {"op": op, "left": left, "right": right},
            st.sampled_from([*_BINARY_OPS, "not"]),
            child,
            child,
        ),
        st.builds(
            lambda op, operands: {"op": op, "operands": operands},
            st.sampled_from(_VARIADIC_OPS),
            st.lists(child, min_size=0, max_size=2),
        ),
    )


@settings(max_examples=60, deadline=None)
@given(document=_tree_strategy(5))
def test_generated_trees_are_decided_alike_by_the_runtime_and_the_schemas(
    document: Any,
) -> None:
    """Depth stays below `MAX_EXPRESSION_DEPTH`, the one runtime-only residual."""
    expected = _runtime_accepts(document)

    for mode in _MODES:
        assert Draft202012Validator(_published(mode)).is_valid(document) is expected, (
            mode,
            document,
        )


# --- Cross-schema propagation ---------------------------------------------


@pytest.mark.parametrize("mode", _MODES)
@pytest.mark.parametrize("record", ["StrategySpec", "StrategyVersion"])
def test_both_strategy_records_republish_the_corrected_dispatcher(
    record: str,
    mode: str,
) -> None:
    adapter = TypeAdapter(StrategySpec if record == "StrategySpec" else StrategyVersion)
    emitted = adapter.json_schema(mode=mode)  # type: ignore[arg-type]
    published = json.loads(canonical_json_bytes(emitted))
    dispatcher = published["$defs"]["Expression"]

    assert "oneOf" not in dispatcher, record
    assert dispatcher == _dispatcher(mode), record
    definitions = published["$defs"]
    for reference in _DISPATCH_REFERENCES:
        assert reference.removeprefix("#/$defs/") in definitions, (record, reference)
    Draft202012Validator.check_schema(published)


# --- Bounded tractability --------------------------------------------------

_TRACTABILITY_BOUND_SECONDS = 10.0
_TRACTABILITY_PROBE = """
from __future__ import annotations

import json
import time

from jsonschema import Draft202012Validator

from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.strategy.expressions import EXPRESSION_ADAPTER, MAX_EXPRESSION_DEPTH

LEAF = {"op": "ref", "id": "close", "bars_ago": 0}
UNARY = ("not", "negate", "is_missing")
VARIADIC = ("and", "or")
BINARY = (
    "add",
    "subtract",
    "multiply",
    "divide",
    "minimum",
    "maximum",
    "equal",
    "not_equal",
    "less_than",
    "less_than_or_equal",
    "greater_than",
    "greater_than_or_equal",
    "crosses_above",
    "crosses_below",
)


def chain(op, levels, seed=None):
    node = dict(LEAF) if seed is None else seed
    for _ in range(levels):
        if op in UNARY:
            node = {"op": op, "operand": node}
        elif op in VARIADIC:
            node = {"op": op, "operands": [node, dict(LEAF)]}
        else:
            node = {"op": op, "left": node, "right": dict(LEAF)}
    return node


def variable(name):
    return {"op": "ref", "id": name, "bars_ago": 0}


levels = MAX_EXPRESSION_DEPTH - 1
cases = [
    (
        "ordinary-six-variable-rule",
        {
            "op": "greater_than",
            "left": {
                "op": "divide",
                "left": {
                    "op": "multiply",
                    "left": {
                        "op": "add",
                        "left": variable("a"),
                        "right": variable("b"),
                    },
                    "right": {
                        "op": "subtract",
                        "left": variable("c"),
                        "right": variable("d"),
                    },
                },
                "right": {"op": "add", "left": variable("e"), "right": variable("f")},
            },
            "right": {"op": "literal", "value_type": "DECIMAL", "value": "1.5"},
        },
        True,
    )
]
for op in UNARY + BINARY + VARIADIC:
    cases.append(("valid-%s-at-max-depth" % op, chain(op, levels), True))
# Breadth as well as depth. A depth-24 chain is only 47 nodes; an `and` tree at
# the 64-operand bound is 1473, and cost should stay linear in node count
# rather than tracking depth alone.
for breadth in (8, 64):
    wide = dict(LEAF)
    for _ in range(levels):
        wide = {
            "op": "and",
            "operands": [wide] + [dict(LEAF) for _ in range(breadth - 1)],
        }
    cases.append(("valid-and-breadth-%d-at-max-depth" % breadth, wide, True))
cases.append(
    (
        "invalid-deep-arity",
        chain("add", levels, {"op": "add", "left": dict(LEAF)}),
        False,
    )
)
cases.append(
    (
        "invalid-deep-unknown-op",
        chain("crosses_below", levels, {"op": "power", "operand": dict(LEAF)}),
        False,
    )
)
cases.append(
    (
        "invalid-deep-extra-field",
        chain("or", levels, {"op": "ref", "id": "a", "bars_ago": 0, "extra": 1}),
        False,
    )
)
cases.append(
    ("invalid-deep-missing-op", chain("multiply", levels, {"left": dict(LEAF)}), False)
)

results = []
for mode in ("validation", "serialization"):
    emitted = EXPRESSION_ADAPTER.json_schema(mode=mode)
    validator = Draft202012Validator(json.loads(canonical_json_bytes(emitted)))
    for name, document, expected in cases:
        started = time.perf_counter()
        valid = validator.is_valid(document)
        results.append(
            {
                "mode": mode,
                "case": name,
                "expected": expected,
                "valid": valid,
                "seconds": time.perf_counter() - started,
            }
        )
print(json.dumps(results))
"""


@pytest.fixture(scope="module")
def tractability_results() -> list[dict[str, Any]]:
    """Decide the whole depth-bound matrix in one bounded child process.

    One child rather than one per case: a fresh interpreter that imports
    pydantic and builds these models costs more than every measured case put
    together. The ceiling below is a hang detector, not the contract -- the
    contract is the per-case bound asserted by the tests that consume this.
    Post-correction the whole matrix decides in about five seconds; before it,
    a single depth-24 `add` chain did not finish at all.
    """
    command = [sys.executable, "-I", "-B", "-c", _TRACTABILITY_PROBE]
    try:
        completed = subprocess.run(  # noqa: S603 - fixed local interpreter
            command,
            check=False,
            capture_output=True,
            shell=False,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(
            "the published expression schema did not decide the bounded "
            "depth-24 matrix within 120s"
        )
    assert completed.returncode == 0, completed.stderr
    decoded: list[dict[str, Any]] = json.loads(completed.stdout)
    return decoded


def test_the_tractability_matrix_covers_every_recursive_family(
    tractability_results: list[dict[str, Any]],
) -> None:
    cases = {result["case"] for result in tractability_results}
    modes = {result["mode"] for result in tractability_results}

    assert modes == set(_MODES)
    for op in (*_UNARY_OPS, *_BINARY_OPS, *_VARIADIC_OPS):
        assert f"valid-{op}-at-max-depth" in cases, op
    assert "ordinary-six-variable-rule" in cases
    assert "valid-and-breadth-8-at-max-depth" in cases
    assert "valid-and-breadth-64-at-max-depth" in cases
    assert len([case for case in cases if case.startswith("invalid-")]) == 4
    assert len(tractability_results) == len(cases) * 2


def test_every_depth_bound_document_is_decided_within_the_bound(
    tractability_results: list[dict[str, Any]],
) -> None:
    """The structural assertions are the real guard; this is defence in depth.

    Deliberately generous and deliberately not a microbenchmark: the old
    dispatcher exceeded this bound at depth 4, while shallow dispatch decides
    depth 24 in milliseconds, so no plausible machine sits between the two.
    """
    for result in tractability_results:
        assert result["seconds"] < _TRACTABILITY_BOUND_SECONDS, result


def test_every_depth_bound_document_gets_the_right_verdict(
    tractability_results: list[dict[str, Any]],
) -> None:
    for result in tractability_results:
        assert result["valid"] is result["expected"], result
