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
from decimal import Decimal
from typing import Any

import pytest
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
