"""Closed discriminated expression AST for ``expressions/v1``.

Every node is a ``CanonicalModel`` carrying a ``Literal`` ``op`` discriminator,
declared first so canonical serialization is discriminator-first. These shapes
are hash material: ``entry_rules`` and ``exit_rules`` sit inside
``strategy_spec`` in the strategy-version hash payload, so no later task may
change a node's field shape.

The ``literal`` node's ``(value_type, value)`` pair is dispatched explicitly
rather than routed through union validation. A ``STRING`` literal whose text is
``"1"`` would otherwise validate as a canonical decimal under any union mode
that tries decimal first, and a ``DECIMAL`` literal would validate as ``str``
under one that tries ``str`` first -- either way putting the wrong Python type
into a permanent ``content_hash``.

The recursive union's *published* projection is dispatched explicitly too, for
a different reason -- see ``_ConditionalDispatch``. Pydantic's runtime tagged
union is untouched by that; only the emitted JSON Schema changes.
"""

from __future__ import annotations

from copy import deepcopy
from decimal import Decimal
from enum import StrEnum
from typing import Annotated, Any, ClassVar, Final, Literal, Self, get_args

from pydantic import (
    AfterValidator,
    ConfigDict,
    Field,
    GetJsonSchemaHandler,
    PlainSerializer,
    PlainValidator,
    TypeAdapter,
    ValidationInfo,
    field_validator,
    model_validator,
)
from pydantic.json_schema import JsonSchemaValue

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.financial import (
    CANONICAL_DECIMAL_PATTERN,
    MAX_DECIMAL_TEXT_LENGTH,
    format_decimal,
    parse_decimal,
)
from crypto_lab.domain.identifiers import NormalizedIdentifier, exact_string_schema

EXPRESSION_SEMANTICS_VERSION: Final = "expressions/v1"
MAX_EXPRESSION_DEPTH: Final = 24
MAX_EXPRESSION_OPERANDS: Final = 64
MAX_BARS_AGO: Final = 4_096
# Declared locally rather than imported from ``strategy.yaml_source``, so that
# importing a model never pulls PyYAML in transitively. A test pins each against
# its loader counterpart, which is what stops the two copies from drifting.
MAX_LITERAL_STRING_CHARACTERS: Final = 8_192
MIN_LITERAL_INTEGER: Final = -(2**63)
MAX_LITERAL_INTEGER: Final = 2**63 - 1


class LiteralValueType(StrEnum):
    """The closed literal type vocabulary of ``strategy/v1``."""

    BOOLEAN = "BOOLEAN"
    INTEGER = "INTEGER"
    DECIMAL = "DECIMAL"
    STRING = "STRING"
    IDENTIFIER = "IDENTIFIER"


_IDENTIFIER_ADAPTER: Final[TypeAdapter[str]] = TypeAdapter(NormalizedIdentifier)


def _validate_literal_value(
    value: object,
    info: ValidationInfo,
) -> bool | int | Decimal | str:
    """Dispatch on the declared ``value_type`` before any union is tried.

    ``info.data`` holds only the fields validated so far, in declaration order,
    which is why ``value_type`` must precede ``value``. When ``value_type``
    itself failed validation this validator still runs against a partial
    ``info.data``, so a missing key raises rather than escaping as ``KeyError``.
    """
    declared = info.data.get("value_type")
    if not isinstance(declared, LiteralValueType):
        raise ValueError("literal value_type must validate before value")

    if declared is LiteralValueType.BOOLEAN:
        # ``type(...) is`` throughout, never ``isinstance``: ``isinstance(True,
        # int)`` is True, so an isinstance check would admit a bool as an
        # integer and write a JSON ``true`` where an integer belongs.
        if type(value) is not bool:
            raise ValueError("BOOLEAN literal requires an exact bool")
        return value

    if declared is LiteralValueType.INTEGER:
        if type(value) is not int:
            raise ValueError("INTEGER literal requires an exact int")
        if not MIN_LITERAL_INTEGER <= value <= MAX_LITERAL_INTEGER:
            raise ValueError("INTEGER literal is outside the signed 64-bit range")
        return value

    if declared is LiteralValueType.DECIMAL:
        # The same validator ``CanonicalDecimal`` uses, carrying ``info`` so
        # ``info.mode`` is honoured: a real ``Decimal`` in Python mode, an exact
        # canonical string at the JSON boundary.
        return parse_decimal(value, info)

    if declared is LiteralValueType.STRING:
        if type(value) is not str:
            raise ValueError("STRING literal requires an exact str")
        if len(value) > MAX_LITERAL_STRING_CHARACTERS:
            raise ValueError("STRING literal exceeds the maximum length")
        return value

    if type(value) is not str:
        raise ValueError("IDENTIFIER literal requires an exact str")
    return _IDENTIFIER_ADAPTER.validate_python(value)


def _render_literal_value(value: bool | int | Decimal | str) -> bool | int | str:
    """Render a Decimal through the canonical serializer; pass others through."""
    if isinstance(value, Decimal):
        return format_decimal(value)
    return value


type LiteralValue = Annotated[
    bool | int | Decimal | str,
    PlainValidator(_validate_literal_value, json_schema_input_type=bool | int | str),
    # ``when_used="json"`` matches ``CanonicalDecimal``: Python-mode dumps keep
    # the real ``Decimal`` so ``model_validate(model_dump(mode="python"))``
    # round-trips, while JSON-mode dumps carry the canonical string.
    PlainSerializer(
        _render_literal_value,
        return_type=bool | int | str,
        when_used="json",
    ),
]

EXACT_RUNTIME_TYPES: Final[dict[LiteralValueType, type]] = {
    LiteralValueType.BOOLEAN: bool,
    LiteralValueType.INTEGER: int,
    LiteralValueType.DECIMAL: Decimal,
    LiteralValueType.STRING: str,
    LiteralValueType.IDENTIFIER: str,
}


# Derived from the type itself rather than restated, so the conditional branch
# cannot drift from the runtime constraint and no hash-material pattern is
# written down twice. ``NormalizedIdentifier`` emits an inline string schema at
# an adapter root; if a future Pydantic emitted a ``$ref`` here instead, the
# reference would be unresolvable inside the literal node's schema and the
# schema-agreement tests would fail rather than silently weakening the contract.
_IDENTIFIER_SCHEMA: Final[JsonSchemaValue] = dict(_IDENTIFIER_ADAPTER.json_schema())

_LITERAL_VALUE_BRANCHES: Final[dict[LiteralValueType, JsonSchemaValue]] = {
    LiteralValueType.BOOLEAN: {"type": "boolean"},
    LiteralValueType.INTEGER: {
        "type": "integer",
        "minimum": MIN_LITERAL_INTEGER,
        "maximum": MAX_LITERAL_INTEGER,
    },
    LiteralValueType.DECIMAL: exact_string_schema(
        CANONICAL_DECIMAL_PATTERN,
        max_length=MAX_DECIMAL_TEXT_LENGTH,
    ),
    LiteralValueType.STRING: {
        "type": "string",
        "maxLength": MAX_LITERAL_STRING_CHARACTERS,
    },
    LiteralValueType.IDENTIFIER: _IDENTIFIER_SCHEMA,
}


def literal_value_branches() -> dict[LiteralValueType, JsonSchemaValue]:
    """Return the exact per-``value_type`` value schema, as an independent copy.

    Exposed so ``strategy/models.py`` can publish ``ParameterDefinition``'s
    identical dispatch from this one table instead of restating it. The comment on
    ``ParameterDefinition.validate_bounds`` already calls that rule "the same
    exact-identity invariant ``LiteralExpression`` carries", so two copies would
    be two statements of one contract -- and the drift would be invisible, because
    each node would still validate its own documents correctly while disagreeing
    with the other.

    Copied rather than shared: the returned mapping is merged into a generated
    schema, and handing out the module's own objects would let a caller that
    mutates its schema in place reach ``LiteralExpression``'s published node.
    """
    return {
        member: deepcopy(branch) for member, branch in _LITERAL_VALUE_BRANCHES.items()
    }


def _literal_schema_extra(schema: JsonSchemaValue) -> None:
    """Bind each ``value_type`` to its exact ``value`` schema.

    Pydantic emits an unconstrained scalar union on its own, and specification
    section 12.4 makes the generated schema the normative union definition, so
    without this the published contract would be weaker than the runtime one.
    """
    schema["allOf"] = [
        {
            "if": {
                "properties": {"value_type": {"const": member.value}},
                "required": ["value_type"],
            },
            "then": {"properties": {"value": branch}},
        }
        for member, branch in _LITERAL_VALUE_BRANCHES.items()
    ]


class LiteralExpression(CanonicalModel):
    """A typed constant. ``value_type`` precedes ``value`` by contract."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_literal_schema_extra
    )

    op: Literal["literal"]
    value_type: LiteralValueType
    value: LiteralValue

    @model_validator(mode="after")
    def validate_value_matches_its_declared_type(self) -> Self:
        """Re-check the stored runtime type against ``value_type``.

        Reachable, not decorative: ``parse_decimal`` admits any ``Decimal``
        instance, so a ``Decimal`` subclass -- whose ``__str__`` or
        ``__format__`` could differ -- passes the dispatcher and is stopped only
        here. The comparison is exact identity, so no ordering between ``bool``
        and ``int`` is required.
        """
        if type(self.value) is not EXACT_RUNTIME_TYPES[self.value_type]:
            raise ValueError("literal value type disagrees with value_type")
        return self


class RefExpression(CanonicalModel):
    """A declared parameter, source field, or feature ID at a bar offset."""

    op: Literal["ref"]
    id: NormalizedIdentifier
    bars_ago: Annotated[
        int,
        Field(
            strict=True,
            le=MAX_BARS_AGO,
            # The lower bound restated for the generated schema. `le` renders
            # `maximum`, but the non-negativity below lives in a
            # `field_validator`, which `Field` never renders -- so the published
            # schema accepted `bars_ago: -1` that ordinary validated
            # construction rejects, in three of the nine Task 8 schemas
            # (`expression-v1` directly, `strategy-spec-v1` and
            # `strategy-version-v1` through `$defs`).
            #
            # Deliberately `json_schema_extra` rather than `ge=0`. A `ge`
            # constraint is enforced by pydantic-core *before* the field
            # validator runs, so a negative offset would surface as a generic
            # `greater_than_equal` error and never reach the line below --
            # silently replacing the `STRATEGY.REFERENCE_NEGATIVE_OFFSET`
            # diagnostic that plan Task 3 step 3 depends on this node emitting.
            # This form publishes the identical constraint while leaving runtime
            # error semantics byte-for-byte unchanged; a test pins the error's
            # pydantic `type` as `value_error` so the shortcut cannot be
            # reintroduced unnoticed.
            json_schema_extra={"minimum": 0},
        ),
    ]

    @field_validator("bars_ago")
    @classmethod
    def validate_offset_is_not_negative(cls, value: int) -> int:
        """Emit the closed error code Task 3 relies on Task 2 emitting here."""
        if value < 0:
            raise ValueError(
                "STRATEGY.REFERENCE_NEGATIVE_OFFSET: bars_ago must be non-negative"
            )
        return value


class NotExpression(CanonicalModel):
    op: Literal["not"]
    operand: Expression


class NegateExpression(CanonicalModel):
    op: Literal["negate"]
    operand: Expression


class IsMissingExpression(CanonicalModel):
    op: Literal["is_missing"]
    operand: Expression


class AddExpression(CanonicalModel):
    op: Literal["add"]
    left: Expression
    right: Expression


class SubtractExpression(CanonicalModel):
    op: Literal["subtract"]
    left: Expression
    right: Expression


class MultiplyExpression(CanonicalModel):
    op: Literal["multiply"]
    left: Expression
    right: Expression


class DivideExpression(CanonicalModel):
    op: Literal["divide"]
    left: Expression
    right: Expression


class MinimumExpression(CanonicalModel):
    op: Literal["minimum"]
    left: Expression
    right: Expression


class MaximumExpression(CanonicalModel):
    op: Literal["maximum"]
    left: Expression
    right: Expression


class EqualExpression(CanonicalModel):
    op: Literal["equal"]
    left: Expression
    right: Expression


class NotEqualExpression(CanonicalModel):
    op: Literal["not_equal"]
    left: Expression
    right: Expression


class LessThanExpression(CanonicalModel):
    op: Literal["less_than"]
    left: Expression
    right: Expression


class LessThanOrEqualExpression(CanonicalModel):
    op: Literal["less_than_or_equal"]
    left: Expression
    right: Expression


class GreaterThanExpression(CanonicalModel):
    op: Literal["greater_than"]
    left: Expression
    right: Expression


class GreaterThanOrEqualExpression(CanonicalModel):
    op: Literal["greater_than_or_equal"]
    left: Expression
    right: Expression


class CrossesAboveExpression(CanonicalModel):
    op: Literal["crosses_above"]
    left: Expression
    right: Expression


class CrossesBelowExpression(CanonicalModel):
    op: Literal["crosses_below"]
    left: Expression
    right: Expression


class AndExpression(CanonicalModel):
    """Order is preserved: rule evaluation order carries semantics."""

    op: Literal["and"]
    operands: tuple[Expression, ...] = Field(
        min_length=1, max_length=MAX_EXPRESSION_OPERANDS
    )


class OrExpression(CanonicalModel):
    op: Literal["or"]
    operands: tuple[Expression, ...] = Field(
        min_length=1, max_length=MAX_EXPRESSION_OPERANDS
    )


def _child_expressions(node: CanonicalModel) -> tuple[CanonicalModel, ...]:
    children: list[CanonicalModel] = []
    for name in type(node).model_fields:
        attribute = getattr(node, name)
        if isinstance(attribute, CanonicalModel):
            children.append(attribute)
        elif isinstance(attribute, tuple):
            children.extend(
                item for item in attribute if isinstance(item, CanonicalModel)
            )
    return tuple(children)


def _bound_expression_depth[NodeT: CanonicalModel](node: NodeT) -> NodeT:
    """Bound tree depth without Python recursion, so no ``RecursionError``."""
    pending: list[tuple[CanonicalModel, int]] = [(node, 1)]
    while pending:
        current, level = pending.pop()
        if level > MAX_EXPRESSION_DEPTH:
            raise ValueError(
                "STRATEGY.EXPRESSION_DEPTH_EXCEEDED: expression nesting "
                "exceeds the maximum depth"
            )
        pending.extend((child, level + 1) for child in _child_expressions(current))
    return node


def _operation_of(model: type[CanonicalModel]) -> str:
    """Read a node's ``op`` constant off its own ``Literal`` annotation.

    ``model_fields.get`` rather than indexing, so a node added without an ``op``
    field fails with this function's own message instead of a bare ``KeyError``.
    """
    field = model.model_fields.get("op")
    arguments = get_args(field.annotation) if field is not None else ()
    if len(arguments) != 1 or type(arguments[0]) is not str:
        raise TypeError(f"{model.__name__} must declare exactly one Literal op")
    return arguments[0]


class _ConditionalDispatch:
    """Publish the recursive union as shallow ``if``/``then`` dispatch on ``op``.

    Pydantic emits a tagged union as a 21-member ``oneOf`` beside an OpenAPI
    ``discriminator``. ``discriminator`` is not a Draft 2020-12 keyword, so a
    conformant validator ignores it and must evaluate the alternatives to decide
    ``oneOf``'s exactly-one rule -- and fourteen of the twenty-one branches share
    the recursive ``left``/``right`` shape, so a *rejected* alternative still
    descends into the shared children before it can fail. Two independent
    mechanisms make that exponential, and they govern different documents:

    * Alternatives *before* the matching one are evaluated with ``iter_errors``,
      which collects every error and therefore cannot short-circuit. Any
      operator with earlier same-shape branches pays this whatever the key
      order: ``crosses_below`` chains cost 0.64 s, 5.7 s, and over 20 s at
      depths 3, 4, and 5 even against the unsorted emitted dict.
    * Alternatives *after* it are scanned with short-circuiting ``is_valid``,
      which is cheap only when ``op`` is reached before a recursive property.
      The published bytes come from ``canonical_json_bytes``, which sorts keys
      and so orders ``left`` ahead of ``op`` -- making that scan recurse too.
      This is what catches ``add``, the first binary branch and the one operator
      with no earlier same-shape alternative: 0.18 s at depth 3 and 2.6 s at
      depth 4 against the published bytes, against 0.007 s unsorted.

    ``MAX_EXPRESSION_DEPTH`` permits depth 24, which the published bytes cannot
    decide at all, and an ordinary six-operator rule -- ``((a+b)*(c-d))/(e+f) >
    1.5``, 250 bytes, nesting depth 5 -- takes 45 s. Specification section 12.4
    makes the generated schema the normative union definition, so a projection a
    consumer cannot evaluate does not discharge that role, and publishing it
    invites a denial of service against anyone validating untrusted strategy
    input against ``schemas/``, which ships in the wheel and the sdist.

    The replacement publishes the identical closed contract: ``op`` is required
    and drawn from the exact twenty-one operations, and each operation carries
    one shallow condition selecting one branch. At most one condition can match,
    only the matching ``then`` recurses, and no alternative ever visits a child
    expression, so cost is linear in the document. Accept set, runtime tagged
    union, and every canonical byte are unchanged.

    Linear is not free: the measured constant is roughly 12 microseconds per
    byte, so the exposure is reduced by about three orders of magnitude rather
    than removed, and an external consumer of ``schemas/`` should still cap
    input size. The in-project path is already capped -- ``yaml_source``'s
    ``MAX_SOURCE_BYTES`` rejects a source over 262,144 bytes before any model
    sees it.

    ``additionalProperties`` is deliberately absent from the root: each branch
    model already carries its own ``extra="forbid"`` closure, and closing the
    root would reject the ``left``, ``right``, ``operand``, and ``operands``
    fields the root itself does not enumerate. Unknown operations are stopped by
    the exact root ``enum`` and missing ones by the exact root ``required``.

    The table is derived, never restated: operations come from each node model's
    own ``Literal``, and the branch references are the ones pydantic just
    emitted. Reusing the emitted strings matters -- at hook time they are
    internal defs-refs that pydantic remaps and garbage-collects afterwards, so a
    hand-built ``#/$defs/...`` would dangle and its branch would be collected
    away. ``discriminator`` is retained verbatim as a tooling annotation; nothing
    about validation or tractability depends on it.
    """

    def __get_pydantic_json_schema__(
        self,
        # `Any` rather than `pydantic_core.CoreSchema`: `pydantic_core` is not
        # one of the roots `test_stage3_boundaries` admits, and re-importing the
        # name through `pydantic.json_schema` is an implicit re-export that
        # strict mypy rejects. The value is passed straight to `handler`.
        core_schema: Any,
        handler: GetJsonSchemaHandler,
    ) -> JsonSchemaValue:
        emitted = handler(core_schema)
        # Replacing a schema means discarding whatever the handler produced, so
        # the shape being discarded is pinned first. Without this, a future
        # pydantic that added a sibling keyword at the union node, or a
        # constraint alongside a branch ``$ref`` -- which Draft 2020-12 does
        # apply -- would have it silently dropped from a normative contract.
        if (
            set(emitted) != {"oneOf", "discriminator"}
            or emitted["discriminator"].get("propertyName") != "op"
            or any(set(branch) != {"$ref"} for branch in emitted["oneOf"])
        ):
            raise RuntimeError("the emitted expression union is not a bare oneOf")
        mapping = emitted["discriminator"]["mapping"]
        branches = [branch["$ref"] for branch in emitted["oneOf"]]
        operations = [_operation_of(model) for model in _NODE_MODELS]
        if len(set(operations)) != len(operations) or set(operations) != set(mapping):
            raise RuntimeError("expression operations must map one to one onto ops")
        references = [mapping[operation] for operation in operations]
        if (
            len(references) != len(branches)
            or len(set(references)) != len(references)
            or set(references) != set(branches)
        ):
            raise RuntimeError("expression branches must map one to one onto models")
        return {
            "type": "object",
            "required": ["op"],
            "properties": {"op": {"enum": operations}},
            "allOf": [
                {
                    "if": {
                        "properties": {"op": {"const": operation}},
                        "required": ["op"],
                    },
                    "then": {"$ref": reference},
                }
                for operation, reference in zip(operations, references, strict=True)
            ],
            "discriminator": emitted["discriminator"],
        }


type ExpressionNode = (
    LiteralExpression
    | RefExpression
    | NotExpression
    | NegateExpression
    | IsMissingExpression
    | AddExpression
    | SubtractExpression
    | MultiplyExpression
    | DivideExpression
    | MinimumExpression
    | MaximumExpression
    | EqualExpression
    | NotEqualExpression
    | LessThanExpression
    | LessThanOrEqualExpression
    | GreaterThanExpression
    | GreaterThanOrEqualExpression
    | CrossesAboveExpression
    | CrossesBelowExpression
    | AndExpression
    | OrExpression
)
type Expression = Annotated[
    ExpressionNode,
    Field(discriminator="op"),
    AfterValidator(_bound_expression_depth),
    # JSON-schema metadata only. It carries no ``__get_pydantic_core_schema__``,
    # so the validator, the serializer, and every runtime diagnostic are the
    # ones the three annotations above already define.
    _ConditionalDispatch(),
]

_NODE_MODELS: Final = (
    LiteralExpression,
    RefExpression,
    NotExpression,
    NegateExpression,
    IsMissingExpression,
    AddExpression,
    SubtractExpression,
    MultiplyExpression,
    DivideExpression,
    MinimumExpression,
    MaximumExpression,
    EqualExpression,
    NotEqualExpression,
    LessThanExpression,
    LessThanOrEqualExpression,
    GreaterThanExpression,
    GreaterThanOrEqualExpression,
    CrossesAboveExpression,
    CrossesBelowExpression,
    AndExpression,
    OrExpression,
)

for _model in _NODE_MODELS:
    _model.model_rebuild()

EXPRESSION_ADAPTER: TypeAdapter[Expression] = TypeAdapter(Expression)
