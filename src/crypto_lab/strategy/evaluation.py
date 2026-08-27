"""Deterministic fixture-sized Level 1 reference evaluator.

Plan section 5.6 fixes what this is and is not. It is pure, deterministic,
fixture-sized, offline, engine-neutral, Decimal-aware, and explicit about missing
values and warm-up. It is **not** an order simulator, fill simulator, portfolio
simulator, or backtesting engine: it produces no order, fill, position, cash
balance, fee, slippage, or return. It takes an explicit in-memory bar series and
returns complete feature and signal series.

It reads no wall clock, filesystem, network, environment variable, subprocess,
engine, or random source. `observed_at_utc` is an explicit parameter, exactly as
plan section 5.3.3 requires.

**The MISSING contract.** A bar at which a feature has no computed value carries
`MISSING_VALUE`, which is `None` and serializes as JSON `null`. That is
deliberately **not** `pydantic.experimental.missing_sentinel.MISSING`, which marks
an absent model *field*; this marks a present field with no value *at one bar*. No
`LiteralValue` is ever `None`, so `null` is unambiguous.

**Decimal isolation.** Every arithmetic step runs inside
`decimal.localcontext(EVALUATION_CONTEXT)`, so the process-global context is read
but never mutated and is restored on both the normal and the exceptional path. The
local variable is named `arithmetic` rather than the obvious word because
`tests/safety/test_stage4_boundaries.py` forbids the bare name `context` anywhere
under `src/crypto_lab`, so that `yaml.YAMLError.context` can never reach a
diagnostic.
"""

from __future__ import annotations

import decimal
from datetime import datetime
from decimal import Decimal
from typing import Final, cast

from pydantic import Field, JsonValue

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.diagnostics import (
    Diagnostic,
    DiagnosticCategory,
    DiagnosticDetailValue,
    DiagnosticSeverity,
)
from crypto_lab.domain.financial import (
    MAX_DECIMAL_TEXT_LENGTH,
    CanonicalDecimal,
    NonNegativeDecimal,
    format_decimal,
)
from crypto_lab.domain.hashing import HashingProfile, _uuid4_shaped, profile_hash
from crypto_lab.domain.identifiers import NormalizedIdentifier
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.domain.time import UtcDateTime
from crypto_lab.strategy.expressions import (
    AndExpression,
    CrossesAboveExpression,
    CrossesBelowExpression,
    DivideExpression,
    ExpressionNode,
    IsMissingExpression,
    LiteralExpression,
    LiteralValueType,
    NegateExpression,
    NotExpression,
    OrExpression,
    RefExpression,
)
from crypto_lab.strategy.feature_graph import (
    FEATURE_OPERATIONS,
    FeatureGraph,
    _canonical_definitions,
)
from crypto_lab.strategy.models import (
    MAX_FEATURES,
    MAX_RULES,
    FeatureDefinition,
    MissingValuePolicy,
    RuleDefinition,
    StrategySpec,
)

MAX_EVALUATION_BARS: Final = 4_096
EVALUATION_PRECISION: Final = 34
EVALUATION_CONTEXT: Final = decimal.Context(
    prec=EVALUATION_PRECISION,
    rounding=decimal.ROUND_HALF_EVEN,
)

# The evaluator's explicit MISSING marker. See the module docstring for why this
# is not Pydantic's field-absence sentinel.
MISSING_VALUE: Final[None] = None

SOURCE_COMPONENT: Final = "strategy.evaluation"

_SERIES_TOO_LONG: Final = "STRATEGY.EVALUATION_SERIES_TOO_LONG"
_DIVIDE_BY_ZERO: Final = "STRATEGY.EVALUATION_DIVIDE_BY_ZERO"
_NON_FINITE: Final = "STRATEGY.EVALUATION_NON_FINITE"
_MISSING_INPUT: Final = "STRATEGY.EVALUATION_MISSING_INPUT"
_DECIMAL_TOO_LONG: Final = "STRATEGY.EVALUATION_DECIMAL_TOO_LONG"

#: The exact message `format_decimal` raises for the canonical length bound.
#: Plan section 5.9.1 maps this one message and no other: a broad
#: `except ValueError` would convert real defects into diagnostics, which is
#: what the `Result`-only contract exists to prevent. A committed test pins
#: this string against `crypto_lab.domain.financial`, so a reword there fails
#: loudly instead of silently restoring the escaping `ValueError`.
_DECIMAL_LENGTH_MESSAGE: Final = "canonical decimal exceeds maximum length"

_MESSAGES: Final[dict[str, str]] = {
    _SERIES_TOO_LONG: "strategy evaluation bar series exceeds the maximum length",
    _DIVIDE_BY_ZERO: "strategy evaluation divided by zero",
    _NON_FINITE: "strategy evaluation produced a non-finite intermediate value",
    _MISSING_INPUT: (
        "strategy evaluation encountered a missing input under a dataset-rejecting "
        "missing-value policy"
    ),
    _DECIMAL_TOO_LONG: (
        "strategy evaluation produced a feature value whose canonical rendering "
        "exceeds the maximum decimal text length"
    ),
}

# A feature cell is a canonical string for a DECIMAL or STRING value, or
# ``MISSING_VALUE``. No feature operation yields a boolean, so no boolean cell
# exists; a signal cell is a plain ``bool`` because a rule containing MISSING is
# false rather than missing.
type FeatureCell = str | None
# An in-flight value before rendering. ``str`` carries a STRING feature such as
# ``bar.timestamp_utc``; ``bool`` carries a comparison result inside a rule.
type Value = Decimal | str | bool | None


class Bar(CanonicalModel):
    """One fully closed OHLCV bar. Every price is canonical `Decimal`."""

    timestamp_utc: UtcDateTime
    open: CanonicalDecimal
    high: CanonicalDecimal
    low: CanonicalDecimal
    close: CanonicalDecimal
    volume: NonNegativeDecimal


class FeatureSeries(CanonicalModel):
    """One feature's complete value series, one cell per input bar."""

    feature_id: NormalizedIdentifier
    values: tuple[FeatureCell, ...] = Field(max_length=MAX_EVALUATION_BARS)


class SignalSeries(CanonicalModel):
    """One rule's complete boolean series, one cell per input bar."""

    rule_id: NormalizedIdentifier
    values: tuple[bool, ...] = Field(max_length=MAX_EVALUATION_BARS)


class EvaluationResult(CanonicalModel):
    """Complete feature and signal series for one accepted bounded input."""

    bar_count: int = Field(strict=True, ge=0, le=MAX_EVALUATION_BARS)
    features: tuple[FeatureSeries, ...] = Field(max_length=MAX_FEATURES)
    entry_signals: tuple[SignalSeries, ...] = Field(max_length=MAX_RULES)
    exit_signals: tuple[SignalSeries, ...] = Field(max_length=MAX_RULES)
    skipped_bars: tuple[bool, ...] = Field(max_length=MAX_EVALUATION_BARS)


class _Rejected(Exception):
    """Internal signal carrying one error code out of a nested computation.

    It never escapes `evaluate_level_one`, which converts it to a `Result`
    failure. The `Result`-only contract of plan section 5.2 holds at the public
    boundary.
    """

    def __init__(self, code: str, details: dict[str, DiagnosticDetailValue]) -> None:
        super().__init__(code)
        self.code = code
        self.details = details


def _render_timestamp(moment: datetime) -> str:
    """Render a UTC instant as a canonical `Z`-suffixed string."""
    return moment.isoformat().replace("+00:00", "Z")


def _unsigned_zero(value: Decimal) -> Decimal:
    """Normalize a negative zero, which `format_decimal` refuses to render.

    **Defensive at the feature boundary, and deliberately kept.** No feature
    operation can produce `Decimal("-0")`: the allowlist contains no negation,
    `rolling.sum` accumulates from `Decimal(0)` so an exactly-cancelling window
    yields `+0`, dividing `+0` yields `+0`, `min` and `max` can only return an
    input, and a canonical bar field can never be `-0` because `format_decimal`
    refuses to render one. Expression-level `negate` of zero does produce `-0`, but
    an expression result only ever feeds a comparison, where `-0` and `+0` compare
    identically, so it is never serialized either.

    It is retained because it guards the one boundary where a signed zero would
    raise `ValueError` out of the `Result`-only contract rather than fail a
    comparison, and because a later operation added to the allowlist would
    otherwise reintroduce the hazard silently.
    """
    return Decimal(0) if value.is_zero() else value


def _checked(value: Decimal) -> Decimal:
    """Reject a non-finite intermediate rather than propagating it."""
    if not value.is_finite():
        raise _Rejected(_NON_FINITE, {})
    return _unsigned_zero(value)


def _bar_field(bar: Bar, name: str) -> Value:
    """Read one reserved bar field. Closed `if` chain, never `getattr`."""
    if name == "bar.open":
        return bar.open
    if name == "bar.high":
        return bar.high
    if name == "bar.low":
        return bar.low
    if name == "bar.close":
        return bar.close
    if name == "bar.volume":
        return bar.volume
    return _render_timestamp(bar.timestamp_utc)


def _numeric(value: Value) -> Decimal | None:
    """Narrow a value to a Decimal, treating a boolean as non-numeric.

    `type(...) is` throughout rather than `isinstance`, because
    `isinstance(True, int)` is true and a boolean must never enter arithmetic.
    """
    if type(value) is Decimal:
        return value
    return None


def _window_values(
    series: list[Value],
    index: int,
    window: int,
) -> list[Value] | None:
    """Return the last `window` cells ending at `index`, or None if pre-history."""
    start = index - window + 1
    if start < 0:
        return None
    return series[start : index + 1]


class _FeatureState:
    """One feature's declaration, resolved parameters, and computed series."""

    __slots__ = ("definition", "series", "window")

    def __init__(self, definition: FeatureDefinition, window: int | None) -> None:
        self.definition = definition
        self.window = window
        self.series: list[Value] = []


def _resolved_window(spec: StrategySpec, definition: FeatureDefinition) -> int | None:
    """Resolve a feature's single integer operation parameter, if it has one."""
    signature = FEATURE_OPERATIONS[definition.operation]
    if not signature.required_parameters:
        return None
    name = signature.required_parameters[0]
    parameter = spec.parameters[definition.parameters[name]]
    return cast("int", parameter.value)


def _source_series(
    definition: FeatureDefinition,
    lookup: dict[str, list[Value]],
    bars: tuple[Bar, ...],
) -> list[Value]:
    """Resolve a feature's single input to a complete series, once per feature.

    Hoisted out of the per-bar computation deliberately. Building a bar-field
    series inside the bar loop would cost work quadratic in the bar count for every
    feature reading a bar field, which at ``MAX_EVALUATION_BARS`` and
    ``MAX_FEATURES`` is billions of reads for an input well inside every declared
    bound. The result is identical either way, because neither ``bars`` nor an
    already-computed feature series changes while a feature is being evaluated.
    """
    if definition.operation == "source.bar_field/v1":
        # Reads its bar directly at each index, so it needs no input series and
        # building one would be pure waste.
        return []
    source = definition.inputs[0]
    if source in lookup:
        return lookup[source]
    return [_bar_field(bar, source) for bar in bars]


def _feature_value(
    state: _FeatureState,
    index: int,
    series: list[Value],
    bars: tuple[Bar, ...],
) -> Value:
    """Compute one feature's value at one bar, or `MISSING_VALUE`.

    `series` is the feature's single input resolved over every bar, supplied by
    the caller so it is built once per feature rather than once per bar.

    Warm-up is evaluated first and unconditionally: plan Task 4 semantics make a
    feature's value MISSING for every bar before its declared warm-up completes,
    so bars `0` through `warm_up_bars - 1` are MISSING and bar `warm_up_bars` is
    the first that can carry a value. That boundary is the whole content of the
    `warm_up_boundary` fixture.
    """
    definition = state.definition
    if index < definition.warm_up_bars:
        return MISSING_VALUE

    operation = definition.operation
    if operation == "source.bar_field/v1":
        return _bar_field(bars[index], definition.inputs[0])

    if operation == "expression.project/v1":
        return series[index]
    if operation == "shift/v1":
        # ``shift/v1`` declares the required parameter ``bars``, so
        # ``_resolved_window`` returned an ``int``. Narrowed by the signature
        # rather than by a runtime check, which would be an unreachable branch.
        origin = index - cast("int", state.window)
        return series[origin] if origin >= 0 else MISSING_VALUE

    # Every operation still reachable here declares a window-sized parameter, so
    # its resolved window is an ``int`` for the same reason.
    window = cast("int", state.window)
    cells = _window_values(series, index, window)
    if cells is None:
        return MISSING_VALUE
    numbers: list[Decimal] = []
    for cell in cells:
        number = _numeric(cell)
        if number is None:
            return MISSING_VALUE
        numbers.append(number)

    if operation == "rolling.sum/v1":
        return _checked(sum(numbers, Decimal(0)))
    if operation in {"rolling.mean/v1", "indicator.sma/v1"}:
        return _checked(sum(numbers, Decimal(0)) / Decimal(len(numbers)))
    if operation == "rolling.min/v1":
        return _checked(min(numbers))
    return _checked(max(numbers))


def _render(value: Value, feature_id: str) -> FeatureCell:
    """Render one computed feature value as its canonical JSON cell.

    A value can be finite, inside `EVALUATION_PRECISION`, and correctly
    computed, and still exceed `MAX_DECIMAL_TEXT_LENGTH` once rendered: 34
    significant digits at a sufficiently negative exponent need 257 characters.
    That is a rejection, not a defect, so it becomes `_Rejected` here and a
    diagnostic at the boundary. Every other `ValueError` propagates unchanged.
    """
    if value is MISSING_VALUE:
        return MISSING_VALUE
    if type(value) is Decimal:
        try:
            return format_decimal(value)
        except ValueError as error:
            if str(error) != _DECIMAL_LENGTH_MESSAGE:
                raise
            raise _Rejected(
                _DECIMAL_TOO_LONG,
                {
                    "feature_id": feature_id,
                    "maximum_text_length": MAX_DECIMAL_TEXT_LENGTH,
                },
            ) from error
    return cast("str", value)


def _reference_value(
    node: RefExpression,
    index: int,
    lookup: dict[str, list[Value]],
    bars: tuple[Bar, ...],
    constants: dict[str, Value],
) -> Value:
    """Resolve one reference at an explicit non-negative bar offset.

    Precedence matches Task 3's static scope exactly: source bar field, then
    declared feature, then declared parameter. A parameter is constant and carries
    no bar dimension, so its offset is honoured only as a pre-history bound.
    """
    origin = index - node.bars_ago
    if origin < 0:
        return MISSING_VALUE
    if node.id in {
        "bar.open",
        "bar.high",
        "bar.low",
        "bar.close",
        "bar.volume",
        "bar.timestamp_utc",
    }:
        return _bar_field(bars[origin], node.id)
    if node.id in lookup:
        return lookup[node.id][origin]
    return constants[node.id]


def _arithmetic(operation: str, left: Decimal, right: Decimal) -> Decimal:
    """Apply one binary arithmetic operator inside the caller's Decimal context.

    **Precondition:** the caller has already rejected a zero divisor, so the
    divide-by-zero raise below is unreachable from `_evaluate_node`, which is this
    function's only caller. It is retained rather than deleted because the
    precondition lives in the caller and nothing in the type system enforces it, so
    a second caller added later would otherwise divide by zero silently.
    """
    if operation == "add":
        return _checked(left + right)
    if operation == "subtract":
        return _checked(left - right)
    if operation == "multiply":
        return _checked(left * right)
    if operation == "minimum":
        return _checked(min(left, right))
    if operation == "maximum":
        return _checked(max(left, right))
    if right.is_zero():
        raise _Rejected(_DIVIDE_BY_ZERO, {"operator": operation})
    return _checked(left / right)


def _compare(operation: str, left: Value, right: Value) -> bool | None:
    """Apply one comparison, returning None when either side is missing."""
    if operation in {"equal", "not_equal"}:
        if left is MISSING_VALUE or right is MISSING_VALUE:
            return None
        # Kind as well as value, so a boolean never equals a numeric one: Python
        # would say `Decimal(1) == True`. When both sides are already the same
        # type the kind test is redundant, so no separate Decimal case is needed.
        equal = left == right and type(left) is type(right)
        return equal if operation == "equal" else not equal
    first = _numeric(left)
    second = _numeric(right)
    if first is None or second is None:
        return None
    if operation == "less_than":
        return first < second
    if operation == "less_than_or_equal":
        return first <= second
    if operation == "greater_than":
        return first > second
    return first >= second


def _crossover(
    operation: str,
    left_now: Value,
    right_now: Value,
    left_prior: Value,
    right_prior: Value,
) -> bool | None:
    """Specification line 699's exact crossover boundary.

    At bar `t`, `crosses_above(left, right)` is true exactly when both series are
    present at `t` and `t-1`, `left[t] > right[t]`, and `left[t-1] <= right[t-1]`.
    The prior-bar inequality is deliberately **non-strict**, which is the equality
    edge the `crossover_equality` fixture isolates. `crosses_below` inverts both.

    All four operands are resolved by the caller. This function performs no bar
    arithmetic of its own, which is why it takes neither the node, the bar index,
    nor an evaluation callback: a signature offering any of those would suggest it
    resolves its own offsets.
    """
    now_left = _numeric(left_now)
    now_right = _numeric(right_now)
    prior_left = _numeric(left_prior)
    prior_right = _numeric(right_prior)
    if (
        now_left is None
        or now_right is None
        or prior_left is None
        or prior_right is None
    ):
        return None
    if operation == "crosses_above":
        return now_left > now_right and prior_left <= prior_right
    return now_left < now_right and prior_left >= prior_right


def _evaluate_node(
    node: ExpressionNode,
    index: int,
    lookup: dict[str, list[Value]],
    bars: tuple[Bar, ...],
    constants: dict[str, Value],
) -> Value:
    """Evaluate one expression node at one bar.

    Recursive over a tree whose depth `MAX_EXPRESSION_DEPTH` bounds at 24, so no
    `RecursionError` is reachable. MISSING propagates through every operator
    except `is_missing`, which is the probe for it.
    """

    def child(operand: ExpressionNode, at: int) -> Value:
        return _evaluate_node(operand, at, lookup, bars, constants)

    if isinstance(node, LiteralExpression):
        if node.value_type is LiteralValueType.INTEGER:
            return Decimal(cast("int", node.value))
        return cast("Value", node.value)
    if isinstance(node, RefExpression):
        return _reference_value(node, index, lookup, bars, constants)
    if isinstance(node, IsMissingExpression):
        return child(node.operand, index) is MISSING_VALUE
    if isinstance(node, NotExpression):
        operand = child(node.operand, index)
        return MISSING_VALUE if type(operand) is not bool else not operand
    if isinstance(node, NegateExpression):
        number = _numeric(child(node.operand, index))
        return MISSING_VALUE if number is None else _checked(-number)
    if isinstance(node, AndExpression | OrExpression):
        # Complete rather than short-circuiting, so a missing operand is never
        # hidden by an earlier decisive one and the result is a pure function of
        # every operand.
        values = [child(operand, index) for operand in node.operands]
        if any(type(value) is not bool for value in values):
            return MISSING_VALUE
        flags = [cast("bool", value) for value in values]
        return all(flags) if isinstance(node, AndExpression) else any(flags)
    if isinstance(node, CrossesAboveExpression | CrossesBelowExpression):
        if index == 0:
            return MISSING_VALUE
        return _crossover(
            node.op,
            child(node.left, index),
            child(node.right, index),
            child(node.left, index - 1),
            child(node.right, index - 1),
        )
    left = child(node.left, index)
    right = child(node.right, index)
    if node.op in {
        "equal",
        "not_equal",
        "less_than",
        "less_than_or_equal",
        "greater_than",
        "greater_than_or_equal",
    }:
        return _compare(node.op, left, right)
    first = _numeric(left)
    second = _numeric(right)
    if first is None or second is None:
        return MISSING_VALUE
    if isinstance(node, DivideExpression) and second.is_zero():
        raise _Rejected(_DIVIDE_BY_ZERO, {"operator": node.op})
    return _arithmetic(node.op, first, second)


def _diagnostic(
    code: str,
    details: dict[str, DiagnosticDetailValue],
    observed_at_utc: datetime,
) -> Diagnostic:
    """Derive one diagnostic from material content only, per section 5.3.3."""
    message = _MESSAGES[code]
    payload: dict[str, JsonValue] = {
        "schema_version": "1.0.0",
        "error_code": code,
        "category": DiagnosticCategory.SCHEMA_VALIDATION.value,
        "severity": DiagnosticSeverity.ERROR.value,
        "source_component": SOURCE_COMPONENT,
        "message": message,
        "retriable": False,
        "details": cast("JsonValue", details),
    }
    identity = _uuid4_shaped(
        profile_hash(HashingProfile.DIAGNOSTIC_IDENTITY_V1, payload),
    )
    return Diagnostic(
        schema_version="1.0.0",
        diagnostic_id=f"diag_{identity}",
        severity=DiagnosticSeverity.ERROR,
        error_code=code,
        category=DiagnosticCategory.SCHEMA_VALIDATION,
        message=message,
        source_component=SOURCE_COMPONENT,
        retriable=False,
        timestamp_utc=observed_at_utc,
        details=details,
        causal_diagnostic_ids=(),
    )


def _constant_values(spec: StrategySpec) -> dict[str, Value]:
    """Every declared parameter as a bar-independent constant value."""
    constants: dict[str, Value] = {}
    for name, definition in spec.parameters.items():
        if definition.value_type is LiteralValueType.INTEGER:
            constants[name] = Decimal(cast("int", definition.value))
        else:
            constants[name] = cast("Value", definition.value)
    return constants


def _compute(
    spec: StrategySpec,
    graph: FeatureGraph,
    bars: tuple[Bar, ...],
) -> tuple[
    dict[str, list[Value]],
    list[bool],
    tuple[tuple[str, list[bool]], ...],
    tuple[tuple[str, list[bool]], ...],
]:
    """Compute every feature and signal series inside the caller's Decimal context."""
    # The same order-independent representative the feature graph resolves, so a
    # duplicated identifier cannot make the evaluated series depend on declaration
    # position. Unreachable on the documented contract, because validation rejects
    # a duplicate before evaluation, but the graph is constructible directly.
    definitions = _canonical_definitions(spec)
    states = {
        name: _FeatureState(
            definitions[name], _resolved_window(spec, definitions[name])
        )
        for name in graph.order
    }
    lookup: dict[str, list[Value]] = {}
    skipped = [False] * len(bars)

    for name in graph.order:
        state = states[name]
        # Resolved once per feature. The graph order guarantees every declared
        # feature this one reads is already in `lookup`.
        source = _source_series(state.definition, lookup, bars)
        series: list[Value] = []
        for index in range(len(bars)):
            value = _feature_value(state, index, source, bars)
            if value is MISSING_VALUE and index >= state.definition.warm_up_bars:
                policy = state.definition.missing_value_policy
                if policy is MissingValuePolicy.REJECT_DATASET:
                    raise _Rejected(
                        _MISSING_INPUT,
                        {"feature_id": name, "bar_index": index},
                    )
                if policy is MissingValuePolicy.SKIP_BAR:
                    skipped[index] = True
            series.append(value)
        state.series = series
        lookup[name] = series

    constants = _constant_values(spec)

    def signals(
        rules: tuple[RuleDefinition, ...],
    ) -> tuple[tuple[str, list[bool]], ...]:
        collected: list[tuple[str, list[bool]]] = []
        for rule in rules:
            values: list[bool] = []
            for index in range(len(bars)):
                if skipped[index]:
                    # SKIP_BAR: the bar produces no signal at all.
                    values.append(False)
                    continue
                outcome = _evaluate_node(
                    rule.expression, index, lookup, bars, constants
                )
                # Specification 12.3.2: a top-level rule containing MISSING
                # evaluates to false and never becomes true through truthiness.
                values.append(outcome is True)
            collected.append((rule.id, values))
        return tuple(collected)

    return lookup, skipped, signals(spec.entry_rules), signals(spec.exit_rules)


def evaluate_level_one(
    spec: StrategySpec,
    graph: FeatureGraph,
    bars: tuple[Bar, ...],
    observed_at_utc: datetime,
) -> Result[EvaluationResult]:
    """Evaluate one validated strategy over an explicit bounded bar series.

    Returns complete feature and signal series for an accepted input, or a
    `Result` failure. No exception escapes: every expected rejection — an
    over-long series, a division by zero, a non-finite intermediate, a missing
    input under `REJECT_DATASET`, and a feature value whose canonical rendering
    would exceed `MAX_DECIMAL_TEXT_LENGTH` — becomes a diagnostic.
    """
    if len(bars) > MAX_EVALUATION_BARS:
        return Failure(
            outcome="FAILURE",
            diagnostics=(
                _diagnostic(
                    _SERIES_TOO_LONG,
                    {
                        "observed_bar_count": len(bars),
                        "maximum_bar_count": MAX_EVALUATION_BARS,
                    },
                    observed_at_utc,
                ),
            ),
        )

    try:
        # `localcontext` restores the process-global context on both the normal
        # and the exceptional path, so a rejected evaluation cannot leak a
        # modified precision or rounding mode into the caller. That restoration
        # is pinned by three committed tests rather than by a runtime assertion:
        # the successful path, the rejected path, and a property test all compare
        # `decimal.getcontext()` by identity before and after evaluation.
        with decimal.localcontext(EVALUATION_CONTEXT) as arithmetic:
            arithmetic.traps[decimal.DivisionByZero] = False
            arithmetic.traps[decimal.Overflow] = False
            arithmetic.traps[decimal.InvalidOperation] = False
            lookup, skipped, entries, exits = _compute(spec, graph, bars)
        # Rendering is inside the guarded region, and outside `localcontext`,
        # exactly as before. `_render` can reject on the canonical length bound
        # of section 5.9.1; building `Success` first would let that escape as a
        # bare `ValueError` and break the contract this docstring states.
        rendered = tuple(
            FeatureSeries(
                feature_id=name,
                values=tuple(_render(value, name) for value in lookup[name]),
            )
            for name in graph.order
        )
    except _Rejected as rejected:
        return Failure(
            outcome="FAILURE",
            diagnostics=(
                _diagnostic(rejected.code, rejected.details, observed_at_utc),
            ),
        )

    return Success[EvaluationResult](
        outcome="SUCCESS",
        value=EvaluationResult(
            bar_count=len(bars),
            features=rendered,
            entry_signals=tuple(
                SignalSeries(rule_id=name, values=tuple(values))
                for name, values in entries
            ),
            exit_signals=tuple(
                SignalSeries(rule_id=name, values=tuple(values))
                for name, values in exits
            ),
            skipped_bars=tuple(skipped),
        ),
    )
