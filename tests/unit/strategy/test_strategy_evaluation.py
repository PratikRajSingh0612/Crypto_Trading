"""Test the deterministic Level 1 reference evaluator (plan Task 4).

Warm-up, missing values, Decimal isolation, divide-by-zero, non-finite results,
the series bound, and the exact crossover boundaries. Feature-graph validation
belongs to `tests/unit/strategy/test_strategy_feature_graph.py`.
"""

from __future__ import annotations

import decimal
import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, Final

import pytest

from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.financial import MAX_DECIMAL_TEXT_LENGTH, format_decimal
from crypto_lab.domain.results import Failure, Success
from crypto_lab.strategy import evaluation, feature_graph
from crypto_lab.strategy.evaluation import (
    EVALUATION_CONTEXT,
    EVALUATION_PRECISION,
    MAX_EVALUATION_BARS,
    MISSING_VALUE,
    Bar,
    EvaluationResult,
    evaluate_level_one,
)
from crypto_lab.strategy.feature_graph import FeatureGraph, validate_feature_graph
from crypto_lab.strategy.models import StrategySpec
from crypto_lab.strategy.validation import validate_strategy_expressions
from crypto_lab.strategy.yaml_source import load_yaml_document

_FIXTURES = Path(__file__).parents[2] / "fixtures" / "strategy"
_OBSERVED_AT = datetime(2026, 8, 17, tzinfo=UTC)
_EPOCH = datetime(2026, 1, 1, tzinfo=UTC)

_SERIES_TOO_LONG = "STRATEGY.EVALUATION_SERIES_TOO_LONG"
_DIVIDE_BY_ZERO = "STRATEGY.EVALUATION_DIVIDE_BY_ZERO"
_NON_FINITE = "STRATEGY.EVALUATION_NON_FINITE"
_MISSING_INPUT = "STRATEGY.EVALUATION_MISSING_INPUT"


def _document(name: str = "sma_cross_long.valid.yaml") -> dict[str, Any]:
    path = _FIXTURES / name
    result = load_yaml_document(path.read_bytes(), path.name, _OBSERVED_AT)
    assert isinstance(result, Success), result
    value = result.value.value
    assert isinstance(value, dict)
    return dict(value)


def _spec(**overrides: object) -> StrategySpec:
    return StrategySpec.model_validate_json(
        canonical_json_bytes(_document() | overrides)
    )


def _graph(spec: StrategySpec) -> FeatureGraph:
    result = validate_feature_graph(spec, _OBSERVED_AT)
    assert isinstance(result, Success), result
    return result.value


def _bars(closes: list[str]) -> tuple[Bar, ...]:
    """One bar per close price, with a distinct increasing timestamp."""
    return tuple(
        Bar(
            timestamp_utc=_EPOCH + timedelta(hours=index),
            open=Decimal(text),
            high=Decimal(text),
            low=Decimal(text),
            close=Decimal(text),
            volume=Decimal(1),
        )
        for index, text in enumerate(closes)
    )


def _feature(
    identifier: str,
    *,
    operation: str = "indicator.sma/v1",
    inputs: list[str] | None = None,
    parameters: dict[str, str] | None = None,
    output_type: str = "DECIMAL",
    warm_up_bars: int = 0,
    missing_value_policy: str = "PROPAGATE_FALSE",
) -> dict[str, Any]:
    return {
        "id": identifier,
        "operation": operation,
        "inputs": ["bar.close"] if inputs is None else inputs,
        "parameters": {"period": "two"} if parameters is None else parameters,
        "output_type": output_type,
        "warm_up_bars": warm_up_bars,
        "missing_value_policy": missing_value_policy,
    }


def _bar_feature(
    identifier: str,
    field: str = "bar.close",
    **overrides: Any,
) -> dict[str, Any]:
    """A `source.bar_field/v1` feature over one bar field, taking no parameters."""
    return _feature(
        identifier,
        operation="source.bar_field/v1",
        inputs=[field],
        parameters={},
        **overrides,
    )


def _sma(identifier: str, period: str = "two", **overrides: Any) -> dict[str, Any]:
    """An `indicator.sma/v1` feature over `bar.close` with the named period."""
    return _feature(identifier, parameters={"period": period}, **overrides)


def _shifted(identifier: str, source: str, bars: str) -> dict[str, Any]:
    """A `shift/v1` feature moving `source` back by the named integer parameter."""
    return _feature(
        identifier,
        operation="shift/v1",
        inputs=[source],
        parameters={"bars": bars},
    )


def _rule(identifier: str, expression: dict[str, Any]) -> dict[str, Any]:
    return {"id": identifier, "expression": expression}


_ALWAYS_FALSE = {"op": "literal", "value_type": "BOOLEAN", "value": False}


def _probe_spec(
    features: list[dict[str, Any]],
    entry: dict[str, Any],
    *,
    parameters: dict[str, Any] | None = None,
) -> StrategySpec:
    """A minimal spec carrying one probe entry rule and a constant exit rule."""
    declared = {
        "two": {"value_type": "INTEGER", "value": 2},
        "three": {"value_type": "INTEGER", "value": 3},
        "zero": {"value_type": "INTEGER", "value": 0},
        "one": {"value_type": "INTEGER", "value": 1},
    }
    if parameters is not None:
        declared |= parameters
    return _spec(
        parameters=declared,
        features=features,
        entry_rules=[_rule("enter_probe", entry)],
        exit_rules=[_rule("exit_probe", _ALWAYS_FALSE)],
        warm_up_requirements={"minimum_bars": 0},
    )


def _evaluate(
    spec: StrategySpec,
    bars: tuple[Bar, ...],
) -> Success[EvaluationResult] | Failure:
    return evaluate_level_one(spec, _graph(spec), bars, _OBSERVED_AT)


def _result(spec: StrategySpec, bars: tuple[Bar, ...]) -> EvaluationResult:
    outcome = _evaluate(spec, bars)
    assert isinstance(outcome, Success), outcome
    return outcome.value


def _series(spec: StrategySpec, bars: tuple[Bar, ...], name: str) -> tuple[Any, ...]:
    for feature in _result(spec, bars).features:
        if feature.feature_id == name:
            return feature.values
    raise AssertionError(f"no feature series named {name}")


def _entry(spec: StrategySpec, bars: tuple[Bar, ...]) -> tuple[bool, ...]:
    return _result(spec, bars).entry_signals[0].values


def _codes(spec: StrategySpec, bars: tuple[Bar, ...]) -> list[str]:
    outcome = _evaluate(spec, bars)
    assert isinstance(outcome, Failure), outcome
    return [diagnostic.error_code for diagnostic in outcome.diagnostics]


# --- The MISSING contract ---------------------------------------------------


def test_the_missing_marker_is_none_and_not_the_pydantic_field_sentinel() -> None:
    from pydantic.experimental.missing_sentinel import MISSING as FIELD_SENTINEL

    assert MISSING_VALUE is None
    assert MISSING_VALUE is not FIELD_SENTINEL


def test_a_missing_cell_serializes_as_json_null() -> None:
    spec = _probe_spec([_feature("probe", warm_up_bars=2)], _ALWAYS_FALSE)
    result = _result(spec, _bars(["1", "2", "3"]))
    payload = result.model_dump(mode="json")
    assert payload["features"][0]["values"][0] is None


# --- Step: warm-up boundary -------------------------------------------------


@pytest.mark.parametrize("warm_up", [0, 1, 2, 3])
def test_the_first_available_bar_is_exactly_the_declared_warm_up_index(
    warm_up: int,
) -> None:
    """`MISSING` for every `t < warm_up_bars`; a value at `t == warm_up_bars`."""
    spec = _probe_spec(
        [
            _bar_feature("probe", warm_up_bars=warm_up),
        ],
        _ALWAYS_FALSE,
    )
    values = _series(spec, _bars(["1", "2", "3", "4"]), "probe")
    assert values[:warm_up] == (MISSING_VALUE,) * warm_up
    assert values[warm_up] is not MISSING_VALUE


def test_a_warm_up_of_zero_makes_every_bar_available() -> None:
    spec = _probe_spec(
        [_bar_feature("probe")],
        _ALWAYS_FALSE,
    )
    assert _series(spec, _bars(["1", "2"]), "probe") == ("1", "2")


def test_insufficient_history_for_a_window_is_missing_not_an_error() -> None:
    """A window reaching before bar zero yields `MISSING`, never an exception."""
    spec = _probe_spec([_sma("probe", "three")], _ALWAYS_FALSE)
    values = _series(spec, _bars(["1", "2", "3", "4"]), "probe")
    assert values[0] is MISSING_VALUE
    assert values[1] is MISSING_VALUE
    assert values[2] == "2"


# --- Step: exact Decimal semantics -----------------------------------------


def test_a_simple_mean_is_exact_decimal_arithmetic() -> None:
    spec = _probe_spec([_feature("probe")], _ALWAYS_FALSE)
    assert _series(spec, _bars(["1", "2", "3"]), "probe") == (
        MISSING_VALUE,
        "1.5",
        "2.5",
    )


def test_a_recurring_quotient_is_rounded_half_even_at_thirty_four_digits() -> None:
    spec = _probe_spec([_sma("probe", "three")], _ALWAYS_FALSE)
    values = _series(spec, _bars(["1", "1", "0", "0", "0"]), "probe")
    # (1 + 1 + 0) / 3, computed independently through the declared context rather
    # than through the evaluator, so this asserts the contract and not itself.
    expected = format_decimal(EVALUATION_CONTEXT.divide(Decimal(2), Decimal(3)))
    assert values[2] is not MISSING_VALUE
    assert values[2] == expected
    # 34 significant digits, and the 34th is the half-even rounding of 6666...
    assert expected == "0." + "6" * 33 + "7"
    # Sum-then-divide, not incremental averaging: averaging `1/3 + 1/3 + 0`
    # would end `...6666` instead, so this literal pins the evaluation order too.


@pytest.mark.parametrize(
    ("addend", "expected", "rejected"),
    [
        # Last retained digit 0, already even: half-even keeps it and rounds
        # DOWN to exactly one, where ROUND_HALF_UP would round away from zero.
        ("1", "1", "1." + "0" * 32 + "1"),
        # Last retained digit 1, odd: half-even must move to the even neighbour
        # and round UP, where ROUND_HALF_DOWN or plain truncation would not.
        ("3", "1." + "0" * 32 + "2", "1." + "0" * 32 + "1"),
    ],
)
def test_an_exact_half_way_quotient_is_rounded_half_to_even(
    addend: str,
    expected: str,
    rejected: str,
) -> None:
    """The declared rounding *mode* is load-bearing, not merely the precision.

    A recurring quotient rounds identically under half-even and half-up, so it
    cannot pin the mode at all. Each case here is an **exact** tie: the two-bar
    window sums to `2 + n * 1e-33` exactly, and halving that lands precisely half
    an ulp past 34 significant digits.

    One tie is not enough either. A tie whose last retained digit is even rounds
    down, which truncation also does; a tie whose last retained digit is odd
    rounds up, which half-down does not. Only the pair excludes every other
    rounding mode, so both are asserted.
    """
    tie = "2." + "0" * 32 + addend
    spec = _probe_spec([_sma("probe")], _ALWAYS_FALSE)
    values = _series(spec, _bars(["0", tie]), "probe")
    assert values[1] == expected
    assert values[1] != rejected
    # Derived through the declared context rather than through the evaluator.
    assert values[1] == format_decimal(
        EVALUATION_CONTEXT.divide(Decimal(tie), Decimal(2))
    )


def test_a_timestamp_bar_field_renders_as_a_canonical_utc_string() -> None:
    """The one feature cell that is a STRING rather than a canonical Decimal."""
    spec = _probe_spec(
        [_bar_feature("stamp", "bar.timestamp_utc", output_type="STRING")],
        _ALWAYS_FALSE,
    )
    values = _series(spec, _bars(["1", "2"]), "stamp")
    assert values == ("2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z")


def test_the_evaluation_context_is_the_specified_precision_and_rounding() -> None:
    assert EVALUATION_PRECISION == 34
    assert EVALUATION_CONTEXT.prec == 34
    assert EVALUATION_CONTEXT.rounding == decimal.ROUND_HALF_EVEN


def test_the_global_decimal_context_is_unchanged_after_a_successful_run() -> None:
    before = decimal.getcontext()
    precision_before = before.prec
    rounding_before = before.rounding
    spec = _probe_spec([_feature("probe")], _ALWAYS_FALSE)
    _result(spec, _bars(["1", "2", "3"]))
    assert decimal.getcontext() is before
    assert decimal.getcontext().prec == precision_before
    assert decimal.getcontext().rounding == rounding_before


def test_the_global_decimal_context_is_restored_after_a_rejected_run() -> None:
    """The exceptional path must restore it too, or a failure leaks precision."""
    before = decimal.getcontext()
    precision_before = before.prec
    spec = _probe_spec(
        [_bar_feature("probe")],
        {
            "op": "greater_than",
            "left": {
                "op": "divide",
                "left": {"op": "ref", "id": "probe", "bars_ago": 0},
                "right": {"op": "literal", "value_type": "DECIMAL", "value": "0"},
            },
            "right": {"op": "literal", "value_type": "DECIMAL", "value": "0"},
        },
    )
    assert _codes(spec, _bars(["1", "2"])) == [_DIVIDE_BY_ZERO]
    assert decimal.getcontext() is before
    assert decimal.getcontext().prec == precision_before


def test_a_negated_zero_never_reaches_canonical_serialization() -> None:
    """`format_decimal` refuses a negative zero, so it must be normalized."""
    spec = _probe_spec(
        [
            _bar_feature("zeroed", "bar.volume"),
        ],
        {
            "op": "greater_than",
            "left": {
                "op": "negate",
                "operand": {"op": "literal", "value_type": "DECIMAL", "value": "0"},
            },
            "right": {"op": "literal", "value_type": "DECIMAL", "value": "0"},
        },
    )
    bars = tuple(
        Bar(
            timestamp_utc=_EPOCH + timedelta(hours=index),
            open=Decimal(1),
            high=Decimal(1),
            low=Decimal(1),
            close=Decimal(1),
            volume=Decimal(0),
        )
        for index in range(2)
    )
    assert _series(spec, bars, "zeroed") == ("0", "0")
    assert _entry(spec, bars) == (False, False)


# --- Step: divide by zero and non-finite ------------------------------------


def test_division_by_zero_yields_a_diagnostic_not_an_exception() -> None:
    spec = _probe_spec(
        [_bar_feature("probe")],
        {
            "op": "greater_than",
            "left": {
                "op": "divide",
                "left": {"op": "ref", "id": "probe", "bars_ago": 0},
                "right": {"op": "literal", "value_type": "DECIMAL", "value": "0"},
            },
            "right": {"op": "literal", "value_type": "DECIMAL", "value": "0"},
        },
    )
    assert _codes(spec, _bars(["1", "2"])) == [_DIVIDE_BY_ZERO]


def test_a_zero_divisor_reached_through_a_reference_is_also_rejected() -> None:
    spec = _probe_spec(
        [_bar_feature("probe", "bar.volume")],
        {
            "op": "greater_than",
            "left": {
                "op": "divide",
                "left": {"op": "literal", "value_type": "DECIMAL", "value": "1"},
                "right": {"op": "ref", "id": "probe", "bars_ago": 0},
            },
            "right": {"op": "literal", "value_type": "DECIMAL", "value": "0"},
        },
    )
    bars = tuple(
        Bar(
            timestamp_utc=_EPOCH + timedelta(hours=index),
            open=Decimal(1),
            high=Decimal(1),
            low=Decimal(1),
            close=Decimal(1),
            volume=Decimal(0),
        )
        for index in range(2)
    )
    assert _codes(spec, bars) == [_DIVIDE_BY_ZERO]


def test_a_non_finite_intermediate_yields_its_own_diagnostic() -> None:
    """A balanced squaring tree overflows the context's exponent range.

    `Decimal` defaults `Emax` to 999999 and `MAX_DECIMAL_TEXT_LENGTH` caps a
    literal at 256 characters, so a linear chain of multiplies cannot reach
    infinity within `MAX_EXPRESSION_DEPTH`. Squaring twelve times takes a
    255-digit literal to an exponent near 255 x 4096, which does, at depth 13.
    """
    huge: dict[str, Any] = {
        "op": "literal",
        "value_type": "DECIMAL",
        "value": "9" * 255,
    }
    product: dict[str, Any] = huge
    for _ in range(12):
        product = {"op": "multiply", "left": product, "right": product}
    spec = _probe_spec(
        [_bar_feature("probe")],
        {
            "op": "greater_than",
            "left": product,
            "right": {"op": "literal", "value_type": "DECIMAL", "value": "0"},
        },
    )
    assert _codes(spec, _bars(["1", "2"])) == [_NON_FINITE]


# --- Step: the series bound -------------------------------------------------


def test_a_series_longer_than_the_maximum_is_rejected() -> None:
    spec = _probe_spec(
        [_bar_feature("probe")],
        _ALWAYS_FALSE,
    )
    bars = _bars(["1"] * (MAX_EVALUATION_BARS + 1))
    assert _codes(spec, bars) == [_SERIES_TOO_LONG]


def test_a_series_at_exactly_the_maximum_is_accepted() -> None:
    spec = _probe_spec(
        [_bar_feature("probe")],
        _ALWAYS_FALSE,
    )
    result = _result(spec, _bars(["1"] * MAX_EVALUATION_BARS))
    assert result.bar_count == MAX_EVALUATION_BARS


def test_an_empty_series_is_accepted_and_yields_empty_series() -> None:
    spec = _probe_spec(
        [_bar_feature("probe")],
        _ALWAYS_FALSE,
    )
    result = _result(spec, ())
    assert result.bar_count == 0
    assert result.features[0].values == ()
    assert result.entry_signals[0].values == ()


# --- Step: missing-value policy --------------------------------------------


def test_reject_dataset_turns_a_post_warm_up_missing_input_into_a_failure() -> None:
    spec = _probe_spec(
        [
            _feature(
                "probe",
                parameters={"period": "three"},
                missing_value_policy="REJECT_DATASET",
            )
        ],
        _ALWAYS_FALSE,
    )
    assert _codes(spec, _bars(["1", "2", "3", "4"])) == [_MISSING_INPUT]


def test_propagate_false_leaves_the_cell_missing_and_the_rule_false() -> None:
    spec = _probe_spec(
        [
            _feature(
                "probe",
                parameters={"period": "three"},
                missing_value_policy="PROPAGATE_FALSE",
            )
        ],
        {
            "op": "greater_than",
            "left": {"op": "ref", "id": "probe", "bars_ago": 0},
            "right": {"op": "literal", "value_type": "DECIMAL", "value": "0"},
        },
    )
    bars = _bars(["1", "2", "3", "4"])
    assert _series(spec, bars, "probe")[:2] == (MISSING_VALUE, MISSING_VALUE)
    assert _entry(spec, bars)[:2] == (False, False)
    assert _entry(spec, bars)[2] is True


def test_skip_bar_marks_the_bar_and_suppresses_every_signal_on_it() -> None:
    spec = _probe_spec(
        [
            _feature(
                "probe",
                parameters={"period": "three"},
                missing_value_policy="SKIP_BAR",
            )
        ],
        {"op": "literal", "value_type": "BOOLEAN", "value": True},
    )
    bars = _bars(["1", "2", "3", "4"])
    result = _result(spec, bars)
    assert result.skipped_bars == (True, True, False, False)
    assert result.entry_signals[0].values == (False, False, True, True)


def test_a_missing_value_never_becomes_true_through_truthiness() -> None:
    """Specification 12.3.2: a rule containing MISSING evaluates to false."""
    spec = _probe_spec(
        [_sma("probe", "three")],
        {"op": "is_missing", "operand": {"op": "ref", "id": "probe", "bars_ago": 0}},
    )
    bars = _bars(["1", "2", "3"])
    # `is_missing` is the one probe that reports MISSING rather than propagating it.
    assert _entry(spec, bars) == (True, True, False)


def test_a_warm_up_missing_value_makes_the_rule_false_regardless_of_policy() -> None:
    for policy in ("PROPAGATE_FALSE", "SKIP_BAR"):
        spec = _probe_spec(
            [
                _bar_feature("probe", warm_up_bars=2, missing_value_policy=policy),
            ],
            {
                "op": "greater_than",
                "left": {"op": "ref", "id": "probe", "bars_ago": 0},
                "right": {"op": "literal", "value_type": "DECIMAL", "value": "0"},
            },
        )
        bars = _bars(["1", "2", "3"])
        assert _entry(spec, bars) == (False, False, True), policy
        # Warm-up MISSING is not a policy event, so no bar is marked skipped.
        assert _result(spec, bars).skipped_bars == (False, False, False), policy


# --- Step: explicit bar offsets --------------------------------------------


def test_a_positive_bar_offset_reads_the_earlier_closed_bar() -> None:
    spec = _probe_spec(
        [_bar_feature("probe")],
        {
            "op": "greater_than",
            "left": {"op": "ref", "id": "probe", "bars_ago": 1},
            "right": {"op": "literal", "value_type": "DECIMAL", "value": "1"},
        },
    )
    # closes 1, 5, 1 -> at t=1 the prior bar is 1 (not > 1); at t=2 it is 5.
    assert _entry(spec, _bars(["1", "5", "1"])) == (False, False, True)


def test_an_offset_reaching_before_the_first_bar_is_missing() -> None:
    spec = _probe_spec(
        [_bar_feature("probe")],
        {
            "op": "greater_than",
            "left": {"op": "ref", "id": "probe", "bars_ago": 2},
            "right": {"op": "literal", "value_type": "DECIMAL", "value": "0"},
        },
    )
    assert _entry(spec, _bars(["1", "2", "3"])) == (False, False, True)


def test_the_shift_operation_moves_a_series_by_its_declared_bars() -> None:
    spec = _probe_spec(
        [
            _bar_feature("base"),
            _shifted("probe", "base", "one"),
        ],
        _ALWAYS_FALSE,
    )
    bars = _bars(["1", "2", "3"])
    assert _series(spec, bars, "probe") == (MISSING_VALUE, "1", "2")


def test_a_shift_of_zero_bars_is_the_current_bar() -> None:
    spec = _probe_spec(
        [
            _bar_feature("base"),
            _shifted("probe", "base", "zero"),
        ],
        _ALWAYS_FALSE,
    )
    assert _series(spec, _bars(["1", "2"]), "probe") == ("1", "2")


# --- Step: exact crossover boundaries --------------------------------------


def _crossover_spec(operation: str) -> StrategySpec:
    return _probe_spec(
        [
            _bar_feature("fast", "bar.close"),
            _bar_feature("slow", "bar.open"),
        ],
        {
            "op": operation,
            "left": {"op": "ref", "id": "fast", "bars_ago": 0},
            "right": {"op": "ref", "id": "slow", "bars_ago": 0},
        },
    )


def _pairs(values: list[tuple[str, str]]) -> tuple[Bar, ...]:
    """One bar per (close, open) pair, so `fast` and `slow` differ per bar."""
    return tuple(
        Bar(
            timestamp_utc=_EPOCH + timedelta(hours=index),
            open=Decimal(open_text),
            high=Decimal(max(close_text, open_text)),
            low=Decimal(min(close_text, open_text)),
            close=Decimal(close_text),
            volume=Decimal(1),
        )
        for index, (close_text, open_text) in enumerate(values)
    )


def test_a_crossover_is_never_true_on_the_first_bar() -> None:
    """Bar zero has no prior bar, so the condition cannot be evaluated."""
    bars = _pairs([("2", "1"), ("2", "1")])
    assert _entry(_crossover_spec("crosses_above"), bars)[0] is False


def test_crosses_above_is_true_only_on_the_transition_bar() -> None:
    bars = _pairs([("1", "2"), ("3", "2"), ("4", "2")])
    assert _entry(_crossover_spec("crosses_above"), bars) == (False, True, False)


def test_crosses_above_accepts_prior_bar_equality() -> None:
    """The prior-bar inequality is non-strict: `left[t-1] <= right[t-1]`."""
    bars = _pairs([("2", "2"), ("3", "2")])
    assert _entry(_crossover_spec("crosses_above"), bars) == (False, True)


def test_crosses_above_requires_strict_current_bar_inequality() -> None:
    bars = _pairs([("1", "2"), ("2", "2")])
    assert _entry(_crossover_spec("crosses_above"), bars) == (False, False)


def test_crosses_below_is_the_exact_inverse() -> None:
    bars = _pairs([("3", "2"), ("1", "2")])
    assert _entry(_crossover_spec("crosses_below"), bars) == (False, True)


def test_crosses_below_accepts_prior_bar_equality() -> None:
    bars = _pairs([("2", "2"), ("1", "2")])
    assert _entry(_crossover_spec("crosses_below"), bars) == (False, True)


def test_a_crossover_with_a_missing_operand_is_false() -> None:
    spec = _probe_spec(
        [
            _sma("fast", "three"),
            _bar_feature("slow", "bar.open"),
        ],
        {
            "op": "crosses_above",
            "left": {"op": "ref", "id": "fast", "bars_ago": 0},
            "right": {"op": "ref", "id": "slow", "bars_ago": 0},
        },
    )
    # `fast` needs three bars of history, so bars 0 to 2 have a missing operand.
    bars = _pairs([("1", "9"), ("2", "9"), ("9", "1"), ("9", "1")])
    assert _entry(spec, bars)[:3] == (False, False, False)


# --- Purity and determinism ------------------------------------------------


def test_evaluation_is_a_pure_function_of_its_inputs() -> None:
    spec = _probe_spec([_feature("probe")], _ALWAYS_FALSE)
    bars = _bars(["1", "2", "3", "4"])
    first = _result(spec, bars)
    second = _result(spec, bars)
    assert canonical_json_bytes(first.model_dump(mode="json")) == canonical_json_bytes(
        second.model_dump(mode="json")
    )


def test_the_result_carries_a_complete_series_for_every_feature_and_rule() -> None:
    spec = _probe_spec(
        [
            _bar_feature("base"),
            _feature("probe", inputs=["base"]),
        ],
        _ALWAYS_FALSE,
    )
    bars = _bars(["1", "2", "3"])
    result = _result(spec, bars)
    assert {series.feature_id for series in result.features} == {"base", "probe"}
    for series in result.features:
        assert len(series.values) == len(bars)
    for signal in (*result.entry_signals, *result.exit_signals):
        assert len(signal.values) == len(bars)
    assert len(result.skipped_bars) == len(bars)


def test_the_feature_series_follow_the_graph_topological_order() -> None:
    spec = _probe_spec(
        [
            _feature("zulu", inputs=["alpha"]),
            _bar_feature("alpha"),
        ],
        _ALWAYS_FALSE,
    )
    result = _result(spec, _bars(["1", "2"]))
    order = tuple(series.feature_id for series in result.features)
    assert order == ("alpha", "zulu")


def test_no_exception_escapes_any_expected_rejection() -> None:
    """Every expected rejection is a `Result`, never a raised error."""
    spec = _probe_spec(
        [_bar_feature("probe")],
        _ALWAYS_FALSE,
    )
    for bars in (_bars(["1"] * (MAX_EVALUATION_BARS + 1)), ()):
        outcome = evaluate_level_one(spec, _graph(spec), bars, _OBSERVED_AT)
        assert isinstance(outcome, Success | Failure)


def test_the_evaluator_produces_no_order_fill_or_portfolio_field() -> None:
    """Plan section 5.6: this is not an order, fill, or portfolio simulator."""
    forbidden = {
        "order",
        "orders",
        "fill",
        "fills",
        "position",
        "positions",
        "portfolio",
        "cash",
        "equity",
        "pnl",
        "fee",
        "fees",
        "slippage",
        "return",
        "returns",
    }
    for model in (EvaluationResult, Bar):
        assert set(model.model_fields) & forbidden == set()


# --- The complete operator surface ------------------------------------------
#
# Every allowlisted feature operation and every expression operator is a Task 4
# behaviour, so section 7's TDD policy owes each one a focused test. Without these
# a defect in `rolling.min/v1`, `maximum`, or `or` would ship unnoticed: the golden
# scenarios exercise only the operators their own semantics need.


def _literal(value: object, value_type: str = "DECIMAL") -> dict[str, Any]:
    return {"op": "literal", "value_type": value_type, "value": value}


def _ref(identifier: str, bars_ago: int = 0) -> dict[str, Any]:
    return {"op": "ref", "id": identifier, "bars_ago": bars_ago}


def _binary(op: str, left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    return {"op": op, "left": left, "right": right}


@pytest.mark.parametrize(
    ("field", "expected"),
    [
        ("bar.open", "2"),
        ("bar.high", "9"),
        ("bar.low", "1"),
        ("bar.close", "4"),
        ("bar.volume", "7"),
    ],
)
def test_every_numeric_bar_field_is_read_from_its_own_attribute(
    field: str,
    expected: str,
) -> None:
    """A closed `if` chain, so each field needs its own case to be proven wired."""
    spec = _probe_spec([_bar_feature("probe", field)], _ALWAYS_FALSE)
    bar = Bar(
        timestamp_utc=_EPOCH,
        open=Decimal(2),
        high=Decimal(9),
        low=Decimal(1),
        close=Decimal(4),
        volume=Decimal(7),
    )
    assert _series(spec, (bar,), "probe") == (expected,)


@pytest.mark.parametrize(
    ("operation", "expected"),
    [
        ("rolling.sum/v1", "9"),
        ("rolling.mean/v1", "3"),
        ("rolling.min/v1", "1"),
        ("rolling.max/v1", "5"),
        ("indicator.sma/v1", "3"),
    ],
)
def test_every_windowed_feature_operation_reduces_its_window(
    operation: str,
    expected: str,
) -> None:
    parameter = "period" if operation == "indicator.sma/v1" else "window"
    spec = _probe_spec(
        [
            _feature(
                "probe",
                operation=operation,
                inputs=["bar.close"],
                parameters={parameter: "three"},
            )
        ],
        _ALWAYS_FALSE,
    )
    # Window 1, 3, 5 ending at bar 2: sum 9, mean 3, min 1, max 5.
    assert _series(spec, _bars(["1", "3", "5"]), "probe")[2] == expected


def test_a_window_containing_a_missing_cell_is_missing_not_partial() -> None:
    """A warm-up cell inside a window must void the window, never be skipped."""
    spec = _probe_spec(
        [
            _bar_feature("base", warm_up_bars=1),
            _feature(
                "probe",
                operation="rolling.sum/v1",
                inputs=["base"],
                parameters={"window": "two"},
                warm_up_bars=1,
            ),
        ],
        _ALWAYS_FALSE,
    )
    values = _series(spec, _bars(["1", "2", "3"]), "probe")
    # Bar 1's window is base[0..1], and base[0] is a warm-up MISSING.
    assert values[1] is MISSING_VALUE
    assert values[2] == "5"


@pytest.mark.parametrize(
    ("operator", "expected"),
    [
        ("add", "5"),
        ("subtract", "-1"),
        ("multiply", "6"),
        ("minimum", "2"),
        ("maximum", "3"),
    ],
)
def test_every_arithmetic_operator_is_exact(operator: str, expected: str) -> None:
    spec = _probe_spec(
        [_bar_feature("probe")],
        _binary(
            "equal",
            _binary(operator, _ref("probe"), _literal("3")),
            _literal(expected),
        ),
    )
    assert _entry(spec, _bars(["2"])) == (True,)


def test_division_by_a_non_zero_divisor_rounds_through_the_declared_context() -> None:
    quotient = format_decimal(EVALUATION_CONTEXT.divide(Decimal(2), Decimal(3)))
    spec = _probe_spec(
        [_bar_feature("probe")],
        _binary(
            "equal",
            _binary("divide", _ref("probe"), _literal("3")),
            _literal(quotient),
        ),
    )
    assert _entry(spec, _bars(["2"])) == (True,)


@pytest.mark.parametrize(
    ("operator", "left", "right", "expected"),
    [
        ("equal", "2", "2", True),
        ("equal", "2", "3", False),
        ("not_equal", "2", "3", True),
        ("not_equal", "2", "2", False),
        ("less_than", "2", "3", True),
        ("less_than", "3", "2", False),
        ("less_than_or_equal", "2", "2", True),
        ("less_than_or_equal", "3", "2", False),
        ("greater_than", "3", "2", True),
        ("greater_than_or_equal", "2", "2", True),
        ("greater_than_or_equal", "1", "2", False),
    ],
)
def test_every_comparison_operator_decides_correctly(
    operator: str,
    left: str,
    right: str,
    expected: bool,
) -> None:
    spec = _probe_spec(
        [_bar_feature("probe")],
        _binary(operator, _literal(left), _literal(right)),
    )
    assert _entry(spec, _bars(["1"])) == (expected,)


def test_equality_with_a_missing_operand_reports_missing() -> None:
    """`equal` accepts non-numeric kinds, so it needs its own MISSING guard rather
    than relying on the numeric narrowing the ordering comparisons use."""
    spec = _probe_spec(
        [_sma("probe", "three")],
        _binary("equal", _ref("probe"), _literal("2")),
    )
    # Bars 0 and 1 are MISSING; bar 2's mean is exactly 2, so only it is true.
    assert _entry(spec, _bars(["1", "2", "3"])) == (False, False, True)


def test_arithmetic_with_a_missing_operand_yields_missing_not_a_substitute() -> None:
    """A MISSING operand must void the arithmetic, never be treated as zero."""
    spec = _probe_spec(
        [_sma("probe", "three")],
        _binary(
            "equal",
            _binary("add", _ref("probe"), _literal("1")),
            _literal("3"),
        ),
    )
    # If MISSING were read as zero, bars 0 and 1 would compute 0 + 1 = 1 and stay
    # false by luck; bar 2 computes 2 + 1 = 3 and is genuinely true.
    assert _entry(spec, _bars(["1", "2", "3"])) == (False, False, True)


def test_a_namespace_invalid_specification_produces_no_series() -> None:
    """Plan section 5.10 fail-closed requirement, proven end to end.

    The validated Task 4 path is `validate_feature_graph` then
    `evaluate_level_one`. A specification whose feature shadows a reserved bar
    field must never reach the second step, so no feature or signal series exists
    for it.
    """
    spec = _probe_spec([_bar_feature("bar.close")], _ALWAYS_FALSE)
    outcome = validate_feature_graph(spec, _OBSERVED_AT)

    assert isinstance(outcome, Failure)
    codes = {item.error_code for item in outcome.diagnostics}
    assert "STRATEGY.REFERENCE_NAMESPACE_COLLISION" in codes


def test_a_non_boolean_rule_outcome_is_false_rather_than_truthy() -> None:
    """Specification 12.3.2: a rule never becomes true through truthiness.

    Task 3 rejects a non-boolean rule root, so reaching the evaluator with one
    requires constructing the graph directly. Without this guard a `bool(outcome)`
    implementation would report a non-zero `Decimal` as an entry signal and the
    whole suite would still pass.
    """
    spec = _probe_spec([_bar_feature("probe")], _ref("probe"))
    outcome = evaluate_level_one(
        spec, FeatureGraph(order=("probe",)), _bars(["5"]), _OBSERVED_AT
    )
    assert isinstance(outcome, Success), outcome
    assert outcome.value.entry_signals[0].values == (False,)


def test_an_integer_literal_enters_arithmetic_as_an_exact_decimal() -> None:
    spec = _probe_spec(
        [_bar_feature("probe")],
        _binary("equal", _literal(2, "INTEGER"), _literal("2")),
    )
    assert _entry(spec, _bars(["1"])) == (True,)


def test_string_equality_compares_by_kind_as_well_as_value() -> None:
    spec = _probe_spec(
        [_bar_feature("stamp", "bar.timestamp_utc", output_type="STRING")],
        _binary("equal", _ref("stamp"), _literal("2026-01-01T00:00:00Z", "STRING")),
    )
    assert _entry(spec, _bars(["1"])) == (True,)


@pytest.mark.parametrize(
    ("operator", "flags", "expected"),
    [
        ("and", [True, True], True),
        ("and", [True, False], False),
        ("or", [False, True], True),
        ("or", [False, False], False),
    ],
)
def test_boolean_connectives_are_complete_rather_than_short_circuiting(
    operator: str,
    flags: list[bool],
    expected: bool,
) -> None:
    spec = _probe_spec(
        [_bar_feature("probe")],
        {
            "op": operator,
            "operands": [_literal(flag, "BOOLEAN") for flag in flags],
        },
    )
    assert _entry(spec, _bars(["1"])) == (expected,)


def test_not_inverts_a_boolean_and_propagates_a_missing_operand() -> None:
    inverted = _probe_spec(
        [_bar_feature("probe")],
        {"op": "not", "operand": _literal(False, "BOOLEAN")},
    )
    assert _entry(inverted, _bars(["1"])) == (True,)
    # `not` of a MISSING comparison is MISSING, which the rule renders false —
    # never `True` by inverting an absent value.
    over_missing = _probe_spec(
        [_sma("probe", "three")],
        {"op": "not", "operand": _binary("less_than", _ref("probe"), _literal("0"))},
    )
    # Bars 0 and 1 are MISSING, so `not` yields MISSING and the rule is false.
    # Bar 2 has a value, `2 < 0` is false, and `not` genuinely inverts it.
    assert _entry(over_missing, _bars(["1", "2", "3"])) == (False, False, True)


def test_a_boolean_connective_with_a_missing_operand_is_missing() -> None:
    spec = _probe_spec(
        [_sma("probe", "three")],
        {
            "op": "and",
            "operands": [
                _literal(True, "BOOLEAN"),
                _binary("greater_than", _ref("probe"), _literal("0")),
            ],
        },
    )
    assert _entry(spec, _bars(["1", "2", "3"])) == (False, False, True)


def test_a_declared_parameter_resolves_as_a_bar_independent_constant() -> None:
    """Reference precedence's third tier, for both an integer and a decimal."""
    spec = _probe_spec(
        [_bar_feature("probe")],
        {
            "op": "and",
            "operands": [
                _binary("equal", _ref("threshold"), _literal("5")),
                _binary("equal", _ref("two"), _literal("2")),
            ],
        },
        parameters={"threshold": {"value_type": "DECIMAL", "value": "5"}},
    )
    assert _entry(spec, _bars(["1", "2"])) == (True, True)


# --- Golden scenarios: the six inputs reach the evaluator boundary -----------
#
# Plan section 6.5.3's TDD disposition is explicit that "fixture missing" is not
# an acceptable RED, and that each scenario must be shown to reach the Task 4
# evaluator boundary: the document loads, `StrategySpec` validates, and Task 3
# static validation succeeds. These tests prove exactly that, for all six inputs,
# before any expected series is compared.

_GOLDEN_INPUTS: Final = (
    "warm_up_boundary",
    "crossover_equality",
    "missing_input",
    "bar_offsets",
    "decimal_rounding",
    "adjacent_entry_exit",
)


def _input_path(scenario: str) -> Path:
    return _FIXTURES / f"{scenario}.valid.yaml"


def _golden_spec(scenario: str) -> StrategySpec:
    """Load one golden input through the real production path.

    `SourceName` forbids a path separator, so the loader receives the fixture's
    basename while the filesystem read uses the full path.
    """
    path = _input_path(scenario)
    loaded = load_yaml_document(path.read_bytes(), path.name, _OBSERVED_AT)
    assert isinstance(loaded, Success), loaded
    payload = loaded.value.value
    assert isinstance(payload, dict)
    return StrategySpec.model_validate_json(canonical_json_bytes(dict(payload)))


@pytest.mark.parametrize("scenario", _GOLDEN_INPUTS)
def test_every_golden_input_exists(scenario: str) -> None:
    assert _input_path(scenario).is_file()


@pytest.mark.parametrize("scenario", _GOLDEN_INPUTS)
def test_every_golden_input_is_utf8_without_a_bom_and_lf_only(scenario: str) -> None:
    raw = _input_path(scenario).read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf")
    assert b"\r" not in raw
    assert raw.endswith(b"\n")
    # Raises `UnicodeDecodeError` rather than substituting, so this is a proof.
    assert raw.decode("utf-8")


@pytest.mark.parametrize("scenario", _GOLDEN_INPUTS)
def test_every_golden_input_loads_through_the_safe_loader(scenario: str) -> None:
    path = _input_path(scenario)
    loaded = load_yaml_document(path.read_bytes(), path.name, _OBSERVED_AT)
    assert isinstance(loaded, Success), loaded


@pytest.mark.parametrize("scenario", _GOLDEN_INPUTS)
def test_every_golden_input_builds_a_strict_strategy_spec(scenario: str) -> None:
    assert isinstance(_golden_spec(scenario), StrategySpec)


@pytest.mark.parametrize("scenario", _GOLDEN_INPUTS)
def test_every_golden_input_passes_task_three_static_validation(scenario: str) -> None:
    outcome = validate_strategy_expressions(_golden_spec(scenario), _OBSERVED_AT)
    assert isinstance(outcome, Success), outcome


@pytest.mark.parametrize("scenario", _GOLDEN_INPUTS)
def test_every_golden_input_passes_feature_graph_validation(scenario: str) -> None:
    """No unrelated diagnostic occurs: each input reaches the evaluator clean."""
    outcome = validate_feature_graph(_golden_spec(scenario), _OBSERVED_AT)
    assert isinstance(outcome, Success), outcome


@pytest.mark.parametrize("scenario", _GOLDEN_INPUTS)
def test_every_golden_input_is_spot_long_only_and_unleveraged(scenario: str) -> None:
    spec = _golden_spec(scenario)
    assert spec.market_type.value == "SPOT"
    assert spec.direction.value == "LONG"
    assert spec.risk_assumptions.leverage == Decimal(1)
    assert spec.risk_assumptions.shorting_allowed is False
    assert spec.engine_extensions == ()


def test_the_six_golden_inputs_are_behaviourally_distinct() -> None:
    """Requirement 11: six scenarios, not six aliases of one strategy.

    Distinctness is asserted on what the evaluator actually consumes — the
    operation multiset, the declared warm-up multiset, and the rule operators —
    rather than on cosmetic fields such as the display name.
    """
    signatures = set()
    for scenario in _GOLDEN_INPUTS:
        spec = _golden_spec(scenario)
        signatures.add(
            (
                tuple(sorted(feature.operation for feature in spec.features)),
                tuple(sorted(feature.warm_up_bars for feature in spec.features)),
                tuple(rule.expression.op for rule in spec.entry_rules),
                tuple(rule.expression.op for rule in spec.exit_rules),
            )
        )
    assert len(signatures) == len(_GOLDEN_INPUTS)


# --- Golden acceptance: complete series against the reviewed expected JSON ----
#
# The expected files are review oracles, not evaluator transcripts. They were
# derived bar by bar in two independent contexts that never saw
# `strategy/evaluation.py` or any of its output, and this module only ever
# **reads** them. There is deliberately no regeneration command, no
# update-goldens option, and no code path here that writes a fixture.

_GOLDEN = _FIXTURES / "golden"

_EXPECTED_GOLDEN_FILES: Final = (
    "adjacent_entry_exit.signals.json",
    "bar_offsets.features.json",
    "crossover_equality.signals.json",
    "decimal_rounding.features.json",
    "missing_input.features.json",
    "sma_cross_long.features.json",
    "sma_cross_long.signals.json",
    "warm_up_boundary.features.json",
)

_FEATURE_GOLDENS: Final = (
    "warm_up_boundary",
    "missing_input",
    "bar_offsets",
    "decimal_rounding",
    "sma_cross_long",
)
_SIGNAL_GOLDENS: Final = (
    "sma_cross_long",
    "crossover_equality",
    "adjacent_entry_exit",
)
_ALL_GOLDEN_SCENARIOS: Final = (*_GOLDEN_INPUTS, "sma_cross_long")


def _sma_cross_long_closes() -> list[str]:
    """The frozen 54-bar close series: a unit ramp, one deep dip, then a spike.

    `close[t] = 1000 + t` for `t` in 0 to 50, then 500, 1050, 1500. The ramp keeps
    both averages exactly representable, and the last three bars are what move
    `fast_sma` below and then back above `slow_sma`.
    """
    closes = [str(1000 + index) for index in range(51)]
    closes.extend(["500", "1050", "1500"])
    return closes


_GOLDEN_BARS: Final[dict[str, tuple[Bar, ...]]] = {
    "sma_cross_long": _bars(_sma_cross_long_closes()),
    "warm_up_boundary": _bars(["1", "2", "3", "4", "5", "6"]),
    "missing_input": _bars(["2", "4", "6", "8", "10", "12"]),
    "bar_offsets": _bars(["10", "20", "30", "40", "50"]),
    "decimal_rounding": _bars(["1", "1", "0", "0", "0"]),
    "crossover_equality": _pairs(
        [("2", "2"), ("3", "2"), ("3", "3"), ("2", "3"), ("2", "2"), ("3", "2")]
    ),
    "adjacent_entry_exit": _pairs(
        [("10", "20"), ("10", "20"), ("50", "20"), ("10", "40"), ("10", "40")]
    ),
}


def _golden_document(name: str) -> dict[str, Any]:
    """Read one expected-output file. Nothing in this module ever writes one."""
    payload = json.loads((_GOLDEN / name).read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return dict(payload)


def _golden_result(scenario: str) -> EvaluationResult:
    """Evaluate one golden scenario over its frozen bar series."""
    spec = _golden_spec(scenario)
    graph = validate_feature_graph(spec, _OBSERVED_AT)
    assert isinstance(graph, Success), graph
    outcome = evaluate_level_one(
        spec, graph.value, _GOLDEN_BARS[scenario], _OBSERVED_AT
    )
    assert isinstance(outcome, Success), outcome
    return outcome.value


@pytest.mark.parametrize("name", _EXPECTED_GOLDEN_FILES)
def test_every_expected_golden_file_exists(name: str) -> None:
    assert (_GOLDEN / name).is_file()


def test_the_golden_directory_holds_exactly_the_eight_expected_files() -> None:
    """No ninth expected file, and no stray scenario, is authorized."""
    present = sorted(path.name for path in _GOLDEN.iterdir())
    assert present == sorted(_EXPECTED_GOLDEN_FILES)


@pytest.mark.parametrize("name", _EXPECTED_GOLDEN_FILES)
def test_every_golden_file_is_utf8_without_a_bom_and_lf_only(name: str) -> None:
    raw = (_GOLDEN / name).read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf")
    assert b"\r" not in raw
    assert raw.endswith(b"\n")
    assert raw.decode("utf-8")


@pytest.mark.parametrize("scenario", _FEATURE_GOLDENS)
def test_every_golden_feature_cell_is_a_canonical_string_or_null(scenario: str) -> None:
    """No `float` is ever the authority, and no negative zero is representable."""
    for series in _golden_document(f"{scenario}.features.json")["features"]:
        for cell in series["values"]:
            assert cell is None or isinstance(cell, str)
            if cell is None:
                continue
            assert cell != "-0"
            # `format_decimal` is the canonical renderer and refuses a negative
            # zero, so a clean round-trip proves the cell is canonical.
            assert format_decimal(Decimal(cell)) == cell


@pytest.mark.parametrize("scenario", _FEATURE_GOLDENS)
def test_the_complete_feature_series_matches_its_reviewed_golden(scenario: str) -> None:
    expected = _golden_document(f"{scenario}.features.json")
    result = _golden_result(scenario)
    bar_count = len(_GOLDEN_BARS[scenario])
    assert expected["bar_count"] == bar_count
    assert result.bar_count == bar_count
    actual = [
        {"feature_id": series.feature_id, "values": list(series.values)}
        for series in result.features
    ]
    # Compared whole, so a length difference, a misalignment, a reordered feature,
    # and a single wrong cell are all failures rather than silently tolerated.
    assert actual == expected["features"]
    for series in result.features:
        assert len(series.values) == bar_count


@pytest.mark.parametrize("scenario", _SIGNAL_GOLDENS)
def test_the_complete_signal_series_matches_its_reviewed_golden(scenario: str) -> None:
    expected = _golden_document(f"{scenario}.signals.json")
    result = _golden_result(scenario)
    bar_count = len(_GOLDEN_BARS[scenario])
    assert expected["bar_count"] == bar_count
    assert result.bar_count == bar_count
    for key, collected in (
        ("entry_signals", result.entry_signals),
        ("exit_signals", result.exit_signals),
    ):
        actual = [
            {"rule_id": item.rule_id, "values": list(item.values)} for item in collected
        ]
        assert actual == expected[key], key
        for item in collected:
            assert len(item.values) == bar_count
            # A signal cell is a real `bool`, never a truthy integer.
            assert all(isinstance(flag, bool) for flag in item.values)
    assert list(result.skipped_bars) == expected["skipped_bars"]
    assert len(result.skipped_bars) == bar_count


def test_no_golden_file_is_regenerated_or_rewritten_by_evaluation() -> None:
    """Evaluating every scenario must leave all eight expected files untouched."""
    before = {name: (_GOLDEN / name).read_bytes() for name in _EXPECTED_GOLDEN_FILES}
    for scenario in _ALL_GOLDEN_SCENARIOS:
        _golden_result(scenario)
    after = {name: (_GOLDEN / name).read_bytes() for name in _EXPECTED_GOLDEN_FILES}
    assert after == before


def test_no_task_four_module_exposes_a_golden_regeneration_entry_point() -> None:
    """No update-goldens option, and no snapshot writer, may exist."""
    forbidden = ("golden", "regenerate", "snapshot", "update_expected", "write_fixture")
    for module in (evaluation, feature_graph):
        for name in dir(module):
            assert not any(marker in name.lower() for marker in forbidden), name


# --- Golden acceptance: the scenario-specific behaviour each input isolates ---


def test_warm_up_boundary_separates_declared_warm_up_from_availability() -> None:
    """Declared warm-up is a lower bound on availability, not a guarantee of it."""
    result = _golden_result("warm_up_boundary")
    cells = {series.feature_id: series.values for series in result.features}
    declared = {
        feature.id: feature.warm_up_bars
        for feature in _golden_spec("warm_up_boundary").features
    }

    def first_available(feature_id: str) -> int:
        values = cells[feature_id]
        return next(
            index for index, cell in enumerate(values) if cell is not MISSING_VALUE
        )

    for feature_id, values in cells.items():
        assert all(cell is MISSING_VALUE for cell in values[: declared[feature_id]])

    assert first_available("close_now") == declared["close_now"] == 0
    # The exact first-valid warm-up bar: window three, warm-up two, so bar two.
    assert first_available("mean_three") == declared["mean_three"] == 2
    # `delayed` declares the minimum its dependency permits and still cannot carry
    # a value on that bar, because shifting reads its dependency's warm-up cell.
    assert declared["delayed"] == declared["mean_three"] == 2
    assert cells["delayed"][2] is MISSING_VALUE
    assert first_available("delayed") == 3


def test_crossover_equality_accepts_prior_and_rejects_current_equality() -> None:
    """The prior-bar clause is non-strict; the current-bar clause is strict."""
    result = _golden_result("crossover_equality")
    entry = result.entry_signals[0].values
    exits = result.exit_signals[0].values
    # Bar zero has no prior bar, so neither crossover can be evaluated.
    assert entry[0] is False
    assert exits[0] is False
    # Bar one: the prior bar is an exact tie and the current bar is strict.
    assert entry[1] is True
    # Bar two: the current bar is an exact tie, so the strict clause fails.
    assert entry[2] is False
    # Bar three: the inverse direction, prior tie accepted, current strict.
    assert exits[3] is True
    # Bar four: a current tie is rejected on the inverse direction too.
    assert exits[4] is False
    # Bar five: prior tie accepted again, proving bar one was not a one-off.
    assert entry[5] is True


def test_missing_input_is_governed_by_its_policy_and_never_by_truthiness() -> None:
    result = _golden_result("missing_input")
    cells = {series.feature_id: series.values for series in result.features}
    # Warm-up is zero everywhere, so these MISSING cells are the missing-input
    # condition itself: a four-bar window reaching before the first bar.
    assert cells["late_mean"][:3] == (MISSING_VALUE,) * 3
    assert cells["late_mean"][3] is not MISSING_VALUE
    # MISSING propagates through a dependent feature rather than becoming a value.
    assert cells["propagated"] == cells["late_mean"]
    # `PROPAGATE_FALSE` is not `SKIP_BAR`: no bar is marked skipped.
    assert result.skipped_bars == (False,) * result.bar_count
    # A rule with a MISSING operand is false, and `is_missing` reports the state
    # explicitly rather than the rule becoming true through truthiness.
    assert result.entry_signals[0].values[:3] == (False, False, False)
    assert result.exit_signals[0].values[:3] == (True, True, True)
    assert result.entry_signals[0].values[3] is True
    assert result.exit_signals[0].values[3] is False


def test_bar_offsets_reads_the_current_bar_and_positive_historical_offsets() -> None:
    """Feature-level `shift/v1`, per section 6.5.3, not `RefExpression.bars_ago`."""
    result = _golden_result("bar_offsets")
    cells = {series.feature_id: series.values for series in result.features}
    # A shift of zero bars is the current fully closed bar.
    assert cells["offset_zero"] == cells["close_now"]
    # A positive shift names an earlier closed bar and is MISSING in pre-history.
    assert cells["offset_one"][0] is MISSING_VALUE
    assert cells["offset_one"][1:] == cells["close_now"][:-1]
    assert cells["offset_two"][:2] == (MISSING_VALUE, MISSING_VALUE)
    assert cells["offset_two"][2:] == cells["close_now"][:-2]
    # A rule-level positive offset reads the earlier closed bar too, and no
    # future-reference grammar exists to invent: section 6.5.2 records that a
    # negative `bars_ago` is rejected at construction, before evaluation.
    entry = result.entry_signals[0].values
    assert entry[:2] == (False, False)
    assert entry[3] is True


def test_decimal_rounding_is_exact_and_every_zero_is_unsigned() -> None:
    result = _golden_result("decimal_rounding")
    cells = {series.feature_id: series.values for series in result.features}
    # Both quotients are computed independently through the declared context, so
    # this asserts the rounding contract rather than the evaluator against itself.
    assert cells["mean_three"][2] == format_decimal(
        EVALUATION_CONTEXT.divide(Decimal(2), Decimal(3))
    )
    assert cells["mean_three"][3] == format_decimal(
        EVALUATION_CONTEXT.divide(Decimal(1), Decimal(3))
    )
    assert cells["mean_three"][2] == "0." + "6" * 33 + "7"
    assert cells["mean_three"][3] == "0." + "3" * 34
    # Mechanical significant-digit counts, so a hand-count error in the reviewed
    # golden literal cannot survive even if both oracles miscounted identically.
    for recurring in (cells["mean_three"][2], cells["mean_three"][3]):
        assert recurring is not None
        assert len(recurring.removeprefix("0.")) == EVALUATION_PRECISION
    # An exactly zero window renders as unsigned zero on both a quotient and a sum.
    assert cells["mean_three"][4] == "0"
    assert cells["sum_three"][4] == "0"
    for values in cells.values():
        assert all(cell != "-0" for cell in values)
    # The exit rule negates a zero literal on every bar. It must stay false and
    # must not raise out of the `Result`-only contract.
    assert result.exit_signals[0].values == (False,) * result.bar_count


def test_adjacent_entry_exit_keeps_adjacent_signals_separately_aligned() -> None:
    result = _golden_result("adjacent_entry_exit")
    entry = result.entry_signals[0].values
    exits = result.exit_signals[0].values
    entry_bars = [index for index, flag in enumerate(entry) if flag]
    exit_bars = [index for index, flag in enumerate(exits) if flag]
    assert entry_bars == [2]
    assert exit_bars == [3]
    assert exit_bars[0] - entry_bars[0] == 1
    # Adjacent, yet never both true on one bar: the two series stay aligned
    # independently rather than one leaking into the other.
    assert not any(a and b for a, b in zip(entry, exits, strict=True))
    # The mean's warm-up cell at bar zero suppresses an otherwise-true exit at
    # bar one, so warm-up and signal alignment interact exactly once here.
    assert exits[1] is False


def test_sma_cross_long_remains_the_unchanged_regression_anchor() -> None:
    """Task 2 committed this input; Task 4 consumes it without modification."""
    result = _golden_result("sma_cross_long")
    cells = {series.feature_id: series.values for series in result.features}
    assert tuple(series.feature_id for series in result.features) == (
        "fast_sma",
        "slow_sma",
    )
    assert cells["fast_sma"][:20] == (MISSING_VALUE,) * 20
    assert cells["fast_sma"][20] is not MISSING_VALUE
    assert cells["slow_sma"][:50] == (MISSING_VALUE,) * 50
    assert cells["slow_sma"][50] is not MISSING_VALUE
    assert result.entry_signals[0].rule_id == "enter_cross"
    assert result.exit_signals[0].rule_id == "exit_cross"


# --- Step: the canonical rendering bound (plan section 5.9.1) ---------------
#
# A value can be finite, inside EVALUATION_PRECISION, and correctly computed,
# and still render longer than MAX_DECIMAL_TEXT_LENGTH. Before this correction
# the rendering ran outside the guarded region, so `format_decimal` raised a
# bare ValueError straight through `evaluate_level_one`, contradicting its
# documented Result-only contract.

_DECIMAL_TOO_LONG: Final = "STRATEGY.EVALUATION_DECIMAL_TOO_LONG"

#: The exact message `format_decimal` raises for the canonical length bound.
#: The evaluator maps this one message and nothing else, so a reword in
#: `crypto_lab.domain.financial` must fail loudly here.
_LENGTH_MESSAGE: Final = "canonical decimal exceeds maximum length"


def _over_long_mean_spec() -> StrategySpec:
    """A three-bar mean whose quotient needs 257 canonical characters."""
    return _probe_spec([_sma("probe", "three", warm_up_bars=2)], _ALWAYS_FALSE)


def _over_long_mean_bars() -> tuple[Bar, ...]:
    """Sum 5E-222 over period three, giving 34 digits at exponent -255."""
    return _bars(["1E-222", "2E-222", "2E-222"])


def test_an_unrenderable_feature_value_is_a_diagnostic_not_an_exception() -> None:
    """The confirmed witness from plan section 5.9.1."""
    assert _codes(_over_long_mean_spec(), _over_long_mean_bars()) == [_DECIMAL_TOO_LONG]


def test_no_exception_escapes_evaluation_for_the_unrenderable_witness() -> None:
    """The docstring contract, asserted rather than trusted."""
    outcome = _evaluate(_over_long_mean_spec(), _over_long_mean_bars())
    assert isinstance(outcome, Failure), outcome


def test_the_unrenderable_diagnostic_names_the_feature_and_omits_the_value() -> None:
    """Structural facts only: embedding the value would defeat the bound."""
    outcome = _evaluate(_over_long_mean_spec(), _over_long_mean_bars())
    assert isinstance(outcome, Failure), outcome
    (diagnostic,) = outcome.diagnostics
    assert diagnostic.error_code == _DECIMAL_TOO_LONG
    assert diagnostic.source_component == evaluation.SOURCE_COMPONENT
    assert diagnostic.details["feature_id"] == "probe"
    assert diagnostic.details["maximum_text_length"] == MAX_DECIMAL_TEXT_LENGTH
    rendered = json.dumps(diagnostic.model_dump(mode="json"))
    assert "666666666666" not in rendered


def test_the_rendering_bound_rejects_at_exactly_one_character_over() -> None:
    """Both sides of the boundary, so the guard is not an approximation."""
    # `1E-n` renders as "0." plus n-1 zeroes plus "1", so its length is n + 2.
    longest = Decimal("1E-" + str(MAX_DECIMAL_TEXT_LENGTH - 2))
    assert len(format_decimal(longest)) == MAX_DECIMAL_TEXT_LENGTH
    with pytest.raises(ValueError, match=_LENGTH_MESSAGE):
        format_decimal(longest.scaleb(-1))


def test_format_decimal_still_raises_the_exact_message_the_evaluator_maps() -> None:
    """Pin the coupling: a reword upstream must fail here, not silently escape."""
    # `match` is a substring search; the equality below is the real assertion,
    # and it is what fails if the message is reworded or merely extended.
    with pytest.raises(ValueError, match=_LENGTH_MESSAGE) as caught:
        format_decimal(Decimal("1E-250").scaleb(-10))
    assert str(caught.value) == _LENGTH_MESSAGE


def test_a_different_value_error_from_rendering_still_propagates() -> None:
    """The catch maps one message; it must not have been broadened."""

    def _other(_: Decimal) -> str:
        raise ValueError("some unrelated rendering defect")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(evaluation, "format_decimal", _other)
        with pytest.raises(ValueError, match="some unrelated rendering defect"):
            _evaluate(
                _probe_spec([_bar_feature("probe")], _ALWAYS_FALSE),
                _bars(["1", "2"]),
            )
