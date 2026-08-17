"""Decimal and missing-value invariants of the Level 1 evaluator (plan Task 4).

Plan Task 4 step 10: evaluation is a pure function of `(spec, bars)`; two calls
with equal inputs return equal outputs; and the process-global Decimal context is
unchanged after evaluation. These are asserted over generated bar series rather
than over hand-chosen ones, so a defect that only appears for some price shape is
reachable.
"""

from __future__ import annotations

import decimal
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.results import Failure, Success
from crypto_lab.strategy.evaluation import (
    MISSING_VALUE,
    Bar,
    evaluate_level_one,
)
from crypto_lab.strategy.feature_graph import FeatureGraph, validate_feature_graph
from crypto_lab.strategy.models import StrategySpec
from crypto_lab.strategy.yaml_source import load_yaml_document

_FIXTURES = Path(__file__).parents[1] / "fixtures" / "strategy"
_OBSERVED_AT = datetime(2026, 8, 17, tzinfo=UTC)
_EPOCH = datetime(2026, 1, 1, tzinfo=UTC)


def _document() -> dict[str, Any]:
    path = _FIXTURES / "sma_cross_long.valid.yaml"
    result = load_yaml_document(path.read_bytes(), path.name, _OBSERVED_AT)
    assert isinstance(result, Success), result
    value = result.value.value
    assert isinstance(value, dict)
    return dict(value)


_DOCUMENT = _document()


def _spec(**overrides: object) -> StrategySpec:
    return StrategySpec.model_validate_json(canonical_json_bytes(_DOCUMENT | overrides))


def _graph(spec: StrategySpec) -> FeatureGraph:
    result = validate_feature_graph(spec, _OBSERVED_AT)
    assert isinstance(result, Success), result
    return result.value


def _probe_spec() -> StrategySpec:
    """A small spec exercising a rolling mean, a shift, and a crossover."""
    return _spec(
        parameters={
            "two": {"value_type": "INTEGER", "value": 2},
            "three": {"value_type": "INTEGER", "value": 3},
            "one": {"value_type": "INTEGER", "value": 1},
        },
        features=[
            {
                "id": "close_field",
                "operation": "source.bar_field/v1",
                "inputs": ["bar.close"],
                "parameters": {},
                "output_type": "DECIMAL",
                "warm_up_bars": 0,
                "missing_value_policy": "PROPAGATE_FALSE",
            },
            {
                "id": "fast_mean",
                "operation": "rolling.mean/v1",
                "inputs": ["close_field"],
                "parameters": {"window": "two"},
                "output_type": "DECIMAL",
                "warm_up_bars": 1,
                "missing_value_policy": "PROPAGATE_FALSE",
            },
            {
                "id": "slow_mean",
                "operation": "rolling.mean/v1",
                "inputs": ["close_field"],
                "parameters": {"window": "three"},
                "output_type": "DECIMAL",
                "warm_up_bars": 2,
                "missing_value_policy": "PROPAGATE_FALSE",
            },
            {
                "id": "lagged",
                "operation": "shift/v1",
                "inputs": ["fast_mean"],
                "parameters": {"bars": "one"},
                "output_type": "DECIMAL",
                "warm_up_bars": 1,
                "missing_value_policy": "PROPAGATE_FALSE",
            },
        ],
        entry_rules=[
            {
                "id": "enter_probe",
                "expression": {
                    "op": "crosses_above",
                    "left": {"op": "ref", "id": "fast_mean", "bars_ago": 0},
                    "right": {"op": "ref", "id": "slow_mean", "bars_ago": 0},
                },
            }
        ],
        exit_rules=[
            {
                "id": "exit_probe",
                "expression": {
                    "op": "crosses_below",
                    "left": {"op": "ref", "id": "fast_mean", "bars_ago": 0},
                    "right": {"op": "ref", "id": "slow_mean", "bars_ago": 0},
                },
            }
        ],
        warm_up_requirements={"minimum_bars": 2},
    )


_SPEC = _probe_spec()
_GRAPH = _graph(_SPEC)

# Bounded, canonical, non-negative prices with at most two decimal places, so
# every generated value is representable as a canonical Decimal string.
_prices = st.lists(
    st.integers(min_value=1, max_value=100_000).map(
        lambda cents: Decimal(cents).scaleb(-2)
    ),
    min_size=0,
    max_size=24,
)


def _bars(prices: list[Decimal]) -> tuple[Bar, ...]:
    return tuple(
        Bar(
            timestamp_utc=_EPOCH + timedelta(hours=index),
            open=price,
            high=price,
            low=price,
            close=price,
            volume=Decimal(1),
        )
        for index, price in enumerate(prices)
    )


def _evaluate(bars: tuple[Bar, ...]) -> Success[Any] | Failure:
    return evaluate_level_one(_SPEC, _GRAPH, bars, _OBSERVED_AT)


@settings(max_examples=60)
@given(_prices)
def test_evaluation_is_a_pure_function_of_its_inputs(prices: list[Decimal]) -> None:
    bars = _bars(prices)
    first = _evaluate(bars)
    second = _evaluate(bars)
    assert isinstance(first, Success)
    assert isinstance(second, Success)
    assert canonical_json_bytes(
        first.value.model_dump(mode="json")
    ) == canonical_json_bytes(second.value.model_dump(mode="json"))


@settings(max_examples=60)
@given(_prices)
def test_the_global_decimal_context_is_unchanged_by_evaluation(
    prices: list[Decimal],
) -> None:
    before = decimal.getcontext()
    precision = before.prec
    rounding = before.rounding
    flags = dict(before.flags)
    _evaluate(_bars(prices))
    after = decimal.getcontext()
    assert after is before
    assert after.prec == precision
    assert after.rounding == rounding
    assert dict(after.flags) == flags


@settings(max_examples=60)
@given(_prices)
def test_every_series_is_complete_and_aligned_to_the_bar_count(
    prices: list[Decimal],
) -> None:
    bars = _bars(prices)
    outcome = _evaluate(bars)
    assert isinstance(outcome, Success)
    result = outcome.value
    assert result.bar_count == len(bars)
    assert len(result.skipped_bars) == len(bars)
    for series in result.features:
        assert len(series.values) == len(bars)
    for signal in (*result.entry_signals, *result.exit_signals):
        assert len(signal.values) == len(bars)


@settings(max_examples=60)
@given(_prices)
def test_every_cell_before_declared_warm_up_is_missing(
    prices: list[Decimal],
) -> None:
    """The prefix half of the warm-up contract, which holds unconditionally.

    The converse does **not** hold in general, and this property exists partly to
    record that: declared warm-up being at least the maximum dependency warm-up —
    all specification line 701 requires — does not make a feature available
    immediately afterwards. `lagged` shifts `fast_mean` by one bar while declaring
    a warm-up of one, which satisfies the graph rule because `fast_mean` also
    declares one, yet `lagged` cannot be available until bar two. Availability is
    therefore asserted only for the features whose window provably fits.
    """
    bars = _bars(prices)
    outcome = _evaluate(bars)
    assert isinstance(outcome, Success)
    declared = {feature.id: feature.warm_up_bars for feature in _SPEC.features}
    provably_available = {"close_field", "fast_mean", "slow_mean"}
    for series in outcome.value.features:
        warm_up = declared[series.feature_id]
        for index, cell in enumerate(series.values):
            if index < warm_up:
                assert cell is MISSING_VALUE
            elif series.feature_id in provably_available:
                assert cell is not MISSING_VALUE


@settings(max_examples=40)
@given(_prices)
def test_a_shift_beyond_its_dependency_warm_up_stays_missing_one_bar_longer(
    prices: list[Decimal],
) -> None:
    """Pins the finding above, so it cannot regress into an unnoticed change."""
    outcome = _evaluate(_bars(prices))
    assert isinstance(outcome, Success)
    lagged = next(
        series for series in outcome.value.features if series.feature_id == "lagged"
    )
    if len(lagged.values) > 1:
        assert lagged.values[1] is MISSING_VALUE
    if len(lagged.values) > 2:
        assert lagged.values[2] is not MISSING_VALUE


@settings(max_examples=60)
@given(_prices)
def test_no_signal_is_true_on_a_bar_carrying_a_missing_operand(
    prices: list[Decimal],
) -> None:
    """A rule containing MISSING is false and never true through truthiness."""
    bars = _bars(prices)
    outcome = _evaluate(bars)
    assert isinstance(outcome, Success)
    result = outcome.value
    cells = {series.feature_id: series.values for series in result.features}
    for signal in (*result.entry_signals, *result.exit_signals):
        for index, flag in enumerate(signal.values):
            if not flag:
                continue
            # Both rules read `fast_mean` and `slow_mean` at the current and the
            # prior bar, so a true signal requires all four to be present.
            assert index >= 1
            for name in ("fast_mean", "slow_mean"):
                assert cells[name][index] is not MISSING_VALUE
                assert cells[name][index - 1] is not MISSING_VALUE


@settings(max_examples=60)
@given(_prices)
def test_entry_and_exit_are_never_both_true_on_one_bar(
    prices: list[Decimal],
) -> None:
    """`crosses_above` and `crosses_below` are mutually exclusive at a bar."""
    outcome = _evaluate(_bars(prices))
    assert isinstance(outcome, Success)
    result = outcome.value
    entries = result.entry_signals[0].values
    exits = result.exit_signals[0].values
    for entry, exit_flag in zip(entries, exits, strict=True):
        assert not (entry and exit_flag)


@settings(max_examples=60)
@given(_prices)
def test_a_rendered_decimal_cell_is_always_canonical(
    prices: list[Decimal],
) -> None:
    """No cell may carry a negative zero, an exponent, or a trailing zero."""
    outcome = _evaluate(_bars(prices))
    assert isinstance(outcome, Success)
    for series in outcome.value.features:
        for cell in series.values:
            if cell is MISSING_VALUE:
                continue
            assert not cell.startswith("-0")
            assert "e" not in cell.casefold()
            if "." in cell:
                assert not cell.endswith("0")


@settings(max_examples=40)
@given(_prices)
def test_a_constant_price_series_yields_no_crossover(
    prices: list[Decimal],
) -> None:
    """A flat series can never cross, whatever its level."""
    if not prices:
        return
    flat = _bars([prices[0]] * len(prices))
    outcome = _evaluate(flat)
    assert isinstance(outcome, Success)
    result = outcome.value
    assert not any(result.entry_signals[0].values)
    assert not any(result.exit_signals[0].values)
