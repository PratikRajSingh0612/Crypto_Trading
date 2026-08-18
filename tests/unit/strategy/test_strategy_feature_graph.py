"""Test feature-graph validation and stable topological order (plan Task 4).

Task 4 owns the closed feature-operation allowlist, duplicate-ID detection,
feature-input existence and typed-input validation, cycle detection with a
canonical rotation-normalized witness, dependency warm-up sufficiency, the stable
total topological order, and the bounded diagnostic combiner of plan section
5.4.1.

Expression-level type checking and reference resolution belong to Task 3's
`tests/unit/strategy/test_strategy_validation.py`; this module covers only the
graph layer and the combiner.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.diagnostics import DiagnosticCategory, DiagnosticSeverity
from crypto_lab.domain.results import MAX_RESULT_DIAGNOSTICS, Failure, Success
from crypto_lab.strategy.feature_graph import (
    FEATURE_OPERATIONS,
    FeatureGraph,
    bounded_failure,
    topological_order,
    validate_feature_graph,
)
from crypto_lab.strategy.models import MAX_FEATURES, StrategySpec
from crypto_lab.strategy.validation import (
    SOURCE_BAR_FIELDS,
    validate_strategy_expressions,
)
from crypto_lab.strategy.yaml_source import load_yaml_document

_FIXTURES = Path(__file__).parents[2] / "fixtures" / "strategy"
_OBSERVED_AT = datetime(2026, 8, 17, tzinfo=UTC)

_DUPLICATE = "STRATEGY.FEATURE_DUPLICATE_ID"
_UNKNOWN_OPERATION = "STRATEGY.FEATURE_UNKNOWN_OPERATION"
_CYCLE = "STRATEGY.FEATURE_CYCLE"
_WARM_UP = "STRATEGY.FEATURE_WARM_UP_TOO_SMALL"
_REFERENCE_UNKNOWN = "STRATEGY.REFERENCE_UNKNOWN"
_MISMATCH = "STRATEGY.EXPRESSION_TYPE_MISMATCH"
_LIMIT = "STRATEGY.DIAGNOSTIC_LIMIT_REACHED"


def _document(name: str = "sma_cross_long.valid.yaml") -> dict[str, Any]:
    """Load a fixture through the real production path.

    `SourceName` forbids a path separator, so the loader receives the fixture's
    **basename** while the filesystem read uses the relative path. That is the
    plan's own construction rule: a source name is a bounded label, never a
    filesystem path.
    """
    path = _FIXTURES / name
    result = load_yaml_document(path.read_bytes(), path.name, _OBSERVED_AT)
    assert isinstance(result, Success), result
    value = result.value.value
    assert isinstance(value, dict)
    return dict(value)


def _spec(**overrides: object) -> StrategySpec:
    payload = _document() | overrides
    return StrategySpec.model_validate_json(canonical_json_bytes(payload))


def _feature(
    identifier: str,
    *,
    operation: str = "indicator.sma/v1",
    inputs: list[str] | None = None,
    parameters: dict[str, str] | None = None,
    output_type: str = "DECIMAL",
    warm_up_bars: int = 50,
) -> dict[str, Any]:
    """One feature definition, defaulting to the fixture's own shape."""
    return {
        "id": identifier,
        "operation": operation,
        "inputs": ["bar.close"] if inputs is None else inputs,
        "parameters": {"period": "slow_period"} if parameters is None else parameters,
        "output_type": output_type,
        "warm_up_bars": warm_up_bars,
        "missing_value_policy": "PROPAGATE_FALSE",
    }


_FAST = _feature("fast_sma", parameters={"period": "fast_period"}, warm_up_bars=20)
_SLOW = _feature("slow_sma", parameters={"period": "slow_period"}, warm_up_bars=50)


def _cyclic_pair(*, warm_up_bars: int = 50) -> list[dict[str, Any]]:
    """The fixture's two averages, each naming the other as its only input.

    A two-member cycle carrying the fixture's own periods and one shared warm-up,
    so no parameter, typing, or warm-up defect can appear beside the cycle.
    """
    return [
        _feature(
            "fast_sma",
            inputs=["slow_sma"],
            parameters={"period": "fast_period"},
            warm_up_bars=warm_up_bars,
        ),
        _feature("slow_sma", inputs=["fast_sma"], warm_up_bars=warm_up_bars),
    ]


def _derived(warm_up_bars: int) -> list[dict[str, Any]]:
    """The two averages plus one feature depending on the slower of them."""
    return [
        _FAST,
        _SLOW,
        _feature("derived", inputs=["slow_sma"], warm_up_bars=warm_up_bars),
    ]


def _bar_rules() -> dict[str, Any]:
    """Entry and exit rules over bar fields only.

    Needed whenever a test replaces `features` without keeping `fast_sma` and
    `slow_sma`: the fixture's own rules reference those two, so dropping them
    would make Task 3 contribute `STRATEGY.REFERENCE_UNKNOWN` diagnostics and
    every graph-level assertion below would be measuring the wrong thing.
    """

    def rule(identifier: str, op: str) -> dict[str, Any]:
        return {
            "id": identifier,
            "expression": {
                "op": op,
                "left": {"op": "ref", "id": "bar.close", "bars_ago": 0},
                "right": {"op": "ref", "id": "bar.open", "bars_ago": 0},
            },
        }

    return {
        "entry_rules": [rule("enter_probe", "crosses_above")],
        "exit_rules": [rule("exit_probe", "crosses_below")],
    }


def _validate(spec: StrategySpec) -> Success[FeatureGraph] | Failure:
    return validate_feature_graph(spec, _OBSERVED_AT)


def _graph(spec: StrategySpec) -> FeatureGraph:
    result = _validate(spec)
    assert isinstance(result, Success), result
    return result.value


def _failure(spec: StrategySpec) -> Failure:
    result = _validate(spec)
    assert isinstance(result, Failure), result
    return result


def _codes(spec: StrategySpec) -> list[str]:
    return [diagnostic.error_code for diagnostic in _failure(spec).diagnostics]


def _details(spec: StrategySpec, code: str) -> list[dict[str, Any]]:
    return [
        dict(diagnostic.details)
        for diagnostic in _failure(spec).diagnostics
        if diagnostic.error_code == code
    ]


# --- Step 1: duplicate feature IDs ------------------------------------------


def test_the_unchanged_fixture_specification_yields_a_valid_graph() -> None:
    graph = _graph(_spec())
    assert graph.order == ("fast_sma", "slow_sma")


def test_a_duplicate_feature_id_is_rejected() -> None:
    spec = _spec(features=[_FAST, _SLOW, _feature("fast_sma")])
    assert _codes(spec) == [_DUPLICATE]


def test_a_duplicate_feature_id_reports_the_offending_id_once() -> None:
    """Three declarations of one ID are one defect, not two."""
    spec = _spec(features=[_FAST, _feature("fast_sma"), _feature("fast_sma"), _SLOW])
    details = _details(spec, _DUPLICATE)
    assert len(details) == 1
    assert details[0]["feature_id"] == "fast_sma"
    assert details[0]["declaration_count"] == 3


def test_two_distinct_duplicate_ids_are_reported_in_feature_id_order() -> None:
    spec = _spec(
        features=[
            _feature("zulu"),
            _feature("alpha"),
            _feature("zulu"),
            _feature("alpha"),
        ],
        **_bar_rules(),
    )
    details = _details(spec, _DUPLICATE)
    assert [entry["feature_id"] for entry in details] == ["alpha", "zulu"]


# --- Step 1b: the closed feature-operation allowlist ------------------------


def test_the_allowlist_is_exactly_the_eight_planned_operations() -> None:
    assert set(FEATURE_OPERATIONS) == {
        "source.bar_field/v1",
        "expression.project/v1",
        "rolling.mean/v1",
        "rolling.sum/v1",
        "rolling.min/v1",
        "rolling.max/v1",
        "shift/v1",
        "indicator.sma/v1",
    }


def test_an_operation_outside_the_allowlist_is_rejected() -> None:
    """The model validates `operation` shape only, so this check is Task 4's."""
    spec = _spec(features=[_FAST, _SLOW, _feature("probe", operation="bogus.thing/v1")])
    assert _codes(spec) == [_UNKNOWN_OPERATION]
    assert _details(spec, _UNKNOWN_OPERATION)[0]["operation"] == "bogus.thing/v1"


def test_a_well_shaped_but_unversioned_lookalike_is_still_rejected() -> None:
    spec = _spec(
        features=[_FAST, _SLOW, _feature("probe", operation="indicator.sma/v2")]
    )
    assert _codes(spec) == [_UNKNOWN_OPERATION]


# --- Step 1c: feature-input existence and typed inputs ----------------------


def test_a_feature_input_naming_nothing_declared_is_rejected() -> None:
    spec = _spec(features=[_FAST, _SLOW, _feature("probe", inputs=["nowhere"])])
    assert _codes(spec) == [_REFERENCE_UNKNOWN]
    assert _details(spec, _REFERENCE_UNKNOWN)[0]["reference_id"] == "nowhere"


def test_every_source_bar_field_resolves_as_a_feature_input() -> None:
    for field in SOURCE_BAR_FIELDS:
        spec = _spec(
            features=[
                _FAST,
                _SLOW,
                _feature(
                    "probe",
                    operation="shift/v1",
                    inputs=[field],
                    parameters={"bars": "shift_bars"},
                    output_type=SOURCE_BAR_FIELDS[field].value,
                    warm_up_bars=1,
                ),
            ],
            parameters=_document()["parameters"]
            | {"shift_bars": {"value_type": "INTEGER", "value": 1}},
        )
        assert isinstance(_validate(spec), Success), field


def test_a_declared_feature_resolves_as_a_feature_input() -> None:
    spec = _spec(
        features=[
            _FAST,
            _SLOW,
            _feature("derived", inputs=["slow_sma"], warm_up_bars=50),
        ]
    )
    assert isinstance(_validate(spec), Success)


def test_a_string_input_to_a_numeric_operation_is_rejected() -> None:
    """`bar.timestamp_utc` is STRING, and `indicator.sma/v1` takes DECIMAL."""
    spec = _spec(
        features=[_FAST, _SLOW, _feature("probe", inputs=["bar.timestamp_utc"])]
    )
    assert _codes(spec) == [_MISMATCH]
    details = _details(spec, _MISMATCH)[0]
    assert details["observed_type"] == "STRING"
    assert details["expected_types"] == ["DECIMAL", "INTEGER"]


def test_an_unresolved_input_reports_no_cascading_type_defect() -> None:
    """One undeclared name is one diagnostic, not one per enclosing check."""
    spec = _spec(features=[_FAST, _SLOW, _feature("probe", inputs=["nowhere"])])
    assert _codes(spec).count(_MISMATCH) == 0


def test_an_unknown_operation_reports_no_cascading_type_defect() -> None:
    """An unknown operation has no signature, so its inputs cannot be typed."""
    spec = _spec(
        features=[
            _FAST,
            _SLOW,
            _feature("probe", operation="bogus.thing/v1", inputs=["bar.timestamp_utc"]),
        ]
    )
    assert _codes(spec) == [_UNKNOWN_OPERATION]


def test_an_unknown_operation_still_reports_a_missing_input() -> None:
    """Input existence does not depend on the signature, so it is still checked."""
    spec = _spec(
        features=[
            _FAST,
            _SLOW,
            _feature("probe", operation="bogus.thing/v1", inputs=["nowhere"]),
        ]
    )
    assert sorted(_codes(spec)) == [_UNKNOWN_OPERATION, _REFERENCE_UNKNOWN]


def test_a_missing_required_operation_parameter_is_rejected() -> None:
    spec = _spec(features=[_FAST, _SLOW, _feature("probe", parameters={})])
    assert _codes(spec) == [_MISMATCH]
    assert _details(spec, _MISMATCH)[0]["missing_parameter"] == "period"


def test_an_operation_parameter_naming_an_undeclared_parameter_is_rejected() -> None:
    spec = _spec(
        features=[_FAST, _SLOW, _feature("probe", parameters={"period": "nowhere"})]
    )
    assert _codes(spec) == [_REFERENCE_UNKNOWN]


def test_a_non_integer_operation_parameter_is_rejected() -> None:
    spec = _spec(
        features=[_FAST, _SLOW, _feature("probe", parameters={"period": "ratio"})],
        parameters=_document()["parameters"]
        | {"ratio": {"value_type": "DECIMAL", "value": "1.5"}},
    )
    assert _codes(spec) == [_MISMATCH]


def test_an_unexpected_operation_parameter_is_rejected() -> None:
    surplus = {"period": "slow_period", "extra": "fast_period"}
    spec = _spec(features=[_FAST, _SLOW, _feature("probe", parameters=surplus)])
    assert _codes(spec) == [_MISMATCH]
    assert _details(spec, _MISMATCH)[0]["unexpected_parameter"] == "extra"


def test_a_declared_output_type_disagreeing_with_the_signature_is_rejected() -> None:
    spec = _spec(features=[_FAST, _SLOW, _feature("probe", output_type="BOOLEAN")])
    assert _codes(spec) == [_MISMATCH]


def test_source_bar_field_requires_the_bar_field_own_type() -> None:
    spec = _spec(
        features=[
            _FAST,
            _SLOW,
            _feature(
                "probe",
                operation="source.bar_field/v1",
                inputs=["bar.timestamp_utc"],
                parameters={},
                output_type="STRING",
                warm_up_bars=0,
            ),
        ]
    )
    assert isinstance(_validate(spec), Success)


def test_source_bar_field_rejects_a_feature_input() -> None:
    """Its single input is a bar field by signature, never another feature."""
    spec = _spec(
        features=[
            _FAST,
            _SLOW,
            _feature(
                "probe",
                operation="source.bar_field/v1",
                inputs=["slow_sma"],
                parameters={},
                warm_up_bars=50,
            ),
        ]
    )
    assert _codes(spec) == [_MISMATCH]


def test_expression_project_is_the_identity_over_its_single_input() -> None:
    spec = _spec(
        features=[
            _FAST,
            _SLOW,
            _feature(
                "probe",
                operation="expression.project/v1",
                inputs=["fast_sma"],
                parameters={},
                warm_up_bars=20,
            ),
        ]
    )
    assert isinstance(_validate(spec), Success)


def test_expression_project_rejects_two_inputs() -> None:
    """`strategy/v1`'s `FeatureDefinition` carries no expression to project."""
    spec = _spec(
        features=[
            _FAST,
            _SLOW,
            _feature(
                "probe",
                operation="expression.project/v1",
                inputs=["fast_sma", "slow_sma"],
                parameters={},
                warm_up_bars=50,
            ),
        ]
    )
    assert _codes(spec) == [_MISMATCH]


def test_a_single_input_operation_rejects_two_inputs() -> None:
    spec = _spec(
        features=[
            _FAST,
            _SLOW,
            _feature("probe", inputs=["bar.close", "bar.open"]),
        ]
    )
    assert _codes(spec) == [_MISMATCH]


# --- Step 2: cycles ---------------------------------------------------------


def test_the_feature_cycle_fixture_is_rejected_with_the_cycle_code() -> None:
    payload = _document("invalid/feature_cycle.yaml")
    spec = StrategySpec.model_validate_json(canonical_json_bytes(payload))
    assert _codes(spec) == [_CYCLE]


def test_a_two_member_cycle_is_reported_rotation_normalized() -> None:
    spec = _spec(features=_cyclic_pair())
    assert _details(spec, _CYCLE)[0]["cycle"] == ["fast_sma", "slow_sma"]


def _twin_orders(field: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Two declaration orders of one duplicated identifier plus a reader of it."""
    if field == "output_type":
        first = _feature("twin", warm_up_bars=50)
        second = _feature("twin", output_type="STRING", warm_up_bars=50)
        reader = _feature("reader", inputs=["twin"], warm_up_bars=50)
    else:
        first = _feature("twin", warm_up_bars=50)
        second = _feature("twin", warm_up_bars=0)
        reader = _feature("reader", inputs=["twin"], warm_up_bars=0)
    return [first, second, reader], [second, first, reader]


@pytest.mark.parametrize("field", ["output_type", "warm_up_bars"])
def test_a_duplicated_identifier_still_yields_permutation_invariant_output(
    field: str,
) -> None:
    """Section 5.4.1 item 2 binds unconditionally, including on rejected input.

    A duplicated identifier makes the identifier-to-definition map ambiguous, and a
    plain dict resolves it last-wins. That made the derived typed-input and
    dependency-warm-up findings appear or vanish with declaration order while the
    named permutation test stayed green, because that test uses distinct
    identifiers only. Both orders are compared here as canonical bytes.
    """
    forward_features, reversed_features = _twin_orders(field)
    forward = _failure(_spec(features=forward_features, **_bar_rules()))
    backward = _failure(_spec(features=reversed_features, **_bar_rules()))
    assert _DUPLICATE in {item.error_code for item in forward.diagnostics}
    assert canonical_json_bytes(
        [item.model_dump(mode="json") for item in forward.diagnostics]
    ) == canonical_json_bytes(
        [item.model_dump(mode="json") for item in backward.diagnostics]
    )


# --- Plan section 5.4.2: the combiner absorbs an inherited marker --------------


def _overflow_rules(count: int) -> dict[str, Any]:
    """Entry rules whose Task 3 validation overflows the diagnostic bound.

    Every numeric operand of an `and` is one expression type mismatch, and `and`
    accepts at most 64 operands, so `count` findings need `count / 64` rules.
    """
    zero = {"op": "literal", "value_type": "DECIMAL", "value": "0"}
    rules: list[dict[str, Any]] = []
    remaining = count
    while remaining >= 2:
        width = min(64, remaining)
        rules.append(
            {
                "id": f"probe_{len(rules):03d}",
                "expression": {"op": "and", "operands": [zero] * width},
            }
        )
        remaining -= width
    return {
        "entry_rules": rules,
        "exit_rules": [
            {
                "id": "exit_probe",
                "expression": {
                    "op": "literal",
                    "value_type": "BOOLEAN",
                    "value": False,
                },
            }
        ],
    }


def test_an_inherited_limit_marker_is_absorbed_rather_than_sorted_inline() -> None:
    """`DIAGNOSTIC_LIMIT_REACHED` starts with `D`, so it would sort to index 0.

    Task 3 now emits its own terminal marker on overflow. The combiner re-sorts
    every inherited diagnostic on an error-code-leading key, so without absorbing
    the marker it would land first in the substantive run and the terminal slot
    would hold an ordinary diagnostic — exactly inverting the positional signal
    that plan section 5.4.1 item 6 depends on.
    """
    spec = _spec(features=[_FAST, _SLOW], **_overflow_rules(320))
    diagnostics = _failure(spec).diagnostics
    codes = [item.error_code for item in diagnostics]

    assert len(diagnostics) == MAX_RESULT_DIAGNOSTICS
    assert codes.count(_LIMIT) == 1
    assert codes[-1] == _LIMIT


def test_an_absorbed_marker_forces_a_terminal_marker_on_a_small_run() -> None:
    """An upstream truncation must surface even when this layer has few findings."""
    overflowing = validate_strategy_expressions(
        _spec(features=[_FAST, _SLOW], **_overflow_rules(320)), _OBSERVED_AT
    )
    assert isinstance(overflowing, Failure)
    inherited_marker = overflowing.diagnostics[-1]
    assert inherited_marker.error_code == _LIMIT
    assert inherited_marker.source_component == "strategy.validation"

    substantive = list(_failure(_spec(features=_cyclic_pair())).diagnostics)
    assert _LIMIT not in {item.error_code for item in substantive}

    combined = bounded_failure([inherited_marker, *substantive], _OBSERVED_AT)
    codes = [item.error_code for item in combined.diagnostics]

    assert codes.count(_LIMIT) == 1
    assert codes[-1] == _LIMIT
    assert len(combined.diagnostics) == len(substantive) + 1
    # The retained marker is the combiner's own, not the inherited one.
    assert combined.diagnostics[-1].source_component == "strategy.feature_graph"


# --- Plan section 5.10: the combiner surfaces namespace collisions -------------

_COLLISION = "STRATEGY.REFERENCE_NAMESPACE_COLLISION"


def test_a_duplicate_reserved_feature_keeps_both_diagnostics() -> None:
    """Duplicate-ID detection stays independent of namespace-collision detection.

    They live in different modules, so only the combiner sees both. Neither masks
    nor gates the other.
    """
    reserved = _feature("bar.close", inputs=["bar.close"], warm_up_bars=50)
    spec = _spec(features=[_FAST, _SLOW, reserved, reserved], **_bar_rules())
    codes = set(_codes(spec))

    assert _COLLISION in codes
    assert _DUPLICATE in codes


def test_a_namespace_invalid_specification_yields_no_feature_graph() -> None:
    """Fail-closed: no graph obtained from validation can reach the evaluator."""
    reserved = _feature("bar.high", inputs=["bar.close"], warm_up_bars=50)
    spec = _spec(features=[_FAST, _SLOW, reserved], **_bar_rules())
    outcome = _validate(spec)

    assert isinstance(outcome, Failure)
    assert _COLLISION in {item.error_code for item in outcome.diagnostics}


def test_the_witness_is_rotated_when_the_walk_enters_at_a_non_minimal_member() -> None:
    """Rotation normalization must be live, not incidentally a no-op.

    Every other cycle test happens to enter its cycle at the lexicographically
    smallest member, so normalization changes nothing and deleting it would leave
    them all green. Here `aaa` leads into the cycle at `zzz`, so the raw witness
    is `("zzz", "mmm")` and only normalization yields `("mmm", "zzz")`.
    """
    spec = _spec(
        features=[
            _feature("aaa", inputs=["zzz"]),
            _feature("zzz", inputs=["mmm"]),
            _feature("mmm", inputs=["zzz"]),
        ],
        **_bar_rules(),
    )
    assert _details(spec, _CYCLE)[0]["cycle"] == ["mmm", "zzz"]


def _diamond_chain(count: int) -> list[dict[str, Any]]:
    """An acyclic chain of `count` diamonds plus a disjoint two-member cycle.

    Each `a{i}` reads both `b{i}0` and `b{i}1`, and both of those read `a{i+1}`, so
    there are `2 ** count` distinct paths from `a00` to `a{count}` across only
    `3 * count + 3` features. The cycle is `z0 <-> z1`, named so it sorts last, and
    the chain is named so `a00` sorts first — therefore the search must exhaust the
    entire exponential chain before it reaches the cycle at all.
    """
    features: list[dict[str, Any]] = []
    for index in range(count):
        head = f"a{index:02d}"
        legs = [f"b{index:02d}0", f"b{index:02d}1"]
        features.append(_feature(head, inputs=legs))
        features.extend(_feature(leg, inputs=[f"a{index + 1:02d}"]) for leg in legs)
    features.append(_feature(f"a{count:02d}", inputs=["bar.close"]))
    features.append(_feature("z0", inputs=["z1"]))
    features.append(_feature("z1", inputs=["z0"]))
    return features


def test_the_cycle_search_is_bounded_by_edges_not_by_distinct_paths() -> None:
    """A document inside every declared bound must not cost unbounded time.

    Forty diamonds is 123 features — well under `MAX_FEATURES` — but `2 ** 40`
    distinct paths. A search that re-explores a node once per path reaching it
    cannot complete this in any practical time, so merely returning is the
    assertion. Marking a node finished once its successors are exhausted makes the
    walk linear in edges, and cannot change the witness.
    """
    spec = _spec(features=_diamond_chain(40), **_bar_rules())
    assert len(spec.features) == 123
    assert _details(spec, _CYCLE)[0]["cycle"] == ["z0", "z1"]


def test_a_self_referencing_feature_is_a_one_member_cycle() -> None:
    spec = _spec(features=[_FAST, _feature("slow_sma", inputs=["slow_sma"])])
    assert _details(spec, _CYCLE)[0]["cycle"] == ["slow_sma"]


def test_a_cycle_witness_starts_at_its_lexicographically_smallest_member() -> None:
    spec = _spec(
        features=[
            _FAST,
            _feature("mike", inputs=["zulu"]),
            _feature("zulu", inputs=["alpha"]),
            _feature("alpha", inputs=["mike"]),
            _SLOW,
        ]
    )
    assert _details(spec, _CYCLE)[0]["cycle"] == ["alpha", "mike", "zulu"]


@pytest.mark.parametrize("rotation", [0, 1, 2])
def test_the_same_cycle_declared_in_a_different_source_order_is_identical(
    rotation: int,
) -> None:
    """Source-order permutation must not move the witness or the diagnostic."""
    members = [
        _feature("mike", inputs=["zulu"]),
        _feature("zulu", inputs=["alpha"]),
        _feature("alpha", inputs=["mike"]),
    ]
    rotated = members[rotation:] + members[:rotation]
    spec = _spec(features=[_FAST, _SLOW, *rotated])
    baseline = _spec(features=[_FAST, _SLOW, *members])
    assert canonical_json_bytes(
        [
            diagnostic.model_dump(mode="json")
            for diagnostic in _failure(spec).diagnostics
        ]
    ) == canonical_json_bytes(
        [
            diagnostic.model_dump(mode="json")
            for diagnostic in _failure(baseline).diagnostics
        ]
    )


def test_a_cycle_suppresses_warm_up_and_topological_order() -> None:
    """Both are undefined on a cyclic graph, so neither is attempted."""
    spec = _spec(features=_cyclic_pair(warm_up_bars=0))
    assert _codes(spec) == [_CYCLE]


def test_a_cycle_does_not_suppress_a_duplicate_id() -> None:
    """Duplicate-ID detection does not depend on acyclicity."""
    spec = _spec(features=[*_cyclic_pair(), _feature("slow_sma", inputs=["fast_sma"])])
    assert sorted(set(_codes(spec))) == [_CYCLE, _DUPLICATE]


def test_no_unrelated_diagnostic_masks_the_feature_cycle_fixture() -> None:
    """The fixture must isolate the cycle: exactly one diagnostic, the cycle."""
    payload = _document("invalid/feature_cycle.yaml")
    spec = StrategySpec.model_validate_json(canonical_json_bytes(payload))
    failure = _failure(spec)
    assert len(failure.diagnostics) == 1
    diagnostic = failure.diagnostics[0]
    assert diagnostic.error_code == _CYCLE
    assert diagnostic.category is DiagnosticCategory.SCHEMA_VALIDATION
    assert diagnostic.severity is DiagnosticSeverity.ERROR


# --- Step 3: stable total topological order ---------------------------------


def test_topological_order_places_every_dependency_first() -> None:
    spec = _spec(
        features=[
            _feature("third", inputs=["second"]),
            _feature("second", inputs=["first"]),
            _feature("first", inputs=["bar.close"]),
        ],
        **_bar_rules(),
    )
    order = _graph(spec).order
    assert order.index("first") < order.index("second") < order.index("third")


def test_topological_order_breaks_ties_by_feature_id() -> None:
    spec = _spec(
        features=[
            _feature("zulu"),
            _feature("mike"),
            _feature("alpha"),
        ],
        **_bar_rules(),
    )
    assert _graph(spec).order == ("alpha", "mike", "zulu")


def test_topological_order_is_a_pure_function_of_the_dependency_mapping() -> None:
    """The exported helper is the ordering itself, not an accessor."""
    assert topological_order(
        {
            "charlie": frozenset({"bravo"}),
            "bravo": frozenset({"alpha"}),
            "alpha": frozenset(),
        }
    ) == ("alpha", "bravo", "charlie")


def test_topological_order_returns_none_for_a_cyclic_mapping() -> None:
    cyclic = {"a": frozenset({"b"}), "b": frozenset({"a"})}
    assert topological_order(cyclic) is None


def test_topological_order_is_total_over_every_declared_feature() -> None:
    spec = _spec(features=[_FAST, _SLOW, _feature("derived", inputs=["slow_sma"])])
    graph = _graph(spec)
    assert set(graph.order) == {"fast_sma", "slow_sma", "derived"}
    assert len(graph.order) == 3


def test_topological_order_is_independent_of_source_order() -> None:
    features = [
        _feature("third", inputs=["second"]),
        _feature("second", inputs=["first"]),
        _feature("first", inputs=["bar.close"]),
    ]
    reversed_spec = _spec(features=list(reversed(features)), **_bar_rules())
    forward = _graph(_spec(features=features, **_bar_rules())).order
    backward = _graph(reversed_spec).order
    assert forward == backward == ("first", "second", "third")


def test_topological_order_prefers_the_smallest_ready_id_at_every_step() -> None:
    """A ready-set tie must resolve by ID, not by insertion order."""
    spec = _spec(
        features=[
            _feature("bravo", inputs=["bar.close"]),
            _feature("alpha", inputs=["bar.close"]),
            _feature("charlie", inputs=["bravo"]),
        ],
        **_bar_rules(),
    )
    assert _graph(spec).order == ("alpha", "bravo", "charlie")


def test_a_specification_with_no_feature_yields_an_empty_order() -> None:
    spec = _spec(features=[], warm_up_requirements={"minimum_bars": 0}, **_bar_rules())
    assert _graph(spec).order == ()


# --- Step 4: dependency warm-up sufficiency ---------------------------------


def test_declared_warm_up_below_the_dependency_maximum_is_rejected() -> None:
    spec = _spec(features=_derived(49))
    assert _codes(spec) == [_WARM_UP]
    details = _details(spec, _WARM_UP)[0]
    assert details["declared_warm_up_bars"] == 49
    assert details["required_warm_up_bars"] == 50


def test_declared_warm_up_equal_to_the_dependency_maximum_is_accepted() -> None:
    spec = _spec(features=_derived(50))
    assert isinstance(_validate(spec), Success)


def test_a_bar_field_dependency_requires_no_warm_up() -> None:
    spec = _spec(
        features=[
            _FAST,
            _SLOW,
            _feature("derived", inputs=["bar.close"], warm_up_bars=0),
        ]
    )
    assert isinstance(_validate(spec), Success)


def test_the_dependency_maximum_is_the_maximum_not_the_first() -> None:
    """Warm-up does not depend on the signature, so an arity defect cannot hide it.

    No allowlisted operation takes two inputs, so the `max` over several
    dependencies is only reachable on a feature that also fails its arity check.
    Warm-up is therefore computed over every resolvable feature input regardless
    of signature validity, exactly as input existence is.
    """
    spec = _spec(
        features=[
            _FAST,
            _SLOW,
            _feature("derived", inputs=["fast_sma", "slow_sma"], warm_up_bars=20),
        ]
    )
    details = _details(spec, _WARM_UP)[0]
    assert details["required_warm_up_bars"] == 50
    assert _MISMATCH in _codes(spec)


# --- Section 5.4.1: the bounded diagnostic combiner -------------------------


def _defective(pairs: int, singles: int) -> StrategySpec:
    """Return a spec producing exactly `2 * pairs + singles` unique diagnostics.

    A feature whose operation is outside the allowlist yields one
    unknown-operation finding; an input naming nothing declared yields one
    reference finding; the two are independent, because input existence does not
    depend on the signature. `fast_sma` and `slow_sma` are retained so the
    fixture's own rules still resolve and Task 3 contributes nothing.
    """
    features = [_FAST, _SLOW]
    for index in range(pairs):
        features.append(
            _feature(
                f"pair{index:03d}",
                operation="bogus.thing/v1",
                inputs=[f"nowhere{index:03d}"],
                parameters={},
                warm_up_bars=0,
            )
        )
    for index in range(singles):
        features.append(
            _feature(
                f"single{index:03d}",
                operation="bogus.thing/v1",
                inputs=["bar.close"],
                parameters={},
                warm_up_bars=0,
            )
        )
    return _spec(features=features)


def test_the_defect_generator_produces_exactly_the_requested_count() -> None:
    """Guards every bound test below from being vacuous."""
    assert len(_failure(_defective(1, 0)).diagnostics) == 2
    assert len(_failure(_defective(0, 1)).diagnostics) == 1
    assert len(_failure(_defective(3, 2)).diagnostics) == 8


def test_the_generator_stays_inside_the_model_feature_bound() -> None:
    assert 2 + 128 + 1 <= MAX_FEATURES


def test_two_hundred_fifty_five_unique_diagnostics_carry_no_marker() -> None:
    diagnostics = _failure(_defective(127, 1)).diagnostics
    assert len(diagnostics) == 255
    assert _LIMIT not in {diagnostic.error_code for diagnostic in diagnostics}


def test_two_hundred_fifty_six_unique_diagnostics_carry_no_marker() -> None:
    """The exact boundary at which diagnostics are still complete."""
    diagnostics = _failure(_defective(128, 0)).diagnostics
    assert len(diagnostics) == MAX_RESULT_DIAGNOSTICS == 256
    assert _LIMIT not in {diagnostic.error_code for diagnostic in diagnostics}


def test_two_hundred_fifty_seven_unique_diagnostics_carry_a_terminal_marker() -> None:
    diagnostics = _failure(_defective(128, 1)).diagnostics
    assert len(diagnostics) == MAX_RESULT_DIAGNOSTICS
    assert diagnostics[-1].error_code == _LIMIT
    substantive = diagnostics[:-1]
    assert len(substantive) == 255
    assert _LIMIT not in {diagnostic.error_code for diagnostic in substantive}


def test_the_limit_marker_carries_its_exact_fixed_contract() -> None:
    marker = _failure(_defective(128, 1)).diagnostics[-1]
    assert marker.error_code == _LIMIT
    assert marker.severity is DiagnosticSeverity.ERROR
    assert marker.category is DiagnosticCategory.SCHEMA_VALIDATION
    assert marker.retriable is False
    assert marker.timestamp_utc == _OBSERVED_AT
    assert marker.causal_diagnostic_ids == ()
    assert marker.details == {
        "diagnostic_limit": 256,
        "retained_diagnostics": 255,
    }


def test_the_limit_marker_publishes_no_omitted_count() -> None:
    """The combiner may stop early, so it cannot know the true total."""
    marker = _failure(_defective(200, 1)).diagnostics[-1]
    assert set(marker.details) == {"diagnostic_limit", "retained_diagnostics"}


def test_the_marker_is_byte_identical_across_overflow_sizes() -> None:
    """Fixing `retained_diagnostics` at 255 keeps its derived identity constant."""
    small = _failure(_defective(128, 1)).diagnostics[-1]
    large = _failure(_defective(200, 40)).diagnostics[-1]
    assert small.diagnostic_id == large.diagnostic_id
    assert small.model_dump(mode="json") == large.model_dump(mode="json")


def test_deduplication_precedes_the_output_bound() -> None:
    """Duplicated findings must not consume the bound."""
    features = [_FAST, _SLOW]
    for index in range(120):
        entry = _feature(
            f"pair{index:03d}",
            operation="bogus.thing/v1",
            inputs=[f"nowhere{index:03d}"],
            parameters={},
            warm_up_bars=0,
        )
        features.extend([entry, dict(entry)])
    spec = _spec(features=features)
    diagnostics = _failure(spec).diagnostics
    codes = [diagnostic.error_code for diagnostic in diagnostics]
    # 120 unknown-operation + 120 reference + 120 duplicate-ID = 360 raw findings
    # collapse to 120 + 120 + 120 unique; the identical pair members dedup.
    assert len(diagnostics) == MAX_RESULT_DIAGNOSTICS
    assert codes[-1] == _LIMIT
    assert len(set(diagnostic.diagnostic_id for diagnostic in diagnostics)) == len(
        diagnostics
    )


def test_a_duplicated_defect_below_the_bound_returns_no_marker() -> None:
    entry = _feature(
        "probe",
        operation="bogus.thing/v1",
        inputs=["nowhere"],
        parameters={},
        warm_up_bars=0,
    )
    spec = _spec(features=[_FAST, _SLOW, entry, dict(entry), dict(entry)])
    codes = sorted(_codes(spec))
    assert codes == [_DUPLICATE, _UNKNOWN_OPERATION, _REFERENCE_UNKNOWN]


@pytest.mark.parametrize(("pairs", "singles"), [(127, 1), (128, 0), (128, 1)])
def test_source_order_permutation_is_byte_identical_at_the_boundary(
    pairs: int,
    singles: int,
) -> None:
    baseline = _failure(_defective(pairs, singles))
    permuted_features = list(reversed(list(_defective(pairs, singles).features)))
    permuted = _failure(
        _spec(
            features=[feature.model_dump(mode="json") for feature in permuted_features]
        )
    )
    assert canonical_json_bytes(
        [item.model_dump(mode="json") for item in baseline.diagnostics]
    ) == canonical_json_bytes(
        [item.model_dump(mode="json") for item in permuted.diagnostics]
    )


@pytest.mark.parametrize(("pairs", "singles"), [(127, 1), (128, 0), (128, 1)])
def test_no_expected_boundary_exception_escapes(pairs: int, singles: int) -> None:
    """Crossing the bound is an expected outcome, never a raised error."""
    result = _validate(_defective(pairs, singles))
    assert isinstance(result, Failure)


def test_overflow_is_distinguishable_from_an_exact_full_result() -> None:
    """No silent slicing: 257 must not look like 256."""
    exact = _failure(_defective(128, 0)).diagnostics
    overflowing = _failure(_defective(128, 1)).diagnostics
    assert len(exact) == len(overflowing) == MAX_RESULT_DIAGNOSTICS
    assert exact[-1].error_code != _LIMIT
    assert overflowing[-1].error_code == _LIMIT


def test_the_existing_failure_schema_is_unchanged() -> None:
    assert MAX_RESULT_DIAGNOSTICS == 256
    assert set(Failure.model_fields) == {"outcome", "diagnostics"}
    metadata = Failure.model_fields["diagnostics"].metadata
    bounds = {
        name: getattr(item, name)
        for item in metadata
        for name in ("min_length", "max_length")
        if getattr(item, name, None) is not None
    }
    assert bounds == {"min_length": 1, "max_length": 256}


def test_every_combined_diagnostic_carries_no_correlation_identifier() -> None:
    """Plan section 5.4.1 item 0, which the ordering-key totality proof needs."""
    for diagnostic in _failure(_defective(128, 1)).diagnostics:
        dumped = diagnostic.model_dump(mode="json")
        for absent in ("experiment_id", "run_id", "invocation_id", "engine"):
            assert absent not in dumped
        assert diagnostic.causal_diagnostic_ids == ()


def test_expression_and_graph_diagnostics_are_combined() -> None:
    """The combiner merges Task 3's output with its own, by source component."""
    spec = _spec(
        features=[_FAST, _SLOW, _feature("probe", operation="bogus.thing/v1")],
        entry_rules=[
            {
                "id": "enter_probe",
                "expression": {"op": "ref", "id": "undeclared", "bars_ago": 0},
            }
        ],
    )
    failure = _failure(spec)
    components = {diagnostic.source_component for diagnostic in failure.diagnostics}
    assert components == {"strategy.validation", "strategy.feature_graph"}


def test_the_diagnostics_are_ordered_by_the_documented_total_key() -> None:
    spec = _spec(
        features=[
            _FAST,
            _SLOW,
            _feature("zulu", operation="bogus.thing/v1", parameters={}),
            _feature("alpha", operation="bogus.thing/v1", parameters={}),
        ],
    )
    details = _details(spec, _UNKNOWN_OPERATION)
    assert [entry["feature_id"] for entry in details] == ["alpha", "zulu"]


def test_two_independent_runs_over_equal_inputs_are_byte_identical() -> None:
    first = _failure(_defective(3, 2))
    second = _failure(_defective(3, 2))
    assert canonical_json_bytes(
        [item.model_dump(mode="json") for item in first.diagnostics]
    ) == canonical_json_bytes(
        [item.model_dump(mode="json") for item in second.diagnostics]
    )
