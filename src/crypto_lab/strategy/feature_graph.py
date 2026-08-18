"""Feature-graph validation, cycle diagnostics, and stable topological order.

Specification section 12.3.1 line 701 fixes what this layer owes: "A feature
graph must be acyclic, every input must exist and type-check, and declared warm-up
must be at least the maximum dependency warm-up." Each of those three, plus
duplicate-ID detection and the closed feature-operation allowlist, is checked
here.

The operation allowlist is data, never callables: a strategy-supplied operation
string selects a ``NamedTuple`` of bounds, and evaluation semantics live in
``strategy/evaluation.py`` behind an ``if`` chain over the same closed names. No
operation name resolves a Python attribute or callable.

This module also owns the Stage 4 bounded diagnostic combiner of plan section
5.4.1. It merges Task 3's expression diagnostics with its own graph diagnostics,
deduplicates them, orders them by the documented total key, and bounds the result
with an explicit terminal marker rather than a silent slice.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Final, NamedTuple, cast

from pydantic import Field, JsonValue

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.diagnostics import (
    Diagnostic,
    DiagnosticCategory,
    DiagnosticDetailValue,
    DiagnosticSeverity,
)
from crypto_lab.domain.hashing import HashingProfile, _uuid4_shaped, profile_hash
from crypto_lab.domain.identifiers import NormalizedIdentifier
from crypto_lab.domain.results import (
    MAX_RESULT_DIAGNOSTICS,
    Failure,
    Result,
    Success,
)
from crypto_lab.strategy.expressions import LiteralValueType
from crypto_lab.strategy.models import (
    MAX_FEATURES,
    FeatureDefinition,
    ParameterDefinition,
    StrategySpec,
)
from crypto_lab.strategy.validation import (
    SOURCE_BAR_FIELDS,
    validate_strategy_expressions,
)

SOURCE_COMPONENT: Final = "strategy.feature_graph"

NUMERIC_TYPES: Final = frozenset({LiteralValueType.INTEGER, LiteralValueType.DECIMAL})

DIAGNOSTIC_LIMIT_REACHED: Final = "STRATEGY.DIAGNOSTIC_LIMIT_REACHED"


class _FeatureSignature(NamedTuple):
    """One allowlist entry's typed signature. Plain data, never a callable."""

    input_count: int
    accepted_input_types: frozenset[LiteralValueType] | None
    input_must_be_bar_field: bool
    required_parameters: tuple[str, ...]
    output_type: LiteralValueType | None


# The eight operations the plan's Task 4 section fixes, with the typed signatures
# Task 4 authors. ``accepted_input_types = None`` accepts every literal type and
# ``output_type = None`` mirrors the single input's type.
#
# ``expression.project/v1`` takes exactly one input and is the identity over it.
# That is a deliberate minimum, not an oversight: specification line 701 calls the
# operation "arithmetic/boolean expression projection", but ``FeatureDefinition``
# in ``strategy/v1`` carries no field able to hold the expression to project, so a
# richer projection is unrepresentable until a later model version adds one.
# Inventing a multi-input reduction here would invent economic semantics the
# approved plan does not grant.
FEATURE_OPERATIONS: Final[Mapping[str, _FeatureSignature]] = {
    "source.bar_field/v1": _FeatureSignature(1, None, True, (), None),
    "expression.project/v1": _FeatureSignature(1, NUMERIC_TYPES, False, (), None),
    "rolling.mean/v1": _FeatureSignature(
        1, NUMERIC_TYPES, False, ("window",), LiteralValueType.DECIMAL
    ),
    "rolling.sum/v1": _FeatureSignature(
        1, NUMERIC_TYPES, False, ("window",), LiteralValueType.DECIMAL
    ),
    "rolling.min/v1": _FeatureSignature(
        1, NUMERIC_TYPES, False, ("window",), LiteralValueType.DECIMAL
    ),
    "rolling.max/v1": _FeatureSignature(
        1, NUMERIC_TYPES, False, ("window",), LiteralValueType.DECIMAL
    ),
    "shift/v1": _FeatureSignature(1, None, False, ("bars",), None),
    "indicator.sma/v1": _FeatureSignature(
        1, NUMERIC_TYPES, False, ("period",), LiteralValueType.DECIMAL
    ),
}

# A window must span at least one bar; a shift of zero bars is the current bar and
# is legitimate. Bounded here rather than in the model because the admissible
# range is a property of the operation, not of the parameter.
PARAMETER_MINIMUM: Final[Mapping[str, int]] = {
    "window": 1,
    "period": 1,
    "bars": 0,
}

_DUPLICATE_ID: Final = "STRATEGY.FEATURE_DUPLICATE_ID"
_UNKNOWN_OPERATION: Final = "STRATEGY.FEATURE_UNKNOWN_OPERATION"
_CYCLE: Final = "STRATEGY.FEATURE_CYCLE"
_WARM_UP_TOO_SMALL: Final = "STRATEGY.FEATURE_WARM_UP_TOO_SMALL"
_REFERENCE_UNKNOWN: Final = "STRATEGY.REFERENCE_UNKNOWN"
_TYPE_MISMATCH: Final = "STRATEGY.EXPRESSION_TYPE_MISMATCH"
_PARAMETER_OUT_OF_BOUNDS: Final = "STRATEGY.PARAMETER_OUT_OF_BOUNDS"

# Each producer owns its own wording, per the plan's section 5.4.1 ordering proof:
# `STRATEGY.EXPRESSION_TYPE_MISMATCH` and `STRATEGY.REFERENCE_UNKNOWN` are shared
# with Task 3, whose committed literals are expression-worded and would misdescribe
# a feature-level defect. `source_component` is in the ordering key precisely so
# the two producers may differ here.
_MESSAGES: Final[Mapping[str, str]] = {
    _DUPLICATE_ID: "strategy declares one feature identifier more than once",
    _UNKNOWN_OPERATION: (
        "strategy feature declares an operation outside the closed allowlist"
    ),
    _CYCLE: "strategy feature graph contains a dependency cycle",
    _WARM_UP_TOO_SMALL: (
        "strategy feature declares fewer warm-up bars than its dependencies require"
    ),
    _REFERENCE_UNKNOWN: (
        "strategy feature references a name that is not a permitted source bar "
        "field, a declared feature, or a declared parameter"
    ),
    _TYPE_MISMATCH: (
        "strategy feature declaration does not satisfy its operation's typed signature"
    ),
    _PARAMETER_OUT_OF_BOUNDS: (
        "strategy feature operation parameter lies outside its permitted range"
    ),
    DIAGNOSTIC_LIMIT_REACHED: (
        "strategy validation produced more unique diagnostics than the result "
        "contract can carry; earlier diagnostics in canonical order are retained"
    ),
}


class FeatureGraph(CanonicalModel):
    """An accepted acyclic feature graph and its stable total evaluation order."""

    order: tuple[NormalizedIdentifier, ...] = Field(max_length=MAX_FEATURES)


class _Finding(NamedTuple):
    """One graph defect, carrying only material content."""

    error_code: str
    details: dict[str, DiagnosticDetailValue]


def topological_order(
    dependencies: Mapping[str, frozenset[str]],
) -> tuple[str, ...] | None:
    """Return the stable total topological order, or ``None`` when cyclic.

    Kahn's algorithm with the ready set resolved by taking the lexicographically
    smallest identifier at every step, so the order is a function of the graph
    alone and never of declaration order. ``min`` over a set is used rather than a
    heap because ``heapq`` is outside the reviewed import allowlist and the
    feature count is bounded by ``MAX_FEATURES``.
    """
    remaining = {
        name: set(edges) & set(dependencies) for name, edges in dependencies.items()
    }
    ordered: list[str] = []
    while remaining:
        ready = {name for name, edges in remaining.items() if not edges}
        if not ready:
            return None
        chosen = min(ready)
        ordered.append(chosen)
        del remaining[chosen]
        for edges in remaining.values():
            edges.discard(chosen)
    return tuple(ordered)


def _canonical_cycle(dependencies: Mapping[str, frozenset[str]]) -> tuple[str, ...]:
    """Return one cycle witness that is a function of the graph alone.

    Both the outer node iteration and the successor iteration are in sorted
    identifier order, never declaration order, so the witness a given graph
    produces is identical under every source permutation. The witness is then
    rotation-normalized to begin at its lexicographically smallest member, which
    removes the remaining freedom in how a cycle may be written down.

    ``finished`` records every node already proven to reach no cycle, and is what
    makes the walk linear in the number of edges rather than in the number of
    distinct paths. Without it a node is re-explored once per path that reaches
    it, which is exponential in the feature count: a chain of `k` diamonds has
    `2**k` paths across only `3 * k + 1` nodes, so a document well inside
    ``MAX_FEATURES`` could consume unbounded time. Skipping a finished node cannot
    change the witness, because any cycle reachable through it would already have
    been found while it was being explored.
    """
    finished: set[str] = set()
    for start in sorted(dependencies):
        if start in finished:
            continue
        path: list[str] = []
        on_path: set[str] = set()
        # Each frame is a node plus the successors still to try, so the walk is
        # iterative and no depth can raise ``RecursionError``.
        frames: list[tuple[str, list[str]]] = [
            (start, sorted(dependencies.get(start, frozenset())))
        ]
        path.append(start)
        on_path.add(start)
        while frames:
            node, pending = frames[-1]
            if not pending:
                frames.pop()
                on_path.discard(node)
                path.pop()
                # Every successor has been exhausted without returning, so no
                # cycle is reachable from this node by any route.
                finished.add(node)
                continue
            successor = pending.pop(0)
            if successor not in dependencies or successor in finished:
                continue
            if successor in on_path:
                cycle = path[path.index(successor) :]
                pivot = cycle.index(min(cycle))
                return tuple(cycle[pivot:] + cycle[:pivot])
            path.append(successor)
            on_path.add(successor)
            frames.append((successor, sorted(dependencies.get(successor, frozenset()))))
    # Unreachable: this helper is called only after ``topological_order`` has
    # already proven a cycle exists, and a graph with no cycle-free ready set
    # always contains a reachable back edge.
    raise AssertionError("a cyclic graph must contain a reachable cycle")


def _duplicate_findings(spec: StrategySpec) -> list[_Finding]:
    counts: dict[str, int] = {}
    for feature in spec.features:
        counts[feature.id] = counts.get(feature.id, 0) + 1
    return [
        _Finding(
            _DUPLICATE_ID,
            {"feature_id": name, "declaration_count": counts[name]},
        )
        for name in sorted(counts)
        if counts[name] > 1
    ]


def _canonical_definitions(spec: StrategySpec) -> dict[str, FeatureDefinition]:
    """One representative definition per declared identifier, order-independently.

    A duplicated identifier makes "the" definition for that name ambiguous, and
    resolving it by declaration position — which a plain ``{f.id: f}`` dict does,
    last-wins — would make every finding derived from it a function of source
    order. Plan section 5.4.1 item 2 forbids that **unconditionally**, not merely
    for well-formed input, so a specification that is already being rejected for a
    duplicate identifier must still produce byte-identical diagnostics under every
    permutation of its features.

    The representative is therefore the candidate whose canonical JSON sorts first,
    which is a function of the declared multiset alone. For a well-formed
    specification each identifier has exactly one candidate and this is the
    identity, so nothing about the valid path changes.
    """
    grouped: dict[str, list[FeatureDefinition]] = {}
    for feature in spec.features:
        grouped.setdefault(feature.id, []).append(feature)
    return {
        name: min(
            candidates,
            key=lambda item: canonical_json_bytes(
                cast("JsonValue", item.model_dump(mode="json"))
            ),
        )
        for name, candidates in grouped.items()
    }


def _declared_types(spec: StrategySpec) -> dict[str, LiteralValueType]:
    """Every name a feature input may resolve to, and its declared type.

    Precedence matches Task 3's `_reference_scope`: a source bar field outranks a
    declared feature, because bar fields are the closed reserved vocabulary and a
    declaration may not shadow one.
    """
    scope: dict[str, LiteralValueType] = {
        name: definition.output_type
        for name, definition in _canonical_definitions(spec).items()
    }
    scope.update(SOURCE_BAR_FIELDS)
    return scope


def _feature_dependencies(spec: StrategySpec) -> dict[str, frozenset[str]]:
    """Map each declared feature to the declared features it reads.

    A bar-field input and an unresolved input both contribute no edge: the first
    is a leaf and the second is already reported as a reference defect.
    """
    declared = {feature.id for feature in spec.features}
    edges: dict[str, set[str]] = {feature.id: set() for feature in spec.features}
    for feature in spec.features:
        for name in feature.inputs:
            if name in SOURCE_BAR_FIELDS:
                continue
            if name in declared:
                edges[feature.id].add(name)
    return {name: frozenset(values) for name, values in edges.items()}


def _input_findings(
    feature: FeatureDefinition,
    signature: _FeatureSignature | None,
    scope: Mapping[str, LiteralValueType],
) -> list[_Finding]:
    """Check input existence always, and input typing only against a signature."""
    findings: list[_Finding] = []
    for index, name in enumerate(feature.inputs):
        if name not in scope:
            findings.append(
                _Finding(
                    _REFERENCE_UNKNOWN,
                    {
                        "feature_id": feature.id,
                        "input_index": index,
                        "reference_id": name,
                    },
                )
            )
    if signature is None:
        # An unknown operation has no signature, so typing its inputs is
        # impossible and a defensive guess would be a second, misleading defect.
        return findings

    if len(feature.inputs) != signature.input_count:
        findings.append(
            _Finding(
                _TYPE_MISMATCH,
                {
                    "feature_id": feature.id,
                    "operation": feature.operation,
                    "observed_input_count": len(feature.inputs),
                    "expected_input_count": signature.input_count,
                },
            )
        )
    for index, name in enumerate(feature.inputs):
        if name not in scope:
            continue
        if signature.input_must_be_bar_field and name not in SOURCE_BAR_FIELDS:
            findings.append(
                _Finding(
                    _TYPE_MISMATCH,
                    {
                        "feature_id": feature.id,
                        "operation": feature.operation,
                        "input_index": index,
                        "expected_source_bar_field": True,
                    },
                )
            )
            continue
        accepted = signature.accepted_input_types
        if accepted is not None and scope[name] not in accepted:
            findings.append(
                _Finding(
                    _TYPE_MISMATCH,
                    {
                        "feature_id": feature.id,
                        "operation": feature.operation,
                        "input_index": index,
                        "observed_type": scope[name].value,
                        # A comprehension rather than ``sorted(...)`` so the element
                        # type is inferred from the detail-value context: ``list``
                        # is invariant, so ``list[str]`` is not a detail value.
                        "expected_types": [
                            member.value
                            for member in sorted(accepted, key=lambda item: item.value)
                        ],
                    },
                )
            )
    return findings


def _output_findings(
    feature: FeatureDefinition,
    signature: _FeatureSignature,
    scope: Mapping[str, LiteralValueType],
) -> list[_Finding]:
    """A declared output type must equal the one the signature determines."""
    expected = signature.output_type
    if expected is None:
        if len(feature.inputs) != 1 or feature.inputs[0] not in scope:
            # The mirroring source is absent or ambiguous; the input findings
            # already report why, so no second defect is added here.
            return []
        expected = scope[feature.inputs[0]]
    if feature.output_type is expected:
        return []
    return [
        _Finding(
            _TYPE_MISMATCH,
            {
                "feature_id": feature.id,
                "operation": feature.operation,
                "observed_output_type": feature.output_type.value,
                "expected_output_type": expected.value,
            },
        )
    ]


def _parameter_findings(
    feature: FeatureDefinition,
    signature: _FeatureSignature,
    parameters: Mapping[str, ParameterDefinition],
) -> list[_Finding]:
    """Every required operation parameter must exist, be integer, and be in range."""
    findings: list[_Finding] = []
    for name in sorted(set(feature.parameters) - set(signature.required_parameters)):
        findings.append(
            _Finding(
                _TYPE_MISMATCH,
                {
                    "feature_id": feature.id,
                    "operation": feature.operation,
                    "unexpected_parameter": name,
                },
            )
        )
    for name in signature.required_parameters:
        declared = feature.parameters.get(name)
        if declared is None:
            findings.append(
                _Finding(
                    _TYPE_MISMATCH,
                    {
                        "feature_id": feature.id,
                        "operation": feature.operation,
                        "missing_parameter": name,
                    },
                )
            )
            continue
        definition = parameters.get(declared)
        if definition is None:
            findings.append(
                _Finding(
                    _REFERENCE_UNKNOWN,
                    {
                        "feature_id": feature.id,
                        "operation_parameter": name,
                        "reference_id": declared,
                    },
                )
            )
            continue
        if definition.value_type is not LiteralValueType.INTEGER:
            findings.append(
                _Finding(
                    _TYPE_MISMATCH,
                    {
                        "feature_id": feature.id,
                        "operation": feature.operation,
                        "operation_parameter": name,
                        "observed_type": definition.value_type.value,
                        "expected_types": [LiteralValueType.INTEGER.value],
                    },
                )
            )
            continue
        # Narrowed by the check above: an INTEGER parameter's value is an exact
        # ``int``, which ``ParameterDefinition`` itself enforces by identity.
        value = cast("int", definition.value)
        minimum = PARAMETER_MINIMUM[name]
        if value < minimum:
            findings.append(
                _Finding(
                    _PARAMETER_OUT_OF_BOUNDS,
                    {
                        "feature_id": feature.id,
                        "operation": feature.operation,
                        "operation_parameter": name,
                        "observed_value": value,
                        "minimum_value": minimum,
                    },
                )
            )
    return findings


def _warm_up_findings(
    spec: StrategySpec,
    dependencies: Mapping[str, frozenset[str]],
) -> list[_Finding]:
    """Declared warm-up must be at least the maximum dependency warm-up.

    Computed over every resolvable feature dependency regardless of signature
    validity, exactly as input existence is, so an arity or typing defect cannot
    mask a genuine warm-up defect.
    """
    declared = {
        name: definition.warm_up_bars
        for name, definition in _canonical_definitions(spec).items()
    }
    findings: list[_Finding] = []
    for feature in sorted(spec.features, key=lambda item: item.id):
        required = 0
        for name in sorted(dependencies.get(feature.id, frozenset())):
            required = max(required, declared[name])
        if feature.warm_up_bars < required:
            findings.append(
                _Finding(
                    _WARM_UP_TOO_SMALL,
                    {
                        "feature_id": feature.id,
                        "declared_warm_up_bars": feature.warm_up_bars,
                        "required_warm_up_bars": required,
                    },
                )
            )
    return findings


def _graph_findings(
    spec: StrategySpec,
) -> tuple[list[_Finding], tuple[str, ...] | None]:
    """Return every graph defect plus the topological order when one exists."""
    findings: list[_Finding] = _duplicate_findings(spec)
    scope = _declared_types(spec)
    for feature in sorted(spec.features, key=lambda item: item.id):
        signature = FEATURE_OPERATIONS.get(feature.operation)
        if signature is None:
            findings.append(
                _Finding(
                    _UNKNOWN_OPERATION,
                    {"feature_id": feature.id, "operation": feature.operation},
                )
            )
        findings.extend(_input_findings(feature, signature, scope))
        if signature is not None:
            findings.extend(_output_findings(feature, signature, scope))
            findings.extend(_parameter_findings(feature, signature, spec.parameters))

    dependencies = _feature_dependencies(spec)
    order = topological_order(dependencies)
    if order is None:
        # Warm-up sufficiency and topological order are both undefined on a cyclic
        # graph, so neither is attempted. Reporting a warm-up defect derived from a
        # cyclic dependency maximum would be nondeterministic in exactly the way
        # the plan's Task 4 step 2 forbids.
        cycle = _canonical_cycle(dependencies)
        findings.append(
            _Finding(
                _CYCLE,
                {"cycle": list(cycle), "cycle_length": len(cycle)},
            )
        )
        return findings, None
    findings.extend(_warm_up_findings(spec, dependencies))
    return findings, order


def _diagnostic(finding: _Finding, observed_at_utc: datetime) -> Diagnostic:
    """Derive one diagnostic, including its identity, from material content only.

    Every correlation field is absent and ``causal_diagnostic_ids`` is empty, which
    is plan section 5.4.1 item 0 and is what makes the combiner's ordering key a
    total order.
    """
    message = _MESSAGES[finding.error_code]
    payload: dict[str, JsonValue] = {
        "schema_version": "1.0.0",
        "error_code": finding.error_code,
        "category": DiagnosticCategory.SCHEMA_VALIDATION.value,
        "severity": DiagnosticSeverity.ERROR.value,
        "source_component": SOURCE_COMPONENT,
        "message": message,
        "retriable": False,
        "details": cast("JsonValue", finding.details),
    }
    identity = _uuid4_shaped(
        profile_hash(HashingProfile.DIAGNOSTIC_IDENTITY_V1, payload),
    )
    return Diagnostic(
        schema_version="1.0.0",
        diagnostic_id=f"diag_{identity}",
        severity=DiagnosticSeverity.ERROR,
        error_code=finding.error_code,
        category=DiagnosticCategory.SCHEMA_VALIDATION,
        message=message,
        source_component=SOURCE_COMPONENT,
        retriable=False,
        timestamp_utc=observed_at_utc,
        details=finding.details,
        causal_diagnostic_ids=(),
    )


def _limit_marker(observed_at_utc: datetime) -> Diagnostic:
    """The terminal diagnostic-limit marker of plan section 5.4.1.

    ``retained_diagnostics`` is the fixed literal 255, never a computed figure, so
    the marker's payload and therefore its derived identity are byte-identical for
    every overflow size. No omitted or total count is published: the plan
    authorizes none, and a fabricated figure would be worse than none.
    """
    return _diagnostic(
        _Finding(
            DIAGNOSTIC_LIMIT_REACHED,
            {
                "diagnostic_limit": MAX_RESULT_DIAGNOSTICS,
                "retained_diagnostics": MAX_RESULT_DIAGNOSTICS - 1,
            },
        ),
        observed_at_utc,
    )


def _order_key(diagnostic: Diagnostic) -> tuple[str, str, bytes]:
    """The plan's documented total ordering key for the Task 4 combiner.

    Total because, under section 5.4.1 item 0, the section 5.3.3 identity payload
    is a function of exactly ``(error_code, source_component, details)``: two
    entries equal on this key have equal identities and one was therefore already
    removed by deduplication, so no tie can reach the sort.
    """
    return (
        diagnostic.error_code,
        diagnostic.source_component,
        canonical_json_bytes(cast("JsonValue", diagnostic.details)),
    )


def bounded_failure(
    diagnostics: list[Diagnostic],
    observed_at_utc: datetime,
) -> Failure:
    """Deduplicate, order, and bound one diagnostic collection.

    Deduplication precedes the bound, so the bound counts unique diagnostics. At
    most ``MAX_RESULT_DIAGNOSTICS`` unique diagnostics are returned in full; beyond
    that the first ``MAX_RESULT_DIAGNOSTICS - 1`` in canonical order are returned
    followed by the single terminal marker. Crossing the bound is an expected
    outcome and never raises.

    Section 5.4.1 permits a combiner to stop generating at the 257th unique
    diagnostic. That permission is deliberately **not** taken: stopping early
    would make the retained prefix a function of generation order at counts above
    257, which would contradict the same section's requirement that a source-order
    permutation produce byte-identical output. Every Stage 4 finding source is
    bounded by ``MAX_FEATURES`` and ``MAX_RULES``, so collecting all of them is
    itself a bounded amount of work.

    **Inherited markers are absorbed, per plan section 5.4.2.** Task 3 now emits its
    own terminal marker on overflow, and this function inherits its diagnostics. Any
    ``STRATEGY.DIAGNOSTIC_LIMIT_REACHED`` in the input is therefore removed before
    ordering and recorded as an overflow signal, and at most one marker — this
    module's own — is ever returned, always last. An inherited marker forces a
    terminal marker even when this layer's own substantive count is small, which is
    the honest outcome: an upstream producer truncated, so the returned set is
    provably incomplete and must say so.
    """
    unique: dict[str, Diagnostic] = {}
    inherited_overflow = False
    for diagnostic in diagnostics:
        if diagnostic.error_code == DIAGNOSTIC_LIMIT_REACHED:
            # Partitioned out **before** ordering, from any producer including this
            # one, so no marker can enter the substantive run. Without this a
            # marker inherited from Task 3 would sort to index 0, because ``D``
            # precedes every other ``STRATEGY.*`` code on an error-code-leading
            # key, and the terminal slot would hold an ordinary diagnostic.
            inherited_overflow = True
            continue
        unique.setdefault(diagnostic.diagnostic_id, diagnostic)
    ordered = sorted(unique.values(), key=_order_key)
    if len(ordered) <= MAX_RESULT_DIAGNOSTICS and not inherited_overflow:
        return Failure(outcome="FAILURE", diagnostics=tuple(ordered))
    retained = tuple(ordered[: MAX_RESULT_DIAGNOSTICS - 1])
    return Failure(
        outcome="FAILURE",
        diagnostics=(*retained, _limit_marker(observed_at_utc)),
    )


def validate_feature_graph(
    spec: StrategySpec,
    observed_at_utc: datetime,
) -> Result[FeatureGraph]:
    """Validate one strategy's feature graph and return its evaluation order.

    Combines Task 3's expression diagnostics with this layer's graph diagnostics,
    per plan section 5.4.1. Time is a parameter, never ambient, and no bar series
    is consulted: this is static validation.
    """
    expression_result = validate_strategy_expressions(spec, observed_at_utc)
    inherited: tuple[Diagnostic, ...] = (
        expression_result.diagnostics if isinstance(expression_result, Failure) else ()
    )
    findings, order = _graph_findings(spec)
    combined = [*inherited]
    combined.extend(_diagnostic(finding, observed_at_utc) for finding in findings)
    if combined:
        return bounded_failure(combined, observed_at_utc)
    # ``order`` is not ``None`` here: a cyclic graph always contributes a cycle
    # finding, so ``combined`` would be non-empty and this line unreachable.
    # Narrowed by that argument rather than by a runtime check, which would be an
    # unreachable branch; `test_topological_order_returns_none_for_a_cyclic_mapping`
    # and the cycle-fixture tests pin the premise.
    return Success[FeatureGraph](
        outcome="SUCCESS",
        value=FeatureGraph(order=cast("tuple[str, ...]", order)),
    )
