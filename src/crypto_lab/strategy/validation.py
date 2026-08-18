"""Static expression type checking and reference validation for ``expressions/v1``.

This layer validates trees built from the closed discriminated ``Expression``
union that ``strategy/expressions.py`` owns. It changes no node's field shape:
``entry_rules`` and ``exit_rules`` sit inside ``strategy_spec`` in the
strategy-version hash payload, so a shape change here would silently move every
``content_hash``.

Operator dispatch is a closed table keyed by the ``op`` discriminator whose
values are plain data. No strategy-supplied string resolves a Python callable,
no operator is looked up by reflection, and no model field holds a callable.

The checker is static. It receives a validated ``StrategySpec`` and the explicit
``observed_at_utc`` that section 5.3.3 requires, and it has no evaluation
cursor, bar-series length, current bar index, open-bar state, runtime series, or
dataset row context. It determines expression types and resolves references; it
evaluates no bar and no feature series.

The identifier ``rule_context`` below reads oddly for a reason: ``context`` is a
bare name ``tests/safety/test_stage4_boundaries.py`` forbids anywhere under
``src/crypto_lab``, so that ``yaml.YAMLError.context`` can never reach a
diagnostic. That guard matches ``ast.Name`` and ``ast.Attribute`` only, never a
docstring, so the prose above is unaffected.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Final, NamedTuple, cast

from pydantic import JsonValue

from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.diagnostics import (
    Diagnostic,
    DiagnosticCategory,
    DiagnosticDetailValue,
    DiagnosticSeverity,
)
from crypto_lab.domain.hashing import HashingProfile, _uuid4_shaped, profile_hash
from crypto_lab.domain.results import (
    MAX_RESULT_DIAGNOSTICS,
    Failure,
    Result,
    Success,
)
from crypto_lab.strategy.expressions import (
    MAX_EXPRESSION_DEPTH,
    AndExpression,
    ExpressionNode,
    IsMissingExpression,
    LiteralExpression,
    LiteralValueType,
    NegateExpression,
    NotExpression,
    OrExpression,
    RefExpression,
)
from crypto_lab.strategy.models import RuleDefinition, StrategySpec

_SOURCE_COMPONENT: Final = "strategy.validation"

# Exactly the bar fields the feature-operation allowlist names. Every price and
# volume field is canonical ``DECIMAL``. ``bar.timestamp_utc`` is ``STRING``
# because ``FeatureDefinition.output_type`` is already a ``LiteralValueType``, so
# a ``source.bar_field/v1`` feature over it must declare a member of that closed
# enum and ``STRING`` is the only one that fits a canonical UTC instant. There is
# no timestamp member and none is invented here.
SOURCE_BAR_FIELDS: Final[dict[str, LiteralValueType]] = {
    "bar.open": LiteralValueType.DECIMAL,
    "bar.high": LiteralValueType.DECIMAL,
    "bar.low": LiteralValueType.DECIMAL,
    "bar.close": LiteralValueType.DECIMAL,
    "bar.volume": LiteralValueType.DECIMAL,
    "bar.timestamp_utc": LiteralValueType.STRING,
}

NUMERIC_TYPES: Final = frozenset({LiteralValueType.INTEGER, LiteralValueType.DECIMAL})
BOOLEAN_TYPES: Final = frozenset({LiteralValueType.BOOLEAN})

_ENTRY_RULES: Final = "entry_rules"
_EXIT_RULES: Final = "exit_rules"

_NAMESPACE_COLLISION: Final = "STRATEGY.REFERENCE_NAMESPACE_COLLISION"
_LIMIT_REACHED: Final = "STRATEGY.DIAGNOSTIC_LIMIT_REACHED"

# The three declaration namespaces of plan section 5.10, and the fixed order in
# which a collision reports them. Plain string constants, never a lookup table.
_SOURCE_FIELD_NAMESPACE: Final = "SOURCE_FIELD"
_FEATURE_NAMESPACE: Final = "FEATURE"
_PARAMETER_NAMESPACE: Final = "PARAMETER"


class _TypeRule(StrEnum):
    """The closed operator families of ``expressions/v1``."""

    ARITHMETIC = "ARITHMETIC"
    BOOLEAN_LOGIC = "BOOLEAN_LOGIC"
    EQUALITY = "EQUALITY"
    ORDERING = "ORDERING"
    CROSSOVER = "CROSSOVER"
    MISSING_PROBE = "MISSING_PROBE"


class _EqualityClass(StrEnum):
    """Equality compatibility classes. ``INTEGER`` and ``DECIMAL`` share one."""

    BOOLEAN = "BOOLEAN"
    NUMERIC = "NUMERIC"
    STRING = "STRING"
    IDENTIFIER = "IDENTIFIER"


# Closed and explicit: the keys are the union's own ``op`` discriminators and the
# values are enum members, never callables.
_TYPE_RULES: Final[dict[str, _TypeRule]] = {
    "not": _TypeRule.BOOLEAN_LOGIC,
    "and": _TypeRule.BOOLEAN_LOGIC,
    "or": _TypeRule.BOOLEAN_LOGIC,
    "negate": _TypeRule.ARITHMETIC,
    "add": _TypeRule.ARITHMETIC,
    "subtract": _TypeRule.ARITHMETIC,
    "multiply": _TypeRule.ARITHMETIC,
    "divide": _TypeRule.ARITHMETIC,
    "minimum": _TypeRule.ARITHMETIC,
    "maximum": _TypeRule.ARITHMETIC,
    "equal": _TypeRule.EQUALITY,
    "not_equal": _TypeRule.EQUALITY,
    "less_than": _TypeRule.ORDERING,
    "less_than_or_equal": _TypeRule.ORDERING,
    "greater_than": _TypeRule.ORDERING,
    "greater_than_or_equal": _TypeRule.ORDERING,
    "crosses_above": _TypeRule.CROSSOVER,
    "crosses_below": _TypeRule.CROSSOVER,
    "is_missing": _TypeRule.MISSING_PROBE,
}

# Specification 12.3.1: arithmetic returns ``DECIMAL``; comparison returns
# ``BOOLEAN``; boolean operators accept booleans only. Every result type is
# fixed by the operator, never derived from an operand, so no implicit widening
# or narrowing exists.
_RESULT_TYPES: Final[dict[_TypeRule, LiteralValueType]] = {
    _TypeRule.ARITHMETIC: LiteralValueType.DECIMAL,
    _TypeRule.BOOLEAN_LOGIC: LiteralValueType.BOOLEAN,
    _TypeRule.EQUALITY: LiteralValueType.BOOLEAN,
    _TypeRule.ORDERING: LiteralValueType.BOOLEAN,
    _TypeRule.CROSSOVER: LiteralValueType.BOOLEAN,
    _TypeRule.MISSING_PROBE: LiteralValueType.BOOLEAN,
}

# A family absent from this table carries no per-operand constraint:
# ``EQUALITY`` is checked pairwise instead, and ``MISSING_PROBE`` deliberately
# accepts every type because asking whether a value is missing is meaningful for
# all of them.
#
# ``ORDERING: NUMERIC_TYPES`` is a deliberate narrowing, recorded here because it
# is the one rule in this table the specification does not fix. Section 12.3.1
# line 697 says only "Comparison accepts compatible operands", and line 693
# groups the four relational operators with the two equality ones, so two
# ``STRING`` values are arguably a compatible ordered pair -- which would make
# ``greater_than_or_equal`` over ``bar.timestamp_utc`` legal. It is narrowed
# anyway, on three grounds. It is over-restrictive and never over-permissive, so
# it can reject a valid strategy but can never admit an invalid one. No fixture
# and no plan test case exercises string ordering. And widening it would hand the
# later evaluator ordered-string trees for which no evaluation semantics are
# defined anywhere in the specification -- lexicographic ordering happens to
# agree with chronological ordering for canonical UTC instants, but nothing
# normative says so. Widening is a plan amendment, not an implementation choice.
_ACCEPTED_OPERAND_TYPES: Final[dict[_TypeRule, frozenset[LiteralValueType]]] = {
    _TypeRule.ARITHMETIC: NUMERIC_TYPES,
    _TypeRule.BOOLEAN_LOGIC: BOOLEAN_TYPES,
    _TypeRule.ORDERING: NUMERIC_TYPES,
    _TypeRule.CROSSOVER: NUMERIC_TYPES,
}

_EQUALITY_CLASSES: Final[dict[LiteralValueType, _EqualityClass]] = {
    LiteralValueType.BOOLEAN: _EqualityClass.BOOLEAN,
    LiteralValueType.INTEGER: _EqualityClass.NUMERIC,
    LiteralValueType.DECIMAL: _EqualityClass.NUMERIC,
    LiteralValueType.STRING: _EqualityClass.STRING,
    LiteralValueType.IDENTIFIER: _EqualityClass.IDENTIFIER,
}

# Classified with its loader sibling ``STRATEGY.YAML_DEPTH_EXCEEDED``: both bound
# an adversarial document's nesting rather than describing a schema shape.
_SECURITY_CODES: Final = frozenset({"STRATEGY.EXPRESSION_DEPTH_EXCEEDED"})
_MESSAGES: Final = {
    "STRATEGY.EXPRESSION_DEPTH_EXCEEDED": (
        "strategy expression nesting exceeds the maximum depth"
    ),
    "STRATEGY.EXPRESSION_TYPE_MISMATCH": (
        "strategy expression operand type does not satisfy its operator signature"
    ),
    "STRATEGY.REFERENCE_UNKNOWN": (
        "strategy expression references a name that is not a declared parameter, "
        "a permitted source bar field, or a declared feature"
    ),
    _NAMESPACE_COLLISION: (
        "strategy declares one name in more than one reference namespace, so the "
        "reference is ambiguous"
    ),
    _LIMIT_REACHED: (
        "strategy validation produced more unique diagnostics than the result "
        "contract can carry; earlier diagnostics in canonical order are retained"
    ),
}


class _Finding(NamedTuple):
    """One static defect, carrying the exact sort key the plan fixes."""

    rule_id: str
    node_path: str
    error_code: str
    details: dict[str, DiagnosticDetailValue]


def _reference_scope(spec: StrategySpec) -> dict[str, LiteralValueType]:
    """Return every resolvable reference name and its declared type.

    Precedence is a source bar field over a declared feature over a declared
    parameter. **It is now unreachable, and deliberately retained.** Plan section
    5.10 makes the three namespaces pairwise disjoint and rejects any collision, so
    no name can be claimed twice and the ``SOURCE_BAR_FIELDS`` update below can
    never overwrite an entry. The ordering is kept as defence in depth: it keeps
    this resolver total if a later expression-semantics version ever admits a
    controlled overlap, and section 5.10 forbids altering precedence as a
    substitute for rejecting the ambiguity.
    """
    scope: dict[str, LiteralValueType] = {
        name: definition.value_type for name, definition in spec.parameters.items()
    }
    for feature in spec.features:
        scope[feature.id] = feature.output_type
    scope.update(SOURCE_BAR_FIELDS)
    return scope


def _child_operands(node: ExpressionNode) -> tuple[tuple[str, ExpressionNode], ...]:
    """Return each operand with its field path segment.

    Structural, not table-driven: the operand names come from ``isinstance``
    narrowing over the closed node set rather than from a string looked up and
    fed to ``getattr``.
    """
    if isinstance(node, LiteralExpression | RefExpression):
        return ()
    if isinstance(node, NotExpression | NegateExpression | IsMissingExpression):
        return (("operand", node.operand),)
    if isinstance(node, AndExpression | OrExpression):
        return tuple(
            (f"operands[{index}]", operand)
            for index, operand in enumerate(node.operands)
        )
    return (("left", node.left), ("right", node.right))


def _node_type(
    node: ExpressionNode,
    scope: dict[str, LiteralValueType],
) -> LiteralValueType | None:
    """Infer one node's type, or ``None`` when a reference does not resolve.

    An unresolved operand yields ``None`` so the parent operator reports no
    cascading type defect on top of the reference defect already recorded.
    """
    if isinstance(node, LiteralExpression):
        return node.value_type
    if isinstance(node, RefExpression):
        return scope.get(node.id)
    return _RESULT_TYPES[_TYPE_RULES[node.op]]


class _RuleContext(NamedTuple):
    """Everything one rule's checks need, so no helper takes six arguments."""

    rule_collection: str
    rule: RuleDefinition
    scope: dict[str, LiteralValueType]

    def finding(
        self,
        node_path: str,
        error_code: str,
        details: dict[str, DiagnosticDetailValue],
    ) -> _Finding:
        """Build one finding whose details always open with the sort-key fields."""
        return _Finding(
            rule_id=self.rule.id,
            node_path=node_path,
            error_code=error_code,
            details={
                "rule_collection": self.rule_collection,
                "rule_id": self.rule.id,
                "node_path": node_path,
                **details,
            },
        )

    def mismatch(
        self,
        node_path: str,
        details: dict[str, DiagnosticDetailValue],
    ) -> _Finding:
        return self.finding(node_path, "STRATEGY.EXPRESSION_TYPE_MISMATCH", details)


def _operand_findings(
    rule_context: _RuleContext,
    node: ExpressionNode,
    node_path: str,
    operands: tuple[tuple[str, ExpressionNode], ...],
    accepted: frozenset[LiteralValueType],
) -> list[_Finding]:
    """Attribute each unacceptable operand to the operand's own path."""
    expected = sorted(member.value for member in accepted)
    findings: list[_Finding] = []
    for name, operand in operands:
        operand_type = _node_type(operand, rule_context.scope)
        if operand_type is None or operand_type in accepted:
            continue
        findings.append(
            rule_context.mismatch(
                f"{node_path}.{name}",
                {
                    "operator": node.op,
                    "observed_type": operand_type.value,
                    "expected_types": list(expected),
                },
            )
        )
    return findings


def _equality_findings(
    rule_context: _RuleContext,
    node: ExpressionNode,
    node_path: str,
    operands: tuple[tuple[str, ExpressionNode], ...],
) -> list[_Finding]:
    """Equality constrains the operand pair, so the operator carries the defect."""
    left_type = _node_type(operands[0][1], rule_context.scope)
    right_type = _node_type(operands[1][1], rule_context.scope)
    if left_type is None or right_type is None:
        return []
    if _EQUALITY_CLASSES[left_type] is _EQUALITY_CLASSES[right_type]:
        return []
    return [
        rule_context.mismatch(
            node_path,
            {
                "operator": node.op,
                "left_type": left_type.value,
                "right_type": right_type.value,
            },
        )
    ]


def _operator_findings(
    rule_context: _RuleContext,
    node: ExpressionNode,
    node_path: str,
    operands: tuple[tuple[str, ExpressionNode], ...],
) -> list[_Finding]:
    type_rule = _TYPE_RULES[node.op]
    accepted = _ACCEPTED_OPERAND_TYPES.get(type_rule)
    if accepted is not None:
        return _operand_findings(rule_context, node, node_path, operands, accepted)
    if type_rule is _TypeRule.EQUALITY:
        return _equality_findings(rule_context, node, node_path, operands)
    # ``MISSING_PROBE`` alone reaches here: asking whether a value is missing is
    # meaningful for every type, so it constrains its operand not at all.
    return []


def _root_findings(rule_context: _RuleContext) -> list[_Finding]:
    """Specification 12.3.2 makes a rule a signal, so its root must be boolean.

    A rule containing a missing value evaluates to false and never becomes true
    through truthiness, which is only meaningful if the rule is boolean to begin
    with. An unresolved root reports its reference defect alone, with no cascade.
    """
    root_type = _node_type(rule_context.rule.expression, rule_context.scope)
    if root_type is None or root_type is LiteralValueType.BOOLEAN:
        return []
    return [
        rule_context.mismatch(
            "expression",
            {
                "observed_type": root_type.value,
                "expected_types": [LiteralValueType.BOOLEAN.value],
            },
        )
    ]


def _check_rule(rule_context: _RuleContext) -> list[_Finding]:
    """Walk one rule's tree iteratively, so no depth can raise ``RecursionError``."""
    findings: list[_Finding] = []
    root: ExpressionNode = rule_context.rule.expression
    pending: list[tuple[ExpressionNode, str, int]] = [(root, "expression", 1)]
    while pending:
        node, node_path, depth = pending.pop()
        if depth > MAX_EXPRESSION_DEPTH:
            # Report the boundary node and stop descending, so a deliberately
            # deep tree costs work proportional to the bound rather than to its
            # own size, and every reported path stays bounded in length.
            findings.append(
                rule_context.finding(
                    node_path,
                    "STRATEGY.EXPRESSION_DEPTH_EXCEEDED",
                    {"maximum_depth": MAX_EXPRESSION_DEPTH},
                )
            )
            continue
        if isinstance(node, RefExpression) and node.id not in rule_context.scope:
            # The offending name is bounded by ``NormalizedIdentifier`` itself,
            # which is at most 128 characters, so it can never exceed the
            # diagnostic detail-string ceiling and needs no clamp.
            findings.append(
                rule_context.finding(
                    node_path,
                    "STRATEGY.REFERENCE_UNKNOWN",
                    {"reference_id": node.id},
                )
            )
        operands = _child_operands(node)
        if operands:
            findings.extend(_operator_findings(rule_context, node, node_path, operands))
        # Reversed, so the traversal is pre-order left to right and the
        # generation order is a deterministic function of the declaration.
        for name, operand in reversed(operands):
            pending.append((operand, f"{node_path}.{name}", depth + 1))
    findings.extend(_root_findings(rule_context))
    return findings


def _namespace_findings(spec: StrategySpec) -> list[_Finding]:
    """Reject any name claimed by more than one declaration namespace.

    Plan section 5.10 makes `SOURCE_FIELD`, `FEATURE` and `PARAMETER` pairwise
    disjoint. Only the **six exact** source-field names are reserved — the `bar.`
    prefix deliberately is not — so membership is exact equality against
    ``SOURCE_BAR_FIELDS`` and a name such as ``bar.midpoint`` or ``barrier`` is
    unaffected.

    One finding per **distinct** conflicting name, never one per namespace pair, so
    a name claimed by all three still yields exactly one. ``namespaces`` is built in
    the fixed order `SOURCE_FIELD`, `FEATURE`, `PARAMETER` rather than in
    declaration order, so the details payload and therefore the derived
    ``diagnostic_id`` are functions of the declaration set alone.

    A collision is **spec-level**: it attaches to no rule, no rule collection, and
    no expression node. It therefore takes the empty string for the ordering key's
    ``rule_id`` and ``node_path`` — which sorts it before every rule-level finding,
    because ``NormalizedIdentifier`` requires a leading lowercase letter — and puts
    neither of them in ``details``. It is deliberately not built through
    ``_RuleContext.finding``, which injects both.
    """
    features = {feature.id for feature in spec.features}
    parameters = set(spec.parameters)
    findings: list[_Finding] = []
    for name in sorted(features | parameters):
        claimed: list[DiagnosticDetailValue] = []
        if name in SOURCE_BAR_FIELDS:
            claimed.append(_SOURCE_FIELD_NAMESPACE)
        if name in features:
            claimed.append(_FEATURE_NAMESPACE)
        if name in parameters:
            claimed.append(_PARAMETER_NAMESPACE)
        if len(claimed) < 2:
            continue
        findings.append(
            _Finding(
                "",
                "",
                _NAMESPACE_COLLISION,
                {"reference_name": name, "namespaces": claimed},
            )
        )
    return findings


def _collect_findings(spec: StrategySpec) -> list[_Finding]:
    scope = _reference_scope(spec)
    findings: list[_Finding] = _namespace_findings(spec)
    for rule_collection, rules in (
        (_ENTRY_RULES, spec.entry_rules),
        (_EXIT_RULES, spec.exit_rules),
    ):
        for rule in rules:
            findings.extend(_check_rule(_RuleContext(rule_collection, rule, scope)))
    return findings


def _limit_marker(observed_at_utc: datetime) -> Diagnostic:
    """The terminal diagnostic-limit marker of plan sections 5.4.1 and 5.4.2.

    The same closed code the feature-graph combiner uses, emitted under this
    module's own ``source_component``; section 5.4.1's ordering key carries
    ``source_component`` so the two producers' markers stay distinct diagnostics of
    one code. No second limit code is introduced.

    ``retained_diagnostics`` is the fixed literal ``MAX_RESULT_DIAGNOSTICS - 1``,
    never a computed figure, so the payload and the identity derived from it are
    byte-identical for every overflow size. No omitted or total count is published:
    the plan authorizes none and a fabricated figure would be worse than none.

    It is spec-level, so it takes the empty ordering-key components and carries
    neither in ``details``.
    """
    return _diagnostic(
        _Finding(
            "",
            "",
            _LIMIT_REACHED,
            {
                "diagnostic_limit": MAX_RESULT_DIAGNOSTICS,
                "retained_diagnostics": MAX_RESULT_DIAGNOSTICS - 1,
            },
        ),
        observed_at_utc,
    )


def _order_key(finding: _Finding) -> tuple[str, str, str, bytes]:
    """Task 3's total ordering key, fixed by plan section 5.4.2.

    The first three components are Task 3's original reviewed key, unchanged, so
    every committed ordering guarantee still holds. The fourth is required because
    the first three are **not total**: an entry rule and an exit rule may share an
    identifier, so two findings at the same ``node_path`` with the same
    ``error_code`` differ only in ``details.rule_collection`` and would tie. Section
    5.4.1 item 2 rules a tie unacceptable, because a permutation test over a key
    admitting one passes vacuously.

    A spec-level finding carries the empty string for the first two components and
    therefore sorts before every rule-level finding.
    """
    return (
        finding.rule_id,
        finding.node_path,
        finding.error_code,
        canonical_json_bytes(cast(JsonValue, finding.details)),
    )


def _diagnostic(finding: _Finding, observed_at_utc: datetime) -> Diagnostic:
    """Derive one diagnostic, including its identity, from material content only."""
    category = (
        DiagnosticCategory.SECURITY
        if finding.error_code in _SECURITY_CODES
        else DiagnosticCategory.SCHEMA_VALIDATION
    )
    message = _MESSAGES[finding.error_code]
    payload: dict[str, JsonValue] = {
        "schema_version": "1.0.0",
        "error_code": finding.error_code,
        "category": category.value,
        "severity": DiagnosticSeverity.ERROR.value,
        "source_component": _SOURCE_COMPONENT,
        "message": message,
        "retriable": False,
        "details": cast(JsonValue, finding.details),
    }
    identity = _uuid4_shaped(
        profile_hash(HashingProfile.DIAGNOSTIC_IDENTITY_V1, payload),
    )
    return Diagnostic(
        schema_version="1.0.0",
        diagnostic_id=f"diag_{identity}",
        severity=DiagnosticSeverity.ERROR,
        error_code=finding.error_code,
        category=category,
        message=message,
        source_component=_SOURCE_COMPONENT,
        retriable=False,
        timestamp_utc=observed_at_utc,
        details=finding.details,
        causal_diagnostic_ids=(),
    )


def validate_strategy_expressions(
    spec: StrategySpec,
    observed_at_utc: datetime,
) -> Result[StrategySpec]:
    """Statically check every entry and exit rule expression of one strategy.

    Returns the specification unchanged on success, or every diagnostic the
    static pass produced. Time is a parameter, never ambient.
    """
    findings = _collect_findings(spec)
    if not findings:
        return Success[StrategySpec](outcome="SUCCESS", value=spec)
    # Plan section 5.4.2's exact order: collect, deduplicate, canonically sort,
    # bound, then append the terminal marker. Deduplicating before the bound is
    # what makes the bound count *unique* diagnostics rather than raw findings.
    #
    # The deduplication key is exactly the diagnostic identity of section 5.3.3.
    # That identity payload is a function of `(error_code, details)` alone: every
    # other field in it is either a fixed literal or a function of `error_code`
    # through this module's own closed per-code tables. So equal keys mean equal
    # `diagnostic_id`s, and this can never drop a distinct diagnostic.
    unique: dict[tuple[str, bytes], _Finding] = {}
    for finding in findings:
        identity = (
            finding.error_code,
            canonical_json_bytes(cast(JsonValue, finding.details)),
        )
        unique.setdefault(identity, finding)
    ordered = sorted(unique.values(), key=_order_key)
    if len(ordered) <= MAX_RESULT_DIAGNOSTICS:
        return Failure(
            outcome="FAILURE",
            diagnostics=tuple(
                _diagnostic(finding, observed_at_utc) for finding in ordered
            ),
        )
    # Beyond the bound the result is explicitly marked rather than silently cut:
    # the first `MAX_RESULT_DIAGNOSTICS - 1` in canonical order, then one terminal
    # marker. `Failure`'s own bound is untouched, and no exception is raised for
    # what is an expected outcome.
    retained = tuple(
        _diagnostic(finding, observed_at_utc)
        for finding in ordered[: MAX_RESULT_DIAGNOSTICS - 1]
    )
    return Failure(
        outcome="FAILURE",
        diagnostics=(*retained, _limit_marker(observed_at_utc)),
    )
