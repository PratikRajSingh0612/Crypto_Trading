"""Comparison levels, eligibility contracts, and difference classification.

This module owns **contracts and one pure predicate**, and nothing else. Plan
section 5.8 splits specification section 25.4 in two: Stage 4 defines
``ComparisonLevel``, ``ComparisonEligibilityOutcome``,
``ComparisonEligibilityResult``, ``ComparisonIneligibilityReason``,
``DifferenceCategory``, the deterministic reason-ordering rules, and "the pure
eligibility predicate over two already-validated comparison inputs", while
``ComparisonEligibilityService`` stays in ``experiments/comparison.py``, owned by
the later stage that owns ``RunManifest``. Stage 4 defines no service class and no
``RunManifest``; both names appear below only as prose, never as a definition,
and a closed-world guard walks ``ClassDef | FunctionDef | AsyncFunctionDef`` to
keep it that way.

**A forward obligation is recorded here rather than discovered later.** Section
8.2 hands the service two ``RunManifest`` records, but the configuration
assumptions ``ComparisonInput.assumptions`` requires live in ``ExperimentSpec``
(section 11.3: ``fee_assumptions``, ``slippage_assumptions``,
``execution_assumptions``, ``starting_balance``, ``configuration_hash``), which
that signature does not supply, and section 25.4 calls the service "pure", so it
may not read a repository to fetch them. The owning stage therefore needs either a
projection input beyond 8.2's two parameters or a spec amendment; Task 8 will have
published this record's schema by then. This is not a Task 7 architecture
conflict -- plan section 5.8 assigns Stage 4 a predicate over "already-validated
comparison inputs" and places the service elsewhere, so the projection is the
owning stage's to define -- but it is a real consequence of that split and it is
escalated in the task ledger rather than left to be found.

Nothing in this module reads a clock, the filesystem, the environment, the
network, process state, machine identity, or a random source; imports an engine,
an adapter, or a strategy; launches a process; evaluates a strategy; loads a
result; persists anything; or touches market data. The result is a function of
the three explicit immutable arguments alone, and no value is cached in module
state.

**What this module must never do, stated because the specification states it.**
Specification section 25.3 forbids Level 3 results from being averaged into a
synthetic return, reduced to majority voting, or used to establish strategy
promotion automatically. There is therefore no function here that averages,
votes, combines returns, merges equity, selects a winner, or promotes or approves
a strategy; ``ComparisonEligibilityResult`` carries no score, no vote count, and
no average-return field; and the module computes no metric and compares no
numeric result series. It evaluates already-validated metadata and assumption
contracts, classifies declared differences, and returns one structured outcome.

**Two field sets are derived rather than read from a table, and each derivation
is stated on its class.** Specification section 11.3 carries **no row** for
``ComparisonEligibilityResult`` -- nor for ``ComparisonInput``, which the
specification does not name at all because section 8.2 types the service's inputs
as ``RunManifest``. Plan line 2944 nonetheless lists
``ComparisonEligibilityResult`` among the models taking "exactly the minimum
fields their specification section 11.3 rows list". Task 6 met the identical
defect for ``CompatibilityResult`` and resolved it by derivation from binding
sentences; the same discipline is applied here.

Every record here is a scalar-and-ordered-sequence record: **no field is a
mapping**. That is what plan section 5.5.1's "latent collision" paragraph
anticipated for this exact record, so no immutable-mapping representation is
needed and this module imports nothing from ``types``.
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator
from pydantic.experimental.missing_sentinel import MISSING
from pydantic.json_schema import JsonSchemaValue

from crypto_lab.capabilities.models import ApproximationDeclaration
from crypto_lab.capabilities.vocabulary import CapabilityVocabulary
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.comparison_levels import ComparisonLevel
from crypto_lab.domain.descriptors import BoundedText
from crypto_lab.domain.diagnostics import ErrorCode
from crypto_lab.domain.identifiers import (
    ApproximationId,
    NormalizedIdentifier,
    Sha256,
)
from crypto_lab.domain.versioning import SemanticVersion

__all__ = [
    "APPROXIMATION_EXCLUDES_LEVEL",
    "ASSUMPTION_MISMATCH",
    "COMPARISON_REASON_CODES",
    "DATASET_HASH_MISMATCH",
    "LEVEL_1_MATERIALS",
    "LEVEL_2_MATERIALS",
    "LEVEL_3_MATERIALS",
    "LEVEL_UNSUPPORTED",
    "MAX_COMPARISON_APPROXIMATIONS",
    "MAX_COMPARISON_ASSUMPTIONS",
    "MAX_COMPARISON_REASONS",
    "MAX_INPUT_DECLARED_DIFFERENCES",
    "MAX_RESULT_DECLARED_DIFFERENCES",
    "METHODOLOGY_MISMATCH",
    "SCHEMA_VERSION_MISMATCH",
    "STRATEGY_HASH_MISMATCH",
    "ComparisonAssumption",
    "ComparisonDifference",
    "ComparisonEligibilityOutcome",
    "ComparisonEligibilityResult",
    "ComparisonIneligibilityReason",
    "ComparisonInput",
    "ComparisonMaterial",
    "DifferenceCategory",
    "difference_sort_key",
    "evaluate_comparison_eligibility",
    "reason_sort_key",
    "required_materials",
]

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------


class ComparisonEligibilityOutcome(StrEnum):
    """The three approved outcomes of specification section 25.4.

    Plan line 3948 and specification section 25.4 both give the three names in
    this order, and both are followed. There is deliberately no fourth member: a
    pair that cannot be compared at the requested level is ``INELIGIBLE``, which
    specification section 25.4 calls "a structured result, not data deletion or
    retroactive run failure".
    """

    ELIGIBLE = "ELIGIBLE"
    INELIGIBLE = "INELIGIBLE"
    ELIGIBLE_WITH_DECLARED_DIFFERENCES = "ELIGIBLE_WITH_DECLARED_DIFFERENCES"


class DifferenceCategory(StrEnum):
    """Exactly the fourteen categories of specification section 20.4, in its order.

    **Open in the specification, closed by the plan.** Section 20.4 writes
    "Initial difference categories *include*", which is open; plan line 3952 says
    "exactly the fourteen categories of specification section 20.4", which closes
    it. The plan governs, so there is no fifteenth member, no ``OTHER``, and no
    engine-specific or venue-specific member.

    **Casing is repository convention, not invention.** Plan lines 2928-2930 fix
    the representation for the whole repository: enums are ``StrEnum``s with
    uppercase values, "matching every merged enum in the repository". Section
    20.4's prose labels carry no serialized spelling of their own, and this
    module does not exist before this task, so there is no committed alternative
    to read.
    """

    INPUT_OR_DATA_ALIGNMENT = "INPUT_OR_DATA_ALIGNMENT"
    WARM_UP_BEHAVIOR = "WARM_UP_BEHAVIOR"
    INDICATOR_IMPLEMENTATION = "INDICATOR_IMPLEMENTATION"
    SIGNAL_TIMING = "SIGNAL_TIMING"
    ORDER_TIMING = "ORDER_TIMING"
    FEE_MODELING = "FEE_MODELING"
    SLIPPAGE_MODELING = "SLIPPAGE_MODELING"
    PRECISION_OR_ROUNDING = "PRECISION_OR_ROUNDING"
    PARTIAL_FILL_BEHAVIOR = "PARTIAL_FILL_BEHAVIOR"
    PORTFOLIO_ACCOUNTING = "PORTFOLIO_ACCOUNTING"
    ENGINE_NATIVE_EXECUTION_SEMANTICS = "ENGINE_NATIVE_EXECUTION_SEMANTICS"
    DECLARED_APPROXIMATION = "DECLARED_APPROXIMATION"
    NORMALIZATION_LIMITATION = "NORMALIZATION_LIMITATION"
    UNEXPLAINED_DIFFERENCE = "UNEXPLAINED_DIFFERENCE"


class ComparisonMaterial(StrEnum):
    """The closed set of configuration assumptions eligibility compares.

    Derived one-to-one from the specification's own two enumerations, so no
    member is invented and none is dropped:

    - specification 25.1, "Inputs use the same normalized bars, warm-up
      boundaries, feature-semantics version, parameter values, universe, and
      Decimal rules", which plan line 3969 restates -- five members, because
      "normalized bars" is ``dataset_version_hash`` and carries its own code;
    - specification 25.2's ten numbered Level 2 additions -- nine members,
      because item 1's "normalized candle data" is again
      ``dataset_version_hash`` and item 3's "warm-up period" is already
      ``WARM_UP_BOUNDARIES``.

    ``DECIMAL_RULES`` (25.1, Decimal arithmetic) and
    ``INSTRUMENT_PRECISION_AND_ROUNDING_RULES`` (25.2 item 9, instrument tick and
    lot precision) are distinct in the specification and are kept distinct here.
    """

    # Specification 25.1 -- Level 1 signal parity.
    WARM_UP_BOUNDARIES = "WARM_UP_BOUNDARIES"
    FEATURE_SEMANTICS_VERSION = "FEATURE_SEMANTICS_VERSION"
    PARAMETER_VALUES = "PARAMETER_VALUES"
    UNIVERSE = "UNIVERSE"
    DECIMAL_RULES = "DECIMAL_RULES"
    # Specification 25.2 -- Level 2 bar-execution parity, in its numbered order.
    DATASET_PARTITION_HASHES = "DATASET_PARTITION_HASHES"
    TIMEZONE_AND_BAR_BOUNDARY_CONVENTION = "TIMEZONE_AND_BAR_BOUNDARY_CONVENTION"
    INITIAL_BALANCE = "INITIAL_BALANCE"
    FEE_ASSUMPTIONS = "FEE_ASSUMPTIONS"
    SLIPPAGE_ASSUMPTIONS = "SLIPPAGE_ASSUMPTIONS"
    SIGNAL_TO_ORDER_TIMING = "SIGNAL_TO_ORDER_TIMING"
    POSITION_SIZING_RULES = "POSITION_SIZING_RULES"
    INSTRUMENT_PRECISION_AND_ROUNDING_RULES = "INSTRUMENT_PRECISION_AND_ROUNDING_RULES"
    BAR_ORDER_PRIORITY_AND_FILL_CONVENTION = "BAR_ORDER_PRIORITY_AND_FILL_CONVENTION"


#: Specification 25.1, in its sentence order.
LEVEL_1_MATERIALS: tuple[ComparisonMaterial, ...] = (
    ComparisonMaterial.WARM_UP_BOUNDARIES,
    ComparisonMaterial.FEATURE_SEMANTICS_VERSION,
    ComparisonMaterial.PARAMETER_VALUES,
    ComparisonMaterial.UNIVERSE,
    ComparisonMaterial.DECIMAL_RULES,
)
#: Specification 25.2's additions, in its numbered order. Level 2 requires
#: ``LEVEL_1_MATERIALS`` too -- "Level 2 requires Level 1 plus".
LEVEL_2_MATERIALS: tuple[ComparisonMaterial, ...] = (
    ComparisonMaterial.DATASET_PARTITION_HASHES,
    ComparisonMaterial.TIMEZONE_AND_BAR_BOUNDARY_CONVENTION,
    ComparisonMaterial.INITIAL_BALANCE,
    ComparisonMaterial.FEE_ASSUMPTIONS,
    ComparisonMaterial.SLIPPAGE_ASSUMPTIONS,
    ComparisonMaterial.SIGNAL_TO_ORDER_TIMING,
    ComparisonMaterial.POSITION_SIZING_RULES,
    ComparisonMaterial.INSTRUMENT_PRECISION_AND_ROUNDING_RULES,
    ComparisonMaterial.BAR_ORDER_PRIORITY_AND_FILL_CONVENTION,
)
#: Exactly Level 1's set: Level 3 relaxes section 25.2's **execution** parity and
#: nothing else.
#:
#: Section 25.3 says each engine uses "its strongest appropriate native execution
#: model **for the declared experiment**", that results "are not expected to be
#: numerically identical", and that differences are classified by "execution,
#: fill, fee, portfolio, precision, or modeling semantics". That list is the 25.2
#: execution surface; it never names warm-up boundaries, the feature-semantics
#: version, parameter values, the universe, or Decimal rules. Those five are the
#: *declared inputs* of section 25.1, and "the declared experiment" is singular --
#: two runs of one experiment share its inputs, and what differs is how each
#: engine executes them. Section 25.4's eligibility check list is unqualified
#: ("dataset hash, strategy hash, **configuration assumptions**, schema versions,
#: methodology versions, and approximation declarations"), so the plan's silence
#: at test item 4 cannot license checking none of them.
#:
#: **An earlier draft made this empty and an independent review rejected it.** The
#: defect was concrete: the record *mandates* one digest per material through
#: ``min_length == max_length``, so a Level 3 caller must supply all fourteen, and
#: the predicate then read none -- two runs with different parameter values,
#: different universes, and different Decimal rules returned plain ``ELIGIBLE``,
#: which ``validate_outcome_shape`` defines as the outcome carrying no difference
#: at all. That is an unqualified parity claim over runs agreeing on nothing but
#: their hashes. Nor does the strategy hash close the gap: ``StrategySpec`` carries
#: no Decimal-rules field, so ``DECIMAL_RULES`` is provably independent of
#: ``strategy_version_hash``.
#:
#: Consequence, stated so it reads as a decision: two Level 3 runs differing in
#: fee, slippage, precision, or fill assumptions -- the 25.2 set -- remain
#: comparable, while two differing in warm-up, feature semantics, parameters,
#: universe, or Decimal rules are not.
LEVEL_3_MATERIALS: tuple[ComparisonMaterial, ...] = LEVEL_1_MATERIALS

LEVEL_UNSUPPORTED = "COMPARISON.LEVEL_UNSUPPORTED"
STRATEGY_HASH_MISMATCH = "COMPARISON.STRATEGY_HASH_MISMATCH"
DATASET_HASH_MISMATCH = "COMPARISON.DATASET_HASH_MISMATCH"
ASSUMPTION_MISMATCH = "COMPARISON.ASSUMPTION_MISMATCH"
APPROXIMATION_EXCLUDES_LEVEL = "COMPARISON.APPROXIMATION_EXCLUDES_LEVEL"
SCHEMA_VERSION_MISMATCH = "COMPARISON.SCHEMA_VERSION_MISMATCH"
METHODOLOGY_MISMATCH = "COMPARISON.METHODOLOGY_MISMATCH"

#: Exactly the seven ``COMPARISON.`` rows of plan section 5.9's closed
#: error-code table. Any addition requires a plan amendment, so an unknown code
#: is rejected at the record boundary rather than carried into a canonical
#: artifact.
COMPARISON_REASON_CODES: frozenset[str] = frozenset(
    {
        LEVEL_UNSUPPORTED,
        STRATEGY_HASH_MISMATCH,
        DATASET_HASH_MISMATCH,
        ASSUMPTION_MISMATCH,
        APPROXIMATION_EXCLUDES_LEVEL,
        SCHEMA_VERSION_MISMATCH,
        METHODOLOGY_MISMATCH,
    }
)

MAX_COMPARISON_ASSUMPTIONS = len(ComparisonMaterial)
#: One approximation record per capability at most, and the vocabulary is closed,
#: so the vocabulary size is the exact bound -- Task 6's identical argument for
#: ``MAX_COMPATIBILITY_APPROXIMATIONS``.
MAX_COMPARISON_APPROXIMATIONS = len(CapabilityVocabulary.names)
#: One declared difference per category per input: a side states one explanation
#: for each kind of difference it knows about. Bounding by the closed category set
#: rather than by an arbitrary count is what keeps the reason and difference
#: counts a function of closed vocabularies instead of caller text volume.
MAX_INPUT_DECLARED_DIFFERENCES = len(DifferenceCategory)
#: The union of two inputs. Two sides may explain the same category differently,
#: so the union is deduplicated by ``(category, detail)`` and can hold both.
MAX_RESULT_DECLARED_DIFFERENCES = 2 * MAX_INPUT_DECLARED_DIFFERENCES
#: A ceiling the predicate provably cannot reach. Five of the seven codes are
#: unscoped and survive deduplication at most once each; ``ASSUMPTION_MISMATCH``
#: is scoped to the fourteen-member closed material set; and
#: ``APPROXIMATION_EXCLUDES_LEVEL`` is scoped to a declared ``ApproximationId``
#: drawn from two bounded input collections. The worst case is therefore
#: ``5 + 14 + 2 * 26 = 71`` -- reachable, and an independent review constructed it
#: -- against this ceiling of 128. Reasons are consequently unconditionally
#: complete, nothing is ever sliced, and no terminal limit marker is required. The
#: proof holds only because **no free caller text ever becomes a reason scope**.
#: For any input that validates, no ``ValidationError`` can escape the predicate;
#: a malformed input is rejected loudly at the ``ComparisonInput`` boundary
#: instead, before the predicate is entered.
MAX_COMPARISON_REASONS = 128


def required_materials(level: ComparisonLevel) -> tuple[ComparisonMaterial, ...]:
    """Return the assumption materials that must agree for one comparison level.

    The fall-through is Level 2, the strictest set, so an unrecognized level
    would demand *more* agreement rather than less. Fail-closed ordering matters
    here even though ``ComparisonLevel`` has exactly three strictly validated
    members: a later stage adding a member must not silently acquire an empty
    requirement set.
    """
    if level is ComparisonLevel.LEVEL_3:
        return LEVEL_3_MATERIALS
    if level is ComparisonLevel.LEVEL_1:
        return LEVEL_1_MATERIALS
    return LEVEL_1_MATERIALS + LEVEL_2_MATERIALS


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


def _is_missing(value: object) -> bool:
    return value is MISSING


def _mark_unique(schema: JsonSchemaValue, fields: tuple[str, ...]) -> None:
    """Add ``uniqueItems`` where Pydantic emits none for a tuple field.

    The hook fails loudly rather than silently skipping the annotation: Task 8
    generates a published schema from these models, so a hook that shrugged would
    quietly publish a contract weaker than the runtime enforces.
    """
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise TypeError("comparison schema properties must be an object")
    for field in fields:
        field_schema = properties.get(field)
        if not isinstance(field_schema, dict):
            raise TypeError(f"comparison schema field {field!r} must be an object")
        field_schema["uniqueItems"] = True


def _input_schema_extra(schema: JsonSchemaValue) -> None:
    _mark_unique(schema, ("assumptions", "approximations", "declared_differences"))


def _result_schema_extra(schema: JsonSchemaValue) -> None:
    _mark_unique(schema, ("reasons", "declared_differences"))


class ComparisonAssumption(CanonicalModel):
    """One configuration assumption, as a canonical digest of its material form.

    A nested record, so it declares no ``schema_version``: plan section 3.1 fixes
    that field on every canonical **top-level** record.

    **Why a digest and not the structured value.** Eligibility only ever tests
    *equality* of an assumption between two runs, and the structured forms live in
    records Stage 4 does not own -- ``ExperimentSpec.fee_assumptions``,
    ``slippage_assumptions``, ``execution_assumptions``, ``starting_balance``, and
    ``StrategySpec.parameters``. Reproducing them here would invent a second
    representation of another stage's contract, and ``StrategySpec.parameters`` is
    a ``Mapping``. Plan section 5.5.1 does not flatly forbid a mapping here -- its
    "latent collision" paragraph says introducing one would require a further
    reviewed correction widening the ``types`` location list, which Task 7 has no
    authority to make. Stated precisely, because a later task could otherwise cite
    a paraphrase as precedent.
    Hashing is the specification's own idiom for exactly this: section 11.3 gives
    ``ExperimentSpec`` a ``configuration_hash`` and ``EngineRunRequest`` a
    ``configuration_hash`` beside its snapshot. Splitting one configuration hash
    into one digest per named material is what lets the predicate report **every**
    independent assumption mismatch instead of a single blanket one.
    """

    material: ComparisonMaterial
    value_hash: Sha256


class ComparisonDifference(CanonicalModel):
    """One classified difference a side declares between its output and canonical
    semantics.

    A nested record, so it declares no ``schema_version``.

    Specification section 20.4 requires comparison to "classify differences rather
    than erase them", and section 25.3 requires Level 3 results to "identify known
    approximations and unexplained differences". ``category`` is the
    classification; ``detail`` is the bounded human-readable explanation, matching
    ``ApproximationDeclaration.method`` and ``expected_impact``.
    """

    category: DifferenceCategory
    detail: BoundedText


def difference_sort_key(difference: ComparisonDifference) -> tuple[str, str]:
    """Return the total ordering key for one declared difference.

    ``category`` alone is **not** total across the union of two inputs: each side
    may declare the same category with a different explanation, and a
    single-component key would then let arrival order decide the output.
    ``detail`` is the second component for exactly that reason, and a committed
    mutation test proves the one-component prefix collides where the full key does
    not.
    """
    return (str(difference.category), difference.detail)


class ComparisonInput(CanonicalModel):
    """One already-validated comparison input: the material facts of one run.

    **Specification section 11.3 carries no row for this record, and the
    specification does not name it at all.** Section 8.2 types the comparison
    service's inputs as two ``RunManifest`` records, and plan section 5.8 places
    both ``RunManifest`` and ``ComparisonEligibilityService`` in the later stage
    that owns them, while assigning Stage 4 "the pure eligibility predicate over
    two already-validated comparison inputs". The plan therefore authorizes this
    record's existence and leaves its shape to be derived. Each field names the
    binding sentence it comes from, so a reviewer can check a source rather than a
    table that is absent:

    - ``schema_version`` -- plan section 3.1; the record is independently
      constructed by a caller, exactly like ``ApproximationDeclaration``
    - ``comparison_level`` -- section 25's preamble, "Comparison level is an
      immutable experiment input"; the field name is the one sections 11.3 and
      27.2 already use on ``ExperimentSpec``, ``EngineRunRequest``, and
      ``MetricValue``
    - ``engine_name``, ``engine_version``, ``adapter_name``, ``adapter_version``
      -- section 20.2's required provenance, "Engine name and version" and
      "Adapter name and version"; section 25.3 requires Level 3 results to be
      "presented side by side with provenance"
    - ``canonical_schema_version`` -- section 20.2 "Canonical schema version";
      section 25.4 "schema versions"
    - ``methodology_version`` -- section 25.4's "methodology versions" among the
      facts the service checks, together with plan section 5.9's
      ``COMPARISON.METHODOLOGY_MISMATCH``, which is in the closed error-code table
      and therefore has to be emittable from something. **The specification
      defines no run-level methodology version**: section 20.3 places
      ``methodology_version`` on each ``MetricValue``, and section 25.4 writes the
      plural. Collapsing a run's per-metric versions to one scalar is the minimum
      shape that makes the mandated code emittable; a per-metric collection would
      have to be scoped by metric name, which is caller text, and that would
      destroy the reason-bound proof above. The collapse rule for a run whose
      metrics disagree is not defined by any source read here and is escalated in
      the task ledger for the stage that owns ``RunManifest.metrics``.
    - ``strategy_version_hash`` and ``dataset_version_hash`` -- section 20.2
      "Strategy and dataset version hashes"; section 25.4 "strategy hash" and
      "dataset hash"; the field names are ``ExperimentSpec``'s
    - ``assumptions`` -- section 25.4 "configuration assumptions", enumerated by
      sections 25.1 and 25.2 and closed by ``ComparisonMaterial``
    - ``approximations`` -- section 25.4 "approximation declarations"; section
      20.2 lists them in every run's required provenance
    - ``declared_differences`` -- plan lines 3952-3958, which assign
      ``DifferenceCategory`` and "An unexplained difference blocks any claim of
      parity at the affected level" to Task 7, and plan section 6.1, which makes
      "difference classification" this module's responsibility. Cited precisely,
      because specification sections 20.4 and 25.3 put difference classification
      on the comparison **report**, not on one run's record: they are the source
      of the *vocabulary*, not of this field's placement. The field is an input
      because Task 7 computes no metric and compares no numeric series, so it
      cannot derive a difference -- it can only receive, classify, deduplicate,
      and preserve what each side declares.

    **This is not a ``RunManifest`` substitute, and the claim is falsifiable.**
    The record carries none of ``run_id``, ``invocation_id``, ``manifest_id``,
    ``artifact_refs``, ``metrics``, ``diagnostics``, ``warnings``,
    ``semantic_status``, ``process_exit_category``, ``run_manifest_hash``,
    ``attempt_token_hash``, or any lifecycle timestamp -- every one of which
    section 11.3's ``RunManifest`` row requires. A committed test asserts that
    intersection is empty.

    **``assumptions`` is complete, not a subset, and that is a validation
    invariant rather than a container type.** Requiring exactly one entry per
    ``ComparisonMaterial`` makes the level check total: a missing material could
    otherwise skip a required comparison and fail open.

    That makes this field semantically a total function from a closed key set to a
    hash, so the question of whether it is a mapping in disguise is a fair one and
    an independent review put it directly. It is not. The hazard plan section 5.5.1
    exists to close is a **reachable mutable container** that can be changed after
    validated construction; a sorted tuple of frozen records cannot be. Section
    5.5.1 names ordered sequences as a permitted shape, the serialized form is a
    JSON array rather than an object, and totality is expressed entirely by a
    validator -- so no ``Mapping`` contract is required and the section's
    ``types``-widening correction is not triggered.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_input_schema_extra
    )

    schema_version: Literal["1.0.0"]
    comparison_level: ComparisonLevel
    engine_name: NormalizedIdentifier
    engine_version: SemanticVersion
    adapter_name: NormalizedIdentifier
    adapter_version: SemanticVersion
    canonical_schema_version: SemanticVersion
    methodology_version: SemanticVersion
    strategy_version_hash: Sha256
    dataset_version_hash: Sha256
    assumptions: tuple[ComparisonAssumption, ...] = Field(
        min_length=MAX_COMPARISON_ASSUMPTIONS,
        max_length=MAX_COMPARISON_ASSUMPTIONS,
    )
    approximations: tuple[ApproximationDeclaration, ...] = Field(
        max_length=MAX_COMPARISON_APPROXIMATIONS
    )
    declared_differences: tuple[ComparisonDifference, ...] = Field(
        max_length=MAX_INPUT_DECLARED_DIFFERENCES
    )

    @field_validator("assumptions")
    @classmethod
    def validate_assumptions(
        cls,
        value: tuple[ComparisonAssumption, ...],
    ) -> tuple[ComparisonAssumption, ...]:
        """Exactly one entry per material, canonicalized by sorting.

        Order carries no economic meaning, so specification section 11.1 requires
        it to be canonicalized. Sorting rather than rejecting follows the Task 6
        precedent for a **producer-supplied input** collection -- the resolver's
        own ``approximations`` argument imposes no order and the resolver sorts --
        and it is what makes "permuting the input never changes the serialized
        output" a property this task can actually test rather than one it defines
        away.

        Completeness and uniqueness are one check rather than two. With the
        field's ``min_length`` and ``max_length`` both fixed at the vocabulary
        size, a duplicate necessarily shrinks the material set below that size, so
        a separate uniqueness branch would be unreachable code asserting a fact
        this comparison already establishes.
        """
        if frozenset(item.material for item in value) != frozenset(ComparisonMaterial):
            raise ValueError(
                "assumptions must name every comparison material exactly once"
            )
        return tuple(sorted(value, key=lambda item: item.material))

    @field_validator("approximations")
    @classmethod
    def validate_approximations(
        cls,
        value: tuple[ApproximationDeclaration, ...],
    ) -> tuple[ApproximationDeclaration, ...]:
        """At most one record per capability, canonicalized by capability order.

        Specification section 13.2 makes "overlapping declarations" invalid, and
        Task 6's ``CompatibilityResult`` enforces the same one-per-capability
        shape. The Task 6 correction is preserved exactly: ``adapter_version`` is
        authoring provenance and is **never** compared for equality, here or
        anywhere else in this module.

        Identity uniqueness is enforced beside capability uniqueness. Two
        materially different declarations sharing one ``approximation_id`` would
        make the ``approximation_id`` on an exclusion reason ambiguous, so the
        reason could no longer name "the exact approximation" that Phase 11
        requires. An independent review raised this; the capability rule alone
        does not cover it, because the two records may name different
        capabilities.
        """
        names = tuple(item.capability for item in value)
        if len(set(names)) != len(names):
            raise ValueError("input approximations must name each capability once")
        identities = tuple(item.approximation_id for item in value)
        if len(set(identities)) != len(identities):
            raise ValueError("input approximations must carry distinct identities")
        return tuple(sorted(value, key=lambda item: item.capability))

    @field_validator("declared_differences")
    @classmethod
    def validate_declared_differences(
        cls,
        value: tuple[ComparisonDifference, ...],
    ) -> tuple[ComparisonDifference, ...]:
        """One explanation per category per side, canonicalized by category order.

        Bounding by the closed category set rather than by an arbitrary count is
        what makes ``MAX_INPUT_DECLARED_DIFFERENCES`` structural, and what keeps
        the result's difference count a function of two closed vocabularies rather
        than of how much text a caller supplies.
        """
        categories = tuple(item.category for item in value)
        if len(set(categories)) != len(categories):
            raise ValueError("a side declares at most one difference per category")
        return tuple(sorted(value, key=difference_sort_key))

    def assumption_hash(self, material: ComparisonMaterial) -> Sha256:
        """Return the digest for one material.

        Total by construction: ``validate_assumptions`` requires every material to
        be present exactly once, so the loop always finds one. The scan is linear
        over a fourteen-element tuple rather than a cached mapping, because a
        cached mapping would be exactly the reachable mutable container plan
        section 5.5.1 forbids.
        """
        for assumption in self.assumptions:
            if assumption.material is material:
                return assumption.value_hash
        raise ValueError(f"assumption {material} is absent")  # pragma: no cover


class ComparisonIneligibilityReason(CanonicalModel):
    """One machine-readable reason a pair is ineligible at the requested level.

    A nested record, so it declares no ``schema_version``.

    ``error_code`` is closed to the seven ``COMPARISON.`` rows of plan section
    5.9. The two scope fields are state-governed in **both** directions: a scoped
    code must carry its scope, and an unscoped code must not invent one. Omitting
    a scope from a scoped reason would let one assumption mismatch mask another
    after deduplication; attaching one to an unscoped reason would make the
    deduplicated reason count depend on something the predicate never decided.

    Neither the affected comparison level nor the mismatching side is recorded,
    and both omissions are deliberate. The affected level is always the enclosing
    result's ``requested_level`` -- an approximation exclusion exists only for
    that level, by the definition of the check -- so a per-reason copy would be an
    invariant-enforced duplicate of a sibling field. The side is omitted because a
    mismatch between two inputs is symmetric: recording "left" would make swapping
    the two arguments change the serialized reasons, which plan Task 6's
    permutation property and this task's item 6 both forbid.
    """

    error_code: ErrorCode
    material: ComparisonMaterial | MISSING = MISSING  # type: ignore[valid-type]
    approximation_id: ApproximationId | MISSING = MISSING  # type: ignore[valid-type]

    @field_validator("error_code")
    @classmethod
    def validate_error_code(cls, value: str) -> str:
        if value not in COMPARISON_REASON_CODES:
            raise ValueError("comparison reason code is outside the closed set")
        return value

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        """Exactly the scope its code takes, and no other."""
        has_material = not _is_missing(self.material)
        has_approximation = not _is_missing(self.approximation_id)
        if self.error_code == ASSUMPTION_MISMATCH:
            if not has_material or has_approximation:
                raise ValueError(
                    "an assumption mismatch names exactly its comparison material"
                )
            return self
        if self.error_code == APPROXIMATION_EXCLUDES_LEVEL:
            if not has_approximation or has_material:
                raise ValueError(
                    "an approximation exclusion names exactly its approximation"
                )
            return self
        if has_material or has_approximation:
            raise ValueError("an unscoped comparison reason carries no scope")
        return self


def reason_sort_key(reason: ComparisonIneligibilityReason) -> tuple[str, str, str]:
    """Return the total ordering key for one ineligibility reason.

    Total over material content: a reason carries exactly an ``error_code`` and at
    most one of two scopes, so two reasons equal on this key are byte-identical
    and one was already removed by deduplication. No tie can therefore be resolved
    by generation order, which is what makes the permutation property
    non-vacuous.

    **The third component is load-bearing.** Two distinct
    ``APPROXIMATION_EXCLUDES_LEVEL`` reasons share the first two components and
    are separated only by ``approximation_id``; a committed mutation test proves a
    two-component prefix collides where the full key does not.

    An absent component takes the empty string, the same device plan section 5.10
    fixes for a spec-level finding and Task 6 uses for an unscoped reason.
    """
    material = reason.material
    approximation_id = reason.approximation_id
    return (
        reason.error_code,
        "" if _is_missing(material) else str(material),
        "" if _is_missing(approximation_id) else str(approximation_id),
    )


class ComparisonEligibilityResult(CanonicalModel):
    """The structured outcome of one eligibility evaluation at one requested level.

    **Specification section 11.3 carries no row for this record either.** Plan
    line 2944 names it among the models taking "exactly the minimum fields their
    specification section 11.3 rows list", but no such row exists -- the identical
    defect Task 6 recorded for ``CompatibilityResult``. Each field's derivation:

    - ``schema_version`` -- plan section 3.1, and Task 8 generates this record's
      schema
    - ``outcome`` -- section 25.4, exactly one of three
    - ``requested_level`` -- section 8.2's ``requested_level`` parameter, retained
      because section 25's preamble makes the level an immutable input and every
      reason is relative to it
    - ``achieved_level`` -- plan test item 1, "Requested versus achieved level are
      distinct fields and both are recorded"
    - ``left`` and ``right`` -- section 25.3, Level 3 results "are presented side
      by side with provenance and assumptions"; both inputs are retained verbatim
      so neither side's provenance is rewritten or deleted
    - ``reasons`` -- section 25.4's "stable reasons"
    - ``declared_differences`` -- section 20.4's requirement to classify
      differences rather than erase them

    There is no ``comparison_eligibility_result_id`` and no ``created_at_utc``:
    plan section 6.2 authorizes exactly two new identifier types, ``appx_`` and
    ``avail_``, so the plan does not treat this as an independently identified
    operational record, and this module has no clock.

    **``achieved_level`` is state-governed, and never lower than requested.**
    Specification section 25's preamble states that a run "that cannot satisfy the
    requested level is excluded from that level rather than coerced", and
    specification section 14.2's negotiation rule states the core "never guesses a
    version or silently downgrades a stored request". No sentence in the
    specification or the plan ranks levels for eligibility purposes -- 25.2's
    "Level 2 requires Level 1" is a statement about the assumption set, and
    ``StrategySpec.comparison_requirements.maximum_level`` is covered by
    ``strategy_version_hash``. So the level is achieved or it is not: the field is
    present and equal to ``requested_level`` on an eligible outcome, and ``MISSING``
    on ``INELIGIBLE``. The two fields remain distinct and both load-bearing --
    conflating them is caught by every ineligible case, and dropping
    ``achieved_level`` is caught by every eligible one.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_result_schema_extra
    )

    schema_version: Literal["1.0.0"]
    outcome: ComparisonEligibilityOutcome
    requested_level: ComparisonLevel
    achieved_level: ComparisonLevel | MISSING = MISSING  # type: ignore[valid-type]
    left: ComparisonInput
    right: ComparisonInput
    reasons: tuple[ComparisonIneligibilityReason, ...] = Field(
        max_length=MAX_COMPARISON_REASONS
    )
    declared_differences: tuple[ComparisonDifference, ...] = Field(
        max_length=MAX_RESULT_DECLARED_DIFFERENCES
    )

    @field_validator("reasons")
    @classmethod
    def validate_reasons(
        cls,
        value: tuple[ComparisonIneligibilityReason, ...],
    ) -> tuple[ComparisonIneligibilityReason, ...]:
        """Deduplicated and totally ordered, enforced at the record boundary.

        Enforcing it here rather than only in the predicate means a hand-built
        result cannot publish an order the predicate would never produce, so
        byte-identity is a property of the *type* and not of one code path.
        """
        keys = tuple(reason_sort_key(reason) for reason in value)
        if len(set(keys)) != len(keys):
            raise ValueError("comparison reasons must be deduplicated")
        if keys != tuple(sorted(keys)):
            raise ValueError("comparison reasons must be canonically ordered")
        return value

    @field_validator("declared_differences")
    @classmethod
    def validate_declared_differences(
        cls,
        value: tuple[ComparisonDifference, ...],
    ) -> tuple[ComparisonDifference, ...]:
        """Deduplicated and totally ordered, for the same reason as ``reasons``."""
        keys = tuple(difference_sort_key(item) for item in value)
        if len(set(keys)) != len(keys):
            raise ValueError("declared differences must be deduplicated")
        if keys != tuple(sorted(keys)):
            raise ValueError("declared differences must be canonically ordered")
        return value

    @model_validator(mode="after")
    def validate_outcome_shape(self) -> Self:
        """The state-governed optionality of this record, as an invariant.

        - ``INELIGIBLE`` -- at least one reason, and no achieved level. A result
          claiming ineligibility with no reason would be an unexplained refusal,
          which specification section 25.4 forbids by calling ineligibility "a
          structured result".
        - ``ELIGIBLE`` -- no reason, no declared difference, and no approximation
          on either side. Section 20.4 classifies "Declared approximation" as a
          difference, so a plain ``ELIGIBLE`` beside an approximation record would
          be a parity claim the specification does not support.
        - ``ELIGIBLE_WITH_DECLARED_DIFFERENCES`` -- no reason, and something
          actually declared: a difference on either side or an approximation on
          either side. This is what makes "an unexplained difference blocks any
          claim of parity at the affected level" a property of the type: an
          unexplained difference is a declared difference, so the outcome can
          never be ``ELIGIBLE`` while one is present.
        """
        achieved = self.achieved_level
        declared = bool(
            self.declared_differences
            or self.left.approximations
            or self.right.approximations
        )
        if self.outcome is ComparisonEligibilityOutcome.INELIGIBLE:
            if not self.reasons:
                raise ValueError("an ineligible outcome requires at least one reason")
            if not _is_missing(achieved):
                raise ValueError("an ineligible outcome achieves no comparison level")
            return self
        if self.reasons:
            raise ValueError("an eligible outcome carries no reason")
        if achieved is not self.requested_level:
            raise ValueError("an eligible outcome achieves exactly the requested level")
        if self.outcome is ComparisonEligibilityOutcome.ELIGIBLE and declared:
            raise ValueError("a plain eligible outcome declares no difference")
        if (
            self.outcome
            is ComparisonEligibilityOutcome.ELIGIBLE_WITH_DECLARED_DIFFERENCES
            and not declared
        ):
            raise ValueError("an eligible-with-differences outcome declares something")
        return self


# ---------------------------------------------------------------------------
# The pure eligibility predicate
# ---------------------------------------------------------------------------


def _reason(
    code: str,
    *,
    material: ComparisonMaterial | None = None,
    approximation_id: str | None = None,
) -> ComparisonIneligibilityReason:
    if material is not None:
        return ComparisonIneligibilityReason(error_code=code, material=material)
    if approximation_id is not None:
        return ComparisonIneligibilityReason(
            error_code=code, approximation_id=approximation_id
        )
    return ComparisonIneligibilityReason(error_code=code)


def _ordered_reasons(
    reasons: list[ComparisonIneligibilityReason],
) -> tuple[ComparisonIneligibilityReason, ...]:
    """Deduplicate by material content, then order totally.

    Deduplication precedes ordering, so the sequence is a function of the *set* of
    logical reasons rather than of generation order.
    """
    unique: dict[tuple[str, str, str], ComparisonIneligibilityReason] = {}
    for reason in reasons:
        unique.setdefault(reason_sort_key(reason), reason)
    return tuple(unique[key] for key in sorted(unique))


def _union_differences(
    left: ComparisonInput,
    right: ComparisonInput,
) -> tuple[ComparisonDifference, ...]:
    """Both sides' declarations, deduplicated by content and totally ordered.

    Neither side is preferred and neither is dropped: specification section 20.4
    requires differences to be classified rather than erased, and section 25.3
    forbids rewriting one side's provenance. Because the union is deduplicated by
    ``(category, detail)`` and then sorted, swapping the two arguments cannot
    change these bytes.
    """
    unique: dict[tuple[str, str], ComparisonDifference] = {}
    for difference in (*left.declared_differences, *right.declared_differences):
        unique.setdefault(difference_sort_key(difference), difference)
    return tuple(unique[key] for key in sorted(unique))


def _collect_reasons(
    left: ComparisonInput,
    right: ComparisonInput,
    requested_level: ComparisonLevel,
) -> tuple[ComparisonIneligibilityReason, ...]:
    """Every independent reason, never only the first.

    The six checks below are exactly specification section 25.4's own enumeration
    -- "dataset hash, strategy hash, configuration assumptions, schema versions,
    methodology versions, and approximation declarations" -- plus the requested
    level itself. Each named check maps to exactly one code, so no mismatch can
    fit two codes and no precedence is guessed. Every check runs; none returns
    early, so an assumption mismatch never masks a hash mismatch on a different
    material.
    """
    reasons: list[ComparisonIneligibilityReason] = []

    # The requested level must be the immutable level each run was produced for.
    # Section 25's preamble excludes a run that "cannot satisfy the requested
    # level" from that level "rather than coerced", and section 14.2 forbids
    # silently downgrading a stored request, so this is exact equality rather than
    # a subsumption test: a subsumption lattice would be strictly more permissive
    # and no sentence directs one.
    #
    # Section 25.2's "Level 2 requires Level 1" is the sentence a subsumption
    # reading would lean on, and it is engaged rather than ignored: it fixes the
    # *assumption set*, which `required_materials` implements exactly by returning
    # `LEVEL_1_MATERIALS + LEVEL_2_MATERIALS` for Level 2. It says nothing about a
    # Level 2 run being admissible to a Level 1 comparison, and section 25.3 has no
    # counterpart at all, so the ladder cannot be completed from any source. The
    # consequence -- two Level 2 runs cannot be compared at Level 1 without
    # misstating their immutable level -- is escalated in the task ledger for the
    # stage that owns the service, not resolved by inventing the missing rung.
    if (
        left.comparison_level is not requested_level
        or right.comparison_level is not requested_level
    ):
        reasons.append(_reason(LEVEL_UNSUPPORTED))

    # The four unconditional section 25.4 identity checks, at every level. Each
    # compares a canonical hash or version, never a human-readable name.
    if left.strategy_version_hash != right.strategy_version_hash:
        reasons.append(_reason(STRATEGY_HASH_MISMATCH))
    if left.dataset_version_hash != right.dataset_version_hash:
        reasons.append(_reason(DATASET_HASH_MISMATCH))
    if left.canonical_schema_version != right.canonical_schema_version:
        reasons.append(_reason(SCHEMA_VERSION_MISMATCH))
    if left.methodology_version != right.methodology_version:
        reasons.append(_reason(METHODOLOGY_MISMATCH))

    # Section 25.4's "configuration assumptions", scoped by the level's own
    # requirement set. A Level 1-compatible pair can still be ineligible for
    # Level 2, because Level 2 requires Level 1 plus nine further materials.
    for material in required_materials(requested_level):
        if left.assumption_hash(material) != right.assumption_hash(material):
            reasons.append(_reason(ASSUMPTION_MISMATCH, material=material))

    # Section 25's preamble: "A run or approximation that cannot satisfy the
    # requested level is excluded from that level rather than coerced." Exact,
    # per plan test item 5. An approximation that prevents some *other* level is
    # not a reason. `adapter_version` is never consulted -- it is authoring
    # provenance, as the Task 6 correction established.
    for declaration in (*left.approximations, *right.approximations):
        if requested_level in declaration.prevented_comparison_levels:
            reasons.append(
                _reason(
                    APPROXIMATION_EXCLUDES_LEVEL,
                    approximation_id=declaration.approximation_id,
                )
            )

    return _ordered_reasons(reasons)


def evaluate_comparison_eligibility(
    left: ComparisonInput,
    right: ComparisonInput,
    requested_level: ComparisonLevel,
) -> ComparisonEligibilityResult:
    """Return one structured eligibility decision for two already-validated inputs.

    The parameter names and order are specification section 8.2's
    ``ComparisonEligibilityService.evaluate(left, right, requested_level)``, whose
    preamble requires "parameters, ownership, sync/async behavior, and result
    semantics" to remain equivalent when a name moves between files. The two input
    types differ from 8.2's ``RunManifest`` because plan section 5.8 places that
    record in a later stage; the parameter *roles* are unchanged.

    The return type is 8.2's own ``-> ComparisonEligibilityResult`` rather than
    ``Result[T]``. Section 8.2's preamble introduces ``Result[T]`` for the case
    where "expected boundary failures are not communicated only through
    exceptions", and section 25.4 states that ineligibility is "a structured
    result, not data deletion or retroactive run failure". Ineligibility is an
    answer, not a failure to answer, so no ``Result`` wrapper applies.

    ``left`` and ``right`` are preserved in the result in the caller's order,
    because section 25.3 requires results to be "presented side by side with
    provenance and assumptions" and forbids rewriting either side. The four
    *eligibility* components -- ``outcome``, ``achieved_level``, ``reasons``, and
    ``declared_differences`` -- are byte-identical under swapping the two
    arguments; only the side-by-side provenance follows the caller's order.

    Nothing here averages, votes, combines, merges, promotes, or synthesizes.
    """
    reasons = _collect_reasons(left, right, requested_level)
    declared_differences = _union_differences(left, right)

    if reasons:
        return ComparisonEligibilityResult(
            schema_version="1.0.0",
            outcome=ComparisonEligibilityOutcome.INELIGIBLE,
            requested_level=requested_level,
            left=left,
            right=right,
            reasons=reasons,
            declared_differences=declared_differences,
        )

    # Specification section 20.4 lists "Declared approximation" among the fourteen
    # difference categories, and section 25.3 requires results to "identify known
    # approximations and unexplained differences" in one breath. A declared
    # approximation is therefore itself a declared difference, and a pair carrying
    # one is eligible *with declared differences* rather than plainly eligible.
    # No synthetic difference record is fabricated for it: the declarations are
    # already preserved verbatim inside `left` and `right`, and manufacturing a
    # second representation of one logical fact was rejected.
    declared = bool(declared_differences or left.approximations or right.approximations)
    outcome = (
        ComparisonEligibilityOutcome.ELIGIBLE_WITH_DECLARED_DIFFERENCES
        if declared
        else ComparisonEligibilityOutcome.ELIGIBLE
    )
    return ComparisonEligibilityResult(
        schema_version="1.0.0",
        outcome=outcome,
        requested_level=requested_level,
        achieved_level=requested_level,
        left=left,
        right=right,
        reasons=reasons,
        declared_differences=declared_differences,
    )
