"""Comparison levels, eligibility contracts, and difference classification.

Plan Task 7. The seven-item test-first sequence of plan lines 3965-3979 is
followed in order and each section names its item. Items 6 and 7 are
**preventive**: they start green once the module exists and are declared here so
they cannot silently stop being true, exactly as
``tests/architecture/test_package_import_boundaries.py`` labels its ``strategy``
assertions. They are not presented as behavioural RED.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, cast

import pytest
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.capabilities import comparison as comparison_module
from crypto_lab.capabilities.comparison import (
    APPROXIMATION_EXCLUDES_LEVEL,
    ASSUMPTION_MISMATCH,
    COMPARISON_REASON_CODES,
    DATASET_HASH_MISMATCH,
    LEVEL_1_MATERIALS,
    LEVEL_2_MATERIALS,
    LEVEL_3_MATERIALS,
    LEVEL_UNSUPPORTED,
    MAX_COMPARISON_APPROXIMATIONS,
    MAX_COMPARISON_ASSUMPTIONS,
    MAX_COMPARISON_REASONS,
    MAX_INPUT_DECLARED_DIFFERENCES,
    MAX_RESULT_DECLARED_DIFFERENCES,
    METHODOLOGY_MISMATCH,
    SCHEMA_VERSION_MISMATCH,
    STRATEGY_HASH_MISMATCH,
    ComparisonAssumption,
    ComparisonDifference,
    ComparisonEligibilityOutcome,
    ComparisonEligibilityResult,
    ComparisonIneligibilityReason,
    ComparisonInput,
    ComparisonMaterial,
    DifferenceCategory,
    difference_sort_key,
    evaluate_comparison_eligibility,
    reason_sort_key,
    required_materials,
)
from crypto_lab.capabilities.models import ApproximationDeclaration
from crypto_lab.capabilities.vocabulary import CapabilityVocabulary
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.comparison_levels import ComparisonLevel

_STRATEGY_HASH = "1" * 64
_DATASET_HASH = "2" * 64
_ASSUMPTION_HASH = "3" * 64
_OTHER_HASH = "4" * 64
_APPROXIMATION_ID = "appx_5b1c3d7e-2f4a-4c6b-8d9e-1a2b3c4d5e6f"
_OTHER_APPROXIMATION_ID = "appx_7d3e1f5a-4b6c-4d8e-9a1b-2c3d4e5f6a7b"

#: **Exactly** the nineteen fields specification section 11.3's ``RunManifest`` row
#: lists, transcribed verbatim from spec line 578 rather than hand-curated. An
#: independent review found the first draft of this set both incomplete and
#: padded, which made the guard prove less than it claimed; it is now the literal
#: row, and the two legitimately shared names are named separately below so the
#: judgement is visible instead of baked into the list.
_RUN_MANIFEST_ROW_FIELDS = frozenset(
    {
        "schema_version",
        "protocol_version",
        "manifest_id",
        "experiment_id",
        "run_id",
        "run_invocation_id",
        "attempt_token_hash",
        "sanitized_adapter_result_manifest_hash",
        "semantic_status",
        "process_exit_category",
        "started_at_utc",
        "completed_at_utc",
        "provenance",
        "artifact_refs",
        "metrics",
        "diagnostics",
        "warnings",
        "approximations",
        "run_manifest_hash",
    }
)
#: The only two ``RunManifest`` field names Task 7's records may share, and why.
#: ``schema_version`` is on every canonical top-level record by plan section 3.1,
#: so its presence carries no information about ``RunManifest`` at all.
#: ``approximations`` is named by specification section 25.4 as one of the six
#: facts the comparison service checks, so an eligibility input that omitted it
#: could not implement plan test item 5.
_SHARED_WITH_RUN_MANIFEST = frozenset({"schema_version", "approximations"})


# --------------------------------------------------------------------------
# Builders
# --------------------------------------------------------------------------


def _assumptions(
    changed: frozenset[ComparisonMaterial] = frozenset(),
) -> tuple[ComparisonAssumption, ...]:
    return tuple(
        ComparisonAssumption(
            material=material,
            value_hash=_OTHER_HASH if material in changed else _ASSUMPTION_HASH,
        )
        for material in ComparisonMaterial
    )


def _approximation(
    approximation_id: str = _APPROXIMATION_ID,
    capability: str = "execution.partial_fills",
    prevented: tuple[ComparisonLevel, ...] = (),
    adapter_version: str = "1.0.0",
) -> ApproximationDeclaration:
    return ApproximationDeclaration(
        schema_version="1.0.0",
        approximation_id=approximation_id,
        capability=capability,
        method="Partial fills collapse into one terminal fill at the bar close.",
        expected_impact="Intra-bar fill timing differs from the native engine.",
        prevented_comparison_levels=prevented,
        adapter_version=adapter_version,
    )


def _difference(
    category: DifferenceCategory = DifferenceCategory.FEE_MODELING,
    detail: str = "Maker and taker fees are modelled with one blended rate.",
) -> ComparisonDifference:
    return ComparisonDifference(category=category, detail=detail)


def _input(**overrides: Any) -> ComparisonInput:
    fields: dict[str, Any] = {
        "schema_version": "1.0.0",
        "comparison_level": ComparisonLevel.LEVEL_1,
        "engine_name": "vectorbt",
        "engine_version": "1.0.0",
        "adapter_name": "vectorbt-adapter",
        "adapter_version": "1.0.0",
        "canonical_schema_version": "1.0.0",
        "methodology_version": "1.0.0",
        "strategy_version_hash": _STRATEGY_HASH,
        "dataset_version_hash": _DATASET_HASH,
        "assumptions": _assumptions(),
        "approximations": (),
        "declared_differences": (),
    }
    fields.update(overrides)
    return ComparisonInput(**fields)


def _reason(code: str, **scope: Any) -> ComparisonIneligibilityReason:
    return ComparisonIneligibilityReason(error_code=code, **scope)


def _codes(result: ComparisonEligibilityResult) -> tuple[str, ...]:
    return tuple(reason.error_code for reason in result.reasons)


def _achieves_no_level(result: ComparisonEligibilityResult) -> bool:
    """``achieved_level`` is absent, checked the way plan section 3.1 permits.

    ``is MISSING`` is rejected by strict mypy as a non-overlapping identity check,
    because the ``# type: ignore[valid-type]`` sentinel annotation narrows the
    attribute to its present type. Task 6 established comparing by type and
    asserting omission from **both** dump modes -- python mode is load-bearing in
    its own right, because ``canonical_json._normalize`` reaches a model through
    ``model_dump(mode="python")`` and raises on an unsupported type.
    """
    return (
        not isinstance(result.achieved_level, ComparisonLevel)
        and "achieved_level" not in result.model_dump(mode="python")
        and "achieved_level" not in result.model_dump(mode="json")
    )


def _eligibility_components(result: ComparisonEligibilityResult) -> tuple[Any, ...]:
    """The four components that must not depend on which input is ``left``.

    ``left`` and ``right`` are deliberately excluded: specification section 25.3
    requires results to be "presented side by side with provenance and
    assumptions", so canonicalizing the two sides by engine name would make the
    field named ``left`` not be the caller's left, which reads as rewriting
    provenance.
    """
    return (
        result.outcome,
        result.achieved_level,
        canonical_json_bytes(result.reasons),
        canonical_json_bytes(result.declared_differences),
    )


# --------------------------------------------------------------------------
# Plan test item 1 -- requested versus achieved level
# --------------------------------------------------------------------------


def test_requested_and_achieved_levels_are_distinct_recorded_fields() -> None:
    """Plan test item 1. **Expected RED:** module missing."""
    result = evaluate_comparison_eligibility(
        _input(), _input(), ComparisonLevel.LEVEL_1
    )

    assert result.requested_level is ComparisonLevel.LEVEL_1
    assert result.achieved_level is ComparisonLevel.LEVEL_1
    assert result.outcome is ComparisonEligibilityOutcome.ELIGIBLE
    fields = tuple(ComparisonEligibilityResult.model_fields)
    assert "requested_level" in fields
    assert "achieved_level" in fields


def test_an_ineligible_result_achieves_no_level_at_all() -> None:
    """The half of item 1 that makes the two fields genuinely distinct.

    A mutation setting ``achieved_level = requested_level`` unconditionally is
    killed here; a mutation dropping ``achieved_level`` is killed by the test
    above.
    """
    result = evaluate_comparison_eligibility(
        _input(), _input(strategy_version_hash=_OTHER_HASH), ComparisonLevel.LEVEL_1
    )

    assert result.outcome is ComparisonEligibilityOutcome.INELIGIBLE
    assert _achieves_no_level(result)
    assert result.requested_level is ComparisonLevel.LEVEL_1


def test_the_achieved_level_is_never_lower_than_the_requested_level() -> None:
    """Specification 25's preamble excludes rather than coerces.

    A Level 2 request that fails only on a Level 2 assumption is ``INELIGIBLE``
    at Level 2. It is **not** silently reported as eligible at Level 1.
    """
    left = _input(comparison_level=ComparisonLevel.LEVEL_2)
    right = _input(
        comparison_level=ComparisonLevel.LEVEL_2,
        assumptions=_assumptions(frozenset({ComparisonMaterial.FEE_ASSUMPTIONS})),
    )

    result = evaluate_comparison_eligibility(left, right, ComparisonLevel.LEVEL_2)

    assert result.outcome is ComparisonEligibilityOutcome.INELIGIBLE
    assert _achieves_no_level(result)
    assert _codes(result) == (ASSUMPTION_MISMATCH,)
    # Level 1 alone would have been satisfied, and that is deliberately not
    # represented as an eligible result at a lower level.
    assert (
        evaluate_comparison_eligibility(
            _input(), _input(), ComparisonLevel.LEVEL_1
        ).outcome
        is ComparisonEligibilityOutcome.ELIGIBLE
    )


def test_the_result_rejects_a_conflated_or_missing_achieved_level() -> None:
    """The invariant is on the type, not only in the predicate."""
    eligible = evaluate_comparison_eligibility(
        _input(), _input(), ComparisonLevel.LEVEL_1
    )
    ineligible = evaluate_comparison_eligibility(
        _input(), _input(dataset_version_hash=_OTHER_HASH), ComparisonLevel.LEVEL_1
    )

    with pytest.raises(ValidationError):
        ComparisonEligibilityResult(
            **{**eligible.model_dump(mode="python"), "achieved_level": MISSING}
        )
    with pytest.raises(ValidationError):
        ComparisonEligibilityResult(
            **{
                **ineligible.model_dump(mode="python"),
                "achieved_level": ComparisonLevel.LEVEL_1,
            }
        )
    with pytest.raises(ValidationError):
        ComparisonEligibilityResult(
            **{
                **eligible.model_dump(mode="python"),
                "achieved_level": ComparisonLevel.LEVEL_2,
            }
        )


# --------------------------------------------------------------------------
# Plan test item 2 -- Level 1 eligibility
# --------------------------------------------------------------------------


def test_two_identical_level_one_inputs_are_eligible() -> None:
    result = evaluate_comparison_eligibility(
        _input(), _input(), ComparisonLevel.LEVEL_1
    )

    assert result.outcome is ComparisonEligibilityOutcome.ELIGIBLE
    assert result.reasons == ()
    assert result.declared_differences == ()


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("strategy_version_hash", _OTHER_HASH, STRATEGY_HASH_MISMATCH),
        ("dataset_version_hash", _OTHER_HASH, DATASET_HASH_MISMATCH),
        ("canonical_schema_version", "2.0.0", SCHEMA_VERSION_MISMATCH),
        ("methodology_version", "2.0.0", METHODOLOGY_MISMATCH),
    ],
)
def test_each_unconditional_identity_mismatch_uses_its_exact_code(
    field: str,
    value: str,
    code: str,
) -> None:
    """Specification 25.4's own check list, one code each, no guessed precedence."""
    result = evaluate_comparison_eligibility(
        _input(), _input(**{field: value}), ComparisonLevel.LEVEL_1
    )

    assert result.outcome is ComparisonEligibilityOutcome.INELIGIBLE
    assert _codes(result) == (code,)


@pytest.mark.parametrize("material", LEVEL_1_MATERIALS)
def test_every_level_one_assumption_is_required_to_match(
    material: ComparisonMaterial,
) -> None:
    """Plan test item 2: warm-up, feature semantics, parameters, universe, Decimal."""
    result = evaluate_comparison_eligibility(
        _input(),
        _input(assumptions=_assumptions(frozenset({material}))),
        ComparisonLevel.LEVEL_1,
    )

    assert result.outcome is ComparisonEligibilityOutcome.INELIGIBLE
    assert result.reasons == (_reason(ASSUMPTION_MISMATCH, material=material),)


@pytest.mark.parametrize("material", LEVEL_2_MATERIALS)
def test_a_level_two_assumption_never_gates_a_level_one_request(
    material: ComparisonMaterial,
) -> None:
    """Level 1 compares strategy intent; execution assumptions are outside it.

    Specification 25.1 states that "Execution fills and portfolio accounting are
    outside Level 1", so widening Level 1 to the Level 2 set would reject pairs
    the specification admits.
    """
    result = evaluate_comparison_eligibility(
        _input(),
        _input(assumptions=_assumptions(frozenset({material}))),
        ComparisonLevel.LEVEL_1,
    )

    assert result.outcome is ComparisonEligibilityOutcome.ELIGIBLE


def test_a_human_readable_name_never_substitutes_for_a_hash() -> None:
    """Engine and adapter identity are provenance, never an eligibility test.

    Two different engines are the *point* of a cross-engine comparison, so
    differing names must not produce a reason; and matching names must not excuse
    a differing strategy hash.
    """
    same_hashes = evaluate_comparison_eligibility(
        _input(engine_name="vectorbt", adapter_name="vectorbt-adapter"),
        _input(engine_name="freqtrade", adapter_name="freqtrade-adapter"),
        ComparisonLevel.LEVEL_1,
    )
    assert same_hashes.outcome is ComparisonEligibilityOutcome.ELIGIBLE

    same_names = evaluate_comparison_eligibility(
        _input(), _input(strategy_version_hash=_OTHER_HASH), ComparisonLevel.LEVEL_1
    )
    assert same_names.outcome is ComparisonEligibilityOutcome.INELIGIBLE


def test_the_complete_level_one_reason_set_is_returned_not_the_first() -> None:
    """Plan test item 6's completeness requirement, at Level 1."""
    result = evaluate_comparison_eligibility(
        _input(),
        _input(
            strategy_version_hash=_OTHER_HASH,
            dataset_version_hash=_OTHER_HASH,
            canonical_schema_version="2.0.0",
            methodology_version="2.0.0",
            assumptions=_assumptions(frozenset(LEVEL_1_MATERIALS)),
        ),
        ComparisonLevel.LEVEL_1,
    )

    assert result.outcome is ComparisonEligibilityOutcome.INELIGIBLE
    assert len(result.reasons) == 4 + len(LEVEL_1_MATERIALS)
    assert set(_codes(result)) == {
        STRATEGY_HASH_MISMATCH,
        DATASET_HASH_MISMATCH,
        SCHEMA_VERSION_MISMATCH,
        METHODOLOGY_MISMATCH,
        ASSUMPTION_MISMATCH,
    }


def test_a_requested_level_the_inputs_were_not_produced_for_is_unsupported() -> None:
    """Specification 25's preamble: excluded from that level, never coerced."""
    result = evaluate_comparison_eligibility(
        _input(comparison_level=ComparisonLevel.LEVEL_1),
        _input(comparison_level=ComparisonLevel.LEVEL_1),
        ComparisonLevel.LEVEL_2,
    )

    assert result.outcome is ComparisonEligibilityOutcome.INELIGIBLE
    assert LEVEL_UNSUPPORTED in _codes(result)


def test_one_unsupported_side_is_enough_and_yields_one_reason() -> None:
    """Symmetric by construction: the side is deliberately not recorded."""
    left_wrong = evaluate_comparison_eligibility(
        _input(comparison_level=ComparisonLevel.LEVEL_2),
        _input(comparison_level=ComparisonLevel.LEVEL_1),
        ComparisonLevel.LEVEL_1,
    )
    right_wrong = evaluate_comparison_eligibility(
        _input(comparison_level=ComparisonLevel.LEVEL_1),
        _input(comparison_level=ComparisonLevel.LEVEL_2),
        ComparisonLevel.LEVEL_1,
    )

    assert _codes(left_wrong) == (LEVEL_UNSUPPORTED,)
    assert _codes(right_wrong) == (LEVEL_UNSUPPORTED,)
    assert canonical_json_bytes(left_wrong.reasons) == canonical_json_bytes(
        right_wrong.reasons
    )


# --------------------------------------------------------------------------
# Plan test item 3 -- Level 2 eligibility
# --------------------------------------------------------------------------


def test_level_two_requires_level_one_plus_the_specification_25_2_assumptions() -> None:
    """Plan test item 3, against the exact section 25.2 list."""
    assert required_materials(ComparisonLevel.LEVEL_1) == LEVEL_1_MATERIALS
    assert (
        required_materials(ComparisonLevel.LEVEL_2)
        == LEVEL_1_MATERIALS + LEVEL_2_MATERIALS
    )
    assert required_materials(ComparisonLevel.LEVEL_3) == LEVEL_3_MATERIALS
    # Level 3 relaxes section 25.2's execution parity and nothing else.
    assert LEVEL_3_MATERIALS == LEVEL_1_MATERIALS
    assert frozenset(LEVEL_1_MATERIALS) | frozenset(LEVEL_2_MATERIALS) == frozenset(
        ComparisonMaterial
    )
    assert frozenset(LEVEL_1_MATERIALS) & frozenset(LEVEL_2_MATERIALS) == frozenset()


@pytest.mark.parametrize("material", LEVEL_1_MATERIALS + LEVEL_2_MATERIALS)
def test_every_level_two_assumption_is_required_to_match(
    material: ComparisonMaterial,
) -> None:
    result = evaluate_comparison_eligibility(
        _input(comparison_level=ComparisonLevel.LEVEL_2),
        _input(
            comparison_level=ComparisonLevel.LEVEL_2,
            assumptions=_assumptions(frozenset({material})),
        ),
        ComparisonLevel.LEVEL_2,
    )

    assert result.outcome is ComparisonEligibilityOutcome.INELIGIBLE
    assert result.reasons == (_reason(ASSUMPTION_MISMATCH, material=material),)


def test_a_level_one_compatible_pair_can_still_be_ineligible_for_level_two() -> None:
    left = _input(comparison_level=ComparisonLevel.LEVEL_2)
    right = _input(
        comparison_level=ComparisonLevel.LEVEL_2,
        assumptions=_assumptions(
            frozenset(
                {
                    ComparisonMaterial.FEE_ASSUMPTIONS,
                    ComparisonMaterial.SLIPPAGE_ASSUMPTIONS,
                }
            )
        ),
    )

    at_level_two = evaluate_comparison_eligibility(left, right, ComparisonLevel.LEVEL_2)
    assert at_level_two.outcome is ComparisonEligibilityOutcome.INELIGIBLE
    assert len(at_level_two.reasons) == 2

    level_one_pair = (
        _input(),
        _input(
            assumptions=_assumptions(
                frozenset(
                    {
                        ComparisonMaterial.FEE_ASSUMPTIONS,
                        ComparisonMaterial.SLIPPAGE_ASSUMPTIONS,
                    }
                )
            )
        ),
    )
    at_level_one = evaluate_comparison_eligibility(
        *level_one_pair, ComparisonLevel.LEVEL_1
    )
    assert at_level_one.outcome is ComparisonEligibilityOutcome.ELIGIBLE


def test_all_independent_level_two_failures_are_retained_in_stable_order() -> None:
    materials = frozenset(LEVEL_2_MATERIALS)
    result = evaluate_comparison_eligibility(
        _input(comparison_level=ComparisonLevel.LEVEL_2),
        _input(
            comparison_level=ComparisonLevel.LEVEL_2,
            assumptions=_assumptions(materials),
        ),
        ComparisonLevel.LEVEL_2,
    )

    assert len(result.reasons) == len(LEVEL_2_MATERIALS)
    reported = tuple(str(reason.material) for reason in result.reasons)
    assert reported == tuple(sorted(str(item) for item in materials))


# --------------------------------------------------------------------------
# Plan test item 4 -- Level 3 side-by-side provenance
# --------------------------------------------------------------------------


def test_level_three_records_both_sides_verbatim_and_averages_nothing() -> None:
    """Plan test item 4; specification 25.3's side-by-side requirement."""
    left = _input(
        comparison_level=ComparisonLevel.LEVEL_3,
        engine_name="vectorbt",
        engine_version="1.2.0",
        adapter_name="vectorbt-adapter",
        adapter_version="3.4.5",
    )
    right = _input(
        comparison_level=ComparisonLevel.LEVEL_3,
        engine_name="freqtrade",
        engine_version="9.8.7",
        adapter_name="freqtrade-adapter",
        adapter_version="6.5.4",
    )

    result = evaluate_comparison_eligibility(left, right, ComparisonLevel.LEVEL_3)

    assert result.outcome is ComparisonEligibilityOutcome.ELIGIBLE
    # Neither side is rewritten, merged, or dropped.
    assert result.left == left
    assert result.right == right
    assert result.left.engine_name == "vectorbt"
    assert result.right.engine_name == "freqtrade"
    assert result.left.assumptions == left.assumptions
    assert result.right.assumptions == right.assumptions


def test_level_three_does_not_require_execution_assumption_parity() -> None:
    """Specification 25.3: native execution models differ by design.

    Section 25.3 classifies Level 3 differences by "execution, fill, fee,
    portfolio, precision, or modeling semantics" -- exactly the section 25.2
    surface. Differing there, with nothing declared, is ``ELIGIBLE`` at Level 3.
    """
    result = evaluate_comparison_eligibility(
        _input(comparison_level=ComparisonLevel.LEVEL_3),
        _input(
            comparison_level=ComparisonLevel.LEVEL_3,
            assumptions=_assumptions(frozenset(LEVEL_2_MATERIALS)),
        ),
        ComparisonLevel.LEVEL_3,
    )

    assert result.outcome is ComparisonEligibilityOutcome.ELIGIBLE


@pytest.mark.parametrize("material", LEVEL_1_MATERIALS)
def test_level_three_still_requires_the_declared_input_parity_of_level_one(
    material: ComparisonMaterial,
) -> None:
    """The correction an independent review forced, pinned per material.

    Section 25.3 scopes itself to "the declared experiment", singular, and its
    classification list never names warm-up, feature semantics, parameters,
    universe, or Decimal rules -- those are section 25.1's declared *inputs*, and
    two runs of one experiment share them. Section 25.4's eligibility check list
    names "configuration assumptions" unconditionally.

    The earlier empty-set ruling returned plain ``ELIGIBLE`` here, which
    ``validate_outcome_shape`` defines as the outcome carrying no difference at
    all -- an unqualified parity claim over runs with different parameters,
    universes, or Decimal rules. ``DECIMAL_RULES`` in particular is provably not
    covered by ``strategy_version_hash``: ``StrategySpec`` has no Decimal-rules
    field.
    """
    result = evaluate_comparison_eligibility(
        _input(comparison_level=ComparisonLevel.LEVEL_3),
        _input(
            comparison_level=ComparisonLevel.LEVEL_3,
            assumptions=_assumptions(frozenset({material})),
        ),
        ComparisonLevel.LEVEL_3,
    )

    assert result.outcome is ComparisonEligibilityOutcome.INELIGIBLE
    assert result.reasons == (_reason(ASSUMPTION_MISMATCH, material=material),)


def test_a_level_three_pair_agreeing_only_on_hashes_is_never_plain_eligible() -> None:
    """The exact reproducing pair the independent review constructed."""
    result = evaluate_comparison_eligibility(
        _input(comparison_level=ComparisonLevel.LEVEL_3),
        _input(
            comparison_level=ComparisonLevel.LEVEL_3,
            assumptions=_assumptions(frozenset(ComparisonMaterial)),
        ),
        ComparisonLevel.LEVEL_3,
    )

    assert result.outcome is ComparisonEligibilityOutcome.INELIGIBLE
    assert len(result.reasons) == len(LEVEL_1_MATERIALS)
    assert set(_codes(result)) == {ASSUMPTION_MISMATCH}
    assert _achieves_no_level(result)


def test_no_comparison_level_has_an_empty_requirement_set() -> None:
    """The fail-closed property `required_materials` claims, asserted for real."""
    for level in ComparisonLevel:
        assert required_materials(level) != ()


def test_level_three_still_checks_identity_and_never_claims_blind_parity() -> None:
    """Both runs succeeding is not an eligibility argument."""
    result = evaluate_comparison_eligibility(
        _input(comparison_level=ComparisonLevel.LEVEL_3),
        _input(
            comparison_level=ComparisonLevel.LEVEL_3,
            strategy_version_hash=_OTHER_HASH,
            dataset_version_hash=_OTHER_HASH,
        ),
        ComparisonLevel.LEVEL_3,
    )

    assert result.outcome is ComparisonEligibilityOutcome.INELIGIBLE
    assert set(_codes(result)) == {STRATEGY_HASH_MISMATCH, DATASET_HASH_MISMATCH}


def test_a_declared_difference_removes_the_parity_claim() -> None:
    result = evaluate_comparison_eligibility(
        _input(declared_differences=(_difference(),)),
        _input(),
        ComparisonLevel.LEVEL_1,
    )

    assert result.outcome is (
        ComparisonEligibilityOutcome.ELIGIBLE_WITH_DECLARED_DIFFERENCES
    )
    assert result.declared_differences == (_difference(),)
    assert result.achieved_level is ComparisonLevel.LEVEL_1


def test_an_unexplained_difference_can_never_yield_a_plain_eligible() -> None:
    """Plan line 3957: it blocks any claim of parity at the affected level.

    The stronger reading -- that it makes the pair ``INELIGIBLE`` -- is
    unimplementable inside plan section 5.9's closed table: an ineligibility
    reason must carry one of exactly seven ``COMPARISON.`` codes and none denotes
    an unexplained difference, while an eighth needs a reviewed plan correction.
    """
    unexplained = _difference(
        category=DifferenceCategory.UNEXPLAINED_DIFFERENCE,
        detail="Equity diverges by 0.4 percent with no identified cause.",
    )

    result = evaluate_comparison_eligibility(
        _input(declared_differences=(unexplained,)), _input(), ComparisonLevel.LEVEL_1
    )

    assert result.outcome is not ComparisonEligibilityOutcome.ELIGIBLE
    assert result.outcome is (
        ComparisonEligibilityOutcome.ELIGIBLE_WITH_DECLARED_DIFFERENCES
    )
    assert unexplained in result.declared_differences


def test_a_declared_difference_is_never_converted_to_equality() -> None:
    """Both sides' declarations survive; neither erases the other."""
    left_difference = _difference(
        category=DifferenceCategory.FEE_MODELING, detail="Blended fee rate."
    )
    right_difference = _difference(
        category=DifferenceCategory.FEE_MODELING, detail="Exact maker/taker split."
    )

    result = evaluate_comparison_eligibility(
        _input(declared_differences=(left_difference,)),
        _input(declared_differences=(right_difference,)),
        ComparisonLevel.LEVEL_1,
    )

    assert result.declared_differences == (left_difference, right_difference)
    assert len(result.declared_differences) == 2


def test_one_difference_declared_identically_by_both_sides_is_one_difference() -> None:
    """The union is deduplicated, and without this the predicate would raise.

    An independent review found the deduplication in ``_union_differences``
    unguarded: no test declared the *identical* ``(category, detail)`` on both
    sides. Removing the deduplication does not merely duplicate an entry -- the
    result's own ``validate_declared_differences`` then rejects the pair, so a
    ``ValidationError`` escapes the predicate, contradicting the bound claim.
    """
    shared = _difference(DifferenceCategory.FEE_MODELING, "One blended fee rate.")

    result = evaluate_comparison_eligibility(
        _input(declared_differences=(shared,)),
        _input(declared_differences=(shared,)),
        ComparisonLevel.LEVEL_1,
    )

    assert result.declared_differences == (shared,)
    assert result.outcome is (
        ComparisonEligibilityOutcome.ELIGIBLE_WITH_DECLARED_DIFFERENCES
    )


def test_the_result_rejects_a_parity_claim_beside_a_declared_difference() -> None:
    """The invariant is on the type."""
    declared = evaluate_comparison_eligibility(
        _input(declared_differences=(_difference(),)), _input(), ComparisonLevel.LEVEL_1
    )

    with pytest.raises(ValidationError):
        ComparisonEligibilityResult(
            **{
                **declared.model_dump(mode="python"),
                "outcome": ComparisonEligibilityOutcome.ELIGIBLE,
            }
        )

    plain = evaluate_comparison_eligibility(_input(), _input(), ComparisonLevel.LEVEL_1)
    with pytest.raises(ValidationError):
        ComparisonEligibilityResult(
            **{
                **plain.model_dump(mode="python"),
                "outcome": (
                    ComparisonEligibilityOutcome.ELIGIBLE_WITH_DECLARED_DIFFERENCES
                ),
            }
        )


def test_the_result_rejects_an_unexplained_refusal() -> None:
    plain = evaluate_comparison_eligibility(_input(), _input(), ComparisonLevel.LEVEL_1)

    with pytest.raises(ValidationError):
        ComparisonEligibilityResult(
            **{
                **plain.model_dump(mode="python"),
                "outcome": ComparisonEligibilityOutcome.INELIGIBLE,
                "achieved_level": MISSING,
            }
        )


def test_the_result_rejects_an_eligible_outcome_that_still_carries_reasons() -> None:
    """Both halves of the reason invariant, not only the ineligible half."""
    ineligible = evaluate_comparison_eligibility(
        _input(), _input(dataset_version_hash=_OTHER_HASH), ComparisonLevel.LEVEL_1
    )
    body = ineligible.model_dump(mode="python")

    for outcome in (
        ComparisonEligibilityOutcome.ELIGIBLE,
        ComparisonEligibilityOutcome.ELIGIBLE_WITH_DECLARED_DIFFERENCES,
    ):
        with pytest.raises(ValidationError):
            ComparisonEligibilityResult(
                **{
                    **body,
                    "outcome": outcome,
                    "achieved_level": ComparisonLevel.LEVEL_1,
                }
            )


# --------------------------------------------------------------------------
# Plan test item 5 -- approximation exclusions
# --------------------------------------------------------------------------


def test_an_approximation_preventing_the_requested_level_is_ineligible() -> None:
    """Plan test item 5."""
    declaration = _approximation(prevented=(ComparisonLevel.LEVEL_1,))

    result = evaluate_comparison_eligibility(
        _input(approximations=(declaration,)), _input(), ComparisonLevel.LEVEL_1
    )

    assert result.outcome is ComparisonEligibilityOutcome.INELIGIBLE
    assert result.reasons == (
        _reason(APPROXIMATION_EXCLUDES_LEVEL, approximation_id=_APPROXIMATION_ID),
    )
    assert _achieves_no_level(result)


def test_the_exact_approximation_and_affected_level_are_identifiable() -> None:
    """Phase 11's identification requirement, without duplicating a sibling field.

    The affected level is the result's ``requested_level`` by the definition of
    the check, and the exact approximation is resolvable in ``left`` or ``right``
    from the reason's ``approximation_id``.
    """
    declaration = _approximation(prevented=(ComparisonLevel.LEVEL_2,))
    result = evaluate_comparison_eligibility(
        _input(comparison_level=ComparisonLevel.LEVEL_2, approximations=(declaration,)),
        _input(comparison_level=ComparisonLevel.LEVEL_2),
        ComparisonLevel.LEVEL_2,
    )

    (reason,) = result.reasons
    assert reason.approximation_id == _APPROXIMATION_ID
    assert result.requested_level is ComparisonLevel.LEVEL_2
    named = tuple(
        item
        for item in result.left.approximations
        if item.approximation_id == reason.approximation_id
    )
    assert named == (declaration,)


def test_an_approximation_preventing_another_level_is_not_a_reason() -> None:
    """Membership is exact, per plan test item 5's "includes the requested level"."""
    declaration = _approximation(prevented=(ComparisonLevel.LEVEL_2,))

    result = evaluate_comparison_eligibility(
        _input(approximations=(declaration,)), _input(), ComparisonLevel.LEVEL_1
    )

    assert result.outcome is (
        ComparisonEligibilityOutcome.ELIGIBLE_WITH_DECLARED_DIFFERENCES
    )
    assert result.reasons == ()


def test_a_non_preventing_approximation_is_a_declared_difference_not_parity() -> None:
    """Specification 20.4 classifies "Declared approximation" as a difference."""
    result = evaluate_comparison_eligibility(
        _input(approximations=(_approximation(),)), _input(), ComparisonLevel.LEVEL_1
    )

    assert result.outcome is (
        ComparisonEligibilityOutcome.ELIGIBLE_WITH_DECLARED_DIFFERENCES
    )
    assert result.declared_differences == ()
    assert result.left.approximations == (_approximation(),)


@pytest.mark.parametrize("side", ["left", "right"])
def test_an_approximation_on_either_side_alone_is_honoured(side: str) -> None:
    """Both sides, not only ``left``.

    An independent review found that every approximation test placed the
    declaration on ``left``, leaving the ``or right.approximations`` term in both
    the predicate and ``validate_outcome_shape`` unguarded. Dropping either term
    makes a right-side-only approximation raise out of the predicate instead of
    producing an outcome.
    """
    declaration = _approximation()
    inputs = {"left": _input(), "right": _input()}
    inputs[side] = _input(approximations=(declaration,))

    result = evaluate_comparison_eligibility(
        inputs["left"], inputs["right"], ComparisonLevel.LEVEL_1
    )

    assert result.outcome is (
        ComparisonEligibilityOutcome.ELIGIBLE_WITH_DECLARED_DIFFERENCES
    )
    assert result.reasons == ()
    assert getattr(result, side).approximations == (declaration,)


@pytest.mark.parametrize("side", ["left", "right"])
def test_a_preventing_approximation_on_either_side_alone_excludes(side: str) -> None:
    declaration = _approximation(prevented=(ComparisonLevel.LEVEL_1,))
    inputs = {"left": _input(), "right": _input()}
    inputs[side] = _input(approximations=(declaration,))

    result = evaluate_comparison_eligibility(
        inputs["left"], inputs["right"], ComparisonLevel.LEVEL_1
    )

    assert result.outcome is ComparisonEligibilityOutcome.INELIGIBLE
    assert result.reasons == (
        _reason(APPROXIMATION_EXCLUDES_LEVEL, approximation_id=_APPROXIMATION_ID),
    )


def test_every_approximation_field_survives_verbatim() -> None:
    """Phase 11: provenance is preserved, never rewritten.

    ``adapter_version`` in particular is authoring provenance and need not equal
    any other adapter version -- the committed Task 6 correction -- so a
    declaration authored by ``2.0.0`` inside an input whose ``adapter_version`` is
    ``1.0.0`` is carried through unchanged and changes no outcome.
    """
    declaration = _approximation(adapter_version="2.0.0")

    result = evaluate_comparison_eligibility(
        _input(adapter_version="1.0.0", approximations=(declaration,)),
        _input(),
        ComparisonLevel.LEVEL_1,
    )

    (preserved,) = result.left.approximations
    assert preserved == declaration
    assert preserved.approximation_id == _APPROXIMATION_ID
    assert preserved.capability == "execution.partial_fills"
    assert preserved.adapter_version == "2.0.0"
    assert preserved.prevented_comparison_levels == ()
    assert preserved.method == declaration.method
    assert preserved.expected_impact == declaration.expected_impact
    assert result.outcome is (
        ComparisonEligibilityOutcome.ELIGIBLE_WITH_DECLARED_DIFFERENCES
    )


def test_an_authoring_version_difference_never_becomes_an_eligibility_reason() -> None:
    """The Task 6 correction, restated as a Task 7 guard."""
    base = evaluate_comparison_eligibility(
        _input(approximations=(_approximation(adapter_version="1.0.0"),)),
        _input(),
        ComparisonLevel.LEVEL_1,
    )
    bumped = evaluate_comparison_eligibility(
        _input(approximations=(_approximation(adapter_version="9.9.9"),)),
        _input(),
        ComparisonLevel.LEVEL_1,
    )

    assert base.outcome is bumped.outcome
    assert base.reasons == bumped.reasons == ()


def test_both_sides_approximations_are_evaluated() -> None:
    left_declaration = _approximation(
        approximation_id=_APPROXIMATION_ID,
        capability="execution.partial_fills",
        prevented=(ComparisonLevel.LEVEL_1,),
    )
    right_declaration = _approximation(
        approximation_id=_OTHER_APPROXIMATION_ID,
        capability="portfolio.multi_asset",
        prevented=(ComparisonLevel.LEVEL_1,),
    )

    result = evaluate_comparison_eligibility(
        _input(approximations=(left_declaration,)),
        _input(approximations=(right_declaration,)),
        ComparisonLevel.LEVEL_1,
    )

    assert len(result.reasons) == 2
    assert {reason.approximation_id for reason in result.reasons} == {
        _APPROXIMATION_ID,
        _OTHER_APPROXIMATION_ID,
    }


def test_duplicate_equivalent_declarations_yield_one_logical_reason() -> None:
    """The same declaration on both sides is one fact, not two."""
    declaration = _approximation(prevented=(ComparisonLevel.LEVEL_1,))

    result = evaluate_comparison_eligibility(
        _input(approximations=(declaration,)),
        _input(approximations=(declaration,)),
        ComparisonLevel.LEVEL_1,
    )

    assert len(result.reasons) == 1


def test_an_input_rejects_overlapping_capability_declarations() -> None:
    """Specification 13.2 and the Task 6 correction: actual overlap stays invalid."""
    with pytest.raises(ValidationError):
        _input(
            approximations=(
                _approximation(approximation_id=_APPROXIMATION_ID),
                _approximation(approximation_id=_OTHER_APPROXIMATION_ID),
            )
        )


def test_an_input_rejects_two_declarations_sharing_one_identity() -> None:
    """Raised by an independent review; the capability rule does not cover it.

    Two materially different declarations naming different capabilities can still
    share an ``approximation_id``. That would make the ``approximation_id`` on an
    exclusion reason ambiguous, so the reason could no longer name "the exact
    approximation".
    """
    with pytest.raises(ValidationError):
        _input(
            approximations=(
                _approximation(
                    approximation_id=_APPROXIMATION_ID,
                    capability="execution.partial_fills",
                ),
                _approximation(
                    approximation_id=_APPROXIMATION_ID,
                    capability="portfolio.multi_asset",
                ),
            )
        )


def test_permuting_the_approximation_input_yields_byte_identical_output() -> None:
    """Phase 11: input approximation order must not affect canonical output."""
    first = _approximation(
        approximation_id=_APPROXIMATION_ID,
        capability="execution.partial_fills",
        prevented=(ComparisonLevel.LEVEL_1,),
    )
    second = _approximation(
        approximation_id=_OTHER_APPROXIMATION_ID,
        capability="data.ohlcv",
        prevented=(ComparisonLevel.LEVEL_1,),
    )

    forward = evaluate_comparison_eligibility(
        _input(approximations=(first, second)), _input(), ComparisonLevel.LEVEL_1
    )
    reversed_order = evaluate_comparison_eligibility(
        _input(approximations=(second, first)), _input(), ComparisonLevel.LEVEL_1
    )

    assert canonical_json_bytes(forward) == canonical_json_bytes(reversed_order)


# --------------------------------------------------------------------------
# Plan test item 6 -- complete, deduplicated, totally ordered reasons
# --------------------------------------------------------------------------


def test_the_reason_sort_key_is_total_over_material_content() -> None:
    reasons = (
        _reason(LEVEL_UNSUPPORTED),
        _reason(ASSUMPTION_MISMATCH, material=ComparisonMaterial.FEE_ASSUMPTIONS),
        _reason(ASSUMPTION_MISMATCH, material=ComparisonMaterial.UNIVERSE),
        _reason(APPROXIMATION_EXCLUDES_LEVEL, approximation_id=_APPROXIMATION_ID),
        _reason(APPROXIMATION_EXCLUDES_LEVEL, approximation_id=_OTHER_APPROXIMATION_ID),
    )

    keys = tuple(reason_sort_key(reason) for reason in reasons)
    assert len(set(keys)) == len(keys)
    # Two reasons that share a key are byte-identical, so no tie can survive to be
    # broken by arrival order.
    assert reason_sort_key(reasons[0]) == reason_sort_key(_reason(LEVEL_UNSUPPORTED))
    assert canonical_json_bytes(reasons[0]) == canonical_json_bytes(
        _reason(LEVEL_UNSUPPORTED)
    )


def test_removing_the_final_reason_order_component_makes_the_key_collide() -> None:
    """The mutation test Phase 12 requires, run in-process.

    Truncating ``reason_sort_key`` to its first two components is a live mutation
    of the total order; this proves a focused test kills it, because two distinct
    approximation exclusions become indistinguishable.
    """
    first = _reason(APPROXIMATION_EXCLUDES_LEVEL, approximation_id=_APPROXIMATION_ID)
    second = _reason(
        APPROXIMATION_EXCLUDES_LEVEL, approximation_id=_OTHER_APPROXIMATION_ID
    )

    assert reason_sort_key(first) != reason_sort_key(second)
    assert reason_sort_key(first)[:2] == reason_sort_key(second)[:2]
    assert canonical_json_bytes(first) != canonical_json_bytes(second)


def test_removing_the_final_difference_order_component_makes_the_key_collide() -> None:
    """The same proof for the difference key.

    Two sides may classify the same category with different explanations, so a
    ``(category,)`` key would let arrival order decide the union's order.
    """
    first = _difference(DifferenceCategory.FEE_MODELING, "Blended rate.")
    second = _difference(DifferenceCategory.FEE_MODELING, "Maker and taker split.")

    assert difference_sort_key(first) != difference_sort_key(second)
    assert difference_sort_key(first)[:1] == difference_sort_key(second)[:1]


def test_reasons_are_deduplicated_and_totally_ordered() -> None:
    result = evaluate_comparison_eligibility(
        _input(
            comparison_level=ComparisonLevel.LEVEL_2,
            approximations=(_approximation(prevented=(ComparisonLevel.LEVEL_2,)),),
        ),
        _input(
            comparison_level=ComparisonLevel.LEVEL_2,
            strategy_version_hash=_OTHER_HASH,
            approximations=(_approximation(prevented=(ComparisonLevel.LEVEL_2,)),),
            assumptions=_assumptions(
                frozenset(
                    {
                        ComparisonMaterial.UNIVERSE,
                        ComparisonMaterial.FEE_ASSUMPTIONS,
                    }
                )
            ),
        ),
        ComparisonLevel.LEVEL_2,
    )

    keys = tuple(reason_sort_key(reason) for reason in result.reasons)
    assert keys == tuple(sorted(keys))
    assert len(set(keys)) == len(keys)
    assert _codes(result) == (
        APPROXIMATION_EXCLUDES_LEVEL,
        ASSUMPTION_MISMATCH,
        ASSUMPTION_MISMATCH,
        STRATEGY_HASH_MISMATCH,
    )


def test_the_result_rejects_unsorted_or_duplicated_reasons() -> None:
    ineligible = evaluate_comparison_eligibility(
        _input(),
        _input(strategy_version_hash=_OTHER_HASH, dataset_version_hash=_OTHER_HASH),
        ComparisonLevel.LEVEL_1,
    )
    body = ineligible.model_dump(mode="python")

    with pytest.raises(ValidationError):
        ComparisonEligibilityResult(
            **{**body, "reasons": tuple(reversed(ineligible.reasons))}
        )
    with pytest.raises(ValidationError):
        ComparisonEligibilityResult(
            **{**body, "reasons": (ineligible.reasons[0], ineligible.reasons[0])}
        )


def test_the_result_rejects_unsorted_or_duplicated_differences() -> None:
    declared = evaluate_comparison_eligibility(
        _input(
            declared_differences=(
                _difference(DifferenceCategory.INPUT_OR_DATA_ALIGNMENT, "Alignment."),
                _difference(DifferenceCategory.FEE_MODELING, "Fees."),
            )
        ),
        _input(),
        ComparisonLevel.LEVEL_1,
    )
    body = declared.model_dump(mode="python")

    with pytest.raises(ValidationError):
        ComparisonEligibilityResult(
            **{
                **body,
                "declared_differences": tuple(reversed(declared.declared_differences)),
            }
        )
    with pytest.raises(ValidationError):
        ComparisonEligibilityResult(
            **{
                **body,
                "declared_differences": (
                    declared.declared_differences[0],
                    declared.declared_differences[0],
                ),
            }
        )


def test_swapping_the_two_inputs_never_changes_the_eligibility_components() -> None:
    """Stable under left/right construction order where it is semantically so.

    ``left`` and ``right`` themselves swap, because specification 25.3 requires
    side-by-side provenance in the caller's order; the four decision components
    must not.
    """
    left = _input(
        comparison_level=ComparisonLevel.LEVEL_2,
        engine_name="vectorbt",
        approximations=(_approximation(prevented=(ComparisonLevel.LEVEL_2,)),),
        declared_differences=(_difference(DifferenceCategory.FEE_MODELING, "Left."),),
    )
    right = _input(
        comparison_level=ComparisonLevel.LEVEL_2,
        engine_name="freqtrade",
        dataset_version_hash=_OTHER_HASH,
        assumptions=_assumptions(frozenset({ComparisonMaterial.UNIVERSE})),
        declared_differences=(
            _difference(DifferenceCategory.SLIPPAGE_MODELING, "Right."),
        ),
    )

    forward = evaluate_comparison_eligibility(left, right, ComparisonLevel.LEVEL_2)
    backward = evaluate_comparison_eligibility(right, left, ComparisonLevel.LEVEL_2)

    assert _eligibility_components(forward) == _eligibility_components(backward)
    assert forward.left == backward.right
    assert forward.right == backward.left


def test_permuting_the_assumption_and_difference_inputs_changes_nothing() -> None:
    forward_assumptions = _assumptions()
    reversed_assumptions = tuple(reversed(forward_assumptions))
    differences = (
        _difference(DifferenceCategory.INPUT_OR_DATA_ALIGNMENT, "Alignment."),
        _difference(DifferenceCategory.SLIPPAGE_MODELING, "Slippage."),
    )

    forward = evaluate_comparison_eligibility(
        _input(assumptions=forward_assumptions, declared_differences=differences),
        _input(),
        ComparisonLevel.LEVEL_1,
    )
    permuted = evaluate_comparison_eligibility(
        _input(
            assumptions=reversed_assumptions,
            declared_differences=tuple(reversed(differences)),
        ),
        _input(),
        ComparisonLevel.LEVEL_1,
    )

    assert canonical_json_bytes(forward) == canonical_json_bytes(permuted)


def test_identical_inputs_produce_byte_identical_results() -> None:
    first = evaluate_comparison_eligibility(_input(), _input(), ComparisonLevel.LEVEL_1)
    second = evaluate_comparison_eligibility(
        _input(), _input(), ComparisonLevel.LEVEL_1
    )

    assert canonical_json_bytes(first) == canonical_json_bytes(second)


def test_the_public_reason_bound_cannot_be_reached() -> None:
    """The arithmetic behind ``MAX_COMPARISON_REASONS``, asserted rather than told."""
    unscoped = len(COMPARISON_REASON_CODES) - 2
    worst_case = unscoped + len(ComparisonMaterial) + 2 * MAX_COMPARISON_APPROXIMATIONS
    assert unscoped == 5
    assert worst_case == 71
    assert worst_case < MAX_COMPARISON_REASONS
    assert MAX_COMPARISON_ASSUMPTIONS == len(ComparisonMaterial) == 14
    assert MAX_COMPARISON_APPROXIMATIONS == len(CapabilityVocabulary.names) == 26
    assert MAX_INPUT_DECLARED_DIFFERENCES == len(DifferenceCategory) == 14
    assert MAX_RESULT_DECLARED_DIFFERENCES == 28


def test_the_union_of_two_full_difference_sets_fits_the_result_bound() -> None:
    """The only way to reach the result's difference bound, exercised end to end."""
    left_differences = tuple(
        ComparisonDifference(category=category, detail="Left explanation.")
        for category in DifferenceCategory
    )
    right_differences = tuple(
        ComparisonDifference(category=category, detail="Right explanation.")
        for category in DifferenceCategory
    )

    result = evaluate_comparison_eligibility(
        _input(declared_differences=left_differences),
        _input(declared_differences=right_differences),
        ComparisonLevel.LEVEL_1,
    )

    assert len(result.declared_differences) == MAX_RESULT_DECLARED_DIFFERENCES


# --------------------------------------------------------------------------
# Plan test item 7 -- the public surface (preventive)
# --------------------------------------------------------------------------

_FORBIDDEN_SURFACE_FRAGMENTS = (
    "aggregate",
    "average",
    "combine",
    "majority",
    "mean",
    "merge",
    "promote",
    "approve",
    "rank",
    "score",
    "synthetic",
    "vote",
    "winner",
)
_MODULE_SOURCE = Path(comparison_module.__file__ or "").read_text(encoding="utf-8")
_MODULE_TREE = ast.parse(_MODULE_SOURCE)


def _imported_names() -> frozenset[str]:
    names: set[str] = set()
    for node in ast.walk(_MODULE_TREE):
        if isinstance(node, ast.Import | ast.ImportFrom):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".")[0])
    return frozenset(names)


def test_the_exported_surface_is_exactly_the_declared_all() -> None:
    """Exact symbol inspection, not a substring scan.

    Every public name the module binds and does not import must be in ``__all__``,
    so a helper that quietly became public cannot escape the next test.
    """
    imported = _imported_names()
    bound = {
        name
        for name in vars(comparison_module)
        if not name.startswith("_") and name not in imported
    }

    assert bound == set(comparison_module.__all__)
    # Sortedness itself is Ruff's ``RUF022`` job, and its convention groups
    # SCREAMING_CASE before CamelCase rather than using a plain ASCII sort; only
    # uniqueness is asserted here so the two checks cannot disagree.
    assert len(comparison_module.__all__) == len(set(comparison_module.__all__))


def test_no_public_symbol_averages_votes_combines_or_promotes() -> None:
    """Plan test item 7, over the exact exported surface plus every bound name."""
    inspected = set(comparison_module.__all__) | {
        name for name in vars(comparison_module)
    }

    offending = tuple(
        sorted(
            name
            for name in inspected
            for fragment in _FORBIDDEN_SURFACE_FRAGMENTS
            if fragment in name.lower()
        )
    )
    assert offending == ()


def test_no_model_field_carries_a_score_vote_or_average() -> None:
    for model in (
        ComparisonAssumption,
        ComparisonDifference,
        ComparisonInput,
        ComparisonIneligibilityReason,
        ComparisonEligibilityResult,
    ):
        for field in model.model_fields:
            for fragment in _FORBIDDEN_SURFACE_FRAGMENTS:
                assert fragment not in field.lower(), (model.__name__, field)


def test_the_module_defines_no_service_and_no_run_manifest() -> None:
    """Plan section 5.8: both belong to the later stage that owns ``RunManifest``."""
    assert not hasattr(comparison_module, "ComparisonEligibilityService")
    assert not hasattr(comparison_module, "RunManifest")
    defined = {
        node.name
        for node in ast.walk(_MODULE_TREE)
        if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
    }
    assert "ComparisonEligibilityService" not in defined
    assert "RunManifest" not in defined


def test_no_task_seven_model_borrows_a_run_manifest_field() -> None:
    """The falsifiable form of "this is not a ``RunManifest`` substitute".

    Compared against the **literal** nineteen-name section 11.3 row, so the guard
    cannot be satisfied by an omission from the list. Seventeen of the nineteen
    must be absent; the two that may overlap are named and justified above, so
    adding a third would fail here rather than pass unnoticed.
    """
    assert len(_RUN_MANIFEST_ROW_FIELDS) == 19
    assert _SHARED_WITH_RUN_MANIFEST < _RUN_MANIFEST_ROW_FIELDS
    for model in (ComparisonInput, ComparisonEligibilityResult):
        borrowed = _RUN_MANIFEST_ROW_FIELDS & set(model.model_fields)
        assert borrowed <= _SHARED_WITH_RUN_MANIFEST, (
            model.__name__,
            sorted(borrowed - _SHARED_WITH_RUN_MANIFEST),
        )


# --------------------------------------------------------------------------
# Purity (preventive)
# --------------------------------------------------------------------------

_ALLOWED_IMPORT_ROOTS = frozenset(
    {"__future__", "crypto_lab", "enum", "pydantic", "typing"}
)
_FORBIDDEN_CALLS = frozenset(
    {
        "compile",
        "eval",
        "exec",
        "getattr",
        "globals",
        "input",
        "locals",
        "open",
        "setattr",
        "vars",
        "__import__",
    }
)


def test_the_module_imports_only_pure_declarative_roots() -> None:
    roots: set[str] = set()
    for node in ast.walk(_MODULE_TREE):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "relative imports hide the dependency direction"
            roots.add((node.module or "").split(".")[0])

    assert roots <= _ALLOWED_IMPORT_ROOTS, sorted(roots - _ALLOWED_IMPORT_ROOTS)


def test_the_module_calls_nothing_that_could_reach_the_outside_world() -> None:
    called: set[str] = set()
    for node in ast.walk(_MODULE_TREE):
        if isinstance(node, ast.Call):
            target = node.func
            if isinstance(target, ast.Name):
                called.add(target.id)
            elif isinstance(target, ast.Attribute):
                called.add(target.attr)

    assert called & _FORBIDDEN_CALLS == set(), sorted(called & _FORBIDDEN_CALLS)
    assert "now" not in called
    assert "utcnow" not in called
    assert "random" not in called


def test_the_predicate_holds_no_state_and_caches_nothing() -> None:
    first = evaluate_comparison_eligibility(_input(), _input(), ComparisonLevel.LEVEL_1)
    mismatch = evaluate_comparison_eligibility(
        _input(), _input(strategy_version_hash=_OTHER_HASH), ComparisonLevel.LEVEL_1
    )
    again = evaluate_comparison_eligibility(_input(), _input(), ComparisonLevel.LEVEL_1)

    assert canonical_json_bytes(first) == canonical_json_bytes(again)
    assert mismatch.outcome is ComparisonEligibilityOutcome.INELIGIBLE


# --------------------------------------------------------------------------
# Vocabulary closure
# --------------------------------------------------------------------------


def test_the_outcome_vocabulary_is_exactly_the_three_approved_values() -> None:
    assert tuple(ComparisonEligibilityOutcome) == (
        ComparisonEligibilityOutcome.ELIGIBLE,
        ComparisonEligibilityOutcome.INELIGIBLE,
        ComparisonEligibilityOutcome.ELIGIBLE_WITH_DECLARED_DIFFERENCES,
    )
    assert tuple(item.value for item in ComparisonEligibilityOutcome) == (
        "ELIGIBLE",
        "INELIGIBLE",
        "ELIGIBLE_WITH_DECLARED_DIFFERENCES",
    )


def test_the_difference_categories_are_exactly_the_fourteen_of_section_20_4() -> None:
    assert tuple(item.value for item in DifferenceCategory) == (
        "INPUT_OR_DATA_ALIGNMENT",
        "WARM_UP_BEHAVIOR",
        "INDICATOR_IMPLEMENTATION",
        "SIGNAL_TIMING",
        "ORDER_TIMING",
        "FEE_MODELING",
        "SLIPPAGE_MODELING",
        "PRECISION_OR_ROUNDING",
        "PARTIAL_FILL_BEHAVIOR",
        "PORTFOLIO_ACCOUNTING",
        "ENGINE_NATIVE_EXECUTION_SEMANTICS",
        "DECLARED_APPROXIMATION",
        "NORMALIZATION_LIMITATION",
        "UNEXPLAINED_DIFFERENCE",
    )
    assert len(DifferenceCategory) == 14
    assert "OTHER" not in {item.name for item in DifferenceCategory}


def test_the_comparison_reason_codes_are_exactly_the_closed_seven() -> None:
    assert COMPARISON_REASON_CODES == frozenset(
        {
            "COMPARISON.LEVEL_UNSUPPORTED",
            "COMPARISON.STRATEGY_HASH_MISMATCH",
            "COMPARISON.DATASET_HASH_MISMATCH",
            "COMPARISON.ASSUMPTION_MISMATCH",
            "COMPARISON.APPROXIMATION_EXCLUDES_LEVEL",
            "COMPARISON.SCHEMA_VERSION_MISMATCH",
            "COMPARISON.METHODOLOGY_MISMATCH",
        }
    )
    assert all(code.startswith("COMPARISON.") for code in COMPARISON_REASON_CODES)


def test_a_reason_code_outside_the_closed_set_is_rejected() -> None:
    with pytest.raises(ValidationError):
        _reason("COMPARISON.UNEXPLAINED_DIFFERENCE")
    with pytest.raises(ValidationError):
        _reason("CAPABILITY.REQUIREMENT_UNMET")
    with pytest.raises(ValidationError):
        _reason("STRATEGY.DIAGNOSTIC_LIMIT_REACHED")


def test_a_reason_carries_exactly_the_scope_its_code_takes() -> None:
    with pytest.raises(ValidationError):
        _reason(ASSUMPTION_MISMATCH)
    with pytest.raises(ValidationError):
        _reason(
            ASSUMPTION_MISMATCH,
            material=ComparisonMaterial.UNIVERSE,
            approximation_id=_APPROXIMATION_ID,
        )
    with pytest.raises(ValidationError):
        _reason(APPROXIMATION_EXCLUDES_LEVEL)
    with pytest.raises(ValidationError):
        _reason(
            APPROXIMATION_EXCLUDES_LEVEL, material=ComparisonMaterial.FEE_ASSUMPTIONS
        )
    # Both scopes together. An independent review found this case unguarded: the
    # two assertions above are both satisfied by the missing-approximation half of
    # the condition, so the extra-material half survived deletion. The
    # `ASSUMPTION_MISMATCH` branch below already pins its own mirror image.
    with pytest.raises(ValidationError):
        _reason(
            APPROXIMATION_EXCLUDES_LEVEL,
            approximation_id=_APPROXIMATION_ID,
            material=ComparisonMaterial.FEE_ASSUMPTIONS,
        )
    with pytest.raises(ValidationError):
        _reason(LEVEL_UNSUPPORTED, material=ComparisonMaterial.UNIVERSE)
    with pytest.raises(ValidationError):
        _reason(STRATEGY_HASH_MISMATCH, approximation_id=_APPROXIMATION_ID)


def test_an_unknown_level_outcome_or_category_value_fails_closed() -> None:
    with pytest.raises(ValidationError):
        _input(comparison_level="LEVEL_4")
    with pytest.raises(ValidationError):
        ComparisonDifference(
            category=cast(DifferenceCategory, "OTHER"), detail="Anything."
        )
    with pytest.raises(ValidationError):
        ComparisonAssumption(
            material=cast(ComparisonMaterial, "FEES"), value_hash=_ASSUMPTION_HASH
        )


# --------------------------------------------------------------------------
# Field-list acceptance, per plan line 2941
# --------------------------------------------------------------------------

_EXPECTED_ASSUMPTION_FIELDS = ("material", "value_hash")
_EXPECTED_DIFFERENCE_FIELDS = ("category", "detail")
_EXPECTED_INPUT_FIELDS = (
    "schema_version",
    "comparison_level",
    "engine_name",
    "engine_version",
    "adapter_name",
    "adapter_version",
    "canonical_schema_version",
    "methodology_version",
    "strategy_version_hash",
    "dataset_version_hash",
    "assumptions",
    "approximations",
    "declared_differences",
)
_EXPECTED_REASON_FIELDS = ("error_code", "material", "approximation_id")
_EXPECTED_RESULT_FIELDS = (
    "schema_version",
    "outcome",
    "requested_level",
    "achieved_level",
    "left",
    "right",
    "reasons",
    "declared_differences",
)


@pytest.mark.parametrize(
    ("model", "expected"),
    [
        (ComparisonAssumption, _EXPECTED_ASSUMPTION_FIELDS),
        (ComparisonDifference, _EXPECTED_DIFFERENCE_FIELDS),
        (ComparisonInput, _EXPECTED_INPUT_FIELDS),
        (ComparisonIneligibilityReason, _EXPECTED_REASON_FIELDS),
        (ComparisonEligibilityResult, _EXPECTED_RESULT_FIELDS),
    ],
)
def test_every_record_declares_its_derived_field_list_in_order(
    model: type[BaseModel],
    expected: tuple[str, ...],
) -> None:
    """Plan line 2941's field-level acceptance test, per model.

    Field order is pinned as well as membership, because Task 8 generates this
    module's schema and the ``required`` list follows declaration order.
    """
    assert tuple(model.model_fields) == expected


def test_only_the_two_independently_constructed_records_carry_a_schema_version() -> (
    None
):
    """Plan section 3.1 fixes ``schema_version`` on top-level records only."""
    assert "schema_version" in ComparisonInput.model_fields
    assert "schema_version" in ComparisonEligibilityResult.model_fields
    for nested in (
        ComparisonAssumption,
        ComparisonDifference,
        ComparisonIneligibilityReason,
    ):
        assert "schema_version" not in nested.model_fields


# --------------------------------------------------------------------------
# Input validation
# --------------------------------------------------------------------------


def test_the_input_requires_a_complete_assumption_set() -> None:
    """A missing material would skip a required comparison and fail open."""
    complete = _assumptions()
    with pytest.raises(ValidationError):
        _input(assumptions=complete[:-1])
    with pytest.raises(ValidationError):
        _input(assumptions=(*complete, complete[0]))
    with pytest.raises(ValidationError):
        _input(assumptions=(complete[0],) * MAX_COMPARISON_ASSUMPTIONS)
    with pytest.raises(ValidationError):
        _input(assumptions=())
    # A duplicate at the exact bound: the length constraints are satisfied, so the
    # one completeness check is what rejects it.
    with pytest.raises(ValidationError):
        _input(assumptions=(*complete[:-1], complete[0]))


def test_the_input_canonicalizes_assumption_and_difference_order() -> None:
    """Order carries no economic meaning, so it is normalized rather than rejected.

    Sorting rather than rejecting is what makes the permutation property above
    testable instead of defined away, and it follows the Task 6 precedent for a
    producer-supplied input collection.
    """
    canonical = tuple(sorted(_assumptions(), key=lambda item: item.material))
    permuted = _input(assumptions=tuple(reversed(_assumptions())))
    assert permuted.assumptions == canonical
    assert _input().assumptions == canonical

    differences = (
        _difference(DifferenceCategory.SLIPPAGE_MODELING, "Slippage."),
        _difference(DifferenceCategory.FEE_MODELING, "Fees."),
    )
    normalized = _input(declared_differences=differences)
    assert normalized.declared_differences == (differences[1], differences[0])


def test_a_side_declares_at_most_one_difference_per_category() -> None:
    with pytest.raises(ValidationError):
        _input(
            declared_differences=(
                _difference(DifferenceCategory.FEE_MODELING, "One."),
                _difference(DifferenceCategory.FEE_MODELING, "Two."),
            )
        )


def test_the_input_rejects_empty_or_oversized_difference_detail() -> None:
    with pytest.raises(ValidationError):
        ComparisonDifference(category=DifferenceCategory.FEE_MODELING, detail="")
    with pytest.raises(ValidationError):
        ComparisonDifference(
            category=DifferenceCategory.FEE_MODELING, detail="x" * 1025
        )


def test_the_records_reject_a_callable_or_arbitrary_object() -> None:
    """Specification section 11.1: models never accept callables or class paths."""
    with pytest.raises(ValidationError):
        _input(strategy_version_hash=len)
    with pytest.raises(ValidationError):
        ComparisonDifference(
            category=DifferenceCategory.FEE_MODELING, detail=cast(str, object())
        )
    with pytest.raises(ValidationError):
        _input(assumptions=(len,))


def test_the_assumption_accessor_is_total_over_the_material_set() -> None:
    record = _input()
    for material in ComparisonMaterial:
        assert record.assumption_hash(material) == _ASSUMPTION_HASH


# --------------------------------------------------------------------------
# Deep immutability, detachment, and round trips
# --------------------------------------------------------------------------

_IMMUTABLE_LEAVES = (bool, int, str, Decimal, datetime, StrEnum)
_FORBIDDEN_CONTAINERS = (dict, list, set, bytearray)


def _audit_material_graph(value: object, path: str, failures: list[str]) -> None:
    """Walk only the declared public field graph, never Pydantic internals."""
    if value is None or value is MISSING or isinstance(value, _IMMUTABLE_LEAVES):
        return
    if isinstance(value, _FORBIDDEN_CONTAINERS):
        failures.append(f"{path}: mutable {type(value).__name__}")
        return
    if isinstance(value, frozenset):
        for index, item in enumerate(sorted(value, key=repr)):
            _audit_material_graph(item, f"{path}[{index}]", failures)
        return
    if isinstance(value, tuple):
        for index, item in enumerate(value):
            _audit_material_graph(item, f"{path}[{index}]", failures)
        return
    if isinstance(value, BaseModel):
        if not value.model_config.get("frozen", False):
            failures.append(f"{path}: unfrozen model {type(value).__name__}")
        for name in type(value).model_fields:
            _audit_material_graph(
                getattr(value, name, None), f"{path}.{name}", failures
            )
        return
    failures.append(f"{path}: unaudited {type(value).__name__}")


def _every_task7_record() -> tuple[tuple[str, BaseModel], ...]:
    """All five canonical records Task 7 introduces, in both scope states.

    Every one is listed, because plan section 5.5.1's forward obligation covers
    every new canonical record and the parametrized tests below only ever see this
    list -- omitting one would let a mutable field land unnoticed.

    An independent review found two blind spots in the first version: the eligible
    fixture left ``reasons`` empty, so no reason was ever audited *through* the
    result graph, and the one standalone reason had ``approximation_id`` MISSING,
    so that field's present-state was never audited at all. Both scope states and
    an ineligible result are now included, and the approximation carries a
    non-empty ``prevented_comparison_levels``.
    """
    eligible = evaluate_comparison_eligibility(
        _input(
            approximations=(_approximation(),),
            declared_differences=(_difference(),),
        ),
        _input(),
        ComparisonLevel.LEVEL_1,
    )
    ineligible = evaluate_comparison_eligibility(
        _input(
            approximations=(_approximation(prevented=(ComparisonLevel.LEVEL_1,)),),
        ),
        _input(strategy_version_hash=_OTHER_HASH),
        ComparisonLevel.LEVEL_1,
    )
    return (
        ("ComparisonAssumption", eligible.left.assumptions[0]),
        ("ComparisonDifference", eligible.declared_differences[0]),
        ("ComparisonInput", eligible.left),
        ("ComparisonInput:prevented", ineligible.left),
        (
            "ComparisonIneligibilityReason:material",
            _reason(ASSUMPTION_MISMATCH, material=ComparisonMaterial.UNIVERSE),
        ),
        (
            "ComparisonIneligibilityReason:approximation",
            ineligible.reasons[0],
        ),
        ("ComparisonIneligibilityReason:unscoped", _reason(LEVEL_UNSUPPORTED)),
        ("ComparisonEligibilityResult", eligible),
        ("ComparisonEligibilityResult:ineligible", ineligible),
    )


class _MutableProbe(BaseModel):
    """A deliberately non-compliant record, used only to prove the audit bites."""

    model_config = ConfigDict(frozen=False)

    mapping: dict[str, str] = Field(default_factory=dict)
    sequence: list[str] = Field(default_factory=list)
    members: set[str] = Field(default_factory=set)


class _NestedProbe(BaseModel):
    """A frozen outer record wrapping an unfrozen inner one."""

    model_config = ConfigDict(frozen=True)

    nested: _MutableProbe


@pytest.mark.parametrize(
    ("record", "expected_fragment"),
    [
        (_MutableProbe(mapping={"a": "b"}), "mutable dict"),
        (_MutableProbe(sequence=["a"]), "mutable list"),
        (_MutableProbe(members={"a"}), "mutable set"),
        (_NestedProbe(nested=_MutableProbe()), "unfrozen model"),
    ],
)
def test_the_material_graph_audit_detects_what_it_claims_to(
    record: BaseModel,
    expected_fragment: str,
) -> None:
    """A guard that cannot fail is not a guard."""
    failures: list[str] = []
    _audit_material_graph(record, "probe", failures)
    assert any(expected_fragment in failure for failure in failures), failures


def test_the_material_graph_audit_rejects_an_unrecognized_leaf() -> None:
    failures: list[str] = []
    _audit_material_graph(object(), "probe", failures)
    assert failures == ["probe: unaudited object"]


def test_the_material_graph_audit_rejects_a_bytearray() -> None:
    """The fourth forbidden container, which had no negative control.

    It is probed directly rather than through a Pydantic model because Pydantic
    cannot build a core schema for ``bytearray`` without ``arbitrary_types_allowed``
    -- which is itself the reason no canonical record could carry one -- but the
    audit still has to bite if a future value reaches it by another route.
    """
    failures: list[str] = []
    _audit_material_graph(bytearray(b"a"), "probe", failures)
    assert failures == ["probe: mutable bytearray"]

    nested: list[str] = []
    _audit_material_graph((bytearray(b"a"),), "probe", nested)
    assert nested == ["probe[0]: mutable bytearray"]


def test_the_material_graph_audit_accepts_the_permitted_value_kinds() -> None:
    failures: list[str] = []
    _audit_material_graph(
        (True, 1, "text", Decimal("1.5"), datetime(2026, 8, 24, tzinfo=UTC), None),
        "permitted",
        failures,
    )
    _audit_material_graph(frozenset({"a", "b"}), "frozen", failures)
    assert failures == []


@pytest.mark.parametrize(("label", "record"), _every_task7_record())
def test_every_task7_canonical_record_is_deeply_immutable(
    label: str,
    record: BaseModel,
) -> None:
    failures: list[str] = []
    _audit_material_graph(record, label, failures)
    assert failures == []


@pytest.mark.parametrize(("label", "record"), _every_task7_record())
def test_every_task7_record_rejects_attribute_rebinding(
    label: str,
    record: BaseModel,
) -> None:
    name = next(iter(type(record).model_fields))
    with pytest.raises(ValidationError):
        setattr(record, name, "mutated")
    assert getattr(record, name) != "mutated", label


@pytest.mark.parametrize(("label", "record"), _every_task7_record())
def test_every_task7_record_detaches_both_dump_modes(
    label: str,
    record: BaseModel,
) -> None:
    """Every field is re-asserted, not only the first one.

    An independent review showed the earlier form was vacuous for containers: it
    mutated nested lists in the dumps but then only re-read the record's **first**
    field, which is a scalar on all five records. Deleting the nested-mutation loop
    changed nothing. Every declared field is now snapshotted before and compared
    after, so a serializer that returned an aliased internal sequence would fail
    here.
    """
    names = tuple(type(record).model_fields)
    before = {name: getattr(record, name) for name in names}
    python_mode = record.model_dump(mode="python")
    json_mode = record.model_dump(mode="json")
    for dumped in (python_mode, json_mode):
        dumped["injected"] = "mutated"
        for name in names:
            if name in dumped:
                dumped[name] = "mutated"
        for nested in list(dumped.values()):
            if isinstance(nested, list):
                nested.append("mutated")
            elif isinstance(nested, dict):
                nested["injected"] = "mutated"

    for name in names:
        assert getattr(record, name) == before[name], (label, name)
    reference = record.model_dump(mode="python")
    assert "injected" not in reference
    for name in names:
        if name in reference:
            assert reference[name] != "mutated", (label, name)


@pytest.mark.parametrize(("label", "record"), _every_task7_record())
def test_every_task7_record_round_trips_through_both_modes(
    label: str,
    record: BaseModel,
) -> None:
    model = type(record)
    from_python = model.model_validate(record.model_dump(mode="python"))
    from_json = model.model_validate_json(record.model_dump_json())
    assert from_python == record
    assert from_json == record
    assert canonical_json_bytes(from_json) == canonical_json_bytes(record)
    failures: list[str] = []
    _audit_material_graph(from_json, f"{label}:round-trip", failures)
    assert failures == []


def test_a_caller_owned_mutable_sequence_can_never_be_stored() -> None:
    """``strict=True`` closes the aliasing path one step earlier than a copy would."""
    caller_owned = [_difference()]
    with pytest.raises(ValidationError):
        _input(declared_differences=caller_owned)
    with pytest.raises(ValidationError):
        _input(assumptions=list(_assumptions()))
    with pytest.raises(ValidationError):
        _input(approximations=[_approximation()])

    snapshot = _input(declared_differences=tuple(caller_owned))
    caller_owned.append(_difference(DifferenceCategory.ORDER_TIMING, "Injected."))
    assert snapshot.declared_differences == (_difference(),)


# --------------------------------------------------------------------------
# Schema readiness -- Task 8 generates this module's schema, Task 7 does not
# --------------------------------------------------------------------------


def test_the_schema_hook_refuses_a_shape_it_cannot_annotate() -> None:
    """The hook fails loudly rather than publishing a weaker contract."""
    with pytest.raises(TypeError):
        comparison_module._result_schema_extra({"properties": "not-an-object"})
    with pytest.raises(TypeError):
        comparison_module._result_schema_extra({"properties": {"reasons": None}})
    with pytest.raises(TypeError):
        comparison_module._input_schema_extra({"properties": {"assumptions": None}})


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_the_generated_result_schema_keeps_its_shape_and_bounds(
    mode: Literal["validation", "serialization"],
) -> None:
    """Task 7 registers no schema, but the emitted shape is pinned anyway.

    Task 8 generates ``capabilities/comparison-eligibility-result-v1.schema.json``
    from exactly this model, so a widened bound or a lost optionality would land in
    a canonical artifact one task later.

    **Both render modes are pinned.** The registry renders ``serialization`` mode
    while ``TypeAdapter.json_schema()`` defaults to ``validation``, and a
    serializer can silently drop a constraint the validator enforces. An
    independent review pointed out that checking only the default would leave the
    mode that actually ships unguarded.
    """
    schema: dict[str, Any] = TypeAdapter(ComparisonEligibilityResult).json_schema(
        mode=mode
    )
    definitions: dict[str, Any] = schema["$defs"]
    properties: dict[str, Any] = schema["properties"]

    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(_EXPECTED_RESULT_FIELDS) - {"achieved_level"}
    assert properties["reasons"]["maxItems"] == MAX_COMPARISON_REASONS
    assert properties["reasons"]["uniqueItems"] is True
    assert (
        properties["declared_differences"]["maxItems"]
        == MAX_RESULT_DECLARED_DIFFERENCES
    )
    assert properties["declared_differences"]["uniqueItems"] is True

    input_schema = definitions["ComparisonInput"]
    assert input_schema["additionalProperties"] is False
    assert set(input_schema["required"]) == set(_EXPECTED_INPUT_FIELDS)
    assert input_schema["properties"]["assumptions"]["minItems"] == (
        MAX_COMPARISON_ASSUMPTIONS
    )
    assert input_schema["properties"]["assumptions"]["maxItems"] == (
        MAX_COMPARISON_ASSUMPTIONS
    )
    assert input_schema["properties"]["assumptions"]["uniqueItems"] is True
    assert input_schema["properties"]["approximations"]["maxItems"] == (
        MAX_COMPARISON_APPROXIMATIONS
    )
    assert input_schema["properties"]["approximations"]["uniqueItems"] is True
    assert input_schema["properties"]["declared_differences"]["maxItems"] == (
        MAX_INPUT_DECLARED_DIFFERENCES
    )
    # Asserted because it was missing: an independent review showed the
    # `uniqueItems` annotation for this one field could be dropped from
    # `_input_schema_extra` with no test failing, while the two fields either side
    # of it were pinned.
    assert input_schema["properties"]["declared_differences"]["uniqueItems"] is True

    reason_schema = definitions["ComparisonIneligibilityReason"]
    assert reason_schema["required"] == ["error_code"]
    assert reason_schema["additionalProperties"] is False
    for enum_name, members in (
        ("DifferenceCategory", DifferenceCategory),
        ("ComparisonEligibilityOutcome", ComparisonEligibilityOutcome),
        ("ComparisonMaterial", ComparisonMaterial),
        ("ComparisonLevel", ComparisonLevel),
    ):
        assert set(definitions[enum_name]["enum"]) == {item.value for item in members}
