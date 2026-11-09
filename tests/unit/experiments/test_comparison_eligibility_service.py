"""Stage 9 Task 7: ``ComparisonEligibilityService`` over two core run manifests
(plan 2.3, 3.2 and Task 7; specification 8.2:357, 25.4; Stage 4 plan 1831-1846,
O-16).

The service adapts each ``RunManifest`` into the Stage 4 ``ComparisonInput`` and
delegates to the pure predicate ``evaluate_comparison_eligibility``: it averages
no metric, mutates no run and reads no artifact reference. The declared readings
of the adaptation (the material digests, the methodology collapse and the
approximation classification) are pinned here.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from crypto_lab.artifacts.models import CandidateArtifactState
from crypto_lab.artifacts.ownership import RunArtifactOwner
from crypto_lab.capabilities.comparison import (
    ASSUMPTION_MISMATCH,
    LEVEL_1_MATERIALS,
    LEVEL_UNSUPPORTED,
    METHODOLOGY_MISMATCH,
    STRATEGY_HASH_MISMATCH,
    ComparisonEligibilityOutcome,
    ComparisonInput,
    ComparisonMaterial,
    DifferenceCategory,
)
from crypto_lab.domain.comparison_levels import ComparisonLevel
from crypto_lab.domain.hashing import run_manifest_id_for
from crypto_lab.experiments.comparison import (
    MATERIAL_SOURCES,
    UNDEFINED_METHODOLOGY_VERSION,
    ComparisonEligibilityService,
    comparison_input_for,
)
from crypto_lab.experiments.run_manifest import RunManifest
from doubles.artifacts import (
    THIRD_CANDIDATE_ID,
    sample_candidate,
    sample_metric,
    sample_ref,
)
from doubles.experiments import (
    DATASET_HASH,
    EXPERIMENT_ID,
    OTHER_INVOCATION_ID,
    OTHER_RUN_ID,
    STRATEGY_HASH,
    UUID_C,
)
from persistence_support.artifacts import (
    RUNNING_EXPERIMENT,
    sample_run_manifest,
    sample_run_provenance,
)

_APPROXIMATION = f"appx_{UUID_C}"


def _other_run_manifest(**overrides: object) -> RunManifest:
    """A manifest of the slot's other run: another run, another invocation, its
    own reference, the same immutable experiment inputs."""
    owner = RunArtifactOwner(
        owner_kind="RUN",
        experiment_id=EXPERIMENT_ID,
        run_id=OTHER_RUN_ID,
        invocation_id=OTHER_INVOCATION_ID,
    )
    ref = sample_ref(
        sample_candidate(
            state=CandidateArtifactState.FINALIZING,
            candidate_artifact_id=THIRD_CANDIDATE_ID,
            owner=owner,
        )
    )
    return sample_run_manifest(
        refs=(ref,),
        manifest_id=run_manifest_id_for(OTHER_RUN_ID, OTHER_INVOCATION_ID),
        run_id=OTHER_RUN_ID,
        run_invocation_id=OTHER_INVOCATION_ID,
        **overrides,
    )


def test_two_manifests_adapt_to_comparison_inputs() -> None:
    left = sample_run_manifest()
    right = _other_run_manifest()
    adapted = comparison_input_for(left)
    assert isinstance(adapted, ComparisonInput)
    assert adapted.comparison_level is ComparisonLevel.LEVEL_2
    assert (adapted.engine_name, adapted.engine_version) == ("engine.alpha", "2.3.4")
    assert (adapted.adapter_name, adapted.adapter_version) == ("adapter.alpha", "1.0.0")
    assert adapted.canonical_schema_version == left.schema_version
    assert adapted.methodology_version == "1.0.0"
    assert adapted.strategy_version_hash == STRATEGY_HASH
    assert adapted.dataset_version_hash == DATASET_HASH
    assert adapted.approximations == ()
    assert adapted.declared_differences == ()
    # The declared reading: one digest per material from the immutable input that
    # owns it -- the strategy for the Level 1 materials, the dataset for the
    # partition hashes and the experiment's material configuration for the rest.
    assert set(MATERIAL_SOURCES) == set(ComparisonMaterial)
    assert len(adapted.assumptions) == len(ComparisonMaterial)
    configuration_hash = RUNNING_EXPERIMENT.spec.configuration_hash
    for material in ComparisonMaterial:
        expected = (
            STRATEGY_HASH
            if material in LEVEL_1_MATERIALS
            else DATASET_HASH
            if material is ComparisonMaterial.DATASET_PARTITION_HASHES
            else configuration_hash
        )
        assert adapted.assumption_hash(material) == expected, material
    service = ComparisonEligibilityService()
    result = service.evaluate(left, right, ComparisonLevel.LEVEL_2)
    assert result.outcome is ComparisonEligibilityOutcome.ELIGIBLE
    assert result.achieved_level is ComparisonLevel.LEVEL_2
    assert result.reasons == ()
    assert (result.left, result.right) == (adapted, comparison_input_for(right))
    # Symmetric eligibility; the sides keep the caller's order.
    swapped = service.evaluate(right, left, ComparisonLevel.LEVEL_2)
    assert (swapped.outcome, swapped.achieved_level, swapped.reasons) == (
        result.outcome,
        result.achieved_level,
        result.reasons,
    )
    assert swapped.left == result.right


def test_requested_level_above_provenance_refused() -> None:
    left = sample_run_manifest()
    right = _other_run_manifest()
    service = ComparisonEligibilityService()
    refused = service.evaluate(left, right, ComparisonLevel.LEVEL_3)
    assert refused.outcome is ComparisonEligibilityOutcome.INELIGIBLE
    assert not isinstance(refused.achieved_level, ComparisonLevel)
    assert {reason.error_code for reason in refused.reasons} == {LEVEL_UNSUPPORTED}
    # A different strategy hash is a hash mismatch and an assumption mismatch on
    # every Level 1 material it digests; the dataset materials still agree.
    foreign = _other_run_manifest(
        provenance=sample_run_provenance(strategy_version_hash="9" * 64)
    )
    mismatched = service.evaluate(left, foreign, ComparisonLevel.LEVEL_2)
    assert mismatched.outcome is ComparisonEligibilityOutcome.INELIGIBLE
    codes = [reason.error_code for reason in mismatched.reasons]
    assert codes.count(STRATEGY_HASH_MISMATCH) == 1
    assert codes.count(ASSUMPTION_MISMATCH) == len(LEVEL_1_MATERIALS)
    assert {
        reason.material
        for reason in mismatched.reasons
        if reason.error_code == ASSUMPTION_MISMATCH
    } == set(LEVEL_1_MATERIALS)
    # The methodology collapse: a run whose metrics agree carries that version, a
    # run without metrics the undefined version, and the two never compare equal.
    bare = _other_run_manifest(metrics=())
    assert (
        comparison_input_for(bare).methodology_version == UNDEFINED_METHODOLOGY_VERSION
    )
    methodology = service.evaluate(left, bare, ComparisonLevel.LEVEL_2)
    assert {reason.error_code for reason in methodology.reasons} == {
        METHODOLOGY_MISMATCH
    }
    first, second = left.artifact_refs
    disagreeing = sample_run_manifest(
        metrics=(
            sample_metric(source_artifact_id=first.artifact_id),
            sample_metric(
                metric_name="max-drawdown",
                methodology_version="2.0.0",
                source_artifact_id=second.artifact_id,
            ),
        )
    )
    with pytest.raises(ValueError, match="methodology_version"):
        comparison_input_for(disagreeing)


def test_evidence_refs_ignored() -> None:
    """A ``RunManifest`` admits no ``EVIDENCE`` reference, so the service reads
    none; the adaptation carries no reference at all and two manifests differing
    only in their result references compare identically."""
    two_refs = sample_run_manifest()
    one_ref = sample_run_manifest(refs=two_refs.artifact_refs[:1])
    assert comparison_input_for(two_refs) == comparison_input_for(one_ref)
    assert not {"artifact_refs", "evidence_refs", "metrics"} & set(
        ComparisonInput.model_fields
    )
    service = ComparisonEligibilityService()
    right = _other_run_manifest()
    full = service.evaluate(two_refs, right, ComparisonLevel.LEVEL_2)
    thin = service.evaluate(one_ref, right, ComparisonLevel.LEVEL_2)
    assert (
        full.outcome,
        full.achieved_level,
        full.reasons,
        full.declared_differences,
    ) == (
        thin.outcome,
        thin.achieved_level,
        thin.reasons,
        thin.declared_differences,
    )
    # A manifest with a declared approximation is eligible with declared
    # differences, never plainly eligible (20.4 "Declared approximation").
    approximated = _other_run_manifest(approximations=(_APPROXIMATION,))
    adapted = comparison_input_for(approximated)
    assert adapted.approximations == ()
    (difference,) = adapted.declared_differences
    assert difference.category is DifferenceCategory.DECLARED_APPROXIMATION
    declared = service.evaluate(two_refs, approximated, ComparisonLevel.LEVEL_2)
    assert declared.outcome is (
        ComparisonEligibilityOutcome.ELIGIBLE_WITH_DECLARED_DIFFERENCES
    )
    assert declared.declared_differences == (difference,)
    assert declared.left == comparison_input_for(two_refs)
    assert declared.right == adapted


def test_adaptation_is_typed_at_both_ends() -> None:
    """The service adapts core run manifests and nothing else: an already
    adapted input, a manifest's provenance in a manifest's place and a level
    given as its text are each refused with ``TypeError`` before the predicate
    runs, so no eligibility answer is minted over a foreign input."""
    left = sample_run_manifest()
    right = _other_run_manifest()
    service = ComparisonEligibilityService()
    adapted = comparison_input_for(left)
    with pytest.raises(TypeError, match="RunManifest"):
        comparison_input_for(cast("Any", adapted))
    with pytest.raises(TypeError, match="RunManifest"):
        service.evaluate(cast("Any", left.provenance), right, ComparisonLevel.LEVEL_2)
    with pytest.raises(TypeError, match="RunManifest"):
        service.evaluate(left, cast("Any", adapted), ComparisonLevel.LEVEL_2)
    with pytest.raises(TypeError, match="ComparisonLevel"):
        service.evaluate(left, right, cast("Any", "LEVEL_2"))
