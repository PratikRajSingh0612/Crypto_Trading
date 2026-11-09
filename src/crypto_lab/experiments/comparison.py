"""``ComparisonEligibilityService``: eligibility over two core run manifests
(Stage 9 plan 2.3, 3.2 and Task 7; specification 8.2:357, 25.4; Stage 4 plan
1831-1846, carried note O-16).

Specification 8.2 types the service's inputs as two ``RunManifest`` records; the
Stage 4 predicate ``evaluate_comparison_eligibility`` is pure over two
already-validated ``ComparisonInput`` records. This module is the adaptation
between them and nothing more: it averages no metric, mutates no run, reads no
artifact reference (a run manifest admits no ``EVIDENCE`` reference, and the
result references carry no comparison material) and returns the predicate's
structured result unchanged.

Declared readings of the adaptation, recorded for review:

- **Material digests.** ``ComparisonInput`` requires one canonical digest per
  ``ComparisonMaterial``. A run manifest carries the immutable inputs that own
  those materials rather than per-material digests, so each material's digest is
  the hash of the input that owns it: the five specification 25.1 materials
  (warm-up boundaries, feature semantics, parameter values, universe, Decimal
  rules) are strategy facts and take ``strategy_version_hash``; the dataset
  partition hashes take ``dataset_version_hash``; the eight remaining 25.2
  materials (bar convention, initial balance, fees, slippage, timing, sizing,
  precision and fill convention) are the experiment's material configuration
  and take ``configuration_hash``. Two runs of one experiment therefore agree on
  every material, and a run of another experiment differs on exactly the
  materials its differing input owns.
- **Methodology collapse.** The Stage 4 module escalated the run-level
  ``methodology_version`` to the stage that owns ``RunManifest.metrics``. The
  rule is: the version every metric of the manifest shares; a manifest without
  metrics carries ``UNDEFINED_METHODOLOGY_VERSION`` (``0.0.0``, which no metric
  can carry, so a run with metrics never compares equal to one without); a
  manifest whose metrics disagree has no run-level methodology and is refused
  with ``ValueError`` -- the caller decides, the service invents no collapse.
- **Approximations.** A manifest declares approximation identifiers, not the
  ``ApproximationDeclaration`` records the predicate scopes exclusions by, so
  the input carries no approximation record and one ``DECLARED_APPROXIMATION``
  difference when the manifest declares any (20.4 classifies a declared
  approximation as a difference); such a pair is eligible with declared
  differences, never plainly eligible.
- The canonical schema version is the manifest's ``schema_version``; the engine
  and adapter identities, the strategy and dataset hashes and the comparison
  level are the manifest's reconciled provenance.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from crypto_lab.capabilities.comparison import (
    LEVEL_1_MATERIALS,
    ComparisonAssumption,
    ComparisonDifference,
    ComparisonEligibilityResult,
    ComparisonInput,
    ComparisonMaterial,
    DifferenceCategory,
    evaluate_comparison_eligibility,
)
from crypto_lab.domain.comparison_levels import ComparisonLevel
from crypto_lab.experiments.run_manifest import RunManifest

#: The run-level methodology version of a manifest without metrics.
UNDEFINED_METHODOLOGY_VERSION: Final = "0.0.0"
#: The provenance attribute whose hash digests each comparison material.
MATERIAL_SOURCES: Final[Mapping[ComparisonMaterial, str]] = {
    **{material: "strategy_version_hash" for material in LEVEL_1_MATERIALS},
    ComparisonMaterial.DATASET_PARTITION_HASHES: "dataset_version_hash",
    **{
        material: "configuration_hash"
        for material in ComparisonMaterial
        if material not in LEVEL_1_MATERIALS
        and material is not ComparisonMaterial.DATASET_PARTITION_HASHES
    },
}


def _methodology_version(manifest: RunManifest) -> str:
    versions = {metric.methodology_version for metric in manifest.metrics}
    if not versions:
        return UNDEFINED_METHODOLOGY_VERSION
    if len(versions) != 1:
        raise ValueError(
            "the manifest's metrics disagree on methodology_version; the run-level "
            "methodology is defined only when every metric shares one"
        )
    return versions.pop()


def comparison_input_for(manifest: RunManifest) -> ComparisonInput:
    """Adapt one core run manifest into the Stage 4 comparison input."""
    if not isinstance(manifest, RunManifest):
        raise TypeError("manifest must be a RunManifest")
    provenance = manifest.provenance
    assumptions = tuple(
        ComparisonAssumption(
            material=material,
            value_hash=getattr(provenance, MATERIAL_SOURCES[material]),
        )
        for material in ComparisonMaterial
    )
    differences: tuple[ComparisonDifference, ...] = ()
    if manifest.approximations:
        differences = (
            ComparisonDifference(
                category=DifferenceCategory.DECLARED_APPROXIMATION,
                detail=(
                    f"the run manifest declares {len(manifest.approximations)} "
                    "approximation identifier(s)"
                ),
            ),
        )
    return ComparisonInput(
        schema_version="1.0.0",
        comparison_level=provenance.comparison_level,
        engine_name=provenance.engine.engine_name,
        engine_version=provenance.engine.engine_version,
        adapter_name=provenance.adapter.adapter_name,
        adapter_version=provenance.adapter.adapter_version,
        canonical_schema_version=manifest.schema_version,
        methodology_version=_methodology_version(manifest),
        strategy_version_hash=provenance.strategy_version_hash,
        dataset_version_hash=provenance.dataset_version_hash,
        assumptions=assumptions,
        approximations=(),
        declared_differences=differences,
    )


class ComparisonEligibilityService:
    """Specification 8.2: ``evaluate(left, right, requested_level)`` over two core
    run manifests, delegating to the pure Stage 4 predicate."""

    __slots__ = ()

    def evaluate(
        self,
        left: RunManifest,
        right: RunManifest,
        requested_level: ComparisonLevel,
    ) -> ComparisonEligibilityResult:
        """One structured eligibility decision; the sides keep the caller's order."""
        if not isinstance(requested_level, ComparisonLevel):
            raise TypeError("requested_level must be a ComparisonLevel")
        return evaluate_comparison_eligibility(
            comparison_input_for(left), comparison_input_for(right), requested_level
        )


__all__ = (
    "MATERIAL_SOURCES",
    "UNDEFINED_METHODOLOGY_VERSION",
    "ComparisonEligibilityService",
    "comparison_input_for",
)
