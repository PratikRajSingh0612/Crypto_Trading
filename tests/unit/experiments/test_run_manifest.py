"""Stage 9 Task 7: the core ``RunManifest`` and ``NormalizedResultProvenance``
contracts of ``experiments/run_manifest.py`` (plan 3.1, 3.2 and 2.5 reading 17;
requirement rows R10.2-03, R10.2-06, R11.3-08, R11.5-07, R11.5-08, R19.1-17,
R19.4-01..03, R20.2-01, T28.1-01, T28.1-06, A33.6-03, A33.6-08).

The manifest is the only record that commits a success state in the project
(plan 4.4, reading 11), so its validators are the gate: every reference is
``RUN``-owned ``RESULT`` of this experiment, run and run-command invocation, a
candidate payload or an ``EVIDENCE`` reference never inhabits it, the self-hash
and the derived identity recompute by their named profiles, the warning status
and the warnings co-occur, and the raw token has no field.
"""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from typing import Any, cast

import pytest
from pydantic import ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.adapters.events import ProtocolWarning
from crypto_lab.artifacts.models import (
    ArtifactFinalizationPurpose,
    CandidateArtifactProducerKind,
    CandidateArtifactState,
)
from crypto_lab.artifacts.ownership import RunArtifactOwner
from crypto_lab.domain.comparison_levels import ComparisonLevel
from crypto_lab.domain.hashing import HashingProfile, profile_hash, run_manifest_id_for
from crypto_lab.domain.lifecycle import CommandInvocationState, ProcessExitCategory
from crypto_lab.domain.metrics import MetricValue
from crypto_lab.experiments.run_manifest import (
    NormalizedResultProvenance,
    RunManifest,
    run_manifest_hash,
)
from doubles.artifacts import (
    CANDIDATE_ID,
    THIRD_CANDIDATE_ID,
    sample_candidate,
    sample_metric,
    sample_ref,
)
from doubles.experiments import (
    ATTEMPT_TOKEN,
    EXPERIMENT_ID,
    INSTANT,
    INVOCATION_ID,
    OTHER_EXPERIMENT_ID,
    OTHER_INVOCATION_ID,
    OTHER_RUN_ID,
    RUN_ID,
    sample_invocation,
)
from persistence_support.artifacts import (
    sample_normalized_provenance,
    sample_run_manifest,
)

_S = CandidateArtifactState
_P = CandidateArtifactProducerKind
_F = ArtifactFinalizationPurpose
_WARNING = ProtocolWarning(
    warning_code="ADAPTER.APPROXIMATED_FILLS",
    message="fills approximated at bar close",
    impact="Level 3 comparison prevented.",
    prevented_comparison_levels=(ComparisonLevel.LEVEL_3,),
)


def _owner(
    *,
    experiment_id: str = EXPERIMENT_ID,
    run_id: str = RUN_ID,
    invocation_id: str = INVOCATION_ID,
) -> RunArtifactOwner:
    return RunArtifactOwner(
        owner_kind="RUN",
        experiment_id=experiment_id,
        run_id=run_id,
        invocation_id=invocation_id,
    )


def _result_ref_for(owner: RunArtifactOwner) -> Any:
    return sample_ref(
        sample_candidate(
            state=_S.FINALIZING, candidate_artifact_id=THIRD_CANDIDATE_ID, owner=owner
        )
    )


# --------------------------------------------------------------------------
# R11.3-08, R19.1-17, A33.6-03: only matching RUN-owned RESULT references
# --------------------------------------------------------------------------


def test_only_matching_run_result_refs() -> None:
    manifest = sample_run_manifest()
    identities = tuple(ref.artifact_id for ref in manifest.artifact_refs)
    assert identities == tuple(sorted(identities))
    assert len(identities) == 2
    for ref in manifest.artifact_refs:
        assert ref.finalization_purpose is _F.RESULT
        assert isinstance(ref.owner, RunArtifactOwner)
        assert (ref.owner.experiment_id, ref.owner.run_id) == (EXPERIMENT_ID, RUN_ID)
    # A candidate payload never inhabits the reference tuple (plan 3.1).
    with pytest.raises(ValidationError):
        sample_run_manifest(refs=cast("Any", (sample_candidate(state=_S.FINALIZING),)))
    # An EVIDENCE reference of the same run is refused.
    evidence = sample_ref(
        sample_candidate(
            "RUN",
            _F.EVIDENCE,
            producer=_P.CORE,
            state=_S.FINALIZING,
            candidate_artifact_id=THIRD_CANDIDATE_ID,
        )
    )
    with pytest.raises(ValidationError, match="RESULT"):
        sample_run_manifest(refs=(*manifest.artifact_refs, evidence))
    # A non-RUN owner is refused.
    dataset = sample_ref(
        sample_candidate(
            "DATASET",
            _F.EVIDENCE,
            producer=_P.CORE,
            state=_S.FINALIZING,
            candidate_artifact_id=THIRD_CANDIDATE_ID,
        )
    )
    with pytest.raises(ValidationError, match="RUN"):
        sample_run_manifest(refs=(*manifest.artifact_refs, dataset))
    # Another run, another experiment and another invocation are each refused.
    with pytest.raises(ValidationError, match="run_id"):
        sample_run_manifest(refs=(_result_ref_for(_owner(run_id=OTHER_RUN_ID)),))
    with pytest.raises(ValidationError, match="experiment_id"):
        sample_run_manifest(
            refs=(_result_ref_for(_owner(experiment_id=OTHER_EXPERIMENT_ID)),)
        )
    with pytest.raises(ValidationError, match="invocation_id"):
        sample_run_manifest(
            refs=(_result_ref_for(_owner(invocation_id=OTHER_INVOCATION_ID)),)
        )
    # At least one reference, each once, in artifact_id order.
    with pytest.raises(ValidationError):
        sample_run_manifest(refs=())
    first = manifest.artifact_refs[0]
    with pytest.raises(ValidationError, match="unique"):
        sample_run_manifest(refs=(first, first))
    with pytest.raises(ValidationError, match="sorted"):
        sample_run_manifest(artifact_refs=tuple(reversed(manifest.artifact_refs)))


# --------------------------------------------------------------------------
# R11.5-07, R11.5-08: the captured exit category of the EXITED invocation
# --------------------------------------------------------------------------


def test_exit_category_from_exited_invocation() -> None:
    invocation = sample_invocation(CommandInvocationState.EXITED)
    category = invocation.process_exit_category
    assert isinstance(category, ProcessExitCategory)
    manifest = sample_run_manifest(process_exit_category=category)
    assert manifest.process_exit_category is ProcessExitCategory.SUCCESS
    # The category is a captured known category, never omitted (11.5:606).
    with pytest.raises(ValidationError, match="process_exit_category"):
        sample_run_manifest(process_exit_category=MISSING)
    # The reconstructed label is not a member: the payload is a valid manifest's
    # serialized record with that one field replaced, submitted to validation
    # directly (never serialized as a draft).
    unknown = manifest.model_dump(mode="python")
    unknown["process_exit_category"] = "UNKNOWN_AFTER_RESTART"
    with pytest.raises(ValidationError, match="process_exit_category"):
        RunManifest.model_validate(unknown)
    assert "process_exit_category" in RunManifest.model_fields
    assert RunManifest.model_fields["process_exit_category"].is_required()


# --------------------------------------------------------------------------
# R10.2-03, R10.2-06, T28.1-01: the self-hash and the derived identity
# --------------------------------------------------------------------------


def test_self_hash_omitted_by_named_profile() -> None:
    manifest = sample_run_manifest()
    content = manifest.model_dump(mode="json")
    del content["run_manifest_hash"]
    assert manifest.run_manifest_hash == profile_hash(
        HashingProfile.RUN_MANIFEST_V1, content
    )
    assert run_manifest_hash(manifest) == manifest.run_manifest_hash
    assert HashingProfile.RUN_MANIFEST_V1.value == "run-manifest/v1"
    assert HashingProfile.RUN_MANIFEST_IDENTITY_V1.value == "run-manifest-identity/v1"
    with pytest.raises(ValidationError, match="run_manifest_hash"):
        sample_run_manifest(run_manifest_hash="f" * 64)
    # The identity derives from the run and its run-command invocation.
    assert manifest.manifest_id == run_manifest_id_for(RUN_ID, INVOCATION_ID)
    with pytest.raises(ValidationError, match="manifest_id"):
        sample_run_manifest(
            manifest_id=run_manifest_id_for(RUN_ID, OTHER_INVOCATION_ID)
        )
    with pytest.raises(TypeError, match="RunManifest"):
        run_manifest_hash(sample_normalized_provenance())  # type: ignore[arg-type]
    # A dumped manifest round-trips through strict validation unchanged.
    assert RunManifest.model_validate(manifest.model_dump(mode="python")) == manifest


# --------------------------------------------------------------------------
# R20.2-01, R19.4-01..03: the twelve required provenance items
# --------------------------------------------------------------------------


def test_provenance_fields_retained() -> None:
    provenance = sample_normalized_provenance()
    assert provenance.converter_name == "core.converter"
    assert provenance.source_artifact_hash == "a" * 64
    assert provenance.validation_profile == "artifact-validation/v1"
    for name in NormalizedResultProvenance.model_fields:
        assert NormalizedResultProvenance.model_fields[name].is_required(), name
        with pytest.raises(ValidationError, match=name):
            sample_normalized_provenance(**{name: MISSING})
    with pytest.raises(ValidationError):
        sample_normalized_provenance(attempt_token=ATTEMPT_TOKEN)
    with pytest.raises(ValidationError):
        sample_normalized_provenance(attempt_number=1.0)
    with pytest.raises(ValidationError, match="sorted"):
        sample_normalized_provenance(
            approximations=(
                "appx_9f8e7d6c-5b4a-4321-8fed-cba987654321",
                "appx_12345678-1234-4234-8234-123456789abc",
            )
        )
    with pytest.raises(ValidationError, match="unique"):
        sample_normalized_provenance(
            approximations=(
                "appx_12345678-1234-4234-8234-123456789abc",
                "appx_12345678-1234-4234-8234-123456789abc",
            )
        )
    assert "attempt_token" not in NormalizedResultProvenance.model_fields
    assert "attempt_token" not in RunManifest.model_fields
    with pytest.raises(ValidationError):
        sample_run_manifest(attempt_token=ATTEMPT_TOKEN)


# --------------------------------------------------------------------------
# R11.3-08: SUCCEEDED_WITH_WARNINGS carries warnings, SUCCEEDED none
# --------------------------------------------------------------------------


def test_warnings_iff_warning_status() -> None:
    warned = sample_run_manifest(
        semantic_status="SUCCEEDED_WITH_WARNINGS", warnings=(_WARNING,)
    )
    assert warned.warnings == (_WARNING,)
    with pytest.raises(ValidationError, match="warnings"):
        sample_run_manifest(semantic_status="SUCCEEDED", warnings=(_WARNING,))
    with pytest.raises(ValidationError, match="warnings"):
        sample_run_manifest(semantic_status="SUCCEEDED_WITH_WARNINGS", warnings=())
    for status in ("FAILED", "CANCELLED", "TIMED_OUT", "NOT_APPLICABLE", "UNAVAILABLE"):
        with pytest.raises(ValidationError, match="semantic_status"):
            sample_run_manifest(semantic_status=status)
    with pytest.raises(ValidationError, match="completed_at_utc"):
        sample_run_manifest(completed_at_utc=INSTANT - timedelta(seconds=1))


# --------------------------------------------------------------------------
# T28.1-06, A33.6-08: metrics are MetricValue records read from a result ref
# --------------------------------------------------------------------------


def test_metrics_are_metric_values_with_source_refs() -> None:
    manifest = sample_run_manifest()
    (metric,) = manifest.metrics
    assert isinstance(metric, MetricValue)
    assert metric.source_artifact_id in {
        ref.artifact_id for ref in manifest.artifact_refs
    }
    assert metric.value == Decimal("0.125")
    stranger = sample_metric(source_artifact_id=f"art_{THIRD_CANDIDATE_ID[5:]}")
    with pytest.raises(ValidationError, match="source_artifact_id"):
        sample_run_manifest(metrics=(stranger,))
    with pytest.raises(ValidationError, match="unique"):
        sample_run_manifest(metrics=(metric, metric))
    # A CandidateMetric payload (the adapter's wire shape) is not a MetricValue:
    # a valid manifest's serialized record with the metric replaced by the wire
    # shape is refused at the field, submitted to validation directly.
    wire = manifest.model_dump(mode="python")
    wire["metrics"] = (
        {
            "metric_name": "total-return",
            "value": "0.125",
            "value_status": "DEFINED",
            "unit": "ratio",
            "methodology_version": "1.0.0",
            "comparison_level": "LEVEL_2",
        },
    )
    with pytest.raises(ValidationError, match="metrics"):
        RunManifest.model_validate(wire)
    empty = sample_run_manifest(metrics=())
    assert empty.metrics == ()
    # Diagnostics are sorted unique identifiers.
    diagnostics = (
        f"diag_{CANDIDATE_ID[5:]}",
        f"diag_{THIRD_CANDIDATE_ID[5:]}",
    )
    assert diagnostics != tuple(sorted(diagnostics))
    with pytest.raises(ValidationError, match="sorted"):
        sample_run_manifest(diagnostics=diagnostics)
    with pytest.raises(ValidationError, match="unique"):
        sample_run_manifest(diagnostics=(diagnostics[0], diagnostics[0]))
    ordered = sample_run_manifest(diagnostics=tuple(sorted(diagnostics)))
    assert ordered.diagnostics == tuple(sorted(diagnostics))


# --------------------------------------------------------------------------
# The invalid inputs of this module: valid serialized records with one field
# replaced, submitted to validation directly (no draft is ever serialized)
# --------------------------------------------------------------------------


def test_serialized_record_mutations_are_refused_at_their_field() -> None:
    """Both records round-trip through JSON unchanged, and a valid manifest's
    serialized record with one field replaced is refused at that field -- a
    foreign metric source, unsorted references, a non-success status, the raw
    token under any name and a stale self-hash -- so every negative of this
    module is a validation answer, never a serializer's guess about a draft."""
    manifest = sample_run_manifest()
    assert RunManifest.model_validate_json(manifest.model_dump_json()) == manifest
    provenance = sample_normalized_provenance()
    assert (
        NormalizedResultProvenance.model_validate_json(provenance.model_dump_json())
        == provenance
    )
    payload = manifest.model_dump(mode="python")
    assert RunManifest.model_validate(payload) == manifest
    foreign = dict(payload)
    foreign["metrics"] = (
        {
            **payload["metrics"][0],
            "source_artifact_id": f"art_{THIRD_CANDIDATE_ID[5:]}",
        },
    )
    with pytest.raises(ValidationError, match="source_artifact_id"):
        RunManifest.model_validate(foreign)
    unsorted = dict(payload)
    unsorted["artifact_refs"] = tuple(reversed(payload["artifact_refs"]))
    with pytest.raises(ValidationError, match="sorted"):
        RunManifest.model_validate(unsorted)
    failed = dict(payload)
    failed["semantic_status"] = "FAILED"
    with pytest.raises(ValidationError, match="semantic_status"):
        RunManifest.model_validate(failed)
    tokened = dict(payload)
    tokened["attempt_token"] = ATTEMPT_TOKEN
    with pytest.raises(ValidationError, match="attempt_token"):
        RunManifest.model_validate(tokened)
    stale = dict(payload)
    stale["run_manifest_hash"] = "f" * 64
    with pytest.raises(ValidationError, match="run_manifest_hash"):
        RunManifest.model_validate(stale)
