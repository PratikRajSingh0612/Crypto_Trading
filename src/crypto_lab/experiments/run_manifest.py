"""The core run manifest and the normalized result provenance (Stage 9 plan 3.1,
3.2 and Task 7; specification 11.3:578, 11.5:606-607, 19.4:1425, 20.2, 23.3.1:1712,
29.3:2182; readings 11 and 17).

``RunManifest`` is the authoritative consolidated success record the core
generates once -- and only -- for a run whose terminal state is ``SUCCEEDED`` or
``SUCCEEDED_WITH_WARNINGS`` (11.5:607): the ``RESULT`` registrar of
``experiments/finalization.py`` builds it inside the registration transaction
after the moved files were validated, and the Task 5 triggers refuse a success
state without its row (reading 11). It carries ``attempt_token_hash`` and
``sanitized_adapter_result_manifest_hash`` in the place of the raw token and
the original candidate (19.4:1425), the captured ``process_exit_category`` of the
durably ``EXITED`` run-command invocation (11.5:606, never reconstructed), the
reconciled adapter ``RunProvenance`` and only matching ``RUN``-owned ``RESULT``
references of its experiment, run and run-command invocation (11.3:578): a
candidate payload, an ``EVIDENCE`` reference, a non-``RUN`` owner and a
mismatched run are each refused by schema. Its metrics are ``MetricValue``
records read from one of those references, its diagnostics the recorded
identities, and its warnings co-occur with the warning status. The manifest
identity is derived (``run_manifest_id_for``) and the self-hash recomputes over
the canonical content with that one field omitted, by the named profile
(10.2:466).

``NormalizedResultProvenance`` is the contract of specification 20.2 for a
normalized result record or partition -- the twelve required items, every one
present -- with no producer in Project 1 (plan 1.6 item 6; the converter plan
owns the producer). The module imports ``adapters``, ``artifacts`` and ``domain``
only, as plan 2.3 places it: the provenance, warning and reference types it
composes belong to those packages and ``artifacts`` may not import ``adapters``.
"""

from __future__ import annotations

from typing import ClassVar, Literal, Self, cast

from pydantic import ConfigDict, Field, JsonValue, field_validator, model_validator
from pydantic.json_schema import JsonSchemaValue

from crypto_lab.adapters.events import ProtocolWarning
from crypto_lab.adapters.limits import (
    MAX_APPROXIMATIONS,
    MAX_CANDIDATE_ARTIFACTS,
    MAX_CANDIDATE_METRICS,
    MAX_WARNINGS,
)
from crypto_lab.adapters.manifests import RunProvenance
from crypto_lab.artifacts.models import (
    RESULT_ROLES,
    ArtifactFinalizationPurpose,
    ArtifactRef,
    ValidationProfile,
)
from crypto_lab.artifacts.ownership import RunArtifactOwner
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.command_invocation import MAX_DIAGNOSTIC_IDS
from crypto_lab.domain.experiment import AdapterIdentity, EngineIdentity
from crypto_lab.domain.hashing import HashingProfile, profile_hash, run_manifest_id_for
from crypto_lab.domain.identifiers import (
    ApproximationId,
    ArtifactId,
    DiagnosticId,
    ExperimentId,
    InvocationId,
    NormalizedIdentifier,
    RunId,
    RunManifestId,
    Sha256,
)
from crypto_lab.domain.lifecycle import ProcessExitCategory
from crypto_lab.domain.metrics import MetricValue
from crypto_lab.domain.retry import MAX_ATTEMPTS_PER_SLOT
from crypto_lab.domain.time import CalendarValidUtcDateTime
from crypto_lab.domain.versioning import SemanticVersion

#: 11.5:607: the two states a core run manifest exists for.
type RunManifestSemanticStatus = Literal["SUCCEEDED", "SUCCEEDED_WITH_WARNINGS"]
_SELF_HASH_FIELD = "run_manifest_hash"
_WARNING_STATUS = "SUCCEEDED_WITH_WARNINGS"


def _unique_sorted_identifiers(value: tuple[str, ...], label: str) -> tuple[str, ...]:
    if len(set(value)) != len(value):
        raise ValueError(f"{label} must be unique")
    if value != tuple(sorted(value)):
        raise ValueError(f"{label} must be sorted")
    return value


def _run_manifest_schema_extra(schema: JsonSchemaValue) -> None:
    """The warnings/status coupling, published in both directions (plan 3.2)."""
    schema["allOf"] = [
        {
            "if": {
                "properties": {"semantic_status": {"const": "SUCCEEDED"}},
                "required": ["semantic_status"],
            },
            "then": {"properties": {"warnings": {"maxItems": 0}}},
        },
        {
            "if": {
                "properties": {"semantic_status": {"const": _WARNING_STATUS}},
                "required": ["semantic_status"],
            },
            "then": {"properties": {"warnings": {"minItems": 1}}},
        },
    ]


class NormalizedResultProvenance(CanonicalModel):
    """Specification 20.2: the provenance every normalized result record retains.

    The twelve required items, each present: the experiment and its immutable
    spec hash; the run, attempt, token hash and producing invocation; the engine
    and adapter identities; the converter name and version; the source artifact
    identity and SHA-256; the canonical schema and protocol versions; the
    strategy and dataset version hashes; the sorted approximation identifiers;
    the normalization instant and the validation profile. No producer exists in
    Project 1; the record is the contract a later converter satisfies.
    """

    schema_version: Literal["1.0.0"]
    experiment_id: ExperimentId
    experiment_spec_hash: Sha256
    run_id: RunId
    attempt_number: int = Field(ge=1, le=MAX_ATTEMPTS_PER_SLOT)
    attempt_token_hash: Sha256
    invocation_id: InvocationId
    engine: EngineIdentity
    adapter: AdapterIdentity
    converter_name: NormalizedIdentifier
    converter_version: SemanticVersion
    source_artifact_id: ArtifactId
    source_artifact_hash: Sha256
    canonical_schema_version: SemanticVersion
    protocol_version: Literal["1.0.0"]
    strategy_version_hash: Sha256
    dataset_version_hash: Sha256
    approximations: tuple[ApproximationId, ...] = Field(
        max_length=MAX_APPROXIMATIONS, json_schema_extra={"uniqueItems": True}
    )
    normalized_at_utc: CalendarValidUtcDateTime
    validation_profile: ValidationProfile

    @field_validator("approximations")
    @classmethod
    def validate_approximations(
        cls, value: tuple[ApproximationId, ...]
    ) -> tuple[ApproximationId, ...]:
        return _unique_sorted_identifiers(value, "approximation identifiers")


class RunManifest(CanonicalModel):
    """Specification 11.3: the core-generated consolidated success record.

    Built only by the core for a ``SUCCEEDED`` or ``SUCCEEDED_WITH_WARNINGS``
    run: every artifact reference is ``RUN``-owned, purpose ``RESULT`` with a
    result role, and names this manifest's experiment, run and run-command
    invocation; ``EVIDENCE`` references, candidates, other owners and other runs
    are refused. The manifest carries the attempt token hash and the sanitized
    adapter result manifest hash, never the raw token or the original candidate;
    the process exit category is the captured category of the ``EXITED``
    run-command invocation; the metrics are read from one of the references;
    warnings are present exactly for the warning status; the identity derives
    from the run and its invocation and the self-hash recomputes over the
    manifest with that one field omitted.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_run_manifest_schema_extra
    )

    schema_version: Literal["1.0.0"]
    protocol_version: Literal["1.0.0"]
    manifest_id: RunManifestId
    experiment_id: ExperimentId
    run_id: RunId
    run_invocation_id: InvocationId
    attempt_token_hash: Sha256
    sanitized_adapter_result_manifest_hash: Sha256
    semantic_status: RunManifestSemanticStatus
    process_exit_category: ProcessExitCategory
    started_at_utc: CalendarValidUtcDateTime
    completed_at_utc: CalendarValidUtcDateTime
    provenance: RunProvenance
    artifact_refs: tuple[ArtifactRef, ...] = Field(
        min_length=1,
        max_length=MAX_CANDIDATE_ARTIFACTS,
        json_schema_extra={"uniqueItems": True},
    )
    metrics: tuple[MetricValue, ...] = Field(
        max_length=MAX_CANDIDATE_METRICS, json_schema_extra={"uniqueItems": True}
    )
    diagnostics: tuple[DiagnosticId, ...] = Field(
        max_length=MAX_DIAGNOSTIC_IDS, json_schema_extra={"uniqueItems": True}
    )
    warnings: tuple[ProtocolWarning, ...] = Field(max_length=MAX_WARNINGS)
    approximations: tuple[ApproximationId, ...] = Field(
        max_length=MAX_APPROXIMATIONS, json_schema_extra={"uniqueItems": True}
    )
    run_manifest_hash: Sha256

    @field_validator("artifact_refs")
    @classmethod
    def validate_artifact_refs(
        cls, value: tuple[ArtifactRef, ...]
    ) -> tuple[ArtifactRef, ...]:
        _unique_sorted_identifiers(
            tuple(ref.artifact_id for ref in value), "artifact_refs identities"
        )
        return value

    @field_validator("metrics")
    @classmethod
    def validate_metrics(
        cls, value: tuple[MetricValue, ...]
    ) -> tuple[MetricValue, ...]:
        names = [metric.metric_name for metric in value]
        if len(set(names)) != len(names):
            raise ValueError("metrics must be unique on metric_name")
        return value

    @field_validator("diagnostics")
    @classmethod
    def validate_diagnostics(
        cls, value: tuple[DiagnosticId, ...]
    ) -> tuple[DiagnosticId, ...]:
        return _unique_sorted_identifiers(value, "diagnostic identifiers")

    @field_validator("approximations")
    @classmethod
    def validate_approximations(
        cls, value: tuple[ApproximationId, ...]
    ) -> tuple[ApproximationId, ...]:
        return _unique_sorted_identifiers(value, "approximation identifiers")

    @model_validator(mode="after")
    def validate_shape(self) -> Self:
        self._validate_references()
        identities = {ref.artifact_id for ref in self.artifact_refs}
        for metric in self.metrics:
            if metric.source_artifact_id not in identities:
                raise ValueError(
                    "a metric's source_artifact_id must name one of the manifest's "
                    "artifact references"
                )
        if self.manifest_id != run_manifest_id_for(self.run_id, self.run_invocation_id):
            raise ValueError(
                "manifest_id must equal run_manifest_id_for(run_id, run_invocation_id)"
            )
        if self.completed_at_utc < self.started_at_utc:
            raise ValueError("completed_at_utc must not precede started_at_utc")
        if (self.semantic_status == _WARNING_STATUS) is not bool(self.warnings):
            raise ValueError(
                "warnings are present exactly when semantic_status is "
                "SUCCEEDED_WITH_WARNINGS"
            )
        if self.run_manifest_hash != run_manifest_hash(self):
            raise ValueError(
                "run_manifest_hash must equal the recomputed hash of the manifest "
                "with the field omitted"
            )
        return self

    def _validate_references(self) -> None:
        for ref in self.artifact_refs:
            owner = ref.owner
            if not isinstance(owner, RunArtifactOwner):
                raise ValueError("every artifact reference is RUN-owned")
            if ref.finalization_purpose is not ArtifactFinalizationPurpose.RESULT:
                raise ValueError(
                    "every artifact reference has purpose RESULT; an EVIDENCE "
                    "reference never contributes to a run manifest"
                )
            if ref.source_role not in RESULT_ROLES:
                raise ValueError("every artifact reference carries a result role")
            if owner.experiment_id != self.experiment_id:
                raise ValueError(
                    "an artifact reference's owner experiment_id must equal the "
                    "manifest's"
                )
            if owner.run_id != self.run_id:
                raise ValueError(
                    "an artifact reference's owner run_id must equal the manifest's"
                )
            if owner.invocation_id != self.run_invocation_id:
                raise ValueError(
                    "an artifact reference's owner invocation_id must equal the "
                    "manifest's run_invocation_id"
                )


def run_manifest_hash(manifest: RunManifest) -> Sha256:
    """The identity of a run manifest over its canonical content with only the
    self-hash omitted (plan 3.2, specification 10.2:466)."""
    if not isinstance(manifest, RunManifest):
        raise TypeError("manifest must be a RunManifest")
    content = manifest.model_dump(mode="json")
    del content[_SELF_HASH_FIELD]
    return profile_hash(
        HashingProfile.RUN_MANIFEST_V1, cast("dict[str, JsonValue]", content)
    )


__all__ = (
    "NormalizedResultProvenance",
    "RunManifest",
    "RunManifestSemanticStatus",
    "run_manifest_hash",
)
