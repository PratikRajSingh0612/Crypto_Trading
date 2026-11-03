"""The core-generated artifact manifest and its owner-appropriate lineage.

Stage 9 plan section 3.1 (rows ``ArtifactManifest``, ``ArtifactLineage``) under
specification 19.4 and 20.2. The manifest records the finalized reference's
facts -- identity, kind, media type, content-addressed path, independently
calculated size and hash, producer, source candidate, owner, purpose, role,
lineage, validation profile and diagnostics, timestamps -- and is itself
canonical JSON content-hashed under ``ARTIFACT_MANIFEST_V1`` with the
``artifact_manifest_hash`` field omitted (10.2:462: self-hash exclusion by named
profile only). It never copies a staging path into ``finalized_relative_path``;
the field's grammar admits only ``objects/<hh>/<sha256>``.

Lineage presence follows the owner variant (19.4:1421, 20.2:1456), read here as:

- ``RUN`` carries ``experiment_id`` and ``run_id`` equal to the owner's and
  ``invocation_id`` exactly when the owner carries one; an ``ADAPTER`` producer
  additionally requires ``source_adapter_manifest_id`` and may carry
  ``source_event_id``; a ``CORE`` producer carries neither.
- ``EXPERIMENT``, ``DATASET`` and ``STRATEGY`` carry ``source_hash`` -- the
  registry fact the snapshot bytes must equal (plan 4.6:
  ``configuration_audit_hash``, ``content_hash``, ``strategy_version_hash``) --
  and none of the run or adapter fields.
- ``ADAPTER`` and ``SYSTEM`` carry none of them.
- ``superseded_artifact_id`` is permitted for every variant (reading 25: a
  correction is a new reference naming the superseded one) and never names the
  manifest's own ``artifact_id``.
"""

from __future__ import annotations

from typing import Final, Literal, Self, cast

from pydantic import Field, JsonValue, field_validator, model_validator
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.artifacts.models import (
    ArtifactFinalizationPurpose,
    ArtifactOwnerKind,
    ArtifactSourceRole,
    CandidateArtifactProducerKind,
    FinalizedRelativePath,
    MediaType,
    SizeBytes,
    ValidationProfile,
    owner_kind_of,
    validate_role_combination,
)
from crypto_lab.artifacts.ownership import ArtifactOwnerRef, RunArtifactOwner
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.hashing import HashingProfile, artifact_id_for, profile_hash
from crypto_lab.domain.identifiers import (
    AdapterManifestId,
    ArtifactId,
    CandidateArtifactId,
    DiagnosticId,
    EventId,
    ExperimentId,
    InvocationId,
    NormalizedIdentifier,
    RunId,
    Sha256,
)
from crypto_lab.domain.time import CalendarValidUtcDateTime

ARTIFACT_VALIDATION_PROFILE: Final = "artifact-validation/v1"
_SELF_HASH_FIELD: Final = "artifact_manifest_hash"
_RUN_FIELDS: Final[tuple[str, ...]] = ("experiment_id", "run_id", "invocation_id")
_ADAPTER_FIELDS: Final[tuple[str, ...]] = (
    "source_event_id",
    "source_adapter_manifest_id",
)
_SNAPSHOT_OWNERS: Final[frozenset[ArtifactOwnerKind]] = frozenset(
    {
        ArtifactOwnerKind.EXPERIMENT,
        ArtifactOwnerKind.DATASET,
        ArtifactOwnerKind.STRATEGY,
    }
)
_MAX_VALIDATION_DIAGNOSTICS: Final = 64


def _is_missing(value: object) -> bool:
    return value is MISSING


class ArtifactLineage(CanonicalModel):
    """Owner-appropriate source lineage; the presence rules are the manifest's."""

    experiment_id: ExperimentId | MISSING = MISSING  # type: ignore[valid-type]
    run_id: RunId | MISSING = MISSING  # type: ignore[valid-type]
    invocation_id: InvocationId | MISSING = MISSING  # type: ignore[valid-type]
    source_event_id: EventId | MISSING = MISSING  # type: ignore[valid-type]
    source_adapter_manifest_id: AdapterManifestId | MISSING = MISSING  # type: ignore[valid-type]
    source_hash: Sha256 | MISSING = MISSING  # type: ignore[valid-type]
    superseded_artifact_id: ArtifactId | MISSING = MISSING  # type: ignore[valid-type]


class ArtifactManifest(CanonicalModel):
    """19.4: the canonical, content-hashed account of one finalized artifact."""

    schema_version: Literal["1.0.0"]
    artifact_id: ArtifactId
    artifact_kind: NormalizedIdentifier
    media_type: MediaType
    finalized_relative_path: FinalizedRelativePath
    size_bytes: SizeBytes
    content_hash: Sha256
    producer_kind: CandidateArtifactProducerKind
    source_candidate_artifact_id: CandidateArtifactId
    owner: ArtifactOwnerRef
    finalization_purpose: ArtifactFinalizationPurpose
    source_role: ArtifactSourceRole
    lineage: ArtifactLineage
    validation_profile: ValidationProfile
    validation_diagnostic_ids: tuple[DiagnosticId, ...] = Field(
        max_length=_MAX_VALIDATION_DIAGNOSTICS, json_schema_extra={"uniqueItems": True}
    )
    created_at_utc: CalendarValidUtcDateTime
    finalized_at_utc: CalendarValidUtcDateTime
    artifact_manifest_hash: Sha256

    @field_validator("validation_diagnostic_ids")
    @classmethod
    def validate_diagnostic_ids(
        cls, value: tuple[DiagnosticId, ...]
    ) -> tuple[DiagnosticId, ...]:
        if len(set(value)) != len(value):
            raise ValueError("validation_diagnostic_ids must be unique")
        if value != tuple(sorted(value)):
            raise ValueError("validation_diagnostic_ids must be sorted")
        return value

    @model_validator(mode="after")
    def validate_shape(self) -> Self:
        owner_kind = owner_kind_of(self.owner)
        validate_role_combination(
            self.finalization_purpose, self.producer_kind, self.source_role, owner_kind
        )
        self._validate_lineage(owner_kind)
        if self.finalized_relative_path.rsplit("/", 1)[-1] != self.content_hash:
            raise ValueError("finalized_relative_path must address content_hash")
        if self.artifact_id != artifact_id_for(
            self.source_candidate_artifact_id, self.content_hash
        ):
            raise ValueError(
                "artifact_id must equal artifact_id_for(source_candidate_artifact_id, "
                "content_hash)"
            )
        if self.finalized_at_utc < self.created_at_utc:
            raise ValueError("finalized_at_utc must not precede created_at_utc")
        if self.artifact_manifest_hash != artifact_manifest_hash(self):
            raise ValueError(
                "artifact_manifest_hash must equal the recomputed ARTIFACT_MANIFEST_V1 "
                "hash of the manifest with the field omitted"
            )
        return self

    def _validate_lineage(self, owner_kind: ArtifactOwnerKind) -> None:
        lineage = self.lineage
        if isinstance(self.owner, RunArtifactOwner):
            if self.finalization_purpose is ArtifactFinalizationPurpose.RESULT and (
                _is_missing(self.owner.invocation_id)
            ):
                raise ValueError(
                    "a RESULT manifest requires a RUN owner with invocation_id"
                )
            if lineage.experiment_id != self.owner.experiment_id:
                raise ValueError(
                    "lineage.experiment_id must equal the RUN owner's experiment_id"
                )
            if lineage.run_id != self.owner.run_id:
                raise ValueError("lineage.run_id must equal the RUN owner's run_id")
            if lineage.invocation_id != self.owner.invocation_id:
                raise ValueError(
                    "lineage.invocation_id must equal the RUN owner's invocation_id, "
                    "present exactly when the owner carries one"
                )
        elif any(not _is_missing(getattr(lineage, name)) for name in _RUN_FIELDS):
            raise ValueError(
                "a non-RUN owner's lineage carries no experiment_id, run_id or "
                "invocation_id"
            )
        if self.producer_kind is CandidateArtifactProducerKind.ADAPTER:
            if _is_missing(lineage.source_adapter_manifest_id):
                raise ValueError(
                    "an ADAPTER producer's lineage requires source_adapter_manifest_id"
                )
        elif any(not _is_missing(getattr(lineage, name)) for name in _ADAPTER_FIELDS):
            raise ValueError(
                "a CORE producer's lineage carries no source_event_id or "
                "source_adapter_manifest_id"
            )
        if (owner_kind in _SNAPSHOT_OWNERS) != (not _is_missing(lineage.source_hash)):
            raise ValueError(
                "source_hash is carried exactly by an EXPERIMENT, DATASET or STRATEGY "
                "owner's lineage"
            )
        if lineage.superseded_artifact_id == self.artifact_id:
            raise ValueError(
                "superseded_artifact_id must not name the manifest's own artifact"
            )


def artifact_manifest_hash(manifest: ArtifactManifest) -> Sha256:
    """The ``ARTIFACT_MANIFEST_V1`` identity of a manifest over its canonical content
    with only the self-hash omitted (plan 3.1; 10.2:462)."""
    if not isinstance(manifest, ArtifactManifest):
        raise TypeError("manifest must be an ArtifactManifest")
    content = manifest.model_dump(mode="json")
    del content[_SELF_HASH_FIELD]
    return profile_hash(
        HashingProfile.ARTIFACT_MANIFEST_V1, cast("dict[str, JsonValue]", content)
    )


__all__ = (
    "ARTIFACT_VALIDATION_PROFILE",
    "ArtifactLineage",
    "ArtifactManifest",
    "artifact_manifest_hash",
)
