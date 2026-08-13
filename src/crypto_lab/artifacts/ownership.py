"""Strict discriminated artifact ownership values."""

from __future__ import annotations

from typing import Annotated, ClassVar, Literal, cast

from pydantic import (
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    TypeAdapter,
    WithJsonSchema,
    model_validator,
)
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.hashing import HashingProfile, profile_hash
from crypto_lab.domain.identifiers import (
    DatasetId,
    ExperimentId,
    InvocationId,
    NormalizedIdentifier,
    RunId,
    Sha256,
    StrategyVersionId,
    exact_string_schema,
)
from crypto_lab.domain.versioning import SemanticVersion

CorrelationId = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    ),
    WithJsonSchema(
        exact_string_schema(
            r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
            min_length=1,
            max_length=128,
        )
    ),
]


class RunArtifactOwner(CanonicalModel):
    owner_kind: Literal["RUN"]
    experiment_id: ExperimentId
    run_id: RunId
    invocation_id: InvocationId | MISSING = MISSING  # type: ignore[valid-type]


class ExperimentArtifactOwner(CanonicalModel):
    owner_kind: Literal["EXPERIMENT"]
    experiment_id: ExperimentId


class DatasetArtifactOwner(CanonicalModel):
    owner_kind: Literal["DATASET"]
    dataset_id: DatasetId


class StrategyArtifactOwner(CanonicalModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra={
            "oneOf": [
                {
                    "required": ["strategy_version_id"],
                    "not": {"required": ["strategy_version_hash"]},
                },
                {
                    "required": ["strategy_version_hash"],
                    "not": {"required": ["strategy_version_id"]},
                },
            ]
        }
    )

    owner_kind: Literal["STRATEGY"]
    strategy_version_id: StrategyVersionId | MISSING = MISSING  # type: ignore[valid-type]
    strategy_version_hash: Sha256 | MISSING = MISSING  # type: ignore[valid-type]

    @model_validator(mode="after")
    def validate_strategy_identity(self) -> StrategyArtifactOwner:
        if _is_missing(self.strategy_version_id) == _is_missing(
            self.strategy_version_hash
        ):
            raise ValueError("strategy owner requires exactly one version identity")
        return self


class AdapterArtifactOwner(CanonicalModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra={
            "dependentRequired": {
                "engine_name": ["engine_version"],
                "engine_version": ["engine_name"],
            }
        }
    )

    owner_kind: Literal["ADAPTER"]
    adapter_name: NormalizedIdentifier
    adapter_version: SemanticVersion
    engine_name: NormalizedIdentifier | MISSING = MISSING  # type: ignore[valid-type]
    engine_version: SemanticVersion | MISSING = MISSING  # type: ignore[valid-type]

    @model_validator(mode="after")
    def validate_engine_pair(self) -> AdapterArtifactOwner:
        if _is_missing(self.engine_name) != _is_missing(self.engine_version):
            raise ValueError("adapter owner engine name/version must co-occur")
        return self


class SystemArtifactOwner(CanonicalModel):
    owner_kind: Literal["SYSTEM"]
    core_component: NormalizedIdentifier
    correlation_id: CorrelationId


def _is_missing(value: object) -> bool:
    return value is MISSING


type ArtifactOwnerRef = Annotated[
    RunArtifactOwner
    | ExperimentArtifactOwner
    | DatasetArtifactOwner
    | StrategyArtifactOwner
    | AdapterArtifactOwner
    | SystemArtifactOwner,
    Field(discriminator="owner_kind"),
]
ARTIFACT_OWNER_ADAPTER: TypeAdapter[ArtifactOwnerRef] = TypeAdapter(ArtifactOwnerRef)


def owner_presentation(owner: ArtifactOwnerRef) -> dict[str, JsonValue]:
    """Return discriminator-first review presentation, excluding absent fields."""
    raw = cast(dict[str, JsonValue], owner.model_dump(mode="json"))
    kind = raw.pop("owner_kind")
    return {"owner_kind": kind, **raw}


def artifact_owner_hash(owner: ArtifactOwnerRef) -> Sha256:
    """Hash owner presentation through globally sorted canonical JSON."""
    return profile_hash(HashingProfile.ARTIFACT_OWNER_V1, owner_presentation(owner))
