"""Artifact ownership foundation; finalization remains deferred."""

from crypto_lab.artifacts.ownership import (
    ARTIFACT_OWNER_ADAPTER,
    AdapterArtifactOwner,
    ArtifactOwnerRef,
    DatasetArtifactOwner,
    ExperimentArtifactOwner,
    RunArtifactOwner,
    StrategyArtifactOwner,
    SystemArtifactOwner,
    artifact_owner_hash,
    owner_presentation,
)

__all__ = (
    "ARTIFACT_OWNER_ADAPTER",
    "AdapterArtifactOwner",
    "ArtifactOwnerRef",
    "DatasetArtifactOwner",
    "ExperimentArtifactOwner",
    "RunArtifactOwner",
    "StrategyArtifactOwner",
    "SystemArtifactOwner",
    "artifact_owner_hash",
    "owner_presentation",
)
