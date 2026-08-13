"""Pure stable version intersection for later protocol negotiation."""

from __future__ import annotations

from crypto_lab.domain.versioning import SemanticVersion, parse_semantic_version


def highest_common_stable_version(
    core_versions: tuple[SemanticVersion, ...],
    adapter_versions: tuple[SemanticVersion, ...],
) -> SemanticVersion | None:
    """Return the numerically highest exact common stable version."""
    for version in core_versions:
        parse_semantic_version(version)
    for version in adapter_versions:
        parse_semantic_version(version)
    if len(set(core_versions)) != len(core_versions):
        raise ValueError("core versions must be unique")
    if len(set(adapter_versions)) != len(adapter_versions):
        raise ValueError("adapter versions must be unique")
    common = set(core_versions).intersection(adapter_versions)
    if not common:
        return None
    return max(common, key=parse_semantic_version)
