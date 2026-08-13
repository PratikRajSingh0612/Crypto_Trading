"""Structural adapter contracts; no engine or process implementation."""

from crypto_lab.adapters.descriptors import (
    AdapterDescriptor,
    EngineDescriptor,
    OperatingSystem,
    SupportedSchemaVersion,
)
from crypto_lab.adapters.versioning import highest_common_stable_version

__all__ = (
    "AdapterDescriptor",
    "EngineDescriptor",
    "OperatingSystem",
    "SupportedSchemaVersion",
    "highest_common_stable_version",
)
