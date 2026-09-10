"""Structural adapter contracts; no engine or process implementation.

Stage 6 Task 1 adds the closed protocol vocabularies, the compiled protocol
limits, the textual candidate-path grammar, the explicit adapter catalog and
the closed Stage 6 diagnostic table. Every module in this package imports
``crypto_lab.domain`` and this package alone (specification 27.1), and none
launches a process, reads the filesystem, the environment or a clock.
"""

from crypto_lab.adapters.catalog import (
    AdapterCatalog,
    AdapterCatalogEntry,
    FrozenAdapterCatalog,
)
from crypto_lab.adapters.descriptors import (
    AdapterDescriptor,
    EngineDescriptor,
    OperatingSystem,
    SupportedSchemaVersion,
)
from crypto_lab.adapters.diagnostics import (
    STAGE6_DIAGNOSTIC_CODES,
    Stage6DiagnosticPosture,
    stage6_diagnostic,
    stage6_failure,
)
from crypto_lab.adapters.limits import (
    PROTOCOL_LIMITS_DEFAULT,
    PROTOCOL_VERSION,
    RESULT_MANIFEST_RELATIVE_PATH,
    ProtocolLimits,
)
from crypto_lab.adapters.paths import (
    RelativeCandidatePath,
    validate_relative_candidate_path,
)
from crypto_lab.adapters.ports import CommandInvocationRepository
from crypto_lab.adapters.versioning import highest_common_stable_version
from crypto_lab.adapters.vocabulary import (
    NEGOTIABLE_SCHEMA_NAMES,
    AdapterDiagnosticCategory,
    NegotiationOutcome,
    ProtocolEventType,
    ProtocolIntegrityStatus,
    ReconciliationVerdict,
    SemanticStatus,
    ValidationOutcome,
)

__all__ = (
    "NEGOTIABLE_SCHEMA_NAMES",
    "PROTOCOL_LIMITS_DEFAULT",
    "PROTOCOL_VERSION",
    "RESULT_MANIFEST_RELATIVE_PATH",
    "STAGE6_DIAGNOSTIC_CODES",
    "AdapterCatalog",
    "AdapterCatalogEntry",
    "AdapterDescriptor",
    "AdapterDiagnosticCategory",
    "CommandInvocationRepository",
    "EngineDescriptor",
    "FrozenAdapterCatalog",
    "NegotiationOutcome",
    "OperatingSystem",
    "ProtocolEventType",
    "ProtocolIntegrityStatus",
    "ProtocolLimits",
    "ReconciliationVerdict",
    "RelativeCandidatePath",
    "SemanticStatus",
    "Stage6DiagnosticPosture",
    "SupportedSchemaVersion",
    "ValidationOutcome",
    "highest_common_stable_version",
    "stage6_diagnostic",
    "stage6_failure",
    "validate_relative_candidate_path",
)
