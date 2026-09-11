"""Structural adapter contracts; no engine or process implementation.

Stage 6 Task 1 adds the closed protocol vocabularies, the compiled protocol
limits, the textual candidate-path grammar, the explicit adapter catalog and
the closed Stage 6 diagnostic table; Task 2 adds the command-discriminated
request envelopes, the request material and its identity, and the adapter
command contract; Task 3 adds the bootstrap descriptor envelope, the core
protocol support, pure version negotiation, the describe output parse and the
availability-observation projection; Task 4 adds the protocol events, the
sanitized run event and its content identity, the staged line parser, the
invocation event ledger and the raw-token sanitization helpers. Every module in
this package imports ``crypto_lab.domain`` and this package alone (specification
27.1), and none launches a process, reads the filesystem, the environment or an
ambient clock.
"""

from crypto_lab.adapters.catalog import (
    AdapterCatalog,
    AdapterCatalogEntry,
    FrozenAdapterCatalog,
)
from crypto_lab.adapters.commands import AdapterCommand, argument_array
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
from crypto_lab.adapters.envelopes import (
    AdapterCommandRequestEnvelope,
    DescribeRequestPayload,
    EngineRunRequest,
    NegotiatedVersions,
    RunConfigurationSnapshot,
    SanitizedEngineRunRequest,
    WorkDirectoryReference,
    build_engine_run_request,
    build_request_envelope,
    payload_hash_of,
    request_envelope_bytes,
    request_hash_of,
    request_material_hash,
    sanitize_engine_run_request,
)
from crypto_lab.adapters.events import (
    AdapterDiagnostic,
    ArtifactDeclarationRecord,
    ArtifactProducedPayload,
    DiagnosticPayload,
    EventAcceptanceContext,
    EventAccepted,
    EventRejected,
    EventReplayed,
    FinalResultPayload,
    HeartbeatPayload,
    InvocationEventLedger,
    LineOutcome,
    MediaType,
    ProgressPayload,
    ProtocolEventEnvelope,
    ProtocolEventSummary,
    ProtocolWarning,
    ResourceObservation,
    RunEvent,
    WarningPayload,
    frame_protocol_lines,
    parse_protocol_line,
    run_event_content_hash,
)
from crypto_lab.adapters.limits import (
    PROTOCOL_LIMITS_DEFAULT,
    PROTOCOL_VERSION,
    RESULT_MANIFEST_RELATIVE_PATH,
    ProtocolLimits,
)
from crypto_lab.adapters.negotiation import (
    CORE_PROTOCOL_SUPPORT,
    BootstrapDescriptorEnvelope,
    CoreProtocolSupport,
    DescriptorHeader,
    DescriptorParse,
    NegotiationResult,
    describe_availability_observation,
    negotiate_protocol,
    negotiated_versions_of,
    parse_bootstrap_descriptor,
)
from crypto_lab.adapters.paths import (
    RelativeCandidatePath,
    validate_relative_candidate_path,
)
from crypto_lab.adapters.ports import CommandInvocationRepository
from crypto_lab.adapters.sanitization import (
    REDACTION_PLACEHOLDER,
    BoundedStderrCapture,
    ContaminationSample,
    StderrCapture,
    contamination_sample,
    redact_attempt_token,
    redact_payload,
    token_present,
)
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
    "CORE_PROTOCOL_SUPPORT",
    "NEGOTIABLE_SCHEMA_NAMES",
    "PROTOCOL_LIMITS_DEFAULT",
    "PROTOCOL_VERSION",
    "REDACTION_PLACEHOLDER",
    "RESULT_MANIFEST_RELATIVE_PATH",
    "STAGE6_DIAGNOSTIC_CODES",
    "AdapterCatalog",
    "AdapterCatalogEntry",
    "AdapterCommand",
    "AdapterCommandRequestEnvelope",
    "AdapterDescriptor",
    "AdapterDiagnostic",
    "AdapterDiagnosticCategory",
    "ArtifactDeclarationRecord",
    "ArtifactProducedPayload",
    "BootstrapDescriptorEnvelope",
    "BoundedStderrCapture",
    "CommandInvocationRepository",
    "ContaminationSample",
    "CoreProtocolSupport",
    "DescribeRequestPayload",
    "DescriptorHeader",
    "DescriptorParse",
    "DiagnosticPayload",
    "EngineDescriptor",
    "EngineRunRequest",
    "EventAcceptanceContext",
    "EventAccepted",
    "EventRejected",
    "EventReplayed",
    "FinalResultPayload",
    "FrozenAdapterCatalog",
    "HeartbeatPayload",
    "InvocationEventLedger",
    "LineOutcome",
    "MediaType",
    "NegotiatedVersions",
    "NegotiationOutcome",
    "NegotiationResult",
    "OperatingSystem",
    "ProgressPayload",
    "ProtocolEventEnvelope",
    "ProtocolEventSummary",
    "ProtocolEventType",
    "ProtocolIntegrityStatus",
    "ProtocolLimits",
    "ProtocolWarning",
    "ReconciliationVerdict",
    "RelativeCandidatePath",
    "ResourceObservation",
    "RunConfigurationSnapshot",
    "RunEvent",
    "SanitizedEngineRunRequest",
    "SemanticStatus",
    "Stage6DiagnosticPosture",
    "StderrCapture",
    "SupportedSchemaVersion",
    "ValidationOutcome",
    "WarningPayload",
    "WorkDirectoryReference",
    "argument_array",
    "build_engine_run_request",
    "build_request_envelope",
    "contamination_sample",
    "describe_availability_observation",
    "frame_protocol_lines",
    "highest_common_stable_version",
    "negotiate_protocol",
    "negotiated_versions_of",
    "parse_bootstrap_descriptor",
    "parse_protocol_line",
    "payload_hash_of",
    "redact_attempt_token",
    "redact_payload",
    "request_envelope_bytes",
    "request_hash_of",
    "request_material_hash",
    "run_event_content_hash",
    "sanitize_engine_run_request",
    "stage6_diagnostic",
    "stage6_failure",
    "token_present",
    "validate_relative_candidate_path",
)
