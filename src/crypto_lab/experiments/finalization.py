"""The application integration of artifact finalization (Stage 9 plan 4.4, 4.6
and Task 7; specification 14.5, 14.7, 15.6, 19.2 step 9, 19.3, 19.4, 21.3, 23.3.1,
29.3, 30.2-30.3; readings 5, 7, 11, 14, 16, 17, 23, 24).

This module is the one place that may import both ``crypto_lab.artifacts`` and
``crypto_lab.audit`` abstractions beside the adapter and experiment records
(plan 2.3, 27.1): it composes the Task 6 ``CoreArtifactFinalizer`` with the
purpose-specific registration that needs adapter and experiment types. It
imports neither ``persistence`` nor ``process_supervision``: the caller (Task
8's flow, later the Stage 10 composition) destructures ``SupervisionOutcome``
and ``CommandPaths`` into the ``CommandResult``, the parses, the summary and the
domain-typed ``CommandRootPaths`` consumed here.

The RESULT branch (plan 4.4), in the caller's order:

0. ``observe_candidates`` -- run by the caller before the Stage 6 verdict: every
   declared path confined (``confine_candidate_path``) before it is opened, then
   stream-hashed and scanned for the raw token through the store's
   identity-checked handle bridge, so ``reconcile_run`` decides leakage and the
   declared size and hash agreement from these observations. A refusal here is
   handed to ``fail_run_for_refusal``.
1. ``conclude_command`` records every minted diagnostic of the outcome.
2. It registers the ``RUN`` owner and one ``CANDIDATE`` row per accepted
   ``ARTIFACT_PRODUCED`` declaration (``register_result_candidates`` -- the
   production step that makes ``artifact_produced`` create only a candidate,
   O-14) and stages the core evidence that exists after any outcome: the
   sanitized stderr, the protocol capture regenerated from the accepted events,
   the sanitized adapter result manifest with its row, the sanitized validation
   result with its row.
3. For a ``RESULT_FINALIZATION_ELIGIBLE`` verdict on a ``RUNNING`` run it builds
   the ``ResultFinalizationRequest`` from the parse, the sanitized manifest and
   the invocation and awaits the finalizer. An ``ARTIFACT.*`` or ``SECURITY.*``
   refusal fails the run through ``fail_run_for_refusal``; so does a
   ``CORE.INVARIANT_VIOLATION`` under which the finalizer abandoned the RESULT
   journal for good (21.2.1: the invariant fails the affected run, and the
   caller owns that write -- at the run's durable post-lease revision, fenced
   by the same state and revision check), while a pre-lease invariant leaves
   no journal and is returned unchanged; a ``PERSISTENCE.CONCURRENCY_CONFLICT``
   is returned to the driver; any other refusal is returned unchanged.
4. On success the registrar has committed the run's success: the conclusion
   carries the ``FinalizationResult``, the ``RunManifest`` and the references.
5. The staged evidence is finalized under the ``INVOCATION`` correlation after
   every outcome (an evidence refusal never changes the conclusion: 29.1); a
   terminal run that took no RESULT lease has its token-bearing root closed
   through ``close_raw_bytes``.

``ResultRegistrar`` is the production ``PurposeRegistrar``: inside the open T3
it reads the sanitized manifest (the row written at step 2, or the manifest the
recovery validator remembered), builds the ``ArtifactManifest`` of every
reference, stages and records the references, builds and inserts the
``RunManifest`` and its row, links the manifest members, swaps the run
``RUNNING -> SUCCEEDED*`` at the journal's stored ``expected_run_revision`` --
the post-snapshot revision the finalizer recorded, compared directly -- and
appends the ``RUN_MANIFEST_REGISTERED`` and ``RUN_SUCCEEDED`` facts.
``EvidenceRegistrar`` records the ``RUN_EVIDENCE`` links of ``RUN`` owners, the
write-once ``stderr_artifact_id`` enrichment, the sanitized-manifest and
validation-result evidence links and the ``STDERR_EVIDENCE_LINKED`` fact; it
never reads or writes ``engine_runs``.

Under the canonical evidence ruling of 2026-11-09 (``docs/decisions/2026-11-09-
stage9-canonical-evidence-validation-clarification.md``) both registrars also
answer the plan 4.1 ``CanonicalEvidenceQualifier`` -- the producer side of the
plan 4.6 contract the finalizer's phase 1 consults for a ``CORE`` ``EVIDENCE``
candidate. A kind qualifies only when every part agrees: the candidate's role,
owner kind, correlation kind and fixed staging leaf are the producer's; every
record parses from its bytes as exactly the producer's model and re-serializes
to those very bytes (so no alternate escaping and no stray field survives); and
the records agree with the authoritative facts -- the stored text of the
``sanitized_adapter_result_manifests`` or ``adapter_validation_results`` row, the
ledger's events in sequence order, the recorded diagnostics, the ``DESCRIBE``
invocation of an adapter owner, the invocation of a run owner. A media type, a
kind label, the ``CORE`` flag or a valid parse alone never qualifies. Content
that is not the model answers no contract (the validation's whole-content
protection stands); content that is the model but disagrees with the facts is
``ARTIFACT.VALIDATION_FAILED``. The qualification names the records' uncontrolled
strings -- ``uncontrolled_strings_of``: every string whose declared type is not a
closed identifier or digest grammar or a literal, free text, adapter-chosen
identifiers, error codes, versions and dynamic mapping keys included -- which
the validation holds to the token-shape rule field by field; the describe
header's echo of the envelope's ``executable_hash``, which the parse validator
proves equal, is the one mirrored value. ``finalize_evidence`` and
``conclude_command`` hand the finalizer the attempt token material the
conclusion's frame already holds, so the exact raw-token scan runs over every
finalization of a conclusion before the terminal close removes ``request.json``;
a describe conclusion is token-free.

``ResultRecoveryValidator`` is the production 29.3 validator: over a ``RUN``
root it requires the durably ``EXITED`` run-command invocation with captured
exit facts, hashes the raw token from the surviving request material and
compares the hash with the durable ``attempt_token_hash`` (never loading a
durable token), confines and bounds the temporary manifest before reading it,
rebuilds the protocol summary from the stored events, observes the candidates
through ``observe_candidates`` and applies ``reconcile_run`` exactly as
uninterrupted execution does; only a ``RESULT_FINALIZATION_ELIGIBLE`` verdict
yields facts, and a failed check is the check's own diagnostic.

``semantic_outcome_or_replay`` (reading 24) loads the run first and answers a
run already in a success state with the stored ``CommandConclusion`` instead of
invoking the Stage 6 operation, which would refuse it. ``conclude_describe``
is the ``DESCRIBE`` counterpart of ``conclude_command``: the descriptor and
stderr evidence under the ``ADAPTER`` owner, no run row, no close.

Declared readings recorded for review: the unit of work the integration needs
is the Stage 5 ``UnitOfWork`` whose transaction also carries the Task 6
registration members and an owner registry (``ConclusionTransaction``, a
structural protocol the Stage 8 ``SqliteTransaction`` satisfies); the metrics of
the run manifest project the sanitized ``CandidateMetric`` records onto
``MetricValue`` with the value type derived from the declared unit, a fixed
sampling convention and the first result reference in candidate order as the
source artifact; the sanitized-manifest evidence link reads the sanitized hash
from the ``run_manifests`` row (durable after a success) or from the memo the
conclusion fills through ``ConclusionConfig.registrar`` -- the staging leaf is
fixed because a hash-bearing leaf under the owner-hash and correlation
directories exceeds the Windows path limit without long-path support; the
stderr truncation diagnostic restates the Stage 6 ``PROCESS.STDERR_TRUNCATED``
posture.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Coroutine, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from enum import Enum
from pathlib import Path
from typing import (
    Annotated,
    Any,
    Final,
    Literal,
    Protocol,
    TypeAliasType,
    Union,
    cast,
    get_args,
    get_origin,
)

from pydantic import BaseModel, InstanceOf, ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.adapters.commands import CommandResult
from crypto_lab.adapters.diagnostics import (
    PROCESS_STDERR_TRUNCATED,
    PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
    stage6_diagnostic,
    stage6_failure,
)
from crypto_lab.adapters.envelopes import NegotiatedVersions
from crypto_lab.adapters.events import (
    ArtifactDeclarationRecord,
    InvocationEventLedger,
    ProtocolEventSummary,
    RunEvent,
)
from crypto_lab.adapters.limits import (
    MAX_RESULT_MANIFEST_BYTES,
    RESULT_MANIFEST_RELATIVE_PATH,
)
from crypto_lab.adapters.manifests import (
    AdapterResultManifest,
    AdapterValidationResult,
    CandidateMetric,
    ManifestParse,
    SanitizedAdapterResultManifest,
    ValidationResultParse,
    parse_result_manifest,
)
from crypto_lab.adapters.negotiation import (
    BootstrapDescriptorEnvelope,
    DescriptorParse,
)
from crypto_lab.adapters.reconciliation import (
    CandidateObservation,
    ReconciliationRuleViolation,
    SemanticReconciliation,
    reconcile_run,
)
from crypto_lab.adapters.sanitization import StderrCapture
from crypto_lab.adapters.vocabulary import (
    NEGOTIABLE_SCHEMA_NAMES,
    ReconciliationVerdict,
    SemanticStatus,
)
from crypto_lab.artifacts.diagnostics import (
    ARTIFACT_RESULT_MANIFEST_INVALID,
    ARTIFACT_VALIDATION_FAILED,
    artifact_failure,
)
from crypto_lab.artifacts.finalizer import close_raw_bytes
from crypto_lab.artifacts.hashing import ContentHasher
from crypto_lab.artifacts.journal import (
    FinalizationJournalEntry,
    FinalizationJournalState,
)
from crypto_lab.artifacts.manifest import (
    ARTIFACT_VALIDATION_PROFILE,
    ArtifactLineage,
    ArtifactManifest,
    artifact_manifest_hash,
)
from crypto_lab.artifacts.models import (
    ArtifactFinalizationPurpose,
    ArtifactRef,
    ArtifactSourceRole,
    CandidateArtifact,
    CandidateArtifactProducerKind,
    CandidateArtifactState,
    CandidateFinalization,
    FinalizationResult,
    owner_kind_of,
    validate_role_combination,
)
from crypto_lab.artifacts.ownership import (
    AdapterArtifactOwner,
    ArtifactOwnerRef,
    DatasetArtifactOwner,
    ExperimentArtifactOwner,
    RunArtifactOwner,
    StrategyArtifactOwner,
    SystemArtifactOwner,
    artifact_owner_hash,
)
from crypto_lab.artifacts.paths import confine_candidate_path, lexical_candidate_path
from crypto_lab.artifacts.ports import (
    ArtifactFinalizer,
    AuditFact,
    CandidateObservationFacts,
    CanonicalQualification,
    CommandRootPaths,
    FinalizationAuditor,
    FinalizationUnitOfWork,
    RegistrationUnitOfWork,
    ResultLeaseFacts,
    ResultRecoveryFacts,
    ResultRegistration,
)
from crypto_lab.artifacts.requests import (
    EvidenceCorrelation,
    EvidenceFinalizationRequest,
    ResultFinalizationRequest,
)
from crypto_lab.artifacts.store import ArtifactStore, read_confined, scan_confined
from crypto_lab.audit.models import (
    CORE_ACTOR,
    AuditAction,
    AuditEvent,
    AuditOutcome,
    audit_details_hash,
)
from crypto_lab.audit.sink import AuditEventIds
from crypto_lab.domain.canonical_json import canonical_json_bytes, canonical_json_text
from crypto_lab.domain.command_invocation import (
    CommandInvocationRecord,
    CommandInvocationRuleViolation,
    assert_write_once_enrichment,
)
from crypto_lab.domain.diagnostics import Diagnostic, DiagnosticDetailValue
from crypto_lab.domain.engine_run import (
    SUCCESS_ENGINE_RUN_STATES,
    AttemptTokenMaterial,
    EngineRunRecord,
    EngineRunRuleViolation,
    RunEdgeOwner,
    assert_run_transition,
)
from crypto_lab.domain.hashing import (
    attempt_token_hash,
    candidate_artifact_id_for,
    candidate_set_hash_for,
    core_candidate_artifact_id_for,
    finalization_identity,
    run_manifest_id_for,
    sha256_bytes,
)
from crypto_lab.domain.identifiers import (
    AdapterManifestId,
    ApproximationId,
    ArtifactId,
    AuditEventId,
    AvailabilityObservationId,
    CandidateArtifactId,
    DatasetId,
    DatasetPartitionId,
    DiagnosticId,
    EventId,
    ExperimentId,
    FinalizationId,
    InvocationId,
    LogicalSlotId,
    RequestId,
    RunId,
    RunManifestId,
    Sha256,
    StrategyId,
    StrategyVersionId,
    validate_prefixed_uuid4,
)
from crypto_lab.domain.lifecycle import (
    TERMINAL_ENGINE_RUN_STATES,
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ProcessExitCategory,
)
from crypto_lab.domain.metrics import MetricStatus, MetricValue, MetricValueType
from crypto_lab.domain.ports import Clock
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.experiments.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
    stage5_failure,
)
from crypto_lab.experiments.ports import UnitOfWork
from crypto_lab.experiments.requests import SemanticOutcomeRequest
from crypto_lab.experiments.run_manifest import RunManifest, run_manifest_hash
from crypto_lab.experiments.semantic_outcome import (
    SemanticOutcome,
    apply_command_semantic_outcome,
)

SOURCE_COMPONENT: Final = "experiments.finalization"
#: Plan 4.6: the artifact kinds of the seven producers and their staging leaves.
STDERR_KIND: Final = "stderr-capture"
PROTOCOL_CAPTURE_KIND: Final = "protocol-capture"
SANITIZED_MANIFEST_KIND: Final = "sanitized-adapter-result-manifest"
VALIDATION_RESULT_KIND: Final = "sanitized-validation-result"
DESCRIPTOR_KIND: Final = "adapter-descriptor"
DIAGNOSTIC_REPORT_KIND: Final = "diagnostic-report"
#: The fixed staging leaves of the six invocation- and diagnostic-correlated
#: producers; the canonical contract of each kind requires its leaf exactly.
_STDERR_LEAF: Final = "stderr.txt"
_PROTOCOL_CAPTURE_LEAF: Final = "protocol-capture.jsonl"
_SANITIZED_MANIFEST_LEAF: Final = "sanitized-manifest.json"
_VALIDATION_RESULT_LEAF: Final = "validation-result.json"
_DESCRIPTOR_LEAF: Final = "adapter-descriptor.json"
_DIAGNOSTIC_REPORT_LEAF: Final = "diagnostic-report.jsonl"
INPUT_SNAPSHOT_KINDS: Final[Mapping[str, str]] = {
    "EXPERIMENT": "configuration-snapshot",
    "DATASET": "dataset-manifest",
    "STRATEGY": "strategy-snapshot",
}
INPUT_SNAPSHOT_ROLES: Final[Mapping[str, ArtifactSourceRole]] = {
    "EXPERIMENT": ArtifactSourceRole.EXPERIMENT_INPUT,
    "DATASET": ArtifactSourceRole.DATASET_INPUT,
    "STRATEGY": ArtifactSourceRole.STRATEGY_INPUT,
}
#: The declared reading of the metric projection: the value type by declared
#: unit (``DECIMAL`` otherwise) and the one sampling convention an adapter metric
#: carries -- the adapter declared it, the core did not resample it.
METRIC_VALUE_TYPES: Final[Mapping[str, MetricValueType]] = {
    "ratio": MetricValueType.RATIO,
    "count": MetricValueType.COUNT,
    "seconds": MetricValueType.DURATION_SECONDS,
}
METRIC_SAMPLING_CONVENTION: Final = "adapter-declared"
RESULT_MANIFEST_MEMBER: Final = "RESULT_MANIFEST_MEMBER"
RUN_EVIDENCE: Final = "RUN_EVIDENCE"
_TOKEN_BEARING_KINDS: Final[frozenset[CommandKind]] = frozenset(
    {CommandKind.VALIDATE, CommandKind.RUN}
)
_RUN_FAILING_PREFIXES: Final = ("ARTIFACT.", "SECURITY.")
_SUCCESS_STATE_OF_STATUS: Final[Mapping[SemanticStatus, EngineRunState]] = {
    SemanticStatus.SUCCEEDED: EngineRunState.SUCCEEDED,
    SemanticStatus.SUCCEEDED_WITH_WARNINGS: EngineRunState.SUCCEEDED_WITH_WARNINGS,
}
_F: Final = ArtifactFinalizationPurpose
_P: Final = CandidateArtifactProducerKind
_R: Final = ArtifactSourceRole
_S: Final = CandidateArtifactState


#: Plan 4.6's structured stderr record when no text survived the fold
#: (14.7:1014): exactly these three keys -- a non-negative integer count, a
#: boolean and a SHA-256 digest -- the exact producer/model mapping the stderr
#: canonical contract checks.
_STDERR_FALLBACK_KEYS: Final[frozenset[str]] = frozenset(
    {"retained_byte_count", "source_hash", "truncated"}
)
_SHA256_HEX: Final = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True, slots=True, kw_only=True)
class _CanonicalContract:
    """One plan 4.6 producer's canonical contract: the role, the owner kinds, the
    correlation kind and the fixed staging leaf its candidate carries, and the
    model its records are (``None`` for the stderr fallback record)."""

    role: ArtifactSourceRole
    owners: tuple[type[Any], ...]
    correlation_kind: str
    leaf: str
    model: type[BaseModel] | None


#: The canonical evidence ruling of 2026-11-09: the six producers whose content
#: the registrars can establish. The three input snapshots (``AUDIT``
#: correlation, caller-supplied bytes proved equal to a registry fact) answer no
#: contract here and keep the whole-content protection (Task 8 exercises them).
_CANONICAL_CONTRACTS: Final[Mapping[str, _CanonicalContract]] = {
    STDERR_KIND: _CanonicalContract(
        role=_R.CORE_EVIDENCE,
        owners=(RunArtifactOwner, AdapterArtifactOwner),
        correlation_kind="INVOCATION",
        leaf=_STDERR_LEAF,
        model=None,
    ),
    PROTOCOL_CAPTURE_KIND: _CanonicalContract(
        role=_R.CORE_EVIDENCE,
        owners=(RunArtifactOwner,),
        correlation_kind="INVOCATION",
        leaf=_PROTOCOL_CAPTURE_LEAF,
        model=RunEvent,
    ),
    SANITIZED_MANIFEST_KIND: _CanonicalContract(
        role=_R.CORE_EVIDENCE,
        owners=(RunArtifactOwner,),
        correlation_kind="INVOCATION",
        leaf=_SANITIZED_MANIFEST_LEAF,
        model=SanitizedAdapterResultManifest,
    ),
    VALIDATION_RESULT_KIND: _CanonicalContract(
        role=_R.CORE_EVIDENCE,
        owners=(RunArtifactOwner,),
        correlation_kind="INVOCATION",
        leaf=_VALIDATION_RESULT_LEAF,
        model=AdapterValidationResult,
    ),
    DESCRIPTOR_KIND: _CanonicalContract(
        role=_R.ADAPTER_DESCRIPTOR_EVIDENCE,
        owners=(AdapterArtifactOwner,),
        correlation_kind="INVOCATION",
        leaf=_DESCRIPTOR_LEAF,
        model=DescriptorParse,
    ),
    DIAGNOSTIC_REPORT_KIND: _CanonicalContract(
        role=_R.CORE_EVIDENCE,
        owners=(RunArtifactOwner, SystemArtifactOwner),
        correlation_kind="DIAGNOSTIC",
        leaf=_DIAGNOSTIC_REPORT_LEAF,
        model=Diagnostic,
    ),
}


# --------------------------------------------------------------------------
# The controlled-string classifier of the canonical evidence ruling
# --------------------------------------------------------------------------

#: The closed grammars a string field may declare -- the prefixed uuid4
#: identifier aliases and the SHA-256 digest of ``domain/identifiers.py`` --
#: whose values are core-derived and identifier- or digest-shaped by
#: construction. Every other string (free text, adapter-chosen identifiers,
#: error codes, versions, dynamic mapping keys) is uncontrolled and held to the
#: token-shape rule by the validation.
#: The runtime class of a ``X | Y`` union (``types.UnionType``), taken from an
#: instance rather than imported: the ``types`` root is confined to one approved
#: import site (Stage 3 guard).
_UNION_TYPE: Final = type(int | str)
_CONTROLLED_STRING_ALIASES: Final[tuple[TypeAliasType, ...]] = (
    Sha256,
    ExperimentId,
    RunId,
    ArtifactId,
    DatasetId,
    StrategyId,
    StrategyVersionId,
    InvocationId,
    EventId,
    CandidateArtifactId,
    DiagnosticId,
    AuditEventId,
    DatasetPartitionId,
    ApproximationId,
    AvailabilityObservationId,
    LogicalSlotId,
    RequestId,
    AdapterManifestId,
    FinalizationId,
    RunManifestId,
)


def _type_leaves(
    annotation: object, metadata: tuple[object, ...] = ()
) -> list[tuple[object, tuple[object, ...]]]:
    """Expand a declared type into its leaf types with the ``Annotated`` metadata
    accumulated on the way: through PEP 695 aliases, ``Annotated`` and unions."""
    if isinstance(annotation, TypeAliasType):
        return _type_leaves(annotation.__value__, metadata)
    origin = get_origin(annotation)
    if origin is Annotated:
        arguments = get_args(annotation)
        return _type_leaves(arguments[0], (*metadata, *arguments[1:]))
    if origin is Union or origin is _UNION_TYPE:
        return [
            leaf
            for argument in get_args(annotation)
            for leaf in _type_leaves(argument, metadata)
        ]
    return [(annotation, metadata)]


def _pattern_of(metadata: tuple[object, ...]) -> str | None:
    """The string pattern a constraint in ``metadata`` declares, if any (the
    ``StringConstraints`` of the alias or the constraint pydantic unpacked)."""
    for item in metadata:
        pattern = getattr(item, "pattern", None)
        if isinstance(pattern, str):
            return pattern
    return None


_CONTROLLED_PATTERNS: Final[frozenset[str]] = frozenset(
    pattern
    for alias in _CONTROLLED_STRING_ALIASES
    for _, metadata in _type_leaves(alias)
    if (pattern := _pattern_of(metadata)) is not None
)
#: The one core-owned closed vocabulary a canonical record restates verbatim as
#: ``NormalizedIdentifier`` text: the five negotiable schema names of plan 5.2
#: (``NegotiatedVersions`` and the descriptor's supported schema versions). A
#: value equal to a member is the core's constant, not adapter-chosen text, so
#: the contracts carrying them mirror the vocabulary as controlled.
_CORE_VOCABULARY: Final[frozenset[str]] = frozenset(NEGOTIABLE_SCHEMA_NAMES)


def _admits_string(leaf: object) -> bool:
    return leaf is str or leaf is Any or get_origin(leaf) is Literal


def _leaf_controlled(leaf: object, metadata: tuple[object, ...]) -> bool:
    if get_origin(leaf) is Literal:
        return True
    return leaf is str and _pattern_of(metadata) in _CONTROLLED_PATTERNS


def _string_controlled(annotation: object, metadata: tuple[object, ...]) -> bool:
    """A string is controlled only when every string-admitting member of its
    declared type is a closed grammar -- a controlled alias or a literal; ``Any``
    and an unknown declaration are uncontrolled (the classifier fails closed)."""
    admitting = [
        (leaf, meta)
        for leaf, meta in _type_leaves(annotation, metadata)
        if _admits_string(leaf)
    ]
    return bool(admitting) and all(
        _leaf_controlled(leaf, meta) for leaf, meta in admitting
    )


def _element_annotation(annotation: object, value: object) -> object:
    """The element type of the mapping or sequence member of a declared type
    matching ``value``; ``Any`` when the declaration says nothing."""
    mapping = isinstance(value, Mapping)
    for leaf, _ in _type_leaves(annotation):
        origin = get_origin(leaf)
        arguments = get_args(leaf)
        if mapping and origin in (dict, Mapping) and len(arguments) == 2:
            return arguments[1]
        if not mapping and origin in (list, tuple, Sequence) and arguments:
            return arguments[0]
    return Any


def _collect_strings(
    value: object,
    annotation: object,
    metadata: tuple[object, ...],
    mirrored: frozenset[str],
    out: list[str],
) -> None:
    if (
        value is MISSING
        or value is None
        or isinstance(value, Enum | bool | int | Decimal | datetime)
    ):
        return
    if isinstance(value, BaseModel):
        for name, field in type(value).model_fields.items():
            _collect_strings(
                getattr(value, name),
                Any if field.annotation is None else field.annotation,
                tuple(field.metadata),
                mirrored,
                out,
            )
        return
    if isinstance(value, str):
        if value not in mirrored and not _string_controlled(annotation, metadata):
            out.append(value)
        return
    if isinstance(value, Mapping):
        element = _element_annotation(annotation, value)
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("canonical mapping keys are strings")
            out.append(key)
            _collect_strings(item, element, (), mirrored, out)
        return
    if isinstance(value, list | tuple):
        element = _element_annotation(annotation, value)
        for item in value:
            _collect_strings(item, element, (), mirrored, out)
        return
    raise TypeError(f"unsupported canonical leaf of type {type(value).__name__}")


def uncontrolled_strings_of(
    model: BaseModel, *, mirrored: frozenset[str] = frozenset()
) -> tuple[str, ...]:
    """The strings of a canonical record that no closed grammar governs, in
    field order: every string value whose declared type is not a controlled
    identifier or digest alias or a literal (free text, adapter-chosen
    identifiers, error codes, versions), and every key of a mapping field.
    Enumeration members, numbers, instants and absent fields carry no string;
    an unknown leaf is refused. ``mirrored`` names values proven equal to a core
    fact -- a controlled field of the same record (the describe header's echo of
    the envelope's ``executable_hash``) or a member of a core-owned closed
    vocabulary (the negotiable schema names) -- which are controlled too."""
    if not isinstance(model, BaseModel):
        raise TypeError("a canonical record is a pydantic model")
    out: list[str] = []
    _collect_strings(model, type(model), (), mirrored, out)
    return tuple(out)


# --------------------------------------------------------------------------
# The unit of work the integration consumes (declared reading)
# --------------------------------------------------------------------------


class OwnerRegistry(Protocol):
    """The ``artifact_owners`` member: idempotent registration by owner hash."""

    def register(self, owner: ArtifactOwnerRef) -> Result[Sha256]: ...


class ConclusionTransaction(UnitOfWork, RegistrationUnitOfWork, Protocol):
    """One open transaction carrying the Stage 5 repositories, the Task 6
    registration members and the owner registry; ``SqliteTransaction`` satisfies
    it structurally."""

    @property
    def artifact_owners(self) -> OwnerRegistry: ...

    def begin(self) -> ConclusionTransaction: ...


class ConclusionUnitOfWork(UnitOfWork, Protocol):
    """The root whose ``begin()`` opens a ``ConclusionTransaction``."""

    def begin(self) -> ConclusionTransaction: ...


# --------------------------------------------------------------------------
# Composition facts and the conclusion
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class ConclusionConfig:
    """The composition facts a conclusion needs beside the unit of work: the
    opened store (the caller's ``artifacts_root``/``runtime_root``), the hasher,
    the production auditor, ``process.finalization_timeout_seconds`` and, when
    the composition's finalizer registers through ``ResultRegistrar``, that
    registrar -- so the conclusion can hand it the verdict's sanitized manifest
    for the evidence link (``remember``)."""

    store: ArtifactStore
    hasher: ContentHasher
    auditor: FinalizationAuditor
    finalization_timeout_seconds: int
    registrar: ResultRegistrar | None = None

    def __post_init__(self) -> None:
        if type(self.finalization_timeout_seconds) is not int or not (
            1 <= self.finalization_timeout_seconds <= 3600
        ):
            raise ValueError("finalization_timeout_seconds must be within 1..3600")


@dataclass(frozen=True, slots=True, kw_only=True)
class CommandConclusion:
    """What one concluded ``VALIDATE`` or ``RUN`` invocation left durable: the run
    and invocation as last read, the RESULT finalization with its run manifest and
    result references when the run succeeded, the finalized evidence references,
    an evidence refusal that changed nothing (29.1), and whether the answer is the
    stored replay of an earlier success (reading 24)."""

    run: EngineRunRecord
    invocation: CommandInvocationRecord
    finalization: FinalizationResult | MISSING = MISSING  # type: ignore[valid-type]
    run_manifest: RunManifest | MISSING = MISSING  # type: ignore[valid-type]
    result_refs: tuple[ArtifactRef, ...] = ()
    evidence_refs: tuple[ArtifactRef, ...] = ()
    evidence_failure: Failure | MISSING = MISSING  # type: ignore[valid-type]
    replayed: bool = False


type ConclusionOutcome = SemanticOutcome | InstanceOf[CommandConclusion]


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------


class _NeverCancelled:
    """The integration's cancellation token: a conclusion is never cancelled
    mid-protocol (plan 4.3: after T1 the run compare-and-swap decides)."""

    def is_cancellation_requested(self) -> bool:
        return False

    def request_cancellation(self) -> None:
        return None


def _drive[T](coroutine: Coroutine[Any, Any, T]) -> T:
    """Step a finalizer coroutine to completion without an event loop: every
    suspension point is a cooperative checkpoint that yields once."""
    try:
        while True:
            coroutine.send(None)
    except StopIteration as stop:
        value: T = stop.value
        return value


def _is_missing(value: object) -> bool:
    return value is MISSING


def _invariant(
    message: str,
    *,
    now: datetime,
    experiment_id: str | MISSING = MISSING,  # type: ignore[valid-type]
    run_id: str | MISSING = MISSING,  # type: ignore[valid-type]
    invocation_id: str | MISSING = MISSING,  # type: ignore[valid-type]
) -> Failure:
    return stage5_failure(
        INVARIANT_VIOLATION,
        message,
        source_component=SOURCE_COMPONENT,
        timestamp_utc=now,
        experiment_id=experiment_id,
        run_id=run_id,
        invocation_id=invocation_id,
    )


def _conflict(message: str, *, now: datetime, run: EngineRunRecord) -> Failure:
    return stage5_failure(
        CONCURRENCY_CONFLICT,
        message,
        source_component=SOURCE_COMPONENT,
        timestamp_utc=now,
        experiment_id=run.experiment_id,
        run_id=run.run_id,
    )


def _none() -> Success[None]:
    return Success[None](outcome="SUCCESS", value=None)


def _absent() -> Success[Any]:
    """The qualifier's "no canonical contract applies" answer."""
    nothing: Any = MISSING
    return Success[Any](outcome="SUCCESS", value=nothing)


def _code_of(failure: Failure) -> str:
    return failure.diagnostics[0].error_code


def _correlation_for(
    owner: ArtifactOwnerRef, invocation_id: str
) -> EvidenceCorrelation:
    del owner
    return EvidenceCorrelation(kind="INVOCATION", invocation_id=invocation_id)


def _run_ids(owner: ArtifactOwnerRef) -> dict[str, Any]:
    if isinstance(owner, RunArtifactOwner):
        return {
            "experiment_id": owner.experiment_id,
            "run_id": owner.run_id,
            "invocation_id": owner.invocation_id,
        }
    return {}


# --------------------------------------------------------------------------
# The production auditor (plan 4.1 port module docstring)
# --------------------------------------------------------------------------


class AuditFactRecorder:
    """The production ``FinalizationAuditor``: one ``AuditFact`` becomes the
    sink's ``AuditEvent`` -- identifier from ``ids``, instant from ``clock``, the
    ``CORE`` actor -- appended on the open transaction (23.3.1:1714)."""

    __slots__ = ("_clock", "_ids")

    def __init__(self, ids: AuditEventIds, clock: Clock) -> None:
        self._ids = ids
        self._clock = clock

    def append(
        self, transaction: FinalizationUnitOfWork, fact: AuditFact
    ) -> Result[None]:
        payload: dict[str, Any] = {
            "schema_version": "1.0.0",
            "audit_event_id": self._ids.new_audit_event_id(),
            "action": AuditAction(fact.action),
            "actor": CORE_ACTOR,
            "outcome": AuditOutcome(fact.outcome),
            "timestamp_utc": self._clock.now_utc(),
            "correlation_id": fact.correlation_id,
            "details_hash": audit_details_hash(fact.details),
            "details": dict(fact.details),
        }
        for name in ("experiment_id", "run_id", "invocation_id", "artifact_id"):
            value = getattr(fact, name)
            if isinstance(value, str):
                payload[name] = value
        return transaction.audit.append(AuditEvent.model_validate(payload))


# --------------------------------------------------------------------------
# Step 0: the production candidate observation (plan 4.4)
# --------------------------------------------------------------------------


def declared_candidate_paths(
    protocol_summary: ProtocolEventSummary,
    output_parse: ValidationResultParse | ManifestParse | MISSING,  # type: ignore[valid-type]
) -> tuple[str, ...]:
    """The union of the accepted ``ARTIFACT_PRODUCED`` paths and, for a success
    manifest, its declared paths (Stage 6 plan 11.3 item 4), in first-seen order."""
    declared: list[str] = [
        record.payload.relative_path
        for record in protocol_summary.artifact_declarations
    ]
    if isinstance(output_parse, ManifestParse) and isinstance(
        output_parse.manifest, AdapterResultManifest
    ):
        manifest = output_parse.manifest
        if manifest.semantic_status in _SUCCESS_STATE_OF_STATUS:
            declared.extend(
                item.relative_path
                for item in manifest.candidate_artifacts
                if item.relative_path not in declared
            )
    return tuple(declared)


def observe_candidates(
    work_dir: Path,
    declarations: Sequence[str],
    token: AttemptTokenMaterial | MISSING,  # type: ignore[valid-type]
    *,
    hasher: ContentHasher,
    clock: Clock,
) -> Result[tuple[CandidateObservation, ...]]:
    """Plan 4.4 step 0: confine every declared path before any open, then stream
    the digest and the exact-byte token scan through the identity-checked handle
    bridge; a declared file that was never written is not observed (the verdict
    reports it unobserved); a junction, symlink, reparse ancestor, hard link or
    escaping path is ``ARTIFACT.PATH_BOUNDARY_VIOLATION`` and is never opened."""
    if not isinstance(work_dir, Path) or not work_dir.is_absolute():
        raise ValueError("work_dir must be an absolute Path")
    now = clock.now_utc()
    observations: list[CandidateObservation] = []
    seen: set[str] = set()
    for relative in declarations:
        if relative in seen:
            continue
        seen.add(relative)
        try:
            validated = lexical_candidate_path(relative)
        except ValueError as error:
            return artifact_failure(
                "ARTIFACT.PATH_BOUNDARY_VIOLATION",
                message=f"declared candidate path refused: {error}",
                now_utc=now,
            )
        confined = confine_candidate_path(work_dir, validated, now_utc=now)
        if isinstance(confined, Failure):
            leaf = work_dir.joinpath(*validated.split("/"))
            try:
                leaf.lstat()
            except FileNotFoundError:
                continue  # never written: reconcile_run reports it unobserved
            except OSError:
                return confined
            return confined
        scan = scan_confined(
            confined.value, hasher, token, detect_token_shape=False, now_utc=now
        )
        if isinstance(scan, Failure):
            return scan
        observations.append(
            CandidateObservation(
                relative_path=validated,
                observed_size_bytes=scan.value.size_bytes,
                observed_sha256=scan.value.sha256,
                contains_attempt_token=scan.value.token_found,
            )
        )
    return Success[tuple[CandidateObservation, ...]](
        outcome="SUCCESS", value=tuple(observations)
    )


# --------------------------------------------------------------------------
# Step 2: candidate registration and core evidence staging (plan 4.4, 4.6)
# --------------------------------------------------------------------------


def register_result_candidates(
    declarations: Sequence[ArtifactDeclarationRecord],
    owner: RunArtifactOwner,
    *,
    unit_of_work: ConclusionUnitOfWork,
    clock: Clock,
) -> Result[tuple[CandidateArtifact, ...]]:
    """Plan 4.4 step 2: the ``RUN`` owner (idempotent on its hash) and one
    ``CANDIDATE`` row per accepted declaration -- ``ADAPTER`` producer, purpose
    ``RESULT``, role ``ENGINE_NATIVE_RESULT``, identity ``candidate_artifact_id_for``
    -- each registered once; an existing row is returned unchanged."""
    if not isinstance(owner, RunArtifactOwner) or not isinstance(
        owner.invocation_id, str
    ):
        raise ValueError("result candidates belong to a RUN owner with an invocation")
    now = clock.now_utc()
    transaction = unit_of_work.begin()
    try:
        registered = transaction.artifact_owners.register(owner)
        if isinstance(registered, Failure):
            return registered
        records: list[CandidateArtifact] = []
        for record in declarations:
            payload = record.payload
            identity = candidate_artifact_id_for(
                owner.run_id, owner.invocation_id, payload.relative_path
            )
            existing = transaction.candidate_artifacts.get(identity)
            if isinstance(existing, Success):
                records.append(existing.value)
                continue
            candidate = CandidateArtifact.model_validate(
                {
                    "schema_version": "1.0.0",
                    "candidate_artifact_id": identity,
                    "owner": owner,
                    "finalization_purpose": _F.RESULT,
                    "source_role": _R.ENGINE_NATIVE_RESULT,
                    "producer_kind": _P.ADAPTER,
                    "artifact_kind": payload.artifact_kind,
                    "staging_relative_path": payload.relative_path,
                    "state": _S.CANDIDATE,
                    "adapter_declared_size": payload.declared_size_bytes,
                    "adapter_declared_hash": payload.declared_sha256,
                    "adapter_declared_media_type": payload.media_type,
                    "validation_observations": (),
                    "source_event_id": record.event_id,
                    "created_at_utc": now,
                    "updated_at_utc": now,
                    "revision": 1,
                }
            )
            added = transaction.candidate_artifacts.add(candidate)
            if isinstance(added, Failure):
                return added
            records.append(candidate)
        committed = transaction.commit()
        if isinstance(committed, Failure):
            return committed
    finally:
        transaction.rollback()
    return Success[tuple[CandidateArtifact, ...]](
        outcome="SUCCESS",
        value=tuple(sorted(records, key=lambda item: item.candidate_artifact_id)),
    )


def _adapter_evidence_describes(
    owner: AdapterArtifactOwner,
    correlation: EvidenceCorrelation,
    *,
    unit_of_work: ConclusionUnitOfWork,
    now: datetime,
) -> Failure | None:
    """Plan 3.1.1 row 3 at the staging boundary: an ``ADAPTER`` owner's
    ``CORE_EVIDENCE`` is correlated to a ``DESCRIBE`` invocation of that adapter
    and version -- read from the authoritative ``command_invocations`` row in a
    short transaction released before any filesystem work -- so under any other
    correlation no byte is staged and no candidate inserted (the finalizer's
    phase 0 re-checks the same fact over the registered rows)."""
    if correlation.kind != "INVOCATION":
        return artifact_failure(
            ARTIFACT_VALIDATION_FAILED,
            message=(
                "ADAPTER-owned CORE_EVIDENCE is correlated to a DESCRIBE invocation "
                f"of {owner.adapter_name} {owner.adapter_version}, not to a "
                f"{correlation.kind} correlation"
            ),
            now_utc=now,
        )
    invocation_id = correlation.correlation_id
    transaction = unit_of_work.begin()
    try:
        loaded = transaction.command_invocations.get(invocation_id)
    finally:
        transaction.rollback()
    if isinstance(loaded, Failure):
        return loaded
    invocation = loaded.value
    if (
        invocation.command_kind is not CommandKind.DESCRIBE
        or invocation.adapter_name != owner.adapter_name
        or invocation.adapter_version != owner.adapter_version
    ):
        return artifact_failure(
            ARTIFACT_VALIDATION_FAILED,
            message=(
                f"invocation {invocation_id} is not a DESCRIBE invocation of adapter "
                f"{owner.adapter_name} {owner.adapter_version}"
            ),
            now_utc=now,
            invocation_id=invocation_id,
        )
    return None


def stage_core_evidence(
    owner: ArtifactOwnerRef,
    source_role: ArtifactSourceRole,
    artifact_kind: str,
    relative_path: str,
    payload: bytes,
    correlation: EvidenceCorrelation,
    *,
    store: ArtifactStore,
    unit_of_work: ConclusionUnitOfWork,
    clock: Clock,
) -> Result[CandidateArtifact]:
    """Plan 4.6: the only way core evidence enters staging. The bytes go through
    ``store.write_staged`` under ``<correlation_kind>/<correlation_id>/<relative_path>``
    of the owner's core staging root, and the ``CORE`` candidate is inserted with
    ``core_candidate_artifact_id_for``; idempotent: an existing equal file and row
    are returned, a differing file is ``CORE.INVARIANT_VIOLATION`` (the store's
    answer). A role and owner pair outside plan 3.1.1 is refused before any I/O,
    and an ``ADAPTER`` owner's ``CORE_EVIDENCE`` under a correlation that is not
    the ``INVOCATION`` of a ``DESCRIBE`` of that adapter and version is refused
    before any byte is written (plan 3.1.1 row 3, ``_adapter_evidence_describes``)."""
    now = clock.now_utc()
    try:
        validate_role_combination(
            _F.EVIDENCE, _P.CORE, source_role, owner_kind_of(owner)
        )
    except ValueError as error:
        return artifact_failure(
            ARTIFACT_VALIDATION_FAILED,
            message=str(error),
            now_utc=now,
            **_run_ids(owner),
        )
    if isinstance(owner, AdapterArtifactOwner) and source_role is _R.CORE_EVIDENCE:
        described = _adapter_evidence_describes(
            owner, correlation, unit_of_work=unit_of_work, now=now
        )
        if described is not None:
            return described
    owner_hash = artifact_owner_hash(owner)
    staging_relative = (
        f"{correlation.kind}/{correlation.correlation_id}/{relative_path}"
    )
    written = store.write_staged(owner_hash, staging_relative, payload, now_utc=now)
    if isinstance(written, Failure):
        return written
    identity = core_candidate_artifact_id_for(
        owner_hash, correlation.kind, correlation.correlation_id, relative_path
    )
    transaction = unit_of_work.begin()
    try:
        registered = transaction.artifact_owners.register(owner)
        if isinstance(registered, Failure):
            return registered
        existing = transaction.candidate_artifacts.get(identity)
        if isinstance(existing, Success):
            transaction.rollback()
            return existing
        candidate = CandidateArtifact.model_validate(
            {
                "schema_version": "1.0.0",
                "candidate_artifact_id": identity,
                "owner": owner,
                "finalization_purpose": _F.EVIDENCE,
                "source_role": source_role,
                "producer_kind": _P.CORE,
                "artifact_kind": artifact_kind,
                "staging_relative_path": staging_relative,
                "state": _S.CANDIDATE,
                "validation_observations": (),
                "created_at_utc": now,
                "updated_at_utc": now,
                "revision": 1,
            }
        )
        added = transaction.candidate_artifacts.add(candidate)
        if isinstance(added, Failure):
            return added
        committed = transaction.commit()
        if isinstance(committed, Failure):
            return committed
    finally:
        transaction.rollback()
    return Success[CandidateArtifact](outcome="SUCCESS", value=candidate)


def stderr_evidence(
    capture: StderrCapture,
    owner: RunArtifactOwner | AdapterArtifactOwner,
    invocation_id: str,
    *,
    store: ArtifactStore,
    unit_of_work: ConclusionUnitOfWork,
    auditor: FinalizationAuditor,
    clock: Clock,
) -> Result[CandidateArtifact]:
    """Plan 4.6: the sanitized stderr text (UTF-8) or, when no text survived the
    fold, a JSON record of the retained count, truncation and source hash
    (14.7:1014); a truncated capture records ``PROCESS.STDERR_TRUNCATED`` and the
    ``STDERR_TRUNCATED`` audit fact in their own short transaction."""
    now = clock.now_utc()
    text = capture.sanitized_text
    if isinstance(text, str):
        payload = text.encode("utf-8")
    else:
        payload = canonical_json_bytes(
            {
                "retained_byte_count": capture.retained_byte_count,
                "truncated": capture.truncated,
                "source_hash": capture.source_hash,
            }
        )
    correlation = _correlation_for(owner, invocation_id)
    staged = stage_core_evidence(
        owner,
        _R.CORE_EVIDENCE,
        STDERR_KIND,
        _STDERR_LEAF,
        payload,
        correlation,
        store=store,
        unit_of_work=unit_of_work,
        clock=clock,
    )
    if isinstance(staged, Failure) or not capture.truncated:
        return staged
    ids = _run_ids(owner)
    diagnostic = stage6_diagnostic(
        PROCESS_STDERR_TRUNCATED,
        "stderr exceeded the retained budget and was truncated before redaction",
        source_component=SOURCE_COMPONENT,
        timestamp_utc=now,
        experiment_id=ids.get("experiment_id", MISSING),
        run_id=ids.get("run_id", MISSING),
        invocation_id=invocation_id,
        details={"retained_byte_count": capture.retained_byte_count},
    )
    transaction = unit_of_work.begin()
    try:
        recorded = transaction.diagnostics_writer.record(diagnostic)
        if isinstance(recorded, Failure):
            return recorded
        audited = auditor.append(
            transaction,
            AuditFact(
                action="STDERR_TRUNCATED",
                outcome="SUCCEEDED",
                correlation_id=invocation_id,
                details={"retained_byte_count": capture.retained_byte_count},
                **{**ids, "invocation_id": invocation_id},
            ),
        )
        if isinstance(audited, Failure):
            return audited
        committed = transaction.commit()
        if isinstance(committed, Failure):
            return committed
    finally:
        transaction.rollback()
    return staged


def protocol_capture_evidence(
    events: Sequence[RunEvent],
    owner: RunArtifactOwner,
    invocation_id: str,
    *,
    store: ArtifactStore,
    unit_of_work: ConclusionUnitOfWork,
    clock: Clock,
) -> Result[CandidateArtifact]:
    """Plan 4.6: JSON Lines of the accepted sanitized ``RunEvent`` records,
    regenerated from the ledger -- never raw stdout."""
    payload = b"".join(canonical_json_bytes(event) + b"\n" for event in events)
    return stage_core_evidence(
        owner,
        _R.CORE_EVIDENCE,
        PROTOCOL_CAPTURE_KIND,
        _PROTOCOL_CAPTURE_LEAF,
        payload,
        _correlation_for(owner, invocation_id),
        store=store,
        unit_of_work=unit_of_work,
        clock=clock,
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class _SanitizedManifestFacts:
    sanitized_adapter_result_manifest_hash: str
    run_id: str
    run_invocation_id: str
    experiment_id: str
    attempt_token_hash: str
    source_adapter_result_manifest_hash: str
    semantic_status: str
    manifest_json: str
    evidence_artifact_id: str | MISSING  # type: ignore[valid-type]
    recorded_at_utc: datetime


def _sanitized_facts(
    sanitized: SanitizedAdapterResultManifest, now: datetime
) -> _SanitizedManifestFacts:
    return _SanitizedManifestFacts(
        sanitized_adapter_result_manifest_hash=(
            sanitized.sanitized_adapter_result_manifest_hash
        ),
        run_id=sanitized.run_id,
        run_invocation_id=sanitized.invocation_id,
        experiment_id=sanitized.experiment_id,
        attempt_token_hash=sanitized.attempt_token_hash,
        source_adapter_result_manifest_hash=(
            sanitized.source_adapter_result_manifest_hash
        ),
        semantic_status=sanitized.semantic_status.value,
        manifest_json=canonical_json_text(sanitized),
        evidence_artifact_id=MISSING,
        recorded_at_utc=now,
    )


def _ensure_sanitized_row(
    transaction: RegistrationUnitOfWork,
    sanitized: SanitizedAdapterResultManifest,
    now: datetime,
) -> Result[None]:
    found = transaction.sanitized_manifests.get(
        sanitized.sanitized_adapter_result_manifest_hash
    )
    if isinstance(found, Failure):
        return found
    if not _is_missing(found.value):
        return _none()
    return transaction.sanitized_manifests.add(_sanitized_facts(sanitized, now))


def sanitized_manifest_leaf() -> str:
    """The fixed, short staging leaf of the sanitized-manifest evidence. The leaf
    never carries the 64-character sanitized hash and stays short on purpose:
    core staging already spends 134 characters on the owner-hash and
    correlation directories, and a longer leaf exceeds the Windows path limit
    on hosts without long-path support; the T3 link derives the hash from the
    ``run_manifests`` row or the registrar's memo instead."""
    return _SANITIZED_MANIFEST_LEAF


def sanitized_result_manifest_evidence(
    sanitized: SanitizedAdapterResultManifest,
    owner: RunArtifactOwner,
    *,
    store: ArtifactStore,
    unit_of_work: ConclusionUnitOfWork,
    clock: Clock,
) -> Result[CandidateArtifact]:
    """Plan 4.6: the sanitized manifest's canonical JSON as ``RUN``-owned
    ``CORE_EVIDENCE`` and its ``sanitized_adapter_result_manifests`` row (once)."""
    now = clock.now_utc()
    transaction = unit_of_work.begin()
    try:
        ensured = _ensure_sanitized_row(transaction, sanitized, now)
        if isinstance(ensured, Failure):
            return ensured
        committed = transaction.commit()
        if isinstance(committed, Failure):
            return committed
    finally:
        transaction.rollback()
    return stage_core_evidence(
        owner,
        _R.CORE_EVIDENCE,
        SANITIZED_MANIFEST_KIND,
        sanitized_manifest_leaf(),
        canonical_json_bytes(sanitized),
        _correlation_for(owner, sanitized.invocation_id),
        store=store,
        unit_of_work=unit_of_work,
        clock=clock,
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class _ValidationResultFacts:
    invocation_id: str
    run_id: str
    experiment_id: str
    validation_result_hash: str
    outcome: str
    result_json: str
    evidence_artifact_id: str | MISSING  # type: ignore[valid-type]
    recorded_at_utc: datetime


def validation_result_evidence(
    result: AdapterValidationResult,
    owner: RunArtifactOwner,
    *,
    store: ArtifactStore,
    unit_of_work: ConclusionUnitOfWork,
    clock: Clock,
) -> Result[CandidateArtifact]:
    """Plan 4.6: the sanitized ``AdapterValidationResult`` as ``RUN``-owned
    ``CORE_EVIDENCE`` and its ``adapter_validation_results`` row (once)."""
    now = clock.now_utc()
    transaction = unit_of_work.begin()
    try:
        found = transaction.validation_results.get(result.invocation_id)
        if isinstance(found, Failure):
            return found
        if _is_missing(found.value):
            added = transaction.validation_results.add(
                _ValidationResultFacts(
                    invocation_id=result.invocation_id,
                    run_id=result.run_id,
                    experiment_id=owner.experiment_id,
                    validation_result_hash=result.result_hash,
                    outcome=result.outcome.value,
                    result_json=canonical_json_text(result),
                    evidence_artifact_id=MISSING,
                    recorded_at_utc=now,
                )
            )
            if isinstance(added, Failure):
                return added
        committed = transaction.commit()
        if isinstance(committed, Failure):
            return committed
    finally:
        transaction.rollback()
    return stage_core_evidence(
        owner,
        _R.CORE_EVIDENCE,
        VALIDATION_RESULT_KIND,
        _VALIDATION_RESULT_LEAF,
        canonical_json_bytes(result),
        _correlation_for(owner, result.invocation_id),
        store=store,
        unit_of_work=unit_of_work,
        clock=clock,
    )


def descriptor_evidence(
    parse: DescriptorParse,
    owner: AdapterArtifactOwner,
    invocation_id: str,
    *,
    store: ArtifactStore,
    unit_of_work: ConclusionUnitOfWork,
    clock: Clock,
) -> Result[CandidateArtifact]:
    """Plan 4.6: the ``DescriptorParse`` canonical JSON as ``ADAPTER``-owned
    ``ADAPTER_DESCRIPTOR_EVIDENCE`` -- the typed parse, never raw stdout."""
    return stage_core_evidence(
        owner,
        _R.ADAPTER_DESCRIPTOR_EVIDENCE,
        DESCRIPTOR_KIND,
        _DESCRIPTOR_LEAF,
        canonical_json_bytes(parse),
        _correlation_for(owner, invocation_id),
        store=store,
        unit_of_work=unit_of_work,
        clock=clock,
    )


def diagnostic_report_evidence(
    diagnostics: Sequence[Diagnostic],
    owner: RunArtifactOwner | SystemArtifactOwner,
    primary_diagnostic_id: str,
    *,
    store: ArtifactStore,
    unit_of_work: ConclusionUnitOfWork,
    clock: Clock,
) -> Result[CandidateArtifact]:
    """Plan 4.6: the recorded ``Diagnostic`` closure as JSON Lines under the
    ``DIAGNOSTIC`` correlation of its primary diagnostic (bounded, redacted
    records by construction, 21.3)."""
    payload = b"".join(
        canonical_json_bytes(diagnostic) + b"\n"
        for diagnostic in sorted(diagnostics, key=lambda item: item.diagnostic_id)
    )
    return stage_core_evidence(
        owner,
        _R.CORE_EVIDENCE,
        DIAGNOSTIC_REPORT_KIND,
        _DIAGNOSTIC_REPORT_LEAF,
        payload,
        EvidenceCorrelation(kind="DIAGNOSTIC", diagnostic_id=primary_diagnostic_id),
        store=store,
        unit_of_work=unit_of_work,
        clock=clock,
    )


def input_snapshot_evidence(
    owner: ExperimentArtifactOwner | DatasetArtifactOwner | StrategyArtifactOwner,
    payload: bytes,
    expected_hash: str,
    audit_event_id: str,
    *,
    store: ArtifactStore,
    unit_of_work: ConclusionUnitOfWork,
    clock: Clock,
) -> Result[CandidateArtifact]:
    """Plan 4.6 and O-12: caller-supplied canonical bytes whose SHA-256 must equal
    the registry fact (``configuration_audit_hash``, the dataset ``content_hash``,
    ``strategy_version_hash``) under the ``AUDIT`` correlation; differing bytes
    are ``ARTIFACT.VALIDATION_FAILED`` before anything is staged."""
    now = clock.now_utc()
    kind = owner.owner_kind
    if sha256_bytes(payload) != expected_hash:
        return artifact_failure(
            ARTIFACT_VALIDATION_FAILED,
            message=f"{kind} input snapshot bytes differ from the registry fact",
            now_utc=now,
        )
    return stage_core_evidence(
        owner,
        INPUT_SNAPSHOT_ROLES[kind],
        INPUT_SNAPSHOT_KINDS[kind],
        f"{INPUT_SNAPSHOT_KINDS[kind]}.json",
        payload,
        EvidenceCorrelation(kind="AUDIT", audit_event_id=audit_event_id),
        store=store,
        unit_of_work=unit_of_work,
        clock=clock,
    )


def evidence_request_for(
    candidates: Sequence[CandidateArtifact], correlation: EvidenceCorrelation
) -> EvidenceFinalizationRequest:
    """The ``EvidenceFinalizationRequest`` over the staged candidates of one owner,
    one role and one correlation (plan 4.6); a mixed set is a caller defect."""
    if not candidates:
        raise ValueError("an evidence request needs at least one staged candidate")
    owner = candidates[0].owner
    owner_hash = artifact_owner_hash(owner)
    role = candidates[0].source_role
    for candidate in candidates:
        if artifact_owner_hash(candidate.owner) != owner_hash:
            raise ValueError("every evidence candidate of one request shares its owner")
        if candidate.source_role is not role:
            raise ValueError("every evidence candidate of one request shares its role")
    ids = tuple(sorted(candidate.candidate_artifact_id for candidate in candidates))
    set_hash = candidate_set_hash_for(ids)
    return EvidenceFinalizationRequest.model_validate(
        {
            "schema_version": "1.0.0",
            "finalization_purpose": "EVIDENCE",
            "owner": owner,
            "source_role": role,
            "candidate_artifact_ids": ids,
            "candidate_set_hash": set_hash,
            "correlation": correlation,
            "idempotency_key": finalization_identity(
                "EVIDENCE",
                owner_hash=owner_hash,
                correlation_kind=correlation.kind,
                correlation_id=correlation.correlation_id,
                candidate_set_hash=set_hash,
            ),
        }
    )


def finalize_evidence(
    candidates: Sequence[CandidateArtifact],
    correlation: EvidenceCorrelation,
    *,
    finalizer: ArtifactFinalizer,
    token: AttemptTokenMaterial | MISSING = MISSING,  # type: ignore[valid-type]
) -> Result[FinalizationResult]:
    """Plan 4.6: build the request over the staged candidates and await
    ``finalize``; ``token`` is the caller's transient material for the exact
    raw-token scan of this one finalization (the ruling of 2026-11-09)."""
    request = evidence_request_for(candidates, correlation)
    return _drive(finalizer.finalize(request, _NeverCancelled(), token_material=token))


# --------------------------------------------------------------------------
# The canonical contracts' fact checks (the ruling of 2026-11-09)
# --------------------------------------------------------------------------

type _Disagreement = Callable[[str], Failure]


@dataclass(frozen=True, slots=True)
class _Established:
    """A contract check's success: the records' uncontrolled strings and, for
    the sanitized manifest, the hash under which the registration links the
    stored row to the reference (the fact the check just established)."""

    uncontrolled: tuple[str, ...]
    sanitized_hash: str | None = None


def _staging_correlation(candidate: CandidateArtifact) -> tuple[str, str, str]:
    """A ``CORE`` candidate's ``<correlation_kind>/<correlation_id>/<leaf>``."""
    kind, correlation_id, *leaf = candidate.staging_relative_path.split("/")
    return kind, correlation_id, "/".join(leaf)


def _canonical_records[T: BaseModel](
    model: type[T], records: tuple[bytes, ...]
) -> tuple[T, ...] | None:
    """Every record parsed from its bytes as exactly ``model`` and re-serialized
    to those very bytes; ``None`` when any record is not the producer's model."""
    parsed: list[T] = []
    for record in records:
        try:
            instance = model.model_validate_json(record)
        except ValidationError:
            return None
        if canonical_json_bytes(instance) != record:
            return None
        parsed.append(instance)
    return tuple(parsed)


def _is_stderr_fallback(record: bytes) -> bool:
    """Whether one well-formed text record is plan 4.6's structured stderr
    fallback -- exactly its three typed keys, canonically serialized."""
    document = json.loads(record.decode("utf-8"))
    if not isinstance(document, dict) or set(document) != _STDERR_FALLBACK_KEYS:
        return False
    count = document["retained_byte_count"]
    source = document["source_hash"]
    if (
        type(count) is not int
        or count < 0
        or type(document["truncated"]) is not bool
        or not isinstance(source, str)
        or _SHA256_HEX.fullmatch(source) is None
    ):
        return False
    return canonical_json_bytes(document) == record


def _invocation_agrees(
    transaction: ConclusionTransaction,
    owner: ArtifactOwnerRef,
    correlation_id: str,
    disagrees: _Disagreement,
) -> Failure | None:
    """The ``INVOCATION`` correlation names the run owner's own invocation of its
    run, or a ``DESCRIBE`` invocation of the adapter owner (plan 3.1.1 row 3)."""
    if isinstance(owner, RunArtifactOwner) and owner.invocation_id != correlation_id:
        return disagrees("invocation")
    loaded = transaction.command_invocations.get(correlation_id)
    if isinstance(loaded, Failure):
        return loaded
    invocation = loaded.value
    if isinstance(owner, RunArtifactOwner):
        agreed = invocation.run_id == owner.run_id
    else:
        agreed = (
            isinstance(owner, AdapterArtifactOwner)
            and invocation.command_kind is CommandKind.DESCRIBE
            and invocation.adapter_name == owner.adapter_name
            and invocation.adapter_version == owner.adapter_version
        )
    return None if agreed else disagrees("invocation")


def _qualify_stderr(
    transaction: ConclusionTransaction,
    owner: ArtifactOwnerRef,
    correlation_id: str,
    records: tuple[bytes, ...],
    disagrees: _Disagreement,
) -> _Established | Failure | None:
    if not _is_stderr_fallback(records[0]):
        return None
    agreed = _invocation_agrees(transaction, owner, correlation_id, disagrees)
    return agreed if isinstance(agreed, Failure) else _Established(())


def _qualify_sanitized_manifest(
    transaction: ConclusionTransaction,
    owner: ArtifactOwnerRef,
    correlation_id: str,
    records: tuple[bytes, ...],
    disagrees: _Disagreement,
) -> _Established | Failure | None:
    models = _canonical_records(SanitizedAdapterResultManifest, records)
    if models is None:
        return None
    manifest = models[0]
    if (
        not isinstance(owner, RunArtifactOwner)
        or manifest.run_id != owner.run_id
        or manifest.experiment_id != owner.experiment_id
        or manifest.invocation_id != owner.invocation_id
        or manifest.invocation_id != correlation_id
    ):
        return disagrees("owner")
    found = transaction.sanitized_manifests.get(
        manifest.sanitized_adapter_result_manifest_hash
    )
    if isinstance(found, Failure):
        return found
    stored = found.value
    if _is_missing(stored) or stored.manifest_json != records[0].decode("utf-8"):
        return disagrees("stored row")
    return _Established(
        uncontrolled_strings_of(manifest, mirrored=_CORE_VOCABULARY),
        manifest.sanitized_adapter_result_manifest_hash,
    )


def _qualify_validation_result(
    transaction: ConclusionTransaction,
    owner: ArtifactOwnerRef,
    correlation_id: str,
    records: tuple[bytes, ...],
    disagrees: _Disagreement,
) -> _Established | Failure | None:
    models = _canonical_records(AdapterValidationResult, records)
    if models is None:
        return None
    result = models[0]
    if (
        not isinstance(owner, RunArtifactOwner)
        or result.run_id != owner.run_id
        or result.invocation_id != owner.invocation_id
        or result.invocation_id != correlation_id
    ):
        return disagrees("owner")
    found = transaction.validation_results.get(correlation_id)
    if isinstance(found, Failure):
        return found
    stored = found.value
    if _is_missing(stored) or stored.result_json != records[0].decode("utf-8"):
        return disagrees("stored row")
    return _Established(uncontrolled_strings_of(result))


def _qualify_protocol_capture(
    transaction: ConclusionTransaction,
    owner: ArtifactOwnerRef,
    correlation_id: str,
    records: tuple[bytes, ...],
    disagrees: _Disagreement,
) -> _Established | Failure | None:
    events = _canonical_records(RunEvent, records)
    if events is None:
        return None
    if not isinstance(owner, RunArtifactOwner) or owner.invocation_id != correlation_id:
        return disagrees("correlation")
    ledger = transaction.engine_runs.list_events(correlation_id)
    if isinstance(ledger, Failure):
        return ledger
    stored = {event.event_id: canonical_json_bytes(event) for event in ledger.value}
    last_sequence = 0
    for record, event in zip(records, events, strict=True):
        if (
            event.run_id != owner.run_id
            or event.invocation_id != correlation_id
            or stored.get(event.event_id) != record
            or event.sequence <= last_sequence
        ):
            return disagrees("ledger")
        last_sequence = event.sequence
    return _Established(
        tuple(text for event in events for text in uncontrolled_strings_of(event))
    )


def _qualify_descriptor(
    transaction: ConclusionTransaction,
    owner: ArtifactOwnerRef,
    correlation_id: str,
    records: tuple[bytes, ...],
    disagrees: _Disagreement,
) -> _Established | Failure | None:
    parses = _canonical_records(DescriptorParse, records)
    if parses is None:
        return None
    parse = parses[0]
    envelope = parse.envelope
    if not isinstance(envelope, BootstrapDescriptorEnvelope):
        return disagrees("envelope")
    if (
        not isinstance(owner, AdapterArtifactOwner)
        or envelope.adapter_name != owner.adapter_name
        or envelope.adapter_version != owner.adapter_version
        or (
            isinstance(owner.engine_name, str)
            and owner.engine_name != envelope.engine_name
        )
        or (
            isinstance(owner.engine_version, str)
            and owner.engine_version != envelope.engine_version
        )
    ):
        return disagrees("owner")
    agreed = _invocation_agrees(transaction, owner, correlation_id, disagrees)
    if isinstance(agreed, Failure):
        return agreed
    # The permissively read header echoes the envelope's executable hash as
    # bounded text; the parse validator proved them equal, so it is controlled,
    # as are the negotiable schema names the descriptor restates.
    return _Established(
        uncontrolled_strings_of(
            parse, mirrored=_CORE_VOCABULARY | {envelope.executable_hash}
        )
    )


def _qualify_diagnostic_report(
    transaction: ConclusionTransaction,
    owner: ArtifactOwnerRef,
    correlation_id: str,
    records: tuple[bytes, ...],
    disagrees: _Disagreement,
) -> _Established | Failure | None:
    diagnostics = _canonical_records(Diagnostic, records)
    if diagnostics is None:
        return None
    if correlation_id not in {diagnostic.diagnostic_id for diagnostic in diagnostics}:
        return disagrees("correlation")
    uncontrolled: list[str] = []
    for record, diagnostic in zip(records, diagnostics, strict=True):
        if (
            isinstance(owner, RunArtifactOwner)
            and isinstance(diagnostic.run_id, str)
            and diagnostic.run_id != owner.run_id
        ):
            return disagrees("owner")
        stored = transaction.diagnostics.get(diagnostic.diagnostic_id)
        if isinstance(stored, Failure):
            return stored
        if canonical_json_bytes(stored.value) != record:
            return disagrees("recorded diagnostics")
        uncontrolled.extend(uncontrolled_strings_of(diagnostic))
    return _Established(tuple(uncontrolled))


type _ContractCheck = Callable[
    [ConclusionTransaction, ArtifactOwnerRef, str, tuple[bytes, ...], _Disagreement],
    _Established | Failure | None,
]
_CONTRACT_CHECKS: Final[Mapping[str, _ContractCheck]] = {
    STDERR_KIND: _qualify_stderr,
    PROTOCOL_CAPTURE_KIND: _qualify_protocol_capture,
    SANITIZED_MANIFEST_KIND: _qualify_sanitized_manifest,
    VALIDATION_RESULT_KIND: _qualify_validation_result,
    DESCRIPTOR_KIND: _qualify_descriptor,
    DIAGNOSTIC_REPORT_KIND: _qualify_diagnostic_report,
}


# --------------------------------------------------------------------------
# The production registrars (plan 4.1, 4.4, 4.6)
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class _RunManifestFacts:
    manifest_id: str
    run_id: str
    experiment_id: str
    run_invocation_id: str
    attempt_token_hash: str
    sanitized_adapter_result_manifest_hash: str
    semantic_status: str
    process_exit_category: str
    manifest_json: str
    run_manifest_hash: str
    registered_at_utc: datetime


@dataclass(frozen=True, slots=True, kw_only=True)
class _RunArtifactLink:
    run_id: str
    artifact_id: str
    link_role: str
    experiment_id: str
    run_manifest_id: str | MISSING  # type: ignore[valid-type]


def _metric_value(metric: CandidateMetric, source_artifact_id: str) -> MetricValue:
    value_present = not _is_missing(metric.value)
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "metric_name": metric.metric_name,
        "value_type": METRIC_VALUE_TYPES.get(metric.unit, MetricValueType.DECIMAL),
        "unit": metric.unit,
        "methodology_version": metric.methodology_version,
        "sampling_convention": METRIC_SAMPLING_CONVENTION,
        "comparison_level": metric.comparison_level,
        "status": MetricStatus.DEFINED if value_present else MetricStatus.UNDEFINED,
        "source_artifact_id": source_artifact_id,
    }
    if value_present:
        payload["value"] = metric.value
    return MetricValue.model_validate(payload)


def _artifact_manifest(
    ref: ArtifactRef,
    candidate: CandidateArtifact,
    *,
    source_adapter_manifest_id: str,
) -> ArtifactManifest:
    """The ``ArtifactManifest`` beside one RESULT reference (plan 3.1): the ``RUN``
    lineage, the accepted event and the adapter manifest the sanitized facts name."""
    owner = ref.owner
    lineage: dict[str, Any] = {}
    if isinstance(owner, RunArtifactOwner):
        lineage["experiment_id"] = owner.experiment_id
        lineage["run_id"] = owner.run_id
        if isinstance(owner.invocation_id, str):
            lineage["invocation_id"] = owner.invocation_id
    if isinstance(candidate.source_event_id, str):
        lineage["source_event_id"] = candidate.source_event_id
    lineage["source_adapter_manifest_id"] = source_adapter_manifest_id
    draft = ArtifactManifest.model_construct(
        schema_version="1.0.0",
        artifact_id=ref.artifact_id,
        artifact_kind=ref.artifact_kind,
        media_type=ref.media_type,
        finalized_relative_path=ref.finalized_relative_path,
        size_bytes=ref.size_bytes,
        content_hash=ref.content_hash,
        producer_kind=ref.producer_kind,
        source_candidate_artifact_id=ref.source_candidate_artifact_id,
        owner=ref.owner,
        finalization_purpose=ref.finalization_purpose,
        source_role=ref.source_role,
        lineage=ArtifactLineage.model_validate(lineage),
        validation_profile=ARTIFACT_VALIDATION_PROFILE,
        validation_diagnostic_ids=tuple(
            sorted(
                {
                    observation.diagnostic_id
                    for observation in candidate.validation_observations
                    if isinstance(observation.diagnostic_id, str)
                }
            )
        ),
        created_at_utc=ref.created_at_utc,
        finalized_at_utc=ref.finalized_at_utc,
        artifact_manifest_hash="0" * 64,
    )
    payload = draft.model_dump(mode="python")
    payload["artifact_manifest_hash"] = artifact_manifest_hash(draft)
    return ArtifactManifest.model_validate(payload)


def _finalization_result(
    journal: FinalizationJournalEntry,
    refs: Sequence[ArtifactRef],
    now: datetime,
    *,
    run_manifest_id: str,
    run_manifest_hash_value: str,
) -> FinalizationResult:
    deduplicated = {
        move.candidate_artifact_id: move.deduplicated for move in journal.observed
    }
    return FinalizationResult.model_validate(
        {
            "schema_version": "1.0.0",
            "finalization_id": journal.finalization_id,
            "finalization_purpose": journal.finalization_purpose,
            "owner": journal.owner,
            "journal_state": "REGISTERED",
            "candidate_to_artifact_refs": tuple(
                CandidateFinalization(
                    candidate_artifact_id=ref.source_candidate_artifact_id,
                    artifact_id=ref.artifact_id,
                    content_hash=ref.content_hash,
                    size_bytes=ref.size_bytes,
                    deduplicated=deduplicated.get(
                        ref.source_candidate_artifact_id, False
                    ),
                )
                for ref in refs
            ),
            "run_manifest_id": run_manifest_id,
            "run_manifest_hash": run_manifest_hash_value,
            "registered_at_utc": max(journal.updated_at_utc, now),
            "replayed": False,
        }
    )


class EvidenceRegistrar:
    """The ``register_evidence`` half of the production ``PurposeRegistrar`` (plan
    4.6): ``RUN_EVIDENCE`` links for ``RUN`` owners, the write-once
    ``stderr_artifact_id`` enrichment for a stderr capture under an ``INVOCATION``
    correlation, the sanitized-manifest and validation-result evidence links, and
    the ``STDERR_EVIDENCE_LINKED`` fact; it never reads or writes ``engine_runs``.
    ``register_result`` is refused: the RESULT branch is ``ResultRegistrar``'s.
    ``qualify_evidence`` answers the canonical contract of the ruling of
    2026-11-09 over the facts a transaction of ``transactions`` reads (see the
    module docstring); composed without ``transactions`` it answers no contract,
    so every text evidence keeps the whole-content protection."""

    __slots__ = ("_auditor", "_clock", "_remembered", "_transactions")

    def __init__(
        self,
        auditor: FinalizationAuditor,
        clock: Clock,
        *,
        remembered: dict[str, str] | None = None,
        transactions: Callable[[], ConclusionTransaction] | None = None,
    ) -> None:
        self._auditor = auditor
        self._clock = clock
        #: ``invocation_id -> sanitized hash`` the composition remembered in this
        #: process (``ResultRegistrar.remember``) or the canonical qualification
        #: established against the stored row; the ``run_manifests`` row is
        #: consulted first and is the durable source after a success.
        self._remembered: dict[str, str] = {} if remembered is None else remembered
        #: The short read-only transactions of the canonical fact checks.
        self._transactions = transactions

    def qualify_evidence(
        self, candidate: CandidateArtifact, records: tuple[bytes, ...]
    ) -> Result[CanonicalQualification | MISSING]:  # type: ignore[valid-type]
        """The plan 4.6 canonical contract (the ruling of 2026-11-09):
        ``Success(MISSING)`` when no contract governs the candidate or its records
        are not the producer's model, the qualification when they are the model
        and agree with the authoritative facts, the refusal when they are the
        model but disagree. The facts are read in one short transaction."""
        now = self._clock.now_utc()
        contract = _CANONICAL_CONTRACTS.get(candidate.artifact_kind)
        transactions = self._transactions
        if (
            contract is None
            or transactions is None
            or candidate.producer_kind is not _P.CORE
            or candidate.finalization_purpose is not _F.EVIDENCE
        ):
            return _absent()
        owner = candidate.owner
        ids = _run_ids(owner)

        def disagrees(subject: str) -> Failure:
            return artifact_failure(
                ARTIFACT_VALIDATION_FAILED,
                message=(
                    f"canonical {candidate.artifact_kind} evidence disagrees with "
                    f"its {subject}"
                ),
                now_utc=now,
                **ids,
            )

        if candidate.source_role is not contract.role or not isinstance(
            owner, contract.owners
        ):
            return disagrees("owner")
        correlation_kind, correlation_id, leaf = _staging_correlation(candidate)
        if correlation_kind != contract.correlation_kind or leaf != contract.leaf:
            return disagrees("correlation")
        check = _CONTRACT_CHECKS[candidate.artifact_kind]
        transaction = transactions()
        try:
            qualified = check(transaction, owner, correlation_id, records, disagrees)
        finally:
            transaction.rollback()
        if qualified is None:
            return _absent()
        if isinstance(qualified, Failure):
            return qualified
        if qualified.sanitized_hash is not None:
            # Established against the stored row: the registration links that
            # row to the reference under this hash (plan 4.6) even when no
            # conclusion of this process remembered it.
            self._remembered[correlation_id] = qualified.sanitized_hash
        return Success[Any](
            outcome="SUCCESS",
            value=CanonicalQualification(
                records=len(records), uncontrolled_strings=qualified.uncontrolled
            ),
        )

    def register_result(
        self,
        transaction: RegistrationUnitOfWork,
        journal: FinalizationJournalEntry,
        refs: tuple[ArtifactRef, ...],
        facts: ResultLeaseFacts,
    ) -> Result[ResultRegistration]:
        del transaction, refs, facts
        return _invariant(
            f"the evidence registrar registers no RESULT finalization "
            f"({journal.finalization_id})",
            now=self._clock.now_utc(),
        )

    def register_evidence(
        self,
        transaction: RegistrationUnitOfWork,
        journal: FinalizationJournalEntry,
        refs: tuple[ArtifactRef, ...],
    ) -> Result[None]:
        now = self._clock.now_utc()
        owner = journal.owner
        correlation = journal.correlation
        invocation_id = (
            correlation.correlation_id
            if isinstance(correlation, EvidenceCorrelation)
            and correlation.kind == "INVOCATION"
            else None
        )
        for ref in refs:
            if isinstance(owner, RunArtifactOwner):
                linked = transaction.run_artifacts.link(
                    _RunArtifactLink(
                        run_id=owner.run_id,
                        artifact_id=ref.artifact_id,
                        link_role=RUN_EVIDENCE,
                        experiment_id=owner.experiment_id,
                        run_manifest_id=MISSING,
                    )
                )
                if isinstance(linked, Failure):
                    return linked
            if invocation_id is None:
                continue
            if ref.artifact_kind == STDERR_KIND:
                enriched = self._enrich_stderr(transaction, invocation_id, ref, now)
                if isinstance(enriched, Failure):
                    return enriched
            elif ref.artifact_kind == SANITIZED_MANIFEST_KIND:
                linked_manifest = self._link_sanitized_manifest(
                    transaction, owner, invocation_id, ref
                )
                if isinstance(linked_manifest, Failure):
                    return linked_manifest
            elif ref.artifact_kind == VALIDATION_RESULT_KIND:
                linked_result = transaction.validation_results.link_evidence(
                    invocation_id, ref.artifact_id
                )
                if isinstance(linked_result, Failure):
                    return linked_result
        return _none()

    def _enrich_stderr(
        self,
        transaction: RegistrationUnitOfWork,
        invocation_id: str,
        ref: ArtifactRef,
        now: datetime,
    ) -> Result[None]:
        loaded = transaction.command_invocations.get(invocation_id)
        if isinstance(loaded, Failure):
            return loaded
        stored = loaded.value
        if isinstance(stored.stderr_artifact_id, str):
            return _none()  # write-once: the first evidence reference stands
        payload = stored.model_dump(mode="python")
        payload["stderr_artifact_id"] = ref.artifact_id
        payload["revision"] = stored.revision + 1
        payload["updated_at_utc"] = max(stored.updated_at_utc, now)
        try:
            replacement = CommandInvocationRecord.model_validate(payload)
            assert_write_once_enrichment(stored, replacement)
        except (ValueError, CommandInvocationRuleViolation):
            return _invariant(
                f"invocation {invocation_id} admits no stderr enrichment: the "
                "replacement record or enrichment does not validate",
                now=now,
                invocation_id=invocation_id,
            )
        swapped = transaction.command_invocations.compare_and_swap(
            stored.revision, replacement
        )
        if isinstance(swapped, Failure):
            return swapped
        ids: dict[str, Any] = {"invocation_id": invocation_id}
        if isinstance(stored.run_id, str) and isinstance(ref.owner, RunArtifactOwner):
            ids["run_id"] = stored.run_id
            ids["experiment_id"] = ref.owner.experiment_id
        return self._auditor.append(
            transaction,
            AuditFact(
                action="STDERR_EVIDENCE_LINKED",
                outcome="SUCCEEDED",
                correlation_id=invocation_id,
                artifact_id=ref.artifact_id,
                details={"kind": STDERR_KIND},
                **ids,
            ),
        )

    def _link_sanitized_manifest(
        self,
        transaction: RegistrationUnitOfWork,
        owner: ArtifactOwnerRef,
        invocation_id: str,
        ref: ArtifactRef,
    ) -> Result[None]:
        """Link the sanitized row to its evidence reference. The sanitized hash
        is read from the run's ``run_manifests`` row when the run succeeded (the
        durable source, valid across restarts) and otherwise from the memo the
        composition filled for this process; without either the row stays
        unlinked and the registration proceeds."""
        sanitized_hash: str | None = None
        if isinstance(owner, RunArtifactOwner):
            manifest = transaction.run_manifests.get(owner.run_id)
            if isinstance(manifest, Failure):
                return manifest
            facts = manifest.value
            if not _is_missing(facts) and facts.run_invocation_id == invocation_id:
                sanitized_hash = facts.sanitized_adapter_result_manifest_hash
        if sanitized_hash is None:
            sanitized_hash = self._remembered.get(invocation_id)
        if sanitized_hash is None:
            return _none()
        found = transaction.sanitized_manifests.get(sanitized_hash)
        if isinstance(found, Failure):
            return found
        stored = found.value
        if _is_missing(stored) or isinstance(stored.evidence_artifact_id, str):
            return _none()
        return transaction.sanitized_manifests.link_evidence(
            sanitized_hash, ref.artifact_id
        )


class ResultRegistrar:
    """The production ``PurposeRegistrar`` (plan 4.4 ``register_result``): inside
    the finalizer's open T3 and in reading 11's trigger order -- the sanitized
    facts, the artifact manifests, the staged and recorded references, the
    ``RunManifest`` and its row, the member links, the run compare-and-swap
    ``RUNNING -> SUCCEEDED*`` at the journal's stored post-snapshot revision, and
    the ``RUN_MANIFEST_REGISTERED`` and ``RUN_SUCCEEDED`` facts. ``register_evidence``
    delegates to ``EvidenceRegistrar``. ``remember`` hands the registrar a
    sanitized manifest the row store may not hold yet (the recovery validator's
    regenerated representation); the stored row is otherwise authoritative."""

    __slots__ = ("_auditor", "_by_invocation", "_clock", "_evidence", "_remembered")

    def __init__(
        self,
        auditor: FinalizationAuditor,
        clock: Clock,
        *,
        transactions: Callable[[], ConclusionTransaction] | None = None,
    ) -> None:
        self._auditor = auditor
        self._clock = clock
        self._remembered: dict[str, SanitizedAdapterResultManifest] = {}
        self._by_invocation: dict[str, str] = {}
        self._evidence = EvidenceRegistrar(
            auditor,
            clock,
            remembered=self._by_invocation,
            transactions=transactions,
        )

    def qualify_evidence(
        self, candidate: CandidateArtifact, records: tuple[bytes, ...]
    ) -> Result[CanonicalQualification | MISSING]:  # type: ignore[valid-type]
        """The canonical contract of the ruling of 2026-11-09, the evidence
        registrar's (the finalizer and the reconciler consult it through this
        registrar)."""
        return self._evidence.qualify_evidence(candidate, records)

    def remember(self, sanitized: SanitizedAdapterResultManifest) -> None:
        """Hand the registrar a sanitized manifest the row store may not hold yet
        (the recovery validator's regenerated representation, the conclusion's
        verdict) and index its hash by invocation for the evidence link."""
        sanitized_hash = sanitized.sanitized_adapter_result_manifest_hash
        self._remembered[sanitized_hash] = sanitized
        self._by_invocation[sanitized.invocation_id] = sanitized_hash

    def register_evidence(
        self,
        transaction: RegistrationUnitOfWork,
        journal: FinalizationJournalEntry,
        refs: tuple[ArtifactRef, ...],
    ) -> Result[None]:
        return self._evidence.register_evidence(transaction, journal, refs)

    def register_result(
        self,
        transaction: RegistrationUnitOfWork,
        journal: FinalizationJournalEntry,
        refs: tuple[ArtifactRef, ...],
        facts: ResultLeaseFacts,
    ) -> Result[ResultRegistration]:
        now = self._clock.now_utc()
        owner = journal.owner
        if (
            journal.finalization_purpose is not _F.RESULT
            or not isinstance(owner, RunArtifactOwner)
            or not isinstance(owner.invocation_id, str)
            or not isinstance(journal.expected_run_revision, int)
            or not isinstance(journal.sanitized_adapter_result_manifest_hash, str)
        ):
            return _invariant(
                f"journal {journal.finalization_id} is not a RESULT journal of a RUN "
                "owner with its invocation",
                now=now,
            )
        ids = {
            "experiment_id": owner.experiment_id,
            "run_id": owner.run_id,
            "invocation_id": owner.invocation_id,
        }
        sanitized = self._sanitized(transaction, journal, now)
        if isinstance(sanitized, Failure):
            return sanitized
        manifest_shape = self._check_sanitized(sanitized.value, journal, facts, now)
        if manifest_shape is not None:
            return manifest_shape
        if not refs:
            return _invariant(
                "a RESULT registration needs at least one reference", now=now, **ids
            )
        ordered = tuple(sorted(refs, key=lambda ref: ref.artifact_id))
        manifests: list[ArtifactManifest] = []
        candidates: dict[str, CandidateArtifact] = {}
        for ref in ordered:
            loaded = transaction.candidate_artifacts.get(
                ref.source_candidate_artifact_id
            )
            if isinstance(loaded, Failure):
                return loaded
            candidates[ref.artifact_id] = loaded.value
            manifests.append(
                _artifact_manifest(
                    ref,
                    loaded.value,
                    source_adapter_manifest_id=sanitized.value.adapter_manifest_id,
                )
            )
        if set(sanitized.value.candidate_artifact_ids) != {
            candidate.candidate_artifact_id for candidate in candidates.values()
        }:
            return _invariant(
                "the references do not cover the sanitized manifest's candidates",
                now=now,
                **ids,
            )
        for ref, manifest in zip(ordered, manifests, strict=True):
            staged = transaction.artifact_refs.stage_reference(ref, manifest)
            if isinstance(staged, Failure):
                return staged
        category = facts.process_exit_category
        if not isinstance(category, ProcessExitCategory):
            return _invariant(
                f"invocation {owner.invocation_id} has no captured exit category",
                now=now,
                **ids,
            )
        invocation = transaction.command_invocations.get(owner.invocation_id)
        if isinstance(invocation, Failure):
            return invocation
        diagnostic_ids = set(invocation.value.diagnostic_ids)
        for candidate in candidates.values():
            diagnostic_ids.update(
                observation.diagnostic_id
                for observation in candidate.validation_observations
                if isinstance(observation.diagnostic_id, str)
            )
        first_ref = min(
            ordered, key=lambda ref: ref.source_candidate_artifact_id
        ).artifact_id
        metrics = tuple(
            _metric_value(metric, first_ref)
            for metric in sanitized.value.candidate_metrics
        )
        try:
            run_manifest = _run_manifest(
                sanitized.value,
                owner,
                refs=ordered,
                metrics=metrics,
                diagnostics=tuple(sorted(diagnostic_ids)),
                process_exit_category=category,
            )
        except ValueError:
            return _invariant(
                "the run manifest built for the registration does not validate",
                now=now,
                **ids,
            )
        # The result restates the references in the journal's observed order (the
        # finalizer hands them in that order), so the stored replay of RC-6 --
        # rebuilt from ``observed`` -- equals the first answer field for field.
        result = _finalization_result(
            journal,
            refs,
            now,
            run_manifest_id=run_manifest.manifest_id,
            run_manifest_hash_value=run_manifest.run_manifest_hash,
        )
        recorded = transaction.artifact_refs.record_finalization(result)
        if isinstance(recorded, Failure):
            return recorded
        added = transaction.run_manifests.add(
            _RunManifestFacts(
                manifest_id=run_manifest.manifest_id,
                run_id=run_manifest.run_id,
                experiment_id=run_manifest.experiment_id,
                run_invocation_id=run_manifest.run_invocation_id,
                attempt_token_hash=run_manifest.attempt_token_hash,
                sanitized_adapter_result_manifest_hash=(
                    run_manifest.sanitized_adapter_result_manifest_hash
                ),
                semantic_status=run_manifest.semantic_status,
                process_exit_category=run_manifest.process_exit_category.value,
                manifest_json=canonical_json_text(run_manifest),
                run_manifest_hash=run_manifest.run_manifest_hash,
                registered_at_utc=now,
            )
        )
        if isinstance(added, Failure):
            return added
        for ref in recorded.value:
            linked = transaction.run_artifacts.link(
                _RunArtifactLink(
                    run_id=owner.run_id,
                    artifact_id=ref.artifact_id,
                    link_role=RESULT_MANIFEST_MEMBER,
                    experiment_id=owner.experiment_id,
                    run_manifest_id=run_manifest.manifest_id,
                )
            )
            if isinstance(linked, Failure):
                return linked
        swapped = self._swap_run_to_success(
            transaction, journal, sanitized.value.semantic_status, now
        )
        if isinstance(swapped, Failure):
            return swapped
        for action, details in (
            (
                "RUN_MANIFEST_REGISTERED",
                {"references": len(recorded.value), "metrics": len(metrics)},
            ),
            ("RUN_SUCCEEDED", {"semantic_status": run_manifest.semantic_status}),
        ):
            audited = self._auditor.append(
                transaction,
                AuditFact(
                    action=action,
                    outcome="SUCCEEDED",
                    correlation_id=journal.finalization_id,
                    details=cast("Mapping[str, DiagnosticDetailValue]", details),
                    **ids,
                ),
            )
            if isinstance(audited, Failure):
                return audited
        return Success[InstanceOf[ResultRegistration]](
            outcome="SUCCESS",
            value=ResultRegistration(
                run_manifest_id=run_manifest.manifest_id,
                run_manifest_hash=run_manifest.run_manifest_hash,
                refs=recorded.value,
                manifests=tuple(manifests),
            ),
        )

    def _sanitized(
        self,
        transaction: RegistrationUnitOfWork,
        journal: FinalizationJournalEntry,
        now: datetime,
    ) -> Result[SanitizedAdapterResultManifest]:
        sanitized_hash = str(journal.sanitized_adapter_result_manifest_hash)
        found = transaction.sanitized_manifests.get(sanitized_hash)
        if isinstance(found, Failure):
            return found
        stored = found.value
        if not _is_missing(stored):
            try:
                manifest = SanitizedAdapterResultManifest.model_validate_json(
                    stored.manifest_json
                )
            except ValueError:
                # Reading 7: the parse failure is translated to a fixed, bounded
                # reason; neither the exception text nor the stored payload
                # enters a durable diagnostic.
                return _invariant(
                    "the stored sanitized manifest does not validate as a "
                    "sanitized adapter result manifest",
                    now=now,
                )
            return Success[SanitizedAdapterResultManifest](
                outcome="SUCCESS", value=manifest
            )
        remembered = self._remembered.get(sanitized_hash)
        if remembered is None:
            return _invariant(
                f"no sanitized manifest {sanitized_hash} is recorded for the "
                "finalization",
                now=now,
            )
        added = transaction.sanitized_manifests.add(_sanitized_facts(remembered, now))
        if isinstance(added, Failure):
            return added
        return Success[SanitizedAdapterResultManifest](
            outcome="SUCCESS", value=remembered
        )

    @staticmethod
    def _check_sanitized(
        sanitized: SanitizedAdapterResultManifest,
        journal: FinalizationJournalEntry,
        facts: ResultLeaseFacts,
        now: datetime,
    ) -> Failure | None:
        expectations = (
            ("run_id", sanitized.run_id, journal.run_id),
            ("run_invocation_id", sanitized.invocation_id, journal.run_invocation_id),
            (
                "attempt_token_hash",
                sanitized.attempt_token_hash,
                journal.attempt_token_hash,
            ),
            (
                "attempt_token_hash",
                sanitized.attempt_token_hash,
                facts.attempt_token_hash,
            ),
            (
                "source_adapter_result_manifest_hash",
                sanitized.source_adapter_result_manifest_hash,
                journal.source_adapter_result_manifest_hash,
            ),
        )
        mismatched = [
            name for name, declared, stored in expectations if declared != stored
        ]
        if mismatched:
            return _invariant(
                "the sanitized manifest disagrees with the journal on "
                + ", ".join(mismatched),
                now=now,
            )
        if sanitized.semantic_status not in _SUCCESS_STATE_OF_STATUS:
            return _invariant(
                f"a {sanitized.semantic_status.value} manifest registers no RESULT",
                now=now,
            )
        if set(sanitized.candidate_artifact_ids) != set(journal.candidate_artifact_ids):
            return _invariant(
                "the journal's candidates differ from the sanitized manifest's", now=now
            )
        return None

    @staticmethod
    def _swap_run_to_success(
        transaction: RegistrationUnitOfWork,
        journal: FinalizationJournalEntry,
        status: SemanticStatus,
        now: datetime,
    ) -> Result[EngineRunRecord]:
        run_id = str(journal.run_id)
        expected = journal.expected_run_revision
        if not isinstance(expected, int):
            return _invariant(
                "a RESULT journal carries its expected run revision", now=now
            )
        loaded = transaction.engine_runs.get(run_id)
        if isinstance(loaded, Failure):
            return loaded
        run = loaded.value
        if run.state is not EngineRunState.RUNNING or run.revision != expected:
            return _conflict(
                f"run {run_id} is at revision {run.revision} ({run.state.value}), "
                f"not the journal's expected revision {expected}",
                now=now,
                run=run,
            )
        payload = run.model_dump(mode="python")
        payload["state"] = _SUCCESS_STATE_OF_STATUS[status]
        payload["revision"] = expected + 1
        payload["updated_at_utc"] = max(run.updated_at_utc, now)
        try:
            replacement = EngineRunRecord.model_validate(payload)
            assert_run_transition(run, replacement, owner=RunEdgeOwner.GENERIC)
        except (ValueError, EngineRunRuleViolation):
            return _invariant(
                f"run {run_id} admits no success write: the replacement record or "
                "transition does not validate",
                now=now,
                experiment_id=run.experiment_id,
                run_id=run_id,
            )
        # The expected revision is the journal's stored post-snapshot revision,
        # compared directly (the Task 6 contract): a terminal winner that moved
        # the run loses this swap and the finalizer abandons the journal.
        return transaction.engine_runs.compare_and_swap(expected, replacement)


def _run_manifest(
    sanitized: SanitizedAdapterResultManifest,
    owner: RunArtifactOwner,
    *,
    refs: tuple[ArtifactRef, ...],
    metrics: tuple[MetricValue, ...],
    diagnostics: tuple[str, ...],
    process_exit_category: ProcessExitCategory,
) -> RunManifest:
    invocation_id = str(owner.invocation_id)
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "protocol_version": "1.0.0",
        "manifest_id": run_manifest_id_for(owner.run_id, invocation_id),
        "experiment_id": owner.experiment_id,
        "run_id": owner.run_id,
        "run_invocation_id": invocation_id,
        "attempt_token_hash": sanitized.attempt_token_hash,
        "sanitized_adapter_result_manifest_hash": (
            sanitized.sanitized_adapter_result_manifest_hash
        ),
        "semantic_status": sanitized.semantic_status.value,
        "process_exit_category": process_exit_category,
        "started_at_utc": sanitized.started_at_utc,
        "completed_at_utc": sanitized.completed_at_utc,
        "provenance": sanitized.provenance,
        "artifact_refs": refs,
        "metrics": metrics,
        "diagnostics": diagnostics,
        "warnings": sanitized.warnings,
        "approximations": sanitized.approximations,
        "run_manifest_hash": "0" * 64,
    }
    draft = RunManifest.model_construct(**payload)
    payload["run_manifest_hash"] = run_manifest_hash(draft)
    return RunManifest.model_validate(payload)


# --------------------------------------------------------------------------
# The production recovery validator (plan 4.1, 29.3)
# --------------------------------------------------------------------------


class ResultRecoveryValidator:
    """The production ``ResultRecoveryValidator`` (specification 29.3) over the
    temporary result manifest of one ``RUN`` root; see the module docstring."""

    __slots__ = (
        "_clock",
        "_hasher",
        "_negotiated_versions",
        "_registrar",
        "_timeout_seconds",
        "_unit_of_work",
    )

    def __init__(
        self,
        *,
        unit_of_work: ConclusionUnitOfWork,
        hasher: ContentHasher,
        negotiated_versions: NegotiatedVersions,
        finalization_timeout_seconds: int,
        clock: Clock,
        registrar: ResultRegistrar | None = None,
    ) -> None:
        if type(finalization_timeout_seconds) is not int or not (
            1 <= finalization_timeout_seconds <= 3600
        ):
            raise ValueError("finalization_timeout_seconds must be within 1..3600")
        self._unit_of_work = unit_of_work
        self._hasher = hasher
        self._negotiated_versions = negotiated_versions
        self._timeout_seconds = finalization_timeout_seconds
        self._clock = clock
        self._registrar = registrar

    def validate_temporary_manifest(
        self,
        roots: CommandRootPaths,
        token: AttemptTokenMaterial | MISSING,  # type: ignore[valid-type]
        candidates: tuple[CandidateArtifact, ...],
    ) -> Result[ResultRecoveryFacts]:
        now = self._clock.now_utc()
        if (
            not isinstance(roots, CommandRootPaths)
            or not isinstance(roots.work_dir, Path)
            or not isinstance(roots.result_path, Path)
        ):
            return _invariant("RESULT recovery requires a RUN root", now=now)
        owner = self._owner_of(candidates, now)
        if isinstance(owner, Failure):
            return owner
        invocation_id = str(owner.value.invocation_id)
        run_id = owner.value.run_id
        experiment_id = owner.value.experiment_id
        loaded = self._load(run_id, invocation_id, experiment_id)
        if isinstance(loaded, Failure):
            return loaded
        run, invocation, experiment, events = loaded
        if (
            invocation.state is not CommandInvocationState.EXITED
            or invocation.command_kind is not CommandKind.RUN
            or invocation.run_id != run_id
            or _is_missing(invocation.process_exit_category)
        ):
            return artifact_failure(
                ARTIFACT_RESULT_MANIFEST_INVALID,
                message=(
                    "the run-command invocation is not durably EXITED with captured "
                    "exit facts; lost exit facts are never reconstructed"
                ),
                now_utc=now,
                experiment_id=experiment_id,
                run_id=run_id,
                invocation_id=invocation_id,
            )
        # 29.3: the raw token is hashed from the surviving request material and
        # compared with the durable hash; no durable token is loaded.
        if not isinstance(token, AttemptTokenMaterial) or (
            token.run_id != run_id
            or attempt_token_hash(token.attempt_token) != run.attempt_token_hash
        ):
            return stage6_failure(
                PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
                "the surviving request material does not prove the attempt's identity",
                source_component=SOURCE_COMPONENT,
                timestamp_utc=now,
                experiment_id=experiment_id,
                run_id=run_id,
                invocation_id=invocation_id,
            )
        parsed = self._parse_manifest(
            roots, token, now, experiment_id, run_id, invocation_id
        )
        if isinstance(parsed, Failure):
            return parsed
        summary = InvocationEventLedger.from_events(events).summary()
        observed = observe_candidates(
            roots.work_dir,
            declared_candidate_paths(summary, parsed.value),
            token,
            hasher=self._hasher,
            clock=self._clock,
        )
        if isinstance(observed, Failure):
            return observed
        slot = next(
            (
                entry
                for entry in (experiment.slot_compatibility or ())
                if not _is_missing(experiment.slot_compatibility)
                and entry.logical_slot_id == run.logical_slot_id
            ),
            None,
        )
        if slot is None:
            return _invariant(
                f"experiment {run.experiment_id} freezes no compatibility entry for "
                f"slot {run.logical_slot_id}",
                now=now,
                experiment_id=experiment_id,
                run_id=run_id,
                invocation_id=invocation_id,
            )
        try:
            reconciliation = reconcile_run(
                invocation,
                run,
                experiment,
                slot,
                parsed.value,
                summary,
                observed.value,
                self._negotiated_versions,
                MISSING,
                now_utc=now,
            )
        except ReconciliationRuleViolation as violation:
            return _invariant(
                str(violation),
                now=now,
                experiment_id=experiment_id,
                run_id=run_id,
                invocation_id=invocation_id,
            )
        if (
            reconciliation.verdict
            is not ReconciliationVerdict.RESULT_FINALIZATION_ELIGIBLE
        ):
            primary = reconciliation.primary_diagnostic
            if isinstance(primary, Diagnostic):
                return Failure(outcome="FAILURE", diagnostics=(primary,))
            return artifact_failure(
                ARTIFACT_RESULT_MANIFEST_INVALID,
                message=f"recovery reconciled to {reconciliation.verdict.value}",
                now_utc=now,
                experiment_id=experiment_id,
                run_id=run_id,
                invocation_id=invocation_id,
            )
        sanitized = reconciliation.sanitized_manifest
        if not isinstance(sanitized, SanitizedAdapterResultManifest):
            return _invariant(
                "an eligible verdict carries its sanitized manifest", now=now
            )
        if set(sanitized.candidate_artifact_ids) != {
            candidate.candidate_artifact_id for candidate in candidates
        }:
            return artifact_failure(
                ARTIFACT_VALIDATION_FAILED,
                message=(
                    "the recoverable candidates differ from the manifest's declarations"
                ),
                now_utc=now,
                experiment_id=experiment_id,
                run_id=run_id,
                invocation_id=invocation_id,
            )
        if self._registrar is not None:
            self._registrar.remember(sanitized)
        observations = tuple(
            CandidateObservationFacts(
                candidate_artifact_id=candidate_artifact_id_for(
                    run_id, invocation_id, observation.relative_path
                ),
                sha256=observation.observed_sha256,
                size_bytes=observation.observed_size_bytes,
            )
            for observation in observed.value
        )
        return Success[InstanceOf[ResultRecoveryFacts]](
            outcome="SUCCESS",
            value=ResultRecoveryFacts(
                run_id=run_id,
                run_invocation_id=invocation_id,
                experiment_id=owner.value.experiment_id,
                attempt_token_hash=run.attempt_token_hash,
                source_adapter_result_manifest_hash=parsed.value.source_hash,
                sanitized_adapter_result_manifest_hash=(
                    sanitized.sanitized_adapter_result_manifest_hash
                ),
                semantic_status=cast("Any", sanitized.semantic_status.value),
                finalization_timeout_seconds=self._timeout_seconds,
                candidate_observations=observations,
            ),
        )

    @staticmethod
    def _owner_of(
        candidates: tuple[CandidateArtifact, ...], now: datetime
    ) -> Result[RunArtifactOwner]:
        if not candidates:
            return artifact_failure(
                ARTIFACT_VALIDATION_FAILED,
                message="RESULT recovery needs at least one candidate",
                now_utc=now,
            )
        owner = candidates[0].owner
        if not isinstance(owner, RunArtifactOwner) or not isinstance(
            owner.invocation_id, str
        ):
            return artifact_failure(
                ARTIFACT_VALIDATION_FAILED,
                message="a RESULT candidate is RUN-owned with its invocation",
                now_utc=now,
            )
        owner_hash = artifact_owner_hash(owner)
        for candidate in candidates:
            if (
                candidate.finalization_purpose is not _F.RESULT
                or candidate.producer_kind is not _P.ADAPTER
                or artifact_owner_hash(candidate.owner) != owner_hash
            ):
                return artifact_failure(
                    ARTIFACT_VALIDATION_FAILED,
                    message=(
                        "every recoverable candidate is an adapter-produced RESULT "
                        "candidate of the same run and invocation"
                    ),
                    now_utc=now,
                    experiment_id=owner.experiment_id,
                    run_id=owner.run_id,
                    invocation_id=owner.invocation_id,
                )
        return Success[RunArtifactOwner](outcome="SUCCESS", value=owner)

    def _load(
        self, run_id: str, invocation_id: str, experiment_id: str
    ) -> (
        tuple[EngineRunRecord, CommandInvocationRecord, Any, tuple[RunEvent, ...]]
        | Failure
    ):
        transaction = self._unit_of_work.begin()
        try:
            run = transaction.engine_runs.get(run_id)
            if isinstance(run, Failure):
                return run
            invocation = transaction.command_invocations.get(invocation_id)
            if isinstance(invocation, Failure):
                return invocation
            experiment = transaction.experiments.get(experiment_id)
            if isinstance(experiment, Failure):
                return experiment
            events = transaction.engine_runs.list_events(invocation_id)
            if isinstance(events, Failure):
                return events
        finally:
            transaction.rollback()
        return run.value, invocation.value, experiment.value, events.value

    def _parse_manifest(
        self,
        roots: CommandRootPaths,
        token: AttemptTokenMaterial,
        now: datetime,
        experiment_id: str,
        run_id: str,
        invocation_id: str,
    ) -> Result[ManifestParse]:
        work_dir = roots.work_dir
        if not isinstance(work_dir, Path):
            return _invariant("RESULT recovery requires a RUN root", now=now)
        confined = confine_candidate_path(
            work_dir, RESULT_MANIFEST_RELATIVE_PATH, now_utc=now
        )
        if isinstance(confined, Failure):
            return artifact_failure(
                ARTIFACT_RESULT_MANIFEST_INVALID,
                message=(
                    "the temporary result manifest is absent from the assigned "
                    "directory or unconfined: " + confined.diagnostics[0].message
                ),
                now_utc=now,
                experiment_id=experiment_id,
                run_id=run_id,
                invocation_id=invocation_id,
            )
        size = confined.value.identity.st_size
        if size > MAX_RESULT_MANIFEST_BYTES:
            return artifact_failure(
                ARTIFACT_RESULT_MANIFEST_INVALID,
                message="the temporary result manifest exceeds the manifest ceiling",
                now_utc=now,
                experiment_id=experiment_id,
                run_id=run_id,
                invocation_id=invocation_id,
            )
        data = read_confined(confined.value, limit=size, now_utc=now)
        if isinstance(data, Failure):
            return data
        parsed = parse_result_manifest(
            data.value, max_bytes=MAX_RESULT_MANIFEST_BYTES, token=token.attempt_token
        )
        return Success[ManifestParse](outcome="SUCCESS", value=parsed)


# --------------------------------------------------------------------------
# The replay wrapper (reading 24) and the run failure path (plan 4.4)
# --------------------------------------------------------------------------


def _stored_conclusion(
    transaction: ConclusionTransaction,
    run: EngineRunRecord,
    invocation_id: str,
    now: datetime,
) -> Result[CommandConclusion]:
    invocation = transaction.command_invocations.get(invocation_id)
    if isinstance(invocation, Failure):
        return invocation
    facts = transaction.run_manifests.get(run.run_id)
    if isinstance(facts, Failure):
        return facts
    if _is_missing(facts.value):
        return _invariant(
            f"run {run.run_id} is {run.state.value} without a run manifest",
            now=now,
            experiment_id=run.experiment_id,
            run_id=run.run_id,
        )
    manifest = RunManifest.model_validate_json(facts.value.manifest_json)
    links = transaction.run_artifacts.list_for_run(run.run_id)
    if isinstance(links, Failure):
        return links
    result_refs: list[ArtifactRef] = []
    evidence_refs: list[ArtifactRef] = []
    for link in links.value:
        ref = transaction.artifact_refs.get(link.artifact_id)
        if isinstance(ref, Failure):
            return ref
        if link.link_role == RESULT_MANIFEST_MEMBER:
            result_refs.append(ref.value)
        else:
            evidence_refs.append(ref.value)
    return Success[InstanceOf[CommandConclusion]](
        outcome="SUCCESS",
        value=CommandConclusion(
            run=run,
            invocation=invocation.value,
            run_manifest=manifest,
            result_refs=tuple(sorted(result_refs, key=lambda ref: ref.artifact_id)),
            evidence_refs=tuple(sorted(evidence_refs, key=lambda ref: ref.artifact_id)),
            replayed=True,
        ),
    )


def semantic_outcome_or_replay(
    request: SemanticOutcomeRequest,
    *,
    unit_of_work: ConclusionUnitOfWork,
    clock: Clock,
) -> Result[ConclusionOutcome]:
    """Reading 24: a run already in a success state answers with its stored
    conclusion (the ``run_manifests`` row, its references and evidence,
    ``replayed=True``) and the Stage 6 operation is not invoked; every other run
    goes through ``apply_command_semantic_outcome`` unchanged."""
    now = clock.now_utc()
    transaction = unit_of_work.begin()
    try:
        loaded = transaction.engine_runs.get(request.run_id)
        if isinstance(loaded, Failure):
            return loaded
        run = loaded.value
        if run.state in SUCCESS_ENGINE_RUN_STATES:
            stored = _stored_conclusion(transaction, run, request.invocation_id, now)
            if isinstance(stored, Failure):
                return stored
            return Success[ConclusionOutcome](outcome="SUCCESS", value=stored.value)
    finally:
        transaction.rollback()
    applied = apply_command_semantic_outcome(
        request, unit_of_work=unit_of_work, clock=clock
    )
    if isinstance(applied, Failure):
        return applied
    return Success[ConclusionOutcome](outcome="SUCCESS", value=applied.value)


def _invocation_of_root(roots: CommandRootPaths) -> str:
    name = roots.command_root.name
    validate_prefixed_uuid4(name, "inv_")
    return name


def fail_run_for_refusal(
    refusal: Failure,
    *,
    run_id: str,
    expected_run_revision: int,
    roots: CommandRootPaths,
    config: ConclusionConfig,
    unit_of_work: ConclusionUnitOfWork,
    clock: Clock,
) -> Result[None]:
    """Plan 4.4 steps 0 and 3: record the refusal's diagnostic, move the run
    ``RUNNING -> FAILED`` with it as primary through the registration unit of
    work's compare-and-swap guarded by ``assert_run_transition`` (owner
    ``GENERIC``), audit ``RUN_FAILED`` in the same transaction and close the
    token-bearing root's raw bytes (step 5). A run that moved meanwhile is the
    conflict and nothing is written."""
    now = clock.now_utc()
    diagnostic = refusal.diagnostics[0]
    invocation_id = _invocation_of_root(roots)
    transaction = unit_of_work.begin()
    try:
        loaded = transaction.engine_runs.get(run_id)
        if isinstance(loaded, Failure):
            return loaded
        run = loaded.value
        if (
            run.state is not EngineRunState.RUNNING
            or run.revision != expected_run_revision
        ):
            return _conflict(
                f"run {run_id} is at revision {run.revision} ({run.state.value}), not "
                f"RUNNING at revision {expected_run_revision}",
                now=now,
                run=run,
            )
        recorded = transaction.diagnostics_writer.record(diagnostic)
        if isinstance(recorded, Failure):
            return recorded
        payload = run.model_dump(mode="python")
        payload["state"] = EngineRunState.FAILED
        payload["primary_terminal_diagnostic_id"] = diagnostic.diagnostic_id
        payload["revision"] = run.revision + 1
        payload["updated_at_utc"] = max(run.updated_at_utc, now)
        try:
            replacement = EngineRunRecord.model_validate(payload)
            assert_run_transition(run, replacement, owner=RunEdgeOwner.GENERIC)
        except (ValueError, EngineRunRuleViolation):
            return _invariant(
                f"run {run_id} admits no FAILED write: the replacement record or "
                "transition does not validate",
                now=now,
                experiment_id=run.experiment_id,
                run_id=run_id,
                invocation_id=invocation_id,
            )
        swapped = transaction.engine_runs.compare_and_swap(run.revision, replacement)
        if isinstance(swapped, Failure):
            return swapped
        audited = config.auditor.append(
            transaction,
            AuditFact(
                action="RUN_FAILED",
                outcome="FAILED",
                correlation_id=invocation_id,
                experiment_id=run.experiment_id,
                run_id=run_id,
                invocation_id=invocation_id,
                details={"reason": diagnostic.error_code},
            ),
        )
        if isinstance(audited, Failure):
            return audited
        if any(path.exists() for path in roots.raw_byte_paths):
            closed = close_raw_bytes(
                roots,
                store=config.store,
                unit_of_work=transaction,
                auditor=config.auditor,
                correlation=invocation_id,
                clock=clock,
                experiment_id=run.experiment_id,
                run_id=run_id,
                invocation_id=invocation_id,
            )
            if isinstance(closed, Failure):
                return closed
        committed = transaction.commit()
        if isinstance(committed, Failure):
            return committed
    finally:
        transaction.rollback()
    return _none()


# --------------------------------------------------------------------------
# conclude_command and conclude_describe (plan 4.4, 4.6)
# --------------------------------------------------------------------------


def _record_diagnostics(
    unit_of_work: ConclusionUnitOfWork, diagnostics: Sequence[Diagnostic]
) -> Result[None]:
    if not diagnostics:
        return _none()
    transaction = unit_of_work.begin()
    try:
        for diagnostic in diagnostics:
            recorded = transaction.diagnostics_writer.record(diagnostic)
            if isinstance(recorded, Failure):
                return recorded
        committed = transaction.commit()
        if isinstance(committed, Failure):
            return committed
    finally:
        transaction.rollback()
    return _none()


def _refs_of(
    unit_of_work: ConclusionUnitOfWork, artifact_ids: Sequence[str]
) -> Result[tuple[ArtifactRef, ...]]:
    transaction = unit_of_work.begin()
    try:
        refs: list[ArtifactRef] = []
        for artifact_id in artifact_ids:
            ref = transaction.artifact_refs.get(artifact_id)
            if isinstance(ref, Failure):
                return ref
            refs.append(ref.value)
    finally:
        transaction.rollback()
    return Success[tuple[ArtifactRef, ...]](
        outcome="SUCCESS", value=tuple(sorted(refs, key=lambda ref: ref.artifact_id))
    )


def _fresh_run(
    unit_of_work: ConclusionUnitOfWork, run_id: str
) -> Result[EngineRunRecord]:
    transaction = unit_of_work.begin()
    try:
        return transaction.engine_runs.get(run_id)
    finally:
        transaction.rollback()


def _result_journal_exists(
    unit_of_work: ConclusionUnitOfWork, invocation_id: str, source_hash: str
) -> bool:
    transaction = unit_of_work.begin()
    try:
        found = transaction.finalization_journal.find_result_identity(
            invocation_id, source_hash
        )
    finally:
        transaction.rollback()
    return isinstance(found, Success) and isinstance(
        found.value, FinalizationJournalEntry
    )


def _abandoned_result_journal(
    unit_of_work: ConclusionUnitOfWork,
    invocation_id: str,
    source_hash: str,
    reason: str,
) -> Result[bool]:
    """Whether the RESULT journal of this attempt is durably ``ABANDONED`` under
    ``reason`` -- the finalizer's permanent abandonment from phase 3 on -- as
    opposed to a refusal before any lease, which leaves no journal, or a
    storage failure, which leaves the journal open for recovery. A failed read
    is the storage failure, never a silent "not abandoned"."""
    transaction = unit_of_work.begin()
    try:
        found = transaction.finalization_journal.find_result_identity(
            invocation_id, source_hash
        )
    finally:
        transaction.rollback()
    if isinstance(found, Failure):
        return found
    entry = found.value
    abandoned = (
        isinstance(entry, FinalizationJournalEntry)
        and entry.state is FinalizationJournalState.ABANDONED
        and entry.abandon_reason == reason
    )
    return Success[bool](outcome="SUCCESS", value=abandoned)


def _close_terminal_root(
    run: EngineRunRecord,
    invocation_id: str,
    roots: CommandRootPaths,
    *,
    config: ConclusionConfig,
    unit_of_work: ConclusionUnitOfWork,
    clock: Clock,
) -> Result[None]:
    """Plan 4.4 step 5: the phase-6 close for a terminal run that took no RESULT
    lease, in one short transaction; nothing when no raw byte remains."""
    if not any(path.exists() for path in roots.raw_byte_paths):
        return _none()
    transaction = unit_of_work.begin()
    try:
        closed = close_raw_bytes(
            roots,
            store=config.store,
            unit_of_work=transaction,
            auditor=config.auditor,
            correlation=invocation_id,
            clock=clock,
            experiment_id=run.experiment_id,
            run_id=run.run_id,
            invocation_id=invocation_id,
        )
        if isinstance(closed, Failure):
            return closed
        committed = transaction.commit()
        if isinstance(committed, Failure):
            return committed
    finally:
        transaction.rollback()
    return _none()


def _stage_command_evidence(
    outcome: SemanticOutcome,
    command_result: CommandResult,
    owner: RunArtifactOwner,
    *,
    config: ConclusionConfig,
    unit_of_work: ConclusionUnitOfWork,
    clock: Clock,
) -> Result[tuple[CandidateArtifact, ...]]:
    """Plan 4.4 step 2: the core evidence that exists after any outcome."""
    invocation_id = str(owner.invocation_id)
    staged: list[CandidateArtifact] = []
    stderr = command_result.stderr
    if isinstance(stderr, StderrCapture):
        candidate = stderr_evidence(
            stderr,
            owner,
            invocation_id,
            store=config.store,
            unit_of_work=unit_of_work,
            auditor=config.auditor,
            clock=clock,
        )
        if isinstance(candidate, Failure):
            return candidate
        staged.append(candidate.value)
    if command_result.accepted_events:
        candidate = protocol_capture_evidence(
            command_result.accepted_events,
            owner,
            invocation_id,
            store=config.store,
            unit_of_work=unit_of_work,
            clock=clock,
        )
        if isinstance(candidate, Failure):
            return candidate
        staged.append(candidate.value)
    reconciliation = outcome.reconciliation
    if isinstance(reconciliation, SemanticReconciliation):
        sanitized = reconciliation.sanitized_manifest
        if isinstance(sanitized, SanitizedAdapterResultManifest):
            candidate = sanitized_result_manifest_evidence(
                sanitized,
                owner,
                store=config.store,
                unit_of_work=unit_of_work,
                clock=clock,
            )
            if isinstance(candidate, Failure):
                return candidate
            staged.append(candidate.value)
        validation = reconciliation.sanitized_validation_result
        if isinstance(validation, AdapterValidationResult):
            candidate = validation_result_evidence(
                validation,
                owner,
                store=config.store,
                unit_of_work=unit_of_work,
                clock=clock,
            )
            if isinstance(candidate, Failure):
                return candidate
            staged.append(candidate.value)
    return Success[tuple[CandidateArtifact, ...]](
        outcome="SUCCESS", value=tuple(staged)
    )


def _result_request(
    outcome: SemanticOutcome,
    sanitized: SanitizedAdapterResultManifest,
    source_hash: str,
    owner: RunArtifactOwner,
    *,
    timeout_seconds: int,
) -> ResultFinalizationRequest:
    run = outcome.run
    invocation = outcome.invocation
    ids = sanitized.candidate_artifact_ids
    return ResultFinalizationRequest.model_validate(
        {
            "schema_version": "1.0.0",
            "finalization_purpose": "RESULT",
            "owner": owner,
            "experiment_id": run.experiment_id,
            "run_id": run.run_id,
            "run_invocation_id": invocation.invocation_id,
            "expected_run_revision": run.revision,
            "expected_invocation_revision": invocation.revision,
            "attempt_token_hash": run.attempt_token_hash,
            "source_adapter_result_manifest_hash": source_hash,
            "sanitized_adapter_result_manifest_hash": (
                sanitized.sanitized_adapter_result_manifest_hash
            ),
            "semantic_status": sanitized.semantic_status.value,
            "candidate_artifact_ids": ids,
            "candidate_set_hash": candidate_set_hash_for(ids),
            "finalization_timeout_seconds": timeout_seconds,
            "idempotency_key": finalization_identity(
                "RESULT",
                run_id=run.run_id,
                run_invocation_id=invocation.invocation_id,
                attempt_token_hash=run.attempt_token_hash,
                source_adapter_result_manifest_hash=source_hash,
                sanitized_adapter_result_manifest_hash=(
                    sanitized.sanitized_adapter_result_manifest_hash
                ),
            ),
        }
    )


def conclude_command(
    outcome: SemanticOutcome,
    command_result: CommandResult,
    output_parse: ValidationResultParse | ManifestParse | MISSING,  # type: ignore[valid-type]
    protocol_summary: ProtocolEventSummary,
    observations: tuple[CandidateObservation, ...],
    *,
    roots: CommandRootPaths,
    token: AttemptTokenMaterial | MISSING,  # type: ignore[valid-type]
    config: ConclusionConfig,
    unit_of_work: ConclusionUnitOfWork,
    finalizer: ArtifactFinalizer,
    clock: Clock,
) -> Result[CommandConclusion]:
    """Plan 4.4 steps 1 to 5 over one applied ``VALIDATE`` or ``RUN`` outcome;
    see the module docstring. The step-0 ``observations`` are the ones the
    caller's request carried and are never recomputed here (the finalizer's
    phase 1 re-hashes under its own confinement); ``token`` is the frame's
    material, handed to every finalization of this conclusion for its exact
    raw-token scan (the ruling of 2026-11-09) and retained nowhere."""
    del observations  # consumed by the verdict
    invocation = outcome.invocation
    run = outcome.run
    now = clock.now_utc()
    if invocation.command_kind not in _TOKEN_BEARING_KINDS:
        return _invariant(
            "conclude_command concludes a VALIDATE or RUN invocation; a DESCRIBE goes "
            "through conclude_describe",
            now=now,
            invocation_id=invocation.invocation_id,
        )
    if invocation.state is not CommandInvocationState.EXITED:
        return _invariant(
            f"invocation {invocation.invocation_id} is {invocation.state.value}, "
            "not EXITED",
            now=now,
            experiment_id=run.experiment_id,
            run_id=run.run_id,
            invocation_id=invocation.invocation_id,
        )
    reconciliation = outcome.reconciliation
    diagnostics: tuple[Diagnostic, ...] = (
        reconciliation.diagnostics
        if isinstance(reconciliation, SemanticReconciliation)
        else ()
    )
    recorded = _record_diagnostics(unit_of_work, diagnostics)
    if isinstance(recorded, Failure):
        return recorded
    owner = RunArtifactOwner(
        owner_kind="RUN",
        experiment_id=run.experiment_id,
        run_id=run.run_id,
        invocation_id=invocation.invocation_id,
    )
    if invocation.command_kind is CommandKind.RUN:
        registered = register_result_candidates(
            protocol_summary.artifact_declarations,
            owner,
            unit_of_work=unit_of_work,
            clock=clock,
        )
        if isinstance(registered, Failure):
            return registered
    staged = _stage_command_evidence(
        outcome,
        command_result,
        owner,
        config=config,
        unit_of_work=unit_of_work,
        clock=clock,
    )
    if isinstance(staged, Failure):
        return staged
    finalization: FinalizationResult | MISSING = MISSING  # type: ignore[valid-type]
    run_manifest: RunManifest | MISSING = MISSING  # type: ignore[valid-type]
    result_refs: tuple[ArtifactRef, ...] = ()
    eligible = (
        isinstance(reconciliation, SemanticReconciliation)
        and reconciliation.verdict is ReconciliationVerdict.RESULT_FINALIZATION_ELIGIBLE
        and run.state is EngineRunState.RUNNING
        and isinstance(
            reconciliation.sanitized_manifest, SanitizedAdapterResultManifest
        )
        and isinstance(output_parse, ManifestParse)
    )
    sanitized = (
        reconciliation.sanitized_manifest
        if isinstance(reconciliation, SemanticReconciliation)
        else MISSING
    )
    if (
        isinstance(sanitized, SanitizedAdapterResultManifest)
        and config.registrar is not None
    ):
        config.registrar.remember(sanitized)
    if (
        eligible
        and isinstance(sanitized, SanitizedAdapterResultManifest)
        and isinstance(output_parse, ManifestParse)
    ):
        parse = output_parse
        request = _result_request(
            outcome,
            sanitized,
            parse.source_hash,
            owner,
            timeout_seconds=config.finalization_timeout_seconds,
        )
        finalized = _drive(
            finalizer.finalize(request, _NeverCancelled(), token_material=token)
        )
        if isinstance(finalized, Failure):
            code = _code_of(finalized)
            fails_run = code.startswith(_RUN_FAILING_PREFIXES)
            if not fails_run and code == INVARIANT_VIOLATION:
                # 21.2.1: an invariant under which the finalizer abandoned the
                # RESULT journal for good fails the affected run through the
                # same guarded path; a pre-lease invariant (no journal) and a
                # journal another holder owns are returned unchanged below.
                abandoned = _abandoned_result_journal(
                    unit_of_work, invocation.invocation_id, parse.source_hash, code
                )
                if isinstance(abandoned, Failure):
                    return abandoned
                fails_run = abandoned.value
            if fails_run:
                fresh = _fresh_run(unit_of_work, run.run_id)
                if isinstance(fresh, Failure):
                    return fresh
                if fresh.value.state is EngineRunState.RUNNING:
                    failed = fail_run_for_refusal(
                        finalized,
                        run_id=run.run_id,
                        expected_run_revision=fresh.value.revision,
                        roots=roots,
                        config=config,
                        unit_of_work=unit_of_work,
                        clock=clock,
                    )
                    if isinstance(failed, Failure):
                        return failed
            elif code == CONCURRENCY_CONFLICT:
                return finalized
            else:
                closed = _close_after_refusal(
                    run.run_id,
                    invocation.invocation_id,
                    parse.source_hash,
                    roots,
                    config=config,
                    unit_of_work=unit_of_work,
                    clock=clock,
                )
                if isinstance(closed, Failure):
                    return closed
                return finalized
        else:
            finalization = finalized.value
            loaded = _fresh_manifest(unit_of_work, run.run_id, now)
            if isinstance(loaded, Failure):
                return loaded
            run_manifest = loaded.value
            refs = _refs_of(
                unit_of_work,
                [
                    mapping.artifact_id
                    for mapping in finalization.candidate_to_artifact_refs
                ],
            )
            if isinstance(refs, Failure):
                return refs
            result_refs = refs.value
    evidence_refs: tuple[ArtifactRef, ...] = ()
    evidence_failure: Failure | MISSING = MISSING  # type: ignore[valid-type]
    if staged.value:
        evidence = finalize_evidence(
            staged.value,
            _correlation_for(owner, invocation.invocation_id),
            finalizer=finalizer,
            token=token,
        )
        if isinstance(evidence, Failure):
            evidence_failure = evidence  # 29.1: no outcome waits for evidence
        else:
            refs = _refs_of(
                unit_of_work,
                [
                    mapping.artifact_id
                    for mapping in evidence.value.candidate_to_artifact_refs
                ],
            )
            if isinstance(refs, Failure):
                return refs
            evidence_refs = refs.value
    fresh_run = _fresh_run(unit_of_work, run.run_id)
    if isinstance(fresh_run, Failure):
        return fresh_run
    final_run = fresh_run.value
    if final_run.state in TERMINAL_ENGINE_RUN_STATES and not (
        isinstance(output_parse, ManifestParse)
        and _result_journal_exists(
            unit_of_work, invocation.invocation_id, output_parse.source_hash
        )
    ):
        closed = _close_terminal_root(
            final_run,
            invocation.invocation_id,
            roots,
            config=config,
            unit_of_work=unit_of_work,
            clock=clock,
        )
        if isinstance(closed, Failure):
            return closed
    transaction = unit_of_work.begin()
    try:
        fresh_invocation = transaction.command_invocations.get(invocation.invocation_id)
    finally:
        transaction.rollback()
    if isinstance(fresh_invocation, Failure):
        return fresh_invocation
    return Success[InstanceOf[CommandConclusion]](
        outcome="SUCCESS",
        value=CommandConclusion(
            run=final_run,
            invocation=fresh_invocation.value,
            finalization=finalization,
            run_manifest=run_manifest,
            result_refs=result_refs,
            evidence_refs=evidence_refs,
            evidence_failure=evidence_failure,
        ),
    )


def _fresh_manifest(
    unit_of_work: ConclusionUnitOfWork, run_id: str, now: datetime
) -> Result[RunManifest]:
    transaction = unit_of_work.begin()
    try:
        facts = transaction.run_manifests.get(run_id)
    finally:
        transaction.rollback()
    if isinstance(facts, Failure):
        return facts
    if _is_missing(facts.value):
        return _invariant(f"run {run_id} succeeded without a run manifest", now=now)
    return Success[RunManifest](
        outcome="SUCCESS",
        value=RunManifest.model_validate_json(facts.value.manifest_json),
    )


def _close_after_refusal(
    run_id: str,
    invocation_id: str,
    source_hash: str,
    roots: CommandRootPaths,
    *,
    config: ConclusionConfig,
    unit_of_work: ConclusionUnitOfWork,
    clock: Clock,
) -> Result[None]:
    """A lease refused against a run already terminal (RC-1) closes the root
    (plan 4.4 step 5); a run still RUNNING keeps its bytes."""
    fresh = _fresh_run(unit_of_work, run_id)
    if isinstance(fresh, Failure):
        return fresh
    if fresh.value.state not in TERMINAL_ENGINE_RUN_STATES or _result_journal_exists(
        unit_of_work, invocation_id, source_hash
    ):
        return _none()
    return _close_terminal_root(
        fresh.value,
        invocation_id,
        roots,
        config=config,
        unit_of_work=unit_of_work,
        clock=clock,
    )


def conclude_describe(
    command_result: CommandResult,
    descriptor_parse: DescriptorParse | MISSING,  # type: ignore[valid-type]
    reconciliation: SemanticReconciliation,
    *,
    roots: CommandRootPaths,
    config: ConclusionConfig,
    unit_of_work: ConclusionUnitOfWork,
    finalizer: ArtifactFinalizer,
    clock: Clock,
) -> Result[tuple[ArtifactRef, ...]]:
    """Plan 4.6: the ``DESCRIBE`` counterpart of ``conclude_command`` -- the
    describe reconciliation's diagnostics recorded, the descriptor evidence (when
    the parse succeeded) and the ``ADAPTER``-owned stderr evidence staged and
    finalized under the ``INVOCATION`` correlation naming the describe invocation,
    ``stderr_artifact_id`` enriched through the evidence registrar; no run row is
    read or written and no close runs (a describe root carries no token)."""
    del roots  # a DESCRIBE root is never closed here (plan 4.6)
    invocation = command_result.invocation
    now = clock.now_utc()
    if invocation.command_kind is not CommandKind.DESCRIBE:
        return _invariant(
            "conclude_describe concludes a DESCRIBE invocation",
            now=now,
            invocation_id=invocation.invocation_id,
        )
    if invocation.state is not CommandInvocationState.EXITED:
        return _invariant(
            f"invocation {invocation.invocation_id} is {invocation.state.value}, "
            "not EXITED",
            now=now,
            invocation_id=invocation.invocation_id,
        )
    recorded = _record_diagnostics(unit_of_work, reconciliation.diagnostics)
    if isinstance(recorded, Failure):
        return recorded
    owner_payload: dict[str, Any] = {
        "owner_kind": "ADAPTER",
        "adapter_name": invocation.adapter_name,
        "adapter_version": invocation.adapter_version,
    }
    if isinstance(descriptor_parse, DescriptorParse) and not _is_missing(
        descriptor_parse.envelope
    ):
        owner_payload["engine_name"] = descriptor_parse.envelope.engine_name
        owner_payload["engine_version"] = descriptor_parse.envelope.engine_version
    owner = AdapterArtifactOwner.model_validate(owner_payload)
    correlation = _correlation_for(owner, invocation.invocation_id)
    groups: list[CandidateArtifact] = []
    if isinstance(descriptor_parse, DescriptorParse) and not _is_missing(
        descriptor_parse.envelope
    ):
        descriptor = descriptor_evidence(
            descriptor_parse,
            owner,
            invocation.invocation_id,
            store=config.store,
            unit_of_work=unit_of_work,
            clock=clock,
        )
        if isinstance(descriptor, Failure):
            return descriptor
        groups.append(descriptor.value)
    stderr = command_result.stderr
    if isinstance(stderr, StderrCapture):
        capture = stderr_evidence(
            stderr,
            owner,
            invocation.invocation_id,
            store=config.store,
            unit_of_work=unit_of_work,
            auditor=config.auditor,
            clock=clock,
        )
        if isinstance(capture, Failure):
            return capture
        groups.append(capture.value)
    artifact_ids: list[str] = []
    for candidate in groups:  # one request per role (plan 4.6: two producers)
        finalized = finalize_evidence((candidate,), correlation, finalizer=finalizer)
        if isinstance(finalized, Failure):
            return finalized
        artifact_ids.extend(
            mapping.artifact_id
            for mapping in finalized.value.candidate_to_artifact_refs
        )
    return _refs_of(unit_of_work, artifact_ids)


__all__ = (
    "DESCRIPTOR_KIND",
    "DIAGNOSTIC_REPORT_KIND",
    "INPUT_SNAPSHOT_KINDS",
    "INPUT_SNAPSHOT_ROLES",
    "METRIC_SAMPLING_CONVENTION",
    "METRIC_VALUE_TYPES",
    "PROTOCOL_CAPTURE_KIND",
    "RESULT_MANIFEST_MEMBER",
    "RUN_EVIDENCE",
    "SANITIZED_MANIFEST_KIND",
    "SOURCE_COMPONENT",
    "STDERR_KIND",
    "VALIDATION_RESULT_KIND",
    "AuditFactRecorder",
    "CommandConclusion",
    "ConclusionConfig",
    "ConclusionOutcome",
    "ConclusionTransaction",
    "ConclusionUnitOfWork",
    "EvidenceRegistrar",
    "OwnerRegistry",
    "ResultRecoveryValidator",
    "ResultRegistrar",
    "conclude_command",
    "conclude_describe",
    "declared_candidate_paths",
    "descriptor_evidence",
    "diagnostic_report_evidence",
    "evidence_request_for",
    "fail_run_for_refusal",
    "finalize_evidence",
    "input_snapshot_evidence",
    "observe_candidates",
    "protocol_capture_evidence",
    "register_result_candidates",
    "sanitized_manifest_leaf",
    "sanitized_result_manifest_evidence",
    "semantic_outcome_or_replay",
    "stage_core_evidence",
    "stderr_evidence",
    "uncontrolled_strings_of",
    "validation_result_evidence",
)
