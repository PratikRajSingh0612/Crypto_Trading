"""Deterministic builders and doubles for the Stage 9 audit, log and metric
contracts (Stage 9 plan section 7.1; Task 2 creates this module with the
builders it needs, later tasks extend it).

Test-resident like ``doubles.experiments``: nothing under ``crypto_lab``
imports this module. ``SequentialAuditIds`` is the deterministic
``AuditEventIds`` double -- every identifier derives from a seed and a counter
through the existing ``_uuid4_shaped`` reshaping, so identical draw order yields
identical identifiers and no random source is consulted. The ``sample_*``
builders return production records validated in Python mode over the shared
doubles identities; an override whose value is ``MISSING`` removes the key, so a
test can build the record without that field.

Task 5 adds the artifact, reference, manifest and journal builders
(``sample_candidate``, ``sample_ref``, ``sample_artifact_manifest``,
``sample_journal``, ``sample_finalization_result`` with their ``bump_*`` and
``renew_journal`` variants) over the same identities -- the ``RUN`` owner names
the doubles' run and invocation, the attempt token hash is the one
``sample_run`` carries, so a RESULT journal entry matches the run row the Stage 8
fixtures plant -- and the minimal in-memory pair the shared artifact port
contract suite runs as kind ``memory``: ``MemoryCandidateArtifactRepository``
and ``MemoryArtifactRepository`` over one ``MemoryArtifactStore``, answering
exactly as the SQLite repositories do (a missing identity is
``CORE.INVARIANT_VIOLATION`` containing ``does not exist``; a duplicate identity,
a missing compare-and-swap row and a stale revision are
``PERSISTENCE.CONCURRENCY_CONFLICT``; a wrong replacement step, a refused domain
transition and a payload of the other type are the invariant; never an
exception; a staged pair is the staging repository instance's own, so it does
not outlive the transaction the contract harness opened it in). The pair is
deliberately minimal: ``MemoryFinalizationUnitOfWork`` and the journal double
belong to Task 6.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Coroutine, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, Final

from pydantic import BaseModel, ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.artifacts.diagnostics import (
    ARTIFACT_RESULT_MANIFEST_INVALID,
    artifact_failure,
)
from crypto_lab.artifacts.finalizer import CoreArtifactFinalizer
from crypto_lab.artifacts.hashing import StreamingContentHasher
from crypto_lab.artifacts.journal import (
    FinalizationJournalEntry,
    FinalizationJournalRuleViolation,
    FinalizationJournalState,
    ObservedMove,
    PlannedMove,
    assert_journal_transition,
)
from crypto_lab.artifacts.manifest import (
    ArtifactLineage,
    ArtifactManifest,
    artifact_manifest_hash,
)
from crypto_lab.artifacts.models import (
    ArtifactFinalizationPurpose,
    ArtifactOwnerKind,
    ArtifactRef,
    ArtifactSourceRole,
    CandidateArtifact,
    CandidateArtifactProducerKind,
    CandidateArtifactRuleViolation,
    CandidateArtifactState,
    CandidateFinalization,
    FinalizationResult,
    ValidationObservation,
    assert_candidate_transition,
    finalized_relative_path_for,
    owner_kind_of,
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
from crypto_lab.artifacts.ports import (
    AuditFact,
    CommandRootPaths,
    FinalizationLog,
    FinalizationProbe,
    FinalizationUnitOfWork,
    LogFact,
    RegistrationUnitOfWork,
    ResultRecoveryFacts,
    ResultRegistration,
    RunArtifactLink,
    RunManifestFacts,
    SanitizedManifestFacts,
    ValidationResultFacts,
)
from crypto_lab.artifacts.recovery import (
    FinalizationReconciliationReport,
    reconcile_finalization,
)
from crypto_lab.artifacts.requests import (
    EvidenceCorrelation,
    EvidenceFinalizationRequest,
    ResultFinalizationRequest,
)
from crypto_lab.artifacts.store import ArtifactStore, QuarantineEntry
from crypto_lab.audit.models import (
    CORE_ACTOR,
    LOCAL_USER_ACTOR,
    AuditAction,
    AuditActor,
    AuditEvent,
    AuditOutcome,
    LogRecord,
    LogSeverity,
    audit_details_hash,
)
from crypto_lab.audit.sink import AuditEventIds
from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.comparison_levels import ComparisonLevel
from crypto_lab.domain.diagnostics import Diagnostic
from crypto_lab.domain.engine_run import (
    SUCCESS_ENGINE_RUN_STATES,
    AttemptTokenMaterial,
    EngineRunRecord,
    EngineRunRuleViolation,
    assert_deadline_snapshot,
    assert_run_transition,
)
from crypto_lab.domain.hashing import (
    _uuid4_shaped,
    artifact_id_for,
    attempt_token_hash,
    candidate_artifact_id_for,
    candidate_set_hash_for,
    core_candidate_artifact_id_for,
    finalization_id_for,
    finalization_identity,
    sha256_bytes,
)
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
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
from doubles.experiments import (
    ARTIFACT_ID,
    ATTEMPT_TOKEN,
    DIAG_ID,
    EXPERIMENT_ID,
    INSTANT,
    INVOCATION_ID,
    RUN_ID,
    UUID_A,
    UUID_B,
    UUID_C,
    FixedClock,
    sample_invocation,
    sample_run,
)

AUDIT_EVENT_ID: Final = f"audit_{UUID_A}"
CORRELATION_ID: Final = "stage9.task2"
ADAPTER_ACTOR: Final = AuditActor(
    kind="ADAPTER", adapter_name="adapter.alpha", adapter_version="1.0.0"
)
SAMPLE_DETAILS: Final[dict[str, Any]] = {"stage": "HASH", "observed": 2}


class SequentialAuditIds:
    """Derives every ``audit_`` identifier from a fixed seed and a counter."""

    def __init__(self, prefix_seed: str = "task2") -> None:
        self._prefix_seed = prefix_seed
        self._issued: list[str] = []

    def new_audit_event_id(self) -> str:
        ordinal = len(self._issued) + 1
        digest = sha256_bytes(f"{self._prefix_seed}\x00audit\x00{ordinal}".encode())
        identifier = f"audit_{_uuid4_shaped(digest)}"
        self._issued.append(identifier)
        return identifier

    @property
    def issued(self) -> tuple[str, ...]:
        return tuple(self._issued)


def _without_missing(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if value is not MISSING}


def sample_audit_event(
    action: AuditAction = AuditAction.ARTIFACT_VALIDATED, **overrides: Any
) -> AuditEvent:
    """A ``CORE`` ``SUCCEEDED`` event carrying every correlation identifier."""
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "audit_event_id": AUDIT_EVENT_ID,
        "action": action,
        "actor": CORE_ACTOR,
        "outcome": AuditOutcome.SUCCEEDED,
        "experiment_id": EXPERIMENT_ID,
        "run_id": RUN_ID,
        "invocation_id": INVOCATION_ID,
        "artifact_id": ARTIFACT_ID,
        "timestamp_utc": INSTANT,
        "correlation_id": CORRELATION_ID,
        "details": dict(SAMPLE_DETAILS),
    }
    payload.update(overrides)
    payload = _without_missing(payload)
    if "details_hash" not in payload:
        payload["details_hash"] = audit_details_hash(payload["details"])
    return AuditEvent.model_validate(payload)


def sample_log_record(**overrides: Any) -> LogRecord:
    """An ``INFO`` record of the artifact component with every identifier."""
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "timestamp_utc": INSTANT,
        "severity": LogSeverity.INFO,
        "component": "core.artifacts",
        "event_code": "ARTIFACT.VALIDATED",
        "correlation_id": CORRELATION_ID,
        "experiment_id": EXPERIMENT_ID,
        "run_id": RUN_ID,
        "invocation_id": INVOCATION_ID,
        "adapter": "adapter.alpha",
        "engine": "engine.alpha",
        "message": "candidate validated",
        "details": dict(SAMPLE_DETAILS),
    }
    payload.update(overrides)
    return LogRecord.model_validate(_without_missing(payload))


def sample_metric(**overrides: Any) -> MetricValue:
    """A ``DEFINED`` ratio metric with a canonical Decimal value."""
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "metric_name": "total-return",
        "value": Decimal("0.125"),
        "value_type": MetricValueType.RATIO,
        "unit": "ratio",
        "methodology_version": "1.0.0",
        "sampling_convention": "close-to-close",
        "comparison_level": ComparisonLevel.LEVEL_2,
        "status": MetricStatus.DEFINED,
        "source_artifact_id": ARTIFACT_ID,
    }
    payload.update(overrides)
    return MetricValue.model_validate(_without_missing(payload))


# --------------------------------------------------------------------------
# Task 5 (plan 7.1): the artifact, reference, manifest and journal builders
# --------------------------------------------------------------------------

_S: Final = CandidateArtifactState
_P: Final = CandidateArtifactProducerKind
_F: Final = ArtifactFinalizationPurpose
_R: Final = ArtifactSourceRole
_K: Final = ArtifactOwnerKind
_J: Final = FinalizationJournalState

CANDIDATE_ID: Final = f"cand_{UUID_A}"
OTHER_CANDIDATE_ID: Final = f"cand_{UUID_B}"
THIRD_CANDIDATE_ID: Final = f"cand_{UUID_C}"
ADAPTER_MANIFEST_ID: Final = f"amf_{UUID_A}"
SOURCE_EVENT_ID: Final = f"evt_{UUID_A}"
RUN_MANIFEST_ID: Final = f"rmf_{UUID_A}"
DATASET_ID: Final = f"ds_{UUID_A}"
STRATEGY_VERSION_ID: Final = f"strv_{UUID_A}"
#: The hash ``sample_run`` carries, so a RESULT journal entry matches the run row.
ATTEMPT_TOKEN_HASH: Final = attempt_token_hash(ATTEMPT_TOKEN)
SOURCE_MANIFEST_HASH: Final = sha256_bytes(b"doubles.artifacts:source-manifest")
SANITIZED_MANIFEST_HASH: Final = sha256_bytes(b"doubles.artifacts:sanitized-manifest")
SNAPSHOT_SOURCE_HASH: Final = sha256_bytes(b"doubles.artifacts:snapshot-source")
RUN_MANIFEST_HASH: Final = sha256_bytes(b"doubles.artifacts:run-manifest")
DEADLINE: Final = INSTANT + timedelta(minutes=5)
LEASE_EXPIRY: Final = INSTANT + timedelta(minutes=1)
SIZE_BYTES: Final = 12
NATIVE_PATH: Final = "results/native.bin"
NATIVE_KIND: Final = "engine-native-report"
NATIVE_MEDIA: Final = "application/octet-stream"
CORE_PATH: Final = f"INVOCATION/{INVOCATION_ID}/stderr.txt"
CORE_KIND: Final = "stderr-capture"
CORE_MEDIA: Final = "text/plain"
#: ``source_component`` of every memory-double failure.
ARTIFACT_DOUBLE_COMPONENT: Final = "doubles.artifacts"
ABANDON_REASON: Final = "ARTIFACT.VALIDATION_FAILED"

RUN_OWNER: Final = RunArtifactOwner(
    owner_kind="RUN",
    experiment_id=EXPERIMENT_ID,
    run_id=RUN_ID,
    invocation_id=INVOCATION_ID,
)
RUN_OWNER_WITHOUT_INVOCATION: Final = RunArtifactOwner(
    owner_kind="RUN", experiment_id=EXPERIMENT_ID, run_id=RUN_ID
)
EXPERIMENT_OWNER: Final = ExperimentArtifactOwner(
    owner_kind="EXPERIMENT", experiment_id=EXPERIMENT_ID
)
DATASET_OWNER: Final = DatasetArtifactOwner(owner_kind="DATASET", dataset_id=DATASET_ID)
STRATEGY_OWNER: Final = StrategyArtifactOwner(
    owner_kind="STRATEGY", strategy_version_id=STRATEGY_VERSION_ID
)
#: The adapter identity ``sample_invocation`` carries (the describe stderr owner).
ADAPTER_OWNER: Final = AdapterArtifactOwner(
    owner_kind="ADAPTER", adapter_name="adapter.alpha", adapter_version="1.0.0"
)
SYSTEM_OWNER: Final = SystemArtifactOwner(
    owner_kind="SYSTEM", core_component="artifacts", correlation_id="stage9.task5"
)
OWNERS: Final[dict[ArtifactOwnerKind, ArtifactOwnerRef]] = {
    _K.RUN: RUN_OWNER,
    _K.EXPERIMENT: EXPERIMENT_OWNER,
    _K.DATASET: DATASET_OWNER,
    _K.STRATEGY: STRATEGY_OWNER,
    _K.ADAPTER: ADAPTER_OWNER,
    _K.SYSTEM: SYSTEM_OWNER,
}
DIAGNOSTIC_CORRELATION: Final = EvidenceCorrelation(
    kind="DIAGNOSTIC", diagnostic_id=DIAG_ID
)
INVOCATION_CORRELATION: Final = EvidenceCorrelation(
    kind="INVOCATION", invocation_id=INVOCATION_ID
)
_CANDIDATE_REVISION: Final[dict[CandidateArtifactState, int]] = {
    _S.CANDIDATE: 1,
    _S.VALIDATING: 2,
    _S.FINALIZING: 3,
    _S.QUARANTINED: 2,
    _S.CORRUPT: 3,
}
_JOURNAL_REVISION: Final[dict[FinalizationJournalState, int]] = {
    _J.PREPARED: 1,
    _J.MOVED: 2,
    _J.REGISTERED: 3,
    _J.ABANDONED: 2,
}
_SNAPSHOT_OWNER_ROLES: Final[dict[ArtifactOwnerKind, ArtifactSourceRole]] = {
    _K.EXPERIMENT: _R.EXPERIMENT_INPUT,
    _K.DATASET: _R.DATASET_INPUT,
    _K.STRATEGY: _R.STRATEGY_INPUT,
}
_MAX_LISTING: Final = 1024


def content_hash_for(candidate_artifact_id: str) -> str:
    """The deterministic content hash the fixtures give one candidate's bytes."""
    return sha256_bytes(f"doubles.artifacts:content:{candidate_artifact_id}".encode())


CONTENT_HASH: Final = content_hash_for(CANDIDATE_ID)


def staging_path_for(
    candidate_artifact_id: str, producer: CandidateArtifactProducerKind
) -> str:
    """The fixture staging path of one candidate: the shared constants for the
    primary identity, a derived sibling for every other."""
    if candidate_artifact_id == CANDIDATE_ID:
        return CORE_PATH if producer is _P.CORE else NATIVE_PATH
    stem = candidate_artifact_id[5:13]
    if producer is _P.CORE:
        return f"INVOCATION/{INVOCATION_ID}/{stem}.txt"
    return f"results/{stem}.bin"


def default_role(
    purpose: ArtifactFinalizationPurpose,
    producer: CandidateArtifactProducerKind,
    owner_kind: ArtifactOwnerKind,
) -> ArtifactSourceRole:
    """The one role plan 3.1.1 gives a ``(purpose, producer, owner)`` column."""
    if purpose is _F.RESULT:
        if producer is _P.ADAPTER:
            return _R.ENGINE_NATIVE_RESULT
        return _R.NORMALIZED_RESULT
    return _SNAPSHOT_OWNER_ROLES.get(owner_kind, _R.CORE_EVIDENCE)


def passed_observation(stage: str = "PATH", **overrides: Any) -> ValidationObservation:
    payload: dict[str, Any] = {
        "observed_at_utc": INSTANT,
        "stage": stage,
        "outcome": "PASSED",
    }
    payload.update(overrides)
    return ValidationObservation.model_validate(_without_missing(payload))


def hash_observation(
    candidate_artifact_id: str = CANDIDATE_ID,
) -> ValidationObservation:
    return passed_observation(
        "HASH",
        observed_size_bytes=SIZE_BYTES,
        observed_sha256=content_hash_for(candidate_artifact_id),
    )


def failed_observation(
    error_code: str = ABANDON_REASON, stage: str = "SIZE"
) -> ValidationObservation:
    return ValidationObservation.model_validate(
        {
            "observed_at_utc": INSTANT,
            "stage": stage,
            "outcome": "FAILED",
            "error_code": error_code,
        }
    )


def _observations_for(
    state: CandidateArtifactState, candidate_artifact_id: str
) -> tuple[ValidationObservation, ...]:
    """The observation prefix each state carries, so a later state's tuple extends
    an earlier state's (``assert_candidate_transition`` requires the prefix)."""
    if state is _S.CANDIDATE:
        return ()
    if state is _S.VALIDATING:
        return (passed_observation(),)
    if state is _S.FINALIZING:
        return (passed_observation(), hash_observation(candidate_artifact_id))
    if state is _S.QUARANTINED:
        return (failed_observation(),)
    return (passed_observation(), failed_observation(ABANDON_REASON, "HASH"))


def sample_candidate(
    owner_kind: ArtifactOwnerKind | str = "RUN",
    purpose: ArtifactFinalizationPurpose = _F.RESULT,
    role: ArtifactSourceRole | None = None,
    producer: CandidateArtifactProducerKind = _P.ADAPTER,
    state: CandidateArtifactState = _S.CANDIDATE,
    *,
    candidate_artifact_id: str = CANDIDATE_ID,
    **overrides: Any,
) -> CandidateArtifact:
    """A shape-valid candidate for one row of plan 3.1.1; the default is the
    adapter-produced ``RUN``-owned ``RESULT`` candidate (row 1)."""
    kind = ArtifactOwnerKind(owner_kind)
    owner = overrides.pop("owner", OWNERS[kind])
    if role is None:
        role = default_role(purpose, producer, kind)
    revision = _CANDIDATE_REVISION[state]
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "candidate_artifact_id": candidate_artifact_id,
        "owner": owner,
        "finalization_purpose": purpose,
        "source_role": role,
        "producer_kind": producer,
        "artifact_kind": CORE_KIND if producer is _P.CORE else NATIVE_KIND,
        "staging_relative_path": staging_path_for(candidate_artifact_id, producer),
        "state": state,
        "validation_observations": _observations_for(state, candidate_artifact_id),
        "created_at_utc": INSTANT,
        "updated_at_utc": INSTANT + timedelta(seconds=revision - 1),
        "revision": revision,
    }
    if producer is _P.ADAPTER:
        payload["adapter_declared_size"] = SIZE_BYTES
        payload["adapter_declared_hash"] = content_hash_for(candidate_artifact_id)
        payload["adapter_declared_media_type"] = NATIVE_MEDIA
        payload["source_event_id"] = SOURCE_EVENT_ID
    payload.update(overrides)
    return CandidateArtifact.model_validate(_without_missing(payload))


def bump_candidate(
    record: CandidateArtifact,
    state: CandidateArtifactState,
    *,
    observation: ValidationObservation | None = None,
    **overrides: Any,
) -> CandidateArtifact:
    """The same candidate one revision and one second later in ``state``, its
    observations extended by ``observation`` (or the step the target implies)."""
    payload = record.model_dump(mode="python")
    if observation is None and state is not record.state:
        if state is _S.FINALIZING:
            observation = hash_observation(record.candidate_artifact_id)
        elif state in (_S.QUARANTINED, _S.CORRUPT):
            observation = failed_observation()
        else:
            observation = passed_observation()
    observations = list(record.validation_observations)
    if observation is not None:
        observations.append(observation)
    payload["validation_observations"] = tuple(observations)
    payload["state"] = state
    payload["revision"] = record.revision + 1
    payload["updated_at_utc"] = record.updated_at_utc + timedelta(seconds=1)
    payload.update(overrides)
    return CandidateArtifact.model_validate(_without_missing(payload))


def sample_ref(
    candidate: CandidateArtifact | None = None,
    *,
    content_hash: str | None = None,
    size_bytes: int = SIZE_BYTES,
    **overrides: Any,
) -> ArtifactRef:
    """The finalized reference of ``candidate`` (a ``FINALIZING`` row 1 candidate
    by default): owner, purpose, role, producer and kind restated, the derived
    ``artifact_id`` and the content-addressed path."""
    if candidate is None:
        candidate = sample_candidate(state=_S.FINALIZING)
    digest = content_hash or content_hash_for(candidate.candidate_artifact_id)
    declared_media = candidate.adapter_declared_media_type
    media_type = declared_media if isinstance(declared_media, str) else CORE_MEDIA
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "artifact_id": artifact_id_for(candidate.candidate_artifact_id, digest),
        "owner": candidate.owner,
        "finalization_purpose": candidate.finalization_purpose,
        "artifact_kind": candidate.artifact_kind,
        "finalized_relative_path": finalized_relative_path_for(digest),
        "content_hash": digest,
        "size_bytes": size_bytes,
        "media_type": media_type,
        "source_role": candidate.source_role,
        "source_candidate_artifact_id": candidate.candidate_artifact_id,
        "producer_kind": candidate.producer_kind,
        "validation_profile": "artifact-validation/v1",
        "created_at_utc": candidate.created_at_utc,
        "finalized_at_utc": candidate.updated_at_utc + timedelta(seconds=1),
        "state": "FINALIZED",
    }
    payload.update(overrides)
    return ArtifactRef.model_validate(_without_missing(payload))


def sample_artifact_manifest(
    ref: ArtifactRef, **lineage_overrides: Any
) -> ArtifactManifest:
    """The canonical manifest beside ``ref`` with the owner-appropriate lineage and
    its ``ARTIFACT_MANIFEST_V1`` self-hash recomputed."""
    lineage: dict[str, Any] = {}
    owner = ref.owner
    if isinstance(owner, RunArtifactOwner):
        lineage["experiment_id"] = owner.experiment_id
        lineage["run_id"] = owner.run_id
        if isinstance(owner.invocation_id, str):
            lineage["invocation_id"] = owner.invocation_id
    if ref.producer_kind is _P.ADAPTER:
        lineage["source_adapter_manifest_id"] = ADAPTER_MANIFEST_ID
        lineage["source_event_id"] = SOURCE_EVENT_ID
    if owner_kind_of(owner) in _SNAPSHOT_OWNER_ROLES:
        lineage["source_hash"] = SNAPSHOT_SOURCE_HASH
    lineage.update(lineage_overrides)
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
        lineage=ArtifactLineage.model_validate(_without_missing(lineage)),
        validation_profile="artifact-validation/v1",
        validation_diagnostic_ids=(),
        created_at_utc=ref.created_at_utc,
        finalized_at_utc=ref.finalized_at_utc,
        artifact_manifest_hash="0" * 64,
    )
    # The strict canonical models accept Python-mode dumps (nested dicts, enum
    # and datetime instances), never a JSON-mode dump through ``model_validate``.
    payload = draft.model_dump(mode="python")
    payload["artifact_manifest_hash"] = artifact_manifest_hash(draft)
    return ArtifactManifest.model_validate(payload)


def sample_mapping(
    ref: ArtifactRef, *, deduplicated: bool = False
) -> CandidateFinalization:
    return CandidateFinalization(
        candidate_artifact_id=ref.source_candidate_artifact_id,
        artifact_id=ref.artifact_id,
        content_hash=ref.content_hash,
        size_bytes=ref.size_bytes,
        deduplicated=deduplicated,
    )


def sample_finalization_result(
    refs: Sequence[ArtifactRef],
    *,
    finalization_id: str | None = None,
    replayed: bool = False,
    **overrides: Any,
) -> FinalizationResult:
    """The ``REGISTERED`` outcome naming exactly ``refs``; purpose and owner are
    the first reference's and a RESULT carries the fixture run-manifest facts."""
    first = refs[0]
    purpose = first.finalization_purpose
    if finalization_id is None:
        finalization_id = sample_journal(_J.REGISTERED, purpose).finalization_id
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "finalization_id": finalization_id,
        "finalization_purpose": purpose,
        "owner": first.owner,
        "journal_state": "REGISTERED",
        "candidate_to_artifact_refs": tuple(sample_mapping(ref) for ref in refs),
        "registered_at_utc": max(ref.finalized_at_utc for ref in refs),
        "replayed": replayed,
    }
    if purpose is _F.RESULT:
        payload["run_manifest_id"] = RUN_MANIFEST_ID
        payload["run_manifest_hash"] = RUN_MANIFEST_HASH
    payload.update(overrides)
    return FinalizationResult.model_validate(_without_missing(payload))


def _planned_move(
    candidate_artifact_id: str, producer: CandidateArtifactProducerKind
) -> PlannedMove:
    digest = content_hash_for(candidate_artifact_id)
    return PlannedMove(
        candidate_artifact_id=candidate_artifact_id,
        staging_relative_path=staging_path_for(candidate_artifact_id, producer),
        finalized_relative_path=finalized_relative_path_for(digest),
        expected_sha256=digest,
        expected_size_bytes=SIZE_BYTES,
    )


def observed_move(planned: PlannedMove, **overrides: Any) -> ObservedMove:
    payload = planned.model_dump(mode="python")
    payload.update(
        observed_sha256=planned.expected_sha256,
        observed_size_bytes=planned.expected_size_bytes,
        deduplicated=False,
    )
    payload.update(overrides)
    return ObservedMove.model_validate(payload)


def _result_identity(payload: dict[str, Any]) -> str:
    return finalization_identity(
        "RESULT",
        run_id=payload["run_id"],
        run_invocation_id=payload["run_invocation_id"],
        attempt_token_hash=payload["attempt_token_hash"],
        source_adapter_result_manifest_hash=payload[
            "source_adapter_result_manifest_hash"
        ],
        sanitized_adapter_result_manifest_hash=payload[
            "sanitized_adapter_result_manifest_hash"
        ],
    )


def _evidence_identity(payload: dict[str, Any]) -> str:
    link = payload["correlation"]
    return finalization_identity(
        "EVIDENCE",
        owner_hash=artifact_owner_hash(payload["owner"]),
        correlation_kind=link.kind,
        correlation_id=link.correlation_id,
        candidate_set_hash=payload["candidate_set_hash"],
    )


def sample_journal(
    state: FinalizationJournalState = _J.PREPARED,
    purpose: ArtifactFinalizationPurpose = _F.RESULT,
    *,
    candidate_artifact_ids: Sequence[str] = (CANDIDATE_ID,),
    owner: ArtifactOwnerRef | None = None,
    correlation: EvidenceCorrelation | None = None,
    source_role: ArtifactSourceRole | None = None,
    **overrides: Any,
) -> FinalizationJournalEntry:
    """A shape-valid journal entry whose ``finalization_id`` and
    ``candidate_set_hash`` recompute from the (possibly overridden) identity
    fields; a RESULT entry names the doubles' run, invocation and token hash."""
    ids = tuple(sorted(candidate_artifact_ids))
    producer = _P.ADAPTER if purpose is _F.RESULT else _P.CORE
    planned = tuple(_planned_move(identity, producer) for identity in ids)
    observed: tuple[ObservedMove, ...] = ()
    if state in (_J.MOVED, _J.REGISTERED):
        observed = tuple(observed_move(move) for move in planned)
    revision = _JOURNAL_REVISION[state]
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "finalization_purpose": purpose,
        "candidate_artifact_ids": ids,
        "state": state,
        "prepared_at_utc": INSTANT,
        "lease_expires_at_utc": LEASE_EXPIRY,
        "planned_paths": planned,
        "observed": observed,
        "updated_at_utc": INSTANT + timedelta(seconds=revision - 1),
        "revision": revision,
    }
    if state is _J.ABANDONED:
        payload["abandon_reason"] = ABANDON_REASON
    if purpose is _F.RESULT:
        run_owner = owner if owner is not None else RUN_OWNER
        if not isinstance(run_owner, RunArtifactOwner):
            raise TypeError("a RESULT journal entry requires a RUN owner")
        run_revision = sample_run(EngineRunState.RUNNING).revision
        invocation_revision = sample_invocation(CommandInvocationState.EXITED).revision
        payload.update(
            owner=run_owner,
            source_role=source_role or _R.ENGINE_NATIVE_RESULT,
            finalization_deadline_utc=DEADLINE,
            expected_run_revision=run_revision,
            expected_invocation_revision=invocation_revision,
            run_id=run_owner.run_id,
            run_invocation_id=run_owner.invocation_id,
            attempt_token_hash=ATTEMPT_TOKEN_HASH,
            source_adapter_result_manifest_hash=SOURCE_MANIFEST_HASH,
            sanitized_adapter_result_manifest_hash=SANITIZED_MANIFEST_HASH,
        )
    else:
        evidence_owner = owner if owner is not None else SYSTEM_OWNER
        evidence_role = source_role
        if evidence_role is None:
            evidence_role = default_role(
                _F.EVIDENCE, _P.CORE, owner_kind_of(evidence_owner)
            )
        payload.update(
            owner=evidence_owner,
            source_role=evidence_role,
            correlation=correlation or DIAGNOSTIC_CORRELATION,
        )
    payload.update(overrides)
    payload = _without_missing(payload)
    payload.setdefault("candidate_set_hash", candidate_set_hash_for(ids))
    if "finalization_id" not in payload:
        if purpose is _F.RESULT:
            identity = _result_identity(payload)
        else:
            identity = _evidence_identity(payload)
        payload["finalization_id"] = finalization_id_for(identity)
    return FinalizationJournalEntry.model_validate(payload)


def bump_journal(
    entry: FinalizationJournalEntry,
    state: FinalizationJournalState,
    *,
    abandon_reason: str = ABANDON_REASON,
    **overrides: Any,
) -> FinalizationJournalEntry:
    """The same entry one revision and one second later in ``state``; a move to
    ``MOVED`` or ``REGISTERED`` observes every planned move, ``ABANDONED`` carries
    ``abandon_reason``."""
    payload = entry.model_dump(mode="python")
    payload["state"] = state
    payload["revision"] = entry.revision + 1
    payload["updated_at_utc"] = entry.updated_at_utc + timedelta(seconds=1)
    if state in (_J.MOVED, _J.REGISTERED) and not entry.observed:
        payload["observed"] = tuple(observed_move(move) for move in entry.planned_paths)
    if state is _J.ABANDONED:
        payload["abandon_reason"] = abandon_reason
    payload.update(overrides)
    return FinalizationJournalEntry.model_validate(_without_missing(payload))


def renew_journal(
    entry: FinalizationJournalEntry, lease_expires_at_utc: datetime
) -> FinalizationJournalEntry:
    """The reflexive lease renewal: the lease advances and nothing else changes."""
    payload = entry.model_dump(mode="python")
    payload["lease_expires_at_utc"] = lease_expires_at_utc
    payload["revision"] = entry.revision + 1
    payload["updated_at_utc"] = entry.updated_at_utc + timedelta(seconds=1)
    return FinalizationJournalEntry.model_validate(payload)


# --------------------------------------------------------------------------
# Task 5 (plan 7.1): the minimal in-memory candidate and reference pair
# --------------------------------------------------------------------------


class MemoryArtifactStore:
    """The dict stores one memory pair shares: committed candidates and the
    reference rows (each beside its manifest). Staging is not stored here: a
    pair staged for ``record_finalization`` belongs to the repository instance
    that staged it, so it lives exactly as long as the transaction the contract
    harness opened it for, as the SQLite repository's does."""

    def __init__(self, clock: Clock | None = None) -> None:
        self.clock: Clock = clock if clock is not None else FixedClock(INSTANT)
        self.candidates: dict[str, CandidateArtifact] = {}
        self.refs: dict[str, tuple[ArtifactRef, ArtifactManifest]] = {}
        #: Task 6: the journal, run, invocation, facts, audit and diagnostic tables.
        self.tables: MemoryTables = MemoryTables()

    def committed_candidates(self) -> tuple[CandidateArtifact, ...]:
        return tuple(self.candidates[key] for key in sorted(self.candidates))

    def committed_refs(self) -> tuple[ArtifactRef, ...]:
        return tuple(self.refs[key][0] for key in sorted(self.refs))

    def mapped_candidate_ids(self) -> frozenset[str]:
        return frozenset(
            ref.source_candidate_artifact_id for ref, _ in self.refs.values()
        )

    def conflict(self, message: str) -> Failure:
        return stage5_failure(
            CONCURRENCY_CONFLICT,
            message,
            source_component=ARTIFACT_DOUBLE_COMPONENT,
            timestamp_utc=self.clock.now_utc(),
        )

    def invariant(self, message: str) -> Failure:
        return stage5_failure(
            INVARIANT_VIOLATION,
            message,
            source_component=ARTIFACT_DOUBLE_COMPONENT,
            timestamp_utc=self.clock.now_utc(),
        )

    def missing(self, kind: str, identity: str) -> Failure:
        return self.invariant(f"{kind} {identity} does not exist")


def _none() -> Success[None]:
    return Success[None](outcome="SUCCESS", value=None)


#: One mapping ``record_finalization`` validated, beside its staged pair.
_ValidatedMapping = tuple[CandidateFinalization, ArtifactRef, ArtifactManifest]


class MemoryCandidateArtifactRepository:
    """``CandidateArtifactRepository`` (plan 4.1) over the shared store, with the
    Stage 8 section 4.3.1 order the SQLite repository applies verbatim."""

    def __init__(self, store: MemoryArtifactStore) -> None:
        self._store = store

    def get(self, candidate_artifact_id: str) -> Result[CandidateArtifact]:
        record = self._store.candidates.get(candidate_artifact_id)
        if record is None:
            return self._store.missing("candidate artifact", candidate_artifact_id)
        return Success[CandidateArtifact](outcome="SUCCESS", value=record)

    def add(self, record: CandidateArtifact) -> Result[None]:
        if not isinstance(record, CandidateArtifact):
            return self._store.invariant(
                "the candidate repository stores CandidateArtifact records only"
            )
        identity = record.candidate_artifact_id
        if identity in self._store.candidates:
            return self._store.conflict(
                f"candidate artifact {identity} is already registered"
            )
        self._store.candidates[identity] = record
        return _none()

    def compare_and_swap(
        self,
        expected_revision: int,
        replacement: CandidateArtifact,
        *,
        registered_mapping: CandidateFinalization | MISSING = MISSING,  # type: ignore[valid-type]
    ) -> Result[CandidateArtifact]:
        identity = replacement.candidate_artifact_id
        stored = self._store.candidates.get(identity)
        if stored is None:
            return self._store.conflict(
                f"candidate artifact {identity} does not exist for compare-and-swap"
            )
        if stored.revision != expected_revision:
            return self._store.conflict(
                f"candidate artifact {identity} is at revision {stored.revision}, "
                f"not {expected_revision}"
            )
        if replacement.revision != expected_revision + 1:
            return self._store.invariant(
                "candidate artifact replacement must carry revision "
                f"{expected_revision + 1}, not {replacement.revision}"
            )
        try:
            assert_candidate_transition(
                stored, replacement, registered_mapping=registered_mapping
            )
        except CandidateArtifactRuleViolation as violation:
            return self._store.invariant(str(violation))
        self._store.candidates[identity] = replacement
        return Success[CandidateArtifact](outcome="SUCCESS", value=replacement)

    def list_recoverable(
        self,
        states: Sequence[CandidateArtifactState],
        owner: ArtifactOwnerRef | MISSING = MISSING,  # type: ignore[valid-type]
        purpose: ArtifactFinalizationPurpose | MISSING = MISSING,  # type: ignore[valid-type]
        limit: int = _MAX_LISTING,
    ) -> Result[tuple[CandidateArtifact, ...]]:
        mapped = self._store.mapped_candidate_ids()
        wanted = frozenset(states)
        owner_hash = (
            artifact_owner_hash(owner) if isinstance(owner, BaseModel) else None
        )
        listed: list[CandidateArtifact] = []
        for identity in sorted(self._store.candidates):
            record = self._store.candidates[identity]
            if record.state not in wanted or identity in mapped:
                continue
            if owner_hash is not None and owner_hash != artifact_owner_hash(
                record.owner
            ):
                continue
            if (
                isinstance(purpose, ArtifactFinalizationPurpose)
                and record.finalization_purpose is not purpose
            ):
                continue
            listed.append(record)
            if len(listed) == limit:
                break
        return Success[tuple[CandidateArtifact, ...]](
            outcome="SUCCESS", value=tuple(listed)
        )


class MemoryArtifactRepository:
    """``ArtifactRepository`` (plan 4.1) over the shared store: the only writer of
    references, through ``stage_reference`` then ``record_finalization``.

    The staged pairs are this instance's alone -- transaction-local, since the
    contract harness builds a fresh pair per ``begin()`` -- so a rollback or a
    commit that never recorded them leaves nothing staged for a later
    transaction, exactly as the per-transaction SQLite repository answers.
    ``reference_lookup_failure`` is the root unit of work's pending read fault,
    consulted by ``list_by_content_hash`` alone (Task 6: the memory twin of a
    content-hash read the driver refuses).
    """

    def __init__(
        self,
        store: MemoryArtifactStore,
        *,
        reference_lookup_failure: Callable[[], Failure | None] | None = None,
    ) -> None:
        self._store = store
        self._staged: dict[str, tuple[ArtifactRef, ArtifactManifest]] = {}
        self._reference_lookup_failure = reference_lookup_failure

    def get(self, artifact_id: str) -> Result[ArtifactRef]:
        stored = self._store.refs.get(artifact_id)
        if stored is None:
            return self._store.missing("artifact", artifact_id)
        return Success[ArtifactRef](outcome="SUCCESS", value=stored[0])

    def get_manifest(self, artifact_id: str) -> Result[ArtifactManifest]:
        stored = self._store.refs.get(artifact_id)
        if stored is None:
            return self._store.missing("artifact", artifact_id)
        return Success[ArtifactManifest](outcome="SUCCESS", value=stored[1])

    def list_by_owner(
        self,
        owner: ArtifactOwnerRef,
        purpose: ArtifactFinalizationPurpose | MISSING = MISSING,  # type: ignore[valid-type]
    ) -> Result[tuple[ArtifactRef, ...]]:
        owner_hash = artifact_owner_hash(owner)
        listed: list[ArtifactRef] = []
        for identity in sorted(self._store.refs):
            ref = self._store.refs[identity][0]
            if artifact_owner_hash(ref.owner) != owner_hash:
                continue
            if (
                isinstance(purpose, ArtifactFinalizationPurpose)
                and ref.finalization_purpose is not purpose
            ):
                continue
            listed.append(ref)
        return Success[tuple[ArtifactRef, ...]](outcome="SUCCESS", value=tuple(listed))

    def list_by_content_hash(
        self, content_hash: str
    ) -> Result[tuple[ArtifactRef, ...]]:
        """Every reference registering ``content_hash`` by ``artifact_id`` (the
        Task 6 RV-9 read, plan 6.2); a read fault armed on the root unit of work
        is answered first, as the SQLite repository answers a refused statement."""
        if self._reference_lookup_failure is not None:
            failure = self._reference_lookup_failure()
            if failure is not None:
                return failure
        listed = tuple(
            self._store.refs[identity][0]
            for identity in sorted(self._store.refs)
            if self._store.refs[identity][0].content_hash == content_hash
        )
        return Success[tuple[ArtifactRef, ...]](outcome="SUCCESS", value=listed)

    def stage_reference(
        self, ref: ArtifactRef, manifest: ArtifactManifest
    ) -> Result[None]:
        if not isinstance(ref, ArtifactRef) or not isinstance(
            manifest, ArtifactManifest
        ):
            return self._store.invariant(
                "the reference repository stages ArtifactRef records beside their "
                "ArtifactManifest only"
            )
        described = (
            manifest.artifact_id,
            manifest.content_hash,
            manifest.size_bytes,
            manifest.source_candidate_artifact_id,
            manifest.owner,
        )
        referenced = (
            ref.artifact_id,
            ref.content_hash,
            ref.size_bytes,
            ref.source_candidate_artifact_id,
            ref.owner,
        )
        if described != referenced:
            return self._store.invariant(
                "the manifest must describe the same finalized artifact"
            )
        self._staged[ref.artifact_id] = (ref, manifest)
        return _none()

    def record_finalization(
        self, result: FinalizationResult
    ) -> Result[tuple[ArtifactRef, ...]]:
        """The SQLite repository's two phases: every mapping validated (staged,
        restating its mapping, carrying the finalization's owner and purpose,
        sourced from a ``FINALIZING`` candidate) before the first reference is
        stored, then the validated pairs stored in mapping order; the duplicate
        conflict stays in the storing phase, where SQLite's UNIQUE refusal is."""
        if not isinstance(result, FinalizationResult):
            return self._store.invariant(
                "record_finalization consumes a FinalizationResult only"
            )
        validated: list[_ValidatedMapping] = []
        for mapping in result.candidate_to_artifact_refs:
            staged = self._staged.get(mapping.artifact_id)
            if staged is None:
                return self._store.invariant(
                    f"artifact {mapping.artifact_id} was not staged on this transaction"
                )
            ref, manifest = staged
            if (
                ref.source_candidate_artifact_id != mapping.candidate_artifact_id
                or ref.content_hash != mapping.content_hash
                or ref.size_bytes != mapping.size_bytes
            ):
                return self._store.invariant(
                    f"artifact {mapping.artifact_id} does not match its mapping"
                )
            if artifact_owner_hash(ref.owner) != artifact_owner_hash(result.owner):
                return self._store.invariant(
                    f"artifact {mapping.artifact_id} does not carry the "
                    "finalization's owner"
                )
            if ref.finalization_purpose is not result.finalization_purpose:
                return self._store.invariant(
                    f"artifact {mapping.artifact_id} does not carry the "
                    "finalization's purpose"
                )
            candidate = self._store.candidates.get(mapping.candidate_artifact_id)
            if candidate is None or candidate.state is not _S.FINALIZING:
                return self._store.invariant(
                    f"candidate artifact {mapping.candidate_artifact_id} is not "
                    "FINALIZING"
                )
            validated.append((mapping, ref, manifest))
        inserted: list[ArtifactRef] = []
        for mapping, ref, manifest in validated:
            if mapping.artifact_id in self._store.refs or (
                mapping.candidate_artifact_id in self._store.mapped_candidate_ids()
            ):
                return self._store.conflict(
                    f"artifact {mapping.artifact_id} is already recorded"
                )
            self._store.refs[mapping.artifact_id] = (ref, manifest)
            inserted.append(ref)
        for ref in inserted:
            del self._staged[ref.artifact_id]
        return Success[tuple[ArtifactRef, ...]](
            outcome="SUCCESS", value=tuple(inserted)
        )


# --------------------------------------------------------------------------
# Task 6 (plan 7.1): the finalization unit of work, its member doubles, the
# probes, the coroutine driver, the registrar, the validator and the auditor
# --------------------------------------------------------------------------
#
# Labelled accurately: every class below is a test double. The memory unit of
# work answers with the SQLite repositories' conflict, invariant and missing
# vocabulary over dict stores and gives each transaction a copy-on-write view of
# the shared store, so a rollback -- or a ``BaseException`` escaping with the
# transaction open -- discards every staged write and a commit publishes them
# together. ``MemoryRegistrar`` records evidence links only and refuses every
# RESULT registration; ``MemoryRecoveryValidator`` answers planted facts; so a
# successful RESULT registration is unreachable through them by construction
# (plan 7.1: Task 7 supplies the production registrar and validator).

_E: Final = ExperimentState
_RS: Final = EngineRunState
_C: Final = CommandInvocationState
_RUN_ARTIFACT_LINK_ROLES: Final = frozenset({"RESULT_MANIFEST_MEMBER", "RUN_EVIDENCE"})
#: The fixture token's hash is ``ATTEMPT_TOKEN_HASH``; the raw token is written
#: only into the planted ``request.json`` and read back by ``token_material``.
FIXTURE_TOKEN: Final = ATTEMPT_TOKEN
RESULT_TIMEOUT_SECONDS: Final = 600
#: Two declared native result candidates under the work directory.
RESULT_FILES: Final[Mapping[str, bytes]] = {
    "results/native.bin": b"native result bytes 0001\n" * 3,
    "results/second.bin": b"second native result bytes\n" * 2,
}
#: Core evidence bytes: text without a token-shaped run.
EVIDENCE_FILES: Final[Mapping[str, bytes]] = {
    "stderr.txt": b"engine stderr line one\nengine stderr line two\n",
}
EVIDENCE_MEDIA: Final = "text/plain"
#: The sanitized manifest bytes the fixture plants as the adapter result manifest.
RESULT_MANIFEST_BYTES: Final = (
    b'{"schema_version": "1.0.0", "semantic_status": "SUCCEEDED"}\n'
)


class FinalizationCrash(BaseException):
    """Raised by ``CrashingProbe`` at its point: a ``BaseException`` so the
    finalizer's ``except Exception`` boundary never absorbs it, exactly as a
    killed process would leave the durable state (plan 4.3)."""


class CrashingProbe:
    """Raise ``FinalizationCrash`` at ``point`` (and, for the two indexed points,
    at ``index``); every other point is a no-op. Satisfies ``FinalizationProbe``."""

    def __init__(self, point: str, index: int = 0) -> None:
        self.point = point
        self.index = index
        self.reached: list[str] = []

    def _at(self, point: str, index: int | None = None) -> None:
        label = point if index is None else f"{point}:{index}"
        self.reached.append(label)
        if point == self.point and (index is None or index == self.index):
            raise FinalizationCrash(label)

    def before_prepared(self) -> None:
        self._at("before_prepared")

    def after_prepared(self) -> None:
        self._at("after_prepared")

    def before_move(self, index: int) -> None:
        self._at("before_move", index)

    def after_move(self, index: int) -> None:
        self._at("after_move", index)

    def before_moved(self) -> None:
        self._at("before_moved")

    def after_moved(self) -> None:
        self._at("after_moved")

    def before_registered(self) -> None:
        self._at("before_registered")

    def inside_registered(self) -> None:
        self._at("inside_registered")

    def after_registered(self) -> None:
        self._at("after_registered")

    def after_close(self) -> None:
        self._at("after_close")


class RecordingProbe:
    """Record every probe point in call order (``before_move:0`` for the indexed
    ones); never raises. Satisfies ``FinalizationProbe``."""

    def __init__(self) -> None:
        self.reached: list[str] = []

    def before_prepared(self) -> None:
        self.reached.append("before_prepared")

    def after_prepared(self) -> None:
        self.reached.append("after_prepared")

    def before_move(self, index: int) -> None:
        self.reached.append(f"before_move:{index}")

    def after_move(self, index: int) -> None:
        self.reached.append(f"after_move:{index}")

    def before_moved(self) -> None:
        self.reached.append("before_moved")

    def after_moved(self) -> None:
        self.reached.append("after_moved")

    def before_registered(self) -> None:
        self.reached.append("before_registered")

    def inside_registered(self) -> None:
        self.reached.append("inside_registered")

    def after_registered(self) -> None:
        self.reached.append("after_registered")

    def after_close(self) -> None:
        self.reached.append("after_close")


class FlagCancellationToken:
    """A ``CancellationToken`` double: a flag set by ``request_cancellation``."""

    def __init__(self, *, requested: bool = False) -> None:
        self._requested = requested
        self.polls = 0

    def is_cancellation_requested(self) -> bool:
        self.polls += 1
        return self._requested

    def request_cancellation(self) -> None:
        self._requested = True


def run_coroutine[T](coroutine: Coroutine[Any, Any, T]) -> T:
    """The ``send(None)`` driver of plan 2.7: step the coroutine until it returns.

    No event loop: every suspension point is a ``cooperative_checkpoint`` whose
    ``__await__`` yields exactly once, so each ``send(None)`` resumes the
    finalizer at the next phase boundary.
    """
    try:
        while True:
            coroutine.send(None)
    except StopIteration as stop:
        value: T = stop.value
        return value


def count_checkpoints[T](coroutine: Coroutine[Any, Any, T]) -> tuple[T, int]:
    """Drive the coroutine and count its suspension points."""
    yields = 0
    try:
        while True:
            coroutine.send(None)
            yields += 1
    except StopIteration as stop:
        value: T = stop.value
        return value, yields


class RecordingLog:
    """A ``FinalizationLog`` double recording every ``LogFact``."""

    def __init__(self) -> None:
        self.facts: list[LogFact] = []

    def write(self, fact: LogFact) -> Result[None]:
        self.facts.append(fact)
        return _none()


# -- The store's Task 6 tables ---------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class MemoryResultLeaseFacts:
    """The memory double's ``ResultLeaseFacts`` value (the port's read-only shape)."""

    run_id: str
    run_invocation_id: str
    experiment_id: str
    run_state: EngineRunState
    run_revision: int
    attempt_token_hash: str
    deadline_snapshotted: bool
    invocation_state: CommandInvocationState
    invocation_revision: int
    command_kind: CommandKind
    process_exit_category: ProcessExitCategory | MISSING  # type: ignore[valid-type]
    experiment_state: ExperimentState | MISSING  # type: ignore[valid-type]
    is_latest_attempt: bool


@dataclass(frozen=True, slots=True, kw_only=True)
class MemoryRunArtifactLink:
    """A ``RunArtifactLink``-shaped value for the memory registrar's links."""

    run_id: str
    artifact_id: str
    link_role: str
    experiment_id: str
    run_manifest_id: str | MISSING  # type: ignore[valid-type]


@dataclass(slots=True)
class MemoryTables:
    """The Task 6 tables beside the candidates and references of
    ``MemoryArtifactStore``; one instance per store, copied per transaction."""

    journal: dict[str, FinalizationJournalEntry] = field(default_factory=dict)
    runs: dict[str, EngineRunRecord] = field(default_factory=dict)
    invocations: dict[str, CommandInvocationRecord] = field(default_factory=dict)
    experiments: dict[str, ExperimentState] = field(default_factory=dict)
    run_manifests: dict[str, RunManifestFacts] = field(default_factory=dict)
    sanitized_manifests: dict[str, SanitizedManifestFacts] = field(default_factory=dict)
    validation_results: dict[str, ValidationResultFacts] = field(default_factory=dict)
    run_artifacts: dict[tuple[str, str, str], RunArtifactLink] = field(
        default_factory=dict
    )
    audit_events: list[AuditEvent] = field(default_factory=list)
    diagnostics: dict[str, Diagnostic] = field(default_factory=dict)

    def copy(self) -> MemoryTables:
        return MemoryTables(
            journal=dict(self.journal),
            runs=dict(self.runs),
            invocations=dict(self.invocations),
            experiments=dict(self.experiments),
            run_manifests=dict(self.run_manifests),
            sanitized_manifests=dict(self.sanitized_manifests),
            validation_results=dict(self.validation_results),
            run_artifacts=dict(self.run_artifacts),
            audit_events=list(self.audit_events),
            diagnostics=dict(self.diagnostics),
        )


def _tables_of(store: MemoryArtifactStore) -> MemoryTables:
    return store.tables


def _snapshot_store(store: MemoryArtifactStore) -> MemoryArtifactStore:
    """A transaction's copy-on-write view: the same clock, copied dicts."""
    view = MemoryArtifactStore(store.clock)
    view.candidates = dict(store.candidates)
    view.refs = dict(store.refs)
    view.tables = store.tables.copy()
    return view


def _publish_store(view: MemoryArtifactStore, into: MemoryArtifactStore) -> None:
    into.candidates = view.candidates
    into.refs = view.refs
    into.tables = view.tables


# -- The journal, lease, run, invocation and facts doubles -------------------------


class MemoryFinalizationJournalRepository:
    """``FinalizationJournalRepository`` over the store, with the SQLite answers:
    a missing identity is the invariant; a duplicate identity, a second RESULT
    journal for one invocation and source hash, a second active RESULT lease for
    one run and a second EVIDENCE identity are the conflict; a stale revision
    and a missing compare-and-swap row are the conflict; a wrong step or a
    refused journal edge is the invariant."""

    def __init__(self, store: MemoryArtifactStore) -> None:
        self._store = store
        self._tables = _tables_of(store)

    def get(self, finalization_id: str) -> Result[FinalizationJournalEntry]:
        entry = self._tables.journal.get(finalization_id)
        if entry is None:
            return self._store.missing("finalization", finalization_id)
        return Success[FinalizationJournalEntry](outcome="SUCCESS", value=entry)

    def prepare(self, entry: FinalizationJournalEntry) -> Result[None]:
        if entry.state is not _J.PREPARED:
            return self._store.invariant(
                f"finalization {entry.finalization_id} must be prepared in state "
                f"PREPARED, not {entry.state.value}"
            )
        if entry.finalization_id in self._tables.journal:
            return self._store.conflict(
                f"finalization {entry.finalization_id} is already prepared"
            )
        for other in self._tables.journal.values():
            if other.finalization_purpose is not entry.finalization_purpose:
                continue
            if entry.finalization_purpose is _F.RESULT:
                if (
                    other.run_invocation_id == entry.run_invocation_id
                    and other.source_adapter_result_manifest_hash
                    == entry.source_adapter_result_manifest_hash
                ):
                    return self._store.conflict(
                        "a RESULT journal already names this invocation and source"
                    )
                if other.run_id == entry.run_id and other.state in (
                    _J.PREPARED,
                    _J.MOVED,
                ):
                    return self._store.conflict(
                        f"run {entry.run_id} already holds an active RESULT lease"
                    )
            elif (
                artifact_owner_hash(other.owner) == artifact_owner_hash(entry.owner)
                and other.correlation == entry.correlation
                and other.candidate_set_hash == entry.candidate_set_hash
            ):
                return self._store.conflict(
                    "an EVIDENCE journal already names this owner, correlation and set"
                )
        self._tables.journal[entry.finalization_id] = entry
        return _none()

    def compare_and_swap(
        self, expected_revision: int, replacement: FinalizationJournalEntry
    ) -> Result[FinalizationJournalEntry]:
        identity = replacement.finalization_id
        stored = self._tables.journal.get(identity)
        if stored is None:
            return self._store.conflict(
                f"finalization {identity} does not exist for compare-and-swap"
            )
        if stored.revision != expected_revision:
            return self._store.conflict(
                f"finalization {identity} is at revision {stored.revision}, "
                f"not {expected_revision}"
            )
        if replacement.revision != expected_revision + 1:
            return self._store.invariant(
                f"finalization replacement must carry revision {expected_revision + 1}"
            )
        try:
            assert_journal_transition(stored, replacement)
        except FinalizationJournalRuleViolation as violation:
            return self._store.invariant(str(violation))
        self._tables.journal[identity] = replacement
        return Success[FinalizationJournalEntry](outcome="SUCCESS", value=replacement)

    def list_open(
        self,
        purpose: ArtifactFinalizationPurpose | MISSING = MISSING,  # type: ignore[valid-type]
        limit: int = _MAX_LISTING,
    ) -> Result[tuple[FinalizationJournalEntry, ...]]:
        entries = sorted(
            (
                entry
                for entry in self._tables.journal.values()
                if entry.state in (_J.PREPARED, _J.MOVED)
                and (
                    not isinstance(purpose, ArtifactFinalizationPurpose)
                    or entry.finalization_purpose is purpose
                )
            ),
            key=lambda entry: (entry.prepared_at_utc, entry.finalization_id),
        )
        return Success[tuple[FinalizationJournalEntry, ...]](
            outcome="SUCCESS", value=tuple(entries[:limit])
        )

    def find_result_identity(
        self, run_invocation_id: str, source_hash: str
    ) -> Result[FinalizationJournalEntry | MISSING]:  # type: ignore[valid-type]
        for entry in self._tables.journal.values():
            if (
                entry.finalization_purpose is _F.RESULT
                and entry.run_invocation_id == run_invocation_id
                and entry.source_adapter_result_manifest_hash == source_hash
            ):
                return Success[FinalizationJournalEntry](outcome="SUCCESS", value=entry)
        return _absent()

    def find_evidence_identity(
        self, owner_hash: str, kind: str, correlation_id: str, set_hash: str
    ) -> Result[FinalizationJournalEntry | MISSING]:  # type: ignore[valid-type]
        for entry in self._tables.journal.values():
            correlation = entry.correlation
            if (
                entry.finalization_purpose is _F.EVIDENCE
                and isinstance(correlation, EvidenceCorrelation)
                and artifact_owner_hash(entry.owner) == owner_hash
                and correlation.kind == kind
                and correlation.correlation_id == correlation_id
                and entry.candidate_set_hash == set_hash
            ):
                return Success[FinalizationJournalEntry](outcome="SUCCESS", value=entry)
        return _absent()


def _absent() -> Success[Any]:
    nothing: Any = MISSING
    return Success(outcome="SUCCESS", value=nothing)


def _facts(value: object) -> Success[Any]:
    """A facts row answered as stored. The facts views of ``artifacts.ports`` are
    plain ``Protocol`` types, which pydantic cannot schematize as a ``Success``
    parameter, so the answer is typed ``Any`` exactly as ``_absent`` is."""
    facts: Any = value
    return Success(outcome="SUCCESS", value=facts)


class MemoryEngineRunRecords:
    """``EngineRunRecords`` over the planted runs, with the Stage 8 compare-and-swap
    answers and the reading-11 refusal: a swap into a success state requires a
    ``run_manifests`` row for the run (``refuse_success_without_manifest``), and a
    present ``finalization_deadline_utc`` never changes (the immutability trigger).
    """

    def __init__(self, store: MemoryArtifactStore) -> None:
        self._store = store
        self._tables = _tables_of(store)

    def get(self, run_id: str) -> Result[EngineRunRecord]:
        record = self._tables.runs.get(run_id)
        if record is None:
            return self._store.missing("run", run_id)
        return Success[EngineRunRecord](outcome="SUCCESS", value=record)

    def compare_and_swap(
        self, expected_revision: int, replacement: EngineRunRecord
    ) -> Result[EngineRunRecord]:
        identity = replacement.run_id
        stored = self._tables.runs.get(identity)
        if stored is None:
            return self._store.conflict(
                f"run {identity} does not exist for compare-and-swap"
            )
        if stored.revision != expected_revision:
            return self._store.conflict(
                f"run {identity} is at revision {stored.revision}, "
                f"not {expected_revision}"
            )
        if replacement.revision != expected_revision + 1:
            return self._store.invariant(
                f"run replacement must carry revision {expected_revision + 1}"
            )
        if (
            replacement.state in SUCCESS_ENGINE_RUN_STATES
            and identity not in self._tables.run_manifests
        ):
            return self._store.invariant(
                f"run {identity} cannot reach a success state without a run manifest"
            )
        if (
            isinstance(stored.finalization_deadline_utc, datetime)
            and replacement.finalization_deadline_utc
            != stored.finalization_deadline_utc
        ):
            return self._store.invariant(
                f"run {identity} finalization deadline is immutable once set"
            )
        self._tables.runs[identity] = replacement
        return Success[EngineRunRecord](outcome="SUCCESS", value=replacement)


class MemoryCommandInvocationRecords:
    """``CommandInvocationRecords`` over the planted invocations; the
    ``stderr_artifact_id`` enrichment is write-once and must name a committed
    ``CORE_EVIDENCE`` reference of a ``RUN`` owner of the same run or of an
    ``ADAPTER`` owner for a ``DESCRIBE`` (reading 10)."""

    def __init__(self, store: MemoryArtifactStore) -> None:
        self._store = store
        self._tables = _tables_of(store)

    def get(self, invocation_id: str) -> Result[CommandInvocationRecord]:
        record = self._tables.invocations.get(invocation_id)
        if record is None:
            return self._store.missing("invocation", invocation_id)
        return Success[CommandInvocationRecord](outcome="SUCCESS", value=record)

    def compare_and_swap(
        self, expected_revision: int, replacement: CommandInvocationRecord
    ) -> Result[CommandInvocationRecord]:
        identity = replacement.invocation_id
        stored = self._tables.invocations.get(identity)
        if stored is None:
            return self._store.conflict(
                f"invocation {identity} does not exist for compare-and-swap"
            )
        if stored.revision != expected_revision:
            return self._store.conflict(
                f"invocation {identity} is at revision {stored.revision}, "
                f"not {expected_revision}"
            )
        if replacement.revision != expected_revision + 1:
            return self._store.invariant(
                f"invocation replacement must carry revision {expected_revision + 1}"
            )
        enrichment = replacement.stderr_artifact_id
        if enrichment != stored.stderr_artifact_id:
            if isinstance(stored.stderr_artifact_id, str):
                return self._store.invariant(
                    f"invocation {identity} stderr_artifact_id is write-once"
                )
            refusal = self._stderr_refusal(stored, enrichment)
            if refusal is not None:
                return refusal
        self._tables.invocations[identity] = replacement
        return Success[CommandInvocationRecord](outcome="SUCCESS", value=replacement)

    def _stderr_refusal(
        self, invocation: CommandInvocationRecord, artifact_id: object
    ) -> Failure | None:
        stored = self._store.refs.get(str(artifact_id))
        if stored is None:
            return self._store.invariant(
                "stderr_artifact_id must name a committed reference"
            )
        ref = stored[0]
        owner = ref.owner
        if (
            ref.finalization_purpose is not _F.EVIDENCE
            or ref.producer_kind is not _P.CORE
            or ref.source_role is not _R.CORE_EVIDENCE
        ):
            return self._store.invariant(
                "stderr_artifact_id must name CORE_EVIDENCE of a CORE producer"
            )
        if invocation.command_kind is CommandKind.DESCRIBE:
            if not isinstance(owner, AdapterArtifactOwner):
                return self._store.invariant(
                    "a DESCRIBE stderr reference is ADAPTER-owned"
                )
        elif not isinstance(owner, RunArtifactOwner) or (
            owner.run_id != invocation.run_id
        ):
            return self._store.invariant(
                "a VALIDATE or RUN stderr reference is RUN-owned by the same run"
            )
        return None


class MemoryResultLeaseRepository:
    """``ResultLeaseRepository`` over the planted runs, invocations and
    experiment states: ``active_attempt_facts`` is a value object, the two
    writes mirror ``SqliteEngineRunRepository.snapshot_deadline`` and
    ``record_timeout`` step for step."""

    def __init__(self, store: MemoryArtifactStore) -> None:
        self._store = store
        self._tables = _tables_of(store)
        self._runs = MemoryEngineRunRecords(store)

    def active_attempt_facts(
        self, run_id: str, run_invocation_id: str
    ) -> Result[MemoryResultLeaseFacts]:
        loaded = self._runs.get(run_id)
        if isinstance(loaded, Failure):
            return loaded
        run = loaded.value
        invocation = self._tables.invocations.get(run_invocation_id)
        if invocation is None:
            return self._store.missing("invocation", run_invocation_id)
        if invocation.run_id != run_id:
            return self._store.invariant(
                f"invocation {run_invocation_id} is not linked to run {run_id}"
            )
        siblings = [
            record
            for record in self._tables.runs.values()
            if record.experiment_id == run.experiment_id
            and record.logical_slot_id == run.logical_slot_id
        ]
        latest = max(siblings, key=lambda record: record.attempt_number)
        experiment_state = self._tables.experiments.get(run.experiment_id, MISSING)
        return Success[MemoryResultLeaseFacts](
            outcome="SUCCESS",
            value=MemoryResultLeaseFacts(
                run_id=run_id,
                run_invocation_id=run_invocation_id,
                experiment_id=run.experiment_id,
                run_state=run.state,
                run_revision=run.revision,
                attempt_token_hash=run.attempt_token_hash,
                deadline_snapshotted=isinstance(
                    run.finalization_deadline_utc, datetime
                ),
                invocation_state=invocation.state,
                invocation_revision=invocation.revision,
                command_kind=invocation.command_kind,
                process_exit_category=invocation.process_exit_category,
                experiment_state=experiment_state,
                is_latest_attempt=latest.run_id == run_id,
            ),
        )

    def snapshot_deadline(
        self, expected_run_revision: int, run_id: str, deadline_utc: datetime
    ) -> Result[EngineRunRecord]:
        loaded = self._runs.get(run_id)
        if isinstance(loaded, Failure):
            return loaded
        current = loaded.value
        if current.revision != expected_run_revision:
            return self._store.conflict(
                f"run {run_id} is at revision {current.revision}, "
                f"not {expected_run_revision}"
            )
        payload = current.model_dump(mode="python")
        payload["finalization_deadline_utc"] = deadline_utc
        payload["revision"] = current.revision + 1
        payload["updated_at_utc"] = max(
            current.updated_at_utc, self._store.clock.now_utc()
        )
        try:
            replacement = EngineRunRecord.model_validate(payload)
            assert_deadline_snapshot(current, replacement)
        except (ValidationError, EngineRunRuleViolation) as violation:
            return self._store.invariant(
                f"run {run_id} admits no deadline snapshot: {violation}"
            )
        return self._runs.compare_and_swap(expected_run_revision, replacement)

    def record_timeout(
        self, expected_run_revision: int, run_id: str, diagnostic: Diagnostic
    ) -> Result[EngineRunRecord]:
        if diagnostic.category.value != "TIMEOUT" or not isinstance(
            diagnostic.invocation_id, str
        ):
            return self._store.invariant(
                f"run {run_id} timeout requires a TIMEOUT diagnostic naming its "
                "invocation"
            )
        loaded = self._runs.get(run_id)
        if isinstance(loaded, Failure):
            return loaded
        current = loaded.value
        if current.revision != expected_run_revision:
            return self._store.conflict(
                f"run {run_id} is at revision {current.revision}, "
                f"not {expected_run_revision}"
            )
        payload = current.model_dump(mode="python")
        payload["state"] = _RS.TIMED_OUT
        payload["primary_terminal_diagnostic_id"] = diagnostic.diagnostic_id
        payload["revision"] = current.revision + 1
        payload["updated_at_utc"] = max(
            current.updated_at_utc, self._store.clock.now_utc()
        )
        try:
            replacement = EngineRunRecord.model_validate(payload)
            assert_run_transition(current, replacement)
        except (ValidationError, EngineRunRuleViolation) as violation:
            return self._store.invariant(
                f"run {run_id} admits no finalization timeout: {violation}"
            )
        return self._runs.compare_and_swap(expected_run_revision, replacement)


class MemoryRunManifestRepository:
    """``RunManifestRepository`` double: insert-only, and the reading-11 trigger
    restated -- the run must be ``RUNNING`` with a deadline and its run-command
    invocation ``EXITED``."""

    def __init__(self, store: MemoryArtifactStore) -> None:
        self._store = store
        self._tables = _tables_of(store)

    def add(self, facts: RunManifestFacts) -> Result[None]:
        if facts.run_id in self._tables.run_manifests or any(
            stored.manifest_id == facts.manifest_id
            or stored.run_manifest_hash == facts.run_manifest_hash
            for stored in self._tables.run_manifests.values()
        ):
            return self._store.conflict(
                f"run manifest {facts.manifest_id} is already registered"
            )
        run = self._tables.runs.get(facts.run_id)
        invocation = self._tables.invocations.get(facts.run_invocation_id)
        if (
            run is None
            or run.state is not _RS.RUNNING
            or not isinstance(run.finalization_deadline_utc, datetime)
            or invocation is None
            or invocation.state is not _C.EXITED
            or invocation.command_kind is not CommandKind.RUN
            or invocation.run_id != facts.run_id
            or run.attempt_token_hash != facts.attempt_token_hash
        ):
            return self._store.invariant(
                f"run manifest {facts.manifest_id} requires a RUNNING run with a "
                "deadline and its EXITED run-command invocation"
            )
        self._tables.run_manifests[facts.run_id] = facts
        return _none()

    def get(self, run_id: str) -> Result[RunManifestFacts | MISSING]:  # type: ignore[valid-type]
        facts = self._tables.run_manifests.get(run_id)
        if facts is None:
            return _absent()
        return _facts(facts)


class MemorySanitizedManifestRepository:
    """``SanitizedManifestRepository`` double: insert-once, evidence linked once
    to a ``RUN``-owned ``EVIDENCE`` reference of the same run."""

    def __init__(self, store: MemoryArtifactStore) -> None:
        self._store = store
        self._tables = _tables_of(store)

    def add(self, facts: SanitizedManifestFacts) -> Result[None]:
        key = facts.sanitized_adapter_result_manifest_hash
        if key in self._tables.sanitized_manifests:
            return self._store.conflict(f"sanitized manifest {key} is already recorded")
        invocation = self._tables.invocations.get(facts.run_invocation_id)
        if invocation is None or invocation.run_id != facts.run_id:
            return self._store.invariant(
                f"sanitized manifest {key} names no invocation of run {facts.run_id}"
            )
        self._tables.sanitized_manifests[key] = facts
        return _none()

    def get(
        self, sanitized_adapter_result_manifest_hash: str
    ) -> Result[SanitizedManifestFacts | MISSING]:  # type: ignore[valid-type]
        facts = self._tables.sanitized_manifests.get(
            sanitized_adapter_result_manifest_hash
        )
        if facts is None:
            return _absent()
        return _facts(facts)

    def link_evidence(
        self, sanitized_adapter_result_manifest_hash: str, artifact_id: str
    ) -> Result[None]:
        key = sanitized_adapter_result_manifest_hash
        facts = self._tables.sanitized_manifests.get(key)
        if facts is None or isinstance(facts.evidence_artifact_id, str):
            return self._store.conflict(
                f"sanitized_adapter_result_manifests row {key} was not linked "
                "(absent or already linked)"
            )
        refusal = _run_evidence_refusal(self._store, artifact_id, facts.run_id)
        if refusal is not None:
            return refusal
        linked = _LinkedSanitizedFacts(facts, artifact_id)
        self._tables.sanitized_manifests[key] = linked
        return _none()


class MemoryValidationResultRepository:
    """``ValidationResultRepository`` double: insert-once, evidence linked once."""

    def __init__(self, store: MemoryArtifactStore) -> None:
        self._store = store
        self._tables = _tables_of(store)

    def add(self, facts: ValidationResultFacts) -> Result[None]:
        key = facts.invocation_id
        if key in self._tables.validation_results:
            return self._store.conflict(
                f"validation result for {key} is already recorded"
            )
        invocation = self._tables.invocations.get(key)
        if (
            invocation is None
            or invocation.command_kind is not CommandKind.VALIDATE
            or invocation.run_id != facts.run_id
        ):
            return self._store.invariant(
                f"validation result {key} requires a VALIDATE invocation of its run"
            )
        self._tables.validation_results[key] = facts
        return _none()

    def get(self, invocation_id: str) -> Result[ValidationResultFacts | MISSING]:  # type: ignore[valid-type]
        facts = self._tables.validation_results.get(invocation_id)
        if facts is None:
            return _absent()
        return _facts(facts)

    def link_evidence(self, invocation_id: str, artifact_id: str) -> Result[None]:
        facts = self._tables.validation_results.get(invocation_id)
        if facts is None or isinstance(facts.evidence_artifact_id, str):
            return self._store.conflict(
                f"adapter_validation_results row {invocation_id} was not linked "
                "(absent or already linked)"
            )
        refusal = _run_evidence_refusal(self._store, artifact_id, facts.run_id)
        if refusal is not None:
            return refusal
        self._tables.validation_results[invocation_id] = _LinkedValidationFacts(
            facts, artifact_id
        )
        return _none()


@dataclass(frozen=True, slots=True)
class _LinkedSanitizedFacts:
    """``facts`` with ``evidence_artifact_id`` set (a frozen view's one write)."""

    inner: SanitizedManifestFacts
    linked: str

    @property
    def sanitized_adapter_result_manifest_hash(self) -> str:
        return self.inner.sanitized_adapter_result_manifest_hash

    @property
    def run_id(self) -> str:
        return self.inner.run_id

    @property
    def run_invocation_id(self) -> str:
        return self.inner.run_invocation_id

    @property
    def experiment_id(self) -> str:
        return self.inner.experiment_id

    @property
    def attempt_token_hash(self) -> str:
        return self.inner.attempt_token_hash

    @property
    def source_adapter_result_manifest_hash(self) -> str:
        return self.inner.source_adapter_result_manifest_hash

    @property
    def semantic_status(self) -> str:
        return self.inner.semantic_status

    @property
    def manifest_json(self) -> str:
        return self.inner.manifest_json

    @property
    def evidence_artifact_id(self) -> str:
        return self.linked

    @property
    def recorded_at_utc(self) -> datetime:
        return self.inner.recorded_at_utc


@dataclass(frozen=True, slots=True)
class _LinkedValidationFacts:
    """``facts`` with ``evidence_artifact_id`` set."""

    inner: ValidationResultFacts
    linked: str

    @property
    def invocation_id(self) -> str:
        return self.inner.invocation_id

    @property
    def run_id(self) -> str:
        return self.inner.run_id

    @property
    def experiment_id(self) -> str:
        return self.inner.experiment_id

    @property
    def validation_result_hash(self) -> str:
        return self.inner.validation_result_hash

    @property
    def outcome(self) -> str:
        return self.inner.outcome

    @property
    def result_json(self) -> str:
        return self.inner.result_json

    @property
    def evidence_artifact_id(self) -> str:
        return self.linked

    @property
    def recorded_at_utc(self) -> datetime:
        return self.inner.recorded_at_utc


def _run_evidence_refusal(
    store: MemoryArtifactStore, artifact_id: str, run_id: str
) -> Failure | None:
    stored = store.refs.get(artifact_id)
    if stored is None:
        return store.invariant(f"artifact {artifact_id} does not exist")
    ref = stored[0]
    if (
        ref.finalization_purpose is not _F.EVIDENCE
        or not isinstance(ref.owner, RunArtifactOwner)
        or ref.owner.run_id != run_id
    ):
        return store.invariant(
            f"artifact {artifact_id} is not RUN-owned EVIDENCE of run {run_id}"
        )
    return None


class MemoryRunArtifactRepository:
    """``RunArtifactRepository`` double with the ``run_artifacts_target_run_owner``
    and ``run_artifacts_member_requires_manifest`` rules restated: the reference
    is ``RUN``-owned by the same run and experiment; a ``RESULT_MANIFEST_MEMBER``
    names a ``RESULT`` reference and an existing manifest; ``RUN_EVIDENCE`` an
    ``EVIDENCE`` reference."""

    def __init__(self, store: MemoryArtifactStore) -> None:
        self._store = store
        self._tables = _tables_of(store)

    def link(self, link: RunArtifactLink) -> Result[None]:
        if link.link_role not in _RUN_ARTIFACT_LINK_ROLES:
            return self._store.invariant(
                f"{link.link_role} is not a run artifact link role"
            )
        key = (link.run_id, link.artifact_id, link.link_role)
        if key in self._tables.run_artifacts:
            return self._store.conflict(
                f"artifact {link.artifact_id} is already linked to run {link.run_id}"
            )
        stored = self._store.refs.get(link.artifact_id)
        if stored is None:
            return self._store.invariant(f"artifact {link.artifact_id} does not exist")
        ref = stored[0]
        owner = ref.owner
        if (
            not isinstance(owner, RunArtifactOwner)
            or owner.run_id != link.run_id
            or owner.experiment_id != link.experiment_id
        ):
            return self._store.invariant(
                f"artifact {link.artifact_id} is not owned by run {link.run_id}"
            )
        manifest = link.run_manifest_id
        if link.link_role == "RESULT_MANIFEST_MEMBER":
            if ref.finalization_purpose is not _F.RESULT:
                return self._store.invariant(
                    "a RESULT_MANIFEST_MEMBER link names a RESULT reference"
                )
            if not isinstance(manifest, str) or not any(
                facts.manifest_id == manifest
                for facts in self._tables.run_manifests.values()
            ):
                return self._store.invariant(
                    "a RESULT_MANIFEST_MEMBER link requires its run manifest"
                )
        elif ref.finalization_purpose is not _F.EVIDENCE:
            return self._store.invariant(
                "a RUN_EVIDENCE link names an EVIDENCE reference"
            )
        self._tables.run_artifacts[key] = link
        return _none()

    def list_for_run(self, run_id: str) -> Result[tuple[RunArtifactLink, ...]]:
        links = sorted(
            (
                link
                for (linked_run, _, _), link in self._tables.run_artifacts.items()
                if linked_run == run_id
            ),
            key=lambda link: (link.link_role, link.artifact_id),
        )
        return Success[tuple[RunArtifactLink, ...]](
            outcome="SUCCESS", value=tuple(links)
        )


class MemoryDiagnosticWriter:
    """``DiagnosticWriter`` double: idempotent on identity, refusing a same-identity
    re-record with different content."""

    def __init__(self, store: MemoryArtifactStore) -> None:
        self._store = store
        self._tables = _tables_of(store)

    def record(self, diagnostic: Diagnostic) -> Result[None]:
        stored = self._tables.diagnostics.get(diagnostic.diagnostic_id)
        if stored is not None:
            if stored.model_dump(mode="json", exclude={"timestamp_utc"}) != (
                diagnostic.model_dump(mode="json", exclude={"timestamp_utc"})
            ):
                return self._store.invariant(
                    f"diagnostic {diagnostic.diagnostic_id} is already recorded with "
                    "different content"
                )
            return _none()
        self._tables.diagnostics[diagnostic.diagnostic_id] = diagnostic
        return _none()


class MemoryAuditSink:
    """``AuditSink``/``AuditAppender`` double joining the transaction: a duplicate
    identity is the conflict, a present ``run_id`` must name a planted run (the
    Task 5 ingress reading), and the sequence is the position in the committed
    list."""

    def __init__(self, store: MemoryArtifactStore) -> None:
        self._store = store
        self._tables = _tables_of(store)

    def append(self, event: AuditEvent) -> Result[None]:
        if not isinstance(event, AuditEvent):
            return self._store.invariant("the audit sink appends AuditEvent records")
        if any(
            stored.audit_event_id == event.audit_event_id
            for stored in self._tables.audit_events
        ):
            return self._store.conflict(
                f"audit event {event.audit_event_id} is already appended"
            )
        run_id = event.run_id
        if isinstance(run_id, str) and run_id not in self._tables.runs:
            return self._store.invariant(
                f"audit event {event.audit_event_id} references run {run_id}, "
                "which does not exist"
            )
        self._tables.audit_events.append(event)
        return _none()


# -- The unit of work -------------------------------------------------------------


class MemoryFinalizationTransaction:
    """One open transaction over a copy-on-write view of the shared store; it
    satisfies ``FinalizationUnitOfWork`` and ``RegistrationUnitOfWork``
    structurally. ``commit()`` publishes the view (or answers the stored failure
    a test injected), ``rollback()`` discards it; both release."""

    def __init__(
        self,
        root: MemoryFinalizationUnitOfWork,
        view: MemoryArtifactStore,
        *,
        commit_failure: Failure | None,
    ) -> None:
        self._root = root
        self._view = view
        self._finished = False
        self._commit_failure = commit_failure
        self._candidate_artifacts = MemoryCandidateArtifactRepository(view)
        self._artifact_refs = MemoryArtifactRepository(
            view, reference_lookup_failure=root.take_pending_reference_lookup_failure
        )
        self._finalization_journal = MemoryFinalizationJournalRepository(view)
        self._result_leases = MemoryResultLeaseRepository(view)
        self._engine_runs = MemoryEngineRunRecords(view)
        self._command_invocations = MemoryCommandInvocationRecords(view)
        self._run_manifests = MemoryRunManifestRepository(view)
        self._sanitized_manifests = MemorySanitizedManifestRepository(view)
        self._validation_results = MemoryValidationResultRepository(view)
        self._run_artifacts = MemoryRunArtifactRepository(view)
        self._diagnostics_writer = MemoryDiagnosticWriter(view)
        self._audit = MemoryAuditSink(view)

    def _require_live(self) -> None:
        if self._finished:
            raise RuntimeError("the transaction is closed")

    def begin(self) -> MemoryFinalizationTransaction:
        raise RuntimeError(
            "nested transactions are not supported: begin() is valid on the root "
            "unit of work only"
        )

    def commit(self) -> Result[None]:
        self._require_live()
        self._finished = True
        self._root.forget(self)
        failure = self._commit_failure
        if failure is None:
            failure = self._root.take_pending_commit_failure()
        if failure is not None:
            return failure
        _publish_store(self._view, self._root.store)
        return _none()

    def rollback(self) -> None:
        if self._finished:
            return
        self._finished = True
        self._root.forget(self)

    def open_failure(self) -> Failure | None:
        return None

    @property
    def candidate_artifacts(self) -> MemoryCandidateArtifactRepository:
        self._require_live()
        return self._candidate_artifacts

    @property
    def artifact_refs(self) -> MemoryArtifactRepository:
        self._require_live()
        return self._artifact_refs

    @property
    def finalization_journal(self) -> MemoryFinalizationJournalRepository:
        self._require_live()
        return self._finalization_journal

    @property
    def result_leases(self) -> MemoryResultLeaseRepository:
        self._require_live()
        return self._result_leases

    @property
    def engine_runs(self) -> MemoryEngineRunRecords:
        self._require_live()
        return self._engine_runs

    @property
    def command_invocations(self) -> MemoryCommandInvocationRecords:
        self._require_live()
        return self._command_invocations

    @property
    def run_manifests(self) -> MemoryRunManifestRepository:
        self._require_live()
        return self._run_manifests

    @property
    def sanitized_manifests(self) -> MemorySanitizedManifestRepository:
        self._require_live()
        return self._sanitized_manifests

    @property
    def validation_results(self) -> MemoryValidationResultRepository:
        self._require_live()
        return self._validation_results

    @property
    def run_artifacts(self) -> MemoryRunArtifactRepository:
        self._require_live()
        return self._run_artifacts

    @property
    def diagnostics_writer(self) -> MemoryDiagnosticWriter:
        self._require_live()
        return self._diagnostics_writer

    @property
    def audit(self) -> MemoryAuditSink:
        self._require_live()
        return self._audit


class MemoryFinalizationUnitOfWork:
    """The in-memory root (plan 7.1): ``begin()`` opens one copy-on-write
    transaction, ``open_transactions()`` lists the unreleased ones and
    ``max_open`` records the most ever open at once -- the harness's measure that
    no transaction spans hashing or a move (``max_open == 0`` while those
    phases run). ``fail_next_commit`` injects one commit failure into the next
    *begun* transaction, the memory twin of the Stage 8 dialect fault at
    ``do_commit``; ``fail_next_committed`` injects it into the next transaction
    that actually reaches ``commit()``, so the read-only transactions a pass
    opens and rolls back first do not consume it; ``fail_next_reference_lookup``
    injects a read failure into the next ``artifact_refs.list_by_content_hash``
    call of any transaction, the memory twin of the Stage 8 cursor fault at that
    one statement (Task 6, RV-9)."""

    def __init__(self, store: MemoryArtifactStore) -> None:
        self.store = store
        self._open: list[MemoryFinalizationTransaction] = []
        self.max_open = 0
        self.begun = 0
        self._next_commit_failure: Failure | None = None
        self._pending_commit_failure: Failure | None = None
        self._pending_reference_lookup_failure: Failure | None = None

    def fail_next_commit(self, failure: Failure) -> None:
        self._next_commit_failure = failure

    def fail_next_committed(self, failure: Failure) -> None:
        self._pending_commit_failure = failure

    def fail_next_reference_lookup(self, failure: Failure) -> None:
        self._pending_reference_lookup_failure = failure

    def take_pending_commit_failure(self) -> Failure | None:
        failure = self._pending_commit_failure
        self._pending_commit_failure = None
        return failure

    def take_pending_reference_lookup_failure(self) -> Failure | None:
        failure = self._pending_reference_lookup_failure
        self._pending_reference_lookup_failure = None
        return failure

    def begin(self) -> MemoryFinalizationTransaction:
        failure = self._next_commit_failure
        self._next_commit_failure = None
        transaction = MemoryFinalizationTransaction(
            self, _snapshot_store(self.store), commit_failure=failure
        )
        self._open.append(transaction)
        self.begun += 1
        self.max_open = max(self.max_open, len(self._open))
        return transaction

    def forget(self, transaction: MemoryFinalizationTransaction) -> None:
        self._open = [item for item in self._open if item is not transaction]

    def open_transactions(self) -> tuple[MemoryFinalizationTransaction, ...]:
        return tuple(self._open)

    def reset_max_open(self) -> None:
        self.max_open = len(self._open)


# -- The registrar, the recovery validator and the auditor -----------------------


class MemoryRegistrar:
    """The Task 6 ``PurposeRegistrar`` double: ``register_evidence`` records the
    ``RUN_EVIDENCE`` links of ``RUN`` owners and the write-once
    ``stderr_artifact_id`` enrichment through the open transaction;
    ``register_result`` refuses every call with ``CORE.INVARIANT_VIOLATION`` and
    records nothing, so a successful RESULT registration is unreachable through
    this double (plan 7.1; the production registrar is Task 7's)."""

    def __init__(self) -> None:
        self.result_calls = 0
        self.evidence_calls = 0

    def register_result(
        self,
        transaction: RegistrationUnitOfWork,
        journal: FinalizationJournalEntry,
        refs: tuple[ArtifactRef, ...],
        facts: object,
    ) -> Result[ResultRegistration]:
        del transaction, refs, facts
        self.result_calls += 1
        return stage5_failure(
            INVARIANT_VIOLATION,
            f"the Task 6 memory registrar registers no RESULT finalization "
            f"({journal.finalization_id}); the production registrar is Task 7's",
            source_component=ARTIFACT_DOUBLE_COMPONENT,
            timestamp_utc=journal.updated_at_utc,
        )

    def register_evidence(
        self,
        transaction: RegistrationUnitOfWork,
        journal: FinalizationJournalEntry,
        refs: tuple[ArtifactRef, ...],
    ) -> Result[None]:
        self.evidence_calls += 1
        owner = journal.owner
        for ref in refs:
            if isinstance(owner, RunArtifactOwner):
                linked = transaction.run_artifacts.link(
                    MemoryRunArtifactLink(
                        run_id=owner.run_id,
                        artifact_id=ref.artifact_id,
                        link_role="RUN_EVIDENCE",
                        experiment_id=owner.experiment_id,
                        run_manifest_id=MISSING,
                    )
                )
                if isinstance(linked, Failure):
                    return linked
            correlation = journal.correlation
            if ref.artifact_kind == CORE_KIND and isinstance(
                correlation, EvidenceCorrelation
            ):
                if correlation.kind != "INVOCATION":
                    continue
                enriched = _enrich_stderr(
                    transaction, correlation.correlation_id, ref.artifact_id
                )
                if isinstance(enriched, Failure):
                    return enriched
        return _none()


def _enrich_stderr(
    transaction: RegistrationUnitOfWork, invocation_id: str, artifact_id: str
) -> Result[None]:
    loaded = transaction.command_invocations.get(invocation_id)
    if isinstance(loaded, Failure):
        return loaded
    invocation = loaded.value
    if isinstance(invocation.stderr_artifact_id, str):
        return _none()
    payload = invocation.model_dump(mode="python")
    payload["stderr_artifact_id"] = artifact_id
    payload["revision"] = invocation.revision + 1
    replacement = CommandInvocationRecord.model_validate(payload)
    swapped = transaction.command_invocations.compare_and_swap(
        invocation.revision, replacement
    )
    if isinstance(swapped, Failure):
        return swapped
    return _none()


@dataclass(frozen=True, slots=True)
class ValidatorCall:
    """One ``validate_temporary_manifest`` call as the double saw it: the roots,
    whether token material was supplied (never the material) and the ids."""

    roots: CommandRootPaths
    token_supplied: bool
    candidate_ids: tuple[str, ...]


class MemoryRecoveryValidator:
    """The Task 6 ``ResultRecoveryValidator`` double: answers the planted
    ``Result`` (a Failure of ``ARTIFACT.RESULT_MANIFEST_INVALID`` until a test
    plants otherwise) and records every call without the token (plan 7.1; the
    production validator is Task 7's)."""

    def __init__(self, clock: Clock | None = None) -> None:
        self._clock: Clock = clock if clock is not None else FixedClock(INSTANT)
        self._planted: Result[ResultRecoveryFacts] | None = None
        self.calls: list[ValidatorCall] = []

    def plant(self, answer: Result[ResultRecoveryFacts]) -> None:
        self._planted = answer

    def validate_temporary_manifest(
        self,
        roots: CommandRootPaths,
        token: AttemptTokenMaterial | MISSING,  # type: ignore[valid-type]
        candidates: tuple[CandidateArtifact, ...],
    ) -> Result[ResultRecoveryFacts]:
        self.calls.append(
            ValidatorCall(
                roots=roots,
                token_supplied=isinstance(token, AttemptTokenMaterial),
                candidate_ids=tuple(
                    candidate.candidate_artifact_id for candidate in candidates
                ),
            )
        )
        if self._planted is not None:
            return self._planted
        return artifact_failure(
            ARTIFACT_RESULT_MANIFEST_INVALID,
            message=(
                "the Task 6 memory validator validates no temporary manifest; the "
                "production validator is Task 7's"
            ),
            now_utc=self._clock.now_utc(),
        )


class FactAuditor:
    """The Task 6 test-resident ``FinalizationAuditor``: turns an ``AuditFact``
    into an ``AuditEvent`` (identifier from ``ids``, instant from ``clock``, the
    ``CORE`` actor) and appends it through the transaction's ``audit`` member.
    The production twin lives beside the ``experiments`` composition (Task 7)."""

    def __init__(self, ids: AuditEventIds, clock: Clock) -> None:
        self._ids = ids
        self._clock = clock
        self.facts: list[AuditFact] = []

    def append(
        self, transaction: FinalizationUnitOfWork, fact: AuditFact
    ) -> Result[None]:
        self.facts.append(fact)
        payload: dict[str, Any] = {
            "schema_version": "1.0.0",
            "audit_event_id": self._ids.new_audit_event_id(),
            "action": AuditAction(fact.action),
            "actor": CORE_ACTOR,
            "outcome": AuditOutcome(fact.outcome),
            "experiment_id": fact.experiment_id,
            "run_id": fact.run_id,
            "invocation_id": fact.invocation_id,
            "artifact_id": fact.artifact_id,
            "timestamp_utc": self._clock.now_utc(),
            "correlation_id": fact.correlation_id,
            "details_hash": audit_details_hash(fact.details),
            "details": dict(fact.details),
        }
        event = AuditEvent.model_validate(_without_missing(payload))
        return transaction.audit.append(event)


class RefusingAuditor(FactAuditor):
    """A ``FactAuditor`` whose append of one named action answers the injected
    ``Failure`` instead of reaching the sink -- the audit-side fault of a phase
    transaction; every other fact is appended normally. ``refusals`` counts the
    refused appends."""

    def __init__(
        self,
        ids: AuditEventIds,
        clock: Clock,
        *,
        refused_action: str,
        failure: Failure,
    ) -> None:
        super().__init__(ids, clock)
        self.refused_action = refused_action
        self.failure = failure
        self.refusals = 0

    def append(
        self, transaction: FinalizationUnitOfWork, fact: AuditFact
    ) -> Result[None]:
        if fact.action == self.refused_action:
            self.refusals += 1
            return self.failure
        return super().append(transaction, fact)


# -- Request builders -------------------------------------------------------------


def sample_result_request(
    candidate_artifact_ids: Sequence[str],
    *,
    run: EngineRunRecord,
    invocation: CommandInvocationRecord,
    owner: RunArtifactOwner = RUN_OWNER,
    semantic_status: str = "SUCCEEDED",
    source_hash: str = SOURCE_MANIFEST_HASH,
    sanitized_hash: str = SANITIZED_MANIFEST_HASH,
    timeout_seconds: int = RESULT_TIMEOUT_SECONDS,
    **overrides: Any,
) -> ResultFinalizationRequest:
    """A ``RESULT`` request over ``run`` and its run-command ``invocation`` whose
    revisions, token hash and identities it restates; the idempotency key and the
    candidate-set hash recompute from the (possibly overridden) fields."""
    ids = tuple(sorted(candidate_artifact_ids))
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "finalization_purpose": "RESULT",
        "owner": owner,
        "experiment_id": owner.experiment_id,
        "run_id": owner.run_id,
        "run_invocation_id": owner.invocation_id,
        "expected_run_revision": run.revision,
        "expected_invocation_revision": invocation.revision,
        "attempt_token_hash": run.attempt_token_hash,
        "source_adapter_result_manifest_hash": source_hash,
        "sanitized_adapter_result_manifest_hash": sanitized_hash,
        "semantic_status": semantic_status,
        "candidate_artifact_ids": ids,
        "finalization_timeout_seconds": timeout_seconds,
    }
    payload.update(overrides)
    payload = _without_missing(payload)
    set_hash = candidate_set_hash_for(payload["candidate_artifact_ids"])
    payload.setdefault("candidate_set_hash", set_hash)
    payload.setdefault("idempotency_key", _result_identity(payload))
    return ResultFinalizationRequest.model_validate(payload)


def sample_evidence_request(
    candidate_artifact_ids: Sequence[str],
    *,
    owner: ArtifactOwnerRef = RUN_OWNER,
    source_role: ArtifactSourceRole | None = None,
    correlation: EvidenceCorrelation = INVOCATION_CORRELATION,
    **overrides: Any,
) -> EvidenceFinalizationRequest:
    """An ``EVIDENCE`` request over ``owner`` and ``correlation`` whose key and set
    hash recompute from the (possibly overridden) fields."""
    ids = tuple(sorted(candidate_artifact_ids))
    role = source_role or default_role(_F.EVIDENCE, _P.CORE, owner_kind_of(owner))
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "finalization_purpose": "EVIDENCE",
        "owner": owner,
        "source_role": role,
        "candidate_artifact_ids": ids,
        "correlation": correlation,
    }
    payload.update(overrides)
    payload = _without_missing(payload)
    set_hash = candidate_set_hash_for(payload["candidate_artifact_ids"])
    payload.setdefault("candidate_set_hash", set_hash)
    payload.setdefault("idempotency_key", _evidence_identity(payload))
    return EvidenceFinalizationRequest.model_validate(payload)


# -- The filesystem planting shared by the memory harness and the SQLite fixture --


class ArtifactStoreFixture:
    """``staging/``, ``artifacts/`` and ``quarantine/`` under one ``tmp_path``, the
    store opened over them (plan 7.1). ``runtime_root`` holds the command roots
    beside ``staging`` and ``quarantine``."""

    def __init__(
        self,
        tmp_path: Path,
        *,
        clock: Clock | None = None,
        hasher: StreamingContentHasher | None = None,
        reuse: bool = False,
    ) -> None:
        self.clock: Clock = clock if clock is not None else FixedClock(INSTANT)
        self.hasher = hasher if hasher is not None else StreamingContentHasher()
        self.runtime_root = tmp_path / "runtime"
        self.staging_root = self.runtime_root / "staging"
        self.quarantine_root = self.runtime_root / "quarantine"
        self.artifacts_root = tmp_path / "artifacts"
        self.staging_root.mkdir(parents=True, exist_ok=reuse)
        self.artifacts_root.mkdir(parents=True, exist_ok=reuse)
        opened = ArtifactStore.open(
            self.staging_root,
            self.artifacts_root,
            self.quarantine_root,
            now_utc=self.clock.now_utc(),
            hasher=self.hasher,
        )
        assert isinstance(opened, Success), opened
        self.store: ArtifactStore = opened.value

    def object_blobs(self) -> tuple[str, ...]:
        """The content hashes present under ``objects/``, sorted."""
        return tuple(
            sorted(
                path.name
                for path in self.artifacts_root.joinpath("objects").rglob("*")
                if path.is_file()
            )
        )

    def staging_files(self) -> tuple[str, ...]:
        return _relative_files(self.staging_root)

    def command_root_files(self) -> tuple[str, ...]:
        """Every file under a command root (``inv_*``) of the runtime root."""
        files: list[str] = []
        for child in sorted(self.runtime_root.iterdir()):
            if child.is_dir() and child.name.startswith("inv_"):
                files.extend(
                    f"{child.name}/{relative}" for relative in _relative_files(child)
                )
        return tuple(files)

    def quarantine_entries(self) -> tuple[QuarantineEntry, ...]:
        return self.store.quarantine_entries()


def _relative_files(root: Path) -> tuple[str, ...]:
    if not root.exists():
        return ()
    return tuple(
        sorted(
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file()
        )
    )


def plant_command_root(
    runtime_root: Path,
    *,
    run_id: str = RUN_ID,
    invocation_id: str = INVOCATION_ID,
    token: str = FIXTURE_TOKEN,
    files: Mapping[str, bytes] = RESULT_FILES,
    manifest: bytes = RESULT_MANIFEST_BYTES,
) -> CommandRootPaths:
    """The Stage 7 ``RUN`` root layout under ``runtime_root``: ``request.json``
    carrying the fixture token (the one place the raw token is written), the
    adapter result manifest and the declared candidate files under the work
    directory."""
    command_root = runtime_root / invocation_id
    work_dir = command_root / "runs" / run_id / "work"
    work_dir.mkdir(parents=True, exist_ok=True)
    request_path = command_root / "request.json"
    request_path.write_bytes(
        json.dumps(
            {"schema_version": "1.0.0", "run_id": run_id, "attempt_token": token}
        ).encode("utf-8")
    )
    result_path = work_dir / "adapter-result-manifest.json"
    result_path.write_bytes(manifest)
    for relative, data in files.items():
        target = work_dir.joinpath(*relative.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return CommandRootPaths(
        command_root=command_root,
        request_path=request_path,
        work_dir=work_dir,
        result_path=result_path,
    )


def read_token_material(
    roots: CommandRootPaths, *, run_id: str = RUN_ID
) -> AttemptTokenMaterial:
    """The test-side read of the planted ``request.json`` (the Stage 7 reader's
    production twin is the composition's); the material lives in the caller's
    frame only."""
    payload = json.loads(roots.request_path.read_bytes().decode("utf-8"))
    return AttemptTokenMaterial(
        run_id=run_id, attempt_token=str(payload["attempt_token"])
    )


def result_candidates(
    *,
    run_id: str = RUN_ID,
    invocation_id: str = INVOCATION_ID,
    owner: RunArtifactOwner = RUN_OWNER,
    files: Mapping[str, bytes] = RESULT_FILES,
    state: CandidateArtifactState = _S.CANDIDATE,
    now_utc: datetime = INSTANT,
) -> tuple[CandidateArtifact, ...]:
    """The adapter-produced ``RESULT`` candidates of ``files``, declared size, hash
    and media type equal to the planted bytes, identities derived from the run,
    the invocation and the relative path."""
    records: list[CandidateArtifact] = []
    for relative, data in files.items():
        records.append(
            CandidateArtifact.model_validate(
                {
                    "schema_version": "1.0.0",
                    "candidate_artifact_id": candidate_artifact_id_for(
                        run_id, invocation_id, relative
                    ),
                    "owner": owner,
                    "finalization_purpose": _F.RESULT,
                    "source_role": _R.ENGINE_NATIVE_RESULT,
                    "producer_kind": _P.ADAPTER,
                    "artifact_kind": NATIVE_KIND,
                    "staging_relative_path": relative,
                    "state": state,
                    "adapter_declared_size": len(data),
                    "adapter_declared_hash": sha256_bytes(data),
                    "adapter_declared_media_type": NATIVE_MEDIA,
                    "validation_observations": (),
                    "source_event_id": SOURCE_EVENT_ID,
                    "created_at_utc": now_utc,
                    "updated_at_utc": now_utc,
                    "revision": 1,
                }
            )
        )
    return tuple(sorted(records, key=lambda record: record.candidate_artifact_id))


def plant_core_evidence(
    store: ArtifactStore,
    *,
    owner: ArtifactOwnerRef = RUN_OWNER,
    correlation: EvidenceCorrelation = INVOCATION_CORRELATION,
    files: Mapping[str, bytes] = EVIDENCE_FILES,
    source_role: ArtifactSourceRole | None = None,
    artifact_kind: str = CORE_KIND,
    now_utc: datetime = INSTANT,
) -> tuple[CandidateArtifact, ...]:
    """Write ``files`` into core staging through ``store.write_staged`` under the
    owner's correlation-scoped path and build the ``CORE`` candidates."""
    owner_hash = artifact_owner_hash(owner)
    role = source_role or default_role(_F.EVIDENCE, _P.CORE, owner_kind_of(owner))
    records: list[CandidateArtifact] = []
    for relative, data in files.items():
        staging_relative = f"{correlation.kind}/{correlation.correlation_id}/{relative}"
        written = store.write_staged(
            owner_hash, staging_relative, data, now_utc=now_utc
        )
        assert isinstance(written, Success), written
        records.append(
            CandidateArtifact.model_validate(
                {
                    "schema_version": "1.0.0",
                    "candidate_artifact_id": core_candidate_artifact_id_for(
                        owner_hash,
                        correlation.kind,
                        correlation.correlation_id,
                        relative,
                    ),
                    "owner": owner,
                    "finalization_purpose": _F.EVIDENCE,
                    "source_role": role,
                    "producer_kind": _P.CORE,
                    "artifact_kind": artifact_kind,
                    "staging_relative_path": staging_relative,
                    "state": _S.CANDIDATE,
                    "validation_observations": (),
                    "created_at_utc": now_utc,
                    "updated_at_utc": now_utc,
                    "revision": 1,
                }
            )
        )
    return tuple(sorted(records, key=lambda record: record.candidate_artifact_id))


# -- The durable snapshot both harness kinds answer -------------------------------


@dataclass(frozen=True, slots=True)
class DurableState:
    """A frozen snapshot of the Stage 9 tables, the run and invocation rows, the
    filesystem and the audit rows (plan 7.1 ``durable()``)."""

    journal: tuple[FinalizationJournalEntry, ...]
    candidates: tuple[CandidateArtifact, ...]
    refs: tuple[ArtifactRef, ...]
    run: EngineRunRecord | None
    invocation: CommandInvocationRecord | None
    run_manifests: tuple[RunManifestFacts, ...]
    run_artifacts: tuple[RunArtifactLink, ...]
    audit_events: tuple[AuditEvent, ...]
    diagnostics: tuple[Diagnostic, ...]
    object_blobs: tuple[str, ...]
    staging_files: tuple[str, ...]
    command_root_files: tuple[str, ...]
    quarantine_entries: tuple[QuarantineEntry, ...]

    @property
    def journal_state(self) -> str | None:
        """The one journal entry's state, or ``None``; more than one is an error."""
        if not self.journal:
            return None
        assert len(self.journal) == 1, self.journal
        return self.journal[0].state.value

    @property
    def abandon_reason(self) -> str | None:
        if len(self.journal) != 1:
            return None
        reason = self.journal[0].abandon_reason
        return reason if isinstance(reason, str) else None

    @property
    def run_state(self) -> str | None:
        return None if self.run is None else self.run.state.value

    @property
    def run_revision(self) -> int | None:
        return None if self.run is None else self.run.revision

    @property
    def run_deadline(self) -> datetime | None:
        if self.run is None:
            return None
        deadline = self.run.finalization_deadline_utc
        return deadline if isinstance(deadline, datetime) else None

    @property
    def candidate_states(self) -> dict[str, str]:
        return {
            candidate.candidate_artifact_id: candidate.state.value
            for candidate in self.candidates
        }

    @property
    def audit_actions(self) -> tuple[str, ...]:
        return tuple(event.action.value for event in self.audit_events)

    @property
    def diagnostic_codes(self) -> tuple[str, ...]:
        return tuple(sorted(diagnostic.error_code for diagnostic in self.diagnostics))


def memory_durable(
    store: MemoryArtifactStore, roots: ArtifactStoreFixture, *, run_id: str = RUN_ID
) -> DurableState:
    """The memory store's committed state beside the fixture roots' files."""
    tables = _tables_of(store)
    invocation: CommandInvocationRecord | None = None
    run = tables.runs.get(run_id)
    if run is not None:
        for record in tables.invocations.values():
            if record.run_id == run_id and record.command_kind is CommandKind.RUN:
                invocation = record
    return DurableState(
        journal=tuple(tables.journal[key] for key in sorted(tables.journal)),
        candidates=store.committed_candidates(),
        refs=store.committed_refs(),
        run=run,
        invocation=invocation,
        run_manifests=tuple(
            tables.run_manifests[key] for key in sorted(tables.run_manifests)
        ),
        run_artifacts=tuple(
            tables.run_artifacts[key] for key in sorted(tables.run_artifacts)
        ),
        audit_events=tuple(tables.audit_events),
        diagnostics=tuple(tables.diagnostics[k] for k in sorted(tables.diagnostics)),
        object_blobs=roots.object_blobs(),
        staging_files=roots.staging_files(),
        command_root_files=roots.command_root_files(),
        quarantine_entries=roots.quarantine_entries(),
    )


# -- The memory harness of the Task 6 unit tests -----------------------------------


@dataclass(frozen=True, slots=True)
class ResultPlan:
    """The planted RESULT pre-state: the rows, the files and the request."""

    run: EngineRunRecord
    invocation: CommandInvocationRecord
    candidates: tuple[CandidateArtifact, ...]
    roots: CommandRootPaths
    request: ResultFinalizationRequest


@dataclass(frozen=True, slots=True)
class EvidencePlan:
    """The planted EVIDENCE pre-state: the candidates and the request."""

    owner: ArtifactOwnerRef
    candidates: tuple[CandidateArtifact, ...]
    request: EvidenceFinalizationRequest


class MemoryFinalizationHarness:
    """The Task 6 unit-test composition: the memory unit of work and registrar
    over a real store under ``tmp_path`` (files are hashed and moved for real;
    rows live in the dict store). Mirrors ``FinalizationFixture``'s surface so a
    behavior proven here reads the same way over SQLite."""

    def __init__(
        self,
        tmp_path: Path,
        *,
        clock: FixedClock | None = None,
        hasher: StreamingContentHasher | None = None,
    ) -> None:
        self.clock: FixedClock = clock if clock is not None else FixedClock(INSTANT)
        self.hasher = hasher if hasher is not None else StreamingContentHasher()
        self.roots = ArtifactStoreFixture(
            tmp_path, clock=self.clock, hasher=self.hasher
        )
        self.store_data = MemoryArtifactStore(self.clock)
        self.unit_of_work = MemoryFinalizationUnitOfWork(self.store_data)
        self.audit_ids = SequentialAuditIds("task6")
        self.auditor = FactAuditor(self.audit_ids, self.clock)
        self.registrar = MemoryRegistrar()
        self.validator = MemoryRecoveryValidator(self.clock)
        self.log = RecordingLog()
        self._command_roots: dict[str, CommandRootPaths] = {}

    # -- lookups ------------------------------------------------------------------

    def command_roots(self, invocation_id: str) -> CommandRootPaths | MISSING:  # type: ignore[valid-type]
        return self._command_roots.get(invocation_id, MISSING)

    def token_material(self, invocation_id: str) -> AttemptTokenMaterial | MISSING:  # type: ignore[valid-type]
        roots = self._command_roots.get(invocation_id)
        if roots is None:
            return MISSING
        invocation = _tables_of(self.store_data).invocations.get(invocation_id)
        run_id = invocation.run_id if invocation is not None else RUN_ID
        return read_token_material(roots, run_id=str(run_id))

    def finalizer(
        self,
        probe: FinalizationProbe | None = None,
        *,
        log: FinalizationLog | None = None,
    ) -> CoreArtifactFinalizer:
        return CoreArtifactFinalizer(
            self.unit_of_work.begin,
            self.clock,
            self.hasher,
            self.roots.store,
            probe if probe is not None else RecordingProbe(),
            self.registrar,
            self.auditor,
            command_roots=self.command_roots,
            token_material=self.token_material,
            log=log,
        )

    # -- planting -----------------------------------------------------------------

    def plant_run(
        self,
        *,
        run_state: EngineRunState = _RS.RUNNING,
        invocation_state: CommandInvocationState = _C.EXITED,
        experiment_state: ExperimentState = _E.RUNNING,
    ) -> tuple[EngineRunRecord, CommandInvocationRecord]:
        tables = _tables_of(self.store_data)
        run = sample_run(run_state)
        invocation = sample_invocation(invocation_state, kind=CommandKind.RUN)
        tables.experiments[EXPERIMENT_ID] = experiment_state
        tables.runs[run.run_id] = run
        tables.invocations[invocation.invocation_id] = invocation
        return run, invocation

    def plant_result_prestate(
        self,
        *,
        files: Mapping[str, bytes] = RESULT_FILES,
        candidate_state: CandidateArtifactState = _S.CANDIDATE,
        **request_overrides: Any,
    ) -> ResultPlan:
        run, invocation = self.plant_run()
        roots = plant_command_root(self.roots.runtime_root, files=files)
        self._command_roots[INVOCATION_ID] = roots
        candidates = result_candidates(files=files, state=candidate_state)
        for candidate in candidates:
            self.store_data.candidates[candidate.candidate_artifact_id] = candidate
        request = sample_result_request(
            [candidate.candidate_artifact_id for candidate in candidates],
            run=run,
            invocation=invocation,
            **request_overrides,
        )
        return ResultPlan(
            run=run,
            invocation=invocation,
            candidates=candidates,
            roots=roots,
            request=request,
        )

    def plant_evidence_prestate(
        self,
        owner: ArtifactOwnerRef = RUN_OWNER,
        *,
        correlation: EvidenceCorrelation = INVOCATION_CORRELATION,
        files: Mapping[str, bytes] = EVIDENCE_FILES,
        with_run: bool = True,
        **request_overrides: Any,
    ) -> EvidencePlan:
        if with_run and RUN_ID not in _tables_of(self.store_data).runs:
            self.plant_run()
        candidates = plant_core_evidence(
            self.roots.store, owner=owner, correlation=correlation, files=files
        )
        for candidate in candidates:
            self.store_data.candidates[candidate.candidate_artifact_id] = candidate
        request = sample_evidence_request(
            [candidate.candidate_artifact_id for candidate in candidates],
            owner=owner,
            correlation=correlation,
            **request_overrides,
        )
        return EvidencePlan(owner=owner, candidates=candidates, request=request)

    # -- driving ------------------------------------------------------------------

    def finalize(
        self,
        request: ResultFinalizationRequest | EvidenceFinalizationRequest,
        *,
        probe: FinalizationProbe | None = None,
        cancellation: FlagCancellationToken | None = None,
        log: FinalizationLog | None = None,
    ) -> Result[FinalizationResult]:
        token = cancellation if cancellation is not None else FlagCancellationToken()
        return run_coroutine(self.finalizer(probe, log=log).finalize(request, token))

    def recover(self) -> Result[FinalizationReconciliationReport]:
        return reconcile_finalization(
            unit_of_work_factory=self.unit_of_work.begin,
            store=self.roots.store,
            hasher=self.hasher,
            registrar=self.registrar,
            recovery_validator=self.validator,
            auditor=self.auditor,
            clock=self.clock,
            runtime_root=self.roots.runtime_root,
            command_roots=self.command_roots,
            token_material=self.token_material,
            log=self.log,
        )

    def advance_clock(self, seconds: float) -> None:
        self.clock.advance(seconds)

    def durable(self) -> DurableState:
        return memory_durable(self.store_data, self.roots)


__all__ = (
    "ABANDON_REASON",
    "ADAPTER_ACTOR",
    "ADAPTER_MANIFEST_ID",
    "ADAPTER_OWNER",
    "ARTIFACT_DOUBLE_COMPONENT",
    "ATTEMPT_TOKEN_HASH",
    "AUDIT_EVENT_ID",
    "CANDIDATE_ID",
    "CONTENT_HASH",
    "CORE_KIND",
    "CORE_MEDIA",
    "CORE_PATH",
    "CORRELATION_ID",
    "DATASET_ID",
    "DATASET_OWNER",
    "DEADLINE",
    "DIAGNOSTIC_CORRELATION",
    "EVIDENCE_FILES",
    "EVIDENCE_MEDIA",
    "EXPERIMENT_OWNER",
    "FIXTURE_TOKEN",
    "INVOCATION_CORRELATION",
    "LEASE_EXPIRY",
    "LOCAL_USER_ACTOR",
    "NATIVE_KIND",
    "NATIVE_MEDIA",
    "NATIVE_PATH",
    "OTHER_CANDIDATE_ID",
    "OWNERS",
    "RESULT_FILES",
    "RESULT_MANIFEST_BYTES",
    "RESULT_TIMEOUT_SECONDS",
    "RUN_MANIFEST_HASH",
    "RUN_MANIFEST_ID",
    "RUN_OWNER",
    "RUN_OWNER_WITHOUT_INVOCATION",
    "SAMPLE_DETAILS",
    "SANITIZED_MANIFEST_HASH",
    "SIZE_BYTES",
    "SNAPSHOT_SOURCE_HASH",
    "SOURCE_EVENT_ID",
    "SOURCE_MANIFEST_HASH",
    "STRATEGY_OWNER",
    "STRATEGY_VERSION_ID",
    "SYSTEM_OWNER",
    "THIRD_CANDIDATE_ID",
    "ArtifactStoreFixture",
    "CrashingProbe",
    "DurableState",
    "EvidencePlan",
    "FactAuditor",
    "FinalizationCrash",
    "FlagCancellationToken",
    "MemoryArtifactRepository",
    "MemoryArtifactStore",
    "MemoryAuditSink",
    "MemoryCandidateArtifactRepository",
    "MemoryCommandInvocationRecords",
    "MemoryDiagnosticWriter",
    "MemoryEngineRunRecords",
    "MemoryFinalizationHarness",
    "MemoryFinalizationJournalRepository",
    "MemoryFinalizationTransaction",
    "MemoryFinalizationUnitOfWork",
    "MemoryRecoveryValidator",
    "MemoryRegistrar",
    "MemoryResultLeaseFacts",
    "MemoryResultLeaseRepository",
    "MemoryRunArtifactLink",
    "MemoryRunArtifactRepository",
    "MemoryRunManifestRepository",
    "MemorySanitizedManifestRepository",
    "MemoryTables",
    "MemoryValidationResultRepository",
    "RecordingLog",
    "RecordingProbe",
    "RefusingAuditor",
    "ResultPlan",
    "SequentialAuditIds",
    "ValidatorCall",
    "bump_candidate",
    "bump_journal",
    "content_hash_for",
    "count_checkpoints",
    "default_role",
    "failed_observation",
    "hash_observation",
    "memory_durable",
    "observed_move",
    "passed_observation",
    "plant_command_root",
    "plant_core_evidence",
    "read_token_material",
    "renew_journal",
    "result_candidates",
    "run_coroutine",
    "sample_artifact_manifest",
    "sample_audit_event",
    "sample_candidate",
    "sample_evidence_request",
    "sample_finalization_result",
    "sample_journal",
    "sample_log_record",
    "sample_mapping",
    "sample_metric",
    "sample_ref",
    "sample_result_request",
    "staging_path_for",
)
