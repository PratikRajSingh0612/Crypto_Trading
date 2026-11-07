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

from collections.abc import Sequence
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, Final

from pydantic import BaseModel
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.artifacts.journal import (
    FinalizationJournalEntry,
    FinalizationJournalState,
    ObservedMove,
    PlannedMove,
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
from crypto_lab.artifacts.requests import EvidenceCorrelation
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
from crypto_lab.domain.comparison_levels import ComparisonLevel
from crypto_lab.domain.hashing import (
    _uuid4_shaped,
    artifact_id_for,
    attempt_token_hash,
    candidate_set_hash_for,
    finalization_id_for,
    finalization_identity,
    sha256_bytes,
)
from crypto_lab.domain.lifecycle import CommandInvocationState, EngineRunState
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
    """

    def __init__(self, store: MemoryArtifactStore) -> None:
        self._store = store
        self._staged: dict[str, tuple[ArtifactRef, ArtifactManifest]] = {}

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
    "EXPERIMENT_OWNER",
    "INVOCATION_CORRELATION",
    "LEASE_EXPIRY",
    "LOCAL_USER_ACTOR",
    "NATIVE_KIND",
    "NATIVE_MEDIA",
    "NATIVE_PATH",
    "OTHER_CANDIDATE_ID",
    "OWNERS",
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
    "MemoryArtifactRepository",
    "MemoryArtifactStore",
    "MemoryCandidateArtifactRepository",
    "SequentialAuditIds",
    "bump_candidate",
    "bump_journal",
    "content_hash_for",
    "default_role",
    "failed_observation",
    "hash_observation",
    "observed_move",
    "passed_observation",
    "renew_journal",
    "sample_artifact_manifest",
    "sample_audit_event",
    "sample_candidate",
    "sample_finalization_result",
    "sample_journal",
    "sample_log_record",
    "sample_mapping",
    "sample_metric",
    "sample_ref",
    "staging_path_for",
)
