"""The core artifact finalizer: the four-transaction journal protocol of plan
4.3, the probe, the cooperative checkpoint, the raw-byte close and the lease
close (Stage 9 plan 4.2-4.5, 4.7; specification 19.2 steps 1-9, 23.3.1:1719-1723,
14.7:1018, 14.8:1029; readings 1, 2, 12, 13, 18, 21, 26).

The protocol, phase by phase:

0. Pre-validation, no transaction: the request type; the cancellation token
   (``PROCESS.CANCELLED`` before T1, ignored after it); the candidates loaded in
   a read-only transaction and released; the owner revalidated against the
   registered rows (an ``ADAPTER`` owner's ``CORE_EVIDENCE`` requires its
   ``INVOCATION`` correlation to name a ``DESCRIBE`` invocation of that adapter);
   the replay lookup by identity (``REGISTERED`` returns the stored result with
   ``replayed=True`` and one ``FINALIZATION_REPLAYED`` row; ``PREPARED``/``MOVED``
   under an unexpired lease is ``PERSISTENCE.CONCURRENCY_CONFLICT``; an expired
   lease is taken over under the same ``finalization_id`` through
   ``resume_journal``, below); every path confined, a candidate whose path
   fails is ``QUARANTINED`` in a short transaction.
1. Validate and hash, no transaction: the attempt token material resolved first
   -- the caller's transient material or ``token_material(invocation_id)``,
   required for ``RESULT``, optional for ``RUN``-owned evidence, never for an
   owner without a run -- and validated against the authoritative run and
   invocation (the material's run, the run's stored ``attempt_token_hash``, the
   invocation's run) in one short read transaction closed before any hash; then
   ``CANDIDATE -> VALIDATING`` per candidate in a short transaction, then
   ``validate_candidate`` -- size, media, schema, the exact-byte token scan for
   either purpose whenever material is available, the canonical qualification
   of ``CORE`` evidence through the registrar that also answers
   ``CanonicalEvidenceQualifier`` (the ruling of 2026-11-09; a registrar without
   it leaves every text evidence under the whole-content token-shape scan), the
   streamed digest -- with the planned moves fixed here (19.2 step 4). A
   failure quarantines the candidate (``CORRUPT`` for a size or hash mismatch)
   and, for a leaked raw token, every ``RESULT`` candidate of the request.
2. T1 ``PREPARED``: ``RESULT`` checks the active attempt facts and snapshots the
   deadline once through the run compare-and-swap as ``prepared_at_utc +
   finalization_timeout_seconds`` (reading 2: the deadline exists only from
   here and no later write moves it); both purposes move the candidates to
   ``FINALIZING`` and insert the journal with a lease (``RESULT``: ``min(now +
   RESULT_LEASE_SECONDS, deadline)``, so the lease expires strictly before the
   deadline and an expired lease can be taken over before it -- the RESULT lease
   ruling of 2026-11-08; ``EVIDENCE``: ``EVIDENCE_LEASE_SECONDS``, no deadline,
   reading 13).
3. Move, no transaction: per planned move in sorted order the deadline poll, the
   confinement and identity recheck, ``fsync`` and the atomic same-volume move
   with deduplication (reading 21), the probe between moves.
4. T2 ``MOVED``: every moved blob re-hashed in place (reading 18), the lease
   renewed by the same compare-and-swap that writes ``MOVED`` -- at the
   journal's revision and state, never past the deadline, which the renewal
   leaves unchanged -- so a holder whose revision a takeover moved is refused
   and writes nothing.
5. T3 ``REGISTERED``: the references built from the observed facts; ``EVIDENCE``
   stages and records them and the registrar links them; ``RESULT`` hands them to
   the registrar, which owns the plan 4.4 write order (sanitized facts,
   manifests, references, run manifest, links, the run compare-and-swap at the
   journal's expected revision); the journal closes. The
   ``manifests/<artifact_id>.json`` projections are written exclusive-create
   after the commit returned (plan 6.2: the ``artifact_refs`` row is
   authoritative, the file is a human-inspection projection whose absence
   readers tolerate), so a rolled-back T3 leaves no projection behind and a
   projection never stands as proof of a registration that did not commit.
6. T4 close, ``RESULT`` only, after ``REGISTERED`` or ``ABANDONED``: the raw-bearing
   bytes of the token-bearing root removed or quarantined through
   ``close_raw_bytes`` (14.7:1018); an ``EVIDENCE`` finalization never closes a
   root.

Failure handling. A refusal before T1 writes nothing except the candidate
quarantine, which is its own committed fact (plan 4.7). From phase 3 on, a move
failure, a hash mismatch, a lost run compare-and-swap or any non-storage
registration refusal rolls the open transaction back and marks the journal
``ABANDONED(<code>)`` in a new short transaction, moves the candidates
``FINALIZING -> QUARANTINED`` and the moved blobs that no other reference
shares into one quarantine entry keyed by the ``finalization_id`` (reading 12:
``PERSISTENCE.CONCURRENCY_CONFLICT`` is the stored code of ``SUPERSEDED``). A
storage-class failure (``PERSISTENCE.WRITE_FAILED``, ``STORAGE_UNAVAILABLE``) at
T2 or T3 leaves the journal where it was for recovery. A passed deadline at any
poll is the plan 4.5 timeout path: ``RUNNING -> TIMED_OUT`` through
``record_timeout``, ``ABANDONED(ARTIFACT.FINALIZATION_TIMED_OUT)``, quarantine.
The finalizer never fails a run itself except through that timeout: a ``RESULT``
refusal is returned to the caller, who owns the run's ``FAILED`` write (plan
4.4 step 3); the reconciler, which has no caller, fails the run on a failed
recovery check (17.3).

Lease takeover and fencing (the RESULT lease ruling of 2026-11-08). An open
journal is resumed -- by a later ``finalize`` under the same identity or by the
reconciler -- only through ``resume_journal``, which takes the lease before any
move: an unexpired lease belongs to its holder and is the conflict (RC-12; a
restart alone supplies no authority over it, so the reconciler defers such a
journal); an expired lease before the deadline is re-acquired by one audited
compare-and-swap at the stored revision that renews ``lease_expires_at_utc`` and
nothing else (RC-13, CP-2); a deadline reached or passed takes no lease -- the
attempt proceeds at the stored revision, where the strict deadline polls of
phases 3 to 5 admit the deadline instant itself (plan 4.3 phase 5: ``now_utc <=
deadline``) and time every later instant out (RV-15). Because every later write
of a superseded holder -- its renewal at T2, its registration at T3, its
abandonment with the quarantine and run writes of that transaction -- is a
compare-and-swap at its stale revision inside one transaction, the holder is
fenced from interfering with the new holder, and it never reaches the lease
close of phase 6.

Boundaries. ``artifacts`` imports ``domain`` and itself only, so the three
non-artifact codes minted here (``PROCESS.CANCELLED``,
``PERSISTENCE.CONCURRENCY_CONFLICT``, ``CORE.INVARIANT_VIOLATION``) are restated
with their reviewed postures as ``artifacts/store.py`` restates its two, and
every audit fact goes through the injected ``FinalizationAuditor`` (plan 4.1
port module docstring). The raw attempt token reaches this module only as the
``AttemptTokenMaterial`` the injected ``token_material`` callable answers or the
caller's frame hands ``finalize`` for that one call, lives in the call frame of
one ``finalize`` and is never an attribute of the finalizer, a journal field, a
diagnostic or an audit detail (the ``ARTIFACT_VALIDATED`` fact records only
whether an exact scan ran). ``finalize`` is a
coroutine without an ``asyncio`` import: ``cooperative_checkpoint`` is an
awaitable whose ``__await__`` yields exactly once, awaited after every probe
point beside the cancellation poll, so the coroutine has genuine suspension
points and the test driver steps it with ``send(None)``. ``FinalizationCrash``
is the test tree's ``BaseException``; nothing here catches ``BaseException``,
and the transaction scope's ``finally`` rolls an open transaction back when one
escapes (the in-process CP-6 shape).
"""

from __future__ import annotations

from collections.abc import Generator, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Final, cast

from pydantic import InstanceOf, JsonValue
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.artifacts.diagnostics import (
    ARTIFACT_FINALIZATION_TIMED_OUT,
    ARTIFACT_MOVE_FAILED,
    ARTIFACT_PATH_BOUNDARY_VIOLATION,
    ARTIFACT_SOURCE_COMPONENT,
    ARTIFACT_VALIDATION_FAILED,
    SECURITY_SENSITIVE_MATERIAL_LEAKAGE,
    ArtifactDiagnosticPosture,
    artifact_diagnostic,
    artifact_failure,
)
from crypto_lab.artifacts.hashing import ContentHasher
from crypto_lab.artifacts.journal import (
    FinalizationJournalEntry,
    FinalizationJournalState,
    ObservedMove,
    PlannedMove,
)
from crypto_lab.artifacts.manifest import (
    ARTIFACT_VALIDATION_PROFILE,
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
    CandidateArtifactState,
    CandidateFinalization,
    FinalizationResult,
    ValidationObservation,
    owner_kind_of,
)
from crypto_lab.artifacts.ownership import (
    AdapterArtifactOwner,
    ArtifactOwnerRef,
    RunArtifactOwner,
    artifact_owner_hash,
)
from crypto_lab.artifacts.paths import (
    ConfinedPath,
    confine_candidate_path,
    recheck_confined_path,
)
from crypto_lab.artifacts.ports import (
    AuditFact,
    CanonicalEvidenceQualifier,
    CommandRootPaths,
    CommandRootsLookup,
    FinalizationAuditor,
    FinalizationLog,
    FinalizationProbe,
    FinalizationRequest,
    FinalizationUnitOfWork,
    LogFact,
    PurposeRegistrar,
    RegistrationUnitOfWork,
    ResultLeaseFacts,
    TokenMaterialLookup,
    UnitOfWorkFactory,
)
from crypto_lab.artifacts.requests import (
    EvidenceCorrelation,
    EvidenceFinalizationRequest,
    ResultFinalizationRequest,
)
from crypto_lab.artifacts.store import (
    CORE_INVARIANT_VIOLATION,
    ArtifactStore,
)
from crypto_lab.artifacts.validation import (
    DEFAULT_CEILINGS,
    CandidateValidation,
    ValidatedCandidate,
    ValidationCeilings,
    validate_candidate,
)
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.diagnostics import (
    Diagnostic,
    DiagnosticCategory,
    DiagnosticDetailValue,
    DiagnosticSeverity,
)
from crypto_lab.domain.engine_run import (
    AttemptTokenMaterial,
    EngineRunRecord,
    EngineRunRuleViolation,
    assert_run_transition,
)
from crypto_lab.domain.hashing import (
    HashingProfile,
    _uuid4_shaped,
    artifact_id_for,
    attempt_token_hash,
    finalization_id_for,
    profile_hash,
)
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.ports import CancellationToken, Clock
from crypto_lab.domain.results import Failure, Result, Success

#: Plan 4.3 phase 2 (reading 13): the compiled EVIDENCE lease; no configuration
#: key and no deadline.
EVIDENCE_LEASE_SECONDS: Final = 300
#: The RESULT lease ruling of 2026-11-08: the RESULT lease is the same compiled
#: interval and expires at ``min(now + RESULT_LEASE_SECONDS, deadline)``, so it
#: expires strictly before the immutable deadline and leaves the takeover window
#: of RC-13 and CP-2 (a lease equal to the deadline could never be taken over
#: before the deadline). The deadline itself is snapshotted once at T1 as
#: ``prepared_at_utc + finalization_timeout_seconds`` and never moves.
RESULT_LEASE_SECONDS: Final = EVIDENCE_LEASE_SECONDS
#: The three non-artifact codes this module mints, restated with their reviewed
#: postures (``adapters/diagnostics.py:144``, ``persistence/diagnostics.py:87``,
#: ``artifacts/store.py``); ``artifacts`` may import neither package.
PROCESS_CANCELLED: Final = "PROCESS.CANCELLED"
PERSISTENCE_CONCURRENCY_CONFLICT: Final = "PERSISTENCE.CONCURRENCY_CONFLICT"
PERSISTENCE_WRITE_FAILED: Final = "PERSISTENCE.WRITE_FAILED"
PERSISTENCE_STORAGE_UNAVAILABLE: Final = "PERSISTENCE.STORAGE_UNAVAILABLE"
FINALIZER_DIAGNOSTIC_POSTURES: Final[Mapping[str, ArtifactDiagnosticPosture]] = {
    PROCESS_CANCELLED: ArtifactDiagnosticPosture(
        DiagnosticCategory.CANCELLATION, False, DiagnosticSeverity.ERROR
    ),
    PERSISTENCE_CONCURRENCY_CONFLICT: ArtifactDiagnosticPosture(
        DiagnosticCategory.PERSISTENCE, True, DiagnosticSeverity.ERROR
    ),
    CORE_INVARIANT_VIOLATION: ArtifactDiagnosticPosture(
        DiagnosticCategory.INTERNAL_INVARIANT, False, DiagnosticSeverity.ERROR
    ),
}
#: Reading 26 and Stage 8 reading 3: the storage class leaves the journal in
#: place for recovery instead of abandoning it.
STORAGE_FAILURE_CODES: Final[frozenset[str]] = frozenset(
    {PERSISTENCE_WRITE_FAILED, PERSISTENCE_STORAGE_UNAVAILABLE}
)
#: Plan 4.6: the media type of each core-generated evidence kind; the candidate
#: record carries no declaration for a ``CORE`` producer, so the kind decides.
CORE_EVIDENCE_MEDIA_TYPES: Final[Mapping[str, str]] = {
    "stderr-capture": "text/plain",
    "protocol-capture": "application/x-ndjson",
    "sanitized-adapter-result-manifest": "application/json",
    "sanitized-validation-result": "application/json",
    "adapter-descriptor": "application/json",
    "diagnostic-report": "application/x-ndjson",
    "configuration-snapshot": "application/json",
    "dataset-manifest": "application/json",
    "strategy-snapshot": "application/json",
}
#: The stages whose ``ARTIFACT.VALIDATION_FAILED`` is a proven mismatch (CORRUPT).
_CORRUPT_STAGES: Final[frozenset[str]] = frozenset({"SIZE", "HASH"})
_SNAPSHOT_OWNERS: Final[frozenset[ArtifactOwnerKind]] = frozenset(
    {
        ArtifactOwnerKind.EXPERIMENT,
        ArtifactOwnerKind.DATASET,
        ArtifactOwnerKind.STRATEGY,
    }
)
_F: Final = ArtifactFinalizationPurpose
_J: Final = FinalizationJournalState
_S: Final = CandidateArtifactState
_P: Final = CandidateArtifactProducerKind
_OPEN_JOURNAL_STATES: Final = (_J.PREPARED, _J.MOVED)


# --------------------------------------------------------------------------
# The cooperative checkpoint (plan 4.1)
# --------------------------------------------------------------------------


class _Checkpoint:
    """An awaitable whose ``__await__`` yields exactly once: the
    ``asyncio.sleep(0)`` shape without the import."""

    __slots__ = ()

    def __await__(self) -> Generator[None, None, None]:
        yield None


def cooperative_checkpoint() -> _Checkpoint:
    """The one suspension point of ``finalize``, awaited at every phase boundary."""
    return _Checkpoint()


# --------------------------------------------------------------------------
# Diagnostics restated for the three non-artifact codes
# --------------------------------------------------------------------------


def _is_missing(value: object) -> bool:
    return value is MISSING


def _as_int(value: object) -> int:
    """Narrow a RESULT-only ``int | MISSING`` field the purpose guarantees present."""
    if not isinstance(value, int):
        raise RuntimeError("a RESULT finalization carries its expected revisions")
    return value


def _without_missing(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if value is not MISSING}


def _restated_diagnostic(
    code: str,
    *,
    message: str,
    now_utc: datetime,
    experiment_id: str | MISSING = MISSING,  # type: ignore[valid-type]
    run_id: str | MISSING = MISSING,  # type: ignore[valid-type]
    invocation_id: str | MISSING = MISSING,  # type: ignore[valid-type]
    details: Mapping[str, DiagnosticDetailValue] | None = None,
) -> Diagnostic:
    """One of the three restated codes with the ``DIAGNOSTIC_IDENTITY_V1`` identity
    the artifact factory derives (the instant excluded)."""
    posture = FINALIZER_DIAGNOSTIC_POSTURES[code]
    detail_payload: dict[str, DiagnosticDetailValue] = dict(details or {})
    payload: dict[str, JsonValue] = {
        "schema_version": "1.0.0",
        "error_code": code,
        "category": posture.category.value,
        "severity": posture.severity.value,
        "source_component": ARTIFACT_SOURCE_COMPONENT,
        "message": message,
        "retriable": posture.retriable,
        "details": cast("JsonValue", detail_payload),
    }
    correlation: dict[str, object] = {}
    for name, value in (
        ("experiment_id", experiment_id),
        ("run_id", run_id),
        ("invocation_id", invocation_id),
    ):
        if isinstance(value, str):
            payload[name] = value
            correlation[name] = value
    payload["causal_diagnostic_ids"] = []
    identity = _uuid4_shaped(
        profile_hash(HashingProfile.DIAGNOSTIC_IDENTITY_V1, payload)
    )
    return Diagnostic.model_validate(
        {
            "schema_version": "1.0.0",
            "diagnostic_id": f"diag_{identity}",
            "severity": posture.severity,
            "error_code": code,
            "category": posture.category,
            "message": message,
            "source_component": ARTIFACT_SOURCE_COMPONENT,
            "retriable": posture.retriable,
            "timestamp_utc": now_utc,
            "details": detail_payload,
            "causal_diagnostic_ids": (),
            **correlation,
        }
    )


def _failure_of(diagnostic: Diagnostic) -> Failure:
    return Failure(outcome="FAILURE", diagnostics=(diagnostic,))


def _code_of(failure: Failure) -> str:
    return failure.diagnostics[0].error_code


# --------------------------------------------------------------------------
# The call frame
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class _Scope:
    """One finalization's identity and correlation, derived from the request or
    the journal; immutable for the call."""

    purpose: ArtifactFinalizationPurpose
    finalization_id: str
    owner: ArtifactOwnerRef
    owner_hash: str
    source_role: ArtifactSourceRole
    candidate_ids: tuple[str, ...]
    candidate_set_hash: str
    correlation: EvidenceCorrelation | MISSING  # type: ignore[valid-type]
    experiment_id: str | MISSING  # type: ignore[valid-type]
    run_id: str | MISSING  # type: ignore[valid-type]
    invocation_id: str | MISSING  # type: ignore[valid-type]
    expected_run_revision: int | MISSING  # type: ignore[valid-type]
    expected_invocation_revision: int | MISSING  # type: ignore[valid-type]
    attempt_token_hash: str | MISSING  # type: ignore[valid-type]
    source_hash: str | MISSING  # type: ignore[valid-type]
    sanitized_hash: str | MISSING  # type: ignore[valid-type]
    semantic_status: str | MISSING  # type: ignore[valid-type]
    timeout_seconds: int

    @property
    def is_result(self) -> bool:
        return self.purpose is _F.RESULT

    def audit_ids(self) -> dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "run_id": self.run_id,
            "invocation_id": self.invocation_id,
        }


def _scope_of_request(request: FinalizationRequest) -> _Scope:
    if isinstance(request, ResultFinalizationRequest):
        return _Scope(
            purpose=_F.RESULT,
            finalization_id=finalization_id_for(request.idempotency_key),
            owner=request.owner,
            owner_hash=artifact_owner_hash(request.owner),
            source_role=ArtifactSourceRole.ENGINE_NATIVE_RESULT,
            candidate_ids=request.candidate_artifact_ids,
            candidate_set_hash=request.candidate_set_hash,
            correlation=MISSING,
            experiment_id=request.experiment_id,
            run_id=request.run_id,
            invocation_id=request.run_invocation_id,
            expected_run_revision=request.expected_run_revision,
            expected_invocation_revision=request.expected_invocation_revision,
            attempt_token_hash=request.attempt_token_hash,
            source_hash=request.source_adapter_result_manifest_hash,
            sanitized_hash=request.sanitized_adapter_result_manifest_hash,
            semantic_status=request.semantic_status,
            timeout_seconds=request.finalization_timeout_seconds,
        )
    owner = request.owner
    correlation = request.correlation
    return _Scope(
        purpose=_F.EVIDENCE,
        finalization_id=finalization_id_for(request.idempotency_key),
        owner=owner,
        owner_hash=artifact_owner_hash(owner),
        source_role=request.source_role,
        candidate_ids=request.candidate_artifact_ids,
        candidate_set_hash=request.candidate_set_hash,
        correlation=correlation,
        experiment_id=(
            owner.experiment_id if isinstance(owner, RunArtifactOwner) else MISSING
        ),
        run_id=owner.run_id if isinstance(owner, RunArtifactOwner) else MISSING,
        invocation_id=(
            correlation.invocation_id
            if correlation.kind == "INVOCATION"
            else (
                owner.invocation_id if isinstance(owner, RunArtifactOwner) else MISSING
            )
        ),
        expected_run_revision=MISSING,
        expected_invocation_revision=MISSING,
        attempt_token_hash=MISSING,
        source_hash=MISSING,
        sanitized_hash=MISSING,
        semantic_status=MISSING,
        timeout_seconds=EVIDENCE_LEASE_SECONDS,
    )


def _scope_of_journal(entry: FinalizationJournalEntry) -> _Scope:
    owner = entry.owner
    correlation = entry.correlation
    if entry.finalization_purpose is _F.RESULT:
        deadline = entry.finalization_deadline_utc
        timeout = (
            int((deadline - entry.prepared_at_utc).total_seconds())
            if isinstance(deadline, datetime)
            else EVIDENCE_LEASE_SECONDS
        )
        return _Scope(
            purpose=_F.RESULT,
            finalization_id=entry.finalization_id,
            owner=owner,
            owner_hash=artifact_owner_hash(owner),
            source_role=entry.source_role,
            candidate_ids=entry.candidate_artifact_ids,
            candidate_set_hash=entry.candidate_set_hash,
            correlation=MISSING,
            experiment_id=(
                owner.experiment_id if isinstance(owner, RunArtifactOwner) else MISSING
            ),
            run_id=entry.run_id,
            invocation_id=entry.run_invocation_id,
            expected_run_revision=entry.expected_run_revision,
            expected_invocation_revision=entry.expected_invocation_revision,
            attempt_token_hash=entry.attempt_token_hash,
            source_hash=entry.source_adapter_result_manifest_hash,
            sanitized_hash=entry.sanitized_adapter_result_manifest_hash,
            semantic_status=MISSING,
            timeout_seconds=max(timeout, 1),
        )
    invocation: str | MISSING = MISSING  # type: ignore[valid-type]
    if isinstance(correlation, EvidenceCorrelation) and (
        correlation.kind == "INVOCATION"
    ):
        invocation = correlation.invocation_id
    elif isinstance(owner, RunArtifactOwner):
        invocation = owner.invocation_id
    return _Scope(
        purpose=_F.EVIDENCE,
        finalization_id=entry.finalization_id,
        owner=owner,
        owner_hash=artifact_owner_hash(owner),
        source_role=entry.source_role,
        candidate_ids=entry.candidate_artifact_ids,
        candidate_set_hash=entry.candidate_set_hash,
        correlation=correlation,
        experiment_id=(
            owner.experiment_id if isinstance(owner, RunArtifactOwner) else MISSING
        ),
        run_id=owner.run_id if isinstance(owner, RunArtifactOwner) else MISSING,
        invocation_id=invocation,
        expected_run_revision=MISSING,
        expected_invocation_revision=MISSING,
        attempt_token_hash=MISSING,
        source_hash=MISSING,
        sanitized_hash=MISSING,
        semantic_status=MISSING,
        timeout_seconds=EVIDENCE_LEASE_SECONDS,
    )


@dataclass(slots=True)
class _Work:
    """The mutable state of one protocol run: the records as last written, the
    confined paths, the planned facts, the journal and the moves so far."""

    scope: _Scope
    candidates: dict[str, CandidateArtifact]
    root: Path
    roots: CommandRootPaths | MISSING  # type: ignore[valid-type]
    confined: dict[str, ConfinedPath] = field(default_factory=dict)
    validated: dict[str, ValidatedCandidate] = field(default_factory=dict)
    journal: FinalizationJournalEntry | None = None
    deadline_utc: datetime | MISSING = MISSING  # type: ignore[valid-type]
    deadline_monotonic: float | None = None
    moved: dict[str, bool] = field(default_factory=dict)
    observed: list[ObservedMove] = field(default_factory=list)

    @property
    def entry(self) -> FinalizationJournalEntry:
        journal = self.journal
        if journal is None:
            raise RuntimeError("the journal entry is not prepared yet")
        return journal

    @property
    def terminal(self) -> bool:
        journal = self.journal
        return journal is not None and journal.state in (_J.REGISTERED, _J.ABANDONED)


@dataclass(frozen=True, slots=True)
class RawByteClose:
    """The outcome of ``close_raw_bytes``: files removed, missing, quarantined
    after a failed removal, and retained because the quarantine failed too."""

    removed: int
    missing: int
    quarantined: int
    retained: int


# --------------------------------------------------------------------------
# The phase-6 primitive and its leased caller (plan 4.3 phase 6, 4.4 step 5)
# --------------------------------------------------------------------------


def close_raw_bytes(
    paths: CommandRootPaths,
    *,
    store: ArtifactStore,
    unit_of_work: FinalizationUnitOfWork,
    auditor: FinalizationAuditor,
    correlation: str,
    clock: Clock,
    experiment_id: str | MISSING = MISSING,  # type: ignore[valid-type]
    run_id: str | MISSING = MISSING,  # type: ignore[valid-type]
    invocation_id: str | MISSING = MISSING,  # type: ignore[valid-type]
) -> Result[RawByteClose]:
    """Remove the raw-bearing bytes of one token-bearing command root (14.7:1018):
    ``request.json``, ``output.json`` when present and, for a ``RUN`` root, the
    original adapter result manifest -- narrowed from the kind-governed
    ``CommandRootPaths`` by ``isinstance``. A refused removal is moved to the
    quarantine entry keyed by the root's invocation; the audit facts
    (``RETENTION_DELETED``, ``ARTIFACT_QUARANTINED`` once per closed root with a
    failure) are appended on the caller's open transaction. Never an
    ``ArtifactRef``."""
    if not isinstance(paths, CommandRootPaths):
        raise TypeError("paths must be a CommandRootPaths")
    now = clock.now_utc()
    report = store.remove_raw_bytes(paths.raw_byte_paths)
    quarantined = 0
    retained = 0
    for path in report.failed:
        relative = path.relative_to(paths.command_root).as_posix()
        confined = confine_candidate_path(paths.command_root, relative, now_utc=now)
        if isinstance(confined, Failure):
            retained += 1
            continue
        moved = store.quarantine_move(
            confined.value,
            paths.command_root.name,
            ARTIFACT_MOVE_FAILED,
            now_utc=now,
        )
        if isinstance(moved, Failure):
            retained += 1
        else:
            quarantined += 1
    ids = {
        "experiment_id": experiment_id,
        "run_id": run_id,
        "invocation_id": invocation_id,
    }
    deleted = auditor.append(
        unit_of_work,
        AuditFact(
            action="RETENTION_DELETED",
            outcome="SUCCEEDED" if retained == 0 else "FAILED",
            correlation_id=correlation,
            details={
                "removed": len(report.removed),
                "missing": len(report.missing),
                "quarantined": quarantined,
                "retained": retained,
            },
            **ids,
        ),
    )
    if isinstance(deleted, Failure):
        return deleted
    if report.failed:
        quarantine_fact = auditor.append(
            unit_of_work,
            AuditFact(
                action="ARTIFACT_QUARANTINED",
                outcome="SUCCEEDED" if retained == 0 else "FAILED",
                correlation_id=correlation,
                details={
                    "reason": ARTIFACT_MOVE_FAILED,
                    "files": len(report.failed),
                    "quarantined": quarantined,
                    "retained": retained,
                },
                **ids,
            ),
        )
        if isinstance(quarantine_fact, Failure):
            return quarantine_fact
    return Success[InstanceOf[RawByteClose]](
        outcome="SUCCESS",
        value=RawByteClose(
            removed=len(report.removed),
            missing=len(report.missing),
            quarantined=quarantined,
            retained=retained,
        ),
    )


def close_result_lease(
    journal: FinalizationJournalEntry,
    paths: CommandRootPaths,
    *,
    store: ArtifactStore,
    unit_of_work_factory: UnitOfWorkFactory,
    auditor: FinalizationAuditor,
    clock: Clock,
) -> Result[RawByteClose]:
    """The leased caller of ``close_raw_bytes`` (plan 4.3 phase 6): a ``RESULT``
    journal that reached ``REGISTERED`` or ``ABANDONED`` closes its root in one
    short transaction; anything else is refused unchanged."""
    now = clock.now_utc()
    if journal.finalization_purpose is not _F.RESULT or journal.state not in (
        _J.REGISTERED,
        _J.ABANDONED,
    ):
        return _failure_of(
            _restated_diagnostic(
                CORE_INVARIANT_VIOLATION,
                message=(
                    "only a RESULT journal that reached REGISTERED or ABANDONED "
                    "closes its command root"
                ),
                now_utc=now,
            )
        )
    scope = _scope_of_journal(journal)
    transaction = unit_of_work_factory()
    try:
        closed = close_raw_bytes(
            paths,
            store=store,
            unit_of_work=transaction,
            auditor=auditor,
            correlation=journal.finalization_id,
            clock=clock,
            experiment_id=scope.experiment_id,
            run_id=scope.run_id,
            invocation_id=scope.invocation_id,
        )
        if isinstance(closed, Failure):
            return closed
        committed = transaction.commit()
        if isinstance(committed, Failure):
            return committed
        return closed
    finally:
        transaction.rollback()


# --------------------------------------------------------------------------
# The finalizer
# --------------------------------------------------------------------------


class CoreArtifactFinalizer:
    """Plan 4.2: the production ``ArtifactFinalizer`` over the store, the unit of
    work factory and the purpose registrar. Holds no state between calls; two
    calls with equal requests are replays."""

    def __init__(
        self,
        unit_of_work_factory: UnitOfWorkFactory,
        clock: Clock,
        hasher: ContentHasher,
        store: ArtifactStore,
        probe: FinalizationProbe,
        registrar: PurposeRegistrar,
        auditor: FinalizationAuditor,
        *,
        command_roots: CommandRootsLookup,
        token_material: TokenMaterialLookup,
        log: FinalizationLog | None = None,
        ceilings: ValidationCeilings = DEFAULT_CEILINGS,
        fail_run_on_abandon: bool = False,
    ) -> None:
        if not isinstance(store, ArtifactStore):
            raise TypeError("store must be an ArtifactStore")
        if not isinstance(hasher, ContentHasher):
            raise TypeError("hasher must implement ContentHasher")
        if not isinstance(probe, FinalizationProbe):
            raise TypeError("probe must implement FinalizationProbe")
        if not callable(unit_of_work_factory):
            raise TypeError("unit_of_work_factory must be callable")
        self._factory = unit_of_work_factory
        self._clock = clock
        self._hasher = hasher
        self._store = store
        self._probe = probe
        self._registrar = registrar
        #: The canonical evidence ruling of 2026-11-09: a registrar that also
        #: answers the plan 4.6 contract qualifies ``CORE`` evidence; any other
        #: registrar leaves every text evidence under the whole-content scan.
        self._canonical: CanonicalEvidenceQualifier | None = (
            registrar if isinstance(registrar, CanonicalEvidenceQualifier) else None
        )
        self._auditor = auditor
        self._command_roots = command_roots
        self._token_material = token_material
        self._log = log
        self._ceilings = ceilings
        #: 17.3: the reconciler, which has no caller, fails the run it abandons.
        self._fail_run_on_abandon = fail_run_on_abandon

    # -- the coroutine ----------------------------------------------------------

    async def finalize(
        self,
        request: FinalizationRequest,
        cancellation: CancellationToken,
        *,
        token_material: AttemptTokenMaterial | MISSING = MISSING,  # type: ignore[valid-type]
    ) -> Result[FinalizationResult]:
        """Specification 8.2 and plan 4.3: one purpose-tagged finalization.
        ``token_material`` is the caller's transient material for this call
        (plan 4.4's conclusion, before the root's raw bytes are closed); absent,
        the ``token_material`` lookup answers."""
        now = self._clock.now_utc()
        if not isinstance(
            request, ResultFinalizationRequest | EvidenceFinalizationRequest
        ):
            return _failure_of(
                _restated_diagnostic(
                    CORE_INVARIANT_VIOLATION,
                    message=(
                        "finalize consumes a ResultFinalizationRequest or an "
                        "EvidenceFinalizationRequest"
                    ),
                    now_utc=now,
                )
            )
        if token_material is not MISSING and not isinstance(
            token_material, AttemptTokenMaterial
        ):
            return _failure_of(
                _restated_diagnostic(
                    CORE_INVARIANT_VIOLATION,
                    message="token_material must be AttemptTokenMaterial or absent",
                    now_utc=now,
                )
            )
        scope = _scope_of_request(request)
        if cancellation.is_cancellation_requested():
            return self._cancelled(scope)
        opened = self._open(scope)
        if isinstance(opened, Failure):
            return opened
        if isinstance(opened, FinalizationResult):
            return Success[FinalizationResult](outcome="SUCCESS", value=opened)
        if isinstance(opened, FinalizationJournalEntry):
            # An expired lease: the request takes over under the same identity.
            return self.resume_journal(opened)
        work = opened
        await cooperative_checkpoint()
        if cancellation.is_cancellation_requested():
            return self._cancelled(scope)
        validated = self._validate_phase(work, token_material)
        if validated is not None:
            return validated
        self._probe.before_prepared()
        await cooperative_checkpoint()
        if cancellation.is_cancellation_requested():
            return self._cancelled(scope)
        prepared = self._prepare_phase(work)
        if prepared is not None:
            return prepared
        self._probe.after_prepared()
        await cooperative_checkpoint()
        # A request observed from here on is ignored: the lease is held and the
        # run compare-and-swap of T3 decides (reading 1).
        cancellation.is_cancellation_requested()
        return await self._complete(work)

    async def _complete(self, work: _Work) -> Result[FinalizationResult]:
        """Phases 3 through 6 with a checkpoint after every probe point."""
        outcome: Result[FinalizationResult] | None = None
        for index in range(len(work.entry.planned_paths)):
            failed = self._move_one(work, index)
            await cooperative_checkpoint()
            if failed is not None:
                outcome = failed
                break
        if outcome is None:
            moved = self._moved_phase(work)
            await cooperative_checkpoint()
            if moved is not None:
                outcome = moved
        if outcome is None:
            outcome = self._register_phase(work)
            await cooperative_checkpoint()
        if work.scope.is_result and work.terminal:
            self._close_phase(work)
            self._probe.after_close()
            await cooperative_checkpoint()
        return outcome

    def resume_journal(
        self, entry: FinalizationJournalEntry
    ) -> Result[FinalizationResult]:
        """Resume an open journal from its durable state (plan 5.1 recovery
        columns) after taking its lease (``_take_over``: an unexpired lease is
        the conflict, an expired one is renewed by one compare-and-swap, an
        exhausted deadline takes no lease): a ``PREPARED`` entry revalidates
        every planned move -- at its finalized path with the expected hash, or
        still in staging -- and continues phase 3; a ``MOVED`` entry registers.
        The deadline governs a ``RESULT`` entry at every poll, and it is polled
        first: a deadline already exhausted when the journal is resumed is the
        plan 4.5 timeout (RV-15) before any revalidation or hash of disturbed
        bytes can select a different failure outcome."""
        if entry.state not in _OPEN_JOURNAL_STATES:
            return _failure_of(
                _restated_diagnostic(
                    CORE_INVARIANT_VIOLATION,
                    message=f"journal {entry.finalization_id} is not open",
                    now_utc=self._clock.now_utc(),
                )
            )
        scope = _scope_of_journal(entry)
        loaded = self._load_journal_work(scope, entry)
        if isinstance(loaded, Failure):
            return loaded
        work = loaded
        taken = self._take_over(work)
        if taken is not None:
            return taken
        entry = work.entry
        outcome: Result[FinalizationResult] | None = None
        if self._deadline_passed(work):
            outcome = self._time_out(work)
        elif entry.state is _J.PREPARED:
            revalidated = self._revalidate_planned(work)
            if revalidated is not None:
                outcome = revalidated
            else:
                for index in range(len(entry.planned_paths)):
                    failed = self._move_one(work, index)
                    if failed is not None:
                        outcome = failed
                        break
                if outcome is None:
                    outcome = self._moved_phase(work)
        if outcome is None:
            outcome = self._register_phase(work)
        if scope.is_result and work.terminal:
            self._close_phase(work)
            self._probe.after_close()
        return outcome

    # -- phase 0 -----------------------------------------------------------------

    @contextmanager
    def _transaction(self) -> Iterator[RegistrationUnitOfWork]:
        transaction = self._factory()
        try:
            yield transaction
        finally:
            transaction.rollback()

    def _cancelled(self, scope: _Scope) -> Failure:
        return _failure_of(
            _restated_diagnostic(
                PROCESS_CANCELLED,
                message="cancellation was requested before the finalization lease",
                now_utc=self._clock.now_utc(),
                **scope.audit_ids(),
            )
        )

    def _invariant(self, scope: _Scope, message: str) -> Failure:
        return _failure_of(
            _restated_diagnostic(
                CORE_INVARIANT_VIOLATION,
                message=message,
                now_utc=self._clock.now_utc(),
                **scope.audit_ids(),
            )
        )

    def _conflict(self, scope: _Scope, message: str) -> Failure:
        return _failure_of(
            _restated_diagnostic(
                PERSISTENCE_CONCURRENCY_CONFLICT,
                message=message,
                now_utc=self._clock.now_utc(),
                **scope.audit_ids(),
            )
        )

    def _validation_refusal(self, scope: _Scope, code: str, message: str) -> Failure:
        return artifact_failure(
            code,
            message=message,
            invocation_id=scope.invocation_id,
            run_id=scope.run_id,
            experiment_id=scope.experiment_id,
            now_utc=self._clock.now_utc(),
        )

    def _open(
        self, scope: _Scope
    ) -> _Work | FinalizationResult | FinalizationJournalEntry | Failure:
        """Plan 4.7 (c) and (d): the candidates and the replay lookup in one
        read-only transaction, then the confinement."""
        now = self._clock.now_utc()
        replay: FinalizationResult | None = None
        candidates: dict[str, CandidateArtifact] = {}
        with self._transaction() as transaction:
            found = self._find_journal(transaction, scope)
            if isinstance(found, Failure):
                return found
            entry = found.value
            if isinstance(entry, FinalizationJournalEntry):
                if entry.finalization_id != scope.finalization_id:
                    return self._conflict(
                        scope,
                        "a finalization with a different identity already names this "
                        "attempt or evidence set (17.2)",
                    )
                if entry.state is _J.REGISTERED:
                    stored = self._stored_result(transaction, entry, scope)
                    if isinstance(stored, Failure):
                        return stored
                    replay = stored
                elif entry.state is _J.ABANDONED:
                    return self._conflict(
                        scope, f"finalization {entry.finalization_id} was abandoned"
                    )
                elif entry.lease_expires_at_utc > now:
                    return self._conflict(
                        scope,
                        f"finalization {entry.finalization_id} holds an active lease",
                    )
                else:
                    return entry
            if replay is None:
                for candidate_id in scope.candidate_ids:
                    loaded = transaction.candidate_artifacts.get(candidate_id)
                    if isinstance(loaded, Failure):
                        return loaded
                    refusal = self._check_candidate(scope, loaded.value)
                    if refusal is not None:
                        return refusal
                    candidates[candidate_id] = loaded.value
                describe = self._check_describe_correlation(transaction, scope)
                if describe is not None:
                    return describe
        if replay is not None:
            audited = self._audit_alone(
                scope, "FINALIZATION_REPLAYED", "SUCCEEDED", {"replayed": True}
            )
            if isinstance(audited, Failure):
                return audited
            return replay
        located = self._locate(scope)
        if isinstance(located, Failure):
            return located
        root, roots = located
        work = _Work(scope=scope, candidates=candidates, root=root, roots=roots)
        for candidate_id in scope.candidate_ids:
            candidate = candidates[candidate_id]
            confined = confine_candidate_path(
                root, candidate.staging_relative_path, now_utc=now
            )
            if isinstance(confined, Failure):
                return self._quarantine_unconfined(work, candidate, confined)
            work.confined[candidate_id] = confined.value
        return work

    def _find_journal(
        self, transaction: RegistrationUnitOfWork, scope: _Scope
    ) -> Result[FinalizationJournalEntry | MISSING]:  # type: ignore[valid-type]
        journal = transaction.finalization_journal
        if scope.is_result:
            return journal.find_result_identity(
                str(scope.invocation_id), str(scope.source_hash)
            )
        correlation = scope.correlation
        if not isinstance(correlation, EvidenceCorrelation):
            return self._invariant(
                scope, "an EVIDENCE finalization carries a correlation"
            )
        return journal.find_evidence_identity(
            scope.owner_hash,
            correlation.kind,
            correlation.correlation_id,
            scope.candidate_set_hash,
        )

    def _stored_result(
        self,
        transaction: RegistrationUnitOfWork,
        entry: FinalizationJournalEntry,
        scope: _Scope,
    ) -> FinalizationResult | Failure:
        payload: dict[str, Any] = {
            "schema_version": "1.0.0",
            "finalization_id": entry.finalization_id,
            "finalization_purpose": entry.finalization_purpose,
            "owner": entry.owner,
            "journal_state": "REGISTERED",
            "candidate_to_artifact_refs": tuple(
                CandidateFinalization(
                    candidate_artifact_id=move.candidate_artifact_id,
                    artifact_id=artifact_id_for(
                        move.candidate_artifact_id, move.observed_sha256
                    ),
                    content_hash=move.observed_sha256,
                    size_bytes=move.observed_size_bytes,
                    deduplicated=move.deduplicated,
                )
                for move in entry.observed
            ),
            "registered_at_utc": entry.updated_at_utc,
            "replayed": True,
        }
        if entry.finalization_purpose is _F.RESULT:
            manifest = transaction.run_manifests.get(str(entry.run_id))
            if isinstance(manifest, Failure):
                return manifest
            facts = manifest.value
            if _is_missing(facts):
                return self._invariant(
                    scope, "a REGISTERED RESULT finalization requires its run manifest"
                )
            payload["run_manifest_id"] = facts.manifest_id
            payload["run_manifest_hash"] = facts.run_manifest_hash
        return FinalizationResult.model_validate(payload)

    def _check_candidate(
        self, scope: _Scope, candidate: CandidateArtifact
    ) -> Failure | None:
        identity = candidate.candidate_artifact_id
        if artifact_owner_hash(candidate.owner) != scope.owner_hash:
            return self._invariant(
                scope,
                f"candidate {identity} belongs to another registered owner than the "
                "request's",
            )
        if scope.purpose is _F.EVIDENCE and candidate.producer_kind is _P.ADAPTER:
            return self._validation_refusal(
                scope,
                ARTIFACT_VALIDATION_FAILED,
                "adapter-produced candidate cannot be evidence (19.1)",
            )
        if candidate.finalization_purpose is not scope.purpose:
            return self._validation_refusal(
                scope,
                ARTIFACT_VALIDATION_FAILED,
                f"candidate {identity} purpose differs from the request",
            )
        if candidate.source_role is not scope.source_role:
            return self._validation_refusal(
                scope,
                ARTIFACT_VALIDATION_FAILED,
                f"candidate {identity} role differs from the request",
            )
        if candidate.state in (_S.QUARANTINED, _S.CORRUPT):
            return self._validation_refusal(
                scope,
                ARTIFACT_VALIDATION_FAILED,
                f"candidate {identity} is terminal ({candidate.state.value})",
            )
        if candidate.state is _S.FINALIZING:
            return self._invariant(
                scope,
                f"candidate {identity} is FINALIZING without an open journal for "
                "this identity",
            )
        return None

    def _check_describe_correlation(
        self, transaction: RegistrationUnitOfWork, scope: _Scope
    ) -> Failure | None:
        """Plan 3.1.1 row 3: an ``ADAPTER`` owner's ``INVOCATION`` correlation names
        a ``DESCRIBE`` invocation of that adapter."""
        owner = scope.owner
        correlation = scope.correlation
        if not isinstance(owner, AdapterArtifactOwner) or not isinstance(
            correlation, EvidenceCorrelation
        ):
            return None
        loaded = transaction.command_invocations.get(correlation.correlation_id)
        if isinstance(loaded, Failure):
            return loaded
        invocation = loaded.value
        if (
            invocation.command_kind is not CommandKind.DESCRIBE
            or invocation.adapter_name != owner.adapter_name
            or invocation.adapter_version != owner.adapter_version
        ):
            return self._validation_refusal(
                scope,
                ARTIFACT_VALIDATION_FAILED,
                "the INVOCATION correlation of an ADAPTER owner must name a DESCRIBE "
                "invocation of that adapter",
            )
        return None

    def _locate(
        self, scope: _Scope
    ) -> tuple[Path, CommandRootPaths | MISSING] | Failure:  # type: ignore[valid-type]
        """The confinement root: the ``RUN`` root's work directory for ``RESULT``,
        the owner's core staging root for ``EVIDENCE``."""
        if not scope.is_result:
            return self._store.staging_root / scope.owner_hash, MISSING
        roots = self._command_roots(str(scope.invocation_id))
        if not isinstance(roots, CommandRootPaths) or not isinstance(
            roots.work_dir, Path
        ):
            return self._invariant(
                scope,
                "a RESULT finalization requires the RUN root of its run-command "
                "invocation",
            )
        return roots.work_dir, roots

    def _quarantine_unconfined(
        self, work: _Work, candidate: CandidateArtifact, refusal: Failure
    ) -> Failure:
        """Phase 0: the candidate at fault is ``QUARANTINED``; nothing else is
        written and the file, unconfined, is never opened or moved."""
        scope = work.scope
        now = self._clock.now_utc()
        diagnostic = artifact_diagnostic(
            ARTIFACT_PATH_BOUNDARY_VIOLATION,
            message=refusal.diagnostics[0].message,
            invocation_id=scope.invocation_id,
            run_id=scope.run_id,
            experiment_id=scope.experiment_id,
            now_utc=now,
        )
        observation = ValidationObservation(
            observed_at_utc=now,
            stage="PATH",
            outcome="FAILED",
            error_code=ARTIFACT_PATH_BOUNDARY_VIOLATION,
            diagnostic_id=diagnostic.diagnostic_id,
        )
        with self._transaction() as transaction:
            recorded = transaction.diagnostics_writer.record(diagnostic)
            if isinstance(recorded, Failure):
                return recorded
            swapped = transaction.candidate_artifacts.compare_and_swap(
                candidate.revision,
                _candidate_replacement(candidate, _S.QUARANTINED, (observation,), now),
            )
            if isinstance(swapped, Failure):
                return swapped
            audited = self._auditor.append(
                transaction,
                AuditFact(
                    action="ARTIFACT_QUARANTINED",
                    outcome="REFUSED",
                    correlation_id=scope.finalization_id,
                    details={
                        "reason": ARTIFACT_PATH_BOUNDARY_VIOLATION,
                        "stage": "PATH",
                    },
                    **scope.audit_ids(),
                ),
            )
            if isinstance(audited, Failure):
                return audited
            committed = transaction.commit()
            if isinstance(committed, Failure):
                return committed
        work.candidates[candidate.candidate_artifact_id] = swapped.value
        self._write_log("ERROR", ARTIFACT_PATH_BOUNDARY_VIOLATION, scope, "quarantined")
        return _failure_of(diagnostic)

    # -- phase 1 -----------------------------------------------------------------

    def _resolve_material(
        self,
        scope: _Scope,
        supplied: AttemptTokenMaterial | MISSING,  # type: ignore[valid-type]
    ) -> AttemptTokenMaterial | Failure | None:
        """The ruling of 2026-11-09: the material for the phase-1 exact scan --
        the caller's transient material, else the lookup's answer -- validated
        against the authoritative run and invocation before use: it names the
        owner's run and hashes to the run's stored ``attempt_token_hash``; for
        evidence the invocation it was answered for must belong to that run too
        (a ``RESULT`` request's run-command invocation is verified by the T1 lease
        check itself). Required for ``RESULT`` (the invariant when absent);
        optional for ``RUN``-owned evidence with an invocation (``None`` is a
        token-free validation, never reported as an exact scan); never admitted
        for an owner without a run. The reads are one short transaction, closed
        before any candidate is opened."""
        owner = scope.owner
        if not isinstance(owner, RunArtifactOwner) or not isinstance(
            scope.invocation_id, str
        ):
            if isinstance(supplied, AttemptTokenMaterial):
                return self._invariant(
                    scope,
                    "a finalization of an owner without a run and an invocation "
                    "takes no attempt token material",
                )
            return None
        invocation_id = scope.invocation_id
        material = (
            supplied
            if isinstance(supplied, AttemptTokenMaterial)
            else self._token_material(invocation_id)
        )
        if not isinstance(material, AttemptTokenMaterial):
            if scope.is_result:
                return self._invariant(
                    scope,
                    "a RESULT finalization requires the attempt token material of "
                    "its invocation",
                )
            return None
        mismatch = (
            f"the attempt token material answered for invocation {invocation_id} "
            "is not the run's"
        )
        if material.run_id != owner.run_id:
            return self._invariant(scope, mismatch)
        with self._transaction() as transaction:
            run = transaction.engine_runs.get(owner.run_id)
            if isinstance(run, Failure):
                return run
            if (
                attempt_token_hash(material.attempt_token)
                != run.value.attempt_token_hash
            ):
                return self._invariant(scope, mismatch)
            if scope.is_result:
                return material
            invocation = transaction.command_invocations.get(invocation_id)
            if isinstance(invocation, Failure):
                return invocation
            if invocation.value.run_id != owner.run_id:
                return self._invariant(scope, mismatch)
        return material

    def _validate_phase(
        self,
        work: _Work,
        supplied: AttemptTokenMaterial | MISSING,  # type: ignore[valid-type]
    ) -> Failure | None:
        """Plan 4.3 phase 1 over every candidate, no transaction across hashing."""
        scope = work.scope
        now = self._clock.now_utc()
        resolved = self._resolve_material(scope, supplied)
        if isinstance(resolved, Failure):
            return resolved
        token: AttemptTokenMaterial | MISSING = (  # type: ignore[valid-type]
            resolved if resolved is not None else MISSING
        )
        validations: dict[str, CandidateValidation] = {}
        for candidate_id in scope.candidate_ids:
            candidate = work.candidates[candidate_id]
            if candidate.state is _S.CANDIDATE:
                swapped = self._swap_candidate(
                    candidate, _S.VALIDATING, (), now, registered_mapping=MISSING
                )
                if isinstance(swapped, Failure):
                    return swapped
                candidate = swapped.value
                work.candidates[candidate_id] = candidate
            validations[candidate_id] = self._validate_one(work, candidate, token, now)
        failed = {
            candidate_id: validation
            for candidate_id, validation in validations.items()
            if isinstance(validation.result, Failure)
        }
        if not failed:
            for candidate_id, validation in validations.items():
                if isinstance(validation.result, Success):
                    work.validated[candidate_id] = validation.result.value
            return None
        leakage = any(
            _code_of(validation.result) == SECURITY_SENSITIVE_MATERIAL_LEAKAGE
            for validation in failed.values()
            if isinstance(validation.result, Failure)
        )
        primary: Failure | None = None
        for candidate_id in scope.candidate_ids:
            validation = validations[candidate_id]
            if candidate_id in failed and isinstance(validation.result, Failure):
                outcome = self._fail_candidate(
                    work, candidate_id, validation.observations, validation.result
                )
                if primary is None or (
                    leakage and _code_of(outcome) == SECURITY_SENSITIVE_MATERIAL_LEAKAGE
                ):
                    primary = outcome
            elif leakage and scope.is_result:
                # 14.7: contamination rejects every RESULT candidate of the attempt.
                sibling = self._validation_refusal(
                    scope,
                    SECURITY_SENSITIVE_MATERIAL_LEAKAGE,
                    "a sibling RESULT candidate carried the raw attempt token",
                )
                observation = ValidationObservation(
                    observed_at_utc=now,
                    stage="SEMANTIC",
                    outcome="FAILED",
                    error_code=SECURITY_SENSITIVE_MATERIAL_LEAKAGE,
                    diagnostic_id=sibling.diagnostics[0].diagnostic_id,
                )
                self._fail_candidate(
                    work,
                    candidate_id,
                    (*validation.observations, observation),
                    sibling,
                )
        assert primary is not None  # noqa: S101 - failed is non-empty
        return primary

    def _validate_one(
        self,
        work: _Work,
        candidate: CandidateArtifact,
        token: AttemptTokenMaterial | MISSING,  # type: ignore[valid-type]
        now: datetime,
    ) -> CandidateValidation:
        media: str | MISSING = MISSING  # type: ignore[valid-type]
        if candidate.producer_kind is _P.CORE:
            known = CORE_EVIDENCE_MEDIA_TYPES.get(candidate.artifact_kind)
            if known is None:
                refusal = self._validation_refusal(
                    work.scope,
                    ARTIFACT_VALIDATION_FAILED,
                    f"artifact kind {candidate.artifact_kind} has no admitted media "
                    "type",
                )
                return CandidateValidation(
                    observations=(
                        ValidationObservation(
                            observed_at_utc=now,
                            stage="MEDIA",
                            outcome="FAILED",
                            error_code=ARTIFACT_VALIDATION_FAILED,
                            diagnostic_id=refusal.diagnostics[0].diagnostic_id,
                        ),
                    ),
                    result=refusal,
                )
            media = known
        return validate_candidate(
            candidate,
            work.confined[candidate.candidate_artifact_id],
            hasher=self._hasher,
            token=token,
            ceilings=self._ceilings,
            now_utc=now,
            media_type=media,
            canonical=self._canonical if self._canonical is not None else MISSING,
        )

    def _fail_candidate(
        self,
        work: _Work,
        candidate_id: str,
        observations: tuple[ValidationObservation, ...],
        failure: Failure,
    ) -> Failure:
        """A failed phase-1 check: ``VALIDATING -> QUARANTINED`` (``CORRUPT`` for a
        proven size or hash mismatch), the diagnostic recorded and the audit fact
        in one short transaction, then the bytes to the candidate's quarantine
        entry; a storage failure classifies nothing and leaves the candidate
        ``VALIDATING`` for recovery (reading 26)."""
        scope = work.scope
        now = self._clock.now_utc()
        diagnostic = failure.diagnostics[0]
        code = diagnostic.error_code
        if code == ARTIFACT_MOVE_FAILED:
            return failure
        failed_stage = next(
            (item.stage for item in reversed(observations) if item.outcome == "FAILED"),
            "SEMANTIC",
        )
        corrupt = code == ARTIFACT_VALIDATION_FAILED and failed_stage in _CORRUPT_STAGES
        target_state = _S.CORRUPT if corrupt else _S.QUARANTINED
        candidate = work.candidates[candidate_id]
        with self._transaction() as transaction:
            recorded = transaction.diagnostics_writer.record(diagnostic)
            if isinstance(recorded, Failure):
                return recorded
            swapped = transaction.candidate_artifacts.compare_and_swap(
                candidate.revision,
                _candidate_replacement(candidate, target_state, observations, now),
            )
            if isinstance(swapped, Failure):
                return swapped
            details: dict[str, DiagnosticDetailValue] = {
                "reason": code,
                "stage": failed_stage,
            }
            facts = [("ARTIFACT_CORRUPT" if corrupt else "ARTIFACT_QUARANTINED")]
            leaked = code == SECURITY_SENSITIVE_MATERIAL_LEAKAGE
            if leaked and failed_stage != "SEMANTIC":
                facts.insert(0, "ARTIFACT_LEAKAGE_DETECTED")
            for action in facts:
                audited = self._auditor.append(
                    transaction,
                    AuditFact(
                        action=action,
                        outcome="REFUSED",
                        correlation_id=scope.finalization_id,
                        details=details,
                        **scope.audit_ids(),
                    ),
                )
                if isinstance(audited, Failure):
                    return audited
            committed = transaction.commit()
            if isinstance(committed, Failure):
                return committed
        work.candidates[candidate_id] = swapped.value
        confined = work.confined.get(candidate_id)
        if confined is not None:
            self._store.quarantine_move(
                confined, candidate_id, code, now_utc=now, sha256=MISSING
            )
        self._write_log("ERROR", code, scope, f"candidate {target_state.value.lower()}")
        return failure

    def _swap_candidate(
        self,
        candidate: CandidateArtifact,
        state: CandidateArtifactState,
        observations: tuple[ValidationObservation, ...],
        now: datetime,
        *,
        registered_mapping: CandidateFinalization | MISSING,  # type: ignore[valid-type]
    ) -> Result[CandidateArtifact]:
        with self._transaction() as transaction:
            swapped = transaction.candidate_artifacts.compare_and_swap(
                candidate.revision,
                _candidate_replacement(candidate, state, observations, now),
                registered_mapping=registered_mapping,
            )
            if isinstance(swapped, Failure):
                return swapped
            committed = transaction.commit()
            if isinstance(committed, Failure):
                return committed
            return swapped

    # -- T1 ---------------------------------------------------------------------

    def _prepare_phase(self, work: _Work) -> Failure | None:
        scope = work.scope
        now = self._clock.now_utc()
        with self._transaction() as transaction:
            deadline: datetime | MISSING = MISSING  # type: ignore[valid-type]
            expected_run_revision: int | MISSING = MISSING  # type: ignore[valid-type]
            if scope.is_result:
                facts = transaction.result_leases.active_attempt_facts(
                    str(scope.run_id), str(scope.invocation_id)
                )
                if isinstance(facts, Failure):
                    return facts
                refusal = self._lease_refusal(transaction, scope, facts.value)
                if refusal is not None:
                    transaction.rollback()
                    return self._lease_refused(scope, refusal)
                found = self._find_journal(transaction, scope)
                if isinstance(found, Failure):
                    return found
                if isinstance(found.value, FinalizationJournalEntry):
                    return self._conflict(
                        scope, "a RESULT journal already names this attempt"
                    )
                deadline = now + timedelta(seconds=scope.timeout_seconds)
                snapshot = transaction.result_leases.snapshot_deadline(
                    _as_int(scope.expected_run_revision), str(scope.run_id), deadline
                )
                if isinstance(snapshot, Failure):
                    transaction.rollback()
                    return self._lease_refused(scope, snapshot)
                expected_run_revision = snapshot.value.revision
                lease = min(now + timedelta(seconds=RESULT_LEASE_SECONDS), deadline)
            else:
                found = self._find_journal(transaction, scope)
                if isinstance(found, Failure):
                    return found
                if isinstance(found.value, FinalizationJournalEntry):
                    return self._conflict(
                        scope, "an EVIDENCE journal already names this identity"
                    )
                lease = now + timedelta(seconds=EVIDENCE_LEASE_SECONDS)
            finalizing: dict[str, CandidateArtifact] = {}
            for candidate_id in scope.candidate_ids:
                candidate = work.candidates[candidate_id]
                swapped = transaction.candidate_artifacts.compare_and_swap(
                    candidate.revision,
                    _candidate_replacement(
                        candidate,
                        _S.FINALIZING,
                        work.validated[candidate_id].observations,
                        now,
                    ),
                )
                if isinstance(swapped, Failure):
                    return swapped
                finalizing[candidate_id] = swapped.value
            entry = self._prepared_entry(
                work,
                now=now,
                deadline=deadline,
                lease=lease,
                expected_run_revision=expected_run_revision,
            )
            prepared = transaction.finalization_journal.prepare(entry)
            if isinstance(prepared, Failure):
                return prepared
            for candidate_id in scope.candidate_ids:
                validated = work.validated[candidate_id]
                audited = self._audit(
                    transaction,
                    scope,
                    "ARTIFACT_VALIDATED",
                    "SUCCEEDED",
                    {
                        "purpose": scope.purpose.value,
                        # The ruling of 2026-11-09: a token-free validation is
                        # never represented as a successful exact scan.
                        "exact_scan": validated.exact_token_scanned,
                        "canonical": validated.canonical,
                    },
                )
                if isinstance(audited, Failure):
                    return audited
            for action in ("FINALIZATION_LEASE_ACQUIRED", "FINALIZATION_PREPARED"):
                audited = self._audit(
                    transaction,
                    scope,
                    action,
                    "SUCCEEDED",
                    {
                        "purpose": scope.purpose.value,
                        "candidates": len(scope.candidate_ids),
                        "lease_seconds": _lease_interval_seconds(scope),
                        "timeout_seconds": scope.timeout_seconds,
                    },
                )
                if isinstance(audited, Failure):
                    return audited
            committed = transaction.commit()
            if isinstance(committed, Failure):
                return committed
        work.candidates.update(finalizing)
        work.journal = entry
        work.deadline_utc = deadline
        if isinstance(deadline, datetime):
            work.deadline_monotonic = self._clock.monotonic().seconds + float(
                scope.timeout_seconds
            )
        self._write_log("INFO", "ARTIFACT.FINALIZATION_PREPARED", scope, "prepared")
        return None

    def _lease_refusal(
        self,
        transaction: RegistrationUnitOfWork,
        scope: _Scope,
        facts: ResultLeaseFacts,
    ) -> Failure | None:
        """Plan 4.4's refusals before T1 and plan 4.7 (e), in order."""
        if facts.run_state is not EngineRunState.RUNNING:
            return self._invariant(
                scope, f"run {facts.run_id} is {facts.run_state.value}, not RUNNING"
            )
        if facts.run_revision != scope.expected_run_revision:
            return self._conflict(
                scope,
                f"run {facts.run_id} is at revision {facts.run_revision}, not "
                f"{scope.expected_run_revision}",
            )
        if (
            facts.invocation_state is not CommandInvocationState.EXITED
            or facts.command_kind is not CommandKind.RUN
        ):
            return self._invariant(
                scope,
                f"invocation {facts.run_invocation_id} is not the EXITED run-command "
                "invocation of the run",
            )
        if _is_missing(facts.process_exit_category):
            return self._invariant(
                scope,
                f"invocation {facts.run_invocation_id} has no captured exit facts",
            )
        if facts.invocation_revision != scope.expected_invocation_revision:
            return self._conflict(
                scope,
                f"invocation {facts.run_invocation_id} is at revision "
                f"{facts.invocation_revision}, not "
                f"{scope.expected_invocation_revision}",
            )
        if facts.attempt_token_hash != scope.attempt_token_hash:
            return self._invariant(
                scope, "the request's attempt token hash is not the run's"
            )
        if not facts.is_latest_attempt:
            return self._invariant(
                scope, f"run {facts.run_id} is not the latest attempt of its slot"
            )
        if facts.experiment_state is not ExperimentState.RUNNING:
            return self._invariant(
                scope, f"experiment {facts.experiment_id} is not RUNNING"
            )
        run = transaction.engine_runs.get(str(scope.run_id))
        if isinstance(run, Failure):
            return run
        invocation = transaction.command_invocations.get(str(scope.invocation_id))
        if isinstance(invocation, Failure):
            return invocation
        if invocation.value.request_hash != run.value.request_hash:
            return self._invariant(
                scope,
                f"invocation {facts.run_invocation_id} is not the active run-command "
                "of the run",
            )
        return None

    def _lease_refused(self, scope: _Scope, refusal: Failure) -> Failure:
        """``FINALIZATION_LEASE_REFUSED`` in its own short transaction; no journal
        row is written."""
        audited = self._audit_alone(
            scope,
            "FINALIZATION_LEASE_REFUSED",
            "REFUSED",
            {"reason": _code_of(refusal)},
        )
        if isinstance(audited, Failure):
            return audited
        self._write_log("WARNING", _code_of(refusal), scope, "lease refused")
        return refusal

    def _prepared_entry(
        self,
        work: _Work,
        *,
        now: datetime,
        deadline: datetime | MISSING,  # type: ignore[valid-type]
        lease: datetime,
        expected_run_revision: int | MISSING,  # type: ignore[valid-type]
    ) -> FinalizationJournalEntry:
        scope = work.scope
        planned: list[PlannedMove] = []
        for candidate_id in scope.candidate_ids:
            candidate = work.candidates[candidate_id]
            validated = work.validated[candidate_id]
            planned.append(
                PlannedMove(
                    candidate_artifact_id=candidate_id,
                    staging_relative_path=candidate.staging_relative_path,
                    finalized_relative_path=validated.finalized_relative_path,
                    expected_sha256=validated.content_hash,
                    expected_size_bytes=validated.size_bytes,
                )
            )
        payload: dict[str, Any] = {
            "schema_version": "1.0.0",
            "finalization_id": scope.finalization_id,
            "finalization_purpose": scope.purpose,
            "owner": scope.owner,
            "source_role": scope.source_role,
            "candidate_artifact_ids": scope.candidate_ids,
            "candidate_set_hash": scope.candidate_set_hash,
            "state": _J.PREPARED,
            "prepared_at_utc": now,
            "finalization_deadline_utc": deadline,
            "lease_expires_at_utc": lease,
            "expected_run_revision": expected_run_revision,
            "expected_invocation_revision": scope.expected_invocation_revision,
            # The run and invocation are journal fields of a RESULT entry alone; an
            # EVIDENCE scope carries them only as audit correlation.
            "run_id": scope.run_id if scope.is_result else MISSING,
            "run_invocation_id": scope.invocation_id if scope.is_result else MISSING,
            "attempt_token_hash": scope.attempt_token_hash,
            "source_adapter_result_manifest_hash": scope.source_hash,
            "sanitized_adapter_result_manifest_hash": scope.sanitized_hash,
            "correlation": scope.correlation,
            "planned_paths": tuple(planned),
            "observed": (),
            "updated_at_utc": now,
            "revision": 1,
        }
        return FinalizationJournalEntry.model_validate(_without_missing(payload))

    # -- resume ------------------------------------------------------------------

    def _take_over(self, work: _Work) -> Failure | None:
        """The RESULT lease ruling of 2026-11-08, applied to both purposes: an
        open journal is resumed only by taking its lease. An unexpired lease
        belongs to its holder -- a restart alone supplies no authority over it --
        and is the conflict (RC-12). A deadline reached or passed takes no lease:
        the attempt proceeds at the stored revision, where the strict polls of
        phases 3 to 5 admit the deadline instant itself (the plan's ``now_utc <=
        deadline``) and time every later instant out (RV-15). Otherwise the
        takeover is one compare-and-swap at the
        stored revision -- the same state, ``lease_expires_at_utc`` renewed to
        ``min(now + interval, deadline)``, revision plus one, nothing else --
        audited as ``FINALIZATION_LEASE_ACQUIRED`` with ``takeover`` in the same
        transaction (RC-13, CP-2). A stale newcomer, whose revision another
        takeover already moved, is refused here before any move or hash; the
        superseded holder's every later write fails at its stale revision."""
        scope = work.scope
        entry = work.entry
        now = self._clock.now_utc()
        if entry.lease_expires_at_utc > now:
            return self._conflict(
                scope, f"finalization {entry.finalization_id} holds an active lease"
            )
        deadline = work.deadline_utc
        if self._deadline_passed(work) or (
            isinstance(deadline, datetime) and now >= deadline
        ):
            return None
        replacement = _journal_replacement(
            entry,
            state=entry.state,
            now=now,
            observed=entry.observed,
            lease=self._renewed_lease(work, now),
        )
        with self._transaction() as transaction:
            swapped = transaction.finalization_journal.compare_and_swap(
                entry.revision, replacement
            )
            if isinstance(swapped, Failure):
                return swapped
            audited = self._audit(
                transaction,
                scope,
                "FINALIZATION_LEASE_ACQUIRED",
                "SUCCEEDED",
                {
                    "purpose": scope.purpose.value,
                    "takeover": True,
                    "from_revision": entry.revision,
                    "lease_seconds": _lease_interval_seconds(scope),
                },
            )
            if isinstance(audited, Failure):
                return audited
            committed = transaction.commit()
            if isinstance(committed, Failure):
                return committed
        work.journal = swapped.value
        self._write_log(
            "INFO", "ARTIFACT.FINALIZATION_LEASE_ACQUIRED", scope, "lease taken over"
        )
        return None

    def _load_journal_work(
        self, scope: _Scope, entry: FinalizationJournalEntry
    ) -> _Work | Failure:
        candidates: dict[str, CandidateArtifact] = {}
        with self._transaction() as transaction:
            for candidate_id in scope.candidate_ids:
                loaded = transaction.candidate_artifacts.get(candidate_id)
                if isinstance(loaded, Failure):
                    return loaded
                candidates[candidate_id] = loaded.value
        located = self._locate(scope)
        if isinstance(located, Failure):
            return located
        root, roots = located
        work = _Work(scope=scope, candidates=candidates, root=root, roots=roots)
        work.journal = entry
        deadline = entry.finalization_deadline_utc
        if isinstance(deadline, datetime):
            work.deadline_utc = deadline
            remaining = (deadline - self._clock.now_utc()).total_seconds()
            work.deadline_monotonic = self._clock.monotonic().seconds + remaining
        work.observed = list(entry.observed)
        for move in entry.observed:
            work.moved[move.candidate_artifact_id] = move.deduplicated
        return work

    def _revalidate_planned(self, work: _Work) -> Failure | None:
        """CP-2 and CP-3 recovery: each planned move is at its finalized path with
        the expected hash, or still in staging with the expected hash; anything
        else abandons (plan 5.1)."""
        now = self._clock.now_utc()
        for planned in work.entry.planned_paths:
            candidate_id = planned.candidate_artifact_id
            staged = confine_candidate_path(
                work.root, planned.staging_relative_path, now_utc=now
            )
            if isinstance(staged, Success):
                digest = self._store.hash_confined(staged.value, now_utc=now)
                if isinstance(digest, Failure):
                    return self._abandon(work, digest)
                if (
                    digest.value != planned.expected_sha256
                    or staged.value.identity.st_size != planned.expected_size_bytes
                ):
                    return self._abandon(
                        work,
                        self._validation_refusal(
                            work.scope,
                            ARTIFACT_VALIDATION_FAILED,
                            "a staged candidate differs from its planned facts",
                        ),
                    )
                work.confined[candidate_id] = staged.value
                continue
            target = confine_candidate_path(
                self._store.artifacts_root, planned.finalized_relative_path, now_utc=now
            )
            if isinstance(target, Failure):
                return self._abandon(
                    work,
                    self._validation_refusal(
                        work.scope,
                        ARTIFACT_VALIDATION_FAILED,
                        "a planned move is neither in staging nor at its finalized "
                        "path",
                    ),
                )
            digest = self._store.hash_confined(target.value, now_utc=now)
            if isinstance(digest, Failure):
                return self._abandon(work, digest)
            if digest.value != planned.expected_sha256:
                return self._abandon(
                    work,
                    self._validation_refusal(
                        work.scope,
                        ARTIFACT_VALIDATION_FAILED,
                        "a moved blob differs from its planned hash",
                    ),
                )
            work.moved.setdefault(candidate_id, False)
        return None

    # -- phase 3 -----------------------------------------------------------------

    def _deadline_passed(self, work: _Work) -> bool:
        if not isinstance(work.deadline_utc, datetime):
            return False
        if self._clock.now_utc() > work.deadline_utc:
            return True
        monotonic = work.deadline_monotonic
        return monotonic is not None and self._clock.monotonic().seconds > monotonic

    def _move_one(self, work: _Work, index: int) -> Failure | None:
        planned = work.entry.planned_paths[index]
        candidate_id = planned.candidate_artifact_id
        if self._deadline_passed(work):
            return self._time_out(work)
        self._probe.before_move(index)
        if candidate_id in work.moved:
            self._probe.after_move(index)
            return None
        now = self._clock.now_utc()
        rechecked = recheck_confined_path(work.confined[candidate_id], now_utc=now)
        if isinstance(rechecked, Failure):
            return self._abandon(work, rechecked)
        moved = self._store.atomic_move(
            rechecked.value,
            self._store.finalized_path_for(planned.expected_sha256),
            now_utc=now,
        )
        if isinstance(moved, Failure):
            return self._abandon(work, moved)
        work.moved[candidate_id] = moved.value.deduplicated
        self._probe.after_move(index)
        return None

    # -- T2 ---------------------------------------------------------------------

    def _moved_phase(self, work: _Work) -> Failure | None:
        scope = work.scope
        self._probe.before_moved()
        now = self._clock.now_utc()
        observed: list[ObservedMove] = []
        for planned in work.entry.planned_paths:
            confined = confine_candidate_path(
                self._store.artifacts_root, planned.finalized_relative_path, now_utc=now
            )
            if isinstance(confined, Failure):
                work.observed = observed
                return self._abandon(
                    work,
                    self._validation_refusal(
                        scope,
                        ARTIFACT_VALIDATION_FAILED,
                        "a moved blob could not be re-read in place",
                    ),
                )
            digest = self._store.hash_confined(confined.value, now_utc=now)
            if isinstance(digest, Failure):
                work.observed = observed
                return self._abandon(work, digest)
            move = ObservedMove(
                candidate_artifact_id=planned.candidate_artifact_id,
                staging_relative_path=planned.staging_relative_path,
                finalized_relative_path=planned.finalized_relative_path,
                expected_sha256=planned.expected_sha256,
                expected_size_bytes=planned.expected_size_bytes,
                observed_sha256=digest.value,
                observed_size_bytes=confined.value.identity.st_size,
                deduplicated=work.moved.get(planned.candidate_artifact_id, False),
            )
            observed.append(move)
            if not move.matches_plan:
                work.observed = observed
                return self._abandon(
                    work,
                    self._validation_refusal(
                        scope,
                        ARTIFACT_VALIDATION_FAILED,
                        "a moved blob differs from the planned facts (reading 18)",
                    ),
                )
        work.observed = observed
        if self._deadline_passed(work):
            return self._time_out(work)
        entry = work.entry
        replacement = _journal_replacement(
            entry,
            state=_J.MOVED,
            now=now,
            observed=tuple(observed),
            lease=self._renewed_lease(work, now),
        )
        with self._transaction() as transaction:
            swapped = transaction.finalization_journal.compare_and_swap(
                entry.revision, replacement
            )
            if isinstance(swapped, Failure):
                return swapped
            audited = self._audit(
                transaction,
                scope,
                "FINALIZATION_MOVED",
                "SUCCEEDED",
                {"moves": len(observed)},
            )
            if isinstance(audited, Failure):
                return audited
            committed = transaction.commit()
            if isinstance(committed, Failure):
                return committed
        work.journal = swapped.value
        self._probe.after_moved()
        self._write_log("INFO", "ARTIFACT.FINALIZATION_MOVED", scope, "moved")
        return None

    def _renewed_lease(self, work: _Work, now: datetime) -> datetime:
        """Renew the lease by the purpose's compiled interval, never past the
        deadline, which the renewal leaves unchanged."""
        renewed = now + timedelta(seconds=_lease_interval_seconds(work.scope))
        deadline = work.deadline_utc
        if isinstance(deadline, datetime):
            return min(renewed, deadline)
        return renewed

    # -- T3 ---------------------------------------------------------------------

    def _register_phase(self, work: _Work) -> Result[FinalizationResult]:
        scope = work.scope
        self._probe.before_registered()
        now = self._clock.now_utc()
        if self._deadline_passed(work):
            return self._time_out(work)
        refs = self._build_refs(work, now)
        if isinstance(refs, Failure):
            return self._abandon(work, refs)
        entry = work.entry
        with self._transaction() as transaction:
            manifests: tuple[ArtifactManifest, ...]
            if scope.is_result:
                facts = transaction.result_leases.active_attempt_facts(
                    str(scope.run_id), str(scope.invocation_id)
                )
                if isinstance(facts, Failure):
                    return self._after_registration_failure(work, facts)
                if (
                    facts.value.run_state is not EngineRunState.RUNNING
                    or facts.value.run_revision != entry.expected_run_revision
                ):
                    transaction.rollback()
                    return self._abandon(
                        work,
                        self._conflict(
                            scope,
                            f"run {scope.run_id} moved to revision "
                            f"{facts.value.run_revision} "
                            f"({facts.value.run_state.value}) before registration",
                        ),
                    )
                registration = self._registrar.register_result(
                    transaction, entry, refs, facts.value
                )
                if isinstance(registration, Failure):
                    transaction.rollback()
                    return self._after_registration_failure(work, registration)
                recorded_refs = registration.value.refs
                manifests = registration.value.manifests
                result = _finalization_result(
                    entry,
                    recorded_refs,
                    now,
                    run_manifest_id=registration.value.run_manifest_id,
                    run_manifest_hash=registration.value.run_manifest_hash,
                )
            else:
                manifests = tuple(
                    self._manifest_for(
                        ref, work.candidates[ref.source_candidate_artifact_id]
                    )
                    for ref in refs
                )
                for ref, manifest in zip(refs, manifests, strict=True):
                    staged = transaction.artifact_refs.stage_reference(ref, manifest)
                    if isinstance(staged, Failure):
                        transaction.rollback()
                        return self._after_registration_failure(work, staged)
                result = _finalization_result(entry, refs, now)
                recorded = transaction.artifact_refs.record_finalization(result)
                if isinstance(recorded, Failure):
                    transaction.rollback()
                    return self._after_registration_failure(work, recorded)
                linked = self._registrar.register_evidence(
                    transaction, entry, recorded.value
                )
                if isinstance(linked, Failure):
                    transaction.rollback()
                    return self._after_registration_failure(work, linked)
            self._probe.inside_registered()
            replacement = _journal_replacement(
                entry, state=_J.REGISTERED, now=now, observed=entry.observed, lease=None
            )
            swapped = transaction.finalization_journal.compare_and_swap(
                entry.revision, replacement
            )
            if isinstance(swapped, Failure):
                transaction.rollback()
                return self._after_registration_failure(work, swapped)
            audited = self._audit(
                transaction,
                scope,
                "FINALIZATION_REGISTERED",
                "SUCCEEDED",
                {"purpose": scope.purpose.value, "references": len(refs)},
            )
            if isinstance(audited, Failure):
                transaction.rollback()
                return self._after_registration_failure(work, audited)
            committed = transaction.commit()
            if isinstance(committed, Failure):
                return self._after_registration_failure(work, committed)
        work.journal = swapped.value
        # Plan 6.2: the projections follow the committed registration; the rows
        # are authoritative and a projection that could not be written is
        # tolerated (logged), never a failure of the registration that committed.
        self._write_projections(manifests, scope)
        self._probe.after_registered()
        self._write_log("INFO", "ARTIFACT.FINALIZATION_REGISTERED", scope, "registered")
        return Success[FinalizationResult](outcome="SUCCESS", value=result)

    def _after_registration_failure(self, work: _Work, failure: Failure) -> Failure:
        """T3 was rolled back: a storage-class failure leaves the journal ``MOVED``
        for recovery; a conflict is ``ABANDONED(SUPERSEDED)``; any other refusal
        abandons under its own code."""
        if _code_of(failure) in STORAGE_FAILURE_CODES:
            self._write_log(
                "ERROR", _code_of(failure), work.scope, "registration failed"
            )
            return failure
        return self._abandon(work, failure)

    def _build_refs(
        self, work: _Work, now: datetime
    ) -> tuple[ArtifactRef, ...] | Failure:
        refs: list[ArtifactRef] = []
        for move in work.entry.observed:
            candidate = work.candidates[move.candidate_artifact_id]
            media = (
                candidate.adapter_declared_media_type
                if candidate.producer_kind is _P.ADAPTER
                else CORE_EVIDENCE_MEDIA_TYPES.get(candidate.artifact_kind, MISSING)
            )
            if not isinstance(media, str):
                return self._invariant(
                    work.scope,
                    f"candidate {candidate.candidate_artifact_id} has no media type",
                )
            refs.append(
                ArtifactRef.model_validate(
                    {
                        "schema_version": "1.0.0",
                        "artifact_id": artifact_id_for(
                            move.candidate_artifact_id, move.observed_sha256
                        ),
                        "owner": candidate.owner,
                        "finalization_purpose": candidate.finalization_purpose,
                        "artifact_kind": candidate.artifact_kind,
                        "finalized_relative_path": move.finalized_relative_path,
                        "content_hash": move.observed_sha256,
                        "size_bytes": move.observed_size_bytes,
                        "media_type": media,
                        "source_role": candidate.source_role,
                        "source_candidate_artifact_id": candidate.candidate_artifact_id,
                        "producer_kind": candidate.producer_kind,
                        "validation_profile": ARTIFACT_VALIDATION_PROFILE,
                        "created_at_utc": candidate.created_at_utc,
                        "finalized_at_utc": max(now, candidate.created_at_utc),
                        "state": "FINALIZED",
                    }
                )
            )
        return tuple(refs)

    def _manifest_for(
        self, ref: ArtifactRef, candidate: CandidateArtifact
    ) -> ArtifactManifest:
        """The ``EVIDENCE`` manifest beside ``ref`` (plan 3.1): a ``RUN`` lineage
        restates the owner, a snapshot owner's ``source_hash`` is the content hash
        the producer proved equal to the registry fact (plan 4.6)."""
        lineage: dict[str, Any] = {}
        owner = ref.owner
        if isinstance(owner, RunArtifactOwner):
            lineage["experiment_id"] = owner.experiment_id
            lineage["run_id"] = owner.run_id
            if isinstance(owner.invocation_id, str):
                lineage["invocation_id"] = owner.invocation_id
        if owner_kind_of(owner) in _SNAPSHOT_OWNERS:
            lineage["source_hash"] = ref.content_hash
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

    def _write_projections(
        self, manifests: tuple[ArtifactManifest, ...], scope: _Scope
    ) -> None:
        """The ``manifests/<artifact_id>.json`` projections (plan 6.2), written
        exclusive-create after T3 committed. An ``artifact_id`` is registered at
        most once (insert-only references), so an existing file is this very
        registration's and is kept; a file that cannot be written is logged and
        tolerated -- the ``artifact_refs.manifest_json`` column is the record."""
        for manifest in manifests:
            path = self._store.manifest_path_for(manifest.artifact_id)
            try:
                with path.open("xb") as handle:
                    handle.write(canonical_json_bytes(manifest))
            except FileExistsError:
                continue
            except OSError:
                self._write_log(
                    "WARNING",
                    ARTIFACT_MOVE_FAILED,
                    scope,
                    f"projection of {manifest.artifact_id} not written",
                )

    # -- abandonment, timeout and close ------------------------------------------

    def _abandon(self, work: _Work, failure: Failure) -> Failure:
        """Plan 4.3's failure column from phase 3 on: the journal ``ABANDONED``
        under the failure's code, the candidates ``QUARANTINED``, the diagnostic
        recorded and the audit facts in one short transaction; then the moved
        blobs no other reference shares and the unmoved staging bytes to one
        quarantine entry keyed by the ``finalization_id``. The reconciler's
        finalizer also applies the 17.3 rule (``RUNNING -> FAILED`` at the
        journal's expected revision); the in-process caller owns that write."""
        scope = work.scope
        entry = work.journal
        diagnostic = failure.diagnostics[0]
        reason = diagnostic.error_code
        if entry is None or entry.state not in _OPEN_JOURNAL_STATES:
            return failure
        fail_run = self._fail_run_on_abandon
        now = self._clock.now_utc()
        replacement = _journal_replacement(
            entry,
            state=_J.ABANDONED,
            now=now,
            observed=tuple(work.observed) if work.observed else entry.observed,
            lease=None,
            abandon_reason=reason,
        )
        with self._transaction() as transaction:
            swapped = transaction.finalization_journal.compare_and_swap(
                entry.revision, replacement
            )
            if isinstance(swapped, Failure):
                return failure
            recorded = transaction.diagnostics_writer.record(diagnostic)
            if isinstance(recorded, Failure):
                return recorded
            quarantined = self._quarantine_candidates(
                transaction, work, reason, diagnostic.diagnostic_id, now
            )
            if isinstance(quarantined, Failure):
                return quarantined
            if fail_run and scope.is_result:
                failed_run = self._fail_run(transaction, work, diagnostic, now)
                if isinstance(failed_run, Failure):
                    return failed_run
            audited = self._audit(
                transaction,
                scope,
                "FINALIZATION_ABANDONED",
                "FAILED",
                {"reason": reason, "from_state": entry.state.value},
            )
            if isinstance(audited, Failure):
                return audited
            for _candidate_id in scope.candidate_ids:
                audited = self._audit(
                    transaction,
                    scope,
                    "ARTIFACT_QUARANTINED",
                    "FAILED",
                    {"reason": reason},
                )
                if isinstance(audited, Failure):
                    return audited
            committed = transaction.commit()
            if isinstance(committed, Failure):
                return committed
        work.journal = swapped.value
        work.candidates.update(quarantined)
        self._quarantine_bytes(work, reason, now)
        self._write_log("ERROR", reason, scope, "abandoned")
        return failure

    def _quarantine_candidates(
        self,
        transaction: RegistrationUnitOfWork,
        work: _Work,
        reason: str,
        diagnostic_id: str,
        now: datetime,
    ) -> dict[str, CandidateArtifact] | Failure:
        observation = ValidationObservation(
            observed_at_utc=now,
            stage="MOVE",
            outcome="FAILED",
            error_code=reason,
            diagnostic_id=diagnostic_id,
        )
        updated: dict[str, CandidateArtifact] = {}
        for candidate_id in work.scope.candidate_ids:
            candidate = work.candidates[candidate_id]
            if candidate.state is not _S.FINALIZING:
                continue
            swapped = transaction.candidate_artifacts.compare_and_swap(
                candidate.revision,
                _candidate_replacement(candidate, _S.QUARANTINED, (observation,), now),
            )
            if isinstance(swapped, Failure):
                return swapped
            updated[candidate_id] = swapped.value
        return updated

    def _fail_run(
        self,
        transaction: RegistrationUnitOfWork,
        work: _Work,
        diagnostic: Diagnostic,
        now: datetime,
    ) -> Failure | None:
        """17.3: a failed recovery check moves the original attempt ``RUNNING ->
        FAILED`` with the check's diagnostic as primary, at the journal's expected
        revision; a run that moved meanwhile is left to its winner."""
        scope = work.scope
        loaded = transaction.engine_runs.get(str(scope.run_id))
        if isinstance(loaded, Failure):
            return loaded
        run = loaded.value
        if (
            run.state is not EngineRunState.RUNNING
            or run.revision != work.entry.expected_run_revision
        ):
            return None
        payload = run.model_dump(mode="python")
        payload["state"] = EngineRunState.FAILED
        payload["primary_terminal_diagnostic_id"] = diagnostic.diagnostic_id
        payload["revision"] = run.revision + 1
        payload["updated_at_utc"] = max(run.updated_at_utc, now)
        try:
            replacement = EngineRunRecord.model_validate(payload)
            assert_run_transition(run, replacement)
        except (ValueError, EngineRunRuleViolation) as violation:
            return self._invariant(
                scope, f"run {scope.run_id} admits no FAILED write: {violation}"
            )
        swapped = transaction.engine_runs.compare_and_swap(run.revision, replacement)
        if isinstance(swapped, Failure):
            return swapped
        audited = self._audit(
            transaction,
            scope,
            "RUN_FAILED",
            "FAILED",
            {"reason": diagnostic.error_code},
        )
        return audited if isinstance(audited, Failure) else None

    def _time_out(self, work: _Work) -> Failure:
        """Plan 4.5: ``RUNNING -> TIMED_OUT`` with the finalization-timeout
        diagnostic as primary, ``ABANDONED(ARTIFACT.FINALIZATION_TIMED_OUT)``, the
        audit facts, then the quarantine; a run another winner moved first is the
        ``SUPERSEDED`` abandonment instead."""
        scope = work.scope
        entry = work.entry
        now = self._clock.now_utc()
        diagnostic = artifact_diagnostic(
            ARTIFACT_FINALIZATION_TIMED_OUT,
            message="the result finalization deadline passed",
            invocation_id=scope.invocation_id,
            run_id=scope.run_id,
            experiment_id=scope.experiment_id,
            now_utc=now,
        )
        replacement = _journal_replacement(
            entry,
            state=_J.ABANDONED,
            now=now,
            observed=tuple(work.observed) if work.observed else entry.observed,
            lease=None,
            abandon_reason=ARTIFACT_FINALIZATION_TIMED_OUT,
        )
        with self._transaction() as transaction:
            timed = transaction.result_leases.record_timeout(
                _as_int(entry.expected_run_revision), str(scope.run_id), diagnostic
            )
            if isinstance(timed, Failure):
                transaction.rollback()
                if _code_of(timed) == PERSISTENCE_CONCURRENCY_CONFLICT:
                    return self._abandon(work, timed)
                return timed
            swapped = transaction.finalization_journal.compare_and_swap(
                entry.revision, replacement
            )
            if isinstance(swapped, Failure):
                return swapped
            recorded = transaction.diagnostics_writer.record(diagnostic)
            if isinstance(recorded, Failure):
                return recorded
            quarantined = self._quarantine_candidates(
                transaction,
                work,
                ARTIFACT_FINALIZATION_TIMED_OUT,
                diagnostic.diagnostic_id,
                now,
            )
            if isinstance(quarantined, Failure):
                return quarantined
            audited = self._audit(
                transaction,
                scope,
                "FINALIZATION_TIMED_OUT",
                "FAILED",
                {
                    "reason": ARTIFACT_FINALIZATION_TIMED_OUT,
                    "from_state": entry.state.value,
                },
            )
            if isinstance(audited, Failure):
                return audited
            for _candidate_id in scope.candidate_ids:
                audited = self._audit(
                    transaction,
                    scope,
                    "ARTIFACT_QUARANTINED",
                    "FAILED",
                    {"reason": ARTIFACT_FINALIZATION_TIMED_OUT},
                )
                if isinstance(audited, Failure):
                    return audited
            committed = transaction.commit()
            if isinstance(committed, Failure):
                return committed
        work.journal = swapped.value
        work.candidates.update(quarantined)
        self._quarantine_bytes(work, ARTIFACT_FINALIZATION_TIMED_OUT, now)
        self._write_log("ERROR", ARTIFACT_FINALIZATION_TIMED_OUT, scope, "timed out")
        return _failure_of(diagnostic)

    def _quarantine_bytes(self, work: _Work, reason: str, now: datetime) -> None:
        """Every moved blob no other reference shares (a deduplicated move left the
        pre-existing blob alone) and every unmoved staging file, into the one
        entry keyed by the ``finalization_id``."""
        entry_id = work.scope.finalization_id
        for planned in work.entry.planned_paths:
            candidate_id = planned.candidate_artifact_id
            if candidate_id in work.moved:
                if work.moved[candidate_id]:
                    continue
                target = confine_candidate_path(
                    self._store.artifacts_root,
                    planned.finalized_relative_path,
                    now_utc=now,
                )
                if isinstance(target, Success):
                    self._store.quarantine_move(
                        target.value,
                        entry_id,
                        reason,
                        now_utc=now,
                        sha256=planned.expected_sha256,
                    )
                continue
            staged = work.confined.get(candidate_id)
            if staged is None:
                located = confine_candidate_path(
                    work.root, planned.staging_relative_path, now_utc=now
                )
                if isinstance(located, Failure):
                    continue
                staged = located.value
            self._store.quarantine_move(staged, entry_id, reason, now_utc=now)

    def _close_phase(self, work: _Work) -> None:
        """T4: the lease close never changes the finalization's outcome. A close
        whose audit or commit fails is logged -- the removal itself is a
        filesystem fact the transaction cannot undo -- and the next
        reconciliation pass sees whatever bytes remain under the root."""
        roots = work.roots
        if not isinstance(roots, CommandRootPaths):
            return
        closed = close_result_lease(
            work.entry,
            roots,
            store=self._store,
            unit_of_work_factory=self._factory,
            auditor=self._auditor,
            clock=self._clock,
        )
        if isinstance(closed, Failure):
            self._write_log(
                "WARNING", _code_of(closed), work.scope, "close not audited"
            )

    # -- audit and log -------------------------------------------------------------

    def _audit(
        self,
        transaction: FinalizationUnitOfWork,
        scope: _Scope,
        action: str,
        outcome: str,
        details: Mapping[str, DiagnosticDetailValue],
    ) -> Result[None]:
        fact = AuditFact(
            action=action,
            outcome=cast("Any", outcome),
            correlation_id=scope.finalization_id,
            details=details,
            **scope.audit_ids(),
        )
        return self._auditor.append(transaction, fact)

    def _audit_alone(
        self,
        scope: _Scope,
        action: str,
        outcome: str,
        details: Mapping[str, DiagnosticDetailValue],
    ) -> Result[None]:
        with self._transaction() as transaction:
            audited = self._audit(transaction, scope, action, outcome, details)
            if isinstance(audited, Failure):
                return audited
            return transaction.commit()

    def _write_log(self, severity: str, code: str, scope: _Scope, message: str) -> None:
        log = self._log
        if log is None:
            return
        log.write(
            LogFact(
                severity=cast("Any", severity),
                event_code=code,
                message=f"finalization {message}",
                correlation_id=scope.finalization_id,
                details={"purpose": scope.purpose.value},
                **scope.audit_ids(),
            )
        )


# --------------------------------------------------------------------------
# Record replacements
# --------------------------------------------------------------------------


def _lease_interval_seconds(scope: _Scope) -> int:
    """The purpose's compiled lease interval (plan 4.3 phase 2; the ruling)."""
    return RESULT_LEASE_SECONDS if scope.is_result else EVIDENCE_LEASE_SECONDS


def _candidate_replacement(
    candidate: CandidateArtifact,
    state: CandidateArtifactState,
    observations: tuple[ValidationObservation, ...],
    now: datetime,
) -> CandidateArtifact:
    payload = candidate.model_dump(mode="python")
    payload["state"] = state
    payload["validation_observations"] = (
        *candidate.validation_observations,
        *observations,
    )
    payload["revision"] = candidate.revision + 1
    payload["updated_at_utc"] = max(candidate.updated_at_utc, now)
    return CandidateArtifact.model_validate(_without_missing(payload))


def _journal_replacement(
    entry: FinalizationJournalEntry,
    *,
    state: FinalizationJournalState,
    now: datetime,
    observed: tuple[ObservedMove, ...],
    lease: datetime | None,
    abandon_reason: str | MISSING = MISSING,  # type: ignore[valid-type]
) -> FinalizationJournalEntry:
    payload = entry.model_dump(mode="python")
    payload["state"] = state
    payload["observed"] = observed
    payload["abandon_reason"] = abandon_reason
    if lease is not None:
        payload["lease_expires_at_utc"] = lease
    payload["revision"] = entry.revision + 1
    payload["updated_at_utc"] = max(entry.updated_at_utc, now)
    return FinalizationJournalEntry.model_validate(_without_missing(payload))


def _finalization_result(
    entry: FinalizationJournalEntry,
    refs: tuple[ArtifactRef, ...],
    now: datetime,
    *,
    run_manifest_id: str | MISSING = MISSING,  # type: ignore[valid-type]
    run_manifest_hash: str | MISSING = MISSING,  # type: ignore[valid-type]
) -> FinalizationResult:
    deduplicated = {
        move.candidate_artifact_id: move.deduplicated for move in entry.observed
    }
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "finalization_id": entry.finalization_id,
        "finalization_purpose": entry.finalization_purpose,
        "owner": entry.owner,
        "journal_state": "REGISTERED",
        "candidate_to_artifact_refs": tuple(
            CandidateFinalization(
                candidate_artifact_id=ref.source_candidate_artifact_id,
                artifact_id=ref.artifact_id,
                content_hash=ref.content_hash,
                size_bytes=ref.size_bytes,
                deduplicated=deduplicated.get(ref.source_candidate_artifact_id, False),
            )
            for ref in refs
        ),
        "run_manifest_id": run_manifest_id,
        "run_manifest_hash": run_manifest_hash,
        "registered_at_utc": max(entry.updated_at_utc, now),
        "replayed": False,
    }
    return FinalizationResult.model_validate(_without_missing(payload))


__all__ = (
    "CORE_EVIDENCE_MEDIA_TYPES",
    "EVIDENCE_LEASE_SECONDS",
    "FINALIZER_DIAGNOSTIC_POSTURES",
    "PERSISTENCE_CONCURRENCY_CONFLICT",
    "PERSISTENCE_STORAGE_UNAVAILABLE",
    "PERSISTENCE_WRITE_FAILED",
    "PROCESS_CANCELLED",
    "RESULT_LEASE_SECONDS",
    "STORAGE_FAILURE_CODES",
    "CoreArtifactFinalizer",
    "RawByteClose",
    "close_raw_bytes",
    "close_result_lease",
    "cooperative_checkpoint",
)
