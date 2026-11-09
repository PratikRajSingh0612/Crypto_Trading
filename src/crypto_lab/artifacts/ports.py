"""The structural ports of the artifact finalizer, the journal protocol and the
reconciler (Stage 9 plan 4.1, Task 6; specification 8.2:320-354).

Every member answers a ``Result`` in the Stage 8 failure vocabulary
(``CORE.INVARIANT_VIOLATION`` containing ``does not exist`` for a missing
identity, ``PERSISTENCE.CONCURRENCY_CONFLICT`` for a lost swap, a duplicate
identity or a busy timeout; never an exception) and every protocol here is
satisfied structurally: the Stage 8 ``SqliteTransaction`` after Task 5 and the
in-memory ``MemoryFinalizationUnitOfWork`` of ``tests/doubles/artifacts.py``
alike, without either importing this module (plan "Dependency direction").

``artifacts`` imports ``domain`` and itself only (plan 2.6; the architecture
closure ``_ALLOWED_FOR_ARTIFACTS``), so three plan 4.1 shapes are restated here
as domain-typed structural twins rather than imported:

- the facts of the four registration tables (``RunManifestFacts``,
  ``SanitizedManifestFacts``, ``ValidationResultFacts``, ``RunArtifactLink``)
  and ``ResultLeaseFacts`` are read-only ``Protocol`` views over identifiers,
  hashes, canonical text, enums and instants, which the persistence dataclasses
  of the same names satisfy by shape;
- the audit sink member ``audit`` is an ``AuditAppender`` and the finalizer never
  builds an audit event itself: it describes each meaningful action as an
  ``AuditFact`` and hands it to the injected ``FinalizationAuditor``, whose
  production implementation lives beside the ``experiments`` composition (the
  layer that may import both ``artifacts`` and ``audit``) and turns the fact
  into the sink's event on the open transaction; the test-resident auditor of
  Task 6 does the same over ``SqliteAuditSink`` and the memory sink. Declared
  reading, recorded for review: plan 4.1 names ``audit (AuditSink)`` and plan
  4.2 an ``audit_ids`` constructor argument, both ``crypto_lab.audit`` types the
  accepted architecture closure keeps out of ``artifacts``; the fact port keeps
  every phase audited in its own transaction without widening that boundary;
- ``CommandRootPaths`` is the domain-typed projection of the Stage 7
  ``CommandPaths`` the caller builds; it is kind-governed exactly as that record
  (``roots.py``): a ``DESCRIBE`` or ``VALIDATE`` root carries ``output_path`` with
  ``work_dir`` and ``result_path`` absent, a ``RUN`` root carries ``work_dir`` and
  ``result_path`` with ``output_path`` absent. Consumers narrow by ``isinstance``.

The ten probe points of ``FinalizationProbe`` are plan 4.3's; ``NoProbe`` is the
production instance. ``ArtifactFinalizer.finalize`` is a coroutine whose only
suspension points are the ``cooperative_checkpoint`` awaits of
``artifacts/finalizer.py`` (no ``asyncio`` import anywhere in the package). Its
keyword ``token_material`` is the transient attempt token material a caller
already holds in its frame (the conclusion of plan 4.4, before the raw bytes of
the root are closed); it is consumed by the phase-1 scan of one call and never
retained -- the canonical request shapes carry no token.

The canonical evidence ruling of 2026-11-09 (``docs/decisions/2026-11-09-stage9-
canonical-evidence-validation-clarification.md``) adds one more structural twin:
``CanonicalEvidenceQualifier`` is the producer side of the plan 4.6 contract --
whether the bytes of a ``CORE`` ``EVIDENCE`` candidate are exactly the approved
producer's canonical output agreeing with the authoritative facts, and which of
its strings remain uncontrolled. The production ``PurposeRegistrar`` of the
``experiments`` composition satisfies it beside the registrar protocol, so the
finalizer -- and the reconciler, which builds its finalizer from the registrar it
is handed -- consults it through the registrar boundary; a registrar without it
leaves every text evidence under the whole-content token-shape scan.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PureWindowsPath
from typing import Any, Final, Literal, Protocol, runtime_checkable

from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.artifacts.journal import FinalizationJournalEntry
from crypto_lab.artifacts.manifest import ArtifactManifest
from crypto_lab.artifacts.models import (
    ArtifactFinalizationPurpose,
    ArtifactRef,
    CandidateArtifact,
    CandidateArtifactState,
    CandidateFinalization,
    FinalizationResult,
)
from crypto_lab.artifacts.ownership import ArtifactOwnerRef
from crypto_lab.artifacts.requests import (
    EvidenceFinalizationRequest,
    ResultFinalizationRequest,
)
from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.diagnostics import Diagnostic, DiagnosticDetailValue
from crypto_lab.domain.engine_run import AttemptTokenMaterial, EngineRunRecord
from crypto_lab.domain.identifiers import (
    ArtifactId,
    CandidateArtifactId,
    ExperimentId,
    FinalizationId,
    InvocationId,
    RunId,
    RunManifestId,
    Sha256,
)
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
    ProcessExitCategory,
)
from crypto_lab.domain.ports import CancellationToken
from crypto_lab.domain.results import Failure, Result

#: ``adapters.limits.RESULT_MANIFEST_RELATIVE_PATH`` restated (plan 2.6: no
#: ``adapters`` import); the leaf a ``RUN`` root's ``result_path`` must name.
RESULT_MANIFEST_FILE_NAME: Final = "adapter-result-manifest.json"
#: The repositories' listing bound, restated for the port defaults.
MAX_LISTING: Final = 1024

type FinalizationRequest = ResultFinalizationRequest | EvidenceFinalizationRequest
type SemanticSuccessStatus = Literal["SUCCEEDED", "SUCCEEDED_WITH_WARNINGS"]
type AuditOutcomeName = Literal["SUCCEEDED", "REFUSED", "FAILED"]


class Answer[T](Protocol):
    """The read-only shape of a ``Success`` whose value is typed structurally.

    ``Success[T]`` is invariant under strict mypy (its ``value`` is a model field),
    so a repository that answers ``Success[<its own facts dataclass>]`` could never
    satisfy a port member typed ``Result[<facts protocol>]`` nominally. The members
    below that answer facts views are typed ``Answer[...] | Failure`` instead: the
    two read-only properties make ``T`` covariant, every ``Success`` satisfies the
    shape, and the consumer narrows with ``isinstance(answer, Failure)`` exactly as
    it narrows a ``Result``.
    """

    @property
    def outcome(self) -> Literal["SUCCESS"]: ...

    @property
    def value(self) -> T: ...


# --------------------------------------------------------------------------
# The repositories (plan 4.1; the Stage 8 section 4.3.1 answer order)
# --------------------------------------------------------------------------


@runtime_checkable
class CandidateArtifactRepository(Protocol):
    """The candidate lifecycle repository."""

    def get(
        self, candidate_artifact_id: CandidateArtifactId
    ) -> Result[CandidateArtifact]: ...

    def add(self, record: CandidateArtifact) -> Result[None]: ...

    def compare_and_swap(
        self,
        expected_revision: int,
        replacement: CandidateArtifact,
        *,
        registered_mapping: CandidateFinalization | MISSING = MISSING,  # type: ignore[valid-type]
    ) -> Result[CandidateArtifact]: ...

    def list_recoverable(
        self,
        states: Sequence[CandidateArtifactState],
        owner: ArtifactOwnerRef | MISSING = MISSING,  # type: ignore[valid-type]
        purpose: ArtifactFinalizationPurpose | MISSING = MISSING,  # type: ignore[valid-type]
        limit: int = MAX_LISTING,
    ) -> Result[tuple[CandidateArtifact, ...]]:
        """Candidates in ``states``, excluding a ``FINALIZING`` candidate that
        already has a reference (19.1:1358)."""
        ...


@runtime_checkable
class ArtifactRepository(Protocol):
    """The finalized-reference repository: the only writer of ``artifact_refs``.

    A reference and its manifest are staged on the open transaction with
    ``stage_reference`` and inserted by ``record_finalization(result)``, which
    inserts exactly the staged pairs the result's mappings name and refuses when
    any source candidate is not ``FINALIZING`` (the Task 5 staging shape, adopted
    as the port). ``list_by_content_hash`` is the one read added over the
    committed plan 4.1 member list, recorded as a Task 6 file-map correction: RV-9
    decides a blob's registration by the ``artifact_refs`` row alone and plan 6.2
    tolerates a missing ``manifests/<artifact_id>.json`` projection, so recovery
    must reach the rows a content hash registers (a deduplicated blob is
    registered by several) through the existing ``ix_artifact_refs_content_hash``
    index rather than through the projection.
    """

    def get(self, artifact_id: ArtifactId) -> Result[ArtifactRef]: ...

    def get_manifest(self, artifact_id: ArtifactId) -> Result[ArtifactManifest]: ...

    def list_by_owner(
        self,
        owner: ArtifactOwnerRef,
        purpose: ArtifactFinalizationPurpose | MISSING = MISSING,  # type: ignore[valid-type]
    ) -> Result[tuple[ArtifactRef, ...]]: ...

    def list_by_content_hash(
        self, content_hash: Sha256
    ) -> Result[tuple[ArtifactRef, ...]]:
        """Every reference registering ``content_hash``, in ``artifact_id`` order;
        ``()`` when no row registers it. Read-only: the RV-9 registration read."""
        ...

    def stage_reference(
        self, ref: ArtifactRef, manifest: ArtifactManifest
    ) -> Result[None]: ...

    def record_finalization(
        self, result: FinalizationResult
    ) -> Result[tuple[ArtifactRef, ...]]: ...


@runtime_checkable
class FinalizationJournalRepository(Protocol):
    """The purpose-discriminated journal repository (plan 4.3)."""

    def get(
        self, finalization_id: FinalizationId
    ) -> Result[FinalizationJournalEntry]: ...

    def prepare(self, entry: FinalizationJournalEntry) -> Result[None]:
        """The ``PREPARED`` insert."""
        ...

    def compare_and_swap(
        self, expected_revision: int, replacement: FinalizationJournalEntry
    ) -> Result[FinalizationJournalEntry]: ...

    def list_open(
        self,
        purpose: ArtifactFinalizationPurpose | MISSING = MISSING,  # type: ignore[valid-type]
        limit: int = MAX_LISTING,
    ) -> Result[tuple[FinalizationJournalEntry, ...]]:
        """Every ``PREPARED`` or ``MOVED`` entry, oldest first."""
        ...

    def find_result_identity(
        self, run_invocation_id: InvocationId, source_hash: Sha256
    ) -> Result[FinalizationJournalEntry | MISSING]: ...  # type: ignore[valid-type]

    def find_evidence_identity(
        self,
        owner_hash: Sha256,
        kind: str,
        correlation_id: str,
        set_hash: Sha256,
    ) -> Result[FinalizationJournalEntry | MISSING]: ...  # type: ignore[valid-type]


class ResultLeaseFacts(Protocol):
    """The value object ``active_attempt_facts`` answers (plan 4.1): a ``RUNNING``
    run, its ``EXITED`` run-command invocation, the experiment state and the
    latest-attempt predicate of reading 4 -- revisions and categories, never a
    verdict. The persistence dataclass of the same name satisfies it by shape."""

    @property
    def run_id(self) -> RunId: ...

    @property
    def run_invocation_id(self) -> InvocationId: ...

    @property
    def experiment_id(self) -> ExperimentId: ...

    @property
    def run_state(self) -> EngineRunState: ...

    @property
    def run_revision(self) -> int: ...

    @property
    def attempt_token_hash(self) -> Sha256: ...

    @property
    def deadline_snapshotted(self) -> bool: ...

    @property
    def invocation_state(self) -> CommandInvocationState: ...

    @property
    def invocation_revision(self) -> int: ...

    @property
    def command_kind(self) -> CommandKind: ...

    @property
    def process_exit_category(self) -> ProcessExitCategory | MISSING: ...  # type: ignore[valid-type]

    @property
    def experiment_state(self) -> ExperimentState | MISSING: ...  # type: ignore[valid-type]

    @property
    def is_latest_attempt(self) -> bool: ...


@runtime_checkable
class ResultLeaseRepository(Protocol):
    """The RESULT lease's run-side writes (plan 4.1, 4.3 phase 2, 4.5)."""

    def active_attempt_facts(
        self, run_id: RunId, run_invocation_id: InvocationId
    ) -> Answer[ResultLeaseFacts] | Failure: ...

    def snapshot_deadline(
        self, expected_run_revision: int, run_id: RunId, deadline_utc: datetime
    ) -> Result[EngineRunRecord]:
        """The one ``RUNNING -> RUNNING`` write: ``finalization_deadline_utc``."""
        ...

    def record_timeout(
        self, expected_run_revision: int, run_id: RunId, diagnostic: Diagnostic
    ) -> Result[EngineRunRecord]:
        """``RUNNING -> TIMED_OUT`` with the finalization-timeout diagnostic."""
        ...


class EngineRunRecords(Protocol):
    """The two domain-typed run reads and writes the registration needs."""

    def get(self, run_id: RunId) -> Result[EngineRunRecord]: ...

    def compare_and_swap(
        self, expected_revision: int, replacement: EngineRunRecord
    ) -> Result[EngineRunRecord]: ...


class CommandInvocationRecords(Protocol):
    """The two domain-typed invocation reads and writes the registration needs."""

    def get(self, invocation_id: InvocationId) -> Result[CommandInvocationRecord]: ...

    def compare_and_swap(
        self, expected_revision: int, replacement: CommandInvocationRecord
    ) -> Result[CommandInvocationRecord]: ...


class DiagnosticWriter(Protocol):
    """The in-transaction, idempotent diagnostic writer (``DiagnosticRecorder``
    shaped)."""

    def record(self, diagnostic: Diagnostic) -> Result[None]: ...


class AuditAppender(Protocol):
    """The audit sink joined to the open transaction (specification 23.3.1:1714).

    The event type belongs to ``crypto_lab.audit``, which ``artifacts`` may not
    import; the appender is therefore typed structurally over the object the
    injected ``FinalizationAuditor`` composed, and the finalizer never calls it
    directly.
    """

    def append(self, event: Any) -> Result[None]: ...


# --------------------------------------------------------------------------
# The registration facts (plan 4.1): domain-typed read-only views
# --------------------------------------------------------------------------


class RunManifestFacts(Protocol):
    """One ``run_manifests`` row as facts; never the ``RunManifest`` record."""

    @property
    def manifest_id(self) -> RunManifestId: ...

    @property
    def run_id(self) -> RunId: ...

    @property
    def experiment_id(self) -> ExperimentId: ...

    @property
    def run_invocation_id(self) -> InvocationId: ...

    @property
    def attempt_token_hash(self) -> Sha256: ...

    @property
    def sanitized_adapter_result_manifest_hash(self) -> Sha256: ...

    @property
    def semantic_status(self) -> str: ...

    @property
    def process_exit_category(self) -> str: ...

    @property
    def manifest_json(self) -> str: ...

    @property
    def run_manifest_hash(self) -> Sha256: ...

    @property
    def registered_at_utc(self) -> datetime: ...


class SanitizedManifestFacts(Protocol):
    """One ``sanitized_adapter_result_manifests`` row as facts."""

    @property
    def sanitized_adapter_result_manifest_hash(self) -> Sha256: ...

    @property
    def run_id(self) -> RunId: ...

    @property
    def run_invocation_id(self) -> InvocationId: ...

    @property
    def experiment_id(self) -> ExperimentId: ...

    @property
    def attempt_token_hash(self) -> Sha256: ...

    @property
    def source_adapter_result_manifest_hash(self) -> Sha256: ...

    @property
    def semantic_status(self) -> str: ...

    @property
    def manifest_json(self) -> str: ...

    @property
    def evidence_artifact_id(self) -> ArtifactId | MISSING: ...  # type: ignore[valid-type]

    @property
    def recorded_at_utc(self) -> datetime: ...


class ValidationResultFacts(Protocol):
    """One ``adapter_validation_results`` row as facts."""

    @property
    def invocation_id(self) -> InvocationId: ...

    @property
    def run_id(self) -> RunId: ...

    @property
    def experiment_id(self) -> ExperimentId: ...

    @property
    def validation_result_hash(self) -> Sha256: ...

    @property
    def outcome(self) -> str: ...

    @property
    def result_json(self) -> str: ...

    @property
    def evidence_artifact_id(self) -> ArtifactId | MISSING: ...  # type: ignore[valid-type]

    @property
    def recorded_at_utc(self) -> datetime: ...


class RunArtifactLink(Protocol):
    """One ``run_artifacts`` row as facts: a ``RUN``-owned reference and its run."""

    @property
    def run_id(self) -> RunId: ...

    @property
    def artifact_id(self) -> ArtifactId: ...

    @property
    def link_role(self) -> str: ...

    @property
    def experiment_id(self) -> ExperimentId: ...

    @property
    def run_manifest_id(self) -> RunManifestId | MISSING: ...  # type: ignore[valid-type]


class RunManifestRepository(Protocol):
    """``run_manifests``: insert-only, one per successful run (reading 11)."""

    def add(self, facts: RunManifestFacts) -> Result[None]: ...

    def get(self, run_id: RunId) -> Result[RunManifestFacts | MISSING]: ...  # type: ignore[valid-type]


class SanitizedManifestRepository(Protocol):
    """``sanitized_adapter_result_manifests``: insert-once, evidence linked once."""

    def add(self, facts: SanitizedManifestFacts) -> Result[None]: ...

    def get(
        self, sanitized_adapter_result_manifest_hash: Sha256
    ) -> Result[SanitizedManifestFacts | MISSING]: ...  # type: ignore[valid-type]

    def link_evidence(
        self, sanitized_adapter_result_manifest_hash: Sha256, artifact_id: ArtifactId
    ) -> Result[None]: ...


class ValidationResultRepository(Protocol):
    """``adapter_validation_results``: insert-once, evidence linked once."""

    def add(self, facts: ValidationResultFacts) -> Result[None]: ...

    def get(
        self, invocation_id: InvocationId
    ) -> Result[ValidationResultFacts | MISSING]: ...  # type: ignore[valid-type]

    def link_evidence(
        self, invocation_id: InvocationId, artifact_id: ArtifactId
    ) -> Result[None]: ...


class RunArtifactRepository(Protocol):
    """``run_artifacts``: the ``RUN``-owner-only links (plan 3.3)."""

    def link(self, link: RunArtifactLink) -> Result[None]: ...

    def list_for_run(
        self, run_id: RunId
    ) -> Answer[tuple[RunArtifactLink, ...]] | Failure: ...


# --------------------------------------------------------------------------
# The units of work (plan 4.1)
# --------------------------------------------------------------------------


@runtime_checkable
class FinalizationUnitOfWork(Protocol):
    """One open transaction carrying the finalizer's members (plan 4.1).

    ``begin()`` is the Stage 5 root shape and a programmer defect on an open
    transaction; ``commit()`` publishes every staged write or none; ``rollback()``
    is idempotent, so the finalizer's ``finally`` clause is always safe and a
    ``BaseException`` raised with a transaction open rolls it back.
    """

    @property
    def candidate_artifacts(self) -> CandidateArtifactRepository: ...

    @property
    def artifact_refs(self) -> ArtifactRepository: ...

    @property
    def finalization_journal(self) -> FinalizationJournalRepository: ...

    @property
    def result_leases(self) -> ResultLeaseRepository: ...

    @property
    def diagnostics_writer(self) -> DiagnosticWriter: ...

    @property
    def audit(self) -> AuditAppender: ...

    def begin(self) -> FinalizationUnitOfWork: ...

    def commit(self) -> Result[None]: ...

    def rollback(self) -> None: ...


@runtime_checkable
class RegistrationUnitOfWork(FinalizationUnitOfWork, Protocol):
    """The finalization members plus those the RESULT registrar writes inside
    T3 and the reconciler reads per ``inv_`` root (plan 4.1, 4.3 phase 6)."""

    @property
    def engine_runs(self) -> EngineRunRecords: ...

    @property
    def command_invocations(self) -> CommandInvocationRecords: ...

    @property
    def run_manifests(self) -> RunManifestRepository: ...

    @property
    def sanitized_manifests(self) -> SanitizedManifestRepository: ...

    @property
    def validation_results(self) -> ValidationResultRepository: ...

    @property
    def run_artifacts(self) -> RunArtifactRepository: ...


type UnitOfWorkFactory = Callable[[], RegistrationUnitOfWork]


# --------------------------------------------------------------------------
# The command roots the caller projects (plan 4.1)
# --------------------------------------------------------------------------


def _lexically_under(candidate: Path, root: Path) -> bool:
    return PureWindowsPath(root) in PureWindowsPath(candidate).parents


@dataclass(frozen=True, slots=True, kw_only=True)
class CommandRootPaths:
    """The domain-typed projection of the Stage 7 ``CommandPaths`` (plan 4.1).

    Kind-governed exactly as that record: ``output_path`` is present exactly when
    ``work_dir`` is absent, ``work_dir`` and ``result_path`` are present together,
    every path is lexically under ``command_root`` and ``result_path`` is
    ``work_dir`` joined with ``adapter-result-manifest.json``. Consumers narrow by
    ``isinstance``: the RESULT branch and the recovery validator require a ``RUN``
    root; ``close_raw_bytes`` removes ``request_path``, ``output_path`` when
    present and, for a ``RUN`` root, ``result_path``.
    """

    command_root: Path
    request_path: Path
    output_path: Path | MISSING = MISSING  # type: ignore[valid-type]
    work_dir: Path | MISSING = MISSING  # type: ignore[valid-type]
    result_path: Path | MISSING = MISSING  # type: ignore[valid-type]

    def __post_init__(self) -> None:
        for name in ("command_root", "request_path"):
            value = getattr(self, name)
            if not isinstance(value, Path) or not value.is_absolute():
                raise ValueError(f"{name} must be an absolute Path")
        for name in ("output_path", "work_dir", "result_path"):
            value = getattr(self, name)
            if value is not MISSING and (
                not isinstance(value, Path) or not value.is_absolute()
            ):
                raise ValueError(f"{name} must be an absolute Path when present")
        work_present = isinstance(self.work_dir, Path)
        if work_present is not isinstance(self.result_path, Path):
            raise ValueError("work_dir and result_path are present together or absent")
        if isinstance(self.output_path, Path) is work_present:
            raise ValueError("output_path is present exactly when work_dir is absent")
        for name in ("request_path", "output_path", "work_dir", "result_path"):
            value = getattr(self, name)
            if isinstance(value, Path) and not _lexically_under(
                value, self.command_root
            ):
                raise ValueError(f"{name} must be lexically under command_root")
        if isinstance(self.work_dir, Path) and isinstance(self.result_path, Path):
            expected = PureWindowsPath(self.work_dir) / RESULT_MANIFEST_FILE_NAME
            if PureWindowsPath(self.result_path) != expected:
                raise ValueError(
                    "result_path must be work_dir joined with "
                    "adapter-result-manifest.json"
                )

    @property
    def is_run_root(self) -> bool:
        """Whether this is a ``RUN`` root (``work_dir`` and ``result_path`` present)."""
        return isinstance(self.work_dir, Path)

    @property
    def raw_byte_paths(self) -> tuple[Path, ...]:
        """The raw-bearing files of plan 4.3 phase 6, in removal order."""
        paths: list[Path] = [self.request_path]
        if isinstance(self.output_path, Path):
            paths.append(self.output_path)
        if isinstance(self.result_path, Path):
            paths.append(self.result_path)
        return tuple(paths)


type CommandRootsLookup = Callable[[InvocationId], CommandRootPaths | MISSING]  # type: ignore[valid-type]
type TokenMaterialLookup = Callable[[InvocationId], AttemptTokenMaterial | MISSING]  # type: ignore[valid-type]


# --------------------------------------------------------------------------
# Registrar, recovery validator and their facts (plan 4.1)
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class ResultRegistration:
    """What ``register_result`` recorded on T3: the run-manifest facts the
    ``FinalizationResult`` carries, the references it inserted and the artifact
    manifests it built beside them (the finalizer writes their projections)."""

    run_manifest_id: RunManifestId
    run_manifest_hash: Sha256
    refs: tuple[ArtifactRef, ...]
    manifests: tuple[ArtifactManifest, ...]


@runtime_checkable
class PurposeRegistrar(Protocol):
    """The purpose-specific registration inside T3 (plan 4.1, 4.3 phase 5).

    ``register_result`` owns the RESULT write order of plan 4.4 over the open
    transaction the finalizer passes in: the sanitized facts, the ``ArtifactManifest``
    of every reference (its ``ADAPTER`` lineage names the adapter manifest the
    sanitized facts identify -- a fact the finalizer never holds), the references
    through ``ArtifactRepository.stage_reference`` and ``record_finalization`` (a
    RESULT ``FinalizationResult`` must carry the run-manifest facts the registrar
    derives, plan 3.1, so the registrar records the references after deriving
    them), the ``RunManifest`` and its row, the member links, the run
    compare-and-swap ``RUNNING -> SUCCEEDED*`` at the journal's expected revision,
    and its audit facts. ``register_evidence`` records the evidence links of
    ``RUN`` owners, the ``stderr_artifact_id`` enrichment and its audit facts
    after the finalizer has recorded the references; it never reads or writes
    ``engine_runs``.
    """

    def register_result(
        self,
        transaction: RegistrationUnitOfWork,
        journal: FinalizationJournalEntry,
        refs: tuple[ArtifactRef, ...],
        facts: ResultLeaseFacts,
    ) -> Result[ResultRegistration]: ...

    def register_evidence(
        self,
        transaction: RegistrationUnitOfWork,
        journal: FinalizationJournalEntry,
        refs: tuple[ArtifactRef, ...],
    ) -> Result[None]: ...


@dataclass(frozen=True, slots=True, kw_only=True)
class CanonicalQualification:
    """The producer-side verdict over one ``CORE`` ``EVIDENCE`` candidate's records
    (the canonical evidence ruling of 2026-11-09): the bytes are exactly the
    approved producer's canonical output and agree with the authoritative facts
    for the candidate, its owner and its correlation. ``records`` counts the
    documents qualified (one for a JSON document, one per line of JSON Lines);
    ``uncontrolled_strings`` are the strings of those records that no closed
    grammar governs -- free text, adapter-chosen identifiers, dynamic mapping keys
    -- which the validation still holds to the field-level token-shape rule. A
    qualification is never a verdict on the raw token: the exact-byte scan runs
    over the candidate regardless."""

    records: int
    uncontrolled_strings: tuple[str, ...]


@runtime_checkable
class CanonicalEvidenceQualifier(Protocol):
    """The plan 4.6 canonical contract, answered by the composition that owns the
    producers (plan 2.3: ``experiments``, the one layer that may import the
    adapter and experiment records beside ``artifacts``).

    ``qualify_evidence`` receives the candidate and its already well-formed
    records (strict JSON, split by the validation) and answers ``Success(MISSING)``
    when no canonical contract governs the candidate or the records are not the
    producer's model (the whole-content protection then stands),
    ``Success(CanonicalQualification)`` when the records are the model, re-serialize
    to the very bytes and agree with the authoritative facts, and a ``Failure`` --
    ``ARTIFACT.VALIDATION_FAILED`` for content that is the model but disagrees
    with the facts, a ``PERSISTENCE.*`` code for facts that could not be read --
    which the validation records at its ``SCHEMA`` stage. A media type, a kind
    label, the ``CORE`` flag or a valid parse alone never qualifies.
    """

    def qualify_evidence(
        self, candidate: CandidateArtifact, records: tuple[bytes, ...]
    ) -> Result[CanonicalQualification | MISSING]: ...  # type: ignore[valid-type]


@dataclass(frozen=True, slots=True, kw_only=True)
class CandidateObservationFacts:
    """One candidate's independently observed digest and size (29.3)."""

    candidate_artifact_id: CandidateArtifactId
    sha256: Sha256
    size_bytes: int


@dataclass(frozen=True, slots=True, kw_only=True)
class ResultRecoveryFacts:
    """The domain-typed facts a validated temporary result manifest yields
    (plan 4.1, 29.3): identities, hashes, the semantic status, the finalization
    timeout to snapshot afresh (reading 2) and the per-candidate observations."""

    run_id: RunId
    run_invocation_id: InvocationId
    experiment_id: ExperimentId
    attempt_token_hash: Sha256
    source_adapter_result_manifest_hash: Sha256
    sanitized_adapter_result_manifest_hash: Sha256
    semantic_status: SemanticSuccessStatus
    finalization_timeout_seconds: int
    candidate_observations: tuple[CandidateObservationFacts, ...]


@runtime_checkable
class ResultRecoveryValidator(Protocol):
    """The 29.3 checks over the temporary result manifest (plan 4.1)."""

    def validate_temporary_manifest(
        self,
        roots: CommandRootPaths,
        token: AttemptTokenMaterial | MISSING,  # type: ignore[valid-type]
        candidates: tuple[CandidateArtifact, ...],
    ) -> Result[ResultRecoveryFacts]: ...


# --------------------------------------------------------------------------
# Audit and log facts (plan 4.8), the probe and the finalizer (plan 4.3)
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class AuditFact:
    """One meaningful action of the finalizer or the reconciler, described in
    domain terms for the auditor to turn into the sink's event. ``action`` and
    ``outcome`` are the audit vocabulary's member names; ``details`` carries
    counts, stages and codes -- never an identifier or a hash as a value, which
    the redaction fixed point would refuse (plan 7.3)."""

    action: str
    outcome: AuditOutcomeName
    correlation_id: str
    experiment_id: ExperimentId | MISSING = MISSING  # type: ignore[valid-type]
    run_id: RunId | MISSING = MISSING  # type: ignore[valid-type]
    invocation_id: InvocationId | MISSING = MISSING  # type: ignore[valid-type]
    artifact_id: ArtifactId | MISSING = MISSING  # type: ignore[valid-type]
    details: Mapping[str, DiagnosticDetailValue]


@runtime_checkable
class FinalizationAuditor(Protocol):
    """Append one ``AuditFact`` as the sink's event on the open transaction."""

    def append(
        self, transaction: FinalizationUnitOfWork, fact: AuditFact
    ) -> Result[None]: ...


@dataclass(frozen=True, slots=True, kw_only=True)
class LogFact:
    """One structured log line (specification 30.1), a projection and never a
    record of truth."""

    severity: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    event_code: str
    message: str
    correlation_id: str
    experiment_id: ExperimentId | MISSING = MISSING  # type: ignore[valid-type]
    run_id: RunId | MISSING = MISSING  # type: ignore[valid-type]
    invocation_id: InvocationId | MISSING = MISSING  # type: ignore[valid-type]
    details: Mapping[str, DiagnosticDetailValue]


@runtime_checkable
class FinalizationLog(Protocol):
    """The optional log projection the finalizer and the reconciler write."""

    def write(self, fact: LogFact) -> Result[None]: ...


@runtime_checkable
class FinalizationProbe(Protocol):
    """The ten probe points of plan 4.3; tests inject a crashing or recording
    probe, production ``NoProbe()``."""

    def before_prepared(self) -> None: ...

    def after_prepared(self) -> None: ...

    def before_move(self, index: int) -> None: ...

    def after_move(self, index: int) -> None: ...

    def before_moved(self) -> None: ...

    def after_moved(self) -> None: ...

    def before_registered(self) -> None: ...

    def inside_registered(self) -> None: ...

    def after_registered(self) -> None: ...

    def after_close(self) -> None: ...


class NoProbe:
    """The production probe: ten no-ops."""

    def before_prepared(self) -> None:
        return None

    def after_prepared(self) -> None:
        return None

    def before_move(self, index: int) -> None:
        del index

    def after_move(self, index: int) -> None:
        del index

    def before_moved(self) -> None:
        return None

    def after_moved(self) -> None:
        return None

    def before_registered(self) -> None:
        return None

    def inside_registered(self) -> None:
        return None

    def after_registered(self) -> None:
        return None

    def after_close(self) -> None:
        return None


@runtime_checkable
class ArtifactFinalizer(Protocol):
    """Specification 8.2: finalize one purpose-tagged request idempotently.

    ``token_material`` is optional transient material the caller's frame already
    holds (plan 4.4's conclusion before the root's raw bytes are closed); absent,
    the finalizer consults its ``TokenMaterialLookup``. Either source is validated
    against the authoritative run and invocation before use and lives in the call
    frame of the one ``finalize`` alone.
    """

    async def finalize(
        self,
        request: FinalizationRequest,
        cancellation: CancellationToken,
        *,
        token_material: AttemptTokenMaterial | MISSING = MISSING,  # type: ignore[valid-type]
    ) -> Result[FinalizationResult]: ...


__all__ = (
    "MAX_LISTING",
    "RESULT_MANIFEST_FILE_NAME",
    "Answer",
    "ArtifactFinalizer",
    "ArtifactRepository",
    "AuditAppender",
    "AuditFact",
    "AuditOutcomeName",
    "CandidateArtifactRepository",
    "CandidateObservationFacts",
    "CanonicalEvidenceQualifier",
    "CanonicalQualification",
    "CommandInvocationRecords",
    "CommandRootPaths",
    "CommandRootsLookup",
    "DiagnosticWriter",
    "EngineRunRecords",
    "FinalizationAuditor",
    "FinalizationJournalRepository",
    "FinalizationLog",
    "FinalizationProbe",
    "FinalizationRequest",
    "FinalizationUnitOfWork",
    "LogFact",
    "NoProbe",
    "PurposeRegistrar",
    "RegistrationUnitOfWork",
    "ResultLeaseFacts",
    "ResultLeaseRepository",
    "ResultRecoveryFacts",
    "ResultRecoveryValidator",
    "ResultRegistration",
    "RunArtifactLink",
    "RunArtifactRepository",
    "RunManifestFacts",
    "RunManifestRepository",
    "SanitizedManifestFacts",
    "SanitizedManifestRepository",
    "SemanticSuccessStatus",
    "TokenMaterialLookup",
    "UnitOfWorkFactory",
    "ValidationResultFacts",
    "ValidationResultRepository",
)
