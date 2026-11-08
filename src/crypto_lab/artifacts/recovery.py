"""The artifact half of startup reconciliation and the quarantine retention
primitives (Stage 9 plan 5.3, Task 6; specification 29.2 steps 4, 6, 7 and 9,
29.3, 29.4, 29.5, 17.3; readings 2, 8, 13).

The RESULT lease ruling of 2026-11-08: a restart alone supplies no authority
over an open journal. The single local reconciliation lease of specification
29.2 step 3 and the startup order are Stage 10 deliverables (plan 1.3 and 1.4:
"29.2 steps 1-3, 5, 8, 10, the reconciliation lease"), so this module cannot
prove that the prior holder is absent, and being called at startup is not by
itself that proof. The pass therefore resumes a ``PREPARED`` or ``MOVED``
journal only once its lease has expired -- the finalizer's ``resume_journal``
then takes the lease over by one audited compare-and-swap before any move, so a
holder that is still live, or a second newcomer, is fenced by the journal
revision -- and defers a journal whose lease is unexpired: counted as
``deferred``, never a change, its journal, candidates, planned blobs and staged
bytes left for a later pass (steps 2 and 3 skip every candidate and blob an open
journal names, and no root of a run with an open ``RESULT`` journal is closed).
The finalization deadline decides a ``RESULT`` journal's fate (reading 13). One
pass, in order:

1. Every ``PREPARED`` or ``MOVED`` journal whose lease has expired resumes
   through the finalizer's ``resume_journal`` (plan 5.1 recovery columns): a
   passed deadline is the plan 4.5 timeout, a hash mismatch or move failure
   abandons under 17.3 with the run ``RUNNING -> FAILED``, a ``MOVED``
   ``EVIDENCE`` journal registers without touching its run (29.4), a ``MOVED``
   ``RESULT`` journal registers only through the production registrar (Task 7)
   and is otherwise abandoned; a journal whose lease is unexpired is deferred.
2. The recoverable candidates (``CANDIDATE``, ``VALIDATING`` and unmapped
   ``FINALIZING``, 29.2 step 4): a ``FINALIZING`` candidate no open journal
   names is quarantined (RV-11); a ``RESULT`` group whose run-command invocation
   is not ``EXITED`` is left to the Stage 7 reconciler (RV-5); one whose run is
   terminal is quarantined (RV-8); one whose rows disagree with the invocation
   is quarantined (RV-7); one whose run is ``RUNNING`` with an ``EXITED``
   invocation is validated through the ``ResultRecoveryValidator`` (29.3) and
   resumed from phase 2 under a fresh deadline (reading 2) or, when any check
   fails, quarantined with the run ``FAILED`` under the check's diagnostic; a
   ``CORE`` candidate left in ``CANDIDATE`` or ``VALIDATING`` is abandoned
   staging and is quarantined (RV-10).
3. Step 9: a directory under the runtime root shaped like a command root that
   names no invocation is quarantined and never attached by name (RV-6); the
   raw-bearing bytes of every token-bearing root of a terminal run with no open
   ``RESULT`` journal are closed through ``close_raw_bytes`` (RV-8, plan 4.4
   step 5); a canonical object under ``objects/`` -- a file at the complete
   layout ``objects/<hh>/<sha256>`` the store writes, its shard matching its
   leaf, classified by the store's ``canonical_content_address`` over that
   whole root-relative path and never by the leaf alone -- that no open journal
   plans and that the ``artifact_refs`` rows do not register at that very path
   is quarantined as unregistered finalized content (RV-9: presence is never
   evidence of finalization, 19.3); protection is the complete durable path
   identity a planned move or a row names, never a digest alone, so a misplaced
   copy of a protected blob's bytes protects nothing. The supported store is a
   case-insensitive Windows volume, so the classification and both protection
   comparisons are case-folded as ``is_within_root`` folds (plan 6.3): a
   case-only rename of a shard directory or a leaf leaves the very same file at
   the very path a row or a planned move names and protects what it protected,
   while ``objects/zz/<sha256>`` or ``objects/.x/<sha256>`` is no case variant
   of any canonical path. Any other file there is one the store never wrote, so
   no row and no planned move can name it, and it is unregistered by
   construction: the rows are never asked about it, and it is quarantined with
   no digest claim under an identity derived from its confined relative path,
   never the untrusted name itself, which need not satisfy the store's entry
   grammar. A file whose ordinary name the candidate-path grammar refuses (a
   leading dot, a space; 15.5), and a misplaced file whose leaf merely resembles
   a content address (``objects/.x/<sha256>``, ``objects/odd dir/<sha256>``, a
   non-matching shard), go through the store's orphan operation -- the Task 6
   RV-9 file-map correction: ``confine_orphan_path`` keeps every physical rule
   and the structural rules and bounds of the candidate grammar, relaxing its
   character class alone, and ``quarantine_orphan`` moves the bytes to the plan
   6.2 layout ``<quarantine>/<entry_id>/<original relative path>`` -- the entry
   keyed by the derived identity, the bytes at the path they were found at --
   with that path in the validated metadata and every directory of the
   destination refused while it is a reparse point. What neither confinement
   admits (a reparse ancestor, a second hard link, a name no identity can be
   derived from) or whose destination is unsafe is left where the sweep found
   it, unmoved and unaudited: the pass never moves what it cannot confine. The
   orphan operation is scoped to ``objects/``; a projection under
   ``manifests/`` with such a name is not content and stays.
   Registration is decided by the rows alone, read by the blob's content hash
   through ``ArtifactRepository.list_by_content_hash`` -- the one read added
   over the committed plan 4.1 member list, recorded as a Task 6 file-map
   correction for RV-9 and plan 6.2: the row is authoritative and the
   ``manifests/<artifact_id>.json`` projection is a human-inspection file whose
   absence readers tolerate (after the 6.2 write order a crash between the T3
   commit and the projection write produces exactly a registered blob with no
   projection). A projection therefore never establishes registration: one
   naming the digest of a quarantined blob is stale and travels with it. A row
   read the repository refuses is answered as the pass's failure and quarantines
   nothing -- a read that failed is never absence.
4. A quarantine entry older than ``QUARANTINE_OVERDUE_SECONDS`` yields the
   ``ARTIFACT.QUARANTINE_OVERDUE`` diagnostic and audit fact; its bytes are
   untouched (RV-17, reading 8).
5. One ``RECONCILIATION_FINALIZATION_RESUMED`` audit row closes the pass with the
   report's counts and ``changes``; a second pass over the same state changes
   nothing and appends that one row with ``changes == 0`` (RV-14).

``purge_quarantine`` removes one entry's bytes with a ``RETENTION_DELETED``
audit fact and is refused while any ``PREPARED`` or ``MOVED`` journal names a
candidate of the entry (RV-18, 29.5:2192). Nothing here reads configuration,
the environment, the current directory or a home directory; every root is the
caller's.
"""

from __future__ import annotations

from collections.abc import Coroutine
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Final

from pydantic import InstanceOf
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.artifacts.diagnostics import (
    ARTIFACT_MOVE_FAILED,
    ARTIFACT_QUARANTINE_OVERDUE,
    ARTIFACT_RESULT_MANIFEST_INVALID,
    ARTIFACT_VALIDATION_FAILED,
    artifact_diagnostic,
    artifact_failure,
)
from crypto_lab.artifacts.finalizer import CoreArtifactFinalizer, close_raw_bytes
from crypto_lab.artifacts.hashing import ContentHasher
from crypto_lab.artifacts.journal import (
    FinalizationJournalEntry,
    FinalizationJournalState,
)
from crypto_lab.artifacts.manifest import ArtifactManifest
from crypto_lab.artifacts.models import (
    ArtifactFinalizationPurpose,
    ArtifactRef,
    CandidateArtifact,
    CandidateArtifactProducerKind,
    CandidateArtifactState,
    ValidationObservation,
)
from crypto_lab.artifacts.ownership import RunArtifactOwner, artifact_owner_hash
from crypto_lab.artifacts.paths import (
    confine_candidate_path,
    confine_orphan_path,
    lexical_candidate_path,
)
from crypto_lab.artifacts.ports import (
    AuditFact,
    CommandRootPaths,
    CommandRootsLookup,
    FinalizationAuditor,
    FinalizationLog,
    NoProbe,
    PurposeRegistrar,
    RegistrationUnitOfWork,
    ResultRecoveryFacts,
    ResultRecoveryValidator,
    TokenMaterialLookup,
    UnitOfWorkFactory,
)
from crypto_lab.artifacts.requests import (
    EvidenceFinalizationRequest,
    ResultFinalizationRequest,
)
from crypto_lab.artifacts.store import ArtifactStore, canonical_content_address
from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.diagnostics import Diagnostic, DiagnosticDetailValue
from crypto_lab.domain.engine_run import (
    EngineRunRecord,
    EngineRunRuleViolation,
    assert_run_transition,
)
from crypto_lab.domain.hashing import (
    _uuid4_shaped,
    candidate_set_hash_for,
    finalization_identity,
    sha256_bytes,
)
from crypto_lab.domain.identifiers import validate_prefixed_uuid4
from crypto_lab.domain.lifecycle import (
    TERMINAL_ENGINE_RUN_STATES,
    CommandInvocationState,
    CommandKind,
    EngineRunState,
)
from crypto_lab.domain.ports import Clock
from crypto_lab.domain.results import Failure, Result, Success

#: Plan 1.6 item 8 and 14.7:1018: the compiled quarantine age bound.
QUARANTINE_OVERDUE_SECONDS: Final = 86_400
#: The roots under the runtime root that are never command roots.
_RESERVED_RUNTIME_SEGMENTS: Final[frozenset[str]] = frozenset({"staging", "quarantine"})
_TOKEN_BEARING_KINDS: Final[frozenset[CommandKind]] = frozenset(
    {CommandKind.VALIDATE, CommandKind.RUN}
)
_RECOVERABLE_STATES: Final = (
    CandidateArtifactState.CANDIDATE,
    CandidateArtifactState.VALIDATING,
    CandidateArtifactState.FINALIZING,
)
_MAX_PROJECTION_BYTES: Final = 65_536
#: The digits of a content-address name under ``objects/`` (64 lowercase hex).
_HEX_DIGITS: Final[frozenset[str]] = frozenset("0123456789abcdef")
_S: Final = CandidateArtifactState
_P: Final = CandidateArtifactProducerKind
_F: Final = ArtifactFinalizationPurpose
_J: Final = FinalizationJournalState


@dataclass(frozen=True, slots=True, kw_only=True)
class FinalizationReconciliationReport:
    """The counts of one ``reconcile_finalization`` pass (plan Task 6).
    ``deferred`` counts the open journals left under an unexpired lease (the
    ruling of 2026-11-08); a deferral changes nothing."""

    resumed: int
    deferred: int
    registered: int
    abandoned: int
    quarantined: int
    overdue: int
    closed_roots: int
    changes: int


@dataclass(slots=True)
class _Counts:
    resumed: int = 0
    deferred: int = 0
    registered: int = 0
    abandoned: int = 0
    quarantined: int = 0
    overdue: int = 0
    closed_roots: int = 0

    def report(self) -> FinalizationReconciliationReport:
        return FinalizationReconciliationReport(
            resumed=self.resumed,
            deferred=self.deferred,
            registered=self.registered,
            abandoned=self.abandoned,
            quarantined=self.quarantined,
            overdue=self.overdue,
            closed_roots=self.closed_roots,
            changes=self.registered
            + self.abandoned
            + self.quarantined
            + self.closed_roots,
        )


class _NeverCancelled:
    """The reconciler's cancellation token: recovery is never cancelled."""

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


def _is_command_root_name(name: str) -> bool:
    try:
        validate_prefixed_uuid4(name, "inv_")
    except ValueError:
        return False
    return True


def _is_content_address(name: str) -> bool:
    """Whether ``name`` is, compared case-folded as the supported case-insensitive
    store compares names, a blob name the store writes: 64 hex digits. A leaf of
    that shape at no canonical layout is misplaced content (RV-9)."""
    folded = name.casefold()
    return len(folded) == 64 and set(folded) <= _HEX_DIGITS


def _candidate_grammar_admits(relative: str) -> bool:
    """Whether the candidate-path grammar admits ``relative`` lexically; a path it
    refuses is an orphan for the store's orphan operation (RV-9)."""
    try:
        lexical_candidate_path(relative)
    except ValueError:
        return False
    return True


def _unregistered_entry_id(relative: str) -> str:
    """The quarantine entry of a file under ``objects/`` whose name is no content
    address (RV-9): derived from the confined relative path, so the identity
    satisfies the store's entry grammar whatever the untrusted name was and
    claims no digest -- the bare digest family belongs to the content-addressed
    names alone."""
    return f"unregistered_{_uuid4_shaped(sha256_bytes(relative.encode('utf-8')))}"


def _correlation_of(candidate: CandidateArtifact) -> dict[str, Any]:
    """The run correlation a ``RUN``-owned candidate's diagnostic and audit fact
    carry; any other owner carries none."""
    owner = candidate.owner
    if isinstance(owner, RunArtifactOwner):
        return {
            "experiment_id": owner.experiment_id,
            "run_id": owner.run_id,
            "invocation_id": owner.invocation_id,
        }
    return {}


def _relative_files(root: Path) -> tuple[str, ...]:
    return tuple(
        sorted(
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file() and not path.is_symlink()
        )
    )


class _Reconciler:
    """One pass of ``reconcile_finalization``; the state is the pass's counts."""

    def __init__(
        self,
        *,
        unit_of_work_factory: UnitOfWorkFactory,
        store: ArtifactStore,
        hasher: ContentHasher,
        registrar: PurposeRegistrar,
        recovery_validator: ResultRecoveryValidator,
        auditor: FinalizationAuditor,
        clock: Clock,
        runtime_root: Path,
        command_roots: CommandRootsLookup,
        token_material: TokenMaterialLookup,
        log: FinalizationLog | None,
    ) -> None:
        self._factory = unit_of_work_factory
        self._store = store
        self._validator = recovery_validator
        self._auditor = auditor
        self._clock = clock
        self._runtime_root = runtime_root
        self._command_roots = command_roots
        self._token_material = token_material
        self._counts = _Counts()
        self._finalizer = CoreArtifactFinalizer(
            unit_of_work_factory,
            clock,
            hasher,
            store,
            NoProbe(),
            registrar,
            auditor,
            command_roots=command_roots,
            token_material=token_material,
            log=log,
            fail_run_on_abandon=True,
        )

    # -- the pass ----------------------------------------------------------------

    def run(self) -> Result[FinalizationReconciliationReport]:
        for step in (
            self._resume_open_journals,
            self._reconcile_candidates,
            self._quarantine_orphans_and_close_roots,
            self._quarantine_unregistered_content,
            self._report_overdue_quarantine,
        ):
            failed = step()
            if failed is not None:
                return failed
        summary = self._summary()
        if summary is not None:
            return summary
        return Success[InstanceOf[FinalizationReconciliationReport]](
            outcome="SUCCESS", value=self._counts.report()
        )

    def _open_journals(self) -> Result[tuple[FinalizationJournalEntry, ...]]:
        transaction = self._factory()
        try:
            return transaction.finalization_journal.list_open()
        finally:
            transaction.rollback()

    def _journal_state(self, finalization_id: str) -> FinalizationJournalState | None:
        transaction = self._factory()
        try:
            loaded = transaction.finalization_journal.get(finalization_id)
        finally:
            transaction.rollback()
        return loaded.value.state if isinstance(loaded, Success) else None

    def _count_terminal(self, finalization_id: str) -> None:
        state = self._journal_state(finalization_id)
        if state is _J.REGISTERED:
            self._counts.registered += 1
        elif state is _J.ABANDONED:
            self._counts.abandoned += 1

    def _resume_open_journals(self) -> Failure | None:
        """Step 1: an open journal under an unexpired lease is deferred -- the
        pass has no authority over a lease that may still be held -- and one
        whose lease has expired is taken over and resumed by the finalizer."""
        entries = self._open_journals()
        if isinstance(entries, Failure):
            return entries
        now = self._clock.now_utc()
        for entry in entries.value:
            if entry.lease_expires_at_utc > now:
                self._counts.deferred += 1
                continue
            self._counts.resumed += 1
            self._finalizer.resume_journal(entry)
            self._count_terminal(entry.finalization_id)
        return None

    # -- step 4: candidates ---------------------------------------------------------

    def _reconcile_candidates(self) -> Failure | None:
        transaction = self._factory()
        try:
            listed = transaction.candidate_artifacts.list_recoverable(
                _RECOVERABLE_STATES
            )
            open_entries = transaction.finalization_journal.list_open()
        finally:
            transaction.rollback()
        if isinstance(listed, Failure):
            return listed
        if isinstance(open_entries, Failure):
            return open_entries
        open_ids = {
            candidate_id
            for entry in open_entries.value
            for candidate_id in entry.candidate_artifact_ids
        }
        result_groups: dict[tuple[str, str], list[CandidateArtifact]] = {}
        evidence_groups: dict[tuple[str, str, str, str], list[CandidateArtifact]] = {}
        for candidate in listed.value:
            if candidate.candidate_artifact_id in open_ids:
                continue
            if candidate.state is _S.FINALIZING:
                failed = self._quarantine_candidate(
                    candidate,
                    ARTIFACT_VALIDATION_FAILED,
                    "a FINALIZING candidate with no journal and no reference (RV-11)",
                )
                if failed is not None:
                    return failed
                continue
            owner = candidate.owner
            if candidate.finalization_purpose is _F.RESULT and isinstance(
                owner, RunArtifactOwner
            ):
                key = (owner.run_id, str(owner.invocation_id))
                result_groups.setdefault(key, []).append(candidate)
                continue
            if candidate.producer_kind is not _P.CORE:
                failed = self._quarantine_candidate(
                    candidate,
                    ARTIFACT_VALIDATION_FAILED,
                    "an adapter-produced candidate outside a RUN-owned RESULT (RV-7)",
                )
                if failed is not None:
                    return failed
                continue
            kind, correlation_id = candidate.staging_relative_path.split("/")[:2]
            evidence_key = (
                artifact_owner_hash(owner),
                candidate.source_role.value,
                kind,
                correlation_id,
            )
            evidence_groups.setdefault(evidence_key, []).append(candidate)
        for (run_id, invocation_id), group in sorted(result_groups.items()):
            failed = self._reconcile_result_group(run_id, invocation_id, tuple(group))
            if failed is not None:
                return failed
        for _, evidence in sorted(evidence_groups.items()):
            failed = self._reconcile_evidence_group(tuple(evidence))
            if failed is not None:
                return failed
        return None

    def _reconcile_evidence_group(
        self, group: tuple[CandidateArtifact, ...]
    ) -> Failure | None:
        """29.4 and plan 5.1 CP-1: core candidates left before their lease resume
        through the finalizer, revalidated independently; staging whose
        invocation is gone or already cleaned up is abandoned (RV-10)."""
        first = group[0]
        kind, correlation_id = first.staging_relative_path.split("/")[:2]
        if kind == "INVOCATION":
            transaction = self._factory()
            try:
                invocation = transaction.command_invocations.get(correlation_id)
            finally:
                transaction.rollback()
            if isinstance(invocation, Failure) or invocation.value.cleanup_complete:
                return self._quarantine_group(
                    group,
                    ARTIFACT_VALIDATION_FAILED,
                    "abandoned core staging older than its invocation's cleanup "
                    "(RV-10)",
                )
        ids = tuple(sorted(candidate.candidate_artifact_id for candidate in group))
        owner_hash = artifact_owner_hash(first.owner)
        set_hash = candidate_set_hash_for(ids)
        correlation_field = {
            "INVOCATION": "invocation_id",
            "DIAGNOSTIC": "diagnostic_id",
            "AUDIT": "audit_event_id",
        }.get(kind)
        if correlation_field is None:
            return self._quarantine_group(
                group, ARTIFACT_VALIDATION_FAILED, "an unknown correlation kind"
            )
        try:
            request = EvidenceFinalizationRequest.model_validate(
                {
                    "schema_version": "1.0.0",
                    "finalization_purpose": "EVIDENCE",
                    "owner": first.owner,
                    "source_role": first.source_role,
                    "candidate_artifact_ids": ids,
                    "candidate_set_hash": set_hash,
                    "correlation": {"kind": kind, correlation_field: correlation_id},
                    "idempotency_key": finalization_identity(
                        "EVIDENCE",
                        owner_hash=owner_hash,
                        correlation_kind=kind,
                        correlation_id=correlation_id,
                        candidate_set_hash=set_hash,
                    ),
                }
            )
        except ValueError as error:
            return self._quarantine_group(
                group,
                ARTIFACT_VALIDATION_FAILED,
                f"the staged evidence forms no EVIDENCE request: {error}",
            )
        self._counts.resumed += 1
        outcome = _drive(self._finalizer.finalize(request, _NeverCancelled()))
        if isinstance(outcome, Success):
            self._counts.registered += 1
            return None
        transaction = self._factory()
        try:
            found = transaction.finalization_journal.find_evidence_identity(
                owner_hash, kind, correlation_id, set_hash
            )
        finally:
            transaction.rollback()
        if isinstance(found, Success) and isinstance(
            found.value, FinalizationJournalEntry
        ):
            if found.value.state is _J.ABANDONED:
                self._counts.abandoned += 1
            elif found.value.state is _J.REGISTERED:
                self._counts.registered += 1
            return None
        # Refused before T1 (a failed independent revalidation): the finalizer
        # quarantined the failing candidate; the others stay for the next pass.
        return None

    def _reconcile_result_group(
        self, run_id: str, invocation_id: str, group: tuple[CandidateArtifact, ...]
    ) -> Failure | None:
        transaction = self._factory()
        try:
            run = transaction.engine_runs.get(run_id)
            invocation = transaction.command_invocations.get(invocation_id)
        finally:
            transaction.rollback()
        if isinstance(run, Failure) or isinstance(invocation, Failure):
            return self._quarantine_group(
                group,
                ARTIFACT_VALIDATION_FAILED,
                "a RESULT candidate names a run or invocation that does not exist",
            )
        record = invocation.value
        if (
            record.run_id != run_id
            or record.command_kind is not CommandKind.RUN
            or any(
                candidate.producer_kind is not _P.ADAPTER
                or artifact_owner_hash(candidate.owner)
                != artifact_owner_hash(group[0].owner)
                for candidate in group
            )
        ):
            return self._quarantine_group(
                group,
                ARTIFACT_VALIDATION_FAILED,
                "a RESULT candidate's rows disagree with its invocation (RV-7)",
            )
        if record.state is not CommandInvocationState.EXITED:
            return None  # RV-5: the Stage 7 reconciler owns the invocation
        current = run.value
        if current.state in TERMINAL_ENGINE_RUN_STATES:
            failed = self._quarantine_group(
                group,
                ARTIFACT_VALIDATION_FAILED,
                "a RESULT candidate of a terminal attempt is never finalized (RV-8)",
            )
            if failed is not None:
                return failed
            return self._close_root_if_terminal(record, current)
        if current.state is not EngineRunState.RUNNING:
            return None
        return self._recover_result(current, record, group)

    def _recover_result(
        self,
        run: EngineRunRecord,
        invocation: CommandInvocationRecord,
        group: tuple[CandidateArtifact, ...],
    ) -> Failure | None:
        """29.3 and plan 5.1 CP-1: the validated temporary manifest resumes the
        attempt from phase 2 under a fresh deadline; a failed check quarantines
        the candidates and fails the run under the check's diagnostic (17.3)."""
        now = self._clock.now_utc()
        roots = self._command_roots(invocation.invocation_id)
        if not isinstance(roots, CommandRootPaths) or not roots.is_run_root:
            refusal = artifact_failure(
                ARTIFACT_RESULT_MANIFEST_INVALID,
                message="the RUN root of the attempt no longer exists",
                invocation_id=invocation.invocation_id,
                run_id=run.run_id,
                experiment_id=run.experiment_id,
                now_utc=now,
            )
            return self._fail_recovery(run, invocation, group, refusal, roots=MISSING)
        token = self._token_material(invocation.invocation_id)
        validated = self._validator.validate_temporary_manifest(roots, token, group)
        if isinstance(validated, Failure):
            return self._fail_recovery(run, invocation, group, validated, roots=roots)
        request = _request_of(validated.value, run, invocation, group)
        if isinstance(request, Failure):
            return self._fail_recovery(run, invocation, group, request, roots=roots)
        self._counts.resumed += 1
        outcome = _drive(self._finalizer.finalize(request, _NeverCancelled()))
        if isinstance(outcome, Success):
            self._counts.registered += 1
            return None
        transaction = self._factory()
        try:
            found = transaction.finalization_journal.find_result_identity(
                invocation.invocation_id,
                validated.value.source_adapter_result_manifest_hash,
            )
        finally:
            transaction.rollback()
        if isinstance(found, Success) and isinstance(
            found.value, FinalizationJournalEntry
        ):
            if found.value.state is _J.ABANDONED:
                self._counts.abandoned += 1
            elif found.value.state is _J.REGISTERED:
                self._counts.registered += 1
            return None
        # Refused before T1: the candidates the finalizer did not quarantine are
        # quarantined here and the attempt fails under the refusal (17.3).
        return self._fail_recovery(run, invocation, group, outcome, roots=roots)

    def _fail_recovery(
        self,
        run: EngineRunRecord,
        invocation: CommandInvocationRecord,
        group: tuple[CandidateArtifact, ...],
        failure: Failure,
        *,
        roots: CommandRootPaths | MISSING,  # type: ignore[valid-type]
    ) -> Failure | None:
        """17.3 after a failed check: the run ``RUNNING -> FAILED`` under the
        check's diagnostic and every candidate of the group ``-> QUARANTINED``
        under the same diagnostic commit in one transaction, or not at all. A
        refused terminal write therefore leaves the pre-state -- the recoverable
        rows beside the ``RUNNING`` run -- for the next pass to re-derive the same
        failure from (the diagnostic identity is content-addressed; the clock
        instant is not hash material), never quarantined rows step 4 can no
        longer list beside a run no later pass would fail. The byte moves and
        the root close follow the commit, outside the transaction; a run a
        terminal winner moved meanwhile keeps its state and the cleanup still
        completes."""
        diagnostic = failure.diagnostics[0]
        quarantined = self._quarantine_rows(
            group,
            diagnostic,
            self._clock.now_utc(),
            run_failure=(run, invocation),
        )
        if quarantined is not None:
            return quarantined
        if isinstance(roots, CommandRootPaths) and invocation.command_kind in (
            _TOKEN_BEARING_KINDS
        ):
            return self._close_root(roots, run, invocation)
        return None

    def _stage_run_failure(
        self,
        transaction: RegistrationUnitOfWork,
        run: EngineRunRecord,
        invocation: CommandInvocationRecord,
        diagnostic: Diagnostic,
        now: datetime,
    ) -> Failure | None:
        """Stage ``RUNNING -> FAILED`` with ``diagnostic`` as the primary terminal
        diagnostic and its ``RUN_FAILED`` fact on ``transaction``; a run that is
        no longer ``RUNNING`` belongs to its terminal winner and is left alone."""
        loaded = transaction.engine_runs.get(run.run_id)
        if isinstance(loaded, Failure):
            return loaded
        current = loaded.value
        if current.state is not EngineRunState.RUNNING:
            return None
        payload = current.model_dump(mode="python")
        payload["state"] = EngineRunState.FAILED
        payload["primary_terminal_diagnostic_id"] = diagnostic.diagnostic_id
        payload["revision"] = current.revision + 1
        payload["updated_at_utc"] = max(current.updated_at_utc, now)
        try:
            replacement = EngineRunRecord.model_validate(payload)
            assert_run_transition(current, replacement)
        except (ValueError, EngineRunRuleViolation) as violation:
            return artifact_failure(
                ARTIFACT_VALIDATION_FAILED,
                message=f"run {run.run_id} admits no FAILED write: {violation}",
                now_utc=now,
            )
        recorded = transaction.diagnostics_writer.record(diagnostic)
        if isinstance(recorded, Failure):
            return recorded
        swapped = transaction.engine_runs.compare_and_swap(
            current.revision, replacement
        )
        if isinstance(swapped, Failure):
            return swapped
        audited = self._auditor.append(
            transaction,
            AuditFact(
                action="RUN_FAILED",
                outcome="FAILED",
                correlation_id=invocation.invocation_id,
                experiment_id=run.experiment_id,
                run_id=run.run_id,
                invocation_id=invocation.invocation_id,
                details={"reason": diagnostic.error_code, "recovery": True},
            ),
        )
        if isinstance(audited, Failure):
            return audited
        return None

    # -- quarantine of candidates ----------------------------------------------------

    def _quarantine_group(
        self, group: tuple[CandidateArtifact, ...], reason: str, message: str
    ) -> Failure | None:
        """Every candidate of ``group`` through ``_quarantine_candidate``, each in
        a transaction of its own (RV-7, RV-8, RV-10); a failed check's group goes
        through ``_fail_recovery`` instead, with its run in one transaction."""
        for candidate in group:
            failed = self._quarantine_candidate(candidate, reason, message)
            if failed is not None:
                return failed
        return None

    def _candidate_root(self, candidate: CandidateArtifact) -> Path | None:
        owner = candidate.owner
        if candidate.producer_kind is _P.ADAPTER:
            if not isinstance(owner, RunArtifactOwner) or not isinstance(
                owner.invocation_id, str
            ):
                return None
            roots = self._command_roots(owner.invocation_id)
            if isinstance(roots, CommandRootPaths) and isinstance(roots.work_dir, Path):
                return roots.work_dir
            return None
        return self._store.staging_root / artifact_owner_hash(owner)

    def _quarantine_candidate(
        self, candidate: CandidateArtifact, reason: str, message: str
    ) -> Failure | None:
        """One candidate ``-> QUARANTINED`` in a transaction of its own under the
        diagnostic built from ``reason`` and ``message`` (the candidate's run
        correlation when it has one), with its
        ``RECONCILIATION_CANDIDATE_QUARANTINED`` fact, then its staging bytes to
        the entry keyed by its identity."""
        now = self._clock.now_utc()
        diagnostic = artifact_diagnostic(
            reason, message=message, now_utc=now, **_correlation_of(candidate)
        )
        return self._quarantine_rows((candidate,), diagnostic, now)

    def _quarantine_rows(
        self,
        group: tuple[CandidateArtifact, ...],
        diagnostic: Diagnostic,
        now: datetime,
        *,
        run_failure: tuple[EngineRunRecord, CommandInvocationRecord] | None = None,
    ) -> Failure | None:
        """One transaction: the 17.3 run ``RUNNING -> FAILED`` when ``run_failure``
        names the attempt, then every candidate of ``group`` ``-> QUARANTINED``
        under ``diagnostic`` with its fact. Each row is re-read inside the
        transaction and swapped at its current revision: a candidate another
        write already moved to ``QUARANTINED`` or ``CORRUPT`` -- the finalizer's
        own phase-1 quarantine of a refused recovery (14.7, 17.3) -- is left
        alone, neither swapped nor counted. Only after the commit are the staged
        candidates counted and their bytes moved, outside any transaction."""
        staged: list[CandidateArtifact] = []
        transaction = self._factory()
        try:
            if run_failure is not None:
                run, invocation = run_failure
                failed = self._stage_run_failure(
                    transaction, run, invocation, diagnostic, now
                )
                if failed is not None:
                    return failed
            for candidate in group:
                outcome = self._stage_quarantine(
                    transaction, candidate, diagnostic, now
                )
                if isinstance(outcome, Failure):
                    return outcome
                if outcome:
                    staged.append(candidate)
            committed = transaction.commit()
            if isinstance(committed, Failure):
                return committed
        finally:
            transaction.rollback()
        for candidate in staged:
            self._counts.quarantined += 1
            self._move_quarantined_bytes(candidate, diagnostic.error_code, now)
        return None

    def _stage_quarantine(
        self,
        transaction: RegistrationUnitOfWork,
        candidate: CandidateArtifact,
        diagnostic: Diagnostic,
        now: datetime,
    ) -> Failure | bool:
        """Stage one candidate ``-> QUARANTINED`` under ``diagnostic`` on
        ``transaction``: ``True`` once staged, ``False`` when another write
        already moved the row to ``QUARANTINED`` or ``CORRUPT``."""
        loaded = transaction.candidate_artifacts.get(candidate.candidate_artifact_id)
        if isinstance(loaded, Failure):
            return loaded
        current = loaded.value
        if current.state in (_S.QUARANTINED, _S.CORRUPT):
            return False
        observation = ValidationObservation(
            observed_at_utc=now,
            stage="SEMANTIC",
            outcome="FAILED",
            error_code=diagnostic.error_code,
            diagnostic_id=diagnostic.diagnostic_id,
        )
        payload = current.model_dump(mode="python")
        payload["state"] = _S.QUARANTINED
        payload["validation_observations"] = (
            *current.validation_observations,
            observation,
        )
        payload["revision"] = current.revision + 1
        payload["updated_at_utc"] = max(current.updated_at_utc, now)
        replacement = CandidateArtifact.model_validate(
            {key: value for key, value in payload.items() if value is not MISSING}
        )
        recorded = transaction.diagnostics_writer.record(diagnostic)
        if isinstance(recorded, Failure):
            return recorded
        swapped = transaction.candidate_artifacts.compare_and_swap(
            current.revision, replacement
        )
        if isinstance(swapped, Failure):
            return swapped
        audited = self._auditor.append(
            transaction,
            AuditFact(
                action="RECONCILIATION_CANDIDATE_QUARANTINED",
                outcome="FAILED",
                correlation_id=candidate.candidate_artifact_id,
                details={"reason": diagnostic.error_code},
                **_correlation_of(candidate),
            ),
        )
        if isinstance(audited, Failure):
            return audited
        return True

    def _move_quarantined_bytes(
        self, candidate: CandidateArtifact, reason: str, now: datetime
    ) -> None:
        """A quarantined candidate's staging bytes to the entry keyed by its
        identity, after the commit; bytes no root confines stay where they are."""
        root = self._candidate_root(candidate)
        if root is None:
            return
        confined = confine_candidate_path(
            root, candidate.staging_relative_path, now_utc=now
        )
        if isinstance(confined, Success):
            self._store.quarantine_move(
                confined.value, candidate.candidate_artifact_id, reason, now_utc=now
            )

    # -- step 9: orphans, raw-byte sweep, unregistered content -------------------

    def _quarantine_orphans_and_close_roots(self) -> Failure | None:
        if not self._runtime_root.is_dir():
            return None
        for child in sorted(self._runtime_root.iterdir()):
            if child.name in _RESERVED_RUNTIME_SEGMENTS or not child.is_dir():
                continue
            if child.is_symlink() or not _is_command_root_name(child.name):
                continue
            transaction = self._factory()
            try:
                invocation = transaction.command_invocations.get(child.name)
                run: Result[EngineRunRecord] | None = None
                if isinstance(invocation, Success) and isinstance(
                    invocation.value.run_id, str
                ):
                    run = transaction.engine_runs.get(invocation.value.run_id)
            finally:
                transaction.rollback()
            if isinstance(invocation, Failure):
                failed = self._quarantine_tree(child)
                if failed is not None:
                    return failed
                continue
            if run is None or isinstance(run, Failure):
                continue
            failed = self._close_root_if_terminal(invocation.value, run.value)
            if failed is not None:
                return failed
        return None

    def _quarantine_tree(self, directory: Path) -> Failure | None:
        """RV-6: every regular file of an orphan command root into the quarantine
        entry keyed by the directory name, the emptied directories removed."""
        now = self._clock.now_utc()
        for relative in _relative_files(directory):
            confined = confine_candidate_path(directory, relative, now_utc=now)
            if isinstance(confined, Failure):
                continue
            self._store.quarantine_move(
                confined.value, directory.name, ARTIFACT_VALIDATION_FAILED, now_utc=now
            )
        for path in sorted(directory.rglob("*"), reverse=True):
            if path.is_dir() and not path.is_symlink():
                try:
                    path.rmdir()
                except OSError:
                    continue
        try:
            directory.rmdir()
        except OSError:
            pass
        failed = self._audit_alone(
            "RECONCILIATION_ORPHAN_QUARANTINED",
            "FAILED",
            directory.name,
            {"kind": "orphan_directory"},
        )
        if failed is not None:
            return failed
        self._counts.quarantined += 1
        return None

    def _close_root_if_terminal(
        self, invocation: CommandInvocationRecord, run: EngineRunRecord
    ) -> Failure | None:
        """RV-8 and plan 4.4 step 5: the raw-bearing bytes of a token-bearing root
        of a terminal run with no open RESULT journal are closed."""
        if (
            invocation.command_kind not in _TOKEN_BEARING_KINDS
            or run.state not in TERMINAL_ENGINE_RUN_STATES
        ):
            return None
        entries = self._open_journals()
        if isinstance(entries, Failure):
            return entries
        if any(
            entry.finalization_purpose is _F.RESULT and entry.run_id == run.run_id
            for entry in entries.value
        ):
            return None
        roots = self._command_roots(invocation.invocation_id)
        if not isinstance(roots, CommandRootPaths):
            return None
        if not any(path.exists() for path in roots.raw_byte_paths):
            return None  # already closed: a second pass changes nothing
        return self._close_root(roots, run, invocation)

    def _close_root(
        self,
        roots: CommandRootPaths,
        run: EngineRunRecord,
        invocation: CommandInvocationRecord,
    ) -> Failure | None:
        transaction = self._factory()
        try:
            closed = close_raw_bytes(
                roots,
                store=self._store,
                unit_of_work=transaction,
                auditor=self._auditor,
                correlation=invocation.invocation_id,
                clock=self._clock,
                experiment_id=run.experiment_id,
                run_id=run.run_id,
                invocation_id=invocation.invocation_id,
            )
            if isinstance(closed, Failure):
                return closed
            committed = transaction.commit()
            if isinstance(committed, Failure):
                return committed
        finally:
            transaction.rollback()
        self._counts.closed_roots += 1
        return None

    def _quarantine_unregistered_content(self) -> Failure | None:
        """RV-9: a canonical object -- a file at the complete layout
        ``objects/<hh>/<sha256>`` with the shard matching its leaf, classified by
        the store's ``canonical_content_address`` over its root-relative path
        compared case-folded as the supported case-insensitive store compares
        names, never by its leaf alone -- that no open journal plans and no
        ``artifact_refs`` row registers is unregistered content. Protection is a
        complete durable path identity: the ``finalized_relative_path`` of a
        planned move of an open journal, or of a row read by the blob's digest
        through ``list_by_content_hash`` (plan 6.2), must equal the blob's own
        path under the same fold, so a case-only rename of a shard or a leaf --
        the very same file on that store -- protects what it protected, while a
        misplaced copy under any other directory is no canonical object and never
        protected. A refused read is the pass's failure, never absence, so the
        blob stays for the next pass; a projection naming the digest of a
        quarantined blob is stale and travels with it. Any other file is never
        asked about -- no row and no planned move can name a path the store never
        writes -- and is quarantined under the identity ``_unregistered_entry_id``
        derives from its confined relative path, with no digest claim: a
        misplaced file whose leaf merely resembles a content address, and one
        whose name the candidate-path grammar refuses, go through the store's
        orphan operation; an ordinary grammar-admitted name goes through the
        candidate quarantine; both keep the path they were found at under the
        entry (plan 6.2; see the module docstring)."""
        objects_root = self._store.objects_root
        if not objects_root.is_dir():
            return None
        entries = self._open_journals()
        if isinstance(entries, Failure):
            return entries
        planned = {
            move.finalized_relative_path.casefold()
            for entry in entries.value
            for move in entry.planned_paths
        }
        projections = self._projections_by_hash()
        now = self._clock.now_utc()
        for blob in sorted(objects_root.rglob("*")):
            if not blob.is_file() or blob.is_symlink():
                continue
            relative = blob.relative_to(self._store.artifacts_root).as_posix()
            digest = canonical_content_address(relative)
            if digest is not None:
                folded = relative.casefold()
                if folded in planned:
                    continue
                registered = self._registered_references(digest)
                if isinstance(registered, Failure):
                    return registered
                if any(
                    ref.finalized_relative_path.casefold() == folded
                    for ref in registered.value
                ):
                    continue
                entry_id = self._quarantine_unregistered_blob(
                    relative, digest, projections.get(digest, []), now
                )
            elif _is_content_address(blob.name) or not _candidate_grammar_admits(
                relative
            ):
                entry_id = self._quarantine_orphan_file(relative, now)
            else:
                entry_id = self._quarantine_unregistered_blob(relative, None, [], now)
            if entry_id is None:
                continue
            failed = self._audit_alone(
                "RECONCILIATION_ORPHAN_QUARANTINED",
                "FAILED",
                entry_id,
                {"kind": "unregistered_content"},
            )
            if failed is not None:
                return failed
            self._counts.quarantined += 1
        return None

    def _quarantine_unregistered_blob(
        self,
        relative: str,
        digest: str | None,
        stale: list[Path],
        now: datetime,
    ) -> str | None:
        """A blob whose path the candidate grammar admits: confined and moved by
        ``quarantine_move`` under its ``digest`` (a canonical object, with the
        digest claim; its observed-case path kept under the entry) or, given no
        digest, under the derived identity (an ordinary admitted name that is no
        content address, no claim), its stale projections travelling with it;
        the entry id once the bytes moved, ``None`` when the sweep leaves the
        file for a later pass."""
        confined = confine_candidate_path(
            self._store.artifacts_root, relative, now_utc=now
        )
        if isinstance(confined, Failure):
            return None
        entry_id = _unregistered_entry_id(relative) if digest is None else digest
        moved = self._store.quarantine_move(
            confined.value,
            entry_id,
            ARTIFACT_VALIDATION_FAILED,
            now_utc=now,
            sha256=MISSING if digest is None else digest,
        )
        if isinstance(moved, Failure):
            return None
        for path in stale:
            projection = confine_candidate_path(
                self._store.artifacts_root,
                path.relative_to(self._store.artifacts_root).as_posix(),
                now_utc=now,
            )
            if isinstance(projection, Success):
                self._store.quarantine_move(
                    projection.value,
                    entry_id,
                    ARTIFACT_VALIDATION_FAILED,
                    now_utc=now,
                )
        return entry_id

    def _quarantine_orphan_file(self, relative: str, now: datetime) -> str | None:
        """The Task 6 RV-9 file-map correction: a file under ``objects/`` whose
        ordinary name the candidate grammar refuses, or whose leaf resembles a
        content address at no canonical layout (misplaced content), is confined
        by the orphan confinement -- every physical rule kept -- and moved by the
        store's ``quarantine_orphan`` into the entry keyed by the identity derived
        from its confined relative path (derived only once the confinement, whose
        grammar requires UTF-8, has admitted the path), at that very path under
        the entry (plan 6.2), with no digest claim; the entry id once the bytes
        moved, ``None`` when either refusal leaves the file where the sweep found
        it."""
        confined = confine_orphan_path(
            self._store.artifacts_root, relative, now_utc=now
        )
        if isinstance(confined, Failure):
            return None
        entry_id = _unregistered_entry_id(relative)
        moved = self._store.quarantine_orphan(
            confined.value, entry_id, ARTIFACT_VALIDATION_FAILED, now_utc=now
        )
        if isinstance(moved, Failure):
            return None
        return entry_id

    def _registered_references(self, digest: str) -> Result[tuple[ArtifactRef, ...]]:
        """The ``artifact_refs`` rows registering ``digest`` (RV-9), read in a
        transaction of their own and released before any byte moves."""
        transaction = self._factory()
        try:
            return transaction.artifact_refs.list_by_content_hash(digest)
        finally:
            transaction.rollback()

    def _projections_by_hash(self) -> dict[str, list[Path]]:
        """The readable ``manifests/*.json`` projections by the content hash each
        names: never evidence of registration (plan 6.2), only the files that
        travel with a quarantined blob of that digest."""
        found: dict[str, list[Path]] = {}
        manifests_root = self._store.manifests_root
        if not manifests_root.is_dir():
            return found
        for path in sorted(manifests_root.glob("*.json")):
            if not path.is_file() or path.is_symlink():
                continue
            try:
                with path.open("rb") as handle:
                    manifest = ArtifactManifest.model_validate_json(
                        handle.read(_MAX_PROJECTION_BYTES)
                    )
            except (OSError, ValueError):
                continue
            found.setdefault(manifest.content_hash, []).append(path)
        return found

    # -- RV-17 and the summary ---------------------------------------------------------

    def _report_overdue_quarantine(self) -> Failure | None:
        now = self._clock.now_utc()
        bound = timedelta(seconds=QUARANTINE_OVERDUE_SECONDS)
        for entry in self._store.quarantine_entries():
            instant = entry.quarantined_at_utc
            if instant is None or now - instant <= bound:
                continue
            diagnostic = artifact_diagnostic(
                ARTIFACT_QUARANTINE_OVERDUE,
                message="a quarantine entry is older than the compiled retention bound",
                now_utc=now,
            )
            transaction = self._factory()
            try:
                recorded = transaction.diagnostics_writer.record(diagnostic)
                if isinstance(recorded, Failure):
                    return recorded
                audited = self._auditor.append(
                    transaction,
                    AuditFact(
                        action="QUARANTINE_OVERDUE",
                        outcome="FAILED",
                        correlation_id=entry.entry_id,
                        details={
                            "age_seconds": int((now - instant).total_seconds()),
                            "files": len(entry.files),
                        },
                    ),
                )
                if isinstance(audited, Failure):
                    return audited
                committed = transaction.commit()
                if isinstance(committed, Failure):
                    return committed
            finally:
                transaction.rollback()
            self._counts.overdue += 1
        return None

    def _summary(self) -> Failure | None:
        report = self._counts.report()
        return self._audit_alone(
            "RECONCILIATION_FINALIZATION_RESUMED",
            "SUCCEEDED",
            "reconcile-finalization",
            {
                "resumed": report.resumed,
                "deferred": report.deferred,
                "registered": report.registered,
                "abandoned": report.abandoned,
                "quarantined": report.quarantined,
                "overdue": report.overdue,
                "closed_roots": report.closed_roots,
                "changes": report.changes,
            },
        )

    def _audit_alone(
        self,
        action: str,
        outcome: str,
        correlation_id: str,
        details: dict[str, DiagnosticDetailValue],
    ) -> Failure | None:
        transaction = self._factory()
        try:
            audited = self._auditor.append(
                transaction,
                AuditFact(
                    action=action,
                    outcome=outcome,  # type: ignore[arg-type]
                    correlation_id=correlation_id,
                    details=details,
                ),
            )
            if isinstance(audited, Failure):
                return audited
            committed = transaction.commit()
            if isinstance(committed, Failure):
                return committed
        finally:
            transaction.rollback()
        return None


def _request_of(
    facts: ResultRecoveryFacts,
    run: EngineRunRecord,
    invocation: CommandInvocationRecord,
    group: tuple[CandidateArtifact, ...],
) -> ResultFinalizationRequest | Failure:
    """The RESULT request a validated temporary manifest yields (29.3), at the
    current run and invocation revisions."""
    owner = group[0].owner
    ids = tuple(sorted(candidate.candidate_artifact_id for candidate in group))
    try:
        return ResultFinalizationRequest.model_validate(
            {
                "schema_version": "1.0.0",
                "finalization_purpose": "RESULT",
                "owner": owner,
                "experiment_id": facts.experiment_id,
                "run_id": facts.run_id,
                "run_invocation_id": facts.run_invocation_id,
                "expected_run_revision": run.revision,
                "expected_invocation_revision": invocation.revision,
                "attempt_token_hash": facts.attempt_token_hash,
                "source_adapter_result_manifest_hash": (
                    facts.source_adapter_result_manifest_hash
                ),
                "sanitized_adapter_result_manifest_hash": (
                    facts.sanitized_adapter_result_manifest_hash
                ),
                "semantic_status": facts.semantic_status,
                "candidate_artifact_ids": ids,
                "candidate_set_hash": candidate_set_hash_for(ids),
                "finalization_timeout_seconds": facts.finalization_timeout_seconds,
                "idempotency_key": finalization_identity(
                    "RESULT",
                    run_id=facts.run_id,
                    run_invocation_id=facts.run_invocation_id,
                    attempt_token_hash=facts.attempt_token_hash,
                    source_adapter_result_manifest_hash=(
                        facts.source_adapter_result_manifest_hash
                    ),
                    sanitized_adapter_result_manifest_hash=(
                        facts.sanitized_adapter_result_manifest_hash
                    ),
                ),
            }
        )
    except ValueError as error:
        return artifact_failure(
            ARTIFACT_RESULT_MANIFEST_INVALID,
            message=f"the recovered result facts form no RESULT request: {error}",
            invocation_id=invocation.invocation_id,
            run_id=run.run_id,
            experiment_id=run.experiment_id,
            now_utc=run.updated_at_utc,
        )


def reconcile_finalization(
    *,
    unit_of_work_factory: UnitOfWorkFactory,
    store: ArtifactStore,
    hasher: ContentHasher,
    registrar: PurposeRegistrar,
    recovery_validator: ResultRecoveryValidator,
    auditor: FinalizationAuditor,
    clock: Clock,
    runtime_root: Path,
    command_roots: CommandRootsLookup,
    token_material: TokenMaterialLookup,
    log: FinalizationLog | None = None,
) -> Result[FinalizationReconciliationReport]:
    """The artifact half of startup reconciliation (29.2 steps 4, 6, 7, 9); see
    the module docstring. Precondition owed by the caller: the single local
    reconciliation lease of 29.2 step 3 is held and normal scheduling is not yet
    permitted (29.2 step 10) -- a Stage 10 composition fact this function cannot
    verify. Idempotent: a second pass over the same state appends one summary
    row with ``changes == 0``."""
    if not isinstance(runtime_root, Path) or not runtime_root.is_absolute():
        raise ValueError("runtime_root must be an absolute Path")
    return _Reconciler(
        unit_of_work_factory=unit_of_work_factory,
        store=store,
        hasher=hasher,
        registrar=registrar,
        recovery_validator=recovery_validator,
        auditor=auditor,
        clock=clock,
        runtime_root=runtime_root,
        command_roots=command_roots,
        token_material=token_material,
        log=log,
    ).run()


def purge_quarantine(
    entry_id: str,
    correlation: str,
    *,
    store: ArtifactStore,
    unit_of_work_factory: UnitOfWorkFactory,
    auditor: FinalizationAuditor,
    clock: Clock,
) -> Result[None]:
    """RV-18 (29.5:2192): remove one quarantine entry's bytes with a
    ``RETENTION_DELETED`` fact; refused while any ``PREPARED`` or ``MOVED``
    journal names a candidate of the entry -- an entry keyed by a finalization
    whose journal is open, or by a candidate an open journal plans."""
    now = clock.now_utc()
    entries = {entry.entry_id: entry for entry in store.quarantine_entries()}
    entry = entries.get(entry_id)
    if entry is None:
        return artifact_failure(
            ARTIFACT_VALIDATION_FAILED,
            message="the quarantine entry does not exist",
            now_utc=now,
        )
    transaction = unit_of_work_factory()
    try:
        open_entries = transaction.finalization_journal.list_open()
    finally:
        transaction.rollback()
    if isinstance(open_entries, Failure):
        return open_entries
    for journal in open_entries.value:
        if journal.finalization_id == entry_id or entry_id in (
            journal.candidate_artifact_ids
        ):
            return Failure(
                outcome="FAILURE",
                diagnostics=(
                    artifact_diagnostic(
                        ARTIFACT_VALIDATION_FAILED,
                        message=(
                            "the quarantine entry is required by an active "
                            "finalization lease"
                        ),
                        now_utc=now,
                    ),
                ),
            )
    entry_root = store.quarantine_root / entry_id
    removed = 0
    for path in sorted(entry_root.rglob("*"), reverse=True):
        if path.is_symlink():
            continue
        try:
            if path.is_dir():
                path.rmdir()
            else:
                path.unlink()
                removed += 1
        except OSError:
            return artifact_failure(
                ARTIFACT_MOVE_FAILED,
                message="a quarantined file could not be removed",
                now_utc=now,
            )
    try:
        entry_root.rmdir()
    except OSError:
        pass
    transaction = unit_of_work_factory()
    try:
        audited = auditor.append(
            transaction,
            AuditFact(
                action="RETENTION_DELETED",
                outcome="SUCCEEDED",
                correlation_id=correlation,
                details={"entry_files": removed, "purge": True},
            ),
        )
        if isinstance(audited, Failure):
            return audited
        committed = transaction.commit()
        if isinstance(committed, Failure):
            return committed
    finally:
        transaction.rollback()
    return Success[None](outcome="SUCCESS", value=None)


__all__ = (
    "QUARANTINE_OVERDUE_SECONDS",
    "FinalizationReconciliationReport",
    "purge_quarantine",
    "reconcile_finalization",
)
