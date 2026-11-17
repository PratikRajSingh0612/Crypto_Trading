"""Ordered CLI startup: integrity gates, reconciliation and the scheduling barrier.

Stage 10 plan Task 2 (decisions D04, D05, D07, D08, D09, D10, D13 and D14; Matrix B
rows B05-B19 of plan section 4.2; specification 29.2). The composition root calls
these functions explicitly; importing the module reads no clock, opens nothing and
launches nothing. Every gate answers either its proven fact or a ``StartupRefusal``
carrying the gate, a bounded reason code, the CLI exit code (3 for dispatch
contention, 4 for every other startup refusal) and the underlying diagnostics; a
refusal is never an empty success.

The order (``run_startup``):

1. ``check_storage`` -- the explicit staging and artifact roots through the Task 1
   probe; nothing is created or discovered (B05).
2. ``check_schema_distribution`` -- the complete explicitly supplied source schema
   tree against the registry's rendered bytes: missing, extra, changed and
   physically unsafe entries (a reparse point, a second hard link, anything that is
   neither a plain directory nor a regular file) refuse; nothing is generated and no
   other location is consulted (B08, plan section 4.4).
3. ``open_current_database`` -- the normal opener, which admits an existing
   ``CURRENT`` database only and refuses absent, empty, behind, foreign, unknown and
   unversioned files without creating, stamping or migrating them (B06).
4. ``check_database`` -- the ``CURRENT`` revision rechecked over a fresh connection,
   then every consistency query; the eight Stage 8 findings and
   ``refs_without_manifest_file`` and ``success_without_manifest`` refuse when
   non-zero, while ``unmapped_finalizing`` and ``journal_open`` are classified as
   requiring the fenced recovery inventory (B07).
5. ``begin_reconciliation`` -- dispatch ownership, then the database gate again: the
   authority read before the mutex is never trusted after it (B09). Contention is
   exit 3; a changed authority releases the owner and refuses.
6. ``reconcile_startup`` -- under the nested reconciliation phase: durable inventory
   (``inventory_work``, B11), artifact ``inventory`` (B12), invocation
   reconciliation (B13), related-run reconciliation over a reread inventory
   (``reconcile_runs``, B14), artifact ``recover`` (B15), the injected requeue
   assessment over a fresh inventory (B16) and the artifact ``sweep`` (B17); then
   the consistency recheck and the open-journal reread. Unresolved work -- a live
   or deadline-pending child, a pending cleanup, a run awaiting purpose recovery,
   an open RESULT journal, the assessment's own fences -- is fenced; eligible slots
   never include a fenced one. Every artifact phase goes through the public
   ``reconcile_finalization`` entry point.
7. ``permit_scheduling`` -- requires the storage and schema facts, the still-active
   phase and the still-held owner; it ends the nested phase and returns the
   invocation-scoped ``SchedulingPermit``, which is valid only while the dispatch
   owner is held and is rebuilt from fresh facts by every startup (B18).
8. ``dispatch(permit)``; then the owner is released and the database closed in
   ``finally`` blocks on every path (B19).

B2: the closed audit vocabulary cannot record migration, process-reconciliation
or run-transition facts, so ``APPLICATION_AUDIT_UNAVAILABLE`` admits none of them
and each such mutation is refused before it starts -- ``maintain_database`` before
it opens a database for migration, ``reconcile_startup`` before invocation
reconciliation acts on any target, ``reconcile_runs`` before any run transition. A
capability that admits a mutation is injected explicitly; even then this module
performs no run transition (it fences the run). A refusal is a bounded diagnostic,
never an authoritative audit fact. Requeue assessment launches nothing, so the
durable attempt counts, original deadlines, retry decisions and not-before instants
are untouched.

Maintenance is separate (``maintain_database``): a ``CURRENT`` database is answered
as a replay before ``apply_migrations`` would run, an ``EMPTY``, ``BEHIND`` or
absent one migrates only through the packaged script directory, and no migration
script override exists anywhere in this module.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, fields, replace
from enum import StrEnum
from pathlib import Path
from typing import Any, Final, Literal, Protocol

from crypto_lab.artifacts.hashing import ContentHasher
from crypto_lab.artifacts.journal import FinalizationJournalEntry
from crypto_lab.artifacts.models import ArtifactFinalizationPurpose
from crypto_lab.artifacts.ports import (
    CommandRootsLookup,
    FinalizationAuditor,
    FinalizationLog,
    PurposeRegistrar,
    ResultRecoveryValidator,
    TokenMaterialLookup,
    UnitOfWorkFactory,
)
from crypto_lab.artifacts.recovery import (
    FinalizationReconciliationReport,
    reconcile_finalization,
)
from crypto_lab.artifacts.store import ArtifactStore
from crypto_lab.cli.runtime import (
    DispatchOwner,
    DispatchRefusal,
    DispatchRefusalReason,
    DispatchRelease,
    StorageProbe,
    StorageRefusal,
    VolumeInspector,
    acquire_dispatch_owner,
    probe_storage,
    release_dispatch_owner,
)
from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.diagnostics import Diagnostic
from crypto_lab.domain.engine_run import EngineRunRecord
from crypto_lab.domain.lifecycle import (
    TERMINAL_COMMAND_INVOCATION_STATES,
    TERMINAL_ENGINE_RUN_STATES,
    CommandInvocationState,
    CommandKind,
    EngineRunState,
)
from crypto_lab.domain.ports import Clock
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.experiments.application_ports import (
    ApplicationQueryPort,
    DurableWorkInventory,
    RequeueAssessment,
    RequeueAssessmentPort,
)
from crypto_lab.persistence.database import (
    ConsistencyReport,
    RevisionPolicy,
    SqliteDatabase,
)
from crypto_lab.persistence.diagnostics import MIGRATION_MISMATCH, persistence_failure
from crypto_lab.persistence.migration_runner import (
    RevisionState,
    apply_migrations,
    check_revision,
    expected_head,
    open_database,
    open_for_migration,
)
from crypto_lab.process_supervision.models import ReconciliationReport
from crypto_lab.process_supervision.ports import ReconciliationSource
from crypto_lab.schema_registry import render_schema_files

__all__ = [
    "APPLICATION_AUDIT_UNAVAILABLE",
    "EXIT_CONTENDED",
    "EXIT_STARTUP_REFUSED",
    "ApplicationAuditCapability",
    "ArtifactRecoveryPort",
    "ConsistencyTreatment",
    "DatabaseCheck",
    "FinalizationPhases",
    "InvocationRecovery",
    "InvocationRecoveryPort",
    "MaintenanceResult",
    "ReconciliationPhase",
    "RecoveryPhase",
    "RunReconciliation",
    "SchedulingPermit",
    "SchemaDistribution",
    "StartupComponents",
    "StartupDatabase",
    "StartupGate",
    "StartupMutation",
    "StartupPlan",
    "StartupReconciliation",
    "StartupRefusal",
    "begin_reconciliation",
    "check_database",
    "check_schema_distribution",
    "check_storage",
    "inventory_work",
    "maintain_database",
    "open_current_database",
    "permit_scheduling",
    "reconcile_runs",
    "reconcile_startup",
    "run_startup",
]

#: Plan section 3.4: dispatch contention, and every other startup refusal.
EXIT_CONTENDED: Final = 3
EXIT_STARTUP_REFUSED: Final = 4
#: Plan section 4.3: the closed artifact phases, in startup order.
type RecoveryPhase = Literal["inventory", "recover", "sweep"]
#: Plan section 4.2 (B07): the two findings that enter the fenced recovery
#: inventory; every other consistency field refuses dispatch when non-zero.
_RECOVERY_INVENTORY_FIELDS: Final = frozenset({"unmapped_finalizing", "journal_open"})
_CONSISTENCY_FIELDS: Final[tuple[str, ...]] = tuple(
    item.name for item in fields(ConsistencyReport)
)
#: The selected schema-location class: the explicit source tree (plan section 4.4).
_SCHEMA_LOCATION: Final = "EXPLICIT_SOURCE_TREE"
#: Win32 attribute bits and POSIX mode bits, spelled locally.
_FILE_ATTRIBUTE_DIRECTORY: Final = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT: Final = 0x00000400
_S_IFMT: Final = 0o170000
_S_IFREG: Final = 0o100000
_B2_CATEGORY: Final = "B2_APPLICATION_AUDIT_UNAVAILABLE"
_REVISION_DETAILS: Final = ("state", "current_revision", "expected_head")
_ACTIVE_RUN_STATES: Final = frozenset(
    {EngineRunState.VALIDATING, EngineRunState.STARTING, EngineRunState.RUNNING}
)
_PRELAUNCH_RUN_STATES: Final = frozenset({EngineRunState.PENDING, EngineRunState.READY})
_MIGRATABLE: Final = frozenset({RevisionState.EMPTY.value, RevisionState.BEHIND.value})

type _DetailValue = int | str
type _Details = Mapping[str, _DetailValue]


# --------------------------------------------------------------------------
# Refusals
# --------------------------------------------------------------------------


class StartupGate(StrEnum):
    """The Matrix B gate that refused."""

    STORAGE = "STORAGE"
    SCHEMA_DISTRIBUTION = "SCHEMA_DISTRIBUTION"
    DATABASE = "DATABASE"
    DISPATCH_OWNERSHIP = "DISPATCH_OWNERSHIP"
    DURABLE_INVENTORY = "DURABLE_INVENTORY"
    ARTIFACT_INVENTORY = "ARTIFACT_INVENTORY"
    INVOCATION_RECONCILIATION = "INVOCATION_RECONCILIATION"
    RUN_RECONCILIATION = "RUN_RECONCILIATION"
    ARTIFACT_RECOVERY = "ARTIFACT_RECOVERY"
    REQUEUE_ASSESSMENT = "REQUEUE_ASSESSMENT"
    ARTIFACT_SWEEP = "ARTIFACT_SWEEP"
    CONSISTENCY_RECHECK = "CONSISTENCY_RECHECK"
    AUDIT_CAPABILITY = "AUDIT_CAPABILITY"
    SCHEDULING_BARRIER = "SCHEDULING_BARRIER"
    MAINTENANCE = "MAINTENANCE"


@dataclass(frozen=True, slots=True)
class StartupRefusal:
    """One refused gate: a bounded reason code and details, never a row dump."""

    gate: StartupGate
    reason: str
    exit_code: int = EXIT_STARTUP_REFUSED
    details: tuple[tuple[str, _DetailValue], ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()


def _refuse(
    gate: StartupGate,
    reason: str,
    *,
    details: _Details | None = None,
    failure: Failure | None = None,
    exit_code: int = EXIT_STARTUP_REFUSED,
) -> StartupRefusal:
    return StartupRefusal(
        gate=gate,
        reason=reason,
        exit_code=exit_code,
        details=tuple((details or {}).items()),
        diagnostics=() if failure is None else failure.diagnostics,
    )


def _bounded(diagnostic: Diagnostic, keys: tuple[str, ...]) -> dict[str, _DetailValue]:
    """The named scalar details of one diagnostic, and nothing else."""
    found: dict[str, _DetailValue] = {}
    for key in keys:
        value = diagnostic.details.get(key)
        if isinstance(value, int | str) and not isinstance(value, bool):
            found[key] = value
    return found


# --------------------------------------------------------------------------
# B2: the required application audit capability
# --------------------------------------------------------------------------


class StartupMutation(StrEnum):
    """The startup mutations whose required application audit facts B2 lacks."""

    MIGRATION = "MIGRATION"
    PROCESS_RECONCILIATION = "PROCESS_RECONCILIATION"
    RUN_TRANSITION = "RUN_TRANSITION"


class ApplicationAuditCapability(Protocol):
    """Whether the authoritative audit can record a mutation's required facts."""

    def admits(self, mutation: StartupMutation) -> bool:
        """``True`` only when the mutation's facts are faithfully recordable."""


class _ApplicationAuditUnavailable:
    """B2: the closed audit vocabulary records none of the startup mutations."""

    __slots__ = ()

    def admits(self, mutation: StartupMutation) -> bool:
        del mutation
        return False


APPLICATION_AUDIT_UNAVAILABLE: Final[ApplicationAuditCapability] = (
    _ApplicationAuditUnavailable()
)


def _audit_refusal(mutation: StartupMutation, details: _Details) -> StartupRefusal:
    return _refuse(
        StartupGate.AUDIT_CAPABILITY,
        mutation.value,
        details={"corrective_category": _B2_CATEGORY, **details},
    )


# --------------------------------------------------------------------------
# B05 storage and B08 schema distribution
# --------------------------------------------------------------------------


def check_storage(
    staging_root: Path,
    artifact_root: Path,
    *,
    inspector: VolumeInspector | None = None,
) -> StorageProbe | StartupRefusal:
    """The two explicit run-storage roots through the Task 1 probe (B05)."""
    probed = probe_storage(
        staging_root=staging_root, artifact_root=artifact_root, inspector=inspector
    )
    if isinstance(probed, StorageRefusal):
        details: dict[str, _DetailValue] = {"role": probed.role}
        if probed.winerror is not None:
            details["winerror"] = probed.winerror
        return _refuse(StartupGate.STORAGE, probed.reason.value, details=details)
    return probed


@dataclass(frozen=True, slots=True, kw_only=True)
class SchemaDistribution:
    """The selected source schema tree equals the registry's rendered bytes."""

    root: Path
    registry_count: int
    location: str = _SCHEMA_LOCATION


def _schema_root_refusal(root: Path) -> StartupRefusal | None:
    def refused(reason: str) -> StartupRefusal:
        return _refuse(StartupGate.SCHEMA_DISTRIBUTION, reason)

    if not root.is_absolute():
        return refused("ROOT_NOT_ABSOLUTE")
    try:
        status = root.lstat()
    except FileNotFoundError:
        return refused("ROOT_ABSENT")
    except OSError:
        return refused("ROOT_UNREADABLE")
    if status.st_file_attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        return refused("ROOT_UNSAFE")
    if not status.st_file_attributes & _FILE_ATTRIBUTE_DIRECTORY:
        return refused("ROOT_NOT_A_DIRECTORY")
    return None


def _schema_entries(root: Path) -> tuple[dict[str, Path], list[str]]:
    """Every regular file under ``root`` by relative path, and every unsafe entry;
    a reparse point is reported and never followed."""
    files: dict[str, Path] = {}
    unsafe: list[str] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            children = sorted(directory.iterdir())
        except OSError:
            unsafe.append(directory.relative_to(root).as_posix())
            continue
        for child in children:
            relative = child.relative_to(root).as_posix()
            try:
                status = child.lstat()
            except OSError:
                unsafe.append(relative)
                continue
            if status.st_file_attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
                unsafe.append(relative)
            elif status.st_file_attributes & _FILE_ATTRIBUTE_DIRECTORY:
                pending.append(child)
            elif (status.st_mode & _S_IFMT) != _S_IFREG or status.st_nlink != 1:
                unsafe.append(relative)
            else:
                files[relative] = child
    return files, sorted(unsafe)


def _read_bounded(path: Path, limit: int) -> bytes | None:
    try:
        with path.open("rb") as handle:
            return handle.read(limit + 1)
    except OSError:
        return None


def check_schema_distribution(schema_root: Path) -> SchemaDistribution | StartupRefusal:
    """Compare the complete explicitly supplied schema tree with the registry (B08).

    ``schema_root`` is the caller's selection (the invocation base's ``schemas``
    directory, plan section 4.4); no other location is searched and nothing is
    written. Missing, extra, changed and physically unsafe entries are counted, and
    any of them refuses with the counts and the first path of each kind.
    """
    refusal = _schema_root_refusal(schema_root)
    if refusal is not None:
        return refusal
    expected = {
        relative.as_posix(): contents
        for relative, contents in render_schema_files().items()
    }
    found, unsafe = _schema_entries(schema_root)
    unsafe_paths = set(unsafe)
    missing = sorted(set(expected) - set(found) - unsafe_paths)
    extra = sorted(set(found) - set(expected))
    changed: list[str] = []
    for relative in sorted(set(found) & set(expected)):
        contents = expected[relative]
        observed = _read_bounded(found[relative], len(contents))
        if observed is None:
            unsafe.append(relative)
        elif observed != contents:
            changed.append(relative)
    unsafe = sorted(set(unsafe))
    kinds = (
        ("missing", missing),
        ("extra", extra),
        ("changed", changed),
        ("unsafe", unsafe),
    )
    if any(paths for _, paths in kinds):
        details: dict[str, _DetailValue] = {name: len(paths) for name, paths in kinds}
        for name, paths in kinds:
            if paths:
                details[f"first_{name}"] = paths[0]
        return _refuse(
            StartupGate.SCHEMA_DISTRIBUTION, "SCHEMA_MISMATCH", details=details
        )
    return SchemaDistribution(root=schema_root, registry_count=len(expected))


# --------------------------------------------------------------------------
# B06 opening, maintenance and B07 the database gate
# --------------------------------------------------------------------------


class StartupDatabase(Protocol):
    """The database facts startup reads; ``SqliteDatabase`` implements it."""

    @property
    def path(self) -> Path:
        """The absolute database path."""

    def verify_revision(self, revision_policy: RevisionPolicy) -> Result[None]:
        """Run a revision policy over a fresh connection."""

    def read_consistency(self) -> Result[ConsistencyReport]:
        """The twelve consistency counts, or a ``Failure``."""


def open_current_database(
    path: Path, *, busy_timeout_ms: int, clock: Clock
) -> SqliteDatabase | StartupRefusal:
    """The normal opener (B06): an existing ``CURRENT`` database or a refusal;
    nothing is created, stamped or migrated."""
    opened = open_database(path, busy_timeout_ms=busy_timeout_ms, clock=clock)
    if isinstance(opened, Failure):
        diagnostic = opened.diagnostics[0]
        return _refuse(
            StartupGate.DATABASE,
            diagnostic.error_code,
            details=_bounded(diagnostic, _REVISION_DETAILS),
            failure=opened,
        )
    return opened.value


@dataclass(frozen=True, slots=True, kw_only=True)
class MaintenanceResult:
    """Explicit maintenance: a ``CURRENT`` replay or a completed migration."""

    state: str
    replayed: bool
    from_state: str
    revision: str


def maintain_database(
    path: Path,
    *,
    busy_timeout_ms: int,
    clock: Clock,
    audit: ApplicationAuditCapability = APPLICATION_AUDIT_UNAVAILABLE,
) -> MaintenanceResult | StartupRefusal:
    """Explicit maintenance, separate from normal opening.

    A ``CURRENT`` database is answered as a replay before ``apply_migrations``
    would run. An absent, ``EMPTY`` or ``BEHIND`` database needs a migration, whose
    required audit facts B2 lacks: unless ``audit`` admits it, the refusal comes
    before anything opens the file for migration. An admitted migration runs only
    through the packaged script directory. Every other state is refused.
    """
    if path.is_absolute() and path.parent.is_dir() and not path.exists():
        from_state = "ABSENT"
    else:
        opened = open_database(path, busy_timeout_ms=busy_timeout_ms, clock=clock)
        if isinstance(opened, Success):
            opened.value.close()
            return MaintenanceResult(
                state=RevisionState.CURRENT.value,
                replayed=True,
                from_state=RevisionState.CURRENT.value,
                revision=expected_head(),
            )
        diagnostic = opened.diagnostics[0]
        state = diagnostic.details.get("state")
        if (
            diagnostic.error_code != MIGRATION_MISMATCH
            or not isinstance(state, str)
            or state not in _MIGRATABLE
        ):
            return _refuse(
                StartupGate.MAINTENANCE,
                diagnostic.error_code,
                details=_bounded(diagnostic, _REVISION_DETAILS),
                failure=opened,
            )
        from_state = state
    if not audit.admits(StartupMutation.MIGRATION):
        return _audit_refusal(StartupMutation.MIGRATION, {"state": from_state})
    migrating = open_for_migration(path, busy_timeout_ms=busy_timeout_ms, clock=clock)
    if isinstance(migrating, Failure):
        return _refuse(
            StartupGate.MAINTENANCE,
            migrating.diagnostics[0].error_code,
            failure=migrating,
        )
    database = migrating.value
    try:
        applied = apply_migrations(database)
    finally:
        database.close()
    if isinstance(applied, Failure):
        return _refuse(
            StartupGate.MAINTENANCE, applied.diagnostics[0].error_code, failure=applied
        )
    report = applied.value
    if report.state is not RevisionState.CURRENT:
        return _refuse(
            StartupGate.MAINTENANCE,
            "MIGRATION_INCOMPLETE",
            details={"state": report.state.value},
        )
    return MaintenanceResult(
        state=report.state.value,
        replayed=False,
        from_state=from_state,
        revision=report.expected_head,
    )


class ConsistencyTreatment(StrEnum):
    """How a non-zero consistency field is treated (B07)."""

    REFUSE_DISPATCH = "REFUSE_DISPATCH"
    FENCED_RECOVERY_INVENTORY = "FENCED_RECOVERY_INVENTORY"


@dataclass(frozen=True, slots=True, kw_only=True)
class DatabaseCheck:
    """A ``CURRENT`` database whose twelve counts were all read and classified."""

    report: ConsistencyReport
    classification: tuple[tuple[str, ConsistencyTreatment], ...]
    recovery_required: frozenset[str]


def _current_revision_policy(clock: Clock) -> Callable[[Any], Result[None]]:
    """The ``CURRENT``-only revision policy, read over the caller's connection."""

    def policy(connection: Any) -> Result[None]:
        report = check_revision(connection)
        if report.state is RevisionState.CURRENT:
            return Success[None](outcome="SUCCESS", value=None)
        details: dict[str, _DetailValue] = {
            "operation": "startup",
            "state": report.state.value,
            "expected_head": report.expected_head,
        }
        if isinstance(report.current_revision, str):
            details["current_revision"] = report.current_revision
        return persistence_failure(
            MIGRATION_MISMATCH,
            message=f"database revision state is {report.state.value}; "
            "a current database is required",
            clock=clock,
            details=details,
        )

    return policy


def check_database(
    database: StartupDatabase, *, clock: Clock
) -> DatabaseCheck | StartupRefusal:
    """The B07 gate: the ``CURRENT`` revision, then every consistency query.

    A non-current or unreadable revision, a failed or malformed consistency read
    and any non-zero refusing field each refuse; ``journal_open`` and
    ``unmapped_finalizing`` pass, classified as requiring the fenced recovery
    inventory. The counts are reported, never the rows.
    """
    revision = database.verify_revision(_current_revision_policy(clock))
    if isinstance(revision, Failure):
        diagnostic = revision.diagnostics[0]
        reason = (
            "REVISION_NOT_CURRENT"
            if diagnostic.error_code == MIGRATION_MISMATCH
            else "REVISION_UNREADABLE"
        )
        return _refuse(
            StartupGate.DATABASE,
            reason,
            details=_bounded(diagnostic, _REVISION_DETAILS),
            failure=revision,
        )
    read = database.read_consistency()
    if isinstance(read, Failure):
        return _refuse(StartupGate.DATABASE, "CONSISTENCY_UNREADABLE", failure=read)
    report = read.value
    if not isinstance(report, ConsistencyReport):
        return _refuse(StartupGate.DATABASE, "CONSISTENCY_MALFORMED")
    counts: dict[str, int] = {}
    for name in _CONSISTENCY_FIELDS:
        count = getattr(report, name)
        if type(count) is not int or count < 0:
            return _refuse(
                StartupGate.DATABASE, "CONSISTENCY_MALFORMED", details={"field": name}
            )
        counts[name] = count
    classification = tuple(
        (
            name,
            ConsistencyTreatment.FENCED_RECOVERY_INVENTORY
            if name in _RECOVERY_INVENTORY_FIELDS
            else ConsistencyTreatment.REFUSE_DISPATCH,
        )
        for name in _CONSISTENCY_FIELDS
    )
    findings: dict[str, _DetailValue] = {
        name: counts[name]
        for name, treatment in classification
        if treatment is ConsistencyTreatment.REFUSE_DISPATCH and counts[name] != 0
    }
    if findings:
        return _refuse(StartupGate.DATABASE, "CONSISTENCY_FINDINGS", details=findings)
    return DatabaseCheck(
        report=report,
        classification=classification,
        recovery_required=frozenset(
            name for name in _RECOVERY_INVENTORY_FIELDS if counts[name] != 0
        ),
    )


# --------------------------------------------------------------------------
# B09 ownership and the nested reconciliation phase
# --------------------------------------------------------------------------


class ReconciliationPhase:
    """The nested reconciliation phase under one held dispatch owner.

    ``end`` closes the phase while the owner stays held (before scheduling);
    ``close`` closes it and releases the owner, idempotently.
    """

    __slots__ = ("_active", "_clock", "_database", "_owner", "_release", "check")

    def __init__(
        self,
        *,
        database: StartupDatabase,
        owner: DispatchOwner,
        release: Callable[[DispatchOwner], DispatchRelease],
        check: DatabaseCheck,
        clock: Clock,
    ) -> None:
        self._database = database
        self._owner = owner
        self._release = release
        self._clock = clock
        self._active = True
        self.check = check

    @property
    def database(self) -> StartupDatabase:
        return self._database

    @property
    def owner(self) -> DispatchOwner:
        return self._owner

    @property
    def clock(self) -> Clock:
        return self._clock

    @property
    def active(self) -> bool:
        return self._active

    def end(self) -> None:
        self._active = False

    def close(self) -> DispatchRelease:
        self._active = False
        return self._release(self._owner)


def begin_reconciliation(
    database: StartupDatabase,
    *,
    clock: Clock,
    acquire: Callable[[Path], DispatchOwner | DispatchRefusal] = acquire_dispatch_owner,
    release: Callable[[DispatchOwner], DispatchRelease] = release_dispatch_owner,
) -> ReconciliationPhase | StartupRefusal:
    """Take dispatch ownership, then read the database authority afresh (B09).

    Contention is exit 3 and no recovery; a refused acquisition is exit 4; a
    changed authority releases the owner before refusing. Abandoned ownership is
    admitted -- the complete reconciliation that follows is what it demands.
    """
    owned = acquire(database.path)
    if isinstance(owned, DispatchRefusal):
        if owned.reason is DispatchRefusalReason.CONTENDED:
            return _refuse(
                StartupGate.DISPATCH_OWNERSHIP,
                owned.reason.value,
                exit_code=EXIT_CONTENDED,
            )
        details: dict[str, _DetailValue] = {}
        if owned.winerror is not None:
            details["winerror"] = owned.winerror
        return _refuse(
            StartupGate.DISPATCH_OWNERSHIP, owned.reason.value, details=details
        )
    try:
        fresh = check_database(database, clock=clock)
    except BaseException:
        release(owned)
        raise
    if isinstance(fresh, StartupRefusal):
        release(owned)
        return replace(
            fresh,
            gate=StartupGate.DISPATCH_OWNERSHIP,
            reason="AUTHORITY_CHANGED",
            details=(("cause", fresh.reason), *fresh.details),
        )
    return ReconciliationPhase(
        database=database, owner=owned, release=release, check=fresh, clock=clock
    )


# --------------------------------------------------------------------------
# B11-B17: the reconciliation ports and their concrete public routes
# --------------------------------------------------------------------------


class ArtifactRecoveryPort(Protocol):
    """The artifact phases and the open-journal reread startup needs."""

    def reconcile(
        self, phase: RecoveryPhase
    ) -> Result[FinalizationReconciliationReport]:
        """One selected phase of the public reconciler."""

    def open_journals(self) -> Result[tuple[FinalizationJournalEntry, ...]]:
        """The open (``PREPARED`` or ``MOVED``) journals, read afresh."""


@dataclass(frozen=True, slots=True, kw_only=True)
class FinalizationPhases:
    """``ArtifactRecoveryPort`` through the public ``reconcile_finalization``."""

    unit_of_work_factory: UnitOfWorkFactory
    store: ArtifactStore
    hasher: ContentHasher
    registrar: PurposeRegistrar
    recovery_validator: ResultRecoveryValidator
    auditor: FinalizationAuditor
    clock: Clock
    runtime_root: Path
    command_roots: CommandRootsLookup
    token_material: TokenMaterialLookup
    log: FinalizationLog | None = None

    def reconcile(
        self, phase: RecoveryPhase
    ) -> Result[FinalizationReconciliationReport]:
        return reconcile_finalization(
            unit_of_work_factory=self.unit_of_work_factory,
            store=self.store,
            hasher=self.hasher,
            registrar=self.registrar,
            recovery_validator=self.recovery_validator,
            auditor=self.auditor,
            clock=self.clock,
            runtime_root=self.runtime_root,
            command_roots=self.command_roots,
            token_material=self.token_material,
            log=self.log,
            phase=phase,
        )

    def open_journals(self) -> Result[tuple[FinalizationJournalEntry, ...]]:
        transaction = self.unit_of_work_factory()
        try:
            return transaction.finalization_journal.list_open()
        finally:
            transaction.rollback()


class InvocationRecoveryPort(Protocol):
    """The fresh target listing and the invocation reconciliation pass."""

    def targets(self) -> Result[tuple[CommandInvocationRecord, ...]]:
        """The invocations a pass would act on, read afresh."""

    def reconcile(self) -> Result[ReconciliationReport]:
        """One pass of the existing invocation reconciler."""


@dataclass(frozen=True, slots=True, kw_only=True)
class InvocationRecovery:
    """``InvocationRecoveryPort`` over a reconciliation source and a bound pass of
    the existing ``reconcile_invocations`` the composition root supplies."""

    source: ReconciliationSource
    reconcile_invocations: Callable[[], Result[ReconciliationReport]]

    def targets(self) -> Result[tuple[CommandInvocationRecord, ...]]:
        return self.source.list_reconciliation_targets()

    def reconcile(self) -> Result[ReconciliationReport]:
        return self.reconcile_invocations()


@dataclass(frozen=True, slots=True, kw_only=True)
class StartupComponents:
    """The explicitly scoped dependencies of one reconciliation."""

    queries: ApplicationQueryPort
    invocations: InvocationRecoveryPort
    artifacts: ArtifactRecoveryPort
    requeue: RequeueAssessmentPort | None
    audit: ApplicationAuditCapability = APPLICATION_AUDIT_UNAVAILABLE


def inventory_work(
    queries: ApplicationQueryPort,
    *,
    gate: StartupGate = StartupGate.DURABLE_INVENTORY,
) -> DurableWorkInventory | StartupRefusal:
    """One complete detached inventory (B11), or a refusal: a failed read or an
    answer that is not an inventory never becomes an empty one."""
    answered: object = queries.work_inventory()
    if isinstance(answered, Failure):
        return _refuse(gate, "INVENTORY_UNREADABLE", failure=answered)
    if not isinstance(answered, Success) or not isinstance(
        answered.value, DurableWorkInventory
    ):
        return _refuse(gate, "INVENTORY_MALFORMED")
    return answered.value


@dataclass(frozen=True, slots=True, kw_only=True)
class RunReconciliation:
    """B14: runs fenced from scheduling, runs needing an application transition and
    prelaunch runs left to the requeue assessment, each in run-id order."""

    fenced_runs: tuple[str, ...]
    required_transitions: tuple[str, ...]
    prelaunch_runs: tuple[str, ...]


def _attempt_contradiction(inventory: DurableWorkInventory) -> StartupRefusal | None:
    """Latest-attempt agreement: per slot, distinct attempt numbers and at most one
    nonterminal attempt, which is the latest."""
    slots: dict[tuple[str, str], list[EngineRunRecord]] = {}
    for run in inventory.engine_runs:
        slots.setdefault((run.experiment_id, run.logical_slot_id), []).append(run)
    for (_, slot), runs in sorted(slots.items()):
        attempts = [run.attempt_number for run in runs]
        open_runs = [run for run in runs if run.state not in TERMINAL_ENGINE_RUN_STATES]
        if (
            len(set(attempts)) != len(attempts)
            or len(open_runs) > 1
            or (open_runs and open_runs[0].attempt_number != max(attempts))
        ):
            return _refuse(
                StartupGate.RUN_RECONCILIATION,
                "CONTRADICTORY_ATTEMPTS",
                details={"logical_slot_id": slot},
            )
    return None


def _awaits_purpose_recovery(
    run: EngineRunRecord, related: list[CommandInvocationRecord]
) -> bool:
    return run.state is EngineRunState.RUNNING and any(
        record.command_kind is CommandKind.RUN
        and record.state is CommandInvocationState.EXITED
        for record in related
    )


def reconcile_runs(
    inventory: DurableWorkInventory, *, audit: ApplicationAuditCapability
) -> RunReconciliation | StartupRefusal:
    """Related-run reconciliation over a reread inventory (B14).

    Contradictory attempts refuse. A run beside an unresolved invocation or a
    pending cleanup, and a ``RUNNING`` run whose run command is durably ``EXITED``
    (purpose recovery decides it), are fenced. An active run left with neither
    needs an application transition no supported audit records: B2 refuses it
    unless ``audit`` admits it, and even then it is fenced, never written. A lost
    exit never implies success or ``PROTOCOL_FAILED``.
    """
    contradiction = _attempt_contradiction(inventory)
    if contradiction is not None:
        return contradiction
    related: dict[str, list[CommandInvocationRecord]] = {}
    for record in inventory.command_invocations:
        run_id: object = record.run_id
        if isinstance(run_id, str):
            related.setdefault(run_id, []).append(record)
    fenced: set[str] = set()
    required: list[str] = []
    prelaunch: list[str] = []
    for run in inventory.engine_runs:
        records = related.get(run.run_id, [])
        unresolved = any(
            record.state not in TERMINAL_COMMAND_INVOCATION_STATES
            or not record.cleanup_complete
            for record in records
        )
        if run.state in TERMINAL_ENGINE_RUN_STATES:
            if unresolved:
                fenced.add(run.run_id)
        elif unresolved or _awaits_purpose_recovery(run, records):
            fenced.add(run.run_id)
        elif run.state in _PRELAUNCH_RUN_STATES:
            prelaunch.append(run.run_id)
        elif run.state in _ACTIVE_RUN_STATES:
            required.append(run.run_id)
    if required:
        if not audit.admits(StartupMutation.RUN_TRANSITION):
            return _audit_refusal(
                StartupMutation.RUN_TRANSITION,
                {"runs": len(required), "first_run_id": required[0]},
            )
        fenced.update(required)
    return RunReconciliation(
        fenced_runs=tuple(sorted(fenced)),
        required_transitions=tuple(sorted(required)),
        prelaunch_runs=tuple(sorted(prelaunch)),
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class StartupReconciliation:
    """The complete reconciliation of one startup, under its phase."""

    phase: ReconciliationPhase
    inventory: DurableWorkInventory
    artifact_reports: Mapping[str, FinalizationReconciliationReport]
    invocation_report: ReconciliationReport
    runs: RunReconciliation
    assessment: RequeueAssessment
    consistency: DatabaseCheck
    fenced_runs: tuple[str, ...]
    fenced_slots: tuple[str, ...]
    eligible_slots: tuple[str, ...]


def _artifact_phase(
    artifacts: ArtifactRecoveryPort, phase: RecoveryPhase, gate: StartupGate
) -> FinalizationReconciliationReport | StartupRefusal:
    answered: object = artifacts.reconcile(phase)
    if isinstance(answered, Failure):
        return _refuse(gate, "PHASE_FAILED", details={"phase": phase}, failure=answered)
    if not isinstance(answered, Success) or not isinstance(
        answered.value, FinalizationReconciliationReport
    ):
        return _refuse(gate, "PHASE_MALFORMED", details={"phase": phase})
    return answered.value


def _assess(
    components: StartupComponents, inventory: DurableWorkInventory
) -> RequeueAssessment | StartupRefusal:
    """B16: the injected assessment over the fresh inventory; it launches nothing."""
    gate = StartupGate.REQUEUE_ASSESSMENT
    if components.requeue is None:
        return _refuse(gate, "ASSESSMENT_MISSING")
    answered: object = components.requeue.assess_requeue(inventory)
    if isinstance(answered, Failure):
        return _refuse(gate, "ASSESSMENT_FAILED", failure=answered)
    if not isinstance(answered, Success) or not isinstance(
        answered.value, RequeueAssessment
    ):
        return _refuse(gate, "ASSESSMENT_MALFORMED")
    assessment = answered.value
    known = {
        slot.logical_slot_id
        for experiment in inventory.experiments
        for slot in experiment.spec.selected_engine_slots
    }
    named = set(assessment.eligible_slots) | set(assessment.fenced_slots)
    unknown = sorted(named - known)
    if unknown:
        return _refuse(
            gate,
            "ASSESSMENT_CONTRADICTS_INVENTORY",
            details={"logical_slot_id": unknown[0]},
        )
    return assessment


def _recheck(
    phase: ReconciliationPhase, artifacts: ArtifactRecoveryPort
) -> tuple[DatabaseCheck, tuple[FinalizationJournalEntry, ...]] | StartupRefusal:
    """Every consistency query again after recovery, then the open journals."""
    gate = StartupGate.CONSISTENCY_RECHECK
    check = check_database(phase.database, clock=phase.clock)
    if isinstance(check, StartupRefusal):
        return replace(check, gate=gate)
    if check.report.unmapped_finalizing != 0:
        return _refuse(
            gate,
            "RECOVERY_INCOMPLETE",
            details={"unmapped_finalizing": check.report.unmapped_finalizing},
        )
    journals: object = artifacts.open_journals()
    if isinstance(journals, Failure):
        return _refuse(gate, "JOURNALS_UNREADABLE", failure=journals)
    if not isinstance(journals, Success) or not isinstance(journals.value, tuple):
        return _refuse(gate, "JOURNALS_MALFORMED")
    entries: tuple[FinalizationJournalEntry, ...] = journals.value
    if len(entries) != check.report.journal_open:
        return _refuse(
            gate,
            "CONTRADICTORY_AUTHORITY",
            details={
                "journal_open": check.report.journal_open,
                "journals_read": len(entries),
            },
        )
    return check, entries


def reconcile_startup(
    phase: ReconciliationPhase, components: StartupComponents
) -> StartupReconciliation | StartupRefusal:
    """Matrix B rows B11-B17 in order, under the active nested phase.

    durable inventory -> artifact inventory -> invocation reconciliation ->
    related-run reconciliation -> purpose recovery -> requeue assessment -> orphan
    sweep -> consistency recheck. Each step reads its own fresh authority; the
    first refusal ends the reconciliation and nothing later runs.
    """
    if not phase.active:
        return _refuse(StartupGate.SCHEDULING_BARRIER, "PHASE_NOT_ACTIVE")
    inventory = inventory_work(components.queries)
    if isinstance(inventory, StartupRefusal):
        return inventory
    reports: dict[str, FinalizationReconciliationReport] = {}
    inventoried = _artifact_phase(
        components.artifacts, "inventory", StartupGate.ARTIFACT_INVENTORY
    )
    if isinstance(inventoried, StartupRefusal):
        return inventoried
    reports["inventory"] = inventoried
    targets = components.invocations.targets()
    if isinstance(targets, Failure):
        return _refuse(
            StartupGate.INVOCATION_RECONCILIATION,
            "TARGETS_UNREADABLE",
            failure=targets,
        )
    if targets.value and not components.audit.admits(
        StartupMutation.PROCESS_RECONCILIATION
    ):
        return _audit_refusal(
            StartupMutation.PROCESS_RECONCILIATION, {"targets": len(targets.value)}
        )
    invoked = components.invocations.reconcile()
    if isinstance(invoked, Failure):
        return _refuse(
            StartupGate.INVOCATION_RECONCILIATION,
            "RECONCILIATION_FAILED",
            failure=invoked,
        )
    reread = inventory_work(components.queries, gate=StartupGate.RUN_RECONCILIATION)
    if isinstance(reread, StartupRefusal):
        return reread
    runs = reconcile_runs(reread, audit=components.audit)
    if isinstance(runs, StartupRefusal):
        return runs
    recovered = _artifact_phase(
        components.artifacts, "recover", StartupGate.ARTIFACT_RECOVERY
    )
    if isinstance(recovered, StartupRefusal):
        return recovered
    reports["recover"] = recovered
    fresh = inventory_work(components.queries, gate=StartupGate.REQUEUE_ASSESSMENT)
    if isinstance(fresh, StartupRefusal):
        return fresh
    assessment = _assess(components, fresh)
    if isinstance(assessment, StartupRefusal):
        return assessment
    swept = _artifact_phase(components.artifacts, "sweep", StartupGate.ARTIFACT_SWEEP)
    if isinstance(swept, StartupRefusal):
        return swept
    reports["sweep"] = swept
    rechecked = _recheck(phase, components.artifacts)
    if isinstance(rechecked, StartupRefusal):
        return rechecked
    consistency, journals = rechecked
    settled = reconcile_runs(fresh, audit=components.audit)
    if isinstance(settled, StartupRefusal):
        return replace(settled, gate=StartupGate.CONSISTENCY_RECHECK)
    slot_of = {run.run_id: run.logical_slot_id for run in fresh.engine_runs}
    journal_runs = {
        str(entry.run_id)
        for entry in journals
        if entry.finalization_purpose is ArtifactFinalizationPurpose.RESULT
    }
    if not journal_runs <= set(slot_of):
        return _refuse(
            StartupGate.CONSISTENCY_RECHECK,
            "CONTRADICTORY_AUTHORITY",
            details={"journal_run_id": sorted(journal_runs - set(slot_of))[0]},
        )
    fenced_runs = tuple(sorted(set(settled.fenced_runs) | journal_runs))
    fenced_slots = tuple(
        sorted(set(assessment.fenced_slots) | {slot_of[run] for run in fenced_runs})
    )
    eligible_slots = tuple(
        slot for slot in assessment.eligible_slots if slot not in fenced_slots
    )
    return StartupReconciliation(
        phase=phase,
        inventory=fresh,
        artifact_reports=reports,
        invocation_report=invoked.value,
        runs=settled,
        assessment=assessment,
        consistency=consistency,
        fenced_runs=fenced_runs,
        fenced_slots=fenced_slots,
        eligible_slots=eligible_slots,
    )


# --------------------------------------------------------------------------
# B18 the scheduling barrier and the composed startup
# --------------------------------------------------------------------------


class SchedulingPermit:
    """The invocation-scoped permission to schedule (B18): built from one
    successful startup and valid only while its dispatch owner is held."""

    __slots__ = ("_owner", "reconciliation", "schema", "storage")

    def __init__(
        self,
        *,
        owner: DispatchOwner,
        reconciliation: StartupReconciliation,
        storage: StorageProbe,
        schema: SchemaDistribution,
    ) -> None:
        self._owner = owner
        self.reconciliation = reconciliation
        self.storage = storage
        self.schema = schema

    @property
    def valid(self) -> bool:
        return not self._owner.released

    @property
    def owner_identity(self) -> str:
        return self._owner.identity

    @property
    def eligible_slots(self) -> tuple[str, ...]:
        return self.reconciliation.eligible_slots

    @property
    def fenced_slots(self) -> tuple[str, ...]:
        return self.reconciliation.fenced_slots

    @property
    def fenced_runs(self) -> tuple[str, ...]:
        return self.reconciliation.fenced_runs


def permit_scheduling(
    phase: ReconciliationPhase,
    reconciliation: StartupReconciliation,
    *,
    storage: StorageProbe,
    schema: SchemaDistribution,
) -> SchedulingPermit | StartupRefusal:
    """End the nested reconciliation phase and permit scheduling (B18).

    Requires the proven storage and schema facts, the reconciliation of this very
    phase, the phase still active and its owner still held; the owner is retained
    by the permit. A phase that has ended, been closed or lost its owner is
    refused, so a permit is never issued twice from one reconciliation.
    """
    gate = StartupGate.SCHEDULING_BARRIER
    if not isinstance(storage, StorageProbe):
        return _refuse(gate, "STORAGE_NOT_PROVEN")
    if not isinstance(schema, SchemaDistribution):
        return _refuse(gate, "SCHEMA_NOT_PROVEN")
    if reconciliation.phase is not phase:
        return _refuse(gate, "RECONCILIATION_MISMATCH")
    if not phase.active:
        return _refuse(gate, "PHASE_NOT_ACTIVE")
    if phase.owner.released:
        return _refuse(gate, "OWNER_RELEASED")
    phase.end()
    return SchedulingPermit(
        owner=phase.owner,
        reconciliation=reconciliation,
        storage=storage,
        schema=schema,
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class StartupPlan:
    """The explicit inputs of one driving startup; nothing is read from ambient
    state. ``components`` builds the scoped dependencies over the opened database."""

    database_path: Path
    busy_timeout_ms: int
    schema_root: Path
    staging_root: Path
    artifact_root: Path
    clock: Clock
    components: Callable[[SqliteDatabase], StartupComponents]
    volume_inspector: VolumeInspector | None = None
    acquire: Callable[[Path], DispatchOwner | DispatchRefusal] = acquire_dispatch_owner
    release: Callable[[DispatchOwner], DispatchRelease] = release_dispatch_owner


def run_startup[T](
    plan: StartupPlan, *, dispatch: Callable[[SchedulingPermit], T]
) -> T | StartupRefusal:
    """The Matrix B order, then ``dispatch`` with the permit; see the module
    docstring. Every refusal dispatches nothing; the dispatch owner is released and
    the database closed on every path."""
    storage = check_storage(
        plan.staging_root, plan.artifact_root, inspector=plan.volume_inspector
    )
    if isinstance(storage, StartupRefusal):
        return storage
    schema = check_schema_distribution(plan.schema_root)
    if isinstance(schema, StartupRefusal):
        return schema
    database = open_current_database(
        plan.database_path, busy_timeout_ms=plan.busy_timeout_ms, clock=plan.clock
    )
    if isinstance(database, StartupRefusal):
        return database
    try:
        initial = check_database(database, clock=plan.clock)
        if isinstance(initial, StartupRefusal):
            return initial
        phase = begin_reconciliation(
            database, clock=plan.clock, acquire=plan.acquire, release=plan.release
        )
        if isinstance(phase, StartupRefusal):
            return phase
        try:
            reconciled = reconcile_startup(phase, plan.components(database))
            if isinstance(reconciled, StartupRefusal):
                return reconciled
            permit = permit_scheduling(
                phase, reconciled, storage=storage, schema=schema
            )
            if isinstance(permit, StartupRefusal):
                return permit
            return dispatch(permit)
        finally:
            phase.close()
    finally:
        database.close()
