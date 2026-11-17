"""Stage 10 plan Task 2 (U2): ordered CLI startup, reconciliation and the
scheduling barrier (Matrix B, plan section 4).

The initial RED of every selector here is the missing ``crypto_lab.cli.startup``
module. The tests then pin the Task 2 obligations:

- normal opening refuses absent, empty, behind, foreign, unknown and unversioned
  databases without creating, stamping or migrating them, while explicit
  maintenance replays ``CURRENT`` before ``apply_migrations`` and exposes no
  migration-script override;
- the database gate executes every consistency query and classifies all twelve
  fields: ten refuse dispatch when non-zero, ``journal_open`` and
  ``unmapped_finalizing`` require the fenced recovery inventory;
- the schema-distribution gate compares the explicitly supplied tree with the
  registry's rendered bytes and refuses missing, extra, changed and physically
  unsafe entries without generating anything;
- startup runs durable inventory, artifact inventory, invocation reconciliation,
  related-run reconciliation, purpose recovery, the injected requeue assessment
  and the orphan sweep in that order, rechecks consistency, and only then permits
  scheduling; every failure dispatches nothing, closes the database and releases
  dispatch ownership; the nested reconciliation phase ends before dispatch while
  the dispatch owner is retained;
- a second startup over the same state changes nothing and its phase summaries are
  distinguishable; an unavailable required application audit (B2) refuses before
  the unsupported migration, process or run mutation.

Declared readings, so nothing is inferred silently:

- The component doubles are structural: they prove ordering, gating and refusal,
  never that a production mutation is supported. The admitting audit capability
  used by two cases is such a double; B2 is not closed by this module.
- "The database is closed" is proved by an exclusive (share-none) open of the
  database file succeeding; its positive control is the same probe failing while
  the startup still holds the database inside ``dispatch``.
- The successful application-audit facet ``test_startup_application_facts_are_atomic``
  is B2-gated (authored at the D14 reinspection after integration; not part of this
  dispatch) and is absent here, not skipped.
"""

from __future__ import annotations

import _winapi
import inspect
import os
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Final

import pytest
from pydantic import InstanceOf
from sqlalchemy import event

from crypto_lab.artifacts.journal import FinalizationJournalEntry
from crypto_lab.artifacts.recovery import FinalizationReconciliationReport
from crypto_lab.cli import startup as startup_module
from crypto_lab.cli.runtime import (
    DispatchOwner,
    DispatchRefusal,
    DispatchRefusalReason,
    DispatchRelease,
    RuntimeWindowsError,
    StorageProbe,
    acquire_dispatch_owner,
    release_dispatch_owner,
)
from crypto_lab.cli.startup import (
    APPLICATION_AUDIT_UNAVAILABLE,
    ConsistencyTreatment,
    DatabaseCheck,
    FinalizationPhases,
    InvocationRecovery,
    MaintenanceResult,
    RunReconciliation,
    SchedulingPermit,
    SchemaDistribution,
    StartupComponents,
    StartupGate,
    StartupMutation,
    StartupPlan,
    StartupReconciliation,
    StartupRefusal,
    begin_reconciliation,
    check_database,
    check_schema_distribution,
    check_storage,
    inventory_work,
    maintain_database,
    open_current_database,
    permit_scheduling,
    reconcile_runs,
    reconcile_startup,
    run_startup,
)
from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.experiments.application_ports import (
    DurableWorkInventory,
    RequeueAssessment,
)
from crypto_lab.persistence import database as database_module
from crypto_lab.persistence.database import ConsistencyReport, SqliteDatabase
from crypto_lab.persistence.diagnostics import (
    MIGRATION_MISMATCH,
    STORAGE_UNAVAILABLE,
    persistence_failure,
)
from crypto_lab.persistence.migration_runner import (
    RevisionReport,
    RevisionState,
    apply_migrations,
    expected_head,
)
from crypto_lab.persistence.reconciliation_source import SqliteReconciliationSource
from crypto_lab.process_supervision.models import ReconciliationReport
from crypto_lab.schema_registry import SCHEMA_DEFINITIONS, render_schema_files
from doubles.artifacts import MemoryFinalizationHarness, sample_journal
from doubles.experiments import (
    INSTANT,
    INVOCATION_ID,
    OTHER_RUN_ID,
    RUN_ID,
    SLOT_A,
    SLOT_B,
    FixedClock,
    sample_experiment,
    sample_invocation,
    sample_run,
)
from persistence_support.harness import open_test_database, raw_connection

_C: Final = CommandInvocationState
_K: Final = CommandKind
_R: Final = EngineRunState
_E: Final = ExperimentState
_DATABASE_NAME: Final = "registry.sqlite3"
_SUPERVISOR: Final = "supervisor-startup-test"
_EXIT_CONTENDED: Final = 3
_EXIT_REFUSED: Final = 4
#: Plan section 4.2 (B07): the eight Stage 8 findings plus the two Stage 9 ones
#: refuse dispatch; the last two require the fenced recovery inventory.
_REFUSING_FIELDS: Final = (
    "dangling_diagnostic_references",
    "slot_identity_mismatches",
    "spec_projection_mismatches",
    "queued_without_snapshot",
    "causal_edge_mismatches",
    "unresolved_causal_references",
    "registry_projection_mismatches",
    "foreign_key_violations",
    "refs_without_manifest_file",
    "success_without_manifest",
)
_RECOVERY_FIELDS: Final = ("unmapped_finalizing", "journal_open")
_CLEAN: Final = ConsistencyReport(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
_RENDERED: dict[PurePosixPath, bytes] = {}


def _rendered() -> dict[PurePosixPath, bytes]:
    if not _RENDERED:
        _RENDERED.update(render_schema_files())
    return _RENDERED


# --------------------------------------------------------------------------
# Probes and fixtures
# --------------------------------------------------------------------------


def _no_open_handles(path: Path) -> bool:
    """An exclusive open succeeds only when no other handle holds the file."""
    try:
        handle = _winapi.CreateFile(
            str(path),
            _winapi.GENERIC_READ,
            0,
            _winapi.NULL,
            _winapi.OPEN_EXISTING,
            0,
            _winapi.NULL,
        )
    except OSError:
        return False
    _winapi.CloseHandle(handle)
    return True


class _FixedNtfs:
    """A ``VolumeInspector`` answering one fixed NTFS volume."""

    def volume_root(self, path: Path) -> str:
        del path
        return "C:\\"

    def drive_type(self, volume_root: str) -> int:
        del volume_root
        return 3

    def volume_identity(self, volume_root: str) -> tuple[int, str]:
        del volume_root
        return 0x5EED, "NTFS"


def _write_schema_tree(root: Path) -> None:
    for relative, contents in _rendered().items():
        target = root.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(contents)


def _tree_snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _migrated(tmp_path: Path) -> Path:
    database = open_test_database(tmp_path, clock=FixedClock(INSTANT))
    database.close()
    return tmp_path / _DATABASE_NAME


def _raw_scalar(path: Path, statement: str) -> object:
    connection = raw_connection(path)
    try:
        row = connection.execute(statement).fetchone()
    finally:
        connection.close()
    return None if row is None else row[0]


def _raw_execute(path: Path, *statements: str) -> None:
    connection = raw_connection(path)
    try:
        for statement in statements:
            connection.execute(statement)
    finally:
        connection.close()


def _empty_report() -> Success[FinalizationReconciliationReport]:
    report = FinalizationReconciliationReport(
        resumed=0,
        deferred=0,
        registered=0,
        abandoned=0,
        quarantined=0,
        overdue=0,
        closed_roots=0,
        changes=0,
    )
    return Success[InstanceOf[FinalizationReconciliationReport]](
        outcome="SUCCESS", value=report
    )


def _failure(operation: str) -> Failure:
    return persistence_failure(
        STORAGE_UNAVAILABLE,
        message=f"{operation} was refused",
        clock=FixedClock(INSTANT),
        details={"operation": operation},
    )


def _inventory(
    *,
    runs: tuple[Any, ...] = (),
    invocations: tuple[CommandInvocationRecord, ...] = (),
) -> DurableWorkInventory:
    experiments = (sample_experiment(_E.RUNNING),) if runs else ()
    return DurableWorkInventory(
        experiments=experiments,
        engine_runs=tuple(sorted(runs, key=lambda run: run.run_id)),
        command_invocations=tuple(
            sorted(invocations, key=lambda record: record.invocation_id)
        ),
        retry_decisions=(),
    )


def _cleaned(record: CommandInvocationRecord) -> CommandInvocationRecord:
    payload = record.model_dump(mode="python")
    payload["cleanup_complete"] = True
    payload["cleanup_completed_at_utc"] = payload["completed_at_utc"]
    return CommandInvocationRecord.model_validate(payload)


# --------------------------------------------------------------------------
# Structural component doubles (they prove order and gating only)
# --------------------------------------------------------------------------


@dataclass
class _Queries:
    trace: list[str]
    inventory: DurableWorkInventory
    fail_at: int | None = None
    calls: int = 0

    def work_inventory(self) -> Result[DurableWorkInventory]:
        self.trace.append("work_inventory")
        self.calls += 1
        if self.calls == self.fail_at:
            return _failure("work_inventory")
        return Success[DurableWorkInventory](outcome="SUCCESS", value=self.inventory)


@dataclass
class _Artifacts:
    trace: list[str]
    failing: frozenset[str] = frozenset()
    journals: tuple[FinalizationJournalEntry, ...] = ()

    def reconcile(self, phase: Any) -> Result[FinalizationReconciliationReport]:
        self.trace.append(f"artifacts:{phase}")
        if f"artifacts:{phase}" in self.failing:
            return _failure(f"reconcile {phase}")
        return _empty_report()

    def open_journals(self) -> Result[tuple[FinalizationJournalEntry, ...]]:
        self.trace.append("artifacts:open_journals")
        if "artifacts:open_journals" in self.failing:
            return _failure("open journals")
        return Success[tuple[FinalizationJournalEntry, ...]](
            outcome="SUCCESS", value=self.journals
        )


@dataclass
class _Invocations:
    trace: list[str]
    targets_value: tuple[CommandInvocationRecord, ...] = ()
    failing: frozenset[str] = frozenset()

    def targets(self) -> Result[tuple[CommandInvocationRecord, ...]]:
        self.trace.append("invocations:targets")
        if "invocations:targets" in self.failing:
            return _failure("list targets")
        return Success[tuple[CommandInvocationRecord, ...]](
            outcome="SUCCESS", value=self.targets_value
        )

    def reconcile(self) -> Result[ReconciliationReport]:
        self.trace.append("invocations:reconcile")
        if "invocations:reconcile" in self.failing:
            return _failure("reconcile invocations")
        report = ReconciliationReport(
            supervisor_instance_id=_SUPERVISOR, started_at_utc=INSTANT, entries=()
        )
        return Success[ReconciliationReport](outcome="SUCCESS", value=report)


@dataclass
class _Requeue:
    trace: list[str]
    answer: Result[RequeueAssessment] | None = None
    seen: list[DurableWorkInventory] = field(default_factory=list)

    def assess_requeue(
        self, inventory: DurableWorkInventory
    ) -> Result[RequeueAssessment]:
        self.trace.append("requeue")
        self.seen.append(inventory)
        if self.answer is not None:
            return self.answer
        assessment = RequeueAssessment(eligible_slots=(), fenced_slots=())
        return Success[RequeueAssessment](outcome="SUCCESS", value=assessment)


class _AdmittingAudit:
    """A structural double admitting the named mutations; never production proof."""

    def __init__(self, *admitted: StartupMutation) -> None:
        self._admitted = frozenset(admitted)

    def admits(self, mutation: StartupMutation) -> bool:
        return mutation in self._admitted


@dataclass
class _Rig:
    """One startup plan over a migrated database, explicit roots and doubles."""

    tmp_path: Path
    trace: list[str] = field(default_factory=list)
    owners: list[DispatchOwner] = field(default_factory=list)
    releases: list[DispatchRelease] = field(default_factory=list)
    dispatched: list[SchedulingPermit] = field(default_factory=list)
    inventory: DurableWorkInventory = field(default_factory=_inventory)
    query_fail_at: int | None = None
    artifact_failing: frozenset[str] = frozenset()
    journals: tuple[FinalizationJournalEntry, ...] = ()
    invocation_targets: tuple[CommandInvocationRecord, ...] = ()
    invocation_failing: frozenset[str] = frozenset()
    requeue: _Requeue | None = None
    omit_requeue: bool = False
    audit: Any = APPLICATION_AUDIT_UNAVAILABLE
    contended: bool = False
    record_consistency: bool = False
    databases: list[SqliteDatabase] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.tmp_path.mkdir(parents=True, exist_ok=True)
        self.database_path = _migrated(self.tmp_path)
        self.schema_root = self.tmp_path / "base" / "schemas"
        _write_schema_tree(self.schema_root)
        self.staging_root = self.tmp_path / "staging"
        self.artifact_root = self.tmp_path / "artifacts"
        self.staging_root.mkdir()
        self.artifact_root.mkdir()

    def acquire(self, path: Path) -> DispatchOwner | DispatchRefusal:
        self.trace.append("acquire")
        if self.contended:
            return DispatchRefusal(DispatchRefusalReason.CONTENDED)
        owned = acquire_dispatch_owner(path)
        assert isinstance(owned, DispatchOwner), owned
        self.owners.append(owned)
        return owned

    def release(self, owner: DispatchOwner) -> DispatchRelease:
        self.trace.append("release")
        released = release_dispatch_owner(owner)
        self.releases.append(released)
        return released

    def components(self, database: SqliteDatabase) -> StartupComponents:
        self.trace.append("components")
        self.databases.append(database)
        if self.record_consistency:
            with database.connection() as connection:
                engine = connection.engine

            def recorder(*args: Any) -> None:
                statement = str(args[2])
                if "FROM finalization_journal WHERE state IN" in statement:
                    self.trace.append("consistency")

            event.listen(engine, "before_cursor_execute", recorder)
        if self.requeue is None:
            self.requeue = _Requeue(self.trace)
        return StartupComponents(
            queries=_Queries(self.trace, self.inventory, fail_at=self.query_fail_at),
            invocations=_Invocations(
                self.trace,
                targets_value=self.invocation_targets,
                failing=self.invocation_failing,
            ),
            artifacts=_Artifacts(
                self.trace, failing=self.artifact_failing, journals=self.journals
            ),
            requeue=None if self.omit_requeue else self.requeue,
            audit=self.audit,
        )

    def plan(self, **overrides: Any) -> StartupPlan:
        values: dict[str, Any] = {
            "database_path": self.database_path,
            "busy_timeout_ms": 100,
            "schema_root": self.schema_root,
            "staging_root": self.staging_root,
            "artifact_root": self.artifact_root,
            "clock": FixedClock(INSTANT),
            "components": self.components,
            "volume_inspector": _FixedNtfs(),
            "acquire": self.acquire,
            "release": self.release,
        }
        values.update(overrides)
        return StartupPlan(**values)

    def dispatch(self, permit: SchedulingPermit) -> str:
        self.trace.append("dispatch")
        self.dispatched.append(permit)
        return "dispatched"

    def run(self, **overrides: Any) -> str | StartupRefusal:
        return run_startup(self.plan(**overrides), dispatch=self.dispatch)


@pytest.fixture
def rig(tmp_path: Path) -> _Rig:
    return _Rig(tmp_path)


# --------------------------------------------------------------------------
# B06 and maintenance: normal opening never creates, stamps or migrates
# --------------------------------------------------------------------------


def _foreign(path: Path) -> None:
    _raw_execute(path, "CREATE TABLE foreign_rows (x INTEGER)")


def test_normal_startup_never_migrates(tmp_path: Path) -> None:
    clock = FixedClock(INSTANT)
    head = expected_head()
    # Absent: refused before anything creates the file.
    absent = tmp_path / "absent.sqlite3"
    refused = open_current_database(absent, busy_timeout_ms=100, clock=clock)
    assert isinstance(refused, StartupRefusal)
    assert (refused.gate, refused.exit_code) == (StartupGate.DATABASE, _EXIT_REFUSED)
    assert refused.reason == STORAGE_UNAVAILABLE
    assert not absent.exists()
    # Empty: refused and never stamped with the application identity.
    empty = tmp_path / "empty.sqlite3"
    empty.write_bytes(b"")
    refused = open_current_database(empty, busy_timeout_ms=100, clock=clock)
    assert isinstance(refused, StartupRefusal)
    assert refused.reason == MIGRATION_MISMATCH
    assert dict(refused.details)["state"] == "EMPTY"
    assert _raw_scalar(empty, "PRAGMA application_id") == 0
    assert _raw_scalar(empty, "SELECT count(*) FROM sqlite_master") == 0
    # Behind, unknown and unversioned: refused with the stamped facts unchanged.
    behind_root = tmp_path / "behind"
    behind_root.mkdir()
    behind = _migrated(behind_root)
    _raw_execute(
        behind, "UPDATE alembic_version SET version_num = 'r0001_stage8_baseline'"
    )
    unknown_root = tmp_path / "unknown"
    unknown_root.mkdir()
    unknown = _migrated(unknown_root)
    _raw_execute(unknown, "UPDATE alembic_version SET version_num = 'r9999_from_later'")
    unversioned_root = tmp_path / "unversioned"
    unversioned_root.mkdir()
    unversioned = _migrated(unversioned_root)
    _raw_execute(unversioned, "DROP TABLE alembic_version")
    for path, state in (
        (behind, "BEHIND"),
        (unknown, "UNKNOWN"),
        (unversioned, "UNVERSIONED"),
    ):
        tables = _raw_scalar(path, "SELECT count(*) FROM sqlite_master")
        version = (
            None
            if state == "UNVERSIONED"
            else _raw_scalar(path, "SELECT version_num FROM alembic_version")
        )
        refused = open_current_database(path, busy_timeout_ms=100, clock=clock)
        assert isinstance(refused, StartupRefusal), state
        assert refused.reason == MIGRATION_MISMATCH, state
        assert dict(refused.details)["state"] == state
        assert _raw_scalar(path, "SELECT count(*) FROM sqlite_master") == tables
        if version is not None:
            assert _raw_scalar(path, "SELECT version_num FROM alembic_version") == (
                version
            )
            assert version != head
    # Foreign: another application's file is refused untouched.
    foreign = tmp_path / "foreign.sqlite3"
    _foreign(foreign)
    refused = open_current_database(foreign, busy_timeout_ms=100, clock=clock)
    assert isinstance(refused, StartupRefusal)
    assert refused.reason == STORAGE_UNAVAILABLE
    assert _raw_scalar(foreign, "PRAGMA application_id") == 0
    # Current: the one admitted state, opened as a ``SqliteDatabase``.
    current = _migrated(tmp_path)
    opened = open_current_database(current, busy_timeout_ms=100, clock=clock)
    assert isinstance(opened, SqliteDatabase)
    opened.close()
    # The normal route exposes no maintenance or migration parameter.
    parameters = inspect.signature(open_current_database).parameters
    assert set(parameters) == {"path", "busy_timeout_ms", "clock"}


def test_maintenance_replays_current_before_migrating(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Explicit maintenance answers ``CURRENT`` as a replay without calling
    ``apply_migrations`` and exposes no script override; given an admitting
    structural capability it migrates an absent database through the packaged
    script directory only."""
    calls: list[tuple[SqliteDatabase, dict[str, object]]] = []

    def recording_apply(
        database: SqliteDatabase, **keywords: Any
    ) -> Result[RevisionReport]:
        calls.append((database, dict(keywords)))
        return apply_migrations(database, **keywords)

    monkeypatch.setattr(startup_module, "apply_migrations", recording_apply)
    clock = FixedClock(INSTANT)
    current = _migrated(tmp_path)
    replay = maintain_database(current, busy_timeout_ms=100, clock=clock)
    assert isinstance(replay, MaintenanceResult)
    assert (replay.state, replay.replayed) == ("CURRENT", True)
    assert replay.revision == expected_head()
    assert calls == []
    assert set(inspect.signature(maintain_database).parameters) == {
        "path",
        "busy_timeout_ms",
        "clock",
        "audit",
    }
    absent = tmp_path / "fresh.sqlite3"
    migrated = maintain_database(
        absent,
        busy_timeout_ms=100,
        clock=clock,
        audit=_AdmittingAudit(StartupMutation.MIGRATION),
    )
    assert isinstance(migrated, MaintenanceResult)
    assert (migrated.state, migrated.replayed, migrated.from_state) == (
        "CURRENT",
        False,
        "ABSENT",
    )
    ((_, keywords),) = calls
    assert keywords == {}
    replayed = maintain_database(absent, busy_timeout_ms=100, clock=clock)
    assert isinstance(replayed, MaintenanceResult)
    assert replayed.replayed is True
    assert len(calls) == 1
    # A state no migration admits is refused, never stamped.
    foreign = tmp_path / "foreign.sqlite3"
    _foreign(foreign)
    refused = maintain_database(
        foreign,
        busy_timeout_ms=100,
        clock=clock,
        audit=_AdmittingAudit(StartupMutation.MIGRATION),
    )
    assert isinstance(refused, StartupRefusal)
    assert refused.gate is StartupGate.MAINTENANCE
    assert _raw_scalar(foreign, "PRAGMA application_id") == 0
    assert len(calls) == 1


# --------------------------------------------------------------------------
# B07: the database gate
# --------------------------------------------------------------------------


@dataclass
class _StubDatabase:
    """A ``StartupDatabase`` answering planted revision and consistency reads."""

    path: Path
    reports: list[Result[ConsistencyReport]]
    revision: Result[None] = field(
        default_factory=lambda: Success[None](outcome="SUCCESS", value=None)
    )
    consistency_reads: int = 0
    closed: bool = False

    def verify_revision(self, revision_policy: Any) -> Result[None]:
        del revision_policy
        return self.revision

    def read_consistency(self) -> Result[ConsistencyReport]:
        self.consistency_reads += 1
        if len(self.reports) > 1:
            return self.reports.pop(0)
        return self.reports[0]

    def close(self) -> None:
        self.closed = True


def _report(**counts: int) -> Success[ConsistencyReport]:
    values = {name: 0 for name in (*_REFUSING_FIELDS, *_RECOVERY_FIELDS)}
    values.update(counts)
    return Success[InstanceOf[ConsistencyReport]](
        outcome="SUCCESS", value=ConsistencyReport(**values)
    )


@contextmanager
def _recorded_statements(database: SqliteDatabase) -> Iterator[list[str]]:
    with database.connection() as connection:
        engine = connection.engine
    statements: list[str] = []

    def recorder(*args: Any) -> None:
        statements.append(str(args[2]))

    event.listen(engine, "before_cursor_execute", recorder)
    try:
        yield statements
    finally:
        event.remove(engine, "before_cursor_execute", recorder)


def test_database_gate(tmp_path: Path) -> None:
    clock = FixedClock(INSTANT)
    path = _migrated(tmp_path)
    opened = open_current_database(path, busy_timeout_ms=100, clock=clock)
    assert isinstance(opened, SqliteDatabase)
    try:
        with _recorded_statements(opened) as statements:
            check = check_database(opened, clock=clock)
        assert isinstance(check, DatabaseCheck)
        assert check.report == _CLEAN
        assert check.recovery_required == frozenset()
        # Every integrity query ran: the twelve, the three registry projections.
        queries = [
            database_module._DANGLING_DIAGNOSTIC_REFERENCES_SQL,
            database_module._SLOT_IDENTITY_MISMATCHES_SQL,
            database_module._SPEC_PROJECTION_MISMATCHES_SQL,
            database_module._QUEUED_WITHOUT_SNAPSHOT_SQL,
            database_module._CAUSAL_EDGE_MISMATCHES_SQL,
            database_module._UNRESOLVED_CAUSAL_REFERENCES_SQL,
            *database_module._REGISTRY_PROJECTION_SQL,
            database_module._FOREIGN_KEY_CHECK_SQL,
            database_module._UNMAPPED_FINALIZING_SQL,
            database_module._REFS_WITHOUT_MANIFEST_FILE_SQL,
            database_module._SUCCESS_WITHOUT_MANIFEST_SQL,
            database_module._JOURNAL_OPEN_SQL,
        ]
        for query in queries:
            assert query in statements, query
        assert "alembic_version" in " ".join(statements)
    finally:
        opened.close()
    # All twelve fields are classified, each exactly once.
    treatments = dict(check.classification)
    assert set(treatments) == {*_REFUSING_FIELDS, *_RECOVERY_FIELDS}
    assert len(check.classification) == 12
    for name in _REFUSING_FIELDS:
        assert treatments[name] is ConsistencyTreatment.REFUSE_DISPATCH
    for name in _RECOVERY_FIELDS:
        assert treatments[name] is ConsistencyTreatment.FENCED_RECOVERY_INVENTORY
    # Each refusing finding refuses; each recovery finding enters the inventory.
    for name in _REFUSING_FIELDS:
        stub = _StubDatabase(path, [_report(**{name: 2})])
        refused = check_database(stub, clock=clock)
        assert isinstance(refused, StartupRefusal), name
        assert (refused.gate, refused.reason) == (
            StartupGate.DATABASE,
            "CONSISTENCY_FINDINGS",
        )
        assert dict(refused.details) == {name: 2}
        assert refused.exit_code == _EXIT_REFUSED
    for name in _RECOVERY_FIELDS:
        passed = check_database(
            _StubDatabase(path, [_report(**{name: 1})]), clock=clock
        )
        assert isinstance(passed, DatabaseCheck), name
        assert passed.recovery_required == frozenset({name})
    # A failed read and a non-current revision never become a clean check.
    unread = check_database(_StubDatabase(path, [_failure("consistency")]), clock=clock)
    assert isinstance(unread, StartupRefusal)
    assert unread.reason == "CONSISTENCY_UNREADABLE"
    assert unread.diagnostics[0].error_code == STORAGE_UNAVAILABLE
    behind = _StubDatabase(
        path,
        [_report()],
        revision=persistence_failure(
            MIGRATION_MISMATCH,
            message="behind",
            clock=clock,
            details={"state": "BEHIND"},
        ),
    )
    stale = check_database(behind, clock=clock)
    assert isinstance(stale, StartupRefusal)
    assert stale.reason == "REVISION_NOT_CURRENT"
    assert behind.consistency_reads == 0
    # A real unreadable table: the consistency query raises and is refused.
    corrupt_root = tmp_path / "corrupt"
    corrupt_root.mkdir()
    corrupt = _migrated(corrupt_root)
    _raw_execute(corrupt, "PRAGMA foreign_keys = OFF", "DROP TABLE run_manifests")
    opened = open_current_database(corrupt, busy_timeout_ms=100, clock=clock)
    assert isinstance(opened, SqliteDatabase)
    try:
        broken = check_database(opened, clock=clock)
    finally:
        opened.close()
    assert isinstance(broken, StartupRefusal)
    assert broken.reason == "CONSISTENCY_UNREADABLE"
    # Fresh authority after ownership: a second read that fails releases the owner.
    lock_target = tmp_path / "owner.target"
    lock_target.write_bytes(b"")
    owners: list[DispatchOwner] = []

    def acquire(target: Path) -> DispatchOwner | DispatchRefusal:
        owned = acquire_dispatch_owner(target)
        assert isinstance(owned, DispatchOwner)
        owners.append(owned)
        return owned

    racing = _StubDatabase(lock_target, [_report(foreign_key_violations=1)])
    lost = begin_reconciliation(racing, clock=clock, acquire=acquire)
    assert isinstance(lost, StartupRefusal)
    assert lost.gate is StartupGate.DISPATCH_OWNERSHIP
    assert lost.reason == "AUTHORITY_CHANGED"
    (owner,) = owners
    assert owner.released


# --------------------------------------------------------------------------
# B08: the schema-distribution gate
# --------------------------------------------------------------------------


def test_schema_distribution_matches_registry(tmp_path: Path) -> None:
    root = tmp_path / "base" / "schemas"
    _write_schema_tree(root)
    before = _tree_snapshot(root)
    accepted = check_schema_distribution(root)
    assert isinstance(accepted, SchemaDistribution)
    assert accepted.registry_count == len(SCHEMA_DEFINITIONS) == 48
    assert accepted.root == root
    assert _tree_snapshot(root) == before  # nothing generated or rewritten
    relative = sorted(_rendered())[0]
    victim = root.joinpath(*relative.parts)

    def refused(reason: str) -> dict[str, object]:
        verdict = check_schema_distribution(root)
        assert isinstance(verdict, StartupRefusal), reason
        assert verdict.gate is StartupGate.SCHEMA_DISTRIBUTION
        assert verdict.reason == reason
        assert verdict.exit_code == _EXIT_REFUSED
        return dict(verdict.details)

    # Missing.
    original = victim.read_bytes()
    victim.unlink()
    details = refused("SCHEMA_MISMATCH")
    assert details["missing"] == 1
    assert details["first_missing"] == relative.as_posix()
    assert not victim.exists()  # never regenerated
    victim.write_bytes(original)
    # Changed.
    victim.write_bytes(original + b" ")
    details = refused("SCHEMA_MISMATCH")
    assert details["changed"] == 1
    assert details["first_changed"] == relative.as_posix()
    victim.write_bytes(original)
    # Extra.
    extra = root / "domain" / "planted-v1.schema.json"
    extra.write_bytes(b"{}\n")
    details = refused("SCHEMA_MISMATCH")
    assert details["extra"] == 1
    extra.unlink()
    # Physically unsafe: a second hard link to an expected entry.
    outside = tmp_path / "outside.json"
    os.link(victim, outside)
    details = refused("SCHEMA_MISMATCH")
    assert details["unsafe"] == 1
    assert details["first_unsafe"] == relative.as_posix()
    outside.unlink()
    # Physically unsafe: a junction inside the tree is reported, never followed.
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "hidden-v1.schema.json").write_bytes(b"{}\n")
    junction = root / "linked"
    _winapi.CreateJunction(str(elsewhere), str(junction))
    try:
        details = refused("SCHEMA_MISMATCH")
        assert details["unsafe"] == 1
        assert details["first_unsafe"] == "linked"
        assert details["extra"] == 0
    finally:
        os.rmdir(junction)
    assert isinstance(check_schema_distribution(root), SchemaDistribution)
    # The root itself: relative, absent, a file, a junction.
    for planted, reason in (
        (Path("base") / "schemas", "ROOT_NOT_ABSOLUTE"),
        (tmp_path / "absent", "ROOT_ABSENT"),
        (outside, "ROOT_ABSENT"),
    ):
        verdict = check_schema_distribution(planted)
        assert isinstance(verdict, StartupRefusal), planted
        assert verdict.reason == reason
    as_file = tmp_path / "file-root"
    as_file.write_bytes(b"x")
    verdict = check_schema_distribution(as_file)
    assert isinstance(verdict, StartupRefusal)
    assert verdict.reason == "ROOT_NOT_A_DIRECTORY"
    junction_root = tmp_path / "junction-root"
    _winapi.CreateJunction(str(root), str(junction_root))
    try:
        verdict = check_schema_distribution(junction_root)
        assert isinstance(verdict, StartupRefusal)
        assert verdict.reason == "ROOT_UNSAFE"
    finally:
        os.rmdir(junction_root)
    assert _tree_snapshot(root) == before


def test_storage_gate_wraps_the_explicit_probe(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    artifacts = tmp_path / "artifacts"
    staging.mkdir()
    artifacts.mkdir()
    probe = check_storage(staging, artifacts, inspector=_FixedNtfs())
    assert isinstance(probe, StorageProbe)
    missing = check_storage(tmp_path / "absent", artifacts, inspector=_FixedNtfs())
    assert isinstance(missing, StartupRefusal)
    assert (missing.gate, missing.reason) == (StartupGate.STORAGE, "MISSING")
    assert dict(missing.details) == {"role": "staging"}
    assert not (tmp_path / "absent").exists()


# --------------------------------------------------------------------------
# B11-B18: order, barrier and failure paths
# --------------------------------------------------------------------------


_EXPECTED_ORDER: Final = (
    "acquire",
    "components",
    "work_inventory",
    "artifacts:inventory",
    "invocations:targets",
    "invocations:reconcile",
    "work_inventory",
    "artifacts:recover",
    "work_inventory",
    "requeue",
    "artifacts:sweep",
    "consistency",
    "artifacts:open_journals",
    "dispatch",
    "release",
)


def test_startup_phases_precede_scheduling(rig: _Rig) -> None:
    rig.record_consistency = True
    outcome = rig.run()
    assert outcome == "dispatched"
    assert tuple(rig.trace) == _EXPECTED_ORDER
    (permit,) = rig.dispatched
    reconciliation = permit.reconciliation
    assert isinstance(reconciliation, StartupReconciliation)
    assert tuple(reconciliation.artifact_reports) == ("inventory", "recover", "sweep")
    assert reconciliation.consistency.report == _CLEAN
    assert permit.eligible_slots == ()
    assert permit.fenced_slots == ()
    # The requeue assessment saw the fresh post-recovery inventory.
    assert rig.requeue is not None
    assert rig.requeue.seen == [rig.inventory]
    assert _no_open_handles(rig.database_path)
    assert rig.releases == [DispatchRelease.RELEASED]


_FAILURES: Final = (
    pytest.param({"staging_missing": True}, StartupGate.STORAGE, 0, id="storage"),
    pytest.param(
        {"schema_missing": True}, StartupGate.SCHEMA_DISTRIBUTION, 0, id="schema"
    ),
    pytest.param({"database_absent": True}, StartupGate.DATABASE, 0, id="database"),
    pytest.param(
        {"contended": True}, StartupGate.DISPATCH_OWNERSHIP, 0, id="contended"
    ),
    pytest.param(
        {"query_fail_at": 1}, StartupGate.DURABLE_INVENTORY, 1, id="inventory"
    ),
    pytest.param(
        {"artifact_failing": frozenset({"artifacts:inventory"})},
        StartupGate.ARTIFACT_INVENTORY,
        1,
        id="artifact-inventory",
    ),
    pytest.param(
        {"invocation_failing": frozenset({"invocations:targets"})},
        StartupGate.INVOCATION_RECONCILIATION,
        1,
        id="invocation-targets",
    ),
    pytest.param(
        {"invocation_failing": frozenset({"invocations:reconcile"})},
        StartupGate.INVOCATION_RECONCILIATION,
        1,
        id="invocation-reconcile",
    ),
    pytest.param({"query_fail_at": 2}, StartupGate.RUN_RECONCILIATION, 1, id="runs"),
    pytest.param(
        {"artifact_failing": frozenset({"artifacts:recover"})},
        StartupGate.ARTIFACT_RECOVERY,
        1,
        id="recover",
    ),
    pytest.param({"query_fail_at": 3}, StartupGate.REQUEUE_ASSESSMENT, 1, id="fresh"),
    pytest.param(
        {"omit_requeue": True}, StartupGate.REQUEUE_ASSESSMENT, 1, id="no-requeue"
    ),
    pytest.param(
        {"requeue_fails": True}, StartupGate.REQUEUE_ASSESSMENT, 1, id="requeue"
    ),
    pytest.param(
        {"requeue_unknown_slot": True},
        StartupGate.REQUEUE_ASSESSMENT,
        1,
        id="requeue-contradicts",
    ),
    pytest.param(
        {"artifact_failing": frozenset({"artifacts:sweep"})},
        StartupGate.ARTIFACT_SWEEP,
        1,
        id="sweep",
    ),
    pytest.param(
        {"artifact_failing": frozenset({"artifacts:open_journals"})},
        StartupGate.CONSISTENCY_RECHECK,
        1,
        id="journal-read",
    ),
    pytest.param(
        {"journals": (sample_journal(),)},
        StartupGate.CONSISTENCY_RECHECK,
        1,
        id="journal-contradiction",
    ),
)


@pytest.mark.parametrize(("setup", "gate", "owners"), _FAILURES)
def test_failed_phase_never_permits_scheduling(
    rig: _Rig, setup: Mapping[str, Any], gate: StartupGate, owners: int
) -> None:
    overrides: dict[str, Any] = {}
    for key, value in setup.items():
        if key == "staging_missing":
            overrides["staging_root"] = rig.tmp_path / "no-staging"
        elif key == "schema_missing":
            overrides["schema_root"] = rig.tmp_path / "no-base" / "schemas"
        elif key == "database_absent":
            overrides["database_path"] = rig.tmp_path / "absent.sqlite3"
        elif key == "requeue_fails":
            rig.requeue = _Requeue(rig.trace, answer=_failure("assess requeue"))
        elif key == "requeue_unknown_slot":
            unknown = RequeueAssessment(
                eligible_slots=("slot_00000000-0000-4000-8000-000000000009",),
                fenced_slots=(),
            )
            rig.requeue = _Requeue(
                rig.trace,
                answer=Success[RequeueAssessment](outcome="SUCCESS", value=unknown),
            )
        else:
            setattr(rig, key, value)
    outcome = rig.run(**overrides)
    assert isinstance(outcome, StartupRefusal), outcome
    assert outcome.gate is gate
    expected_exit = _EXIT_CONTENDED if gate is StartupGate.DISPATCH_OWNERSHIP else 4
    assert outcome.exit_code == expected_exit
    assert rig.dispatched == []
    assert "dispatch" not in rig.trace
    assert len(rig.owners) == owners
    assert all(owner.released for owner in rig.owners)
    assert rig.releases == [DispatchRelease.RELEASED] * owners
    if rig.database_path.exists():
        assert _no_open_handles(rig.database_path)
    assert not (rig.tmp_path / "absent.sqlite3").exists()


def test_reconciliation_phase_releases_before_dispatch(rig: _Rig) -> None:
    observed: dict[str, object] = {}

    def dispatch(permit: SchedulingPermit) -> str:
        phase = permit.reconciliation.phase
        observed["phase_active"] = phase.active
        observed["owner_released"] = phase.owner.released
        observed["valid"] = permit.valid
        observed["database_open"] = not _no_open_handles(rig.database_path)
        again = permit_scheduling(
            phase, permit.reconciliation, storage=permit.storage, schema=permit.schema
        )
        observed["second_permit"] = again
        return "driven"

    outcome = run_startup(rig.plan(), dispatch=dispatch)
    assert outcome == "driven"
    assert observed["phase_active"] is False
    assert observed["owner_released"] is False
    assert observed["valid"] is True
    assert observed["database_open"] is True
    second = observed["second_permit"]
    assert isinstance(second, StartupRefusal)
    assert (second.gate, second.reason) == (
        StartupGate.SCHEDULING_BARRIER,
        "PHASE_NOT_ACTIVE",
    )
    (owner,) = rig.owners
    assert owner.released
    # After return the permit is void: its owner has been released.
    assert rig.releases == [DispatchRelease.RELEASED]
    assert _no_open_handles(rig.database_path)


def test_startup_fences_unresolved_work_and_rebuilds_its_permit(rig: _Rig) -> None:
    """A deferred RESULT journal, an unresolved child and the assessment's own
    fences all fence their slots; eligible work never includes a fenced slot; a
    second startup rebuilds the permit from fresh facts."""
    runs = (
        sample_run(_R.RUNNING),
        sample_run(_R.PENDING, run_id=OTHER_RUN_ID, logical_slot_id=SLOT_B),
    )
    rig.inventory = _inventory(
        runs=runs,
        invocations=(sample_invocation(_C.RUNNING, kind=_K.RUN),),
    )
    assessment = RequeueAssessment(eligible_slots=(SLOT_A, SLOT_B), fenced_slots=())
    rig.requeue = _Requeue(
        rig.trace,
        answer=Success[RequeueAssessment](outcome="SUCCESS", value=assessment),
    )
    first = rig.run()
    assert first == "dispatched"
    (permit,) = rig.dispatched
    assert permit.fenced_slots == (SLOT_A,)
    assert permit.eligible_slots == (SLOT_B,)
    assert permit.fenced_runs == (RUN_ID,)
    assert not permit.valid
    second = rig.run()
    assert second == "dispatched"
    rebuilt = rig.dispatched[1]
    assert rebuilt is not permit
    assert rebuilt.fenced_slots == permit.fenced_slots
    assert rebuilt.owner_identity == permit.owner_identity


def test_reconciliation_second_pass_is_idempotent(tmp_path: Path) -> None:
    """Two startups over the same state through the public artifact entry point:
    the first registers the resumable evidence and sweeps the orphan root, the
    second changes nothing -- no attempt, reference, manifest or terminal
    transition is duplicated -- and the six phase summaries are told apart by
    their ``phase`` detail."""
    harness = MemoryFinalizationHarness(tmp_path / "artifacts-root")
    harness.plant_evidence_prestate()
    orphan = harness.roots.runtime_root / "inv_5e5e5e5e-1111-4222-8333-444455556666"
    orphan.mkdir()
    (orphan / "request.json").write_bytes(b'{"orphan": true}')
    rig = _Rig(tmp_path / "startup-root")
    clock = FixedClock(INSTANT)

    def components(database: SqliteDatabase) -> StartupComponents:
        source = SqliteReconciliationSource(database, clock)

        def reconcile() -> Result[ReconciliationReport]:
            report = ReconciliationReport(
                supervisor_instance_id=_SUPERVISOR, started_at_utc=INSTANT, entries=()
            )
            return Success[ReconciliationReport](outcome="SUCCESS", value=report)

        return StartupComponents(
            queries=source,
            invocations=InvocationRecovery(
                source=source, reconcile_invocations=reconcile
            ),
            artifacts=FinalizationPhases(
                unit_of_work_factory=harness.unit_of_work.begin,
                store=harness.roots.store,
                hasher=harness.hasher,
                registrar=harness.registrar,
                recovery_validator=harness.validator,
                auditor=harness.auditor,
                clock=harness.clock,
                runtime_root=harness.roots.runtime_root,
                command_roots=harness.command_roots,
                token_material=harness.token_material,
                log=harness.log,
            ),
            requeue=_Requeue([]),
            audit=APPLICATION_AUDIT_UNAVAILABLE,
        )

    first = rig.run(components=components)
    assert first == "dispatched"
    after_first = harness.durable()
    assert len(after_first.refs) == 1
    assert not orphan.exists()
    first_inventory = rig.dispatched[0].reconciliation.inventory
    second = rig.run(components=components)
    assert second == "dispatched"
    after_second = harness.durable()
    assert after_second.refs == after_first.refs
    assert after_second.candidates == after_first.candidates
    assert after_second.journal == after_first.journal
    assert after_second.run_manifests == after_first.run_manifests
    assert after_second.run == after_first.run
    assert rig.dispatched[1].reconciliation.inventory == first_inventory
    summaries = [
        dict(event.details)
        for event in after_second.audit_events
        if event.action.value == "RECONCILIATION_FINALIZATION_RESUMED"
    ]
    assert [details["phase"] for details in summaries] == [
        "inventory",
        "recover",
        "sweep",
        "inventory",
        "recover",
        "sweep",
    ]
    assert [details["changes"] for details in summaries] == [0, 1, 1, 0, 0, 0]
    second_reports = rig.dispatched[1].reconciliation.artifact_reports
    assert all(report.changes == 0 for report in second_reports.values())
    non_summary = [
        event.action.value
        for event in after_second.audit_events[len(after_first.audit_events) :]
        if event.action.value != "RECONCILIATION_FINALIZATION_RESUMED"
    ]
    assert non_summary == []


# --------------------------------------------------------------------------
# B13, B14 and B2: run reconciliation and the unavailable required audit
# --------------------------------------------------------------------------


def test_run_reconciliation_classifies_coupling_and_attempt_agreement() -> None:
    running = sample_run(_R.RUNNING)
    awaiting = (sample_invocation(_C.EXITED, kind=_K.RUN),)
    live = (sample_invocation(_C.RUNNING, kind=_K.RUN),)
    timed_out = (_cleaned(sample_invocation(_C.TIMED_OUT, kind=_K.RUN)),)
    uncleaned = (sample_invocation(_C.TIMED_OUT, kind=_K.RUN),)
    audit = APPLICATION_AUDIT_UNAVAILABLE
    clean = reconcile_runs(_inventory(), audit=audit)
    assert isinstance(clean, RunReconciliation)
    assert (clean.fenced_runs, clean.required_transitions) == ((), ())
    for invocations, fenced in ((awaiting, (RUN_ID,)), (live, (RUN_ID,))):
        verdict = reconcile_runs(
            _inventory(runs=(running,), invocations=invocations), audit=audit
        )
        assert isinstance(verdict, RunReconciliation)
        assert verdict.fenced_runs == fenced
    prelaunch = reconcile_runs(_inventory(runs=(sample_run(_R.PENDING),)), audit=audit)
    assert isinstance(prelaunch, RunReconciliation)
    assert prelaunch.fenced_runs == ()
    # A terminal run whose invocation still needs cleanup stays fenced.
    failed = sample_run(_R.FAILED)
    pending_cleanup = reconcile_runs(
        _inventory(runs=(failed,), invocations=uncleaned), audit=audit
    )
    assert isinstance(pending_cleanup, RunReconciliation)
    assert pending_cleanup.fenced_runs == (RUN_ID,)
    # A required transition is B2-refused; an admitting double fences it instead.
    planted_cases: tuple[tuple[CommandInvocationRecord, ...], ...] = (timed_out, ())
    for planted in planted_cases:
        inventory = _inventory(runs=(running,), invocations=planted)
        refused = reconcile_runs(inventory, audit=audit)
        assert isinstance(refused, StartupRefusal)
        assert (refused.gate, refused.reason) == (
            StartupGate.AUDIT_CAPABILITY,
            StartupMutation.RUN_TRANSITION.value,
        )
        admitted = reconcile_runs(
            inventory, audit=_AdmittingAudit(StartupMutation.RUN_TRANSITION)
        )
        assert isinstance(admitted, RunReconciliation)
        assert admitted.required_transitions == (RUN_ID,)
        assert admitted.fenced_runs == (RUN_ID,)
    # Latest-attempt agreement: two open attempts of one slot contradict.
    second = sample_run(
        _R.RUNNING, run_id=OTHER_RUN_ID, attempt_number=2, predecessor_run_id=RUN_ID
    )
    contradiction = reconcile_runs(
        _inventory(runs=(running, second), invocations=live), audit=audit
    )
    assert isinstance(contradiction, StartupRefusal)
    assert (contradiction.gate, contradiction.reason) == (
        StartupGate.RUN_RECONCILIATION,
        "CONTRADICTORY_ATTEMPTS",
    )


def test_required_startup_audit_unavailable_refuses_mutation(
    rig: _Rig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """B2 is checked before the unsupported mutation: maintenance never opens for
    migration, process reconciliation never runs over a target, run
    reconciliation never writes, and nothing is dispatched."""
    applied: list[object] = []
    monkeypatch.setattr(
        startup_module, "apply_migrations", lambda *args, **kwargs: applied.append(args)
    )
    clock = FixedClock(INSTANT)
    absent = tmp_path / "never.sqlite3"
    empty = tmp_path / "empty.sqlite3"
    empty.write_bytes(b"")
    behind_root = tmp_path / "behind"
    behind_root.mkdir()
    behind = _migrated(behind_root)
    _raw_execute(
        behind, "UPDATE alembic_version SET version_num = 'r0001_stage8_baseline'"
    )
    for path in (absent, empty, behind):
        refused = maintain_database(path, busy_timeout_ms=100, clock=clock)
        assert isinstance(refused, StartupRefusal), path
        assert (refused.gate, refused.reason) == (
            StartupGate.AUDIT_CAPABILITY,
            StartupMutation.MIGRATION.value,
        )
        assert refused.exit_code == _EXIT_REFUSED
    assert applied == []
    assert not absent.exists()
    assert _raw_scalar(empty, "PRAGMA application_id") == 0
    assert _raw_scalar(behind, "SELECT version_num FROM alembic_version") == (
        "r0001_stage8_baseline"
    )
    # Process reconciliation over a target is refused before the reconciler runs.
    rig.invocation_targets = (sample_invocation(_C.RUNNING, kind=_K.RUN),)
    refused_process = rig.run()
    assert isinstance(refused_process, StartupRefusal)
    assert (refused_process.gate, refused_process.reason) == (
        StartupGate.AUDIT_CAPABILITY,
        StartupMutation.PROCESS_RECONCILIATION.value,
    )
    assert "invocations:reconcile" not in rig.trace
    assert "artifacts:recover" not in rig.trace
    assert rig.dispatched == []
    # Run reconciliation needing a transition is refused before recovery.
    rig.trace.clear()
    rig.invocation_targets = ()
    rig.inventory = _inventory(
        runs=(sample_run(_R.RUNNING),),
        invocations=(_cleaned(sample_invocation(_C.TIMED_OUT, kind=_K.RUN)),),
    )
    refused_run = rig.run()
    assert isinstance(refused_run, StartupRefusal)
    assert (refused_run.gate, refused_run.reason) == (
        StartupGate.AUDIT_CAPABILITY,
        StartupMutation.RUN_TRANSITION.value,
    )
    assert "artifacts:recover" not in rig.trace
    assert rig.dispatched == []
    assert all(owner.released for owner in rig.owners)
    assert _no_open_handles(rig.database_path)


class _FailingVolumes(_FixedNtfs):
    """A ``VolumeInspector`` whose first kernel call fails with a numeric code."""

    def volume_root(self, path: Path) -> str:
        del path
        raise RuntimeWindowsError("GetVolumePathNameW", 5)


class _RaisingDatabase(_StubDatabase):
    def read_consistency(self) -> Result[ConsistencyReport]:
        raise RuntimeError("planted defect inside the fresh authority read")


def _answering(
    answer: Result[RevisionReport],
) -> Callable[[SqliteDatabase], Result[RevisionReport]]:
    """A planted ``apply_migrations`` answering ``answer`` without migrating."""

    def apply(database: SqliteDatabase) -> Result[RevisionReport]:
        del database
        return answer

    return apply


def test_startup_gates_refuse_unproven_or_malformed_answers(
    rig: _Rig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every remaining refusal is a stable, bounded answer: a failed volume probe
    keeps its kernel code; a refused acquisition is exit 4 with its code; a raising
    authority read releases the owner and propagates; a malformed count, an
    unreadable revision and a database that fell behind after opening refuse; a
    malformed phase or assessment answer refuses; the permit refuses unproven
    storage or schema facts, a foreign reconciliation and a released owner; and
    a migration that fails or stops short is refused."""
    clock = FixedClock(INSTANT)
    probed = check_storage(
        rig.staging_root, rig.artifact_root, inspector=_FailingVolumes()
    )
    assert isinstance(probed, StartupRefusal)
    assert (probed.reason, dict(probed.details)) == (
        "PROBE_FAILED",
        {"role": "staging", "winerror": 5},
    )
    stub = _StubDatabase(rig.database_path, [_report()])
    refused = begin_reconciliation(
        stub,
        clock=clock,
        acquire=lambda path: DispatchRefusal(
            DispatchRefusalReason.OWNERSHIP_FAILED, winerror=5
        ),
    )
    assert isinstance(refused, StartupRefusal)
    assert (refused.reason, refused.exit_code, dict(refused.details)) == (
        "OWNERSHIP_FAILED",
        _EXIT_REFUSED,
        {"winerror": 5},
    )
    raising = _RaisingDatabase(rig.database_path, [_report()])
    with pytest.raises(RuntimeError, match="planted defect"):
        begin_reconciliation(raising, clock=clock, acquire=rig.acquire)
    assert rig.owners[-1].released
    negative = ConsistencyReport(0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0)
    malformed = check_database(
        _StubDatabase(
            rig.database_path,
            [Success[InstanceOf[ConsistencyReport]](outcome="SUCCESS", value=negative)],
        ),
        clock=clock,
    )
    assert isinstance(malformed, StartupRefusal)
    assert (malformed.reason, dict(malformed.details)) == (
        "CONSISTENCY_MALFORMED",
        {"field": "foreign_key_violations"},
    )
    unreadable = check_database(
        _StubDatabase(rig.database_path, [_report()], revision=_failure("revision")),
        clock=clock,
    )
    assert isinstance(unreadable, StartupRefusal)
    assert unreadable.reason == "REVISION_UNREADABLE"
    # The database falls behind after it was opened: the real policy refuses it.
    opened = open_current_database(rig.database_path, busy_timeout_ms=100, clock=clock)
    assert isinstance(opened, SqliteDatabase)
    try:
        _raw_execute(
            rig.database_path,
            "UPDATE alembic_version SET version_num = 'r0001_stage8_baseline'",
        )
        behind = check_database(opened, clock=clock)
    finally:
        opened.close()
        assert expected_head() == "r0002_stage9_artifacts"
        _raw_execute(
            rig.database_path,
            "UPDATE alembic_version SET version_num = 'r0002_stage9_artifacts'",
        )
    assert isinstance(behind, StartupRefusal)
    assert (behind.reason, dict(behind.details)["state"]) == (
        "REVISION_NOT_CURRENT",
        "BEHIND",
    )

    class _WrongArtifacts(_Artifacts):
        def reconcile(self, phase: Any) -> Any:
            return Success[str](outcome="SUCCESS", value="not a report")

    class _WrongRequeue(_Requeue):
        def assess_requeue(self, inventory: DurableWorkInventory) -> Any:
            return Success[str](outcome="SUCCESS", value="not an assessment")

    trace: list[str] = []
    cases: tuple[tuple[StartupComponents, StartupGate, str], ...] = (
        (
            StartupComponents(
                queries=_Queries(trace, _inventory()),
                invocations=_Invocations(trace),
                artifacts=_WrongArtifacts(trace),
                requeue=_Requeue(trace),
            ),
            StartupGate.ARTIFACT_INVENTORY,
            "PHASE_MALFORMED",
        ),
        (
            StartupComponents(
                queries=_Queries(trace, _inventory()),
                invocations=_Invocations(trace),
                artifacts=_Artifacts(trace),
                requeue=_WrongRequeue(trace),
            ),
            StartupGate.REQUEUE_ASSESSMENT,
            "ASSESSMENT_MALFORMED",
        ),
    )
    storage = check_storage(rig.staging_root, rig.artifact_root, inspector=_FixedNtfs())
    schema = check_schema_distribution(rig.schema_root)
    assert isinstance(storage, StorageProbe)
    assert isinstance(schema, SchemaDistribution)
    for components, gate, reason in cases:
        phase = begin_reconciliation(stub, clock=clock, acquire=rig.acquire)
        assert not isinstance(phase, StartupRefusal)
        try:
            answer = reconcile_startup(phase, components)
        finally:
            phase.close()
        assert isinstance(answer, StartupRefusal)
        assert (answer.gate, answer.reason) == (gate, reason)
    clean = StartupComponents(
        queries=_Queries(trace, _inventory()),
        invocations=_Invocations(trace),
        artifacts=_Artifacts(trace),
        requeue=_Requeue(trace),
    )
    first = begin_reconciliation(stub, clock=clock, acquire=rig.acquire)
    assert not isinstance(first, StartupRefusal)
    try:
        reconciled = reconcile_startup(first, clean)
        assert isinstance(reconciled, StartupReconciliation)
        unproven: Any = object()
        for kwargs, reason in (
            ({"storage": unproven, "schema": schema}, "STORAGE_NOT_PROVEN"),
            ({"storage": storage, "schema": unproven}, "SCHEMA_NOT_PROVEN"),
        ):
            verdict = permit_scheduling(first, reconciled, **kwargs)
            assert isinstance(verdict, StartupRefusal)
            assert verdict.reason == reason
        assert first.active
        release_dispatch_owner(first.owner)
        released = permit_scheduling(first, reconciled, storage=storage, schema=schema)
        assert isinstance(released, StartupRefusal)
        assert released.reason == "OWNER_RELEASED"
    finally:
        first.close()
    second = begin_reconciliation(stub, clock=clock, acquire=rig.acquire)
    assert not isinstance(second, StartupRefusal)
    try:
        foreign = permit_scheduling(second, reconciled, storage=storage, schema=schema)
    finally:
        second.close()
    assert isinstance(foreign, StartupRefusal)
    assert foreign.reason == "RECONCILIATION_MISMATCH"
    # Maintenance: an apply that fails, and one that stops short of the head.
    stopped_short = RevisionReport(
        state=RevisionState.BEHIND,
        current_revision="r0001_stage8_baseline",
        expected_head=expected_head(),
    )
    maintenance_cases: tuple[tuple[Result[RevisionReport], str], ...] = (
        (_failure("upgrade"), STORAGE_UNAVAILABLE),
        (
            Success[InstanceOf[RevisionReport]](outcome="SUCCESS", value=stopped_short),
            "MIGRATION_INCOMPLETE",
        ),
    )
    for planted_answer, reason in maintenance_cases:
        target = tmp_path / f"maintenance-{reason.lower()}.sqlite3"
        monkeypatch.setattr(
            startup_module, "apply_migrations", _answering(planted_answer)
        )
        maintained = maintain_database(
            target,
            busy_timeout_ms=100,
            clock=clock,
            audit=_AdmittingAudit(StartupMutation.MIGRATION),
        )
        assert isinstance(maintained, StartupRefusal), reason
        assert (maintained.gate, maintained.reason) == (StartupGate.MAINTENANCE, reason)


def test_startup_queries_and_inventory_refuse_malformed_answers(rig: _Rig) -> None:
    """``inventory_work`` refuses a failed or non-inventory answer; the permit is
    refused for a phase that is not active or whose owner is gone."""

    class _Wrong:
        def work_inventory(self) -> Any:
            return Success[str](outcome="SUCCESS", value="not an inventory")

    wrong = inventory_work(_Wrong())
    assert isinstance(wrong, StartupRefusal)
    assert wrong.reason == "INVENTORY_MALFORMED"
    failed = inventory_work(_Queries([], _inventory(), fail_at=1))
    assert isinstance(failed, StartupRefusal)
    assert failed.reason == "INVENTORY_UNREADABLE"
    stub = _StubDatabase(rig.database_path, [_report()])
    phase = begin_reconciliation(
        stub, clock=FixedClock(INSTANT), acquire=rig.acquire, release=rig.release
    )
    assert not isinstance(phase, StartupRefusal)
    trace: list[str] = []
    components = StartupComponents(
        queries=_Queries(trace, _inventory()),
        invocations=_Invocations(trace),
        artifacts=_Artifacts(trace),
        requeue=_Requeue(trace),
        audit=APPLICATION_AUDIT_UNAVAILABLE,
    )
    reconciled = reconcile_startup(phase, components)
    assert isinstance(reconciled, StartupReconciliation)
    storage = check_storage(rig.staging_root, rig.artifact_root, inspector=_FixedNtfs())
    schema = check_schema_distribution(rig.schema_root)
    assert isinstance(storage, StorageProbe)
    assert isinstance(schema, SchemaDistribution)
    assert phase.close() is DispatchRelease.RELEASED
    void = permit_scheduling(phase, reconciled, storage=storage, schema=schema)
    assert isinstance(void, StartupRefusal)
    assert void.gate is StartupGate.SCHEDULING_BARRIER
    assert phase.close() is DispatchRelease.ALREADY_RELEASED
    # After recovery an unmapped FINALIZING candidate is recovery left incomplete.
    stub = _StubDatabase(rig.database_path, [_report(), _report(unmapped_finalizing=1)])
    phase = begin_reconciliation(stub, clock=FixedClock(INSTANT), acquire=rig.acquire)
    assert not isinstance(phase, StartupRefusal)
    try:
        incomplete = reconcile_startup(phase, components)
    finally:
        phase.close()
    assert isinstance(incomplete, StartupRefusal)
    assert (incomplete.gate, incomplete.reason) == (
        StartupGate.CONSISTENCY_RECHECK,
        "RECOVERY_INCOMPLETE",
    )
    # A deferred open RESULT journal agreeing with the recheck fences its run.
    journal = sample_journal()
    stub = _StubDatabase(rig.database_path, [_report(), _report(journal_open=1)])
    phase = begin_reconciliation(stub, clock=FixedClock(INSTANT), acquire=rig.acquire)
    assert not isinstance(phase, StartupRefusal)
    awaiting = _inventory(
        runs=(sample_run(_R.RUNNING),),
        invocations=(_cleaned(sample_invocation(_C.EXITED, kind=_K.RUN)),),
    )
    journal_components = StartupComponents(
        queries=_Queries(trace, awaiting),
        invocations=_Invocations(trace),
        artifacts=_Artifacts(trace, journals=(journal,)),
        requeue=_Requeue(trace),
        audit=APPLICATION_AUDIT_UNAVAILABLE,
    )
    try:
        fenced = reconcile_startup(phase, journal_components)
    finally:
        phase.close()
    assert isinstance(fenced, StartupReconciliation)
    assert journal.run_id == RUN_ID
    assert journal.run_invocation_id == INVOCATION_ID
    assert fenced.fenced_runs == (RUN_ID,)
    assert fenced.fenced_slots == (SLOT_A,)
