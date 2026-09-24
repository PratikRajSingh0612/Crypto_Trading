"""Restart reconciliation over a reopened SQLite database (case C-23, Task 5).

Every state of the Stage 7 ``run_every_row`` table is seeded through the Task 4
repositories into one migrated file-backed database, the database is closed, and
the file is reopened with new objects: ``reconcile_invocations`` then runs over
``SqliteReconciliationSource``, a fresh ``Stage5InvocationLifecycle`` composed over
``SqliteUnitOfWork`` and ``SqliteDiagnosticRecorder``, and a scripted controller.
Each row reaches the Stage 7 plan section 8.5 decision, no row reaches ``EXITED``
that was not already ``EXITED`` and no run reaches a success state; every durable
assertion is a fresh read of the reopened file; a second pass over the same file
repeats no destructive action and changes no row; the consistency report is
clean apart from the seeded ``RUNNING`` parents that carry no snapshot; and no raw
attempt token reaches the report, a diagnostic or a stored row.

Test-local readings, declared rather than inferred silently:

- ``tests/integration/persistence/conftest.py`` is **not** created: under the
  pinned strict mypy profile its identity would be ``conftest`` (duplicating
  ``tests/conftest.py``) and, with a leaf package marker, ``persistence.conftest``
  (duplicating ``tests/unit/persistence/conftest.py``); both were measured to fail
  ``mypy-all``. Every helper this module needs is module-local.
- Rows that must be past their deadline in the same pass are seeded with an
  older ``created_at_utc`` (the Stage 7 module's technique), so one clock instant
  serves every row and ``RestartRow.now`` is that instant.
- The supervision root of the preflight is ``tmp_path / "supervision"``, bound by
  an autouse fixture into a module global that ``RestartRow.preflight`` reads
  (the Stage 7 module's ``_active`` precedent), so the sketch line
  ``preflight=row.preflight`` stays verbatim; it is never created -- every row
  only inspects it (``lstat`` of a planned result path, or the removal of a
  command root that does not exist, which plan 7.5 makes a success) -- and the
  fixture's teardown asserts so.
- The per-row sketch test carries one added line after its three asserts,
  ``assert _checked_out(reopened) == 0``: the pool lent nothing after the pass.
- Process identities are deterministic per row (pid ``4000 + index`` and the
  scripted creation identity), so a row's controller is built from its own
  declaration and the seeded identity can be recomputed for the fresh reads.
- Every terminal seed references the doubles' one fixture diagnostic, recorded
  once through ``SqliteDiagnosticRecorder``, so ``dangling_diagnostic_references``
  is zero before and after every pass.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Final

import pytest
from pydantic.experimental.missing_sentinel import MISSING
from sqlalchemy.pool import QueuePool

from crypto_lab.adapters.diagnostics import (
    PROCESS_CANCELLED,
    PROCESS_VALIDATE_TIMED_OUT,
)
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.engine_run import EngineRunRecord
from crypto_lab.domain.experiment import (
    AdapterIdentity,
    EngineIdentity,
    SelectedEngineSlot,
)
from crypto_lab.domain.lifecycle import (
    TERMINAL_COMMAND_INVOCATION_STATES,
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.results import Failure, Result
from crypto_lab.experiments.experiment_service import cancel_experiment
from crypto_lab.experiments.requests import CancelExperimentRequest
from crypto_lab.experiments.supervision_lifecycle import Stage5InvocationLifecycle
from crypto_lab.persistence.database import SqliteDatabase
from crypto_lab.persistence.reconciliation_source import SqliteReconciliationSource
from crypto_lab.persistence.registries import SqliteDiagnosticRecorder
from crypto_lab.persistence.unit_of_work import SqliteTransaction, SqliteUnitOfWork
from crypto_lab.process_supervision.diagnostics import (
    CORE_INVARIANT_VIOLATION,
    PROCESS_FORCED_TERMINATION,
    PROCESS_LAUNCH_NOT_COMMITTED,
    PROCESS_ORCHESTRATOR_RESTART_LOST_SUPERVISION,
    PROCESS_PID_REUSE_DETECTED,
)
from crypto_lab.process_supervision.models import (
    FORCED_TERMINATION_EXIT_CODE,
    InvocationReconciliation,
    ProcessPresence,
    ReconciliationAction,
    ReconciliationReport,
    render_creation_identity,
)
from crypto_lab.process_supervision.reconciliation import reconcile_invocations
from crypto_lab.process_supervision.roots import PathPreflight
from doubles.experiments import (
    INSTANT,
    UUID_C,
    FixedClock,
    SequentialIdentitySource,
    sample_diagnostic,
    sample_draft,
    sample_experiment,
    sample_invocation,
    sample_observation,
    sample_process_identity,
    sample_run,
)
from doubles.supervision import (
    SCRIPTED_CREATION_100NS,
    SCRIPTED_SUPERVISOR_INSTANCE_ID,
    ScriptedProcessController,
)
from persistence_support.harness import ok, open_test_database, raw_connection

_C: Final = CommandInvocationState
_K: Final = CommandKind
_R: Final = EngineRunState
_A: Final = ReconciliationAction
_P: Final = ProcessPresence
TIMEOUT_SECONDS: Final = 120
_SEED_OFFSET: Final = timedelta(seconds=60)
_EXPIRED_OFFSET: Final = timedelta(seconds=TIMEOUT_SECONDS + 2)
_ADAPTER: Final = AdapterIdentity(
    adapter_name="fake.conformant", adapter_version="1.0.0"
)
_FAKE_ENGINE: Final = EngineIdentity(engine_name="fake.engine", engine_version="1.0.0")
#: The frozen observation identity ``sample_slot_compatibility`` assigns a slot
#: outside the doubles' two; one identical row serves every seeded run.
_OBSERVATION_ID: Final = f"avail_{UUID_C}"
#: The preflight's supervision root: bound under ``tmp_path`` by the autouse
#: ``supervision_root`` fixture below and never created; every row only inspects
#: paths under it (module docstring). A module global, so the sketch line
#: ``preflight=row.preflight`` stays verbatim (the Stage 7 module's ``_active``
#: precedent).
_SUPERVISION_ROOT: Path | None = None
SUPERVISOR_INSTANCE_ID: Final = SCRIPTED_SUPERVISOR_INSTANCE_ID
#: The error code of the doubles' one fixture diagnostic every terminal seed
#: references as its primary.
_SEEDED_PRIMARY_CODE: Final = sample_diagnostic().error_code
_SUCCESS_RUN_STATES: Final = frozenset({_R.SUCCEEDED, _R.SUCCEEDED_WITH_WARNINGS})
_PROCESS_STATES: Final = frozenset({_C.RUNNING, _C.EXITED, _C.PROTOCOL_FAILED})
#: The run state seeded beside each invocation state (the Stage 7 module's table).
_MATCHING_RUN_STATE: Final[
    dict[CommandKind, dict[CommandInvocationState, EngineRunState]]
] = {
    _K.RUN: {
        _C.PENDING: _R.READY,
        _C.STARTING: _R.STARTING,
        _C.RUNNING: _R.RUNNING,
        _C.EXITED: _R.RUNNING,
        _C.FAILED_TO_START: _R.FAILED,
        _C.CANCELLED: _R.CANCELLED,
        _C.TIMED_OUT: _R.TIMED_OUT,
        _C.PROTOCOL_FAILED: _R.FAILED,
    },
    _K.VALIDATE: {
        _C.PENDING: _R.VALIDATING,
        _C.STARTING: _R.VALIDATING,
        _C.RUNNING: _R.VALIDATING,
        _C.EXITED: _R.VALIDATING,
        _C.FAILED_TO_START: _R.FAILED,
        _C.CANCELLED: _R.CANCELLED,
        _C.TIMED_OUT: _R.TIMED_OUT,
        _C.PROTOCOL_FAILED: _R.FAILED,
    },
}


@pytest.fixture(autouse=True)
def supervision_root(tmp_path: Path) -> Iterator[Path]:
    """Bind the preflight's supervision root under ``tmp_path``; never created.

    Every row only inspects paths under it -- ``lstat`` of a planned result path,
    or ``remove_command_root`` of an absent root, which plan 7.5 makes a success --
    so the teardown proves nothing was written there.
    """
    global _SUPERVISION_ROOT
    root = tmp_path / "supervision"
    _SUPERVISION_ROOT = root
    try:
        yield root
    finally:
        _SUPERVISION_ROOT = None
        assert not root.exists()


def _checked_out(database: SqliteDatabase) -> int:
    """Connections the pool has lent out, not counting this probe's own."""
    with database.connection() as connection:
        pool = connection.engine.pool
        assert isinstance(pool, QueuePool)
        return pool.checkedout() - 1


def _in_transaction[T](
    unit_of_work: SqliteUnitOfWork, act: Callable[[SqliteTransaction], Result[T]]
) -> T:
    """One committed transaction; released in ``finally`` on every path."""
    transaction = unit_of_work.begin()
    try:
        value = ok(act(transaction))
        ok(transaction.commit())
        return value
    finally:
        transaction.rollback()


def _read[T](database: SqliteDatabase, read: Callable[[SqliteTransaction], T]) -> T:
    """One fresh read-only transaction over a fresh root, rolled back."""
    transaction = SqliteUnitOfWork(database, FixedClock(INSTANT)).begin()
    try:
        return read(transaction)
    finally:
        transaction.rollback()


def sqlite_lifecycle_over(
    database: SqliteDatabase, now: datetime
) -> Stage5InvocationLifecycle:
    """The Stage 7 lifecycle composed over the reopened file (plan 7.1.2)."""
    clock = FixedClock(now)
    return Stage5InvocationLifecycle(
        unit_of_work=SqliteUnitOfWork(database, clock),
        clock=clock,
        diagnostics=SqliteDiagnosticRecorder(database, clock=clock),
    )


@dataclass(frozen=True, slots=True)
class _Identities:
    """Every identity one row seeds, derived deterministically from its name."""

    experiment_id: str
    slot_id: str
    run_id: str
    attempt_token: str
    invocation_id: str
    pid: int
    creation_identity: str


def _identities(name: str, index: int) -> _Identities:
    source = SequentialIdentitySource(f"task5-restart-{name}")
    pid = 4000 + index
    return _Identities(
        experiment_id=source.new_experiment_id(),
        slot_id=source.new_logical_slot_id(),
        run_id=source.new_run_id(),
        attempt_token=source.new_attempt_token(),
        invocation_id=source.new_invocation_id(),
        pid=pid,
        creation_identity=render_creation_identity(pid, SCRIPTED_CREATION_100NS + pid),
    )


@dataclass(frozen=True, slots=True)
class RestartRow:
    """One plan 8.5 row: what is seeded, and what the reopened pass must decide."""

    name: str
    index: int
    kind: CommandKind
    state: CommandInvocationState
    expected_action: ReconciliationAction
    expected_invocation_state: CommandInvocationState
    expected_run_state: EngineRunState | None
    expected_cleanup_complete: bool
    now: datetime = INSTANT
    presence: ProcessPresence = _P.ABSENT
    cleanup_complete: bool = True
    process_created: bool | None = None
    run_state: EngineRunState | None = None
    cancelled: bool = False
    expired: bool = False
    expected_codes: frozenset[str] = frozenset()
    expected_terminations: int = 0
    #: The error code of the stored ``primary_diagnostic_id`` after the pass, or
    #: ``None`` when the record carries no primary (the Stage 7 module's
    #: ``primary_code`` pin).
    expected_primary_code: str | None = None

    @property
    def identities(self) -> _Identities:
        return _identities(self.name, self.index)

    @property
    def has_run(self) -> bool:
        return self.kind is not _K.DESCRIBE

    @property
    def seeded_process_created(self) -> bool:
        return (
            self.state in _PROCESS_STATES
            if self.process_created is None
            else self.process_created
        )

    # -- seeding ---------------------------------------------------------------

    def seed(self, database: SqliteDatabase) -> None:
        """Seed the experiment, observation, run, diagnostic and invocation."""
        ids = self.identities
        clock = FixedClock(INSTANT)
        unit_of_work = SqliteUnitOfWork(database, clock)
        recorder = SqliteDiagnosticRecorder(database, clock=clock)
        seeded_at = INSTANT - _SEED_OFFSET
        if self.expired:
            seeded_at -= _EXPIRED_OFFSET
        run: EngineRunRecord | None = None
        experiment_revision = 0
        if self.has_run:
            slot = SelectedEngineSlot(
                logical_slot_id=ids.slot_id,
                slot_ordinal=0,
                adapter=_ADAPTER,
                engine=_FAKE_ENGINE,
            )
            experiment = sample_experiment(
                ExperimentState.RUNNING,
                experiment_id=ids.experiment_id,
                draft=sample_draft(selected_engine_slots=(slot,)),
                created_at_utc=seeded_at,
            )
            experiment_revision = experiment.revision
            _in_transaction(unit_of_work, lambda t: t.experiments.add(experiment))
            _in_transaction(
                unit_of_work,
                lambda t: t.availability_observation_writer.add(
                    sample_observation(
                        _OBSERVATION_ID,
                        adapter_name=_ADAPTER.adapter_name,
                        adapter_version=_ADAPTER.adapter_version,
                    )
                ),
            )
            chosen = (
                _MATCHING_RUN_STATE[self.kind][self.state]
                if self.run_state is None
                else self.run_state
            )
            run = sample_run(
                chosen,
                run_id=ids.run_id,
                experiment_id=ids.experiment_id,
                logical_slot_id=ids.slot_id,
                adapter=_ADAPTER,
                engine=_FAKE_ENGINE,
                attempt_token=ids.attempt_token,
                availability_observation_id=_OBSERVATION_ID,
                created_at_utc=seeded_at,
            )
            if isinstance(run.primary_terminal_diagnostic_id, str):
                ok(recorder.record(sample_diagnostic()))
            seeded_run = run
            _in_transaction(
                unit_of_work, lambda t: t.engine_runs.add_attempt(seeded_run)
            )
        via: CommandInvocationState | None = None
        if self.state in (_C.CANCELLED, _C.TIMED_OUT):
            via = _C.RUNNING if self.seeded_process_created else _C.STARTING
        facts: dict[str, Any] = {
            "kind": self.kind,
            "via": via,
            "invocation_id": ids.invocation_id,
            "adapter_name": _ADAPTER.adapter_name,
            "adapter_version": _ADAPTER.adapter_version,
            "timeout_seconds": TIMEOUT_SECONDS,
            "created_at_utc": seeded_at,
        }
        if run is not None:
            facts["run_id"] = run.run_id
            facts["request_hash"] = run.request_hash
        record = sample_invocation(self.state, **facts)
        payload = record.model_dump(mode="python")
        if record.process_created:
            payload["pid_identity"] = sample_process_identity(
                pid=ids.pid,
                creation_identity=ids.creation_identity,
                supervisor_instance_id=SUPERVISOR_INSTANCE_ID,
            )
        if self.state in TERMINAL_COMMAND_INVOCATION_STATES and self.cleanup_complete:
            payload["cleanup_complete"] = True
            payload["cleanup_completed_at_utc"] = payload["completed_at_utc"]
        stored = CommandInvocationRecord.model_validate(payload)
        if isinstance(stored.primary_diagnostic_id, str):
            ok(recorder.record(sample_diagnostic()))
        _in_transaction(unit_of_work, lambda t: t.command_invocations.add(stored))
        if self.cancelled:
            ok(
                cancel_experiment(
                    CancelExperimentRequest(
                        schema_version="1.0.0",
                        experiment_id=ids.experiment_id,
                        expected_revision=experiment_revision,
                        correlation_id="task5-cancel",
                    ),
                    unit_of_work=unit_of_work,
                    clock=clock,
                )
            )
        assert unit_of_work.open_transactions() == ()

    # -- the pass's collaborators ----------------------------------------------

    @property
    def controller(self) -> ScriptedProcessController:
        """A fresh scripted controller reporting this row's presence."""
        controller = ScriptedProcessController(clock=None)
        controller.inspection = self.presence
        return controller

    @property
    def preflight(self) -> PathPreflight:
        root = _SUPERVISION_ROOT
        assert root is not None, "the supervision_root fixture binds the root"
        return PathPreflight(
            supervision_root=str(root),
            long_paths_supported=False,
            directory_ceiling=247,
            file_ceiling=259,
            probed_at_utc=INSTANT,
        )

    # -- expectations ------------------------------------------------------------

    def entry(
        self, report: Result[ReconciliationReport] | ReconciliationReport
    ) -> InvocationReconciliation:
        """This row's entry of a report, or of the ``Result`` carrying one."""
        unwrapped = report if isinstance(report, ReconciliationReport) else ok(report)
        (found,) = (
            item
            for item in unwrapped.entries
            if item.invocation_id == self.identities.invocation_id
        )
        return found

    def expected_decision(
        self, report: Result[ReconciliationReport] | ReconciliationReport
    ) -> bool:
        """The plan 8.5 decision for this row; asserts explain a mismatch."""
        entry = self.entry(report)
        assert entry.action is self.expected_action, (self.name, entry.action)
        assert entry.state_before is self.state
        assert entry.record_after.state is self.expected_invocation_state, self.name
        codes = {diagnostic.error_code for diagnostic in entry.diagnostics}
        assert self.expected_codes <= codes, (self.name, codes)
        if self.expected_action is _A.LEFT_RUNNING_AWAITING_DEADLINE and (
            self.kind is _K.RUN
        ):
            assert entry.manifest_present is False
        return True

    def stored_invocation(self, database: SqliteDatabase) -> CommandInvocationRecord:
        identity = self.identities.invocation_id
        return _read(database, lambda t: ok(t.command_invocations.get(identity)))

    def stored_run(self, database: SqliteDatabase) -> EngineRunRecord | None:
        if not self.has_run:
            return None
        identity = self.identities.run_id
        return _read(database, lambda t: ok(t.engine_runs.get(identity)))

    def expected_state(self, database: SqliteDatabase) -> bool:
        """The durable state after the pass, read through a fresh transaction."""
        invocation = self.stored_invocation(database)
        assert invocation.state is self.expected_invocation_state, self.name
        assert invocation.cleanup_complete is self.expected_cleanup_complete, self.name
        run = self.stored_run(database)
        if self.expected_run_state is None:
            assert run is None
        else:
            assert run is not None
            assert run.state is self.expected_run_state, (self.name, run.state)
        if invocation.state is self.state and self.state not in (
            TERMINAL_COMMAND_INVOCATION_STATES
        ):
            assert invocation.revision == self.revision_when_seeded(), self.name
        # The process facts are never invented: ``process_created`` is the seeded
        # flag, and an exit pair exists exactly on the seeded EXITED record.
        assert invocation.process_created is self.seeded_process_created, self.name
        if invocation.state is _C.EXITED:
            assert invocation.native_exit_value == 0, self.name
        else:
            assert not isinstance(invocation.native_exit_value, int), self.name
        # The stored primary, resolved through a fresh diagnostic read.
        primary_id = invocation.primary_diagnostic_id
        if self.expected_primary_code is None:
            assert not isinstance(primary_id, str), (self.name, primary_id)
        else:
            assert isinstance(primary_id, str), self.name
            identity: str = primary_id
            primary = _read(database, lambda t: ok(t.diagnostics.get(identity)))
            assert primary.error_code == self.expected_primary_code, self.name
            assert identity in invocation.diagnostic_ids
            terminalized = self.state not in TERMINAL_COMMAND_INVOCATION_STATES
            if terminalized and run is not None:
                # The coupled run edge references the same primary (plan 5.2).
                assert run.primary_terminal_diagnostic_id == identity, self.name
        return True

    def revision_when_seeded(self) -> int:
        """The revision ``sample_invocation`` assigns the seeded state."""
        via = _C.RUNNING if self.seeded_process_created else _C.STARTING
        return sample_invocation(
            self.state,
            kind=self.kind,
            via=via if self.state in (_C.CANCELLED, _C.TIMED_OUT) else None,
            timeout_seconds=TIMEOUT_SECONDS,
        ).revision

    def reached_exited_or_success(self, database: SqliteDatabase) -> bool:
        """Did the pass manufacture an exit or a success from durable facts?"""
        invocation = self.stored_invocation(database)
        reached_exited = invocation.state is _C.EXITED and self.state is not _C.EXITED
        run = self.stored_run(database)
        reached_success = run is not None and run.state in _SUCCESS_RUN_STATES
        return reached_exited or reached_success


RESTART_ROWS: Final[tuple[RestartRow, ...]] = (
    RestartRow(
        name="describe-pending",
        index=1,
        kind=_K.DESCRIBE,
        state=_C.PENDING,
        expected_action=_A.LEFT_PENDING,
        expected_invocation_state=_C.PENDING,
        expected_run_state=None,
        expected_cleanup_complete=False,
    ),
    RestartRow(
        name="run-starting-cancelled",
        index=2,
        kind=_K.RUN,
        state=_C.STARTING,
        cancelled=True,
        expected_action=_A.TERMINALIZED_CANCELLED,
        expected_invocation_state=_C.CANCELLED,
        expected_run_state=_R.CANCELLED,
        expected_cleanup_complete=True,
        expected_codes=frozenset({PROCESS_CANCELLED}),
        expected_primary_code=PROCESS_CANCELLED,
    ),
    RestartRow(
        name="validate-starting-expired",
        index=3,
        kind=_K.VALIDATE,
        state=_C.STARTING,
        expired=True,
        expected_action=_A.TERMINALIZED_TIMED_OUT,
        expected_invocation_state=_C.TIMED_OUT,
        expected_run_state=_R.TIMED_OUT,
        expected_cleanup_complete=True,
        expected_codes=frozenset({PROCESS_VALIDATE_TIMED_OUT}),
        expected_primary_code=PROCESS_VALIDATE_TIMED_OUT,
    ),
    RestartRow(
        name="describe-starting",
        index=4,
        kind=_K.DESCRIBE,
        state=_C.STARTING,
        expected_action=_A.TERMINALIZED_FAILED_TO_START,
        expected_invocation_state=_C.FAILED_TO_START,
        expected_run_state=None,
        expected_cleanup_complete=True,
        expected_codes=frozenset({PROCESS_LAUNCH_NOT_COMMITTED}),
        expected_primary_code=PROCESS_LAUNCH_NOT_COMMITTED,
    ),
    RestartRow(
        name="run-running-beside-a-starting-run",
        index=5,
        kind=_K.RUN,
        state=_C.RUNNING,
        run_state=_R.STARTING,
        expected_action=_A.INVARIANT_REPORTED,
        expected_invocation_state=_C.RUNNING,
        expected_run_state=_R.STARTING,
        expected_cleanup_complete=False,
        expected_codes=frozenset({CORE_INVARIANT_VIOLATION}),
    ),
    RestartRow(
        name="validate-running-beside-a-ready-run",
        index=6,
        kind=_K.VALIDATE,
        state=_C.RUNNING,
        run_state=_R.READY,
        expected_action=_A.INVARIANT_REPORTED,
        expected_invocation_state=_C.RUNNING,
        expected_run_state=_R.READY,
        expected_cleanup_complete=False,
        expected_codes=frozenset({CORE_INVARIANT_VIOLATION}),
    ),
    RestartRow(
        name="run-running-alive-matching",
        index=7,
        kind=_K.RUN,
        state=_C.RUNNING,
        presence=_P.ALIVE_MATCHING,
        expected_action=_A.TERMINALIZED_PROTOCOL_FAILED,
        expected_invocation_state=_C.PROTOCOL_FAILED,
        expected_run_state=_R.FAILED,
        expected_cleanup_complete=True,
        expected_codes=frozenset(
            {PROCESS_ORCHESTRATOR_RESTART_LOST_SUPERVISION, PROCESS_FORCED_TERMINATION}
        ),
        expected_terminations=1,
        expected_primary_code=PROCESS_ORCHESTRATOR_RESTART_LOST_SUPERVISION,
    ),
    RestartRow(
        name="run-running-alive-different-identity",
        index=8,
        kind=_K.RUN,
        state=_C.RUNNING,
        presence=_P.ALIVE_DIFFERENT_IDENTITY,
        expected_action=_A.LEFT_RUNNING_AWAITING_DEADLINE,
        expected_invocation_state=_C.RUNNING,
        expected_run_state=_R.RUNNING,
        expected_cleanup_complete=False,
        expected_codes=frozenset({PROCESS_PID_REUSE_DETECTED}),
    ),
    RestartRow(
        name="run-running-cancelled",
        index=9,
        kind=_K.RUN,
        state=_C.RUNNING,
        cancelled=True,
        expected_action=_A.TERMINALIZED_CANCELLED,
        expected_invocation_state=_C.CANCELLED,
        expected_run_state=_R.CANCELLED,
        expected_cleanup_complete=True,
        expected_codes=frozenset({PROCESS_CANCELLED}),
        expected_primary_code=PROCESS_CANCELLED,
    ),
    RestartRow(
        name="validate-running-undetermined-expired",
        index=10,
        kind=_K.VALIDATE,
        state=_C.RUNNING,
        presence=_P.UNDETERMINED,
        expired=True,
        expected_action=_A.TERMINALIZED_TIMED_OUT,
        expected_invocation_state=_C.TIMED_OUT,
        expected_run_state=_R.TIMED_OUT,
        expected_cleanup_complete=True,
        expected_codes=frozenset({PROCESS_VALIDATE_TIMED_OUT}),
        expected_primary_code=PROCESS_VALIDATE_TIMED_OUT,
    ),
    RestartRow(
        name="run-running-absent",
        index=11,
        kind=_K.RUN,
        state=_C.RUNNING,
        expected_action=_A.LEFT_RUNNING_AWAITING_DEADLINE,
        expected_invocation_state=_C.RUNNING,
        expected_run_state=_R.RUNNING,
        expected_cleanup_complete=False,
    ),
    RestartRow(
        name="run-cancelled-cleanup-pending-live-tree",
        index=12,
        kind=_K.RUN,
        state=_C.CANCELLED,
        cleanup_complete=False,
        process_created=True,
        presence=_P.ALIVE_MATCHING,
        expected_action=_A.CLEANUP_COMPLETED,
        expected_invocation_state=_C.CANCELLED,
        expected_run_state=_R.CANCELLED,
        expected_cleanup_complete=True,
        expected_codes=frozenset({PROCESS_FORCED_TERMINATION}),
        expected_terminations=1,
        expected_primary_code=_SEEDED_PRIMARY_CODE,
    ),
    RestartRow(
        name="validate-timed-out-cleanup-pending",
        index=13,
        kind=_K.VALIDATE,
        state=_C.TIMED_OUT,
        cleanup_complete=False,
        process_created=True,
        expected_action=_A.CLEANUP_COMPLETED,
        expected_invocation_state=_C.TIMED_OUT,
        expected_run_state=_R.TIMED_OUT,
        expected_cleanup_complete=True,
        expected_primary_code=_SEEDED_PRIMARY_CODE,
    ),
    RestartRow(
        name="run-exited-cleanup-pending",
        index=14,
        kind=_K.RUN,
        state=_C.EXITED,
        cleanup_complete=False,
        expected_action=_A.CLEANUP_COMPLETED,
        expected_invocation_state=_C.EXITED,
        expected_run_state=_R.RUNNING,
        expected_cleanup_complete=True,
    ),
    RestartRow(
        name="describe-failed-to-start-cleanup-pending",
        index=15,
        kind=_K.DESCRIBE,
        state=_C.FAILED_TO_START,
        cleanup_complete=False,
        expected_action=_A.CLEANUP_COMPLETED,
        expected_invocation_state=_C.FAILED_TO_START,
        expected_run_state=None,
        expected_cleanup_complete=True,
        expected_primary_code=_SEEDED_PRIMARY_CODE,
    ),
)


def _reconcile(
    database: SqliteDatabase, now: datetime, controller: ScriptedProcessController
) -> ReconciliationReport:
    return ok(
        reconcile_invocations(
            source=SqliteReconciliationSource(database, FixedClock(now)),
            lifecycle=sqlite_lifecycle_over(database, now),
            controller=controller,
            preflight=RESTART_ROWS[0].preflight,
            clock=FixedClock(now),
            supervisor_instance_id=SUPERVISOR_INSTANCE_ID,
            observer=MISSING,
        )
    )


def _text_columns(database: SqliteDatabase, table: str) -> bytes:
    """Every text-valued cell of ``table`` through an independent connection."""
    connection = raw_connection(database.path)
    try:
        rows = connection.execute(f"SELECT * FROM {table}").fetchall()  # noqa: S608
    finally:
        connection.close()
    return "\n".join(
        str(value) for row in rows for value in row if isinstance(value, str)
    ).encode("utf-8")


# --------------------------------------------------------------------------
# Plan Task 5 Step 1 (verbatim)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("row", RESTART_ROWS, ids=[row.name for row in RESTART_ROWS])
def test_every_reconciliation_row_over_a_reopened_database(
    tmp_path: Path, row: RestartRow
) -> None:
    first = open_test_database(tmp_path, clock=FixedClock(INSTANT))
    try:
        row.seed(first)
    finally:
        first.close()
    reopened = open_test_database(tmp_path, clock=FixedClock(row.now))
    try:
        report = reconcile_invocations(
            source=SqliteReconciliationSource(reopened, FixedClock(row.now)),
            lifecycle=sqlite_lifecycle_over(reopened, row.now),
            controller=row.controller,
            preflight=row.preflight,
            clock=FixedClock(row.now),
            supervisor_instance_id=SUPERVISOR_INSTANCE_ID,
            observer=MISSING,
        )
        assert row.expected_decision(report)
        assert row.expected_state(reopened)
        assert not row.reached_exited_or_success(reopened)
        assert _checked_out(reopened) == 0  # added to the sketch (module docstring)
    finally:
        reopened.close()


# --------------------------------------------------------------------------
# Every row in one file: reopen, one pass, a second pass, the report, tokens
# --------------------------------------------------------------------------


def test_every_row_in_one_reopened_file_matches_the_table_and_replays_idempotently(
    tmp_path: Path, supervision_root: Path
) -> None:
    first = open_test_database(tmp_path, clock=FixedClock(INSTANT))
    try:
        for row in RESTART_ROWS:
            row.seed(first)
        seeded = {row.name: row.stored_invocation(first) for row in RESTART_ROWS}
        assert first.consistency_report().dangling_diagnostic_references == 0
    finally:
        first.close()
    assert not supervision_root.exists()
    reopened = open_test_database(tmp_path, clock=FixedClock(INSTANT))
    try:
        # Close-and-reopen reconstructs every fact the pass needs: the source over
        # the reopened file lists exactly the seeded records, decoded whole.
        listed = ok(
            SqliteReconciliationSource(
                reopened, FixedClock(INSTANT)
            ).list_reconciliation_targets()
        )
        assert {record.invocation_id for record in listed} == {
            row.identities.invocation_id for row in RESTART_ROWS
        }
        assert {record.invocation_id: record for record in listed} == {
            record.invocation_id: record for record in seeded.values()
        }
        controller = _RowController()
        report = _reconcile(reopened, INSTANT, controller)
        assert len(report.entries) == len(RESTART_ROWS)
        assert [entry.invocation_id for entry in report.entries] == sorted(
            (entry.invocation_id for entry in report.entries),
            key=lambda identity: (seeded_created_at(seeded, identity), identity),
        )
        for row in RESTART_ROWS:
            assert row.expected_decision(report), row.name
            assert row.expected_state(reopened), row.name
            assert not row.reached_exited_or_success(reopened), row.name
        assert controller.terminate_calls == [FORCED_TERMINATION_EXIT_CODE] * sum(
            row.expected_terminations for row in RESTART_ROWS
        )
        # Terminal seeds never change state; nonterminal seeds never become EXITED.
        for row in RESTART_ROWS:
            after = row.stored_invocation(reopened)
            if row.state in TERMINAL_COMMAND_INVOCATION_STATES:
                assert after.state is row.state
            else:
                assert after.state is not _C.EXITED
        runs = _read(
            reopened,
            lambda t: tuple(
                ok(t.engine_runs.get(row.identities.run_id))
                for row in RESTART_ROWS
                if row.has_run
            ),
        )
        assert len(runs) == sum(1 for row in RESTART_ROWS if row.has_run)
        assert all(run.state not in _SUCCESS_RUN_STATES for run in runs)
        report_after_first = reopened.consistency_report()
        assert report_after_first.dangling_diagnostic_references == 0
        assert report_after_first.causal_edge_mismatches == 0
        assert report_after_first.unresolved_causal_references == 0
        assert report_after_first.foreign_key_violations == 0
        assert report_after_first.slot_identity_mismatches == 0
        assert report_after_first.spec_projection_mismatches == 0
        assert report_after_first.registry_projection_mismatches == 0
        # Every seeded RUNNING experiment carries no snapshot; the cancelled ones
        # left that count (plan 4.6).
        assert report_after_first.queued_without_snapshot == sum(
            1 for row in RESTART_ROWS if row.has_run and not row.cancelled
        )
        assert _checked_out(reopened) == 0
        # The second pass: only the rows the first left open are targets, each
        # decides the same way, nothing is terminated again and no row changes.
        before_second = {
            row.name: row.stored_invocation(reopened) for row in RESTART_ROWS
        }
        again = _RowController()
        second = _reconcile(reopened, INSTANT, again)
        remaining = {
            row.identities.invocation_id: row
            for row in RESTART_ROWS
            if row.expected_action
            in (
                _A.LEFT_PENDING,
                _A.INVARIANT_REPORTED,
                _A.LEFT_RUNNING_AWAITING_DEADLINE,
            )
        }
        assert {entry.invocation_id for entry in second.entries} == set(remaining)
        for entry in second.entries:
            assert entry.action is remaining[entry.invocation_id].expected_action
        assert again.terminate_calls == []
        assert {
            row.name: row.stored_invocation(reopened) for row in RESTART_ROWS
        } == before_second
        assert reopened.consistency_report() == report_after_first
        # No raw attempt token reaches the report, a diagnostic or a stored row of
        # any table a token could plausibly leak into.
        report_bytes = canonical_json_bytes(report) + canonical_json_bytes(second)
        stored_text = b"\n".join(
            _text_columns(reopened, table)
            for table in (
                "diagnostics",
                "command_invocations",
                "engine_runs",
                "run_events",
            )
        )
        assert stored_text
        for row in RESTART_ROWS:
            if row.has_run:
                needle = row.identities.attempt_token.encode("utf-8")
                assert needle not in report_bytes
                assert needle not in stored_text
        assert _checked_out(reopened) == 0
    finally:
        reopened.close()
    assert not supervision_root.exists()


def seeded_created_at(
    seeded: dict[str, CommandInvocationRecord], invocation_id: str
) -> datetime:
    (record,) = (
        item for item in seeded.values() if item.invocation_id == invocation_id
    )
    return record.created_at_utc


class _RowController(ScriptedProcessController):
    """The scripted controller with a per-identity presence map for the one-file pass.

    ``inspect`` reads the presence the row declared for its own creation identity;
    a terminated identity is ``ABSENT`` (inherited).
    """

    def __init__(self) -> None:
        super().__init__(clock=None)
        self.presence_of: dict[str, ProcessPresence] = {
            row.identities.creation_identity: row.presence for row in RESTART_ROWS
        }

    def inspect(self, identity: Any) -> Any:
        saved = self.inspection
        self.inspection = self.presence_of.get(identity.creation_identity, saved)
        try:
            return super().inspect(identity)
        finally:
            self.inspection = saved


def test_a_run_facts_miss_over_the_reopened_file_is_reported_not_repaired(
    tmp_path: Path,
) -> None:
    """C-23: a linked record whose run facts fail is ``INVARIANT_REPORTED`` from one
    snapshot, and the pass neither writes it nor stops."""
    row = RESTART_ROWS[10]  # run-running-absent
    first = open_test_database(tmp_path, clock=FixedClock(INSTANT))
    try:
        row.seed(first)
    finally:
        first.close()
    reopened = open_test_database(tmp_path, clock=FixedClock(INSTANT))
    try:

        class _FactsMissingSource:
            def __init__(self, inner: SqliteReconciliationSource) -> None:
                self._inner = inner

            def list_reconciliation_targets(self) -> Any:
                return self._inner.list_reconciliation_targets()

            def run_facts(self, run_id: Any) -> Any:
                return self._inner.run_facts("run_00000000-0000-4000-8000-000000000000")

        inner = SqliteReconciliationSource(reopened, FixedClock(INSTANT))
        missing: Failure | Any = inner.run_facts(
            "run_00000000-0000-4000-8000-000000000000"
        )
        assert isinstance(missing, Failure)
        assert "does not exist" in missing.diagnostics[0].message
        report = ok(
            reconcile_invocations(
                source=_FactsMissingSource(inner),
                lifecycle=sqlite_lifecycle_over(reopened, INSTANT),
                controller=row.controller,
                preflight=row.preflight,
                clock=FixedClock(INSTANT),
                supervisor_instance_id=SUPERVISOR_INSTANCE_ID,
                observer=MISSING,
            )
        )
        (entry,) = report.entries
        assert entry.action is _A.INVARIANT_REPORTED
        codes = [diagnostic.error_code for diagnostic in entry.diagnostics]
        assert codes.count(CORE_INVARIANT_VIOLATION) == 2  # minted plus the source's
        assert row.stored_invocation(reopened).state is _C.RUNNING
        assert row.stored_invocation(reopened).revision == row.revision_when_seeded()
        assert _checked_out(reopened) == 0
    finally:
        reopened.close()
