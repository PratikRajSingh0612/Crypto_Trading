"""Stage 7 Task 7: restart reconciliation over the scripted controller (plan 8.5).

The first RED of Task 7 is the ``crypto_lab.process_supervision.reconciliation`` import
below. The ``reconciler`` fixture of plan Task 7 mints, per ``run_one`` call, a fresh
``RUNNING`` experiment with its frozen slot compatibility, a fresh run for a linked kind
and a fresh invocation by direct store write, stamped a minute before the fixture clock
so a reconciliation write never moves ``updated_at_utc`` backwards and ``deadline_utc``
stays relative to the clock; ``cancelled=True`` cancels the experiment through the
merged ``cancel_experiment``; ``past_deadline=True`` advances the clock past the seeded
deadline; ``presence`` is written onto the scripted controller before the pass. The
lifecycle is a real ``Stage5InvocationLifecycle`` wrapped in the recording double, the
source is ``InMemoryReconciliationSource`` and no process is ever launched.

Test-local readings, declared rather than inferred silently:

- The plan's Step 1 tests are copied verbatim except for the strict-mypy fixture
  annotation and the PT018 splits of the plan's compound asserts (every clause kept, in
  order).
- ``run_every_row`` seeds one record per plan 8.5 row into one store and runs one pass,
  so the controller of this module (a subclass of the scripted controller) reads a
  per-identity presence map first and falls back to the scripted ``inspection``; the
  rows that need an elapsed deadline in the same pass are seeded with an older
  ``created_at_utc`` instead of advancing the shared clock. The subclass also reports a
  different observed creation identity for ``ALIVE_DIFFERENT_IDENTITY`` (the scripted
  double echoes the stored one) and can keep a terminated identity alive (a surviving
  tree).
- ``hold_request_open`` peeks the next invocation identifier through a deep copy of the
  sequential identity source (identical construction order yields identical ids), so it
  plants ``<root>\\<invocation_id>\\request.json`` under the id the next ``run_one``
  mints and holds it open with a plain read handle (Task 3's technique: ``unlink``
  reports ``sharing_violation:32``).
"""

from __future__ import annotations

import ast
import copy
import inspect
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Final

import pytest
from pydantic import ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab import process_supervision as package
from crypto_lab.adapters.diagnostics import (
    PROCESS_CANCELLED,
    PROCESS_DESCRIBE_TIMED_OUT,
    PROCESS_RUN_TIMED_OUT,
    PROCESS_START_TIMED_OUT,
    PROCESS_VALIDATE_TIMED_OUT,
    stage6_diagnostic,
)
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.command_invocation import (
    CommandInvocationRecord,
    ProcessIdentity,
)
from crypto_lab.domain.diagnostics import Diagnostic
from crypto_lab.domain.engine_run import EngineRunRecord
from crypto_lab.domain.experiment import (
    AdapterIdentity,
    EngineIdentity,
    ExperimentRecord,
    SelectedEngineSlot,
)
from crypto_lab.domain.identifiers import RunId
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.experiments.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
    stage5_failure,
)
from crypto_lab.experiments.experiment_service import cancel_experiment
from crypto_lab.experiments.requests import CancelExperimentRequest
from crypto_lab.experiments.supervision_lifecycle import Stage5InvocationLifecycle
from crypto_lab.process_supervision import reconciliation as reconciliation_module
from crypto_lab.process_supervision.diagnostics import (
    CORE_INVARIANT_VIOLATION,
    PROCESS_CLEANUP_FAILED,
    PROCESS_FORCED_TERMINATION,
    PROCESS_LAUNCH_NOT_COMMITTED,
    PROCESS_ORCHESTRATOR_RESTART_LOST_SUPERVISION,
    PROCESS_PID_REUSE_DETECTED,
)
from crypto_lab.process_supervision.models import (
    FORCED_TERMINATION_EXIT_CODE,
    CleanupAction,
    CleanupFailure,
    InvocationReconciliation,
    ProcessInspection,
    ProcessPresence,
    ReconciliationAction,
    ReconciliationReport,
    RunReconciliationFacts,
    SupervisionTraceEntry,
    SupervisionTraceKind,
    TerminationReport,
    parse_creation_identity,
    render_creation_identity,
)
from crypto_lab.process_supervision.reconciliation import reconcile_invocations
from crypto_lab.process_supervision.roots import PathPreflight, plan_command_paths
from crypto_lab.process_supervision.windows_process import WindowsProcessController
from doubles.experiments import (
    INSTANT,
    FixedClock,
    InMemoryBackingStore,
    InMemoryUnitOfWork,
    SequentialIdentitySource,
    sample_draft,
    sample_experiment,
    sample_invocation,
    sample_process_identity,
    sample_run,
)
from doubles.supervision import (
    SCRIPTED_CREATION_100NS,
    SCRIPTED_SUPERVISOR_INSTANCE_ID,
    InMemoryReconciliationSource,
    RecordingLifecycle,
    RecordingObserver,
    ScriptedProcessController,
    SeedingDiagnosticRecorder,
)

_INSTANT: Final = INSTANT
#: Seeds are stamped a minute before the clock (the Task 5 and 6 precedent), so the
#: sample records' ``updated_at_utc`` never lies after a reconciliation write.
_SEED_OFFSET: Final = timedelta(seconds=60)
_ADAPTER_NAME: Final = "fake.conformant"
_ADAPTER_VERSION: Final = "1.0.0"
_FAKE_ENGINE: Final = EngineIdentity(engine_name="fake.engine", engine_version="1.0.0")
_RECONCILER: Final = "process_supervision.reconciliation"
_REPOSITORY: Final = Path(__file__).resolve().parents[3]
_STAGE3_GUARD: Final = _REPOSITORY / "tests/safety/test_stage3_boundaries.py"
_PACKAGE_LAYOUT: Final = _REPOSITORY / "tests/unit/test_package_layout.py"
_MODULE_PATH: Final = (
    _REPOSITORY / "src/crypto_lab/process_supervision/reconciliation.py"
)
_PACKAGE_INIT: Final = _REPOSITORY / "src/crypto_lab/process_supervision/__init__.py"
#: Plan 2.6 and 3.1: the roots the reconciliation module may import.
_MODULE_ROOTS: Final = frozenset(
    {
        "__future__",
        "contextlib",
        "crypto_lab",
        "dataclasses",
        "datetime",
        "enum",
        "pathlib",
        "pydantic",
        "typing",
    }
)
_PURITY_SUBSTRINGS: Final = (
    "time.time",
    "random.",
    "datetime.now",
    "uuid4(",
    "os.environ",
    "import random",
    "import doubles",
    "from doubles",
    "sandbox",
    "subprocess",
    "read_output_file",
    "request_envelope",
)
TIMEOUT_SECONDS: Final = 120

DESCRIBE: Final = CommandKind.DESCRIBE
VALIDATE: Final = CommandKind.VALIDATE
RUN: Final = CommandKind.RUN
PENDING: Final = CommandInvocationState.PENDING
STARTING: Final = CommandInvocationState.STARTING
RUNNING: Final = CommandInvocationState.RUNNING
EXITED: Final = CommandInvocationState.EXITED
FAILED_TO_START: Final = CommandInvocationState.FAILED_TO_START
CANCELLED: Final = CommandInvocationState.CANCELLED
TIMED_OUT: Final = CommandInvocationState.TIMED_OUT
PROTOCOL_FAILED: Final = CommandInvocationState.PROTOCOL_FAILED
ALIVE_MATCHING: Final = ProcessPresence.ALIVE_MATCHING
ALIVE_DIFFERENT_IDENTITY: Final = ProcessPresence.ALIVE_DIFFERENT_IDENTITY
ABSENT: Final = ProcessPresence.ABSENT
UNDETERMINED: Final = ProcessPresence.UNDETERMINED
LEFT_PENDING: Final = ReconciliationAction.LEFT_PENDING
TERMINALIZED_FAILED_TO_START: Final = ReconciliationAction.TERMINALIZED_FAILED_TO_START
TERMINALIZED_TIMED_OUT: Final = ReconciliationAction.TERMINALIZED_TIMED_OUT
TERMINALIZED_CANCELLED: Final = ReconciliationAction.TERMINALIZED_CANCELLED
TERMINALIZED_PROTOCOL_FAILED: Final = ReconciliationAction.TERMINALIZED_PROTOCOL_FAILED
LEFT_RUNNING_AWAITING_DEADLINE: Final = (
    ReconciliationAction.LEFT_RUNNING_AWAITING_DEADLINE
)
CLEANUP_COMPLETED: Final = ReconciliationAction.CLEANUP_COMPLETED
CLEANUP_FAILED: Final = ReconciliationAction.CLEANUP_FAILED
CLEANUP_STILL_FAILING: Final = ReconciliationAction.CLEANUP_STILL_FAILING
INVARIANT_REPORTED: Final = ReconciliationAction.INVARIANT_REPORTED
SKIPPED_EXTERNAL_WINNER: Final = ReconciliationAction.SKIPPED_EXTERNAL_WINNER
RECONCILIATION_DECISION: Final = SupervisionTraceKind.RECONCILIATION_DECISION

#: Plan 3.5: the ``STARTING``-origin timeout primaries (``START_TIMED_OUT`` for a RUN).
TIMEOUT_CODE_OF: Final[dict[CommandKind, str]] = {
    DESCRIBE: PROCESS_DESCRIBE_TIMED_OUT,
    VALIDATE: PROCESS_VALIDATE_TIMED_OUT,
    RUN: PROCESS_START_TIMED_OUT,
}
#: Plan 5.2: the coupled run target of each terminalizing action.
COUPLED_RUN_TARGET: Final[dict[ReconciliationAction, EngineRunState]] = {
    TERMINALIZED_FAILED_TO_START: EngineRunState.FAILED,
    TERMINALIZED_CANCELLED: EngineRunState.CANCELLED,
    TERMINALIZED_TIMED_OUT: EngineRunState.TIMED_OUT,
    TERMINALIZED_PROTOCOL_FAILED: EngineRunState.FAILED,
}
type _RunStateOf = dict[CommandInvocationState, EngineRunState]
#: The run state seeded beside each invocation state when a test names none.
_MATCHING_RUN_STATE: Final[dict[CommandKind, _RunStateOf]] = {
    RUN: {
        PENDING: EngineRunState.READY,
        STARTING: EngineRunState.STARTING,
        RUNNING: EngineRunState.RUNNING,
        EXITED: EngineRunState.RUNNING,
        FAILED_TO_START: EngineRunState.FAILED,
        CANCELLED: EngineRunState.CANCELLED,
        TIMED_OUT: EngineRunState.TIMED_OUT,
        PROTOCOL_FAILED: EngineRunState.FAILED,
    },
    VALIDATE: {
        PENDING: EngineRunState.VALIDATING,
        STARTING: EngineRunState.VALIDATING,
        RUNNING: EngineRunState.VALIDATING,
        EXITED: EngineRunState.VALIDATING,
        FAILED_TO_START: EngineRunState.FAILED,
        CANCELLED: EngineRunState.CANCELLED,
        TIMED_OUT: EngineRunState.TIMED_OUT,
        PROTOCOL_FAILED: EngineRunState.FAILED,
    },
}
_PROCESS_STATES: Final = frozenset({RUNNING, EXITED, PROTOCOL_FAILED})
_TERMINAL_STATES: Final = frozenset(
    {EXITED, FAILED_TO_START, CANCELLED, TIMED_OUT, PROTOCOL_FAILED}
)
_SUCCESS_RUN_STATES: Final = frozenset(
    {EngineRunState.SUCCEEDED, EngineRunState.SUCCEEDED_WITH_WARNINGS}
)
#: The lifecycle members a reconciliation pass may call (plan 8.5).
_RECONCILER_MEMBERS: Final = frozenset({"load", "record_terminal", "enrich"})
#: Names Task 8 and later own; none may appear in the Task 7 module.
_LATER_TASK_NAMES: Final = (
    "TeeController",
    "SUPERVISION_FAKE_PATH",
    "supervision_fake",
    "WindowsProcessSupervisor",
)
_SIGNATURE_NAMES: Final = (
    "source",
    "lifecycle",
    "controller",
    "preflight",
    "clock",
    "supervisor_instance_id",
    "observer",
)


# --------------------------------------------------------------------------
# Helpers (``ok`` as in Task 3; the rest per plan Task 7)
# --------------------------------------------------------------------------


def ok[T](result: Success[T] | Failure) -> T:
    assert isinstance(result, Success), result
    return result.value


def codes_of_diagnostics(diagnostics: tuple[Diagnostic, ...]) -> tuple[str, ...]:
    return tuple(diagnostic.error_code for diagnostic in diagnostics)


_active: _Reconciler | None = None


def _fixture() -> _Reconciler:
    assert _active is not None, "the reconciler fixture is not active"
    return _active


def primary(record: CommandInvocationRecord) -> Diagnostic:
    identity = record.primary_diagnostic_id
    assert isinstance(identity, str), record
    return _fixture().store.diagnostics.live[identity]


def primary_code(record: CommandInvocationRecord) -> str:
    return primary(record).error_code


def stored_codes(record: CommandInvocationRecord) -> tuple[str, ...]:
    """The codes of the record's ``diagnostic_ids`` that the store can resolve."""
    live = _fixture().store.diagnostics.live
    return tuple(
        live[identity].error_code
        for identity in record.diagnostic_ids
        if identity in live
    )


def _literal(path: Path, name: str) -> Any:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        if value is not None and any(
            isinstance(target, ast.Name) and target.id == name for target in targets
        ):
            return ast.literal_eval(value)
    raise AssertionError(f"{name} is not assigned a literal in {path}")


def decision_entries(observer: RecordingObserver) -> list[SupervisionTraceEntry]:
    return [
        entry for entry in observer.entries if entry.kind is RECONCILIATION_DECISION
    ]


def _identity(record: CommandInvocationRecord) -> ProcessIdentity:
    identity = record.pid_identity
    assert isinstance(identity, ProcessIdentity), record
    return identity


# --------------------------------------------------------------------------
# The ``reconciler`` fixture of plan Task 7
# --------------------------------------------------------------------------


class _RowController(ScriptedProcessController):
    """The scripted controller with a per-identity presence map for ``run_every_row``.

    ``inspect`` reads ``presence_of[creation_identity]`` first and otherwise the
    scripted ``inspection``; a terminated identity is ``ABSENT`` (inherited) unless it
    is listed in ``survivors``; an ``ALIVE_DIFFERENT_IDENTITY`` inspection reports a
    creation time one tick later than the stored one, as a reused pid would.
    """

    def __init__(self) -> None:
        super().__init__(clock=None)
        self.presence_of: dict[str, ProcessPresence] = {}
        self.survivors: set[str] = set()

    def inspect(self, identity: ProcessIdentity) -> ProcessInspection:
        scripted = self.presence_of.get(identity.creation_identity, self.inspection)
        saved = self.inspection
        self.inspection = scripted
        try:
            inspection = super().inspect(identity)
        finally:
            self.inspection = saved
        if identity.creation_identity in self.survivors:
            return ProcessInspection(
                identity=identity,
                presence=ALIVE_MATCHING,
                observed_creation_identity=identity.creation_identity,
            )
        if inspection.presence is ALIVE_DIFFERENT_IDENTITY:
            parsed = parse_creation_identity(identity.creation_identity)
            return ProcessInspection(
                identity=identity,
                presence=ALIVE_DIFFERENT_IDENTITY,
                observed_creation_identity=render_creation_identity(
                    parsed.pid, parsed.creation_100ns + 1
                ),
            )
        return inspection


class _MisorderedSource:
    """A source violating the port's order and uniqueness (a determinism control)."""

    def __init__(self, inner: InMemoryReconciliationSource) -> None:
        self._inner = inner

    def list_reconciliation_targets(
        self,
    ) -> Result[tuple[CommandInvocationRecord, ...]]:
        listed: tuple[CommandInvocationRecord, ...] = ok(
            self._inner.list_reconciliation_targets()
        )
        targets = list(listed)
        targets.reverse()
        if targets:
            targets.append(targets[0])
        return Success[tuple[CommandInvocationRecord, ...]](
            outcome="SUCCESS", value=tuple(targets)
        )

    def run_facts(self, run_id: RunId) -> Result[RunReconciliationFacts]:
        return self._inner.run_facts(run_id)


class _FailingSource:
    """A source whose listing fails."""

    def list_reconciliation_targets(
        self,
    ) -> Result[tuple[CommandInvocationRecord, ...]]:
        return stage5_failure(
            INVARIANT_VIOLATION,
            "the listing failed",
            source_component="task7.failing_source",
            timestamp_utc=_INSTANT,
        )

    def run_facts(self, run_id: RunId) -> Result[RunReconciliationFacts]:
        raise AssertionError("run_facts must not be read after a failed listing")


class _RaisingObserver:
    def __init__(self) -> None:
        self.calls = 0

    def observe(self, entry: SupervisionTraceEntry) -> None:
        self.calls += 1
        raise RuntimeError("an observer never alters a decision")


class _Reconciler:
    """One store, one clock, one scripted controller; a fresh record per call."""

    def __init__(self, tmp_path: Path) -> None:
        self.root = tmp_path / "supervision"
        self.root.mkdir()
        self.clock = FixedClock(_INSTANT)
        self.store = InMemoryBackingStore()
        self.identity = SequentialIdentitySource("task7")
        self.unit_of_work = InMemoryUnitOfWork(self.store, clock=self.clock)
        self.recorder = SeedingDiagnosticRecorder(self.store)
        self.inner_lifecycle = Stage5InvocationLifecycle(
            unit_of_work=self.unit_of_work, clock=self.clock, diagnostics=self.recorder
        )
        self.lifecycle = RecordingLifecycle(self.inner_lifecycle)
        self.source = InMemoryReconciliationSource(self.store)
        self.controller = _RowController()
        self.observer = RecordingObserver()
        self.preflight = PathPreflight(
            supervision_root=str(self.root),
            long_paths_supported=False,
            directory_ceiling=247,
            file_ceiling=259,
            probed_at_utc=_INSTANT,
        )
        self.timeout_seconds = TIMEOUT_SECONDS
        self.supervisor_instance_id = SCRIPTED_SUPERVISOR_INSTANCE_ID
        self.reports: list[ReconciliationReport] = []
        self.raw_tokens: dict[str, str] = {}
        self._run_of: dict[str, str] = {}
        self._pid = 0

    # -- Seeding ------------------------------------------------------------------

    def next_invocation_id(self) -> str:
        """The id the next ``run_one`` mints (a deep copy of the counters)."""
        return copy.deepcopy(self.identity).new_invocation_id()

    def _seed_experiment(
        self, adapter: AdapterIdentity
    ) -> tuple[ExperimentRecord, str]:
        slot = SelectedEngineSlot(
            logical_slot_id=self.identity.new_logical_slot_id(),
            slot_ordinal=0,
            adapter=adapter,
            engine=_FAKE_ENGINE,
        )
        experiment = sample_experiment(
            ExperimentState.RUNNING,
            experiment_id=self.identity.new_experiment_id(),
            draft=sample_draft(selected_engine_slots=(slot,)),
            created_at_utc=self.clock.now_utc() - _SEED_OFFSET,
        )
        self.store.experiments.live[experiment.experiment_id] = experiment
        compatibility = experiment.slot_compatibility
        assert isinstance(compatibility, tuple)
        (frozen,) = compatibility
        return experiment, frozen.availability_observation_id

    def _seed_run(
        self,
        experiment: ExperimentRecord,
        observation_id: str,
        run_state: EngineRunState,
        *,
        seeded_at: datetime,
    ) -> EngineRunRecord:
        (slot,) = experiment.spec.selected_engine_slots
        run_id = self.identity.new_run_id()
        raw_token = self.identity.new_attempt_token()
        run = sample_run(
            run_state,
            run_id=run_id,
            experiment_id=experiment.experiment_id,
            logical_slot_id=slot.logical_slot_id,
            adapter=slot.adapter,
            engine=slot.engine,
            attempt_token=raw_token,
            availability_observation_id=observation_id,
            created_at_utc=seeded_at,
        )
        self.store.engine_runs.live[run_id] = run
        self.raw_tokens[run_id] = raw_token
        return run

    def _process_identity(self) -> ProcessIdentity:
        self._pid += 1
        pid = 4000 + self._pid
        return sample_process_identity(
            pid=pid,
            creation_identity=render_creation_identity(
                pid, SCRIPTED_CREATION_100NS + pid
            ),
            supervisor_instance_id=self.supervisor_instance_id,
        )

    def seed(
        self,
        kind: CommandKind,
        state: CommandInvocationState,
        *,
        presence: ProcessPresence = ABSENT,
        cleanup_complete: bool = True,
        process_created: bool | None = None,
        run_state: EngineRunState | None = None,
        cancelled: bool = False,
        expired: bool = False,
    ) -> str:
        """Seed one fresh experiment, run and invocation; return the invocation id."""
        seeded_at = self.clock.now_utc() - _SEED_OFFSET
        if expired:
            seeded_at -= timedelta(seconds=self.timeout_seconds + 2)
        adapter = AdapterIdentity(
            adapter_name=_ADAPTER_NAME, adapter_version=_ADAPTER_VERSION
        )
        experiment: ExperimentRecord | None = None
        run: EngineRunRecord | None = None
        if kind is not DESCRIBE:
            experiment, observation_id = self._seed_experiment(adapter)
            chosen = (
                _MATCHING_RUN_STATE[kind][state] if run_state is None else run_state
            )
            run = self._seed_run(
                experiment, observation_id, chosen, seeded_at=seeded_at
            )
        if process_created is None:
            process_created = state in _PROCESS_STATES
        via: CommandInvocationState | None = None
        if state in (CANCELLED, TIMED_OUT):
            via = RUNNING if process_created else STARTING
        invocation_id = self.identity.new_invocation_id()
        facts: dict[str, Any] = {
            "kind": kind,
            "via": via,
            "invocation_id": invocation_id,
            "adapter_name": _ADAPTER_NAME,
            "adapter_version": _ADAPTER_VERSION,
            "timeout_seconds": self.timeout_seconds,
            "created_at_utc": seeded_at,
        }
        if run is not None:
            facts["run_id"] = run.run_id
            facts["request_hash"] = run.request_hash
        record = sample_invocation(state, **facts)
        payload = record.model_dump(mode="python")
        if record.process_created:
            identity = self._process_identity()
            payload["pid_identity"] = identity
            self.controller.presence_of[identity.creation_identity] = presence
        if state in _TERMINAL_STATES and cleanup_complete:
            payload["cleanup_complete"] = True
            payload["cleanup_completed_at_utc"] = payload["completed_at_utc"]
        stored = CommandInvocationRecord.model_validate(payload)
        self.store.command_invocations.live[invocation_id] = stored
        if run is not None:
            self._run_of[invocation_id] = run.run_id
        if cancelled and experiment is not None:
            ok(
                cancel_experiment(
                    CancelExperimentRequest(
                        schema_version="1.0.0",
                        experiment_id=experiment.experiment_id,
                        expected_revision=experiment.revision,
                        correlation_id="task7-cancel",
                    ),
                    unit_of_work=self.unit_of_work,
                    clock=self.clock,
                )
            )
        return invocation_id

    # -- Passes -------------------------------------------------------------------

    def run_pass(
        self, *, source: object | None = None, observer: object | None = None
    ) -> ReconciliationReport:
        report = ok(self.reconcile(source=source, observer=observer))
        self.reports.append(report)
        return report

    def reconcile(
        self, *, source: object | None = None, observer: object | None = None
    ) -> Result[ReconciliationReport]:
        chosen_source: Any = self.source if source is None else source
        chosen_observer: Any = self.observer if observer is None else observer
        return reconcile_invocations(
            source=chosen_source,
            lifecycle=self.lifecycle,
            controller=self.controller,
            preflight=self.preflight,
            clock=self.clock,
            supervisor_instance_id=self.supervisor_instance_id,
            observer=chosen_observer,
        )

    @staticmethod
    def entry_for(
        report: ReconciliationReport, invocation_id: str
    ) -> InvocationReconciliation:
        (entry,) = (
            item for item in report.entries if item.invocation_id == invocation_id
        )
        return entry

    def run_one(
        self,
        kind: CommandKind,
        state: CommandInvocationState,
        *,
        presence: ProcessPresence = ABSENT,
        cleanup_complete: bool = True,
        process_created: bool | None = None,
        run_state: EngineRunState | None = None,
        cancelled: bool = False,
        past_deadline: bool = False,
    ) -> InvocationReconciliation:
        invocation_id = self.seed(
            kind,
            state,
            presence=presence,
            cleanup_complete=cleanup_complete,
            process_created=process_created,
            run_state=run_state,
            cancelled=cancelled,
        )
        self.controller.inspection = presence
        if past_deadline:
            self.clock.advance(self.timeout_seconds + 1)
        return self.entry_for(self.run_pass(), invocation_id)

    def run_again(self, entry: InvocationReconciliation) -> InvocationReconciliation:
        return self.entry_for(self.run_pass(), entry.invocation_id)

    def run_every_row(self) -> tuple[InvocationReconciliation, ...]:
        """One fresh record per plan 8.5 row, then one pass."""
        seeded = [
            self.seed(DESCRIBE, PENDING),
            self.seed(RUN, STARTING, cancelled=True),
            self.seed(VALIDATE, STARTING, expired=True),
            self.seed(DESCRIBE, STARTING),
            self.seed(RUN, RUNNING, run_state=EngineRunState.STARTING),
            self.seed(VALIDATE, RUNNING, run_state=EngineRunState.READY),
            self.seed(RUN, RUNNING, presence=ALIVE_MATCHING),
            self.seed(RUN, RUNNING, presence=ALIVE_DIFFERENT_IDENTITY),
            self.seed(RUN, RUNNING, cancelled=True),
            self.seed(VALIDATE, RUNNING, presence=UNDETERMINED, expired=True),
            self.seed(RUN, RUNNING),
            self.seed(
                RUN,
                CANCELLED,
                cleanup_complete=False,
                process_created=True,
                presence=ALIVE_MATCHING,
            ),
            self.seed(
                VALIDATE, TIMED_OUT, cleanup_complete=False, process_created=True
            ),
            self.seed(RUN, EXITED, cleanup_complete=False),
            self.seed(DESCRIBE, FAILED_TO_START, cleanup_complete=False),
        ]
        report = self.run_pass()
        return tuple(self.entry_for(report, invocation_id) for invocation_id in seeded)

    # -- Reads --------------------------------------------------------------------

    def list_targets(self) -> tuple[CommandInvocationRecord, ...]:
        return ok(self.source.list_reconciliation_targets())

    def stored_run(self, entry: InvocationReconciliation) -> EngineRunRecord:
        return self.store.engine_runs.live[self._run_of[entry.invocation_id]]

    def stored_invocation(
        self, entry: InvocationReconciliation
    ) -> CommandInvocationRecord:
        return self.store.command_invocations.live[entry.invocation_id]

    def stored_experiment(self, entry: InvocationReconciliation) -> ExperimentRecord:
        run = self.stored_run(entry)
        return self.store.experiments.live[run.experiment_id]

    def paths_of(self, invocation_id: str) -> Any:
        record = self.store.command_invocations.live[invocation_id]
        return plan_command_paths(
            str(self.root),
            command_kind=record.command_kind,
            invocation_id=record.invocation_id,
            run_id=record.run_id,
        )

    @contextmanager
    def hold_request_open(self) -> Iterator[Path]:
        """Plant the next invocation's request file and hold it open (Task 3's
        technique): ``remove_command_root`` reports ``sharing_violation:32`` while it
        is held."""
        command_root = self.root / self.next_invocation_id()
        command_root.mkdir()
        request = command_root / "request.json"
        request.write_bytes(b"{}")
        with request.open("rb"):
            yield command_root


@pytest.fixture
def reconciler(tmp_path: Path) -> Iterator[_Reconciler]:
    global _active  # the plan's module-level helpers read the active fixture
    fixture = _Reconciler(tmp_path)
    _active = fixture
    try:
        yield fixture
    finally:
        _active = None


def _external_cancelled(fixture: _Reconciler, invocation_id: str) -> Diagnostic:
    return stage6_diagnostic(
        PROCESS_CANCELLED,
        "task7 external move",
        source_component="doubles.supervision.test",
        timestamp_utc=fixture.clock.now_utc(),
        invocation_id=invocation_id,
    )


# --------------------------------------------------------------------------
# Plan Task 7 Step 1 (copied verbatim; PT018 splits keep every clause)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("kind", [DESCRIBE, VALIDATE, RUN])
def test_a_persisted_starting_record_fails_to_start_unless_cancelled_or_expired(
    reconciler: _Reconciler, kind: CommandKind
) -> None:
    for cancelled, past_deadline, action, code in [
        (False, False, TERMINALIZED_FAILED_TO_START, PROCESS_LAUNCH_NOT_COMMITTED),
        (True, False, TERMINALIZED_CANCELLED, PROCESS_CANCELLED),
        (False, True, TERMINALIZED_TIMED_OUT, TIMEOUT_CODE_OF[kind]),
    ]:  # explicit keywords: strict mypy rejects **dict[str, bool] against the signature
        if kind is DESCRIBE and cancelled:
            continue  # a describe has no run or experiment, so `cancelled` is never true for it (§8.5)  # noqa: E501
        entry = reconciler.run_one(
            kind=kind, state=STARTING, cancelled=cancelled, past_deadline=past_deadline
        )  # a fresh invocation (and run) per call
        assert (entry.action, primary_code(entry.record_after)) == (action, code)
        assert entry.record_after.process_created is False
        assert (
            entry.record_after.cleanup_complete
        )  # complete because the fixture seeds no root
        if kind is not DESCRIBE:
            assert reconciler.stored_run(entry).state is COUPLED_RUN_TARGET[action]
    if kind is DESCRIBE:
        entry = reconciler.run_one(
            kind=DESCRIBE, state=STARTING, cancelled=True
        )  # the flag is meaningless for a describe
        assert entry.action is TERMINALIZED_FAILED_TO_START


def test_a_live_matching_process_is_terminated_and_becomes_protocol_failed(
    reconciler: _Reconciler,
) -> None:
    entry = reconciler.run_one(kind=RUN, state=RUNNING, presence=ALIVE_MATCHING)
    assert entry.action is TERMINALIZED_PROTOCOL_FAILED
    assert (
        primary_code(entry.record_after)
        == PROCESS_ORCHESTRATOR_RESTART_LOST_SUPERVISION
    )
    assert reconciler.controller.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]
    assert reconciler.stored_run(entry).state is EngineRunState.FAILED
    assert (
        entry.record_after.cleanup_complete
    )  # the scripted controller reports ABSENT after its own terminate_tree


def test_a_reused_pid_is_left_alone_and_recorded(reconciler: _Reconciler) -> None:
    entry = reconciler.run_one(
        kind=RUN, state=RUNNING, presence=ALIVE_DIFFERENT_IDENTITY
    )
    assert entry.action is LEFT_RUNNING_AWAITING_DEADLINE
    assert reconciler.controller.terminate_calls == []
    assert PROCESS_PID_REUSE_DETECTED in codes_of_diagnostics(entry.diagnostics)


def test_an_absent_process_waits_for_its_deadline_and_never_becomes_exited(
    reconciler: _Reconciler,
) -> None:
    before = reconciler.run_one(kind=RUN, state=RUNNING, presence=ABSENT)
    assert before.action is LEFT_RUNNING_AWAITING_DEADLINE
    assert before.manifest_present is False
    reconciler.clock.advance(reconciler.timeout_seconds + 1)
    after = reconciler.run_again(before)  # the same record, its deadline now passed
    assert after.action is TERMINALIZED_TIMED_OUT
    assert not isinstance(
        after.record_after.native_exit_value, int
    )  # no exit pair (MISSING)


def test_a_cancelled_run_beside_a_running_invocation_is_honored_alone(
    reconciler: _Reconciler,
) -> None:
    entry = reconciler.run_one(
        kind=RUN, state=RUNNING, presence=ABSENT, run_state=EngineRunState.CANCELLED
    )
    assert entry.action is TERMINALIZED_CANCELLED
    assert reconciler.stored_run(entry).state is EngineRunState.CANCELLED


@pytest.mark.parametrize(
    ("process_created", "presence"),
    [
        (True, ABSENT),
        (True, UNDETERMINED),
        (True, ALIVE_DIFFERENT_IDENTITY),
        (False, ABSENT),
    ],
)
def test_a_terminal_with_incomplete_cleanup_is_cleaned_and_enriched_once(
    reconciler: _Reconciler, process_created: bool, presence: ProcessPresence
) -> None:
    entry = reconciler.run_one(
        kind=RUN,
        state=CANCELLED,
        cleanup_complete=False,
        process_created=process_created,
        presence=presence,
    )
    assert entry.action is CLEANUP_COMPLETED
    assert entry.record_after.cleanup_complete
    assert (PROCESS_PID_REUSE_DETECTED in codes_of_diagnostics(entry.diagnostics)) is (
        presence is ALIVE_DIFFERENT_IDENTITY
    )
    assert (
        reconciler.controller.terminate_calls == []
    )  # a reused pid is never ours to kill
    assert entry.record_after.invocation_id not in {
        r.invocation_id for r in reconciler.list_targets()
    }


def test_a_repeated_cleanup_failure_does_not_grow_the_diagnostic_list(
    reconciler: _Reconciler,
) -> None:
    with (
        reconciler.hold_request_open()
    ):  # plants <root>\<invocation_id>\request.json and keeps it open
        first = reconciler.run_one(
            kind=DESCRIBE,
            state=FAILED_TO_START,
            cleanup_complete=False,
            process_created=False,
        )
        second = reconciler.run_again(first)
    assert (first.action, second.action) == (
        CLEANUP_FAILED,
        CLEANUP_STILL_FAILING,
    )  # sharing_violation:32 both times
    assert len(second.record_after.diagnostic_ids) == len(
        first.record_after.diagnostic_ids
    )
    third = reconciler.run_again(first)
    assert third.action is CLEANUP_COMPLETED
    assert third.record_after.cleanup_complete


def test_a_starting_record_whose_root_is_held_terminalizes_with_incomplete_cleanup(
    reconciler: _Reconciler,
) -> None:
    with reconciler.hold_request_open():
        first = reconciler.run_one(
            kind=DESCRIBE, state=STARTING, cleanup_complete=False
        )  # a persisted STARTING crash with its root present
        second = reconciler.run_again(first)
    assert first.action is TERMINALIZED_FAILED_TO_START
    assert first.record_after.cleanup_complete is False
    assert codes_of_diagnostics(first.diagnostics).count(PROCESS_CLEANUP_FAILED) == 1
    assert second.action is CLEANUP_STILL_FAILING
    assert len(second.record_after.diagnostic_ids) == len(
        first.record_after.diagnostic_ids
    )
    third = reconciler.run_again(first)
    assert third.action is CLEANUP_COMPLETED
    assert third.record_after.cleanup_complete


@pytest.mark.parametrize(
    ("kind", "state", "run_state"),
    [
        (RUN, RUNNING, EngineRunState.STARTING),
        (VALIDATE, STARTING, EngineRunState.READY),
        (VALIDATE, RUNNING, EngineRunState.READY),
    ],
)
def test_a_mixed_running_pair_is_reported_not_repaired(
    reconciler: _Reconciler,
    kind: CommandKind,
    state: CommandInvocationState,
    run_state: EngineRunState,
) -> None:
    entry = reconciler.run_one(
        kind=kind, state=state, presence=ABSENT, run_state=run_state
    )
    assert entry.action is INVARIANT_REPORTED
    assert (
        reconciler.stored_invocation(entry).state is state
    )  # a VALIDATE beside READY has no edge to TIMED_OUT or FAILED


def test_the_reconciler_never_produces_exited(reconciler: _Reconciler) -> None:
    for entry in reconciler.run_every_row():
        assert (
            entry.state_before is CommandInvocationState.EXITED
            or entry.record_after.state is not CommandInvocationState.EXITED
        )


# --------------------------------------------------------------------------
# Plan Task 7 Step 1, the listed extras
# --------------------------------------------------------------------------


def test_a_pending_record_is_left_alone_without_facts_or_inspection(
    reconciler: _Reconciler,
) -> None:
    entry = reconciler.run_one(kind=RUN, state=PENDING)
    assert entry.action is LEFT_PENDING
    assert entry.record_after == reconciler.stored_invocation(entry)
    assert entry.record_after.revision == 0
    assert not isinstance(entry.presence, ProcessPresence)  # MISSING: not inspected
    assert not isinstance(entry.manifest_present, bool)  # MISSING: no RUN left running
    assert entry.diagnostics == ()
    assert reconciler.controller.inspect_calls == []
    assert reconciler.lifecycle.calls == []


def test_an_exited_record_with_incomplete_cleanup_is_enriched_without_inspection(
    reconciler: _Reconciler,
) -> None:
    entry = reconciler.run_one(kind=RUN, state=EXITED, cleanup_complete=False)
    assert entry.action is CLEANUP_COMPLETED
    assert not isinstance(entry.presence, ProcessPresence)  # MISSING: not inspected
    assert reconciler.controller.inspect_calls == []
    assert reconciler.controller.terminate_calls == []
    assert entry.record_after.state is EXITED
    assert entry.record_after.cleanup_complete
    assert entry.record_after.native_exit_value == 0
    assert reconciler.lifecycle.calls == ["enrich"]
    assert reconciler.stored_run(entry).state is EngineRunState.RUNNING


def test_the_report_lists_every_target_once_in_creation_order(
    reconciler: _Reconciler,
) -> None:
    first = reconciler.seed(RUN, RUNNING)
    reconciler.clock.advance(1)
    second = reconciler.seed(DESCRIBE, PENDING)
    report = reconciler.run_pass()
    assert [entry.invocation_id for entry in report.entries] == [first, second]
    assert [entry.action for entry in report.entries] == [
        LEFT_RUNNING_AWAITING_DEADLINE,
        LEFT_PENDING,
    ]
    assert report.supervisor_instance_id == SCRIPTED_SUPERVISOR_INSTANCE_ID
    assert report.started_at_utc == reconciler.clock.now_utc()
    assert [entry.sequence for entry in decision_entries(reconciler.observer)] == [1, 2]
    again = reconciler.run_pass()
    assert again == report  # write-free rows replay identically
    assert [entry.sequence for entry in decision_entries(reconciler.observer)] == [
        1,
        2,
        1,
        2,
    ]


def test_a_swap_another_actor_won_is_skipped_and_left_for_the_next_pass(
    reconciler: _Reconciler,
) -> None:
    reconciler.lifecycle.fail("record_terminal", CONCURRENCY_CONFLICT)
    entry = reconciler.run_one(kind=DESCRIBE, state=STARTING)
    assert entry.action is SKIPPED_EXTERNAL_WINNER
    assert entry.record_after == reconciler.stored_invocation(entry)
    assert entry.record_after.state is STARTING
    assert CONCURRENCY_CONFLICT in codes_of_diagnostics(entry.diagnostics)
    assert PROCESS_LAUNCH_NOT_COMMITTED in codes_of_diagnostics(entry.diagnostics)
    assert reconciler.lifecycle.calls == ["record_terminal", "load"]
    again = reconciler.run_again(entry)  # the next pass re-evaluates the record
    assert again.action is TERMINALIZED_FAILED_TO_START
    assert again.record_after.cleanup_complete


def test_a_terminal_written_externally_during_the_pass_is_the_winner(
    reconciler: _Reconciler,
) -> None:
    invocation_id = reconciler.next_invocation_id()

    def move_externally() -> None:
        record = reconciler.store.command_invocations.live[invocation_id]
        ok(
            reconciler.inner_lifecycle.record_terminal(
                invocation_id,
                expected_revision=record.revision,
                target_state=CANCELLED,
                primary=_external_cancelled(reconciler, invocation_id),
                additional=(),
                native_exit_value=MISSING,
            )
        )

    reconciler.lifecycle.before("record_terminal", move_externally)
    entry = reconciler.run_one(kind=DESCRIBE, state=STARTING)
    assert entry.action is SKIPPED_EXTERNAL_WINNER
    assert entry.record_after.state is CANCELLED
    assert entry.record_after == reconciler.stored_invocation(entry)
    assert entry.record_after.cleanup_complete is False
    assert "enrich" not in reconciler.lifecycle.calls
    again = reconciler.run_again(entry)
    assert again.action is CLEANUP_COMPLETED
    assert again.record_after.state is CANCELLED


# --------------------------------------------------------------------------
# The VALIDATE-beside-READY predicate order (plan 8.5 preamble and row; the carried
# note the brief assigns to Task 7) -- one test per kind kills the reversed order
# --------------------------------------------------------------------------


@pytest.mark.parametrize("state", [STARTING, RUNNING])
def test_a_validate_beside_ready_is_cancelled_before_it_is_reported(
    reconciler: _Reconciler, state: CommandInvocationState
) -> None:
    entry = reconciler.run_one(
        kind=VALIDATE, state=state, run_state=EngineRunState.READY, cancelled=True
    )
    assert entry.action is TERMINALIZED_CANCELLED  # READY -> CANCELLED is an edge
    assert primary_code(entry.record_after) == PROCESS_CANCELLED
    assert reconciler.stored_run(entry).state is EngineRunState.CANCELLED
    assert reconciler.stored_experiment(entry).state is ExperimentState.CANCELLED
    assert CORE_INVARIANT_VIOLATION not in codes_of_diagnostics(entry.diagnostics)
    assert entry.record_after.cleanup_complete


@pytest.mark.parametrize(
    ("state", "run_state"),
    [(RUNNING, EngineRunState.STARTING), (STARTING, EngineRunState.READY)],
)
def test_a_run_mixed_pair_is_reported_before_cancellation_is_honoured(
    reconciler: _Reconciler, state: CommandInvocationState, run_state: EngineRunState
) -> None:
    entry = reconciler.run_one(
        kind=RUN, state=state, run_state=run_state, cancelled=True
    )
    assert entry.action is INVARIANT_REPORTED  # the coupled swap would be refused
    assert reconciler.stored_invocation(entry).state is state
    assert reconciler.stored_run(entry).state is run_state
    assert reconciler.stored_experiment(entry).state is ExperimentState.CANCELLED
    assert codes_of_diagnostics(entry.diagnostics) == (CORE_INVARIANT_VIOLATION,)
    assert entry.diagnostics[0].details["check"] == "mixed_running_pair"
    assert reconciler.lifecycle.calls == []  # no write was even attempted
    assert entry.presence is (MISSING if state is STARTING else ABSENT)


@pytest.mark.parametrize("state", [STARTING, RUNNING])
def test_a_validate_beside_ready_past_its_deadline_is_still_reported(
    reconciler: _Reconciler, state: CommandInvocationState
) -> None:
    # Review T7-R-01: the VALIDATE mixed predicate precedes the deadline row, because a
    # READY run has no edge to TIMED_OUT and the coupled swap would be refused.
    entry = reconciler.run_one(
        kind=VALIDATE, state=state, run_state=EngineRunState.READY, past_deadline=True
    )
    assert entry.action is INVARIANT_REPORTED
    assert reconciler.stored_invocation(entry).state is state
    assert reconciler.stored_run(entry).state is EngineRunState.READY
    assert codes_of_diagnostics(entry.diagnostics) == (CORE_INVARIANT_VIOLATION,)
    assert reconciler.lifecycle.calls == []


def test_a_mixed_pair_beside_a_live_matching_process_is_terminated_not_repaired(
    reconciler: _Reconciler,
) -> None:
    entry = reconciler.run_one(
        kind=VALIDATE,
        state=RUNNING,
        run_state=EngineRunState.READY,
        presence=ALIVE_MATCHING,
    )
    assert entry.action is INVARIANT_REPORTED
    assert entry.presence is ALIVE_MATCHING
    assert reconciler.controller.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]
    assert codes_of_diagnostics(entry.diagnostics) == (
        CORE_INVARIANT_VIOLATION,
        PROCESS_FORCED_TERMINATION,
    )
    assert entry.diagnostics[1].details["reason"] == "reconciliation"
    assert reconciler.lifecycle.calls == []
    assert reconciler.stored_invocation(entry).state is RUNNING
    for diagnostic in entry.diagnostics:  # reported, not persisted
        assert diagnostic.diagnostic_id not in reconciler.store.diagnostics.live


def test_a_cancelled_mixed_validate_beside_a_live_process_terminates_it_too(
    reconciler: _Reconciler,
) -> None:
    entry = reconciler.run_one(
        kind=VALIDATE,
        state=RUNNING,
        run_state=EngineRunState.READY,
        presence=ALIVE_MATCHING,
        cancelled=True,
    )
    assert entry.action is TERMINALIZED_CANCELLED
    assert reconciler.controller.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]
    assert PROCESS_FORCED_TERMINATION in stored_codes(entry.record_after)
    assert reconciler.stored_run(entry).state is EngineRunState.CANCELLED
    assert entry.record_after.cleanup_complete


def test_a_live_matching_process_beside_a_cancelled_run_is_still_lost_supervision(
    reconciler: _Reconciler,
) -> None:
    # Plan 8.5: the ALIVE_MATCHING row deliberately precedes the cancelled rows; a live
    # matching orphan is a lost-supervision fact first, and the cancelled run is still
    # honoured by the alone path.
    entry = reconciler.run_one(
        kind=RUN,
        state=RUNNING,
        presence=ALIVE_MATCHING,
        run_state=EngineRunState.CANCELLED,
    )
    assert entry.action is TERMINALIZED_PROTOCOL_FAILED
    assert (
        primary_code(entry.record_after)
        == PROCESS_ORCHESTRATOR_RESTART_LOST_SUPERVISION
    )
    assert reconciler.controller.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]
    assert reconciler.stored_run(entry).state is EngineRunState.CANCELLED  # alone
    assert entry.record_after.cleanup_complete


# --------------------------------------------------------------------------
# Process presence, identity and pid reuse
# --------------------------------------------------------------------------


def test_an_undetermined_process_is_never_terminated_and_times_out_from_running(
    reconciler: _Reconciler,
) -> None:
    before = reconciler.run_one(kind=RUN, state=RUNNING, presence=UNDETERMINED)
    assert before.action is LEFT_RUNNING_AWAITING_DEADLINE
    assert before.presence is UNDETERMINED
    assert reconciler.controller.terminate_calls == []
    reconciler.clock.advance(reconciler.timeout_seconds + 1)
    after = reconciler.run_again(before)
    assert after.action is TERMINALIZED_TIMED_OUT
    assert (
        primary_code(after.record_after) == PROCESS_RUN_TIMED_OUT
    )  # not START_TIMED_OUT
    assert after.record_after.cleanup_complete
    assert not isinstance(after.record_after.native_exit_value, int)
    assert reconciler.stored_run(after).state is EngineRunState.TIMED_OUT
    assert reconciler.controller.terminate_calls == []


def test_a_reused_pid_that_times_out_attaches_the_reuse_diagnostic(
    reconciler: _Reconciler,
) -> None:
    entry = reconciler.run_one(
        kind=RUN, state=RUNNING, presence=ALIVE_DIFFERENT_IDENTITY, past_deadline=True
    )
    assert entry.action is TERMINALIZED_TIMED_OUT
    assert reconciler.controller.terminate_calls == []
    reuse = next(
        d for d in entry.diagnostics if d.error_code == PROCESS_PID_REUSE_DETECTED
    )
    assert reuse.diagnostic_id in entry.record_after.diagnostic_ids  # attached
    identity = _identity(entry.record_after)
    assert reuse.details["pid"] == identity.pid
    assert reuse.details["expected_creation_identity"] == identity.creation_identity
    assert reuse.details["observed_creation_identity"] != identity.creation_identity
    assert reuse.run_id == entry.record_after.run_id


def test_a_reported_reuse_is_not_persisted_while_the_record_is_left_running(
    reconciler: _Reconciler,
) -> None:
    entry = reconciler.run_one(
        kind=RUN, state=RUNNING, presence=ALIVE_DIFFERENT_IDENTITY
    )
    assert entry.action is LEFT_RUNNING_AWAITING_DEADLINE
    (reuse,) = entry.diagnostics
    assert reuse.error_code == PROCESS_PID_REUSE_DETECTED
    assert reuse.diagnostic_id not in reconciler.store.diagnostics.live
    assert entry.record_after.diagnostic_ids == ()
    assert reconciler.lifecycle.calls == []


def test_lost_supervision_details_name_the_recorded_owner_and_the_termination(
    reconciler: _Reconciler,
) -> None:
    entry = reconciler.run_one(kind=RUN, state=RUNNING, presence=ALIVE_MATCHING)
    lost = primary(entry.record_after)
    identity = _identity(entry.record_after)
    assert lost.details == {
        "pid": identity.pid,
        "creation_identity": identity.creation_identity,
        "supervisor_instance_id": identity.supervisor_instance_id,
        "tree_terminated": True,
    }
    assert lost.run_id == entry.record_after.run_id
    assert lost.source_component == _RECONCILER
    forced = next(
        d for d in entry.diagnostics if d.error_code == PROCESS_FORCED_TERMINATION
    )
    assert forced.diagnostic_id in entry.record_after.diagnostic_ids
    assert forced.details["reason"] == "reconciliation"
    assert forced.details["exit_code"] == FORCED_TERMINATION_EXIT_CODE
    assert entry.presence is ALIVE_MATCHING
    assert reconciler.controller.inspect_calls[0] == identity  # identity, never a pid


def test_a_malformed_stored_identity_is_undetermined_for_the_windows_controller() -> (
    None
):
    controller = WindowsProcessController()  # holds no handle; inspect makes no OS call
    merged_shape = sample_process_identity()  # the Stage 5 fixture shape, not windows:
    inspection = controller.inspect(merged_shape)
    assert inspection.presence is UNDETERMINED
    assert not isinstance(inspection.observed_creation_identity, str)  # MISSING
    disagreeing = sample_process_identity(
        pid=4321, creation_identity=render_creation_identity(4322, 1)
    )
    assert controller.inspect(disagreeing).presence is UNDETERMINED


# --------------------------------------------------------------------------
# Terminal cleanup rows
# --------------------------------------------------------------------------


def test_a_terminal_beside_a_live_matching_tree_is_terminated_once_and_completed(
    reconciler: _Reconciler,
) -> None:
    entry = reconciler.run_one(
        kind=RUN, state=PROTOCOL_FAILED, cleanup_complete=False, presence=ALIVE_MATCHING
    )
    assert entry.action is CLEANUP_COMPLETED
    assert reconciler.controller.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]
    assert PROCESS_FORCED_TERMINATION in stored_codes(entry.record_after)
    assert entry.record_after.cleanup_complete
    assert entry.record_after.state is PROTOCOL_FAILED
    assert reconciler.lifecycle.calls == ["enrich"]
    assert reconciler.run_pass().entries == ()  # no longer a target


def test_a_tree_that_survives_termination_is_cleanup_failed_then_still_failing(
    reconciler: _Reconciler,
) -> None:
    controller = reconciler.controller
    controller.terminate_report = TerminationReport(
        forced=True,
        exit_code_used=FORCED_TERMINATION_EXIT_CODE,
        job_terminated=False,
        descendants=(),
        failures=(
            CleanupFailure(
                action=CleanupAction.TREE_VERIFIED_DEAD, reason="access_denied:5"
            ),
        ),
    )
    invocation_id = reconciler.seed(
        RUN, TIMED_OUT, cleanup_complete=False, process_created=True
    )
    identity = _identity(reconciler.store.command_invocations.live[invocation_id])
    controller.presence_of[identity.creation_identity] = ALIVE_MATCHING
    controller.survivors.add(identity.creation_identity)
    first = reconciler.entry_for(reconciler.run_pass(), invocation_id)
    assert first.action is CLEANUP_FAILED
    assert first.record_after.cleanup_complete is False
    codes = codes_of_diagnostics(first.diagnostics)
    assert codes.count(PROCESS_CLEANUP_FAILED) == 2  # the report's failure + tree_alive
    assert codes.count(PROCESS_FORCED_TERMINATION) == 1
    failed = [d for d in first.diagnostics if d.error_code == PROCESS_CLEANUP_FAILED]
    assert {d.details["error_class"] for d in failed} == {"access_denied", "tree_alive"}
    assert all(d.details["cleanup_action"] == "TREE_VERIFIED_DEAD" for d in failed)
    assert controller.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]
    second = reconciler.run_again(first)
    assert second.action is CLEANUP_STILL_FAILING
    assert second.record_after == first.record_after
    assert controller.terminate_calls == [FORCED_TERMINATION_EXIT_CODE] * 2
    controller.survivors.clear()
    controller.terminate_report = None
    third = reconciler.run_again(first)
    assert third.action is CLEANUP_COMPLETED
    assert third.record_after.cleanup_complete


def test_a_post_running_root_is_never_removed_by_the_reconciler(
    reconciler: _Reconciler,
) -> None:
    invocation_id = reconciler.seed(RUN, RUNNING, expired=True)
    paths = reconciler.paths_of(invocation_id)
    Path(paths.work_dir).mkdir(parents=True)
    Path(paths.result_path).write_bytes(b"not a manifest")
    entry = reconciler.entry_for(reconciler.run_pass(), invocation_id)
    assert entry.action is TERMINALIZED_TIMED_OUT
    assert entry.record_after.cleanup_complete
    assert Path(paths.result_path).exists()  # a post-RUNNING root is left in place
    assert reconciler.stored_run(entry).state is EngineRunState.TIMED_OUT


# --------------------------------------------------------------------------
# Idempotency and replay
# --------------------------------------------------------------------------


def test_a_second_pass_over_a_left_running_record_changes_nothing(
    reconciler: _Reconciler,
) -> None:
    first = reconciler.run_one(kind=RUN, state=RUNNING, presence=ABSENT)
    stored = dict(reconciler.store.diagnostics.live)
    second = reconciler.run_again(first)
    assert second == first
    assert reconciler.store.diagnostics.live == stored
    assert reconciler.stored_invocation(second).revision == first.record_after.revision
    assert reconciler.lifecycle.calls == []
    facts = [entry.facts for entry in decision_entries(reconciler.observer)]
    assert facts[0] == facts[1]


def test_a_completed_record_leaves_the_target_set_and_the_next_pass_is_empty(
    reconciler: _Reconciler,
) -> None:
    entry = reconciler.run_one(kind=VALIDATE, state=STARTING)
    assert entry.action is TERMINALIZED_FAILED_TO_START
    assert reconciler.list_targets() == ()
    calls = list(reconciler.lifecycle.calls)
    report = reconciler.run_pass()
    assert report.entries == ()
    assert reconciler.lifecycle.calls == calls
    assert reconciler.controller.terminate_calls == []


def test_the_report_is_deterministic_under_a_misordered_duplicating_source(
    reconciler: _Reconciler,
) -> None:
    reconciler.seed(RUN, RUNNING)
    reconciler.clock.advance(1)
    reconciler.seed(DESCRIBE, PENDING)
    reconciler.clock.advance(1)
    reconciler.seed(VALIDATE, RUNNING, presence=UNDETERMINED)
    conforming = reconciler.run_pass()
    misordered = reconciler.run_pass(source=_MisorderedSource(reconciler.source))
    assert misordered == conforming
    identities = [entry.invocation_id for entry in misordered.entries]
    assert len(identities) == 3
    assert len(set(identities)) == 3


# --------------------------------------------------------------------------
# Failure paths
# --------------------------------------------------------------------------


def test_a_source_listing_failure_is_returned_and_nothing_is_touched(
    reconciler: _Reconciler,
) -> None:
    reconciler.seed(RUN, RUNNING, presence=ALIVE_MATCHING)
    result = reconciler.reconcile(source=_FailingSource())
    assert isinstance(result, Failure)
    assert codes_of_diagnostics(result.diagnostics) == (INVARIANT_VIOLATION,)
    assert reconciler.lifecycle.calls == []
    assert reconciler.controller.inspect_calls == []
    assert reconciler.controller.terminate_calls == []
    assert decision_entries(reconciler.observer) == []


def test_a_linked_record_whose_run_facts_fail_is_reported_not_repaired(
    reconciler: _Reconciler,
) -> None:
    invocation_id = reconciler.seed(RUN, RUNNING, presence=ALIVE_MATCHING)
    run_id = reconciler.store.command_invocations.live[invocation_id].run_id
    assert isinstance(run_id, str)
    del reconciler.store.engine_runs.live[run_id]
    entry = reconciler.entry_for(reconciler.run_pass(), invocation_id)
    assert entry.action is INVARIANT_REPORTED
    codes = codes_of_diagnostics(entry.diagnostics)
    assert codes.count(CORE_INVARIANT_VIOLATION) == 2  # the source's and the pass's
    assert (
        PROCESS_FORCED_TERMINATION in codes
    )  # an unverifiable live child never survives
    assert entry.diagnostics[0].details["check"] == "run_facts_unavailable"
    assert reconciler.controller.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]
    assert reconciler.lifecycle.calls == []
    assert reconciler.store.command_invocations.live[invocation_id].state is RUNNING


def test_a_terminal_record_whose_run_facts_fail_is_reported_and_its_tree_terminated(
    reconciler: _Reconciler,
) -> None:
    # Review T7-R-02: a run_facts failure is INVARIANT_REPORTED for every linked
    # non-PENDING record, a terminal cleanup row included; the cleanup diagnostics would
    # otherwise lack their run and experiment correlation (plan 3.5).
    invocation_id = reconciler.seed(
        RUN,
        TIMED_OUT,
        cleanup_complete=False,
        process_created=True,
        presence=ALIVE_MATCHING,
    )
    stored = reconciler.store.command_invocations.live[invocation_id]
    run_id = stored.run_id
    assert isinstance(run_id, str)
    del reconciler.store.engine_runs.live[run_id]
    entry = reconciler.entry_for(reconciler.run_pass(), invocation_id)
    assert entry.action is INVARIANT_REPORTED
    assert entry.diagnostics[0].details["check"] == "run_facts_unavailable"
    assert PROCESS_FORCED_TERMINATION in codes_of_diagnostics(entry.diagnostics)
    assert reconciler.controller.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]
    assert reconciler.lifecycle.calls == []
    assert reconciler.store.command_invocations.live[invocation_id] == stored


def test_launch_not_committed_details_and_terminal_correlation_follow_the_table(
    reconciler: _Reconciler,
) -> None:
    # Review T7-R-03: plan 3.5 details keys and correlation ids on the STARTING rows.
    failed = reconciler.run_one(kind=RUN, state=STARTING)
    stored = reconciler.stored_invocation(failed)
    not_committed = primary(failed.record_after)
    assert set(not_committed.details) == {
        "launch_attempted_at_utc",
        "deadline_utc",
        "stored_revision",
    }
    assert not_committed.details["stored_revision"] == 1  # the seeded STARTING revision
    launch = stored.launch_attempted_at_utc
    deadline = stored.deadline_utc
    assert isinstance(launch, datetime)
    assert isinstance(deadline, datetime)
    assert not_committed.details["launch_attempted_at_utc"] == launch.isoformat()
    assert not_committed.details["deadline_utc"] == deadline.isoformat()
    assert not_committed.run_id == stored.run_id
    assert not_committed.experiment_id == reconciler.stored_run(failed).experiment_id
    assert not_committed.source_component == _RECONCILER
    cancelled = reconciler.run_one(kind=VALIDATE, state=STARTING, cancelled=True)
    assert primary(cancelled.record_after).run_id == cancelled.record_after.run_id
    timed_out = reconciler.run_one(kind=RUN, state=RUNNING, past_deadline=True)
    assert primary(timed_out.record_after).run_id == timed_out.record_after.run_id
    describe = reconciler.run_one(kind=DESCRIBE, state=STARTING)
    assert not isinstance(primary(describe.record_after).run_id, str)  # invocation only


def test_an_enrichment_failure_keeps_the_terminal_action_and_reports_it(
    reconciler: _Reconciler,
) -> None:
    reconciler.lifecycle.fail("enrich", CONCURRENCY_CONFLICT)
    entry = reconciler.run_one(kind=DESCRIBE, state=STARTING)
    assert entry.action is TERMINALIZED_FAILED_TO_START
    assert entry.record_after.state is FAILED_TO_START
    assert entry.record_after.cleanup_complete is False
    assert entry.record_after == reconciler.stored_invocation(entry)
    assert CONCURRENCY_CONFLICT in codes_of_diagnostics(entry.diagnostics)
    assert reconciler.lifecycle.calls == ["record_terminal", "enrich", "load"]
    again = reconciler.run_again(entry)
    assert again.action is CLEANUP_COMPLETED


def test_a_refused_reload_after_a_refused_swap_reports_the_listed_record(
    reconciler: _Reconciler,
) -> None:
    # Characterization of the defensive arms: both one-shot failures are consumed, the
    # listed record is the entry's record_after and both failures are reported.
    reconciler.lifecycle.fail("record_terminal", CONCURRENCY_CONFLICT)
    reconciler.lifecycle.fail("load", INVARIANT_VIOLATION)
    entry = reconciler.run_one(kind=DESCRIBE, state=STARTING)
    assert entry.action is SKIPPED_EXTERNAL_WINNER
    assert entry.record_after == reconciler.stored_invocation(entry)
    assert entry.record_after.state is STARTING
    codes = codes_of_diagnostics(entry.diagnostics)
    assert CONCURRENCY_CONFLICT in codes
    assert INVARIANT_VIOLATION in codes
    assert reconciler.lifecycle.calls == ["record_terminal", "load"]


def test_a_refused_enrichment_whose_reload_fails_keeps_the_terminal_record(
    reconciler: _Reconciler,
) -> None:
    reconciler.lifecycle.fail("enrich", CONCURRENCY_CONFLICT)
    reconciler.lifecycle.fail("load", INVARIANT_VIOLATION)
    entry = reconciler.run_one(kind=DESCRIBE, state=STARTING)
    assert entry.action is TERMINALIZED_FAILED_TO_START
    assert entry.record_after.state is FAILED_TO_START  # the committed terminal write
    assert entry.record_after.cleanup_complete is False
    codes = codes_of_diagnostics(entry.diagnostics)
    assert CONCURRENCY_CONFLICT in codes
    assert INVARIANT_VIOLATION in codes


def test_a_cleanup_row_whose_only_write_is_refused_is_skipped(
    reconciler: _Reconciler,
) -> None:
    reconciler.lifecycle.fail("enrich", CONCURRENCY_CONFLICT)
    entry = reconciler.run_one(kind=RUN, state=EXITED, cleanup_complete=False)
    assert entry.action is SKIPPED_EXTERNAL_WINNER
    assert entry.record_after == reconciler.stored_invocation(entry)
    assert entry.record_after.cleanup_complete is False
    assert reconciler.lifecycle.calls == ["enrich", "load"]
    again = reconciler.run_again(entry)  # the next pass re-evaluates the record
    assert again.action is CLEANUP_COMPLETED


def test_the_entry_point_refuses_a_foreign_preflight_and_an_unbounded_instance_id(
    reconciler: _Reconciler,
) -> None:
    with pytest.raises(TypeError, match="PathPreflight"):
        reconcile_invocations(
            source=reconciler.source,
            lifecycle=reconciler.lifecycle,
            controller=reconciler.controller,
            preflight=str(reconciler.root),  # type: ignore[arg-type]
            clock=reconciler.clock,
            supervisor_instance_id=SCRIPTED_SUPERVISOR_INSTANCE_ID,
            observer=MISSING,
        )
    with pytest.raises(ValidationError):
        reconcile_invocations(
            source=reconciler.source,
            lifecycle=reconciler.lifecycle,
            controller=reconciler.controller,
            preflight=reconciler.preflight,
            clock=reconciler.clock,
            supervisor_instance_id="x" * 1025,
            observer=MISSING,
        )
    assert reconciler.lifecycle.calls == []  # both refusals precede every read


# --------------------------------------------------------------------------
# The manifest fact, success and finalization
# --------------------------------------------------------------------------


def test_manifest_present_is_existence_only_and_never_a_success(
    reconciler: _Reconciler,
) -> None:
    run_kind = reconciler.seed(RUN, RUNNING)
    validate_kind = reconciler.seed(VALIDATE, RUNNING)
    paths = reconciler.paths_of(run_kind)
    Path(paths.work_dir).mkdir(parents=True)
    Path(paths.result_path).write_bytes(b"\x00not json")
    report = reconciler.run_pass()
    run_entry = reconciler.entry_for(report, run_kind)
    validate_entry = reconciler.entry_for(report, validate_kind)
    assert run_entry.action is LEFT_RUNNING_AWAITING_DEADLINE
    assert run_entry.manifest_present is True
    assert not isinstance(validate_entry.manifest_present, bool)  # MISSING for VALIDATE
    assert reconciler.stored_run(run_entry).state is EngineRunState.RUNNING
    assert reconciler.lifecycle.calls == []


def test_no_row_produces_a_success_run_state_or_reopens_a_terminal(
    reconciler: _Reconciler,
) -> None:
    entries = reconciler.run_every_row()
    assert len(entries) == 15
    for run in reconciler.store.committed_engine_runs():
        assert run.state not in _SUCCESS_RUN_STATES
    for entry in entries:
        if entry.state_before in _TERMINAL_STATES:
            assert entry.record_after.state is entry.state_before
    assert set(reconciler.lifecycle.calls) <= _RECONCILER_MEMBERS
    assert "resolve_external_winner" not in reconciler.lifecycle.calls
    assert reconciler.controller.terminate_calls == [FORCED_TERMINATION_EXIT_CODE] * 2
    actions = [entry.action for entry in entries]
    assert actions == [
        LEFT_PENDING,
        TERMINALIZED_CANCELLED,
        TERMINALIZED_TIMED_OUT,
        TERMINALIZED_FAILED_TO_START,
        INVARIANT_REPORTED,
        INVARIANT_REPORTED,
        TERMINALIZED_PROTOCOL_FAILED,
        LEFT_RUNNING_AWAITING_DEADLINE,
        TERMINALIZED_CANCELLED,
        TERMINALIZED_TIMED_OUT,
        LEFT_RUNNING_AWAITING_DEADLINE,
        CLEANUP_COMPLETED,
        CLEANUP_COMPLETED,
        CLEANUP_COMPLETED,
        CLEANUP_COMPLETED,
    ]


# --------------------------------------------------------------------------
# Trace, observer, token absence
# --------------------------------------------------------------------------


def test_every_decision_is_one_trace_entry_and_an_observer_cannot_alter_it(
    reconciler: _Reconciler,
) -> None:
    seeded = reconciler.run_every_row()
    entries = reconciler.reports[-1].entries  # report order, not seeding order
    assert {entry.invocation_id for entry in entries} == {
        entry.invocation_id for entry in seeded
    }
    traced = decision_entries(reconciler.observer)
    assert [entry.invocation_id for entry in traced] == [
        entry.invocation_id for entry in entries
    ]
    assert [entry.sequence for entry in traced] == list(range(1, 16))
    assert [entry.facts["action"] for entry in traced] == [
        entry.action.value for entry in entries
    ]
    assert all(entry.at_utc == reconciler.clock.now_utc() for entry in traced)
    raising = _RaisingObserver()
    quiet = reconciler.run_pass(observer=raising)
    assert raising.calls == len(quiet.entries)
    missing = reconciler.run_pass(observer=MISSING)
    assert missing == quiet


def test_the_report_and_the_store_never_carry_a_raw_attempt_token(
    reconciler: _Reconciler,
) -> None:
    entries = reconciler.run_every_row()
    assert entries
    report_bytes = canonical_json_bytes(reconciler.reports[-1])
    for raw_token in reconciler.raw_tokens.values():
        needle = raw_token.encode("utf-8")
        assert needle not in report_bytes
        for stored in reconciler.store.diagnostics.live.values():
            assert needle not in canonical_json_bytes(stored)
        for entry in reconciler.observer.entries:
            assert needle not in canonical_json_bytes(entry)


# --------------------------------------------------------------------------
# Surface, purity and the plan 2.6 guard expectations
# --------------------------------------------------------------------------


def test_the_module_exports_reconcile_invocations_with_the_exact_signature() -> None:
    assert reconciliation_module.__all__ == ["reconcile_invocations"]
    assert reconciliation_module.SOURCE_COMPONENT == _RECONCILER
    signature = inspect.signature(reconcile_invocations)
    assert tuple(signature.parameters) == _SIGNATURE_NAMES
    assert all(
        parameter.kind is inspect.Parameter.KEYWORD_ONLY
        for parameter in signature.parameters.values()
    )
    assert all(
        parameter.default is inspect.Parameter.empty
        for parameter in signature.parameters.values()
    )
    for name in _LATER_TASK_NAMES:
        assert not hasattr(reconciliation_module, name), name


def test_the_package_exports_the_reconciliation_surface_sorted() -> None:
    exported = package.__all__
    assert {
        "InvocationReconciliation",
        "ReconciliationAction",
        "ReconciliationReport",
        "reconcile_invocations",
    } <= set(exported)
    assert len(set(exported)) == len(exported)
    constants = [name for name in exported if name.isupper()]
    classes = [name for name in exported if not name.isupper() and name[0].isupper()]
    functions = [name for name in exported if name[0].islower()]
    assert list(exported) == [*constants, *classes, *functions]
    for group in (constants, classes, functions):
        assert group == sorted(group)
    for name in exported:
        assert hasattr(package, name), name
    assert package.reconcile_invocations is reconcile_invocations
    docstring = package.__doc__
    assert isinstance(docstring, str)
    assert "not a security sandbox" in docstring
    assert docstring.count("sandbox") == 1
    for name in _LATER_TASK_NAMES[:3]:
        assert not hasattr(package, name), name


def test_the_module_is_pure_and_imports_only_the_reviewed_roots() -> None:
    text = _MODULE_PATH.read_text(encoding="utf-8")
    assert text.startswith('"""')
    tree = ast.parse(text)
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            roots.add(node.module.partition(".")[0])
    assert roots <= _MODULE_ROOTS, roots
    for substring in _PURITY_SUBSTRINGS:
        assert substring not in text, substring
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = node.func.attr if isinstance(node.func, ast.Attribute) else None
            if isinstance(node.func, ast.Name):
                name = node.func.id
            assert name not in {"open", "read_bytes", "read_text", "now"}, name
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and node.module is not None
        and node.module.startswith("crypto_lab.experiments")
        for alias in node.names
    }
    assert imported == set()  # process_supervision never reaches experiments


def test_the_source_allowlist_and_package_modules_name_the_reconciliation_module() -> (
    None
):
    allowed = _literal(_STAGE3_GUARD, "_ALLOWED_SOURCE_FILES")
    assert "process_supervision/reconciliation.py" in allowed
    assert (
        len(allowed) == 107
    )  # Stage 8 Task 3 appended the codec/registry/port modules
    modules = _literal(_PACKAGE_LAYOUT, "PACKAGE_MODULES")
    assert "crypto_lab.process_supervision.reconciliation" in modules
    assert modules.index("crypto_lab.process_supervision.reconciliation") == (
        modules.index("crypto_lab.process_supervision.supervisor") + 1
    )
    assert (
        len(modules) == 107
    )  # Stage 8 Task 3 appended the codec/registry/port modules
