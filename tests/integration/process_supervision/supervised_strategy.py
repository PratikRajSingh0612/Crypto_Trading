"""Stage 7 Task 8: the production supervise strategy and the shared test helpers.

``ProductionSupervision`` is the ``SuperviseStrategy`` of plan section 9.3: for one
``CommandPlan`` it binds a real ``Stage5InvocationLifecycle`` over the harness's unit of
work, registers the request material, builds the ``AdapterCommand`` from
``plan_command_paths`` and ``supervised_catalog_entry_for``, wraps a real
``WindowsProcessController`` in a ``TeeController`` (the write-boundary snapshot, the
stdout tee and the destructive-call counters), plants the row-47 stale file from the
recording observer's ``REQUEST_WRITTEN`` hook, arms a ``ThreadSafeCancellationToken``
the observer trips on the first accepted heartbeat when the plan asks, runs
``asyncio.run(supervisor.invoke(command, token))`` and maps the ``SupervisionOutcome``
to the harness's ``_Supervised``. A pre-swap ``Failure`` (a preflight or long-path
refusal) is raised as ``SupervisionRefused`` so a test asserts the plan's ``Failure``
and the record still ``PENDING``.

Task-local seams, declared in the Task 8 derivation (reading R2, R15): ``controller``
(the plan's scripted rows run through the same strategy over a
``ScriptedProcessController``), ``observers`` (extra observers), ``catalog_entry`` (an
entry used verbatim: the merged script under a Stage 7 name, a copied launcher) and
``preflight`` (an injected long-path arm); ``request_cancellation`` trips the token of
the supervision in progress. The strategy's clock is a ``RealtimeMonotonicClock`` over
the fixed doubles instant, which ``build_harness`` adopts.

``assert_stage_six_expectation`` re-implements the per-kind assertions of the four
Stage 6 contract modules (plan 9.4) with the tolerated production differences of that
section, adds the retained-outcome token walk on every validate and run row and the
no-false-success closure over every adverse row. The remaining helpers are the Windows
fixtures of plan 10: a sleeper that ignores ``SIGBREAK`` and prints ``ready``, the
identity-first termination of a pid the fake reported (never a kill by pid alone), the
console precondition, the reconciler call with a fresh lifecycle and source over the
harness store, and the ``finally:`` proof that nothing a strategy launched survives.
"""

from __future__ import annotations

import asyncio
import os
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

from pydantic.experimental.missing_sentinel import MISSING

from contract.harness import (
    FAKE_ADAPTER_VERSION,
    STALE_OUTPUT_FILE_NAME,
    CommandPlan,
    CommandRun,
    OfflineCommandHarness,
    _Supervised,
    assert_token_absent,
    assert_token_only_in_wire_material,
    token_free_projections,
)
from contract.scenarios import DEFAULT_TIMEOUT_SECONDS, Scenario
from crypto_lab.adapters.catalog import AdapterCatalogEntry
from crypto_lab.adapters.commands import AdapterCommand
from crypto_lab.adapters.diagnostics import (
    ENGINE_RUNTIME_FAILURE,
    PROCESS_START_TIMED_OUT,
    PROCESS_VALIDATE_TIMED_OUT,
)
from crypto_lab.adapters.events import EventRejected, frame_protocol_lines
from crypto_lab.adapters.manifests import (
    AdapterResultManifest,
    AdapterValidationResult,
    SanitizedAdapterResultManifest,
)
from crypto_lab.adapters.negotiation import NegotiationResult
from crypto_lab.adapters.reconciliation import SemanticReconciliation
from crypto_lab.adapters.sanitization import StderrCapture
from crypto_lab.adapters.vocabulary import (
    ProtocolIntegrityStatus,
    ReconciliationVerdict,
)
from crypto_lab.domain.command_invocation import (
    CommandInvocationRecord,
    ProcessIdentity,
)
from crypto_lab.domain.diagnostics import (
    Diagnostic,
    DiagnosticDetailKey,
    DiagnosticDetailValue,
)
from crypto_lab.domain.engine_run import SUCCESS_ENGINE_RUN_STATES
from crypto_lab.domain.hashing import sha256_bytes
from crypto_lab.domain.lifecycle import (
    TERMINAL_ENGINE_RUN_STATES,
    CommandInvocationState,
    CommandKind,
    EngineRunState,
)
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.experiments.supervision_lifecycle import Stage5InvocationLifecycle
from crypto_lab.process_supervision import windows_api
from crypto_lab.process_supervision.cancellation import ThreadSafeCancellationToken
from crypto_lab.process_supervision.diagnostics import (
    PROCESS_WRITE_BOUNDARY_VIOLATION,
)
from crypto_lab.process_supervision.models import (
    FORCED_TERMINATION_EXIT_CODE,
    CleanupAction,
    DescendantIdentity,
    LaunchSpecification,
    ProcessPresence,
    ReconciliationReport,
    SupervisionOutcome,
    SupervisionTraceEntry,
    SupervisionTraceKind,
    parse_creation_identity,
    render_creation_identity,
)
from crypto_lab.process_supervision.ports import (
    LaunchedProcess,
    ProcessController,
    SupervisionObserver,
)
from crypto_lab.process_supervision.reconciliation import reconcile_invocations
from crypto_lab.process_supervision.roots import (
    PathPreflight,
    plan_command_paths,
    probe_long_path_support,
    snapshot_written_paths,
)
from crypto_lab.process_supervision.windows_api import WindowsApiError
from crypto_lab.process_supervision.windows_process import (
    WindowsLaunchedProcess,
    WindowsProcessController,
)
from doubles.experiments import AVAIL_A, INSTANT, FixedClock
from doubles.supervision import (
    SCRIPTED_SUPERVISOR_INSTANCE_ID,
    InMemoryReconciliationSource,
    RealtimeMonotonicClock,
    RecordingObserver,
    SeedingDiagnosticRecorder,
    TeeController,
    build_supervisor,
    supervised_catalog_entry_for,
)

_C = CommandInvocationState
_R = EngineRunState
_V = ReconciliationVerdict
_K = CommandKind
_T = SupervisionTraceKind
#: The venv launcher every production entry hashes: the identity fields a test builds
#: for a process it launched or a descendant a termination report recorded.
LAUNCHER_PATH: Final = str(Path(sys.executable))
LAUNCHER_HASH: Final = sha256_bytes(Path(sys.executable).read_bytes())
#: Plan Task 4: sleeps in 0.1 s slices, one line (a LaunchSpecification refuses control
#: characters), SIGBREAK ignored so only tree termination ends the sleeper; the ready
#: variant prints a line first so an interrupt never reaches an initializing child.
_SLEEP_FOREVER: Final = "any(time.sleep(0.1) for _ in iter(int, 1))"
SLEEPER_PROGRAM: Final = (
    "import signal, time; signal.signal(signal.SIGBREAK, signal.SIG_IGN); "
    f"{_SLEEP_FOREVER}"
)
READY_SLEEPER_PROGRAM: Final = (
    "import signal, time; signal.signal(signal.SIGBREAK, signal.SIG_IGN); "
    f"print('ready', flush=True); {_SLEEP_FOREVER}"
)
_GRANDCHILD_LINE: Final = re.compile(r"grandchild_pid=(\d+)")
_ERROR_NO_SYSTEM_RESOURCES: Final = 1450
_PROCESS_TIMEOUT_ROW: Final = 26
_STALE_ATTEMPT_ROW: Final = 47
_CONTROL_C_EXIT: Final = 3221225786


def _missing(value: object) -> bool:
    return value is MISSING


def ok[T](result: Result[T]) -> T:
    """Unwrap a ``Success`` or fail with the codes and messages of the ``Failure``."""
    if isinstance(result, Failure):
        codes = [item.error_code for item in result.diagnostics]
        messages = [item.message for item in result.diagnostics]
        raise AssertionError(f"operation failed: {codes} {messages}")
    assert isinstance(result, Success)
    return result.value


# --------------------------------------------------------------------------
# The production strategy (plan 9.3)
# --------------------------------------------------------------------------


class SupervisionRefused(Exception):
    """A pre-swap ``Failure`` from ``invoke`` (plan 2.5 reading 1): the record stays
    ``PENDING`` and nothing was launched; the test asserts the ``Failure`` itself."""

    def __init__(self, failure: Failure, invocation_id: str) -> None:
        codes = tuple(item.error_code for item in failure.diagnostics)
        super().__init__(f"supervision refused for {invocation_id}: {codes}")
        self.failure = failure
        self.invocation_id = invocation_id


class ProductionSupervision:
    """The ``SuperviseStrategy`` that drives the production supervisor (plan 9.3)."""

    def __init__(
        self,
        *,
        cancellation_grace_seconds: int = 1,
        controller: ProcessController | None = None,
        observers: tuple[SupervisionObserver, ...] = (),
        catalog_entry: AdapterCatalogEntry | None = None,
        preflight: PathPreflight | MISSING = MISSING,  # type: ignore[valid-type]
    ) -> None:
        self._clock = RealtimeMonotonicClock(INSTANT)
        self._grace = cancellation_grace_seconds
        self._controller = controller
        self._observers = observers
        self._catalog_entry = catalog_entry
        self._preflight = preflight
        self._token: ThreadSafeCancellationToken | None = None
        #: One tee, one recording observer and one outcome per supervised command.
        self.tees: list[TeeController] = []
        self.observers_seen: list[RecordingObserver] = []
        self.outcomes: list[SupervisionOutcome] = []

    @property
    def clock(self) -> FixedClock:
        return self._clock

    @property
    def launches(self) -> tuple[LaunchSpecification, ...]:
        return tuple(spec for tee in self.tees for spec in tee.launches)

    @property
    def last_tee(self) -> TeeController:
        assert self.tees, "no command has been supervised"
        return self.tees[-1]

    @property
    def last_outcome(self) -> SupervisionOutcome:
        assert self.outcomes, "no command has been supervised"
        return self.outcomes[-1]

    def request_cancellation(self) -> None:
        """Trip the token of the supervision in progress (an observer hook's seam)."""
        token = self._token
        assert token is not None, "no supervision is in progress"
        token.request_cancellation()

    def _entry_for(self, adapter_name: str) -> AdapterCatalogEntry:
        if self._catalog_entry is not None:
            return self._catalog_entry
        return supervised_catalog_entry_for(adapter_name)

    def supervise(
        self, harness: OfflineCommandHarness, plan: CommandPlan
    ) -> _Supervised:
        invocation = plan.invocation
        kind = invocation.command_kind
        lifecycle = Stage5InvocationLifecycle(
            unit_of_work=harness._unit_of_work(),
            clock=harness.clock,
            diagnostics=SeedingDiagnosticRecorder(harness.store),
        )
        lifecycle.register_request_material(invocation.invocation_id, plan.material)
        run_id: Any = MISSING if plan.run is None else plan.run.run_id
        paths = plan_command_paths(
            str(harness.root),
            command_kind=kind,
            invocation_id=invocation.invocation_id,
            run_id=run_id,
        )
        entry = self._entry_for(invocation.adapter_name)
        payload: dict[str, object] = {
            "command_kind": kind,
            "catalog_entry": entry,
            "invocation_id": invocation.invocation_id,
            "request_path": paths.request_path,
            "timeout_seconds": invocation.timeout_seconds,
        }
        if kind is _K.RUN:
            payload["work_dir"] = paths.work_dir
            payload["result_path"] = paths.result_path
        else:
            payload["output_path"] = paths.output_path
        command = AdapterCommand.model_validate(payload)
        inner = (
            WindowsProcessController() if self._controller is None else self._controller
        )
        tee = TeeController(inner)
        observer = RecordingObserver()
        token = ThreadSafeCancellationToken()
        stale = plan.stale_output_bytes
        if stale is not None:
            planted: bytes = stale
            command_root = Path(paths.command_root)

            def plant(_entry: SupervisionTraceEntry) -> None:
                # Plan 7.3: after the request file exists and before the supervisor's
                # baseline snapshot, so the boundary treats the file as pre-existing.
                (command_root / STALE_OUTPUT_FILE_NAME).write_bytes(planted)

            observer.on(_T.REQUEST_WRITTEN, plant)
        if plan.cancel_after_first_heartbeat:

            def cancel_on_heartbeat(entry: SupervisionTraceEntry) -> None:
                if entry.facts.get("event_type") == "HEARTBEAT":
                    token.request_cancellation()

            observer.on(_T.EVENT_ACCEPTED, cancel_on_heartbeat)
        supervisor = build_supervisor(
            lifecycle=lifecycle,
            controller=tee,
            clock=self._clock,
            supervision_root=str(harness.root),
            supervisor_instance_id=SCRIPTED_SUPERVISOR_INSTANCE_ID,
            cancellation_grace_seconds=self._grace,
            describe_limits=harness.limits,
            preflight=self._preflight,
            observers=(observer, *self._observers),
        )
        self.tees.append(tee)
        self.observers_seen.append(observer)
        self._token = token
        try:
            result = asyncio.run(supervisor.invoke(command, token))
        finally:
            self._token = None
        if isinstance(result, Failure):
            raise SupervisionRefused(result, invocation.invocation_id)
        outcome = result.value
        self.outcomes.append(outcome)
        return self._supervised(harness, plan, paths.command_root, tee, outcome)

    def _supervised(
        self,
        harness: OfflineCommandHarness,
        plan: CommandPlan,
        command_root: str,
        tee: TeeController,
        outcome: SupervisionOutcome,
    ) -> _Supervised:
        record = outcome.command_result.invocation
        run = None if plan.run is None else harness.stored_run(plan.run.run_id)
        stderr = outcome.command_result.stderr
        rejection: EventRejected | None = None
        if record.state is _C.PROTOCOL_FAILED:
            for entry in outcome.trace:
                if entry.kind is _T.EVENT_REJECTED and isinstance(
                    entry.rejection, EventRejected
                ):
                    rejection = entry.rejection
                    break
        raw_lines: tuple[bytes, ...] = ()
        if record.command_kind is not _K.DESCRIBE:
            lines, pending = frame_protocol_lines(
                b"", tee.last_stdout, max_event_bytes=harness.limits.max_event_bytes
            )
            raw_lines = (*lines, pending) if pending else lines
        baseline = tee.baseline
        written = (
            frozenset[str]()
            if baseline is None
            else snapshot_written_paths(command_root) - baseline
        )
        return _Supervised(
            invocation=record,
            run=run,
            events=outcome.command_result.accepted_events,
            summary=outcome.protocol_summary,
            raw_lines=raw_lines,
            rejection=rejection,
            replayed=outcome.replay_count,
            stderr=stderr if isinstance(stderr, StderrCapture) else None,
            diagnostics=outcome.command_result.diagnostics,
            stdout_bytes_seen=outcome.stdout_byte_count,
            written_paths=written,
            supervision_outcome=outcome,
        )


# --------------------------------------------------------------------------
# Row 47 through the production strategy (plan 9.4)
# --------------------------------------------------------------------------


def drive_stale_attempt(harness: OfflineCommandHarness, entry: Scenario) -> CommandRun:
    """The merged ``_stale_attempt`` sequence of ``test_validate_contract.py`` over the
    production strategy: attempt 1 validates and runs to ``FAILED``, the successor is
    created after the durable delay, and attempt 2's validate copies attempt 1's output
    byte for byte through the ``REQUEST_WRITTEN`` plant."""
    assert entry.row == _STALE_ATTEMPT_ROW
    experiment = harness.new_experiment(entry.adapter_name)
    experiment, first_run = harness.new_attempt(experiment)
    first_run = harness.validating(first_run)
    first = harness.validate(first_run, timeout_seconds=DEFAULT_TIMEOUT_SECONDS)
    assert first.outcome is not None
    assert first.outcome.run.state is _R.READY
    failed = harness.run(first.outcome.run, timeout_seconds=DEFAULT_TIMEOUT_SECONDS)
    assert failed.outcome is not None
    assert failed.outcome.run.state is _R.FAILED
    assert harness.primary_code_of(failed.reconciliation) == ENGINE_RUNTIME_FAILURE
    experiment, second_run = harness.successor(
        harness.stored_experiment(experiment.experiment_id), failed.outcome.run
    )
    assert second_run.attempt_number == 2
    assert second_run.predecessor_run_id == first_run.run_id
    second_run = harness.validating(second_run)
    assert first.output_bytes is not None
    return harness.validate(
        second_run,
        timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
        stale_output_bytes=first.output_bytes,
    )


# --------------------------------------------------------------------------
# The four Stage 6 contract modules' per-kind assertions (plan 9.4)
# --------------------------------------------------------------------------


def _starting_origin(invocation: CommandInvocationRecord) -> bool:
    """The plan 9.4 tolerance for the 1 s linked entries of row 26: the pre-handoff
    span exceeded the budget, so the terminal is ``STARTING``-origin."""
    return invocation.process_created is False


def _cleaned_pre_handoff_timeout(result: CommandRun, scenario: Scenario) -> bool:
    """Plan 9.4's STARTING-origin form of a row-26 linked entry, decided by the
    canonical record alone: a VALIDATE or RUN of row 26 that timed out before the
    RUNNING handoff carries no committed process-start facts (``process_created``
    False; the record validator keeps the start instant and identity ``MISSING``
    with it). A child may well have been launched and terminated; its start was
    never committed. Never decided by a missing file."""
    invocation = result.command_result.invocation
    return (
        scenario.row == _PROCESS_TIMEOUT_ROW
        and scenario.command in (_K.VALIDATE, _K.RUN)
        and invocation.state is _C.TIMED_OUT
        and _starting_origin(invocation)
    )


def _assert_cleaned_command_root(result: CommandRun, token: str) -> None:
    """The pre-handoff terminal's evidence (plan 7.5, 8.4): the supervisor removes
    the command root of an invocation that never reached RUNNING, so the request
    file is gone by design and cannot be read back. Proves the root is actually
    absent -- ``lstat`` fails with ``FileNotFoundError``; any other ``OSError``
    propagates, so "inaccessible" never passes -- while its parent survives; that
    the retained outcome of this very invocation traces exactly one successful
    ``COMMAND_ROOT_REMOVED`` cleanup action and no failed one; and that the raw
    token is absent from every surviving surface (records, diagnostics, events,
    stderr, the result, the outcome and the reconciliation). Evidence limit: this
    branch proves cleanup and token absence in what survives; it does not inspect
    the deleted wire bytes after the run or prove their earlier contents."""
    root = Path(result.command_root)
    try:
        os.lstat(root)
    except FileNotFoundError:
        absent = True
    else:
        absent = False
    assert absent, "the command root of a pre-handoff timeout was retained"
    assert root.parent.is_dir(), "the supervision root above the command root is gone"
    outcome = result.supervision_outcome
    assert outcome is not None
    invocation_id = result.command_result.invocation.invocation_id
    assert outcome.command_result.invocation.invocation_id == invocation_id
    removal = CleanupAction.COMMAND_ROOT_REMOVED.value
    completed = [
        entry
        for entry in outcome.trace
        if entry.kind is _T.CLEANUP_ACTION and entry.facts.get("action") == removal
    ]
    failed = [
        entry
        for entry in outcome.trace
        if entry.kind is _T.CLEANUP_FAILED and entry.facts.get("action") == removal
    ]
    assert len(completed) == 1, (
        "exactly one successful COMMAND_ROOT_REMOVED cleanup action is traced"
    )
    assert failed == [], "a COMMAND_ROOT_REMOVED cleanup failure is traced"
    absence: list[object] = list(token_free_projections(result))
    if result.outcome is not None:
        absence.append(result.outcome)
    if result.reconciliation is not None:
        absence.append(result.reconciliation)
    assert_token_absent(absence, token)


def _assert_wire_material_boundary(
    result: CommandRun, scenario: Scenario, token: str
) -> None:
    """Plan 11.3 item 5 on the production path: the wire-material check for every
    row, except the pre-handoff form of row 26's two linked entries, whose request
    file the supervisor removed with the command root (plan 9.4's tolerance). Every
    other row -- the RUNNING-origin form of row 26 included -- keeps the request-file
    and wire-material requirements unchanged."""
    if _cleaned_pre_handoff_timeout(result, scenario):
        _assert_cleaned_command_root(result, token)
    else:
        assert_token_only_in_wire_material(result, token)


def _assert_describe(
    harness: OfflineCommandHarness, result: CommandRun, scenario: Scenario
) -> None:
    invocation = result.command_result.invocation
    assert invocation.command_kind is _K.DESCRIBE
    assert _missing(invocation.run_id)
    assert invocation.state is scenario.invocation_state
    assert harness.store.committed_engine_runs() == ()
    assert harness.store.committed_run_events() == ()
    assert result.outcome is None
    assert result.command_result.accepted_events == ()
    assert result.command_result.protocol_integrity is ProtocolIntegrityStatus.INTACT
    assert result.written_paths <= frozenset({"output.json"})
    observation = result.observation
    assert observation is not None
    assert observation.adapter_name == scenario.adapter_name
    assert observation.adapter_version == FAKE_ADAPTER_VERSION
    if scenario.invocation_state is _C.TIMED_OUT:
        assert result.reconciliation is None
        assert result.command_result.timed_out is True
        assert harness.primary_code_of(invocation) == scenario.primary_code
        assert observation.available is False
        assert observation.reason_code == scenario.primary_code
        return
    assert result.command_result.timed_out is False
    assert invocation.native_exit_value == scenario.native_exit
    reconciliation = result.reconciliation
    assert isinstance(reconciliation, SemanticReconciliation)
    assert reconciliation.command_kind is _K.DESCRIBE
    assert reconciliation.verdict is scenario.verdict
    assert _missing(reconciliation.run_target_state)
    assert harness.primary_code_of(reconciliation) == scenario.primary_code
    if scenario.negotiation is None:
        assert _missing(reconciliation.negotiation)
    else:
        assert isinstance(reconciliation.negotiation, NegotiationResult)
        assert reconciliation.negotiation.outcome is scenario.negotiation
    assert observation.available is (scenario.verdict is _V.DESCRIBED)
    if scenario.verdict is _V.DESCRIBED:
        assert _missing(observation.reason_code)
        assert invocation.diagnostic_ids == ()
    else:
        assert observation.reason_code == scenario.primary_code
        assert set(harness.codes_of(invocation.diagnostic_ids)) == {
            scenario.primary_code
        }
        assert harness.primary_code_of(invocation) is None
    if scenario.row == 21:
        outcome = result.supervision_outcome
        assert outcome is not None
        assert outcome.stdout_byte_count == 1  # the tee saw the one stdout byte


def _assert_core_won_common(
    harness: OfflineCommandHarness, result: CommandRun, scenario: Scenario
) -> None:
    invocation = result.command_result.invocation
    run = harness.stored_run(invocation.run_id)
    assert run.state is scenario.run_state
    assert result.outcome is None
    assert result.reconciliation is None
    assert run.primary_terminal_diagnostic_id == invocation.primary_diagnostic_id
    for code in scenario.secondary_codes:
        assert code in harness.codes_of(invocation.diagnostic_ids)
    assert result.command_result.protocol_integrity is (
        ProtocolIntegrityStatus.VIOLATED
        if scenario.invocation_state is _C.PROTOCOL_FAILED
        else ProtocolIntegrityStatus.INTACT
    )
    assert result.command_result.cancelled is (
        scenario.invocation_state is _C.CANCELLED
    )
    assert result.command_result.timed_out is (
        scenario.invocation_state is _C.TIMED_OUT
    )
    assert harness.store.committed_run_events() == result.command_result.accepted_events
    assert _missing(result.command_result.parsed_output)
    codes = [item.error_code for item in result.command_result.diagnostics]
    if scenario.row == _PROCESS_TIMEOUT_ROW and _starting_origin(invocation):
        expected = (
            PROCESS_START_TIMED_OUT
            if scenario.command is _K.RUN
            else PROCESS_VALIDATE_TIMED_OUT
        )
        assert harness.primary_code_of(invocation) == expected
        assert expected in codes
        assert _missing(invocation.native_exit_value)
        assert invocation.process_created is False
    else:
        assert harness.primary_code_of(invocation) == scenario.primary_code
        assert scenario.primary_code in codes
        # The killed child's native exit is recorded by enrichment (plan 11.3 item 3);
        # the value is never pinned on the production path (plan 9.4).
        assert not _missing(invocation.native_exit_value)
        assert invocation.process_created is True
    if scenario.invocation_state is _C.PROTOCOL_FAILED:
        rejection = result.rejection
        assert isinstance(rejection, EventRejected)
        assert rejection.diagnostic.error_code == scenario.primary_code
        assert rejection.diagnostic.diagnostic_id == invocation.primary_diagnostic_id
        sample = rejection.sample.sample
        if isinstance(sample, str):
            leaked = harness.token_for(run.run_id) in sample
            assert leaked is False
    else:
        assert result.rejection is None


def _assert_validate(
    harness: OfflineCommandHarness, result: CommandRun, scenario: Scenario
) -> None:
    invocation = result.command_result.invocation
    assert invocation.command_kind is _K.VALIDATE
    assert invocation.state is scenario.invocation_state
    assert not _missing(invocation.run_id)
    run = harness.stored_run(invocation.run_id)
    assert run.state is scenario.run_state
    assert run.state not in SUCCESS_ENGINE_RUN_STATES
    assert _missing(run.finalization_deadline_utc)
    assert harness.invocations_of(run.run_id, _K.RUN) == ()
    assert result.written_paths <= frozenset({"output.json", "stale-output.json"})
    assert not isinstance(result.command_result.parsed_output, AdapterResultManifest)
    if scenario.accepted_events is not None:
        assert len(result.command_result.accepted_events) == scenario.accepted_events
    token = harness.token_for(run.run_id)
    assert_token_absent(token_free_projections(result), token)
    _assert_wire_material_boundary(result, scenario, token)
    if scenario.core_won:
        _assert_core_won_common(harness, result, scenario)
        return
    assert invocation.native_exit_value == scenario.native_exit
    assert result.command_result.protocol_integrity is ProtocolIntegrityStatus.INTACT
    assert result.outcome is not None
    assert result.outcome.run == run
    assert result.outcome.invocation == invocation
    assert _missing(result.outcome.superseded_by)
    reconciliation = result.reconciliation
    assert isinstance(reconciliation, SemanticReconciliation)
    assert reconciliation.command_kind is _K.VALIDATE
    assert reconciliation.verdict is scenario.verdict
    assert harness.primary_code_of(reconciliation) == scenario.primary_code
    assert _missing(reconciliation.sanitized_manifest)
    if scenario.verdict is _V.VALIDATED_READY:
        assert invocation.diagnostic_ids == ()
        assert run.availability_observation_id == AVAIL_A
        assert isinstance(
            reconciliation.sanitized_validation_result, AdapterValidationResult
        )
        return
    primary = reconciliation.primary_diagnostic
    assert not _missing(primary)
    assert run.primary_terminal_diagnostic_id == primary.diagnostic_id
    assert primary.diagnostic_id in invocation.diagnostic_ids
    assert primary.run_id == run.run_id
    assert primary.invocation_id == invocation.invocation_id
    if scenario.verdict is _V.UNAVAILABLE:
        assert run.availability_observation_id == AVAIL_A


def _assert_run(
    harness: OfflineCommandHarness, result: CommandRun, scenario: Scenario
) -> None:
    invocation = result.command_result.invocation
    assert invocation.command_kind is _K.RUN
    assert invocation.state is _C.EXITED
    assert invocation.native_exit_value == scenario.native_exit
    assert result.command_result.protocol_integrity is ProtocolIntegrityStatus.INTACT
    assert result.command_result.cancelled is False
    assert result.command_result.timed_out is False
    assert not _missing(invocation.run_id)
    run = harness.stored_run(invocation.run_id)
    assert run.state is scenario.run_state
    assert run.state not in SUCCESS_ENGINE_RUN_STATES
    assert _missing(run.finalization_deadline_utc)
    work_prefix = f"runs/{run.run_id}/work/"
    assert all(path.startswith(work_prefix) for path in result.written_paths)
    if scenario.accepted_events is not None:
        assert len(result.command_result.accepted_events) == scenario.accepted_events
    assert harness.store.committed_run_events() == result.command_result.accepted_events
    token = harness.token_for(run.run_id)
    assert_token_absent(token_free_projections(result), token)
    assert_token_only_in_wire_material(result, token)
    assert result.outcome is not None
    assert result.outcome.run == run
    assert result.outcome.invocation == invocation
    assert _missing(result.outcome.superseded_by)
    reconciliation = result.reconciliation
    assert isinstance(reconciliation, SemanticReconciliation)
    assert reconciliation.command_kind is _K.RUN
    assert reconciliation.verdict is scenario.verdict
    assert harness.primary_code_of(reconciliation) == scenario.primary_code
    for code in scenario.secondary_codes:
        assert code in harness.codes_of(invocation.diagnostic_ids)
    if scenario.sanitized_manifest:
        sanitized = reconciliation.sanitized_manifest
        assert isinstance(sanitized, SanitizedAdapterResultManifest)
        assert sanitized.semantic_status is scenario.semantic_status
        assert reconciliation.semantic_status is scenario.semantic_status
        assert (
            sanitized.sanitized_adapter_result_manifest_hash
            != sanitized.source_adapter_result_manifest_hash
        )
        assert sanitized.attempt_token_hash == run.attempt_token_hash
        assert sanitized.run_id == run.run_id
        assert sanitized.invocation_id == invocation.invocation_id
    else:
        assert _missing(reconciliation.sanitized_manifest)
        assert _missing(reconciliation.semantic_status)
    if scenario.verdict is _V.RESULT_FINALIZATION_ELIGIBLE:
        # Plan 9.3 (Stage 6): the run stays RUNNING at the revision the launch left it.
        assert (run.state, run.revision) == (_R.RUNNING, 4)
        assert _missing(run.primary_terminal_diagnostic_id)
        assert set(harness.codes_of(invocation.diagnostic_ids)) == set(
            scenario.secondary_codes
        )
        return
    primary = reconciliation.primary_diagnostic
    assert not _missing(primary)
    assert run.primary_terminal_diagnostic_id == primary.diagnostic_id
    assert primary.diagnostic_id in invocation.diagnostic_ids
    assert primary.run_id == run.run_id
    assert primary.invocation_id == invocation.invocation_id


def _assert_core_won_run(
    harness: OfflineCommandHarness, result: CommandRun, scenario: Scenario
) -> None:
    invocation = result.command_result.invocation
    assert invocation.command_kind is _K.RUN
    assert invocation.state is scenario.invocation_state
    assert not _missing(invocation.run_id)
    run = harness.stored_run(invocation.run_id)
    assert run.state not in SUCCESS_ENGINE_RUN_STATES
    if scenario.accepted_events is not None:
        assert len(result.command_result.accepted_events) == scenario.accepted_events
    _assert_core_won_common(harness, result, scenario)
    token = harness.token_for(run.run_id)
    assert_token_absent(token_free_projections(result), token)
    _assert_wire_material_boundary(result, scenario, token)


def _assert_retained_outcome_token_free(
    harness: OfflineCommandHarness, result: CommandRun
) -> None:
    """Plan 9.4, 11: the trace, the protocol summary and the executable observation of
    the retained outcome never carry the raw token (a ``ManifestParse`` stays excluded,
    as the merged manifest keeps the token on the wire by design)."""
    outcome = result.supervision_outcome
    assert outcome is not None
    token = harness.token_for(result.command_result.invocation.run_id)
    assert_token_absent(
        (*outcome.trace, outcome.protocol_summary, outcome.executable_observation),
        token,
    )


def _assert_no_false_success(
    harness: OfflineCommandHarness, result: CommandRun, scenario: Scenario
) -> None:
    """The brief's closure: no adverse row reaches a success run state, a
    finalization-eligible verdict or an unwritten primary; a describe never creates a
    run and an adverse describe leaves the adapter unavailable."""
    invocation = result.command_result.invocation
    if scenario.command is _K.DESCRIBE:
        assert harness.store.committed_engine_runs() == ()
        if scenario.verdict is not _V.DESCRIBED:
            assert result.observation is not None
            assert result.observation.available is False
        return
    run = harness.stored_run(invocation.run_id)
    assert run.state not in SUCCESS_ENGINE_RUN_STATES
    assert _missing(run.finalization_deadline_utc)
    if scenario.verdict not in (_V.VALIDATED_READY, _V.RESULT_FINALIZATION_ELIGIBLE):
        assert run.state in TERMINAL_ENGINE_RUN_STATES
        assert not _missing(run.primary_terminal_diagnostic_id)
        if result.reconciliation is not None:
            assert result.reconciliation.verdict is not _V.RESULT_FINALIZATION_ELIGIBLE


def _assert_no_stray_write(harness: OfflineCommandHarness, result: CommandRun) -> None:
    """Plan 9.4 row 47 and plan 7.3: no Stage 6 row writes outside its permitted paths
    on the production path, and the row-47 stale file planted at ``REQUEST_WRITTEN`` is
    pre-existing to the boundary, so no row carries ``PROCESS.WRITE_BOUNDARY_VIOLATION``
    or a ``WRITE_BOUNDARY_VIOLATION`` trace entry."""
    invocation = result.command_result.invocation
    assert PROCESS_WRITE_BOUNDARY_VIOLATION not in harness.codes_of(
        invocation.diagnostic_ids
    )
    assert PROCESS_WRITE_BOUNDARY_VIOLATION not in {
        item.error_code for item in result.command_result.diagnostics
    }
    outcome = result.supervision_outcome
    assert outcome is not None
    assert _T.WRITE_BOUNDARY_VIOLATION not in {entry.kind for entry in outcome.trace}


def assert_stage_six_expectation(
    harness: OfflineCommandHarness, command_run: CommandRun, entry: Scenario
) -> None:
    """Exactly what the four Stage 6 contract modules assert for ``entry`` (plan 9.4),
    the tolerated production differences of that section, the retained-outcome token
    walk on every validate and run row, the write-boundary silence of every row and the
    no-false-success closure."""
    if entry.command is _K.DESCRIBE:
        _assert_describe(harness, command_run, entry)
    elif entry.command is _K.VALIDATE:
        _assert_validate(harness, command_run, entry)
    elif entry.core_won:
        _assert_core_won_run(harness, command_run, entry)
    else:
        _assert_run(harness, command_run, entry)
    if entry.command is not _K.DESCRIBE:
        _assert_retained_outcome_token_free(harness, command_run)
    _assert_no_stray_write(harness, command_run)
    _assert_no_false_success(harness, command_run, entry)


def reconciliation_content(result: CommandRun) -> tuple[object, ...]:
    """A reconciliation's order-independent content (the harness-safety helper): the
    verdict, the primary code, the status and the declared candidates."""
    reconciliation = result.reconciliation
    assert isinstance(reconciliation, SemanticReconciliation)
    manifest = reconciliation.sanitized_manifest
    declarations: tuple[tuple[str, str, int, str], ...] = ()
    if isinstance(manifest, SanitizedAdapterResultManifest):
        declarations = tuple(
            (
                item.artifact_kind,
                item.media_type,
                item.declared_size_bytes,
                item.declared_sha256,
            )
            for item in manifest.candidate_declarations
        )
    primary = reconciliation.primary_diagnostic
    code = primary.error_code if isinstance(primary, Diagnostic) else None
    return (reconciliation.verdict, code, reconciliation.semantic_status, declarations)


# --------------------------------------------------------------------------
# Windows fixtures (plan 10) and the hygiene proofs
# --------------------------------------------------------------------------


def identity_for(pid: int, creation_identity: str) -> ProcessIdentity:
    """The durable identity of a process a test launched or a report recorded."""
    return ProcessIdentity(
        pid=pid,
        creation_identity=creation_identity,
        executable_path=LAUNCHER_PATH,
        executable_hash=LAUNCHER_HASH,
        supervisor_instance_id=SCRIPTED_SUPERVISOR_INSTANCE_ID,
    )


def failing_job_factory() -> int:
    """Plan 8.2 step 3: force the job-unavailable branch with a real child."""
    raise WindowsApiError("CreateJobObjectW", _ERROR_NO_SYSTEM_RESOURCES)


def started(
    result: LaunchedProcess | WindowsLaunchedProcess | object,
) -> WindowsLaunchedProcess:
    """Narrow a launch result to the Windows process, failing on a ``LaunchFailure``."""
    assert isinstance(result, WindowsLaunchedProcess), result
    return result


def launch_sleeper(
    controller: ProcessController,
    *,
    invocation_id: str,
    cwd: Path,
    ready: bool = True,
) -> WindowsLaunchedProcess:
    """A sleeper that ignores ``SIGBREAK``; with ``ready`` the test waits for its
    readiness line so no interrupt can reach an initializing child (plan Task 4)."""
    program = READY_SLEEPER_PROGRAM if ready else SLEEPER_PROGRAM
    launched = started(
        controller.launch(
            LaunchSpecification(
                invocation_id=invocation_id,
                argv=(sys.executable, "-I", "-B", "-c", program),
                cwd=str(cwd),
            )
        )
    )
    if ready:
        assert launched.stdout.readline().strip() == b"ready"
    return launched


def own_creation_100ns() -> int:
    """The test process's own creation time, read through the Windows API."""
    handle = windows_api.open_process_limited(os.getpid())
    try:
        return windows_api.process_times(handle)
    finally:
        windows_api.close_handle(handle)


def _own_images() -> frozenset[Path]:
    """The two images a sleeper the fake spawned may carry: the venv launcher the fake's
    ``sys.executable`` names (plan 4.2), or the base interpreter it hands over to."""
    base = getattr(sys, "_base_executable", None)
    images = {Path(sys.executable).resolve()}
    if isinstance(base, str) and base:
        images.add(Path(base).resolve())
    return frozenset(images)


def _sleeper_identity(pid: int) -> ProcessIdentity | None:
    """The live identity behind a pid the fake reported, or ``None`` when the pid is
    gone or names a process whose image is neither of ours (a reused pid is never
    ours)."""
    try:
        handle = windows_api.open_process_limited(pid)
    except WindowsApiError:
        return None
    try:
        creation = windows_api.process_times(handle)
    except WindowsApiError:
        return None
    finally:
        windows_api.close_handle(handle)
    identity = identity_for(pid, render_creation_identity(pid, creation))
    inspection = WindowsProcessController().inspect(identity)
    if inspection.presence is not ProcessPresence.ALIVE_MATCHING:
        return None
    image = inspection.observed_image_path
    if not isinstance(image, str) or Path(image).resolve() not in _own_images():
        return None
    return identity


def descendant_identity(strategy: ProductionSupervision, pid: int) -> ProcessIdentity:
    """The recorded identity of a descendant the last termination report enumerated
    (plan 8.3: pid plus creation time, verified against its parent); the positive
    control that a pid the fake reported was really part of the terminated tree."""
    matches = [item for item in strategy.last_tee.descendants if item.pid == pid]
    assert len(matches) == 1, "the reported pid is not among the enumerated descendants"
    return identity_for(pid, matches[0].creation_identity)


def live_descendants(strategy: ProductionSupervision) -> tuple[DescendantIdentity, ...]:
    """Plan 8.3's verified enumeration of the last launched root's tree, for an observer
    hook that runs while the whole chain is alive (the grandchild row heartbeats until
    interrupted, so its first accepted heartbeat is such an instant): the positive
    control that the pid the fake reported is a verified descendant and that the pid
    helpers see a live sleeper of ours."""
    pid, creation_identity = strategy.last_tee.identities[-1]
    return windows_api.descendants_of(
        pid, parse_creation_identity(creation_identity).creation_100ns
    )


def presence_of_pid(pid: int) -> ProcessPresence:
    """``ALIVE_MATCHING`` only for a live base-interpreter sleeper at that pid."""
    identity = _sleeper_identity(pid)
    if identity is None:
        return ProcessPresence.ABSENT
    return WindowsProcessController().inspect(identity).presence


def terminate_reported_pid(pid: int) -> None:
    """Terminate a sleeper the fake reported, by identity, through the controller
    (plan 8.1: never a kill by pid alone); a gone or foreign pid is left untouched."""
    identity = _sleeper_identity(pid)
    if identity is None:
        return
    WindowsProcessController().terminate_tree(identity, FORCED_TERMINATION_EXIT_CODE)


def assert_console_attached() -> None:
    """Plan 10: every real-process interrupt test requires an attached console."""
    assert windows_api.console_process_count() >= 1, (
        "the test process is not attached to a console; CTRL_BREAK cannot be generated"
    )


def assert_nothing_launched_survives(strategy: ProductionSupervision) -> None:
    """The test-tree rule (plan 10): every identity a strategy's controller launched or
    recorded as a descendant is terminated if still ours and asserted not
    ``ALIVE_MATCHING`` through a fresh controller. Scripted controllers launch nothing
    real, so their identities are not inspected."""
    fresh = WindowsProcessController()
    for tee in strategy.tees:
        if not isinstance(tee.inner, WindowsProcessController):
            continue
        identities = [
            identity_for(pid, creation) for pid, creation in tee.identities
        ] + [identity_for(item.pid, item.creation_identity) for item in tee.descendants]
        for identity in identities:
            if fresh.inspect(identity).presence is ProcessPresence.ALIVE_MATCHING:
                fresh.terminate_tree(identity, FORCED_TERMINATION_EXIT_CODE)
            assert fresh.inspect(identity).presence is not (
                ProcessPresence.ALIVE_MATCHING
            )


def grandchild_pid_of(result: CommandRun) -> int:
    """The ``grandchild_pid=<n>`` line the grandchild fakes write on stderr."""
    capture = result.command_result.stderr
    assert isinstance(capture, StderrCapture)
    text = capture.sanitized_text
    assert isinstance(text, str)
    match = _GRANDCHILD_LINE.search(text)
    assert match is not None, "the fake reported no grandchild pid"
    return int(match.group(1))


def trace_kinds(result: CommandRun) -> tuple[SupervisionTraceKind, ...]:
    outcome = result.supervision_outcome
    assert outcome is not None
    return tuple(entry.kind for entry in outcome.trace)


def trace_entries(
    result: CommandRun, kind: SupervisionTraceKind
) -> tuple[SupervisionTraceEntry, ...]:
    outcome = result.supervision_outcome
    assert outcome is not None
    return tuple(entry for entry in outcome.trace if entry.kind is kind)


def monotonic_gap_seconds(
    result: CommandRun, first: SupervisionTraceKind, second: SupervisionTraceKind
) -> float:
    """The monotonic seconds between the first retained entries of two kinds."""
    (start, *_) = trace_entries(result, first)
    (end, *_) = trace_entries(result, second)
    return (end.monotonic_100ns - start.monotonic_100ns) / 1e7


def details_of(
    harness: OfflineCommandHarness, invocation: CommandInvocationRecord, code: str
) -> Mapping[DiagnosticDetailKey, DiagnosticDetailValue]:
    """The ``details`` of the first stored diagnostic with ``code`` on the record."""
    identities = list(invocation.diagnostic_ids)
    primary = invocation.primary_diagnostic_id
    if isinstance(primary, str) and primary not in identities:
        identities.insert(0, primary)
    for identity in identities:
        diagnostic = harness.diagnostic(identity)
        if diagnostic.error_code == code:
            return diagnostic.details
    raise AssertionError(f"no diagnostic with code {code} on the record")


def stage5_lifecycle(harness: OfflineCommandHarness) -> Stage5InvocationLifecycle:
    """A fresh lifecycle over the harness store (what a restarted process binds)."""
    return Stage5InvocationLifecycle(
        unit_of_work=harness._unit_of_work(),
        clock=harness.clock,
        diagnostics=SeedingDiagnosticRecorder(harness.store),
    )


def reconcile(
    harness: OfflineCommandHarness,
    *,
    controller: ProcessController,
    observer: SupervisionObserver | MISSING = MISSING,  # type: ignore[valid-type]
) -> ReconciliationReport:
    """One reconciliation pass over the harness store with a fresh lifecycle, a fresh
    source and the given controller: durable records plus fresh inspection only."""
    return ok(
        reconcile_invocations(
            source=InMemoryReconciliationSource(harness.store),
            lifecycle=stage5_lifecycle(harness),
            controller=controller,
            preflight=ok(
                probe_long_path_support(str(harness.root), now=harness.clock.now_utc())
            ),
            clock=harness.clock,
            supervisor_instance_id=SCRIPTED_SUPERVISOR_INSTANCE_ID,
            observer=observer,
        )
    )


__all__ = [
    "LAUNCHER_HASH",
    "LAUNCHER_PATH",
    "READY_SLEEPER_PROGRAM",
    "SLEEPER_PROGRAM",
    "ProductionSupervision",
    "SupervisionRefused",
    "assert_console_attached",
    "assert_nothing_launched_survives",
    "assert_stage_six_expectation",
    "descendant_identity",
    "details_of",
    "drive_stale_attempt",
    "failing_job_factory",
    "grandchild_pid_of",
    "identity_for",
    "launch_sleeper",
    "live_descendants",
    "monotonic_gap_seconds",
    "ok",
    "own_creation_100ns",
    "presence_of_pid",
    "reconcile",
    "reconciliation_content",
    "stage5_lifecycle",
    "started",
    "terminate_reported_pid",
    "trace_entries",
    "trace_kinds",
]
