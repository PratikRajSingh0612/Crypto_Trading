"""Stage 7 Task 8: process groups, Job Objects, termination and backpressure (plan 10).

Manifest rows W-12 to W-17. Real children of the Stage 7 fake run through the production
supervisor: the grandchild tree dies with the Job Object and every controller cleanup
action completes (W-12); a cooperating adapter exits ``50`` on the graceful interrupt
inside the grace and is never force-terminated (W-13); an adapter ignoring the interrupt
is force-terminated after the grace with ``1067`` (W-14); with the Job Object
unavailable the verified Toolhelp enumeration still kills the grandchild (W-15); an
undeliverable
interrupt is recorded and the grace is still waited before the force (W-16, scripted);
and a 5000-line stdout flood is drained without a dropped line or a replay (W-17).
Destructive actions are counted through the tee, never inferred from idempotence: at
most one interrupt and at most one forced termination per invocation. Every interrupt
test asserts the console precondition of plan 10 first, and every test asserts in
``finally:`` that nothing it launched is still ``ALIVE_MATCHING``.
"""

from __future__ import annotations

from pathlib import Path

from supervised_strategy import (
    ProductionSupervision,
    assert_console_attached,
    assert_nothing_launched_survives,
    details_of,
    failing_job_factory,
    grandchild_pid_of,
    identity_for,
    live_descendants,
    monotonic_gap_seconds,
    presence_of_pid,
    trace_kinds,
)
from supervision_scenarios import SUPERVISION_SCENARIOS

from contract.harness import CommandRun, OfflineCommandHarness, build_harness
from crypto_lab.adapters.diagnostics import PROCESS_CANCELLED
from crypto_lab.adapters.limits import PROTOCOL_LIMITS_DEFAULT
from crypto_lab.adapters.vocabulary import ReconciliationVerdict
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
)
from crypto_lab.process_supervision.diagnostics import (
    PROCESS_FORCED_TERMINATION,
    PROCESS_GRACEFUL_INTERRUPT_UNAVAILABLE,
    PROCESS_JOB_OBJECT_UNAVAILABLE,
)
from crypto_lab.process_supervision.models import (
    FORCED_TERMINATION_EXIT_CODE,
    DescendantIdentity,
    InterruptOutcome,
    ProcessPresence,
    SupervisionTraceEntry,
    SupervisionTraceKind,
)
from crypto_lab.process_supervision.windows_process import WindowsProcessController
from doubles.supervision import RecordingObserver, ScriptedProcessController

_C = CommandInvocationState
_R = EngineRunState
_T = SupervisionTraceKind
_TIMEOUT = 30


def _run(
    root: Path,
    adapter_name: str,
    strategy: ProductionSupervision,
    *,
    cancel_after_first_heartbeat: bool,
    timeout_seconds: int = _TIMEOUT,
) -> tuple[OfflineCommandHarness, CommandRun]:
    harness = build_harness(
        root,
        adapter_name,
        limits=PROTOCOL_LIMITS_DEFAULT,
        seed=f"task8-tree-{adapter_name}",
        supervise=strategy,
    )
    return harness, harness.drive(
        adapter_name,
        CommandKind.RUN,
        timeout_seconds=timeout_seconds,
        cancel_after_first_heartbeat=cancel_after_first_heartbeat,
    )


def _assert_cancelled(
    harness: OfflineCommandHarness, result: CommandRun
) -> tuple[str, ...]:
    invocation = result.command_result.invocation
    assert invocation.state is _C.CANCELLED
    assert invocation.process_created is True
    assert invocation.cleanup_complete is True
    assert harness.primary_code_of(invocation) == PROCESS_CANCELLED
    run = harness.stored_run(invocation.run_id)
    assert run.state is _R.CANCELLED
    assert run.primary_terminal_diagnostic_id == invocation.primary_diagnostic_id
    assert result.outcome is None
    assert result.command_result.cancelled is True
    return harness.codes_of(invocation.diagnostic_ids)


def _assert_descendants_dead(strategy: ProductionSupervision, grandchild: int) -> None:
    tee = strategy.last_tee
    descendants = tee.descendants
    assert grandchild in {item.pid for item in descendants}
    fresh = WindowsProcessController()
    for descendant in descendants:
        presence = fresh.inspect(
            identity_for(descendant.pid, descendant.creation_identity)
        ).presence
        assert presence is ProcessPresence.ABSENT


# --- W-12: the grandchild dies with the tree; every handle is closed ------------------


def test_a_grandchild_dies_with_the_tree_and_every_handle_is_closed(
    tmp_path: Path,
) -> None:
    assert_console_attached()
    # The positive control for the pid helpers of W-24 and W-25: the fake spawns the
    # sleeper before its first heartbeat and then heartbeats until interrupted, so at
    # the first accepted heartbeat the whole chain is alive and the identity-first
    # enumeration of plan 8.3 deterministically holds the sleeper; every enumerated
    # process is one of ours and presence_of_pid sees each of them ALIVE_MATCHING.
    observer = RecordingObserver()
    strategy = ProductionSupervision(
        cancellation_grace_seconds=1, observers=(observer,)
    )
    live_tree: list[DescendantIdentity] = []
    live_presences: list[ProcessPresence] = []

    def record_live_tree(entry: SupervisionTraceEntry) -> None:
        if entry.facts.get("event_type") == "HEARTBEAT" and not live_tree:
            live_tree.extend(live_descendants(strategy))
            live_presences.extend(presence_of_pid(item.pid) for item in live_tree)

    observer.on(_T.EVENT_ACCEPTED, record_live_tree)
    try:
        harness, result = _run(
            tmp_path, "fake.grandchild", strategy, cancel_after_first_heartbeat=True
        )
        codes = _assert_cancelled(harness, result)
        invocation = result.command_result.invocation
        assert PROCESS_FORCED_TERMINATION in codes
        forced = details_of(harness, invocation, PROCESS_FORCED_TERMINATION)
        assert forced["reason"] == "grace_elapsed"
        assert invocation.native_exit_value == FORCED_TERMINATION_EXIT_CODE
        tee = strategy.last_tee
        assert tee.interrupt_calls == 1
        assert tee.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]
        (report,) = tee.termination_reports
        assert report.forced is True
        assert report.job_terminated is True
        assert report.failures == ()
        grandchild = grandchild_pid_of(result)
        _assert_descendants_dead(strategy, grandchild)
        # The positive control: the reported pid was a verified descendant while the
        # chain lived, and the pid helper saw every enumerated process alive.
        assert grandchild in {item.pid for item in live_tree}
        assert live_presences
        assert set(live_presences) == {ProcessPresence.ALIVE_MATCHING}
        for item in live_tree:
            recorded = identity_for(item.pid, item.creation_identity)
            assert (
                WindowsProcessController().inspect(recorded).presence
                is ProcessPresence.ABSENT
            )
        assert presence_of_pid(grandchild) is not ProcessPresence.ALIVE_MATCHING
        (close_report,) = tee.close_reports
        assert close_report.complete
        kinds = trace_kinds(result)
        assert kinds.count(_T.FORCED_TERMINATION) == 1
        assert kinds.count(_T.INTERRUPT_SENT) == 1
        assert kinds.count(_T.ENRICHMENT_COMMITTED) == 1
        assert PROCESS_JOB_OBJECT_UNAVAILABLE not in codes
    finally:
        assert_nothing_launched_survives(strategy)


# --- W-13, W-14: graceful and forced termination --------------------------------------


def test_a_graceful_interrupt_lets_the_adapter_exit_fifty_within_grace(
    tmp_path: Path,
) -> None:
    assert_console_attached()
    strategy = ProductionSupervision(cancellation_grace_seconds=5)
    try:
        harness, result = _run(
            tmp_path,
            "fake.cancellation-graceful",
            strategy,
            cancel_after_first_heartbeat=True,
        )
        codes = _assert_cancelled(harness, result)
        invocation = result.command_result.invocation
        assert invocation.native_exit_value == 50
        assert PROCESS_FORCED_TERMINATION not in codes
        assert PROCESS_GRACEFUL_INTERRUPT_UNAVAILABLE not in codes
        kinds = trace_kinds(result)
        assert kinds.count(_T.INTERRUPT_SENT) == 1
        assert _T.FORCED_TERMINATION not in kinds
        tee = strategy.last_tee
        assert tee.interrupt_calls == 1
        assert tee.terminate_calls == []
        assert monotonic_gap_seconds(result, _T.TERMINAL_DECIDED, _T.EXIT_REAPED) < 5.0
    finally:
        assert_nothing_launched_survives(strategy)


def test_an_adapter_ignoring_the_interrupt_is_force_terminated_after_grace(
    tmp_path: Path,
) -> None:
    assert_console_attached()
    strategy = ProductionSupervision(cancellation_grace_seconds=1)
    try:
        harness, result = _run(
            tmp_path,
            "fake.cancellation-ignores-interrupt",
            strategy,
            cancel_after_first_heartbeat=True,
        )
        codes = _assert_cancelled(harness, result)
        invocation = result.command_result.invocation
        assert PROCESS_FORCED_TERMINATION in codes
        forced = details_of(harness, invocation, PROCESS_FORCED_TERMINATION)
        assert forced["reason"] == "grace_elapsed"
        assert invocation.native_exit_value == FORCED_TERMINATION_EXIT_CODE
        kinds = trace_kinds(result)
        assert kinds.index(_T.INTERRUPT_SENT) < kinds.index(_T.FORCED_TERMINATION)
        assert kinds.count(_T.FORCED_TERMINATION) == 1
        tee = strategy.last_tee
        assert tee.interrupt_calls == 1
        assert tee.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]
        elapsed = monotonic_gap_seconds(
            result, _T.TERMINAL_DECIDED, _T.FORCED_TERMINATION
        )
        assert 1.0 <= elapsed < 3.0
    finally:
        assert_nothing_launched_survives(strategy)


# --- W-15: the Job Object unavailable -------------------------------------------------


def test_when_the_job_object_is_unavailable_toolhelp_termination_still_kills_the_grandchild(  # noqa: E501 - the plan 10 test name, verbatim
    tmp_path: Path,
) -> None:
    assert_console_attached()
    strategy = ProductionSupervision(
        cancellation_grace_seconds=1,
        controller=WindowsProcessController(job_object_factory=failing_job_factory),
    )
    try:
        harness, result = _run(
            tmp_path, "fake.grandchild", strategy, cancel_after_first_heartbeat=True
        )
        codes = _assert_cancelled(harness, result)
        invocation = result.command_result.invocation
        assert PROCESS_JOB_OBJECT_UNAVAILABLE in codes
        assert PROCESS_FORCED_TERMINATION in codes
        unavailable = details_of(harness, invocation, PROCESS_JOB_OBJECT_UNAVAILABLE)
        assert unavailable["fallback"] == "toolhelp_descendants"
        tee = strategy.last_tee
        (report,) = tee.termination_reports
        assert report.forced is True
        assert report.job_terminated is False
        _assert_descendants_dead(strategy, grandchild_pid_of(result))
        assert tee.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]
    finally:
        assert_nothing_launched_survives(strategy)


# --- W-16: an undeliverable interrupt (scripted) --------------------------------------


def test_an_undeliverable_interrupt_records_the_limitation_and_still_waits_the_grace(
    tmp_path: Path,
) -> None:
    scripted = ScriptedProcessController()
    scripted.interrupt_outcome = InterruptOutcome.UNAVAILABLE
    observer = RecordingObserver()
    strategy = ProductionSupervision(
        cancellation_grace_seconds=1, controller=scripted, observers=(observer,)
    )
    # Cancellation is requested the instant the handoff commits: the child is owned and
    # running, no heartbeat is needed, and the interrupt cannot be generated.
    observer.on(_T.RUNNING_COMMITTED, lambda _entry: strategy.request_cancellation())
    harness, result = _run(
        tmp_path, "fake.conformant", strategy, cancel_after_first_heartbeat=False
    )
    codes = _assert_cancelled(harness, result)
    invocation = result.command_result.invocation
    assert PROCESS_GRACEFUL_INTERRUPT_UNAVAILABLE in codes
    assert PROCESS_FORCED_TERMINATION in codes
    assert details_of(harness, invocation, PROCESS_FORCED_TERMINATION)["reason"] == (
        "interrupt_unavailable"
    )
    kinds = trace_kinds(result)
    assert _T.INTERRUPT_SENT not in kinds
    assert kinds.index(_T.INTERRUPT_UNAVAILABLE) < kinds.index(_T.FORCED_TERMINATION)
    assert kinds.count(_T.FORCED_TERMINATION) == 1
    assert (
        monotonic_gap_seconds(result, _T.INTERRUPT_UNAVAILABLE, _T.FORCED_TERMINATION)
        >= 1.0
    )
    assert scripted.interrupt_calls == 1
    assert scripted.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]
    assert invocation.native_exit_value == FORCED_TERMINATION_EXIT_CODE


# --- W-17: backpressure ------------------------------------------------------------


def test_a_stdout_flood_is_drained_without_deadlock(tmp_path: Path) -> None:
    # The flood row's timeout is the scenario table's (plan 10 "timeouts of 30 s unless
    # stated"; the table states 120 s): 5001 events each cost the supervision thread a
    # parse, a ledger append and a trace entry, about 2-5 ms per event on this host and
    # slower under coverage tracing, so the plan's default would race the host's load.
    (flood,) = (
        item for item in SUPERVISION_SCENARIOS if item.name == "fake.stdout-flood"
    )
    strategy = ProductionSupervision(cancellation_grace_seconds=1)
    try:
        harness, result = _run(
            tmp_path,
            "fake.stdout-flood",
            strategy,
            cancel_after_first_heartbeat=False,
            timeout_seconds=flood.timeout_seconds,
        )
        invocation = result.command_result.invocation
        assert invocation.state is _C.EXITED
        assert invocation.native_exit_value == 0
        assert len(result.command_result.accepted_events) == 5001
        assert result.replayed_count == 0
        assert harness.store.committed_run_events() == (
            result.command_result.accepted_events
        )
        assert not any(
            item.error_code.startswith("PROTOCOL.")
            for item in result.command_result.diagnostics
        )
        assert result.reconciliation is not None
        assert result.reconciliation.verdict is (
            ReconciliationVerdict.RESULT_FINALIZATION_ELIGIBLE
        )
        assert harness.stored_run(invocation.run_id).state is _R.RUNNING
        assert monotonic_gap_seconds(result, _T.RUNNING_COMMITTED, _T.EXIT_REAPED) < (
            flood.timeout_seconds
        )
        # Plan 10 asserts nothing about termination here, and the supervisor may fire
        # its pipe-holder rule once on the reaped root when the parse of the final
        # 64-chunk backlog outlasts the 1 s window (the idle stamp is taken before the
        # parse; observed under coverage tracing, a Task 6 timing note for Task 9).
        # Pinned rather than tolerated silently: at most one forced termination, only
        # with reason pipe_holder, never an interrupt, no descendant killed, and the
        # root's own exit still recorded on the EXITED transition.
        tee = strategy.last_tee
        kinds = trace_kinds(result)
        assert tee.interrupt_calls == 0
        assert tee.terminate_calls in ([], [FORCED_TERMINATION_EXIT_CODE])
        assert kinds.count(_T.FORCED_TERMINATION) == len(tee.terminate_calls)
        if tee.terminate_calls:
            forced = details_of(harness, invocation, PROCESS_FORCED_TERMINATION)
            assert forced["reason"] == "pipe_holder"
            (report,) = tee.termination_reports
            assert report.descendants == ()
            assert report.failures == ()
        else:
            assert PROCESS_FORCED_TERMINATION not in harness.codes_of(
                invocation.diagnostic_ids
            )
    finally:
        assert_nothing_launched_survives(strategy)
