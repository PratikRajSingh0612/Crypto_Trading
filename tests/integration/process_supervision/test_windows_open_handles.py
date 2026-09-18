"""Stage 7 Task 8: open handles, inherited pipes and stale writers (plan 10).

Manifest rows W-23 to W-25. A pre-handoff terminal whose ``request.json`` the test holds
open records ``PROCESS.CLEANUP_FAILED`` with ``cleanup_complete=false``, and a
reconciliation pass after the handle is closed completes the cleanup with exactly one
cleanup-failed identity on the record (W-23; the launch failure is the scripted
controller's, so no child exists). A grandchild inheriting the root's stdout keeps EOF
pending after the root exits: with the Job Object attached the ``pipe_holder`` force
lets ``EXITED`` complete with native exit ``0``; on a host without the job the
invocation times out instead, the reader is ended through ``cancel_read`` and the
surviving sleeper is terminated by identity in ``finally:`` (W-24; the sleeper is
checked through the identity-first pid helper, because its parent chain exits before
any walk can enumerate it, plan 8.2, and W-12 proves that helper sees a live sleeper).
A stale writer from attempt one cannot
reach attempt two's root (W-25). Destructive actions are counted through the tee.
"""

from __future__ import annotations

from pathlib import Path
from typing import IO

from pydantic.experimental.missing_sentinel import MISSING
from supervised_strategy import (
    ProductionSupervision,
    assert_nothing_launched_survives,
    descendant_identity,
    details_of,
    grandchild_pid_of,
    identity_for,
    monotonic_gap_seconds,
    presence_of_pid,
    reconcile,
    terminate_reported_pid,
    trace_entries,
    trace_kinds,
)

from contract.harness import CommandRun, OfflineCommandHarness, build_harness
from crypto_lab.adapters.diagnostics import PROCESS_RUN_TIMED_OUT
from crypto_lab.adapters.limits import PROTOCOL_LIMITS_DEFAULT
from crypto_lab.adapters.manifests import AdapterResultManifest
from crypto_lab.adapters.vocabulary import ReconciliationVerdict
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
)
from crypto_lab.process_supervision.diagnostics import (
    PROCESS_CLEANUP_FAILED,
    PROCESS_FORCED_TERMINATION,
    PROCESS_JOB_OBJECT_UNAVAILABLE,
    PROCESS_LAUNCH_FAILED,
)
from crypto_lab.process_supervision.models import (
    FORCED_TERMINATION_EXIT_CODE,
    CleanupAction,
    LaunchFailure,
    ProcessPresence,
    ReconciliationAction,
    SupervisionTraceKind,
)
from crypto_lab.process_supervision.windows_process import WindowsProcessController
from doubles.supervision import RecordingObserver, ScriptedProcessController

_C = CommandInvocationState
_R = EngineRunState
_T = SupervisionTraceKind
_TIMEOUT = 30


def _missing(value: object) -> bool:
    return value is MISSING


# --- W-23: an open handle blocks the root removal -------------------------------------


def test_root_removal_blocked_by_an_open_handle_records_cleanup_failed(
    tmp_path: Path,
) -> None:
    scripted = ScriptedProcessController()
    scripted.launch_failure = LaunchFailure(
        stage="popen", os_error_code=5, error_class="PermissionError", not_found=False
    )
    held: list[IO[bytes]] = []
    observer = RecordingObserver()
    strategy = ProductionSupervision(
        cancellation_grace_seconds=1, controller=scripted, observers=(observer,)
    )
    harness = build_harness(
        tmp_path,
        "fake.conformant",
        limits=PROTOCOL_LIMITS_DEFAULT,
        seed="task8-open-handle",
        supervise=strategy,
    )
    # The request file exists once REQUEST_WRITTEN is delivered; holding it open makes
    # the pre-handoff root removal a sharing violation.
    observer.on(
        _T.REQUEST_WRITTEN,
        lambda entry: held.append(
            (harness.root / entry.invocation_id / "request.json").open("rb")
        ),
    )
    try:
        result = harness.drive(
            "fake.conformant", CommandKind.RUN, timeout_seconds=_TIMEOUT
        )
        invocation = result.command_result.invocation
        assert invocation.state is _C.FAILED_TO_START
        assert invocation.process_created is False
        assert invocation.cleanup_complete is False
        assert harness.primary_code_of(invocation) == PROCESS_LAUNCH_FAILED
        launch_failed = details_of(harness, invocation, PROCESS_LAUNCH_FAILED)
        assert launch_failed["stage"] == "popen"
        codes = harness.codes_of(invocation.diagnostic_ids)
        assert codes.count(PROCESS_CLEANUP_FAILED) == 1
        failed = details_of(harness, invocation, PROCESS_CLEANUP_FAILED)
        assert failed["cleanup_action"] == CleanupAction.COMMAND_ROOT_REMOVED.value
        assert failed["error_class"] == "sharing_violation"
        assert harness.stored_run(invocation.run_id).state is _R.FAILED
        assert result.outcome is None
        assert len(held) == 1
        assert (harness.root / invocation.invocation_id / "request.json").is_file()
        assert strategy.last_tee.identities == []
    finally:
        for handle in held:
            handle.close()
    # The second pass, after the handle is closed: the reconciler removes the root and
    # writes cleanup_complete once; the record shows exactly one cleanup-failed id.
    report = reconcile(harness, controller=WindowsProcessController())
    (entry,) = (
        item
        for item in report.entries
        if item.invocation_id == invocation.invocation_id
    )
    assert entry.action is ReconciliationAction.CLEANUP_COMPLETED
    assert entry.record_after.cleanup_complete is True
    assert entry.record_after.state is _C.FAILED_TO_START
    stored = harness.stored_invocation(invocation.invocation_id)
    assert stored == entry.record_after
    assert harness.codes_of(stored.diagnostic_ids).count(PROCESS_CLEANUP_FAILED) == 1
    assert not (harness.root / invocation.invocation_id).exists()
    # Replay: nothing is left to reconcile and nothing is written twice.
    assert reconcile(harness, controller=WindowsProcessController()).entries == ()
    assert harness.stored_invocation(invocation.invocation_id) == stored


# --- W-24: an inherited pipe keeps EOF pending ----------------------------------------


def test_a_grandchild_inheriting_stdout_is_terminated_so_exit_can_complete(
    tmp_path: Path,
) -> None:
    # The root and the fake exit a few milliseconds after the first heartbeat, before
    # the pipe-holder force, so neither the supervisor's walk from the dead root nor a
    # snapshot taken at an observer hook can enumerate the sleeper deterministically
    # (plan 8.2's stated limitation). The sleeper is therefore proven dead through the
    # identity-first pid helper, whose ability to see a live sleeper of ours is proven
    # by the positive control of W-12 (test_windows_process_tree.py).
    strategy = ProductionSupervision(cancellation_grace_seconds=1)
    grandchild: int | None = None
    try:
        harness = build_harness(
            tmp_path,
            "fake.grandchild-inherits-stdout",
            limits=PROTOCOL_LIMITS_DEFAULT,
            seed="task8-inherits",
            supervise=strategy,
        )
        result = harness.drive(
            "fake.grandchild-inherits-stdout", CommandKind.RUN, timeout_seconds=3
        )
        invocation = result.command_result.invocation
        grandchild = grandchild_pid_of(result)
        codes = harness.codes_of(invocation.diagnostic_ids)
        kinds = trace_kinds(result)
        tee = strategy.last_tee
        assert kinds.count(_T.FORCED_TERMINATION) == 1
        assert tee.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]
        assert tee.interrupt_calls == 0
        assert PROCESS_FORCED_TERMINATION in codes
        forced = details_of(harness, invocation, PROCESS_FORCED_TERMINATION)
        assert forced["reason"] == "pipe_holder"
        assert invocation.cleanup_complete is True
        if PROCESS_JOB_OBJECT_UNAVAILABLE not in codes:
            # The ordinary case: the job kill ends the sleeper, EOF arrives (the
            # sleeper held the only other write end, so EOF itself proves it gone), the
            # root's own exit is recorded on the EXITED transition.
            assert invocation.state is _C.EXITED
            assert invocation.native_exit_value == 0
            assert result.reconciliation is not None
            assert result.reconciliation.verdict is (
                ReconciliationVerdict.RESULT_FINALIZATION_ELIGIBLE
            )
            assert presence_of_pid(grandchild) is not ProcessPresence.ALIVE_MATCHING
            elapsed = monotonic_gap_seconds(
                result, _T.RUNNING_COMMITTED, _T.EXIT_REAPED
            )
            assert elapsed < 3.0
        else:
            # The stated limitation of plan 8.2: the sleeper's parent is dead, so the
            # job-less controller cannot reach it; the deadline decides, the stdout
            # reader is ended through cancel_read and the test terminates the sleeper.
            assert invocation.state is _C.TIMED_OUT
            assert harness.primary_code_of(invocation) == PROCESS_RUN_TIMED_OUT
            assert _missing(result.command_result.parsed_output)
            stdout_stopped = CleanupAction.STDOUT_READER_STOPPED.value
            (stopped,) = (
                entry
                for entry in trace_entries(result, _T.CLEANUP_ACTION)
                if entry.facts.get("action") == stdout_stopped
            )
            assert stopped.facts.get("ended_by") == "CANCELLED"
            assert presence_of_pid(grandchild) is ProcessPresence.ALIVE_MATCHING
    finally:
        if grandchild is not None:
            terminate_reported_pid(grandchild)
            assert presence_of_pid(grandchild) is not ProcessPresence.ALIVE_MATCHING
        assert_nothing_launched_survives(strategy)


# --- W-25: a stale writer from attempt one cannot reach attempt two -------------------


def _descendants_absent(strategy: ProductionSupervision) -> None:
    fresh = WindowsProcessController()
    for descendant in strategy.last_tee.descendants:
        assert (
            fresh.inspect(
                identity_for(descendant.pid, descendant.creation_identity)
            ).presence
            is ProcessPresence.ABSENT
        )


def test_a_stale_writer_from_attempt_one_cannot_reach_attempt_two(
    tmp_path: Path,
) -> None:
    strategy = ProductionSupervision(cancellation_grace_seconds=1)
    grandchild: int | None = None
    try:
        harness: OfflineCommandHarness = build_harness(
            tmp_path,
            "fake.grandchild",
            limits=PROTOCOL_LIMITS_DEFAULT,
            seed="task8-stale-writer",
            supervise=strategy,
        )
        experiment = harness.new_experiment("fake.grandchild")
        experiment, first_run = harness.new_attempt(experiment)
        first_run = harness.ready(first_run)
        first: CommandRun = harness.run(first_run, timeout_seconds=2)
        first_invocation = first.command_result.invocation
        assert first_invocation.state is _C.TIMED_OUT
        assert harness.primary_code_of(first_invocation) == PROCESS_RUN_TIMED_OUT
        assert harness.stored_run(first_run.run_id).state is _R.TIMED_OUT
        grandchild = grandchild_pid_of(first)
        # Attempt 1's tree is dead before attempt 2 launches: the reported pid was
        # enumerated as a descendant of the terminated tree and is gone by identity.
        _descendants_absent(strategy)
        sleeper = descendant_identity(strategy, grandchild)
        assert (
            WindowsProcessController().inspect(sleeper).presence
            is ProcessPresence.ABSENT
        )
        assert presence_of_pid(grandchild) is not ProcessPresence.ALIVE_MATCHING
        experiment, second_run = harness.successor(
            harness.stored_experiment(experiment.experiment_id),
            harness.stored_run(first_run.run_id),
        )
        assert second_run.attempt_number == 2
        assert second_run.predecessor_run_id == first_run.run_id
        second_run = harness.ready(second_run)
        second: CommandRun = harness.run(second_run, timeout_seconds=_TIMEOUT)
        second_invocation = second.command_result.invocation
        assert second_invocation.state is _C.EXITED
        assert second_invocation.native_exit_value == 0
        manifest = second.command_result.parsed_output
        assert isinstance(manifest, AdapterResultManifest)
        assert manifest.run_id == second_run.run_id
        assert manifest.invocation_id == second_invocation.invocation_id
        assert second.reconciliation is not None
        assert second.reconciliation.verdict is (
            ReconciliationVerdict.RESULT_FINALIZATION_ELIGIBLE
        )
        assert second.command_root != first.command_root
        assert second.command_root.parent == first.command_root.parent == tmp_path
        assert second.work_dir != first.work_dir
        assert all(
            path.startswith(f"runs/{second_run.run_id}/work/")
            for path in second.written_paths
        )
        assert len(strategy.launches) == 2
        assert len(harness.store.committed_retry_decisions()) == 1
    finally:
        if grandchild is not None:
            terminate_reported_pid(grandchild)
        assert_nothing_launched_survives(strategy)
