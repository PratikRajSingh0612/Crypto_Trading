"""Stage 7 Task 8: restart reconciliation over real children (plan 10, 8.5).

Manifest rows W-20 to W-22. Live supervision and restart reconciliation are distinct
(brief section 12): every ``RUNNING`` record here is committed through the public
lifecycle operations (``begin_linked_launch`` through ``harness.launch_pair`` and
``Stage5InvocationLifecycle.record_process_start``) with the identity of a child
launched through a job-less ``WindowsProcessController``, no supervisor instance exists,
and the "restart" hands the durable records and a fresh controller to
``reconcile_invocations`` with nothing process-local carried over. A live matching
orphan is terminated by identity and recorded as lost supervision while a planted
wrong-creation-time identity for the
same pid, reconciled first, is left alive with ``PROCESS.PID_REUSE_DETECTED`` (W-20); a
finished conformant run committed ``RUNNING`` only stays ``RUNNING`` before its deadline
and reports the manifest's presence (W-21); a ``CANCELLED`` record committed without
cleanup while its tree lives is cleaned by the pass (W-22). A second pass repeats no
destructive action, and no raw token appears in any report.
"""

from __future__ import annotations

from pathlib import Path

from pydantic.experimental.missing_sentinel import MISSING
from supervised_strategy import (
    LAUNCHER_HASH,
    LAUNCHER_PATH,
    failing_job_factory,
    identity_for,
    launch_sleeper,
    ok,
    reconcile,
    stage5_lifecycle,
    started,
)

from contract.harness import DEFAULT_NEGOTIATED, OfflineCommandHarness, build_harness
from crypto_lab.adapters.commands import AdapterCommand, argument_array
from crypto_lab.adapters.diagnostics import PROCESS_CANCELLED, stage6_diagnostic
from crypto_lab.adapters.envelopes import request_envelope_bytes
from crypto_lab.adapters.limits import PROTOCOL_LIMITS_DEFAULT
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.command_invocation import (
    CommandInvocationRecord,
    ProcessIdentity,
    ProcessStartFacts,
)
from crypto_lab.domain.engine_run import AttemptTokenMaterial, EngineRunRecord
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
)
from crypto_lab.experiments.supervision_lifecycle import RequestMaterial
from crypto_lab.process_supervision.diagnostics import (
    PROCESS_FORCED_TERMINATION,
    PROCESS_ORCHESTRATOR_RESTART_LOST_SUPERVISION,
    PROCESS_PID_REUSE_DETECTED,
)
from crypto_lab.process_supervision.models import (
    FORCED_TERMINATION_EXIT_CODE,
    LaunchSpecification,
    ProcessPresence,
    ReconciliationAction,
    catalog_launch_arguments,
    parse_creation_identity,
    render_creation_identity,
)
from crypto_lab.process_supervision.roots import (
    create_command_root,
    plan_command_paths,
    write_request_file,
)
from crypto_lab.process_supervision.windows_process import (
    WindowsLaunchedProcess,
    WindowsProcessController,
)
from doubles.supervision import TeeController, supervised_catalog_entry_for

_C = CommandInvocationState
_R = EngineRunState
_A = ReconciliationAction
_CONFORMANT = "fake.conformant"
_TIMEOUT = 30


def _harness(root: Path, *, seed: str) -> OfflineCommandHarness:
    return build_harness(root, _CONFORMANT, limits=PROTOCOL_LIMITS_DEFAULT, seed=seed)


def _starting_pair(
    harness: OfflineCommandHarness,
) -> tuple[CommandInvocationRecord, EngineRunRecord]:
    """A ``RUN`` invocation at ``(STARTING, STARTING)`` through public operations."""
    experiment = harness.new_experiment(_CONFORMANT)
    _experiment, run = harness.new_attempt(experiment)
    run = harness.ready(run)
    pair = harness.launch_pair(run, timeout_seconds=_TIMEOUT)
    return pair.invocation, pair.run


def _commit_running(
    harness: OfflineCommandHarness,
    invocation: CommandInvocationRecord,
    identity: ProcessIdentity,
) -> CommandInvocationRecord:
    """``STARTING -> RUNNING`` through the lifecycle port with the given identity."""
    lifecycle = stage5_lifecycle(harness)
    return ok(
        lifecycle.record_process_start(
            invocation.invocation_id,
            expected_revision=invocation.revision,
            process_start=ProcessStartFacts(
                pid_identity=identity,
                process_started_at_utc=harness.clock.now_utc(),
            ),
        )
    )


def _token_free(report: object, harness: OfflineCommandHarness, run_id: str) -> None:
    token = harness.token_for(run_id)
    # Boolean form: a failure report prints True/False, never the token itself.
    leaked = token in canonical_json_bytes(report).decode("utf-8")
    assert leaked is False


# --- W-20: a live matching orphan beside a planted reused-pid identity ----------------


def test_a_live_matching_orphan_is_terminated_and_recorded_as_lost_supervision(
    tmp_path: Path,
) -> None:
    harness = _harness(tmp_path / "sup", seed="task8-restart-orphan")
    launcher = WindowsProcessController(job_object_factory=failing_job_factory)
    # The planted record is created first (the earlier created_at_utc), so the source
    # order of plan 3.4 reconciles it before the matching record.
    planted_invocation, planted_run = _starting_pair(harness)
    harness.clock.advance(1)
    matching_invocation, matching_run = _starting_pair(harness)
    launched: WindowsLaunchedProcess = launch_sleeper(
        launcher, invocation_id=matching_invocation.invocation_id, cwd=tmp_path
    )
    creation = parse_creation_identity(launched.creation_identity).creation_100ns
    planted_identity = identity_for(
        launched.pid, render_creation_identity(launched.pid, creation - 1)
    )
    matching_identity = identity_for(launched.pid, launched.creation_identity)
    try:
        planted = _commit_running(harness, planted_invocation, planted_identity)
        matching = _commit_running(harness, matching_invocation, matching_identity)
        assert planted.state is matching.state is _C.RUNNING
        assert planted.created_at_utc < matching.created_at_utc
        # The restart: no supervisor ever existed for these records; the first launch's
        # process object stays alive (its handles are the test's), and the reconciler
        # receives only the durable records and a fresh controller.
        tee = TeeController(WindowsProcessController())
        report = reconcile(harness, controller=tee)
        assert [item.invocation_id for item in report.entries] == [
            planted.invocation_id,
            matching.invocation_id,
        ]
        first, second = report.entries
        assert first.action is _A.LEFT_RUNNING_AWAITING_DEADLINE
        assert first.presence is ProcessPresence.ALIVE_DIFFERENT_IDENTITY
        assert PROCESS_PID_REUSE_DETECTED in {d.error_code for d in first.diagnostics}
        assert first.record_after.state is _C.RUNNING
        assert first.record_after == planted
        assert harness.stored_run(planted_run.run_id).state is _R.RUNNING
        assert second.action is _A.TERMINALIZED_PROTOCOL_FAILED
        assert second.presence is ProcessPresence.ALIVE_MATCHING
        after = second.record_after
        assert after.state is _C.PROTOCOL_FAILED
        assert after.cleanup_complete is True
        assert harness.primary_code_of(after) == (
            PROCESS_ORCHESTRATOR_RESTART_LOST_SUPERVISION
        )
        assert PROCESS_FORCED_TERMINATION in harness.codes_of(after.diagnostic_ids)
        # Lost exit facts are never reconstructed (plan 8.5): the reconciler writes no
        # native exit even though it terminated the tree itself.
        assert not isinstance(after.native_exit_value, int)
        assert harness.stored_run(matching_run.run_id).state is _R.FAILED
        assert tee.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]
        assert launched.wait(5.0) == FORCED_TERMINATION_EXIT_CODE
        fresh = WindowsProcessController()
        assert fresh.inspect(matching_identity).presence is ProcessPresence.ABSENT
        _token_free(report, harness, matching_run.run_id)
        # Replay: the planted record is inspected again (now absent) and left alone;
        # the terminalized record is no longer a target; nothing is terminated again.
        again = TeeController(WindowsProcessController())
        second_report = reconcile(harness, controller=again)
        assert [item.invocation_id for item in second_report.entries] == [
            planted.invocation_id
        ]
        (replayed,) = second_report.entries
        assert replayed.action is _A.LEFT_RUNNING_AWAITING_DEADLINE
        assert replayed.record_after == planted
        assert again.terminate_calls == []
        assert harness.stored_invocation(matching.invocation_id) == after
    finally:
        launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
        launched.close(close_stdout=True, close_stderr=True)
        final = WindowsProcessController()
        assert final.inspect(matching_identity).presence is not (
            ProcessPresence.ALIVE_MATCHING
        )


# --- W-21: an absent process before the deadline --------------------------------------


def test_an_absent_process_before_the_deadline_stays_running_and_reports_the_manifest(
    tmp_path: Path,
) -> None:
    harness = _harness(tmp_path / "sup", seed="task8-restart-absent")
    invocation, run = _starting_pair(harness)
    lifecycle = stage5_lifecycle(harness)
    lifecycle.register_request_material(
        invocation.invocation_id,
        RequestMaterial(
            token=AttemptTokenMaterial(
                run_id=run.run_id, attempt_token=harness.token_for(run.run_id)
            ),
            negotiated_versions=DEFAULT_NEGOTIATED,
            limits=harness.limits,
        ),
    )
    envelope = ok(lifecycle.request_envelope(invocation.invocation_id))
    paths = plan_command_paths(
        str(harness.root),
        command_kind=CommandKind.RUN,
        invocation_id=invocation.invocation_id,
        run_id=run.run_id,
    )
    create_command_root(paths)
    write_request_file(paths.request_path, request_envelope_bytes(envelope))
    entry = supervised_catalog_entry_for(_CONFORMANT)
    command = AdapterCommand(
        command_kind=CommandKind.RUN,
        catalog_entry=entry,
        invocation_id=invocation.invocation_id,
        request_path=paths.request_path,
        work_dir=paths.work_dir,
        result_path=paths.result_path,
        timeout_seconds=_TIMEOUT,
    )
    controller = WindowsProcessController(job_object_factory=failing_job_factory)
    launched = started(
        controller.launch(
            LaunchSpecification(
                invocation_id=invocation.invocation_id,
                argv=(
                    entry.executable_path,
                    *catalog_launch_arguments(entry),
                    *argument_array(command),
                ),
                cwd=paths.command_root,
            )
        )
    )
    identity = identity_for(launched.pid, launched.creation_identity)
    try:
        # The conformant run completes on its own; nothing supervised it, so no exit
        # fact was ever recorded: the record says RUNNING while the process is gone.
        stdout = launched.stdout.read()
        stderr = launched.stderr.read()
        assert launched.wait(_TIMEOUT) == 0
        assert stdout.count(b"\n") == 5
        assert stderr == b""
        assert Path(paths.result_path).is_file()
        running = _commit_running(harness, invocation, identity)
        assert running.state is _C.RUNNING
        launched.close(close_stdout=True, close_stderr=True)
        report = reconcile(harness, controller=WindowsProcessController())
        (reconciled,) = report.entries
        assert reconciled.invocation_id == invocation.invocation_id
        assert reconciled.action is _A.LEFT_RUNNING_AWAITING_DEADLINE
        assert reconciled.presence is ProcessPresence.ABSENT
        assert reconciled.manifest_present is True
        assert reconciled.record_after.state is _C.RUNNING
        assert reconciled.record_after == running
        # Lost exit facts are never reconstructed (plan 8.5).
        assert not isinstance(reconciled.record_after.native_exit_value, int)
        assert harness.stored_run(run.run_id).state is _R.RUNNING
        assert reconciled.diagnostics == ()
        _token_free(report, harness, run.run_id)
        assert Path(paths.command_root).is_dir()  # a post-RUNNING root is never removed
    finally:
        launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
        launched.close(close_stdout=True, close_stderr=True)
        assert (
            WindowsProcessController().inspect(identity).presence
            is not ProcessPresence.ALIVE_MATCHING
        )


# --- W-22: a terminal with incomplete cleanup and a live tree -------------------------


def test_a_terminal_with_incomplete_cleanup_and_a_live_tree_is_cleaned(
    tmp_path: Path,
) -> None:
    harness = _harness(tmp_path / "sup", seed="task8-restart-cleanup")
    invocation, run = _starting_pair(harness)
    launcher = WindowsProcessController(job_object_factory=failing_job_factory)
    launched = launch_sleeper(
        launcher, invocation_id=invocation.invocation_id, cwd=tmp_path
    )
    identity = identity_for(launched.pid, launched.creation_identity)
    try:
        running = _commit_running(harness, invocation, identity)
        lifecycle = stage5_lifecycle(harness)
        primary = stage6_diagnostic(
            PROCESS_CANCELLED,
            "cancelled by the orchestrator; the process tree was never cleaned up",
            source_component="process_supervision.supervisor",
            timestamp_utc=harness.clock.now_utc(),
            invocation_id=invocation.invocation_id,
            run_id=run.run_id,
            experiment_id=run.experiment_id,
        )
        terminal = ok(
            lifecycle.record_terminal(
                invocation.invocation_id,
                expected_revision=running.revision,
                target_state=_C.CANCELLED,
                primary=primary,
                additional=(),
                native_exit_value=MISSING,
            )
        )
        assert terminal.state is _C.CANCELLED
        assert terminal.process_created is True
        assert terminal.cleanup_complete is False
        assert harness.stored_run(run.run_id).state is _R.CANCELLED
        assert WindowsProcessController().inspect(identity).presence is (
            ProcessPresence.ALIVE_MATCHING
        )
        tee = TeeController(WindowsProcessController())
        report = reconcile(harness, controller=tee)
        (cleaned,) = report.entries
        assert cleaned.invocation_id == invocation.invocation_id
        assert cleaned.action is _A.CLEANUP_COMPLETED
        assert cleaned.presence is ProcessPresence.ALIVE_MATCHING
        after = cleaned.record_after
        assert after.state is _C.CANCELLED
        assert after.cleanup_complete is True
        assert PROCESS_FORCED_TERMINATION in harness.codes_of(after.diagnostic_ids)
        assert harness.stored_invocation(invocation.invocation_id) == after
        assert tee.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]
        assert launched.wait(5.0) == FORCED_TERMINATION_EXIT_CODE
        assert WindowsProcessController().inspect(identity).presence is (
            ProcessPresence.ABSENT
        )
        _token_free(report, harness, run.run_id)
        # Replay: a complete record is no target and nothing is terminated again.
        again = TeeController(WindowsProcessController())
        assert reconcile(harness, controller=again).entries == ()
        assert again.terminate_calls == []
        assert identity.executable_path == LAUNCHER_PATH
        assert identity.executable_hash == LAUNCHER_HASH
    finally:
        launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
        launched.close(close_stdout=True, close_stderr=True)
        assert (
            WindowsProcessController().inspect(identity).presence
            is not ProcessPresence.ALIVE_MATCHING
        )
