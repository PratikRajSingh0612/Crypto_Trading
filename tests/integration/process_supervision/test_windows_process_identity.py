"""Stage 7 Task 8: durable creation identity and PID-reuse protection (plan 10).

Manifest rows W-18 and W-19. A sleeper launched directly through a job-less
``WindowsProcessController`` keeps its ``windows:<pid>:<creation>`` identity after every
pipe and handle of the launching side is closed and the process object is dropped: a
fresh controller finds it ``ALIVE_MATCHING`` by identity alone and terminates it by
identity (W-18). The test process's own pid with a creation time one tick earlier is
``ALIVE_DIFFERENT_IDENTITY``, its true creation time is ``ALIVE_MATCHING``, and a
finished launch is never ``ALIVE_MATCHING`` (W-19). Nothing here kills by pid alone.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from supervised_strategy import (
    failing_job_factory,
    identity_for,
    launch_sleeper,
    own_creation_100ns,
    started,
)

from crypto_lab.process_supervision.models import (
    FORCED_TERMINATION_EXIT_CODE,
    CleanupAction,
    LaunchSpecification,
    ProcessPresence,
    parse_creation_identity,
    render_creation_identity,
)
from crypto_lab.process_supervision.windows_process import WindowsProcessController

_INVOCATION_ID = "inv_7a7a7a7a-1111-4222-8333-444455556666"


# --- W-18: the identity survives the loss of every handle -----------------------------


def test_the_creation_identity_survives_the_loss_of_every_handle(
    tmp_path: Path,
) -> None:
    controller = WindowsProcessController(job_object_factory=failing_job_factory)
    # The sleeper's readiness line is read before any handle is closed or the tree is
    # terminated: without a Job Object the venv launcher's interpreter child is caught
    # by enumeration only while it exists (plan 8.2), and a launcher killed between
    # creating that child suspended and resuming it would leave a suspended orphan.
    launched = launch_sleeper(controller, invocation_id=_INVOCATION_ID, cwd=tmp_path)
    identity = identity_for(launched.pid, launched.creation_identity)
    parsed = parse_creation_identity(launched.creation_identity)
    assert parsed.pid == launched.pid
    try:
        assert launched.job_available is False
        report = launched.close(close_stdout=True, close_stderr=True)
        assert CleanupAction.PIPES_CLOSED in report.completed
        assert CleanupAction.PROCESS_HANDLE_CLOSED in report.completed
        assert launched.stdout.closed
        assert launched.stderr.closed
        del launched  # no Python reference to the process object survives
        fresh = WindowsProcessController()
        inspection = fresh.inspect(identity)
        assert inspection.presence is ProcessPresence.ALIVE_MATCHING
        assert inspection.observed_creation_identity == identity.creation_identity
        termination = fresh.terminate_tree(identity, FORCED_TERMINATION_EXIT_CODE)
        assert termination.forced
        assert termination.exit_code_used == FORCED_TERMINATION_EXIT_CODE
        assert termination.failures == ()
        assert fresh.inspect(identity).presence is ProcessPresence.ABSENT
        # The launcher's interpreter child was enumerated and is gone as well.
        assert len(termination.descendants) >= 1
        for descendant in termination.descendants:
            child = identity_for(descendant.pid, descendant.creation_identity)
            assert fresh.inspect(child).presence is ProcessPresence.ABSENT
    finally:
        final = WindowsProcessController()
        if final.inspect(identity).presence is ProcessPresence.ALIVE_MATCHING:
            final.terminate_tree(identity, FORCED_TERMINATION_EXIT_CODE)
        assert final.inspect(identity).presence is not ProcessPresence.ALIVE_MATCHING


# --- W-19: PID reuse protection ------------------------------------------------------


def test_a_live_process_with_a_different_creation_time_is_not_ours(
    tmp_path: Path,
) -> None:
    controller = WindowsProcessController()
    creation = own_creation_100ns()
    own_pid = os.getpid()
    earlier = identity_for(own_pid, render_creation_identity(own_pid, creation - 1))
    assert controller.inspect(earlier).presence is (
        ProcessPresence.ALIVE_DIFFERENT_IDENTITY
    )
    true = identity_for(own_pid, render_creation_identity(own_pid, creation))
    assert controller.inspect(true).presence is ProcessPresence.ALIVE_MATCHING
    # A finished launch is never ALIVE_MATCHING: its handle is signaled.
    finished = started(
        controller.launch(
            LaunchSpecification(
                invocation_id=_INVOCATION_ID,
                argv=(sys.executable, "-I", "-B", "-c", "pass"),
                cwd=str(tmp_path),
            )
        )
    )
    identity = identity_for(finished.pid, finished.creation_identity)
    try:
        assert finished.wait(10.0) == 0
        assert controller.inspect(identity).presence is not (
            ProcessPresence.ALIVE_MATCHING
        )
        assert controller.inspect(identity).presence is ProcessPresence.ABSENT
    finally:
        finished.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
        finished.close(close_stdout=True, close_stderr=True)
        assert (
            WindowsProcessController().inspect(identity).presence
            is not ProcessPresence.ALIVE_MATCHING
        )
