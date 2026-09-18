"""The Stage 7 Task 8 scenario manifests as data (plan sections 9.1 and 10).

``SUPERVISION_SCENARIOS`` holds the six Stage 7 fake-adapter behaviours of plan 9.1 —
the merged ``SCENARIOS`` table of ``tests/contract/scenarios.py`` is untouched — and
``PLATFORM_ROWS`` the twenty-six Windows platform rows of plan 10 that Task 8 owns, one
per test, keyed ``W-01`` to ``W-26``. Both tables are the single scenario authority of
the task: ``test_supervised_contract_matrix.py`` pins their cardinality, their unique
identifiers and, for the platform rows, that every named test exists in its module.
Two rows of the plan 10 table belong to earlier tasks and are not repeated here:
"Identity checks for every invocation state" (Task 7,
``tests/unit/process_supervision/test_restart_reconciliation.py``) and "Console
interrupt group safety" (Task 4,
``tests/unit/process_supervision/test_windows_api.py``). Nothing here launches, times
or reads anything.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from crypto_lab.domain.lifecycle import CommandKind

_K = CommandKind
_RUN_ONLY: Final = (_K.RUN,)


@dataclass(frozen=True, slots=True, kw_only=True)
class SupervisionScenario:
    """One plan 9.1 row: the fake's behaviour and its expectation through the
    supervisor."""

    name: str
    commands: tuple[CommandKind, ...]
    behaviour: str
    expectation: str
    cancellation_grace_seconds: int
    cancel_after_first_heartbeat: bool
    timeout_seconds: int = 30


SUPERVISION_SCENARIOS: Final[tuple[SupervisionScenario, ...]] = (
    SupervisionScenario(
        name="fake.cancellation-graceful",
        commands=_RUN_ONLY,
        behaviour=(
            "a SIGBREAK handler exits 50; heartbeats every 0.2 s until interrupted"
        ),
        expectation=(
            "CANCELLED; run CANCELLED; PROCESS.CANCELLED; INTERRUPT_SENT (DELIVERED); "
            "native exit 50 by enrichment; no PROCESS.FORCED_TERMINATION; below the "
            "grace"
        ),
        cancellation_grace_seconds=5,
        cancel_after_first_heartbeat=True,
    ),
    SupervisionScenario(
        name="fake.cancellation-ignores-interrupt",
        commands=_RUN_ONLY,
        behaviour="SIGBREAK ignored; heartbeats until killed",
        expectation=(
            "CANCELLED; PROCESS.FORCED_TERMINATION (grace_elapsed); native exit 1067; "
            "elapsed at least the grace"
        ),
        cancellation_grace_seconds=1,
        cancel_after_first_heartbeat=True,
    ),
    SupervisionScenario(
        name="fake.grandchild",
        commands=_RUN_ONLY,
        behaviour=(
            "SIGBREAK ignored; an ignoring sleeper spawned in a new process group; "
            "grandchild_pid=<n> on stderr; heartbeats until terminated"
        ),
        expectation=(
            "CANCELLED after the first heartbeat (grace 1); PROCESS.FORCED_TERMINATION "
            "(grace_elapsed); the reported pid among TerminationReport.descendants; "
            "every descendant ABSENT afterwards; cleanup_complete true"
        ),
        cancellation_grace_seconds=1,
        cancel_after_first_heartbeat=True,
    ),
    SupervisionScenario(
        name="fake.grandchild-inherits-stdout",
        commands=_RUN_ONLY,
        behaviour=(
            "handler-less; the sleeper inherits the root's stdout; grandchild_pid=<n> "
            "on stderr; a SUCCEEDED manifest with no candidates; FINAL_RESULT; exit 0"
        ),
        expectation=(
            "job attached: EXITED exit 0 after the pipe_holder force, "
            "RESULT_FINALIZATION_ELIGIBLE, the sleeper dead; job unavailable: "
            "TIMED_OUT (timeout 3), one FORCED_TERMINATION (pipe_holder), the stdout "
            "reader ended by CANCELLED, cleanup_complete true, the sleeper terminated "
            "by the test"
        ),
        cancellation_grace_seconds=1,
        cancel_after_first_heartbeat=False,
        timeout_seconds=3,
    ),
    SupervisionScenario(
        name="fake.stdout-flood",
        commands=_RUN_ONLY,
        behaviour=(
            "5000 heartbeats back to back, a SUCCEEDED manifest, FINAL_RESULT, exit 0"
        ),
        expectation=(
            "EXITED; 5001 accepted events; replay_count 0; RESULT_FINALIZATION_ELIGIBLE"
        ),
        cancellation_grace_seconds=1,
        cancel_after_first_heartbeat=False,
        # Plan 10 "timeouts of 30 s unless stated": stated here, because 5001 accepted
        # events cost the supervision thread about 2-5 ms each (a parse, a ledger
        # append and a trace entry per event) and more under coverage tracing, so the
        # default would race the host's load rather than test the drain.
        timeout_seconds=120,
    ),
    SupervisionScenario(
        name="fake.argv-echo",
        commands=(_K.DESCRIBE, _K.VALIDATE, _K.RUN),
        behaviour=(
            "one canonical JSON line on stderr: argv (sys.orig_argv[1:]), arguments, "
            "isolated, dont_write_bytecode, cwd, environment_keys; ordinary output"
        ),
        expectation=(
            "EXITED; no PROCESS.WRITE_BOUNDARY_VIOLATION; argv == [-I, -B, <script>, "
            "*argument_array]; isolated 1; cwd == command_root; the parent sentinel "
            "and PATH, SYSTEMROOT, USERPROFILE absent from environment_keys"
        ),
        cancellation_grace_seconds=1,
        cancel_after_first_heartbeat=False,
    ),
)


@dataclass(frozen=True, slots=True, kw_only=True)
class PlatformRow:
    """One plan 10 row Task 8 owns: the requirement, its test and its mechanism."""

    row_id: str
    requirement: str
    module: str
    test: str
    scripted: bool = False


_PATHS: Final = "test_windows_paths.py"
_ARGUMENTS: Final = "test_windows_launch_arguments.py"
_TREE: Final = "test_windows_process_tree.py"
_IDENTITY: Final = "test_windows_process_identity.py"
_RESTART: Final = "test_windows_restart_reconciliation.py"
_HANDLES: Final = "test_windows_open_handles.py"
_STDERR: Final = "test_windows_stderr_limits.py"

PLATFORM_ROWS: Final[tuple[PlatformRow, ...]] = (
    PlatformRow(
        row_id="W-01",
        requirement="Paths with spaces",
        module=_PATHS,
        test="test_a_supervision_root_with_spaces_reaches_exited_for_every_kind",
    ),
    PlatformRow(
        row_id="W-02",
        requirement="Unicode path components",
        module=_PATHS,
        test="test_a_unicode_supervision_root_reaches_exited_for_every_kind",
    ),
    PlatformRow(
        row_id="W-03",
        requirement="Unicode and space in the catalog executable and script paths",
        module=_PATHS,
        test="test_a_unicode_executable_and_script_path_are_launched",
    ),
    PlatformRow(
        row_id="W-04",
        requirement="Long paths, conditional",
        module=_PATHS,
        test=(
            "test_long_paths_succeed_when_supported_and_are_rejected_deterministically"
            "_otherwise"
        ),
    ),
    PlatformRow(
        row_id="W-05",
        requirement="Long paths, always-run rejection",
        module=_PATHS,
        test="test_a_command_root_longer_than_the_directory_ceiling_is_rejected_on_every_host",
    ),
    PlatformRow(
        row_id="W-06",
        requirement="Junction and reparse rejection: a root under a junction",
        module=_PATHS,
        test="test_a_supervision_root_under_a_junction_is_rejected_before_any_launch",
    ),
    PlatformRow(
        row_id="W-07",
        requirement=(
            "Junction and reparse rejection: a junction as the command root parent"
        ),
        module=_PATHS,
        test="test_a_junction_planted_as_the_command_root_parent_is_rejected",
    ),
    PlatformRow(
        row_id="W-08",
        requirement="Junction and reparse rejection: an executable through a junction",
        module=_PATHS,
        test="test_an_executable_path_through_a_junction_is_refused_even_with_a_matching_hash",
    ),
    PlatformRow(
        row_id="W-09",
        requirement="Argument-array preservation for every kind",
        module=_ARGUMENTS,
        test="test_the_fake_echoes_exactly_the_argument_array_for_every_kind",
    ),
    PlatformRow(
        row_id="W-10",
        requirement="Argument-array preservation with hostile path segments",
        module=_ARGUMENTS,
        test="test_spaces_quotes_unicode_and_blank_looking_components_survive",
    ),
    PlatformRow(
        row_id="W-11",
        requirement="Fresh environment block",
        module=_ARGUMENTS,
        test="test_the_child_sees_no_parent_variable",
    ),
    PlatformRow(
        row_id="W-12",
        requirement="Process group, Job Object, handle cleanup",
        module=_TREE,
        test="test_a_grandchild_dies_with_the_tree_and_every_handle_is_closed",
    ),
    PlatformRow(
        row_id="W-13",
        requirement="Graceful termination",
        module=_TREE,
        test="test_a_graceful_interrupt_lets_the_adapter_exit_fifty_within_grace",
    ),
    PlatformRow(
        row_id="W-14",
        requirement="Forced termination after grace",
        module=_TREE,
        test="test_an_adapter_ignoring_the_interrupt_is_force_terminated_after_grace",
    ),
    PlatformRow(
        row_id="W-15",
        requirement="Job Object unavailable fallback",
        module=_TREE,
        test=(
            "test_when_the_job_object_is_unavailable_toolhelp_termination_still_kills"
            "_the_grandchild"
        ),
    ),
    PlatformRow(
        row_id="W-16",
        requirement="Undeliverable interrupt",
        module=_TREE,
        test=(
            "test_an_undeliverable_interrupt_records_the_limitation_and_still_waits"
            "_the_grace"
        ),
        scripted=True,
    ),
    PlatformRow(
        row_id="W-17",
        requirement="Backpressure",
        module=_TREE,
        test="test_a_stdout_flood_is_drained_without_deadlock",
    ),
    PlatformRow(
        row_id="W-18",
        requirement="Durable creation identity across handle loss",
        module=_IDENTITY,
        test="test_the_creation_identity_survives_the_loss_of_every_handle",
    ),
    PlatformRow(
        row_id="W-19",
        requirement="PID reuse protection",
        module=_IDENTITY,
        test="test_a_live_process_with_a_different_creation_time_is_not_ours",
    ),
    PlatformRow(
        row_id="W-20",
        requirement="Restart with a live matching orphan",
        module=_RESTART,
        test="test_a_live_matching_orphan_is_terminated_and_recorded_as_lost_supervision",
    ),
    PlatformRow(
        row_id="W-21",
        requirement="Restart with an absent process before the deadline",
        module=_RESTART,
        test=(
            "test_an_absent_process_before_the_deadline_stays_running_and_reports"
            "_the_manifest"
        ),
    ),
    PlatformRow(
        row_id="W-22",
        requirement="Restart cleanup of a terminal with a live tree",
        module=_RESTART,
        test="test_a_terminal_with_incomplete_cleanup_and_a_live_tree_is_cleaned",
    ),
    PlatformRow(
        row_id="W-23",
        requirement="Open handle blocks root removal",
        module=_HANDLES,
        test="test_root_removal_blocked_by_an_open_handle_records_cleanup_failed",
        scripted=True,
    ),
    PlatformRow(
        row_id="W-24",
        requirement="Inherited pipe keeps EOF pending",
        module=_HANDLES,
        test="test_a_grandchild_inheriting_stdout_is_terminated_so_exit_can_complete",
    ),
    PlatformRow(
        row_id="W-25",
        requirement="Stale child output after retry",
        module=_HANDLES,
        test="test_a_stale_writer_from_attempt_one_cannot_reach_attempt_two",
    ),
    PlatformRow(
        row_id="W-26",
        requirement="Independent stderr budgets per kind",
        module=_STDERR,
        test="test_each_kind_gets_its_own_stderr_budget_and_truncation_diagnostic",
        scripted=True,
    ),
)


def supervision_scenario_ids(
    rows: tuple[SupervisionScenario, ...],
) -> tuple[str, ...]:
    return tuple(item.name for item in rows)


def platform_row_ids(rows: tuple[PlatformRow, ...]) -> tuple[str, ...]:
    return tuple(item.row_id for item in rows)
