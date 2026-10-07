"""Stage 7 Task 8: the Stage 6 contract matrix through the production supervisor.

Plan section 9.4. All 58 entries of ``tests/contract/scenarios.py`` run through
``build_harness(..., supervise=ProductionSupervision(cancellation_grace_seconds=1))``:
the real ``WindowsProcessSupervisor`` over the real ``WindowsProcessController``, the
``Stage5InvocationLifecycle`` over the harness's in-memory store, the merged parsers and
the merged fake adapter; row 47 runs through the merged stale-attempt sequence. Every
entry asserts exactly what the four Stage 6 contract modules assert for it
(``assert_stage_six_expectation`` re-implements their per-kind assertions) plus the
production-only facts of plan 9.4: a parseable ``windows:<pid>:<creation>`` identity, no
Stage 7 diagnostic on a clean ``EXITED`` row, and nothing the supervisor launched alive
afterwards. The merged fake launched under the six Stage 7 names still exits ``10``, so
the Stage 7 script's ``KNOWN_ADAPTER_NAMES`` rebinding is proven process-local. The two
Task 8 manifests (``SUPERVISION_SCENARIOS`` and ``PLATFORM_ROWS``) are pinned closed
here so no scenario row can be added, dropped or renamed silently.
"""

from __future__ import annotations

import ast
import dataclasses
import json
import os
import shutil
from pathlib import Path
from typing import Final

import pytest
from pydantic.experimental.missing_sentinel import MISSING
from supervised_strategy import (
    ProductionSupervision,
    assert_nothing_launched_survives,
    assert_stage_six_expectation,
    drive_stale_attempt,
    reconciliation_content,
    trace_kinds,
)
from supervision_scenarios import (
    PLATFORM_ROWS,
    SUPERVISION_SCENARIOS,
    SupervisionScenario,
    platform_row_ids,
    supervision_scenario_ids,
)

from contract.harness import (
    FAKE_ADAPTER_PATH,
    FAKE_ADAPTER_VERSION,
    REQUEST_FILE_NAME,
    CommandRun,
    OfflineCommandHarness,
    build_harness,
)
from contract.scenarios import (
    DEFAULT_TIMEOUT_SECONDS,
    PLAN_ROW_COUNT,
    PROCESS_TIMEOUT_SECONDS,
    SCENARIO_ENTRY_COUNT,
    SCENARIOS,
    Scenario,
    scenario_ids,
)
from crypto_lab.adapters.diagnostics import SCHEMA_REQUEST_INVALID
from crypto_lab.adapters.limits import PROTOCOL_LIMITS_DEFAULT
from crypto_lab.adapters.reconciliation import SemanticReconciliation
from crypto_lab.adapters.vocabulary import ReconciliationVerdict
from crypto_lab.domain.command_invocation import ProcessIdentity
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
)
from crypto_lab.process_supervision.diagnostics import STAGE7_DIAGNOSTIC_CODES
from crypto_lab.process_supervision.models import (
    CleanupAction,
    SupervisionTraceKind,
    parse_creation_identity,
)
from doubles.supervision import (
    SUPERVISION_FAKE_NAMES,
    RealtimeMonotonicClock,
    RecordingObserver,
    supervised_catalog_entry_for,
)

_C = CommandInvocationState
_R = EngineRunState
_V = ReconciliationVerdict
_T = SupervisionTraceKind
_STALE_ATTEMPT = "fake.stale-attempt-result"
_CONFORMANT = "fake.conformant"
_HERE = Path(__file__).resolve().parent
#: Plan 9.4: the rows the Stage 6 table declares successful; every other row is adverse.
_SUCCESS_VERDICTS = frozenset(
    {_V.DESCRIBED, _V.VALIDATED_READY, _V.RESULT_FINALIZATION_ELIGIBLE}
)


def _missing(value: object) -> bool:
    return value is MISSING


def _drive(
    entry: Scenario, root: Path, strategy: ProductionSupervision
) -> tuple[OfflineCommandHarness, CommandRun]:
    harness = build_harness(
        root,
        entry.adapter_name,
        limits=entry.limits,
        seed=f"task8-{entry.adapter_name}",
        letter_leading_token=entry.letter_leading_token,
        supervise=strategy,
    )
    if entry.adapter_name == _STALE_ATTEMPT:
        return harness, drive_stale_attempt(harness, entry)
    return harness, harness.drive(
        entry.adapter_name,
        entry.command,
        timeout_seconds=entry.timeout_seconds,
        cancel_after_first_heartbeat=entry.cancel_after_first_heartbeat,
    )


# --- The 58 entries (M-rows) ----------------------------------------------------------


@pytest.mark.parametrize("entry", SCENARIOS, ids=scenario_ids(SCENARIOS))
def test_every_stage_six_row_passes_through_the_production_supervisor(
    tmp_path: Path, entry: Scenario
) -> None:
    strategy = ProductionSupervision(cancellation_grace_seconds=1)
    try:
        harness, command_run = _drive(entry, tmp_path, strategy)
        assert_stage_six_expectation(harness, command_run, entry)
        identity = command_run.command_result.invocation.pid_identity
        if isinstance(
            identity, ProcessIdentity
        ):  # never `is not MISSING` on a typed field (plan 2.6)
            parse_creation_identity(identity.creation_identity)
        clean = (
            entry.invocation_state is _C.EXITED
            and entry.primary_code is None
            and entry.secondary_codes == ()
        )
        if clean:
            assert not {
                d.error_code for d in command_run.command_result.diagnostics
            } & set(STAGE7_DIAGNOSTIC_CODES)
        outcome = command_run.supervision_outcome
        assert outcome is not None
        # The retained outcome is the supervisor's own record; the harness epilogue
        # may enrich it further (describe reconciliation, semantic application).
        assert outcome.command_result.invocation.invocation_id == (
            command_run.command_result.invocation.invocation_id
        )
        assert command_run.command_result.invocation.revision >= (
            outcome.command_result.invocation.revision
        )
        # Plan 6.6: exactly one enrichment per invocation on every row.
        assert trace_kinds(command_run).count(_T.ENRICHMENT_COMMITTED) == 1
    finally:
        assert_nothing_launched_survives(strategy)


# --- The merged fake under the Stage 7 names (F-rows) ------------------------------


@pytest.mark.parametrize(
    "scenario",
    SUPERVISION_SCENARIOS,
    ids=supervision_scenario_ids(SUPERVISION_SCENARIOS),
)
def test_the_merged_fake_still_refuses_every_stage_seven_name(
    tmp_path: Path, scenario: SupervisionScenario
) -> None:
    """Plan 9.1: the Stage 7 script widens ``KNOWN_ADAPTER_NAMES`` in its own process
    only; the merged ``fake_adapter.py`` run under a Stage 7 name still exits ``10``."""
    name = scenario.name
    strategy = ProductionSupervision(
        cancellation_grace_seconds=1,
        catalog_entry=supervised_catalog_entry_for(name, script=FAKE_ADAPTER_PATH),
    )
    try:
        harness = build_harness(
            tmp_path,
            name,
            limits=PROTOCOL_LIMITS_DEFAULT,
            seed=f"task8-merged-{name}",
            supervise=strategy,
        )
        result = harness.drive(
            name, CommandKind.RUN, timeout_seconds=DEFAULT_TIMEOUT_SECONDS
        )
        invocation = result.command_result.invocation
        assert invocation.state is _C.EXITED
        assert invocation.native_exit_value == 10
        assert result.command_result.accepted_events == ()
        assert result.written_paths == frozenset()
        assert _missing(result.command_result.parsed_output)
        assert harness.stored_run(invocation.run_id).state is _R.FAILED
        reconciliation = result.reconciliation
        assert isinstance(reconciliation, SemanticReconciliation)
        assert reconciliation.verdict is _V.FAILED
        assert harness.primary_code_of(reconciliation) == SCHEMA_REQUEST_INVALID
        (specification,) = strategy.launches
        assert specification.argv[3] == str(FAKE_ADAPTER_PATH)
    finally:
        assert_nothing_launched_survives(strategy)


# --- The manifests (closed inventories) ---------------------------------------------


def test_the_stage_six_table_is_still_the_fifty_eight_entries() -> None:
    assert len(SCENARIOS) == SCENARIO_ENTRY_COUNT == 58
    assert {item.row for item in SCENARIOS} == set(range(1, PLAN_ROW_COUNT + 1))
    assert PLAN_ROW_COUNT == 52


def test_the_stage_seven_scenario_table_is_closed_and_names_the_fake_set() -> None:
    names = [item.name for item in SUPERVISION_SCENARIOS]
    assert len(SUPERVISION_SCENARIOS) == 6
    assert len(set(names)) == 6
    assert frozenset(names) == SUPERVISION_FAKE_NAMES
    assert all(name.startswith("fake.") for name in names)
    assert frozenset(names).isdisjoint({item.adapter_name for item in SCENARIOS})
    by_name = {item.name: item for item in SUPERVISION_SCENARIOS}
    assert by_name["fake.argv-echo"].commands == (
        CommandKind.DESCRIBE,
        CommandKind.VALIDATE,
        CommandKind.RUN,
    )
    for name in names:
        if name != "fake.argv-echo":
            assert by_name[name].commands == (CommandKind.RUN,)
    assert supervision_scenario_ids(SUPERVISION_SCENARIOS) == tuple(names)


def _test_functions(module: Path) -> set[str]:
    tree = ast.parse(module.read_text(encoding="utf-8"))
    return {
        node.name
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
    }


def test_the_platform_row_manifest_is_closed_and_every_named_test_exists() -> None:
    ids = platform_row_ids(PLATFORM_ROWS)
    assert len(PLATFORM_ROWS) == 26
    assert len(set(ids)) == 26
    assert ids == tuple(f"W-{index:02d}" for index in range(1, 27))
    modules = {row.module for row in PLATFORM_ROWS}
    assert modules == {
        "test_windows_paths.py",
        "test_windows_launch_arguments.py",
        "test_windows_process_tree.py",
        "test_windows_process_identity.py",
        "test_windows_restart_reconciliation.py",
        "test_windows_open_handles.py",
        "test_windows_stderr_limits.py",
    }
    for module in modules:
        path = _HERE / module
        assert path.is_file(), module
        defined = _test_functions(path)
        named = {row.test for row in PLATFORM_ROWS if row.module == module}
        assert named <= defined, (module, sorted(named - defined))
    tests = [(row.module, row.test) for row in PLATFORM_ROWS]
    assert len(set(tests)) == len(tests)
    assert {row.row_id for row in PLATFORM_ROWS if row.scripted} == {
        "W-16",
        "W-23",
        "W-26",
    }


def test_the_adverse_rows_are_the_closed_complement_of_the_success_declarations() -> (
    None
):
    """Plan 9.4 and the brief's no-false-success rule: the success declarations are
    exactly rows 1, 2, 3, 4, 13, 22, 23, 24 and 40; every other row is adverse and
    ``assert_stage_six_expectation`` holds each adverse row to a non-success terminal
    run state with a written primary (or, for a describe, an unavailable
    observation)."""
    success = {item.row for item in SCENARIOS if item.verdict in _SUCCESS_VERDICTS}
    assert success == {1, 2, 3, 4, 13, 22, 23, 24, 40}
    adverse = {item.row for item in SCENARIOS} - success
    assert adverse == set(range(1, PLAN_ROW_COUNT + 1)) - success
    assert len(adverse) == 43
    for item in SCENARIOS:
        if item.row in adverse:
            assert item.verdict not in _SUCCESS_VERDICTS
            if item.command is not CommandKind.DESCRIBE:
                assert item.run_state not in (
                    _R.SUCCEEDED,
                    _R.SUCCEEDED_WITH_WARNINGS,
                    _R.RUNNING,
                    _R.READY,
                )


# --- The timing rows' measured spans (plan 9.4 row 25/26 evidence) -------------------


def test_the_timing_rows_record_their_measured_spans(tmp_path: Path) -> None:
    """A characterization test for the Task 8 evidence, not a pin: plan 9.4 requires the
    measured pre-handoff span of the two 1 s row-26 linked entries to be recorded beside
    row 25's heartbeat margin. The three entries run through the production strategy;
    the spans are read from the retained trace (monotonic ticks between
    ``STARTING_COMMITTED`` and the handoff or the pre-handoff decision, and between the
    minted missing heartbeat and the deadline decision) and written to
    ``tmp_path / "task8-timing.json"`` for the ledger. No exit value or span is
    pinned."""
    entries = [
        item
        for item in SCENARIOS
        if item.row in (25, 26) and item.command is not CommandKind.DESCRIBE
    ]
    assert [(item.row, item.command) for item in entries] == [
        (25, CommandKind.RUN),
        (26, CommandKind.VALIDATE),
        (26, CommandKind.RUN),
    ]
    measured: dict[str, dict[str, object]] = {}
    for entry in entries:
        strategy = ProductionSupervision(cancellation_grace_seconds=1)
        try:
            harness, command_run = _drive(entry, tmp_path / entry.name, strategy)
            assert_stage_six_expectation(harness, command_run, entry)
            outcome = command_run.supervision_outcome
            assert outcome is not None
            first: dict[SupervisionTraceKind, int] = {}
            for trace_entry in outcome.trace:
                first.setdefault(trace_entry.kind, trace_entry.monotonic_100ns)
            swap = first[_T.STARTING_COMMITTED]
            decided = first[_T.TERMINAL_DECIDED]
            handoff = first.get(_T.RUNNING_COMMITTED)
            facts: dict[str, object] = {
                "state": command_run.command_result.invocation.state.value,
                "origin": "RUNNING" if handoff is not None else "STARTING",
                "pre_handoff_seconds": (
                    (handoff if handoff is not None else decided) - swap
                )
                / 1e7,
                "swap_to_decision_seconds": (decided - swap) / 1e7,
            }
            if entry.row == 25:
                missed = first[_T.HEARTBEAT_MISSED]
                assert missed < decided
                facts["heartbeat_missed_to_deadline_seconds"] = (decided - missed) / 1e7
            measured[entry.name] = facts
        finally:
            assert_nothing_launched_survives(strategy)
    assert set(measured) == {item.name for item in entries}
    (tmp_path / "task8-timing.json").write_text(
        json.dumps(measured, indent=2, sort_keys=True), encoding="utf-8"
    )


# --- Determinism across scenario order (brief section 20) ----------------------------


def test_scenarios_reach_the_same_content_in_either_order_through_the_supervisor(
    tmp_path: Path,
) -> None:
    forward_strategy = ProductionSupervision(cancellation_grace_seconds=1)
    reverse_strategy = ProductionSupervision(cancellation_grace_seconds=1)
    try:
        forward = build_harness(
            tmp_path / "forward",
            _CONFORMANT,
            limits=PROTOCOL_LIMITS_DEFAULT,
            seed="task8-order",
            supervise=forward_strategy,
        )
        described_first = forward.describe(
            _CONFORMANT, FAKE_ADAPTER_VERSION, timeout_seconds=DEFAULT_TIMEOUT_SECONDS
        )
        run_second = forward.drive(
            _CONFORMANT, CommandKind.RUN, timeout_seconds=DEFAULT_TIMEOUT_SECONDS
        )
        reverse = build_harness(
            tmp_path / "reverse",
            _CONFORMANT,
            limits=PROTOCOL_LIMITS_DEFAULT,
            seed="task8-order",
            supervise=reverse_strategy,
        )
        run_first = reverse.drive(
            _CONFORMANT, CommandKind.RUN, timeout_seconds=DEFAULT_TIMEOUT_SECONDS
        )
        described_second = reverse.describe(
            _CONFORMANT, FAKE_ADAPTER_VERSION, timeout_seconds=DEFAULT_TIMEOUT_SECONDS
        )
        assert described_first.reconciliation == described_second.reconciliation
        assert reconciliation_content(run_second) == reconciliation_content(run_first)
        assert run_second.written_paths == run_first.written_paths
        for harness in (forward, reverse):
            assert len(harness.store.committed_experiments()) == 1
            assert len(harness.store.committed_engine_runs()) == 1
            assert len(harness.store.committed_command_invocations()) == 2
        assert forward.store is not reverse.store
        assert [event.event_type for event in forward.store.committed_run_events()] == [
            event.event_type for event in reverse.store.committed_run_events()
        ]
        # The operating-system facts differ per launch; the authoritative content
        # above does not, and every trace is delivered in sequence order.
        for outcome in (*forward_strategy.outcomes, *reverse_strategy.outcomes):
            sequences = [entry.sequence for entry in outcome.trace]
            assert sequences == sorted(sequences)
    finally:
        assert_nothing_launched_survives(forward_strategy)
        assert_nothing_launched_survives(reverse_strategy)


# --- Row 26's pre-handoff form and the cleaned command root (plan 9.4, 7.5, 8.4) -----

#: The two 1 s linked entries of row 26 (plan 9.4): the VALIDATE and RUN forms, by
#: row and command, never by a name substring.
_ROW26_LINKED: Final = tuple(
    item
    for item in SCENARIOS
    if item.row == 26 and item.command is not CommandKind.DESCRIBE
)
_ROW26_RUN: Final = next(
    item for item in _ROW26_LINKED if item.command is CommandKind.RUN
)
#: An unaffected core-won RUN row that reaches RUNNING and keeps its command root.
_ROW27_RUN: Final = next(
    item for item in SCENARIOS if item.row == 27 and item.command is CommandKind.RUN
)


def _pre_handoff_strategy() -> ProductionSupervision:
    """The production strategy whose monotonic reading is pushed past the 1 s budget
    the moment the STARTING swap commits, so the pre-handoff deadline check that
    follows the real launch fires deterministically: plan 9.4's STARTING-origin form
    without loading the host. The child is really launched, terminated and cleaned
    up by the production supervisor; only the clock reading moves (the doubles'
    ``advance_monotonic`` seam), and the durable UTC instants stay fixed."""
    observer = RecordingObserver()
    strategy = ProductionSupervision(
        cancellation_grace_seconds=1, observers=(observer,)
    )
    clock = strategy.clock
    assert isinstance(clock, RealtimeMonotonicClock)

    def push_past_the_budget(_entry: object) -> None:
        clock.advance_monotonic(PROCESS_TIMEOUT_SECONDS + 1)

    observer.on(_T.STARTING_COMMITTED, push_past_the_budget)
    return strategy


def _is_absent(path: Path) -> bool:
    """Actually absent -- ``lstat`` fails with ``FileNotFoundError`` -- rather than
    merely inaccessible (any other ``OSError`` propagates)."""
    try:
        os.lstat(path)
    except FileNotFoundError:
        return True
    return False


def _root_removal_entries(command_run: CommandRun) -> tuple[SupervisionTraceKind, ...]:
    """The kinds of every retained cleanup entry naming ``COMMAND_ROOT_REMOVED``."""
    outcome = command_run.supervision_outcome
    assert outcome is not None
    return tuple(
        entry.kind
        for entry in outcome.trace
        if entry.kind in (_T.CLEANUP_ACTION, _T.CLEANUP_FAILED)
        and entry.facts.get("action") == CleanupAction.COMMAND_ROOT_REMOVED.value
    )


def test_the_row_26_linked_entries_are_exactly_the_validate_and_run_forms() -> None:
    assert [item.name for item in _ROW26_LINKED] == [
        "row26-process-timeout-validate",
        "row26-process-timeout-run",
    ]
    assert {item.adapter_name for item in _ROW26_LINKED} == {"fake.process-timeout"}
    assert {item.timeout_seconds for item in _ROW26_LINKED} == {PROCESS_TIMEOUT_SECONDS}
    assert all(item.invocation_state is _C.TIMED_OUT for item in _ROW26_LINKED)
    assert all(item.core_won for item in _ROW26_LINKED)
    assert _ROW27_RUN.name == "row27-cancellation-run"


@pytest.mark.parametrize("entry", _ROW26_LINKED, ids=scenario_ids(_ROW26_LINKED))
def test_row_26_pre_handoff_timeout_removes_the_root_and_passes_the_expectation(
    tmp_path: Path, entry: Scenario
) -> None:
    """Live production composition in plan 9.4's STARTING-origin form, taken
    deterministically through the clock seam. The terminal is ``TIMED_OUT`` with no
    committed process-start facts (a child was launched and terminated; its start
    was never committed), the coupled run is ``TIMED_OUT``, the supervisor removed
    the command root and traced exactly one successful ``COMMAND_ROOT_REMOVED``,
    and ``assert_stage_six_expectation`` accepts the form. Before the correction
    the helper read ``request.json`` from the removed root and raised
    ``FileNotFoundError`` -- the manual verifier failure of 2026-09-29."""
    strategy = _pre_handoff_strategy()
    try:
        harness, command_run = _drive(entry, tmp_path, strategy)
        invocation = command_run.command_result.invocation
        assert invocation.state is _C.TIMED_OUT
        assert invocation.process_created is False
        assert _missing(invocation.pid_identity)
        assert _missing(invocation.process_started_at_utc)
        assert harness.stored_run(invocation.run_id).state is _R.TIMED_OUT
        kinds = trace_kinds(command_run)
        assert _T.PRE_HANDOFF_DEADLINE in kinds
        assert _T.RUNNING_COMMITTED not in kinds
        root = Path(command_run.command_root)
        assert _is_absent(root)
        assert root.parent.is_dir()
        assert _root_removal_entries(command_run) == (_T.CLEANUP_ACTION,)
        assert_stage_six_expectation(harness, command_run, entry)
    finally:
        assert_nothing_launched_survives(strategy)


def test_a_retained_root_after_a_pre_handoff_timeout_fails_the_expectation(
    tmp_path: Path,
) -> None:
    """Assertion logic over a fixture derived from one live STARTING-origin run
    (constructing the mutation executes no supervisor): recreating the removed
    command root as an empty directory must fail the cleaned-root branch. The
    branch is selected by the canonical record, so a present root is caught
    instead of being routed to the wire-material check."""
    strategy = _pre_handoff_strategy()
    try:
        harness, command_run = _drive(_ROW26_RUN, tmp_path, strategy)
        root = Path(command_run.command_root)
        assert _is_absent(root)
        root.mkdir()
        try:
            with pytest.raises(AssertionError, match="retained"):
                assert_stage_six_expectation(harness, command_run, _ROW26_RUN)
        finally:
            root.rmdir()
    finally:
        assert_nothing_launched_survives(strategy)


def test_a_removed_root_without_the_traced_cleanup_fails_the_expectation(
    tmp_path: Path,
) -> None:
    """Assertion logic over a fixture derived from one live STARTING-origin run: the
    same run with the ``COMMAND_ROOT_REMOVED`` cleanup entry dropped from the
    retained trace (a synthetic outcome; production did trace it) must fail. The
    root's absence alone is not evidence of the prescribed cleanup."""
    strategy = _pre_handoff_strategy()
    try:
        harness, command_run = _drive(_ROW26_RUN, tmp_path, strategy)
        outcome = command_run.supervision_outcome
        assert outcome is not None
        removal = CleanupAction.COMMAND_ROOT_REMOVED.value
        kept = tuple(
            entry
            for entry in outcome.trace
            if not (
                entry.kind is _T.CLEANUP_ACTION and entry.facts.get("action") == removal
            )
        )
        assert len(kept) == len(outcome.trace) - 1
        mutated = dataclasses.replace(
            command_run, supervision_outcome=outcome.model_copy(update={"trace": kept})
        )
        with pytest.raises(AssertionError, match="COMMAND_ROOT_REMOVED"):
            assert_stage_six_expectation(harness, mutated, _ROW26_RUN)
    finally:
        assert_nothing_launched_survives(strategy)


def test_a_missing_request_file_still_fails_the_running_origin_row_26(
    tmp_path: Path,
) -> None:
    """Preservation control. Row 26 RUN in its ordinary RUNNING-origin form keeps
    its root and its request file; with the file present the expectation holds,
    and with the file deleted by hand the wire-material check still requires it.
    No broad missing-file acceptance. The RUNNING-origin form cannot be forced
    through a seam -- it needs the real launch to return inside the 1 s budget --
    so this control is host-load-sensitive by construction: a ``TIMED_OUT`` record
    failing the precondition below means the host did not reach the handoff in
    time (the STARTING-origin form the matrix row now tolerates), not a regression
    of the assertion helper; any other state is a different failure."""
    strategy = ProductionSupervision(cancellation_grace_seconds=1)
    try:
        harness, command_run = _drive(_ROW26_RUN, tmp_path, strategy)
        invocation = command_run.command_result.invocation
        assert invocation.state is _C.TIMED_OUT, "precondition: the row timed out"
        assert invocation.process_created is True, "precondition: RUNNING-origin form"
        request = Path(command_run.command_root) / REQUEST_FILE_NAME
        assert request.is_file()
        assert_stage_six_expectation(harness, command_run, _ROW26_RUN)
        request.unlink()
        with pytest.raises(FileNotFoundError):
            assert_stage_six_expectation(harness, command_run, _ROW26_RUN)
    finally:
        assert_nothing_launched_survives(strategy)


def test_a_removed_root_of_an_unaffected_row_still_fails_the_expectation(
    tmp_path: Path,
) -> None:
    """Preservation control. Row 27 (cancellation, RUN) reaches RUNNING and keeps
    its root; with the root removed by hand after the run the wire-material check
    still fails: the cleaned-root branch is not selected by the very absence it
    validates, nor by another row's terminal state."""
    strategy = ProductionSupervision(cancellation_grace_seconds=1)
    try:
        harness, command_run = _drive(_ROW27_RUN, tmp_path, strategy)
        assert command_run.command_result.invocation.process_created is True
        assert_stage_six_expectation(harness, command_run, _ROW27_RUN)
        shutil.rmtree(command_run.command_root)
        assert _is_absent(Path(command_run.command_root))
        with pytest.raises(FileNotFoundError):
            assert_stage_six_expectation(harness, command_run, _ROW27_RUN)
    finally:
        assert_nothing_launched_survives(strategy)


def test_the_raw_token_in_a_surviving_surface_fails_despite_the_cleaned_root(
    tmp_path: Path,
) -> None:
    """Assertion logic over a fixture derived from one live STARTING-origin run: a
    synthetic diagnostic carrying the raw attempt token, planted into the retained
    command result, must fail the token-absence walk even though the root was
    cleaned. The walk that fires is the caller's kept ``assert_token_absent`` over
    the token-free projections, which precedes the cleaned-root branch; the
    branch's own mirror of that walk (its extra surfaces, the outcome and the
    reconciliation, are ``None`` on a core-won row) is therefore not independently
    covered by this control. Boolean assertion only: the token is never printed."""
    strategy = _pre_handoff_strategy()
    try:
        harness, command_run = _drive(_ROW26_RUN, tmp_path, strategy)
        invocation = command_run.command_result.invocation
        token = harness.token_for(invocation.run_id)
        result = command_run.command_result
        assert len(result.diagnostics) >= 1
        first = result.diagnostics[0]
        leaking = first.model_copy(update={"message": f"leaked {token}"})
        mutated = dataclasses.replace(
            command_run,
            command_result=result.model_copy(
                update={"diagnostics": (*result.diagnostics, leaking)}
            ),
        )
        with pytest.raises(AssertionError, match="raw attempt token"):
            assert_stage_six_expectation(harness, mutated, _ROW26_RUN)
    finally:
        assert_nothing_launched_survives(strategy)
