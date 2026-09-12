"""Stage 6 Task 8: the ``run`` rows the core terminalizes itself.

A rejected stdout line terminalizes the live invocation as ``PROTOCOL_FAILED`` with
the run ``FAILED`` through the Stage 5 coupled transition; the command deadline
terminalizes it as ``TIMED_OUT`` and a cancellation as ``CANCELLED`` (plan 11.3
item 3). No such invocation is reconciled or applied: ``CommandRun.outcome`` is
``None`` and no favourable output the child may still have written can override the
core decision. The native exit of the killed child is recorded by enrichment.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic.experimental.missing_sentinel import MISSING

from contract.harness import (
    CommandRun,
    OfflineCommandHarness,
    assert_token_absent,
    assert_token_only_in_wire_material,
    build_harness,
    token_free_projections,
)
from contract.scenarios import Scenario, protocol_failure_rows, scenario_ids
from crypto_lab.adapters.diagnostics import (
    PROCESS_CANCELLED,
    PROCESS_MISSING_HEARTBEAT,
    PROCESS_RUN_TIMED_OUT,
    PROTOCOL_STDOUT_CONTAMINATION,
)
from crypto_lab.adapters.events import EventRejected
from crypto_lab.adapters.sanitization import REDACTION_PLACEHOLDER
from crypto_lab.adapters.vocabulary import ProtocolEventType, ProtocolIntegrityStatus
from crypto_lab.domain.engine_run import SUCCESS_ENGINE_RUN_STATES
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
)

_C = CommandInvocationState
_R = EngineRunState
_ROWS = protocol_failure_rows()
_RUN_STATE_OF: dict[CommandInvocationState, EngineRunState] = {
    _C.PROTOCOL_FAILED: _R.FAILED,
    _C.TIMED_OUT: _R.TIMED_OUT,
    _C.CANCELLED: _R.CANCELLED,
}


def _missing(value: object) -> bool:
    return value is MISSING


def _row(row: int) -> Scenario:
    (scenario,) = (item for item in _ROWS if item.row == row)
    return scenario


def _drive(scenario: Scenario, root: Path) -> tuple[OfflineCommandHarness, CommandRun]:
    harness = build_harness(
        root,
        scenario.adapter_name,
        limits=scenario.limits,
        seed=f"task8-{scenario.name}",
        letter_leading_token=scenario.letter_leading_token,
    )
    return harness, harness.drive(
        scenario.adapter_name,
        CommandKind.RUN,
        timeout_seconds=scenario.timeout_seconds,
        cancel_after_first_heartbeat=scenario.cancel_after_first_heartbeat,
    )


@pytest.mark.parametrize("scenario", _ROWS, ids=scenario_ids(_ROWS))
def test_core_won_run_row(scenario: Scenario, tmp_path: Path) -> None:
    harness, result = _drive(scenario, tmp_path)
    invocation = result.command_result.invocation
    assert invocation.command_kind is CommandKind.RUN
    assert invocation.state is scenario.invocation_state
    assert not _missing(invocation.run_id)
    run = harness.stored_run(invocation.run_id)
    assert run.state is scenario.run_state
    assert run.state is _RUN_STATE_OF[scenario.invocation_state]
    assert run.state not in SUCCESS_ENGINE_RUN_STATES
    # The core decision is the primary of both records; nothing was reconciled.
    assert result.outcome is None
    assert result.reconciliation is None
    assert harness.primary_code_of(invocation) == scenario.primary_code
    assert run.primary_terminal_diagnostic_id == invocation.primary_diagnostic_id
    for code in scenario.secondary_codes:
        assert code in harness.codes_of(invocation.diagnostic_ids)
    # The killed child's native exit is recorded by enrichment (plan 11.3 item 3).
    assert not _missing(invocation.native_exit_value)
    assert invocation.process_created is True
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
    if scenario.accepted_events is not None:
        assert len(result.command_result.accepted_events) == scenario.accepted_events
    assert harness.store.committed_run_events() == result.command_result.accepted_events
    assert _missing(result.command_result.parsed_output)
    codes = [item.error_code for item in result.command_result.diagnostics]
    assert scenario.primary_code in codes
    token = harness.token_for(run.run_id)
    assert_token_absent(token_free_projections(result), token)
    assert_token_only_in_wire_material(result, token)
    if scenario.invocation_state is _C.PROTOCOL_FAILED:
        rejection = result.rejection
        assert isinstance(rejection, EventRejected)
        assert rejection.diagnostic.error_code == scenario.primary_code
        assert rejection.diagnostic.diagnostic_id == invocation.primary_diagnostic_id
        sample = rejection.sample.sample
        if isinstance(sample, str):
            # Boolean form: a failure report prints True/False, never the token.
            leaked = token in sample
            assert leaked is False
    else:
        assert result.rejection is None


def test_a_missing_heartbeat_is_minted_once_and_cited_by_the_deadline(
    tmp_path: Path,
) -> None:
    harness, result = _drive(_row(25), tmp_path)
    invocation = result.command_result.invocation
    assert not _missing(invocation.primary_diagnostic_id)
    primary = harness.diagnostic(invocation.primary_diagnostic_id)
    assert primary.error_code == PROCESS_RUN_TIMED_OUT
    (causal,) = primary.causal_diagnostic_ids
    assert harness.diagnostic(causal).error_code == PROCESS_MISSING_HEARTBEAT
    assert causal in invocation.diagnostic_ids
    assert (
        harness.codes_of(invocation.diagnostic_ids).count(PROCESS_MISSING_HEARTBEAT)
        == 1
    )
    assert len(result.command_result.accepted_events) == 1


def test_cancellation_after_the_first_heartbeat_records_the_termination(
    tmp_path: Path,
) -> None:
    harness, result = _drive(_row(27), tmp_path)
    invocation = result.command_result.invocation
    assert invocation.state is _C.CANCELLED
    assert harness.primary_code_of(invocation) == PROCESS_CANCELLED
    heartbeats = [
        event
        for event in result.command_result.accepted_events
        if event.event_type is ProtocolEventType.HEARTBEAT
    ]
    assert len(heartbeats) >= 1
    assert not _missing(invocation.native_exit_value)
    assert not _missing(invocation.process_exit_category)
    run = harness.stored_run(invocation.run_id)
    assert (run.state, run.primary_terminal_diagnostic_id) == (
        _R.CANCELLED,
        invocation.primary_diagnostic_id,
    )


def test_a_token_shaped_path_is_rejected_with_a_token_free_sample(
    tmp_path: Path,
) -> None:
    harness, result = _drive(_row(49), tmp_path)
    rejection = result.rejection
    assert isinstance(rejection, EventRejected)
    token = harness.token_for(result.command_result.invocation.run_id)
    sample = rejection.sample.sample
    assert isinstance(sample, str)
    leaked = token in sample
    assert leaked is False
    assert REDACTION_PLACEHOLDER in sample
    assert len(result.command_result.accepted_events) == 1


def test_a_token_shaped_phase_produces_no_run_event(tmp_path: Path) -> None:
    harness, result = _drive(_row(50), tmp_path)
    token = harness.token_for(result.command_result.invocation.run_id)
    assert token[0].isalpha()
    assert result.command_result.accepted_events == ()
    assert harness.store.committed_run_events() == ()
    rejection = result.rejection
    assert isinstance(rejection, EventRejected)
    sample = rejection.sample.sample
    assert isinstance(sample, str)
    leaked = token in sample
    assert leaked is False


def test_invalid_utf8_stdout_retains_no_sample(tmp_path: Path) -> None:
    _harness, result = _drive(_row(52), tmp_path)
    rejection = result.rejection
    assert isinstance(rejection, EventRejected)
    assert rejection.diagnostic.error_code == PROTOCOL_STDOUT_CONTAMINATION
    assert _missing(rejection.sample.sample)
    assert rejection.sample.byte_length == 3
    assert len(result.command_result.accepted_events) == 1


def test_favourable_output_after_a_rejection_never_overrides_the_failure(
    tmp_path: Path,
) -> None:
    """Rows 10, 12, 14 and 45 wrote or would have written a valid manifest and
    exit 0; the rejection terminalizes the pair before any exit is read."""
    for row in (10, 12, 14, 45):
        harness, result = _drive(_row(row), tmp_path / str(row))
        run = harness.stored_run(result.command_result.invocation.run_id)
        assert run.state is _R.FAILED
        assert result.outcome is None
        assert _missing(result.command_result.parsed_output)
