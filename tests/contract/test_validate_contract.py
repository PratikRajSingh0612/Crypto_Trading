"""Stage 6 Task 8: the ``validate`` rows of plan 11.2 through the offline harness.

Rows 2, 5, 7, 9, 18, 26 (validate), 46 and 47. Each row drives the real Stage 5
lifecycle (experiment, attempt, ``PENDING -> VALIDATING``, the ``VALIDATE``
invocation) and, for an ``EXITED`` invocation, ``parse_validation_result`` and
``apply_command_semantic_outcome``; a ``VALID`` result moves the run to ``READY``
and never launches a ``RUN``. Row 47 is the stale-attempt flow: attempt 1 validates
and fails its run, the retry decision reserves attempt 2, and attempt 2's fake
copies attempt 1's validation result byte for byte, which the identity check of plan
9.2 (3) rejects.
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
from contract.scenarios import (
    DEFAULT_TIMEOUT_SECONDS,
    Scenario,
    scenario_ids,
    validate_rows,
)
from crypto_lab.adapters.diagnostics import (
    ENGINE_RUNTIME_FAILURE,
    PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
)
from crypto_lab.adapters.manifests import AdapterResultManifest, AdapterValidationResult
from crypto_lab.adapters.reconciliation import SemanticReconciliation
from crypto_lab.adapters.vocabulary import (
    ProtocolIntegrityStatus,
    ReconciliationVerdict,
)
from crypto_lab.domain.engine_run import SUCCESS_ENGINE_RUN_STATES
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
)
from doubles.experiments import AVAIL_A

_C = CommandInvocationState
_R = EngineRunState
_V = ReconciliationVerdict
_ROWS = validate_rows()
_STALE_ROW = 47


def _missing(value: object) -> bool:
    return value is MISSING


def _drive(scenario: Scenario, root: Path) -> tuple[OfflineCommandHarness, CommandRun]:
    harness = build_harness(
        root,
        scenario.adapter_name,
        limits=scenario.limits,
        seed=f"task8-{scenario.name}",
        letter_leading_token=scenario.letter_leading_token,
    )
    if scenario.row == _STALE_ROW:
        return harness, _stale_attempt(harness, scenario)
    return harness, harness.drive(
        scenario.adapter_name,
        CommandKind.VALIDATE,
        timeout_seconds=scenario.timeout_seconds,
    )


def _stale_attempt(harness: OfflineCommandHarness, scenario: Scenario) -> CommandRun:
    """Plan 11.2 row 47: attempt 1 validates and runs to ``FAILED``, the successor is
    created after the durable delay, and attempt 2's validate copies attempt 1's
    output byte for byte."""
    experiment = harness.new_experiment(scenario.adapter_name)
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


@pytest.mark.parametrize("scenario", _ROWS, ids=scenario_ids(_ROWS))
def test_validate_row(scenario: Scenario, tmp_path: Path) -> None:
    harness, result = _drive(scenario, tmp_path)
    invocation = result.command_result.invocation
    assert invocation.command_kind is CommandKind.VALIDATE
    assert invocation.state is scenario.invocation_state
    assert not _missing(invocation.run_id)
    run = harness.stored_run(invocation.run_id)
    assert run.state is scenario.run_state
    assert run.state not in SUCCESS_ENGINE_RUN_STATES
    assert _missing(run.finalization_deadline_utc)
    # A validate never launches a RUN, writes no candidate file and no manifest.
    assert harness.invocations_of(run.run_id, CommandKind.RUN) == ()
    assert result.written_paths <= frozenset({"output.json", "stale-output.json"})
    assert not isinstance(result.command_result.parsed_output, AdapterResultManifest)
    if scenario.accepted_events is not None:
        assert len(result.command_result.accepted_events) == scenario.accepted_events
    token = harness.token_for(run.run_id)
    assert_token_absent(token_free_projections(result), token)
    assert_token_only_in_wire_material(result, token)
    if scenario.core_won:
        assert result.outcome is None
        assert result.reconciliation is None
        assert harness.primary_code_of(invocation) == scenario.primary_code
        assert run.primary_terminal_diagnostic_id == invocation.primary_diagnostic_id
        assert not _missing(invocation.native_exit_value)
        assert result.command_result.protocol_integrity is (
            ProtocolIntegrityStatus.VIOLATED
            if scenario.invocation_state is _C.PROTOCOL_FAILED
            else ProtocolIntegrityStatus.INTACT
        )
        assert result.command_result.timed_out is (
            scenario.invocation_state is _C.TIMED_OUT
        )
        return
    assert invocation.native_exit_value == scenario.native_exit
    assert result.command_result.protocol_integrity is ProtocolIntegrityStatus.INTACT
    assert result.outcome is not None
    assert result.outcome.run == run
    assert result.outcome.invocation == invocation
    assert _missing(result.outcome.superseded_by)
    reconciliation = result.reconciliation
    assert isinstance(reconciliation, SemanticReconciliation)
    assert reconciliation.command_kind is CommandKind.VALIDATE
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


def test_the_valid_result_is_the_evidence_and_the_run_is_ready(tmp_path: Path) -> None:
    (scenario,) = (item for item in _ROWS if item.row == 2)
    harness, result = _drive(scenario, tmp_path)
    reconciliation = result.reconciliation
    assert isinstance(reconciliation, SemanticReconciliation)
    evidence = reconciliation.sanitized_validation_result
    assert isinstance(evidence, AdapterValidationResult)
    parsed = result.command_result.parsed_output
    assert isinstance(parsed, AdapterValidationResult)
    assert evidence == parsed
    assert evidence.invocation_id == result.command_result.invocation.invocation_id
    run = harness.stored_run(evidence.run_id)
    assert evidence.attempt_token_hash == run.attempt_token_hash
    assert (run.state, run.revision) == (_R.READY, 2)
    events = result.command_result.accepted_events
    assert tuple(event.event_type.value for event in events) == (
        "HEARTBEAT",
        "PROGRESS",
    )
    assert harness.store.committed_run_events() == events


def test_a_stale_attempt_result_fails_every_identity_field(tmp_path: Path) -> None:
    (scenario,) = (item for item in _ROWS if item.row == _STALE_ROW)
    harness, result = _drive(scenario, tmp_path)
    reconciliation = result.reconciliation
    assert isinstance(reconciliation, SemanticReconciliation)
    primary = reconciliation.primary_diagnostic
    assert not _missing(primary)
    assert primary.error_code == PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION
    assert primary.details["mismatched_fields"] == [
        "invocation_id",
        "run_id",
        "request_id",
        "attempt_token_hash",
    ]
    # The stale document parsed strict-valid but is not this run's evidence.
    assert _missing(reconciliation.sanitized_validation_result)
    assert isinstance(result.command_result.parsed_output, AdapterValidationResult)
    runs = harness.store.committed_engine_runs()
    assert sorted(run.attempt_number for run in runs) == [1, 2]
    assert {run.state for run in runs} == {_R.FAILED}
    assert len(harness.store.committed_retry_decisions()) == 1


def test_wrong_token_proof_is_identity_not_schema(tmp_path: Path) -> None:
    (scenario,) = (item for item in _ROWS if item.row == 18)
    _harness, result = _drive(scenario, tmp_path)
    reconciliation = result.reconciliation
    assert isinstance(reconciliation, SemanticReconciliation)
    primary = reconciliation.primary_diagnostic
    assert not _missing(primary)
    assert primary.details["mismatched_fields"] == ["attempt_token_hash"]
    # The document is strict-valid on its own terms; only the proof is foreign.
    assert isinstance(result.command_result.parsed_output, AdapterValidationResult)
    assert _missing(reconciliation.sanitized_validation_result)
