"""Stage 6 Task 8: the ``run`` rows of plan 11.2 that reach ``EXITED``.

Every row drives the real Stage 5 lifecycle to a ``RUNNING`` pair, launches the
fake through the offline harness, parses stdout with ``parse_protocol_line``,
folds the ledger, parses the manifest with ``parse_result_manifest``, observes the
declared candidate files and applies ``apply_command_semantic_outcome``. No row
produces a success run state: ``RESULT_FINALIZATION_ELIGIBLE`` leaves the run
``RUNNING`` for Stage 9, and every adverse row lands in a non-success terminal with
a hard-blocking or exit-derived primary.
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
from contract.scenarios import Scenario, run_rows, scenario_ids
from crypto_lab.adapters.diagnostics import (
    ARTIFACT_RESULT_MANIFEST_INVALID,
    COMPAT_LATE_NOT_APPLICABLE,
    ENGINE_RUNTIME_FAILURE,
    PROCESS_MISSING_HEARTBEAT,
    PROCESS_STDERR_TRUNCATED,
    PROCESS_UNRECOGNIZED_PROCESS_EXIT,
    SECURITY_SENSITIVE_MATERIAL_LEAKAGE,
)
from crypto_lab.adapters.events import HeartbeatPayload, WarningPayload
from crypto_lab.adapters.limits import RESULT_MANIFEST_RELATIVE_PATH
from crypto_lab.adapters.manifests import (
    AdapterResultManifest,
    SanitizedAdapterResultManifest,
    parse_result_manifest,
)
from crypto_lab.adapters.reconciliation import SemanticReconciliation
from crypto_lab.adapters.sanitization import REDACTION_PLACEHOLDER, StderrCapture
from crypto_lab.adapters.vocabulary import (
    ProtocolEventType,
    ProtocolIntegrityStatus,
    ReconciliationVerdict,
)
from crypto_lab.domain.engine_run import SUCCESS_ENGINE_RUN_STATES
from crypto_lab.domain.hashing import candidate_artifact_id_for
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
)

_C = CommandInvocationState
_R = EngineRunState
_V = ReconciliationVerdict
_ROWS = run_rows()
_WORK_PREFIX = "runs/"


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


def _reconciliation(result: CommandRun) -> SemanticReconciliation:
    assert isinstance(result.reconciliation, SemanticReconciliation)
    return result.reconciliation


@pytest.mark.parametrize("scenario", _ROWS, ids=scenario_ids(_ROWS))
def test_run_row(scenario: Scenario, tmp_path: Path) -> None:
    harness, result = _drive(scenario, tmp_path)
    invocation = result.command_result.invocation
    assert invocation.command_kind is CommandKind.RUN
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
    work_prefix = f"{_WORK_PREFIX}{run.run_id}/work/"
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
    reconciliation = _reconciliation(result)
    assert reconciliation.command_kind is CommandKind.RUN
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
        # Plan 9.3: the run stays RUNNING at the revision the launch left it at.
        assert (run.state, run.revision) == (_R.RUNNING, 4)
        assert _missing(run.primary_terminal_diagnostic_id)
        # Only the supervisor's secondaries (if any) reach the invocation.
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


def test_the_conformant_run_derives_both_candidate_identities(tmp_path: Path) -> None:
    harness, result = _drive(_row(3), tmp_path)
    reconciliation = _reconciliation(result)
    sanitized = reconciliation.sanitized_manifest
    assert isinstance(sanitized, SanitizedAdapterResultManifest)
    invocation = result.command_result.invocation
    manifest = result.command_result.parsed_output
    assert isinstance(manifest, AdapterResultManifest)
    expected = tuple(
        sorted(
            candidate_artifact_id_for(
                manifest.run_id, invocation.invocation_id, item.relative_path
            )
            for item in manifest.candidate_artifacts
        )
    )
    assert len(expected) == 2
    assert sanitized.candidate_artifact_ids == expected
    declared_events = {
        event.event_id
        for event in result.command_result.accepted_events
        if event.event_type is ProtocolEventType.ARTIFACT_PRODUCED
    }
    assert {item.source_event_id for item in sanitized.candidate_declarations} == (
        declared_events
    )
    assert result.written_paths == frozenset(
        f"runs/{manifest.run_id}/work/{name}"
        for name in (
            RESULT_MANIFEST_RELATIVE_PATH,
            "results/native.bin",
            "results/normalized.json",
        )
    )
    types = tuple(event.event_type for event in result.command_result.accepted_events)
    assert types == (
        ProtocolEventType.HEARTBEAT,
        ProtocolEventType.PROGRESS,
        ProtocolEventType.ARTIFACT_PRODUCED,
        ProtocolEventType.ARTIFACT_PRODUCED,
        ProtocolEventType.FINAL_RESULT,
    )
    assert result.protocol_summary is not None
    assert result.protocol_summary.redactions == 0
    assert harness.store.committed_engine_runs()[0].revision == 4


def test_late_not_applicable_cites_the_explaining_adapter_diagnostic(
    tmp_path: Path,
) -> None:
    _harness, result = _drive(_row(6), tmp_path)
    primary = _reconciliation(result).primary_diagnostic
    assert not _missing(primary)
    assert primary.error_code == COMPAT_LATE_NOT_APPLICABLE
    manifest = result.command_result.parsed_output
    assert isinstance(manifest, AdapterResultManifest)
    assert primary.details["adapter_error_code"] == manifest.diagnostics[0].error_code
    assert primary.details["adapter_manifest_id"] == manifest.adapter_manifest_id
    assert primary.causal_diagnostic_ids == ()


def test_a_replayed_sequence_is_accepted_once_under_an_advanced_clock(
    tmp_path: Path,
) -> None:
    _harness, result = _drive(_row(13), tmp_path)
    assert result.replayed_count == 1
    events = result.command_result.accepted_events
    assert tuple(event.sequence for event in events) == (1, 2, 3, 4, 5, 6)
    assert sum(1 for event in events if event.sequence == 2) == 1
    # Seven framed lines were written for six accepted events.
    assert len(result.raw_stdout_lines) == 7
    assert result.raw_stdout_lines[1] == result.raw_stdout_lines[2]


def test_stderr_text_is_retained_redacted_and_token_free(tmp_path: Path) -> None:
    harness, result = _drive(_row(22), tmp_path)
    capture = result.command_result.stderr
    assert isinstance(capture, StderrCapture)
    assert capture.truncated is False
    assert isinstance(capture.sanitized_text, str)
    assert "engine warming up" in capture.sanitized_text
    assert REDACTION_PLACEHOLDER in capture.sanitized_text
    token = harness.token_for(result.command_result.invocation.run_id)
    # Boolean form: a failure report prints True/False, never the token itself.
    leaked = token in capture.sanitized_text
    assert leaked is False
    assert result.command_result.invocation.diagnostic_ids == ()
    assert result.command_result.diagnostics == ()


def test_a_stderr_flood_is_truncated_and_recorded_as_a_secondary(
    tmp_path: Path,
) -> None:
    harness, result = _drive(_row(23), tmp_path)
    capture = result.command_result.stderr
    assert isinstance(capture, StderrCapture)
    assert capture.truncated is True
    assert capture.retained_byte_count == _row(23).limits.max_stderr_bytes
    invocation = result.command_result.invocation
    assert harness.codes_of(invocation.diagnostic_ids) == (PROCESS_STDERR_TRUNCATED,)
    assert [item.error_code for item in result.command_result.diagnostics] == [
        PROCESS_STDERR_TRUNCATED
    ]
    assert _reconciliation(result).verdict is _V.RESULT_FINALIZATION_ELIGIBLE


def test_regular_heartbeats_never_mint_a_missing_heartbeat(tmp_path: Path) -> None:
    harness, result = _drive(_row(24), tmp_path)
    invocation = result.command_result.invocation
    assert PROCESS_MISSING_HEARTBEAT not in harness.codes_of(invocation.diagnostic_ids)
    assert result.command_result.diagnostics == ()
    heartbeats = [
        event.payload.activity_counter
        for event in result.command_result.accepted_events
        if isinstance(event.payload, HeartbeatPayload)
    ]
    assert len(heartbeats) >= 5
    assert heartbeats == sorted(heartbeats)


def test_an_unrecognized_exit_is_cited_causally(tmp_path: Path) -> None:
    harness, result = _drive(_row(29), tmp_path)
    invocation = result.command_result.invocation
    assert not _missing(invocation.primary_diagnostic_id)
    assert (
        harness.diagnostic(invocation.primary_diagnostic_id).error_code
        == PROCESS_UNRECOGNIZED_PROCESS_EXIT
    )
    primary = _reconciliation(result).primary_diagnostic
    assert not _missing(primary)
    assert primary.error_code == ENGINE_RUNTIME_FAILURE
    assert primary.causal_diagnostic_ids == (invocation.primary_diagnostic_id,)
    assert primary.details["manifest_present"] is False


def test_a_crash_before_any_event_records_the_absent_manifest(tmp_path: Path) -> None:
    _harness, result = _drive(_row(38), tmp_path)
    assert result.command_result.accepted_events == ()
    assert result.raw_stdout_lines == ()
    primary = _reconciliation(result).primary_diagnostic
    assert not _missing(primary)
    assert primary.details["manifest_present"] is False
    assert primary.details["native_exit_value"] == 40
    assert result.written_paths == frozenset()


def test_a_crash_after_partial_events_keeps_the_accepted_events(tmp_path: Path) -> None:
    harness, result = _drive(_row(39), tmp_path)
    events = result.command_result.accepted_events
    assert tuple(event.event_type for event in events) == (
        ProtocolEventType.HEARTBEAT,
        ProtocolEventType.HEARTBEAT,
        ProtocolEventType.HEARTBEAT,
        ProtocolEventType.ARTIFACT_PRODUCED,
    )
    assert harness.store.committed_run_events() == events
    assert result.written_paths == frozenset()
    assert result.protocol_summary is not None
    assert len(result.protocol_summary.artifact_declarations) == 1


def test_a_token_in_a_warning_is_redacted_on_both_sides(tmp_path: Path) -> None:
    harness, result = _drive(_row(40), tmp_path)
    token = harness.token_for(result.command_result.invocation.run_id)
    warnings = [
        event.payload.warning
        for event in result.command_result.accepted_events
        if isinstance(event.payload, WarningPayload)
    ]
    assert len(warnings) == 1
    assert REDACTION_PLACEHOLDER in warnings[0].message
    sanitized = _reconciliation(result).sanitized_manifest
    assert isinstance(sanitized, SanitizedAdapterResultManifest)
    assert REDACTION_PLACEHOLDER in sanitized.warnings[0].message
    assert sanitized.warnings == (warnings[0],)
    assert result.protocol_summary is not None
    assert result.protocol_summary.redactions == 1
    manifest_bytes = (result.work_dir / RESULT_MANIFEST_RELATIVE_PATH).read_bytes()
    carried = token.encode("utf-8") in manifest_bytes
    assert carried is True
    reparsed = parse_result_manifest(
        manifest_bytes, max_bytes=_row(40).limits.max_manifest_bytes, token=token
    )
    assert reparsed.redactions >= 1
    assert result.command_result.diagnostics == ()


def test_a_token_in_a_candidate_file_is_leakage(tmp_path: Path) -> None:
    harness, result = _drive(_row(41), tmp_path)
    primary = _reconciliation(result).primary_diagnostic
    assert not _missing(primary)
    assert primary.error_code == SECURITY_SENSITIVE_MATERIAL_LEAKAGE
    assert primary.details["leaking_candidates"] == 1
    token = harness.token_for(result.command_result.invocation.run_id)
    native_bytes = (result.work_dir / "results/native.bin").read_bytes()
    carried = token.encode("utf-8") in native_bytes
    assert carried is True


def test_provenance_and_declaration_mismatches_pin_their_checks(
    tmp_path: Path,
) -> None:
    """Rows 16 and 37 both end in ``ARTIFACT.RESULT_MANIFEST_INVALID``; the detail
    keys pin the branch: check (5) names the mismatched provenance field and check
    (9) counts the declared and accepted candidates. A reconciler that reached the
    code from the FINAL pointer (6) or the warnings (11) instead would not match."""
    _harness, sixteen = _drive(_row(16), tmp_path / "row-16")
    provenance = _reconciliation(sixteen).primary_diagnostic
    assert not _missing(provenance)
    assert provenance.error_code == ARTIFACT_RESULT_MANIFEST_INVALID
    assert provenance.details["mismatched_fields"] == ["request_hash"]
    _harness, thirty_seven = _drive(_row(37), tmp_path / "row-37")
    declarations = _reconciliation(thirty_seven).primary_diagnostic
    assert not _missing(declarations)
    assert declarations.error_code == ARTIFACT_RESULT_MANIFEST_INVALID
    assert sorted(declarations.details) == [
        "accepted_declarations",
        "declared_candidates",
    ]
    assert declarations.details["declared_candidates"] == 2
    assert declarations.details["accepted_declarations"] == 2


def test_a_failed_manifest_after_a_declared_candidate_keeps_the_retriable_posture(
    tmp_path: Path,
) -> None:
    _harness, result = _drive(_row(48), tmp_path)
    reconciliation = _reconciliation(result)
    primary = reconciliation.primary_diagnostic
    assert not _missing(primary)
    assert primary.error_code == ENGINE_RUNTIME_FAILURE
    assert primary.retriable is True
    sanitized = reconciliation.sanitized_manifest
    assert isinstance(sanitized, SanitizedAdapterResultManifest)
    assert sanitized.candidate_artifact_ids == ()
    assert result.protocol_summary is not None
    assert len(result.protocol_summary.artifact_declarations) == 1


def test_an_oversized_manifest_is_never_decoded(tmp_path: Path) -> None:
    harness, result = _drive(_row(51), tmp_path)
    token = harness.token_for(result.command_result.invocation.run_id)
    manifest_bytes = (result.work_dir / RESULT_MANIFEST_RELATIVE_PATH).read_bytes()
    limits = _row(51).limits
    assert len(manifest_bytes) > limits.max_manifest_bytes
    reparsed = parse_result_manifest(
        manifest_bytes, max_bytes=limits.max_manifest_bytes, token=token
    )
    assert _missing(reparsed.header)
    assert reparsed.failure_code == ARTIFACT_RESULT_MANIFEST_INVALID
    assert _missing(result.command_result.parsed_output)
    primary = _reconciliation(result).primary_diagnostic
    assert not _missing(primary)
    assert primary.details["byte_length"] == len(manifest_bytes)


def test_no_adverse_run_row_is_finalization_eligible(tmp_path: Path) -> None:
    """The closed no-false-success proof over the run rows that are not the
    plan's success declarations: none reaches the eligible verdict, a success run
    state or an unwritten primary."""
    adverse = [
        item for item in _ROWS if item.verdict is not _V.RESULT_FINALIZATION_ELIGIBLE
    ]
    assert {item.row for item in adverse} >= {
        16,
        29,
        30,
        31,
        32,
        33,
        35,
        36,
        37,
        38,
        39,
        41,
        48,
        51,
    }
    for scenario in adverse:
        harness, result = _drive(scenario, tmp_path / scenario.name)
        run = harness.stored_run(result.command_result.invocation.run_id)
        assert run.state not in SUCCESS_ENGINE_RUN_STATES
        assert run.state is not _R.RUNNING
        assert not _missing(run.primary_terminal_diagnostic_id)
        assert _reconciliation(result).verdict is not _V.RESULT_FINALIZATION_ELIGIBLE
