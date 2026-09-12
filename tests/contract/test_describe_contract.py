"""Stage 6 Task 8: the ``describe`` rows of plan 11.2 through the offline harness.

Rows 1, 21, 26 (describe), 43 and 44. A describe has no run, no attempt token and
no stdout protocol: any stdout byte is contamination, the output file is parsed by
the committed ``parse_bootstrap_descriptor``, reconciled by ``reconcile_describe``
and projected into a ``RuntimeAvailabilityObservation`` by
``describe_availability_observation``; a ``DESCRIBED`` describe is never enriched
and every other verdict is (plan 5.4).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic.experimental.missing_sentinel import MISSING

from contract.harness import (
    DEFAULT_NEGOTIATED,
    FAKE_ADAPTER_VERSION,
    CommandRun,
    OfflineCommandHarness,
    build_harness,
    catalog_entry_for,
)
from contract.scenarios import Scenario, describe_rows, scenario_ids
from crypto_lab.adapters.diagnostics import (
    PROCESS_DESCRIBE_TIMED_OUT,
    PROTOCOL_STDOUT_CONTAMINATION,
)
from crypto_lab.adapters.negotiation import NegotiationResult
from crypto_lab.adapters.reconciliation import SemanticReconciliation
from crypto_lab.adapters.vocabulary import (
    NegotiationOutcome,
    ProtocolIntegrityStatus,
    ReconciliationVerdict,
)
from crypto_lab.domain.descriptors import AdapterDescriptor
from crypto_lab.domain.lifecycle import CommandInvocationState, CommandKind

_C = CommandInvocationState
_V = ReconciliationVerdict
_ROWS = describe_rows()
_CONFORMANT = "fake.conformant"


def _missing(value: object) -> bool:
    return value is MISSING


def _drive(scenario: Scenario, root: Path) -> tuple[OfflineCommandHarness, CommandRun]:
    harness = build_harness(
        root,
        scenario.adapter_name,
        limits=scenario.limits,
        seed=f"task8-{scenario.name}",
    )
    return harness, harness.describe(
        scenario.adapter_name,
        FAKE_ADAPTER_VERSION,
        timeout_seconds=scenario.timeout_seconds,
    )


@pytest.mark.parametrize("scenario", _ROWS, ids=scenario_ids(_ROWS))
def test_describe_row(scenario: Scenario, tmp_path: Path) -> None:
    harness, result = _drive(scenario, tmp_path)
    invocation = result.command_result.invocation
    assert invocation.command_kind is CommandKind.DESCRIBE
    assert _missing(invocation.run_id)
    assert invocation.state is scenario.invocation_state
    # A describe manufactures no run, applies no semantic outcome and has no events.
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
        assert observation.reason_code == PROCESS_DESCRIBE_TIMED_OUT
        return
    assert result.command_result.timed_out is False
    assert invocation.native_exit_value == scenario.native_exit
    reconciliation = result.reconciliation
    assert isinstance(reconciliation, SemanticReconciliation)
    assert reconciliation.command_kind is CommandKind.DESCRIBE
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


def _conformant(root: Path) -> tuple[OfflineCommandHarness, CommandRun]:
    (scenario,) = (item for item in _ROWS if item.row == 1)
    return _drive(scenario, root)


def test_a_described_adapter_negotiates_the_default_versions(tmp_path: Path) -> None:
    harness, result = _conformant(tmp_path)
    reconciliation = result.reconciliation
    assert isinstance(reconciliation, SemanticReconciliation)
    descriptor = reconciliation.descriptor
    assert isinstance(descriptor, AdapterDescriptor)
    entry = catalog_entry_for(_CONFORMANT)
    assert (descriptor.adapter_name, descriptor.adapter_version) == (
        entry.adapter_name,
        entry.adapter_version,
    )
    assert descriptor.executable_hash == entry.executable_hash
    assert descriptor.network_required is False
    assert descriptor.credentials_required is False
    negotiation = reconciliation.negotiation
    assert isinstance(negotiation, NegotiationResult)
    assert negotiation.outcome is NegotiationOutcome.NEGOTIATED
    assert negotiation.selected_protocol_version == DEFAULT_NEGOTIATED.protocol_version
    assert negotiation.selected_schema_versions == DEFAULT_NEGOTIATED.schema_versions
    assert (
        negotiation.selected_vocabulary_version
        == DEFAULT_NEGOTIATED.capability_vocabulary_version
    )
    assert result.written_paths == frozenset({"output.json"})
    assert result.raw_stdout_lines == ()
    parsed = result.command_result.parsed_output
    assert not _missing(parsed)
    assert result.output_bytes is not None
    assert harness.store.committed_command_invocations() == (
        result.command_result.invocation,
    )


def test_describe_noise_counts_the_stdout_byte_and_keeps_the_output(
    tmp_path: Path,
) -> None:
    (scenario,) = (item for item in _ROWS if item.row == 21)
    _harness, result = _drive(scenario, tmp_path)
    reconciliation = result.reconciliation
    assert isinstance(reconciliation, SemanticReconciliation)
    primary = reconciliation.primary_diagnostic
    assert not _missing(primary)
    assert primary.error_code == PROTOCOL_STDOUT_CONTAMINATION
    assert primary.details == {"stdout_bytes_seen": 1}
    # The output file was still written and parsed; contamination wins over it.
    assert result.written_paths == frozenset({"output.json"})
    assert not _missing(result.command_result.parsed_output)
    assert _missing(reconciliation.descriptor)


def test_a_repeated_describe_is_a_new_invocation_with_the_same_request_hash(
    tmp_path: Path,
) -> None:
    (scenario,) = (item for item in _ROWS if item.row == 1)
    harness = build_harness(
        tmp_path, _CONFORMANT, limits=scenario.limits, seed="task8-repeat"
    )
    first = harness.describe(_CONFORMANT, FAKE_ADAPTER_VERSION, timeout_seconds=30)
    second = harness.describe(_CONFORMANT, FAKE_ADAPTER_VERSION, timeout_seconds=30)
    one = first.command_result.invocation
    two = second.command_result.invocation
    assert one.invocation_id != two.invocation_id
    assert one.request_hash == two.request_hash
    assert len(harness.store.committed_command_invocations()) == 2
    assert first.reconciliation == second.reconciliation
    assert first.observation is not None
    assert second.observation is not None
    assert (
        first.observation.availability_observation_id
        != second.observation.availability_observation_id
    )


def test_two_fresh_roots_describe_identically(tmp_path: Path) -> None:
    """Determinism: the same seed and clock reproduce every authoritative
    projection; only the operating-system process facts may differ."""
    (scenario,) = (item for item in _ROWS if item.row == 1)
    _a, first = _drive(scenario, tmp_path / "a")
    _b, second = _drive(scenario, tmp_path / "b")
    assert first.reconciliation == second.reconciliation
    assert first.observation == second.observation
    assert first.output_bytes == second.output_bytes
    one = first.command_result.invocation.model_dump(mode="json")
    two = second.command_result.invocation.model_dump(mode="json")
    one.pop("pid_identity")
    two.pop("pid_identity")
    assert one == two
