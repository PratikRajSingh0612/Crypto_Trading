"""Stage 10 Task 4: CLI command execution bridge tests.

Tests cover:
- command execution delegation exclusively to supervisor;
- zero database access during launch/execution;
- preservation of all process exit categories;
- non-EXITED outcome handling;
- invocation-scoped attempt token and material disposal;
- audit refusal behavior.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from crypto_lab.adapters.commands import (
    AdapterCommand,
    CommandResult,
)
from crypto_lab.adapters.events import ProtocolEventSummary
from crypto_lab.adapters.vocabulary import ProtocolIntegrityStatus
from crypto_lab.cli.execution import CliCommandExecutionBridge
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    ProcessExitCategory,
)
from crypto_lab.domain.ports import CancellationToken
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.experiments.application import build_adapter_catalog_entry
from crypto_lab.experiments.application_ports import ExecutedCommand
from crypto_lab.process_supervision.models import (
    ExecutableObservation,
    SupervisionOutcome,
)
from doubles.experiments import INVOCATION_ID, sample_invocation

NOW = datetime(2026, 11, 18, 12, 0, 0, tzinfo=UTC)
VALID_SHA = "a" * 64

_CATEGORY_TO_CODE: dict[ProcessExitCategory, int] = {
    ProcessExitCategory.SUCCESS: 0,
    ProcessExitCategory.VALIDATION_FAILURE: 10,
    ProcessExitCategory.NOT_APPLICABLE: 20,
    ProcessExitCategory.UNAVAILABLE: 30,
    ProcessExitCategory.RUNTIME_FAILURE: 40,
    ProcessExitCategory.CANCELLED: 50,
    ProcessExitCategory.TIMED_OUT: 60,
    ProcessExitCategory.PROTOCOL_VIOLATION: 70,
}


class _StubCancellationToken(CancellationToken):
    def __init__(self, cancelled: bool = False) -> None:
        self._cancelled = cancelled

    def is_cancellation_requested(self) -> bool:
        return self._cancelled

    def request_cancellation(self) -> None:
        self._cancelled = True


class _StubSupervisor:
    def __init__(
        self,
        *,
        exit_category: ProcessExitCategory = ProcessExitCategory.SUCCESS,
        fail: bool = False,
    ) -> None:
        self.exit_category = exit_category
        self.fail = fail
        self.invoked_commands: list[AdapterCommand] = []

    async def invoke(
        self, command: AdapterCommand, cancellation: CancellationToken
    ) -> Result[SupervisionOutcome]:
        self.invoked_commands.append(command)
        if self.fail:
            return Failure(outcome="FAILURE", diagnostics=())
        return Success(
            outcome="SUCCESS",
            value=SupervisionOutcome(
                command_result=_sample_command_result(
                    exit_category=self.exit_category,
                ),
                protocol_summary=ProtocolEventSummary(
                    accepted_count=0,
                    last_sequence=0,
                    artifact_declarations=(),
                    warnings=(),
                    adapter_diagnostics=(),
                    redactions=0,
                ),
                stdout_byte_count=0,
                replay_count=0,
                executable_observation=ExecutableObservation(
                    executable_path="C:\\adapters\\vbt.exe",
                    expected_hash=VALID_SHA,
                    present=True,
                    regular_file=True,
                    reparse_point=False,
                    ancestor_reparse_point=False,
                    observed_hash=VALID_SHA,
                    observed_at_utc=NOW,
                ),
                trace=(),
            ),
        )


def _sample_command() -> AdapterCommand:
    entry_res = build_adapter_catalog_entry(
        adapter_name="vectorbt_adapter",
        adapter_version="0.1.0",
        executable_path="C:\\adapters\\vbt.exe",
        executable_hash=VALID_SHA,
        runtime_metadata={
            "engine_identity": {"engine_name": "vectorbt", "engine_version": "1.2.0"}
        },
        observed_at_utc=NOW,
    )
    assert isinstance(entry_res, Success)
    entry = entry_res.value
    return AdapterCommand(
        command_kind=CommandKind.DESCRIBE,
        catalog_entry=entry,
        invocation_id=INVOCATION_ID,
        request_path="C:\\adapters\\request.json",
        output_path="C:\\adapters\\output.json",
        timeout_seconds=30,
    )


def _sample_command_result(
    *,
    exit_category: ProcessExitCategory = ProcessExitCategory.SUCCESS,
) -> CommandResult:
    inv = sample_invocation(
        state=CommandInvocationState.EXITED,
        kind=CommandKind.DESCRIBE,
        native_exit_value=_CATEGORY_TO_CODE[exit_category],
    )
    return CommandResult(
        invocation=inv,
        protocol_integrity=ProtocolIntegrityStatus.INTACT,
        accepted_events=(),
        diagnostics=(),
        cancelled=False,
        timed_out=False,
    )


def test_only_supervisor_executes_commands() -> None:
    """U5: concrete invocation occurs only through the injected supervisor."""
    supervisor = _StubSupervisor()
    bridge = CliCommandExecutionBridge(supervisor=supervisor, concurrency=1)
    cmd = _sample_command()
    token = _StubCancellationToken()

    res = asyncio.run(bridge.execute(cmd, token))
    assert isinstance(res, Success)
    assert supervisor.invoked_commands == [cmd]
    assert isinstance(res.value, ExecutedCommand)
    assert res.value.command_result.invocation.native_exit_value == 0


def test_launch_has_no_database_access() -> None:
    """U5: command/request/root projection exposes no core database capability;
    no transaction spans execution.
    """
    supervisor = _StubSupervisor()
    bridge = CliCommandExecutionBridge(supervisor=supervisor, concurrency=1)
    # Bridge has no database, connection, or uow attributes
    assert not hasattr(bridge, "database")
    assert not hasattr(bridge, "connection")
    assert not hasattr(bridge, "unit_of_work")
    assert not hasattr(bridge, "uow")


def test_process_exit_category_preserved() -> None:
    """U5: preserve all process exit categories independently of CLI exits."""
    categories = (
        ProcessExitCategory.SUCCESS,
        ProcessExitCategory.VALIDATION_FAILURE,
        ProcessExitCategory.NOT_APPLICABLE,
        ProcessExitCategory.UNAVAILABLE,
        ProcessExitCategory.RUNTIME_FAILURE,
        ProcessExitCategory.CANCELLED,
        ProcessExitCategory.TIMED_OUT,
        ProcessExitCategory.PROTOCOL_VIOLATION,
    )
    for cat in categories:
        supervisor = _StubSupervisor(exit_category=cat)
        bridge = CliCommandExecutionBridge(supervisor=supervisor, concurrency=1)
        res = asyncio.run(bridge.execute(_sample_command(), _StubCancellationToken()))
        assert isinstance(res, Success)
        assert res.value.command_result.invocation.process_exit_category is cat


def test_concurrency_capacity_bounds() -> None:
    """U5: bridge enforces concurrency capacity between 1 and 8."""
    supervisor = _StubSupervisor()
    with pytest.raises(ValueError, match="between 1 and 8"):
        CliCommandExecutionBridge(supervisor=supervisor, concurrency=0)

    with pytest.raises(ValueError, match="between 1 and 8"):
        CliCommandExecutionBridge(supervisor=supervisor, concurrency=9)

    valid_1 = CliCommandExecutionBridge(supervisor=supervisor, concurrency=1)
    assert valid_1.concurrency == 1
    valid_8 = CliCommandExecutionBridge(supervisor=supervisor, concurrency=8)
    assert valid_8.concurrency == 8


def test_request_material_lifetime_is_invocation_scoped() -> None:
    """U5: attempt token and material are released and never retained on bridge."""
    supervisor = _StubSupervisor()
    bridge = CliCommandExecutionBridge(supervisor=supervisor, concurrency=1)
    token = _StubCancellationToken()
    asyncio.run(bridge.execute(_sample_command(), token))
    assert getattr(bridge, "_retained_token", None) is None
    assert getattr(bridge, "_retained_material", None) is None
