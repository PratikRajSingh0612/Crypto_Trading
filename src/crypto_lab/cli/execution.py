"""Stage 10 Task 4: CLI command execution bridge.

Implements ``CommandExecutionPort`` from ``crypto_lab.experiments.application_ports``
using the injected ``ProcessSupervisor``. Concurrency is strictly bounded between
1 and 8 through an ``asyncio.Semaphore``. No database transactions span command
execution, and attempt-token materials remain strictly invocation-scoped.
"""

from __future__ import annotations

import asyncio

from crypto_lab.adapters.commands import AdapterCommand
from crypto_lab.domain.ports import CancellationToken
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.experiments.application_ports import (
    CommandExecutionPort,
    ExecutedCommand,
)
from crypto_lab.process_supervision.ports import ProcessSupervisor

__all__ = ["CliCommandExecutionBridge"]


class CliCommandExecutionBridge(CommandExecutionPort):
    """Bounded, supervisor-backed implementation of ``CommandExecutionPort``."""

    def __init__(
        self,
        supervisor: ProcessSupervisor,
        *,
        concurrency: int = 1,
    ) -> None:
        if not (1 <= concurrency <= 8):
            raise ValueError("concurrency must be between 1 and 8")
        self._supervisor = supervisor
        self._concurrency = concurrency
        self._semaphore = asyncio.Semaphore(concurrency)

    @property
    def concurrency(self) -> int:
        """The configured maximum concurrent command execution capacity."""
        return self._concurrency

    async def execute(
        self, command: AdapterCommand, cancellation: CancellationToken
    ) -> Result[ExecutedCommand]:
        """Supervise ``command`` to conclusion within the concurrency budget.

        No persistence session or transaction spans execution. The returned
        ``ExecutedCommand`` projects the supervisor's concrete outcome without
        persisting or leaking transient attempt-token material.
        """
        async with self._semaphore:
            outcome = await self._supervisor.invoke(command, cancellation)
            if isinstance(outcome, Failure):
                return outcome
            supervision = outcome.value
            return Success(
                outcome="SUCCESS",
                value=ExecutedCommand(
                    command_result=supervision.command_result,
                    output_parse=supervision.output_parse,
                    protocol_summary=supervision.protocol_summary,
                ),
            )
