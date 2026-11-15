"""The inward application query, execution and transaction ports of Stage 10.

Stage 10 plan Task 1 (decisions D05 and D06; plan section 2.5). Specification
section 8 places the protocols an application consumes in the application package
and lets only the composition root wire concrete implementations to them, so these
are pure structural contracts: ``persistence`` implements the query port, the CLI
execution bridge the execution port, and a transaction facade the transaction port,
while application orchestration consumes them. This module imports ``domain``,
``adapters`` and the Stage 5 ``experiments.ports`` alone; it names no concrete
persistence, configuration, CLI or process-supervision type and reaches neither the
artifact nor the audit package.

Its values are immutable internal projections detached from any session or
connection. They are not registered schemas and publish no ``$id``. Each holds only
frozen ``domain`` records or ``adapters`` facts in tuples, rejects unknown fields and
validates its own population, so a malformed or incomplete read cannot pass as an
empty or partial success:

- ``DurableWorkInventory`` is one complete projection of durable work: experiments,
  engine runs, command invocations and retry decisions, each in canonical ascending
  identity order, with every run, invocation and decision referring to a record of
  the same inventory.
- ``RequeueAssessment`` partitions logical slots into those eligible to be queued
  again and those fenced; it launches nothing, and a slot is never both.
- ``ExecutedCommand`` is one supervised command's outcome projected into existing
  adapter facts: the ``CommandResult``, the output parse (present only when the
  supervisor parsed one) and the protocol event summary.

The existing six-member ``UnitOfWork`` is preserved: ``ApplicationTransactionPort``
hands it out unchanged and never extends it.
"""

from __future__ import annotations

from typing import Protocol, Self, runtime_checkable

from pydantic import model_validator
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.adapters.commands import AdapterCommand, CommandResult
from crypto_lab.adapters.events import ProtocolEventSummary
from crypto_lab.adapters.manifests import ManifestParse, ValidationResultParse
from crypto_lab.adapters.negotiation import DescriptorParse
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.engine_run import EngineRunRecord
from crypto_lab.domain.experiment import ExperimentRecord
from crypto_lab.domain.identifiers import LogicalSlotId
from crypto_lab.domain.ports import CancellationToken
from crypto_lab.domain.results import Result
from crypto_lab.domain.retry import RetryDecisionRecord
from crypto_lab.experiments.ports import UnitOfWork

__all__ = [
    "ApplicationQueryPort",
    "ApplicationTransactionPort",
    "CommandExecutionPort",
    "DurableWorkInventory",
    "ExecutedCommand",
    "RequeueAssessment",
    "RequeueAssessmentPort",
]


def _require_ascending(kind: str, identities: tuple[str, ...]) -> None:
    """Canonical order: strictly ascending, which also rules out a duplicate."""
    if identities != tuple(sorted(set(identities))):
        raise ValueError(f"{kind} must be in strictly ascending identity order")


class DurableWorkInventory(CanonicalModel):
    """One complete, detached projection of durable work (Matrix B row B11)."""

    experiments: tuple[ExperimentRecord, ...]
    engine_runs: tuple[EngineRunRecord, ...]
    command_invocations: tuple[CommandInvocationRecord, ...]
    retry_decisions: tuple[RetryDecisionRecord, ...]

    @model_validator(mode="after")
    def validate_population(self) -> Self:
        experiment_ids = tuple(record.experiment_id for record in self.experiments)
        run_ids = tuple(record.run_id for record in self.engine_runs)
        _require_ascending("experiments", experiment_ids)
        _require_ascending("engine runs", run_ids)
        _require_ascending(
            "command invocations",
            tuple(record.invocation_id for record in self.command_invocations),
        )
        _require_ascending(
            "retry decisions",
            tuple(record.predecessor_run_id for record in self.retry_decisions),
        )
        known_experiments = frozenset(experiment_ids)
        known_runs = frozenset(run_ids)
        for run in self.engine_runs:
            if run.experiment_id not in known_experiments:
                raise ValueError(
                    f"engine run {run.run_id} names unknown experiment "
                    f"{run.experiment_id}"
                )
        for invocation in self.command_invocations:
            run_id: object = invocation.run_id
            if isinstance(run_id, str) and run_id not in known_runs:
                raise ValueError(
                    f"command invocation {invocation.invocation_id} names unknown "
                    f"run {run_id}"
                )
        for decision in self.retry_decisions:
            if decision.predecessor_run_id not in known_runs:
                raise ValueError(
                    "retry decision names unknown predecessor run "
                    f"{decision.predecessor_run_id}"
                )
        return self


class RequeueAssessment(CanonicalModel):
    """Which logical slots may be queued again and which stay fenced (B16)."""

    eligible_slots: tuple[LogicalSlotId, ...]
    fenced_slots: tuple[LogicalSlotId, ...]

    @model_validator(mode="after")
    def validate_partition(self) -> Self:
        _require_ascending("eligible slots", self.eligible_slots)
        _require_ascending("fenced slots", self.fenced_slots)
        overlap = sorted(set(self.eligible_slots) & set(self.fenced_slots))
        if overlap:
            raise ValueError(f"slot {overlap[0]} is both eligible and fenced")
        return self


class ExecutedCommand(CanonicalModel):
    """One supervised command outcome as existing adapter facts (D06)."""

    command_result: CommandResult
    output_parse: (  # type: ignore[valid-type]
        DescriptorParse | ValidationResultParse | ManifestParse | MISSING
    ) = MISSING
    protocol_summary: ProtocolEventSummary


@runtime_checkable
class ApplicationQueryPort(Protocol):
    """Detached read-only queries over durable work; implemented by persistence."""

    def work_inventory(self) -> Result[DurableWorkInventory]:
        """Read the complete inventory in one short read-only session; a failed or
        malformed read is a ``Failure``, never an empty inventory."""


@runtime_checkable
class RequeueAssessmentPort(Protocol):
    """Decide requeue eligibility from an inventory without launching anything."""

    def assess_requeue(
        self, inventory: DurableWorkInventory
    ) -> Result[RequeueAssessment]:
        """Partition the inventory's slots into eligible and fenced work."""


@runtime_checkable
class CommandExecutionPort(Protocol):
    """Execute one adapter command; implemented by the CLI execution bridge."""

    async def execute(
        self, command: AdapterCommand, cancellation: CancellationToken
    ) -> Result[ExecutedCommand]:
        """Run ``command`` to its outcome; no database transaction spans the call."""


@runtime_checkable
class ApplicationTransactionPort(Protocol):
    """The source of short application transactions (D05)."""

    def unit_of_work(self) -> UnitOfWork:
        """Return the root unit of work application services begin on; each
        transaction stays short and never spans process, hashing or file work."""
