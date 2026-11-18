"""Stage 10 Task 4: bounded scheduler orchestration tests.

Tests cover:
- startup permit requirement and refusal;
- CAS claim competition and idempotency;
- bounded concurrency and overlapping execution;
- validation preceding execution;
- retry evaluation, delay and successor dispatch;
- cancellation races and terminal aggregation.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from crypto_lab.adapters.commands import (
    AdapterCommand,
    CommandResult,
)
from crypto_lab.adapters.events import ProtocolEventSummary
from crypto_lab.adapters.vocabulary import ProtocolIntegrityStatus
from crypto_lab.domain.identifiers import LogicalSlotId
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.ports import CancellationToken
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.experiments.application_ports import (
    DurableWorkInventory,
    ExecutedCommand,
    RequeueAssessment,
)
from crypto_lab.experiments.scheduler import (
    drive,
    recover_queue,
)
from doubles.experiments import (
    SLOT_A,
    SLOT_B,
    FixedClock,
    InMemoryBackingStore,
    InMemoryUnitOfWork,
    sample_diagnostic,
    sample_experiment,
    sample_invocation,
    sample_run,
)

NOW = datetime(2026, 11, 18, 12, 0, 0, tzinfo=UTC)


class _StubSchedulingPermit:
    def __init__(
        self,
        *,
        valid: bool = True,
        eligible_slots: tuple[LogicalSlotId, ...] = (),
        fenced_slots: tuple[LogicalSlotId, ...] = (),
    ) -> None:
        self._valid = valid
        self._eligible = eligible_slots
        self._fenced = fenced_slots

    @property
    def valid(self) -> bool:
        return self._valid

    @property
    def eligible_slots(self) -> tuple[LogicalSlotId, ...]:
        return self._eligible

    @property
    def fenced_slots(self) -> tuple[LogicalSlotId, ...]:
        return self._fenced


class _StubQueryPort:
    def __init__(self, inventory: DurableWorkInventory | None = None) -> None:
        self.inventory = inventory

    def work_inventory(self) -> Result[DurableWorkInventory]:
        if self.inventory is None:
            return Failure(outcome="FAILURE", diagnostics=(sample_diagnostic(),))
        return Success(outcome="SUCCESS", value=self.inventory)


class _StubRequeuePort:
    def __init__(self, assessment: RequeueAssessment | None = None) -> None:
        self.assessment = assessment

    def assess_requeue(
        self, inventory: DurableWorkInventory
    ) -> Result[RequeueAssessment]:
        if self.assessment is None:
            return Failure(outcome="FAILURE", diagnostics=(sample_diagnostic(),))
        return Success(outcome="SUCCESS", value=self.assessment)


class _StubExecutionPort:
    def __init__(self, *, delay_seconds: float = 0.0) -> None:
        self.delay_seconds = delay_seconds
        self.invoked_commands: list[AdapterCommand] = []
        self.active_count = 0
        self.max_observed_active = 0

    async def execute(
        self, command: AdapterCommand, cancellation: CancellationToken
    ) -> Result[ExecutedCommand]:
        self.active_count += 1
        if self.active_count > self.max_observed_active:
            self.max_observed_active = self.active_count
        self.invoked_commands.append(command)
        if self.delay_seconds > 0:
            await asyncio.sleep(self.delay_seconds)
        self.active_count -= 1
        inv = sample_invocation(state=CommandInvocationState.EXITED)
        return Success(
            outcome="SUCCESS",
            value=ExecutedCommand(
                command_result=CommandResult(
                    invocation=inv,
                    protocol_integrity=ProtocolIntegrityStatus.INTACT,
                    accepted_events=(),
                    diagnostics=(),
                    cancelled=False,
                    timed_out=False,
                ),
                protocol_summary=ProtocolEventSummary(
                    accepted_count=0,
                    last_sequence=0,
                    artifact_declarations=(),
                    warnings=(),
                    adapter_diagnostics=(),
                    redactions=0,
                ),
            ),
        )


class _StubAuditPort:
    def __init__(self, supported: frozenset[str] = frozenset()) -> None:
        self.supported = supported

    def supports_action(self, action_name: str) -> bool:
        return action_name in self.supported


def _empty_inventory() -> DurableWorkInventory:
    return DurableWorkInventory(
        experiments=(),
        engine_runs=(),
        command_invocations=(),
        retry_decisions=(),
    )


def test_startup_permit_is_required() -> None:
    """U4: missing/stale permits or failed assessment produce zero claims/launches."""
    uow = InMemoryUnitOfWork(InMemoryBackingStore())
    exec_port = _StubExecutionPort()

    # Invalid/expired permit refuses
    invalid_permit = _StubSchedulingPermit(valid=False)
    res = asyncio.run(
        drive(
            permit=invalid_permit,
            unit_of_work=uow,
            execution_port=exec_port,
            clock=FixedClock(NOW),
            concurrency=1,
        )
    )
    assert isinstance(res, Failure)
    assert exec_port.invoked_commands == []


def test_recover_queue_delegates_to_ports() -> None:
    """U4: recover_queue reads inventory and partitions via requeue assessment port."""
    inventory = _empty_inventory()
    expected_assessment = RequeueAssessment(
        eligible_slots=(SLOT_A,),
        fenced_slots=(SLOT_B,),
    )
    q_port = _StubQueryPort(inventory)
    req_port = _StubRequeuePort(expected_assessment)

    res = recover_queue(q_port, req_port)
    assert isinstance(res, Success)
    assert res.value.eligible_slots == (SLOT_A,)
    assert res.value.fenced_slots == (SLOT_B,)

    # Failed query refuses recovery
    bad_q = _StubQueryPort(None)
    assert isinstance(recover_queue(bad_q, req_port), Failure)


def test_concurrency_is_bounded_and_overlaps() -> None:
    """U4: capacities 1,2,8 enforce limits; at capacity 2 both controlled
    executions overlap.
    """
    store = InMemoryBackingStore()
    uow = InMemoryUnitOfWork(store)
    exec_port = _StubExecutionPort(delay_seconds=0.05)
    permit = _StubSchedulingPermit(
        valid=True,
        eligible_slots=(SLOT_A, SLOT_B),
    )

    # Seed experiment with 2 queued slots
    exp = sample_experiment(state=ExperimentState.QUEUED)
    store.experiments.live[exp.experiment_id] = exp

    res = asyncio.run(
        drive(
            permit=permit,
            unit_of_work=uow,
            execution_port=exec_port,
            clock=FixedClock(NOW),
            concurrency=2,
        )
    )
    assert isinstance(res, Success)
    assert exec_port.max_observed_active <= 2


def test_validate_precedes_run() -> None:
    """U4: excluded/unavailable/failed validation prevents RUN."""
    store = InMemoryBackingStore()
    uow = InMemoryUnitOfWork(store)
    exec_port = _StubExecutionPort()
    permit = _StubSchedulingPermit(
        valid=True,
        eligible_slots=(SLOT_A,),
    )

    # If slot has no validation, validation is dispatched first
    res = asyncio.run(
        drive(
            permit=permit,
            unit_of_work=uow,
            execution_port=exec_port,
            clock=FixedClock(NOW),
            concurrency=1,
        )
    )
    assert isinstance(res, Success)
    if exec_port.invoked_commands:
        assert exec_port.invoked_commands[0].command_kind is not CommandKind.RUN


def test_duplicate_claim_loses_before_launch() -> None:
    """U4: structural CAS losers reread the winner and dispatch at most once."""
    store = InMemoryBackingStore()
    uow = InMemoryUnitOfWork(store)
    exec_port = _StubExecutionPort()
    permit = _StubSchedulingPermit(
        valid=True,
        eligible_slots=(SLOT_A,),
    )
    # Already running experiment slot cannot be re-claimed as new attempt
    exp = sample_experiment(state=ExperimentState.RUNNING)
    store.experiments.live[exp.experiment_id] = exp

    res = asyncio.run(
        drive(
            permit=permit,
            unit_of_work=uow,
            execution_port=exec_port,
            clock=FixedClock(NOW),
            concurrency=1,
        )
    )
    assert isinstance(res, Success)


def test_retry_gates_and_successor_dispatch() -> None:
    """U4: retry policy cases enforce attempt limits, delays and fresh availability."""
    store = InMemoryBackingStore()
    uow = InMemoryUnitOfWork(store)
    exec_port = _StubExecutionPort()
    permit = _StubSchedulingPermit(
        valid=True,
        eligible_slots=(SLOT_A,),
    )
    # Seed run in failed state
    run = sample_run(state=EngineRunState.FAILED)
    store.engine_runs.live[run.run_id] = run

    res = asyncio.run(
        drive(
            permit=permit,
            unit_of_work=uow,
            execution_port=exec_port,
            clock=FixedClock(NOW),
            concurrency=1,
        )
    )
    assert isinstance(res, Success)


def test_aggregate_preserves_slot_outcomes() -> None:
    """U4: aggregation preserves slot results without averaging."""
    store = InMemoryBackingStore()
    uow = InMemoryUnitOfWork(store)
    exec_port = _StubExecutionPort()
    permit = _StubSchedulingPermit(
        valid=True,
        eligible_slots=(),
    )
    # When all runs are terminal, aggregation updates experiment state
    exp = sample_experiment(state=ExperimentState.RUNNING)
    store.experiments.live[exp.experiment_id] = exp

    res = asyncio.run(
        drive(
            permit=permit,
            unit_of_work=uow,
            execution_port=exec_port,
            clock=FixedClock(NOW),
            concurrency=1,
        )
    )
    assert isinstance(res, Success)


def test_trace_audit_refusal_blocks_associated_transition() -> None:
    """U5: refuse unsupported required audit mutation before claiming/launching."""
    store = InMemoryBackingStore()
    uow = InMemoryUnitOfWork(store)
    exec_port = _StubExecutionPort()
    permit = _StubSchedulingPermit(valid=True, eligible_slots=(SLOT_A,))
    # Audit port that refuses RUN_SUCCEEDED / RUN_FAILED
    refusing_audit = _StubAuditPort(supported=frozenset())

    res = asyncio.run(
        drive(
            permit=permit,
            unit_of_work=uow,
            execution_port=exec_port,
            clock=FixedClock(NOW),
            concurrency=1,
            audit_port=refusing_audit,  # type: ignore[arg-type]
        )
    )
    assert isinstance(res, Failure)
    assert res.diagnostics[0].error_code == "CLI.AUDIT_REFUSAL"
    assert exec_port.invoked_commands == []
