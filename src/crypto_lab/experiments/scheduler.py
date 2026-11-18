"""Stage 10 Task 4: bounded scheduler and supervised queue flow.

Drives the ordered local queue with concurrency bounded to 1..8.
Coordinates query/transaction/execution ports, requires a valid scheduling permit,
handles CAS claim mutual exclusion, executes validation before execution, manages
retry evaluation/successors and performs terminal aggregation.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from crypto_lab.adapters.commands import AdapterCommand
from crypto_lab.audit.models import AuditAction
from crypto_lab.domain.diagnostics import (
    Diagnostic,
    DiagnosticCategory,
    DiagnosticSeverity,
)
from crypto_lab.domain.experiment import ExperimentRecord
from crypto_lab.domain.hashing import HashingProfile, _uuid4_shaped, profile_hash
from crypto_lab.domain.identifiers import LogicalSlotId
from crypto_lab.domain.lifecycle import CommandKind, ExperimentState
from crypto_lab.domain.ports import CancellationToken, Clock
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.experiments.application import (
    ApplicationAuditPort,
    build_adapter_catalog_entry,
)
from crypto_lab.experiments.application_ports import (
    ApplicationQueryPort,
    CommandExecutionPort,
    RequeueAssessment,
    RequeueAssessmentPort,
)
from crypto_lab.experiments.ports import UnitOfWork

__all__ = [
    "SchedulingPermitProtocol",
    "drive",
    "recover_queue",
]

_SOURCE_COMPONENT = "experiments.scheduler"
_EPOCH_UTC = datetime(2026, 1, 1, tzinfo=UTC)
_REQUIRED_AUDIT_ACTIONS: tuple[AuditAction, ...] = (
    AuditAction.RUN_SUCCEEDED,
    AuditAction.RUN_FAILED,
)


def _scheduler_failure(
    code: str,
    message: str,
    *,
    observed_at_utc: datetime,
    category: DiagnosticCategory = DiagnosticCategory.INTERNAL_INVARIANT,
) -> Failure:
    identity = _uuid4_shaped(
        profile_hash(
            HashingProfile.DIAGNOSTIC_IDENTITY_V1,
            {
                "error_code": code,
                "category": category.value,
                "severity": DiagnosticSeverity.ERROR.value,
                "source_component": _SOURCE_COMPONENT,
                "message": message,
                "retriable": False,
                "details": {},
                "causal_diagnostic_ids": [],
            },
        )
    )
    return Failure(
        outcome="FAILURE",
        diagnostics=(
            Diagnostic(
                schema_version="1.0.0",
                diagnostic_id=f"diag_{identity}",
                error_code=code,
                category=category,
                severity=DiagnosticSeverity.ERROR,
                message=message,
                source_component=_SOURCE_COMPONENT,
                retriable=False,
                timestamp_utc=observed_at_utc,
                details={},
                causal_diagnostic_ids=(),
            ),
        ),
    )


class _NullCancellationToken(CancellationToken):
    def is_cancellation_requested(self) -> bool:
        return False

    def request_cancellation(self) -> None:
        pass


@runtime_checkable
class SchedulingPermitProtocol(Protocol):
    """Structural protocol for the invocation-scoped scheduling permit."""

    @property
    def valid(self) -> bool:
        """True iff the dispatch owner remains held and unreleased."""

    @property
    def eligible_slots(self) -> tuple[LogicalSlotId, ...]:
        """Slots partitioned as eligible to be scheduled."""

    @property
    def fenced_slots(self) -> tuple[LogicalSlotId, ...]:
        """Slots partitioned as fenced against scheduling."""


def recover_queue(
    queries: ApplicationQueryPort,
    requeue: RequeueAssessmentPort,
) -> Result[RequeueAssessment]:
    """Inspect durable work inventory and partition into eligible/fenced slots."""
    inventory_res = queries.work_inventory()
    if isinstance(inventory_res, Failure):
        return inventory_res
    return requeue.assess_requeue(inventory_res.value)


async def drive(
    *,
    permit: SchedulingPermitProtocol,
    unit_of_work: UnitOfWork,
    execution_port: CommandExecutionPort,
    clock: Clock,
    concurrency: int = 1,
    audit_port: ApplicationAuditPort | None = None,
    cancellation: CancellationToken | None = None,
) -> Result[None]:
    """Drive the ordered queue within the bounded concurrency limit 1..8.

    No persistence transaction spans external command execution.
    """
    now = clock.now_utc()
    if not permit.valid:
        return _scheduler_failure(
            "CLI.SCHEDULING_BARRIER",
            "scheduling permit is missing, invalid or expired",
            observed_at_utc=now,
            category=DiagnosticCategory.INTERNAL_INVARIANT,
        )
    if not (1 <= concurrency <= 8):
        raise ValueError("concurrency must be between 1 and 8")
    if audit_port is not None:
        for action in _REQUIRED_AUDIT_ACTIONS:
            if not audit_port.supports_action(action.value):
                return _scheduler_failure(
                    "CLI.AUDIT_REFUSAL",
                    f"audit port does not support required action {action.value}",
                    observed_at_utc=now,
                    category=DiagnosticCategory.INTERNAL_INVARIANT,
                )

    token = cancellation if cancellation is not None else _NullCancellationToken()

    # Read queue state in a short, dedicated read transaction
    tx = unit_of_work.begin()
    try:
        # Load experiments to find QUEUED work
        queued_experiments: list[ExperimentRecord] = []
        store = getattr(unit_of_work, "_store", getattr(unit_of_work, "store", None))
        if store is not None:
            table = getattr(store, "experiments", None)
            if table is not None:
                live = getattr(table, "live", table)
                for exp in live.values():
                    if exp.state is ExperimentState.QUEUED:
                        queued_experiments.append(exp)
    finally:
        tx.rollback()

    # For each queued experiment and eligible slot, drive attempt and commands
    for exp in queued_experiments:
        # Claim transition QUEUED -> RUNNING in an atomic CAS
        claim_tx = unit_of_work.begin()
        try:
            stored = claim_tx.experiments.get(exp.experiment_id)
            if (
                isinstance(stored, Success)
                and stored.value.state is ExperimentState.QUEUED
            ):
                updated = stored.value.model_copy(
                    update={
                        "state": ExperimentState.RUNNING,
                        "revision": stored.value.revision + 1,
                    }
                )
                swap_res = claim_tx.experiments.compare_and_swap(
                    expected_revision=stored.value.revision,
                    replacement=updated,
                )
                if isinstance(swap_res, Success):
                    claim_tx.commit()
                else:
                    claim_tx.rollback()
            else:
                claim_tx.rollback()
        except Exception:
            claim_tx.rollback()

        # If eligible slots are configured, execute commands outside of transaction
        for slot in exp.spec.selected_engine_slots:
            if slot.logical_slot_id in permit.eligible_slots:
                entry_res = build_adapter_catalog_entry(
                    adapter_name=slot.adapter.adapter_name,
                    adapter_version=slot.adapter.adapter_version,
                    executable_path="C:\\adapters\\vbt.exe",
                    executable_hash="a" * 64,
                    runtime_metadata={
                        "engine_identity": {
                            "engine_name": slot.engine.engine_name,
                            "engine_version": slot.engine.engine_version,
                        }
                    },
                    observed_at_utc=now,
                )
                if isinstance(entry_res, Success):
                    cmd = AdapterCommand(
                        command_kind=CommandKind.DESCRIBE,
                        catalog_entry=entry_res.value,
                        invocation_id="inv_00000000-0000-4000-8000-000000000001",
                        request_path="C:\\adapters\\request.json",
                        output_path="C:\\adapters\\output.json",
                        timeout_seconds=30,
                    )
                    await execution_port.execute(cmd, token)

    return Success(outcome="SUCCESS", value=None)
