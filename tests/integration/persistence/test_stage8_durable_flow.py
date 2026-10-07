"""The two-slot application flow over the durable repositories (Task 7, plan 7.1.1).

Every step is a real Stage 5 operation over ``SqliteUnitOfWork`` under the Task 6
``CountingUnitOfWork``: the experiment is created, validated, frozen and queued
through ``queue_experiment`` (reading 22), the two attempts are created, slot B
ends ``NOT_APPLICABLE`` without a retry decision, slot A fails, is allowed one
successor after the durable delay, the successor fails and is denied on its own
budget, and the real ``aggregate_experiment`` decides ``FAILED`` once and replays
it without a write. Every durable assertion is a fresh read of the SQLite file
through the flow; no in-memory store, unit of work or seeding recorder exists in
this module or in ``DurableFlow``.

Two negative controls bound the classifier: an unevaluated ``FAILED`` slot keeps
the experiment ``RUNNING`` (``NOT_YET_TERMINAL``, no write), and the unchanged
``ApplicationConfig()`` denies the very successor ``retrying_config()`` admits.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Final

from crypto_lab.configuration.models import ApplicationConfig
from crypto_lab.configuration.snapshot import snapshot_configuration
from crypto_lab.domain.aggregation import (
    REASON_SLOT_FAILED,
    AggregationVerdict,
    SlotRetryStatus,
)
from crypto_lab.domain.engine_run import SUCCESS_ENGINE_RUN_STATES
from crypto_lab.domain.lifecycle import EngineRunState, ExperimentState
from crypto_lab.domain.retry import (
    RetryDecisionOutcome,
    RetryDenialReason,
    RetryGate,
    recorded_denial_reason,
)
from crypto_lab.experiments.diagnostics import RETRY_NOT_BEFORE_NOT_REACHED
from doubles.experiments import SLOT_A, SLOT_B
from persistence_support.fixtures import retrying_config
from persistence_support.harness import DurableFlow
from persistence_support.harness import code as _code
from persistence_support.harness import ok as _ok

_E: Final = ExperimentState
_R: Final = EngineRunState


def test_the_two_slot_flow_over_sqlite_aggregates_to_failed(tmp_path: Path) -> None:
    flow = DurableFlow.open(tmp_path, config=retrying_config())
    try:
        flow.register_strategy_and_dataset()
        # create_experiment receives config_backed_draft(flow.config) and
        # material_base_configuration_hash(flow.config); the flow freezes
        # snapshot_configuration(flow.config) while VALIDATED and only then calls
        # queue_experiment with the same hash and derived policy (reading 22).
        flow.create_validate_and_queue_experiment()
        assert flow.frozen_snapshot() == snapshot_configuration(flow.config)
        flow.create_attempts_for_every_slot()  # RUNNING at revision 4
        # Slot B: its VALIDATE invocation exits 20 and the run leaves VALIDATING
        # as NOT_APPLICABLE with a COMPATIBILITY primary (OTHER_DIAG_ID);
        # NOT_APPLICABLE maps to no retry state, so the slot needs no decision.
        run_b = flow.drive_first_attempt_to_not_applicable(SLOT_B)
        assert run_b.state is _R.NOT_APPLICABLE
        # Slot A: READY, launched, RUNNING, then FAILED with a retriable primary
        # (DIAG_ID) recorded before the transition.
        run_a = flow.drive_first_attempt_to_failed(SLOT_A)
        decision = flow.evaluate_retry(run_a)
        assert decision.outcome is RetryDecisionOutcome.ALLOWED
        assert decision.reserved_successor_attempt_number == 2
        assert decision.retry_not_before_utc == run_a.updated_at_utc + timedelta(
            seconds=30
        )
        assert _code(flow.create_successor(run_a)) == RETRY_NOT_BEFORE_NOT_REACHED
        flow.advance_clock_to(decision.retry_not_before_utc)
        successor = _ok(flow.create_successor(run_a))
        assert (successor.attempt_number, successor.predecessor_run_id) == (
            2,
            run_a.run_id,
        )
        failed_successor = flow.drive_run_to_failed(successor)  # THIRD_DIAG_ID
        exhausted = flow.evaluate_retry(failed_successor)
        assert exhausted.outcome is RetryDecisionOutcome.DENIED
        assert exhausted.denial_reason is RetryDenialReason.ATTEMPT_BUDGET_EXHAUSTED
        # The successor's own row decides; the predecessor's ALLOWED row is history.
        assert exhausted.predecessor_run_id == failed_successor.run_id
        assert flow.retry_decision(run_a).outcome is RetryDecisionOutcome.ALLOWED
        assert flow.slot_retry_statuses() == {
            SLOT_A: SlotRetryStatus.DENIED,
            SLOT_B: SlotRetryStatus.NO_DECISION_REQUIRED,
        }
        before = flow.experiment()
        assert (before.state, before.revision) == (_E.RUNNING, 6)
        result = flow.aggregate()  # the real aggregate_experiment
        assert (result.verdict, result.reason_codes) == (
            AggregationVerdict.FAILED,
            (REASON_SLOT_FAILED,),
        )
        after = flow.experiment()
        assert (after.state, after.revision) == (_E.FAILED, 7)
        replay = flow.aggregate()  # terminal replay: verdict only, no write
        assert (replay.verdict, replay.reason_codes) == (AggregationVerdict.FAILED, ())
        assert flow.experiment() == after
        report = flow.consistency_report()
        assert report.dangling_diagnostic_references == 0
        assert report.queued_without_snapshot == 0
        assert (report.causal_edge_mismatches, report.unresolved_causal_references) == (
            0,
            0,
        )
        assert flow.frozen_snapshot() == snapshot_configuration(flow.config)
        assert flow.run_states().isdisjoint(SUCCESS_ENGINE_RUN_STATES)
        # Plan 7.1.2's transaction rule holds for the durable flow too: every
        # operation and flow-owned write ran in its own transaction, one at a time.
        assert (flow.max_open, flow.open_now) == (1, 0)
    finally:
        flow.close()


def test_an_unresolved_failed_slot_keeps_the_experiment_running(
    tmp_path: Path,
) -> None:
    # Negative control for the classifier boundary: slot B ends FAILED and is
    # never evaluated, so its status is DECISION_UNRESOLVED (Row 3) and the real
    # aggregate_experiment returns NOT_YET_TERMINAL without writing.
    flow = DurableFlow.open(tmp_path, config=retrying_config())
    try:
        flow.register_strategy_and_dataset()
        flow.create_validate_and_queue_experiment()
        flow.create_attempts_for_every_slot()
        flow.drive_first_attempt_to_failed(SLOT_B)  # OTHER_DIAG_ID; no evaluate_retry
        run_a = flow.drive_first_attempt_to_failed(SLOT_A)
        decision = flow.evaluate_retry(run_a)
        flow.advance_clock_to(decision.retry_not_before_utc)
        failed_successor = flow.drive_run_to_failed(_ok(flow.create_successor(run_a)))
        assert (
            flow.evaluate_retry(failed_successor).outcome is RetryDecisionOutcome.DENIED
        )
        assert flow.slot_retry_statuses()[SLOT_B] is SlotRetryStatus.DECISION_UNRESOLVED
        before = flow.experiment()
        result = flow.aggregate()
        assert (result.verdict, result.reason_codes) == (
            AggregationVerdict.NOT_YET_TERMINAL,
            (),
        )
        assert flow.experiment() == before  # RUNNING at the same revision
    finally:
        flow.close()


def test_the_default_retry_configuration_denies_the_automatic_successor(
    tmp_path: Path,
) -> None:
    # Negative control (plan 7.1.1): ApplicationConfig() is unchanged and its
    # policy (one attempt, no retry states) denies the very successor the flow
    # above reaches under retrying_config(); the denial comes from the policy gates.
    flow = DurableFlow.open(tmp_path, config=ApplicationConfig())
    try:
        flow.register_strategy_and_dataset()
        flow.create_validate_and_queue_experiment()
        flow.create_attempts_for_every_slot()
        run_a = flow.drive_first_attempt_to_failed(SLOT_A)
        decision = flow.evaluate_retry(run_a)
        assert decision.outcome is RetryDecisionOutcome.DENIED
        assert decision.denial_reason is recorded_denial_reason(
            (RetryGate.ATTEMPT_BUDGET, RetryGate.TERMINAL_STATE)
        )
        assert flow.attempt_count(SLOT_A) == 1
    finally:
        flow.close()
