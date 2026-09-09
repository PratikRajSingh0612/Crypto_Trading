"""Stage 5 Task 9: the callable end-to-end in-memory application flow.

One scenario over the in-memory ports (plan Task 9, "Callable Stage 5 integration
flow"; acceptance criterion 17) with three selected slots whose frozen
``slot_compatibility`` is ``SUPPORTED``, ``SUPPORTED``, ``NOT_APPLICABLE``. Every
operation is the committed application service driven through the ROOT in-memory
unit of work; the test seeds only the one diagnostic the retry evaluation reads and
inspects the backing store's committed rows, so a rejected or losing operation is
proven to write nothing. No engine, adapter or process is executed anywhere: the
terminal results are injected as core decisions through ``transition_run``, and
the process facts are the caller-supplied launch-handoff material of plan 3.7.

Declared readings of the plan sentence, so nothing is inferred silently:

- Before each injected run terminal, the run's ``RUN`` invocation is terminalized
  ``RUNNING -> EXITED`` through ``transition_invocation`` (native exit ``40`` for
  the failing attempt, ``0`` otherwise), so no durable pair of plan section 6's
  "mixed running" kind ever exists; ``EXITED`` couples no run transition.
- The retriable primary diagnostic is seeded with the DRAWN identities (the created
  experiment, attempt 1 of slot A and its ``RUN`` invocation), because the retry
  snapshot requires the diagnostic's correlation to match the predecessor.
- "Contend cancellation, retry and aggregation on one experiment revision" is
  driven with the double's one-shot compare-and-swap hook: cancellation runs through
  the hooked root, terminal aggregation commits inside the hook through a separate
  root, and retry evaluation at the same revision is a plan 8.4 phase-1 replay that
  reads no clock. Exactly one write happens. The verdict and reason codes are
  asserted on the winning aggregation's own result -- the only call that ever
  carries reason codes; every later aggregation replays the terminal verdict with
  none (plan 9.4).
- "Cancellation idempotent" after the rebuild is the plan 9.5 row 1 / 9.1 step 3
  loser contract holding across a service rebuild: the same
  ``CORE.INVARIANT_VIOLATION`` code and no write. The plan 9.1 step 2
  correlation-identity replay is unreachable in this scenario, because aggregation
  must win for any reason code to exist; ``tests/unit/experiments/
  test_cancellation_races.py`` covers it (criterion 14).
- Failure values are compared by error code, never by value: the rebuilt clock
  stamps a different instant.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Final

from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.domain.aggregation import (
    REASON_SLOT_SUCCEEDED_WITH_WARNINGS,
    AggregationVerdict,
    ExperimentAggregationInput,
    ExperimentAggregationResult,
    SlotRetryStatus,
    classify_experiment_outcome,
    effective_terminal_state,
    is_late_not_applicable,
    slot_reason_codes,
)
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.compatibility import CompatibilityOutcome
from crypto_lab.domain.engine_run import EngineRunRecord
from crypto_lab.domain.experiment import (
    AdapterIdentity,
    EngineIdentity,
    ExperimentRecord,
    SelectedEngineSlot,
)
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
    RetryTerminalState,
)
from crypto_lab.domain.ports import Clock
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.domain.retry import RetryDecisionOutcome, RetryDecisionRecord
from crypto_lab.experiments.aggregation import (
    aggregate_experiment,
    build_aggregation_input,
)
from crypto_lab.experiments.diagnostics import (
    INVARIANT_VIOLATION,
    RETRY_NOT_BEFORE_NOT_REACHED,
)
from crypto_lab.experiments.experiment_service import (
    cancel_experiment,
    create_experiment,
    queue_experiment,
    transition_experiment,
)
from crypto_lab.experiments.invocation_service import (
    begin_linked_launch,
    create_invocation,
    start_linked_run,
    transition_invocation,
)
from crypto_lab.experiments.requests import (
    AttemptCreationRequest,
    CancelExperimentRequest,
    ExperimentAggregationRequest,
    ExperimentCreationRequest,
    ExperimentQueueRequest,
    ExperimentTransitionRequest,
    InvocationCreationRequest,
    InvocationTransitionRequest,
    LinkedLaunchRequest,
    LinkedStartRequest,
    RetryEvaluationRequest,
    RunTransitionRequest,
    SuccessorCreationRequest,
)
from crypto_lab.experiments.retry import create_successor, evaluate_retry
from crypto_lab.experiments.run_service import (
    AttemptCreation,
    create_attempt,
    transition_run,
)
from doubles.experiments import (
    ADAPTER_ALPHA,
    ADAPTER_BETA,
    AVAIL_A,
    AVAIL_B,
    DIAG_ID,
    ENGINE_ALPHA,
    ENGINE_BETA,
    INSTANT,
    MATERIAL_HASH,
    OTHER_REQUEST_HASH,
    REQUEST_HASH,
    SLOT_A,
    SLOT_B,
    SLOT_C,
    FailingClock,
    FixedClock,
    InMemoryBackingStore,
    InMemoryUnitOfWork,
    SequentialIdentitySource,
    sample_diagnostic,
    sample_draft,
    sample_process_start,
    sample_slot_compatibility,
    sample_slots,
)

_E = ExperimentState
_R = EngineRunState
_C = CommandInvocationState

#: A stable namespaced label for every transition the flow asks for (plan 3.11).
REASON: Final = "FLOW.STEP"
#: The third slot's distinct adapter/engine pair (plan 3.5 uniqueness rule).
ADAPTER_GAMMA: Final = AdapterIdentity(
    adapter_name="adapter.gamma", adapter_version="3.0.0"
)
ENGINE_GAMMA: Final = EngineIdentity(engine_name="engine.gamma", engine_version="1.0.0")
VALIDATE_TIMEOUT: Final = 600
RUN_TIMEOUT: Final = 3600
#: The correlation identity of the cancellation that loses the race.
CANCEL: Final = "operator-cancel"
#: The sample policy allows three attempts with a thirty-second delay.
RETRY_DELAY: Final = timedelta(seconds=30)


def _missing(value: object) -> bool:
    return value is MISSING


def _ok[T](result: Result[T]) -> T:
    assert isinstance(result, Success), result
    return result.value


def _code(result: object) -> str:
    assert isinstance(result, Failure), result
    assert len(result.diagnostics) == 1
    return result.diagnostics[0].error_code


def _bytes(*records: object) -> tuple[bytes, ...]:
    return tuple(canonical_json_bytes(record) for record in records)


class CountingIdentitySource(SequentialIdentitySource):
    """Counts every draw, so a replay can be proven to draw nothing (plan 8.5)."""

    def __init__(self, seed: str) -> None:
        super().__init__(seed)
        self.draws = 0

    def new_run_id(self) -> str:
        self.draws += 1
        return super().new_run_id()

    def new_attempt_token(self) -> str:
        self.draws += 1
        return super().new_attempt_token()


@dataclass(slots=True)
class Services:
    """One composition of the Stage 5 services over one store, clock and identity.

    The test rebuilds this over the same store to prove restart idempotency; the
    root unit of work is created per composition because the services call
    ``begin()`` themselves.
    """

    store: InMemoryBackingStore
    clock: FixedClock
    identity: CountingIdentitySource

    @property
    def root(self) -> InMemoryUnitOfWork:
        return InMemoryUnitOfWork(self.store)

    # -- experiment -------------------------------------------------------------

    def create(self, draft_slots: tuple[SelectedEngineSlot, ...]) -> ExperimentRecord:
        request = ExperimentCreationRequest(
            schema_version="1.0.0",
            spec_draft=sample_draft(selected_engine_slots=draft_slots),
            material_base_configuration_hash=MATERIAL_HASH,
        )
        return _ok(
            create_experiment(
                request,
                unit_of_work=self.root,
                clock=self.clock,
                identity_source=self.identity,
            )
        )

    def transition(
        self, experiment: ExperimentRecord, target: ExperimentState
    ) -> ExperimentRecord:
        request = ExperimentTransitionRequest(
            schema_version="1.0.0",
            experiment_id=experiment.experiment_id,
            expected_revision=experiment.revision,
            target_state=target,
            reason_code=REASON,
        )
        return _ok(
            transition_experiment(request, unit_of_work=self.root, clock=self.clock)
        )

    def queue(self, experiment: ExperimentRecord) -> ExperimentRecord:
        draft = sample_draft(
            selected_engine_slots=experiment.spec.selected_engine_slots
        )
        request = ExperimentQueueRequest(
            schema_version="1.0.0",
            experiment_id=experiment.experiment_id,
            expected_revision=experiment.revision,
            config_derived_retry_policy=experiment.spec.retry_policy,
            material_base_configuration_hash=MATERIAL_HASH,
            slot_compatibility=sample_slot_compatibility(
                draft, outcomes={SLOT_C: CompatibilityOutcome.NOT_APPLICABLE}
            ),
        )
        return _ok(queue_experiment(request, unit_of_work=self.root, clock=self.clock))

    def cancel(self, experiment_id: str, revision: int) -> Result[ExperimentRecord]:
        request = CancelExperimentRequest(
            schema_version="1.0.0",
            experiment_id=experiment_id,
            expected_revision=revision,
            correlation_id=CANCEL,
        )
        return cancel_experiment(request, unit_of_work=self.root, clock=self.clock)

    def aggregate(
        self, experiment_id: str, revision: int, *, clock: Clock | None = None
    ) -> Result[ExperimentAggregationResult]:
        request = ExperimentAggregationRequest(
            schema_version="1.0.0",
            experiment_id=experiment_id,
            expected_revision=revision,
        )
        return aggregate_experiment(
            request,
            unit_of_work=self.root,
            clock=self.clock if clock is None else clock,
        )

    def aggregation_input(self, experiment_id: str) -> ExperimentAggregationInput:
        """Plan 9.2's authoritative read set, via a transaction of the test's own."""
        transaction = self.root.begin()
        try:
            experiment = _ok(transaction.experiments.get(experiment_id))
            built = build_aggregation_input(
                transaction, experiment, now=self.clock.now_utc()
            )
        finally:
            transaction.rollback()
        assert isinstance(built, ExperimentAggregationInput), built
        return built

    # -- runs -------------------------------------------------------------------

    def attempt(
        self, experiment: ExperimentRecord, slot: str, request_hash: str = REQUEST_HASH
    ) -> Result[AttemptCreation]:
        request = AttemptCreationRequest(
            schema_version="1.0.0",
            experiment_id=experiment.experiment_id,
            logical_slot_id=slot,
            expected_experiment_revision=experiment.revision,
            request_hash=request_hash,
        )
        return create_attempt(
            request,
            unit_of_work=self.root,
            clock=self.clock,
            identity_source=self.identity,
        )

    def move_run(
        self,
        run: EngineRunRecord,
        target: EngineRunState,
        *,
        primary_terminal_diagnostic_id: str | None = None,
        availability_observation_id: str | None = None,
    ) -> EngineRunRecord:
        payload: dict[str, object] = {
            "schema_version": "1.0.0",
            "run_id": run.run_id,
            "expected_revision": run.revision,
            "target_state": target,
            "reason_code": REASON,
        }
        if primary_terminal_diagnostic_id is not None:
            payload["primary_terminal_diagnostic_id"] = primary_terminal_diagnostic_id
        if availability_observation_id is not None:
            payload["availability_observation_id"] = availability_observation_id
        request = RunTransitionRequest.model_validate(payload)
        return _ok(transition_run(request, unit_of_work=self.root, clock=self.clock))

    def evaluate_retry(
        self,
        experiment: ExperimentRecord,
        predecessor: EngineRunRecord,
        *,
        clock: Clock | None = None,
    ) -> Result[RetryDecisionRecord]:
        request = RetryEvaluationRequest(
            schema_version="1.0.0",
            experiment_id=experiment.experiment_id,
            logical_slot_id=predecessor.logical_slot_id,
            predecessor_run_id=predecessor.run_id,
            expected_experiment_revision=experiment.revision,
            expected_predecessor_revision=predecessor.revision,
        )
        return evaluate_retry(
            request,
            unit_of_work=self.root,
            clock=self.clock if clock is None else clock,
        )

    def successor(
        self, experiment: ExperimentRecord, predecessor: EngineRunRecord
    ) -> Result[AttemptCreation]:
        request = SuccessorCreationRequest(
            schema_version="1.0.0",
            experiment_id=experiment.experiment_id,
            logical_slot_id=predecessor.logical_slot_id,
            predecessor_run_id=predecessor.run_id,
            expected_experiment_revision=experiment.revision,
            request_hash=OTHER_REQUEST_HASH,
        )
        return create_successor(
            request,
            unit_of_work=self.root,
            clock=self.clock,
            identity_source=self.identity,
        )

    # -- invocations --------------------------------------------------------------

    def invocation(
        self,
        run: EngineRunRecord,
        kind: CommandKind,
        *,
        request_hash: str,
        timeout_seconds: int,
    ) -> CommandInvocationRecord:
        request = InvocationCreationRequest(
            schema_version="1.0.0",
            command_kind=kind,
            adapter_name=run.adapter.adapter_name,
            adapter_version=run.adapter.adapter_version,
            run_id=run.run_id,
            expected_run_revision=run.revision,
            request_hash=request_hash,
            timeout_seconds=timeout_seconds,
        )
        return _ok(
            create_invocation(
                request,
                unit_of_work=self.root,
                clock=self.clock,
                identity_source=self.identity,
            )
        )

    def move_invocation(
        self,
        invocation: CommandInvocationRecord,
        target: CommandInvocationState,
        *,
        with_process_start: bool = False,
        native_exit_value: int | None = None,
    ) -> CommandInvocationRecord:
        payload: dict[str, object] = {
            "schema_version": "1.0.0",
            "invocation_id": invocation.invocation_id,
            "expected_revision": invocation.revision,
            "target_state": target,
            "reason_code": REASON,
            "diagnostic_ids": (),
        }
        if with_process_start:
            payload["process_start"] = sample_process_start(
                process_started_at_utc=self.clock.now_utc()
            )
        if native_exit_value is not None:
            payload["native_exit_value"] = native_exit_value
        request = InvocationTransitionRequest.model_validate(payload)
        return _ok(
            transition_invocation(request, unit_of_work=self.root, clock=self.clock)
        )

    def launch(
        self, invocation: CommandInvocationRecord, run: EngineRunRecord
    ) -> tuple[CommandInvocationRecord, EngineRunRecord]:
        launched = _ok(
            begin_linked_launch(
                LinkedLaunchRequest(
                    schema_version="1.0.0",
                    invocation_id=invocation.invocation_id,
                    expected_invocation_revision=invocation.revision,
                    run_id=run.run_id,
                    expected_run_revision=run.revision,
                ),
                unit_of_work=self.root,
                clock=self.clock,
            )
        )
        started = _ok(
            start_linked_run(
                LinkedStartRequest(
                    schema_version="1.0.0",
                    invocation_id=launched.invocation.invocation_id,
                    expected_invocation_revision=launched.invocation.revision,
                    run_id=launched.run.run_id,
                    expected_run_revision=launched.run.revision,
                    process_start=sample_process_start(
                        process_started_at_utc=self.clock.now_utc()
                    ),
                ),
                unit_of_work=self.root,
                clock=self.clock,
            )
        )
        return started.invocation, started.run

    # -- composite steps ----------------------------------------------------------

    def validate_and_ready(
        self, run: EngineRunRecord, observation_id: str
    ) -> EngineRunRecord:
        """``PENDING -> VALIDATING``, a ``VALIDATE`` invocation driven to ``EXITED``
        with the run untouched, then ``VALIDATING -> READY``."""
        validating = self.move_run(run, _R.VALIDATING)
        validate = self.invocation(
            validating,
            CommandKind.VALIDATE,
            request_hash=OTHER_REQUEST_HASH,
            timeout_seconds=VALIDATE_TIMEOUT,
        )
        assert validate.state is _C.PENDING
        starting = self.move_invocation(validate, _C.STARTING)
        running = self.move_invocation(starting, _C.RUNNING, with_process_start=True)
        exited = self.move_invocation(running, _C.EXITED, native_exit_value=0)
        assert exited.state is _C.EXITED
        assert exited.process_created is True
        # Plan 6: the VALIDATE handoff leaves the linked run in VALIDATING, untouched.
        stored = self.run(validating.run_id)
        assert stored == validating
        assert stored.state is _R.VALIDATING
        return self.move_run(
            validating, _R.READY, availability_observation_id=observation_id
        )

    def launch_run(
        self, run: EngineRunRecord
    ) -> tuple[CommandInvocationRecord, EngineRunRecord]:
        """A ``RUN`` invocation against a ``READY`` run, launched and started."""
        assert run.state is _R.READY
        invocation = self.invocation(
            run,
            CommandKind.RUN,
            request_hash=run.request_hash,
            timeout_seconds=RUN_TIMEOUT,
        )
        invocation, run = self.launch(invocation, run)
        assert (invocation.state, run.state) == (_C.RUNNING, _R.RUNNING)
        return invocation, run

    def finish(
        self,
        invocation: CommandInvocationRecord,
        run: EngineRunRecord,
        target: EngineRunState,
        *,
        native_exit_value: int,
        primary_terminal_diagnostic_id: str | None = None,
    ) -> EngineRunRecord:
        """Terminalize the ``RUN`` invocation as a process fact, then inject the
        core decision on the run; no engine, adapter or process is executed."""
        exited = self.move_invocation(
            invocation, _C.EXITED, native_exit_value=native_exit_value
        )
        assert exited.state is _C.EXITED
        return self.move_run(
            run, target, primary_terminal_diagnostic_id=primary_terminal_diagnostic_id
        )

    # -- store inspection ---------------------------------------------------------

    def experiment(self, experiment_id: str) -> ExperimentRecord:
        (stored,) = [
            record
            for record in self.store.committed_experiments()
            if record.experiment_id == experiment_id
        ]
        return stored

    def run(self, run_id: str) -> EngineRunRecord:
        (stored,) = [
            record
            for record in self.store.committed_engine_runs()
            if record.run_id == run_id
        ]
        return stored


def _three_slots() -> tuple[SelectedEngineSlot, ...]:
    third = SelectedEngineSlot(
        logical_slot_id=SLOT_C,
        slot_ordinal=2,
        adapter=ADAPTER_GAMMA,
        engine=ENGINE_GAMMA,
    )
    return (*sample_slots(), third)


def test_stage5_in_memory_flow() -> None:
    store = InMemoryBackingStore()
    clock = FixedClock(INSTANT)
    services = Services(store, clock, CountingIdentitySource("task9"))

    # -- construct and queue: DRAFT -> VALIDATED -> QUEUED (plan 4, 7) -------------
    created = services.create(_three_slots())
    assert (created.state, created.revision) == (_E.DRAFT, 0)
    assert tuple(
        slot.logical_slot_id for slot in created.spec.selected_engine_slots
    ) == (
        SLOT_A,
        SLOT_B,
        SLOT_C,
    )
    clock.advance(1)
    validated = services.transition(created, _E.VALIDATED)
    assert (validated.state, validated.revision) == (_E.VALIDATED, 1)
    clock.advance(1)
    queued = services.queue(validated)
    assert (queued.state, queued.revision) == (_E.QUEUED, 2)
    assert not _missing(queued.slot_compatibility)
    assert tuple(entry.outcome for entry in queued.slot_compatibility) == (
        CompatibilityOutcome.SUPPORTED,
        CompatibilityOutcome.SUPPORTED,
        CompatibilityOutcome.NOT_APPLICABLE,
    )
    experiment_id = queued.experiment_id

    # -- attempts for the two supported slots; the third is rejected (plan 5) ------
    clock.advance(1)
    creation_a = _ok(services.attempt(queued, SLOT_A))
    assert (creation_a.experiment.state, creation_a.experiment.revision) == (
        _E.RUNNING,
        3,
    )
    run_a = creation_a.attempt
    assert (run_a.state, run_a.attempt_number, run_a.adapter) == (
        _R.PENDING,
        1,
        ADAPTER_ALPHA,
    )
    assert run_a.engine == ENGINE_ALPHA
    assert not _missing(creation_a.attempt_token)
    clock.advance(1)
    creation_b = _ok(services.attempt(creation_a.experiment, SLOT_B))
    assert creation_b.experiment.revision == 4
    run_b = creation_b.attempt
    assert (run_b.adapter, run_b.engine) == (ADAPTER_BETA, ENGINE_BETA)
    rejected = services.attempt(creation_b.experiment, SLOT_C)
    assert _code(rejected) == INVARIANT_VIOLATION
    assert len(store.committed_engine_runs()) == 2
    assert services.experiment(experiment_id) == creation_b.experiment
    experiment = creation_b.experiment

    # -- VALIDATE handoff, readiness, RUN launch for both runs (plan 5, 6) ---------
    clock.advance(1)
    ready_a = services.validate_and_ready(run_a, AVAIL_A)
    assert (ready_a.state, ready_a.availability_observation_id) == (_R.READY, AVAIL_A)
    invocation_a, running_a = services.launch_run(ready_a)
    clock.advance(1)
    ready_b = services.validate_and_ready(run_b, AVAIL_B)
    invocation_b, running_b = services.launch_run(ready_b)
    assert invocation_a.run_id == running_a.run_id
    assert invocation_b.run_id == running_b.run_id
    assert running_a.revision == running_b.revision == 4

    # -- inject the canonical terminal results (plan 5: a core decision) ------------
    clock.advance(5)
    store.seed_diagnostic(
        sample_diagnostic(
            DIAG_ID,
            experiment_id=experiment_id,
            run_id=running_a.run_id,
            invocation_id=invocation_a.invocation_id,
            retriable=True,
            timestamp_utc=clock.now_utc(),
        )
    )
    failed_a = services.finish(
        invocation_a,
        running_a,
        _R.FAILED,
        native_exit_value=40,
        primary_terminal_diagnostic_id=DIAG_ID,
    )
    assert (failed_a.state, failed_a.primary_terminal_diagnostic_id) == (
        _R.FAILED,
        DIAG_ID,
    )
    clock.advance(1)
    succeeded_b = services.finish(
        invocation_b, running_b, _R.SUCCEEDED, native_exit_value=0
    )
    assert succeeded_b.state is _R.SUCCEEDED
    assert services.experiment(experiment_id) == experiment  # no run edge bumps it

    # -- retry decision and the durable delay (plan 8.2-8.5) -----------------------
    clock.advance(1)
    decision = _ok(services.evaluate_retry(experiment, failed_a))
    assert decision.outcome is RetryDecisionOutcome.ALLOWED
    assert decision.reserved_successor_attempt_number == 2
    assert decision.retry_not_before_utc == failed_a.updated_at_utc + RETRY_DELAY
    experiment = services.experiment(experiment_id)
    assert (experiment.state, experiment.revision) == (_E.RUNNING, 5)
    assert clock.now_utc() < decision.retry_not_before_utc
    not_yet = services.successor(experiment, failed_a)
    assert _code(not_yet) == RETRY_NOT_BEFORE_NOT_REACHED
    assert len(store.committed_engine_runs()) == 2
    assert services.experiment(experiment_id) == experiment
    clock.advance(int(RETRY_DELAY.total_seconds()))
    assert clock.now_utc() >= decision.retry_not_before_utc
    creation_a2 = _ok(services.successor(experiment, failed_a))
    run_a2 = creation_a2.attempt
    assert (run_a2.attempt_number, run_a2.predecessor_run_id, run_a2.retry_reason) == (
        2,
        failed_a.run_id,
        RetryTerminalState.FAILED,
    )
    assert (run_a2.adapter, run_a2.engine, run_a2.request_hash) == (
        ADAPTER_ALPHA,
        ENGINE_ALPHA,
        OTHER_REQUEST_HASH,
    )
    experiment = creation_a2.experiment
    assert (experiment.state, experiment.revision) == (_E.RUNNING, 6)

    # -- drive the successor to SUCCEEDED_WITH_WARNINGS ------------------------------
    clock.advance(1)
    ready_a2 = services.validate_and_ready(run_a2, AVAIL_A)
    invocation_a2, running_a2 = services.launch_run(ready_a2)
    clock.advance(3)
    warned_a2 = services.finish(
        invocation_a2, running_a2, _R.SUCCEEDED_WITH_WARNINGS, native_exit_value=0
    )
    assert warned_a2.state is _R.SUCCEEDED_WITH_WARNINGS
    assert services.experiment(experiment_id) == experiment

    # -- readiness: the third slot's preflight NOT_APPLICABLE contribution (plan 9.2)
    aggregation = services.aggregation_input(experiment_id)
    by_slot = {slot.logical_slot_id: slot for slot in aggregation.slots}
    slot_c = by_slot[SLOT_C]
    assert _missing(slot_c.latest_attempt_run_id)
    assert slot_c.compatibility_outcome is CompatibilityOutcome.NOT_APPLICABLE
    assert slot_c.retry_status is SlotRetryStatus.NO_DECISION_REQUIRED
    assert effective_terminal_state(slot_c) is _R.NOT_APPLICABLE
    assert is_late_not_applicable(slot_c) is False
    assert slot_reason_codes(slot_c) == ()
    assert by_slot[SLOT_A].latest_attempt_run_id == run_a2.run_id
    assert by_slot[SLOT_A].latest_attempt_state is _R.SUCCEEDED_WITH_WARNINGS
    assert by_slot[SLOT_B].latest_attempt_state is _R.SUCCEEDED
    expected_verdict = classify_experiment_outcome(aggregation)
    assert expected_verdict.verdict is AggregationVerdict.COMPLETED_WITH_WARNINGS
    assert expected_verdict.reason_codes == (REASON_SLOT_SUCCEEDED_WITH_WARNINGS,)

    # -- contend cancellation, retry and aggregation on revision 6 (plan 9.1, 9.5) --
    revision = experiment.revision
    replayed = _ok(services.evaluate_retry(experiment, failed_a, clock=FailingClock()))
    assert _bytes(replayed) == _bytes(decision)
    winners: list[ExperimentAggregationResult] = []
    fired: list[int] = []

    def hook(expected_revision: int, _candidate: ExperimentRecord) -> None:
        fired.append(expected_revision)
        winners.append(_ok(services.aggregate(experiment_id, revision)))

    hooked = InMemoryUnitOfWork(store)
    hooked.install_experiment_compare_and_swap_hook(hook)
    lost = cancel_experiment(
        CancelExperimentRequest(
            schema_version="1.0.0",
            experiment_id=experiment_id,
            expected_revision=revision,
            correlation_id=CANCEL,
        ),
        unit_of_work=hooked,
        clock=clock,
    )
    assert hooked.hooks_installed == ()
    assert fired == [revision]
    (winner,) = winners
    assert _code(lost) == INVARIANT_VIOLATION
    assert winner.verdict is AggregationVerdict.COMPLETED_WITH_WARNINGS
    assert winner.reason_codes == (REASON_SLOT_SUCCEEDED_WITH_WARNINGS,)
    assert winner == expected_verdict
    terminal = services.experiment(experiment_id)
    assert (terminal.state, terminal.revision) == (
        _E.COMPLETED_WITH_WARNINGS,
        revision + 1,
    )
    assert _missing(terminal.cancellation_correlation_id)
    assert len(store.committed_retry_decisions()) == 1
    assert len(store.committed_engine_runs()) == 3
    replay = _ok(
        services.aggregate(experiment_id, terminal.revision, clock=FailingClock())
    )
    assert (replay.verdict, replay.reason_codes) == (
        AggregationVerdict.COMPLETED_WITH_WARNINGS,
        (),
    )

    # -- rebuild every service over the same repositories (plan 11, restart) --------
    before = (
        _bytes(*store.committed_experiments()),
        _bytes(*store.committed_engine_runs()),
        _bytes(*store.committed_retry_decisions()),
        _bytes(*store.committed_command_invocations()),
    )
    rebuilt = Services(
        store,
        FixedClock(INSTANT + timedelta(days=1)),
        CountingIdentitySource("restart"),
    )
    again = _ok(rebuilt.evaluate_retry(terminal, failed_a, clock=FailingClock()))
    assert _bytes(again) == _bytes(decision)
    assert again.retry_not_before_utc == decision.retry_not_before_utc
    successor_again = _ok(rebuilt.successor(terminal, failed_a))
    assert _bytes(successor_again.attempt) == _bytes(rebuilt.run(run_a2.run_id))
    assert _missing(successor_again.attempt_token)
    assert rebuilt.identity.draws == 0
    assert (
        _code(rebuilt.cancel(experiment_id, terminal.revision)) == INVARIANT_VIOLATION
    )
    assert _code(rebuilt.cancel(experiment_id, revision)) == INVARIANT_VIOLATION
    verdict_again = _ok(rebuilt.aggregate(experiment_id, terminal.revision))
    assert (verdict_again.verdict, verdict_again.reason_codes) == (
        AggregationVerdict.COMPLETED_WITH_WARNINGS,
        (),
    )
    after = (
        _bytes(*store.committed_experiments()),
        _bytes(*store.committed_engine_runs()),
        _bytes(*store.committed_retry_decisions()),
        _bytes(*store.committed_command_invocations()),
    )
    assert after == before
    assert rebuilt.experiment(experiment_id) == terminal
