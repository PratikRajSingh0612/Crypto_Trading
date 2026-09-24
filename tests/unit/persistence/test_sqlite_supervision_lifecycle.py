"""The Stage 7 lifecycle over SQLite (plan 7.4, Task 5; case C-25 (b)).

``Stage5InvocationLifecycle`` is composed, unchanged, over ``SqliteUnitOfWork`` and
``SqliteDiagnosticRecorder`` bound to one migrated file-backed database, and the
named Stage 5-7 scenarios are replayed against it: the coupled terminal that
records its primary before the swap, the recorder failure that stops the write,
the two ``append_event`` cases, the linked launch and start, the same-state
replay, the external winner alone and coupled, the lost-swap paths, the
enrichment, and the recorded diagnostic that survives a refused swap. Every
durable assertion is a fresh read -- a new ``SqliteUnitOfWork`` transaction opened
after the writing call returned and rolled back afterwards -- never a retained
Python object; ``consistency_report()`` is asserted clean after every scenario
except for the one ``queued_without_snapshot`` row the seeded ``RUNNING`` parent
contributes (plan 4.6); and no transaction and no pooled connection survives any
call, successful or refused.

Test-local readings, declared rather than inferred silently:

- "Recorded before the swap" is proven behaviourally: the recorder wrapper reads
  the invocation's committed state through a fresh transaction at the moment of
  each ``record`` call, so a primary recorded while the record is still ``RUNNING``
  was durable before the coupled swap moved it.
- The recorder failure is the real recorder's own refusal -- a diagnostic already
  stored under the same identity with different content (plan 4.4) -- not a
  double; the commit-refusing unit of work of the ``append_event`` lost-commit
  case wraps the real ``SqliteUnitOfWork`` and intercepts ``commit()`` only,
  because over SQLite a commit never loses on its own (reading 3).
- The fixture's three runs carry the attempt tokens ``A``, ``B`` and ``C`` times
  thirty-two so the heartbeat of ``persistence_support.harness.sample_run_event``
  (hashed from the doubles' ``ATTEMPT_TOKEN``) belongs to the ``RUN``-kind run.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Final

import pytest
from pydantic.experimental.missing_sentinel import MISSING
from sqlalchemy.pool import QueuePool

from contract.harness import DEFAULT_NEGOTIATED
from crypto_lab.adapters.diagnostics import (
    PROCESS_CANCELLED,
    PROCESS_RUN_TIMED_OUT,
    PROCESS_VALIDATE_TIMED_OUT,
    PROTOCOL_STDOUT_CONTAMINATION,
    stage6_diagnostic,
)
from crypto_lab.adapters.envelopes import (
    DescribeRequestPayload,
    request_hash_of,
    request_material_hash,
)
from crypto_lab.adapters.events import RunEvent
from crypto_lab.adapters.limits import PROTOCOL_LIMITS_DEFAULT
from crypto_lab.adapters.negotiation import CORE_PROTOCOL_SUPPORT
from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.diagnostics import Diagnostic
from crypto_lab.domain.engine_run import AttemptTokenMaterial, EngineRunRecord
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
)
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.experiments.experiment_service import cancel_experiment
from crypto_lab.experiments.requests import (
    CancelExperimentRequest,
    RunTransitionRequest,
)
from crypto_lab.experiments.run_service import transition_run
from crypto_lab.experiments.supervision_lifecycle import (
    RequestMaterial,
    Stage5InvocationLifecycle,
)
from crypto_lab.persistence.database import ConsistencyReport, SqliteDatabase
from crypto_lab.persistence.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
    persistence_failure,
)
from crypto_lab.persistence.registries import SqliteDiagnosticRecorder
from crypto_lab.persistence.unit_of_work import SqliteTransaction, SqliteUnitOfWork
from crypto_lab.process_supervision.diagnostics import (
    PROCESS_CLEANUP_FAILED,
    stage7_diagnostic,
)
from doubles.experiments import (
    ATTEMPT_TOKEN,
    AVAIL_A,
    AVAIL_B,
    EXECUTABLE_HASH,
    INSTANT,
    SLOT_A,
    SLOT_B,
    SLOT_C,
    UUID_C,
    FixedClock,
    SequentialIdentitySource,
    sample_draft,
    sample_experiment,
    sample_invocation,
    sample_observation,
    sample_process_start,
    sample_run,
    sample_slots,
)
from persistence_support.harness import (
    SqliteHarness,
    causal_edges,
    ok,
    put_experiment,
    put_invocation,
    put_run,
    sample_run_event,
)

_C: Final = CommandInvocationState
_R: Final = EngineRunState
_E: Final = ExperimentState
_SEEDED_AT: Final = INSTANT - timedelta(seconds=60)
_SUPERVISOR: Final = "process_supervision.supervisor"
_THIRD_ADAPTER: Final = AdapterIdentity(
    adapter_name="adapter.gamma", adapter_version="1.0.0"
)
_THIRD_ENGINE: Final = EngineIdentity(
    engine_name="engine.gamma", engine_version="1.0.0"
)
#: The frozen observation identity ``sample_slot_compatibility`` assigns a slot
#: outside the doubles' two.
_AVAIL_C: Final = f"avail_{UUID_C}"
_MATERIAL_BY_SLOT: Final[dict[str, str]] = {
    SLOT_A: ATTEMPT_TOKEN,
    SLOT_B: "B" * 32,
    SLOT_C: "C" * 32,
}
_RUN_PRIMARY_CODE: Final[dict[EngineRunState, str]] = {
    _R.CANCELLED: PROCESS_CANCELLED,
    _R.TIMED_OUT: PROCESS_RUN_TIMED_OUT,
}


def codes_of(result: Result[Any]) -> tuple[str, ...]:
    assert isinstance(result, Failure), result
    return tuple(diagnostic.error_code for diagnostic in result.diagnostics)


def _checked_out(database: SqliteDatabase) -> int:
    """Connections the pool has lent out, not counting this probe's own."""
    with database.connection() as connection:
        pool = connection.engine.pool
        assert isinstance(pool, QueuePool)
        return pool.checkedout() - 1


class _RecordingRecorder:
    """The real recorder, with each call's identity and the record's state then.

    ``states_at_record`` holds, per call, the committed state of the diagnostic's
    invocation read through a fresh transaction before the recorder ran -- the
    behavioural proof that a primary is durable before the swap it references.
    """

    def __init__(self, inner: SqliteDiagnosticRecorder, harness: SqliteHarness) -> None:
        self._inner = inner
        self._harness = harness
        self.calls: list[str] = []
        self.states_at_record: list[CommandInvocationState | None] = []

    def record(self, diagnostic: Diagnostic) -> Result[None]:
        self.calls.append(diagnostic.diagnostic_id)
        invocation_id = diagnostic.invocation_id
        state: CommandInvocationState | None = None
        if isinstance(invocation_id, str):
            transaction = self._harness.unit_of_work().begin()
            try:
                loaded = transaction.command_invocations.get(invocation_id)
                if isinstance(loaded, Success):
                    state = loaded.value.state
            finally:
                transaction.rollback()
        self.states_at_record.append(state)
        return self._inner.record(diagnostic)


class _CommitRefusingUnitOfWork:
    """The real ``SqliteUnitOfWork`` whose every ``commit`` is a lost commit."""

    def __init__(self, inner: SqliteUnitOfWork | SqliteTransaction) -> None:
        self._inner = inner

    def begin(self) -> _CommitRefusingUnitOfWork:
        return _CommitRefusingUnitOfWork(self._inner.begin())

    def commit(self) -> Result[None]:
        self._inner.rollback()
        return persistence_failure(
            CONCURRENCY_CONFLICT, message="the commit lost", clock=FixedClock(INSTANT)
        )

    def rollback(self) -> None:
        self._inner.rollback()

    @property
    def experiments(self) -> Any:
        return self._inner.experiments

    @property
    def engine_runs(self) -> Any:
        return self._inner.engine_runs

    @property
    def command_invocations(self) -> Any:
        return self._inner.command_invocations

    @property
    def retry_decisions(self) -> Any:
        return self._inner.retry_decisions

    @property
    def availability_observations(self) -> Any:
        return self._inner.availability_observations

    @property
    def diagnostics(self) -> Any:
        return self._inner.diagnostics


@dataclass(slots=True)
class LifecycleFixture:
    """One experiment, three runs, four invocations over one SQLite database.

    The ``RUN``-kind ``invocation_id`` is brought to ``RUNNING`` (revision 2)
    through the lifecycle's own ``begin_start`` and ``record_process_start``; the
    other three stay ``PENDING`` for the launch, replay and external-winner
    scenarios. Every ``stored_*`` reader opens a fresh transaction.
    """

    harness: SqliteHarness
    clock: FixedClock
    unit_of_work: SqliteUnitOfWork
    recorder: _RecordingRecorder
    lifecycle: Stage5InvocationLifecycle
    experiment_id: str
    run_id: str
    run_kind_run_id: str
    validate_run_id: str
    invocation_id: str
    run_kind_invocation_id: str
    validate_invocation_id: str
    describe_invocation_id: str
    describe_payload: DescribeRequestPayload
    invocation_revision: int
    primary: Diagnostic
    materials: dict[str, RequestMaterial] = field(default_factory=dict)

    @property
    def database(self) -> SqliteDatabase:
        return self.harness.database

    # -- fresh reads --------------------------------------------------------------

    def _read[T](self, read: Callable[[SqliteTransaction], T]) -> T:
        transaction = self.harness.unit_of_work().begin()
        try:
            return read(transaction)
        finally:
            transaction.rollback()

    def stored_invocation(
        self, invocation_id: str | None = None
    ) -> CommandInvocationRecord:
        identity = self.invocation_id if invocation_id is None else invocation_id
        return self._read(lambda t: ok(t.command_invocations.get(identity)))

    def stored_run(self, run_id: str | None = None) -> EngineRunRecord:
        identity = self.run_id if run_id is None else run_id
        return self._read(lambda t: ok(t.engine_runs.get(identity)))

    def stored_experiment(self) -> ExperimentRecord:
        return self._read(lambda t: ok(t.experiments.get(self.experiment_id)))

    def stored_diagnostic(self, diagnostic_id: str) -> Result[Diagnostic]:
        return self._read(lambda t: t.diagnostics.get(diagnostic_id))

    def stored_events(self, invocation_id: str | None = None) -> tuple[RunEvent, ...]:
        identity = self.invocation_id if invocation_id is None else invocation_id
        return self._read(lambda t: ok(t.engine_runs.list_events(identity)))

    def run_state(self, run_id: str | None = None) -> EngineRunState:
        return self.stored_run(run_id).state

    def recorded_ids(self) -> list[str]:
        return list(self.recorder.calls)

    def report(self) -> ConsistencyReport:
        return self.database.consistency_report()

    def assert_idle(self) -> None:
        """No transaction and no lent connection survives the last call."""
        assert self.harness.open_transactions() == ()
        assert _checked_out(self.database) == 0

    def assert_clean(self) -> None:
        """Plan 4.6: every count zero except the seeded parent's snapshot row.

        The experiment is inserted directly at ``RUNNING`` through ``add`` and
        freezes no snapshot, so ``queued_without_snapshot`` counts it exactly
        until a cancellation moves it to ``CANCELLED`` (plan 7.1).
        """
        report = self.report()
        expected_scaffolding = (
            0 if self.stored_experiment().state is _E.CANCELLED else 1
        )
        assert report == ConsistencyReport(
            dangling_diagnostic_references=0,
            slot_identity_mismatches=0,
            spec_projection_mismatches=0,
            queued_without_snapshot=expected_scaffolding,
            causal_edge_mismatches=0,
            unresolved_causal_references=0,
            registry_projection_mismatches=0,
            foreign_key_violations=0,
        )

    # -- the plan's fixture helpers ------------------------------------------------

    def frozen_observation(self, logical_slot_id: str) -> str:
        compatibility = self.stored_experiment().slot_compatibility
        assert isinstance(compatibility, tuple)
        (entry,) = (
            item for item in compatibility if item.logical_slot_id == logical_slot_id
        )
        return entry.availability_observation_id

    def running(self, invocation_id: str) -> CommandInvocationRecord:
        ok(self.lifecycle.begin_start(invocation_id, expected_revision=0))
        return ok(
            self.lifecycle.record_process_start(
                invocation_id, expected_revision=1, process_start=sample_process_start()
            )
        )

    def terminal(
        self, invocation_id: str, state: CommandInvocationState
    ) -> CommandInvocationRecord:
        stored = self.stored_invocation(invocation_id)
        if stored.state is _C.PENDING:
            stored = self.running(invocation_id)
        timeout_code = (
            PROCESS_VALIDATE_TIMED_OUT
            if stored.command_kind is CommandKind.VALIDATE
            else PROCESS_RUN_TIMED_OUT
        )
        primary_code = {
            _C.CANCELLED: PROCESS_CANCELLED,
            _C.TIMED_OUT: timeout_code,
            _C.PROTOCOL_FAILED: PROTOCOL_STDOUT_CONTAMINATION,
        }[state]
        return ok(
            self.lifecycle.record_terminal(
                invocation_id,
                expected_revision=stored.revision,
                target_state=state,
                primary=self.mint_stage6(primary_code, invocation_id=invocation_id),
                additional=(),
                native_exit_value=MISSING,
            )
        )

    def move_run(
        self, state: EngineRunState, *, run_id: str | None = None
    ) -> EngineRunRecord:
        """An external ``transition_run`` -- the orchestrator moving the run."""
        key = self.run_id if run_id is None else run_id
        run = self.stored_run(key)
        payload: dict[str, object] = {
            "schema_version": "1.0.0",
            "run_id": key,
            "expected_revision": run.revision,
            "target_state": state,
            "reason_code": "TASK5.EXTERNAL_MOVE",
        }
        if state in (_R.READY, _R.UNAVAILABLE):
            payload["availability_observation_id"] = self.frozen_observation(
                run.logical_slot_id
            )
        if state in _RUN_PRIMARY_CODE:
            invocation_id = {
                self.run_id: self.invocation_id,
                self.run_kind_run_id: self.run_kind_invocation_id,
                self.validate_run_id: self.validate_invocation_id,
            }[key]
            primary = self.mint_stage6(
                _RUN_PRIMARY_CODE[state], invocation_id=invocation_id
            )
            ok(
                SqliteDiagnosticRecorder(self.database, clock=self.clock).record(
                    primary
                )
            )
            payload["primary_terminal_diagnostic_id"] = primary.diagnostic_id
        return ok(
            transition_run(
                RunTransitionRequest.model_validate(payload),
                unit_of_work=self.unit_of_work,
                clock=self.clock,
            )
        )

    def cancel_experiment(self) -> ExperimentRecord:
        return ok(
            cancel_experiment(
                CancelExperimentRequest(
                    schema_version="1.0.0",
                    experiment_id=self.experiment_id,
                    expected_revision=self.stored_experiment().revision,
                    correlation_id="task5-cancel",
                ),
                unit_of_work=self.unit_of_work,
                clock=self.clock,
            )
        )

    def _run_of(self, invocation_id: str) -> str | None:
        return {
            self.invocation_id: self.run_id,
            self.run_kind_invocation_id: self.run_kind_run_id,
            self.validate_invocation_id: self.validate_run_id,
        }.get(invocation_id)

    def _mint(
        self,
        factory: Callable[..., Diagnostic],
        code_: str,
        invocation_id: str | None,
        causes: tuple[str, ...],
    ) -> Diagnostic:
        invocation = self.invocation_id if invocation_id is None else invocation_id
        run_id = self._run_of(invocation)
        if run_id is None:
            return factory(
                code_,
                "task5 diagnostic",
                source_component=_SUPERVISOR,
                timestamp_utc=self.clock.now_utc(),
                invocation_id=invocation,
                causal_diagnostic_ids=causes,
            )
        return factory(
            code_,
            "task5 diagnostic",
            source_component=_SUPERVISOR,
            timestamp_utc=self.clock.now_utc(),
            experiment_id=self.experiment_id,
            run_id=run_id,
            invocation_id=invocation,
            causal_diagnostic_ids=causes,
        )

    def mint(
        self,
        code_: str,
        *,
        invocation_id: str | None = None,
        causes: tuple[str, ...] = (),
    ) -> Diagnostic:
        return self._mint(stage7_diagnostic, code_, invocation_id, causes)

    def mint_stage6(
        self, code_: str, *, invocation_id: str | None = None
    ) -> Diagnostic:
        return self._mint(stage6_diagnostic, code_, invocation_id, ())

    def heartbeat_event(self, *, phase: str = "warmup") -> RunEvent:
        """One heartbeat of the ``RUN``-kind invocation (sequence 1)."""
        return sample_run_event(
            sequence=1,
            invocation_id=self.invocation_id,
            run_id=self.run_id,
            phase=phase,
        )


def _build(harness: SqliteHarness) -> LifecycleFixture:
    clock = FixedClock(INSTANT)
    identity = SequentialIdentitySource("task5-sqlite")
    unit_of_work = harness.unit_of_work()
    recorder = _RecordingRecorder(
        SqliteDiagnosticRecorder(harness.database, clock=clock), harness
    )
    draft = sample_draft(
        selected_engine_slots=(
            *sample_slots(),
            SelectedEngineSlot(
                logical_slot_id=SLOT_C,
                slot_ordinal=2,
                adapter=_THIRD_ADAPTER,
                engine=_THIRD_ENGINE,
            ),
        )
    )
    experiment = sample_experiment(_E.RUNNING, draft=draft, created_at_utc=_SEEDED_AT)
    put_experiment(harness, experiment)
    for observation_id, adapter in (
        (AVAIL_A, sample_slots()[0].adapter),
        (AVAIL_B, sample_slots()[1].adapter),
        (_AVAIL_C, _THIRD_ADAPTER),
    ):
        harness.seed_observation(
            sample_observation(
                observation_id,
                adapter_name=adapter.adapter_name,
                adapter_version=adapter.adapter_version,
            )
        )
    compatibility = experiment.slot_compatibility
    assert isinstance(compatibility, tuple)
    frozen = {
        entry.logical_slot_id: entry.availability_observation_id
        for entry in compatibility
    }

    def seed_run(logical_slot_id: str, state: EngineRunState) -> EngineRunRecord:
        (slot,) = (
            item
            for item in experiment.spec.selected_engine_slots
            if item.logical_slot_id == logical_slot_id
        )
        record = sample_run(
            state,
            run_id=identity.new_run_id(),
            experiment_id=experiment.experiment_id,
            logical_slot_id=logical_slot_id,
            adapter=slot.adapter,
            engine=slot.engine,
            request_hash=request_material_hash(
                experiment=experiment,
                logical_slot_id=logical_slot_id,
                attempt_number=1,
                negotiated=DEFAULT_NEGOTIATED,
                limits=PROTOCOL_LIMITS_DEFAULT,
            ),
            attempt_token=_MATERIAL_BY_SLOT[logical_slot_id],
            availability_observation_id=frozen[logical_slot_id],
            created_at_utc=_SEEDED_AT,
        )
        put_run(harness, record)
        return record

    def seed_invocation(kind: CommandKind, run: EngineRunRecord) -> str:
        record = sample_invocation(
            _C.PENDING,
            kind=kind,
            invocation_id=identity.new_invocation_id(),
            run_id=run.run_id,
            adapter_name=run.adapter.adapter_name,
            adapter_version=run.adapter.adapter_version,
            request_hash=run.request_hash,
            created_at_utc=_SEEDED_AT,
        )
        put_invocation(harness, record)
        return record.invocation_id

    run = seed_run(SLOT_A, _R.READY)
    run_kind_run = seed_run(SLOT_B, _R.READY)
    validate_run = seed_run(SLOT_C, _R.VALIDATING)
    invocation_id = seed_invocation(CommandKind.RUN, run)
    run_kind_invocation_id = seed_invocation(CommandKind.RUN, run_kind_run)
    validate_invocation_id = seed_invocation(CommandKind.VALIDATE, validate_run)
    support = CORE_PROTOCOL_SUPPORT
    describe_payload = DescribeRequestPayload(
        bootstrap_schema_version="1.0.0",
        adapter_name="adapter.alpha",
        adapter_version="1.0.0",
        executable_hash=EXECUTABLE_HASH,
        core_supported_protocol_versions=support.protocol_versions,
        core_supported_schema_versions=support.schema_versions,
        core_capability_vocabulary_versions=support.vocabulary_versions,
    )
    describe_invocation_id = identity.new_invocation_id()
    put_invocation(
        harness,
        sample_invocation(
            _C.PENDING,
            kind=CommandKind.DESCRIBE,
            invocation_id=describe_invocation_id,
            adapter_name=describe_payload.adapter_name,
            adapter_version=describe_payload.adapter_version,
            request_hash=request_hash_of(describe_payload),
            created_at_utc=_SEEDED_AT,
        ),
    )

    def linked(run_record: EngineRunRecord, slot: str) -> RequestMaterial:
        return RequestMaterial(
            token=AttemptTokenMaterial(
                run_id=run_record.run_id, attempt_token=_MATERIAL_BY_SLOT[slot]
            ),
            negotiated_versions=DEFAULT_NEGOTIATED,
            limits=PROTOCOL_LIMITS_DEFAULT,
        )

    materials = {
        invocation_id: linked(run, SLOT_A),
        run_kind_invocation_id: linked(run_kind_run, SLOT_B),
        validate_invocation_id: linked(validate_run, SLOT_C),
        describe_invocation_id: RequestMaterial(describe_payload=describe_payload),
    }
    lifecycle = Stage5InvocationLifecycle(
        unit_of_work=unit_of_work, clock=clock, diagnostics=recorder
    )
    for key, material in materials.items():
        lifecycle.register_request_material(key, material)
    fixture = LifecycleFixture(
        harness=harness,
        clock=clock,
        unit_of_work=unit_of_work,
        recorder=recorder,
        lifecycle=lifecycle,
        experiment_id=experiment.experiment_id,
        run_id=run.run_id,
        run_kind_run_id=run_kind_run.run_id,
        validate_run_id=validate_run.run_id,
        invocation_id=invocation_id,
        run_kind_invocation_id=run_kind_invocation_id,
        validate_invocation_id=validate_invocation_id,
        describe_invocation_id=describe_invocation_id,
        describe_payload=describe_payload,
        invocation_revision=0,
        primary=stage6_diagnostic(
            PROCESS_CANCELLED,
            "task5 diagnostic",
            source_component=_SUPERVISOR,
            timestamp_utc=INSTANT,
            experiment_id=experiment.experiment_id,
            run_id=run.run_id,
            invocation_id=invocation_id,
        ),
        materials=materials,
    )
    running = fixture.running(invocation_id)
    fixture.invocation_revision = running.revision
    recorder.calls.clear()
    recorder.states_at_record.clear()
    return fixture


@pytest.fixture
def sqlite_lifecycle(sqlite_harness: SqliteHarness) -> Iterator[LifecycleFixture]:
    fixture = _build(sqlite_harness)
    assert fixture.invocation_revision == 2
    assert fixture.stored_invocation().state is _C.RUNNING
    assert fixture.run_state() is _R.RUNNING
    fixture.assert_idle()
    yield fixture
    # Teardown: no scenario may leave a transaction or a lent connection behind,
    # and every count of the consistency report is clean after every scenario
    # except the seeded parent's snapshot row (plan Task 5 Step 1, plan 4.6).
    fixture.assert_idle()
    fixture.assert_clean()


# --------------------------------------------------------------------------
# Plan Task 5 Step 1 (verbatim)
# --------------------------------------------------------------------------


def test_a_core_won_terminal_records_the_primary_before_the_coupled_swap(
    sqlite_lifecycle: LifecycleFixture,
) -> None:
    outcome = sqlite_lifecycle.lifecycle.record_terminal(
        sqlite_lifecycle.invocation_id,
        expected_revision=sqlite_lifecycle.invocation_revision,
        target_state=_C.TIMED_OUT,
        primary=sqlite_lifecycle.primary,
        additional=(),
        native_exit_value=MISSING,
    )
    assert isinstance(outcome, Success)
    assert sqlite_lifecycle.recorded_ids() == [sqlite_lifecycle.primary.diagnostic_id]
    assert sqlite_lifecycle.run_state() is _R.TIMED_OUT


# --------------------------------------------------------------------------
# The coupled terminal, every target, with the order proven behaviourally
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("target", "run_target"),
    [
        (_C.CANCELLED, _R.CANCELLED),
        (_C.TIMED_OUT, _R.TIMED_OUT),
        (_C.PROTOCOL_FAILED, _R.FAILED),
    ],
)
def test_every_core_won_terminal_couples_the_run_and_records_the_primary_first(
    sqlite_lifecycle: LifecycleFixture,
    target: CommandInvocationState,
    run_target: EngineRunState,
) -> None:
    fixture = sqlite_lifecycle
    primary = fixture.primary
    record = ok(
        fixture.lifecycle.record_terminal(
            fixture.invocation_id,
            expected_revision=fixture.invocation_revision,
            target_state=target,
            primary=primary,
            additional=(),
            native_exit_value=MISSING,
        )
    )
    assert record.state is target
    # Fresh reads: both rows moved, and the primary is the run's terminal primary.
    stored = fixture.stored_invocation()
    assert stored == record
    assert stored.primary_diagnostic_id == primary.diagnostic_id
    assert stored.diagnostic_ids == (primary.diagnostic_id,)
    assert not isinstance(stored.native_exit_value, int)
    run = fixture.stored_run()
    assert run.state is run_target
    assert run.primary_terminal_diagnostic_id == primary.diagnostic_id
    # Recorded before the swap: at record time the invocation was still RUNNING.
    assert fixture.recorded_ids() == [primary.diagnostic_id]
    assert fixture.recorder.states_at_record == [_C.RUNNING]
    assert ok(fixture.stored_diagnostic(primary.diagnostic_id)) == primary
    fixture.assert_clean()
    fixture.assert_idle()


def test_a_coupled_terminal_records_the_primary_before_its_citing_additional(
    sqlite_lifecycle: LifecycleFixture,
) -> None:
    """Reading 23: the referrer-first order converges the causal relation."""
    fixture = sqlite_lifecycle
    primary = fixture.primary
    extra = fixture.mint(PROCESS_CLEANUP_FAILED, causes=(primary.diagnostic_id,))
    record = ok(
        fixture.lifecycle.record_terminal(
            fixture.invocation_id,
            expected_revision=fixture.invocation_revision,
            target_state=_C.CANCELLED,
            primary=primary,
            additional=(extra,),
            native_exit_value=MISSING,
        )
    )
    assert record.diagnostic_ids == tuple(
        sorted((primary.diagnostic_id, extra.diagnostic_id))
    )
    assert fixture.recorded_ids() == [primary.diagnostic_id, extra.diagnostic_id]
    assert fixture.recorder.states_at_record == [_C.RUNNING, _C.RUNNING]
    assert causal_edges(fixture.database) == (
        (extra.diagnostic_id, primary.diagnostic_id),
    )
    report = fixture.report()
    assert report.causal_edge_mismatches == 0
    assert report.unresolved_causal_references == 0
    assert report.dangling_diagnostic_references == 0
    assert fixture.stored_invocation() == record
    fixture.assert_idle()


# --------------------------------------------------------------------------
# The recorder failure stops the write
# --------------------------------------------------------------------------


def test_the_recorders_own_refusal_stops_the_terminal_write_before_the_swap(
    sqlite_lifecycle: LifecycleFixture,
) -> None:
    fixture = sqlite_lifecycle
    primary = fixture.primary
    # The real refusal of plan 4.4: the identity is already stored with other
    # content, so the recorder returns the invariant and the lifecycle stops.
    twin = primary.model_copy(update={"message": "a different message"})
    ok(SqliteDiagnosticRecorder(fixture.database, clock=fixture.clock).record(twin))
    result = fixture.lifecycle.record_terminal(
        fixture.invocation_id,
        expected_revision=fixture.invocation_revision,
        target_state=_C.CANCELLED,
        primary=primary,
        additional=(),
        native_exit_value=MISSING,
    )
    assert codes_of(result) == (INVARIANT_VIOLATION,)
    assert isinstance(result, Failure)
    assert result.diagnostics[0].source_component == "persistence"
    assert "already recorded with different content" in result.diagnostics[0].message
    # Nothing moved: both rows are exactly as seeded, read fresh.
    stored = fixture.stored_invocation()
    assert stored.state is _C.RUNNING
    assert stored.revision == fixture.invocation_revision
    assert fixture.run_state() is _R.RUNNING
    assert ok(fixture.stored_diagnostic(primary.diagnostic_id)) == twin
    assert fixture.recorded_ids() == [primary.diagnostic_id]
    fixture.assert_clean()
    fixture.assert_idle()


def test_the_recorder_refusal_stops_the_alone_path_and_the_enrichment_too(
    sqlite_lifecycle: LifecycleFixture,
) -> None:
    fixture = sqlite_lifecycle
    fixture.move_run(_R.CANCELLED)  # records the run's own PROCESS.CANCELLED primary
    # A different code, so its identity is the one poisoned with other content.
    primary = fixture.mint_stage6(PROCESS_RUN_TIMED_OUT)
    ok(
        SqliteDiagnosticRecorder(fixture.database, clock=fixture.clock).record(
            primary.model_copy(update={"message": "other"})
        )
    )
    alone = fixture.lifecycle.record_terminal(
        fixture.invocation_id,
        expected_revision=fixture.invocation_revision,
        target_state=_C.TIMED_OUT,
        primary=primary,
        additional=(),
        native_exit_value=MISSING,
    )
    assert codes_of(alone) == (INVARIANT_VIOLATION,)
    assert fixture.stored_invocation().state is _C.RUNNING
    fixture.assert_idle()
    # The identical PROCESS.CANCELLED primary re-records idempotently and the
    # alone path proceeds.
    terminal = fixture.terminal(fixture.invocation_id, _C.CANCELLED)
    assert fixture.stored_invocation() == terminal
    extra = fixture.mint(PROCESS_CLEANUP_FAILED)
    ok(
        SqliteDiagnosticRecorder(fixture.database, clock=fixture.clock).record(
            extra.model_copy(update={"message": "other"})
        )
    )
    enriched = fixture.lifecycle.enrich(
        fixture.invocation_id,
        expected_revision=terminal.revision,
        native_exit_value=MISSING,
        cleanup_complete=True,
        additional=(extra,),
    )
    assert codes_of(enriched) == (INVARIANT_VIOLATION,)
    stored = fixture.stored_invocation()
    assert stored == terminal
    assert stored.cleanup_complete is False
    fixture.assert_idle()


# --------------------------------------------------------------------------
# The two append_event cases
# --------------------------------------------------------------------------


def test_append_event_commits_once_and_replays_an_identical_event(
    sqlite_lifecycle: LifecycleFixture,
) -> None:
    fixture = sqlite_lifecycle
    event = fixture.heartbeat_event()
    assert ok(fixture.lifecycle.append_event(event)) == event
    assert ok(fixture.lifecycle.append_event(event)) == event  # idempotent
    assert fixture.stored_events() == (event,)
    fixture.assert_idle()


def test_append_event_returns_a_lost_commit_and_a_conflicting_duplicate_unchanged(
    sqlite_lifecycle: LifecycleFixture,
) -> None:
    fixture = sqlite_lifecycle
    event = fixture.heartbeat_event()
    refusing = Stage5InvocationLifecycle(
        unit_of_work=_CommitRefusingUnitOfWork(fixture.unit_of_work),
        clock=fixture.clock,
        diagnostics=fixture.recorder,
    )
    assert codes_of(refusing.append_event(event)) == (CONCURRENCY_CONFLICT,)
    assert fixture.stored_events() == ()  # the lost commit published nothing
    fixture.assert_idle()
    ok(fixture.lifecycle.append_event(event))
    conflicting = fixture.heartbeat_event(phase="teardown")
    assert conflicting.sequence == event.sequence
    assert conflicting.content_hash != event.content_hash
    assert codes_of(fixture.lifecycle.append_event(conflicting)) == (
        CONCURRENCY_CONFLICT,
    )
    assert fixture.stored_events() == (event,)
    fixture.assert_idle()


# --------------------------------------------------------------------------
# The linked launch and start, and the same-state replay
# --------------------------------------------------------------------------


def test_the_linked_launch_and_start_move_both_rows_and_the_plain_kinds_one(
    sqlite_lifecycle: LifecycleFixture,
) -> None:
    fixture = sqlite_lifecycle
    started = ok(
        fixture.lifecycle.begin_start(
            fixture.run_kind_invocation_id, expected_revision=0
        )
    )
    assert started.state is _C.STARTING
    assert fixture.stored_invocation(fixture.run_kind_invocation_id) == started
    assert fixture.run_state(fixture.run_kind_run_id) is _R.STARTING  # coupled
    running = ok(
        fixture.lifecycle.record_process_start(
            fixture.run_kind_invocation_id,
            expected_revision=1,
            process_start=sample_process_start(),
        )
    )
    assert running.state is _C.RUNNING
    assert running.revision == 2
    assert fixture.stored_invocation(fixture.run_kind_invocation_id) == running
    assert fixture.run_state(fixture.run_kind_run_id) is _R.RUNNING  # linked start
    for plain in (fixture.validate_invocation_id, fixture.describe_invocation_id):
        plain_started = ok(fixture.lifecycle.begin_start(plain, expected_revision=0))
        assert plain_started.state is _C.STARTING
        assert fixture.stored_invocation(plain) == plain_started
    assert fixture.run_state(fixture.validate_run_id) is _R.VALIDATING  # untouched
    envelope = ok(fixture.lifecycle.request_envelope(fixture.describe_invocation_id))
    assert envelope.payload == fixture.describe_payload
    assert fixture.recorded_ids() == []  # a launch records no diagnostic
    fixture.assert_clean()
    fixture.assert_idle()


def test_same_state_replays_return_the_stored_record_and_stale_revisions_conflict(
    sqlite_lifecycle: LifecycleFixture,
) -> None:
    fixture = sqlite_lifecycle
    started = ok(
        fixture.lifecycle.begin_start(
            fixture.run_kind_invocation_id, expected_revision=0
        )
    )
    assert started.revision == 1
    # (STARTING, STARTING) replay through begin_linked_launch
    assert (
        ok(
            fixture.lifecycle.begin_start(
                fixture.run_kind_invocation_id, expected_revision=1
            )
        )
        == started
    )
    run_after_launch = fixture.stored_run(fixture.run_kind_run_id)
    assert run_after_launch.state is _R.STARTING
    assert codes_of(
        fixture.lifecycle.begin_start(
            fixture.run_kind_invocation_id, expected_revision=0
        )
    ) == (CONCURRENCY_CONFLICT,)
    # Neither the replay nor the refused stale launch moved either row again.
    assert fixture.stored_invocation(fixture.run_kind_invocation_id) == started
    assert fixture.stored_run(fixture.run_kind_run_id) == run_after_launch
    validate = ok(
        fixture.lifecycle.begin_start(
            fixture.validate_invocation_id, expected_revision=0
        )
    )
    replayed = ok(
        fixture.lifecycle.begin_start(
            fixture.validate_invocation_id, expected_revision=1
        )
    )
    assert replayed == validate  # same-state replay through transition_invocation
    assert fixture.stored_run(fixture.validate_run_id).revision == 1  # untouched
    # The RUN-kind record already RUNNING: identical facts replay, divergent conflict.
    facts = sample_process_start()
    replayed_start = ok(
        fixture.lifecycle.record_process_start(
            fixture.invocation_id, expected_revision=2, process_start=facts
        )
    )
    assert replayed_start == fixture.stored_invocation()
    divergent = fixture.lifecycle.record_process_start(
        fixture.invocation_id,
        expected_revision=2,
        process_start=sample_process_start(pid=4322),
    )
    assert codes_of(divergent) == (CONCURRENCY_CONFLICT,)
    assert fixture.stored_invocation().revision == 2
    fixture.assert_idle()


# --------------------------------------------------------------------------
# The external winner, alone and coupled; the lost-swap paths
# --------------------------------------------------------------------------


def test_resolve_external_winner_cancels_only_beside_a_terminal_run_or_cancelled_experiment(  # noqa: E501
    sqlite_lifecycle: LifecycleFixture,
) -> None:
    fixture = sqlite_lifecycle
    primary = fixture.mint_stage6(
        PROCESS_CANCELLED, invocation_id=fixture.validate_invocation_id
    )
    fixture.move_run(_R.READY, run_id=fixture.validate_run_id)  # a lawful move
    assert not isinstance(
        ok(
            fixture.lifecycle.resolve_external_winner(
                fixture.validate_invocation_id, expected_revision=0, primary=primary
            )
        ),
        CommandInvocationRecord,
    )  # MISSING: not a winner
    assert fixture.run_state(fixture.validate_run_id) is _R.READY  # nothing written
    assert fixture.recorded_ids() == []
    fixture.move_run(_R.CANCELLED, run_id=fixture.validate_run_id)
    record = ok(
        fixture.lifecycle.resolve_external_winner(
            fixture.validate_invocation_id, expected_revision=0, primary=primary
        )
    )
    assert isinstance(record, CommandInvocationRecord)
    assert record.state is _C.CANCELLED  # the alone path beside the terminal run
    assert fixture.stored_invocation(fixture.validate_invocation_id) == record
    assert fixture.recorder.states_at_record[-1] is _C.PENDING  # before the swap
    fixture.cancel_experiment()
    primary = fixture.mint_stage6(
        PROCESS_CANCELLED, invocation_id=fixture.run_kind_invocation_id
    )
    record = ok(
        fixture.lifecycle.resolve_external_winner(
            fixture.run_kind_invocation_id, expected_revision=0, primary=primary
        )
    )
    assert isinstance(record, CommandInvocationRecord)
    assert record.state is _C.CANCELLED
    assert fixture.stored_invocation(fixture.run_kind_invocation_id) == record
    assert fixture.run_state(fixture.run_kind_run_id) is _R.CANCELLED  # coupled
    assert fixture.stored_run(
        fixture.run_kind_run_id
    ).primary_terminal_diagnostic_id == (primary.diagnostic_id)
    fixture.assert_clean()
    fixture.assert_idle()


def test_a_stale_external_winner_conflicts_and_leaves_the_record_unchanged(
    sqlite_lifecycle: LifecycleFixture,
) -> None:
    fixture = sqlite_lifecycle
    fixture.move_run(_R.CANCELLED, run_id=fixture.run_kind_run_id)
    primary = fixture.mint_stage6(
        PROCESS_CANCELLED, invocation_id=fixture.run_kind_invocation_id
    )
    assert codes_of(
        fixture.lifecycle.resolve_external_winner(
            fixture.run_kind_invocation_id, expected_revision=7, primary=primary
        )
    ) == (CONCURRENCY_CONFLICT,)
    stored = fixture.stored_invocation(fixture.run_kind_invocation_id)
    assert stored.state is _C.PENDING
    assert stored.revision == 0
    # C-25 shape: the primary was recorded before the refused swap and stays
    # durable and unreferenced, which is not dangling.
    assert ok(fixture.stored_diagnostic(primary.diagnostic_id)) == primary
    assert fixture.report().dangling_diagnostic_references == 0
    refused = fixture.lifecycle.resolve_external_winner(
        fixture.run_kind_invocation_id, expected_revision=-1, primary=primary
    )
    assert codes_of(refused) == (INVARIANT_VIOLATION,)
    assert isinstance(refused, Failure)
    assert refused.diagnostics[0].details == {"check": "request_shape"}
    assert fixture.recorded_ids() == [
        primary.diagnostic_id
    ]  # the shape refusal recorded nothing
    fixture.assert_idle()


def test_a_terminal_beside_a_terminal_run_takes_the_alone_path(
    sqlite_lifecycle: LifecycleFixture,
) -> None:
    fixture = sqlite_lifecycle
    moved = fixture.move_run(_R.CANCELLED)  # transition_run won
    record = ok(
        fixture.lifecycle.record_terminal(
            fixture.invocation_id,
            expected_revision=fixture.invocation_revision,
            target_state=_C.CANCELLED,
            primary=fixture.mint_stage6(PROCESS_CANCELLED),
            additional=(),
            native_exit_value=MISSING,
        )
    )
    assert record.state is _C.CANCELLED
    assert fixture.stored_invocation() == record
    assert fixture.stored_run() == moved  # the run the orchestrator wrote stands
    fixture.assert_clean()
    fixture.assert_idle()


def test_an_exited_write_beside_a_run_cancelled_externally_succeeds_alone(
    sqlite_lifecycle: LifecycleFixture,
) -> None:
    fixture = sqlite_lifecycle
    moved = fixture.move_run(
        _R.CANCELLED
    )  # reading 17: the live path writes the decided state
    record = ok(
        fixture.lifecycle.record_terminal(
            fixture.invocation_id,
            expected_revision=fixture.invocation_revision,
            target_state=_C.EXITED,
            primary=MISSING,
            additional=(),
            native_exit_value=0,
        )
    )
    assert record.state is _C.EXITED
    stored = fixture.stored_invocation()
    assert stored == record
    assert stored.native_exit_value == 0
    assert fixture.stored_run() == moved
    assert fixture.run_state() is _R.CANCELLED
    fixture.assert_clean()
    fixture.assert_idle()


# --------------------------------------------------------------------------
# Enrichment
# --------------------------------------------------------------------------


def test_enrich_writes_once_records_additionals_and_refuses_an_overwrite(
    sqlite_lifecycle: LifecycleFixture,
) -> None:
    fixture = sqlite_lifecycle
    terminal = fixture.terminal(fixture.invocation_id, _C.TIMED_OUT)
    assert terminal.revision == 3
    primary_id = terminal.primary_diagnostic_id
    assert isinstance(primary_id, str)
    primary = ok(fixture.stored_diagnostic(primary_id))
    extra = fixture.mint(PROCESS_CLEANUP_FAILED)
    enriched = ok(
        fixture.lifecycle.enrich(
            fixture.invocation_id,
            expected_revision=3,
            native_exit_value=1067,
            cleanup_complete=True,
            additional=(primary, extra),
        )
    )
    stored = fixture.stored_invocation()
    assert stored == enriched
    assert stored.native_exit_value == 1067
    assert stored.cleanup_complete is True
    assert stored.diagnostic_ids == tuple(sorted({primary_id, extra.diagnostic_id}))
    assert fixture.recorded_ids()[-2:] == [primary_id, extra.diagnostic_id]
    assert ok(fixture.stored_diagnostic(extra.diagnostic_id)) == extra
    assert codes_of(
        fixture.lifecycle.enrich(
            fixture.invocation_id,
            expected_revision=4,
            native_exit_value=0,
            cleanup_complete=False,
            additional=(primary,),
        )
    ) == (INVARIANT_VIOLATION,)  # nothing new: the merged predicate refuses
    assert fixture.stored_invocation() == stored  # the refusal wrote nothing
    fixture.assert_clean()
    fixture.assert_idle()


# --------------------------------------------------------------------------
# C-25 (b): a recorded diagnostic survives a refused swap
# --------------------------------------------------------------------------


def test_a_recorded_diagnostic_survives_a_refused_swap(
    sqlite_lifecycle: LifecycleFixture,
) -> None:
    fixture = sqlite_lifecycle
    d = fixture.primary
    ok(SqliteDiagnosticRecorder(fixture.database, clock=fixture.clock).record(d))
    before = fixture.stored_invocation()
    before_run = fixture.stored_run()
    refused = fixture.lifecycle.record_terminal(
        fixture.invocation_id,
        expected_revision=fixture.invocation_revision + 5,  # stale
        target_state=_C.CANCELLED,
        primary=d,
        additional=(),
        native_exit_value=MISSING,
    )
    assert codes_of(refused) == (CONCURRENCY_CONFLICT,)
    # The terminal write never happened; d stays readable; nothing dangles.
    assert fixture.stored_invocation() == before
    assert fixture.stored_invocation().state is _C.RUNNING
    assert fixture.stored_run() == before_run
    assert ok(fixture.stored_diagnostic(d.diagnostic_id)) == d
    assert fixture.report().dangling_diagnostic_references == 0
    fixture.assert_clean()
    fixture.assert_idle()


# --------------------------------------------------------------------------
# Transaction lifetime across every refusal shape
# --------------------------------------------------------------------------


def test_no_transaction_or_connection_survives_any_refusal(
    sqlite_lifecycle: LifecycleFixture,
) -> None:
    fixture = sqlite_lifecycle
    unknown = "inv_00000000-0000-4000-8000-000000000099"
    missing = fixture.lifecycle.load(unknown)
    assert codes_of(missing) == (INVARIANT_VIOLATION,)
    assert isinstance(missing, Failure)
    assert "does not exist" in missing.diagnostics[0].message
    fixture.assert_idle()
    assert codes_of(
        fixture.lifecycle.record_terminal(
            fixture.invocation_id,
            expected_revision=-1,
            target_state=_C.CANCELLED,
            primary=fixture.primary,
            additional=(),
            native_exit_value=MISSING,
        )
    ) == (INVARIANT_VIOLATION,)  # request_shape, before any recording
    assert fixture.recorded_ids() == []
    fixture.assert_idle()
    assert codes_of(
        fixture.lifecycle.record_terminal(
            fixture.invocation_id,
            expected_revision=fixture.invocation_revision,
            target_state=_C.CANCELLED,
            primary=MISSING,
            additional=(),
            native_exit_value=MISSING,
        )
    ) == (INVARIANT_VIOLATION,)  # primary_missing
    fixture.assert_idle()
    assert codes_of(
        fixture.lifecycle.enrich(
            fixture.invocation_id,
            expected_revision=fixture.invocation_revision,
            native_exit_value=MISSING,
            cleanup_complete=True,
            additional=(),
        )
    ) == (INVARIANT_VIOLATION,)  # a RUNNING record accepts no enrichment
    fixture.assert_idle()
    assert fixture.stored_invocation().revision == fixture.invocation_revision
    assert fixture.run_state() is _R.RUNNING
    fixture.assert_clean()
