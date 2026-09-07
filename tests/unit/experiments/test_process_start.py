"""Stage 5 Task 6: the process-start handoff by command kind (plan section 6).

``DESCRIBE`` and ``VALIDATE`` reach ``RUNNING`` through ``transition_invocation``:
``PENDING -> STARTING`` establishes the launch facts from the injected clock and
``STARTING -> RUNNING`` copies the request's ``ProcessStartFacts`` verbatim onto the
record (``process_started_at_utc`` is an operating-system observation, plan 3.2, and
is therefore request-sourced, never clock-sourced). A ``VALIDATE``'s linked run
stays ``VALIDATING`` throughout. ``RUN`` reaches ``STARTING`` and ``RUNNING`` only
through ``begin_linked_launch`` and ``start_linked_run`` (``test_linked_operations``),
so here both generic edges are proven refused. ``InvocationTransitionRequest``
itself binds ``process_start`` to a ``RUNNING`` target (plan 3.11).
"""

from __future__ import annotations

from datetime import timedelta
from typing import Final

import pytest
from pydantic import ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.domain.command_invocation import (
    CommandInvocationRecord,
    ProcessStartFacts,
)
from crypto_lab.domain.engine_run import EngineRunRecord
from crypto_lab.domain.experiment import ExperimentRecord
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.experiments.diagnostics import CONCURRENCY_CONFLICT, INVARIANT_VIOLATION
from crypto_lab.experiments.invocation_service import (
    create_invocation,
    transition_invocation,
)
from crypto_lab.experiments.ports import UnitOfWork
from crypto_lab.experiments.requests import (
    InvocationCreationRequest,
    InvocationTransitionRequest,
)
from doubles.experiments import (
    ADAPTER_ALPHA,
    DIAG_ID,
    INSTANT,
    INVOCATION_ID,
    OTHER_DIAG_ID,
    REQUEST_HASH,
    RUN_ID,
    SLOT_A,
    FixedClock,
    InMemoryBackingStore,
    InMemoryUnitOfWork,
    SequentialIdentitySource,
    sample_experiment,
    sample_invocation,
    sample_process_start,
    sample_run,
)

_E = ExperimentState
_R = EngineRunState
_C = CommandInvocationState
_K = CommandKind

#: The operation clock: later than every fixture instant, including the default
#: ``process_started_at_utc`` of ``sample_process_start`` (``INSTANT`` + 2 s).
NOW: Final = INSTANT + timedelta(minutes=5)
REASON: Final = "INVOCATION.TRANSITION_REQUESTED"


# --------------------------------------------------------------------------
# Helpers (the ``test_port_contracts`` idioms) and the harness
# --------------------------------------------------------------------------


def _missing(value: object) -> bool:
    return value is MISSING


def _code(result: object) -> str:
    assert isinstance(result, Failure)
    assert len(result.diagnostics) == 1
    return result.diagnostics[0].error_code


def _ok[T](result: Success[T] | Failure) -> T:
    assert isinstance(result, Success), result
    return result.value


def _commit(unit_of_work: UnitOfWork) -> None:
    committed = unit_of_work.commit()
    assert isinstance(committed, Success), committed


class _Harness:
    """One backing store and a fixed clock; every operation gets a fresh ROOT."""

    def __init__(self) -> None:
        self.store = InMemoryBackingStore()
        self.clock = FixedClock(NOW)
        self.identity = SequentialIdentitySource()

    def root(self) -> InMemoryUnitOfWork:
        return InMemoryUnitOfWork(self.store, clock=self.clock)

    def seed(
        self,
        *,
        experiments: tuple[ExperimentRecord, ...] = (),
        runs: tuple[EngineRunRecord, ...] = (),
        invocations: tuple[CommandInvocationRecord, ...] = (),
    ) -> None:
        transaction = self.root().begin()
        for experiment in experiments:
            _ok(transaction.experiments.add(experiment))
        for run in runs:
            _ok(transaction.engine_runs.add_attempt(run))
        for invocation in invocations:
            _ok(transaction.command_invocations.add(invocation))
        _commit(transaction)

    def create(
        self, request: InvocationCreationRequest
    ) -> Result[CommandInvocationRecord]:
        return create_invocation(
            request,
            unit_of_work=self.root(),
            clock=self.clock,
            identity_source=self.identity,
        )

    def transition(
        self, request: InvocationTransitionRequest
    ) -> Result[CommandInvocationRecord]:
        return transition_invocation(
            request, unit_of_work=self.root(), clock=self.clock
        )

    def invocations(self) -> tuple[CommandInvocationRecord, ...]:
        return self.store.committed_command_invocations()

    def runs(self) -> tuple[EngineRunRecord, ...]:
        return self.store.committed_engine_runs()


@pytest.fixture
def harness() -> _Harness:
    return _Harness()


def _run(state: EngineRunState) -> EngineRunRecord:
    return sample_run(
        state, run_id=RUN_ID, logical_slot_id=SLOT_A, adapter=ADAPTER_ALPHA
    )


def _describe_request() -> InvocationCreationRequest:
    return InvocationCreationRequest.model_validate(
        {
            "schema_version": "1.0.0",
            "command_kind": _K.DESCRIBE,
            "adapter_name": ADAPTER_ALPHA.adapter_name,
            "adapter_version": ADAPTER_ALPHA.adapter_version,
            "request_hash": REQUEST_HASH,
            "timeout_seconds": 120,
        }
    )


def _transition_payload(
    invocation_id: str,
    expected_revision: int,
    target: CommandInvocationState,
    *,
    process_start: ProcessStartFacts | None = None,
    native_exit_value: int | None = None,
    primary_diagnostic_id: str | None = None,
    diagnostic_ids: tuple[str, ...] = (),
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "invocation_id": invocation_id,
        "expected_revision": expected_revision,
        "target_state": target,
        "reason_code": REASON,
        "diagnostic_ids": diagnostic_ids,
    }
    if process_start is not None:
        payload["process_start"] = process_start
    if native_exit_value is not None:
        payload["native_exit_value"] = native_exit_value
    if primary_diagnostic_id is not None:
        payload["primary_diagnostic_id"] = primary_diagnostic_id
    return payload


def _launch_request(stored: CommandInvocationRecord) -> InvocationTransitionRequest:
    return InvocationTransitionRequest.model_validate(
        _transition_payload(stored.invocation_id, stored.revision, _C.STARTING)
    )


def _start_request(
    stored: CommandInvocationRecord,
    facts: ProcessStartFacts,
    *,
    expected_revision: int | None = None,
) -> InvocationTransitionRequest:
    revision = stored.revision if expected_revision is None else expected_revision
    return InvocationTransitionRequest.model_validate(
        _transition_payload(
            stored.invocation_id, revision, _C.RUNNING, process_start=facts
        )
    )


def _assert_no_process(record: CommandInvocationRecord) -> None:
    assert record.process_created is False
    assert _missing(record.pid_identity)
    assert _missing(record.process_started_at_utc)


# --------------------------------------------------------------------------
# DESCRIBE and VALIDATE: the generic two-step path to RUNNING
# --------------------------------------------------------------------------


def test_a_describe_reaches_running_through_two_generic_transitions(
    harness: _Harness,
) -> None:
    pending = sample_invocation(_C.PENDING, kind=_K.DESCRIBE)
    harness.seed(invocations=(pending,))
    starting = _ok(harness.transition(_launch_request(pending)))
    assert starting.state is _C.STARTING
    assert starting.revision == pending.revision + 1
    assert starting.launch_attempted_at_utc == NOW
    assert starting.deadline_utc == NOW + timedelta(seconds=pending.timeout_seconds)
    _assert_no_process(starting)
    facts = sample_process_start()
    running = _ok(harness.transition(_start_request(starting, facts)))
    assert running.state is _C.RUNNING
    assert running.revision == pending.revision + 2
    assert running.process_created is True
    assert running.pid_identity == facts.pid_identity
    assert running.process_started_at_utc == facts.process_started_at_utc
    # Request-sourced, not clock-sourced (plan 3.2).
    assert running.process_started_at_utc != NOW
    assert running.updated_at_utc == NOW
    assert running.launch_attempted_at_utc == starting.launch_attempted_at_utc
    assert running.deadline_utc == starting.deadline_utc
    assert _missing(running.run_id)
    assert _missing(running.completed_at_utc)
    assert running.cleanup_complete is False
    # There is no run anywhere: a DESCRIBE never reads one.
    assert harness.runs() == ()
    assert harness.invocations() == (running,)


def test_a_validate_reaches_running_while_its_linked_run_stays_validating(
    harness: _Harness,
) -> None:
    run = _run(_R.VALIDATING)
    pending = sample_invocation(_C.PENDING, kind=_K.VALIDATE)
    harness.seed(
        experiments=(sample_experiment(_E.RUNNING),),
        runs=(run,),
        invocations=(pending,),
    )
    starting = _ok(harness.transition(_launch_request(pending)))
    assert starting.state is _C.STARTING
    assert harness.runs() == (run,)
    facts = sample_process_start()
    running = _ok(harness.transition(_start_request(starting, facts)))
    assert running.state is _C.RUNNING
    assert running.command_kind is _K.VALIDATE
    assert running.run_id == RUN_ID
    assert running.process_created is True
    assert running.pid_identity == facts.pid_identity
    assert running.process_started_at_utc == facts.process_started_at_utc
    # The linked run is untouched: same state, same revision, same record.
    stored_run = harness.runs()
    assert stored_run == (run,)
    assert stored_run[0].state is _R.VALIDATING
    assert stored_run[0].revision == run.revision
    assert harness.invocations() == (running,)


def test_process_created_stays_false_through_pending_and_starting(
    harness: _Harness,
) -> None:
    created = _ok(harness.create(_describe_request()))
    assert created.state is _C.PENDING
    _assert_no_process(created)
    assert _missing(created.deadline_utc)
    starting = _ok(harness.transition(_launch_request(created)))
    assert starting.state is _C.STARTING
    _assert_no_process(starting)
    assert not _missing(starting.deadline_utc)
    running = _ok(harness.transition(_start_request(starting, sample_process_start())))
    assert running.state is _C.RUNNING
    assert running.process_created is True
    assert harness.invocations() == (running,)


def test_process_start_is_copied_verbatim_onto_the_record(harness: _Harness) -> None:
    starting = sample_invocation(_C.STARTING, kind=_K.DESCRIBE)
    harness.seed(invocations=(starting,))
    observed_at = INSTANT + timedelta(seconds=7)
    facts = sample_process_start(
        process_started_at_utc=observed_at,
        pid=777,
        supervisor_instance_id="supervisor-07",
    )
    assert facts.pid_identity.pid == 777
    running = _ok(harness.transition(_start_request(starting, facts)))
    assert running.pid_identity == facts.pid_identity
    assert running.process_started_at_utc == observed_at
    assert running.process_started_at_utc != NOW
    assert running.updated_at_utc == NOW
    assert running.revision == starting.revision + 1
    assert harness.invocations() == (running,)


def test_a_second_start_at_the_matching_revision_replays_the_stored_record(
    harness: _Harness,
) -> None:
    starting = sample_invocation(_C.STARTING, kind=_K.DESCRIBE)
    harness.seed(invocations=(starting,))
    facts = sample_process_start()
    running = _ok(harness.transition(_start_request(starting, facts)))
    replayed = _ok(harness.transition(_start_request(running, facts)))
    assert replayed == running
    assert harness.invocations() == (running,)
    # The pre-start revision is stale: a same-state request there is a conflict.
    stale = harness.transition(
        _start_request(running, facts, expected_revision=starting.revision)
    )
    assert _code(stale) == CONCURRENCY_CONFLICT
    assert harness.invocations() == (running,)


# --------------------------------------------------------------------------
# RUN: only the linked operations may launch or start it
# --------------------------------------------------------------------------


def test_a_run_kind_cannot_reach_starting_through_transition_invocation(
    harness: _Harness,
) -> None:
    ready = _run(_R.READY)
    pending = sample_invocation(_C.PENDING, kind=_K.RUN)
    harness.seed(runs=(ready,), invocations=(pending,))
    assert _code(harness.transition(_launch_request(pending))) == INVARIANT_VIOLATION
    assert harness.invocations() == (pending,)
    assert harness.runs() == (ready,)


def test_a_run_kind_cannot_reach_running_through_transition_invocation(
    harness: _Harness,
) -> None:
    starting_run = _run(_R.STARTING)
    starting = sample_invocation(_C.STARTING, kind=_K.RUN)
    harness.seed(runs=(starting_run,), invocations=(starting,))
    result = harness.transition(_start_request(starting, sample_process_start()))
    assert _code(result) == INVARIANT_VIOLATION
    assert harness.invocations() == (starting,)
    assert harness.runs() == (starting_run,)


# --------------------------------------------------------------------------
# The request binds process_start to a RUNNING target (plan 3.11)
# --------------------------------------------------------------------------


def test_the_request_requires_process_start_exactly_on_a_running_target() -> None:
    facts = sample_process_start()
    with pytest.raises(ValidationError):
        InvocationTransitionRequest.model_validate(
            _transition_payload(INVOCATION_ID, 1, _C.RUNNING)
        )
    for target in _C:
        if target is _C.RUNNING:
            continue
        with pytest.raises(ValidationError):
            InvocationTransitionRequest.model_validate(
                _transition_payload(INVOCATION_ID, 1, target, process_start=facts)
            )
        without = InvocationTransitionRequest.model_validate(
            _transition_payload(INVOCATION_ID, 1, target)
        )
        assert _missing(without.process_start)
    request = InvocationTransitionRequest.model_validate(
        _transition_payload(INVOCATION_ID, 1, _C.RUNNING, process_start=facts)
    )
    assert request.process_start == facts
    assert request.target_state is _C.RUNNING


def test_the_request_requires_a_supplied_primary_to_be_listed() -> None:
    with pytest.raises(ValidationError):
        InvocationTransitionRequest.model_validate(
            _transition_payload(
                INVOCATION_ID,
                2,
                _C.CANCELLED,
                primary_diagnostic_id=DIAG_ID,
                diagnostic_ids=(OTHER_DIAG_ID,),
            )
        )
    request = InvocationTransitionRequest.model_validate(
        _transition_payload(
            INVOCATION_ID,
            2,
            _C.CANCELLED,
            primary_diagnostic_id=DIAG_ID,
            diagnostic_ids=(DIAG_ID, OTHER_DIAG_ID),
        )
    )
    assert request.primary_diagnostic_id == DIAG_ID
    assert request.diagnostic_ids == (DIAG_ID, OTHER_DIAG_ID)
