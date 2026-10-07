"""Stage 5 Task 6: the three single-invocation operations of ``invocation_service``.

Plan sections 3.7, 6 and 10.1 (the ``create_invocation``, ``transition_invocation``
and ``enrich_invocation`` rows) under the task-local readings declared in the
``invocation_service`` module docstring: the owned-target check precedes replay; a
same-state request at a
stale revision is ``PERSISTENCE.CONCURRENCY_CONFLICT``; the kind-specific timeout
bound is a service invariant rather than a request shape rule;
``transition_invocation`` refuses a coupled terminal target for ``VALIDATE`` and
``RUN`` while the linked run is non-terminal; and enrichment carries an already
completed cleanup forward unchanged.

Every operation receives the ROOT ``InMemoryUnitOfWork`` and opens its own
transaction. Tests seed state through a transaction of their own and inspect the
store's ``committed_*()`` tuples, so an accepted operation is proven durable and a
rejected one is proven to write nothing. The clock is fixed later than every
fixture instant, so a clock-sourced field is distinguishable from a carried one.
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
from crypto_lab.domain.diagnostics import Diagnostic
from crypto_lab.domain.engine_run import EngineRunRecord
from crypto_lab.domain.experiment import ExperimentRecord
from crypto_lab.domain.lifecycle import (
    TERMINAL_COMMAND_INVOCATION_STATES,
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
    ProcessExitCategory,
)
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.experiments.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
    UNRECOGNIZED_PROCESS_EXIT,
)
from crypto_lab.experiments.invocation_service import (
    create_invocation,
    enrich_invocation,
    transition_invocation,
)
from crypto_lab.experiments.ports import UnitOfWork
from crypto_lab.experiments.requests import (
    InvocationCreationRequest,
    InvocationEnrichmentRequest,
    InvocationTransitionRequest,
)
from crypto_lab.persistence.diagnostics import (
    STORAGE_UNAVAILABLE,
    WRITE_FAILED,
    persistence_failure,
)
from doubles.experiments import (
    ADAPTER_ALPHA,
    ADAPTER_BETA,
    ARTIFACT_ID,
    DIAG_ID,
    INSTANT,
    INVOCATION_ID,
    OTHER_DIAG_ID,
    OTHER_INVOCATION_ID,
    OTHER_REQUEST_HASH,
    OTHER_RUN_ID,
    REQUEST_HASH,
    RUN_ID,
    SLOT_A,
    THIRD_DIAG_ID,
    UUID_B,
    FixedClock,
    InMemoryBackingStore,
    InMemoryUnitOfWork,
    MemberOverridingUnitOfWork,
    SequentialIdentitySource,
    sample_diagnostic,
    sample_experiment,
    sample_invocation,
    sample_process_start,
    sample_run,
)

_E = ExperimentState
_R = EngineRunState
_C = CommandInvocationState
_K = CommandKind

#: The operation clock: later than every fixture instant (``INSTANT`` plus seconds).
NOW: Final = INSTANT + timedelta(minutes=5)
REASON: Final = "INVOCATION.TRANSITION_REQUESTED"
DEFAULT_TIMEOUT: Final = 120
OTHER_ARTIFACT_ID: Final = f"art_{UUID_B}"
LINKED_KINDS: Final = [_K.VALIDATE, _K.RUN]
#: Plan section 6 parent-eligibility matrix, "Parent run state" column.
ELIGIBLE_PARENT_STATE: Final[dict[CommandKind, EngineRunState]] = {
    _K.VALIDATE: _R.VALIDATING,
    _K.RUN: _R.READY,
}
#: The four coupled terminal targets (plan 6) with the stored state each leaves.
COUPLED_EDGES: Final[list[tuple[CommandInvocationState, CommandInvocationState]]] = [
    (_C.STARTING, _C.FAILED_TO_START),
    (_C.RUNNING, _C.CANCELLED),
    (_C.RUNNING, _C.TIMED_OUT),
    (_C.RUNNING, _C.PROTOCOL_FAILED),
]


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
    """One backing store, a fixed clock and a deterministic identity source.

    Every operation is handed a fresh ROOT unit of work over the same store and
    the same clock; the service opens and closes its own transaction.
    """

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

    def enrich(
        self, request: InvocationEnrichmentRequest
    ) -> Result[CommandInvocationRecord]:
        return enrich_invocation(request, unit_of_work=self.root(), clock=self.clock)

    def invocations(self) -> tuple[CommandInvocationRecord, ...]:
        return self.store.committed_command_invocations()

    def runs(self) -> tuple[EngineRunRecord, ...]:
        return self.store.committed_engine_runs()


@pytest.fixture
def harness() -> _Harness:
    return _Harness()


def _run(state: EngineRunState) -> EngineRunRecord:
    """Attempt 1 of slot A on adapter alpha: the run every linked create names."""
    return sample_run(
        state, run_id=RUN_ID, logical_slot_id=SLOT_A, adapter=ADAPTER_ALPHA
    )


def _eligible_run(kind: CommandKind) -> EngineRunRecord:
    return _run(ELIGIBLE_PARENT_STATE[kind])


def _amended(
    record: CommandInvocationRecord, **changes: object
) -> CommandInvocationRecord:
    payload = record.model_dump(mode="python")
    payload.update(changes)
    return CommandInvocationRecord.model_validate(payload)


def _creation_request(
    kind: CommandKind,
    *,
    adapter_name: str = ADAPTER_ALPHA.adapter_name,
    adapter_version: str = ADAPTER_ALPHA.adapter_version,
    run_id: object = MISSING,
    expected_run_revision: object = MISSING,
    request_hash: str = REQUEST_HASH,
    timeout_seconds: int = DEFAULT_TIMEOUT,
) -> InvocationCreationRequest:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "command_kind": kind,
        "adapter_name": adapter_name,
        "adapter_version": adapter_version,
        "request_hash": request_hash,
        "timeout_seconds": timeout_seconds,
    }
    if not _missing(run_id):
        payload["run_id"] = run_id
    if not _missing(expected_run_revision):
        payload["expected_run_revision"] = expected_run_revision
    return InvocationCreationRequest.model_validate(payload)


def _linked_request(
    kind: CommandKind,
    run: EngineRunRecord,
    *,
    adapter_name: str = ADAPTER_ALPHA.adapter_name,
    adapter_version: str = ADAPTER_ALPHA.adapter_version,
    request_hash: str = REQUEST_HASH,
    timeout_seconds: int = DEFAULT_TIMEOUT,
) -> InvocationCreationRequest:
    """A fully linked create against ``run`` at its current revision."""
    return _creation_request(
        kind,
        adapter_name=adapter_name,
        adapter_version=adapter_version,
        run_id=run.run_id,
        expected_run_revision=run.revision,
        request_hash=request_hash,
        timeout_seconds=timeout_seconds,
    )


def _transition_request(
    invocation_id: str,
    expected_revision: int,
    target: CommandInvocationState,
    *,
    process_start: ProcessStartFacts | None = None,
    native_exit_value: int | None = None,
    primary_diagnostic_id: str | None = None,
    diagnostic_ids: tuple[str, ...] = (),
) -> InvocationTransitionRequest:
    """Build the request; a supplied primary is merged into ``diagnostic_ids``."""
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
        payload["diagnostic_ids"] = tuple(
            sorted({*diagnostic_ids, primary_diagnostic_id})
        )
    return InvocationTransitionRequest.model_validate(payload)


def _shaped_request(
    invocation_id: str, expected_revision: int, target: CommandInvocationState
) -> InvocationTransitionRequest:
    """A request carrying exactly the target-governed facts ``target`` needs."""
    if target is _C.RUNNING:
        return _transition_request(
            invocation_id,
            expected_revision,
            target,
            process_start=sample_process_start(),
        )
    if target is _C.EXITED:
        return _transition_request(
            invocation_id, expected_revision, target, native_exit_value=0
        )
    if target in TERMINAL_COMMAND_INVOCATION_STATES:
        return _transition_request(
            invocation_id, expected_revision, target, primary_diagnostic_id=DIAG_ID
        )
    return _transition_request(invocation_id, expected_revision, target)


def _enrichment_request(
    invocation_id: str, expected_revision: int, **fields: object
) -> InvocationEnrichmentRequest:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "invocation_id": invocation_id,
        "expected_revision": expected_revision,
        "additional_diagnostic_ids": (),
    }
    payload.update(fields)
    return InvocationEnrichmentRequest.model_validate(payload)


# --------------------------------------------------------------------------
# create_invocation: DESCRIBE (plan 6 matrix row 1)
# --------------------------------------------------------------------------


def test_a_describe_create_is_pending_at_revision_zero_with_no_run_and_no_reads(
    harness: _Harness,
) -> None:
    expected_id = SequentialIdentitySource().new_invocation_id()
    record = _ok(harness.create(_creation_request(_K.DESCRIBE)))
    assert record.invocation_id == expected_id
    assert record.command_kind is _K.DESCRIBE
    assert record.state is _C.PENDING
    assert record.revision == 0
    assert _missing(record.run_id)
    assert record.adapter_name == ADAPTER_ALPHA.adapter_name
    assert record.adapter_version == ADAPTER_ALPHA.adapter_version
    assert record.request_hash == REQUEST_HASH
    assert record.timeout_seconds == DEFAULT_TIMEOUT
    assert record.process_created is False
    assert record.cleanup_complete is False
    assert record.diagnostic_ids == ()
    assert _missing(record.deadline_utc)
    assert _missing(record.launch_attempted_at_utc)
    assert _missing(record.pid_identity)
    assert _missing(record.completed_at_utc)
    assert record.created_at_utc == NOW
    assert record.updated_at_utc == NOW
    # The store holds no experiment and no run: a DESCRIBE reads nothing.
    assert harness.store.committed_experiments() == ()
    assert harness.runs() == ()
    assert harness.invocations() == (record,)


def test_two_describe_creates_are_not_deduplicated(harness: _Harness) -> None:
    probe = SequentialIdentitySource()
    first = _ok(harness.create(_creation_request(_K.DESCRIBE)))
    second = _ok(harness.create(_creation_request(_K.DESCRIBE)))
    assert first.invocation_id == probe.new_invocation_id()
    assert second.invocation_id == probe.new_invocation_id()
    assert first.invocation_id != second.invocation_id
    assert first.model_dump(exclude={"invocation_id"}) == second.model_dump(
        exclude={"invocation_id"}
    )
    assert harness.invocations() == tuple(
        sorted((first, second), key=lambda record: record.invocation_id)
    )


@pytest.mark.parametrize(
    ("run_id", "expected_run_revision"),
    [(RUN_ID, MISSING), (MISSING, 1), (RUN_ID, 1)],
    ids=["run-only", "revision-only", "both"],
)
def test_a_describe_with_any_linkage_is_an_invariant_violation(
    harness: _Harness, run_id: object, expected_run_revision: object
) -> None:
    # A real VALIDATING run exists, so only the DESCRIBE linkage rule can reject.
    harness.seed(
        experiments=(sample_experiment(_E.RUNNING),), runs=(_run(_R.VALIDATING),)
    )
    result = harness.create(
        _creation_request(
            _K.DESCRIBE, run_id=run_id, expected_run_revision=expected_run_revision
        )
    )
    assert _code(result) == INVARIANT_VIOLATION
    assert harness.invocations() == ()


# --------------------------------------------------------------------------
# create_invocation: the VALIDATE and RUN parent-eligibility matrix
# --------------------------------------------------------------------------


@pytest.mark.parametrize("kind", LINKED_KINDS)
@pytest.mark.parametrize("run_state", list(_R))
def test_the_parent_eligibility_matrix_admits_exactly_one_run_state_per_kind(
    harness: _Harness, kind: CommandKind, run_state: EngineRunState
) -> None:
    run = _run(run_state)
    harness.seed(experiments=(sample_experiment(_E.RUNNING),), runs=(run,))
    result = harness.create(_linked_request(kind, run))
    if run_state is ELIGIBLE_PARENT_STATE[kind]:
        record = _ok(result)
        assert record.command_kind is kind
        assert record.state is _C.PENDING
        assert record.revision == 0
        assert record.run_id == RUN_ID
        assert record.request_hash == REQUEST_HASH
        assert record.process_created is False
        assert record.cleanup_complete is False
        assert record.diagnostic_ids == ()
        assert _missing(record.deadline_utc)
        assert record.created_at_utc == NOW
        assert record.updated_at_utc == NOW
        assert harness.invocations() == (record,)
    else:
        assert _code(result) == INVARIANT_VIOLATION
        assert harness.invocations() == ()
    assert harness.runs() == (run,)


@pytest.mark.parametrize("kind", LINKED_KINDS)
def test_a_half_linked_request_is_an_invariant_violation(
    harness: _Harness, kind: CommandKind
) -> None:
    run = _eligible_run(kind)
    harness.seed(experiments=(sample_experiment(_E.RUNNING),), runs=(run,))
    run_only = harness.create(_creation_request(kind, run_id=RUN_ID))
    revision_only = harness.create(
        _creation_request(kind, expected_run_revision=run.revision)
    )
    assert _code(run_only) == INVARIANT_VIOLATION
    assert _code(revision_only) == INVARIANT_VIOLATION
    assert harness.invocations() == ()


@pytest.mark.parametrize("kind", LINKED_KINDS)
def test_a_run_that_is_not_the_slots_latest_attempt_is_rejected(
    harness: _Harness, kind: CommandKind
) -> None:
    # Attempt 1 is in the eligible parent state, so only currency can reject it.
    attempt_one = _eligible_run(kind)
    attempt_two = sample_run(
        _R.PENDING,
        run_id=OTHER_RUN_ID,
        logical_slot_id=SLOT_A,
        attempt_number=2,
        adapter=ADAPTER_ALPHA,
    )
    harness.seed(
        experiments=(sample_experiment(_E.RUNNING),), runs=(attempt_one, attempt_two)
    )
    result = harness.create(_linked_request(kind, attempt_one))
    assert _code(result) == INVARIANT_VIOLATION
    assert harness.invocations() == ()


@pytest.mark.parametrize("kind", LINKED_KINDS)
def test_an_experiment_that_is_not_running_is_rejected(
    harness: _Harness, kind: CommandKind
) -> None:
    run = _eligible_run(kind)
    harness.seed(experiments=(sample_experiment(_E.QUEUED),), runs=(run,))
    assert _code(harness.create(_linked_request(kind, run))) == INVARIANT_VIOLATION
    assert harness.invocations() == ()


@pytest.mark.parametrize("kind", LINKED_KINDS)
@pytest.mark.parametrize(
    ("adapter_name", "adapter_version"),
    [
        (ADAPTER_BETA.adapter_name, ADAPTER_ALPHA.adapter_version),
        (ADAPTER_ALPHA.adapter_name, "1.0.1"),
    ],
    ids=["name", "version"],
)
def test_a_mismatched_adapter_identity_is_rejected(
    harness: _Harness, kind: CommandKind, adapter_name: str, adapter_version: str
) -> None:
    run = _eligible_run(kind)
    harness.seed(experiments=(sample_experiment(_E.RUNNING),), runs=(run,))
    result = harness.create(
        _linked_request(
            kind, run, adapter_name=adapter_name, adapter_version=adapter_version
        )
    )
    assert _code(result) == INVARIANT_VIOLATION
    assert harness.invocations() == ()


def test_a_run_create_with_a_mismatched_request_hash_is_rejected(
    harness: _Harness,
) -> None:
    ready = _run(_R.READY)
    assert ready.request_hash == REQUEST_HASH
    harness.seed(experiments=(sample_experiment(_E.RUNNING),), runs=(ready,))
    result = harness.create(
        _linked_request(_K.RUN, ready, request_hash=OTHER_REQUEST_HASH)
    )
    assert _code(result) == INVARIANT_VIOLATION
    assert harness.invocations() == ()


def test_a_validate_create_does_not_bind_request_hash_to_the_run(
    harness: _Harness,
) -> None:
    validating = _run(_R.VALIDATING)
    harness.seed(experiments=(sample_experiment(_E.RUNNING),), runs=(validating,))
    record = _ok(
        harness.create(
            _linked_request(_K.VALIDATE, validating, request_hash=OTHER_REQUEST_HASH)
        )
    )
    assert record.request_hash == OTHER_REQUEST_HASH
    assert record.run_id == RUN_ID
    assert harness.invocations() == (record,)


@pytest.mark.parametrize("kind", LINKED_KINDS)
@pytest.mark.parametrize("offset", [-1, 1])
def test_a_stale_expected_run_revision_is_a_concurrency_conflict(
    harness: _Harness, kind: CommandKind, offset: int
) -> None:
    run = _eligible_run(kind)
    harness.seed(experiments=(sample_experiment(_E.RUNNING),), runs=(run,))
    result = harness.create(
        _creation_request(
            kind, run_id=RUN_ID, expected_run_revision=run.revision + offset
        )
    )
    assert _code(result) == CONCURRENCY_CONFLICT
    assert harness.invocations() == ()


def test_an_open_validate_blocks_a_run_create_and_a_closed_one_does_not(
    harness: _Harness,
) -> None:
    ready = _run(_R.READY)
    open_validate = sample_invocation(
        _C.STARTING, kind=_K.VALIDATE, invocation_id=OTHER_INVOCATION_ID
    )
    harness.seed(
        experiments=(sample_experiment(_E.RUNNING),),
        runs=(ready,),
        invocations=(open_validate,),
    )
    blocked = harness.create(_linked_request(_K.RUN, ready))
    assert _code(blocked) == INVARIANT_VIOLATION
    assert harness.invocations() == (open_validate,)
    # Near miss: the same VALIDATE, already terminal, no longer blocks.
    closed = _Harness()
    exited_validate = sample_invocation(
        _C.EXITED, kind=_K.VALIDATE, invocation_id=OTHER_INVOCATION_ID
    )
    closed.seed(
        experiments=(sample_experiment(_E.RUNNING),),
        runs=(ready,),
        invocations=(exited_validate,),
    )
    record = _ok(closed.create(_linked_request(_K.RUN, ready)))
    assert record.command_kind is _K.RUN
    assert record.run_id == RUN_ID
    assert set(closed.invocations()) == {exited_validate, record}


def test_the_kind_specific_timeout_bound_is_a_service_invariant(
    harness: _Harness,
) -> None:
    # Both requests construct: the request carries only the 1..604800 envelope.
    over_describe = _creation_request(_K.DESCRIBE, timeout_seconds=301)
    assert over_describe.timeout_seconds == 301
    assert _code(harness.create(over_describe)) == INVARIANT_VIOLATION
    validating = _run(_R.VALIDATING)
    harness.seed(experiments=(sample_experiment(_E.RUNNING),), runs=(validating,))
    over_validate = _linked_request(_K.VALIDATE, validating, timeout_seconds=1801)
    assert _code(harness.create(over_validate)) == INVARIANT_VIOLATION
    assert harness.invocations() == ()
    # The bound itself is admitted.
    at_bound = _ok(harness.create(_creation_request(_K.DESCRIBE, timeout_seconds=300)))
    assert at_bound.timeout_seconds == 300
    # Only the kind-independent envelope is a request shape rule.
    for outside in (0, 604801):
        with pytest.raises(ValidationError):
            _creation_request(_K.RUN, timeout_seconds=outside)


@pytest.mark.parametrize("kind", LINKED_KINDS)
def test_an_identical_create_replays_the_open_invocation_without_a_write(
    harness: _Harness, kind: CommandKind
) -> None:
    run = _eligible_run(kind)
    existing = sample_invocation(_C.PENDING, kind=kind)
    harness.seed(
        experiments=(sample_experiment(_E.RUNNING),),
        runs=(run,),
        invocations=(existing,),
    )
    replayed = _ok(harness.create(_linked_request(kind, run)))
    assert replayed == existing
    assert replayed.created_at_utc == existing.created_at_utc
    assert harness.invocations() == (existing,)


@pytest.mark.parametrize("kind", LINKED_KINDS)
def test_a_divergent_create_against_an_open_invocation_is_a_conflict(
    harness: _Harness, kind: CommandKind
) -> None:
    run = _eligible_run(kind)
    existing = sample_invocation(_C.PENDING, kind=kind)
    harness.seed(
        experiments=(sample_experiment(_E.RUNNING),),
        runs=(run,),
        invocations=(existing,),
    )
    divergent = harness.create(
        _linked_request(kind, run, timeout_seconds=DEFAULT_TIMEOUT + 1)
    )
    assert _code(divergent) == CONCURRENCY_CONFLICT
    assert harness.invocations() == (existing,)


def test_a_validate_create_with_another_request_hash_diverges_from_the_open_one(
    harness: _Harness,
) -> None:
    validating = _run(_R.VALIDATING)
    existing = sample_invocation(_C.PENDING, kind=_K.VALIDATE)
    harness.seed(
        experiments=(sample_experiment(_E.RUNNING),),
        runs=(validating,),
        invocations=(existing,),
    )
    divergent = harness.create(
        _linked_request(_K.VALIDATE, validating, request_hash=OTHER_REQUEST_HASH)
    )
    assert _code(divergent) == CONCURRENCY_CONFLICT
    assert harness.invocations() == (existing,)


@pytest.mark.parametrize("kind", LINKED_KINDS)
def test_a_missing_run_is_an_invariant_violation(
    harness: _Harness, kind: CommandKind
) -> None:
    harness.seed(experiments=(sample_experiment(_E.RUNNING),))
    result = harness.create(
        _creation_request(kind, run_id=RUN_ID, expected_run_revision=0)
    )
    assert _code(result) == INVARIANT_VIOLATION
    assert harness.invocations() == ()


# --------------------------------------------------------------------------
# transition_invocation: launch facts, ownership, replay and revision
# --------------------------------------------------------------------------


@pytest.mark.parametrize("kind", [_K.DESCRIBE, _K.VALIDATE])
def test_pending_to_starting_establishes_the_launch_facts_from_the_clock(
    harness: _Harness, kind: CommandKind
) -> None:
    stored = sample_invocation(_C.PENDING, kind=kind)
    runs: tuple[EngineRunRecord, ...] = ()
    if kind is _K.VALIDATE:
        runs = (_run(_R.VALIDATING),)
    harness.seed(runs=runs, invocations=(stored,))
    started = _ok(
        harness.transition(
            _transition_request(INVOCATION_ID, stored.revision, _C.STARTING)
        )
    )
    assert started.state is _C.STARTING
    assert started.revision == stored.revision + 1
    assert started.launch_attempted_at_utc == NOW
    assert started.deadline_utc == NOW + timedelta(seconds=stored.timeout_seconds)
    assert started.updated_at_utc == NOW
    assert started.created_at_utc == stored.created_at_utc
    assert started.process_created is False
    assert _missing(started.pid_identity)
    assert _missing(started.process_started_at_utc)
    assert _missing(started.completed_at_utc)
    assert harness.invocations() == (started,)
    assert harness.runs() == runs


@pytest.mark.parametrize(
    ("stored_state", "target"),
    [
        (_C.PENDING, _C.STARTING),
        (_C.STARTING, _C.RUNNING),
        (_C.STARTING, _C.STARTING),
    ],
    ids=["launch", "start", "same-state-starting"],
)
def test_run_kind_launch_and_start_targets_are_linked_only(
    harness: _Harness,
    stored_state: CommandInvocationState,
    target: CommandInvocationState,
) -> None:
    stored = sample_invocation(stored_state, kind=_K.RUN)
    run = _run(_R.READY if stored_state is _C.PENDING else _R.STARTING)
    harness.seed(runs=(run,), invocations=(stored,))
    # The owned-target check precedes replay: a matching revision does not
    # turn a RUN-kind STARTING request against a STARTING record into a replay.
    result = harness.transition(_shaped_request(INVOCATION_ID, stored.revision, target))
    assert _code(result) == INVARIANT_VIOLATION
    assert harness.invocations() == (stored,)
    assert harness.runs() == (run,)


@pytest.mark.parametrize("stored_state", [_C.STARTING, _C.EXITED])
def test_a_same_state_request_at_the_matching_revision_replays_without_a_write(
    harness: _Harness, stored_state: CommandInvocationState
) -> None:
    stored = sample_invocation(stored_state, kind=_K.DESCRIBE)
    harness.seed(invocations=(stored,))
    replayed = _ok(
        harness.transition(
            _shaped_request(INVOCATION_ID, stored.revision, stored_state)
        )
    )
    assert replayed == stored
    assert replayed.updated_at_utc != NOW
    assert harness.invocations() == (stored,)


@pytest.mark.parametrize("stored_state", [_C.STARTING, _C.EXITED])
def test_a_same_state_request_at_a_stale_revision_is_a_concurrency_conflict(
    harness: _Harness, stored_state: CommandInvocationState
) -> None:
    stored = sample_invocation(stored_state, kind=_K.DESCRIBE)
    harness.seed(invocations=(stored,))
    result = harness.transition(
        _shaped_request(INVOCATION_ID, stored.revision + 1, stored_state)
    )
    assert _code(result) == CONCURRENCY_CONFLICT
    assert harness.invocations() == (stored,)


@pytest.mark.parametrize("stored_state", sorted(TERMINAL_COMMAND_INVOCATION_STATES))
def test_a_terminal_record_rejects_every_other_target(
    harness: _Harness, stored_state: CommandInvocationState
) -> None:
    stored = sample_invocation(stored_state, kind=_K.DESCRIBE)
    harness.seed(invocations=(stored,))
    for target in _C:
        if target is stored_state:
            continue
        result = harness.transition(
            _shaped_request(INVOCATION_ID, stored.revision, target)
        )
        assert _code(result) == INVARIANT_VIOLATION, target
    assert harness.invocations() == (stored,)


@pytest.mark.parametrize(
    ("stored_state", "target"),
    [
        (_C.PENDING, _C.RUNNING),
        (_C.PENDING, _C.EXITED),
        (_C.PENDING, _C.TIMED_OUT),
        (_C.PENDING, _C.FAILED_TO_START),
        (_C.STARTING, _C.EXITED),
        (_C.STARTING, _C.PROTOCOL_FAILED),
        (_C.RUNNING, _C.STARTING),
        (_C.RUNNING, _C.FAILED_TO_START),
    ],
)
def test_a_non_permitted_edge_is_an_invariant_violation(
    harness: _Harness,
    stored_state: CommandInvocationState,
    target: CommandInvocationState,
) -> None:
    stored = sample_invocation(stored_state, kind=_K.DESCRIBE)
    harness.seed(invocations=(stored,))
    result = harness.transition(_shaped_request(INVOCATION_ID, stored.revision, target))
    assert _code(result) == INVARIANT_VIOLATION
    assert harness.invocations() == (stored,)


def test_a_stale_revision_on_a_permitted_edge_is_a_conflict_with_no_write(
    harness: _Harness,
) -> None:
    stored = sample_invocation(_C.PENDING, kind=_K.DESCRIBE)
    harness.seed(invocations=(stored,))
    result = harness.transition(
        _transition_request(INVOCATION_ID, stored.revision + 1, _C.STARTING)
    )
    assert _code(result) == CONCURRENCY_CONFLICT
    assert harness.invocations() == (stored,)


def test_a_missing_invocation_is_an_invariant_violation(harness: _Harness) -> None:
    result = harness.transition(_transition_request(INVOCATION_ID, 0, _C.STARTING))
    assert _code(result) == INVARIANT_VIOLATION
    assert harness.invocations() == ()


# --------------------------------------------------------------------------
# transition_invocation: terminal targets, the exit pair and diagnostics
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("native_exit_value", "category"),
    [
        (0, ProcessExitCategory.SUCCESS),
        (10, ProcessExitCategory.VALIDATION_FAILURE),
        (70, ProcessExitCategory.PROTOCOL_VIOLATION),
    ],
)
def test_running_to_exited_with_a_recognized_exit_records_the_pair(
    harness: _Harness, native_exit_value: int, category: ProcessExitCategory
) -> None:
    stored = sample_invocation(_C.RUNNING, kind=_K.DESCRIBE)
    harness.seed(invocations=(stored,))
    exited = _ok(
        harness.transition(
            _transition_request(
                INVOCATION_ID,
                stored.revision,
                _C.EXITED,
                native_exit_value=native_exit_value,
            )
        )
    )
    assert exited.state is _C.EXITED
    assert exited.native_exit_value == native_exit_value
    assert exited.process_exit_category is category
    assert exited.completed_at_utc == NOW
    assert exited.updated_at_utc == NOW
    assert exited.revision == stored.revision + 1
    assert _missing(exited.primary_diagnostic_id)
    assert exited.diagnostic_ids == ()
    assert exited.cleanup_complete is False
    assert exited.process_created is True
    assert exited.launch_attempted_at_utc == stored.launch_attempted_at_utc
    assert exited.deadline_utc == stored.deadline_utc
    assert exited.pid_identity == stored.pid_identity
    assert exited.process_started_at_utc == stored.process_started_at_utc
    assert harness.invocations() == (exited,)


@pytest.mark.parametrize(
    ("primary", "seeded"),
    [(False, None), (True, None), (True, sample_diagnostic(DIAG_ID))],
    ids=["no-primary", "primary-not-stored", "primary-with-another-code"],
)
def test_an_unrecognized_exit_is_rejected_unless_its_primary_resolves(
    harness: _Harness, primary: bool, seeded: Diagnostic | None
) -> None:
    stored = sample_invocation(_C.RUNNING, kind=_K.DESCRIBE)
    harness.seed(invocations=(stored,))
    if seeded is not None:
        assert seeded.error_code != UNRECOGNIZED_PROCESS_EXIT
        harness.store.seed_diagnostic(seeded)
    # The request constructs: only the record and the service require a primary.
    request = _transition_request(
        INVOCATION_ID,
        stored.revision,
        _C.EXITED,
        native_exit_value=3,
        primary_diagnostic_id=DIAG_ID if primary else None,
    )
    assert _code(harness.transition(request)) == INVARIANT_VIOLATION
    assert harness.invocations() == (stored,)


def test_an_unrecognized_exit_is_accepted_when_the_primary_resolves_to_the_code(
    harness: _Harness,
) -> None:
    stored = sample_invocation(_C.RUNNING, kind=_K.DESCRIBE)
    harness.seed(invocations=(stored,))
    harness.store.seed_diagnostic(
        sample_diagnostic(DIAG_ID, error_code=UNRECOGNIZED_PROCESS_EXIT)
    )
    exited = _ok(
        harness.transition(
            _transition_request(
                INVOCATION_ID,
                stored.revision,
                _C.EXITED,
                native_exit_value=3,
                primary_diagnostic_id=DIAG_ID,
            )
        )
    )
    assert exited.state is _C.EXITED
    assert exited.native_exit_value == 3
    assert exited.process_exit_category is ProcessExitCategory.RUNTIME_FAILURE
    assert exited.primary_diagnostic_id == DIAG_ID
    assert exited.diagnostic_ids == (DIAG_ID,)
    assert exited.completed_at_utc == NOW
    assert exited.revision == stored.revision + 1
    assert harness.invocations() == (exited,)


def _planted_reader_failure(code: str) -> Failure:
    """A correctly formed persistence read ``Failure`` -- built by the factory the
    SQLite reader uses for a refused ``diagnostics.get`` -- planted through the
    overriding double. A result-propagation double, not a database failure."""
    return persistence_failure(
        code,
        message="get on diagnostics was refused by the database",
        clock=FixedClock(INSTANT),
        details={"table": "diagnostics", "operation": "get", "identity": DIAG_ID},
    )


def _unrecognized_exit_request(revision: int) -> InvocationTransitionRequest:
    return _transition_request(
        INVOCATION_ID,
        revision,
        _C.EXITED,
        native_exit_value=3,
        primary_diagnostic_id=DIAG_ID,
    )


@pytest.mark.parametrize(
    "code",
    [WRITE_FAILED, STORAGE_UNAVAILABLE, CONCURRENCY_CONFLICT],
    ids=["write-failed", "storage-unavailable", "concurrency-conflict"],
)
def test_a_non_invariant_primary_read_failure_is_returned_unchanged(
    harness: _Harness, code: str
) -> None:
    """Result propagation (correction D): the primary diagnostic IS recorded, so
    absence cannot explain the reader's ``Failure``; the operation returns that very
    object -- code, details and identity intact -- from its one attempt, and
    nothing is written. A conflict returned by a read is not a lost swap, so the
    driver does not reload."""
    stored = sample_invocation(_C.RUNNING, kind=_K.DESCRIBE)
    harness.seed(invocations=(stored,))
    harness.store.seed_diagnostic(
        sample_diagnostic(DIAG_ID, error_code=UNRECOGNIZED_PROCESS_EXIT)
    )
    planted = _planted_reader_failure(code)
    overriding = MemberOverridingUnitOfWork(
        harness.root(), "diagnostics", {"get": lambda diagnostic_id: planted}
    )
    outcome = transition_invocation(
        _unrecognized_exit_request(stored.revision),
        unit_of_work=overriding,
        clock=harness.clock,
    )
    assert outcome is planted
    assert _code(outcome) == code
    assert overriding.begins == 1
    assert harness.invocations() == (stored,)


def test_an_invariant_primary_read_keeps_the_absence_invariant(
    harness: _Harness,
) -> None:
    """The invariant class keeps the operation's own "does not exist" invariant:
    the repositories' invariant-coded reads do not distinguish a missing row from a
    stored row the canonical model refuses (recorded limitation), so this pass
    preserves the established behaviour for that class."""
    stored = sample_invocation(_C.RUNNING, kind=_K.DESCRIBE)
    harness.seed(invocations=(stored,))
    planted = _planted_reader_failure(INVARIANT_VIOLATION)
    overriding = MemberOverridingUnitOfWork(
        harness.root(), "diagnostics", {"get": lambda diagnostic_id: planted}
    )
    outcome = transition_invocation(
        _unrecognized_exit_request(stored.revision),
        unit_of_work=overriding,
        clock=harness.clock,
    )
    assert isinstance(outcome, Failure)
    assert outcome is not planted
    assert _code(outcome) == INVARIANT_VIOLATION
    assert outcome.diagnostics[0].message.endswith("does not exist")
    assert overriding.begins == 1
    assert harness.invocations() == (stored,)


def test_a_describe_fails_to_start_without_any_run_linkage(harness: _Harness) -> None:
    stored = sample_invocation(_C.STARTING, kind=_K.DESCRIBE)
    harness.seed(invocations=(stored,))
    failed = _ok(
        harness.transition(
            _transition_request(
                INVOCATION_ID,
                stored.revision,
                _C.FAILED_TO_START,
                primary_diagnostic_id=DIAG_ID,
            )
        )
    )
    assert failed.state is _C.FAILED_TO_START
    assert failed.primary_diagnostic_id == DIAG_ID
    assert failed.diagnostic_ids == (DIAG_ID,)
    assert failed.completed_at_utc == NOW
    assert failed.updated_at_utc == NOW
    assert failed.revision == stored.revision + 1
    assert failed.process_created is False
    assert _missing(failed.native_exit_value)
    assert _missing(failed.process_exit_category)
    assert failed.launch_attempted_at_utc == stored.launch_attempted_at_utc
    assert failed.deadline_utc == stored.deadline_utc
    assert harness.runs() == ()
    assert harness.invocations() == (failed,)


@pytest.mark.parametrize(("stored_state", "target"), COUPLED_EDGES)
def test_a_coupled_terminal_target_is_refused_while_the_linked_run_is_open(
    harness: _Harness,
    stored_state: CommandInvocationState,
    target: CommandInvocationState,
) -> None:
    stored = sample_invocation(stored_state, kind=_K.VALIDATE)
    run = _run(_R.VALIDATING)
    harness.seed(runs=(run,), invocations=(stored,))
    result = harness.transition(
        _transition_request(
            INVOCATION_ID, stored.revision, target, primary_diagnostic_id=DIAG_ID
        )
    )
    # The outcome belongs to transition_invocation_and_run (spec 15.2 coupling).
    assert _code(result) == INVARIANT_VIOLATION
    assert harness.invocations() == (stored,)
    assert harness.runs() == (run,)


@pytest.mark.parametrize(("stored_state", "target"), COUPLED_EDGES)
def test_a_coupled_terminal_target_proceeds_alone_once_the_linked_run_is_terminal(
    harness: _Harness,
    stored_state: CommandInvocationState,
    target: CommandInvocationState,
) -> None:
    stored = sample_invocation(stored_state, kind=_K.VALIDATE)
    run = _run(_R.FAILED)
    harness.seed(runs=(run,), invocations=(stored,))
    finished = _ok(
        harness.transition(
            _transition_request(
                INVOCATION_ID, stored.revision, target, primary_diagnostic_id=DIAG_ID
            )
        )
    )
    assert finished.state is target
    assert finished.completed_at_utc == NOW
    assert finished.primary_diagnostic_id == DIAG_ID
    assert finished.diagnostic_ids == (DIAG_ID,)
    assert finished.revision == stored.revision + 1
    assert finished.run_id == RUN_ID
    assert finished.process_created is stored.process_created
    assert finished.pid_identity == stored.pid_identity
    assert finished.launch_attempted_at_utc == stored.launch_attempted_at_utc
    assert _missing(finished.native_exit_value)
    assert harness.invocations() == (finished,)
    assert harness.runs() == (run,)


def test_exited_couples_nothing_so_a_validate_may_exit_while_its_run_validates(
    harness: _Harness,
) -> None:
    stored = sample_invocation(_C.RUNNING, kind=_K.VALIDATE)
    run = _run(_R.VALIDATING)
    harness.seed(runs=(run,), invocations=(stored,))
    exited = _ok(
        harness.transition(
            _transition_request(
                INVOCATION_ID, stored.revision, _C.EXITED, native_exit_value=0
            )
        )
    )
    assert exited.state is _C.EXITED
    assert exited.process_exit_category is ProcessExitCategory.SUCCESS
    assert harness.invocations() == (exited,)
    assert harness.runs() == (run,)


def test_diagnostic_ids_merge_the_stored_and_requested_sets_in_sorted_order(
    harness: _Harness,
) -> None:
    stored = _amended(
        sample_invocation(_C.RUNNING, kind=_K.DESCRIBE), diagnostic_ids=(THIRD_DIAG_ID,)
    )
    harness.seed(invocations=(stored,))
    cancelled = _ok(
        harness.transition(
            _transition_request(
                INVOCATION_ID,
                stored.revision,
                _C.CANCELLED,
                primary_diagnostic_id=DIAG_ID,
                diagnostic_ids=(DIAG_ID, OTHER_DIAG_ID),
            )
        )
    )
    assert cancelled.state is _C.CANCELLED
    assert cancelled.primary_diagnostic_id == DIAG_ID
    # THIRD sorts first: the union is re-sorted, not appended.
    assert cancelled.diagnostic_ids == (THIRD_DIAG_ID, DIAG_ID, OTHER_DIAG_ID)
    assert cancelled.diagnostic_ids == tuple(sorted(cancelled.diagnostic_ids))
    assert cancelled.completed_at_utc == NOW
    assert harness.invocations() == (cancelled,)


# --------------------------------------------------------------------------
# enrich_invocation: the four write-once enrichments (plan 6)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        (
            {"native_exit_value": 50},
            {
                "native_exit_value": 50,
                "process_exit_category": ProcessExitCategory.CANCELLED,
            },
        ),
        (
            {"cleanup_complete": True},
            {"cleanup_complete": True, "cleanup_completed_at_utc": NOW},
        ),
        ({"stderr_artifact_id": ARTIFACT_ID}, {"stderr_artifact_id": ARTIFACT_ID}),
        (
            {"additional_diagnostic_ids": (OTHER_DIAG_ID,)},
            {"diagnostic_ids": (DIAG_ID, OTHER_DIAG_ID)},
        ),
    ],
    ids=["native-exit-pair", "cleanup", "stderr", "additional-diagnostics"],
)
def test_each_of_the_four_enrichments_alone_is_accepted_on_a_terminal_record(
    harness: _Harness, fields: dict[str, object], expected: dict[str, object]
) -> None:
    stored = sample_invocation(_C.CANCELLED, kind=_K.DESCRIBE)
    assert stored.primary_diagnostic_id == DIAG_ID
    harness.seed(invocations=(stored,))
    enriched = _ok(
        harness.enrich(_enrichment_request(INVOCATION_ID, stored.revision, **fields))
    )
    assert enriched.state is stored.state
    assert enriched.revision == stored.revision + 1
    assert enriched.updated_at_utc == NOW
    for name, value in expected.items():
        assert getattr(enriched, name) == value, name
    moved = set(expected) | {"updated_at_utc", "revision"}
    for name in set(CommandInvocationRecord.model_fields) - moved:
        assert getattr(enriched, name) == getattr(stored, name), name
    assert harness.invocations() == (enriched,)


def test_enrichment_never_changes_state_or_a_recorded_outcome(
    harness: _Harness,
) -> None:
    stored = sample_invocation(_C.EXITED, kind=_K.DESCRIBE)
    harness.seed(invocations=(stored,))
    enriched = _ok(
        harness.enrich(
            _enrichment_request(INVOCATION_ID, stored.revision, cleanup_complete=True)
        )
    )
    assert enriched.state is _C.EXITED
    assert enriched.native_exit_value == stored.native_exit_value
    assert enriched.process_exit_category is stored.process_exit_category
    assert enriched.cleanup_complete is True
    assert enriched.cleanup_completed_at_utc == NOW
    assert enriched.revision == stored.revision + 1


def test_overwriting_a_recorded_native_exit_pair_is_rejected(
    harness: _Harness,
) -> None:
    stored = _amended(
        sample_invocation(_C.CANCELLED, kind=_K.DESCRIBE),
        native_exit_value=50,
        process_exit_category=ProcessExitCategory.CANCELLED,
    )
    harness.seed(invocations=(stored,))
    result = harness.enrich(
        _enrichment_request(INVOCATION_ID, stored.revision, native_exit_value=40)
    )
    assert _code(result) == INVARIANT_VIOLATION
    assert harness.invocations() == (stored,)


def test_replacing_a_recorded_stderr_reference_is_rejected(
    harness: _Harness,
) -> None:
    stored = _amended(
        sample_invocation(_C.CANCELLED, kind=_K.DESCRIBE),
        stderr_artifact_id=ARTIFACT_ID,
    )
    harness.seed(invocations=(stored,))
    result = harness.enrich(
        _enrichment_request(
            INVOCATION_ID, stored.revision, stderr_artifact_id=OTHER_ARTIFACT_ID
        )
    )
    assert _code(result) == INVARIANT_VIOLATION
    assert harness.invocations() == (stored,)


def test_an_enrichment_that_adds_nothing_is_rejected(harness: _Harness) -> None:
    cleanup_instant = INSTANT + timedelta(seconds=20)
    stored = _amended(
        sample_invocation(_C.CANCELLED, kind=_K.DESCRIBE),
        native_exit_value=50,
        process_exit_category=ProcessExitCategory.CANCELLED,
        cleanup_complete=True,
        cleanup_completed_at_utc=cleanup_instant,
        stderr_artifact_id=ARTIFACT_ID,
        diagnostic_ids=(DIAG_ID, OTHER_DIAG_ID),
    )
    harness.seed(invocations=(stored,))
    restated = harness.enrich(
        _enrichment_request(
            INVOCATION_ID,
            stored.revision,
            native_exit_value=50,
            cleanup_complete=True,
            stderr_artifact_id=ARTIFACT_ID,
            additional_diagnostic_ids=(OTHER_DIAG_ID,),
        )
    )
    assert _code(restated) == INVARIANT_VIOLATION
    empty = harness.enrich(_enrichment_request(INVOCATION_ID, stored.revision))
    assert _code(empty) == INVARIANT_VIOLATION
    assert harness.invocations() == (stored,)


def test_a_restated_cleanup_keeps_its_original_instant_while_stderr_is_added(
    harness: _Harness,
) -> None:
    cleanup_instant = INSTANT + timedelta(seconds=20)
    stored = _amended(
        sample_invocation(_C.CANCELLED, kind=_K.DESCRIBE),
        cleanup_complete=True,
        cleanup_completed_at_utc=cleanup_instant,
    )
    harness.seed(invocations=(stored,))
    enriched = _ok(
        harness.enrich(
            _enrichment_request(
                INVOCATION_ID,
                stored.revision,
                cleanup_complete=True,
                stderr_artifact_id=ARTIFACT_ID,
            )
        )
    )
    assert enriched.cleanup_complete is True
    assert enriched.cleanup_completed_at_utc == cleanup_instant
    assert enriched.cleanup_completed_at_utc != NOW
    assert enriched.stderr_artifact_id == ARTIFACT_ID
    assert enriched.state is stored.state
    assert enriched.revision == stored.revision + 1
    assert enriched.updated_at_utc == NOW
    assert harness.invocations() == (enriched,)


@pytest.mark.parametrize("stored_state", [_C.PENDING, _C.STARTING, _C.RUNNING])
def test_a_non_terminal_record_rejects_enrichment(
    harness: _Harness, stored_state: CommandInvocationState
) -> None:
    stored = sample_invocation(stored_state, kind=_K.DESCRIBE)
    harness.seed(invocations=(stored,))
    # Additional diagnostics are the one enrichment a non-terminal shape could
    # hold, so only the terminal-state rule can reject this request.
    result = harness.enrich(
        _enrichment_request(
            INVOCATION_ID, stored.revision, additional_diagnostic_ids=(OTHER_DIAG_ID,)
        )
    )
    assert _code(result) == INVARIANT_VIOLATION
    assert harness.invocations() == (stored,)


def test_a_stale_enrichment_revision_is_a_concurrency_conflict_with_no_write(
    harness: _Harness,
) -> None:
    stored = sample_invocation(_C.CANCELLED, kind=_K.DESCRIBE)
    harness.seed(invocations=(stored,))
    result = harness.enrich(
        _enrichment_request(
            INVOCATION_ID, stored.revision + 1, stderr_artifact_id=ARTIFACT_ID
        )
    )
    assert _code(result) == CONCURRENCY_CONFLICT
    assert harness.invocations() == (stored,)


def test_enriching_a_missing_invocation_is_an_invariant_violation(
    harness: _Harness,
) -> None:
    result = harness.enrich(
        _enrichment_request(INVOCATION_ID, 3, stderr_artifact_id=ARTIFACT_ID)
    )
    assert _code(result) == INVARIANT_VIOLATION
    assert harness.invocations() == ()
