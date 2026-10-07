"""Stage 5 Task 6: the three linked operations that couple a RUN invocation to its run.

Plan section 6 ("Linked operations", "Process-start handoff by command kind" and
"Coupled terminal transitions"), section 5's edge ownership (``READY -> STARTING``
and ``STARTING -> RUNNING`` belong to the linked launch operations alone) and the
section 10.1 rows ``begin_linked_launch``, ``start_linked_run`` and
``transition_invocation_and_run``. The signatures, request shapes and result
codes asserted here are those declared by ``invocation_service``,
``run_service`` and ``requests``.

Every case hands the operation the ROOT ``InMemoryUnitOfWork`` -- the service
begins its own transaction -- seeds state through a transaction of its own, and
inspects the backing store's committed rows, so "nothing durable" is asserted
against the store rather than inferred from the result value. The clock is fixed
one minute after the fixture instant so every accepted write moves
``updated_at_utc`` forward. The module fails at collection until
``crypto_lab.experiments.invocation_service``, ``run_service`` and ``requests``
exist: the intended RED of the linked half of Task 6.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Final

import pytest
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.domain.command_invocation import (
    CommandInvocationRecord,
    ProcessStartFacts,
)
from crypto_lab.domain.diagnostics import DiagnosticCategory
from crypto_lab.domain.engine_run import EngineRunRecord, is_mixed_running_pair
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.experiments.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
)
from crypto_lab.experiments.invocation_service import (
    LinkedPair,
    begin_linked_launch,
    start_linked_run,
    transition_invocation,
    transition_invocation_and_run,
)
from crypto_lab.experiments.ports import UnitOfWork
from crypto_lab.experiments.requests import (
    CoupledTransitionRequest,
    InvocationTransitionRequest,
    LinkedLaunchRequest,
    LinkedStartRequest,
    RunTransitionRequest,
)
from crypto_lab.experiments.run_service import transition_run
from crypto_lab.persistence.diagnostics import (
    STORAGE_UNAVAILABLE,
    WRITE_FAILED,
    persistence_failure,
)
from doubles.experiments import (
    ADAPTER_BETA,
    AVAIL_A,
    AVAIL_B,
    DIAG_ID,
    ENGINE_BETA,
    INSTANT,
    OTHER_RUN_ID,
    RUN_ID,
    SLOT_B,
    FixedClock,
    InMemoryBackingStore,
    InMemoryUnitOfWork,
    MemberOverridingUnitOfWork,
    sample_diagnostic,
    sample_experiment,
    sample_invocation,
    sample_process_start,
    sample_run,
)

_E: Final = ExperimentState
_R: Final = EngineRunState
_C: Final = CommandInvocationState
_K: Final = CommandKind

#: Every fixture record is stamped at or before ``INSTANT + 11s``; the operations
#: run one minute later so ``updated_at_utc`` never moves backwards.
LATER: Final = INSTANT + timedelta(minutes=1)
#: Any well-formed ``ErrorCode``; the services record it, they do not interpret it.
REASON: Final = "TEST.LINKED_OPERATION"


# --------------------------------------------------------------------------
# Harness and helpers (style of test_port_contracts.py)
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Harness:
    """One backing store, its root unit of work and the clock every operation reads."""

    store: InMemoryBackingStore
    root: InMemoryUnitOfWork
    clock: FixedClock

    def launch(self, request: LinkedLaunchRequest) -> Result[LinkedPair]:
        return begin_linked_launch(request, unit_of_work=self.root, clock=self.clock)

    def start(self, request: LinkedStartRequest) -> Result[LinkedPair]:
        return start_linked_run(request, unit_of_work=self.root, clock=self.clock)

    def couple(self, request: CoupledTransitionRequest) -> Result[LinkedPair]:
        return transition_invocation_and_run(
            request, unit_of_work=self.root, clock=self.clock
        )

    def run_only(self, request: RunTransitionRequest) -> Result[EngineRunRecord]:
        return transition_run(request, unit_of_work=self.root, clock=self.clock)

    def invocation_only(
        self,
        request: InvocationTransitionRequest,
    ) -> Result[CommandInvocationRecord]:
        return transition_invocation(request, unit_of_work=self.root, clock=self.clock)


@pytest.fixture
def harness() -> _Harness:
    store = InMemoryBackingStore()
    return _Harness(
        store=store, root=InMemoryUnitOfWork(store), clock=FixedClock(LATER)
    )


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


def _seed(
    harness: _Harness,
    *records: CommandInvocationRecord | EngineRunRecord,
) -> None:
    """Commit the RUNNING experiment and ``records`` through one transaction."""
    transaction = harness.root.begin()
    _ok(transaction.experiments.add(sample_experiment(_E.RUNNING)))
    for record in records:
        if isinstance(record, EngineRunRecord):
            _ok(transaction.engine_runs.add_attempt(record))
        else:
            _ok(transaction.command_invocations.add(record))
    _commit(transaction)


def _assert_durable(
    harness: _Harness,
    invocation: CommandInvocationRecord,
    run: EngineRunRecord,
) -> None:
    """The committed invocation and run rows are exactly these two records."""
    assert harness.store.committed_command_invocations() == (invocation,)
    assert harness.store.committed_engine_runs() == (run,)


def _launch_request(
    invocation: CommandInvocationRecord,
    run: EngineRunRecord,
    *,
    invocation_revision: int | None = None,
    run_revision: int | None = None,
) -> LinkedLaunchRequest:
    return LinkedLaunchRequest(
        schema_version="1.0.0",
        invocation_id=invocation.invocation_id,
        expected_invocation_revision=(
            invocation.revision if invocation_revision is None else invocation_revision
        ),
        run_id=run.run_id,
        expected_run_revision=run.revision if run_revision is None else run_revision,
    )


def _start_request(
    invocation: CommandInvocationRecord,
    run: EngineRunRecord,
    *,
    process_start: ProcessStartFacts | None = None,
    invocation_revision: int | None = None,
    run_revision: int | None = None,
) -> LinkedStartRequest:
    facts = sample_process_start() if process_start is None else process_start
    return LinkedStartRequest(
        schema_version="1.0.0",
        invocation_id=invocation.invocation_id,
        expected_invocation_revision=(
            invocation.revision if invocation_revision is None else invocation_revision
        ),
        run_id=run.run_id,
        expected_run_revision=run.revision if run_revision is None else run_revision,
        process_start=facts,
    )


def _invocation_request(
    invocation: CommandInvocationRecord,
    target: CommandInvocationState,
    *,
    expected_revision: int | None = None,
    process_start: ProcessStartFacts | None = None,
    native_exit_value: int | None = None,
    primary_diagnostic_id: str | None = DIAG_ID,
) -> InvocationTransitionRequest:
    """A transition request whose primary diagnostic, when present, is also its
    only listed diagnostic; every absent fact is ``MISSING``."""
    diagnostic_ids = () if primary_diagnostic_id is None else (primary_diagnostic_id,)
    return InvocationTransitionRequest(
        schema_version="1.0.0",
        invocation_id=invocation.invocation_id,
        expected_revision=(
            invocation.revision if expected_revision is None else expected_revision
        ),
        target_state=target,
        reason_code=REASON,
        process_start=MISSING if process_start is None else process_start,
        native_exit_value=MISSING if native_exit_value is None else native_exit_value,
        primary_diagnostic_id=(
            MISSING if primary_diagnostic_id is None else primary_diagnostic_id
        ),
        diagnostic_ids=diagnostic_ids,
    )


def _run_request(
    run: EngineRunRecord,
    target: EngineRunState,
    *,
    expected_revision: int | None = None,
    primary_terminal_diagnostic_id: str | None = DIAG_ID,
    availability_observation_id: str | None = None,
) -> RunTransitionRequest:
    return RunTransitionRequest(
        schema_version="1.0.0",
        run_id=run.run_id,
        expected_revision=(
            run.revision if expected_revision is None else expected_revision
        ),
        target_state=target,
        reason_code=REASON,
        primary_terminal_diagnostic_id=(
            MISSING
            if primary_terminal_diagnostic_id is None
            else primary_terminal_diagnostic_id
        ),
        availability_observation_id=(
            MISSING
            if availability_observation_id is None
            else availability_observation_id
        ),
    )


def _coupled_request(
    invocation: CommandInvocationRecord,
    run: EngineRunRecord,
    invocation_target: CommandInvocationState,
    run_target: EngineRunState,
    *,
    invocation_revision: int | None = None,
    run_revision: int | None = None,
    availability_observation_id: str | None = None,
    native_exit_value: int | None = None,
) -> CoupledTransitionRequest:
    return CoupledTransitionRequest(
        schema_version="1.0.0",
        invocation=_invocation_request(
            invocation,
            invocation_target,
            expected_revision=invocation_revision,
            native_exit_value=native_exit_value,
        ),
        run=_run_request(
            run,
            run_target,
            expected_revision=run_revision,
            availability_observation_id=availability_observation_id,
        ),
    )


# --------------------------------------------------------------------------
# begin_linked_launch (plan 6 "Linked operations" row 1; 10.1)
# --------------------------------------------------------------------------


def test_begin_linked_launch_moves_both_records_to_starting_atomically(
    harness: _Harness,
) -> None:
    invocation = sample_invocation(_C.PENDING)
    run = sample_run(_R.READY)
    _seed(harness, invocation, run)
    pair = _ok(harness.launch(_launch_request(invocation, run)))
    assert isinstance(pair, LinkedPair)
    assert tuple(LinkedPair.model_fields) == ("invocation", "run")
    launched, started = pair.invocation, pair.run
    assert launched.invocation_id == invocation.invocation_id
    assert launched.run_id == RUN_ID
    assert launched.state is _C.STARTING
    # Launch facts come from the one clock observation of this transaction.
    assert launched.launch_attempted_at_utc == LATER
    deadline = LATER + timedelta(seconds=invocation.timeout_seconds)
    assert launched.deadline_utc == deadline
    assert launched.process_created is False
    assert _missing(launched.pid_identity)
    assert _missing(launched.process_started_at_utc)
    assert launched.diagnostic_ids == ()
    assert launched.updated_at_utc == LATER
    assert launched.revision == invocation.revision + 1
    assert started.run_id == RUN_ID
    assert started.state is _R.STARTING
    # The READY-time observation identity is carried, not re-supplied.
    assert started.availability_observation_id == AVAIL_A
    assert _missing(started.primary_terminal_diagnostic_id)
    assert started.updated_at_utc == LATER
    assert started.revision == run.revision + 1
    _assert_durable(harness, launched, started)
    assert harness.store.committed_experiments() == (sample_experiment(_E.RUNNING),)


@pytest.mark.parametrize(("invocation_offset", "run_offset"), [(1, 0), (0, 1)])
def test_begin_linked_launch_with_a_stale_revision_conflicts_and_writes_nothing(
    harness: _Harness,
    invocation_offset: int,
    run_offset: int,
) -> None:
    invocation = sample_invocation(_C.PENDING)
    run = sample_run(_R.READY)
    _seed(harness, invocation, run)
    request = _launch_request(
        invocation,
        run,
        invocation_revision=invocation.revision + invocation_offset,
        run_revision=run.revision + run_offset,
    )
    assert _code(harness.launch(request)) == CONCURRENCY_CONFLICT
    _assert_durable(harness, invocation, run)


def test_begin_linked_launch_leaves_the_invocation_pending_when_the_run_is_not_ready(
    harness: _Harness,
) -> None:
    # The invocation half (PENDING -> STARTING) is lawful on its own; the run half
    # (VALIDATING -> STARTING) is not, and neither may land.
    invocation = sample_invocation(_C.PENDING)
    run = sample_run(_R.VALIDATING)
    _seed(harness, invocation, run)
    result = harness.launch(_launch_request(invocation, run))
    assert _code(result) == INVARIANT_VIOLATION
    _assert_durable(harness, invocation, run)


def test_begin_linked_launch_leaves_the_run_ready_when_the_invocation_is_not_pending(
    harness: _Harness,
) -> None:
    invocation = sample_invocation(_C.STARTING)
    run = sample_run(_R.READY)
    _seed(harness, invocation, run)
    result = harness.launch(_launch_request(invocation, run))
    assert _code(result) == INVARIANT_VIOLATION
    _assert_durable(harness, invocation, run)


def test_begin_linked_launch_rejects_a_validate_invocation(harness: _Harness) -> None:
    # (PENDING, READY) is the lawful launch pair, so only the kind rule rejects.
    invocation = sample_invocation(_C.PENDING, kind=_K.VALIDATE)
    run = sample_run(_R.READY)
    _seed(harness, invocation, run)
    result = harness.launch(_launch_request(invocation, run))
    assert _code(result) == INVARIANT_VIOLATION
    _assert_durable(harness, invocation, run)


def test_begin_linked_launch_rejects_a_request_naming_another_run(
    harness: _Harness,
) -> None:
    invocation = sample_invocation(_C.PENDING)
    run = sample_run(_R.READY)
    other_run = sample_run(
        _R.READY,
        run_id=OTHER_RUN_ID,
        logical_slot_id=SLOT_B,
        adapter=ADAPTER_BETA,
        engine=ENGINE_BETA,
        availability_observation_id=AVAIL_B,
    )
    _seed(harness, invocation, run, other_run)
    # The invocation links RUN_ID; the request names the other READY run at its
    # correct revision, so only the linkage rule can reject it.
    result = harness.launch(_launch_request(invocation, other_run))
    assert _code(result) == INVARIANT_VIOLATION
    assert harness.store.committed_command_invocations() == (invocation,)
    assert harness.store.committed_engine_runs() == (run, other_run)


def test_begin_linked_launch_replays_a_completed_launch_without_a_write(
    harness: _Harness,
) -> None:
    invocation = sample_invocation(_C.STARTING)
    run = sample_run(_R.STARTING)
    _seed(harness, invocation, run)
    pair = _ok(harness.launch(_launch_request(invocation, run)))
    assert pair.invocation == invocation
    assert pair.run == run
    _assert_durable(harness, invocation, run)


def test_begin_linked_launch_requires_both_records_to_exist(harness: _Harness) -> None:
    invocation = sample_invocation(_C.PENDING)
    run = sample_run(_R.READY)
    request = _launch_request(invocation, run)
    _seed(harness)
    assert _code(harness.launch(request)) == INVARIANT_VIOLATION
    assert harness.store.committed_command_invocations() == ()
    assert harness.store.committed_engine_runs() == ()
    only_invocation = harness.root.begin()
    _ok(only_invocation.command_invocations.add(invocation))
    _commit(only_invocation)
    assert _code(harness.launch(request)) == INVARIANT_VIOLATION
    assert harness.store.committed_command_invocations() == (invocation,)
    assert harness.store.committed_engine_runs() == ()


# --------------------------------------------------------------------------
# start_linked_run (plan 6 "Linked operations" row 2, "Process-start handoff")
# --------------------------------------------------------------------------


def test_start_linked_run_moves_both_records_to_running_with_the_process_facts(
    harness: _Harness,
) -> None:
    invocation = sample_invocation(_C.STARTING)
    run = sample_run(_R.STARTING)
    _seed(harness, invocation, run)
    # The start instant is a supervisor observation (plan 3.2), so it is taken
    # from the request and deliberately differs from the clock.
    facts = sample_process_start(
        pid=777, process_started_at_utc=LATER - timedelta(seconds=1)
    )
    pair = _ok(harness.start(_start_request(invocation, run, process_start=facts)))
    running, started = pair.invocation, pair.run
    assert running.state is _C.RUNNING
    assert running.process_created is True
    assert running.pid_identity == facts.pid_identity
    assert running.pid_identity.pid == 777
    assert running.process_started_at_utc == facts.process_started_at_utc
    assert running.process_started_at_utc != LATER
    # Launch facts established by begin_linked_launch are carried unchanged.
    assert running.launch_attempted_at_utc == invocation.launch_attempted_at_utc
    assert running.deadline_utc == invocation.deadline_utc
    assert running.updated_at_utc == LATER
    assert running.revision == invocation.revision + 1
    assert started.state is _R.RUNNING
    assert started.availability_observation_id == AVAIL_A
    assert started.updated_at_utc == LATER
    assert started.revision == run.revision + 1
    _assert_durable(harness, running, started)


@pytest.mark.parametrize(("invocation_offset", "run_offset"), [(1, 0), (0, 1)])
def test_start_linked_run_with_a_stale_revision_conflicts_and_writes_nothing(
    harness: _Harness,
    invocation_offset: int,
    run_offset: int,
) -> None:
    invocation = sample_invocation(_C.STARTING)
    run = sample_run(_R.STARTING)
    _seed(harness, invocation, run)
    request = _start_request(
        invocation,
        run,
        invocation_revision=invocation.revision + invocation_offset,
        run_revision=run.revision + run_offset,
    )
    assert _code(harness.start(request)) == CONCURRENCY_CONFLICT
    _assert_durable(harness, invocation, run)


def test_start_linked_run_leaves_the_invocation_starting_when_the_run_is_not_starting(
    harness: _Harness,
) -> None:
    # The invocation half (STARTING -> RUNNING) is lawful on its own; the run is
    # still READY, so the pair is the half-applied launch and nothing may land.
    invocation = sample_invocation(_C.STARTING)
    run = sample_run(_R.READY)
    _seed(harness, invocation, run)
    result = harness.start(_start_request(invocation, run))
    assert _code(result) == INVARIANT_VIOLATION
    _assert_durable(harness, invocation, run)


def test_start_linked_run_replays_when_the_stored_process_facts_match(
    harness: _Harness,
) -> None:
    invocation = sample_invocation(_C.RUNNING)
    run = sample_run(_R.RUNNING)
    _seed(harness, invocation, run)
    matching = ProcessStartFacts(
        pid_identity=invocation.pid_identity,
        process_started_at_utc=invocation.process_started_at_utc,
    )
    pair = _ok(harness.start(_start_request(invocation, run, process_start=matching)))
    assert pair.invocation == invocation
    assert pair.run == run
    _assert_durable(harness, invocation, run)


def test_start_linked_run_conflicts_when_the_replayed_process_facts_differ(
    harness: _Harness,
) -> None:
    # Both records already hold RUNNING at the expected revisions, but the caller
    # claims a different process: the stored facts are the durable truth (A77).
    invocation = sample_invocation(_C.RUNNING)
    run = sample_run(_R.RUNNING)
    _seed(harness, invocation, run)
    divergent = sample_process_start(pid=invocation.pid_identity.pid + 1)
    result = harness.start(_start_request(invocation, run, process_start=divergent))
    assert _code(result) == CONCURRENCY_CONFLICT
    _assert_durable(harness, invocation, run)


def test_start_linked_run_rejects_a_validate_invocation(harness: _Harness) -> None:
    # (STARTING, STARTING) is the lawful start pair, so only the kind rule rejects.
    invocation = sample_invocation(_C.STARTING, kind=_K.VALIDATE)
    run = sample_run(_R.STARTING)
    _seed(harness, invocation, run)
    result = harness.start(_start_request(invocation, run))
    assert _code(result) == INVARIANT_VIOLATION
    _assert_durable(harness, invocation, run)


# --------------------------------------------------------------------------
# Run-only and invocation-only attempts at the linked edges (plan 5, 6)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("invocation_state", "run_state", "target"),
    [(_C.PENDING, _R.READY, _R.STARTING), (_C.STARTING, _R.STARTING, _R.RUNNING)],
)
def test_transition_run_refuses_the_two_linked_only_edges(
    harness: _Harness,
    invocation_state: CommandInvocationState,
    run_state: EngineRunState,
    target: EngineRunState,
) -> None:
    invocation = sample_invocation(invocation_state)
    run = sample_run(run_state)
    _seed(harness, invocation, run)
    request = _run_request(run, target, primary_terminal_diagnostic_id=None)
    assert _code(harness.run_only(request)) == INVARIANT_VIOLATION
    _assert_durable(harness, invocation, run)
    # Had the run-only write landed, the durable pair would be the half-applied
    # handoff the pure predicate names; the stored lawful pair is not mixed.
    assert is_mixed_running_pair(sample_run(target), invocation)
    assert not is_mixed_running_pair(run, invocation)


@pytest.mark.parametrize(
    ("invocation_state", "run_state", "target"),
    [(_C.PENDING, _R.READY, _C.STARTING), (_C.STARTING, _R.STARTING, _C.RUNNING)],
)
def test_transition_invocation_refuses_the_two_linked_only_run_kind_edges(
    harness: _Harness,
    invocation_state: CommandInvocationState,
    run_state: EngineRunState,
    target: CommandInvocationState,
) -> None:
    invocation = sample_invocation(invocation_state)
    run = sample_run(run_state)
    _seed(harness, invocation, run)
    request = _invocation_request(
        invocation,
        target,
        process_start=sample_process_start() if target is _C.RUNNING else None,
        primary_diagnostic_id=None,
    )
    assert _code(harness.invocation_only(request)) == INVARIANT_VIOLATION
    _assert_durable(harness, invocation, run)
    assert is_mixed_running_pair(run, sample_invocation(target))
    assert not is_mixed_running_pair(run, invocation)


@pytest.mark.parametrize(
    ("invocation_state", "run_state", "mixed"),
    [
        (_C.STARTING, _R.READY, True),
        (_C.PENDING, _R.STARTING, True),
        (_C.RUNNING, _R.STARTING, True),
        (_C.STARTING, _R.RUNNING, True),
        (_C.PENDING, _R.READY, False),
        (_C.STARTING, _R.STARTING, False),
        (_C.RUNNING, _R.RUNNING, False),
    ],
)
def test_is_mixed_running_pair_names_the_half_applied_handoffs(
    invocation_state: CommandInvocationState,
    run_state: EngineRunState,
    mixed: bool,
) -> None:
    run = sample_run(run_state)
    invocation = sample_invocation(invocation_state)
    assert is_mixed_running_pair(run, invocation) is mixed


# --------------------------------------------------------------------------
# transition_invocation_and_run (plan 6 "Coupled terminal transitions"; 10.1)
# --------------------------------------------------------------------------


def test_coupled_timed_out_from_running_moves_both_records_in_one_unit_of_work(
    harness: _Harness,
) -> None:
    invocation = sample_invocation(_C.RUNNING)
    run = sample_run(_R.RUNNING)
    _seed(harness, invocation, run)
    request = _coupled_request(invocation, run, _C.TIMED_OUT, _R.TIMED_OUT)
    pair = _ok(harness.couple(request))
    ended, terminal = pair.invocation, pair.run
    assert ended.state is _C.TIMED_OUT
    assert ended.completed_at_utc == LATER
    assert ended.updated_at_utc == LATER
    assert ended.primary_diagnostic_id == DIAG_ID
    assert ended.diagnostic_ids == (DIAG_ID,)
    # Process and launch facts are carried; no exit pair, no cleanup yet.
    assert ended.process_created is True
    assert ended.pid_identity == invocation.pid_identity
    assert ended.process_started_at_utc == invocation.process_started_at_utc
    assert ended.deadline_utc == invocation.deadline_utc
    assert _missing(ended.native_exit_value)
    assert _missing(ended.process_exit_category)
    assert ended.cleanup_complete is False
    assert ended.revision == invocation.revision + 1
    assert terminal.state is _R.TIMED_OUT
    assert terminal.primary_terminal_diagnostic_id == DIAG_ID
    assert terminal.availability_observation_id == AVAIL_A
    assert terminal.updated_at_utc == LATER
    assert terminal.revision == run.revision + 1
    _assert_durable(harness, ended, terminal)


@pytest.mark.parametrize(
    ("kind", "invocation_state", "run_state", "invocation_target", "run_target"),
    [
        (_K.RUN, _C.STARTING, _R.STARTING, _C.TIMED_OUT, _R.TIMED_OUT),
        (_K.VALIDATE, _C.RUNNING, _R.VALIDATING, _C.TIMED_OUT, _R.TIMED_OUT),
        (_K.RUN, _C.RUNNING, _R.RUNNING, _C.CANCELLED, _R.CANCELLED),
        (_K.RUN, _C.STARTING, _R.STARTING, _C.CANCELLED, _R.CANCELLED),
        (_K.RUN, _C.RUNNING, _R.RUNNING, _C.PROTOCOL_FAILED, _R.FAILED),
        (_K.VALIDATE, _C.RUNNING, _R.VALIDATING, _C.PROTOCOL_FAILED, _R.FAILED),
    ],
)
def test_coupled_terminal_rows_with_an_any_condition_map_as_the_table_says(
    harness: _Harness,
    kind: CommandKind,
    invocation_state: CommandInvocationState,
    run_state: EngineRunState,
    invocation_target: CommandInvocationState,
    run_target: EngineRunState,
) -> None:
    invocation = sample_invocation(invocation_state, kind=kind)
    run = sample_run(run_state)
    _seed(harness, invocation, run)
    request = _coupled_request(invocation, run, invocation_target, run_target)
    pair = _ok(harness.couple(request))
    assert pair.invocation.state is invocation_target
    assert pair.invocation.completed_at_utc == LATER
    assert pair.invocation.primary_diagnostic_id == DIAG_ID
    assert pair.invocation.process_created is invocation.process_created
    assert pair.invocation.revision == invocation.revision + 1
    assert pair.run.state is run_target
    assert pair.run.primary_terminal_diagnostic_id == DIAG_ID
    # Absent on a VALIDATING run, present from READY onward; carried either way.
    assert pair.run.availability_observation_id == run.availability_observation_id
    assert pair.run.updated_at_utc == LATER
    assert pair.run.revision == run.revision + 1
    _assert_durable(harness, pair.invocation, pair.run)


@pytest.mark.parametrize(
    ("category", "error_code", "run_target"),
    [
        (
            DiagnosticCategory.ADAPTER_UNAVAILABILITY,
            "ADAPTER.UNAVAILABLE",
            _R.UNAVAILABLE,
        ),
        (DiagnosticCategory.ENGINE_RUNTIME, "ENGINE.RUNTIME_FAILURE", _R.FAILED),
    ],
)
def test_coupled_failed_to_start_reads_the_primary_diagnostic_category(
    harness: _Harness,
    category: DiagnosticCategory,
    error_code: str,
    run_target: EngineRunState,
) -> None:
    harness.store.seed_diagnostic(
        sample_diagnostic(DIAG_ID, error_code=error_code, category=category)
    )
    invocation = sample_invocation(_C.STARTING)
    run = sample_run(_R.STARTING)
    _seed(harness, invocation, run)
    observation = AVAIL_B if run_target is _R.UNAVAILABLE else None
    request = _coupled_request(
        invocation,
        run,
        _C.FAILED_TO_START,
        run_target,
        availability_observation_id=observation,
    )
    pair = _ok(harness.couple(request))
    assert pair.invocation.state is _C.FAILED_TO_START
    assert pair.invocation.process_created is False
    assert pair.invocation.completed_at_utc == LATER
    assert pair.invocation.primary_diagnostic_id == DIAG_ID
    assert pair.invocation.revision == invocation.revision + 1
    assert pair.run.state is run_target
    assert pair.run.primary_terminal_diagnostic_id == DIAG_ID
    # UNAVAILABLE is request-governed for the observation identity (plan 3.8
    # row 14); FAILED carries the READY-time observation forward unchanged.
    expected_observation = AVAIL_B if run_target is _R.UNAVAILABLE else AVAIL_A
    assert pair.run.availability_observation_id == expected_observation
    assert pair.run.updated_at_utc == LATER
    assert pair.run.revision == run.revision + 1
    _assert_durable(harness, pair.invocation, pair.run)


def test_coupled_failed_to_start_rejects_a_run_target_that_ignores_the_category(
    harness: _Harness,
) -> None:
    harness.store.seed_diagnostic(
        sample_diagnostic(
            DIAG_ID,
            error_code="ADAPTER.UNAVAILABLE",
            category=DiagnosticCategory.ADAPTER_UNAVAILABILITY,
        )
    )
    invocation = sample_invocation(_C.STARTING)
    run = sample_run(_R.STARTING)
    _seed(harness, invocation, run)
    request = _coupled_request(invocation, run, _C.FAILED_TO_START, _R.FAILED)
    assert _code(harness.couple(request)) == INVARIANT_VIOLATION
    _assert_durable(harness, invocation, run)


def test_coupled_failed_to_start_requires_the_primary_diagnostic_to_resolve(
    harness: _Harness,
) -> None:
    invocation = sample_invocation(_C.STARTING)
    run = sample_run(_R.STARTING)
    _seed(harness, invocation, run)
    request = _coupled_request(invocation, run, _C.FAILED_TO_START, _R.FAILED)
    assert _code(harness.couple(request)) == INVARIANT_VIOLATION
    _assert_durable(harness, invocation, run)


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


@pytest.mark.parametrize(
    "code",
    [WRITE_FAILED, STORAGE_UNAVAILABLE, CONCURRENCY_CONFLICT],
    ids=["write-failed", "storage-unavailable", "concurrency-conflict"],
)
def test_coupled_failed_to_start_returns_a_primary_read_failure_unchanged(
    harness: _Harness, code: str
) -> None:
    """Result propagation (correction D): the primary diagnostic IS recorded, so
    absence cannot explain the reader's ``Failure``; the coupled operation returns
    that very object from its one attempt and neither row moves."""
    harness.store.seed_diagnostic(sample_diagnostic(DIAG_ID))
    invocation = sample_invocation(_C.STARTING)
    run = sample_run(_R.STARTING)
    _seed(harness, invocation, run)
    planted = _planted_reader_failure(code)
    overriding = MemberOverridingUnitOfWork(
        harness.root, "diagnostics", {"get": lambda diagnostic_id: planted}
    )
    request = _coupled_request(invocation, run, _C.FAILED_TO_START, _R.FAILED)
    outcome = transition_invocation_and_run(
        request, unit_of_work=overriding, clock=harness.clock
    )
    assert outcome is planted
    assert _code(outcome) == code
    assert overriding.begins == 1
    _assert_durable(harness, invocation, run)


def test_coupled_failed_to_start_keeps_absence_for_an_invariant_read(
    harness: _Harness,
) -> None:
    """The invariant class keeps the operation's own "does not exist" invariant:
    the repositories' invariant-coded reads do not distinguish a missing row from a
    stored row the canonical model refuses (recorded limitation)."""
    invocation = sample_invocation(_C.STARTING)
    run = sample_run(_R.STARTING)
    _seed(harness, invocation, run)
    planted = _planted_reader_failure(INVARIANT_VIOLATION)
    overriding = MemberOverridingUnitOfWork(
        harness.root, "diagnostics", {"get": lambda diagnostic_id: planted}
    )
    request = _coupled_request(invocation, run, _C.FAILED_TO_START, _R.FAILED)
    outcome = transition_invocation_and_run(
        request, unit_of_work=overriding, clock=harness.clock
    )
    assert isinstance(outcome, Failure)
    assert outcome is not planted
    assert _code(outcome) == INVARIANT_VIOLATION
    assert outcome.diagnostics[0].message.endswith("does not exist")
    assert overriding.begins == 1
    _assert_durable(harness, invocation, run)


def test_coupled_request_whose_run_target_disagrees_with_the_mapping_is_rejected(
    harness: _Harness,
) -> None:
    invocation = sample_invocation(_C.RUNNING)
    run = sample_run(_R.RUNNING)
    _seed(harness, invocation, run)
    # RUNNING -> FAILED is a lawful run edge on its own; the table couples a
    # TIMED_OUT invocation to TIMED_OUT, so the caller's target is refused.
    request = _coupled_request(invocation, run, _C.TIMED_OUT, _R.FAILED)
    assert _code(harness.couple(request)) == INVARIANT_VIOLATION
    _assert_durable(harness, invocation, run)


def test_coupled_request_targeting_exited_is_rejected(harness: _Harness) -> None:
    invocation = sample_invocation(_C.RUNNING)
    run = sample_run(_R.RUNNING)
    _seed(harness, invocation, run)
    request = _coupled_request(
        invocation, run, _C.EXITED, _R.SUCCEEDED, native_exit_value=0
    )
    assert _code(harness.couple(request)) == INVARIANT_VIOLATION
    _assert_durable(harness, invocation, run)


def test_coupled_request_for_a_describe_invocation_is_rejected(
    harness: _Harness,
) -> None:
    invocation = sample_invocation(_C.RUNNING, kind=_K.DESCRIBE)
    run = sample_run(_R.RUNNING)
    _seed(harness, invocation, run)
    request = _coupled_request(invocation, run, _C.TIMED_OUT, _R.TIMED_OUT)
    assert _code(harness.couple(request)) == INVARIANT_VIOLATION
    _assert_durable(harness, invocation, run)


@pytest.mark.parametrize("invocation_state", [_C.RUNNING, _C.STARTING])
def test_coupled_transition_writes_nothing_when_the_run_is_already_terminal(
    harness: _Harness,
    invocation_state: CommandInvocationState,
) -> None:
    # The invocation half (-> TIMED_OUT) is lawful on its own; the run is already
    # FAILED and accepts no transition, so the invocation must not advance either.
    invocation = sample_invocation(invocation_state)
    run = sample_run(_R.FAILED)
    _seed(harness, invocation, run)
    request = _coupled_request(invocation, run, _C.TIMED_OUT, _R.TIMED_OUT)
    assert _code(harness.couple(request)) == INVARIANT_VIOLATION
    _assert_durable(harness, invocation, run)


def test_coupled_transition_writes_nothing_when_the_run_edge_does_not_exist(
    harness: _Harness,
) -> None:
    # A VALIDATE pair is never subject to the mixed-pair rule, so this isolates
    # the run predicate: the table maps TIMED_OUT onto VALIDATING -> TIMED_OUT and
    # a READY run has no such edge.
    invocation = sample_invocation(_C.RUNNING, kind=_K.VALIDATE)
    run = sample_run(_R.READY)
    _seed(harness, invocation, run)
    request = _coupled_request(invocation, run, _C.TIMED_OUT, _R.TIMED_OUT)
    assert _code(harness.couple(request)) == INVARIANT_VIOLATION
    _assert_durable(harness, invocation, run)


def test_coupled_transition_rejects_a_mixed_stored_pair(harness: _Harness) -> None:
    # STARTING -> TIMED_OUT and RUNNING -> TIMED_OUT are both lawful edges, so only
    # the launch-handoff invariant can reject this pair.
    invocation = sample_invocation(_C.STARTING)
    run = sample_run(_R.RUNNING)
    _seed(harness, invocation, run)
    assert is_mixed_running_pair(run, invocation)
    request = _coupled_request(invocation, run, _C.TIMED_OUT, _R.TIMED_OUT)
    assert _code(harness.couple(request)) == INVARIANT_VIOLATION
    _assert_durable(harness, invocation, run)


@pytest.mark.parametrize(("invocation_offset", "run_offset"), [(1, 0), (0, 1)])
def test_coupled_transition_with_a_stale_revision_conflicts_and_writes_nothing(
    harness: _Harness,
    invocation_offset: int,
    run_offset: int,
) -> None:
    invocation = sample_invocation(_C.RUNNING)
    run = sample_run(_R.RUNNING)
    _seed(harness, invocation, run)
    request = _coupled_request(
        invocation,
        run,
        _C.TIMED_OUT,
        _R.TIMED_OUT,
        invocation_revision=invocation.revision + invocation_offset,
        run_revision=run.revision + run_offset,
    )
    assert _code(harness.couple(request)) == CONCURRENCY_CONFLICT
    _assert_durable(harness, invocation, run)


def test_coupled_transition_replays_when_both_records_hold_their_targets(
    harness: _Harness,
) -> None:
    invocation = sample_invocation(_C.TIMED_OUT, via=_C.RUNNING)
    run = sample_run(_R.TIMED_OUT)
    _seed(harness, invocation, run)
    request = _coupled_request(invocation, run, _C.TIMED_OUT, _R.TIMED_OUT)
    pair = _ok(harness.couple(request))
    assert pair.invocation == invocation
    assert pair.run == run
    _assert_durable(harness, invocation, run)
