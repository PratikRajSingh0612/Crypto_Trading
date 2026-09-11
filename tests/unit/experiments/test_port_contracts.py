"""Stage 5 Task 6: the application ports, their in-memory doubles and the unit of work.

Plan sections 10, 10.1 and 11. The suite is implementation-agnostic where the
contract is: every case that speaks only through the protocols runs against the
``harness`` fixture, which Stage 8 can re-point at real repositories by adding a
parameter. The cases that exercise the deterministic test-only coordination hooks
and the double's misuse detectors are pinned to the in-memory double explicitly,
because they are properties of the double, not of the protocol.

The first RED of Task 6 is the ``doubles.experiments`` import below: plan section 11
requires it to resolve through pytest's prepend mode without editing the pinned
``pythonpath`` option, and the task stops if it does not.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Protocol, cast

import pytest
from pydantic import ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.adapters.ports import CommandInvocationRepository
from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.descriptors import RuntimeAvailabilityObservation
from crypto_lab.domain.diagnostics import (
    Diagnostic,
    DiagnosticCategory,
    DiagnosticSeverity,
)
from crypto_lab.domain.engine_run import EngineRunRecord
from crypto_lab.domain.experiment import ExperimentRecord
from crypto_lab.domain.hashing import HashingProfile, _uuid4_shaped, profile_hash
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.ports import Clock, IdentitySource
from crypto_lab.domain.results import Failure, Success
from crypto_lab.domain.retry import RetryDecisionRecord
from crypto_lab.experiments import diagnostics as diagnostics_module
from crypto_lab.experiments.diagnostics import (
    CONCURRENCY_CONFLICT,
    IMMUTABLE_INPUT_MISMATCH,
    INVARIANT_VIOLATION,
    RETRY_DECISION_CONFLICT,
    RETRY_NOT_BEFORE_NOT_REACHED,
    STAGE5_DIAGNOSTIC_CODES,
    UNRECOGNIZED_PROCESS_EXIT,
    stage5_diagnostic,
    stage5_failure,
)
from crypto_lab.experiments.ports import (
    DiagnosticReader,
    EngineRunRepository,
    ExperimentRepository,
    RetryDecisionInsertOutcome,
    RetryDecisionRepository,
    RuntimeAvailabilityObservationReader,
    UnitOfWork,
)
from doubles.experiments import (
    DIAG_ID,
    EXECUTABLE_HASH,
    EXPERIMENT_ID,
    INSTANT,
    INVOCATION_ID,
    OTHER_DIAG_ID,
    OTHER_INVOCATION_ID,
    OTHER_RUN_ID,
    RUN_ID,
    SLOT_A,
    SLOT_B,
    THIRD_DIAG_ID,
    UUID_A,
    UUID_B,
    UUID_C,
    UUID_D,
    UUID_E,
    FixedClock,
    InMemoryBackingStore,
    InMemoryUnitOfWork,
    SequentialIdentitySource,
    sample_diagnostic,
    sample_experiment,
    sample_invocation,
    sample_observation,
    sample_retry_decision,
    sample_run,
)

_E = ExperimentState
_R = EngineRunState
_C = CommandInvocationState
_K = CommandKind


# --------------------------------------------------------------------------
# The factory fixture (plan section 12 Task 6: "parametrized over a factory
# fixture so Stage 8 can re-point it at real repositories")
# --------------------------------------------------------------------------


class PortHarness(Protocol):
    """One backing store and the ability to open units of work over it."""

    def unit_of_work(self) -> UnitOfWork: ...

    def seed_diagnostic(self, diagnostic: Diagnostic) -> None: ...

    def seed_observation(self, observation: RuntimeAvailabilityObservation) -> None: ...

    def committed_experiments(self) -> tuple[ExperimentRecord, ...]: ...

    def committed_engine_runs(self) -> tuple[EngineRunRecord, ...]: ...

    def committed_command_invocations(self) -> tuple[CommandInvocationRecord, ...]: ...

    def committed_retry_decisions(self) -> tuple[RetryDecisionRecord, ...]: ...


@dataclass(frozen=True, slots=True)
class _InMemoryHarness:
    store: InMemoryBackingStore

    def unit_of_work(self) -> UnitOfWork:
        return InMemoryUnitOfWork(self.store)

    def seed_diagnostic(self, diagnostic: Diagnostic) -> None:
        self.store.seed_diagnostic(diagnostic)

    def seed_observation(self, observation: RuntimeAvailabilityObservation) -> None:
        self.store.seed_availability_observation(observation)

    def committed_experiments(self) -> tuple[ExperimentRecord, ...]:
        return self.store.committed_experiments()

    def committed_engine_runs(self) -> tuple[EngineRunRecord, ...]:
        return self.store.committed_engine_runs()

    def committed_command_invocations(self) -> tuple[CommandInvocationRecord, ...]:
        return self.store.committed_command_invocations()

    def committed_retry_decisions(self) -> tuple[RetryDecisionRecord, ...]:
        return self.store.committed_retry_decisions()


@pytest.fixture(params=["in_memory"])
def harness(request: pytest.FixtureRequest) -> PortHarness:
    assert request.param == "in_memory"
    return _InMemoryHarness(InMemoryBackingStore())


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


def _put_experiment(harness: PortHarness, record: ExperimentRecord) -> None:
    transaction = harness.unit_of_work().begin()
    _ok(transaction.experiments.add(record))
    _commit(transaction)


def _put_run(harness: PortHarness, record: EngineRunRecord) -> None:
    transaction = harness.unit_of_work().begin()
    _ok(transaction.engine_runs.add_attempt(record))
    _commit(transaction)


def _put_invocation(harness: PortHarness, record: CommandInvocationRecord) -> None:
    transaction = harness.unit_of_work().begin()
    _ok(transaction.command_invocations.add(record))
    _commit(transaction)


def _bump(record: ExperimentRecord) -> ExperimentRecord:
    payload = record.model_dump(mode="python")
    payload["revision"] = record.revision + 1
    payload["updated_at_utc"] = record.updated_at_utc + timedelta(seconds=1)
    return ExperimentRecord.model_validate(payload)


def _bump_run(record: EngineRunRecord, target: EngineRunState) -> EngineRunRecord:
    payload = record.model_dump(mode="python")
    payload["state"] = target
    payload["revision"] = record.revision + 1
    payload["updated_at_utc"] = record.updated_at_utc + timedelta(seconds=1)
    if target is _R.READY:
        payload["availability_observation_id"] = f"avail_{UUID_A}"
    return EngineRunRecord.model_validate(payload)


def _bump_invocation(
    record: CommandInvocationRecord, target: CommandInvocationState
) -> CommandInvocationRecord:
    payload = record.model_dump(mode="python")
    instant = record.updated_at_utc + timedelta(seconds=1)
    payload["state"] = target
    payload["revision"] = record.revision + 1
    payload["updated_at_utc"] = instant
    if target is _C.STARTING:
        payload["launch_attempted_at_utc"] = instant
        payload["deadline_utc"] = instant + timedelta(seconds=record.timeout_seconds)
    return CommandInvocationRecord.model_validate(payload)


# --------------------------------------------------------------------------
# Protocol inventory (plan section 10)
# --------------------------------------------------------------------------


def test_the_six_experiments_ports_and_the_adapters_port_are_runtime_protocols(
    harness: PortHarness,
) -> None:
    for port in (
        ExperimentRepository,
        EngineRunRepository,
        RetryDecisionRepository,
        RuntimeAvailabilityObservationReader,
        DiagnosticReader,
        UnitOfWork,
        CommandInvocationRepository,
    ):
        assert Protocol in cast(tuple[object, ...], port.__mro__)
    assert CommandInvocationRepository.__module__ == "crypto_lab.adapters.ports"
    assert UnitOfWork.__module__ == "crypto_lab.experiments.ports"
    root = harness.unit_of_work()
    assert isinstance(root, UnitOfWork)
    transaction = root.begin()
    assert isinstance(transaction, UnitOfWork)
    assert isinstance(transaction.experiments, ExperimentRepository)
    assert isinstance(transaction.engine_runs, EngineRunRepository)
    assert isinstance(transaction.retry_decisions, RetryDecisionRepository)
    assert isinstance(
        transaction.availability_observations, RuntimeAvailabilityObservationReader
    )
    assert isinstance(transaction.diagnostics, DiagnosticReader)
    assert isinstance(transaction.command_invocations, CommandInvocationRepository)
    assert not isinstance(object(), UnitOfWork)
    transaction.rollback()


def test_the_protocol_operation_inventory_is_exactly_plan_section_ten() -> None:
    def members(port: type) -> set[str]:
        return {
            name
            for name, value in vars(port).items()
            if not name.startswith("_")
            and (callable(value) or isinstance(value, property))
        }

    assert members(ExperimentRepository) == {"get", "add", "compare_and_swap"}
    assert members(EngineRunRepository) == {
        "get",
        "add_attempt",
        "compare_and_swap",
        "count_attempts",
        "latest_attempt",
        "get_by_attempt_number",
        # Stage 6 plan section 7.5: `append_event` is specification 8.2 verbatim and
        # `list_events` the declared extension `InvocationEventLedger.from_events`
        # reads; both joined in Stage 6 Task 4 with the `RunEvent` they carry.
        "append_event",
        "list_events",
    }
    assert members(RetryDecisionRepository) == {
        "get_by_predecessor",
        "insert_if_absent",
    }
    assert members(RuntimeAvailabilityObservationReader) == {"get", "list_for_adapter"}
    assert members(DiagnosticReader) == {"get", "get_many"}
    assert members(CommandInvocationRepository) == {
        "get",
        "add",
        "compare_and_swap",
        "list_for_run",
    }
    assert members(UnitOfWork) == {
        "begin",
        "commit",
        "rollback",
        "experiments",
        "engine_runs",
        "command_invocations",
        "retry_decisions",
        "availability_observations",
        "diagnostics",
    }
    # Stage 5 plan section 1.4 deferred `append_event` to Stage 6's `RunEvent`; Stage 6
    # plan section 7.5 delivers it together with `list_events` in Task 4.
    assert hasattr(EngineRunRepository, "append_event")
    assert hasattr(EngineRunRepository, "list_events")


def test_retry_decision_insert_outcome_is_a_nested_value_object() -> None:
    record = sample_retry_decision()
    outcome = RetryDecisionInsertOutcome(inserted=True, record=record)
    assert tuple(RetryDecisionInsertOutcome.model_fields) == ("inserted", "record")
    assert outcome.record is record
    with pytest.raises(ValidationError):
        RetryDecisionInsertOutcome.model_validate(
            {"inserted": True, "record": record, "extra": 1}
        )
    with pytest.raises(ValidationError):
        RetryDecisionInsertOutcome.model_validate({"inserted": "yes", "record": record})


# --------------------------------------------------------------------------
# Failure diagnostics (plan sections 3.3 and 8.6)
# --------------------------------------------------------------------------


def test_the_stage_five_code_table_is_exactly_the_six_plan_codes() -> None:
    assert set(STAGE5_DIAGNOSTIC_CODES) == {
        CONCURRENCY_CONFLICT,
        INVARIANT_VIOLATION,
        IMMUTABLE_INPUT_MISMATCH,
        RETRY_DECISION_CONFLICT,
        RETRY_NOT_BEFORE_NOT_REACHED,
        UNRECOGNIZED_PROCESS_EXIT,
    }
    assert CONCURRENCY_CONFLICT == "PERSISTENCE.CONCURRENCY_CONFLICT"
    assert INVARIANT_VIOLATION == "CORE.INVARIANT_VIOLATION"
    assert IMMUTABLE_INPUT_MISMATCH == "CORE.IMMUTABLE_INPUT_MISMATCH"
    assert RETRY_DECISION_CONFLICT == "RETRY.DECISION_CONFLICT"
    assert RETRY_NOT_BEFORE_NOT_REACHED == "RETRY.NOT_BEFORE_NOT_REACHED"
    assert UNRECOGNIZED_PROCESS_EXIT == "PROCESS.UNRECOGNIZED_PROCESS_EXIT"
    expected = {
        CONCURRENCY_CONFLICT: (DiagnosticCategory.PERSISTENCE, True),
        INVARIANT_VIOLATION: (DiagnosticCategory.INTERNAL_INVARIANT, False),
        IMMUTABLE_INPUT_MISMATCH: (DiagnosticCategory.INTERNAL_INVARIANT, False),
        RETRY_DECISION_CONFLICT: (DiagnosticCategory.INTERNAL_INVARIANT, False),
        RETRY_NOT_BEFORE_NOT_REACHED: (DiagnosticCategory.PERSISTENCE, True),
        UNRECOGNIZED_PROCESS_EXIT: (DiagnosticCategory.ENGINE_RUNTIME, True),
    }
    for code, (category, retriable) in expected.items():
        posture = STAGE5_DIAGNOSTIC_CODES[code]
        assert posture.category is category
        assert posture.retriable is retriable


def test_a_stage_five_diagnostic_derives_its_identity_from_content_alone() -> None:
    first = stage5_diagnostic(
        INVARIANT_VIOLATION,
        "forbidden edge",
        source_component="experiments.experiment_service",
        timestamp_utc=INSTANT,
        experiment_id=EXPERIMENT_ID,
        details={"stored_state": "DRAFT"},
    )
    later = stage5_diagnostic(
        INVARIANT_VIOLATION,
        "forbidden edge",
        source_component="experiments.experiment_service",
        timestamp_utc=INSTANT + timedelta(hours=1),
        experiment_id=EXPERIMENT_ID,
        details={"stored_state": "DRAFT"},
    )
    assert first.diagnostic_id == later.diagnostic_id
    assert first.timestamp_utc != later.timestamp_utc
    assert first.category is DiagnosticCategory.INTERNAL_INVARIANT
    assert first.severity is DiagnosticSeverity.ERROR
    assert first.retriable is False
    assert first.experiment_id == EXPERIMENT_ID
    assert _missing(first.run_id)
    assert _missing(first.invocation_id)
    assert first.causal_diagnostic_ids == ()
    # The identity is the reviewed DIAGNOSTIC_IDENTITY_V1 derivation over the
    # content payload, with the correlation identifiers included and the
    # timestamp excluded.
    payload = {
        "schema_version": "1.0.0",
        "error_code": INVARIANT_VIOLATION,
        "category": DiagnosticCategory.INTERNAL_INVARIANT.value,
        "severity": DiagnosticSeverity.ERROR.value,
        "source_component": "experiments.experiment_service",
        "message": "forbidden edge",
        "retriable": False,
        "details": {"stored_state": "DRAFT"},
        "experiment_id": EXPERIMENT_ID,
        "causal_diagnostic_ids": [],
    }
    expected = _uuid4_shaped(
        profile_hash(HashingProfile.DIAGNOSTIC_IDENTITY_V1, payload)  # type: ignore[arg-type]
    )
    assert first.diagnostic_id == f"diag_{expected}"


def test_a_stage_five_diagnostic_identity_is_sensitive_to_every_correlation() -> None:
    def build(**overrides: object) -> Diagnostic:
        arguments: dict[str, object] = {
            "source_component": "experiments.run_service",
            "timestamp_utc": INSTANT,
            "experiment_id": EXPERIMENT_ID,
            "run_id": RUN_ID,
        }
        arguments.update(overrides)
        return stage5_diagnostic(
            CONCURRENCY_CONFLICT,
            "stale revision",
            **arguments,  # type: ignore[arg-type]
        )

    base = build()
    assert base.run_id == RUN_ID
    assert build(run_id=OTHER_RUN_ID).diagnostic_id != base.diagnostic_id
    assert build(source_component="experiments.x").diagnostic_id != base.diagnostic_id
    assert build(details={"k": 1}).diagnostic_id != base.diagnostic_id
    assert build(causal_diagnostic_ids=(DIAG_ID,)).diagnostic_id != base.diagnostic_id


def test_the_factory_refuses_a_code_outside_the_closed_table() -> None:
    with pytest.raises(ValueError, match="Stage 5 code"):
        stage5_diagnostic(
            "CORE.UNKNOWN",
            "x",
            source_component="experiments.experiment_service",
            timestamp_utc=INSTANT,
        )


def test_stage5_failure_wraps_exactly_one_diagnostic() -> None:
    failure = stage5_failure(
        CONCURRENCY_CONFLICT,
        "moved",
        source_component="experiments.experiment_service",
        timestamp_utc=INSTANT,
        experiment_id=EXPERIMENT_ID,
        details={"expected_revision": 1, "stored_revision": 2},
    )
    assert isinstance(failure, Failure)
    assert len(failure.diagnostics) == 1
    assert failure.diagnostics[0].error_code == CONCURRENCY_CONFLICT
    assert failure.diagnostics[0].retriable is True
    assert failure.diagnostics[0].category is DiagnosticCategory.PERSISTENCE


def test_the_diagnostics_module_reads_no_clock_and_draws_nothing() -> None:
    source = diagnostics_module.__file__
    assert source is not None
    text = Path(source).read_text(encoding="utf-8")
    for forbidden in (
        "datetime.now",
        "uuid4(",
        "import random",
        "random.",
        "time.time",
        "os.environ",
    ):
        assert forbidden not in text


# --------------------------------------------------------------------------
# Clock and identity doubles (plan section 11)
# --------------------------------------------------------------------------


def test_fixed_clock_returns_the_caller_set_instant_and_advances_only_by_request() -> (
    None
):
    clock = FixedClock(INSTANT)
    assert isinstance(clock, Clock)
    assert clock.now_utc() == INSTANT
    assert clock.now_utc() == INSTANT
    clock.advance(30)
    assert clock.now_utc() == INSTANT + timedelta(seconds=30)
    with pytest.raises(ValueError, match="timezone-aware UTC"):
        FixedClock(datetime(2026, 9, 7, 12, 0, 0))  # noqa: DTZ001 - deliberate probe


def test_sequential_identity_source_is_deterministic_and_kind_scoped() -> None:
    first = SequentialIdentitySource("seed")
    second = SequentialIdentitySource("seed")
    assert isinstance(first, IdentitySource)
    sequence_a = (
        first.new_experiment_id(),
        first.new_run_id(),
        first.new_run_id(),
        first.new_invocation_id(),
        first.new_logical_slot_id(),
        first.new_attempt_token(),
    )
    sequence_b = (
        second.new_experiment_id(),
        second.new_run_id(),
        second.new_run_id(),
        second.new_invocation_id(),
        second.new_logical_slot_id(),
        second.new_attempt_token(),
    )
    assert sequence_a == sequence_b
    assert sequence_a[1] != sequence_a[2]
    assert sequence_a[0].startswith("exp_")
    assert sequence_a[1].startswith("run_")
    assert sequence_a[3].startswith("inv_")
    assert sequence_a[4].startswith("slot_")
    assert len(sequence_a[5]) >= 32
    assert SequentialIdentitySource("other").new_run_id() != sequence_a[1]
    # A different kind at the same counter never collides with another kind.
    assert sequence_a[0].removeprefix("exp_") != sequence_a[1].removeprefix("run_")


# --------------------------------------------------------------------------
# Repository contracts: get, add, replay-vs-duplicate, compare-and-swap
# --------------------------------------------------------------------------


def test_get_missing_is_an_invariant_failure_on_every_repository(
    harness: PortHarness,
) -> None:
    transaction = harness.unit_of_work().begin()
    assert _code(transaction.experiments.get(EXPERIMENT_ID)) == INVARIANT_VIOLATION
    assert _code(transaction.engine_runs.get(RUN_ID)) == INVARIANT_VIOLATION
    assert _missing(
        _ok(transaction.engine_runs.get_by_attempt_number(EXPERIMENT_ID, SLOT_A, 1))
    )
    assert (
        _code(transaction.command_invocations.get(INVOCATION_ID)) == INVARIANT_VIOLATION
    )
    assert (
        _code(transaction.retry_decisions.get_by_predecessor(SLOT_A, RUN_ID))
        == INVARIANT_VIOLATION
    )
    assert (
        _code(transaction.availability_observations.get(f"avail_{UUID_A}"))
        == INVARIANT_VIOLATION
    )
    assert _code(transaction.diagnostics.get(DIAG_ID)) == INVARIANT_VIOLATION
    transaction.rollback()


def test_add_then_get_round_trips_and_a_duplicate_identity_conflicts(
    harness: PortHarness,
) -> None:
    experiment = sample_experiment(_E.DRAFT)
    run = sample_run(_R.PENDING)
    invocation = sample_invocation(_C.PENDING)
    transaction = harness.unit_of_work().begin()
    _ok(transaction.experiments.add(experiment))
    _ok(transaction.engine_runs.add_attempt(run))
    _ok(transaction.command_invocations.add(invocation))
    assert _ok(transaction.experiments.get(EXPERIMENT_ID)) == experiment
    assert _ok(transaction.engine_runs.get(RUN_ID)) == run
    assert _ok(transaction.command_invocations.get(INVOCATION_ID)) == invocation
    # An identical re-add is still a duplicate at the repository: replay is the
    # service's decision after a read, never the repository's.
    assert _code(transaction.experiments.add(experiment)) == CONCURRENCY_CONFLICT
    assert _code(transaction.engine_runs.add_attempt(run)) == CONCURRENCY_CONFLICT
    assert (
        _code(transaction.command_invocations.add(invocation)) == CONCURRENCY_CONFLICT
    )
    _commit(transaction)
    fresh = harness.unit_of_work().begin()
    assert _ok(fresh.experiments.get(EXPERIMENT_ID)) == experiment
    assert _code(fresh.experiments.add(_bump(experiment))) == CONCURRENCY_CONFLICT
    fresh.rollback()
    assert harness.committed_experiments() == (experiment,)


def test_compare_and_swap_succeeds_only_at_the_expected_revision(
    harness: PortHarness,
) -> None:
    stored = sample_experiment(_E.DRAFT)
    _put_experiment(harness, stored)
    replacement = _bump(stored)
    transaction = harness.unit_of_work().begin()
    stale = transaction.experiments.compare_and_swap(stored.revision + 1, replacement)
    assert _code(stale) == CONCURRENCY_CONFLICT
    assert _ok(transaction.experiments.get(EXPERIMENT_ID)) == stored
    swapped = _ok(
        transaction.experiments.compare_and_swap(stored.revision, replacement)
    )
    assert swapped == replacement
    assert swapped.revision == stored.revision + 1
    assert _ok(transaction.experiments.get(EXPERIMENT_ID)) == replacement
    _commit(transaction)
    assert harness.committed_experiments() == (replacement,)
    # The candidate itself is never mutated and a stale retry writes nothing.
    assert replacement.revision == stored.revision + 1
    again = harness.unit_of_work().begin()
    assert (
        _code(again.experiments.compare_and_swap(stored.revision, _bump(stored)))
        == CONCURRENCY_CONFLICT
    )
    again.rollback()
    assert harness.committed_experiments() == (replacement,)


def test_compare_and_swap_rejects_a_missing_row_and_a_wrong_revision_step(
    harness: PortHarness,
) -> None:
    stored = sample_experiment(_E.DRAFT)
    transaction = harness.unit_of_work().begin()
    assert (
        _code(transaction.experiments.compare_and_swap(0, _bump(stored)))
        == CONCURRENCY_CONFLICT
    )
    _ok(transaction.experiments.add(stored))
    same_revision = ExperimentRecord.model_validate(
        {
            **stored.model_dump(mode="python"),
            "updated_at_utc": stored.updated_at_utc + timedelta(seconds=1),
        }
    )
    assert (
        _code(transaction.experiments.compare_and_swap(stored.revision, same_revision))
        == INVARIANT_VIOLATION
    )
    skipped = _bump(_bump(stored))
    assert (
        _code(transaction.experiments.compare_and_swap(stored.revision, skipped))
        == INVARIANT_VIOLATION
    )
    assert _ok(transaction.experiments.get(EXPERIMENT_ID)) == stored
    transaction.rollback()


def test_run_and_invocation_compare_and_swap_share_the_contract(
    harness: PortHarness,
) -> None:
    run = sample_run(_R.PENDING)
    invocation = sample_invocation(_C.PENDING)
    _put_run(harness, run)
    _put_invocation(harness, invocation)
    transaction = harness.unit_of_work().begin()
    next_run = _bump_run(run, _R.VALIDATING)
    next_invocation = _bump_invocation(invocation, _C.STARTING)
    assert (
        _code(transaction.engine_runs.compare_and_swap(run.revision + 1, next_run))
        == CONCURRENCY_CONFLICT
    )
    assert (
        _code(
            transaction.command_invocations.compare_and_swap(
                invocation.revision + 1, next_invocation
            )
        )
        == CONCURRENCY_CONFLICT
    )
    assert _ok(transaction.engine_runs.compare_and_swap(run.revision, next_run)) == (
        next_run
    )
    assert (
        _ok(
            transaction.command_invocations.compare_and_swap(
                invocation.revision, next_invocation
            )
        )
        == next_invocation
    )
    _commit(transaction)
    assert harness.committed_engine_runs() == (next_run,)
    assert harness.committed_command_invocations() == (next_invocation,)


# --------------------------------------------------------------------------
# Unique indexes and the engine-run queries (plan sections 10, 11; spec 23.3)
# --------------------------------------------------------------------------


def test_the_attempt_unique_index_rejects_a_second_attempt_one_for_the_slot(
    harness: PortHarness,
) -> None:
    first = sample_run(_R.PENDING)
    divergent = sample_run(_R.PENDING, run_id=OTHER_RUN_ID, request_hash="b" * 64)
    transaction = harness.unit_of_work().begin()
    _ok(transaction.engine_runs.add_attempt(first))
    assert _code(transaction.engine_runs.add_attempt(divergent)) == CONCURRENCY_CONFLICT
    assert _ok(transaction.engine_runs.count_attempts(EXPERIMENT_ID, SLOT_A)) == 1
    other_slot = sample_run(_R.PENDING, run_id=OTHER_RUN_ID, logical_slot_id=SLOT_B)
    _ok(transaction.engine_runs.add_attempt(other_slot))
    assert _ok(transaction.engine_runs.count_attempts(EXPERIMENT_ID, SLOT_B)) == 1
    _commit(transaction)
    assert len(harness.committed_engine_runs()) == 2


def test_latest_attempt_is_missing_for_an_unattempted_slot_and_highest_otherwise(
    harness: PortHarness,
) -> None:
    transaction = harness.unit_of_work().begin()
    assert _missing(_ok(transaction.engine_runs.latest_attempt(EXPERIMENT_ID, SLOT_A)))
    assert _ok(transaction.engine_runs.count_attempts(EXPERIMENT_ID, SLOT_A)) == 0
    # Reverse insertion order: the successor lands before the initial attempt.
    successor = sample_run(_R.PENDING, run_id=OTHER_RUN_ID, attempt_number=2)
    initial = sample_run(_R.FAILED)
    _ok(transaction.engine_runs.add_attempt(successor))
    _ok(transaction.engine_runs.add_attempt(initial))
    latest = _ok(transaction.engine_runs.latest_attempt(EXPERIMENT_ID, SLOT_A))
    assert not _missing(latest)
    assert latest == successor
    assert _ok(transaction.engine_runs.count_attempts(EXPERIMENT_ID, SLOT_A)) == 2
    assert (
        _ok(transaction.engine_runs.get_by_attempt_number(EXPERIMENT_ID, SLOT_A, 1))
        == initial
    )
    assert (
        _ok(transaction.engine_runs.get_by_attempt_number(EXPERIMENT_ID, SLOT_A, 2))
        == successor
    )
    assert _missing(
        _ok(transaction.engine_runs.get_by_attempt_number(EXPERIMENT_ID, SLOT_A, 3))
    )
    _commit(transaction)
    rebuilt = harness.unit_of_work().begin()
    assert _ok(rebuilt.engine_runs.latest_attempt(EXPERIMENT_ID, SLOT_A)) == successor
    rebuilt.rollback()


def test_the_invocation_index_permits_one_non_terminal_invocation_per_run_and_kind(
    harness: PortHarness,
) -> None:
    open_run = sample_invocation(_C.PENDING)
    another_open_run = sample_invocation(_C.STARTING, invocation_id=OTHER_INVOCATION_ID)
    transaction = harness.unit_of_work().begin()
    _ok(transaction.command_invocations.add(open_run))
    assert (
        _code(transaction.command_invocations.add(another_open_run))
        == CONCURRENCY_CONFLICT
    )
    # A different kind for the same run and a terminal same-kind row are permitted.
    open_validate = sample_invocation(
        _C.PENDING, kind=_K.VALIDATE, invocation_id=OTHER_INVOCATION_ID
    )
    _ok(transaction.command_invocations.add(open_validate))
    terminal_run = sample_invocation(
        _C.EXITED,
        invocation_id=f"inv_{UUID_C}",
        created_at_utc=INSTANT - timedelta(hours=1),
    )
    _ok(transaction.command_invocations.add(terminal_run))
    _commit(transaction)
    assert len(harness.committed_command_invocations()) == 3


def test_list_for_run_is_ordered_by_creation_then_identifier_regardless_of_insertion(
    harness: PortHarness,
) -> None:
    early = sample_invocation(
        _C.EXITED,
        invocation_id=f"inv_{UUID_C}",
        created_at_utc=INSTANT - timedelta(hours=2),
    )
    middle_low = sample_invocation(
        _C.CANCELLED,
        invocation_id=f"inv_{UUID_A}",
        created_at_utc=INSTANT - timedelta(hours=1),
    )
    middle_high = sample_invocation(
        _C.TIMED_OUT,
        invocation_id=f"inv_{UUID_B}",
        created_at_utc=INSTANT - timedelta(hours=1),
    )
    latest = sample_invocation(_C.PENDING, invocation_id=f"inv_{UUID_D}")
    other_kind = sample_invocation(
        _C.PENDING, kind=_K.VALIDATE, invocation_id=f"inv_{UUID_E}"
    )
    for permutation in (
        (latest, middle_high, early, middle_low, other_kind),
        (middle_low, early, other_kind, latest, middle_high),
    ):
        store_harness = _InMemoryHarness(InMemoryBackingStore())
        transaction = store_harness.unit_of_work().begin()
        for record in permutation:
            _ok(transaction.command_invocations.add(record))
        listed = _ok(transaction.command_invocations.list_for_run(RUN_ID, _K.RUN))
        assert type(listed) is tuple
        assert listed == (early, middle_low, middle_high, latest)
        assert _ok(
            transaction.command_invocations.list_for_run(RUN_ID, _K.VALIDATE)
        ) == (other_kind,)
        assert (
            _ok(transaction.command_invocations.list_for_run(OTHER_RUN_ID, _K.RUN))
            == ()
        )
        transaction.rollback()
    del harness


# --------------------------------------------------------------------------
# Retry-decision insert-if-absent (plan sections 8.4 phase 3, 11)
# --------------------------------------------------------------------------


def test_insert_if_absent_inserts_once_and_then_returns_the_stored_winner(
    harness: PortHarness,
) -> None:
    candidate = sample_retry_decision()
    divergent = sample_retry_decision(decided_at_utc=INSTANT + timedelta(minutes=5))
    transaction = harness.unit_of_work().begin()
    first = _ok(transaction.retry_decisions.insert_if_absent(candidate))
    assert first.inserted is True
    assert first.record == candidate
    second = _ok(transaction.retry_decisions.insert_if_absent(divergent))
    assert second.inserted is False
    assert second.record == candidate
    assert _ok(transaction.retry_decisions.get_by_predecessor(SLOT_A, RUN_ID)) == (
        candidate
    )
    _commit(transaction)
    assert harness.committed_retry_decisions() == (candidate,)
    rebuilt = harness.unit_of_work().begin()
    third = _ok(rebuilt.retry_decisions.insert_if_absent(divergent))
    assert third.inserted is False
    assert third.record == candidate
    rebuilt.rollback()
    assert harness.committed_retry_decisions() == (candidate,)


def test_insert_if_absent_under_a_simulated_concurrent_winner_returns_the_winner() -> (
    None
):
    store = InMemoryBackingStore()
    root = InMemoryUnitOfWork(store)
    loser_candidate = sample_retry_decision()
    winner_candidate = sample_retry_decision(
        decided_at_utc=INSTANT + timedelta(minutes=1)
    )
    seen: list[RetryDecisionRecord] = []

    def concurrent_winner(record: RetryDecisionRecord) -> None:
        seen.append(record)
        winner = InMemoryUnitOfWork(store).begin()
        _ok(winner.retry_decisions.insert_if_absent(winner_candidate))
        _commit(winner)

    root.install_retry_decision_insert_hook(concurrent_winner)
    transaction = root.begin()
    outcome = _ok(transaction.retry_decisions.insert_if_absent(loser_candidate))
    assert seen == [loser_candidate]
    assert outcome.inserted is False
    assert outcome.record == winner_candidate
    _commit(transaction)
    assert store.committed_retry_decisions() == (winner_candidate,)
    # One-shot: a later insert on a fresh key proceeds without the hook.
    later = root.begin()
    fresh = sample_retry_decision(predecessor_run_id=OTHER_RUN_ID)
    assert _ok(later.retry_decisions.insert_if_absent(fresh)).inserted is True
    assert seen == [loser_candidate]
    _commit(later)


# --------------------------------------------------------------------------
# Read-only ports (plan sections 8.2, 10, 11, 16 of the task prompt)
# --------------------------------------------------------------------------


def test_diagnostic_reader_offers_primitive_reads_only(harness: PortHarness) -> None:
    root_cause = sample_diagnostic(THIRD_DIAG_ID)
    middle = sample_diagnostic(OTHER_DIAG_ID, causal_diagnostic_ids=(THIRD_DIAG_ID,))
    primary = sample_diagnostic(DIAG_ID, causal_diagnostic_ids=(OTHER_DIAG_ID,))
    for diagnostic in (primary, middle, root_cause):
        harness.seed_diagnostic(diagnostic)
    transaction = harness.unit_of_work().begin()
    assert _ok(transaction.diagnostics.get(DIAG_ID)) == primary
    many = _ok(transaction.diagnostics.get_many((DIAG_ID, THIRD_DIAG_ID)))
    assert type(many) is tuple
    # Sorted by identifier, not by request order; no traversal follows causes.
    assert many == tuple(sorted((primary, root_cause), key=lambda d: d.diagnostic_id))
    assert _ok(transaction.diagnostics.get_many(())) == ()
    assert (
        _code(transaction.diagnostics.get_many((DIAG_ID, f"diag_{UUID_D}")))
        == INVARIANT_VIOLATION
    )
    assert _code(transaction.diagnostics.get_many((DIAG_ID, DIAG_ID))) == (
        INVARIANT_VIOLATION
    )
    assert not hasattr(transaction.diagnostics, "closure")
    assert not hasattr(transaction.diagnostics, "causal_closure")
    transaction.rollback()


def test_list_for_adapter_filters_on_the_three_keys_and_sorts_by_identifier(
    harness: PortHarness,
) -> None:
    low = sample_observation(f"avail_{UUID_C}", observed_at_utc=INSTANT)
    mid = sample_observation(
        f"avail_{UUID_A}", observed_at_utc=INSTANT + timedelta(minutes=2)
    )
    high = sample_observation(
        f"avail_{UUID_B}", observed_at_utc=INSTANT + timedelta(minutes=1)
    )
    other_version = sample_observation(f"avail_{UUID_D}", adapter_version="2.0.0")
    for observation in (high, other_version, low, mid):
        harness.seed_observation(observation)
    transaction = harness.unit_of_work().begin()
    listed = _ok(
        transaction.availability_observations.list_for_adapter(
            "adapter.alpha", "1.0.0", EXECUTABLE_HASH
        )
    )
    assert type(listed) is tuple
    assert listed == (low, mid, high)
    assert _ok(
        transaction.availability_observations.list_for_adapter(
            "adapter.alpha", "2.0.0", EXECUTABLE_HASH
        )
    ) == (other_version,)
    assert (
        _ok(
            transaction.availability_observations.list_for_adapter(
                "adapter.alpha", "1.0.0", "f" * 64
            )
        )
        == ()
    )
    assert _ok(transaction.availability_observations.get(f"avail_{UUID_A}")) == mid
    transaction.rollback()


def test_list_for_adapter_is_unbounded_so_no_qualifying_observation_is_dropped(
    harness: PortHarness,
) -> None:
    identifiers: list[str] = []
    for index in range(257):
        suffix = f"{index:012x}"
        identifier = f"avail_00000000-0000-4000-8000-{suffix}"
        identifiers.append(identifier)
        harness.seed_observation(
            sample_observation(
                identifier,
                observed_at_utc=INSTANT + timedelta(seconds=index),
                # The freshest 256 are unavailable: a bounded read would hide
                # the one qualifying (oldest, available) observation.
                available=index == 0,
            )
        )
    transaction = harness.unit_of_work().begin()
    listed = _ok(
        transaction.availability_observations.list_for_adapter(
            "adapter.alpha", "1.0.0", EXECUTABLE_HASH
        )
    )
    assert len(listed) == 257
    assert [item.availability_observation_id for item in listed] == sorted(identifiers)
    available = [item for item in listed if item.available]
    assert [item.availability_observation_id for item in available] == [identifiers[0]]
    transaction.rollback()


# --------------------------------------------------------------------------
# The unit of work: commit, rollback, atomicity, reconstruction
# --------------------------------------------------------------------------


def test_rollback_restores_every_store_and_commit_publishes_all_or_nothing(
    harness: PortHarness,
) -> None:
    experiment = sample_experiment(_E.DRAFT)
    run = sample_run(_R.PENDING)
    invocation = sample_invocation(_C.PENDING)
    decision = sample_retry_decision()
    abandoned = harness.unit_of_work().begin()
    _ok(abandoned.experiments.add(experiment))
    _ok(abandoned.engine_runs.add_attempt(run))
    _ok(abandoned.command_invocations.add(invocation))
    _ok(abandoned.retry_decisions.insert_if_absent(decision))
    abandoned.rollback()
    assert harness.committed_experiments() == ()
    assert harness.committed_engine_runs() == ()
    assert harness.committed_command_invocations() == ()
    assert harness.committed_retry_decisions() == ()
    committed = harness.unit_of_work().begin()
    _ok(committed.experiments.add(experiment))
    _ok(committed.engine_runs.add_attempt(run))
    # Nothing is visible outside the transaction before commit.
    peek = harness.unit_of_work().begin()
    assert _code(peek.experiments.get(EXPERIMENT_ID)) == INVARIANT_VIOLATION
    peek.rollback()
    _commit(committed)
    assert harness.committed_experiments() == (experiment,)
    assert harness.committed_engine_runs() == (run,)


def test_a_failed_second_write_leaves_the_first_undurable_after_rollback(
    harness: PortHarness,
) -> None:
    stored_run = sample_run(_R.PENDING)
    _put_run(harness, stored_run)
    transaction = harness.unit_of_work().begin()
    _ok(transaction.experiments.add(sample_experiment(_E.DRAFT)))
    stale = transaction.engine_runs.compare_and_swap(
        stored_run.revision + 5, _bump_run(stored_run, _R.VALIDATING)
    )
    assert _code(stale) == CONCURRENCY_CONFLICT
    transaction.rollback()
    assert harness.committed_experiments() == ()
    assert harness.committed_engine_runs() == (stored_run,)


def test_an_unfinished_transaction_never_reaches_a_rebuilt_unit_of_work(
    harness: PortHarness,
) -> None:
    dangling = harness.unit_of_work().begin()
    _ok(dangling.experiments.add(sample_experiment(_E.DRAFT)))
    rebuilt = harness.unit_of_work().begin()
    assert _code(rebuilt.experiments.get(EXPERIMENT_ID)) == INVARIANT_VIOLATION
    rebuilt.rollback()
    assert harness.committed_experiments() == ()
    del dangling


def test_commit_detects_a_row_that_moved_since_the_transaction_began(
    harness: PortHarness,
) -> None:
    stored = sample_experiment(_E.DRAFT)
    _put_experiment(harness, stored)
    loser = harness.unit_of_work().begin()
    assert _ok(loser.experiments.get(EXPERIMENT_ID)) == stored
    winner = harness.unit_of_work().begin()
    winning = _bump(stored)
    _ok(winner.experiments.compare_and_swap(stored.revision, winning))
    _commit(winner)
    # The loser's compare-and-swap sees the committed winner, not its snapshot.
    assert (
        _code(loser.experiments.compare_and_swap(stored.revision, _bump(stored)))
        == CONCURRENCY_CONFLICT
    )
    loser.rollback()
    assert harness.committed_experiments() == (winning,)
    # An insert that raced a committed insert of the same identity cannot publish.
    first = harness.unit_of_work().begin()
    second = harness.unit_of_work().begin()
    _ok(first.engine_runs.add_attempt(sample_run(_R.PENDING)))
    _ok(second.engine_runs.add_attempt(sample_run(_R.PENDING, request_hash="b" * 64)))
    _commit(second)
    lost = first.commit()
    assert _code(lost) == CONCURRENCY_CONFLICT
    assert harness.committed_engine_runs() == (
        sample_run(_R.PENDING, request_hash="b" * 64),
    )


def test_commit_rejects_distinct_identities_that_collide_on_a_unique_index(
    harness: PortHarness,
) -> None:
    # Attempt index (experiment_id, logical_slot_id, attempt_number).
    first = harness.unit_of_work().begin()
    second = harness.unit_of_work().begin()
    _ok(first.engine_runs.add_attempt(sample_run(_R.PENDING)))
    _ok(second.engine_runs.add_attempt(sample_run(_R.PENDING, run_id=OTHER_RUN_ID)))
    _commit(first)
    assert _code(second.commit()) == CONCURRENCY_CONFLICT
    assert harness.committed_engine_runs() == (sample_run(_R.PENDING),)
    # Non-terminal invocation index (run_id, command_kind).
    third = harness.unit_of_work().begin()
    fourth = harness.unit_of_work().begin()
    _ok(third.command_invocations.add(sample_invocation(_C.PENDING, kind=_K.VALIDATE)))
    _ok(
        fourth.command_invocations.add(
            sample_invocation(
                _C.PENDING, kind=_K.VALIDATE, invocation_id=OTHER_INVOCATION_ID
            )
        )
    )
    _commit(third)
    assert _code(fourth.commit()) == CONCURRENCY_CONFLICT
    assert harness.committed_command_invocations() == (
        sample_invocation(_C.PENDING, kind=_K.VALIDATE),
    )
    # A terminal row of the same kind and two open DESCRIBEs never collide.
    fifth = harness.unit_of_work().begin()
    sixth = harness.unit_of_work().begin()
    _ok(
        fifth.command_invocations.add(
            sample_invocation(
                _C.EXITED, kind=_K.VALIDATE, invocation_id=f"inv_{UUID_C}"
            )
        )
    )
    _ok(
        sixth.command_invocations.add(
            sample_invocation(
                _C.PENDING, kind=_K.DESCRIBE, invocation_id=f"inv_{UUID_D}"
            )
        )
    )
    _commit(fifth)
    _commit(sixth)
    seventh = harness.unit_of_work().begin()
    _ok(
        seventh.command_invocations.add(
            sample_invocation(
                _C.PENDING, kind=_K.DESCRIBE, invocation_id=f"inv_{UUID_E}"
            )
        )
    )
    _commit(seventh)
    assert len(harness.committed_command_invocations()) == 4


def test_rebuilt_units_of_work_observe_committed_state_in_deterministic_order(
    harness: PortHarness,
) -> None:
    ordered = (
        sample_experiment(_E.DRAFT, experiment_id=f"exp_{UUID_C}"),
        sample_experiment(_E.DRAFT, experiment_id=f"exp_{UUID_A}"),
        sample_experiment(_E.DRAFT, experiment_id=f"exp_{UUID_B}"),
    )
    transaction = harness.unit_of_work().begin()
    for record in ordered:
        _ok(transaction.experiments.add(record))
    _commit(transaction)
    rolled_back = harness.unit_of_work().begin()
    _ok(
        rolled_back.experiments.add(
            sample_experiment(_E.DRAFT, experiment_id=f"exp_{UUID_D}")
        )
    )
    rolled_back.rollback()
    for _ in range(2):
        rebuilt = harness.unit_of_work().begin()
        for record in ordered:
            assert _ok(rebuilt.experiments.get(record.experiment_id)) == record
        assert _code(rebuilt.experiments.get(f"exp_{UUID_D}")) == INVARIANT_VIOLATION
        rebuilt.rollback()
    assert harness.committed_experiments() == tuple(
        sorted(ordered, key=lambda record: record.experiment_id)
    )


def test_protocol_returns_are_immutable_projections_not_internal_collections(
    harness: PortHarness,
) -> None:
    _put_invocation(harness, sample_invocation(_C.PENDING))
    listed_once = harness.committed_command_invocations()
    listed_twice = harness.committed_command_invocations()
    assert type(listed_once) is tuple
    assert listed_once == listed_twice
    assert listed_once is not listed_twice
    transaction = harness.unit_of_work().begin()
    first = _ok(transaction.command_invocations.list_for_run(RUN_ID, _K.RUN))
    second = _ok(transaction.command_invocations.list_for_run(RUN_ID, _K.RUN))
    assert type(first) is tuple
    assert first == second
    assert first is not second
    transaction.rollback()


# --------------------------------------------------------------------------
# The in-memory double's lifecycle detectors (task-local D2)
# --------------------------------------------------------------------------


def test_the_in_memory_unit_of_work_lifecycle_is_explicit() -> None:
    root = InMemoryUnitOfWork(InMemoryBackingStore())
    assert root.active is False
    with pytest.raises(RuntimeError, match="active transaction"):
        _ = root.experiments
    transaction = root.begin()
    assert transaction.active is True
    with pytest.raises(RuntimeError, match="nested"):
        transaction.begin()
    _commit(transaction)
    assert transaction.active is False
    with pytest.raises(RuntimeError, match="closed"):
        transaction.commit()
    with pytest.raises(RuntimeError, match="closed"):
        _ = transaction.engine_runs
    # Rollback is idempotent, before and after close, so a `finally` is safe.
    transaction.rollback()
    transaction.rollback()
    second = root.begin()
    second.rollback()
    second.rollback()
    assert second.active is False
    with pytest.raises(RuntimeError, match="closed"):
        second.commit()


def test_an_exception_inside_the_context_manager_rolls_back() -> None:
    store = InMemoryBackingStore()

    def add_then_raise() -> None:
        with InMemoryUnitOfWork(store).begin() as transaction:
            _ok(transaction.experiments.add(sample_experiment(_E.DRAFT)))
            raise KeyError("boom")

    with pytest.raises(KeyError):
        add_then_raise()
    assert store.committed_experiments() == ()
    with InMemoryUnitOfWork(store).begin() as transaction:
        _ok(transaction.experiments.add(sample_experiment(_E.DRAFT)))
    # Exit without commit is a rollback, never an implicit commit.
    assert store.committed_experiments() == ()
    with InMemoryUnitOfWork(store).begin() as transaction:
        _ok(transaction.experiments.add(sample_experiment(_E.DRAFT)))
        _commit(transaction)
    assert len(store.committed_experiments()) == 1


# --------------------------------------------------------------------------
# The experiment compare-and-swap coordination hook (task prompt section 10)
# --------------------------------------------------------------------------


def test_without_a_hook_the_experiment_compare_and_swap_is_immediate() -> None:
    store = InMemoryBackingStore()
    root = InMemoryUnitOfWork(store)
    assert root.hooks_installed == ()
    stored = sample_experiment(_E.DRAFT)
    transaction = root.begin()
    _ok(transaction.experiments.add(stored))
    _commit(transaction)
    swap = root.begin()
    assert _ok(swap.experiments.compare_and_swap(0, _bump(stored))) == _bump(stored)
    _commit(swap)


def test_a_hook_fires_once_at_the_boundary_and_cannot_alter_the_candidate() -> None:
    store = InMemoryBackingStore()
    root = InMemoryUnitOfWork(store)
    stored = sample_experiment(_E.DRAFT)
    seed = root.begin()
    _ok(seed.experiments.add(stored))
    _commit(seed)
    observed: list[tuple[int, ExperimentRecord]] = []
    replacement = _bump(stored)
    decoy = _bump(_bump(stored))

    def hook(expected_revision: int, candidate: ExperimentRecord) -> object:
        observed.append((expected_revision, candidate))
        with pytest.raises(ValidationError):
            candidate.__setattr__("revision", 99)
        return decoy

    root.install_experiment_compare_and_swap_hook(hook)
    assert root.hooks_installed == ("experiment_compare_and_swap",)
    transaction = root.begin()
    swapped = _ok(
        transaction.experiments.compare_and_swap(stored.revision, replacement)
    )
    assert observed == [(stored.revision, replacement)]
    assert swapped == replacement
    assert swapped != decoy
    assert not root.hooks_installed
    _commit(transaction)
    assert store.committed_experiments() == (replacement,)
    # Fired once: the next swap runs without it.
    again = root.begin()
    _ok(again.experiments.compare_and_swap(replacement.revision, _bump(replacement)))
    assert len(observed) == 1
    _commit(again)


def test_a_hook_cannot_bypass_expected_revision_validation() -> None:
    store = InMemoryBackingStore()
    root = InMemoryUnitOfWork(store)
    stored = sample_experiment(_E.DRAFT)
    seed = root.begin()
    _ok(seed.experiments.add(stored))
    _commit(seed)
    fired: list[int] = []
    root.install_experiment_compare_and_swap_hook(
        lambda expected, _candidate: fired.append(expected)
    )
    transaction = root.begin()
    assert (
        _code(
            transaction.experiments.compare_and_swap(stored.revision + 1, _bump(stored))
        )
        == CONCURRENCY_CONFLICT
    )
    assert fired == [stored.revision + 1]
    transaction.rollback()
    assert store.committed_experiments() == (stored,)


def test_a_hook_that_commits_a_winner_makes_the_swap_lose_deterministically() -> None:
    store = InMemoryBackingStore()
    root = InMemoryUnitOfWork(store)
    stored = sample_experiment(_E.RUNNING)
    seed = root.begin()
    _ok(seed.experiments.add(stored))
    _commit(seed)
    winner_record = ExperimentRecord.model_validate(
        {
            **stored.model_dump(mode="python"),
            "state": _E.CANCELLED,
            "cancellation_correlation_id": "cancel-1",
            "revision": stored.revision + 1,
            "updated_at_utc": stored.updated_at_utc + timedelta(seconds=1),
        }
    )

    def winner(expected_revision: int, _candidate: ExperimentRecord) -> None:
        concurrent = InMemoryUnitOfWork(store).begin()
        _ok(concurrent.experiments.compare_and_swap(expected_revision, winner_record))
        _commit(concurrent)

    root.install_experiment_compare_and_swap_hook(winner)
    loser = root.begin()
    _ok(loser.engine_runs.add_attempt(sample_run(_R.PENDING)))
    lost = loser.experiments.compare_and_swap(stored.revision, _bump(stored))
    assert _code(lost) == CONCURRENCY_CONFLICT
    loser.rollback()
    assert store.committed_experiments() == (winner_record,)
    assert store.committed_engine_runs() == ()


def test_a_hook_is_removed_before_it_runs_so_a_same_root_winner_does_not_recurse() -> (
    None
):
    store = InMemoryBackingStore()
    root = InMemoryUnitOfWork(store)
    stored = sample_experiment(_E.RUNNING)
    seed = root.begin()
    _ok(seed.experiments.add(stored))
    _commit(seed)
    fired: list[int] = []

    def same_root_winner(expected_revision: int, _candidate: ExperimentRecord) -> None:
        fired.append(expected_revision)
        assert root.hooks_installed == ()
        winner = root.begin()
        _ok(winner.experiments.compare_and_swap(expected_revision, _bump(stored)))
        _commit(winner)

    root.install_experiment_compare_and_swap_hook(same_root_winner)
    loser = root.begin()
    assert _code(
        loser.experiments.compare_and_swap(stored.revision, _bump(stored))
    ) == (CONCURRENCY_CONFLICT)
    loser.rollback()
    assert fired == [stored.revision]
    assert store.committed_experiments() == (_bump(stored),)
    decision_fired: list[RetryDecisionRecord] = []

    def same_root_insert(record: RetryDecisionRecord) -> None:
        decision_fired.append(record)
        winner = root.begin()
        _ok(winner.retry_decisions.insert_if_absent(record))
        _commit(winner)

    root.install_retry_decision_insert_hook(same_root_insert)
    transaction = root.begin()
    outcome = _ok(transaction.retry_decisions.insert_if_absent(sample_retry_decision()))
    assert outcome.inserted is False
    assert len(decision_fired) == 1
    transaction.rollback()


def test_the_factory_names_the_two_diagnostic_preconditions() -> None:
    with pytest.raises(ValueError, match="experiment correlation"):
        stage5_diagnostic(
            CONCURRENCY_CONFLICT,
            "x",
            source_component="experiments.run_service",
            timestamp_utc=INSTANT,
            run_id=RUN_ID,
        )
    with pytest.raises(ValueError, match="requires invocation_id"):
        stage5_diagnostic(
            UNRECOGNIZED_PROCESS_EXIT,
            "x",
            source_component="experiments.invocation_service",
            timestamp_utc=INSTANT,
        )
    built = stage5_diagnostic(
        UNRECOGNIZED_PROCESS_EXIT,
        "x",
        source_component="experiments.invocation_service",
        timestamp_utc=INSTANT,
        invocation_id=INVOCATION_ID,
    )
    assert built.category is DiagnosticCategory.ENGINE_RUNTIME
    assert built.invocation_id == INVOCATION_ID


def test_reset_hooks_prevents_cross_test_leakage() -> None:
    store = InMemoryBackingStore()
    root = InMemoryUnitOfWork(store)

    def never(_expected: int, _candidate: ExperimentRecord) -> None:
        pytest.fail("hook leaked")

    def never_insert(_record: RetryDecisionRecord) -> None:
        pytest.fail("hook leaked")

    root.install_experiment_compare_and_swap_hook(never)
    root.install_retry_decision_insert_hook(never_insert)
    assert root.hooks_installed == (
        "experiment_compare_and_swap",
        "retry_decision_insert",
    )
    root.reset_hooks()
    assert not root.hooks_installed
    stored = sample_experiment(_E.DRAFT)
    transaction = root.begin()
    _ok(transaction.experiments.add(stored))
    _ok(transaction.retry_decisions.insert_if_absent(sample_retry_decision()))
    _ok(transaction.experiments.compare_and_swap(stored.revision, _bump(stored)))
    _commit(transaction)
    # A fresh root over the same store carries no hook either.
    assert not InMemoryUnitOfWork(store).hooks_installed
    root.install_experiment_compare_and_swap_hook(never)
    with pytest.raises(RuntimeError, match="already installed"):
        root.install_experiment_compare_and_swap_hook(never)
    # Hooks are a root-level control: a transaction handle cannot install or reset.
    handle = InMemoryUnitOfWork(store).begin()
    with pytest.raises(RuntimeError, match="root unit of work"):
        handle.install_retry_decision_insert_hook(never_insert)
    with pytest.raises(RuntimeError, match="root unit of work"):
        handle.reset_hooks()
    handle.rollback()


def test_the_doubles_module_declares_no_thread_sleep_or_random_dependency() -> None:
    import doubles.experiments as module

    source = module.__file__
    assert source is not None
    text = Path(source).read_text(encoding="utf-8")
    for forbidden in (
        "import threading",
        "import time",
        "import random",
        "sleep(",
        "datetime.now",
        "uuid4(",
        "import sqlite3",
        "sqlalchemy",
        "import subprocess",
        "import socket",
    ):
        assert forbidden not in text
    # Plan section 11: the doubles are never imported by `crypto_lab`.
    package_root = Path(source).resolve().parents[2] / "src" / "crypto_lab"
    for path in package_root.rglob("*.py"):
        module_text = path.read_text(encoding="utf-8")
        assert "import doubles" not in module_text, path
        assert "from doubles" not in module_text, path
