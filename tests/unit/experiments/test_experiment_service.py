"""Stage 5 Task 6: the sixteen public requests and the five experiment operations.

Plan sections 3.11 (requests), 4 (edge ownership and replay), 7 (queue-time
freeze), 9.1 (cancellation), 9.5 (the loser reloads once) and 10.1. Every
operation runs against the in-memory doubles of plan section 11 through the root
unit of work; the tests seed state through their own transaction and read the
committed store back, so a "no write" assertion is a statement about durable
state, not about a return value.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta

import pytest
from pydantic import ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.compatibility import CompatibilityOutcome
from crypto_lab.domain.experiment import (
    ExperimentRecord,
    build_experiment_spec,
    experiment_spec_hash,
)
from crypto_lab.domain.lifecycle import (
    TERMINAL_EXPERIMENT_STATES,
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.results import Failure, Success
from crypto_lab.experiments.diagnostics import (
    CONCURRENCY_CONFLICT,
    IMMUTABLE_INPUT_MISMATCH,
    INVARIANT_VIOLATION,
    stage5_failure,
)
from crypto_lab.experiments.experiment_service import (
    LostSwap,
    Outcome,
    cancel_experiment,
    create_experiment,
    queue_experiment,
    replace_experiment_spec,
    run_operation,
    transition_experiment,
)
from crypto_lab.experiments.ports import UnitOfWork
from crypto_lab.experiments.requests import (
    REQUEST_OPERATIONS,
    AttemptCreationRequest,
    CancelExperimentRequest,
    CoupledTransitionRequest,
    ExperimentAggregationRequest,
    ExperimentCreationRequest,
    ExperimentQueueRequest,
    ExperimentSpecReplacementRequest,
    ExperimentTransitionRequest,
    InvocationCreationRequest,
    InvocationEnrichmentRequest,
    InvocationTransitionRequest,
    LinkedLaunchRequest,
    LinkedStartRequest,
    RetryEvaluationRequest,
    RunTransitionRequest,
    SuccessorCreationRequest,
)
from doubles.experiments import (
    ARTIFACT_ID,
    DIAG_ID,
    EXPERIMENT_ID,
    INSTANT,
    INVOCATION_ID,
    MATERIAL_HASH,
    OTHER_DIAG_ID,
    REQUEST_HASH,
    RUN_ID,
    SLOT_A,
    SLOT_B,
    UUID_B,
    FixedClock,
    InMemoryBackingStore,
    InMemoryUnitOfWork,
    SequentialIdentitySource,
    sample_draft,
    sample_experiment,
    sample_process_start,
    sample_retry_policy,
    sample_slot_compatibility,
)

_E = ExperimentState
_R = EngineRunState
_C = CommandInvocationState
_K = CommandKind
_REASON = "EXPERIMENT.OPERATOR_DECISION"
_LATER = INSTANT + timedelta(minutes=5)


def _missing(value: object) -> bool:
    return value is MISSING


def _code(result: object) -> str:
    assert isinstance(result, Failure), result
    assert len(result.diagnostics) == 1
    return result.diagnostics[0].error_code


def _ok[T](result: Success[T] | Failure) -> T:
    assert isinstance(result, Success), result
    return result.value


def _commit(unit_of_work: InMemoryUnitOfWork) -> None:
    assert isinstance(unit_of_work.commit(), Success)


def _seed(store: InMemoryBackingStore, *records: ExperimentRecord) -> None:
    transaction = InMemoryUnitOfWork(store).begin()
    for record in records:
        _ok(transaction.experiments.add(record))
    _commit(transaction)


def _stored(
    store: InMemoryBackingStore, experiment_id: str = EXPERIMENT_ID
) -> ExperimentRecord:
    matching = [
        record
        for record in store.committed_experiments()
        if record.experiment_id == experiment_id
    ]
    assert len(matching) == 1
    return matching[0]


def _transition(
    target: ExperimentState, *, revision: int, experiment_id: str = EXPERIMENT_ID
) -> ExperimentTransitionRequest:
    return ExperimentTransitionRequest(
        schema_version="1.0.0",
        experiment_id=experiment_id,
        expected_revision=revision,
        target_state=target,
        reason_code=_REASON,
    )


def _queue(*, revision: int, **overrides: object) -> ExperimentQueueRequest:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "experiment_id": EXPERIMENT_ID,
        "expected_revision": revision,
        "config_derived_retry_policy": sample_retry_policy(),
        "material_base_configuration_hash": MATERIAL_HASH,
        "slot_compatibility": sample_slot_compatibility(),
    }
    payload.update(overrides)
    return ExperimentQueueRequest.model_validate(payload)


def _cancel(
    *, revision: int, correlation_id: str = "cancel-1"
) -> CancelExperimentRequest:
    return CancelExperimentRequest(
        schema_version="1.0.0",
        experiment_id=EXPERIMENT_ID,
        expected_revision=revision,
        correlation_id=correlation_id,
    )


def _replacement(
    *, revision: int, **draft_overrides: object
) -> ExperimentSpecReplacementRequest:
    return ExperimentSpecReplacementRequest(
        schema_version="1.0.0",
        experiment_id=EXPERIMENT_ID,
        expected_revision=revision,
        spec_draft=sample_draft(**draft_overrides),
        material_base_configuration_hash=MATERIAL_HASH,
    )


# --------------------------------------------------------------------------
# The sixteen requests (plan section 3.11)
# --------------------------------------------------------------------------


_OPERATION_NAMES = (
    "create_experiment",
    "replace_experiment_spec",
    "transition_experiment",
    "queue_experiment",
    "cancel_experiment",
    "create_attempt",
    "transition_run",
    "create_invocation",
    "begin_linked_launch",
    "transition_invocation",
    "start_linked_run",
    "enrich_invocation",
    "transition_invocation_and_run",
    "evaluate_retry",
    "create_successor",
    "aggregate_experiment",
)
_FIELD_ORDERS: dict[type[CanonicalModel], tuple[str, ...]] = {
    ExperimentCreationRequest: ("spec_draft", "material_base_configuration_hash"),
    ExperimentSpecReplacementRequest: (
        "experiment_id",
        "expected_revision",
        "spec_draft",
        "material_base_configuration_hash",
    ),
    ExperimentTransitionRequest: (
        "experiment_id",
        "expected_revision",
        "target_state",
        "reason_code",
    ),
    ExperimentQueueRequest: (
        "experiment_id",
        "expected_revision",
        "config_derived_retry_policy",
        "material_base_configuration_hash",
        "slot_compatibility",
    ),
    CancelExperimentRequest: ("experiment_id", "expected_revision", "correlation_id"),
    AttemptCreationRequest: (
        "experiment_id",
        "logical_slot_id",
        "expected_experiment_revision",
        "request_hash",
    ),
    RunTransitionRequest: (
        "run_id",
        "expected_revision",
        "target_state",
        "reason_code",
        "primary_terminal_diagnostic_id",
        "availability_observation_id",
    ),
    InvocationCreationRequest: (
        "command_kind",
        "adapter_name",
        "adapter_version",
        "run_id",
        "expected_run_revision",
        "request_hash",
        "timeout_seconds",
    ),
    LinkedLaunchRequest: (
        "invocation_id",
        "expected_invocation_revision",
        "run_id",
        "expected_run_revision",
    ),
    InvocationTransitionRequest: (
        "invocation_id",
        "expected_revision",
        "target_state",
        "reason_code",
        "process_start",
        "native_exit_value",
        "primary_diagnostic_id",
        "diagnostic_ids",
    ),
    LinkedStartRequest: (
        "invocation_id",
        "expected_invocation_revision",
        "run_id",
        "expected_run_revision",
        "process_start",
    ),
    InvocationEnrichmentRequest: (
        "invocation_id",
        "expected_revision",
        "native_exit_value",
        "cleanup_complete",
        "stderr_artifact_id",
        "additional_diagnostic_ids",
    ),
    CoupledTransitionRequest: ("invocation", "run"),
    RetryEvaluationRequest: (
        "experiment_id",
        "logical_slot_id",
        "predecessor_run_id",
        "expected_experiment_revision",
        "expected_predecessor_revision",
    ),
    SuccessorCreationRequest: (
        "experiment_id",
        "logical_slot_id",
        "predecessor_run_id",
        "expected_experiment_revision",
        "request_hash",
    ),
    ExperimentAggregationRequest: ("experiment_id", "expected_revision"),
}
#: Plan section 3.11's closing sentence, as field names no request may carry.
_AUTHORITATIVE_FIELD_NAMES = frozenset(
    {
        "revision",
        "state",
        "created_attempt_count",
        "latest_attempt_state",
        "outcome",
        "denial_reason",
        "hard_block_error_code",
        "retry_not_before_utc",
        "reserved_successor_attempt_number",
        "verdict",
        "reason_codes",
        "used_approximation",
        "late_not_applicable",
        "process_exit_category",
        "attempt_token",
        "attempt_token_hash",
        "cancellation_correlation_id",
        "spec_hash",
        "configuration_hash",
    }
)


def _invocation_transition(**overrides: object) -> InvocationTransitionRequest:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "invocation_id": INVOCATION_ID,
        "expected_revision": 1,
        "target_state": _C.CANCELLED,
        "reason_code": "PROCESS.CANCELLED",
        "primary_diagnostic_id": DIAG_ID,
        "diagnostic_ids": (DIAG_ID,),
    }
    payload.update(overrides)
    return InvocationTransitionRequest.model_validate(payload)


def _sample_requests() -> tuple[CanonicalModel, ...]:
    run_transition = RunTransitionRequest(
        schema_version="1.0.0",
        run_id=RUN_ID,
        expected_revision=4,
        target_state=_R.TIMED_OUT,
        reason_code="PROCESS.RUN_TIMED_OUT",
        primary_terminal_diagnostic_id=DIAG_ID,
    )
    invocation_transition = _invocation_transition(target_state=_C.TIMED_OUT)
    return (
        ExperimentCreationRequest(
            schema_version="1.0.0",
            spec_draft=sample_draft(),
            material_base_configuration_hash=MATERIAL_HASH,
        ),
        _replacement(revision=0),
        _transition(_E.VALIDATED, revision=0),
        _queue(revision=1),
        _cancel(revision=0),
        AttemptCreationRequest(
            schema_version="1.0.0",
            experiment_id=EXPERIMENT_ID,
            logical_slot_id=SLOT_A,
            expected_experiment_revision=2,
            request_hash=REQUEST_HASH,
        ),
        run_transition,
        InvocationCreationRequest(
            schema_version="1.0.0",
            command_kind=_K.RUN,
            adapter_name="adapter.alpha",
            adapter_version="1.0.0",
            run_id=RUN_ID,
            expected_run_revision=2,
            request_hash=REQUEST_HASH,
            timeout_seconds=120,
        ),
        LinkedLaunchRequest(
            schema_version="1.0.0",
            invocation_id=INVOCATION_ID,
            expected_invocation_revision=0,
            run_id=RUN_ID,
            expected_run_revision=2,
        ),
        invocation_transition,
        LinkedStartRequest(
            schema_version="1.0.0",
            invocation_id=INVOCATION_ID,
            expected_invocation_revision=1,
            run_id=RUN_ID,
            expected_run_revision=3,
            process_start=sample_process_start(),
        ),
        InvocationEnrichmentRequest(
            schema_version="1.0.0",
            invocation_id=INVOCATION_ID,
            expected_revision=3,
            cleanup_complete=True,
            stderr_artifact_id=ARTIFACT_ID,
            additional_diagnostic_ids=(),
        ),
        CoupledTransitionRequest(
            schema_version="1.0.0", invocation=invocation_transition, run=run_transition
        ),
        RetryEvaluationRequest(
            schema_version="1.0.0",
            experiment_id=EXPERIMENT_ID,
            logical_slot_id=SLOT_A,
            predecessor_run_id=RUN_ID,
            expected_experiment_revision=3,
            expected_predecessor_revision=5,
        ),
        SuccessorCreationRequest(
            schema_version="1.0.0",
            experiment_id=EXPERIMENT_ID,
            logical_slot_id=SLOT_A,
            predecessor_run_id=RUN_ID,
            expected_experiment_revision=4,
            request_hash=REQUEST_HASH,
        ),
        ExperimentAggregationRequest(
            schema_version="1.0.0", experiment_id=EXPERIMENT_ID, expected_revision=3
        ),
    )


def test_the_request_inventory_is_one_to_one_with_the_sixteen_operations() -> None:
    assert len(REQUEST_OPERATIONS) == 16
    assert set(REQUEST_OPERATIONS) == set(_FIELD_ORDERS)
    assert tuple(REQUEST_OPERATIONS.values()) == _OPERATION_NAMES
    assert len(set(REQUEST_OPERATIONS.values())) == 16
    for request_type in REQUEST_OPERATIONS:
        assert issubclass(request_type, CanonicalModel)
        assert request_type.__module__ == "crypto_lab.experiments.requests"


def test_every_request_carries_the_envelope_first_and_the_plan_field_order() -> None:
    for request_type, fields in _FIELD_ORDERS.items():
        assert tuple(request_type.model_fields) == ("schema_version", *fields), (
            request_type.__name__
        )
        assert not _AUTHORITATIVE_FIELD_NAMES & set(fields), request_type.__name__


@pytest.mark.parametrize(
    "instance", _sample_requests(), ids=lambda item: type(item).__name__
)
def test_every_request_is_strict_frozen_and_closed(instance: CanonicalModel) -> None:
    payload = instance.model_dump(mode="python")
    assert type(instance).model_validate(payload) == instance
    with pytest.raises(ValidationError):
        type(instance).model_validate({**payload, "unexpected": 1})
    with pytest.raises(ValidationError):
        instance.__setattr__("schema_version", "2.0.0")
    with pytest.raises(ValidationError):
        type(instance).model_validate({**payload, "schema_version": "1.0.1"})
    # Absent optional material is MISSING, never None, in both dump modes.
    for name, value in instance.model_dump(mode="python").items():
        assert value is not None, name
    assert None not in instance.model_dump(mode="json").values()


def test_expected_revisions_are_non_negative_integers() -> None:
    with pytest.raises(ValidationError):
        _transition(_E.VALIDATED, revision=-1)
    with pytest.raises(ValidationError):
        ExperimentTransitionRequest.model_validate(
            {
                **_transition(_E.VALIDATED, revision=0).model_dump(mode="python"),
                "expected_revision": "0",
            }
        )


def test_invocation_transition_requires_process_start_exactly_on_running() -> None:
    with pytest.raises(ValidationError, match="process_start"):
        _invocation_transition(
            target_state=_C.RUNNING,
            primary_diagnostic_id=MISSING,
            diagnostic_ids=(),
        )
    with pytest.raises(ValidationError, match="process_start"):
        _invocation_transition(process_start=sample_process_start())
    accepted = _invocation_transition(
        target_state=_C.RUNNING,
        process_start=sample_process_start(),
        primary_diagnostic_id=MISSING,
        diagnostic_ids=(),
    )
    assert accepted.process_start == sample_process_start()
    assert _missing(accepted.primary_diagnostic_id)
    assert _missing(accepted.native_exit_value)


def test_invocation_transition_requires_the_primary_among_its_diagnostics() -> None:
    with pytest.raises(ValidationError, match="member of diagnostic_ids"):
        _invocation_transition(diagnostic_ids=(OTHER_DIAG_ID,))
    with pytest.raises(ValidationError, match="unique"):
        _invocation_transition(diagnostic_ids=(DIAG_ID, DIAG_ID))
    with pytest.raises(ValidationError, match="sorted"):
        _invocation_transition(diagnostic_ids=(OTHER_DIAG_ID, DIAG_ID))
    with pytest.raises(ValidationError):
        _invocation_transition(native_exit_value=4294967296)


def test_enrichment_cannot_uncomplete_cleanup_and_orders_its_diagnostics() -> None:
    with pytest.raises(ValidationError):
        InvocationEnrichmentRequest(
            schema_version="1.0.0",
            invocation_id=INVOCATION_ID,
            expected_revision=3,
            cleanup_complete=False,
            additional_diagnostic_ids=(),
        )
    with pytest.raises(ValidationError, match="sorted"):
        InvocationEnrichmentRequest(
            schema_version="1.0.0",
            invocation_id=INVOCATION_ID,
            expected_revision=3,
            additional_diagnostic_ids=(OTHER_DIAG_ID, DIAG_ID),
        )
    empty = InvocationEnrichmentRequest(
        schema_version="1.0.0",
        invocation_id=INVOCATION_ID,
        expected_revision=3,
        additional_diagnostic_ids=(),
    )
    assert _missing(empty.cleanup_complete)
    assert _missing(empty.native_exit_value)
    assert _missing(empty.stderr_artifact_id)


def test_invocation_creation_carries_only_the_envelope_timeout_bound() -> None:
    def build(kind: CommandKind, timeout_seconds: int) -> InvocationCreationRequest:
        return InvocationCreationRequest(
            schema_version="1.0.0",
            command_kind=kind,
            adapter_name="adapter.alpha",
            adapter_version="1.0.0",
            request_hash=REQUEST_HASH,
            timeout_seconds=timeout_seconds,
        )

    with pytest.raises(ValidationError):
        build(_K.DESCRIBE, 0)
    with pytest.raises(ValidationError):
        build(_K.RUN, 604801)
    # The kind-specific bound is a plan section 6 matrix cell, a service result.
    over = build(_K.DESCRIBE, 301)
    assert over.timeout_seconds == 301
    assert _missing(over.run_id)
    assert _missing(over.expected_run_revision)


def test_queue_request_bounds_slots_and_leaves_alignment_to_the_freeze() -> None:
    with pytest.raises(ValidationError):
        _queue(revision=1, slot_compatibility=())
    with pytest.raises(ValidationError):
        _queue(revision=1, slot_compatibility=sample_slot_compatibility() * 5)
    misordered = _queue(
        revision=1, slot_compatibility=sample_slot_compatibility()[::-1]
    )
    assert misordered.slot_compatibility[0].logical_slot_id == SLOT_B


# --------------------------------------------------------------------------
# create_experiment (plan 10.1 row 1)
# --------------------------------------------------------------------------


def _create(store: InMemoryBackingStore, *, seed: str = "task6") -> ExperimentRecord:
    return _ok(
        create_experiment(
            ExperimentCreationRequest(
                schema_version="1.0.0",
                spec_draft=sample_draft(),
                material_base_configuration_hash=MATERIAL_HASH,
            ),
            unit_of_work=InMemoryUnitOfWork(store),
            clock=FixedClock(INSTANT),
            identity_source=SequentialIdentitySource(seed),
        )
    )


def test_create_experiment_lands_in_draft_at_revision_zero_with_derived_material() -> (
    None
):
    store = InMemoryBackingStore()
    created = _create(store)
    assert created.state is _E.DRAFT
    assert created.revision == 0
    assert created.created_at_utc == INSTANT
    assert created.updated_at_utc == INSTANT
    assert (
        created.experiment_id == SequentialIdentitySource("task6").new_experiment_id()
    )
    assert created.spec == build_experiment_spec(sample_draft(), MATERIAL_HASH, INSTANT)
    assert created.spec_hash == experiment_spec_hash(created.spec)
    assert _missing(created.slot_compatibility)
    assert _missing(created.cancellation_correlation_id)
    assert store.committed_experiments() == (created,)
    # Deterministic: the same inputs over another store yield the same record.
    assert _create(InMemoryBackingStore()) == created


def test_create_experiment_reports_an_identity_collision_as_a_conflict() -> None:
    store = InMemoryBackingStore()
    colliding = SequentialIdentitySource("task6").new_experiment_id()
    _seed(store, sample_experiment(_E.DRAFT, experiment_id=colliding))
    result = create_experiment(
        ExperimentCreationRequest(
            schema_version="1.0.0",
            spec_draft=sample_draft(),
            material_base_configuration_hash=MATERIAL_HASH,
        ),
        unit_of_work=InMemoryUnitOfWork(store),
        clock=FixedClock(INSTANT),
        identity_source=SequentialIdentitySource("task6"),
    )
    assert _code(result) == CONCURRENCY_CONFLICT
    assert store.committed_experiments() == (
        sample_experiment(_E.DRAFT, experiment_id=colliding),
    )


# --------------------------------------------------------------------------
# replace_experiment_spec (plan 4, 7, 10.1 row 2)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("state", [_E.DRAFT, _E.VALIDATED])
def test_replacing_the_spec_lands_in_draft_with_a_fresh_spec(
    state: ExperimentState,
) -> None:
    store = InMemoryBackingStore()
    stored = sample_experiment(state)
    _seed(store, stored)
    replaced = _ok(
        replace_experiment_spec(
            _replacement(revision=stored.revision, strategy_version_hash="3" * 64),
            unit_of_work=InMemoryUnitOfWork(store),
            clock=FixedClock(_LATER),
        )
    )
    assert replaced.state is _E.DRAFT
    assert replaced.revision == stored.revision + 1
    assert replaced.updated_at_utc == _LATER
    assert replaced.created_at_utc == stored.created_at_utc
    assert replaced.spec.strategy_version_hash == "3" * 64
    assert replaced.spec.created_at_utc == _LATER
    assert replaced.spec_hash == experiment_spec_hash(replaced.spec)
    assert replaced.spec_hash != stored.spec_hash
    assert _stored(store) == replaced


@pytest.mark.parametrize("state", [_E.QUEUED, _E.RUNNING])
def test_replacing_a_frozen_spec_is_an_immutable_input_mismatch(
    state: ExperimentState,
) -> None:
    store = InMemoryBackingStore()
    stored = sample_experiment(state)
    _seed(store, stored)
    result = replace_experiment_spec(
        _replacement(revision=stored.revision),
        unit_of_work=InMemoryUnitOfWork(store),
        clock=FixedClock(_LATER),
    )
    assert _code(result) == IMMUTABLE_INPUT_MISMATCH
    assert _stored(store) == stored


@pytest.mark.parametrize("state", sorted(TERMINAL_EXPERIMENT_STATES))
def test_replacing_a_terminal_spec_is_an_invariant_violation(
    state: ExperimentState,
) -> None:
    store = InMemoryBackingStore()
    stored = sample_experiment(state)
    _seed(store, stored)
    result = replace_experiment_spec(
        _replacement(revision=stored.revision),
        unit_of_work=InMemoryUnitOfWork(store),
        clock=FixedClock(_LATER),
    )
    assert _code(result) == INVARIANT_VIOLATION
    assert _stored(store) == stored


def test_replacing_with_a_stale_revision_or_a_missing_experiment_fails_cleanly() -> (
    None
):
    store = InMemoryBackingStore()
    stored = sample_experiment(_E.DRAFT)
    _seed(store, stored)
    stale = replace_experiment_spec(
        _replacement(revision=stored.revision + 1),
        unit_of_work=InMemoryUnitOfWork(store),
        clock=FixedClock(_LATER),
    )
    assert _code(stale) == CONCURRENCY_CONFLICT
    assert _stored(store) == stored
    missing = replace_experiment_spec(
        _replacement(revision=0),
        unit_of_work=InMemoryUnitOfWork(InMemoryBackingStore()),
        clock=FixedClock(_LATER),
    )
    assert _code(missing) == INVARIANT_VIOLATION


# --------------------------------------------------------------------------
# transition_experiment (plan 4, 10.1 row 3)
# --------------------------------------------------------------------------


def test_transition_experiment_owns_draft_to_validated_and_queued_to_failed() -> None:
    store = InMemoryBackingStore()
    draft = sample_experiment(_E.DRAFT)
    _seed(store, draft)
    validated = _ok(
        transition_experiment(
            _transition(_E.VALIDATED, revision=0),
            unit_of_work=InMemoryUnitOfWork(store),
            clock=FixedClock(_LATER),
        )
    )
    assert validated.state is _E.VALIDATED
    assert validated.revision == 1
    assert validated.updated_at_utc == _LATER
    assert validated.spec == draft.spec
    assert _stored(store) == validated
    queued_store = InMemoryBackingStore()
    queued = sample_experiment(_E.QUEUED)
    _seed(queued_store, queued)
    failed = _ok(
        transition_experiment(
            _transition(_E.FAILED, revision=queued.revision),
            unit_of_work=InMemoryUnitOfWork(queued_store),
            clock=FixedClock(_LATER),
        )
    )
    assert failed.state is _E.FAILED
    assert failed.revision == queued.revision + 1
    assert failed.slot_compatibility == queued.slot_compatibility
    assert _stored(queued_store) == failed


@pytest.mark.parametrize(
    "target",
    [
        _E.DRAFT,
        _E.QUEUED,
        _E.RUNNING,
        _E.COMPLETED,
        _E.COMPLETED_WITH_WARNINGS,
        _E.CANCELLED,
    ],
)
def test_a_target_outside_the_owned_set_is_rejected_before_anything_else(
    target: ExperimentState,
) -> None:
    # Even a same-state request at the matching revision is not a replay when
    # the target is not this operation's to produce (plan 4 edge ownership).
    store = InMemoryBackingStore()
    stored = sample_experiment(target)
    _seed(store, stored)
    result = transition_experiment(
        _transition(target, revision=stored.revision),
        unit_of_work=InMemoryUnitOfWork(store),
        clock=FixedClock(_LATER),
    )
    assert _code(result) == INVARIANT_VIOLATION
    assert _stored(store) == stored


@pytest.mark.parametrize(
    ("state", "target"),
    [
        (_E.DRAFT, _E.FAILED),
        (_E.VALIDATED, _E.VALIDATED),
        (_E.RUNNING, _E.FAILED),
        (_E.RUNNING, _E.VALIDATED),
        (_E.QUEUED, _E.VALIDATED),
    ],
)
def test_an_edge_this_operation_does_not_own_is_an_invariant_violation(
    state: ExperimentState, target: ExperimentState
) -> None:
    if state is target:
        pytest.skip("same-state requests are the replay cases below")
    store = InMemoryBackingStore()
    stored = sample_experiment(state)
    _seed(store, stored)
    result = transition_experiment(
        _transition(target, revision=stored.revision),
        unit_of_work=InMemoryUnitOfWork(store),
        clock=FixedClock(_LATER),
    )
    assert _code(result) == INVARIANT_VIOLATION
    assert _stored(store) == stored


@pytest.mark.parametrize("state", [_E.VALIDATED, _E.FAILED])
def test_a_same_state_request_at_the_matching_revision_replays_without_a_write(
    state: ExperimentState,
) -> None:
    store = InMemoryBackingStore()
    stored = sample_experiment(state)
    _seed(store, stored)
    clock = FixedClock(_LATER)
    replayed = _ok(
        transition_experiment(
            _transition(state, revision=stored.revision),
            unit_of_work=InMemoryUnitOfWork(store),
            clock=clock,
        )
    )
    assert replayed == stored
    assert _stored(store) == stored
    stale = transition_experiment(
        _transition(state, revision=stored.revision + 1),
        unit_of_work=InMemoryUnitOfWork(store),
        clock=clock,
    )
    assert _code(stale) == CONCURRENCY_CONFLICT
    assert _stored(store) == stored


def test_a_terminal_experiment_accepts_no_owned_transition_regardless_of_revision() -> (
    None
):
    store = InMemoryBackingStore()
    stored = sample_experiment(_E.COMPLETED)
    _seed(store, stored)
    for revision in (stored.revision, stored.revision + 7):
        result = transition_experiment(
            _transition(_E.FAILED, revision=revision),
            unit_of_work=InMemoryUnitOfWork(store),
            clock=FixedClock(_LATER),
        )
        assert _code(result) == INVARIANT_VIOLATION
    assert _stored(store) == stored


def test_a_stale_revision_on_an_owned_edge_is_a_conflict_with_no_write() -> None:
    store = InMemoryBackingStore()
    stored = sample_experiment(_E.DRAFT)
    _seed(store, stored)
    result = transition_experiment(
        _transition(_E.VALIDATED, revision=stored.revision + 1),
        unit_of_work=InMemoryUnitOfWork(store),
        clock=FixedClock(_LATER),
    )
    assert _code(result) == CONCURRENCY_CONFLICT
    assert _stored(store) == stored
    missing = transition_experiment(
        _transition(_E.VALIDATED, revision=0),
        unit_of_work=InMemoryUnitOfWork(InMemoryBackingStore()),
        clock=FixedClock(_LATER),
    )
    assert _code(missing) == INVARIANT_VIOLATION


# --------------------------------------------------------------------------
# queue_experiment (plan 7, 10.1 row 4)
# --------------------------------------------------------------------------


def test_queue_experiment_freezes_slot_compatibility_at_the_validated_revision() -> (
    None
):
    store = InMemoryBackingStore()
    validated = sample_experiment(_E.VALIDATED)
    _seed(store, validated)
    queued = _ok(
        queue_experiment(
            _queue(revision=validated.revision),
            unit_of_work=InMemoryUnitOfWork(store),
            clock=FixedClock(_LATER),
        )
    )
    assert queued.state is _E.QUEUED
    assert queued.revision == validated.revision + 1
    assert queued.updated_at_utc == _LATER
    assert queued.slot_compatibility == sample_slot_compatibility()
    assert queued.spec == validated.spec
    assert queued.spec_hash == validated.spec_hash
    assert _stored(store) == queued


def test_queue_replays_only_when_every_frozen_input_agrees() -> None:
    store = InMemoryBackingStore()
    queued = sample_experiment(_E.QUEUED)
    _seed(store, queued)
    replayed = _ok(
        queue_experiment(
            _queue(revision=queued.revision),
            unit_of_work=InMemoryUnitOfWork(store),
            clock=FixedClock(_LATER),
        )
    )
    assert replayed == queued
    assert _stored(store) == queued
    divergent = (
        _queue(
            revision=queued.revision,
            slot_compatibility=sample_slot_compatibility()[::-1],
        ),
        _queue(
            revision=queued.revision,
            config_derived_retry_policy=sample_retry_policy(retry_delay_seconds=31),
        ),
        _queue(revision=queued.revision, material_base_configuration_hash="d" * 64),
        _queue(
            revision=queued.revision,
            slot_compatibility=sample_slot_compatibility(
                outcomes={SLOT_B: CompatibilityOutcome.UNAVAILABLE}
            ),
        ),
    )
    for request in divergent:
        result = queue_experiment(
            request, unit_of_work=InMemoryUnitOfWork(store), clock=FixedClock(_LATER)
        )
        assert _code(result) == IMMUTABLE_INPUT_MISMATCH
    assert _stored(store) == queued
    # Already QUEUED at another revision: the loser of an identical race, a conflict.
    stale = queue_experiment(
        _queue(revision=queued.revision + 1),
        unit_of_work=InMemoryUnitOfWork(store),
        clock=FixedClock(_LATER),
    )
    assert _code(stale) == CONCURRENCY_CONFLICT
    assert _stored(store) == queued


def test_queue_rejects_each_frozen_input_mismatch_without_a_write() -> None:
    store = InMemoryBackingStore()
    validated = sample_experiment(_E.VALIDATED)
    _seed(store, validated)
    compatibility = sample_slot_compatibility()
    cases = {
        "retry policy": _queue(
            revision=validated.revision,
            config_derived_retry_policy=sample_retry_policy(
                maximum_attempts_per_slot=2
            ),
        ),
        "material hash": _queue(
            revision=validated.revision, material_base_configuration_hash="d" * 64
        ),
        "omitted slot": _queue(
            revision=validated.revision, slot_compatibility=compatibility[:1]
        ),
        "duplicated slot": _queue(
            revision=validated.revision,
            slot_compatibility=(compatibility[0], compatibility[0]),
        ),
        "misordered slots": _queue(
            revision=validated.revision, slot_compatibility=compatibility[::-1]
        ),
    }
    for label, request in cases.items():
        result = queue_experiment(
            request, unit_of_work=InMemoryUnitOfWork(store), clock=FixedClock(_LATER)
        )
        assert _code(result) == IMMUTABLE_INPUT_MISMATCH, label
    assert _stored(store) == validated
    assert canonical_json_bytes(validated.spec.retry_policy) == canonical_json_bytes(
        sample_retry_policy()
    )


def test_the_driver_reloads_exactly_once_and_then_returns_the_second_loss() -> None:
    # The operations' own revision checks answer first after a reload, so the
    # driver's terminal branch is proven directly: a `once` that loses twice.
    store = InMemoryBackingStore()
    root = InMemoryUnitOfWork(store)
    conflict = stage5_failure(
        CONCURRENCY_CONFLICT,
        "lost",
        source_component="experiments.experiment_service",
        timestamp_utc=INSTANT,
    )
    calls: list[bool] = []

    def always_lost(transaction: UnitOfWork) -> Outcome[ExperimentRecord]:
        assert isinstance(transaction, InMemoryUnitOfWork)
        calls.append(transaction.active)
        return LostSwap(conflict)

    result = run_operation(root, always_lost)
    assert result is conflict
    assert calls == [True, True]
    assert root.active is False
    assert store.committed_experiments() == ()

    committed: list[ExperimentRecord] = []

    def writes_once(transaction: UnitOfWork) -> Outcome[ExperimentRecord]:
        record = sample_experiment(_E.DRAFT)
        _ok(transaction.experiments.add(record))
        committed.append(record)
        return Success[ExperimentRecord](outcome="SUCCESS", value=record)

    assert _ok(run_operation(root, writes_once)) == committed[0]
    assert store.committed_experiments() == (committed[0],)

    def fails_after_a_write(transaction: UnitOfWork) -> Outcome[ExperimentRecord]:
        other = sample_experiment(_E.DRAFT, experiment_id=f"exp_{UUID_B}")
        _ok(transaction.experiments.add(other))
        return conflict

    assert run_operation(root, fails_after_a_write) is conflict
    # A Failure is returned after rollback: the staged insert never published.
    assert store.committed_experiments() == (committed[0],)


@pytest.mark.parametrize("state", [_E.DRAFT, _E.RUNNING, _E.COMPLETED, _E.CANCELLED])
def test_queue_from_any_state_but_validated_is_an_invariant_violation(
    state: ExperimentState,
) -> None:
    store = InMemoryBackingStore()
    stored = sample_experiment(state)
    _seed(store, stored)
    result = queue_experiment(
        _queue(revision=stored.revision + 1),
        unit_of_work=InMemoryUnitOfWork(store),
        clock=FixedClock(_LATER),
    )
    assert _code(result) == INVARIANT_VIOLATION
    assert _stored(store) == stored


def test_queue_stale_revision_conflicts_and_missing_experiment_is_invariant() -> None:
    store = InMemoryBackingStore()
    validated = sample_experiment(_E.VALIDATED)
    _seed(store, validated)
    stale = queue_experiment(
        _queue(revision=validated.revision + 1),
        unit_of_work=InMemoryUnitOfWork(store),
        clock=FixedClock(_LATER),
    )
    assert _code(stale) == CONCURRENCY_CONFLICT
    assert _stored(store) == validated
    missing = queue_experiment(
        _queue(revision=1),
        unit_of_work=InMemoryUnitOfWork(InMemoryBackingStore()),
        clock=FixedClock(_LATER),
    )
    assert _code(missing) == INVARIANT_VIOLATION


# --------------------------------------------------------------------------
# cancel_experiment (plan 9.1, 10.1 row 5)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("state", [_E.DRAFT, _E.VALIDATED, _E.QUEUED, _E.RUNNING])
def test_cancellation_wins_from_every_non_terminal_state(
    state: ExperimentState,
) -> None:
    store = InMemoryBackingStore()
    stored = sample_experiment(state)
    _seed(store, stored)
    cancelled = _ok(
        cancel_experiment(
            _cancel(revision=stored.revision, correlation_id="cancel-7"),
            unit_of_work=InMemoryUnitOfWork(store),
            clock=FixedClock(_LATER),
        )
    )
    assert cancelled.state is _E.CANCELLED
    assert cancelled.cancellation_correlation_id == "cancel-7"
    assert cancelled.revision == stored.revision + 1
    assert cancelled.updated_at_utc == _LATER
    assert cancelled.slot_compatibility == stored.slot_compatibility
    assert _stored(store) == cancelled


def test_cancellation_replays_on_the_correlation_identity_regardless_of_revision() -> (
    None
):
    store = InMemoryBackingStore()
    stored = sample_experiment(_E.CANCELLED, correlation_id="cancel-7")
    _seed(store, stored)
    for revision in (stored.revision, stored.revision - 3, stored.revision + 9):
        replayed = _ok(
            cancel_experiment(
                _cancel(revision=revision, correlation_id="cancel-7"),
                unit_of_work=InMemoryUnitOfWork(store),
                clock=FixedClock(_LATER),
            )
        )
        assert replayed == stored
    other = cancel_experiment(
        _cancel(revision=stored.revision, correlation_id="cancel-8"),
        unit_of_work=InMemoryUnitOfWork(store),
        clock=FixedClock(_LATER),
    )
    assert _code(other) == CONCURRENCY_CONFLICT
    assert _stored(store) == stored


@pytest.mark.parametrize("state", [_E.COMPLETED, _E.COMPLETED_WITH_WARNINGS, _E.FAILED])
def test_cancelling_a_terminal_non_cancelled_experiment_is_an_invariant_violation(
    state: ExperimentState,
) -> None:
    store = InMemoryBackingStore()
    stored = sample_experiment(state)
    _seed(store, stored)
    result = cancel_experiment(
        _cancel(revision=stored.revision),
        unit_of_work=InMemoryUnitOfWork(store),
        clock=FixedClock(_LATER),
    )
    assert _code(result) == INVARIANT_VIOLATION
    assert _stored(store) == stored


def test_cancelling_with_a_stale_revision_is_a_conflict() -> None:
    store = InMemoryBackingStore()
    stored = sample_experiment(_E.RUNNING)
    _seed(store, stored)
    result = cancel_experiment(
        _cancel(revision=stored.revision - 1),
        unit_of_work=InMemoryUnitOfWork(store),
        clock=FixedClock(_LATER),
    )
    assert _code(result) == CONCURRENCY_CONFLICT
    assert _stored(store) == stored
    missing = cancel_experiment(
        _cancel(revision=0),
        unit_of_work=InMemoryUnitOfWork(InMemoryBackingStore()),
        clock=FixedClock(_LATER),
    )
    assert _code(missing) == INVARIANT_VIOLATION


# --------------------------------------------------------------------------
# The loser reloads once (plan 9.5) and restart (plan 11)
# --------------------------------------------------------------------------


def _winner_cancels(
    store: InMemoryBackingStore,
) -> Callable[[int, ExperimentRecord], None]:
    def hook(expected_revision: int, _candidate: ExperimentRecord) -> None:
        _ok(
            cancel_experiment(
                _cancel(revision=expected_revision, correlation_id="winner"),
                unit_of_work=InMemoryUnitOfWork(store),
                clock=FixedClock(INSTANT + timedelta(seconds=1)),
            )
        )

    return hook


def test_a_transition_losing_to_a_cancellation_reloads_and_reports_its_own_rule() -> (
    None
):
    store = InMemoryBackingStore()
    stored = sample_experiment(_E.DRAFT)
    _seed(store, stored)
    root = InMemoryUnitOfWork(store)
    root.install_experiment_compare_and_swap_hook(_winner_cancels(store))
    result = transition_experiment(
        _transition(_E.VALIDATED, revision=stored.revision),
        unit_of_work=root,
        clock=FixedClock(_LATER),
    )
    # The reloaded record is terminal: plan 4's rule, not a uniform loser code.
    assert _code(result) == INVARIANT_VIOLATION
    winner = _stored(store)
    assert winner.state is _E.CANCELLED
    assert winner.cancellation_correlation_id == "winner"
    assert winner.revision == stored.revision + 1
    assert root.hooks_installed == ()


def test_a_queue_that_loses_to_a_cancellation_reports_the_freeze_rule() -> None:
    store = InMemoryBackingStore()
    stored = sample_experiment(_E.VALIDATED)
    _seed(store, stored)
    root = InMemoryUnitOfWork(store)
    root.install_experiment_compare_and_swap_hook(_winner_cancels(store))
    result = queue_experiment(
        _queue(revision=stored.revision), unit_of_work=root, clock=FixedClock(_LATER)
    )
    assert _code(result) == INVARIANT_VIOLATION
    assert _stored(store).state is _E.CANCELLED


def test_a_cancellation_that_loses_to_a_state_preserving_bump_reports_a_conflict() -> (
    None
):
    store = InMemoryBackingStore()
    stored = sample_experiment(_E.RUNNING)
    _seed(store, stored)
    root = InMemoryUnitOfWork(store)

    def bump(expected_revision: int, _candidate: ExperimentRecord) -> None:
        winner = InMemoryUnitOfWork(store).begin()
        bumped = ExperimentRecord.model_validate(
            {
                **stored.model_dump(mode="python"),
                "revision": expected_revision + 1,
                "updated_at_utc": stored.updated_at_utc + timedelta(seconds=1),
            }
        )
        _ok(winner.experiments.compare_and_swap(expected_revision, bumped))
        _commit(winner)

    root.install_experiment_compare_and_swap_hook(bump)
    result = cancel_experiment(
        _cancel(revision=stored.revision), unit_of_work=root, clock=FixedClock(_LATER)
    )
    assert _code(result) == CONCURRENCY_CONFLICT
    reloaded = _stored(store)
    assert reloaded.state is _E.RUNNING
    assert reloaded.revision == stored.revision + 1
    # The caller may cancel again at the new revision.
    again = _ok(
        cancel_experiment(
            _cancel(revision=reloaded.revision),
            unit_of_work=root,
            clock=FixedClock(_LATER),
        )
    )
    assert again.state is _E.CANCELLED


def test_a_cancellation_that_loses_to_an_identical_cancellation_replays() -> None:
    store = InMemoryBackingStore()
    stored = sample_experiment(_E.RUNNING)
    _seed(store, stored)
    root = InMemoryUnitOfWork(store)

    def same_cancellation(expected_revision: int, _candidate: ExperimentRecord) -> None:
        _ok(
            cancel_experiment(
                _cancel(revision=expected_revision, correlation_id="cancel-1"),
                unit_of_work=InMemoryUnitOfWork(store),
                clock=FixedClock(INSTANT + timedelta(seconds=1)),
            )
        )

    root.install_experiment_compare_and_swap_hook(same_cancellation)
    result = _ok(
        cancel_experiment(
            _cancel(revision=stored.revision, correlation_id="cancel-1"),
            unit_of_work=root,
            clock=FixedClock(_LATER),
        )
    )
    assert result == _stored(store)
    assert result.updated_at_utc == INSTANT + timedelta(seconds=1)


def test_committed_state_survives_a_rebuild_and_rolled_back_state_does_not() -> None:
    store = InMemoryBackingStore()
    created = _create(store)
    validated = _ok(
        transition_experiment(
            _transition(_E.VALIDATED, revision=0, experiment_id=created.experiment_id),
            unit_of_work=InMemoryUnitOfWork(store),
            clock=FixedClock(_LATER),
        )
    )
    rejected = transition_experiment(
        _transition(_E.FAILED, revision=1, experiment_id=created.experiment_id),
        unit_of_work=InMemoryUnitOfWork(store),
        clock=FixedClock(_LATER),
    )
    assert _code(rejected) == INVARIANT_VIOLATION
    rebuilt = InMemoryUnitOfWork(store).begin()
    assert _ok(rebuilt.experiments.get(created.experiment_id)) == validated
    rebuilt.rollback()
    assert store.committed_experiments() == (validated,)
