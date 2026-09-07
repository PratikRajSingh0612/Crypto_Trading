"""The five experiment operations and the shared reload-once transaction driver.

Plan sections 4 (edge ownership, replay, conflict), 7 (the queue-time freeze),
9.1 (cancellation), 9.5 (the loser reloads once) and 10.1 rows 1-5, under
specification sections 16 and 23.2. Every operation receives its unit of work and
clock explicitly (plan 9.1's signature), opens one transaction, reads the
experiment through the unit of work's repository, validates against the committed
domain rules, builds one validated replacement and compare-and-swaps it. Nothing
here reads a wall clock, draws an identifier, launches a process or imports a
concrete repository.

**The driver.** ``run_operation`` is the single implementation of plan 9.5 and
13.2 criterion 6, imported by the run and invocation services as well: an
operation is written as ``once(transaction)`` returning its ``Result`` or a
``LostSwap``; a lost internal compare-and-swap (or a lost unique insert after the
operation's own checks passed, or a commit-time conflict) rolls the transaction
back, a single fresh transaction reloads every record and re-applies the whole
precondition sequence, and a second loss returns the conflict. The public
``Result`` therefore always comes from the operation's own contract, never from a
uniform loser code, and no partial write ever survives.

Task-local readings, declared here rather than inferred silently (each was
submitted to an adversarial cross-check; see the Task 6 ledger):

- Check order for every operation: load (a missing identity is the repository's
  ``CORE.INVARIANT_VIOLATION``); the request's target within the operation's
  owned target set (plan 4: "a ``target_state`` outside its operation's owned set
  is ``CORE.INVARIANT_VIOLATION``"); replay; the stored state or edge
  (``CORE.INVARIANT_VIOLATION``, or plan 7's ``CORE.IMMUTABLE_INPUT_MISMATCH`` for a
  spec replacement after the freeze); the expected revision
  (``PERSISTENCE.CONCURRENCY_CONFLICT``); build; compare-and-swap. Plan 10.1 lists
  "edge ownership, expected revision" and plans 7 and 9.1 put state before
  revision.
- Replay: a request whose target equals the stored state returns the stored
  record unchanged when its expected revision matches (plan 4, terminal included)
  and ``PERSISTENCE.CONCURRENCY_CONFLICT`` when it does not -- a reflexive pair is
  never an edge, so a same-state request at a stale revision is the loser of an
  identical race, not a forbidden transition. ``queue_experiment`` replays only
  when every frozen input agrees (retry-policy bytes, the configuration hash
  recomputed from the request's material hash, and ``slot_compatibility``); a
  divergent repeat is ``CORE.IMMUTABLE_INPUT_MISMATCH`` (specification 29.6: the
  prior identical outcome or a stable conflict, never a silent divergence), and a
  ``QUEUED`` record at a stale revision is ``PERSISTENCE.CONCURRENCY_CONFLICT``
  like every other same-state request; any other stored state goes through the
  freeze kernel, whose ``STORED_STATE`` check precedes its revision check.
  ``cancel_experiment`` replays on the correlation identity alone (plan 9.1 step 2).
- ``replace_experiment_spec``: ``DRAFT`` or ``VALIDATED`` lands in ``DRAFT`` with a
  fresh spec whose ``created_at_utc`` is the clock instant; ``QUEUED`` or
  ``RUNNING`` is ``CORE.IMMUTABLE_INPUT_MISMATCH`` (plan 7); any terminal state is
  ``CORE.INVARIANT_VIOLATION`` (plan 4 names spec replacement explicitly).
- ``queue_experiment`` maps ``QueueFreezeCheck``: ``STORED_STATE`` and the two
  defensive checks (``SPEC_HASH``, ``SELECTED_SLOTS``) to
  ``CORE.INVARIANT_VIOLATION``, ``EXPECTED_REVISION`` to
  ``PERSISTENCE.CONCURRENCY_CONFLICT``, and the three frozen-input checks to
  ``CORE.IMMUTABLE_INPUT_MISMATCH``.
- An identity collision on ``create_experiment`` is returned as the repository's
  conflict rather than retried: a fresh identifier that already exists is not a
  race a reload resolves.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from pydantic import ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.diagnostics import DiagnosticDetailValue
from crypto_lab.domain.experiment import (
    ExperimentRecord,
    QueueFreezeCheck,
    QueueFreezeViolation,
    assert_queue_freeze,
    build_experiment_spec,
    experiment_configuration_hash,
    experiment_spec_hash,
)
from crypto_lab.domain.lifecycle import TERMINAL_EXPERIMENT_STATES, ExperimentState
from crypto_lab.domain.ports import Clock, IdentitySource
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.experiments.diagnostics import (
    CONCURRENCY_CONFLICT,
    IMMUTABLE_INPUT_MISMATCH,
    INVARIANT_VIOLATION,
    stage5_failure,
)
from crypto_lab.experiments.ports import UnitOfWork
from crypto_lab.experiments.requests import (
    CancelExperimentRequest,
    ExperimentCreationRequest,
    ExperimentQueueRequest,
    ExperimentSpecReplacementRequest,
    ExperimentTransitionRequest,
)

SOURCE_COMPONENT: Final = "experiments.experiment_service"
_E: Final = ExperimentState

#: Plan 4 edge ownership: the edges `transition_experiment` alone may produce.
TRANSITION_OWNED_EDGES: Final[frozenset[tuple[ExperimentState, ExperimentState]]] = (
    frozenset({(_E.DRAFT, _E.VALIDATED), (_E.QUEUED, _E.FAILED)})
)
TRANSITION_OWNED_TARGETS: Final[frozenset[ExperimentState]] = frozenset(
    target for _, target in TRANSITION_OWNED_EDGES
)
#: Plan 7: the two states a spec may still be replaced from.
_REPLACEABLE_STATES: Final[frozenset[ExperimentState]] = frozenset(
    {_E.DRAFT, _E.VALIDATED}
)
#: Plan 7 and 8.6: the code each freeze check reports.
_FREEZE_CODES: Final[Mapping[QueueFreezeCheck, str]] = {
    QueueFreezeCheck.STORED_STATE: INVARIANT_VIOLATION,
    QueueFreezeCheck.EXPECTED_REVISION: CONCURRENCY_CONFLICT,
    QueueFreezeCheck.RETRY_POLICY_BYTES: IMMUTABLE_INPUT_MISMATCH,
    QueueFreezeCheck.CONFIGURATION_HASH: IMMUTABLE_INPUT_MISMATCH,
    QueueFreezeCheck.SPEC_HASH: INVARIANT_VIOLATION,
    QueueFreezeCheck.SELECTED_SLOTS: INVARIANT_VIOLATION,
    QueueFreezeCheck.SLOT_COMPATIBILITY: IMMUTABLE_INPUT_MISMATCH,
}


# --------------------------------------------------------------------------
# The shared transaction driver (plan 9.5; 13.2 criterion 6)
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LostSwap:
    """An internal compare-and-swap, unique insert or commit lost after the
    operation's own precondition checks had passed; carries the repository's
    conflict so a second loss can return it."""

    failure: Failure


type Outcome[T] = Success[T] | Failure | LostSwap


def run_operation[T](
    unit_of_work: UnitOfWork,
    once: Callable[[UnitOfWork], Outcome[T]],
) -> Result[T]:
    """Run ``once`` in one transaction, reloading exactly once on a lost swap.

    ``once`` receives the active transaction, performs every read, check and
    write of the operation and returns its ``Result`` or a ``LostSwap``. A
    ``Failure`` is returned after rollback; a ``Success`` is committed, and a
    commit-time conflict counts as a lost swap; a ``LostSwap`` rolls back and the
    whole of ``once`` runs again over a fresh transaction, once. The second loss
    returns the conflict. ``rollback`` is idempotent, so the ``finally`` clause is
    a no-op after a commit.
    """
    # Every Task 6 operation re-checks its expected revision after the reload, so
    # in practice a second loss surfaces through the operation's own conflict; the
    # terminal return below is the driver's own guarantee for an implementation
    # whose compare-and-swap can lose without a visible revision move.
    lost: LostSwap | None = None
    for _attempt in range(2):
        transaction = unit_of_work.begin()
        try:
            outcome = once(transaction)
            if isinstance(outcome, LostSwap):
                lost = outcome
                continue
            if isinstance(outcome, Failure):
                return outcome
            committed = transaction.commit()
            if isinstance(committed, Failure):
                lost = LostSwap(committed)
                continue
            return outcome
        finally:
            transaction.rollback()
    if lost is None:  # pragma: no cover - the loop returns or records a loss
        raise RuntimeError("run_operation exhausted without an outcome")
    return lost.failure


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------


def _is_missing(value: object) -> bool:
    return value is MISSING


def _failure(
    code: str,
    message: str,
    *,
    now: datetime,
    experiment_id: str,
    details: Mapping[str, DiagnosticDetailValue] | None = None,
) -> Failure:
    return stage5_failure(
        code,
        message,
        source_component=SOURCE_COMPONENT,
        timestamp_utc=now,
        experiment_id=experiment_id,
        details=details,
    )


def _load(transaction: UnitOfWork, experiment_id: str) -> ExperimentRecord | Failure:
    loaded = transaction.experiments.get(experiment_id)
    if isinstance(loaded, Failure):
        return loaded
    return loaded.value


def _replacement(
    stored: ExperimentRecord,
    *,
    now: datetime,
    changes: Mapping[str, object],
) -> ExperimentRecord:
    """The stored record with ``changes`` applied, ``updated_at_utc`` at ``now``
    and ``revision + 1``; every other field is carried forward (plan 3.2)."""
    payload = stored.model_dump(mode="python")
    payload.update(changes)
    payload["updated_at_utc"] = now
    payload["revision"] = stored.revision + 1
    return ExperimentRecord.model_validate(payload)


def _swap(
    transaction: UnitOfWork,
    stored: ExperimentRecord,
    replacement: ExperimentRecord,
) -> Success[ExperimentRecord] | LostSwap:
    swapped = transaction.experiments.compare_and_swap(stored.revision, replacement)
    if isinstance(swapped, Failure):
        return LostSwap(swapped)
    return swapped


def _stale(
    stored: ExperimentRecord, expected_revision: int, *, now: datetime
) -> Failure:
    return _failure(
        CONCURRENCY_CONFLICT,
        f"experiment {stored.experiment_id} is at revision {stored.revision}, "
        f"not {expected_revision}",
        now=now,
        experiment_id=stored.experiment_id,
        details={
            "expected_revision": expected_revision,
            "stored_revision": stored.revision,
        },
    )


# --------------------------------------------------------------------------
# create_experiment (plan 10.1 row 1)
# --------------------------------------------------------------------------


def create_experiment(
    request: ExperimentCreationRequest,
    *,
    unit_of_work: UnitOfWork,
    clock: Clock,
    identity_source: IdentitySource,
) -> Result[ExperimentRecord]:
    """Insert one ``DRAFT`` experiment at revision 0 from a validated draft.

    The identifier is drawn from ``identity_source``, the spec is assembled by
    ``build_experiment_spec`` at the single clock instant, and an identity
    collision is returned as the repository's conflict.
    """

    def once(transaction: UnitOfWork) -> Outcome[ExperimentRecord]:
        now = clock.now_utc()
        experiment_id = identity_source.new_experiment_id()
        spec = build_experiment_spec(
            request.spec_draft, request.material_base_configuration_hash, now
        )
        record = ExperimentRecord(
            schema_version="1.0.0",
            experiment_id=experiment_id,
            spec=spec,
            spec_hash=experiment_spec_hash(spec),
            state=_E.DRAFT,
            created_at_utc=now,
            updated_at_utc=now,
            revision=0,
        )
        added = transaction.experiments.add(record)
        if isinstance(added, Failure):
            return added
        return Success[ExperimentRecord](outcome="SUCCESS", value=record)

    return run_operation(unit_of_work, once)


# --------------------------------------------------------------------------
# replace_experiment_spec (plan 4, 7, 10.1 row 2)
# --------------------------------------------------------------------------


def replace_experiment_spec(
    request: ExperimentSpecReplacementRequest,
    *,
    unit_of_work: UnitOfWork,
    clock: Clock,
) -> Result[ExperimentRecord]:
    """Replace the spec of a ``DRAFT`` or ``VALIDATED`` experiment, landing in
    ``DRAFT`` at revision + 1 (plan 4: the same-state ``DRAFT`` replacement and
    the ``VALIDATED -> DRAFT`` edge)."""

    def once(transaction: UnitOfWork) -> Outcome[ExperimentRecord]:
        now = clock.now_utc()
        stored = _load(transaction, request.experiment_id)
        if isinstance(stored, Failure):
            return stored
        if stored.state in TERMINAL_EXPERIMENT_STATES:
            return _failure(
                INVARIANT_VIOLATION,
                f"a terminal experiment ({stored.state.value}) accepts no spec "
                "replacement",
                now=now,
                experiment_id=stored.experiment_id,
                details={"stored_state": stored.state.value},
            )
        if stored.state not in _REPLACEABLE_STATES:
            return _failure(
                IMMUTABLE_INPUT_MISMATCH,
                f"the spec is frozen from QUEUED onward (stored state "
                f"{stored.state.value}); a material change requires a new experiment",
                now=now,
                experiment_id=stored.experiment_id,
                details={"stored_state": stored.state.value},
            )
        if request.expected_revision != stored.revision:
            return _stale(stored, request.expected_revision, now=now)
        spec = build_experiment_spec(
            request.spec_draft, request.material_base_configuration_hash, now
        )
        replacement = _replacement(
            stored,
            now=now,
            changes={
                "spec": spec,
                "spec_hash": experiment_spec_hash(spec),
                "state": _E.DRAFT,
            },
        )
        return _swap(transaction, stored, replacement)

    return run_operation(unit_of_work, once)


# --------------------------------------------------------------------------
# transition_experiment (plan 4, 10.1 row 3)
# --------------------------------------------------------------------------


def transition_experiment(
    request: ExperimentTransitionRequest,
    *,
    unit_of_work: UnitOfWork,
    clock: Clock,
) -> Result[ExperimentRecord]:
    """Produce one of the two edges this operation owns: ``DRAFT -> VALIDATED`` or
    ``QUEUED -> FAILED``; every other target or edge is an invariant violation."""

    def once(transaction: UnitOfWork) -> Outcome[ExperimentRecord]:
        now = clock.now_utc()
        target = request.target_state
        stored = _load(transaction, request.experiment_id)
        if isinstance(stored, Failure):
            return stored
        if target not in TRANSITION_OWNED_TARGETS:
            return _failure(
                INVARIANT_VIOLATION,
                f"transition_experiment does not own the target {target.value}",
                now=now,
                experiment_id=stored.experiment_id,
                details={"target_state": target.value},
            )
        if target is stored.state:
            if request.expected_revision == stored.revision:
                return Success[ExperimentRecord](outcome="SUCCESS", value=stored)
            return _stale(stored, request.expected_revision, now=now)
        if stored.state in TERMINAL_EXPERIMENT_STATES:
            return _failure(
                INVARIANT_VIOLATION,
                f"a terminal experiment ({stored.state.value}) accepts no transition",
                now=now,
                experiment_id=stored.experiment_id,
                details={"stored_state": stored.state.value},
            )
        if (stored.state, target) not in TRANSITION_OWNED_EDGES:
            return _failure(
                INVARIANT_VIOLATION,
                f"{stored.state.value} -> {target.value} is not an edge "
                "transition_experiment may produce",
                now=now,
                experiment_id=stored.experiment_id,
                details={
                    "stored_state": stored.state.value,
                    "target_state": target.value,
                },
            )
        if request.expected_revision != stored.revision:
            return _stale(stored, request.expected_revision, now=now)
        replacement = _replacement(stored, now=now, changes={"state": target})
        return _swap(transaction, stored, replacement)

    return run_operation(unit_of_work, once)


# --------------------------------------------------------------------------
# queue_experiment (plan 7, 10.1 row 4)
# --------------------------------------------------------------------------


def _frozen_inputs_agree(
    stored: ExperimentRecord, request: ExperimentQueueRequest
) -> bool:
    """Plan 7 checks 2, 3 and 6 against an already-queued record."""
    return (
        canonical_json_bytes(stored.spec.retry_policy)
        == canonical_json_bytes(request.config_derived_retry_policy)
        and stored.spec.configuration_hash
        == experiment_configuration_hash(
            stored.spec, request.material_base_configuration_hash
        )
        and not _is_missing(stored.slot_compatibility)
        and stored.slot_compatibility == request.slot_compatibility
    )


def queue_experiment(
    request: ExperimentQueueRequest,
    *,
    unit_of_work: UnitOfWork,
    clock: Clock,
) -> Result[ExperimentRecord]:
    """The ``VALIDATED -> QUEUED`` freeze of plan 7, through the committed
    ``assert_queue_freeze`` kernel; the only path to ``QUEUED``."""

    def once(transaction: UnitOfWork) -> Outcome[ExperimentRecord]:
        now = clock.now_utc()
        stored = _load(transaction, request.experiment_id)
        if isinstance(stored, Failure):
            return stored
        if stored.state is _E.QUEUED:
            if request.expected_revision != stored.revision:
                return _stale(stored, request.expected_revision, now=now)
            if _frozen_inputs_agree(stored, request):
                return Success[ExperimentRecord](outcome="SUCCESS", value=stored)
            return _failure(
                IMMUTABLE_INPUT_MISMATCH,
                "a repeated queue request must carry the frozen inputs unchanged",
                now=now,
                experiment_id=stored.experiment_id,
            )
        try:
            assert_queue_freeze(
                stored,
                expected_revision=request.expected_revision,
                config_derived_retry_policy=request.config_derived_retry_policy,
                material_base_configuration_hash=(
                    request.material_base_configuration_hash
                ),
                slot_compatibility=request.slot_compatibility,
            )
        except QueueFreezeViolation as violation:
            return _failure(
                _FREEZE_CODES[violation.check],
                str(violation),
                now=now,
                experiment_id=stored.experiment_id,
                details={"check": violation.check.value},
            )
        replacement = _replacement(
            stored,
            now=now,
            changes={
                "state": _E.QUEUED,
                "slot_compatibility": request.slot_compatibility,
            },
        )
        return _swap(transaction, stored, replacement)

    return run_operation(unit_of_work, once)


# --------------------------------------------------------------------------
# cancel_experiment (plan 9.1, 10.1 row 5)
# --------------------------------------------------------------------------


def cancel_experiment(
    request: CancelExperimentRequest,
    *,
    unit_of_work: UnitOfWork,
    clock: Clock,
) -> Result[ExperimentRecord]:
    """Plan 9.1 steps 1-5: replay on the correlation identity, refuse another
    terminal state, verify the revision, compare-and-swap to ``CANCELLED``."""

    def once(transaction: UnitOfWork) -> Outcome[ExperimentRecord]:
        now = clock.now_utc()
        stored = _load(transaction, request.experiment_id)
        if isinstance(stored, Failure):
            return stored
        if stored.state is _E.CANCELLED:
            if stored.cancellation_correlation_id == request.correlation_id:
                return Success[ExperimentRecord](outcome="SUCCESS", value=stored)
            return _failure(
                CONCURRENCY_CONFLICT,
                "the experiment was cancelled under a different correlation identity",
                now=now,
                experiment_id=stored.experiment_id,
                details={"requested_correlation_id": request.correlation_id},
            )
        if stored.state in TERMINAL_EXPERIMENT_STATES:
            return _failure(
                INVARIANT_VIOLATION,
                f"a terminal experiment ({stored.state.value}) cannot be cancelled",
                now=now,
                experiment_id=stored.experiment_id,
                details={"stored_state": stored.state.value},
            )
        if request.expected_revision != stored.revision:
            return _stale(stored, request.expected_revision, now=now)
        try:
            replacement = _replacement(
                stored,
                now=now,
                changes={
                    "state": _E.CANCELLED,
                    "cancellation_correlation_id": request.correlation_id,
                },
            )
        except ValidationError as error:  # pragma: no cover - every non-terminal
            # shape admits CANCELLED; kept so a future shape rule surfaces as a Result.
            return _failure(
                INVARIANT_VIOLATION,
                str(error),
                now=now,
                experiment_id=stored.experiment_id,
            )
        return _swap(transaction, stored, replacement)

    return run_operation(unit_of_work, once)
