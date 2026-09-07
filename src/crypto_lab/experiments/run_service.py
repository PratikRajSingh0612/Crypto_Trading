"""The two engine-run operations: attempt creation and the generic run transition.

Plan sections 3.8, 5 (the run table, edge ownership and the attempt creation
contract), 9.1 (the experiment revision as the mutual-exclusion primitive) and
10.1 rows 6-7, under specification sections 17.1 and 17.2. Both operations run
through ``run_operation`` (plan 9.5 reload-once) and reach their repositories
through the unit of work alone; the run-side replacement builder and the rule
mapping are shared with the invocation service's linked operations so every run
edge Stage 5 writes is built by one set of rules.

Task-local readings, declared here rather than inferred silently (each was
submitted to an adversarial cross-check; see the Task 6 ledger):

- Owned targets before replay: ``STARTING`` and ``RUNNING`` are reached only
  through the linked launch operations (plan 5 edge ownership), so
  ``transition_run`` rejects those targets before anything else, including a
  same-state request against a ``STARTING`` or ``RUNNING`` run. Replay (target
  equals the stored state) returns the stored run at a matching revision and
  ``PERSISTENCE.CONCURRENCY_CONFLICT`` otherwise, terminal included; a terminal run
  with any other target is ``CORE.INVARIANT_VIOLATION`` regardless of revision.
- Carry-forward (plan 3.2, 3.8 row 14): ``availability_observation_id`` is taken
  from the request only when the target is ``READY`` or ``UNAVAILABLE``; on every
  other target a supplied value must equal the stored one (a different value is
  ``CORE.INVARIANT_VIOLATION``) and an omitted value is carried forward, so a
  request may restate but never move a carried fact. ``primary_terminal_diagnostic_id``
  comes from the request and the record shape decides where it is required or
  prohibited; an unrepresentable replacement is ``CORE.INVARIANT_VIOLATION``.
- ``create_attempt`` (plan 5 steps 1-6): the slot's attempt 1 is read through
  ``latest_attempt`` and, when the latest is a successor, ``get_by_attempt_number``;
  identical replay returns ``AttemptCreation`` with the stored experiment, attempt 1
  and a ``MISSING`` token (the raw token is never persisted, so a replay cannot
  return it); the identifier and token are drawn only after every check has
  passed; a lost insert or experiment swap rolls back and the driver re-applies the
  whole sequence -- including the attempt re-read -- once, so a concurrent
  identical create resolves to replay and a concurrent cancellation to plan 5
  step 4's invariant violation.
- The experiment bump is ``RUNNING`` in both cases (``QUEUED -> RUNNING`` for the
  first accepted attempt, otherwise state-preserving), with ``updated_at_utc`` at
  the clock instant and revision + 1 (plan 9.1).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Final

from pydantic import ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.compatibility import CompatibilityOutcome
from crypto_lab.domain.diagnostics import DiagnosticDetailValue
from crypto_lab.domain.engine_run import (
    AttemptTokenMaterial,
    EngineRunCheck,
    EngineRunRecord,
    EngineRunRuleViolation,
    RunEdgeOwner,
    assert_run_transition,
)
from crypto_lab.domain.experiment import ExperimentRecord
from crypto_lab.domain.hashing import attempt_token_hash
from crypto_lab.domain.lifecycle import (
    ENGINE_RUN_TRANSITIONS,
    TERMINAL_ENGINE_RUN_STATES,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.ports import Clock, IdentitySource
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.experiments.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
    stage5_failure,
)
from crypto_lab.experiments.experiment_service import (
    LostSwap,
    Outcome,
    run_operation,
)
from crypto_lab.experiments.ports import UnitOfWork
from crypto_lab.experiments.requests import AttemptCreationRequest, RunTransitionRequest

SOURCE_COMPONENT: Final = "experiments.run_service"
_R: Final = EngineRunState
_E: Final = ExperimentState

#: Plan 5 edge ownership: every target but the two linked-only ones.
TRANSITION_RUN_OWNED_TARGETS: Final[frozenset[EngineRunState]] = frozenset(
    EngineRunState
) - {_R.STARTING, _R.RUNNING}
#: Plan 3.8 row 14: "R at the transition into READY or UNAVAILABLE".
_OBSERVATION_GOVERNING_TARGETS: Final[frozenset[EngineRunState]] = frozenset(
    {_R.READY, _R.UNAVAILABLE}
)
#: Plan 5 step 4: the experiment states that admit a new attempt.
_ATTEMPT_ADMITTING_STATES: Final[frozenset[ExperimentState]] = frozenset(
    {_E.QUEUED, _E.RUNNING}
)


class AttemptCreation(CanonicalModel):
    """The result of ``create_attempt``: the experiment after the operation, the
    slot's attempt 1, and the raw attempt token as explicitly temporary material
    (plan 3.8) -- ``MISSING`` on an identical replay, because the token is never
    persisted. A nested value object without an envelope ``schema_version``."""

    experiment: ExperimentRecord
    attempt: EngineRunRecord
    attempt_token: AttemptTokenMaterial | MISSING = MISSING  # type: ignore[valid-type]


# --------------------------------------------------------------------------
# Shared helpers (also consumed by the invocation service)
# --------------------------------------------------------------------------


def _is_missing(value: object) -> bool:
    return value is MISSING


def _failure(
    code: str,
    message: str,
    *,
    now: datetime,
    experiment_id: str | MISSING = MISSING,  # type: ignore[valid-type]
    run: EngineRunRecord | None = None,
    details: Mapping[str, DiagnosticDetailValue] | None = None,
) -> Failure:
    return stage5_failure(
        code,
        message,
        source_component=SOURCE_COMPONENT,
        timestamp_utc=now,
        experiment_id=experiment_id if run is None else run.experiment_id,
        run_id=MISSING if run is None else run.run_id,
        details=details,
    )


def run_rule_failure(
    violation: EngineRunRuleViolation, *, now: datetime, stored: EngineRunRecord
) -> Failure:
    """Map a committed run-pair rule violation onto its Stage 5 code: a moved
    revision is a conflict, every other check an invariant violation (plan 8.6)."""
    code = (
        CONCURRENCY_CONFLICT
        if violation.check is EngineRunCheck.REVISION
        else INVARIANT_VIOLATION
    )
    return _failure(
        code,
        str(violation),
        now=now,
        run=stored,
        details={"check": violation.check.value},
    )


def run_replacement(
    stored: EngineRunRecord,
    *,
    target: EngineRunState,
    now: datetime,
    primary_terminal_diagnostic_id: str | MISSING,  # type: ignore[valid-type]
    availability_observation_id: str | MISSING,  # type: ignore[valid-type]
) -> EngineRunRecord | Failure:
    """The plan 5 replacement for ``stored -> target`` under the carry-forward rule.

    Applies the request's primary terminal diagnostic when supplied, applies its
    availability observation only on a ``READY`` or ``UNAVAILABLE`` target (a
    different value on any other target is an invariant violation; an omitted one
    is carried forward), moves ``updated_at_utc`` to ``now`` and ``revision`` by
    one, and carries every other field. An unrepresentable record for ``target``
    is returned as ``CORE.INVARIANT_VIOLATION``.
    """
    payload = stored.model_dump(mode="python")
    payload["state"] = target
    if not _is_missing(primary_terminal_diagnostic_id):
        payload["primary_terminal_diagnostic_id"] = primary_terminal_diagnostic_id
    if not _is_missing(availability_observation_id):
        if target in _OBSERVATION_GOVERNING_TARGETS:
            payload["availability_observation_id"] = availability_observation_id
        elif availability_observation_id != stored.availability_observation_id:
            return _failure(
                INVARIANT_VIOLATION,
                "availability_observation_id is request-governed only on a "
                "transition into READY or UNAVAILABLE and is otherwise carried "
                "forward unchanged",
                now=now,
                run=stored,
            )
    payload["updated_at_utc"] = now
    payload["revision"] = stored.revision + 1
    try:
        return EngineRunRecord.model_validate(payload)
    except ValidationError as error:
        return _failure(
            INVARIANT_VIOLATION,
            f"{stored.state.value} -> {target.value} produces no representable "
            f"record from this request: {error}",
            now=now,
            run=stored,
            details={"target_state": target.value},
        )


def _load_run(transaction: UnitOfWork, run_id: str) -> EngineRunRecord | Failure:
    loaded = transaction.engine_runs.get(run_id)
    if isinstance(loaded, Failure):
        return loaded
    return loaded.value


def _load_experiment(
    transaction: UnitOfWork, experiment_id: str
) -> ExperimentRecord | Failure:
    loaded = transaction.experiments.get(experiment_id)
    if isinstance(loaded, Failure):
        return loaded
    return loaded.value


def _stale_run(
    stored: EngineRunRecord, expected_revision: int, *, now: datetime
) -> Failure:
    return _failure(
        CONCURRENCY_CONFLICT,
        f"run {stored.run_id} is at revision {stored.revision}, "
        f"not {expected_revision}",
        now=now,
        run=stored,
        details={
            "expected_revision": expected_revision,
            "stored_revision": stored.revision,
        },
    )


# --------------------------------------------------------------------------
# transition_run (plan 5, 10.1 row 7)
# --------------------------------------------------------------------------


def transition_run(
    request: RunTransitionRequest,
    *,
    unit_of_work: UnitOfWork,
    clock: Clock,
) -> Result[EngineRunRecord]:
    """Produce one generic edge of plan 5's table from a core decision."""

    def once(transaction: UnitOfWork) -> Outcome[EngineRunRecord]:
        now = clock.now_utc()
        target = request.target_state
        stored = _load_run(transaction, request.run_id)
        if isinstance(stored, Failure):
            return stored
        if target not in TRANSITION_RUN_OWNED_TARGETS:
            return _failure(
                INVARIANT_VIOLATION,
                f"{target.value} is reached only through the linked launch operations",
                now=now,
                run=stored,
                details={"target_state": target.value},
            )
        if target is stored.state:
            if request.expected_revision == stored.revision:
                return Success[EngineRunRecord](outcome="SUCCESS", value=stored)
            return _stale_run(stored, request.expected_revision, now=now)
        if stored.state in TERMINAL_ENGINE_RUN_STATES:
            return _failure(
                INVARIANT_VIOLATION,
                f"a terminal engine run ({stored.state.value}) accepts no transition; "
                "a retry is a new attempt",
                now=now,
                run=stored,
                details={"stored_state": stored.state.value},
            )
        if not ENGINE_RUN_TRANSITIONS.is_allowed(stored.state, target):
            return _failure(
                INVARIANT_VIOLATION,
                f"{stored.state.value} -> {target.value} is not a permitted engine-run "
                "edge",
                now=now,
                run=stored,
                details={
                    "stored_state": stored.state.value,
                    "target_state": target.value,
                },
            )
        if request.expected_revision != stored.revision:
            return _stale_run(stored, request.expected_revision, now=now)
        replacement = run_replacement(
            stored,
            target=target,
            now=now,
            primary_terminal_diagnostic_id=request.primary_terminal_diagnostic_id,
            availability_observation_id=request.availability_observation_id,
        )
        if isinstance(replacement, Failure):
            return replacement
        try:
            assert_run_transition(stored, replacement, owner=RunEdgeOwner.GENERIC)
        except EngineRunRuleViolation as violation:
            return run_rule_failure(violation, now=now, stored=stored)
        swapped = transaction.engine_runs.compare_and_swap(stored.revision, replacement)
        if isinstance(swapped, Failure):
            return LostSwap(swapped)
        return swapped

    return run_operation(unit_of_work, once)


# --------------------------------------------------------------------------
# create_attempt (plan 5 attempt creation contract, 10.1 row 6)
# --------------------------------------------------------------------------


def _existing_attempt_one(
    transaction: UnitOfWork, experiment_id: str, logical_slot_id: str, *, now: datetime
) -> EngineRunRecord | Failure | None:
    """Plan 5 step 1: the slot's attempt 1 if any, read through ``latest_attempt``."""
    latest = transaction.engine_runs.latest_attempt(experiment_id, logical_slot_id)
    if isinstance(latest, Failure):
        return latest
    if _is_missing(latest.value):
        return None
    if latest.value.attempt_number == 1:
        return latest.value
    first = transaction.engine_runs.get_by_attempt_number(
        experiment_id, logical_slot_id, 1
    )
    if isinstance(first, Failure):
        return first
    if _is_missing(first.value):
        return _failure(
            INVARIANT_VIOLATION,
            f"slot {logical_slot_id} has a successor attempt but no attempt 1",
            now=now,
            experiment_id=experiment_id,
        )
    return first.value


def create_attempt(
    request: AttemptCreationRequest,
    *,
    unit_of_work: UnitOfWork,
    clock: Clock,
    identity_source: IdentitySource,
) -> Result[AttemptCreation]:
    """Plan 5 steps 1-6: create attempt 1 of a selected slot and bump the experiment
    in the same unit of work, or return the identical existing attempt."""

    def once(transaction: UnitOfWork) -> Outcome[AttemptCreation]:
        now = clock.now_utc()
        experiment = _load_experiment(transaction, request.experiment_id)
        if isinstance(experiment, Failure):
            return experiment
        existing = _existing_attempt_one(
            transaction, request.experiment_id, request.logical_slot_id, now=now
        )
        if isinstance(existing, Failure):
            return existing
        if existing is not None:
            if existing.request_hash == request.request_hash:
                return Success[AttemptCreation](
                    outcome="SUCCESS",
                    value=AttemptCreation(experiment=experiment, attempt=existing),
                )
            return _failure(
                CONCURRENCY_CONFLICT,
                f"slot {request.logical_slot_id} already has attempt 1 "
                f"({existing.run_id}) with a different request_hash",
                now=now,
                run=existing,
            )
        if experiment.state not in _ATTEMPT_ADMITTING_STATES:
            return _failure(
                INVARIANT_VIOLATION,
                f"an experiment in {experiment.state.value} admits no attempt",
                now=now,
                experiment_id=experiment.experiment_id,
                details={"experiment_state": experiment.state.value},
            )
        slots = [
            slot
            for slot in experiment.spec.selected_engine_slots
            if slot.logical_slot_id == request.logical_slot_id
        ]
        if not slots:
            return _failure(
                INVARIANT_VIOLATION,
                f"slot {request.logical_slot_id} is not a selected slot of the "
                "experiment",
                now=now,
                experiment_id=experiment.experiment_id,
            )
        slot = slots[0]
        frozen = [
            entry
            for entry in (
                ()
                if _is_missing(experiment.slot_compatibility)
                else (experiment.slot_compatibility)
            )
            if entry.logical_slot_id == request.logical_slot_id
        ]
        if frozen and frozen[0].outcome is CompatibilityOutcome.NOT_APPLICABLE:
            return _failure(
                INVARIANT_VIOLATION,
                f"slot {request.logical_slot_id} is frozen NOT_APPLICABLE and "
                "never runs",
                now=now,
                experiment_id=experiment.experiment_id,
            )
        if request.expected_experiment_revision != experiment.revision:
            return _failure(
                CONCURRENCY_CONFLICT,
                f"experiment {experiment.experiment_id} is at revision "
                f"{experiment.revision}, not {request.expected_experiment_revision}",
                now=now,
                experiment_id=experiment.experiment_id,
                details={
                    "expected_revision": request.expected_experiment_revision,
                    "stored_revision": experiment.revision,
                },
            )
        run_id = identity_source.new_run_id()
        token = identity_source.new_attempt_token()
        attempt = EngineRunRecord(
            schema_version="1.0.0",
            run_id=run_id,
            experiment_id=experiment.experiment_id,
            logical_slot_id=request.logical_slot_id,
            attempt_number=1,
            attempt_token_hash=attempt_token_hash(token),
            state=_R.PENDING,
            adapter=slot.adapter,
            engine=slot.engine,
            request_hash=request.request_hash,
            created_at_utc=now,
            updated_at_utc=now,
            revision=0,
        )
        added = transaction.engine_runs.add_attempt(attempt)
        if isinstance(added, Failure):
            return LostSwap(added)
        payload = experiment.model_dump(mode="python")
        payload["state"] = _E.RUNNING
        payload["updated_at_utc"] = now
        payload["revision"] = experiment.revision + 1
        bumped = ExperimentRecord.model_validate(payload)
        swapped = transaction.experiments.compare_and_swap(experiment.revision, bumped)
        if isinstance(swapped, Failure):
            return LostSwap(swapped)
        return Success[AttemptCreation](
            outcome="SUCCESS",
            value=AttemptCreation(
                experiment=swapped.value,
                attempt=attempt,
                attempt_token=AttemptTokenMaterial(run_id=run_id, attempt_token=token),
            ),
        )

    return run_operation(unit_of_work, once)
