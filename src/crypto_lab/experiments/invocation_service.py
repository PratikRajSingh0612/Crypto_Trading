"""The six command-invocation operations, including the three linked operations.

Plan sections 3.7, 6 and 10.1 rows 8-13, under specification sections 14.8, 15.2
and 15.6. ``create_invocation`` applies plan 6's parent-eligibility matrix and its
identical-create replay; ``transition_invocation`` and ``enrich_invocation`` move a
single invocation through the committed pair predicates of Task 3;
``begin_linked_launch``, ``start_linked_run`` and ``transition_invocation_and_run``
advance a ``RUN``-kind (or, for the coupled terminal outcome, a ``VALIDATE``-kind)
invocation together with its engine run in one unit of work, or not at all
(specification 15.2: "neither aggregate is partially advanced"). Every operation
runs through ``run_operation`` (plan 9.5 reload-once) and reaches its
repositories through the unit of work alone. Nothing here launches or inspects a
process: ``ProcessStartFacts`` is caller-supplied launch-handoff material (plan
3.7).

Task-local readings, declared here rather than inferred silently (each was
submitted to an adversarial cross-check; see the Task 6 ledger):

- Owned targets before replay: a ``RUN``-kind invocation reaches ``STARTING`` and
  ``RUNNING`` only through the linked operations, so ``transition_invocation``
  rejects those targets for it before anything else (plan 6 "Process-start
  handoff by command kind"). Replay -- the target equals the stored state -- returns
  the stored record at a matching revision and ``PERSISTENCE.CONCURRENCY_CONFLICT``
  otherwise; the linked operations replay when both records already hold their
  targets, ``start_linked_run`` additionally requiring the stored process facts to
  equal the request's (a divergent repeat is a conflict, specification 29.6).
- A coupled terminal outcome is never written half: for a ``VALIDATE`` or ``RUN``
  invocation, ``transition_invocation`` returns ``CORE.INVARIANT_VIOLATION`` for a
  target in ``FAILED_TO_START``, ``CANCELLED``, ``TIMED_OUT`` or ``PROTOCOL_FAILED``
  while the linked run is non-terminal -- that outcome belongs to
  ``transition_invocation_and_run`` (specification 15.2) -- and proceeds alone only
  when the run is already terminal (plan 5: "cancellation without a live command").
  Its read set therefore includes the linked run for those targets, and the
  primary diagnostic for an unrecognized ``EXITED`` exit (plan 6). ``EXITED``
  couples nothing (plan 1.4) and is refused by the coupled operation.
- ``transition_invocation_and_run`` reads the primary diagnostic only for a
  ``FAILED_TO_START`` target, where plan 6's mapping needs its category (the
  Task 4 handoff note on plan 10.1's read set); the request's run target must equal
  ``coupled_run_terminal_state``'s answer, a ``RUN`` pair that
  ``is_mixed_running_pair`` flags is refused, and the run half is built by the run
  service's carry-forward rules (its primary terminal diagnostic and any
  availability observation come from ``request.run``).
- ``create_invocation``: the kind-specific timeout bound is a plan 6 matrix cell,
  so it is a service ``CORE.INVARIANT_VIOLATION``; a stale ``expected_run_revision``
  is ``PERSISTENCE.CONCURRENCY_CONFLICT`` (plan 4/8.6 precondition movement); "slot
  and adapter identity agree with the run" is read as the run's slot being a slot
  of the experiment spec and the request's adapter equalling both the run's and
  that slot's; a ``DESCRIBE`` reads nothing and is never deduplicated (plan 1.4);
  the identifier is drawn only after every check has passed. A unique-index
  collision on the insert after those checks is a lost race: the driver reloads
  once and the open-invocation check then recognises replay or divergence.
- ``diagnostic_ids`` from a transition request are merged (sorted, unique) into
  the record on every target; the shape validator decides where a primary or an
  exit pair may appear.
- Enrichment carries an already complete cleanup forward unchanged (a restated
  ``cleanup_complete`` sets no new instant) and, like a restated exit pair, leaves
  the write-once predicate to judge only the facts actually added.
- Domain rule violations map ``REVISION`` to ``PERSISTENCE.CONCURRENCY_CONFLICT``
  and every other check to ``CORE.INVARIANT_VIOLATION``; a ``ValidationError`` while
  building a replacement is ``CORE.INVARIANT_VIOLATION`` (the request asks for an
  unrepresentable record, plan 3.2).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Final

from pydantic import ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.command_invocation import (
    CommandInvocationCheck,
    CommandInvocationRecord,
    CommandInvocationRuleViolation,
    assert_invocation_transition,
    assert_parent_run_eligibility,
    assert_write_once_enrichment,
    command_timeout_bounds,
)
from crypto_lab.domain.diagnostics import DiagnosticCategory, DiagnosticDetailValue
from crypto_lab.domain.engine_run import (
    EngineRunRecord,
    EngineRunRuleViolation,
    RunEdgeOwner,
    assert_run_transition,
    coupled_run_terminal_state,
    is_mixed_running_pair,
)
from crypto_lab.domain.experiment import ExperimentRecord
from crypto_lab.domain.lifecycle import (
    COMMAND_INVOCATION_TRANSITIONS,
    RECOGNIZED_NATIVE_EXIT_VALUES,
    TERMINAL_COMMAND_INVOCATION_STATES,
    TERMINAL_ENGINE_RUN_STATES,
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
    process_exit_category_for,
)
from crypto_lab.domain.ports import Clock, IdentitySource
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.experiments.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
    UNRECOGNIZED_PROCESS_EXIT,
    stage5_failure,
)
from crypto_lab.experiments.experiment_service import (
    LostSwap,
    Outcome,
    run_operation,
)
from crypto_lab.experiments.ports import UnitOfWork
from crypto_lab.experiments.requests import (
    CoupledTransitionRequest,
    InvocationCreationRequest,
    InvocationEnrichmentRequest,
    InvocationTransitionRequest,
    LinkedLaunchRequest,
    LinkedStartRequest,
)
from crypto_lab.experiments.run_service import run_replacement, run_rule_failure

SOURCE_COMPONENT: Final = "experiments.invocation_service"
_C: Final = CommandInvocationState
_R: Final = EngineRunState
_K: Final = CommandKind

#: Plan 6: a ``RUN`` invocation reaches these only through the linked operations.
LINKED_ONLY_INVOCATION_TARGETS: Final[frozenset[CommandInvocationState]] = frozenset(
    {_C.STARTING, _C.RUNNING}
)
#: Plan 6 "Coupled terminal transitions": the outcomes that couple a run edge.
COUPLED_TERMINAL_TARGETS: Final[frozenset[CommandInvocationState]] = frozenset(
    {_C.FAILED_TO_START, _C.CANCELLED, _C.TIMED_OUT, _C.PROTOCOL_FAILED}
)


class LinkedPair(CanonicalModel):
    """The invocation and its run after one linked or coupled operation.

    A nested value object without an envelope ``schema_version`` (plan 3.1).
    """

    invocation: CommandInvocationRecord
    run: EngineRunRecord


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
    invocation_id: str | MISSING = MISSING,  # type: ignore[valid-type]
    run: EngineRunRecord | None = None,
    details: Mapping[str, DiagnosticDetailValue] | None = None,
) -> Failure:
    return stage5_failure(
        code,
        message,
        source_component=SOURCE_COMPONENT,
        timestamp_utc=now,
        experiment_id=MISSING if run is None else run.experiment_id,
        run_id=MISSING if run is None else run.run_id,
        invocation_id=invocation_id,
        details=details,
    )


def _invariant(
    message: str,
    *,
    now: datetime,
    invocation_id: str | MISSING = MISSING,  # type: ignore[valid-type]
    run: EngineRunRecord | None = None,
    details: Mapping[str, DiagnosticDetailValue] | None = None,
) -> Failure:
    return _failure(
        INVARIANT_VIOLATION,
        message,
        now=now,
        invocation_id=invocation_id,
        run=run,
        details=details,
    )


def _conflict(
    message: str,
    *,
    now: datetime,
    invocation_id: str | MISSING = MISSING,  # type: ignore[valid-type]
    run: EngineRunRecord | None = None,
    details: Mapping[str, DiagnosticDetailValue] | None = None,
) -> Failure:
    return _failure(
        CONCURRENCY_CONFLICT,
        message,
        now=now,
        invocation_id=invocation_id,
        run=run,
        details=details,
    )


def _invocation_rule_failure(
    violation: CommandInvocationRuleViolation,
    *,
    now: datetime,
    stored: CommandInvocationRecord,
) -> Failure:
    code = (
        CONCURRENCY_CONFLICT
        if violation.check is CommandInvocationCheck.REVISION
        else INVARIANT_VIOLATION
    )
    return _failure(
        code,
        str(violation),
        now=now,
        invocation_id=stored.invocation_id,
        details={"check": violation.check.value},
    )


def _load_invocation(
    transaction: UnitOfWork, invocation_id: str
) -> CommandInvocationRecord | Failure:
    loaded = transaction.command_invocations.get(invocation_id)
    if isinstance(loaded, Failure):
        return loaded
    return loaded.value


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


def _stale_invocation(
    stored: CommandInvocationRecord, expected_revision: int, *, now: datetime
) -> Failure:
    return _conflict(
        f"invocation {stored.invocation_id} is at revision {stored.revision}, "
        f"not {expected_revision}",
        now=now,
        invocation_id=stored.invocation_id,
        details={
            "expected_revision": expected_revision,
            "stored_revision": stored.revision,
        },
    )


def _stale_run(
    stored: EngineRunRecord, expected_revision: int, *, now: datetime
) -> Failure:
    return _conflict(
        f"run {stored.run_id} is at revision {stored.revision}, "
        f"not {expected_revision}",
        now=now,
        run=stored,
        details={
            "expected_revision": expected_revision,
            "stored_revision": stored.revision,
        },
    )


def _merged_diagnostics(
    stored: CommandInvocationRecord, additional: tuple[str, ...]
) -> tuple[str, ...]:
    return tuple(sorted({*stored.diagnostic_ids, *additional}))


def _invocation_replacement(
    stored: CommandInvocationRecord,
    *,
    target: CommandInvocationState,
    now: datetime,
    request: InvocationTransitionRequest,
) -> CommandInvocationRecord:
    """The plan 6 replacement for ``stored -> target`` from one transition request.

    Establishes the launch pair on ``STARTING``, the process facts on ``RUNNING``
    (from the request's ``ProcessStartFacts``), completion plus the exit pair and
    the primary diagnostic on a terminal target, merges the request's
    ``diagnostic_ids`` on every target, carries everything else forward, and moves
    ``updated_at_utc`` and ``revision``. Raises ``ValidationError`` when the result
    is not a representable record for ``target``.
    """
    payload = stored.model_dump(mode="python")
    payload["state"] = target
    if target is _C.STARTING:
        payload["launch_attempted_at_utc"] = now
        payload["deadline_utc"] = now + timedelta(seconds=stored.timeout_seconds)
    if target is _C.RUNNING and not _is_missing(request.process_start):
        payload["process_created"] = True
        payload["process_started_at_utc"] = request.process_start.process_started_at_utc
        payload["pid_identity"] = request.process_start.pid_identity
    if target in TERMINAL_COMMAND_INVOCATION_STATES:
        payload["completed_at_utc"] = now
    if not _is_missing(request.native_exit_value):
        payload["native_exit_value"] = request.native_exit_value
        payload["process_exit_category"] = process_exit_category_for(
            request.native_exit_value
        )
    if not _is_missing(request.primary_diagnostic_id):
        payload["primary_diagnostic_id"] = request.primary_diagnostic_id
    payload["diagnostic_ids"] = _merged_diagnostics(stored, request.diagnostic_ids)
    payload["updated_at_utc"] = now
    payload["revision"] = stored.revision + 1
    return CommandInvocationRecord.model_validate(payload)


def _launch_replacement(
    stored: CommandInvocationRecord, *, now: datetime
) -> CommandInvocationRecord:
    """``PENDING -> STARTING`` with the paired-clock launch facts (spec 14.8)."""
    payload = stored.model_dump(mode="python")
    payload["state"] = _C.STARTING
    payload["launch_attempted_at_utc"] = now
    payload["deadline_utc"] = now + timedelta(seconds=stored.timeout_seconds)
    payload["updated_at_utc"] = now
    payload["revision"] = stored.revision + 1
    return CommandInvocationRecord.model_validate(payload)


def _start_replacement(
    stored: CommandInvocationRecord, *, now: datetime, request: LinkedStartRequest
) -> CommandInvocationRecord:
    """``STARTING -> RUNNING`` with the request's process facts (plan 6)."""
    payload = stored.model_dump(mode="python")
    payload["state"] = _C.RUNNING
    payload["process_created"] = True
    payload["process_started_at_utc"] = request.process_start.process_started_at_utc
    payload["pid_identity"] = request.process_start.pid_identity
    payload["updated_at_utc"] = now
    payload["revision"] = stored.revision + 1
    return CommandInvocationRecord.model_validate(payload)


def _swap_invocation(
    transaction: UnitOfWork,
    stored: CommandInvocationRecord,
    replacement: CommandInvocationRecord,
) -> CommandInvocationRecord | LostSwap:
    swapped = transaction.command_invocations.compare_and_swap(
        stored.revision, replacement
    )
    if isinstance(swapped, Failure):
        return LostSwap(swapped)
    return swapped.value


def _swap_run(
    transaction: UnitOfWork, stored: EngineRunRecord, replacement: EngineRunRecord
) -> EngineRunRecord | LostSwap:
    swapped = transaction.engine_runs.compare_and_swap(stored.revision, replacement)
    if isinstance(swapped, Failure):
        return LostSwap(swapped)
    return swapped.value


def _pair(
    invocation: CommandInvocationRecord, run: EngineRunRecord
) -> Success[LinkedPair]:
    return Success[LinkedPair](
        outcome="SUCCESS", value=LinkedPair(invocation=invocation, run=run)
    )


# --------------------------------------------------------------------------
# create_invocation (plan 6 matrix, 10.1 row 8)
# --------------------------------------------------------------------------


def _identical_create(
    existing: CommandInvocationRecord, request: InvocationCreationRequest
) -> bool:
    """Plan 6: the six fields an identical-create replay must agree on."""
    return (
        existing.command_kind is request.command_kind
        and existing.run_id == request.run_id
        and existing.adapter_name == request.adapter_name
        and existing.adapter_version == request.adapter_version
        and existing.request_hash == request.request_hash
        and existing.timeout_seconds == request.timeout_seconds
    )


def _open_invocations(
    transaction: UnitOfWork, run_id: str, kind: CommandKind
) -> tuple[CommandInvocationRecord, ...] | Failure:
    listed = transaction.command_invocations.list_for_run(run_id, kind)
    if isinstance(listed, Failure):
        return listed
    return tuple(
        record
        for record in listed.value
        if record.state not in TERMINAL_COMMAND_INVOCATION_STATES
    )


def _new_invocation(
    request: InvocationCreationRequest, *, invocation_id: str, now: datetime
) -> CommandInvocationRecord:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "invocation_id": invocation_id,
        "command_kind": request.command_kind,
        "adapter_name": request.adapter_name,
        "adapter_version": request.adapter_version,
        "request_hash": request.request_hash,
        "timeout_seconds": request.timeout_seconds,
        "state": _C.PENDING,
        "process_created": False,
        "cleanup_complete": False,
        "diagnostic_ids": (),
        "created_at_utc": now,
        "updated_at_utc": now,
        "revision": 0,
    }
    if not _is_missing(request.run_id):
        payload["run_id"] = request.run_id
    return CommandInvocationRecord.model_validate(payload)


def create_invocation(
    request: InvocationCreationRequest,
    *,
    unit_of_work: UnitOfWork,
    clock: Clock,
    identity_source: IdentitySource,
) -> Result[CommandInvocationRecord]:
    """Insert one ``PENDING`` invocation, or return the identical open one (plan 6)."""

    def once(transaction: UnitOfWork) -> Outcome[CommandInvocationRecord]:
        now = clock.now_utc()
        kind = request.command_kind
        run: EngineRunRecord | None = None
        if kind is not _K.DESCRIBE and not _is_missing(request.run_id):
            loaded = _load_run(transaction, request.run_id)
            if isinstance(loaded, Failure):
                return loaded
            run = loaded
        try:
            assert_parent_run_eligibility(
                kind,
                run_id=request.run_id,
                expected_run_revision=request.expected_run_revision,
                parent_run_state=MISSING if run is None else run.state,
            )
        except CommandInvocationRuleViolation as violation:
            return _failure(
                INVARIANT_VIOLATION,
                str(violation),
                now=now,
                run=run,
                details={"check": violation.check.value},
            )
        bounds = command_timeout_bounds(kind)
        if (
            not bounds.minimum_seconds
            <= request.timeout_seconds
            <= bounds.maximum_seconds
        ):
            return _invariant(
                f"timeout_seconds must be within {bounds.minimum_seconds}.."
                f"{bounds.maximum_seconds} for {kind.value}",
                now=now,
                run=run,
                details={"timeout_seconds": request.timeout_seconds},
            )
        if run is None:
            record = _new_invocation(
                request, invocation_id=identity_source.new_invocation_id(), now=now
            )
            added = transaction.command_invocations.add(record)
            if isinstance(added, Failure):
                return added
            return Success[CommandInvocationRecord](outcome="SUCCESS", value=record)
        experiment = _load_experiment(transaction, run.experiment_id)
        if isinstance(experiment, Failure):
            return experiment
        if experiment.state is not ExperimentState.RUNNING:
            return _invariant(
                f"the experiment is {experiment.state.value}, not RUNNING",
                now=now,
                run=run,
                details={"experiment_state": experiment.state.value},
            )
        latest = transaction.engine_runs.latest_attempt(
            run.experiment_id, run.logical_slot_id
        )
        if isinstance(latest, Failure):
            return latest
        if _is_missing(latest.value) or latest.value.run_id != run.run_id:
            return _invariant(
                f"run {run.run_id} is not the current attempt of its slot",
                now=now,
                run=run,
            )
        slots = [
            slot
            for slot in experiment.spec.selected_engine_slots
            if slot.logical_slot_id == run.logical_slot_id
        ]
        if not slots:
            return _invariant(
                f"slot {run.logical_slot_id} is not a selected slot of the experiment",
                now=now,
                run=run,
            )
        slot = slots[0]
        requested = (request.adapter_name, request.adapter_version)
        run_adapter = (run.adapter.adapter_name, run.adapter.adapter_version)
        slot_adapter = (slot.adapter.adapter_name, slot.adapter.adapter_version)
        if requested != run_adapter or run_adapter != slot_adapter:
            return _invariant(
                "the request's adapter identity must equal the run's and the slot's",
                now=now,
                run=run,
                details={
                    "requested_adapter": list(requested),
                    "run_adapter": list(run_adapter),
                },
            )
        if kind is _K.RUN and request.request_hash != run.request_hash:
            return _invariant(
                "a RUN invocation's request_hash must equal the run's request_hash",
                now=now,
                run=run,
            )
        if request.expected_run_revision != run.revision:
            return _stale_run(run, request.expected_run_revision, now=now)
        if kind is _K.RUN:
            open_validates = _open_invocations(transaction, run.run_id, _K.VALIDATE)
            if isinstance(open_validates, Failure):
                return open_validates
            if open_validates:
                return _invariant(
                    f"run {run.run_id} still has an open VALIDATE invocation "
                    f"{open_validates[0].invocation_id}",
                    now=now,
                    run=run,
                    invocation_id=open_validates[0].invocation_id,
                )
        open_same_kind = _open_invocations(transaction, run.run_id, kind)
        if isinstance(open_same_kind, Failure):
            return open_same_kind
        if open_same_kind:
            existing = open_same_kind[0]
            if _identical_create(existing, request):
                return Success[CommandInvocationRecord](
                    outcome="SUCCESS", value=existing
                )
            return _conflict(
                f"run {run.run_id} already has an open {kind.value} invocation "
                f"{existing.invocation_id} with different material",
                now=now,
                run=run,
                invocation_id=existing.invocation_id,
            )
        record = _new_invocation(
            request, invocation_id=identity_source.new_invocation_id(), now=now
        )
        added = transaction.command_invocations.add(record)
        if isinstance(added, Failure):
            return LostSwap(added)
        return Success[CommandInvocationRecord](outcome="SUCCESS", value=record)

    return run_operation(unit_of_work, once)


# --------------------------------------------------------------------------
# transition_invocation (plan 6 table, 10.1 row 10)
# --------------------------------------------------------------------------


def _unrecognized_exit_requires_its_diagnostic(
    transaction: UnitOfWork,
    request: InvocationTransitionRequest,
    stored: CommandInvocationRecord,
    *,
    now: datetime,
) -> Failure | None:
    """Plan 6: an ``EXITED`` with an unrecognized native exit carries a primary
    diagnostic that resolves to ``PROCESS.UNRECOGNIZED_PROCESS_EXIT``."""
    if request.target_state is not _C.EXITED or _is_missing(request.native_exit_value):
        return None
    if request.native_exit_value in RECOGNIZED_NATIVE_EXIT_VALUES:
        return None
    if _is_missing(request.primary_diagnostic_id):
        return _invariant(
            "an EXITED invocation with an unrecognized native exit requires a "
            "PROCESS.UNRECOGNIZED_PROCESS_EXIT primary diagnostic",
            now=now,
            invocation_id=stored.invocation_id,
            details={"native_exit_value": request.native_exit_value},
        )
    diagnostic = transaction.diagnostics.get(request.primary_diagnostic_id)
    if isinstance(diagnostic, Failure):
        return _invariant(
            f"primary diagnostic {request.primary_diagnostic_id} does not exist",
            now=now,
            invocation_id=stored.invocation_id,
        )
    if diagnostic.value.error_code != UNRECOGNIZED_PROCESS_EXIT:
        return _invariant(
            f"primary diagnostic {request.primary_diagnostic_id} carries "
            f"{diagnostic.value.error_code}, not {UNRECOGNIZED_PROCESS_EXIT}",
            now=now,
            invocation_id=stored.invocation_id,
        )
    return None


def transition_invocation(
    request: InvocationTransitionRequest,
    *,
    unit_of_work: UnitOfWork,
    clock: Clock,
) -> Result[CommandInvocationRecord]:
    """Move one invocation along a plan 6 edge that couples no run transition."""

    def once(transaction: UnitOfWork) -> Outcome[CommandInvocationRecord]:
        now = clock.now_utc()
        target = request.target_state
        stored = _load_invocation(transaction, request.invocation_id)
        if isinstance(stored, Failure):
            return stored
        if stored.command_kind is _K.RUN and target in LINKED_ONLY_INVOCATION_TARGETS:
            return _invariant(
                f"a RUN invocation reaches {target.value} only through the linked "
                "launch operations",
                now=now,
                invocation_id=stored.invocation_id,
            )
        if target is stored.state:
            if request.expected_revision == stored.revision:
                return Success[CommandInvocationRecord](outcome="SUCCESS", value=stored)
            return _stale_invocation(stored, request.expected_revision, now=now)
        if stored.state in TERMINAL_COMMAND_INVOCATION_STATES:
            return _invariant(
                f"a terminal invocation ({stored.state.value}) accepts no transition",
                now=now,
                invocation_id=stored.invocation_id,
            )
        if not COMMAND_INVOCATION_TRANSITIONS.is_allowed(stored.state, target):
            return _invariant(
                f"{stored.state.value} -> {target.value} is not a permitted "
                "command-invocation edge",
                now=now,
                invocation_id=stored.invocation_id,
            )
        if (
            stored.command_kind is not _K.DESCRIBE
            and target in COUPLED_TERMINAL_TARGETS
        ):
            run = _load_run(transaction, stored.run_id)
            if isinstance(run, Failure):
                return run
            if run.state not in TERMINAL_ENGINE_RUN_STATES:
                return _invariant(
                    f"{target.value} on a {stored.command_kind.value} invocation "
                    f"couples a run transition while run {run.run_id} is "
                    f"{run.state.value}; use transition_invocation_and_run",
                    now=now,
                    invocation_id=stored.invocation_id,
                    run=run,
                )
        if request.expected_revision != stored.revision:
            return _stale_invocation(stored, request.expected_revision, now=now)
        unrecognized = _unrecognized_exit_requires_its_diagnostic(
            transaction, request, stored, now=now
        )
        if unrecognized is not None:
            return unrecognized
        try:
            replacement = _invocation_replacement(
                stored, target=target, now=now, request=request
            )
            assert_invocation_transition(stored, replacement)
        except ValidationError as error:
            return _invariant(str(error), now=now, invocation_id=stored.invocation_id)
        except CommandInvocationRuleViolation as violation:
            return _invocation_rule_failure(violation, now=now, stored=stored)
        swapped = _swap_invocation(transaction, stored, replacement)
        if isinstance(swapped, LostSwap):
            return swapped
        return Success[CommandInvocationRecord](outcome="SUCCESS", value=swapped)

    return run_operation(unit_of_work, once)


# --------------------------------------------------------------------------
# enrich_invocation (plan 6 write-once enrichment, 10.1 row 12)
# --------------------------------------------------------------------------


def enrich_invocation(
    request: InvocationEnrichmentRequest,
    *,
    unit_of_work: UnitOfWork,
    clock: Clock,
) -> Result[CommandInvocationRecord]:
    """Apply plan 6's four write-once enrichments to a terminal invocation."""

    def once(transaction: UnitOfWork) -> Outcome[CommandInvocationRecord]:
        now = clock.now_utc()
        stored = _load_invocation(transaction, request.invocation_id)
        if isinstance(stored, Failure):
            return stored
        if stored.state not in TERMINAL_COMMAND_INVOCATION_STATES:
            return _invariant(
                "only a terminal invocation accepts write-once enrichment",
                now=now,
                invocation_id=stored.invocation_id,
            )
        if request.expected_revision != stored.revision:
            return _stale_invocation(stored, request.expected_revision, now=now)
        payload = stored.model_dump(mode="python")
        if not _is_missing(request.native_exit_value):
            payload["native_exit_value"] = request.native_exit_value
            payload["process_exit_category"] = process_exit_category_for(
                request.native_exit_value
            )
        if not _is_missing(request.cleanup_complete) and not stored.cleanup_complete:
            payload["cleanup_complete"] = True
            payload["cleanup_completed_at_utc"] = now
        if not _is_missing(request.stderr_artifact_id):
            payload["stderr_artifact_id"] = request.stderr_artifact_id
        payload["diagnostic_ids"] = _merged_diagnostics(
            stored, request.additional_diagnostic_ids
        )
        payload["updated_at_utc"] = now
        payload["revision"] = stored.revision + 1
        try:
            replacement = CommandInvocationRecord.model_validate(payload)
            assert_write_once_enrichment(stored, replacement)
        except ValidationError as error:
            return _invariant(str(error), now=now, invocation_id=stored.invocation_id)
        except CommandInvocationRuleViolation as violation:
            return _invocation_rule_failure(violation, now=now, stored=stored)
        swapped = _swap_invocation(transaction, stored, replacement)
        if isinstance(swapped, LostSwap):
            return swapped
        return Success[CommandInvocationRecord](outcome="SUCCESS", value=swapped)

    return run_operation(unit_of_work, once)


# --------------------------------------------------------------------------
# The linked launch operations (plan 6, 10.1 rows 9 and 11)
# --------------------------------------------------------------------------


def _load_linked_pair(
    transaction: UnitOfWork,
    *,
    invocation_id: str,
    run_id: str,
    now: datetime,
) -> tuple[CommandInvocationRecord, EngineRunRecord] | Failure:
    invocation = _load_invocation(transaction, invocation_id)
    if isinstance(invocation, Failure):
        return invocation
    run = _load_run(transaction, run_id)
    if isinstance(run, Failure):
        return run
    if invocation.run_id != run.run_id:
        return _invariant(
            f"invocation {invocation.invocation_id} is not linked to run {run.run_id}",
            now=now,
            invocation_id=invocation.invocation_id,
            run=run,
        )
    return invocation, run


def _require_run_kind(
    invocation: CommandInvocationRecord, run: EngineRunRecord, *, now: datetime
) -> Failure | None:
    if invocation.command_kind is not _K.RUN:
        return _invariant(
            f"the linked launch operations apply to a RUN invocation, not "
            f"{invocation.command_kind.value}",
            now=now,
            invocation_id=invocation.invocation_id,
            run=run,
        )
    return None


def _both_revisions(
    invocation: CommandInvocationRecord,
    run: EngineRunRecord,
    *,
    expected_invocation_revision: int,
    expected_run_revision: int,
    now: datetime,
) -> Failure | None:
    if expected_invocation_revision != invocation.revision:
        return _stale_invocation(invocation, expected_invocation_revision, now=now)
    if expected_run_revision != run.revision:
        return _stale_run(run, expected_run_revision, now=now)
    return None


def _swap_pair(
    transaction: UnitOfWork,
    invocation: CommandInvocationRecord,
    invocation_replacement: CommandInvocationRecord,
    run: EngineRunRecord,
    run_replacement_record: EngineRunRecord,
) -> Success[LinkedPair] | LostSwap:
    swapped_invocation = _swap_invocation(
        transaction, invocation, invocation_replacement
    )
    if isinstance(swapped_invocation, LostSwap):
        return swapped_invocation
    swapped_run = _swap_run(transaction, run, run_replacement_record)
    if isinstance(swapped_run, LostSwap):
        return swapped_run
    return _pair(swapped_invocation, swapped_run)


def begin_linked_launch(
    request: LinkedLaunchRequest,
    *,
    unit_of_work: UnitOfWork,
    clock: Clock,
) -> Result[LinkedPair]:
    """``PENDING -> STARTING`` with ``READY -> STARTING``, in one unit of work."""

    def once(transaction: UnitOfWork) -> Outcome[LinkedPair]:
        now = clock.now_utc()
        loaded = _load_linked_pair(
            transaction,
            invocation_id=request.invocation_id,
            run_id=request.run_id,
            now=now,
        )
        if isinstance(loaded, Failure):
            return loaded
        invocation, run = loaded
        kind_failure = _require_run_kind(invocation, run, now=now)
        if kind_failure is not None:
            return kind_failure
        if invocation.state is _C.STARTING and run.state is _R.STARTING:
            stale = _both_revisions(
                invocation,
                run,
                expected_invocation_revision=request.expected_invocation_revision,
                expected_run_revision=request.expected_run_revision,
                now=now,
            )
            return _pair(invocation, run) if stale is None else stale
        if invocation.state is not _C.PENDING or run.state is not _R.READY:
            return _invariant(
                f"begin_linked_launch requires a PENDING invocation and a READY run, "
                f"not ({invocation.state.value}, {run.state.value})",
                now=now,
                invocation_id=invocation.invocation_id,
                run=run,
            )
        stale = _both_revisions(
            invocation,
            run,
            expected_invocation_revision=request.expected_invocation_revision,
            expected_run_revision=request.expected_run_revision,
            now=now,
        )
        if stale is not None:
            return stale
        next_run = run_replacement(
            run,
            target=_R.STARTING,
            now=now,
            primary_terminal_diagnostic_id=MISSING,
            availability_observation_id=MISSING,
        )
        if isinstance(next_run, Failure):
            return next_run
        try:
            next_invocation = _launch_replacement(invocation, now=now)
            assert_invocation_transition(invocation, next_invocation)
            assert_run_transition(run, next_run, owner=RunEdgeOwner.LINKED_LAUNCH)
        except ValidationError as error:
            return _invariant(
                str(error), now=now, invocation_id=invocation.invocation_id, run=run
            )
        except CommandInvocationRuleViolation as violation:
            return _invocation_rule_failure(violation, now=now, stored=invocation)
        except EngineRunRuleViolation as violation:
            return run_rule_failure(violation, now=now, stored=run)
        return _swap_pair(transaction, invocation, next_invocation, run, next_run)

    return run_operation(unit_of_work, once)


def start_linked_run(
    request: LinkedStartRequest,
    *,
    unit_of_work: UnitOfWork,
    clock: Clock,
) -> Result[LinkedPair]:
    """``STARTING -> RUNNING`` with the process facts and ``STARTING -> RUNNING``
    on the run, in one unit of work (the process-creation handoff, spec 15.2)."""

    def once(transaction: UnitOfWork) -> Outcome[LinkedPair]:
        now = clock.now_utc()
        loaded = _load_linked_pair(
            transaction,
            invocation_id=request.invocation_id,
            run_id=request.run_id,
            now=now,
        )
        if isinstance(loaded, Failure):
            return loaded
        invocation, run = loaded
        kind_failure = _require_run_kind(invocation, run, now=now)
        if kind_failure is not None:
            return kind_failure
        if invocation.state is _C.RUNNING and run.state is _R.RUNNING:
            stale = _both_revisions(
                invocation,
                run,
                expected_invocation_revision=request.expected_invocation_revision,
                expected_run_revision=request.expected_run_revision,
                now=now,
            )
            if stale is not None:
                return stale
            same_facts = (
                invocation.pid_identity == request.process_start.pid_identity
                and invocation.process_started_at_utc
                == request.process_start.process_started_at_utc
            )
            if same_facts:
                return _pair(invocation, run)
            return _conflict(
                "the pair is already RUNNING with different process facts",
                now=now,
                invocation_id=invocation.invocation_id,
                run=run,
            )
        if invocation.state is not _C.STARTING or run.state is not _R.STARTING:
            return _invariant(
                f"start_linked_run requires a STARTING invocation and a STARTING run, "
                f"not ({invocation.state.value}, {run.state.value})",
                now=now,
                invocation_id=invocation.invocation_id,
                run=run,
            )
        stale = _both_revisions(
            invocation,
            run,
            expected_invocation_revision=request.expected_invocation_revision,
            expected_run_revision=request.expected_run_revision,
            now=now,
        )
        if stale is not None:
            return stale
        next_run = run_replacement(
            run,
            target=_R.RUNNING,
            now=now,
            primary_terminal_diagnostic_id=MISSING,
            availability_observation_id=MISSING,
        )
        if isinstance(next_run, Failure):
            return next_run
        try:
            next_invocation = _start_replacement(invocation, now=now, request=request)
            assert_invocation_transition(invocation, next_invocation)
            assert_run_transition(run, next_run, owner=RunEdgeOwner.LINKED_LAUNCH)
        except ValidationError as error:
            return _invariant(
                str(error), now=now, invocation_id=invocation.invocation_id, run=run
            )
        except CommandInvocationRuleViolation as violation:
            return _invocation_rule_failure(violation, now=now, stored=invocation)
        except EngineRunRuleViolation as violation:
            return run_rule_failure(violation, now=now, stored=run)
        return _swap_pair(transaction, invocation, next_invocation, run, next_run)

    return run_operation(unit_of_work, once)


# --------------------------------------------------------------------------
# transition_invocation_and_run (plan 6 coupled terminal table, 10.1 row 13)
# --------------------------------------------------------------------------


def transition_invocation_and_run(
    request: CoupledTransitionRequest,
    *,
    unit_of_work: UnitOfWork,
    clock: Clock,
) -> Result[LinkedPair]:
    """A terminal invocation outcome and its coupled run transition, together."""

    def once(transaction: UnitOfWork) -> Outcome[LinkedPair]:
        now = clock.now_utc()
        invocation_request = request.invocation
        run_request = request.run
        target = invocation_request.target_state
        loaded = _load_linked_pair(
            transaction,
            invocation_id=invocation_request.invocation_id,
            run_id=run_request.run_id,
            now=now,
        )
        if isinstance(loaded, Failure):
            return loaded
        invocation, run = loaded
        kind = invocation.command_kind
        if kind is _K.DESCRIBE:
            return _invariant(
                "a DESCRIBE invocation has no run linkage to couple",
                now=now,
                invocation_id=invocation.invocation_id,
                run=run,
            )
        if target not in COUPLED_TERMINAL_TARGETS:
            return _invariant(
                f"{target.value} couples no run transition; EXITED and the non-"
                "terminal targets belong to transition_invocation",
                now=now,
                invocation_id=invocation.invocation_id,
                run=run,
            )
        if invocation.state is target and run.state is run_request.target_state:
            stale = _both_revisions(
                invocation,
                run,
                expected_invocation_revision=invocation_request.expected_revision,
                expected_run_revision=run_request.expected_revision,
                now=now,
            )
            return _pair(invocation, run) if stale is None else stale
        if invocation.state in TERMINAL_COMMAND_INVOCATION_STATES:
            return _invariant(
                f"a terminal invocation ({invocation.state.value}) accepts no "
                "transition",
                now=now,
                invocation_id=invocation.invocation_id,
                run=run,
            )
        if not COMMAND_INVOCATION_TRANSITIONS.is_allowed(invocation.state, target):
            return _invariant(
                f"{invocation.state.value} -> {target.value} is not a permitted "
                "command-invocation edge",
                now=now,
                invocation_id=invocation.invocation_id,
                run=run,
            )
        category: DiagnosticCategory | MISSING = MISSING  # type: ignore[valid-type]
        if target is _C.FAILED_TO_START:
            if _is_missing(invocation_request.primary_diagnostic_id):
                return _invariant(
                    "FAILED_TO_START requires the primary start diagnostic",
                    now=now,
                    invocation_id=invocation.invocation_id,
                    run=run,
                )
            diagnostic = transaction.diagnostics.get(
                invocation_request.primary_diagnostic_id
            )
            if isinstance(diagnostic, Failure):
                return _invariant(
                    f"primary diagnostic {invocation_request.primary_diagnostic_id} "
                    "does not exist",
                    now=now,
                    invocation_id=invocation.invocation_id,
                    run=run,
                )
            category = diagnostic.value.category
        mapped = coupled_run_terminal_state(
            kind, invocation.state, target, primary_diagnostic_category=category
        )
        if _is_missing(mapped) or mapped is not run_request.target_state:
            return _invariant(
                f"{target.value} on a {kind.value} invocation couples the run to "
                f"{'nothing' if _is_missing(mapped) else mapped.value}, not "
                f"{run_request.target_state.value}",
                now=now,
                invocation_id=invocation.invocation_id,
                run=run,
            )
        if kind is _K.RUN and is_mixed_running_pair(run, invocation):
            return _invariant(
                f"the stored pair ({invocation.state.value}, {run.state.value}) is a "
                "mixed running pair",
                now=now,
                invocation_id=invocation.invocation_id,
                run=run,
            )
        if run.state in TERMINAL_ENGINE_RUN_STATES:
            return _invariant(
                f"run {run.run_id} is already terminal ({run.state.value}); the "
                "invocation alone may terminalize through transition_invocation",
                now=now,
                invocation_id=invocation.invocation_id,
                run=run,
            )
        stale = _both_revisions(
            invocation,
            run,
            expected_invocation_revision=invocation_request.expected_revision,
            expected_run_revision=run_request.expected_revision,
            now=now,
        )
        if stale is not None:
            return stale
        next_run = run_replacement(
            run,
            target=run_request.target_state,
            now=now,
            primary_terminal_diagnostic_id=run_request.primary_terminal_diagnostic_id,
            availability_observation_id=run_request.availability_observation_id,
        )
        if isinstance(next_run, Failure):
            return next_run
        try:
            next_invocation = _invocation_replacement(
                invocation, target=target, now=now, request=invocation_request
            )
            assert_invocation_transition(invocation, next_invocation)
            assert_run_transition(run, next_run, owner=RunEdgeOwner.GENERIC)
        except ValidationError as error:
            return _invariant(
                str(error), now=now, invocation_id=invocation.invocation_id, run=run
            )
        except CommandInvocationRuleViolation as violation:
            return _invocation_rule_failure(violation, now=now, stored=invocation)
        except EngineRunRuleViolation as violation:
            return run_rule_failure(violation, now=now, stored=run)
        return _swap_pair(transaction, invocation, next_invocation, run, next_run)

    return run_operation(unit_of_work, once)
