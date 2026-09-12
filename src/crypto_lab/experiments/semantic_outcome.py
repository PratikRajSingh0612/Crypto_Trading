"""The command semantic outcome operation (Stage 6 plan sections 3.12, 9.3, 10, 13
and 14 Task 7; specification 8.1-8.2, 14.6, 15.2, 17.1, 19.4, 21.2.1, 23.2, 29.6).

``apply_command_semantic_outcome`` is the fourth of the four Task 6 layers: the
**authoritative application effect**. The process fact (the ``EXITED`` invocation),
the parsed adapter declaration (the typed parse outcome) and the pure reconciliation
proposal (``SemanticReconciliation``) are consumed as committed; this module never
reinterprets an exit, re-parses adapter bytes or recomputes a verdict's run target.
Driven by ``run_operation`` like every Stage 5 operation, in one unit of work:

1. Load the invocation and the run; a ``DESCRIBE`` invocation, an invocation not
   linked to the run, a non-``EXITED`` invocation or a parse outcome of the wrong
   kind is ``CORE.INVARIANT_VIOLATION``.
2. Both expected revisions must match, else ``PERSISTENCE.CONCURRENCY_CONFLICT`` --
   before every state precondition, so a re-issue after either record moved on is a
   stable conflict (specification 29.6).
3. A run already ``CANCELLED`` or ``TIMED_OUT`` is a core win: the stored pair is
   returned with ``superseded_by`` set and no reconciliation; nothing is written or
   minted.
4. Load the experiment and the run's frozen ``SlotCompatibility`` and call
   ``reconcile_validate`` or ``reconcile_run`` with the injected clock's instant; a
   ``ReconciliationRuleViolation`` is ``CORE.INVARIANT_VIOLATION``.
5. Replay is decided after the verdict exists and before the first-application
   preconditions. A run still in its pre-state proceeds. A run at the verdict's
   target whose invocation already records every recomputed diagnostic identity is
   an identical replay: the stored pair and the recomputed reconciliation, no write.
   A run in an admitted terminal state the verdict did not produce, or at the
   target under a core-decided primary, is a lawful later Stage 5 move: the stored
   pair, the recomputed reconciliation and ``superseded_by``, no write. Every other
   combination is a divergent re-issue: ``CORE.INVARIANT_VIOLATION``, no write.
   ``RESULT_FINALIZATION_ELIGIBLE`` never short-circuits: a ``RUNNING`` run reaches
   step 6 on every issue and returns after it with no write.
6. First-application preconditions, the authoritative read Stage 5's
   ``transition_run`` could not perform (Stage 6 plan 1.5 item 3): the run is the
   slot's latest attempt, the experiment is ``RUNNING`` and the run's ``VALIDATE``
   and ``RUN`` invocations show no other non-terminal invocation.
7. For a verdict with a run target: the Stage 5 ``run_replacement`` with the primary
   diagnostic identity and, for ``READY`` and ``UNAVAILABLE``, the slot's frozen
   availability observation; ``assert_run_transition`` with owner ``GENERIC``; the
   run compare-and-swap. ``RESULT_FINALIZATION_ELIGIBLE`` writes no run: the run
   stays ``RUNNING`` for Stage 9.
8. When the verdict minted an identity the invocation does not yet record, the
   write-once enrichment adding it (``assert_write_once_enrichment``) and the
   invocation compare-and-swap, in the same unit of work as the run write; a lost
   swap on either record rolls back both and the driver reloads exactly once.
9. Return ``SemanticOutcome`` carrying the minted ``Diagnostic`` objects for the
   caller to seed; a later stage persists them.

No code path builds a success run state, the core run manifest, an artifact
reference or an event-ledger operation; no clock but the injected one is read; no
adapter byte, filesystem path or process is touched.

Task-local readings, declared here rather than inferred silently (each recorded in
the Task 7 ledger):

- R1. The clock is read once at the start of the transaction, the Stage 5 pattern;
  step 4 needs the instant on every issue and every Stage 6 identity excludes it, so
  an identical replay under an advanced clock recomputes identical identities.
- R2. Step 8 writes the invocation exactly when the minted identities add one the
  invocation does not yet record; an identity already present (a supervisor
  pre-enrichment with the same content-derived id) is not re-added, because the
  merged predicate rejects an empty enrichment. The run write still happens, and a
  re-issue then replays.
- R3. The experiment and the slot's frozen entry are loaded at step 4 for both kinds,
  after the step-3 core-win return; a missing frozen entry for the run's slot is
  ``CORE.INVARIANT_VIOLATION``.
- R4. The step-6 check spans both linked kinds: a lawful Stage 5 history never holds
  an open ``RUN`` invocation beside a ``VALIDATING`` run or an open ``VALIDATE``
  beside a ``RUNNING`` one, so an open invocation of either kind is an impossible
  aggregate state, not a per-kind uniqueness race.
- R5. ``SemanticOutcome`` validates its own shape: the invocation is linked to the
  run, the run is never a success state, ``superseded_by`` names the run's terminal
  state when present, and an absent reconciliation is the core-win answer alone.
- R6. A ``superseded_by`` answer is a stable, idempotent success carrying the durable
  state (specification 29.6's "prior identical outcome" is the stored pair; the flag
  records that a later core decision, not this verdict, produced it); it is never a
  conflict, because nothing raced -- the core decision lawfully won first.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any, Final, Self

from pydantic import ValidationError, model_validator
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.adapters.manifests import ManifestParse, ValidationResultParse
from crypto_lab.adapters.reconciliation import (
    ReconciliationRuleViolation,
    SemanticReconciliation,
    reconcile_run,
    reconcile_validate,
)
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.command_invocation import (
    CommandInvocationCheck,
    CommandInvocationRecord,
    CommandInvocationRuleViolation,
    assert_write_once_enrichment,
)
from crypto_lab.domain.diagnostics import DiagnosticDetailValue
from crypto_lab.domain.engine_run import (
    SUCCESS_ENGINE_RUN_STATES,
    EngineRunRecord,
    EngineRunRuleViolation,
    RunEdgeOwner,
    assert_run_transition,
)
from crypto_lab.domain.experiment import ExperimentRecord, SlotCompatibility
from crypto_lab.domain.lifecycle import (
    TERMINAL_COMMAND_INVOCATION_STATES,
    TERMINAL_ENGINE_RUN_STATES,
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.ports import Clock
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.experiments.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
    stage5_failure,
)
from crypto_lab.experiments.experiment_service import LostSwap, run_operation
from crypto_lab.experiments.ports import UnitOfWork
from crypto_lab.experiments.requests import SemanticOutcomeRequest
from crypto_lab.experiments.run_service import run_replacement, run_rule_failure

SOURCE_COMPONENT: Final = "experiments.semantic_outcome"
_K: Final = CommandKind
_R: Final = EngineRunState
_C: Final = CommandInvocationState

#: Plan 10 step 3: the two terminal states only a core decision produces.
_CORE_WON_STATES: Final[frozenset[EngineRunState]] = frozenset(
    {_R.CANCELLED, _R.TIMED_OUT}
)
#: Plan 6.2 and 9.2: the pre-state each command kind's outcome moves the run from.
_PRE_STATE_OF_KIND: Final[Mapping[CommandKind, EngineRunState]] = {
    _K.VALIDATE: _R.VALIDATING,
    _K.RUN: _R.RUNNING,
}
#: Plan 3.8 row 14 and 10 step 7: the targets that take the slot's observation.
_OBSERVATION_GOVERNING_TARGETS: Final[frozenset[EngineRunState]] = frozenset(
    {_R.READY, _R.UNAVAILABLE}
)
#: Plan 10 step 6: the two command kinds whose invocations link to a run.
_LINKED_KINDS: Final[tuple[CommandKind, ...]] = (_K.VALIDATE, _K.RUN)


def _is_missing(value: object) -> bool:
    return value is MISSING


class SemanticOutcome(CanonicalModel):
    """The invocation and run after one application (plan 3.12; trust class P).

    A nested value object without an envelope ``schema_version`` (the ``LinkedPair``
    precedent). ``reconciliation`` is the recomputed Task 6 verdict, absent exactly
    for the core-win answer of plan 10 step 3; ``superseded_by`` is present exactly
    when the run was found in a terminal state this verdict did not produce and then
    equals ``run.state``. The run is never a success state (reading R5).
    """

    invocation: CommandInvocationRecord
    run: EngineRunRecord
    reconciliation: SemanticReconciliation | MISSING = MISSING  # type: ignore[valid-type]
    superseded_by: EngineRunState | MISSING = MISSING  # type: ignore[valid-type]

    @model_validator(mode="after")
    def validate_shape(self) -> Self:
        if self.invocation.run_id != self.run.run_id:
            raise ValueError("the invocation is not linked to the run")
        if self.run.state in SUCCESS_ENGINE_RUN_STATES:
            raise ValueError(
                "the run is never a success state: only Stage 9 commits success"
            )
        superseded = not _is_missing(self.superseded_by)
        if superseded and (
            self.superseded_by is not self.run.state
            or self.run.state not in TERMINAL_ENGINE_RUN_STATES
        ):
            raise ValueError("superseded_by must name the run's terminal state")
        if _is_missing(self.reconciliation) and (
            not superseded or self.superseded_by not in _CORE_WON_STATES
        ):
            raise ValueError(
                "an absent reconciliation is the core-win answer alone: superseded_by "
                "must be CANCELLED or TIMED_OUT"
            )
        return self


# --------------------------------------------------------------------------
# Failures and loads
# --------------------------------------------------------------------------


def _failure(
    code: str,
    message: str,
    *,
    now: datetime,
    invocation: CommandInvocationRecord,
    run: EngineRunRecord,
    details: Mapping[str, DiagnosticDetailValue] | None = None,
) -> Failure:
    return stage5_failure(
        code,
        message,
        source_component=SOURCE_COMPONENT,
        timestamp_utc=now,
        experiment_id=run.experiment_id,
        run_id=run.run_id,
        invocation_id=invocation.invocation_id,
        details=details,
    )


def _invariant(
    message: str,
    *,
    now: datetime,
    invocation: CommandInvocationRecord,
    run: EngineRunRecord,
    details: Mapping[str, DiagnosticDetailValue] | None = None,
) -> Failure:
    return _failure(
        INVARIANT_VIOLATION,
        message,
        now=now,
        invocation=invocation,
        run=run,
        details=details,
    )


def _conflict(
    message: str,
    *,
    now: datetime,
    invocation: CommandInvocationRecord,
    run: EngineRunRecord,
    details: Mapping[str, DiagnosticDetailValue] | None = None,
) -> Failure:
    return _failure(
        CONCURRENCY_CONFLICT,
        message,
        now=now,
        invocation=invocation,
        run=run,
        details=details,
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


def _outcome(
    invocation: CommandInvocationRecord,
    run: EngineRunRecord,
    *,
    reconciliation: SemanticReconciliation | MISSING = MISSING,  # type: ignore[valid-type]
    superseded_by: EngineRunState | MISSING = MISSING,  # type: ignore[valid-type]
) -> Success[SemanticOutcome]:
    payload: dict[str, Any] = {"invocation": invocation, "run": run}
    if not _is_missing(reconciliation):
        payload["reconciliation"] = reconciliation
    if not _is_missing(superseded_by):
        payload["superseded_by"] = superseded_by
    return Success[SemanticOutcome](
        outcome="SUCCESS", value=SemanticOutcome.model_validate(payload)
    )


def _minted_identities(reconciliation: SemanticReconciliation) -> frozenset[str]:
    return frozenset(item.diagnostic_id for item in reconciliation.diagnostics)


# --------------------------------------------------------------------------
# Steps 1-2: the shape of the loaded pair and the expected revisions
# --------------------------------------------------------------------------


def _shape_failure(
    request: SemanticOutcomeRequest,
    invocation: CommandInvocationRecord,
    run: EngineRunRecord,
    *,
    now: datetime,
) -> Failure | None:
    kind = invocation.command_kind
    if kind is _K.DESCRIBE:
        return _invariant(
            "a DESCRIBE invocation has no run and no semantic outcome to apply",
            now=now,
            invocation=invocation,
            run=run,
            details={"command_kind": kind.value},
        )
    if invocation.run_id != run.run_id:
        return _invariant(
            f"invocation {invocation.invocation_id} is not linked to run {run.run_id}",
            now=now,
            invocation=invocation,
            run=run,
            details={"command_kind": kind.value},
        )
    if invocation.state is not _C.EXITED:
        return _invariant(
            "only an EXITED invocation has a semantic outcome to apply, not "
            f"{invocation.state.value}",
            now=now,
            invocation=invocation,
            run=run,
            details={
                "command_kind": kind.value,
                "stored_state": invocation.state.value,
            },
        )
    output = request.parsed_output
    if kind is _K.VALIDATE and isinstance(output, ManifestParse):
        return _invariant(
            "a ManifestParse is admitted only for a RUN invocation",
            now=now,
            invocation=invocation,
            run=run,
            details={"command_kind": kind.value},
        )
    if kind is _K.RUN and isinstance(output, ValidationResultParse):
        return _invariant(
            "a ValidationResultParse is admitted only for a VALIDATE invocation",
            now=now,
            invocation=invocation,
            run=run,
            details={"command_kind": kind.value},
        )
    return None


def _revision_failure(
    request: SemanticOutcomeRequest,
    invocation: CommandInvocationRecord,
    run: EngineRunRecord,
    *,
    now: datetime,
) -> Failure | None:
    if request.expected_invocation_revision != invocation.revision:
        return _conflict(
            f"invocation {invocation.invocation_id} is at revision "
            f"{invocation.revision}, not {request.expected_invocation_revision}",
            now=now,
            invocation=invocation,
            run=run,
            details={
                "expected_revision": request.expected_invocation_revision,
                "stored_revision": invocation.revision,
            },
        )
    if request.expected_run_revision != run.revision:
        return _conflict(
            f"run {run.run_id} is at revision {run.revision}, "
            f"not {request.expected_run_revision}",
            now=now,
            invocation=invocation,
            run=run,
            details={
                "expected_revision": request.expected_run_revision,
                "stored_revision": run.revision,
            },
        )
    return None


# --------------------------------------------------------------------------
# Step 4: the frozen slot and the pure reconciliation
# --------------------------------------------------------------------------


def _frozen_slot(
    experiment: ExperimentRecord,
    invocation: CommandInvocationRecord,
    run: EngineRunRecord,
    *,
    now: datetime,
) -> SlotCompatibility | Failure:
    """The experiment's frozen compatibility entry for the run's slot (reading R3)."""
    entries: tuple[SlotCompatibility, ...] = (
        ()
        if _is_missing(experiment.slot_compatibility)
        else experiment.slot_compatibility
    )
    for entry in entries:
        if entry.logical_slot_id == run.logical_slot_id:
            return entry
    return _invariant(
        "the experiment holds no frozen slot compatibility for the run's slot",
        now=now,
        invocation=invocation,
        run=run,
        details={"logical_slot_id": run.logical_slot_id},
    )


def _reconcile(
    request: SemanticOutcomeRequest,
    invocation: CommandInvocationRecord,
    run: EngineRunRecord,
    experiment: ExperimentRecord,
    slot: SlotCompatibility,
    *,
    now: datetime,
) -> SemanticReconciliation:
    """The Task 6 reconciler of the invocation's kind over the request's material."""
    output = request.parsed_output
    if invocation.command_kind is _K.VALIDATE:
        validation: Any = (
            output if isinstance(output, ValidationResultParse) else MISSING
        )
        return reconcile_validate(
            invocation,
            run,
            validation,
            request.protocol_summary,
            request.protocol_failure,
            now_utc=now,
        )
    manifest: Any = output if isinstance(output, ManifestParse) else MISSING
    return reconcile_run(
        invocation,
        run,
        experiment,
        slot,
        manifest,
        request.protocol_summary,
        request.candidate_observations,
        request.negotiated_versions,
        request.protocol_failure,
        now_utc=now,
    )


# --------------------------------------------------------------------------
# Step 5: replay, supersession and divergence
# --------------------------------------------------------------------------


def _settled(
    reconciliation: SemanticReconciliation,
    invocation: CommandInvocationRecord,
    run: EngineRunRecord,
    *,
    now: datetime,
) -> Success[SemanticOutcome] | Failure | None:
    """Plan 10 step 5. ``None`` means the run is still in its pre-state: proceed."""
    if run.state is _PRE_STATE_OF_KIND[invocation.command_kind]:
        return None
    minted = _minted_identities(reconciliation)
    target = reconciliation.run_target_state
    target_label = "MISSING" if _is_missing(target) else target.value
    details: dict[str, DiagnosticDetailValue] = {
        "stored_state": run.state.value,
        "run_target_state": target_label,
    }
    if not _is_missing(target) and run.state is target:
        if minted <= frozenset(invocation.diagnostic_ids):
            return _outcome(invocation, run, reconciliation=reconciliation)
        if run.primary_terminal_diagnostic_id in minted:
            return _invariant(
                "a divergent re-issue: the run is at the verdict's target but the "
                "invocation never recorded the recomputed diagnostic identity",
                now=now,
                invocation=invocation,
                run=run,
                details=details,
            )
        return _outcome(
            invocation, run, reconciliation=reconciliation, superseded_by=run.state
        )
    if run.state in TERMINAL_ENGINE_RUN_STATES:
        return _outcome(
            invocation, run, reconciliation=reconciliation, superseded_by=run.state
        )
    return _invariant(
        "a divergent re-issue: the run left its pre-state under another verdict",
        now=now,
        invocation=invocation,
        run=run,
        details=details,
    )


# --------------------------------------------------------------------------
# Step 6: the first-application preconditions (plan 1.5 item 3)
# --------------------------------------------------------------------------


def _precondition_failure(
    transaction: UnitOfWork,
    invocation: CommandInvocationRecord,
    run: EngineRunRecord,
    experiment: ExperimentRecord,
    *,
    now: datetime,
) -> Failure | None:
    latest = transaction.engine_runs.latest_attempt(
        run.experiment_id, run.logical_slot_id
    )
    if isinstance(latest, Failure):
        return latest
    current = latest.value
    if _is_missing(current) or current.run_id != run.run_id:
        return _invariant(
            f"run {run.run_id} is not the current attempt of its slot",
            now=now,
            invocation=invocation,
            run=run,
            details={
                "latest_attempt_run_id": (
                    "MISSING" if _is_missing(current) else current.run_id
                )
            },
        )
    if experiment.state is not ExperimentState.RUNNING:
        return _invariant(
            f"the experiment is {experiment.state.value}, not RUNNING",
            now=now,
            invocation=invocation,
            run=run,
            details={"experiment_state": experiment.state.value},
        )
    for kind in _LINKED_KINDS:
        listed = transaction.command_invocations.list_for_run(run.run_id, kind)
        if isinstance(listed, Failure):
            return listed
        for record in listed.value:
            if (
                record.invocation_id != invocation.invocation_id
                and record.state not in TERMINAL_COMMAND_INVOCATION_STATES
            ):
                return _invariant(
                    f"run {run.run_id} has another open {kind.value} invocation",
                    now=now,
                    invocation=invocation,
                    run=run,
                    details={
                        "open_invocation_id": record.invocation_id,
                        "open_command_kind": kind.value,
                    },
                )
    return None


# --------------------------------------------------------------------------
# Step 8: the write-once enrichment
# --------------------------------------------------------------------------


def _enrichment(
    invocation: CommandInvocationRecord,
    additional: frozenset[str],
    run: EngineRunRecord,
    *,
    now: datetime,
) -> CommandInvocationRecord | Failure:
    """The invocation with ``additional`` identities recorded (reading R2)."""
    payload = invocation.model_dump(mode="python")
    payload["diagnostic_ids"] = tuple(sorted({*invocation.diagnostic_ids, *additional}))
    payload["updated_at_utc"] = now
    payload["revision"] = invocation.revision + 1
    try:
        replacement = CommandInvocationRecord.model_validate(payload)
    except ValidationError:
        return _invariant(
            "the enriched invocation is not a representable record",
            now=now,
            invocation=invocation,
            run=run,
            details={"diagnostic_count": len(payload["diagnostic_ids"])},
        )
    try:
        assert_write_once_enrichment(invocation, replacement)
    except CommandInvocationRuleViolation as violation:
        code = (
            CONCURRENCY_CONFLICT
            if violation.check is CommandInvocationCheck.REVISION
            else INVARIANT_VIOLATION
        )
        return _failure(
            code,
            str(violation),
            now=now,
            invocation=invocation,
            run=run,
            details={"check": violation.check.value},
        )
    return replacement


# --------------------------------------------------------------------------
# The operation (plan 10)
# --------------------------------------------------------------------------


def apply_command_semantic_outcome(
    request: SemanticOutcomeRequest,
    *,
    unit_of_work: UnitOfWork,
    clock: Clock,
) -> Result[SemanticOutcome]:
    """Apply one Task 6 reconciliation to the run and invocation, or replay it.

    The module docstring is the step table. Every read and both compare-and-swaps
    happen inside one transaction of ``unit_of_work``; the run is never moved to a
    success state and ``RESULT_FINALIZATION_ELIGIBLE`` writes nothing.
    """

    def once(
        transaction: UnitOfWork,
    ) -> Success[SemanticOutcome] | Failure | LostSwap:
        now = clock.now_utc()
        # 1. The pair and its shape.
        invocation = _load_invocation(transaction, request.invocation_id)
        if isinstance(invocation, Failure):
            return invocation
        run = _load_run(transaction, request.run_id)
        if isinstance(run, Failure):
            return run
        shape = _shape_failure(request, invocation, run, now=now)
        if shape is not None:
            return shape
        # 2. Expected revisions before every state precondition.
        stale = _revision_failure(request, invocation, run, now=now)
        if stale is not None:
            return stale
        # 3. A core win is returned unchanged.
        if run.state in _CORE_WON_STATES:
            return _outcome(invocation, run, superseded_by=run.state)
        # 4. The experiment, the frozen slot and the pure reconciliation.
        experiment = _load_experiment(transaction, run.experiment_id)
        if isinstance(experiment, Failure):
            return experiment
        slot = _frozen_slot(experiment, invocation, run, now=now)
        if isinstance(slot, Failure):
            return slot
        try:
            reconciliation = _reconcile(
                request, invocation, run, experiment, slot, now=now
            )
        except ReconciliationRuleViolation as violation:
            return _invariant(str(violation), now=now, invocation=invocation, run=run)
        # 5. Replay, supersession or divergence, decided after the verdict exists.
        settled = _settled(reconciliation, invocation, run, now=now)
        if settled is not None:
            return settled
        # 6. The authoritative reads of a first application.
        precondition = _precondition_failure(
            transaction, invocation, run, experiment, now=now
        )
        if precondition is not None:
            return precondition
        # 7. The run write, through the Stage 5 run rules.
        target = reconciliation.run_target_state
        next_run = run
        if not _is_missing(target):
            primary = reconciliation.primary_diagnostic
            replacement = run_replacement(
                run,
                target=target,
                now=now,
                primary_terminal_diagnostic_id=(
                    MISSING if _is_missing(primary) else primary.diagnostic_id
                ),
                availability_observation_id=(
                    slot.availability_observation_id
                    if target in _OBSERVATION_GOVERNING_TARGETS
                    else MISSING
                ),
            )
            if isinstance(replacement, Failure):
                return replacement
            try:
                assert_run_transition(run, replacement, owner=RunEdgeOwner.GENERIC)
            except EngineRunRuleViolation as violation:
                return run_rule_failure(violation, now=now, stored=run)
            swapped_run = transaction.engine_runs.compare_and_swap(
                run.revision, replacement
            )
            if isinstance(swapped_run, Failure):
                return LostSwap(swapped_run)
            next_run = swapped_run.value
        # 8. The write-once enrichment, in the same unit of work.
        next_invocation = invocation
        additional = _minted_identities(reconciliation) - frozenset(
            invocation.diagnostic_ids
        )
        if additional:
            enriched = _enrichment(invocation, additional, run, now=now)
            if isinstance(enriched, Failure):
                return enriched
            swapped_invocation = transaction.command_invocations.compare_and_swap(
                invocation.revision, enriched
            )
            if isinstance(swapped_invocation, Failure):
                return LostSwap(swapped_invocation)
            next_invocation = swapped_invocation.value
        # 9. The applied pair and the minted diagnostics.
        return _outcome(next_invocation, next_run, reconciliation=reconciliation)

    return run_operation(unit_of_work, once)
