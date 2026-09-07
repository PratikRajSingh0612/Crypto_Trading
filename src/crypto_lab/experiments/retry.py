"""Retry scheduling, replay and successor creation: the two retry operations.

Plan sections 8.1-8.6 (the retry gates, preconditions, the three-phase decision flow,
successor creation and the Stage 5 codes), 9.1 (the experiment revision as the single
mutual-exclusion primitive), 9.5 rows 3-4 and 9-10 (the loser reloads once) and 10.1
rows ``evaluate_retry`` / ``create_successor``, under specification sections 7.2, 16.3,
17.2, 17.2.1, 21.4, 23.3.1 and 29.6. Both operations run through the Task 6 reload-once
driver ``run_operation``, reach every repository through the unit of work alone, read
the injected ``Clock`` and ``IdentitySource`` only where declared below, and consume the
committed Task 5 kernel -- ``evaluate_retry_gates`` over a ``RetryEvaluationSnapshot``
assembled here from authoritative reads -- rather than re-evaluating any gate. Nothing
here reads a wall clock, draws a random value, launches a process, traverses a
diagnostic graph anywhere but ``resolve_causal_closure``, or imports a concrete
repository.

Four public pieces:

1. ``resolve_causal_closure`` -- the single owner of causal traversal (plan 8.2).
2. ``build_retry_evaluation_snapshot`` -- the authoritative snapshot assembler (plan
   8.2, 10.1 read set).
3. ``evaluate_retry`` -- plan 8.3 preconditions and plan 8.4 phases 1-3.
4. ``create_successor`` -- plan 8.5 steps 1-6, with ``successor_is_due`` as the pure
   scheduler-eligibility predicate of specification 7.2.

Task-local readings, declared here rather than inferred silently (each was submitted to
an adversarial cross-check before any code was written; see the Task 7 ledger):

- **Traversal.** Breadth-first from the primary (depth 0) along
  ``causal_diagnostic_ids``, one ``get_many`` per level with sorted unique identifiers,
  a visited set so a diamond is fetched once, the depth bound checked before the node
  bound (a 33-node chain succeeds, a 34-node chain fails; 256 nodes succeed, 257 fail),
  and Kahn's algorithm over the collected edges for the cycle test, so a back edge to an
  ancestor is a cycle while a cross edge or a diamond is not. A reader ``Failure`` whose
  every diagnostic carries ``CORE.INVARIANT_VIOLATION`` (the reader's
  missing/degenerate-read vocabulary) is the helper's ``missing_reference``; any other
  reader ``Failure`` passes through unchanged and is never fail-closed, because a
  transient read fault must not become a permanent denial. ``now`` stamps the helper's
  ``Failure`` diagnostic only -- the helper reads no clock -- and is a keyword-only
  extension of the plan's ``(reader, primary_id)`` signature forced by
  ``Diagnostic.timestamp_utc``. The plan 8.2 fail-closed substitution
  (``FAIL_CLOSED_CAUSAL_CLOSURE``) applies exactly to the four degenerate causes.
- **The primary diagnostic.** It is read through ``DiagnosticReader.get`` before the
  walk, which then re-fetches it as level 0; a missing primary ABORTS the evaluation
  with a non-persisted ``CORE.INVARIANT_VIOLATION`` rather than fail-closing, because
  the committed snapshot requires the whole ``Diagnostic`` for gate 3 and specification
  23.3.1 makes the reference restricted; the slot then stays ``DECISION_UNRESOLVED``
  (plan 9.2) and only ``cancel_experiment`` can end the experiment.
- **Gate 6 material.** For an ``UNAVAILABLE`` predecessor the snapshot carries the
  predecessor's referenced observation and, as its candidate tuple, the qualifying
  SELECTION of ``select_fresh_availability_observation`` over the unbounded
  ``list_for_adapter`` read -- at most one observation -- so the snapshot's 256 bound
  can never drop a qualifying observation and the kernel's own selection returns the
  identical one. This narrows the Task 5 module docstring's "the candidate observations
  from ``list_for_adapter``" to the qualifying selection; outcome and recorded
  identifier agree under both readings whenever the read holds at most 256 observations.
- **Phase 1.** Every ``get_by_predecessor`` ``Failure`` is treated as absence (the port
  defines no other failure). A present row with the request's ``experiment_id`` is
  returned unchanged with no clock read, no other repository read, no write and no gate
  evaluation; the expected revisions are not compared on replay (plan 8.4 names identity
  alone). A row for the same key under a different ``experiment_id`` is
  ``CORE.INVARIANT_VIOLATION``.
- **Phase 2 order.** The single clock read of the attempt comes first (every
  precondition failure needs an instant; plan 8.4's "exactly once" is the constraint),
  then the experiment, the predecessor, request identity, predecessor eligibility (plan
  8.3, five non-success terminals), the experiment being ``RUNNING`` or terminal, the
  two expected revisions (``PERSISTENCE.CONCURRENCY_CONFLICT``), the predecessor still
  being the latest attempt (movement is the same conflict), and only then the snapshot
  and the gates.
- **Phase 3 order (CAS first).** An ``ALLOWED`` candidate compare-and-swaps the
  experiment (revision + 1, ``updated_at_utc`` at the instant, state unchanged) BEFORE
  the decision insert: plan 8.3 gives a failed experiment-revision swap precedence over
  every gate result of the invalidated snapshot and specification 17.2.1 verifies the
  revisions before it records. A lost swap is a ``LostSwap``; the reload replays
  whatever durable row now exists or fails the expected-revision precondition -- never a
  persisted gate-5 denial and never a ``RETRY.DECISION_CONFLICT`` from a stale snapshot.
  ``insert_if_absent`` then reads the live row: a present winner under a different
  ``experiment_id`` is the phase 1 invariant defect; an equal semantic projection
  returns the winner; a divergent one is ``RETRY.DECISION_CONFLICT`` with neither row
  modified. Because gate 6 compares an observation's ``expires_at_utc`` against the
  instant, two evaluations of an ``UNAVAILABLE`` predecessor that straddle that expiry
  legitimately diverge and the loser receives the conflict. A ``DENIED`` candidate
  performs no experiment write (plan 9.1); its expected-revision precondition is
  therefore snapshot-time, which is sound because every recordable denial reason is a
  durable fact of immutable rows or of an already-terminal experiment, and a snapshot in
  which every other gate passes yields ``ALLOWED``, whose swap detects the movement. A
  repository ``Failure`` from the insert (a Stage 8 unique-key loss) is a ``LostSwap``.
  Residual for Stage 8: a unit of work that surfaces a unique-key loss only at commit
  replays the durable row rather than conflicting.
- **The driver.** ``run_operation`` is used unchanged: at most two attempts, rollback
  before the fresh transaction, one clock read per attempt (a losing invocation reads
  twice). Plan 9.5 and 13.2 criterion 6 (reload once, re-apply, return the operation's
  own ``Result``) are followed over plan 8.4 phase 3's "the next invocation begins a new
  evaluation"; both yield the same non-persisted code, and the reload attempt cannot
  pass the expected-revision check after a cancellation or terminal-aggregation winner.
  A durable ``EXPERIMENT_TERMINAL`` denial requires a new public invocation carrying the
  terminal experiment's revision.
- **Successor creation.** The clock is read only by the first path that needs an
  instant, at most once per attempt, so the identical-replay path reads it zero times.
  Order: the decision (absent is the repository's invariant violation; a foreign
  ``experiment_id`` or a ``DENIED`` outcome is ``CORE.INVARIANT_VIOLATION``); the
  reserved attempt number's existing row -- identical material (same predecessor and
  ``request_hash``) replays with ``attempt_token`` ``MISSING``, drawing nothing and
  writing nothing, and this precedes the terminal-experiment rule so an existing
  successor replays even after cancellation; divergent material is
  ``PERSISTENCE.CONCURRENCY_CONFLICT`` (plan 5 step 3, plan 8.6 "divergent create",
  specification 29.6 -- plan 8.5 step 2's "return it unchanged" is read as the identical
  case); the experiment must be ``RUNNING`` independently of revision agreement; the
  stored ``retry_not_before_utc`` must have arrived (``>=``; never recomputed) else
  ``RETRY.NOT_BEFORE_NOT_REACHED`` with both instants in its detail; the expected
  revision, the predecessor's identity and state against the decision, the
  latest-attempt relationship and the spec slot's adapter and engine are re-checked;
  identity is drawn only after every check. The successor is attempt
  ``reserved_successor_attempt_number`` at ``PENDING``, revision 0, with
  ``predecessor_run_id``, ``retry_reason`` (``retry_terminal_state_of`` the decision's
  terminal state), the caller's ``request_hash`` and the predecessor's adapter and
  engine; the insert and the state-preserving experiment bump commit together or not at
  all. The decision row is never mutated. The return shape is
  ``run_service.AttemptCreation`` (the attempt being the successor).
- ``successor_is_due``, ``build_retry_evaluation_snapshot`` and the two traversal bounds
  ``MAX_CAUSAL_CLOSURE_DEPTH`` and ``MAX_CAUSAL_CLOSURE_NODES`` are exported beside the
  plan's four produced names: the predicate is the pure eligibility rule the task prompt
  permits (specification 7.2 fixes the ``>=``), the assembler is the plan's named one.
  The primary-diagnostic and observation ``get`` reads follow the same rule as the walk:
  a reader fault outside the invariant vocabulary passes through unchanged.

Absence is ``MISSING``, never ``None`` (plan section 3.1).
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Final

from pydantic import ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.domain.diagnostics import Diagnostic, DiagnosticDetailValue
from crypto_lab.domain.engine_run import (
    NON_SUCCESS_TERMINAL_ENGINE_RUN_STATES,
    AttemptTokenMaterial,
    EngineRunRecord,
)
from crypto_lab.domain.experiment import ExperimentRecord, SelectedEngineSlot
from crypto_lab.domain.hashing import attempt_token_hash
from crypto_lab.domain.identifiers import DiagnosticId
from crypto_lab.domain.lifecycle import (
    TERMINAL_EXPERIMENT_STATES,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.ports import Clock, IdentitySource
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.domain.retry import (
    FAIL_CLOSED_CAUSAL_CLOSURE,
    MAX_CAUSAL_CLOSURE_ENTRIES,
    CausalClosureEntry,
    RetryDecisionOutcome,
    RetryDecisionRecord,
    RetryEvaluationSnapshot,
    canonical_causal_closure,
    evaluate_retry_gates,
    retry_decision_semantic_projection,
    retry_terminal_state_of,
    select_fresh_availability_observation,
)
from crypto_lab.domain.time import format_utc, require_utc
from crypto_lab.experiments.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
    RETRY_DECISION_CONFLICT,
    RETRY_NOT_BEFORE_NOT_REACHED,
    stage5_failure,
)
from crypto_lab.experiments.experiment_service import (
    LostSwap,
    Outcome,
    run_operation,
)
from crypto_lab.experiments.ports import DiagnosticReader, UnitOfWork
from crypto_lab.experiments.requests import (
    RetryEvaluationRequest,
    SuccessorCreationRequest,
)
from crypto_lab.experiments.run_service import AttemptCreation

SOURCE_COMPONENT: Final = "experiments.retry"
#: Plan section 8.2: the traversal's depth bound; the primary is depth 0.
MAX_CAUSAL_CLOSURE_DEPTH: Final = 32
#: Plan section 8.2: the traversal's node bound, the primary included; equal to the
#: snapshot's entry bound because each node yields at most one pair.
MAX_CAUSAL_CLOSURE_NODES: Final = MAX_CAUSAL_CLOSURE_ENTRIES

_CAUSE_CYCLE: Final = "cycle"
_CAUSE_MISSING_REFERENCE: Final = "missing_reference"
_CAUSE_DEPTH_BOUND: Final = "depth_bound"
_CAUSE_NODE_BOUND: Final = "node_bound"
_R: Final = EngineRunState


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
    experiment_id: str | MISSING = MISSING,  # type: ignore[valid-type]
    run_id: str | MISSING = MISSING,  # type: ignore[valid-type]
    details: Mapping[str, DiagnosticDetailValue] | None = None,
) -> Failure:
    return stage5_failure(
        code,
        message,
        source_component=SOURCE_COMPONENT,
        timestamp_utc=now,
        experiment_id=experiment_id,
        run_id=run_id,
        details=details,
    )


def _all_invariant(failure: Failure) -> bool:
    """Is every diagnostic of ``failure`` the repository's
    ``CORE.INVARIANT_VIOLATION``?"""
    return all(
        diagnostic.error_code == INVARIANT_VIOLATION
        for diagnostic in failure.diagnostics
    )


def _bumped(experiment: ExperimentRecord, *, now: datetime) -> ExperimentRecord:
    """Plan 9.1: the state-preserving revision bump committed by the ALLOWED and
    successor paths."""
    payload = experiment.model_dump(mode="python")
    payload["updated_at_utc"] = now
    payload["revision"] = experiment.revision + 1
    return ExperimentRecord.model_validate(payload)


def _stale_experiment(
    experiment: ExperimentRecord,
    expected_revision: int,
    *,
    now: datetime,
    run_id: str,
) -> Failure:
    return _failure(
        CONCURRENCY_CONFLICT,
        f"experiment {experiment.experiment_id} is at revision {experiment.revision}, "
        f"not {expected_revision}",
        now=now,
        experiment_id=experiment.experiment_id,
        run_id=run_id,
        details={
            "expected_revision": expected_revision,
            "stored_revision": experiment.revision,
        },
    )


def _not_latest(
    predecessor: EngineRunRecord, latest_run_id: str, *, now: datetime
) -> Failure:
    return _failure(
        CONCURRENCY_CONFLICT,
        f"run {predecessor.run_id} is no longer the current attempt of slot "
        f"{predecessor.logical_slot_id}; the latest attempt is {latest_run_id}",
        now=now,
        experiment_id=predecessor.experiment_id,
        run_id=predecessor.run_id,
        details={"latest_attempt_run_id": latest_run_id},
    )


def _selected_slot(
    experiment: ExperimentRecord, logical_slot_id: str
) -> SelectedEngineSlot | None:
    for slot in experiment.spec.selected_engine_slots:
        if slot.logical_slot_id == logical_slot_id:
            return slot
    return None


# --------------------------------------------------------------------------
# resolve_causal_closure (plan 8.2): the single traversal owner
# --------------------------------------------------------------------------


def _has_cycle(nodes: Mapping[str, Diagnostic]) -> bool:
    """Kahn's algorithm over the collected graph: does any node never become ready?"""
    indegree = dict.fromkeys(nodes, 0)
    for diagnostic in nodes.values():
        for child in diagnostic.causal_diagnostic_ids:
            indegree[child] += 1
    ready = deque(sorted(node for node, count in indegree.items() if count == 0))
    processed = 0
    while ready:
        node = ready.popleft()
        processed += 1
        for child in nodes[node].causal_diagnostic_ids:
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
    return processed != len(nodes)


def _entries(diagnostics: Iterable[Diagnostic]) -> tuple[CausalClosureEntry, ...]:
    return canonical_causal_closure(
        CausalClosureEntry(
            category=diagnostic.category, error_code=diagnostic.error_code
        )
        for diagnostic in diagnostics
    )


def resolve_causal_closure(
    reader: DiagnosticReader,
    primary_id: DiagnosticId,
    *,
    now: datetime,
) -> Result[tuple[CausalClosureEntry, ...]]:
    """Plan section 8.2: the paired causal closure of one primary terminal diagnostic.

    Breadth-first over ``causal_diagnostic_ids`` through ``reader.get_many`` alone, one
    call per level with sorted unique identifiers and a visited set; the primary is
    depth 0. Returns ``Failure`` carrying ``CORE.INVARIANT_VIOLATION`` -- with the cause
    named in its details -- when a level beyond depth 32 would be fetched
    (``depth_bound``, checked first), when the distinct nodes would exceed 256
    (``node_bound``), when the reader reports a missing or degenerate read
    (``missing_reference``), or when the collected graph is not acyclic (``cycle``); any
    other reader ``Failure`` is returned unchanged. On success the value is
    ``canonical_causal_closure`` over every collected diagnostic, the primary included.
    ``now`` stamps the failure diagnostic only.
    """

    def degenerate(cause: str, message: str) -> Failure:
        return _failure(
            INVARIANT_VIOLATION,
            message,
            now=now,
            details={"primary_terminal_diagnostic_id": primary_id, "cause": cause},
        )

    collected: dict[str, Diagnostic] = {}
    frontier: list[str] = [primary_id]
    depth = 0
    while frontier:
        if depth > MAX_CAUSAL_CLOSURE_DEPTH:
            return degenerate(
                _CAUSE_DEPTH_BOUND,
                f"the causal closure of {primary_id} exceeds the depth bound of "
                f"{MAX_CAUSAL_CLOSURE_DEPTH}",
            )
        if len(collected) + len(frontier) > MAX_CAUSAL_CLOSURE_NODES:
            return degenerate(
                _CAUSE_NODE_BOUND,
                f"the causal closure of {primary_id} exceeds the node bound of "
                f"{MAX_CAUSAL_CLOSURE_NODES}",
            )
        fetched = reader.get_many(tuple(frontier))
        if isinstance(fetched, Failure):
            if _all_invariant(fetched):
                return degenerate(
                    _CAUSE_MISSING_REFERENCE,
                    f"the causal closure of {primary_id} references a diagnostic "
                    "the reader cannot resolve",
                )
            return fetched
        discovered: set[str] = set()
        for diagnostic in fetched.value:
            collected[diagnostic.diagnostic_id] = diagnostic
            discovered.update(diagnostic.causal_diagnostic_ids)
        frontier = sorted(node for node in discovered if node not in collected)
        depth += 1
    if _has_cycle(collected):
        return degenerate(
            _CAUSE_CYCLE,
            f"the causal closure of {primary_id} contains a cycle",
        )
    return Success[tuple[CausalClosureEntry, ...]](
        outcome="SUCCESS", value=_entries(collected.values())
    )


# --------------------------------------------------------------------------
# build_retry_evaluation_snapshot (plan 8.2, 10.1): the authoritative read set
# --------------------------------------------------------------------------


def build_retry_evaluation_snapshot(
    transaction: UnitOfWork,
    experiment: ExperimentRecord,
    predecessor: EngineRunRecord,
    *,
    now: datetime,
) -> RetryEvaluationSnapshot | Failure:
    """Assemble the six gates' snapshot from repository reads and ``now`` alone.

    Reads the persisted attempt count, the predecessor's primary terminal diagnostic
    (a missing one aborts with ``CORE.INVARIANT_VIOLATION``), its causal closure through
    ``resolve_causal_closure`` (a degenerate closure is replaced by
    ``FAIL_CLOSED_CAUSAL_CLOSURE``; a passed-through reader fault aborts), and for an
    ``UNAVAILABLE`` predecessor its referenced observation plus the qualifying selection
    over ``list_for_adapter``. ``predecessor_terminal_completed_at_utc`` is the terminal
    record's ``updated_at_utc`` (plan 3.8). The caller has already applied plan 8.3's
    preconditions; a snapshot the committed shape rejects is
    ``CORE.INVARIANT_VIOLATION``.
    """
    experiment_id = experiment.experiment_id
    run_id = predecessor.run_id
    counted = transaction.engine_runs.count_attempts(
        experiment_id, predecessor.logical_slot_id
    )
    if isinstance(counted, Failure):
        return counted
    primary_id = predecessor.primary_terminal_diagnostic_id
    loaded = transaction.diagnostics.get(primary_id)
    if isinstance(loaded, Failure):
        if not _all_invariant(loaded):
            return loaded
        return _failure(
            INVARIANT_VIOLATION,
            f"the primary terminal diagnostic {primary_id} of run {run_id} does not "
            "exist",
            now=now,
            experiment_id=experiment_id,
            run_id=run_id,
            details={"primary_terminal_diagnostic_id": primary_id},
        )
    resolved = resolve_causal_closure(transaction.diagnostics, primary_id, now=now)
    if isinstance(resolved, Failure):
        if not _all_invariant(resolved):
            return resolved
        closure = FAIL_CLOSED_CAUSAL_CLOSURE
    else:
        closure = resolved.value
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "experiment_id": experiment_id,
        "logical_slot_id": predecessor.logical_slot_id,
        "predecessor_run_id": run_id,
        "experiment_spec_hash": experiment.spec_hash,
        "retry_policy": experiment.spec.retry_policy,
        "experiment_state": experiment.state,
        "created_attempt_count": counted.value,
        "predecessor_terminal_state": predecessor.state,
        "predecessor_terminal_completed_at_utc": predecessor.updated_at_utc,
        "primary_terminal_diagnostic": loaded.value,
        "causal_closure": closure,
        "candidate_availability_observations": (),
        "evaluated_at_utc": now,
    }
    if predecessor.state is _R.UNAVAILABLE:
        observation_id = predecessor.availability_observation_id
        observed = transaction.availability_observations.get(observation_id)
        if isinstance(observed, Failure):
            if not _all_invariant(observed):
                return observed
            return _failure(
                INVARIANT_VIOLATION,
                f"the availability observation {observation_id} referenced by run "
                f"{run_id} does not exist",
                now=now,
                experiment_id=experiment_id,
                run_id=run_id,
                details={"availability_observation_id": observation_id},
            )
        referenced = observed.value
        listed = transaction.availability_observations.list_for_adapter(
            referenced.adapter_name,
            referenced.adapter_version,
            referenced.executable_hash,
        )
        if isinstance(listed, Failure):
            return listed
        selected = select_fresh_availability_observation(
            referenced,
            listed.value,
            terminal_completed_at_utc=predecessor.updated_at_utc,
            evaluated_at_utc=now,
        )
        payload["predecessor_availability_observation"] = referenced
        payload["candidate_availability_observations"] = (
            () if _is_missing(selected) else (selected,)
        )
    try:
        return RetryEvaluationSnapshot.model_validate(payload)
    except ValidationError as error:
        return _failure(
            INVARIANT_VIOLATION,
            f"the authoritative reads for run {run_id} do not form a valid retry "
            f"evaluation snapshot: {error}",
            now=now,
            experiment_id=experiment_id,
            run_id=run_id,
        )


# --------------------------------------------------------------------------
# evaluate_retry (plan 8.3, 8.4, 9.1, 10.1)
# --------------------------------------------------------------------------


def evaluate_retry(
    request: RetryEvaluationRequest,
    *,
    unit_of_work: UnitOfWork,
    clock: Clock,
) -> Result[RetryDecisionRecord]:
    """Plan 8.4: replay the stored decision, or evaluate, insert and reconcile one.

    Phase 1 returns an existing row for the predecessor unchanged with no clock read and
    no other read. Phase 2 reads the clock once, applies plan 8.3's preconditions and
    builds the one complete ``ALLOWED`` or ``DENIED`` candidate through the Task 5
    kernel.
    Phase 3 compare-and-swaps the experiment first for ``ALLOWED`` (a lost swap reloads
    once), inserts the candidate atomically, and reconciles a same-key winner by
    semantic projection: equal returns the winner, divergent is
    ``RETRY.DECISION_CONFLICT``. Nothing partial survives.
    """

    def once(transaction: UnitOfWork) -> Outcome[RetryDecisionRecord]:
        # Phase 1 -- existing-row replay (plan 8.4).
        existing = transaction.retry_decisions.get_by_predecessor(
            request.logical_slot_id, request.predecessor_run_id
        )
        if isinstance(existing, Success):
            stored = existing.value
            if stored.experiment_id == request.experiment_id:
                return existing
            return _failure(
                INVARIANT_VIOLATION,
                f"the stored retry decision for predecessor "
                f"{request.predecessor_run_id} belongs to experiment "
                f"{stored.experiment_id}, not {request.experiment_id}",
                now=clock.now_utc(),
                experiment_id=request.experiment_id,
                run_id=request.predecessor_run_id,
                details={"stored_experiment_id": stored.experiment_id},
            )
        # Phase 2 -- fresh candidate construction (plan 8.3, 8.4).
        now = clock.now_utc()
        loaded_experiment = transaction.experiments.get(request.experiment_id)
        if isinstance(loaded_experiment, Failure):
            return loaded_experiment
        experiment = loaded_experiment.value
        loaded_run = transaction.engine_runs.get(request.predecessor_run_id)
        if isinstance(loaded_run, Failure):
            return loaded_run
        predecessor = loaded_run.value
        if (
            predecessor.experiment_id != request.experiment_id
            or predecessor.logical_slot_id != request.logical_slot_id
        ):
            return _failure(
                INVARIANT_VIOLATION,
                f"run {predecessor.run_id} belongs to experiment "
                f"{predecessor.experiment_id} slot {predecessor.logical_slot_id}, not "
                f"to the requested experiment and slot",
                now=now,
                experiment_id=request.experiment_id,
                run_id=predecessor.run_id,
            )
        if predecessor.state not in NON_SUCCESS_TERMINAL_ENGINE_RUN_STATES:
            return _failure(
                INVARIANT_VIOLATION,
                f"run {predecessor.run_id} is {predecessor.state.value}; only a "
                "non-success terminal attempt is a retry predecessor",
                now=now,
                experiment_id=experiment.experiment_id,
                run_id=predecessor.run_id,
                details={"predecessor_state": predecessor.state.value},
            )
        if (
            experiment.state is not ExperimentState.RUNNING
            and experiment.state not in TERMINAL_EXPERIMENT_STATES
        ):
            return _failure(
                INVARIANT_VIOLATION,
                f"experiment {experiment.experiment_id} is {experiment.state.value}; a "
                "terminal attempt exists only once the experiment has run",
                now=now,
                experiment_id=experiment.experiment_id,
                run_id=predecessor.run_id,
                details={"experiment_state": experiment.state.value},
            )
        if request.expected_experiment_revision != experiment.revision:
            return _stale_experiment(
                experiment,
                request.expected_experiment_revision,
                now=now,
                run_id=predecessor.run_id,
            )
        if request.expected_predecessor_revision != predecessor.revision:
            return _failure(
                CONCURRENCY_CONFLICT,
                f"run {predecessor.run_id} is at revision {predecessor.revision}, "
                f"not {request.expected_predecessor_revision}",
                now=now,
                experiment_id=experiment.experiment_id,
                run_id=predecessor.run_id,
                details={
                    "expected_revision": request.expected_predecessor_revision,
                    "stored_revision": predecessor.revision,
                },
            )
        latest = transaction.engine_runs.latest_attempt(
            experiment.experiment_id, predecessor.logical_slot_id
        )
        if isinstance(latest, Failure):
            return latest
        if _is_missing(latest.value):
            return _failure(
                INVARIANT_VIOLATION,
                f"slot {predecessor.logical_slot_id} has a stored attempt but no "
                "latest attempt",
                now=now,
                experiment_id=experiment.experiment_id,
                run_id=predecessor.run_id,
            )
        if latest.value.run_id != predecessor.run_id:
            return _not_latest(predecessor, latest.value.run_id, now=now)
        snapshot = build_retry_evaluation_snapshot(
            transaction, experiment, predecessor, now=now
        )
        if isinstance(snapshot, Failure):
            return snapshot
        candidate = evaluate_retry_gates(snapshot)
        # Phase 3 -- the experiment swap first for ALLOWED, then the atomic insert and
        # the reconciliation of a same-key winner (plan 8.4, 9.1).
        if candidate.outcome is RetryDecisionOutcome.ALLOWED:
            swapped = transaction.experiments.compare_and_swap(
                experiment.revision, _bumped(experiment, now=now)
            )
            if isinstance(swapped, Failure):
                return LostSwap(swapped)
        inserted = transaction.retry_decisions.insert_if_absent(candidate)
        if isinstance(inserted, Failure):
            return LostSwap(inserted)
        if inserted.value.inserted:
            return Success[RetryDecisionRecord](outcome="SUCCESS", value=candidate)
        winner = inserted.value.record
        if winner.experiment_id != request.experiment_id:
            return _failure(
                INVARIANT_VIOLATION,
                f"the retry decision for predecessor {request.predecessor_run_id} "
                f"belongs to experiment {winner.experiment_id}, not "
                f"{request.experiment_id}",
                now=now,
                experiment_id=request.experiment_id,
                run_id=request.predecessor_run_id,
                details={"stored_experiment_id": winner.experiment_id},
            )
        if retry_decision_semantic_projection(
            winner
        ) == retry_decision_semantic_projection(candidate):
            return Success[RetryDecisionRecord](outcome="SUCCESS", value=winner)
        return _failure(
            RETRY_DECISION_CONFLICT,
            f"a concurrent retry decision for predecessor {request.predecessor_run_id} "
            "diverges semantically from this evaluation",
            now=now,
            experiment_id=request.experiment_id,
            run_id=request.predecessor_run_id,
            details={"predecessor_run_id": request.predecessor_run_id},
        )

    return run_operation(unit_of_work, once)


# --------------------------------------------------------------------------
# successor_is_due and create_successor (plan 8.5, 9.1, 9.5 rows 3-4; spec 7.2)
# --------------------------------------------------------------------------


def successor_is_due(decision: RetryDecisionRecord, *, now: datetime) -> bool:
    """Specification 7.2: is the reserved successor queue-eligible at ``now``?

    True exactly when the decision is ``ALLOWED`` and ``now`` is at or after its stored
    ``retry_not_before_utc``; a ``DENIED`` decision is never due. Pure over its
    arguments; ``now`` must be UTC. Restart compares the same stored instant.
    """
    instant = require_utc(now)
    if decision.outcome is not RetryDecisionOutcome.ALLOWED:
        return False
    return instant >= decision.retry_not_before_utc


def create_successor(
    request: SuccessorCreationRequest,
    *,
    unit_of_work: UnitOfWork,
    clock: Clock,
    identity_source: IdentitySource,
) -> Result[AttemptCreation]:
    """Plan 8.5 steps 1-6: create the reserved successor once, or replay it.

    Requires an ``ALLOWED`` decision, returns an existing successor at the reserved
    number unchanged (identical material) or conflicts (divergent material), requires
    the experiment to be ``RUNNING`` and the stored ``retry_not_before_utc`` to have
    arrived, re-checks the revision and the latest-attempt relationship, draws the run
    identifier and token only then, and inserts the successor together with the
    state-preserving experiment bump. A lost swap reloads once through the driver.
    """

    def once(transaction: UnitOfWork) -> Outcome[AttemptCreation]:
        loaded_decision = transaction.retry_decisions.get_by_predecessor(
            request.logical_slot_id, request.predecessor_run_id
        )
        if isinstance(loaded_decision, Failure):
            return loaded_decision
        decision = loaded_decision.value
        if decision.experiment_id != request.experiment_id:
            return _failure(
                INVARIANT_VIOLATION,
                f"the retry decision for predecessor {request.predecessor_run_id} "
                f"belongs to experiment {decision.experiment_id}, not "
                f"{request.experiment_id}",
                now=clock.now_utc(),
                experiment_id=request.experiment_id,
                run_id=request.predecessor_run_id,
                details={"stored_experiment_id": decision.experiment_id},
            )
        if decision.outcome is not RetryDecisionOutcome.ALLOWED:
            return _failure(
                INVARIANT_VIOLATION,
                f"the retry decision for predecessor {request.predecessor_run_id} is "
                "DENIED and reserves no successor",
                now=clock.now_utc(),
                experiment_id=request.experiment_id,
                run_id=request.predecessor_run_id,
            )
        reserved = decision.reserved_successor_attempt_number
        existing = transaction.engine_runs.get_by_attempt_number(
            request.experiment_id, request.logical_slot_id, reserved
        )
        if isinstance(existing, Failure):
            return existing
        loaded_experiment = transaction.experiments.get(request.experiment_id)
        if isinstance(loaded_experiment, Failure):
            return loaded_experiment
        experiment = loaded_experiment.value
        if not _is_missing(existing.value):
            stored_successor: EngineRunRecord = existing.value
            if (
                stored_successor.predecessor_run_id == request.predecessor_run_id
                and stored_successor.request_hash == request.request_hash
            ):
                return Success[AttemptCreation](
                    outcome="SUCCESS",
                    value=AttemptCreation(
                        experiment=experiment, attempt=stored_successor
                    ),
                )
            return _failure(
                CONCURRENCY_CONFLICT,
                f"attempt {reserved} of slot {request.logical_slot_id} already exists "
                f"as {stored_successor.run_id} with different material",
                now=clock.now_utc(),
                experiment_id=request.experiment_id,
                run_id=stored_successor.run_id,
                details={"existing_run_id": stored_successor.run_id},
            )
        if experiment.state is not ExperimentState.RUNNING:
            return _failure(
                INVARIANT_VIOLATION,
                f"experiment {experiment.experiment_id} is {experiment.state.value}; a "
                "successor is created only while it is RUNNING",
                now=clock.now_utc(),
                experiment_id=experiment.experiment_id,
                run_id=request.predecessor_run_id,
                details={"experiment_state": experiment.state.value},
            )
        now = clock.now_utc()
        if not successor_is_due(decision, now=now):
            return _failure(
                RETRY_NOT_BEFORE_NOT_REACHED,
                f"the durable retry delay for predecessor {request.predecessor_run_id} "
                "has not elapsed: not before "
                f"{format_utc(decision.retry_not_before_utc)}",
                now=now,
                experiment_id=experiment.experiment_id,
                run_id=request.predecessor_run_id,
                details={
                    "retry_not_before_utc": format_utc(decision.retry_not_before_utc),
                    "now_utc": format_utc(now),
                },
            )
        if request.expected_experiment_revision != experiment.revision:
            return _stale_experiment(
                experiment,
                request.expected_experiment_revision,
                now=now,
                run_id=request.predecessor_run_id,
            )
        loaded_run = transaction.engine_runs.get(request.predecessor_run_id)
        if isinstance(loaded_run, Failure):
            return loaded_run
        predecessor = loaded_run.value
        if (
            predecessor.experiment_id != request.experiment_id
            or predecessor.logical_slot_id != request.logical_slot_id
        ):
            return _failure(
                INVARIANT_VIOLATION,
                f"run {predecessor.run_id} belongs to experiment "
                f"{predecessor.experiment_id} slot {predecessor.logical_slot_id}, not "
                "to the requested experiment and slot",
                now=now,
                experiment_id=request.experiment_id,
                run_id=predecessor.run_id,
            )
        if predecessor.state is not decision.predecessor_terminal_state:
            return _failure(
                INVARIANT_VIOLATION,
                f"run {predecessor.run_id} is {predecessor.state.value} but its retry "
                f"decision records {decision.predecessor_terminal_state.value}",
                now=now,
                experiment_id=experiment.experiment_id,
                run_id=predecessor.run_id,
            )
        latest = transaction.engine_runs.latest_attempt(
            experiment.experiment_id, predecessor.logical_slot_id
        )
        if isinstance(latest, Failure):
            return latest
        if _is_missing(latest.value):
            return _failure(
                INVARIANT_VIOLATION,
                f"slot {predecessor.logical_slot_id} has a stored attempt but no "
                "latest attempt",
                now=now,
                experiment_id=experiment.experiment_id,
                run_id=predecessor.run_id,
            )
        if latest.value.run_id != predecessor.run_id:
            return _not_latest(predecessor, latest.value.run_id, now=now)
        slot = _selected_slot(experiment, predecessor.logical_slot_id)
        if slot is None:
            return _failure(
                INVARIANT_VIOLATION,
                f"slot {predecessor.logical_slot_id} is not a selected slot of "
                f"experiment {experiment.experiment_id}",
                now=now,
                experiment_id=experiment.experiment_id,
                run_id=predecessor.run_id,
            )
        if slot.adapter != predecessor.adapter or slot.engine != predecessor.engine:
            return _failure(
                INVARIANT_VIOLATION,
                f"run {predecessor.run_id} names an adapter or engine that differs "
                f"from selected slot {slot.logical_slot_id}",
                now=now,
                experiment_id=experiment.experiment_id,
                run_id=predecessor.run_id,
            )
        retry_reason = retry_terminal_state_of(decision.predecessor_terminal_state)
        if _is_missing(retry_reason):  # pragma: no cover - an ALLOWED record's
            # terminal state always maps (RetryDecisionRecord gate 2 consistency).
            return _failure(
                INVARIANT_VIOLATION,
                f"terminal state {decision.predecessor_terminal_state.value} maps to "
                "no retry reason",
                now=now,
                experiment_id=experiment.experiment_id,
                run_id=predecessor.run_id,
            )
        run_id = identity_source.new_run_id()
        token = identity_source.new_attempt_token()
        successor = EngineRunRecord(
            schema_version="1.0.0",
            run_id=run_id,
            experiment_id=experiment.experiment_id,
            logical_slot_id=predecessor.logical_slot_id,
            attempt_number=reserved,
            attempt_token_hash=attempt_token_hash(token),
            state=_R.PENDING,
            adapter=predecessor.adapter,
            engine=predecessor.engine,
            request_hash=request.request_hash,
            predecessor_run_id=predecessor.run_id,
            retry_reason=retry_reason,
            created_at_utc=now,
            updated_at_utc=now,
            revision=0,
        )
        added = transaction.engine_runs.add_attempt(successor)
        if isinstance(added, Failure):
            return LostSwap(added)
        swapped = transaction.experiments.compare_and_swap(
            experiment.revision, _bumped(experiment, now=now)
        )
        if isinstance(swapped, Failure):
            return LostSwap(swapped)
        return Success[AttemptCreation](
            outcome="SUCCESS",
            value=AttemptCreation(
                experiment=swapped.value,
                attempt=successor,
                attempt_token=AttemptTokenMaterial(run_id=run_id, attempt_token=token),
            ),
        )

    return run_operation(unit_of_work, once)
