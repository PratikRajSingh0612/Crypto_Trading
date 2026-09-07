"""The immutable retry policy, the six retry gates and the immutable retry decision.

Stage 5 plan sections 3.4, 3.9, 8.1, 8.2 and 8.4, under specification sections
7.2, 11.3, 11.5, 16.3, 17.2.1, 21.2, 21.2.1 and 22.2.1. ``RetryPolicy`` lives in
``domain`` so that ``configuration`` can project onto it while keeping its single
inward dependency on ``domain`` (plan section 2.3); the sole projection is
``crypto_lab.configuration.retry_policy.retry_policy_from_config``.

Every ``RetryPolicy`` field is required. Specification section 11.5 says the policy
"has no optional fields" and that its terminal-state collection "is an explicit
empty array when no states are automatically retried". The configuration defaults
of section 22.2.1 -- one attempt, no automatic states, no delay -- belong to
``RetryConfig`` and reach a policy only through the projection, which is what lets
Task 9's generated ``retry-policy-v1`` schema publish all five names as
``required``. ``automatically_retry_terminal_states`` follows the rule the merged
``RetryConfig`` already applies: duplicate and foreign values are rejected, and
accepted members are normalized to the fixed order ``FAILED``, ``TIMED_OUT``,
``UNAVAILABLE`` before hashing (specification 11.5), so a permutation never
changes an experiment's identity. The normalizer is re-expressed here rather than
imported, because ``domain`` may not import ``configuration``.

The retry decision (Task 5) is the pure kernel of plan section 8.4 phase 2. The
application service in ``experiments`` (Task 7) performs the three-phase flow --
existing-row replay, fresh candidate construction, concurrent-insert
reconciliation -- reads the repositories and the injected clock exactly once,
assembles ``RetryEvaluationSnapshot`` from those authoritative reads, and calls
``evaluate_retry_gates`` to obtain the one complete immutable ``ALLOWED`` or
``DENIED`` candidate. Nothing here reads a repository, a clock or the environment,
launches anything, or traverses a diagnostic graph.

Five kinds of rule live here.

1. **The hard-blocking partition** -- ``HARD_BLOCKING_DIAGNOSTIC_CATEGORIES`` and
   ``RETRY_PERMITTING_DIAGNOSTIC_CATEGORIES`` (plan 8.2, specification 21.2): a
   closed partition of the twelve ``DiagnosticCategory`` members, asserted
   disjoint and total so a future category cannot arrive unclassified.
2. **The retry terminal-state mapping** -- ``retry_terminal_state_of``: total over
   all twelve ``EngineRunState`` members; ``FAILED``, ``TIMED_OUT`` and
   ``UNAVAILABLE`` map by name and every other member, terminal or not, maps to
   ``MISSING``, which is what gate 2 and plan 9.2's ``NO_DECISION_REQUIRED`` read.
3. **The paired causal closure** -- ``CausalClosureEntry``,
   ``canonical_causal_closure`` and ``hard_block_error_code``: the closure is a
   tuple of whole ``(category, error_code)`` pairs, deduplicated as pairs and
   sorted by ``(category, error_code)``; category and code are never carried as two
   independent tuples, because independent sorting destroys their correspondence.
   The recorded hard-block code is read from the first hard-blocking entry of the
   sorted closure, category and code from that same entry. Traversal is **not**
   implemented here: plan 8.2 makes Task 7's ``resolve_causal_closure`` the single
   owner of the walk; this module consumes the finished closure, and
   ``canonical_causal_closure`` is the ordering helper that walk calls.
   ``FAIL_CLOSED_CAUSAL_CLOSURE`` is the single entry that helper's ``Failure``
   substitutes, so gate 4 fails and a durable ``DENIED`` row is still persisted.
4. **The snapshot and the gates** -- ``RetryEvaluationSnapshot``,
   ``select_fresh_availability_observation``, ``failed_retry_gates``,
   ``recorded_denial_reason`` and ``evaluate_retry_gates``: the six gates of plan
   8.2 are ANDed, so the outcome is order-independent, while the recorded reason
   follows the fixed precedence ``4, 1, 2, 3, 6, 5`` (``RETRY_DENIAL_PRECEDENCE``),
   because a hard blocker is unconditional and permanent while a budget bound is
   incidental. The specification's conflicting-decision condition is not part of
   gate 5: plan 8.4 phases 1 and 3 handle it and it never produces a persisted
   denial.
5. **The record and its projection** -- ``RetryDecisionRecord`` and
   ``retry_decision_semantic_projection``: plan 3.9's sixteen fields in order,
   complete and immutable at insertion, identity ``(logical_slot_id,
   predecessor_run_id)``, no revision, no separate operational identifier and no
   successor pointer; the projection is canonical JSON over fields 1-15, so two
   candidates built from the same authoritative facts at different instants agree
   and only a divergent projection is a decision conflict.

Where the plan is silent, these task-local readings are applied and declared here
rather than inferred silently:

- ``RetryEvaluationSnapshot`` is a top-level model with the envelope
  ``schema_version`` (plan 3.1). Its fields are the authoritative inputs the gates
  name: the record identities (plan 3.9 fields 2-5, all repository reads), the
  policy, the experiment's lifecycle state (gate 5), the persisted attempt count
  from ``count_attempts`` (gate 1), the predecessor's terminal state (gate 2) and
  its ``updated_at_utc`` -- the authoritative terminal completion instant of plan
  3.8, carried as ``predecessor_terminal_completed_at_utc`` and never sourced from
  a diagnostic or observation instant -- the whole primary terminal ``Diagnostic``
  (gate 3 reads ``retriable``; field 9 of the record is its identifier), the
  closure (gate 4), the predecessor's referenced availability observation and the
  candidate observations from ``list_for_adapter`` (gate 6), and
  ``evaluated_at_utc``, the single clock instant plan 8.4 phase 2 reads, which is
  the instant gate 6 compares ``expires_at_utc`` against and becomes the record's
  ``decided_at_utc``. No field lets a caller choose an outcome, denial material, a
  delay, a reservation or a freshness conclusion (plan 3.11).
- The experiment state must be ``RUNNING`` or terminal: attempts exist only from
  ``RUNNING`` onward (plan 5), so a terminal predecessor under ``DRAFT``,
  ``VALIDATED`` or ``QUEUED`` is an impossible aggregate state.
- When the primary diagnostic carries ``run_id`` or ``experiment_id``, each must
  equal the snapshot's; an uncorrelated diagnostic is accepted.
- The closure must contain the primary diagnostic's own pair -- plan 8.2 defines
  it as "the primary terminal diagnostic and every diagnostic in its causal
  closure" -- unless it is exactly ``FAIL_CLOSED_CAUSAL_CLOSURE``.
- Observation material is present exactly for an ``UNAVAILABLE`` predecessor: the
  predecessor's observation is required there and prohibited elsewhere, and the
  candidate tuple must be empty elsewhere; an ``UNAVAILABLE`` predecessor may have
  no candidate at all, in which case gate 6 fails. Candidates are unique by
  identifier and sorted by identifier, because their order is not semantic.
- Gate 6 identity is exactly the three ``list_for_adapter`` keys -- adapter name,
  adapter version and executable hash; the path, runtime version, operating system
  and the two requirement flags are deliberately not compared. Both temporal
  comparisons are strict. The selector filters rather than raises: a candidate
  that fails a condition is simply not qualifying. For a ``FAILED`` or
  ``TIMED_OUT`` predecessor gate 6 passes vacuously and records no observation.
- Gate 2 has two failure modes plan 8.2 distinguishes in prose -- the state maps
  to no ``RetryTerminalState`` (``CANCELLED``, ``NOT_APPLICABLE``) or it maps to a
  member the policy does not list -- and both record
  ``TERMINAL_STATE_NOT_RETRYABLE``.
- ``retry_not_before_utc`` is ``predecessor_terminal_completed_at_utc`` plus
  ``retry_delay_seconds`` and never a function of the clock instant; a sum beyond
  the representable ``datetime`` range is a ``ValueError``, not a silent wrap.
  Whether ``evaluated_at_utc`` is at or after the completion instant is not
  enforced: the plan does not require it and a restarted host clock could
  legitimately read earlier.
- ``RetryDecisionRecord``'s validator is a **necessary-condition filter, not a
  re-evaluation**. Beyond plan 3.9's presence rules it enforces the consistency
  the fixed precedence implies for the gates decidable from the record's own
  fields: gate 1 (``created_attempt_count`` against ``maximum_attempts_per_slot``),
  gate 2 (the terminal state against ``automatically_retry_terminal_states``) and
  gate 6's failure direction (only an ``UNAVAILABLE`` predecessor can be denied
  for freshness). An ``ALLOWED`` record must pass gates 1 and 2; a ``DENIED``
  record must pass every decidable gate that precedes its reason and must fail its
  own gate where that is decidable. Gates 3, 4 and 5 and gate 6's passing
  direction are never checked at the record level, because ``retriable``, the
  closure, the experiment state and the candidate observations are not record
  fields. ``ATTEMPT_BUDGET_EXHAUSTED`` is accepted for a count above as well as at
  the maximum, because gate 1 is a strict ``<``. These rules are runtime-only
  residuals the generated ``retry-decision-record-v1`` schema cannot express,
  alongside plan 3.9's own residual that field 8 publishes the full
  ``EngineRunState`` enum and the runtime narrows it.
- Beyond plan 12's produced list, ``RetryGate``, ``RETRY_DENIAL_PRECEDENCE``,
  ``denial_reason_for``, ``recorded_denial_reason``, ``failed_retry_gates``,
  ``select_fresh_availability_observation``, ``durable_retry_not_before``,
  ``canonical_causal_closure``, ``hard_block_error_code`` and
  ``FAIL_CLOSED_CAUSAL_CLOSURE`` are exported so that Task 7's service and its
  tests consume one definition of each rule rather than re-expressing it.

Absence is ``MISSING``, never ``None`` (plan section 3.1).
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Annotated, Final, Literal, Self

from pydantic import Field, field_validator, model_validator
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.descriptors import RuntimeAvailabilityObservation
from crypto_lab.domain.diagnostics import Diagnostic, DiagnosticCategory, ErrorCode
from crypto_lab.domain.identifiers import (
    AvailabilityObservationId,
    DiagnosticId,
    ExperimentId,
    LogicalSlotId,
    RunId,
    Sha256,
)
from crypto_lab.domain.lifecycle import (
    TERMINAL_ENGINE_RUN_STATES,
    TERMINAL_EXPERIMENT_STATES,
    EngineRunState,
    ExperimentState,
    RetryTerminalState,
)
from crypto_lab.domain.time import CalendarValidUtcDateTime, require_utc

MAX_ATTEMPTS_PER_SLOT: Final = 5
MAX_RETRY_DELAY_SECONDS: Final = 300
#: Plan section 8.2: the traversal's node bound; each node yields at most one pair.
MAX_CAUSAL_CLOSURE_ENTRIES: Final = 256
#: Task-local bound on the ``list_for_adapter`` read carried by the snapshot.
MAX_CANDIDATE_AVAILABILITY_OBSERVATIONS: Final = 256
_RETRY_ORDER: Final = tuple(RetryTerminalState)

_R: Final = EngineRunState
_D: Final = DiagnosticCategory
#: Local alias so the snapshot's observation fields fit the formatter's width.
_Observation = RuntimeAvailabilityObservation

#: Plan section 5 and 3.9: the five terminals that carry a primary terminal
#: diagnostic, the exact set plan 8.3 admits as a retry predecessor. Derived from
#: the Task 1 table exactly as Task 4 derives its constant; not imported from
#: ``engine_run`` because that module imports this one.
_NON_SUCCESS_TERMINAL_STATES: Final[frozenset[EngineRunState]] = (
    TERMINAL_ENGINE_RUN_STATES - {_R.SUCCEEDED, _R.SUCCEEDED_WITH_WARNINGS}
)

#: Plan section 8.2 and specification 21.2: the closed partition.
HARD_BLOCKING_DIAGNOSTIC_CATEGORIES: Final[frozenset[DiagnosticCategory]] = frozenset(
    {
        _D.USER_CONFIGURATION,
        _D.SCHEMA_VALIDATION,
        _D.COMPATIBILITY,
        _D.PROTOCOL,
        _D.CANCELLATION,
        _D.ARTIFACT_CORRUPTION,
        _D.INTERNAL_INVARIANT,
        _D.SECURITY,
    }
)
RETRY_PERMITTING_DIAGNOSTIC_CATEGORIES: Final[frozenset[DiagnosticCategory]] = (
    frozenset(
        {
            _D.ADAPTER_UNAVAILABILITY,
            _D.ENGINE_RUNTIME,
            _D.TIMEOUT,
            _D.PERSISTENCE,
        }
    )
)

#: Plan section 3.8 row 12 and 8.2 gate 2: the three states that map by name.
_RETRY_TERMINAL_STATE_OF: Final[dict[EngineRunState, RetryTerminalState]] = {
    _R.FAILED: RetryTerminalState.FAILED,
    _R.TIMED_OUT: RetryTerminalState.TIMED_OUT,
    _R.UNAVAILABLE: RetryTerminalState.UNAVAILABLE,
}


def _is_missing(value: object) -> bool:
    return value is MISSING


def _ordered_retry_terminal_states(value: object) -> tuple[RetryTerminalState, ...]:
    """Reject duplicates and foreign values; return the fixed canonical order."""
    if not isinstance(value, list | tuple):
        raise ValueError("retry states must be an array")
    if not all(isinstance(item, str | RetryTerminalState) for item in value):
        raise ValueError("retry states must be strings")
    try:
        items = tuple(RetryTerminalState(item) for item in value)
    except ValueError as error:
        raise ValueError("retry states contain a foreign value") from error
    if len(set(items)) != len(items):
        raise ValueError("retry states must be unique")
    return tuple(item for item in _RETRY_ORDER if item in items)


class RetryPolicy(CanonicalModel):
    """Specification section 11.3: the immutable bounded automatic-retry policy.

    ``maximum_attempts_per_slot`` counts the initial attempt and every successor
    already created for the slot, so the value ``1`` always disables automatic
    retry (specification 11.5). The fresh-availability requirement for an
    ``UNAVAILABLE`` predecessor is fixed ``true`` in Project 1.
    """

    schema_version: Literal["1.0.0"]
    maximum_attempts_per_slot: int = Field(ge=1, le=MAX_ATTEMPTS_PER_SLOT)
    automatically_retry_terminal_states: tuple[RetryTerminalState, ...] = Field(
        max_length=len(_RETRY_ORDER),
        # Pydantic emits no `uniqueItems` for a tuple; the runtime rule below
        # rejects duplicates, so the published schema must agree.
        json_schema_extra={"uniqueItems": True},
    )
    retry_delay_seconds: int = Field(ge=0, le=MAX_RETRY_DELAY_SECONDS)
    require_fresh_availability_observation_for_unavailable: Literal[True]

    @field_validator("automatically_retry_terminal_states", mode="before")
    @classmethod
    def normalize_retry_states(cls, value: object) -> tuple[RetryTerminalState, ...]:
        return _ordered_retry_terminal_states(value)


# --- Retry terminal-state mapping (plan sections 3.8 row 12, 8.2 gate 2, 9.2) ------


def retry_terminal_state_of(
    state: EngineRunState,
) -> RetryTerminalState | MISSING:  # type: ignore[valid-type]
    """Map an engine-run state onto the retry vocabulary, or ``MISSING``.

    Total over the twelve members: ``FAILED``, ``TIMED_OUT`` and ``UNAVAILABLE``
    map by name; every other member -- the two success terminals, ``CANCELLED``,
    ``NOT_APPLICABLE`` and the five non-terminal states -- has no retry terminal
    state. A foreign object raises ``TypeError``.
    """
    if type(state) is not EngineRunState:
        raise TypeError("state must be an EngineRunState member")
    return _RETRY_TERMINAL_STATE_OF.get(state, MISSING)


# --- Vocabularies and precedence (plan section 8.2) -----------------------------------


class RetryDecisionOutcome(StrEnum):
    """Plan section 3.9 field 10: the two persisted retry outcomes."""

    ALLOWED = "ALLOWED"
    DENIED = "DENIED"


class RetryDenialReason(StrEnum):
    """Plan section 8.2: one durable denial reason per gate, in gate order."""

    ATTEMPT_BUDGET_EXHAUSTED = "ATTEMPT_BUDGET_EXHAUSTED"
    TERMINAL_STATE_NOT_RETRYABLE = "TERMINAL_STATE_NOT_RETRYABLE"
    PRIMARY_DIAGNOSTIC_NOT_RETRIABLE = "PRIMARY_DIAGNOSTIC_NOT_RETRIABLE"
    HARD_BLOCKED_OUTCOME = "HARD_BLOCKED_OUTCOME"
    EXPERIMENT_TERMINAL = "EXPERIMENT_TERMINAL"
    AVAILABILITY_OBSERVATION_NOT_FRESH = "AVAILABILITY_OBSERVATION_NOT_FRESH"


class RetryGate(StrEnum):
    """Plan section 8.2: the six gates, declared in the plan's gate order 1..6."""

    ATTEMPT_BUDGET = "ATTEMPT_BUDGET"
    TERMINAL_STATE = "TERMINAL_STATE"
    PRIMARY_DIAGNOSTIC = "PRIMARY_DIAGNOSTIC"
    HARD_BLOCK = "HARD_BLOCK"
    EXPERIMENT_ACTIVE = "EXPERIMENT_ACTIVE"
    AVAILABILITY_FRESHNESS = "AVAILABILITY_FRESHNESS"


_G: Final = RetryGate
_N: Final = RetryDenialReason
_DENIAL_REASON_OF_GATE: Final[dict[RetryGate, RetryDenialReason]] = {
    _G.ATTEMPT_BUDGET: _N.ATTEMPT_BUDGET_EXHAUSTED,
    _G.TERMINAL_STATE: _N.TERMINAL_STATE_NOT_RETRYABLE,
    _G.PRIMARY_DIAGNOSTIC: _N.PRIMARY_DIAGNOSTIC_NOT_RETRIABLE,
    _G.HARD_BLOCK: _N.HARD_BLOCKED_OUTCOME,
    _G.EXPERIMENT_ACTIVE: _N.EXPERIMENT_TERMINAL,
    _G.AVAILABILITY_FRESHNESS: _N.AVAILABILITY_OBSERVATION_NOT_FRESH,
}
#: Plan section 8.2: the recorded reason is selected by the fixed precedence
#: ``4, 1, 2, 3, 6, 5``.
RETRY_DENIAL_PRECEDENCE: Final[tuple[RetryGate, ...]] = (
    RetryGate.HARD_BLOCK,
    RetryGate.ATTEMPT_BUDGET,
    RetryGate.TERMINAL_STATE,
    RetryGate.PRIMARY_DIAGNOSTIC,
    RetryGate.AVAILABILITY_FRESHNESS,
    RetryGate.EXPERIMENT_ACTIVE,
)


def _require_gate(gate: object) -> RetryGate:
    if type(gate) is not RetryGate:
        raise TypeError("gate must be a RetryGate member")
    return gate


def denial_reason_for(gate: RetryGate) -> RetryDenialReason:
    """The durable denial reason recorded when ``gate`` is the selected failure."""
    return _DENIAL_REASON_OF_GATE[_require_gate(gate)]


def recorded_denial_reason(failed_gates: Iterable[RetryGate]) -> RetryDenialReason:
    """Plan section 8.2: the reason of the first failed gate in ``4, 1, 2, 3, 6, 5``.

    Input order is not semantic. An empty collection is a programming error --
    an ``ALLOWED`` decision records no denial reason -- and raises ``ValueError``.
    """
    failed = frozenset(_require_gate(gate) for gate in failed_gates)
    for gate in RETRY_DENIAL_PRECEDENCE:
        if gate in failed:
            return _DENIAL_REASON_OF_GATE[gate]
    raise ValueError("no failed gate: an ALLOWED decision records no denial reason")


# --- The paired causal closure (plan section 8.2) -------------------------------------


class CausalClosureEntry(CanonicalModel):
    """One whole ``(category, error_code)`` pair of the causal closure (plan 8.2).

    A nested value object without an envelope ``schema_version`` (plan 3.1). The
    pair is never split: the closure is deduplicated and sorted over whole entries.
    """

    category: DiagnosticCategory
    error_code: ErrorCode


def _closure_key(entry: CausalClosureEntry) -> tuple[str, str]:
    return (entry.category.value, entry.error_code)


def _require_closure_entries(
    entries: Iterable[CausalClosureEntry],
) -> tuple[CausalClosureEntry, ...]:
    materialized = tuple(entries)
    for entry in materialized:
        if type(entry) is not CausalClosureEntry:
            raise TypeError("closure entries must be CausalClosureEntry values")
    return materialized


def _require_canonical_closure(closure: tuple[CausalClosureEntry, ...]) -> None:
    keys = [_closure_key(entry) for entry in closure]
    if len(set(keys)) != len(keys):
        raise ValueError(
            "causal closure entries must be unique whole pairs (canonical form)"
        )
    if keys != sorted(keys):
        raise ValueError(
            "causal closure must be sorted by (category, error_code) (canonical form)"
        )


def canonical_causal_closure(
    entries: Iterable[CausalClosureEntry],
) -> tuple[CausalClosureEntry, ...]:
    """Deduplicate whole pairs and sort them by ``(category, error_code)``.

    The ordering helper Task 7's traversal applies to the pairs it collects; pure
    over its argument and total over any iterable of entries, including an empty
    one. A foreign element raises ``TypeError``.
    """
    unique: dict[tuple[str, str], CausalClosureEntry] = {}
    for entry in _require_closure_entries(entries):
        unique.setdefault(_closure_key(entry), entry)
    return tuple(unique[key] for key in sorted(unique))


def hard_block_error_code(
    closure: tuple[CausalClosureEntry, ...],
) -> ErrorCode | MISSING:  # type: ignore[valid-type]
    """Plan section 8.2: the code of the first hard-blocking entry, or ``MISSING``.

    Category and code are read from that same entry, so the recorded cause is
    deterministic and provably paired. The closure must already be canonical: a
    duplicate or an unsorted pair raises ``ValueError`` rather than being reordered
    here, so the answer cannot depend on how the caller happened to order it.
    """
    entries = _require_closure_entries(closure)
    _require_canonical_closure(entries)
    for entry in entries:
        if entry.category in HARD_BLOCKING_DIAGNOSTIC_CATEGORIES:
            return entry.error_code
    return MISSING


#: Plan section 8.2: the closure the service substitutes when Task 7's traversal
#: helper returns a ``Failure`` (a cycle, a missing reference or a breached bound),
#: so gate 4 fails and a durable ``DENIED`` row is persisted rather than the
#: operation aborting.
FAIL_CLOSED_CAUSAL_CLOSURE: Final[tuple[CausalClosureEntry, ...]] = (
    CausalClosureEntry(
        category=DiagnosticCategory.INTERNAL_INVARIANT,
        error_code="CORE.INVARIANT_VIOLATION",
    ),
)


# --- The authoritative evaluation snapshot (plan section 8.2) -------------------------


def _require_non_success_terminal(state: EngineRunState) -> EngineRunState:
    if state not in _NON_SUCCESS_TERMINAL_STATES:
        raise ValueError(
            "predecessor_terminal_state must be one of the five non-success terminal "
            "states"
        )
    return state


class RetryEvaluationSnapshot(CanonicalModel):
    """Plan section 8.2: the authoritative inputs of one retry evaluation.

    Assembled by the Task 7 service from repository reads and one clock read, never
    supplied by a caller; see the module docstring for each field's source and the
    declared shape rules. Pure data: it decides nothing itself.
    """

    schema_version: Literal["1.0.0"]
    experiment_id: ExperimentId
    logical_slot_id: LogicalSlotId
    predecessor_run_id: RunId
    experiment_spec_hash: Sha256
    retry_policy: RetryPolicy
    experiment_state: ExperimentState
    created_attempt_count: int = Field(ge=1, le=MAX_ATTEMPTS_PER_SLOT)
    predecessor_terminal_state: EngineRunState
    predecessor_terminal_completed_at_utc: CalendarValidUtcDateTime
    primary_terminal_diagnostic: Diagnostic
    causal_closure: tuple[CausalClosureEntry, ...] = Field(
        min_length=1, max_length=MAX_CAUSAL_CLOSURE_ENTRIES
    )
    predecessor_availability_observation: _Observation | MISSING = MISSING  # type: ignore[valid-type]
    candidate_availability_observations: tuple[_Observation, ...] = Field(
        max_length=MAX_CANDIDATE_AVAILABILITY_OBSERVATIONS
    )
    evaluated_at_utc: CalendarValidUtcDateTime

    @field_validator("predecessor_terminal_state")
    @classmethod
    def validate_predecessor_terminal_state(
        cls, value: EngineRunState
    ) -> EngineRunState:
        return _require_non_success_terminal(value)

    @field_validator("causal_closure")
    @classmethod
    def validate_causal_closure(
        cls, value: tuple[CausalClosureEntry, ...]
    ) -> tuple[CausalClosureEntry, ...]:
        _require_canonical_closure(value)
        return value

    @field_validator("candidate_availability_observations")
    @classmethod
    def validate_candidates(
        cls, value: tuple[RuntimeAvailabilityObservation, ...]
    ) -> tuple[RuntimeAvailabilityObservation, ...]:
        identifiers = [item.availability_observation_id for item in value]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError(
                "candidate availability observations must be unique by identifier"
            )
        if identifiers != sorted(identifiers):
            raise ValueError(
                "candidate availability observations must be sorted by "
                "availability_observation_id"
            )
        return value

    @model_validator(mode="after")
    def validate_authoritative_shape(self) -> Self:
        self._validate_experiment_state()
        self._validate_primary_diagnostic()
        self._validate_observation_material()
        return self

    def _validate_experiment_state(self) -> None:
        if (
            self.experiment_state is not ExperimentState.RUNNING
            and self.experiment_state not in TERMINAL_EXPERIMENT_STATES
        ):
            raise ValueError(
                "experiment_state must be RUNNING or terminal: a terminal attempt "
                "exists only once the experiment has run"
            )

    def _validate_primary_diagnostic(self) -> None:
        diagnostic = self.primary_terminal_diagnostic
        if (
            not _is_missing(diagnostic.run_id)
            and diagnostic.run_id != self.predecessor_run_id
        ):
            raise ValueError(
                "primary_terminal_diagnostic.run_id must equal predecessor_run_id"
            )
        if (
            not _is_missing(diagnostic.experiment_id)
            and diagnostic.experiment_id != self.experiment_id
        ):
            raise ValueError(
                "primary_terminal_diagnostic.experiment_id must equal experiment_id"
            )
        primary = _closure_key(
            CausalClosureEntry(
                category=diagnostic.category, error_code=diagnostic.error_code
            )
        )
        if self.causal_closure != FAIL_CLOSED_CAUSAL_CLOSURE and primary not in {
            _closure_key(entry) for entry in self.causal_closure
        }:
            raise ValueError(
                "causal_closure must contain the primary terminal diagnostic's "
                "(category, error_code) pair unless it is the fail-closed closure"
            )

    def _validate_observation_material(self) -> None:
        unavailable = self.predecessor_terminal_state is _R.UNAVAILABLE
        present = not _is_missing(self.predecessor_availability_observation)
        if unavailable and not present:
            raise ValueError(
                "an UNAVAILABLE predecessor requires "
                "predecessor_availability_observation"
            )
        if present and not unavailable:
            raise ValueError(
                "predecessor_availability_observation is present exactly for an "
                "UNAVAILABLE predecessor"
            )
        if self.candidate_availability_observations and not unavailable:
            raise ValueError(
                "candidate_availability_observations are read only for an "
                "UNAVAILABLE predecessor"
            )


# --- Gate 6: availability identity and freshness (plan section 8.2) ------------------


def _qualifies(
    candidate: RuntimeAvailabilityObservation,
    predecessor: RuntimeAvailabilityObservation,
    terminal_completed_at_utc: datetime,
    evaluated_at_utc: datetime,
) -> bool:
    return (
        candidate.available
        and candidate.adapter_name == predecessor.adapter_name
        and candidate.adapter_version == predecessor.adapter_version
        and candidate.executable_hash == predecessor.executable_hash
        and candidate.observed_at_utc > terminal_completed_at_utc
        and candidate.expires_at_utc > evaluated_at_utc
        and candidate.availability_observation_id
        != predecessor.availability_observation_id
    )


def select_fresh_availability_observation(
    predecessor_observation: RuntimeAvailabilityObservation,
    candidates: Iterable[RuntimeAvailabilityObservation],
    *,
    terminal_completed_at_utc: datetime,
    evaluated_at_utc: datetime,
) -> RuntimeAvailabilityObservation | MISSING:  # type: ignore[valid-type]
    """Plan section 8.2: the qualifying observation gate 6 requires, or ``MISSING``.

    A candidate qualifies when all of: ``available`` is true; adapter name, adapter
    version and executable hash equal the predecessor observation's;
    ``observed_at_utc`` is strictly after the predecessor's terminal completion;
    ``expires_at_utc`` is strictly after the single evaluation instant; and its
    identifier differs from the predecessor's. When several qualify the choice is
    deterministic: greatest ``observed_at_utc``, ties broken by lexicographically
    greatest identifier. Pure over its arguments; both instants must be UTC.
    """
    if type(predecessor_observation) is not RuntimeAvailabilityObservation:
        raise TypeError(
            "predecessor_observation must be a RuntimeAvailabilityObservation"
        )
    completed = require_utc(terminal_completed_at_utc)
    evaluated = require_utc(evaluated_at_utc)
    qualifying: list[RuntimeAvailabilityObservation] = []
    for candidate in candidates:
        if type(candidate) is not RuntimeAvailabilityObservation:
            raise TypeError("candidates must be RuntimeAvailabilityObservation values")
        if _qualifies(candidate, predecessor_observation, completed, evaluated):
            qualifying.append(candidate)
    if not qualifying:
        return MISSING
    return max(
        qualifying,
        key=lambda item: (item.observed_at_utc, item.availability_observation_id),
    )


# --- Durable delay (plan section 8.4, specification 7.2) ------------------------------


def durable_retry_not_before(
    terminal_completed_at_utc: datetime,
    retry_delay_seconds: int,
) -> datetime:
    """``terminal_completed_at_utc + retry_delay_seconds`` (specification 7.2).

    A function of durable facts alone -- the predecessor's authoritative terminal
    completion instant and the immutable policy's delay -- and never of any clock.
    The instant must be UTC; the delay must be a built-in integer within the
    policy's ``0..300`` range; a sum beyond the representable range is a
    ``ValueError``.
    """
    if type(retry_delay_seconds) is not int:
        raise TypeError("retry_delay_seconds must be a built-in integer")
    if not 0 <= retry_delay_seconds <= MAX_RETRY_DELAY_SECONDS:
        raise ValueError(
            f"retry_delay_seconds must be within 0..{MAX_RETRY_DELAY_SECONDS}"
        )
    completed = require_utc(terminal_completed_at_utc)
    try:
        return completed + timedelta(seconds=retry_delay_seconds)
    except OverflowError as error:
        raise ValueError(
            "retry_not_before_utc falls outside the representable datetime range"
        ) from error


# --- The immutable retry decision (plan section 3.9) ----------------------------------

#: Plan section 3.9 field 15: a reservation is always a successor number, ``2..5``.
type ReservedAttemptNumber = Annotated[int, Field(ge=2, le=MAX_ATTEMPTS_PER_SLOT)]


class RetryDecisionRecord(CanonicalModel):
    """Plan section 3.9: the complete, immutable outcome of one retry evaluation.

    The sixteen fields in order. Identity is ``(logical_slot_id,
    predecessor_run_id)``; there is no revision and no separate operational
    identifier, and the created successor is found through run identity and
    predecessor relationships, never through a field of this record. Field 16,
    ``decided_at_utc``, is clock metadata and the sole exclusion from the semantic
    projection. See the module docstring for the outcome-governed presence rules
    and the declared consistency filter.
    """

    schema_version: Literal["1.0.0"]
    experiment_id: ExperimentId
    logical_slot_id: LogicalSlotId
    predecessor_run_id: RunId
    experiment_spec_hash: Sha256
    retry_policy: RetryPolicy
    created_attempt_count: int = Field(ge=1, le=MAX_ATTEMPTS_PER_SLOT)
    predecessor_terminal_state: EngineRunState
    primary_terminal_diagnostic_id: DiagnosticId
    outcome: RetryDecisionOutcome
    denial_reason: RetryDenialReason | MISSING = MISSING  # type: ignore[valid-type]
    hard_block_error_code: ErrorCode | MISSING = MISSING  # type: ignore[valid-type]
    availability_observation_id: AvailabilityObservationId | MISSING = MISSING  # type: ignore[valid-type]
    retry_not_before_utc: CalendarValidUtcDateTime | MISSING = MISSING  # type: ignore[valid-type]
    reserved_successor_attempt_number: ReservedAttemptNumber | MISSING = MISSING  # type: ignore[valid-type]
    decided_at_utc: CalendarValidUtcDateTime

    @field_validator("predecessor_terminal_state")
    @classmethod
    def validate_predecessor_terminal_state(
        cls, value: EngineRunState
    ) -> EngineRunState:
        return _require_non_success_terminal(value)

    @model_validator(mode="after")
    def validate_outcome_governed_shape(self) -> Self:
        if self.outcome is RetryDecisionOutcome.ALLOWED:
            self._validate_allowed_shape()
        else:
            self._validate_denied_shape()
        self._validate_precedence_consistency()
        return self

    # -- Plan section 3.9 rows 11-15 ------------------------------------------------

    def _validate_allowed_shape(self) -> None:
        if not _is_missing(self.denial_reason):
            raise ValueError("an ALLOWED decision carries no denial_reason")
        if not _is_missing(self.hard_block_error_code):
            raise ValueError("an ALLOWED decision carries no hard_block_error_code")
        if _is_missing(self.retry_not_before_utc):
            raise ValueError("an ALLOWED decision requires retry_not_before_utc")
        if _is_missing(self.reserved_successor_attempt_number):
            raise ValueError(
                "an ALLOWED decision requires reserved_successor_attempt_number"
            )
        if self.reserved_successor_attempt_number != self.created_attempt_count + 1:
            raise ValueError(
                "reserved_successor_attempt_number must equal created_attempt_count + 1"
            )
        unavailable = self.predecessor_terminal_state is _R.UNAVAILABLE
        observed = not _is_missing(self.availability_observation_id)
        if unavailable and not observed:
            raise ValueError(
                "an ALLOWED decision for an UNAVAILABLE predecessor requires "
                "availability_observation_id"
            )
        if observed and not unavailable:
            raise ValueError(
                "availability_observation_id is present only on an ALLOWED decision "
                "for an UNAVAILABLE predecessor"
            )

    def _validate_denied_shape(self) -> None:
        if _is_missing(self.denial_reason):
            raise ValueError("a DENIED decision requires denial_reason")
        if not _is_missing(self.retry_not_before_utc):
            raise ValueError("a DENIED decision carries no retry_not_before_utc")
        if not _is_missing(self.reserved_successor_attempt_number):
            raise ValueError(
                "a DENIED decision carries no reserved_successor_attempt_number"
            )
        if not _is_missing(self.availability_observation_id):
            raise ValueError("a DENIED decision carries no availability_observation_id")
        hard_blocked = self.denial_reason is RetryDenialReason.HARD_BLOCKED_OUTCOME
        coded = not _is_missing(self.hard_block_error_code)
        if hard_blocked and not coded:
            raise ValueError("HARD_BLOCKED_OUTCOME requires hard_block_error_code")
        if coded and not hard_blocked:
            raise ValueError(
                "hard_block_error_code is present only under HARD_BLOCKED_OUTCOME"
            )

    # -- Task-local reading: the precedence-implied consistency filter ---------------

    def _decidable_gate_failures(self) -> dict[RetryGate, bool]:
        """The gates whose failure is decidable from the record's own fields."""
        policy = self.retry_policy
        mapped = retry_terminal_state_of(self.predecessor_terminal_state)
        return {
            RetryGate.ATTEMPT_BUDGET: (
                self.created_attempt_count >= policy.maximum_attempts_per_slot
            ),
            RetryGate.TERMINAL_STATE: (
                _is_missing(mapped)
                or mapped not in policy.automatically_retry_terminal_states
            ),
        }

    def _validate_precedence_consistency(self) -> None:
        failures = self._decidable_gate_failures()
        if self.outcome is RetryDecisionOutcome.ALLOWED:
            if failures[RetryGate.ATTEMPT_BUDGET]:
                raise ValueError(
                    "an ALLOWED decision requires created_attempt_count below "
                    "maximum_attempts_per_slot"
                )
            if failures[RetryGate.TERMINAL_STATE]:
                raise ValueError(
                    "an ALLOWED decision requires a predecessor_terminal_state listed "
                    "in automatically_retry_terminal_states"
                )
            return
        reason = self.denial_reason
        own_gate = next(
            gate for gate, mapped in _DENIAL_REASON_OF_GATE.items() if mapped is reason
        )
        for gate in RETRY_DENIAL_PRECEDENCE:
            if gate is own_gate:
                break
            if failures.get(gate, False):
                raise ValueError(
                    f"a decision denied for {reason.value} must pass the "
                    f"higher-precedence gate whose reason is "
                    f"{_DENIAL_REASON_OF_GATE[gate].value}"
                )
        if own_gate is RetryGate.ATTEMPT_BUDGET and not failures[own_gate]:
            raise ValueError(
                "a decision denied for ATTEMPT_BUDGET_EXHAUSTED requires "
                "created_attempt_count at or above maximum_attempts_per_slot"
            )
        if own_gate is RetryGate.TERMINAL_STATE and not failures[own_gate]:
            raise ValueError(
                "a decision denied for TERMINAL_STATE_NOT_RETRYABLE requires a "
                "predecessor_terminal_state outside automatically_retry_terminal_states"
            )
        if (
            own_gate is RetryGate.AVAILABILITY_FRESHNESS
            and self.predecessor_terminal_state is not _R.UNAVAILABLE
        ):
            raise ValueError(
                "a decision denied for AVAILABILITY_OBSERVATION_NOT_FRESH requires an "
                "UNAVAILABLE predecessor"
            )


def retry_decision_semantic_projection(record: RetryDecisionRecord) -> bytes:
    """Plan section 3.9: canonical JSON over fields 1-15; ``decided_at_utc`` excluded.

    Two candidates built from the same authoritative facts at different instants
    project equally; plan 8.4 phase 3 compares projections to tell a concurrent
    winner from a divergent one. Absent fields are omitted, never written as null.
    """
    if type(record) is not RetryDecisionRecord:
        raise TypeError("record must be a RetryDecisionRecord")
    payload = record.model_dump(mode="python")
    del payload["decided_at_utc"]
    return canonical_json_bytes(payload)


# --- The six gates and phase 2 candidate construction (plan sections 8.2, 8.4) -------


def _require_snapshot(snapshot: object) -> RetryEvaluationSnapshot:
    if type(snapshot) is not RetryEvaluationSnapshot:
        raise TypeError("snapshot must be a RetryEvaluationSnapshot")
    return snapshot


def _qualifying_observation(
    snapshot: RetryEvaluationSnapshot,
) -> RuntimeAvailabilityObservation | MISSING:  # type: ignore[valid-type]
    if snapshot.predecessor_terminal_state is not _R.UNAVAILABLE:
        return MISSING
    return select_fresh_availability_observation(
        snapshot.predecessor_availability_observation,
        snapshot.candidate_availability_observations,
        terminal_completed_at_utc=snapshot.predecessor_terminal_completed_at_utc,
        evaluated_at_utc=snapshot.evaluated_at_utc,
    )


def failed_retry_gates(snapshot: RetryEvaluationSnapshot) -> tuple[RetryGate, ...]:
    """Plan section 8.2: the complete set of failed gates, in gate order ``1..6``.

    Every gate is evaluated -- none short-circuits -- so the result is the whole
    failed set and not merely the first failure. Empty when the retry is allowed.
    Pure over the snapshot.
    """
    snapshot = _require_snapshot(snapshot)
    policy = snapshot.retry_policy
    failed: list[RetryGate] = []
    if not snapshot.created_attempt_count < policy.maximum_attempts_per_slot:
        failed.append(RetryGate.ATTEMPT_BUDGET)
    mapped = retry_terminal_state_of(snapshot.predecessor_terminal_state)
    if _is_missing(mapped) or mapped not in policy.automatically_retry_terminal_states:
        failed.append(RetryGate.TERMINAL_STATE)
    if not snapshot.primary_terminal_diagnostic.retriable:
        failed.append(RetryGate.PRIMARY_DIAGNOSTIC)
    if not _is_missing(hard_block_error_code(snapshot.causal_closure)):
        failed.append(RetryGate.HARD_BLOCK)
    if snapshot.experiment_state in TERMINAL_EXPERIMENT_STATES:
        failed.append(RetryGate.EXPERIMENT_ACTIVE)
    if snapshot.predecessor_terminal_state is _R.UNAVAILABLE and _is_missing(
        _qualifying_observation(snapshot)
    ):
        failed.append(RetryGate.AVAILABILITY_FRESHNESS)
    return tuple(failed)


def evaluate_retry_gates(snapshot: RetryEvaluationSnapshot) -> RetryDecisionRecord:
    """Plan section 8.4 phase 2: the one complete immutable candidate.

    Evaluates the six gates over the snapshot and constructs the ``ALLOWED`` or
    ``DENIED`` record. For ``ALLOWED``, ``retry_not_before_utc`` is the
    predecessor's terminal completion instant plus ``retry_delay_seconds`` -- a
    function of durable facts alone, never of the evaluation instant --
    ``reserved_successor_attempt_number`` is ``created_attempt_count + 1``, and for
    an ``UNAVAILABLE`` predecessor ``availability_observation_id`` names the
    selected qualifying observation. For ``DENIED``, ``denial_reason`` follows the
    fixed precedence and ``hard_block_error_code`` is present exactly under
    ``HARD_BLOCKED_OUTCOME``. ``decided_at_utc`` is the snapshot's single clock
    instant. Pure and repeatable: the same snapshot always yields the same record.
    """
    snapshot = _require_snapshot(snapshot)
    failed = failed_retry_gates(snapshot)
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "experiment_id": snapshot.experiment_id,
        "logical_slot_id": snapshot.logical_slot_id,
        "predecessor_run_id": snapshot.predecessor_run_id,
        "experiment_spec_hash": snapshot.experiment_spec_hash,
        "retry_policy": snapshot.retry_policy,
        "created_attempt_count": snapshot.created_attempt_count,
        "predecessor_terminal_state": snapshot.predecessor_terminal_state,
        "primary_terminal_diagnostic_id": (
            snapshot.primary_terminal_diagnostic.diagnostic_id
        ),
        "decided_at_utc": snapshot.evaluated_at_utc,
    }
    if failed:
        reason = recorded_denial_reason(failed)
        payload["outcome"] = RetryDecisionOutcome.DENIED
        payload["denial_reason"] = reason
        if reason is RetryDenialReason.HARD_BLOCKED_OUTCOME:
            payload["hard_block_error_code"] = hard_block_error_code(
                snapshot.causal_closure
            )
        return RetryDecisionRecord.model_validate(payload)
    payload["outcome"] = RetryDecisionOutcome.ALLOWED
    payload["retry_not_before_utc"] = durable_retry_not_before(
        snapshot.predecessor_terminal_completed_at_utc,
        snapshot.retry_policy.retry_delay_seconds,
    )
    payload["reserved_successor_attempt_number"] = snapshot.created_attempt_count + 1
    observation = _qualifying_observation(snapshot)
    if not _is_missing(observation):
        payload["availability_observation_id"] = observation.availability_observation_id
    return RetryDecisionRecord.model_validate(payload)
