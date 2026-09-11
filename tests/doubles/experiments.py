"""Deterministic in-memory doubles and fixture material for the Stage 5 ports.

Plan section 11. Every double here is a faithful test double, not a mock: the
repositories enforce identity uniqueness, the unique indexes, the expected-revision
compare-and-swap and the ``+1`` revision step; the unit of work is atomic and
isolated; nothing reads the wall clock, draws a random value, sleeps or starts a
thread. Concurrency is simulated deterministically through two injected one-shot
hooks and explicit revision manipulation.

Task-local readings (plan 11 is silent on them) are declared in the class docstrings
below: the isolation model (private working copies, authoritative live reads at the
compare-and-swap and insert boundaries, commit-time validation of every changed
row), the lifecycle detectors (no nesting, no commit after close, idempotent
rollback) and the two one-shot hooks that live only on this double.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from typing import Any, Final, Protocol, cast

from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.adapters.events import RunEvent
from crypto_lab.adapters.ports import CommandInvocationRepository
from crypto_lab.domain.command_invocation import (
    CommandInvocationRecord,
    ProcessIdentity,
    ProcessStartFacts,
)
from crypto_lab.domain.comparison_levels import ComparisonLevel
from crypto_lab.domain.compatibility import CompatibilityOutcome
from crypto_lab.domain.descriptors import (
    OperatingSystem,
    RuntimeAvailabilityObservation,
)
from crypto_lab.domain.diagnostics import (
    Diagnostic,
    DiagnosticCategory,
    DiagnosticSeverity,
)
from crypto_lab.domain.engine_run import EngineRunRecord
from crypto_lab.domain.experiment import (
    AdapterIdentity,
    BarOrderPriority,
    EngineIdentity,
    ExecutionAssumptions,
    ExperimentRecord,
    ExperimentSpecDraft,
    FeeAssumptions,
    FillConvention,
    SelectedEngineSlot,
    SignalToOrderTiming,
    SlippageAssumptions,
    SlippageModel,
    SlotCompatibility,
    build_experiment_spec,
    experiment_spec_hash,
)
from crypto_lab.domain.hashing import _uuid4_shaped, attempt_token_hash, sha256_bytes
from crypto_lab.domain.lifecycle import (
    TERMINAL_COMMAND_INVOCATION_STATES,
    TERMINAL_ENGINE_RUN_STATES,
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
    RetryTerminalState,
    process_exit_category_for,
)
from crypto_lab.domain.ports import Clock
from crypto_lab.domain.records import Money
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.domain.retry import (
    RetryDecisionOutcome,
    RetryDecisionRecord,
    RetryDenialReason,
    RetryPolicy,
)
from crypto_lab.domain.time import require_utc
from crypto_lab.experiments.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
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

_E: Final = ExperimentState
_R: Final = EngineRunState
_C: Final = CommandInvocationState

# --------------------------------------------------------------------------
# Deterministic fixture material (shared by the Task 6-8 test modules)
# --------------------------------------------------------------------------

# Lowercase canonical UUID4 text: version nibble 4, variant nibble in [89ab].
UUID_A: Final = "12345678-1234-4234-8234-123456789abc"
UUID_B: Final = "9f8e7d6c-5b4a-4321-8fed-cba987654321"
UUID_C: Final = "0a1b2c3d-4e5f-4a6b-9c7d-8e9f0a1b2c3d"
UUID_D: Final = "5e5e5e5e-1111-4222-8333-444455556666"
UUID_E: Final = "7c7c7c7c-2222-4333-9444-555566667777"
EXPERIMENT_ID: Final = f"exp_{UUID_A}"
OTHER_EXPERIMENT_ID: Final = f"exp_{UUID_B}"
SLOT_A: Final = f"slot_{UUID_A}"
SLOT_B: Final = f"slot_{UUID_B}"
SLOT_C: Final = f"slot_{UUID_C}"
RUN_ID: Final = f"run_{UUID_A}"
OTHER_RUN_ID: Final = f"run_{UUID_B}"
THIRD_RUN_ID: Final = f"run_{UUID_C}"
INVOCATION_ID: Final = f"inv_{UUID_A}"
OTHER_INVOCATION_ID: Final = f"inv_{UUID_B}"
DIAG_ID: Final = f"diag_{UUID_A}"
OTHER_DIAG_ID: Final = f"diag_{UUID_B}"
THIRD_DIAG_ID: Final = f"diag_{UUID_C}"
AVAIL_A: Final = f"avail_{UUID_A}"
AVAIL_B: Final = f"avail_{UUID_B}"
ARTIFACT_ID: Final = f"art_{UUID_A}"
STRATEGY_HASH: Final = "1" * 64
DATASET_HASH: Final = "2" * 64
MATERIAL_HASH: Final = "c" * 64
REQUEST_HASH: Final = "a" * 64
OTHER_REQUEST_HASH: Final = "b" * 64
EXECUTABLE_HASH: Final = "e" * 64
ATTEMPT_TOKEN: Final = "A" * 32
INSTANT: Final = datetime(2026, 9, 7, 12, 0, 0, tzinfo=UTC)
ADAPTER_ALPHA: Final = AdapterIdentity(
    adapter_name="adapter.alpha", adapter_version="1.0.0"
)
ENGINE_ALPHA: Final = EngineIdentity(engine_name="engine.alpha", engine_version="2.3.4")
ADAPTER_BETA: Final = AdapterIdentity(
    adapter_name="adapter.beta", adapter_version="1.2.0"
)
ENGINE_BETA: Final = EngineIdentity(engine_name="engine.beta", engine_version="2.3.4")

_EXPERIMENT_REVISION: Final[dict[ExperimentState, int]] = {
    _E.DRAFT: 0,
    _E.VALIDATED: 1,
    _E.QUEUED: 2,
    _E.RUNNING: 3,
    _E.COMPLETED: 4,
    _E.COMPLETED_WITH_WARNINGS: 4,
    _E.FAILED: 4,
    _E.CANCELLED: 4,
}
_RUN_REVISION: Final[dict[EngineRunState, int]] = {
    _R.PENDING: 0,
    _R.VALIDATING: 1,
    _R.READY: 2,
    _R.STARTING: 3,
    _R.RUNNING: 4,
    _R.SUCCEEDED: 5,
    _R.SUCCEEDED_WITH_WARNINGS: 5,
    _R.FAILED: 5,
    _R.CANCELLED: 5,
    _R.TIMED_OUT: 5,
    _R.NOT_APPLICABLE: 5,
    _R.UNAVAILABLE: 5,
}
_NON_SUCCESS_TERMINAL: Final = TERMINAL_ENGINE_RUN_STATES - {
    _R.SUCCEEDED,
    _R.SUCCEEDED_WITH_WARNINGS,
}
_OBSERVATION_PROHIBITED: Final = frozenset({_R.PENDING, _R.VALIDATING})
_OBSERVATION_REQUIRED: Final = frozenset(
    {
        _R.READY,
        _R.STARTING,
        _R.RUNNING,
        _R.SUCCEEDED,
        _R.SUCCEEDED_WITH_WARNINGS,
        _R.UNAVAILABLE,
    }
)


def _is_missing(value: object) -> bool:
    return value is MISSING


def sample_retry_policy(**overrides: object) -> RetryPolicy:
    """Three attempts, every retry state listed, a thirty-second delay."""
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "maximum_attempts_per_slot": 3,
        "automatically_retry_terminal_states": (
            RetryTerminalState.FAILED,
            RetryTerminalState.TIMED_OUT,
            RetryTerminalState.UNAVAILABLE,
        ),
        "retry_delay_seconds": 30,
        "require_fresh_availability_observation_for_unavailable": True,
    }
    payload.update(overrides)
    return RetryPolicy.model_validate(payload)


def sample_slots() -> tuple[SelectedEngineSlot, ...]:
    return (
        SelectedEngineSlot(
            logical_slot_id=SLOT_A,
            slot_ordinal=0,
            adapter=ADAPTER_ALPHA,
            engine=ENGINE_ALPHA,
        ),
        SelectedEngineSlot(
            logical_slot_id=SLOT_B,
            slot_ordinal=1,
            adapter=ADAPTER_BETA,
            engine=ENGINE_BETA,
        ),
    )


def sample_draft(**overrides: object) -> ExperimentSpecDraft:
    """Two selected slots (alpha, beta) and a fixed-basis-point slippage model."""
    payload: dict[str, object] = {
        "strategy_version_hash": STRATEGY_HASH,
        "dataset_version_hash": DATASET_HASH,
        "selected_engine_slots": sample_slots(),
        "starting_balance": Money(
            schema_version="1.0.0", currency="USDT", amount=Decimal("10000")
        ),
        "fee_assumptions": FeeAssumptions(
            maker_fee_rate=Decimal("0.001"), taker_fee_rate=Decimal("0.002")
        ),
        "slippage_assumptions": SlippageAssumptions(
            model=SlippageModel.FIXED_BASIS_POINTS, basis_points=Decimal("5")
        ),
        "execution_assumptions": ExecutionAssumptions(
            signal_to_order_timing=SignalToOrderTiming.NEXT_BAR_OPEN,
            bar_order_priority=BarOrderPriority.EXITS_BEFORE_ENTRIES,
            fill_convention=FillConvention.FULL_FILL,
            price_precision=2,
            quantity_precision=8,
            rounding_mode="ROUND_HALF_EVEN",
        ),
        "comparison_level": ComparisonLevel.LEVEL_2,
        "retry_policy": sample_retry_policy(),
    }
    payload.update(overrides)
    return ExperimentSpecDraft.model_validate(payload)


_SLOT_OBSERVATIONS: Final[dict[str, str]] = {SLOT_A: AVAIL_A, SLOT_B: AVAIL_B}


def sample_slot_compatibility(
    draft: ExperimentSpecDraft | None = None,
    *,
    outcomes: Mapping[str, CompatibilityOutcome] | None = None,
) -> tuple[SlotCompatibility, ...]:
    """One frozen compatibility entry per selected slot, in slot order.

    ``outcomes`` overrides the default ``SUPPORTED`` per slot identifier; an
    approximated outcome carries one approximation identifier.
    """
    draft = sample_draft() if draft is None else draft
    entries: list[SlotCompatibility] = []
    for slot in draft.selected_engine_slots:
        outcome = (outcomes or {}).get(
            slot.logical_slot_id, CompatibilityOutcome.SUPPORTED
        )
        approximations: tuple[str, ...] = ()
        if outcome is CompatibilityOutcome.SUPPORTED_WITH_APPROXIMATION:
            approximations = (f"appx_{UUID_C}",)
        entries.append(
            SlotCompatibility(
                logical_slot_id=slot.logical_slot_id,
                outcome=outcome,
                availability_observation_id=_SLOT_OBSERVATIONS.get(
                    slot.logical_slot_id, f"avail_{UUID_C}"
                ),
                approximation_ids=approximations,
            )
        )
    return tuple(entries)


def sample_experiment(
    state: ExperimentState = _E.DRAFT,
    *,
    experiment_id: str = EXPERIMENT_ID,
    draft: ExperimentSpecDraft | None = None,
    slot_compatibility: tuple[SlotCompatibility, ...] | None = None,
    include_compatibility: bool | None = None,
    correlation_id: str = "cancel-1",
    revision: int | None = None,
    created_at_utc: datetime = INSTANT,
) -> ExperimentRecord:
    """A shape-valid experiment record in ``state``.

    ``slot_compatibility`` is present from ``QUEUED`` onward by default and, for
    ``CANCELLED``, whenever ``include_compatibility`` is true (a cancellation after
    the freeze) -- the record admits either there.
    """
    draft = sample_draft() if draft is None else draft
    spec = build_experiment_spec(draft, MATERIAL_HASH, created_at_utc)
    revision = _EXPERIMENT_REVISION[state] if revision is None else revision
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "experiment_id": experiment_id,
        "spec": spec,
        "spec_hash": experiment_spec_hash(spec),
        "state": state,
        "created_at_utc": created_at_utc,
        "updated_at_utc": created_at_utc + timedelta(seconds=revision),
        "revision": revision,
    }
    if include_compatibility is None:
        include_compatibility = state not in (_E.DRAFT, _E.VALIDATED, _E.CANCELLED)
    if include_compatibility:
        payload["slot_compatibility"] = (
            sample_slot_compatibility(draft)
            if slot_compatibility is None
            else slot_compatibility
        )
    if state is _E.CANCELLED:
        payload["cancellation_correlation_id"] = correlation_id
    return ExperimentRecord.model_validate(payload)


def sample_run(
    state: EngineRunState = _R.PENDING,
    *,
    run_id: str = RUN_ID,
    experiment_id: str = EXPERIMENT_ID,
    logical_slot_id: str = SLOT_A,
    attempt_number: int = 1,
    predecessor_run_id: str | None = None,
    retry_reason: RetryTerminalState = RetryTerminalState.FAILED,
    adapter: AdapterIdentity = ADAPTER_ALPHA,
    engine: EngineIdentity = ENGINE_ALPHA,
    request_hash: str = REQUEST_HASH,
    attempt_token: str = ATTEMPT_TOKEN,
    primary_terminal_diagnostic_id: str = DIAG_ID,
    availability_observation_id: str = AVAIL_A,
    observed: bool | None = None,
    revision: int | None = None,
    created_at_utc: datetime = INSTANT,
) -> EngineRunRecord:
    """A shape-valid engine-run record in ``state``; ``observed`` fixes the
    predecessor-dependent observation of the four terminals ``VALIDATING`` reaches."""
    if observed is None:
        observed = state not in _OBSERVATION_PROHIBITED and (
            state in _OBSERVATION_REQUIRED
            or state in (_R.FAILED, _R.CANCELLED, _R.TIMED_OUT)
        )
    revision = _RUN_REVISION[state] if revision is None else revision
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "run_id": run_id,
        "experiment_id": experiment_id,
        "logical_slot_id": logical_slot_id,
        "attempt_number": attempt_number,
        "attempt_token_hash": attempt_token_hash(attempt_token),
        "state": state,
        "adapter": adapter,
        "engine": engine,
        "request_hash": request_hash,
        "created_at_utc": created_at_utc,
        "updated_at_utc": created_at_utc + timedelta(seconds=revision),
        "revision": revision,
    }
    if attempt_number > 1:
        if predecessor_run_id is None:
            predecessor_run_id = OTHER_RUN_ID if run_id != OTHER_RUN_ID else RUN_ID
        payload["predecessor_run_id"] = predecessor_run_id
        payload["retry_reason"] = retry_reason
    if observed:
        payload["availability_observation_id"] = availability_observation_id
    if state in _NON_SUCCESS_TERMINAL:
        payload["primary_terminal_diagnostic_id"] = primary_terminal_diagnostic_id
    return EngineRunRecord.model_validate(payload)


def sample_process_identity(**overrides: object) -> ProcessIdentity:
    payload: dict[str, object] = {
        "pid": 4321,
        "creation_identity": "2026-09-07T12:00:03.1234567Z#0001",
        "executable_path": r"C:\adapters\alpha\adapter.exe",
        "executable_hash": EXECUTABLE_HASH,
        "supervisor_instance_id": "supervisor-01",
    }
    payload.update(overrides)
    return ProcessIdentity.model_validate(payload)


def sample_process_start(
    *,
    process_started_at_utc: datetime = INSTANT + timedelta(seconds=2),
    **identity_overrides: object,
) -> ProcessStartFacts:
    return ProcessStartFacts(
        pid_identity=sample_process_identity(**identity_overrides),
        process_started_at_utc=process_started_at_utc,
    )


def sample_invocation(
    state: CommandInvocationState = _C.PENDING,
    *,
    kind: CommandKind = CommandKind.RUN,
    via: CommandInvocationState | None = None,
    invocation_id: str = INVOCATION_ID,
    run_id: str = RUN_ID,
    adapter_name: str = "adapter.alpha",
    adapter_version: str = "1.0.0",
    request_hash: str = REQUEST_HASH,
    timeout_seconds: int = 120,
    primary_diagnostic_id: str = DIAG_ID,
    native_exit_value: int = 0,
    created_at_utc: datetime = INSTANT,
) -> CommandInvocationRecord:
    """A shape-valid invocation record in ``state``.

    ``via`` names the predecessor of the two predecessor-dependent terminals
    (``CANCELLED`` from ``PENDING``/``STARTING``/``RUNNING``, ``TIMED_OUT`` from
    ``STARTING``/``RUNNING``); the default is ``RUNNING``. A ``DESCRIBE`` carries
    no ``run_id``.
    """
    if via is None and state in (_C.CANCELLED, _C.TIMED_OUT):
        via = _C.RUNNING
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "invocation_id": invocation_id,
        "command_kind": kind,
        "adapter_name": adapter_name,
        "adapter_version": adapter_version,
        "request_hash": request_hash,
        "timeout_seconds": timeout_seconds,
        "state": state,
        "process_created": False,
        "cleanup_complete": False,
        "diagnostic_ids": (),
        "created_at_utc": created_at_utc,
        "updated_at_utc": created_at_utc,
        "revision": 0,
    }
    if kind is not CommandKind.DESCRIBE:
        payload["run_id"] = run_id
    revision = 0
    launch = created_at_utc + timedelta(seconds=1)
    launched = state is not _C.PENDING and not (
        state is _C.CANCELLED and via is _C.PENDING
    )
    if launched:
        payload["launch_attempted_at_utc"] = launch
        payload["deadline_utc"] = launch + timedelta(seconds=timeout_seconds)
        payload["updated_at_utc"] = launch
        revision += 1
    process = state in (_C.RUNNING, _C.EXITED, _C.PROTOCOL_FAILED) or (
        state in (_C.CANCELLED, _C.TIMED_OUT) and via is _C.RUNNING
    )
    if process:
        payload["process_created"] = True
        payload["process_started_at_utc"] = launch + timedelta(seconds=1)
        payload["pid_identity"] = sample_process_identity()
        payload["updated_at_utc"] = launch + timedelta(seconds=1)
        revision += 1
    if state in TERMINAL_COMMAND_INVOCATION_STATES:
        completed = launch + timedelta(seconds=10)
        payload["completed_at_utc"] = completed
        payload["updated_at_utc"] = completed
        revision += 1
        if state is _C.EXITED:
            payload["native_exit_value"] = native_exit_value
            payload["process_exit_category"] = process_exit_category_for(
                native_exit_value
            )
        if state is not _C.EXITED or native_exit_value not in {
            0,
            10,
            20,
            30,
            40,
            50,
            60,
            70,
        }:
            payload["primary_diagnostic_id"] = primary_diagnostic_id
            payload["diagnostic_ids"] = (primary_diagnostic_id,)
    payload["revision"] = revision
    return CommandInvocationRecord.model_validate(payload)


def sample_diagnostic(
    diagnostic_id: str = DIAG_ID,
    *,
    error_code: str = "ENGINE.RUNTIME_FAILURE",
    category: DiagnosticCategory = DiagnosticCategory.ENGINE_RUNTIME,
    retriable: bool = True,
    experiment_id: str = EXPERIMENT_ID,
    run_id: str = RUN_ID,
    invocation_id: str = INVOCATION_ID,
    causal_diagnostic_ids: tuple[str, ...] = (),
    timestamp_utc: datetime = INSTANT,
) -> Diagnostic:
    """A fully correlated diagnostic; every command-category diagnostic carries an
    ``invocation_id`` as the record requires."""
    return Diagnostic.model_validate(
        {
            "schema_version": "1.0.0",
            "diagnostic_id": diagnostic_id,
            "severity": DiagnosticSeverity.ERROR,
            "error_code": error_code,
            "category": category,
            "message": "fixture diagnostic",
            "source_component": "doubles.experiments",
            "experiment_id": experiment_id,
            "run_id": run_id,
            "invocation_id": invocation_id,
            "retriable": retriable,
            "timestamp_utc": timestamp_utc,
            "details": {},
            "causal_diagnostic_ids": causal_diagnostic_ids,
        }
    )


def sample_observation(
    observation_id: str = AVAIL_A,
    *,
    adapter_name: str = "adapter.alpha",
    adapter_version: str = "1.0.0",
    executable_hash: str = EXECUTABLE_HASH,
    available: bool = True,
    observed_at_utc: datetime = INSTANT,
    expires_at_utc: datetime | None = None,
) -> RuntimeAvailabilityObservation:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "availability_observation_id": observation_id,
        "adapter_name": adapter_name,
        "adapter_version": adapter_version,
        "executable_path": r"C:\adapters\alpha\adapter.exe",
        "executable_hash": executable_hash,
        "runtime_version": "3.12.0",
        "operating_system": OperatingSystem.WINDOWS,
        "available": available,
        "observed_at_utc": observed_at_utc,
        "expires_at_utc": (
            observed_at_utc + timedelta(hours=1)
            if expires_at_utc is None
            else expires_at_utc
        ),
        "network_required": False,
        "credentials_required": False,
    }
    if not available:
        payload["reason_code"] = "ADAPTER.UNAVAILABLE"
    return RuntimeAvailabilityObservation.model_validate(payload)


def sample_retry_decision(
    *,
    experiment_id: str = EXPERIMENT_ID,
    logical_slot_id: str = SLOT_A,
    predecessor_run_id: str = RUN_ID,
    decided_at_utc: datetime = INSTANT,
) -> RetryDecisionRecord:
    """A ``DENIED`` decision for an exhausted single-attempt budget."""
    return RetryDecisionRecord.model_validate(
        {
            "schema_version": "1.0.0",
            "experiment_id": experiment_id,
            "logical_slot_id": logical_slot_id,
            "predecessor_run_id": predecessor_run_id,
            "experiment_spec_hash": "a" * 64,
            "retry_policy": sample_retry_policy(maximum_attempts_per_slot=1),
            "created_attempt_count": 1,
            "predecessor_terminal_state": _R.FAILED,
            "primary_terminal_diagnostic_id": DIAG_ID,
            "outcome": RetryDecisionOutcome.DENIED,
            "denial_reason": RetryDenialReason.ATTEMPT_BUDGET_EXHAUSTED,
            "decided_at_utc": decided_at_utc,
        }
    )


# --------------------------------------------------------------------------
# Clock and identity doubles (plan section 11)
# --------------------------------------------------------------------------


class FixedClock:
    """Returns a caller-set UTC instant; ``advance`` moves it; no wall-clock read."""

    def __init__(self, instant: datetime) -> None:
        self._instant = require_utc(instant)

    def now_utc(self) -> datetime:
        return self._instant

    def advance(self, seconds: int) -> None:
        self._instant = self._instant + timedelta(seconds=seconds)


class SequentialIdentitySource:
    """Derives every identifier from a fixed seed and a per-kind counter.

    Identical construction order yields identical identifiers; the digest is
    reshaped by the existing ``_uuid4_shaped`` helper so every value is a
    canonical prefixed UUID4, and the attempt token is the 64-character
    hexadecimal digest of the same material (url-safe, within ``32..1024``).
    """

    def __init__(self, seed: str = "task6") -> None:
        self._seed = seed
        self._counters: dict[str, int] = {}

    def _digest(self, kind: str) -> str:
        counter = self._counters.get(kind, 0) + 1
        self._counters[kind] = counter
        return sha256_bytes(f"{self._seed}\x00{kind}\x00{counter}".encode())

    def new_experiment_id(self) -> str:
        return f"exp_{_uuid4_shaped(self._digest('experiment'))}"

    def new_run_id(self) -> str:
        return f"run_{_uuid4_shaped(self._digest('run'))}"

    def new_invocation_id(self) -> str:
        return f"inv_{_uuid4_shaped(self._digest('invocation'))}"

    def new_logical_slot_id(self) -> str:
        return f"slot_{_uuid4_shaped(self._digest('slot'))}"

    def new_attempt_token(self) -> str:
        return self._digest("attempt-token")


# --------------------------------------------------------------------------
# The backing store, the transaction views and the failure factory
# --------------------------------------------------------------------------

SOURCE_COMPONENT: Final = "doubles.experiments"
#: The bound Task 7's traversal declares (plan 8.2 node bound).
MAX_DIAGNOSTICS_PER_READ: Final = 256


class _Revisioned(Protocol):
    revision: int


class _Table[K, R]:
    """One live dictionary of committed rows, owned by the backing store."""

    __slots__ = ("live",)

    def __init__(self) -> None:
        self.live: dict[K, R] = {}


class _View[K, R]:
    """One transaction's private view of a table (task-local reading D3).

    ``snapshot`` and ``working`` are shallow copies of the live rows taken at
    ``begin()``; records are immutable, so copying the dictionary is enough.
    Reads are repeatable (snapshot plus this transaction's own writes). The
    compare-and-swap and insert predicates read ``authoritative`` -- this
    transaction's own write when it has one, otherwise the LIVE row -- so a
    winner committed by another transaction defeats them. ``commit`` publishes
    only the changed rows and only when none of them moved since ``begin()``.
    """

    def __init__(self, table: _Table[K, R]) -> None:
        self._table = table
        self._snapshot: dict[K, R] = dict(table.live)
        self._working: dict[K, R] = dict(table.live)

    def read(self, key: K) -> R | None:
        return self._working.get(key)

    def values(self) -> tuple[R, ...]:
        return tuple(self._working.values())

    def wrote(self, key: K) -> bool:
        return self._working.get(key) is not self._snapshot.get(key)

    def authoritative(self, key: K) -> R | None:
        if self.wrote(key):
            return self._working.get(key)
        return self._table.live.get(key)

    def exists_anywhere(self, key: K) -> bool:
        return key in self._working or key in self._table.live

    def index_candidates(self) -> tuple[R, ...]:
        """Every row an insert must be unique against: staged and live."""
        return (*self._working.values(), *self._table.live.values())

    def put(self, key: K, record: R) -> None:
        self._working[key] = record

    def changed(self) -> dict[K, R]:
        return {
            key: record
            for key, record in self._working.items()
            if record is not self._snapshot.get(key)
        }

    def moved(self) -> bool:
        live = self._table.live
        return any(
            live.get(key) is not self._snapshot.get(key) for key in self.changed()
        )

    def index_collides(self, index_key: Callable[[R], object | None]) -> bool:
        """Does any changed row share a non-``None`` index key with a live row of a
        different identity? Two transactions inserting distinct identities that
        collide on a unique index must not both publish."""
        live = self._table.live
        for key, record in self.changed().items():
            wanted = index_key(record)
            if wanted is None:
                continue
            for other_key, other in live.items():
                if other_key != key and index_key(other) == wanted:
                    return True
        return False

    def publish(self) -> None:
        self._table.live.update(self.changed())


class InMemoryBackingStore:
    """The explicit shared store a rebuilt unit of work observes.

    Holds the seven live tables. Only a committed transaction writes the five
    repository tables; the two reader tables are seeded here because the ports
    over them are read-only. ``run_events`` (Stage 6 plan 7.5) is keyed by
    ``(invocation_id, sequence)`` with an ``event_id`` uniqueness index checked at
    commit. Every inspection accessor returns a fresh sorted tuple, never a live
    collection.
    """

    def __init__(self) -> None:
        self.experiments: _Table[str, ExperimentRecord] = _Table()
        self.engine_runs: _Table[str, EngineRunRecord] = _Table()
        self.run_events: _Table[tuple[str, int], RunEvent] = _Table()
        self.command_invocations: _Table[str, CommandInvocationRecord] = _Table()
        self.retry_decisions: _Table[tuple[str, str], RetryDecisionRecord] = _Table()
        self.availability_observations: _Table[str, RuntimeAvailabilityObservation] = (
            _Table()
        )
        self.diagnostics: _Table[str, Diagnostic] = _Table()

    def seed_diagnostic(self, diagnostic: Diagnostic) -> None:
        if diagnostic.diagnostic_id in self.diagnostics.live:
            raise ValueError(f"diagnostic {diagnostic.diagnostic_id} is already seeded")
        self.diagnostics.live[diagnostic.diagnostic_id] = diagnostic

    def seed_availability_observation(
        self, observation: RuntimeAvailabilityObservation
    ) -> None:
        key = observation.availability_observation_id
        if key in self.availability_observations.live:
            raise ValueError(f"observation {key} is already seeded")
        self.availability_observations.live[key] = observation

    def committed_experiments(self) -> tuple[ExperimentRecord, ...]:
        live = self.experiments.live
        return tuple(live[key] for key in sorted(live))

    def committed_engine_runs(self) -> tuple[EngineRunRecord, ...]:
        live = self.engine_runs.live
        return tuple(live[key] for key in sorted(live))

    def committed_run_events(self) -> tuple[RunEvent, ...]:
        live = self.run_events.live
        return tuple(live[key] for key in sorted(live))

    def committed_command_invocations(self) -> tuple[CommandInvocationRecord, ...]:
        live = self.command_invocations.live
        return tuple(live[key] for key in sorted(live))

    def committed_retry_decisions(self) -> tuple[RetryDecisionRecord, ...]:
        live = self.retry_decisions.live
        return tuple(live[key] for key in sorted(live))


class _Failures:
    """Stage 5 failure values stamped with the double's injected clock instant."""

    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    def conflict(
        self,
        message: str,
        *,
        experiment_id: str | MISSING = MISSING,  # type: ignore[valid-type]
        run_id: str | MISSING = MISSING,  # type: ignore[valid-type]
        invocation_id: str | MISSING = MISSING,  # type: ignore[valid-type]
    ) -> Failure:
        return stage5_failure(
            CONCURRENCY_CONFLICT,
            message,
            source_component=SOURCE_COMPONENT,
            timestamp_utc=self._clock.now_utc(),
            experiment_id=experiment_id,
            run_id=run_id,
            invocation_id=invocation_id,
        )

    def invariant(
        self,
        message: str,
        *,
        experiment_id: str | MISSING = MISSING,  # type: ignore[valid-type]
        run_id: str | MISSING = MISSING,  # type: ignore[valid-type]
        invocation_id: str | MISSING = MISSING,  # type: ignore[valid-type]
    ) -> Failure:
        return stage5_failure(
            INVARIANT_VIOLATION,
            message,
            source_component=SOURCE_COMPONENT,
            timestamp_utc=self._clock.now_utc(),
            experiment_id=experiment_id,
            run_id=run_id,
            invocation_id=invocation_id,
        )


def _compare_and_swap[K, R: _Revisioned](
    view: _View[K, R],
    key: K,
    expected_revision: int,
    replacement: R,
    failures: _Failures,
    label: str,
) -> Result[R]:
    """The shared revision predicate of the three compare-and-swap repositories.

    A missing row or a revision mismatch is a zero-row update, hence
    ``PERSISTENCE.CONCURRENCY_CONFLICT`` (specification 23.2); a replacement that
    does not carry exactly ``expected_revision + 1`` is a programming error the
    persistence CHECK analogue reports as ``CORE.INVARIANT_VIOLATION``. Nothing
    is written on either failure and the candidate is never mutated.
    """
    current = view.authoritative(key)
    if current is None:
        return failures.conflict(f"{label} {key!r} does not exist for compare-and-swap")
    if current.revision != expected_revision:
        return failures.conflict(
            f"{label} {key!r} is at revision {current.revision}, "
            f"not {expected_revision}"
        )
    if replacement.revision != expected_revision + 1:
        return failures.invariant(
            f"{label} replacement must carry revision {expected_revision + 1}, "
            f"not {replacement.revision}"
        )
    view.put(key, replacement)
    return Success(outcome="SUCCESS", value=replacement)


# --------------------------------------------------------------------------
# The repositories and readers
# --------------------------------------------------------------------------


ExperimentCasHook = Callable[[int, ExperimentRecord], object]
RetryInsertHook = Callable[[RetryDecisionRecord], object]


class _Hooks:
    """The two one-shot coordination hooks, shared by a root and its transactions.

    Disabled by default; each fires exactly once, before the predicate it
    precedes, and is removed from the root BEFORE it is invoked, so a winner the
    hook commits through the same root does not re-trigger it. The first matching
    call from any transaction opened on the root consumes it. A hook's return
    value is ignored, so it can neither replace the candidate nor skip validation.
    """

    def __init__(self) -> None:
        self.experiment_cas: ExperimentCasHook | None = None
        self.retry_insert: RetryInsertHook | None = None

    def installed(self) -> tuple[str, ...]:
        names: list[str] = []
        if self.experiment_cas is not None:
            names.append("experiment_compare_and_swap")
        if self.retry_insert is not None:
            names.append("retry_decision_insert")
        return tuple(names)

    def take_experiment_cas(self) -> ExperimentCasHook | None:
        hook, self.experiment_cas = self.experiment_cas, None
        return hook

    def take_retry_insert(self) -> RetryInsertHook | None:
        hook, self.retry_insert = self.retry_insert, None
        return hook


class InMemoryExperimentRepository:
    """Dict keyed by ``experiment_id``; conflict on revision mismatch (plan 11)."""

    def __init__(
        self,
        view: _View[str, ExperimentRecord],
        failures: _Failures,
        hooks: _Hooks,
    ) -> None:
        self._view = view
        self._failures = failures
        self._hooks = hooks

    def get(self, experiment_id: str) -> Result[ExperimentRecord]:
        record = self._view.read(experiment_id)
        if record is None:
            return self._failures.invariant(
                f"experiment {experiment_id} does not exist",
                experiment_id=experiment_id,
            )
        return Success[ExperimentRecord](outcome="SUCCESS", value=record)

    def add(self, record: ExperimentRecord) -> Result[None]:
        if self._view.exists_anywhere(record.experiment_id):
            return self._failures.conflict(
                f"experiment {record.experiment_id} already exists",
                experiment_id=record.experiment_id,
            )
        self._view.put(record.experiment_id, record)
        return Success[None](outcome="SUCCESS", value=None)

    def compare_and_swap(
        self,
        expected_revision: int,
        replacement: ExperimentRecord,
    ) -> Result[ExperimentRecord]:
        hook = self._hooks.take_experiment_cas()
        if hook is not None:
            hook(expected_revision, replacement)
        return _compare_and_swap(
            self._view,
            replacement.experiment_id,
            expected_revision,
            replacement,
            self._failures,
            "experiment",
        )


class InMemoryEngineRunRepository:
    """Dict keyed by ``run_id`` with the attempt uniqueness index (plan 11), plus the
    ``run_events`` dict keyed by ``(invocation_id, sequence)`` with the ``event_id``
    uniqueness index (Stage 6 plan 7.5)."""

    def __init__(
        self,
        view: _View[str, EngineRunRecord],
        event_view: _View[tuple[str, int], RunEvent],
        failures: _Failures,
    ) -> None:
        self._view = view
        self._event_view = event_view
        self._failures = failures

    def get(self, run_id: str) -> Result[EngineRunRecord]:
        record = self._view.read(run_id)
        if record is None:
            return self._failures.invariant(f"run {run_id} does not exist")
        return Success[EngineRunRecord](outcome="SUCCESS", value=record)

    def add_attempt(self, record: EngineRunRecord) -> Result[None]:
        if self._view.exists_anywhere(record.run_id):
            return self._failures.conflict(
                f"run {record.run_id} already exists",
                experiment_id=record.experiment_id,
                run_id=record.run_id,
            )
        for existing in self._view.index_candidates():
            if (
                existing.experiment_id == record.experiment_id
                and existing.logical_slot_id == record.logical_slot_id
                and existing.attempt_number == record.attempt_number
            ):
                return self._failures.conflict(
                    f"attempt {record.attempt_number} of slot {record.logical_slot_id} "
                    f"already exists as {existing.run_id}",
                    experiment_id=record.experiment_id,
                    run_id=existing.run_id,
                )
        self._view.put(record.run_id, record)
        return Success[None](outcome="SUCCESS", value=None)

    def compare_and_swap(
        self,
        expected_revision: int,
        replacement: EngineRunRecord,
    ) -> Result[EngineRunRecord]:
        return _compare_and_swap(
            self._view,
            replacement.run_id,
            expected_revision,
            replacement,
            self._failures,
            "run",
        )

    def _slot_attempts(
        self, experiment_id: str, logical_slot_id: str
    ) -> tuple[EngineRunRecord, ...]:
        return tuple(
            sorted(
                (
                    record
                    for record in self._view.values()
                    if record.experiment_id == experiment_id
                    and record.logical_slot_id == logical_slot_id
                ),
                key=lambda record: record.attempt_number,
            )
        )

    def count_attempts(self, experiment_id: str, logical_slot_id: str) -> Result[int]:
        return Success[int](
            outcome="SUCCESS",
            value=len(self._slot_attempts(experiment_id, logical_slot_id)),
        )

    def latest_attempt(
        self,
        experiment_id: str,
        logical_slot_id: str,
    ) -> Result[EngineRunRecord | MISSING]:  # type: ignore[valid-type]
        attempts = self._slot_attempts(experiment_id, logical_slot_id)
        absent: Any = MISSING
        if not attempts:
            return Success(outcome="SUCCESS", value=absent)
        return Success(outcome="SUCCESS", value=attempts[-1])

    def get_by_attempt_number(
        self,
        experiment_id: str,
        logical_slot_id: str,
        attempt_number: int,
    ) -> Result[EngineRunRecord | MISSING]:  # type: ignore[valid-type]
        for record in self._slot_attempts(experiment_id, logical_slot_id):
            if record.attempt_number == attempt_number:
                return Success(outcome="SUCCESS", value=record)
        absent: Any = MISSING
        return Success(outcome="SUCCESS", value=absent)

    def append_event(self, event: RunEvent) -> Result[RunEvent]:
        """Stage 6 plan 7.5: idempotent on an identical event, a conflict on a
        different content under one key or an ``event_id`` reused under another."""
        if not isinstance(event, RunEvent):
            raise TypeError("event must be a RunEvent")
        key = (event.invocation_id, event.sequence)
        existing = self._event_view.authoritative(key)
        if existing is not None:
            if existing.content_hash == event.content_hash:
                return Success[RunEvent](outcome="SUCCESS", value=existing)
            return self._failures.conflict(
                f"event {event.sequence} of invocation {event.invocation_id} is "
                "already stored with another content hash",
                invocation_id=event.invocation_id,
            )
        for candidate in self._event_view.index_candidates():
            if candidate.event_id == event.event_id:
                return self._failures.conflict(
                    f"event {event.event_id} is already stored at sequence "
                    f"{candidate.sequence} of invocation {candidate.invocation_id}",
                    invocation_id=event.invocation_id,
                )
        self._event_view.put(key, event)
        return Success[RunEvent](outcome="SUCCESS", value=event)

    def list_events(self, invocation_id: str) -> Result[tuple[RunEvent, ...]]:
        """Every stored event of the invocation, sequence-ordered."""
        matching = sorted(
            (
                record
                for record in self._event_view.values()
                if record.invocation_id == invocation_id
            ),
            key=lambda record: record.sequence,
        )
        return Success[tuple[RunEvent, ...]](outcome="SUCCESS", value=tuple(matching))


class InMemoryRetryDecisionRepository:
    """Dict keyed by ``(logical_slot_id, predecessor_run_id)``; atomic insert-if-absent
    with the injected pre-insert hook (plan 11)."""

    def __init__(
        self,
        view: _View[tuple[str, str], RetryDecisionRecord],
        failures: _Failures,
        hooks: _Hooks,
    ) -> None:
        self._view = view
        self._failures = failures
        self._hooks = hooks

    def get_by_predecessor(
        self,
        logical_slot_id: str,
        predecessor_run_id: str,
    ) -> Result[RetryDecisionRecord]:
        record = self._view.read((logical_slot_id, predecessor_run_id))
        if record is None:
            return self._failures.invariant(
                f"no retry decision for predecessor {predecessor_run_id} of slot "
                f"{logical_slot_id}",
            )
        return Success[RetryDecisionRecord](outcome="SUCCESS", value=record)

    def insert_if_absent(
        self,
        record: RetryDecisionRecord,
    ) -> Result[RetryDecisionInsertOutcome]:
        hook = self._hooks.take_retry_insert()
        if hook is not None:
            hook(record)
        key = (record.logical_slot_id, record.predecessor_run_id)
        existing = self._view.authoritative(key)
        if existing is not None:
            return Success[RetryDecisionInsertOutcome](
                outcome="SUCCESS",
                value=RetryDecisionInsertOutcome(inserted=False, record=existing),
            )
        self._view.put(key, record)
        return Success[RetryDecisionInsertOutcome](
            outcome="SUCCESS",
            value=RetryDecisionInsertOutcome(inserted=True, record=record),
        )


class InMemoryCommandInvocationRepository:
    """Dict keyed by ``invocation_id`` with the ``(run_id, command_kind)``
    non-terminal index (plan 11; spec 23.3.1)."""

    def __init__(
        self, view: _View[str, CommandInvocationRecord], failures: _Failures
    ) -> None:
        self._view = view
        self._failures = failures

    def get(self, invocation_id: str) -> Result[CommandInvocationRecord]:
        record = self._view.read(invocation_id)
        if record is None:
            return self._failures.invariant(
                f"invocation {invocation_id} does not exist",
                invocation_id=invocation_id,
            )
        return Success[CommandInvocationRecord](outcome="SUCCESS", value=record)

    def add(self, record: CommandInvocationRecord) -> Result[None]:
        if self._view.exists_anywhere(record.invocation_id):
            return self._failures.conflict(
                f"invocation {record.invocation_id} already exists",
                invocation_id=record.invocation_id,
            )
        if record.state not in TERMINAL_COMMAND_INVOCATION_STATES and not _is_missing(
            record.run_id
        ):
            for existing in self._view.index_candidates():
                if (
                    existing.state not in TERMINAL_COMMAND_INVOCATION_STATES
                    and existing.command_kind is record.command_kind
                    and existing.run_id == record.run_id
                ):
                    return self._failures.conflict(
                        f"run {record.run_id} already has an open "
                        f"{record.command_kind.value} invocation "
                        f"{existing.invocation_id}",
                        invocation_id=existing.invocation_id,
                    )
        self._view.put(record.invocation_id, record)
        return Success[None](outcome="SUCCESS", value=None)

    def compare_and_swap(
        self,
        expected_revision: int,
        replacement: CommandInvocationRecord,
    ) -> Result[CommandInvocationRecord]:
        return _compare_and_swap(
            self._view,
            replacement.invocation_id,
            expected_revision,
            replacement,
            self._failures,
            "invocation",
        )

    def list_for_run(
        self,
        run_id: str,
        command_kind: CommandKind,
    ) -> Result[tuple[CommandInvocationRecord, ...]]:
        matching = sorted(
            (
                record
                for record in self._view.values()
                if record.command_kind is command_kind
                and not _is_missing(record.run_id)
                and record.run_id == run_id
            ),
            key=lambda record: (record.created_at_utc, record.invocation_id),
        )
        return Success[tuple[CommandInvocationRecord, ...]](
            outcome="SUCCESS", value=tuple(matching)
        )


class InMemoryAvailabilityObservationReader:
    """Ordered store; ``list_for_adapter`` returns a deterministically sorted
    tuple (plan 11), unbounded so no qualifying observation is dropped."""

    def __init__(
        self, view: _View[str, RuntimeAvailabilityObservation], failures: _Failures
    ) -> None:
        self._view = view
        self._failures = failures

    def get(self, observation_id: str) -> Result[RuntimeAvailabilityObservation]:
        record = self._view.read(observation_id)
        if record is None:
            return self._failures.invariant(
                f"availability observation {observation_id} does not exist"
            )
        return Success[RuntimeAvailabilityObservation](outcome="SUCCESS", value=record)

    def list_for_adapter(
        self,
        adapter_name: str,
        adapter_version: str,
        executable_hash: str,
    ) -> Result[tuple[RuntimeAvailabilityObservation, ...]]:
        matching = [
            record
            for record in self._view.values()
            if record.adapter_name == adapter_name
            and record.adapter_version == adapter_version
            and record.executable_hash == executable_hash
        ]
        matching.sort(key=lambda record: record.availability_observation_id)
        return Success[tuple[RuntimeAvailabilityObservation, ...]](
            outcome="SUCCESS", value=tuple(matching)
        )


class InMemoryDiagnosticReader:
    """Ordered store; ``get`` and ``get_many`` are primitive lookups only -- no
    traversal (plan 8.2, 11)."""

    def __init__(self, view: _View[str, Diagnostic], failures: _Failures) -> None:
        self._view = view
        self._failures = failures

    def get(self, diagnostic_id: str) -> Result[Diagnostic]:
        record = self._view.read(diagnostic_id)
        if record is None:
            return self._failures.invariant(
                f"diagnostic {diagnostic_id} does not exist"
            )
        return Success[Diagnostic](outcome="SUCCESS", value=record)

    def get_many(
        self, diagnostic_ids: tuple[str, ...]
    ) -> Result[tuple[Diagnostic, ...]]:
        if len(set(diagnostic_ids)) != len(diagnostic_ids):
            return self._failures.invariant("diagnostic identifiers must be unique")
        if len(diagnostic_ids) > MAX_DIAGNOSTICS_PER_READ:
            return self._failures.invariant(
                f"at most {MAX_DIAGNOSTICS_PER_READ} diagnostics per read"
            )
        found: list[Diagnostic] = []
        for diagnostic_id in diagnostic_ids:
            record = self._view.read(diagnostic_id)
            if record is None:
                return self._failures.invariant(
                    f"diagnostic {diagnostic_id} does not exist"
                )
            found.append(record)
        found.sort(key=lambda record: record.diagnostic_id)
        return Success[tuple[Diagnostic, ...]](outcome="SUCCESS", value=tuple(found))


# --------------------------------------------------------------------------
# The unit of work
# --------------------------------------------------------------------------


class _State(StrEnum):
    ROOT = "ROOT"
    ACTIVE = "ACTIVE"
    CLOSED = "CLOSED"


def _attempt_index_key(record: EngineRunRecord) -> tuple[str, str, int]:
    """Specification 23.3: the unique attempt index of one slot."""
    return (record.experiment_id, record.logical_slot_id, record.attempt_number)


def _open_invocation_index_key(record: CommandInvocationRecord) -> object | None:
    """Specification 23.3.1: at most one active invocation per run and kind; a
    ``DESCRIBE`` (no ``run_id``) and a terminal row never participate."""
    if record.state in TERMINAL_COMMAND_INVOCATION_STATES or _is_missing(record.run_id):
        return None
    return (record.run_id, record.command_kind)


def _event_id_index_key(record: RunEvent) -> str:
    """Stage 6 plan 7.5: one ``event_id`` under one ``(invocation_id, sequence)``."""
    return record.event_id


class _Bound:
    """The six repositories of one active transaction."""

    def __init__(
        self, store: InMemoryBackingStore, failures: _Failures, hooks: _Hooks
    ) -> None:
        self.experiment_view = _View(store.experiments)
        self.run_view = _View(store.engine_runs)
        self.event_view = _View(store.run_events)
        self.invocation_view = _View(store.command_invocations)
        self.decision_view = _View(store.retry_decisions)
        self.observation_view = _View(store.availability_observations)
        self.diagnostic_view = _View(store.diagnostics)
        self.experiments = InMemoryExperimentRepository(
            self.experiment_view, failures, hooks
        )
        self.engine_runs = InMemoryEngineRunRepository(
            self.run_view, self.event_view, failures
        )
        self.command_invocations = InMemoryCommandInvocationRepository(
            self.invocation_view, failures
        )
        self.retry_decisions = InMemoryRetryDecisionRepository(
            self.decision_view, failures, hooks
        )
        self.availability_observations = InMemoryAvailabilityObservationReader(
            self.observation_view, failures
        )
        self.diagnostics = InMemoryDiagnosticReader(self.diagnostic_view, failures)

    def writable_views(
        self,
    ) -> tuple[
        _View[str, ExperimentRecord],
        _View[str, EngineRunRecord],
        _View[tuple[str, int], RunEvent],
        _View[str, CommandInvocationRecord],
        _View[tuple[str, str], RetryDecisionRecord],
    ]:
        return (
            self.experiment_view,
            self.run_view,
            self.event_view,
            self.invocation_view,
            self.decision_view,
        )


class InMemoryUnitOfWork:
    """Snapshot-isolated, all-or-nothing transaction over every registered store.

    The object constructed by a test is the **root**: it holds the backing store,
    the clock the double stamps failure diagnostics with, and the two test-only
    hooks. ``begin()`` returns a new **active** transaction sharing those; the
    root itself never holds staged writes. On the active transaction the six
    repository members are bound to private views; ``commit()`` validates that
    no changed row moved underneath the transaction and that no inserted row
    collides on a unique index with a row committed since ``begin()`` (else a
    ``PERSISTENCE.CONCURRENCY_CONFLICT`` and a rollback -- no lost update), then
    publishes every changed row; ``rollback()`` discards the views and is
    idempotent. Reads are snapshot reads (the copies taken at ``begin()`` plus
    this transaction's own writes); only the compare-and-swap and insert
    predicates consult the live store. Nesting, committing a closed transaction
    and reading a repository off the root or a closed transaction are programmer
    defects and raise ``RuntimeError``. The context-manager form rolls back on
    any exit that did not commit. Rebuilding a root over the same store observes
    exactly the committed rows. Declared limitation: commit validates the rows
    the transaction changed (identity, revision and unique indexes), not rows it
    merely read; every Task 6 operation protects its read set by comparing the
    expected revision it was given, and Stage 8's SQLite writer serialisation
    makes the read-only interleaving unconstructible there.
    """

    def __init__(
        self,
        store: InMemoryBackingStore,
        *,
        clock: Clock | None = None,
    ) -> None:
        self._store = store
        self._clock: Clock = FixedClock(INSTANT) if clock is None else clock
        self._hooks = _Hooks()
        self._state = _State.ROOT
        self._bound: _Bound | None = None

    # -- Test-only coordination hooks (task prompt section 10) ------------------

    @property
    def hooks_installed(self) -> tuple[str, ...]:
        return self._hooks.installed()

    def _require_root(self) -> None:
        if self._state is not _State.ROOT:
            raise RuntimeError("hooks are installed and reset on the root unit of work")

    def install_experiment_compare_and_swap_hook(self, hook: ExperimentCasHook) -> None:
        self._require_root()
        if self._hooks.experiment_cas is not None:
            raise RuntimeError(
                "an experiment compare-and-swap hook is already installed"
            )
        self._hooks.experiment_cas = hook

    def install_retry_decision_insert_hook(self, hook: RetryInsertHook) -> None:
        self._require_root()
        if self._hooks.retry_insert is not None:
            raise RuntimeError("a retry-decision insert hook is already installed")
        self._hooks.retry_insert = hook

    def reset_hooks(self) -> None:
        self._require_root()
        self._hooks.experiment_cas = None
        self._hooks.retry_insert = None

    # -- Lifecycle -----------------------------------------------------------------

    @property
    def active(self) -> bool:
        return self._state is _State.ACTIVE

    def begin(self) -> InMemoryUnitOfWork:
        if self._state is not _State.ROOT:
            raise RuntimeError(
                "nested transactions are not supported: begin() is valid on the root "
                "unit of work only"
            )
        transaction = InMemoryUnitOfWork(self._store, clock=self._clock)
        transaction._hooks = self._hooks
        transaction._bound = _Bound(self._store, _Failures(self._clock), self._hooks)
        transaction._state = _State.ACTIVE
        return transaction

    def _require_bound(self) -> _Bound:
        if self._state is _State.CLOSED:
            raise RuntimeError("the transaction is closed")
        if self._state is _State.ROOT or self._bound is None:
            raise RuntimeError("no active transaction: call begin() first")
        return self._bound

    def commit(self) -> Result[None]:
        bound = self._require_bound()
        if any(view.moved() for view in bound.writable_views()):
            self.rollback()
            return _Failures(self._clock).conflict(
                "a row changed by this transaction moved before commit"
            )
        if (
            bound.run_view.index_collides(_attempt_index_key)
            or bound.invocation_view.index_collides(_open_invocation_index_key)
            or bound.event_view.index_collides(_event_id_index_key)
        ):
            self.rollback()
            return _Failures(self._clock).conflict(
                "a row inserted by this transaction collides with a unique index of "
                "a row committed since it began"
            )
        for view in bound.writable_views():
            view.publish()
        self._close()
        return Success[None](outcome="SUCCESS", value=None)

    def rollback(self) -> None:
        if self._state is _State.ACTIVE:
            self._close()

    def _close(self) -> None:
        self._state = _State.CLOSED
        self._bound = None

    def __enter__(self) -> InMemoryUnitOfWork:
        self._require_bound()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.rollback()

    # -- Repository members (plan 10; task-local reading D2) ----------------------

    @property
    def experiments(self) -> InMemoryExperimentRepository:
        return self._require_bound().experiments

    @property
    def engine_runs(self) -> InMemoryEngineRunRepository:
        return self._require_bound().engine_runs

    @property
    def command_invocations(self) -> InMemoryCommandInvocationRepository:
        return self._require_bound().command_invocations

    @property
    def retry_decisions(self) -> InMemoryRetryDecisionRepository:
        return self._require_bound().retry_decisions

    @property
    def availability_observations(self) -> InMemoryAvailabilityObservationReader:
        return self._require_bound().availability_observations

    @property
    def diagnostics(self) -> InMemoryDiagnosticReader:
        return self._require_bound().diagnostics


def _conforms(unit_of_work: UnitOfWork) -> UnitOfWork:
    """A static conformance probe: the double satisfies the protocol structurally."""
    return unit_of_work


_PROBE: Final[Callable[[InMemoryUnitOfWork], UnitOfWork]] = _conforms


# --------------------------------------------------------------------------
# Task 7 additions: read-discipline clocks, a call-recording unit of work and the
# retry fixture material (plan 12 Task 7 focused RED: "a clock double that fails when
# called and repositories that record every call")
# --------------------------------------------------------------------------


def sequential_diagnostic_id(index: int) -> str:
    """A canonical ``diag_`` UUID4 whose lexical order is the index order.

    Version nibble ``4`` and variant nibble ``8`` are fixed; the first group is the
    zero-padded index, so a graph of up to ``0xffffffff`` nodes sorts by index and
    every ``causal_diagnostic_ids`` tuple built from ascending indexes is already
    sorted and unique.
    """
    if not 0 <= index <= 0xFFFFFFFF:
        raise ValueError("index must fit eight hexadecimal digits")
    return f"diag_{index:08x}-0000-4000-8000-000000000000"


def sample_allowed_retry_decision(
    *,
    experiment_id: str = EXPERIMENT_ID,
    logical_slot_id: str = SLOT_A,
    predecessor_run_id: str = RUN_ID,
    experiment_spec_hash: str = "a" * 64,
    retry_policy: RetryPolicy | None = None,
    created_attempt_count: int = 1,
    predecessor_terminal_state: EngineRunState = _R.FAILED,
    primary_terminal_diagnostic_id: str = DIAG_ID,
    predecessor_completed_at_utc: datetime = INSTANT + timedelta(seconds=5),
    availability_observation_id: str | None = None,
    decided_at_utc: datetime = INSTANT + timedelta(minutes=1),
) -> RetryDecisionRecord:
    """An ``ALLOWED`` decision reserving ``created_attempt_count + 1``.

    ``retry_not_before_utc`` is the predecessor's terminal completion instant plus
    the policy delay (plan 8.4); the default completion instant equals
    ``sample_run(<terminal>).updated_at_utc``.
    """
    policy = sample_retry_policy() if retry_policy is None else retry_policy
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "experiment_id": experiment_id,
        "logical_slot_id": logical_slot_id,
        "predecessor_run_id": predecessor_run_id,
        "experiment_spec_hash": experiment_spec_hash,
        "retry_policy": policy,
        "created_attempt_count": created_attempt_count,
        "predecessor_terminal_state": predecessor_terminal_state,
        "primary_terminal_diagnostic_id": primary_terminal_diagnostic_id,
        "outcome": RetryDecisionOutcome.ALLOWED,
        "retry_not_before_utc": predecessor_completed_at_utc
        + timedelta(seconds=policy.retry_delay_seconds),
        "reserved_successor_attempt_number": created_attempt_count + 1,
        "decided_at_utc": decided_at_utc,
    }
    if availability_observation_id is not None:
        payload["availability_observation_id"] = availability_observation_id
    return RetryDecisionRecord.model_validate(payload)


class FailingClock:
    """A conforming clock whose every read is a test failure.

    Installed on the paths plan 8.4 phase 1 and 8.5 step 2 declare clock-free
    (existing-row replay, existing-successor replay): a read raises, so the
    assertion cannot pass by accident.
    """

    def now_utc(self) -> datetime:
        raise AssertionError("the clock must not be read on this path")


class CountingClock(FixedClock):
    """A ``FixedClock`` that counts its reads, so a test can pin exactly one."""

    def __init__(self, instant: datetime) -> None:
        super().__init__(instant)
        self.reads = 0

    def now_utc(self) -> datetime:
        self.reads += 1
        return super().now_utc()


class CallRecorder:
    """The ordered ``(member, method)`` log shared by a recording root and its
    transactions."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def of(self, member: str) -> tuple[str, ...]:
        """Every method recorded against one member, in call order."""
        return tuple(method for name, method in self.calls if name == member)

    def repositories(self) -> tuple[tuple[str, str], ...]:
        """Every repository or reader call, excluding the unit-of-work lifecycle."""
        return tuple(call for call in self.calls if call[0] != "unit_of_work")


class _RecordingMember:
    """Delegates every attribute to ``target``; records each method call first."""

    def __init__(self, member: str, target: object, recorder: CallRecorder) -> None:
        self._member = member
        self._target = target
        self._recorder = recorder

    def __getattr__(self, name: str) -> Any:
        attribute = getattr(self._target, name)
        if not callable(attribute):
            return attribute

        def call(*args: Any, **kwargs: Any) -> Any:
            self._recorder.calls.append((self._member, name))
            return attribute(*args, **kwargs)

        return call


class RecordingUnitOfWork:
    """A ``UnitOfWork`` over an ``InMemoryUnitOfWork`` that records every call.

    Structurally the protocol: ``begin()`` returns a recording transaction over
    the inner ``begin()``; ``commit`` and ``rollback`` delegate; each of the six
    members is a proxy that appends ``(member, method)`` to the shared
    ``CallRecorder`` before delegating. A call is recorded whether or not it
    succeeds, so a test can prove that a path performed no repository read at
    all. Hooks stay on the inner root; nothing here changes the double's
    semantics.
    """

    def __init__(
        self, inner: InMemoryUnitOfWork, recorder: CallRecorder | None = None
    ) -> None:
        self._inner = inner
        self.recorder = CallRecorder() if recorder is None else recorder

    @property
    def calls(self) -> tuple[tuple[str, str], ...]:
        return tuple(self.recorder.calls)

    def begin(self) -> RecordingUnitOfWork:
        self.recorder.calls.append(("unit_of_work", "begin"))
        return RecordingUnitOfWork(self._inner.begin(), self.recorder)

    def commit(self) -> Result[None]:
        self.recorder.calls.append(("unit_of_work", "commit"))
        return self._inner.commit()

    def rollback(self) -> None:
        self.recorder.calls.append(("unit_of_work", "rollback"))
        self._inner.rollback()

    def _member(self, name: str) -> Any:
        return _RecordingMember(name, getattr(self._inner, name), self.recorder)

    @property
    def experiments(self) -> ExperimentRepository:
        return cast("ExperimentRepository", self._member("experiments"))

    @property
    def engine_runs(self) -> EngineRunRepository:
        return cast("EngineRunRepository", self._member("engine_runs"))

    @property
    def command_invocations(self) -> CommandInvocationRepository:
        return cast("CommandInvocationRepository", self._member("command_invocations"))

    @property
    def retry_decisions(self) -> RetryDecisionRepository:
        return cast("RetryDecisionRepository", self._member("retry_decisions"))

    @property
    def availability_observations(self) -> RuntimeAvailabilityObservationReader:
        return cast(
            "RuntimeAvailabilityObservationReader",
            self._member("availability_observations"),
        )

    @property
    def diagnostics(self) -> DiagnosticReader:
        return cast("DiagnosticReader", self._member("diagnostics"))


_RECORDING_PROBE: Final[Callable[[RecordingUnitOfWork], UnitOfWork]] = _conforms


class _OverriddenMember:
    """Delegates every attribute to ``target`` except the supplied method overrides."""

    def __init__(
        self, target: object, overrides: Mapping[str, Callable[..., object]]
    ) -> None:
        self._target = target
        self._overrides = overrides

    def __getattr__(self, name: str) -> Any:
        override = self._overrides.get(name)
        if override is not None:
            return override
        return getattr(self._target, name)


class MemberOverridingUnitOfWork:
    """A ``UnitOfWork`` over an ``InMemoryUnitOfWork`` in which one member's named
    methods are replaced by test-supplied callables.

    Simulates the repository faults and answers the in-memory double cannot produce
    (a Stage 8 read fault on ``count_attempts`` or ``list_for_adapter``, a
    ``latest_attempt`` that reports ``MISSING`` beside a stored run, an
    ``add_attempt`` that loses). Every other member, ``commit`` and ``rollback``
    delegate; ``begin()`` returns a wrapper over the inner transaction and counts
    the transactions opened in ``begins`` (shared by the root and its transactions),
    so a test can pin the reload-once driver's two attempts.
    """

    def __init__(
        self,
        inner: InMemoryUnitOfWork,
        member: str,
        overrides: Mapping[str, Callable[..., object]],
        counter: list[int] | None = None,
    ) -> None:
        self._inner = inner
        self._member = member
        self._overrides = overrides
        self._counter = [0] if counter is None else counter

    @property
    def begins(self) -> int:
        return self._counter[0]

    def begin(self) -> MemberOverridingUnitOfWork:
        self._counter[0] += 1
        return MemberOverridingUnitOfWork(
            self._inner.begin(), self._member, self._overrides, self._counter
        )

    def commit(self) -> Result[None]:
        return self._inner.commit()

    def rollback(self) -> None:
        self._inner.rollback()

    def _member_of(self, name: str) -> Any:
        target = getattr(self._inner, name)
        if name != self._member:
            return target
        return _OverriddenMember(target, self._overrides)

    @property
    def experiments(self) -> ExperimentRepository:
        return cast("ExperimentRepository", self._member_of("experiments"))

    @property
    def engine_runs(self) -> EngineRunRepository:
        return cast("EngineRunRepository", self._member_of("engine_runs"))

    @property
    def command_invocations(self) -> CommandInvocationRepository:
        return cast(
            "CommandInvocationRepository", self._member_of("command_invocations")
        )

    @property
    def retry_decisions(self) -> RetryDecisionRepository:
        return cast("RetryDecisionRepository", self._member_of("retry_decisions"))

    @property
    def availability_observations(self) -> RuntimeAvailabilityObservationReader:
        return cast(
            "RuntimeAvailabilityObservationReader",
            self._member_of("availability_observations"),
        )

    @property
    def diagnostics(self) -> DiagnosticReader:
        return cast("DiagnosticReader", self._member_of("diagnostics"))


_OVERRIDING_PROBE: Final[Callable[[MemberOverridingUnitOfWork], UnitOfWork]] = _conforms
