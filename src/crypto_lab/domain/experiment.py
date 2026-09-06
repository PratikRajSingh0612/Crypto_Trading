"""Experiment specification, experiment record and the queue-time freeze rules.

Stage 5 plan sections 3.5, 3.6 and 7, under specification sections 10.2, 11.3,
11.5 and 16. Placement follows plan section 2.3: every Stage 5 canonical record
and its state-governed invariants live in ``domain``, while the operations that
read and write them (create, replace, queue, cancel, ...) are Task 6's
application services in ``experiments``. That is also why ``ExperimentSpecDraft``
-- the value object a caller supplies, exactly spec fields 2-10 -- is defined
here rather than beside the request models that will wrap it:
``build_experiment_spec`` consumes it, and ``domain`` cannot import
``experiments``.

Two hashes, neither a self-hash (plan section 3.5, specification 10.2):

- ``configuration_hash`` is ``profile_hash(EXPERIMENT_CONFIGURATION_V1, payload)``
  over exactly the request-supplied material base configuration hash plus spec
  fields 2-10 in canonical JSON form; ``schema_version``, ``configuration_hash``
  and ``created_at_utc`` are excluded. ``build_experiment_spec`` derives it. The
  spec alone cannot re-verify it, because the material hash is deliberately not
  a spec field (``experiments`` cannot import ``configuration``, so requests carry
  it by value); plan section 7 check 3 re-verifies it at queue time from the
  request through ``assert_queue_freeze``.
- ``spec_hash`` is ``profile_hash(EXPERIMENT_SPEC_V1, payload)`` over the complete
  canonical spec, including ``schema_version``, ``configuration_hash`` and
  ``created_at_utc``. ``ExperimentRecord`` recomputes and compares it.

State-governed optionality is ``MISSING``, never ``None`` (plan section 3.1).
Terminal immutability, compare-and-swap, edge ownership and the carry-forward
rule (plan sections 4 and 9) are service rules and are deliberately not encoded
here: a record answers only whether its own shape is consistent with its state.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import Final, Literal, Self, cast

from pydantic import Field, JsonValue, TypeAdapter, field_validator, model_validator
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.comparison_levels import ComparisonLevel
from crypto_lab.domain.compatibility import CompatibilityOutcome
from crypto_lab.domain.financial import NonNegativeDecimal
from crypto_lab.domain.hashing import HashingProfile, profile_hash
from crypto_lab.domain.identifiers import (
    ApproximationId,
    AvailabilityObservationId,
    CorrelationId,
    ExperimentId,
    LogicalSlotId,
    NormalizedIdentifier,
    Sha256,
)
from crypto_lab.domain.lifecycle import ExperimentState
from crypto_lab.domain.records import Money
from crypto_lab.domain.retry import RetryPolicy
from crypto_lab.domain.time import CalendarValidUtcDateTime
from crypto_lab.domain.versioning import SemanticVersion

MAX_SELECTED_ENGINE_SLOTS: Final = 8
MAX_SLOT_ORDINAL: Final = MAX_SELECTED_ENGINE_SLOTS - 1
MAX_PRECISION: Final = 18
MAX_APPROXIMATION_IDS: Final = 64
MAX_FEE_RATE: Final = Decimal("1")

#: The material base configuration hash arrives by value on a request, so every
#: entry point that consumes it validates the ``Sha256`` shape before hashing.
_SHA256: Final[TypeAdapter[str]] = TypeAdapter(Sha256)

#: Plan section 3.6 row 6: ``slot_compatibility`` is absent before ``QUEUED``. It is
#: required in every later state reachable only through ``QUEUED``; ``CANCELLED`` is
#: the one state reachable both before and after the freeze (plan section 4 gives
#: ``cancel_experiment`` the ``DRAFT`` and ``VALIDATED`` edges), so it admits either.
_PRE_QUEUE_STATES: Final[frozenset[ExperimentState]] = frozenset(
    {ExperimentState.DRAFT, ExperimentState.VALIDATED}
)


def _is_missing(value: object) -> bool:
    return value is MISSING


class SlippageModel(StrEnum):
    """Plan section 3.5: the Project 1 slippage vocabulary, extended additively."""

    NONE = "NONE"
    FIXED_BASIS_POINTS = "FIXED_BASIS_POINTS"


class SignalToOrderTiming(StrEnum):
    """Plan section 3.5: when a bar-close signal becomes an order intent."""

    NEXT_BAR_OPEN = "NEXT_BAR_OPEN"
    SAME_BAR_CLOSE = "SAME_BAR_CLOSE"


class BarOrderPriority(StrEnum):
    """Plan section 3.5: the order in which one bar's exits and entries apply."""

    EXITS_BEFORE_ENTRIES = "EXITS_BEFORE_ENTRIES"
    ENTRIES_BEFORE_EXITS = "ENTRIES_BEFORE_EXITS"


class FillConvention(StrEnum):
    """Plan section 3.5: whether an order intent fills whole or may fill partially."""

    FULL_FILL = "FULL_FILL"
    PARTIAL_FILLS_ALLOWED = "PARTIAL_FILLS_ALLOWED"


class AdapterIdentity(CanonicalModel):
    """A pinned adapter name and version, plan section 3.5."""

    adapter_name: NormalizedIdentifier
    adapter_version: SemanticVersion


class EngineIdentity(CanonicalModel):
    """A pinned engine name and version, plan section 3.5."""

    engine_name: NormalizedIdentifier
    engine_version: SemanticVersion


class SelectedEngineSlot(CanonicalModel):
    """One selected engine slot of an experiment, plan section 3.5.

    A nested value object, so it carries no envelope ``schema_version`` (plan
    section 3.1). The collection rules -- ordinals ``0..n-1`` ascending, unique
    slot identifiers, unique adapter/engine pairs -- belong to the enclosing spec.
    """

    logical_slot_id: LogicalSlotId
    slot_ordinal: int = Field(ge=0, le=MAX_SLOT_ORDINAL)
    adapter: AdapterIdentity
    engine: EngineIdentity


class FeeAssumptions(CanonicalModel):
    """Maker and taker fee rates, each a non-negative rate of at most one."""

    maker_fee_rate: NonNegativeDecimal
    taker_fee_rate: NonNegativeDecimal

    @field_validator("maker_fee_rate", "taker_fee_rate")
    @classmethod
    def validate_rate_bound(cls, value: Decimal) -> Decimal:
        if value > MAX_FEE_RATE:
            raise ValueError("fee rates must be at most 1")
        return value


class SlippageAssumptions(CanonicalModel):
    """A slippage model and its basis points, present exactly under the fixed model."""

    model: SlippageModel
    basis_points: NonNegativeDecimal | MISSING = MISSING  # type: ignore[valid-type]

    @model_validator(mode="after")
    def validate_basis_points_follow_the_model(self) -> Self:
        present = not _is_missing(self.basis_points)
        if self.model is SlippageModel.FIXED_BASIS_POINTS and not present:
            raise ValueError(
                "basis_points is required under slippage model FIXED_BASIS_POINTS"
            )
        if self.model is not SlippageModel.FIXED_BASIS_POINTS and present:
            raise ValueError("basis_points is present only under FIXED_BASIS_POINTS")
        return self


class ExecutionAssumptions(CanonicalModel):
    """Level 2 execution and rounding assumptions, plan section 3.5.

    Prices and quantities are quantized only when sizing intent becomes an order
    intent (specification 12.3.2), using these precisions and the fixed rounding.
    """

    signal_to_order_timing: SignalToOrderTiming
    bar_order_priority: BarOrderPriority
    fill_convention: FillConvention
    price_precision: int = Field(ge=0, le=MAX_PRECISION)
    quantity_precision: int = Field(ge=0, le=MAX_PRECISION)
    rounding_mode: Literal["ROUND_HALF_EVEN"]


def _validate_selected_engine_slots(slots: tuple[SelectedEngineSlot, ...]) -> None:
    """Plan section 3.5 row 4 and section 7 check 5, as one shared rule."""
    if not slots:
        raise ValueError("at least one engine slot must be selected")
    ordinals = tuple(slot.slot_ordinal for slot in slots)
    if ordinals != tuple(range(len(slots))):
        raise ValueError("slot ordinals must run 0..n-1 in ascending tuple order")
    slot_ids = tuple(slot.logical_slot_id for slot in slots)
    if len(set(slot_ids)) != len(slot_ids):
        raise ValueError("logical_slot_id must be unique across selected slots")
    pairs = tuple(
        (
            slot.adapter.adapter_name,
            slot.adapter.adapter_version,
            slot.engine.engine_name,
            slot.engine.engine_version,
        )
        for slot in slots
    )
    if len(set(pairs)) != len(pairs):
        raise ValueError("each adapter and engine pair may be selected only once")


def _validate_starting_balance(balance: Money) -> None:
    """Plan section 3.5 row 5: ``Money`` with a positive amount.

    ``Money`` itself admits zero and negative amounts, and its released
    ``domain/money-v1`` schema must stay byte-identical, so positivity is a rule
    of the enclosing record rather than of the nested type.
    """
    if balance.amount <= 0:
        raise ValueError("starting balance must be positive")


class ExperimentSpecDraft(CanonicalModel):
    """Exactly ``ExperimentSpec`` fields 2-10: the material inputs a caller supplies.

    Plan sections 3.5 and 3.11. A nested value object, so it carries no envelope
    ``schema_version``; ``build_experiment_spec`` adds the envelope, derives
    ``configuration_hash`` and stamps ``created_at_utc``. The slot and balance
    rules are enforced here as well as on the spec, because ``create_experiment``
    validates the draft before any clock read (plan section 10.1).
    """

    strategy_version_hash: Sha256
    dataset_version_hash: Sha256
    selected_engine_slots: tuple[SelectedEngineSlot, ...] = Field(
        min_length=1,
        max_length=MAX_SELECTED_ENGINE_SLOTS,
        # Distinct ordinals make every accepted member distinct, so whole-value
        # uniqueness is an exact publication of the runtime rule.
        json_schema_extra={"uniqueItems": True},
    )
    starting_balance: Money
    fee_assumptions: FeeAssumptions
    slippage_assumptions: SlippageAssumptions
    execution_assumptions: ExecutionAssumptions
    comparison_level: ComparisonLevel
    retry_policy: RetryPolicy

    @model_validator(mode="after")
    def validate_material_inputs(self) -> Self:
        _validate_selected_engine_slots(self.selected_engine_slots)
        _validate_starting_balance(self.starting_balance)
        return self


class ExperimentSpec(CanonicalModel):
    """Specification section 11.3: the immutable material inputs of one experiment.

    The twelve fields in the specification's order. ``configuration_hash`` and
    ``created_at_utc`` are derived by ``build_experiment_spec``; see the module
    docstring for why the former is not re-verified here.
    """

    schema_version: Literal["1.0.0"]
    strategy_version_hash: Sha256
    dataset_version_hash: Sha256
    selected_engine_slots: tuple[SelectedEngineSlot, ...] = Field(
        min_length=1,
        max_length=MAX_SELECTED_ENGINE_SLOTS,
        json_schema_extra={"uniqueItems": True},
    )
    starting_balance: Money
    fee_assumptions: FeeAssumptions
    slippage_assumptions: SlippageAssumptions
    execution_assumptions: ExecutionAssumptions
    comparison_level: ComparisonLevel
    retry_policy: RetryPolicy
    configuration_hash: Sha256
    created_at_utc: CalendarValidUtcDateTime

    @model_validator(mode="after")
    def validate_material_inputs(self) -> Self:
        _validate_selected_engine_slots(self.selected_engine_slots)
        _validate_starting_balance(self.starting_balance)
        return self


class SlotCompatibility(CanonicalModel):
    """The frozen compatibility result of one selected slot, plan section 3.6.

    Resolved by the Stage 4 resolver in the composition root before queueing and
    frozen with the spec. It carries no ``ApproximationDeclaration`` body:
    ``domain`` may not import ``capabilities``, and aggregation needs only the
    outcome and the declaration identities. Approximation status anywhere in
    Stage 5 is derived solely from this record.
    """

    logical_slot_id: LogicalSlotId
    outcome: CompatibilityOutcome
    availability_observation_id: AvailabilityObservationId
    approximation_ids: tuple[ApproximationId, ...] = Field(
        max_length=MAX_APPROXIMATION_IDS,
        json_schema_extra={"uniqueItems": True},
    )

    @field_validator("approximation_ids")
    @classmethod
    def validate_approximation_ids(
        cls,
        value: tuple[ApproximationId, ...],
    ) -> tuple[ApproximationId, ...]:
        """Order carries no meaning, so it is canonicalized by rejection."""
        if len(set(value)) != len(value):
            raise ValueError("approximation identifiers must be unique")
        if value != tuple(sorted(value)):
            raise ValueError("approximation identifiers must be sorted")
        return value

    @model_validator(mode="after")
    def validate_approximations_follow_the_outcome(self) -> Self:
        approximated = self.outcome is CompatibilityOutcome.SUPPORTED_WITH_APPROXIMATION
        if approximated and not self.approximation_ids:
            raise ValueError(
                "an approximated outcome requires at least one approximation identifier"
            )
        if not approximated and self.approximation_ids:
            raise ValueError(
                "approximation identifiers are carried only by "
                "SUPPORTED_WITH_APPROXIMATION"
            )
        return self


def _validate_slot_compatibility_alignment(
    slots: tuple[SelectedEngineSlot, ...],
    compatibility: tuple[SlotCompatibility, ...],
) -> None:
    """Plan 3.6 row 6 and section 7 check 6: one entry per slot, in slot order."""
    expected = tuple(slot.logical_slot_id for slot in slots)
    actual = tuple(entry.logical_slot_id for entry in compatibility)
    if actual != expected:
        raise ValueError(
            "slot_compatibility must hold exactly one entry per selected slot "
            "in slot order"
        )


class ExperimentRecord(CanonicalModel):
    """Specification section 11.3: the authoritative experiment lifecycle record.

    The specification's eight minimum fields plus the two state-governed fields of
    plan section 3.6: ``slot_compatibility`` (the frozen compatibility results,
    absent before ``QUEUED``) and ``cancellation_correlation_id`` (present exactly
    in ``CANCELLED``, written once by the winning cancellation). Both are
    ``MISSING`` when absent and are published by Task 9 with these rules.
    """

    schema_version: Literal["1.0.0"]
    experiment_id: ExperimentId
    spec: ExperimentSpec
    spec_hash: Sha256
    state: ExperimentState
    slot_compatibility: tuple[SlotCompatibility, ...] | MISSING = MISSING  # type: ignore[valid-type]
    cancellation_correlation_id: CorrelationId | MISSING = MISSING  # type: ignore[valid-type]
    created_at_utc: CalendarValidUtcDateTime
    updated_at_utc: CalendarValidUtcDateTime
    revision: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_identity_and_state_governed_shape(self) -> Self:
        if self.spec_hash != experiment_spec_hash(self.spec):
            raise ValueError(
                "spec_hash must equal the recomputed experiment spec identity"
            )
        if self.updated_at_utc < self.created_at_utc:
            raise ValueError("updated_at_utc must be at or after created_at_utc")
        compatibility_present = not _is_missing(self.slot_compatibility)
        if self.state in _PRE_QUEUE_STATES:
            if compatibility_present:
                raise ValueError("slot_compatibility is absent before QUEUED")
        elif self.state is not ExperimentState.CANCELLED and not compatibility_present:
            raise ValueError("slot_compatibility is required from QUEUED onward")
        if compatibility_present:
            _validate_slot_compatibility_alignment(
                self.spec.selected_engine_slots,
                self.slot_compatibility,
            )
        cancelled = self.state is ExperimentState.CANCELLED
        correlation_present = not _is_missing(self.cancellation_correlation_id)
        if cancelled and not correlation_present:
            raise ValueError("a CANCELLED record requires cancellation_correlation_id")
        if correlation_present and not cancelled:
            raise ValueError("cancellation_correlation_id is present only in CANCELLED")
        return self


def experiment_configuration_payload(
    material: ExperimentSpecDraft | ExperimentSpec,
    material_base_configuration_hash: Sha256,
) -> dict[str, JsonValue]:
    """Build the exact ten-key payload behind ``configuration_hash``.

    The request-supplied material base configuration hash plus spec fields 2-10
    (the ``ExperimentSpecDraft`` field set) in canonical JSON form; the envelope
    ``schema_version``, ``configuration_hash`` and ``created_at_utc`` never enter.
    Nested ``Money`` and ``RetryPolicy`` keep their own envelope versions because
    those are their content. ``model_dump(mode="json")`` is required because
    ``profile_hash`` types its payload ``dict[str, JsonValue]`` and neither
    ``Decimal`` nor ``datetime`` is a JSON value.
    """
    dumped = material.model_dump(mode="json")
    payload: dict[str, JsonValue] = {
        "material_base_configuration_hash": _SHA256.validate_python(
            material_base_configuration_hash
        ),
    }
    for name in ExperimentSpecDraft.model_fields:
        payload[name] = cast("JsonValue", dumped[name])
    return payload


def experiment_configuration_hash(
    material: ExperimentSpecDraft | ExperimentSpec,
    material_base_configuration_hash: Sha256,
) -> Sha256:
    """``profile_hash(EXPERIMENT_CONFIGURATION_V1, ...)``; not a self-hash."""
    return profile_hash(
        HashingProfile.EXPERIMENT_CONFIGURATION_V1,
        experiment_configuration_payload(material, material_base_configuration_hash),
    )


def experiment_spec_payload(spec: ExperimentSpec) -> dict[str, JsonValue]:
    """The complete canonical spec, including its envelope, hash and instant."""
    return cast("dict[str, JsonValue]", spec.model_dump(mode="json"))


def experiment_spec_hash(spec: ExperimentSpec) -> Sha256:
    """``profile_hash(EXPERIMENT_SPEC_V1, ...)`` over the complete spec.

    External to the payload, so it is not a self-hash field; it is stored on
    ``ExperimentRecord.spec_hash`` and recomputed by that record's validator.
    """
    return profile_hash(
        HashingProfile.EXPERIMENT_SPEC_V1, experiment_spec_payload(spec)
    )


def build_experiment_spec(
    draft: ExperimentSpecDraft,
    material_base_configuration_hash: Sha256,
    created_at_utc: datetime,
) -> ExperimentSpec:
    """Assemble the spec at the one moment its derived fields are obtainable.

    Copies fields 2-10 from the draft, derives ``configuration_hash`` from the
    draft and the request-supplied material hash, and stamps the instant the
    service read from its injected ``Clock``. Reads no clock and draws no value
    itself: the instant is a parameter, and the same inputs always produce the
    same spec.
    """
    return ExperimentSpec(
        schema_version="1.0.0",
        **draft.model_dump(mode="python"),
        configuration_hash=experiment_configuration_hash(
            draft, material_base_configuration_hash
        ),
        created_at_utc=created_at_utc,
    )


class QueueFreezeCheck(StrEnum):
    """Plan section 7's checks, in evaluation order, as distinguishable outcomes.

    Check 1 is split into its two halves because Task 6 maps them to different
    codes (a moved revision is a concurrency conflict; a wrong state is an
    invariant violation), while checks 2, 3 and 6 are frozen-input mismatches.
    """

    STORED_STATE = "STORED_STATE"
    EXPECTED_REVISION = "EXPECTED_REVISION"
    RETRY_POLICY_BYTES = "RETRY_POLICY_BYTES"
    CONFIGURATION_HASH = "CONFIGURATION_HASH"
    SPEC_HASH = "SPEC_HASH"
    SELECTED_SLOTS = "SELECTED_SLOTS"
    SLOT_COMPATIBILITY = "SLOT_COMPATIBILITY"


class QueueFreezeViolation(ValueError):
    """Raised by ``assert_queue_freeze`` naming the first failed check."""

    def __init__(self, check: QueueFreezeCheck, message: str) -> None:
        super().__init__(message)
        self.check = check


def assert_queue_freeze(
    record: ExperimentRecord,
    *,
    expected_revision: int,
    config_derived_retry_policy: RetryPolicy,
    material_base_configuration_hash: Sha256,
    slot_compatibility: tuple[SlotCompatibility, ...],
) -> None:
    """Plan section 7: the pure kernel of the ``VALIDATED -> QUEUED`` freeze.

    Evaluates the six checks in section 7 order over the loaded record and the
    request-supplied values, and raises ``QueueFreezeViolation`` naming the first
    check that fails. Pure over its arguments: it reads no repository, clock or
    environment, writes nothing and never mutates the record. Task 6's
    ``queue_experiment`` wraps it, maps the check onto the diagnostic code plan
    sections 7 and 8.6 assign, and performs the compare-and-swap. Checks 4 and 5
    are re-evaluated defensively: a record that validates cannot reach them.
    """
    if record.state is not ExperimentState.VALIDATED:
        raise QueueFreezeViolation(
            QueueFreezeCheck.STORED_STATE,
            f"stored state must be VALIDATED, not {record.state.value}",
        )
    if record.revision != expected_revision:
        raise QueueFreezeViolation(
            QueueFreezeCheck.EXPECTED_REVISION,
            "expected_revision does not match the stored revision",
        )
    if canonical_json_bytes(record.spec.retry_policy) != canonical_json_bytes(
        config_derived_retry_policy
    ):
        raise QueueFreezeViolation(
            QueueFreezeCheck.RETRY_POLICY_BYTES,
            "the embedded retry policy differs from the configuration-derived policy",
        )
    if record.spec.configuration_hash != experiment_configuration_hash(
        record.spec, material_base_configuration_hash
    ):
        raise QueueFreezeViolation(
            QueueFreezeCheck.CONFIGURATION_HASH,
            "configuration_hash does not reproduce from the material base hash",
        )
    if record.spec_hash != experiment_spec_hash(record.spec):
        raise QueueFreezeViolation(
            QueueFreezeCheck.SPEC_HASH,
            "spec_hash does not equal the recomputed experiment spec identity",
        )
    try:
        _validate_selected_engine_slots(record.spec.selected_engine_slots)
    except ValueError as error:
        raise QueueFreezeViolation(
            QueueFreezeCheck.SELECTED_SLOTS, str(error)
        ) from error
    try:
        _validate_slot_compatibility_alignment(
            record.spec.selected_engine_slots, slot_compatibility
        )
    except ValueError as error:
        raise QueueFreezeViolation(
            QueueFreezeCheck.SLOT_COMPATIBILITY, str(error)
        ) from error
