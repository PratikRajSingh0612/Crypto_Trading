"""Stage 5 Task 2: experiment spec, experiment record, frozen slot compatibility,
the immutable retry policy and the queue-time freeze predicate.

Every rule below is transcribed from Stage 5 plan sections 3.1 (shared model
conventions), 3.4 (``RetryPolicy``), 3.5 (``ExperimentSpec`` and its nested value
objects), 3.6 (``ExperimentRecord`` and ``SlotCompatibility``) and 7 (queue-time
immutability), under specification sections 10.2, 11.3, 11.5 and 16.2. Where the
plan and the specification disagree on wording the specification wins: duplicate
retry terminal states are *rejected* and only their order is normalized (spec
11.5), and ``RetryPolicy`` has no optional field (spec 11.5), so every one of its
five fields is required and the configuration defaults reach it only through the
projection tested in ``tests/unit/configuration/test_retry_policy_projection.py``.

Two conventions of the merged tree are load-bearing here. Absent state-governed
fields are ``MISSING``, never ``None``, and are asserted absent from **both** dump
modes because ``canonical_json`` reaches a model through ``mode="python"``. And a
model is never mutated through ``model_copy``, which skips validators: every
"invalid" record is rebuilt through ``model_validate`` so a rejection is real.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from types import ModuleType

import pytest
from pydantic import TypeAdapter, ValidationError

from crypto_lab.domain import experiment as experiment_module
from crypto_lab.domain import retry as retry_module
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.comparison_levels import ComparisonLevel
from crypto_lab.domain.compatibility import CompatibilityOutcome
from crypto_lab.domain.experiment import (
    AdapterIdentity,
    BarOrderPriority,
    EngineIdentity,
    ExecutionAssumptions,
    ExperimentRecord,
    ExperimentSpec,
    ExperimentSpecDraft,
    FeeAssumptions,
    FillConvention,
    QueueFreezeCheck,
    QueueFreezeViolation,
    SelectedEngineSlot,
    SignalToOrderTiming,
    SlippageAssumptions,
    SlippageModel,
    SlotCompatibility,
    assert_queue_freeze,
    build_experiment_spec,
    experiment_configuration_hash,
    experiment_configuration_payload,
    experiment_spec_hash,
    experiment_spec_payload,
)
from crypto_lab.domain.hashing import (
    CanonicalHashEnvelope,
    HashingProfile,
    profile_hash,
    sha256_bytes,
)
from crypto_lab.domain.identifiers import Sha256
from crypto_lab.domain.lifecycle import ExperimentState, RetryTerminalState
from crypto_lab.domain.records import Money
from crypto_lab.domain.retry import RetryPolicy
from crypto_lab.domain.time import CalendarValidUtcDateTime

_E = ExperimentState
_O = CompatibilityOutcome
_T = RetryTerminalState

# Lowercase canonical UUID4 text: version nibble 4, variant nibble in [89ab].
_UUID_A = "12345678-1234-4234-8234-123456789abc"
_UUID_B = "9f8e7d6c-5b4a-4321-8fed-cba987654321"
_UUID_C = "0a1b2c3d-4e5f-4a6b-9c7d-8e9f0a1b2c3d"
_SLOT_A = f"slot_{_UUID_A}"
_SLOT_B = f"slot_{_UUID_B}"
_SLOT_C = f"slot_{_UUID_C}"
_EXPERIMENT_ID = f"exp_{_UUID_A}"
_AVAIL_A = f"avail_{_UUID_A}"
_AVAIL_B = f"avail_{_UUID_B}"
_AVAIL_C = f"avail_{_UUID_C}"
# Sorted: "appx_0a..." < "appx_12..." < "appx_9f...".
_APPX_LOW = f"appx_{_UUID_C}"
_APPX_MID = f"appx_{_UUID_A}"
_APPX_HIGH = f"appx_{_UUID_B}"
_CORRELATION = "cancel-2026-09-06"

_STRATEGY_HASH = "a" * 64
_DATASET_HASH = "b" * 64
_MATERIAL = "c" * 64
_OTHER_MATERIAL = "d" * 64
_OTHER_SHA256 = "e" * 64

_CREATED = datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)
_UPDATED = _CREATED + timedelta(seconds=1)
_NAIVE = datetime(2026, 9, 6, 12, 0, 0)  # noqa: DTZ001 - deliberate naive probe
_OFFSET = datetime(2026, 9, 6, 13, 0, 0, tzinfo=timezone(timedelta(hours=1)))

_RECORD_FIELDS = (
    "schema_version",
    "experiment_id",
    "spec",
    "spec_hash",
    "state",
    "slot_compatibility",
    "cancellation_correlation_id",
    "created_at_utc",
    "updated_at_utc",
    "revision",
)
_SPEC_FIELDS = (
    "schema_version",
    "strategy_version_hash",
    "dataset_version_hash",
    "selected_engine_slots",
    "starting_balance",
    "fee_assumptions",
    "slippage_assumptions",
    "execution_assumptions",
    "comparison_level",
    "retry_policy",
    "configuration_hash",
    "created_at_utc",
)
_POLICY_FIELDS = (
    "schema_version",
    "maximum_attempts_per_slot",
    "automatically_retry_terminal_states",
    "retry_delay_seconds",
    "require_fresh_availability_observation_for_unavailable",
)
_PRE_QUEUE_STATES = (_E.DRAFT, _E.VALIDATED)
_POST_QUEUE_STATES = (
    _E.QUEUED,
    _E.RUNNING,
    _E.COMPLETED,
    _E.COMPLETED_WITH_WARNINGS,
    _E.FAILED,
)


# --- Fixture factories ----------------------------------------------------------


def _adapter(name: str = "adapter.alpha", version: str = "1.0.0") -> AdapterIdentity:
    return AdapterIdentity(adapter_name=name, adapter_version=version)


def _engine(name: str = "engine.alpha", version: str = "2.3.4") -> EngineIdentity:
    return EngineIdentity(engine_name=name, engine_version=version)


def _slot(
    ordinal: int,
    slot_id: str,
    adapter: AdapterIdentity,
    engine: EngineIdentity,
) -> SelectedEngineSlot:
    return SelectedEngineSlot(
        logical_slot_id=slot_id,
        slot_ordinal=ordinal,
        adapter=adapter,
        engine=engine,
    )


def _slots() -> tuple[SelectedEngineSlot, ...]:
    return (
        _slot(0, _SLOT_A, _adapter(), _engine()),
        _slot(1, _SLOT_B, _adapter("adapter.beta", "1.2.0"), _engine("engine.beta")),
    )


def _policy(**overrides: object) -> RetryPolicy:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "maximum_attempts_per_slot": 2,
        "automatically_retry_terminal_states": (_T.FAILED, _T.UNAVAILABLE),
        "retry_delay_seconds": 30,
        "require_fresh_availability_observation_for_unavailable": True,
    }
    payload.update(overrides)
    return RetryPolicy.model_validate(payload)


def _money(amount: str = "10000") -> Money:
    return Money(schema_version="1.0.0", currency="USDT", amount=Decimal(amount))


def _fees() -> FeeAssumptions:
    return FeeAssumptions(
        maker_fee_rate=Decimal("0.001"),
        taker_fee_rate=Decimal("0.002"),
    )


def _slippage() -> SlippageAssumptions:
    return SlippageAssumptions(
        model=SlippageModel.FIXED_BASIS_POINTS,
        basis_points=Decimal("5"),
    )


def _execution() -> ExecutionAssumptions:
    return ExecutionAssumptions(
        signal_to_order_timing=SignalToOrderTiming.NEXT_BAR_OPEN,
        bar_order_priority=BarOrderPriority.EXITS_BEFORE_ENTRIES,
        fill_convention=FillConvention.FULL_FILL,
        price_precision=2,
        quantity_precision=8,
        rounding_mode="ROUND_HALF_EVEN",
    )


def _draft_payload() -> dict[str, object]:
    return {
        "strategy_version_hash": _STRATEGY_HASH,
        "dataset_version_hash": _DATASET_HASH,
        "selected_engine_slots": _slots(),
        "starting_balance": _money(),
        "fee_assumptions": _fees(),
        "slippage_assumptions": _slippage(),
        "execution_assumptions": _execution(),
        "comparison_level": ComparisonLevel.LEVEL_2,
        "retry_policy": _policy(),
    }


def _draft(**overrides: object) -> ExperimentSpecDraft:
    payload = _draft_payload()
    payload.update(overrides)
    return ExperimentSpecDraft.model_validate(payload)


def _spec(**overrides: object) -> ExperimentSpec:
    """A spec built by the builder, then rebuilt with overrides through validation."""
    built = build_experiment_spec(_draft(), _MATERIAL, _CREATED)
    if not overrides:
        return built
    return _revalidate(ExperimentSpec, built, **overrides)


def _compatibility(**overrides: object) -> SlotCompatibility:
    payload: dict[str, object] = {
        "logical_slot_id": _SLOT_A,
        "outcome": _O.SUPPORTED,
        "availability_observation_id": _AVAIL_A,
        "approximation_ids": (),
    }
    payload.update(overrides)
    return SlotCompatibility.model_validate(payload)


def _compatibilities() -> tuple[SlotCompatibility, ...]:
    return (
        _compatibility(),
        _compatibility(
            logical_slot_id=_SLOT_B,
            outcome=_O.SUPPORTED_WITH_APPROXIMATION,
            availability_observation_id=_AVAIL_B,
            approximation_ids=(_APPX_MID,),
        ),
    )


def _record_payload(spec: ExperimentSpec | None = None) -> dict[str, object]:
    spec = _spec() if spec is None else spec
    return {
        "schema_version": "1.0.0",
        "experiment_id": _EXPERIMENT_ID,
        "spec": spec,
        "spec_hash": experiment_spec_hash(spec),
        "state": _E.DRAFT,
        "created_at_utc": _CREATED,
        "updated_at_utc": _UPDATED,
        "revision": 0,
    }


def _record(**overrides: object) -> ExperimentRecord:
    payload = _record_payload()
    payload.update(overrides)
    return ExperimentRecord.model_validate(payload)


def _shaped_record(state: ExperimentState, **overrides: object) -> ExperimentRecord:
    """A record whose state-governed fields are consistent with ``state``."""
    payload = _record_payload()
    payload["state"] = state
    if state not in _PRE_QUEUE_STATES:
        payload["slot_compatibility"] = _compatibilities()
    if state is _E.CANCELLED:
        payload["cancellation_correlation_id"] = _CORRELATION
    payload.update(overrides)
    return ExperimentRecord.model_validate(payload)


def _revalidate[M: CanonicalModel](
    model_type: type[M],
    instance: CanonicalModel,
    **updates: object,
) -> M:
    """Rebuild through validation, never through ``model_copy``."""
    payload = instance.model_dump(mode="python")
    payload.update(updates)
    return model_type.model_validate(payload)


def _without[M: CanonicalModel](
    model_type: type[M],
    instance: CanonicalModel,
    *fields: str,
) -> M:
    payload = instance.model_dump(mode="python")
    for field in fields:
        payload.pop(field, None)
    return model_type.model_validate(payload)


def _every_instance() -> tuple[CanonicalModel, ...]:
    return (
        _policy(),
        _adapter(),
        _engine(),
        _slots()[0],
        _fees(),
        _slippage(),
        _execution(),
        _draft(),
        _spec(),
        _compatibility(),
        _record(),
    )


def _configuration_payload(
    draft: ExperimentSpecDraft,
    material: str,
) -> dict[str, object]:
    return {
        "material_base_configuration_hash": material,
        **draft.model_dump(mode="json"),
    }


def _module_source(module: ModuleType) -> str:
    assert module.__file__ is not None
    return Path(module.__file__).read_text(encoding="utf-8")


# --- Shared conventions (plan section 3.1) ---------------------------------------


@pytest.mark.parametrize("instance", _every_instance(), ids=lambda m: type(m).__name__)
def test_every_task_two_model_rejects_an_unknown_field(
    instance: CanonicalModel,
) -> None:
    payload = instance.model_dump(mode="python")
    assert type(instance).model_validate(payload) == instance
    payload["unexpected"] = "rejected"
    with pytest.raises(ValidationError, match="extra_forbidden"):
        type(instance).model_validate(payload)


@pytest.mark.parametrize("instance", _every_instance(), ids=lambda m: type(m).__name__)
def test_every_task_two_model_is_frozen(instance: CanonicalModel) -> None:
    first = next(iter(type(instance).model_fields))
    with pytest.raises(ValidationError):
        setattr(instance, first, getattr(instance, first))


def test_strict_mode_refuses_string_coercion_for_integers() -> None:
    payload = _slots()[0].model_dump(mode="python")
    payload["slot_ordinal"] = "0"
    with pytest.raises(ValidationError):
        SelectedEngineSlot.model_validate(payload)
    record = _record_payload()
    record["revision"] = "0"
    with pytest.raises(ValidationError):
        ExperimentRecord.model_validate(record)


def test_the_task_two_models_declare_exactly_the_plan_field_lists_in_order() -> None:
    assert tuple(ExperimentSpec.model_fields) == _SPEC_FIELDS
    assert tuple(ExperimentSpecDraft.model_fields) == _SPEC_FIELDS[1:10]
    assert tuple(ExperimentRecord.model_fields) == _RECORD_FIELDS
    assert tuple(RetryPolicy.model_fields) == _POLICY_FIELDS
    assert tuple(SlotCompatibility.model_fields) == (
        "logical_slot_id",
        "outcome",
        "availability_observation_id",
        "approximation_ids",
    )
    assert tuple(SelectedEngineSlot.model_fields) == (
        "logical_slot_id",
        "slot_ordinal",
        "adapter",
        "engine",
    )
    assert tuple(AdapterIdentity.model_fields) == ("adapter_name", "adapter_version")
    assert tuple(EngineIdentity.model_fields) == ("engine_name", "engine_version")
    assert tuple(FeeAssumptions.model_fields) == ("maker_fee_rate", "taker_fee_rate")
    assert tuple(SlippageAssumptions.model_fields) == ("model", "basis_points")
    assert tuple(ExecutionAssumptions.model_fields) == (
        "signal_to_order_timing",
        "bar_order_priority",
        "fill_convention",
        "price_precision",
        "quantity_precision",
        "rounding_mode",
    )
    for nested in (
        AdapterIdentity,
        EngineIdentity,
        SelectedEngineSlot,
        FeeAssumptions,
        SlippageAssumptions,
        ExecutionAssumptions,
        SlotCompatibility,
        ExperimentSpecDraft,
    ):
        assert "schema_version" not in nested.model_fields, nested.__name__


def test_the_narrow_vocabularies_hold_exactly_the_plan_members_in_order() -> None:
    assert [m.value for m in SlippageModel] == ["NONE", "FIXED_BASIS_POINTS"]
    assert [m.value for m in SignalToOrderTiming] == ["NEXT_BAR_OPEN", "SAME_BAR_CLOSE"]
    assert [m.value for m in BarOrderPriority] == [
        "EXITS_BEFORE_ENTRIES",
        "ENTRIES_BEFORE_EXITS",
    ]
    assert [m.value for m in FillConvention] == ["FULL_FILL", "PARTIAL_FILLS_ALLOWED"]


@pytest.mark.parametrize(
    ("model_type", "field"),
    [
        (ExperimentSpec, "created_at_utc"),
        (ExperimentRecord, "created_at_utc"),
        (ExperimentRecord, "updated_at_utc"),
    ],
)
def test_a_naive_timestamp_is_rejected_on_every_instant_field(
    model_type: type[CanonicalModel],
    field: str,
) -> None:
    payload = (
        _spec().model_dump(mode="python")
        if model_type is ExperimentSpec
        else _record().model_dump(mode="python")
    )
    payload[field] = _NAIVE
    with pytest.raises(ValidationError, match="timezone-aware UTC"):
        model_type.model_validate(payload)
    payload[field] = _OFFSET
    with pytest.raises(ValidationError, match="offset must be UTC"):
        model_type.model_validate(payload)


def test_every_published_timestamp_uses_the_forward_schema_view() -> None:
    """Plan section 2.6: every Stage 5 timestamp field uses the calendar-valid view,
    so Task 9's registration passes the merged forward-view guard unchanged."""
    for model in (ExperimentSpec, ExperimentRecord):
        for mode in ("validation", "serialization"):
            schema = model.model_json_schema(mode=mode)
            assert "UtcDateTime" not in schema.get("$defs", {}), model.__name__
            assert "CalendarValidUtcDateTime" in schema["$defs"], model.__name__
    TypeAdapter(CalendarValidUtcDateTime).validate_python(_CREATED)


def test_a_float_amount_is_rejected_in_python_and_json_modes() -> None:
    draft = _draft_payload()
    draft["starting_balance"] = {
        "schema_version": "1.0.0",
        "currency": "USDT",
        "amount": 1.0,
    }
    with pytest.raises(ValidationError, match="Python input must be Decimal"):
        ExperimentSpecDraft.model_validate(draft)
    with pytest.raises(ValidationError, match="Python input must be Decimal"):
        FeeAssumptions.model_validate(
            {"maker_fee_rate": 0.001, "taker_fee_rate": Decimal("0.002")}
        )
    with pytest.raises(ValidationError, match="Python input must be Decimal"):
        SlippageAssumptions.model_validate(
            {"model": SlippageModel.FIXED_BASIS_POINTS, "basis_points": 5.0}
        )
    encoded = _spec().model_dump_json().replace('"amount":"10000"', '"amount":10000.0')
    assert '"amount":10000.0' in encoded
    with pytest.raises(ValidationError, match="JSON decimal input must be a string"):
        ExperimentSpec.model_validate_json(encoded)


# --- ExperimentSpecDraft and ExperimentSpec slot and balance rules (plan 3.5) ----


@pytest.mark.parametrize("model_type", [ExperimentSpecDraft, ExperimentSpec])
@pytest.mark.parametrize("amount", ["0", "-1"])
def test_a_non_positive_starting_balance_is_rejected(
    model_type: type[CanonicalModel],
    amount: str,
) -> None:
    # A zero or negative Money is valid on its own: positivity is this record's rule.
    balance = _money(amount)
    source = _draft() if model_type is ExperimentSpecDraft else _spec()
    with pytest.raises(ValidationError, match="starting balance must be positive"):
        _revalidate(model_type, source, starting_balance=balance)
    _revalidate(model_type, source, starting_balance=_money("0.00000001"))


def _slots_with_ordinals(*ordinals: int) -> tuple[SelectedEngineSlot, ...]:
    identities = (
        (_SLOT_A, _adapter(), _engine()),
        (_SLOT_B, _adapter("adapter.beta", "1.2.0"), _engine("engine.beta")),
        (_SLOT_C, _adapter("adapter.gamma", "3.0.0"), _engine("engine.gamma")),
    )
    return tuple(
        _slot(ordinal, *identities[index]) for index, ordinal in enumerate(ordinals)
    )


@pytest.mark.parametrize("model_type", [ExperimentSpecDraft, ExperimentSpec])
@pytest.mark.parametrize(
    "ordinals",
    [(0, 0), (1, 0), (0, 2), (1, 2), (0, 1, 1), (2, 1, 0)],
    ids=("duplicate", "descending", "gap", "not-from-zero", "late-dup", "reversed"),
)
def test_duplicate_or_non_ascending_slot_ordinals_are_rejected(
    model_type: type[CanonicalModel],
    ordinals: tuple[int, ...],
) -> None:
    source = _draft() if model_type is ExperimentSpecDraft else _spec()
    with pytest.raises(ValidationError, match="ordinal"):
        _revalidate(
            model_type,
            source,
            selected_engine_slots=_slots_with_ordinals(*ordinals),
        )
    accepted = _revalidate(
        model_type,
        source,
        selected_engine_slots=_slots_with_ordinals(0, 1, 2),
    )
    assert isinstance(accepted, ExperimentSpecDraft | ExperimentSpec)
    assert tuple(s.slot_ordinal for s in accepted.selected_engine_slots) == (0, 1, 2)


@pytest.mark.parametrize("model_type", [ExperimentSpecDraft, ExperimentSpec])
def test_a_duplicate_adapter_engine_pair_is_rejected(
    model_type: type[CanonicalModel],
) -> None:
    source = _draft() if model_type is ExperimentSpecDraft else _spec()
    duplicate = (
        _slot(0, _SLOT_A, _adapter(), _engine()),
        _slot(1, _SLOT_B, _adapter(), _engine()),
    )
    with pytest.raises(ValidationError, match="adapter"):
        _revalidate(model_type, source, selected_engine_slots=duplicate)
    # Near miss: same adapter, a different engine version, is a distinct pair.
    near_miss = (
        _slot(0, _SLOT_A, _adapter(), _engine()),
        _slot(1, _SLOT_B, _adapter(), _engine(version="2.3.5")),
    )
    _revalidate(model_type, source, selected_engine_slots=near_miss)


@pytest.mark.parametrize("model_type", [ExperimentSpecDraft, ExperimentSpec])
def test_a_duplicate_logical_slot_id_is_rejected(
    model_type: type[CanonicalModel],
) -> None:
    source = _draft() if model_type is ExperimentSpecDraft else _spec()
    duplicate = (
        _slot(0, _SLOT_A, _adapter(), _engine()),
        _slot(1, _SLOT_A, _adapter("adapter.beta", "1.2.0"), _engine("engine.beta")),
    )
    with pytest.raises(ValidationError, match="logical_slot_id"):
        _revalidate(model_type, source, selected_engine_slots=duplicate)


@pytest.mark.parametrize("model_type", [ExperimentSpecDraft, ExperimentSpec])
def test_selected_engine_slots_holds_between_one_and_eight_entries(
    model_type: type[CanonicalModel],
) -> None:
    source = _draft() if model_type is ExperimentSpecDraft else _spec()
    with pytest.raises(ValidationError):
        _revalidate(model_type, source, selected_engine_slots=())
    eight = tuple(
        _slot(
            index,
            f"slot_{index:08x}-1234-4234-8234-123456789abc",
            _adapter(f"adapter.slot{index}"),
            _engine(f"engine.slot{index}"),
        )
        for index in range(8)
    )
    _revalidate(model_type, source, selected_engine_slots=eight)
    # A ninth slot cannot even be constructed (ordinal 8 exceeds the slot bound),
    # so the tuple bound is exercised through plain payloads on the record itself.
    nine: tuple[dict[str, object], ...] = (
        *(slot.model_dump(mode="python") for slot in eight),
        {
            "logical_slot_id": f"slot_{8:08x}-1234-4234-8234-123456789abc",
            "slot_ordinal": 8,
            "adapter": _adapter("adapter.slot8").model_dump(mode="python"),
            "engine": _engine("engine.slot8").model_dump(mode="python"),
        },
    )
    with pytest.raises(ValidationError):
        _revalidate(model_type, source, selected_engine_slots=nine)
    schema = model_type.model_json_schema()["properties"]["selected_engine_slots"]
    assert schema["minItems"] == 1
    assert schema["maxItems"] == 8
    assert schema["uniqueItems"] is True


def test_slot_ordinal_is_bounded_zero_to_seven() -> None:
    for ordinal in (-1, 8):
        with pytest.raises(ValidationError):
            _slot(ordinal, _SLOT_A, _adapter(), _engine())
    payload = _slots()[0].model_dump(mode="python")
    payload["slot_ordinal"] = True
    with pytest.raises(ValidationError):
        SelectedEngineSlot.model_validate(payload)
    assert _slot(7, _SLOT_A, _adapter(), _engine()).slot_ordinal == 7


def test_fee_rates_are_non_negative_and_at_most_one() -> None:
    with pytest.raises(ValidationError, match="at most 1"):
        FeeAssumptions(
            maker_fee_rate=Decimal("1.00000001"),
            taker_fee_rate=Decimal("0"),
        )
    with pytest.raises(ValidationError, match="at most 1"):
        FeeAssumptions(
            maker_fee_rate=Decimal("0"),
            taker_fee_rate=Decimal("1.5"),
        )
    with pytest.raises(ValidationError, match="non-negative"):
        FeeAssumptions(maker_fee_rate=Decimal("-0.001"), taker_fee_rate=Decimal("0"))
    boundary = FeeAssumptions(maker_fee_rate=Decimal("1"), taker_fee_rate=Decimal("0"))
    assert boundary.model_dump(mode="json") == {
        "maker_fee_rate": "1",
        "taker_fee_rate": "0",
    }


def test_slippage_none_carries_no_basis_points() -> None:
    with pytest.raises(ValidationError, match="basis_points"):
        SlippageAssumptions(model=SlippageModel.NONE, basis_points=Decimal("5"))
    none = SlippageAssumptions(model=SlippageModel.NONE)
    assert "basis_points" not in none.model_dump(mode="json")
    assert "basis_points" not in none.model_dump(mode="python")
    assert not isinstance(none.basis_points, Decimal)


def test_slippage_fixed_basis_points_requires_basis_points_and_rejects_null() -> None:
    with pytest.raises(ValidationError, match="basis_points"):
        SlippageAssumptions(model=SlippageModel.FIXED_BASIS_POINTS)
    with pytest.raises(ValidationError):
        SlippageAssumptions.model_validate(
            {"model": "FIXED_BASIS_POINTS", "basis_points": None}
        )
    fixed = _slippage()
    assert fixed.model_dump(mode="json") == {
        "model": "FIXED_BASIS_POINTS",
        "basis_points": "5",
    }


def test_execution_assumptions_bounds_and_the_fixed_rounding_mode() -> None:
    base = _execution().model_dump(mode="python")
    for update in (
        {"price_precision": 19},
        {"quantity_precision": -1},
        {"rounding_mode": "ROUND_HALF_UP"},
        {"signal_to_order_timing": "IMMEDIATE"},
        {"bar_order_priority": "RANDOM"},
        {"fill_convention": "NONE"},
    ):
        with pytest.raises(ValidationError):
            ExecutionAssumptions.model_validate({**base, **update})
    ExecutionAssumptions.model_validate(
        {**base, "price_precision": 0, "quantity_precision": 18}
    )


# --- SlotCompatibility (plan 3.6) ------------------------------------------------


@pytest.mark.parametrize(
    "outcome",
    [_O.SUPPORTED, _O.NOT_APPLICABLE, _O.UNAVAILABLE],
)
def test_approximation_ids_are_rejected_under_every_non_approximation_outcome(
    outcome: CompatibilityOutcome,
) -> None:
    with pytest.raises(ValidationError, match="approximation"):
        _compatibility(outcome=outcome, approximation_ids=(_APPX_MID,))
    accepted = _compatibility(outcome=outcome)
    assert accepted.approximation_ids == ()
    assert accepted.model_dump(mode="json")["approximation_ids"] == []


def test_the_non_approximation_outcomes_partition_the_vocabulary() -> None:
    assert {_O.SUPPORTED, _O.NOT_APPLICABLE, _O.UNAVAILABLE} | {
        _O.SUPPORTED_WITH_APPROXIMATION
    } == set(CompatibilityOutcome)


def test_supported_with_approximation_requires_at_least_one_approximation_id() -> None:
    with pytest.raises(ValidationError, match="approximation"):
        _compatibility(outcome=_O.SUPPORTED_WITH_APPROXIMATION, approximation_ids=())
    accepted = _compatibility(
        outcome=_O.SUPPORTED_WITH_APPROXIMATION,
        approximation_ids=(_APPX_LOW, _APPX_MID),
    )
    assert accepted.approximation_ids == (_APPX_LOW, _APPX_MID)


def test_approximation_ids_are_sorted_unique_and_bounded() -> None:
    with pytest.raises(ValidationError, match="unique"):
        _compatibility(
            outcome=_O.SUPPORTED_WITH_APPROXIMATION,
            approximation_ids=(_APPX_MID, _APPX_MID),
        )
    with pytest.raises(ValidationError, match="sorted"):
        _compatibility(
            outcome=_O.SUPPORTED_WITH_APPROXIMATION,
            approximation_ids=(_APPX_HIGH, _APPX_LOW),
        )
    many = tuple(f"appx_{index:08x}-1234-4234-8234-123456789abc" for index in range(65))
    _compatibility(
        outcome=_O.SUPPORTED_WITH_APPROXIMATION,
        approximation_ids=many[:64],
    )
    with pytest.raises(ValidationError):
        _compatibility(
            outcome=_O.SUPPORTED_WITH_APPROXIMATION,
            approximation_ids=many,
        )
    schema = SlotCompatibility.model_json_schema()["properties"]["approximation_ids"]
    assert schema["maxItems"] == 64
    assert schema["uniqueItems"] is True


# --- ExperimentRecord (plan 3.6) -------------------------------------------------


def test_a_record_whose_spec_hash_disagrees_with_the_recomputed_value_is_rejected() -> (
    None
):
    with pytest.raises(ValidationError, match="spec_hash"):
        _record(spec_hash=_OTHER_SHA256)
    with pytest.raises(ValidationError):
        _record(spec_hash="A" * 64)
    assert _record().spec_hash == experiment_spec_hash(_spec())


def test_experiment_spec_hash_is_the_spec_profile_over_the_complete_spec() -> None:
    spec = _spec()
    payload = experiment_spec_payload(spec)
    assert payload == spec.model_dump(mode="json")
    assert set(payload) == set(_SPEC_FIELDS)
    assert payload["created_at_utc"] == "2026-09-06T12:00:00Z"
    assert payload["configuration_hash"] == spec.configuration_hash
    assert "spec_hash" not in payload
    envelope = CanonicalHashEnvelope(
        schema_version="1.0.0",
        hashing_profile=HashingProfile.EXPERIMENT_SPEC_V1,
        payload=payload,
    )
    expected = sha256_bytes(canonical_json_bytes(envelope))
    assert experiment_spec_hash(spec) == expected
    assert expected == profile_hash(HashingProfile.EXPERIMENT_SPEC_V1, payload)
    TypeAdapter(Sha256).validate_python(expected)


@pytest.mark.parametrize("state", _PRE_QUEUE_STATES)
def test_slot_compatibility_is_prohibited_before_queued(state: ExperimentState) -> None:
    with pytest.raises(ValidationError, match="slot_compatibility"):
        _record(state=state, slot_compatibility=_compatibilities())
    record = _record(state=state)
    assert "slot_compatibility" not in record.model_dump(mode="json")
    assert "slot_compatibility" not in record.model_dump(mode="python")
    assert not isinstance(record.slot_compatibility, tuple)


@pytest.mark.parametrize("state", _POST_QUEUE_STATES)
def test_slot_compatibility_is_required_from_queued_through_every_non_cancelled_state(
    state: ExperimentState,
) -> None:
    with pytest.raises(ValidationError, match="slot_compatibility"):
        _record(state=state)
    record = _record(state=state, slot_compatibility=_compatibilities())
    assert record.slot_compatibility == _compatibilities()


def test_the_slot_compatibility_state_partition_is_total() -> None:
    every_state = set(_PRE_QUEUE_STATES) | set(_POST_QUEUE_STATES) | {_E.CANCELLED}
    assert every_state == set(ExperimentState)


def test_a_cancelled_record_accepts_slot_compatibility_present_or_absent() -> None:
    """A cancellation from ``DRAFT`` or ``VALIDATED`` (plan section 4, spec 16.1)
    has no frozen slot set to carry forward; one from ``QUEUED`` or ``RUNNING`` keeps
    the frozen set unchanged. The record cannot know which edge produced it."""
    before_queue = _record(state=_E.CANCELLED, cancellation_correlation_id=_CORRELATION)
    assert "slot_compatibility" not in before_queue.model_dump(mode="python")
    after_queue = _record(
        state=_E.CANCELLED,
        cancellation_correlation_id=_CORRELATION,
        slot_compatibility=_compatibilities(),
    )
    assert after_queue.slot_compatibility == _compatibilities()


@pytest.mark.parametrize(
    "shape",
    ["empty", "short", "extra", "reversed", "duplicate", "foreign"],
)
def test_slot_compatibility_must_match_the_selected_slots_one_to_one_in_order(
    shape: str,
) -> None:
    first, second = _compatibilities()
    foreign = _compatibility(
        logical_slot_id=_SLOT_C, availability_observation_id=_AVAIL_C
    )
    shapes: dict[str, tuple[SlotCompatibility, ...]] = {
        "empty": (),
        "short": (first,),
        "extra": (first, second, foreign),
        "reversed": (second, first),
        "duplicate": (first, first),
        "foreign": (first, foreign),
    }
    with pytest.raises(ValidationError, match="slot_compatibility"):
        _record(state=_E.QUEUED, slot_compatibility=shapes[shape])
    _record(state=_E.QUEUED, slot_compatibility=(first, second))


@pytest.mark.parametrize(
    "state",
    [state for state in ExperimentState if state is not _E.CANCELLED],
)
def test_cancellation_correlation_id_is_prohibited_outside_cancelled(
    state: ExperimentState,
) -> None:
    with pytest.raises(ValidationError, match="cancellation_correlation_id"):
        _shaped_record(state, cancellation_correlation_id=_CORRELATION)
    record = _shaped_record(state)
    assert "cancellation_correlation_id" not in record.model_dump(mode="json")
    assert "cancellation_correlation_id" not in record.model_dump(mode="python")
    assert not isinstance(record.cancellation_correlation_id, str)


def test_a_cancelled_record_requires_a_cancellation_correlation_id() -> None:
    with pytest.raises(ValidationError, match="cancellation_correlation_id"):
        _record(state=_E.CANCELLED, slot_compatibility=_compatibilities())
    payload = _record_payload()
    payload.update(
        {
            "state": _E.CANCELLED,
            "slot_compatibility": _compatibilities(),
            "cancellation_correlation_id": None,
        }
    )
    with pytest.raises(ValidationError):
        ExperimentRecord.model_validate(payload)
    payload["cancellation_correlation_id"] = ".bad"
    with pytest.raises(ValidationError):
        ExperimentRecord.model_validate(payload)
    cancelled = _shaped_record(_E.CANCELLED)
    assert cancelled.cancellation_correlation_id == _CORRELATION
    dumped = cancelled.model_dump(mode="json")
    assert dumped["cancellation_correlation_id"] == _CORRELATION


def test_updated_at_may_not_precede_created_at() -> None:
    with pytest.raises(ValidationError, match="updated_at_utc"):
        _record(updated_at_utc=_CREATED - timedelta(seconds=1))
    assert _record(updated_at_utc=_CREATED).updated_at_utc == _CREATED


def test_revision_is_a_non_negative_strict_integer() -> None:
    with pytest.raises(ValidationError):
        _record(revision=-1)
    payload = _record_payload()
    payload["revision"] = True
    with pytest.raises(ValidationError):
        ExperimentRecord.model_validate(payload)
    assert _record(revision=0).revision == 0
    assert _record(revision=7).revision == 7


def test_absent_fields_are_omitted_from_both_dump_modes_and_null_is_rejected() -> None:
    cases: tuple[tuple[CanonicalModel, str], ...] = (
        (SlippageAssumptions(model=SlippageModel.NONE), "basis_points"),
        (_record(), "slot_compatibility"),
        (_record(), "cancellation_correlation_id"),
    )
    for instance, field in cases:
        assert field not in instance.model_dump(mode="json"), field
        assert field not in instance.model_dump(mode="python"), field
        payload = instance.model_dump(mode="python")
        payload[field] = None
        with pytest.raises(ValidationError):
            type(instance).model_validate(payload)
        again = type(instance).model_validate_json(instance.model_dump_json())
        assert again == instance


def test_spec_and_records_round_trip_through_json_with_a_stable_spec_hash() -> None:
    spec = _spec()
    encoded = spec.model_dump_json()
    assert '"created_at_utc":"2026-09-06T12:00:00Z"' in encoded
    assert '"amount":"10000"' in encoded
    round_tripped = ExperimentSpec.model_validate_json(encoded)
    assert round_tripped == spec
    assert experiment_spec_hash(round_tripped) == experiment_spec_hash(spec)
    for record in (
        _record(),
        _shaped_record(_E.QUEUED),
        _shaped_record(_E.CANCELLED),
        _record(state=_E.CANCELLED, cancellation_correlation_id=_CORRELATION),
    ):
        again = ExperimentRecord.model_validate_json(record.model_dump_json())
        assert again == record
        assert canonical_json_bytes(again) == canonical_json_bytes(record)


# --- Hashing (plan 3.5) --------------------------------------------------------------


def test_the_configuration_hash_ignores_the_envelope_the_instant_and_itself() -> None:
    draft = _draft()
    spec_a = build_experiment_spec(draft, _MATERIAL, _CREATED)
    spec_b = _revalidate(
        ExperimentSpec,
        spec_a,
        created_at_utc=_CREATED + timedelta(days=1),
        configuration_hash=_OTHER_SHA256,
    )
    payload = experiment_configuration_payload(draft, _MATERIAL)
    assert payload == _configuration_payload(draft, _MATERIAL)
    assert set(payload) == {
        "material_base_configuration_hash",
        *ExperimentSpecDraft.model_fields,
    }
    assert set(payload).isdisjoint(
        {"schema_version", "configuration_hash", "created_at_utc"}
    )
    expected = profile_hash(HashingProfile.EXPERIMENT_CONFIGURATION_V1, payload)
    assert experiment_configuration_hash(draft, _MATERIAL) == expected
    assert experiment_configuration_hash(spec_a, _MATERIAL) == expected
    assert experiment_configuration_hash(spec_b, _MATERIAL) == expected
    assert spec_a.configuration_hash == expected
    assert experiment_configuration_payload(spec_b, _MATERIAL) == payload
    spec_identity = experiment_spec_hash(spec_a)
    assert experiment_configuration_hash(draft, _MATERIAL) != spec_identity


def _mutated_draft(field: str) -> tuple[ExperimentSpecDraft, str]:
    """One draft differing from the fixture in exactly ``field``, and the material
    hash to pair it with (only the material mutation changes that)."""
    base = _draft()
    material = _MATERIAL
    if field == "material_base_configuration_hash":
        return base, _OTHER_MATERIAL
    updates: dict[str, object] = {
        "strategy_version_hash": _OTHER_SHA256,
        "dataset_version_hash": _OTHER_SHA256,
        "selected_engine_slots": (
            _slots()[0],
            _slot(
                1,
                _SLOT_B,
                _adapter("adapter.beta", "1.2.0"),
                _engine("engine.beta", "0.9.1"),
            ),
        ),
        "starting_balance": _money("10001"),
        "fee_assumptions": FeeAssumptions(
            maker_fee_rate=Decimal("0.0011"),
            taker_fee_rate=Decimal("0.002"),
        ),
        "slippage_assumptions": SlippageAssumptions(model=SlippageModel.NONE),
        "execution_assumptions": _revalidate(
            ExecutionAssumptions,
            _execution(),
            signal_to_order_timing=SignalToOrderTiming.SAME_BAR_CLOSE,
        ),
        "comparison_level": ComparisonLevel.LEVEL_1,
        "retry_policy": _policy(maximum_attempts_per_slot=3),
    }
    return _revalidate(ExperimentSpecDraft, base, **{field: updates[field]}), material


_CONFIGURATION_FIELDS = (
    *ExperimentSpecDraft.model_fields,
    "material_base_configuration_hash",
)


@pytest.mark.parametrize("field", _CONFIGURATION_FIELDS)
def test_the_configuration_hash_changes_with_each_draft_field_and_the_material_hash(
    field: str,
) -> None:
    baseline = _draft()
    mutated, material = _mutated_draft(field)
    dump_a = baseline.model_dump(mode="json")
    dump_b = mutated.model_dump(mode="json")
    differing = {
        name
        for name in ExperimentSpecDraft.model_fields
        if dump_a[name] != dump_b[name]
    }
    expected: set[str] = set()
    if field != "material_base_configuration_hash":
        expected = {field}
    assert differing == expected
    before = experiment_configuration_hash(baseline, _MATERIAL)
    after = experiment_configuration_hash(mutated, material)
    assert before != after


def test_the_configuration_mutation_table_covers_every_material_input() -> None:
    expected = set(ExperimentSpecDraft.model_fields) | {
        "material_base_configuration_hash"
    }
    assert set(_CONFIGURATION_FIELDS) == expected


@pytest.mark.parametrize("field", _SPEC_FIELDS[1:])
def test_the_spec_hash_changes_with_every_spec_field_except_the_fixed_envelope(
    field: str,
) -> None:
    baseline = _spec()
    if field in ExperimentSpecDraft.model_fields:
        mutated_draft, _ = _mutated_draft(field)
        mutated = build_experiment_spec(mutated_draft, _MATERIAL, _CREATED)
        # The builder derives configuration_hash from the draft, so a draft mutation
        # legitimately moves that derived field too; compare the draft projection.
        names = tuple(ExperimentSpecDraft.model_fields)
    else:
        if field == "configuration_hash":
            value: object = _OTHER_SHA256
        else:
            value = _CREATED + timedelta(seconds=1)
        mutated = _revalidate(ExperimentSpec, baseline, **{field: value})
        names = tuple(ExperimentSpec.model_fields)
    dump_a = baseline.model_dump(mode="json")
    dump_b = mutated.model_dump(mode="json")
    differing = {name for name in names if dump_a[name] != dump_b[name]}
    assert differing == {field}
    assert experiment_spec_hash(baseline) != experiment_spec_hash(mutated)


def test_build_experiment_spec_copies_the_draft_and_derives_the_rest() -> None:
    draft = _draft()
    spec = build_experiment_spec(draft, _MATERIAL, _CREATED)
    assert spec.schema_version == "1.0.0"
    assert spec.created_at_utc == _CREATED
    dumped = spec.model_dump(mode="json")
    projected = {k: dumped[k] for k in ExperimentSpecDraft.model_fields}
    assert projected == draft.model_dump(mode="json")
    assert spec.configuration_hash == experiment_configuration_hash(draft, _MATERIAL)
    assert build_experiment_spec(draft, _MATERIAL, _CREATED) == spec
    with pytest.raises(ValidationError):
        build_experiment_spec(draft, _MATERIAL, _NAIVE)
    with pytest.raises(ValidationError):
        build_experiment_spec(draft, "Z" * 64, _CREATED)
    with pytest.raises(ValidationError):
        experiment_configuration_hash(draft, "c" * 63)


# --- Queue-time freeze predicate (plan section 7) -----------------------------------


def _validated_record() -> ExperimentRecord:
    return _record(state=_E.VALIDATED, revision=1)


def _freeze(record: ExperimentRecord, **overrides: object) -> None:
    arguments: dict[str, object] = {
        "expected_revision": record.revision,
        "config_derived_retry_policy": record.spec.retry_policy,
        "material_base_configuration_hash": _MATERIAL,
        "slot_compatibility": _compatibilities(),
    }
    arguments.update(overrides)
    assert_queue_freeze(record, **arguments)  # type: ignore[arg-type]


def _violation(record: ExperimentRecord, **overrides: object) -> QueueFreezeCheck:
    with pytest.raises(QueueFreezeViolation) as captured:
        _freeze(record, **overrides)
    assert isinstance(captured.value, ValueError)
    return captured.value.check


def test_the_freeze_predicate_accepts_consistent_inputs_and_is_pure() -> None:
    record = _validated_record()
    _freeze(record)
    permuted = _policy(automatically_retry_terminal_states=(_T.UNAVAILABLE, _T.FAILED))
    stored = canonical_json_bytes(record.spec.retry_policy)
    assert canonical_json_bytes(permuted) == stored
    _freeze(record, config_derived_retry_policy=permuted)
    assert record == _validated_record()


def test_the_freeze_predicate_refuses_a_retry_policy_byte_mismatch() -> None:
    record = _validated_record()
    mismatch = _policy(retry_delay_seconds=31)
    check = _violation(record, config_derived_retry_policy=mismatch)
    assert check is QueueFreezeCheck.RETRY_POLICY_BYTES
    listed = _policy(automatically_retry_terminal_states=(_T.FAILED,))
    check = _violation(record, config_derived_retry_policy=listed)
    assert check is QueueFreezeCheck.RETRY_POLICY_BYTES


def test_the_freeze_predicate_refuses_a_material_hash_that_does_not_reproduce() -> None:
    record = _validated_record()
    check = _violation(record, material_base_configuration_hash=_OTHER_MATERIAL)
    assert check is QueueFreezeCheck.CONFIGURATION_HASH
    with pytest.raises(ValidationError):
        _freeze(record, material_base_configuration_hash="not-a-hash")


@pytest.mark.parametrize(
    "shape",
    ["empty", "short", "extra", "reversed", "duplicate", "foreign", "inconsistent"],
)
def test_the_freeze_predicate_refuses_a_slot_compatibility_that_does_not_match(
    shape: str,
) -> None:
    record = _validated_record()
    first, second = _compatibilities()
    foreign = _compatibility(
        logical_slot_id=_SLOT_C, availability_observation_id=_AVAIL_C
    )
    shapes: dict[str, tuple[SlotCompatibility, ...]] = {
        "empty": (),
        "short": (first,),
        "extra": (first, second, foreign),
        "reversed": (second, first),
        "duplicate": (first, first),
        "foreign": (first, foreign),
        "inconsistent": (first, second, second),
    }
    check = _violation(record, slot_compatibility=shapes[shape])
    assert check is QueueFreezeCheck.SLOT_COMPATIBILITY


@pytest.mark.parametrize(
    "state",
    [state for state in ExperimentState if state is not _E.VALIDATED],
)
def test_the_freeze_predicate_refuses_every_non_validated_stored_state(
    state: ExperimentState,
) -> None:
    record = _shaped_record(state, revision=1)
    # Stored state is check 1 and precedes every other check, so a record that also
    # carries a retry-policy mismatch still reports the state.
    assert _violation(record) is QueueFreezeCheck.STORED_STATE
    mismatch = _policy(retry_delay_seconds=31)
    check = _violation(record, config_derived_retry_policy=mismatch)
    assert check is QueueFreezeCheck.STORED_STATE


def test_the_freeze_predicate_refuses_a_moved_revision_before_content_checks() -> None:
    record = _validated_record()
    check = _violation(record, expected_revision=record.revision + 1)
    assert check is QueueFreezeCheck.EXPECTED_REVISION
    check = _violation(
        record,
        expected_revision=record.revision + 1,
        config_derived_retry_policy=_policy(retry_delay_seconds=31),
    )
    assert check is QueueFreezeCheck.EXPECTED_REVISION


def test_the_freeze_predicate_reports_checks_in_section_seven_order() -> None:
    record = _validated_record()
    check = _violation(
        record,
        config_derived_retry_policy=_policy(retry_delay_seconds=31),
        material_base_configuration_hash=_OTHER_MATERIAL,
        slot_compatibility=(),
    )
    assert check is QueueFreezeCheck.RETRY_POLICY_BYTES
    check = _violation(
        record,
        material_base_configuration_hash=_OTHER_MATERIAL,
        slot_compatibility=(),
    )
    assert check is QueueFreezeCheck.CONFIGURATION_HASH
    assert [check.value for check in QueueFreezeCheck] == [
        "STORED_STATE",
        "EXPECTED_REVISION",
        "RETRY_POLICY_BYTES",
        "CONFIGURATION_HASH",
        "SPEC_HASH",
        "SELECTED_SLOTS",
        "SLOT_COMPATIBILITY",
    ]


def test_spec_hash_and_slot_checks_are_unreachable_through_a_valid_record() -> None:
    """Checks 4 and 5 are re-evaluated defensively by the predicate, but the record
    validator already enforces both, so no validated record can reach them."""
    with pytest.raises(ValidationError, match="spec_hash"):
        _record(state=_E.VALIDATED, spec_hash=_OTHER_SHA256)
    with pytest.raises(ValidationError, match="ordinal"):
        _spec(selected_engine_slots=_slots_with_ordinals(1, 0))


def test_the_defensive_checks_fire_only_on_an_unvalidated_record() -> None:
    """``model_construct`` bypasses validation, which is the only way to reach
    checks 4 and 5; the predicate still refuses such a record in section 7 order."""
    valid = _validated_record()
    fields = dict(valid)
    fields["spec_hash"] = _OTHER_SHA256
    tampered = ExperimentRecord.model_construct(**fields)
    check = _violation(tampered)
    assert check is QueueFreezeCheck.SPEC_HASH
    # Disordered ordinals and an empty selection are both unconstructible through
    # validation (the tuple bound and the ordinal rule fire first), so this is the
    # only way to reach either branch of check 5.
    for slots in (_slots_with_ordinals(1, 0), ()):
        spec_fields = dict(valid.spec)
        spec_fields["selected_engine_slots"] = slots
        provisional = ExperimentSpec.model_construct(**spec_fields)
        # Keep checks 3 and 4 satisfied so that the slot check is the first to fire.
        spec_fields["configuration_hash"] = experiment_configuration_hash(
            provisional, _MATERIAL
        )
        tampered_spec = ExperimentSpec.model_construct(**spec_fields)
        fields = dict(valid)
        fields["spec"] = tampered_spec
        fields["spec_hash"] = experiment_spec_hash(tampered_spec)
        check = _violation(ExperimentRecord.model_construct(**fields))
        assert check is QueueFreezeCheck.SELECTED_SLOTS


# --- RetryPolicy (plan 3.4) ----------------------------------------------------------


def test_retry_state_permutations_normalize_and_hash_identically() -> None:
    forward = _policy(automatically_retry_terminal_states=(_T.FAILED, _T.UNAVAILABLE))
    backward = _policy(automatically_retry_terminal_states=(_T.UNAVAILABLE, _T.FAILED))
    assert forward.automatically_retry_terminal_states == (_T.FAILED, _T.UNAVAILABLE)
    assert backward == forward
    assert canonical_json_bytes(backward) == canonical_json_bytes(forward)
    three = RetryPolicy.model_validate_json(
        '{"schema_version":"1.0.0","maximum_attempts_per_slot":3,'
        '"automatically_retry_terminal_states":["UNAVAILABLE","TIMED_OUT","FAILED"],'
        '"retry_delay_seconds":0,'
        '"require_fresh_availability_observation_for_unavailable":true}'
    )
    assert three.model_dump(mode="json")["automatically_retry_terminal_states"] == [
        "FAILED",
        "TIMED_OUT",
        "UNAVAILABLE",
    ]
    spec_a = build_experiment_spec(_draft(retry_policy=forward), _MATERIAL, _CREATED)
    spec_b = build_experiment_spec(_draft(retry_policy=backward), _MATERIAL, _CREATED)
    assert experiment_spec_hash(spec_a) == experiment_spec_hash(spec_b)
    assert spec_a.configuration_hash == spec_b.configuration_hash


def test_retry_policy_rejects_duplicate_and_foreign_terminal_states() -> None:
    with pytest.raises(ValidationError, match="unique"):
        _policy(automatically_retry_terminal_states=(_T.FAILED, _T.FAILED))
    with pytest.raises(ValidationError, match="foreign"):
        _policy(automatically_retry_terminal_states=("CANCELLED",))
    with pytest.raises(ValidationError, match="array"):
        _policy(automatically_retry_terminal_states="FAILED")
    with pytest.raises(ValidationError, match="strings"):
        _policy(automatically_retry_terminal_states=(1,))
    # A plain string member is accepted and normalized, mirroring RetryConfig, but
    # never collapsed: the accepted length always equals the input length.
    accepted = _policy(automatically_retry_terminal_states=("UNAVAILABLE", "FAILED"))
    assert accepted.automatically_retry_terminal_states == (_T.FAILED, _T.UNAVAILABLE)
    assert len(accepted.automatically_retry_terminal_states) == 2


@pytest.mark.parametrize(
    "update",
    [
        {"maximum_attempts_per_slot": 0},
        {"maximum_attempts_per_slot": 6},
        {"maximum_attempts_per_slot": True},
        {"retry_delay_seconds": -1},
        {"retry_delay_seconds": 301},
        {"require_fresh_availability_observation_for_unavailable": False},
        {"schema_version": "1.0.1"},
    ],
)
def test_retry_policy_bounds_and_fixed_literals(update: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        _policy(**update)
    for boundary in (
        {"maximum_attempts_per_slot": 1},
        {"maximum_attempts_per_slot": 5},
        {"retry_delay_seconds": 0},
        {"retry_delay_seconds": 300},
    ):
        _policy(**boundary)


def test_retry_policy_has_no_optional_field_and_requires_the_explicit_empty_array() -> (
    None
):
    """Specification section 11.5: ``RetryPolicy`` has no optional fields and its
    terminal-state collection is an explicit empty array. The configuration
    defaults (1, empty, 0) live on ``RetryConfig`` and reach the policy only
    through the projection."""
    for name, field in RetryPolicy.model_fields.items():
        assert field.is_required(), name
    with pytest.raises(ValidationError):
        RetryPolicy.model_validate({"schema_version": "1.0.0"})
    full = _policy()
    for name in _POLICY_FIELDS:
        with pytest.raises(ValidationError):
            _without(RetryPolicy, full, name)
    empty = _policy(automatically_retry_terminal_states=())
    assert empty.model_dump(mode="json")["automatically_retry_terminal_states"] == []
    assert '"automatically_retry_terminal_states":[]' in empty.model_dump_json()
    schema = RetryPolicy.model_json_schema()
    assert schema["required"] == list(_POLICY_FIELDS)
    states = schema["properties"]["automatically_retry_terminal_states"]
    assert states["uniqueItems"] is True
    assert states["maxItems"] == 3
    assert "default" not in states


# --- Module purity (plan 3.1) ------------------------------------------------------

_AMBIENT_ROOTS = frozenset(
    {"os", "random", "secrets", "socket", "subprocess", "sys", "time", "uuid"}
)
_AMBIENT_CALLS = frozenset(
    {
        "monotonic",
        "now",
        "perf_counter",
        "today",
        "token_hex",
        "token_urlsafe",
        "utcnow",
        "uuid1",
        "uuid4",
    }
)


@pytest.mark.parametrize(
    "module",
    [experiment_module, retry_module],
    ids=("experiment", "retry"),
)
def test_the_new_domain_modules_reach_no_clock_random_process_or_configuration_source(
    module: ModuleType,
) -> None:
    roots: set[str] = set()
    modules: set[str] = set()
    calls: set[str] = set()
    for node in ast.walk(ast.parse(_module_source(module))):
        if isinstance(node, ast.Import):
            roots.update(alias.name.partition(".")[0] for alias in node.names)
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            roots.add(node.module.partition(".")[0])
            modules.add(node.module)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                calls.add(node.func.attr)
            elif isinstance(node.func, ast.Name):
                calls.add(node.func.id)
    assert roots.isdisjoint(_AMBIENT_ROOTS), sorted(roots & _AMBIENT_ROOTS)
    assert calls.isdisjoint(_AMBIENT_CALLS), sorted(calls & _AMBIENT_CALLS)
    forbidden_packages = (
        "crypto_lab.configuration",
        "crypto_lab.capabilities",
        "crypto_lab.experiments",
        "crypto_lab.adapters",
        "crypto_lab.artifacts",
        "crypto_lab.persistence",
    )
    assert not any(m.startswith(forbidden_packages) for m in modules), sorted(modules)
