"""Property tests for experiment identity (Stage 5 plan sections 3.5 and 13.2).

Three claims, in the style of ``tests/property/test_strategy_hashing.py``:

**Configuration-hash exclusions.** ``configuration_hash`` is a function of the
material base configuration hash and spec fields 2-10 alone. Varying
``created_at_utc`` and the stored ``configuration_hash`` never moves it, and the
envelope ``schema_version`` is proven excluded by construction, because its
``Literal`` admits one value and the payload key set is asserted directly.

**Material sensitivity.** Two drafts, or two specs, generated to differ in exactly
one field have different hashes. The test first proves that exactly that field
differs by comparing the two JSON-mode dumps field by field, and only then asserts
the digests differ, so no inequality can come from two fields moving at once.

**Retry-state normalization.** Permuting ``automatically_retry_terminal_states``
leaves the embedded policy and both hashes unchanged (specification 10.2 and
28.4), while a repeated state is rejected rather than collapsed (specification
11.5).

Generators draw **plain data** only and every model is constructed in the test
body; ``st.builds`` is never used, and no per-test ``settings`` override is needed
because model construction here is sub-millisecond.
"""

from __future__ import annotations

import copy
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, NamedTuple

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from crypto_lab.domain.comparison_levels import ComparisonLevel
from crypto_lab.domain.experiment import (
    AdapterIdentity,
    BarOrderPriority,
    EngineIdentity,
    ExecutionAssumptions,
    ExperimentSpec,
    ExperimentSpecDraft,
    FeeAssumptions,
    FillConvention,
    SelectedEngineSlot,
    SignalToOrderTiming,
    SlippageAssumptions,
    SlippageModel,
    build_experiment_spec,
    experiment_configuration_hash,
    experiment_configuration_payload,
    experiment_spec_hash,
    experiment_spec_payload,
)
from crypto_lab.domain.hashing import HashingProfile, profile_hash
from crypto_lab.domain.lifecycle import RetryTerminalState
from crypto_lab.domain.records import Money
from crypto_lab.domain.retry import RetryPolicy

_CREATED = datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)
_VERSIONS = ("1.0.0", "1.9.0", "1.10.0", "2.0.0")
_CURRENCIES = ("USDT", "USDC", "EUR")
_ONE = Decimal("1")
_STEP = Decimal("0.00000001")


def _no_negative_zero(value: Decimal) -> bool:
    return not (value.is_zero() and value.is_signed())


# --- Plain-data generators -------------------------------------------------------

_SHA256 = st.integers(min_value=0, max_value=2**256 - 1).map(lambda n: f"{n:064x}")
_UUID4 = st.uuids(version=4).map(str)
_SLOT_IDS = st.lists(_UUID4, min_size=8, max_size=8, unique=True)
_SLOT_COUNT = st.integers(min_value=1, max_value=8)
_RATE = st.decimals(
    min_value=Decimal("0"),
    max_value=_ONE,
    allow_nan=False,
    allow_infinity=False,
    places=8,
).filter(_no_negative_zero)
_BASIS_POINTS = st.decimals(
    min_value=Decimal("0"),
    max_value=Decimal("10000"),
    allow_nan=False,
    allow_infinity=False,
    places=4,
).filter(_no_negative_zero)
_AMOUNT = st.decimals(
    min_value=_STEP,
    max_value=Decimal("1000000000000"),
    allow_nan=False,
    allow_infinity=False,
    places=8,
)
_VERSION_LIST = st.lists(st.sampled_from(_VERSIONS), min_size=8, max_size=8)
_PRECISION = st.integers(min_value=0, max_value=18)
_RETRY_STATES = st.lists(
    st.sampled_from(list(RetryTerminalState)),
    unique=True,
    max_size=3,
)


class _Fields(NamedTuple):
    """Every generated material input, as plain data."""

    strategy_hash: str
    dataset_hash: str
    material_hash: str
    slot_count: int
    slot_ids: list[str]
    adapter_versions: list[str]
    engine_versions: list[str]
    currency: str
    amount: Decimal
    maker: Decimal
    taker: Decimal
    slippage_model: SlippageModel
    basis_points: Decimal
    timing: SignalToOrderTiming
    priority: BarOrderPriority
    fill: FillConvention
    price_precision: int
    quantity_precision: int
    level: ComparisonLevel
    attempts: int
    retry_states: list[RetryTerminalState]
    delay: int


_FIELD_STRATEGIES: dict[str, st.SearchStrategy[Any]] = {
    "strategy_hash": _SHA256,
    "dataset_hash": _SHA256,
    "material_hash": _SHA256,
    "slot_count": _SLOT_COUNT,
    "slot_ids": _SLOT_IDS,
    "adapter_versions": _VERSION_LIST,
    "engine_versions": _VERSION_LIST,
    "currency": st.sampled_from(_CURRENCIES),
    "amount": _AMOUNT,
    "maker": _RATE,
    "taker": _RATE,
    "slippage_model": st.sampled_from(list(SlippageModel)),
    "basis_points": _BASIS_POINTS,
    "timing": st.sampled_from(list(SignalToOrderTiming)),
    "priority": st.sampled_from(list(BarOrderPriority)),
    "fill": st.sampled_from(list(FillConvention)),
    "price_precision": _PRECISION,
    "quantity_precision": _PRECISION,
    "level": st.sampled_from(list(ComparisonLevel)),
    "attempts": st.integers(min_value=1, max_value=5),
    "retry_states": _RETRY_STATES,
    "delay": st.integers(min_value=0, max_value=300),
}
_DRAWN = st.tuples(*(_FIELD_STRATEGIES[name] for name in _Fields._fields))


def _fields(drawn: tuple[Any, ...]) -> _Fields:
    return _Fields(*drawn)


# --- Assembly in the test body ----------------------------------------------------


def _slots(fields: _Fields) -> tuple[SelectedEngineSlot, ...]:
    # Index-derived names make every (adapter, engine) pair unique by construction.
    return tuple(
        SelectedEngineSlot(
            logical_slot_id=f"slot_{fields.slot_ids[index]}",
            slot_ordinal=index,
            adapter=AdapterIdentity(
                adapter_name=f"adapter.slot{index}",
                adapter_version=fields.adapter_versions[index],
            ),
            engine=EngineIdentity(
                engine_name=f"engine.slot{index}",
                engine_version=fields.engine_versions[index],
            ),
        )
        for index in range(fields.slot_count)
    )


def _slippage(fields: _Fields) -> SlippageAssumptions:
    if fields.slippage_model is SlippageModel.FIXED_BASIS_POINTS:
        return SlippageAssumptions(
            model=fields.slippage_model,
            basis_points=fields.basis_points,
        )
    return SlippageAssumptions(model=fields.slippage_model)


def _policy(fields: _Fields) -> RetryPolicy:
    return RetryPolicy(
        schema_version="1.0.0",
        maximum_attempts_per_slot=fields.attempts,
        automatically_retry_terminal_states=tuple(fields.retry_states),
        retry_delay_seconds=fields.delay,
        require_fresh_availability_observation_for_unavailable=True,
    )


def _draft(fields: _Fields) -> ExperimentSpecDraft:
    return ExperimentSpecDraft(
        strategy_version_hash=fields.strategy_hash,
        dataset_version_hash=fields.dataset_hash,
        selected_engine_slots=_slots(fields),
        starting_balance=Money(
            schema_version="1.0.0",
            currency=fields.currency,
            amount=fields.amount,
        ),
        fee_assumptions=FeeAssumptions(
            maker_fee_rate=fields.maker,
            taker_fee_rate=fields.taker,
        ),
        slippage_assumptions=_slippage(fields),
        execution_assumptions=ExecutionAssumptions(
            signal_to_order_timing=fields.timing,
            bar_order_priority=fields.priority,
            fill_convention=fields.fill,
            price_precision=fields.price_precision,
            quantity_precision=fields.quantity_precision,
            rounding_mode="ROUND_HALF_EVEN",
        ),
        comparison_level=fields.level,
        retry_policy=_policy(fields),
    )


# --- Single-field mutations, each guaranteed to keep the draft valid --------------


def _flip_hex(digest: str) -> str:
    return ("0" if digest[0] != "0" else "1") + digest[1:]


def _rotate[T](vocabulary: Sequence[T], current: T) -> T:
    return vocabulary[(vocabulary.index(current) + 1) % len(vocabulary)]


def _nudge_rate(rate: Decimal) -> Decimal:
    return rate - _STEP if rate == _ONE else rate + _STEP


_CONFIGURATION_MUTATIONS: dict[str, Callable[[_Fields], _Fields]] = {
    "strategy_version_hash": lambda f: f._replace(
        strategy_hash=_flip_hex(f.strategy_hash)
    ),
    "dataset_version_hash": lambda f: f._replace(
        dataset_hash=_flip_hex(f.dataset_hash)
    ),
    "selected_engine_slots": lambda f: f._replace(
        engine_versions=[
            _rotate(_VERSIONS, f.engine_versions[0]),
            *f.engine_versions[1:],
        ]
    ),
    "starting_balance": lambda f: f._replace(amount=f.amount + _ONE),
    "fee_assumptions": lambda f: f._replace(maker=_nudge_rate(f.maker)),
    "slippage_assumptions": lambda f: f._replace(
        slippage_model=_rotate(list(SlippageModel), f.slippage_model)
    ),
    "execution_assumptions": lambda f: f._replace(
        timing=_rotate(list(SignalToOrderTiming), f.timing)
    ),
    "comparison_level": lambda f: f._replace(
        level=_rotate(list(ComparisonLevel), f.level)
    ),
    "retry_policy": lambda f: f._replace(attempts=(f.attempts % 5) + 1),
    "material_base_configuration_hash": lambda f: f._replace(
        material_hash=_flip_hex(f.material_hash)
    ),
}
_SPEC_ONLY_FIELDS = ("configuration_hash", "created_at_utc")
_DRAFT_MUTATION_NAMES = tuple(
    sorted(set(_CONFIGURATION_MUTATIONS) - {"material_base_configuration_hash"})
)
_SPEC_MUTATION_NAMES = (*_DRAFT_MUTATION_NAMES, *_SPEC_ONLY_FIELDS)


def _spec_from(fields: _Fields) -> ExperimentSpec:
    return build_experiment_spec(_draft(fields), fields.material_hash, _CREATED)


def _mutated_spec(fields: _Fields, name: str) -> ExperimentSpec:
    if name in _CONFIGURATION_MUTATIONS:
        return _spec_from(_CONFIGURATION_MUTATIONS[name](fields))
    baseline = _spec_from(fields)
    payload = baseline.model_dump(mode="python")
    if name == "configuration_hash":
        payload[name] = _flip_hex(baseline.configuration_hash)
    else:
        payload[name] = baseline.created_at_utc + timedelta(seconds=1)
    return ExperimentSpec.model_validate(payload)


def _differing(a: dict[str, Any], b: dict[str, Any], names: Sequence[str]) -> set[str]:
    return {name for name in names if a[name] != b[name]}


# --- Properties -----------------------------------------------------------------


@given(drawn=_DRAWN, seconds=st.integers(min_value=0, max_value=10**7), other=_SHA256)
def test_the_configuration_hash_ignores_the_envelope_the_instant_and_itself(
    drawn: tuple[Any, ...],
    seconds: int,
    other: str,
) -> None:
    fields = _fields(drawn)
    draft = _draft(fields)
    material = fields.material_hash
    spec_a = build_experiment_spec(draft, material, _CREATED)
    spec_b = ExperimentSpec.model_validate(
        {
            **spec_a.model_dump(mode="python"),
            "created_at_utc": _CREATED + timedelta(seconds=seconds),
            "configuration_hash": other,
        }
    )
    payload = experiment_configuration_payload(draft, material)
    assert set(payload) == {
        "material_base_configuration_hash",
        *ExperimentSpecDraft.model_fields,
    }
    expected = profile_hash(HashingProfile.EXPERIMENT_CONFIGURATION_V1, payload)
    assert spec_a.configuration_hash == expected
    assert experiment_configuration_hash(draft, material) == expected
    assert experiment_configuration_hash(spec_a, material) == expected
    assert experiment_configuration_hash(spec_b, material) == expected


@given(drawn=_DRAWN, name=st.sampled_from(sorted(_CONFIGURATION_MUTATIONS)))
def test_two_drafts_differing_in_one_material_input_have_different_configuration_hashes(
    drawn: tuple[Any, ...],
    name: str,
) -> None:
    fields = _fields(drawn)
    mutated_fields = _CONFIGURATION_MUTATIONS[name](fields)
    draft_a = _draft(fields)
    draft_b = _draft(mutated_fields)
    differing = _differing(
        draft_a.model_dump(mode="json"),
        draft_b.model_dump(mode="json"),
        tuple(ExperimentSpecDraft.model_fields),
    )
    if name == "material_base_configuration_hash":
        assert differing == set()
        assert fields.material_hash != mutated_fields.material_hash
    else:
        assert differing == {name}
        assert fields.material_hash == mutated_fields.material_hash
    hash_a = experiment_configuration_hash(draft_a, fields.material_hash)
    hash_b = experiment_configuration_hash(draft_b, mutated_fields.material_hash)
    assert hash_a != hash_b


@given(drawn=_DRAWN, name=st.sampled_from(_SPEC_MUTATION_NAMES))
def test_two_specs_differing_in_one_field_have_different_spec_hashes(
    drawn: tuple[Any, ...],
    name: str,
) -> None:
    fields = _fields(drawn)
    spec_a = _spec_from(fields)
    spec_b = _mutated_spec(fields, name)
    dump_a = spec_a.model_dump(mode="json")
    dump_b = spec_b.model_dump(mode="json")
    if name in ExperimentSpecDraft.model_fields:
        # A draft mutation legitimately moves the derived configuration_hash too, so
        # the single-field proof is made over the draft projection.
        differing = _differing(dump_a, dump_b, tuple(ExperimentSpecDraft.model_fields))
        assert differing == {name}
        assert dump_a["configuration_hash"] != dump_b["configuration_hash"]
    else:
        differing = _differing(dump_a, dump_b, tuple(ExperimentSpec.model_fields))
        assert differing == {name}
    assert experiment_spec_hash(spec_a) != experiment_spec_hash(spec_b)


@given(drawn=_DRAWN)
def test_an_unmutated_rebuild_from_plain_data_reproduces_both_hashes(
    drawn: tuple[Any, ...],
) -> None:
    fields = _fields(drawn)
    first = _spec_from(fields)
    second = _spec_from(_fields(copy.deepcopy(drawn)))
    assert first is not second
    assert first == second
    assert first.configuration_hash == second.configuration_hash
    assert experiment_spec_hash(first) == experiment_spec_hash(second)
    payload = experiment_spec_payload(first)
    expected = profile_hash(HashingProfile.EXPERIMENT_SPEC_V1, payload)
    assert experiment_spec_hash(first) == expected
    assert ExperimentSpec.model_validate_json(first.model_dump_json()) == first


@given(
    drawn=_DRAWN,
    rotation=st.integers(min_value=0, max_value=2),
    repeated=st.integers(min_value=0, max_value=2),
)
def test_retry_state_permutations_hash_identically_and_duplicates_are_rejected(
    drawn: tuple[Any, ...],
    rotation: int,
    repeated: int,
) -> None:
    fields = _fields(drawn)
    states = fields.retry_states
    permuted = [*states[rotation:], *states[:rotation]]
    reversed_states = list(reversed(states))
    spec_a = _spec_from(fields)
    spec_b = _spec_from(fields._replace(retry_states=permuted))
    spec_c = _spec_from(fields._replace(retry_states=reversed_states))
    canonical = tuple(state for state in RetryTerminalState if state in states)
    assert spec_a.retry_policy.automatically_retry_terminal_states == canonical
    assert spec_a.retry_policy == spec_b.retry_policy == spec_c.retry_policy
    assert experiment_spec_hash(spec_a) == experiment_spec_hash(spec_b)
    assert experiment_spec_hash(spec_a) == experiment_spec_hash(spec_c)
    assert spec_a.configuration_hash == spec_b.configuration_hash
    if states:
        duplicate = [*states, states[repeated % len(states)]]
        with pytest.raises(ValidationError, match="unique"):
            _policy(fields._replace(retry_states=duplicate))


@given(drawn=_DRAWN)
def test_every_generated_draft_is_valid_and_canonically_shaped(
    drawn: tuple[Any, ...],
) -> None:
    fields = _fields(drawn)
    draft = _draft(fields)
    assert 1 <= len(draft.selected_engine_slots) <= 8
    ordinals = tuple(slot.slot_ordinal for slot in draft.selected_engine_slots)
    assert ordinals == tuple(range(fields.slot_count))
    assert draft.starting_balance.amount > 0


def test_the_mutation_tables_name_exactly_the_material_inputs() -> None:
    assert set(_CONFIGURATION_MUTATIONS) == set(ExperimentSpecDraft.model_fields) | {
        "material_base_configuration_hash"
    }
    assert set(_SPEC_MUTATION_NAMES) == set(ExperimentSpec.model_fields) - {
        "schema_version"
    }
