"""Stage 5 Task 2: the sole projection from configuration to the domain retry policy.

``retry_policy_from_config`` (plan section 3.4) maps the strict ``scheduler.retry``
configuration object onto the immutable ``RetryPolicy`` embedded in every
``ExperimentSpec``. Specification sections 16.2 and 22.2.1 require the two
representations to be byte-equivalent after canonical normalization before an
experiment is queued, which is exactly what plan section 7 check 2 compares, so the
last test here ties the projection to the freeze predicate rather than restating
it. ``RetryConfig`` already normalizes order and rejects duplicate or foreign states
(tests/unit/configuration/test_models.py); those assertions are cited as preventive,
not re-proven as new behaviour.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import ValidationError

from crypto_lab import configuration as configuration_package
from crypto_lab.configuration import retry_policy as projection_module
from crypto_lab.configuration.models import ApplicationConfig, RetryConfig
from crypto_lab.configuration.retry_policy import retry_policy_from_config
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.comparison_levels import ComparisonLevel
from crypto_lab.domain.compatibility import CompatibilityOutcome
from crypto_lab.domain.experiment import (
    AdapterIdentity,
    BarOrderPriority,
    EngineIdentity,
    ExecutionAssumptions,
    ExperimentRecord,
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
    experiment_spec_hash,
)
from crypto_lab.domain.lifecycle import ExperimentState, RetryTerminalState
from crypto_lab.domain.records import Money
from crypto_lab.domain.retry import RetryPolicy

_T = RetryTerminalState
_UUID_A = "12345678-1234-4234-8234-123456789abc"
_MATERIAL = "c" * 64
_CREATED = datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)


def _config(**overrides: object) -> RetryConfig:
    payload: dict[str, object] = {
        "maximum_attempts_per_slot": 2,
        "automatically_retry_terminal_states": ("FAILED", "UNAVAILABLE"),
        "retry_delay_seconds": 30,
    }
    payload.update(overrides)
    return RetryConfig.model_validate(payload)


def _draft(policy: RetryPolicy) -> ExperimentSpecDraft:
    return ExperimentSpecDraft(
        strategy_version_hash="a" * 64,
        dataset_version_hash="b" * 64,
        selected_engine_slots=(
            SelectedEngineSlot(
                logical_slot_id=f"slot_{_UUID_A}",
                slot_ordinal=0,
                adapter=AdapterIdentity(
                    adapter_name="adapter.alpha", adapter_version="1.0.0"
                ),
                engine=EngineIdentity(
                    engine_name="engine.alpha", engine_version="2.3.4"
                ),
            ),
        ),
        starting_balance=Money(
            schema_version="1.0.0", currency="USDT", amount=Decimal("10000")
        ),
        fee_assumptions=FeeAssumptions(
            maker_fee_rate=Decimal("0.001"), taker_fee_rate=Decimal("0.002")
        ),
        slippage_assumptions=SlippageAssumptions(model=SlippageModel.NONE),
        execution_assumptions=ExecutionAssumptions(
            signal_to_order_timing=SignalToOrderTiming.NEXT_BAR_OPEN,
            bar_order_priority=BarOrderPriority.EXITS_BEFORE_ENTRIES,
            fill_convention=FillConvention.FULL_FILL,
            price_precision=2,
            quantity_precision=8,
            rounding_mode="ROUND_HALF_EVEN",
        ),
        comparison_level=ComparisonLevel.LEVEL_2,
        retry_policy=policy,
    )


def test_retry_policy_from_config_maps_every_field_and_stamps_the_envelope() -> None:
    config = _config()
    policy = retry_policy_from_config(config)
    assert isinstance(policy, RetryPolicy)
    assert policy.schema_version == "1.0.0"
    assert policy.model_dump(mode="python", exclude={"schema_version"}) == (
        config.model_dump(mode="python")
    )
    assert set(RetryConfig.model_fields) == set(RetryPolicy.model_fields) - {
        "schema_version"
    }
    assert policy.automatically_retry_terminal_states == (_T.FAILED, _T.UNAVAILABLE)
    assert policy.maximum_attempts_per_slot == 2
    assert policy.retry_delay_seconds == 30
    assert policy.require_fresh_availability_observation_for_unavailable is True


def test_the_projection_round_trips_through_retry_config_and_canonical_json() -> None:
    config = _config()
    policy = retry_policy_from_config(config)
    back = RetryConfig.model_validate(
        policy.model_dump(mode="python", exclude={"schema_version"})
    )
    assert back == config
    again = retry_policy_from_config(back)
    assert again == policy
    assert canonical_json_bytes(again) == canonical_json_bytes(policy)
    assert RetryPolicy.model_validate_json(policy.model_dump_json()) == policy
    # The configuration defaults of specification section 22.2.1 reach the policy
    # only through this projection; the policy itself has no defaults.
    defaults = RetryPolicy(
        schema_version="1.0.0",
        maximum_attempts_per_slot=1,
        automatically_retry_terminal_states=(),
        retry_delay_seconds=0,
        require_fresh_availability_observation_for_unavailable=True,
    )
    assert retry_policy_from_config(ApplicationConfig().scheduler.retry) == defaults
    assert retry_policy_from_config(RetryConfig()) == defaults


def test_the_projection_preserves_the_fixed_order_and_never_collapses_states() -> None:
    # RetryConfig normalizes order before the projection sees it (preventive:
    # test_models.py::test_heartbeat_ratio_and_retry_normalization).
    reordered = _config(automatically_retry_terminal_states=("UNAVAILABLE", "FAILED"))
    assert retry_policy_from_config(reordered).automatically_retry_terminal_states == (
        _T.FAILED,
        _T.UNAVAILABLE,
    )
    assert canonical_json_bytes(retry_policy_from_config(reordered)) == (
        canonical_json_bytes(retry_policy_from_config(_config()))
    )
    complete = _config(
        automatically_retry_terminal_states=("UNAVAILABLE", "TIMED_OUT", "FAILED")
    )
    assert retry_policy_from_config(complete).automatically_retry_terminal_states == (
        _T.FAILED,
        _T.TIMED_OUT,
        _T.UNAVAILABLE,
    )
    # Duplicates and foreign values are rejected on both sides (specification 11.5),
    # so nothing is ever silently collapsed on the way into the policy.
    with pytest.raises(ValidationError, match="unique"):
        _config(automatically_retry_terminal_states=("FAILED", "FAILED"))
    with pytest.raises(ValidationError, match="unique"):
        RetryPolicy.model_validate(
            {
                **retry_policy_from_config(_config()).model_dump(mode="python"),
                "automatically_retry_terminal_states": (_T.FAILED, _T.FAILED),
            }
        )
    with pytest.raises(ValidationError, match="foreign"):
        _config(automatically_retry_terminal_states=("CANCELLED",))


def test_the_config_derived_policy_is_byte_identical_to_the_spec_policy() -> None:
    config = _config()
    policy = retry_policy_from_config(config)
    spec = build_experiment_spec(_draft(policy), _MATERIAL, _CREATED)
    assert canonical_json_bytes(spec.retry_policy) == canonical_json_bytes(
        retry_policy_from_config(config)
    )
    record = ExperimentRecord(
        schema_version="1.0.0",
        experiment_id=f"exp_{_UUID_A}",
        spec=spec,
        spec_hash=experiment_spec_hash(spec),
        state=ExperimentState.VALIDATED,
        created_at_utc=_CREATED,
        updated_at_utc=_CREATED,
        revision=1,
    )
    compatibility = (
        SlotCompatibility(
            logical_slot_id=f"slot_{_UUID_A}",
            outcome=CompatibilityOutcome.SUPPORTED,
            availability_observation_id=f"avail_{_UUID_A}",
            approximation_ids=(),
        ),
    )
    assert_queue_freeze(
        record,
        expected_revision=1,
        config_derived_retry_policy=retry_policy_from_config(
            _config(automatically_retry_terminal_states=("UNAVAILABLE", "FAILED"))
        ),
        material_base_configuration_hash=_MATERIAL,
        slot_compatibility=compatibility,
    )
    moved = retry_policy_from_config(_config(retry_delay_seconds=31))
    assert canonical_json_bytes(spec.retry_policy) != canonical_json_bytes(moved)
    with pytest.raises(QueueFreezeViolation) as captured:
        assert_queue_freeze(
            record,
            expected_revision=1,
            config_derived_retry_policy=moved,
            material_base_configuration_hash=_MATERIAL,
            slot_compatibility=compatibility,
        )
    assert captured.value.check is QueueFreezeCheck.RETRY_POLICY_BYTES


def test_the_projection_is_exported_and_imports_only_its_two_endpoints() -> None:
    assert configuration_package.retry_policy_from_config is retry_policy_from_config
    assert "retry_policy_from_config" in configuration_package.__all__
    assert projection_module.__file__ is not None
    tree = ast.parse(Path(projection_module.__file__).read_text(encoding="utf-8"))
    imported = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    assert imported == {
        "__future__",
        "crypto_lab.configuration.models",
        "crypto_lab.domain.retry",
    }
