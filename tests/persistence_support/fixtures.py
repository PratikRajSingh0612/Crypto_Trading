"""Pure fixture constructors of Stage 8 plan section 7.1.1."""

from __future__ import annotations

from typing import Final

from contract.harness import FAKE_ADAPTER_VERSION, FAKE_ENGINE
from crypto_lab.configuration.models import (
    ApplicationConfig,
    RetryConfig,
    SchedulerConfig,
)
from crypto_lab.configuration.retry_policy import retry_policy_from_config
from crypto_lab.configuration.snapshot import material_base_configuration_hash
from crypto_lab.domain.comparison_levels import ComparisonLevel
from crypto_lab.domain.experiment import (
    AdapterIdentity,
    EngineIdentity,
    ExperimentRecord,
    ExperimentSpec,
    ExperimentSpecDraft,
    SelectedEngineSlot,
    build_experiment_spec,
)
from crypto_lab.domain.lifecycle import ExperimentState, RetryTerminalState
from doubles.experiments import (
    DATASET_HASH,
    EXPERIMENT_ID,
    INSTANT,
    MATERIAL_HASH,
    SLOT_A,
    SLOT_C,
    STRATEGY_HASH,
    sample_draft,
    sample_experiment,
    sample_slot_compatibility,
    sample_slots,
)

#: The third slot's identities: the pair the Stage 5 in-memory flow uses for its
#: third slot. Distinct from (adapter.alpha 1.0.0, engine.alpha 2.3.4) and
#: (adapter.beta 1.2.0, engine.beta 2.3.4) under the validator key
#: (adapter_name, adapter_version, engine_name, engine_version).
ADAPTER_GAMMA: Final = AdapterIdentity(
    adapter_name="adapter.gamma", adapter_version="3.0.0"
)
ENGINE_GAMMA: Final = EngineIdentity(engine_name="engine.gamma", engine_version="1.0.0")
THIRD_SLOT: Final = SelectedEngineSlot(
    logical_slot_id=SLOT_C,
    slot_ordinal=2,
    adapter=ADAPTER_GAMMA,
    engine=ENGINE_GAMMA,
)


def three_slot_draft() -> ExperimentSpecDraft:
    """The shared two slots plus ``THIRD_SLOT`` (C-28)."""
    return sample_draft(selected_engine_slots=(*sample_slots(), THIRD_SLOT))


def three_slot_experiment(
    state: ExperimentState, *, experiment_id: str = EXPERIMENT_ID
) -> ExperimentRecord:
    """A QUEUED-or-later record over ``three_slot_draft`` with aligned compatibility."""
    draft = three_slot_draft()
    return sample_experiment(
        state,
        experiment_id=experiment_id,
        draft=draft,
        slot_compatibility=sample_slot_compatibility(draft),
    )


def other_spec() -> ExperimentSpec:
    """One non-slot field changed (LEVEL_2 -> LEVEL_1); slots unchanged."""
    return build_experiment_spec(
        sample_draft(comparison_level=ComparisonLevel.LEVEL_1), MATERIAL_HASH, INSTANT
    )


def other_slots_spec() -> ExperimentSpec:
    """The slot set changed; for DRAFT records only (no slot_compatibility)."""
    return build_experiment_spec(three_slot_draft(), MATERIAL_HASH, INSTANT)


def config_backed_draft(
    config: ApplicationConfig,
    *,
    strategy_version_hash: str = STRATEGY_HASH,
    dataset_version_hash: str = DATASET_HASH,
) -> ExperimentSpecDraft:
    """The shared draft carrying the configuration-derived retry policy."""
    return sample_draft(
        strategy_version_hash=strategy_version_hash,
        dataset_version_hash=dataset_version_hash,
        retry_policy=retry_policy_from_config(config.scheduler.retry),
    )


def config_backed_spec(config: ApplicationConfig) -> ExperimentSpec:
    """A spec whose configuration_hash and retry_policy agree with the snapshot."""
    return build_experiment_spec(
        config_backed_draft(config), material_base_configuration_hash(config), INSTANT
    )


def supervised_draft(
    config: ApplicationConfig,
    adapter_name: str,
    *,
    strategy_version_hash: str = STRATEGY_HASH,
    dataset_version_hash: str = DATASET_HASH,
) -> ExperimentSpecDraft:
    """One slot naming the scenario adapter at the fake catalogue's identities."""
    return sample_draft(
        strategy_version_hash=strategy_version_hash,
        dataset_version_hash=dataset_version_hash,
        selected_engine_slots=(
            SelectedEngineSlot(
                logical_slot_id=SLOT_A,
                slot_ordinal=0,
                adapter=AdapterIdentity(
                    adapter_name=adapter_name, adapter_version=FAKE_ADAPTER_VERSION
                ),
                engine=FAKE_ENGINE,
            ),
        ),
        retry_policy=retry_policy_from_config(config.scheduler.retry),
    )


def other_config() -> ApplicationConfig:
    """ApplicationConfig() with one bounded scheduler.retry field changed (C-32)."""
    return ApplicationConfig(
        scheduler=SchedulerConfig(retry=RetryConfig(maximum_attempts_per_slot=2))
    )


def retrying_config() -> ApplicationConfig:
    """The smallest explicit configuration that admits Task 7's one successor."""
    return ApplicationConfig(
        scheduler=SchedulerConfig(
            retry=RetryConfig(
                maximum_attempts_per_slot=2,
                automatically_retry_terminal_states=(RetryTerminalState.FAILED,),
                retry_delay_seconds=30,
            )
        )
    )
