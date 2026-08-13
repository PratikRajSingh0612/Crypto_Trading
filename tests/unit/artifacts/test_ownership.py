from __future__ import annotations

import pytest
from pydantic import ValidationError

from crypto_lab.artifacts.ownership import (
    ARTIFACT_OWNER_ADAPTER,
    AdapterArtifactOwner,
    DatasetArtifactOwner,
    ExperimentArtifactOwner,
    RunArtifactOwner,
    StrategyArtifactOwner,
    SystemArtifactOwner,
    artifact_owner_hash,
    owner_presentation,
)

_EXP = "exp_12345678-1234-4234-8234-123456789abc"
_RUN = "run_12345678-1234-4234-8234-123456789abc"
_DS = "ds_12345678-1234-4234-8234-123456789abc"
_STRV = "strv_12345678-1234-4234-8234-123456789abc"


def test_all_six_owner_variants_validate() -> None:
    owners = (
        RunArtifactOwner(
            owner_kind="RUN",
            experiment_id=_EXP,
            run_id=_RUN,
        ),
        ExperimentArtifactOwner(owner_kind="EXPERIMENT", experiment_id=_EXP),
        DatasetArtifactOwner(owner_kind="DATASET", dataset_id=_DS),
        StrategyArtifactOwner(
            owner_kind="STRATEGY",
            strategy_version_id=_STRV,
        ),
        AdapterArtifactOwner(
            owner_kind="ADAPTER",
            adapter_name="adapter.alpha",
            adapter_version="1.0.0",
        ),
        SystemArtifactOwner(
            owner_kind="SYSTEM",
            core_component="schema_registry",
            correlation_id="stage3",
        ),
    )
    for owner in owners:
        model_python = owner.model_dump(mode="python")
        model_json = owner.model_dump_json()
        adapter_python = ARTIFACT_OWNER_ADAPTER.dump_python(owner, mode="python")
        adapter_json = ARTIFACT_OWNER_ADAPTER.dump_json(owner)
        assert ARTIFACT_OWNER_ADAPTER.validate_python(model_python) == owner
        assert ARTIFACT_OWNER_ADAPTER.validate_json(model_json) == owner
        assert ARTIFACT_OWNER_ADAPTER.validate_python(adapter_python) == owner
        assert ARTIFACT_OWNER_ADAPTER.validate_json(adapter_json) == owner
        assert None not in model_python.values()
        assert "null" not in model_json
        assert None not in adapter_python.values()
        assert b"null" not in adapter_json


def test_owner_presentation_is_discriminator_first_and_omits_absent_fields() -> None:
    owner = RunArtifactOwner(
        owner_kind="RUN",
        experiment_id=_EXP,
        run_id=_RUN,
    )
    presentation = owner_presentation(owner)
    assert tuple(presentation) == ("owner_kind", "experiment_id", "run_id")
    assert "invocation_id" not in presentation


def test_system_owner_hash_matches_the_normative_golden() -> None:
    owner = SystemArtifactOwner(
        owner_kind="SYSTEM",
        core_component="schema_registry",
        correlation_id="stage3",
    )
    assert artifact_owner_hash(owner) == (
        "1ec94f41e62924c7715e7a6cd4c34cfa05af92060ecd7f05b8ebba580d213b11"
    )


@pytest.mark.parametrize(
    "payload",
    [
        {"owner_kind": "STRATEGY"},
        {
            "owner_kind": "STRATEGY",
            "strategy_version_id": _STRV,
            "strategy_version_hash": "a" * 64,
        },
        {
            "owner_kind": "ADAPTER",
            "adapter_name": "adapter.alpha",
            "adapter_version": "1.0.0",
            "engine_name": "engine.alpha",
        },
        {
            "owner_kind": "RUN",
            "experiment_id": _EXP,
            "run_id": _RUN,
            "dataset_id": _DS,
        },
        {"owner_kind": "FOREIGN"},
    ],
)
def test_owner_union_rejects_invalid_cross_branch_combinations(
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        ARTIFACT_OWNER_ADAPTER.validate_python(payload)


@pytest.mark.parametrize(
    "payload",
    [
        {
            "owner_kind": "RUN",
            "experiment_id": _EXP,
            "run_id": _RUN,
            "invocation_id": None,
        },
        {
            "owner_kind": "STRATEGY",
            "strategy_version_id": None,
            "strategy_version_hash": "a" * 64,
        },
        {
            "owner_kind": "ADAPTER",
            "adapter_name": "adapter.alpha",
            "adapter_version": "1.0.0",
            "engine_name": None,
        },
        {
            "owner_kind": "ADAPTER",
            "adapter_name": "adapter.alpha",
            "adapter_version": "1.0.0",
            "engine_version": None,
        },
    ],
)
def test_optional_owner_fields_reject_explicit_null(
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        ARTIFACT_OWNER_ADAPTER.validate_python(payload)


def test_owner_is_frozen() -> None:
    owner = SystemArtifactOwner(
        owner_kind="SYSTEM",
        core_component="schema_registry",
        correlation_id="stage3",
    )
    with pytest.raises(ValidationError, match="frozen_instance"):
        owner.core_component = "other"
