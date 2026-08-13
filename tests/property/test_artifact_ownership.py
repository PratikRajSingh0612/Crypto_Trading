from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from crypto_lab.artifacts.ownership import (
    ARTIFACT_OWNER_ADAPTER,
    AdapterArtifactOwner,
    StrategyArtifactOwner,
    SystemArtifactOwner,
    artifact_owner_hash,
)

_STRV = "strv_12345678-1234-4234-8234-123456789abc"


@given(has_id=st.booleans(), has_hash=st.booleans())
def test_strategy_owner_requires_exactly_one_identity(
    has_id: bool,
    has_hash: bool,
) -> None:
    payload: dict[str, object] = {"owner_kind": "STRATEGY"}
    if has_id:
        payload["strategy_version_id"] = _STRV
    if has_hash:
        payload["strategy_version_hash"] = "a" * 64
    if has_id != has_hash:
        owner = ARTIFACT_OWNER_ADAPTER.validate_python(payload)
        assert isinstance(owner, StrategyArtifactOwner)
    else:
        with pytest.raises(ValidationError):
            ARTIFACT_OWNER_ADAPTER.validate_python(payload)


@given(
    has_engine_name=st.booleans(),
    has_engine_version=st.booleans(),
    null_name=st.booleans(),
    null_version=st.booleans(),
)
def test_adapter_engine_fields_are_all_or_none_and_never_null(
    has_engine_name: bool,
    has_engine_version: bool,
    null_name: bool,
    null_version: bool,
) -> None:
    payload: dict[str, object] = {
        "owner_kind": "ADAPTER",
        "adapter_name": "adapter.alpha",
        "adapter_version": "1.0.0",
    }
    if has_engine_name:
        payload["engine_name"] = None if null_name else "engine.alpha"
    if has_engine_version:
        payload["engine_version"] = None if null_version else "1.0.0"
    valid = (not has_engine_name and not has_engine_version) or (
        has_engine_name and has_engine_version and not null_name and not null_version
    )
    if valid:
        owner = ARTIFACT_OWNER_ADAPTER.validate_python(payload)
        assert isinstance(owner, AdapterArtifactOwner)
    else:
        with pytest.raises(ValidationError):
            ARTIFACT_OWNER_ADAPTER.validate_python(payload)


@given(
    component=st.from_regex(r"[a-z][a-z0-9]{0,15}", fullmatch=True),
    correlation=st.from_regex(
        r"[A-Za-z0-9][A-Za-z0-9._:-]{0,31}",
        fullmatch=True,
    ),
)
def test_owner_hash_is_deterministic(
    component: str,
    correlation: str,
) -> None:
    owner = SystemArtifactOwner(
        owner_kind="SYSTEM",
        core_component=component,
        correlation_id=correlation,
    )
    assert artifact_owner_hash(owner) == artifact_owner_hash(owner)


@given(
    kind=st.sampled_from(
        ("RUN", "EXPERIMENT", "DATASET", "STRATEGY", "ADAPTER", "SYSTEM")
    ),
    foreign_field=st.sampled_from(
        ("artifact_id", "candidate_artifact_id", "event_id", "audit_event_id")
    ),
)
def test_every_selected_branch_rejects_foreign_fields(
    kind: str,
    foreign_field: str,
) -> None:
    payloads: dict[str, dict[str, object]] = {
        "RUN": {
            "owner_kind": "RUN",
            "experiment_id": "exp_12345678-1234-4234-8234-123456789abc",
            "run_id": "run_12345678-1234-4234-8234-123456789abc",
        },
        "EXPERIMENT": {
            "owner_kind": "EXPERIMENT",
            "experiment_id": "exp_12345678-1234-4234-8234-123456789abc",
        },
        "DATASET": {
            "owner_kind": "DATASET",
            "dataset_id": "ds_12345678-1234-4234-8234-123456789abc",
        },
        "STRATEGY": {
            "owner_kind": "STRATEGY",
            "strategy_version_id": _STRV,
        },
        "ADAPTER": {
            "owner_kind": "ADAPTER",
            "adapter_name": "adapter.alpha",
            "adapter_version": "1.0.0",
        },
        "SYSTEM": {
            "owner_kind": "SYSTEM",
            "core_component": "schema_registry",
            "correlation_id": "stage3",
        },
    }
    payload = dict(payloads[kind])
    payload[foreign_field] = "foreign"
    with pytest.raises(ValidationError):
        ARTIFACT_OWNER_ADAPTER.validate_python(payload)
