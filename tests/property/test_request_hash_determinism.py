"""Stage 6 Task 2: the request identity is a deterministic function of the plan
section 4 material alone.

Three properties over `request_hash_of` and the `ADAPTER_REQUEST_V1` profile:
invariance under key permutation of the dumped request, invariance under every
named exclusion (`run_id`, `request_id`, `attempt_token`, the relative work path,
`created_at_utc`), and sensitivity to twelve of the thirteen material keys with
one generated mutation per field. The thirteenth, `assigned_work_dir.authorized_root`,
admits a single value and is proven material at the dict level in
`test_the_authorized_root_is_material_and_the_relative_path_is_not`
(tests/unit/adapters/test_request_envelopes.py). `deadline=None` because the
examples validate several nested strict models and the suite may run under load.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any, Final

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from crypto_lab.adapters.envelopes import (
    EngineRunRequest,
    NegotiatedVersions,
    RunConfigurationSnapshot,
    WorkDirectoryReference,
    build_engine_run_request,
    request_hash_of,
    request_material_hash,
    sanitize_engine_run_request,
)
from crypto_lab.adapters.limits import PROTOCOL_LIMITS_DEFAULT, ProtocolLimits
from crypto_lab.adapters.vocabulary import NEGOTIABLE_SCHEMA_NAMES
from crypto_lab.domain.comparison_levels import ComparisonLevel
from crypto_lab.domain.descriptors import SupportedSchemaVersion
from crypto_lab.domain.engine_run import AttemptTokenMaterial
from crypto_lab.domain.experiment import AdapterIdentity, EngineIdentity
from crypto_lab.domain.hashing import _uuid4_shaped, request_id_for, sha256_bytes
from crypto_lab.domain.lifecycle import EngineRunState, ExperimentState
from doubles.experiments import (
    ATTEMPT_TOKEN,
    RUN_ID,
    SLOT_A,
    sample_experiment,
    sample_run,
)

_CREATED: Final = datetime(2026, 9, 10, 12, 0, tzinfo=UTC)
_EXPERIMENT: Final = sample_experiment(ExperimentState.QUEUED)
_NEGOTIATED: Final = NegotiatedVersions(
    protocol_version="1.0.0",
    schema_versions=tuple(
        SupportedSchemaVersion(schema_name=name, schema_version="1.0.0")
        for name in NEGOTIABLE_SCHEMA_NAMES
    ),
    capability_vocabulary_version="capabilities/v1",
)
_MATERIAL: Final = request_material_hash(
    experiment=_EXPERIMENT,
    logical_slot_id=SLOT_A,
    attempt_number=1,
    negotiated=_NEGOTIATED,
    limits=PROTOCOL_LIMITS_DEFAULT,
)
_BASE: Final = build_engine_run_request(
    run=sample_run(EngineRunState.PENDING, request_hash=_MATERIAL),
    experiment=_EXPERIMENT,
    token=AttemptTokenMaterial(run_id=RUN_ID, attempt_token=ATTEMPT_TOKEN),
    negotiated=_NEGOTIATED,
    limits=PROTOCOL_LIMITS_DEFAULT,
    created_at_utc=_CREATED,
)
_KEYS: Final = tuple(EngineRunRequest.model_fields)
_HEX: Final = st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)
_SEEDS: Final = st.text(min_size=1, max_size=16)
_TOKENS: Final = st.text(
    alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
    min_size=32,
    max_size=96,
)
_SEGMENTS: Final = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=12
)


def _derived_id(prefix: str, seed: str) -> str:
    return f"{prefix}_{_uuid4_shaped(sha256_bytes(seed.encode('utf-8')))}"


def _with(request: EngineRunRequest, **changes: object) -> EngineRunRequest:
    """``request`` with ``changes`` applied and ``request_hash`` recomputed."""
    fields: dict[str, Any] = dict(request)
    fields.update(changes)
    draft = EngineRunRequest.model_construct(**fields)
    payload = draft.model_dump(mode="python")
    payload["request_hash"] = request_hash_of(draft)
    return EngineRunRequest.model_validate(payload)


def _revalidated(request: EngineRunRequest, **changes: object) -> EngineRunRequest:
    payload = request.model_dump(mode="python")
    payload.update(changes)
    return EngineRunRequest.model_validate(payload)


def _snapshot(**changes: object) -> RunConfigurationSnapshot:
    return RunConfigurationSnapshot.model_validate(
        {**dict(_BASE.configuration_snapshot), **changes}
    )


# --- Excluded fields: the same identity ------------------------------------------


@st.composite
def excluded_changes(draw: st.DrawFn) -> dict[str, object]:
    """One or more named exclusions replaced by other admitted values."""
    changes: dict[str, object] = {}
    if draw(st.booleans()):
        changes["run_id"] = _derived_id("run", draw(_SEEDS))
    if draw(st.booleans()):
        changes["request_id"] = request_id_for(_derived_id("run", draw(_SEEDS)))
    if draw(st.booleans()):
        changes["attempt_token"] = draw(_TOKENS)
    if draw(st.booleans()):
        segments = draw(st.lists(_SEGMENTS, min_size=1, max_size=4))
        changes["assigned_work_dir"] = WorkDirectoryReference(
            authorized_root="RUNTIME_ROOT", relative_path="/".join(segments)
        )
    if draw(st.booleans()):
        changes["created_at_utc"] = _CREATED + timedelta(
            seconds=draw(st.integers(min_value=-(10**8), max_value=10**8))
        )
    return changes


@settings(max_examples=60, deadline=None)
@given(changes=excluded_changes())
def test_every_named_exclusion_leaves_the_request_identity_unchanged(
    changes: dict[str, object],
) -> None:
    changed = _revalidated(_BASE, **changes)
    assert changed.request_hash == _BASE.request_hash
    assert request_hash_of(changed) == _MATERIAL
    assert request_hash_of(sanitize_engine_run_request(changed)) == _MATERIAL
    for name, value in changes.items():
        assert getattr(changed, name) == value


# --- Key permutation: canonical serialization ----------------------------------------


@settings(max_examples=40, deadline=None)
@given(order=st.permutations(list(_KEYS)))
def test_the_identity_is_invariant_under_key_permutation_of_the_dump(
    order: list[str],
) -> None:
    dumped = _BASE.model_dump(mode="python")
    permuted = {name: dumped[name] for name in order}
    assert list(permuted) == order
    request = EngineRunRequest.model_validate(permuted)
    assert request == _BASE
    assert request_hash_of(request) == _MATERIAL
    dumped_json = _BASE.model_dump(mode="json")
    permuted_json = {name: dumped_json[name] for name in reversed(order)}
    from_json = EngineRunRequest.model_validate_json(json.dumps(permuted_json))
    assert request_hash_of(from_json) == _MATERIAL


# --- Material fields: a different identity -------------------------------------------


@st.composite
def material_mutation(draw: st.DrawFn) -> tuple[str, object]:
    """Exactly one material field replaced by another admitted, different value."""
    field = draw(
        st.sampled_from(
            [
                "experiment_id",
                "logical_slot_id",
                "attempt_number",
                "strategy_version_hash",
                "dataset_version_hash",
                "adapter",
                "engine",
                "configuration_snapshot",
                "configuration_hash",
                "comparison_level",
                "experiment_spec_hash",
                "negotiated_versions",
            ]
        )
    )
    value: object
    if field == "comparison_level":
        value = draw(
            st.sampled_from(
                [
                    level
                    for level in ComparisonLevel
                    if level is not _BASE.comparison_level
                ]
            )
        )
    elif field == "experiment_id":
        value = _derived_id("exp", draw(_SEEDS))
    elif field == "logical_slot_id":
        value = _derived_id("slot", draw(_SEEDS))
    elif field == "attempt_number":
        value = draw(st.integers(min_value=2, max_value=5))
    elif field in {"strategy_version_hash", "dataset_version_hash"}:
        value = draw(_HEX)
    elif field in {"configuration_hash", "experiment_spec_hash"}:
        value = draw(_HEX)
    elif field == "adapter":
        value = AdapterIdentity(
            adapter_name="adapter." + draw(_SEGMENTS), adapter_version="1.0.0"
        )
    elif field == "engine":
        value = EngineIdentity(
            engine_name="engine." + draw(_SEGMENTS), engine_version="2.3.4"
        )
    elif field == "configuration_snapshot":
        interval = draw(st.integers(min_value=1, max_value=300))
        threshold = draw(st.integers(min_value=2 * interval, max_value=900))
        value = _snapshot(
            limits=ProtocolLimits.model_validate(
                {
                    **PROTOCOL_LIMITS_DEFAULT.model_dump(),
                    "heartbeat_interval_seconds": interval,
                    "missing_heartbeat_seconds": threshold,
                }
            )
        )
    else:
        value = NegotiatedVersions.model_validate(
            {
                **dict(_NEGOTIATED),
                "capability_vocabulary_version": (
                    f"capabilities/v{draw(st.integers(min_value=2, max_value=99))}"
                ),
            }
        )
    return field, value


@settings(max_examples=120, deadline=None)
@given(mutation=material_mutation())
def test_every_material_field_moves_the_request_identity(
    mutation: tuple[str, object],
) -> None:
    field, value = mutation
    if getattr(_BASE, field) == value:
        return  # a drawn value that happens to equal the base is not a mutation
    changes: dict[str, object] = {field: value}
    if field == "comparison_level":
        # The agreement validator makes the level a paired mutation.
        changes["configuration_snapshot"] = _snapshot(comparison_level=value)
    changed = _with(_BASE, **changes)
    assert getattr(changed, field) == value
    assert changed.request_hash != _MATERIAL
    assert request_hash_of(changed) == changed.request_hash
    assert request_hash_of(sanitize_engine_run_request(changed)) == changed.request_hash
    # The original hash is refused for the changed material.
    payload = changed.model_dump(mode="python")
    payload["request_hash"] = _MATERIAL
    with pytest.raises(ValueError, match="request_hash") as captured:
        EngineRunRequest.model_validate(payload)
    assert ATTEMPT_TOKEN not in str(captured.value)


@settings(max_examples=40, deadline=None)
@given(
    token=_TOKENS,
    created=st.integers(min_value=-(10**6), max_value=10**6),
)
def test_sanitization_is_token_free_and_identity_preserving(
    token: str, created: int
) -> None:
    request = _revalidated(
        _BASE,
        attempt_token=token,
        created_at_utc=_CREATED + timedelta(seconds=created),
    )
    sanitized = sanitize_engine_run_request(request)
    assert request_hash_of(sanitized) == request.request_hash == _MATERIAL
    assert token not in repr(request)
    assert token not in repr(sanitized)
    assert token not in sanitized.model_dump_json()
    assert "attempt_token" not in sanitized.model_dump()
