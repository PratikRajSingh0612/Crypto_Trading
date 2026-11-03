"""Stage 9 plan 7.3: a candidate payload never inhabits ``ArtifactRef`` and a
reference payload never inhabits ``CandidateArtifact`` (specification 11.3:
"a candidate can never substitute for this type"; 11.5: "Candidate paths and
candidate states cannot inhabit this type")."""

from __future__ import annotations

import json
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from crypto_lab.artifacts.models import (
    PERMITTED_ROLE_TUPLES,
    ArtifactOwnerKind,
    ArtifactRef,
    CandidateArtifact,
    CandidateArtifactProducerKind,
    CandidateArtifactState,
    finalized_relative_path_for,
)
from crypto_lab.domain.hashing import artifact_id_for

_EXP = "exp_12345678-1234-4234-8234-123456789abc"
_RUN = "run_12345678-1234-4234-8234-123456789abc"
_INV = "inv_12345678-1234-4234-8234-123456789abc"
_DS = "ds_12345678-1234-4234-8234-123456789abc"
_STRV = "strv_12345678-1234-4234-8234-123456789abc"
_EVT = "evt_12345678-1234-4234-8234-123456789abc"
_CAND = "cand_12345678-1234-4234-8234-123456789abc"
_T0 = "2026-08-10T01:02:03Z"
_T1 = "2026-08-10T01:02:08Z"
_OWNERS: dict[ArtifactOwnerKind, dict[str, Any]] = {
    ArtifactOwnerKind.RUN: {
        "owner_kind": "RUN",
        "experiment_id": _EXP,
        "run_id": _RUN,
        "invocation_id": _INV,
    },
    ArtifactOwnerKind.EXPERIMENT: {"owner_kind": "EXPERIMENT", "experiment_id": _EXP},
    ArtifactOwnerKind.DATASET: {"owner_kind": "DATASET", "dataset_id": _DS},
    ArtifactOwnerKind.STRATEGY: {
        "owner_kind": "STRATEGY",
        "strategy_version_id": _STRV,
    },
    ArtifactOwnerKind.ADAPTER: {
        "owner_kind": "ADAPTER",
        "adapter_name": "adapter.alpha",
        "adapter_version": "1.0.0",
    },
    ArtifactOwnerKind.SYSTEM: {
        "owner_kind": "SYSTEM",
        "core_component": "artifacts",
        "correlation_id": "stage9",
    },
}
_HEX = st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)
_ROWS = st.sampled_from(
    sorted(PERMITTED_ROLE_TUPLES, key=lambda row: [member.value for member in row])
)
_STATES = st.sampled_from(sorted(CandidateArtifactState, key=lambda s: s.value))
_TERMINAL = (CandidateArtifactState.QUARANTINED, CandidateArtifactState.CORRUPT)
_Row = tuple[Any, ...]


def _failed_observation() -> dict[str, Any]:
    return {
        "observed_at_utc": _T0,
        "stage": "SIZE",
        "outcome": "FAILED",
        "error_code": "ARTIFACT.VALIDATION_FAILED",
    }


def _candidate(
    row: _Row, state: CandidateArtifactState, content_hash: str
) -> dict[str, Any]:
    purpose, producer, role, kind = row
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "candidate_artifact_id": _CAND,
        "owner": _OWNERS[kind],
        "finalization_purpose": purpose.value,
        "source_role": role.value,
        "producer_kind": producer.value,
        "artifact_kind": "artifact-kind",
        "staging_relative_path": (
            "results/native.bin"
            if producer is CandidateArtifactProducerKind.ADAPTER
            else f"INVOCATION/{_INV}/payload.bin"
        ),
        "state": state.value,
        "validation_observations": (
            [_failed_observation()] if state in _TERMINAL else []
        ),
        "created_at_utc": _T0,
        "updated_at_utc": _T1,
        "revision": 1,
    }
    if producer is CandidateArtifactProducerKind.ADAPTER:
        payload.update(
            adapter_declared_size=12,
            adapter_declared_hash=content_hash,
            adapter_declared_media_type="application/octet-stream",
            source_event_id=_EVT,
        )
    return payload


def _ref(row: _Row, content_hash: str) -> dict[str, Any]:
    purpose, producer, role, kind = row
    return {
        "schema_version": "1.0.0",
        "artifact_id": artifact_id_for(_CAND, content_hash),
        "owner": _OWNERS[kind],
        "finalization_purpose": purpose.value,
        "artifact_kind": "artifact-kind",
        "finalized_relative_path": finalized_relative_path_for(content_hash),
        "content_hash": content_hash,
        "size_bytes": 12,
        "media_type": "application/octet-stream",
        "source_role": role.value,
        "source_candidate_artifact_id": _CAND,
        "producer_kind": producer.value,
        "validation_profile": "artifact-validation/v1",
        "created_at_utc": _T0,
        "finalized_at_utc": _T1,
        "state": "FINALIZED",
    }


@settings(deadline=None, max_examples=60)
@given(row=_ROWS, state=_STATES, content_hash=_HEX)
def test_any_valid_candidate_payload_fails_the_reference_type(
    row: _Row, state: CandidateArtifactState, content_hash: str
) -> None:
    payload = _candidate(row, state, content_hash)
    candidate = CandidateArtifact.model_validate_json(json.dumps(payload))
    assert candidate.state is state
    with pytest.raises(ValidationError):
        ArtifactRef.model_validate_json(json.dumps(payload))
    with pytest.raises(ValidationError):
        ArtifactRef.model_validate_json(candidate.model_dump_json())
    # Any candidate state is refused by the reference's literal FINALIZED state, even
    # when every other reference field is present.
    restated = {**_ref(row, content_hash), "state": state.value}
    with pytest.raises(ValidationError):
        ArtifactRef.model_validate_json(json.dumps(restated))


@settings(deadline=None, max_examples=60)
@given(row=_ROWS, content_hash=_HEX)
def test_any_valid_reference_payload_fails_the_candidate_type(
    row: _Row, content_hash: str
) -> None:
    payload = _ref(row, content_hash)
    reference = ArtifactRef.model_validate_json(json.dumps(payload))
    assert reference.state == "FINALIZED"
    with pytest.raises(ValidationError):
        CandidateArtifact.model_validate_json(json.dumps(payload))
    with pytest.raises(ValidationError):
        CandidateArtifact.model_validate_json(reference.model_dump_json())
    # No candidate state is FINALIZED.
    candidate = _candidate(row, CandidateArtifactState.CANDIDATE, content_hash)
    finalized = {**candidate, "state": "FINALIZED"}
    with pytest.raises(ValidationError):
        CandidateArtifact.model_validate_json(json.dumps(finalized))
