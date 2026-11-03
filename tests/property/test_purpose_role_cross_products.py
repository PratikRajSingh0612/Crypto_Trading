"""Stage 9 plan 3.1.1 and 7.3: over all 2 x 2 x 7 x 6 (purpose, producer, role,
owner) tuples, exactly the nine tuples of the seven rows validate -- row 3
contributes three, every other row one -- and the count ``9`` is asserted
explicitly, through the production record type and both request models."""

from __future__ import annotations

import json
from itertools import product
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from crypto_lab.artifacts.models import (
    PERMITTED_ROLE_TUPLES,
    ArtifactFinalizationPurpose,
    ArtifactOwnerKind,
    ArtifactSourceRole,
    CandidateArtifact,
    CandidateArtifactProducerKind,
    validate_role_combination,
)
from crypto_lab.artifacts.ownership import ARTIFACT_OWNER_ADAPTER, artifact_owner_hash
from crypto_lab.artifacts.requests import EvidenceFinalizationRequest
from crypto_lab.domain.hashing import candidate_set_hash_for, finalization_identity

_EXP = "exp_12345678-1234-4234-8234-123456789abc"
_RUN = "run_12345678-1234-4234-8234-123456789abc"
_INV = "inv_12345678-1234-4234-8234-123456789abc"
_DS = "ds_12345678-1234-4234-8234-123456789abc"
_STRV = "strv_12345678-1234-4234-8234-123456789abc"
_EVT = "evt_12345678-1234-4234-8234-123456789abc"
_CAND = "cand_12345678-1234-4234-8234-123456789abc"
_AUDIT = "audit_12345678-1234-4234-8234-123456789abc"
_HASH = "a" * 64
_T0 = "2026-08-10T01:02:03Z"
_F = ArtifactFinalizationPurpose
_P = CandidateArtifactProducerKind
_R = ArtifactSourceRole
_K = ArtifactOwnerKind
_OWNERS: dict[_K, dict[str, Any]] = {
    _K.RUN: {
        "owner_kind": "RUN",
        "experiment_id": _EXP,
        "run_id": _RUN,
        "invocation_id": _INV,
    },
    _K.EXPERIMENT: {"owner_kind": "EXPERIMENT", "experiment_id": _EXP},
    _K.DATASET: {"owner_kind": "DATASET", "dataset_id": _DS},
    _K.STRATEGY: {"owner_kind": "STRATEGY", "strategy_version_id": _STRV},
    _K.ADAPTER: {
        "owner_kind": "ADAPTER",
        "adapter_name": "adapter.alpha",
        "adapter_version": "1.0.0",
    },
    _K.SYSTEM: {
        "owner_kind": "SYSTEM",
        "core_component": "artifacts",
        "correlation_id": "s9",
    },
}
_Combination = tuple[_F, _P, _R, _K]
_EXPECTED = frozenset(
    {
        (_F.RESULT, _P.ADAPTER, _R.ENGINE_NATIVE_RESULT, _K.RUN),
        (_F.RESULT, _P.CORE, _R.NORMALIZED_RESULT, _K.RUN),
        (_F.EVIDENCE, _P.CORE, _R.CORE_EVIDENCE, _K.RUN),
        (_F.EVIDENCE, _P.CORE, _R.CORE_EVIDENCE, _K.SYSTEM),
        (_F.EVIDENCE, _P.CORE, _R.CORE_EVIDENCE, _K.ADAPTER),
        (_F.EVIDENCE, _P.CORE, _R.ADAPTER_DESCRIPTOR_EVIDENCE, _K.ADAPTER),
        (_F.EVIDENCE, _P.CORE, _R.DATASET_INPUT, _K.DATASET),
        (_F.EVIDENCE, _P.CORE, _R.STRATEGY_INPUT, _K.STRATEGY),
        (_F.EVIDENCE, _P.CORE, _R.EXPERIMENT_INPUT, _K.EXPERIMENT),
    }
)
_ALL = tuple(product(_F, _P, _R, _K))


def _candidate(purpose: _F, producer: _P, role: _R, kind: _K) -> dict[str, Any]:
    """The production record with every producer-governed field in its lawful
    shape, so only the (purpose, producer, role, owner) rule decides."""
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
            if producer is _P.ADAPTER
            else f"INVOCATION/{_INV}/payload.bin"
        ),
        "state": "CANDIDATE",
        "validation_observations": [],
        "created_at_utc": _T0,
        "updated_at_utc": _T0,
        "revision": 1,
    }
    if producer is _P.ADAPTER:
        payload.update(
            adapter_declared_size=12,
            adapter_declared_hash=_HASH,
            adapter_declared_media_type="application/octet-stream",
            source_event_id=_EVT,
        )
    return payload


def _accepts(payload: dict[str, Any]) -> bool:
    try:
        CandidateArtifact.model_validate_json(json.dumps(payload))
    except ValidationError:
        return False
    return True


def test_exactly_seven_rows_validate() -> None:
    assert len(_ALL) == 2 * 2 * 7 * 6
    accepted = frozenset(
        combination for combination in _ALL if _accepts(_candidate(*combination))
    )
    assert accepted == _EXPECTED
    assert len(accepted) == 9
    rows = {combination[:3] for combination in accepted}
    assert len(rows) == 7
    # Row 3 contributes three owner variants; every other row exactly one.
    owners_by_row = {row: {c[3] for c in accepted if c[:3] == row} for row in rows}
    row_three = (_F.EVIDENCE, _P.CORE, _R.CORE_EVIDENCE)
    assert owners_by_row[row_three] == {_K.RUN, _K.SYSTEM, _K.ADAPTER}
    assert all(
        len(owners) == 1 for row, owners in owners_by_row.items() if row != row_three
    )
    # The record and the pure table agree on every tuple; the table is the data.
    assert PERMITTED_ROLE_TUPLES == _EXPECTED
    table_accepted = frozenset(
        combination for combination in _ALL if _table_accepts(*combination)
    )
    assert table_accepted == accepted
    # An ADAPTER producer with purpose EVIDENCE, any role, is the 24.3:1776 refusal.
    assert not any(c[0] is _F.EVIDENCE and c[1] is _P.ADAPTER for c in accepted)


def _table_accepts(purpose: _F, producer: _P, role: _R, kind: _K) -> bool:
    try:
        validate_role_combination(purpose, producer, role, kind)
    except ValueError:
        return False
    return True


def _evidence_request(role: _R, kind: _K) -> dict[str, Any]:
    owner = ARTIFACT_OWNER_ADAPTER.validate_json(json.dumps(_OWNERS[kind]))
    invocation_roles = (_R.CORE_EVIDENCE, _R.ADAPTER_DESCRIPTOR_EVIDENCE)
    correlation_kind = "INVOCATION" if role in invocation_roles else "AUDIT"
    correlation = (
        {"kind": "INVOCATION", "invocation_id": _INV}
        if correlation_kind == "INVOCATION"
        else {"kind": "AUDIT", "audit_event_id": _AUDIT}
    )
    return {
        "schema_version": "1.0.0",
        "finalization_purpose": "EVIDENCE",
        "owner": _OWNERS[kind],
        "source_role": role.value,
        "candidate_artifact_ids": [_CAND],
        "candidate_set_hash": candidate_set_hash_for((_CAND,)),
        "correlation": correlation,
        "idempotency_key": finalization_identity(
            "EVIDENCE",
            owner_hash=artifact_owner_hash(owner),
            correlation_kind=correlation_kind,
            correlation_id=_INV if correlation_kind == "INVOCATION" else _AUDIT,
            candidate_set_hash=candidate_set_hash_for((_CAND,)),
        ),
    }


def test_the_evidence_request_admits_exactly_the_seven_evidence_tuples() -> None:
    accepted: set[tuple[_R, _K]] = set()
    for role, kind in product(_R, _K):
        try:
            EvidenceFinalizationRequest.model_validate_json(
                json.dumps(_evidence_request(role, kind))
            )
        except ValidationError:
            continue
        accepted.add((role, kind))
    assert accepted == {(row[2], row[3]) for row in _EXPECTED if row[0] is _F.EVIDENCE}
    assert len(accepted) == 7


@settings(deadline=None, max_examples=100)
@given(combination=st.sampled_from(_ALL))
def test_sampled_tuples_agree_with_the_table(combination: _Combination) -> None:
    assert _accepts(_candidate(*combination)) is (combination in _EXPECTED)
    assert _table_accepts(*combination) is (combination in _EXPECTED)
