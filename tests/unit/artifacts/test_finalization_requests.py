"""Stage 9 Task 1: the two typed finalization requests and the evidence correlation
(plan 3.1 rows ``ResultFinalizationRequest``, ``EvidenceFinalizationRequest``,
``EvidenceCorrelation``; specification 17.2)."""

from __future__ import annotations

import json
from itertools import product
from typing import Any

import pytest
from pydantic import ValidationError

from crypto_lab.artifacts.models import (
    MAX_CANDIDATE_ARTIFACTS,
    ArtifactOwnerKind,
    ArtifactSourceRole,
)
from crypto_lab.artifacts.ownership import ARTIFACT_OWNER_ADAPTER, artifact_owner_hash
from crypto_lab.artifacts.requests import (
    PERMITTED_CORRELATION_KINDS,
    EvidenceCorrelation,
    EvidenceFinalizationRequest,
    ResultFinalizationRequest,
)
from crypto_lab.domain.hashing import candidate_set_hash_for, finalization_identity

_EXP = "exp_12345678-1234-4234-8234-123456789abc"
_EXP2 = "exp_22345678-1234-4234-8234-123456789abc"
_RUN = "run_12345678-1234-4234-8234-123456789abc"
_RUN2 = "run_22345678-1234-4234-8234-123456789abc"
_INV = "inv_12345678-1234-4234-8234-123456789abc"
_INV2 = "inv_22345678-1234-4234-8234-123456789abc"
_DS = "ds_12345678-1234-4234-8234-123456789abc"
_STRV = "strv_12345678-1234-4234-8234-123456789abc"
_DIAG = "diag_12345678-1234-4234-8234-123456789abc"
_AUDIT = "audit_12345678-1234-4234-8234-123456789abc"
_CAND = "cand_12345678-1234-4234-8234-123456789abc"
_CAND2 = "cand_22345678-1234-4234-8234-123456789abc"
_TOKEN_HASH = "c" * 64
_SOURCE_HASH = "d" * 64
_SANITIZED_HASH = "e" * 64
_IDS = (_CAND, _CAND2)
_SET_HASH = candidate_set_hash_for(_IDS)


def _owner(kind: str = "RUN", *, invocation: bool = True) -> dict[str, Any]:
    owners: dict[str, dict[str, Any]] = {
        "RUN": {"owner_kind": "RUN", "experiment_id": _EXP, "run_id": _RUN},
        "EXPERIMENT": {"owner_kind": "EXPERIMENT", "experiment_id": _EXP},
        "DATASET": {"owner_kind": "DATASET", "dataset_id": _DS},
        "STRATEGY": {"owner_kind": "STRATEGY", "strategy_version_id": _STRV},
        "ADAPTER": {
            "owner_kind": "ADAPTER",
            "adapter_name": "adapter.alpha",
            "adapter_version": "1.0.0",
        },
        "SYSTEM": {
            "owner_kind": "SYSTEM",
            "core_component": "artifacts",
            "correlation_id": "stage9",
        },
    }
    owner = dict(owners[kind])
    if kind == "RUN" and invocation:
        owner["invocation_id"] = _INV
    return owner


def _result_key(**overrides: str) -> str:
    fields = {
        "run_id": _RUN,
        "run_invocation_id": _INV,
        "attempt_token_hash": _TOKEN_HASH,
        "source_adapter_result_manifest_hash": _SOURCE_HASH,
        "sanitized_adapter_result_manifest_hash": _SANITIZED_HASH,
    }
    fields.update(overrides)
    return finalization_identity("RESULT", **fields)


def _result_request(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "finalization_purpose": "RESULT",
        "owner": _owner(),
        "experiment_id": _EXP,
        "run_id": _RUN,
        "run_invocation_id": _INV,
        "expected_run_revision": 4,
        "expected_invocation_revision": 6,
        "attempt_token_hash": _TOKEN_HASH,
        "source_adapter_result_manifest_hash": _SOURCE_HASH,
        "sanitized_adapter_result_manifest_hash": _SANITIZED_HASH,
        "semantic_status": "SUCCEEDED",
        "candidate_artifact_ids": list(_IDS),
        "candidate_set_hash": _SET_HASH,
        "finalization_timeout_seconds": 300,
        "idempotency_key": _result_key(),
    }
    payload.update(overrides)
    return payload


def _correlation(kind: str = "INVOCATION", **overrides: Any) -> dict[str, Any]:
    ids = {"INVOCATION": _INV, "DIAGNOSTIC": _DIAG, "AUDIT": _AUDIT}
    fields = {
        "INVOCATION": "invocation_id",
        "DIAGNOSTIC": "diagnostic_id",
        "AUDIT": "audit_event_id",
    }
    payload: dict[str, Any] = {"kind": kind}
    if kind in fields:
        payload[fields[kind]] = ids[kind]
    payload.update(overrides)
    return payload


def _evidence_key(
    owner: dict[str, Any], correlation: dict[str, Any], ids: tuple[str, ...]
) -> str:
    owner_model = ARTIFACT_OWNER_ADAPTER.validate_json(json.dumps(owner))
    correlation_id = next(
        value
        for key, value in correlation.items()
        if key != "kind" and value is not None
    )
    return finalization_identity(
        "EVIDENCE",
        owner_hash=artifact_owner_hash(owner_model),
        correlation_kind=correlation["kind"],
        correlation_id=correlation_id,
        candidate_set_hash=candidate_set_hash_for(ids),
    )


def _evidence_request(**overrides: Any) -> dict[str, Any]:
    owner = overrides.pop("owner", _owner())
    correlation = overrides.pop("correlation", _correlation())
    ids = tuple(overrides.pop("candidate_artifact_ids", list(_IDS)))
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "finalization_purpose": "EVIDENCE",
        "owner": owner,
        "source_role": "CORE_EVIDENCE",
        "candidate_artifact_ids": list(ids),
        "candidate_set_hash": candidate_set_hash_for(ids) if ids else "a" * 64,
        "correlation": correlation,
        "idempotency_key": (
            _evidence_key(owner, correlation, ids)
            if isinstance(correlation, dict) and "kind" in correlation and ids
            else "a" * 64
        ),
    }
    payload.update(overrides)
    return payload


def _rejects(
    model: type[Any], payload: dict[str, Any], match: str | None = None
) -> None:
    with pytest.raises(ValidationError, match=match):
        model.model_validate_json(json.dumps(payload))


def _result_rejects(payload: dict[str, Any], match: str | None = None) -> None:
    _rejects(ResultFinalizationRequest, payload, match)


def _evidence_rejects(payload: dict[str, Any], match: str | None = None) -> None:
    _rejects(EvidenceFinalizationRequest, payload, match)


def _load_result(payload: dict[str, Any]) -> ResultFinalizationRequest:
    return ResultFinalizationRequest.model_validate_json(json.dumps(payload))


def _load_evidence(payload: dict[str, Any]) -> EvidenceFinalizationRequest:
    return EvidenceFinalizationRequest.model_validate_json(json.dumps(payload))


def _without(payload: dict[str, Any], *names: str) -> dict[str, Any]:
    trimmed = dict(payload)
    for name in names:
        del trimmed[name]
    return trimmed


# --- RESULT ---------------------------------------------------------------------------


def test_result_branch_fields() -> None:
    request = _load_result(_result_request())
    assert request.finalization_purpose == "RESULT"
    assert request.owner.invocation_id == _INV
    assert request.candidate_artifact_ids == _IDS
    for field in _result_request():
        _rejects(ResultFinalizationRequest, _without(_result_request(), field))
    _rejects(ResultFinalizationRequest, _result_request(owner=_owner(invocation=False)))
    _rejects(
        ResultFinalizationRequest,
        _result_request(owner={**_owner(), "experiment_id": _EXP2}),
        "experiment_id",
    )
    _rejects(
        ResultFinalizationRequest,
        _result_request(owner={**_owner(), "run_id": _RUN2}),
        "run_id",
    )
    _rejects(
        ResultFinalizationRequest,
        _result_request(owner={**_owner(), "invocation_id": _INV2}),
        "invocation",
    )
    _result_rejects(_result_request(owner=_owner("SYSTEM")))
    _result_rejects(_result_request(semantic_status="FAILED"))
    _result_rejects(_result_request(finalization_purpose="EVIDENCE"))
    for seconds in (0, 3601):
        _result_rejects(_result_request(finalization_timeout_seconds=seconds))
    longest = _load_result(_result_request(finalization_timeout_seconds=3600))
    assert longest.finalization_timeout_seconds == 3600
    for field in ("expected_run_revision", "expected_invocation_revision"):
        _rejects(ResultFinalizationRequest, _result_request(**{field: 0}))
    assert MAX_CANDIDATE_ARTIFACTS == 256


def test_result_candidate_set_is_bounded_sorted_unique_and_hashed() -> None:
    _rejects(ResultFinalizationRequest, _result_request(candidate_artifact_ids=[]))
    _rejects(
        ResultFinalizationRequest,
        _result_request(candidate_artifact_ids=[_CAND2, _CAND]),
        "sorted",
    )
    _rejects(
        ResultFinalizationRequest,
        _result_request(candidate_artifact_ids=[_CAND, _CAND]),
        "unique",
    )
    too_many = [
        f"cand_{index:08x}-1234-4234-8234-123456789abc"
        for index in range(MAX_CANDIDATE_ARTIFACTS + 1)
    ]
    _result_rejects(_result_request(candidate_artifact_ids=too_many))
    _rejects(
        ResultFinalizationRequest,
        _result_request(candidate_set_hash=candidate_set_hash_for((_CAND,))),
        "candidate_set_hash",
    )
    single = ResultFinalizationRequest.model_validate_json(
        json.dumps(
            _result_request(
                candidate_artifact_ids=[_CAND],
                candidate_set_hash=candidate_set_hash_for((_CAND,)),
            )
        )
    )
    assert single.candidate_set_hash == candidate_set_hash_for((_CAND,))


def test_idempotency_key_recomputed() -> None:
    assert _load_result(_result_request()).idempotency_key == _result_key()
    _result_rejects(_result_request(idempotency_key="f" * 64), "idempotency")
    # The key covers every member of the 17.2 tuple: changing one field without
    # recomputing is refused, and the recomputed key for the changed field passes.
    for field, value in (
        ("run_invocation_id", _INV2),
        ("attempt_token_hash", "f" * 64),
        ("source_adapter_result_manifest_hash", "f" * 64),
        ("sanitized_adapter_result_manifest_hash", "f" * 64),
    ):
        payload = _result_request(**{field: value})
        if field == "run_invocation_id":
            payload["owner"] = {**_owner(), "invocation_id": _INV2}
        _result_rejects(payload, "idempotency")
        payload["idempotency_key"] = _result_key(**{field: value})
        assert _load_result(payload)
    evidence = _evidence_request()
    assert _load_evidence(evidence).idempotency_key == evidence["idempotency_key"]
    _evidence_rejects({**evidence, "idempotency_key": "f" * 64}, "idempotency")
    # A RESULT key never satisfies the EVIDENCE identity (17.2: separate tuples).
    _evidence_rejects({**evidence, "idempotency_key": _result_key()}, "idempotency")


# --- EVIDENCE -------------------------------------------------------------------------


def test_evidence_branch_exactly_one_typed_correlation() -> None:
    fields = {
        "INVOCATION": "invocation_id",
        "DIAGNOSTIC": "diagnostic_id",
        "AUDIT": "audit_event_id",
    }
    for kind, field in fields.items():
        correlation = EvidenceCorrelation.model_validate_json(
            json.dumps(_correlation(kind))
        )
        assert correlation.kind == kind
        assert correlation.correlation_id == _correlation(kind)[field]
        request = _load_evidence(_evidence_request(correlation=_correlation(kind)))
        assert request.correlation.kind == kind
    _rejects(EvidenceCorrelation, {"kind": "INVOCATION"}, "exactly")
    two_ids = _correlation("INVOCATION", diagnostic_id=_DIAG)
    _rejects(EvidenceCorrelation, two_ids, "exactly")
    _rejects(EvidenceCorrelation, _correlation("AUDIT", invocation_id=_INV), "exactly")
    wrong_id = {"kind": "DIAGNOSTIC", "invocation_id": _INV}
    _rejects(EvidenceCorrelation, wrong_id, "exactly")
    _rejects(EvidenceCorrelation, _correlation("INVOCATION", invocation_id=None))
    _rejects(EvidenceCorrelation, _correlation("OTHER"))
    _rejects(EvidenceCorrelation, {"kind": "INVOCATION", "invocation_id": _RUN})
    _rejects(EvidenceCorrelation, _correlation("INVOCATION", extra="x"), "extra")


def test_generic_string_cannot_be_correlation() -> None:
    _evidence_rejects(_evidence_request(correlation=_INV))
    _evidence_rejects(_evidence_request(correlation={"invocation_id": _INV}))
    _evidence_rejects(_evidence_request(correlation=None))
    with pytest.raises(ValidationError):
        EvidenceCorrelation.model_validate(_INV)


@pytest.mark.parametrize("kind", ["INVOCATION", "DIAGNOSTIC", "AUDIT"])
def test_correlation_id_refuses_unchecked_record_lacking_identifier(kind: str) -> None:
    """``correlation_id`` is public; on a record built without validation it
    refuses to name an identifier the ``kind`` requires but the record lacks,
    rather than hand back the absent sentinel in its place."""
    ids: dict[str, Any] = {
        "invocation_id": _INV,
        "diagnostic_id": _DIAG,
        "audit_event_id": _AUDIT,
    }
    field = next(key for key in _correlation(kind) if key != "kind")
    absent = EvidenceCorrelation.model_construct(kind=kind)
    with pytest.raises(ValueError, match="names exactly one identifier"):
        _ = absent.correlation_id
    other = next(name for name in ids if name != field)
    mismatched = EvidenceCorrelation.model_construct(kind=kind, **{other: ids[other]})
    with pytest.raises(ValueError, match="names exactly one identifier"):
        _ = mismatched.correlation_id
    # The refusal is the guard's, not ``model_construct``'s: the same unchecked
    # construction with the matching identifier present names it.
    present = EvidenceCorrelation.model_construct(kind=kind, **{field: ids[field]})
    assert present.correlation_id == ids[field]


def test_other_branch_fields_rejected() -> None:
    _result_rejects(_result_request(correlation=_correlation()), "extra")
    _result_rejects(_result_request(source_role="CORE_EVIDENCE"), "extra")
    for field, value in (
        ("run_id", _RUN),
        ("run_invocation_id", _INV),
        ("experiment_id", _EXP),
        ("attempt_token_hash", _TOKEN_HASH),
        ("source_adapter_result_manifest_hash", _SOURCE_HASH),
        ("sanitized_adapter_result_manifest_hash", _SANITIZED_HASH),
        ("semantic_status", "SUCCEEDED"),
        ("finalization_timeout_seconds", 300),
        ("expected_run_revision", 1),
        ("expected_invocation_revision", 1),
    ):
        _evidence_rejects(_evidence_request(**{field: value}), "extra")
    _evidence_rejects(_evidence_request(finalization_purpose="RESULT"))
    for field in _evidence_request():
        _rejects(EvidenceFinalizationRequest, _without(_evidence_request(), field))


def test_evidence_role_owner_and_correlation_table() -> None:
    """Plan 3.1.1 rows 3 through 7 with their correlation column; an ``ADAPTER``
    owner with ``CORE_EVIDENCE`` carries only an ``INVOCATION`` correlation
    (the describe stderr of 23.3.1:1703; the DESCRIBE fact itself is phase 0)."""
    every_kind = frozenset({"INVOCATION", "DIAGNOSTIC", "AUDIT"})
    assert dict(PERMITTED_CORRELATION_KINDS) == {
        ArtifactSourceRole.CORE_EVIDENCE: every_kind,
        ArtifactSourceRole.ADAPTER_DESCRIPTOR_EVIDENCE: frozenset({"INVOCATION"}),
        ArtifactSourceRole.DATASET_INPUT: frozenset({"AUDIT", "DIAGNOSTIC"}),
        ArtifactSourceRole.STRATEGY_INPUT: frozenset({"AUDIT", "DIAGNOSTIC"}),
        ArtifactSourceRole.EXPERIMENT_INPUT: frozenset({"AUDIT", "DIAGNOSTIC"}),
    }
    expected_pairs = {
        ("CORE_EVIDENCE", "RUN"),
        ("CORE_EVIDENCE", "SYSTEM"),
        ("CORE_EVIDENCE", "ADAPTER"),
        ("ADAPTER_DESCRIPTOR_EVIDENCE", "ADAPTER"),
        ("DATASET_INPUT", "DATASET"),
        ("STRATEGY_INPUT", "STRATEGY"),
        ("EXPERIMENT_INPUT", "EXPERIMENT"),
    }
    accepted: dict[tuple[str, str], set[str]] = {}
    for role, kind, correlation_kind in product(
        (member.value for member in ArtifactSourceRole),
        (member.value for member in ArtifactOwnerKind),
        ("INVOCATION", "DIAGNOSTIC", "AUDIT"),
    ):
        payload = _evidence_request(
            owner=_owner(kind), correlation=_correlation(correlation_kind)
        )
        payload["source_role"] = role
        try:
            EvidenceFinalizationRequest.model_validate_json(json.dumps(payload))
        except ValidationError:
            continue
        accepted.setdefault((role, kind), set()).add(correlation_kind)
    assert set(accepted) == expected_pairs
    assert accepted[("CORE_EVIDENCE", "RUN")] == every_kind
    assert accepted[("CORE_EVIDENCE", "SYSTEM")] == every_kind
    assert accepted[("CORE_EVIDENCE", "ADAPTER")] == {"INVOCATION"}
    assert accepted[("ADAPTER_DESCRIPTOR_EVIDENCE", "ADAPTER")] == {"INVOCATION"}
    for role in ("DATASET_INPUT", "STRATEGY_INPUT", "EXPERIMENT_INPUT"):
        kind = role.removesuffix("_INPUT")
        assert accepted[(role, kind)] == {"AUDIT", "DIAGNOSTIC"}
    # The result roles never enter an evidence request.
    _evidence_rejects(_evidence_request(source_role="ENGINE_NATIVE_RESULT"))
    _evidence_rejects(_evidence_request(source_role="NORMALIZED_RESULT"))


def test_evidence_candidate_set_is_bounded_sorted_unique_and_hashed() -> None:
    _rejects(EvidenceFinalizationRequest, _evidence_request(candidate_artifact_ids=[]))
    _rejects(
        EvidenceFinalizationRequest,
        _evidence_request(candidate_artifact_ids=[_CAND2, _CAND]),
        "sorted",
    )
    _rejects(
        EvidenceFinalizationRequest,
        _evidence_request(candidate_artifact_ids=[_CAND, _CAND]),
        "unique",
    )
    _rejects(
        EvidenceFinalizationRequest,
        _evidence_request(candidate_set_hash=candidate_set_hash_for((_CAND,))),
        "candidate_set_hash",
    )
    request = EvidenceFinalizationRequest.model_validate_json(
        json.dumps(_evidence_request(candidate_artifact_ids=[_CAND]))
    )
    assert request.candidate_set_hash == candidate_set_hash_for((_CAND,))
    assert request.owner.owner_kind == "RUN"
