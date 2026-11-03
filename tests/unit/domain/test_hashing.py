from __future__ import annotations

from typing import Literal, cast

import pytest
from pydantic import JsonValue

from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.hashing import (
    CanonicalHashEnvelope,
    HashingProfile,
    artifact_id_for,
    attempt_token_hash,
    candidate_set_hash_for,
    core_candidate_artifact_id_for,
    finalization_id_for,
    finalization_identity,
    profile_hash,
    sha256_bytes,
)
from crypto_lab.domain.identifiers import validate_prefixed_uuid4

_ATTEMPT_GOLDEN = "c2e83ef7cf00c619f6cfb843bcfffbb91da6ae7b26de5110f36db68762ec74de"
_OWNER_GOLDEN = "1ec94f41e62924c7715e7a6cd4c34cfa05af92060ecd7f05b8ebba580d213b11"


def test_sha256_and_attempt_token_goldens() -> None:
    assert sha256_bytes(b"abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    assert attempt_token_hash("token-123") == _ATTEMPT_GOLDEN


@pytest.mark.parametrize("token", ["", "x" * 1025])
def test_attempt_token_length_is_bounded(token: str) -> None:
    with pytest.raises(ValueError, match="length must be 1 through 1024"):
        attempt_token_hash(token)


class TokenSubclass(str):
    pass


@pytest.mark.parametrize("token", [b"bytes", 1, TokenSubclass("token")])
def test_attempt_token_requires_an_exact_builtin_string(token: object) -> None:
    with pytest.raises(TypeError, match="must be a built-in string"):
        attempt_token_hash(cast(str, token))


def test_system_owner_envelope_matches_golden_bytes_and_hash() -> None:
    payload: dict[str, JsonValue] = {
        "owner_kind": "SYSTEM",
        "core_component": "schema_registry",
        "correlation_id": "stage3",
    }
    envelope = CanonicalHashEnvelope(
        schema_version="1.0.0",
        hashing_profile=HashingProfile.ARTIFACT_OWNER_V1,
        payload=payload,
    )
    expected = (
        b'{"hashing_profile":"artifact-owner/v1","payload":'
        b'{"core_component":"schema_registry","correlation_id":"stage3",'
        b'"owner_kind":"SYSTEM"},"schema_version":"1.0.0"}'
    )
    assert canonical_json_bytes(envelope) == expected
    assert profile_hash(HashingProfile.ARTIFACT_OWNER_V1, payload) == _OWNER_GOLDEN


def test_profile_name_is_part_of_the_hash_domain() -> None:
    payload: dict[str, JsonValue] = {"value": "same"}
    hashes = {profile_hash(profile, payload) for profile in HashingProfile}
    assert len(hashes) == len(HashingProfile)


_STAGE9_TASK1_PROFILE_TAIL = (
    HashingProfile.ARTIFACT_IDENTITY_V1,
    HashingProfile.ARTIFACT_MANIFEST_V1,
    HashingProfile.CANDIDATE_SET_V1,
    HashingProfile.FINALIZATION_IDENTITY_V1,
    HashingProfile.CORE_CANDIDATE_IDENTITY_V1,
)


def test_stage_nine_profiles_are_named_and_ordered() -> None:
    members = tuple(HashingProfile)
    assert len(members) == 17
    assert members[-5:] == _STAGE9_TASK1_PROFILE_TAIL


_CANDIDATE = "cand_1e6f2a4c-4b3d-4f2e-8a1b-0c9d8e7f6a5b"
_OTHER_CANDIDATE = "cand_2e6f2a4c-4b3d-4f2e-8a1b-0c9d8e7f6a5b"
_RUN = "run_1e6f2a4c-4b3d-4f2e-8a1b-0c9d8e7f6a5b"
_INVOCATION = "inv_1e6f2a4c-4b3d-4f2e-8a1b-0c9d8e7f6a5b"
_AUDIT = "audit_1e6f2a4c-4b3d-4f2e-8a1b-0c9d8e7f6a5b"
_OWNER_HASH = "b" * 64
# Stage 9 plan section 3.2 / reading 17: the deterministic identity vectors, each
# pinned beside the derivation it is recomputed from (``assert x == G, x``).
_ARTIFACT_ID_GOLDEN = "art_52a78d96-b977-4926-b450-fdda5f45a8b9"
_CORE_CANDIDATE_GOLDEN = "cand_7739dd85-5460-4e5c-a368-7901603ba877"
_CANDIDATE_SET_GOLDEN = (
    "d03e7d4fd4a7d2a4bb64f7cff3bf58876345e220887e8627e5f7ae876ec57781"
)
_RESULT_IDENTITY_GOLDEN = (
    "2ab26fb476a84b022bfea8deb7495af861f2a5fd522407984b955b39e065fe05"
)
_EVIDENCE_IDENTITY_GOLDEN = (
    "cd6e6d17a1993786c38e46e189d2b6b4b6f4f057827c657b226f024c79ecc79d"
)
_FINALIZATION_ID_GOLDEN = "fin_2ab26fb4-76a8-4b02-abfe-a8deb7495af8"


def _result_identity() -> str:
    return finalization_identity(
        "RESULT",
        run_id=_RUN,
        run_invocation_id=_INVOCATION,
        attempt_token_hash="c" * 64,
        source_adapter_result_manifest_hash="d" * 64,
        sanitized_adapter_result_manifest_hash="e" * 64,
    )


def test_derived_identities_are_uuid4_shaped_and_stable() -> None:
    artifact_id = artifact_id_for(_CANDIDATE, "a" * 64)
    core_id = core_candidate_artifact_id_for(
        _OWNER_HASH, "INVOCATION", _INVOCATION, "stderr.txt"
    )
    set_hash = candidate_set_hash_for((_OTHER_CANDIDATE, _CANDIDATE))
    result_identity = _result_identity()
    finalization_id = finalization_id_for(result_identity)
    evidence_identity = finalization_identity(
        "EVIDENCE",
        owner_hash=_OWNER_HASH,
        correlation_kind="AUDIT",
        correlation_id=_AUDIT,
        candidate_set_hash=set_hash,
    )
    vectors = (
        artifact_id,
        core_id,
        set_hash,
        result_identity,
        finalization_id,
        evidence_identity,
    )
    assert vectors == (
        _ARTIFACT_ID_GOLDEN,
        _CORE_CANDIDATE_GOLDEN,
        _CANDIDATE_SET_GOLDEN,
        _RESULT_IDENTITY_GOLDEN,
        _FINALIZATION_ID_GOLDEN,
        _EVIDENCE_IDENTITY_GOLDEN,
    ), " ".join(vectors)

    validate_prefixed_uuid4(artifact_id, "art_")
    assert artifact_id_for(_CANDIDATE, "a" * 64) == artifact_id
    assert artifact_id_for(_OTHER_CANDIDATE, "a" * 64) != artifact_id
    assert artifact_id_for(_CANDIDATE, "f" * 64) != artifact_id

    # Reading 17: ``core_candidate_artifact_id_for(owner_hash, correlation_kind,
    # correlation_id, relative_path)`` -- the candidate-identity pattern keyed on the
    # owner and the correlation that scopes the core staging path (plan 4.6).
    validate_prefixed_uuid4(core_id, "cand_")
    same = core_candidate_artifact_id_for(
        _OWNER_HASH, "INVOCATION", _INVOCATION, "stderr.txt"
    )
    assert same == core_id
    other_kind = core_candidate_artifact_id_for(
        _OWNER_HASH, "DIAGNOSTIC", _INVOCATION, "stderr.txt"
    )
    assert other_kind != core_id
    other_path = core_candidate_artifact_id_for(
        _OWNER_HASH, "INVOCATION", _INVOCATION, "other.txt"
    )
    assert other_path != core_id
    other_owner = core_candidate_artifact_id_for(
        "e" * 64, "INVOCATION", _INVOCATION, "stderr.txt"
    )
    assert other_owner != core_id

    # Order independent: the profile hashes the sorted tuple.
    assert candidate_set_hash_for((_CANDIDATE, _OTHER_CANDIDATE)) == set_hash
    assert candidate_set_hash_for((_CANDIDATE,)) != set_hash

    assert _result_identity() == result_identity
    validate_prefixed_uuid4(finalization_id, "fin_")
    assert finalization_id_for(result_identity) == finalization_id
    assert evidence_identity != result_identity
    assert len(set(vectors)) == len(vectors)


def test_derivation_inputs_are_checked_before_hashing() -> None:
    with pytest.raises(ValueError, match="finalization purpose"):
        finalization_identity("EVIDENCE", run_id=_RUN)
    foreign_purpose = cast("Literal['RESULT', 'EVIDENCE']", "OTHER")
    with pytest.raises(ValueError, match="RESULT or EVIDENCE"):
        finalization_identity(foreign_purpose, run_id=_RUN)
    with pytest.raises(ValueError, match="must start with 'cand_'"):
        artifact_id_for(_RUN, "a" * 64)
    with pytest.raises(ValueError, match="64 lowercase hex"):
        artifact_id_for(_CANDIDATE, "A" * 64)
    with pytest.raises(ValueError, match="64 lowercase hex"):
        core_candidate_artifact_id_for("b" * 63, "INVOCATION", _INVOCATION, "x")
    with pytest.raises(ValueError, match="must not be empty"):
        core_candidate_artifact_id_for(_OWNER_HASH, "INVOCATION", _INVOCATION, "")
    with pytest.raises(ValueError, match="non-empty tuple"):
        candidate_set_hash_for(())
    with pytest.raises(ValueError, match="must start with 'cand_'"):
        candidate_set_hash_for((_RUN,))
    with pytest.raises(ValueError, match="64 lowercase hex"):
        finalization_id_for("zz")
    for foreign in (b"x", 1, TokenSubclass("x")):
        with pytest.raises(TypeError, match="built-in string"):
            artifact_id_for(cast("str", foreign), "a" * 64)
        with pytest.raises(TypeError, match="built-in string"):
            core_candidate_artifact_id_for(
                _OWNER_HASH, cast("str", foreign), _INVOCATION, "x"
            )
        with pytest.raises(TypeError, match="built-in string"):
            candidate_set_hash_for((cast("str", foreign),))
        with pytest.raises(TypeError, match="built-in string"):
            finalization_identity(
                "EVIDENCE",
                owner_hash=cast("str", foreign),
                correlation_kind="AUDIT",
                correlation_id=_AUDIT,
                candidate_set_hash="a" * 64,
            )
