from __future__ import annotations

from typing import cast

import pytest
from pydantic import JsonValue

from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.hashing import (
    CanonicalHashEnvelope,
    HashingProfile,
    attempt_token_hash,
    profile_hash,
    sha256_bytes,
)

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
