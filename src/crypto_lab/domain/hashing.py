"""Named deterministic SHA-256 profiles."""

from __future__ import annotations

from enum import StrEnum
from hashlib import sha256
from typing import Literal

from pydantic import JsonValue

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.identifiers import Sha256

_ATTEMPT_TOKEN_DOMAIN = b"crypto_lab:attempt-token:v1"


class HashingProfile(StrEnum):
    CONFIGURATION_AUDIT_V1 = "configuration-audit/v1"
    CONFIGURATION_MATERIAL_BASE_V1 = "configuration-material-base/v1"
    DATASET_METADATA_V1 = "dataset-metadata/v1"
    ARTIFACT_OWNER_V1 = "artifact-owner/v1"
    DIAGNOSTIC_IDENTITY_V1 = "diagnostic-identity/v1"


class CanonicalHashEnvelope(CanonicalModel):
    schema_version: Literal["1.0.0"]
    hashing_profile: HashingProfile
    payload: dict[str, JsonValue]


def sha256_bytes(value: bytes) -> Sha256:
    """Hash exact bytes with SHA-256."""
    return sha256(value).hexdigest()


def profile_hash(
    profile: HashingProfile,
    payload: dict[str, JsonValue],
) -> Sha256:
    """Hash one explicit canonical profile envelope."""
    envelope = CanonicalHashEnvelope(
        schema_version="1.0.0",
        hashing_profile=profile,
        payload=payload,
    )
    return sha256_bytes(canonical_json_bytes(envelope))


def _uuid4_shaped(digest: Sha256) -> str:
    """Render a digest as a canonical UUID4-shaped string.

    Derived rather than drawn, because every random and wall-clock source is
    forbidden. Takes the first 32 hex digits, forces the version nibble to
    ``4`` and the variant nibble into ``[89ab]``, and applies the canonical
    ``8-4-4-4-12`` grouping so ``validate_prefixed_uuid4`` accepts it.
    """
    digits = list(digest[:32])
    digits[12] = "4"
    digits[16] = "89ab"[int(digits[16], 16) % 4]
    grouped = "".join(digits)
    return (
        f"{grouped[:8]}-{grouped[8:12]}-{grouped[12:16]}-"
        f"{grouped[16:20]}-{grouped[20:]}"
    )


def attempt_token_hash(token: str) -> Sha256:
    """Hash a raw attempt token with the normative byte domain separator."""
    if type(token) is not str:
        raise TypeError("attempt token must be a built-in string")
    if not token or len(token) > 1024:
        raise ValueError("attempt token length must be 1 through 1024")
    return sha256_bytes(_ATTEMPT_TOKEN_DOMAIN + b"\x00" + token.encode("utf-8"))
