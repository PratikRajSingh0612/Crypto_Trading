"""Named deterministic SHA-256 profiles."""

from __future__ import annotations

from enum import StrEnum
from hashlib import sha256
from typing import Literal

from pydantic import JsonValue

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.identifiers import (
    CandidateArtifactId,
    InvocationId,
    RequestId,
    RunId,
    Sha256,
    validate_prefixed_uuid4,
)

_ATTEMPT_TOKEN_DOMAIN = b"crypto_lab:attempt-token:v1"


class HashingProfile(StrEnum):
    CONFIGURATION_AUDIT_V1 = "configuration-audit/v1"
    CONFIGURATION_MATERIAL_BASE_V1 = "configuration-material-base/v1"
    DATASET_METADATA_V1 = "dataset-metadata/v1"
    ARTIFACT_OWNER_V1 = "artifact-owner/v1"
    DIAGNOSTIC_IDENTITY_V1 = "diagnostic-identity/v1"
    STRATEGY_VERSION_V1 = "strategy-version/v1"
    EXPERIMENT_CONFIGURATION_V1 = "experiment-configuration/v1"
    EXPERIMENT_SPEC_V1 = "experiment-spec/v1"
    # Stage 6 plan section 4: the four protocol profiles.
    ADAPTER_REQUEST_V1 = "adapter-request/v1"
    RUN_EVENT_CONTENT_V1 = "run-event-content/v1"
    SANITIZED_ADAPTER_RESULT_MANIFEST_V1 = "sanitized-adapter-result-manifest/v1"
    CANDIDATE_ARTIFACT_IDENTITY_V1 = "candidate-artifact-identity/v1"


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


def request_id_for(anchor: RunId | InvocationId) -> RequestId:
    """Derive the ``req_`` request identity of one run or describe anchor.

    Stage 6 plan section 4: ``req_`` + ``_uuid4_shaped(sha256_bytes(anchor))``,
    derived rather than drawn, so no ``IdentitySource`` method exists for it.
    A run's ``VALIDATE`` and ``RUN`` requests anchor on the run identity and a
    describe request on its invocation identity; the distinct prefixes make a
    collision between the two families impossible. Any other anchor is refused.
    """
    if type(anchor) is not str:
        raise TypeError("request anchor must be a built-in string")
    prefix = "run_" if anchor.startswith("run_") else "inv_"
    validate_prefixed_uuid4(anchor, prefix)
    return f"req_{_uuid4_shaped(sha256_bytes(anchor.encode('utf-8')))}"


def candidate_artifact_id_for(
    run_id: RunId,
    invocation_id: InvocationId,
    relative_path: str,
) -> CandidateArtifactId:
    """Derive the ``cand_`` identity of one declared candidate artifact.

    Stage 6 plan section 4: ``cand_`` + ``_uuid4_shaped(profile_hash(...))``
    under ``CANDIDATE_ARTIFACT_IDENTITY_V1`` over the run, the run-command
    invocation and the declared relative path, so a restart derives the same
    identity. The path is a plain ``str`` because ``domain`` may not import the
    ``adapters`` path alias; the adapter grammar is applied by the caller.
    """
    if (
        type(run_id) is not str
        or type(invocation_id) is not str
        or type(relative_path) is not str
    ):
        raise TypeError("candidate identity inputs must be built-in strings")
    if not relative_path:
        raise ValueError("candidate relative path must not be empty")
    validate_prefixed_uuid4(run_id, "run_")
    validate_prefixed_uuid4(invocation_id, "inv_")
    payload: dict[str, JsonValue] = {
        "run_id": run_id,
        "invocation_id": invocation_id,
        "relative_path": relative_path,
    }
    digest = profile_hash(HashingProfile.CANDIDATE_ARTIFACT_IDENTITY_V1, payload)
    return f"cand_{_uuid4_shaped(digest)}"
