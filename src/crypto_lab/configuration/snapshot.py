"""Canonical Stage 3 configuration projections and hashes."""

from __future__ import annotations

from typing import Literal, Self, cast

from pydantic import Field, JsonValue, ValidationError, model_validator

from crypto_lab.configuration.models import (
    MAX_CONFIGURATION_BYTES,
    ApplicationConfig,
)
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_text
from crypto_lab.domain.hashing import HashingProfile, profile_hash
from crypto_lab.domain.identifiers import Sha256


class ConfigSnapshot(CanonicalModel):
    schema_version: Literal["1.0.0"]
    configuration_json: str = Field(
        min_length=2,
        max_length=MAX_CONFIGURATION_BYTES,
    )
    configuration_audit_hash: Sha256
    material_base_configuration_hash: Sha256

    @model_validator(mode="after")
    def validate_canonical_snapshot(self) -> Self:
        if len(self.configuration_json.encode("utf-8")) > MAX_CONFIGURATION_BYTES:
            raise ValueError("configuration snapshot exceeds maximum encoded bytes")
        try:
            config = ApplicationConfig.model_validate_json(self.configuration_json)
        except (ValidationError, ValueError, TypeError):
            raise ValueError("configuration snapshot JSON is invalid") from None
        canonical = canonical_json_text(config)
        if self.configuration_json != canonical:
            raise ValueError("configuration snapshot JSON is not canonical")
        if self.configuration_audit_hash != _configuration_audit_hash(config):
            raise ValueError("configuration snapshot audit hash mismatch")
        if self.material_base_configuration_hash != _material_base_configuration_hash(
            config
        ):
            raise ValueError("configuration snapshot material hash mismatch")
        return self


def _json_payload(value: object) -> dict[str, JsonValue]:
    return cast(dict[str, JsonValue], value)


def _validated_configuration(config: ApplicationConfig) -> ApplicationConfig:
    return ApplicationConfig.model_validate(config.model_dump(mode="python"))


def _configuration_audit_hash(config: ApplicationConfig) -> Sha256:
    return profile_hash(
        HashingProfile.CONFIGURATION_AUDIT_V1,
        _json_payload(config.model_dump(mode="json")),
    )


def _material_base_configuration_hash(config: ApplicationConfig) -> Sha256:
    return profile_hash(
        HashingProfile.CONFIGURATION_MATERIAL_BASE_V1,
        {
            "scheduler": {
                "retry": cast(
                    JsonValue, config.scheduler.retry.model_dump(mode="json")
                ),
            },
            "process": cast(JsonValue, config.process.model_dump(mode="json")),
            "protocol": cast(JsonValue, config.protocol.model_dump(mode="json")),
            "logging": {
                "max_stderr_bytes_per_invocation": (
                    config.logging.max_stderr_bytes_per_invocation
                ),
            },
            "policy": cast(JsonValue, config.policy.model_dump(mode="json")),
        },
    )


def configuration_audit_hash(config: ApplicationConfig) -> Sha256:
    return _configuration_audit_hash(_validated_configuration(config))


def material_base_configuration_hash(config: ApplicationConfig) -> Sha256:
    return _material_base_configuration_hash(_validated_configuration(config))


def snapshot_configuration(config: ApplicationConfig) -> ConfigSnapshot:
    validated = _validated_configuration(config)
    return ConfigSnapshot(
        schema_version="1.0.0",
        configuration_json=canonical_json_text(validated),
        configuration_audit_hash=_configuration_audit_hash(validated),
        material_base_configuration_hash=_material_base_configuration_hash(validated),
    )
