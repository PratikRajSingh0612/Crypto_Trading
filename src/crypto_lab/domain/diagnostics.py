"""Stable bounded machine-readable diagnostics."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, ClassVar, Literal, Self

from pydantic import (
    ConfigDict,
    Field,
    StringConstraints,
    WithJsonSchema,
    field_validator,
    model_validator,
)
from pydantic.experimental.missing_sentinel import MISSING
from pydantic.json_schema import JsonSchemaValue

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.identifiers import (
    DiagnosticId,
    ExperimentId,
    InvocationId,
    NormalizedIdentifier,
    RunId,
    exact_string_schema,
)
from crypto_lab.domain.time import UtcDateTime

_ERROR_CODE_PATTERN = r"^[A-Z][A-Z0-9_]*(?:\.[A-Z][A-Z0-9_]*)+$"
_SECRET_KEY_PARTS = {
    "access_token",
    "api_key",
    "attempt_token",
    "auth_token",
    "credential",
    "credentials",
    "password",
    "secret",
    "secrets",
}
_SECRET_KEY_COMPACT = {
    "accesstoken",
    "apikey",
    "attempttoken",
    "authtoken",
    "credential",
    "credentials",
    "password",
    "secret",
    "secrets",
}
MAX_DETAIL_BYTES = 16_384
MAX_DETAIL_DEPTH = 8
MAX_DETAIL_NODES = 256
MAX_DETAIL_COLLECTION = 64
MAX_DETAIL_KEY = 128
MAX_DETAIL_STRING = 2_048
MIN_DETAIL_INTEGER = -(2**63)
MAX_DETAIL_INTEGER = 2**63 - 1

type BoundedDetailInteger = Annotated[
    int,
    Field(
        strict=True,
        ge=MIN_DETAIL_INTEGER,
        le=MAX_DETAIL_INTEGER,
    ),
]
type ErrorCode = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=3,
        max_length=128,
        pattern=_ERROR_CODE_PATTERN,
    ),
    WithJsonSchema(
        exact_string_schema(
            _ERROR_CODE_PATTERN,
            min_length=3,
            max_length=128,
        )
    ),
]
type DiagnosticDetailKey = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=MAX_DETAIL_KEY),
]
type DiagnosticDetailString = Annotated[
    str,
    StringConstraints(strict=True, max_length=MAX_DETAIL_STRING),
]
type DiagnosticDetailValue = (
    DiagnosticDetailString
    | BoundedDetailInteger
    | bool
    | Annotated[list[DiagnosticDetailValue], Field(max_length=MAX_DETAIL_COLLECTION)]
    | Annotated[
        dict[DiagnosticDetailKey, DiagnosticDetailValue],
        Field(max_length=MAX_DETAIL_COLLECTION),
    ]
    | None
)


class DiagnosticSeverity(StrEnum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class DiagnosticCategory(StrEnum):
    USER_CONFIGURATION = "USER_CONFIGURATION"
    SCHEMA_VALIDATION = "SCHEMA_VALIDATION"
    COMPATIBILITY = "COMPATIBILITY"
    ADAPTER_UNAVAILABILITY = "ADAPTER_UNAVAILABILITY"
    ENGINE_RUNTIME = "ENGINE_RUNTIME"
    PROTOCOL = "PROTOCOL"
    TIMEOUT = "TIMEOUT"
    CANCELLATION = "CANCELLATION"
    ARTIFACT_CORRUPTION = "ARTIFACT_CORRUPTION"
    PERSISTENCE = "PERSISTENCE"
    INTERNAL_INVARIANT = "INTERNAL_INVARIANT"
    SECURITY = "SECURITY"


BoundedMessage = Annotated[
    str, StringConstraints(strict=True, min_length=1, max_length=1024)
]


def _inspect_details(value: DiagnosticDetailValue, depth: int = 0) -> int:
    if depth > MAX_DETAIL_DEPTH:
        raise ValueError("diagnostic details exceed maximum depth")
    if value is None or type(value) is bool:
        return 1
    if type(value) is int:
        if not MIN_DETAIL_INTEGER <= value <= MAX_DETAIL_INTEGER:
            raise ValueError("diagnostic detail integer is outside signed 64-bit range")
        return 1
    if type(value) is str:
        if len(value) > MAX_DETAIL_STRING:
            raise ValueError("diagnostic detail string is too long")
        return 1
    if type(value) is list:
        if len(value) > MAX_DETAIL_COLLECTION:
            raise ValueError("diagnostic detail list is too large")
        return 1 + sum(_inspect_details(item, depth + 1) for item in value)
    if type(value) is dict:
        if len(value) > MAX_DETAIL_COLLECTION:
            raise ValueError("diagnostic detail object is too large")
        nodes = 1
        for key, nested in value.items():
            if len(key) > MAX_DETAIL_KEY:
                raise ValueError("diagnostic detail key is too long")
            separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key)
            normalized = re.sub(r"[^a-z0-9]+", "_", separated.casefold()).strip("_")
            padded = f"_{normalized}_"
            compact = re.sub(r"[^a-z0-9]+", "", key.casefold())
            if any(
                f"_{secret_key}_" in padded for secret_key in _SECRET_KEY_PARTS
            ) or any(secret_key in compact for secret_key in _SECRET_KEY_COMPACT):
                raise ValueError("secret-like diagnostic detail key is forbidden")
            nodes += _inspect_details(nested, depth + 1)
        return nodes
    raise ValueError("diagnostic details contain an unsupported value")


def _diagnostic_schema_extra(schema: JsonSchemaValue) -> None:
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise TypeError("diagnostic schema properties must be an object")
    causal_ids = properties.get("causal_diagnostic_ids")
    if not isinstance(causal_ids, dict):
        raise TypeError("causal diagnostic ID schema must be an object")
    causal_ids["uniqueItems"] = True
    schema["dependentRequired"] = {"run_id": ["experiment_id"]}
    schema["allOf"] = [
        {
            "if": {
                "properties": {
                    "category": {
                        "enum": [
                            "ENGINE_RUNTIME",
                            "PROTOCOL",
                            "TIMEOUT",
                            "CANCELLATION",
                        ]
                    }
                },
                "required": ["category"],
            },
            "then": {"required": ["invocation_id"]},
        }
    ]


def _is_missing(value: object) -> bool:
    return value is MISSING


class Diagnostic(CanonicalModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_diagnostic_schema_extra
    )

    schema_version: Literal["1.0.0"]
    diagnostic_id: DiagnosticId
    severity: DiagnosticSeverity
    error_code: ErrorCode
    category: DiagnosticCategory
    message: BoundedMessage
    source_component: NormalizedIdentifier
    experiment_id: ExperimentId | MISSING = MISSING  # type: ignore[valid-type]
    run_id: RunId | MISSING = MISSING  # type: ignore[valid-type]
    invocation_id: InvocationId | MISSING = MISSING  # type: ignore[valid-type]
    engine: NormalizedIdentifier | MISSING = MISSING  # type: ignore[valid-type]
    retriable: bool
    timestamp_utc: UtcDateTime
    details: Annotated[
        dict[DiagnosticDetailKey, DiagnosticDetailValue],
        Field(max_length=MAX_DETAIL_COLLECTION),
    ]
    causal_diagnostic_ids: tuple[DiagnosticId, ...] = Field(max_length=32)

    @field_validator("details")
    @classmethod
    def validate_details(
        cls,
        value: dict[DiagnosticDetailKey, DiagnosticDetailValue],
    ) -> dict[DiagnosticDetailKey, DiagnosticDetailValue]:
        nodes = _inspect_details(value)
        if nodes > MAX_DETAIL_NODES:
            raise ValueError("diagnostic details contain too many nodes")
        if len(canonical_json_bytes(value)) > MAX_DETAIL_BYTES:
            raise ValueError("diagnostic details exceed maximum encoded bytes")
        return value

    @field_validator("causal_diagnostic_ids")
    @classmethod
    def validate_causal_ids(
        cls,
        value: tuple[DiagnosticId, ...],
    ) -> tuple[DiagnosticId, ...]:
        if len(set(value)) != len(value):
            raise ValueError("causal diagnostic IDs must be unique")
        if value != tuple(sorted(value)):
            raise ValueError("causal diagnostic IDs must be sorted")
        return value

    @model_validator(mode="after")
    def validate_causes(self) -> Self:
        if self.diagnostic_id in self.causal_diagnostic_ids:
            raise ValueError("diagnostic cannot directly cause itself")
        if not _is_missing(self.run_id) and _is_missing(self.experiment_id):
            raise ValueError("run correlation requires experiment correlation")
        command_categories = {
            DiagnosticCategory.ENGINE_RUNTIME,
            DiagnosticCategory.PROTOCOL,
            DiagnosticCategory.TIMEOUT,
            DiagnosticCategory.CANCELLATION,
        }
        if self.category in command_categories and _is_missing(self.invocation_id):
            raise ValueError("command/process/protocol diagnostic requires invocation")
        return self
