"""Strict Project 1 configuration and typed precedence layers."""

from __future__ import annotations

import re
from pathlib import PureWindowsPath
from typing import Annotated, ClassVar, Literal, Self

from pydantic import (
    AfterValidator,
    ConfigDict,
    Field,
    StringConstraints,
    WithJsonSchema,
    field_validator,
    model_validator,
)
from pydantic.json_schema import JsonSchemaValue

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.identifiers import NormalizedIdentifier, Sha256
from crypto_lab.domain.lifecycle import RetryTerminalState as RetryTerminalState
from crypto_lab.domain.versioning import SemanticVersion

PathText = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=1024),
]
SafeFilename = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=255,
        pattern=r"^[^<>:\"/\\|?*\x00-\x1f]+$",
    ),
    WithJsonSchema(
        {
            "type": "string",
            "minLength": 1,
            "maxLength": 255,
            "allOf": [
                {"pattern": r"^[^<>:\"/\\|?*\x00-\x1f]+(?![\s\S])"},
                {"not": {"pattern": r"[ .](?![\s\S])"}},
                {
                    "not": {
                        "pattern": (
                            r"^(?:[Aa][Uu][Xx]|[Cc][Oo][Nn]|[Nn][Uu][Ll]|"
                            r"[Pp][Rr][Nn]|[Cc][Oo][Mm][1-9]|[Ll][Pp][Tt][1-9])"
                            r"(?:\..*)?(?![\s\S])"
                        )
                    }
                },
            ],
        }
    ),
]
BoundedText = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=1024),
]


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
_WINDOWS_RESERVED_NAMES = {
    "AUX",
    "CON",
    "NUL",
    "PRN",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}
_MAX_RUNTIME_METADATA_BYTES = 16_384
_MAX_RUNTIME_METADATA_COLLECTION = 64
_MAX_RUNTIME_METADATA_DEPTH = 8
_MAX_RUNTIME_METADATA_KEY = 128
_MAX_RUNTIME_METADATA_NODES = 256
_MAX_RUNTIME_METADATA_STRING = 2_048
_MIN_RUNTIME_METADATA_INTEGER = -(2**63)
_MAX_RUNTIME_METADATA_INTEGER = 2**63 - 1
_INVALID_WINDOWS_PATH_CHARACTERS = re.compile(r'[<>"|?*\x00-\x1f]')
_WINDOWS_RESERVED_SCHEMA_PATTERN = (
    r"(?:^|[\\/])"
    r"(?:[Aa][Uu][Xx]|[Cc][Oo][Nn]|[Nn][Uu][Ll]|[Pp][Rr][Nn]|"
    r"[Cc][Oo][Mm][1-9]|[Ll][Pp][Tt][1-9])"
    r"(?:\.|[\\/]|(?![\s\S]))"
)
MAX_CONFIGURATION_BYTES = 1_048_576
_LOCAL_PATH_JSON_SCHEMA: JsonSchemaValue = {
    "type": "string",
    "minLength": 1,
    "maxLength": 1024,
    "allOf": [
        {
            "pattern": (
                r"^(?:[A-Za-z]:[\\/])?"
                r'[^<>:"/\\|?*\x00-\x1f]+'
                r'(?:[\\/][^<>:"/\\|?*\x00-\x1f]+)*(?![\s\S])'
            )
        },
        {"not": {"pattern": r"(?:^|[\\/])\.{1,2}(?:[\\/]|(?![\s\S]))"}},
        {"not": {"pattern": r"[ .](?:[\\/]|(?![\s\S]))"}},
        {"not": {"pattern": _WINDOWS_RESERVED_SCHEMA_PATTERN}},
    ],
}
_ABSOLUTE_LOCAL_PATH_JSON_SCHEMA: JsonSchemaValue = {
    "type": "string",
    "minLength": 1,
    "maxLength": 1024,
    "allOf": [
        {
            "pattern": (
                r"^[A-Za-z]:[\\/]"
                r'[^<>:"/\\|?*\x00-\x1f]+'
                r'(?:[\\/][^<>:"/\\|?*\x00-\x1f]+)*(?![\s\S])'
            )
        },
        {"not": {"pattern": r"(?:^|[\\/])\.{1,2}(?:[\\/]|(?![\s\S]))"}},
        {"not": {"pattern": r"[ .](?:[\\/]|(?![\s\S]))"}},
        {"not": {"pattern": _WINDOWS_RESERVED_SCHEMA_PATTERN}},
    ],
}


def validate_local_windows_path(
    value: str,
    *,
    require_absolute: bool = False,
) -> str:
    """Validate local Windows path syntax without touching the filesystem."""
    if value.startswith(("\\\\", "//")):
        raise ValueError("path must be local, not UNC")
    if _INVALID_WINDOWS_PATH_CHARACTERS.search(value) is not None:
        raise ValueError("path contains a Windows-invalid character")
    configured = PureWindowsPath(value)
    if configured.drive and not configured.root:
        raise ValueError("drive-relative paths are forbidden")
    if configured.root and not configured.drive:
        raise ValueError("rooted paths require a local drive")
    if require_absolute and not configured.is_absolute():
        raise ValueError("path must be absolute")
    segments = re.split(r"[\\/]", value)
    for index, segment in enumerate(segments):
        is_drive = index == 0 and re.fullmatch(r"[A-Za-z]:", segment) is not None
        trimmed = segment.rstrip(" .")
        stem = trimmed.partition(".")[0].upper()
        if (
            segment in {"", ".", ".."}
            or (":" in segment and not is_drive)
            or trimmed != segment
            or stem in _WINDOWS_RESERVED_NAMES
        ):
            raise ValueError("path contains an unsafe Windows segment")
    return value


def _local_path(value: str) -> str:
    return validate_local_windows_path(value)


def _absolute_local_path(value: str) -> str:
    return validate_local_windows_path(value, require_absolute=True)


LocalPathText = Annotated[
    PathText,
    AfterValidator(_local_path),
    WithJsonSchema(_LOCAL_PATH_JSON_SCHEMA),
]
AbsoluteLocalPathText = Annotated[
    PathText,
    AfterValidator(_absolute_local_path),
    WithJsonSchema(_ABSOLUTE_LOCAL_PATH_JSON_SCHEMA),
]
type BoundedRuntimeMetadataInteger = Annotated[
    int,
    Field(
        strict=True,
        ge=_MIN_RUNTIME_METADATA_INTEGER,
        le=_MAX_RUNTIME_METADATA_INTEGER,
    ),
]
type RuntimeMetadataKey = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=_MAX_RUNTIME_METADATA_KEY,
    ),
]
type RuntimeMetadataString = Annotated[
    str,
    StringConstraints(strict=True, max_length=_MAX_RUNTIME_METADATA_STRING),
]
type RuntimeMetadataValue = (
    RuntimeMetadataString
    | BoundedRuntimeMetadataInteger
    | bool
    | Annotated[
        list[RuntimeMetadataValue],
        Field(max_length=_MAX_RUNTIME_METADATA_COLLECTION),
    ]
    | Annotated[
        dict[RuntimeMetadataKey, RuntimeMetadataValue],
        Field(max_length=_MAX_RUNTIME_METADATA_COLLECTION),
    ]
    | None
)


# `RetryTerminalState` is defined in `crypto_lab.domain.lifecycle` since Stage 5
# Task 1 (Stage 5 plan section 2.5) and re-exported above in the explicit
# `import X as X` form, so `from crypto_lab.configuration.models import
# RetryTerminalState` stays valid under strict mypy. The relocation is
# byte-neutral for the released `configuration/application-config-v1` schema,
# which renders the enum by bare class name and without a description.
_RETRY_ORDER = tuple(RetryTerminalState)


def _ordered_retry_states(value: object) -> tuple[RetryTerminalState, ...]:
    if not isinstance(value, list | tuple):
        raise ValueError("retry states must be an array")
    if not all(isinstance(item, str | RetryTerminalState) for item in value):
        raise ValueError("retry states must be strings")
    try:
        items = tuple(RetryTerminalState(item) for item in value)
    except ValueError as error:
        raise ValueError("retry states contain a foreign value") from error
    if len(set(items)) != len(items):
        raise ValueError("retry states must be unique")
    return tuple(item for item in _RETRY_ORDER if item in items)


def _set_array_unique(schema: JsonSchemaValue, field: str) -> None:
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise TypeError("configuration schema properties must be an object")
    field_schema = properties.get(field)
    if not isinstance(field_schema, dict):
        raise TypeError(f"configuration schema field {field!r} must be an object")
    field_schema["uniqueItems"] = True


def _retry_schema_extra(schema: JsonSchemaValue) -> None:
    _set_array_unique(schema, "automatically_retry_terminal_states")


def _adapters_schema_extra(schema: JsonSchemaValue) -> None:
    _set_array_unique(schema, "entries")


def _inspect_runtime_metadata(value: RuntimeMetadataValue, depth: int = 0) -> int:
    if depth > _MAX_RUNTIME_METADATA_DEPTH:
        raise ValueError("runtime metadata exceeds maximum depth")
    if value is None or type(value) is bool:
        return 1
    if type(value) is int:
        if not _MIN_RUNTIME_METADATA_INTEGER <= value <= _MAX_RUNTIME_METADATA_INTEGER:
            raise ValueError("runtime metadata integer is outside signed 64-bit range")
        return 1
    if type(value) is str:
        if len(value) > _MAX_RUNTIME_METADATA_STRING:
            raise ValueError("runtime metadata string is too long")
        return 1
    if type(value) is dict:
        if len(value) > _MAX_RUNTIME_METADATA_COLLECTION:
            raise ValueError("runtime metadata object is too large")
        nodes = 1
        for key, nested in value.items():
            if len(key) > _MAX_RUNTIME_METADATA_KEY:
                raise ValueError("runtime metadata key is too long")
            separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key)
            normalized = re.sub(r"[^a-z0-9]+", "_", separated.casefold()).strip("_")
            padded = f"_{normalized}_"
            compact = re.sub(r"[^a-z0-9]+", "", key.casefold())
            if any(
                f"_{secret_key}_" in padded for secret_key in _SECRET_KEY_PARTS
            ) or any(secret_key in compact for secret_key in _SECRET_KEY_COMPACT):
                raise ValueError("secret-like runtime metadata key is forbidden")
            nodes += _inspect_runtime_metadata(nested, depth + 1)
        return nodes
    if type(value) is list:
        if len(value) > _MAX_RUNTIME_METADATA_COLLECTION:
            raise ValueError("runtime metadata list is too large")
        nodes = 1
        for item in value:
            nodes += _inspect_runtime_metadata(item, depth + 1)
        return nodes
    raise ValueError("runtime metadata contains an unsupported value")


class PathsConfig(CanonicalModel):
    runtime_root: LocalPathText = "runtime"
    data_root: LocalPathText = "data"
    artifacts_root: LocalPathText = "artifacts"
    logs_root: LocalPathText = "logs"
    runtimes_root: LocalPathText = "runtimes"


class DatabaseConfig(CanonicalModel):
    filename: SafeFilename = "crypto_lab.sqlite3"
    busy_timeout_ms: int = Field(default=5000, ge=100, le=60000)

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, value: str) -> str:
        trimmed = value.rstrip(" .")
        stem = trimmed.partition(".")[0].upper()
        if value in {".", ".."} or trimmed != value or stem in _WINDOWS_RESERVED_NAMES:
            raise ValueError("database filename is unsafe on Windows")
        return value


class RetryConfig(CanonicalModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_retry_schema_extra
    )

    maximum_attempts_per_slot: int = Field(default=1, ge=1, le=5)
    automatically_retry_terminal_states: tuple[RetryTerminalState, ...] = ()
    retry_delay_seconds: int = Field(default=0, ge=0, le=300)
    require_fresh_availability_observation_for_unavailable: Literal[True] = True

    @field_validator("automatically_retry_terminal_states", mode="before")
    @classmethod
    def normalize_retry_states(
        cls,
        value: object,
    ) -> tuple[RetryTerminalState, ...]:
        return _ordered_retry_states(value)


class SchedulerConfig(CanonicalModel):
    max_concurrent_runs: int = Field(default=1, ge=1, le=8)
    retry: RetryConfig = Field(default_factory=RetryConfig)


class ProcessConfig(CanonicalModel):
    heartbeat_interval_seconds: int = Field(default=15, ge=1, le=300)
    missing_heartbeat_seconds: int = Field(default=45, ge=2, le=900)
    describe_timeout_seconds: int = Field(default=30, ge=1, le=300)
    validate_timeout_seconds: int = Field(default=120, ge=1, le=1800)
    default_run_timeout_seconds: int = Field(default=3600, ge=1, le=604800)
    finalization_timeout_seconds: int = Field(default=300, ge=1, le=3600)
    cancellation_grace_seconds: int = Field(default=10, ge=0, le=300)

    @model_validator(mode="after")
    def validate_heartbeat_ratio(self) -> Self:
        if self.missing_heartbeat_seconds < 2 * self.heartbeat_interval_seconds:
            raise ValueError("missing heartbeat must be at least twice the interval")
        return self


class ProtocolConfig(CanonicalModel):
    max_event_bytes: int = Field(default=1_048_576, ge=4096, le=1_048_576)
    max_manifest_bytes: int = Field(default=16_777_216, ge=65536, le=16_777_216)


class LoggingConfig(CanonicalModel):
    max_stderr_bytes_per_invocation: int = Field(
        default=52_428_800,
        ge=1_048_576,
        le=52_428_800,
    )
    retained_files: int = Field(default=10, ge=1, le=100)


class AdapterEntryConfig(CanonicalModel):
    adapter_name: NormalizedIdentifier
    adapter_version: SemanticVersion
    executable_path: AbsoluteLocalPathText
    executable_hash: Sha256
    runtime_metadata: Annotated[
        dict[RuntimeMetadataKey, RuntimeMetadataValue],
        Field(max_length=_MAX_RUNTIME_METADATA_COLLECTION),
    ] = Field(default_factory=dict)

    @field_validator("runtime_metadata")
    @classmethod
    def validate_runtime_metadata(
        cls,
        value: dict[RuntimeMetadataKey, RuntimeMetadataValue],
    ) -> dict[RuntimeMetadataKey, RuntimeMetadataValue]:
        nodes = _inspect_runtime_metadata(value)
        if nodes > _MAX_RUNTIME_METADATA_NODES:
            raise ValueError("runtime metadata contains too many nodes")
        if len(canonical_json_bytes(value)) > _MAX_RUNTIME_METADATA_BYTES:
            raise ValueError("runtime metadata exceeds maximum encoded bytes")
        return value


class AdaptersConfig(CanonicalModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_adapters_schema_extra
    )

    entries: tuple[AdapterEntryConfig, ...] = Field(default=(), max_length=32)

    @field_validator("entries", mode="before")
    @classmethod
    def normalize_entries(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("entries")
    @classmethod
    def validate_entries(
        cls,
        value: tuple[AdapterEntryConfig, ...],
    ) -> tuple[AdapterEntryConfig, ...]:
        identities = tuple((item.adapter_name, item.adapter_version) for item in value)
        if len(set(identities)) != len(identities):
            raise ValueError("adapter entries must be unique")
        if identities != tuple(sorted(identities)):
            raise ValueError("adapter entries must be deterministically ordered")
        return value


class PolicyConfig(CanonicalModel):
    allow_network: Literal[False] = False
    allow_credentials: Literal[False] = False
    allow_live: Literal[False] = False


class ApplicationConfig(CanonicalModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    paths: PathsConfig = Field(default_factory=PathsConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    scheduler: SchedulerConfig = Field(default_factory=SchedulerConfig)
    process: ProcessConfig = Field(default_factory=ProcessConfig)
    protocol: ProtocolConfig = Field(default_factory=ProtocolConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    adapters: AdaptersConfig = Field(default_factory=AdaptersConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)

    @model_validator(mode="after")
    def validate_encoded_size(self) -> Self:
        if len(canonical_json_bytes(self)) > MAX_CONFIGURATION_BYTES:
            raise ValueError("configuration exceeds maximum encoded bytes")
        return self


class PathsLayer(CanonicalModel):
    runtime_root: PathText | None = None
    data_root: PathText | None = None
    artifacts_root: PathText | None = None
    logs_root: PathText | None = None
    runtimes_root: PathText | None = None


class DatabaseLayer(CanonicalModel):
    filename: SafeFilename | None = None
    busy_timeout_ms: int | None = Field(default=None, ge=100, le=60000)


class RetryLayer(CanonicalModel):
    maximum_attempts_per_slot: int | None = Field(default=None, ge=1, le=5)
    automatically_retry_terminal_states: tuple[RetryTerminalState, ...] | None = None
    retry_delay_seconds: int | None = Field(default=None, ge=0, le=300)
    require_fresh_availability_observation_for_unavailable: Literal[True] | None = None

    @field_validator("automatically_retry_terminal_states", mode="before")
    @classmethod
    def normalize_retry_states(cls, value: object) -> object:
        return None if value is None else _ordered_retry_states(value)


class SchedulerLayer(CanonicalModel):
    max_concurrent_runs: int | None = Field(default=None, ge=1, le=8)
    retry: RetryLayer | None = None


class ProcessLayer(CanonicalModel):
    heartbeat_interval_seconds: int | None = Field(default=None, ge=1, le=300)
    missing_heartbeat_seconds: int | None = Field(default=None, ge=2, le=900)
    describe_timeout_seconds: int | None = Field(default=None, ge=1, le=300)
    validate_timeout_seconds: int | None = Field(default=None, ge=1, le=1800)
    default_run_timeout_seconds: int | None = Field(default=None, ge=1, le=604800)
    finalization_timeout_seconds: int | None = Field(default=None, ge=1, le=3600)
    cancellation_grace_seconds: int | None = Field(default=None, ge=0, le=300)


class ProtocolLayer(CanonicalModel):
    max_event_bytes: int | None = Field(default=None, ge=4096, le=1_048_576)
    max_manifest_bytes: int | None = Field(default=None, ge=65536, le=16_777_216)


class LoggingLayer(CanonicalModel):
    max_stderr_bytes_per_invocation: int | None = Field(
        default=None,
        ge=1_048_576,
        le=52_428_800,
    )
    retained_files: int | None = Field(default=None, ge=1, le=100)


class AdaptersLayer(CanonicalModel):
    entries: tuple[AdapterEntryConfig, ...] | None = None

    @field_validator("entries", mode="before")
    @classmethod
    def normalize_entries(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value


class PolicyLayer(CanonicalModel):
    allow_network: Literal[False] | None = None
    allow_credentials: Literal[False] | None = None
    allow_live: Literal[False] | None = None


class ConfigurationLayer(CanonicalModel):
    schema_version: Literal["1.0.0"]
    paths: PathsLayer | None = None
    database: DatabaseLayer | None = None
    scheduler: SchedulerLayer | None = None
    process: ProcessLayer | None = None
    protocol: ProtocolLayer | None = None
    logging: LoggingLayer | None = None
    adapters: AdaptersLayer | None = None
    policy: PolicyLayer | None = None


class CliOverrides(CanonicalModel):
    runtime_root: PathText | None = None
    data_root: PathText | None = None
    artifacts_root: PathText | None = None
    logs_root: PathText | None = None
    runtimes_root: PathText | None = None
    max_concurrent_runs: int | None = Field(default=None, ge=1, le=8)
    maximum_attempts_per_slot: int | None = Field(default=None, ge=1, le=5)
    automatically_retry_terminal_states: tuple[RetryTerminalState, ...] | None = None
    retry_delay_seconds: int | None = Field(default=None, ge=0, le=300)
    heartbeat_interval_seconds: int | None = Field(default=None, ge=1, le=300)
    missing_heartbeat_seconds: int | None = Field(default=None, ge=2, le=900)
    describe_timeout_seconds: int | None = Field(default=None, ge=1, le=300)
    validate_timeout_seconds: int | None = Field(default=None, ge=1, le=1800)
    default_run_timeout_seconds: int | None = Field(default=None, ge=1, le=604800)
    finalization_timeout_seconds: int | None = Field(default=None, ge=1, le=3600)
    cancellation_grace_seconds: int | None = Field(default=None, ge=0, le=300)

    @field_validator("automatically_retry_terminal_states", mode="before")
    @classmethod
    def normalize_retry_states(cls, value: object) -> object:
        return None if value is None else _ordered_retry_states(value)
