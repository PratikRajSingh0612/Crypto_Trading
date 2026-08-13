"""Explicit TOML loading and deterministic configuration precedence."""

from __future__ import annotations

import tomllib
from pathlib import Path, PureWindowsPath
from typing import Any, cast

from pydantic import ValidationError

from crypto_lab.configuration.models import (
    MAX_CONFIGURATION_BYTES,
    ApplicationConfig,
    CliOverrides,
    ConfigurationLayer,
    validate_local_windows_path,
)


class ConfigurationError(Exception):
    """Stable code plus caller-supplied path, never source content."""

    def __init__(self, code: str, path: Path | None = None) -> None:
        self.code = code
        self.path = path
        suffix = "" if path is None else f": {path}"
        super().__init__(f"{code}{suffix}")


def _read_layer(path: Path) -> ConfigurationLayer:
    try:
        with path.open("rb") as source:
            encoded = source.read(MAX_CONFIGURATION_BYTES + 1)
        if len(encoded) > MAX_CONFIGURATION_BYTES:
            raise ConfigurationError("CONFIG.LAYER_TOO_LARGE", path)
        text = encoded.decode("utf-8")
        document = tomllib.loads(text)
        return ConfigurationLayer.model_validate(document)
    except ValidationError as error:
        if any("executable_path" in item["loc"] for item in error.errors()):
            raise ConfigurationError(
                "CONFIG.ADAPTER_EXECUTABLE_NOT_ABSOLUTE",
                path,
            ) from error
        raise ConfigurationError("CONFIG.LAYER_INVALID", path) from error
    except (OSError, tomllib.TOMLDecodeError, UnicodeError) as error:
        raise ConfigurationError("CONFIG.LAYER_INVALID", path) from error


def _deep_merge(
    base: dict[str, Any],
    override: dict[str, Any],
) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        current = merged.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            merged[key] = _deep_merge(current, value)
        else:
            merged[key] = value
    return merged


def _require_absolute_source(path: Path, label: str) -> None:
    rendered = str(path)
    if not path.is_absolute() or rendered.startswith(("\\\\", "//")):
        raise ConfigurationError(f"CONFIG.{label}_PATH_NOT_ABSOLUTE", path)


def _lexical_root(base: Path, value: str) -> str:
    try:
        validate_local_windows_path(value)
    except ValueError as error:
        raise ConfigurationError("CONFIG.UNSAFE_PATH") from error
    configured_windows = PureWindowsPath(value)
    configured = Path(value)
    candidate = configured if configured_windows.is_absolute() else base / configured
    return str(candidate)


def _cli_document(overrides: CliOverrides) -> dict[str, Any]:
    raw = overrides.model_dump(mode="python", exclude_none=True)
    document: dict[str, Any] = {}
    path_names = {
        "runtime_root",
        "data_root",
        "artifacts_root",
        "logs_root",
        "runtimes_root",
    }
    retry_names = {
        "maximum_attempts_per_slot",
        "automatically_retry_terminal_states",
        "retry_delay_seconds",
    }
    process_names = {
        "heartbeat_interval_seconds",
        "missing_heartbeat_seconds",
        "describe_timeout_seconds",
        "validate_timeout_seconds",
        "default_run_timeout_seconds",
        "finalization_timeout_seconds",
        "cancellation_grace_seconds",
    }
    paths = {name: raw[name] for name in path_names if name in raw}
    retry = {name: raw[name] for name in retry_names if name in raw}
    process = {name: raw[name] for name in process_names if name in raw}
    if paths:
        document["paths"] = paths
    scheduler: dict[str, Any] = {}
    if "max_concurrent_runs" in raw:
        scheduler["max_concurrent_runs"] = raw["max_concurrent_runs"]
    if retry:
        scheduler["retry"] = retry
    if scheduler:
        document["scheduler"] = scheduler
    if process:
        document["process"] = process
    return document


def _resolve_paths(config: ApplicationConfig, base: Path) -> ApplicationConfig:
    document = config.model_dump(mode="python")
    paths = cast(dict[str, str], document["paths"])
    document["paths"] = {
        key: _lexical_root(base, value) for key, value in paths.items()
    }
    adapters = cast(dict[str, object], document["adapters"])
    entries = cast(
        list[dict[str, object]] | tuple[dict[str, object], ...],
        adapters["entries"],
    )
    for entry in entries:
        executable = cast(str, entry["executable_path"])
        if not PureWindowsPath(executable).is_absolute():
            raise ConfigurationError("CONFIG.ADAPTER_EXECUTABLE_NOT_ABSOLUTE")
        entry["executable_path"] = _lexical_root(base, executable)
    return ApplicationConfig.model_validate(document)


def load_configuration(
    *,
    primary_path: Path | None,
    local_override_path: Path | None,
    cli_overrides: CliOverrides | None,
    invocation_base: Path,
) -> ApplicationConfig:
    """Load only exact supplied sources under fixed precedence."""
    _require_absolute_source(invocation_base, "INVOCATION_BASE")
    if local_override_path is not None and primary_path is None:
        raise ConfigurationError("CONFIG.OVERRIDE_REQUIRES_PRIMARY")
    base_document = ApplicationConfig().model_dump(mode="python")
    root_base = invocation_base
    if primary_path is not None:
        _require_absolute_source(primary_path, "PRIMARY")
        primary = _read_layer(primary_path)
        base_document = _deep_merge(
            base_document,
            primary.model_dump(mode="python", exclude_none=True),
        )
        root_base = primary_path.parent
    if local_override_path is not None:
        _require_absolute_source(local_override_path, "OVERRIDE")
        local = _read_layer(local_override_path)
        base_document = _deep_merge(
            base_document,
            local.model_dump(mode="python", exclude_none=True),
        )
    if cli_overrides is not None:
        base_document = _deep_merge(base_document, _cli_document(cli_overrides))
    try:
        config = ApplicationConfig.model_validate(base_document)
        return _resolve_paths(config, root_base)
    except ValidationError as error:
        if any("executable_path" in item["loc"] for item in error.errors()):
            raise ConfigurationError(
                "CONFIG.ADAPTER_EXECUTABLE_NOT_ABSOLUTE"
            ) from error
        if any("paths" in item["loc"] for item in error.errors()):
            raise ConfigurationError("CONFIG.UNSAFE_PATH") from error
        raise ConfigurationError("CONFIG.RESOLVED_INVALID") from error
