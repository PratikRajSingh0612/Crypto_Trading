from __future__ import annotations

import os
import socket
import urllib.request
from pathlib import Path
from typing import Never

import pytest

from crypto_lab.configuration.loader import ConfigurationError, load_configuration
from crypto_lab.configuration.models import MAX_CONFIGURATION_BYTES, CliOverrides

_HASH = "a" * 64


def _write(path: Path, contents: str) -> Path:
    path.write_text(contents, encoding="utf-8")
    return path


def _forbidden(*_args: object, **_kwargs: object) -> Never:
    raise AssertionError("ambient source was accessed")


class ForbiddenEnvironment:
    def __getitem__(self, _key: str) -> Never:
        raise AssertionError("environment was accessed")

    def get(self, _key: str, _default: object = None) -> Never:
        raise AssertionError("environment was accessed")


def test_precedence_is_defaults_primary_local_cli(tmp_path: Path) -> None:
    primary = _write(
        tmp_path / "primary.toml",
        """
schema_version = "1.0.0"
[paths]
runtime_root = "primary-runtime"
[scheduler]
max_concurrent_runs = 2
""".strip(),
    )
    local = _write(
        tmp_path / "local.toml",
        """
schema_version = "1.0.0"
[paths]
runtime_root = "local-runtime"
[scheduler]
max_concurrent_runs = 3
""".strip(),
    )
    config = load_configuration(
        primary_path=primary,
        local_override_path=local,
        cli_overrides=CliOverrides(
            runtime_root="cli-runtime",
            max_concurrent_runs=4,
        ),
        invocation_base=tmp_path,
    )
    assert config.paths.runtime_root == str(tmp_path / "cli-runtime")
    assert config.paths.data_root == str(tmp_path / "data")
    assert config.scheduler.max_concurrent_runs == 4


def test_default_paths_use_explicit_invocation_base(tmp_path: Path) -> None:
    config = load_configuration(
        primary_path=None,
        local_override_path=None,
        cli_overrides=None,
        invocation_base=tmp_path,
    )
    assert config.paths.runtime_root == str(tmp_path / "runtime")
    assert config.paths.data_root == str(tmp_path / "data")


@pytest.mark.parametrize(
    ("primary", "local", "base", "code"),
    [
        (
            Path("relative.toml"),
            None,
            Path("C:/base"),
            "PRIMARY_PATH_NOT_ABSOLUTE",
        ),
        (
            None,
            Path("relative.toml"),
            Path("C:/base"),
            "OVERRIDE_REQUIRES_PRIMARY",
        ),
        (None, None, Path("relative"), "INVOCATION_BASE_PATH_NOT_ABSOLUTE"),
    ],
)
def test_relative_or_unpaired_sources_are_rejected(
    primary: Path | None,
    local: Path | None,
    base: Path,
    code: str,
) -> None:
    with pytest.raises(ConfigurationError, match=code):
        load_configuration(
            primary_path=primary,
            local_override_path=local,
            cli_overrides=None,
            invocation_base=base,
        )


@pytest.mark.parametrize(
    "contents",
    [
        "",
        'schema_version = "2.0.0"',
        'schema_version = "1.0.0"\nunknown = true',
        'schema_version = "1.0.0"\n[paths\nruntime_root = "x"',
    ],
)
def test_invalid_layers_use_one_path_only_error(
    tmp_path: Path,
    contents: str,
) -> None:
    primary = _write(tmp_path / "primary.toml", contents)
    with pytest.raises(
        ConfigurationError,
        match=r"CONFIG\.LAYER_INVALID",
    ) as captured:
        load_configuration(
            primary_path=primary,
            local_override_path=None,
            cli_overrides=None,
            invocation_base=tmp_path,
        )
    assert str(captured.value) == f"CONFIG.LAYER_INVALID: {primary}"


def test_oversized_layer_is_rejected_before_decode_or_parse(tmp_path: Path) -> None:
    primary = tmp_path / "oversized.toml"
    primary.write_bytes(b"x" * (MAX_CONFIGURATION_BYTES + 1))
    with pytest.raises(ConfigurationError, match=r"CONFIG\.LAYER_TOO_LARGE"):
        load_configuration(
            primary_path=primary,
            local_override_path=None,
            cli_overrides=None,
            invocation_base=tmp_path,
        )


def test_local_schema_version_cannot_differ(tmp_path: Path) -> None:
    primary = _write(tmp_path / "primary.toml", 'schema_version = "1.0.0"')
    local = _write(tmp_path / "local.toml", 'schema_version = "2.0.0"')
    with pytest.raises(ConfigurationError, match=r"CONFIG\.LAYER_INVALID"):
        load_configuration(
            primary_path=primary,
            local_override_path=local,
            cli_overrides=None,
            invocation_base=tmp_path,
        )


def test_unsafe_roots_and_relative_adapter_executables_fail(
    tmp_path: Path,
) -> None:
    unsafe = _write(
        tmp_path / "unsafe.toml",
        'schema_version = "1.0.0"\n[paths]\nruntime_root = "../escape"',
    )
    with pytest.raises(ConfigurationError, match=r"CONFIG\.UNSAFE_PATH"):
        load_configuration(
            primary_path=unsafe,
            local_override_path=None,
            cli_overrides=None,
            invocation_base=tmp_path,
        )
    adapter = _write(
        tmp_path / "adapter.toml",
        f"""
schema_version = "1.0.0"
[[adapters.entries]]
adapter_name = "adapter.alpha"
adapter_version = "1.0.0"
executable_path = "relative.exe"
executable_hash = "{_HASH}"
runtime_metadata = {{}}
""".strip(),
    )
    with pytest.raises(
        ConfigurationError,
        match=r"CONFIG\.ADAPTER_EXECUTABLE_NOT_ABSOLUTE",
    ):
        load_configuration(
            primary_path=adapter,
            local_override_path=None,
            cli_overrides=None,
            invocation_base=tmp_path,
        )


@pytest.mark.parametrize(
    "value",
    [
        r"C:drive-relative",
        r"\rooted-without-drive",
        r"\\server\share",
        "folder//child",
        "folder/./child",
        "folder/name:stream",
        "folder/CON",
        "folder/trailing. ",
        "folder/root?/file",
        "folder/bad<name",
        "folder/control\x1f",
    ],
)
def test_cli_roots_reject_unsafe_windows_syntax(
    tmp_path: Path,
    value: str,
) -> None:
    with pytest.raises(ConfigurationError, match=r"CONFIG\.UNSAFE_PATH"):
        load_configuration(
            primary_path=None,
            local_override_path=None,
            cli_overrides=CliOverrides(runtime_root=value),
            invocation_base=tmp_path,
        )


def test_explicit_loading_uses_no_ambient_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary = _write(tmp_path / "primary.toml", 'schema_version = "1.0.0"')
    with monkeypatch.context() as boundary:
        boundary.setattr(os, "getenv", _forbidden)
        boundary.setattr(os, "environ", ForbiddenEnvironment())
        boundary.setattr(Path, "home", _forbidden)
        boundary.setattr(Path, "cwd", _forbidden)
        boundary.setattr(Path, "expanduser", _forbidden)
        boundary.setattr(Path, "resolve", _forbidden)
        boundary.setattr(socket, "create_connection", _forbidden)
        boundary.setattr(urllib.request, "urlopen", _forbidden)
        config = load_configuration(
            primary_path=primary,
            local_override_path=None,
            cli_overrides=None,
            invocation_base=tmp_path,
        )
    assert config.schema_version == "1.0.0"


def test_implicit_config_file_is_never_discovered(tmp_path: Path) -> None:
    _write(
        tmp_path / "config.toml",
        'schema_version = "1.0.0"\n[scheduler]\nmax_concurrent_runs = 8',
    )
    config = load_configuration(
        primary_path=None,
        local_override_path=None,
        cli_overrides=None,
        invocation_base=tmp_path,
    )
    assert config.scheduler.max_concurrent_runs == 1
