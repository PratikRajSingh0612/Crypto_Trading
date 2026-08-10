"""Tests for the version-only Stage 1 command line."""

from __future__ import annotations

import importlib.metadata
import runpy
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

import pytest

import crypto_lab.cli.main as cli_main

EXPECTED_VERSION_LINE = "crypto-lab 0.1.0"


def _run_local_command(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - arguments contain fixed local executables.
        list(command),
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def test_version_is_read_from_distribution_metadata(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    requested: list[str] = []

    def fake_version(distribution_name: str) -> str:
        requested.append(distribution_name)
        return "9.8.7"

    monkeypatch.setattr(importlib.metadata, "version", fake_version)

    with pytest.raises(SystemExit) as error:
        cli_main.main(["--version"])

    assert error.value.code == 0
    assert requested == ["crypto-trading-lab"]
    assert capsys.readouterr().out == "crypto-lab 9.8.7\n"


def test_main_prints_exact_installed_version(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as error:
        cli_main.main(["--version"])

    assert error.value.code == 0
    assert capsys.readouterr().out == f"{EXPECTED_VERSION_LINE}\n"


def test_main_without_arguments_prints_help_and_succeeds(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli_main.main([]) == 0
    output = capsys.readouterr().out
    assert output.startswith("usage: crypto-lab")
    assert "--version" in output


def test_unknown_argument_uses_argparse_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as error:
        cli_main.main(["--unknown"])

    assert error.value.code == 2
    assert "unrecognized arguments: --unknown" in capsys.readouterr().err


def test_installed_console_script_prints_exact_version() -> None:
    console_script = Path(sys.executable).with_name("crypto-lab.exe")
    assert console_script.is_file()

    result = _run_local_command([str(console_script), "--version"])

    assert result.returncode == 0
    assert result.stdout == f"{EXPECTED_VERSION_LINE}\n"
    assert result.stderr == ""


def test_python_module_prints_exact_version() -> None:
    result = _run_local_command([sys.executable, "-m", "crypto_lab.cli", "--version"])

    assert result.returncode == 0
    assert result.stdout == f"{EXPECTED_VERSION_LINE}\n"
    assert result.stderr == ""


def test_module_entrypoint_exits_with_main_result(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["crypto-lab"])
    monkeypatch.delitem(sys.modules, "crypto_lab.cli.__main__", raising=False)

    with pytest.raises(SystemExit) as error:
        runpy.run_module("crypto_lab.cli", run_name="__main__")

    assert error.value.code == 0
    assert capsys.readouterr().out.startswith("usage: crypto-lab")
