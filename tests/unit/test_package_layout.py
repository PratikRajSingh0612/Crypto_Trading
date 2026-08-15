"""Test the Stage 1 package layout and bounded fresh-process import guard."""

from __future__ import annotations

import importlib
import subprocess
import sys
from importlib.metadata import version
from pathlib import Path

PACKAGE_MODULES: tuple[str, ...] = (
    "crypto_lab",
    "crypto_lab.domain",
    "crypto_lab.domain.base",
    "crypto_lab.domain.identifiers",
    "crypto_lab.domain.time",
    "crypto_lab.domain.financial",
    "crypto_lab.domain.records",
    "crypto_lab.domain.versioning",
    "crypto_lab.domain.canonical_json",
    "crypto_lab.domain.hashing",
    "crypto_lab.domain.diagnostics",
    "crypto_lab.strategy",
    "crypto_lab.capabilities",
    "crypto_lab.adapters",
    "crypto_lab.adapters.versioning",
    "crypto_lab.adapters.descriptors",
    "crypto_lab.experiments",
    "crypto_lab.datasets",
    "crypto_lab.datasets.models",
    "crypto_lab.datasets.hashing",
    "crypto_lab.artifacts",
    "crypto_lab.artifacts.ownership",
    "crypto_lab.persistence",
    "crypto_lab.process_supervision",
    "crypto_lab.configuration",
    "crypto_lab.configuration.models",
    "crypto_lab.configuration.loader",
    "crypto_lab.configuration.snapshot",
    "crypto_lab.audit",
    "crypto_lab.cli",
    "crypto_lab.cli.main",
    "crypto_lab.cli.__main__",
    "crypto_lab.schema_registry",
)
_IMPORT_SENTINEL = "IMPORT_GUARDS_OK"
_IMPORT_PROBE = """
from __future__ import annotations

import builtins
import http.client
import importlib
import os
import socket
import subprocess
import sys
import urllib.request
import winreg
from pathlib import Path
from typing import NoReturn


def _unexpected_operation(*args: object, **kwargs: object) -> NoReturn:
    del args, kwargs
    raise AssertionError("package import attempted a forbidden side effect")


builtins.open = _unexpected_operation
os.putenv = _unexpected_operation
os.unsetenv = _unexpected_operation
os.system = _unexpected_operation
os.spawnl = _unexpected_operation
os.spawnle = _unexpected_operation
os.spawnlp = _unexpected_operation
os.spawnlpe = _unexpected_operation
os.spawnv = _unexpected_operation
os.spawnve = _unexpected_operation
os.spawnvp = _unexpected_operation
os.spawnvpe = _unexpected_operation
os.startfile = _unexpected_operation
socket.socket = _unexpected_operation
socket.create_connection = _unexpected_operation
subprocess.Popen = _unexpected_operation
urllib.request.urlopen = _unexpected_operation
http.client.HTTPConnection.connect = _unexpected_operation
http.client.HTTPSConnection.connect = _unexpected_operation
winreg.OpenKey = _unexpected_operation
winreg.OpenKeyEx = _unexpected_operation
winreg.QueryValue = _unexpected_operation
winreg.QueryValueEx = _unexpected_operation
winreg.EnumKey = _unexpected_operation
winreg.EnumValue = _unexpected_operation
Path.home = _unexpected_operation
Path.expanduser = _unexpected_operation
Path.open = _unexpected_operation
Path.read_bytes = _unexpected_operation
Path.read_text = _unexpected_operation
Path.exists = _unexpected_operation
Path.is_dir = _unexpected_operation
Path.is_file = _unexpected_operation
Path.iterdir = _unexpected_operation
Path.glob = _unexpected_operation
Path.rglob = _unexpected_operation
Path.stat = _unexpected_operation
Path.lstat = _unexpected_operation
Path.mkdir = _unexpected_operation
Path.touch = _unexpected_operation
Path.write_bytes = _unexpected_operation
Path.write_text = _unexpected_operation

sentinel = sys.argv[1]
module_names = tuple(sys.argv[2:])
imported_names = tuple(
    importlib.import_module(module_name).__name__
    for module_name in module_names
)
if imported_names != module_names:
    raise AssertionError("imported module names did not match the requested modules")
print(sentinel)
"""


def test_all_planned_modules_import_fresh_without_observable_side_effects(
    tmp_path: Path,
) -> None:
    paths_before = tuple(tmp_path.iterdir())
    assert paths_before == ()

    repository_root = Path(__file__).resolve().parents[2]
    expected_interpreter = repository_root / ".venv" / "Scripts" / "python.exe"
    assert Path(sys.executable).resolve() == expected_interpreter.resolve()
    command: list[str] = [
        sys.executable,
        "-I",
        "-B",
        "-c",
        _IMPORT_PROBE,
        _IMPORT_SENTINEL,
        *PACKAGE_MODULES,
    ]
    completed = subprocess.run(  # noqa: S603 - fixed isolated Python command.
        command,
        cwd=tmp_path,
        check=False,
        capture_output=True,
        shell=False,
        text=True,
        # Stage 3 stability qualification measured this test body at 1.35-1.91s
        # idle and 3.50-5.46s with all 14 logical cores saturated; the child's
        # own startup is strictly less. A 10s ceiling left too little margin
        # above legitimate loaded startup, so it is raised to 30s, which still
        # bounds a hung child.
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == f"{_IMPORT_SENTINEL}\n"
    assert completed.stderr == ""
    assert tuple(tmp_path.iterdir()) == paths_before


def test_distribution_metadata_reports_initial_version() -> None:
    assert version("crypto-trading-lab") == "0.1.0"


def test_package_contains_pep_561_marker() -> None:
    package = importlib.import_module("crypto_lab")
    package_file = package.__file__
    assert package_file is not None
    typing_marker = Path(package_file).with_name("py.typed")
    assert typing_marker.is_file()
    assert typing_marker.read_bytes() == b""
