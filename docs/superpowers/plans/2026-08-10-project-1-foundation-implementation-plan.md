# Project 1 Repository Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish a deterministic, strictly typed, offline-verifiable Python 3.12 repository foundation for the Project 1 engine-neutral core without implementing any future trading, domain, persistence, adapter, or runtime behavior.

**Architecture:** Create a `src`-layout distribution named `crypto-trading-lab` with import package `crypto_lab`, empty runtime dependencies, side-effect-free package boundaries, and a version/help-only standard-library CLI. Keep production behavior deliberately minimal while enforcing the future domain dependency boundary and fixed safety scope through typed tests and one Windows PowerShell verification entry point.

**Tech Stack:** Windows; CPython 3.12 only; `uv`; Hatchling; PEP 621; Python standard-library `argparse`, `ast`, `importlib.metadata`, and `tomllib`; pytest; pytest-cov; Ruff; strict mypy; PowerShell; Git.

## Global Constraints

- Treat `docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md` at commit `4bbf58a7cb46b63e925ecd7fc00c9c88141d88fe` as the normative architecture.
- Treat `docs/decisions/0001-gitnexus-development-tooling.md` at commit `9db208c902ab92be615fa4494f7a4bf7810d7768` as the approved developer-tooling boundary.
- Operate on Windows with CPython `>=3.12,<3.13`; do not add a WSL requirement.
- Use `uv` for dependency and virtual-environment management, Hatchling for builds, and a `src` package layout.
- Configure `uv` to require manual Python downloads and to build without isolation from the already-synchronized locked development environment.
- Name the distribution `crypto-trading-lab`, the import package `crypto_lab`, and the initial version `0.1.0`.
- Keep `[project].dependencies` empty and create no optional runtime dependency group.
- Limit development dependencies to Hatchling, pytest, pytest-cov, Ruff, and mypy.
- Use standard-library `argparse` for the version/help-only CLI and `importlib.metadata` as the sole Python source of the installed version.
- Use Ruff with rules `E`, `F`, `I`, `UP`, `B`, `S`, `DTZ`, `PT`, and `RUF`; ignore `S101` only below `tests/`.
- Run mypy in strict mode over `src` and `tests`.
- Enforce the domain import boundary with a typed, tested standard-library AST scanner; do not add import-linter.
- Normalize repository text deterministically to LF and use PowerShell for repository automation.
- Use red-green-refactor for every production Python behavior. No production Python behavior is exempt.
- Do not add pre-commit, hosted CI, GitHub workflows, Docker, a WSL dependency, GitNexus installation/configuration, custom Skills, schemas, databases, runtime directories, or engine folders.
- Do not add Binance, CCXT, broker, exchange, network-client, Pydantic, SQLAlchemy, Alembic, Parquet, YAML, LLM, tax, UI, or trading-engine dependencies.
- Do not implement configuration loading, canonical domain types, dataset ingestion, strategies, experiments, adapters, engines, process supervision, persistence, artifacts, paper trading, tax logic, or LLM behavior.
- Ordinary synchronization, focused checks, full verification, lock validation, and package builds must be independently offline: use `uv sync --frozen --offline`, `uv run --no-sync`, `uv lock --check --offline`, and `uv build --offline` as applicable.
- The only non-offline `uv` commands permitted are the exact one-time user-approved Task 2 bootstrap commands `uv lock` and dependency-acquisition `uv sync --frozen`; before the source scaffold exists, that synchronization command must include `--no-install-project`. Never request permanent or unrestricted network access, and never use a bootstrap approval as verification evidence.
- Do not inspect, print, persist, or log ambient environment-variable values, credentials, browser data, credential-store contents, suspected secret contents, or private keys. Application code must not use ambient environment variables for implicit configuration or credentials. The future `AGENTS.md` makes only the reviewed non-secret GitNexus MCP control-variable exception required by ADR 0001; those values remain developer-tool configuration, never application configuration, credentials, or runtime product inputs.
- Keep GitNexus optional and outside product, runtime, build, package, and test dependencies; do not install, configure, or invoke it in Stage 1.
- Run the complete repository verification workflow and review the full diff before a completion claim. Report every skipped check and warning.
- Avoid unrelated edits.

---

## Normative scope and file map

This plan implements only roadmap Stage 1. It creates exactly these files:

```text
.python-version
.editorconfig
.gitignore
AGENTS.md
pyproject.toml
uv.lock
src/crypto_lab/__init__.py
src/crypto_lab/py.typed
src/crypto_lab/domain/__init__.py
src/crypto_lab/strategy/__init__.py
src/crypto_lab/capabilities/__init__.py
src/crypto_lab/adapters/__init__.py
src/crypto_lab/experiments/__init__.py
src/crypto_lab/datasets/__init__.py
src/crypto_lab/artifacts/__init__.py
src/crypto_lab/persistence/__init__.py
src/crypto_lab/process_supervision/__init__.py
src/crypto_lab/configuration/__init__.py
src/crypto_lab/audit/__init__.py
src/crypto_lab/cli/__init__.py
src/crypto_lab/cli/__main__.py
src/crypto_lab/cli/main.py
tests/conftest.py
tests/unit/test_package_layout.py
tests/unit/test_cli.py
tests/architecture/test_domain_import_boundary.py
tests/safety/test_project_dependencies.py
tests/safety/test_forbidden_runtime_paths.py
scripts/verify.ps1
docs/development/verification.md
```

It modifies only:

```text
README.md
.gitattributes
```

It must not create `.gitnexusrc`, `.gitnexusignore`, `.codex/config.toml`, `.gitnexus/`, `runtime/`, `data/`, `artifacts/`, `logs/`, `runtimes/`, `schemas/`, database files, engine directories, environment files, secret files, custom Skills, or GitHub workflow files.

`uv.lock` is generated text. Do not fabricate or hand-edit it: the exact offline-first generation and approval-gated resolution procedure in Task 2 is its complete construction instruction. Every other created or modified text file has complete content or an exact patch below.

## TDD policy and explicit configuration exceptions

For production Python behavior, every cycle is:

1. Write a focused failing test.
2. Run that test and confirm the stated failure.
3. Add only the minimum implementation.
4. Run the focused test to green.
5. Run the relevant broader suite.
6. Refactor only while green.

The following files are configuration-only exceptions and may be created before a behavioral test: `.python-version`, `.editorconfig`, `.gitignore`, `.gitattributes`, `pyproject.toml`, and generated `uv.lock`. Documentation-only exceptions are `AGENTS.md`, `README.md`, and `docs/development/verification.md`. `scripts/verify.ps1` is repository automation rather than production Python behavior, but it must be executed successfully before acceptance. Tests and `tests/conftest.py` are verification code, not production behavior. Package modules and CLI modules receive no exception.

## Worktree and network transition gates

Task 1 runs in the supplied repository root and is the sole pre-worktree read-only baseline. After Task 1 passes, the execution controller uses the appropriate Superpowers worktree workflow to create an isolated Git worktree branch from local `main` before Task 2 changes a file. The worktree must begin at the same approved commit, have a clean status, and prove before the first edit that `git merge-base HEAD main` equals its current `HEAD`. Do not create a worktree during this planning task.

Task 2 attempts dependency resolution and acquisition from local cache first. If the cache is insufficient, the worker shows the exact `uv lock` and/or dependency-acquisition `uv sync --frozen` command required, using `--no-install-project` while the source scaffold is absent, requests one-time approval for each exact command, and waits. These are the only non-offline commands in Stage 1. Every later development and verification command remains offline or `--no-sync`; a missing local package returns to this Task 2 bootstrap gate. Task 2 never installs CPython, `uv`, GitNexus, or any trading engine automatically.

### Task 1: Environment preflight and baseline evidence

**Files:**
- Create: none
- Modify: none
- Test: none

**Interfaces:**
- Consumes: supplied repository root `C:\Users\59557\Documents\Projects\Crypto_Trading`, Git metadata, Windows Python launcher, and installed `uv` executable
- Produces: read-only evidence that the baseline is clean, the expected repository is selected, CPython 3.12 is available, and `uv` is installed

- [ ] **Step 1: Confirm the working tree is clean**

Run from the supplied repository root:

```powershell
git status --short
```

Expected: exit `0` and no output. If output exists, stop without editing and report it.

- [ ] **Step 2: Capture the recent history**

```powershell
git log -5 --oneline
```

Expected: exit `0`; the history includes the approved architecture and ADR ancestry. Record the five lines as baseline evidence.

- [ ] **Step 3: Confirm the repository root**

```powershell
git rev-parse --show-toplevel
```

Expected: exit `0` and the resolved supplied repository path. If the path differs, stop without editing.

- [ ] **Step 4: List Windows Python launcher registrations**

```powershell
py -0p
```

Expected: exit `0` and a registration for CPython 3.12. This command is evidence only; do not install a missing interpreter.

- [ ] **Step 5: Verify the required interpreter**

```powershell
py -3.12 --version
```

Expected: exit `0` and a `Python 3.12.x` version. If it is missing or resolves outside Python 3.12, stop without editing and report the exact output.

- [ ] **Step 6: Verify `uv`**

```powershell
uv --version
```

Expected: exit `0` and an installed `uv` version. If missing, stop without editing and report the exact error. Do not install or update it.

**Focused verification:** The six commands above, with their exit codes and outputs recorded.

**Broader verification:** None; the six listed commands are the entire allowed preflight surface.

**Commit:** No commit command or commit message is permitted. This task is read-only, and an empty preflight commit would violate the no-empty-commit rule.

**Post-task transition:** After all checks pass, create the isolated worktree branch from local `main` through the required Superpowers workflow, change into it, and rerun `git status --short`, `git log -5 --oneline`, and `git rev-parse --show-toplevel`. The worktree status must be clean, its history must include the same approved commits, and its root must be the new isolated worktree path associated with the supplied repository. Before the first edit, run:

```powershell
$currentWorktreeHead = (git rev-parse HEAD).Trim()
$localMainHead = (git rev-parse main).Trim()
$worktreeMergeBase = (git merge-base HEAD main).Trim()
if (
    [string]::IsNullOrWhiteSpace($currentWorktreeHead) -or
    [string]::IsNullOrWhiteSpace($localMainHead) -or
    [string]::IsNullOrWhiteSpace($worktreeMergeBase)
) {
    throw "Unable to determine the pre-edit worktree commits"
}
if (
    $worktreeMergeBase -ne $currentWorktreeHead -or
    $currentWorktreeHead -ne $localMainHead
) {
    throw "The isolated worktree was not created from the current local main"
}
```

Expected: all three commands exit `0`; the current worktree `HEAD`, local `main`, and their merge base are identical; and no file has yet been edited. Stop if any hash is missing or differs.

### Task 2: Project metadata, uv lock, ignore rules, and quality configuration

**Files:**
- Create: `.python-version`
- Create: `.editorconfig`
- Create: `.gitignore`
- Create: `pyproject.toml`
- Create: `uv.lock` through the exact generator procedure below
- Modify: `.gitattributes`
- Test: lock and cached-environment validation through `uv`, formatting and lint checks through Ruff, Git whitespace checks, and exact-scope status review; mypy, pytest, and Hatchling verification begin after the package scaffold exists in Task 3

**Interfaces:**
- Consumes: CPython 3.12, installed `uv`, the Stage 1 naming/version/dependency decisions, current `README.md`, and the current two-line `.gitattributes`
- Produces: deterministic Python selection, PEP 621 metadata, empty runtime dependency contract, `crypto-lab = "crypto_lab.cli.main:main"` entry point, development dependency lock, quality-tool configuration, and ignore/EOL policy consumed by Tasks 3–6

- [ ] **Step 1: Create `.python-version`**

Create `.python-version` with exactly:

```text
3.12
```

- [ ] **Step 2: Create `.editorconfig`**

Create `.editorconfig` with exactly:

```ini
root = true

[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
indent_style = space
indent_size = 4
trim_trailing_whitespace = true

[*.md]
trim_trailing_whitespace = false

[*.{json,toml,yaml,yml}]
indent_size = 2
```

- [ ] **Step 3: Replace `.gitattributes` with deterministic text normalization**

Apply this exact patch:

```diff
-# Auto detect text files and perform LF normalization
-* text=auto
+# Normalize repository text deterministically.
+* text=auto eol=lf
```

- [ ] **Step 4: Create `.gitignore`**

Create `.gitignore` with exactly:

```gitignore
# Python bytecode
__pycache__/
*.py[cod]
*$py.class

# Local Python and uv state
.venv/
venv/
.uv/
.uv-cache/

# Test, coverage, lint, and type-check caches
.pytest_cache/
.coverage
.coverage.*
htmlcov/
.ruff_cache/
.mypy_cache/

# Package build output
build/
dist/
*.egg-info/

# Editors and operating systems
.idea/
.vscode/
*.swp
*~
.DS_Store
Desktop.ini
Thumbs.db

# Environment and common key or certificate files
.env
.env.*
*.pem
*.key
*.p12
*.pfx

# Local databases
*.sqlite
*.sqlite3
*.db

# Generated Project 1 and future runtime state
/runtime/
/data/
/artifacts/
/logs/
/runtimes/
/.gitnexus/
```

Do not add ignore rules for `.codex/`, `docs/`, `schemas/`, `tests/`, `scripts/`, `uv.lock`, or `.python-version`.

- [ ] **Step 5: Create `pyproject.toml`**

Create `pyproject.toml` with exactly:

```toml
[build-system]
requires = ["hatchling>=1.27,<2"]
build-backend = "hatchling.build"

[project]
name = "crypto-trading-lab"
version = "0.1.0"
description = "Local engine-neutral cryptocurrency research foundation"
readme = "README.md"
requires-python = ">=3.12,<3.13"
dependencies = []

[project.scripts]
crypto-lab = "crypto_lab.cli.main:main"

[dependency-groups]
dev = [
  "hatchling>=1.27,<2",
  "mypy>=1.15,<2",
  "pytest>=8.3,<9",
  "pytest-cov>=6,<7",
  "ruff>=0.11,<1",
]

[tool.uv]
no-build-isolation = true
python-downloads = "manual"

[tool.hatch.build.targets.wheel]
packages = ["src/crypto_lab"]

[tool.hatch.build.targets.sdist]
include = [
  "/src",
  "/tests",
  "/scripts",
  "/docs/development",
  "/README.md",
  "/AGENTS.md",
  "/pyproject.toml",
  "/uv.lock",
]

[tool.ruff]
target-version = "py312"
line-length = 88
src = ["src", "tests"]

[tool.ruff.format]
line-ending = "lf"

[tool.ruff.lint]
select = ["B", "DTZ", "E", "F", "I", "PT", "RUF", "S", "UP"]

[tool.ruff.lint.per-file-ignores]
"tests/**/*.py" = ["S101"]

[tool.ruff.lint.flake8-pytest-style]
fixture-parentheses = false

[tool.mypy]
python_version = "3.12"
strict = true
files = ["src", "tests"]

[tool.pytest.ini_options]
addopts = [
  "--strict-config",
  "--strict-markers",
  "--cov=crypto_lab",
  "--cov-branch",
  "--cov-report=term-missing",
  "--cov-fail-under=90",
]
testpaths = ["tests"]

[tool.coverage.run]
branch = true
source = ["crypto_lab"]

[tool.coverage.report]
fail_under = 90
show_missing = true
skip_covered = true
```

The bounded version ranges establish the Stage 1 compatibility floor; the generated `uv.lock` supplies exact resolved project and development versions. Hatchling appears in both the build-system requirements and the development group intentionally. `no-build-isolation = true` makes `uv build --offline` use the Hatchling version already installed by the offline frozen development sync instead of resolving an isolated build environment, and `python-downloads = "manual"` forbids automatic managed-Python downloads. No dependency above belongs to `[project].dependencies`.

- [ ] **Step 6: Attempt complete local lock generation first**

Run:

```powershell
uv lock --offline
```

Expected when all required package metadata is cached: exit `0` and a generated `uv.lock`.

If the command reports missing cached packages, show the user the exact prospective network commands:

```powershell
uv lock
uv sync --frozen --no-install-project
```

Request one-time approval for those displayed commands only. Do not run either command before approval, do not broaden approval, and do not alter network policy. If the offline command fails for a reason other than missing cached packages, stop and diagnose that local configuration error without requesting network access.

- [ ] **Step 7: Complete and validate `uv.lock` through the permitted path**

If Step 6 succeeded, do not resolve again. If cache content was missing and the user approved the exact network commands, run:

```powershell
uv lock
```

Then run:

```powershell
uv lock --check --offline
```

Expected: exit `0` without network access and a generated `uv.lock` that pins the project and development dependencies, including the Hatchling version later used without build isolation. Do not hand-edit the generated file.

- [ ] **Step 8: Probe and synchronize development tools strictly from the lock**

```powershell
uv sync --frozen --offline --no-install-project
```

Expected when all required wheels are cached: exit `0`, no lockfile change, and no dependency outside the locked Stage 1 development set. `--no-install-project` is required here because `src/crypto_lab` is intentionally absent until Task 3.

If this offline probe reports a missing cached wheel and the earlier one-time approval did not cover synchronization, show this exact prospective network command and request one-time approval for it:

```powershell
uv sync --frozen --no-install-project
```

After approval, run that exact command once. Once Task 3 creates `src/crypto_lab`, ordinary synchronization uses `uv sync --frozen --offline` so the project itself is installed from the unchanged lock without network access. If any later offline synchronization reports missing local content, stop and return to this approval gate; do not make a verification command non-offline.

- [ ] **Step 9: Check configuration syntax and the pre-code baseline**

Run:

```powershell
uv run --no-sync ruff format --check .
uv run --no-sync ruff check .
uv lock --check --offline
git diff --check
git status --short
```

Expected: every command exits `0`; status lists exactly `.python-version`, `.editorconfig`, `.gitattributes`, `.gitignore`, `pyproject.toml`, and `uv.lock` as intended Task 2 changes. Source type checking and package building begin only after Task 3 creates the scaffold.

**Focused verification:** `uv lock --offline` or the explicitly approved one-time `uv lock`, `uv lock --check --offline`, the offline-first no-project synchronization, exact status review, and `git diff --check`. The only possible non-offline synchronization is the separately approved one-time `uv sync --frozen --no-install-project`; it is bootstrap, not verification.

**Broader verification:** Ruff configuration checks, lock consistency, exact status review, and whitespace validation.

**Commit:**

```powershell
git add .python-version .editorconfig .gitattributes .gitignore pyproject.toml uv.lock
git diff --cached --check
git commit -m "chore: initialize python project foundation"
```

Expected: one commit containing exactly the six named foundation paths and no source, test, documentation, runtime, or GitNexus file.

### Task 3: Package scaffold and version-only CLI using TDD

**Files:**
- Create: `src/crypto_lab/__init__.py`
- Create: `src/crypto_lab/py.typed`
- Create: `src/crypto_lab/domain/__init__.py`
- Create: `src/crypto_lab/strategy/__init__.py`
- Create: `src/crypto_lab/capabilities/__init__.py`
- Create: `src/crypto_lab/adapters/__init__.py`
- Create: `src/crypto_lab/experiments/__init__.py`
- Create: `src/crypto_lab/datasets/__init__.py`
- Create: `src/crypto_lab/artifacts/__init__.py`
- Create: `src/crypto_lab/persistence/__init__.py`
- Create: `src/crypto_lab/process_supervision/__init__.py`
- Create: `src/crypto_lab/configuration/__init__.py`
- Create: `src/crypto_lab/audit/__init__.py`
- Create: `src/crypto_lab/cli/__init__.py`
- Create: `src/crypto_lab/cli/__main__.py`
- Create: `src/crypto_lab/cli/main.py`
- Create: `tests/conftest.py`
- Create: `tests/unit/test_package_layout.py`
- Create: `tests/unit/test_cli.py`

**Interfaces:**
- Consumes: locked project metadata from Task 2, installed-distribution metadata name `crypto-trading-lab`, and Python module execution semantics
- Produces: side-effect-free `crypto_lab` packages, PEP 561 marker `py.typed`, `build_parser() -> argparse.ArgumentParser`, `main(argv: Sequence[str] | None = None) -> int`, console command `crypto-lab`, and module command `python -m crypto_lab.cli`

- [ ] **Step 1: Create the shared repository-root fixture**

Create `tests/conftest.py` with exactly:

```python
"""Shared pytest fixtures for repository checks."""

from pathlib import Path

import pytest


@pytest.fixture
def repository_root() -> Path:
    """Return the checked-out repository root."""
    return Path(__file__).resolve().parents[1]
```

- [ ] **Step 2: Write the package-layout tests before the package exists**

Create `tests/unit/test_package_layout.py` with exactly:

```python
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
    "crypto_lab.strategy",
    "crypto_lab.capabilities",
    "crypto_lab.adapters",
    "crypto_lab.experiments",
    "crypto_lab.datasets",
    "crypto_lab.artifacts",
    "crypto_lab.persistence",
    "crypto_lab.process_supervision",
    "crypto_lab.configuration",
    "crypto_lab.audit",
    "crypto_lab.cli",
    "crypto_lab.cli.main",
    "crypto_lab.cli.__main__",
)
_IMPORT_SENTINEL = "IMPORT_GUARDS_OK"
_IMPORT_PROBE = """
from __future__ import annotations

import importlib
import os
import socket
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import NoReturn


def _unexpected_operation(*args: object, **kwargs: object) -> NoReturn:
    del args, kwargs
    raise AssertionError("package import attempted a forbidden side effect")


os.getenv = _unexpected_operation
socket.create_connection = _unexpected_operation
subprocess.Popen = _unexpected_operation
urllib.request.urlopen = _unexpected_operation
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
        timeout=10,
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
```

The fresh child uses the current `sys.executable`, Python isolated mode, an argument array, and `tmp_path` as its working directory. It installs the listed guards before importing any planned project module, and `-B` suppresses ordinary bytecode-cache writes. This is a bounded fresh-process observable-side-effect guard for the named calls, output streams, and paths below `tmp_path`; it is combined with exact source review and the architecture constraints, not presented as detection of every possible operating-system side effect.

- [ ] **Step 3: Run the package test and confirm red**

```powershell
uv run --no-sync pytest -o addopts="" tests/unit/test_package_layout.py -q
```

Expected: exit `1`. The isolated child fails on its first `crypto_lab` import because the package does not exist; the separate distribution-metadata and `py.typed` tests also fail while the project is absent. A pass means an unrelated package is shadowing the intended project and must be investigated before continuing.

- [ ] **Step 4: Create the package directories with exact module contents**

Create each listed `__init__.py` with exactly the corresponding one-line docstring and a final newline:

| File | Exact content |
|---|---|
| `src/crypto_lab/__init__.py` | `"""Engine-neutral local cryptocurrency research foundation."""` |
| `src/crypto_lab/domain/__init__.py` | `"""Canonical domain boundary for the research core."""` |
| `src/crypto_lab/strategy/__init__.py` | `"""Portable strategy boundary for the research core."""` |
| `src/crypto_lab/capabilities/__init__.py` | `"""Capability and compatibility boundary for the research core."""` |
| `src/crypto_lab/adapters/__init__.py` | `"""Adapter protocol boundary for the research core."""` |
| `src/crypto_lab/experiments/__init__.py` | `"""Experiment orchestration boundary for the research core."""` |
| `src/crypto_lab/datasets/__init__.py` | `"""Dataset metadata boundary for the research core."""` |
| `src/crypto_lab/artifacts/__init__.py` | `"""Artifact lifecycle boundary for the research core."""` |
| `src/crypto_lab/persistence/__init__.py` | `"""Persistence implementation boundary for the research core."""` |
| `src/crypto_lab/process_supervision/__init__.py` | `"""Process supervision boundary for the research core."""` |
| `src/crypto_lab/configuration/__init__.py` | `"""Configuration boundary for the research core."""` |
| `src/crypto_lab/audit/__init__.py` | `"""Diagnostics and audit boundary for the research core."""` |
| `src/crypto_lab/cli/__init__.py` | `"""Command-line composition boundary for the research core."""` |

Create `src/crypto_lab/py.typed` as an empty, zero-byte marker file. Do not add imports, constants, classes, functions, service objects, or runtime initialization to any of these files.

- [ ] **Step 5: Install the newly created project from the frozen lock**

```powershell
uv sync --frozen --offline
```

Expected: exit `0`; the partial package scaffold is installed from the unchanged lock with no network access and no new dependency. If local locked content is missing, stop and return to the Task 2 approval gate.

- [ ] **Step 6: Write the CLI tests before the CLI modules exist**

Create `tests/unit/test_cli.py` with exactly:

```python
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
    result = _run_local_command(
        [sys.executable, "-m", "crypto_lab.cli", "--version"]
    )

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
```

- [ ] **Step 7: Run the CLI test and confirm red**

```powershell
uv run --no-sync pytest -o addopts="" tests/unit/test_cli.py -q
```

Expected: collection fails with `ModuleNotFoundError` for `crypto_lab.cli.main` because CLI production behavior has not been created.

- [ ] **Step 8: Add the minimum CLI implementation**

Create `src/crypto_lab/cli/main.py` with exactly:

```python
"""Version and help command for the local research foundation."""

from __future__ import annotations

import argparse
import importlib.metadata
from collections.abc import Sequence

_DISTRIBUTION_NAME = "crypto-trading-lab"


def build_parser() -> argparse.ArgumentParser:
    """Build the Stage 1 command parser."""
    parser = argparse.ArgumentParser(
        prog="crypto-lab",
        description="Local engine-neutral cryptocurrency research foundation.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {importlib.metadata.version(_DISTRIBUTION_NAME)}",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the version/help-only Stage 1 command line."""
    parser = build_parser()
    parser.parse_args(argv)
    parser.print_help()
    return 0
```

Create `src/crypto_lab/cli/__main__.py` with exactly:

```python
"""Execute the crypto_lab command-line package."""

from crypto_lab.cli.main import main

if __name__ == "__main__":
    raise SystemExit(main())
```

Do not place `0.1.0` or another version constant in Python source. Do not add subcommands.

- [ ] **Step 9: Refresh the editable install without changing the lock**

```powershell
uv sync --frozen --offline
```

Expected: exit `0` without network access, `uv.lock` unchanged, and the console entry point installed. If local locked content is missing, stop and return to Task 2 rather than weakening the command.

- [ ] **Step 10: Run focused package and CLI tests and confirm both green**

```powershell
uv run --no-sync pytest -o addopts="" tests/unit/test_package_layout.py tests/unit/test_cli.py -q
```

Expected: all tests pass. This is the fresh-process import guard's first permitted green run because the complete package and both CLI implementation modules now exist. The child imports all fifteen planned modules under its guards, prints exactly `IMPORT_GUARDS_OK` plus one newline, emits no stderr, and creates no path below `tmp_path`. Both command forms print exactly `crypto-lab 0.1.0`, no-argument help exits `0`, and unknown arguments exit `2`.

- [ ] **Step 11: Run the broader source checks**

```powershell
uv run --no-sync ruff format --check src tests/unit tests/conftest.py
uv run --no-sync ruff check src tests/unit tests/conftest.py
uv run --no-sync mypy src tests
uv run --no-sync pytest
uv build --offline
git diff --check
```

Expected: every command exits `0` without network access; the full pytest command, not the focused `addopts`-overridden slices, proves branch coverage of at least 90 percent; the source-level PEP 561 marker test passes; and the sdist and wheel build offline without introducing a runtime dependency. Review the package modules directly alongside the bounded fresh-process guard; the guard is not an operating-system sandbox or proof against every possible import side effect.

**Focused verification:** The initial package-layout command is red because the package does not exist, the CLI command is red before the CLI modules exist, and the combined command turns both green only after the complete package and CLI scaffold exists. Focused runs disable repository coverage options and therefore do not establish the coverage threshold.

**Broader verification:** No-sync Ruff format/lint, strict mypy, all unit tests with coverage, offline package build, exact source review, and whitespace check.

**Commit:**

```powershell
git add src/crypto_lab tests/conftest.py tests/unit/test_package_layout.py tests/unit/test_cli.py
git diff --cached --check
git commit -m "feat: add package scaffold and version command"
```

Expected: one commit containing only the package scaffold, CLI, PEP 561 marker, shared fixture, and unit tests.

### Task 4: Architecture and safety guardrails using TDD

**Files:**
- Create: `tests/architecture/test_domain_import_boundary.py`
- Create: `tests/safety/test_project_dependencies.py`
- Create: `tests/safety/test_forbidden_runtime_paths.py`

**Interfaces:**
- Consumes: `repository_root: Path`, `src/crypto_lab/domain`, `pyproject.toml`, `.gitignore`, and local Git metadata
- Produces: test-only `ImportViolation`, `find_domain_import_violations(domain_root: Path) -> tuple[ImportViolation, ...]`, `RuntimeDependency`, `runtime_dependencies(document: Mapping[str, object]) -> tuple[RuntimeDependency, ...]`, `prohibited_runtime_dependencies(dependencies: tuple[RuntimeDependency, ...]) -> tuple[RuntimeDependency, ...]`, and `is_forbidden_runtime_path(relative_path: str) -> bool`

These interfaces remain inside tests and do not become product APIs.

- [ ] **Step 1: Write architecture meta-tests around deliberately red scanner functions**

Create `tests/architecture/test_domain_import_boundary.py` with exactly this red test state:

```python
"""Enforce the domain package import boundary with the standard-library AST."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from importlib.util import resolve_name
from pathlib import Path

import pytest

_PROHIBITED_PROJECT_PACKAGES: tuple[str, ...] = (
    "crypto_lab.strategy",
    "crypto_lab.capabilities",
    "crypto_lab.adapters",
    "crypto_lab.experiments",
    "crypto_lab.datasets",
    "crypto_lab.artifacts",
    "crypto_lab.persistence",
    "crypto_lab.process_supervision",
    "crypto_lab.configuration",
    "crypto_lab.audit",
    "crypto_lab.cli",
)


@dataclass(frozen=True, order=True, slots=True)
class ImportViolation:
    """One prohibited import found in a domain source file."""

    relative_path: str
    line_number: int
    imported_name: str


def _source_package_name(source_path: Path, domain_root: Path) -> str:
    relative_parts = list(source_path.relative_to(domain_root).with_suffix("").parts)
    relative_parts.pop()
    return ".".join(("crypto_lab", "domain", *relative_parts))


def _imported_names(
    node: ast.Import | ast.ImportFrom,
    package_name: str,
) -> tuple[str, ...]:
    del node, package_name
    raise NotImplementedError("scanner import extraction is not present in the red state")


def _is_prohibited(imported_name: str) -> bool:
    del imported_name
    raise NotImplementedError("boundary matching is not present in the red state")


def find_domain_import_violations(domain_root: Path) -> tuple[ImportViolation, ...]:
    del domain_root
    raise NotImplementedError("domain scanning is not present in the red state")


def _write_domain_source(tmp_path: Path, source: str) -> Path:
    domain_root = tmp_path / "src" / "crypto_lab" / "domain"
    domain_root.mkdir(parents=True)
    (domain_root / "sample.py").write_text(source, encoding="utf-8")
    return domain_root


@pytest.mark.parametrize("package_name", _PROHIBITED_PROJECT_PACKAGES)
def test_scanner_rejects_every_prohibited_package(
    tmp_path: Path,
    package_name: str,
) -> None:
    domain_root = _write_domain_source(tmp_path, f"import {package_name}\n")

    violations = find_domain_import_violations(domain_root)

    assert tuple(item.imported_name for item in violations) == (package_name,)


@pytest.mark.parametrize(
    ("statement", "expected_name"),
    [
        ("import crypto_lab.persistence", "crypto_lab.persistence"),
        (
            "import crypto_lab.persistence.repositories",
            "crypto_lab.persistence.repositories",
        ),
        ("from crypto_lab import persistence", "crypto_lab.persistence"),
        (
            "from crypto_lab.persistence import repositories",
            "crypto_lab.persistence",
        ),
        ("import crypto_lab.persistence as storage", "crypto_lab.persistence"),
        (
            "import crypto_lab.persistence.repositories as repositories",
            "crypto_lab.persistence.repositories",
        ),
        ("from crypto_lab import persistence as storage", "crypto_lab.persistence"),
        (
            "from crypto_lab.persistence import repositories as repositories",
            "crypto_lab.persistence",
        ),
    ],
)
def test_scanner_rejects_each_absolute_import_shape(
    tmp_path: Path,
    statement: str,
    expected_name: str,
) -> None:
    domain_root = _write_domain_source(tmp_path, f"{statement}\n")

    violations = find_domain_import_violations(domain_root)

    assert tuple(item.imported_name for item in violations) == (expected_name,)


def test_scanner_rejects_relative_import_that_escapes_domain(tmp_path: Path) -> None:
    domain_root = _write_domain_source(tmp_path, "from .. import persistence\n")

    violations = find_domain_import_violations(domain_root)

    assert tuple(item.imported_name for item in violations) == (
        "crypto_lab.persistence",
    )


def test_scanner_recurses_into_nested_domain_packages(tmp_path: Path) -> None:
    domain_root = tmp_path / "src" / "crypto_lab" / "domain"
    nested_root = domain_root / "nested"
    nested_root.mkdir(parents=True)
    (nested_root / "sample.py").write_text(
        "import crypto_lab.persistence\n",
        encoding="utf-8",
    )

    violations = find_domain_import_violations(domain_root)

    assert violations == (
        ImportViolation(
            relative_path="nested/sample.py",
            line_number=1,
            imported_name="crypto_lab.persistence",
        ),
    )


def test_scanner_ignores_non_import_text_and_allowed_imports(tmp_path: Path) -> None:
    domain_root = _write_domain_source(
        tmp_path,
        '''"""import crypto_lab.persistence inside a string."""
# from crypto_lab import persistence
import datetime
import external_library
from . import sibling
from .nested import helper
''',
    )

    assert find_domain_import_violations(domain_root) == ()


def test_repository_domain_package_has_no_prohibited_imports(
    repository_root: Path,
) -> None:
    domain_root = repository_root / "src" / "crypto_lab" / "domain"

    assert find_domain_import_violations(domain_root) == ()
```

- [ ] **Step 2: Run the architecture slice and confirm red**

```powershell
uv run --no-sync pytest -o addopts="" tests/architecture/test_domain_import_boundary.py -q
```

Expected: exit `1`; the first scanner exercise raises `NotImplementedError` with the red-state message. The coverage override applies only to this focused cycle.

- [ ] **Step 3: Replace the red scanner functions with the typed AST implementation**

Apply this exact patch:

```diff
 def _imported_names(
     node: ast.Import | ast.ImportFrom,
     package_name: str,
 ) -> tuple[str, ...]:
-    del node, package_name
-    raise NotImplementedError("scanner import extraction is not present in the red state")
+    if isinstance(node, ast.Import):
+        return tuple(alias.name for alias in node.names)
+
+    imported_base = node.module or ""
+    if node.level > 0:
+        imported_base = resolve_name("." * node.level + imported_base, package_name)
+
+    if imported_base == "crypto_lab":
+        return tuple(f"crypto_lab.{alias.name}" for alias in node.names)
+    return (imported_base,)


 def _is_prohibited(imported_name: str) -> bool:
-    del imported_name
-    raise NotImplementedError("boundary matching is not present in the red state")
+    return any(
+        imported_name == package_name
+        or imported_name.startswith(f"{package_name}.")
+        for package_name in _PROHIBITED_PROJECT_PACKAGES
+    )


 def find_domain_import_violations(domain_root: Path) -> tuple[ImportViolation, ...]:
-    del domain_root
-    raise NotImplementedError("domain scanning is not present in the red state")
+    """Return prohibited imports below the supplied domain package root."""
+    violations: list[ImportViolation] = []
+    source_paths = sorted(domain_root.rglob("*.py"), key=lambda path: path.as_posix())
+
+    for source_path in source_paths:
+        source = source_path.read_text(encoding="utf-8")
+        syntax_tree = ast.parse(source, filename=str(source_path))
+        package_name = _source_package_name(source_path, domain_root)
+        for node in ast.walk(syntax_tree):
+            if not isinstance(node, (ast.Import, ast.ImportFrom)):
+                continue
+            for imported_name in _imported_names(node, package_name):
+                if _is_prohibited(imported_name):
+                    violations.append(
+                        ImportViolation(
+                            relative_path=source_path.relative_to(
+                                domain_root
+                            ).as_posix(),
+                            line_number=node.lineno,
+                            imported_name=imported_name,
+                        )
+                    )
+
+    return tuple(sorted(violations))
```

This resolves relative imports in package context. It allows imports that remain below `crypto_lab.domain` but catches `from .. import persistence`.

- [ ] **Step 4: Run the architecture slice and confirm green**

```powershell
uv run --no-sync pytest -o addopts="" tests/architecture/test_domain_import_boundary.py -q
```

Expected: exit `0`; all eleven prohibited roots, four required import shapes, aliased forms, parent-relative escape, safe relative imports, comments, strings, standard-library imports, and third-party imports behave as specified.

- [ ] **Step 5: Write dependency safety tests around deliberately red classifiers**

Create `tests/safety/test_project_dependencies.py` with exactly this red test state:

```python
"""Keep every Stage 1 runtime dependency group empty and engine-free."""

from __future__ import annotations

import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest

_PROHIBITED_FAMILIES: tuple[str, ...] = (
    "vectorbt",
    "freqtrade",
    "nautilus-trader",
    "jesse",
    "octobot",
    "hummingbot",
    "lean",
    "quantconnect",
    "binance",
    "ccxt",
    "alpaca",
    "ib-insync",
    "zerodha",
    "kiteconnect",
    "upstox",
    "openalgo",
    "requests",
    "httpx",
    "aiohttp",
    "websocket",
    "websockets",
    "pydantic",
    "sqlalchemy",
    "alembic",
    "pyarrow",
    "pandas",
    "polars",
    "numpy",
    "ollama",
    "openai",
)
_REQUIREMENT_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


@dataclass(frozen=True, order=True, slots=True)
class RuntimeDependency:
    """One dependency declared in a PEP 621 runtime group."""

    group: str
    requirement: str


def _mapping(value: object, location: str) -> Mapping[str, object]:
    assert isinstance(value, dict), f"{location} must be a table"
    assert all(isinstance(key, str) for key in value), (
        f"{location} keys must be strings"
    )
    return cast(dict[str, object], value)


def _string_list(value: object, location: str) -> tuple[str, ...]:
    assert isinstance(value, list), f"{location} must be an array"
    assert all(isinstance(item, str) for item in value), (
        f"{location} entries must be strings"
    )
    return tuple(cast(list[str], value))


def _load_pyproject(path: Path) -> Mapping[str, object]:
    return cast(dict[str, object], tomllib.loads(path.read_text(encoding="utf-8")))


def runtime_dependencies(
    document: Mapping[str, object],
) -> tuple[RuntimeDependency, ...]:
    del document
    raise NotImplementedError("runtime dependency extraction is absent in the red state")


def _normalized_requirement_name(requirement: str) -> str:
    del requirement
    raise NotImplementedError("requirement normalization is absent in the red state")


def prohibited_runtime_dependencies(
    dependencies: tuple[RuntimeDependency, ...],
) -> tuple[RuntimeDependency, ...]:
    del dependencies
    raise NotImplementedError("prohibited matching is absent in the red state")


def test_project_runtime_dependencies_are_empty(repository_root: Path) -> None:
    document = _load_pyproject(repository_root / "pyproject.toml")

    assert runtime_dependencies(document) == ()


def test_project_has_no_prohibited_runtime_dependency(repository_root: Path) -> None:
    document = _load_pyproject(repository_root / "pyproject.toml")

    assert prohibited_runtime_dependencies(runtime_dependencies(document)) == ()


def test_optional_runtime_dependencies_are_extracted_and_rejected() -> None:
    document: dict[str, object] = {
        "project": {
            "dependencies": [],
            "optional-dependencies": {
                "exchange": ["Binance.Client>=1"],
            },
        }
    }
    expected = (
        RuntimeDependency(
            group="project.optional-dependencies.exchange",
            requirement="Binance.Client>=1",
        ),
    )

    extracted = runtime_dependencies(document)

    assert extracted == expected
    assert prohibited_runtime_dependencies(extracted) == expected


@pytest.mark.parametrize("family", _PROHIBITED_FAMILIES)
def test_matcher_rejects_every_prohibited_family(family: str) -> None:
    dependency = RuntimeDependency(
        group="project.dependencies",
        requirement=f"vendor-{family}-client>=1",
    )

    assert prohibited_runtime_dependencies((dependency,)) == (dependency,)


@pytest.mark.parametrize(
    ("requirement", "normalized"),
    [
        ("nautilus_trader>=1", "nautilus-trader"),
        ("IB.Insync[all]>=1; python_version >= '3.12'", "ib-insync"),
        ("requests @ https://invalid.example/package.whl", "requests"),
    ],
)
def test_requirement_name_normalization(
    requirement: str,
    normalized: str,
) -> None:
    assert _normalized_requirement_name(requirement) == normalized


def test_development_and_build_dependencies_are_not_runtime_dependencies() -> None:
    document: dict[str, object] = {
        "project": {"dependencies": []},
        "dependency-groups": {
            "dev": ["hatchling", "pytest", "pytest-cov", "ruff", "mypy"]
        },
        "build-system": {"requires": ["hatchling"]},
    }

    assert runtime_dependencies(document) == ()


def test_required_development_tools_are_declared(repository_root: Path) -> None:
    document = _load_pyproject(repository_root / "pyproject.toml")
    groups = _mapping(document.get("dependency-groups"), "dependency-groups")
    dev_requirements = _string_list(groups.get("dev"), "dependency-groups.dev")
    declared = {_normalized_requirement_name(item) for item in dev_requirements}

    assert declared == {"hatchling", "mypy", "pytest", "pytest-cov", "ruff"}
```

- [ ] **Step 6: Run the dependency slice and confirm red**

```powershell
uv run --no-sync pytest -o addopts="" tests/safety/test_project_dependencies.py -q
```

Expected: exit `1`; runtime extraction raises the stated `NotImplementedError`.

- [ ] **Step 7: Replace the red dependency classifiers with strict TOML logic**

Apply this exact patch:

```diff
 def runtime_dependencies(
     document: Mapping[str, object],
 ) -> tuple[RuntimeDependency, ...]:
-    del document
-    raise NotImplementedError("runtime dependency extraction is absent in the red state")
+    """Return PEP 621 default and optional runtime dependencies only."""
+    project = _mapping(document.get("project"), "[project]")
+    dependencies = [
+        RuntimeDependency(
+            group="project.dependencies",
+            requirement=requirement,
+        )
+        for requirement in _string_list(
+            project.get("dependencies"),
+            "project.dependencies",
+        )
+    ]
+    optional_groups = _mapping(
+        project.get("optional-dependencies", {}),
+        "project.optional-dependencies",
+    )
+    for group_name in sorted(optional_groups):
+        requirements = _string_list(
+            optional_groups[group_name],
+            f"project.optional-dependencies.{group_name}",
+        )
+        dependencies.extend(
+            RuntimeDependency(
+                group=f"project.optional-dependencies.{group_name}",
+                requirement=requirement,
+            )
+            for requirement in requirements
+        )
+    return tuple(dependencies)


 def _normalized_requirement_name(requirement: str) -> str:
-    del requirement
-    raise NotImplementedError("requirement normalization is absent in the red state")
+    match = _REQUIREMENT_NAME.match(requirement)
+    assert match is not None, f"Cannot parse dependency name from {requirement!r}"
+    return re.sub(r"[-_.]+", "-", match.group(1)).lower()


 def prohibited_runtime_dependencies(
     dependencies: tuple[RuntimeDependency, ...],
 ) -> tuple[RuntimeDependency, ...]:
-    del dependencies
-    raise NotImplementedError("prohibited matching is absent in the red state")
+    """Return runtime dependencies containing a prohibited normalized family."""
+    return tuple(
+        sorted(
+            dependency
+            for dependency in dependencies
+            if any(
+                family in _normalized_requirement_name(dependency.requirement)
+                for family in _PROHIBITED_FAMILIES
+            )
+        )
+    )
```

The extractor reads `[project].dependencies` and every `[project.optional-dependencies]` group. It deliberately excludes `[dependency-groups]` and `[build-system]`, which are development/build inputs rather than project runtime dependencies.

- [ ] **Step 8: Run the dependency slice and confirm green**

```powershell
uv run --no-sync pytest -o addopts="" tests/safety/test_project_dependencies.py -q
```

Expected: exit `0`; runtime groups are empty, every prohibited normalized family is detected by the synthetic cases, optional runtime groups are included by the extractor, and the exact development tools are present without being classified as runtime dependencies.

- [ ] **Step 9: Write forbidden-path tests around deliberately red helpers**

Create `tests/safety/test_forbidden_runtime_paths.py` with exactly this red test state:

```python
"""Keep generated runtime roots and secret filenames out of version control."""

from __future__ import annotations

import fnmatch
import shutil
import subprocess
from pathlib import Path, PurePosixPath

import pytest

_FORBIDDEN_ROOT_DIRECTORIES = frozenset(
    {
        "runtime",
        "data",
        "artifacts",
        "logs",
        "runtimes",
        ".gitnexus",
        ".venv",
    }
)
_FORBIDDEN_FILE_PATTERNS: tuple[str, ...] = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.sqlite",
    "*.sqlite3",
    "*.db",
)
_IGNORE_PROBES: tuple[str, ...] = (
    "runtime/.stage1-ignore-probe",
    "data/.stage1-ignore-probe",
    "artifacts/.stage1-ignore-probe",
    "logs/.stage1-ignore-probe",
    "runtimes/.stage1-ignore-probe",
    ".gitnexus/.stage1-ignore-probe",
    ".venv/.stage1-ignore-probe",
    ".env",
    ".env.local",
    "stage1.pem",
    "stage1.key",
    "stage1.p12",
    "stage1.pfx",
    "stage1.sqlite",
    "stage1.sqlite3",
    "stage1.db",
)
_MUST_REMAIN_VISIBLE_PROBES: tuple[str, ...] = (
    ".codex/config.toml",
    "docs/stage1-visible-probe.md",
    "schemas/stage1-visible-probe.json",
    "tests/stage1_visible_probe.py",
    "scripts/stage1-visible-probe.ps1",
    "uv.lock",
    ".python-version",
    "src/crypto_lab/artifacts/stage1_visible_probe.py",
)


def is_forbidden_runtime_path(relative_path: str) -> bool:
    del relative_path
    raise NotImplementedError("path classification is absent in the red state")


def _run_git(
    repository_root: Path,
    *arguments: str,
) -> subprocess.CompletedProcess[str]:
    del repository_root, arguments
    raise NotImplementedError("Git path inspection is absent in the red state")


@pytest.mark.parametrize("relative_path", _IGNORE_PROBES)
def test_classifier_covers_each_required_path(relative_path: str) -> None:
    assert is_forbidden_runtime_path(relative_path)


@pytest.mark.parametrize("relative_path", _IGNORE_PROBES)
def test_each_required_path_is_git_ignored(
    repository_root: Path,
    relative_path: str,
) -> None:
    completed = _run_git(
        repository_root,
        "check-ignore",
        "--quiet",
        "--no-index",
        "--",
        relative_path,
    )

    assert completed.returncode == 0, (
        f"Expected {relative_path!r} to be ignored; git stderr: "
        f"{completed.stderr!r}"
    )


@pytest.mark.parametrize("relative_path", _MUST_REMAIN_VISIBLE_PROBES)
def test_source_and_control_paths_are_not_git_ignored(
    repository_root: Path,
    relative_path: str,
) -> None:
    completed = _run_git(
        repository_root,
        "check-ignore",
        "--quiet",
        "--no-index",
        "--",
        relative_path,
    )

    assert completed.returncode == 1, (
        f"Expected {relative_path!r} to remain visible; git stderr: "
        f"{completed.stderr!r}"
    )


def test_repository_has_no_tracked_or_unignored_forbidden_path(
    repository_root: Path,
) -> None:
    completed = _run_git(
        repository_root,
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
    )
    assert completed.returncode == 0, completed.stderr

    visible_paths = tuple(path for path in completed.stdout.split("\0") if path)
    forbidden_paths = tuple(
        sorted(path for path in visible_paths if is_forbidden_runtime_path(path))
    )
    assert forbidden_paths == ()
```

- [ ] **Step 10: Run the forbidden-path slice and confirm red**

```powershell
uv run --no-sync pytest -o addopts="" tests/safety/test_forbidden_runtime_paths.py -q
```

Expected: exit `1`; path classification raises the stated `NotImplementedError`. The test has not opened or created any suspected secret file.

- [ ] **Step 11: Replace the red path helpers with filename-only Git inspection**

Apply this exact patch:

```diff
 def is_forbidden_runtime_path(relative_path: str) -> bool:
-    del relative_path
-    raise NotImplementedError("path classification is absent in the red state")
+    """Return whether a repository-relative path is forbidden in source control."""
+    normalized = PurePosixPath(relative_path.replace("\\", "/"))
+    parts = normalized.parts
+    if parts and parts[0].lower() in _FORBIDDEN_ROOT_DIRECTORIES:
+        return True
+    filename = normalized.name.lower()
+    return any(
+        fnmatch.fnmatchcase(filename, pattern)
+        for pattern in _FORBIDDEN_FILE_PATTERNS
+    )


 def _run_git(
     repository_root: Path,
     *arguments: str,
 ) -> subprocess.CompletedProcess[str]:
-    del repository_root, arguments
-    raise NotImplementedError("Git path inspection is absent in the red state")
+    git_executable = shutil.which("git")
+    assert git_executable is not None, (
+        "Git is required by the repository verification workflow"
+    )
+    return subprocess.run(  # noqa: S603 - shutil.which returns the local Git path.
+        [git_executable, *arguments],
+        cwd=repository_root,
+        check=False,
+        capture_output=True,
+        text=True,
+        timeout=10,
+    )
```

The Git-visible-path query includes tracked files and unignored untracked files while excluding ignored local runtime state. `git check-ignore --no-index` proves ignore semantics for names that do not exist. No suspected secret file is opened.

- [ ] **Step 12: Run the forbidden-path slice and confirm green**

```powershell
uv run --no-sync pytest -o addopts="" tests/safety/test_forbidden_runtime_paths.py -q
```

Expected: exit `0`; every required generated/secret probe is ignored, every source/control probe remains visible, `src/crypto_lab/artifacts` is not swallowed by the root runtime ignore, and no tracked or unignored prohibited filename is present.

- [ ] **Step 13: Run all architecture and safety tests together**

```powershell
uv run --no-sync pytest -o addopts="" tests/architecture tests/safety -q
```

Expected: exit `0` with no network, engine, database, Docker, WSL, credential, or environment-variable requirement.

- [ ] **Step 14: Format and run the complete quality gate**

```powershell
uv sync --frozen --offline
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
uv run --no-sync ruff format tests
uv run --no-sync ruff check .
uv run --no-sync mypy src tests
uv run --no-sync pytest
uv build --offline
git diff --check
```

Expected: every command exits `0` without network access. Offline synchronization installs exactly the locked environment, every tool runs with `--no-sync`, branch coverage is at least 90 percent, and both package distributions build offline from the synchronized Hatchling without an isolated resolver. A missing local package stops the task and returns to the Task 2 bootstrap gate.

**Focused verification:** Three independent red-green cycles: AST import boundary, dependency classification, and filename/Git-ignore safety.

**Broader verification:** Combined architecture/safety slice, full Ruff, strict mypy, complete pytest with coverage, package build, and whitespace check.

**Commit:**

```powershell
git add tests/architecture/test_domain_import_boundary.py tests/safety/test_project_dependencies.py tests/safety/test_forbidden_runtime_paths.py
git diff --cached --check
git commit -m "test: enforce architecture and safety boundaries"
```

Expected: one test-only commit containing exactly the three guardrail files.

### Task 5: Agent instructions, README, and verification workflow

**Files:**
- Create: `AGENTS.md`
- Create: `scripts/verify.ps1`
- Create: `docs/development/verification.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: the locked environment, package/CLI commands, quality configuration, and guardrail tests from Tasks 2–4
- Produces: repository instructions for coding agents; local operator guidance; and `scripts/verify.ps1`, a parameterless command that exits `0` only when all seven required checks exit `0` and otherwise returns the first failing native exit code

This task uses the documentation/automation exception declared above. It adds no production Python behavior.

- [ ] **Step 1: Create repository agent instructions**

Create `AGENTS.md` with exactly:

```markdown
# Repository Instructions

## Authority and scope

- Read `docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md` and `docs/decisions/0001-gitnexus-development-tooling.md` before an architectural change.
- Treat the approved specification and reviewed source as authoritative. GitNexus output is advisory and cannot override either.
- Keep changes inside the requested stage and avoid modifying unrelated files.

## Development workflow

- Use CPython 3.12 and `uv` for the central project.
- Use test-driven development for production behavior: focused failing test, minimum implementation, focused passing test, then broader verification.
- Run `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1` before claiming completion.
- Report every skipped check, warning, and failure; do not infer success from a partial verification run.
- Ordinary development and verification are offline: synchronize with `uv sync --frozen --offline`, run installed tools with `uv run --no-sync`, build with `uv build --offline`, and validate the lock with `uv lock --check --offline`.
- If locked packages are absent locally, stop and return to the separately approved Task 2 bootstrap procedure. Only its exact, one-time-approved `uv lock` and dependency-acquisition `uv sync --frozen` commands may access the network; use `--no-install-project` before the source scaffold exists, and never enable unrestricted or permanent network access.

## Architecture rules

- Keep `crypto_lab.domain` independent of strategy, capabilities, adapters, experiments, datasets, artifacts, persistence, process supervision, configuration, audit, CLI, engine, database, and network implementations.
- Keep imports free of file reads, environment inspection, network access, database initialization, directory creation, and process launch.
- Use `Decimal` for authoritative financial values and timezone-aware UTC timestamps when those types are introduced.
- Reject unknown fields at future configuration, schema, protocol, and artifact boundaries.
- Never install or import a real trading engine during Project 1.
- During Stage 1, do not install, configure, or invoke GitNexus. After a separately approved Stage 2, keep it optional, project-scoped, read-only, advisory, and outside product, build, test, and runtime dependencies.

## Safety boundaries

- Never add live trading, real-order placement, credentials, API-key handling, withdrawal behavior, leverage, futures, margin, or shorting.
- Never add Docker, cloud deployment, or server deployment.
- Never add implicit network access.
- Application code must not read configuration or credentials implicitly from ambient environment variables in Project 1.
- Agents and application code must never inspect, print, persist, or log ambient environment-variable values or credential-store contents.
- Project-scoped Codex MCP configuration may set only the reviewed, non-secret GitNexus control variables explicitly required by ADR 0001. Those variables are developer-tool configuration, not application configuration, credentials, or runtime product inputs. No other exception is implied.
- Do not add Binance, exchange, broker, or network-client integration during Project 1.
```

- [ ] **Step 2: Replace the current README with foundation guidance**

Replace the current one-line `README.md` with exactly:

````markdown
# Crypto Trading Lab

**Status:** Project 1 foundation

Crypto Trading Lab is a personal, local-only Windows project for building an engine-neutral research and simulated-trading foundation. Stage 1 supplies only the Python package scaffold, version command, offline safety checks, and local quality workflow.

## Planned future engine adapters

The approved architecture names seven engines as future isolated adapters:

1. VectorBT Community
2. Freqtrade
3. NautilusTrader
4. Jesse
5. OctoBot
6. Hummingbot
7. QuantConnect LEAN

These adapters do not exist in the repository yet. Their versions, capabilities, operating-system behavior, and limitations must be verified in their later adapter projects.

## Current safety scope

- Personal and local-only operation on Windows
- Research and simulated-trading architecture only
- No real-money order placement
- No credentials, API keys, or withdrawal behavior
- No leverage, futures, margin, or shorting
- No implicit network access

## Project 1 exclusions

Project 1 contains no real trading engine, Binance integration, market-data download, real backtest, paper wallet, tax or TDS logic, risk engine, dashboard, LLM integration, Docker setup, cloud deployment, or server deployment.

## Prerequisites

- CPython 3.12 available through the Windows Python launcher
- `uv`

If either prerequisite is missing, stop and install nothing automatically.

## Local setup

From the repository root:

```powershell
py -3.12 --version
uv --version
uv sync --frozen --offline
uv run --no-sync crypto-lab --version
uv run --no-sync python -m crypto_lab.cli --version
```

Both version commands print `crypto-lab 0.1.0`. Always try the offline synchronization first. If its cache is incomplete, the user or agent must review and explicitly approve the exact `uv sync --frozen` command once under the Task 2 bootstrap procedure. After that acquisition succeeds, rerun `uv sync --frozen --offline`; normal development and verification remain offline.

## Verification

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
```

The workflow checks the locked environment, formatting, linting, strict typing, tests and coverage, package builds, and Git whitespace. See [development verification](docs/development/verification.md) for focused commands and the dependency network gate.

## Architecture references

- [Engine-neutral core design](docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md)
- [ADR 0001: GitNexus for local development context](docs/decisions/0001-gitnexus-development-tooling.md)

No trading engine or Binance integration exists yet.
````

- [ ] **Step 3: Create the PowerShell verification entry point**

Create `scripts/verify.ps1` with exactly:

```powershell
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$verificationExitCode = 0
$repositoryRoot = (
    Resolve-Path -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath "..")
).Path

function Invoke-VerificationStep {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Heading,

        [Parameter(Mandatory = $true)]
        [string]$Executable,

        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList
    )

    Write-Host ""
    Write-Host "==> $Heading"
    & $Executable @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        $script:verificationExitCode = $LASTEXITCODE
        throw "Command failed with exit code $LASTEXITCODE`: $Executable $($ArgumentList -join ' ')"
    }
}

Push-Location -LiteralPath $repositoryRoot
try {
    Invoke-VerificationStep "Sync locked environment" "uv" @("sync", "--frozen", "--offline")
    Invoke-VerificationStep "Check formatting" "uv" @("run", "--no-sync", "ruff", "format", "--check", ".")
    Invoke-VerificationStep "Run lint checks" "uv" @("run", "--no-sync", "ruff", "check", ".")
    Invoke-VerificationStep "Run strict type checks" "uv" @("run", "--no-sync", "mypy", "src", "tests")
    Invoke-VerificationStep "Run test suite" "uv" @("run", "--no-sync", "pytest")
    Invoke-VerificationStep "Build package" "uv" @("build", "--offline")
    Invoke-VerificationStep "Check Git whitespace" "git" @("diff", "--check")
}
catch {
    if ($verificationExitCode -eq 0) {
        $verificationExitCode = 1
    }
    [Console]::Error.WriteLine($_.Exception.Message)
}
finally {
    Pop-Location
}

exit $verificationExitCode
```

This executes, in exact logical order:

1. `uv sync --frozen --offline`
2. `uv run --no-sync ruff format --check .`
3. `uv run --no-sync ruff check .`
4. `uv run --no-sync mypy src tests`
5. `uv run --no-sync pytest`
6. `uv build --offline`
7. `git diff --check`

The helper captures `$LASTEXITCODE` before throwing, stops immediately, and returns that native nonzero value after the `finally` block restores the original directory. Every package operation in the script is independently offline or `--no-sync`; it never relies on an earlier probe and contains no network enablement, engine, Docker, WSL, credential, Binance, runtime, or GitNexus operation. If a locked package is unavailable locally, synchronization fails and the operator returns to the separately approved Task 2 bootstrap procedure.

- [ ] **Step 4: Create development verification guidance**

Create `docs/development/verification.md` with exactly:

````markdown
# Development Verification

Stage 1 verification is local, Windows-oriented, and independent of trading engines, Binance, databases, Docker, WSL, credentials, and environment-variable configuration.

## Prerequisites

Run these read-only checks from the repository root:

```powershell
py -3.12 --version
uv --version
```

Stop without installing anything automatically if CPython 3.12 or `uv` is unavailable.

## Locked setup

After `uv.lock` exists, synchronize only from local locked content:

```powershell
uv sync --frozen --offline
```

If locally cached packages are insufficient, stop. Return to the Task 2 bootstrap procedure, show the exact `uv sync --frozen` acquisition command, and obtain one-time approval before running it. Then rerun `uv sync --frozen --offline`. The approved acquisition is not a verification step, and no ordinary development or verification command becomes non-offline.

## Complete verification

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
```

The script stops at the first failure and runs, in order:

1. `uv sync --frozen --offline`
2. `uv run --no-sync ruff format --check .`
3. `uv run --no-sync ruff check .`
4. `uv run --no-sync mypy src tests`
5. `uv run --no-sync pytest`
6. `uv build --offline`
7. `git diff --check`

A successful partial command does not establish repository acceptance.

## Focused checks

Use focused checks during red-green development, then run complete verification:

```powershell
uv run --no-sync pytest -o addopts="" tests\unit\test_cli.py -q
uv run --no-sync pytest -o addopts="" tests\architecture\test_domain_import_boundary.py -q
uv run --no-sync pytest -o addopts="" tests\safety -q
uv run --no-sync ruff check src tests
uv run --no-sync mypy src tests
```

The `addopts` override removes the repository-wide coverage threshold only from the focused diagnostic run. The later complete suite must meet the configured 90 percent branch-coverage gate.

## Dependency changes

Do not hand-edit `uv.lock`. After an approved `pyproject.toml` dependency change:

1. Run `uv lock --offline` to attempt resolution locally.
2. If resolution fails only because cached metadata is absent, return to the Task 2 gate, show the exact `uv lock` command, and obtain one-time approval before running it.
3. Validate with `uv lock --check --offline`.
4. Run `uv sync --frozen --offline` to install only locally available locked packages.
5. If acquisition is still required, return to Task 2, show its exact `uv sync --frozen --no-install-project` command, and obtain one-time approval before running it; then rerun the ordinary offline synchronization.
6. Commit `pyproject.toml` and the generated `uv.lock` together.
7. Use `uv run --no-sync` for installed tools and `uv build --offline` for builds.

No dependency operation may install a trading engine or add GitNexus to the product environment. A Task 2 bootstrap approval never permits online verification.
````

- [ ] **Step 5: Execute the complete workflow from a non-root directory**

Run from `docs` so root resolution and directory restoration are exercised:

```powershell
$verificationExitCode = 0
Push-Location docs
try {
    powershell -NoProfile -ExecutionPolicy Bypass -File ..\scripts\verify.ps1
    $verificationExitCode = $LASTEXITCODE
}
finally {
    Pop-Location
}
if ($verificationExitCode -ne 0) {
    exit $verificationExitCode
}
```

Expected: exit `0`; the script's own offline synchronization succeeds, seven headings appear in the required order, the script returns the caller to `docs`, and no lockfile changes. The script is independently offline and does not rely on a separate probe. If its offline synchronization fails because locked content is absent locally, stop and use the Task 2 one-time approval gate before rerunning the unchanged script.

- [ ] **Step 6: Review the complete documentation and automation diff**

```powershell
git diff -- AGENTS.md README.md scripts/verify.ps1 docs/development/verification.md
git diff --check
git status --short
```

Expected: only the four Task 5 paths are uncommitted; the instructions and README match the fixed safety scope; the script contains exactly the seven required operations; and the whitespace check exits `0`.

**Focused verification:** Execute `scripts/verify.ps1` from `docs` and confirm root resolution, ordered headings, first-failure behavior by inspection, exit propagation by implementation, and caller-directory restoration.

**Broader verification:** The script itself runs offline frozen sync, no-sync format check, no-sync lint, no-sync strict mypy, no-sync full pytest with coverage, offline package build, and Git whitespace.

**Commit:**

```powershell
git add AGENTS.md README.md scripts/verify.ps1 docs/development/verification.md
git diff --cached --check
git commit -m "docs: add repository development workflow"
```

Expected: one commit containing exactly the four documentation and workflow files.

### Task 6: Full fresh verification and foundation acceptance review

**Files:**
- Create: none
- Modify: none
- Test: all Stage 1 tests and acceptance commands

**Interfaces:**
- Consumes: all committed implementation-task outputs from Tasks 2–5, including any narrow correction commits
- Produces: fresh console, format, lint, strict-type, test/coverage, build, safety, diff, and clean-worktree evidence only; no file or API output

The preferred primary structure remains these four task commits: `chore: initialize python project foundation`, `feat: add package scaffold and version command`, `test: enforce architecture and safety boundaries`, and `docs: add repository development workflow`. They are not an exact total-commit requirement. A review or verification defect may use a narrow additional correction commit under the rules below.

- [ ] **Step 1: Confirm a clean committed worktree**

```powershell
git status --short
```

Expected: exit `0` with no output. If any path is present, stop and resolve it in the task that owns that path.

- [ ] **Step 2: Run the complete verification workflow fresh**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
```

Expected: exit `0`; the script itself performs offline frozen synchronization, no-sync Ruff format and lint, no-sync strict mypy, no-sync full pytest with at least 90 percent branch coverage, offline sdist/wheel build, and Git whitespace. It never initiates network access or relies on an earlier probe. If local locked content is missing, it fails and the operator returns to the Task 2 approval gate.

- [ ] **Step 3: Prove both exact version forms**

```powershell
uv run --no-sync crypto-lab --version
uv run --no-sync python -m crypto_lab.cli --version
```

Expected: each command exits `0` and prints exactly `crypto-lab 0.1.0` followed by one newline.

- [ ] **Step 4: Prove no-argument help and argparse failure**

```powershell
uv run --no-sync crypto-lab
$helpExit = $LASTEXITCODE
uv run --no-sync crypto-lab --unknown
$unknownExit = $LASTEXITCODE
if ($helpExit -ne 0) { throw "No-argument help exited $helpExit" }
if ($unknownExit -ne 2) { throw "Unknown argument exited $unknownExit instead of 2" }
```

Expected: help begins with `usage: crypto-lab` and exits `0`; the unknown option emits argparse's error to stderr and exits `2`.

- [ ] **Step 5: Determine the Stage 1 base and review the complete path set**

```powershell
$stage1BaseCommit = (git merge-base HEAD main).Trim()
if ([string]::IsNullOrWhiteSpace($stage1BaseCommit)) {
    throw "Unable to determine the Stage 1 base commit"
}

git diff --name-status "$stage1BaseCommit..HEAD"
git diff --stat "$stage1BaseCommit..HEAD"
git diff --check "$stage1BaseCommit..HEAD"
```

Expected: merge-base resolution and every diff command exit `0`; the name/status output matches exactly the created and modified Stage 1 file map in this plan; the stat contains no runtime, secret, engine, database, schema, GitNexus, MCP, Docker, WSL, workflow-hosting, or unrelated path; every primary or correction commit since the branch point is included; and the whitespace check exits `0`.

- [ ] **Step 6: Review the complete Stage 1 diff**

```powershell
$stage1BaseCommit = (git merge-base HEAD main).Trim()
if ([string]::IsNullOrWhiteSpace($stage1BaseCommit)) {
    throw "Unable to determine the Stage 1 base commit"
}

git diff "$stage1BaseCommit..HEAD"
```

Review every line against the normative specification, ADR, this plan, and these acceptance points:

- the fresh-process import guard covers all fifteen planned modules, including `crypto_lab.cli.main` and `crypto_lab.cli.__main__`, and detects the named guarded calls, output, and paths below its temporary working directory; exact source review and architecture constraints cover the broader import boundary without claiming a complete operating-system side-effect detector;
- `crypto_lab/__init__.py` contains no trading behavior or version duplication;
- runtime dependencies and optional runtime groups are empty;
- real engines and network clients are absent;
- the domain scanner handles every absolute and relative import form in scope;
- forbidden paths are ignored while source/control paths remain visible;
- the CLI has only version and help behavior;
- all documentation preserves the fixed exclusions; and
- GitNexus was neither installed nor configured.

- [ ] **Step 7: Confirm final cleanliness**

```powershell
git status --short
```

Expected: exit `0` with no output.

**Focused verification:** Exact version, help, unknown-argument, file-map, and whitespace acceptance checks.

**Broader verification:** A fresh independently offline full script run plus complete merge-base-to-HEAD diff and safety review.

**Commit:** No commit command or commit message is permitted when this task changes no tracked evidence. Do not create an empty `chore: verify project foundation` commit. If verification exposes a defect, return to the owning task and make the narrow correction through a failing test where production behavior is involved. A correction commit is allowed; it must be non-empty, independently reviewed, and covered by the relevant focused and broader checks. Do not rewrite an already reviewed commit merely to preserve a commit count. Rerun Task 6 so the merge-base-to-HEAD review includes every primary and correction commit.

## Stage 1 implementation handoff

- Preferred execution uses `superpowers:subagent-driven-development`, with a fresh worker and review gate per task.
- Establish an isolated Git worktree branch from local `main` through the appropriate Superpowers workflow before Task 2 changes any file, and prove its pre-edit merge base equals its current `HEAD`. Task 1 remains the read-only source-repository preflight.
- Do not install, configure, or invoke GitNexus during Stage 1.
- Do not begin execution until the user reviews and approves this plan.
- After Stage 1 is implemented, freshly verified, reviewed, and committed, write and approve the Stage 2 Guarded GitNexus Development Tooling implementation plan.
- Stage 2 must inspect the actual Stage 1 scaffold and current local environment, including the pre-existing launcher and Node/package-manager facts, rather than assuming a global package layout or launcher design.

No Stage 2 file, network action, or GitNexus operation is authorized by this Stage 1 plan.
