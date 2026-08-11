# Development Verification

Stage 1 verification is local, Windows-oriented, and independent of trading engines, Binance, databases, Docker, WSL, credentials, and environment-variable configuration.

## Prerequisites

Run these read-only checks from the repository root:

```powershell
uv --version
uv python find --managed-python --system --no-python-downloads 3.12
```

The second command must resolve the already installed user-local uv-managed CPython 3.12 and must not download an interpreter. It is read-only: `--system` skips the project `.venv` during discovery, `--managed-python` still requires a uv-managed install, and `--no-python-downloads` prevents acquisition without modifying system Python. Normal project execution still uses `.venv` via `uv run --no-sync`. Stop without installing anything automatically if the managed interpreter or `uv` is unavailable. Stage 1 does not require Windows `py` launcher or PythonCore registration, a Python installer or WinGet Python package, or a Python `PATH` entry.

The verification workflow relies on `.python-version` requesting `3.12`, `[tool.uv] python-preference = "only-managed"` prohibiting fallback to system Python 3.13 or 3.13t, and `[tool.uv] python-downloads = "manual"` disabling automatic interpreter downloads. `scripts/verify.ps1` therefore uses the existing managed prerequisite and never installs Python.

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

1. `uv lock --check --offline`
2. `uv sync --frozen --offline`
3. `uv run --no-sync ruff format --check .`
4. `uv run --no-sync ruff check .`
5. `uv run --no-sync mypy src tests`
6. `uv run --no-sync pytest`
7. `uv build --offline`
8. `git diff --check`

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
