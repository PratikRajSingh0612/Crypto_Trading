# Crypto Trading Lab - offline historical candle data (`offline_data`)

**Status:** Project 2, first bounded slice - scaffold only. No reader, validation,
normalization, metadata emission or command entry exists yet; they land in Tasks 1-3
of `docs/superpowers/plans/2026-11-09-project-2-offline-data-first-slice-implementation-plan.md`.

## Scope

This sub-project is the first slice of Project 2: read one local historical-candle
fixture in one documented input format, validate and normalize it under the core's
dataset rules, and emit the dataset metadata the core already defines
(`DatasetDescriptor`, `DatasetPartition`) with a deterministic content identity.
Everything is offline: no download, no exchange or broker integration, no credentials,
no live trading, no cloud or server deployment.

## Placement: outside the core's dependency and runtime boundary

`offline_data/` is a self-contained Python sub-project inside the repository. It has
its own `pyproject.toml`, its own `uv.lock`, its own managed-Python environment
(`offline_data/.venv`, ignored by the root `.gitignore` pattern `.venv/`) and its own
launcher. It consumes the core distribution `crypto-trading-lab` as a non-editable path
dependency (`[tool.uv.sources] crypto-trading-lab = { path = "../" }`) built from the
repository root into the sub-project environment. It never writes into the core's
environment, lockfile, source tree or guards.

The complete closure is pinned with `==` to the versions the root `uv.lock` already
resolved: the runtime closure as uv `constraint-dependencies` and the development tools
in the `dev` dependency group, so the offline lock resolves from the local uv cache the
core populated. The package is `crypto_lab_offline_data` (distribution
`crypto-lab-offline-data`, version `0.1.0`) under `offline_data/src/`, for CPython
`>=3.12,<3.13` selected by `uv` from the user-local managed installs only.

## Prerequisites

Same as the core: `uv` installed and a user-local uv-managed CPython 3.12
(`uv python find --managed-python --system --no-python-downloads 3.12`). This
sub-project downloads nothing; if the interpreter is missing, stop.

## Launcher

`offline_data/scripts/invoke-offline-uv.ps1` mirrors the core launcher
`scripts/invoke-uv.ps1`: exactly one resolvable `uv.exe`, invoked by its normalized
absolute path; `--no-config`, `--managed-python`, `--no-python-downloads` and
`--offline` on every profile; the project pinned with `--directory` and `--project` to
`offline_data/`; the same child-environment hygiene (`PYDANTIC_DISABLE_PLUGINS=__all__`
set unconditionally, the fixed uv, Python, virtual-environment, pytest, coverage and
mypy selection variables removed by name, no environment value ever read or printed);
caller-selected Python, scripts, tools, uv flags and external pytest paths or options
rejected. The profile set is closed. There is no acquiring (`lock-acquire`,
`sync-acquire`), `build`, schema, migration or command-line profile, and no profile can
reach the network. The launcher derives its root from its own location, so it behaves
identically from the repository root and from `offline_data/`:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\offline_data\scripts\invoke-offline-uv.ps1 <profile> [arguments]
```

Operator-run environment profiles. They create or check the environment, dispatch
before any interpreter is resolved, and are run by the operator in this order on a
fresh checkout:

| Profile | uv command (after the fixed controls) | Purpose |
|---|---|---|
| `lock-resolve-offline` | `uv --offline lock` | Resolves `offline_data/uv.lock` from the local cache; the first proof of the environment |
| `lock-check` | `uv --offline lock --check` | Proves the committed lock matches `pyproject.toml` |
| `sync` | `uv --offline sync --frozen --no-build-isolation` | Creates `offline_data/.venv` from the frozen lock and builds the core wheel without isolation (hence `hatchling==1.31.0` in the dev group) |

Profiles a relay worker may run. Each resolves and validates
`offline_data\.venv\Scripts\python.exe` and proves it stays inside the sub-project
environment before running:

| Profile | Runs | Arguments |
|---|---|---|
| `pytest-focused` | pytest on explicit targets | `[-o addopts=] <tests/...> [<tests/...> ...] [-q]`; each target is spelled relative to `offline_data/` and must match `^tests/[A-Za-z0-9_./-]+(?:::[A-Za-z0-9_]+)?$`; no `..`, no absolute path, no other option; a bare `tests` is refused |
| `ruff-format-all` | `ruff format --check .` | none |
| `ruff-check-all` | `ruff check .` | none |
| `mypy-all` | `python -m mypy` (strict, `files = ["src", "tests"]`) | none |

`pytest-all` runs the whole suite with the configured addopts (branch coverage and the
floor below). It is used by the verify script.

## Verification

`offline_data/scripts/verify-offline.ps1` mirrors the core's `scripts/verify.ps1`. It
runs, each stage through the launcher, in order: `lock-check`, `sync`,
`ruff-format-all`, `ruff-check-all`, `mypy-all`, `pytest-all`, then `git diff --check`
scoped to `offline_data/`. It stops at the first non-zero exit and names the failed
stage.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\offline_data\scripts\verify-offline.ps1
```

The enforced branch-coverage floor is 98.61 percent: `--cov-fail-under=98.61` in the
pytest addopts and `fail_under = 98.61` with `precision = 2` in the coverage report
settings, so the comparison is made at two decimals rather than after rounding the total
to a whole percent. The plan names both the core's configured 90 percent floor and the
98.61 percent acceptance figure; this sub-project enforces 98.61.

The core's own `scripts/verify.ps1` keeps applying to every Project 2 task: its
`ruff-format-all` and `ruff-check-all` stages traverse `offline_data/` from the
repository root and apply this sub-project's nested `[tool.ruff]` configuration. Run the
sub-project verifier and the core verifier alone, never concurrently.

## Reporting boundaries

- **P2-B1 - Parquet.** The specification makes dataset partitions Parquet files. Parquet
  emission needs `pyarrow`, a prohibited dependency family that is not approved for
  acquisition anywhere. The declared policy for this slice: the partition container is
  an explicitly labelled interim NDJSON container; nothing names it a Parquet partition;
  every descriptor carries the limitation in `known_limitations` and every partition in
  `quality_observations`; and no interim container is ever registered in a persistent
  registry. Lifting P2-B1 is a separately authorized acquisition and a later task. The
  current scaffold emits no container.
- **P2-B2 - offline lock resolution.** If `lock-resolve-offline`, `lock-check` or
  `sync` cannot be satisfied from the local uv cache, the exact missing distribution
  and the exact uv message are reported once as P2-B2 and nothing is acquired. P2-B2
  stops Task 0: the scaffold is not committed, no worker is dispatched and no product
  code is authored, because no executable route other than the launcher's pinned
  `offline_data/.venv` exists (no `uv run`, no system Python, no provisional runner) and
  nothing is faked. The one-time boundary report names the exact uv message and asks
  the owner how the clause to continue independently useful parsing and validation work
  is to be honoured.

## Input format

The `ohlcv-csv/1` section is written by Task 1.

## Safety scope

Unchanged from the core: personal, local-only, research only; no real-money orders, no
credentials or API keys, no leverage, futures, margin or shorting, no implicit network
access, no Docker, cloud or server deployment.
