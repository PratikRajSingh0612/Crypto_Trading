# Development Verification

Project 1 verification is local, Windows-oriented, and independent of trading
engines, Binance, databases, Docker, WSL, credentials, ambient environment
configuration, and application networking.

## Prerequisites

Run these read-only checks from the repository root:

```powershell
uv --version
uv python find --managed-python --system --no-python-downloads 3.12
```

The second command must resolve the already installed user-local uv-managed
CPython 3.12 and must not download an interpreter. `--system` skips the project
`.venv` during discovery, `--managed-python` still requires a uv-managed
install, and `--no-python-downloads` prevents acquisition. Normal execution
goes through the repository `scripts/invoke-uv.ps1` child launcher; every
profile except the five bootstrap profiles runs against the project `.venv`.
Stop without installing anything when either prerequisite is absent.

`.python-version` requesting `3.12`, `python-preference = "only-managed"`, and
`python-downloads = "manual"` remain ordinary project metadata for uv commands
issued outside the closed launcher. They are not the enforcement mechanism for
launcher profiles: the launcher passes `--no-config` on every profile, so uv
consults neither `.python-version` nor `[tool.uv]`. The launcher's own fixed
`--managed-python` and `--no-python-downloads` arguments carry that policy
instead.

## Fresh-worktree bootstrap

A new worktree carries tracked metadata but no `.venv`. After `uv.lock`
exists, `sync` is the supported first launcher operation there: it creates and
populates `.venv` from local locked content only, and must precede every
Python-bearing profile.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 sync
```

Five bootstrap profiles (`lock-resolve-offline`, `lock-check`, `sync`,
`lock-acquire`, and `sync-acquire`) dispatch before the launcher resolves
`.venv\Scripts\python.exe`. They therefore require no existing project
environment and pass no `--python` argument at all. They still validate that
the project `pyproject.toml` is a regular file below the repository root, and
that the root and any existing `.venv` prefix traverse no reparse point.

Their interpreter is constrained by the launcher's fixed `--managed-python`
and `--no-python-downloads` arguments together with the project
`requires-python = ">=3.12,<3.13"`: uv selects a user-local uv-managed CPython
satisfying that range and never falls back to an unreviewed system
interpreter. `--managed-python` alone names no exact patch release. Because
the launcher also passes `--no-config`, these profiles consult neither
`.python-version` nor `[tool.uv]`.

Once `sync` has created and populated `.venv`, every Python-bearing profile
resolves and validates `.venv\Scripts\python.exe`, proves it remains inside
the project environment, and runs its fixed Python or tool command against
that interpreter. The launcher sets the fixed Pydantic plugin-discovery
control in the child environment on every profile, bootstrap included.

`lock-resolve-offline`, `lock-check`, and `sync` are explicitly offline;
`lock-acquire` and `sync-acquire` are the two profiles that omit `--offline`,
and both remain separately approval-gated. If cached packages are
insufficient, stop. Show and obtain one-time approval for the exact Task 1
`sync-acquire` launcher profile, then return to the launcher `sync` operation,
which expands only to the fixed offline form. Acquisition is not verification
and never permits a non-offline ordinary command.

## Complete verification

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
```

The script stops at the first failure and runs, in order:

1. launcher `lock-check`
2. launcher `sync`
3. launcher `ruff-format-all`
4. launcher `ruff-check-all`
5. launcher `mypy-all`
6. launcher `schema-generate-check`
7. launcher `pytest-all`
8. launcher `build`
9. launcher `schema-distribution`
10. direct `git diff --check`

A successful partial command does not establish repository acceptance. Schema
generation checks the closed 11-file registry without writing; distribution
verification byte-compares the reviewed source schemas with their sole wheel
and sdist locations.

## Focused checks

Use focused checks during red-green development, then run complete verification:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\domain -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\configuration -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\datasets -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\adapters tests\unit\artifacts -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\property -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\safety -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 ruff-check-all
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 mypy-all
```

The `addopts` override removes the repository-wide coverage threshold only
from a focused diagnostic run. The later complete suite must satisfy the
configured branch-coverage gate.

## Schema workflow

Schemas are generated only from the explicit registry:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 schema-generate-write
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 schema-generate-check
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 build
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 schema-distribution
```

`--write` is an intentional source update reviewed in the schema task. The
operator must supply the reviewed repository `schemas` root explicitly; the
generator targets only the 11 fixed lexical descendants, rejects an existing
symlink root or entry, and refuses every unexpected file without deleting it.
Stage 7 retains physical ancestor reparse-point and volume containment. The
`--check` mode writes nothing and fails on a missing, changed, or unexpected
schema. The distribution check requires one wheel copy under
`crypto_lab/schemas/` and one sdist copy under `schemas/`, with bytes identical
to the reviewed source, and rejects every unexpected payload beneath either
schema prefix.

## Explicit configuration

Configuration sources are compiled defaults, an explicitly named primary TOML
file, an optional explicitly named local-override TOML file, and allowlisted
typed CLI overrides in that precedence order. No environment-variable layer,
profile discovery, home-directory lookup, current-directory lookup, registry
lookup, directory scan, credential source, or implicit file is permitted.

## Dependency changes

Do not hand-edit `uv.lock`. After an approved `pyproject.toml` dependency
change:

1. Run launcher profile `lock-resolve-offline`.
2. If cached registry metadata alone is absent, stop, show exact launcher
   profile `lock-acquire`, and obtain one-time approval before running it.
3. Validate with the launcher `lock-check` operation.
4. Run the launcher `sync` operation.
5. If distributions alone are absent, stop, show the exact
   `sync-acquire` launcher profile, and obtain one-time approval.
6. Return to both ordinary offline commands.
7. Commit `pyproject.toml` and generated `uv.lock` together.

No dependency operation may install an engine, exchange client, networking
client, database stack, or GitNexus. GitNexus remains disabled with evidence
and outside product, test, build, runtime, verification, and acceptance paths.
