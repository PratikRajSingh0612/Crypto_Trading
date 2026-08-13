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
uses `.venv` through the repository `scripts/invoke-uv.ps1` child launcher.
Stop without installing anything when either prerequisite is absent.

The workflow relies on `.python-version` requesting `3.12`,
`python-preference = "only-managed"` prohibiting system-Python fallback, and
`python-downloads = "manual"` disabling automatic interpreter downloads.

## Locked setup

After `uv.lock` exists, synchronize only from local locked content:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\invoke-uv.ps1 sync
```

If cached packages are insufficient, stop. Show and obtain one-time approval
for the exact Task 1 `sync-acquire` launcher profile,
then return to the launcher `sync` operation, which expands only to the fixed
offline form. Acquisition is not verification
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
