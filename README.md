# Crypto Trading Lab

**Status:** Project 1 Stages 1-3 complete

Crypto Trading Lab is a personal, local-only Windows project for building an engine-neutral research and simulated-trading foundation. Stage 1 supplies the Python scaffold and offline workflow; Stage 2 records GitNexus as `DISABLED_WITH_EVIDENCE`; Stage 3 completes the strict canonical-value, explicit-configuration, deterministic-hashing, dataset-metadata, structural-descriptor, artifact-ownership, and generated-schema foundation without adding an engine or runtime service.

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

- `uv` already installed
- A user-local uv-managed CPython 3.12 already installed (the current verified prerequisite is CPython 3.12.13 x64)

Stage 1 does not install Python. No Python.org MSI, WinGet Python package, PythonCore registration, Windows `py` launcher registration, or Python `PATH` entry is required. If either prerequisite is missing, stop and install nothing automatically; `uv python install` belongs to a separately reviewed and approved prerequisite task.

## Local setup

From the repository root:

```powershell
uv --version
uv python find --managed-python --system --no-python-downloads 3.12
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 sync
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 cli-version
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 cli-module-version
```

The first two commands are read-only prerequisite checks. `--system` skips the
project `.venv` during discovery, `--managed-python` still requires a
uv-managed install, and `--no-python-downloads` makes a missing managed
interpreter fail instead of acquiring one. The discovery command does not
modify system Python. `.python-version` requests Python 3.12,
`python-preference = "only-managed"` prevents system-Python fallback, and
`python-downloads = "manual"` disables automatic interpreter downloads.

Normal project execution uses `.venv` only through the repository-controlled
`scripts/invoke-uv.ps1` child launcher. Both launcher version profiles print
`crypto-lab 0.1.0`. Ordinary development and verification remain offline.
Always run the launcher `sync` profile first. If its cache is incomplete, stop.
Only the exact Stage 3 Task 1 `sync-acquire` launcher profile may acquire the
missing distributions, and only after separate explicit one-time approval.
After that acquisition succeeds, rerun the launcher `sync` profile.

## Explicit configuration and schemas

Stage 3 configuration accepts only compiled defaults, an explicitly named
primary TOML file, an optional explicitly named local override, and allowlisted
typed CLI overrides. It does not inspect environment variables, profiles, home
directories, the current directory, the registry, credentials, or implicit
configuration files.

The reviewed source schemas are generated and checked offline:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 schema-generate-write
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 schema-generate-check
```

The complete verifier checks that exactly those 11 schemas are packaged once
in the wheel and once in the sdist with identical bytes.

## Verification

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
```

The ten-operation workflow checks the lock and offline synchronization, formatting, linting, strict typing, deterministic schemas, tests and coverage, the offline build, exact schema bytes in both distributions, and Git whitespace. See [development verification](docs/development/verification.md) for focused commands and the dependency network gate.

## Optional GitNexus developer context

Project 1 Stage 2 records its exact governance outcome in
[`tools/gitnexus/outcome.json`](tools/gitnexus/outcome.json) and its reviewed
package identity in
[`tools/gitnexus/supply-chain.json`](tools/gitnexus/supply-chain.json).
GitNexus is optional, advisory developer tooling and is not needed to set up,
verify, build, test, or run the Python project.

When the outcome is `DISABLED_WITH_EVIDENCE`, no package, MCP entry, wrapper,
or local index is present. Use the manual source, reference, and diff workflow
in [`tools/gitnexus/README.md`](tools/gitnexus/README.md). When the outcome is
`ENABLED`, use only its project-local committed wrappers and exact lock.

## Architecture references

- [Engine-neutral core design](docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md)
- [ADR 0001: GitNexus for local development context](docs/decisions/0001-gitnexus-development-tooling.md)

No trading engine or Binance integration exists yet.
