# Crypto Trading Lab

**Status:** Project 1 Stages 1-4 complete

Crypto Trading Lab is a personal, local-only Windows project for building an engine-neutral research and simulated-trading foundation. Stage 1 supplies the Python scaffold and offline workflow; Stage 2 records GitNexus as `DISABLED_WITH_EVIDENCE`; Stage 3 completes the strict canonical-value, explicit-configuration, deterministic-hashing, dataset-metadata, structural-descriptor, artifact-ownership, and generated-schema foundation; Stage 4 adds portable strategy specification, static validation, a deterministic reference feature evaluator, strategy versioning and hashing, the capability vocabulary and compatibility resolver, and the comparison-eligibility predicate. None of these stages adds an engine, an exchange connection, or a runtime service.

Project 1 Stage 4 is complete. Portable strategy ingestion, deterministic Level 1 evaluation, strategy versioning and hashing, capability resolution, comparison eligibility, and the reviewed 20-schema registry are implemented. Stage 4 implementation completed at `33f5b1c3b644c1df7e8db0df17dae88c6bcea2ce`; the final status was recorded by the separate Task 9 status commit. Stage 5 has not started.

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

Stage 4 adds none of them. It declares strategies, capabilities, and comparison eligibility as data and validates them; it executes no engine, no adapter, no strategy, and no declared engine extension, places no order, simulates no fill, keeps no portfolio account, persists nothing, and combines no comparison result into an averaged, voted, or synthetic figure.

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

The registry is closed at **20** schemas: the eleven Stage 3 files, which Stage
4 leaves byte-identical, followed by the nine Stage 4 files below.

```text
schemas/strategy/strategy-spec-v1.schema.json
schemas/strategy/strategy-version-v1.schema.json
schemas/strategy/expression-v1.schema.json
schemas/capabilities/capability-requirement-v1.schema.json
schemas/capabilities/capability-declaration-v1.schema.json
schemas/capabilities/approximation-declaration-v1.schema.json
schemas/capabilities/compatibility-result-v1.schema.json
schemas/capabilities/runtime-availability-observation-v1.schema.json
schemas/capabilities/comparison-eligibility-result-v1.schema.json
```

Generated schemas are reviewed canonical source artifacts, not incidental
build output: every byte is read before it is committed, and a published `$id`
is a permanent contract. The complete verifier checks that exactly those 20
schemas are packaged once in the wheel and once in the sdist with identical
bytes.

Every timestamp field reachable from the published Stage 4 schema graph uses
the calendar- and clock-valid forward schema view, so an impossible instant
such as `2026-02-30T00:00:00Z`, `2026-01-01T24:00:00Z`, `2026-01-01T00:60:00Z`,
or `2026-01-01T00:00:60Z` is rejected by the published schema as well as by the
runtime. The three released Stage 3 `$id`s keep their original, more permissive
date grammar, because their bytes are frozen.

The closed twenty-one-member expression union is published as standard Draft
2020-12 conditional dispatch — a root `op` enum plus one shallow `if`/`then`
clause per operation — rather than as a recursive `oneOf`, which was exponential
in tree depth. Exactly one clause descends into a node's children, so validation
cost is linear in document size rather than exponential in depth. Linear in
*size*, though: the depth bound does not bound size, and a large tree still costs
proportionally, so a consumer validating an untrusted document against these
schemas should bound its size itself. `docs/development/verification.md` records
the measurements. The `discriminator` annotation is kept for tooling only; Draft
2020-12 ignores it and validation does not depend on it.

Some runtime rules cannot be expressed in JSON Schema Draft 2020-12 at all —
expression-tree depth, ordering of a collection whose element domain is
unbounded, comparisons between two values carried by the same document, and
recomputing the SHA-256 strategy identity to check a recorded content hash among
them. Those remain enforced by the runtime validators and are recorded as such
rather than silently dropped or approximated in the published bytes.

## Portable strategy loading

A strategy is a single safe-YAML document. `StrategyLoader.load` returns a
discriminated success-or-diagnostics result: it decodes the bytes without ever
constructing a node graph, builds a strict `StrategySpec`, statically type-checks
every entry and exit expression, validates the feature graph for cycles and
warm-up sufficiency, and produces an immutable `StrategyVersion` whose content
hash is independent of comments, whitespace, and key order. Declared capability
requirements resolve against an adapter's declarations through a pure
deterministic compatibility resolver with complete, deduplicated, stably ordered
reasons; `runtime.live` is rejected by core policy before resolution runs.

Nothing here loads, imports, or runs an engine adapter or a declared engine
extension. The reference evaluator is a deterministic Decimal-only Level 1
implementation used to fix the meaning of a feature, not a backtester.

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
