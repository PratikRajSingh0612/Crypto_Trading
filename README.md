# Crypto Trading Lab

**Status:** Project 1 Stages 1-9 complete

Crypto Trading Lab is a personal, local-only Windows project for building an engine-neutral research and simulated-trading foundation. Stage 1 supplies the Python scaffold and offline workflow; Stage 2 records GitNexus as `DISABLED_WITH_EVIDENCE`; Stage 3 completes the strict canonical-value, explicit-configuration, deterministic-hashing, dataset-metadata, structural-descriptor, artifact-ownership, and generated-schema foundation; Stage 4 adds portable strategy specification, static validation, a deterministic reference feature evaluator, strategy versioning and hashing, the capability vocabulary and compatibility resolver, and the comparison-eligibility predicate; Stage 5 adds the experiment, engine-run, and command-invocation lifecycles with closed transition tables, queue-time immutability, revision compare-and-swap, the immutable six-gate retry decision with durable delay, deterministic terminal aggregation, and application-owned repository ports exercised through in-memory doubles; Stage 6 adds the adapter protocol: explicit adapter catalog contracts, bootstrap descriptors and negotiation, command-discriminated request envelopes, invocation-scoped stdout events, validation results, adapter result manifests reconciled into core-sanitized manifests, stable exit mappings, raw-token redaction, and executable fake adapters exercised through a test-resident offline harness; Stage 7 adds the production Windows process supervisor: shell-free absolute argument-array launch of the registered executable with a fresh empty environment, bounded stdout and stderr readers with incremental protocol parsing, paired UTC and monotonic deadlines, heartbeat liveness, graceful and forced termination with Job Object process-tree cleanup, durable PID creation identity, path preflight, stale-invocation rejection, and restart reconciliation, and drives the Stage 6 fake-adapter contract matrix and the Windows platform cases through that supervisor; Stage 8 adds SQLite persistence and migrations: write-ahead-log storage with foreign keys and a bounded busy timeout, SQLAlchemy mappings separate from the canonical models, repositories and short units of work with revision compare-and-swap, the Alembic baseline migration and its offline consistency check, durable retry decisions, invocation-scoped sanitized events, owner relations, and a persistence-side reconciliation source, and composes the Stage 5 operations and the Stage 7 supervisor over them; Stage 9 adds artifact finalization, recovery, provenance and audit: candidate and finalized artifact records with disjoint `RESULT` and `EVIDENCE` identities, owner, purpose and role validation, lexical and physical path confinement, streaming hashing with the exact-byte token scan, the content-addressed store with same-volume atomic moves, the purpose-tagged finalization journal with crash recovery and quarantine, the core `RunManifest` created only for a successful run, normalized result provenance, diagnostic causal chains, the bounded rotated JSON Lines log, append-only audit events and the post-run raw-token scans, and commits the first success run states of the project only through the result registrar over the production supervisor and SQLite. None of these stages adds an engine, an exchange connection, or a runtime service.

Project 1 Stage 9 is complete. Candidate and finalized artifact records with disjoint RESULT and EVIDENCE identities, lexical and physical path confinement, streaming hashing with the exact-byte token scan, the content-addressed store with same-volume atomic moves, the purpose-tagged finalization journal with crash recovery and quarantine, the core run manifest, normalized result provenance, diagnostic causal chains, the bounded rotated JSON Lines log, append-only audit events and the post-run raw-token scans are implemented, and the first success run states of the project are committed only through the result registrar over the production supervisor and SQLite. Stage 9 implementation completed at the implementation checkpoint the roadmap's status table records for Stage 9; the Stage 9 boundary guard and this status were added by the separate Task 9 commit, which is not the implementation hash. The closed 48-schema registry — 13 new Stage 9 schemas with the 35 Stage 3–6 schemas preserved byte-identical — is published; the relational schema has one Alembic head, `r0002_stage9_artifacts`. Stage 10 has not started.

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

Stage 5 adds none of them either. It records experiment, engine-run, and command-invocation lifecycles, retry decisions, and aggregation verdicts as strict data over in-memory test doubles; it launches no process, executes no adapter or engine, opens no database or file, contacts no network, and derives every decision from recorded facts and an injected clock rather than from a wall clock or a random source.

Stage 6 adds none of them either. It defines the adapter protocol as strict data and exercises it only through executable fake adapters launched by a test-resident harness: no real engine or adapter, no production process supervision, no shell invocation, no network or credentials, no database, no final artifact registration, and no success run state; every adapter output is untrusted until reconciled, and every raw attempt token is redacted before any core record exists.

Stage 8 adds none of them either. It stores the canonical lifecycle, retry, invocation, event, diagnostic, registry, snapshot, and ownership records in one local SQLite file through short transactions that never span a child process or a file operation; it opens no network connection, hands no database path to an adapter, finalizes no artifact, creates no `RunManifest`, and commits no success run state.

Stage 9 adds none of them either. It finalizes the bytes a fake adapter or the core produced under a test-resident root into a content-addressed store, registers them in the local SQLite file through short transactions that never span hashing or a file move, and records audit events and local JSON Lines logs; it opens no network connection, hands no database path, store path or finalized path to an adapter, relabels no failed result as evidence, finalizes no unsanitized stdout, raw-token input, original adapter-result candidate or quarantined bytes, and converts no normalized result, because no normalized-result producer and no Parquet reader exists.

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

The registry is closed at **48** schemas: the eleven Stage 3 files, which
Stages 4, 5, 6 and 9 leave byte-identical, followed by the nine Stage 4 files
below, which Stages 5, 6 and 9 also leave byte-identical.

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

The seven Stage 5 files follow them, in registry order:

```text
schemas/experiments/experiment-spec-v1.schema.json
schemas/experiments/experiment-record-v1.schema.json
schemas/experiments/engine-run-record-v1.schema.json
schemas/experiments/command-invocation-record-v1.schema.json
schemas/experiments/retry-policy-v1.schema.json
schemas/experiments/retry-decision-record-v1.schema.json
schemas/experiments/experiment-aggregation-result-v1.schema.json
```

The eight Stage 6 protocol files follow them, in registry order; Stage 6
leaves the twenty-seven earlier files byte-identical:

```text
schemas/protocol/bootstrap-descriptor-envelope-v1.schema.json
schemas/protocol/negotiation-result-v1.schema.json
schemas/protocol/adapter-command-request-envelope-v1.schema.json
schemas/protocol/protocol-event-envelope-v1.schema.json
schemas/protocol/run-event-v1.schema.json
schemas/protocol/adapter-validation-result-v1.schema.json
schemas/protocol/adapter-result-manifest-v1.schema.json
schemas/protocol/sanitized-adapter-result-manifest-v1.schema.json
```

Three of the eight describe temporary adapter-facing wire records that
carry the raw attempt token (the request envelope through its run payload,
the protocol event envelope, and the adapter result manifest); they are
never persisted. The sanitized `RunEvent` and the sanitized manifest are
the core-preserved forms and carry only the token's hash.

The thirteen Stage 9 files follow them, in registry order; Stage 9 leaves the
thirty-five earlier files byte-identical:

```text
schemas/artifacts/candidate-artifact-v1.schema.json
schemas/artifacts/artifact-ref-v1.schema.json
schemas/artifacts/artifact-finalization-purpose-v1.schema.json
schemas/artifacts/artifact-manifest-v1.schema.json
schemas/artifacts/result-finalization-request-v1.schema.json
schemas/artifacts/evidence-finalization-request-v1.schema.json
schemas/artifacts/finalization-result-v1.schema.json
schemas/artifacts/finalization-journal-entry-v1.schema.json
schemas/audit/audit-event-v1.schema.json
schemas/audit/log-record-v1.schema.json
schemas/domain/metric-value-v1.schema.json
schemas/experiments/run-manifest-v1.schema.json
schemas/experiments/normalized-result-provenance-v1.schema.json
```

The eight artifact files sit beside the frozen Stage 3 owner-reference entry,
the two audit files open a new group, the metric value joins the frozen Stage
3 domain entries and the run manifest and the normalized result provenance
join the Stage 5 experiments entries. No Stage 9 schema carries a raw attempt
token: the requests, journal entries and the run manifest carry only
`attempt_token_hash`, and the normalized record family stays unpublished
because Task 3 of the Stage 9 plan was excluded by the plan's default and did
not run.

Generated schemas are reviewed canonical source artifacts, not incidental
build output: every byte is read before it is committed, and a published `$id`
is a permanent contract. The complete verifier checks that exactly those 48
schemas are packaged once in the wheel and once in the sdist with identical
bytes.

Every timestamp field reachable from the published Stage 4, Stage 5, Stage 6
and Stage 9 schema graphs uses the calendar- and clock-valid forward schema view, so an impossible
instant such as `2026-02-30T00:00:00Z`, `2026-01-01T24:00:00Z`,
`2026-01-01T00:60:00Z`, or `2026-01-01T00:00:60Z` is rejected by the published
schema as well as by the runtime. The three released Stage 3 `$id`s keep their
original, more permissive date grammar, because their bytes are frozen.

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

The eleven-operation workflow checks the lock and offline synchronization, formatting, linting, strict typing, deterministic schemas, the relational migration baseline, tests and coverage, the offline build, exact schema bytes in both distributions, and Git whitespace. See [development verification](docs/development/verification.md) for focused commands and the dependency network gate.

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
