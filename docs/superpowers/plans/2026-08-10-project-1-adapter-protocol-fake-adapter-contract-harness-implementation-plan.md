# Project 1 Stage 6 — Adapter Protocol and Fake-Adapter Contract Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** Detailed implementation plan for Stage 6. Implementation status is
recorded only in the master roadmap status table, never in this header, so the
header cannot go stale.
**Planning base:** `b129dfb8c83423666f68616bd627f1175e3005b8` (`main` = `HEAD` = merge base)
**Prerequisites:** Stages 1–5 complete and merged
**Goal:** Implement the versioned executable adapter protocol — catalog, bootstrap
descriptor and negotiation, command-discriminated request envelopes, invocation-scoped
JSON Lines events, validation results, adapter result manifests and their sanitized
core projections, exit semantics and reconciliation — plus stdlib-only executable fake
adapters and an offline contract harness that drives every positive and adversarial
protocol case through the merged Stage 5 lifecycle.
**Architecture:** Every new protocol record is a strict frozen `CanonicalModel` in
`crypto_lab.adapters`, which imports `crypto_lab.domain` alone. Pure parsers,
validators, sanitizers and reconcilers turn untrusted adapter bytes into sanitized
core records and verdicts; one new `experiments` operation applies a verdict to the
Stage 5 run and invocation records through the existing ports. Nothing in
`src/crypto_lab` launches a process, reads the filesystem, reads a clock or draws a
random value; the child-process harness and the fake adapters are test-resident.
**Tech stack:** Python 3.12, Pydantic v2 strict models, `hypothesis` for the bounded
property tests, the closed `scripts/invoke-uv.ps1` launcher and `scripts/verify.ps1`.
**Spec:** `docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md`
(sections 8.1–8.2, 10.2–10.3, 11.3–11.5, 13.2–13.4, 14, 15.5, 15.7, 19.1, 19.4,
20–21, 28.2–28.4, 33.2, 33.4, 33.6, 33.7 per the roadmap's Stage 6 row).

## Global Constraints

- Python `>=3.12,<3.13`; runtime dependencies stay exactly `pydantic>=2.12,<3` and
  `pyyaml>=6.0.3,<7`; no dependency, lockfile, `pyproject.toml` or launcher change.
- Every command runs through `scripts/invoke-uv.ps1` profiles; the complete
  verifier `scripts/verify.ps1` is unchanged (its normalized SHA-256 is pinned).
- Branch coverage floor stays 90 percent in `pyproject.toml`; the complete verifier
  must report at least **97.69 percent**, the value measured on the planning base.
- The two approved skips stay exactly two: `tests/safety/test_uv_launcher.py`
  (symbolic-link privilege) and `tests/unit/experiments/test_experiment_service.py`
  (same-state replay cases).
- `crypto_lab.adapters` imports only `crypto_lab.domain` and itself;
  `crypto_lab.experiments` imports only `domain`, `adapters`, `capabilities` and
  itself; no Stage 6 source module imports any root of the §2.6 design-rule list
  (the merged filesystem, environment and infrastructure scans, pinned to the
  fourteen Stage 6 paths; four merged modules already import `pathlib`, which is in
  the allowlist), and no new import root joins the exact 22-root allowlist.
- No real engine, adapter, exchange, market data, backtest, SQLAlchemy, SQLite,
  Alembic, network, credential, wallet, tax, UI, LLM, Docker, cloud or server
  behavior anywhere; GitNexus stays `DISABLED_WITH_EVIDENCE` and is never invoked.
- Adapters are untrusted; every raw attempt token stays out of every persisted or
  sanitized record; no adapter ever receives a database handle or an authoritative
  final path; only the core may finalize a result, and Stage 6 never does.

---

## 1. Goal, scope and exclusions

### 1.1 Goal

Deliver the Stage 6 contracts the roadmap names — "explicit adapter catalog
contracts; bootstrap descriptors; negotiation; command-discriminated request
envelopes; invocation-scoped stdout events; validation results; temporary adapter
result manifests and core-sanitized representations; stable exit mappings;
incremental protocol validation; raw-token redaction; executable fake adapters;
reusable contract vectors; and generated protocol schemas" — consuming, never
redesigning, the Stage 5 `CommandKind`, `CommandInvocationRecord`,
`EngineRunRecord`, `ProcessStartFacts`, `ProcessExitCategory`, identifiers, request
and attempt-token hashes, lifecycle predicates, ports and cancellation and retry
semantics.

### 1.2 In scope

The record inventory of §3 and the hashing profiles of §4; negotiation and the
`describe` flow of §5; request envelopes, argument arrays and the adapter-side
verification contract of §6; the event matrix, framing rules, sequence ledger and
sanitization of §7; validation results, result manifests and sanitized manifests of
§8; exit semantics, reconciliation and the closed Stage 6 diagnostic table of §9;
the one new application operation of §10; the fake adapters and offline harness of
§11; eight generated protocol schemas extending the registry from 27 to 35 with the
existing 27 preserved byte-identical (§12); the safety enforcement map of §13; the
closed-world guard reconciliation of §2.6; and the Stage 6 status, documentation and
guard updates of Task 9.

### 1.3 Out of scope

Nothing below is created, imported or referenced by Stage 6 source: a real trading
engine or adapter; VectorBT, Freqtrade, NautilusTrader, Jesse, OctoBot, Hummingbot or
LEAN; exchange or Binance access; credentials; market-data download; real backtests;
SQLAlchemy, SQLite or Alembic; a production `ProcessSupervisor`, `CancellationToken`
or `MonotonicInstant` (Stage 7); `CandidateArtifact`, `ArtifactRef`, `RunManifest`,
finalization leases, atomic moves or the `EVIDENCE`/`RESULT` finalizers (Stage 9);
paper trading, wallets, tax, UI, LLM, Docker, cloud, server or application
networking. Stage 6 source launches no process: the only child-process code is the
test-resident harness of §11, and the roadmap's exclusion "claims that contract
vectors have passed through the production supervisor before Stage 7" is honoured
by naming the harness a stand-in throughout.

### 1.4 Named forward obligations

| Omission | Reason | Closed by |
|---|---|---|
| Moving a run to `SUCCEEDED` or `SUCCEEDED_WITH_WARNINGS` | Requires finalized `RESULT` artifacts and a core `RunManifest` (spec 14.6, 17.1, 19.4); Stage 6 stops at the `RESULT_FINALIZATION_ELIGIBLE` verdict of §9.3 and leaves the run `RUNNING` | Stage 9 |
| `CandidateArtifact` records for `artifact_produced` declarations | Stage 6 persists the sanitized `RunEvent` and derives the candidate identity (§4); the lifecycle record and repository are artifact contracts | Stage 9 |
| Byte-level candidate validation (size, checksum, reparse points, token scan over files) | Stage 6 compares adapter declarations against caller-supplied `CandidateObservation`s (§9.2); the observing I/O is Stage 9's, and the harness supplies observations in tests | Stage 9 |
| Persisting `Diagnostic`, `NegotiationResult` and `SanitizedAdapterResultManifest` rows | Stage 6 returns them inside `Result` values and `SemanticOutcome`; no table exists before Stage 8 | Stages 8–9 |
| Real deadlines, heartbeat liveness policy, cancellation delivery, stderr pipe capture | The harness emulates them with test-side timers so the codes of §9.4 are provoked; production behaviour is process supervision | Stage 7 |
| `RuntimeAvailabilityObservation` minting after `describe` | §5.4 defines the pure projection over caller-supplied runtime facts and instants (the Stage 5 `ProcessStartFacts` pattern); observing `runtime_version` and choosing expiry are supervisor and composition concerns | Stages 7 and 10 |
| Filesystem write-boundary enforcement (`describe` writes only its output, `run` only inside its work dir) | Spec 14.1; detecting stray writes needs a filesystem scan, which Stage 6 source may not perform; the harness asserts it for the fake adapters only | Stage 7 |
| Stderr capture and segmenting to the 50 MiB budget | Spec 27.1 assigns stderr capture to `process_supervision`; §7.6 hosts the bounded redacting capture early as a pure byte fold in `adapters/sanitization.py` because Stage 7 may not expand canonical contracts and `StderrCapture` is the projection it will return; the pipe reader itself is supervision | Stage 7 |
| `SanitizedEngineRunRequest` as a published evidence schema | Spec 19.1 lists sanitized request snapshots as an artifact class but names no record; Stage 6 defines the model (§3.6) without a permanent `$id` | Stage 9 |
| `Diagnostic` rows derived from adapter-authored diagnostics | Stage 6 keeps adapter diagnostics inside events and manifests (`AdapterDiagnostic`, §3.9) and cites them from core diagnostics through `details`; minting a `DiagnosticId` for them and persisting them is not a Stage 6 output | Stage 8 |
| The replay answer for a run already `SUCCEEDED` or `SUCCEEDED_WITH_WARNINGS` | `reconcile_run` does not admit a success state, so a re-issue of `apply_command_semantic_outcome` after Stage 9 has finalized the run is `CORE.INVARIANT_VIOLATION` (§10 step 4); the stable post-success replay answer belongs to the owner of the success edge | Stage 9 |
| Causal-projection insert-loss residual | Assigned to Stage 8 by the Stage 5 review; not absorbed | Stage 8 |

### 1.5 Carried Stage 5 notes and dispositions

1. **The Stage 5 plan header still reads "implementation not started".** Verified
   unpinned: no test reads that header (the only plan header any test pins is Stage
   4's). It is Stage 5's historical document; correcting it is a docs-only change
   outside this planning task's single-file rule and outside Stage 6's file map.
   Disposition: **LEAVE**; this plan's own header states no implementation status
   so it cannot go stale the same way. A separate docs-only commit may correct the
   Stage 5 header if the user authorizes it.
2. **Stage 5 runtime restrictions absent from published schemas.** No Stage 6
   published schema embeds a Stage 5 **record** (`CommandInvocationRecord`,
   `EngineRunRecord`, `ExperimentRecord`, `RetryDecisionRecord`): `CommandResult`,
   `SemanticReconciliation` and `SemanticOutcome`, the Stage 6 types that carry one, are
   unpublished (§12.1). The Stage 5 value objects a Stage 6 schema nests
   (`AdapterIdentity`, `EngineIdentity`, `FeeAssumptions`, `SlippageAssumptions`,
   `ExecutionAssumptions`) and the enum `CommandKind` render by bare name,
   byte-identically to their existing bodies, and nesting never moves an existing
   file's bytes (`render_schema_files` renders each entry independently). None of
   the Stage 5 residuals lives in those value objects. Disposition: **NO RECORD
   EMBEDDING, NO `$id` CHANGE**; the Stage 5 residual register in
   `docs/development/verification.md` is untouched and Stage 6 adds its own register
   (Task 9).
3. **`transition_run` cannot itself see a live `RUN` invocation.** Confirmed from
   source: its read set is one `engine_runs.get` plus the compare-and-swap. Stage 6
   owns the missing authoritative read through `apply_command_semantic_outcome`
   (§10), which loads the `EXITED` invocation, the run, the experiment's frozen slot
   compatibility and the run's invocation list in one unit of work before any run
   write. `transition_run` and every Stage 5 domain predicate are unchanged.
   Disposition: **OWNED BY STAGE 6 TASK 7** without changing Stage 5 domain
   semantics.
4. **Causal-projection insert-loss residual.** Disposition: **NOT ABSORBED**;
   remains a Stage 8 forward obligation (§1.4).

## 2. Authority and merged interfaces

### 2.1 Authority order

The architecture specification is normative and wins over this plan. The master
roadmap fixes Stage 6 ownership, exclusions and gates. `AGENTS.md`, `README.md` and
`docs/development/verification.md` fix the working and verification workflow. The
merged Stage 1–5 source, tests and schemas are the executable prerequisite
interfaces and may not be reinterpreted. No architecture conflict was found:
every placement below is name movement between files, which spec 8.2 authorizes,
and every Stage 6 rule the spec leaves open is decided in this plan and marked as
a declared reading.

### 2.2 Consumed merged interfaces

Each name is imported from its defining module. Every name below exists on the
planning base.

<!-- consumed -->
| Defining module | Names Stage 6 consumes |
|---|---|
| `crypto_lab.domain.base` | `CanonicalModel`, `SCHEMA_VERSION` |
| `crypto_lab.domain.command_invocation` (constants) | `MAX_DIAGNOSTIC_IDS` (mirrored by the §3.2 collection bounds) |
| `crypto_lab.domain.identifiers` | `ExperimentId`, `RunId`, `InvocationId`, `EventId`, `CandidateArtifactId`, `DiagnosticId`, `ApproximationId`, `AvailabilityObservationId`, `LogicalSlotId`, `Sha256`, `NormalizedIdentifier`, `AttemptToken`, `exact_string_schema`, `validate_prefixed_uuid4` |
| `crypto_lab.domain.time` | `CalendarValidUtcDateTime`, `format_utc` |
| `crypto_lab.domain.financial` | `CanonicalDecimal`, `NonNegativeDecimal` |
| `crypto_lab.domain.records` | `Money` |
| `crypto_lab.domain.diagnostics` | `Diagnostic`, `DiagnosticCategory`, `DiagnosticSeverity`, `ErrorCode`, `BoundedMessage`, `DiagnosticDetailValue`, `DiagnosticDetailKey`, `MAX_DETAIL_COLLECTION`, `_inspect_details` (the bounded-value and secret-key rule, reused by the catalog entry as `_uuid4_shaped` is reused today) |
| `crypto_lab.domain.results` | `Result`, `Success`, `Failure` |
| `crypto_lab.domain.hashing` | `HashingProfile`, `profile_hash`, `sha256_bytes`, `attempt_token_hash`, `_uuid4_shaped` |
| `crypto_lab.domain.canonical_json` | `canonical_json_bytes`, `canonical_json_text` |
| `crypto_lab.domain.versioning` | `SemanticVersion`, `parse_semantic_version` |
| `crypto_lab.domain.comparison_levels` | `ComparisonLevel`, `sorted_comparison_level_enum` |
| `crypto_lab.domain.capability_names` | `VocabularyVersion` |
| `crypto_lab.domain.descriptors` | `AdapterDescriptor`, `EngineDescriptor`, `SupportedSchemaVersion`, `RuntimeAvailabilityObservation`, `OperatingSystem`, `BoundedText`, `ExecutablePath` |
| `crypto_lab.domain.lifecycle` | `CommandKind`, `CommandInvocationState`, `EngineRunState`, `ProcessExitCategory`, `process_exit_category_for`, `RECOGNIZED_NATIVE_EXIT_VALUES`, `TERMINAL_COMMAND_INVOCATION_STATES` |
| `crypto_lab.domain.command_invocation` | `CommandInvocationRecord`, `ProcessIdentity`, `ProcessStartFacts`, `NativeExitValue`, `command_timeout_bounds`, `assert_write_once_enrichment`, `CommandInvocationRuleViolation` |
| `crypto_lab.domain.engine_run` | `EngineRunRecord`, `AttemptTokenMaterial`, `SUCCESS_ENGINE_RUN_STATES`, `assert_run_transition`, `RunEdgeOwner`, `EngineRunRuleViolation` |
| `crypto_lab.experiments.retry` | `evaluate_retry`, `create_successor` (harness only, the row-47 successor) |
| `crypto_lab.domain.aggregation` | `REASON_LATE_NOT_APPLICABLE` (the `COMPAT.LATE_NOT_APPLICABLE` code string, imported by `adapters/diagnostics.py`) |
| `crypto_lab.domain.experiment` | `AdapterIdentity`, `EngineIdentity`, `FeeAssumptions`, `SlippageAssumptions`, `ExecutionAssumptions`, `SlotCompatibility`, `ExperimentRecord` |
| `crypto_lab.domain.compatibility` | `CompatibilityOutcome` |
| `crypto_lab.domain.ports` | `Clock` |
| `crypto_lab.adapters.versioning` | `highest_common_stable_version` |
| `crypto_lab.adapters.ports` | `CommandInvocationRepository` |
| `crypto_lab.experiments.ports` | `EngineRunRepository`, `ExperimentRepository`, `UnitOfWork` |
| `crypto_lab.experiments.requests` | `REQUEST_OPERATIONS` (the operation of §10 joins it), `RunTransitionRequest`, `InvocationTransitionRequest` |
| `crypto_lab.experiments.run_service` | `run_replacement`, `run_rule_failure`; harness only: `create_attempt`, `transition_run` |
| `crypto_lab.experiments.invocation_service` | harness only: `create_invocation`, `transition_invocation`, `begin_linked_launch`, `start_linked_run`, `transition_invocation_and_run`, `enrich_invocation` |
| `crypto_lab.experiments.experiment_service` | `run_operation`, `LostSwap`; harness only: `create_experiment`, `transition_experiment`, `queue_experiment` |
| `crypto_lab.experiments.diagnostics` | `stage5_failure`, `CONCURRENCY_CONFLICT`, `INVARIANT_VIOLATION` (consumed by `experiments/semantic_outcome.py` only); `UNRECOGNIZED_PROCESS_EXIT` and `STAGE5_DIAGNOSTIC_CODES` are **test-only** consumers — `adapters` may not import `experiments`, so `adapters/diagnostics.py` spells its own `PROCESS.UNRECOGNIZED_PROCESS_EXIT` literal and the equality of the two postures is a test assertion |
| `crypto_lab.schema_registry` | `SCHEMA_DEFINITIONS`, `SchemaDefinition`, `render_schema_files` |
<!-- /consumed -->

The test tree consumes `tests/doubles/experiments.py` (`InMemoryBackingStore`,
`InMemoryUnitOfWork`, `FixedClock`, `SequentialIdentitySource`, the `sample_*`
helpers, `RecordingUnitOfWork`) and `tests/safety/test_stage3_boundaries.py`'s
scanner helpers (same-directory import, the merged `test_stage5_boundaries`
precedent). The architecture scanner of
`tests/architecture/test_package_import_boundaries.py` needs no edit and is not
imported: its two boundary tests walk every `src/crypto_lab/adapters` and
`experiments` module by `rglob`, so the fourteen Stage 6 modules are covered as
written (a cross-directory import from `tests/safety/` would resolve only by
collection order and fail the §15.1 focused command).

### 2.3 Placement decision

**Every new Stage 6 record, enum, parser, sanitizer and reconciler lives in
`crypto_lab.adapters`; the one new application operation lives in
`crypto_lab.experiments`.** Spec 27.1 gives `adapters` the "descriptor, request,
event, manifest, command, exit-category, and negotiation contracts; explicit adapter
catalog interface" with `domain` as its only inward dependency, and 27.2 lists
`adapters/descriptors.py, envelopes.py, events.py, manifests.py, exit_codes.py,
negotiation.py, catalog.py` while permitting splits. Unlike Stage 5, no
impossibility forces relocation into `domain`: `experiments` may import `adapters`;
`process_supervision` (Stage 7) may import `domain`, `adapters` and `audit`; and
`persistence` (Stage 8) already implements `crypto_lab.adapters.ports`. The seven
modules beyond the 27.2 list — `vocabulary.py`, `limits.py`, `paths.py`,
`diagnostics.py`, `sanitization.py`, `commands.py`, `reconciliation.py` — are
splits of the listed responsibilities. Two identifier aliases (`RequestId`,
`AdapterManifestId`) and four `HashingProfile` members join `domain` because
identifiers and hashing profiles are `domain`'s (spec 27.1).

Forward note: `artifacts` (Stage 9) may import only `domain`. If Stage 9 needs
`SanitizedAdapterResultManifest` as a model rather than as canonical bytes plus
hash, it relocates the class to `domain` with an `adapters` re-export; `$defs` are
keyed by bare class name, so the published bytes do not move.

### 2.4 Frozen-byte constraints

All 27 committed schemas are digest-pinned (`_STAGE3_SHA256`, `_STAGE4_SHA256`,
`_STAGE5_SHA256`). Stage 6 therefore edits no Stage 3–5 model, docstring, `Field`
bound, validator or `json_schema_extra`. Consequences, each proven by the digest
gate rather than asserted:

1. **No new `DiagnosticCategory` member and no change to `Diagnostic`.** Every
   Stage 6 code maps onto an existing member (§9.4). `Diagnostic.timestamp_utc` is
   the legacy `UtcDateTime`, so **no published Stage 6 schema may embed
   `Diagnostic`**: nesting it would re-render the legacy `$defs/UtcDateTime` inside a
   non-Stage-3 entry and fail the forward-view guard of §2.5. Adapter-emitted
   diagnostics are the protocol-side `AdapterDiagnostic` model (§7.2), which has no
   timestamp of its own.
2. **No change to `ProcessExitCategory`, `CommandKind`, `AdapterDescriptor`,
   `EngineDescriptor`, `SupportedSchemaVersion` or `RuntimeAvailabilityObservation`.**
   Nesting them in a new file re-renders byte-identical `$defs` there and moves
   nothing in an existing file.
3. **Bare-name uniqueness.** A Stage 6 class reachable from a published root must
   not share a bare name with another reachable class (pydantic would fall back to
   module-qualified keys). Protocol models therefore use distinct names:
   `AdapterDiagnostic` not `Diagnostic`, `CandidateArtifactDeclaration` not
   `CandidateArtifact`, `CandidateMetric` not `MetricValue`, `ProtocolWarning` not
   `Warning`.
4. **New identifier aliases and `HashingProfile` members are safe** because no
   published schema reaches `HashingProfile` (asserted by an existing render scan)
   and each alias appears only in Stage 6 files.

### 2.5 Published-timestamp and pattern rules

Every Stage 6 timestamp field reachable from a registered schema is
`CalendarValidUtcDateTime`; the merged guard
`test_every_published_stage_four_timestamp_uses_the_forward_view` iterates every
non-Stage-3 registry entry and needs no edit. Every published string pattern ends
in the project's `(?![\s\S])` form through `exact_string_schema`, never in `$`.

### 2.6 Closed-world guard reconciliation

The merged tree enforces closed sets by exact equality. Every such guard Stage 6
trips is reconciled here, assigned to the task whose work first trips it, and none
is weakened, deleted or replaced by a lower bound. **This section is the single
authority for every guard edit Stage 6 makes to a Stage 1–5 test file**; the two
non-guard test-tree extensions (`tests/unit/domain/test_identifiers.py`, Task 1;
`tests/doubles/experiments.py`, Task 4) are listed in their tasks and in §16. It was derived
by enumerating every `assert`, parametrize literal and module constant in the
sixteen guard files with `ast`, then adding the five exact pins outside those files
that the critics located (`test_port_contracts`, `test_lifecycle_tables`,
`test_domain_ports`, `test_experiment_service`, `test_engine_run_record`).

**Rule.** A task that creates a module under `src/crypto_lab` appends that module,
in the same commit, to both `_ALLOWED_SOURCE_FILES` in
`tests/safety/test_stage3_boundaries.py` and `PACKAGE_MODULES` in
`tests/unit/test_package_layout.py`. A task that first defines a name held in
`_DEFERRED_DEFINITIONS` removes exactly that name, in the same commit, from the set
and the literal set-equality assertion and decrements the pinned count by one per
name. A name is never released before the commit that defines it.

**Source-file allowlist.** `_ALLOWED_SOURCE_FILES` is a literal set of 69 paths at
the planning base. Stage 6 adds exactly 14 paths, taking it to 83; the same 14
dotted names join `PACKAGE_MODULES`.

| Task | Paths appended (relative to `src/crypto_lab`) | Running size |
|---|---|---|
| 1 | `adapters/vocabulary.py`, `adapters/limits.py`, `adapters/paths.py`, `adapters/catalog.py`, `adapters/diagnostics.py` | 74 |
| 2 | `adapters/envelopes.py`, `adapters/commands.py` | 76 |
| 3 | `adapters/negotiation.py` | 77 |
| 4 | `adapters/events.py`, `adapters/sanitization.py` | 79 |
| 5 | `adapters/manifests.py` | 80 |
| 6 | `adapters/exit_codes.py`, `adapters/reconciliation.py` | 82 |
| 7 | `experiments/semantic_outcome.py` | 83 |

**Deferred-definition guard.** `_DEFERRED_DEFINITIONS` holds 53 names, asserted by
`len == 53` and an exact literal set in
`test_the_deferred_definition_set_is_exactly_the_reviewed_sixty_five` (the test
name is historical and is kept; its docstring arithmetic gains a Stage 6
paragraph), enforced against every `class`/`def` in `src/crypto_lab`, self-tested
per name and by a seven-name representative-mutation list. Stage 6 defines exactly
16 of the 53 and releases each in its defining task; the final count is
`53 − 16 = 37`.

| Task | Names released | Running count |
|---|---|---|
| 1 | `SemanticStatus`, `ValidationOutcome`, `AdapterCatalog`, `AdapterCatalogEntry` | 49 |
| 2 | `AdapterCommandRequestEnvelope`, `EngineRunRequest`, `AdapterCommand` | 46 |
| 3 | `BootstrapDescriptorEnvelope`, `NegotiationResult`, `negotiate_protocol` | 43 |
| 4 | `ProtocolEventEnvelope`, `RunEvent` | 41 |
| 5 | `AdapterValidationResult`, `AdapterResultManifest`, `SanitizedAdapterResultManifest` | 38 |
| 6 | `CommandResult` | 37 |

<!-- released-names -->
Released (16): `SemanticStatus`, `ValidationOutcome`, `AdapterCatalog`,
`AdapterCatalogEntry`, `AdapterCommandRequestEnvelope`, `EngineRunRequest`,
`AdapterCommand`, `BootstrapDescriptorEnvelope`, `NegotiationResult`,
`negotiate_protocol`, `ProtocolEventEnvelope`, `RunEvent`, `AdapterValidationResult`,
`AdapterResultManifest`, `SanitizedAdapterResultManifest`, `CommandResult`.
<!-- /released-names -->

<!-- remaining-names -->
Remaining deferred (37), which no Stage 6 module may define under these exact
names: `ArtifactFinalizationPurpose`, `ArtifactFinalizer`, `ArtifactOwnerKind`,
`ArtifactRef`, `ArtifactRepository`, `ArtifactSourceRole`, `AuditSink`,
`AuditEvent`, `CancellationToken`, `CandidateArtifact`,
`CandidateArtifactRepository`, `CandidateArtifactState`,
`CandidateArtifactProducerKind`, `CandidateFinalization`, `CanonicalFill`,
`CanonicalOrder`, `ComparisonEligibilityService`, `ContentHasher`,
`DatasetRepository`, `EquityPoint`, `EvidenceFinalizationRequest`, `Fee`,
`FinalizationResult`, `MetricValue`, `MonotonicInstant`, `OrderSide`, `OrderType`,
`PortfolioSnapshot`, `PositionSnapshot`, `PositionEffect`, `ProcessSupervisor`,
`ResultFinalizationRequest`, `Result`, `RunManifest`, `ingest_dataset`,
`normalize_dataset`, `place_order`.
<!-- /remaining-names -->

`Result` stays the existing `type` alias in `domain/results.py`, which the
`ClassDef`/`FunctionDef` walk does not visit. The seven-name representative-mutation
list loses four live names; each releasing task swaps in a still-deferred name so
the self-test keeps seven live cases: Task 1 `ValidationOutcome` →
`ProcessSupervisor`, Task 2 `EngineRunRequest` → `RunManifest`, Task 4 `RunEvent` →
`ArtifactRef`, Task 5 `AdapterResultManifest` → `CandidateArtifact`.

**Schema-registry guards.** Stage 6 extends the registry from 27 to 35 entries,
preserving Stage 3 at positions 0–10, Stage 4 at 11–19, Stage 5 at 20–26 and
placing Stage 6 at 27–34. Task 9 owns every row.

| File | Assertion | Change |
|---|---|---|
| `tests/unit/test_schema_registry.py` | `_STAGE3_SHA256`, `_STAGE4_SHA256`, `_STAGE5_SHA256` blocks and their key and disjointness tests | unchanged, plus a Stage-6-absent assertion in the Stage 5 key test |
| same | `_EXPECTED` path→`$id` map and its consumers | +8 entries |
| same | `len(SCHEMA_DEFINITIONS) == 27` and the three `== 27` counts in the ordered-tuple test | `== 35` |
| same | `_ordered_paths()[20:] == _STAGE5_PATHS` (two occurrences) | `[20:27] == _STAGE5_PATHS`; new `_STAGE6_PATHS` tuple (`len == 8`), `_ordered_paths()[27:] == _STAGE6_PATHS`, every path `startswith("protocol/")`, every `$id` `startswith("urn:crypto-lab:schema:protocol:")` |
| same | `paths == _STAGE3_PATHS + _STAGE4_PATHS + _STAGE5_PATHS` and the `$id` twin | `+ _STAGE6_PATHS` |
| same | `_EXPECTED_ADAPTED_TYPES` and the singleton-plus-adapted `== 27` | +8 fresh `TypeAdapter` entries, no new singleton; `== 35` |
| same | `len(rendered) == 27`; directory census `== 27`; committed-file loop | `== 35`; include `_STAGE6_PATHS` |
| same | `test_the_twenty_pre_existing_schemas_are_byte_identical_after_stage_five` (`len(frozen) == 20`) | renamed to the twenty-seven form; frozen = Stage 3 + 4 + 5 digests, `== 27` |
| same | new `_STAGE6_SHA256` (8 digests keyed on paths) with key-equality, `== 8` and Stage-3/4/5-absent assertions | added |
| same | new `_STAGE6_CLOSED_ENUMS`, `_STAGE6_REQUIRED`, `_STAGE6_OPTIONAL`, `_STAGE6_UNIQUE_POINTERS`, baselines, expressible-violation tables and the one-directional residual pin | added per §12.3 |
| `tests/unit/domain/test_domain_descriptors.py` | `len(rendered) == 27` | `== 35` |
| `tests/safety/test_stage3_boundaries.py` | `len(paths) == 27` over `SCHEMA_DEFINITIONS` | `== 35` |
| `tests/integration/test_schema_distribution.py`, `scripts/generate_schemas.py`, `scripts/verify_schema_distribution.py`, `pyproject.toml` | derive expected paths from the registry | unchanged |

**Other exact pins.**

| File | Assertion | Change | Task |
|---|---|---|---|
| `tests/unit/domain/test_lifecycle_tables.py` | `len(HashingProfile) == 8` and `len({member.value ...}) == 8` | `== 12`; the render scan (`test_the_two_stage_five_hashing_profiles_exist_and_reach_no_schema`) asserts the two Stage 5 profile values absent from every render, and the four new value strings join that loop | 1 |
| `tests/unit/domain/test_domain_ports.py` | `IdentitySource` has exactly the five Stage 5 methods; `Clock` exactly `now_utc` | unchanged: Stage 6 derives `request_id`, `candidate_artifact_id` and diagnostic identities (§4) and accepts adapter-minted `event_id` and `adapter_manifest_id`, so no port method is added | — |
| `tests/unit/experiments/test_port_contracts.py` | `members(EngineRunRepository) == {get, add_attempt, compare_and_swap, count_attempts, latest_attempt, get_by_attempt_number}` and `not hasattr(EngineRunRepository, "append_event")` | member set gains `append_event` and `list_events`; the `hasattr` negative becomes the positive `hasattr` pair with a docstring citing §7.5 | 4 |
| same | `set(STAGE5_DIAGNOSTIC_CODES)` exactly six | unchanged: Stage 6 has its own closed table (§9.4) | — |
| `tests/unit/experiments/test_experiment_service.py` | `len(REQUEST_OPERATIONS) == 16`, `set(REQUEST_OPERATIONS) == set(_FIELD_ORDERS)`, `tuple(REQUEST_OPERATIONS.values()) == _OPERATION_NAMES`, `== 16` on distinct values | `== 17`; `_FIELD_ORDERS` and `_OPERATION_NAMES` gain `SemanticOutcomeRequest` → `apply_command_semantic_outcome` as the seventeenth entry | 7 |
| `tests/safety/test_stage5_boundaries.py` | `STAGE5_SOURCE_FILES` exactly 18; `scanned >= 12`; `_EXPECTED_READER_IMPLEMENTATIONS` exactly four; single traversal owner; whole-tree infrastructure, ambient-clock and test-double scans | unchanged by rule: no Stage 6 module joins the Stage 5 tuple; no Stage 6 test class defines both `get` and `get_many`; no Stage 6 code reads `causal_diagnostic_ids` or calls `get_many` | — |
| `tests/safety/test_stage4_boundaries.py` | `_BARE_FORBIDDEN_NAMES` over every `ast.Name`/`ast.Attribute` in `src` | unchanged by rule: no Stage 6 identifier is `buffer`, `context`, `note`, `problem`, `compose` or `Loader` (the incremental parser names its carry-over `pending_bytes`) | — |
| `tests/unit/domain/test_engine_run_record.py`, `tests/unit/experiments/test_aggregation.py` | module-scoped deferred-name negatives for `domain/engine_run.py` and `experiments/aggregation.py` | unchanged: neither module is edited | — |
| `tests/unit/domain/test_domain_capability_contracts.py` | `crypto_lab.domain.__all__` resolves exactly once (ordering is `RUF022`'s) | unchanged: the two new exports (`RequestId`, `AdapterManifestId`) resolve and are unique; their sorted position is `RUF022`'s concern, not this test's | — |
| `tests/safety/test_uv_launcher.py` | launcher hash, `len(_EXPECTED_OPERATIONS) == 20` | unchanged | — |
| `tests/safety/test_project_dependencies.py`, `test_forbidden_runtime_paths.py`, `test_stage4_yaml_runtime.py`, `tests/unit/test_cli.py` | dependencies, ignored roots, yaml importer, version | unchanged | — |

**Documentation and status pins.** Task 9 owns every change below in the one commit
that changes the prose, and introduces `STAGE6_IMPLEMENTATION_COMMIT` (the Task 8
commit, the last commit that adds Stage 6 behaviour), asserted to match
`[0-9a-f]{40}` and to differ from every previously pinned commit.

| File | Assertion | Stage 6 successor |
|---|---|---|
| `tests/safety/test_stage3_boundaries.py` | `_STAGE5_ROADMAP_STATUS_LINE` ("Stages 1 through 5 complete"), three occurrences | `_STAGE6_ROADMAP_STATUS_LINE`: "**Status:** Approved planning decomposition; Stages 1 through 6 complete" |
| same | `_STAGE5_ROADMAP_PLAN_SENTENCE`, two occurrences | "Stages 1 through 6 have approved detailed implementation plans." |
| same | `_STAGE5_ROADMAP_ROW` (ends "; Stage 6 not started \|"), two occurrences | identical row text with the final clause "; Stage 6 complete \|" |
| same | the README status heading `"**Status:** Project 1 Stages 1-5 complete"` | "**Status:** Project 1 Stages 1-6 complete" |
| same | `_README_STAGE5_STATUS in readme` | `_README_STAGE6_STATUS`: Stage 6 complete at `STAGE6_IMPLEMENTATION_COMMIT`; eight protocol schemas; closed 35-schema registry; fake adapters run only through the test-resident harness; "Stage 7 has not started." |
| same | `_VERIFICATION_STAGE5_STATUS in guide` | `_VERIFICATION_STAGE6_STATUS`: same facts; "The closed 35-schema registry holds the eight new Stage 6 schemas together with the twenty-seven Stage 3, 4 and 5 schemas, preserved byte-identical to `main`. Stage 7 is not started." |
| same | `STAGE5_IMPLEMENTATION_COMMIT in readme / guide` | roadmap keeps the Stage 5 hash in its history row; README and guide assert `STAGE6_IMPLEMENTATION_COMMIT`; new assertion pins `STAGE6_IMPLEMENTATION_COMMIT in roadmap` |
| same | `"Stage 6" not in readme_rest / guide_rest` | `"Stage 7" not in readme_rest`; for the guide, subtract the one legitimate sentence "Stage 7 retains physical ancestor reparse-point and volume containment." (pinned positively as a constant) before asserting `"Stage 7" not in guide_rest` |
| same | `_README_STAGE4_STATUS not in readme`, `_VERIFICATION_STAGE4_STATUS not in guide`, `STAGE4_IMPLEMENTATION_COMMIT not in readme` and `not in guide` | the four negatives gain their Stage 5 successors (`_README_STAGE5_STATUS not in readme`, `_VERIFICATION_STAGE5_STATUS not in guide`, `STAGE5_IMPLEMENTATION_COMMIT not in readme` and `not in guide`); the Stage 4 negatives are kept | 9 |
| same | `"exhaustiv" not in …rest.lower()`, retired phrases, `_VERIFICATION_CORPUS_QUALIFICATION`, `_VERIFICATION_NON_GOALS` | unchanged; Stage 6 prose reintroduces none |
| `tests/safety/test_stage5_boundaries.py` | `_STAGE6_ROADMAP_ROW in roadmap` (deferred row); `for later in ("Stage 7", ..., "Stage 10"): assert later not in readme` | the deferred-row positive becomes a negative; the loop subtracts `_README_STAGE6_STATUS` first and shifts to `("Stage 8", "Stage 9", "Stage 10")`; the Stage 6 completion row and the Stage 7 deferred row are pinned by the new `tests/safety/test_stage6_boundaries.py` |
| `tests/safety/test_gitnexus_development_tooling.py` | duplicate pins of the roadmap plan sentence and status line | the same two Stage 6 successors |
| roadmap | Stage 6 "**Planned detailed implementation plan:**" line | "**Approved detailed implementation plan:**" with the same path, pinned by the Stage 6 guard together with the negative of the planned form |

Roadmap, README and guide edits all land in Task 9, following the Stage 5
precedent in which the plan-approval commit touched only the plan file.

**Design rules (no test edit; every task obeys).** No new import root; no
`pathlib`, `os`, `sys`, `io`, `importlib`, `shutil`, `tempfile`, `glob`,
`subprocess`, `time`, `random`, `secrets` or `open()` in any Stage 6 source module
(the Stage 6 guard pins the fourteen paths to the Stage 5 filesystem scan); no
`types` root; no yaml import; no `# type: ignore[import]`; no pytest marker (the
suite runs with `--strict-markers` and `pyproject.toml` is untouched); every
Stage 6 `subprocess` call (the harness launch helper, `Popen`) carries the
repository's `# noqa: S603 - reviewed …` comment, `shell=False`, a list argument
array and `env={}` (the nine merged importers keep their own reviewed comments and
environments; `test_harness_safety.py` pins `env == {}` on the helper alone); every new test file
has a basename unique across `tests/` (mypy resolves test modules by basename);
`RUF022` keeps every `__all__` sorted.

### 2.7 Toolchain gates

`ruff check` selects `B, DTZ, E, F, I, PT, RUF, S, UP` with only `S101` ignored
under `tests/`; `ruff format --check` is check-only, so formatter output is applied
by hand; strict mypy covers `src`, `tests` and `scripts`, including
`tests/fake_adapters/fake_adapter.py`; `pytest-all` runs with coverage over
`crypto_lab` only, so the fake adapter and harness are not measured but every Stage
6 source module counts toward the 97.69 percent target; `pytest-focused` accepts
only `-o addopts=`, targets under `tests/` and a final `-q`.

## 3. Protocol record inventory (matrix A)

### 3.1 Shared conventions

All Stage 6 models are frozen strict Pydantic v2 models deriving from
`CanonicalModel`, with one exception: the internal header readers (§3.11's
`OutputHeader` and `DescriptorHeader`, §7.4's event header) are `extra="ignore"`
models that are never published or persisted (the parse outcomes carry them to the
reconcilers' identity checks and no further). Every top-level record carries `schema_version: Literal["1.0.0"]`
first; every wire record additionally carries `protocol_version: Literal["1.0.0"]`
second (§5.1 explains why both are exact literals), except the bootstrap descriptor
envelope and the describe payload, which carry `bootstrap_schema_version` instead
(spec 14.2 fixed fields). Nested value objects, class-P projections and parse
outcomes carry no envelope version (the merged `AttemptCreation` precedent). Absence is `MISSING` (the `pydantic.experimental.missing_sentinel` sentinel every merged record module imports), never `None`; a collection whose absence has
no distinct meaning is a required, possibly empty, tuple. Collections whose order
carries no meaning are sorted and unique and are rejected otherwise. Every bound
below is a compiled literal in `adapters/limits.py` (§3.2) or on the field. No model
reads the environment, filesystem, clock or a random source; every instant a core
record carries comes from the injected `Clock`, and every instant an adapter record
carries is adapter-declared data.

**Trust classes.** **W** = untrusted temporary wire input written or emitted by the
adapter; may carry the raw attempt token where the row says so; never persisted,
never finalized. **C** = core-authoritative record produced only after validation;
carries `attempt_token_hash`, never the raw token. **P** = core projection returned
inside `Result` values or `CommandResult`; unpublished. **K** = core-owned
configuration-shaped contract.

### 3.2 Limits — `adapters/limits.py`

| Constant | Value | Source |
|---|---|---|
| `PROTOCOL_VERSION` | `"1.0.0"` | spec 10.4; the single version the core supports |
| `MAX_EVENT_LINE_BYTES` | `1_048_576`; floor `MIN_EVENT_LINE_BYTES = 4_096` | spec 14.7; `ProtocolConfig.max_event_bytes` bounds |
| `MAX_RESULT_MANIFEST_BYTES` | `16_777_216`; floor `65_536` | spec 14.7; `ProtocolConfig.max_manifest_bytes` |
| `MAX_STDERR_BYTES` | `52_428_800`; floor `1_048_576` | spec 14.7; `LoggingConfig.max_stderr_bytes_per_invocation` |
| `MAX_DESCRIPTOR_OUTPUT_BYTES`, `MAX_VALIDATION_RESULT_BYTES` | `1_048_576` each | declared reading: spec 24.3 bounds every output; the spec names no ceiling for these two files, so the event ceiling is reused |
| `MAX_SEQUENCE` | `1_000_000` | declared reading: spec 11.5 requires a published bound; the command deadline bounds duration, this bounds the ledger |
| `MAX_CANDIDATE_ARTIFACTS`, `MAX_CANDIDATE_METRICS` | `256` each | declared reading |
| `MAX_ADAPTER_DIAGNOSTICS`, `MAX_WARNINGS`, `MAX_APPROXIMATIONS` | `64` each | declared reading; matches `MAX_DIAGNOSTIC_IDS` |
| `MAX_CAUSAL_EVENT_IDS` | `32` | mirrors `Diagnostic.causal_diagnostic_ids` |
| `MAX_DECLARED_SIZE_BYTES`, `MAX_COUNTER` | `2**53 − 1` | declared reading: exact in JSON number space |
| `MAX_RELATIVE_PATH_CHARACTERS`, `MAX_PATH_SEGMENTS`, `MAX_SEGMENT_CHARACTERS` | `512`, `32`, `255` | §3.3 |
| `MAX_CONTAMINATION_SAMPLE_BYTES` | `256` | §7.6 |
| `MAX_CATALOG_ENTRIES` | `32` | `AdaptersConfig.entries` bound copied as a literal |
| `RESULT_MANIFEST_RELATIVE_PATH` | `"adapter-result-manifest.json"` | declared reading: the `--result` path is always this name directly under the work dir, so `FINAL_RESULT.manifest_relative_path` must equal it |
| `HEARTBEAT_INTERVAL_BOUNDS`, `MISSING_HEARTBEAT_BOUNDS` | `1..300`, `2..900`, missing ≥ 2 × interval | `ProcessConfig` bounds copied as literals |

`ProtocolLimits` (nested, **K**): `max_event_bytes`, `max_manifest_bytes`,
`max_stderr_bytes`, `heartbeat_interval_seconds`, `missing_heartbeat_seconds`, each
bounded as above; the snapshot the request carries (§3.6). `PROTOCOL_LIMITS_DEFAULT`
is the instance built from the defaults.

### 3.3 Candidate relative paths — `adapters/paths.py`

`RelativeCandidatePath` is a strict `str` alias validated by
`validate_relative_candidate_path` and published through `exact_string_schema`.
Declared reading of spec 15.5 "relative, normalized, free of drive prefixes, free of
alternate data-stream syntax, and free of `..` traversal" for a textual check on a
Windows host, deliberately over-strict:

1. total length 1–`MAX_RELATIVE_PATH_CHARACTERS`; 1–`MAX_PATH_SEGMENTS` segments
   separated by exactly one `/`; every segment 1–`MAX_SEGMENT_CHARACTERS` characters
   matching `^[A-Za-z0-9][A-Za-z0-9._-]*$` (the three values live in §3.2 only);
2. hence rejected by construction: a leading or trailing `/`, an empty segment, any
   `\`, `:` (drive and alternate-data-stream syntax), whitespace, control characters,
   non-ASCII text, percent signs, UNC or device prefixes;
3. a segment may not be `.` or `..` and may not end in `.` (Windows trailing-dot
   aliasing);
4. a segment whose stem before the first `.` is, case-insensitively, `CON`, `PRN`,
   `AUX`, `NUL`, `COM1`–`COM9` or `LPT1`–`LPT9` is rejected.

Each accepted shape in the tests is paired with its rejected near-miss (`a/b.json`
against `a//b.json`, `./a`, `a/.`, `a\b`, `C:/a`, `a:stream`, `a/..`, `a/../b`,
`/a`, `a/`, `a%2e%2e/b`, `CON.json`, `con.json`, `LPT9`, `a./b`, `a b`, `ä`, a
513-character path, 33 segments, a 256-character segment), and the reserved-stem
rule is proven not over-broad by the accepted lookalikes `CONX.json`, `COM10` and
`a.b/c`. Containment against a real root, link and reparse-point rejection remain
Stage 7 and Stage 9; Stage 6 asserts the text alone.

Prior art: `datasets/models.py` already defines `RegistryRelativePath` with the same
reserved-stem, trailing-dot and dot-segment rejections for registry paths;
`adapters` may import only `domain`, so §3.3 is a separate grammar in
`adapters/paths.py`, kept textually aligned with it, and moving the shared pattern
into `domain` is a later refactor, not a Stage 6 task.

### 3.4 Vocabularies — `adapters/vocabulary.py`

| Enum | Members | Source |
|---|---|---|
| `SemanticStatus` | `SUCCEEDED`, `SUCCEEDED_WITH_WARNINGS`, `FAILED`, `CANCELLED`, `TIMED_OUT`, `NOT_APPLICABLE`, `UNAVAILABLE` | spec 11.5 |
| `ValidationOutcome` | `VALID`, `NOT_APPLICABLE`, `UNAVAILABLE`, `INVALID` | spec 11.5 |
| `ProtocolEventType` | `HEARTBEAT`, `PROGRESS`, `WARNING`, `DIAGNOSTIC`, `ARTIFACT_PRODUCED`, `FINAL_RESULT` | spec 14.4 names; uppercase per spec 11.1 (declared reading: the 14.4 table spellings are labels, 11.1 fixes serialization) |
| `NegotiationOutcome` | `NEGOTIATED`, `FAILED` | spec 11.5 lists none; declared reading of 14.2 |
| `ProtocolIntegrityStatus` | `INTACT`, `VIOLATED` | spec 14.1 "protocol-integrity status" |
| `ReconciliationVerdict` | `DESCRIBED`, `DESCRIBE_UNAVAILABLE`, `VALIDATED_READY`, `NOT_APPLICABLE`, `UNAVAILABLE`, `FAILED`, `RESULT_FINALIZATION_ELIGIBLE` | §9.3 |
| `AdapterDiagnosticCategory` | `ENGINE_RUNTIME`, `ADAPTER_UNAVAILABILITY`, `COMPATIBILITY` | §7.2; the three `DiagnosticCategory` members an adapter may claim |

### 3.5 Catalog — `adapters/catalog.py`

`AdapterCatalogEntry` (**K**): `adapter_name` (`NormalizedIdentifier`),
`adapter_version` (`SemanticVersion`), `engine` (`EngineIdentity`),
`executable_path` (`ExecutablePath`, additionally required to be an absolute local
Windows path by the regex `^[A-Za-z]:[\\/]` with no `..` segment), `executable_hash`
(`Sha256`), `runtime_metadata` (`dict[DiagnosticDetailKey, DiagnosticDetailValue]`,
at most `MAX_DETAIL_COLLECTION` keys; the bounded JSON value union of `domain`
reused so `adapters` needs no `configuration` import). `AdapterCatalog` is a
`runtime_checkable` `Protocol` with `get(adapter_name: str, adapter_version: str) ->
Result[AdapterCatalogEntry]` and `list_registered() -> tuple[AdapterCatalogEntry,
...]` (spec 8.2 verbatim). `FrozenAdapterCatalog(entries, *, clock: Clock)` is the
pure concrete catalog: at most `MAX_CATALOG_ENTRIES` entries, unique on
`(adapter_name, adapter_version)` and sorted; `get` returns a `Failure` carrying
`ADAPTER.UNAVAILABLE` (§9.4) with the requested identity in `details` for a missing
entry, because an unregistered adapter is an ordinary availability fact, and the
diagnostic's instant comes from the injected clock (the doubles' `_Failures(clock)`
pattern; the spec 8.2 `get` signature is unchanged); `list_registered` returns the
sorted tuple. The catalog never scans a directory. The composition root (Stage 10)
projects `AdapterEntryConfig` rows into entries.

### 3.6 Requests — `adapters/envelopes.py`

`DescribeRequestPayload` (**W**, token-free): `bootstrap_schema_version:
Literal["1.0.0"]` first, then `adapter_name`, `adapter_version` (the catalog
identity the core expects the adapter to describe), `executable_hash`,
`core_supported_protocol_versions`
(`tuple[SemanticVersion, ...]`, 1–32, sorted unique),
`core_supported_schema_versions` (`tuple[SupportedSchemaVersion, ...]`, 1–128,
sorted unique on `(schema_name, version)` with numeric version order — the
`parse_semantic_version` rule of the merged `AdapterDescriptor.validate_schema_versions`), `core_capability_vocabulary_versions`
(`tuple[VocabularyVersion, ...]`, 1–8, sorted unique).

`WorkDirectoryReference` (nested): `authorized_root: Literal["RUNTIME_ROOT"]`,
`relative_path: RelativeCandidatePath` (spec 11.3 "an authorized root plus safe
relative references"; the absolute directory travels only on the argument array).

`RunConfigurationSnapshot` (nested): `starting_balance` (`Money`, positive amount),
`fee_assumptions`, `slippage_assumptions`, `execution_assumptions` (the Stage 5
value objects), `comparison_level` (`ComparisonLevel`), `approximation_ids`
(`tuple[ApproximationId, ...]`, sorted unique, ≤ `MAX_APPROXIMATIONS`, copied from the frozen
`SlotCompatibility` of the run's slot so the adapter can echo them in its manifest),
`limits` (`ProtocolLimits`). Declared reading of spec 11.3 `configuration_snapshot`,
13.4 "approximation records attached to request" and 15.3 "snapshotted into the
immutable request": the material assumptions the adapter needs plus the protocol
limits, all copied from the frozen `ExperimentSpec`, the frozen slot compatibility
and the queued configuration.

`NegotiatedVersions` (nested): `protocol_version: Literal["1.0.0"]`,
`schema_versions` (`tuple[SupportedSchemaVersion, ...]`, exactly the five negotiable
names of `NEGOTIABLE_SCHEMA_NAMES`, §5.2 — a Task 1 constant in
`adapters/vocabulary.py`, so Task 2 can consume it), `capability_vocabulary_version`
(`VocabularyVersion`). Spec 14.2
"chosen versions are pinned in the request".

`EngineRunRequest` (**W**, token-bearing; spec 11.3 row in order plus the pinned
versions and two provenance hashes the manifest must echo): `schema_version`,
`protocol_version`, `request_id` (`RequestId`), `experiment_id`, `run_id`,
`logical_slot_id`, `attempt_number` (`1..5`), `attempt_token` (`AttemptToken`,
`repr=False`), `strategy_version_hash`, `dataset_version_hash`, `adapter`
(`AdapterIdentity`), `engine` (`EngineIdentity`), `configuration_snapshot`,
`configuration_hash`, `comparison_level`, `negotiated_versions`,
`assigned_work_dir` (`WorkDirectoryReference`), `experiment_spec_hash`,
`request_hash`, `created_at_utc`. Validators: `comparison_level ==
configuration_snapshot.comparison_level`; `request_hash == request_hash_of(self)`
(§4), which is well-founded because the profile excludes `request_hash` itself.

`SanitizedEngineRunRequest` (**C**, unpublished): the same fields with
`attempt_token` replaced by `attempt_token_hash: Sha256`; built only by
`sanitize_engine_run_request(request)`.

`AdapterCommandRequestEnvelope` (**W**; field order per spec 11.3 — spec 14.3
lists `protocol_version` first, a discrepancy the plan resolves toward 11.3 and
the §3.1 convention): `schema_version`, `protocol_version`, `request_id`,
`invocation_id`, `command` (`CommandKind`), `created_at_utc`, `timeout_seconds`,
`deadline_utc`, `payload_hash`, `payload` (`DescribeRequestPayload |
EngineRunRequest`). Validators: `command is DESCRIBE` iff the payload is a
`DescribeRequestPayload`; `timeout_seconds` within `command_timeout_bounds(command)`;
`deadline_utc == created_at_utc + timeout_seconds`; `payload.request_id ==
request_id` for a run payload; `payload_hash == payload_hash_of(payload)`. The
published schema pins the command↔payload pairing with three `if`/`then` clauses in
`json_schema_extra`, so the pairing is exactly expressible and published.

**Adapter-side verification contract** (spec 14.3 "the adapter verifies the
envelope, invocation ID, payload hash, versions, assigned path, and attempt identity
before engine initialization"), declared here as the conforming-adapter rule the
fake adapters implement and the harness provokes: the adapter must (a) parse the
request file as a JSON object with exactly the header keys and no unknown key, (b)
require `protocol_version == "1.0.0"` and `schema_version == "1.0.0"`, (c)
recompute `payload_hash` over the canonical JSON of `payload` and require equality,
(d) require `command` to equal the sub-command it was invoked with, (e) for
`validate` and `run` require `payload.run_id`, `attempt_number` and `attempt_token`
to be present and, for `run`, require the `--work-dir` argument to end with
`payload.assigned_work_dir.relative_path` under `/` or `\` separators, (f) for
`describe` require `payload.adapter_name`/`adapter_version` to be its own identity.
On any failure the adapter writes no output file, emits no stdout byte and exits
`10`. The core maps that exit as §9.1 does for exit 10.

### 3.7 Commands — `adapters/commands.py`

`AdapterCommand` (**K**, spec 8.2/14.1): `command_kind`, `catalog_entry`
(`AdapterCatalogEntry`), `invocation_id`, `request_path` (absolute local path text,
same rule as `AdapterCatalogEntry.executable_path`), `output_path | MISSING`
(required for `DESCRIBE` and `VALIDATE`, prohibited for `RUN`), `work_dir |
MISSING` and `result_path | MISSING` (both required for `RUN`, prohibited
otherwise), `timeout_seconds` (within the kind's bounds). It carries no request
material by value, so it is never token-bearing.

`argument_array(command) -> tuple[str, ...]` renders spec 14.1 exactly:
`("describe", "--request", request_path, "--output", output_path)`,
`("validate", "--request", request_path, "--output", output_path)`,
`("run", "--request", request_path, "--work-dir", work_dir, "--result",
result_path)`. The executable itself is `catalog_entry.executable_path`, prepended
by whoever launches; Stage 6 never launches.

`StderrCapture` (**P**; defined in `adapters/sanitization.py` by Task 4, because it
is the stderr fold's output): `retained_byte_count: int` (the number of bytes kept
under the budget; the bytes themselves never leave the fold, §7.6), `truncated:
bool`, `source_hash` (`Sha256` of every byte received), `sanitized_text` (`str` of
at most `max_stderr_bytes` characters `| MISSING`; present when the whole retained
capture decoded as UTF-8 and was redacted; absent
when decoding failed, in which case only the count and the hash are retained).

`CommandResult` (**P**, spec 14.1 last paragraph): `invocation`
(`CommandInvocationRecord`, terminal), `parsed_output`
(`BootstrapDescriptorEnvelope | AdapterValidationResult | AdapterResultManifest |
MISSING`; declared reading: spec 14.1 names `AdapterDescriptor` for the describe
member, and the bootstrap envelope is the file that contains it together with the
negotiation header; the manifest member is trust class W and carries the raw
token, so `CommandResult` is transient and never persisted),
`parsed_output_source_hash | MISSING` (exact bytes of the output file),
`protocol_integrity` (`ProtocolIntegrityStatus`), `accepted_events`
(`tuple[RunEvent, ...]`, sequence-ordered), `diagnostics` (`tuple[Diagnostic,
...]`, the core diagnostics minted while supervising), `stderr` (`StderrCapture |
MISSING`), `cancelled: bool`, `timed_out: bool`. Validators: the parsed-output type
matches `invocation.command_kind`; `cancelled` implies `invocation.state is
CANCELLED`; `timed_out` implies `TIMED_OUT`; `accepted_events` is empty for
`DESCRIBE`. Its consumer is the asynchronous `ProcessSupervisor.invoke` of Stage 7;
`CommandResult` is a plain frozen model and needs no `asyncio`.

### 3.8 Negotiation — `adapters/negotiation.py`

`BootstrapDescriptorEnvelope` (**W**, spec 14.2 fixed fields):
`bootstrap_schema_version: Literal["1.0.0"]`, `adapter_name`, `adapter_version`,
`engine_name`, `engine_version`, `executable_hash`, `supported_protocol_versions`,
`supported_schema_versions`, `capability_vocabulary_versions`
(`tuple[VocabularyVersion, ...]`, 1–8, sorted unique), `descriptor_payload_hash`
(`Sha256`), `descriptor` (`AdapterDescriptor`). Validators: every header field
equals the corresponding descriptor field (`adapter_name`, `adapter_version`,
`engine.engine_name`, `engine.engine_version`, `executable_hash`,
`supported_protocol_versions`, `supported_schema_versions`), the descriptor's single
`capability_vocabulary_version` is a member of `capability_vocabulary_versions`, and
`descriptor_payload_hash == sha256_bytes(canonical_json_bytes(descriptor))`. Every
version collection is sorted numerically (`parse_semantic_version`, and the integer
after `capabilities/v` for vocabularies), matching the merged descriptor validator so
header↔descriptor equality is satisfiable for `1.9.0` beside `1.10.0`.

`CoreProtocolSupport` (**K**): `protocol_versions` (`("1.0.0",)`), `schema_versions`
(the five negotiable names at `1.0.0`, §5.2), `vocabulary_versions`
(`("capabilities/v1",)`), `negotiation_policy_version: Literal["negotiation/v1"]`.
`CORE_PROTOCOL_SUPPORT` is the constant instance.

`NegotiationResult` (**C**; spec 11.3 row plus `adapter_version` and the 14.2
policy version): `schema_version`, `adapter_name`, `adapter_version`,
`candidate_protocol_versions`, `candidate_schema_versions`
(`tuple[SupportedSchemaVersion, ...]`), `candidate_vocabulary_versions`,
`selected_protocol_version | MISSING`, `selected_schema_versions | MISSING`,
`selected_vocabulary_version | MISSING`, `negotiation_policy_version`, `outcome`
(`NegotiationOutcome`), `reason_codes` (`tuple[ErrorCode, ...]`, sorted unique, at
most 8). `reason_codes` is a **declared deviation** from the spec 11.3 minimum field
name `diagnostics`, recorded in the model docstring and in the §12.4 register: a
`Diagnostic` would need an invocation the pure function does not see and would nest
the legacy timestamp grammar into a published schema. Validators: `NEGOTIATED` iff
all three selected fields are present and `reason_codes` is empty (that the selected
vocabulary equals the descriptor's own `capability_vocabulary_version` — the
vocabulary the capability claims were made in — is a `negotiate_protocol` rule,
§5.3, because the record does not carry the descriptor); `FAILED` iff all three are absent and `reason_codes` is non-empty; candidates are
numerically sorted intersections.

### 3.9 Events — `adapters/events.py`

`AdapterDiagnostic` (**W** inside events and manifests; **C** after sanitization,
same shape): `error_code` (`ErrorCode`; must start with `ADAPTER.` or `ENGINE.`),
`category` (`AdapterDiagnosticCategory`), `severity` (`DiagnosticSeverity`),
`message` (`BoundedMessage`), `retriable: bool`, `details`
(`dict[DiagnosticDetailKey, DiagnosticDetailValue]`, the `domain` bounds),
`causal_event_ids` (`tuple[EventId, ...]`, sorted unique, ≤ `MAX_CAUSAL_EVENT_IDS`).
It has no `diagnostic_id`, `source_component`, correlation identifiers or timestamp:
those are core-derived when a later stage persists it as a `Diagnostic`, and the
envelope carries the instant. In Stage 6 no adapter diagnostic receives a
`DiagnosticId` and none enters any `causal_diagnostic_ids`; a core diagnostic that
is explained by an adapter diagnostic carries `adapter_error_code` plus
`adapter_event_id` (event-borne) or `adapter_manifest_id` (manifest-borne) in its
`details` (§9.1), and deriving persisted `Diagnostic` rows from adapter diagnostics
is the Stage 8/9 obligation of §1.4. Declared reading of spec 14.4/21.1/24.3: the adapter reports
facts in its own namespace; a code in a core namespace or a core category
(`PROTOCOL`, `SECURITY`, `INTERNAL_INVARIANT`, `TIMEOUT`, `CANCELLATION`,
`PERSISTENCE`, `ARTIFACT_CORRUPTION`, `SCHEMA_VALIDATION`, `USER_CONFIGURATION`) is a
schema failure, so an adapter cannot spoof a hard-blocking closure entry; and
because adapter diagnostics never enter a causal closure in Stage 6, an
adapter-claimed `COMPATIBILITY` category cannot block a retry either.

`ProtocolWarning`: `warning_code` (`ErrorCode`, same namespace rule), `message`,
`impact` (`BoundedText`), `prevented_comparison_levels` (`tuple[ComparisonLevel,
...]`, sorted unique, ≤ 3 — the `ComparisonLevel` cardinality; sortedness is
published through the merged `sorted_comparison_level_enum()`).

`ResourceObservation`: `resident_memory_bytes` (`int 0..MAX_DECLARED_SIZE_BYTES |
MISSING`), `cpu_seconds` (`NonNegativeDecimal | MISSING`), both optional, at least
one present.

Payloads: `HeartbeatPayload(activity_counter: int 0..MAX_COUNTER, phase:
NormalizedIdentifier, resource_observation: ResourceObservation | MISSING)`;
`ProgressPayload(phase, completed_units: int ≥ 0, total_units: int | MISSING ≥
completed_units, percentage: NonNegativeDecimal | MISSING ≤ 100)`;
`WarningPayload(warning: ProtocolWarning)`; `DiagnosticPayload(diagnostic:
AdapterDiagnostic)`; `ArtifactProducedPayload(relative_path: RelativeCandidatePath,
artifact_kind: NormalizedIdentifier, media_type: MediaType, declared_size_bytes: int
0..MAX_DECLARED_SIZE_BYTES, declared_sha256: Sha256)`;
`FinalResultPayload(manifest_relative_path: RelativeCandidatePath,
source_adapter_result_manifest_hash: Sha256, semantic_status: SemanticStatus)`.
`MediaType` is a strict `str` matching `^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$`
(RFC 6838 shape, lowercase), published through `exact_string_schema` like every
other pattern alias. `artifact_kind` is an adapter-declared normalized
identifier; the core-selected source role and artifact vocabulary are Stage 9's.

`ProtocolEventEnvelope` (**W**, token-bearing; field order per spec 11.3, which
places `schema_version` first where 14.4 places `protocol_version` first):
`schema_version`, `protocol_version`, `event_id` (`EventId`), `invocation_id`,
`run_id`, `attempt_token` (`repr=False`), `sequence` (`1..MAX_SEQUENCE`),
`event_type`, `timestamp_utc`, `payload` (union of the six payloads). Validator:
payload type matches `event_type`; published as six `if`/`then` clauses.

`RunEvent` (**C**; spec 11.3 row in order): `schema_version`, `protocol_version`,
`event_id`, `invocation_id`, `run_id`, `attempt_token_hash`, `sequence`,
`event_type`, `timestamp_utc`, `payload` (the sanitized payload), `received_at_utc`,
`wire_event_hash`, `content_hash`. Validators: payload type matches `event_type`
(the same six `if`/`then` clauses as the envelope — spec 11.3's `RunEvent` row,
"event type selects a strict payload schema" — so the permanently published record
is as strict as the wire one); `content_hash == run_event_content_hash(self)`, whose payload is the adapter-authored sanitized
content alone (§4), so a byte-identical replay received at a later instant or
re-serialized differently still has the same `content_hash`.

### 3.10 Validation results and manifests — `adapters/manifests.py`

`AdapterValidationResult` (**W**, token-free; spec 11.3 row in order):
`schema_version`, `protocol_version`, `request_id`, `invocation_id`, `run_id`,
`attempt_token_hash`, `outcome` (`ValidationOutcome`), `diagnostics`
(`tuple[AdapterDiagnostic, ...]`, ≤ `MAX_ADAPTER_DIAGNOSTICS`), `validated_at_utc`, `result_hash`.
Validators: `INVALID`, `NOT_APPLICABLE` and `UNAVAILABLE` require at least one
diagnostic; `result_hash == validation_result_hash(self)` (§4), which holds only
for the document as the adapter wrote it. Spec 14.1's
"declared bounded diagnostics" and "adapter-specific applicability facts" are read
as this `diagnostics` array plus the `diagnostic` stdout events; there is no second
output file. The strict-valid model is itself the sanitized evidence form: a
validation result is token-free by contract, a raw token found anywhere in one is a
contract violation the parser records (§3.11), and so a strict-valid
`AdapterValidationResult` never needed redaction.

`RunProvenance` (nested; spec 10.3 list): `experiment_spec_hash`, `request_hash`,
`strategy_version_hash`, `dataset_version_hash`, `configuration_hash`, `adapter`
(`AdapterIdentity`), `engine` (`EngineIdentity`), `negotiated_versions`
(`NegotiatedVersions`), `comparison_level`, `logical_slot_id`, `attempt_number`.

`CandidateArtifactDeclaration` (nested, **W**): the five `ArtifactProducedPayload`
fields. `CandidateMetric` (nested): `metric_name` (`NormalizedIdentifier`), `value`
(`CanonicalDecimal | MISSING`), `value_status` (`Literal["DEFINED", "UNDEFINED"]`;
`DEFINED` iff `value` present), `unit` (`NormalizedIdentifier`),
`methodology_version` (`SemanticVersion`), `comparison_level`. It is not
`MetricValue`, which stays deferred with its `source_artifact_id`.

`AdapterResultManifest` (**W**, token-bearing; spec 11.3 row in order):
`schema_version`, `protocol_version`, `adapter_manifest_id` (`AdapterManifestId`),
`experiment_id`, `run_id`, `invocation_id`, `attempt_token` (`repr=False`),
`semantic_status`, `started_at_utc`, `completed_at_utc` (≥ `started_at_utc`),
`provenance` (`RunProvenance`), `candidate_artifacts`
(`tuple[CandidateArtifactDeclaration, ...]`, ≤ `MAX_CANDIDATE_ARTIFACTS`, unique
`relative_path`), `candidate_metrics` (≤ `MAX_CANDIDATE_METRICS`, unique
`metric_name`), `diagnostics` (≤ `MAX_ADAPTER_DIAGNOSTICS`), `warnings`
(`tuple[ProtocolWarning, ...]`, ≤ `MAX_WARNINGS`), `approximations`
(`tuple[ApproximationId, ...]`, sorted unique, ≤ `MAX_APPROXIMATIONS`). Validators: `SUCCEEDED`
requires `warnings == ()`; `SUCCEEDED_WITH_WARNINGS` requires non-empty `warnings`;
`FAILED`, `CANCELLED`, `TIMED_OUT`, `NOT_APPLICABLE` and `UNAVAILABLE` require at
least one diagnostic and empty `candidate_artifacts`.

`SanitizedCandidateArtifactDeclaration` (nested, **C**): `candidate_artifact_id`
(`CandidateArtifactId`, derived per §4), `source_event_id` (`EventId`),
`artifact_kind`, `media_type`, `declared_size_bytes`, `declared_sha256`; no path.

`SanitizedAdapterResultManifest` (**C**; spec 11.3 row in order, with the aligned
declarations): `schema_version`, `protocol_version`, `adapter_manifest_id`,
`experiment_id`, `run_id`, `invocation_id`, `attempt_token_hash`, `semantic_status`,
`started_at_utc`, `completed_at_utc`, `provenance`, `candidate_artifact_ids`
(`tuple[CandidateArtifactId, ...]`, sorted unique), `candidate_declarations`
(`tuple[SanitizedCandidateArtifactDeclaration, ...]`; validator: its identities
equal `candidate_artifact_ids` as a set), `candidate_metrics`, `diagnostics`,
`warnings`, `approximations`, `source_adapter_result_manifest_hash`,
`sanitized_adapter_result_manifest_hash` (validator: recomputed per §4). The wire
manifest's status↔`warnings`/`diagnostics`/candidates coupling is restated on this
model verbatim and published as the same `if`/`then` clauses, so schema 34 is as
strict as schema 33.

### 3.11 Parse outcomes, observations and reconciliation — `adapters/manifests.py`, `adapters/negotiation.py`, `adapters/events.py`, `adapters/reconciliation.py`

Byte-level parsing is separated from record-level reconciliation so that the
application operation of §10 never holds adapter bytes. Each parser is pure over
bytes plus, for validation results and manifests, the run's raw token (`token:
str`, supplied by the supervisor from the `AttemptTokenMaterial` it holds since
`create_attempt`; the token is what redaction removes and what the identity phase
compares by hash) and returns a typed parse outcome (**P**). Oversized bytes are
never decoded (spec 14.7 applies byte limits before JSON decoding), so an oversized
document yields no header at all. The header readers never fail on a JSON object:
each header field is read when its value is a `str` within the bound (for the
event header's `sequence`, an `int`) and is `MISSING` otherwise, so a wrongly typed,
over-long or absent identity field reports identity at §9.2 check (3) or the §7.4
identity phase (spec 21.2.1 "missing or invalid `invocation_id`"), and `header` is
`MISSING` only for oversized, non-UTF-8 or non-object bytes:

- `OutputHeader` (nested): the permissively read `protocol_version`,
  `schema_version` (plain bounded `str`, so an unsupported value can be named),
  `invocation_id`, `run_id`, `request_id` (`str | MISSING` each, bounded) and
  `attempt_token_hash | MISSING` — the parser hashes a raw `attempt_token` it finds
  with `attempt_token_hash` at once (only when the value is a `str` of 1–1024
  characters, the hash function's own bound; otherwise `MISSING`, so a wrongly typed
  or over-long token reports identity) and never carries the raw value here.
- `ValidationResultParse`: `byte_length`, `source_hash` (`sha256_bytes` of the
  bytes), `header | MISSING` (absent when the bytes are not a JSON object),
  `result` (`AdapterValidationResult | MISSING`, present only when strict validation
  passed), `failure_code` (`ErrorCode | MISSING`: `PROTOCOL.VALIDATION_RESULT_INVALID`
  for oversized, non-UTF-8, non-object or strict-invalid bytes,
  `PROTOCOL.UNSUPPORTED_VERSION` for a header version the core does not support),
  `redactions: int` — the raw-token occurrences the parser redacted from the decoded
  document. A validation result is token-free by contract (§3.10), so
  `redactions > 0` always accompanies `PROTOCOL.VALIDATION_RESULT_INVALID` with
  `result` absent: the adapter's `result_hash` no longer recomputes over the
  redacted document and the un-redacted document is never validated; the sanitized
  evidence form is the strict-valid model, which exists exactly when `redactions ==
  0`, and the run is `FAILED`.
- `ManifestParse`: the same shape with `manifest` (`AdapterResultManifest |
  MISSING`; trust class W, `repr=False` on its token, transient), `failure_code`
  (`ARTIFACT.RESULT_MANIFEST_INVALID`; `PROTOCOL.UNSUPPORTED_VERSION`; or
  `ARTIFACT.PATH_BOUNDARY_VIOLATION` when the strict validation error is located at
  a `relative_path` field — the same path-located mapping as §7.4) and
  `redactions: int`. Redaction precedes strict validation (spec 14.7 "sanitized and
  revalidated", 19.4): every text field is redacted in place with the run's token
  (the parser's `token` input; the manifest's own `attempt_token` field is compared
  by hash, never used for redaction), so `manifest` never carries the token outside
  its `attempt_token` field, and a placeholder that lands in a pattern-constrained
  field (an identifier, code or path) makes the document strict-invalid —
  `ARTIFACT.RESULT_MANIFEST_INVALID`, because an adapter that put a token where an
  identifier belongs wrote an invalid manifest — except that the path-located
  mapping wins: a placeholder (or any other invalid text) at a `relative_path`
  field is `ARTIFACT.PATH_BOUNDARY_VIOLATION`, the same precedence as §7.4's event
  rule. A token in manifest text is a
  redaction fact, never leakage; leakage (§9.2) is a candidate file containing the
  token.
- `DescriptorParse`: `byte_length`, `source_hash`, `header` (`DescriptorHeader |
  MISSING`: `bootstrap_schema_version`, `adapter_name`, `adapter_version`,
  `executable_hash`, each `str | MISSING`),
  `envelope` (`BootstrapDescriptorEnvelope | MISSING`), `failure_code`
  (`PROTOCOL.DESCRIBE_OUTPUT_INVALID` or `PROTOCOL.UNSUPPORTED_VERSION`).

`CandidateObservation` (**K**, caller-supplied): `relative_path`,
`observed_size_bytes`, `observed_sha256`, `contains_attempt_token: bool`.
`ArtifactDeclarationRecord` (nested, **P**): `event_id`, `payload`
(`ArtifactProducedPayload`). `ProtocolEventSummary` (**P**, produced by the ledger
of §7.5): `accepted_count`, `last_sequence`, `artifact_declarations`
(`tuple[ArtifactDeclarationRecord, ...]`, ≤ `MAX_CANDIDATE_ARTIFACTS`),
`warnings` (`tuple[ProtocolWarning, ...]`, ≤ `MAX_WARNINGS`), `final_result`
(`FinalResultPayload | MISSING`), `adapter_diagnostics` (`tuple[AdapterDiagnostic,
...]`, ≤ `MAX_ADAPTER_DIAGNOSTICS`), `redactions` (`int`, the sum of
`EventAccepted.redactions` over the accepted events; the ledger rejects the event
that would exceed any of these bounds, §7.2). `SemanticReconciliation` (**P**): `command_kind`, `verdict`
(`ReconciliationVerdict`), `run_target_state` (`EngineRunState | MISSING`),
`semantic_status | MISSING`, `primary_diagnostic` (`Diagnostic | MISSING`),
`diagnostics` (`tuple[Diagnostic, ...]`, the primary first), `sanitized_manifest |
MISSING`, `sanitized_validation_result | MISSING`, `negotiation | MISSING`,
`descriptor | MISSING`.

### 3.12 Application operation — `experiments/semantic_outcome.py`

`SemanticOutcomeRequest` (the seventeenth request, `experiments/requests.py`):
`schema_version`, `invocation_id`, `expected_invocation_revision`, `run_id`,
`expected_run_revision`, `parsed_output` (`ValidationResultParse | ManifestParse |
MISSING`; `MISSING` means no output file existed), `protocol_summary`
(`ProtocolEventSummary`), `candidate_observations` (`tuple[CandidateObservation,
...]`, ≤ `2 × MAX_CANDIDATE_ARTIFACTS`, unique `relative_path` — the union of
event-declared and manifest-declared paths, §11.3 step 4), `negotiated_versions`
(`NegotiatedVersions`, class K and token-free: the versions the supervisor handed
the adapter, which §9.2 check (5) compares with the manifest's echo), and
`protocol_failure` (`Diagnostic | MISSING`: the parser's rejection diagnostic the
supervisor already holds; present exactly when `CommandResult.protocol_integrity`
is `VIOLATED`, so the reconcilers receive the primary they must return rather than
a bare flag).
Operation rule, not a model validator (the request carries no command kind): a
`ManifestParse` is admitted only for a `RUN` and a `ValidationResultParse` only for
a `VALIDATE`, checked against the loaded invocation at §10 step 1. The request is a
transient in-memory value that the supervisor (Stage 7; the harness in Stage 6)
constructs and hands to the operation; it is never persisted, logged, hashed or
rendered, and `parsed_output` is the only token-bearing field of any `experiments`
request (the sixteen Stage 5 requests are token-free), which §13 records.
`SemanticOutcome` (**P**): `invocation` (enriched or unchanged), `run`
(transitioned or unchanged), `reconciliation` (`SemanticReconciliation | MISSING`),
`superseded_by` (`EngineRunState | MISSING`; present exactly when §10 step 3
(with `reconciliation` absent) or step 5 (with the recomputed `reconciliation`)
found the run already in a terminal state the verdict did not produce — a core win
or a lawful later Stage 5 move).

## 4. Hashing profiles and derived identities

`HashingProfile` gains four members in `domain/hashing.py` (8 → 12):

| Member | Value | Covers |
|---|---|---|
| `ADAPTER_REQUEST_V1` | `adapter-request/v1` | `request_hash`: over the **pre-attempt request material** — `experiment_id`, `logical_slot_id`, `attempt_number`, `strategy_version_hash`, `dataset_version_hash`, `configuration_hash`, `experiment_spec_hash`, `adapter`, `engine`, `configuration_snapshot`, `comparison_level`, `negotiated_versions`, `assigned_work_dir.authorized_root` — with the **named exclusions** `run_id`, `request_id`, `attempt_token`, `attempt_token_hash`, `assigned_work_dir.relative_path`, `created_at_utc`, `schema_version`, `protocol_version` and `request_hash` itself. Every excluded field is minted by or after `create_attempt`, which takes `request_hash` as an input, so the hash is computable before the run exists and recomputable from the finished request; `VALIDATE` and `RUN` invocations of one run carry it, and it equals `EngineRunRecord.request_hash`. For `DESCRIBE` the payload is the canonical `DescribeRequestPayload` (the catalog-level describe identity the Stage 5 plan deferred) |
| `RUN_EVENT_CONTENT_V1` | `run-event-content/v1` | `RunEvent.content_hash` over the sanitized event content (the adapter-authored fields plus the core-derived `attempt_token_hash`): `schema_version`, `protocol_version`, `event_id`, `invocation_id`, `run_id`, `attempt_token_hash`, `sequence`, `event_type`, `timestamp_utc`, sanitized `payload`; the **named exclusions** are `content_hash`, `received_at_utc` (core clock) and `wire_event_hash` (exact bytes), so an identical replay under an advanced clock or with different whitespace is still identical content |
| `SANITIZED_ADAPTER_RESULT_MANIFEST_V1` | `sanitized-adapter-result-manifest/v1` | the self-hash with that field omitted |
| `CANDIDATE_ARTIFACT_IDENTITY_V1` | `candidate-artifact-identity/v1` | `candidate_artifact_id_for(run_id, invocation_id, relative_path: str)` (a plain `str`, because `domain` may not import the `adapters` path alias): `cand_` + `_uuid4_shaped(profile_hash(...))`, derived rather than drawn, so a restart derives the same identity |

Exact-byte and stdlib-reproducible hashes, deliberately outside the profile
envelope so a conforming adapter can compute or verify them with `hashlib` and
`json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)`:
`payload_hash = sha256(canonical_json_bytes(payload))`; `descriptor_payload_hash =
sha256(canonical_json_bytes(descriptor))`; `result_hash =
sha256(canonical_json_bytes(result without result_hash))`; `wire_event_hash =
sha256(line bytes without the terminator)`; `source_adapter_result_manifest_hash =
sha256(manifest file bytes)`; `attempt_token_hash` stays the merged domain-separated
profile, published to adapters as `sha256(b"crypto_lab:attempt-token:v1" + b"\x00" +
token_utf8)`. That stdlib reproducibility holds only for a document already in
canonical value form, which the adapter contract therefore requires (§12.4
register): decimals as their canonical text (the `CanonicalDecimal` spelling, no
exponent, no trailing zeros), instants as `YYYY-MM-DDTHH:MM:SSZ` with a six-digit
fraction only when it is non-zero (the merged `format_utc` rule), integers never
floats; the adapter verifies `payload_hash` over the parsed request object, which
the core wrote canonically, and computes its own output hashes over canonical
values. Two new `domain/identifiers.py` aliases: `RequestId` (`req_` UUID4),
derived as `req_` + `_uuid4_shaped(sha256_bytes(anchor.encode()))` by
`request_id_for(anchor: RunId | InvocationId)`, which lives in `domain/hashing.py`
beside `candidate_artifact_id_for` (`hashing.py` already imports `identifiers.py`;
the reverse placement would be a circular import) — the run request anchors on the run
identity, a describe request on its invocation identity, and the distinct prefixes
make collisions impossible — so no `IdentitySource` method is added; and
`AdapterManifestId` (`amf_` UUID4, adapter-minted, format-checked only). Stage 6
diagnostics derive their identity with the merged `DIAGNOSTIC_IDENTITY_V1` pattern
(§9.4).

## 5. Version negotiation and the `describe` flow

### 5.1 Versions

Every wire record pins `protocol_version` and `schema_version` as
`Literal["1.0.0"]`: the core supports exactly one protocol version, so the exact
literal is both strict and fully published, and a future version is a new model and
a new `$id`. Negotiation therefore selects among the adapter's declared lists, never
among core alternatives. Spec 14.2's "chosen versions are pinned in the request and
run record" is met by placing `negotiated_versions` inside the request material
covered by `request_hash` (§4), which the frozen `EngineRunRecord` carries. A record carrying any other value fails schema validation
and is classified `PROTOCOL.UNSUPPORTED_VERSION` (§9.4) by the staged parser of
§7.4, which reads the two version fields before full validation.

### 5.2 Negotiable schema names

`NEGOTIABLE_SCHEMA_NAMES` (a Task 1 constant in `adapters/vocabulary.py`, so that
Task 2's `NegotiatedVersions` and Task 3's `CoreProtocolSupport` both consume it
without a cycle) is the closed tuple `protocol.adapter-descriptor`,
`protocol.adapter-command-request-envelope`, `protocol.protocol-event-envelope`,
`protocol.adapter-validation-result`, `protocol.adapter-result-manifest`, each at
`1.0.0`, mapped one-to-one to the `$id`s `urn:crypto-lab:schema:protocol:<name>:1.0.0`,
where `<name>` is the schema name without its `protocol.` prefix
(`protocol.adapter-descriptor` → `adapter-descriptor`; the descriptor is the Stage
3 entry, the other four are Stage 6 entries of §12).
The nine families spec 33.4 names (request, event, heartbeat, progress, warning,
diagnostic, artifact-produced, final-result, manifest) are the request envelope, the
event envelope with its six payload `$defs`, and the manifest; they are versioned
with those three schemas. The bootstrap envelope, `RunEvent` and the sanitized
manifest are core-side and not negotiated.

### 5.3 `negotiate_protocol`

`negotiate_protocol(envelope: BootstrapDescriptorEnvelope, support: CoreProtocolSupport
= CORE_PROTOCOL_SUPPORT) -> NegotiationResult` is pure: protocol candidates are the
numerically sorted intersection and the selection is `highest_common_stable_version`;
for every negotiable schema name the adapter must list at least one common version
and the numerically highest is selected, an omitted or disjoint name fails
negotiation; the vocabulary selection is the numerically highest common
`capabilities/vN`, which must also equal the descriptor's declared vocabulary.
Failure records `ADAPTER.UNAVAILABLE` in `reason_codes` (spec 21.2.1 "version
negotiation empty") and leaves every selected field absent.
`negotiated_versions_of(result) -> NegotiatedVersions` projects a `NEGOTIATED`
result for the request.

### 5.4 `describe` reconciliation

`parse_bootstrap_descriptor(output_bytes: bytes, *, max_bytes) -> DescriptorParse`
(§3.11) is the byte-level half. `reconcile_describe(invocation:
CommandInvocationRecord, output: DescriptorParse | MISSING, stdout_bytes_seen: int,
*, catalog_entry, now_utc) -> SemanticReconciliation` requires `command_kind is
DESCRIBE` and `state is EXITED`, then in order: (1) any stdout byte →
`PROTOCOL.STDOUT_CONTAMINATION` (spec 14.1) and `DESCRIBE_UNAVAILABLE`; (2) a
nonzero exit → the §9.1 `DESCRIBE` cell with verdict `DESCRIBE_UNAVAILABLE`, adding
`output_present: false` to the exit's diagnostic when no output exists
(`semantic_exit_reading(DESCRIBE, exit).output_required` is false for every nonzero
describe exit, so absence there is never a protocol failure and an exit-`30`
describe without output stays `ADAPTER.UNAVAILABLE`, spec 21.2.1); (3) exit `0`
with output absent, or output bytes present but `header` absent →
`PROTOCOL.DESCRIBE_OUTPUT_INVALID`; (4) header `adapter_name`, `adapter_version` or
`executable_hash` differing from the catalog entry →
`PROTOCOL.IDENTITY_OR_SEQUENCE_VIOLATION` (identity before schema, the §9.2 order);
(5) `failure_code` set → that code (`PROTOCOL.DESCRIBE_OUTPUT_INVALID` or
`PROTOCOL.UNSUPPORTED_VERSION`); (6) a valid envelope → `negotiate_protocol`;
`NEGOTIATED` → verdict `DESCRIBED` with the descriptor and negotiation; `FAILED` →
`DESCRIBE_UNAVAILABLE` with `ADAPTER.UNAVAILABLE`. The reconciliation carries
`descriptor` whenever the envelope parsed strict-valid (checks (5)–(6) reached,
whatever the verdict) and `negotiation` whenever (6) ran, so the observation's
network and credential flags come from the descriptor even for a failed
negotiation. In (4) an absent header field
counts as differing (spec 21.2.1 orders a missing identity before any schema
classification). When the reconciliation minted at least one diagnostic (every
verdict except `DESCRIBED`), the supervisor (the harness, §11.3 step 4) records
those identities on the `EXITED` describe invocation through `enrich_invocation`,
so describe diagnostics are durable invocation facts exactly as validate and run
diagnostics are (§10 step 8); a `DESCRIBED` describe is not enriched, because the
merged predicate rejects an empty enrichment. Describe stdout is never parsed and
never terminalizes the invocation: the bytes are counted, the child runs to exit,
and the count is classified here (spec 14.6 reserves `PROTOCOL_FAILED` for a live
stdout protocol, which `describe` does not have).

`describe_availability_observation(*, adapter_name, adapter_version, verdict:
ReconciliationVerdict | MISSING, primary_code: ErrorCode | MISSING (required
`MISSING` exactly for verdict `DESCRIBED`, because the Stage 4 validator requires
`reason_code` absent on an available observation, and required present otherwise), descriptor:
AdapterDescriptor | MISSING, observation_id, executable_path, executable_hash,
runtime_version, operating_system, observed_at_utc, expires_at_utc) ->
RuntimeAvailabilityObservation` (Task 3; depends only on Task 1 types and merged
domain types) projects any terminal describe into the Stage 4 record (a validate or
run verdict is rejected): `available` is
true exactly for verdict `DESCRIBED`; otherwise `reason_code` is `primary_code` —
the reconciliation's primary code after `EXITED`, or `PROCESS.DESCRIBE_TIMED_OUT`
for a describe whose deadline won, which is how spec 14.8's "creates or refreshes
an unavailable observation" on a describe deadline is met. A cancelled describe
mints no observation: spec 21.2.1 calls cancellation "not a failure" and 14.8
names only the deadline, so `PROCESS.CANCELLED` never becomes an unavailability
reason; `network_required` and
`credentials_required` are copied from the descriptor when present and are `false`
when no descriptor exists (every fake adapter declares both `false`, spec 24.4).
Identity, instants and runtime facts are caller-supplied, the Stage 5
`ProcessStartFacts` pattern; every mandatory Stage 4 field, including
`runtime_version`, is supplied even when no descriptor exists (the harness passes
the fake's constant `1.0.0` and the host operating system).

## 6. Request material and command flows (matrix B)

### 6.1 Building requests

The request material exists in two steps because `create_attempt` mints the run
identity and the attempt token internally and takes `request_hash` as an input.

1. **Before the attempt.** `request_material_hash(*, experiment: ExperimentRecord,
   logical_slot_id, attempt_number, negotiated: NegotiatedVersions, limits:
   ProtocolLimits) -> Sha256` assembles the pre-attempt material of §4 from the
   frozen spec (`adapter`, `engine`, hashes, `comparison_level`, the assumptions,
   `experiment_spec_hash`), the frozen slot compatibility (`approximation_ids`), the
   negotiated versions and the limits, and returns the `ADAPTER_REQUEST_V1` hash.
   The caller passes it to `create_attempt` (or `create_successor`) as the
   attempt's `request_hash`.
2. **After the attempt.** `build_engine_run_request(*, run: EngineRunRecord,
   experiment: ExperimentRecord, token: AttemptTokenMaterial, negotiated, limits,
   created_at_utc) -> EngineRunRequest` requires `token.run_id == run.run_id`, copies
the same material, adds `run_id`,
   `request_id = request_id_for(run.run_id)`, the raw token, `request_hash =
   run.request_hash` and `assigned_work_dir.relative_path` = `runs/<run_id>/work`
   (all named exclusions of the profile), copies `experiment_spec_hash` and the
   authorized root label from the same material step 1 hashed, and asserts
   `request_hash_of(request) == run.request_hash`, which holds by construction. `request_hash_of(request) -> Sha256` recomputes the profile over a
   raw or sanitized request.

`build_request_envelope(*, invocation: CommandInvocationRecord, payload)` requires
`invocation.state is STARTING` (the envelope is written at launch, after the
paired-clock deadline exists), copies `invocation_id`, `timeout_seconds`,
`deadline_utc` and `created_at_utc = invocation.launch_attempted_at_utc` (the one
instant that satisfies the envelope's deadline rule), and computes `payload_hash`.
For a describe the payload is the `DescribeRequestPayload`, which carries no
`request_id`; the **envelope's** `request_id` is
`request_id_for(invocation.invocation_id)`, and the describe `request_hash` handed
to `create_invocation` is the `ADAPTER_REQUEST_V1` hash over the payload alone, so
it is computable before the invocation exists and equal across repeated describes
(§6.2). `request_envelope_bytes(envelope) ->
bytes` is the canonical JSON the launcher writes; it is the only token-bearing byte
string the core produces and it is never persisted.

### 6.2 Command flow matrix

| Aspect | `DESCRIBE` | `VALIDATE` | `RUN` |
|---|---|---|---|
| Request | envelope with `DescribeRequestPayload`; `request_hash` = describe identity (§4) | envelope with `EngineRunRequest`; `request_hash` = the run's | envelope with the same `EngineRunRequest`; `request_hash` = the run's (Stage 5 requires equality) |
| Parent state at `create_invocation` | none | run `VALIDATING` | run `READY` |
| Invocation transitions | `PENDING → STARTING → RUNNING → EXITED`, or `PENDING/STARTING/RUNNING → CANCELLED`, `STARTING/RUNNING → TIMED_OUT`, `RUNNING → PROTOCOL_FAILED`, `STARTING → FAILED_TO_START` (the Stage 5 table, cited not restated) | same | `begin_linked_launch`, `start_linked_run`, then the same terminals; every coupled terminal is Stage 5's |
| Run transitions the outcome drives | none | `VALIDATING → READY / NOT_APPLICABLE / UNAVAILABLE / FAILED` through §10 | `RUNNING → NOT_APPLICABLE / UNAVAILABLE / FAILED` through §10; `RUNNING → SUCCEEDED*` only in Stage 9 |
| Stdout events permitted | none; any byte is contamination | `HEARTBEAT`, `PROGRESS`, `WARNING`, `DIAGNOSTIC` | all six; `ARTIFACT_PRODUCED` and `FINAL_RESULT` are `RUN`-only (declared reading) |
| Valid completion | exit `0`, output file holds a valid `BootstrapDescriptorEnvelope`, negotiation `NEGOTIATED` | exit `0` with `AdapterValidationResult` `VALID`; or exit `20`/`30`/`10` agreeing with outcome `NOT_APPLICABLE`/`UNAVAILABLE`/`INVALID` | exit `0` with a valid matching manifest `SUCCEEDED`/`SUCCEEDED_WITH_WARNINGS` whose declarations reconcile; or exit `20`/`30` with a matching `NOT_APPLICABLE`/`UNAVAILABLE` manifest carrying an explaining diagnostic |
| Invalid completion | any other combination (§5.4) | output missing, malformed, wrong identity, disagreeing with the exit (§9.2) | manifest missing on exit `0`, malformed, wrong identity, disagreeing with exit or events, declared candidates not matching observations (§9.2) |
| Native exit interaction | §9.1 table | §9.1 table | §9.1 table |
| Output requirement | `BootstrapDescriptorEnvelope` at `--output` | `AdapterValidationResult` at `--output` | `AdapterResultManifest` at `--result`, pointed to by the `FINAL_RESULT` event |
| Diagnostics | §9.4 | §9.4 | §9.4 |
| Replay | a repeated describe is a new invocation with the same `request_hash`; `create_invocation` deduplicates nothing (Stage 5 rule kept) | identical-create replay per Stage 5; events idempotent on `(invocation_id, sequence)` + `content_hash`; `apply_command_semantic_outcome` replays idempotently per the §10 replay rule | same, plus `RESULT_FINALIZATION_ELIGIBLE` recomputed deterministically from the same inputs with no write |

## 7. Events, framing, the sequence ledger and sanitization

### 7.1 Framing rules (declared readings of spec 14.4 and 14.7)

1. A line is the byte sequence between stream start or a `\n` byte and the next
   `\n` byte; the terminator is not part of the line and does not count toward
   `max_event_bytes`.
2. A `\r` anywhere in a line, a UTF-8 byte-order mark, invalid UTF-8, an empty line
   (zero bytes between terminators) and any line whose first byte is not `{` are
   `PROTOCOL.STDOUT_CONTAMINATION`; a line that starts with `{` but fails JSON
   parsing or envelope validation is `PROTOCOL.MALFORMED_JSONL`. (The fake adapters'
   byte-exact stdout write rule is §11.1's.)
3. A trailing fragment at end of stream without a terminator is
   `PROTOCOL.STDOUT_CONTAMINATION`; the protocol requires complete lines and the core
   does not guess whether a fragment is a crash or contamination. An empty
   remainder after the final terminator is normal, and so is an empty stream (a
   child that wrote nothing to stdout, row 38).
4. The byte limit is applied before decoding: a line exceeding `max_event_bytes` is
   `PROTOCOL.EVENT_TOO_LARGE` and its bytes are never parsed.
5. Any stdout byte during `DESCRIBE` is `PROTOCOL.STDOUT_CONTAMINATION` (spec 14.1).

### 7.2 Event matrix (matrix C)

Common to every row: envelope fields per §3.9; `sequence` starts at 1 for each
invocation and increases by exactly one; the identity phase of §7.4 precedes payload
validation; a payload of the wrong type for the `event_type` is
`PROTOCOL.MALFORMED_JSONL`; an `event_type` that is not a `ProtocolEventType`
member is `PROTOCOL.MALFORMED_JSONL` (membership is tested first in the identity
phase and a non-member falls through to strict validation); a member the command
kind may not emit is `PROTOCOL.IDENTITY_OR_SEQUENCE_VIOLATION` (the parser
validates "command kind" in the identity phase, spec 14.4). The ledger's bounded
collections are sequence rules: the accepted event that would exceed
`MAX_CANDIDATE_ARTIFACTS` declarations, `MAX_WARNINGS` warnings or
`MAX_ADAPTER_DIAGNOSTICS` diagnostics for one invocation is
`PROTOCOL.IDENTITY_OR_SEQUENCE_VIOLATION` (declared reading), so
`ProtocolEventSummary` is always constructible.

| Event type | Payload (§3.9) | Permitted commands | Semantic effect | Lifecycle effect | Additional rules |
|---|---|---|---|---|---|
| `HEARTBEAT` | `HeartbeatPayload` | `VALIDATE`, `RUN` | liveness evidence; resets the harness's missing-heartbeat timer | none; never extends a deadline (spec 14.8) | `activity_counter` non-decreasing across accepted heartbeats of one invocation, else `PROTOCOL.IDENTITY_OR_SEQUENCE_VIOLATION` (declared reading of "monotonic activity counter") |
| `PROGRESS` | `ProgressPayload` | `VALIDATE`, `RUN` | informational | none; never infers success (spec 15.3) | `completed_units` non-decreasing per phase is not enforced |
| `WARNING` | `WarningPayload` | `VALIDATE`, `RUN` | recorded; must reappear in the manifest's `warnings` for a `RUN` (§9.2) | none | namespace rule of §3.9 |
| `DIAGNOSTIC` | `DiagnosticPayload` | `VALIDATE`, `RUN` | recorded; available to reconciliation, which cites it by `adapter_error_code` and `adapter_event_id` in `details` (§3.9) | none by itself; a `RUN` whose manifest declares a non-success status must carry at least one diagnostic (§3.10) | namespace and category rules of §3.9 |
| `ARTIFACT_PRODUCED` | `ArtifactProducedPayload` | `RUN` | declares one candidate; must match exactly one manifest declaration (§9.2) | none in Stage 6 (Stage 9 creates the `CandidateArtifact`) | duplicate `relative_path` within one invocation is `PROTOCOL.IDENTITY_OR_SEQUENCE_VIOLATION`; a `relative_path` failing §3.3 is `ARTIFACT.PATH_BOUNDARY_VIOLATION` (the parser maps a validation error located at a path field to that code) and terminalizes the invocation as `PROTOCOL_FAILED`, spec 15.4's severe path violation |
| `FINAL_RESULT` | `FinalResultPayload` | `RUN` | a pointer to the manifest; never authoritative | none until reconciliation | at most one per invocation and no event may follow it; a second `FINAL_RESULT` or any later event is `PROTOCOL.IDENTITY_OR_SEQUENCE_VIOLATION` |

### 7.3 Sequence and identity rules

Accepted-event identity is `(invocation_id, sequence)` plus `content_hash`. For
each line the ledger of §7.5 decides exactly one of: **accepted** (next sequence,
identity valid); **replayed** (`sequence` already accepted and the sanitized
`content_hash` equals the stored one — the stored `RunEvent` is returned, nothing is
written); **rejected** with `PROTOCOL.IDENTITY_OR_SEQUENCE_VIOLATION` for a
conflicting duplicate (same `sequence`, different `content_hash`), a gap (`sequence >
last + 1`), a `sequence` below `1` or above `MAX_SEQUENCE`, a wrong or unregistered
`invocation_id`, a `run_id` not equal to the invocation's, a raw `attempt_token`
whose domain-separated hash differs from the run's `attempt_token_hash`, a duplicate
`event_id` at a new sequence, a new event after `FINAL_RESULT`, or a
`ProtocolEventType` member the command kind may not emit (a non-member is
`PROTOCOL.MALFORMED_JSONL`, §7.2). Two ordering rules follow: a repeated
`sequence` (equal to or below `last`) is classified only after the line has passed
sanitization and strict validation (§7.4's order), because the classification needs
`content_hash` — a repeat that fails validation is `PROTOCOL.MALFORMED_JSONL`; and
for such a repeated `sequence` the replay decision (stored `content_hash` equality)
is taken before every §7.2 additional rule — the after-final rule,
heartbeat-counter monotonicity, duplicate `relative_path`, second `FINAL_RESULT`
and the collection bounds — so an identical replay of any earlier line, including
a heartbeat whose counter is now below the last accepted one or a line arriving
after `FINAL_RESULT`, is `EventReplayed`, and only a non-identical repeat proceeds
to those rules as a conflicting duplicate. The parser is defined for a `RUNNING`
invocation; the supervisor (the harness in Stage 6) stops feeding lines the moment
the invocation is terminalized, and Stage 7 owns rejection of output that arrives
for a terminal invocation.

### 7.4 The staged parser — `parse_protocol_line`

`parse_protocol_line(line: bytes, *, acceptance: EventAcceptanceContext) ->
LineOutcome`, pure, in `adapters/events.py`. (The parameter is deliberately not
named `context`: that word is in the merged `_BARE_FORBIDDEN_NAMES` scan over every
name in `src/crypto_lab`, as are `buffer`, `note` and `problem`.)
`EventAcceptanceContext` carries the invocation record (must be `RUNNING`, kind
`VALIDATE` or `RUN`), the run's `attempt_token_hash`, `max_event_bytes`, the ledger
state of §7.5 and the receipt instant from the injected `Clock`. Order: byte limit
(§7.1 rule 4); framing (rules 1–3) with UTF-8 decoding; a permissive header read of
`protocol_version`, `schema_version`, `invocation_id`, `run_id`, `sequence`,
`event_type` and `attempt_token_hash` — the reader takes the raw `attempt_token`
from the decoded object, hashes it with `attempt_token_hash` at once and stores
only the hash, exactly as §3.11's `OutputHeader` does, so no header class carries
the raw token and the four-class allowlist of §13 stands — each typed as a plain
bounded `str` or `int` through an `extra="ignore"` header model so the violation
class can be named; version check (`PROTOCOL.UNSUPPORTED_VERSION`); identity and
sequence (§7.3), in which the header hash is compared with the acceptance
context's stored hash (spec 14.4 puts the token in the first phase, so a
wrong-token line with a malformed payload reports identity), the `event_type`
membership test precedes the command-kind test, a gap or a `sequence` below `1` or
above `MAX_SEQUENCE` is rejected here, and a repeat (`1 <= sequence <= last`) is
deferred to the replay decision after `content_hash` exists (§7.3); redaction
(§7.6) over the decoded JSON object, exempting exactly the envelope's
`attempt_token` key (already hashed by the header reader) — this is the one
statement of the redaction-versus-validation order for events, and §7.6 defers to
it; strict `ProtocolEventEnvelope` validation over the redacted object
(`PROTOCOL.MALFORMED_JSONL` for unknown fields, unknown `event_type`, wrong payload
shape, namespace or category violations, and for a redaction placeholder that
landed in a pattern-constrained payload field such as `phase`, `artifact_kind` or
`metric_name` — an adapter that put a token where an identifier belongs wrote a
malformed event — except that a validation error located at `relative_path` or
`manifest_relative_path`, including a placeholder there, is
`ARTIFACT.PATH_BOUNDARY_VIOLATION`; a token drawn from the letter-leading subset of
the `AttemptToken` grammar is a valid path segment and a valid lowercase
identifier, so both cases are reachable, and the §7.2 additional rules run after
strict validation for every line, so a malformed line is `PROTOCOL.MALFORMED_JSONL`
whatever its position); then `wire_event_hash`,
`content_hash` and the `RunEvent`, whose construction cannot fail because the
payload it receives has already passed strict validation in its redacted form. Every rejection carries the Stage 6 diagnostic
(§9.4) and the redacted sample of §7.6; on every rejection the supervisor (the
harness, §11.3 step 3) terminalizes the live invocation as `PROTOCOL_FAILED`
through the Stage 5 coupled transition, whose coupled run target is `FAILED` — the
parser itself writes nothing. No
untyped dictionary leaves the parser: `LineOutcome` is a discriminated
`EventAccepted | EventReplayed | EventRejected` union of frozen models (spec 14.7
last paragraph, 8.1); `EventReplayed` carries the stored `RunEvent`, which the
ledger retains per accepted sequence (§7.5).

### 7.5 The invocation event ledger and `append_event`

`InvocationEventLedger` (frozen dataclass in `adapters/events.py`) holds the
accepted `RunEvent` per sequence (hence the `(sequence → content_hash, event_id)`
map), the set of seen `event_id`s, the
seen `artifact_produced` paths, the accepted warning and diagnostic counts (bounded
per §7.2), the last heartbeat counter, the live-only redaction total (a
`compare=False` field that `from_events` initialises to `0`, because `RunEvent`
carries no redaction count, so ledger equality excludes it) and whether
`FINAL_RESULT` was accepted; `accept(outcome)` returns the successor ledger and
`from_events(events: tuple[RunEvent, ...])` rebuilds one from persisted events, which
is what makes restart unable to duplicate an accepted event. `summary() ->
ProtocolEventSummary`.

`EngineRunRepository` (in `experiments/ports.py`) gains `append_event(event:
RunEvent) -> Result[RunEvent]` — spec 8.2 verbatim; idempotent when an identical
`(invocation_id, sequence, content_hash)` exists (returns the stored event, writes
nothing), `PERSISTENCE.CONCURRENCY_CONFLICT` when the key exists with a different
`content_hash` or the `event_id` exists under another key, otherwise inserts — and
`list_events(invocation_id: InvocationId) -> Result[tuple[RunEvent, ...]]`,
sequence-ordered, empty for an invocation without events. `list_events` is a
**declared extension** beyond spec 8.2's operation list, in the style of the merged
`list_for_run`, because `InvocationEventLedger.from_events` reads it. The protocol
classification of a conflicting duplicate is the ledger's; the repository only
refuses to store two different events under one key. `InMemoryBackingStore` gains a
`run_events` table keyed by `(invocation_id, sequence)` with an `event_id` uniqueness
index checked at commit, and `committed_run_events()`.

### 7.6 Sanitization — `adapters/sanitization.py`

- `redact_attempt_token(text: str, token: str) -> tuple[str, int]` replaces every
  occurrence with `<attempt-token-redacted>` and returns the count.
- `redact_payload(payload, token) -> tuple[payload, int]` walks strings in every
  field of a payload, `AdapterDiagnostic`, `ProtocolWarning` or manifest — except a
  manifest's own `attempt_token` field and an event envelope's `attempt_token` key,
  which are retained verbatim on the W input for the hash comparison and the
  harness's presence assertion — redacting the decoded object before strict
  validation (the order §7.4 states for events and §3.11 for output files) and
  returning the count; the event is still accepted
  (spec 14.4 "redacts token occurrences", 19.4) and the count is carried on
  `EventAccepted.redactions`, summed into `ProtocolEventSummary.redactions`, and on
  `ManifestParse.redactions` for a manifest; no diagnostic is minted for a
  redaction. Leakage (`SECURITY.SENSITIVE_MATERIAL_LEAKAGE`, §9.2) is a candidate
  file containing the token (`CandidateObservation.contains_attempt_token`), spec
  14.7's "native or binary candidate"; a token in text is redacted, never leakage.
- `token_present(chunks: Iterable[bytes], token: bytes) -> bool` is the exact-byte
  scan that tolerates chunk boundaries by carrying the last `len(token) − 1` bytes
  forward; the harness feeds it file chunks and stderr chunks.
- `contamination_sample(line: bytes, token: str) -> ContaminationSample` records
  `byte_length`, `source_hash` (`sha256_bytes(line)`) and, only when the line decodes
  as UTF-8 and every token occurrence is provably removed, an escaped sample of at
  most `MAX_CONTAMINATION_SAMPLE_BYTES` (`repr`-style escaping of control
  characters); otherwise `sample` is absent (spec 14.7).
- `BoundedStderrCapture(limit, token)`: `feed(chunk: bytes)` accumulates up to
  `limit` bytes, sets `truncated` beyond it, hashes every byte; `finish() ->
  StderrCapture` decodes and redacts the retained bytes, then discards them: only
  `retained_byte_count`, `source_hash`, `truncated` and `sanitized_text` leave the
  fold. Truncation mints `PROCESS.STDERR_TRUNCATED`, which reaches the invocation
  only through the supervisor's `enrich_invocation` (`additional_diagnostic_ids`),
  §11.3 step 3.

## 8. Manifest and artifact matrix (matrix D)

| Item | Author | Trust | Path constraints | Hash fields | Size and type | Relation to `RunManifest` | Relation to finalized artifacts | Later-stage owner | Stage 6 does / does not |
|---|---|---|---|---|---|---|---|---|---|
| Request envelope file | core | W (token-bearing for validate/run) | absolute core-selected path under the command root; only on the argument array | `payload_hash`, `request_hash` | canonical JSON, unbounded by contract (bounded by its models) | none | never an artifact (spec 14.3) | Stage 7 writes and deletes it | Stage 6 builds bytes, never writes |
| Raw stdout stream | adapter | W | none (pipe) | `wire_event_hash` per line | `max_event_bytes` per line | none | never finalized | Stage 7 reads | Stage 6 parses lines |
| `RunEvent` | core | C | none | `wire_event_hash`, `content_hash` | bounded by its schema | none | protocol capture regenerated from these as `EVIDENCE` in Stage 9 | Stage 8 persists (`run_events`) | Stage 6 defines, sanitizes, appends in memory |
| Describe output file | adapter | W | `--output` absolute path under the describe root | `descriptor_payload_hash` | `MAX_DESCRIPTOR_OUTPUT_BYTES` | none | `ADAPTER`-owned `EVIDENCE` later | Stage 9 | Stage 6 parses, negotiates |
| Validation output file | adapter | W (token-free) | `--output` absolute path | `result_hash` | `MAX_VALIDATION_RESULT_BYTES` | none | sanitized form is `RUN`-owned `EVIDENCE` later | Stage 9 | Stage 6 parses, checks identity, redacts |
| `AdapterResultManifest` file | adapter | W (token-bearing) | at `--result` inside the work dir; `FINAL_RESULT.manifest_relative_path` names it | `source_adapter_result_manifest_hash` (exact bytes) | `max_manifest_bytes` | authoritative only for the adapter's declaration; never referenced by `RunManifest` | never finalized (spec 19.4) | Stage 7 reads, Stage 9 deletes after lease | Stage 6 parses, validates, reconciles, sanitizes |
| Declared candidate artifacts | adapter | W | `RelativeCandidatePath` within the work dir (§3.3) | `declared_sha256`, `declared_size_bytes` vs observation | declared size ≤ `MAX_DECLARED_SIZE_BYTES` | `RESULT` candidates become `RunManifest.artifact_refs` after Stage 9 finalization | `RUN`-owned `RESULT` candidates; adapter chooses neither owner, purpose, role nor final path | Stage 9 | Stage 6 derives `candidate_artifact_id`, compares declarations with observations |
| `SanitizedAdapterResultManifest` | core | C | no paths (identities only) | `source_adapter_result_manifest_hash`, `sanitized_adapter_result_manifest_hash` | bounded by its schema | `RunManifest.sanitized_adapter_result_manifest_hash` references it | `RUN`-owned `EVIDENCE` after any outcome | Stage 8 persists, Stage 9 finalizes | Stage 6 defines and builds |
| Sanitized stderr | core | C | none | `source_hash` | `max_stderr_bytes` | none | `RUN`/`ADAPTER`-owned `EVIDENCE` | Stage 7 captures, Stage 9 finalizes | Stage 6 defines the bounded redacting fold |
| Core `RunManifest` | core | C | none | `run_manifest_hash` | — | is it | references only `RUN`-owned `RESULT` refs | Stage 9 | Stage 6 does not define it |

## 9. Exit semantics, reconciliation and diagnostics

### 9.1 Per-command semantic exit table — `adapters/exit_codes.py`

`process_exit_category_for` (Stage 5) is the process fact; this table is the
semantic reading of an `EXITED` invocation and is total over `CommandKind ×
ProcessExitCategory`. "Output" means the command's output record when valid.

| Native exit | `DESCRIBE` | `VALIDATE` | `RUN` |
|---|---|---|---|
| `0` | output required; §5.4 | output required; `VALID` → `VALIDATED_READY`; any other outcome disagrees → `FAILED`, `PROTOCOL.VALIDATION_RESULT_INVALID` | manifest required; `SUCCEEDED`/`SUCCEEDED_WITH_WARNINGS` and declarations reconcile → `RESULT_FINALIZATION_ELIGIBLE`; manifest `FAILED` → `FAILED`, `ENGINE.RUNTIME_FAILURE` (truthful declaration, policy-retriable); `NOT_APPLICABLE`/`UNAVAILABLE`/`CANCELLED`/`TIMED_OUT` → `FAILED`, `ARTIFACT.RESULT_MANIFEST_INVALID` (contradiction); missing manifest → `FAILED`, `ARTIFACT.RESULT_MANIFEST_INVALID` |
| `10` | `DESCRIBE_UNAVAILABLE`, `SCHEMA.REQUEST_INVALID` | output `INVALID` agreeing, or output absent (the §3.6 adapter-side contract writes none; `output_present: false`) → `FAILED`, `SCHEMA.REQUEST_INVALID`; output present with any other outcome → `FAILED`, `PROTOCOL.VALIDATION_RESULT_INVALID` | `FAILED`, `SCHEMA.REQUEST_INVALID`; a present manifest must declare `FAILED`, else `ARTIFACT.RESULT_MANIFEST_INVALID` |
| `20` | `DESCRIBE_UNAVAILABLE`, `ENGINE.RUNTIME_FAILURE` (a describe carries no strategy) | output `NOT_APPLICABLE` agreeing → `NOT_APPLICABLE`, `COMPAT.NOT_APPLICABLE`; output absent or any other outcome → `FAILED`, `PROTOCOL.VALIDATION_RESULT_INVALID` (a validate that claims exit `20` owes its result) | manifest `NOT_APPLICABLE` with ≥1 diagnostic → `NOT_APPLICABLE`, `COMPAT.LATE_NOT_APPLICABLE` (`adapter_error_code` and `adapter_manifest_id` of the first explaining diagnostic in `details`, §3.9); otherwise `FAILED`, `ARTIFACT.RESULT_MANIFEST_INVALID` |
| `30` | `DESCRIBE_UNAVAILABLE`, `ADAPTER.UNAVAILABLE` | output `UNAVAILABLE` agreeing → `UNAVAILABLE`, `ADAPTER.UNAVAILABLE`; output absent or any other outcome → `FAILED`, `PROTOCOL.VALIDATION_RESULT_INVALID` | manifest `UNAVAILABLE` with ≥1 diagnostic → `UNAVAILABLE`, `ADAPTER.UNAVAILABLE` (the same `details` reference); otherwise `FAILED`, `ARTIFACT.RESULT_MANIFEST_INVALID` |
| `40` | `DESCRIBE_UNAVAILABLE`, `ENGINE.RUNTIME_FAILURE` | `FAILED`, `ENGINE.RUNTIME_FAILURE` | `FAILED`, `ENGINE.RUNTIME_FAILURE`; a present manifest must declare `FAILED`, else `ARTIFACT.RESULT_MANIFEST_INVALID` |
| `50` | `DESCRIBE_UNAVAILABLE`, `ENGINE.RUNTIME_FAILURE` | `FAILED`, `ENGINE.RUNTIME_FAILURE` | `FAILED`, `ENGINE.RUNTIME_FAILURE`; a present manifest must declare `CANCELLED` or `FAILED`, else `ARTIFACT.RESULT_MANIFEST_INVALID` |
| `60` | `DESCRIBE_UNAVAILABLE`, `ENGINE.RUNTIME_FAILURE` | `FAILED`, `ENGINE.RUNTIME_FAILURE` | `FAILED`, `ENGINE.RUNTIME_FAILURE`; a present manifest must declare `TIMED_OUT` or `FAILED`, else `ARTIFACT.RESULT_MANIFEST_INVALID` |
| `70` | `DESCRIBE_UNAVAILABLE`, `PROTOCOL.ADAPTER_REPORTED_VIOLATION` | `FAILED`, `PROTOCOL.ADAPTER_REPORTED_VIOLATION` | `FAILED`, `PROTOCOL.ADAPTER_REPORTED_VIOLATION`; a present manifest must declare `FAILED`, else `ARTIFACT.RESULT_MANIFEST_INVALID`; every accepted `ARTIFACT_PRODUCED` declaration is an abandoned candidate |
| other | `DESCRIBE_UNAVAILABLE`, `ENGINE.RUNTIME_FAILURE` with causal `PROCESS.UNRECOGNIZED_PROCESS_EXIT` (read from the `EXITED` invocation's `primary_diagnostic_id`, which the merged shape validator makes mandatory for an unrecognized exit) | `FAILED`, same | `FAILED`, same; a present manifest must declare `FAILED` |

Declared readings: an adapter's self-reported exit `50` or `60` without a core
cancellation or deadline is an engine runtime failure, because spec 17.1 reserves
run `CANCELLED` and `TIMED_OUT` for core wins and spec 14.6 makes the exit code
non-semantic; a core cancellation or deadline that wins first terminalizes the
invocation through Stage 5 (`CANCELLED`/`TIMED_OUT`) and never reaches this table.
Exit `0` with a manifest declaring `FAILED` is read as a truthful failure
declaration (`ENGINE.RUNTIME_FAILURE`, policy-retriable) rather than spec 21.2.1's
"inconsistent with exit" row, because the adapter declared the same non-success
the core would otherwise infer and nothing about the declaration is corrupt; the
outcome is non-success either way. A manifest that is **absent** on exit `10`,
`40`, `50`, `60`, `70` or an unrecognized value adds a `manifest_present: false`
detail to that exit's output-independent diagnostic (`SCHEMA.REQUEST_INVALID`,
`ENGINE.RUNTIME_FAILURE`, `PROTOCOL.ADAPTER_REPORTED_VIOLATION`) and keeps that
code's posture; a manifest absent on exit `0`, `20` or `30` is
`ARTIFACT.RESULT_MANIFEST_INVALID`, because spec 14.6 accepts a late exit `20` or
`30` only with a matching manifest and spec 21.2.1 reads "manifest missing" as
that code; a manifest that is **present but malformed, oversized, wrong-identity or
contradictory** is `ARTIFACT.RESULT_MANIFEST_INVALID` and hard-blocking regardless
of exit. The same shape governs the other two commands:
`semantic_exit_reading(kind, exit).output_required` is the single source of
"output required" — true for `DESCRIBE` on exit `0` only, and for `VALIDATE` and
`RUN` on exits `0`, `20` and `30` — and both reconcilers consult it before any
absence check; on an exit that does not require output, an absent output adds the
absence detail (`output_present: false` for a validate, `manifest_present: false`
for a run) to the exit's diagnostic (spec 21.2.1's exit-`40` crash keeps its
retriable posture with or without output) and a present output is parsed and,
when it contradicts the exit, is exactly the contradiction the cell names; where
the cell names none (`VALIDATE` on exits `40`, `50`, `60`, `70` and other) the
output is recorded and the code is the exit's — `output_required` governs absence
only.

### 9.2 Reconciliation predicates — `adapters/reconciliation.py`

Both predicates take parse outcomes (§3.11), never bytes, and admit the run in its
**pre-state or in a state the mapping can produce**, so the same call can serve a
first application and the §10 replay check: `reconcile_validate` admits
`VALIDATING`, `READY`, `NOT_APPLICABLE`, `UNAVAILABLE`, `FAILED`; `reconcile_run`
admits `RUNNING`, `NOT_APPLICABLE`, `UNAVAILABLE`, `FAILED`. A run already
`CANCELLED` or `TIMED_OUT` by a core win is never a reconciler input: §10 step 3
returns before reconciling. Any other run state, a non-`EXITED` invocation, a
wrong kind or a broken linkage raises `ReconciliationRuleViolation`, which the
operation maps to `CORE.INVARIANT_VIOLATION`.

`reconcile_validate(invocation, run, output: ValidationResultParse | MISSING,
protocol_summary, protocol_failure: Diagnostic | MISSING, *, now_utc)` checks in
order: (1) `protocol_failure` present → `FAILED` with that diagnostic as the
primary (it is the parser's rejection diagnostic the supervisor minted, handed in
rather than summarised as a flag, so the run write of §10 step 7 has its primary
identity); (2) output bytes present but `header` absent (oversized, non-UTF-8 or
not a JSON object) → `PROTOCOL.VALIDATION_RESULT_INVALID`, and output absent while
`semantic_exit_reading(VALIDATE, exit).output_required` → the same code (absence on
an exit that does not require output is the `output_present: false` detail at
(5)); when `output` is `MISSING`, (3) and (4) are skipped and the path is (5);
(3) header identity — `invocation_id`,
`run_id`, `request_id` or `attempt_token_hash` absent or differing from the records
(`request_id` from `request_id_for(run.run_id)`, §4) →
`PROTOCOL.IDENTITY_OR_SEQUENCE_VIOLATION` (spec 21.2.1: identity before any schema
classification, evaluated on the permissively read header so a mis-identified and
malformed document reports identity); (4) `failure_code` set → that code as
recorded (a `result_hash` mismatch is a strict-validation failure the parser has
already recorded, §3.10) — identity before the recorded version or schema code is
spec 21.2.1's order for output files, deliberately unlike the event parser's
version-before-identity order of spec 14.4 (§7.4); (5) the §9.1 column, including the exit-`10`
absent-output rule. The availability observation for `VALIDATED_READY` and `UNAVAILABLE` is the
frozen `SlotCompatibility.availability_observation_id` of the run's slot, read by
§10.

`reconcile_run(invocation, run, experiment: ExperimentRecord, slot_compatibility,
output: ManifestParse | MISSING, protocol_summary, candidate_observations,
negotiated_versions: NegotiatedVersions, protocol_failure: Diagnostic | MISSING, *,
now_utc)` checks in order: (1) `protocol_failure` present → `FAILED` with that
diagnostic as the primary; (2) manifest bytes
present but `header` absent (oversized, non-UTF-8 or not a JSON object) →
`ARTIFACT.RESULT_MANIFEST_INVALID`; (3) header identity — `invocation_id`, `run_id`
or `attempt_token_hash` absent or differing → `PROTOCOL.IDENTITY_OR_SEQUENCE_VIOLATION`; (4)
`failure_code` set → that code as recorded (`PROTOCOL.UNSUPPORTED_VERSION`,
`ARTIFACT.PATH_BOUNDARY_VIOLATION` for a path-located validation error, or
`ARTIFACT.RESULT_MANIFEST_INVALID`); when `output` is `MISSING`, (2)–(6) and
(9)–(12) are skipped and the path is (7) then (13), which is how the absent-manifest
rows read; (5) with a parsed manifest present — otherwise (5), (6) and (9)–(12) are
skipped likewise — `experiment_id`,
`provenance.request_hash`, `provenance.experiment_spec_hash`, `logical_slot_id`,
`attempt_number`, `adapter`, `engine` (from `run`), `comparison_level` and the
strategy, dataset and configuration hashes (from
`experiment.spec_hash` and `experiment.spec`), or `negotiated_versions` (from the
request's `negotiated_versions` input) differing → `ARTIFACT.RESULT_MANIFEST_INVALID`
(wrong identity; every compared value is an input of the call); (6) `FINAL_RESULT`
event absent while a manifest exists, its `manifest_relative_path` not equal to
`RESULT_MANIFEST_RELATIVE_PATH`, its `source_adapter_result_manifest_hash` not
equal to `output.source_hash`, or its `semantic_status` not equal to the
manifest's → `ARTIFACT.RESULT_MANIFEST_INVALID`; (7) any observation with
`contains_attempt_token` → `SECURITY.SENSITIVE_MATERIAL_LEAKAGE` (a token in
manifest text was redacted by the parser and is not leakage, §3.11); (8) no
parsed manifest → continue at (13), skipping (9)–(12); (9) for a manifest whose
`semantic_status` is `SUCCEEDED` or `SUCCEEDED_WITH_WARNINGS`, its
`candidate_artifacts` and the summary's `artifact_declarations` not equal as sets of
five-tuples → `ARTIFACT.RESULT_MANIFEST_INVALID` (a non-success manifest declares no
candidates by §3.10, and the accepted declarations are abandoned candidates for
Stage 9 to quarantine, so a truthful `FAILED` manifest written after accepted
`ARTIFACT_PRODUCED` events keeps the exit's retriable posture); (10) a **manifest** declaration without an
observation, or an observation whose size or hash differs from that declaration →
`ARTIFACT.VALIDATION_FAILED` (event-declared paths of a non-success manifest are
abandoned candidates and are not compared here, so an absent or corrupt abandoned
file keeps the exit's posture; they are still observed for the leakage check (7)); (11) `warnings` of the manifest, compared after
redaction on both sides, not a superset of the accepted `WARNING` events →
`ARTIFACT.RESULT_MANIFEST_INVALID`; (12) `approximations`
not equal to `slot_compatibility.approximation_ids` (which the request snapshot
handed the adapter) → `ARTIFACT.RESULT_MANIFEST_INVALID`; (13) the §9.1 column,
where a manifest absent on an exit that does not require one is the
`manifest_present: false` detail and a manifest absent on exit `0`, `20` or `30`
is `ARTIFACT.RESULT_MANIFEST_INVALID`.
For `RESULT_FINALIZATION_ELIGIBLE` the reconciliation carries the
`SanitizedAdapterResultManifest` built by `sanitize_result_manifest(output,
protocol_summary)` and no run target; for every other verdict it carries
`run_target_state` and the primary `Diagnostic` — each reconciler mints exactly one
diagnostic, at the first failing check, so `diagnostics` is that single primary and
every secondary on the invocation comes from the supervisor
(`PROCESS.STDERR_TRUNCATED`, `PROCESS.MISSING_HEARTBEAT`) — and for
`NOT_APPLICABLE`/`UNAVAILABLE`/`FAILED` it also carries the sanitized manifest when
checks (5), (6), (9), (11) and (12) all passed (in particular when the manifest
declares no candidates), which is `EVIDENCE` material after any outcome;
`sanitize_result_manifest` matches declarations to accepted events by
`relative_path` (unique on both sides, §3.10 and §7.2), is never called when a
declaration lacks its event, and `sanitized_manifest` is absent in that case.

Primary-diagnostic precedence, one rule: a protocol-integrity diagnostic beats
everything; then the identity/schema/leakage/path/declaration diagnostics in the
order listed; then the exit-derived diagnostic. Every other minted diagnostic is a
secondary diagnostic carried on the invocation's `diagnostic_ids`.

### 9.3 Verdict semantics

| Verdict | Run target | Invocation | What the caller may do next |
|---|---|---|---|
| `DESCRIBED` | none | `EXITED` | record the descriptor and negotiation; build an available observation (§5.4) |
| `DESCRIBE_UNAVAILABLE` | none | `EXITED`, enriched by the supervisor with the reconciliation's diagnostics (§5.4) | build an unavailable observation |
| `VALIDATED_READY` | `VALIDATING → READY` | `EXITED` | create the `RUN` invocation |
| `NOT_APPLICABLE` | `VALIDATING → NOT_APPLICABLE` or `RUNNING → NOT_APPLICABLE` | `EXITED` | aggregation |
| `UNAVAILABLE` | `VALIDATING → UNAVAILABLE` or `RUNNING → UNAVAILABLE` | `EXITED` | retry gate 6 |
| `FAILED` | `VALIDATING → FAILED` or `RUNNING → FAILED` | `EXITED` (a `PROTOCOL_FAILED` invocation reaches run `FAILED` through Stage 5's coupled transition, not through this verdict) | retry evaluation |
| `RESULT_FINALIZATION_ELIGIBLE` | **none; the run stays `RUNNING`** | `EXITED` | Stage 9 `RESULT` finalization, which alone commits `SUCCEEDED`/`SUCCEEDED_WITH_WARNINGS` with the `RunManifest` |

### 9.4 The closed Stage 6 diagnostic table — `adapters/diagnostics.py`

`STAGE6_DIAGNOSTIC_CODES` is a closed mapping from code to `(category, retriable,
severity)`; `stage6_diagnostic(code, message, *, source_component, timestamp_utc,
experiment_id, run_id, invocation_id, details, causal_diagnostic_ids) -> Diagnostic`
and `stage6_failure(...)` mirror the Stage 5 factory, derive identity with
`DIAGNOSTIC_IDENTITY_V1` over the same payload shape, reject a code outside the
table, require `invocation_id` for every `ENGINE_RUNTIME`, `PROTOCOL`, `TIMEOUT`
and `CANCELLATION` code, and reject `details` keys the `Diagnostic` validator would
reject. Every reconciler message and detail value is a pure function of the
reconciliation inputs — no instant, host path or receipt fact enters them — because
the identity profile hashes `message` and `details` and the §10 replay rule relies
on a re-issue recomputing the same identities. `PROCESS.UNRECOGNIZED_PROCESS_EXIT` appears in both tables with an asserted
identical posture, so the harness can mint the diagnostic Stage 5's `EXITED`
transition demands for an unrecognized exit.

| Code | Category | Retriable | Severity | Minted by | Hard block |
|---|---|---|---|---|---|
| `PROTOCOL.STDOUT_CONTAMINATION` | `PROTOCOL` | false | ERROR | parser (§7.1 framing; describe stdout) | yes |
| `PROTOCOL.MALFORMED_JSONL` | `PROTOCOL` | false | ERROR | parser (schema-level failure of a framed line) | yes |
| `PROTOCOL.EVENT_TOO_LARGE` | `PROTOCOL` | false | ERROR | parser | yes |
| `PROTOCOL.IDENTITY_OR_SEQUENCE_VIOLATION` | `PROTOCOL` | false | ERROR | parser identity phase; validation-result and manifest identity checks | yes |
| `PROTOCOL.UNSUPPORTED_VERSION` | `PROTOCOL` | false | ERROR | parser; describe, validation and manifest readers | yes |
| `PROTOCOL.ADAPTER_REPORTED_VIOLATION` | `PROTOCOL` | false | ERROR | exit 70 | yes |
| `PROTOCOL.VALIDATION_RESULT_INVALID` | `PROTOCOL` | false | ERROR | validation output missing, malformed or disagreeing with exit | yes |
| `PROTOCOL.DESCRIBE_OUTPUT_INVALID` | `PROTOCOL` | false | ERROR | describe output missing, malformed or oversized | yes |
| `SCHEMA.REQUEST_INVALID` | `SCHEMA_VALIDATION` | false | ERROR | exit 10 | yes |
| `COMPAT.NOT_APPLICABLE` | `COMPATIBILITY` | false | ERROR | validate exit 20 | yes |
| `COMPAT.LATE_NOT_APPLICABLE` | `COMPATIBILITY` | false | ERROR | run exit 20 with matching manifest (the code string is the merged `REASON_LATE_NOT_APPLICABLE` of `domain/aggregation.py`, imported rather than respelled) | yes |
| `ADAPTER.UNAVAILABLE` | `ADAPTER_UNAVAILABILITY` | true | ERROR | negotiation failure; catalog miss; exit 30 | no |
| `ENGINE.RUNTIME_FAILURE` | `ENGINE_RUNTIME` | true | ERROR | exits 20 (describe), 40, 50, 60, other; manifest `FAILED` on exit 0 | no |
| `PROCESS.UNRECOGNIZED_PROCESS_EXIT` | `ENGINE_RUNTIME` | true | ERROR | harness on an unrecognized exit, before the `EXITED` transition | no |
| `PROCESS.STDERR_TRUNCATED` | `ENGINE_RUNTIME` | true | WARNING | stderr capture over the budget | no |
| `PROCESS.MISSING_HEARTBEAT` | `TIMEOUT` | true | WARNING | harness liveness timer (Stage 7 in production) | no |
| `PROCESS.DESCRIBE_TIMED_OUT` | `TIMEOUT` | false | ERROR | harness describe deadline | no |
| `PROCESS.VALIDATE_TIMED_OUT` | `TIMEOUT` | true | ERROR | harness validate deadline | no |
| `PROCESS.START_TIMED_OUT` | `TIMEOUT` | true | ERROR | harness deadline before the handoff (a direct unit case in Task 8, since no scenario can deterministically win that race) | no |
| `PROCESS.RUN_TIMED_OUT` | `TIMEOUT` | true | ERROR | harness run deadline | no |
| `PROCESS.CANCELLED` | `CANCELLATION` | false | ERROR | harness cancellation | yes |
| `ARTIFACT.RESULT_MANIFEST_INVALID` | `ARTIFACT_CORRUPTION` | false | ERROR | §9.2 manifest checks | yes |
| `ARTIFACT.PATH_BOUNDARY_VIOLATION` | `ARTIFACT_CORRUPTION` | false | ERROR | event parser (§7.4 path-located mapping) and manifest parser (`ManifestParse.failure_code`, §3.11), surfaced by §9.2 check (4) | yes |
| `ARTIFACT.VALIDATION_FAILED` | `ARTIFACT_CORRUPTION` | false | ERROR | declaration versus observation | yes |
| `SECURITY.SENSITIVE_MATERIAL_LEAKAGE` | `SECURITY` | false | ERROR | raw token in a candidate file (`contains_attempt_token`); text occurrences are redacted, §7.6 | yes |

Twenty-five codes. The category choices resolve spec 21.2.1's dual-category rows
in favour of the retry posture the row states (both alternatives of each dual row
are hard-blocking, so retry semantics are unchanged either way). `CORE.*`,
`PERSISTENCE.*` and `RETRY.*` are minted only through the Stage 5 factory by the
operation of §10; `ARTIFACT.FINALIZATION_TIMED_OUT` and `PERSISTENCE.WRITE_FAILED`
are not Stage 6 codes.

## 10. The application operation: `apply_command_semantic_outcome`

`apply_command_semantic_outcome(request: SemanticOutcomeRequest, *, unit_of_work:
UnitOfWork, clock: Clock) -> Result[SemanticOutcome]` in
`experiments/semantic_outcome.py`, driven by `run_operation` like every Stage 5
operation. One unit of work:

1. Load the invocation and the run; `invocation.run_id != run.run_id`,
   `command_kind is DESCRIBE`, `state is not EXITED`, or a parse-outcome type that
   does not match the kind is `CORE.INVARIANT_VIOLATION`.
2. Revisions: `expected_invocation_revision` and `expected_run_revision` must match
   the stored records, else `PERSISTENCE.CONCURRENCY_CONFLICT`. This check comes
   before every state precondition (steps 3–6) so that a re-issue after either
   record has moved on is a stable conflict, never an invariant report (spec 29.6);
   step 1's shape checks precede it because none of those facts can change after
   a first issue.
3. Core win: a run already `CANCELLED` or `TIMED_OUT` (Stage 5's `transition_run`
   can lawfully produce either between `EXITED` and this call, §1.5 item 3) →
   return the stored pair unchanged with `reconciliation` absent and
   `superseded_by` set to that state; nothing is written and nothing is minted.
4. Load the experiment and the slot's frozen `SlotCompatibility`; call
   `reconcile_validate` or `reconcile_run` (§9.2) with `now = clock.now_utc()`; a
   `ReconciliationRuleViolation` is `CORE.INVARIANT_VIOLATION`.
5. Idempotent replay, decided **after** the verdict exists and **before** the
   first-application preconditions, and applying only to verdicts with a
   `run_target_state` (`RESULT_FINALIZATION_ELIGIBLE` never short-circuits here: a
   run still `RUNNING` proceeds to step 6 on every issue and returns after step 6
   with no write, while a run already in an admitted terminal state —
   `NOT_APPLICABLE`, `UNAVAILABLE`, `FAILED` by a later `transition_run` — is
   returned with `superseded_by` set to that state and the recomputed
   reconciliation, nothing written). If
   the run's stored state already equals the verdict's `run_target_state` and the
   invocation's `diagnostic_ids` already contain every recomputed diagnostic
   identity, the prior application is complete: return the stored pair with the
   recomputed reconciliation and write nothing — also after a successor exists or
   the experiment has aggregated, as long as the revisions are current. If the run
   is already in a terminal state different from the verdict's target (a lawful
   later Stage 5 move such as `READY → UNAVAILABLE` or `RUNNING → FAILED` by
   `transition_run`; the operation cannot distinguish it from a divergent earlier
   application and writes nothing either way), return the stored pair with
   `superseded_by` set and the recomputed reconciliation. Any other combination —
   the run in an admitted produced state that is neither the target with every
   recomputed identity present nor terminal (`READY` with a verdict other than
   `VALIDATED_READY`), or a run already at the target whose `diagnostic_ids` lack
   a recomputed identity while `run.primary_terminal_diagnostic_id` is among the
   recomputed identities — is a divergent re-issue: `CORE.INVARIANT_VIOLATION`,
   nothing written. A run at the target whose stored primary is **not** among the
   recomputed identities was terminalized by a core decision (`transition_run`
   with its own primary, the same race as the different-target case) and is
   returned with `superseded_by` set and the recomputed reconciliation. Only a run
   still in its pre-state proceeds to steps 6–8.
6. First-application preconditions: the run must be the slot's current attempt
   (`latest_attempt`), the experiment `RUNNING`, and `list_for_run` for both
   `VALIDATE` and `RUN` must show no other non-terminal invocation for the run (the
   authoritative read Stage 5 could
   not perform, §1.5 item 3); otherwise `CORE.INVARIANT_VIOLATION`.
7. For a verdict with a `run_target_state` and a run still in its pre-state:
   `run_replacement(run, target=..., now=now,
   primary_terminal_diagnostic_id=<primary id>, availability_observation_id=<the
   slot's for READY and UNAVAILABLE, MISSING otherwise>)`; `assert_run_transition`
   with owner `GENERIC` (a violation maps through `run_rule_failure`);
   compare-and-swap the run. For `RESULT_FINALIZATION_ELIGIBLE` no run write occurs.
8. Only on a first application (step 7 reached, the run in its pre-state): when at
   least one diagnostic was minted, build the invocation replacement that
   adds every minted identity to `diagnostic_ids` (revision +1, `updated_at_utc =
   now`), prove it with `assert_write_once_enrichment` (a
   `CommandInvocationRuleViolation` maps as Stage 5 does: `REVISION` to
   `PERSISTENCE.CONCURRENCY_CONFLICT`, every other check to
   `CORE.INVARIANT_VIOLATION`), and compare-and-swap it in the same unit of work; when no diagnostic was minted (`VALIDATED_READY`,
   `RESULT_FINALIZATION_ELIGIBLE`) the invocation is not written and its revision
   is unchanged, because the merged predicate rejects an empty enrichment. The
   enrichment is written inline rather than by calling `enrich_invocation`, which
   opens its own `run_operation` transaction; the run write and the enrichment must
   share one unit of work. A lost swap on either record rolls back both and
   follows the Stage 5 reload-once rule.
9. Return `SemanticOutcome` carrying the minted `Diagnostic` objects; the caller
   seeds each identity not already present into the diagnostic reader in Stage 6
   (`InMemoryBackingStore.seed_diagnostic` raises on a duplicate, and Stage 6
   identities are content-derived, so a replay recomputes the same ids) and a later
   stage persists them.

The request-to-operation inventory becomes seventeen. The operation never reads a
clock other than the injected one, never touches the filesystem, never holds
adapter bytes, and never moves a run to a success state.

## 11. Fake adapters and the offline contract harness

### 11.1 The fake adapter executable

`tests/fake_adapters/fake_adapter.py` is one **stdlib-only** Python script
(`argparse`, `json`, `hashlib`, `sys`, `os`, `time`, `datetime` only; it imports
neither `crypto_lab` nor `pydantic`, which the Stage 6 guard asserts by `ast`). It
implements spec 14.1's three sub-commands over the exact argument array of §3.7,
performs the adapter-side verification of §3.6 (exit `10` on failure), computes
`payload_hash`, `result_hash`, `descriptor_payload_hash`, `attempt_token_hash` and
the manifest file hash with `hashlib` over
`json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()`,
writes stdout lines with `sys.stdout.buffer.write(line + b"\n")` and never with
text-mode `print` (the rule §7.1 rule 2 cites), and derives every
`event_id` (`evt_` UUID4-shaped from `sha256(invocation_id + ":" + str(sequence))`),
every `adapter_manifest_id` (`amf_` UUID4-shaped from `sha256(invocation_id +
":manifest")`) and every `timestamp_utc` (the envelope's `created_at_utc` — the
launch instant, not the payload's build instant — parsed with
`datetime.fromisoformat` after replacing the trailing `Z` with `+00:00`, plus
`timedelta(seconds=sequence)`, rendered with `strftime("%Y-%m-%dT%H:%M:%SZ")`)
deterministically from the request, so a scenario's output is a pure function of
its request. The **scenario is selected by the adapter identity carried in the
request payload** (`DescribeRequestPayload.adapter_name` for describe,
`EngineRunRequest.adapter.adapter_name` otherwise; a scenario may additionally
dispatch on the command and on `payload.attempt_number`, because every command of
every attempt of one slot carries the slot's single adapter identity, which
`create_invocation` enforces). Each scenario's harness holds
its own `FrozenAdapterCatalog` with exactly the entries that scenario needs (one
entry per scenario), every entry pointing at the same script with the script's
SHA-256 as `executable_hash`; the distinct scenario names exceed
`MAX_CATALOG_ENTRIES`, so they never share one catalog, the bound is unchanged,
and `test_harness_safety.py` asserts both facts. It emulates no engine: candidate files are small deterministic
byte strings, metrics are literal Decimal strings, and no market data, order or
portfolio concept appears.

### 11.2 Scenario table

Every scenario is deterministic given its request. "Expected" names the invocation
terminal state, the run terminal state (or the verdict when the run stays
`RUNNING`), the primary diagnostic code and any secondary code. Adapter names carry
the `fake.` prefix; the describe and validate scenarios reuse `fake.conformant`
behaviour unless the row says otherwise. The rows cover, in the roadmap's and the
planning brief's terms, successful DESCRIBE, successful VALIDATE, successful RUN,
unsupported capability, temporarily unavailable state, validation failure, malformed
JSON, unknown event type, duplicate sequence, skipped sequence, wrong invocation
identity, wrong request hash, wrong attempt-token proof, oversized line, oversized
manifest, invalid UTF-8 stdout, stdout noise, stderr output, heartbeat success, heartbeat timeout, process timeout,
cancellation, nonzero recognized exits, unrecognized exit, missing manifest,
malformed manifest, manifest/process disagreement, artifact-path escape, checksum
mismatch, crash before first event and crash after partial events, plus the
adversarial identity, namespace, version and leakage cases the matrices required.
The roadmap's "stale output" category is rows 15, 17, 18 and 47 — foreign or
stale-attempt output rejected by the identity checks; late output for an
already-terminal invocation is the Stage 7 half (§7.3). Every scenario that writes
a manifest emits `FINAL_RESULT` last unless its row says otherwise.

| # | Adapter name | Command | Behaviour | Expected |
|---|---|---|---|---|
| 1 | `fake.conformant` | describe | writes a valid bootstrap envelope, exit 0, no stdout | `EXITED`; verdict `DESCRIBED`; negotiation `NEGOTIATED`; available observation |
| 2 | `fake.conformant` | validate | writes `VALID`, exit 0, one heartbeat and one progress event | `EXITED`; run `READY`; no diagnostics |
| 3 | `fake.conformant` | run | heartbeat, progress, two `ARTIFACT_PRODUCED` (native, normalized), writes both files and the `SUCCEEDED` manifest, then `FINAL_RESULT`, exit 0 | `EXITED`; verdict `RESULT_FINALIZATION_ELIGIBLE`; run stays `RUNNING`; sanitized manifest with two derived candidate ids; source and sanitized hashes distinct |
| 4 | `fake.warnings` | run | as 3 plus one `WARNING` event and manifest `SUCCEEDED_WITH_WARNINGS` with the same warning | `EXITED`; `RESULT_FINALIZATION_ELIGIBLE`, `semantic_status` `SUCCEEDED_WITH_WARNINGS` |
| 5 | `fake.unsupported-capability` | validate | exit 20, result `NOT_APPLICABLE` with one diagnostic | `EXITED`; run `NOT_APPLICABLE`; `COMPAT.NOT_APPLICABLE` |
| 6 | `fake.late-not-applicable` | run | exit 20, manifest `NOT_APPLICABLE` with one explaining diagnostic, no candidates | `EXITED`; run `NOT_APPLICABLE`; `COMPAT.LATE_NOT_APPLICABLE` carrying `adapter_error_code` and `adapter_manifest_id` in `details`, `causal_diagnostic_ids` empty |
| 7 | `fake.temporarily-unavailable` | validate | exit 30, result `UNAVAILABLE` | `EXITED`; run `UNAVAILABLE`; `ADAPTER.UNAVAILABLE`; the slot's observation id supplied |
| 8 | `fake.late-unavailable` | run | exit 30, manifest `UNAVAILABLE` with one diagnostic, no candidates | `EXITED`; run `UNAVAILABLE`; `ADAPTER.UNAVAILABLE` |
| 9 | `fake.validation-failure` | validate | exit 10, result `INVALID` | `EXITED`; run `FAILED`; `SCHEMA.REQUEST_INVALID` |
| 10 | `fake.malformed-json` | run | heartbeat, then the line `{"schema_version": ` | `PROTOCOL_FAILED`; run `FAILED`; `PROTOCOL.MALFORMED_JSONL`; one accepted `RunEvent` |
| 11 | `fake.unknown-event` | run | envelope with `event_type` `TELEMETRY` | `PROTOCOL_FAILED`; run `FAILED`; `PROTOCOL.MALFORMED_JSONL` |
| 12 | `fake.duplicate-sequence` | run | sequence 2 emitted twice with different payloads | `PROTOCOL_FAILED`; run `FAILED`; `PROTOCOL.IDENTITY_OR_SEQUENCE_VIOLATION` |
| 13 | `fake.replayed-sequence` | run | sequence 2 emitted twice byte-identical, then continues from sequence 3 to completion | `EXITED`; `RESULT_FINALIZATION_ELIGIBLE`; exactly one `RunEvent` at sequence 2; the harness counts one `EventReplayed` outcome (the ledger keeps no replay counter), and the replay is still `EventReplayed` when the harness clock has advanced between the two lines |
| 14 | `fake.skipped-sequence` | run | sequences 1 then 3 | `PROTOCOL_FAILED`; run `FAILED`; `PROTOCOL.IDENTITY_OR_SEQUENCE_VIOLATION` |
| 15 | `fake.wrong-invocation` | run | events carry a foreign `invocation_id` | `PROTOCOL_FAILED`; run `FAILED`; `PROTOCOL.IDENTITY_OR_SEQUENCE_VIOLATION` |
| 16 | `fake.wrong-request-hash` | run | manifest `provenance.request_hash` altered | `EXITED`; run `FAILED`; `ARTIFACT.RESULT_MANIFEST_INVALID` |
| 17 | `fake.wrong-token` | run | events carry a wrong `attempt_token` | `PROTOCOL_FAILED`; run `FAILED`; `PROTOCOL.IDENTITY_OR_SEQUENCE_VIOLATION` |
| 18 | `fake.wrong-token-proof` | validate | result `attempt_token_hash` is the hash of another token | `EXITED`; run `FAILED`; `PROTOCOL.IDENTITY_OR_SEQUENCE_VIOLATION` |
| 19 | `fake.oversized-line` | run | a heartbeat padded one byte past `limits.max_event_bytes` (the request snapshot lowers it to 4096) | `PROTOCOL_FAILED`; run `FAILED`; `PROTOCOL.EVENT_TOO_LARGE` |
| 20 | `fake.stdout-noise` | run | the text line `starting engine` before the first envelope | `PROTOCOL_FAILED`; run `FAILED`; `PROTOCOL.STDOUT_CONTAMINATION` |
| 21 | `fake.describe-noise` | describe | valid output but one stdout byte | `EXITED`; `DESCRIBE_UNAVAILABLE`; `PROTOCOL.STDOUT_CONTAMINATION` |
| 22 | `fake.stderr-output` | run | as 3 plus two lines of human text on stderr, one containing the raw token | `EXITED`; `RESULT_FINALIZATION_ELIGIBLE`; `StderrCapture.sanitized_text` present and token-free; no diagnostic |
| 23 | `fake.stderr-flood` | run | as 3 plus stderr beyond the snapshot's `max_stderr_bytes` (lowered to 1 MiB) | `EXITED`; `RESULT_FINALIZATION_ELIGIBLE`; `truncated`; `PROCESS.STDERR_TRUNCATED` secondary |
| 24 | `fake.heartbeat-success` | run | heartbeats every 0.2 s for 1.5 s with interval 1 s and missing threshold 2 s, then completes | `EXITED`; `RESULT_FINALIZATION_ELIGIBLE`; no `PROCESS.MISSING_HEARTBEAT` |
| 25 | `fake.heartbeat-timeout` | run | one heartbeat, then silence; timeout 4 s, missing threshold 2 s | `TIMED_OUT`; run `TIMED_OUT`; `PROCESS.RUN_TIMED_OUT` with causal `PROCESS.MISSING_HEARTBEAT`; native exit enrichment after termination |
| 26 | `fake.process-timeout` | describe, validate, run | sleeps past a 1 s timeout | `TIMED_OUT`; describe no run and `PROCESS.DESCRIBE_TIMED_OUT`; validate run `TIMED_OUT` and `PROCESS.VALIDATE_TIMED_OUT`; run `TIMED_OUT` and `PROCESS.RUN_TIMED_OUT` |
| 27 | `fake.cancellation` | run | heartbeats until terminated; harness cancels after the first heartbeat | `CANCELLED`; run `CANCELLED`; `PROCESS.CANCELLED`; enrichment with the termination exit value |
| 28 | `fake.exit-10-run`, `fake.exit-40`, `fake.exit-50`, `fake.exit-60`, `fake.exit-70` | run | one heartbeat, manifest agreeing with the exit (`FAILED`, `FAILED`, `CANCELLED`, `TIMED_OUT`, `FAILED`), then the exit | `EXITED` with the mapped category; run `FAILED`; `SCHEMA.REQUEST_INVALID`, `ENGINE.RUNTIME_FAILURE`, `ENGINE.RUNTIME_FAILURE`, `ENGINE.RUNTIME_FAILURE`, `PROTOCOL.ADAPTER_REPORTED_VIOLATION` |
| 29 | `fake.exit-unrecognized` | run | exit 3 after one heartbeat | `EXITED` with `PROCESS.UNRECOGNIZED_PROCESS_EXIT` as the invocation's primary; run `FAILED`; `ENGINE.RUNTIME_FAILURE` with that causal reference |
| 30 | `fake.missing-manifest` | run | heartbeat, exit 0, no `FINAL_RESULT`, no file | `EXITED`; run `FAILED`; `ARTIFACT.RESULT_MANIFEST_INVALID` |
| 31 | `fake.malformed-manifest` | run | `FINAL_RESULT` points at a file holding `not json` | `EXITED`; run `FAILED`; `ARTIFACT.RESULT_MANIFEST_INVALID` |
| 32 | `fake.disagreeing-manifest` | run | exit 40 with a `SUCCEEDED` manifest that declares no candidates (so the exit-versus-status contradiction is the first failing check) | `EXITED`; run `FAILED`; `ARTIFACT.RESULT_MANIFEST_INVALID` |
| 33 | `fake.exit-0-not-applicable` | run | exit 0 with a `NOT_APPLICABLE` manifest | `EXITED`; run `FAILED`; `ARTIFACT.RESULT_MANIFEST_INVALID` |
| 34 | `fake.path-escape` | run | `ARTIFACT_PRODUCED` with `../escape.bin` | `PROTOCOL_FAILED`; run `FAILED`; `ARTIFACT.PATH_BOUNDARY_VIOLATION` |
| 35 | `fake.manifest-path-escape` | run | events clean; manifest declaration path `C:/escape.bin` | `EXITED`; run `FAILED`; `ARTIFACT.PATH_BOUNDARY_VIOLATION` |
| 36 | `fake.checksum-mismatch` | run | declares a sha256 of different bytes than it writes | `EXITED`; run `FAILED`; `ARTIFACT.VALIDATION_FAILED` |
| 37 | `fake.event-manifest-mismatch` | run | event and manifest declare different hashes for one path | `EXITED`; run `FAILED`; `ARTIFACT.RESULT_MANIFEST_INVALID` |
| 38 | `fake.crash-before-first-event` | run | `os._exit(40)` immediately | `EXITED` (40); run `FAILED`; `ENGINE.RUNTIME_FAILURE` with `manifest_present: false`; zero events |
| 39 | `fake.crash-after-partial-events` | run | three heartbeats and one `ARTIFACT_PRODUCED` whose file is never written, then `os._exit(40)` | `EXITED` (40); four accepted `RunEvent`s; run `FAILED`; `ENGINE.RUNTIME_FAILURE` |
| 40 | `fake.token-in-warning` | run | as 4 with the raw token inside the warning message, in the event and in the manifest | `EXITED`; `RESULT_FINALIZATION_ELIGIBLE`; the accepted `WARNING` event and the sanitized manifest carry `<attempt-token-redacted>`; `ProtocolEventSummary.redactions == 1` and `ManifestParse.redactions >= 1`; no diagnostic |
| 41 | `fake.token-in-candidate` | run | writes the raw token into a candidate file | `EXITED`; run `FAILED`; `SECURITY.SENSITIVE_MATERIAL_LEAKAGE` |
| 42 | `fake.core-namespace-code` | run | a `DIAGNOSTIC` event with `error_code` `SECURITY.SPOOF` | `PROTOCOL_FAILED`; run `FAILED`; `PROTOCOL.MALFORMED_JSONL` |
| 43 | `fake.describe-bad-version` | describe | bootstrap envelope with `bootstrap_schema_version` `2.0.0` | `EXITED`; `DESCRIBE_UNAVAILABLE`; `PROTOCOL.UNSUPPORTED_VERSION` |
| 44 | `fake.describe-no-common-version` | describe | `supported_protocol_versions` `("2.0.0",)` | `EXITED`; `DESCRIBE_UNAVAILABLE`; negotiation `FAILED`; `ADAPTER.UNAVAILABLE` |
| 45 | `fake.second-final-result` | run | two `FINAL_RESULT` events at sequences 3 and 4 | `PROTOCOL_FAILED`; run `FAILED`; `PROTOCOL.IDENTITY_OR_SEQUENCE_VIOLATION` |
| 46 | `fake.validate-emits-artifact` | validate | an `ARTIFACT_PRODUCED` event during validate | `PROTOCOL_FAILED`; run `FAILED`; `PROTOCOL.IDENTITY_OR_SEQUENCE_VIOLATION` |
| 47 | `fake.stale-attempt-result` | validate | one slot, one adapter name; the fake behaves as `fake.conformant` on `validate` with `attempt_number` 1, as `fake.exit-40` on `run` (run `FAILED`, `ENGINE.RUNTIME_FAILURE`, retriable), and on `validate` with `attempt_number` 2 copies `<command root>/stale-output.json` byte for byte to `--output` and exits 0; between the attempts the harness advances the clock past `retry_delay_seconds`, drives `evaluate_retry` (`sample_retry_policy`: three attempts, `FAILED` listed) and `create_successor`, and copies attempt 1's `AdapterValidationResult` file to `stale-output.json` | `EXITED`; run `FAILED`; `PROTOCOL.IDENTITY_OR_SEQUENCE_VIOLATION` at §9.2 check (3) — attempt 1's `invocation_id`, `run_id`, `request_id` and `attempt_token_hash` |
| 48 | `fake.partial-then-failed-manifest` | run | one heartbeat, one `ARTIFACT_PRODUCED` with its file written, then a `FAILED` manifest with one diagnostic and no candidates, `FINAL_RESULT`, exit 40 | `EXITED` (40); run `FAILED`; `ENGINE.RUNTIME_FAILURE` (retriable; check (9) is scoped to success statuses); sanitized manifest present; the accepted declaration is an abandoned candidate |
| 49 | `fake.token-as-path` | run | an `ARTIFACT_PRODUCED` whose `relative_path` is the raw token (a valid path segment) | `PROTOCOL_FAILED`; run `FAILED`; `ARTIFACT.PATH_BOUNDARY_VIOLATION` (the redaction placeholder fails at a path location, §7.4); the rejection sample is token-free |
| 50 | `fake.token-as-phase` | run | a `HEARTBEAT` whose `phase` is the raw token; the harness asserts `token[0].isalpha()` for this row and re-seeds its `SequentialIdentitySource` until it holds, so the un-redacted line is wire-valid and only the placeholder fails | `PROTOCOL_FAILED`; run `FAILED`; `PROTOCOL.MALFORMED_JSONL` (the placeholder fails the identifier pattern after redaction, §7.4); no `RunEvent` produced |
| 51 | `fake.oversized-manifest` | run | the request snapshot lowers `max_manifest_bytes` to its `65_536` floor; the fake writes a strict-valid manifest padded past the limit with a long warning message, then `FINAL_RESULT`, exit 0 | `EXITED`; run `FAILED`; `ARTIFACT.RESULT_MANIFEST_INVALID`; `ManifestParse.header` absent (bytes never decoded) |
| 52 | `fake.invalid-utf8-stdout` | run | a heartbeat, then a line whose bytes are `{` followed by `0xFF 0xFE` | `PROTOCOL_FAILED`; run `FAILED`; `PROTOCOL.STDOUT_CONTAMINATION`; `ContaminationSample.sample` absent |

Adapter-side verification vectors (the harness writes a conformant request, then
tampers the file before launch, against `fake.conformant`), five in all: altered
`payload_hash` (`run`); `protocol_version` `2.0.0` (`run`); the `validate` envelope
handed to the `run` sub-command; a `--work-dir` whose tail differs from
`assigned_work_dir.relative_path` (`run`); and altered `payload_hash` on a
`validate`, which proves the exit-`10` `VALIDATE` cell of §9.1. Each ends with exit
`10`, no output file and no stdout byte, and the core records run `FAILED` with
`SCHEMA.REQUEST_INVALID` carrying `manifest_present: false` for the four `run`
vectors and `output_present: false` for the `validate` vector.

### 11.3 The offline harness

`tests/contract/harness.py` defines `OfflineCommandHarness(store, clock, identity,
catalog, root: Path, limits)` with `describe(adapter_name, adapter_version, *,
timeout_seconds)`, `validate(run, *, timeout_seconds)` and `run(run, *,
timeout_seconds, cancel_after_first_heartbeat=False)`, each returning a
`CommandRun` (frozen dataclass: `command_result: CommandResult`, `outcome:
SemanticOutcome | None`, `reconciliation: SemanticReconciliation | None` (from
`reconcile_describe` for a describe, copied from `outcome` otherwise),
`observation: RuntimeAvailabilityObservation | None` (describe only),
`raw_stdout_lines: tuple[bytes, ...]`, `work_dir: Path`).
It is a stand-in supervisor for tests only and is named so in every docstring:

1. It drives the Stage 5 lifecycle with the real operations (`create_experiment`,
   `transition_experiment` `DRAFT → VALIDATED`, `queue_experiment`, `create_attempt`,
   and for row 47 `evaluate_retry` then `create_successor` under
   `sample_retry_policy` with the clock advanced past the retry delay): `transition_run`
   (`PENDING → VALIDATING` before a validate, and `PENDING → VALIDATING → READY` with
   the slot's `availability_observation_id` before a run row, so no validate child
   is launched for a run row except row 47; `assert_parent_run_eligibility`
   requires a `VALIDATING` parent, and a run's parent is already `READY`),
   `create_invocation`, `transition_invocation` (`PENDING → STARTING`, describe and validate) or
   `begin_linked_launch` (run); writes the request envelope (§6.1) under
   `root/<invocation_id>/request.json` after the deadline exists — that
   per-invocation directory is the **command root**: the child's `cwd`, the parent
   of the `--output` file, of `--work-dir` (`<command root>/runs/<run_id>/work`)
   and of `--result` (`<work dir>/adapter-result-manifest.json`), and the root the
   write-boundary snapshot of `test_harness_safety.py` compares; launches
   `[sys.executable, "-I", "-B", <fake_adapter.py>, *argument_array(command)]` with
   `subprocess.Popen(..., shell=False, env={}, cwd=<command root>, stdin=DEVNULL,
   stdout=PIPE, stderr=PIPE)` (the empty environment block was probed to start a
   CPython child on this host); then `transition_invocation` (`STARTING → RUNNING`)
   or `start_linked_run` with `ProcessStartFacts(pid_identity=ProcessIdentity(pid,
   creation_identity=f"offline-harness:{pid}", executable_path, executable_hash,
   supervisor_instance_id="offline-harness"), process_started_at_utc=clock.now_utc())`,
   with `executable_path` and `executable_hash` copied from the catalog entry (the
   script), never `sys.executable`.
2. Two reader threads move stdout lines and stderr chunks into queues; the main
   loop polls with `time.monotonic()` (test code only) against the command deadline
   and the missing-heartbeat threshold (armed when the invocation reaches `RUNNING`
   at `start_linked_run` or `STARTING → RUNNING`, spec 15.3's threshold running
   from process start, and reset on every accepted `HEARTBEAT`; row 24's 2 s
   threshold therefore also bounds the fake's start-up time). For `validate` and `run` it feeds each line
   to `parse_protocol_line` and the ledger and appends accepted events through
   `append_event`; for `describe` it never parses stdout and only counts the bytes.
   The missing-heartbeat timer mints `PROCESS.MISSING_HEARTBEAT` once and never
   terminates the child; termination (`proc.kill()`) happens only on a rejected
   line, the command deadline, or cancellation. A `PROCESS.MISSING_HEARTBEAT` minted
   for a child that then completes before its deadline is recorded like
   `PROCESS.STDERR_TRUNCATED`: on the `EXITED` invocation through the same
   `enrich_invocation` (`additional_diagnostic_ids`) and in `CommandResult.diagnostics`;
   when the deadline wins instead (row 25), its identity is merged into the
   `TIMED_OUT` transition's `diagnostic_ids` as well as cited causally by
   `PROCESS.RUN_TIMED_OUT`.
3. Terminal mapping: a rejected line (validate or run only) →
   `transition_invocation_and_run` to `PROTOCOL_FAILED` with run `FAILED`; a
   deadline → `TIMED_OUT` with the command-specific code (coupled for validate and
   run, `transition_invocation` for describe); cancellation → `CANCELLED` with
   `PROCESS.CANCELLED` (likewise); then `enrich_invocation` with the native exit once
   reaped. A normal exit → `transition_invocation` (`RUNNING → EXITED`), minting
   and seeding `PROCESS.UNRECOGNIZED_PROCESS_EXIT` first for an unrecognized value.
   Every harness-minted diagnostic — the core-won terminal primaries, the
   missing-heartbeat causal reference, `PROCESS.STDERR_TRUNCATED` — is seeded into
   the store before the transition that references it (`seed_diagnostic` raises on
   a duplicate, so each identity is seeded once), so a later retry evaluation over
   any harness-produced run finds its primary.
   The exit is mapped only after the stdout reader has reached end of stream and
   every buffered line, plus any unterminated fragment (§7.1 rule 3), has been fed
   to `parse_protocol_line`; a rejection found during that drain wins and
   terminalizes as `PROTOCOL_FAILED` before the reaped exit is applied as
   enrichment, so an `EXITED` invocation produced by the harness always has
   `protocol_integrity: INTACT`, §9.2 check (1) is reached only by Task 6's direct
   unit case, and `test_harness_safety.py` asserts that no `EXITED` scenario
   reports `VIOLATED`.
4. For an `EXITED` invocation it parses the output bytes with
   `parse_bootstrap_descriptor`, or with `parse_validation_result` /
   `parse_result_manifest` handing them the run's raw token from the
   `AttemptTokenMaterial` it holds since `create_attempt`, computes a
   `CandidateObservation` for every path declared by an accepted `ARTIFACT_PRODUCED`
   event or by the manifest (the union, so an abandoned candidate still reaches the
   leakage check; a manifest-declared path is observed only when the manifest is a
   success declaration, which keeps the union within `2 × MAX_CANDIDATE_ARTIFACTS`)
   under the work dir (size, sha256, `token_present`); a declared path whose file
   does not exist yields no `CandidateObservation` — the harness never fabricates
   or raises, and the reconciler's check (10) then reports a manifest declaration
   without an observation while an event-only declaration is simply unobserved —
   and calls
   `reconcile_describe`
   (describe; then, when the reconciliation minted at least one diagnostic — every
   verdict except `DESCRIBED` — `enrich_invocation` with those identities, §5.4) or
   `apply_command_semantic_outcome` (validate, run) with the request's
   `negotiated_versions` and, when the invocation ended `EXITED`, `protocol_failure`
   absent, and then seeds every returned `Diagnostic` not already present (the
   reconciliation diagnostics exist only after the call, §10 step 9). For a
   core-won terminal (`PROTOCOL_FAILED`, `TIMED_OUT`, `CANCELLED`)
   `CommandRun.outcome` is `None`. Every describe that reached `EXITED` (with the
   reconciliation's verdict and primary) or `TIMED_OUT` (with
   `PROCESS.DESCRIBE_TIMED_OUT`) is projected through
   `describe_availability_observation` with the harness's constant runtime facts
   (§5.4) and an `observation_id` derived as the merged `AvailabilityObservationId`
   prefix plus `_uuid4_shaped(sha256(invocation_id))`, because no `IdentitySource`
   method exists for it (§2.6); a cancelled describe mints no observation. The
   harness's own enrichment (`PROCESS.STDERR_TRUNCATED`, `PROCESS.MISSING_HEARTBEAT`,
   step 2) happens before the operation, so the operation reads the enriched
   revision, and `CommandResult.invocation` is the invocation the operation returned
   (or the harness-enriched one when no operation ran). The harness's terminal-mapping helper is also
   callable without a child, which is how Task 8 exercises
   `PROCESS.START_TIMED_OUT` (a `STARTING` invocation with a `STARTING` run driven
   to the coupled `TIMED_OUT`).
5. `assert_token_absent(objects, token)` in `tests/contract/harness.py` walks the
   canonical JSON of every core projection — every `RunEvent`, the sanitized
   manifest, every `Diagnostic`, the `CommandResult` with `parsed_output` excluded
   only when it is an `AdapterResultManifest` (the redacted validation result and
   the bootstrap envelope are walked), and the stderr capture — and fails on any
   occurrence; every validate and run row calls it, and describe rows skip it
   because a describe has no attempt token. Its complement
   `assert_token_only_in_wire_material(command_run, token)`, called by every
   validate and run row, asserts absence outside the trust-class-W set and presence
   in each W object that exists: the request file always, every accepted-envelope
   stdout line, and — when `CommandResult.parsed_output` is an
   `AdapterResultManifest` — both the manifest file's bytes and that parsed model
   (rows 31 and 35 have no parsed manifest and assert no manifest presence). Its
   absence universe is exactly the object set `assert_token_absent` walks plus
   `CommandRun.outcome` and `CommandRun.reconciliation`; every `raw_stdout_lines`
   entry, accepted or rejected, is W wire material on which it asserts nothing
   beyond presence in the accepted lines, and candidate files under `work_dir` are
   outside both sets (row 41's leakage is proven by its verdict and
   `CandidateObservation.contains_attempt_token`, not by this helper).

Test modules — the directory carries `tests/contract/__init__.py`, and every
consumer (the six test modules, the Stage 6 guard and Task 9's flow test) imports
`from contract.harness import …` / `from contract.scenarios import …`, the merged
`from doubles.experiments import …` pattern, so pytest and strict mypy agree on one
module name: `tests/contract/scenarios.py` (the §11.2 table as data: adapter name,
command, expected states and codes, timeouts), `test_describe_contract.py`,
`test_validate_contract.py`, `test_run_contract.py`,
`test_protocol_failure_contract.py`, `test_adapter_side_verification.py`,
`test_harness_safety.py` (the launch helper returns exactly the argument array,
`shell=False`, `env == {}`, a list argv whose first element is the test process's
own `sys.executable` — never a PATH lookup, spec 14.1's "no executable discovery
from untrusted paths" — and a cwd under the harness root; every scenario catalog
holds at most `MAX_CATALOG_ENTRIES` entries and the constant is still `32`; the
fake adapter script imports only the allowed stdlib roots; describe, validate and
run never wrote outside their permitted paths — the harness snapshots the command
root before and after; the `PROCESS.START_TIMED_OUT` direct case).

## 12. Schemas (matrix F)

### 12.1 Registry extension

Eight entries appended after the twenty-seven existing ones, extending the registry
from 27 to 35; every path is a new lexical descendant of `schemas/protocol/`, every
identifier a new permanent `urn:crypto-lab:schema:protocol:<name>:1.0.0`, every
adapter a fresh `TypeAdapter` (no new singleton). Existing entries are never
reordered and no published identifier is reused.

| Position | Path | `$id` | Model |
|---|---|---|---|
| 27 | `protocol/bootstrap-descriptor-envelope-v1.schema.json` | `urn:crypto-lab:schema:protocol:bootstrap-descriptor-envelope:1.0.0` | `BootstrapDescriptorEnvelope` |
| 28 | `protocol/negotiation-result-v1.schema.json` | `urn:crypto-lab:schema:protocol:negotiation-result:1.0.0` | `NegotiationResult` |
| 29 | `protocol/adapter-command-request-envelope-v1.schema.json` | `urn:crypto-lab:schema:protocol:adapter-command-request-envelope:1.0.0` | `AdapterCommandRequestEnvelope` |
| 30 | `protocol/protocol-event-envelope-v1.schema.json` | `urn:crypto-lab:schema:protocol:protocol-event-envelope:1.0.0` | `ProtocolEventEnvelope` |
| 31 | `protocol/run-event-v1.schema.json` | `urn:crypto-lab:schema:protocol:run-event:1.0.0` | `RunEvent` |
| 32 | `protocol/adapter-validation-result-v1.schema.json` | `urn:crypto-lab:schema:protocol:adapter-validation-result:1.0.0` | `AdapterValidationResult` |
| 33 | `protocol/adapter-result-manifest-v1.schema.json` | `urn:crypto-lab:schema:protocol:adapter-result-manifest:1.0.0` | `AdapterResultManifest` |
| 34 | `protocol/sanitized-adapter-result-manifest-v1.schema.json` | `urn:crypto-lab:schema:protocol:sanitized-adapter-result-manifest:1.0.0` | `SanitizedAdapterResultManifest` |

Not published, by decision: `AdapterCatalogEntry`, `AdapterCommand`,
`CommandResult`, `SanitizedEngineRunRequest`, `SemanticReconciliation`,
`ProtocolEventSummary`, `CandidateObservation` and every request model. The three
token-bearing wire schemas (29, 30, 33) publish an `attempt_token` string field:
the `AttemptToken` comment sentence "no registered schema publishes this
projection" is corrected by Task 1 to "no registered schema for a persisted record
publishes this projection; the three temporary wire contracts of Stage 6 do", which
changes no schema bytes because it is a source comment, not a description.

### 12.2 Nested `$defs` a Stage 6 file re-renders

`AdapterDescriptor`, `EngineDescriptor`, `SupportedSchemaVersion`,
`OperatingSystem`, `CommandKind`, `CalendarValidUtcDateTime`, `ComparisonLevel`,
`DiagnosticSeverity`, `Money`, `FeeAssumptions`, `SlippageAssumptions`,
`ExecutionAssumptions`, `AdapterIdentity`, `EngineIdentity`, `AssetCode` (through
`Money`), `ErrorCode`, `DiagnosticDetailKey`, `DiagnosticDetailValue` (with its
recursive `DiagnosticDetailString` and `BoundedDetailInteger`), `SlippageModel`, `SignalToOrderTiming`, `BarOrderPriority`, `FillConvention`,
`CanonicalDecimal`, `NonNegativeDecimal`, `AttemptToken`, the identifier aliases,
`SemanticVersion`, and the new `MediaType` and `RelativeCandidatePath` (both PEP 695
`type` aliases, so they render as `$defs` exactly like the identifier aliases);
`VocabularyVersion`, `BoundedText` and `CapabilityName` are plain `Annotated`
aliases and inline rather than render; none
carries `UtcDateTime`, so the §2.4 forward-view conclusion stands.
`DiagnosticCategory` is not re-rendered because
`AdapterDiagnosticCategory` is its own enum, and `Diagnostic` is never nested
(§2.4). Each nested body renders byte-identically to its existing body under its
bare name; no existing file moves.

### 12.3 Schema tests (Task 9), the exact shape of the Stage 6 block

`_STAGE6_PATHS` (8), `_STAGE6_SHA256` (8 digests keyed on paths, disjoint from the
three earlier blocks), `_STAGE6_CLOSED_ENUMS` (`SemanticStatus` 7,
`ValidationOutcome` 4, `ProtocolEventType` 6, `NegotiationOutcome` 2,
`AdapterDiagnosticCategory` 3, `CommandKind` 3, `DiagnosticSeverity` 4,
`ComparisonLevel`, `OperatingSystem` 3, and — reached through schema 29's
`RunConfigurationSnapshot` — `SlippageModel`, `SignalToOrderTiming`,
`BarOrderPriority`, `FillConvention`, member by member), `_STAGE6_REQUIRED` and
`_STAGE6_OPTIONAL` per schema in declaration order with `schema_version` and,
where the record carries it (schemas 29–34), `protocol_version` as `{"const":
"1.0.0"}` — schema 27 pins `bootstrap_schema_version` instead and schema 28 has no
`protocol_version` — `_STAGE6_UNIQUE_POINTERS` (every
sorted-unique tuple position, exact census), `additionalProperties: false` on every
object, both generation modes identical, Draft 2020-12 validity, document-local
`$ref`s, no `$`-terminated pattern, no `UtcDateTime` `$def` (the forward-view rule),
`_stage6_baselines()` built from the runtime (one accepting document per schema plus
the fake adapters' own outputs captured from scenario 1–3), and per-schema
"reject every expressible violation" tables with exact counts where each rejected
document is rejected by the committed bytes and by the runtime and is paired with an
accepting baseline. `test_the_stage_six_runtime_only_rules_stay_one_directional`
pins the register of §12.4 with one document per bullet, accepted by the bytes and
rejected by the runtime.

### 12.4 Runtime rules the Stage 6 schemas cannot express (register)

Recorded for `docs/development/verification.md`, one bullet each: the declared
deviation `NegotiationResult.reason_codes` for spec 11.3's `diagnostics` (§3.8);
the `RUN_EVENT_CONTENT_V1` exclusion of `received_at_utc` and `wire_event_hash` as
the reading of spec 10.2 and 11.3 that makes 14.4's replay rule satisfiable (§4);
the canonical value forms an adapter must emit for the stdlib-reproducible hashes
(§4); the adapter-diagnostic reference carried as `details` rather than
`causal_diagnostic_ids` (§3.9); `CommandResult.parsed_output`'s describe member
being the bootstrap envelope rather than spec 14.1's bare `AdapterDescriptor`
(§3.7); `list_events` as a declared port extension (§7.5); the cross-field rules
published as `if`/`then` and therefore exact — the `NEGOTIATED`/`FAILED`
biconditionals over `outcome` (§3.8), `value_status` `DEFINED` iff `value`
present, `SUCCEEDED` ⇒ empty `warnings`, `SUCCEEDED_WITH_WARNINGS` ⇒ non-empty
`warnings`, a non-success status ⇒ at least one diagnostic and no candidate
(§3.10), `INVALID`/`NOT_APPLICABLE`/`UNAVAILABLE` ⇒ at least one diagnostic on the
validation result (§3.10), `ResourceObservation` at least one field present
(`anyOf` over `required`, §3.9); and the cross-field rules that stay runtime-only
— `comparison_level == configuration_snapshot.comparison_level` and
`payload.request_id == request_id` (§3.6), the missing-heartbeat threshold at
least twice the interval (§3.2);
the adapter-namespace rule for `error_code`/`warning_code` (a prefix rule is
expressible as a pattern and **is** published; the *core-namespace* denial is the
same pattern, so this row is exact, not a residual); `payload_hash`, `result_hash`,
`descriptor_payload_hash`, `content_hash`, `request_hash` and
`sanitized_adapter_result_manifest_hash` recomputation (inexpressible);
`ProgressPayload.percentage <= 100` on a decimal string and the positive amount of
`RunConfigurationSnapshot.starting_balance` on the shared `Money` (runtime-only);
`deadline_utc == created_at_utc + timeout_seconds` and `completed_at_utc >=
started_at_utc` (cross-field); bootstrap header equality with the nested descriptor
(cross-field); `candidate_artifact_ids` equal to the declaration identities
(cross-field); `total_units >= completed_units` (cross-field); sortedness of
unbounded-domain collections (`approximations`, `candidate_artifact_ids`,
`causal_event_ids`, `reason_codes`); uniqueness of declarations on `relative_path`
and metrics on `metric_name` (key-based, published as whole-value `uniqueItems`,
a sound partial tightening); the command↔payload pairing (schema 29) and the
event-type↔payload pairing (schemas 30 **and** 31, the envelope and the published
`RunEvent`) **are** published as `if`/`then` and are exact, as is the
status↔`warnings`/`diagnostics`/candidates coupling on schemas 33 and 34; the
reserved-device-stem and
trailing-dot rules of §3.3 are published inside the path pattern and are exact.

## 13. Protocol safety requirements, each with its enforcement

| Requirement | Enforced by |
|---|---|
| Adapters are untrusted | every adapter-authored record is trust class W (§3.1); nothing W is persisted; every W record passes strict validation, identity checks and sanitization before a C record exists |
| Engines run outside the core process | no `subprocess` in `src` (Stage 5 guard, kept); the fake adapters are child processes of the test harness only; `crypto_lab` imports nothing from `tests/` |
| No shell invocation | the harness launches a list argv with `shell=False`; the Stage 6 guard walks every `tests/**/*.py` with `ast` and flags any **call** of `subprocess.*`, `os.system`, `os.popen`, `os.spawn*` or `os.startfile` outside the pinned importer allowlist, and any `subprocess` call whose first positional argument is a `str` constant or whose keywords include `shell=True`; string constants and assignment targets are not calls and are not flagged (three merged test files carry `os.system` only inside string constants; the assignment-target exemption is proven by a planted `os.system = sentinel` negative control in Task 9) |
| Bounded request, event and result sizes | §3.2 constants; §7.1 byte limit before decoding; manifest, descriptor and validation ceilings in §9.2 and §5.4; every collection has a `max_length` |
| Strict unknown-field rejection | `CanonicalModel` `extra="forbid"` on every model; `additionalProperties: false` asserted on every published object |
| Strict command and protocol versions | `Literal["1.0.0"]` on both version fields (§5.1); `PROTOCOL.UNSUPPORTED_VERSION` |
| Deterministic event sequencing | §7.3; `MAX_SEQUENCE`; the ledger is a pure fold |
| Duplicate and gap detection | §7.3 conflicting duplicate, identical replay, gap and out-of-order rules; `append_event` refuses two contents under one key |
| Invocation-scoped event identity | `(invocation_id, sequence)` identity; wrong, stale or foreign `invocation_id` rejected before any other classification (spec 21.2.1 precedence) |
| Stdout reserved for protocol events | §7.1 rules 2, 3 and 5 |
| Stderr treated as bounded human-readable output | `BoundedStderrCapture` (§7.6); stderr never enters parsing; `PROCESS.STDERR_TRUNCATED` |
| Process exit is not sufficient for semantic success | §9.1: exit 0 without a valid matching manifest is `FAILED`; `EXITED` never implies success; the `ProcessExitCategory` docstring's promise that Stage 6 derives the semantic result is implemented by §9.2 |
| An adapter result manifest is untrusted until reconciled | §9.2 order of checks; the sanitized manifest exists only after them |
| Paths remain within assigned roots | §3.3 textual rule on every declared path; `ARTIFACT.PATH_BOUNDARY_VIOLATION`; Stage 7 and 9 resolve against real roots |
| Raw attempt tokens never enter durable records | every C record carries `attempt_token_hash`; `redact_payload`; `assert_token_absent` in every scenario; `SemanticOutcomeRequest.parsed_output` is the one token-bearing `experiments` request field and the request is transient (§3.12); the Stage 6 guard's allowlist of the exact classes permitted to carry a field annotated `AttemptToken` (`EngineRunRequest`, `ProtocolEventEnvelope`, `AdapterResultManifest`, `AttemptTokenMaterial`); the scan keys on the annotation, not the field name, so the merged `AttemptCreation.attempt_token` (typed by the `AttemptTokenMaterial` wrapper) is the near-miss control that proves the basis |
| No adapter receives a database handle or authoritative final path | `AdapterCommand` carries only command-root paths (§3.7); `argument_array` renders exactly spec 14.1; the harness safety test pins both |
| An adapter cannot mark a run successful directly | §9.3: success is a verdict, the run stays `RUNNING`, only Stage 9 commits `SUCCEEDED*` |
| Malformed output cannot produce false success | §9.1 and §9.2: every malformed, missing, mismatched or contradictory output ends in a non-success verdict with a hard-blocking or exit-derived diagnostic |
| Restart cannot duplicate accepted events or falsely finalize a run | `InvocationEventLedger.from_events` rebuilt from `list_events`; `append_event` idempotency; `apply_command_semantic_outcome` replay rule; no Stage 6 path writes success |

## 14. Task decomposition

Nine vertical tasks. No task depends on a file created by a later task. Each is
test-first: focused RED, minimum implementation, focused GREEN, then broader
verification; each ends in one commit and a clean worktree. Focused runs use the
launcher `pytest-focused` profile with `-o addopts=` (diagnostic only, no coverage
number). **Every task that creates a module under `src/crypto_lab` or first defines
a deferred name also edits `tests/safety/test_stage3_boundaries.py` and
`tests/unit/test_package_layout.py` exactly as §2.6 tabulates; those two files are
owned by Tasks 1–7 and are not repeated in each list, and each such task's focused
RED includes the §2.6 guard expectations for its own paths and names** (set test
naming the missing path; deferred count failing until exactly the task's names are
removed; per-name absence guard passing for every remaining name; seven live
mutation cases after the task's swap). Every task's **Quality gates** are the
launcher `ruff-format-all` (apply the printed diff by hand), `ruff-check-all`,
`mypy-all` and `schema-generate-check` (which must stay clean until Task 9
registers the entries), and every task's **Independent review** is a fresh reviewer
over the task's diff with the task's declared readings listed. Every step below is a
checkbox for the executor.

### Task 1 — Protocol vocabulary, limits, paths, catalog, diagnostics and hashing profiles

**Files created.** `src/crypto_lab/adapters/vocabulary.py`,
`src/crypto_lab/adapters/limits.py`, `src/crypto_lab/adapters/paths.py`,
`src/crypto_lab/adapters/catalog.py`, `src/crypto_lab/adapters/diagnostics.py`,
`tests/unit/adapters/test_protocol_vocabulary.py`,
`tests/unit/adapters/test_protocol_limits.py`,
`tests/unit/adapters/test_candidate_paths.py`,
`tests/unit/adapters/test_adapter_catalog.py`,
`tests/unit/adapters/test_adapter_diagnostics.py`,
`tests/property/test_candidate_path_boundaries.py`.
**Files modified.** `src/crypto_lab/domain/hashing.py` (four `HashingProfile`
members, `request_id_for`, `candidate_artifact_id_for`),
`src/crypto_lab/domain/identifiers.py` (`RequestId`, `AdapterManifestId`,
the `AttemptToken` comment correction of §12.1), `src/crypto_lab/domain/__init__.py`
(two sorted exports), `src/crypto_lab/adapters/__init__.py`,
`tests/unit/domain/test_lifecycle_tables.py` (`8` → `12`),
`tests/unit/domain/test_identifiers.py` (two alias cases), and the two §2.6 guard
files.
**Interfaces consumed.** Source: `CanonicalModel`, `NormalizedIdentifier`,
`SemanticVersion`, `Sha256`, `ExecutablePath`, `EngineIdentity`,
`DiagnosticDetailKey`, `DiagnosticDetailValue`, `_inspect_details`, `Diagnostic`,
`DiagnosticCategory`, `DiagnosticSeverity`, `ErrorCode`, `Failure`, `Result`,
`Clock`, `HashingProfile`, `profile_hash`, `_uuid4_shaped`, `exact_string_schema`,
`validate_prefixed_uuid4`, `REASON_LATE_NOT_APPLICABLE`. Test-only:
`STAGE5_DIAGNOSTIC_CODES` (the posture
equality assertion; `adapters` never imports `experiments`).
**Interfaces produced.** `SemanticStatus`, `ValidationOutcome`, `ProtocolEventType`,
`NegotiationOutcome`, `ProtocolIntegrityStatus`, `ReconciliationVerdict`,
`AdapterDiagnosticCategory`; every constant and `ProtocolLimits` of §3.2;
`RelativeCandidatePath`, `validate_relative_candidate_path`;
`AdapterCatalogEntry`, `AdapterCatalog`, `FrozenAdapterCatalog` (clock-injected);
`NEGOTIABLE_SCHEMA_NAMES` (in `vocabulary.py`, consumed by Tasks 2 and 3);
`STAGE6_DIAGNOSTIC_CODES`, `stage6_diagnostic`, `stage6_failure`; `RequestId`,
`request_id_for`, `AdapterManifestId`; `HashingProfile.ADAPTER_REQUEST_V1`,
`RUN_EVENT_CONTENT_V1`, `SANITIZED_ADAPTER_RESULT_MANIFEST_V1`,
`CANDIDATE_ARTIFACT_IDENTITY_V1`; `candidate_artifact_id_for`. Releases
`SemanticStatus`, `ValidationOutcome`, `AdapterCatalog`, `AdapterCatalogEntry`
(deferred count 49); appends five paths (allowlist 74); swaps `ValidationOutcome`
for `ProcessSupervisor` in the seven-name list.

- [ ] **Step 1: Focused RED.** Write the tests: every enum asserted member by member
  against §3.4 with `len` pinned; every §3.2 constant asserted by value and each
  `ProtocolLimits` bound rejected one below and one above; §3.3 accepted shapes each
  paired with its listed near-miss rejection, the Windows reserved stems and
  trailing-dot cases, and the three accepted lookalikes; `FrozenAdapterCatalog`
  rejecting a duplicate or unsorted entry pair and a thirty-third entry, `get`
  returning `ADAPTER.UNAVAILABLE` for a missing identity with the identity in
  `details` and the injected clock's instant on the diagnostic (proven with a
  `CountingClock`), `list_registered` sorted; `AdapterCatalogEntry` rejecting a
  relative `executable_path`, a `..` segment and a secret-like `runtime_metadata`
  key; the twenty-five codes of §9.4 asserted against their category, retriable
  flag and severity, `PROCESS.UNRECOGNIZED_PROCESS_EXIT` asserted equal in posture
  to the Stage 5 table, the `COMPAT.LATE_NOT_APPLICABLE` key being the imported
  `REASON_LATE_NOT_APPLICABLE` object, a code outside the table rejected, `invocation_id` required
  for every command-category code, identity derived (two calls with equal content
  give one id; a changed message gives another; a changed timestamp does not);
  `request_id_for` deterministic and `req_`-prefixed; `candidate_artifact_id_for`
  deterministic and sensitive to each of its three inputs; the property test
  generating arbitrary ASCII strings and asserting acceptance exactly on the §3.3
  grammar; `len(HashingProfile) == 12` and the render scan still finding no
  `HashingProfile` in any schema; the §2.6 guard expectations for this task.
- [ ] **Step 2: Run the focused set and confirm every new test fails for the
  expected reason** (`ImportError` for the new modules; `== 8` for the profile count;
  the allowlist set test naming the five missing paths; the deferred count at 53).
- [ ] **Step 3: Minimum GREEN.** The five modules, the two aliases, the four
  profile members, the exports.
- [ ] **Step 4: Focused GREEN.** `tests\unit\adapters tests\unit\domain
  tests\property tests\safety tests\unit\test_package_layout.py -q`.
- [ ] **Step 5: Quality gates, Security review, Independent review.**

**Broader tests.** `tests\unit tests\safety tests\architecture`.
**Quality gates.** As stated above.
**Security review.** No filesystem, environment or process access in any new module;
`FrozenAdapterCatalog` never scans; `runtime_metadata` reuses the secret-key
rejection; the catalog is the only source of executable paths.
**Independent review.** Declared readings to confirm: uppercase event-type values;
the §3.3 grammar; the describe identity as `request_hash`; the derived identities.
**Commit message.** `feat: add stage 6 protocol vocabulary, limits, paths and catalog`
**Clean-worktree boundary.** `git status --short` empty after the commit; every
guard edit travels in this commit.

### Task 2 — Request envelopes and command contracts

**Files created.** `src/crypto_lab/adapters/envelopes.py`,
`src/crypto_lab/adapters/commands.py`,
`tests/unit/adapters/test_request_envelopes.py`,
`tests/unit/adapters/test_adapter_commands.py`,
`tests/property/test_request_hash_determinism.py`.
**Files modified.** `src/crypto_lab/adapters/__init__.py` and the two §2.6 guard files.
**Interfaces consumed.** Task 1 output; `AttemptToken`, `attempt_token_hash`,
`Money`, `FeeAssumptions`, `SlippageAssumptions`, `ExecutionAssumptions`,
`ComparisonLevel`, `SupportedSchemaVersion`, `VocabularyVersion`,
`CalendarValidUtcDateTime`, `CommandKind`, `command_timeout_bounds`,
`CommandInvocationRecord`, `EngineRunRecord`, `ExperimentRecord`,
`canonical_json_bytes`, `sha256_bytes`.
**Interfaces produced.** `DescribeRequestPayload`, `WorkDirectoryReference`,
`RunConfigurationSnapshot`, `NegotiatedVersions`, `EngineRunRequest`,
`SanitizedEngineRunRequest`, `AdapterCommandRequestEnvelope`, `payload_hash_of`,
`request_material_hash`, `request_hash_of`, `sanitize_engine_run_request`,
`build_engine_run_request`, `build_request_envelope`, `request_envelope_bytes`;
`AdapterCommand`, `argument_array`. Releases `AdapterCommandRequestEnvelope`,
`EngineRunRequest`, `AdapterCommand` (count 46); appends two paths (allowlist 76);
swaps `EngineRunRequest` for `RunManifest` in the seven-name list.

- [ ] **Step 1: Focused RED.** Envelope: command↔payload mismatch rejected both ways;
  timeout outside the kind's bounds rejected; `deadline_utc` not equal to
  `created_at_utc + timeout_seconds` rejected; `payload_hash` mismatch rejected;
  unknown header field rejected; the raw token absent from `repr` and present
  exactly once in `request_envelope_bytes`; `SanitizedEngineRunRequest` carrying
  `attempt_token_hash(token)` and no `attempt_token` key in its dump;
  `request_material_hash` computed from a `sample_experiment`, its slot, attempt
  number 1, negotiated versions and limits **before** any run exists, then
  `create_attempt` driven with that hash and `build_engine_run_request` built from
  the returned record and `AttemptTokenMaterial` with `request_hash_of(request) ==
  run.request_hash` (the profile's named exclusions proven one by one: changing
  `run_id`, `request_id`, the token, the relative work path or `created_at_utc`
  leaves the hash unchanged, while changing any material field changes it); an
  `EngineRunRequest` whose `request_hash` does not recompute rejected;
  `build_engine_run_request` rejecting a run whose slot is not in the spec and a
  token whose `run_id` is another run's, and copying `approximation_ids` from the
  frozen slot; `build_request_envelope`
  rejecting a `PENDING` invocation and taking `created_at_utc` from
  `launch_attempted_at_utc`; `argument_array` asserted byte-exact for all three
  kinds; `AdapterCommand` rejecting `output_path` on `RUN`, `work_dir` on
  `VALIDATE`, a relative path anywhere; the property test: `request_hash_of`
  invariant under key permutation of the dumped payload and under every excluded
  field, and sensitive to every material field (one mutation per field); the §2.6
  expectations.
- [ ] **Step 2: Confirm RED.**
- [ ] **Step 3: Minimum GREEN.** The two modules.
- [ ] **Step 4: Focused GREEN.** `tests\unit\adapters tests\property tests\safety -q`.
- [ ] **Step 5: Quality gates, Security review, Independent review.**

**Broader tests.** `tests\unit tests\safety`.
**Quality gates.** As stated in the section preamble.
**Security review.** `AdapterCommand` carries no request material; only
`request_envelope_bytes` emits the token and its docstring says it is never
persisted; `repr=False` on every token field.
**Independent review.** Declared readings: `request_id` derivation; `assigned_work_dir`
as a root label plus relative path; the snapshot's content.
**Commit message.** `feat: add adapter request envelopes and command contracts`
**Clean-worktree boundary.** As Task 1.

### Task 3 — Bootstrap descriptor envelope and negotiation

**Files created.** `src/crypto_lab/adapters/negotiation.py`,
`tests/unit/adapters/test_protocol_negotiation.py`.
**Files modified.** `src/crypto_lab/adapters/__init__.py` and the two §2.6 guard files.
**Interfaces consumed.** Tasks 1–2 output; `AdapterDescriptor`, `EngineDescriptor`,
`SupportedSchemaVersion`, `highest_common_stable_version`,
`RuntimeAvailabilityObservation`, `OperatingSystem`.
**Interfaces produced.** `BootstrapDescriptorEnvelope`, `CoreProtocolSupport`,
`CORE_PROTOCOL_SUPPORT` (consuming Task 1's `NEGOTIABLE_SCHEMA_NAMES`), `NegotiationResult`,
`negotiate_protocol`, `negotiated_versions_of`, `DescriptorHeader`, `DescriptorParse`,
`parse_bootstrap_descriptor`, `describe_availability_observation` (the §5.4
signature, which depends only on Task 1 types and merged domain types). Releases
`BootstrapDescriptorEnvelope`, `NegotiationResult`, `negotiate_protocol` (count
43); appends one path (allowlist 77).

- [ ] **Step 1: Focused RED.** Envelope header/descriptor disagreement rejected for
  each of the seven mirrored fields; `descriptor_payload_hash` mismatch rejected;
  vocabulary version not among the declared versions rejected; version tuples
  lexically sorted but numerically unsorted (`1.10.0` before `1.9.0`) rejected;
  `parse_bootstrap_descriptor` mapping oversized bytes, non-UTF-8, a non-object,
  unknown fields and `bootstrap_schema_version` `2.0.0` to the §9.4 codes with the
  permissive header populated whenever the bytes were decoded to a JSON object
  (never for oversized bytes, which are not decoded); negotiation: highest
  common protocol selected numerically from unsorted adapter lists (`1.10.0` over
  `1.9.0`); an adapter omitting one negotiable schema name fails; a disjoint
  vocabulary fails; a selected vocabulary differing from the descriptor's declared
  one fails; `FAILED` results carry `ADAPTER.UNAVAILABLE` and no selected field;
  `NEGOTIATED` results carry all three and empty reasons; every candidate tuple
  sorted and equal to the intersection; `negotiated_versions_of` rejecting a
  `FAILED` result; `describe_availability_observation` producing `available=True`
  exactly for verdict `DESCRIBED` with `primary_code` required `MISSING` there and
  required present otherwise, `reason_code` equal to the supplied primary code
  otherwise (including a `PROCESS.DESCRIBE_TIMED_OUT` describe with no descriptor),
  and copying the descriptor's network and credential flags when present and
  `false` otherwise; the §2.6 expectations.
- [ ] **Step 2: Confirm RED.**
- [ ] **Step 3: Minimum GREEN.**
- [ ] **Step 4: Focused GREEN.** `tests\unit\adapters tests\safety -q`.
- [ ] **Step 5: Quality gates, Security review, Independent review.**

**Broader tests.** `tests\unit tests\safety`.
**Quality gates.** As stated in the section preamble.
**Security review.** Negotiation never guesses or downgrades; an empty intersection
is unavailability; the bootstrap version is a fixed literal.
**Independent review.** Declared readings: the five negotiable names; plural
vocabulary versions on the bootstrap envelope; `adapter_version` added to
`NegotiationResult`.
**Commit message.** `feat: add bootstrap descriptor envelope and protocol negotiation`
**Clean-worktree boundary.** As Task 1.

### Task 4 — Protocol events, sanitization, the event ledger and `append_event`

**Files created.** `src/crypto_lab/adapters/events.py`,
`src/crypto_lab/adapters/sanitization.py`,
`tests/unit/adapters/test_protocol_events.py`,
`tests/unit/adapters/test_event_ledger.py`,
`tests/unit/adapters/test_protocol_sanitization.py`,
`tests/property/test_event_chunk_boundaries.py`,
`tests/property/test_run_event_idempotency.py`.
**Files modified.** `src/crypto_lab/experiments/ports.py` (its module docstring —
retire the "`append_event` is deliberately absent" sentence and add `list_events`
to the declared-extension list, citing §7.5 — and the two methods `append_event`,
`list_events`), `tests/doubles/experiments.py` (`run_events` table, both methods,
`committed_run_events`), `tests/unit/experiments/test_port_contracts.py` (member
set and the `hasattr` pair, per §2.6), `src/crypto_lab/adapters/__init__.py`, and
the two §2.6 guard files.
**Interfaces consumed.** Tasks 1–3 output; `EventId`, `attempt_token_hash`,
`CommandInvocationRecord`, `TERMINAL_COMMAND_INVOCATION_STATES`,
`NonNegativeDecimal`, `Clock`.
**Interfaces produced.** `AdapterDiagnostic`, `ProtocolWarning`,
`ResourceObservation`, `HeartbeatPayload`, `ProgressPayload`, `WarningPayload`,
`DiagnosticPayload`, `ArtifactProducedPayload`, `FinalResultPayload`, `MediaType`,
`ProtocolEventEnvelope`, `RunEvent`, `run_event_content_hash`,
`EventAcceptanceContext`, `LineOutcome` (`EventAccepted`, `EventReplayed`,
`EventRejected`), `parse_protocol_line`, `InvocationEventLedger`,
`ArtifactDeclarationRecord`, `ProtocolEventSummary`; `redact_attempt_token`,
`redact_payload`, `token_present`,
`ContaminationSample`, `contamination_sample`, `BoundedStderrCapture`,
`StderrCapture` (the §3.7 shape, defined here);
`EngineRunRepository.append_event` and `list_events`. Releases
`ProtocolEventEnvelope`, `RunEvent` (count 41); appends two paths (allowlist 79);
swaps `RunEvent` for `ArtifactRef` in the seven-name list.

- [ ] **Step 1: Focused RED.** Every §7.1 framing rule with a positive and a
  negative line (LF line accepted; `\r\n` rejected as contamination; BOM rejected;
  empty line rejected; unterminated fragment rejected; a line one byte over the
  limit rejected as too large without being decoded — assert the decoder was not
  reached by feeding bytes that are also invalid UTF-8 and checking the code);
  a line whose first byte is not `{` is contamination and one that is is malformed;
  every §7.3 identity and sequence rule with the expected code; identical replay
  returning the stored event and writing nothing, **also when the acceptance
  context's receipt instant has advanced between the two lines** (a `CountingClock`
  proves `content_hash` ignores `received_at_utc` and `wire_event_hash`), and an
  identical replay of an earlier sequence after `FINAL_RESULT` still
  `EventReplayed`; a malformed repeat of an accepted sequence reported as
  `PROTOCOL.MALFORMED_JSONL`; a planted-name control asserting the Stage 4 bare-name
  scan finds no `context`, `buffer`, `note` or `problem` in `adapters/events.py` or
  `adapters/sanitization.py`; `RunEvent` rejecting a payload of the wrong type for
  its `event_type`; an empty stdout stream accepted as normal; an `ARTIFACT_PRODUCED`
  whose `relative_path` is the raw token → `ARTIFACT.PATH_BOUNDARY_VIOLATION` and a
  `HEARTBEAT` whose `phase` is a fixed 32-character lowercase letter-leading token →
  `PROTOCOL.MALFORMED_JSONL` with no `RunEvent` produced, with the discriminating
  control that the same line validates as a `ProtocolEventEnvelope` when strict
  validation runs without redaction (so the rejection is caused by the placeholder),
  while the envelope's own `attempt_token` key is not redacted (control: a
  conformant line is accepted); each payload type validated
  against its bounds (counter ceiling, percentage above 100, `total_units` below
  `completed_units`, media type uppercase, path near-miss mapped to
  `ARTIFACT.PATH_BOUNDARY_VIOLATION`, core-namespace `error_code` and
  core-owned `category` rejected as malformed, `causal_event_ids` over 32);
  `RunEvent` rejecting a `content_hash` that does not recompute and never
  accepting an `attempt_token` field; `wire_event_hash` equal to the SHA-256 of the
  line bytes; the ledger rejecting an event after `FINAL_RESULT`, a second
  `FINAL_RESULT`, a duplicate `artifact_produced` path, a duplicate `event_id`, a
  non-monotonic heartbeat counter, `ARTIFACT_PRODUCED` during `VALIDATE`;
  `from_events` over a persisted tuple rebuilding an equal ledger (equality
  excluding the live-only redaction total); an `event_type`
  outside the enum → `PROTOCOL.MALFORMED_JSONL` while a member the kind may not
  emit → `PROTOCOL.IDENTITY_OR_SEQUENCE_VIOLATION`; a `sequence` of `0` on a fresh
  invocation → `PROTOCOL.IDENTITY_OR_SEQUENCE_VIOLATION`; a wrong header token on a
  malformed payload reported as identity, not as malformed, with the header model
  holding only `attempt_token_hash` (the §13 allowlist guard is the control); two heartbeats
  replayed out of counter order both `EventReplayed`; the accepted `WARNING` that
  would exceed `MAX_WARNINGS` rejected; `redact_payload` returning the count,
  `EventAccepted.redactions` carrying it and the summary totalling it;
  `BoundedStderrCapture.finish()` leaving no bytes in `StderrCapture`
  (`retained_byte_count` only); sanitization:
  every occurrence redacted with the count returned, a token split across two
  `token_present` chunks detected, a sample omitted when the line is not valid UTF-8
  and present and escaped otherwise, `BoundedStderrCapture` truncating at the limit
  with the hash over every byte; `append_event` idempotent on an identical event,
  conflicting on a different content under one key, conflicting on a reused
  `event_id`, `list_events` ordered; the port-contract member sets updated; the
  property tests: any split of a valid multi-line stdout byte string into chunks
  yields the same accepted `RunEvent`s, and generated interleaved streams from two
  invocations never collide on `(invocation_id, sequence)`; the §2.6 expectations.
- [ ] **Step 2: Confirm RED.**
- [ ] **Step 3: Minimum GREEN.**
- [ ] **Step 4: Focused GREEN.** `tests\unit\adapters tests\unit\experiments
  tests\property tests\safety -q`.
- [ ] **Step 5: Quality gates, Security review, Independent review.**

**Broader tests.** `tests\unit tests\safety tests\architecture`.
**Quality gates.** As stated in the section preamble.
**Security review.** Byte limits before decoding; identity before schema; no
untyped dictionary crosses the parser boundary; samples redacted or omitted;
`RunEvent` cannot carry a raw token; the ledger is pure.
**Independent review.** Declared readings: framing rules 1–5; the trailing-fragment
rule; the contamination-versus-malformed split on the first byte; the adapter
namespace and category allowlist; `MAX_SEQUENCE`; heartbeat counter monotonicity.
**Commit message.** `feat: add protocol events, sanitization and the event ledger`
**Clean-worktree boundary.** As Task 1.

### Task 5 — Validation results and result manifests

**Files created.** `src/crypto_lab/adapters/manifests.py`,
`tests/unit/adapters/test_adapter_manifests.py`,
`tests/property/test_manifest_sanitization_determinism.py`.
**Files modified.** `src/crypto_lab/adapters/__init__.py` and the two §2.6 guard files.
**Interfaces consumed.** Tasks 1–4 output; `ApproximationId`, `CandidateArtifactId`,
`LogicalSlotId`, `ExperimentId`, `RunId`, `InvocationId`, `AdapterIdentity`,
`EngineIdentity`, `CanonicalDecimal`.
**Interfaces produced.** `RunProvenance`, `CandidateArtifactDeclaration`,
`CandidateMetric`, `AdapterValidationResult`, `validation_result_hash`,
`OutputHeader`, `ValidationResultParse`, `parse_validation_result(bytes, *,
max_bytes, token) -> ValidationResultParse`, `AdapterResultManifest`,
`ManifestParse`, `parse_result_manifest(bytes, *, max_bytes, token) -> ManifestParse`,
`SanitizedCandidateArtifactDeclaration`, `SanitizedAdapterResultManifest`,
`sanitized_manifest_hash`, `sanitize_result_manifest(output: ManifestParse,
protocol_summary) -> SanitizedAdapterResultManifest`,
`redact_validation_result(document, token)` over the decoded JSON object (the step
`parse_validation_result` calls before strict validation).
Releases
`AdapterValidationResult`, `AdapterResultManifest`,
`SanitizedAdapterResultManifest` (count 38); appends one path (allowlist 80);
swaps `AdapterResultManifest` for `CandidateArtifact` in the seven-name list.

- [ ] **Step 1: Focused RED.** Validation result: `result_hash` mismatch rejected;
  `INVALID` without a diagnostic rejected; unknown field rejected;
  `parse_validation_result` mapping oversized, non-UTF-8, non-object,
  strict-invalid and unsupported-version bytes to the §9.4 codes while still
  filling the permissive `OutputHeader` whenever the bytes were decoded to a JSON
  object — oversized bytes are never decoded — and a wrongly typed or over-long
  `invocation_id` read as `MISSING` so the reconciler reports identity (a
  mis-identified *and* malformed document yields both the header and the failure
  code), hashing a raw token found in the document into `attempt_token_hash`
  without carrying the raw value, and a raw token in a diagnostic message yielding
  `redactions >= 1`, `result` absent and `PROTOCOL.VALIDATION_RESULT_INVALID` (the
  token-free contract of §3.10); a 257th `candidate_artifacts` declaration and a
  257th `candidate_metrics` entry rejected; `parse_result_manifest` likewise, plus a
  declaration path `C:/escape.bin` recorded as `ARTIFACT.PATH_BOUNDARY_VIOLATION`
  (path-located), `redactions` counting the in-place redactions when the
  manifest's own token appears in a provenance or warning text field with the
  redacted `manifest` still strict-valid and its `attempt_token` field retained
  verbatim, and a token placed in an identifier field
  yielding `ARTIFACT.RESULT_MANIFEST_INVALID` after redaction while a token placed
  in a `relative_path` yields `ARTIFACT.PATH_BOUNDARY_VIOLATION` (path-located
  precedence). Manifest:
  `completed_at_utc` before
  `started_at_utc` rejected; `SUCCEEDED` with a warning rejected;
  `SUCCEEDED_WITH_WARNINGS` without one rejected; every non-success status without
  a diagnostic or with a candidate rejected; duplicate declaration path and
  duplicate metric name rejected; `DEFINED` metric without a value and `UNDEFINED`
  with one rejected; approximations unsorted rejected; the raw token absent from
  `repr`; `sanitize_result_manifest` producing derived candidate ids equal to
  `candidate_artifact_id_for` for each declaration with the accepted event's id as
  `source_event_id`, `candidate_artifact_ids` sorted and equal to the declaration
  identities, `attempt_token_hash` equal to the hash of the raw token,
  `source_adapter_result_manifest_hash` equal to `sha256_bytes(manifest_bytes)`,
  `sanitized_adapter_result_manifest_hash` recomputing and differing from the
  source hash, no raw token in the canonical dump; the property test: the sanitized
  manifest is a deterministic function of (manifest, bytes, summary) and its hash
  changes under every material mutation and never under key permutation; the §2.6
  expectations.
- [ ] **Step 2: Confirm RED.**
- [ ] **Step 3: Minimum GREEN.**
- [ ] **Step 4: Focused GREEN.** `tests\unit\adapters tests\property tests\safety -q`.
- [ ] **Step 5: Quality gates, Security review, Independent review.**

**Broader tests.** `tests\unit tests\safety`.
**Quality gates.** As stated in the section preamble.
**Security review.** No path in any sanitized record; the source hash is over exact
bytes and the sanitized hash over canonical JSON so they cannot coincide by
construction; the raw token never leaves the wire model.
**Independent review.** Declared readings: the `candidate_declarations` companion
to `candidate_artifact_ids`; `CandidateMetric` rather than `MetricValue`;
approximations as identities; the status↔warnings coupling.
**Commit message.** `feat: add adapter validation results and result manifests`
**Clean-worktree boundary.** As Task 1.

### Task 6 — Exit semantics, reconciliation and `CommandResult`

**Files created.** `src/crypto_lab/adapters/exit_codes.py`,
`src/crypto_lab/adapters/reconciliation.py`,
`tests/unit/adapters/test_exit_semantics.py`,
`tests/unit/adapters/test_command_reconciliation.py`.
**Files modified.** `src/crypto_lab/adapters/commands.py` (`CommandResult`),
`src/crypto_lab/adapters/__init__.py`, and the two §2.6 guard files.
**Interfaces consumed.** Source: Tasks 1–5 output; `SlotCompatibility`,
`EngineRunState`, `ProcessExitCategory`, `process_exit_category_for`,
`RECOGNIZED_NATIVE_EXIT_VALUES`, `SUCCESS_ENGINE_RUN_STATES`. Test-only:
`UNRECOGNIZED_PROCESS_EXIT` (the causal-reference assertion).
**Interfaces produced.** `SemanticExitReading`, `semantic_exit_reading(command_kind,
native_exit_value) -> SemanticExitReading` (the §9.1 table as a total function
returning the diagnostic code, the run target when output-independent, and whether
output is required); `CandidateObservation`, `SemanticReconciliation`,
`ReconciliationRuleViolation`, `reconcile_describe`, `reconcile_validate`,
`reconcile_run` (the §9.2 signatures over parse outcomes); `CommandResult`.
Releases `CommandResult` (count 37); appends two paths
(allowlist 82).

- [ ] **Step 1: Focused RED.** `semantic_exit_reading` asserted for every cell of
  §9.1 (three kinds × nine rows, including an unrecognized value); each
  reconciliation predicate asserted for every branch of §9.2 in order with a
  minimal input that reaches exactly that branch and a control input that passes
  it, including: a `RUNNING` invocation rejected; a `DESCRIBE` invocation rejected
  by `reconcile_run`; a run in a produced state admitted (the §10 replay input) and
  a run in any other state rejected; a `protocol_failure` diagnostic overriding a
  valid manifest and returned as the primary; `negotiated_versions` or a spec hash
  differing from the manifest's provenance → `ARTIFACT.RESULT_MANIFEST_INVALID`;
  `sanitized_manifest` present for a `FAILED` verdict whose manifest declares no
  candidates and absent when a declaration lacks its event; a mis-identified and malformed document reporting identity
  (from the permissive header) before the recorded failure code, a header with an
  absent `invocation_id` likewise reporting identity, and a document whose bytes
  are not a JSON object reporting `*_INVALID` because no header exists;
  a `contains_attempt_token` observation yielding leakage while a redacted
  manifest does not; a path escape at the manifest surfacing as the parser's
  recorded `ARTIFACT.PATH_BOUNDARY_VIOLATION` at check (4); a `FINAL_RESULT` path other than
  `RESULT_MANIFEST_RELATIVE_PATH`; declarations differing from events; an
  observation whose hash differs; warnings not a superset of events;
  approximations differing from the slot's; `RESULT_FINALIZATION_ELIGIBLE`
  carrying the sanitized manifest and no run target;
  `NOT_APPLICABLE`/`UNAVAILABLE` carrying a sanitized manifest and
  `adapter_error_code` plus `adapter_manifest_id` in the primary's `details` with
  `causal_diagnostic_ids` empty; the exit-0 `FAILED` manifest mapping to
  `ENGINE.RUNTIME_FAILURE` with `retriable=True`; the absent-manifest-on-40 detail
  rule; `output_required` true exactly for describe exit 0 and for validate and run
  exits 0, 20 and 30; a run exiting 20 or 30 with `output` `MISSING` → `FAILED`,
  `ARTIFACT.RESULT_MANIFEST_INVALID` with no `manifest_present` detail; a `FAILED`
  manifest after an accepted `ARTIFACT_PRODUCED` event → `ENGINE.RUNTIME_FAILURE`
  with the sanitized manifest present (check (9) is scoped to success statuses), and
  the same shape with the abandoned file absent still `ENGINE.RUNTIME_FAILURE`
  (check (10) compares manifest declarations only); exit 70 with a `SUCCEEDED`
  manifest → `ARTIFACT.RESULT_MANIFEST_INVALID` and with a `FAILED` manifest →
  `PROTOCOL.ADAPTER_REPORTED_VIOLATION`; a validate
  exiting 40 after writing `VALID` → `ENGINE.RUNTIME_FAILURE` with the output
  recorded; two reconciliations under different `now_utc` minting identical
  diagnostic identities; a validate exiting 40 with no output →
  `ENGINE.RUNTIME_FAILURE` with `output_present: false` and exiting 10 with no
  output → `SCHEMA.REQUEST_INVALID`; a describe exiting 30 with no output →
  `ADAPTER.UNAVAILABLE`; `CommandResult` rejecting a parsed output of the wrong
  kind and a `cancelled` flag on an `EXITED` invocation.
- [ ] **Step 2: Confirm RED.**
- [ ] **Step 3: Minimum GREEN.**
- [ ] **Step 4: Focused GREEN.** `tests\unit\adapters tests\safety -q`.
- [ ] **Step 5: Quality gates, Security review, Independent review.**

**Broader tests.** `tests\unit tests\safety tests\architecture`.
**Quality gates.** As stated in the section preamble.
**Security review.** No success target exists in any reconciliation output; the
precedence rule cannot be bypassed by a valid manifest after a protocol violation;
leakage and path checks precede any semantic reading.
**Independent review.** Declared readings: self-reported exit 50/60; manifest
absence versus invalidity; the primary-diagnostic precedence; bidirectional
event↔manifest declaration equality.
**Commit message.** `feat: add exit semantics and command outcome reconciliation`
**Clean-worktree boundary.** As Task 1.

### Task 7 — The command semantic outcome operation

**Files created.** `src/crypto_lab/experiments/semantic_outcome.py`,
`tests/unit/experiments/test_semantic_outcome.py`.
**Files modified.** `src/crypto_lab/experiments/requests.py`
(`SemanticOutcomeRequest`; `REQUEST_OPERATIONS` seventeen),
`src/crypto_lab/experiments/__init__.py`,
`tests/unit/experiments/test_experiment_service.py` (`16` → `17`, `_FIELD_ORDERS`,
`_OPERATION_NAMES`, per §2.6), and the two §2.6 guard files.
**Interfaces consumed.** Source: Tasks 1–6 output; `UnitOfWork`,
`EngineRunRepository`, `ExperimentRepository`, `CommandInvocationRepository`,
`run_operation`, `LostSwap`, `run_replacement`, `run_rule_failure`,
`assert_run_transition`, `RunEdgeOwner`, `EngineRunRuleViolation`,
`assert_write_once_enrichment`, `CommandInvocationRuleViolation`, `stage5_failure`,
`Clock`. Test-only: `InMemoryBackingStore`, `RecordingUnitOfWork`, `CountingClock`.
**Interfaces produced.** `SemanticOutcomeRequest`, `SemanticOutcome`,
`apply_command_semantic_outcome`. Releases no deferred name; appends one path
(allowlist 83).

- [ ] **Step 1: Focused RED.** Every numbered step of §10 with a case that fails
  exactly there and a control that passes: describe kind, non-`EXITED`, unlinked
  run, a parse outcome of the wrong kind, non-current attempt, non-`RUNNING`
  experiment, a second non-terminal invocation, stale invocation revision, stale run
  revision, each returning the tabulated code and writing nothing (assert through
  the store); every §9.3 verdict driven end to end through the doubles with the run
  landing in the mapped state carrying the primary diagnostic identity and, for
  `READY` and `UNAVAILABLE`, the slot's observation identity;
  `RESULT_FINALIZATION_ELIGIBLE` and `VALIDATED_READY` leaving the invocation
  unwritten and, for the former, the run at the same revision, with a
  `RecordingUnitOfWork` proving no `engine_runs.compare_and_swap` and no
  `command_invocations.compare_and_swap`; every diagnostic-bearing verdict enriching
  the invocation with exactly the minted ids in the same unit of work; a lost run
  swap rolling back the enrichment; idempotent replay of each verdict — the same
  request re-issued with the post-write revisions returns the stored pair and
  writes nothing, a re-issue with the pre-write revisions is
  `PERSISTENCE.CONCURRENCY_CONFLICT`; a run found `CANCELLED` or `TIMED_OUT`
  returning the stored pair with `superseded_by` set, `reconciliation` absent and
  nothing written; a run moved `READY → UNAVAILABLE` by `transition_run` after
  `VALIDATED_READY`, re-issued with the current revisions, returning the stored
  pair with `superseded_by` `UNAVAILABLE` and the recomputed reconciliation; a run
  driven to `FAILED` by `transition_run` with a foreign primary, then issued a
  `FAILED` verdict, returning `superseded_by` `FAILED`; a
  replay after a successor exists (run no longer `latest_attempt`, revisions
  unchanged) still answered from the replay step; after `create_invocation(RUN)`
  alone the run revision is unchanged and the replay still returns the stored pair
  (positive control), while after `begin_linked_launch` a re-issue with the
  pre-launch run revision is a stable `PERSISTENCE.CONCURRENCY_CONFLICT` and one
  with the post-launch revision is `CORE.INVARIANT_VIOLATION` because
  `reconcile_validate` does not admit `STARTING`; the non-current-attempt,
  non-`RUNNING`-experiment and second-open-invocation cases driven with
  `VALIDATED_READY` and a diagnostic-bearing verdict, and
  `RESULT_FINALIZATION_ELIGIBLE` shown to reach those reads on every issue because
  it is write-free; the divergent re-issues — a `READY` run re-issued with inputs
  that recompute `FAILED`, and a run at its target whose `diagnostic_ids` lack a
  recomputed identity while its stored primary is among them — each
  `CORE.INVARIANT_VIOLATION` with no write (a
  `RecordingUnitOfWork` proving no `command_invocations.compare_and_swap`); a
  `protocol_failure` request for an `EXITED` invocation yielding `FAILED` with that
  diagnostic as the run's primary; `RESULT_FINALIZATION_ELIGIBLE` recomputed over a
  run moved `RUNNING → FAILED` by `transition_run` returning the stored pair with
  `superseded_by` `FAILED`; every re-issue seeding only identities not already present;
  the request-to-operation inventory asserted one-to-one at seventeen.
- [ ] **Step 2: Confirm RED.**
- [ ] **Step 3: Minimum GREEN.**
- [ ] **Step 4: Focused GREEN.** `tests\unit\experiments tests\safety -q`.
- [ ] **Step 5: Quality gates, Security review, Independent review.**

**Broader tests.** `tests\unit tests\safety tests\architecture`, then `pytest-all`
in the background and alone.
**Quality gates.** As stated in the section preamble.
**Security review.** The operation cannot move a run to a success state (no code
path builds one); it reads the invocation list authoritatively before writing.
**Independent review.** Declared readings: the seventeenth request; the replay
rule; the observation source.
**Commit message.** `feat: add the command semantic outcome operation`
**Clean-worktree boundary.** As Task 1.

### Task 8 — Fake adapters and the offline contract harness

**Files created.** `tests/fake_adapters/fake_adapter.py`,
`tests/contract/__init__.py` (empty package marker, the `tests/doubles` pattern),
`tests/contract/harness.py`, `tests/contract/scenarios.py`,
`tests/contract/test_describe_contract.py`,
`tests/contract/test_validate_contract.py`, `tests/contract/test_run_contract.py`,
`tests/contract/test_protocol_failure_contract.py`,
`tests/contract/test_adapter_side_verification.py`,
`tests/contract/test_harness_safety.py`.
**Files modified.** None under `src`; no Stage 1–5 test is edited.
**Interfaces consumed.** Tasks 1–7 output; the Stage 5 operations
`create_invocation`, `transition_invocation`, `begin_linked_launch`,
`start_linked_run`, `transition_invocation_and_run`, `enrich_invocation`,
`create_experiment`, `transition_experiment`, `queue_experiment`, `create_attempt`,
`transition_run`, `evaluate_retry`, `create_successor` (row 47's successor); the
doubles including `sample_retry_policy`; `ProcessStartFacts`, `ProcessIdentity`.
**Interfaces produced.** `OfflineCommandHarness`, `CommandRun`,
`assert_token_absent`, `assert_token_only_in_wire_material`, `SCENARIOS` (the
§11.2 table as data), the fake adapter executable. No deferred name released; no source path added.

- [ ] **Step 1: Focused RED.** Write `scenarios.py` and the six test modules first:
  one parametrized test per §11.2 row asserting the invocation state, the run state
  or verdict, the primary and secondary codes, the accepted-event count where
  stated, sanitized-manifest presence, `assert_token_absent` and, for every
  validate and run row, `assert_token_only_in_wire_material`; the five
  adapter-side vectors; the harness safety assertions of §11.3 item 5, the
  launch-argument pins (argv[0] is `sys.executable`; `ProcessIdentity` carries
  the catalog entry's script path and hash), the per-scenario catalog bound, the
  write-boundary snapshot over the command root and the `PROCESS.START_TIMED_OUT`
  direct case; a stdlib-only `ast` assertion over `fake_adapter.py`.
- [ ] **Step 2: Confirm RED** (`ModuleNotFoundError` for `contract.harness`, missing script).
- [ ] **Step 3: Minimum GREEN.** The fake adapter, then the harness; scenario by
  scenario until the parametrized suite is green. Timing scenarios use the request
  snapshot's lowered limits and one- to four-second timeouts; the contract suite
  targets under sixty seconds on an idle host (about sixty child launches plus the
  fixed waits of rows 24–27), measured with `--durations` and recorded in the
  task's completion evidence, never asserted by a test.
- [ ] **Step 4: Focused GREEN.** `tests\contract tests\safety -q`.
- [ ] **Step 5: Quality gates, Security review, Independent review.**

**Broader tests.** `tests\unit tests\safety tests\contract`, then `pytest-all` in
the background and alone (heavier host load flakes the hypothesis deadline in the
Stage 4 strategy-hashing properties).
**Quality gates.** As stated in the section preamble.
**Security review.** `env={}`, `shell=False`, list argv, cwd under the harness root,
no ambient environment read anywhere in the fake or the harness (the harness reads
no environment variable to build the block); the fake imports no `crypto_lab`; the
raw token appears only in the request file, the wire lines and the manifest file,
all under the per-invocation temporary root the test deletes.
**Independent review.** Declared readings: scenario selection by adapter identity;
the interpreter-prefixed launch of Python fakes; harness-owned deadlines as
stand-ins.
**Commit message.** `feat: add fake adapters and the offline contract harness`
**Clean-worktree boundary.** As Task 1; `STAGE6_IMPLEMENTATION_COMMIT` is this
commit.

### Task 9 — Schemas, boundaries, integration flow, documentation and Stage 6 status

**Files created.** The eight schema files of §12.1,
`tests/safety/test_stage6_boundaries.py`,
`tests/integration/adapters/test_stage6_protocol_flow.py`.
**Files modified.** `src/crypto_lab/schema_registry.py` (eight entries, docstring),
`tests/unit/test_schema_registry.py`, `tests/unit/domain/test_domain_descriptors.py`,
`tests/safety/test_stage3_boundaries.py`, `tests/safety/test_stage5_boundaries.py`,
`tests/safety/test_gitnexus_development_tooling.py`, `README.md`,
`docs/development/verification.md`,
`docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md`. Every edit to a
Stage 1–5 test file is one §2.6 tabulates; this task creates no source module and
releases no deferred name.
**Interfaces consumed.** Tasks 1–8 output; `SCHEMA_DEFINITIONS`,
`SchemaDefinition`, `render_schema_files`.
**Interfaces produced.** Positions 27–34 of the registry; the `_STAGE6_*` blocks
of §12.3; the Stage 6 safety guard; the end-to-end protocol flow; the documentation
and roadmap status.

- [ ] **Step 1: Focused RED (schemas).** The registry render asserted to hold
  exactly 35 entries with Stage 6 at 27–34; every §2.6 registry assertion updated;
  the 27 pre-existing files asserted byte-identical against their digests; the
  §12.3 blocks written against the intended bytes (digests filled after the first
  reviewed `schema-generate-write`).
- [ ] **Step 2: Focused RED (guards).** `tests/safety/test_stage6_boundaries.py`:
  `STAGE6_SOURCE_FILES` exactly the fourteen §2.6 paths and each a file; the Stage 5
  filesystem/environment scan over them, with a planted `os.system = sentinel`
  assignment as the negative control of the no-shell scan's assignment-target
  exemption; the `AttemptToken`-annotated field
  allowlist (the exact four classes of §13, keyed on the annotation, with the
  merged `AttemptCreation` as the near-miss control); the tests-tree `ast` no-shell scan of §13 (calls
  only, with the three merged text-only `os.system` files as negative controls and
  a planted `shell=True` call as the positive control) and the `subprocess`
  importer allowlist (exactly ten files: the nine importers at the planning base
  plus `tests/contract/harness.py`; `test_harness_safety.py` inspects the launch
  helper's returned arguments and must not import `subprocess`, which the allowlist
  enforces); the fake adapter importing only
  `argparse`, `json`, `hashlib`, `sys`, `os`, `time`, `datetime`;
  a test-double root scan extended to `fake_adapters` and `contract`; the roadmap
  Stage 6 completion row and Stage 7 deferred row pins, the "Approved detailed
  implementation plan" line for this plan's path and the negative of its "Planned"
  form; every scan with a planted-violation control.
- [ ] **Step 3: Focused RED (flow).** `test_stage6_protocol_flow`: one scenario over
  the in-memory ports and the offline harness (`from contract.harness import
  OfflineCommandHarness`) with two selected slots: create, transition (`DRAFT →
  VALIDATED`) and queue an experiment whose frozen compatibility is `SUPPORTED`,
  `SUPPORTED_WITH_APPROXIMATION`;
  describe `fake.conformant` and build the available observation; create both
  attempts; validate slot A to `READY` and slot B to `NOT_APPLICABLE` through
  `fake.unsupported-capability`; launch slot A's run through `fake.conformant` to
  `RESULT_FINALIZATION_ELIGIBLE` with the run still `RUNNING`; rebuild the ledger
  from `list_events`, prove it equals the live ledger (the live-only redaction total
  excluded), and feed the captured stdout
  lines again under the pre-exit `RUNNING` invocation snapshot with an advanced
  clock, proving every line is `EventReplayed` and `append_event` stores nothing
  new; prove `assert_token_absent` over every record; then aggregate and prove
  `NOT_YET_TERMINAL` (slot A awaits Stage 9), which is the exact Stage 6/Stage 9
  boundary.
- [ ] **Step 4: Minimum GREEN.** Registry entries; `schema-generate-write` once;
  read every generated byte; fill the digests; the guard; documentation:
  `README.md` status and Stage 6 paragraph (35-schema registry, the eight file
  names, fake adapters run only through the test-resident harness, "Stage 7 has not
  started."); `docs/development/verification.md` Stage 6 focused checks
  (`tests\unit\adapters`, `tests\contract`, `tests\safety\test_stage6_boundaries.py`,
  `tests\integration`, `tests\unit\test_schema_registry.py`), registry rows 28–35
  in its 1-based table, every occurrence of the 27 count in the README ("closed at
  **27** schemas", "exactly those 27") and the guide ("27 fixed lexical descendants",
  "closed 27-file registry", "final registry count of 27", the registry heading
  and its lead-in, which gain the eight Stage 6 entries) → 35, the Stage 6 timestamp
  section, the §12.4 register, the status block; the roadmap status line, plan
  sentence, Stage 5 row clause, Stage 6 completion row with
  `STAGE6_IMPLEMENTATION_COMMIT`, and the Planned→Approved line.
- [ ] **Step 5: Focused GREEN.** `tests\unit\test_schema_registry.py tests\integration
  tests\contract tests\architecture tests\safety tests\unit\domain tests\unit\adapters -q`.
- [ ] **Step 6: The complete unmodified `scripts/verify.ps1`, alone.**

**Broader tests.** The complete verifier.
**Quality gates.** As stated above plus `schema-generate-check`, `build`,
`schema-distribution`, `git diff --check`.
**Security review.** No Stage 3–5 byte moves; the three token-bearing schemas are
labelled temporary wire contracts in the guide; no prose claims supervision,
persistence or finalization began.
**Independent review.** Every generated byte read; every `$id` checked against
§12.1; the documentation pins byte-exact.
**Commit message.** `feat: add stage 6 schemas, boundaries and protocol flow`
**Clean-worktree boundary.** As Task 1; the roadmap records
`STAGE6_IMPLEMENTATION_COMMIT` (Task 8) and states that the schemas, guards, flow
and status were added by this separate commit, which is not the implementation
hash.

## 15. Verification and acceptance

### 15.1 Commands

Focused, during red-green development (diagnostic only; `-o addopts=` disables
coverage):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\adapters tests\unit\domain -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\experiments tests\unit\test_schema_registry.py -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\contract tests\safety tests\architecture tests\integration tests\property -q
```

Complete, before any completion claim, alone on the host:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
```

The verifier is not modified. Stage 6 introduces no dependency, so no lock or
acquisition operation is required and none may be cited as evidence.

### 15.2 Acceptance criteria

Stage 6 is complete only when all of the following hold with fresh offline evidence:

1. Every record of §3 rejects an unknown field, a raw token where prohibited and a
   value outside its bound, and every published record renders identically in both
   generation modes.
2. Every framing, identity and sequence rule of §7 is demonstrated with a
   positive and a negative line, identical replay returns the prior event, and the
   ledger rebuilt from persisted events accepts no duplicate.
3. Negotiation selects the highest common versions and fails closed to
   `ADAPTER.UNAVAILABLE`.
4. Every cell of the §9.1 table and every branch of §9.2 is exercised through a
   fake adapter or a direct unit case, and no path produces a success run state.
5. The fifty-two scenario rows of §11.2 and the five adapter-side vectors pass
   through the offline harness with `assert_token_absent` green.
6. `apply_command_semantic_outcome` performs the authoritative reads of §10 and the
   inventory is one-to-one at seventeen.
7. Source and sanitized manifest hashes are distinct on every successful scenario
   and the sanitized manifest is deterministic.
8. Every closed-world guard of §2.6 holds at its reconciled value: 83 allowed source
   files, 37 deferred definitions, seven live mutation cases, 12 hashing profiles,
   every registry assertion at 35 with Stage 3, 4, 5 and 6 at their fixed positions,
   and every documentation pin at its Stage 6 successor.
9. `schema-generate-check` passes on the closed 35-entry registry; the 27
   pre-existing files match their digests byte for byte; the eight new files are
   pinned alongside them.
10. `ruff-format-all`, `ruff-check-all`, `mypy-all`, `pytest-all`, `build`,
    `schema-distribution` and `git diff --check` are clean offline.
11. The complete verifier reports branch coverage of at least **97.69 percent**
    with exactly the two approved skips.
12. No Stage 7 supervisor, Stage 8 persistence or Stage 9 finalization module exists
    anywhere in `crypto_lab`, proven by the guards of Task 9.

## 16. Rollback and completion

Each task ends in one commit, so any task is reverted with `git revert` of that
commit without touching another task; §2.6's guard edits travel in the same commit
as the module or definition that trips them, so a revert restores guard and source
together. The highest-risk reversals are Task 4 (the port method, which also
touches the double and the port-contract pins) and Task 9 (the registry extension,
whose revert returns the registry to 27 entries and leaves Tasks 1–8 green because
no earlier task registers a schema).

Stage 1–5 test files edited, all only as §2.6 tabulates:
`tests/safety/test_stage3_boundaries.py` and `tests/unit/test_package_layout.py`
by Tasks 1–7 and the former also by Task 9; `tests/unit/domain/test_lifecycle_tables.py`
and `tests/unit/domain/test_identifiers.py` by Task 1;
`tests/unit/experiments/test_port_contracts.py` and `tests/doubles/experiments.py`
by Task 4; `tests/unit/experiments/test_experiment_service.py` by Task 7;
`tests/unit/test_schema_registry.py`, `tests/unit/domain/test_domain_descriptors.py`,
`tests/safety/test_stage5_boundaries.py` and
`tests/safety/test_gitnexus_development_tooling.py` by Task 9. `pyproject.toml`,
`scripts/verify.ps1` and `scripts/invoke-uv.ps1` are not modified, and no generated
schema is ever hand-edited: a wrong byte is corrected in the model and regenerated.

Stage 6 is complete when every criterion of §15.2 holds, the worktree is clean and
committed, and the roadmap status table records `STAGE6_IMPLEMENTATION_COMMIT`
together with the closed 35-schema registry. Stage 7 is not started, and no process
supervisor, persistence implementation or artifact finalizer exists anywhere in the
tree.
