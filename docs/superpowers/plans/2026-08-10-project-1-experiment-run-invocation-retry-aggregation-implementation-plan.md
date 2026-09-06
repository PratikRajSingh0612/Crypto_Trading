# Project 1 Stage 5 — Experiment, Run, Invocation, Retry, and Aggregation Implementation Plan

**Status:** Detailed implementation plan for Stage 5; implementation not started
**Planning base:** `7a96176ae418491fc9740984c45b56cca6b3ac41` (`main` = `HEAD` = merge base)
**Prerequisites:** Stages 1–4 complete and merged
**Length:** exceeds the 1,500-line compact target because §2.7's closed-world guard
reconciliation and §6's command-kind matrices are mandatory constructibility
detail; correctness was not traded for the target.

## 1. Goal, scope and exclusions

### 1.1 Goal

Implement the three Stage 5 lifecycles — experiment, engine run, and command
invocation — as strict canonical records with exhaustive transition tables,
revision-based compare-and-swap semantics, queue-time immutability, an immutable
six-gate retry contract with durable delay and replay, deterministic terminal
aggregation over selected slots, and the narrow application ports those
operations need. Every port is exercised through deterministic in-memory doubles.

### 1.2 In scope

Canonical Stage 5 records, enums and transition tables (§3–§6); queue-time
immutability and experiment-spec identity (§7); `RetryPolicy`, the three-phase
retry decision and successor creation (§8); cancellation, terminal aggregation
and their contention mechanism (§9); application repository and unit-of-work
protocols (§10); deterministic in-memory doubles and an implementation-agnostic
port-contract suite (§11); reconciliation of every closed-world guard the merged
tree enforces (§2.7); and seven new generated JSON Schemas that extend the
registry from 20 to 27 entries with the existing 20 preserved byte-identical
(§12 Task 9, §13).

### 1.3 Out of scope

Nothing below is created, imported, or referenced by Stage 5 code: SQLAlchemy,
SQLite, Alembic, any concrete persistence implementation; operating-system
process launch, process supervision, adapter execution; adapter protocol
contracts including request envelopes, stdout events, `RunEvent`, validation
results and adapter result manifests; artifact staging, validation, hashing,
leases or finalization; real engines, market data, backtests, networking,
credentials; audit sinks and structured log writers.

### 1.4 Named forward obligations

Deliberate omissions, each with the stage that closes it:

| Omission | Reason | Closed by |
|---|---|---|
| `Clock.monotonic()` and `MonotonicInstant` | The monotonic value governs only within one live supervisor, is never persisted and never compared across restarts; no Stage 5 operation has monotonic semantics | Stage 7 |
| `ContentHasher.sha256_stream` | The second `domain` port of the interface table; it hashes artifact bytes, and all artifact hashing is out of scope by §1.3 | Stage 9 |
| `EngineRunRepository.append_event` | Its `RunEvent` parameter is an adapter-protocol contract | Stage 6 |
| Idempotency identity for a `DESCRIBE` create | A describe has no run; its catalog-level correlation identity is a protocol contract, so Stage 5 does not deduplicate describe creates | Stage 6 |
| Minting the `COMPAT.LATE_NOT_APPLICABLE` diagnostic on a run | Late incompatibility is discovered from the adapter result manifest; Stage 5 consumes the code only as an aggregation reason | Stage 6 |
| Owner and purpose validation of `CommandInvocationRecord.stderr_artifact_id` | Requires the finalized `ArtifactRef` lifecycle | Stage 9 |
| Semantic mapping of an `EXITED` invocation onto a run terminal state | Requires the validated adapter result manifest; the process category (§6) is never that mapping | Stage 6 |
| Persisting diagnostics and audit events | Stage 5 mints diagnostics only inside `Failure` values and reads existing ones | Stages 8–9 |

## 2. Normative authority and current merged interfaces

### 2.1 Authority order

`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md` is normative
and wins over this plan. `docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md`
fixes Stage 5 ownership, exclusions and gates. `AGENTS.md`, `README.md` and
`docs/development/verification.md` fix the working and verification workflow.
The merged Stage 1–4 source, tests and schemas are the executable prerequisite
interfaces and may not be reinterpreted.

### 2.2 Consumed merged interfaces

Stage 5 builds only on names that exist today. **Each is imported from its
defining module, not from a package root**, because the package roots do not
re-export several of them:

| Defining module | Names Stage 5 consumes |
|---|---|
| `crypto_lab.domain.base` | `CanonicalModel` (`extra="forbid"`, `frozen=True`, `hide_input_in_errors=True`, `strict=True`, `validate_default=True`), `SCHEMA_VERSION` |
| `crypto_lab.domain.identifiers` | `ExperimentId`, `RunId`, `InvocationId`, `DiagnosticId`, `ArtifactId`, `ApproximationId`, `AvailabilityObservationId`, `Sha256`, `NormalizedIdentifier`, `exact_string_schema`, `validate_prefixed_uuid4` |
| `crypto_lab.domain.time` | `CalendarValidUtcDateTime`, `format_utc` |
| `crypto_lab.domain.financial` | `CanonicalDecimal`, `NonNegativeDecimal`, `PositiveDecimal` |
| `crypto_lab.domain.records` | `Money` |
| `crypto_lab.domain.diagnostics` | `Diagnostic`, `DiagnosticCategory`, `DiagnosticSeverity`, `ErrorCode`, `BoundedMessage`, `DiagnosticDetailValue` |
| `crypto_lab.domain.results` | `Result`, `Success`, `Failure` |
| `crypto_lab.domain.hashing` | `HashingProfile`, `profile_hash`, `sha256_bytes`, `attempt_token_hash`, and the `_uuid4_shaped` helper already imported cross-module by `capabilities/policy.py` and `strategy/versioning.py` |
| `crypto_lab.domain.canonical_json` | `canonical_json_bytes`, `canonical_json_text` |
| `crypto_lab.domain.versioning` | `SemanticVersion` |
| `crypto_lab.domain.comparison_levels` | `ComparisonLevel` |
| `crypto_lab.domain.descriptors` | `RuntimeAvailabilityObservation`, `BoundedText` (the only one of the five identically named aliases reachable from `domain`), `ExecutablePath` |
| `crypto_lab.capabilities.models` | `CompatibilityOutcome` (relocated by Task 1, §2.5), `ApproximationDeclaration` (read by the composition root only) |
| `crypto_lab.configuration.models` | `RetryConfig`, `RetryTerminalState` |
| `crypto_lab.schema_registry` | `SCHEMA_DEFINITIONS`, `render_schema_files` |
| `tests/architecture/test_package_import_boundaries.py` | `find_package_import_violations`, `_allowed_project_imports` and their self-tests, extended rather than duplicated |

`ProcessConfig` is **not** consumed: neither `domain` nor `experiments` may import
`configuration`, so §3.7 copies its numeric timeout bounds as literals. Every
import root Stage 5 needs — `__future__`, `typing`, `enum`, `datetime`,
`decimal`, `collections`, `pydantic`, `crypto_lab` — is already a member of the
merged `_ALLOWED_IMPORT_ROOTS` allowlist, which therefore needs no change.

`crypto_lab.experiments` exists as a docstring-only package. There is no `Clock`,
no `Protocol`, no `UnitOfWork` and no lifecycle record anywhere in the merged
tree; Stage 5 creates all of them.

### 2.3 Normative placement decision

**Every Stage 5 canonical record, enum and transition table lives in
`crypto_lab.domain`. Every Stage 5 port, service and request model lives in
`crypto_lab.experiments`, except `CommandInvocationRepository` (§2.4).**

Specification section 8 states directly that canonical record types and
state-transition invariants live in `domain` while behavior that coordinates I/O
does not, and section 27.1 lists "state-transition tables" among `domain`'s
responsibilities. Two independent impossibility results make this the only
placement that works:

1. Section 27.1 gives `process_supervision` inward dependencies of `domain`,
   `adapters` and `audit` only, yet section 14.1 requires the supervisor's
   `CommandResult` to contain the finalized `CommandInvocationRecord`. A record
   in `experiments` would force the `process_supervision → experiments` edge the
   table forbids.
2. Section 22.2.1 requires the strict `scheduler.retry` object to normalize into
   `RetryPolicy`, and `configuration`'s only inward dependency is `domain`,
   while `experiments`' inward list excludes `configuration`. A `RetryPolicy` in
   `experiments` is unreachable from either side.

Section 27.2's module map, which names `experiments/models.py` and
`experiments/state_machine.py`, is explicitly a responsibility map that permits
splitting a listed module provided package boundaries and dependency direction
are preserved. This follows the merged Stage 4 precedent that relocated the
adapter, engine and availability descriptors into `domain` for the same reason,
and the same precedent governs the two enum relocations of §2.5.

Concrete port implementations stay outside `experiments` entirely: section 8
states that `persistence` implements the protocols and that the application does
not import concrete implementations. Because `persistence` is Stage 8-owned,
Stage 5's implementations are test-resident (§11).

### 2.4 `CommandInvocationRepository` placement

Section 8.1's owner column reads "`adapters` application port". Section 27.1
permits `experiments → adapters`, and the protocol's entire signature —
`CommandInvocationRecord`, `InvocationId`, `Result` — resolves inside `domain`,
so `adapters` can host it without gaining a forbidden edge. Stage 5 therefore
places this one protocol in `crypto_lab/adapters/ports.py`. Stage 4 has already
added modules to `adapters`, so this is not a new cross-stage ownership pattern.

### 2.5 Frozen-byte constraints

The verification workflow treats the 20 committed schemas as reviewed source and
a published `$id` as a permanent contract. Stage 5 must leave all 20
byte-identical. Four constraints follow, each proven by the digest gate rather
than asserted:

1. **No new `DiagnosticCategory` member.** The enum is published inside
   `domain/diagnostic-v1`. Every Stage 5 diagnostic maps onto an existing member
   (§8.6); `Diagnostic`'s validator requires `invocation_id` for
   `ENGINE_RUNTIME`, `PROTOCOL`, `TIMEOUT` and `CANCELLATION`, and requires
   `experiment_id` whenever `run_id` is set.
2. **`RetryTerminalState` relocation is byte-neutral or is not performed.** It
   renders into `configuration/application-config-v1` `$defs` by bare class name
   as `{"enum":["FAILED","TIMED_OUT","UNAVAILABLE"],"title":"RetryTerminalState","type":"string"}`.
   Task 1 moves the definition to `crypto_lab/domain/lifecycle.py` and re-exports
   it from `crypto_lab.configuration.models`. The moved class keeps the identical
   name, the identical three members in order, and **no docstring**, because a
   docstring emits a `description` key.
3. **`CompatibilityOutcome` relocation is byte-neutral or is not performed.** It
   renders into `capabilities/compatibility-result-v1` `$defs` by bare class name
   **with a `description`**, because the merged class carries a docstring. Task 1
   moves the definition to `crypto_lab/domain/compatibility.py` and re-exports it
   from `crypto_lab.capabilities.models`; the moved class keeps the identical
   name, the identical four members in order, and the **byte-identical
   docstring**. The relocation exists because §9 needs a domain-typed
   compatibility outcome and `domain` may not import `capabilities`.
4. **New identifier types and new `HashingProfile` members are safe only because
   nothing published reaches them.** `HashingProfile` appears in no generated
   schema, because `StrategyVersion.hashing_profile_version` publishes a
   `Literal` rather than the enum.

For constraints 2 and 3 the fallback, if Task 1's digest gate shows any movement,
is to leave the merged enum untouched and let `domain` define an independent
enum with the same members, with the projection functions mapping between them.

### 2.6 Published-timestamp rule

Every Stage 5 timestamp field reachable from a registered schema uses
`CalendarValidUtcDateTime`. The merged guard
`test_every_published_stage_four_timestamp_uses_the_forward_view` in
`tests/unit/domain/test_time.py` needs **no** edit: its registry half increments
its counter for every non-Stage-3 entry before asserting that entry publishes no
loose timestamp pattern, so it self-adjusts to 27 entries and passes for a Stage 5
schema with no timestamp field at all.

### 2.7 Closed-world guard reconciliation

The merged tree enforces several **closed sets** as exact equalities. Stage 5
necessarily changes their membership, so every such guard is reconciled here,
each change is assigned to the task whose work first trips it, and no guard is
weakened, deleted or replaced by a lower bound. This section is the single
normative authority for every edit Stage 5 makes to a Stage 1–4 test file, and it
was derived by enumerating every `assert` statement in the four guard files with
the `ast` module rather than by sampling.

**Rule.** A task that creates a module under `src/crypto_lab` appends that
module, in the same commit, to both `_ALLOWED_SOURCE_FILES` in
`tests/safety/test_stage3_boundaries.py` and `PACKAGE_MODULES` in
`tests/unit/test_package_layout.py`. A task that first defines a name held in
`_DEFERRED_DEFINITIONS` removes exactly that name, in the same commit, from both
the set and the literal set-equality assertion, and decrements the pinned count
by exactly one per name. A definition is never released before the commit that
defines it.

**Source-file allowlist.** `_ALLOWED_SOURCE_FILES` is a literal 51-path set
asserted by set equality in `test_stage3_source_file_set_is_closed`. Stage 5 adds
exactly 18 paths, taking it to 69:

| Task | Paths appended (relative to `src/crypto_lab`) | Running size |
|---|---|---:|
| 1 | `domain/lifecycle.py`, `domain/ports.py`, `domain/compatibility.py` | 54 |
| 2 | `domain/experiment.py`, `domain/retry.py`, `configuration/retry_policy.py` | 57 |
| 3 | `domain/command_invocation.py` | 58 |
| 4 | `domain/engine_run.py` | 59 |
| 5 | `domain/aggregation.py` | 60 |
| 6 | `experiments/ports.py`, `experiments/requests.py`, `experiments/diagnostics.py`, `experiments/experiment_service.py`, `experiments/run_service.py`, `experiments/invocation_service.py`, `adapters/ports.py` | 67 |
| 7 | `experiments/retry.py` | 68 |
| 8 | `experiments/aggregation.py` | 69 |

The same 18 dotted module names are appended to `PACKAGE_MODULES` by the same
tasks, so the fresh-import side-effect probe covers every Stage 5 module.

**Deferred-definition guard.** `_DEFERRED_DEFINITIONS` holds 65 names, asserted
by `len == 65` and an exact literal set in
`test_the_deferred_definition_set_is_exactly_the_reviewed_sixty_five`, enforced
against every `class`/`def` in `src/crypto_lab` by
`test_source_has_no_path_ambient_access_or_later_stage_definitions`, and
self-tested per name and by a seven-name representative-mutation list. Stage 5
defines exactly 12 of those names and releases each in the task that defines it;
the final pinned count is `65 − 12 = 53`:

| Task | Names released | Running count |
|---|---|---:|
| 1 | `Clock`, `CommandKind`, `CommandInvocationState` | 62 |
| 2 | `RetryPolicy`, `ExperimentSpec`, `ExperimentRecord` | 59 |
| 3 | `CommandInvocationRecord` | 58 |
| 4 | `EngineRunRecord` | 57 |
| 6 | `ExperimentRepository`, `EngineRunRepository`, `UnitOfWork`, `CommandInvocationRepository` | 53 |

No other Stage 5 name — including `ExperimentState`, `EngineRunState`,
`ProcessExitCategory`, `ProcessStartFacts`, `SlotCompatibility`,
`IdentitySource`, `RetryDecisionRecord`, `RetryDecisionRepository`,
`CompatibilityOutcome` and every request model — is a member of the set, and
`LogicalSlotId`, `AttemptToken`, `CorrelationId` and `Result` are `type` aliases
the guard's `ClassDef`/`FunctionDef` walk does not visit. `ContentHasher` and
`MonotonicInstant` remain deferred (§1.4). Task 1 additionally replaces
`CommandInvocationState` in the seven-name parametrize list of
`test_representative_later_stage_type_mutations_are_blocked` with the
still-deferred `RunEvent`, so that self-test keeps seven live cases, and updates
the sixty-five test's docstring arithmetic to cite this section.

**Schema-registry guards.** Stage 5 moves the registry from 20 to 27 entries,
preserving Stage 3 at positions 0–10, Stage 4 at 11–19 and placing Stage 5 at
20–26. Every affected assertion and its owning task:

| File | Assertion | Change | Task |
|---|---|---|---|
| `tests/unit/test_schema_registry.py` | `_STAGE3_SHA256` block (11 digests, `== 11`, Stage 4 paths asserted absent) | unchanged | — |
| same | new `_STAGE4_SHA256` (9 digests) with key-equality, `== 9` and Stage-3-and-Stage-5-absent assertions | added | 1 |
| same | `_EXPECTED` path→`$id` map and its three consumers | +7 entries | 9 |
| same | `len(SCHEMA_DEFINITIONS) == 20` | `== 27` | 9 |
| same | `_STAGE5_PATHS` tuple with `len == 7` | added | 9 |
| same | `_ordered_paths()[:11] == _STAGE3_PATHS` and its `$id` twin | unchanged | — |
| same | `_ordered_paths()[11:] == _STAGE4_PATHS` | `[11:20] == _STAGE4_PATHS` plus `[20:] == _STAGE5_PATHS`; `len(_STAGE4_PATHS) == 9` stays | 9 |
| same | `paths == _STAGE3_PATHS + _STAGE4_PATHS` and the parallel `$id` tuple | `+ _STAGE5_PATHS` | 9 |
| same | `len(paths)`, `len(set(paths))`, `len(set(identifiers))` `== 20` | `== 27` | 9 |
| same | `_EXPECTED_ADAPTED_TYPES` and the singleton-plus-adapted `== 20` | +7 fresh `TypeAdapter` entries, no new singleton; `== 27` | 9 |
| same | `len(rendered) == 20` | `== 27` | 9 |
| same | rendered-path inventory `found == sorted(...)` and the on-disk `$id` loop | include `_STAGE5_PATHS` | 9 |
| same | new `_STAGE5_SHA256` (7 digests) with key-equality, `== 7` and Stage-3-and-Stage-4-absent assertions | added | 9 |
| same | every loop scoped to `_STAGE4_PATHS` alone, every Stage 4 semantic count, the generator `_write`/`_check` tests | unchanged | — |
| `tests/unit/domain/test_domain_descriptors.py` | `len(rendered) == 20` | `== 27` | 9 |
| `tests/safety/test_stage3_boundaries.py` | `len(paths) == 20` over `SCHEMA_DEFINITIONS` | `== 27` | 9 |
| `tests/integration/test_schema_distribution.py`, `scripts/verify_schema_distribution.py`, `scripts/generate_schemas.py` | derive expected paths from the registry | unchanged | — |

No `paths[11:] == _STAGE4_PATHS` assertion survives.

**Documentation and status pins.** Task 9 owns every completion-status change
below, in the same commit that changes the prose, and introduces the constant
`STAGE5_IMPLEMENTATION_COMMIT`, asserted to match `[0-9a-f]{40}` and to differ
from every previously pinned commit.

| File | Assertion | Stage 5 successor |
|---|---|---|
| `tests/safety/test_stage3_boundaries.py` | `_STAGE4_ROADMAP_STATUS_LINE` ("Stages 1 through 4 complete"), three occurrences | `_STAGE5_ROADMAP_STATUS_LINE`: "**Status:** Approved planning decomposition; Stages 1 through 5 complete" |
| same | `_STAGE4_ROADMAP_PLAN_SENTENCE`, two occurrences | "Stages 1 through 5 have approved detailed implementation plans." |
| same | `_STAGE4_ROADMAP_ROW` (ends "; Stage 5 not started \|"), three occurrences | identical row text with the final clause replaced by "; Stage 5 complete \|" |
| same | Stage 5 roadmap row "Intentionally deferred … \| Not started \| Not evaluated \|" | "\| 5 — Experiment, Run, Invocation, Retry, and Aggregation Logic \| Approved and executed \| Implementation complete at `STAGE5_IMPLEMENTATION_COMMIT` \| Complete; … closed 27-schema registry …; Stage 6 not started \|" |
| same | `"**Status:** Project 1 Stages 1-4 complete" in readme` (README line 3) | "**Status:** Project 1 Stages 1-5 complete" |
| same | `_README_STAGE4_STATUS in readme` | `_README_STAGE5_STATUS`: Stage 5 complete at `STAGE5_IMPLEMENTATION_COMMIT`; reviewed 27-schema registry; "Stage 6 has not started." |
| same | `_VERIFICATION_STAGE4_STATUS in guide` | `_VERIFICATION_STAGE5_STATUS`: same facts; "The closed 27-schema registry holds the seven new Stage 5 schemas together with the twenty Stage 3 and Stage 4 schemas, preserved byte-identical to `main`. Stage 6 is not started." |
| same | `STAGE4_IMPLEMENTATION_COMMIT in roadmap / readme / guide` | roadmap keeps the Stage 4 hash in its history row; readme and guide assert `STAGE5_IMPLEMENTATION_COMMIT`; a new assertion pins `STAGE5_IMPLEMENTATION_COMMIT in roadmap` |
| same | remainder subtraction of the Stage 4 README and guide blocks | subtracts the Stage 5 successor blocks; `_VERIFICATION_CORPUS_QUALIFICATION` and `_VERIFICATION_NON_GOALS` stay verbatim and stay pinned |
| same | `"Stage 5" not in readme_rest / guide_rest` | `"Stage 6" not in readme_rest / guide_rest` — the exact contract that "Stage 6 not started" appears only inside the pinned block and no other Stage 6 claim exists |
| same | `"exhaustiv" not in …rest.lower()` | unchanged; the subtracted Stage 5 block is the only place permitted to say "exhaustive" |
| same | retired-phrase negatives | unchanged; Stage 5 prose reintroduces none |
| `tests/safety/test_gitnexus_development_tooling.py` | duplicate pins of the roadmap plan sentence and status line | the same two Stage 5 successors |

No prose may claim that protocol, process supervision, persistence or artifact
finalization has begun; the successor blocks state Stage 5 completion at its exact
implementation commit and that Stage 6 is not started.

**Not touched.** `tests/safety/test_uv_launcher.py`'s unrelated
`len(_EXPECTED_OPERATIONS) == 20`, `_ALLOWED_IMPORT_ROOTS`,
`_EXPECTED_VERIFICATION_PROFILES`, `_ALLOWED_VERIFIER_COMMANDS`, the
`pythonpath == ["scripts"]` pin (§11), every Stage 2, Stage 3 and Stage 4 plan
pin, the README uv-command prose pins, and every Stage 1–4 test not named above.

## 3. Canonical model inventory

### 3.1 Shared conventions

All Stage 5 models are frozen strict Pydantic v2 models deriving from
`CanonicalModel`. Every **top-level** model carries
`schema_version: Literal["1.0.0"]` as its first field; **nested value objects
carry no such envelope version**, following the merged `SupportedSchemaVersion`
precedent, whose `schema_version` field is a `SemanticVersion` rather than the
`Literal["1.0.0"]` envelope. `RetryPolicy` is the one nested model that keeps the
envelope, because the specification lists it among that record's minimum fields.
Absence is `pydantic.experimental.missing_sentinel.MISSING`, never `None`.
Collections are `tuple[...]` with explicit `max_length`, sorted and deduplicated
where order has no semantic meaning. No public dictionary is untyped. No model
reads the environment, filesystem, clock or a random source.

### 3.2 Field sources

Every required field has exactly one declared source **per operation**: **R**
request identity (caller-supplied on a public operation request), **C** existing
canonical record, **A** authoritative repository or unit-of-work read, **D** pure
deterministic derivation, **K** injected `Clock`, **I** injected
`IdentitySource`. Where a field's source differs between the operation that first
establishes it and later operations, both are given.

**Carry-forward rule, stated once.** On every transition and enrichment
operation, the service copies each stored non-immutable state-governed field
forward unchanged, except where the target state's field shape (§4, §5, §6)
requires it absent, or the request supplies a new value for a field that target
state governs. A request may never clear a field the target state requires
present, and may never set a field that state prohibits; either is
`CORE.INVARIANT_VIOLATION`.

**Instants.** Every recorded instant comes from the injected `Clock`, with one
declared exception: `ProcessStartFacts.process_started_at_utc` (§3.7) is an
operating-system observation made by the supervisor and is therefore **R**.

### 3.3 New identifiers, ports and profiles (`domain`)

| Name | Module | Shape |
|---|---|---|
| `LogicalSlotId` | `domain/identifiers.py` | `slot_<uuid4>`, same annotation stack as the merged prefixed identifiers |
| `AttemptToken` | `domain/identifiers.py` | Strict `str`, length 32–1024, pattern `^[A-Za-z0-9_-]+$`; temporary sensitive correlation material, never a field of a persisted record |
| `CorrelationId` | `domain/identifiers.py` | Strict `str`, length 1–128, pattern `^[A-Za-z0-9][A-Za-z0-9._:-]*$`; the same constraints as the alias in `artifacts/ownership.py`, defined separately because `domain` may not import `artifacts` |
| `Clock` | `domain/ports.py` | `Protocol` with `now_utc() -> datetime` returning a timezone-aware UTC instant |
| `IdentitySource` | `domain/ports.py` | `Protocol` with `new_experiment_id`, `new_run_id`, `new_invocation_id`, `new_logical_slot_id`, `new_attempt_token` |
| `CompatibilityOutcome` | `domain/compatibility.py` | Relocated (§2.5 constraint 3); members `SUPPORTED`, `SUPPORTED_WITH_APPROXIMATION`, `NOT_APPLICABLE`, `UNAVAILABLE` |
| `HashingProfile.EXPERIMENT_CONFIGURATION_V1` | `domain/hashing.py` | New member, value `experiment-configuration/v1` |
| `HashingProfile.EXPERIMENT_SPEC_V1` | `domain/hashing.py` | New member, value `experiment-spec/v1` |

Ambient randomness and ambient wall-clock reads are forbidden, which is why both
`Clock` and `IdentitySource` are injected protocols. Diagnostic identity is
**derived, not drawn**: Stage 5 reuses the merged
`HashingProfile.DIAGNOSTIC_IDENTITY_V1` content-derivation pattern, extending the
payload with the correlation identifiers Stage 5 diagnostics carry and excluding
`timestamp_utc`, so identity stays a function of content alone.

### 3.4 `RetryPolicy` — `domain/retry.py`

| # | Field | Type | Source | Optionality |
|---:|---|---|---|---|
| 1 | `schema_version` | `Literal["1.0.0"]` | D | Required |
| 2 | `maximum_attempts_per_slot` | `int` 1–5, default 1 | R | Required |
| 3 | `automatically_retry_terminal_states` | `tuple[RetryTerminalState, ...]`, unique, normalized to fixed order `FAILED`, `TIMED_OUT`, `UNAVAILABLE`, default `()` | R | Required, explicit empty array |
| 4 | `retry_delay_seconds` | `int` 0–300, default 0 | R | Required |
| 5 | `require_fresh_availability_observation_for_unavailable` | `Literal[True]` | D | Required |

`retry_policy_from_config(retry: RetryConfig) -> RetryPolicy` in
`configuration/retry_policy.py` is the sole projection from configuration.

### 3.5 `ExperimentSpec` — `domain/experiment.py`

| # | Field | Type | Source |
|---:|---|---|---|
| 1 | `schema_version` | `Literal["1.0.0"]` | D |
| 2 | `strategy_version_hash` | `Sha256` | R |
| 3 | `dataset_version_hash` | `Sha256` | R |
| 4 | `selected_engine_slots` | `tuple[SelectedEngineSlot, ...]`, 1–8, ordinals `0..n-1` ascending, `logical_slot_id` unique, `(adapter, engine)` unique | R |
| 5 | `starting_balance` | `Money` with positive amount | R |
| 6 | `fee_assumptions` | `FeeAssumptions` | R |
| 7 | `slippage_assumptions` | `SlippageAssumptions` | R |
| 8 | `execution_assumptions` | `ExecutionAssumptions` | R |
| 9 | `comparison_level` | `ComparisonLevel` | R |
| 10 | `retry_policy` | `RetryPolicy` | R |
| 11 | `configuration_hash` | `Sha256` | D |
| 12 | `created_at_utc` | `CalendarValidUtcDateTime` | K |

Every field is required. Fields 2–10 are exactly the content of
`ExperimentSpecDraft`, the nested value object a caller supplies (§3.11); the
service derives field 11, reads field 12 from the `Clock`, and assembles the
record, which is what makes fields 11 and 12 obtainable at the one moment the
spec first exists.

Nested value objects, all caller-supplied and all anchored to the
specification's Level 2 parity list:

- `SelectedEngineSlot`: `logical_slot_id`, `slot_ordinal` (`int` 0–7),
  `adapter` (`AdapterIdentity`), `engine` (`EngineIdentity`).
- `AdapterIdentity`: `adapter_name` (`NormalizedIdentifier`), `adapter_version`
  (`SemanticVersion`). `EngineIdentity`: `engine_name`, `engine_version`.
- `FeeAssumptions`: `maker_fee_rate`, `taker_fee_rate`, both
  `NonNegativeDecimal` and at most `1`.
- `SlippageAssumptions`: `model` (`SlippageModel`: `NONE`,
  `FIXED_BASIS_POINTS`), `basis_points` (`NonNegativeDecimal | MISSING`, present
  if and only if `model` is `FIXED_BASIS_POINTS`).
- `ExecutionAssumptions`: `signal_to_order_timing` (`NEXT_BAR_OPEN`,
  `SAME_BAR_CLOSE`), `bar_order_priority` (`EXITS_BEFORE_ENTRIES`,
  `ENTRIES_BEFORE_EXITS`), `fill_convention` (`FULL_FILL`,
  `PARTIAL_FILLS_ALLOWED`), `price_precision` (`int` 0–18),
  `quantity_precision` (`int` 0–18), `rounding_mode`
  (`Literal["ROUND_HALF_EVEN"]`).

These enumerations are deliberately narrow for the approved Project 1 scope and
extend additively.

`configuration_hash` is **not** a self-hash and is non-circular. It is
`profile_hash(EXPERIMENT_CONFIGURATION_V1, payload)` over exactly the
request-supplied `material_base_configuration_hash` plus fields 2–10 in canonical
form; fields 1, 11 and 12 are excluded. That hash value is carried by
`ExperimentCreationRequest`, `ExperimentSpecReplacementRequest` and
`ExperimentQueueRequest`, because `experiments` cannot import `configuration`.

`experiment_spec_hash(spec) -> Sha256` is
`profile_hash(EXPERIMENT_SPEC_V1, canonical spec payload)` over the complete
canonical `ExperimentSpec` including `schema_version`, `configuration_hash` and
`created_at_utc`. It is external to that payload and is therefore not a self-hash
field.

### 3.6 `ExperimentRecord` — `domain/experiment.py`

| # | Field | Type | Source | Optionality |
|---:|---|---|---|---|
| 1 | `schema_version` | `Literal["1.0.0"]` | D | Required |
| 2 | `experiment_id` | `ExperimentId` | I | Required |
| 3 | `spec` | `ExperimentSpec` | D from the request's `ExperimentSpecDraft` at `create_experiment` and `replace_experiment_spec`; **C** on every other operation | Required |
| 4 | `spec_hash` | `Sha256` | D | Required; recomputed and compared by a model validator |
| 5 | `state` | `ExperimentState` | D | Required |
| 6 | `slot_compatibility` | `tuple[SlotCompatibility, ...] \| MISSING` | R at `queue_experiment`; C thereafter | Absent in `DRAFT` and `VALIDATED`; present from `QUEUED`, exactly one entry per selected slot in slot order, immutable thereafter |
| 7 | `cancellation_correlation_id` | `CorrelationId \| MISSING` | R at `cancel_experiment` | Present if and only if `state` is `CANCELLED` |
| 8 | `created_at_utc` | `CalendarValidUtcDateTime` | K | Required |
| 9 | `updated_at_utc` | `CalendarValidUtcDateTime` | K | Required; at or after `created_at_utc` |
| 10 | `revision` | `int` ≥ 0 | D | Required |

`SlotCompatibility` is a nested value object holding the **immutable
compatibility result** of one selected slot, resolved by the Stage 4 resolver in
the composition root before queueing and frozen with the spec: `logical_slot_id`,
`outcome` (`CompatibilityOutcome`), `availability_observation_id`
(`AvailabilityObservationId`), and `approximation_ids`
(`tuple[ApproximationId, ...]`, sorted unique, ≤ 64, **non-empty if and only if**
`outcome` is `SUPPORTED_WITH_APPROXIMATION`). It carries no `ApproximationDeclaration`
body: `domain` may not import `capabilities`, and aggregation needs only the
outcome and the declaration identities. Approximation status anywhere in Stage 5
is derived solely from this frozen record.

### 3.7 `CommandInvocationRecord` — `domain/command_invocation.py`

| # | Field | Type | Source | Optionality (governing rule in §6) |
|---:|---|---|---|---|
| 1 | `schema_version` | `Literal["1.0.0"]` | D | Required |
| 2 | `invocation_id` | `InvocationId` | I | Required |
| 3 | `command_kind` | `CommandKind` | R | Required |
| 4 | `adapter_name` | `NormalizedIdentifier` | R | Required |
| 5 | `adapter_version` | `SemanticVersion` | R | Required |
| 6 | `run_id` | `RunId \| MISSING` | R | Absent for `DESCRIBE`, required for `VALIDATE`/`RUN` |
| 7 | `request_hash` | `Sha256` | R | Required; immutable |
| 8 | `timeout_seconds` | `int` | R | Required; bounded by `command_kind` |
| 9 | `deadline_utc` | `CalendarValidUtcDateTime \| MISSING` | D at `PENDING → STARTING` as `now_utc + timeout_seconds`; C thereafter | Absent in `PENDING`; present from `STARTING` |
| 10 | `state` | `CommandInvocationState` | D | Required |
| 11 | `process_created` | `bool` | D | Required |
| 12 | `launch_attempted_at_utc` | `CalendarValidUtcDateTime \| MISSING` | K at `STARTING`; C thereafter | Absent in `PENDING`; present from `STARTING` |
| 13 | `process_started_at_utc` | `CalendarValidUtcDateTime \| MISSING` | R from `ProcessStartFacts` at the process-start handoff; C thereafter | Present exactly when `process_created` is true |
| 14 | `pid_identity` | `ProcessIdentity \| MISSING` | R from `ProcessStartFacts` at the process-start handoff; C thereafter | Present exactly when `process_created` is true |
| 15 | `completed_at_utc` | `CalendarValidUtcDateTime \| MISSING` | K | Present exactly in a terminal state |
| 16 | `native_exit_value` | `int` −2147483648…4294967295 `\| MISSING` | R | Co-occurs with field 17 |
| 17 | `process_exit_category` | `ProcessExitCategory \| MISSING` | D from field 16 by the §6 mapping | Required in `EXITED`; elsewhere co-occurs with field 16 or both absent |
| 18 | `cleanup_complete` | `bool` | D false at creation; R through `InvocationEnrichmentRequest` | Required; false in every non-terminal state |
| 19 | `cleanup_completed_at_utc` | `CalendarValidUtcDateTime \| MISSING` | K | Present if and only if `cleanup_complete` |
| 20 | `stderr_artifact_id` | `ArtifactId \| MISSING` | R through `InvocationEnrichmentRequest` | Absent unless terminal; owner/purpose validation deferred (§1.4) |
| 21 | `primary_diagnostic_id` | `DiagnosticId \| MISSING` | R | Required in every terminal state except `EXITED`, where it is optional except as §6 requires for an unrecognized exit; must be a member of field 22 |
| 22 | `diagnostic_ids` | `tuple[DiagnosticId, ...]`, ≤ 64, sorted unique | R | Required, explicit empty array |
| 23 | `created_at_utc` | `CalendarValidUtcDateTime` | K | Required |
| 24 | `updated_at_utc` | `CalendarValidUtcDateTime` | K | Required |
| 25 | `revision` | `int` ≥ 0 | D | Required |

`timeout_seconds` bounds are `1–300` for `DESCRIBE`, `1–1800` for `VALIDATE` and
`1–604800` for `RUN`, copied as literals from the merged configuration schema.

`ProcessIdentity` (nested, persisted in field 14): `pid` (`int` 1…4294967295),
`creation_identity` (`BoundedText`), `executable_path` (`ExecutablePath`),
`executable_hash` (`Sha256`), `supervisor_instance_id` (`BoundedText`).

`ProcessStartFacts` (nested, request-side, **the one common carrier for every
command kind**): `pid_identity` (`ProcessIdentity`) and `process_started_at_utc`
(`CalendarValidUtcDateTime`, an operating-system observation, §3.2). Stage 5
accepts it as caller-supplied launch-handoff material; Stage 7 produces real
values. It travels on `InvocationTransitionRequest` for `DESCRIBE` and `VALIDATE`
and on `LinkedStartRequest` for `RUN`, so no command kind is barred from
`RUNNING`.

### 3.8 `EngineRunRecord` — `domain/engine_run.py`

| # | Field | Type | Source | Optionality (governing rule in §5) |
|---:|---|---|---|---|
| 1 | `schema_version` | `Literal["1.0.0"]` | D | Required |
| 2 | `run_id` | `RunId` | I | Required |
| 3 | `experiment_id` | `ExperimentId` | C | Required |
| 4 | `logical_slot_id` | `LogicalSlotId` | C | Required; must be a slot of the experiment |
| 5 | `attempt_number` | `int` 1–5 | D | Required |
| 6 | `attempt_token_hash` | `Sha256` | D | Required; `attempt_token_hash(token)` over an `IdentitySource` token |
| 7 | `state` | `EngineRunState` | D | Required |
| 8 | `adapter` | `AdapterIdentity` | C | Required |
| 9 | `engine` | `EngineIdentity` | C | Required |
| 10 | `request_hash` | `Sha256` | R | Required; the request itself is Stage 6-owned |
| 11 | `predecessor_run_id` | `RunId \| MISSING` | A | Present if and only if `attempt_number > 1` |
| 12 | `retry_reason` | `RetryTerminalState \| MISSING` | D over A, as `retry_terminal_state_of(decision.predecessor_terminal_state)` | Present if and only if field 11 is present |
| 13 | `primary_terminal_diagnostic_id` | `DiagnosticId \| MISSING` | R | Present exactly in a non-success terminal state |
| 14 | `availability_observation_id` | `AvailabilityObservationId \| MISSING` | R at the transition into `READY` or `UNAVAILABLE`; C thereafter | Present from `READY` onward and in `UNAVAILABLE` |
| 15 | `finalization_deadline_utc` | `CalendarValidUtcDateTime \| MISSING` | R | Absent throughout Stage 5; snapshotted by Stage 9 |
| 16 | `created_at_utc` | `CalendarValidUtcDateTime` | K | Required |
| 17 | `updated_at_utc` | `CalendarValidUtcDateTime` | K | Required |
| 18 | `revision` | `int` ≥ 0 | D | Required |

**A terminal `EngineRunRecord` is completely immutable: no post-terminal
enrichment, no further compare-and-swap, no revision increment.** Its
`updated_at_utc` is therefore the authoritative terminal completion instant and
is what the durable retry delay is measured from (§8.4). Write-once terminal
enrichment exists only on `CommandInvocationRecord` (§6).

The raw attempt token never appears in this or any other persisted record. The
create-attempt operation returns `AttemptTokenMaterial` (`run_id`,
`attempt_token`) alongside the record as explicitly temporary material; it is
never persisted, never hashed into anything but field 6, and never placed in a
diagnostic.

### 3.9 `RetryDecisionRecord` — `domain/retry.py`

Immutable and complete at insertion. There is no `revision` and no separate
operational identifier: identity is `(logical_slot_id, predecessor_run_id)`.

| # | Field | Type | Source | Optionality | In projection |
|---:|---|---|---|---|---|
| 1 | `schema_version` | `Literal["1.0.0"]` | D | Required | Yes |
| 2 | `experiment_id` | `ExperimentId` | A | Required | Yes |
| 3 | `logical_slot_id` | `LogicalSlotId` | A | Required | Yes |
| 4 | `predecessor_run_id` | `RunId` | R | Required | Yes |
| 5 | `experiment_spec_hash` | `Sha256` | A | Required | Yes |
| 6 | `retry_policy` | `RetryPolicy` | A | Required | Yes |
| 7 | `created_attempt_count` | `int` 1–5 | A | Required | Yes |
| 8 | `predecessor_terminal_state` | `EngineRunState`, restricted to the five non-success terminal members | A | Required | Yes |
| 9 | `primary_terminal_diagnostic_id` | `DiagnosticId` | A | Required | Yes |
| 10 | `outcome` | `RetryDecisionOutcome` (`ALLOWED`, `DENIED`) | D | Required | Yes |
| 11 | `denial_reason` | `RetryDenialReason \| MISSING` | D | Present iff `DENIED` | Yes |
| 12 | `hard_block_error_code` | `ErrorCode \| MISSING` | D over A | Present iff `denial_reason` is `HARD_BLOCKED_OUTCOME` | Yes |
| 13 | `availability_observation_id` | `AvailabilityObservationId \| MISSING` | A | Present iff `ALLOWED` and the terminal state is `UNAVAILABLE` | Yes |
| 14 | `retry_not_before_utc` | `CalendarValidUtcDateTime \| MISSING` | D | Present iff `ALLOWED` | Yes |
| 15 | `reserved_successor_attempt_number` | `int` 2–5 `\| MISSING` | D | Present iff `ALLOWED`; equals `created_attempt_count + 1` | Yes |
| 16 | `decided_at_utc` | `CalendarValidUtcDateTime` | K | Required | **No** |

Field 8's restriction to `FAILED`, `CANCELLED`, `TIMED_OUT`, `NOT_APPLICABLE` and
`UNAVAILABLE` is what makes field 9 unconditionally satisfiable: those are
exactly the states §5 requires to carry a primary terminal diagnostic; the two
success states are rejected by §8.3 before construction. The published schema
carries the full `EngineRunState` enum and the runtime validator narrows it — a
recorded residual of the kind `docs/development/verification.md` already lists.

`retry_decision_semantic_projection(record) -> bytes` returns canonical JSON over
fields 1–15; field 16 is clock metadata and the sole exclusion. The created
successor is found through run identity and predecessor relationships; the
decision is never mutated to carry a successor run ID.

### 3.10 Aggregation records — `domain/aggregation.py`

`SlotRetryStatus`: `NO_DECISION_REQUIRED`, `DECISION_UNRESOLVED`,
`ALLOWED_SUCCESSOR_PENDING`, `DENIED`. `AggregationVerdict`: `NOT_YET_TERMINAL`,
`COMPLETED`, `COMPLETED_WITH_WARNINGS`, `FAILED`, `CANCELLED`.

`SlotAggregationInput` (nested) represents **one selected slot, whether or not it
has an attempt**: `logical_slot_id`, `slot_ordinal`, `compatibility_outcome`
(`CompatibilityOutcome`), `approximation_ids`, `latest_attempt_run_id`
(`RunId | MISSING`), `latest_attempt_state` (`EngineRunState | MISSING`; present
exactly when the run id is), and `retry_status`. Every field is **A**: the first
four come from the experiment's frozen `slot_compatibility`, the rest from the run
and decision repositories. `ExperimentAggregationInput` (top level):
`schema_version` (**D**), `experiment_id` (**A**), `experiment_spec_hash`
(**A**), `slots` (1–8, ordered by `slot_ordinal`, unique, and asserted equal to
the frozen selected-slot set). `ExperimentAggregationResult` (top level):
`schema_version`, `experiment_id`, `verdict`, `reason_codes`
(`tuple[ErrorCode, ...]`, ≤ 32, sorted unique) — all **D**.

The pure classifier never emits `CANCELLED`; that member exists so §9.4's
idempotent already-terminal path can express a cancelled experiment with the same
result type.

### 3.11 Public operation requests — `experiments/requests.py`

Top-level models carrying `schema_version`, not published as schemas. Each
carries stable identity and expected revisions only. The inventory is exactly
one request per §10.1 operation, sixteen each.

| Request | Fields beyond `schema_version` |
|---|---|
| `ExperimentCreationRequest` | `spec_draft` (`ExperimentSpecDraft`), `material_base_configuration_hash` |
| `ExperimentSpecReplacementRequest` | `experiment_id`, `expected_revision`, `spec_draft`, `material_base_configuration_hash` |
| `ExperimentTransitionRequest` | `experiment_id`, `expected_revision`, `target_state`, `reason_code` |
| `ExperimentQueueRequest` | `experiment_id`, `expected_revision`, `config_derived_retry_policy`, `material_base_configuration_hash`, `slot_compatibility` (`tuple[SlotCompatibility, ...]`) |
| `CancelExperimentRequest` | `experiment_id`, `expected_revision`, `correlation_id` |
| `AttemptCreationRequest` | `experiment_id`, `logical_slot_id`, `expected_experiment_revision`, `request_hash` |
| `RunTransitionRequest` | `run_id`, `expected_revision`, `target_state`, `reason_code`, `primary_terminal_diagnostic_id \| MISSING`, `availability_observation_id \| MISSING` |
| `InvocationCreationRequest` | `command_kind`, `adapter_name`, `adapter_version`, `run_id \| MISSING`, `expected_run_revision \| MISSING`, `request_hash`, `timeout_seconds` |
| `LinkedLaunchRequest` | `invocation_id`, `expected_invocation_revision`, `run_id`, `expected_run_revision` |
| `InvocationTransitionRequest` | `invocation_id`, `expected_revision`, `target_state`, `reason_code`, `process_start` (`ProcessStartFacts \| MISSING`), `native_exit_value \| MISSING`, `primary_diagnostic_id \| MISSING`, `diagnostic_ids` |
| `LinkedStartRequest` | `invocation_id`, `expected_invocation_revision`, `run_id`, `expected_run_revision`, `process_start` (`ProcessStartFacts`) |
| `InvocationEnrichmentRequest` | `invocation_id`, `expected_revision`, `native_exit_value \| MISSING`, `cleanup_complete \| MISSING`, `stderr_artifact_id \| MISSING`, `additional_diagnostic_ids` |
| `CoupledTransitionRequest` | `invocation` (`InvocationTransitionRequest`), `run` (`RunTransitionRequest`) |
| `RetryEvaluationRequest` | `experiment_id`, `logical_slot_id`, `predecessor_run_id`, `expected_experiment_revision`, `expected_predecessor_revision` |
| `SuccessorCreationRequest` | `experiment_id`, `logical_slot_id`, `predecessor_run_id`, `expected_experiment_revision`, `request_hash` |
| `ExperimentAggregationRequest` | `experiment_id`, `expected_revision` |

`ExperimentSpecDraft` holds exactly `ExperimentSpec` fields 2–10 (§3.5).
`process_start` is required on `InvocationTransitionRequest` exactly when
`target_state` is `RUNNING` and prohibited otherwise. `process_exit_category` is
never a request field: it is derived from `native_exit_value` (§6). No request
carries an authoritative attempt count, a caller-built authoritative snapshot, a
caller-selected outcome, denial material, `retry_not_before_utc`, a reserved
successor number, an approximation flag, or an authoritative terminal fact.

## 4. Experiment lifecycle

`ExperimentState` has exactly eight members and therefore 64 ordered state pairs,
of which exactly **12** are permitted. Every ordered pair not listed below is
forbidden and fails atomically with `CORE.INVARIANT_VIOLATION`.

| State | Terminal | Permitted successors | Revision | Immutable fields |
|---|---|---|---|---|
| `DRAFT` | No | `VALIDATED`, `CANCELLED` | +1 per accepted transition or spec replacement | `experiment_id`, `created_at_utc` |
| `VALIDATED` | No | `DRAFT`, `QUEUED`, `CANCELLED` | +1 | as above |
| `QUEUED` | No | `RUNNING`, `FAILED`, `CANCELLED` | +1 | `spec`, `spec_hash`, `slot_compatibility` plus the above |
| `RUNNING` | No | `COMPLETED`, `COMPLETED_WITH_WARNINGS`, `FAILED`, `CANCELLED` | +1, including a state-preserving bump (§9.1) | as `QUEUED` |
| `COMPLETED` | Yes | none | frozen | every field |
| `COMPLETED_WITH_WARNINGS` | Yes | none | frozen | every field |
| `FAILED` | Yes | none | frozen | every field |
| `CANCELLED` | Yes | none | frozen | every field |

**Edge ownership.** Every one of the twelve edges is owned by exactly one
operation, and no other operation may produce it. A `target_state` outside its
operation's owned set is `CORE.INVARIANT_VIOLATION`, which is what stops a
generic transition from reaching `QUEUED` or a terminal state and skipping §7's
freeze checks or §9's readiness rule.

| Owning operation | Owned edges |
|---|---|
| `transition_experiment` | `DRAFT → VALIDATED`, `QUEUED → FAILED` |
| `replace_experiment_spec` | `VALIDATED → DRAFT`, and the same-state `DRAFT` replacement |
| `queue_experiment` | `VALIDATED → QUEUED` |
| `create_attempt` | `QUEUED → RUNNING` |
| `cancel_experiment` | `DRAFT`, `VALIDATED`, `QUEUED`, `RUNNING` → `CANCELLED` |
| `aggregate_experiment` | `RUNNING → COMPLETED`, `RUNNING → COMPLETED_WITH_WARNINGS`, `RUNNING → FAILED` |

The `DRAFT` spec replacement is a same-state content change with revision +1, not
a transition, so it does not add a thirteenth edge; from `VALIDATED` the same
operation uses the `VALIDATED → DRAFT` edge. Both land in `DRAFT` and invalidate
any prior validation result.

**Idempotent replay is evaluated before the terminal-immutability rule:** a
transition request whose `target_state` already equals the stored state and whose
`expected_revision` equals the stored revision returns the stored record
unchanged with no write, including for a terminal state; cancellation has its own
stronger replay identity (§9.1). Otherwise a terminal record accepts no
transition, no spec replacement and no enrichment, and any attempt is
`CORE.INVARIANT_VIOLATION`, not a concurrency conflict. **Expected conflict
result:** a compare-and-swap whose `expected_revision` does not match returns
`Failure` carrying `PERSISTENCE.CONCURRENCY_CONFLICT`; the loser rereads and
never overwrites the winner. Re-execution after any terminal state requires a new
experiment.

## 5. Engine-run lifecycle

`EngineRunState` has exactly twelve members and therefore 144 ordered state
pairs, of which exactly **23** are permitted. Every ordered pair not listed is
forbidden and fails atomically with `CORE.INVARIANT_VIOLATION`.

| State | Terminal | Permitted successors | State-governed fields that become present |
|---|---|---|---|
| `PENDING` | No | `VALIDATING`, `CANCELLED` | — |
| `VALIDATING` | No | `READY`, `NOT_APPLICABLE`, `UNAVAILABLE`, `FAILED`, `CANCELLED`, `TIMED_OUT` | — |
| `READY` | No | `STARTING`, `UNAVAILABLE`, `CANCELLED` | `availability_observation_id` |
| `STARTING` | No | `RUNNING`, `FAILED`, `UNAVAILABLE`, `CANCELLED`, `TIMED_OUT` | — |
| `RUNNING` | No | `SUCCEEDED`, `SUCCEEDED_WITH_WARNINGS`, `NOT_APPLICABLE`, `UNAVAILABLE`, `FAILED`, `CANCELLED`, `TIMED_OUT` | — |
| `SUCCEEDED` | Yes | none | — |
| `SUCCEEDED_WITH_WARNINGS` | Yes | none | — |
| `FAILED` | Yes | none | `primary_terminal_diagnostic_id` |
| `CANCELLED` | Yes | none | `primary_terminal_diagnostic_id` |
| `TIMED_OUT` | Yes | none | `primary_terminal_diagnostic_id` |
| `NOT_APPLICABLE` | Yes | none | `primary_terminal_diagnostic_id` |
| `UNAVAILABLE` | Yes | none | `primary_terminal_diagnostic_id`, `availability_observation_id` |

The five states carrying `primary_terminal_diagnostic_id` are the **non-success
terminal** states, the exact set §8.3 admits as a retry predecessor.

**Edge ownership.** Two edges are owned exclusively by linked operations and are
rejected by `transition_run` with `CORE.INVARIANT_VIOLATION`: `READY → STARTING`
belongs to `begin_linked_launch` and `STARTING → RUNNING` belongs to
`start_linked_run` (§6, §10.1). Every other permitted edge is produced by
`transition_run` when the trigger is a core decision — compatibility resolution,
an injected terminal result, cancellation without a live command — or by
`transition_invocation_and_run` when the trigger is a linked invocation's
terminal outcome (§6). All paths apply the same table and field shapes.

Immutable across every transition: `run_id`, `experiment_id`, `logical_slot_id`,
`attempt_number`, `attempt_token_hash`, `adapter`, `engine`, `request_hash`,
`predecessor_run_id`, `retry_reason`, `created_at_utc`. Revision increments once
per accepted transition, including the terminal one, after which the record is
frozen (§3.8). Idempotent replay and conflict results follow §4.

**Attempt creation contract.** `create_attempt` creates attempt 1 of a slot;
every later attempt is created only by `create_successor` (§8.5). Attempt
numbers are therefore monotonic within a slot, only the highest is the
**current attempt**, and predecessors remain immutable history that never
contributes to aggregation. In one unit of work the operation:

1. loads the experiment and the slot's existing attempt 1, if any;
2. **identical replay** — an existing attempt 1 whose `request_hash` equals the
   request's is returned unchanged; nothing is written and the experiment
   revision is not bumped again;
3. **divergent duplicate** — an existing attempt 1 with a different
   `request_hash` returns `PERSISTENCE.CONCURRENCY_CONFLICT`; nothing is written;
4. requires the experiment to be `QUEUED` or `RUNNING`, the slot to belong to
   the spec, and the frozen `slot_compatibility.outcome` not to be
   `NOT_APPLICABLE` (a preflight-incompatible slot never runs, §9.2), each
   otherwise `CORE.INVARIANT_VIOLATION`;
5. requires `expected_experiment_revision` to match, otherwise
   `PERSISTENCE.CONCURRENCY_CONFLICT`;
6. inserts the attempt **and** compare-and-swaps the experiment in the same unit
   of work — `QUEUED → RUNNING` for the experiment's first accepted attempt,
   otherwise a state-preserving `RUNNING` revision bump — so every accepted
   insertion contends on the experiment revision (§9.1). A lost swap rolls back
   the insertion, reloads the experiment once and re-applies steps 2–5 to the
   reloaded record; **an attempt row never becomes durable if the experiment
   swap fails.**

## 6. Command-invocation lifecycle

`CommandInvocationState` has exactly eight members and therefore 64 ordered state
pairs, of which exactly **10** are permitted: `PENDING → STARTING`,
`PENDING → CANCELLED`, `STARTING → RUNNING`, `STARTING → FAILED_TO_START`,
`STARTING → CANCELLED`, `STARTING → TIMED_OUT`, `RUNNING → EXITED`,
`RUNNING → CANCELLED`, `RUNNING → TIMED_OUT`, `RUNNING → PROTOCOL_FAILED`. Every
other ordered pair is forbidden and fails atomically with
`CORE.INVARIANT_VIOLATION`.

`cleanup_complete` (field 18) is false in every non-terminal state, so field 19
is absent there; both may change only through terminal write-once enrichment.

| State | Terminal | Required field shape (field numbers from §3.7) |
|---|---|---|
| `PENDING` | No | 11 false; 9, 12, 13, 14, 15, 16, 17, 20, 21 absent |
| `STARTING` | No | 9 and 12 present; 11 false; 13, 14, 15, 16, 17, 20, 21 absent |
| `RUNNING` | No | 11 true; 13 and 14 present; 15, 16, 17, 20 absent |
| `EXITED` | Yes | 11 true; 13, 14, 15, 16, 17 present; 21 optional, except required when 17 came from an unrecognized exit |
| `FAILED_TO_START` | Yes | 11 false; 15 and 21 present; 13, 14, 16, 17 absent |
| `CANCELLED` | Yes | 15 and 21 present; 9 and 12 present exactly when the predecessor was `STARTING` or `RUNNING`; 13 and 14 present exactly when the predecessor was `RUNNING`; 16 and 17 both present or both absent |
| `TIMED_OUT` | Yes | 9, 12, 15, 21 present; 13 and 14 present exactly when the predecessor was `RUNNING`; 16 and 17 both present or both absent |
| `PROTOCOL_FAILED` | Yes | 11 true; 13, 14, 15, 21 present; 16 and 17 both present or both absent |

Revision behavior: one increment per accepted transition and one per accepted
write-once enrichment. Terminal states are immutable except for **write-once
enrichment**, applied through a same-state revision compare-and-swap of exactly
four things: the co-occurring `(native_exit_value, process_exit_category)` pair;
`cleanup_complete` together with `cleanup_completed_at_utc`; additional
`diagnostic_ids`; and `stderr_artifact_id`. Enrichment never overwrites an
existing value, never alters `state` and never changes semantic outcome.

**Process exit category v1.** `ProcessExitCategory` has exactly eight members,
pinned in both the runtime test and the generated `command-invocation-record-v1`
`$defs`: `SUCCESS`, `VALIDATION_FAILURE`, `NOT_APPLICABLE`, `UNAVAILABLE`,
`RUNTIME_FAILURE`, `CANCELLED`, `TIMED_OUT`, `PROTOCOL_VIOLATION`. The pure
mapping `process_exit_category_for(native_exit_value)` in `domain/lifecycle.py`
is frozen: `0 → SUCCESS`, `10 → VALIDATION_FAILURE`, `20 → NOT_APPLICABLE`,
`30 → UNAVAILABLE`, `40 → RUNTIME_FAILURE`, `50 → CANCELLED`, `60 → TIMED_OUT`,
`70 → PROTOCOL_VIOLATION`; **every other native value maps to `RUNTIME_FAILURE`**
and additionally requires a `PROCESS.UNRECOGNIZED_PROCESS_EXIT` diagnostic as
field 21, which the service resolves through `DiagnosticReader.get` and rejects
with `CORE.INVARIANT_VIOLATION` if absent or carrying another code. The native
value stays stored separately in field 16; the category is a process fact and is
never the semantic result of the run (§1.4). There is no `UNKNOWN_AFTER_RESTART`
member: lost native exit facts can never be reconstructed into `EXITED`.

**Parent eligibility for `create_invocation`.** One exact matrix; a violation is
`CORE.INVARIANT_VIOLATION`.

| Command kind | `run_id` / `expected_run_revision` | Parent run state | Further checks |
|---|---|---|---|
| `DESCRIBE` | both absent | no parent run | timeout bounds only; creates are not deduplicated in Stage 5 (§1.4) |
| `VALIDATE` | both required | `VALIDATING` | run is the current attempt of its slot; experiment is `RUNNING`; slot and adapter identity agree with the run; expected run revision matches; no non-terminal `VALIDATE` for the run |
| `RUN` | both required | `READY` | run is the current attempt; experiment is `RUNNING`; slot and adapter identity agree; expected run revision matches; `request_hash` equals the run's `request_hash`; no non-terminal `VALIDATE` and no non-terminal `RUN` for the run |

**Identical-create replay and divergent-create conflict.** For `VALIDATE` and
`RUN`, a create whose `command_kind`, `run_id`, `adapter_name`,
`adapter_version`, `request_hash` and `timeout_seconds` all equal those of the
existing non-terminal same-kind invocation returns that invocation unchanged with
no write; any differing field returns `PERSISTENCE.CONCURRENCY_CONFLICT`, because
the existing invocation is the durable state the caller must reread.

**Linked operations.** Three edges couple a `RUN`-kind invocation to its run and
are committed as single units of work, or not at all:

| Operation | Invocation transition | Coupled run transition | Request |
|---|---|---|---|
| `begin_linked_launch` | `PENDING → STARTING` (deadline established) | `READY → STARTING` | `LinkedLaunchRequest` |
| `start_linked_run` | `STARTING → RUNNING` with `ProcessStartFacts` | `STARTING → RUNNING` | `LinkedStartRequest` |
| `transition_invocation_and_run` | a terminal outcome per the table below | per the table below | `CoupledTransitionRequest` |

**Process-start handoff by command kind.** `DESCRIBE`: `transition_invocation`
moves `STARTING → RUNNING` with `process_start` supplied; there is no run.
`VALIDATE`: `transition_invocation` moves `STARTING → RUNNING` with
`process_start`; the linked run stays `VALIDATING`. `RUN`: only
`start_linked_run` moves both aggregates. `transition_invocation` rejects a
`RUN`-kind `PENDING → STARTING` and `STARTING → RUNNING`, and `transition_run`
rejects `READY → STARTING` and `STARTING → RUNNING`, all with
`CORE.INVARIANT_VIOLATION`. A durable pair in which a `RUN` invocation is
`RUNNING` while its linked run is not, or the run is `RUNNING` while its active
`RUN` invocation is still `STARTING`, is `CORE.INVARIANT_VIOLATION`;
`is_mixed_running_pair` is the pure predicate for it. Because Windows may reuse a
PID, ownership requires the full `ProcessIdentity`; a durably `STARTING` record
has no trusted process identity.

**Coupled terminal transitions.** `DESCRIBE` has no run linkage.

| Invocation terminal state | Condition | Coupled engine-run transition |
|---|---|---|
| `FAILED_TO_START` | primary diagnostic category is `ADAPTER_UNAVAILABILITY` | → `UNAVAILABLE` |
| `FAILED_TO_START` | any other primary diagnostic category | → `FAILED` |
| `TIMED_OUT` | `command_kind` is `VALIDATE` | `VALIDATING → TIMED_OUT` |
| `TIMED_OUT` | `command_kind` is `RUN`, invocation was `STARTING` | `STARTING → TIMED_OUT` |
| `TIMED_OUT` | `command_kind` is `RUN`, invocation was `RUNNING` | `RUNNING → TIMED_OUT` |
| `CANCELLED` | any | → `CANCELLED` |
| `PROTOCOL_FAILED` | any | → `FAILED` |
| `EXITED` | any | **none**; `EXITED` is a process fact whose semantic mapping is Stage 6 |

## 7. Queue-time immutability

The `VALIDATED → QUEUED` transaction is the freeze point, reachable only through
`queue_experiment` (§4). It executes these checks in order and commits only if
all pass:

1. Stored state is `VALIDATED` and `expected_revision` matches.
2. `spec.retry_policy` canonical bytes equal those of the request's
   `config_derived_retry_policy`. Inequality is `CORE.IMMUTABLE_INPUT_MISMATCH`.
3. `spec.configuration_hash` equals the value recomputed from the request's
   `material_base_configuration_hash` and the spec (§3.5). Inequality is
   `CORE.IMMUTABLE_INPUT_MISMATCH`.
4. `spec_hash` equals `experiment_spec_hash(spec)`.
5. `selected_engine_slots` is non-empty and satisfies its ordinal, uniqueness and
   pairing rules (§3.5).
6. The request's `slot_compatibility` holds exactly one entry per selected slot,
   in slot order, each internally consistent (§3.6). Any mismatch is
   `CORE.IMMUTABLE_INPUT_MISMATCH`.

After the commit, `spec`, `spec_hash` and `slot_compatibility` are immutable for
the record's whole remaining life (§4). `replace_experiment_spec` is valid only
from `DRAFT` or `VALIDATED`; from any later state it is
`CORE.IMMUTABLE_INPUT_MISMATCH` — never a silent no-op and never a concurrency
conflict — so every material change requires a new `experiment_id` and a new
`spec_hash`. Timeout and cancellation policy freeze through the same mechanism:
the process timeout values sit inside the material base configuration hash that
feeds `configuration_hash`.

## 8. Retry policy and retry-decision flow

### 8.1 Created attempts

Gate 1 uses the authoritative number of persisted run attempts for the logical
slot, including the initial attempt, obtained from
`EngineRunRepository.count_attempts`. **A reserved but not yet created successor
is not an attempt.** A policy with `maximum_attempts_per_slot = 1` therefore
always denies.

### 8.2 The six gates

Evaluated over `RetryEvaluationSnapshot`, a domain value assembled by the service
from authoritative reads and never supplied by a caller. Besides the fields the
gates name, it carries `causal_closure: tuple[CausalClosureEntry, ...]`, where
`CausalClosureEntry` is a nested value object of exactly `category`
(`DiagnosticCategory`) and `error_code` (`ErrorCode`). The tuple holds the
primary terminal diagnostic and every diagnostic in its causal closure as
**whole pairs**, deduplicated as pairs and sorted by `(category, error_code)`.
Category and code are never carried as two independent tuples, because
independent sorting and deduplication destroy the correspondence between them.

| Gate | Condition to pass | Denial reason when it fails |
|---:|---|---|
| 1 | `created_attempt_count < retry_policy.maximum_attempts_per_slot` | `ATTEMPT_BUDGET_EXHAUSTED` |
| 2 | `predecessor_terminal_state` maps to a `RetryTerminalState` that is a member of `automatically_retry_terminal_states` | `TERMINAL_STATE_NOT_RETRYABLE` |
| 3 | the primary terminal `Diagnostic` has `retriable=true` | `PRIMARY_DIAGNOSTIC_NOT_RETRIABLE` |
| 4 | no `causal_closure` entry has a hard-blocking category | `HARD_BLOCKED_OUTCOME` |
| 5 | the experiment is not already terminal | `EXPERIMENT_TERMINAL` |
| 6 | for `UNAVAILABLE`, a qualifying fresh availability observation exists | `AVAILABILITY_OBSERVATION_NOT_FRESH` |

All six are ANDed, so the outcome is order-independent. The **recorded reason**
is selected by the fixed precedence `4, 1, 2, 3, 6, 5`, because a hard blocker is
unconditional and permanent while a budget bound is incidental. When gate 4
fails, `hard_block_error_code` is the `error_code` of the **first entry in the
sorted `causal_closure` whose `category` is hard-blocking**; category and code
are read from that same entry, so the recorded cause is deterministic and
provably paired. The specification's conflicting-decision condition is not part
of gate 5: it is handled entirely by §8.4 phases 1 and 3 and can never produce a
persisted denial.

**Hard-blocking categories are a closed partition of the twelve existing
`DiagnosticCategory` members**, derived from the specification's per-category
retry posture. Hard-blocking: `USER_CONFIGURATION`, `SCHEMA_VALIDATION`,
`COMPATIBILITY`, `PROTOCOL`, `CANCELLATION`, `ARTIFACT_CORRUPTION`,
`INTERNAL_INVARIANT`, `SECURITY`. Retry-permitting: `ADAPTER_UNAVAILABILITY`,
`ENGINE_RUNTIME`, `TIMEOUT`, `PERSISTENCE`. The two sets are asserted disjoint
and their union asserted equal to `set(DiagnosticCategory)`, so a future category
cannot arrive unclassified. The `NOT_APPLICABLE` and `CANCELLED` engine-run
terminal states are already excluded by gate 2, since neither maps to a
`RetryTerminalState`.

**Causal-closure ownership.** The application helper
`resolve_causal_closure(reader, primary_id)` in `experiments/retry.py` is the
**single owner** of traversal: it performs a breadth-first walk over
`causal_diagnostic_ids` through `DiagnosticReader.get_many`, with a visited set,
a depth bound of 32, a node bound of 256, deduplication and canonical
`(category, error_code)` ordering, and returns a `Failure` carrying
`CORE.INVARIANT_VIOLATION` on a cycle, a missing reference, or either bound.
`DiagnosticReader` offers primitive reads only, and neither the in-memory double
nor a future Stage 8 implementation may contain traversal logic. **A helper
`Failure` does not abort the operation:** the service substitutes the single entry
`(INTERNAL_INVARIANT, CORE.INVARIANT_VIOLATION)` as the closure, so gate 4 fails
and a durable `DENIED` row is persisted — fail-closed, and the slot still
resolves rather than leaving the experiment permanently non-terminal.

Gate 6's qualifying observation must satisfy all of: `available` is true; adapter
name, adapter version and executable hash equal those of the observation
referenced by the predecessor; `observed_at_utc` is strictly after the
predecessor's `updated_at_utc`; `expires_at_utc` is strictly after the single
clock instant; and its identifier differs from the predecessor's. When several
qualify, selection is deterministic: greatest `observed_at_utc`, ties broken by
lexicographically greatest `availability_observation_id`.

### 8.3 Preconditions

Two durable preconditions are checked before any candidate is constructed:

- **Predecessor eligibility.** The predecessor must be in one of the five
  non-success terminal states (§5). A non-terminal, `SUCCEEDED` or
  `SUCCEEDED_WITH_WARNINGS` predecessor returns a non-persisted `Failure`
  carrying `CORE.INVARIANT_VIOLATION` and writes nothing. This is what guarantees
  `RetryDecisionRecord` field 9 is always obtainable; §9.2's
  `NO_DECISION_REQUIRED` derivation is what keeps a legitimate caller from ever
  reaching this rejection.
- **Concurrency.** Experiment revision, predecessor revision and current-attempt
  status are authoritative preconditions checked at insert time. Movement in any
  of them produces a **non-persisted** `Failure` carrying
  `PERSISTENCE.CONCURRENCY_CONFLICT`. It is never converted into a permanent
  retry denial. **A failed experiment-revision compare-and-swap takes precedence
  over every gate result computed from the invalidated snapshot:** the
  transaction rolls back completely — no `RetryDecisionRecord`, no
  `retry_not_before_utc`, no successor reservation — and the prior durable
  winner is unchanged. A reload begins a new evaluation on a subsequent
  invocation; it never continues the rolled-back transaction. Only a stable,
  durably observed terminal experiment, read at the authoritative start of an
  evaluation, produces the persisted `EXPERIMENT_TERMINAL` denial of gate 5.

### 8.4 Three-phase decision flow

**Phase 1 — existing-row replay.** Load the `RetryDecisionRecord` by its unique
predecessor identity. A row whose `experiment_id`, `logical_slot_id` and
`predecessor_run_id` match the request is returned unchanged. There is **no clock
read, no gate evaluation, no delay recomputation and no new reservation.** A
stored row keyed to a different predecessor is `CORE.INVARIANT_VIOLATION`.

**Phase 2 — fresh candidate construction.** Reached only when no row exists.
Reload authoritative state; apply both §8.3 preconditions; read the `Clock`
exactly once; evaluate the six gates; and construct one complete immutable
`ALLOWED` or `DENIED` candidate. For `ALLOWED`, `retry_not_before_utc` is
`predecessor.updated_at_utc + retry_delay_seconds` — a function of durable facts
alone, never of the clock instant — and `reserved_successor_attempt_number` is
`created_attempt_count + 1`.

**Phase 3 — concurrent-insert reconciliation.** The insert is a single atomic
unique-key operation, committed in the same unit of work as the experiment
revision bump of §9.1 when the outcome is `ALLOWED`. If the experiment
compare-and-swap fails, the whole unit of work rolls back and the operation
returns the §8.3 concurrency `Failure`: no row is inserted, nothing is reserved,
and the next invocation begins a new evaluation from the reloaded state. If
instead the decision insert loses the unique-key race, reload the winner and
compare semantic projections (§3.9): an equal projection returns the winner
unchanged; a divergent projection returns `Failure` carrying
`RETRY.DECISION_CONFLICT`. **Neither row is modified in either case.**

### 8.5 Immutability and successor creation

`RetryDecisionRecord` is complete at insertion, has no field populated through
later enrichment, and is never updated. Successor creation is a separate
idempotent atomic operation using the stored reservation and the durable
`retry_not_before_utc`:

1. Load the decision; require `outcome = ALLOWED`.
2. If an attempt with `reserved_successor_attempt_number` already exists in the
   slot, return it unchanged. This is the exactly-one-successor guarantee and it
   holds across restart.
3. **Require the stored experiment state to be `RUNNING`.** A terminal experiment
   returns `Failure` carrying `CORE.INVARIANT_VIOLATION`, independently of
   revision agreement, so a caller that rereads after cancellation or terminal
   aggregation commits still cannot create a successor.
4. Require the clock instant to be at or after `retry_not_before_utc`; otherwise
   return `Failure` carrying `RETRY.NOT_BEFORE_NOT_REACHED` with that instant in
   its detail. Restart never restarts or recomputes the delay.
5. Re-check the experiment revision and that the predecessor is still the
   current attempt; movement is a non-persisted concurrency `Failure`.
6. Draw a new `run_id` and a new `attempt_token` from `IdentitySource`, compute
   `attempt_token_hash`, and insert the successor with `predecessor_run_id`,
   `retry_reason`, the caller-supplied `request_hash`, and the adapter and engine
   copied from the predecessor, bumping the experiment revision in the same unit
   of work. Identity is drawn only at this point, so replay consumes nothing. A
   lost experiment swap rolls back the insertion, reloads once and re-applies
   steps 1–5 to the reloaded record (§9.5).

### 8.6 Stage 5 codes

**Diagnostic codes**, which inhabit a `Diagnostic` inside a `Failure` and
therefore carry a category. Stage 5 introduces exactly three and reuses three:

| Code | New | Category | Retriable | Meaning |
|---|---|---|---:|---|
| `RETRY.DECISION_CONFLICT` | yes | `INTERNAL_INVARIANT` | false | Two decision candidates for one predecessor diverge semantically |
| `RETRY.NOT_BEFORE_NOT_REACHED` | yes | `PERSISTENCE` | true | The durable retry delay has not elapsed; the detail carries `retry_not_before_utc` |
| `PROCESS.UNRECOGNIZED_PROCESS_EXIT` | yes | `ENGINE_RUNTIME` | true | A native exit outside the eight mapped values; mandatory on such an `EXITED` invocation (§6) |
| `PERSISTENCE.CONCURRENCY_CONFLICT` | no | `PERSISTENCE` | true | Compare-and-swap loss, precondition movement, divergent create, divergent cancellation replay — and nothing else |
| `CORE.INVARIANT_VIOLATION` | no | `INTERNAL_INVARIANT` | false | Forbidden transition or edge, impossible aggregate state, ineligible parent or predecessor, terminal-experiment successor, degenerate closure |
| `CORE.IMMUTABLE_INPUT_MISMATCH` | no | `INTERNAL_INVARIANT` | false | Frozen-input violation |

`RETRY.NOT_BEFORE_NOT_REACHED` is distinct from
`PERSISTENCE.CONCURRENCY_CONFLICT` because the latter's normative remedy is state
reload, which can never satisfy a not-yet-elapsed delay; only clock advance can.
Its category is retry-permitting, so it can never hard-block a later gate 4.

**Aggregation reason codes**, which label
`ExperimentAggregationResult.reason_codes` and never inhabit a `Diagnostic`, so
they carry no `DiagnosticCategory`. The mapping is closed and total over a slot's
**effective terminal state** (§9.2):

| Effective terminal state or condition | Reason code |
|---|---|
| `FAILED` | `EXPERIMENT.SLOT_FAILED` |
| `TIMED_OUT` | `EXPERIMENT.SLOT_TIMED_OUT` |
| `UNAVAILABLE` | `EXPERIMENT.SLOT_UNAVAILABLE` |
| `CANCELLED` | `EXPERIMENT.SLOT_CANCELLED` |
| `SUCCEEDED_WITH_WARNINGS` | `EXPERIMENT.SLOT_SUCCEEDED_WITH_WARNINGS` |
| `NOT_APPLICABLE` and late | `COMPAT.LATE_NOT_APPLICABLE` |
| `NOT_APPLICABLE` and not late | none |
| `SUCCEEDED` | none |
| frozen outcome `SUPPORTED_WITH_APPROXIMATION`, in any state | `EXPERIMENT.SLOT_USED_APPROXIMATION` |
| every slot effectively `NOT_APPLICABLE`, at experiment level | `EXPERIMENT.NO_APPLICABLE_ENGINE` |

`EXPERIMENT.SLOT_TIMED_OUT` is deliberately **not** one of the specification's
four command-specific timeout codes: an aggregation reason names which slot
outcome contributed, while which deadline fired is recorded on that run's primary
terminal diagnostic. The same rule is why the cancelled row uses
`EXPERIMENT.SLOT_CANCELLED` rather than `PROCESS.CANCELLED`.

## 9. Cancellation and terminal aggregation

### 9.1 Cancellation and the coordination mechanism

**The experiment `revision` is the single mutual-exclusion primitive.** The
`ALLOWED` branch of `evaluate_retry`, every accepted `create_attempt` insertion
(§5) and `create_successor` each commit a compare-and-swap on the experiment
that increments `revision` and refreshes `updated_at_utc` — without changing
`state`, except the first attempt's `QUEUED → RUNNING` — so attempt creation,
retry scheduling, successor creation, experiment cancellation and terminal
aggregation all contend on the same value and exactly one of them can win at any
instant. If cancellation or terminal aggregation commits first, no attempt or
successor may be created; if an attempt, retry or successor transaction commits
first, the loser reloads and observes the new state (§9.5). A `DENIED` decision
performs no experiment write, because it resolves the slot rather than keeping it
alive.

`cancel_experiment(request: CancelExperimentRequest, *, unit_of_work: UnitOfWork,
clock: Clock) -> Result[ExperimentRecord]` executes, in order:

1. Load the experiment.
2. **Replay recognition.** If the stored state is `CANCELLED` and the stored
   `cancellation_correlation_id` equals the request's `correlation_id`, return
   the stored record unchanged — the prior identical outcome — regardless of
   `expected_revision`. If the state is `CANCELLED` and the correlation
   identifiers differ, return `PERSISTENCE.CONCURRENCY_CONFLICT`: an arbitrary
   already-cancelled record is not replay evidence.
3. If the stored state is any other terminal state, return
   `CORE.INVARIANT_VIOLATION`.
4. Verify `expected_revision`; movement is `PERSISTENCE.CONCURRENCY_CONFLICT`.
5. Compare-and-swap to `CANCELLED`, writing `cancellation_correlation_id`,
   `updated_at_utc` from the clock and revision +1. A lost swap reloads the
   experiment once and re-applies steps 2–4 to the reloaded record, so the
   public result follows this same contract (§9.5).

The durable correlation identifier is therefore how prior transition identity is
recognized: it is written exactly once, by the winning cancellation, and it is
immutable with the terminal record.

### 9.2 Selected slots, effective terminal state and readiness

Aggregation is **selected-slot based, not attempt-presence based**. For every
selected slot, `build_aggregation_input` reads the frozen `slot_compatibility`
entry, the current attempt if any, and the decision row if any, and derives:

- **`retry_status`**, total over every slot: `NO_DECISION_REQUIRED` when there is
  no attempt, or the current attempt is non-terminal, is a success, or its
  terminal state maps to no `RetryTerminalState`; `DECISION_UNRESOLVED` when it
  does map and no decision row exists; `ALLOWED_SUCCESSOR_PENDING` when an
  `ALLOWED` row exists and no attempt bears its reserved number; `DENIED` when a
  `DENIED` row exists. A created successor is itself the current attempt, so an
  "allowed successor created" status is not a reachable status of a current
  attempt.
- **Effective terminal state**: the current attempt's state when an attempt
  exists and is terminal; otherwise, with **no attempt**, `NOT_APPLICABLE` when
  the frozen outcome is `NOT_APPLICABLE`, `UNAVAILABLE` when the frozen outcome
  is `UNAVAILABLE`, and **unresolved** when the frozen outcome is `SUPPORTED` or
  `SUPPORTED_WITH_APPROXIMATION` — such a slot has work outstanding and blocks
  terminal aggregation. A zero-attempt `UNAVAILABLE` slot has no retry decision
  to wait for; a refresh is expressed by creating an attempt, after which the
  attempt governs.
- **`late_not_applicable`**: the effective terminal state is `NOT_APPLICABLE`
  while the frozen outcome is not, so preflight did not predict it.
- **`used_approximation`**: the frozen outcome is `SUPPORTED_WITH_APPROXIMATION`.

Terminal aggregation is attempted only when every selected slot has an effective
terminal state **and** every slot's `retry_status` is `NO_DECISION_REQUIRED` or
`DENIED`. Only the current attempt of a slot ever contributes; predecessors are
history.

### 9.3 The deterministic aggregation table

`classify_experiment_outcome(input: ExperimentAggregationInput) -> ExperimentAggregationResult`
is pure and total over the declared input alone. Let `S` be the slots whose
effective terminal state is `SUCCEEDED` or `SUCCEEDED_WITH_WARNINGS`, and `N`
those whose effective terminal state is `NOT_APPLICABLE`. Rows are evaluated top
to bottom; the first match wins. Reason codes come from §8.6's closed mapping.

| # | Condition | Verdict | Reason codes contributed |
|---:|---|---|---|
| 1 | any slot has a non-terminal current attempt | `NOT_YET_TERMINAL` | none |
| 2 | any slot has no attempt and a frozen outcome of `SUPPORTED` or `SUPPORTED_WITH_APPROXIMATION` | `NOT_YET_TERMINAL` | none |
| 3 | any slot is `DECISION_UNRESOLVED` or `ALLOWED_SUCCESSOR_PENDING` | `NOT_YET_TERMINAL` | none |
| 4 | `N` is every slot | `FAILED` | `EXPERIMENT.NO_APPLICABLE_ENGINE`, plus `COMPAT.LATE_NOT_APPLICABLE` when any member of `N` is late |
| 5 | `S` is empty and some slot is effectively `FAILED`, `TIMED_OUT` or `UNAVAILABLE` | `FAILED` | the §8.6 code of each contributing slot |
| 6 | `S` is empty and some slot is effectively `CANCELLED` | `FAILED` | `EXPERIMENT.SLOT_CANCELLED` |
| 7 | `S` is non-empty, every member of `S` is `SUCCEEDED`, no slot used an approximation, every member of `N` is not late, and no other slot exists | `COMPLETED` | none |
| 8 | otherwise | `COMPLETED_WITH_WARNINGS` | the §8.6 code of every contributing slot and condition |

Rows 5 and 6 complete the specification's partition, which names failure, timeout
and unavailability but not a cancelled child attempt under a non-cancelled
experiment; a cancelled child yields no usable result, so it is treated as
failure when nothing succeeded and as a warning otherwise. A `DENIED` decision
lets its terminal predecessor contribute normally through rows 4–8. No averaging,
majority voting or synthetic return exists anywhere in the classifier.

### 9.4 The aggregation transaction

`aggregate_experiment` returns `Result[ExperimentAggregationResult]` in every
case. It reads the experiment first. **If the stored state is already terminal it
returns idempotently without invoking the classifier**, with `verdict` equal to
that terminal state's member of `AggregationVerdict` and empty `reason_codes`;
this is why the stored state is not a classifier input and why `CANCELLED` is a
verdict member. Otherwise it requires the state to be `RUNNING`
(`CORE.INVARIANT_VIOLATION` for `DRAFT`, `VALIDATED` or `QUEUED`, none of which
has slots to aggregate), builds `ExperimentAggregationInput` from authoritative
reads, invokes the pure classifier, and — for any verdict other than
`NOT_YET_TERMINAL` — compare-and-swaps the experiment to the mapped terminal
state. Losing that swap mutates nothing, reloads the experiment once and
re-applies this section to the reloaded record: a now-terminal experiment yields
the idempotent verdict above, and a still-`RUNNING` experiment at a newer
revision yields `PERSISTENCE.CONCURRENCY_CONFLICT` (§9.5).

### 9.5 Pairwise contention table

Every write to the experiment contends on `revision`, and every losing operation
follows one rule: **the lost internal compare-and-swap is never the public
result; the operation reloads the experiment exactly once and re-applies its own
precondition sequence to the reloaded record.** The public `Result` therefore
comes from each operation's existing contract, never from a uniform loser code.

A three-way race among retry scheduling, cancellation and terminal aggregation
is **not constructible**: a fresh `ALLOWED` retry needs an unresolved slot, which
makes aggregation return `NOT_YET_TERMINAL` without a write, and once aggregation
is write-ready any retry is a phase-1 replay or a non-bumping `DENIED`. The
constructible races are pairwise. Every row starts from an experiment at
`RUNNING`, revision `N`, both operations having read revision `N`; the winner
commits `N → N+1`, the loser leaves no partial write.

| # | Shared start (why both are eligible) | Winner and atomic write | Loser: lost swap, single reload, public `Result` |
|---:|---|---|---|
| 1 | every slot has an effective terminal state and no unresolved decision (§9.2), so aggregation is write-ready; cancellation is permitted from `RUNNING` (§4) | `aggregate_experiment`: `RUNNING →` mapped terminal state | `cancel_experiment`: reload shows a terminal non-cancelled record; §9.1 step 3 → `CORE.INVARIANT_VIOLATION` |
| 2 | as row 1 | `cancel_experiment`: `RUNNING → CANCELLED` with `cancellation_correlation_id` | `aggregate_experiment`: reload shows `CANCELLED`; §9.4 pre-classifier → `Success` with verdict `CANCELLED` and no reason codes |
| 3 | slot A holds an `ALLOWED` decision whose `retry_not_before_utc` has passed, its predecessor is the current attempt and no successor exists, so `create_successor` passes §8.5 steps 1–5; cancellation is permitted | `cancel_experiment` | `create_successor`: insertion rolled back; reload shows `CANCELLED`; §8.5 step 3 → `CORE.INVARIANT_VIOLATION`; no successor durable |
| 4 | as row 3 | `create_successor`: successor inserted, state-preserving bump | `cancel_experiment`: reload shows `RUNNING` at `N+1`; §9.1 step 4 → `PERSISTENCE.CONCURRENCY_CONFLICT`; the caller may cancel again at `N+1` |
| 5 | slot A has its attempt 1; slot B has no attempt and a frozen `SUPPORTED` outcome, so `create_attempt` for B passes §5 steps 2–5; cancellation is permitted | `create_attempt`: attempt 1 of B inserted, state-preserving bump | `cancel_experiment`: reload shows `RUNNING` at `N+1`; §9.1 step 4 → `PERSISTENCE.CONCURRENCY_CONFLICT` |
| 6 | as row 5 | `cancel_experiment` | `create_attempt`: insertion rolled back; reload shows `CANCELLED`; §5 step 4 → `CORE.INVARIANT_VIOLATION`; no attempt durable |
| 7 | slot A's current attempt is terminal `SUCCEEDED`; slot B has no attempt and a frozen `UNAVAILABLE` outcome, so B is effectively terminal (§9.2) and aggregation is write-ready, while `create_attempt` for B is permitted | `create_attempt`: attempt 1 of B inserted, state-preserving bump | `aggregate_experiment`: reload shows `RUNNING` at `N+1`; §9.4 → `PERSISTENCE.CONCURRENCY_CONFLICT`; a re-issued aggregation then meets B's `PENDING` attempt and returns `NOT_YET_TERMINAL` |
| 8 | as row 7 | `aggregate_experiment`: `RUNNING →` mapped terminal state | `create_attempt`: insertion rolled back; reload shows a terminal record; §5 step 4 → `CORE.INVARIANT_VIOLATION`; no attempt durable |
| 9 | slot A's current attempt is terminal `FAILED` with a retriable primary diagnostic and no decision row, so `evaluate_retry` reaches phase 2 with every gate passing; cancellation is permitted | `evaluate_retry`: `ALLOWED` row inserted, state-preserving bump | `cancel_experiment`: reload shows `RUNNING` at `N+1`; §9.1 step 4 → `PERSISTENCE.CONCURRENCY_CONFLICT` |
| 10 | as row 9 | `cancel_experiment` | `evaluate_retry`: decision insert and bump rolled back together; reload shows the revision moved; §8.3 → non-persisted `PERSISTENCE.CONCURRENCY_CONFLICT` — no decision row, no `retry_not_before_utc`, no reservation, winner unchanged. A **subsequent** `evaluate_retry` invocation reads the now-stable terminal experiment, fails gate 5 and persists `DENIED` with `EXPERIMENT_TERMINAL`, reserving no successor and rewriting no terminal state |

Rows 1–2, 3–4, 5–6, 7–8 and 9–10 are the two orderings of one pair each. The
three loser contracts the table depends on — a stale cancel after terminal
aggregation is `CORE.INVARIANT_VIOLATION`, a stale aggregate after cancellation
is the idempotent `CANCELLED` verdict, a stale `create_successor` after a
terminal winner is `CORE.INVARIANT_VIOLATION` — are those operations' own
contracts in §9.1, §9.4 and §8.5, not race-specific rules.

## 10. Repository and unit-of-work protocols

All protocols are `typing.Protocol` classes with synchronous methods returning
`Result[...]`, because these are short local transactions. An application service
owns the unit of work; a repository never commits on its own.

`crypto_lab/experiments/ports.py`:

| Protocol | Operations |
|---|---|
| `ExperimentRepository` | `get(experiment_id)`, `add(record)`, `compare_and_swap(expected_revision, replacement)` |
| `EngineRunRepository` | `get(run_id)`, `add_attempt(record)`, `compare_and_swap(expected_revision, replacement)`, `count_attempts(experiment_id, logical_slot_id)`, `latest_attempt(experiment_id, logical_slot_id)`, `get_by_attempt_number(experiment_id, logical_slot_id, attempt_number)` |
| `RetryDecisionRepository` | `get_by_predecessor(logical_slot_id, predecessor_run_id)`, `insert_if_absent(record) -> Result[RetryDecisionInsertOutcome]` |
| `RuntimeAvailabilityObservationReader` | `get(observation_id)`, `list_for_adapter(adapter_name, adapter_version, executable_hash)` |
| `DiagnosticReader` | `get(diagnostic_id)`, `get_many(diagnostic_ids)` — primitive reads only, no traversal |
| `UnitOfWork` | `begin() -> UnitOfWork`, `commit() -> Result[None]`, `rollback() -> None` |

`crypto_lab/adapters/ports.py`: `CommandInvocationRepository` with
`get(invocation_id)`, `add(record)`,
`compare_and_swap(expected_revision, replacement)` and
`list_for_run(run_id, command_kind)`.

`RetryDecisionInsertOutcome` is a nested value object with `inserted: bool` and
`record: RetryDecisionRecord`, where `record` is always the stored winner.
`latest_attempt` returns `Result` of `EngineRunRecord | MISSING` so a zero-attempt
slot is an ordinary answer, not a failure. `list_for_run`, `get_many` and the
three `EngineRunRepository` query operations are declared extensions beyond the
specification's operation list; each exists because a named Stage 5 rule reads it
(§6, §8.1, §8.2, §9.2).

### 10.1 Atomic operations

Each row is one unit of work. Movement in any read-set revision aborts the row.
Exactly one §3.11 request corresponds to each row.

| Operation | Read set | Validation set | Write set |
|---|---|---|---|
| `create_experiment` | none | draft shape, slot rules | insert `ExperimentRecord` at `DRAFT`, revision 0 |
| `replace_experiment_spec` | experiment | state is `DRAFT` or `VALIDATED`, expected revision, draft shape | replace experiment at `DRAFT`, revision +1 |
| `transition_experiment` | experiment | §4 edge ownership, expected revision | replace experiment, revision +1 |
| `queue_experiment` | experiment | §7 checks 1–6 | replace experiment at `QUEUED` with frozen `slot_compatibility`, revision +1 |
| `cancel_experiment` | experiment | §9.1 steps 2–4 | replace experiment at `CANCELLED` with `cancellation_correlation_id`, revision +1 |
| `create_attempt` | experiment, the slot's existing attempt 1 if any | §5 contract steps 2–5: identical replay, divergent duplicate, experiment `QUEUED` or `RUNNING`, slot in spec, frozen outcome not `NOT_APPLICABLE`, expected experiment revision | insert attempt 1 **and** replace the experiment in the same unit of work — `QUEUED → RUNNING` for the first accepted attempt, otherwise a state-preserving revision bump; nothing on identical replay; both rolled back on a lost swap |
| `transition_run` | run | §5 table and edge ownership, expected revision, field shape, carry-forward rule | replace run, revision +1 |
| `create_invocation` | run and experiment when linked, existing invocations for the run | §6 parent-eligibility matrix, timeout bounds, identical-create replay | insert `CommandInvocationRecord`, or return the identical existing one |
| `begin_linked_launch` | invocation, run | `RUN` kind, invocation `PENDING`, run `READY`, linkage, both expected revisions | replace invocation at `STARTING` (deadline, launch instant) and run at `STARTING`, each revision +1 |
| `transition_invocation` | invocation; the primary diagnostic when the exit is unrecognized | §6 table and field shape, expected revision, `process_start` exactly on `STARTING → RUNNING`; rejects `RUN`-kind `PENDING → STARTING` and `STARTING → RUNNING` | replace invocation, revision +1 |
| `start_linked_run` | invocation, run | `RUN` kind, both `STARTING`, linkage, both expected revisions, `process_start` supplied | replace invocation at `RUNNING` with process facts and run at `RUNNING`, each revision +1 |
| `enrich_invocation` | invocation | terminal state, write-once, no overwrite | replace invocation at the same state, revision +1 |
| `transition_invocation_and_run` | invocation, run | both §6 tables, the coupled terminal mapping, both expected revisions | replace both, each revision +1 |
| `evaluate_retry` | decision row, experiment, predecessor, attempt count, current attempt, diagnostic closure, availability observations | §8.3 preconditions, §8.2 gates | insert one `RetryDecisionRecord` and, when the outcome is `ALLOWED`, replace the experiment with revision +1 and no state change; or nothing |
| `create_successor` | decision, experiment, predecessor, attempt by reserved number | §8.5 steps 1–5 | insert successor `EngineRunRecord`; replace experiment revision +1 without state change |
| `aggregate_experiment` | experiment with `slot_compatibility`, each slot's current attempt or its absence, each decision row | §9.4 pre-classifier step, §9.2 readiness, §9.3 classifier | replace experiment at the mapped terminal state, revision +1 |

## 11. Deterministic in-memory doubles

Implementations live in `tests/doubles/` and are never imported by `crypto_lab`,
because the specification requires that `persistence` implement the protocols and
that the application not import concrete implementations, and `persistence` is
Stage 8-owned.

| Double | Behavior |
|---|---|
| `FixedClock` | Returns a caller-set UTC instant; `advance(seconds)` moves it forward; never reads the wall clock |
| `SequentialIdentitySource` | Derives each identifier from a fixed seed and a per-kind counter through the existing UUID4-shaping helper; identical construction order yields identical identifiers |
| `InMemoryExperimentRepository` | Dict keyed by `experiment_id`; `compare_and_swap` returns `PERSISTENCE.CONCURRENCY_CONFLICT` on revision mismatch |
| `InMemoryEngineRunRepository` | Dict keyed by `run_id` with a `(experiment_id, logical_slot_id, attempt_number)` uniqueness index; `latest_attempt` returns `MISSING` for an unattempted slot |
| `InMemoryRetryDecisionRepository` | Dict keyed by `(logical_slot_id, predecessor_run_id)`; `insert_if_absent` is atomic and supports an injected pre-insert hook so a concurrent winner can be simulated deterministically |
| `InMemoryCommandInvocationRepository` | Dict keyed by `invocation_id` with a `(run_id, command_kind)` non-terminal index |
| `InMemoryAvailabilityObservationReader` | Ordered store; `list_for_adapter` returns a deterministically sorted tuple |
| `InMemoryDiagnosticReader` | Ordered store; `get` and `get_many` primitive lookups only — no traversal |
| `InMemoryUnitOfWork` | Snapshot-and-restore transaction over every registered store; `rollback` restores the entry snapshot; `commit` is all-or-nothing |

Concurrency is simulated deterministically through the injected hooks and
explicit revision manipulation. No thread, no sleep, no wall-clock read and no
random source appears in any double or test.

**Import plumbing has one permitted mechanism and no fallback.**
`tests/safety/test_stage3_boundaries.py` pins
`pytest_options["pythonpath"] == ["scripts"]` and no task may edit it, so
`pyproject.toml` is untouched. Pytest's default prepend mode resolves
`tests/conftest.py` to a base directory of `tests` because `tests/__init__.py`
does not exist, prepending `<root>/tests` to `sys.path` before any test module
loads, so `import doubles.experiments` resolves; mypy walks up identically and
`[tool.ruff.lint.per-file-ignores]` already covers `tests/**/*.py`. Task 6's
first RED step probes that import and, **if it fails, stops and escalates rather
than editing the pinned option.**

## 12. Task/file decomposition

Nine vertical tasks. No task depends on a file created by a later task. Each is
test-first: focused RED, minimum implementation, focused GREEN, then broader
verification. Focused runs use the launcher `pytest-focused` profile with
`-o addopts=`, which disables coverage and is diagnostic only (§13.1); broader
verification uses the unmodified `scripts/verify.ps1` operations named per task.
**Every task that creates a module under `src/crypto_lab` or first defines a
deferred name also edits `tests/safety/test_stage3_boundaries.py` and
`tests/unit/test_package_layout.py` exactly as §2.7 tabulates; those two files
are therefore owned by Tasks 1–8 and are not repeated in each task's list, and
each such task's Focused RED includes the §2.7 guard expectations for its own
paths and names.**

### Task 1 — Stage 5 model and identifier foundations

**Owned files.** New `src/crypto_lab/domain/lifecycle.py`,
`src/crypto_lab/domain/ports.py`, `src/crypto_lab/domain/compatibility.py`,
`tests/unit/domain/test_lifecycle_tables.py`,
`tests/unit/domain/test_domain_ports.py`. Edited
`src/crypto_lab/domain/identifiers.py`, `src/crypto_lab/domain/hashing.py`,
`src/crypto_lab/domain/__init__.py`, `src/crypto_lab/configuration/models.py`,
`src/crypto_lab/configuration/__init__.py`,
`src/crypto_lab/capabilities/models.py` (re-export only),
`tests/unit/domain/test_identifiers.py`, `tests/unit/test_schema_registry.py`
(the new `_STAGE4_SHA256` block only, per §2.7), and the two §2.7 guard files.

**Consumed interfaces.** `CanonicalModel`, `exact_string_schema`,
`validate_prefixed_uuid4`, `HashingProfile`, `RetryTerminalState`,
`CompatibilityOutcome`.

**Produced interfaces.** `LogicalSlotId`, `AttemptToken`, `CorrelationId`;
`ExperimentState`, `EngineRunState`, `CommandInvocationState`, `CommandKind`,
`ProcessExitCategory` with `process_exit_category_for`; relocated
`RetryTerminalState` and `CompatibilityOutcome`; the three transition tables with
`is_allowed_transition`, `permitted_successors` and terminal-state sets; `Clock`
and `IdentitySource`; two `HashingProfile` members. Releases `Clock`,
`CommandKind`, `CommandInvocationState` (deferred count 62); appends three paths
(allowlist 54).

**Focused RED.** Assert 8/64/12, 12/144/23 and 8/64/10 by arithmetic over the
enums and tables; assert every forbidden pair is rejected by complement; assert
the eight `ProcessExitCategory` members and the frozen native-exit mapping,
including that every value outside the eight maps to `RUNTIME_FAILURE`; add the
nine-entry `_STAGE4_SHA256` block so §2.5's byte-identity gate covers all 20
existing schemas before any other Stage 5 change lands, and assert entries 5 and
17 specifically after both relocations; and the §2.7 guard expectations — the
source-file set-equality test failing until exactly the three new paths are
appended, the sixty-five test failing until exactly the three names are removed
and the count reads 62, the per-name absence guard passing for every remaining
name, and the representative-mutation list holding seven live names after
`RunEvent` replaces `CommandInvocationState`.
**Minimum implementation.** The enums, tables, mapping, identifier annotations,
protocol classes and hashing members, plus the two relocations with
`RetryTerminalState` carrying no docstring and `CompatibilityOutcome` carrying
its byte-identical one.
**Focused GREEN.** `tests\unit\domain`, `tests\unit\configuration`,
`tests\unit\capabilities`, `tests\unit\test_schema_registry.py`, `tests\safety`,
`tests\unit\test_package_layout.py`.
**Broader verification.** `ruff-check-all`, `mypy-all`, `schema-generate-check`.
**Commit message.** `feat: add stage 5 lifecycle enums, tables and ports`

### Task 2 — Experiment lifecycle and queue-time immutability

**Owned files.** New `src/crypto_lab/domain/experiment.py`,
`src/crypto_lab/domain/retry.py` (created here with `RetryPolicy` only and
extended in Task 5), `src/crypto_lab/configuration/retry_policy.py`,
`tests/unit/domain/test_experiment_records.py`,
`tests/unit/configuration/test_retry_policy_projection.py`,
`tests/property/test_experiment_spec_hash.py`. Edited
`src/crypto_lab/domain/__init__.py`,
`src/crypto_lab/configuration/__init__.py`, and the two §2.7 guard files.

**Consumed interfaces.** Task 1 output; `Money`, `ComparisonLevel`,
`NonNegativeDecimal`, `CalendarValidUtcDateTime`, `profile_hash`, `RetryConfig`,
`ApproximationId`, `AvailabilityObservationId`.

**Produced interfaces.** `RetryPolicy`; `AdapterIdentity`, `EngineIdentity`,
`SelectedEngineSlot`, `FeeAssumptions`, `SlippageAssumptions`,
`ExecutionAssumptions`, `ExperimentSpecDraft`, `ExperimentSpec`,
`SlotCompatibility`, `ExperimentRecord`; `experiment_configuration_hash`,
`experiment_spec_hash` and
`build_experiment_spec(draft, material_base_configuration_hash, created_at_utc)`;
`assert_queue_freeze` as a pure predicate; `retry_policy_from_config`. Releases
`RetryPolicy`, `ExperimentSpec`, `ExperimentRecord` (count 59); appends three
paths (allowlist 57).

**Focused RED.** Reject an unknown field, a naive timestamp, a float amount, a
non-positive starting balance, duplicate slot ordinals, a non-ascending ordinal
sequence, a duplicate adapter/engine pair, a `spec_hash` disagreeing with the
recomputed value, a `SlippageAssumptions` carrying `basis_points` under model
`NONE` or omitting it under `FIXED_BASIS_POINTS`, a `SlotCompatibility` with
approximation identifiers under any outcome but `SUPPORTED_WITH_APPROXIMATION` or
without them under it, `slot_compatibility` present before `QUEUED` or absent
after, and `cancellation_correlation_id` present outside `CANCELLED`; prove the
configuration hash is insensitive to `schema_version`, `created_at_utc` and
`configuration_hash` and sensitive to every other spec field and to
`material_base_configuration_hash`; prove every material input changes
`spec_hash`; prove the config projection round-trips and normalizes duplicate
and out-of-order retry states.
**Minimum implementation.** The models, both hash functions, the builder, the
freeze predicate and the projection.
**Focused GREEN.** `tests\unit\domain`, `tests\unit\configuration`,
`tests\property`, `tests\safety`.
**Broader verification.** `ruff-check-all`, `mypy-all`.
**Commit message.** `feat: add experiment spec, record and queue freeze rules`

### Task 3 — Command-invocation lifecycle

**Owned files.** New `src/crypto_lab/domain/command_invocation.py`,
`tests/unit/domain/test_command_invocation_record.py`. Edited
`src/crypto_lab/domain/__init__.py` and the two §2.7 guard files.

**Consumed interfaces.** Tasks 1–2 output; `DiagnosticId`, `ArtifactId`,
`crypto_lab.domain.descriptors.BoundedText`, `ExecutablePath`, `Sha256`.

**Produced interfaces.** `ProcessIdentity`, `ProcessStartFacts`,
`CommandInvocationRecord`, the §6 state-governed field-shape validator, the
write-once enrichment predicate, the parent-eligibility matrix as a pure
function, and `command_timeout_bounds(command_kind)`. Releases
`CommandInvocationRecord` (count 58); appends one path (allowlist 58).

**Focused RED.** Each of the eight states asserted for its exact required and
prohibited field set, including `cleanup_complete = true` rejected in all three
non-terminal states; `run_id` absent for `DESCRIBE` and required otherwise;
`timeout_seconds` rejected outside its command-kind bounds; field 17 rejected
when it disagrees with `process_exit_category_for(field 16)`; an `EXITED` record
with an unrecognized native exit rejected without `primary_diagnostic_id`;
`cleanup_completed_at_utc` present if and only if `cleanup_complete`;
`primary_diagnostic_id` required in every terminal state except `EXITED` and
required to be a member of `diagnostic_ids`; the `CANCELLED` and `TIMED_OUT`
predecessor-dependent shapes for fields 9, 12, 13 and 14; the parent-eligibility
matrix asserted for every command kind against every parent state; and
enrichment rejected when it would overwrite an existing value or change `state`.
**Minimum implementation.** The records, the shape validator, the eligibility
function and the enrichment predicate.
**Focused GREEN.** `tests\unit\domain`, `tests\safety`.
**Broader verification.** `ruff-check-all`, `mypy-all`.
**Commit message.** `feat: add command invocation record and field shape rules`

### Task 4 — Engine-run lifecycle

**Owned files.** New `src/crypto_lab/domain/engine_run.py`,
`tests/unit/domain/test_engine_run_record.py`,
`tests/property/test_lifecycle_transitions.py`. Edited
`src/crypto_lab/domain/__init__.py` and the two §2.7 guard files.

**Consumed interfaces.** Tasks 1–3 output.

**Produced interfaces.** `EngineRunRecord`, `AttemptTokenMaterial`, the §5
state-governed field validator and edge-ownership predicate, the
terminal-immutability predicate, the §6 coupled terminal mapping as a pure total
function, and `is_mixed_running_pair`. Releases `EngineRunRecord` (count 57);
appends one path (allowlist 59).

**Focused RED.** Predecessor and retry-reason fields present if and only if
`attempt_number > 1`; `primary_terminal_diagnostic_id` present exactly in the
five non-success terminal states; `availability_observation_id` governed by state
and carried forward unchanged when the request omits it;
`finalization_deadline_utc` rejected throughout Stage 5; a terminal record
rejecting every field change including a revision bump; `READY → STARTING` and
`STARTING → RUNNING` rejected by the generic edge predicate; the coupled terminal
mapping asserted for every `(invocation terminal state, command kind, predecessor
state)` triple, including the `EXITED` row that produces no run transition and
every `DESCRIBE` case that produces no linkage; both mixed-pair orientations
detected by `is_mixed_running_pair`. Property tests generate arbitrary ordered
state pairs for all three machines and assert acceptance exactly on the tabulated
edges.
**Minimum implementation.** The record, validators and mapping functions.
**Focused GREEN.** `tests\unit\domain`, `tests\property`, `tests\safety`.
**Broader verification.** `ruff-check-all`, `mypy-all`.
**Commit message.** `feat: add engine run record and coupled transition mapping`

### Task 5 — Retry policy and immutable retry decisions

**Owned files.** New `src/crypto_lab/domain/aggregation.py`,
`tests/unit/domain/test_retry_records.py`,
`tests/unit/domain/test_aggregation_inputs.py`. Edited
`src/crypto_lab/domain/retry.py`, `src/crypto_lab/domain/__init__.py`, and the
two §2.7 guard files.

**Consumed interfaces.** Tasks 1–4 output; `DiagnosticCategory`, `ErrorCode`.

**Produced interfaces.** `RetryDecisionOutcome`, `RetryDenialReason`,
`RetryDecisionRecord`, `retry_decision_semantic_projection`;
`HARD_BLOCKING_DIAGNOSTIC_CATEGORIES` and
`RETRY_PERMITTING_DIAGNOSTIC_CATEGORIES`; `retry_terminal_state_of`;
`CausalClosureEntry`, `RetryEvaluationSnapshot` and the pure
`evaluate_retry_gates`; the §3.10 aggregation models, the effective-terminal-state
derivation, §8.6's `slot_reason_code` mapping and the pure
`classify_experiment_outcome`. Releases no deferred name; appends one path
(allowlist 60).

**Focused RED.** The two category sets asserted disjoint with a union equal to
`set(DiagnosticCategory)`; all 64 boolean gate-outcome tuples asserted against
their expected outcome and recorded reason, pinning the `4, 1, 2, 3, 6, 5`
precedence under simultaneous failures; `causal_closure` proven to deduplicate
and sort whole pairs and to reject a duplicate pair; `hard_block_error_code`
proven to come from the first hard-blocking entry with category and code read
from that same entry; **one mutation control**: a closure of
`(ENGINE_RUNTIME, ENGINE.RUNTIME_FAILURE)` and
`(SECURITY, SECURITY.SENSITIVE_MATERIAL_LEAKAGE)` must select the `SECURITY`
code, while a deliberately wrong implementation that sorts categories and codes
independently and takes the smallest code selects the `ENGINE` code, and the test
asserts the two differ; every state-governed presence rule of
`RetryDecisionRecord` in both directions including rejection of the two success
states in field 8; the semantic projection proven to exclude `decided_at_utc` and
include each of the other fifteen fields one at a time; a `SlotAggregationInput`
rejected when exactly one of the two latest-attempt fields is present; the
effective terminal state asserted for every `(frozen outcome, attempt presence,
attempt state)` combination including the three zero-attempt cases; `slot_reason_code`
asserted total over all seven terminal states plus the approximation condition;
and the classifier asserted over every row of the §9.3 table plus the ordering
cases that distinguish rows 1–3 from each other and rows 4–8 from each other.
**Minimum implementation.** The records, the gate function, the derivations, the
reason mapping and the classifier.
**Focused GREEN.** `tests\unit\domain`, `tests\safety`.
**Broader verification.** `ruff-check-all`, `mypy-all`.
**Commit message.** `feat: add retry decision record, gates and aggregation rules`

### Task 6 — Repository/UoW protocols and in-memory doubles

**Owned files.** New `src/crypto_lab/experiments/ports.py`,
`src/crypto_lab/experiments/requests.py`,
`src/crypto_lab/experiments/diagnostics.py`,
`src/crypto_lab/experiments/experiment_service.py`,
`src/crypto_lab/experiments/run_service.py`,
`src/crypto_lab/experiments/invocation_service.py`,
`src/crypto_lab/adapters/ports.py`, `tests/doubles/__init__.py`,
`tests/doubles/experiments.py`,
`tests/unit/experiments/test_port_contracts.py`,
`tests/unit/experiments/test_experiment_service.py`,
`tests/unit/experiments/test_run_service.py`,
`tests/unit/experiments/test_invocation_service.py`,
`tests/unit/experiments/test_process_start.py`,
`tests/unit/experiments/test_linked_operations.py`. Edited
`src/crypto_lab/experiments/__init__.py`,
`src/crypto_lab/adapters/__init__.py`, and the two §2.7 guard files.

This task owns the transaction layer for the experiment, run and invocation
aggregates as well as the ports, because those services cannot exist before the
ports and doubles they consume and separating them would create the forward
dependency this decomposition forbids.

**Consumed interfaces.** Tasks 1–5 output.

**Produced interfaces.** The protocols of §10; the sixteen request models of
§3.11; the Stage 5 diagnostic factory with content-derived identity; the
`create_experiment`, `replace_experiment_spec`, `transition_experiment`,
`queue_experiment`, `cancel_experiment`, `create_attempt`, `transition_run`,
`create_invocation`, `begin_linked_launch`, `transition_invocation`,
`start_linked_run`, `enrich_invocation` and `transition_invocation_and_run`
operations; every double of §11; and an implementation-agnostic port-contract
suite parametrized over a factory fixture so Stage 8 can re-point it at real
repositories. Releases `ExperimentRepository`, `EngineRunRepository`,
`UnitOfWork`, `CommandInvocationRepository` (count 53); appends seven paths
(allowlist 67).

**Focused RED.** The `doubles.experiments` import probe; every port-contract case
— get-missing, add-duplicate, compare-and-swap success and revision mismatch,
unique-index violation, `latest_attempt` returning `MISSING` for an unattempted
slot, atomic `insert_if_absent` under a simulated concurrent winner, unit-of-work
rollback restoring every store, and commit atomicity across two stores; every
operation of §10.1 asserted for its read, validation and write sets, including
that a rejected operation writes nothing; the request-to-operation inventory
asserted one-to-one at sixteen; idempotent replay of each transition, including a
terminal replay at a matching revision; §4's edge ownership by rejecting every
`target_state` outside each operation's owned set; the carry-forward rule for
`availability_observation_id` and `deadline_utc`; `queue_experiment` rejecting a
`slot_compatibility` that omits, duplicates or misorders a slot; the
`create_attempt` contract of §5 — the first accepted attempt moving the
experiment `QUEUED → RUNNING`, a later-slot attempt bumping the `RUNNING`
revision, identical replay returning the stored attempt without a second bump, a
divergent duplicate returning `PERSISTENCE.CONCURRENCY_CONFLICT` with no write, a
frozen `NOT_APPLICABLE` slot rejected, a cancellation winner leaving no attempt
durable, an attempt winner forcing a stale cancellation to reload and return the
conflict, and a failure of either write rolling back both; a `replace_experiment_spec` after
`QUEUED` returning `CORE.IMMUTABLE_INPUT_MISMATCH` and one from `VALIDATED`
landing in `DRAFT`; **cancellation**: replay with the same `correlation_id`
returning the identical record regardless of revision, a different
`correlation_id` against `CANCELLED` returning `PERSISTENCE.CONCURRENCY_CONFLICT`,
a terminal non-cancelled experiment returning `CORE.INVARIANT_VIOLATION`, and a
stale revision returning the conflict; **parent eligibility**: every cell of the
§6 matrix, including a `VALIDATE` against a `READY` run, a `RUN` against a
`VALIDATING` run, a non-current attempt, a mismatched adapter, a mismatched
`request_hash`, a stale run revision and a still-open `VALIDATE`; identical-create
replay returning the existing invocation and a divergent create returning the
conflict; **process start**: `DESCRIBE`, `VALIDATE` and `RUN` each reaching
`RUNNING` through their permitted path only, `process_start` required exactly on
that edge and rejected elsewhere, the `VALIDATE` run staying `VALIDATING`;
**linked operations**: `begin_linked_launch` and `start_linked_run` each proven
for atomic success with both revisions +1, stale invocation revision with no
write, stale run revision with no write, rollback when the second predicate
fails, idempotent replay when both records already hold the target state at
matching revisions, and rejection of the run-only and invocation-only attempts
with `is_mixed_running_pair` detecting the resulting state; the coupled terminal
transition all-or-nothing when the second predicate fails; and an `EXITED`
transition with an unrecognized native exit accepted only when the primary
diagnostic resolves to `PROCESS.UNRECOGNIZED_PROCESS_EXIT`.
**Minimum implementation.** Protocols, requests, diagnostics factory, the three
services and the doubles.
**Focused GREEN.** `tests\unit\experiments`, `tests\safety`.
**Broader verification.** `ruff-check-all`, `mypy-all`, `pytest-all`.
**Commit message.** `feat: add application ports, lifecycle services and doubles`

### Task 7 — Retry scheduling, replay and successor creation

**Owned files.** New `src/crypto_lab/experiments/retry.py`,
`tests/unit/experiments/test_retry_decision.py`,
`tests/unit/experiments/test_successor_creation.py`,
`tests/property/test_retry_decision_determinism.py`. Edited
`src/crypto_lab/experiments/__init__.py`, `tests/doubles/experiments.py`, and
the two §2.7 guard files.

**Consumed interfaces.** Tasks 1–6 output.

**Produced interfaces.** `resolve_causal_closure` (the single traversal owner,
§8.2); the authoritative `RetryEvaluationSnapshot` assembler;
`evaluate_retry` implementing §8.3 and §8.4 phases 1–3; and
`create_successor` implementing §8.5. Releases no deferred name; appends
one path (allowlist 68).

**Focused RED.** Phase 1 replay proven to perform no clock read, no gate
evaluation and no write, using a clock double that fails when called and
repositories that record every call; phase 2 proven to read the clock exactly
once; a non-terminal, `SUCCEEDED` and `SUCCEEDED_WITH_WARNINGS` predecessor each
returning `CORE.INVARIANT_VIOLATION` and writing nothing; each gate individually
decisive with the other five passing; the created-attempt boundary at
`maximum_attempts_per_slot = 1` and at its bound, with a reservation proven not
to count; every hard blocker denying even when the terminal state is listed and
the primary diagnostic reports retriable; `resolve_causal_closure` proven to emit
whole pairs sorted by `(category, error_code)` from a closure containing duplicate
codes under different categories, to call only `get_many`, and to return
`Failure` on a cycle, a missing reference, depth 33 and node 257; each such
failure proven to persist a `DENIED` row with `HARD_BLOCKED_OUTCOME` and
`CORE.INVARIANT_VIOLATION` rather than abort; fresh-availability identity,
expiry and tie-breaking; an `ALLOWED` decision bumping the experiment revision
without a state change and a `DENIED` one not; a divergent concurrent insert
returning `RETRY.DECISION_CONFLICT` with both rows unmodified and an equal one
returning the winner; revision movement yielding a non-persisted concurrency
`Failure` and no decision row; the two-invocation contention proof for both a
cancellation winner, driven through `cancel_experiment`, and a
terminal-aggregation winner, simulated through the experiment repository's
injected hook because no application sequence makes aggregation write-ready
while a fresh `ALLOWED` retry is eligible (§9.5) — in the first invocation the
experiment swap fails, the decision insert and bump roll back, no decision row,
no `retry_not_before_utc` and no reservation exist, the winner is unchanged and
`PERSISTENCE.CONCURRENCY_CONFLICT` is returned; in the second invocation the
reloaded terminal experiment fails gate 5, a `DENIED` row with
`EXPERIMENT_TERMINAL` is persisted, no successor is reserved and no terminal
state is rewritten; a not-yet-due successor returning
`RETRY.NOT_BEFORE_NOT_REACHED`; a terminal experiment blocking successor creation
even at the current revision; durable delay surviving a rebuilt service over the
same stores unchanged; and successor creation idempotent, drawing no identity on
replay, and producing exactly one successor under repeated invocation.
**Minimum implementation.** The helper, the assembler and the two operations.
**Focused GREEN.** `tests\unit\experiments`, `tests\property`, `tests\safety`.
**Broader verification.** `ruff-check-all`, `mypy-all`, `pytest-all`.
**Commit message.** `feat: add three-phase retry decision and successor creation`

### Task 8 — Cancellation races and terminal aggregation

**Owned files.** New `src/crypto_lab/experiments/aggregation.py`,
`tests/unit/experiments/test_aggregation.py`,
`tests/unit/experiments/test_cancellation_races.py`. Edited
`src/crypto_lab/experiments/__init__.py` and the two §2.7 guard files.

**Consumed interfaces.** Tasks 1–7 output.

**Produced interfaces.** `build_aggregation_input`, reading every authoritative
fact of §9.2 including zero-attempt slots, and `aggregate_experiment`,
implementing §9.4 with the experiment-revision compare-and-swap of §9.1.
Releases no deferred name; appends one path (allowlist 69).

**Focused RED.** Every row of the §9.3 table exercised end to end through the
doubles, including row 4 with and without a late member and rows 2 and 5 over
zero-attempt slots with frozen `SUPPORTED`, `SUPPORTED_WITH_APPROXIMATION`,
`UNAVAILABLE` and `NOT_APPLICABLE` outcomes; the input's slot set asserted equal
to the frozen selected-slot set; `used_approximation` and `late_not_applicable`
proven derived from the frozen record and never accepted from a request;
readiness proven to block on each unresolved status and on each unattempted
supported slot; the already-terminal pre-classifier step proven to return
`Result[ExperimentAggregationResult]` with the stored state's verdict and empty
reason codes for all four terminal states including `CANCELLED`, without invoking
the classifier; aggregation of a `DRAFT`, `VALIDATED` or `QUEUED` experiment
returning `CORE.INVARIANT_VIOLATION`; every row of the §9.5 pairwise contention
table proven end to end through the doubles — the shared start, both operations
eligible, the winner's atomic write, the loser's lost swap, its single reload and
its tabulated public `Result` — including an aggregation winner leaving no
attempt durable and an attempt winner forcing a stale aggregation to reload; and
a successor proven impossible after cancellation or aggregation commits, both
with a stale revision and with a freshly reread one.
**Minimum implementation.** The two operations.
**Focused GREEN.** `tests\unit\experiments`, `tests\safety`.
**Broader verification.** `ruff-check-all`, `mypy-all`, `pytest-all`.
**Commit message.** `feat: add cancellation races and deterministic terminal aggregation`

### Task 9 — Schemas, docs, complete integration and Stage 5 status

**Owned files.** New `schemas/experiments/experiment-spec-v1.schema.json`,
`schemas/experiments/experiment-record-v1.schema.json`,
`schemas/experiments/engine-run-record-v1.schema.json`,
`schemas/experiments/command-invocation-record-v1.schema.json`,
`schemas/experiments/retry-policy-v1.schema.json`,
`schemas/experiments/retry-decision-record-v1.schema.json`,
`schemas/experiments/experiment-aggregation-result-v1.schema.json`,
`tests/integration/experiments/test_stage5_in_memory_flow.py`,
`tests/safety/test_stage5_boundaries.py`. Edited
`src/crypto_lab/schema_registry.py`, `tests/unit/test_schema_registry.py`,
`tests/architecture/test_package_import_boundaries.py`,
`tests/unit/domain/test_domain_descriptors.py`,
`tests/safety/test_stage3_boundaries.py`,
`tests/safety/test_gitnexus_development_tooling.py`,
`docs/development/verification.md`, `README.md`,
`docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md`. Every edit to a
Stage 1–4 test file is one §2.7 tabulates; this task creates no source module and
releases no deferred name.

**Consumed interfaces.** Tasks 1–8 output.

**Produced interfaces.** Seven registry entries appended after the existing
twenty, giving a closed 27-entry registry with Stage 3 at 0–10, Stage 4 at 11–19
and Stage 5 at 20–26; the `_STAGE5_SHA256` block; every §2.7 schema-registry and
documentation-pin change; the extended architecture guard; the Stage 5 safety
guard; the callable in-memory flow; and updated documentation and roadmap
status. Identifiers are `urn:crypto-lab:schema:experiments:<name>:1.0.0` for
`experiment-spec`, `experiment-record`, `engine-run-record`,
`command-invocation-record`, `retry-policy`, `retry-decision-record` and
`experiment-aggregation-result`; existing entries are never reordered and no
published identifier is reused. `schemas/experiments/` needs no change to
`scripts/generate_schemas.py`, `scripts/verify_schema_distribution.py` or
`pyproject.toml`. `engine-run-record-v1` deliberately publishes
`finalization_deadline_utc` as an optional property the Stage 5 runtime always
rejects (§3.8); `command-invocation-record-v1` publishes the eight-member
`ProcessExitCategory`, asserted member by member.

**Callable Stage 5 integration flow.** One scenario over the in-memory ports
with three selected slots: construct and queue an experiment whose frozen
`slot_compatibility` is `SUPPORTED`, `SUPPORTED`, `NOT_APPLICABLE`; create the
initial attempt for the two supported slots and prove the third is rejected;
apply `PENDING → VALIDATING`, create the `VALIDATE` invocation, drive it
`PENDING → STARTING → RUNNING → EXITED` with `process_start` on the run-start
edge while the run stays `VALIDATING`, then move the run `VALIDATING → READY`;
create the `RUN` invocation, commit `begin_linked_launch` and then
`start_linked_run`, and prove both aggregates are `RUNNING`; inject a canonical
terminal result by moving one run to `FAILED` with a retriable primary diagnostic
and the other to `SUCCEEDED`, executing no engine, adapter or process; evaluate
and persist the retry decision; observe the durable delay, where successor
creation before `retry_not_before_utc` returns `RETRY.NOT_BEFORE_NOT_REACHED`
and advancing `FixedClock` past it succeeds; drive the successor to
`SUCCEEDED_WITH_WARNINGS`; contend cancellation, retry and aggregation on one
experiment revision, asserting exactly one winner; aggregate and assert the
verdict and reason codes, including the third slot's preflight `NOT_APPLICABLE`
contribution; then rebuild every service over the same repositories and prove
replayed retry evaluation, successor creation and cancellation idempotent with
`retry_not_before_utc` unchanged.

**Architecture guard.** `experiments` is added to the existing scanner with a
prohibited set of `crypto_lab.persistence`, `crypto_lab.configuration`,
`crypto_lab.cli` and `crypto_lab.schema_registry`, and an allowlist of
`crypto_lab.domain`, `crypto_lab.adapters`, `crypto_lab.capabilities` and
`crypto_lab.experiments`. `adapters` is added with an allowlist of
`crypto_lab.domain` and `crypto_lab.adapters`. The guard separates
**architecturally forbidden** edges from **out-of-this-stage** imports:
`crypto_lab.process_supervision`, `crypto_lab.artifacts`, `crypto_lab.datasets`
and `crypto_lab.audit` are permitted to `experiments` by the dependency table but
excluded by Stage 5 scope, so they are asserted absent by the Stage 5 safety
guard rather than by the architecture guard. The scanner's existing self-tests
are extended, not duplicated.

**Stage 5 safety guard.** Assert that no `crypto_lab` module imports
`sqlalchemy`, `sqlite3`, `alembic`, `subprocess`, `os.environ`, `random`,
`secrets`, `time` or `datetime.now`; that no Stage 5 module reads the filesystem
or the environment at import time; that `crypto_lab.experiments` and
`crypto_lab.adapters` import none of the out-of-scope packages named above; that
`tests/doubles` is imported by no `crypto_lab` module; and that no traversal
logic exists in any `DiagnosticReader` implementation.

**Focused RED.** The registry render asserted to contain exactly 27 entries with
unique paths and identifiers at their fixed positions; all 20 pre-existing files
asserted byte-identical against their pinned digests and the seven new ones
pinned alongside them; every §2.7 registry assertion updated and green; every
Stage 5 timestamp reachable from a registered schema asserted to use the forward
view through the existing unmodified guard; the integration flow written before
the composition helpers exist; every documentation pin and negative of §2.7 green
against the updated prose with `STAGE5_IMPLEMENTATION_COMMIT` distinct from every
prior pinned commit; and the architecture and safety guards written with negative
controls that prove each rejects a planted violation.
**Minimum implementation.** Registry entries, generated schema bytes reviewed by
hand, the §2.7 assertion updates, and documentation updates.
**Focused GREEN.** `tests\unit\test_schema_registry.py`, `tests\integration`,
`tests\architecture`, `tests\safety`, `tests\unit\domain`.
**Broader verification.** The complete unmodified `scripts/verify.ps1`.
**Commit message.** `feat: add stage 5 schemas, boundaries and end-to-end flow`

## 13. Verification and acceptance

### 13.1 Commands

Focused, during red-green development. These override `addopts`, which
**disables pytest-cov**; they are diagnostic only and provide no coverage
evidence:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\domain tests\unit\configuration -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\experiments tests\unit\test_schema_registry.py -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\property tests\architecture tests\safety tests\integration -q
```

Complete, before any completion claim:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
```

The verifier is not modified by Stage 5. It runs `lock-check`, `sync`,
`ruff-format-all`, `ruff-check-all`, `mypy-all`, `schema-generate-check`,
`pytest-all`, `build`, `schema-distribution` and `git diff --check`, stopping at
the first failure. Every check is offline. Stage 5 introduces no dependency, so
no lock or acquisition operation is required and none may be cited as evidence.
`pyproject.toml`'s coverage configuration and its 90 percent threshold are not
altered.

### 13.2 Acceptance criteria

Stage 5 is complete only when all of the following hold with fresh offline
evidence:

1. All 64 ordered `ExperimentState` pairs with exactly 12 accepted, all 144
   ordered `EngineRunState` pairs with exactly 23, and all 64 ordered
   `CommandInvocationState` pairs with exactly 10.
2. Every operation rejects every `target_state` outside its owned set (§4, §5).
3. Terminal `ExperimentRecord`, `EngineRunRecord` and `RetryDecisionRecord`
   reject every change; a terminal `CommandInvocationRecord` accepts only §6's
   four write-once enrichments and rejects every overwrite.
4. `DESCRIBE`, `VALIDATE` and `RUN` each reach `RUNNING` only through their
   permitted path with `ProcessStartFacts`; `begin_linked_launch` and
   `start_linked_run` are the only paths to the run's `STARTING` and `RUNNING`;
   every linked-operation case of Task 6 passes.
5. The `create_invocation` parent-eligibility matrix, identical-create replay and
   divergent-create conflict hold for every command kind.
6. Every operation of §10.1 detects revision movement through its
   compare-and-swap, writes nothing partial, reloads once and returns the public
   `Result` its own contract assigns (§9.5); the request and operation
   inventories are one-to-one at sixteen.
7. All six retry gates are individually decisive, with reason precedence pinned
   over all 64 gate-outcome tuples, and `hard_block_error_code` derived from a
   single paired closure entry with the mutation control of Task 5 passing.
8. A reservation is not an attempt, and `maximum_attempts_per_slot = 1` never
   retries.
9. Every hard blocker denies even when the terminal state is listed and another
   diagnostic reports retriable; the category partition is total and disjoint;
   `resolve_causal_closure` is the single traversal owner and a degenerate
   closure denies durably rather than aborting.
10. Availability identity, freshness and deterministic tie-breaking are enforced.
11. Durable delay survives a service rebuild with an unchanged
    `retry_not_before_utc`, and a not-yet-due successor returns
    `RETRY.NOT_BEFORE_NOT_REACHED`.
12. Existing-row replay performs no clock read, no gate evaluation and no write;
    a divergent concurrent insert yields `RETRY.DECISION_CONFLICT` with neither
    row modified.
13. Exactly one successor is produced under repeated invocation, across a
    simulated restart, and against a terminal experiment with a reread revision.
14. Cancellation replays only on a matching `correlation_id`, conflicts on a
    different one, and every row of the §9.5 pairwise contention table resolves
    to exactly one winner with the loser returning its tabulated public `Result`.
15. Zero-attempt slots contribute `NOT_APPLICABLE` or `UNAVAILABLE` from the
    frozen compatibility result, block aggregation when supported, and
    approximation status is never accepted from a request; `slot_reason_code`
    and the classifier are total.
16. `ProcessExitCategory` has exactly the eight v1 members and the frozen mapping
    in both runtime and generated-schema tests, and an unrecognized exit requires
    its mandatory diagnostic.
17. The end-to-end in-memory application flow of Task 9 passes.
18. Every closed-world guard of §2.7 holds at its reconciled value: 69 allowed
    source files by set equality, 53 deferred definitions by set equality with
    every remaining name still detected, seven live representative-mutation
    cases, every schema-registry assertion at 27 with Stage 3, 4 and 5 at their
    fixed positions, and every documentation pin and negative at its Stage 5
    successor.
19. `schema-generate-check` passes on the closed 27-entry registry; the 20
    pre-existing files match their pinned digests byte for byte; and the seven
    new files are pinned alongside them.
20. `ruff-format-all`, `ruff-check-all`, `mypy-all` (strict, over `src`, `tests`
    and `scripts`), `pytest-all`, `build`, `schema-distribution` and
    `git diff --check` are all clean offline.
21. The unchanged complete verifier reports branch coverage of **at least 97.69
    percent**, the value it measured on the planning-base tree at
    `7a96176ae418491fc9740984c45b56cca6b3ac41`, on top of the repository floor
    of 90 percent that stays configured.
22. No Stage 6 contract and no infrastructure module is imported anywhere in
    `crypto_lab`, proven by the architecture and safety guards of Task 9.

## 14. Rollback and completion

### 14.1 Rollback

Each task ends in one commit on the Stage 5 implementation branch, so any task is
reverted with `git revert` of that commit without touching another task, and
because §2.7's guard edits travel in the same commit as the module or definition
that trips them, a revert restores the guard and the source together. The
highest-risk reversals are the Task 1 enum relocations, where any digest movement
in entries 5 or 17 triggers §2.5's fallback inside Task 1 rather than a merge
with moved bytes; and the Task 9 registry extension, whose revert returns the
registry to 20 entries and leaves Tasks 1–8 green because no earlier task
registers a schema.

Five Stage 1–4 test files are edited, all only as §2.7 tabulates:
`tests/safety/test_stage3_boundaries.py` and `tests/unit/test_package_layout.py`
by Tasks 1–8 and the former also by Task 9; `tests/unit/test_schema_registry.py`
by Tasks 1 and 9; `tests/unit/domain/test_domain_descriptors.py` and
`tests/safety/test_gitnexus_development_tooling.py` by Task 9. No other
Stage 1–4 file is deleted or rewritten, `pyproject.toml` is not modified at all,
and no generated schema is ever hand-edited: a wrong byte is corrected in the
model and regenerated.

### 14.2 Completion

Stage 5 is complete when every criterion of §13.2 holds, the worktree is clean
and committed, and the roadmap status table records the Stage 5 implementation
commit together with the closed 27-schema registry. Stage 6 is not started, and
no adapter protocol contract, process launch, artifact finalization or
persistence implementation exists anywhere in the tree.
