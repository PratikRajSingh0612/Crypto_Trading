# Project 1 Stage 7 — Windows Process Supervision Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** Detailed implementation plan for Stage 7. Implementation status is
recorded only in the master roadmap status table, never in this header, so the
header cannot go stale.
**Planning base:** `49ce9d37497cf4b18c2295eeec85adb6c5c8bf58` (`main` = `HEAD` = merge base)
**Prerequisites:** Stages 1–6 complete and merged
**Goal:** Implement the production Windows process supervisor — command-specific
paired UTC/monotonic deadlines, shell-free launch of the explicitly registered
absolute executable with an exact argument array and a fresh closed environment,
bounded stdout and stderr readers with incremental protocol parsing, heartbeat
monitoring, idempotent cancellation with graceful then bounded forced termination,
durable PID-plus-creation-time identity, Job Object and process-tree cleanup,
stale-invocation protection and restart-oriented invocation reconciliation — and
prove it by driving every Stage 6 fake-adapter contract row through it.
**Architecture:** `crypto_lab.process_supervision` implements the application-facing
`ProcessSupervisor` port over adapter protocol types (spec 8, 27.1). It imports
only `domain` and `adapters`; it never imports `experiments`. The Stage 5 lifecycle
operations stay the sole writers of invocation and run records: the supervisor
drives them through a structural `InvocationLifecycle` port that a new
`experiments` module implements without importing `process_supervision`
(structural typing, so the spec's dependency direction holds in both packages and
both merged import guards stay unchanged). Process creation, identity, Job
Objects, interrupts and tree termination live behind a `ProcessController` port
whose Windows implementation is the only module that imports `subprocess`; a
test-resident scripted controller makes every race deterministic without a child
process. Nothing finalizes an artifact, persists a row, reads an ambient clock,
reads the environment or moves a run to a success state.
**Tech stack:** Python 3.12, Pydantic v2 strict models, standard-library
`subprocess`, `threading`, `queue`, `asyncio` and `ctypes` (Windows API bindings),
`hypothesis` for bounded property tests, the closed `scripts/invoke-uv.ps1`
launcher and `scripts/verify.ps1`.
**Spec:** `docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md`
(sections 7.1, 14.1, 14.4–14.8, 15, 17.3, 21, 22.2.1, 22.5, 28.2–28.3, 28.5,
29.2–29.3, 30, 33.4, 33.5 and 33.7 per the roadmap's Stage 7 row; sections 1–9,
24, 27, 31–32 and 34 as the global floor).

## Global Constraints

- Python `>=3.12,<3.13`; runtime dependencies stay exactly `pydantic>=2.12,<3` and
  `pyyaml>=6.0.3,<7`; no dependency, lockfile, `pyproject.toml`, launcher or
  verifier change; no new pytest marker; no new approved skip (the two stay
  exactly two: `tests/safety/test_uv_launcher.py` symbolic-link privilege and
  `tests/unit/experiments/test_experiment_service.py` same-state replay).
- Every command runs through `scripts/invoke-uv.ps1` profiles; the complete
  verifier `scripts/verify.ps1` is unchanged (its normalized SHA-256 is pinned).
- Branch coverage floor stays 90 percent in `pyproject.toml`; the complete verifier
  must report at least **98.24 percent**, the value measured on the planning base
  (7772 passed, 2 skipped, ten verifier stages green), with
  `crypto_lab.process_supervision` and the new `experiments` module counted.
- Canonical schemas: the registry stays closed at 35 entries and every published
  byte stays identical (roadmap Stage 7 row: "Canonical schema changes: No").
  Relational migrations: none exist and none are created ("Relational schema
  changes: No"). Every task runs `schema-generate-check` and proves the 35
  digests unchanged; no task creates `persistence` content or an Alembic tree.
- Dependency direction (spec 8, 27.1): `crypto_lab.process_supervision` imports
  only `crypto_lab.domain`, `crypto_lab.adapters` and itself;
  `crypto_lab.experiments` keeps its Stage 5 closure (`domain`, `adapters`,
  `capabilities`, itself) and never imports `process_supervision`; `domain` stays
  free of process APIs. The Stage 3 import-root allowlist grows by exactly five
  roots — `asyncio`, `ctypes`, `queue`, `subprocess`, `threading` — each confined
  to the modules §2.6 names; `time`, `os`, `sys`, `io`, `shutil`, `tempfile`,
  `signal`, `stat` and `glob` appear in no source module.
- Launch contract (spec 14.1, 15.1, 22.2.1): the executable is
  `AdapterCatalogEntry.executable_path`, verified as a regular non-reparse file
  whose SHA-256 equals `executable_hash` before the `PENDING → STARTING` swap; the
  argument array is the entry's fixed launch arguments (§4.2) followed by
  `argument_array(command)` exactly; `shell=False`; the child environment block is
  the empty mapping; no string command exists anywhere; the adapter receives no
  database handle, no finalized path and no environment entry.
- Trust: adapters are untrusted; the raw attempt token enters the supervisor only
  through the request envelope it writes and the stdout/stderr bytes it reads, is
  redacted by the Stage 6 folds before any record exists, and never appears in a
  diagnostic, trace entry, log line or persisted record. Job Objects are a
  cleanup mechanism, never a sandbox claim (spec 15.4, 33.4).
- No real engine, adapter, exchange, market data, backtest, SQLAlchemy, SQLite,
  Alembic, network, credential, wallet, tax, UI, LLM, Docker, cloud or server
  behavior anywhere; no artifact finalization, `RunManifest`, `CandidateArtifact`
  record or `AuditSink`; no success run state; GitNexus stays
  `DISABLED_WITH_EVIDENCE` and is never invoked.

---

## 1. Goal, scope and exclusions

### 1.1 Goal

Stage 7 turns the Stage 6 stand-in supervision of `tests/contract/harness.py` into
production behaviour under `src/crypto_lab/process_supervision`, keeps every
Stage 6 protocol, lifecycle and semantic contract byte-identical, and proves the
result on Windows: the 52 scenario rows (58 table entries) of the Stage 6 contract
matrix pass through the production supervisor, every deadline mapping and cleanup
path of spec 14.8 and 15.4 is demonstrated, PID reuse and stale children cannot
corrupt state, and no path produces a false `EXITED` or a semantic success.

### 1.2 In scope

1. `Clock.monotonic() -> MonotonicInstant` on the domain port, the `MonotonicInstant`
   value, the `CancellationToken` domain port and its thread-safe implementation.
2. The `ProcessSupervisor` port and `WindowsProcessSupervisor`: preflight
   revalidation, paired-clock `PENDING → STARTING`, request-envelope write, shell-free
   launch, handoff `STARTING → RUNNING` with durable process identity, the
   supervision loop, terminal mapping, exactly-once enrichment and cleanup.
3. `InvocationLifecycle`: the structural port the supervisor drives and the
   `experiments` implementation over the merged Stage 5 operations, including the
   coupled run targets of every core-won terminal, the alone path beside a terminal
   run, and the `FAILED_TO_START` category rule the merged operation enforces.
4. Bounded pipe readers with backpressure, incremental framing across arbitrary
   chunk boundaries through the merged `frame_protocol_lines`, stdout parsing through
   the merged `parse_protocol_line` and ledger, stderr capture through the merged
   `BoundedStderrCapture`, bounded output-file reads into the merged parsers.
5. Heartbeat arming, reset and once-only `PROCESS.MISSING_HEARTBEAT`; command
   deadlines for `describe`, `validate` and `run` with the `STARTING`- and
   `RUNNING`-origin mappings; idempotent cancellation; graceful interrupt, grace
   period and forced termination.
6. Windows process identity (PID plus creation FILETIME), Job Objects with
   kill-on-close, verified descendant enumeration as the fallback, process-group
   interrupts, handle and reader cleanup, PID-reuse detection.
7. Temporary command roots: the flat layout the Stage 6 envelope fixes,
   preflight (directory and file ceilings with a long-path probe, reparse-point
   ancestors, containment), explicit `cwd`, pre-handoff root removal, and the rule
   that a root of an invocation that reached `RUNNING` is never removed by the
   supervisor.
8. Restart-oriented invocation reconciliation over the durable records and the
   process controller: every `CommandInvocationState`, both launch-handoff crash
   sides, PID reuse, absent processes, terminal records with incomplete cleanup for
   both `process_created` values.
9. A second fake-adapter script with the six Stage 7 scenarios (graceful
   cancellation, ignored interrupt, grandchild tree, a grandchild inheriting
   stdout, stdout flood, argv echo), the harness seam
   that drives the 52 Stage 6 rows through the production supervisor,
   deterministic race tests over a scripted controller, Windows platform tests, the
   Stage 7 boundary guard and the documentation and roadmap status.

### 1.3 Out of scope

Real trading engines or adapters; exchange or market-data access; credentials;
shell invocation or command strings; ambient environment inheritance or reading;
SQLite, SQLAlchemy and Alembic; artifact finalization, `RunManifest` creation,
`CandidateArtifact` records or byte-level candidate validation as production code;
Docker, cloud, server, UI, LLM, wallet or tax behavior; operating-system sandbox
claims; the scheduler, composition root and startup orchestration of Stage 10;
audit sinks and structured logging of Stage 9; Stage 8 persistence; any change to a
published schema, to `pyproject.toml`, to `uv.lock`, to the launcher or to the
verifier.

### 1.4 Named forward obligations

| Omission | Reason | Closed by |
|---|---|---|
| `AuditSink` and the audit events of spec 15.2 and 30.3 | `audit` is Stage 9's package and `AuditSink` stays deferred; Stage 7 exposes every supervision fact as a typed `SupervisionTraceEntry` through the `SupervisionObserver` port so the Stage 9 sink is a projection, not a new observation | Stage 9 |
| `stderr_artifact_id` on the terminal record | Requires a purpose `EVIDENCE` `ArtifactRef`; Stage 7 returns the sanitized `StderrCapture` inside `CommandResult` only | Stage 9 |
| `CandidateObservation` computation as production code | Stage 6 plan 1.4 assigns the observing I/O to Stage 9; the Stage 7 integration tests compute observations exactly as the Stage 6 harness does and hand them to `apply_command_semantic_outcome` | Stage 9 |
| Result-manifest recovery of spec 15.6 and 29.3 (validating a surviving manifest, result lease, finalization) | The reconciler reports `manifest_present` (file existence only) for a `RUNNING` invocation with no live process and leaves the record nonterminal until its deadline | Stage 9 |
| Removal of raw-bearing bytes at command close (spec 14.7: request file, adapter manifest, candidates) and removal of a post-`RUNNING` command root | Spec 15.2 makes `process_created` select "verified process-tree cleanup versus temporary-root ... pre-handoff cleanup", so `cleanup_complete` after `RUNNING` is process cleanup; the bytes stay under the root for the caller's semantic application, observation and the Stage 9 recovery lease; Stage 7 ships `remove_command_root` for that caller | Stage 9 (retention and lease) |
| Run-level requeue of `PENDING`, `VALIDATING` and `READY` attempts from surviving request material, retry-policy application after `PROCESS.ORCHESTRATOR_RESTART_LOST_SUPERVISION` (spec 15.6 "applies retry policy"), the reconciliation lease and the startup order of spec 29.2, cancelling a `PENDING` invocation of a cancelled experiment | Composition and scheduling; Stage 7 reconciles invocation records and reports every run-level fact the scheduler needs | Stage 10 |
| `RuntimeAvailabilityObservation` minting or refresh after `describe` (spec 14.8 "creates or refreshes an unavailable descriptor/runtime observation") | The pure projection is merged (`describe_availability_observation`); no writer port exists at the base; the tests project it as the harness does | Stage 10 |
| A production `Clock` implementation | The supervisor takes the injected `Clock` (now with `monotonic()`); tests inject a fixed-UTC, real-monotonic double; the composition root wires the system clock | Stage 10 |
| Configuration wiring of `process.cancellation_grace_seconds`, the describe-time `ProtocolLimits`, the supervision root and `supervisor_instance_id` | Constructor parameters of `WindowsProcessSupervisor`, bounded like the configuration model; the composition root passes the snapshot values | Stage 10 |
| `DiagnosticRecorder` and `ReconciliationSource` persistence | Both ports are implemented in Stage 7 only by test-resident doubles over `InMemoryBackingStore`; Stage 8 implements them over the tables and the `(state, deadline_utc)` index | Stage 8 |
| Attaching `PROCESS.PID_REUSE_DETECTED` to a `RUNNING` record that stays `RUNNING` | No write path merges `diagnostic_ids` on a live record; the reconciler reports the diagnostic (in `InvocationReconciliation.diagnostics` and the trace) and persists it only by attaching it beside the primary of the pass that terminalizes | Stage 8 (a live-record diagnostic write) |
| Non-Windows process controllers | Project 1 is Windows-only; the controller port is the seam, no other implementation is written | Out of Project 1 |

### 1.5 Carried Stage 6 notes and dispositions

1. **Real deadlines, heartbeat liveness, cancellation delivery, stderr pipe
   capture** (Stage 6 plan 1.4). Disposition: **CLOSED BY THIS PLAN** (§6, Tasks 4
   and 6); the harness stand-in remains for the Stage 6 suites and gains the seam
   of §9.
2. **Filesystem write-boundary enforcement** (Stage 6 plan 1.4). Disposition:
   **PARTLY CLOSED**: the supervisor owns the command root, enforces the layout,
   creates every directory and reads only the declared output file; a post-exit
   snapshot difference outside the permitted paths is a `WRITE_BOUNDARY_VIOLATION`
   trace entry and a `PROCESS.WRITE_BOUNDARY_VIOLATION` additional diagnostic
   (never a terminal cause: a stray adapter write is an artifact-validation concern
   and the run verdict comes from reconciliation). The harness snapshot assertion
   is kept.
3. **Stderr capture and segmenting to the 50 MiB budget.** Disposition: **CLOSED**;
   the pipe reader feeds the merged fold, which owns the budget.
4. **`SemanticOutcomeRequest` is constructed by the supervisor (Stage 6 plan 3.12).**
   Disposition: **DECLARED READING**: the supervisor returns the parse outcome and
   the protocol summary inside `SupervisionOutcome`; a pure `experiments` helper
   (`semantic_outcome_request_for`) builds the request from that outcome plus the
   caller-supplied `CandidateObservation`s, so Stage 9's observation boundary is
   respected.
5. **Late output for an already-terminal invocation is the Stage 7 half of "stale
   output" (Stage 6 plan 7.3).** Disposition: **CLOSED**: after a terminal decision
   the supervisor still drains and parses stdout until EOF, appends accepted events
   (identity-valid protocol), records a rejection during the grace window as an
   additional diagnostic and never lets a late line change the decided terminal
   state; a late output file is read only for an `EXITED` invocation.
6. **The harness reads describe output regardless of state and applies the output
   ceiling after a full read.** Disposition: **TIGHTENED**: the supervisor reads an
   output file only for an `EXITED` invocation and reads at most ceiling + 1 bytes.

## 2. Authority and merged interfaces

### 2.1 Authority order

1. The specification sections named in the header.
2. The merged source, tests, doubles, fake adapter, harness and guards at the
   planning base — every consumed name in §2.2 exists there.
3. The roadmap's Stage 7 row (goal, deliverables, exclusions, test categories, exit
   evidence, control table).
4. This plan's declared readings (§2.5), each stated as a reading rather than
   inferred silently.

### 2.2 Consumed merged interfaces

Each name is imported from its defining module. Every name below exists on the
planning base.

<!-- consumed -->
| Defining module | Names Stage 7 consumes |
|---|---|
| `crypto_lab.domain.base` | `CanonicalModel` |
| `crypto_lab.domain.identifiers` | `InvocationId`, `RunId`, `ExperimentId`, `DiagnosticId`, `Sha256`, `NormalizedIdentifier`, `AttemptToken` (type only, never a field of a Stage 7 record) |
| `crypto_lab.domain.time` | `CalendarValidUtcDateTime`, `require_utc`, `format_utc` |
| `crypto_lab.domain.descriptors` | `BoundedText`, `ExecutablePath`, `MAX_EXECUTABLE_PATH_CHARACTERS`, `OperatingSystem`, `RuntimeAvailabilityObservation` (tests) |
| `crypto_lab.domain.diagnostics` | `Diagnostic`, `DiagnosticCategory`, `DiagnosticSeverity`, `ErrorCode`, `DiagnosticDetailValue`, `DiagnosticDetailKey`, `_inspect_details`, `MAX_DETAIL_NODES`, `MAX_DETAIL_BYTES` |
| `crypto_lab.domain.results` | `Result`, `Success`, `Failure` |
| `crypto_lab.domain.hashing` | `attempt_token_hash`, `sha256_bytes`, `profile_hash`, `HashingProfile`, `_uuid4_shaped` |
| `crypto_lab.domain.canonical_json` | `canonical_json_bytes` |
| `crypto_lab.domain.lifecycle` | `CommandKind`, `CommandInvocationState`, `EngineRunState`, `ExperimentState`, `ProcessExitCategory`, `process_exit_category_for`, `RECOGNIZED_NATIVE_EXIT_VALUES`, `TERMINAL_COMMAND_INVOCATION_STATES`, `TERMINAL_ENGINE_RUN_STATES`, `COMMAND_INVOCATION_TRANSITIONS`, `ENGINE_RUN_TRANSITIONS` |
| `crypto_lab.domain.command_invocation` | `CommandInvocationRecord`, `ProcessIdentity`, `ProcessStartFacts`, `NativeExitValue`, `MAX_DIAGNOSTIC_IDS`, `MIN_TIMEOUT_SECONDS`, `MAX_RUN_TIMEOUT_SECONDS`, `command_timeout_bounds` |
| `crypto_lab.domain.engine_run` | `EngineRunRecord`, `AttemptTokenMaterial` (tests), `is_mixed_running_pair` |
| `crypto_lab.domain.experiment` | `ExperimentRecord`, `SlotCompatibility` (the lifecycle implementation reads the experiment state and the slot's frozen observation identity) |
| `crypto_lab.domain.ports` | `Clock`, `IdentitySource` (tests) |
| `crypto_lab.adapters.catalog` | `AdapterCatalogEntry`, `AbsoluteLocalExecutablePath`, `validate_absolute_local_executable_path` |
| `crypto_lab.adapters.commands` | `AdapterCommand`, `CommandResult`, `argument_array` |
| `crypto_lab.adapters.envelopes` | `AdapterCommandRequestEnvelope`, `EngineRunRequest`, `DescribeRequestPayload`, `NegotiatedVersions`, `build_request_envelope`, `build_engine_run_request`, `request_envelope_bytes`, `request_material_hash` (tests), `request_hash_of` |
| `crypto_lab.adapters.limits` | `ProtocolLimits`, `PROTOCOL_LIMITS_DEFAULT`, `MAX_DESCRIPTOR_OUTPUT_BYTES`, `MAX_VALIDATION_RESULT_BYTES`, `MAX_RESULT_MANIFEST_BYTES`, `MAX_STDERR_BYTES`, `MAX_SEQUENCE`, `RESULT_MANIFEST_RELATIVE_PATH` |
| `crypto_lab.adapters.events` | `frame_protocol_lines`, `parse_protocol_line`, `EventAcceptanceContext`, `InvocationEventLedger`, `EventAccepted`, `EventReplayed`, `EventRejected`, `RunEvent`, `HeartbeatPayload`, `ProtocolEventSummary` |
| `crypto_lab.adapters.sanitization` | `BoundedStderrCapture`, `StderrCapture` |
| `crypto_lab.adapters.manifests` | `parse_validation_result`, `parse_result_manifest`, `ValidationResultParse`, `ManifestParse` |
| `crypto_lab.adapters.negotiation` | `parse_bootstrap_descriptor`, `DescriptorParse`, `describe_availability_observation` (tests) |
| `crypto_lab.adapters.reconciliation` | `CandidateObservation`, `reconcile_describe` (tests) |
| `crypto_lab.adapters.vocabulary` | `ProtocolIntegrityStatus` |
| `crypto_lab.adapters.diagnostics` | `stage6_diagnostic`, `STAGE6_DIAGNOSTIC_CODES` and the constants `PROCESS_MISSING_HEARTBEAT`, `PROCESS_STDERR_TRUNCATED`, `PROCESS_UNRECOGNIZED_PROCESS_EXIT`, `PROCESS_DESCRIBE_TIMED_OUT`, `PROCESS_VALIDATE_TIMED_OUT`, `PROCESS_START_TIMED_OUT`, `PROCESS_RUN_TIMED_OUT`, `PROCESS_CANCELLED`, `ADAPTER_UNAVAILABLE` |
| `crypto_lab.adapters.ports` | `CommandInvocationRepository` (lifecycle implementation, through the unit of work) |
| `crypto_lab.experiments.ports` | `UnitOfWork`, `EngineRunRepository`, `ExperimentRepository`, `DiagnosticReader` |
| `crypto_lab.experiments.requests` | `InvocationTransitionRequest`, `LinkedLaunchRequest`, `LinkedStartRequest`, `InvocationEnrichmentRequest`, `CoupledTransitionRequest`, `RunTransitionRequest`, `SemanticOutcomeRequest`, `CancelExperimentRequest` (tests) |
| `crypto_lab.experiments.invocation_service` | `transition_invocation`, `begin_linked_launch`, `start_linked_run`, `transition_invocation_and_run`, `enrich_invocation`, `LinkedPair`, `COUPLED_TERMINAL_TARGETS`, `LINKED_ONLY_INVOCATION_TARGETS` |
| `crypto_lab.experiments.experiment_service` | `run_operation`, `LostSwap`, `cancel_experiment` (tests) |
| `crypto_lab.experiments.diagnostics` | `CONCURRENCY_CONFLICT`, `INVARIANT_VIOLATION`, `IMMUTABLE_INPUT_MISMATCH`, `stage5_failure`, `stage5_diagnostic` (tests), `STAGE5_DIAGNOSTIC_CODES` (tests) |
| `crypto_lab.experiments.semantic_outcome` | `apply_command_semantic_outcome`, `SemanticOutcome` (tests and the request helper's return type) |
<!-- /consumed -->

The test tree consumes `tests/doubles/experiments.py` (`InMemoryBackingStore`,
`InMemoryUnitOfWork`, `FixedClock`, `CountingClock`, `FailingClock`,
`SequentialIdentitySource`, the `sample_*` helpers, `RecordingUnitOfWork`),
`tests/contract/harness.py` (`OfflineCommandHarness`, `build_harness`,
`CommandRun`, `assert_token_absent`, `assert_token_only_in_wire_material`,
`catalog_entry_for`, `launch_arguments`, `FAKE_ADAPTER_PATH`,
`DESCRIBE_STDERR_SENTINEL`, `DEFAULT_NEGOTIATED`), `tests/contract/scenarios.py`
(`SCENARIOS`, `scenario_ids`), `tests/fake_adapters/fake_adapter.py` (its module-level helpers,
imported by the Stage 7 fake script), plus the scanner helpers of
`tests/safety/test_stage3_boundaries.py` and
`tests/safety/test_stage5_boundaries.py` through the merged same-directory import
pattern.

### 2.3 Placement decisions

- **`ProcessSupervisor`, `InvocationLifecycle`, `ProcessController`,
  `LaunchedProcess`, `SupervisionObserver`, `ReconciliationSource`** live in
  `process_supervision/ports.py`: spec 8.1 names `process_supervision` the owner of
  the supervisor port, and spec 8 places every other port with the package that
  consumes it — the supervisor and the reconciler consume all five.
- **`CancellationToken`** is a `domain` port (`domain/ports.py`): spec 8.2 uses it
  in both `ProcessSupervisor.invoke` and Stage 9's `ArtifactFinalizer.finalize`,
  and `artifacts` may import only `domain`. It is a pure structural contract;
  its thread-safe implementation is `process_supervision/cancellation.py`.
  `tests/architecture/test_domain_import_boundary.py` forces both domain names to
  be defined in `domain`, never imported into it.
- **`MonotonicInstant`** is a frozen dataclass in `domain/time.py`, next to the
  UTC primitives it pairs with; it renders into no schema (no model carries it).
- **`Stage5InvocationLifecycle`, `DiagnosticRecorder`, `RequestMaterial`,
  `semantic_outcome_request_for`** live in `experiments/supervision_lifecycle.py`:
  they hold the unit of work and call the Stage 5 operations, which only the
  application layer may do (spec 8.2). The class satisfies the
  `InvocationLifecycle` protocol structurally and never imports it, so
  `tests/architecture/test_package_import_boundaries.py` `_ALLOWED_FOR_EXPERIMENTS`
  and `tests/safety/test_stage5_boundaries.py` `_OUT_OF_SCOPE_PACKAGES` are
  unchanged and prove the direction; the runtime check
  `isinstance(Stage5InvocationLifecycle(...), InvocationLifecycle)` is a test.
- **`RunReconciliationFacts` and every other Stage 7 record** live in
  `process_supervision/models.py`; `ReconciliationSource` and
  `DiagnosticRecorder` are implemented in Stage 7 only by test-resident doubles
  in a new `tests/doubles/supervision.py`, never by `experiments` (which could not
  name the return type without importing `process_supervision`).
- **The Windows API** is confined to `process_supervision/windows_api.py` (the only
  `ctypes` importer) and `process_supervision/windows_process.py` (the only
  `subprocess` importer). Every other Stage 7 module is platform-neutral Python
  over the ports.
- **Stage 7 fake-adapter scenarios** live in a second script,
  `tests/fake_adapters/supervision_fake.py`, which imports the merged
  `fake_adapter.py` helpers and adds `signal` and `subprocess`; the merged
  `fake_adapter.py` is not edited, so the Stage 6 pins on its seven roots stay
  true (§2.6).
- **The Stage 7 catalog entries** for the production path are built by a Stage 7
  test helper (`supervised_catalog_entry_for`) and point at the venv interpreter
  with fixed launch arguments; the merged `catalog_entry_for` and its script-path
  entries stay for the stand-in path and its pins (§4.2, §9.1).

### 2.4 Frozen-byte and contract constraints

- No published schema changes. `MonotonicInstant` is not a Pydantic field
  anywhere; `Clock` is a Protocol; `CancellationToken` is a Protocol; every
  Stage 7 record is trust class P or K, unpublished, with no `$id`.
- `CommandResult`, `AdapterCommand`, `AdapterCatalogEntry`,
  `SemanticOutcomeRequest`, the envelope's `assigned_work_dir.relative_path`
  literal and every Stage 6 model are consumed unchanged; `CommandResult` is
  returned exactly as Stage 6 defines it, inside `SupervisionOutcome`.
- No Stage 6 source module is edited; the Stage 6 fourteen-module guard scans keep
  their meaning. `adapters/__init__.py` is not edited.
- `tests/contract/harness.py` keeps exactly one `subprocess.Popen` call with its
  pinned keyword set, its `# noqa: S603 - reviewed` line and the "stand-in"
  wording; the seam (§9.3) adds a strategy, never a second launch.
- `tests/contract/scenarios.py` (`SCENARIOS`, 58 entries; `ADAPTER_SIDE_VECTORS`,
  5) is not edited; the Stage 7 scenarios have their own table.

### 2.5 Declared readings of the specification

Each is a reading the plan applies, stated so a reviewer can accept or reject it.

1. **`ProcessSupervisor.invoke` returns `Result[SupervisionOutcome]`.** Spec 8.2
   writes `-> CommandResult` and requires every interface to return "explicit result
   objects, or stable diagnostics" with `Result[T]` as the discriminated form.
   `CommandResult` requires a terminal invocation, so a refusal before any record
   changed cannot be a `CommandResult`; it is a `Failure`. Every path that changed
   a record returns `Success` carrying the spec's `CommandResult` verbatim plus the
   parse outcome and protocol summary the Stage 6 operation needs. The only
   `Failure`s: a structural preflight refusal (§4.4), a lost `PENDING → STARTING`
   or `STARTING → RUNNING` swap against a still-nonterminal record that another
   actor moved (§5.3 row 4), an own-request defect (§5.3), and — once per supervisor
   instance, when no `PathPreflight` was injected — the §7.2 long-path probe's
   `Failure(PROCESS.PATH_PREFLIGHT_REJECTED)`, which fires before any record is
   loaded.
2. **Fixed launch arguments come from `AdapterCatalogEntry.runtime_metadata`.**
   Spec 14.1 says the orchestrator "passes an argument array" and spec 22.2.1
   registers each adapter as "absolute executable path, executable hash, and
   non-secret fixed runtime metadata". The fake adapters are Python scripts, which
   `CreateProcess` cannot start, so their production catalog entries name the venv
   interpreter as the hashed absolute executable and carry the fixed prefix
   `["-I", "-B", "<absolute script path>"]` under the metadata key
   `launch_arguments` (§4.2). The rendered array is
   `(executable_path, *launch_arguments, *argument_array(command))`; the merged
   `argument_array` is never altered, and an entry without the key launches with
   no prefix. The metadata model is unchanged and unpublished.
3. **Launch-path failures pass through `STARTING`.** Spec 15.1 lists the
   executable checksum among the pre-swap revalidations, but the only terminal edge
   from `PENDING` is `CANCELLED`, and `FAILED_TO_START` is the state whose meaning
   is "a launch was attempted and failed" (15.2). The supervisor therefore
   observes the executable before the swap, performs `PENDING → STARTING`, and then
   terminalizes `STARTING → FAILED_TO_START` with the failure as primary; only
   shape-level invariant violations (wrong state, wrong kind, mismatched paths or
   identity, stale revision, undecodable launch arguments) refuse before the swap.
   The primary follows spec 21.2.1: an executable that is **absent** (or a
   `CreateProcess` failure with `ERROR_FILE_NOT_FOUND` `2` or
   `ERROR_PATH_NOT_FOUND` `3`) is the availability failure `ADAPTER.UNAVAILABLE`
   (minted through `stage6_diagnostic`, retriable only after a new observation),
   so the merged coupled mapping moves a linked run `→ UNAVAILABLE`; an
   executable that is **present** but is not a regular file, is a reparse point,
   has a reparse point on any ancestor, or whose SHA-256 differs is
   `CORE.IMMUTABLE_INPUT_MISMATCH` (run `→ FAILED`) — "mismatch" is read as "the
   registered executable's identity cannot be verified", which the three non-hash
   reasons share with a differing hash (the run effect, `FAILED` under a hard
   block, is the same either way);
   every other creation failure is `PROCESS.LAUNCH_FAILED` (engine runtime, run
   `→ FAILED`). For the `UNAVAILABLE` run target the lifecycle supplies the
   `availability_observation_id` the merged record requires exactly as the Stage 6
   operation does: for a `RUN` the `READY`-time observation is carried (the request
   passes `MISSING`), and for a `VALIDATE` the lifecycle reads the run's slot in the
   experiment's frozen `slot_compatibility` and passes that slot's observation
   identity. `stage6_diagnostic` does not force correlation for the
   `ADAPTER_UNAVAILABILITY` category, so the supervisor attaches `invocation_id`
   (and, for a linked kind, `run_id`/`experiment_id` read from the `EngineRunRecord`
   that `lifecycle.linked_run` returns right after `load`, before any preflight
   step — the invocation record itself carries no `experiment_id`) itself and a
   Stage 7 test pins it. Request-material agreement (the token hash against the
   run's, the request hash against the record's) and parent eligibility (the
   experiment not `CANCELLED`) are revalidated inside `begin_start` before the
   swap, as spec 15.1 step 1 orders (§4.4): the merged `build_engine_run_request`
   needs only the run, the experiment and the material, so it runs there with a
   provisional instant; a `request_envelope` failure after the swap is a defence,
   not the primary check.
4. **The graceful interrupt is `CTRL_BREAK_EVENT` to the child's process group,
   and the grace period is always waited.** Spec 15.4 says "an adapter-specific
   interrupt through the process controller" and "forced termination occurs only
   after the grace period or immediately for a severe protocol/path violation";
   Project 1's only adapters are the fake adapters, and the console control event
   is the Windows-native interrupt a Python child can handle without a protocol
   extension. When the event cannot be generated (the supervisor process has no
   console: the call returns `FALSE` with `ERROR_INVALID_HANDLE`), the supervisor
   records `PROCESS.GRACEFUL_INTERRUPT_UNAVAILABLE`, still waits the grace period
   (the child may exit on its own) and then forces. A Python-level `SIGBREAK`
   handler executes only when the child's main thread is running bytecode; neither
   `time.sleep` nor `threading.Event.wait` is interrupted by `CTRL_BREAK`, so every
   cooperating fake and every test child sleeps in slices of at most 0.2 seconds.
5. **A protocol rejection is a severe protocol violation**: forced tree
   termination at once, no interrupt, no grace. Spec 14.7 describes contamination
   handling as "requests cancellation, applies the grace period, terminates if
   necessary" while spec 15.4 permits immediate force "for a severe protocol/path
   violation"; the plan reads every stdout rejection as severe because stdout is
   untrusted from its first bad line, no Stage 6 row pins an exit value, and the
   harness precedent kills at once — an explicit override of 14.7's grace sentence
   for every stdout rejection code, pinned per rejection code by a scripted Task 6
   case that asserts `interrupt_calls == 0` and `terminate_calls ==
   [FORCED_TERMINATION_EXIT_CODE]`. Immediate force also applies to a child that
   was never owned (a pre-handoff cancellation or deadline, spec 15.2 "owned only
   after ... durably associated"), to a child whose invocation an external winner
   has already terminalized, to a child whose root process exited while a
   descendant still holds a pipe (§6.5), and to the reconciler's live matching
   orphan; the grace period belongs to a `CANCELLED` or `TIMED_OUT` decision on an
   owned, running child.
6. **`FORCED_TERMINATION_EXIT_CODE` is `1067`** (Win32 `ERROR_PROCESS_ABORTED`,
   "the process terminated unexpectedly"): outside the eight recognized values, so
   it maps to `RUNTIME_FAILURE`; distinct from `1` (`Popen.kill`), from `259`
   (`STILL_ACTIVE`) and from `3221225786` (`STATUS_CONTROL_C_EXIT`, the value a
   handler-less Python child reports after `CTRL_BREAK`), so tests can tell a
   forced kill from a cooperative or default exit.
7. **A `STARTING`-origin `TIMED_OUT` or `CANCELLED` is never enriched with a
   native exit.** Spec 14.8 says "no captured child exit is required"; a child
   killed before the handoff was never owned, so its exit value is not a fact of
   the invocation.
8. **A lifecycle failure while `RUNNING` is an orchestrator cancellation.** When
   `append_event` or another lifecycle call fails with a core code the supervisor
   cannot leave the child running unsupervised and cannot call the adapter's stdout
   untrustworthy: it interrupts, terminates and terminalizes `CANCELLED` with
   primary `PROCESS.CANCELLED` and the recorded core failure as its causal
   reference (spec 21.2 "user or orchestrator cancellation"). The persistence
   failure's own retriable-after-reload posture is deliberately forfeited: a
   `CANCELLED` run hard-blocks automatic retry, and only an explicit new attempt
   may follow — a child left running while its event log cannot be written is a
   worse outcome than a lost retry, and a Task 6 assertion pins the run's
   `CANCELLED` state on that row. No re-issue precedes the cancellation: the
   merged `append_event` is idempotent on identical content, so a conflict means
   foreign content already sits at that sequence, which no reread changes. After the terminal decision the same failure
   only stops parsing and rides the enrichment.
9. **A lost swap is classified by the stored state, never by the failure code.**
   The merged operations rerun once and report a foreign terminal winner as
   `CORE.INVARIANT_VIOLATION` (stored terminal) and a same-state winner as
   `PERSISTENCE.CONCURRENCY_CONFLICT`; nothing moves a `STARTING` or `RUNNING`
   revision without changing state. After any `Failure` from a state-changing
   lifecycle call the supervisor loads the record: terminal → external winner;
   nonterminal at the expected state and revision → the §5.3 classification
   (external run winner or own-request defect); nonterminal but at another state
   or a moved revision → another actor's write, never re-issued: the original
   `Failure` is returned, because a replay of `begin_start` or
   `record_process_start` would make this supervisor the owner of a launch it did
   not perform (§5.3 row 4).
10. **Cancellation beats the deadline when both are observed in one tick; a fully
    drained exit beats both.** Spec 14.8 resolves races by compare-and-swap; inside
    one supervisor the tick order of §6.3 is the deterministic tie-break.
11. **The command root is `<supervision_root>\<invocation_id>` for every kind and
    the work directory is `<command_root>\runs\<run_id>\work`**, the tail the merged
    `build_engine_run_request` fixes and the fake adapter verifies. Spec 15.1's
    "validate/run roots are owned by their attempt, while describe uses an
    adapter-command root with no run identity" is satisfied by the `runs\<run_id>`
    segment that only an attempt command has; the root is the child's working
    directory and is created by the supervisor from the single layout function,
    which the caller's `AdapterCommand` paths must equal (spec 14.1 "absolute
    core-selected paths").
12. **A post-`RUNNING` command root is never removed by the supervisor** (§1.4;
    spec 15.2's cleanup sentence and spec 14.7's lease). `cleanup_complete=true`
    after `RUNNING` means the process tree is verified dead, handles are closed
    and readers have stopped.
13. **Stdout after a terminal decision is still parsed.** An accepted event during
    the grace window is identity-valid protocol and is appended; a rejection during
    the grace window is an additional diagnostic and never changes the decided
    state; a rejection found while draining after an ordinary exit does win, as the
    harness already established (`EXITED` is decided only after EOF and the flush).
14. **`describe` stdout is counted, never framed, parsed or appended, and never
    terminates the child**: `RunEvent` and `EventAcceptanceContext` have no
    describe form; the merged `reconcile_describe` turns a non-zero count into
    `DESCRIBE_UNAVAILABLE` with `PROTOCOL.STDOUT_CONTAMINATION` on an `EXITED`
    invocation (row 21). The live supervisor therefore never decides
    `PROTOCOL_FAILED` for a describe from its stdout; the reconciler's
    lost-supervision row (§8.5) applies to every kind.
15. **The heartbeat threshold is armed at the handoff commit** (the instant the
    invocation becomes `RUNNING`), reset on every accepted `HEARTBEAT`, checked
    against the process before minting, minted once, and never terminates (spec
    15.3: "does not by itself claim the engine is dead").
16. **The reconciler treats a live process whose creation identity matches as
    unsupervisable after restart** (pipes cannot be reattached), terminates the
    verified tree and terminalizes `PROTOCOL_FAILED` with
    `PROCESS.ORCHESTRATOR_RESTART_LOST_SUPERVISION` (spec 15.6 third bullet). With
    kill-on-close Job Objects this branch is reachable in production only when the
    job was unavailable or the supervisor's job handle survived; the tests reach it
    by keeping the first launch's handles open.
17. **"Cancellation already won" means the experiment is `CANCELLED` or the linked
    run is `CANCELLED`**, and the rule is applied at exactly two sites: by the
    reconciler (§8.5, through `facts.cancelled`) and by `resolve_external_winner` in
    the launch window (reading 22), which generalizes it — beside any terminal run
    (any `TERMINAL_ENGINE_RUN_STATES` member) the launch can no longer proceed, so
    the invocation is cancelled alone; beside a cancelled experiment, coupled. The merged domain calls a run moved beside a
    `PENDING` or `STARTING` invocation lawful (the mixed-pair rule of
    `domain/engine_run.py` exempts only those two states); a run moved beside a
    `RUNNING` invocation is a mixed pair the orchestrator created. The live
    supervisor observes cancellation only through its token: at its terminal
    decision the alone path of §5.1 writes the decided state beside a foreign
    terminal run, and no false `EXITED` or success can follow (a reaped exit is
    still required, and the merged semantic application treats a terminal run as
    superseded). Where the rule applies, the invocation terminalizes `CANCELLED`
    with `PROCESS.CANCELLED`, alone when the run is already terminal and coupled
    (run `→ CANCELLED`) when only the experiment is cancelled.
18. **`process_started_at_utc` is the injected clock's instant at the handoff**,
    as the harness does; the operating-system creation time lives in
    `creation_identity`. **`payload.created_at_utc` of a run envelope is the
    `STARTING` record's `launch_attempted_at_utc`**, so the envelope is a pure
    function of the record and the registered material.
19. **The request snapshot's `ProtocolLimits` govern a validate or run
    invocation** (`payload.configuration_snapshot.limits`, what the adapter sees);
    a describe envelope carries none, so the supervisor's constructor
    `describe_limits` (default `PROTOCOL_LIMITS_DEFAULT`) supplies the stderr
    budget of a describe.
20. **Long-path support is probed, not assumed** (spec 22.5): one create-and-remove
    probe of a directory longer than 247 characters under the supervision root
    fixes the ceilings for that supervisor instance: the command root, which is
    the child's `cwd`, is always bounded at 247 characters: it is created with
    `CreateDirectoryW` (MAX_PATH − 12 without long paths) and handed to
    `CreateProcessW` as `lpCurrentDirectory` (bounded at MAX_PATH), and 247 is the
    conservative intersection of both bounds; the
    work directory and the files are bounded at 247/259 when unsupported and at
    `MAX_EXECUTABLE_PATH_CHARACTERS` (1024, the catalog path grammar's own bound)
    when supported. The supervisor accepts an injected `PathPreflight` so a test
    can force either arm; the deterministic rejection always runs, the long-path
    success case runs only when the probe succeeds and otherwise asserts the
    rejection branch, so no skip is added.
21. **Stage 7 fake scenarios live in `supervision_fake.py`**, which inserts its own
    directory into `sys.path` before importing `fake_adapter` (the `-I` flag omits
    the script directory); the Stage 7 guard pins that single insertion and the
    script's import roots exactly.
22. **An external run terminalization around the launch is honored as a
    cancellation, and the lifecycle decides it.** The merged `transition_run` may
    cancel or time out a run beside a `PENDING` or `STARTING` invocation and calls
    the pair lawful; the merged `begin_linked_launch` and `start_linked_run` then
    refuse with `CORE.INVARIANT_VIOLATION` while the invocation is unchanged. When
    `begin_start` or `record_process_start` fails and the reloaded invocation is
    nonterminal at the expected revision, the supervisor calls
    `lifecycle.resolve_external_winner(...)`: the lifecycle reloads the run and the
    experiment and writes `CANCELLED` with `PROCESS.CANCELLED` only when the linked
    run is terminal (alone path) or the experiment is `CANCELLED` (coupled),
    returning `MISSING` otherwise so the supervisor treats the original failure as
    the own-request defect of §5.3. A failure of `record_terminal` itself never
    triggers this path: the invocation is then left as it is (with the child
    terminated) for reconciliation, because a refused terminal write can only be a
    defect of the request. The supervisor never writes a blind cancellation.
23. **A cancellation observed before `begin_start` still performs the single
    enrichment** (`cleanup_complete=True` over an empty cleanup report), so a
    never-launched `CANCELLED` record leaves the reconciliation target set (the
    merged transition never sets `cleanup_complete`; only an enrichment does).
24. **Readers start on the pipes `CreateProcess` creates, immediately after
    `launch` returns and before any byte is dequeued or interpreted.** Spec 15.1
    orders "opens bounded stdout and stderr readers" before the launch; with
    `stdout=PIPE` the read handles exist only after process creation, so "before
    process work begins" is read as "before any child byte is observed": the pipe
    buffer and the child's blocking write mean no byte is lost in between.

### 2.6 Closed-world guard reconciliation

The merged tree enforces closed sets by exact equality. Every such guard Stage 7
trips is reconciled here, assigned to the task whose work first trips it, and none
is weakened, deleted or replaced by a lower bound. **This section is the single
authority for every guard edit Stage 7 makes to a Stage 1–6 test file.** It was
derived by enumerating every `assert`, parametrize literal and module constant in
the guard files with `ast` (matrix F) and by adding the pins outside those files
that the harness-safety, port-contract, domain-port and doubles modules hold.

**Rule.** A task that creates a module under `src/crypto_lab` appends that module,
in the same commit, to both `_ALLOWED_SOURCE_FILES` in
`tests/safety/test_stage3_boundaries.py` and `PACKAGE_MODULES` in
`tests/unit/test_package_layout.py`. A task that first defines a name held in
`_DEFERRED_DEFINITIONS` removes exactly that name, in the same commit, from the set
and the literal set-equality assertion and decrements the pinned count. A task that
first imports a root outside `_ALLOWED_IMPORT_ROOTS` adds exactly that root, in the
same commit, to the set, to the literal set of
`test_the_import_root_allowlist_is_exactly_the_reviewed_twenty_two` and to its
count. A name or root is never released before the commit that needs it.

**Source-file allowlist.** `_ALLOWED_SOURCE_FILES` is a literal set of 83 paths at
the planning base. Stage 7 adds exactly 12 paths, taking it to 95; the same 12
dotted names join `PACKAGE_MODULES` (in declaration order after
`crypto_lab.process_supervision` and after `crypto_lab.experiments.semantic_outcome`).

<!-- source-files -->
| Task | Paths appended (relative to `src/crypto_lab`) | Running size |
|---|---|---|
| 1 | `process_supervision/cancellation.py`, `process_supervision/deadlines.py` | 85 |
| 2 | `process_supervision/ports.py`, `process_supervision/models.py`, `process_supervision/diagnostics.py` | 88 |
| 3 | `process_supervision/roots.py`, `process_supervision/readers.py` | 90 |
| 4 | `process_supervision/windows_api.py`, `process_supervision/windows_process.py` | 92 |
| 5 | `experiments/supervision_lifecycle.py` | 93 |
| 6 | `process_supervision/supervisor.py` | 94 |
| 7 | `process_supervision/reconciliation.py` | 95 |
<!-- /source-files -->

Every new module is import-side-effect free: `tests/unit/test_package_layout.py`
imports each listed module in a fresh interpreter with `builtins.open`,
`subprocess.Popen`, `os.putenv`, `Path.mkdir`, `Path.exists` and the other
filesystem calls patched to raise, so the long-path probe, Job Object creation,
`ctypes` DLL binding and every file access happen inside functions, never at
import time (`windows_api.py` binds `kernel32` through a module-level
`_KERNEL32: ctypes.WinDLL | None = None` filled on the first call — no
`functools`, which is not an allowed root). The same probe rebinds
`subprocess.Popen` to a plain function before importing, and `asyncio`'s Windows
import chain subclasses `subprocess.Popen` at import time, so `supervisor.py`
imports `asyncio` function-locally inside `invoke` (never at module scope); the
Stage 3 import scan walks every import node, so the root still joins the allowlist
and the confinement pin still names `supervisor.py`. every Stage 7 source module
begins with `from __future__ import annotations` (the repository convention), so
the `subprocess.Popen[bytes]` and `ctypes` annotations of `windows_process.py` and
`windows_api.py` stay unevaluated strings under the probe (which rebinds
`subprocess.Popen` to a plain function before importing); a Pydantic model would
still resolve them, which is why `WindowsLaunchedProcess` is a plain class.

**Deferred-definition guard.** `_DEFERRED_DEFINITIONS` holds 37 names, asserted by
`len == 37` and an exact literal set in
`test_the_deferred_definition_set_is_exactly_the_reviewed_sixty_five` (the test
name is historical and is kept; its docstring arithmetic gains a Stage 7
paragraph), enforced against every `class`/`def` in `src/crypto_lab`, self-tested
per name and by a seven-name representative-mutation list. Stage 7 defines exactly
3 of the 37 and releases each in its defining task; the final count is
`37 − 3 = 34`.

| Task | Names released | Running count |
|---|---|---|
| 1 | `CancellationToken`, `MonotonicInstant` | 35 |
| 2 | `ProcessSupervisor` | 34 |

<!-- released-names -->
Released (3): `CancellationToken`, `MonotonicInstant`, `ProcessSupervisor`.
<!-- /released-names -->

<!-- remaining-names -->
Remaining deferred (34), which no Stage 7 module may define under these exact
names: `ArtifactFinalizationPurpose`, `ArtifactFinalizer`, `ArtifactOwnerKind`,
`ArtifactRef`, `ArtifactRepository`, `ArtifactSourceRole`, `AuditSink`,
`AuditEvent`, `CandidateArtifact`, `CandidateArtifactRepository`,
`CandidateArtifactState`, `CandidateArtifactProducerKind`, `CandidateFinalization`,
`CanonicalFill`, `CanonicalOrder`, `ComparisonEligibilityService`, `ContentHasher`,
`DatasetRepository`, `EquityPoint`, `EvidenceFinalizationRequest`, `Fee`,
`FinalizationResult`, `MetricValue`, `OrderSide`, `OrderType`, `PortfolioSnapshot`,
`PositionSnapshot`, `PositionEffect`, `ResultFinalizationRequest`, `Result`,
`RunManifest`, `ingest_dataset`, `normalize_dataset`, `place_order`.
<!-- /remaining-names -->

`Result` stays the existing `type` alias in `domain/results.py`. The seven-name
representative-mutation list (`test_representative_later_stage_type_mutations_are_
blocked`) contains `ProcessSupervisor`; Task 2 swaps in `ArtifactFinalizer` (still
deferred, not already listed) with the precedent comment shape, so seven live
cases remain. No Stage 7 class or function may take any remaining name: the trace
entry is `SupervisionTraceEntry` (never `AuditEvent`), the observer is
`SupervisionObserver` (never `AuditSink`).

**Import-root allowlist.** `_ALLOWED_IMPORT_ROOTS` is an exact set of 22 roots
(`test_the_import_root_allowlist_is_exactly_the_reviewed_twenty_two`, count and
literal). Stage 7 adds five roots, each in the commit that first imports it, each
confined by the Stage 7 guard (Task 9, `tests/safety/test_stage7_boundaries.py`)
to the exact modules named here; the test name is kept and its docstring gains the
Stage 7 arithmetic.

<!-- import-roots -->
| Task | Root added | Confined to (modules under src/crypto_lab/process_supervision) | Running count |
|---|---|---|---|
| 1 | `threading` | cancellation.py, readers.py, supervisor.py | 23 |
| 3 | `queue` | readers.py | 24 |
| 4 | `ctypes` | windows_api.py | 25 |
| 4 | `subprocess` | windows_process.py | 26 |
| 6 | `asyncio` | supervisor.py | 27 |
<!-- /import-roots -->

`os`, `sys`, `time`, `io`, `shutil`, `tempfile`, `signal`, `stat`, `glob`,
`socket`, `types`, `importlib`, `functools`, `abc`, `math`, `operator`,
`itertools` and `concurrent` are not imported by any Stage 7 module: paths
go through `pathlib` (a merged root); the reparse-point attribute and tag
(`0x400`, `0xA0000003`, `0xA000000C`) and `CTRL_BREAK_EVENT` (`1`) are spelled as
local constants; `math.isfinite` is replaced by the self-comparison of §3.2.

**Stage 5 whole-tree scans** (`tests/safety/test_stage5_boundaries.py`).

| Assertion | Change | Task |
|---|---|---|
| `_INFRASTRUCTURE_ROOTS` (`sqlalchemy`, `sqlite3`, `alembic`, `subprocess`, `random`, `secrets`, `time`) over every `src/crypto_lab` module (`test_no_source_module_imports_an_infrastructure_root`) | A whole-block, label-keyed exemption `_INFRASTRUCTURE_EXEMPTIONS = frozenset({("process_supervision/windows_process.py", "subprocess")})` consulted by `_infrastructure_violations`; a new test `test_the_subprocess_exemption_is_exactly_one_module_and_one_root` asserts the set has one member, that the exempted module really imports the root, that `time` in the same module still fails, that `subprocess` in `process_supervision/windows_api.py` still fails, and that a planted in-memory module (`ast.parse("import subprocess")` labelled `process_supervision/probe.py`; no such repository file exists) still fails. The Stage 6 guard imports `_infrastructure_violations` and applies it to the fourteen Stage 6 labels, none of which is exempt. | 4 |
| `_AMBIENT_CLOCK_READS` and `_environment_access_violations` (whole tree) | unchanged: no Stage 7 module calls `datetime.now`, `utcnow`, `date.today`, or touches `os.environ`/`getenv`/`putenv`/`unsetenv`; `env={}` is a keyword literal | — |
| `STAGE5_SOURCE_FILES` (18) and the filesystem scan over them | unchanged: `domain/ports.py` gains only `from crypto_lab.domain.time import MonotonicInstant` and typing names | — |
| `_OUT_OF_SCOPE_PACKAGES` (`crypto_lab.process_supervision` first) over `experiments` and `adapters`; `scanned >= 12` | unchanged; `scanned` rises to 28 and the scan is what proves `experiments/supervision_lifecycle.py` never imports `process_supervision` | — |
| `_EXPECTED_READER_IMPLEMENTATIONS` (exactly four classes across `src` and `tests` defining both `get` and `get_many`) | unchanged by rule: no Stage 7 class or double defines both; `SeedingDiagnosticRecorder` exposes `record` only | — |
| `test_resolve_causal_closure_is_the_single_traversal_owner` (no `.get_many(` call and no read of `.causal_diagnostic_ids` outside `experiments/retry.py`) | unchanged by rule: Stage 7 passes `causal_diagnostic_ids=` as a keyword and never reads the attribute | — |
| `test_the_roadmap_records_stage_five_approved_and_stage_six_not_started`: imports `_README_STAGE6_STATUS`, asserts it in README and that README minus it contains no `"Stage 8"`, `"Stage 9"`, `"Stage 10"` | import `_README_STAGE7_STATUS` instead and subtract it; the docstring sentence naming the Stage 7 containment becomes Stage 8 | 9 |

**Stage 6 guard** (`tests/safety/test_stage6_boundaries.py`).

| Assertion | Change | Task |
|---|---|---|
| `_FAKE_ADAPTER_ROOTS` (seven), `test_the_fake_adapter_imports_only_its_seven_stdlib_roots`, `"subprocess" not in roots`, `_shell_violations(..., subprocess_importer=False) == []` over `tests/fake_adapters/fake_adapter.py` | unchanged: `fake_adapter.py` is not edited; the Stage 7 scenarios live in `tests/fake_adapters/supervision_fake.py` | — |
| `_SUBPROCESS_IMPORTERS` exactly ten, `len == 10`, `importers == set(...)` over `tests/` and `scripts/` | eleven: `+ "tests/fake_adapters/supervision_fake.py"`; `10` → `11`; docstring and comment updated. No other Stage 7 test module imports `subprocess` (the scripted controller launches nothing; real launches go through `WindowsProcessController`; junctions are created with `_winapi.CreateJunction`; grandchild liveness is checked through `windows_api`) | 8 |
| `_shell_violations` over every test and script file | constraint: the new fake's `Popen` is a list argv with `shell=False`; no string command anywhere | 8 |
| `_TEXT_ONLY_SHELL_FILES` plus this guard: every file under `tests/` whose text contains `os.system` | constraint: no Stage 7 test file, fake or docstring contains that substring | all |
| `_STAGE6_ROADMAP_ROW` last clause `"recorded; Stage 7 not started \|"` | `"recorded; Stage 7 complete \|"` with the precedent comment; the roadmap row changes identically | 9 |
| `test_the_roadmap_records_stage_six_complete_and_stage_seven_not_started`: `_STAGE7_ROADMAP_ROW in roadmap` | becomes `not in roadmap` (the Stage 6 precedent for the Stage 5 guard); the completion row, the Stage 8 deferred row and the plan-approval line are pinned by the Stage 7 guard; test name kept, docstring updated | 9 |
| `_ATTEMPT_TOKEN_CARRIERS` (exactly four classes with an `AttemptToken`-annotated field) | unchanged by rule: no Stage 7 class field is annotated `AttemptToken`; `RequestMaterial.token` is annotated `AttemptTokenMaterial \| MISSING`, the near-miss the scan's own control already excludes | — |
| `_STAGE6_TEST_DOUBLE_ROOTS`, `STAGE6_SOURCE_FILES` (14), planted controls | unchanged | — |

**Stage 3 documentation and status pins** (`tests/safety/test_stage3_boundaries.py`,
`tests/safety/test_gitnexus_development_tooling.py`). Task 9 owns every change
below in the one commit that changes the prose, and introduces
`STAGE7_IMPLEMENTATION_COMMIT` (the Task 8 commit, the last commit that adds Stage 7
behaviour), asserted to match `[0-9a-f]{40}` and to differ from every previously
pinned commit.

| Assertion | Stage 7 successor |
|---|---|
| `_STAGE6_ROADMAP_STATUS_LINE` ("Stages 1 through 6 complete") positive, Stage 5/4 negatives | `_STAGE7_ROADMAP_STATUS_LINE`: "**Status:** Approved planning decomposition; Stages 1 through 7 complete" positive; the Stage 6 line joins the negatives |
| `_STAGE6_ROADMAP_PLAN_SENTENCE` ("Stages 1 through 6 have approved detailed implementation plans.") | "Stages 1 through 7 have approved detailed implementation plans." |
| README status heading `"**Status:** Project 1 Stages 1-6 complete"` and the `1-5`/`1-4` negatives | "**Status:** Project 1 Stages 1-7 complete"; `1-6` joins the negatives |
| `_README_STAGE6_STATUS in readme` | `_README_STAGE7_STATUS` (§9.6 text) positive; `_README_STAGE6_STATUS not in readme` |
| `_VERIFICATION_STAGE6_STATUS in guide` | `_VERIFICATION_STAGE7_STATUS` (§9.6 text, hard-wrapped at 80 columns) positive; `_VERIFICATION_STAGE6_STATUS not in guide` |
| `STAGE6_IMPLEMENTATION_COMMIT in readme / guide / roadmap` | README and guide assert `STAGE7_IMPLEMENTATION_COMMIT` and `STAGE6_IMPLEMENTATION_COMMIT not in readme / guide`; the roadmap keeps both hashes; `earlier` gains `STAGE6_IMPLEMENTATION_COMMIT` in the distinctness chain |
| `"Stage 7" not in readme_rest / guide_rest` after subtracting the Stage 6 blocks and `_VERIFICATION_STAGE7_SENTENCE` | `"Stage 8" not in readme_rest / guide_rest` after subtracting the Stage 7 blocks; `_VERIFICATION_STAGE7_SENTENCE` ("Stage 7 retains physical ancestor reparse-point and volume containment.") keeps its positive pin |
| `test_stage6_completion_status_is_exact` | becomes `test_stage7_completion_status_is_exact` (the Stage 6 precedent), with `STAGE7_PLAN` = this file's path and the "Approved"/"Planned" line pair asserted |
| `test_stage4_plan_approval_status_is_exact` `_STAGE6_ROADMAP_STATUS_LINE in roadmap` | `_STAGE7_ROADMAP_STATUS_LINE in roadmap` |
| `test_gitnexus_development_tooling.py` duplicate pins of the plan sentence and status line | the two Stage 7 successors |
| `_RETIRED_STATUS_PHRASES`, `"exhaustiv" not in ...rest.lower()`, `_VERIFICATION_CORPUS_QUALIFICATION`, `_VERIFICATION_NON_GOALS`, README local-setup block | unchanged; Stage 7 prose reintroduces none and never edits "## Local setup" |

**Other exact pins.**

| File | Assertion | Change | Task |
|---|---|---|---|
| `tests/unit/domain/test_domain_ports.py` | `_public_methods(Clock) == {"now_utc"}`; `not hasattr(Clock, "monotonic")`; `_StoppedClock`/`_NaiveClock` define `now_utc` only; return-type hints | `{"now_utc", "monotonic"}`; `hasattr` positive with a Stage 7 comment; both local doubles gain `monotonic()` returning a constant `MonotonicInstant`; `get_type_hints(Clock.monotonic)["return"] is MonotonicInstant`; new tests: `CancellationToken` is a `Protocol`, `runtime_checkable`, members exactly `{"is_cancellation_requested", "request_cancellation"}`, `not isinstance(object(), CancellationToken)`, `not isinstance(clock, CancellationToken)` | 1 |
| `tests/doubles/experiments.py` | `FixedClock`, `FailingClock`, `CountingClock` define `now_utc` only; the module text may not contain any of the ten substrings `tests/unit/experiments/test_port_contracts.py::test_the_doubles_module_declares_no_thread_sleep_or_random_dependency` forbids (`import threading`, `import time`, `import random`, `sleep(`, `datetime.now`, `uuid4(`, `import sqlite3`, `sqlalchemy`, `import subprocess`, `import socket`) | `FixedClock.monotonic()` returns `MonotonicInstant(seconds=<elapsed>)` from a `float` accumulator that `advance(seconds: float)` moves together with the UTC instant (`timedelta(seconds=seconds)`); the parameter is widened from `int` to `float` in Task 1 so the scripted fixture can advance by `TICK_SECONDS` (an `int` argument still type-checks; every merged caller passes an `int`); a negative value raises `ValueError`; `FailingClock.monotonic` raises `AssertionError`; `CountingClock` gains `monotonic_reads`; `RealtimeMonotonicClock` lives in `tests/doubles/supervision.py` (created in Task 5, extended in Tasks 6 and 8), never here | 1 (clocks), 5, 6, 8 (`supervision.py`) |
| `tests/unit/experiments/test_port_contracts.py` | `isinstance(clock, Clock)` on `FixedClock`; exact member sets of the seven ports | add `clock.monotonic() == MonotonicInstant(0.0)` and `== MonotonicInstant(30.0)` after `advance(30)`; member sets unchanged (`DiagnosticRecorder` is a new protocol in `supervision_lifecycle.py`, not a member of any pinned port) | 1 |
| `src/crypto_lab/adapters/catalog.py:150`, `src/crypto_lab/adapters/events.py:822` | `isinstance(clock, Clock)` at construction | no edit; every clock handed to a catalog or acceptance context has `monotonic()` from Task 1 on | 1 |
| `tests/unit/domain/test_lifecycle_tables.py` | `_AMBIENT_ROOTS`/`_AMBIENT_CALLS` (contains `"monotonic"`) scanned over `domain/ports.py` `ast.Call` nodes; `len(HashingProfile) == 12` | unchanged: `def monotonic(self)` is a `FunctionDef`, and the module contains no call spelled `monotonic(...)`; no new hashing profile | — |
| `tests/unit/domain/test_time.py` | the time-grammar tests | gains new `MonotonicInstant` test functions | 1 |
| `domain/__init__.py` `__all__` (enforced by ruff `F822`/`RUF022` and the fresh-interpreter import of `tests/unit/test_package_layout.py`; `tests/unit/domain/test_domain_capability_contracts.py` covers capability names only and is unchanged) | resolvable, sorted, no duplicates | `CancellationToken` and `MonotonicInstant` join the import list and `__all__` at their `RUF022` positions and resolve | 1 |
| `tests/unit/experiments/test_experiment_service.py` | `len(REQUEST_OPERATIONS) == 17` | unchanged: Stage 7 adds no request model and no operation to `REQUEST_OPERATIONS` | — |
| `tests/unit/adapters/test_adapter_commands.py`, `test_adapter_diagnostics.py`, `test_protocol_limits.py` | `AdapterCommand` field order; `STAGE6_DIAGNOSTIC_CODES` exactly 25; the public constant surface of `adapters/limits.py` | unchanged: Stage 7 adds no field, no Stage 6 code and no constant to `adapters/limits.py` (`FORCED_TERMINATION_EXIT_CODE`, `TICK_SECONDS` and the ceilings live in `process_supervision`) | — |
| `tests/safety/test_stage4_boundaries.py` | `_BARE_FORBIDDEN_NAMES` over every `ast.Name`/`ast.Attribute` in `src`; no `# type: ignore` on import lines | unchanged by rule: no identifier in any Stage 7 module is a member of the 28-name `_BARE_FORBIDDEN_NAMES` set (`buffer`, `context`, `note`, `problem`, `compose`, `Loader` and the yaml-specific names) (the reader's carry-over is `pending_bytes`, the acceptance object is `acceptance`, a trace mapping is `facts`); `ctypes`, `subprocess`, `threading`, `queue`, `asyncio` are typed in typeshed | — |
| `tests/architecture/test_package_import_boundaries.py` | `_ALLOWED_FOR_EXPERIMENTS`, `_ALLOWED_FOR_ADAPTERS`, the prohibitions | unchanged; a new scope-closure test `test_process_supervision_reaches_only_domain_adapters_and_itself` with `_ALLOWED_FOR_PROCESS_SUPERVISION = ("crypto_lab.domain", "crypto_lab.adapters", "crypto_lab.process_supervision")` and `_PROHIBITED_FOR_PROCESS_SUPERVISION` (`experiments`, `strategy`, `capabilities`, `datasets`, `artifacts`, `persistence`, `configuration`, `audit`, `cli`, `schema_registry`), anchored on `crypto_lab.adapters.commands` and `crypto_lab.domain.command_invocation`, plus the scanner self-test | 2 |
| `tests/architecture/test_domain_import_boundary.py` | domain imports no other package | unchanged; forces the placement of §2.3 | — |
| `tests/contract/test_harness_safety.py` | exactly one `subprocess.Popen` call in `harness.py` with keywords `{shell, env, cwd, stdin, stdout, stderr}`, `env` the Name `LAUNCH_ENVIRONMENT`, the `# noqa: S603 - reviewed` line, no `.environ`/`.getenv` attribute; `_ALLOWED_FAKE_ROOTS` (seven) over `fake_adapter.py`; `len(SCENARIOS) == 58`, `PLAN_ROW_COUNT == 52`, per-kind counts 5/8/28/17, `len(ADAPTER_SIDE_VECTORS) == 5`; every scenario name's `catalog_entry_for` entry has `executable_hash == fake_adapter_hash()` and `runtime_metadata == {}`; `written_paths` prefix `runs/<run_id>/work/`, `root.parent == tmp_path`; the harness defines no class named `ProcessSupervisor`, `RunManifest` or `ArtifactRef`; `"stand-in"` in the source | every listed assertion unchanged; Task 8 appends the seam pins (`build_harness(...).supervise is None`, the single-`Popen` re-check through this module's `_popen_calls`/`_HARNESS_PATH`, `command_run.supervision_outcome is None` on the default strategy): the seam adds a strategy object and no launch; the stand-in path keeps the merged entries; the Stage 7 scenarios and entries live in Stage 7 modules; the flat layout keeps the prefix and root pins true on the production path too | 8 |
| `tests/safety/test_forbidden_runtime_paths.py` | no `runtime/`, `artifacts/`, `logs/`, `data/`, `runtimes/` at the repository root | constraint: every supervision root in tests is under `tmp_path` | — |
| `tests/safety/test_uv_launcher.py`, `test_project_dependencies.py`, `test_stage4_yaml_runtime.py`, `tests/unit/test_cli.py` | launcher hash, operations, dependencies, yaml, version | unchanged | — |

**Test-tree rules every Stage 7 test file obeys.** Basename unique across `tests/`
(`prepend` import mode; the merged tree has no `__init__.py` under
`tests/unit/*` or `tests/integration/*`, and Stage 7 adds none; the Stage 7
scenario table is therefore `supervision_scenarios.py`, never a second
`scenarios.py`); no `subprocess`
import outside the eleven; no `os.system` substring; no class defining both `get`
and `get_many`; no new pytest marker; no `pytest.skip`; no supervision root
outside `tmp_path`; every real-process test terminates every identity it launched
in a `finally:` and asserts it is no longer `ALIVE_MATCHING`;
`tests/contract/harness.py` never imports `doubles.supervision` and
`tests/doubles/supervision.py` never imports `contract.harness` (the doubles module
derives the fake script path itself and a test pins it equal to the harness's
`FAKE_ADAPTER_PATH`), so no import cycle can form between them.

**Design rules (no test edit; every task obeys).** Every Stage 7 source module
begins with `from __future__ import annotations` and imports only the roots §2.6
assigns to it; no `# type: ignore[import]`; no pytest marker; no module binds a
string literal to a name ending in `_TOKEN`, `_SECRET` or `_PASSWORD` (ruff S105) —
token-shaped sentinels are built at runtime from `chr(0)` pieces, as the merged
harness does; every `pytest.raises` of a PT011 broad exception (`ValueError`,
`OSError`, `Exception`) carries `match=`; the one `subprocess.Popen` call in `src` carries
`# noqa: S603 - reviewed fixed catalog executable boundary`, `shell=False`, a list
argv, `env={}`, `stdin=subprocess.DEVNULL`, `close_fds=True`,
`creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED` — a
`BinOp(BitOr)` of that `subprocess` attribute and the local name `CREATE_SUSPENDED`
bound to the literal `4` in `models.py`, because the stdlib `subprocess` module
exports no such constant (the child is resumed only after the Job Object
assignment, §8.2) — `bufsize=0`;
every module
docstring avoids the substrings the mirrored purity scan denies (`time.time`,
`random.`, `datetime.now`, `uuid4(`, `os.environ`, `import random`) and the two
the merged port-contract scan denies in every `src` module's text, `import doubles`
and `from doubles` (so a docstring describing the test-resident doubles must
paraphrase); `RUF022` keeps every `__all__` sorted; every `X | MISSING` parameter
is narrowed with `isinstance` before use, and no test compares a typed value with
`is MISSING`/`is not MISSING` directly, nor inside a tuple or container equality
such as `(state, exit) == (CANCELLED, MISSING)` (strict mypy reports a
non-overlapping identity check between the field's type and the `Sentinel`, and
`--strict-equality` checks tuple literals element-wise): tests use
`isinstance` on the present type, or the merged `object`-typed `_missing(value)`
helper idiom.

### 2.7 Toolchain gates

`ruff check` selects `B, DTZ, E, F, I, PT, RUF, S, UP` with only `S101` ignored
under `tests/`; the one `subprocess.Popen` call carries the repository's
`# noqa: S603 - reviewed …` comment and a list argv; `ruff format --check` is
check-only, so formatter output is applied by hand; strict mypy covers `src`,
`tests` and `scripts`, so every `X | MISSING` parameter is narrowed with
`isinstance` up front and every `ctypes` binding is typed through `ctypes.wintypes`
aliases; `pytest-all` runs with coverage over `crypto_lab` only, so the fake
adapter, the harness and the scripted controller are not measured but every Stage 7
source module counts; `pytest-focused` accepts only `-o addopts=`, targets under
`tests/` and a final `-q`; the suite runs with `--strict-markers`, so no new
marker; every new test file has a basename unique across `tests/`.

## 3. Module map and record inventory (matrix A/F/G)

### 3.1 Modules

Twelve new source modules and five edited ones. Every new module is a file under
`src/crypto_lab`; §2.6 tabulates the guard edits each creation trips.

| Module | Responsibility | Imports (project) | Import roots beyond the merged 22 |
|---|---|---|---|
| `process_supervision/cancellation.py` | `ThreadSafeCancellationToken` | `domain.ports` | `threading` |
| `process_supervision/deadlines.py` | `PairedDeadline`, `HeartbeatMonitor`, remaining-interval arithmetic | `domain.time` | — |
| `process_supervision/ports.py` | The six structural ports of §3.4 | `domain`, `adapters` | — |
| `process_supervision/models.py` | The trust-class-P/K records of §3.3, `catalog_launch_arguments`, `parse_creation_identity`, the constants of §6.1 | `domain`, `adapters` | — |
| `process_supervision/diagnostics.py` | The closed Stage 7 code table, `stage7_diagnostic`, `stage7_failure` (§3.5) | `domain`, `adapters.diagnostics` | — |
| `process_supervision/roots.py` | `plan_command_paths`, `PathPreflight`, `probe_long_path_support`, `preflight_command_paths`, `create_command_root`, `write_request_file`, `remove_command_root`, `read_output_file`, `snapshot_written_paths`, `observe_executable` | `domain`, `adapters.catalog`, `adapters.limits`, `process_supervision.models`, `process_supervision.diagnostics` (the two preflight functions mint `PROCESS.PATH_PREFLIGHT_REJECTED` with the ids and instant their caller passes) | — (`pathlib`, `hashlib` are merged roots) |
| `process_supervision/readers.py` | `PipeReader` threads over a bounded queue (each records its `native_thread_id` and counts `put_retries`), `StdoutFramer`, `drain`, `wait_for_chunk` (the only timed wait on a queue, so `queue` stays confined here) | `process_supervision.models` (every constant of §6.1 lives there), `adapters.events` | `threading`, `queue` |
| `process_supervision/windows_api.py` | Typed `ctypes` bindings, bound on first use through a module-level `_KERNEL32: ctypes.WinDLL \| None` (no `functools`): Job Objects, process times, image name, console control events, Toolhelp descendant enumeration, exit codes, `resume_initial_thread` (Toolhelp thread snapshot + `OpenThread(THREAD_SUSPEND_RESUME)` + `ResumeThread` for the suspended launch, §8.2), `cancel_synchronous_io` (`OpenThread` + `CancelSynchronousIo` for a reader blocked in a pipe read) | `process_supervision.models` | `ctypes` |
| `process_supervision/windows_process.py` | `WindowsProcessController`, `WindowsLaunchedProcess` over `subprocess.Popen` and `windows_api` | `process_supervision.{ports,models,windows_api}` | `subprocess` |
| `process_supervision/supervisor.py` | `WindowsProcessSupervisor.invoke`, the supervision loop, terminal mapping, enrichment, cleanup | `process_supervision.{ports,models,diagnostics,roots,readers}` — never `windows_api` or `windows_process`: the one Win32 action the loop needs, cancelling a blocked read, goes through `LaunchedProcess.cancel_read` — plus `adapters.*`, `domain.*` | `asyncio` (imported function-locally inside `invoke`, §2.6), `threading` |
| `process_supervision/reconciliation.py` | `reconcile_invocations` over `ReconciliationSource`, `InvocationLifecycle`, `ProcessController` | `process_supervision.*`, `domain`, `adapters` | — |
| `experiments/supervision_lifecycle.py` | `DiagnosticRecorder` port, `RequestMaterial`, `Stage5InvocationLifecycle`, `semantic_outcome_request_for`, `SUPERVISION_REASON_CODE` | `experiments.*`, `adapters`, `domain` (never `process_supervision`) | — |
| edited `domain/ports.py` | `Clock.monotonic()`, `CancellationToken` | `domain.time` | — |
| edited `domain/time.py` | `MonotonicInstant` | — | — |
| edited `domain/__init__.py`, `experiments/__init__.py`, `process_supervision/__init__.py` | sorted exports (`RUF022`); the package docstring names the Job Object a cleanup mechanism and not a sandbox | — | — |

Naming rule (Stage 4 guard `_BARE_FORBIDDEN_NAMES`): no identifier in any Stage 7
module is `buffer`, `context`, `note`, `problem`, `compose` or `Loader`; the reader's
carry-over is `pending_bytes`, the acceptance object is `acceptance`, a trace
detail mapping is `facts`. No Stage 7 class takes a deferred name (§2.6).

### 3.2 Domain additions

`domain/time.py`:

```python
@dataclass(frozen=True, slots=True, order=True)
class MonotonicInstant:
    """A reading of the process-local monotonic clock, in seconds (spec 14.8)."""

    seconds: float

    def __post_init__(self) -> None:
        if type(self.seconds) is not float or self.seconds != self.seconds:
            raise ValueError("a monotonic instant is a finite float of seconds")
        if self.seconds in (float("inf"), float("-inf")) or self.seconds < 0.0:
            raise ValueError("a monotonic instant is finite and never negative")

    def plus(self, seconds: float) -> MonotonicInstant: ...  # seconds finite, >= 0
    def until(
        self, other: MonotonicInstant
    ) -> float: ...  # other.seconds - self.seconds
```

`MonotonicInstant` is never persisted, serialized, hashed or compared across
restarts (spec 14.8); it is not a Pydantic field anywhere.

`domain/ports.py`:

```python
@runtime_checkable
class Clock(Protocol):
    def now_utc(self) -> datetime: ...
    def monotonic(self) -> MonotonicInstant:
        """The process-local monotonic reading paired with ``now_utc`` (spec 8.2, 14.8)."""


@runtime_checkable
class CancellationToken(Protocol):
    """Spec 8.2, 14.8: an explicit, idempotent cancellation request."""

    def is_cancellation_requested(self) -> bool: ...
    def request_cancellation(self) -> None: ...
```

`MonotonicInstant` is a real module-level import in `domain/ports.py` (a
`TYPE_CHECKING`-only import would break `get_type_hints`). Every merged `Clock`
double gains `monotonic()` in Task 1 (§2.6): `FixedClock` keeps a `float`
elapsed-seconds accumulator that `advance(seconds: float)` moves together with
the UTC instant (the parameter is widened from `int` to `float`; `MonotonicInstant`
accepts only a `float`), `CountingClock` inherits it and counts `monotonic_reads` separately,
`FailingClock.monotonic` raises like `now_utc`, and the two local doubles of
`tests/unit/domain/test_domain_ports.py` return a constant. The new
`tests/doubles/supervision.py` (created in Task 5, extended in Tasks 6 and 8) defines `RealtimeMonotonicClock(FixedClock)`,
whose `monotonic()` returns `MonotonicInstant(time.monotonic() + self.offset)`
(test code may import `time`; `advance_monotonic(seconds)` moves the offset so a
test can push a live deadline) while `now_utc` and `advance` stay `FixedClock`'s;
the integration suites use it so record instants stay deterministic while real
children take real time. It lives outside `tests/doubles/experiments.py` because
that module's text may not contain `import time`.

`process_supervision/cancellation.py`:

```python
class ThreadSafeCancellationToken:
    """Idempotent, thread-safe; ``request_cancellation`` is safe from any thread."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def is_cancellation_requested(self) -> bool:
        return self._event.is_set()

    def request_cancellation(self) -> None:
        self._event.set()
```

### 3.3 Records — `process_supervision/models.py`

Every record is a strict frozen `CanonicalModel` (unknown fields rejected), trust
class P (transient projection) or K (core configuration-shaped), unpublished, with
no envelope version. Absence is `MISSING`, never `None`. No field is annotated
`AttemptToken`.

| Record | Class | Fields and rules |
|---|---|---|
| `ExecutableObservation` | K | `executable_path: AbsoluteLocalExecutablePath`, `expected_hash: Sha256`, `present: bool`, `regular_file: bool`, `reparse_point: bool` (the file itself), `ancestor_reparse_point: bool` (any ancestor up to the drive, the §7.2 walk), `observed_hash: Sha256 \| MISSING` (present iff `present and regular_file and not reparse_point and not ancestor_reparse_point`), `observed_at_utc`; property `verified` = observed hash present and equal to expected |
| `LaunchSpecification` | K | `invocation_id`, `argv: tuple[str, ...]` (`min_length=2`, `argv[0]` an `AbsoluteLocalExecutablePath`, every element non-empty and free of control characters), `cwd: AbsoluteLocalExecutablePath`. **No environment field exists.** |
| `CreationIdentity` | frozen dataclass | `pid: int` (1..4294967295), `creation_100ns: int` (0..2**63−1); `parse_creation_identity(text) -> CreationIdentity` accepts exactly `^windows:[1-9][0-9]{0,9}:(0\|[1-9][0-9]{0,18})$` and refuses the merged fixture shapes (`offline-harness:<pid>`, the ISO-plus-ordinal doubles); `render_creation_identity(pid, creation_100ns) -> str` |
| `ProcessPresence` | `StrEnum` | `ALIVE_MATCHING`, `ALIVE_DIFFERENT_IDENTITY`, `ABSENT`, `UNDETERMINED` |
| `ProcessInspection` | P | `identity: ProcessIdentity`, `presence`, `observed_creation_identity: BoundedText \| MISSING` (present iff alive), `observed_image_path: ExecutablePath \| MISSING`; no instant — the controller has no clock, and the caller stamps its own trace entry |
| `LaunchFailure` | P | `stage: Literal["popen", "open_process", "resume"]`, `os_error_code: int \| MISSING`, `error_class: BoundedText`, `not_found: bool` (`winerror` 2 or 3 at `popen`) — what `ProcessController.launch` returns instead of a process; it carries no `Diagnostic`, because the controller has neither a clock nor the run correlation; the supervisor mints the `FAILED_TO_START` primary from it (§8.2) |
| `InterruptOutcome` | `StrEnum` | `DELIVERED`, `UNAVAILABLE`, `PROCESS_GONE` |
| `CleanupAction` | `StrEnum` | `TREE_VERIFIED_DEAD`, `JOB_CLOSED`, `PROCESS_HANDLE_CLOSED`, `STDOUT_READER_STOPPED`, `STDERR_READER_STOPPED`, `PIPES_CLOSED`, `COMMAND_ROOT_REMOVED` |
| `CleanupFailure` | P | `action: CleanupAction`, `reason: BoundedText` (a closed reason word plus an error number; never adapter bytes or a path) |
| `CleanupReport` | P | `completed: tuple[CleanupAction, ...]` (unique), `failures: tuple[CleanupFailure, ...]` (unique on action, disjoint from `completed`); property `complete` = `failures == ()` |
| `DescendantIdentity` | P | `pid`, `creation_identity: BoundedText`, `image_path: ExecutablePath \| MISSING` |
| `TerminationReport` | P | `forced: bool`, `exit_code_used: int \| MISSING` (present iff forced), `job_terminated: bool`, `descendants: tuple[DescendantIdentity, ...]` (the verified tree snapshot taken before termination), `failures: tuple[CleanupFailure, ...]` |
| `SupervisionTraceKind` | `StrEnum` | `PREFLIGHT_ACCEPTED`, `PREFLIGHT_REFUSED`, `EXECUTABLE_OBSERVED`, `STARTING_COMMITTED`, `REQUEST_WRITTEN`, `LAUNCHED`, `LAUNCH_FAILED`, `PRE_HANDOFF_DEADLINE`, `PRE_HANDOFF_CANCELLATION`, `RUNNING_COMMITTED`, `EVENT_ACCEPTED`, `EVENT_REPLAYED`, `EVENT_REJECTED`, `STDOUT_BYTES_COUNTED`, `HEARTBEAT_MISSED`, `CANCELLATION_OBSERVED`, `INTERRUPT_SENT`, `INTERRUPT_UNAVAILABLE`, `FORCED_TERMINATION`, `EXIT_REAPED`, `TERMINAL_DECIDED`, `TERMINAL_COMMITTED`, `EXTERNAL_TERMINAL_WINNER`, `ENRICHMENT_COMMITTED`, `CLEANUP_ACTION`, `CLEANUP_FAILED`, `WRITE_BOUNDARY_VIOLATION`, `RECONCILIATION_DECISION` |
| `SupervisionTraceEntry` | P | `kind`, `invocation_id`, `sequence: int` (≥ 1, contiguous per invocation), `at_utc`, `monotonic_100ns: int` (≥ 0, `round(instant.seconds * 1e7)` — an integer because the merged canonical JSON forbids floats and the token walk of §11 canonicalises every retained entry), `facts: dict[DiagnosticDetailKey, DiagnosticDetailValue]` (the `Diagnostic.details` bounds through `_inspect_details`; identifiers, counts, codes, state names and the controller-observed image path only — never a stdout, stderr, request or output byte), `rejection: EventRejected \| MISSING` (present exactly on an `EVENT_REJECTED` entry; the sample inside is already redacted by the merged parser) |
| `SupervisionOutcome` | P | `command_result: CommandResult` (spec 8.2 verbatim; `protocol_integrity` is `VIOLATED` iff the decided state is `PROTOCOL_FAILED`; `diagnostics` is every `Diagnostic` the supervisor minted or received for the invocation — the primary, every additional, the parser's rejection diagnostic, a recorded core failure — unique on `diagnostic_id` in first-occurrence order and never a reconciliation diagnostic, the harness's own rule, so the merged row-23 exact list `[PROCESS.STDERR_TRUNCATED]` and the core-won membership assertions hold; `cancelled`/`timed_out` are `state is CANCELLED` / `state is TIMED_OUT` of the decided record, as the merged validator requires), `output_parse: DescriptorParse \| ValidationResultParse \| ManifestParse \| MISSING` (present only for `EXITED` when the file existed and was readable; class matches `invocation.command_kind`; `command_result.parsed_output` equals the parse's strict model when the parse holds one and `parsed_output_source_hash` equals its `source_hash`), `protocol_summary: ProtocolEventSummary` (empty for `DESCRIBE`; `accepted_count == len(command_result.accepted_events)` and `last_sequence` equals the last accepted event's sequence, `0` when none), `stdout_byte_count: int` (≥ 0; zero unless `DESCRIBE`), `replay_count: int` (≥ 0), `executable_observation: ExecutableObservation`, `trace: tuple[SupervisionTraceEntry, ...]` (all naming the invocation, in `sequence` order; the per-event kinds `EVENT_ACCEPTED` and `EVENT_REPLAYED` are delivered to the observers only and never retained here, and `STDOUT_BYTES_COUNTED` is emitted exactly once per `DESCRIBE`, at the terminal decision, with the final `stdout_byte_count` as its single fact, so the outcome stays bounded beside a million-event ledger and a flooding describe alike; no retained kind other than `CLEANUP_ACTION`/`CLEANUP_FAILED` repeats — retained entries keep their emitted `sequence` numbers, so gaps are expected; at most one carries a `rejection`) |
| `RunReconciliationFacts` | K | `run_id`, `experiment_id`, `run_state: EngineRunState`, `run_revision: int`, `attempt_token_hash: Sha256`, `request_hash: Sha256`, `experiment_state: ExperimentState`; property `cancelled` = `experiment_state is CANCELLED or run_state is CANCELLED` |
| `ReconciliationAction` | `StrEnum` | `LEFT_PENDING`, `TERMINALIZED_FAILED_TO_START`, `TERMINALIZED_TIMED_OUT`, `TERMINALIZED_CANCELLED`, `TERMINALIZED_PROTOCOL_FAILED`, `LEFT_RUNNING_AWAITING_DEADLINE`, `CLEANUP_COMPLETED`, `CLEANUP_FAILED`, `CLEANUP_STILL_FAILING`, `INVARIANT_REPORTED`, `SKIPPED_EXTERNAL_WINNER` |
| `InvocationReconciliation` | P | `invocation_id`, `command_kind`, `state_before`, `action`, `record_after: CommandInvocationRecord`, `presence: ProcessPresence \| MISSING` (present iff inspected), `manifest_present: bool \| MISSING` (present iff the action is `LEFT_RUNNING_AWAITING_DEADLINE` on a `RUN`), `diagnostics: tuple[Diagnostic, ...]` (every diagnostic the pass minted, attached or not; a diagnostic of a write-free row is reported here and persisted only when a later pass attaches it) |
| `ReconciliationReport` | P | `supervisor_instance_id: BoundedText`, `started_at_utc`, `entries: tuple[InvocationReconciliation, ...]` (unique invocation ids, source order) |

Deadline and heartbeat values are frozen dataclasses in `deadlines.py`, not
models, because they hold a `MonotonicInstant`:

```python
@dataclass(frozen=True, slots=True)
class PairedDeadline:
    deadline_utc: datetime  # the committed record's deadline_utc
    deadline_monotonic: MonotonicInstant  # monotonic_at_swap.plus(timeout_seconds)
    timeout_seconds: int

    def remaining(
        self, now: MonotonicInstant
    ) -> float: ...  # max(0.0, now.until(deadline_monotonic))
    def passed(self, now: MonotonicInstant) -> bool: ...


class HeartbeatMonitor:  # mutable, one per supervised VALIDATE/RUN
    def __init__(self, *, missing_heartbeat_seconds: int) -> None: ...
    def arm(self, now: MonotonicInstant) -> None: ...
    def reset(self, now: MonotonicInstant) -> None: ...  # on every accepted HEARTBEAT
    def due(self, now: MonotonicInstant) -> bool: ...  # armed and now >= due instant
    def remaining(self, now: MonotonicInstant) -> float: ...

    minted: bool  # set once by the supervisor
```

`CommandPaths` and `PathPreflight` are K records in `roots.py`:

| Record | Fields and rules |
|---|---|
| `CommandPaths` | `command_root`, `request_path`, `output_path \| MISSING`, `work_dir \| MISSING`, `result_path \| MISSING`, all `AbsoluteLocalExecutablePath`; the kind-governed presence rule of `AdapterCommand`; every path lexically under `command_root`; `result_path == work_dir + "\\" + RESULT_MANIFEST_RELATIVE_PATH`; property `directories` (root and work dir) and `files` (the rest) for the ceilings |
| `PathPreflight` | `supervision_root: AbsoluteLocalExecutablePath`, `long_paths_supported: bool`, `directory_ceiling: int` (`DIRECTORY_CEILING_WITHOUT_LONG_PATHS` 247, or `LONG_PATH_CEILING` 1024), `file_ceiling: int` (`FILE_CEILING_WITHOUT_LONG_PATHS` 259, or `LONG_PATH_CEILING` 1024), `probed_at_utc`; the validator accepts exactly the pair keyed on `long_paths_supported` and refuses any other value (32767 included) |

### 3.4 Ports — `process_supervision/ports.py`

All six are `typing.Protocol` classes, `runtime_checkable`, structural, with no
implementation and no I/O. Every parameter and return type reachable from
`InvocationLifecycle` is a `domain` or `adapters` type (never a §3.3 record), so
the `experiments` lifecycle implements it without importing this package; the
other five ports use the §3.3 records freely.

```python
@runtime_checkable
class ProcessSupervisor(Protocol):
    async def invoke(
        self, command: AdapterCommand, cancellation: CancellationToken
    ) -> Result[SupervisionOutcome]: ...


@runtime_checkable
class InvocationLifecycle(Protocol):
    def load(self, invocation_id: InvocationId) -> Result[CommandInvocationRecord]: ...
    def linked_run(
        self, invocation_id: InvocationId
    ) -> Result[EngineRunRecord | MISSING]: ...
    def begin_start(
        self, invocation_id: InvocationId, *, expected_revision: int
    ) -> Result[CommandInvocationRecord]: ...
    def request_envelope(
        self, invocation_id: InvocationId
    ) -> Result[AdapterCommandRequestEnvelope]: ...
    def record_process_start(
        self,
        invocation_id: InvocationId,
        *,
        expected_revision: int,
        process_start: ProcessStartFacts,
    ) -> Result[CommandInvocationRecord]: ...
    def record_terminal(
        self,
        invocation_id: InvocationId,
        *,
        expected_revision: int,
        target_state: CommandInvocationState,
        primary: Diagnostic | MISSING,
        additional: tuple[Diagnostic, ...],
        native_exit_value: NativeExitValue | MISSING,
    ) -> Result[CommandInvocationRecord]: ...
    def enrich(
        self,
        invocation_id: InvocationId,
        *,
        expected_revision: int,
        native_exit_value: NativeExitValue | MISSING,
        cleanup_complete: bool,
        additional: tuple[Diagnostic, ...],
    ) -> Result[CommandInvocationRecord]: ...
    def append_event(self, event: RunEvent) -> Result[RunEvent]: ...
    def resolve_external_winner(
        self,
        invocation_id: InvocationId,
        *,
        expected_revision: int,
        primary: Diagnostic,
    ) -> Result[CommandInvocationRecord | MISSING]: ...


@runtime_checkable
class LaunchedProcess(Protocol):
    @property
    def pid(self) -> int: ...
    @property
    def creation_identity(self) -> str: ...
    @property
    def stdout(self) -> IO[bytes]: ...
    @property
    def stderr(self) -> IO[bytes]: ...
    def wait(self, timeout_seconds: float) -> int | None: ...
    def interrupt(self) -> InterruptOutcome: ...
    def terminate_tree(self, exit_code: int) -> TerminationReport: ...
    def cancel_read(self, native_thread_id: int) -> bool: ...
    def close(self, *, close_stdout: bool, close_stderr: bool) -> CleanupReport: ...
    @property
    def job_available(self) -> bool: ...  # the launch facts the supervisor
    @property
    def job_error_code(
        self,
    ) -> int | MISSING: ...  # mints PROCESS.JOB_OBJECT_UNAVAILABLE
    @property
    def image_path(
        self,
    ) -> ExecutablePath | MISSING: ...  # and the LAUNCHED trace fact from


@runtime_checkable
class ProcessController(Protocol):
    def launch(
        self, specification: LaunchSpecification
    ) -> LaunchedProcess | LaunchFailure: ...
    def inspect(self, identity: ProcessIdentity) -> ProcessInspection: ...
    def terminate_tree(
        self, identity: ProcessIdentity, exit_code: int
    ) -> TerminationReport: ...


@runtime_checkable
class SupervisionObserver(Protocol):
    def observe(self, entry: SupervisionTraceEntry) -> None: ...


@runtime_checkable
class ReconciliationSource(Protocol):
    def list_reconciliation_targets(
        self,
    ) -> Result[tuple[CommandInvocationRecord, ...]]: ...
    def run_facts(self, run_id: RunId) -> Result[RunReconciliationFacts]: ...
```

`resolve_external_winner` (§2.5 reading 22) and `linked_run` are the eighth
and ninth members. The first reloads the invocation, its run and its experiment
and writes `CANCELLED` with the supplied `PROCESS.CANCELLED` primary only when the
run is terminal (alone path) or the experiment is `CANCELLED` (coupled); otherwise
it returns `Success(MISSING)` and writes nothing. The second returns the linked
run's own `EngineRunRecord` (`Success(MISSING)` for a `DESCRIBE`) — a domain
type, so the `experiments` implementation never names a `process_supervision`
record — and the supervisor reads `run_id`, `experiment_id`, `state` and
`revision` from it to correlate every diagnostic it mints before the envelope
exists (§3.5). `LaunchedProcess.cancel_read(native_thread_id)` cancels the
synchronous read a reader thread is blocked in (`OpenThread(THREAD_TERMINATE)` +
`CancelSynchronousIo` behind the port,
so `supervisor.py` never imports `windows_api` and the scripted double can model
the cancellation) and returns whether the call succeeded; `close(close_stdout=...,
close_stderr=...)` closes only the pipe objects whose readers have ended (§8.4). `ProcessController.launch` returns either a
`LaunchedProcess` or a `LaunchFailure` (a plain P record: `stage`,
`os_error_code`, `error_class`, `not_found`), never an exception and never a
`Diagnostic`: the controller has no clock and no run correlation, so the
supervisor mints the `FAILED_TO_START` primary (`ADAPTER.UNAVAILABLE` when
`not_found`, else `PROCESS.LAUNCH_FAILED` with `stage` and `os_error_code` in its
details) with its own clock and the `linked_run` ids; no `Result` ever wraps a
Protocol value, and `inspect` likewise returns an instant-free
`ProcessInspection`. `LaunchedProcess.wait(0.0)` is the poll;
`interrupt`, `terminate_tree`, `cancel_read` and `close` never raise, they report.
`SupervisionObserver.observe` is called on the supervision thread; an exception it
raises is caught and otherwise ignored, so an observer can never alter a terminal
decision. `list_reconciliation_targets` returns every nonterminal invocation and
every terminal with `cleanup_complete=false`, ordered `(created_at_utc,
invocation_id)`; `run_facts` reads the run and its experiment. In Stage 7 the only
implementer of both `ReconciliationSource` and `DiagnosticRecorder` is
`tests/doubles/supervision.py` (`InMemoryReconciliationSource(store)`,
`SeedingDiagnosticRecorder(store)`); Stage 8 implements them in `persistence`.

### 3.5 Diagnostics — `process_supervision/diagnostics.py`

The module mirrors `adapters/diagnostics.py` line for line: a `Stage7DiagnosticPosture`
dataclass, a closed `STAGE7_DIAGNOSTIC_CODES` table of exactly 13 rows, and
`stage7_diagnostic` / `stage7_failure` with the same check order (table lookup;
`run_id` requires `experiment_id`; every `PROCESS.*` row except
`PROCESS.PATH_PREFLIGHT_REJECTED` — a `Failure`-only code, never a persisted
primary, whose `invocation_id` is accepted missing only for the long-path probe of
§7.2, the one minting site with no invocation; the §4.4 command-path rejection
carries the ids the supervisor passes — requires
`invocation_id` unconditionally, the three core literals follow the Stage 5
category rule;
`_inspect_details` before any hash; the identical `DIAGNOSTIC_IDENTITY_V1` payload
— `schema_version`, `error_code`, `category`, `severity`, `source_component`,
`message`, `retriable`, `details`, the present correlation ids, `causal_diagnostic_ids`
as given — so identity excludes `timestamp_utc` and a Stage 7 core-literal
diagnostic equals the Stage 5 one for identical inputs). Merged Stage 6 codes
Stage 7 mints go through `stage6_diagnostic`; the Stage 7 table never repeats a
Stage 6 code.

| Code | Category | Retriable | Severity | Minted by | Role | `details` (deterministic; no path text, no OS message) |
|---|---|---|---|---|---|---|
| `PROCESS.LAUNCH_FAILED` | `ENGINE_RUNTIME` | True | ERROR | supervisor | primary of `STARTING → FAILED_TO_START` (run `→ FAILED`) | `stage` ∈ {`create_root`, `write_request`, `open_readers`, `popen`, `open_process`, `resume`}, `os_error_code` (int or absent), `error_class` |
| `PROCESS.LAUNCH_NOT_COMMITTED` | `ENGINE_RUNTIME` | True | ERROR | reconciler | primary of `STARTING → FAILED_TO_START` after cancellation and deadline are ruled out (run `→ FAILED`) | `launch_attempted_at_utc`, `deadline_utc`, `stored_revision` |
| `PROCESS.PATH_PREFLIGHT_REJECTED` | `USER_CONFIGURATION` | False | ERROR | `roots.py` on behalf of the supervisor (the caller passes `now` and, for the §4.4 command-path check, `invocation_id`/`run_id`/`experiment_id`; the §7.2 probe passes none) | `Failure` only (before the swap); never a persisted primary | `reason` ∈ {`ceiling_exceeded`, `ancestor_reparse_point`, `root_missing`, `root_not_directory`, `root_not_local`}, `path_length`, `ceiling`, `long_path_support` |
| `PROCESS.GRACEFUL_INTERRUPT_UNAVAILABLE` | `ENGINE_RUNTIME` | True | WARNING | supervisor | additional beside `CANCELLED`/`TIMED_OUT` | `os_error_code` |
| `PROCESS.JOB_OBJECT_UNAVAILABLE` | `ENGINE_RUNTIME` | True | WARNING | supervisor | additional, attached at the terminal transition (held until then) | `os_error_code`, `fallback: "toolhelp_descendants"` |
| `PROCESS.FORCED_TERMINATION` | `ENGINE_RUNTIME` | True | WARNING | supervisor, reconciler | additional beside `CANCELLED`/`TIMED_OUT`/`PROTOCOL_FAILED`/`EXITED` or on the enrichment; never a causal id of a timeout primary | `reason` ∈ {`grace_elapsed`, `interrupt_unavailable`, `protocol_failed`, `pre_handoff`, `pipe_holder`, `external_winner`, `reconciliation`}, `exit_code`, `descendants_terminated`, `job_object` |
| `PROCESS.CLEANUP_FAILED` | `ENGINE_RUNTIME` | True | ERROR | supervisor, reconciler | additional (never primary); the enrichment that carries it omits `cleanup_complete` | `cleanup_action` (a `CleanupAction` value), `os_error_code` (int or absent), `error_class` — no revision, no pass counter, so the same failing action recomputes the same id and the record never accumulates ids across passes of the same component (`source_component` is part of the identity, so the first reconciler pass after a live-supervisor failure adds exactly one id; reconciler-to-reconciler repeats are stable) |
| `PROCESS.PID_REUSE_DETECTED` | `ENGINE_RUNTIME` | True | WARNING | reconciler | additional; reported by every pass that observes it and persisted only when attached beside the primary of a terminalizing pass or on a cleanup enrichment | `pid`, `expected_creation_identity`, `observed_creation_identity` |
| `PROCESS.ORCHESTRATOR_RESTART_LOST_SUPERVISION` | `ENGINE_RUNTIME` | True | ERROR | reconciler | primary of `RUNNING → PROTOCOL_FAILED` (run `→ FAILED`); engine-runtime so that spec 15.6's "applies retry policy" stays possible (a `PROTOCOL` category would hard-block; spec 15.2 requires a primary, not a category) | `pid`, `creation_identity`, `supervisor_instance_id`, `tree_terminated` |
| `PROCESS.WRITE_BOUNDARY_VIOLATION` | `ENGINE_RUNTIME` | True | WARNING | supervisor | additional on the enrichment (§1.5 item 2) | `stray_path_count` |
| `CORE.INVARIANT_VIOLATION` | `INTERNAL_INVARIANT` | False | ERROR | supervisor, reconciler | `Failure` only, or the primary of a `FAILED_TO_START` after the swap (envelope disagreement, existing root); the reconciler's `INVARIANT_REPORTED` diagnostic | per site |
| `CORE.IMMUTABLE_INPUT_MISMATCH` | `INTERNAL_INVARIANT` | False | ERROR | supervisor | primary of `STARTING → FAILED_TO_START` when the executable is present but is not a regular file, is a reparse point, has a reparse-point ancestor, or its SHA-256 differs (run `→ FAILED`); an **absent** executable is not this code (§2.5 reading 3) | `reason` ∈ {`not_regular_file`, `reparse_point`, `ancestor_reparse_point`, `hash_mismatch`} (`observed_hash` present only for `hash_mismatch`), `expected_hash`, `observed_hash` (absent when unreadable) |
| `PERSISTENCE.CONCURRENCY_CONFLICT` | `PERSISTENCE` | True | ERROR | none (table parity with `experiments.diagnostics` only) | never minted by Stage 7 code: a lifecycle `Failure` carrying it is returned unchanged (§5.3) | — |

Merged codes Stage 7 mints through `stage6_diagnostic` with their merged postures:
`ADAPTER.UNAVAILABLE` (`ADAPTER_UNAVAILABILITY`, retriable, ERROR: the primary of
`STARTING → FAILED_TO_START` when the executable is absent or `CreateProcess`
fails with `ERROR_FILE_NOT_FOUND`/`ERROR_PATH_NOT_FOUND`; the merged coupled
mapping then moves a linked run `→ UNAVAILABLE`; because the merged factory does
not force correlation for this category, the supervisor passes `invocation_id`
and, for a linked kind, `run_id` and `experiment_id`, which a Stage 7 test pins;
`details` = {`reason` ∈ {`executable_absent`, `create_process_not_found`},
`os_error_code` when present}), `PROCESS.MISSING_HEARTBEAT` (once, `TIMEOUT`, WARNING, retriable), `PROCESS.STDERR_TRUNCATED`
(every terminal whose fold truncated, `ENGINE_RUNTIME`, WARNING),
`PROCESS.UNRECOGNIZED_PROCESS_EXIT` (primary of an unrecognized `EXITED`, recorded
before the swap because the merged operation reads it back), `PROCESS.DESCRIBE_TIMED_OUT`
/ `PROCESS.VALIDATE_TIMED_OUT` / `PROCESS.START_TIMED_OUT` / `PROCESS.RUN_TIMED_OUT`
(kind primaries of `TIMED_OUT`; `START_TIMED_OUT` only for a `STARTING`-origin RUN,
the describe and validate kinds keep their one code from either origin), and
`PROCESS.CANCELLED`. The parser's rejection diagnostic (five `PROTOCOL.*` codes or
`ARTIFACT.PATH_BOUNDARY_VIOLATION`) is the `PROTOCOL_FAILED` primary and is
recorded as received. `source_component` is `process_supervision.supervisor` or
`process_supervision.reconciliation`; because the component is part of the
identity, no Stage 6 test pins a `diagnostic_id` value (they pin codes) and none
breaks under the production path.

The correlation rule: every diagnostic the supervisor or the reconciler mints for
a `VALIDATE` or `RUN` invocation carries `run_id` and `experiment_id` — the
supervisor takes them from the `EngineRunRecord` that `linked_run` returns right after `load` and
before preflight (§6.3), so the pre-envelope primaries of §6.4 rows 1–2 and the
absent-executable `FAILED_TO_START` carry them too; the reconciler takes them from
`RunReconciliationFacts` — and a `DESCRIBE` diagnostic carries `invocation_id`
only. The one exception is the merged parser's rejection diagnostic, which
`parse_protocol_line` mints with `invocation_id` only and which is recorded as
received.
Callers pass `causal_diagnostic_ids` sorted and unique. `stage7_failure` wraps one
diagnostic in a `Failure`. Tests assert the three core literals equal the
`experiments.diagnostics` constants, that `stage7_diagnostic` and
`stage5_diagnostic` produce identical objects for those codes, that
`set(STAGE7) & set(STAGE6) == set()`, `len(STAGE7) == 13`, the hard-block column
equals the merged `domain/retry.py` partition, every `PROCESS.*` row but
`PROCESS.PATH_PREFLIGHT_REJECTED` refuses a missing `invocation_id` (and that one
accepts it), identity is content-only, and the module reads no clock.

### 3.6 The lifecycle module — `experiments/supervision_lifecycle.py`

```python
SUPERVISION_REASON_CODE: Final = "SUPERVISION.TRANSITION"


@runtime_checkable
class DiagnosticRecorder(Protocol):
    """Record one minted diagnostic before the swap that references it (Stage 8
    persists it; the in-memory double seeds it). Idempotent on ``diagnostic_id``:
    an identical re-record is accepted and the first instance kept."""

    def record(self, diagnostic: Diagnostic) -> Result[None]: ...


class RequestMaterial(CanonicalModel):
    """What the lifecycle needs to build one request envelope after STARTING (K,
    transient; token-bearing by containment for VALIDATE/RUN)."""

    describe_payload: DescribeRequestPayload | MISSING = MISSING
    token: AttemptTokenMaterial | MISSING = MISSING
    negotiated_versions: NegotiatedVersions | MISSING = MISSING
    limits: ProtocolLimits | MISSING = MISSING
    # exactly one of: describe_payload alone, or token + negotiated_versions + limits


class Stage5InvocationLifecycle:
    def __init__(
        self, *, unit_of_work: UnitOfWork, clock: Clock, diagnostics: DiagnosticRecorder
    ) -> None: ...
    def register_request_material(
        self, invocation_id: InvocationId, material: RequestMaterial
    ) -> None: ...

    # the nine InvocationLifecycle methods of §3.4, per the effects table of §5.1


def semantic_outcome_request_for(
    *,
    command_result: CommandResult,
    output_parse: ValidationResultParse | ManifestParse | MISSING,
    protocol_summary: ProtocolEventSummary,
    run: EngineRunRecord,
    candidate_observations: tuple[CandidateObservation, ...],
    negotiated_versions: NegotiatedVersions,
) -> SemanticOutcomeRequest: ...
```

The helper takes the outcome's fields rather than the `SupervisionOutcome`
itself, because `experiments` may not import `process_supervision`; the caller
unpacks the outcome into those arguments.

`Stage5InvocationLifecycle` reads no clock of its own beyond the injected one and
never reads `causal_diagnostic_ids`; it records exactly the `Diagnostic` objects it
receives (primary, additional, and the causal referents the supervisor passes
alongside them) in the order given, each before the swap. `semantic_outcome_request_for`
is pure (§5.4) and raises `ValueError` unless `command_result.invocation.state is
EXITED` and the kind is `VALIDATE` or `RUN` (the merged operation applies a
semantic outcome to an `EXITED` invocation only), or for a parse whose class does
not match the invocation's kind.

## 4. Launch inputs and ownership (matrix A)

### 4.1 The launch-input table

Ownership: **caller** = whoever builds the `AdapterCommand` (Stage 10 or a test);
**lifecycle** = `Stage5InvocationLifecycle`; **supervisor** = `WindowsProcessSupervisor`;
**controller** = `WindowsProcessController`.

| # | Input | Source of truth | Chosen by | Validated | Failure |
|---|---|---|---|---|---|
| 1 | argv[0], the executable | `catalog_entry.executable_path` (`AbsoluteLocalExecutablePath`) | caller (catalog entry inside the command) | supervisor, before the swap: regular file, no reparse point on it or any ancestor, SHA-256 of its bytes equals `executable_hash` (`ExecutableObservation`) | absent → `STARTING → FAILED_TO_START` with `ADAPTER.UNAVAILABLE` (run `→ UNAVAILABLE`); not regular, reparse (the file or any ancestor), hash differs → `FAILED_TO_START` with `CORE.IMMUTABLE_INPUT_MISMATCH` (run `→ FAILED`) |
| 2 | fixed launch arguments | `catalog_entry.runtime_metadata["launch_arguments"]` (§4.2) | caller | supervisor, before the swap: absent, or a list of 0..16 non-empty strings without control characters | any other shape → `Failure(CORE.INVARIANT_VIOLATION)`, nothing changed |
| 3 | verb, `--request`, `--output` / `--work-dir` / `--result` | `argument_array(command)` exactly (spec 14.1) | rendered by the merged function | shape by `AdapterCommand`'s validator; paths re-derived by `plan_command_paths` and compared | a path differing from the layout → `Failure(CORE.INVARIANT_VIOLATION)` |
| 4 | `cwd` | `command_root` | supervisor | exists after creation; ≤ the directory ceiling | ceiling → `PROCESS.PATH_PREFLIGHT_REJECTED` (`Failure` before the swap) |
| 5 | environment block | `env={}` always | controller (no field exists) | the Stage 7 guard's AST pin on the one `Popen` call; `fake.argv-echo` echoes its environment key list on stderr and the §10 test asserts the planted parent sentinel, `PATH`, `SYSTEMROOT` and `USERPROFILE` are absent (two host-injected names may be present) | — |
| 6 | `stdin` | `subprocess.DEVNULL` | controller | AST pin | — |
| 7 | `stdout`, `stderr` | `subprocess.PIPE`, binary (`bufsize=0`, no `text`/`encoding`/`errors`) | controller | AST pin; `BoundedStderrCapture.feed` refuses non-bytes | — |
| 8 | `creationflags` | `subprocess.CREATE_NEW_PROCESS_GROUP \| CREATE_SUSPENDED` (the local `models.py` constant `0x00000004`, absent from the stdlib module; the child is resumed only after the job assignment, §8.2) | controller | AST pin | — |
| 9 | `close_fds` | `True` (only the three std handles are inherited) | controller | AST pin | — |
| 10 | Job Object | created and assigned right after `Popen` (§8.2) | controller | `IsProcessInJob` after assignment | attach failure → `PROCESS.JOB_OBJECT_UNAVAILABLE` additional, Toolhelp fallback |
| 11 | request file bytes | `request_envelope_bytes(lifecycle.request_envelope(invocation_id))` | lifecycle builds, supervisor writes (`"xb"`) | envelope header agreement with the record (§4.3) | disagreement → `FAILED_TO_START` with `CORE.INVARIANT_VIOLATION` |
| 12 | command root and work directory | `plan_command_paths` (§7.1) | supervisor creates | preflight (§7.2) | creation failure after the swap → `FAILED_TO_START` with `PROCESS.LAUNCH_FAILED` (`stage: create_root`) |
| 13 | process facts at the handoff | `ProcessStartFacts(pid_identity=ProcessIdentity(pid, creation_identity=windows:<pid>:<creation>, executable_path=entry.executable_path, executable_hash=entry.executable_hash, supervisor_instance_id), process_started_at_utc=clock.now_utc())` | controller supplies pid and creation identity; supervisor builds the facts | record co-occurrence rules | lost swap → §5.3 |
| 14 | `ProtocolLimits` | validate/run: `envelope.payload.configuration_snapshot.limits`; describe: constructor `describe_limits` | lifecycle material / supervisor constructor | `ProtocolLimits` validator | — |
| 15 | grace period | constructor `cancellation_grace_seconds` (0..300, default 10) | supervisor constructor | bound checked at construction | `ValueError` at construction |

### 4.2 Fixed launch arguments

`catalog_launch_arguments(entry: AdapterCatalogEntry) -> tuple[str, ...]` in
`process_supervision/models.py` (named apart from the harness's
`launch_arguments(command)`, which the Task 8 strategy module imports beside it) is
pure: it reads `entry.runtime_metadata.get(
LAUNCH_ARGUMENTS_KEY)` (`LAUNCH_ARGUMENTS_KEY = "launch_arguments"`); a missing key
is `()`; a list of at most `MAX_LAUNCH_ARGUMENTS = 16` non-empty strings without
control characters is returned as a tuple; anything else raises `ValueError`,
which the supervisor's preflight turns into `Failure(CORE.INVARIANT_VIOLATION)`.
The complete array is `(entry.executable_path, *catalog_launch_arguments(entry),
*argument_array(command))`. For the fake adapters the Stage 7 test helper
`supervised_catalog_entry_for(adapter_name, *, script=None, executable=None)`
(`tests/doubles/supervision.py`; `script` overrides the name-based script choice,
`executable` replaces `sys.executable` and the hash is computed from that file)
builds `AdapterCatalogEntry(executable_path=str(Path(sys.executable)),
executable_hash=sha256_bytes(Path(sys.executable).read_bytes()),
runtime_metadata={"launch_arguments": ["-I", "-B", str(<script>)]}, ...)` where
`<script>` is `FAKE_ADAPTER_PATH` for the 52 Stage 6 names and
`SUPERVISION_FAKE_PATH` for the Stage 7 names; the merged `catalog_entry_for`
(script path, empty metadata) stays for the stand-in path. `sys.executable` is the
venv launcher, a real Win32 image whose bytes are hashed; it spawns the base
interpreter as a grandchild inside its own job (silent-breakaway), which is why
the supervisor's own job — not the launcher's — is what contains every process
the fake creates (§8.2).

### 4.3 Envelope agreement

Before writing `request.json` the supervisor checks the envelope the lifecycle
returned against the `STARTING` record and the command: `envelope.invocation_id ==
record.invocation_id`, `envelope.command is record.command_kind`,
`envelope.timeout_seconds == record.timeout_seconds`, `envelope.created_at_utc ==
record.launch_attempted_at_utc`, `envelope.deadline_utc == record.deadline_utc`,
and for a run payload `command.work_dir` ends with the envelope's
`assigned_work_dir.relative_path` under `command_root`. The merged builder already
guarantees the first five; the check is what makes a lifecycle bug a
`FAILED_TO_START` with `CORE.INVARIANT_VIOLATION` instead of an adapter exit `10`.

### 4.4 Structural preflight (no record changed)

In order: the command's `invocation_id` names a record the lifecycle can load; the
loaded record is `PENDING` (`invoke` takes the record and its revision from
`lifecycle.load` and refuses any other state); `command.command_kind
is record.command_kind`; `command.timeout_seconds == record.timeout_seconds`;
`(catalog_entry.adapter_name, adapter_version) == (record.adapter_name,
record.adapter_version)`; `catalog_launch_arguments(entry)` decodes; every command path
equals `plan_command_paths(...)`; the paths pass `preflight_command_paths(paths,
preflight, now=clock.now_utc(), invocation_id=record.invocation_id, run_id=<the
linked run's>, experiment_id=<its experiment's>)` (ids `MISSING` for a `DESCRIBE`),
so the rejection carries the correlation of §3.5. A
failure returns `Failure` with `CORE.INVARIANT_VIOLATION` (shape, identity,
layout) or `PROCESS.PATH_PREFLIGHT_REJECTED` (ceiling, reparse ancestor, root
missing) and a `PREFLIGHT_REFUSED` trace entry; nothing is written.

Inside `begin_start`, still before the swap (spec 15.1 step 1), the lifecycle
revalidates the caller's material and the parent's eligibility: a
`RequestMaterial` must be registered; for a linked kind `material.token.run_id ==
run.run_id`, `attempt_token_hash(material.token.attempt_token) ==
run.attempt_token_hash`, and `build_engine_run_request(run=..., experiment=...,
token=material.token, negotiated=material.negotiated_versions,
limits=material.limits, created_at_utc=<a provisional clock instant>)` must
succeed with a `request_hash` equal to `record.request_hash` (for a `DESCRIBE`,
the describe payload's request hash must equal `record.request_hash` as
`build_request_envelope` computes it); and `experiment.state` must not be
`CANCELLED` (a cancelled parent is a refusal that the supervisor's §5.3
classification turns into `resolve_external_winner`'s coupled `PENDING →
CANCELLED`, the reading-22 outcome). Any mismatch is
`Failure(CORE.INVARIANT_VIOLATION)` with the pair left `(PENDING, READY)` or
`(PENDING, VALIDATING)`; the post-swap agreement check of §4.3 and the
`request_envelope` failure of §5.3 remain as defences.

## 5. The lifecycle port and its transition effects (matrix B)

### 5.1 `Stage5InvocationLifecycle` method by method

Every method is one `run_operation` call (or one unit of work for `append_event`
and `load`), with `reason_code = SUPERVISION_REASON_CODE = "SUPERVISION.TRANSITION"`
on every transition request (an opaque, unpersisted label, the harness's
`HARNESS.STEP` pattern) and every diagnostic the call references recorded through
`DiagnosticRecorder.record` (idempotent on identity) before the swap.

| Method | Kind | Merged operation and request | Preconditions the operation enforces | Run edge |
|---|---|---|---|---|
| `begin_start` | DESCRIBE, VALIDATE | after the pre-swap revalidation of §4.4 (material and parent), `transition_invocation(InvocationTransitionRequest(target_state=STARTING, expected_revision, reason_code, diagnostic_ids=()))`; for VALIDATE the lifecycle first loads the run and refuses (`Failure(CORE.INVARIANT_VIOLATION)`) unless it is `VALIDATING`, because the merged operation reads no run for this target (a terminal run is then the external-run-winner path of §5.3) | `PENDING → STARTING` edge; revision; launch facts established from the injected clock | none |
| `begin_start` | RUN | after the pre-swap revalidation of §4.4 (material and parent), `begin_linked_launch(LinkedLaunchRequest(invocation_id, expected_invocation_revision, run_id, expected_run_revision))` (the lifecycle loads the run for its revision) | pair `(PENDING, READY)`; both revisions; replay when `(STARTING, STARTING)` | `READY → STARTING` (`LINKED_LAUNCH`) |
| `request_envelope` | all | `build_request_envelope(invocation=<STARTING record>, payload=<registered material>)`; for VALIDATE/RUN the payload is `build_engine_run_request(run=..., experiment=..., token=material.token, negotiated=material.negotiated_versions, limits=material.limits, created_at_utc=record.launch_attempted_at_utc)` | the merged builder's own rules (state `STARTING`, kind pairing, request-hash agreement, token hash equals the run's) | none |
| `record_process_start` | DESCRIBE, VALIDATE | `transition_invocation(target_state=RUNNING, process_start=facts, ...)` | `STARTING → RUNNING`; process facts established exactly here | none |
| `record_process_start` | RUN | `start_linked_run(LinkedStartRequest(..., process_start=facts))` | pair `(STARTING, STARTING)`; replay only with identical facts | `STARTING → RUNNING` (`LINKED_LAUNCH`) |
| `record_terminal(EXITED, native_exit_value=v, primary, additional)` | all | `transition_invocation(target_state=EXITED, native_exit_value=v, primary_diagnostic_id=<the recorded `PROCESS.UNRECOGNIZED_PROCESS_EXIT` diagnostic's id when `v` is not in `RECOGNIZED_NATIVE_EXIT_VALUES`, else MISSING>, diagnostic_ids=sorted unique ids of primary + additional)` | `RUNNING → EXITED`; an unrecognized value requires the `PROCESS.UNRECOGNIZED_PROCESS_EXIT` primary, read back through the reader (recorded first) | none (EXITED couples nothing) |
| `record_terminal(CANCELLED \| TIMED_OUT \| PROTOCOL_FAILED \| FAILED_TO_START, primary, additional)` | DESCRIBE | `transition_invocation(target_state=..., primary_diagnostic_id=primary.diagnostic_id, diagnostic_ids=...)` | the edge from the stored state; the record's shape (launch facts for every state but a `PENDING`-origin `CANCELLED`; `process_created` per origin) | none |
| same | VALIDATE, RUN, run non-terminal | `transition_invocation_and_run(CoupledTransitionRequest(invocation=<as above>, run=RunTransitionRequest(run_id, expected_revision=<run revision>, target_state=<coupled target>, reason_code, primary_terminal_diagnostic_id=primary.diagnostic_id, availability_observation_id=<see below>)))`; coupled target: `CANCELLED → CANCELLED`, `TIMED_OUT → TIMED_OUT`, `PROTOCOL_FAILED → FAILED`, `FAILED_TO_START → UNAVAILABLE` iff the recorded primary's category is `ADAPTER_UNAVAILABILITY` else `FAILED` (the operation computes and checks it; the lifecycle restates it from the primary it was handed). `availability_observation_id` is `MISSING` for every target except `UNAVAILABLE`; for an `UNAVAILABLE` target it is `MISSING` for a `RUN` (the `READY`-time observation is carried) and, for a `VALIDATE`, the slot's frozen observation identity read from the experiment's `slot_compatibility` for `run.logical_slot_id` (the Stage 6 operation's own rule for `UNAVAILABLE`) | not a mixed running pair; the run edge exists from the run's actual state (`VALIDATING → *`, `READY → CANCELLED`, `STARTING → *`, `RUNNING → *`); both revisions; `FAILED_TO_START`'s primary read back through the reader | the coupled edge (`GENERIC`) |
| same | VALIDATE, RUN, run already terminal | `transition_invocation` alone (the merged operation admits a coupled target when the linked run is terminal); chosen by the lifecycle from the reloaded `run.state in TERMINAL_ENGINE_RUN_STATES`, never from a failure message | invocation edge; shape | none (the run stays as the core left it) |
| `enrich(native_exit_value, cleanup_complete, additional)` | all | `enrich_invocation(InvocationEnrichmentRequest(expected_revision, native_exit_value=<v or MISSING>, cleanup_complete=<True or MISSING>, stderr_artifact_id=MISSING, additional_diagnostic_ids=<ids not already on the record>))` | stored terminal; at least one new fact; never an overwrite; `FAILED_TO_START` never receives an exit pair | none |
| `append_event(event)` | VALIDATE, RUN | one transaction: `engine_runs.append_event(event)`; commit | idempotent on identical `(invocation_id, sequence, content_hash)`; conflict otherwise | none |
| `resolve_external_winner(primary)` | all | reload the invocation, the run (linked kinds) and the experiment; when the run is in `TERMINAL_ENGINE_RUN_STATES` → `transition_invocation(target_state=CANCELLED, primary_diagnostic_id=primary.diagnostic_id, ...)` alone; when the experiment is `CANCELLED` and the run is not terminal → the coupled `CANCELLED` request of the row above; otherwise return `Success(MISSING)` and write nothing (a `DESCRIBE` has no run and no experiment, so it always returns `MISSING`) | the invocation edge from `PENDING` or `STARTING`; the record's shape | `→ CANCELLED` only in the coupled branch |
| `load(invocation_id)` | all | one transaction: `command_invocations.get` | — | none |
| `linked_run(invocation_id)` | all | one transaction: `command_invocations.get`, then `engine_runs.get(record.run_id)` for a linked kind; returns that `EngineRunRecord` (the supervisor reads `run_id`, `experiment_id`, `state`, `revision`), or `Success(MISSING)` for a `DESCRIBE` | the record exists; a linked record's run exists | none |

`register_request_material(invocation_id, material)` stores a `RequestMaterial`
in memory for the invocation (a `DescribeRequestPayload`, or an
`AttemptTokenMaterial` with the negotiated versions and limits that were used at
attempt creation, so the merged request-hash agreement holds); the lifecycle
keeps it until the invocation's terminal write (`record_terminal` and
`resolve_external_winner` drop it), so `request_envelope` is repeatable and pure
over the same record and material. It is never persisted or logged; the
lifecycle hashes its token only for the pre-swap agreement check of §4.4 and never
stores or emits that hash.

### 5.2 The coupled target table (merged behaviour, restated)

| Invocation target | Condition | Run target | Run pre-states with an edge |
|---|---|---|---|
| `FAILED_TO_START` | primary category `ADAPTER_UNAVAILABILITY` | `UNAVAILABLE` | `VALIDATING`, `READY` (VALIDATE); `STARTING` (RUN; the READY-time observation is carried) |
| `FAILED_TO_START` | any other category | `FAILED` | `VALIDATING`; `STARTING` |
| `TIMED_OUT` | — | `TIMED_OUT` | `VALIDATING`; `STARTING` beside `STARTING`, `RUNNING` beside `RUNNING` |
| `CANCELLED` | — | `CANCELLED` | `VALIDATING`; `READY` beside `PENDING`, `STARTING` beside `STARTING`, `RUNNING` beside `RUNNING` |
| `PROTOCOL_FAILED` | — | `FAILED` | `VALIDATING`; `RUNNING` |
| `EXITED` | — | none | refused by the coupled operation |

The `UNAVAILABLE` row is reached by the supervisor when the executable is absent
(§2.5 reading 3) and by the Task 5 unit tests that drive the lifecycle with an
`ADAPTER.UNAVAILABLE` primary for both a `RUN` (carried observation) and a
`VALIDATE` (the slot's frozen observation supplied by the lifecycle), proving the
restatement agrees with the merged mapping. The `READY (VALIDATE)` cell is a
merged edge the supervisor's own flow never reaches.

### 5.3 The lost-swap and failure rule

After any `Failure` from `begin_start`, `record_process_start` or
`record_terminal`, the supervisor calls `load` and classifies by the stored record;
the external-run-winner row applies only to `begin_start` and
`record_process_start` failures. A refused `record_terminal` is never followed by
a cancellation attempt. It is re-issued exactly once, and only when the reload
shows the invocation unchanged at the expected revision and the linked run now
terminal — the narrow race in which an external `transition_run` landed between
the lifecycle's own reload of the run and the coupled swap (the merged coupled
operation refuses with `CORE.INVARIANT_VIOLATION` or
`PERSISTENCE.CONCURRENCY_CONFLICT`; spec 15.2 sanctions one reread) — and the
lifecycle then takes its alone path from the reloaded run state, never from the
failure code. Any other refusal, or a second failure, is a defect of the request:
the record stays nonterminal for reconciliation, which terminalizes it through the
§8.5 rows when a run edge exists and otherwise reports it (`INVARIANT_REPORTED`,
which now covers a `VALIDATE` beside a run that is neither `VALIDATING` nor
terminal, such as the `READY` example below, whose only surviving edge is a
cancellation) until the experiment or run is cancelled (spec 15.6's "fails
safely" is stated for a RUN-kind mixed pair; the VALIDATE case is the plan's
extension), and no false `EXITED` or success
state can follow:

| Stored record | Classification | Supervisor action |
|---|---|---|
| terminal | external winner (a same-state winner surfaces as `PERSISTENCE.CONCURRENCY_CONFLICT`, a different terminal as `CORE.INVARIANT_VIOLATION`; the code is not consulted) | if a child was launched: forced tree termination, drain, cleanup; then, when the stored record is a `RUNNING`-origin terminal (`process_created=True`) that lacks a native exit pair, one `enrich` with the reaped pair and cleanup facts (a `STARTING`-origin winner never receives the unowned child's exit, reading 7: cleanup facts only); return `Success(SupervisionOutcome)` over the stored record with an `EXTERNAL_TERMINAL_WINNER` trace entry; for a `PENDING`-origin winner (cancelled before `begin_start`) nothing was launched and the outcome carries the stored record |
| nonterminal at the expected state and revision after `begin_start` or `record_process_start`, and `resolve_external_winner(PROCESS.CANCELLED primary)` returns a record | external run winner (§2.5 reading 22: the linked run is terminal — for example cancelled or timed out by `transition_run` before or during the launch — or the experiment is `CANCELLED`, so the merged linked operations refused; the lifecycle wrote the invocation's own `PENDING`/`STARTING → CANCELLED`) | forced tree termination if a child was launched, cleanup, the single enrichment, `Success` over the `CANCELLED` record with an `EXTERNAL_TERMINAL_WINNER` trace entry |
| nonterminal at the expected state and revision after `begin_start` or `record_process_start`, and `resolve_external_winner` returns `MISSING`; or any `record_terminal` failure with a nonterminal stored record | own-request defect (an unrepresentable request: `updated_at_utc` moved backwards, more than 64 diagnostic ids, a shape the record refuses; or a `VALIDATE` whose run an orchestrator moved to `READY`; or the run-moved race of the preamble after its single re-issue also failed) | forced tree termination if launched, cleanup, return the original `Failure` unchanged; the record stays nonterminal and is a reconciliation target |
| nonterminal after `begin_start` or `record_process_start`, but at a state other than the one the call expected (`PENDING` for `begin_start`, `STARTING` for `record_process_start`) or at a moved revision | another actor's write (not reachable with one supervisor per invocation, which is all Stage 7 deploys; noted, never retried — a re-issue with the original revisions is a stale-revision conflict, and a re-issue with the reloaded revisions would be accepted as a replay and make this supervisor the owner of a launch it did not perform, the opposite of spec 15.2's "the loser rereads without overwriting the winner"; neither is attempted) | forced tree termination if a child was launched (trace-only, there is no record to attach to), cleanup, return the original `Failure` |
| any stored record after a `Failure` from `enrich` | lost enrichment swap (reload once; never a second write) | when the reloaded record already carries every fact the call would add, the outcome uses it; otherwise the reloaded record is returned with an `EXTERNAL_TERMINAL_WINNER` trace entry and, while `cleanup_complete` is still false, it stays a reconciliation target (`test_a_lost_enrichment_swap_reloads_once_and_leaves_a_reconciliation_target`, Task 6) |

A `Failure` from `enrich` is the last row of the table (reload once, never a
second write). A `Failure`
from `append_event` while `RUNNING` is the orchestrator cancellation of §2.5
reading 8; after the terminal decision it stops parsing and becomes an additional
diagnostic on the enrichment. A `Failure` from `request_envelope` (a defence: the
same material agreement was already verified before the swap, §4.4) is
`FAILED_TO_START` with `CORE.INVARIANT_VIOLATION`, because the record is already
`STARTING`.

### 5.4 What `apply_command_semantic_outcome` receives

`semantic_outcome_request_for(command_result=outcome.command_result,
output_parse=outcome.output_parse, protocol_summary=outcome.protocol_summary,
run=<stored run>, candidate_observations=..., negotiated_versions=...)` builds the
seventeenth Stage 5 request exactly as the harness does: `parsed_output =
output_parse` (a `ValidationResultParse` or `ManifestParse`, present only for
`EXITED`; a `DescriptorParse` is refused by the parameter type), `protocol_summary`
as given, `protocol_failure = MISSING` (lawful because the helper is called for
`EXITED` invocations only, whose `protocol_integrity` is never `VIOLATED`; a
core-won terminal is never reconciled, and the merged operation requires an
`EXITED` invocation),
`expected_invocation_revision` from `command_result.invocation` (the
post-enrichment revision) and `expected_run_revision` from the stored run. The
caller records the returned `reconciliation.diagnostics` after the call, as the
harness does.

## 6. Deadlines, heartbeat, cancellation and exit races (matrix C)

### 6.1 Paired deadlines

Spec 14.8: one paired clock observation at `PENDING → STARTING`. The supervisor
reads `monotonic_at_swap = clock.monotonic()` immediately before
`lifecycle.begin_start(...)`; the merged operation stamps
`launch_attempted_at_utc = clock.now_utc()` and `deadline_utc =
launch_attempted_at_utc + timeout_seconds` inside the same call (the record
validator makes any other pair unrepresentable). The supervisor then holds
`PairedDeadline(deadline_utc=record.deadline_utc,
deadline_monotonic=monotonic_at_swap.plus(record.timeout_seconds),
timeout_seconds=record.timeout_seconds)`. The monotonic reading precedes the UTC
reading, so the monotonic deadline is never later than the UTC one in wall terms;
it governs inside the live supervisor, it is never persisted, serialized to the
adapter or compared across restarts, and heartbeats never move it. The reconciler
uses only `deadline_utc` against `clock.now_utc()`, so a restart derives the
remaining interval and can never extend a deadline.

Constants (all in `models.py`), each a `Final` literal with a test:

| Constant | Value | Rule |
|---|---|---|
| `TICK_SECONDS` | `0.02` | The maximum wait of one loop iteration (the harness's `POLL_INTERVAL_SECONDS`, so the timing rows keep their margins); every wait primitive receives `min(TICK_SECONDS, remaining)` |
| `READ_CHUNK_BYTES` | `65_536` | The `read(n)` size of a pipe reader (`bufsize=0`, so a short read returns what is available) |
| `QUEUE_CAPACITY_CHUNKS` | `64` | Bounded queue per pipe; at most 4 MiB in flight per pipe, after which the reader blocks and the child's write blocks — that is the backpressure |
| `POST_TERMINATION_WAIT_SECONDS` | `5.0` | The bound on waiting for a terminated tree to exit and for the pipes to reach EOF |
| `READER_JOIN_SECONDS` | `5.0` | The bound on joining a reader thread after EOF or termination |
| `PIPE_HOLDER_GRACE_SECONDS` | `1.0` | After the root's exit is reaped, how long a pipe may stay **idle** (no chunk and no sentinel dequeued from it) before the descendants holding it are terminated (§6.5); the window restarts on every dequeued chunk, so a large post-exit backlog is drained, not killed |
| `FORCED_TERMINATION_EXIT_CODE` | `1067` | `ERROR_PROCESS_ABORTED`; passed to `TerminateJobObject` / `TerminateProcess`; unrecognized, so it maps to `RUNTIME_FAILURE`; distinct from `1`, `259` and `3221225786` (§2.5 reading 6) |
| `CTRL_BREAK_EVENT` | `1` | `GenerateConsoleCtrlEvent` argument |
| `CREATE_SUSPENDED` | `0x00000004` | The Win32 process-creation flag the stdlib `subprocess` module does not export (the venv interpreter has no `subprocess.CREATE_SUSPENDED`); combined with `subprocess.CREATE_NEW_PROCESS_GROUP` in the one `Popen` call (§8.2) |
| `DESCRIBE_STDERR_PLACEHOLDER` | `chr(0) + "describe-has-no-attempt-token" + chr(0)` | The token handed to `BoundedStderrCapture` for a `DESCRIBE`, which has no attempt token while the merged capture refuses an empty one; built from `chr(0)` pieces, never a literal, and named without a `_TOKEN` suffix, so ruff S105 stays silent (the merged harness spells its `DESCRIBE_STDERR_SENTINEL` the same way); NUL-bracketed so no adapter text can contain it, and a test asserts it never appears in a describe's `sanitized_text` |
| `MAX_LAUNCH_ARGUMENTS` | `16` | Bound of `catalog_launch_arguments` |
| `COMMAND_ROOT_CEILING`, `DIRECTORY_CEILING_WITHOUT_LONG_PATHS`, `FILE_CEILING_WITHOUT_LONG_PATHS`, `LONG_PATH_CEILING` | `247`, `247`, `259`, `1024` | §7.2 (the command root is created with `CreateDirectoryW`, MAX_PATH − 12 without long paths, and is the child's `cwd`, whose `CreateProcessW` bound is MAX_PATH; 247 is the conservative intersection, so the command root is bounded at 247 regardless of the probe; plain directory creation fails at 248 and file creation at 260 without long paths; with support the work directory and files are bounded by the catalog grammar's `MAX_EXECUTABLE_PATH_CHARACTERS`, 1024) |

### 6.2 Heartbeat

`HeartbeatMonitor(missing_heartbeat_seconds=<request snapshot limits>)` exists for
`VALIDATE` and `RUN` only. It is armed with the monotonic reading taken right after
`record_process_start` commits (the invocation is `RUNNING` and the process is
owned), reset on every accepted `HEARTBEAT` (the harness rule), and checked each
tick. When due: if this tick's poll (§6.3 step 0; there is no second poll) reaped
an exit, the exit path handles it; otherwise `PROCESS.MISSING_HEARTBEAT` is minted
exactly once (`minted = True`), emitted as a `HEARTBEAT_MISSED` trace entry, and
supervision continues — the command deadline is the only liveness terminal in
Project 1 (spec 15.3). Its identity joins the terminal transition's
`diagnostic_ids` (and, for `TIMED_OUT`, the primary's `causal_diagnostic_ids` as
its only causal id, row 25), or the `EXITED` transition's `diagnostic_ids` when the
child completes. `DESCRIBE` arms no monitor. Row 25's margin: the threshold (2 s)
runs from the first accepted heartbeat, the deadline (4 s) from the swap; the
launch latency (about 0.35 s on the planning host) narrows the margin by that
much, which the row still clears by more than a second.

### 6.3 The supervision loop

One decision thread per `invoke` (the coroutine awaits
`asyncio.to_thread(self._supervise, ...)`; the token is thread-safe so a caller on
the event loop may cancel at any time). Before the loop, the pre-launch sequence
of §4: `load` and `linked_run` (so every diagnostic minted from here on carries
`run_id`/`experiment_id` for a linked kind, §3.5) → preflight (no change) →
executable observation → `monotonic_at_swap`,
`begin_start` → envelope, root creation, request write → readers opened and
started immediately after `launch` returns and before any byte is interpreted,
and at the same instant `PROCESS.JOB_OBJECT_UNAVAILABLE` minted and held when
`launched.job_available` is false (its `os_error_code` from
`launched.job_error_code`) and the `LAUNCHED` entry emitted with
`launched.image_path` as its fact →
pre-handoff checks (cancellation, deadline) → `record_process_start` → heartbeat
armed. If the token is already set when it is first checked — after `load`,
`linked_run`, preflight and the executable observation, so `executable_observation`
is always present, and before `begin_start` — the supervisor records
`PENDING → CANCELLED` with `PROCESS.CANCELLED` (coupled for a linked kind), then
performs the single enrichment (`cleanup_complete=True` over an empty cleanup
report, §2.5 reading 23) and returns the outcome without launching
(`PRE_HANDOFF_CANCELLATION` trace). Every tick of the loop:

0. **Poll** `wait(0.0)` once, at the top of the tick (idempotent after a code was
   returned; the first reaped code is kept and never replaced). A reaped exit is
   a fact of this tick that steps 3–8 consult; no step polls again.
1. **Drain stdout.** For `VALIDATE`/`RUN`: `StdoutFramer.feed(chunk)` yields
   complete lines; each goes to `parse_protocol_line(line,
   acceptance=EventAcceptanceContext(invocation=<the RUNNING record
   `record_process_start` returned, held for the life of the loop and never rebuilt
   from a reload: the merged context refuses any non-RUNNING record, and
   post-decision lines are parsed against this same snapshot>,
   attempt_token_hash=<hash of the envelope's token>, max_event_bytes=<snapshot>,
   ledger=<current>, clock=<injected>))`; `EventAccepted` → `ledger.accept`,
   `lifecycle.append_event`, an `EVENT_ACCEPTED` entry to the observers (never
   retained in the outcome's `trace`, §3.3), heartbeat reset for a
   `HeartbeatPayload`; `EventReplayed` → `replay_count += 1`, an `EVENT_REPLAYED`
   entry to the observers;
   `EventRejected` → the first rejection is kept (with its `EVENT_REJECTED` trace
   entry carrying the rejection) and no further line is parsed. For `DESCRIBE`:
   `stdout_byte_count += len(chunk)`, nothing is framed or parsed (§2.5 reading
   14), and no trace entry is emitted per chunk — the one `STDOUT_BYTES_COUNTED`
   entry is emitted at the terminal decision with the final count. When the stdout reader has reported EOF and a non-empty `pending_bytes`
   remains (`VALIDATE`/`RUN`), the fragment is parsed once (the merged parser
   rejects it as contamination).
2. **Drain stderr** into `BoundedStderrCapture.feed`.
3. **Rejection present** → decide `PROTOCOL_FAILED` (severe protocol violation:
   forced tree termination without interrupt or grace).
4. **Exit complete** — a poll (this tick's or an earlier one; polling continues
   once per tick for the life of the loop, so a scripted clock keyed on polls
   keeps moving) returned a code, both readers reported EOF, the framer is
   flushed — → decide `EXITED` (or `PROTOCOL_FAILED` if the flush
   rejected).
5. **Cancellation requested** (`token.is_cancellation_requested()`) → decide
   `CANCELLED`.
6. **Deadline passed** (`deadline.passed(clock.monotonic())`) → decide `TIMED_OUT`.
7. **Heartbeat due** and not minted → §6.2.
8. **Pipe holder**: the root exit is reaped and a pipe has been idle (nothing
   dequeued from it) for `PIPE_HOLDER_GRACE_SECONDS` without reporting EOF →
   `terminate_tree(FORCED_TERMINATION_EXIT_CODE)` once (`PROCESS.FORCED_TERMINATION`,
   `pipe_holder`) so the descendants holding the handle die and EOF arrives; the
   loop continues. A forced tree termination is performed, traced
   (`FORCED_TERMINATION`) and minted (`PROCESS.FORCED_TERMINATION`) **at most once
   per invocation**: once this step has fired, no later decision — C or D through
   the `PROCESS_GONE` branch of §6.5, a flush or late rejection deciding
   `PROTOCOL_FAILED` — calls `terminate_tree` again or emits a second entry or
   diagnostic; it proceeds straight to the post-termination wait of §6.5 and the
   `cancel_read` path of §6.7, because the reaped root's tree was already terminated
   and `SupervisionOutcome.trace` admits no repeated `FORCED_TERMINATION` (§3.3).
9. Otherwise `item = wait_for_chunk(stdout_queue, bound)` with `bound =
   min(TICK_SECONDS, deadline.remaining(now))`, further lowered to the monitor's
   `remaining(now)` only while a monitor is armed and not yet minted (a minted
   monitor would otherwise contribute `0.0` on every tick and turn the loop into a
   busy wait until the deadline; a `DESCRIBE` has no monitor and omits the term) —
   the timed wait `readers.py` exposes: a returned chunk is fed to the framer (or a returned `ReaderEnd`
   marker noted) before the next tick's drain, so the wait never loses a byte;
   `None` means nothing arrived.

The order is the deterministic tie-break of §2.5 reading 10: a rejection already
proves stdout untrustworthy; a fully drained exit before the checks of steps 5–6 is
a true process fact; cancellation is user intent and beats the deadline; the
heartbeat check never decides anything.

Decision, then the terminal transition (§5.1; a `TERMINAL_DECIDED` and a
`TERMINAL_COMMITTED` trace entry), then termination for the core-won states
(§6.5), then the post-decision drain (stdout still framed and parsed under reading
13, stderr still fed) until EOF or `POST_TERMINATION_WAIT_SECONDS`, then the output
read and parse for `EXITED` (§7.4), the write-boundary snapshot, cleanup (§8.4)
and the single enrichment (§6.6). Committing the terminal before the kill means a
crash between the two leaves a terminal `cleanup_complete=false` record — a
reconciliation target — rather than a `RUNNING` one.

### 6.4 Race matrix

Conditions observed in one tick (R = rejection found, X = exit reaped and both
pipes at EOF, C = cancellation requested, D = deadline passed, H = heartbeat due,
L = a lifecycle call failed). Every row shows the decided terminal state, its
primary, the additional diagnostics, the child action and the swap that carries the
native exit pair.

| Conditions | Decision | Primary | Additional | Child action | Native exit pair |
|---|---|---|---|---|---|
| C before `begin_start` | `CANCELLED` from `PENDING` | `PROCESS.CANCELLED` | none | none (never launched); the enrichment still runs with `cleanup_complete=True` (reading 23) | none |
| `begin_start` or `record_process_start` fails, the reloaded invocation is nonterminal at the expected revision, and `resolve_external_winner` finds the run terminal or the experiment cancelled | `CANCELLED` from `PENDING` or `STARTING`, written by the lifecycle (reading 22) | `PROCESS.CANCELLED` | by the single enrichment (the port member takes no additionals): `PROCESS.FORCED_TERMINATION` (`external_winner`) when a child existed, `PROCESS.JOB_OBJECT_UNAVAILABLE` if held, `PROCESS.CLEANUP_FAILED` per failed action | forced tree termination if launched | none (the child was never owned) |
| `begin_start` or `record_process_start` fails, the invocation is nonterminal at the expected revision, and `resolve_external_winner` returns `MISSING` | own-request defect (§5.3) | — | — | forced tree termination if launched; cleanup | none; `Failure` returned |
| `launch` returns a `LaunchFailure` (any C or D observed at the same instant is irrelevant: the child does not exist) | `FAILED_TO_START` | minted by the supervisor from the failure's fields: `ADAPTER.UNAVAILABLE` when `not_found` (run `→ UNAVAILABLE`), else `PROCESS.LAUNCH_FAILED` with `stage`/`os_error_code` | `PROCESS.JOB_OBJECT_UNAVAILABLE` never (no process) | none | none |
| C observed after launch and before the handoff commit | `CANCELLED` from `STARTING` | `PROCESS.CANCELLED` | `PROCESS.FORCED_TERMINATION` (`pre_handoff`); `PROCESS.JOB_OBJECT_UNAVAILABLE` if held | forced tree termination (the child was never owned) | none (reading 7) |
| D observed after launch and before the handoff commit | `TIMED_OUT` from `STARTING` | `PROCESS.START_TIMED_OUT` (RUN), `PROCESS.VALIDATE_TIMED_OUT`, `PROCESS.DESCRIBE_TIMED_OUT` | `PROCESS.FORCED_TERMINATION` (`pre_handoff`); `PROCESS.JOB_OBJECT_UNAVAILABLE` if held | forced tree termination | none |
| R alone, or R with any of X/C/D/H | `PROTOCOL_FAILED` | the rejection's `Diagnostic` | `PROCESS.MISSING_HEARTBEAT` if minted; `PROCESS.STDERR_TRUNCATED` if truncated; `PROCESS.JOB_OBJECT_UNAVAILABLE` if held; `PROCESS.FORCED_TERMINATION` (`protocol_failed`) | forced tree termination at once; drain; reap | enrichment after cleanup with the value the controller reaps after the forced termination: the root's own exit when it had already exited (at this tick's poll or before the kill landed), else `FORCED_TERMINATION_EXIT_CODE` (§6.5: the observed value, never the constant by assumption) |
| X alone, or X with C, X with D, X with C and D | `EXITED` | `MISSING`, or `PROCESS.UNRECOGNIZED_PROCESS_EXIT` for a value outside the eight | `PROCESS.MISSING_HEARTBEAT` if minted; `PROCESS.STDERR_TRUNCATED` if truncated; `PROCESS.JOB_OBJECT_UNAVAILABLE` if held | none (already exited) | on the `RUNNING → EXITED` transition itself |
| root exit reaped (`wait(0.0)` returned) but a pipe stays idle without EOF for `PIPE_HOLDER_GRACE_SECONDS` (a descendant inherited the handle), with neither C nor D | no decision yet: forced tree termination (`PROCESS.FORCED_TERMINATION`, `pipe_holder`) so EOF arrives; the loop then decides `EXITED` (or `PROTOCOL_FAILED` from the flush) with the root's own reaped exit; a pipe that keeps delivering chunks after the exit is drained, never treated as held | as decided | as above plus the forced-termination diagnostic | forced tree termination of the descendants only (the root is gone) | the root's reaped exit on the `EXITED` transition |
| root exit reaped, pipe not at EOF, and C or D observed | `CANCELLED` / `TIMED_OUT` | as for C / D | as for C / D plus `PROCESS.FORCED_TERMINATION` (`pipe_holder`) — one entry and one diagnostic whether step 8 or this row minted it | the reaped root skips the interrupt (`interrupt()` reports `PROCESS_GONE` from its zero wait on the signaled handle without generating an event), so forced tree termination at once (§6.5) unless §6.3 step 8 already fired, in which case nothing is terminated again | the root's reaped exit by enrichment |
| X where the flush rejected the trailing fragment | `PROTOCOL_FAILED` | the fragment's `PROTOCOL.STDOUT_CONTAMINATION` | as above | `terminate_tree` at once, as for every rejection (a no-op on the reaped root; it kills any job survivor) — unless §6.3 step 8 already fired, in which case no second termination, entry or diagnostic is issued and the `pipe_holder` entry stands | enrichment after cleanup |
| C alone, C with D, C with H | `CANCELLED` | `PROCESS.CANCELLED` | `PROCESS.MISSING_HEARTBEAT` if minted; `PROCESS.STDERR_TRUNCATED`; `PROCESS.GRACEFUL_INTERRUPT_UNAVAILABLE` and/or `PROCESS.FORCED_TERMINATION` when they occurred | interrupt → grace → forced | enrichment after cleanup (`50` when the child cooperated, `3221225786` when a handler-less child died on the interrupt, `1067` when forced, the child's own value when it exited during grace) |
| D alone, D with H | `TIMED_OUT` | `PROCESS.RUN_TIMED_OUT` / `PROCESS.VALIDATE_TIMED_OUT` / `PROCESS.DESCRIBE_TIMED_OUT` by kind, `causal_diagnostic_ids = (missing heartbeat id,)` when minted, else empty | as for C | interrupt → grace → forced | enrichment after cleanup |
| H alone | no decision | — | `PROCESS.MISSING_HEARTBEAT` minted once | poll only | — |
| L on `append_event` or `record`-side failure while `RUNNING`, before any decision | `CANCELLED` | `PROCESS.CANCELLED` with `causal_diagnostic_ids = (the recorded core failure id,)` | the core failure diagnostic itself (recorded), plus the usual additionals | interrupt → grace → forced | enrichment after cleanup |
| L on the terminal transition, stored record terminal | keep the stored terminal (§5.3) | (stored) | (stored) | forced tree termination if still alive | enrichment of the stored record when its exit pair is absent and admitted |
| L on the terminal transition, stored record nonterminal at the expected revision | own-request defect (§5.3; no external-winner attempt is made after a refused terminal write) | — | — | forced tree termination; cleanup | none; `Failure` returned |
| any failure after the terminal transition (post-decision `append_event`) | no change | — | the failure as an additional diagnostic on the enrichment; parsing stops | — | — |

There is no false `EXITED`: `EXITED` is decided only from a reaped exit
value obtained through the owning handle after both pipes reached EOF and the
trailing fragment was flushed, and the value is written by the same swap that
moves the state. No row can produce semantic success: the supervisor never calls a
run transition; the run moves only through the coupled core-won mappings of §5 or
through `apply_command_semantic_outcome`, which never moves a run to a success
state (Stage 6 plan 1.4). A clean `EXITED` (job attached, no truncation, no
missed heartbeat, cleanup complete) carries no Stage 7 diagnostic at all, which is
what keeps every exact Stage 6 pin on the `EXITED` rows true.

### 6.5 Graceful and forced termination

For `CANCELLED` and `TIMED_OUT`: `t0` = decision. `interrupt()`: `DELIVERED` →
`INTERRUPT_SENT` trace; `UNAVAILABLE` → `PROCESS.GRACEFUL_INTERRUPT_UNAVAILABLE`
additional diagnostic and `INTERRUPT_UNAVAILABLE` trace; `PROCESS_GONE` (the root
already exited while a pipe is still open) → `terminate_tree` at once with
`PROCESS.FORCED_TERMINATION` (`pipe_holder`) — only when §6.3 step 8 has not
already fired; otherwise the tree was terminated once already and this branch
proceeds directly to the post-termination wait, emitting nothing; a reaped root
therefore never receives a `CTRL_BREAK` meant for it, and its orphans die by
termination with reason `pipe_holder`, never `grace_elapsed`. In the first two cases wait until the
process exits or `t0 + cancellation_grace_seconds` (still draining both pipes each
tick; spec 15.4's "only after the grace period"): a root still unsignaled at the
grace boundary is terminated with `terminate_tree(FORCED_TERMINATION_EXIT_CODE)`
and a `PROCESS.FORCED_TERMINATION` additional diagnostic (`grace_elapsed`, or
`interrupt_unavailable` on the `UNAVAILABLE` branch) and a `FORCED_TERMINATION`
trace entry; a root that exits inside the window hands over to the pipe-holder
rule — the loop keeps draining, and a pipe still idle without EOF after
`PIPE_HOLDER_GRACE_SECONDS` is terminated with reason `pipe_holder` — so each
reason word of §3.5 is decided by exactly one rule: `pipe_holder` by §6.3 step 8,
which the `PROCESS_GONE` branch merely reaches early when step 8 has not yet
fired; `grace_elapsed` and `interrupt_unavailable` by the grace wait; and the
at-most-once rule of step 8 makes every such termination single. Independently of
any decision, a root whose exit was reaped while either pipe stays **idle**
without EOF for `PIPE_HOLDER_GRACE_SECONDS` (`1.0`; the window restarts on every
chunk dequeued from that pipe, so a backlog of buffered lines is parsed, not
killed) has left a descendant holding the handle: the supervisor terminates the
tree (`pipe_holder`) so EOF arrives and the ordinary `EXITED` decision follows
with the root's own exit value (the grandchild scenarios of §9.1). For `PROTOCOL_FAILED`, the pre-handoff rows and the
external-winner rows: `terminate_tree` at once (no interrupt; §2.5 reading 5).
After termination: wait for the root exit and both EOFs up to
`POST_TERMINATION_WAIT_SECONDS`; the reaped value is whatever
`GetExitCodeProcess` reports after the handle is signaled (the controller records
the observed value, never the constant by assumption; a test pins that a forced
kill observes `1067`). `cancellation_grace_seconds` is a constructor parameter of
`WindowsProcessSupervisor` bounded `0..300`, the `ProcessConfig` range; the default
`10` is spec 15.4's; the Stage 6 rows through the seam pass `1`, the Stage 7
graceful and forced scenarios pass `5` and `1`.

### 6.6 Exactly-once terminal enrichment

Every write to the invocation after the terminal decision, in order:

1. `record_terminal(...)`: the state change. For `EXITED` it carries the native
   exit pair, the optional unrecognized-exit primary and every additional
   diagnostic known at that instant (`PROCESS.MISSING_HEARTBEAT`,
   `PROCESS.STDERR_TRUNCATED` — for `EXITED` the stderr fold is finished before
   the decision, because EOF on stderr is a precondition, so `finish().truncated`
   is known — and a held `PROCESS.JOB_OBJECT_UNAVAILABLE`). For a core-won state it
   carries the primary and the same additionals, where truncation is known from
   the supervisor's own `stderr_bytes_fed` counter (`> limit` is the fold's rule;
   the merged fold exposes `truncated` only through `finish()`, which cannot run
   before a decision that keeps draining stderr); the native exit is not yet
   reaped.
2. Termination, drain, output read, snapshot and cleanup (§8.4) run entirely
   between the two swaps and produce a `CleanupReport`.
3. `enrich(...)`: exactly one call, carrying the reaped native exit pair when the
   record has none and its shape admits one (core-won states from `RUNNING`;
   `MISSING` for `EXITED`, whose pair is already durable; `MISSING` for the
   `STARTING`-origin rows and for `FAILED_TO_START`), `cleanup_complete =
   report.complete`, and the additional diagnostics minted after the transition
   (`PROCESS.CLEANUP_FAILED` per failed action, `PROCESS.FORCED_TERMINATION`,
   `PROCESS.GRACEFUL_INTERRUPT_UNAVAILABLE`, `PROCESS.WRITE_BOUNDARY_VIOLATION`, a
   `PROCESS.STDERR_TRUNCATED` whose truncation happened only during the
   post-decision drain of a core-won state, a post-decision `append_event`
   failure). For the never-launched `PENDING → CANCELLED` row the same single
   enrichment carries `cleanup_complete=True` and nothing else (reading 23).
   `assert_write_once_enrichment`
   guarantees this call adds at least one fact (`cleanup_complete` when true, else
   at least one `PROCESS.CLEANUP_FAILED` identity) and never overwrites; its
   failure handling is §5.3.

There is exactly one enrichment per invocation and no third write from the supervisor. `CommandResult.invocation` is the
record the enrichment returned. The describe epilogue's later enrichment with the
reconciliation's diagnostic identities (the harness precedent, rows 21, 43, 44) is
the caller's and is lawful: an ids-only enrichment of a record already holding
`cleanup_complete` is accepted by the merged predicate as long as one id is new.

### 6.7 Readers and backpressure

`PipeReader(stream, *, capacity=QUEUE_CAPACITY_CHUNKS, stop: threading.Event)` is a
daemon thread: `chunk = stream.read(READ_CHUNK_BYTES)`; an empty read is EOF and
enqueues the `ReaderEnd.EOF` marker; a non-empty chunk is enqueued with
`put(chunk, timeout=TICK_SECONDS)` retried until it succeeds or `stop` is set (a
full queue blocks the reader, the pipe fills, the child's write blocks — bounded
memory, never a dropped byte while the child lives); every `queue.Full` timeout
increments `put_retries` (one per retry, so the counter grows while nobody
drains), the observable that proves backpressure happened. The thread records `threading.get_native_id()` as
`native_thread_id` at start. An `OSError` from a read that a
`cancel_read` interrupted enqueues a distinct `CANCELLED` marker (never the EOF
sentinel) and sets `ended_by = ReaderEnd.CANCELLED` (`ReaderEnd.EOF` for the
sentinel), so `drain` still reports the reader ended while the supervisor can tell
the two apart; an `OSError` or `ValueError` from a pipe object closed after
the thread ended is impossible by construction, because the pipe object is closed
only after the reader has ended (§8.4). `drain(queue) -> tuple[list[bytes], bool]`
takes everything available without blocking (the `bool` is whether a `ReaderEnd`
marker was seen); `wait_for_chunk(queue, timeout_seconds) -> bytes | ReaderEnd |
None` is the only timed wait: it returns the dequeued item — a chunk or a marker,
which the caller must hand to the framer or note before the next `drain`, so no
byte is lost — or `None` when nothing arrived (it catches `queue.Empty`, which is
why `queue` is confined to this module). The supervisor owns both readers (it creates them over `launched.stdout` and
`launched.stderr` right after `launch` returns, §6.3) and it alone stops them:
`stop()` only after the tree is verified dead or the post-termination wait expired;
then `join(READER_JOIN_SECONDS)`; a thread still alive after the join is blocked
inside a pipe read whose write end an unverified process still holds — the
supervisor then calls `launched.cancel_read(reader.native_thread_id)` (the port
member behind which `WindowsLaunchedProcess` performs
`OpenThread(THREAD_TERMINATE)` + `CancelSynchronousIo`, so `supervisor.py` never imports `windows_api` and the
scripted double can model the cancellation) and joins again for
`READER_JOIN_SECONDS`; a thread still alive after that is a `CleanupFailure(STDOUT_
READER_STOPPED | STDERR_READER_STOPPED, ...)` minted by the supervisor, and its
pipe object is left open — the supervisor passes `close_stdout`/`close_stderr`
flags to `launched.close(...)` (§8.4), because closing a pipe under a blocked read
blocks the closer until the writer exits, so the flagged `PIPES_CLOSED` action fails
too — which is exactly the case `cleanup_complete=false` exists for. The final
`CleanupReport` is the union of the supervisor's two reader actions and the
controller's `close` report, in that order. `StdoutFramer` wraps `frame_protocol_lines`
with the request snapshot's `max_event_bytes`; the merged framer already emits an
over-long unterminated tail early, so no unbounded carry-over forms (the harness's
`readline()` pump did not have this property), and the merged property test's
guarantee (any chunking yields the same accepted events) transfers to the reader
because the framer is the same function.

## 7. Temporary roots, paths and the Windows filesystem (matrix A/H)

### 7.1 Layout

`plan_command_paths(supervision_root, *, command_kind, invocation_id, run_id)` is
pure and total and reproduces the harness layout the Stage 6 envelope and fake
adapter fix:

| Kind | `command_root` | Files and directories |
|---|---|---|
| `DESCRIBE` | `<root>\<invocation_id>` | `request.json`, `output.json` |
| `VALIDATE` | `<root>\<invocation_id>` | `request.json`, `output.json` |
| `RUN` | `<root>\<invocation_id>` | `request.json`, `runs\<run_id>\work\`, `runs\<run_id>\work\adapter-result-manifest.json` (`RESULT_MANIFEST_RELATIVE_PATH`) |

`run_id` is required exactly for `VALIDATE` and `RUN` (a `VALIDATE` does not use it
in a path, but the layout function still refuses a linked kind without it). The
work directory is `command_root` joined with the envelope's
`assigned_work_dir.relative_path` (`runs/<run_id>/work`), which the fake adapter
checks as the tail of `--work-dir`. Every returned path is an
`AbsoluteLocalExecutablePath`; the caller builds `AdapterCommand` from
`CommandPaths`, and `WindowsProcessSupervisor` re-derives the paths from the
record and refuses (§4.4) a command whose `request_path`, `output_path`,
`work_dir` or `result_path` differs, so there is one path authority and every
adapter-facing path is core-selected (spec 14.1). The child's `cwd` is
`command_root` (reading 11). The Stage 6 pins on the production path (`written_paths`
prefix `runs/<run_id>/work/`, `command_root.parent == tmp_path`) therefore hold
unchanged.

### 7.2 Preflight

`PathPreflight` is computed once per `WindowsProcessSupervisor` instance
(`probe_long_path_support(supervision_root, now=clock.now_utc()) ->
Result[PathPreflight]`, run lazily on the first `invoke`; the reconciler's caller
probes the same way; a `Failure` carries `PROCESS.PATH_PREFLIGHT_REJECTED`,
never at import) unless the constructor received `preflight: PathPreflight |
MISSING` (a test injects either arm): the root must be an absolute local path (the
catalog grammar), an existing directory, and neither it nor any ancestor may be a
reparse point (`Path.lstat().st_file_attributes & 0x400`, walked to the drive
root); the probe creates and removes one directory whose absolute length exceeds
247 characters under `<root>\.probe`, records `long_paths_supported` and sets the
directory ceiling to `1024` or `247` and the file ceiling to `1024` or `259`
(`MAX_EXECUTABLE_PATH_CHARACTERS` bounds every catalog-grammar path, so `1024` is
the effective supported ceiling). `preflight_command_paths(paths, preflight, *,
now, invocation_id=MISSING, run_id=MISSING, experiment_id=MISSING) ->
Result[None]` (the supervisor passes its clock instant and the ids of §4.4)
rejects a command root longer than `COMMAND_ROOT_CEILING` (`247`, always: it is
the child's `cwd`), a work directory longer than the directory ceiling, a request,
output or result path longer than the file ceiling, and any existing component
that is a reparse point.
A rejection before the swap is `PROCESS.PATH_PREFLIGHT_REJECTED` returned as
`Failure` (nothing changed); after the swap (a component turned out to be a
reparse point when the root was created) it is the `FAILED_TO_START` primary
`PROCESS.LAUNCH_FAILED` (`stage: create_root`). Candidate relative paths inside
the work directory are Stage 9's to bound (§1.4). Project 1 never changes a
Windows setting or requests elevation (spec 22.5).

### 7.3 Creation and the write boundary

`create_command_root(paths)` creates `command_root` with `parents=True,
exist_ok=False` (an existing root for a fresh invocation identity is
`CORE.INVARIANT_VIOLATION` → `FAILED_TO_START`) and, for `RUN`, the work directory;
`write_request_file(paths.request_path, request_envelope_bytes(envelope))` uses an
exclusive create (`"xb"`). `snapshot_written_paths(command_root)` runs after the
write and after the exit — an `lstat` walk that records a reparse-point entry as a
single path and never descends into it (Python's `rglob` would follow a junction
into an arbitrary host tree), mirroring §7.5's refusal to unlink through one; the difference minus the permitted set (`output.json`
for `DESCRIBE` and `VALIDATE`; anything under `runs\<run_id>\work\` for `RUN`) is
a stray write: a `WRITE_BOUNDARY_VIOLATION` trace entry with the count and a
`PROCESS.WRITE_BOUNDARY_VIOLATION` additional diagnostic (never a terminal cause,
§1.5 item 2). The baseline snapshot is taken after the `REQUEST_WRITTEN` trace entry
has been delivered to the observers, so a file an observer plants at that instant
— the row-47 stale file the production strategy plants beside `output.json`
(§9.3) — is pre-existing to the boundary, exactly as a stale file left by an
earlier attempt would be; nothing a test hook does can subtract a path from the
supervisor's own computation.

### 7.4 Reading the output file

Only for an `EXITED` invocation. `read_output_file(path, *, ceiling)` refuses a
reparse point (`lstat` first), opens `"rb"`, reads at most `ceiling + 1` bytes
(ceilings: `MAX_DESCRIPTOR_OUTPUT_BYTES`, `MAX_VALIDATION_RESULT_BYTES`, the
request snapshot's `max_manifest_bytes`) and returns the bytes, `MISSING` for an
absent file, or an `OutputReadFailure` (a P record in `models.py`: `os_error_code:
int | MISSING`, `error_class: BoundedText`) for a file that exists but cannot be
read, from which the supervisor derives the `output_unreadable` fact on the
`EXIT_REAPED` trace entry and leaves `output_parse` `MISSING` (a sharing violation or an
access-denied error). An unreadable output after a clean exit is an artifact
condition the merged reconcilers already classify from a missing parse
(`ARTIFACT.RESULT_MANIFEST_INVALID`, `PROTOCOL.VALIDATION_RESULT_INVALID`,
`PROTOCOL.DESCRIBE_OUTPUT_INVALID`), so no Stage 7 diagnostic is minted for it and
`output_parse` stays `MISSING`. The bytes go to
`parse_bootstrap_descriptor`, `parse_validation_result(data, max_bytes=...,
token=token)` or `parse_result_manifest(data, max_bytes=..., token=token)` (both
keyword-only, as the merged parsers declare them) with the raw token taken from the
envelope the supervisor itself wrote; the parsers enforce the size ceiling by
length, so the one extra byte is what makes an oversized file rejectable without
reading it whole. The bytes are dropped after parsing; `SupervisionOutcome.output_parse`
holds the parse and `command_result.parsed_output`/`parsed_output_source_hash` the
strict model and hash.

### 7.5 Removal

`remove_command_root(command_root)` is a bounded depth-first removal that refuses
to descend into or unlink through a reparse point (it removes the reparse-point
entry itself with `rmdir`), removes files before directories, returns a
`CleanupReport` (a missing root or file is success, so it is idempotent) and never
raises; a sharing violation (an open handle) is a `CleanupFailure(COMMAND_ROOT_
REMOVED, "sharing_violation:32")`. It runs only for pre-handoff terminals
(`FAILED_TO_START`, `STARTING`-origin `TIMED_OUT` and `CANCELLED`; a `PENDING`-origin
`CANCELLED` has no root and its report is trivially complete) and for the
reconciler's pre-handoff cleanup; a root of an invocation that reached `RUNNING`
is never removed by Stage 7 (reading 12), and the caller that closes the command
(Stage 9) calls the same function.

## 8. Process identity, Job Objects, tree cleanup and restart (matrix D)

### 8.1 Creation identity

`ProcessIdentity.creation_identity` is the text `windows:<pid>:<creation>` where
`<creation>` is the process creation `FILETIME` as an unsigned decimal
(`GetProcessTimes` on the owning handle, 100-nanosecond ticks since 1601; bounded
at `2**63 − 1` so it fits a `Diagnostic` detail integer). Its length is 11..38
characters (8 + up to 10 + 1 + up to 19), inside the `BoundedText` bound; the grammar is a `process_supervision`
runtime rule (`parse_creation_identity`), not a domain constraint, because the
record renders into a frozen schema. The durable triple that makes the process
owned (spec 15.1) is that text plus `executable_path`/`executable_hash` from the
catalog entry and `supervisor_instance_id`; the live handle strengthens identity
only inside the supervisor and is never persisted. Re-inspection
(`ProcessController.inspect`) parses the text, opens the pid with
`PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE` (the reconciler's
`ProcessController.terminate_tree(identity, exit_code)` opens the root with the
same mask plus `PROCESS_TERMINATE`), reads `GetProcessTimes` and
`QueryFullProcessImageNameW`, and tests liveness as `WaitForSingleObject(handle, 0)
== WAIT_TIMEOUT` (the handle unsignaled) — never through `GetExitCodeProcess`,
which returns the literal `259` both for a running process and for one that exited
with code `259`; it reports `ALIVE_MATCHING` only when the creation time equals the
recorded one and the handle is unsignaled; a live pid with another creation time is
`ALIVE_DIFFERENT_IDENTITY` (PID reuse); an open that fails with
`ERROR_INVALID_PARAMETER`, or a process whose handle is signaled, is `ABSENT`; `ERROR_ACCESS_DENIED` and any other failure is
`UNDETERMINED` (treated as absent by the reconciler, never killed). The image path
is recorded, not compared: for the launcher it is argv[0], for descendants the
versioned base interpreter.

### 8.2 Launch sequence (`WindowsProcessController.launch`)

1. `subprocess.Popen(list(argv), shell=False, env={}, cwd=cwd,
   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
   bufsize=0, close_fds=True, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP |
   CREATE_SUSPENDED)` (`CREATE_SUSPENDED` is the `models.py` constant `0x00000004`;
   the stdlib `subprocess` module exports no such name) — the only `Popen` call in
   `src`, creating the
   launcher suspended so that nothing it would spawn can exist before the job
   assignment of step 3; with `# noqa: S603 - reviewed fixed catalog
   executable boundary`. An `OSError` is returned as `LaunchFailure(stage="popen",
   os_error_code=<winerror, or MISSING when absent>, error_class=<the exception
   class name>, not_found=<winerror in (2, 3)>)` — `winerror` 2 or 3 means the
   executable vanished between the observation and the launch. The controller
   mints no diagnostic (§3.4); the supervisor maps `not_found` to
   `ADAPTER.UNAVAILABLE` and everything else to `PROCESS.LAUNCH_FAILED` with
   `stage`, `os_error_code` and `error_class` in `details` (§3.5, §6.4), minted
   with its own clock and the `linked_run` ids.
2. `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE |
   PROCESS_SET_QUOTA | SYNCHRONIZE, False, pid)` (`SYNCHRONIZE` because every
   liveness test is a wait on the handle, §8.1); the `Popen` object keeps its own handle open,
   so the pid cannot be reused before this open (a process object lives while any
   handle to it is open). `GetProcessTimes` → `creation_identity`;
   `QueryFullProcessImageNameW` → the observed image path, exposed as the port's
   `image_path` (the supervisor's `LAUNCHED` trace fact). A failure of any of these three calls terminates the still-suspended
   child through the `Popen` handle, waits on it for up to
   `POST_TERMINATION_WAIT_SECONDS`, closes both pipe read ends and every handle,
   and returns `LaunchFailure(stage="open_process", os_error_code=<GetLastError()>,
   error_class=<the failing API name: OpenProcess, GetProcessTimes or
   QueryFullProcessImageNameW>, not_found=False)` — a suspended child is never
   left behind.
3. `CreateJobObjectW(NULL, NULL)`; `SetInformationJobObject(
   JobObjectExtendedLimitInformation, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)`;
   `AssignProcessToJobObject(job, handle)` while the child is still suspended, so
   job membership is settled before its first instruction (membership is
   inherited only at process creation, and the venv launcher's first act is to
   create the interpreter). Nested jobs are supported on Windows 8 and later; the
   planning host probe placed the launcher, the interpreter and a grandchild
   inside the supervisor's job although pytest itself runs inside the launcher's
   job. A failure closes the job and exposes `job_available = False` with the
   `GetLastError()` value as `job_error_code` through the port; the supervisor
   mints `PROCESS.JOB_OBJECT_UNAVAILABLE` from those two members right after
   `launch` returns and holds it until the terminal transition (§6.3); the
   controller then verifies descendants by enumeration (§8.3). The controller
   takes an injected `job_object_factory` (default: the real `windows_api` calls)
   so a test can force this branch with a real child.
4. `windows_api.resume_initial_thread(pid)`: `CreateToolhelp32Snapshot(
   TH32CS_SNAPTHREAD)`, the one thread whose `th32OwnerProcessID` is the pid (a
   suspended new process has exactly one), `OpenThread(THREAD_SUSPEND_RESUME)`,
   `ResumeThread`, close the thread handle. `Popen` closes the primary thread
   handle it received, which is why the thread is reopened by id. The resume runs
   whether or not the job assignment succeeded; a resume failure terminates the
   suspended child (`TerminateProcess`, then a bounded wait), closes the job
   handle (kill-on-close also ends an assigned child), the process handle and
   both pipe read ends, and returns `LaunchFailure(stage="resume",
   os_error_code=<GetLastError()>, error_class=<the failing call: ResumeThread,
   OpenThread or the Toolhelp snapshot>, not_found=False)`.
5. Return `WindowsLaunchedProcess(popen, handle, job, creation_identity)`.

The venv launcher wraps its own child in a job with silent breakaway, so a process
the interpreter spawns survives the launcher's death unless the supervisor's job
contains it; because the launcher is created suspended and resumed only after
step 3, there is no window in which it could create the interpreter outside the
supervisor's job. When the job is unavailable, descendants are caught by the
Toolhelp enumeration only while their parent chain is still alive (the walk starts
at the root pid), so an escaped grandchild whose parent chain has exited cannot be
reached — the plan states this limitation rather than claiming otherwise (§8.4).

### 8.3 Tree termination and interrupt

`terminate_tree(exit_code)`: one Toolhelp32 snapshot (`CreateToolhelp32Snapshot(
TH32CS_SNAPPROCESS)`, `Process32FirstW`/`Process32NextW`) builds the
parent→children map and walks it breadth-first from the root pid, opening each
candidate with `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE`
and keeping
it only when its creation time is later than its parent's recorded creation time
(the PID-reuse guard: a stale parent pid pointing at a newer process is not a
descendant) — that verified set is `TerminationReport.descendants`; then, when the
job is attached, `TerminateJobObject(job, exit_code)`. When that call returns
`TRUE` the controller first waits on each verified handle (the root and every
descendant) for up to `POST_TERMINATION_WAIT_SECONDS` — the job tears its members
down asynchronously, and a `TerminateProcess` issued meanwhile fails with
`ERROR_ACCESS_DENIED` while `GetExitCodeProcess` may still report `STILL_ACTIVE`;
a verified handle still unsignaled after that wait (a process that escaped the
job) then receives `TerminateProcess(handle, exit_code)` and one more bounded
wait. When the job is unavailable or the job kill returned `FALSE`, it calls
`TerminateProcess(handle, exit_code)` on every verified descendant and on the
root, leaves first, and **only while the handle is unsignaled**
(`WaitForSingleObject(handle, 0) == WAIT_TIMEOUT`; never a `GetExitCodeProcess`
comparison against `259`, §8.1). After every `TerminateProcess`, whether it
returned `TRUE` or `FALSE` with `ERROR_ACCESS_DENIED` (`5`), the controller waits
on that handle for up to `POST_TERMINATION_WAIT_SECONDS` before the
`TerminationReport` is built (`TerminateProcess` only initiates termination; the
process object is signaled asynchronously): a handle that becomes signaled means
the process died and is recorded as dead, never as a failure; any other
`TerminateProcess` failure, a handle still unsignaled after the wait, or a wait
that itself fails (`WAIT_FAILED`, recorded with reason `wait_failed:<winerror>`
and never mapped to either liveness value) is a `CleanupFailure(TREE_VERIFIED_DEAD,
<reason>)`. A root whose exit was already reaped has a signaled handle and is
skipped by the same rule, so a forced termination after a job kill or after the
root's own exit reports no spurious failure, and `terminate_tree` returns only
after death is verified or the bound expired, which is why an `inspect` issued
right after it is deterministic.
`interrupt()`: first a zero wait on the root's handle — a signaled handle (the
root already exited) is `PROCESS_GONE` and no event is generated, so a reaped
root's orphans never receive a `CTRL_BREAK` addressed to it; then, for an
unsignaled root, `GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid)` — the child was
created with `CREATE_NEW_PROCESS_GROUP`, so its pid is its group id and the event
reaches the whole group (including the interpreter the venv launcher spawns; the
launcher forwards the interpreter's exit code, `50` for the graceful fake); a
`FALSE` return there is re-checked with one more zero wait (signaled →
`PROCESS_GONE`, the child exited between the two calls) and is otherwise
`UNAVAILABLE` (the supervisor itself has no console, `ERROR_INVALID_HANDLE`); the wrapper refuses pid `0` (that would
signal the whole console). `wait(timeout_seconds)` is `wait_for_handle(process_handle,
timeout_seconds)` followed by `process_exit_code` only when the handle is signaled,
returning `None` on timeout (the port's `int | None`; a bare `Popen.wait` would
raise `TimeoutExpired` instead); the exit value is read only after the handle is
signaled, so `STILL_ACTIVE` (`259`) can never be mistaken for an exit.

### 8.4 Cleanup

`close(*, close_stdout, close_stderr)` runs after the supervisor has stopped its
own readers (§6.7 owns `STDOUT_READER_STOPPED` and `STDERR_READER_STOPPED`) and
after the tree is verified dead (or the post-termination wait expired), in this
order: close the read end of each pipe whose flag is true (`PIPES_CLOSED`; a flag
left false means that reader is still blocked, so the pipe is left open and the
action fails with reason `reader_alive` — closing it would block the supervisor
until the writer exits); re-inspect the root pid and every recorded descendant
(`TREE_VERIFIED_DEAD`: none `ALIVE_MATCHING`, liveness by the unsignaled-handle
test of §8.1); close the job handle (`JOB_CLOSED`; kill-on-close is the last line
of defence for any survivor); close the process handle (`PROCESS_HANDLE_CLOSED`).
The supervisor prepends its two reader actions to the returned report.
`COMMAND_ROOT_REMOVED` applies to pre-handoff terminals only (§7.5). Each failed
action is one `PROCESS.CLEANUP_FAILED` additional diagnostic naming the action in
`details`; `cleanup_complete` is true only when the report is complete. An
`EXITED` invocation's process was reaped, so its cleanup never inspects the pid
(a recycled pid must not mint a spurious PID-reuse diagnostic). Stated
limitation: with the job unavailable, a descendant of a root that reached `EXITED`
with both pipes at EOF (a grandchild launched with null handles) is never
enumerated by the supervisor, because the walk needs the root alive; only the
Job Object contains such a process, and `PROCESS.JOB_OBJECT_UNAVAILABLE` records
that the guarantee was absent.

### 8.5 Restart reconciliation (`reconcile_invocations`)

`reconcile_invocations(*, source: ReconciliationSource, lifecycle:
InvocationLifecycle, controller: ProcessController, preflight: PathPreflight,
clock: Clock, supervisor_instance_id, observer) -> Result[ReconciliationReport]`
walks `list_reconciliation_targets()` in source order and applies exactly one row
per record — for a `STARTING` or `RUNNING` `RUN` record the half-applied-pair
predicate of the `INVARIANT_REPORTED` row is evaluated first, before any
`STARTING`/`RUNNING` row, so a mixed pair never reaches a coupled swap that the
merged operation would refuse; every transition goes through the same lifecycle port, so the coupled
run mappings and the alone path of §5 hold, and every decision is a
`RECONCILIATION_DECISION` trace entry. `now = clock.now_utc()` is read once per
record; `facts = source.run_facts(run_id)` once per linked record (`DESCRIBE`:
`cancelled` is false, no facts). `cancelled` = `facts.cancelled` (experiment or
run `CANCELLED`, §2.5 reading 17). Every primary the pass mints carries
`run_id`/`experiment_id` from the facts and is recorded before its swap.

| State | Facts | Action | Transitions and codes |
|---|---|---|---|
| `PENDING` | any | `LEFT_PENDING` | none; the scheduler re-invokes with fresh material or cancels (Stage 10) |
| `STARTING` | cancelled | `TERMINALIZED_CANCELLED` | `STARTING → CANCELLED`, `PROCESS.CANCELLED`; run coupled `→ CANCELLED`, or alone when the run is already terminal; then `remove_command_root` and `enrich(cleanup_complete=<True only when the report is complete, else MISSING>, additional=<PROCESS.CLEANUP_FAILED per failed action>)` in the same pass (§7.5); an incomplete cleanup leaves the record for the cleanup rows below |
| `STARTING` | `now >= deadline_utc` | `TERMINALIZED_TIMED_OUT` | `STARTING → TIMED_OUT` with the kind's timeout code (`START_TIMED_OUT` for `RUN`); run coupled `→ TIMED_OUT` or alone; then `remove_command_root` and the same conditional `enrich` as the row above |
| `STARTING` | otherwise | `TERMINALIZED_FAILED_TO_START` | `STARTING → FAILED_TO_START`, `PROCESS.LAUNCH_NOT_COMMITTED` (engine-runtime, so a non-terminal run goes `→ FAILED`; alone when the run is already terminal; a RUN whose run is neither `STARTING` nor terminal is the `INVARIANT_REPORTED` row below); then `remove_command_root` and the same conditional `enrich` as the `cancelled` row |
| `RUNNING`, `RUN` kind, run neither `RUNNING` nor terminal — or `STARTING`, `RUN` kind, run neither `STARTING` nor terminal, the half-applied launch pair the coupled operation would refuse — or a `VALIDATE` at `STARTING` or `RUNNING` whose run is neither `VALIDATING` nor terminal (a run moved to `READY` has no edge to `TIMED_OUT` or `FAILED`, so no §8.5 row could terminalize the pair except by cancellation, which the `cancelled` rows above still take first) (a narrower predicate than the merged `is_mixed_running_pair`, which also counts a terminal run: terminal runs are routed to the alone-path rows below) | — | `INVARIANT_REPORTED` | no transition; `CORE.INVARIANT_VIOLATION` reported only — carried in `InvocationReconciliation.diagnostics` and the `RECONCILIATION_DECISION` entry, persisted only if a later pass attaches it (spec 15.6: a mixed pair fails safely); the process is still inspected and, when `ALIVE_MATCHING`, terminated (`PROCESS.FORCED_TERMINATION`, `reconciliation`, reported the same way) so no unverifiable live child survives the pass (spec 29.2 step 7) |
| `RUNNING` | `inspect` = `ALIVE_MATCHING` | `TERMINALIZED_PROTOCOL_FAILED` | `terminate_tree`; `RUNNING → PROTOCOL_FAILED`, `PROCESS.ORCHESTRATOR_RESTART_LOST_SUPERVISION` (+ `PROCESS.FORCED_TERMINATION`, `reconciliation`); run coupled `→ FAILED` or alone; this row deliberately precedes the `cancelled` rows: a live matching orphan is a lost-supervision fact first, and a cancelled experiment or run is still honoured by the coupled or alone path; then cleanup and `enrich(cleanup_complete=<True only when the report is complete, else MISSING>, additional=<PROCESS.FORCED_TERMINATION, PROCESS.CLEANUP_FAILED per failed action>)` in the same pass |
| `RUNNING` | `ALIVE_DIFFERENT_IDENTITY` | as the `ABSENT` rows, plus `PROCESS.PID_REUSE_DETECTED` reported (attached, and so persisted, when the row terminalizes; reported only otherwise — the write-free `LEFT_RUNNING` outcome has no recording channel); the live process is left untouched | — |
| `RUNNING` | `ABSENT`/`UNDETERMINED`, cancelled | `TERMINALIZED_CANCELLED` | `RUNNING → CANCELLED`, `PROCESS.CANCELLED`; coupled or alone; no native exit (lost exit facts are never reconstructed) |
| `RUNNING` | `ABSENT`/`UNDETERMINED`, `now >= deadline_utc` | `TERMINALIZED_TIMED_OUT` | `RUNNING → TIMED_OUT`, kind code; coupled or alone; no native exit |
| `RUNNING` | `ABSENT`/`UNDETERMINED`, otherwise | `LEFT_RUNNING_AWAITING_DEADLINE` | none; `manifest_present` (file existence at the planned result path) reported for `RUN` |
| terminal, `cleanup_complete=false`, `process_created=true`, not `EXITED` | `inspect` alive-matching | `CLEANUP_COMPLETED` / `CLEANUP_FAILED` | `terminate_tree`, re-inspect, `enrich(cleanup_complete=True, additional=[FORCED_TERMINATION])` or `PROCESS.CLEANUP_FAILED` |
| terminal, `cleanup_complete=false`, `process_created=true`, `EXITED` or process absent (`ABSENT`, `UNDETERMINED`, or `ALIVE_DIFFERENT_IDENTITY` — a reused pid is not ours and is left untouched) | — | `CLEANUP_COMPLETED` | no inspection for `EXITED`; `enrich(cleanup_complete=True)`, with `PROCESS.PID_REUSE_DETECTED` attached on that enrichment for the different-identity case |
| terminal, `cleanup_complete=false`, `process_created=false` | — | `CLEANUP_COMPLETED` / `CLEANUP_FAILED` | `remove_command_root`, then `enrich(cleanup_complete=True)` or `PROCESS.CLEANUP_FAILED` |
| terminal, `cleanup_complete=false`, every new `PROCESS.CLEANUP_FAILED` identity already on the record | — | `CLEANUP_STILL_FAILING` | no write (an enrichment adding nothing is refused); reported |
| any row whose swap failed | stored record terminal (external winner) or otherwise unchanged | `SKIPPED_EXTERNAL_WINNER` | none; the next reconciliation re-evaluates the record |

The reconciler never produces `EXITED`, never writes a run success state, never
kills a process by pid alone (identity first), never attaches a directory to a run
by name, never removes a post-`RUNNING` root, and never reads a request file (it
does not re-materialize a raw token; `manifest_present` is existence only).

### 8.6 Stale-attempt protection (spec 15.7)

Identity is enforced at every boundary the supervisor owns: the command's
`invocation_id` must equal the record's; the envelope header must echo the
invocation id, kind, timeout and deadline; every stdout line is accepted only
through the merged parser against the live `RUNNING` record and the envelope's
token hash, so a line from an older attempt, a superseded invocation or the other
command kind fails identity before anything else; the output file is read only
from the core-selected path of this invocation and parsed by the merged parsers,
which check `invocation_id`, run, request and token identity (rows 15, 17, 18,
47); late lines after a terminal decision cannot change it (reading 13); a stale
child is never re-owned after restart (§8.5 turns a live matching process into
`PROTOCOL_FAILED` and leaves a different-identity process alone); the adapter
never receives a registry or final path. A retry creates a new invocation, root
and token through the Stage 5 operations, never by reusing a path; a stale writer
from attempt one cannot reach attempt two's root because the two roots differ in
`invocation_id` and `run_id`.

## 9. Fake adapters and the contract matrix through the production supervisor (matrix E)

### 9.1 The Stage 7 fake script

`tests/fake_adapters/supervision_fake.py` is a second stdlib-only script. Its
first statements insert its own directory into `sys.path` (the `-I` flag omits the
script directory) and import the merged helpers from `fake_adapter`
(including `load_request`, `Wire`, `Run`, `emit`, `emit_stderr`, `write_bytes`,
`canonical`, `bootstrap_envelope`, `validation_result`, `REQUEST_INVALID_EXIT`,
`HEARTBEAT_PERIOD_SECONDS`); its import roots are exactly
`argparse`, `fake_adapter`, `json`, `os`, `signal`, `subprocess`, `sys`, `time`,
pinned by the Stage 7 guard together with the single `sys.path.insert` and the
rule that its one `subprocess.Popen` is a list argv with `shell=False` carrying
`# noqa: S603 - reviewed fixed interpreter boundary` (ruff S603 fires on every
`Popen` call, as the merged harness's own `noqa` shows). Before
calling `load_request` it widens the merged identity check in-process —
`fake_adapter.KNOWN_ADAPTER_NAMES[command] = fake_adapter.KNOWN_ADAPTER_NAMES[command]
| frozenset(SUPERVISION_TABLES[command])` (a module-level dict of frozensets that
`load_request` reads as a global; the merged script, run as a program, still exits
`10` for every Stage 7 name because the rebinding is process-local, and a Task 8
test proves it) — then dispatches through its own `DESCRIBE`/`VALIDATE`/`RUN`
tables and its own `main()`, exiting `10` for any other name. That single
rebinding statement is pinned by the Stage 7 guard beside the single
`sys.path.insert`. The merged `fake_adapter.py` is not edited.

| Adapter name | Command | Behaviour | Expected through the production supervisor |
|---|---|---|---|
| `fake.cancellation-graceful` | run | installs `signal.signal(signal.SIGBREAK, handler)` where the handler calls `os._exit(50)`; heartbeats every 0.2 s in 0.2 s sleeps until interrupted | `CANCELLED`; run `CANCELLED`; `PROCESS.CANCELLED`; `InterruptOutcome.DELIVERED` in the trace; native exit `50` by enrichment; no `PROCESS.FORCED_TERMINATION`; elapsed below the grace |
| `fake.cancellation-ignores-interrupt` | run | `signal.signal(signal.SIGBREAK, signal.SIG_IGN)`; heartbeats until killed | `CANCELLED`; `PROCESS.FORCED_TERMINATION` (`grace_elapsed`); native exit `1067`; elapsed at least the grace |
| `fake.grandchild` | run | `signal.signal(signal.SIGBREAK, signal.SIG_IGN)`, then `subprocess.Popen([sys.executable, "-I", "-B", "-c", "import signal, time; signal.signal(signal.SIGBREAK, signal.SIG_IGN); time.sleep(60)"], stdin=DEVNULL, stdout=DEVNULL, stderr=DEVNULL, close_fds=True, shell=False, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)`; writes `grandchild_pid=<n>\n` to stderr; heartbeats until terminated (both processes survive the interrupt, so the forced path after the grace is what the row exercises) | `CANCELLED` after the test cancels on the first heartbeat (grace 1); `PROCESS.FORCED_TERMINATION` (`grace_elapsed`); `TerminationReport.descendants` contains the reported pid; every descendant identity `ABSENT` afterwards; `cleanup_complete` true |
| `fake.grandchild-inherits-stdout` | run | handler-less; spawns the sleeper with `stdout=sys.stdout.fileno()`, `stdin=DEVNULL`, `stderr=DEVNULL` and the default `close_fds=True` (the stdlib then inherits exactly the three std handles it was given, so only the stdout pipe leaks to the sleeper; `close_fds=False` would hand it every inheritable handle, the stderr pipe included, and a bare `Popen` would inherit nothing), no `CREATE_NEW_PROCESS_GROUP`; writes `grandchild_pid=<n>\n` to stderr, then a `SUCCEEDED` manifest with no candidates, `FINAL_RESULT`, and exits `0` at once | with the job attached (the ordinary case, asserted through the absence of `PROCESS.JOB_OBJECT_UNAVAILABLE`): the root exit is reaped while stdout stays idle and open; after `PIPE_HOLDER_GRACE_SECONDS` the supervisor terminates the tree (`PROCESS.FORCED_TERMINATION`, `pipe_holder`), EOF arrives and the ordinary decision follows: `EXITED` with native exit `0` on the transition, `RESULT_FINALIZATION_ELIGIBLE`, the sleeper dead afterwards; on a host where the job could not be attached the sleeper is unreachable (its parent is dead, so Toolhelp never enumerates it), so the row uses `timeout_seconds=3` and then asserts `TIMED_OUT` (`PROCESS.RUN_TIMED_OUT`), `PROCESS.FORCED_TERMINATION` (`pipe_holder`), `PROCESS.JOB_OBJECT_UNAVAILABLE`, exactly one `FORCED_TERMINATION` trace entry and `terminate_calls == [FORCED_TERMINATION_EXIT_CODE]` (the step-8 kill; the later `PROCESS_GONE` branch terminates nothing again), the stdout reader ended through `cancel_read` — observable as the completed `CLEANUP_ACTION` entry for `STDOUT_READER_STOPPED` whose fact `ended_by` is `"CANCELLED"` (a state name, admissible in `facts`) — `cleanup_complete=true` (the root is reaped, no descendant was recorded, both pipes closed), and the sleeper still `ALIVE_MATCHING` by its reported pid until the test terminates it in `finally:` — the stated limitation of §8.2 |
| `fake.stdout-flood` | run | 5000 valid heartbeats emitted back to back, then a `SUCCEEDED` manifest with no candidates, `FINAL_RESULT`, exit `0` | `EXITED`; `accepted_events` count 5001 (5000 heartbeats and the `FINAL_RESULT`); `replay_count == 0`; `RESULT_FINALIZATION_ELIGIBLE` |
| `fake.argv-echo` | describe, validate, run | emits `canonical({"argv": sys.orig_argv[1:], "arguments": sys.argv[1:], "isolated": sys.flags.isolated, "dont_write_bytecode": sys.flags.dont_write_bytecode, "cwd": os.getcwd(), "environment_keys": sorted(os.environ)})` as one line on **stderr** (present as `StderrCapture.sanitized_text`, the redacted UTF-8 decode of the retained bytes — a no-op here because no token occurs — and under every kind's stderr limit; `sys.argv[1:]` alone would omit the interpreter options and the script, which the interpreter strips) and writes only the kind's ordinary output (describe: a valid bootstrap envelope; validate: `VALID`; run: a `SUCCEEDED` manifest with no candidates) — no sibling file, so the §7.3 write boundary stays clean | `EXITED`; no `PROCESS.WRITE_BOUNDARY_VIOLATION`; after narrowing `sanitized_text` with `isinstance(..., str)` and `json.loads`, `argv == ["-I", "-B", <script>, *argument_array(command)]` element by element, `arguments == argument_array(command)`, `isolated == 1` and `dont_write_bytecode == 1`; `cwd == command_root`; the planted parent sentinel and the parent-only keys (`PATH`, `SYSTEMROOT`, `USERPROFILE`) are absent from `environment_keys` (two host-injected names may be present, so the assertion is on absences) |

The Stage 7 scenario table `tests/integration/process_supervision/supervision_scenarios.py`
(`SUPERVISION_SCENARIOS`) holds these rows; the merged `SCENARIOS` is untouched.

### 9.2 The Stage 7 test doubles — `tests/doubles/supervision.py`

| Double | Purpose |
|---|---|
| `SupervisionFixedClock(FixedClock)` | the scripted fixture's clock: `rewind_utc(seconds)` moves only the UTC instant backwards (the own-request-defect row of §5.3), leaving the monotonic accumulator untouched; `advance` inherited (Task 6) |
| `RealtimeMonotonicClock(FixedClock)` | `monotonic()` = `MonotonicInstant(time.monotonic() + offset)`; `advance_monotonic(seconds)` moves the offset; `now_utc`/`advance` inherited (added in Task 6) |
| `SeedingDiagnosticRecorder(store)` | `record(diagnostic)`: `store.seed_diagnostic` when the identity is absent, else success (idempotent); `calls: list[DiagnosticId]` records every call in order; it implements no `get`/`get_many`, so the §2.6 reader-implementation count is untouched |
| `InMemoryReconciliationSource(store)` | `list_reconciliation_targets` over `committed_command_invocations()` filtered and ordered per §3.4; `run_facts` over the committed runs and experiments |
| `RecordingObserver` | collects `SupervisionTraceEntry`s; `on(kind, callback)` hooks (row 27 trips the token on the first `EVENT_ACCEPTED` heartbeat) |
| `ScriptedProcessController` / `ScriptedProcess` | a script of `stdout_chunks`, `stderr_chunks`, `exit_after` (counted in `wait(0.0)` polls), `exit_code: int = 0` (what `wait` returns once `exit_after` polls have passed), `interrupt_outcome` (what `interrupt()` returns), `job_available: bool = True`, `job_error_code: int | MISSING = MISSING`, `image_path: ExecutablePath | MISSING = MISSING` (the launch facts the port exposes), `terminate_report`, `inspection`, `launch_failure` (a `LaunchFailure` returned instead of a process), `interrupt()` returning `PROCESS_GONE` once the script has exited, `hold_stdout_open`/`hold_stderr_open`, an `on_launch` hook and a `launches: tuple[LaunchSpecification, ...]` record, plus the counters `terminate_calls: list[int]` (the exit codes passed to `terminate_tree`, from the process or the controller) and `interrupt_calls: int` and the recorded `close_flags`; the process advances one script step per `wait(0.0)` poll and hands one chunk per `stdout.read`/`stderr.read` call, then EOF after the last chunk; under `hold_*_open` the read after the last chunk blocks on a `threading.Event` and EOF is withheld until `terminate_tree` is called on the process (or on the controller for its identity), after which the next read returns EOF — unless `release_on_terminate=False` (default `True`), which models a holder the kill cannot reach: EOF then never arrives and only `cancel_read` ends the read; the poll numbered `exit_after` returns `exit_code` (so `exit_after=1` means the first poll — the one at the top of the first tick, §6.3 step 0 — reaps); a `wait(0.0)` that has already returned a code repeats it forever, and a process that had not yet exited reports `code` on the first `wait(0.0)` after `terminate_tree(code)` (the real `Popen.wait` is idempotent, so the double is too); `inspect(identity)` reports `ABSENT` for any identity whose `terminate_tree` has been called on this controller or its process, regardless of the scripted `inspection`; script defaults: `stdout_chunks=[]`, `stderr_chunks=[]`, `exit_after=None` (never exits unless terminated; a test that needs a clean exit sets `exit_after=1`), `exit_code=0`, `hold_*_open=False`, `interrupt_outcome=DELIVERED`, `inspection=ABSENT`, `terminate_report` complete; `cancel_read(native_thread_id)` releases a held read with `OSError(errno.EINVAL)` (the real cancelled-read error) and returns `True`, so the reader's `CANCELLED` path is exercised deterministically; `close(close_stdout=..., close_stderr=...)` records its flags and returns a complete `CleanupReport` of the four controller actions; so the supervisor's own reader threads and tick loop drive it and the test thread only awaits `invoke`; no real process |
| `RecordingLifecycle(inner)` | wraps a `Stage5InvocationLifecycle` structurally (all nine port members): `calls: list[str]`, `before(method, hook)` (runs the hook once before the named call, so a test can move a record or the clock at that instant), `fail(method, code)` (one-shot `Failure` with that code instead of the call) |
| `TeeController(inner)` | wraps a controller: `launch` snapshots the command root, wraps `stdout` in a tee that records every byte, and returns the inner process; `launches` lists every `LaunchSpecification` (the row-47 stale file is planted by the strategy's observer on `REQUEST_WRITTEN`, before the supervisor's baseline snapshot, never by the tee) |
| `supervised_catalog_entry_for(adapter_name, *, script=None, executable=None)` | §4.2 (`script` overrides the name-based choice — the Task 8 test that launches the merged script under a Stage 7 name; `executable` replaces the venv launcher — the §10 Unicode-executable test — with the hash computed from that file); the module derives the merged fake's path as `Path(__file__).resolve().parents[1] / "fake_adapters" / "fake_adapter.py"` (a test pins it equal to the harness's `FAKE_ADAPTER_PATH`) so it never imports `contract.harness` (the `FAKE_ADAPTER_PATH` branch from Task 6, the `SUPERVISION_FAKE_PATH` branch from Task 8) |
| `build_supervisor(*, lifecycle, controller, clock, supervision_root, supervisor_instance_id=SCRIPTED_SUPERVISOR_INSTANCE_ID, cancellation_grace_seconds=1, describe_limits=PROTOCOL_LIMITS_DEFAULT, preflight=MISSING, observers=())` (`SCRIPTED_SUPERVISOR_INSTANCE_ID = "scripted-supervisor"`, a module constant of `tests/doubles/supervision.py` — named apart from the harness's `SUPERVISOR_INSTANCE_ID`, which the Task 8 strategy module imports beside it — that the scripted fixture, the production strategy and the Task 7 identity helpers use; Task 4 binds its own module-level values because it precedes Task 5) | a `WindowsProcessSupervisor` over the given lifecycle, controller and clock (the scripted fixture passes its `SupervisionFixedClock` and `ScriptedProcessController`; the production strategy its `RealtimeMonotonicClock` and the tee-wrapped Windows controller), with an optional injected `PathPreflight` and observers (Task 6) |

### 9.3 The harness seam

`OfflineCommandHarness` gains one constructor parameter, `supervise:
SuperviseStrategy | None = None` (threaded through `build_harness(...,
supervise=None)`), and `drive`/`describe`/`validate`/`run` route the span from the
`PENDING` invocation to the terminal record through it when present; the default
path is today's code, byte for byte in the lines the Stage 6 pins inspect (the one
`Popen`, its keyword set, the `# noqa` line, the "stand-in" wording, no
`ProcessSupervisor` class). `OfflineCommandHarness` stores the strategy as the public attribute
`supervise` (`None` on the default path); `build_harness` takes the harness clock
from `supervise.clock` when a strategy is given (the production strategy supplies a
`RealtimeMonotonicClock(INSTANT)`) and constructs `FixedClock(INSTANT)` otherwise,
so the harness module never imports `doubles.supervision`.

```python
class SuperviseStrategy(Protocol):  # tests/contract/harness.py
    @property
    def clock(self) -> FixedClock: ...  # the clock the harness must use
    def supervise(
        self, harness: OfflineCommandHarness, plan: CommandPlan
    ) -> _Supervised: ...


@dataclass(frozen=True, slots=True)
class CommandPlan:
    invocation: CommandInvocationRecord  # PENDING
    run: EngineRunRecord | None
    material: RequestMaterial  # describe payload, or token + negotiated + limits
    cancel_after_first_heartbeat: bool
    stale_output_bytes: bytes | None  # row 47
```

`_Supervised` is relaxed in three fields: `events: tuple[RunEvent, ...]` and
`summary: ProtocolEventSummary` replace `ledger`, and
`supervision_outcome: SupervisionOutcome | None` (`None` on the default path)
keeps the whole outcome for the production-only assertions; `CommandRun` gains the
same field, filled from `supervised.supervision_outcome` at both of its
construction sites (`describe` and `_conclude`), so `harness.drive`/`validate`/`run`
return it and `tests/contract/test_harness_safety.py` pins it `None` on the default
strategy (the default path fills them from
its live ledger; the production path from `command_result.accepted_events` and
`SupervisionOutcome.protocol_summary`, so row 40's `redactions == 1` still comes
from the live summary), and `rejection: EventRejected | None` is filled from the
trace entry that carries it only when the decided state is `PROTOCOL_FAILED`
(`CommandResult.protocol_integrity` is `VIOLATED` iff the decided state is
`PROTOCOL_FAILED`; a rejection observed during a grace window stays an additional
diagnostic and a trace entry, and `rejection` is `None`). The production strategy
(`tests/integration/process_supervision/supervised_strategy.py::ProductionSupervision`):
binds `Stage5InvocationLifecycle(unit_of_work=harness._unit_of_work(),
clock=harness.clock, diagnostics=SeedingDiagnosticRecorder(harness.store))`,
registers `plan.material`, builds the `AdapterCommand` from `plan_command_paths`
and `supervised_catalog_entry_for`, wraps the Windows controller in a
`TeeController` (snapshotting the root for `written_paths`), plants
`stale_output_bytes` beside `output.json` from the recording observer's
`REQUEST_WRITTEN` hook (after the request file exists and before the supervisor's
baseline snapshot, §7.3), arms a
`ThreadSafeCancellationToken` that the recording observer trips on the first
accepted heartbeat when `cancel_after_first_heartbeat`, runs
`asyncio.run(supervisor.invoke(command, token))`, and maps `SupervisionOutcome`
to `_Supervised`: `invocation` = `command_result.invocation` (the post-enrichment
record), `run` = `harness.stored_run(...)`, `events`/`summary`/`replayed`/
`stderr`/`diagnostics`/`stdout_bytes_seen` from the outcome, `supervision_outcome` =
the outcome itself, `raw_lines` from the
tee re-framed with the snapshot's `max_event_bytes`, `written_paths` from the tee
snapshot difference minus the stale plant. The strategy's `clock` is a
`RealtimeMonotonicClock(INSTANT)`, which `build_harness` adopts (row 47 still
calls `advance` for the retry delay). The epilogue (`_conclude`, `_observation`, the
`_observe_candidates` observation, `apply_command_semantic_outcome`,
`assert_token_absent`, `assert_token_only_in_wire_material`) runs for both
strategies; `_conclude` and `run()` switch their three `supervised.ledger` reads
(`ledger.summary()` twice, `ledger.events` once) to `supervised.summary` and
`supervised.events`, and only the pinned launch lines stay byte-identical.

### 9.4 Rows through the production supervisor

`tests/integration/process_supervision/test_supervised_contract_matrix.py`
re-implements the four Stage 6 contract modules' per-kind assertions locally
(shared helpers in `supervised_strategy.py`), drives row 47 through the merged
`_stale_attempt` sequence (validate, run, `harness.successor`, `harness.validate(...,
stale_output_bytes=...)`) under the production strategy, and otherwise
parametrizes the 58 `SCENARIOS` entries through `build_harness(...,
supervise=ProductionSupervision(cancellation_grace_seconds=1))` (the merged
`PROCESS.START_TIMED_OUT` direct case never launches a child and stays where it is;
the `STARTING`-origin timeout through the supervisor is the scripted
`test_a_deadline_passing_before_the_handoff_times_out_from_starting_without_process_facts`
of Task 6) and
asserts, per entry, exactly what the four Stage 6 contract modules assert for that
entry (state, run state or verdict, primary and secondary codes, accepted-event
count, sanitized-manifest presence, the two token assertions), plus three
production-only facts: `pid_identity.creation_identity` parses as
`windows:<pid>:<creation>`, a clean `EXITED` row carries no Stage 7 diagnostic,
and every descendant recorded at termination is not `ALIVE_MATCHING` afterwards.
Rows whose expectation changes only in a way the Stage 6 assertions tolerate:

| Rows | Production difference | Assertion |
|---|---|---|
| 25, 26 (three entries), 27 | interrupt then grace (1 s) then force instead of an immediate kill; the native exit is `3221225786` (a handler-less child dies on the interrupt) or `1067`; for the two 1 s linked entries of row 26 (validate and run) the invocation may instead end `STARTING`-origin (`PROCESS.VALIDATE_TIMED_OUT` or `PROCESS.START_TIMED_OUT`, `process_created=False`, no exit pair, the coupled run `TIMED_OUT` with `run.primary_terminal_diagnostic_id == invocation.primary_diagnostic_id`) when the pre-handoff span exceeds the 1 s budget on a loaded host, because the production deadline runs from the swap and the stand-in's from `Popen`; the describe entry needs no tolerance (the Stage 6 describe `TIMED_OUT` branch asserts nothing about an exit pair) | presence of the exit pair only for the `RUNNING`-origin form, as Stage 6 asserts; the value is never pinned; `assert_stage_six_expectation` accepts either form for row 26's validate and run entries, and the measured pre-handoff span of both is recorded beside row 25's margin in the Task 8 evidence |
| 25 | `PROCESS.FORCED_TERMINATION` may join the additional ids | the row's exact one-element `causal_diagnostic_ids` of `PROCESS.RUN_TIMED_OUT` holds because termination codes are additional, never causal |
| 21 | the tee records the one stdout byte | `stdout_bytes_seen == 1`, `EXITED`, `DESCRIBE_UNAVAILABLE` unchanged |
| 47 | the stale file is planted by the observer's `REQUEST_WRITTEN` hook, before the baseline snapshot, so the boundary treats it as pre-existing | unchanged (no `PROCESS.WRITE_BOUNDARY_VIOLATION`) |
| every `EXITED` row | one enrichment (`cleanup_complete`) even without secondaries: the invocation revision is one higher than under the stand-in | Stage 6 asserts states and codes, not revisions; the flow test's `revision - 1` snapshot is default-strategy only |
| every describe row | `describe_limits = harness.limits` | unchanged |

The five adapter-side tamper vectors stay on the stand-in path by declared scope:
they test the fake adapter's own verification against a tampered request file, a
property of the merged fake that the stand-in already proves; the three file
tampers could be replayed through the `REQUEST_WRITTEN` observer hook (the
supervisor never re-reads the request file), and the `work-dir-tail-run` vector is
refused before the swap by §4.4, but neither adds a supervisor fact, so Task 8
leaves them where they are and says so in its evidence.

### 9.5 Deterministic race tests

`tests/unit/process_supervision/test_supervisor_loop.py` drives
`WindowsProcessSupervisor` with the `ScriptedProcessController`, a
`RecordingLifecycle` over `Stage5InvocationLifecycle` and the in-memory store, a
`RecordingObserver`, and a `FixedClock` whose `advance(seconds)` moves both
instants. The `scripted` fixture exposes `supervisor`; `lifecycle` (the recording
wrapper: `calls`, `before`, `fail`); `controller` (`launches`, `terminate_calls:
list[int]`, `interrupt_calls: int`, `on_launch`, `close_flags`, `polls_between(kind_a, kind_b)` — the number of `wait(0.0)` polls between the first observer entries of two kinds); `observer`
(`entries`, `on`); `clock`; `store`; the seeded commands `run_command`,
`validate_command`, `describe_command` (each built over
`supervised_catalog_entry_for("fake.conformant")` — the hash-matching venv
interpreter, so the executable observation of §4.4 passes even though the scripted
controller launches nothing; the absent- and mismatched-executable cases rebuild
the entry — and a supervision root under `tmp_path`; each with its `PENDING`
invocation and, for
the linked kinds, its run, whose `request_hash` is `request_material_hash(...)`
over the registered material's limits and whose `attempt_token_hash` matches the
registered token material, both registered by the fixture so `begin_start`'s
pre-swap revalidation passes; `describe_command`'s invocation is seeded with
`request_hash = request_hash_of(<the registered DescribeRequestPayload>)`, as the
harness's `describe` does) and `timeout_seconds` (`4`; the seeded material's
limits mirror the merged heartbeat rows of `tests/contract/scenarios.py`:
`heartbeat_interval_seconds=1`, `missing_heartbeat_seconds=2`, so a missed
heartbeat is due before the deadline; `build_supervisor` uses
`cancellation_grace_seconds=1`); the pass-through script fields
`stdout_chunks`, `stderr_chunks`, `exit_after`, `exit_code`, `hold_stdout_open`,
`hold_stderr_open`, `release_on_terminate`, `job_available`, `job_error_code`,
`image_path` (written straight onto the controller's script, whose defaults
§9.2 fixes: an empty script that never exits unless terminated); `reset()` (fresh
invocation, run and script for a second `invoke`; it also clears
`lifecycle.calls`, `controller.launches`/`terminate_calls`/`interrupt_calls`/
`close_flags` and `observer.entries`; `lifecycle.calls` records every wrapper
call, an intercepted `fail` included); the lifecycle-bound
helpers `stored_run()`, `stored_invocation()`, `cancel_run_externally()` (moves
only the run `→ CANCELLED`, as `transition_run` would),
`terminalize_invocation_externally()` (writes the invocation's own coupled
`CANCELLED` through `transition_invocation_and_run`, so the supervisor's next write
finds a terminal record), `cancel_experiment_externally()` (the merged
`cancel_experiment` on the seeded experiment), `start_invocation_externally()`
(drives the seeded `PENDING` invocation to `STARTING` through a second
`Stage5InvocationLifecycle.begin_start` over the same store, modelling another
actor's write), `missing_heartbeat_id()` (the minted
`PROCESS.MISSING_HEARTBEAT` identity read from the store) and `codes_of_ids(ids)`
(the codes of stored diagnostics by identity); `wait_bounds: list[float]` (the
`timeout_seconds` handed to every `wait_for_chunk` call, recorded by a
fixture-installed wrapper around the name `supervisor.py` imports from
`readers.py` — the observable that pins §6.3 step 9's bound rule); `advance_per_tick(seconds)` (the
controller advances the clock by that amount on every `wait(0.0)` poll; the
default is `TICK_SECONDS`, so grace windows, deadlines and the pipe-holder window
elapse without real time) and `step_utc_backwards_before(method)` (a `before` hook
that rewinds only the UTC instant by one second through the fixture clock's
`rewind_utc(seconds)` — the `SupervisionFixedClock` of §9.2, a `FixedClock` subclass
whose `rewind_utc` subtracts a `timedelta` from the UTC instant and leaves the
monotonic accumulator untouched; never `advance` with a negative argument, which
Task 1 makes raise `ValueError`). It runs one test per
row of §6.4 and one per row of §5.3, asserting the decided state, the primary and
additional codes, the trace order (`TERMINAL_DECIDED`, `TERMINAL_COMMITTED`, then
`INTERRUPT_SENT` or `INTERRUPT_UNAVAILABLE`, `FORCED_TERMINATION` when forced,
`EXIT_REAPED`, the `CLEANUP_ACTION` entries, and `ENRICHMENT_COMMITTED` last), the
single enrichment (exactly one `ENRICHMENT_COMMITTED` entry; the
recorded lifecycle calls show one `enrich`), the exit pair written by the right
swap, and that the returned record equals the stored one.

### 9.6 Documentation and status text (Task 9)

`_README_STAGE7_STATUS`: "Project 1 Stage 7 is complete. Shell-free absolute
argument-array launch with a fresh empty environment, bounded stdout and stderr
readers, incremental protocol parsing, paired UTC and monotonic deadlines,
heartbeat liveness, graceful and forced termination with Job Object process-tree
cleanup, durable PID creation identity, path preflight, stale-invocation rejection,
and restart reconciliation are implemented. Stage 7 implementation completed at
`<STAGE7_IMPLEMENTATION_COMMIT>`; the Stage 7 boundary guard and this status
were added by the separate Task 9 commit, which is not the implementation hash. No schema was added: the closed
35-schema registry is preserved byte-identical. The fake adapters run through the
production supervisor as well as the test-resident stand-in. Stage 8 has not
started." `_VERIFICATION_STAGE7_STATUS` carries the same facts hard-wrapped at 80
columns and ends "Stage 8 is not started." The roadmap Stage 7 row follows the
Stage 6 row's shape minus its schema and flow clauses (Task 9 adds neither a schema
nor a flow test: the supervised matrix and the Windows suites are Task 8's, the
implementation commit), reading "together with the Stage 7 boundary guard and this
status were added by the separate Task 9 commit", with `STAGE7_IMPLEMENTATION_COMMIT`
and ending "; Stage 8 not started |"; the Stage 6 row's last clause becomes "; Stage 7 complete |"; the
"Planned detailed implementation plan" line becomes "Approved". The guide's Stage 6
paragraph that says the fakes run "never through a production supervisor" and
names "the ten `subprocess` importers" is rewritten (both facts change), and the
Stage 7 focused checks of §13.1 are added. `docs/development/verification.md`'s
sentence "Stage 7 retains physical ancestor reparse-point and volume containment."
stays.

## 10. Windows platform tests (matrix H)

All real-process tests use `supervised_catalog_entry_for`, a supervision root under
`tmp_path`, a `RealtimeMonotonicClock`, timeouts of 30 s unless stated, and end by
asserting in a `finally:` that every identity they launched or recorded is not
`ALIVE_MATCHING`. Every real-process interrupt test requires the test process to be
attached to a console (`windows_api.console_process_count()` positive, asserted
with an explicit message at the top of the graceful, forced and Task 4 interrupt
tests), which every documented launch path satisfies; under a console-less runner
those rows would observe `InterruptOutcome.UNAVAILABLE` per reading 4. The tests
end by
asserting in a `finally:` that every identity they launched or recorded is not
`ALIVE_MATCHING`. No test skips; the long-path success arm asserts the rejection
branch when the probe reports no support. Module basenames are unique across
`tests/`.

| Requirement (spec 28.5) | Module :: test | Mechanism and assertion |
|---|---|---|
| Paths with spaces | `test_windows_paths.py::test_a_supervision_root_with_spaces_reaches_exited_for_every_kind` | real; root `tmp_path / "sup root a"`; `fake.conformant` for describe, validate, run; `EXITED`, parsed output, `written_paths` under the layout |
| Unicode path components | `...::test_a_unicode_supervision_root_reaches_exited_for_every_kind` | real; root `tmp_path / "ünï cøde ✓"` |
| Unicode and space in the catalog executable and script paths | `...::test_a_unicode_executable_and_script_path_are_launched` | real; the venv launcher (`sys.executable`) and the fake script are copied byte-identically to `tmp_path / "ünï cøde" / "python launcher.exe"` and `"fake adapter.py"`, together with the venv's `pyvenv.cfg` placed beside the copied launcher (CPython's `venvlauncher` resolves the base interpreter from the `pyvenv.cfg` beside it or in its parent and forwards the child's exit code; a uv trampoline build launches the interpreter named by its `UV_PYTHON_PATH` resource whether or not `pyvenv.cfg` is present — either way the copy launches, and the exit-0-plus-parsed-output assertion makes a resolution failure fail); the entry is built with `supervised_catalog_entry_for(name, executable=<the copy>, script=<the copied script>)`; `EXITED` with native exit `0` and the kind's parsed output, so a launcher failure cannot pass; negative controls: the catalog `executable_hash` with one hex digit flipped → `FAILED_TO_START` with `CORE.IMMUTABLE_INPUT_MISMATCH`, no launch; the copy deleted → `FAILED_TO_START` with `ADAPTER.UNAVAILABLE`, run `UNAVAILABLE`, no launch |
| Long paths, conditional | `...::test_long_paths_succeed_when_supported_and_are_rejected_deterministically_otherwise` | real; the root length is computed from the layout so the RUN command root is 240..247 characters and the manifest path exceeds 259; `supported = ok(probe_long_path_support(root, now=INSTANT)).long_paths_supported`; both arms assert; coverage of the supported arm comes from `test_supervision_roots.py` cases that inject the probe result |
| Long paths, always-run rejection | `...::test_a_command_root_longer_than_the_directory_ceiling_is_rejected_on_every_host` | root chosen so the command root is 248+ characters; the command root is bounded at 247 regardless of the probe (it is the child's `cwd`), so on every host: `PROCESS.PATH_PREFLIGHT_REJECTED`, zero launches, record still `PENDING`; a second case injects an unsupported `PathPreflight` and a work directory over 247 → the same rejection |
| Junction and reparse rejection | `...::test_a_supervision_root_under_a_junction_is_rejected_before_any_launch`, `...::test_a_junction_planted_as_the_command_root_parent_is_rejected`, `...::test_an_executable_path_through_a_junction_is_refused_even_with_a_matching_hash` | `_winapi.CreateJunction(target, link)` (no privilege, no `subprocess`; the target directory and the probed subdirectory are created first, because the call requires an existing directory); the two root/command-root tests assert the pre-swap `Failure(PROCESS.PATH_PREFLIGHT_REJECTED)` with `details["reason"] == "ancestor_reparse_point"` and zero launches; the executable test (the copied launcher reached through a junction, with its true hash in the entry, so only the ancestor walk can refuse it) asserts a `Success` whose invocation is `FAILED_TO_START` with primary `CORE.IMMUTABLE_INPUT_MISMATCH` and `details["reason"] == "ancestor_reparse_point"`, run `FAILED`, `controller.launches == ()`; never the code alone; positive control through a plain directory; `os.rmdir` in `finally:` |
| Argument-array preservation | `test_windows_launch_arguments.py::test_the_fake_echoes_exactly_the_argument_array_for_every_kind`, `...::test_spaces_quotes_unicode_and_blank_looking_components_survive` | real; `fake.argv-echo`; byte-level compare of the echoed `argv` (`sys.orig_argv[1:]`, parsed from `StderrCapture.sanitized_text` after narrowing `MISSING`) with `["-I", "-B", script, *argument_array(command)]` and of `arguments` with `argument_array(command)`; `isolated == 1`; no `PROCESS.WRITE_BOUNDARY_VIOLATION`; hostile content lives in path segments (a space, `'`, Unicode, two spaces) |
| Fresh environment block | `...::test_the_child_sees_no_parent_variable` | real; `monkeypatch.setenv("CRYPTO_LAB_PARENT_SENTINEL", ...)`; the echoed key list lacks the sentinel, `PATH`, `SYSTEMROOT`, `USERPROFILE` |
| Process group, Job Object, handle cleanup | `test_windows_process_tree.py::test_a_grandchild_dies_with_the_tree_and_every_handle_is_closed` | real; `fake.grandchild`; cancel on the first heartbeat, grace 1; `CANCELLED`, `cleanup_complete`, the reported pid in `descendants`, every descendant `ABSENT` |
| Graceful termination | `...::test_a_graceful_interrupt_lets_the_adapter_exit_fifty_within_grace` | real; `fake.cancellation-graceful`; grace 5; native exit `50`, `DELIVERED`, no forced termination, elapsed below the grace |
| Forced termination after grace | `...::test_an_adapter_ignoring_the_interrupt_is_force_terminated_after_grace` | real; `fake.cancellation-ignores-interrupt`; grace 1; `PROCESS.FORCED_TERMINATION`, native exit `1067`, elapsed at least 1 s and below 3 s |
| Job Object unavailable fallback | `...::test_when_the_job_object_is_unavailable_toolhelp_termination_still_kills_the_grandchild` | real; controller built with a failing `job_object_factory`; `PROCESS.JOB_OBJECT_UNAVAILABLE`, descendants `ABSENT` |
| Undeliverable interrupt | `...::test_an_undeliverable_interrupt_records_the_limitation_and_still_waits_the_grace` | scripted `interrupt() -> UNAVAILABLE`; `PROCESS.GRACEFUL_INTERRUPT_UNAVAILABLE`; the trace shows the grace wait before `FORCED_TERMINATION` |
| Backpressure | `...::test_a_stdout_flood_is_drained_without_deadlock` | real; `fake.stdout-flood`; 5001 accepted events (no dropped line), `replay_count == 0` and no `PROTOCOL.*` diagnostic; whether the 64-chunk queue ever fills depends on the parser's speed relative to the child, so `put_retries` is not asserted here — the deterministic proof of backpressure is the Task 3 `_SlowSink` unit test, and a bounded queue's depth is never asserted because it cannot exceed its capacity |
| Durable creation identity across handle loss | `test_windows_process_identity.py::test_the_creation_identity_survives_the_loss_of_every_handle` | real; launch `[sys.executable, "-I", "-B", "-c", "import signal, time; signal.signal(signal.SIGBREAK, signal.SIG_IGN); time.sleep(60)"]` directly through a `WindowsProcessController` built with a failing job factory (no request root is needed), close the pipes and drop every Python reference to the process object (no job to close), `inspect` with a fresh controller → `ALIVE_MATCHING`; `terminate_tree(identity)` → `ABSENT` |
| PID reuse protection | `...::test_a_live_process_with_a_different_creation_time_is_not_ours` | API; the test process's own pid with `creation_100ns - 1` → `ALIVE_DIFFERENT_IDENTITY`; the true value → `ALIVE_MATCHING`; a finished launch → not `ALIVE_MATCHING` |
| Identity checks for every invocation state | `tests/unit/process_supervision/test_restart_reconciliation.py` | scripted; the full §8.5 table parametrized over state × kind × {cancelled, deadline passed, neither} × presence |
| Restart with a live matching orphan | `test_windows_restart_reconciliation.py::test_a_live_matching_orphan_is_terminated_and_recorded_as_lost_supervision` | real; launch through a job-less controller, commit `RUNNING`, keep the first process object alive, reconcile with a second controller → tree terminated, `PROTOCOL_FAILED`, `PROCESS.ORCHESTRATOR_RESTART_LOST_SUPERVISION`, run `FAILED`; a planted wrong-creation-time identity for the same pid, seeded with an earlier `created_at_utc` so the source order of §3.4 reconciles it first, is left alive and yields `LEFT_RUNNING_AWAITING_DEADLINE` with `PROCESS.PID_REUSE_DETECTED` in its `InvocationReconciliation.diagnostics` before the matching record's `TERMINALIZED_PROTOCOL_FAILED` kills the process |
| Restart with an absent process before the deadline | `...::test_an_absent_process_before_the_deadline_stays_running_and_reports_the_manifest` | real; a finished `fake.conformant` run committed `RUNNING` only; `LEFT_RUNNING_AWAITING_DEADLINE`, `manifest_present` true |
| Restart cleanup of a terminal with a live tree | `...::test_a_terminal_with_incomplete_cleanup_and_a_live_tree_is_cleaned` | real; `CANCELLED` committed without cleanup while the tree lives; reconciliation terminates and enriches `cleanup_complete` |
| Open handle blocks root removal | `test_windows_open_handles.py::test_root_removal_blocked_by_an_open_handle_records_cleanup_failed` | no child; the test holds `request.json` open while a pre-handoff terminal cleans up; `PROCESS.CLEANUP_FAILED`, `cleanup_complete` false; a second pass after closing succeeds and the record shows exactly one cleanup-failed id |
| Inherited pipe keeps EOF pending | `...::test_a_grandchild_inheriting_stdout_is_terminated_so_exit_can_complete` | real; `fake.grandchild-inherits-stdout`, `timeout_seconds=3`; with the job attached (no `PROCESS.JOB_OBJECT_UNAVAILABLE`): the forced `pipe_holder` termination runs after about one second, then `EXITED` with native exit `0`, `PROCESS.FORCED_TERMINATION` (`pipe_holder`) among the additional ids, the sleeper dead afterwards, elapsed time below the deadline; otherwise the `TIMED_OUT` arm of §9.1 with `cleanup_complete=true`, exactly one `FORCED_TERMINATION` entry, the `STDOUT_READER_STOPPED` cleanup entry carrying `ended_by == "CANCELLED"`, and the still-alive sleeper terminated in `finally:` by the pid parsed from `StderrCapture.sanitized_text` (`grandchild_pid=<n>`) |
| Stale child output after retry | `...::test_a_stale_writer_from_attempt_one_cannot_reach_attempt_two` | real; attempt 1 `fake.grandchild` ends `TIMED_OUT` (its primary is retriable); `harness.successor`; attempt 2 `fake.conformant` `EXITED` with its own manifest; the two roots differ; attempt 1's sleeper is dead before attempt 2 launches |
| Independent stderr budgets per kind | `test_windows_stderr_limits.py::test_each_kind_gets_its_own_stderr_budget_and_truncation_diagnostic` | scripted; three invocations each fed `max_stderr_bytes + 1` bytes; each capture `truncated` with `retained_byte_count == limit` and one `PROCESS.STDERR_TRUNCATED`; row 23 covers the real flood |
| Console interrupt group safety | `tests/unit/process_supervision/test_windows_api.py::test_the_console_event_wrapper_refuses_pid_zero` | API; pid `0` raises `ValueError` |

Duration budget for the new real-process modules: under 40 s in total; the
supervised matrix adds no launches when it replaces the stand-in run of the same
rows and about 30 s when both strategies run (the plan runs both: the Stage 6
suites stay on the stand-in, the Stage 7 matrix runs the production path).

## 11. Supervision safety requirements, each with its enforcement

| Requirement | Enforced by |
|---|---|
| Only an explicitly registered absolute executable runs | `LaunchSpecification.argv[0]` is `catalog_entry.executable_path` (an `AbsoluteLocalExecutablePath`); the supervisor verifies a regular file, no reparse point on it or any ancestor, and `executable_hash` before the swap; an absent executable is `FAILED_TO_START` with `ADAPTER.UNAVAILABLE` (run `UNAVAILABLE`), a present mismatch is `FAILED_TO_START` with `CORE.IMMUTABLE_INPUT_MISMATCH` (run `FAILED`); the fixed launch arguments come only from the entry's own runtime metadata (§4.2); the Stage 7 guard scans the one `Popen` call for a list first argument, `shell=False`, `env={}`, `stdin=subprocess.DEVNULL`, `close_fds=True`, `bufsize=0`, `creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED` (a `BinOp(BitOr)` of that attribute and the local name bound to `4`) and the `# noqa: S603 - reviewed fixed catalog executable boundary` text by AST with planted controls |
| Exact argument preservation, no shell interpretation | `argv = (executable, *catalog_launch_arguments(entry), *argument_array(command))`, never joined; `fake.argv-echo` echoes `sys.orig_argv[1:]` on stderr (the interpreter strips its own options from `sys.argv`) and the Windows tests compare element by element with spaces, quotes and Unicode inside the path segments |
| Fresh closed child environment | `LaunchSpecification` has no environment field; the controller passes `env={}`; the merged whole-tree environment scan (`os.environ`, `getenv`, the Pydantic control literal) stays green over every Stage 7 module; `fake.argv-echo` echoes its environment key list and the test asserts the planted parent sentinel and the parent-only keys are absent (the host injects two names of its own into every child, so the assertion is on absences, not on an empty list) |
| Explicit `cwd` and core-selected temporary roots | `plan_command_paths` is the single layout; the supervisor refuses a command whose paths differ; `cwd = command_root`; roots are created by the supervisor with `exist_ok=False` |
| Stdin policy | `stdin=subprocess.DEVNULL` always (the child inherits no console input handle), pinned by the AST scan and a controller test |
| Bounded stdout and stderr consumption | `PipeReader` with `QUEUE_CAPACITY_CHUNKS` and `READ_CHUNK_BYTES`; the merged framer emits an over-long tail early; `BoundedStderrCapture` owns the stderr budget; `fake.stdout-flood` proves no dropped line under a real flood, and the Task 3 `_SlowSink` unit test proves the reader blocks (its `put_retries` grows) when the queue is full |
| Incremental parsing across arbitrary chunk boundaries | The reader feeds the merged `frame_protocol_lines`/`parse_protocol_line`; the Stage 7 property test re-chunks recorded stdout streams and asserts the same accepted events, replay count and first rejection as the unsplit stream |
| Reader-thread termination | Readers are daemon threads owned by the supervisor, with a `stop` event and bounded `put`; join bound `READER_JOIN_SECONDS`, then `launched.cancel_read(native_thread_id)` on a survivor and a second bounded join; a pipe is closed only after its reader ended (closing under a blocked read would block the supervisor); a survivor is a `PROCESS.CLEANUP_FAILED` with `cleanup_complete=false`, never a hang |
| Paired UTC and monotonic deadlines | `PairedDeadline` from the `PENDING → STARTING` swap; the monotonic value governs, is never persisted or serialized; the reconciler uses `deadline_utc` only |
| Heartbeat arming and expiry | `HeartbeatMonitor` armed at the handoff, reset per accepted heartbeat, minted once, never terminates; rows 24 and 25 |
| Races among exit, timeout, cancellation, heartbeat loss and protocol rejection | The tick order of §6.3 and the race matrix of §6.4, each row a scripted-controller test; the CAS on the invocation and the coupled run swap decide against an external winner |
| Graceful then bounded forced termination | `interrupt()` → `cancellation_grace_seconds` → `terminate_tree(FORCED_TERMINATION_EXIT_CODE)`; immediate force for a protocol rejection; `fake.cancellation-graceful` and `fake.cancellation-ignores-interrupt` |
| Windows Job Objects and process-tree cleanup | Job with kill-on-close assigned while the launcher is still suspended (created with `CREATE_SUSPENDED`, resumed only after the assignment), so nothing can be created outside it; `terminate_tree` runs the job kill and the verified Toolhelp enumeration; `fake.grandchild` proves the grandchild is dead; the job-unavailable path is exercised through the scripted controller and the enumeration unit tests |
| Durable PID plus creation-time identity | `windows:<pid>:<creation>` from `GetProcessTimes` on the owning handle; `inspect` compares creation time and image; every `RUNNING` record carries it; PID reuse is `ALIVE_DIFFERENT_IDENTITY` |
| PID reuse, handle loss, stale children, orphans, restart | §8.5 table; a live pid with another identity is left untouched and reported; a matching live process after restart is terminated and `PROTOCOL_FAILED`; lost exit facts are never reconstructed |
| Exactly-once terminal enrichment | One `enrich` call after cleanup (§6.6); `assert_write_once_enrichment` refuses an overwrite; a lost swap reloads once and never writes twice |
| Interaction with the Stage 5 state machines | Every write goes through the merged operations behind `InvocationLifecycle`; the coupled targets of §5 are the only run edges the supervisor can cause; `LINKED_ONLY_INVOCATION_TARGETS` and `COUPLED_TERMINAL_TARGETS` are consumed, not redefined |
| Interaction with Stage 6 `CommandResult` and semantic application | `CommandResult` is built exactly as Stage 6 defines it; `semantic_outcome_request_for` is pure; `apply_command_semantic_outcome` is called by the integration driver as the harness does; no Stage 7 code writes a run state outside the coupled core-won mappings |
| Every relevant Stage 6 vector through the production supervisor | The 52 rows via the harness seam (§9); the five adapter-side vectors stay on the stand-in path by declared scope |
| Paths with spaces, Unicode, conditional long paths | `PathPreflight`, the long-path probe and the Windows tests of §10 |
| Deterministic tests with no real engine | The scripted controller drives every race; fake adapters are stdlib scripts; clocks are injected; timeouts are the Stage 6 constants |
| No false `EXITED` | `EXITED` only from a reaped exit after both EOFs and the flush; the reconciler never produces it; a `CommandResult` requires the terminal record the swap returned |
| No false semantic success | The supervisor calls no run transition; the reconcilers and `apply_command_semantic_outcome` are Stage 6's and never move a run to a success state |
| No artifact finalization, persistence or network | No `artifacts` write, no `RunManifest`, no `CandidateArtifact` record; the ports are in-memory doubles in tests; the merged infrastructure scan (`sqlalchemy`, `sqlite3`, `alembic`, `random`, `secrets`, `time`) stays green with the single `subprocess` exemption; no `socket`, `http` or `urllib` root joins the allowlist |
| Raw attempt tokens never enter durable records, traces or diagnostics | The token exists in the supervisor only as the envelope's field and the parsers' argument; `SupervisionTraceEntry.facts` carries identifiers, counts, codes, state names and the controller-observed image path only, and every retained entry canonicalises (its monotonic field is an integer, because canonical JSON forbids floats); on every validate and run row of the supervised matrix `assert_stage_six_expectation` calls `assert_token_absent((*outcome.trace, outcome.protocol_summary, outcome.executable_observation), token)` over the retained `supervision_outcome` (a `ManifestParse` `output_parse` stays excluded, as the merged manifest keeps the token on the wire by design), and a Task 6 scripted test feeds token-bearing heartbeat and contaminated lines and asserts no retained trace entry's canonical JSON contains the token |
| Operating-system sandbox claims are absent | The plan, the module docstrings and the documentation call the Job Object a cleanup mechanism; the Stage 7 guard asserts the word "sandbox" appears in `process_supervision` only inside the negative sentence of the package docstring |

## 12. Task decomposition

Nine vertical tasks. No task depends on a file created by a later task. Each is
test-first: focused RED, minimum implementation, focused GREEN, then broader
verification; each ends in one commit and a clean worktree. Focused runs use the
launcher `pytest-focused` profile with `-o addopts=` (diagnostic only, no coverage
number). **Every task that creates a module under `src/crypto_lab`, first defines a
deferred name or first imports a new root also edits
`tests/safety/test_stage3_boundaries.py` and `tests/unit/test_package_layout.py`
exactly as §2.6 tabulates; those two files are owned by Tasks 1–7 and are not
repeated in each list, and each such task's focused RED includes the §2.6 guard
expectations for its own paths, names and roots.** Every task's **Quality gates**
are the launcher `ruff-format-all` (apply the printed diff by hand),
`ruff-check-all`, `mypy-all` (strict, over `src`, `tests` and `scripts`) and
`schema-generate-check`; every task's **Schema and migration preservation** is
`schema-generate-check` clean on the unchanged 35-entry registry, `git diff --stat
-- schemas/` empty, and no path created under `src/crypto_lab/persistence/` or an
Alembic tree; every task's **Independent review** is a fresh reviewer over the
task's diff with the task's declared readings listed; every task's
**Clean-worktree checkpoint** is `git status --short` empty after the commit with
every guard edit inside it. Every step below is a checkbox for the executor.

### Task 1 — Monotonic clock, cancellation token, deadlines

**Files created.** `src/crypto_lab/process_supervision/cancellation.py`,
`src/crypto_lab/process_supervision/deadlines.py`,
`tests/unit/process_supervision/test_cancellation_tokens.py`,
`tests/unit/process_supervision/test_deadlines.py`,
`tests/property/test_supervision_deadlines.py`.
**Files modified.** `src/crypto_lab/domain/time.py` (`MonotonicInstant`),
`src/crypto_lab/domain/ports.py` (`Clock.monotonic`, `CancellationToken`),
`src/crypto_lab/domain/__init__.py` (two sorted exports),
`tests/unit/domain/test_domain_ports.py`, `tests/unit/domain/test_time.py`
(`MonotonicInstant` cases), `tests/doubles/experiments.py` (`FixedClock`,
`CountingClock`, `FailingClock` gain `monotonic`; `FixedClock.advance` widens its
parameter to `seconds: float` and refuses a negative value with `ValueError`),
`tests/unit/experiments/test_port_contracts.py` (the two monotonic asserts), and
the two §2.6 guard files (paths 83 → 85; `threading` 22 → 23; deferred 37 → 35).
**Interfaces consumed.** `Clock`, `FixedClock`, `require_utc`, `dataclass`,
`threading.Event`.
**Interfaces produced.** `MonotonicInstant(seconds).plus/until`;
`Clock.monotonic()`; `CancellationToken`; `ThreadSafeCancellationToken`;
`PairedDeadline(deadline_utc, deadline_monotonic, timeout_seconds).remaining/passed`;
`HeartbeatMonitor(missing_heartbeat_seconds).arm/reset/due/remaining/minted`.

- [ ] **Step 1: Focused RED.** Write the tests first:

```python
def test_monotonic_instant_rejects_negative_nan_and_infinite_values() -> None:
    for bad in (-0.001, float("nan"), float("inf")):
        with pytest.raises(ValueError, match="monotonic instant"):
            MonotonicInstant(bad)
    assert MonotonicInstant(1.5).plus(2.0) == MonotonicInstant(3.5)
    assert MonotonicInstant(1.5).until(MonotonicInstant(4.0)) == 2.5


def test_the_clock_port_has_exactly_now_utc_and_monotonic() -> None:
    assert _public_methods(Clock) == {"now_utc", "monotonic"}
    assert get_type_hints(Clock.monotonic)["return"] is MonotonicInstant


def test_fixed_clock_advances_both_instants_together() -> None:
    clock = FixedClock(_INSTANT)
    assert clock.monotonic() == MonotonicInstant(0.0)
    clock.advance(30)
    assert clock.monotonic() == MonotonicInstant(30.0)
    assert isinstance(clock, Clock)
    with pytest.raises(ValueError, match="negative"):
        clock.advance(-1)


def test_a_paired_deadline_reports_remaining_and_passed() -> None:
    deadline = PairedDeadline(
        _INSTANT + timedelta(seconds=4), MonotonicInstant(14.0), 4
    )
    assert deadline.remaining(MonotonicInstant(11.5)) == 2.5
    assert not deadline.passed(MonotonicInstant(13.999))
    assert deadline.passed(MonotonicInstant(14.0))


def test_the_heartbeat_monitor_is_due_once_the_threshold_elapses_and_resets() -> None:
    monitor = HeartbeatMonitor(missing_heartbeat_seconds=2)
    monitor.arm(MonotonicInstant(10.0))
    assert not monitor.due(MonotonicInstant(11.9))
    monitor.reset(MonotonicInstant(11.9))
    assert not monitor.due(MonotonicInstant(13.8))
    assert monitor.due(MonotonicInstant(13.9))


def test_the_token_is_idempotent_and_thread_safe() -> None:
    token = ThreadSafeCancellationToken()
    assert not token.is_cancellation_requested()
    token.request_cancellation()
    token.request_cancellation()
    assert token.is_cancellation_requested()
    assert isinstance(token, CancellationToken)
```

  plus the `CancellationToken` protocol tests of §2.6, the `hypothesis` property
  that `remaining` is non-negative and `passed` is monotone over arbitrary
  bounded floats, and the §2.6 guard expectations (allowlist naming the two
  missing paths; deferred count failing until exactly the two names are removed;
  root allowlist naming `threading`).
- [ ] **Step 2: Run the focused set and confirm every new test fails for the
  expected reason** (`ImportError` for the new modules and names; `{"now_utc"}`
  for the port; `AttributeError` on `FixedClock.monotonic`).
- [ ] **Step 3: Minimum GREEN.** The dataclass, the two protocol members, the
  doubles, the two modules.
- [ ] **Step 4: Focused GREEN.** `tests\unit\domain tests\unit\process_supervision
  tests\unit\experiments\test_port_contracts.py tests\property tests\safety
  tests\unit\test_package_layout.py -q`.
- [ ] **Step 5: Quality gates, Schema and migration preservation, Security and
  boundary review, Independent review, Commit, Clean-worktree checkpoint.**

**Broader tests.** `tests\unit tests\contract tests\safety tests\architecture`
(the contract suite proves every catalog and acceptance-context `isinstance`
still passes with the widened `Clock`).
**Windows-specific tests.** None (pure values); the Windows platform tests begin
in Task 4.
**Quality gates.** `ruff-format-all` (apply the printed diff by hand), `ruff-check-all`, strict `mypy-all` over `src`, `tests` and `scripts`, `schema-generate-check`.
**Schema and migration preservation.** As stated above; `MonotonicInstant` is not
a model field.
**Security and boundary review.** `domain` imports nothing new; no clock is read
(`FixedClock.monotonic` is arithmetic); `threading` appears only in
`cancellation.py`; no `time` import anywhere in `src`.
**Independent review.** Declared readings: the monotonic reading precedes the UTC
reading; `advance` moves both instants; `FailingClock.monotonic` raises.
**Commit message.** `feat: add monotonic clock, cancellation token and paired deadlines`
**Clean-worktree checkpoint.** As stated above.

### Task 2 — Supervision ports, records and the Stage 7 diagnostic table

**Files created.** `src/crypto_lab/process_supervision/ports.py`,
`src/crypto_lab/process_supervision/models.py`,
`src/crypto_lab/process_supervision/diagnostics.py`,
`tests/unit/process_supervision/test_supervision_ports.py`,
`tests/unit/process_supervision/test_supervision_models.py`,
`tests/unit/process_supervision/test_supervision_diagnostics.py`.
**Files modified.** `tests/architecture/test_package_import_boundaries.py` (the
`process_supervision` scope-closure test of §2.6), `tests/safety/test_stage3_boundaries.py`
(`ProcessSupervisor` released, 35 → 34; the seven-name swap to `ArtifactFinalizer`),
`tests/unit/test_package_layout.py` (paths 85 → 88).
**Interfaces consumed.** Task 1 output; `CanonicalModel`, `CommandResult`,
`AdapterCommand`, `AdapterCatalogEntry`, `ProcessIdentity`, `ProcessStartFacts`,
`CommandInvocationRecord`, `RunEvent`, `EventRejected`, `ProtocolEventSummary`,
`DescriptorParse`, `ValidationResultParse`, `ManifestParse`, `Diagnostic`,
`stage6_diagnostic`, `_inspect_details`, `profile_hash`, `_uuid4_shaped`.
**Interfaces produced.** The six ports of §3.4 (`InvocationLifecycle` with nine
members, `LaunchedProcess` with `cancel_read` and the flagged `close`,
`ProcessController.launch` returning `LaunchedProcess | LaunchFailure`); every
record and enum of §3.3 (`LaunchFailure` included);
`catalog_launch_arguments`, `LAUNCH_ARGUMENTS_KEY`, `MAX_LAUNCH_ARGUMENTS`,
`parse_creation_identity`, `render_creation_identity`, `CreationIdentity`,
`FORCED_TERMINATION_EXIT_CODE`, `TICK_SECONDS`, `READ_CHUNK_BYTES`,
`QUEUE_CAPACITY_CHUNKS`, `POST_TERMINATION_WAIT_SECONDS`, `READER_JOIN_SECONDS`,
`PIPE_HOLDER_GRACE_SECONDS`, `CTRL_BREAK_EVENT`, `CREATE_SUSPENDED` (`0x00000004`,
absent from the stdlib `subprocess` module), `DESCRIBE_STDERR_PLACEHOLDER`, the ceiling
constants;
`STAGE7_DIAGNOSTIC_CODES` (13 rows),
`stage7_diagnostic`, `stage7_failure`, the thirteen code constants. Releases
`ProcessSupervisor`.

- [ ] **Step 1: Focused RED.**

```python
def _public_members(port: type) -> set[str]:
    # the merged tests/unit/domain/test_domain_ports.py helper skips properties (not callable); this one keeps them
    return {
        name
        for name, value in vars(port).items()
        if not name.startswith("_") and (callable(value) or isinstance(value, property))
    }


def test_the_six_ports_are_runtime_checkable_protocols_with_exact_members() -> None:
    assert _public_members(ProcessSupervisor) == {"invoke"}
    assert _public_members(InvocationLifecycle) == {
        "load",
        "linked_run",
        "begin_start",
        "request_envelope",
        "record_process_start",
        "record_terminal",
        "enrich",
        "append_event",
        "resolve_external_winner",
    }
    assert _public_members(ProcessController) == {"launch", "inspect", "terminate_tree"}
    assert _public_members(LaunchedProcess) == {
        "pid",
        "creation_identity",
        "stdout",
        "stderr",
        "wait",
        "interrupt",
        "terminate_tree",
        "cancel_read",
        "close",
        "job_available",
        "job_error_code",
        "image_path",
    }
    assert _public_members(SupervisionObserver) == {"observe"}
    assert _public_members(ReconciliationSource) == {
        "list_reconciliation_targets",
        "run_facts",
    }
    assert set(inspect.signature(LaunchedProcess.close).parameters) == {
        "self",
        "close_stdout",
        "close_stderr",
    }
    assert inspect.iscoroutinefunction(ProcessSupervisor.invoke)


def test_catalog_launch_arguments_reads_the_metadata_key_and_refuses_other_shapes() -> (
    None
):
    assert catalog_launch_arguments(entry_with({})) == ()
    assert catalog_launch_arguments(
        entry_with({"launch_arguments": ["-I", "-B", "C:\\x\\f.py"]})
    ) == ("-I", "-B", "C:\\x\\f.py")
    for bad in ("text", [""], ["a\x00"], ["x"] * 17):
        with pytest.raises(ValueError, match="launch_arguments"):
            catalog_launch_arguments(entry_with({"launch_arguments": bad}))


def test_creation_identity_round_trips_and_refuses_the_merged_fixture_shapes() -> None:
    text = render_creation_identity(4242, 133_700_000_000_000_000)
    assert text == "windows:4242:133700000000000000"
    assert parse_creation_identity(text) == CreationIdentity(
        4242, 133_700_000_000_000_000
    )
    for bad in (
        "offline-harness:4242",
        "2026-09-07T12:00:03.1234567Z#0001",
        "windows:0:1",
        "windows:1:01",
    ):
        with pytest.raises(ValueError, match="creation identity"):
            parse_creation_identity(bad)


def test_supervision_outcome_requires_parse_kind_agreement_and_a_terminal_record() -> (
    None
):
    with pytest.raises(ValidationError, match="command_kind"):
        outcome_with(
            command_result=exited_run_result(), output_parse=descriptor_parse()
        )


def test_every_retained_record_canonicalises() -> None:
    entry = trace_entry_with(kind=SupervisionTraceKind.LAUNCHED, monotonic_100ns=12_345)
    assert canonical_json_bytes(entry) and canonical_json_bytes(
        outcome_with(trace=(entry,))
    )  # no float anywhere (§11 relies on it)
    with pytest.raises(ValidationError, match="repeat"):
        outcome_with(
            trace=(
                trace_entry_with(
                    kind=SupervisionTraceKind.STDOUT_BYTES_COUNTED, sequence=1
                ),
                trace_entry_with(
                    kind=SupervisionTraceKind.STDOUT_BYTES_COUNTED, sequence=2
                ),
            )
        )  # only CLEANUP_ACTION/CLEANUP_FAILED may repeat


def test_the_stage_seven_table_is_exactly_thirteen_rows_disjoint_from_stage_six() -> (
    None
):
    assert len(STAGE7_DIAGNOSTIC_CODES) == 13
    assert set(STAGE7_DIAGNOSTIC_CODES) & set(STAGE6_DIAGNOSTIC_CODES) == set()
    assert set(STAGE7_DIAGNOSTIC_CODES) & set(STAGE5_DIAGNOSTIC_CODES) == {
        INVARIANT_VIOLATION,
        IMMUTABLE_INPUT_MISMATCH,
        CONCURRENCY_CONFLICT,
    }


def test_a_stage_seven_core_literal_equals_the_stage_five_diagnostic() -> None:
    def mint(
        factory: Callable[..., Diagnostic],
    ) -> Diagnostic:  # explicit keywords: strict mypy rejects **dict[str, object]
        return factory(
            INVARIANT_VIOLATION,
            "m",
            source_component=SC,
            timestamp_utc=_INSTANT,
            experiment_id=EXP,
            run_id=RUN,
            invocation_id=INV,
            details={"k": 1},
        )

    assert mint(stage7_diagnostic) == mint(stage5_diagnostic)


def test_identity_is_content_only_and_every_process_code_requires_an_invocation() -> (
    None
):
    first = stage7_diagnostic(
        PROCESS_CLEANUP_FAILED,
        "m",
        invocation_id=INV,
        timestamp_utc=_INSTANT,
        source_component=SC,
    )
    later = stage7_diagnostic(
        PROCESS_CLEANUP_FAILED,
        "m",
        invocation_id=INV,
        timestamp_utc=_INSTANT + timedelta(1),
        source_component=SC,
    )
    assert first.diagnostic_id == later.diagnostic_id
    for code in (
        c
        for c in STAGE7_DIAGNOSTIC_CODES
        if c.startswith("PROCESS.") and c != PROCESS_PATH_PREFLIGHT_REJECTED
    ):
        with pytest.raises(ValueError, match="invocation_id"):
            stage7_diagnostic(code, "m", timestamp_utc=_INSTANT, source_component=SC)
    preflight = stage7_diagnostic(
        PROCESS_PATH_PREFLIGHT_REJECTED,
        "m",
        timestamp_utc=_INSTANT,
        source_component=SC,
    )
    assert not isinstance(
        preflight.invocation_id, str
    )  # MISSING; the one Failure-only code minted before an invocation exists (no `is MISSING` on a typed field, §2.6)
```

  plus: every record's unknown-field rejection and its co-occurrence rules;
  `TerminationReport` `exit_code_used` present iff `forced`; `CleanupReport.complete`;
  the trace-entry `rejection` present only on `EVENT_REJECTED`; the postures
  asserted row by row against §3.5 and the hard-block partition of
  `domain/retry.py`; the module reads no clock (the mirrored substring scan); the
  architecture closure test with its planted-import controls; the §2.6 guard
  expectations. **Test helpers**: `entry_with(metadata)` (an `AdapterCatalogEntry`
  cloned from `catalog_entry_for("fake.conformant")` with
  `runtime_metadata=metadata`); `exited_run_result()` (a `CommandResult` over
  `sample_invocation(state=EXITED, kind=RUN)`); `descriptor_parse()` (a
  `DescriptorParse` from `parse_bootstrap_descriptor` over a valid bootstrap
  document); `EXP`, `RUN`, `INV` = the doubles' `EXPERIMENT_ID`, `RUN_ID`,
  `INVOCATION_ID`; `SC = "process_supervision.supervisor"`; `_INSTANT = INSTANT`;
  `outcome_with(**overrides)` (a valid `SupervisionOutcome` over an `EXITED` RUN
  record with every required field, the given fields replaced) and
  `trace_entry_with(**overrides)` (likewise for `SupervisionTraceEntry`);
  `canonical_json_bytes` is the merged `domain.canonical_json` function.
- [ ] **Step 2: Confirm RED** (`ModuleNotFoundError`; deferred count at 35; the
  seven-name list failing on `ProcessSupervisor`).
- [ ] **Step 3: Minimum GREEN.** The three modules and their own `__all__` lists
  (the package `__init__.py` stays a docstring until Task 7).
- [ ] **Step 4: Focused GREEN.** `tests\unit\process_supervision tests\architecture
  tests\safety tests\unit\test_package_layout.py -q`.
- [ ] **Step 5: Quality gates, Schema and migration preservation, Security and
  boundary review, Independent review, Commit, Clean-worktree checkpoint.**

**Broader tests.** `tests\unit tests\safety tests\architecture`.
**Windows-specific tests.** None (pure models); `render_creation_identity` is
exercised with a real process in Task 4.
**Quality gates.** `ruff-format-all` (apply the printed diff by hand), `ruff-check-all`, strict `mypy-all` over `src`, `tests` and `scripts`, `schema-generate-check`.
**Schema and migration preservation.** As stated above; no Stage 7 record has an
`$id`.
**Security and boundary review.** No field annotated `AttemptToken`; no record
holds adapter bytes; `LaunchSpecification` has no environment field; the trace
entry's `facts` pass `_inspect_details`; `process_supervision` imports only
`domain`, `adapters` and itself (the new architecture test).
**Independent review.** Declared readings: §2.5 items 1, 2 and 6; the thirteen
postures; `ENGINE_RUNTIME` for the two reconciler primaries.
**Commit message.** `feat: add process supervision ports, records and diagnostics`
**Clean-worktree checkpoint.** As stated above.

### Task 3 — Command roots, path preflight and bounded pipe readers

**Files created.** `src/crypto_lab/process_supervision/roots.py`,
`src/crypto_lab/process_supervision/readers.py`,
`tests/unit/process_supervision/test_supervision_roots.py`,
`tests/unit/process_supervision/test_stream_readers.py`,
`tests/property/test_supervision_frames.py`.
**Files modified.** The two §2.6 guard files (paths 88 → 90; `queue` 23 → 24).
**Interfaces consumed.** `AbsoluteLocalExecutablePath`,
`validate_absolute_local_executable_path`, `RESULT_MANIFEST_RELATIVE_PATH`,
`frame_protocol_lines`, `sha256_bytes`, `request_envelope_bytes`, Task 2 records.
**Interfaces produced.** `plan_command_paths`, `CommandPaths`, `PathPreflight`,
`probe_long_path_support(supervision_root, *, now: datetime) -> Result[PathPreflight]`
(a `Failure` carries `PROCESS.PATH_PREFLIGHT_REJECTED` with `root_missing`,
`root_not_directory`, `root_not_local` or `ancestor_reparse_point`),
`preflight_command_paths`, `create_command_root`,
`write_request_file`, `remove_command_root`, `read_output_file(path, *, ceiling) ->
bytes | OutputReadFailure | MISSING` (with the `OutputReadFailure` record of §7.4),
`snapshot_written_paths`, `observe_executable`; `PipeReader` (with `queue`,
`native_thread_id`, `put_retries` counting every `queue.Full` timeout, `ended_by:
ReaderEnd | None` and the `EOF`/`CANCELLED` markers), `ReaderEnd` (`StrEnum`:
`EOF`, `CANCELLED`), `StdoutFramer`, `drain`, `wait_for_chunk(queue,
timeout_seconds) -> bytes | ReaderEnd | None` (returns the dequeued item, or
`None` when nothing arrived).

- [ ] **Step 1: Focused RED.**

```python
def test_the_layout_is_the_harness_layout(tmp_path: Path) -> None:
    paths = plan_command_paths(
        str(tmp_path), command_kind=CommandKind.RUN, invocation_id=INV, run_id=RUN
    )
    assert paths.command_root == str(tmp_path / INV)
    assert paths.work_dir == str(tmp_path / INV / "runs" / RUN / "work")
    assert paths.result_path == str(
        tmp_path / INV / "runs" / RUN / "work" / "adapter-result-manifest.json"
    )
    with pytest.raises(ValueError, match="run_id"):
        plan_command_paths(
            str(tmp_path),
            command_kind=CommandKind.VALIDATE,
            invocation_id=INV,
            run_id=MISSING,
        )


def test_preflight_uses_the_directory_and_file_ceilings(tmp_path: Path) -> None:
    unsupported = PathPreflight(
        supervision_root=str(tmp_path),
        long_paths_supported=False,
        directory_ceiling=247,
        file_ceiling=259,
        probed_at_utc=_INSTANT,
    )
    supported = PathPreflight(
        supervision_root=str(tmp_path),
        long_paths_supported=True,
        directory_ceiling=1024,
        file_ceiling=1024,
        probed_at_utc=_INSTANT,
    )
    with pytest.raises(ValidationError):
        PathPreflight(
            supervision_root=str(tmp_path),
            long_paths_supported=True,
            directory_ceiling=32767,
            file_ceiling=32767,
            probed_at_utc=_INSTANT,
        )
    assert (
        preflight_command_paths(
            run_paths(str(tmp_path)),
            supported,
            now=_INSTANT,
            invocation_id=INV,
            run_id=RUN,
            experiment_id=EXP,
        ).outcome
        == "SUCCESS"
    )
    long_root = str(tmp_path / ("a" * (248 - len(str(tmp_path)) - 1)))
    failure = preflight_command_paths(
        run_paths(long_root),
        unsupported,
        now=_INSTANT,
        invocation_id=INV,
        run_id=RUN,
        experiment_id=EXP,
    )
    assert isinstance(failure, Failure) and codes_of(failure) == (
        PROCESS_PATH_PREFLIGHT_REJECTED,
    )  # the isinstance narrows Result[None] for mypy
    assert failure.diagnostics[0].details["reason"] == "ceiling_exceeded"
    assert (failure.diagnostics[0].invocation_id, failure.diagnostics[0].run_id) == (
        INV,
        RUN,
    )  # the §4.4 rejection is correlated


def test_an_ancestor_junction_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "target" / "sup").mkdir(
        parents=True
    )  # CreateJunction needs an existing directory
    _winapi.CreateJunction(str(tmp_path / "target"), str(tmp_path / "link"))
    try:
        failure = probe_or_preflight(
            str(tmp_path / "link" / "sup")
        )  # exists through the junction, so the reason is the reparse point
        assert isinstance(failure, Failure) and codes_of(failure) == (
            PROCESS_PATH_PREFLIGHT_REJECTED,
        )
        assert failure.diagnostics[0].details["reason"] == "ancestor_reparse_point"
    finally:
        os.rmdir(tmp_path / "link")


def test_read_output_file_reads_at_most_ceiling_plus_one_bytes(tmp_path: Path) -> None:
    (tmp_path / "output.json").write_bytes(b"x" * 100)
    data = read_output_file(str(tmp_path / "output.json"), ceiling=10)
    assert isinstance(data, bytes) and len(data) == 11  # narrows bytes | MISSING


def test_remove_command_root_reports_a_sharing_violation_and_is_idempotent(
    tmp_path: Path,
) -> None:
    root = tmp_path / "inv"
    root.mkdir()
    (root / "request.json").write_bytes(b"{}")
    with (root / "request.json").open("rb"):
        report = remove_command_root(str(root))
    assert report.failures[0].action is CleanupAction.COMMAND_ROOT_REMOVED
    assert (
        remove_command_root(str(root)).complete
        and remove_command_root(str(root)).complete
    )


def test_the_reader_applies_backpressure_and_ends_with_a_sentinel() -> None:
    source = _SlowSink(chunks=[b"a" * 70_000] * 70)  # a fake IO[bytes]
    reader = PipeReader(source, capacity=QUEUE_CAPACITY_CHUNKS, stop=threading.Event())
    source.attach(reader)  # the sink watches this reader's put_retries
    reader.start()
    assert source.blocked_at_least_once_after(QUEUE_CAPACITY_CHUNKS)
    chunks, ended = drain_all(reader.queue)
    assert b"".join(chunks) == b"a" * 70_000 * 70 and ended


def test_a_chunk_delivered_during_the_timed_wait_is_returned_not_lost() -> None:
    source = _SlowSink(
        chunks=[b'{"a":1}\n'], delay_first_read_until=lambda: waiting.is_set()
    )
    reader = PipeReader(source, capacity=QUEUE_CAPACITY_CHUNKS, stop=threading.Event())
    reader.start()
    waiting.set()
    item = wait_for_chunk(
        reader.queue, 1.0
    )  # the chunk arrives while the wait is blocked
    assert item == b'{"a":1}\n'  # returned to the caller, never dropped
    assert (
        wait_for_chunk(reader.queue, 0.05) is ReaderEnd.EOF
        and wait_for_chunk(reader.queue, 0.05) is None
    )
```

  plus the property test: any chunking of a recorded multi-line stdout stream
  through `StdoutFramer` yields the same framed units as the unsplit stream and
  an over-long tail is emitted early; the write-boundary snapshot; the
  executable observation (absent, directory, junction — `ancestor_reparse_point=True`,
  `observed_hash` absent (`not isinstance(observation.observed_hash, str)`),
  `verified is False` — hash mismatch, verified); a junction planted under a command
  root appears in `snapshot_written_paths` as one entry and its target is never
  walked; `read_output_file` over an `output.json` held open with no sharing
  returns an `OutputReadFailure`;
  `probe_long_path_support` injected both ways; the §2.6 guard expectations.
  **Test helpers** (module-local, one clause each): `codes_of(result) ->
  tuple[str, ...]` (the error codes of a `Failure`, in order); `ok(result)` (asserts
  `Success` and returns its value); `run_paths(root: str)` =
  `plan_command_paths(root, command_kind=CommandKind.RUN, invocation_id=INV,
  run_id=RUN)`; `probe_or_preflight(path: str)` (probe `path` with `now=_INSTANT`;
  on `Failure` return it; on `Success` return `preflight_command_paths(run_paths(path),
  preflight, now=_INSTANT, invocation_id=INV, run_id=RUN, experiment_id=EXP)`);
  `INV`, `RUN`, `EXP` = the doubles' `INVOCATION_ID`, `RUN_ID`, `EXPERIMENT_ID`;
  `_INSTANT = INSTANT`; `_SlowSink(chunks, delay_first_read_until=None)` (a fake
  `IO[bytes]` whose `read` hands one chunk per call, optionally after a predicate
  becomes true; `attach(reader)` gives it the `PipeReader` whose `put_retries` its
  `blocked_at_least_once_after(n)` waits on once `n` chunks were handed out); `waiting` a `threading.Event` of the
  test module; `drain_all(queue)` (`drain` repeated until the reader ended).
- [ ] **Step 2: Confirm RED.**
- [ ] **Step 3: Minimum GREEN.** The two modules.
- [ ] **Step 4: Focused GREEN.** `tests\unit\process_supervision tests\property
  tests\safety tests\unit\test_package_layout.py -q`.
- [ ] **Step 5: Quality gates, Schema and migration preservation, Security and
  boundary review, Independent review, Commit, Clean-worktree checkpoint.**

**Broader tests.** `tests\unit tests\safety tests\architecture tests\property`.
**Windows-specific tests.** The junction, sharing-violation and ceiling tests above
run on the real filesystem under `tmp_path` (they are Windows semantics; no child
process yet).
**Quality gates.** `ruff-format-all` (apply the printed diff by hand), `ruff-check-all`, strict `mypy-all` over `src`, `tests` and `scripts`, `schema-generate-check`.
**Schema and migration preservation.** As stated above.
**Security and boundary review.** `roots.py` never calls `Path.cwd`, `Path.home`
or `expanduser`; it opens files only under a caller-supplied root; `remove_command_root`
never descends through a reparse point; no `os`, `shutil`, `tempfile`, `stat` or
`io` import; `readers.py` holds at most `QUEUE_CAPACITY_CHUNKS × READ_CHUNK_BYTES`
bytes per pipe.
**Independent review.** Declared readings: §2.5 items 11, 12 and 20; the 247/259
ceilings; the exclusive-create request write.
**Commit message.** `feat: add command roots, path preflight and bounded pipe readers`
**Clean-worktree checkpoint.** As stated above.

### Task 4 — Windows process controller: launch, identity, Job Objects, interrupts, tree termination

**Files created.** `src/crypto_lab/process_supervision/windows_api.py`,
`src/crypto_lab/process_supervision/windows_process.py`,
`tests/unit/process_supervision/test_windows_api.py`,
`tests/unit/process_supervision/test_windows_process.py`.
**Files modified.** `tests/safety/test_stage5_boundaries.py` (the `subprocess`
exemption and its test, §2.6), the two §2.6 guard files (paths 90 → 92; `ctypes`
and `subprocess` 24 → 26).
**Interfaces consumed.** Task 2 and Task 3 output; `subprocess.Popen`,
`subprocess.CREATE_NEW_PROCESS_GROUP`, the Task 2 constant `CREATE_SUSPENDED`,
`subprocess.DEVNULL`, `subprocess.PIPE`;
`ctypes.WinDLL`, `ctypes.wintypes`.
**Interfaces produced.** `windows_api`: `open_process_limited`, `process_times`,
`process_image_path`, `process_exit_code`, `create_kill_on_close_job`,
`assign_to_job`, `is_process_in_job(process_handle: int, job_handle: int | None) -> bool`
(`False` for `None`, so a `job_handle: int | None` needs no narrowing),
`resume_initial_thread(pid)` (Toolhelp thread snapshot, `OpenThread`,
`ResumeThread`, §8.2), `terminate_job`, `terminate_process`,
`generate_console_break`, `descendants_of` (Toolhelp, verified by parent pid and
creation time), `cancel_synchronous_io(native_thread_id)`, `wait_for_handle(handle,
timeout_seconds) -> bool` (`WaitForSingleObject`; the only liveness test, §8.1;
`WAIT_FAILED` surfaces as the distinct cleanup reason `wait_failed:<winerror>`),
`close_handle`; `open_process_limited` always includes `SYNCHRONIZE`;
`windows_process`:
`WindowsProcessController(job_object_factory=...)`, `WindowsLaunchedProcess` (a
plain class exposing the port members — `job_available`, `job_error_code` and
`image_path` among them, the launch facts the supervisor reads right after
`launch` — plus `job_handle: int | None` and `process_handle: int`; `cancel_read(native_thread_id)` delegates to
`windows_api.cancel_synchronous_io`; `close(*, close_stdout, close_stderr)` per
§8.4; liveness everywhere by `wait_for_handle(handle, 0.0)`; `launch` returns the
`WindowsLaunchedProcess` or a `LaunchFailure`, never a `Diagnostic` — the
controller has no clock and no run correlation); `windows_api.console_process_count()`
(`GetConsoleProcessList`, for the interrupt tests' precondition).

- [ ] **Step 1: Focused RED.** Tests launch `sys.executable -I -B -c <code>`
  children through the controller (no `subprocess` import in the test). The
  `-c` programs are module-level string constants of the test module, stdlib
  only, every sleep in `time.sleep(0.1)` slices: `HANDLER_EXITS_50_THEN_SLEEPS`
  (installs a `SIGBREAK` handler that exits `50`, then loops sleeping),
  `SPAWNS_A_SLEEPER_AND_PRINTS_ITS_PID` (spawns a second interpreter that sleeps,
  prints that pid on stdout, then sleeps itself) and
  `SPAWNS_A_SLEEPER_INHERITING_STDOUT_AND_EXITS` (spawns the sleeper with
  `stdout=sys.stdout.fileno()`, `stdin=DEVNULL`, `stderr=DEVNULL` and the default
  `close_fds=True`, so only the stdout pipe is inherited; prints the sleeper's pid
  on stderr, exits `0` at once). The `controller` fixture attaches a Job Object;
  `controller_without_job` uses a failing `job_object_factory`; both terminate
  every pid a test printed in `finally:`.

```python
def test_a_launched_process_has_a_parsable_creation_identity_and_is_in_our_job(
    controller, tmp_root: Path
) -> None:
    launched = started(
        controller.launch(
            spec_for(
                [sys.executable, "-I", "-B", "-c", "import time; time.sleep(30)"],
                cwd=tmp_root,
            )
        )
    )
    try:
        identity = parse_creation_identity(launched.creation_identity)
        assert identity.pid == launched.pid
        assert is_process_in_job(launched.process_handle, launched.job_handle)
        assert (
            controller.inspect(process_identity_for(launched)).presence
            is ProcessPresence.ALIVE_MATCHING
        )
    finally:
        launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
        launched.close(close_stdout=True, close_stderr=True)


def test_forced_termination_reports_the_constant_as_the_native_exit(
    controller, tmp_root: Path
) -> None:
    launched = started(controller.launch(sleep_spec(tmp_root)))
    report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    assert report.forced and report.exit_code_used == 1067 and report.failures == ()
    assert launched.wait(5.0) == 1067
    assert launched.close(close_stdout=True, close_stderr=True).complete


def test_terminating_an_already_exited_root_reports_no_failure(
    controller, tmp_root: Path
) -> None:
    launched = started(
        controller.launch(
            spec_for([sys.executable, "-I", "-B", "-c", "pass"], cwd=tmp_root)
        )
    )
    assert launched.wait(5.0) == 0
    assert (
        launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE).failures == ()
    )  # access denied on a dead process is not a failure


def test_launch_returns_a_launched_process_or_a_launch_failure_and_never_raises(
    controller, tmp_root: Path
) -> None:
    result = controller.launch(sleep_spec(tmp_root))
    assert isinstance(result, LaunchedProcess) and not isinstance(result, LaunchFailure)
    result.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    result.close(close_stdout=True, close_stderr=True)


def test_cancel_read_unblocks_a_reader_whose_pipe_a_grandchild_still_holds(
    controller_without_job, tmp_root: Path
) -> None:
    launched = started(
        controller_without_job.launch(
            program_spec(SPAWNS_A_SLEEPER_INHERITING_STDOUT_AND_EXITS, cwd=tmp_root)
        )
    )
    sleeper = int(
        launched.stderr.readline()
    )  # the fake prints the sleeper's pid on stderr
    try:
        reader = PipeReader(
            launched.stdout, capacity=QUEUE_CAPACITY_CHUNKS, stop=threading.Event()
        )  # Task 3's reader, owned by the test here
        reader.start()
        assert (
            launched.wait(5.0) == 0
        )  # the root is gone; the sleeper holds the write end
        reader.join(READER_JOIN_SECONDS)
        assert reader.is_alive()  # blocked inside ReadFile: exactly the §6.7 case
        assert launched.cancel_read(reader.native_thread_id) is True
        reader.join(READER_JOIN_SECONDS)
        assert not reader.is_alive() and reader.ended_by is ReaderEnd.CANCELLED
        assert launched.close(close_stdout=True, close_stderr=True).complete
    finally:
        terminate_pid(
            sleeper
        )  # the orphan the test created; the job-less controller cannot reach it


def test_a_child_that_exits_with_259_is_absent_not_alive(
    controller, tmp_root: Path
) -> None:
    launched = started(
        controller.launch(
            spec_for(
                [sys.executable, "-I", "-B", "-c", "raise SystemExit(259)"],
                cwd=tmp_root,
            )
        )
    )
    assert launched.wait(5.0) == 259
    assert (
        controller.inspect(process_identity_for(launched)).presence
        is ProcessPresence.ABSENT
    )  # the handle is signaled; 259 is not liveness
    assert launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE).failures == ()
    assert launched.close(close_stdout=True, close_stderr=True).complete


def test_a_job_kill_of_a_two_process_tree_reports_no_failure(
    controller, tmp_root: Path
) -> None:
    launched = started(
        controller.launch(
            program_spec(SPAWNS_A_SLEEPER_AND_PRINTS_ITS_PID, cwd=tmp_root)
        )
    )
    grandchild = int(launched.stdout.readline())
    report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    assert (
        report.job_terminated
        and report.failures == ()
        and grandchild in {d.pid for d in report.descendants}
    )
    assert (
        launched.wait(5.0) == 1067 and inspect_pid(grandchild) is ProcessPresence.ABSENT
    )


def test_an_interrupt_reaches_a_child_that_handles_sigbreak(
    controller, tmp_root: Path
) -> None:
    # HANDLER_EXITS_50_THEN_SLEEPS installs the handler and then loops `time.sleep(0.1)`:
    # a Python SIGBREAK handler runs only between bytecodes, never inside one long sleep.
    launched = started(
        controller.launch(
            spec_for(
                [sys.executable, "-I", "-B", "-c", HANDLER_EXITS_50_THEN_SLEEPS],
                cwd=tmp_root,
            )
        )
    )
    assert launched.interrupt() is InterruptOutcome.DELIVERED
    assert launched.wait(5.0) == 50


def test_a_missing_executable_is_an_availability_failure_not_an_exception(
    controller, tmp_root: Path
) -> None:
    failure = controller.launch(
        spec_for(["C:\\nowhere\\absent.exe", "describe"], cwd=tmp_root)
    )
    assert (
        isinstance(failure, LaunchFailure)
        and failure.not_found
        and failure.stage == "popen"
    )  # winerror 2 or 3
    denied = controller.launch(spec_for([str(tmp_root), "describe"], cwd=tmp_root))
    assert (
        isinstance(denied, LaunchFailure) and not denied.not_found
    )  # a directory is not an image


def test_a_reused_pid_is_not_ours() -> None:
    identity = identity_for_own_process(
        creation=own_creation() - 1
    )  # our pid, a creation time one tick earlier
    assert (
        WindowsProcessController().inspect(identity).presence
        is ProcessPresence.ALIVE_DIFFERENT_IDENTITY
    )


def test_the_toolhelp_fallback_terminates_a_verified_grandchild(
    controller_without_job, tmp_root: Path
) -> None:
    launched = started(
        controller_without_job.launch(
            program_spec(SPAWNS_A_SLEEPER_AND_PRINTS_ITS_PID, cwd=tmp_root)
        )
    )
    grandchild = int(launched.stdout.readline())
    report = launched.terminate_tree(FORCED_TERMINATION_EXIT_CODE)
    assert grandchild in {d.pid for d in report.descendants}
    assert not report.job_terminated
    assert inspect_pid(grandchild) is not ProcessPresence.ALIVE_MATCHING
```

  plus: the AST pin on the one `Popen` call (list argv, `shell=False`, `env={}`,
  `stdin=DEVNULL`, `close_fds=True`, `creationflags=subprocess.CREATE_NEW_PROCESS_GROUP |
  CREATE_SUSPENDED` as a `BinOp(BitOr)` of that attribute and the local name bound
  to `4`, `bufsize=0`, the `# noqa`
  text); `generate_console_break(0)` raises; `inspect` of a finished process is
  `ABSENT`; `test_the_interpreter_the_launcher_spawns_is_inside_the_supervisor_job`
  (launch a sleeper, find the launcher's child interpreter through
  `descendants_of`, open it and assert `is_process_in_job(handle,
  launched.job_handle)` — the positive control for the suspended launch, which
  makes the membership deterministic); after a successful job kill
  `TerminateProcess` reaches only a verified handle still unsignaled after the
  bounded wait, and otherwise it is attempted only while the target's handle is
  unsignaled; the Stage 5
  exemption test of §2.6; the §2.6 guard expectations. (The tests that need a real
  child use `time.monotonic()` only to bound wall time, which test code may do.)
  **Test helpers**: `ok`, `codes_of` as in Task 3; `started(result)` (asserts the
  launch result is a `WindowsLaunchedProcess`, not a `LaunchFailure`, and returns
  it narrowed to that class, so `process_handle` and `job_handle` type-check);
  `tmp_root` (a fixture: a
  directory under `tmp_path` that every launching test requests and every
  `LaunchSpecification` uses as `cwd`); `spec_for(argv: list[str], *, cwd: Path)`,
  `program_spec(code: str, *, cwd: Path)` = `spec_for([sys.executable, "-I", "-B",
  "-c", code], cwd=cwd)` (the three `-c` program constants always go through it)
  and `sleep_spec(cwd)` (a `LaunchSpecification` over a 30 s sleeper) build
  specifications; the module binds `SUPERVISOR_INSTANCE_ID = "windows-process-tests"`,
  `EXECUTABLE_PATH = str(Path(sys.executable))` and `EXECUTABLE_HASH =
  sha256_bytes(Path(sys.executable).read_bytes())` (Task 4 precedes the doubles
  module of Task 5, so it owns these values); `process_identity_for(launched)`
  renders the `ProcessIdentity` of a launched process from them;
  `own_creation()` reads this process's creation time through
  `windows_api.process_times`; `identity_for_own_process(creation)` renders a
  `ProcessIdentity` for this process with that creation time and the same three
  module-level values; `inspect_pid(pid)` is
  `WindowsProcessController().inspect` over a rendered identity for that pid;
  `terminate_pid(pid)` opens and terminates an orphan the test itself created;
  `HANDLER_EXITS_50_THEN_SLEEPS`, `SPAWNS_A_SLEEPER_AND_PRINTS_ITS_PID` and
  `SPAWNS_A_SLEEPER_INHERITING_STDOUT_AND_EXITS` are the `-c` programs above.
- [ ] **Step 2: Confirm RED.**
- [ ] **Step 3: Minimum GREEN.** The two modules; every `ctypes` binding bound on
  first use through a module-level `_KERNEL32: ctypes.WinDLL | None = None` (no
  `functools`, which is not an allowed root); `WindowsLaunchedProcess` is a plain
  class.
- [ ] **Step 4: Focused GREEN.** `tests\unit\process_supervision tests\safety
  tests\unit\test_package_layout.py -q`.
- [ ] **Step 5: Quality gates, Schema and migration preservation, Security and
  boundary review, Independent review, Commit, Clean-worktree checkpoint.**

**Broader tests.** `tests\unit tests\safety tests\architecture`; then `pytest-all`
in the background and alone (real children; hypothesis deadlines).
**Windows-specific tests.** Every test above is a Windows platform test: Job
Object membership and kill-on-close, `CTRL_BREAK` delivery to a process group,
`TerminateJobObject` exit code observation, Toolhelp descendant verification, PID
reuse through creation time, launch failure for an absent image; each test ends by
asserting no launched identity is `ALIVE_MATCHING`.
**Quality gates.** `ruff-format-all` (apply the printed diff by hand), `ruff-check-all`, strict `mypy-all` over `src`, `tests` and `scripts`, `schema-generate-check`; `ctypes` bindings typed through `ctypes.wintypes` so strict mypy needs no suppression.
**Schema and migration preservation.** As stated above.
**Security and boundary review.** The only `subprocess` importer and the only
`ctypes` importer in `src`; `env={}` is a literal; no `os.environ`; no shell; the
controller never kills by pid alone (creation time first); the job is a cleanup
mechanism and the module docstring says so with the words "a cleanup mechanism,
never a security boundary" (no "sandbox" substring, so the Task 9 guard's
one-site rule for that word stays true).
**Independent review.** Declared readings: §2.5 items 4, 6 and 16; the
suspended launch, assign, then resume order; `UNDETERMINED` for access-denied opens.
**Commit message.** `feat: add the windows process controller with job objects and tree termination`
**Clean-worktree checkpoint.** As stated above.

### Task 5 — The `experiments` lifecycle over the Stage 5 operations

**Files created.** `src/crypto_lab/experiments/supervision_lifecycle.py`,
`tests/unit/experiments/test_supervision_lifecycle.py`,
`tests/doubles/supervision.py` (only `SeedingDiagnosticRecorder` and
`InMemoryReconciliationSource` in this task; the rest in Tasks 6 and 8).
**Files modified.** `src/crypto_lab/experiments/__init__.py` (sorted exports), the
two §2.6 guard files (paths 92 → 93).
**Interfaces consumed.** The Stage 5 operations of §5.1; `build_request_envelope`,
`build_engine_run_request`; `SemanticOutcomeRequest`; `CommandResult`,
`ProtocolEventSummary`, the two parse types. The helper is defined in
`experiments` and cannot import `process_supervision`, so its signature takes the
outcome's fields rather than the outcome: `semantic_outcome_request_for(*,
command_result: CommandResult, output_parse: ValidationResultParse | ManifestParse
| MISSING, protocol_summary: ProtocolEventSummary, run: EngineRunRecord,
candidate_observations: tuple[CandidateObservation, ...], negotiated_versions:
NegotiatedVersions) -> SemanticOutcomeRequest`; the integration driver unpacks the
`SupervisionOutcome` into those arguments (§3.6 and §5.4 are read with this
signature).
**Interfaces produced.** `DiagnosticRecorder`, `RequestMaterial`,
`Stage5InvocationLifecycle` (all nine port members, `linked_run` and
`resolve_external_winner` included), `SUPERVISION_REASON_CODE`, `semantic_outcome_request_for`; the two
doubles.

- [ ] **Step 1: Focused RED.** Over `InMemoryBackingStore`, `FixedClock`,
  `SequentialIdentitySource` and the merged `sample_*` helpers. The `fixture`
  exposes `lifecycle` (a `Stage5InvocationLifecycle`), `store`, `recorder` (a
  `SeedingDiagnosticRecorder` with `calls`), `clock`, `token_material`,
  `slot_observation_id` (the frozen observation of the VALIDATE run's slot) and
  four seeded invocation ids, every record `PENDING` at revision 0: `inv` (RUN
  kind; its run `run` is `READY`), `run_kind_inv` (a second RUN pair; run
  `run_kind_run`, `READY`), `validate_kind_inv` (VALIDATE; run
  `validate_kind_run`, `VALIDATING`) and `describe_inv` (no run). Every seeded
  linked run carries `request_hash = request_material_hash(experiment=<the fixture
  experiment>, logical_slot_id=<the run's slot>, attempt_number=1,
  negotiated=DEFAULT_NEGOTIATED, limits=PROTOCOL_LIMITS_DEFAULT)` and
  `attempt_token_hash == attempt_token_hash(<that run's token material>.attempt_token)`,
  exactly as the harness seeds them (the merged builder recomputes both), and the
  fixture registers the matching `RequestMaterial` for every seeded invocation
  (`token_material` is `inv`'s) so `begin_start`'s pre-swap revalidation passes;
  `token_material_for(run_id, attempt_token=...)` builds another material (it
  constructs an `AttemptTokenMaterial`, so the token must be a grammar-valid
  `AttemptToken`: 32 to 1024 URL-safe characters) and
  `forget_request_material(invocation_id)` removes a registration. Helpers:
  `running(invocation_id)` (`begin_start` then `record_process_start`; returns the
  `RUNNING` record at revision 2), `terminal(invocation_id, state)` (`running`
  then `record_terminal` with a `PROCESS.*` primary; returns the record at
  revision 3), `stored_run(run_id=fixture.run)`, `stored_invocation(invocation_id)`,
  `move_run(state, run_id=fixture.run)` (a direct store write that models an
  external `transition_run`; it supplies the slot's frozen
  `availability_observation_id` for `READY` and a freshly minted primary for a
  terminal target, so the written record validates), `cancel_experiment()` (the merged
  `cancel_experiment(CancelExperimentRequest(schema_version="1.0.0",
  experiment_id=<the fixture experiment>, expected_revision=<its stored revision>,
  correlation_id="task5-cancel"), unit_of_work=<the fixture's>, clock=fixture.clock)`;
  it swaps the experiment alone and never touches a run, so the pair ends
  `CANCELLED` only through the lifecycle's coupled write, which is what the
  `run_kind_run` assertion below proves), `mint(code, invocation_id=fixture.inv)`
  (a Stage 7 code through `stage7_diagnostic`) and `mint_stage6(code,
  invocation_id=fixture.inv)` (a Stage 6 code such as `PROCESS.CANCELLED` through
  `stage6_diagnostic`), each correlated to the named invocation and its run:

```python
def test_begin_start_uses_the_linked_launch_for_run_and_the_plain_transition_otherwise(
    fixture,
) -> None:
    started = ok(fixture.lifecycle.begin_start(fixture.inv, expected_revision=0))
    assert started.state is CommandInvocationState.STARTING
    assert (
        fixture.stored_run().state is EngineRunState.STARTING
    )  # READY -> STARTING coupled
    validate = ok(
        fixture.lifecycle.begin_start(fixture.validate_kind_inv, expected_revision=0)
    )
    assert fixture.stored_run(validate.run_id).state is EngineRunState.VALIDATING


def test_linked_run_returns_the_run_record_for_linked_kinds_only(fixture) -> None:
    linked = ok(fixture.lifecycle.linked_run(fixture.inv))
    assert isinstance(
        linked, EngineRunRecord
    )  # narrows EngineRunRecord | MISSING for strict mypy
    assert (linked.run_id, linked.experiment_id, linked.state) == (
        fixture.run,
        fixture.stored_run().experiment_id,
        EngineRunState.READY,
    )
    assert not isinstance(
        ok(fixture.lifecycle.linked_run(fixture.describe_inv)), EngineRunRecord
    )  # MISSING for a describe


def test_begin_start_refuses_disagreeing_or_missing_material_before_the_swap(
    fixture,
) -> None:
    fixture.forget_request_material(fixture.run_kind_inv)
    assert codes_of(
        fixture.lifecycle.begin_start(fixture.run_kind_inv, expected_revision=0)
    ) == (INVARIANT_VIOLATION,)  # nothing registered
    fixture.lifecycle.register_request_material(
        fixture.run_kind_inv,
        RequestMaterial(
            token=fixture.token_material_for(
                fixture.run_kind_run, attempt_token="B" * 32
            ),  # grammar-valid, not the run's
            negotiated_versions=DEFAULT_NEGOTIATED,
            limits=PROTOCOL_LIMITS_DEFAULT,
        ),
    )
    assert codes_of(
        fixture.lifecycle.begin_start(fixture.run_kind_inv, expected_revision=0)
    ) == (INVARIANT_VIOLATION,)  # token hash disagrees
    assert (
        fixture.stored_invocation(fixture.run_kind_inv).state,
        fixture.stored_run(fixture.run_kind_run).state,
    ) == (CommandInvocationState.PENDING, EngineRunState.READY)


def test_begin_start_refuses_a_cancelled_parent_before_the_swap(fixture) -> None:
    fixture.cancel_experiment()
    assert codes_of(
        fixture.lifecycle.begin_start(fixture.inv, expected_revision=0)
    ) == (INVARIANT_VIOLATION,)
    assert (
        fixture.stored_invocation(fixture.inv).state,
        fixture.stored_run().state,
    ) == (CommandInvocationState.PENDING, EngineRunState.READY)


def test_begin_start_refuses_a_validate_whose_run_is_not_validating(fixture) -> None:
    fixture.move_run(EngineRunState.NOT_APPLICABLE, run_id=fixture.validate_kind_run)
    assert codes_of(
        fixture.lifecycle.begin_start(fixture.validate_kind_inv, expected_revision=0)
    ) == (INVARIANT_VIOLATION,)


def test_resolve_external_winner_cancels_only_beside_a_terminal_run_or_cancelled_experiment(
    fixture,
) -> None:
    primary = fixture.mint_stage6(
        PROCESS_CANCELLED, invocation_id=fixture.validate_kind_inv
    )
    fixture.move_run(
        EngineRunState.READY, run_id=fixture.validate_kind_run
    )  # a lawful orchestrator move, not a winner
    assert not isinstance(
        ok(
            fixture.lifecycle.resolve_external_winner(
                fixture.validate_kind_inv, expected_revision=0, primary=primary
            )
        ),
        CommandInvocationRecord,
    )  # MISSING: not a winner
    assert (
        fixture.stored_run(fixture.validate_kind_run).state is EngineRunState.READY
    )  # nothing was written
    fixture.move_run(EngineRunState.CANCELLED, run_id=fixture.validate_kind_run)
    record = ok(
        fixture.lifecycle.resolve_external_winner(
            fixture.validate_kind_inv, expected_revision=0, primary=primary
        )
    )
    assert (
        isinstance(record, CommandInvocationRecord)
        and record.state is CommandInvocationState.CANCELLED
    )  # alone path beside the terminal run
    fixture.cancel_experiment()
    primary = fixture.mint_stage6(PROCESS_CANCELLED, invocation_id=fixture.run_kind_inv)
    record = ok(
        fixture.lifecycle.resolve_external_winner(
            fixture.run_kind_inv, expected_revision=0, primary=primary
        )
    )
    assert (
        isinstance(record, CommandInvocationRecord)
        and record.state is CommandInvocationState.CANCELLED
    )
    assert fixture.stored_run(fixture.run_kind_run).state is EngineRunState.CANCELLED


def test_request_envelope_is_a_pure_function_of_the_starting_record_and_material(
    fixture,
) -> None:
    fixture.lifecycle.register_request_material(
        fixture.inv,
        RequestMaterial(
            token=fixture.token_material,
            negotiated_versions=DEFAULT_NEGOTIATED,
            limits=PROTOCOL_LIMITS_DEFAULT,
        ),
    )
    started = ok(fixture.lifecycle.begin_start(fixture.inv, expected_revision=0))
    first = ok(fixture.lifecycle.request_envelope(fixture.inv))
    second = ok(fixture.lifecycle.request_envelope(fixture.inv))
    assert first == second and first.created_at_utc == started.launch_attempted_at_utc


@pytest.mark.parametrize(
    ("target", "run_target"),
    [
        (CommandInvocationState.CANCELLED, EngineRunState.CANCELLED),
        (CommandInvocationState.TIMED_OUT, EngineRunState.TIMED_OUT),
        (CommandInvocationState.PROTOCOL_FAILED, EngineRunState.FAILED),
    ],
)
def test_a_core_won_terminal_couples_the_run_and_records_the_primary_first(
    fixture, target, run_target
) -> None:
    fixture.running(fixture.inv)
    primary = fixture.mint_stage6(PROCESS_CANCELLED)
    record = ok(
        fixture.lifecycle.record_terminal(
            fixture.inv,
            expected_revision=2,
            target_state=target,
            primary=primary,
            additional=(),
            native_exit_value=MISSING,
        )
    )
    assert record.state is target
    assert (
        fixture.stored_run().state is run_target
        and fixture.stored_run().primary_terminal_diagnostic_id == primary.diagnostic_id
    )
    assert fixture.recorder.calls[0] == primary.diagnostic_id


def test_a_terminal_beside_a_terminal_run_takes_the_alone_path(fixture) -> None:
    fixture.running(fixture.inv)
    fixture.move_run(EngineRunState.CANCELLED)  # transition_run won
    record = ok(
        fixture.lifecycle.record_terminal(
            fixture.inv,
            expected_revision=2,
            target_state=CommandInvocationState.CANCELLED,
            primary=fixture.mint_stage6(PROCESS_CANCELLED),
            additional=(),
            native_exit_value=MISSING,
        )
    )
    assert (
        record.state is CommandInvocationState.CANCELLED
        and fixture.stored_run().state is EngineRunState.CANCELLED
    )


def test_an_exited_write_beside_a_run_cancelled_externally_succeeds_alone(
    fixture,
) -> None:
    fixture.running(fixture.inv)
    fixture.move_run(
        EngineRunState.CANCELLED
    )  # reading 17: the live path writes the decided state
    record = ok(
        fixture.lifecycle.record_terminal(
            fixture.inv,
            expected_revision=2,
            target_state=CommandInvocationState.EXITED,
            primary=MISSING,
            additional=(),
            native_exit_value=0,
        )
    )
    assert (
        record.state is CommandInvocationState.EXITED
        and fixture.stored_run().state is EngineRunState.CANCELLED
    )


def test_failed_to_start_maps_the_run_by_the_recorded_primary_category(fixture) -> None:
    for invocation in (fixture.inv, fixture.run_kind_inv, fixture.validate_kind_inv):
        ok(
            fixture.lifecycle.begin_start(invocation, expected_revision=0)
        )  # STARTING beside STARTING / VALIDATING
    runtime = fixture.mint(PROCESS_LAUNCH_FAILED)  # ENGINE_RUNTIME
    ok(
        fixture.lifecycle.record_terminal(
            fixture.inv,
            expected_revision=1,
            target_state=FAILED_TO_START,
            primary=runtime,
            additional=(),
            native_exit_value=MISSING,
        )
    )
    assert fixture.stored_run().state is EngineRunState.FAILED
    availability = fixture.mint_stage6(
        ADAPTER_UNAVAILABLE, invocation_id=fixture.run_kind_inv
    )  # the merged mapping's other branch
    ok(
        fixture.lifecycle.record_terminal(
            fixture.run_kind_inv,
            expected_revision=1,
            target_state=FAILED_TO_START,
            primary=availability,
            additional=(),
            native_exit_value=MISSING,
        )
    )
    assert (
        fixture.stored_run(fixture.run_kind_run).state is EngineRunState.UNAVAILABLE
    )  # READY-time observation carried
    validate_availability = fixture.mint_stage6(
        ADAPTER_UNAVAILABLE, invocation_id=fixture.validate_kind_inv
    )
    ok(
        fixture.lifecycle.record_terminal(
            fixture.validate_kind_inv,
            expected_revision=1,
            target_state=FAILED_TO_START,
            primary=validate_availability,
            additional=(),
            native_exit_value=MISSING,
        )
    )
    validate_run = fixture.stored_run(fixture.validate_kind_run)
    assert validate_run.state is EngineRunState.UNAVAILABLE
    assert (
        validate_run.availability_observation_id == fixture.slot_observation_id
    )  # read from slot_compatibility


def test_the_recorder_is_idempotent_on_identity(fixture) -> None:
    diagnostic = fixture.mint(PROCESS_CLEANUP_FAILED)
    assert (
        ok(fixture.recorder.record(diagnostic)) is None
        and ok(fixture.recorder.record(diagnostic)) is None
    )
    assert (
        fixture.store.diagnostics.live[diagnostic.diagnostic_id] == diagnostic
        and fixture.recorder.calls == [diagnostic.diagnostic_id] * 2
    )


def test_enrich_writes_once_and_refuses_an_overwrite(fixture) -> None:
    fixture.terminal(
        fixture.inv, CommandInvocationState.TIMED_OUT
    )  # a core-won terminal at revision 3 admits an exit pair
    enriched = ok(
        fixture.lifecycle.enrich(
            fixture.inv,
            expected_revision=3,
            native_exit_value=1067,
            cleanup_complete=True,
            additional=(),
        )
    )
    assert enriched.native_exit_value == 1067 and enriched.cleanup_complete
    assert codes_of(
        fixture.lifecycle.enrich(
            fixture.inv,
            expected_revision=4,
            native_exit_value=0,
            cleanup_complete=False,
            additional=(),
        )
    ) == (INVARIANT_VIOLATION,)
```

  plus: the `RunReconciliationFacts` reader double; `semantic_outcome_request_for`
  against the harness's construction; `isinstance(lifecycle, InvocationLifecycle)`
  (the test imports the port); the `_conforms` static-conformance idiom; the
  recorder implements `record` only (no `get`/`get_many`) and records `calls`; the
  §2.6 guard expectations. **Test helpers**: `ok` and `codes_of` as in Task 3;
  bare enum members (`FAILED_TO_START`, `CANCELLED`, ...) are module-level aliases
  of the `CommandInvocationState` and `EngineRunState` members;
  `DEFAULT_NEGOTIATED` and `PROTOCOL_LIMITS_DEFAULT` are the merged constants.
- [ ] **Step 2: Confirm RED.**
- [ ] **Step 3: Minimum GREEN.** `experiments/supervision_lifecycle.py`, the two
  doubles in `tests/doubles/supervision.py`, the sorted `experiments/__init__.py`
  exports.
- [ ] **Step 4: Focused GREEN.** `tests\unit\experiments tests\safety
  tests\architecture tests\unit\test_package_layout.py -q`.
- [ ] **Step 5: Quality gates, Schema and migration preservation, Security and
  boundary review, Independent review, Commit, Clean-worktree checkpoint.**

**Broader tests.** `tests\unit tests\safety tests\architecture tests\contract`.
**Windows-specific tests.** None (in-memory ports).
**Quality gates.** `ruff-format-all` (apply the printed diff by hand), `ruff-check-all`, strict `mypy-all` over `src`, `tests` and `scripts`, `schema-generate-check`.
**Schema and migration preservation.** As stated above; `REQUEST_OPERATIONS` stays
at 17.
**Security and boundary review.** The module imports no `process_supervision`
name (the Stage 5 out-of-scope scan and the architecture allowlist prove it);
`RequestMaterial` is never logged, hashed or persisted and is dropped at the terminal write;
no `causal_diagnostic_ids` read; the recorder receives objects, never ids alone.
**Independent review.** Declared readings: §2.5 items 8, 9, 17 and 18; the single
reason-code literal; the alone path chosen from the reloaded run state.
**Commit message.** `feat: add the experiments lifecycle behind the supervision port`
**Clean-worktree checkpoint.** As stated above.

### Task 6 — The supervisor

**Files created.** `src/crypto_lab/process_supervision/supervisor.py`,
`tests/unit/process_supervision/test_supervisor_loop.py`,
`tests/unit/process_supervision/test_supervisor_preflight.py`.
**Files modified.** `tests/doubles/supervision.py` (`ScriptedProcessController`,
`ScriptedProcess`, `RecordingLifecycle`, `RecordingObserver`,
`SupervisionFixedClock`, `RealtimeMonotonicClock`, `supervised_catalog_entry_for`
for the merged fake, `build_supervisor`), the two §2.6 guard files (paths 93 → 94; `asyncio` 26 → 27).
**Interfaces consumed.** Tasks 1–5 output; `parse_protocol_line`,
`EventAcceptanceContext`, `InvocationEventLedger`, `BoundedStderrCapture`, the
three merged parsers, `attempt_token_hash`, `CommandResult`.
**Interfaces produced.** `WindowsProcessSupervisor(*, lifecycle, controller,
clock, supervision_root, supervisor_instance_id, cancellation_grace_seconds=10,
describe_limits=PROTOCOL_LIMITS_DEFAULT, preflight=MISSING, observers=())` with
`async invoke` (the `asyncio` import is function-local inside `invoke`);
`supervised_catalog_entry_for(adapter_name, *, script=None, executable=None)`,
`build_supervisor`, `SupervisionFixedClock`, `RealtimeMonotonicClock`.

- [ ] **Step 1: Focused RED.** One test per row of §6.4 and §5.3 over the
  scripted controller (§9.5), for example:

```python
def test_a_rejection_wins_over_an_exit_observed_in_the_same_tick(scripted) -> None:
    scripted.stdout_chunks = [valid_heartbeat_line(sequence=1), b"not json\n"]
    scripted.exit_after = 1
    outcome = run(
        scripted.supervisor.invoke(scripted.run_command, ThreadSafeCancellationToken())
    )
    record = ok(outcome).command_result.invocation
    assert (
        record.state is CommandInvocationState.PROTOCOL_FAILED
    )  # EOF follows the last chunk, so the rejection is decided first
    assert (
        scripted.controller.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]
        and scripted.controller.interrupt_calls == 0
    )
    assert (
        scripted.lifecycle.calls.count("enrich") == 1 and record.native_exit_value == 0
    )  # the root's own reaped exit; killing an exited root is a no-op


def test_cancellation_beats_the_deadline_and_is_enriched_once(scripted) -> None:
    token = ThreadSafeCancellationToken()
    scripted.observer.on(
        SupervisionTraceKind.RUNNING_COMMITTED,
        lambda _entry: (
            token.request_cancellation(),
            scripted.clock.advance(scripted.timeout_seconds + 1),
        ),
    )
    scripted.advance_per_tick(1.0)  # the grace window elapses in ticks, not wall time
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token))
    ).command_result.invocation
    assert record.state is CommandInvocationState.CANCELLED
    assert scripted.stored_run().state is EngineRunState.CANCELLED
    assert [e.kind for e in scripted.observer.entries if e.kind in ORDER_KINDS] == [
        TERMINAL_DECIDED,
        TERMINAL_COMMITTED,
        INTERRUPT_SENT,
        FORCED_TERMINATION,
        EXIT_REAPED,
        ENRICHMENT_COMMITTED,
    ]


def test_a_cancellation_after_launch_but_before_the_handoff_forces_without_an_interrupt(
    scripted,
) -> None:
    token = ThreadSafeCancellationToken()
    scripted.controller.on_launch = lambda: token.request_cancellation()
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token))
    ).command_result.invocation
    assert (record.state, record.process_created) == (
        CANCELLED,
        False,
    ) and not isinstance(
        record.native_exit_value, int
    )  # no exit pair; no `MISSING` inside a tuple equality (§2.6)
    assert (
        scripted.controller.interrupt_calls == 0
        and scripted.controller.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]
    )


def test_a_cancellation_before_begin_start_never_launches_and_still_enriches_once(
    scripted,
) -> None:
    token = ThreadSafeCancellationToken()
    token.request_cancellation()
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token))
    ).command_result.invocation
    assert (record.state, record.process_created, record.cleanup_complete) == (
        CANCELLED,
        False,
        True,
    )
    assert (
        scripted.stored_run().state is EngineRunState.CANCELLED
        and scripted.controller.launches == ()
    )
    assert scripted.lifecycle.calls.count("enrich") == 1


def test_a_run_cancelled_externally_around_the_launch_is_honored_as_a_cancellation(
    scripted,
) -> None:
    scripted.lifecycle.before("begin_start", lambda: scripted.cancel_run_externally())
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    assert (
        record.state is CommandInvocationState.CANCELLED
        and record.process_created is False
    )
    scripted.reset()
    scripted.lifecycle.before(
        "record_process_start", lambda: scripted.cancel_run_externally()
    )
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    assert (
        record.state is CommandInvocationState.CANCELLED
        and scripted.controller.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]
    )
    assert scripted.lifecycle.calls.count("resolve_external_winner") == 1


def test_a_refused_exited_write_is_a_defect_and_moves_nothing(scripted) -> None:
    scripted.lifecycle.fail(
        "record_terminal", INVARIANT_VIOLATION
    )  # one-shot, on the EXITED write
    scripted.exit_after = 1
    failure = run(scripted.supervisor.invoke(scripted.run_command, token()))
    assert codes_of(failure) == (INVARIANT_VIOLATION,)
    assert scripted.stored_invocation().state is CommandInvocationState.RUNNING
    assert scripted.stored_run().state is EngineRunState.RUNNING
    assert (
        "resolve_external_winner" not in scripted.lifecycle.calls
        and scripted.lifecycle.calls.count("record_terminal") == 1
    )


def test_a_terminal_write_refused_by_a_run_race_is_reissued_once_on_the_alone_path(
    scripted,
) -> None:
    scripted.exit_after = 1
    scripted.lifecycle.fail(
        "record_terminal", CONCURRENCY_CONFLICT
    )  # the coupled swap lost to an external transition_run
    scripted.lifecycle.before(
        "record_terminal", lambda: scripted.cancel_run_externally()
    )
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    assert (
        record.state is CommandInvocationState.EXITED
        and scripted.lifecycle.calls.count("record_terminal") == 2
    )
    assert (
        scripted.stored_run().state is EngineRunState.CANCELLED
    )  # left as the core left it: the alone path


def test_a_cancelled_experiment_before_begin_start_never_launches(scripted) -> None:
    scripted.lifecycle.before(
        "begin_start", lambda: scripted.cancel_experiment_externally()
    )
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    assert (record.state, record.process_created) == (
        CANCELLED,
        False,
    ) and scripted.controller.launches == ()
    assert (
        scripted.stored_run().state is EngineRunState.CANCELLED
        and scripted.lifecycle.calls.count("resolve_external_winner") == 1
    )


def test_a_backlog_after_the_exit_is_drained_not_treated_as_a_pipe_holder(
    scripted,
) -> None:
    scripted.exit_after = 1
    scripted.stdout_chunks = [valid_heartbeat_line(sequence=i + 1) for i in range(3000)]
    scripted.advance_per_tick(
        0.001
    )  # the drain takes real reader-thread turns; 4000 polls before the fake deadline, 1000 idle polls before the pipe-holder window
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    assert record.state is CommandInvocationState.EXITED
    assert (
        sum(
            1
            for e in scripted.observer.entries
            if e.kind is SupervisionTraceKind.EVENT_ACCEPTED
        )
        == 3000
    )
    assert not any(
        e.kind is SupervisionTraceKind.FORCED_TERMINATION
        for e in scripted.observer.entries
    )
    assert scripted.controller.terminate_calls == []


def test_a_pipe_holder_the_kill_cannot_reach_is_terminated_once_and_times_out(
    scripted,
) -> None:
    scripted.exit_after = 1
    scripted.hold_stdout_open = True
    scripted.release_on_terminate = False
    scripted.advance_per_tick(0.5)
    record = ok(run(...)).command_result.invocation
    assert record.state is CommandInvocationState.TIMED_OUT and record.cleanup_complete
    assert scripted.controller.terminate_calls == [
        FORCED_TERMINATION_EXIT_CODE
    ]  # step 8 once; the PROCESS_GONE branch terminates nothing again
    assert (
        sum(
            1
            for e in scripted.observer.entries
            if e.kind is SupervisionTraceKind.FORCED_TERMINATION
        )
        == 1
    )
    stopped = next(
        e
        for e in scripted.observer.entries
        if e.kind is SupervisionTraceKind.CLEANUP_ACTION
        and e.facts["action"] == "STDOUT_READER_STOPPED"
    )
    assert (
        stopped.facts["ended_by"] == "CANCELLED"
    )  # the double's cancel_read released the held read


def test_a_flush_rejection_after_a_pipe_holder_kill_does_not_terminate_twice(
    scripted,
) -> None:
    scripted.exit_after = 1
    scripted.hold_stdout_open = True
    scripted.stdout_chunks = [b'{"unterminated']
    scripted.advance_per_tick(0.5)
    record = ok(run(...)).command_result.invocation
    assert record.state is CommandInvocationState.PROTOCOL_FAILED
    assert (
        scripted.controller.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]
        and scripted.lifecycle.calls.count("enrich") == 1
    )
    forced = [
        e
        for e in scripted.observer.entries
        if e.kind is SupervisionTraceKind.FORCED_TERMINATION
    ]
    assert len(forced) == 1 and forced[0].facts["reason"] == "pipe_holder"


def test_a_root_that_exits_while_a_descendant_holds_stdout_is_forced_and_still_exits(
    scripted,
) -> None:
    scripted.exit_after = 1
    scripted.hold_stdout_open = True
    scripted.advance_per_tick(0.5)
    record = ok(run(...)).command_result.invocation
    assert (
        record.state is CommandInvocationState.EXITED and record.native_exit_value == 0
    )
    assert PROCESS_FORCED_TERMINATION in scripted.codes_of_ids(record.diagnostic_ids)


def test_a_deadline_passing_before_the_handoff_times_out_from_starting_without_process_facts(
    scripted,
) -> None:
    scripted.controller.on_launch = lambda: scripted.clock.advance(
        scripted.timeout_seconds + 1
    )
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    assert (record.state, record.process_created) == (
        TIMED_OUT,
        False,
    ) and not isinstance(record.native_exit_value, int)  # no exit pair (§2.6)
    assert (
        primary_code(record) == PROCESS_START_TIMED_OUT
        and scripted.stored_run().state is EngineRunState.TIMED_OUT
    )


def test_a_missed_heartbeat_is_minted_once_and_never_terminates(scripted) -> None:
    scripted.stdout_chunks = [valid_heartbeat_line(sequence=1)]
    scripted.advance_per_tick(0.5)
    record = ok(run(...)).command_result.invocation
    assert record.state is CommandInvocationState.TIMED_OUT
    assert (
        scripted.codes_of_ids(record.diagnostic_ids).count(PROCESS_MISSING_HEARTBEAT)
        == 1
    )
    assert causal_ids(primary(record)) == (scripted.missing_heartbeat_id(),)
    missed_at = next(
        i
        for i, e in enumerate(scripted.observer.entries)
        if e.kind is SupervisionTraceKind.HEARTBEAT_MISSED
    )
    bounds_after_mint = scripted.wait_bounds[
        missed_at:
    ]  # §6.3 step 9: a minted monitor no longer lowers the bound
    assert bounds_after_mint and all(
        0.0 < b <= TICK_SECONDS for b in bounds_after_mint
    )  # never 0.0, so never a busy wait
    assert (
        scripted.controller.polls_between(
            SupervisionTraceKind.HEARTBEAT_MISSED, SupervisionTraceKind.TERMINAL_DECIDED
        )
        <= scripted.timeout_seconds / 0.5 + 1
    )  # sanity bound only


def test_an_external_terminal_winner_is_returned_not_overwritten(scripted) -> None:
    scripted.exit_after = 1
    scripted.lifecycle.before(
        "record_terminal", lambda: scripted.terminalize_invocation_externally()
    )
    outcome = ok(run(...))
    assert outcome.command_result.invocation.state is CommandInvocationState.CANCELLED
    assert any(
        e.kind is SupervisionTraceKind.EXTERNAL_TERMINAL_WINNER for e in outcome.trace
    )


def test_a_lost_enrichment_swap_reloads_once_and_leaves_a_reconciliation_target(
    scripted,
) -> None:
    scripted.exit_after = 1
    scripted.lifecycle.fail("enrich", CONCURRENCY_CONFLICT)
    outcome = ok(run(...))
    assert (
        scripted.lifecycle.calls.count("enrich") == 1
    )  # the intercepted call is recorded; no second attempt
    assert (
        outcome.command_result.invocation == scripted.stored_invocation()
        and outcome.command_result.invocation.cleanup_complete is False
    )
    assert any(
        e.kind is SupervisionTraceKind.EXTERNAL_TERMINAL_WINNER for e in outcome.trace
    )
    assert outcome.command_result.invocation.invocation_id in {
        r.invocation_id
        for r in ok(
            InMemoryReconciliationSource(scripted.store).list_reconciliation_targets()
        )
    }


def test_an_own_request_defect_terminates_the_child_and_returns_the_failure(
    scripted,
) -> None:
    scripted.exit_after = 1
    scripted.step_utc_backwards_before("record_terminal")
    failure = run(...)
    assert (
        codes_of(failure) == (INVARIANT_VIOLATION,)
        and scripted.controller.terminate_calls
    )
    assert scripted.stored_invocation().state is CommandInvocationState.RUNNING


def test_a_lifecycle_failure_while_running_is_an_orchestrator_cancellation(
    scripted,
) -> None:
    scripted.stdout_chunks = [valid_heartbeat_line(sequence=1)]
    scripted.lifecycle.fail("append_event", CONCURRENCY_CONFLICT)
    record = ok(run(...)).command_result.invocation
    assert record.state is CommandInvocationState.CANCELLED
    assert causal_codes(primary(record)) == (CONCURRENCY_CONFLICT,)
    assert (
        scripted.stored_run().state is EngineRunState.CANCELLED
    )  # reading 8: the retriable posture is forfeited on purpose


def test_a_clean_exit_carries_no_stage_seven_diagnostic(scripted) -> None:
    scripted.exit_after = 1
    outcome = ok(run(...))
    assert (
        outcome.command_result.diagnostics == ()
        and outcome.command_result.invocation.cleanup_complete
    )
```

  plus: the preflight refusals of §4.4 (record unchanged, `Failure` codes); an
  absent executable → `FAILED_TO_START` with `ADAPTER.UNAVAILABLE` carrying
  `invocation_id`, `run_id` and `experiment_id`, run `UNAVAILABLE` for both a RUN
  and a VALIDATE; a present-but-mismatched executable → `FAILED_TO_START` with
  `CORE.IMMUTABLE_INPUT_MISMATCH`, run `FAILED`; a `LaunchFailure` with `not_found`
  → `ADAPTER.UNAVAILABLE` and any other `LaunchFailure` → `PROCESS.LAUNCH_FAILED`,
  both minted by the supervisor and the stored primary carrying `run_id` and
  `experiment_id` for a linked kind; another actor moving the `PENDING` record to
  `STARTING` before `begin_start` (`scripted.lifecycle.before("begin_start",
  scripted.start_invocation_externally)`) → the original `Failure` returned,
  `controller.launches == ()`, `calls.count("begin_start") == 1` and the stored
  record still `STARTING` at the mover's revision (§5.3 row 4); a run whose
  heartbeat and contaminated lines carry the seeded raw token leaves no trace
  entry whose canonical JSON contains it;
  `tests/unit/test_package_layout.py` passing with `crypto_lab.process_supervision.supervisor`
  listed (the function-local `asyncio` import);
  envelope disagreement; describe stdout counted and never parsed (several chunks
  fed, exactly one retained `STDOUT_BYTES_COUNTED` entry whose fact equals
  `stdout_byte_count`); a forced termination without interrupt for every rejection
  code (`interrupt_calls == 0`, reading 5); the output
  read for `EXITED` only, bounded; the trailing-fragment flush; post-decision
  parsing and a post-decision `append_event` failure; `StderrCapture` present on
  every terminal decided after the envelope was written, and
  `command_result.stderr` absent (`not isinstance(command_result.stderr, StderrCapture)`) on a terminal decided before it (the
  never-launched `PENDING → CANCELLED`, the absent- or mismatched-executable
  `FAILED_TO_START`, the `begin_start`-failure rows: the fold needs the token the
  envelope carries); the `DESCRIBE_STDERR_PLACEHOLDER` policy (a describe has no
  attempt token, and the merged capture refuses an empty one, so `models.py`
  supplies a NUL-bracketed value built from `chr(0)` pieces that no adapter text
  can contain; a test asserts it never appears in a describe's `sanitized_text`);
  a `PROTOCOL_FAILED`/`CANCELLED`/`TIMED_OUT` transition carries
  `PROCESS.STDERR_TRUNCATED` from the supervisor's own `stderr_bytes_fed` counter;
  the
  §2.6 guard expectations. **Test helpers**: `ok`, `codes_of` as in Task 3;
  `run(coro)` is `asyncio.run` (a test module may import `asyncio`); `token()` a
  fresh `ThreadSafeCancellationToken`; `valid_heartbeat_line(sequence: int = 1, *,
  activity_counter: int | None = None) -> bytes` one framed `HEARTBEAT` line for
  the seeded run's token with a fresh `event_id` per call, the given `sequence` and
  a non-decreasing `activity_counter` (default `sequence`), because the merged
  parser replays a repeated sequence and rejects a gap; `primary(record)` the stored primary
  `Diagnostic`, `primary_code(record)` its code, `causal_ids(d)`/`causal_codes(d)`
  its causal identities or their codes; `ORDER_KINDS` the six kinds named in the cancellation test's expected list
  (`CLEANUP_ACTION` entries are excluded from that filter); `ok(run(...))` in the
  sketches abbreviates `ok(run(scripted.supervisor.invoke(scripted.run_command,
  token())))`; bare enum members (`CANCELLED`, `TIMED_OUT`, `RUNNING_COMMITTED`,
  ...) are module-level aliases of the `CommandInvocationState`, `EngineRunState`,
  `SupervisionTraceKind` and `ProcessPresence` members.
- [ ] **Step 2: Confirm RED.**
- [ ] **Step 3: Minimum GREEN.** `process_supervision/supervisor.py` and the Task 6
  doubles (`ScriptedProcessController`, `ScriptedProcess`, `RecordingLifecycle`,
  `RecordingObserver`, `SupervisionFixedClock`, `RealtimeMonotonicClock`,
  `supervised_catalog_entry_for`, `build_supervisor`).
- [ ] **Step 4: Focused GREEN.** `tests\unit\process_supervision tests\safety
  tests\unit\test_package_layout.py -q`.
- [ ] **Step 5: Quality gates, Schema and migration preservation, Security and
  boundary review, Independent review, Commit, Clean-worktree checkpoint.**

**Broader tests.** `tests\unit tests\safety tests\architecture`; then `pytest-all`
alone.
**Windows-specific tests.** One real-child smoke test in
`test_supervisor_loop.py` (`fake.conformant` describe through the Windows
controller and `supervised_catalog_entry_for`, produced in this task, reaches
`EXITED`), so the loop is proven against a real pipe before Task 8's matrix.
**Quality gates.** `ruff-format-all` (apply the printed diff by hand), `ruff-check-all`, strict `mypy-all` over `src`, `tests` and `scripts`, `schema-generate-check`.
**Schema and migration preservation.** As stated above.
**Security and boundary review.** The token appears only as the envelope field and
the parsers' argument; no trace fact carries bytes; the supervisor never calls a
run transition; every write goes through the port; `asyncio` is used only for
`to_thread`.
**Independent review.** Declared readings: §2.5 items 1, 3, 5, 7, 10, 13, 14, 15
and 19; the tick order; the single enrichment.
**Commit message.** `feat: add the windows process supervisor loop`
**Clean-worktree checkpoint.** As stated above.

### Task 7 — Restart reconciliation

**Files created.** `src/crypto_lab/process_supervision/reconciliation.py`,
`tests/unit/process_supervision/test_restart_reconciliation.py`.
**Files modified.** `src/crypto_lab/process_supervision/__init__.py` (exports,
`__all__`, the package docstring), the two §2.6 guard files (paths 94 → 95).
**Interfaces consumed.** Tasks 1–6 output; `InMemoryReconciliationSource`.
**Interfaces produced.** `reconcile_invocations`, `ReconciliationReport`,
`InvocationReconciliation`, `ReconciliationAction` (Task 2 records populated).

- [ ] **Step 1: Focused RED.** The §8.5 table parametrized:

```python
@pytest.mark.parametrize("kind", [DESCRIBE, VALIDATE, RUN])
def test_a_persisted_starting_record_fails_to_start_unless_cancelled_or_expired(
    reconciler, kind
) -> None:
    for cancelled, past_deadline, action, code in [
        (False, False, TERMINALIZED_FAILED_TO_START, PROCESS_LAUNCH_NOT_COMMITTED),
        (True, False, TERMINALIZED_CANCELLED, PROCESS_CANCELLED),
        (False, True, TERMINALIZED_TIMED_OUT, TIMEOUT_CODE_OF[kind]),
    ]:  # explicit keywords: strict mypy rejects **dict[str, bool] against the signature
        if kind is DESCRIBE and cancelled:
            continue  # a describe has no run or experiment, so `cancelled` is never true for it (§8.5)
        entry = reconciler.run_one(
            kind=kind, state=STARTING, cancelled=cancelled, past_deadline=past_deadline
        )  # a fresh invocation (and run) per call
        assert (entry.action, primary_code(entry.record_after)) == (action, code)
        assert (
            entry.record_after.process_created is False
            and entry.record_after.cleanup_complete
        )  # complete because the fixture seeds no root
        if kind is not DESCRIBE:
            assert reconciler.stored_run(entry).state is COUPLED_RUN_TARGET[action]
    if kind is DESCRIBE:
        entry = reconciler.run_one(
            kind=DESCRIBE, state=STARTING, cancelled=True
        )  # the flag is meaningless for a describe
        assert entry.action is TERMINALIZED_FAILED_TO_START


def test_a_live_matching_process_is_terminated_and_becomes_protocol_failed(
    reconciler,
) -> None:
    entry = reconciler.run_one(kind=RUN, state=RUNNING, presence=ALIVE_MATCHING)
    assert entry.action is TERMINALIZED_PROTOCOL_FAILED
    assert (
        primary_code(entry.record_after)
        == PROCESS_ORCHESTRATOR_RESTART_LOST_SUPERVISION
    )
    assert (
        reconciler.controller.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]
        and reconciler.stored_run(entry).state is EngineRunState.FAILED
    )
    assert (
        entry.record_after.cleanup_complete
    )  # the scripted controller reports ABSENT after its own terminate_tree


def test_a_reused_pid_is_left_alone_and_recorded(reconciler) -> None:
    entry = reconciler.run_one(
        kind=RUN, state=RUNNING, presence=ALIVE_DIFFERENT_IDENTITY
    )
    assert (
        entry.action is LEFT_RUNNING_AWAITING_DEADLINE
        and reconciler.controller.terminate_calls == []
    )
    assert PROCESS_PID_REUSE_DETECTED in codes_of_diagnostics(entry.diagnostics)


def test_an_absent_process_waits_for_its_deadline_and_never_becomes_exited(
    reconciler,
) -> None:
    before = reconciler.run_one(kind=RUN, state=RUNNING, presence=ABSENT)
    assert (
        before.action is LEFT_RUNNING_AWAITING_DEADLINE
        and before.manifest_present is False
    )
    reconciler.clock.advance(reconciler.timeout_seconds + 1)
    after = reconciler.run_again(before)  # the same record, its deadline now passed
    assert after.action is TERMINALIZED_TIMED_OUT and not isinstance(
        after.record_after.native_exit_value, int
    )  # no exit pair (MISSING)


def test_a_cancelled_run_beside_a_running_invocation_is_honored_alone(
    reconciler,
) -> None:
    entry = reconciler.run_one(
        kind=RUN, state=RUNNING, presence=ABSENT, run_state=EngineRunState.CANCELLED
    )
    assert (
        entry.action is TERMINALIZED_CANCELLED
        and reconciler.stored_run(entry).state is EngineRunState.CANCELLED
    )


@pytest.mark.parametrize(
    ("process_created", "presence"),
    [
        (True, ABSENT),
        (True, UNDETERMINED),
        (True, ALIVE_DIFFERENT_IDENTITY),
        (False, ABSENT),
    ],
)
def test_a_terminal_with_incomplete_cleanup_is_cleaned_and_enriched_once(
    reconciler, process_created, presence
) -> None:
    entry = reconciler.run_one(
        kind=RUN,
        state=CANCELLED,
        cleanup_complete=False,
        process_created=process_created,
        presence=presence,
    )
    assert entry.action is CLEANUP_COMPLETED and entry.record_after.cleanup_complete
    assert (PROCESS_PID_REUSE_DETECTED in codes_of_diagnostics(entry.diagnostics)) is (
        presence is ALIVE_DIFFERENT_IDENTITY
    )
    assert (
        reconciler.controller.terminate_calls == []
    )  # a reused pid is never ours to kill
    assert entry.record_after.invocation_id not in {
        r.invocation_id for r in reconciler.list_targets()
    }


def test_a_repeated_cleanup_failure_does_not_grow_the_diagnostic_list(
    reconciler,
) -> None:
    with (
        reconciler.hold_request_open()
    ):  # plants <root>\<invocation_id>\request.json and keeps it open
        first = reconciler.run_one(
            kind=DESCRIBE,
            state=FAILED_TO_START,
            cleanup_complete=False,
            process_created=False,
        )
        second = reconciler.run_again(first)
    assert (first.action, second.action) == (
        CLEANUP_FAILED,
        CLEANUP_STILL_FAILING,
    )  # sharing_violation:32 both times
    assert len(second.record_after.diagnostic_ids) == len(
        first.record_after.diagnostic_ids
    )
    third = reconciler.run_again(first)
    assert third.action is CLEANUP_COMPLETED and third.record_after.cleanup_complete


def test_a_starting_record_whose_root_is_held_terminalizes_with_incomplete_cleanup(
    reconciler,
) -> None:
    with reconciler.hold_request_open():
        first = reconciler.run_one(
            kind=DESCRIBE, state=STARTING, cleanup_complete=False
        )  # a persisted STARTING crash with its root present
        second = reconciler.run_again(first)
    assert (
        first.action is TERMINALIZED_FAILED_TO_START
        and first.record_after.cleanup_complete is False
    )
    assert codes_of_diagnostics(first.diagnostics).count(PROCESS_CLEANUP_FAILED) == 1
    assert second.action is CLEANUP_STILL_FAILING and len(
        second.record_after.diagnostic_ids
    ) == len(first.record_after.diagnostic_ids)
    third = reconciler.run_again(first)
    assert third.action is CLEANUP_COMPLETED and third.record_after.cleanup_complete


@pytest.mark.parametrize(
    ("kind", "state", "run_state"),
    [
        (RUN, RUNNING, EngineRunState.STARTING),
        (VALIDATE, STARTING, EngineRunState.READY),
        (VALIDATE, RUNNING, EngineRunState.READY),
    ],
)
def test_a_mixed_running_pair_is_reported_not_repaired(
    reconciler, kind, state, run_state
) -> None:
    entry = reconciler.run_one(
        kind=kind, state=state, presence=ABSENT, run_state=run_state
    )
    assert (
        entry.action is INVARIANT_REPORTED
        and reconciler.stored_invocation(entry).state is state
    )  # a VALIDATE beside READY has no edge to TIMED_OUT or FAILED


def test_the_reconciler_never_produces_exited(reconciler) -> None:
    for entry in reconciler.run_every_row():
        assert (
            entry.state_before is CommandInvocationState.EXITED
            or entry.record_after.state is not CommandInvocationState.EXITED
        )
```

  plus `PENDING` left alone, `EXITED` cleanup without inspection, the report's
  ordering and uniqueness, the `SKIPPED_EXTERNAL_WINNER` row, and the §2.6 guard
  expectations. The `reconciler` fixture exposes `run_one(kind, state, *,
  presence=ProcessPresence.ABSENT (the one channel: it is written onto
  `controller.inspection` before the pass; tests never assign the controller
  directly), cleanup_complete=True, process_created=<by
  state>, run_state=<the pair's matching state: VALIDATING for VALIDATE; STARTING
  or RUNNING beside the same invocation state for RUN; the coupled terminal
  beside a terminal invocation>, cancelled=False, past_deadline=False) ->
  InvocationReconciliation` (mints a fresh experiment with its slot compatibility,
  a fresh invocation and, for a linked kind, a fresh run per call by direct store
  write, stamping `created_at_utc`/`launch_attempted_at_utc` from `clock.now_utc()`
  at seeding so `deadline_utc` is relative to the current clock and neither the
  shared clock nor an earlier `cancelled=True` leaks into a later call;
  `cancelled=True` cancels the experiment through the merged `cancel_experiment`
  so the coupled path is exercised (a no-op for a `DESCRIBE`, which has no
  experiment); `past_deadline=True` advances `clock` past the
  seeded `deadline_utc`; `presence` is what the scripted controller reports; then
  runs one pass and returns that record's entry), `run_again(entry)` (one more
  pass over that entry's existing record, without seeding), `run_every_row()`
  (one fresh record per §8.5 row, one pass), `list_targets() ->
  tuple[CommandInvocationRecord, ...]` (the unwrapped
  `ok(source.list_reconciliation_targets())`), `stored_run(entry)`,
  `stored_invocation(entry)`, `controller` (the scripted controller: `inspection`,
  `terminate_calls: list[int]`; it reports `ABSENT` for any identity its own
  `terminate_tree` was called on, §9.2), `clock`, `timeout_seconds` and
  `hold_request_open()`. **Test helpers**: `ok` as in Task 3;
  `codes_of_diagnostics(diagnostics: tuple[Diagnostic, ...]) -> tuple[str, ...]`
  (codes in order; a different contract from Task 3's `codes_of`, hence the
  different name); `primary_code(record)` (the stored primary's code, as in Task
  6); `TIMEOUT_CODE_OF` and `COUPLED_RUN_TARGET`, the module-level maps the
  parametrized rows read; bare enum members (`DESCRIBE`, `RUN`, `STARTING`,
  `RUNNING`, `CANCELLED`, `FAILED_TO_START`, `ALIVE_MATCHING`, `ABSENT`,
  `TERMINALIZED_*`, ...) are module-level aliases of the `CommandKind`,
  `CommandInvocationState`, `ProcessPresence` and `ReconciliationAction` members.
  `hold_request_open()` uses the open-handle
  technique of Task 3 (no monkeypatch, no injected removal callable):
  `remove_command_root` reports `sharing_violation:32` while the handle is held;
  the fixture mints ids from a `SequentialIdentitySource`, so the context plants
  the request file under the id the next `run_one` will mint.
- [ ] **Step 2: Confirm RED.**
- [ ] **Step 3: Minimum GREEN.** `process_supervision/reconciliation.py` and the
  package `__init__.py` exports and docstring.
- [ ] **Step 4: Focused GREEN.** `tests\unit\process_supervision tests\safety
  tests\unit\test_package_layout.py -q`.
- [ ] **Step 5: Quality gates, Schema and migration preservation, Security and
  boundary review, Independent review, Commit, Clean-worktree checkpoint.**

**Broader tests.** `tests\unit tests\safety tests\architecture`.
**Windows-specific tests.** None in this task (scripted); the real-process restart
cases are Task 8's.
**Quality gates.** `ruff-format-all` (apply the printed diff by hand), `ruff-check-all`, strict `mypy-all` over `src`, `tests` and `scripts`, `schema-generate-check`.
**Schema and migration preservation.** As stated above.
**Security and boundary review.** The reconciler never reads a request file, never
kills by pid alone, never removes a post-`RUNNING` root, never writes a run
success state; `manifest_present` is existence only.
**Independent review.** Declared readings: §2.5 items 16 and 17; the `EXITED`
no-inspection rule; `CLEANUP_STILL_FAILING`; the reported-only rule for the
diagnostics of write-free rows (carried in `InvocationReconciliation.diagnostics`,
persisted only when a later pass attaches them — no recording port member is
added).
**Commit message.** `feat: add restart reconciliation for command invocations`
**Clean-worktree checkpoint.** As stated above.

### Task 8 — Stage 7 fake scenarios, the harness seam, the supervised matrix and the Windows platform suites

**Files created.** `tests/fake_adapters/supervision_fake.py`,
`tests/integration/process_supervision/supervision_scenarios.py`,
`tests/integration/process_supervision/supervised_strategy.py`,
`tests/integration/process_supervision/test_supervised_contract_matrix.py`,
`tests/integration/process_supervision/test_windows_paths.py`,
`tests/integration/process_supervision/test_windows_launch_arguments.py`,
`tests/integration/process_supervision/test_windows_process_tree.py`,
`tests/integration/process_supervision/test_windows_process_identity.py`,
`tests/integration/process_supervision/test_windows_open_handles.py`,
`tests/integration/process_supervision/test_windows_restart_reconciliation.py`,
`tests/integration/process_supervision/test_windows_stderr_limits.py`.
**Files modified.** `tests/contract/harness.py` (the seam of §9.3, including the
`supervision_outcome` field on `_Supervised` and on `CommandRun` at both of its
construction sites), `tests/contract/test_harness_safety.py` (the seam's own safety
pins: the default strategy is the stand-in; `_Supervised` field relaxation;
`command_run.supervision_outcome is None` on the default strategy), `tests/doubles/supervision.py`
(`TeeController`; the `SUPERVISION_FAKE_PATH` branch of `supervised_catalog_entry_for`),
`tests/safety/test_stage6_boundaries.py` (`_SUBPROCESS_IMPORTERS` 10 → 11).
**Interfaces consumed.** Tasks 1–7 output; the harness helpers of §2.2; the merged
fake's module-level helpers.
**Interfaces produced.** `SUPERVISION_SCENARIOS`, `ProductionSupervision`,
`SuperviseStrategy`, `CommandPlan`, the Stage 7 fake executable.

- [ ] **Step 1: Focused RED.** The supervised matrix module (§9.4), the Windows
  suites (§10 table, one test per row) and the seam pins, for example:

```python
@pytest.mark.parametrize("entry", SCENARIOS, ids=scenario_ids(SCENARIOS))
def test_every_stage_six_row_passes_through_the_production_supervisor(
    tmp_path, entry
) -> None:
    harness = build_harness(
        tmp_path,
        entry.adapter_name,
        limits=entry.limits,
        seed=f"task8-{entry.adapter_name}",
        letter_leading_token=entry.letter_leading_token,
        supervise=ProductionSupervision(cancellation_grace_seconds=1),
    )
    if entry.adapter_name == "fake.stale-attempt-result":
        command_run = drive_stale_attempt(
            harness, entry
        )  # the merged _stale_attempt sequence
    else:
        command_run = harness.drive(
            entry.adapter_name,
            entry.command,
            timeout_seconds=entry.timeout_seconds,
            cancel_after_first_heartbeat=entry.cancel_after_first_heartbeat,
        )
    assert_stage_six_expectation(
        harness, command_run, entry
    )  # the four modules' per-kind assertions, re-implemented locally
    identity = command_run.command_result.invocation.pid_identity
    if isinstance(
        identity, ProcessIdentity
    ):  # never `is not MISSING` on a typed field (§2.6)
        parse_creation_identity(identity.creation_identity)
    clean = (
        entry.invocation_state is CommandInvocationState.EXITED
        and entry.primary_code is None
        and entry.secondary_codes == ()
    )
    if clean:
        assert not {d.error_code for d in command_run.command_result.diagnostics} & set(
            STAGE7_DIAGNOSTIC_CODES
        )


def test_the_default_strategy_is_the_stand_in_and_the_harness_keeps_one_popen(
    tmp_path: Path,
) -> None:  # in tests/contract/test_harness_safety.py
    assert (
        build_harness(
            tmp_path, "fake.conformant", limits=PROTOCOL_LIMITS_DEFAULT, seed="seam"
        ).supervise
        is None
    )
    (call,) = _popen_calls(
        ast.parse(_HARNESS_PATH.read_text(encoding="utf-8"))
    )  # that module's own constant and helper
```

  plus: `test_the_merged_fake_still_refuses_every_stage_seven_name` (the merged
  `fake_adapter.py`, launched by the production supervisor under each
  `SUPERVISION_SCENARIOS` name, ends `EXITED` with native exit `10`, so the
  `KNOWN_ADAPTER_NAMES` rebinding is proven process-local; its entry is built with
  `supervised_catalog_entry_for(name, script=FAKE_ADAPTER_PATH)`); one test per §10
  row; the seam pins. **Test helpers** (in `supervised_strategy.py` unless noted):
  `drive_stale_attempt(harness, entry) -> CommandRun` (a local re-implementation of
  the private `_stale_attempt` sequence of `tests/contract/test_validate_contract.py`
  over the production strategy); `assert_stage_six_expectation(harness,
  command_run, entry)` (the four Stage 6 contract modules' per-kind assertions,
  re-implemented locally, plus `assert_token_absent((*outcome.trace,
  outcome.protocol_summary, outcome.executable_observation), token)` over
  `command_run.supervision_outcome` on every validate and run row, and the row-26
  two-form tolerance of §9.4); `scenario_ids` imported from `contract.scenarios`;
  `_popen_calls` and `_HARNESS_PATH` are `tests/contract/test_harness_safety.py`'s
  own, which is where the seam pin lives.

- [ ] **Step 2: Confirm RED** (`ModuleNotFoundError` for the strategy and the
  fake; the importer count at 10).
- [ ] **Step 3: Minimum GREEN.** The fake (its own tables and `main()`, the
  single `KNOWN_ADAPTER_NAMES` rebinding before `load_request`, §9.1), the doubles,
  the seam, then the matrix and the Windows suites; measure durations with the run's own timing
  and record them in the task's completion evidence.
- [ ] **Step 4: Focused GREEN.** `tests\contract tests\integration tests\safety -q`.
- [ ] **Step 5: Quality gates, Schema and migration preservation, Security and
  boundary review, Independent review, Commit, Clean-worktree checkpoint.**

**Broader tests.** `tests\unit tests\contract tests\integration tests\safety`;
then `pytest-all` in the background and alone.
**Windows-specific tests.** The whole §10 table plus the 58 matrix entries on the
production path.
**Quality gates.** `ruff-format-all` (apply the printed diff by hand), `ruff-check-all`, strict `mypy-all` over `src`, `tests` and `scripts`, `schema-generate-check`; strict mypy covers the new fake script and the strategy.
**Schema and migration preservation.** `schema-generate-check` clean on the unchanged 35-entry
registry; `git diff --stat -- schemas/` empty; no `persistence` content.
**Security and boundary review.** The new fake's `Popen` is a list argv with
`shell=False` and carries `# noqa: S603 - reviewed fixed interpreter boundary`
(the Stage 7 guard pins the `noqa` text beside the call, as the harness-safety
precedent does); the fake reads no ambient variable except to echo its key list;
the raw token appears only in the request file, the wire lines and the manifest
under the per-invocation root; every real-process test terminates what it
launched; no supervision root outside `tmp_path`; the harness keeps one `Popen`.
**Independent review.** Declared readings: §2.5 items 2, 11 and 21; the five
tamper vectors staying on the stand-in; the tolerated row differences of §9.4.
**Commit message.** `feat: drive the fake-adapter matrix and windows platform cases through the supervisor`
**Clean-worktree checkpoint.** As stated above; `STAGE7_IMPLEMENTATION_COMMIT` is
this commit.

### Task 9 — Stage 7 boundary guard, documentation and Stage 7 status

**Files created.** `tests/safety/test_stage7_boundaries.py`.
**Files modified.** `tests/safety/test_stage3_boundaries.py`,
`tests/safety/test_stage5_boundaries.py`, `tests/safety/test_stage6_boundaries.py`,
`tests/safety/test_gitnexus_development_tooling.py` (the status pins of §2.6),
`README.md`, `docs/development/verification.md`,
`docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md`. This task creates
no source module and releases no name.
**Interfaces consumed.** Tasks 1–8 output; the Stage 3 and Stage 5 scanner
helpers.
**Interfaces produced.** The Stage 7 safety guard; the documentation and roadmap
status.

- [ ] **Step 1: Focused RED (guard).** `tests/safety/test_stage7_boundaries.py`:
  `STAGE7_SOURCE_FILES` exactly the twelve §2.6 paths and each a file; the
  per-module import-root confinement of §2.6 (each of the five roots imported
  only by its named modules, and by none of the other source modules); the
  filesystem scan over the pure modules and a narrower scan over `roots.py`,
  `windows_api.py`, `windows_process.py` (no `os`, `sys`, `shutil`, `tempfile`,
  `stat`, `io`, `glob`, no `Path.cwd/home/expanduser`); the AST pin on the one
  `Popen` call (its `creationflags` a `BinOp(BitOr)` of the attribute
  `subprocess.CREATE_NEW_PROCESS_GROUP` and the name `CREATE_SUSPENDED`, whose
  `models.py` binding is the literal `4`); `process_supervision` imports no `experiments`, `configuration`,
  `persistence`, `cli` or test-tree root; `experiments` imports no
  `process_supervision`; the Stage 7 fake's roots exactly `{argparse, fake_adapter,
  json, os, signal, subprocess, sys, time}`, its single `sys.path.insert`, its
  single `KNOWN_ADAPTER_NAMES` rebinding statement, its list-argv `Popen` with its `# noqa: S603` text; the word "sandbox" in `process_supervision` only inside the
  package docstring's negative sentence; no Stage 7 module docstring contains the
  purity-scan substrings; the roadmap Stage 7 completion row, the Stage 8 deferred
  row, the "Approved detailed implementation plan" line for this plan's path and
  the negative of its "Planned" form; every scan with a planted-violation control.
- [ ] **Step 2: Focused RED (status).** The §2.6 successors in the Stage 3, 5, 6
  and GitNexus guards, written against the intended prose.
- [ ] **Step 3: Minimum GREEN.** The guard; README (`Stages 1-7 complete`, the
  Stage 7 paragraph of §9.6, a "Stage 7 adds ..." clause in the long paragraph);
  `docs/development/verification.md` (Stage 7 focused checks, the Stage 7 status
  block, the rewritten Stage 6 launch paragraph, the `subprocess` importer count);
  the roadmap (status line, plan sentence, Stage 6 row clause, Stage 7 completion
  row with `STAGE7_IMPLEMENTATION_COMMIT`, Planned → Approved).
- [ ] **Step 4: Focused GREEN.** `tests\safety tests\architecture tests\unit
  tests\contract tests\integration -q`.
- [ ] **Step 5: The complete unmodified `scripts/verify.ps1`, alone.**
- [ ] **Step 6: Quality gates, Schema and migration preservation, Security and
  boundary review, Independent review, Commit, Clean-worktree checkpoint.**

**Broader tests.** The complete verifier.
**Windows-specific tests.** The complete verifier's `pytest-all` runs every Windows
suite of Task 8 once more, alone.
**Quality gates.** `ruff-format-all` (apply the printed diff by hand), `ruff-check-all`, strict `mypy-all` over `src`, `tests` and `scripts`, `schema-generate-check`, plus `build`, `schema-distribution` and `git diff --check`.
**Schema and migration preservation.** `schema-generate-check` and
`schema-distribution` on the unchanged 35 files; no `persistence` content.
**Security and boundary review.** No prose claims a sandbox, persistence,
finalization or Stage 8 work; the README and guide keep every Stage 3–6 pin;
the `subprocess` importer prose matches the guard.
**Independent review.** Every documentation pin byte-exact against the guard
constants (generate the prose from the constants); every roadmap cell.
**Commit message.** `feat: add stage 7 boundaries, documentation and status`
**Clean-worktree checkpoint.** As stated above; the roadmap records
`STAGE7_IMPLEMENTATION_COMMIT` (Task 8) and states that the guard, documentation
and status were added by this separate commit, which is not the implementation
hash.

## 13. Verification and acceptance

### 13.1 Commands

Focused, during red-green development (diagnostic only; `-o addopts=` disables
coverage); every target is a normalized repository-relative path under `tests/`,
the only shape the launcher's `pytest-focused` profile accepts:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\domain tests\unit\process_supervision -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\experiments tests\property -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\integration\process_supervision -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\contract tests\safety tests\architecture tests\integration -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\safety\test_stage7_boundaries.py tests\unit\test_schema_registry.py -q
```

Quality gates after every task: `ruff-format-all` (apply the printed diff by
hand), `ruff-check-all`, `mypy-all`, `schema-generate-check`.

Complete, before any completion claim, alone on the host (no other pytest, no
reviewer agent, no other Python child running — the Stage 4 strategy-hashing
properties flake their hypothesis deadline under load, and the Stage 7
integration suites launch real children), from a shell attached to a console
(the real-process interrupt tests assert that precondition, §10):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
```

The verifier is not modified. Stage 7 introduces no dependency, so no lock or
acquisition operation is required and none may be cited as evidence. Before every
long run, `tasklist` proves no orphan `python.exe` from an earlier fake-adapter
launch survives; a survivor is itself a Stage 7 defect to investigate before the
run, never to kill and forget.

### 13.2 Serial order that stays flake-free

Focused suites → the task's independent review (no pytest running) →
`pytest-all` alone → `scripts/verify.ps1` alone → commit → (Task 9 only)
fast-forward `main` → merged-`main` verifier alone. Reviewer agents and the
verifier never run concurrently.

### 13.3 Acceptance criteria

Stage 7 is complete only when all of the following hold with fresh offline
evidence:

1. `WindowsProcessSupervisor.invoke` drives every one of the 52 Stage 6 scenario
   rows (58 table entries) to the expectation matrix E records for the production
   path, with `assert_token_absent` (over the merged projections and, through the
   retained `supervision_outcome`, the trace, protocol summary and executable
   observation) and `assert_token_only_in_wire_material` green on every validate
   and run row, and the Stage 6 stand-in path stays green on the unchanged
   contract suites.
2. Every launch is the catalog's absolute executable followed by
   `argument_array(command)` exactly, `shell=False`, an empty environment block,
   `stdin` from the null device, an explicit `cwd`, `CREATE_NEW_PROCESS_GROUP |
   CREATE_SUSPENDED` (the local constant `4`) with the resume after the job
   assignment, and a Job Object with kill-on-close when attachable — proven by the launch
   specification tests, the harness safety pins and the Stage 7 guard's AST scan
   of the one `Popen` call.
3. Every row of the race matrix (§6.4) is exercised deterministically over the
   scripted controller, and rows 24–27 plus the new graceful, forced, grandchild,
   inheriting-grandchild and flood scenarios are exercised over the Windows
   controller with real
   children; no test produces `EXITED` without a reaped exit after EOF, and no
   test moves a run to a success state.
4. Every deadline mapping of spec 14.8 is demonstrated: describe, validate and run
   deadlines from `RUNNING`; `STARTING`-origin `START_TIMED_OUT`,
   `VALIDATE_TIMED_OUT` and `DESCRIBE_TIMED_OUT`; paired UTC/monotonic derivation
   and the remaining-interval rule after restart; heartbeats never extend a
   deadline.
5. Cancellation is idempotent (a second request is a no-op), graceful first (the
   cooperating fake exits `50` and the record's native exit is `50`), forced after
   the grace period (the ignoring fake dies with `FORCED_TERMINATION_EXIT_CODE`),
   immediate for a protocol rejection, an unowned pre-handoff child, an external
   winner and a pipe holder; a cancellation observed before `begin_start` never
   launches and still leaves a fully enriched record; an external run
   cancellation around the launch ends the invocation `CANCELLED` through the
   lifecycle's `resolve_external_winner` decision (alone beside a terminal run,
   coupled beside a cancelled experiment), and a refused terminal write is
   returned as the caller's `Failure` without any cancellation attempt.
6. Durable identity: every `RUNNING` record carries `windows:<pid>:<creation>`;
   `inspect` distinguishes the live matching process, a reused pid and an absent
   process; the grandchild scenario (both processes ignoring the interrupt, so the
   forced path runs) proves the tree is dead after termination, both with the job
   and, through the failing job factory, without it; the inheriting-grandchild
   scenario proves a pipe holder is terminated so the root's exit can complete.
7. Restart reconciliation handles every row of §8.5: each `CommandInvocationState`
   for each command kind, both launch-handoff crash sides, PID reuse, absent
   process before and after the deadline, cancelled experiment, terminal records
   with `cleanup_complete=false` for both `process_created` values, mixed
   invocation/run pairs — never `EXITED`, never success.
8. Exactly one enrichment per invocation (§6.6): the recorded native exit pair is
   never overwritten, cleanup facts are written once, and a lost enrichment swap
   leaves a reconciliation target rather than a second write
   (`test_a_lost_enrichment_swap_reloads_once_and_leaves_a_reconciliation_target`,
   Task 6).
9. Windows platform cases pass: paths with spaces and Unicode components for the
   supervision root, the copied launcher and script and the command root; long paths
   under detected support with the deterministic preflight rejection always
   running; reparse-point and junction rejection; argv preservation through
   `fake.argv-echo`; independent stderr limits per command kind; handle loss and
   open-handle cleanup failures reported as `PROCESS.CLEANUP_FAILED` with
   `cleanup_complete=false`.
10. Every closed-world guard of §2.6 holds at its reconciled value: 95 allowed
    source files, 34 deferred definitions, seven live mutation cases, 27 import
    roots each confined to its named modules, the Stage 5 infrastructure exemption
    naming exactly one module, the Stage 6 guard's seven fake-adapter roots
    unchanged and eleven `subprocess` importers, the merged scenario table at 58
    entries, and every documentation pin at its Stage 7 successor.
11. `schema-generate-check` passes on the unchanged 35-entry registry; every one
    of the 35 digests is byte-identical; no `persistence` content, migration tree
    or `RunManifest` exists.
12. `ruff-format-all`, `ruff-check-all`, `mypy-all`, `pytest-all`, `build`,
    `schema-distribution` and `git diff --check` are clean offline; the complete
    verifier reports branch coverage of at least the baseline percentage with
    exactly the two approved skips.
13. No source module reads `time`, `os.environ`, a wall clock or the environment;
    `subprocess` is imported by exactly `process_supervision/windows_process.py`;
    `ctypes` by exactly `process_supervision/windows_api.py`; `experiments` never
    imports `process_supervision`; `process_supervision` never imports
    `experiments`, `configuration`, `persistence`, `cli` or the test tree.

## 14. Rollback and completion

Each task ends in one commit, so any task is reverted with `git revert` of that
commit without touching another task; §2.6's guard edits travel in the same
commit as the module, name, root or fake-adapter change that trips them, so a
revert restores guard and source together. The highest-risk reversals are Task 1
(the `Clock` port change, which touches every clock double) and Task 8 (the
harness seam and the fake-adapter scenarios, which the Stage 6 suites share);
both are covered by the Stage 6 contract suites staying green on the stand-in
path. Task 8 is the implementation commit whose hash the roadmap records; Task 9
touches no source module, so reverting Task 9 alone returns the tree to a
complete implementation without its status prose.

Stage 1–6 test files edited, all only as §2.6 tabulates:
`tests/safety/test_stage3_boundaries.py` and `tests/unit/test_package_layout.py`
by every module-creating task (1–7) and the former also by Task 9;
`tests/architecture/test_package_import_boundaries.py` by Task 2;
`tests/safety/test_stage5_boundaries.py` (the `subprocess` exemption) by Task 4
and (the README status import) by Task 9; `tests/safety/test_stage6_boundaries.py`
(the eleventh importer) by Task 8 and (the Stage 7 status pins) by Task 9;
`tests/unit/domain/test_domain_ports.py`, `tests/unit/domain/test_time.py`,
`tests/unit/experiments/test_port_contracts.py` and `tests/doubles/experiments.py`
by Task 1; `tests/contract/harness.py` and `tests/contract/test_harness_safety.py`
by Task 8; `tests/safety/test_gitnexus_development_tooling.py` by Task 9.
`tests/fake_adapters/fake_adapter.py` and `tests/contract/scenarios.py` are not
edited.
`pyproject.toml`, `uv.lock`, `scripts/verify.ps1` and `scripts/invoke-uv.ps1` are
not modified, and no generated schema is touched.

Stage 7 is complete when every criterion of §13.3 holds, the worktree is clean
and committed, the roadmap status table records `STAGE7_IMPLEMENTATION_COMMIT`
(the Task 8 commit, the last commit that adds Stage 7 behaviour) together with the
statement that the guard, documentation and status were added by the separate
Task 9 commit, README states "Stages 1-7 complete" and "Stage 8 has not started.",
and `docs/development/verification.md` records the Stage 7 focused checks and
"Stage 8 is not started." No persistence implementation, artifact finalizer or
`RunManifest` exists anywhere in the tree.

The planning task that produced this document ends with the token
`STAGE7_PLAN_COMPLETE_AND_MERGED` only after the plan is reviewed, the unchanged
verifier passes on the plan commit and on the fast-forwarded `main`, and Stage 7
implementation has not begun.
