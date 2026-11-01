# Project 1 Stage 9 — Artifact Finalization, Recovery, Provenance and Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** Detailed implementation plan for Stage 9. Implementation status is
recorded only in the master roadmap status table, never in this header, so the
header cannot go stale.
**Planning base:** `079395bec70f1deda406d0ca14b2d4bf79aaf063` (`main` = `HEAD` = merge base)
**Prerequisites:** Stages 1–8 complete and merged
**Goal:** Implement the artifact lifecycle the earlier stages deliberately left
open: strict `CandidateArtifact` and `ArtifactRef` records that can never
substitute for one another; `RESULT` and `EVIDENCE` finalization under
disjoint lease and idempotency identities; separate candidate and finalized
repositories; owner/purpose/producer/role cross-validation over the six
existing owner variants; path confinement with reparse-point, junction and
hard-link defenses rechecked immediately before hashing and moving;
independent streaming SHA-256 and exact-byte raw-token scanning; canonical,
content-hashed artifact manifests and the core `RunManifest`; same-volume
atomic moves into a content-addressed store; a purpose-tagged
`PREPARED`/`MOVED`/`REGISTERED` finalization journal with crash recovery at
every point; the artifact half of startup reconciliation; the normalized
result provenance and metric contracts; diagnostic causal chains for the new
`ARTIFACT.*`/`SECURITY.*` findings; bounded JSON Lines logs; an append-only
audit table and sink; and the post-run raw-token absence scans — all proven
over the Stage 8 SQLite persistence and the Stage 7 supervisor with the fake
adapters. The stage commits the first `SUCCEEDED`/`SUCCEEDED_WITH_WARNINGS`
run state in the project, and only through a registered `RunManifest`. It
does **not** relabel failed results as evidence, finalize unsanitized stdout,
raw-token input, original adapter-result candidates, quarantined or corrupt
bytes, integrate a real engine, add any network, telemetry, dashboard or
cloud feature, add a dependency, or change a schema outside the owned
artifact/manifest/provenance/diagnostic/audit scope. CLI composition,
startup-order ownership and the user-facing retention command remain Stage 10.
**Architecture:** `crypto_lab.artifacts` (models, requests, journal, manifest,
paths, hashing, validation, store, ports, finalizer, recovery, diagnostics)
and `crypto_lab.audit` (models, redaction, correlation, jsonl, sink) import
`crypto_lab.domain` only (spec 27.1). The purpose-specific registration that
needs adapter and experiment types (`RunManifest` over `RunProvenance`, the
run success compare-and-swap, the evidence producers over `StderrCapture`,
`RunEvent`, `ManifestParse`, `DescriptorParse`) lives in three new
`crypto_lab.experiments` modules (`run_manifest`, `finalization`,
`comparison`), which import `artifacts` and `audit` abstractions as 27.1
permits. `crypto_lab.persistence` gains the eight relational increments, one
Alembic revision `r0002_stage9_artifacts`, the codecs and repositories for
them, the SQLite audit sink and an in-transaction diagnostic writer, and
`SqliteTransaction` satisfies the new `FinalizationUnitOfWork` port
structurally; the Stage 5 `experiments.UnitOfWork` protocol keeps its six
members. `process_supervision`, `adapters`, `domain`, `capabilities`,
`strategy`, `configuration` and `datasets` are not edited except `domain`
for the owned contracts (identifiers, hashing profiles, metrics, normalized
records, the `finalization_deadline_utc` validator). Composition into the CLI
is Stage 10; Stage 9 composes the production supervisor, the operations, the
finalizer and the SQLite persistence in the test-resident
`SupervisedSqliteFlow` extension only.
**Tech stack:** Python 3.12, Pydantic v2 strict models, SQLAlchemy 2.x Core
over the Stage 8 declarative metadata, Alembic (one new revision), the stdlib
`hashlib`, `pathlib` and — in exactly one module — `os` (`fstat`, `fsync`),
`hypothesis` for the bounded properties, the unchanged closed
`scripts/invoke-uv.ps1` launcher (21 operations, no new profile) and the
unchanged `scripts/verify.ps1` (eleven steps). No new dependency.
**Spec:** `docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md`
(sections 10.2–10.4, 11.3–11.5, 14.5, 14.7–14.8, 15.5–15.7, 17.2–17.3, 18.3,
19–21, 22.5, 23.3–23.4, 28.1–28.5, 29–30, 33.2, 33.4, 33.5, 33.6 and 33.7 per
the roadmap's Stage 9 row, roadmap line 246; sections 1–9, 24, 27, 31–32 and
34 as the global floor, roadmap line 21).

## Global Constraints

- Python `>=3.12,<3.13`; runtime dependencies stay exactly the four entries
  `alembic`, `pydantic>=2.12,<3`, `pyyaml>=6.0.3,<7` and `sqlalchemy`
  (`tests/safety/test_project_dependencies.py:150`); `pyarrow`, `pandas`,
  `polars` and `numpy` stay prohibited families (27 families, `:209`). No
  development-group change, no `[tool.mypy]` override, no new pytest marker,
  no new approved skip (the two stay exactly two:
  `tests/safety/test_uv_launcher.py:928` symbolic-link privilege and
  `tests/unit/experiments/test_experiment_service.py:811` same-state replay;
  `test_uv_launcher.py:1312` is an `importorskip` site that cannot skip).
- Every command runs through `scripts/invoke-uv.ps1` profiles. The launcher
  gains **no** profile (`_EXPECTED_OPERATIONS` stays 21,
  `tests/safety/test_uv_launcher.py:498`) and `scripts/verify.ps1` gains **no**
  step (eleven, `tests/safety/test_stage8_boundaries.py:949`); the post-run
  raw-token scans are tests, not profiles. `_EXPECTED_VERIFIER_SHA256` and
  `_EXPECTED_NORMALIZED_SHA256` are untouched.
- Branch coverage floor stays 90 percent in `pyproject.toml` (`:96`, `:105`);
  the complete verifier must report at least **98.61 percent branch coverage**,
  the value measured on the planning base (the predecessor convention of the
  Stage 7 and Stage 8 plans, not the Stage 8 requirement of 98.42 carried
  forward): the accepted merged-`main` run `20261031-165647-105036`
  reported 9353 passed, 2 skipped of 9355 collected, 887.36 s, 98.61 percent
  (controller checkpoint line 157), and the branch run on the same bytes
  938.73 s, 98.62 percent (commit `079395b` body); every new `artifacts`, `audit`,
  `experiments` and `persistence` module counts.
- Canonical schemas: the 35 published files stay byte-identical (the four
  digest blocks of `tests/unit/test_schema_registry.py:2799-3977` are never
  edited); Stage 9 appends exactly 19 entries after position 35 (§3.2), each
  one an artifact, manifest, provenance, diagnostic or audit contract under
  roadmap line 264, in the order §3.2 fixes; `HashingProfile` grows from 12 to
  20 by named versioned profiles only (§3.2; 10.2:462); the new `ARTIFACT.*`,
  `SECURITY.*` and `AUDIT.*` codes are admitted by the existing open
  `ErrorCode` pattern (`src/crypto_lab/domain/diagnostics.py:72`);
  `DiagnosticCategory` stays 12. Every task runs `schema-generate-check` and
  proves the 35 Stage 3–6 digests unchanged and the Stage 9 files equal to
  their rendered bytes.
- Relational migrations: exactly two Alembic revisions exist at the end of the
  stage, `r0001_stage8_baseline` (never edited) and its single successor
  `r0002_stage9_artifacts` (Task 5), the script directory has exactly one head,
  the mapped metadata and the migrated database agree, and every new table or
  column is one roadmap line 263 names ("artifact, reference, manifest,
  journal, provenance, diagnostic, audit, and recovery increments"): eight
  tables (§3.3) and one nullable `engine_runs.finalization_deadline_utc`
  column with its index (reading 9). No existing column is altered or dropped;
  no table is rebuilt.
- Dependency direction (spec 8, 27.1): `crypto_lab.artifacts` and
  `crypto_lab.audit` import `crypto_lab.domain` and themselves only;
  `crypto_lab.experiments` additionally imports `crypto_lab.artifacts` and
  `crypto_lab.audit` (the port, model and finalizer modules; never
  `persistence`); `crypto_lab.persistence` additionally imports
  `crypto_lab.artifacts.models/journal/manifest` and `crypto_lab.audit.models/sink`
  (exactly the five modules Task 5 adds to the Stage 8 `_PERSISTENCE_FAMILIES`;
  it satisfies the Task 6 `FinalizationUnitOfWork` and `RegistrationUnitOfWork`
  ports structurally and never imports `artifacts/ports.py`); `process_supervision`, `adapters`,
  `domain`, `strategy`, `capabilities`, `datasets` and `configuration` import
  neither new package. The Stage 3 import-root allowlist grows by exactly `os`,
  confined to `artifacts/store.py` and to the two attributes `fstat` and
  `fsync` (§2.6); `stat`, `shutil`, `tempfile`, `io`, `errno`, `logging`,
  `time`, `secrets`, `random`, `threading`, `asyncio`, `ctypes`, `queue`,
  `subprocess` and `types` appear in no new module; `async def finalize` is
  written without importing `asyncio`.
- Storage contract (spec 19.2, 22.5, 23.3.1, 29.1): the content-addressed
  finalized store lives under the caller-supplied absolute `artifacts_root`,
  staging under the caller-supplied `runtime_root` (the Stage 7 command roots
  for adapter candidates, `<runtime_root>/staging/<owner_hash>/...` for core
  evidence), quarantine under `<runtime_root>/quarantine/`; the finalizer
  refuses to construct when the two roots differ in volume identity, are
  network shares or reparse points (22.5 preflight, §6.1); no database
  transaction is open across hashing, scanning or a move — the journal
  protocol of §4.3 is four short transactions with filesystem work between
  them and the test harness measures `max_open == 0` during those phases;
  `Path.rename` is the only move primitive (it refuses an existing target on
  Windows, so finalized content is never overwritten); nothing in `artifacts`
  or `audit` reads configuration, the environment, the current directory or
  a home directory.
- Trust (spec 14.7, 15.5, 24.1, 24.3): adapters supply only candidate files
  and the temporary `AdapterResultManifest`; owner, purpose, source role,
  finalized path and every identity are core-selected; every candidate is
  hashed and scanned for the raw token by the core before `PREPARED` and
  re-hashed after the move; the raw token reaches the scanner only as the
  existing `AttemptTokenMaterial` carrier read from surviving request
  material and never as a new annotated field (`_ATTEMPT_TOKEN_CARRIERS`
  stays four); the token is never a column, a JSON snapshot member, a log
  field, an audit detail or a manifest field; Decimal stays canonical text;
  timestamps stay integer microseconds in rows and `Z` strings in JSON;
  `NULL` encodes exactly one `MISSING` per column.
- No real engine, adapter, exchange, market data, backtest, network,
  credential, wallet, tax, UI, LLM, Docker, cloud or server behavior anywhere;
  no converter that produces normalized records (the contracts exist, no
  producer); no Parquet reader or writer; no daemon, scheduler or service;
  GitNexus stays `DISABLED_WITH_EVIDENCE` (`tools/gitnexus/outcome.json:4`)
  and is never invoked; no network during verification.

---

## 1. Goal, scope and exclusions

### 1.1 Goal

Stages 6–8 stop exactly at the finalization boundary: `apply_command_semantic_outcome`
leaves a `RESULT_FINALIZATION_ELIGIBLE` run `RUNNING` "for Stage 9" and
builds no success state (`src/crypto_lab/experiments/semantic_outcome.py:1-60`,
steps 5 and 7); `reconcile_run` maps that verdict to no run target
(`src/crypto_lab/adapters/reconciliation.py:212`); the artifacts package owns
ownership only (`src/crypto_lab/artifacts/__init__.py:1`); the audit package
is one docstring (`src/crypto_lab/audit/__init__.py`); no production code
computes a `CandidateObservation` (constructors exist only in
`tests/contract/harness.py:1362` and `tests/persistence_support/supervised.py:265-278`);
`finalization_deadline_utc` has no column (`src/crypto_lab/persistence/codecs.py:38`)
and the domain validator rejects every present value
(`src/crypto_lab/domain/engine_run.py:303-308`). Stage 9 closes that
boundary with the contracts, filesystem discipline, journal, recovery,
provenance and audit of spec sections 19–21, 23.3.1, 29 and 30, proven by the
roadmap's eleven required test categories, and leaves the tree in a state
where Stage 10 only wires commands.

### 1.2 In scope

| Area | Stage 9 delivers | Owning task |
|---|---|---|
| Artifact canonical contracts | `CandidateArtifactState`, `CandidateArtifactProducerKind`, `ArtifactFinalizationPurpose`, `ArtifactSourceRole`, `ArtifactOwnerKind` (enum beside the existing per-class literals), `CandidateArtifact`, `ArtifactRef`, `CandidateFinalization`, `FinalizationResult`, `ResultFinalizationRequest`, `EvidenceFinalizationRequest`, `EvidenceCorrelation`, `ArtifactManifest`, `FinalizationJournalEntry`; the identities `FinalizationId`, `RunManifestId`; five of the eight hashing profiles; eight generated schemas | 1 |
| Audit and log contracts | `AuditEvent`, `AuditAction`, `AuditActor`, `AuditOutcome`, `LogRecord`, `LogSeverity`; field-level redaction; the correlation context; the bounded rotated JSON Lines writer; the `AuditSink` and `AuditEventIds` ports; two generated schemas | 2 |
| Metric and provenance contracts | `MetricValue` (with `MetricValueType`, `MetricStatus`), `NormalizedResultProvenance` (the twelve items of 20.2), `RunManifest` and `run_manifest_hash`; three generated schemas; `ComparisonEligibilityService.evaluate(left, right, requested_level)` over two manifests | 2 (metric), 7 (manifest, service) |
| Normalized result records (conditional: Task 3 runs only after the §1.6 item 1 confirmation is recorded) | `CanonicalOrder`, `CanonicalFill`, `Fee`, `PositionSnapshot`, `PortfolioSnapshot`, `EquityPoint`, `OrderSide`, `OrderType`, `PositionEffect` as strict records with provenance; six generated schemas; no producer, no accounting logic | 3 |
| Paths, hashing, validation, store | lexical and physical confinement (`confine_candidate_path`, reparse/junction/hard-link/alternate-data-stream rejection, TOCTOU recheck), `ContentHasher.sha256_stream`, the streaming exact-byte token scan with chunk-boundary carry, candidate validation (owner, purpose, producer, role, path, size, media, schema, redaction), the content-addressed store layout, `atomic_move`, `quarantine_move`, the same-volume preflight | 4 |
| Relational increments | `candidate_artifacts`, `artifact_refs`, `run_artifacts`, `run_manifests`, `finalization_journal`, `audit_events`, `sanitized_adapter_result_manifests`, `adapter_validation_results`; `engine_runs.finalization_deadline_utc` plus index; the trigger set of §3.4; revision `r0002_stage9_artifacts`; codecs; `SqliteCandidateArtifactRepository`, `SqliteArtifactRepository`, `SqliteFinalizationJournalRepository`, `SqliteRunManifestRepository`, `SqliteSanitizedManifestRepository`, `SqliteValidationResultRepository`, `SqliteAuditSink`, `SqliteDiagnosticWriter`; the `finalization_deadline_utc` admission in domain, codec and repository | 5 |
| Finalizer | `ArtifactFinalizer` protocol and `CoreArtifactFinalizer`: the four-transaction journal protocol, purpose-specific lease/identity acquisition, deadline snapshot and enforcement, RESULT/EVIDENCE branches through the `PurposeRegistrar` port, idempotent replay, the fault probe hook for crash-point tests | 6 |
| Recovery and retention | `reconcile_finalization` (29.2 steps 4, 6, 7-artifact, 9), RESULT recovery under 29.3 through the `ResultRecoveryValidator` and `PurposeRegistrar` ports (their production implementations are Task 7's, so the RESULT success cells are proven in Task 7, §5 intro), EVIDENCE recovery under 29.4, orphan/mismatch/unregistered-content quarantine, raw-byte cleanup at lease close (14.7), the audited `purge_quarantine` operation, the 24 h overdue check | 6 |
| Application integration | `experiments/finalization.py`: request construction from `SemanticOutcome` and the `CommandResult`, parse and path facts the caller destructures from `SupervisionOutcome` and `CommandPaths` (`experiments` never imports `process_supervision`), pre-verdict production `CandidateObservation` computation (`observe_candidates`, §4.4 step 0) and the `fail_run_for_refusal` path, `register_result_candidates` (the `RUN` owner and the adapter-declared `CANDIDATE` rows, §4.4 step 2), the RESULT registrar (RunManifest, run links, sanitized facts, success CAS, over the `RegistrationUnitOfWork` port), the `ResultRecoveryValidator` (the 29.3 checks over the temporary manifest), the post-success replay wrapper `semantic_outcome_or_replay` (reading 24), the EVIDENCE producers (sanitized stderr, protocol capture, sanitized adapter-result manifest, sanitized validation result, descriptor evidence, diagnostic report), `conclude_describe` (the `DESCRIBE` counterpart of `conclude_command`: the two describe producers under the `ADAPTER` owner, no run row, no close — §4.6), `stderr_artifact_id` enrichment, stderr-truncation audit, adapter diagnostic persistence with the `DiagnosticId` minting rule | 7 |
| Composition and scans | `SupervisedSqliteFlow` extended with `finalize(row, outcome)`, `recover()`, `scan_for_token(token)`; the success, warning, failure, cancellation, finalization-timeout, crash-point and recovery rows over the production supervisor and SQLite; post-run raw-token absence over the database file, WAL, logs, audit, diagnostics, evidence and every finalized artifact | 8 |
| Status | the Stage 9 boundary guard, documentation and roadmap status | 9 |

### 1.3 Out of scope

| Excluded | Reason | Owner |
|---|---|---|
| CLI commands, composition root, configuration loading at startup, the startup order of 29.2 steps 1–3, 5, 8, 10, the reconciliation lease | Stage 10 deliverables (roadmap lines 272–276; Stage 8 plan 180, 198) | Stage 10 |
| A converter producing normalized records; Parquet containers; `pyarrow` | No converter exists in Project 1 (11.4:590 mapping documentation presupposes one); a Parquet dependency is a prohibited family; the records and provenance exist, their producer does not (reading 6) | Project 2 converter plan |
| Audit emission inside the Stage 4/5 operations and the composition (strategy/dataset registration, experiment transitions, retry decisions, migration application, the process half of reconciliation, the retention-limit configuration snapshot; 30.3 bullets 1–6, 8, 10 (migration and process halves), 11, 12) | Stage 8 plan 197 assigns them to "Stage 10 composition, or Stage 9 if it widens the operation"; Stage 9 widens no Stage 5 operation (reading 14) | Stage 10 |
| `PROCESS.PID_REUSE_DETECTED` on a live `RUNNING` invocation | A process-supervision finding, not an artifact one (Stage 8 plan 176: "Stage 9 or a corrective plan") | corrective plan or Stage 10 |
| Diagnostic-reference foreign keys from `engine_runs`, `command_invocations`, `retry_decisions`, `diagnostics` | Requires rebuilding Stage 8 tables (SQLite cannot add a constraint in place); the `dangling_diagnostic_references()` control stays (Stage 8 plan 191); escalated in §1.6 item 4 | corrective plan |
| Retention/deletion/export/backup **commands** and the backup checkpoint of 29.5:2194 | Stage 8 plan 184 "Later"; Stage 9 ships the audited `purge_quarantine` operation and the lease-close cleanup, Stage 10 wires the command | Stage 10 / later |
| A log console projection, dashboard, evidence-bundle renderer | 30.1 "projection", 30.5 "future local command" | Stage 10 or later |
| Relabeling failed results as evidence; finalizing unsanitized stdout, raw-token input, the original adapter-result candidate, quarantined or corrupt bytes | roadmap line 252 exclusions; every one is a negative test of §5 | never |

### 1.4 Named forward obligations

Stage 10's control row grants **no** relational and **no** canonical schema
change (roadmap lines 287–289), so anything with schema impact that Stage 9
leaves open returns only through an approved corrective plan. That is why
§1.2 includes `adapter_validation_results`, the normalized record family and
the deadline column rather than deferring them.

| Omission | Reason | Closed by |
|---|---|---|
| Diagnostic-reference foreign keys (Stage 8 plan 191) | table rebuild; §1.6 item 4 | corrective plan with a zero-dangling precondition |
| Production producers for `DATASET`, `STRATEGY`, `EXPERIMENT` and `SYSTEM` evidence (dataset manifests, strategy snapshots, frozen configuration snapshots carrying `configuration_audit_hash`, core projections) | the finalizer and validation are owner-generic and tested for all six variants through the production `stage_core_evidence` entry point; the callers that choose to emit those snapshots are command compositions (reading 7) | Stage 10 |
| Audit emission inside Stage 4/5 operations | reading 14 | Stage 10 |
| Production projection of `SupervisionTraceEntry` into audit events (Stage 7 plan 153) | `experiments` may not import `process_supervision` and `process_supervision` may not import `audit` (27.1; `tests/architecture/test_package_import_boundaries.py:110-135`), so the projection belongs to the composition root; Task 8's test support performs it over the trace the supervisor already returns | Stage 10 |
| `PROCESS.PID_REUSE_DETECTED` on a live `RUNNING` invocation | process half | corrective plan or Stage 10 |
| Startup order, reconciliation lease, requeue | 29.2 steps 1–3, 5, 8, 10 | Stage 10 |
| Retention command, backup checkpoint | Stage 8 plan 184 | Stage 10 / later |
| Normalized record **producer**, Parquet | reading 6 | converter plan |
| Log console projection, evidence bundle | 30.1, 30.5 | Stage 10 |
| Physical confinement of dataset paths (R18.3-01, 18.3:1321 "the same containment and reparse-point defenses as artifacts") | the lexical half exists (`src/crypto_lab/datasets/models.py:111-135`); the physical half runs where a dataset file is opened, which is the dataset-ingest producer — no such producer exists in Project 1 (`input_snapshot_evidence` receives caller-supplied bytes, §4.6) | Stage 10 or the converter plan |
| An artifact correction operation (R19.1-18, operation half) | `artifact_refs` is insert-only, so a correction is structurally a new reference whose lineage names `superseded_artifact_id` (reading 25); no Stage 9 command corrects an artifact | Stage 10 or later |
| Retention limits snapshotted in audit events (R30.1-03 second clause; 30.3 bullet 12) | TOML is loaded only by the Stage 10 composition (§1.3 row 1); the Stage 9 writer receives `retained_files` as a value (reading 15) | Stage 10 |

### 1.5 Carried notes and dispositions

1. (O-1) Stage 8 plan 173, 192 — tables `candidate_artifacts`, `artifact_refs`,
   `run_artifacts`, `run_manifests`, `finalization_journal`, `audit_events` and
   the canonical `CandidateArtifact`, `ArtifactRef`, `RunManifest`,
   `AuditEvent`. **OWNED BY TASKS 1, 2, 5, 7.**
2. (O-2) Stage 8 plan 174 — `adapter_validation_results` and
   `sanitized_adapter_result_manifests` ruled Stage 9's. **OWNED BY TASK 5**
   under reading 8.
3. (O-3) Stage 8 plan 175 — adapter-authored `AdapterDiagnostic` values as
   `Diagnostic` rows need a `DiagnosticId` minting rule. **OWNED BY TASK 7**:
   `DIAGNOSTIC_IDENTITY_V1` over `(invocation_id, sequence, ordinal, code,
   category)` (reading 16).
4. (O-4) Stage 8 plan 176 — PID reuse on a live `RUNNING` invocation.
   **RE-DEFERRED** (§1.3).
5. (O-5) Stage 8 plan 177 — `ExperimentAggregationResult.reason_codes` as audit
   material. **RE-DEFERRED** with reading 14: the aggregation operation is not
   widened; Stage 10 appends the audit event from the operation's returned
   result through the Stage 9 sink.
6. (O-6) Stage 8 plan 181, 195 — nullable `engine_runs.finalization_deadline_utc`
   and the validator/codec/repository admission. **OWNED BY TASK 5** (reading 9).
7. (O-7) Stage 8 plan 182, 1321 — the EVIDENCE/owner rule for
   `command_invocations.stderr_artifact_id`. **OWNED BY TASK 5** as the trigger
   `command_invocations_stderr_targets_core_evidence` (reading 10); no foreign
   key is added because that would rebuild the table.
8. (O-8) Stage 8 plan 191 — diagnostic-reference foreign keys.
   **RE-DEFERRED**, §1.6 item 4.
9. (O-9) Stage 8 plan 197 — persisting the minted diagnostics of
   `apply_command_semantic_outcome` inside the operation. **CLOSED BY DESIGN**:
   the operation is not widened; Task 7's `conclude_command` records every
   minted diagnostic through the Stage 8 recorder before the finalization or
   failure write that references it, and Task 8 asserts
   `dangling_diagnostic_references == 0` after every row.
10. (O-10) Stage 8 plan 184 — retention, deletion, export, backup. **PARTLY
    OWNED BY TASK 6** (the operation and lease-close cleanup) and otherwise
    RE-DEFERRED (§1.3).
11. (O-11) Stage 8 plan 595–598 — `artifact_owners` keyed by `owner_hash`; Stage
    9 may add a surrogate column. **CLOSED BY DESIGN**: every new table
    references `artifact_owners.owner_hash` directly; no surrogate.
12. (O-12) Stage 8 plan 312–318 — any Stage 9 configuration-snapshot artifact
    must carry the same `configuration_audit_hash`. **OWNED BY TASK 4/7 CONTRACT**:
    `stage_core_evidence` for an `EXPERIMENT` owner with role `EXPERIMENT_INPUT`
    requires `source_hash == ConfigSnapshot.configuration_audit_hash` of the
    frozen row (Task 8 exercises it from the frozen experiment).
13. (O-13) Stage 7 plan 153–157 — audit sink as a projection of
    `SupervisionTraceEntry`; `stderr_artifact_id` requires an EVIDENCE ref;
    `CandidateObservation` as production code; result-manifest recovery of
    15.6/29.3; raw-byte removal at command close. **OWNED BY TASKS 6, 7** (the
    close of §4.3 phase 6 runs inside `finalize` for leased RESULT outcomes,
    from `conclude_command` for every terminal outcome that takes no RESULT
    lease — §4.4 step 5 — and from `reconcile_finalization` step 9 as the
    sweep of §5.3 RV-8) except the
    trace projection, which is **RE-DEFERRED** to Stage 10 (§1.4): the
    supervisor is not edited, and Task 8's test support projects the returned
    trace into audit events through the Stage 9 sink so the sink contract is
    exercised with real supervision facts.
14. (O-14) Stage 6 plan 101–111, 1331–1338 — `RUNNING → SUCCEEDED*` only with a
    finalized RESULT plus `RunManifest`; `artifact_produced` creates only a
    candidate; byte-level candidate validation; the sanitized manifest and
    stderr finalized by Stage 9; the original `AdapterResultManifest` deleted
    after the lease. **OWNED BY TASKS 4–7.** The post-success replay answer
    (Stage 6 plan 111) is **OWNED BY TASK 7** (reading 24,
    `semantic_outcome_or_replay`).
15. (O-15) Stage 5 plan 50, 54, 533 — `ContentHasher.sha256_stream`; owner/purpose
    validation of `stderr_artifact_id`; the deadline snapshot. **OWNED BY TASKS
    4, 5, 6.**
16. (O-16) Stage 4 plan 1831–1846 — `ComparisonEligibilityService` over two
    `RunManifest`s. **OWNED BY TASK 7.**
17. (O-17) Verification guide 603 — "Stage 9 can snapshot it without changing the
    published `$id`". **CONSUMED BY TASK 5** (reading 9); the sentence is retired
    from the guide by Task 9 with its pin.
18. (O-18) Controller checkpoint open risks 1–5 (open-handle intermittent,
    positional skip attribution, `C:\Windows\Temp` unprobed, the WAL first-opener
    susceptibility, earlier failed runs standing). **CARRIED** into §9.2 and
    §9.3; none is closed by this plan.

### 1.6 Escalations and declared readings the user must confirm

Each item states the default this plan executes if the user confirms nothing
else; a refusal changes exactly the named task and nothing else.

1. **Normalized record family in Stage 9 (default: exclude; Task 3 runs only
   after a human confirmation is recorded in `.superpowers/sdd/stage9/`).**
   Spec 19.1:1327-1335 lists "canonical normalized orders, fills, positions,
   portfolio snapshots, equity series, and metrics" as artifact classes,
   11.3:579-584 gives their fields, and `RunManifest.metrics` (11.3:578)
   forces `MetricValue` (Task 2, unconditional). Roadmap line 264 permits
   "artifact, manifest, provenance, diagnostic, and audit contracts" and line
   34 confines canonical schema changes to the stage's named ownership
   boundary; reading the normalized records as artifact contracts (the typed
   content of `NORMALIZED_RESULT` artifacts) stretches that list, no Stage 9
   task imports `domain/normalized.py`, and Stage 10 cannot add them (line
   289) — so the plan ships them only on an explicit confirmation, never by
   default. Confirming adds Task 3 (one module, six schemas, nine released
   names); the §2.6 branch table carries both arithmetics, and every count in
   this plan is stated for the confirmed branch with the excluded value in
   that table. Excluding Task 3 moves the normalized half of
   R11.3-01/R11.3-09/R20.3-02 (`test_normalized_records.py`) to the converter
   plan (§1.4) and renumbers nothing. `_VERIFICATION_NON_GOALS` "portfolio
   accounting" stays true either way: records only, no balance arithmetic,
   no accounting operation.
2. **`finalization_deadline_utc` admission is behavior-only (default: yes,
   Task 5).** The published `engine-run-record-v1` already carries the optional
   property (guide 601–603); relaxing `_validate_finalization_deadline`
   (`engine_run.py:303-306`) to "present only while `RUNNING` with an active
   RESULT journal or in a terminal state reached from one" changes no byte of
   the schema, and the new column is the "recovery increment" of line 263.
3. **"RESULT finalization wins first" means the `REGISTERED` commit (default:
   yes).** Reading 1. The lease blocks other finalizers, not cancellation; a
   cancellation or timeout that wins between `PREPARED` and `REGISTERED` makes
   the registration compare-and-swap lose (the journal carries the expected
   run and invocation revisions), the journal is `ABANDONED`, the moved bytes
   are quarantined, and the run stays `CANCELLED`/`TIMED_OUT`.
4. **Diagnostic-reference foreign keys stay deferred (default: defer).** Adding
   them requires `batch_alter_table` rebuilds of `engine_runs`,
   `command_invocations`, `retry_decisions` and `diagnostics`; a destructive
   migration is a human decision outside this plan. The Stage 8 control query
   and Task 8's zero-dangling assertion after every row remain the evidence.
5. **`adapter_validation_results` is a manifest/provenance increment (default:
   include, Task 5).** It is the `VALIDATE` command's sanitized manifest
   analogue (23.3.1:1705 "immutable sanitized validation output", 19.1:1344
   "sanitized `AdapterValidationResult`" evidence). The default is include,
   unlike item 1, because the specification itself names the table
   (23.3.1:1705), the approved Stage 8 plan 174 assigned it to Stage 9 (O-2),
   and Task 7's `validation_result_evidence` writes it; the word "validation"
   is absent from line 263, so the confirmation or refusal is recorded in
   `.superpowers/sdd/stage9/` before Task 5 begins. A refusal removes the
   table, its trigger, codec and repository from Task 5 (21 → 20 tables,
   16 → 15 triggers, six → five repositories) and the table moves to a
   corrective plan; the sanitized validation result is still finalized as an
   EVIDENCE artifact either way.
6. **Project 1 has no normalized-result producer and no Parquet (default:
   yes).** `NORMALIZED_RESULT` candidates are accepted when a future converter
   produces them; in Stage 9 the role, provenance record, validation profile
   and schema exist and are tested with JSON fixtures; media type
   `application/vnd.apache.parquet` is an opaque byte type for
   `ENGINE_NATIVE_RESULT` candidates (size, hash, token scan; never parsed).
7. **Owner variants beyond `RUN` and `ADAPTER` are exercised through the
   production entry point with test-supplied bytes (default: yes).** No Stage
   9 command produces dataset, strategy, experiment or system evidence; the
   finalizer, validation, store, journal, recovery and tables are owner-generic
   and every variant is driven end-to-end through `stage_core_evidence` and
   `finalize` in Task 8 (28.3:2084 satisfied on the production path, not on
   test-only types).
8. **The 24-hour quarantine resolution is checked, not scheduled (default:
   yes).** `reconcile_finalization` and `purge_quarantine` compute the age of
   every quarantine entry from its audited creation instant; an entry older
   than `QUARANTINE_RESOLUTION_SECONDS = 86_400` records
   `ARTIFACT.QUARANTINE_OVERDUE` and an audit event; no daemon exists (7.2:203).
9. **Audit ordering authority is the durable append sequence (default: yes).**
   `AuditEventId` is a prefixed UUID4 (`identifiers.py:173-178`) and cannot
   order; `audit_events.audit_sequence` (`INTEGER PRIMARY KEY AUTOINCREMENT`)
   is the local ordering 30.2:2210 requires and is returned beside the id.
10. **The Stage 3 import-root allowlist gains `os` (default: yes).** Confined
    to `artifacts/store.py` and to `os.fstat` (handle identity for the TOCTOU
    recheck) and `os.fsync` (durability before `MOVED`); the
    `roots.isdisjoint({... "os" ...})` pin at
    `tests/unit/persistence/test_sqlite_database.py:1812` becomes a
    persistence-scoped assertion (no persistence module imports `os`) with the
    same strength, and Task 4 lands the tree-wide pin
    `test_os_is_imported_only_by_the_artifact_store` (exactly one `os`
    importer under `src/crypto_lab`) in the same commit, so no task between 4
    and 9 leaves the widening unconfined (the Stage 9 guard re-pins it).
11. **A thirteenth `subprocess` importer (default: yes).** One real
    child-process crash module (`tests/integration/artifacts/test_finalization_crash_child.py`)
    kills a finalizing child between `MOVED` and `REGISTERED` (CP-5) and with
    T3 open (CP-6); `_NUMBER_WORDS` gains `13: "thirteen"`, the Stage 7
    self-test advances to 14 and the Stage 8 parenthetical moves (§2.6).

## 2. Authority, consumed interfaces, readings and reconciliation

### 2.1 Authority order

1. The specification (`docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md`),
   sections of the header's **Spec** line.
2. The roadmap's Stage 9 row (lines 242–264), its Stage 10 row for the
   far boundary (lines 266–289) and the global rules (lines 18–30).
3. Committed source at the planning base as evidence of the consumed
   interfaces (§2.2); where source and specification disagree the
   specification wins and the disagreement is a reading (§2.5) or an
   escalation (§1.6), never a silent choice.
4. `AGENTS.md`, `docs/development/verification.md`, `README.md`, ADR 0001
   and the earlier stage plans for process, tooling and carried obligations.
GitNexus is `DISABLED_WITH_EVIDENCE`; the manual source, reference and diff
fallback applies throughout.

### 2.2 Consumed interfaces (existing, verified at the base)

<!-- consumed -->
| Symbol | Module | Exact contract consumed |
|---|---|---|
| `CanonicalModel` | `domain/base.py:12-21` | `extra="forbid", frozen=True, strict=True, validate_default=True`; every Stage 9 record inherits it |
| `canonical_json_bytes`, `canonical_json_text` | `domain/canonical_json.py:68-82` | sorted keys, compact, UTF-8 no BOM, no float, Decimal strings, `Z` timestamps |
| `HashingProfile`, `profile_hash`, `sha256_bytes`, `attempt_token_hash`, `candidate_artifact_id_for`, `_uuid4_shaped` | `domain/hashing.py:25-137` | twelve members at the base; `CANDIDATE_ARTIFACT_IDENTITY_V1` derives `cand_` ids from `(run_id, invocation_id, relative_path)`; the uuid4-shaping helper is reused for every derived id |
| `ArtifactId`, `CandidateArtifactId`, `AuditEventId`, `AdapterManifestId`, `Sha256`, `CorrelationId`, `NormalizedIdentifier`, `exact_string_schema`, `validate_prefixed_uuid4` | `domain/identifiers.py:14-42, 125-178, 212-222, 282-297` | prefixes `art_`, `cand_`, `audit_`, `amf_`; two new aliases follow the same helper |
| `Diagnostic`, `DiagnosticCategory`, `DiagnosticSeverity`, `ErrorCode`, bounds | `domain/diagnostics.py:32-128, 206-269` | `ARTIFACT_CORRUPTION`, `PERSISTENCE`, `SECURITY` categories exist; `ENGINE_RUNTIME/PROTOCOL/TIMEOUT/CANCELLATION` require `invocation_id`; `causal_diagnostic_ids` max 32, no self-cause |
| `EngineRunRecord`, `assert_run_transition`, `SUCCESS_ENGINE_RUN_STATES`, `AttemptTokenMaterial` | `domain/engine_run.py:148-150, 208-219, 230-247, 303-308, 442-446` | `(RUNNING, SUCCEEDED)`/`(RUNNING, SUCCEEDED_WITH_WARNINGS)` are permitted edges (`domain/lifecycle.py:241-242`); `finalization_deadline_utc` typed but rejected when present; `AttemptTokenMaterial.attempt_token` is the one domain token carrier |
| `CommandInvocationRecord`, `_ENRICHABLE_FIELDS`, `assert_write_once_enrichment` | `domain/command_invocation.py:215-243, 532-543, 704-710` | `stderr_artifact_id: ArtifactId | MISSING`, absent unless terminal, write-once |
| `Clock`, `IdentitySource`, `CancellationToken` | `domain/ports.py:37-90` | `now_utc()`, `monotonic()`; no artifact or audit id drawer; the token's docstring names `ArtifactFinalizer.finalize` as its hand-off |
| `ArtifactOwnerRef`, six variants, `artifact_owner_hash`, `owner_presentation`, `ARTIFACT_OWNER_ADAPTER` | `artifacts/ownership.py:50-150` | consumed unchanged; the published `artifact-owner-ref-v1` `$id` is frozen |
| `RunProvenance`, `CandidateArtifactDeclaration`, `CandidateMetric`, `AdapterValidationResult`, `validation_result_hash`, `AdapterResultManifest`, `ManifestParse`, `ValidationResultParse`, `SanitizedCandidateArtifactDeclaration`, `SanitizedAdapterResultManifest`, `sanitized_manifest_hash`, `sanitize_result_manifest`, `parse_result_manifest` | `adapters/manifests.py:242-270, 295, 339-380, 505, 645-682, 721, 767-830, 874-887, 1106` | the sanitized manifest "never authorizes finalization" (`:788`); its hash and the exact-byte source hash are the two manifest hashes of 17.2 |
| `CandidateObservation`, `SemanticReconciliation`, `reconcile_run`, `ReconciliationVerdict.RESULT_FINALIZATION_ELIGIBLE` | `adapters/reconciliation.py:287-320, 980-992`; `adapters/vocabulary.py:87` | observation = `(relative_path, observed_size_bytes, observed_sha256, contains_attempt_token)`; the verdict with no run target |
| `validate_relative_candidate_path`, `RelativeCandidatePath`, limits | `adapters/paths.py:85-133`; `adapters/limits.py:43-71` | the lexical half of 15.5; `MAX_CANDIDATE_ARTIFACTS` 256, `MAX_STDERR_BYTES` 52 428 800, `RESULT_MANIFEST_RELATIVE_PATH` |
| `StderrCapture` | `adapters/sanitization.py:279-291` | `retained_byte_count`, `truncated`, `source_hash`, `sanitized_text | MISSING` — the only stderr representation Stage 7 returns |
| `DescriptorParse` | `adapters/negotiation.py:786` | the describe output the `ADAPTER` evidence producer serializes |
| `CommandResult` | `adapters/commands.py:158` | the hand-off fact `experiments` consumes; `SupervisionOutcome` (`process_supervision/models.py:604-622`), `SupervisionTraceEntry` (`process_supervision/ports.py:233-240`) and `CommandPaths` (`process_supervision/roots.py:135-147`) are destructured by the caller — Task 8's flow now, Stage 10's composition later — because `experiments` and `artifacts` may not import `process_supervision` |
| `plan_command_paths`, `snapshot_written_paths`, `read_output_file`, `remove_command_root`, `_FILE_ATTRIBUTE_REPARSE_POINT` | `process_supervision/roots.py:97-100, 222-266, 484, 531, 619, 268-284` | the run work directory `<command_root>\runs\<run_id>\work` is the adapter staging root; the attribute-based reparse test is mirrored, not imported; recovery receives the domain-typed `CommandRootPaths` of §4.1 from its caller |
| `PathsConfig`, `ProcessConfig.finalization_timeout_seconds`, `LoggingConfig.retained_files` | `configuration/models.py:314-319, 366, 388` | `artifacts_root`, `runtime_root`, `logs_root`; 300 s default, 1..3600; 10 retained log files |
| `apply_command_semantic_outcome`, `SemanticOutcome`, `SemanticOutcomeRequest` | `experiments/semantic_outcome.py:158-171, 630-640`; `experiments/requests.py:327-363` | unchanged; `RESULT_FINALIZATION_ELIGIBLE` writes nothing and the run stays `RUNNING`; `reconcile_run` admits no success state (`adapters/reconciliation.py:233-235`; `semantic_outcome.py:177-180`), so once Stage 9 commits success the operation is reached only through the Task 7 wrapper of reading 24 |
| `transition_run`, `cancel_experiment`, `transition_invocation_and_run` | `experiments/run_service.py:247-313`; `experiment_service.py:501-552`; `invocation_service.py:1086-1092` | `transition_run` is the only writer of `RUNNING → CANCELLED/TIMED_OUT/FAILED/UNAVAILABLE/NOT_APPLICABLE` after `EXITED` and never loads the invocation; `cancel_experiment` swaps the experiment row only and never reads or writes a run; `transition_invocation_and_run` refuses any transition of a terminal invocation; a same-state `transition_run` is a no-write replay (`:269-272`) |
| `UnitOfWork` (six members), `EngineRunRepository`, `CommandInvocationRepository`, `DiagnosticReader` | `experiments/ports.py:102-283` | unchanged; `compare_and_swap(expected_revision, replacement)` is the success/timeout write |
| `DiagnosticRecorder` | `experiments/supervision_lifecycle.py:149-157` | idempotent on `diagnostic_id` |
| `evaluate_comparison_eligibility(left, right, requested_level)` | `capabilities/comparison.py:1210-1222` | roles unchanged; Stage 9 adapts two `RunManifest`s into its `ComparisonInput`s |
| `SqliteDatabase`, `classify`, `consistency_report`, `TransactionScope`, `SqliteUnitOfWork`, `SqliteTransaction`, `SqliteDiagnosticRecorder`, `SqliteArtifactOwnerRegistry`, codecs | `persistence/database.py:456-652`; `repositories.py:168-313`; `unit_of_work.py:299-589`; `registries.py:409-418, 960-991`; `codecs.py:126-1071` | the conflict/invariant/missing idioms, the deferred `BEGIN`, egress re-validation, `NULL ⇔ MISSING` |
| `SqliteReconciliationSource`, `reconcile_invocations`, `ReconciliationReport` | `persistence/reconciliation_source.py:139-166`; `process_supervision` | the process half of 29.2 step 5/7; Stage 9's artifact half runs after it in the test composition |
| `SupervisedSqliteFlow` | `tests/persistence_support/supervised.py:281-910` | `prepare_run`, `invoke`, `describe`, `conclude`, `reopen`, `token_absent_everywhere`, `consistency_report`, `reconcile` are extended, never rewritten (`describe`, `:610-625`, gains the `conclude_describe` call of §4.6), except that its test-side `_observe_candidates` (`:244-278`, called pre-verdict at `:730`) is replaced by the production `observe_candidates` (§4.4 step 0); `close()` `rmtree`s every command root (`supervised.py:354-355`), so Task 8 adds `close(keep_command_roots=True)` for the crash rows that `reopen` after a close |
<!-- /consumed -->

### 2.3 Placement decisions

| Concern | Placement | Why |
|---|---|---|
| Candidate, reference, request, journal, manifest records; enums; `FinalizationResult` | `crypto_lab.artifacts.models/requests/journal/manifest` | 27.1:1907 artifacts owns them; domain-only imports |
| `MetricValue` | `crypto_lab.domain.metrics` | 11.3:584 is a domain record used by `RunManifest`; `ComparisonLevel` already lives in `domain` |
| Normalized records | `crypto_lab.domain.normalized` (conditional, §1.6 item 1) | 27.2 lists records under `domain`; `Money`/`Price`/`Quantity` live there |
| `RunManifest`, `NormalizedResultProvenance`, `run_manifest_hash` | `crypto_lab.experiments.run_manifest` | needs `RunProvenance`, `SemanticStatus`, `NegotiatedVersions`, approximations from `adapters`/`capabilities`, which `artifacts` may not import (27.1) |
| `ArtifactFinalizer` protocol and `CoreArtifactFinalizer` | `crypto_lab.artifacts.ports` / `.finalizer` | 8.1:271 interface; the implementation is generic over purpose and delegates registration through `PurposeRegistrar` |
| RESULT registrar (RunManifest, run links, sanitized facts, success CAS), evidence producers, request builders | `crypto_lab.experiments.finalization` | needs adapter and experiment models; 27.1 lets `experiments` import artifacts/audit abstractions; process-supervision values arrive destructured (`CommandResult`, parses, `Path`s) |
| `ComparisonEligibilityService` | `crypto_lab.experiments.comparison` | takes two manifests; `experiments` already imports `capabilities` |
| Audit models, redaction, correlation, JSON Lines writer, `AuditSink` port | `crypto_lab.audit` | 27.1:1911; domain-only; the writer uses `pathlib` only |
| Tables, revision, codecs, repositories, `SqliteAuditSink`, `SqliteDiagnosticWriter` | `crypto_lab.persistence` | 27.1:1908; `schema.py` gains rows in place (Stage 8-owned file edited under §2.6's single-authority sentence) |
| Content-addressed store, `atomic_move`, `quarantine_move`, handle identity, `fsync` | `crypto_lab.artifacts.store` | the one `os` importer |
| Fault probe for crash tests | `crypto_lab.artifacts.finalizer.FinalizationProbe` protocol with a no-op default | production code calls the probe at ten named points (§4.3); tests inject one that raises `BaseException` subclasses to emulate process death |

### 2.4 Frozen-byte and contract constraints

- The 35 published schemas, the four digest blocks, the registry order of
  positions 0–34, every published `$id` are frozen; Stage 9 appends only.
- `r0001_stage8_baseline.py` is never edited; `r0002_stage9_artifacts`
  declares `down_revision = "r0001_stage8_baseline"`; `downgrade()` drops the
  sixteen triggers (the three on existing tables explicitly, the rest with
  their tables), the indexes — the partial index on the added column
  included — and the eight tables, and retains the nullable column by
  decision rather than dropping it (no existing table is rebuilt or altered
  beyond the one added column, Global Constraints); the script records that
  residue as its own last statement (§6.6:
  `op.execute("-- finalization_deadline_utc retained")`), which Task 5's
  `test_downgrade_leaves_column_with_recorded_warning` pins — a documented,
  tested, non-destructive residue.
- `SanitizedAdapterResultManifest`, `RunProvenance`, `CandidateObservation`,
  `RelativeCandidatePath`, `StderrCapture`, every lifecycle table and every
  Stage 5–8 diagnostic code are consumed unchanged.
- `EngineRunRecord` immutable fields (`engine_run.py:380-391`) and
  `_ENRICHABLE_FIELDS` (`command_invocation.py:532-543`) are unchanged; the
  only domain-rule changes are reading 9's validator and the new
  `assert_deadline_snapshot(stored, replacement)` predicate (Task 5): same
  run, both states `RUNNING`, `finalization_deadline_utc` `MISSING` → present,
  revision plus one, every other field equal — the Stage 5
  `assert_write_once_enrichment` shape, needed because `run_edge_owner` has
  no reflexive edge (`engine_run.py:363-371`), a same-state `transition_run`
  is a no-write replay (`run_service.py:269-272`) and the Stage 8 run CAS
  checks revision only (`repositories.py:651-713`). The `EngineRunRecord`
  class docstring, field order and annotations are byte-frozen (the published
  `engine-run-record-v1` description is that docstring, pinned by
  `_STAGE5_SHA256`, `test_schema_registry.py:2969`); the Task 5 edit at
  `engine_run.py:303-308` touches the validator body and message and the
  module docstring only.
- `experiments.UnitOfWork` keeps six members; `tests/doubles/experiments.py`
  and `tests/doubles/supervision.py` are not edited (new doubles live in
  `tests/doubles/artifacts.py`).
- `tests/contract/*`, `tests/fake_adapters/*` are not edited; the fake
  adapters already write candidate files and the manifest.

### 2.5 Declared readings of the specification

1. **"Wins first" is the `REGISTERED` commit (19.3:1411, 14.8:1031).** The
   RESULT lease is the `PREPARED` row plus the run compare-and-swap that
   snapshots the deadline; it excludes other finalizers (23.3:1688), not
   cancellation or timeout. The journal stores `expected_run_revision` and
   `expected_invocation_revision` as of `PREPARED`; the `REGISTERED`
   transaction's success compare-and-swap uses them, so any intervening
   terminal winner yields `PERSISTENCE.CONCURRENCY_CONFLICT`, the journal
   becomes `ABANDONED(SUPERSEDED)`, and the moved bytes go to quarantine
   (29.2:2166). A cancellation issued after `REGISTERED` fails the terminal
   immutability check and is recorded as ineffective by the caller.
2. **A crash between `EXITED` and `PREPARED` leaves no deadline (29.3:2184,
   14.8:1029).** The finalization deadline exists only from `PREPARED`.
   Recovery of such an attempt re-runs validated reconciliation and snapshots
   a fresh deadline at its own `PREPARED`; if any 29.3 condition fails the
   attempt moves to `FAILED` under 17.3:1278 ("other failed recovery checks").
   "Remain nonterminal until the original deadline yields `TIMED_OUT`" applies
   to invocations without captured exit facts and is Stage 7's rule; Stage 9
   never touches an invocation that is not `EXITED`.
3. **`EXITED` never becomes `PROTOCOL_FAILED` (29.3:2184 second clause).**
   29.3's own precondition is a durably `EXITED` invocation and `EXITED` has
   no outgoing transition (15.2); the clause belongs to the `RUNNING` branch
   (Stage 7, `supervision_lifecycle.py:1071`). No Stage 9 test plans that edge.
4. **"Newer attempt won before the lease" (29.3:2181) is a predicate, not a
   scenario.** A successor needs a terminal predecessor (17.2.1 gate 2,
   17.3) and `engine_runs` has active-attempt partial uniqueness; while the
   run is `RUNNING` no newer attempt exists. The lease check still asserts
   `latest_attempt(slot).run_id == run_id` and a test plants a terminal
   predecessor plus successor to prove the predicate refuses.
5. **An EVIDENCE win is non-interference, not a race (19.3:1411).** EVIDENCE
   touches no run row; the pin is "run revision unchanged across an EVIDENCE
   `REGISTERED` commit", asserted after each of the six terminal outcomes.
6. **No normalized-result producer, no Parquet in Project 1** (§1.6 item 6).
7. **Owner variants are exercised through the production entry point** (§1.6
   item 7). `stage_core_evidence(owner, role, relative_path, bytes_source,
   correlation)` is the only way core evidence enters staging; it refuses a
   role/owner pair outside the table of §3.1 (`EXPERIMENT_INPUT` ⇒
   `EXPERIMENT`, `DATASET_INPUT` ⇒ `DATASET`, `STRATEGY_INPUT` ⇒ `STRATEGY`,
   `ADAPTER_DESCRIPTOR_EVIDENCE` ⇒ `ADAPTER`, `CORE_EVIDENCE` ⇒ `RUN`,
   `SYSTEM`, or `ADAPTER` with an `INVOCATION` correlation naming a `DESCRIBE`
   invocation — the describe stderr of 23.3.1:1703).
8. **`adapter_validation_results` is a manifest/provenance increment** (§1.6
   item 5); `sanitized_adapter_result_manifests` is a manifest increment.
9. **`engine_runs.finalization_deadline_utc` is a recovery increment** (§1.6
   item 2); the validator admits it exactly when the state is `RUNNING`,
   `SUCCEEDED`, `SUCCEEDED_WITH_WARNINGS`, `TIMED_OUT`, `CANCELLED` or
   `FAILED` (the states reachable after a snapshot) and rejects it for
   `PENDING`, `VALIDATING`, `READY`, `STARTING`, `UNAVAILABLE`,
   `NOT_APPLICABLE`; once present it is immutable (the row trigger of §3.4).
   The snapshot itself is the `RUNNING → RUNNING` write proven by
   `assert_deadline_snapshot` (§2.4). After a snapshot the generic
   `transition_run` targets `NOT_APPLICABLE` and `UNAVAILABLE` carry the
   deadline forward (`run_service.py:179-198`) and are refused by this
   validator as unrepresentable (`CORE.INVARIANT_VIOLATION`): both verdicts
   were decided by `reconcile_run` before the deadline existed, so neither is
   a lawful successor of a snapshotted run (declared, tested in Task 5).
10. **`stderr_artifact_id` is enforced by trigger, not foreign key** (23.3.1:1703):
    `BEFORE UPDATE OF stderr_artifact_id` on `command_invocations` requires an
    `artifact_refs` row with that id, `finalization_purpose = 'EVIDENCE'`,
    `producer_kind = 'CORE'`, `source_role = 'CORE_EVIDENCE'` and an owner whose
    variant is `ADAPTER` for a `DESCRIBE` invocation or `RUN` with the same
    `run_id` for `VALIDATE`/`RUN`; `RAISE(ABORT)` classifies through
    `SqliteDatabase.classify` as `CORE.INVARIANT_VIOLATION` (the Stage 8
    trigger precedent).
11. **Success requires a manifest, and a manifest requires `RUNNING`**
    (23.3.1:1712, 29.1:2151): `BEFORE UPDATE OF state ON engine_runs WHEN
    NEW.state IN ('SUCCEEDED','SUCCEEDED_WITH_WARNINGS')` requires an existing
    `run_manifests` row for `NEW.run_id`; `BEFORE INSERT ON run_manifests`
    requires the run to be `RUNNING` with a non-null deadline and an `EXITED`
    run-command invocation equal to `NEW.run_invocation_id`. The RESULT
    registrar therefore inserts refs, links, sanitized facts and the manifest,
    then swaps the run, all in one transaction (§4.4); the generic Stage 5
    `transition_run` can no longer reach a success state through SQLite even
    though `TRANSITION_RUN_OWNED_TARGETS` (`run_service.py:90-92`) lists it,
    and the in-memory double gains the same refusal in `tests/doubles/artifacts.py`'s
    wrapper used by Task 7's tests.
12. **Journal states are `PREPARED`, `MOVED`, `REGISTERED`, `ABANDONED`**
    with `abandon_reason: ErrorCode | MISSING` present exactly for `ABANDONED`;
    `ABANDONED` is the "reconcile or quarantine" terminal of 23.3.1:1723 and
    never coexists with an `ArtifactRef` of the same finalization. This plan
    writes `ABANDONED(<reason>)` as shorthand for the stored `ErrorCode`:
    `SUPERSEDED` ≡ `PERSISTENCE.CONCURRENCY_CONFLICT` (a terminal winner moved
    the run or invocation revision), `TIMED_OUT` ≡ `ARTIFACT.FINALIZATION_TIMED_OUT`,
    `VALIDATION_FAILED` ≡ `ARTIFACT.VALIDATION_FAILED`, `LEAKAGE` ≡
    `SECURITY.SENSITIVE_MATERIAL_LEAKAGE`, `PATH_VIOLATION` ≡
    `ARTIFACT.PATH_BOUNDARY_VIOLATION`, `MOVE_FAILED` ≡ `ARTIFACT.MOVE_FAILED`;
    tests assert the full code.
13. **A timed-out RESULT journal's moved bytes are quarantined** (23.3.1:1723
    "may reconcile or quarantine bytes but cannot register a successful
    manifest"): RESULT references exist only with success, so the only lawful
    reconciliation of a timed-out RESULT journal is quarantine; EVIDENCE
    journals have no deadline and recover under 29.4.
14. **Audit emission scope** (30.3, Stage 8 plan 197): Stage 9 emits the
    artifact family (bullet 9), the artifact half of the reconciliation
    actions (bullet 10), stderr truncation (bullet 7) and the
    finalization-side run/invocation facts it itself writes (success,
    finalization timeout, the `RUNNING → FAILED` write of §4.4 step 3 and of
    a failed 29.3 recovery check — `RUN_FAILED`, bullet 4 "terminal
    transition" — and the `stderr_artifact_id` enrichment); bullets 1–6, 8,
    11 and 12 inside the Stage 4/5 operations, the migration-application half
    of bullet 10 (`apply_migrations` is called by the composition), the
    process half of bullet 10 (the Stage 7 reconciler) and the
    retention-limit snapshot of R30.1-03 (bullet 12) are Stage 10's
    composition (§1.3, §1.4).
15. **The log record is an audit contract** (30.1, roadmap line 264):
    `schemas/audit/log-record-v1.schema.json`; rotation is by a compiled byte
    ceiling `LOG_FILE_BYTES = 8 MiB` and `LoggingConfig.retained_files`; no new
    configuration key.
16. **Adapter diagnostic identities** (O-3): `DIAGNOSTIC_IDENTITY_V1` over
    `{"invocation_id", "sequence", "ordinal", "error_code", "category"}` for an
    `AdapterDiagnostic` carried by a `RunEvent` or manifest, so re-ingestion
    mints the same id and the recorder's idempotency absorbs it.
17. **Derived identities** (29.6): `artifact_id_for(candidate_artifact_id,
    content_hash)` (`ARTIFACT_IDENTITY_V1`), `finalization_id_for(identity)`
    (`FINALIZATION_IDENTITY_V1` over the purpose-specific tuple of 17.2),
    `run_manifest_id_for(run_id, run_invocation_id)`
    (`RUN_MANIFEST_IDENTITY_V1`), `core_candidate_artifact_id_for(owner_hash,
    correlation_kind, correlation_id, relative_path)`
    (`CORE_CANDIDATE_IDENTITY_V1`); every replay recomputes the same ids, so
    "returns the prior identical outcome" is structural.
18. **Hash twice** (8.2:369, 23.3.1:1721): independent hash and token scan
    before `PREPARED` with no transaction open; after the move, re-hash in
    place through the opened handle whose `fstat` identity is compared to the
    pre-move identity, and record the observed hash in `MOVED`; a mismatch is
    `ARTIFACT.VALIDATION_FAILED`, `ABANDONED`, quarantine.
19. **Hard links** (15.5:1102): `lstat().st_nlink > 1` on a candidate is
    `ARTIFACT.PATH_BOUNDARY_VIOLATION`; the attribute test mirrors
    `roots.py:268-281` (`st_file_attributes & 0x400`) without importing it;
    alternate data streams are refused lexically (`:` in any segment).
20. **Same volume** (22.5:1653): `Path.stat().st_dev` equality of the two
    roots plus the reparse walk of both; Task 4's RED includes a probe that two
    files under one `tmp_path` share `st_dev` so the semantics are measured,
    not assumed; a UNC root or a root whose `anchor` lacks a drive letter is
    refused.
21. **Deduplication** (19.2:1405): a finalized path that already exists is
    re-hashed; equal hash ⇒ the candidate bytes are removed and the new
    `ArtifactRef` points at the existing blob (one blob, two refs, two
    manifests); unequal hash ⇒ `CORE.INVARIANT_VIOLATION` (a SHA-256
    collision is treated as corruption) and quarantine. 23.3.1:1709 ("Unique
    logical identity, content hash, owner/purpose/role, and finalized-path
    indexes") is read as: `artifact_id` is the one unique logical identity;
    content hash, owner/purpose/role and finalized path are indexes; the
    unique content identity of 23.3:1688 is the blob at `objects/<hh>/<hash>`
    (one blob per hash), not the reference row.
22. **`Result` stays a deferred name**: `domain/results.py` defines a `type`
    alias, not a class, and the guard scans definitions; Stage 9 defines no
    class or function named `Result`.
23. **Run-level cancellation is the cancellation that competes with a RESULT
    lease.** `cancel_experiment` swaps the experiment row only
    (`experiment_service.py:501-552`); after `EXITED` the only writer of
    `RUNNING → CANCELLED` is `transition_run` with a `CANCELLATION` diagnostic
    carrying `invocation_id` (`run_service.py:247-313`, `lifecycle.py:246`,
    `diagnostics.py:262-269`), and the same generic operation can win any of
    `FAILED`, `TIMED_OUT`, `UNAVAILABLE`, `NOT_APPLICABLE` after `EXITED`
    because it never loads the invocation (so RC-15 names
    `transition_invocation_and_run`, the operation that does refuse a terminal
    invocation, and T3's revision CAS is the arbiter against the generic
    writer). The experiment's state is checked once, before or in T1
    (`active_attempt_facts`); an experiment
    cancelled between T1 and T3 does not pre-empt the lease — 19.1:1327 and
    29.3:2181 name run-level winners and the run row's revision decides — and
    the Stage 10 composition that cancels an experiment's runs does so through
    `transition_run`, which then wins or loses by that revision. RC-17 pins
    the reading.
24. **Post-success replay** (Stage 6 plan 111, O-14): `apply_command_semantic_outcome`
    is reached only through `experiments/finalization.py::semantic_outcome_or_replay(request,
    *, unit_of_work, clock)`, which loads the run first and, when it is already
    in `SUCCESS_ENGINE_RUN_STATES`, returns the stored `CommandConclusion`
    (the `run_manifests` row, its refs and evidence, `replayed=True`) without
    invoking the Stage 6 operation (which would answer
    `CORE.INVARIANT_VIOLATION`, `semantic_outcome.py:177-180`); otherwise it
    delegates unchanged. Task 8's flow and Stage 10's composition call only
    the wrapper.
25. **No correction operation in Stage 9** (R19.1-18): `artifact_refs` is
    insert-only, so any future correction is a new reference whose
    `ArtifactLineage.superseded_artifact_id` names the superseded one; Task 1
    pins the field, §1.4 carries the operation.
26. **A move failure is a storage failure, not corruption** (29.5:2192,
    21.2.1:1547, 21.2.1:1551): `ARTIFACT.MOVE_FAILED` mirrors
    `PERSISTENCE.WRITE_FAILED` (`persistence/diagnostics.py:88`: category
    `PERSISTENCE`, `retriable=False`), so it is outside
    `HARD_BLOCKING_DIAGNOSTIC_CATEGORIES` and a successor stays possible
    through `RetryPolicy` ("conditional after storage repair");
    `ARTIFACT_CORRUPTION` is reserved for size/hash/schema mismatch, unsafe
    path and mutation during hashing (21.2:1518). A RESULT move failure fails
    the run with `MOVE_FAILED` as primary ("leaves the run non-successful"),
    abandons the journal and quarantines; an EVIDENCE move failure changes no
    run.

### 2.6 Closed-world guard reconciliation

The merged tree enforces closed sets by exact equality. Every guard Stage 9
trips is reconciled here, assigned to the task whose work first trips it, and
none is weakened, deleted or replaced by a lower bound; the one retirement
(`test_stage_nine_finalization_names_stay_deferred`) is replaced by the Stage
9 guard's positives. **This section is the single authority for every guard
edit Stage 9 makes to a Stage 1–8 test file**, including the Stage 8-owned
constants `_PERSISTENCE_IMPORTS`, `_PERSISTENCE_MODULES`, `_SQLALCHEMY_IMPORTERS`,
`_ALEMBIC_IMPORTERS`, `_PERSISTENCE_FAMILIES`, `_SUBPROCESS_IMPORTER_PARENTHETICAL`,
the Stage 8 status positives of `:977-999`, `_STAGE8_COMPLETION_ROW`'s last
clause and `_LATER_STAGE_CLAIMS` whose docstring claims ownership. The base values are
those of `tests/safety/test_stage8_boundaries.py:934-952`.

**Rule.** A task that creates a module under `src/crypto_lab` appends that
module, in the same commit, to `_ALLOWED_SOURCE_FILES`
(`tests/safety/test_stage3_boundaries.py:18`) and `PACKAGE_MODULES`
(`tests/unit/test_package_layout.py:12`, after the existing group of its
package, so the relative-order pins of the `process_supervision` entries
survive), and moves every `len(...) == 110` cross-pin
(`test_stage8_boundaries.py:770-771, 939`; `tests/unit/persistence/test_sqlite_database.py:1808-1813`
and its string pins `:1821-1829` (`"len(allowed) == 110"`/`"len(modules) == 110" in`
the preflight and reconciliation sources);
`tests/unit/persistence/test_sqlite_migrations.py:1026-1036` and the string
pins `:1039-1045`; `tests/unit/process_supervision/test_supervisor_preflight.py:1246, 1257`;
`tests/unit/process_supervision/test_restart_reconciliation.py:1760, 1768`) to
the running size. A task that first defines a deferred name removes exactly
that name from `_DEFERRED_DEFINITIONS`, its literal set, its count
(`test_stage3_boundaries.py:712`; `test_stage8_boundaries.py:880, 941`) and
the §2.6 remaining list. A task that first imports a root outside
`_ALLOWED_IMPORT_ROOTS` adds exactly that root to the set, to the literal of
`test_the_import_root_allowlist_is_exactly_the_reviewed_twenty_two`
(`:453-509`), to its count and to every `len(roots) == 29` cross-pin. A task
whose persistence module imports `sqlalchemy` or `alembic` adds exactly one
`(module, root)` pair to `_INFRASTRUCTURE_EXEMPTIONS`
(`tests/safety/test_stage5_boundaries.py:108-124`, literal `:583-599`), to
`_EXPECTED_EXEMPTIONS` (`test_sqlite_migrations.py:105-125`) and moves the
`len == len(stage8_pairs) + 1` and census 13 pins (`test_stage8_boundaries.py:799, 942`);
the same task adds the module to `_PERSISTENCE_MODULES`/`_PERSISTENCE_IMPORTS`
(`:110-113, 185-340`) and to `_SQLALCHEMY_IMPORTERS` or `_ALEMBIC_IMPORTERS`
(`:117-136, 789-790`).

**Source-file allowlist.** `_ALLOWED_SOURCE_FILES` is a literal set of 110
paths at the planning base. Stage 9 adds exactly 26 paths (25 without Task 3),
taking it to 136 (135); the same dotted names join `PACKAGE_MODULES`. Running
sizes below are the confirmed-Task-3 branch; subtract one from Task 4 on
otherwise.

<!-- source-files -->
| Task | Paths appended (relative to `src/crypto_lab`) | Running size |
|---|---|---|
| 1 | `artifacts/models.py`, `artifacts/requests.py`, `artifacts/journal.py`, `artifacts/manifest.py`, `artifacts/diagnostics.py` | 115 |
| 2 | `audit/models.py`, `audit/redaction.py`, `audit/correlation.py`, `audit/jsonl.py`, `audit/sink.py`, `domain/metrics.py` | 121 |
| 3 (conditional) | `domain/normalized.py` | 122 |
| 4 | `artifacts/paths.py`, `artifacts/hashing.py`, `artifacts/validation.py`, `artifacts/store.py` | 126 |
| 5 | `persistence/artifact_codecs.py`, `persistence/artifact_repositories.py`, `persistence/audit_sink.py`, `persistence/migrations/versions/r0002_stage9_artifacts.py` | 130 |
| 6 | `artifacts/ports.py`, `artifacts/finalizer.py`, `artifacts/recovery.py` | 133 |
| 7 | `experiments/run_manifest.py`, `experiments/finalization.py`, `experiments/comparison.py` | 136 |
<!-- /source-files -->

Every new module is import-side-effect free: `audit/jsonl.py` opens its file
in `JsonLinesLogWriter.open`, `artifacts/store.py` touches the filesystem only
inside functions, the revision module builds nothing at import.
`STAGE5/6/7/8_SOURCE_FILES` (18/14/12/15) are untouched; the Stage 9 guard
pins `STAGE9_SOURCE_FILES` (26) disjoint from all four. The Stage 7 dependency
scan literal `scanned == 12 + 11` (`tests/safety/test_stage7_boundaries.py:656-681`)
becomes `12 + 14` in Task 7.

**Import-root allowlist.** `_ALLOWED_IMPORT_ROOTS` holds 29 roots. Task 4
adds `os` (30); the test docstring arithmetic gains a Stage 9 paragraph. The
`roots.isdisjoint({"sqlite3", "os", "sys", "time", "logging"})` assertion at
`test_sqlite_database.py:1812` becomes "no `_PERSISTENCE_MODULES` member
imports any of those five" (the Stage 8 denylist `_PERSISTENCE_FORBIDDEN_ROOTS`,
`test_stage8_boundaries.py:143-162`, already proves it; the sentence is
restated, not deleted). No new module imports `stat`, `shutil`, `tempfile`,
`io`, `errno`, `logging`, `time`, `secrets`, `random`, `threading`, `asyncio`,
`ctypes`, `queue`, `subprocess` or `types`.

<!-- import-roots -->
| Task | Root added | Confined to (pinned in Task 4 by `test_artifact_store.py::test_os_is_imported_only_by_the_artifact_store`, a tree-wide AST walk; re-pinned by the Stage 9 guard in Task 9) | Running count |
|---|---|---|---|
| 4 | `os` | `artifacts/store.py`; attributes exactly `{"fstat", "fsync"}` (AST scan of `os.<attr>` reads) | 30 |
<!-- /import-roots -->

**Infrastructure-root exemptions (Stage 5 guard).** Task 5 adds three
`sqlalchemy` pairs (`persistence/artifact_repositories.py`,
`persistence/audit_sink.py`, `persistence/migrations/versions/r0002_stage9_artifacts.py`)
and one `alembic` pair (the revision), taking the set from 13 to 17;
`persistence/artifact_codecs.py` imports no infrastructure root, exactly as
Stage 8's `codecs.py`; the Stage 8
`_SQLALCHEMY_IMPORTERS` grows 9 → 12 and `_ALEMBIC_IMPORTERS` 3 → 4;
`_PERSISTENCE_MODULES` 14 → 18 — it is derived at `test_stage8_boundaries.py:110-113`
from the 13 `persistence/` paths of `STAGE8_SOURCE_FILES` plus
`persistence/__init__.py`, so Task 5 adds a `_STAGE9_PERSISTENCE_FILES`
literal of the four new paths unioned into that derivation while
`STAGE8_SOURCE_FILES` stays 15 — with per-module import literals in
`_PERSISTENCE_IMPORTS` (`set(_PERSISTENCE_IMPORTS) == _PERSISTENCE_MODULES`,
`:805`); `_PERSISTENCE_FAMILIES` (`:344-366`) gains exactly `artifacts.models`,
`artifacts.journal`, `artifacts.manifest`, `audit.models`, `audit.sink` (the
`_family_violations` check at `:598-606` rejects any other); the
`importers <= _PERSISTENCE_MODULES` relation holds.

**Deferred-definition guard.** `_DEFERRED_DEFINITIONS` holds 33 names. Stage 9
defines 29 of them (4 remain). Task 1 retires
`test_stage_nine_finalization_names_stay_deferred` and `_STAGE8_AND_LATER_NAMES`
(`test_stage7_boundaries.py:264-274, 803-822`) and the `<=` assertion at
`test_stage8_boundaries.py:881` in the same commit that defines the first of
the nine names, replacing them with the Stage 9 guard's positives in Task 9
(each released name defined exactly once, in its §2.6 module). The
representative-mutation list (`test_stage3_boundaries.py:768-797`, seven live
names, all seven Stage 9 releases; there is no count pin, only the
parametrize list) keeps the in-file convention "swapped in a still-deferred
name so seven live cases remain": Task 1 swaps `CandidateArtifact`,
`CandidateArtifactState`, `ArtifactRef` for `MetricValue`, `AuditEvent`,
`ContentHasher`; Task 2 swaps `MetricValue`, `AuditEvent` for
`ComparisonEligibilityService`, `ArtifactRepository`; Task 3 (when
confirmed) swaps `CanonicalOrder`, `PortfolioSnapshot` for
`CandidateArtifactRepository`, `Result`; Task 4 swaps `ContentHasher` for
`ingest_dataset` (the plant shape generalizes from `class {name}` to
`def {name}` once a function name enters; `Result` is planted as a class).
The list shrinks only when fewer than seven names remain deferred: to six at
Task 6 and four at Task 7 on the confirmed branch; never on the excluded
branch (thirteen remain), where Tasks 6 and 7 swap instead.

<!-- released-names -->
| Task | Released | Module |
|---|---|---|
| 1 | `ArtifactFinalizationPurpose`, `ArtifactOwnerKind`, `ArtifactRef`, `ArtifactSourceRole`, `CandidateArtifact`, `CandidateArtifactState`, `CandidateArtifactProducerKind`, `CandidateFinalization`, `EvidenceFinalizationRequest`, `FinalizationResult`, `ResultFinalizationRequest` | `artifacts/models.py`, `artifacts/requests.py` |
| 2 | `AuditEvent`, `AuditSink`, `MetricValue` | `audit/models.py`, `audit/sink.py`, `domain/metrics.py` |
| 3 (conditional) | `CanonicalFill`, `CanonicalOrder`, `EquityPoint`, `Fee`, `OrderSide`, `OrderType`, `PortfolioSnapshot`, `PositionSnapshot`, `PositionEffect` | `domain/normalized.py` |
| 4 | `ContentHasher` | `artifacts/hashing.py` |
| 6 | `ArtifactFinalizer`, `ArtifactRepository`, `CandidateArtifactRepository` | `artifacts/ports.py` |
| 7 | `RunManifest`, `ComparisonEligibilityService` | `experiments/run_manifest.py`, `experiments/comparison.py` |
<!-- /released-names -->

Running count (confirmed branch): 33 → 22 (Task 1) → 19 (Task 2) → 10 (Task
3) → 9 (Task 4) → 6 (Task 6) → 4 (Task 7); excluded branch: 33 → 22 → 19 →
18 (Task 4) → 15 (Task 6) → 13 (Task 7).

<!-- remaining-names -->
Remaining deferred (4 on the confirmed branch; 13 on the excluded branch,
adding the nine normalized names), which no Stage 9 module may define under
these exact names: `Result`, `ingest_dataset`, `normalize_dataset`,
`place_order`.
<!-- /remaining-names -->

**Task 3 branch table (§1.6 item 1).** Every count in this plan is the
confirmed branch; the excluded branch differs only here.

| Quantity | Task 3 confirmed | Task 3 excluded |
|---|---|---|
| `_ALLOWED_SOURCE_FILES` / `PACKAGE_MODULES` final; Tasks 4–7 running sizes | 136; 126, 130, 133, 136 | 135; 125, 129, 132, 135 |
| `STAGE9_SOURCE_FILES` | 26 | 25 |
| Released / remaining deferred names | 29 / 4 | 20 / 13 |
| Live mutation cases after Tasks 6, 7 | 6, 4 | 7, 7 |
| `SCHEMA_DEFINITIONS`, schema files, `_STAGE9_PATHS`/`_STAGE9_SHA256` | 54, 54, 19 | 48, 48, 13 |
| Task 7 registry positions | 52–53 | 46–47 |
| README/guide registry prose (Task 9) | "closed 54-schema registry — 19 new" | "closed 48-schema registry — 13 new" |
| §9.3 items 1 and 12 | as written | with these values |

Profiles, tables, triggers, importers, roots and exemption pairs are
Task-3-independent.

**Schema registry.** `SCHEMA_DEFINITIONS` is 35 entries; the schemas directory
holds 35 files. Stage 9 appends 19 entries (13 without Task 3) in the order
of §3.2 (positions 35–53; 35–47 with Task 7's two at 46–47 when Task 3 is
excluded): Task 1 eight (`artifacts/`), Task 2 three (`audit/` two,
`domain/` `metric-value-v1`), Task 3 six (`domain/`), Task 7 two
(`experiments/` `run-manifest-v1`, `normalized-result-provenance-v1`),
total 54 (48). Each task
moves `len(SCHEMA_DEFINITIONS)`/rglob pins (`test_stage3_boundaries.py:808`;
`test_stage8_boundaries.py:950-951`; `tests/unit/test_schema_registry.py:354,
1157-1213`; `tests/unit/domain/test_domain_descriptors.py:239`), extends
`_EXPECTED` and `_EXPECTED_ADAPTED_TYPES`, changes both Stage 6 tail pins of
`test_schema_registry.py:1139-1142` (`_ordered_paths()[27:]` and
`SCHEMA_DEFINITIONS[27:]`) to `[27:35]` and adds `_STAGE9_PATHS` with its
running slice; the Stage 9 guard adds `_STAGE9_SHA256` (19 digests; 13
without Task 3) and the
Stage-9-absent halves to the four keyed digest tests (`:2845, 2906, 3003,
4019`). The four existing digest blocks are not edited. The guide's "closed
35-file registry" sentence (`verification.md:93-94`) moves in Task 9.

**Hashing profiles.** `HashingProfile` is 12. Task 1 adds
`ARTIFACT_IDENTITY_V1`, `ARTIFACT_MANIFEST_V1`, `CANDIDATE_SET_V1`,
`FINALIZATION_IDENTITY_V1`, `CORE_CANDIDATE_IDENTITY_V1` (17); Task 2 adds
`AUDIT_EVENT_DETAILS_V1` (18); Task 7 adds `RUN_MANIFEST_V1`,
`RUN_MANIFEST_IDENTITY_V1` (20). `tests/unit/adapters/test_adapter_diagnostics.py:425-437`
changes `tuple(HashingProfile)[8:]` to `[8:12]` and both `12`s move with each
task; `test_stage8_boundaries.py:952` moves;
`tests/unit/domain/test_lifecycle_tables.py:539-540` (`len(HashingProfile) == 12`
and the value-set size `12` inside
`test_the_two_stage_five_hashing_profiles_exist_and_reach_no_schema`) moves
with each task (17, 18, 20) and its render scan (`:541-545`) gains one
`assert b"<value>" not in contents, path` line per new member's value string
(the kebab-case `<name>/v1` form of `candidate-artifact-identity/v1`), so no
published schema reaches a profile; `tests/unit/domain/test_hashing.py:66-67`
is derived and unchanged.

**Relational pins.** `tests/unit/persistence/test_sqlite_schema.py`:
`_TABLES` 13 → 21 (`:70-83`), the object count `14 + len(_INDEXES) +
len(_TRIGGERS)` (`:249`) regenerated, `_EXPECTED_OBJECTS_DIGEST` (`:66-68`)
re-pinned after review; `test_sqlite_migrations.py:307-322` one head →
`r0002_stage9_artifacts`, the versions directory three files; the test-only
successors (`tests/unit/persistence/conftest.py:53, 130, 149, 169`) re-point
`down_revision` to the new head; `test_stage8_boundaries.py:912-932` head and
directory pins move; `_BASELINE_REVISION in guide` (`:1018`) holds (the guide
keeps naming the baseline and adds the successor). `EXPECTED_SCHEMA_OBJECTS`,
`metadata_drift` and `scripts/verify_migrations.py`'s pinned `sqlite_master`
set regenerate in Task 5. `_DIAGNOSTIC_IDS_NAMERS` (`test_stage8_boundaries.py:399-407`)
is unchanged: no new row names `diagnostic_ids`.

**Dependency guards.** Unchanged: four runtime requirements, 27 prohibited
families, `_EXPECTED_DEVELOPMENT_NAMES` 8, the `[tool.mypy]` key set.

**Reader census (Stage 5 guard).** `_EXPECTED_READER_IMPLEMENTATIONS` stays 5:
no Stage 9 class defines both `get` and `get_many`
(`SqliteArtifactRepository` exposes `get`/`list_by_owner`,
`SqliteCandidateArtifactRepository` `get`/`list_recoverable`; the in-memory
doubles follow the same names). `resolve_causal_closure` stays the only
`.get_many(` caller.

**Bare-name and text scans.** `_BARE_FORBIDDEN_NAMES` (`test_stage4_boundaries.py:37-67`)
forbids `context`, `buffer`, `note`, `problem`, `Loader`: the correlation
module names its type `CorrelationContext` and its instances
`correlation_scope`; the writer's accumulator is `pending_lines`.
`_ATTEMPT_TOKEN_CARRIERS` stays four (the scanner receives
`AttemptTokenMaterial` as a parameter; no `AttemptToken` annotation appears in
any new class). `_TEXT_ONLY_SHELL_FILES`: no Stage 9 test contains `os.system`.
`test_the_doubles_module_declares_no_thread_sleep_or_random_dependency`:
`tests/doubles/experiments.py` is not edited.

**Architecture closure.** `tests/architecture/test_package_import_boundaries.py`:
Task 1 adds `_ALLOWED_FOR_ARTIFACTS = ("crypto_lab.domain", "crypto_lab.artifacts")`
and Task 2 `_ALLOWED_FOR_AUDIT = ("crypto_lab.domain", "crypto_lab.audit")`
with the same self-test parametrizations the other closures have; Task 7
extends `_ALLOWED_FOR_EXPERIMENTS` (`:110-115`) with `crypto_lab.artifacts`
and `crypto_lab.audit`, adds positive anchors (`experiments/finalization.py`
imports both), and removes the two packages from the Stage 5
`_OUT_OF_SCOPE_PACKAGES` (`test_stage5_boundaries.py:135-141`) while adding
`crypto_lab.persistence` and `crypto_lab.cli` negatives there so
`test_experiments_and_adapters_import_no_out_of_scope_package` and its
controls (`:435-448, 778-800`) keep a non-empty refusal set; Task 5 extends
`_ALLOWED_FOR_PERSISTENCE` (`:153-163`) with `crypto_lab.audit` and replaces
`test_the_persistence_allowlist_rejects_the_table_permitted_audit_edge`
(`:607-619`) with a negative proving `crypto_lab.cli` and
`crypto_lab.schema_registry` are still refused. `process_supervision` keeps
`artifacts`, `persistence` and `audit` prohibited (`:124-135`;
`test_stage7_boundaries.py:180-185`). The domain closure
(`tests/architecture/test_domain_import_boundary.py:12-24`) is unchanged;
`domain/metrics.py` and `domain/normalized.py` import `domain` only.

**Subprocess importers (Stage 6 and 7 guards, Task 6).** `_SUBPROCESS_IMPORTERS`
(12) gains `tests/integration/artifacts/test_finalization_crash_child.py`
(13); `_NUMBER_WORDS` (`test_stage7_boundaries.py:255`) gains `13: "thirteen"`,
the guide sentence (`verification.md:824-825`) becomes "the thirteen
`subprocess` importers (the ten of Stage 6, the Stage 7 fake script, the
Stage 8 interrupted-writer test and the finalization crash child)" — without
the literal "Stage 9", which `test_stage3_boundaries.py:1560-1567` forbids
outside the pinned blocks until Task 9 — and the "twelve" phrase joins
`_RETIRED_SUBPROCESS_IMPORTER_PHRASES` (`:258-262`). Four Stage 7/8 pins
move in the same commit: `_SUBPROCESS_IMPORTER_PARENTHETICAL`
(`test_stage8_boundaries.py:482-485`, pinned byte-exact with its hard wrap at
`:1011`) is rewritten to the new parenthetical and the old text joins
`_RETIRED_SUBPROCESS_IMPORTER_PARENTHETICAL`; the Stage 8 census
`len(_SUBPROCESS_IMPORTERS) == 12` (`:944`) → 13; the Stage 7 census of the
same value inside `test_the_guide_names_the_subprocess_importer_count_the_guard_pins`
(`test_stage7_boundaries.py:790`) → 13; and the self-test
`test_the_number_word_lookup_fails_by_name_outside_its_table`
(`test_stage7_boundaries.py:944-947`) advances its refused lookup from 13 to
14 with `_subprocess_importer_phrase(12)` as its positive. The child is
launched with a list argv, `shell=False`, the venv interpreter and a
single-line `-c` program; because that interpreter path is a launcher that
starts the real interpreter as its own child on this host (commit `079395b`),
the child's ready line reports its own interpreter pid and the parent
terminates and awaits that pid through a retained, creation-identity-verified
handle (§7.1); `_FAKE_ADAPTER_ROOTS` and the Stage 7 fake shape
are unchanged.

**Status pins (Task 9).** `_STAGE8_ROADMAP_STATUS_LINE` → "Stages 1 through 9
complete"; `_STAGE8_ROADMAP_PLAN_SENTENCE` → "Stages 1 through 9 have approved
detailed implementation plans." (also `tests/safety/test_gitnexus_development_tooling.py:377-411`);
README `**Status:** Project 1 Stages 1-9 complete`; `_README_STAGE9_STATUS`,
`_VERIFICATION_STAGE9_STATUS`, `STAGE9_IMPLEMENTATION_COMMIT` (the Task 8
hash, asserted distinct from the Stage 4–8 hashes, present once in the roadmap
and absent from README and guide after the Stage 8 hash leaves them); the
Stage 8 forms turned into negatives — enumerated: `test_stage8_boundaries.py:977-978`
`_README_STAGE8_STATUS in readme` / `_VERIFICATION_STAGE8_STATUS in guide` →
`not in` (the blocks are replaced); `:984-985` `"Stages 1 through 8" in
roadmap` / `"Stages 1-8" in readme` → the Stage 9 forms (those strings exist
only at roadmap:3, :9 and README:3, all advanced); `:998-999` `"Stage 9 has
not started."` / `"Stage 9 is not started."` → the Stage 10 forms, with the
Stage 9 forms asserted absent; `test_stage7_boundaries.py:766-770` `"Stage 8
is complete"` in readme and guide, `"Stages 1-8"`, `"Stages 1 through 8"` →
the Stage 9 forms (`:983` `"Stage 8 complete" in roadmap` survives through
the Stage 7 row clause, `:230`); the containment literal advanced to
"Stage 10"; `_VERIFICATION_STAGE9_SENTENCE` (guide 603) retired with its pins
(`test_stage3_boundaries.py:1309-1311, 1522, 1564`); `_VERIFICATION_NON_GOALS`
unchanged (reading: records are not accounting); the Stage 8 completion row
clause `Stage 9 not started |` → `Stage 9 complete |`; `_STAGE9_DEFERRED_ROW`
turned negative and the Stage 10 deferred row (roadmap line 388) pinned
positive; `_LATER_STAGE_CLAIMS` advanced to Stage 10 forms;
`test_stage7_boundaries.py:771` and `test_stage5_boundaries.py:518-520`
advanced; the Stage 5 guard's `_README_STAGE8_STATUS` import →
`_README_STAGE9_STATUS`; roadmap line 258 "Planned" → "Approved" pinned
positive/negative in the Stage 9 guard. "exhaustiv" and "sandbox" stay absent.

**Unchanged by proof.** `DiagnosticCategory` (12), `RECOGNIZED_NATIVE_EXIT_VALUES`
(8), `STAGE5_DIAGNOSTIC_CODES` (6), `CommandKind` (3), the 96 run-state
products, every Stage 5 port member set, `STAGE5/6/7/8_SOURCE_FILES`,
`_ROOT_CONFINEMENT` (5; `os` is pinned by Task 4's tree-wide test and the Stage 9 guard, not added there),
the one `Popen` call, `_FAKE_ADAPTER_ROOTS`, GitNexus pins, the launcher
(`_EXPECTED_OPERATIONS` 21, `_EXPECTED_NORMALIZED_SHA256`, ReparsePoint 6),
the verifier (`_EXPECTED_VERIFIER_SHA256`, 10 profiles, 8 commands, 11 steps),
`pytest_options["pythonpath"]`, hatch `packages`/`force-include`, the
`[tool.ruff]` exclusion list, `tests/safety/test_forbidden_runtime_paths.py`
(every finalized store, staging, quarantine and log fixture lives under
`tmp_path`).

### 2.7 Toolchain gates

`ruff check` selects `B, DTZ, E, F, I, PT, RUF, S, UP` with `S101` ignored
under `tests/`: no `assert` in `src`; `PT011` needs `match=` on
`pytest.raises(ValueError)`; `RUF043` escapes regex metacharacters in
`match=`; `S108` forbids hard-coded temporary paths (every root comes from
`tmp_path`); `S324` is not triggered (`hashlib.sha256` only); isort treats
`contract < crypto_lab < doubles < persistence_support` as first-party.
Strict mypy covers `src`, `tests` and `scripts`: every `X | MISSING` value is
narrowed with `isinstance` before use; `async def finalize` awaits
`cooperative_checkpoint()` (§4.1: an awaitable whose `__await__` yields once,
the `asyncio.sleep(0)` shape, defined in `artifacts/finalizer.py` without
importing `asyncio`) at every phase boundary where it also polls the
cancellation token, so the coroutine has genuine suspension points — `RUF029`
(unused-async) is preview-only in the pinned ruff 0.16.2 and is not relied
on either way — and tests drive it through `_run(coroutine)` in
`tests/doubles/artifacts.py` (`send(None)` until `StopIteration`; no
`asyncio` import anywhere in the Stage 9 tree, so the Stage 7 confinement map
is untouched); `Result[...]` values are narrowed with `isinstance(result, Success)`.
`pytest-all` measures coverage over `crypto_lab` only. `pytest-focused`
accepts only `-o addopts=`, targets under `tests/` and a final `-q`. Every
new test file has a basename unique across `tests/`. Test function names stay
at or below 73 characters.

### 2.8 Dependency acquisition gates

None. Stage 9 adds no dependency; `lock-check` and `sync` are the only
bootstrap profiles used and both run offline. The two acquisition profiles are
never invoked.

---

## 3. Canonical additions and their storage (matrix A)

### 3.1 Records

Every record is a `CanonicalModel` with `schema_version: Literal["1.0.0"]`
unless marked nested. Field names follow 11.3 exactly; state-governed
presence follows 11.5.

| Record | Module | Fields (beyond `schema_version`) | Validators (each a focused test) |
|---|---|---|---|
| `CandidateArtifact` | `artifacts/models.py` | `candidate_artifact_id`, `owner: ArtifactOwnerRef`, `finalization_purpose`, `source_role`, `producer_kind`, `artifact_kind: NormalizedIdentifier`, `staging_relative_path: RelativeStagingPath`, `state`, `adapter_declared_size | MISSING`, `adapter_declared_hash | MISSING`, `adapter_declared_media_type | MISSING`, `validation_observations: tuple[ValidationObservation, ...]` (max 64), `source_event_id | MISSING`, `source_adapter_manifest_id | MISSING`, `created_at_utc`, `updated_at_utc`, `revision` | state ∈ five values; `ADAPTER` ⇒ owner `RUN` with `invocation_id`, purpose `RESULT`, role ∈ result roles, all three declared fields present; `CORE` ⇒ declared fields absent, `source_event_id` absent; role/purpose/owner table of §3.1.1; `source_adapter_manifest_id` absent at `CANDIDATE` unless producer `ADAPTER` and state ≥ `VALIDATING`; for `CORE` candidates `staging_relative_path` begins with `<correlation_kind>/<correlation_id>/` so the `(owner, purpose, path)` uniqueness of §3.3 holds across repeated correlations of one `ADAPTER`/`SYSTEM` owner; `QUARANTINED`/`CORRUPT` require ≥ 1 observation whose `error_code` is set; `updated_at ≥ created_at`; `revision ≥ 1`; immutable fields across `assert_candidate_transition(stored, replacement)` (`domain`-style): identity, owner, purpose, role, producer, kind, path, declared fields, `created_at_utc` |
| `ValidationObservation` (nested) | `artifacts/models.py` | `observed_at_utc`, `stage: Literal["PATH","SIZE","MEDIA","SCHEMA","REDACTION","HASH","SEMANTIC","MOVE"]`, `outcome: Literal["PASSED","FAILED"]`, `observed_size_bytes | MISSING`, `observed_sha256 | MISSING`, `error_code: ErrorCode | MISSING`, `diagnostic_id | MISSING` | `FAILED` ⇒ `error_code` present; `HASH` passed ⇒ size and hash present |
| `ArtifactRef` | `artifacts/models.py` | `artifact_id`, `owner`, `finalization_purpose`, `artifact_kind`, `finalized_relative_path: FinalizedRelativePath`, `content_hash: Sha256`, `size_bytes: int ≥ 0`, `media_type`, `source_role`, `source_candidate_artifact_id`, `producer_kind`, `validation_profile: Literal["artifact-validation/v1"]`, `created_at_utc`, `finalized_at_utc`, `state: Literal["FINALIZED"]` | every field required; `finalized_relative_path` matches `objects/<hh>/<64 hex>` and its hash segment equals `content_hash`; `EVIDENCE` ⇒ `producer_kind == CORE` and role ∈ evidence roles; `RESULT` ⇒ owner `RUN` and role ∈ result roles; `artifact_id == artifact_id_for(source_candidate_artifact_id, content_hash)`; `finalized_at ≥ created_at`; a `CandidateArtifact` JSON payload fails (`state`, `staging_relative_path` unknown) and vice versa |
| `CandidateFinalization` (nested) | `artifacts/models.py` | `candidate_artifact_id`, `artifact_id`, `content_hash`, `size_bytes`, `deduplicated: bool` | — |
| `FinalizationResult` | `artifacts/models.py` | `finalization_id`, `finalization_purpose`, `owner`, `journal_state: Literal["REGISTERED"]`, `candidate_to_artifact_refs: tuple[CandidateFinalization, ...]` (≥ 1, unique on both ids), `run_manifest_id | MISSING`, `run_manifest_hash | MISSING`, `registered_at_utc`, `replayed: bool` | `RESULT` ⇒ both manifest fields present; `EVIDENCE` ⇒ both absent |
| `ResultFinalizationRequest` | `artifacts/requests.py` | `finalization_purpose: Literal["RESULT"]`, `owner: RunArtifactOwner` (with `invocation_id`), `experiment_id`, `run_id`, `run_invocation_id`, `expected_run_revision`, `expected_invocation_revision`, `attempt_token_hash`, `source_adapter_result_manifest_hash`, `sanitized_adapter_result_manifest_hash`, `semantic_status: Literal["SUCCEEDED","SUCCEEDED_WITH_WARNINGS"]`, `candidate_artifact_ids` (1..256, sorted unique), `candidate_set_hash`, `finalization_timeout_seconds` (1..3600), `idempotency_key: Sha256` | owner ids equal the top-level ids; `candidate_set_hash == candidate_set_hash_for(ids)`; `idempotency_key == finalization_identity(...)` over the 17.2 tuple; any EVIDENCE-only field is unknown (`extra="forbid"`) |
| `EvidenceFinalizationRequest` | `artifacts/requests.py` | `finalization_purpose: Literal["EVIDENCE"]`, `owner: ArtifactOwnerRef`, `source_role` (evidence roles), `candidate_artifact_ids`, `candidate_set_hash`, `correlation: EvidenceCorrelation`, `idempotency_key` | role/owner table; `idempotency_key == finalization_identity(EVIDENCE, owner_hash, correlation.kind, correlation.id, candidate_set_hash)`; RESULT-only fields unknown |
| `EvidenceCorrelation` (nested) | `artifacts/requests.py` | `kind: Literal["INVOCATION","DIAGNOSTIC","AUDIT"]`, `invocation_id | MISSING`, `diagnostic_id | MISSING`, `audit_event_id | MISSING` | exactly the id matching `kind`; a bare string is not accepted (strict) |
| `FinalizationJournalEntry` | `artifacts/journal.py` | `finalization_id`, `finalization_purpose`, `owner`, `source_role`, `candidate_artifact_ids`, `candidate_set_hash`, `state: FinalizationJournalState`, `abandon_reason | MISSING`, `prepared_at_utc`, `finalization_deadline_utc | MISSING`, `lease_expires_at_utc`, `expected_run_revision | MISSING`, `expected_invocation_revision | MISSING`, `run_id | MISSING`, `run_invocation_id | MISSING`, `attempt_token_hash | MISSING`, `source_adapter_result_manifest_hash | MISSING`, `sanitized_adapter_result_manifest_hash | MISSING`, `correlation | MISSING`, `planned_paths: tuple[PlannedMove, ...]`, `observed: tuple[ObservedMove, ...]`, `updated_at_utc`, `revision` | `RESULT` ⇒ run/invocation/token/both manifest hashes/deadline/revisions present and `correlation` absent; `EVIDENCE` ⇒ the reverse; `MOVED`/`REGISTERED` ⇒ `observed` covers every planned move; `ABANDONED` ⇔ `abandon_reason`; `lease_expires_at ≤ finalization_deadline` when the latter exists; monotonic state order |
| `PlannedMove`, `ObservedMove` (nested) | `artifacts/journal.py` | `candidate_artifact_id`, `staging_relative_path`, `finalized_relative_path`, `expected_sha256`, `expected_size_bytes` / plus `observed_sha256`, `observed_size_bytes`, `deduplicated` | — |
| `ArtifactManifest` | `artifacts/manifest.py` | `artifact_id`, `artifact_kind`, `media_type`, `finalized_relative_path`, `size_bytes`, `content_hash`, `producer_kind`, `source_candidate_artifact_id`, `owner`, `finalization_purpose`, `source_role`, `lineage: ArtifactLineage`, `validation_profile`, `validation_diagnostic_ids: tuple[DiagnosticId, ...]`, `created_at_utc`, `finalized_at_utc`, `artifact_manifest_hash` | self-hash recomputed over the manifest with the field omitted (`ARTIFACT_MANIFEST_V1`); `finalized_relative_path` never a staging shape; `RUN` lineage carries `experiment_id`, `run_id`, `invocation_id | MISSING`; other variants prohibit them |
| `ArtifactLineage` (nested) | `artifacts/manifest.py` | `experiment_id | MISSING`, `run_id | MISSING`, `invocation_id | MISSING`, `source_event_id | MISSING`, `source_adapter_manifest_id | MISSING`, `source_hash | MISSING`, `superseded_artifact_id | MISSING` | owner-variant presence rules (19.4:1421, 20.2:1456) |
| `MetricValue` | `domain/metrics.py` | `metric_name: NormalizedIdentifier`, `value: CanonicalDecimal | MISSING`, `value_type: MetricValueType` (`DECIMAL`, `COUNT`, `RATIO`, `DURATION_SECONDS`), `unit: NormalizedIdentifier`, `methodology_version: SemanticVersion`, `sampling_convention: NormalizedIdentifier`, `comparison_level: ComparisonLevel`, `status: MetricStatus` (`DEFINED`, `UNDEFINED`, `NOT_COMPUTED`), `source_artifact_id: ArtifactId` | `DEFINED` ⇔ `value` present; no float accepted |
| `NormalizedResultProvenance` | `experiments/run_manifest.py` | `experiment_id`, `experiment_spec_hash`, `run_id`, `attempt_number`, `attempt_token_hash`, `invocation_id`, `engine: EngineIdentity`, `adapter: AdapterIdentity`, `converter_name`, `converter_version`, `source_artifact_id`, `source_artifact_hash`, `canonical_schema_version`, `protocol_version`, `strategy_version_hash`, `dataset_version_hash`, `approximations`, `normalized_at_utc`, `validation_profile` | all twelve 20.2 items required |
| `RunManifest` | `experiments/run_manifest.py` | `protocol_version`, `manifest_id: RunManifestId`, `experiment_id`, `run_id`, `run_invocation_id`, `attempt_token_hash`, `sanitized_adapter_result_manifest_hash`, `semantic_status` (two success values), `process_exit_category: ProcessExitCategory`, `started_at_utc`, `completed_at_utc`, `provenance: RunProvenance`, `artifact_refs: tuple[ArtifactRef, ...]` (≥ 1), `metrics: tuple[MetricValue, ...]`, `diagnostics: tuple[DiagnosticId, ...]`, `warnings`, `approximations`, `run_manifest_hash` | every ref: `owner.owner_kind == "RUN"`, `owner.experiment_id/run_id` equal the manifest's, purpose `RESULT`, role ∈ result roles; a candidate payload, a non-`RUN` owner, an `EVIDENCE` ref or a mismatched run fails; `manifest_id == run_manifest_id_for(run_id, run_invocation_id)`; `run_manifest_hash` recomputed with itself omitted (`RUN_MANIFEST_V1`); `SUCCEEDED_WITH_WARNINGS` ⇔ `warnings` non-empty |
| `AuditEvent` | `audit/models.py` | `audit_event_id`, `action: AuditAction`, `actor: AuditActor`, `outcome: AuditOutcome` (`SUCCEEDED`, `REFUSED`, `FAILED`), `experiment_id | MISSING`, `run_id | MISSING`, `invocation_id | MISSING`, `artifact_id | MISSING`, `timestamp_utc`, `correlation_id: CorrelationId`, `details_hash`, `details: BoundedDetails` | command-lifecycle, protocol, event-ingest and command-produced-artifact actions ⇒ `invocation_id`; `details_hash == profile_hash(AUDIT_EVENT_DETAILS_V1, details)`; details pass `redact_details` fixed-point (no raw-token-shaped value, no denylisted key); bounded by the Stage 3 detail ceilings |
| `AuditActor` (nested) | `audit/models.py` | `kind: Literal["LOCAL_USER","CORE","ADAPTER"]`, `adapter_name | MISSING`, `adapter_version | MISSING` | `ADAPTER` ⇔ both present |
| `LogRecord` | `audit/models.py` | `timestamp_utc`, `severity: LogSeverity`, `component`, `event_code: ErrorCode`, `correlation_id`, `experiment_id | MISSING`, `run_id | MISSING`, `invocation_id | MISSING`, `adapter | MISSING`, `engine | MISSING`, `message: BoundedMessage`, `details: BoundedDetails` | redaction fixed point |
| Normalized records (Task 3) | `domain/normalized.py` | per 11.3:579-584 with `experiment_id`, `run_id`, `source_artifact_id`; `CanonicalOrder.limit_price` present ⇔ `order_type == LIMIT`; `PositionSnapshot.average_entry_price` absent ⇔ zero quantity; `Fee(amount: Money, source_artifact_id)`; `EquityPoint` ratios Decimal | long-only: `quantity ≥ 0`, `side ∈ {BUY, SELL}`, `position_effect` consistent with side; no float |

#### 3.1.1 Purpose, producer, owner and role table (single authority)

| `finalization_purpose` | `producer_kind` | `source_role` | permitted `owner_kind` | correlation |
|---|---|---|---|---|
| `RESULT` | `ADAPTER` | `ENGINE_NATIVE_RESULT` | `RUN` (with `invocation_id`) | the run-command invocation |
| `RESULT` | `CORE` | `NORMALIZED_RESULT` | `RUN` (with `invocation_id`) | the run-command invocation |
| `EVIDENCE` | `CORE` | `CORE_EVIDENCE` | `RUN`, `SYSTEM`; `ADAPTER` only with an `INVOCATION` correlation naming a `DESCRIBE` invocation (describe stderr, 23.3.1:1703; enforced in finalizer phase 0, §4.3) | `INVOCATION`, `DIAGNOSTIC` or `AUDIT` |
| `EVIDENCE` | `CORE` | `ADAPTER_DESCRIPTOR_EVIDENCE` | `ADAPTER` | `INVOCATION` (the describe invocation) |
| `EVIDENCE` | `CORE` | `DATASET_INPUT` | `DATASET` | `AUDIT` or `DIAGNOSTIC` |
| `EVIDENCE` | `CORE` | `STRATEGY_INPUT` | `STRATEGY` | `AUDIT` or `DIAGNOSTIC` |
| `EVIDENCE` | `CORE` | `EXPERIMENT_INPUT` | `EXPERIMENT` | `AUDIT` or `DIAGNOSTIC` |

Every other combination is rejected by `CandidateArtifact`, by both request
models, by the `candidate_artifacts` CHECK, and by the property test of §7.3
(the cross-product generator enumerates all 2 × 2 × 7 × 6 (purpose, producer,
role, owner) tuples and asserts that exactly the nine tuples of these seven
rows validate — row 3 contributes three, every other row one — and
`test_exactly_seven_rows_validate` asserts the tuple count `9` explicitly). An `ADAPTER` producer with
purpose `EVIDENCE`, any role, is the 24.3:1776 refusal.

### 3.2 Enums, identities, profiles and schema entries

Enums (`artifacts/models.py` unless noted): `CandidateArtifactState`
(`CANDIDATE`, `VALIDATING`, `FINALIZING`, `QUARANTINED`, `CORRUPT`),
`CandidateArtifactProducerKind` (`ADAPTER`, `CORE`),
`ArtifactFinalizationPurpose` (`RESULT`, `EVIDENCE`), `ArtifactSourceRole`
(`ENGINE_NATIVE_RESULT`, `NORMALIZED_RESULT`, `CORE_EVIDENCE`,
`ADAPTER_DESCRIPTOR_EVIDENCE`, `DATASET_INPUT`, `STRATEGY_INPUT`,
`EXPERIMENT_INPUT`) with `RESULT_ROLES`/`EVIDENCE_ROLES` frozensets,
`ArtifactOwnerKind` (`RUN`, `EXPERIMENT`, `DATASET`, `STRATEGY`, `ADAPTER`,
`SYSTEM`; `owner_kind_of(owner) -> ArtifactOwnerKind` maps the existing
literal discriminators), `FinalizationJournalState` (`artifacts/journal.py`:
`PREPARED`, `MOVED`, `REGISTERED`, `ABANDONED`), `MetricValueType`,
`MetricStatus` (`domain/metrics.py`), `AuditAction` (`audit/models.py`,
closed set of 25 actions: `ARTIFACT_CANDIDATE_REGISTERED`,
`ARTIFACT_VALIDATED`, `ARTIFACT_VALIDATION_FAILED`, `ARTIFACT_OWNER_PURPOSE_SELECTED`,
`FINALIZATION_LEASE_ACQUIRED`, `FINALIZATION_LEASE_REFUSED`,
`FINALIZATION_PREPARED`, `FINALIZATION_MOVED`, `FINALIZATION_REGISTERED`,
`FINALIZATION_REPLAYED`, `FINALIZATION_ABANDONED`, `FINALIZATION_TIMED_OUT`,
`ARTIFACT_QUARANTINED`, `ARTIFACT_CORRUPT`, `ARTIFACT_LEAKAGE_DETECTED`,
`RUN_SUCCEEDED`, `RUN_FAILED` (the finalization-side `RUNNING → FAILED` write
of §4.4 step 3 and of a failed 29.3 recovery check; 30.3 bullet 4 "terminal
transition"), `RUN_MANIFEST_REGISTERED`, `STDERR_TRUNCATED`,
`STDERR_EVIDENCE_LINKED`, `RECONCILIATION_FINALIZATION_RESUMED`,
`RECONCILIATION_CANDIDATE_QUARANTINED`, `RECONCILIATION_ORPHAN_QUARANTINED`,
`RETENTION_DELETED`, `QUARANTINE_OVERDUE`), `AuditOutcome`, `LogSeverity`
(`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`), `OrderSide`, `OrderType`,
`PositionEffect` (`domain/normalized.py`).

Identities (`domain/identifiers.py`, same helper as `ArtifactId`):
`FinalizationId` prefix `fin_`, `RunManifestId` prefix `rmf_`. Derivations
(`domain/hashing.py`, the `candidate_artifact_id_for` pattern): `artifact_id_for`,
`finalization_id_for`, `run_manifest_id_for`, `core_candidate_artifact_id_for`,
`candidate_set_hash_for(ids) -> Sha256` (`CANDIDATE_SET_V1` over the sorted
tuple), `finalization_identity(...) -> Sha256` (`FINALIZATION_IDENTITY_V1` over
the purpose-specific 17.2 tuple, used as `idempotency_key` and to derive
`finalization_id`).

New `HashingProfile` members, in order: `ARTIFACT_IDENTITY_V1`,
`ARTIFACT_MANIFEST_V1`, `CANDIDATE_SET_V1`, `FINALIZATION_IDENTITY_V1`,
`CORE_CANDIDATE_IDENTITY_V1` (Task 1), `AUDIT_EVENT_DETAILS_V1` (Task 2),
`RUN_MANIFEST_V1`, `RUN_MANIFEST_IDENTITY_V1` (Task 7). Self-hash exclusion is
by named profile only (10.2:462); no existing profile changes.

Schema entries appended to `SCHEMA_DEFINITIONS` in this order (positions
35–53), each `urn:crypto-lab:schema:<group>:<name>:1.0.0` and rendered in
serialization mode exactly as the 35 existing files:

| Pos | Path | Adapted type | Task |
|---|---|---|---|
| 35 | `artifacts/candidate-artifact-v1.schema.json` | `CandidateArtifact` | 1 |
| 36 | `artifacts/artifact-ref-v1.schema.json` | `ArtifactRef` | 1 |
| 37 | `artifacts/artifact-finalization-purpose-v1.schema.json` | `TypeAdapter[ArtifactFinalizationPurpose]` | 1 |
| 38 | `artifacts/artifact-manifest-v1.schema.json` | `ArtifactManifest` | 1 |
| 39 | `artifacts/result-finalization-request-v1.schema.json` | `ResultFinalizationRequest` | 1 |
| 40 | `artifacts/evidence-finalization-request-v1.schema.json` | `EvidenceFinalizationRequest` | 1 |
| 41 | `artifacts/finalization-result-v1.schema.json` | `FinalizationResult` | 1 |
| 42 | `artifacts/finalization-journal-entry-v1.schema.json` | `FinalizationJournalEntry` | 1 |
| 43 | `audit/audit-event-v1.schema.json` | `AuditEvent` | 2 |
| 44 | `audit/log-record-v1.schema.json` | `LogRecord` | 2 |
| 45 | `domain/metric-value-v1.schema.json` | `MetricValue` | 2 |
| 46 | `domain/canonical-order-v1.schema.json` | `CanonicalOrder` | 3 |
| 47 | `domain/canonical-fill-v1.schema.json` | `CanonicalFill` | 3 |
| 48 | `domain/fee-v1.schema.json` | `Fee` | 3 |
| 49 | `domain/position-snapshot-v1.schema.json` | `PositionSnapshot` | 3 |
| 50 | `domain/portfolio-snapshot-v1.schema.json` | `PortfolioSnapshot` | 3 |
| 51 | `domain/equity-point-v1.schema.json` | `EquityPoint` | 3 |
| 52 | `experiments/run-manifest-v1.schema.json` | `RunManifest` | 7 |
| 53 | `experiments/normalized-result-provenance-v1.schema.json` | `NormalizedResultProvenance` | 7 |

Every state-governed rule above that Draft 2020-12 cannot express as a plain
property set is published as `if`/`then` where the Stage 6 precedent
(`json_schema_extra` reusing emitted `$ref`s) allows and is otherwise
recorded in the guide's inexpressible-rules register by Task 9, exactly as
Stage 5–8 did; the register is a maintained enumeration, not a closure claim.

### 3.3 Tables (revision `r0002_stage9_artifacts`, Task 5)

Conventions as Stage 8 §3.2: identities `TEXT` with prefix CHECKs,
timestamps integer microseconds, hashes 64-hex CHECK, enums text CHECK,
`NULL ⇔ MISSING`, canonical JSON snapshot columns beside their SHA-256.
`owner_hash` is the foreign key to `artifact_owners(owner_hash)` (O-11).

| Table | Columns (key ones) | Constraints | Indexes |
|---|---|---|---|
| `candidate_artifacts` | `candidate_artifact_id` PK, `owner_hash` FK RESTRICT, `finalization_purpose`, `source_role`, `producer_kind`, `artifact_kind`, `staging_relative_path`, `state`, `adapter_declared_size`, `adapter_declared_hash`, `adapter_declared_media_type`, `observations_json`, `observations_hash`, `source_event_id`, `source_adapter_manifest_id`, `run_id`, `invocation_id` (denormalized from a `RUN` owner for the FK), `created_at_utc`, `updated_at_utc`, `revision` | CHECK state ∈ 5; CHECK the seven rows of §3.1.1 over (`purpose`, `producer`, `role`) joined to the owner variant via a trigger (owner kind is on `artifact_owners`; nine tuples — row 3's `ADAPTER` owner is admitted here and its `DESCRIBE` correlation is enforced in finalizer phase 0 — the `INVOCATION` correlation's row is loaded and must be a `DESCRIBE` invocation of that adapter, a fact the request model cannot see (§4.3) — and again by reading 10's trigger at link time); CHECK `ADAPTER` ⇒ declared columns non-null and `run_id`/`invocation_id` non-null; CHECK `CORE` ⇒ declared columns null; FK `(run_id, invocation_id)` → `command_invocations` RESTRICT when non-null | UNIQUE `(owner_hash, finalization_purpose, staging_relative_path)`; `(state)`, `(owner_hash, finalization_purpose)`, `(source_role)`, `(run_id)` |
| `artifact_refs` | `artifact_id` PK, `owner_hash` FK RESTRICT, `finalization_purpose`, `source_role`, `producer_kind`, `artifact_kind`, `finalized_relative_path`, `content_hash`, `size_bytes`, `media_type`, `source_candidate_artifact_id` FK RESTRICT NOT NULL, `validation_profile`, `manifest_json`, `artifact_manifest_hash`, `created_at_utc`, `finalized_at_utc`, `state` | CHECK `state = 'FINALIZED'`; CHECK `EVIDENCE ⇒ producer_kind = 'CORE' AND source_role ∈ evidence roles`; CHECK `RESULT ⇒ source_role ∈ result roles`; trigger `artifact_refs_match_candidate` (owner, purpose, role, producer equal the candidate row; candidate `state = 'FINALIZING'`) | UNIQUE `source_candidate_artifact_id`; UNIQUE `artifact_manifest_hash`; `(content_hash)` (not unique: dedup, reading 21); `(owner_hash, finalization_purpose, source_role)`; `(finalized_relative_path, source_candidate_artifact_id)` unique |
| `run_artifacts` | `run_id`, `artifact_id`, `link_role` (`RESULT_MANIFEST_MEMBER`, `RUN_EVIDENCE`), `experiment_id`, `run_manifest_id` nullable | PK `(run_id, artifact_id, link_role)`; FK run → `engine_runs` RESTRICT; FK artifact → `artifact_refs` RESTRICT; trigger `run_artifacts_target_run_owner` (the ref's owner is `RUN` with the same `run_id`/`experiment_id`; `RESULT_MANIFEST_MEMBER` ⇒ ref purpose `RESULT` and `run_manifest_id` non-null and existing; `RUN_EVIDENCE` ⇒ purpose `EVIDENCE`) | `(artifact_id)`, `(link_role)`, `(run_manifest_id)` |
| `run_manifests` | `manifest_id` PK, `run_id` UNIQUE, `experiment_id`, `run_invocation_id`, `attempt_token_hash`, `sanitized_adapter_result_manifest_hash` FK → `sanitized_adapter_result_manifests`, `semantic_status`, `process_exit_category`, `manifest_json`, `run_manifest_hash` UNIQUE, `registered_at_utc` | CHECK semantic ∈ two success values; trigger `run_manifests_require_running_run` (reading 11); FK `(run_id, run_invocation_id)` → `command_invocations` RESTRICT | `(experiment_id)`, `(run_invocation_id)` |
| `finalization_journal` | `finalization_id` PK, `finalization_purpose`, `owner_hash` FK, `source_role`, `candidate_ids_json`, `candidate_set_hash`, `state`, `abandon_reason`, `prepared_at_utc`, `finalization_deadline_utc`, `lease_expires_at_utc`, `expected_run_revision`, `expected_invocation_revision`, `run_id`, `run_invocation_id`, `attempt_token_hash`, `source_adapter_result_manifest_hash`, `sanitized_adapter_result_manifest_hash`, `correlation_kind`, `correlation_id`, `planned_json`, `observed_json`, `updated_at_utc`, `revision` | CHECK state ∈ 4; CHECK `RESULT ⇒ run columns, hashes, deadline, revisions non-null AND correlation null`; CHECK `EVIDENCE ⇒ reverse`; CHECK `ABANDONED ⇔ abandon_reason`; trigger `finalization_journal_monotonic` (state order, `finalization_deadline_utc` immutable, `lease_expires_at_utc ≤ deadline`) | UNIQUE partial `(run_invocation_id, source_adapter_result_manifest_hash) WHERE purpose='RESULT'`; UNIQUE partial `(run_id) WHERE purpose='RESULT' AND state IN ('PREPARED','MOVED')` (one active RESULT lease per attempt, 23.3:1688); UNIQUE partial `(owner_hash, correlation_kind, correlation_id, candidate_set_hash) WHERE purpose='EVIDENCE'`; `(state, lease_expires_at_utc)`, `(finalization_deadline_utc)`, `(owner_hash)`, `(source_role)` |
| `audit_events` | `audit_sequence` INTEGER PK AUTOINCREMENT, `audit_event_id` UNIQUE, `action`, `actor_kind`, `actor_adapter_name`, `actor_adapter_version`, `outcome`, `experiment_id`, `run_id`, `invocation_id`, `artifact_id`, `timestamp_utc`, `correlation_id`, `details_json`, `details_hash` | CHECK action ∈ 25; no FK (references never cascade, 23.3.1:1714; a referenced run may be absent only for `SYSTEM`-correlated events, enforced by the sink's ingress validation); trigger `audit_events_append_only` (UPDATE/DELETE abort) | `(correlation_id)`, `(experiment_id)`, `(run_id)`, `(invocation_id)`, `(action)`, `(timestamp_utc)` |
| `sanitized_adapter_result_manifests` | `sanitized_adapter_result_manifest_hash` PK, `run_id`, `run_invocation_id`, `experiment_id`, `attempt_token_hash`, `source_adapter_result_manifest_hash`, `semantic_status`, `manifest_json`, `evidence_artifact_id` nullable FK → `artifact_refs` RESTRICT, `recorded_at_utc` | FK `(run_id, run_invocation_id)` → `command_invocations`; trigger `sanitized_manifest_evidence_is_run_evidence` (when `evidence_artifact_id` set: purpose `EVIDENCE`, owner `RUN` same run); CHECK `instr(manifest_json, '"attempt_token":') = 0 AND instr(manifest_json, '"relative_path":') = 0` — the quoted key with its colon as canonical JSON renders it, so the legitimate `attempt_token_hash` key is not matched (string CHECK on canonical text) | UNIQUE `(run_id, run_invocation_id, source_adapter_result_manifest_hash)`; `(semantic_status)` |
| `adapter_validation_results` | `invocation_id` PK FK → `command_invocations` RESTRICT, `run_id`, `experiment_id`, `validation_result_hash` UNIQUE, `outcome`, `result_json`, `evidence_artifact_id` nullable FK, `recorded_at_utc` | trigger `validation_result_invocation_is_validate` (command kind `VALIDATE`, run equal) | `(run_id, outcome)` |
| `engine_runs` (altered) | `+ finalization_deadline_utc` INTEGER NULL | trigger `engine_runs_deadline_immutable` (non-null never changes); trigger `engine_runs_success_requires_manifest` (reading 11) | `(finalization_deadline_utc)` partial `WHERE NOT NULL` |

### 3.4 Triggers (created by `r0002`, asserted by Task 5)

`candidate_artifacts_owner_role_combination`, `candidate_artifacts_immutable_fields`
(identity, owner, purpose, role, producer, kind, path, declared columns,
`created_at_utc` never change), `candidate_artifacts_terminal_frozen`
(`QUARANTINED`/`CORRUPT` rows never update except `revision`-less no-ops
refused), `artifact_refs_match_candidate`, `artifact_refs_insert_only`,
`run_artifacts_target_run_owner`, `run_artifacts_member_requires_manifest`,
`run_manifests_require_running_run`, `run_manifests_insert_only`,
`engine_runs_success_requires_manifest`, `engine_runs_deadline_immutable`,
`finalization_journal_monotonic`, `audit_events_append_only`,
`sanitized_manifest_evidence_is_run_evidence`,
`validation_result_invocation_is_validate`,
`command_invocations_stderr_targets_core_evidence` (reading 10). Each has a
refusal test through a raw connection and classifies as
`CORE.INVARIANT_VIOLATION`.

### 3.5 Invariant → enforcing layer

| Invariant | Model | Repository | Table/trigger | Finalizer/recovery | Test |
|---|---|---|---|---|---|
| Candidate ≠ reference (disjoint shapes, states, paths) | both models reject the other's payload | separate repositories, no cross-method | separate tables; `artifact_refs.state='FINALIZED'` | `record_finalization` is the only ref writer | `test_artifact_models.py`, `test_artifact_type_separation.py` |
| Exactly one owner variant | `ArtifactOwnerRef` (existing) | ingress/egress through `ARTIFACT_OWNER_ADAPTER` | `artifact_owners` CHECKs (existing) | revalidated at every boundary | `test_ownership.py` (existing), `test_owner_variants_end_to_end` (Task 8) |
| Purpose/producer/owner/role rows | `CandidateArtifact`, requests | `add` re-validates | CHECK + owner-join trigger | request validation before any I/O | `test_purpose_role_cross_products.py` |
| RESULT needs active run + invocation + success + lease | request | `acquire_result_lease` CAS | journal partial unique; `run_manifests` trigger | step 1 | `test_artifact_finalizer.py`, `test_finalization_races.py` |
| EVIDENCE never mutates a run | request has no run revision | registrar has no run access | no trigger touches `engine_runs` for EVIDENCE | revision-unchanged pin | `test_finalization_races.py::RC-9` |
| Success ⇔ manifest | `RunManifest` | registrar order | reading 11 triggers | step 4 | `test_sqlite_artifact_schema.py`, `test_finalization_service.py` |
| Deadline immutable, never extended by renewal | journal model | `renew_lease` refuses beyond deadline | trigger | monotonic poll + REGISTERED check | `test_sqlite_finalization_deadline.py` |
| Idempotent identities disjoint | derived ids | unique partial indexes | — | replay path | `test_finalization_idempotency.py` |
| No raw token anywhere | redaction fixed point | — | CHECK on `manifest_json` | scanner before PREPARED | `test_stage9_token_absence.py` |
| Confinement before open, recheck before hash/move | `RelativeStagingPath` | — | — | `confine_candidate_path` twice | `test_artifact_paths.py`, property |
| No transaction across I/O | — | — | — | four-transaction protocol | `max_open == 0` in `test_artifact_finalizer.py` |

---

## 4. Finalizer, journal, lease and port contracts (matrix B)

### 4.1 Ports (`artifacts/ports.py`, Task 6; `audit/sink.py`, Task 2)

Signatures are the 8.2:320-354 forms; every method returns `Result[...]`
with the Stage 8 failure vocabulary (`CORE.INVARIANT_VIOLATION` containing
`does not exist` for a missing identity, `PERSISTENCE.CONCURRENCY_CONFLICT`
for a lost swap, duplicate identity or busy timeout; never an exception).

```text
CandidateArtifactRepository.get(candidate_artifact_id) -> Result[CandidateArtifact]
CandidateArtifactRepository.add(record) -> Result[None]
CandidateArtifactRepository.compare_and_swap(expected_revision, replacement) -> Result[CandidateArtifact]
CandidateArtifactRepository.list_recoverable(states, owner, purpose, limit) -> Result[tuple[CandidateArtifact, ...]]
    # excludes FINALIZING candidates that have an artifact_refs row (19.1:1358)

ArtifactRepository.get(artifact_id) -> Result[ArtifactRef]
ArtifactRepository.list_by_owner(owner, purpose) -> Result[tuple[ArtifactRef, ...]]
ArtifactRepository.record_finalization(result: FinalizationResult) -> Result[tuple[ArtifactRef, ...]]
    # inserts the refs and manifests the registrar staged on the transaction; the
    # only writer of artifact_refs; refuses when any source candidate is not FINALIZING

FinalizationJournalRepository.get(finalization_id) -> Result[FinalizationJournalEntry]
FinalizationJournalRepository.prepare(entry) -> Result[None]          # PREPARED insert
FinalizationJournalRepository.compare_and_swap(expected_revision, replacement) -> Result[FinalizationJournalEntry]
FinalizationJournalRepository.list_open(purpose, limit) -> Result[tuple[FinalizationJournalEntry, ...]]
FinalizationJournalRepository.find_result_identity(run_invocation_id, source_hash) -> Result[FinalizationJournalEntry | MISSING]
FinalizationJournalRepository.find_evidence_identity(owner_hash, kind, correlation_id, set_hash) -> Result[FinalizationJournalEntry | MISSING]

ResultLeaseRepository.active_attempt_facts(run_id, run_invocation_id) -> Result[ResultLeaseFacts]
    # RUNNING run, EXITED run-command invocation, latest attempt of its slot,
    # experiment RUNNING, captured exit facts; a value object of revisions and categories
ResultLeaseRepository.snapshot_deadline(expected_run_revision, run_id, deadline_utc) -> Result[EngineRunRecord]
ResultLeaseRepository.record_timeout(expected_run_revision, run_id, diagnostic) -> Result[EngineRunRecord]

PurposeRegistrar.register_result(transaction: RegistrationUnitOfWork, journal, refs, facts) -> Result[ResultRegistration]
    # experiments/finalization.py (Task 7): RunManifest, run_manifests row, member
    # links, sanitized facts, run CAS RUNNING -> SUCCEEDED*, audit facts -- all on
    # the open T3 the finalizer passes in
PurposeRegistrar.register_evidence(transaction: RegistrationUnitOfWork, journal, refs) -> Result[None]
    # evidence links (RUN owners only), stderr_artifact_id enrichment when the
    # correlation names a stderr capture, audit facts
ResultRecoveryValidator.validate_temporary_manifest(roots: CommandRootPaths, token: AttemptTokenMaterial | MISSING, candidates) -> Result[ResultRecoveryFacts]
    # experiments/finalization.py (Task 7): narrows roots by isinstance (work_dir and
    # result_path present -- a RUN root; anything else is CORE.INVARIANT_VIOLATION),
    # then the 29.3 checks over parse_result_manifest,
    # sanitize_result_manifest and reconcile_run -- adapter types artifacts may not
    # import; ResultRecoveryFacts is domain-typed (ids, hashes, semantic status,
    # per-candidate observations); artifacts/recovery.py calls it through the port

AuditSink.append(event: AuditEvent) -> Result[None]
AuditEventIds.new_audit_event_id() -> AuditEventId

async ArtifactFinalizer.finalize(request, cancellation) -> Result[FinalizationResult]
cooperative_checkpoint() -> Awaitable[None]
    # artifacts/finalizer.py: an object whose __await__ yields exactly once (the
    # asyncio.sleep(0) shape); awaited at every phase boundary beside the
    # cancellation poll; no asyncio import
CommandRootPaths(command_root: Path, request_path: Path, output_path: Path | MISSING, work_dir: Path | MISSING, result_path: Path | MISSING)
    # artifacts/ports.py: the domain-typed projection of the Stage 7 CommandPaths
    # the caller builds; artifacts never imports process_supervision. The shape is
    # kind-governed exactly as CommandPaths (roots.py:135-155; plan_command_paths
    # :222-261): a DESCRIBE or VALIDATE root carries output_path (output.json, the
    # adapter's typed describe/validate output written via --output, spec
    # 880-896; no token carrier) with work_dir and result_path MISSING, a RUN
    # root carries
    # work_dir and result_path with output_path MISSING; the validator restates
    # "output_path present exactly when work_dir is absent" and "work_dir and
    # result_path present together". Consumers narrow by isinstance: the RESULT
    # recovery validator and the RESULT branch require a RUN root; close_raw_bytes
    # removes request_path, output_path when present and, for a RUN root,
    # result_path
ContentHasher.sha256_stream(source: BinaryIO) -> Sha256
ContentHasher.sha256_and_scan(source: BinaryIO, token: AttemptTokenMaterial | MISSING) -> HashScan
    # HashScan(sha256, size_bytes, token_found: bool, identity_before, identity_after)
```

`FinalizationUnitOfWork` (`artifacts/ports.py`) is a Protocol with members
`candidate_artifacts`, `artifact_refs`, `finalization_journal`,
`result_leases`, `diagnostics_writer` (`DiagnosticRecorder`-shaped, in
transaction), `audit` (`AuditSink`), `begin()`, `commit()`, `rollback()`;
`SqliteTransaction` satisfies it structurally after Task 5 and the in-memory
`MemoryFinalizationUnitOfWork` in `tests/doubles/artifacts.py` satisfies it
for the unit tests. `RegistrationUnitOfWork(FinalizationUnitOfWork, Protocol)`
(`artifacts/ports.py`) adds the members the RESULT registrar writes inside T3
— `engine_runs` (`get(run_id) -> Result[EngineRunRecord]` and
`compare_and_swap(expected_revision, replacement: EngineRunRecord)`),
`command_invocations` (`get(invocation_id) -> Result[CommandInvocationRecord]`
and `compare_and_swap` over `CommandInvocationRecord`),
`run_manifests`, `sanitized_manifests`, `validation_results`, `run_artifacts`
— each typed over domain records, canonical bytes, hashes and identifiers
(`RunManifestFacts`), never over `RunManifest`, `ManifestParse` or
`experiments.ports` types, so `artifacts` stays domain-only; `SqliteTransaction`
satisfies it structurally after Task 5 (the Task 5 member list) and the memory
double after Task 6. The Stage 5 `experiments.UnitOfWork` is not widened. The
two `get`s are the domain-typed reads the Stage 5 ports already declare
(`experiments/ports.py:124`, `adapters/ports.py:34`) and `SqliteTransaction`
already exposes (`persistence/unit_of_work.py:435-444`,
`persistence/repositories.py:925`), so Task 5 adds nothing for them; the
step-9 sweep of §4.3 phase 6 needs them per `inv_` root — the invocation's
`command_kind` and its run's state — because `active_attempt_facts` requires
a `RUNNING` run and `command_roots`/`token_material` return paths and
material, not facts; the memory double (Task 6, §7.1) implements both over
its planted records.

### 4.2 Finalizer construction

`CoreArtifactFinalizer(unit_of_work_factory, clock, hasher, store, probe,
registrar, audit_ids)` where `store = ArtifactStore.open(staging_root,
artifacts_root, quarantine_root)` runs the 22.5 preflight (same volume,
no reparse point on or above either root, drive-lettered absolute roots) and
returns `Failure(PROCESS.PATH_PREFLIGHT_REJECTED)` otherwise — nothing is
queued. The finalizer holds no state between calls; every `finalize` call
derives its identities from the request, so two calls with equal requests
are replays.

### 4.3 The journal protocol (single authority; 19.2 steps 1–9, 23.3.1:1719-1723)

| Phase | Transaction | Work | Probe point | Failure handling |
|---|---|---|---|---|
| 0 Pre-validation | none | request validated; `cancellation.is_cancellation_requested()` ⇒ `PROCESS.CANCELLED` refusal; candidates loaded in a read-only transaction and released; owner revalidated (`artifact_owner_hash` equals the stored row; an `ADAPTER` owner with `CORE_EVIDENCE` requires the `INVOCATION` correlation to name a `DESCRIBE` invocation of that adapter — §3.1.1 row 3); each path confined (`confine_candidate_path`, reading 19), `lstat` identity recorded | — | refusal diagnostics, candidate `CANDIDATE → QUARANTINED` in a short transaction when the candidate itself is at fault (`PATH_BOUNDARY_VIOLATION`, `VALIDATION_FAILED`, `SENSITIVE_MATERIAL_LEAKAGE`), nothing else written |
| 1 Validate + hash | none | `CANDIDATE → VALIDATING` (short transaction per candidate, then closed); size against declared and ceilings; media type; schema for JSON kinds; `sha256_and_scan` with the token from `AttemptTokenMaterial` (RESULT only; EVIDENCE scans with the run's hash-less redaction check of `audit.redaction.contains_token_shape`); declared hash equality for `ADAPTER` candidates; handle identity before/after equal; the `ArtifactManifest` facts are fixed here — 19.2 step 4: finalized path, hash and size carried as `planned` (§3.1 `PlannedMove`), `artifact_id_for` derivable from the planned candidate id and hash, media type and lineage read from the immutable candidate row | `before_prepared` | failure ⇒ `VALIDATING → QUARANTINED` (or `CORRUPT` for hash/size mismatch and mutation during hashing) with observation and diagnostic; RESULT ⇒ `Failure` to the caller who fails the run (§4.4 "refusal") |
| 2 PREPARED | T1 | RESULT: `active_attempt_facts`, `latest_attempt` predicate (reading 4), semantic facts equal the request, `find_result_identity` replay check, `snapshot_deadline` (run CAS writing `finalization_deadline_utc = now + timeout`); EVIDENCE: `find_evidence_identity` replay check; both: candidates `VALIDATING → FINALIZING`, `prepare(PREPARED)` with `lease_expires_at = now + timeout` (RESULT: the request's `finalization_timeout_seconds`; EVIDENCE: the compiled `EVIDENCE_LEASE_SECONDS = 300` of `artifacts/finalizer.py` — no configuration key and no deadline, reading 13), audit `FINALIZATION_LEASE_ACQUIRED`/`FINALIZATION_PREPARED`; commit | `after_prepared` | replay found `REGISTERED` ⇒ return the stored `FinalizationResult` with `replayed=True`, no write (29.6); found `PREPARED`/`MOVED` with unexpired lease ⇒ `PERSISTENCE.CONCURRENCY_CONFLICT` (RC-12); expired ⇒ the request takes over under the same `finalization_id` (recovery path); lost run CAS ⇒ `FINALIZATION_LEASE_REFUSED`, no journal row |
| 3 Move | none | deadline poll (monotonic); for each planned move in sorted candidate order: recheck confinement and identity, `fsync`, `atomic_move` into `objects/<hh>/<hash>` (dedup per reading 21), probe between moves | `before_move(i)`, `after_move(i)` | an existing-target with different hash ⇒ `CORE.INVARIANT_VIOLATION`; `PermissionError`/`OSError` ⇒ `ARTIFACT.MOVE_FAILED` (new code; category `PERSISTENCE`, retriable `False`, the `PERSISTENCE.WRITE_FAILED` posture — reading 26); on any failure the journal goes `ABANDONED` in a short transaction, moved files are quarantined, candidates `FINALIZING → QUARANTINED`; deadline passed ⇒ §4.5 timeout path |
| 4 MOVED | T2 | re-hash every moved file in place through `sha256_stream` (reading 18), record `observed`, `renew_lease` (never past the deadline), journal `PREPARED → MOVED`; commit | `before_moved`, `after_moved` | mismatch ⇒ `ABANDONED(VALIDATION_FAILED)`, quarantine |
| 5 REGISTERED | T3 | build `ArtifactRef`s and `ArtifactManifest`s from the journal's observed facts (equal to the `planned` facts fixed in phase 1; T3 adds only `finalized_at_utc` and the validation diagnostic ids); `record_finalization`; RESULT: deadline check (`now_utc ≤ deadline` else §4.5), `registrar.register_result(transaction, …)` on the open T3 (manifest, links, sanitized facts, run CAS with `expected_run_revision + 1` — the revision after the deadline snapshot); EVIDENCE: `registrar.register_evidence(transaction, …)`; journal `MOVED → REGISTERED`; audit `FINALIZATION_REGISTERED`; commit | `before_registered`, `inside_registered`, `after_registered` | lost run CAS ⇒ rollback, `ABANDONED(SUPERSEDED)` in a new short transaction, quarantine of the moved blobs that no other ref shares (RC-2) |
| 6 Close | T4 (short) | raw-bearing bytes under a token-bearing (`VALIDATE`/`RUN`) command root removed per 14.7 — `request.json`; `output.json` when present (`output_path`, the adapter's typed describe/validate output written via `--output`, spec 880-896 — no token carrier by contract, removed with the root's other request-era bytes; no production code writes a stdout-capture file); for a `RUN` root the original `adapter-result-manifest.json` at `result_path` — a `DESCRIBE` root carries no token (`adapters/envelopes.py:154-156`); by the one primitive `close_raw_bytes(paths, *, store, unit_of_work, correlation, clock)` (`artifacts/finalizer.py`, Task 6: narrows the kind-governed `CommandRootPaths` by `isinstance`, `store.remove_raw_bytes`, quarantine on failure, audit), called inside `finalize` **only for RESULT after REGISTERED or ABANDONED** (`close_result_lease`), from `conclude_command` for every terminal outcome that takes no RESULT lease (§4.4 step 5) and from `reconcile_finalization` step 9 for every token-bearing root of a terminal run with no `PREPARED`/`MOVED` RESULT journal (§5.3 RV-8; terminal attempts are never reopened, 17.3) — the sweep reads each `inv_` root's invocation through `command_invocations.get` (its `command_kind`) and its run through `engine_runs.get` (its state), §4.1; an EVIDENCE finalization never closes a root; failed deletions moved to quarantine with `RETENTION_DELETED`/`ARTIFACT_QUARANTINED` audit | `after_close` | deletion failure ⇒ quarantine + audit, never an `ArtifactRef` |

The `probe` is a `FinalizationProbe` Protocol with ten no-op methods
(`before_prepared`, `after_prepared`, `before_move`, `after_move`,
`before_moved`, `after_moved`, `before_registered`, `inside_registered` —
called after T3's first insert and before its commit, the CP-6 point —
`after_registered`, `after_close`); the production instance is `NoProbe()`. Tests inject `CrashingProbe(point)` which
raises `FinalizationCrash(BaseException)` at the named point — a
`BaseException` so the finalizer's `except Exception` boundary (which maps
infrastructure errors to `Result` diagnostics) does not absorb it, exactly
as a killed process would leave the durable state. No transaction is open at
any probe point except `before_registered`/`after_prepared`/`after_moved`,
which are called after the commit returned; `before_registered` is called
before T3 begins; `inside_registered` is the one point called with T3 open —
in process a `BaseException` raised there rolls T3 back through the scope's
`finally`, and the crash child blocks there so the parent can terminate it
with the transaction open (CP-6). Immediately after each probe point the coroutine awaits
`cooperative_checkpoint()` and polls `cancellation.is_cancellation_requested()`;
a request observed before T1 is the `PROCESS.CANCELLED` refusal of phase 0,
a request observed after T1 is ignored for RESULT (the lease is held and the
run CAS of T3 decides, reading 1) and for EVIDENCE (no run semantics are at
stake), so the token never aborts a journal mid-protocol.

### 4.4 The RESULT branch (`experiments/finalization.py`, Task 7)

`conclude_command(outcome: SemanticOutcome, command_result: CommandResult,
output_parse: ValidationResultParse | ManifestParse | MISSING,
protocol_summary, observations: tuple[CandidateObservation, ...], *,
roots: CommandRootPaths, token: AttemptTokenMaterial | MISSING,
config, unit_of_work, finalizer, clock) -> Result[CommandConclusion]` — the
caller (Task 8's flow, later Stage 10) destructures `SupervisionOutcome` and
`CommandPaths` into these adapter- and `Path`-typed values, so `experiments`
never imports `process_supervision`. The caller obtains `outcome` from
`semantic_outcome_or_replay` (reading 24), never from the bare Stage 6
operation, so a run already in a success state answers with the stored
conclusion before steps 1–5 below run (step 0 precedes the wrapper):

0. Before the verdict of a `RUN` conclusion (`work_dir` present on the
   `isinstance`-narrowed `CommandRootPaths`; a `VALIDATE`
   conclusion builds its request with `candidate_observations=()`, exactly
   the flow's branch at `supervised.py:709-732`; a `DESCRIBE` invocation has
   no `SemanticOutcomeRequest` at all and goes through `conclude_describe`,
   §4.6), the caller runs
   `observe_candidates(work_dir, declarations, token, *, hasher)` — for each
   declaration
   `confine_candidate_path(work_dir, relative_path)` first, refusing with
   `ARTIFACT.PATH_BOUNDARY_VIOLATION` before any open (15.5:1102; a junction,
   symlink, reparse ancestor or hard link at a declared path is never
   opened), then the streaming hash and scan over the confined path,
   `contains_attempt_token` from the scan — and builds
   `SemanticOutcomeRequest.candidate_observations` from its `Success`
   (`experiments/requests.py:349-351`): `reconcile_run` decides leakage
   (`adapters/reconciliation.py:1157`) and the declared size/hash agreement
   of every declaration (`:1181`) from those observations, so they must
   precede the verdict they feed; Task 8's flow replaces its test-side
   `_observe_candidates` (`supervised.py:244-278`, called pre-verdict at
   `:730`) with this production function. A `Failure` here never reaches the
   Stage 6 operation: the caller hands it to `fail_run_for_refusal(refusal,
   *, run_id, expected_run_revision, roots, unit_of_work, clock)`, which
   records the diagnostic and moves the run `RUNNING → FAILED` with it as
   primary through the registration unit of work's `engine_runs.compare_and_swap`
   guarded by `assert_run_transition` (owner `GENERIC`), audits `RUN_FAILED`
   in the same transaction and runs the step-5 close — the one refusal path
   step 3 also uses; the caller then still stages and finalizes the
   invocation's core evidence (`stderr_evidence`, `protocol_capture_evidence`,
   §4.6), so a refused observation leaves the same evidence as a `FAILED`
   verdict (RC-9, Task 8's failure row). `conclude_command` receives the
   observations and never
   recomputes them (the finalizer's phase 1 re-hashes under its own
   confinement, reading 18).
1. Records every minted diagnostic of `outcome` through the recorder (O-9).
2. Registers the owner and the candidates: `register_result_candidates(declarations,
   owner, *, unit_of_work)` inserts the `RUN` owner through
   `SqliteArtifactOwnerRegistry` (idempotent on `owner_hash`) and one
   `CANDIDATE` row per sanitized adapter declaration (`ADAPTER` producer,
   `RESULT`, `ENGINE_NATIVE_RESULT`, `candidate_artifact_id_for`) — the
   production step that makes `artifact_produced` create only a candidate
   (O-14); nothing registers candidates before `EXITED`, so RV-5 and RV-10
   are planted states. Then produces the EVIDENCE candidates that exist
   after any outcome (§4.6) and the sanitized-manifest and validation-result
   rows.
3. If `outcome.reconciliation.verdict == RESULT_FINALIZATION_ELIGIBLE` and the
   run is `RUNNING`: takes the step-0 observations as given, builds
   `ResultFinalizationRequest` from `ManifestParse`, the sanitized
   manifest and the invocation, and awaits `finalizer.finalize`. A refusal
   whose diagnostic is `ARTIFACT.*` or `SECURITY.*` goes through
   `fail_run_for_refusal` (step 0): the run moves
   `RUNNING → FAILED` with that diagnostic as primary (21.2.1 rows) through
   the registration unit of work's `engine_runs.compare_and_swap` guarded by
   `assert_run_transition` (owner `GENERIC`) — never the Stage 5
   `transition_run` operation — after
   the diagnostic is recorded, and `RUN_FAILED` is audited in the same
   transaction; a `PERSISTENCE.CONCURRENCY_CONFLICT` is returned
   to the driver, which reloads once (the Stage 8 `LostSwap` idiom).
4. On `Success`, the registrar already committed success; the conclusion
   returns the `FinalizationResult`, the `RunManifest` and the evidence refs.
5. On every terminal outcome that takes no RESULT lease — the Stage 6
   verdict's own terminal write (`FAILED`, `NOT_APPLICABLE`, `UNAVAILABLE`;
   RC-14), the Stage 6 core-win answer (`superseded_by` `CANCELLED` or
   `TIMED_OUT`, `semantic_outcome.py:661-663`: the run was already terminal
   and `finalize` is never called), the `RUNNING → FAILED` writes of steps 0
   and 3 (`fail_run_for_refusal`), and a
   `FINALIZATION_LEASE_REFUSED` against a run already terminal (RC-1) — and
   only when the concluded invocation is a token-bearing `VALIDATE` or `RUN`
   command, runs the §4.3 phase-6 close itself through `close_raw_bytes`
   (`store.remove_raw_bytes` of `request.json`, `output.json` when present —
   the typed validate output, §4.3 phase 6 — and, for a `RUN` root, the
   original `adapter-result-manifest.json` at `result_path`; quarantine on
   failure;
   `RETENTION_DELETED`/`ARTIFACT_QUARANTINED` audit): terminal attempts are
   never reopened (17.3), so no recovery lease will need the bytes (14.7:1018,
   29.5:2192). A `PERSISTENCE.CONCURRENCY_CONFLICT` leaves them in place (the
   run is still `RUNNING`); a `VALIDATE` conclusion that leaves the run
   `READY` leaves them in place for the Stage 7 resume rule (15.6); the
   attempt's earlier token-bearing roots and a crash between the terminal
   write and this close are swept by `reconcile_finalization` step 9 (§5.3
   RV-8). Core evidence staging holds no raw bytes and is never touched.

`register_result` (the `PurposeRegistrar` RESULT branch, over the
`RegistrationUnitOfWork` members of the open T3) inside T3: inserts
the `sanitized_adapter_result_manifests` row if absent (unique on
run/invocation/source), builds `RunManifest` (`process_exit_category` from
the `EXITED` invocation's captured category — never reconstructed;
`metrics` from the sanitized `candidate_metrics` projected to `MetricValue`
with `source_artifact_id` of the matching ref; `diagnostics` = recorded
diagnostic ids; `warnings`/`approximations` from the sanitized manifest),
inserts `run_manifests`, inserts `run_artifacts` member links, then the run
compare-and-swap `RUNNING → SUCCEEDED` or `SUCCEEDED_WITH_WARNINGS`
(`assert_run_transition`, owner `GENERIC`), audit `RUN_MANIFEST_REGISTERED`
and `RUN_SUCCEEDED`. The order is fixed by reading 11's triggers.

A RESULT request is refused before T1 when: the run is not `RUNNING`; the
invocation is not `EXITED` or is not the run's run-command invocation; the
semantic status in the request differs from the sanitized manifest's; any
candidate is not `RUN`-owned `RESULT` with a result role and the same
experiment/run/invocation; the latest attempt of the slot is not this run;
the experiment is not `RUNNING`.

### 4.5 Deadline and timeout (14.8:1029, 19.3:1412, 21.2.1:1536)

The deadline is snapshotted once, in T1, as `now_utc + finalization_timeout_seconds`
(UTC, persisted on `engine_runs.finalization_deadline_utc` and the journal)
with the paired monotonic deadline held in the call frame. It is polled
before every move, before T2 and inside T3; phases 0 and 1 poll no
finalization deadline because none exists before T1 (reading 2) — their only
abort is the cancellation token, their duration is bounded by the size
ceilings of §6.4, and a crash there is CP-1, recovered under a fresh
deadline. When it has passed: T3 (or a
short transaction opened for the purpose) records `ARTIFACT.FINALIZATION_TIMED_OUT`
(category `TIMEOUT`, retriable `False`, `invocation_id` set), swaps the run
`RUNNING → TIMED_OUT` with that diagnostic as primary
(`record_timeout`), marks the journal `ABANDONED(ARTIFACT.FINALIZATION_TIMED_OUT)`,
audits `FINALIZATION_TIMED_OUT`, commits, then quarantines the moved blobs.
The invocation stays `EXITED`. A successor exists only through `RetryPolicy`
(17.2:1259). The three hard codes (`ARTIFACT.PATH_BOUNDARY_VIOLATION`,
`ARTIFACT.VALIDATION_FAILED`, `SECURITY.SENSITIVE_MATERIAL_LEAKAGE`;
17.2.1:1272) are already hard-blocked: Stage 5 blocks by category
(`HARD_BLOCKING_DIAGNOSTIC_CATEGORIES`, `domain/retry.py:196-206`, read by
`hard_block_error_code`, `:423-436`), `ARTIFACT_CORRUPTION` and `SECURITY`
are members, and `tests/unit/domain/test_retry_records.py:200-208` pins the
partition (`SECURITY.SENSITIVE_MATERIAL_LEAKAGE` at `:133`). No Stage 5 retry
module is edited and no code-level blocker constant exists or is added
(`experiments/retry.py` holds none); Task 1's
`test_artifact_diagnostics.py::test_hard_codes_are_category_blocked` pins that
each of the three codes' categories in the `artifact_failure` table is a
member of that set, so the partition stays "disjoint and total"
(`domain/retry.py:33-36`). `artifacts/diagnostics.py` re-declares the four
Stage 6 literals (`RESULT_MANIFEST_INVALID`, `PATH_BOUNDARY_VIOLATION`,
`VALIDATION_FAILED`, `SENSITIVE_MATERIAL_LEAKAGE`) because `artifacts` may not
import `adapters`; `test_shared_codes_equal_the_stage6_posture` cross-pins
code, category and retriable against `adapters/diagnostics.py:84-87,145-156`
so there is one posture, not two (the Stage 5 census
`STAGE5_DIAGNOSTIC_CODES` is unchanged).

### 4.6 The EVIDENCE branch and producers (`experiments/finalization.py`)

`stage_core_evidence(owner, source_role, artifact_kind, relative_path,
payload: bytes, correlation, *, store, unit_of_work, clock) -> Result[CandidateArtifact]`
writes the bytes through `store.write_staged(owner_hash, staging_relative_path,
payload)` (Task 4, §6.5: exclusive create and `fsync` inside
`artifacts/store.py`, the one `os` importer of §2.6 — `experiments` opens no
staging file; `observe_candidates` opens only confined candidate files under
`work_dir` to stream-hash them, §4.4 step 0) under the core staging
root `<runtime_root>/staging/<owner_hash>/` at the stored
`staging_relative_path = <correlation_kind>/<correlation_id>/<relative_path>`,
and inserts the `CORE` candidate with
`core_candidate_artifact_id_for(...)` — idempotent: an existing equal file
(the store's equal-bytes answer) and row is returned, a differing file is
`CORE.INVARIANT_VIOLATION`. Producers,
each returning the staged candidate and each **core-generated** (never
adapter bytes):

| Producer | Owner | Role | Kind | Correlation | Source |
|---|---|---|---|---|---|
| `stderr_evidence` | `RUN` (`VALIDATE`/`RUN`) or `ADAPTER` (`DESCRIBE`) | `CORE_EVIDENCE` | `stderr-capture` | `INVOCATION` | `StderrCapture.sanitized_text` (UTF-8); absent text ⇒ a JSON record of `retained_byte_count`, `truncated`, `source_hash` only (14.7:1014); `truncated` ⇒ `PROCESS.STDERR_TRUNCATED` diagnostic + `STDERR_TRUNCATED` audit |
| `protocol_capture_evidence` | `RUN` | `CORE_EVIDENCE` | `protocol-capture` | `INVOCATION` | JSON Lines of the accepted sanitized `RunEvent`s regenerated from the ledger (never raw stdout) |
| `sanitized_result_manifest_evidence` | `RUN` | `CORE_EVIDENCE` | `sanitized-adapter-result-manifest` | `INVOCATION` | `SanitizedAdapterResultManifest` canonical JSON; also the `sanitized_adapter_result_manifests` row |
| `validation_result_evidence` | `RUN` | `CORE_EVIDENCE` | `sanitized-validation-result` | `INVOCATION` | sanitized `AdapterValidationResult`; also the `adapter_validation_results` row |
| `descriptor_evidence` | `ADAPTER` | `ADAPTER_DESCRIPTOR_EVIDENCE` | `adapter-descriptor` | `INVOCATION` | `DescriptorParse` canonical JSON |
| `diagnostic_report_evidence` | `RUN` or `SYSTEM` | `CORE_EVIDENCE` | `diagnostic-report` | `DIAGNOSTIC` | the recorded `Diagnostic` closure as JSON Lines |
| `input_snapshot_evidence` | `EXPERIMENT`/`DATASET`/`STRATEGY` | `*_INPUT` | `configuration-snapshot` / `dataset-manifest` / `strategy-snapshot` | `AUDIT` | caller-supplied canonical bytes whose hash must equal the registry fact (`configuration_audit_hash`, `content_hash`, `strategy_version_hash`); exercised by Task 8 |

`finalize_evidence(candidates, correlation, *, finalizer)` builds the
`EvidenceFinalizationRequest` over the staged candidates of one owner and
correlation and awaits `finalize`. `register_evidence` inserts
`run_artifacts(RUN_EVIDENCE)` links for `RUN` owners only, sets
`stderr_artifact_id` on the invocation by write-once enrichment when the
candidate kind is `stderr-capture` (reading 10 trigger validates), links
`sanitized_adapter_result_manifests.evidence_artifact_id` /
`adapter_validation_results.evidence_artifact_id`, and audits. It never
reads or writes `engine_runs`.

`conclude_describe(command_result: CommandResult, descriptor_parse:
DescriptorParse | MISSING, reconciliation: SemanticReconciliation, *,
roots: CommandRootPaths, unit_of_work, finalizer, clock) ->
Result[tuple[ArtifactRef, ...]]` (`experiments/finalization.py`,
Task 7) is the `DESCRIBE` counterpart of `conclude_command`: no
`SemanticOutcomeRequest` or `SemanticOutcome` exists for a `DESCRIBE`
invocation (`apply_command_semantic_outcome` refuses it,
`semantic_outcome.py:318-324`; the Stage 8 flow asserts it away in `invoke`,
`supervised.py:607`, and keeps a separate `describe()` path, `:610-625`), so
`conclude_command` is never called for one. `conclude_describe` records
`reconciliation.diagnostics`, the describe reconciliation's minted
diagnostics (O-9; the recorder is
idempotent on `diagnostic_id`, so the flow's own recording in `describe()`,
`supervised.py:611-613`, is absorbed), stages
`descriptor_evidence` (when `descriptor_parse` succeeded) and the
`ADAPTER`-owned `stderr_evidence` under the `INVOCATION` correlation naming
the `DESCRIBE` invocation (§3.1.1 row 3), awaits `finalize_evidence`,
enriches `stderr_artifact_id` through `register_evidence`, writes no run row
(a `DESCRIBE` has no run) and runs no close (a `DESCRIBE` root carries no
token, `adapters/envelopes.py:152-156`; Stage 7 keeps the root). Task 8's
`describe()` calls it; Stage 10's composition calls it after every describe.

### 4.7 Idempotency and compare-and-swap precedence (single authority)

For `finalize`: (a) request validation; (b) cancellation token; (c)
candidate load and owner/purpose/role/path refusal; (d) replay lookup by
identity — `REGISTERED` ⇒ stored result; (e) RESULT lease: run facts →
`CONCURRENCY_CONFLICT` when revisions moved, `CORE.INVARIANT_VIOLATION` when
the run is terminal or the invocation is not `EXITED`, refusal when a newer
attempt exists; active-lease conflict; (f) the writes. Every refusal before
(f) leaves no row changed except the candidate quarantine of phase 0/1,
which is its own committed fact. For the repositories, the Stage 8 §4.3.1
order holds verbatim: pre-read, missing → invariant, stale → conflict, wrong
step → invariant, conditional update whose zero rows is a conflict.

### 4.8 Audit sink and log writer

`SqliteAuditSink(scope, ids, clock).append(event)`: ingress validation,
`audit_sequence` assigned by SQLite, joins the caller's transaction
(23.3.1:1714 "append joins the action transaction when possible"); the
standalone `SqliteAuditRecorder(database, ids, clock)` appends in its own
transaction for callers outside a unit of work (reconciliation). Every
finalizer phase audits in the same transaction as its state change, so a
rolled-back phase leaves no audit row and the crash-point tests assert audit
history equals durable history. `JsonLinesLogWriter.open(logs_root,
retained_files, clock)` appends `LogRecord` canonical JSON lines to
`core-00000.jsonl`, rotates by renaming to the next zero-padded index when
`LOG_FILE_BYTES` would be exceeded, and deletes the oldest beyond
`retained_files`; redaction runs before serialization; the writer is handed
to the finalizer and the reconciler as an optional `LogSink` and is never a
record of truth (30.1 "console output is a projection"; the audit table is
authoritative).

---

## 5. Crash points, races and recovery (matrix C)

Every row names the real state machine and the operation sequence that
reaches it; a row the committed state machines cannot reach is listed in
§5.4 and is not asserted anywhere. Pre-state for every RESULT row: an
experiment `RUNNING`, a run `RUNNING` with `attempt_number 1`, its run-command
invocation `EXITED` with captured exit `0` and category `SUCCEEDED`, the fake
adapter's `adapter-result-manifest.json` and two declared candidates under
the work directory, `apply_command_semantic_outcome` having returned
`RESULT_FINALIZATION_ELIGIBLE` with no write — the state Stage 8's
`SupervisedSqliteFlow.conclude` already produces for its success row, plus
the `RUN` owner and two `CANDIDATE` rows that `register_result_candidates`
writes (§4.4 step 2). "Crash" is `CrashingProbe` in process (Tasks 6, 7, 8)
and, for CP-5 and CP-6, a killed child process (Task 6, the thirteenth
importer). "Durable state" is asserted through a fresh connection and after
`reopen` (`FinalizationFixture.reopen()` keeps its roots; the flow's crash
rows use `close(keep_command_roots=True)`, §7.1). Task ownership of the
RESULT cells: Task 6 proves every EVIDENCE cell and every RESULT cell whose
outcome is a refusal, `ABANDONED` or `TIMED_OUT` over the memory double and
SQLite with `MemoryRegistrar`/`MemoryRecoveryValidator`; the RESULT cells
that end in `REGISTERED` success (the RESULT recovery of CP-1..CP-5 and CP-7,
RV-1, RC-13) need the production registrar and recovery validator and are
proven in Task 7 — reading 11's triggers refuse success without a
`run_manifests` row and only Task 7 writes one; Task 8 re-proves all of them
through the flow.

### 5.1 Crash points

| Id | Crash point (probe) | Durable state afterwards | Recovery (`reconcile_finalization`) — RESULT | Recovery — EVIDENCE | Test | Task |
|---|---|---|---|---|---|---|
| CP-1 | `before_prepared` (after `VALIDATING`, no journal) | candidates `VALIDATING`, staging bytes intact, run `RUNNING`, no deadline | step 4 lists the candidates; step 6 validates the temp manifest under 29.3 (invocation `EXITED`, manifest inside the work dir and ≤ 16 MiB, ids and request hash match, token hashed from `request.json` equals the durable hash, semantic success, every candidate passes path/producer/size/schema/scan/hash); resumes from phase 2 with a fresh deadline (reading 2); any failed check ⇒ candidates `QUARANTINED`, run `FAILED` with the check's diagnostic | step 4 revalidates the core candidates independently (29.4) and resumes from phase 2 | `test_finalization_crash_points.py::test_cp1_*` | 6 (EVIDENCE, failed checks), 7 (RESULT success) |
| CP-2 | `after_prepared` | journal `PREPARED`, candidates `FINALIZING`, deadline set, bytes in staging | lease expired ⇒ take over: revalidate files against `planned`, resume phase 3; deadline passed ⇒ RV-15 | take over, resume phase 3 | `test_cp2_*` | 6, 7 |
| CP-3 | `after_move(0)` of two | `PREPARED`; first blob in `objects/`, second in staging | each planned move is either at its finalized path with the expected hash or still in staging; both ⇒ continue phase 3 for the remainder; neither or hash mismatch ⇒ `ABANDONED`, quarantine both, run `FAILED(VALIDATION_FAILED)` | same without run effect | `test_cp3_*` | 6, 7 |
| CP-4 | `before_moved` (all moved, journal still `PREPARED`) | `PREPARED`; every blob at its finalized path | re-hash in place; all match ⇒ write `MOVED` and continue | same | `test_cp4_*` | 6, 7 |
| CP-5 | `after_moved` / child killed between T2 and T3 | journal `MOVED` with `observed`; no `artifact_refs` row; run `RUNNING` with deadline | deadline not passed and run still `RUNNING` at the stored revision ⇒ phase 5 registers refs, manifest, links and success; revision moved (cancelled meanwhile) ⇒ `ABANDONED(SUPERSEDED)` + quarantine; deadline passed ⇒ RV-15 | phase 5 registers evidence refs and links without touching the run (29.4) | `test_cp5_*`; `test_finalization_crash_child.py` | 6, 7 |
| CP-6 | `inside_registered` (T3 open after its first insert): in process `CrashingProbe` raises and the scope's `finally` rolls T3 back; in the crash child the probe blocks and the parent terminates the child with T3 open (the Stage 8 interrupted-writer idiom re-implemented in the crash-child module — `test_wal_restart.py`'s `_launch_writer`/`InterruptedWriter` are private and run a fixed writer; the load-bearing part: the child's ready line reports its own interpreter pid, the parent accepts it only as the launched process or a live descendant verified by creation identity, and terminates and awaits it through a retained handle before `reopen()`, because the launched `.venv\Scripts\python.exe` is a launcher whose child holds the SQLite connection — the C-17 defect of commit `079395b`; §7.1) | exactly `MOVED` — never a ref without a manifest, never success without a manifest (SQLite atomicity + reading 11 triggers) | as CP-5 | as CP-5 | `test_cp6_*`; `test_finalization_crash_child.py::test_child_killed_inside_registered_leaves_moved` | 6, 7 |
| CP-7 | `after_registered` (before phase 6 cleanup) | `REGISTERED`, refs and manifest committed, raw-bearing bytes still under the command root | step 9 cleanup: raw bytes removed (or quarantined on failure) with audit; nothing else changes; a second run is a no-op (29.1:2152 idempotent) | the same cleanup rule applies only to RESULT; EVIDENCE leaves the command root to the RESULT close or Stage 7 cleanup | `test_cp7_*` | 6 (EVIDENCE), 7 (RESULT) |

Each cell asserts, after recovery: database state (candidate states, journal
state, refs, manifest, run state and revision, invocation unchanged), audit
rows (one per phase actually committed, plus the reconciliation action),
diagnostics (zero dangling references), temporary and final filesystem
state (staging empty or quarantined; `objects/` holds exactly the registered
blobs), and that no child survives (28.3:2096).

### 5.2 Races and precedence

| Id | Interleaving (operations, in order) | Winner | Loser result | Durable state | Test | Task |
|---|---|---|---|---|---|---|
| RC-1 | `transition_run(target=CANCELLED, primary_terminal_diagnostic_id=<CANCELLATION diagnostic with invocation_id>)` → run `RUNNING → CANCELLED` (`run_service.py:247-313`; `cancel_experiment` never touches a run, reading 23); then `finalize(RESULT)` | cancellation | `FINALIZATION_LEASE_REFUSED`, `CORE.INVARIANT_VIOLATION` (run terminal); no journal row; candidates stay `VALIDATING`→ quarantined by step 9 later | run `CANCELLED`, no refs, no manifest, no raw bytes under the root after `recover()` (§4.4 step 5 at the flow; step 9 here); EVIDENCE for the same invocation still finalizes (RC-9) | `test_finalization_races.py::test_rc1` | 6 |
| RC-2 | `finalize(RESULT)` to `after_moved` (probe pauses by raising, test continues) → `transition_run(RUNNING → CANCELLED)` wins the run CAS → finalizer resumed via recovery | cancellation | T3's run CAS loses (`expected_run_revision + 1` ≠ stored) ⇒ rollback, `ABANDONED(SUPERSEDED)`, blobs quarantined | run `CANCELLED`, journal `ABANDONED`, no ref, candidates `QUARANTINED`, audit shows `FINALIZATION_ABANDONED` | `test_rc2` | 6 |
| RC-3 | `finalize(RESULT)` to `REGISTERED` → `transition_run(RUNNING → CANCELLED)` for the run, then `cancel_experiment` | finalization | `transition_run` refuses the terminal run (`run_service.py:276-283`, `CORE.INVARIANT_VIOLATION`); `cancel_experiment` still swaps the experiment row to `CANCELLED` (it reads no run) | run `SUCCEEDED`, manifest present; experiment `CANCELLED`; the run cancellation recorded ineffective | `test_rc3` | 7 |
| RC-4 | `finalize(RESULT)` with `FixedClock` advanced past the deadline between `after_moved` and T3 | deadline | `ARTIFACT.FINALIZATION_TIMED_OUT`; run `RUNNING → TIMED_OUT`; journal `ABANDONED`; blobs quarantined; invocation `EXITED` unchanged | no manifest, no RESULT ref; later recovery never registers success (RV-15) | `test_rc4`; `test_sqlite_finalization_deadline.py` | 6 |
| RC-5 | deadline passes during phase 3 (monotonic poll, clock advanced before the second move) | deadline | as RC-4; the first blob is quarantined, the second never moved | as RC-4 | `test_rc5` | 6 |
| RC-6 | `finalize(RESULT)` twice with equal requests | first | second returns the stored `FinalizationResult` with `replayed=True`; zero writes (row counts and `audit_sequence` unchanged except one `FINALIZATION_REPLAYED` row) | one manifest, one ref set | `test_rc6` (7: its first call must reach `REGISTERED` success); `test_finalization_idempotency.py` (6: the identity derivations and the memory double's EVIDENCE replay) | 6, 7 |
| RC-7 | second request with a different `sanitized_adapter_result_manifest_hash` for the same invocation | first | `PERSISTENCE.CONCURRENCY_CONFLICT` ("different manifest for the same attempt", 17.2:1256); no write | unchanged | `test_rc7` | 6 |
| RC-8 | request naming an invocation that is not the run's run-command invocation: the run's own `EXITED` `VALIDATE` invocation (Stage 5 `create_invocation` created it while the run was `VALIDATING`; no Stage 5 operation can create a second `RUN` invocation for a `RUNNING` run, `command_invocation.py:469-473`) and, planted raw, a second `RUN` invocation row | identity check | `CORE.INVARIANT_VIOLATION`: the invocation is not the active run-command of the run | unchanged | `test_rc8` | 6 |
| RC-9 | for each terminal outcome in {`SUCCEEDED`, `FAILED`, `CANCELLED`, `TIMED_OUT`, `UNAVAILABLE`, `NOT_APPLICABLE`}: reach it through the Stage 5/6 operations (the Task 7 registrar for `SUCCEEDED`), then `finalize(EVIDENCE)` for the invocation's stderr and protocol capture | evidence registers | — | run row revision unchanged across the EVIDENCE `REGISTERED` commit (reading 5); no `run_manifests` row for non-success; `run_artifacts(RUN_EVIDENCE)` links present | `test_rc9[outcome]` | 7 |
| RC-10 | `finalize(EVIDENCE)` twice | first | replay, zero writes | one ref set | `test_rc10` | 6 |
| RC-11 | an `EvidenceFinalizationRequest` whose candidates are the RESULT candidates (adapter-produced) | request validation | `ARTIFACT.VALIDATION_FAILED` ("adapter-produced candidate cannot be evidence", 19.1:1344); candidates untouched | unchanged | `test_rc11` | 6 |
| RC-12 | journal `PREPARED` with an unexpired lease (planted or left by CP-2 within the lease window) → a second `finalize(RESULT)` | the holder | `PERSISTENCE.CONCURRENCY_CONFLICT` (one active RESULT lease per attempt) | unchanged | `test_rc12` | 6 |
| RC-13 | journal `PREPARED` with an expired lease (clock advanced) → `finalize(RESULT)` | the newcomer | — | takes over the same `finalization_id`, completes to `REGISTERED` success | `test_rc13_takeover_reaches_moved` (6), `test_rc13` (7) | 6, 7 |
| RC-14 | run moved `RUNNING → FAILED` by the Stage 6 verdict (`FAILED` manifest) → `finalize(RESULT)` | failure | refused; candidates quarantined by step 9; the root's raw-bearing bytes closed by `conclude_command` at the terminal verdict (§4.4 step 5) or by step 9 when the process died first; "never relabeled as evidence": an EVIDENCE request over them is RC-11 | run `FAILED`, no ref, no raw bytes under the root after `recover()` | `test_rc14` | 6 |
| RC-15 | `finalize(RESULT)` to `after_prepared` → (a) `transition_invocation_and_run(invocation → TIMED_OUT, run → TIMED_OUT)` by the command-deadline path: refused, the invocation is terminal (`invocation_service.py:1086-1092`); (b) generic `transition_run(RUNNING → TIMED_OUT)`: succeeds (`lifecycle.py:247`; the operation never loads the invocation) — **any generic `transition_run` target can win after `EXITED`; T3's revision CAS is the arbiter** (reading 23) | (a) the lease holder; (b) the generic writer | (a) `CORE.INVARIANT_VIOLATION`, journal untouched; (b) T3 loses, `ABANDONED(SUPERSEDED)`, quarantine | (a) unchanged; (b) run `TIMED_OUT`, no ref, no manifest | `test_rc15_pair_refused`, `test_rc15_generic_timeout_wins` | 7 |
| RC-16 | two sequential RESULT finalizers for different attempts of one slot (attempt 1 `FAILED` → `RetryPolicy` successor attempt 2 `RUNNING`/`EXITED`) → `finalize(RESULT)` for attempt 1's stale identity | identity | refused: `latest_attempt(slot).run_id != run_id` (reading 4) and the run is terminal | attempt 2 finalizes normally | `test_rc16` | 7 |
| RC-17 | `finalize(RESULT)` to `after_moved` → `cancel_experiment` (experiment `RUNNING → CANCELLED`, run untouched) → recovery | finalization (reading 23) | — | run `SUCCEEDED` under a `CANCELLED` experiment, journal `REGISTERED`; the experiment's runs are cancelled only by `transition_run`, which here would lose to the terminal run | `test_rc17` | 7 |

True concurrency (two writers) is not constructible over one SQLite file
(Stage 8 plan 270, 1921); every row above is a sequential interleaving
driven by the test, and the busy-timeout path is covered by the Stage 8
conflict tests the new repositories inherit through `TransactionScope`.

### 5.3 Reconciliation rows (29.2 steps 4, 6, 7-artifact, 9; 29.3; 29.4)

| Id | Planted durable state | Expected action | Test | Task |
|---|---|---|---|---|
| RV-1 | CP-1 state with a valid temp manifest and surviving `request.json` | full RESULT recovery to success; `run_manifest_hash` verified separately after registration (29.3:2182) | `test_finalization_recovery.py::test_rv1` | 7 |
| RV-2 | CP-1 state, manifest deleted | `ARTIFACT.RESULT_MANIFEST_INVALID`; run `FAILED`; candidates `QUARANTINED` (17.3) | `test_rv2` (asserts `RUN_FAILED` by name) | 7 |
| RV-3 | manifest > 16 MiB | as RV-2 | `test_rv3` | 7 |
| RV-4 | `request.json` token altered (hash mismatch) | `PROTOCOL.IDENTITY_OR_SEQUENCE_VIOLATION`; run `FAILED`; no raw token read into a record (only its hash is compared) | `test_rv4` | 7 |
| RV-5 | invocation `RUNNING` (exit facts lost), candidates `CANDIDATE` (planted raw: production registers candidates only after `EXITED`, §4.4 step 2) | step 4 skips the attempt (not `EXITED`); candidates untouched; the Stage 7 reconciler owns the invocation; assertion: no Stage 9 write | `test_rv5` | 6 |
| RV-6 | a directory under `<runtime_root>/<inv_...>` naming no invocation row (`reconcile_finalization` lists `runtime_root` itself; the Stage 7 reconciler has no orphan scan, `process_supervision/reconciliation.py:573-578`) | quarantined with `RECONCILIATION_ORPHAN_QUARANTINED`; never attached by name (29.2:2169) | `test_rv6` | 6 |
| RV-7 | a `CANDIDATE` whose purpose/role/owner row mismatches its invocation (planted raw) | `QUARANTINED` with `ARTIFACT.VALIDATION_FAILED` | `test_rv7` | 6 |
| RV-8 | run `FAILED` (RC-14) with `CANDIDATE` result candidates and raw-bearing bytes still under its token-bearing roots | `QUARANTINED`; staging bytes moved to quarantine; never finalized; the raw-bearing bytes of every token-bearing root of the terminal attempt closed through `close_raw_bytes` (§4.3 phase 6; the sweep behind §4.4 step 5) | `test_rv8` | 6 |
| RV-9 | a blob under `objects/` with no `artifact_refs` row and no `MOVED` journal naming it | quarantined as unregistered finalized content | `test_rv9` | 6 |
| RV-10 | abandoned `CANDIDATE`/`VALIDATING` rows older than their invocation's cleanup (planted raw) | `QUARANTINED` | `test_rv10` | 6 |
| RV-11 | `FINALIZING` candidate with no journal and no ref | `QUARANTINED` (unmapped) | `test_rv11` | 6 |
| RV-12 | `FINALIZING` candidate with a ref (historical) | excluded from `list_recoverable`; untouched (19.1:1358) | `test_sqlite_artifact_repositories.py::test_list_recoverable_excludes_mapped_finalizing` | 5 |
| RV-13 | any `artifact_refs` row | never updated by recovery (insert-only trigger + no code path) | `test_sqlite_artifact_repositories.py::test_refs_never_update` | 5 |
| RV-14 | run `reconcile_finalization` twice over any planted state | second pass changes nothing and appends one `RECONCILIATION_*` audit row with outcome `SUCCEEDED` and `details.changes == 0` | `test_rv14` | 6 |
| RV-15 | `PREPARED`/`MOVED` RESULT journal whose deadline has passed (clock advanced across `reopen`) | run `RUNNING → TIMED_OUT`, `ABANDONED(FINALIZATION_TIMED_OUT)`, blobs quarantined; never success (23.3.1:1723, reading 13) | `test_rv15` | 6 |
| RV-16 | `MOVED` EVIDENCE journal for a run already `FAILED` | evidence registered; run row untouched | `test_rv16` | 6 |
| RV-17 | quarantine entry older than 86 400 s | `ARTIFACT.QUARANTINE_OVERDUE` diagnostic + `QUARANTINE_OVERDUE` audit; bytes untouched (reading 8) | `test_rv17` | 6 |
| RV-18 | `purge_quarantine(entry_id, correlation)` | bytes removed, `RETENTION_DELETED` audit; refused while any `PREPARED`/`MOVED` journal names a candidate of the entry (29.5:2192) | `test_rv18` | 6 |

### 5.4 Not constructible or not a Stage 9 scenario (declared, not asserted)

- `EXITED → PROTOCOL_FAILED` on recovery (reading 3).
- "Newer attempt before the lease" while the run is `RUNNING` (reading 4;
  RC-16 tests the predicate with a terminal predecessor).
- Two parallel RESULT finalizers (Stage 8 plan 270; RC-12/13 are sequential).
- A finalization deadline for an attempt that never reached `PREPARED`
  (reading 2).
- A command-deadline timeout of an `EXITED` invocation through
  `transition_invocation_and_run` (RC-15a asserts the refusal); the generic
  `transition_run` is not excluded and RC-15b proves T3 loses to it.
- Experiment cancellation pre-empting an in-flight RESULT lease (reading 23;
  RC-17 proves the run row is the arbiter).
- `stdout`-trust loss during finalization: stdout trust is decided by Stage
  6/7 before `EXITED`; Stage 9 consumes the verdict.

---

## 6. Filesystem, store, confinement and migration contract (matrix D)

### 6.1 Roots and preflight (22.5)

`ArtifactStore.open(staging_root, artifacts_root, quarantine_root)` requires
absolute, drive-lettered, non-UNC roots; `artifacts_root` and `staging_root`
share `Path.stat().st_dev` (reading 20); no component of either path on or
above the root is a reparse point (the `roots.py` walk mirrored); the store
creates `objects/` and `manifests/` under `artifacts_root` and the quarantine
root on first use with exclusive semantics (`mkdir(exist_ok=True)` inside
`open`, never at import). Dataset storage is not checked (22.5:1653).
Long-path preflight reuses the Stage 7 `PathPreflight` facts handed in by the
caller: a planned finalized path longer than the ceiling when long paths are
unsupported is `PROCESS.PATH_PREFLIGHT_REJECTED` before `PREPARED`; the
success test is conditional on detected support, the rejection test always
runs (22.5:1655).

### 6.2 Layout

- Adapter staging: the Stage 7 work directory `<command_root>\runs\<run_id>\work`;
  `staging_relative_path` is the adapter's `relative_path` validated by
  `validate_relative_candidate_path` (lexical) and `confine_candidate_path`
  (physical).
- Core staging: root `<runtime_root>\staging\<owner_hash>\`; the candidate's
  `staging_relative_path` is `<correlation_kind>\<correlation_id>\<relative_path>`
  (the correlation segments are part of the stored path, §3.1).
- Finalized: `<artifacts_root>\objects\<hh>\<sha256>` (content-addressed; `hh`
  the first two hex digits) and `<artifacts_root>\manifests\<artifact_id>.json`
  (the `ArtifactManifest`, written exclusive-create after the blob is
  registered; its absence is tolerated by readers because the manifest JSON
  is also the `artifact_refs.manifest_json` column — the file is a projection
  for human inspection, the row is authoritative).
- Quarantine: `<runtime_root>\quarantine\<finalization_id or candidate_artifact_id>\<original relative path>`
  plus `quarantine.json` (reason code, instant, source paths, hashes); a
  journal-driven quarantine (`ABANDONED`, RV-15) is one entry keyed by the
  `finalization_id` holding every moved blob of that finalization, a
  phase-0/1 or step-9 candidate quarantine is one entry per
  `candidate_artifact_id`, a failed raw-byte deletion of the phase-6 close is
  one entry keyed by the `invocation_id`, and `ARTIFACT_QUARANTINED` is
  audited once per candidate (or once per closed root);
  entries are `ACLs-untouched`, no OS sandbox claim (15.5:1104).

### 6.3 Confinement (`artifacts/paths.py`, 15.5, 24.3:1772)

`confine_candidate_path(root, relative) -> Result[ConfinedPath]`: lexical
rules (relative, no drive, no UNC, no `..`, no `.`, no empty segment, no `:`
in any segment, no reserved device name, ≤ 512 characters, ≤ 32 segments —
the existing `RelativeCandidatePath` rules plus the ADS rule); physical rules
in order: every ancestor from the root down exists and is a directory whose
`lstat` attributes carry no reparse bit (junction, symlink, mount point are
all reparse points on NTFS); the leaf exists, is a regular file, is not a
reparse point, `st_nlink == 1` (reading 19); `resolve(strict=True)` of the
leaf is inside `resolve(strict=True)` of the root (string-prefix with a
separator, case-folded as Windows does); the returned `ConfinedPath` carries
the `(st_dev, st_ino, st_size, st_mtime_ns)` identity. The recheck before
hashing and before each move calls the same function and compares the
identity; a change is `ARTIFACT.VALIDATION_FAILED` ("changed while
finalizing"). Property test inputs (28.4:2108): separators `/` `\`, traversal
segments, drive and UNC prefixes, Unicode and normalization forms, ADS
suffixes, reserved names, long segments; physical fixtures: a symlink (when
the principal may create one; otherwise the existing Stage 7 skip reason is
**not** reused — the test uses a junction, which needs no privilege), a
junction, a hard link, a mount-point-shaped reparse attribute planted by the
Stage 7 `_winapi` fixture idiom.

### 6.4 Hashing and scanning (`artifacts/hashing.py`, 10.2:472, 14.7:1018)

`StreamingContentHasher(chunk_size=1 MiB)` implements `ContentHasher`:
`sha256_stream` reads fixed chunks (never `read()` whole); `sha256_and_scan`
additionally searches each chunk plus a carry of `len(token) - 1` bytes from
the previous chunk for the exact token bytes, so a token split across any
boundary is found (property test over arbitrary chunk sizes and offsets,
28.4:2114); it also runs the Stage 6 redaction's token-shape detector on
text kinds so that a redacted-looking placeholder is not mistaken for
absence. The scan result is a boolean and the byte offset is never recorded
(14.7:1014 "never sample bytes"). Size ceilings: candidates ≤
`MAX_DECLARED_SIZE_BYTES`; JSON kinds parsed only when ≤ 16 MiB; stderr
evidence ≤ 50 MiB; manifests ≤ 16 MiB.

### 6.5 Atomic move and durability (`artifacts/store.py`)

`atomic_move(confined: ConfinedPath, target: Path) -> Result[MoveOutcome]`:
reopen the source by path, compare `os.fstat(handle)` identity with the
confined identity, `os.fsync(handle)`, close, `target.parent.mkdir(parents=True,
exist_ok=True)`, then `source.rename(target)`; `FileExistsError` ⇒ dedup
branch (re-hash target; equal ⇒ remove source, `deduplicated=True`; unequal
⇒ `CORE.INVARIANT_VIOLATION`); `PermissionError` (open handle, 28.5:2133) ⇒
`ARTIFACT.MOVE_FAILED` (category `PERSISTENCE`, reading 26;
`test_disk_full_permission_lock_diagnostics` asserts the category and that
`hard_block_error_code` does not name it); cross-volume is prevented by preflight so `rename`
never falls back to copy. `quarantine_move` uses the same primitive toward
the quarantine root and writes `quarantine.json` exclusive-create. No
`shutil`, no `os.replace`. `write_staged(owner_hash, staging_relative_path,
payload: bytes) -> Result[ConfinedPath]` is the only writer into core staging
(§4.6): the relative path passes the lexical rules of §6.3, parents are
created below `<staging_root>/<owner_hash>/` only, the file is opened with
`open(path, "xb")`, written, `os.fsync`ed and closed, and the returned
`ConfinedPath` comes from `confine_candidate_path` over the written leaf;
`FileExistsError` ⇒ the existing file is re-hashed — equal bytes ⇒ its
`ConfinedPath` (the idempotent replay of `stage_core_evidence`), differing
bytes ⇒ `CORE.INVARIANT_VIOLATION`; every other `OSError` ⇒
`ARTIFACT.MOVE_FAILED` (reading 26's storage-failure posture; no new code).

### 6.6 Revision `r0002_stage9_artifacts`

`upgrade()`: the eight `create_table` calls in §3.3 order, `op.add_column`
on `engine_runs`, the partial indexes via `op.execute(normalized_sql(...))`
from `schema.py`'s `PARTIAL_INDEX_SQL` extension, then the Stage 9 triggers
from `schema.TRIGGER_SQL` (the Stage 8 list extended in place so metadata
and migration share one authority). `downgrade()`: drop triggers, indexes
and the eight tables in reverse order; the added column stays (§2.4) and the
function returns after `op.execute("-- finalization_deadline_utc retained")`
so the residue is explicit in the script. `check_revision` classifies a
database at `r0001` as `BEHIND`, at `r0002` as `CURRENT`; `open_database`
opens only `CURRENT`; `apply_migrations` upgrades `BEHIND` in one
transaction per revision; `scripts/verify_migrations.py` pins the new
`sqlite_master` set and `migration-check` stays the verifier step. A
migrated-from-`r0001` database and a fresh `r0002` database have identical
`metadata_drift() == ()` and identical schema objects (the Stage 8 test
idiom, `test_sqlite_migrations.py`).

---

## 7. Test strategy, harness and the requirement map

### 7.1 Test support (`tests/doubles/artifacts.py`, `tests/persistence_support/artifacts.py`, `tests/persistence_support/supervised.py`)

| Helper | Shape | Used by |
|---|---|---|
| `tests/doubles/artifacts.py::MemoryFinalizationUnitOfWork` (Task 6) | in-memory `FinalizationUnitOfWork` and `RegistrationUnitOfWork` over dict stores with the same conflict/invariant/missing answers as SQLite (`engine_runs`/`command_invocations` with `get` and `compare_and_swap` over planted records, §4.1), `max_open` counter, a `refuse_success_without_manifest` rule mirroring reading 11, `open_transactions()`; `SequentialAuditIds(prefix_seed)` deterministic `AuditEventIds`; `CrashingProbe(point)`, `RecordingProbe()`; `_run(coroutine)` the `send(None)` driver; `ArtifactStoreFixture(tmp_path)` building `staging/`, `artifacts/`, `quarantine/` under one `tmp_path` | every unit test of Tasks 6–7; the contract suite kinds `"memory"` |
| `tests/doubles/artifacts.py::sample_candidate(owner_kind, purpose, role, producer, state)`, `sample_ref(...)`, `sample_result_request(...)`, `sample_evidence_request(...)`, `sample_journal(state, purpose)`, `sample_audit_event(action)`, `sample_metric()`, `sample_run_manifest(refs)` | pure builders over the doubles' identities (`EXPERIMENT_ID`, `RUN_ID`, `INVOCATION_ID`, `UUID_*`) and `INSTANT`; `rekey`/`bump` variants | Tasks 1–7 |
| `tests/persistence_support/artifacts.py::ArtifactHarness(database)` (Task 5) | `PortHarness`-style over `SqliteUnitOfWork`; `put_candidate`, `put_ref`, `put_journal`, `committed_candidates/refs/journal/audit_events/run_manifests/run_artifacts()` through a read-only session; `plant_raw(table, row)` for the trigger refusal tests; `install_refusing_trigger(table, when)` through `raw_connection` with the Stage 8 `sql_identity_literal` rule; `token_scan(path_or_bytes, token) -> bool` the test-side exact-byte scan (independent implementation, `bytes.find` over the whole file, used to cross-check the production scanner); `scan_tree_for_token(root, token) -> tuple[Path, ...]` | Task 5 contract kind `"sqlite"`, Tasks 6–8 |
| `tests/persistence_support/artifacts.py::FinalizationFixture.open(tmp_path, *, clock)` (Task 6) | composes `ArtifactStoreFixture`, `open_test_database`, `SqliteUnitOfWork`, `SqliteDiagnosticRecorder`, `SqliteAuditRecorder`, `MemoryRegistrar` and `MemoryRecoveryValidator` (Task 6: a registrar that records refs and links only, no `RunManifest`, and a validator that returns planted facts — so RESULT success is unreachable in Task 6 by construction; replaced by the production `ResultRegistrar` and `ResultRecoveryValidator` in Task 7) and `CoreArtifactFinalizer`; `plant_result_prestate()` seeds the §5 pre-state rows raw (experiment, slot, run `RUNNING`, invocation `EXITED`, owners, two candidates, the work dir files and `request.json` with a fixture token); `finalize_result(*, probe=NoProbe())`, `finalize_evidence(owner_kind, *, probe=NoProbe())` (the probe is per call, so `recover()` — always `NoProbe()` — never re-trips it), `advance_clock(seconds)`, `reopen()`, `recover()` (`reconcile_finalization`), `durable()` (a frozen snapshot of every Stage 9 table plus run/invocation rows, filesystem listing with hashes, audit rows) | Tasks 6, 8 |
| `SupervisedSqliteFlow` extension (Task 8) | new members `finalizer` (production `CoreArtifactFinalizer` over the production registrar), `describe()` extended to call `conclude_describe` (§4.6), `conclude_and_finalize(row, run, outcome)` (`observe_candidates` before the verdict for a `RUN` conclusion, `candidate_observations=()` for `VALIDATE` — §4.4 step 0 — then `semantic_outcome_or_replay` and `conclude_command` with those observations), `recover()` (Stage 7 `reconcile()` then `reconcile_finalization` with the flow's `runtime_root`), `close(keep_command_roots=True)` (the Stage 8 `close()` `rmtree`s every command root, `supervised.py:354-355`, which would delete the staging bytes, work dir and `request.json` the crash rows recover from), `fresh_refs(run_id)`, `fresh_manifest(run_id)`, `fresh_journal()`, `fresh_audit()`, `scan_for_token(token)` (database file, `-wal`, `-shm`, logs root, artifacts root, quarantine root, staging root, every command root of the attempt — scanned after the row's `recover()`, which the §5.3 step-9 sweep and the phase-6 close have emptied of raw bytes — and every `manifest_json`/`details_json` column through `raw_connection`), `object_blobs()` | Task 8 |
| the thirteenth importer `tests/integration/artifacts/test_finalization_crash_child.py` (Task 6) | launches the venv interpreter with a single-line `-c` program that opens `FinalizationFixture` on a path argument and runs `finalize_result()` (Task 6: `finalize_evidence()`; Task 7 adds the RESULT twin) with a probe that **blocks** (a `threading.Event().wait` inside the child only) at `after_moved` (CP-5) or `inside_registered` (CP-6); the parent waits for the point's marker file and for the child's ready line, which reports the child's **own interpreter pid** (the `HELD <pid>` shape of `test_wal_restart.py:91-116`): on this host `.venv\Scripts\python.exe` is a launcher that starts the real interpreter as its own child, so the launched process is not the SQLite holder (the C-17 defect, commit `079395b`); the parent accepts the reported pid only when it is the launched process or a live descendant of it verified by creation identity (`descendants_of`, `process_times`, `render_creation_identity`), opens and retains a handle on it while it is alive, terminates it through that handle with the fixture's forced exit value, awaits the same handle within the bound, asserts the exit value, only then reaps the launcher, and then `reopen()` and `recover()`; nothing is terminated by pid alone | CP-5 and CP-6 real-process cells |

Ownership: Task 1 creates nothing under `tests/doubles` (its tests use
inline builders); Task 2 creates `tests/doubles/artifacts.py` with the
builders it needs; Task 5 creates `tests/persistence_support/artifacts.py`;
Task 6 adds `MemoryFinalizationUnitOfWork`, the probes, `FinalizationFixture`;
Task 7 adds the production-registrar wiring; Task 8 extends `supervised.py`.
No helper is used before the task that creates it (Task 9's review repeats
the dependency walk).

### 7.2 Requirement map (every matrix id → task and named test)

Test paths are under `tests/`; `U/artifacts` = `unit/artifacts`, `U/audit` =
`unit/audit`, `U/domain` = `unit/domain`, `U/exp` = `unit/experiments`,
`U/pers` = `unit/persistence`, `P` = `property`, `I/art` =
`integration/artifacts`, `I/pers` = `integration/persistence`, `S` = `safety`.
A row whose category is OOS names the roadmap exclusion or owner instead of
a test.

| Id(s) | Task | Test |
|---|---|---|
| F6.3-1, R15.5-01, R15.5-04, R19.2-09, F24.3-2, R29.2-05 | 4, 6, 7 | `U/artifacts/test_artifact_paths.py::test_untrusted_path_confined_before_open`, `::test_identity_recheck_detects_swap`; `I/art/test_finalization_recovery.py::test_rv6`; `U/exp/test_finalization_service.py::test_observe_candidates_refuses_junction_before_open` |
| F6.3-2, F24.1-3, F24.3-8, R19.2-02, R29.3-06 | 4, 6 | `U/artifacts/test_candidate_validation.py::test_engine_output_untrusted_until_validated`; `I/art/test_finalization_recovery.py::test_rv1` |
| F6.3-3 | — (EXISTS Stage 5) | `tests/architecture/test_package_import_boundaries.py:28` (the `adapters` allowlist is `domain` and itself, so no adapter module can reach a database handle, store or finalized path); re-pinned by `S/test_stage9_boundaries.py::test_artifacts_and_audit_import_domain_only` |
| F7.1-1, F7.1-3, R19.4-06, A33.4-01 | 7 | `U/exp/test_finalization_service.py::test_success_committed_only_with_manifest_and_refs` |
| F7.1-2, R19.1-10, R19.3-04, R19.3-06, R29.4-02, A33.6-04 | 7 | `I/art/test_finalization_races.py::test_rc9[outcome]` (reading 5 pin) |
| F7.2-1, R15.7-01, R15.7-02, R23.3-02, R23.3.1-13 | 5, 6 | `U/pers/test_sqlite_finalization_journal.py::test_one_active_result_lease_per_attempt`, `::test_renew_never_extends_deadline`; `I/art/test_finalization_races.py::test_rc12` |
| F8.1-1, R14.8-01, R23.3.1-02, I-6 | 5 | `U/pers/test_sqlite_finalization_deadline.py::test_deadline_column_admitted_only_after_snapshot` |
| F8.1-2, F8.1-3, F8.2-1, F8.2-2, T28.2-03, A33.6-02 | 5, 6 | `U/artifacts/test_artifact_port_contracts.py[memory,sqlite]::test_reference_repository_refuses_candidate_payload` |
| F8.1-4, F8.2-3, R23.3.1-12, R30.2-02 | 5 | `U/pers/test_sqlite_audit_sink.py::test_append_only_and_sequence_ordered` |
| F8.1-5, F8.2-4 | 6 | `U/artifacts/test_artifact_finalizer.py::test_finalize_returns_explicit_mappings_per_purpose`, `::test_cancellation_token_refuses_before_prepared` |
| F8.1-6, F24.3-1, R10.4-01, R11.5-01, R11.5-13 | 1, 2 | `U/artifacts/test_artifact_models.py::test_unknown_fields_and_implicit_none_rejected`; `U/audit/test_audit_models.py::test_unknown_fields_rejected` |
| F8.2-5, F8.2-6, F8.2-7, T28.2-05, R19.1-05 | 1 | `U/artifacts/test_finalization_requests.py::test_result_branch_fields`, `::test_evidence_branch_exactly_one_typed_correlation`, `::test_other_branch_fields_rejected`, `::test_generic_string_cannot_be_correlation` |
| F8.2-8, R23.3.1-15 | 6 | `U/artifacts/test_artifact_finalizer.py::test_no_transaction_open_across_hashing_or_moves` (`max_open == 0`) |
| F8.2-9, R21.3-01 | 4, 6 | `U/artifacts/test_artifact_store.py::test_os_errors_become_stable_diagnostics` |
| F9-1, R20.2-02, R20.3-01 | — (reading 6) | no Parquet in Project 1; `S/test_project_dependencies.py` keeps `pyarrow` prohibited |
| F24.1-1, R15.5-06, R18.3-03 | 8 | `I/pers/test_stage9_supervised_finalization.py::test_adapter_wrote_only_under_its_work_dir` |
| F24.1-2, F24.3-4, R10.2-07, R30.1-02, R30.3-03, A33.4-02, A33.7-01 | 8 | `I/pers/test_stage9_token_absence.py::test_token_absent_from_every_surface` |
| F24.1-4 | 9 | `S/test_stage9_boundaries.py::test_no_pickle_marshal_or_eval_in_new_modules` |
| F24.3-3, R14.7-01, R29.3-03 | 4, 6 | `U/artifacts/test_candidate_validation.py::test_sizes_bounded_before_parsing`; `I/art/test_finalization_recovery.py::test_rv3` |
| F24.3-5 | 4 | `U/artifacts/test_candidate_validation.py::test_adapter_output_cannot_request_paths_or_imports` |
| F24.3-6, F24.3-7, R19.1-14, R15.5-05, T28.2-04, A33.6-05 | 1, 4 | `U/artifacts/test_artifact_models.py::test_adapter_cannot_declare_evidence_owner_role_or_path`; `P/test_purpose_role_cross_products.py::test_exactly_seven_rows_validate` (nine owner tuples) |
| F27.1-1, F27.1-2, F27.1-3, F27.2-1 | 9 | `S/test_stage9_boundaries.py::test_artifacts_and_audit_import_domain_only`, `::test_stage_nine_modules_are_exactly_the_plan_paths` |
| R10.2-01, A33.2-02 | 4 | `U/artifacts/test_content_hashing.py::test_sha256_is_the_authoritative_digest` |
| R10.2-02 | — (EXISTS) | `U/domain/test_canonical_json.py` (existing) |
| R10.2-03, R10.2-06, T28.1-01 | 1, 7 | `U/domain/test_hashing.py::test_stage_nine_profiles_are_named_and_ordered`; `U/exp/test_run_manifest.py::test_self_hash_omitted_by_named_profile` |
| R10.2-04, R19.4-04 | 7 | `U/exp/test_finalization_service.py::test_source_hash_persisted_bytes_not` |
| R10.2-05 | — (EXISTS) | `U/domain/test_hashing.py` (existing) |
| R10.2-08 | 4 | `U/artifacts/test_content_hashing.py::test_streaming_never_reads_whole_file` (a 64 MiB sparse fixture with a read-size spy) |
| R10.3-01..05, R20.2-01, R20.2-03, R20.2-04, R19.4-01, R19.4-02, R19.4-03, A33.6-08 | 1, 7 | `U/artifacts/test_artifact_manifest.py::test_manifest_fields_and_owner_lineage`; `U/exp/test_run_manifest.py::test_provenance_fields_retained` |
| R10.4-02, R23.4-02 | — (N/A) | all Stage 9 contracts are v1; no converter exercised; recorded in the guide register |
| R10.4-03 | 5 | `U/pers/test_sqlite_artifact_repositories.py::test_egress_revalidates_and_refuses_reinterpretation` |
| R11.3-01, R11.3-09, R20.3-02 | 2, 3 (conditional) | `U/domain/test_metric_value.py::test_unit_methodology_status_mandatory_no_nan`; `U/domain/test_normalized_records.py::test_source_artifact_and_provenance_required` |
| R11.3-02, R11.5-09, R11.5-10, R11.5-11 (literal half), T28.1-04 | — (EXISTS) | `U/artifacts/test_ownership.py`, `P/test_artifact_ownership.py` (existing) |
| R11.5-11 (registry half), R19.1-04 | 6 | `U/artifacts/test_artifact_finalizer.py::test_owner_inconsistent_with_registry_refused_before_io` |
| R11.3-03, R11.3-04, R11.5-03, R11.5-04, R11.5-05, R19.1-15, R19.1-19, R19.1-22, T28.1-03 | 1 | `U/artifacts/test_artifact_models.py::test_candidate_states_and_forbidden_transitions`, `::test_producer_governed_fields` (adapter-declared fields and provenance only on adapter-produced `RUN` `RESULT` candidates; a staging path is refused by `ArtifactRef`) |
| R19.4-07, R19.4-08 | 6, 8 | `I/art/test_finalization_races.py::test_rc14` (no `RunManifest`, no RESULT for a non-success run; result bytes never relabeled); `I/pers/test_stage9_supervised_finalization.py::test_native_output_preserved_as_result_only_on_success` (native bytes registered unmodified: the finalized blob hash equals the staging hash) |
| R11.3-05, R11.5-06, R19.1-16, A33.6-02 | 1 | `U/artifacts/test_artifact_models.py::test_artifact_ref_every_field_required_and_finalized` |
| R11.3-06, R19.4-04 | — (EXISTS) | `U/adapters/test_adapter_manifests.py` (existing; e.g. `:1696 test_oversized_manifest_bytes_are_never_decoded`) |
| R11.3-07, R19.4-05, R23.3.1-09 | 5, 7 | `U/pers/test_sqlite_artifact_schema.py::test_sanitized_manifest_row_has_no_token_or_path`; `U/exp/test_finalization_service.py::test_sanitized_manifest_is_run_evidence_after_any_outcome` |
| R11.3-08, R19.1-17, R11.5-07, R11.5-08, T28.1-06, A33.6-03 | 7 | `U/exp/test_run_manifest.py::test_only_matching_run_result_refs`, `::test_exit_category_from_exited_invocation` |
| R11.3-10, R21.1-01, T28.1-02 | — (EXISTS) | `U/domain/test_diagnostics.py` (existing) |
| R11.3-11 | 2 | `U/audit/test_audit_models.py::test_invocation_required_for_command_actions` |
| R11.3-12, R23.3.1-03, T28.1-07, I-7 | 5, 7 | `U/pers/test_sqlite_artifact_schema.py::test_stderr_artifact_id_targets_core_evidence_only` (both halves of 23.3.1:1703: `RUN` owner for validate/run, `ADAPTER` owner for describe — §3.1.1 row 3); `U/exp/test_finalization_service.py::test_conclude_describe_stages_descriptor_and_stderr_only` (the `ADAPTER` half driven in production, §4.6) |
| R11.4-01, R11.4-02 | — (no converter) | reading 6 |
| R11.5-02, I-6 | 5 | `U/domain/test_engine_run_record.py::test_deadline_present_only_in_snapshot_states` |
| R11.5-12 | 1 | `U/artifacts/test_artifact_models.py::test_enum_memberships_exact` |
| R14.5-01, T28.2-03 | 7 | `U/exp/test_finalization_service.py::test_artifact_produced_creates_only_a_candidate` |
| R14.5-02, R19.2-01 | 6 | `U/artifacts/test_artifact_finalizer.py::test_nine_step_order_observed_by_probe` |
| R14.7-02 | 7 | `U/exp/test_finalization_service.py::test_stderr_truncation_diagnostic_and_audit` |
| R14.7-03, R14.7-04, R21.2.1-05, T28.3-05 | 6, 7 | `U/artifacts/test_artifact_finalizer.py::test_leakage_rejects_every_result_candidate`; `U/exp/test_finalization_service.py::test_unsanitized_stdout_never_staged` |
| R14.7-05, R14.7-06, R29.5-02, T28.3-06 (cleanup half) | 6, 7, 8 | `I/art/test_finalization_recovery.py::test_raw_bytes_survive_lease_and_vanish_at_close` (the leased path and the `close_raw_bytes` primitive: removal, quarantine of a held file, audit), `::test_rv8` (the step-9 sweep); `U/exp/test_finalization_service.py::test_conclude_command_closes_raw_bytes_without_a_lease`; `I/pers/test_stage9_supervised_finalization.py::test_failure_row_keeps_only_evidence` (raw bytes gone from the `RUN` root before `recover()`) |
| T28.3-06 (regeneration half: recovery regenerates an identical sanitized manifest without finalizing the original) | 7 | `I/art/test_finalization_recovery.py::test_rv1`; `U/exp/test_finalization_service.py::test_sanitized_manifest_is_run_evidence_after_any_outcome` |
| R14.7-07, R19.1-20, R15.6-02 | 6 | `I/art/test_finalization_recovery.py::test_rv17`, `::test_rv18` |
| R29.2-04 (step 9: orphans, purpose mismatches, failed result candidates and the raw-bearing bytes of their terminal attempts, unregistered content) | 6 | `I/art/test_finalization_recovery.py::test_rv6`, `::test_rv7`, `::test_rv8`, `::test_rv9` |
| R14.7-08, R19.1-13 | 4 | `U/artifacts/test_content_hashing.py::test_binary_candidate_with_token_rejected` |
| R14.8-02, R19.3-05, R21.2.1-01, T28.3-01 | 6 | `I/art/test_finalization_races.py::test_rc4`, `::test_rc5`; `I/art/test_finalization_recovery.py::test_rv15` |
| R14.8-03, R19.3-03 | 6, 7 | `I/art/test_finalization_races.py::test_rc2`, `::test_rc3` (reading 1) |
| R14.8-04 | — (EXISTS Stage 7) | `tests/unit/process_supervision/test_supervisor_loop.py:994 test_a_deadline_passing_before_the_handoff_times_out_from_starting_without_process_facts`, `:2171 test_a_timed_out_describe_counts_every_byte_including_post_decision_ones` |
| R15.5-02 | 4, 7 | `U/artifacts/test_artifact_store.py::test_write_staged_is_exclusive_and_fsynced`; `U/exp/test_finalization_service.py::test_core_staging_root_by_owner` |
| R15.5-03, R19.3-10, T28.3-02, T28.5-01 | 4 | `I/art/test_windows_artifact_platform.py::test_junction_symlink_hardlink_rejected`, `::test_mutation_during_hashing_rejected`, `::test_open_handle_move_failure` |
| R15.6-01, R29.3-01..05, R17.3-01 | 6, 7 | `I/art/test_finalization_recovery.py::test_rv1`, `::test_rv2`, `::test_rv4` (Task 7), `::test_rv5` (Task 6) |
| R15.7-03, R17.2-01 (stale), R29.3-07 | 6, 7 | `I/art/test_finalization_races.py::test_rc8`, `::test_rc16` |
| R17.2-01, R17.2-02, R29.6-01, T28.4-02, T28.1-05 | 6, 7 | `I/art/test_finalization_races.py::test_rc6`, `::test_rc7`, `::test_rc10`; `P/test_finalization_idempotency.py::test_identities_disjoint_and_replay_stable` |
| R17.2-03 | 7 | `U/exp/test_finalization_service.py::test_timeout_never_retries_in_place` |
| R17.2.1-01, R21.2-01, R21.2.1-10 | — (EXISTS Stage 5), 1 | `U/domain/test_retry_records.py:200-208` (the category partition; `SECURITY.SENSITIVE_MATERIAL_LEAKAGE` at `:133`); `U/artifacts/test_artifact_diagnostics.py::test_hard_codes_are_category_blocked` (the three codes' categories ∈ `HARD_BLOCKING_DIAGNOSTIC_CATEGORIES`) |
| R17.3-02, R17.3-03 | 6 | `I/art/test_finalization_recovery.py::test_rv5`, `::test_terminal_attempts_never_reopened` |
| R18.3-01 (lexical half) | — (EXISTS Stage 4) | `src/crypto_lab/datasets/models.py:111-135`; `tests/unit/datasets/test_dataset_models.py` (existing) |
| R18.3-01 (physical half) | — (§1.4) | no dataset file is opened in Project 1; owner: the dataset-ingest producer |
| R18.3-02 | 7 | `U/exp/test_finalization_service.py::test_dataset_input_evidence_hash_equals_registry` |
| R19.1-01, R19.1-06, R19.1-07, R19.1-08, R19.3-01, R19.3-02, R29.3-07 | 6 | `I/art/test_finalization_races.py::test_rc1`, `::test_rc14` |
| R19.1-02, R19.1-03, T28.3-09, A33.6-06 | 8 | `I/pers/test_stage9_supervised_finalization.py::test_owner_variants_end_to_end[kind]` (the `ADAPTER` case through `describe()` → `conclude_describe`, §4.6) |
| R19.1-09, R19.1-11, R19.1-12, R29.4-01 | 6, 7 | `U/artifacts/test_artifact_finalizer.py::test_evidence_roles_and_owners`; `I/art/test_finalization_recovery.py::test_rv16` |
| R19.1-18 (field half; the operation half is §1.4, reading 25) | 1 | `U/artifacts/test_artifact_manifest.py::test_correction_links_superseded_artifact` |
| R19.1-21, R19.2-07 | 6 | `U/artifacts/test_artifact_finalizer.py::test_failed_candidate_is_quarantined_or_corrupt` |
| R19.2-03 | 6 | `U/artifacts/test_artifact_finalizer.py::test_manifest_built_at_step_four` (the manifest facts fixed in phase 1 before the lease are what T3 writes; T3 adds only `finalized_at_utc` and the validation diagnostic ids — §4.3 phases 1 and 5) |
| R19.2-04, R23.3.1-17 | 7 | `U/exp/test_finalization_service.py::test_only_result_branch_creates_links_manifest_success` |
| R19.2-05, R19.2-08 | 4 | `U/artifacts/test_artifact_store.py::test_content_addressed_dedup_never_overwrites` |
| R19.2-06 | 5 | `U/pers/test_sqlite_artifact_repositories.py::test_registration_leaves_candidate_finalizing` |
| R19.2-10, R19.3-07, R19.3-08, R19.3-09, T28.3-07, T28.3-10, T28.3-11, A33.5-01 | 6, 7 | `I/art/test_finalization_crash_points.py::test_cp1_*` … `::test_cp7_*` (14 cells) |
| R20.1-01, R20.1-02, R20.1-03, A33.6-07 | 8 | `I/pers/test_stage9_supervised_finalization.py::test_native_output_preserved_as_result_only_on_success` |
| R20.4-01 | — (EXISTS Stage 4) | `tests/unit/capabilities/test_capability_comparison.py:665 test_a_declared_difference_removes_the_parity_claim`, `:703 test_a_declared_difference_is_never_converted_to_equality` |
| R21.1-02, R21.2.1-09 | 1 | `U/artifacts/test_artifact_diagnostics.py::test_codes_stable_and_within_category` |
| R21.2-02, R21.2.1-07, R21.2.1-08 | 6 | `U/artifacts/test_artifact_finalizer.py::test_persistence_failure_rolls_back_journal_drives_recovery` |
| R21.2.1-02 | 7 | `U/exp/test_finalization_service.py::test_identity_violation_blocks_result_not_evidence` |
| R21.2.1-03, R21.2.1-04, R21.2.1-06 | 6, 7 | `U/artifacts/test_artifact_finalizer.py::test_path_violation_and_validation_failure_outcomes`; `U/exp/test_finalization_service.py::test_manifest_invalid_fails_run` |
| R21.3-02 | 7 | `U/exp/test_finalization_service.py::test_diagnostic_report_evidence_sanitized` |
| R21.4-01 | 7 | `U/exp/test_finalization_service.py::test_causal_chain_terminal_references_artifact_findings` |
| R22.5-01, R22.5-02 | 4 | `U/artifacts/test_artifact_store.py::test_same_volume_preflight` (probe + rejection) |
| R22.5-03 | 4 | `I/art/test_windows_artifact_platform.py::test_long_path_rejection_always_success_conditional` |
| R23.3-01, R23.3.1-01, R23.3.1-04..08, R23.3.1-10, R23.3.1-11, R23.3.1-19, I-1, I-2 | 5 | `U/pers/test_sqlite_artifact_schema.py::test_tables_constraints_and_triggers[...]` (one case per constraint of §3.3/§3.4), `::test_restrict_everywhere` |
| R23.3.1-14, R23.3.1-16, R23.3.1-18 | 6, 7 | `U/artifacts/test_artifact_finalizer.py::test_step_one_fields_by_purpose`; `I/art/test_finalization_crash_points.py` |
| R23.4-01 | 5 | `U/pers/test_sqlite_stage9_migration.py::test_r0001_is_behind_r0002_is_current_newer_blocks` |
| R29.1-01, R29.1-03 | 4, 7 | `U/artifacts/test_artifact_store.py::test_rename_only_same_volume`; `U/exp/test_finalization_service.py::test_non_success_never_waits_for_evidence` |
| R29.1-02 | — (EXISTS Stage 6/7) | `tests/unit/process_supervision/test_supervisor_loop.py:1585 test_a_zero_exit_without_output_is_a_process_fact_and_moves_no_run`; `tests/unit/adapters/test_command_reconciliation.py:1616 test_a_valid_result_on_exit_zero_is_validated_ready_without_a_diagnostic` |
| R29.1-04, R29.2-01, R29.2-02, R29.2-03 | 6, 7 | `I/art/test_finalization_recovery.py::test_rv14` and the RV rows |
| R29.2-06 | — (OOS Stage 10/7) | Stage 8 plan 180, 198 |
| R29.3-08, R29.3-09, R29.3-10 | 7 | `I/art/test_finalization_recovery.py::test_rv1` (hash verified separately), `::test_rv2` (never repaired) |
| R29.5-01 | 4, 6 | `U/artifacts/test_artifact_store.py::test_disk_full_permission_lock_diagnostics` (asserts category `PERSISTENCE` and no hard block, reading 26) |
| R29.5-03 | — (OOS later) | Stage 8 plan 184 |
| R30.1-01, R30.1-03 (bounded, rotated) | 2 | `U/audit/test_jsonl_log.py::test_record_schema_rotation_and_retention` |
| R30.1-03 ("snapshotted in audit events") | — (reading 14, §1.4) | Stage 10 composition, where TOML is loaded |
| R30.2-01 | 7 | `U/exp/test_finalization_service.py::test_one_correlation_across_finalization_diagnostics_audit` |
| R30.3-01 (artifact family and the finalization-side run writes), R30.3-02 | 6, 7 | `U/artifacts/test_artifact_finalizer.py::test_every_phase_audited_in_its_transaction`; `U/exp/test_finalization_service.py::test_manifest_invalid_fails_run` and `I/art/test_finalization_recovery.py::test_rv2` (`RUN_FAILED` asserted by name) |
| R30.3-01 (operation bullets) | — (reading 14) | Stage 10 |
| R30.4-01, R30.5-01 | 8 | `I/pers/test_stage9_supervised_finalization.py::test_failure_exposes_code_category_retriable_evidence` (data only), `::test_success_row_registers_manifest_and_refs` (the success half of 30.5:2237: `RunManifest`, metrics and result refs only for success) |
| T28.2-01 | 7 | `U/exp/test_finalization_service.py::test_manifest_validation_sanitization_generation_reconciliation` |
| T28.2-02 | 7 | `U/exp/test_finalization_service.py::test_protocol_capture_regenerated_from_ledger` |
| T28.3-03 | — (EXISTS Stage 6/7) | `tests/contract/test_run_contract.py:400`, `tests/unit/adapters/test_command_reconciliation.py:1459, 1616, 2515`, `tests/unit/process_supervision/test_supervisor_loop.py:1585`; Stage 9 adds `::test_adapter_claiming_core_ids_rejected` in `U/exp/test_finalization_service.py` |
| T28.3-04 | 4, 8 | `P/test_token_scan_chunk_boundaries.py`; `I/pers/test_stage9_token_absence.py` |
| T28.3-08 | 7 | `I/art/test_finalization_races.py::test_rc9[outcome]`, `::test_rc14` |
| T28.3-12 | 6, 8 | every CP/RC/RV test asserts the six facets through `durable()` |
| T28.4-01 | 4 | `P/test_artifact_path_boundaries.py` |
| T28.4-03 | 4 | `P/test_token_scan_chunk_boundaries.py`; `P/test_audit_redaction_determinism.py` (Task 2) |
| A33.2-01 | 1, 2, 3 (conditional), 7 | `U/test_schema_registry.py::test_stage_nine_entries_rendered_and_registered` |
| A33.5-02 | 5 | `U/pers/test_sqlite_artifact_schema.py::test_tables_constraints_and_triggers[...]`, `::test_success_requires_manifest_and_manifest_requires_running`; `U/pers/test_sqlite_finalization_journal.py::test_result_and_evidence_identities_disjoint`; `U/pers/test_sqlite_finalization_deadline.py::test_deadline_immutable_once_set` |
| A33.6-01 | 8 | `I/pers/test_stage9_supervised_finalization.py::test_both_purposes_share_the_pipeline_only_result_succeeds` |
| A33.6-09 | 2, 8 | `U/audit/test_redaction.py`; `I/pers/test_stage9_token_absence.py` |
| I-3 | 7 | `U/exp/test_finalization_service.py::test_adapter_diagnostic_ids_are_stable` |
| I-4, I-5, I-8, I-10 | — | §1.5 dispositions |
| I-9 | 7, 8 | `I/pers/test_stage9_supervised_finalization.py::test_zero_dangling_diagnostics_after_every_row` |
| O-14 post-success replay (Stage 6 plan 111; reading 24) | 7 | `U/exp/test_finalization_service.py::test_post_success_replay_returns_stored_conclusion` |
| RC-17, reading 23 | 7 | `I/art/test_finalization_races.py::test_rc17` |

### 7.3 Property tests (`hypothesis`, bounded, `deadline=None` per the repository convention)

`P/test_artifact_path_boundaries.py` (separators, traversal, drive/UNC,
Unicode NFC/NFD, ADS, reserved names, length; the property: `confine_candidate_path`
accepts exactly the strings `validate_relative_candidate_path` accepts minus
ADS, and never resolves outside the root); `P/test_artifact_type_separation.py`
(any valid candidate payload fails `ArtifactRef`, any valid ref payload
fails `CandidateArtifact`; any candidate state fails `state="FINALIZED"`);
`P/test_purpose_role_cross_products.py::test_exactly_seven_rows_validate`
(§3.1.1: the seven rows, nine owner tuples, counted explicitly);
`P/test_finalization_idempotency.py` (`finalization_identity` differs between
purposes for any shared fields; same inputs ⇒ same ids; `MemoryFinalizationUnitOfWork`
replay returns the same `FinalizationResult`); `P/test_token_scan_chunk_boundaries.py`
(token of 32–1024 URL-safe bytes placed at every offset of a 0–3 chunk
payload under chunk sizes 1–4096: found iff present; absence under
arbitrary split points); `P/test_audit_redaction_determinism.py`
(`redact_details` is idempotent and removes any value containing a
token-shaped substring; details hash stable under key order).
`tests/property/test_artifact_ownership.py` is extended with the fixed owner
hash vectors of the six variants (28.4:2111) — an addition, not an edit of
existing cases.

### 7.4 Re-pointed suites

| Suite | Treatment | Task |
|---|---|---|
| `tests/unit/domain/test_engine_run_record.py` | the "deadline absent throughout Stage 5" case becomes the state-governed pair of reading 9 (present in `RUNNING`… accepted; present in `PENDING` refused) | 5 |
| `tests/unit/persistence/test_sqlite_repositories.py`, `test_sqlite_constraints.py` | the rule-N4 refusal cases become the admitted/refused pair | 5 |
| `tests/unit/persistence/test_sqlite_migrations.py`, `test_sqlite_schema.py` | head, directory, object digest, table list move (§2.6) | 5 |
| `tests/unit/test_schema_registry.py`, `tests/unit/domain/test_domain_descriptors.py` | counts and `_STAGE9_PATHS` | 1, 2, 3, 7 |
| `tests/integration/persistence/test_stage8_supervised_flow.py` | unchanged; the Stage 9 rows live in the new module over the extended flow | 8 |
| `tests/unit/adapters/test_adapter_diagnostics.py` | profile tail slice | 1 |

### 7.5 Windows platform cases (Tasks 4, 6, 8; 28.5)

Paths with spaces and Unicode components for staging, store and quarantine
roots; atomic same-volume rename; `PermissionError` on a candidate held open
by another handle (the Stage 7 share-lock fixture); junction and
reparse-point rejection; hard-link rejection; long-path rejection always and
success conditionally; WAL restart recovery of a `MOVED` journal (CP-6 through the crash child
killed with T3 open, with the retained-handle discipline of the Stage 8
walfix); orphan directories after a killed child (CP-5).

### 7.6 What Stage 9 tests never do

Install or import an engine; contact a network; write outside `tmp_path`;
read the ambient environment; use `os.system` or a shell; sleep on a wall
clock (`FixedClock` is advanced explicitly; the crash child blocks on an
event, not a sleep); kill by PID without creation identity (the Stage 7
controller idiom); weaken a ceiling, skip, timeout or coverage floor;
construct a candidate or reference through a test-only type (every record
is the production type); assert an unreachable race (§5.4).

---

## 8. Task decomposition

Nine vertical tasks, sized by the dependency graph of §1.2 (artifact
contracts → audit and metric contracts → normalized records (conditional) →
paths, hashing, validation, store → relational increments → finalizer and
recovery → application integration → composition and scans → status). No
task depends on a file created by a later task; Task 3 is depended on by no
task. Each is test-first: focused RED, minimum implementation, focused
GREEN, then broader verification; each ends in one commit and a clean
worktree. Before every task commit the complete `scripts/verify.ps1` runs
alone (§9.2); each task's **Broader tests** field names the launcher
`pytest-focused` sets run before the independent review and is never a
substitute for that verifier run. Focused runs use the launcher `pytest-focused` profile with
`-o addopts=` (diagnostic only, no coverage number). **Every task that
creates a module under `src/crypto_lab`, first defines a deferred name, first
imports a new root, first imports an infrastructure root in a module, or
appends a schema entry also edits the guard files exactly as §2.6 tabulates;
those edits are owned by the task and are not repeated in each file list,
and each such task's focused RED includes the §2.6 guard expectations for
its own paths, names, roots, pairs and schema positions.** Every task's
**Quality gates** are the launcher `ruff-format-all` (apply the printed diff
by hand), `ruff-check-all`, `mypy-all`, `schema-generate-check` and
`migration-check`. Every task's **Schema and migration preservation** is
`schema-generate-check` clean with the 35 Stage 3–6 files byte-identical
(`git diff --stat -- schemas/` shows only the Stage 9 additions of that task
and earlier tasks) and `migration-check` green with exactly one head
(`r0001` through Task 4, `r0002` from Task 5). Every task's **Independent
review** is a fresh reviewer over the task's diff with the task's declared
readings listed; every task's **Clean-worktree checkpoint** is `git status
--short` empty after the commit with every guard edit inside it. Every RED
sketch is judged as strict-mypy, ruff-clean code. RED tables name file, test
and the expected failure reason; the executor writes the bodies from §3–§7.

### Task 1 — Artifact canonical contracts, identities, profiles and schemas

**Objective.** Deliver the artifact record family of §3.1 (candidate,
reference, mappings, result, both requests, correlation, manifest, journal
entry), the five enums, two identities, five hashing profiles, the eight
`artifacts/` schemas, and the `ARTIFACT.*`/`SECURITY.*` code table; retire
the Stage 7 "Stage 9 names stay deferred" negative.
**Prerequisites.** Planning base merged; a fresh worktree synced with the
launcher `sync` profile.
**Files created.** `src/crypto_lab/artifacts/models.py`,
`src/crypto_lab/artifacts/requests.py`, `src/crypto_lab/artifacts/journal.py`,
`src/crypto_lab/artifacts/manifest.py`, `src/crypto_lab/artifacts/diagnostics.py`,
`schemas/artifacts/{candidate-artifact,artifact-ref,artifact-finalization-purpose,artifact-manifest,result-finalization-request,evidence-finalization-request,finalization-result,finalization-journal-entry}-v1.schema.json`
(rendered by the schema tool), `tests/unit/artifacts/test_artifact_models.py`,
`tests/unit/artifacts/test_finalization_requests.py`,
`tests/unit/artifacts/test_artifact_manifest.py`,
`tests/unit/artifacts/test_finalization_journal.py`,
`tests/unit/artifacts/test_artifact_diagnostics.py`,
`tests/property/test_artifact_type_separation.py`,
`tests/property/test_purpose_role_cross_products.py`.
**Files modified.** `src/crypto_lab/domain/identifiers.py` (`FinalizationId`,
`RunManifestId`), `src/crypto_lab/domain/hashing.py` (five profiles,
`artifact_id_for`, `finalization_id_for`, `core_candidate_artifact_id_for`,
`candidate_set_hash_for`, `finalization_identity`),
`src/crypto_lab/domain/__init__.py` (exports), `src/crypto_lab/artifacts/__init__.py`
(exports; docstring no longer says "finalization remains deferred"),
`src/crypto_lab/schema_registry.py` (positions 35–42), `tests/unit/domain/test_hashing.py`
(new vectors), `tests/unit/adapters/test_adapter_diagnostics.py` (`[8:12]`, 17),
`tests/unit/domain/test_lifecycle_tables.py` (`:539-540` → 17; the five value
strings join the render scan `:541-545`),
`tests/unit/test_schema_registry.py`, `tests/unit/domain/test_domain_descriptors.py`,
`tests/safety/test_stage3_boundaries.py` (paths → 115; deferred 33 → 22;
mutation list: the three released names swapped for `MetricValue`,
`AuditEvent`, `ContentHasher`, seven live cases; registry 43), `tests/unit/test_package_layout.py`,
the six cross-pin files of §2.6, `tests/safety/test_stage7_boundaries.py`
(retire `test_stage_nine_finalization_names_stay_deferred`, `_STAGE8_AND_LATER_NAMES`),
`tests/safety/test_stage8_boundaries.py` (`:881` retired; census 115/22/43/17),
`tests/architecture/test_package_import_boundaries.py` (`_ALLOWED_FOR_ARTIFACTS`).
**Interfaces consumed.** `CanonicalModel`, identifiers, `profile_hash`,
`_uuid4_shaped`, `ArtifactOwnerRef`, `artifact_owner_hash`, `ErrorCode`,
`DiagnosticCategory`, `exact_string_schema`.
**Interfaces produced.** Everything in §3.1 rows 1–12, §3.2 enums, identities
and derivations; `artifacts/diagnostics.py`: the four Stage 6 literals
re-declared equal (`PATH_BOUNDARY_VIOLATION`, `VALIDATION_FAILED`,
`RESULT_MANIFEST_INVALID`, `SENSITIVE_MATERIAL_LEAKAGE`; `artifacts` may not
import `adapters`) and the three new codes `FINALIZATION_TIMED_OUT`
(`TIMEOUT`, `False`), `MOVE_FAILED` (`PERSISTENCE`, `False`, reading 26),
`QUARANTINE_OVERDUE`; `artifact_failure(code, *, message, invocation_id,
run_id, experiment_id, causal_ids, now_utc) -> Failure` with the
category/retriable table of 21.2.1, equal to `adapters/diagnostics.py:145-156`
for the four shared codes.
**Owned schema/migration/configuration changes.** Eight schema entries.
**Guard/dependency transitions.** §2.6: paths → 115; names 33 → 22; registry
35 → 43; profiles 12 → 17; `_ALLOWED_FOR_ARTIFACTS`; Stage 7 negative retired.

- [ ] **Step 1: Focused RED.**

| File | Test | Fails because |
|---|---|---|
| `test_artifact_models.py` | `test_enum_memberships_exact` | enums undefined |
| | `test_candidate_states_and_forbidden_transitions` (all 25 pairs; the five allowed edges plus `FINALIZING → FINALIZING` with a registered mapping) | `CandidateArtifact` undefined |
| | `test_producer_governed_fields` (ADAPTER requires declared fields, RUN owner with invocation, RESULT, result role; CORE prohibits) | — |
| | `test_artifact_ref_every_field_required_and_finalized` (each field removed ⇒ `ValidationError`; `state="CANDIDATE"` ⇒ error; candidate payload ⇒ error) | — |
| | `test_adapter_cannot_declare_evidence_owner_role_or_path` | — |
| | `test_unknown_fields_and_implicit_none_rejected` (`None` for a `MISSING` field is rejected in strict mode) | — |
| `test_finalization_requests.py` | `test_result_branch_fields`, `test_evidence_branch_exactly_one_typed_correlation`, `test_other_branch_fields_rejected`, `test_generic_string_cannot_be_correlation`, `test_idempotency_key_recomputed` | undefined |
| `test_artifact_manifest.py` | `test_manifest_fields_and_owner_lineage` (six variants), `test_self_hash_omitted_by_named_profile`, `test_staging_path_never_in_finalized_field`, `test_correction_links_superseded_artifact` | undefined |
| `test_finalization_journal.py` | `test_purpose_governed_fields`, `test_state_order_and_abandon_reason`, `test_lease_never_past_deadline` | undefined |
| `test_artifact_diagnostics.py` | `test_codes_stable_and_within_category`, `test_retriable_flags_match_table`, `test_shared_codes_equal_the_stage6_posture` (code, category, retriable against `adapters/diagnostics.py:84-87,145-156`), `test_hard_codes_are_category_blocked` (the three codes' categories ∈ `HARD_BLOCKING_DIAGNOSTIC_CATEGORIES`; `MOVE_FAILED`'s is not) | undefined |
| `test_hashing.py` | `test_stage_nine_profiles_are_named_and_ordered` (`len == 17`, exact tail), `test_derived_identities_are_uuid4_shaped_and_stable` | profiles absent |
| `test_schema_registry.py` | `test_stage_nine_entries_rendered_and_registered` (positions 35–42; `len == 43`) | absent |
| `test_purpose_role_cross_products.py` | `test_exactly_seven_rows_validate` (nine tuples) | undefined |
| `test_artifact_type_separation.py` | as §7.3 | undefined |

plus: the §2.6 guard expectations (115 paths, 22 names, the seven-name
mutation list with its three swaps, registry 43, profiles 17, `_ALLOWED_FOR_ARTIFACTS` closure self-tests,
the retired Stage 7 negative replaced by a Stage 3 positive that each of the
nine names is now defined in exactly its §2.6 module).
- [ ] **Step 2: Run the focused set and confirm every new test fails for the
  expected reason** (`ImportError`/`AttributeError` for the new names; the
  guard counts at their base values).
- [ ] **Step 3: Minimum GREEN.** The modules of §3.1–§3.2 with their
  validators; schema registration; the derivations.
- [ ] **Step 4: Focused GREEN.** `tests\unit\artifacts tests\property\test_artifact_type_separation.py tests\property\test_purpose_role_cross_products.py tests\unit\domain\test_hashing.py tests\unit\test_schema_registry.py tests\safety tests\architecture -q`.
- [ ] **Step 5: Quality gates, Schema and migration preservation, Security and
  boundary review, Independent review, Commit, Clean-worktree checkpoint.**

**Broader tests.** `tests\unit tests\safety tests\architecture tests\property`;
then `scripts/verify.ps1` alone before the commit (§9.2).
**Windows-specific tests.** None.
**Minimum passing evidence.** Focused set green; eight new schema files equal
their rendered bytes; the 35 digests unchanged; `migration-check` green on
`r0001`.
**Security and boundary review.** No `AttemptToken` annotation; no I/O; no
import outside `domain`/`pydantic`/stdlib typing roots; `extra="forbid"`
everywhere; `hide_input_in_errors` inherited.
**Independent review.** Readings 17, 22; §3.1.1 table versus the model
validators and the property generator.
**Commit message.** `feat: add artifact candidate, reference, request and journal contracts`

### Task 2 — Audit, log, correlation, redaction and metric contracts

**Objective.** Deliver `crypto_lab.audit` (models, redaction, correlation,
JSON Lines writer, `AuditSink`/`AuditEventIds` ports) and `domain/metrics.py`
with their three schemas and the `AUDIT_EVENT_DETAILS_V1` profile.
**Prerequisites.** Task 1.
**Files created.** `src/crypto_lab/audit/models.py`, `.../redaction.py`,
`.../correlation.py`, `.../jsonl.py`, `.../sink.py`, `src/crypto_lab/domain/metrics.py`,
`schemas/audit/audit-event-v1.schema.json`, `schemas/audit/log-record-v1.schema.json`,
`schemas/domain/metric-value-v1.schema.json`, `tests/doubles/artifacts.py`
(builders, `SequentialAuditIds`), `tests/unit/audit/__init__.py`,
`tests/unit/audit/test_audit_models.py`, `.../test_redaction.py`,
`.../test_correlation.py`, `.../test_jsonl_log.py`,
`tests/unit/domain/test_metric_value.py`, `tests/property/test_audit_redaction_determinism.py`.
**Files modified.** `domain/hashing.py` (profile 18), `domain/__init__.py`,
`audit/__init__.py`, `schema_registry.py` (43–45), the registry and census
pins (→ 121 paths, 19 names, 46 schemas, 18 profiles —
`tests/unit/domain/test_lifecycle_tables.py:539-540` included, with the one
value string joining its render scan; mutation list:
`MetricValue`, `AuditEvent` → `ComparisonEligibilityService`,
`ArtifactRepository`),
`tests/architecture/test_package_import_boundaries.py` (`_ALLOWED_FOR_AUDIT`).
**Interfaces consumed.** `Diagnostic` bounds and the secret-key denylist
(`domain/diagnostics.py:33-62`), `CorrelationId`, `AuditEventId`,
`ComparisonLevel`, `SemanticVersion`, `CanonicalDecimal`, `Clock`.
**Interfaces produced.** `AuditEvent`, `AuditAction`, `AuditActor`,
`AuditOutcome`, `LogRecord`, `LogSeverity`, `MetricValue`, `MetricValueType`,
`MetricStatus`; `redact_details(details) -> BoundedDetails` and
`contains_token_shape(text) -> bool` (the Stage 6 redaction rule re-exposed
over `JsonValue` trees: any string value matching the attempt-token grammar
or any denylisted key is replaced by `"[REDACTED]"`); `CorrelationContext(
correlation_id, experiment_id | MISSING, run_id | MISSING, invocation_id | MISSING)`
with `.derive(**narrower)` and `.event(action, outcome, details, *, clock,
ids) -> AuditEvent`; `JsonLinesLogWriter.open(logs_root, *, retained_files,
clock) -> Result[JsonLinesLogWriter]`, `.write(record) -> Result[None]`,
`.close()`; `AuditSink`, `AuditEventIds`, `LogSink` protocols.
**Owned schema/migration/configuration changes.** Three schema entries.
**Guard/dependency transitions.** §2.6: paths → 121; names → 19; registry →
46; profiles → 18; `_ALLOWED_FOR_AUDIT`.

- [ ] **Step 1: Focused RED.**

| File | Test | Fails because |
|---|---|---|
| `test_audit_models.py` | `test_unknown_fields_rejected`, `test_invocation_required_for_command_actions` (the actions of 11.3:586 by name), `test_details_hash_recomputed`, `test_details_with_token_shape_rejected`, `test_actor_adapter_requires_both_fields`, `test_action_set_is_exactly_twenty_five` | undefined |
| `test_redaction.py` | `test_token_shaped_values_replaced`, `test_denylisted_keys_replaced`, `test_idempotent`, `test_bounds_preserved` | undefined |
| `test_correlation.py` | `test_derive_narrows_never_widens`, `test_event_carries_context_ids`, `test_no_forbidden_identifier_names` (AST: no `context`, `buffer`, `note`, `problem` in the module) | undefined |
| `test_jsonl_log.py` | `test_record_schema_rotation_and_retention` (8 MiB ceiling with a small injected ceiling constant parameter; `retained_files=2`), `test_redaction_before_serialization`, `test_open_creates_nothing_at_import`, `test_write_failure_is_a_result` | undefined |
| `test_metric_value.py` | `test_unit_methodology_status_mandatory_no_nan`, `test_defined_iff_value_present` | undefined |
| property | as §7.3 | undefined |

plus: the §2.6 guard expectations.
- [ ] **Step 2: Run the focused set and confirm every new test fails for the
  expected reason.**
- [ ] **Step 3: Minimum GREEN.**
- [ ] **Step 4: Focused GREEN.** `tests\unit\audit tests\unit\domain\test_metric_value.py tests\property\test_audit_redaction_determinism.py tests\unit\test_schema_registry.py tests\safety tests\architecture -q`.
- [ ] **Step 5: Quality gates, Schema and migration preservation, Security and
  boundary review, Independent review, Commit, Clean-worktree checkpoint.**

**Broader tests.** `tests\unit tests\safety tests\architecture tests\property`;
then `scripts/verify.ps1` alone before the commit.
**Windows-specific tests.** `test_jsonl_log.py::test_rotation_rename_on_windows`
(rename over an existing index refused; the writer picks the next index).
**Minimum passing evidence.** Focused set green; three schema files rendered.
**Security and boundary review.** The writer uses `pathlib` only, opens in
`open`, never reads the environment; no token-shaped value survives
redaction (property).
**Independent review.** Readings 9 (ordering is the sequence, so the model
has no ordering field), 15.
**Commit message.** `feat: add audit, log, correlation, redaction and metric contracts`

### Task 3 — Normalized result records (conditional: runs only after the §1.6 item 1 confirmation is recorded)

**Objective.** Deliver `domain/normalized.py` (`CanonicalOrder`, `CanonicalFill`,
`Fee`, `PositionSnapshot`, `PortfolioSnapshot`, `EquityPoint`, `OrderSide`,
`OrderType`, `PositionEffect`) with six schemas; no producer, no arithmetic.
**Prerequisites.** Task 2; the confirmation record in `.superpowers/sdd/stage9/`
(absent ⇒ this task is skipped and the §2.6 branch table's excluded values
apply from Task 4 on).
**Files created.** `src/crypto_lab/domain/normalized.py`, six
`schemas/domain/*-v1.schema.json`, `tests/unit/domain/test_normalized_records.py`.
**Files modified.** `domain/__init__.py`, `schema_registry.py` (46–51), the
registry and census pins (→ 122 paths, 10 names, 52 schemas; mutation list:
`CanonicalOrder`, `PortfolioSnapshot` → `CandidateArtifactRepository`,
`Result`).
**Interfaces consumed.** `Money`, `Price`, `Quantity`, `InstrumentRef`,
`CanonicalDecimal`, `NonNegativeDecimal`, `PositiveDecimal`, `ArtifactId`.
**Interfaces produced.** The nine names.
**Owned schema/migration/configuration changes.** Six schema entries.
**Guard/dependency transitions.** §2.6: paths → 122; names → 10; registry →
52.

- [ ] **Step 1: Focused RED.** `test_normalized_records.py`:
  `test_source_artifact_and_provenance_required`, `test_long_only_rules`
  (`quantity ≥ 0`, `SELL` with `OPEN_OR_INCREASE` refused), `test_limit_price_iff_limit`,
  `test_average_entry_absent_iff_zero_quantity`, `test_fee_currency_explicit`,
  `test_equity_series_decimal_only`, `test_no_float_anywhere`; registry
  positions 46–51; guard pins.
- [ ] **Step 2: Run the focused set and confirm every new test fails for the
  expected reason.**
- [ ] **Step 3: Minimum GREEN.**
- [ ] **Step 4: Focused GREEN.** `tests\unit\domain\test_normalized_records.py tests\unit\test_schema_registry.py tests\safety tests\architecture -q`.
- [ ] **Step 5: Quality gates, Schema and migration preservation, Security and
  boundary review, Independent review, Commit, Clean-worktree checkpoint.**

**Broader tests.** `tests\unit tests\safety tests\architecture tests\property`;
then `scripts/verify.ps1` alone before the commit.
**Windows-specific tests.** None.
**Minimum passing evidence.** Focused set green; six schemas rendered.
**Security and boundary review.** No accounting logic; `_VERIFICATION_NON_GOALS`
"portfolio accounting" remains true (asserted by Task 9's review).
**Independent review.** §1.6 item 1 reading; no later task imports the module.
**Commit message.** `feat: add normalized result record contracts`

### Task 4 — Path confinement, streaming hashing and token scan, candidate validation, the artifact store

**Objective.** Deliver the filesystem discipline of §6: `confine_candidate_path`,
`StreamingContentHasher` (`ContentHasher`), `validate_candidate`, `ArtifactStore`
with preflight, `atomic_move`, `quarantine_move`.
**Prerequisites.** Task 1 (Task 2 for `contains_token_shape`).
**Files created.** `src/crypto_lab/artifacts/paths.py`, `.../hashing.py`,
`.../validation.py`, `.../store.py`, `tests/unit/artifacts/test_artifact_paths.py`,
`.../test_content_hashing.py`, `.../test_candidate_validation.py`,
`.../test_artifact_store.py`, `tests/property/test_artifact_path_boundaries.py`,
`tests/property/test_token_scan_chunk_boundaries.py`,
`tests/integration/artifacts/__init__.py`,
`tests/integration/artifacts/test_windows_artifact_platform.py`.
**Files modified.** `artifacts/__init__.py`; `tests/safety/test_stage3_boundaries.py`
(paths → 126; roots 29 → 30 with `os`; mutation list: `ContentHasher` →
`ingest_dataset`, `def` plant shape); `tests/unit/persistence/test_sqlite_database.py:1812`
(persistence-scoped restatement); the cross-pins; names → 9.
`tests/safety/test_stage7_boundaries.py` is not edited (`_ROOT_CONFINEMENT`
stays 5); the `os` confinement lands in this task as
`test_artifact_store.py::test_os_is_imported_only_by_the_artifact_store`, a
tree-wide AST walk over `src/crypto_lab` asserting exactly one importer.
**Interfaces consumed.** `validate_relative_candidate_path`, limits,
`AttemptTokenMaterial`, `contains_token_shape`, `artifact_failure`,
`CandidateArtifact`, `ValidationObservation`, `PathPreflight` facts (values,
not the module).
**Interfaces produced.** `confine_candidate_path(root, relative) -> Result[ConfinedPath]`;
`ConfinedPath(path, identity: FileIdentity)`; `StreamingContentHasher(chunk_size)`
with `sha256_stream`, `sha256_and_scan`; `HashScan`;
`validate_candidate(candidate, confined, *, hasher, token, ceilings, now_utc) -> Result[ValidatedCandidate]`
(the §4.3 phase-1 checks, returning observations); `ArtifactStore.open(...)`,
`.finalized_path_for(sha256)`, `.manifest_path_for(artifact_id)`,
`.atomic_move(confined, target)`, `.quarantine_move(confined, entry_id, reason)`,
`.quarantine_entries()`, `.remove_raw_bytes(paths)`,
`.write_staged(owner_hash, staging_relative_path, payload) -> Result[ConfinedPath]`
(§6.5, the only core-staging writer); `same_volume(a, b) -> bool`.
**Owned schema/migration/configuration changes.** None.
**Guard/dependency transitions.** §2.6: paths → 126; root `os` (30); name
`ContentHasher` → 9.

- [ ] **Step 1: Focused RED.**

| File | Test | Fails because |
|---|---|---|
| `test_artifact_paths.py` | `test_untrusted_path_confined_before_open`, `test_ads_and_drive_and_unc_rejected`, `test_reparse_ancestor_rejected`, `test_hard_link_rejected`, `test_identity_recheck_detects_swap`, `test_resolve_prefix_is_separator_aware` | undefined |
| `test_content_hashing.py` | `test_sha256_is_the_authoritative_digest` (known vector), `test_streaming_never_reads_whole_file`, `test_token_found_across_chunk_boundary`, `test_binary_candidate_with_token_rejected`, `test_offset_never_recorded` | undefined |
| `test_candidate_validation.py` | `test_engine_output_untrusted_until_validated`, `test_sizes_bounded_before_parsing`, `test_declared_hash_mismatch_is_corrupt`, `test_adapter_output_cannot_request_paths_or_imports` (a JSON candidate with `import`/`exec`/absolute-path keys is just bytes; nothing is interpreted), `test_media_type_closed_set` | undefined |
| `test_artifact_store.py` | `test_same_volume_preflight` (probe: two files under `tmp_path` share `st_dev`; rejection: a UNC-shaped root and a reparse root), `test_content_addressed_dedup_never_overwrites`, `test_rename_only_same_volume`, `test_os_errors_become_stable_diagnostics`, `test_disk_full_permission_lock_diagnostics`, `test_quarantine_entry_written_exclusive`, `test_write_staged_is_exclusive_and_fsynced` (exclusive create below `<staging_root>/<owner_hash>/`, `fsync` observed through the `os` spy, equal existing bytes replayed, differing bytes `CORE.INVARIANT_VIOLATION`, a path escaping the owner root refused), `test_os_usage_is_fstat_and_fsync_only` (AST over `store.py`), `test_os_is_imported_only_by_the_artifact_store` (AST over every `src/crypto_lab` module: exactly one `os` importer) | undefined |
| property files | as §7.3 | undefined |
| `test_windows_artifact_platform.py` | `test_junction_symlink_hardlink_rejected`, `test_mutation_during_hashing_rejected` (a writer appends between chunks through the probe-free `on_chunk` hook of the hasher), `test_open_handle_move_failure`, `test_long_path_rejection_always_success_conditional`, `test_space_and_unicode_roots` | undefined |

plus: the §2.6 guard expectations (root `os`, confinement to `store.py`).
- [ ] **Step 2: Run the focused set and confirm every new test fails for the
  expected reason.**
- [ ] **Step 3: Minimum GREEN.**
- [ ] **Step 4: Focused GREEN.** `tests\unit\artifacts tests\property\test_artifact_path_boundaries.py tests\property\test_token_scan_chunk_boundaries.py tests\integration\artifacts\test_windows_artifact_platform.py tests\safety tests\architecture -q`.
- [ ] **Step 5: Quality gates, Schema and migration preservation, Security and
  boundary review, Independent review, Commit, Clean-worktree checkpoint.**

**Broader tests.** `tests\unit tests\safety tests\architecture tests\property`;
then `scripts/verify.ps1` alone before the commit.
**Windows-specific tests.** The platform module above.
**Minimum passing evidence.** Focused set green; the `st_dev` probe recorded
in the ledger with the host's values.
**Security and boundary review.** `os` attributes exactly `fstat`, `fsync`;
no `shutil`, `os.replace`, `Path.cwd`, `expanduser`; junction fixtures
created through the Stage 7 `_winapi` idiom and removed in `finally:`.
**Independent review.** Readings 18, 19, 20, 21.
**Commit message.** `feat: add artifact path confinement, streaming hashing and the content store`

### Task 5 — Relational increments, revision r0002, codecs, repositories, audit sink and the deadline admission

**Objective.** Deliver the eight tables, the column, the triggers, the
revision, the codecs, the six Stage 9 repositories, `SqliteAuditSink`/
`SqliteAuditRecorder`, `SqliteDiagnosticWriter`, the `FinalizationUnitOfWork`
members on `SqliteTransaction`, and the state-governed admission of
`finalization_deadline_utc` in domain, codec and repository.
**Prerequisites.** Task 2 (Task 1 models; audit models).
**Files created.** `src/crypto_lab/persistence/artifact_codecs.py`,
`.../artifact_repositories.py`, `.../audit_sink.py`,
`.../migrations/versions/r0002_stage9_artifacts.py`,
`tests/persistence_support/artifacts.py`, `tests/unit/persistence/test_sqlite_artifact_schema.py`,
`.../test_sqlite_artifact_repositories.py`, `.../test_sqlite_audit_sink.py`,
`.../test_sqlite_finalization_journal.py`, `.../test_sqlite_stage9_migration.py`,
`.../test_sqlite_finalization_deadline.py`, `tests/unit/artifacts/test_artifact_port_contracts.py`
(kinds `memory` — a minimal in-memory pair added to `tests/doubles/artifacts.py`
here — and `sqlite`).
**Files modified.** `persistence/schema.py` (eight row classes, the column,
`TABLES_IN_DEPENDENCY_ORDER` 13 → 21, `PARTIAL_INDEX_SQL`, `TRIGGER_SQL`),
`persistence/codecs.py` (rule N4 → the state-governed pair), `persistence/repositories.py`
(`:906-908` guard → the pair; `SqliteEngineRunRepository` gains
`snapshot_deadline`, `record_timeout`, `active_attempt_facts` as
`ResultLeaseRepository`), `persistence/unit_of_work.py` (members
`candidate_artifacts`, `artifact_refs`, `finalization_journal`, `run_manifests`,
`sanitized_manifests`, `validation_results`, `run_artifacts`, `result_leases`,
`diagnostics_writer`, `audit` — with `engine_runs` and `command_invocations`
already present, the `RegistrationUnitOfWork` member set of §4.1),
`persistence/database.py` (`consistency_report`
gains `unmapped_finalizing`, `refs_without_manifest_file`,
`success_without_manifest`, `journal_open`), `persistence/migration_runner.py`
(`EXPECTED_SCHEMA_OBJECTS`), `scripts/verify_migrations.py` (pinned set),
`src/crypto_lab/domain/engine_run.py` (`:303-308` → reading 9;
`assert_deadline_snapshot`, §2.4; class docstring, field order and
annotations untouched),
`tests/unit/domain/test_engine_run_record.py`, `tests/unit/persistence/conftest.py`
(`down_revision` of the test successors → `r0002_stage9_artifacts`),
`tests/unit/persistence/test_sqlite_schema.py`, `test_sqlite_migrations.py`,
`test_sqlite_repositories.py`, `test_sqlite_constraints.py`,
`tests/safety/test_stage5_boundaries.py` (pairs 13 → 17),
`tests/safety/test_stage8_boundaries.py` (`_PERSISTENCE_MODULES` 14 → 18
through the `_STAGE9_PERSISTENCE_FILES` union at `:110-113`, four
`_PERSISTENCE_IMPORTS` literals, `_PERSISTENCE_FAMILIES` + five,
`_SQLALCHEMY_IMPORTERS` 12, `_ALEMBIC_IMPORTERS` 4, head and directory pins,
census), `tests/architecture/test_package_import_boundaries.py`
(`_ALLOWED_FOR_PERSISTENCE` + `crypto_lab.audit`, replacement negative), the
paths/cross-pins (→ 130).
**Interfaces consumed.** The Task 1/2 records, `TransactionScope`, the Stage
8 codec helpers, `SqliteArtifactOwnerRegistry`, `normalized_sql`, `metadata`.
**Interfaces produced.** The repositories of §4.1 (`Sqlite*` names) and the
transaction members (including `run_artifacts`, so `SqliteTransaction`
satisfies `RegistrationUnitOfWork` structurally); `SqliteAuditSink`, `SqliteAuditRecorder`,
`SqliteDiagnosticWriter.record(diagnostic)` (in-transaction, idempotent);
`ArtifactHarness`.
**Owned schema/migration/configuration changes.** `r0002_stage9_artifacts`;
eight tables; one column; sixteen triggers; the indexes of §3.3.
**Guard/dependency transitions.** §2.6: paths → 130; pairs → 17; Stage 8
importer sets and `_PERSISTENCE_FAMILIES`; head → `r0002`; schema object
digest re-pin.

- [ ] **Step 1: Focused RED.**

| File | Test | Fails because |
|---|---|---|
| `test_sqlite_stage9_migration.py` | `test_r0001_is_behind_r0002_is_current_newer_blocks`, `test_upgrade_from_r0001_equals_fresh_r0002` (objects, drift), `test_downgrade_leaves_column_with_recorded_warning`, `test_script_directory_has_one_head_named_r0002` | revision absent |
| `test_sqlite_artifact_schema.py` | `test_tables_constraints_and_triggers[case]` (one raw-insert refusal per CHECK/trigger of §3.3–§3.4, 40+ cases), `test_stderr_artifact_id_targets_core_evidence_only`, `test_sanitized_manifest_row_has_no_token_or_path`, `test_success_requires_manifest_and_manifest_requires_running`, `test_restrict_everywhere`, `test_pinned_objects_digest` | tables absent |
| `test_sqlite_artifact_repositories.py` | round trips for every new row; `test_egress_revalidates_and_refuses_reinterpretation`; `test_registration_leaves_candidate_finalizing`; `test_list_recoverable_excludes_mapped_finalizing` (RV-12); `test_refs_never_update` (RV-13); CAS precedence cases mirroring Stage 8 §4.3.1 for `candidate_artifacts` and `finalization_journal` | undefined |
| `test_sqlite_finalization_journal.py` | `test_one_active_result_lease_per_attempt`, `test_result_and_evidence_identities_disjoint`, `test_renew_never_extends_deadline`, `test_find_identity_methods` | undefined |
| `test_sqlite_audit_sink.py` | `test_append_only_and_sequence_ordered`, `test_joins_caller_transaction`, `test_recorder_autonomous`, `test_rollback_leaves_no_audit_row` | undefined |
| `test_sqlite_finalization_deadline.py` | `test_deadline_column_admitted_only_after_snapshot`, `test_deadline_immutable_once_set`, `test_snapshot_deadline_is_a_cas`, `test_record_timeout_requires_running` | column absent |
| `test_engine_run_record.py` | `test_deadline_present_only_in_snapshot_states`, `test_deadline_snapshot_predicate` (same run, `RUNNING` both, `MISSING` → present, revision +1, nothing else; every other difference refused), `test_post_snapshot_generic_targets_unrepresentable` (`NOT_APPLICABLE`/`UNAVAILABLE` with a deadline refused) | validator rejects all; predicate absent |
| `test_artifact_port_contracts.py` | `test_reference_repository_refuses_candidate_payload[kind]`, the §4.1 answer shapes per method per kind | undefined |

plus: the §2.6 guard expectations.
- [ ] **Step 2: Run the focused set and confirm every new test fails for the
  expected reason.**
- [ ] **Step 3: Minimum GREEN.**
- [ ] **Step 4: Focused GREEN.** `tests\unit\persistence tests\unit\artifacts\test_artifact_port_contracts.py tests\unit\domain\test_engine_run_record.py tests\safety tests\architecture -q`.
- [ ] **Step 5: Quality gates, Schema and migration preservation, Security and
  boundary review, Independent review, Commit, Clean-worktree checkpoint.**

**Broader tests.** `tests\unit tests\safety tests\architecture tests\property
tests\integration\persistence` (Stage 8 flows still green on `r0002`); then
`scripts/verify.ps1` alone before the commit.
**Windows-specific tests.** The Stage 8 WAL/lock suites rerun unchanged.
**Minimum passing evidence.** `migration-check` green with head `r0002`; the
object digest re-pinned after review; every trigger refusal classified
`CORE.INVARIANT_VIOLATION`.
**Security and boundary review.** No persistence module imports `os`,
`time`, `logging`; the manifest-JSON CHECK rejects the quoted keys
`"attempt_token":` and `"relative_path":` and never the `attempt_token_hash`
substring (§3.3); no cascade anywhere.
**Independent review.** Readings 8, 9, 10, 11, 12.
**Commit message.** `feat: add stage 9 artifact, manifest, journal and audit persistence`

### Task 6 — The finalizer, the journal protocol, recovery and retention

**Objective.** Deliver `artifacts/ports.py`, `CoreArtifactFinalizer` with the
four-transaction protocol of §4.3, the probe, `reconcile_finalization`,
`purge_quarantine`, the lease-close cleanup; prove every EVIDENCE cell and
every RESULT cell of §5 that ends in a refusal, `ABANDONED` or `TIMED_OUT`
over SQLite and the in-memory double with `MemoryRegistrar`/`MemoryRecoveryValidator`
(the RESULT success cells, RC-3, RC-9, RC-13, RC-15, RC-16, RC-17 and
RV-1..4 are Task 7's; §5 intro).
**Prerequisites.** Task 5 (Task 4 store).
**Files created.** `src/crypto_lab/artifacts/ports.py`, `.../finalizer.py`,
`.../recovery.py`, `tests/unit/artifacts/test_artifact_finalizer.py`,
`.../test_artifact_recovery.py`, `tests/property/test_finalization_idempotency.py`,
`tests/integration/artifacts/test_finalization_crash_points.py`,
`.../test_finalization_races.py`, `.../test_finalization_recovery.py`,
`.../test_finalization_crash_child.py`.
**Files modified.** `tests/doubles/artifacts.py` (`MemoryFinalizationUnitOfWork`
with the `RegistrationUnitOfWork` members, `engine_runs.get` and
`command_invocations.get` included — §4.1; probes, `_run`, `MemoryRegistrar`), `tests/persistence_support/artifacts.py`
(`FinalizationFixture`), `artifacts/__init__.py`, the paths/cross-pins
(→ 133), names → 6 (the mutation list shrinks to the six still deferred),
`tests/safety/test_stage6_boundaries.py` (importers 13),
`test_stage7_boundaries.py` (`_NUMBER_WORDS`, the retired "twelve" phrase,
the `:790` census → 13, the `:944-947` self-test → 14), `tests/safety/test_stage8_boundaries.py`
(`_SUBPROCESS_IMPORTER_PARENTHETICAL` `:482-485`, census `:944` → 13),
`docs/development/verification.md` (the importer sentence, without the
literal "Stage 9").
**Interfaces consumed.** Everything of Tasks 1, 2, 4, 5; `CancellationToken`;
`Clock`.
**Interfaces produced.** `ArtifactFinalizer`, `CandidateArtifactRepository`,
`ArtifactRepository`, `FinalizationJournalRepository`, `ResultLeaseRepository`,
`PurposeRegistrar`, `FinalizationUnitOfWork`, `RegistrationUnitOfWork`,
`ResultRecoveryValidator`, `ResultRecoveryFacts`, `RunManifestFacts`,
`FinalizationProbe` (ten points), `NoProbe`, `CommandRootPaths`,
`cooperative_checkpoint`;
`CoreArtifactFinalizer(...)` with `async finalize(request, cancellation) -> Result[FinalizationResult]`;
`reconcile_finalization(*, unit_of_work_factory, store, hasher, registrar,
recovery_validator, clock, audit_ids, runtime_root: Path,
command_roots: Callable[[InvocationId], CommandRootPaths | MISSING],
token_material: Callable[[InvocationId], AttemptTokenMaterial | MISSING], log) -> Result[FinalizationReconciliationReport]`
(the report counts resumed, registered, abandoned, quarantined, overdue);
`purge_quarantine(entry_id, correlation, *, ...) -> Result[None]`;
`close_raw_bytes(paths: CommandRootPaths, *, store, unit_of_work, correlation, clock) -> Result[RawByteClose]`
(the §4.3 phase-6 primitive in `artifacts/finalizer.py`: narrows the
kind-governed `CommandRootPaths` by `isinstance` — `request_path` always,
`output_path` when present, `result_path` for a `RUN` root — removal,
quarantine on failure, audit; `RawByteClose` counts removed and quarantined
files) and
`close_result_lease(journal, paths, *, store, ...)` (its leased caller after
`REGISTERED`/`ABANDONED`); `EVIDENCE_LEASE_SECONDS = 300` (§4.3 phase 2).
**Owned schema/migration/configuration changes.** None.
**Guard/dependency transitions.** §2.6: paths → 133; names → 6; importers 13.

- [ ] **Step 1: Focused RED.**

| File | Test | Fails because |
|---|---|---|
| `test_artifact_finalizer.py` | `test_finalize_returns_explicit_mappings_per_purpose`, `test_nine_step_order_observed_by_probe`, `test_no_transaction_open_across_hashing_or_moves`, `test_step_one_fields_by_purpose`, `test_owner_inconsistent_with_registry_refused_before_io`, `test_leakage_rejects_every_result_candidate`, `test_evidence_roles_and_owners`, `test_failed_candidate_is_quarantined_or_corrupt`, `test_manifest_built_at_step_four`, `test_path_violation_and_validation_failure_outcomes`, `test_persistence_failure_rolls_back_journal_drives_recovery` (Stage 8 dialect fault injection at `do_commit` of T3), `test_every_phase_audited_in_its_transaction`, `test_cancellation_token_refuses_before_prepared`, `test_adapter_candidate_cannot_be_evidence` | undefined |
| `test_artifact_recovery.py` | unit halves of RV-6, RV-7, RV-9, RV-10, RV-11, RV-17, RV-18 over the memory double | undefined |
| `test_finalization_crash_points.py` | `test_cp{1..7}_evidence` (7), `test_cp{1..6}_result_durable_state` (the state before recovery and the failing recovery branches: hash mismatch, deadline passed; CP-7's RESULT half is Task 7's) | undefined |
| `test_finalization_races.py` | `test_rc1`, `test_rc2`, `test_rc4`, `test_rc5`, `test_rc7`, `test_rc8`, `test_rc10`, `test_rc11`, `test_rc12`, `test_rc13_takeover_reaches_moved`, `test_rc14` | undefined |
| `test_finalization_recovery.py` | `test_rv5`…`test_rv18` minus RV-12/13 (Task 5; RV-1..4 are Task 7's), `test_raw_bytes_survive_lease_and_vanish_at_close`, `test_terminal_attempts_never_reopened` | undefined |
| `test_finalization_crash_child.py` | `test_child_killed_after_moved_recovers_evidence_to_registered`, `test_child_killed_inside_registered_leaves_moved` | undefined |
| property | `test_identities_disjoint_and_replay_stable` | undefined |

A representative sketch (RC-2; strict-mypy, ruff-clean):

```python
def test_rc2_cancellation_between_moved_and_registered_abandons(
    tmp_path: Path,
) -> None:
    fixture = FinalizationFixture.open(tmp_path, clock=FixedClock(INSTANT))
    try:
        fixture.plant_result_prestate()
        with pytest.raises(FinalizationCrash):
            fixture.finalize_result(probe=CrashingProbe("after_moved"))
        before = fixture.durable()
        assert before.journal_state == "MOVED"
        assert before.refs == ()
        fixture.cancel_run()  # Stage 5 transition_run(CANCELLED), CANCELLATION diagnostic
        report = ok(fixture.recover())
        after = fixture.durable()
        assert report.abandoned == 1
        assert after.journal_state == "ABANDONED"
        assert after.abandon_reason == "PERSISTENCE.CONCURRENCY_CONFLICT"
        assert after.run_state == "CANCELLED"
        assert after.refs == ()
        assert after.run_manifests == ()
        assert after.object_blobs == ()
        assert len(after.quarantine_entries) == 1  # keyed by finalization_id (§6.2)
        appended = after.audit_actions[len(before.audit_actions) :]
        assert appended.count("FINALIZATION_ABANDONED") == 1
        assert appended.count("ARTIFACT_QUARANTINED") == 2  # one per candidate
        assert appended.index("FINALIZATION_ABANDONED") < appended.index(
            "ARTIFACT_QUARANTINED"
        )
        assert sum(action.startswith("RECONCILIATION_") for action in appended) == 1
    finally:
        fixture.close()
```

plus: the §2.6 guard expectations; the crash child's ready line reports its
own interpreter pid, the parent verifies that pid as the launched process or
a live creation-identity-verified descendant, terminates and awaits it
through a retained handle, and asserts it dead under that recorded creation
identity before `reopen()` (§7.1; the launched `.venv\Scripts\python.exe` is
a launcher whose child holds the connection — commit `079395b`).
- [ ] **Step 2: Run the focused set and confirm every new test fails for the
  expected reason.**
- [ ] **Step 3: Minimum GREEN.**
- [ ] **Step 4: Focused GREEN.** `tests\unit\artifacts tests\integration\artifacts tests\property\test_finalization_idempotency.py tests\safety tests\architecture -q`.
- [ ] **Step 5: Quality gates, Schema and migration preservation, Security and
  boundary review, Independent review, Commit, Clean-worktree checkpoint.**

**Broader tests.** `tests\unit tests\safety tests\architecture tests\property
tests\integration`; then `scripts/verify.ps1` alone before the commit.
**Windows-specific tests.** The CP-5 and CP-6 crash child, the open-handle
move failure during phase 3.
**Minimum passing evidence.** The 7 EVIDENCE crash cells and the 6 RESULT
durable-state halves (CP-1..6; CP-7's RESULT half is Task 7's because its
pre-recovery state is already `REGISTERED` success), 11 race rows (RC-1, 2,
4, 5, 7, 8, 10–12, 14 and the RC-13 takeover half) and 12 recovery rows
(RV-5..18 less RV-12/13, which are Task 5's) green over SQLite; `max_open == 0` during phases 1 and 3; zero orphan processes
after the child tests.
**Security and boundary review.** The token enters the finalizer only as
`AttemptTokenMaterial` from `token_material(invocation_id)` (which reads
`request.json` under the command root through the Stage 7 reader) and is
never stored on the finalizer, the journal, a diagnostic or an audit detail;
`FinalizationCrash` is a `BaseException`; no `asyncio` import.
**Independent review.** Readings 1, 2, 4, 5, 12, 13, 18, 21, 26; the probe
points versus §4.3; the `abandon_reason` vocabulary.
**Commit message.** `feat: add the artifact finalizer, finalization journal recovery and retention`

### Task 7 — Application integration: run manifest, evidence producers, result registrar, recovery validator, comparison service

**Objective.** Deliver `experiments/run_manifest.py`, `experiments/finalization.py`
(`semantic_outcome_or_replay`, `conclude_command`, `conclude_describe`,
`fail_run_for_refusal`, `register_result_candidates`, `observe_candidates`,
`stage_core_evidence`, the producers,
`ResultRegistrar`/`EvidenceRegistrar` implementing `PurposeRegistrar`, the
`ResultRecoveryValidator` implementation), `experiments/comparison.py`;
prove the RESULT success cells of §5.1, RC-3, RC-9, RC-13, RC-15, RC-16,
RC-17, RV-1..4 and the requirement rows of §7.2 assigned to Task 7.
**Prerequisites.** Task 6.
**Files created.** `src/crypto_lab/experiments/run_manifest.py`,
`.../finalization.py`, `.../comparison.py`,
`schemas/experiments/run-manifest-v1.schema.json`,
`schemas/experiments/normalized-result-provenance-v1.schema.json`,
`tests/unit/experiments/test_run_manifest.py`, `.../test_finalization_service.py`,
`.../test_comparison_eligibility_service.py`.
**Files modified.** `experiments/__init__.py`, `domain/hashing.py` (profiles
19, 20), `schema_registry.py` (52, 53), `tests/persistence_support/artifacts.py`
(production registrar and recovery-validator wiring),
`tests/integration/artifacts/test_finalization_races.py` (RC-3, RC-9, RC-13,
RC-15, RC-16, RC-17), `test_finalization_crash_points.py`
(`test_cp{1..7}_result_success`), `test_finalization_recovery.py` (RV-1..4),
`test_finalization_crash_child.py` (the RESULT twin), `tests/architecture/test_package_import_boundaries.py`
(`_ALLOWED_FOR_EXPERIMENTS` + artifacts, audit; anchors), `tests/safety/test_stage5_boundaries.py`
(`_OUT_OF_SCOPE_PACKAGES`), `tests/safety/test_stage7_boundaries.py`
(`12 + 14`), `tests/unit/domain/test_lifecycle_tables.py` (`:539-540` → 20;
the two value strings join the render scan), the paths/cross-pins (→ 136),
names → 4, registry → 54, profiles → 20.
**Interfaces consumed.** `SemanticOutcome`, `CommandResult` and the parse,
summary and `Path` facts the caller destructures from `SupervisionOutcome`
and `CommandPaths` (never those two types), `CommandRootPaths`,
`StderrCapture`, `ManifestParse`, `ValidationResultParse`,
`DescriptorParse`, `SemanticReconciliation` (its `diagnostics`), `RunEvent` ledger
(`list_events`), `RunProvenance`,
`CandidateMetric`, `DiagnosticRecorder`, `EngineRunRepository.compare_and_swap`,
`assert_run_transition`, `assert_write_once_enrichment`, `evaluate_comparison_eligibility`,
the Task 6 finalizer and ports (`close_raw_bytes` included),
`ArtifactStore.write_staged`, `confine_candidate_path`, `CandidateObservation`.
**Interfaces produced.** `RunManifest`, `NormalizedResultProvenance`,
`run_manifest_hash`, `run_manifest_id_for`; `conclude_command(...) -> Result[CommandConclusion]`
(taking the step-0 `observations`; `VALIDATE`/`RUN` only);
`conclude_describe(command_result, descriptor_parse: DescriptorParse | MISSING, reconciliation: SemanticReconciliation, *, roots, unit_of_work, finalizer, clock) -> Result[tuple[ArtifactRef, ...]]`
(§4.6: the two describe producers, no run row, no close);
`fail_run_for_refusal(refusal, *, run_id, expected_run_revision, roots, unit_of_work, clock) -> Result[None]`
(§4.4 step 0);
`observe_candidates(work_dir, declarations, token, *, hasher) -> Result[tuple[CandidateObservation, ...]]`
(run by the caller before the verdict, §4.4 step 0);
`stage_core_evidence(...)`; the seven producers of §4.6; `ResultRegistrar`,
`EvidenceRegistrar`; `ComparisonEligibilityService.evaluate(left: RunManifest, right: RunManifest, requested_level) -> ComparisonEligibilityResult`;
`semantic_outcome_or_replay(request, *, unit_of_work, clock) -> Result[SemanticOutcome | CommandConclusion]`
(reading 24); `register_result_candidates(declarations, owner, *, unit_of_work) -> Result[tuple[CandidateArtifact, ...]]`;
the `ResultRecoveryValidator` implementation over `parse_result_manifest`,
`sanitize_result_manifest` and `reconcile_run`.
**Owned schema/migration/configuration changes.** Two schema entries.
**Guard/dependency transitions.** §2.6: paths → 136; names → 4; registry →
54; profiles → 20; `_ALLOWED_FOR_EXPERIMENTS`; Stage 7 count `12 + 14`.

- [ ] **Step 1: Focused RED.**

| File | Test | Fails because |
|---|---|---|
| `test_run_manifest.py` | `test_only_matching_run_result_refs` (candidate payload, EVIDENCE ref, non-RUN owner, other run, other experiment each refused), `test_exit_category_from_exited_invocation`, `test_self_hash_omitted_by_named_profile`, `test_provenance_fields_retained`, `test_warnings_iff_warning_status`, `test_metrics_are_metric_values_with_source_refs` | undefined |
| `test_finalization_service.py` | `test_success_committed_only_with_manifest_and_refs`, `test_only_result_branch_creates_links_manifest_success`, `test_sanitized_manifest_is_run_evidence_after_any_outcome`, `test_artifact_produced_creates_only_a_candidate`, `test_stderr_truncation_diagnostic_and_audit`, `test_unsanitized_stdout_never_staged`, `test_core_staging_root_by_owner`, `test_timeout_never_retries_in_place`, `test_dataset_input_evidence_hash_equals_registry`, `test_identity_violation_blocks_result_not_evidence`, `test_manifest_invalid_fails_run`, `test_diagnostic_report_evidence_sanitized`, `test_causal_chain_terminal_references_artifact_findings`, `test_non_success_never_waits_for_evidence`, `test_one_correlation_across_finalization_diagnostics_audit`, `test_manifest_validation_sanitization_generation_reconciliation`, `test_protocol_capture_regenerated_from_ledger`, `test_adapter_claiming_core_ids_rejected`, `test_adapter_diagnostic_ids_are_stable`, `test_source_hash_persisted_bytes_not`, `test_stderr_artifact_id_enriched_once`, `test_conclude_describe_stages_descriptor_and_stderr_only` (both describe producers finalized under the `ADAPTER` owner with the `INVOCATION` correlation naming the `DESCRIBE` invocation, `stderr_artifact_id` enriched on it, no `engine_runs` read or write, no `close_raw_bytes` call, `request.json` and `output.json` still under the root), `test_observe_candidates_streams_and_scans`, `test_observe_candidates_refuses_junction_before_open` (a junction planted at a declared path under `work_dir` is refused with `ARTIFACT.PATH_BOUNDARY_VIOLATION` and never opened — an open spy records zero opens; the refusal arises before any `SemanticOutcomeRequest` exists, and `fail_run_for_refusal` moves the run `RUNNING → FAILED` with that diagnostic, audits `RUN_FAILED` and closes the root, after which the invocation's stderr and protocol-capture evidence is still staged and finalized — §4.4 step 0), `test_conclude_command_uses_the_step_zero_observations` (the observations handed in are the ones the request carries; a read spy on `work_dir` records no open inside `conclude_command`), `test_conclude_command_closes_raw_bytes_without_a_lease` (RC-14's Stage 6 `FAILED` verdict, the step-3 `RUNNING → FAILED` refusal and a lease refused against a `CANCELLED` run each leave no `request.json`, `output.json` or `adapter-result-manifest.json` under the root, with `RETENTION_DELETED` audit and quarantine of a held file; a `PERSISTENCE.CONCURRENCY_CONFLICT` and a `VALIDATE` → `READY` conclusion leave them in place), `test_post_success_replay_returns_stored_conclusion` (reading 24: the Stage 6 operation is not invoked), `test_register_result_candidates_after_exited_only`, `test_recovery_validator_rejects_each_29_3_failure` | undefined |
| `test_comparison_eligibility_service.py` | `test_two_manifests_adapt_to_comparison_inputs`, `test_requested_level_above_provenance_refused`, `test_evidence_refs_ignored` | undefined |
| `test_finalization_races.py` | `test_rc3`, `test_rc6`, `test_rc9[outcome]` (six), `test_rc13`, `test_rc15_pair_refused`, `test_rc15_generic_timeout_wins`, `test_rc16`, `test_rc17` | registrar absent |
| `test_finalization_crash_points.py` | `test_cp{1..7}_result_success` (7: recovery to `REGISTERED` success through the production registrar and validator) | registrar absent |
| `test_finalization_recovery.py` | `test_rv1`, `test_rv2` (`RUN_FAILED` by name), `test_rv3`, `test_rv4` | validator absent |
| `test_finalization_crash_child.py` | `test_child_killed_after_moved_recovers_result_to_registered` | registrar absent |

plus: the §2.6 guard expectations.
- [ ] **Step 2: Run the focused set and confirm every new test fails for the
  expected reason.**
- [ ] **Step 3: Minimum GREEN.**
- [ ] **Step 4: Focused GREEN.** `tests\unit\experiments tests\integration\artifacts tests\unit\test_schema_registry.py tests\safety tests\architecture -q`.
- [ ] **Step 5: Quality gates, Schema and migration preservation, Security and
  boundary review, Independent review, Commit, Clean-worktree checkpoint.**

**Broader tests.** `tests\unit tests\safety tests\architecture tests\property
tests\integration`; then `scripts/verify.ps1` alone before the commit.
**Windows-specific tests.** None new.
**Minimum passing evidence.** RC-9 revision pin for all six outcomes; the
first `SUCCEEDED` run in the project's test history committed only through
`ResultRegistrar`; `dangling_diagnostic_references == 0` after every service
test.
**Security and boundary review.** `experiments` imports no `persistence` and
no `process_supervision` (the Stage 7 direction scan and the architecture
closure both stay green); `observe_candidates` is the only production `CandidateObservation`
constructor, runs before the verdict it feeds (§4.4 step 0) and confines every declared path before opening it; the registrar never reads a staging path; no `AttemptToken`
annotation; the describe producer serializes `DescriptorParse`, never raw
stdout; `conclude_describe` touches no `engine_runs` row and never calls
`close_raw_bytes`.
**Independent review.** Readings 5, 7, 11, 14, 16, 17, 23, 24; the `RunManifest`
field table against 11.3:578.
**Commit message.** `feat: compose result registration, evidence producers and the run manifest`

### Task 8 — Composition over the supervisor and SQLite, owner variants, post-run token scans

**Objective.** Extend `SupervisedSqliteFlow` and prove the end-to-end rows:
success with `RunManifest`, warning success, failure with evidence,
cancellation, finalization timeout, every crash point through the production
registrar, the six owner variants, and the post-run raw-token absence over
every surface. **This task's commit is the Stage 9 implementation hash.**
**Prerequisites.** Task 7.
**Files created.** `tests/integration/persistence/test_stage9_supervised_finalization.py`,
`tests/integration/persistence/test_stage9_token_absence.py`.
**Files modified.** `tests/persistence_support/supervised.py` (the §7.1
members; it replaces its test-side `_observe_candidates` (`:244-278`) with
the production `observe_candidates` before the verdict (§4.4 step 0), has
its `describe()` (`:610-625`) call `conclude_describe` (§4.6),
destructures `SupervisionOutcome` and `CommandPaths` into
`conclude_command`'s arguments and projects every `SupervisionTraceEntry`
into an `AuditEvent` through the Stage 9 sink — the test-support stand-in
for the Stage 10 projection of O-13), `tests/persistence_support/artifacts.py`
(shared scan helpers).
**Interfaces consumed.** The production supervisor, operations, finalizer,
registrars, recovery, SQLite persistence; the fake adapters' existing success,
warning, failure, crash and stale rows.
**Interfaces produced.** None (test support only).
**Owned schema/migration/configuration changes.** None.
**Guard/dependency transitions.** None (no source file; no new importer).

- [ ] **Step 1: Focused RED.**

| File | Test | Fails because |
|---|---|---|
| `test_stage9_supervised_finalization.py` | `test_success_row_registers_manifest_and_refs` (run `SUCCEEDED`, two RESULT refs, member links, sanitized manifest row with its evidence ref, stderr evidence linked, journal `REGISTERED`, raw bytes gone, `objects/` holds exactly the blobs), `test_warning_row_succeeds_with_warnings`, `test_failure_row_keeps_only_evidence` (run `FAILED`, no manifest, raw-bearing bytes gone from the `RUN` command root before `recover()` — §4.4 step 5 — candidates `QUARANTINED` and the `VALIDATE` root's `request.json` gone after `recover()`, stderr/protocol/sanitized-manifest evidence present), `test_cancellation_row` (RC-1 through `transition_run(CANCELLED)` with a `CANCELLATION` diagnostic — the production run-cancel edge; `cancel_experiment` is also issued and shown to leave the run row untouched), `test_finalization_timeout_row` (RC-4 with the flow's advancing clock), `test_every_crash_point_through_production_registrar[point,purpose]` (14), `test_owner_variants_end_to_end[kind]` (six: `RUN` via the success row; `ADAPTER` via the describe row (`describe()` → `conclude_describe`, §4.6); `EXPERIMENT` from the frozen `ConfigSnapshot` with the audit-hash equality; `DATASET` and `STRATEGY` from the registered fixtures' canonical bytes; `SYSTEM` a diagnostic-report projection), `test_adapter_wrote_only_under_its_work_dir`, `test_native_output_preserved_as_result_only_on_success`, `test_both_purposes_share_the_pipeline_only_result_succeeds`, `test_failure_exposes_code_category_retriable_evidence`, `test_zero_dangling_diagnostics_after_every_row`, `test_reopen_after_every_row_is_consistent` (`quick_check == ok`, `consistency_report` zeros, WAL checkpointed before hashing the file; crash rows close with `close(keep_command_roots=True)` before `reopen`) | members absent |
| `test_stage9_token_absence.py` | `test_token_absent_from_every_surface[row]` (after success, failure, cancellation, timeout, each crash point, each row followed by `recover()`: the database file bytes after a checkpoint, `-wal`/`-shm` if present, every `*_json` column, logs root, artifacts root, quarantine root, staging root, every command root of the attempt (kept by `close(keep_command_roots=True)`; the phase-6 close and the step-9 sweep have emptied them of raw bytes), every evidence blob — the test-side `bytes.find` scan, independent of the production scanner; a planted positive control proves the scan finds a token written into a scratch file under `tmp_path`) | members absent |

- [ ] **Step 2: Run the focused set and confirm every new test fails for the
  expected reason.**
- [ ] **Step 3: Minimum GREEN.** The flow extension; no source change is
  expected — a source defect found here is fixed under its owning task's
  commit message prefix `fix:` with the §5 case named, before this task's
  commit.
- [ ] **Step 4: Focused GREEN.** `tests\integration\persistence -q`, then
  `tests\integration\artifacts -q`.
- [ ] **Step 5: Quality gates, Schema and migration preservation, Security and
  boundary review, Independent review, Commit, Clean-worktree checkpoint.**

**Broader tests.** `scripts/verify.ps1` alone (the implementation-hash
candidate must pass the complete verifier before the status task begins).
**Windows-specific tests.** The crash child row through the flow; paths with
spaces and Unicode for the flow's `tmp_path`.
**Minimum passing evidence.** Every row above green; the positive control
of the scan; the complete verifier green on this commit.
**Security and boundary review.** The flow binds no in-memory store; the
token is read from the flow's `_token_for(run_id)` only to plant the
positive control and to hand `AttemptTokenMaterial` to the production path,
never asserted into a record.
**Independent review.** Readings 5, 7; the six-facet assertion of 28.3:2096
in every row.
**Commit message.** `feat: finalize artifacts over the supervised sqlite flow with raw-token scans`

### Task 9 — Stage 9 boundary guard, documentation and Stage 9 status

**Objective.** Pin the Stage 9 surface and record completion: the Stage 9
guard, the focused checks in the verification guide, README and roadmap
status, and every status pin of §2.6 (Status pins).
**Prerequisites.** Task 8 committed; its hash known.
**Files created.** `tests/safety/test_stage9_boundaries.py`.
**Files modified.** `README.md`, `docs/development/verification.md`,
`docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md`,
`tests/safety/test_stage3_boundaries.py`, `tests/safety/test_stage5_boundaries.py`,
`tests/safety/test_stage7_boundaries.py` (`:766-770`), `tests/safety/test_stage8_boundaries.py`
(the completion-row clause and the status positives of `:977-999`, §2.6),
`tests/safety/test_gitnexus_development_tooling.py`,
`tests/unit/test_schema_registry.py` (`_STAGE9_SHA256`, the keyed halves).
**Interfaces consumed.** None.
**Interfaces produced.** None.
**Guard/dependency transitions.** §2.6 Status pins; the Stage 9 guard.

- [ ] **Step 1: Focused RED.** The Stage 9 guard asserts:
  `test_stage_nine_modules_are_exactly_the_plan_paths` — `STAGE9_SOURCE_FILES`
  (26, or 25 without Task 3; disjoint from Stage 5/6/7/8) equals the §2.6
  table; `test_artifacts_and_audit_import_domain_only` — `artifacts` and
  `audit` import only `domain` and themselves (AST over every `crypto_lab.*`
  import);
  `experiments` imports `artifacts`/`audit` only from the three new modules
  and `retry.py` imports neither; `os` is imported only by `artifacts/store.py`
  and only `fstat`/`fsync` are read; no new module imports the §2.6 denied
  roots; no new class carries an `AttemptToken` annotation; no identifier
  `context`/`buffer`/`note`/`problem`; each of the 29 released names is
  defined exactly once in its §2.6 module and the four remaining names
  nowhere; `HashingProfile` tail is the eight Stage 9 profiles in order;
  `_STAGE9_PATHS` positions 35–53 with digests; the Alembic head is
  `r0002_stage9_artifacts` with `down_revision == "r0001_stage8_baseline"`
  and the versions directory holds exactly `__init__.py`, `r0001_…`,
  `r0002_…`; `AuditAction` has 25 members; the roadmap Stage 9 completion
  row, the Stage 10 deferred row (roadmap line 388), the approved-plan line,
  README and guide status blocks (positives), the Stage 8 forms (negatives),
  the hash rules of §2.6; the guide's Stage 9 focused-check sentences; no
  documentation surface says "exhaustiv", "sandbox" or "Stage 10 has
  started"; `test_no_pickle_marshal_or_eval_in_new_modules`.
- [ ] **Step 2: Run the focused set and confirm every new test fails for the
  expected reason** (the status prose absent; the Stage 8 pins still
  positive).
- [ ] **Step 3: Minimum GREEN.** The prose and the pin edits: README status
  line and paragraph ("Project 1 Stage 9 is complete. … implementation
  completed at `<Task 8 hash>`; the Stage 9 boundary guard and this status
  were added by the separate Task 9 commit, which is not the implementation
  hash. The closed 54-schema registry — 19 new Stage 9 schemas with the 35
  Stage 3–6 schemas preserved byte-identical (48 and 13 without Task 3); the relational schema has one
  Alembic head, `r0002_stage9_artifacts`. Stage 10 has not started."), the
  guide's "Stage scope" block ending "Stage 10 is not started.", the Stage
  9 focused targets and evidence, the inexpressible-rules register
  additions, the retired guide 603 sentence, the roadmap header, plan
  sentence, Stage 8 row clause, Stage 9 completion row (`Implementation
  complete at <Task 8 hash>`) and the plan line changed from "Planned" to
  "Approved". The hash appears once, in the roadmap, and nowhere in README or
  the guide.
- [ ] **Step 4: Focused GREEN.** `tests\safety tests\unit\test_schema_registry.py -q`.
- [ ] **Step 5: Quality gates, Schema and migration preservation, Security and
  boundary review, Independent review, Commit, Clean-worktree checkpoint.**

**Broader tests.** `scripts/verify.ps1` alone before the commit and again on
the fast-forwarded `main`, followed by the ownership-aware hygiene checks.
**Windows-specific tests.** None new.
**Minimum passing evidence.** The complete verifier green twice (branch and
merged `main`), eleven stages, two skips, coverage at or above 98.61 percent
(the planning-base measurement this plan requires; the Stage 8 stage
requirement of 98.42 percent stays exceeded, Global Constraints).
**Security and boundary review.** Documentation names no sandbox claim; the
guide records the Stage 9 evidence (§9.3), the carried limitations (§1.4,
§1.6 items 4 and 6) and the open risks of O-18 rather than erasing them.
**Independent review.** Every §2.6 status pin before/after; the guide prose
generated from guard constants where the guards pin it; the dependency walk
of §7.1.
**Commit message.** `feat: add stage 9 boundaries, documentation and status`

---

## 9. Verification and acceptance

### 9.1 Commands

Focused, during red-green development (diagnostic only; `-o addopts=`
disables coverage); every target is a normalized repository-relative path
under `tests/`, the only shape the launcher's `pytest-focused` profile
accepts:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\artifacts tests\unit\audit -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\persistence tests\unit\domain -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\integration\artifacts -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\unit\experiments tests\property -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\integration\persistence -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-uv.ps1 pytest-focused -o addopts= tests\safety tests\architecture tests\unit\test_schema_registry.py -q
```

Quality gates after every task: `ruff-format-all` (apply the printed diff by
hand), `ruff-check-all`, `mypy-all`, `schema-generate-check`,
`migration-check` — all existing profiles; no profile is added.

Dependency gates: none (§2.8).

Complete, before any completion claim, alone on the host (no other pytest,
no reviewer agent, no other Python child running — the Stage 4
strategy-hashing properties flake their hypothesis deadline under load, the
Stage 7 suites launch real children, the Stage 8 lock tests measure bounded
waits, and the Stage 9 crash child and open-handle fixtures hold handles),
from a shell attached to a console:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
```

The verifier runs its unchanged eleven steps (lock-check, sync,
ruff-format-all, ruff-check-all, mypy-all, schema-generate-check,
migration-check, pytest-all, build, schema-distribution, `git diff --check`).
Before every long run, `tasklist` proves no orphan `python.exe` from an
earlier fake-adapter launch, interrupted-writer child or finalization crash
child survives; a survivor is a defect to investigate, never to kill and
forget (a suspended uv-trampoline orphan sharing the base-interpreter image
is recorded, not killed). After every long run the ownership-aware hygiene
checks record process probes (task-owned survivors and suspended fixture
processes must be zero), the Stage 7 command-root check counts only roots
outside pytest's retained base temporary directories, and the Stage 9 check
confirms no `objects/`, `quarantine/` or `staging/` directory exists outside
those temporary directories.

### 9.2 Serial order that stays flake-free

For every task (1–9): focused suites → the task's broader sets → the task's
independent review (no pytest running) → `scripts/verify.ps1` alone →
commit → (Task 9 only) fast-forward `main` →
merged-`main` verifier alone → hygiene checks → non-force publication.
Reviewer agents and the verifier never run concurrently; no file is edited
while a review is running. A standalone `pytest-all` immediately before the
verifier is not run (the verifier contains it). For work the controller
dispatches, the verifier is launched through the controller's
`SerialVerifier` with the execution-identity gate (the prospective policy
recorded at the controller checkpoint); a human foreground launch remains
valid evidence; the criteria are identical on both routes and there is no
stop-after-every-task gate beyond the independent review. Carried risks,
not closed by this plan: the Stage 7 open-handle-count intermittent (a rerun
is performed alone once and recorded with both outcomes; a later pass does
not prove it fixed; no test is altered for it); positional skip attribution
(the verifier prints no reasons; the two skips are identified by
progress-marker position plus the inventory); `C:\Windows\Temp` is never
probed; the WAL first-opener susceptibility under a deliberately mapped
`-shm` (the Stage 9 CP-6 test keeps the retained-handle discipline of the
Stage 8 correction); earlier failed runs stand on the record.

### 9.3 Acceptance criteria

Stage 9 is complete only when all of the following hold with fresh offline
evidence:

1. The artifact, audit, metric, manifest and (if Task 3 is confirmed)
   normalized record families exist as strict `CanonicalModel`s with the 19
   generated schemas at positions 35–53; the 35 earlier files are
   byte-identical; every state-governed rule is either published or in the
   guide register (A33.2-01, T28.1-03..07, Tasks 1–3, 7).
2. `CandidateArtifact` and `ArtifactRef` are disjoint: each rejects the
   other's payload; a reference has literal `FINALIZED`; every reference
   retains source candidate, owner, purpose, role, producer, independent hash
   and size, validation profile and timestamps (A33.6-02, §3.1).
3. Exactly the seven purpose/producer/owner/role rows of §3.1.1 (nine owner tuples) validate in
   the models, the requests, the table CHECKs and the property generator;
   an adapter can select none of purpose, owner, role, correlation or path
   (A33.6-05, A33.6-06, T28.2-04, T28.4-02).
4. Every path is confined lexically and physically before it is opened and
   rechecked by identity before hashing and before each move; junctions,
   symlinks, reparse ancestors, hard links, ADS, drive and UNC prefixes,
   traversal and over-ceiling paths are refused with
   `ARTIFACT.PATH_BOUNDARY_VIOLATION` or `PROCESS.PATH_PREFLIGHT_REJECTED`
   (T28.4-01, T28.5-01, §6.3).
5. Hashing streams; the token scan finds the token across every chunk
   boundary and in binary candidates; the finalized hash is recomputed in
   place after the move; a mutation between hash and move is refused
   (R10.2-08, T28.3-02, T28.4-03, §6.4).
6. The journal protocol holds: no transaction is open across hashing or
   moves (`max_open == 0`); `PREPARED` is written only with the
   purpose-allowed fields; `MOVED` records observed hashes; `REGISTERED`
   is the only transaction that creates references, and only the RESULT
   branch creates links, a `RunManifest` and success (A33.6-01, §4.3).
6a. Every one of the 14 crash cells of §5.1 recovers without false success:
   the durable state after recovery equals the table, audit history equals
   committed phases, no reference exists without its manifest and no
   success without a manifest, and a second recovery pass is a no-op
   (A33.5-01, T28.3-07, T28.3-10, T28.3-11, Tasks 6, 8).
6b. Every race row of §5.2 resolves as tabulated: run-level cancellation
   before `PREPARED` refuses the lease, between `MOVED` and `REGISTERED`
   abandons and quarantines, after `REGISTERED` is ineffective, and
   experiment-level cancellation after T1 never pre-empts the lease (RC-17); the finalization
   deadline yields `RUNNING → TIMED_OUT` with the invocation `EXITED`, no
   manifest, no RESULT reference and no later recovery to success; identical
   replay is a no-write; a different manifest for the same attempt is a
   conflict; a stale invocation or stale attempt is refused (T28.3-01,
   R17.2-01..03, R19.3-01..05).
6c. EVIDENCE finalizes after each of the six terminal outcomes without
   changing the run row's revision, never creates a `RunManifest`, never
   satisfies the RESULT identity, and refuses adapter-produced, failed-run
   result, quarantined or corrupt candidates (A33.6-04, T28.3-08, R19.1-09..14,
   R29.4-01..02).
7. Reconciliation rows RV-1..RV-18 hold: a valid temporary manifest with a
   durably `EXITED` invocation recovers to success with the token hashed from
   surviving request material and never stored; a missing, oversized or
   mismatched manifest fails the attempt; orphan directories,
   purpose-mismatched candidates, failed-run candidates and unregistered
   finalized content are quarantined with audit; mapped `FINALIZING`
   candidates are excluded; references never transition; an overdue
   quarantine entry is diagnosed; `purge_quarantine` refuses under an active
   lease (R29.2-01..04, R29.3-01..10, R15.6-01..02, R14.7-05..08).
8. Persistence enforces the Stage 9 invariants at the table: one active
   RESULT lease per attempt, disjoint RESULT/EVIDENCE identities, matching
   owner/purpose/role across candidate and reference, `RUN`-only
   `run_artifacts`, success ⇔ manifest, immutable deadline,
   `stderr_artifact_id` → core EVIDENCE with the matching owner, insert-only
   references, append-only audit, `RESTRICT` everywhere, and the head is
   `r0002_stage9_artifacts` with `r0001` classified `BEHIND` (A33.5-02,
   R23.3.1-*, R23.4-01).
9. Audit events exist for every artifact-family action in the same
   transaction as the state change; the JSON Lines log rotates and redacts;
   diagnostics form acyclic causal chains from the run's primary terminal
   diagnostic to the artifact finding; zero dangling diagnostic references
   after every row (A33.6-09, R30.3-02, R21.4-01, I-9).
10. The post-run scan finds the raw token in none of: the checkpointed
    database file, WAL/SHM, any JSON column, logs, artifacts root,
    quarantine, staging, the attempt's command roots, evidence blobs,
    manifests — after success, failure,
    cancellation, timeout and every crash point — while the planted positive
    control is found (A33.4-02, A33.7-01, T28.3-04).
11. The supervised flow commits the first `SUCCEEDED` and
    `SUCCEEDED_WITH_WARNINGS` runs of the project only through
    `ResultRegistrar`, preserves native output as RESULT only for them, keeps
    failed-run candidates quarantined, exercises all six owner variants
    through the production path, and reopens consistent after every row
    (A33.4-01, A33.6-07, A33.6-08, T28.3-09, Task 8).
12. Every closed-world guard of §2.6 holds at its reconciled value: 136
    allowed source files, 30 import roots, 4 deferred definitions (13 without
    Task 3), four live mutation cases (seven without Task 3), 17
    infrastructure exemption pairs, five reader
    implementations, thirteen `subprocess` importers, four runtime
    dependencies, 27 prohibited families, 21 launcher operations, an
    eleven-step verifier, the registry at 54 (48 without Task 3) with five
    digest blocks,
    `HashingProfile` at 20, 21 tables, one Alembic head, and every
    documentation pin at its Stage 9 successor.
13. `ruff-format-all`, `ruff-check-all`, `mypy-all`, `schema-generate-check`,
    `migration-check`, `pytest-all`, `build`, `schema-distribution` and
    `git diff --check` are clean offline; the complete verifier reports
    branch coverage of at least 98.61 percent (the planning-base measurement;
    the Stage 8 requirement of 98.42 percent is the floor it already exceeds)
    with exactly the two approved
    skips identified positionally; the reviewed subject identity (the commit
    hash of the verified tree) is unchanged before and after the run; the
    ownership-aware hygiene checks report zero task-owned survivors; the
    merged-`main` verifier passes before publication; publication is a
    non-force push of the fast-forwarded `main`.
14. No `artifacts` or `audit` module imports anything outside `domain`; `os`
    is imported only by `artifacts/store.py`; `experiments` reaches
    `artifacts`/`audit` only from its three new modules and never
    `persistence`; `process_supervision`, `adapters`, `domain`, `strategy`,
    `capabilities`, `configuration` and `datasets` import neither new
    package; no adapter receives a database handle, a store path or a
    finalized path; no `process_supervision`, `adapters`, `capabilities`,
    `configuration`, `strategy` or `datasets` module is edited.

## 10. Rollback and completion

Each task ends in one commit, so any task is reverted with `git revert` of
that commit without touching another task; §2.6's guard edits travel in the
same commit as the module, name, root, pair, schema or dependency change
that trips them, so a revert restores guard and source together. The
highest-risk reversals are Task 1 (the retired Stage 7 negative and the
identities every later task derives), Task 5 (the revision; reverting it on
a database already at `r0002` leaves that file `UNKNOWN` to the reverted
tree, which refuses to open it — the documented, non-destructive outcome)
and Task 7 (the first success commit path). Task 3 exists only when confirmed
(§1.6 item 1).
Task 8 is the implementation commit whose hash the roadmap records; Task 9
touches no source module, so reverting Task 9 alone returns the tree to a
complete implementation without its status prose.

Stage 1–8 files edited, all only as §2.6 tabulates: `src/crypto_lab/domain/identifiers.py`,
`hashing.py`, `__init__.py` (Tasks 1, 2, 3, 7); `src/crypto_lab/domain/engine_run.py`
(Task 5); `src/crypto_lab/artifacts/__init__.py`, `audit/__init__.py`,
`experiments/__init__.py` (exports); `src/crypto_lab/schema_registry.py`
(Tasks 1, 2, 3, 7); `src/crypto_lab/persistence/schema.py`, `codecs.py`,
`repositories.py`, `unit_of_work.py`, `database.py`, `migration_runner.py`
and `scripts/verify_migrations.py` (Task 5); `tests/safety/test_stage3_boundaries.py`
and `tests/unit/test_package_layout.py` by every module-creating task (1–7)
and the former by Task 9; the six cross-pin files by Tasks 1–7;
`tests/safety/test_stage5_boundaries.py` by Tasks 5, 7 and 9;
`tests/safety/test_stage6_boundaries.py` by Task 6; `tests/safety/test_stage7_boundaries.py`
by Tasks 1, 6, 7 and 9; `tests/safety/test_stage8_boundaries.py` by Tasks 1,
5, 6 and 9; `tests/safety/test_gitnexus_development_tooling.py` by Task 9;
`tests/architecture/test_package_import_boundaries.py` by Tasks 1, 2, 5 and
7; `tests/unit/test_schema_registry.py` and `tests/unit/domain/test_domain_descriptors.py`
by Tasks 1, 2, 3, 7 and 9; `tests/unit/adapters/test_adapter_diagnostics.py`
by Tasks 1, 2 and 7; `tests/unit/domain/test_hashing.py` and
`tests/unit/domain/test_lifecycle_tables.py` by Tasks 1, 2, 7;
`tests/unit/domain/test_engine_run_record.py`, `tests/unit/persistence/*`
and `tests/unit/persistence/conftest.py` by Task 5;
`tests/persistence_support/supervised.py` by Task 8;
`docs/development/verification.md` by Tasks 6 and 9; `README.md` and the
roadmap by Task 9. `tests/doubles/experiments.py`, `tests/doubles/supervision.py`,
`tests/contract/*`, `tests/fake_adapters/*`, every `process_supervision`,
`adapters`, `capabilities`, `configuration`, `strategy` and `datasets`
module, `scripts/invoke-uv.ps1`, `scripts/verify.ps1`, `pyproject.toml`,
`uv.lock`, `r0001_stage8_baseline.py`, `src/crypto_lab/experiments/retry.py`,
`tests/unit/experiments/test_retry.py`, `tests/unit/domain/test_retry_records.py`
and every Stage 3–6 generated schema are not edited.

Stage 9 is complete when every criterion of §9.3 holds, the worktree is
clean and committed, the roadmap status table records
`STAGE9_IMPLEMENTATION_COMMIT` (the Task 8 commit, the last commit that adds
Stage 9 behaviour) together with the statement that the guard,
documentation and status were added by the separate Task 9 commit, README
states "Stages 1-9 complete" and "Stage 10 has not started.", and
`docs/development/verification.md` records the Stage 9 focused checks and
"Stage 10 is not started." No CLI command, composition root, startup-order
owner, retention command, converter or Parquet reader exists anywhere in the
tree.

The planning task that produced this document ends with the token
`STAGE9_PLAN_COMPLETE_AND_MERGED` only after the plan is reviewed, the
unchanged verifier passes on the plan commit and on the fast-forwarded
`main`, and Stage 9 implementation has not begun.
